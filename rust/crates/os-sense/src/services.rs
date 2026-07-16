use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::command::{run_limited_command, LimitedCommandOutput};
use crate::error::{OsSenseError, Result};
use crate::model::{
    CollectionStatus, HealthProbeResult, ServiceSnapshot, ServiceSource, ServiceSourceStatus,
    ServiceUnit,
};
use crate::network::{probe_tcp, NetworkQuery, TcpProbeRequest};
use crate::procfs::basic_meta;
use crate::redaction::redact_sensitive_text;

const MAX_SERVICE_LIMIT: usize = 4_096;
const MAX_SERVICE_SOURCE_LINES: usize = 8_192;
const MAX_SERVICE_WARNINGS: usize = 32;
const MAX_SERVICE_ERROR_CHARS: usize = 256;
const MAX_SERVICE_NAME_CHARS: usize = 256;
const MAX_SERVICE_DESCRIPTION_CHARS: usize = 512;
const MAX_HEALTH_PROBES: usize = 5;
const SERVICE_STDOUT_LIMIT: usize = 1024 * 1024;
const SERVICE_STDERR_LIMIT: usize = 32 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const LIST_UNITS_ARGS: [&str; 7] = [
    "list-units",
    "--type=service",
    "--all",
    "--no-pager",
    "--plain",
    "--no-legend",
    "--full",
];
const LIST_UNIT_FILES_ARGS: [&str; 4] = [
    "list-unit-files",
    "--type=service",
    "--no-pager",
    "--no-legend",
];
const SHOW_ALL_PATTERN: &str = "*.service";
const SHOW_PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,UnitFileState,Description,Result,ExecMainStatus,FragmentPath,Requires,Wants,After,Before";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ServiceQuery {
    pub name: Option<String>,
    pub include_all: bool,
    pub include_dependencies: bool,
    pub include_ports: bool,
    pub health_probes: Vec<TcpProbeRequest>,
    pub limit: Option<usize>,
}

impl Default for ServiceQuery {
    fn default() -> Self {
        Self {
            name: None,
            include_all: true,
            include_dependencies: true,
            include_ports: false,
            health_probes: Vec::new(),
            limit: Some(MAX_SERVICE_LIMIT),
        }
    }
}

impl ServiceQuery {
    pub fn validate(&self) -> Result<()> {
        if let Some(name) = self.name.as_deref() {
            validate_unit_name(name)?;
        }
        if self
            .limit
            .is_some_and(|limit| !(1..=MAX_SERVICE_LIMIT).contains(&limit))
        {
            return Err(OsSenseError::Configuration(format!(
                "service query limit must be between 1 and {MAX_SERVICE_LIMIT}"
            )));
        }
        if self.health_probes.len() > MAX_HEALTH_PROBES {
            return Err(OsSenseError::Configuration(format!(
                "service query health_probes must not contain more than {MAX_HEALTH_PROBES} entries"
            )));
        }
        NetworkQuery {
            tcp_probes: self.health_probes.clone(),
            ..NetworkQuery::default()
        }
        .validate()?;
        Ok(())
    }
}

trait ServiceCommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> io::Result<LimitedCommandOutput>;
}

struct SystemServiceCommandRunner;

impl ServiceCommandRunner for SystemServiceCommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> io::Result<LimitedCommandOutput> {
        run_limited_command(program, args, timeout, stdout_limit, stderr_limit)
    }
}

#[derive(Default)]
struct ParsedServiceSource {
    units: BTreeMap<String, ServiceUnit>,
    failure_evaluable_names: BTreeSet<String>,
    parse_failure_count: usize,
    duplicate_count: usize,
    conflict_count: usize,
    omitted_count: usize,
    total_unknown: bool,
    truncated: bool,
}

#[must_use = "service query failures must be handled"]
pub fn query_services(query: &ServiceQuery) -> Result<ServiceSnapshot> {
    query_services_with_runner(query, &SystemServiceCommandRunner)
}

fn query_services_with_runner(
    query: &ServiceQuery,
    runner: &dyn ServiceCommandRunner,
) -> Result<ServiceSnapshot> {
    query.validate()?;
    let mut warnings = Vec::new();
    let mut omitted_warning_count = 0usize;

    let (runtime_units, runtime_status, _) = collect_service_source(
        runner,
        ServiceSource::ListUnits,
        &LIST_UNITS_ARGS,
        parse_list_units_output,
    );
    let runtime_unit_names = runtime_units.keys().cloned().collect::<BTreeSet<_>>();
    if let Some(error) = runtime_status.error.as_deref() {
        push_service_warning(
            &mut warnings,
            &mut omitted_warning_count,
            format!("systemctl list-units: {error}"),
        );
    }

    let (file_units, file_status, _) = collect_service_source(
        runner,
        ServiceSource::ListUnitFiles,
        &LIST_UNIT_FILES_ARGS,
        parse_list_unit_files_output,
    );
    if let Some(error) = file_status.error.as_deref() {
        push_service_warning(
            &mut warnings,
            &mut omitted_warning_count,
            format!("systemctl list-unit-files: {error}"),
        );
    }

    let mut source_statuses = vec![runtime_status, file_status];
    let mut merged = runtime_units;
    merge_service_maps(&mut merged, file_units);

    let show_target = query.name.as_deref().unwrap_or(SHOW_ALL_PATTERN);
    let (show_units, show_status, show_failure_evaluable_names) =
        if let Some(name) = query.name.as_deref() {
            let show_args = ["show", name, "--no-pager", "--property", SHOW_PROPERTIES];
            collect_service_source(
                runner,
                ServiceSource::Show,
                &show_args,
                |content, input_truncated| parse_show_output(content, name, input_truncated),
            )
        } else {
            let show_args = [
                "show",
                SHOW_ALL_PATTERN,
                "--all",
                "--no-pager",
                "--property",
                SHOW_PROPERTIES,
            ];
            collect_service_source(
                runner,
                ServiceSource::Show,
                &show_args,
                parse_show_records_output,
            )
        };
    if let Some(error) = show_status.error.as_deref() {
        push_service_warning(
            &mut warnings,
            &mut omitted_warning_count,
            format!("systemctl show {show_target}: {error}"),
        );
    }
    let show_unit_name = query
        .name
        .as_ref()
        .and_then(|_| show_units.keys().next().cloned());
    let required_failure_names = if query.name.is_some() {
        show_unit_name.iter().cloned().collect::<BTreeSet<String>>()
    } else {
        runtime_unit_names
    };
    let show_failure_coverage_complete =
        required_failure_names.is_subset(&show_failure_evaluable_names);
    if show_status.status != CollectionStatus::Failed {
        merge_show_units(&mut merged, show_units);
    }
    source_statuses.push(show_status);

    let collection_status = aggregate_service_collection_status(&source_statuses);
    let available = collection_status != CollectionStatus::Failed;
    let filter_complete = source_statuses
        .iter()
        .all(|status| status.status == CollectionStatus::Complete);
    let failed_filter_complete = source_statuses.iter().any(|status| {
        status.source == ServiceSource::ListUnits && status.status == CollectionStatus::Complete
    }) && source_statuses.iter().any(|status| {
        status.source == ServiceSource::Show && status.status == CollectionStatus::Complete
    }) && show_failure_coverage_complete;
    let source_truncated = source_statuses.iter().any(|status| status.truncated);

    let mut units = merged.into_values().collect::<Vec<_>>();
    if let Some(name) = query.name.as_deref() {
        if let Some(show_name) = show_unit_name.as_deref() {
            units.retain(|unit| {
                unit.name == show_name && unit.sources.contains(&ServiceSource::Show)
            });
        } else {
            units.retain(|unit| unit.name == name);
        }
    } else if !query.include_all {
        units.retain(|unit| {
            unit.runtime_present
                && unit
                    .active_state
                    .as_deref()
                    .is_some_and(|state| state != "inactive")
        });
    }
    units.sort_by(|left, right| left.name.cmp(&right.name));
    if !query.include_dependencies {
        for unit in &mut units {
            unit.requires.clear();
            unit.wants.clear();
            unit.after.clear();
            unit.before.clear();
        }
    }
    if query.include_ports {
        push_service_warning(
            &mut warnings,
            &mut omitted_warning_count,
            "service-to-port mapping requires FR-1.20 probing and is not part of FR-1.17 inventory"
                .to_string(),
        );
    }

    let total = units.len();
    let mut failed_units = units
        .iter()
        .filter(|unit| service_failed(unit))
        .cloned()
        .collect::<Vec<_>>();
    let failed_total = failed_units.len();
    failed_units.truncate(MAX_SERVICE_LIMIT);
    let failed_returned_count = failed_units.len();
    let failed_omitted_count = failed_total.saturating_sub(failed_returned_count);
    let limit = query.limit.unwrap_or(MAX_SERVICE_LIMIT);
    let omitted_count = total.saturating_sub(limit);
    units.truncate(limit);
    let returned_count = units.len();
    let truncated = source_truncated || omitted_count > 0 || failed_omitted_count > 0;
    let health_probes = query.health_probes.iter().map(probe_tcp).collect();

    Ok(ServiceSnapshot {
        meta: basic_meta("services", warnings),
        available,
        truncated,
        collection_status,
        source_statuses,
        total,
        returned_count,
        omitted_count,
        failed_total,
        failed_returned_count,
        failed_omitted_count,
        failed_filter_complete,
        filter_complete,
        omitted_warning_count,
        units,
        failed_units,
        health_probes,
    })
}

fn collect_service_source<F>(
    runner: &dyn ServiceCommandRunner,
    source: ServiceSource,
    args: &[&str],
    parser: F,
) -> (
    BTreeMap<String, ServiceUnit>,
    ServiceSourceStatus,
    BTreeSet<String>,
)
where
    F: FnOnce(&str, bool) -> ParsedServiceSource,
{
    let output = match runner.run(
        "systemctl",
        args,
        COMMAND_TIMEOUT,
        SERVICE_STDOUT_LIMIT,
        SERVICE_STDERR_LIMIT,
    ) {
        Ok(output) => output,
        Err(error) => {
            return (
                BTreeMap::new(),
                ServiceSourceStatus {
                    source,
                    available: error.kind() != io::ErrorKind::NotFound,
                    status: CollectionStatus::Failed,
                    exit_code: None,
                    timed_out: error.kind() == io::ErrorKind::TimedOut,
                    parse_failure_count: 0,
                    duplicate_count: 0,
                    conflict_count: 0,
                    entry_count: 0,
                    omitted_count: 0,
                    total_unknown: true,
                    truncated: false,
                    error: Some(bounded_service_error(&error.to_string())),
                },
                BTreeSet::new(),
            );
        }
    };
    if output.timed_out || !output.success {
        let detail = if output.timed_out {
            "systemctl command timed out".to_string()
        } else if output.stderr.trim().is_empty() {
            "systemctl command failed".to_string()
        } else {
            output.stderr.trim().to_string()
        };
        return (
            BTreeMap::new(),
            ServiceSourceStatus {
                source,
                available: true,
                status: CollectionStatus::Failed,
                exit_code: output.exit_code,
                timed_out: output.timed_out,
                parse_failure_count: 0,
                duplicate_count: 0,
                conflict_count: 0,
                entry_count: 0,
                omitted_count: 0,
                total_unknown: true,
                truncated: output.stdout_truncated || output.stderr_truncated,
                error: Some(bounded_service_error(&detail)),
            },
            BTreeSet::new(),
        );
    }

    let parsed = parser(
        &output.stdout,
        output.stdout_truncated || output.stderr_truncated,
    );
    let status = if parsed.truncated || parsed.parse_failure_count > 0 || parsed.conflict_count > 0
    {
        CollectionStatus::Partial
    } else {
        CollectionStatus::Complete
    };
    let error = (status == CollectionStatus::Partial).then(|| {
        bounded_service_error(&format!(
            "{} malformed, {} conflicting, {} duplicate row(s), at least {} omitted; truncated={}",
            parsed.parse_failure_count,
            parsed.conflict_count,
            parsed.duplicate_count,
            parsed.omitted_count,
            parsed.truncated
        ))
    });
    let source_status = ServiceSourceStatus {
        source,
        available: true,
        status,
        exit_code: output.exit_code,
        timed_out: false,
        parse_failure_count: parsed.parse_failure_count,
        duplicate_count: parsed.duplicate_count,
        conflict_count: parsed.conflict_count,
        entry_count: parsed.units.len(),
        omitted_count: parsed.omitted_count,
        total_unknown: parsed.total_unknown,
        truncated: parsed.truncated,
        error,
    };
    (parsed.units, source_status, parsed.failure_evaluable_names)
}

fn parse_list_units_output(content: &str, input_truncated: bool) -> ParsedServiceSource {
    let mut parsed = ParsedServiceSource {
        truncated: input_truncated || content.contains('\u{fffd}'),
        total_unknown: input_truncated,
        ..ParsedServiceSource::default()
    };
    for (index, raw) in content.lines().enumerate() {
        if index >= MAX_SERVICE_SOURCE_LINES {
            parsed.truncated = true;
            parsed.total_unknown = true;
            break;
        }
        let line = raw
            .trim_start()
            .strip_prefix('●')
            .unwrap_or(raw.trim_start())
            .trim_start();
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 || validate_unit_name(fields[0]).is_err() {
            mark_malformed_source_row(&mut parsed);
            continue;
        }
        let (description, description_truncated) = fields
            .get(4..)
            .filter(|parts| !parts.is_empty())
            .map(|parts| bounded_service_text(&parts.join(" "), MAX_SERVICE_DESCRIPTION_CHARS))
            .map_or((None, false), |(description, truncated)| {
                (Some(description), truncated)
            });
        parsed.truncated |= description_truncated;
        let unit = ServiceUnit {
            name: fields[0].to_string(),
            load_state: Some(fields[1].to_string()),
            active_state: Some(fields[2].to_string()),
            sub_state: Some(fields[3].to_string()),
            unit_file_state: None,
            unit_file_preset: None,
            loaded: fields[1] == "loaded",
            runtime_present: true,
            sources: vec![ServiceSource::ListUnits],
            description,
            description_truncated,
            result: None,
            exec_main_status: None,
            fragment_path: None,
            requires: Vec::new(),
            wants: Vec::new(),
            after: Vec::new(),
            before: Vec::new(),
            ports: Vec::new(),
        };
        if insert_source_unit(&mut parsed, unit) {
            break;
        }
    }
    parsed
}

fn parse_list_unit_files_output(content: &str, input_truncated: bool) -> ParsedServiceSource {
    let mut parsed = ParsedServiceSource {
        truncated: input_truncated || content.contains('\u{fffd}'),
        total_unknown: input_truncated,
        ..ParsedServiceSource::default()
    };
    for (index, raw) in content.lines().enumerate() {
        if index >= MAX_SERVICE_SOURCE_LINES {
            parsed.truncated = true;
            parsed.total_unknown = true;
            break;
        }
        let fields = raw.split_whitespace().collect::<Vec<_>>();
        if fields.is_empty() {
            continue;
        }
        if !(2..=3).contains(&fields.len())
            || validate_unit_name(fields[0]).is_err()
            || !valid_state_token(fields[1])
            || fields
                .get(2)
                .is_some_and(|preset| !valid_state_token(preset))
        {
            mark_malformed_source_row(&mut parsed);
            continue;
        }
        let unit = ServiceUnit {
            name: fields[0].to_string(),
            load_state: None,
            active_state: None,
            sub_state: None,
            unit_file_state: Some(fields[1].to_string()),
            unit_file_preset: fields
                .get(2)
                .filter(|preset| **preset != "-")
                .map(|preset| (*preset).to_string()),
            loaded: false,
            runtime_present: false,
            sources: vec![ServiceSource::ListUnitFiles],
            description: None,
            description_truncated: false,
            result: None,
            exec_main_status: None,
            fragment_path: None,
            requires: Vec::new(),
            wants: Vec::new(),
            after: Vec::new(),
            before: Vec::new(),
            ports: Vec::new(),
        };
        if insert_source_unit(&mut parsed, unit) {
            break;
        }
    }
    parsed
}

fn insert_source_unit(parsed: &mut ParsedServiceSource, unit: ServiceUnit) -> bool {
    match parsed.units.get(&unit.name) {
        Some(existing) if existing == &unit => {
            parsed.duplicate_count = parsed.duplicate_count.saturating_add(1);
            false
        }
        Some(_) => {
            parsed.conflict_count = parsed.conflict_count.saturating_add(1);
            false
        }
        None if parsed.units.len() < MAX_SERVICE_LIMIT => {
            parsed.units.insert(unit.name.clone(), unit);
            false
        }
        None => {
            parsed.omitted_count = parsed.omitted_count.saturating_add(1);
            parsed.total_unknown = true;
            parsed.truncated = true;
            true
        }
    }
}

fn mark_malformed_source_row(parsed: &mut ParsedServiceSource) {
    parsed.parse_failure_count = parsed.parse_failure_count.saturating_add(1);
    parsed.omitted_count = parsed.omitted_count.saturating_add(1);
    parsed.total_unknown = true;
    parsed.truncated = true;
}

fn merge_service_maps(
    target: &mut BTreeMap<String, ServiceUnit>,
    source: BTreeMap<String, ServiceUnit>,
) {
    for (name, incoming) in source {
        if let Some(existing) = target.get_mut(&name) {
            existing.unit_file_state = incoming.unit_file_state;
            existing.unit_file_preset = incoming.unit_file_preset;
            if !existing.sources.contains(&ServiceSource::ListUnitFiles) {
                existing.sources.push(ServiceSource::ListUnitFiles);
            }
        } else {
            target.insert(name, incoming);
        }
    }
}

fn merge_show_units(
    target: &mut BTreeMap<String, ServiceUnit>,
    source: BTreeMap<String, ServiceUnit>,
) {
    for (name, mut incoming) in source {
        if let Some(existing) = target.get_mut(&name) {
            let unit_file_preset = existing.unit_file_preset.take();
            let unit_file_state = incoming
                .unit_file_state
                .take()
                .or_else(|| existing.unit_file_state.take());
            let show_has_description = incoming.description.is_some();
            let description = incoming
                .description
                .take()
                .or_else(|| existing.description.take());
            let mut sources = std::mem::take(&mut existing.sources);
            if !sources.contains(&ServiceSource::Show) {
                sources.push(ServiceSource::Show);
            }
            existing.load_state = incoming.load_state;
            existing.active_state = incoming.active_state;
            existing.sub_state = incoming.sub_state;
            existing.unit_file_state = unit_file_state;
            existing.unit_file_preset = unit_file_preset;
            existing.loaded = incoming.loaded;
            existing.runtime_present = true;
            existing.sources = sources;
            existing.description = description;
            if show_has_description {
                existing.description_truncated = incoming.description_truncated;
            }
            existing.result = incoming.result;
            existing.exec_main_status = incoming.exec_main_status;
            existing.fragment_path = incoming.fragment_path;
            existing.requires = incoming.requires;
            existing.wants = incoming.wants;
            existing.after = incoming.after;
            existing.before = incoming.before;
        } else {
            target.insert(name, incoming);
        }
    }
}

fn aggregate_service_collection_status(statuses: &[ServiceSourceStatus]) -> CollectionStatus {
    if statuses
        .iter()
        .all(|status| status.status == CollectionStatus::Failed)
    {
        CollectionStatus::Failed
    } else if statuses
        .iter()
        .all(|status| status.status == CollectionStatus::Complete)
    {
        CollectionStatus::Complete
    } else {
        CollectionStatus::Partial
    }
}

#[must_use]
pub fn parse_systemctl_list_units(content: &str) -> Vec<ServiceUnit> {
    parse_list_units_output(content, false)
        .units
        .into_values()
        .collect()
}

fn parse_show_records_output(content: &str, input_truncated: bool) -> ParsedServiceSource {
    let mut parsed = ParsedServiceSource {
        truncated: input_truncated || content.contains('\u{fffd}'),
        total_unknown: input_truncated || content.contains('\u{fffd}'),
        ..ParsedServiceSource::default()
    };
    let mut records = Vec::<String>::new();
    let mut current = String::new();
    let mut current_has_id = false;
    for line in content.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                records.push(std::mem::take(&mut current));
                current_has_id = false;
            }
            continue;
        }
        if line.starts_with("Id=") && current_has_id {
            records.push(std::mem::take(&mut current));
        }
        current_has_id |= line.starts_with("Id=");
        current.push_str(line);
        current.push('\n');
    }
    if !current.is_empty() {
        records.push(current);
    }

    for record in records {
        let Some(id) = record
            .lines()
            .find_map(|line| line.strip_prefix("Id="))
            .filter(|id| validate_unit_name(id).is_ok())
        else {
            mark_malformed_source_row(&mut parsed);
            continue;
        };
        let record = parse_show_output(&record, id, false);
        parsed.parse_failure_count = parsed
            .parse_failure_count
            .saturating_add(record.parse_failure_count);
        parsed.duplicate_count = parsed
            .duplicate_count
            .saturating_add(record.duplicate_count);
        parsed.conflict_count = parsed.conflict_count.saturating_add(record.conflict_count);
        parsed.omitted_count = parsed.omitted_count.saturating_add(record.omitted_count);
        parsed.total_unknown |= record.total_unknown;
        parsed.truncated |= record.truncated;
        parsed
            .failure_evaluable_names
            .extend(record.failure_evaluable_names);
        let mut cap_reached = false;
        for unit in record.units.into_values() {
            cap_reached |= insert_source_unit(&mut parsed, unit);
        }
        if cap_reached {
            break;
        }
    }
    parsed
}

#[must_use]
pub fn parse_systemctl_show(content: &str, fallback_name: &str) -> ServiceUnit {
    parse_show_output(content, fallback_name, false)
        .units
        .into_values()
        .next()
        .expect("show parser always emits the requested service")
}

fn parse_show_output(
    content: &str,
    fallback_name: &str,
    input_truncated: bool,
) -> ParsedServiceSource {
    let mut parsed = ParsedServiceSource {
        truncated: input_truncated || content.contains('\u{fffd}'),
        total_unknown: input_truncated,
        ..ParsedServiceSource::default()
    };
    let mut values = BTreeMap::<String, String>::new();
    for line in content.lines().filter(|line| !line.is_empty()) {
        let Some((key, value)) = line.split_once('=') else {
            parsed.parse_failure_count = parsed.parse_failure_count.saturating_add(1);
            continue;
        };
        if let Some(previous) = values.insert(key.to_string(), value.to_string()) {
            parsed.duplicate_count = parsed.duplicate_count.saturating_add(1);
            if previous != value {
                parsed.conflict_count = parsed.conflict_count.saturating_add(1);
            }
        }
    }
    if values.is_empty() {
        parsed.parse_failure_count = parsed.parse_failure_count.saturating_add(1);
    }
    let mut name = non_empty(&values, "Id").unwrap_or_else(|| fallback_name.to_string());
    if validate_unit_name(&name).is_err() {
        parsed.parse_failure_count = parsed.parse_failure_count.saturating_add(1);
        name = fallback_name.to_string();
    }
    let failure_evaluable = values
        .get("ActiveState")
        .is_some_and(|state| !state.is_empty())
        && values.contains_key("Result");
    let (description, description_truncated) = non_empty(&values, "Description")
        .map(|value| bounded_service_text(&value, MAX_SERVICE_DESCRIPTION_CHARS))
        .map_or((None, false), |(description, truncated)| {
            (Some(description), truncated)
        });
    parsed.truncated |= description_truncated;
    let exec_main_status = match non_empty(&values, "ExecMainStatus") {
        Some(value) => match value.parse::<i32>() {
            Ok(status) => Some(status),
            Err(_) => {
                parsed.parse_failure_count = parsed.parse_failure_count.saturating_add(1);
                None
            }
        },
        None => None,
    };
    let load_state = non_empty(&values, "LoadState");
    let unit = ServiceUnit {
        name: name.clone(),
        loaded: load_state.as_deref() == Some("loaded"),
        load_state,
        active_state: non_empty(&values, "ActiveState"),
        sub_state: non_empty(&values, "SubState"),
        unit_file_state: non_empty(&values, "UnitFileState"),
        unit_file_preset: None,
        runtime_present: true,
        sources: vec![ServiceSource::Show],
        description,
        description_truncated,
        result: non_empty(&values, "Result"),
        exec_main_status,
        fragment_path: non_empty(&values, "FragmentPath"),
        requires: split_units(values.get("Requires")),
        wants: split_units(values.get("Wants")),
        after: split_units(values.get("After")),
        before: split_units(values.get("Before")),
        ports: Vec::new(),
    };
    if failure_evaluable {
        parsed.failure_evaluable_names.insert(name.clone());
    }
    parsed.units.insert(name, unit);
    parsed
}

fn non_empty(values: &BTreeMap<String, String>, key: &str) -> Option<String> {
    values.get(key).filter(|value| !value.is_empty()).cloned()
}

fn split_units(value: Option<&String>) -> Vec<String> {
    value
        .map(|value| value.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

fn validate_unit_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.chars().count() > MAX_SERVICE_NAME_CHARS
        || name.starts_with('-')
        || !name.ends_with(".service")
        || !name.is_ascii()
        || name
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || name.contains('/')
        || name.contains("..")
    {
        return Err(OsSenseError::Configuration(
            "service name must be a bounded systemd .service unit without options, paths, whitespace, or control characters"
                .to_string(),
        ));
    }
    let bytes = name.as_bytes();
    let mut index = 0usize;
    let mut at_count = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'@' {
            at_count += 1;
        }
        if byte == b'\\' {
            if index + 3 >= bytes.len()
                || bytes[index + 1] != b'x'
                || !bytes[index + 2].is_ascii_hexdigit()
                || !bytes[index + 3].is_ascii_hexdigit()
            {
                return Err(OsSenseError::Configuration(
                    "systemd unit escape must use \\xNN form".to_string(),
                ));
            }
            index += 4;
            continue;
        }
        if !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'@' | b'_' | b'-' | b':')) {
            return Err(OsSenseError::Configuration(
                "service name contains unsupported characters".to_string(),
            ));
        }
        index += 1;
    }
    if at_count > 1 {
        return Err(OsSenseError::Configuration(
            "service name must contain at most one template separator".to_string(),
        ));
    }
    Ok(())
}

fn valid_state_token(value: &str) -> bool {
    value.len() <= 64
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn push_service_warning(warnings: &mut Vec<String>, omitted: &mut usize, warning: String) {
    if warnings.len() < MAX_SERVICE_WARNINGS {
        warnings.push(bounded_service_error(&warning));
    } else {
        *omitted = omitted.saturating_add(1);
    }
}

fn bounded_service_error(value: &str) -> String {
    redact_sensitive_text(value, MAX_SERVICE_ERROR_CHARS.saturating_sub(16))
        .chars()
        .take(MAX_SERVICE_ERROR_CHARS)
        .collect()
}

fn bounded_service_text(value: &str, maximum: usize) -> (String, bool) {
    let mut chars = value.chars();
    let bounded = chars.by_ref().take(maximum).collect::<String>();
    (bounded, chars.next().is_some())
}

fn service_failed(unit: &ServiceUnit) -> bool {
    unit.active_state.as_deref() == Some("failed")
        || unit
            .result
            .as_deref()
            .is_some_and(|result| result != "success")
}

#[allow(dead_code)]
fn summarize_probe(probe: &HealthProbeResult) -> String {
    format!(
        "{}={}",
        probe.target,
        if probe.ok { "ok" } else { "failed" }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct FixtureRunner {
        outputs: Mutex<VecDeque<io::Result<LimitedCommandOutput>>>,
        calls: Mutex<Vec<(String, Vec<String>, Duration, usize, usize)>>,
    }

    impl FixtureRunner {
        fn new(outputs: Vec<io::Result<LimitedCommandOutput>>) -> Self {
            Self {
                outputs: Mutex::new(outputs.into()),
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl ServiceCommandRunner for FixtureRunner {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            timeout: Duration,
            stdout_limit: usize,
            stderr_limit: usize,
        ) -> io::Result<LimitedCommandOutput> {
            self.calls.lock().expect("calls").push((
                program.to_string(),
                args.iter().map(|arg| (*arg).to_string()).collect(),
                timeout,
                stdout_limit,
                stderr_limit,
            ));
            self.outputs
                .lock()
                .expect("outputs")
                .pop_front()
                .expect("fixture output")
        }
    }

    fn output(stdout: impl Into<String>) -> io::Result<LimitedCommandOutput> {
        Ok(LimitedCommandOutput {
            success: true,
            exit_code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
            timed_out: false,
            stdout_truncated: false,
            stderr_truncated: false,
        })
    }

    fn truncated_output(stdout: impl Into<String>) -> io::Result<LimitedCommandOutput> {
        Ok(LimitedCommandOutput {
            success: true,
            exit_code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
            timed_out: false,
            stdout_truncated: true,
            stderr_truncated: false,
        })
    }

    #[test]
    fn merges_runtime_and_installed_inventory_with_fixed_commands() {
        let runner = FixtureRunner::new(vec![
            output("ssh.service loaded active running OpenSSH server daemon\n● bad.service loaded failed failed Broken service\n"),
            output("ssh.service enabled enabled\nbad.service disabled disabled\nonly.service masked -\nfoo@.service static -\n"),
            output(""),
        ]);
        let snapshot = query_services_with_runner(&ServiceQuery::default(), &runner)
            .expect("service inventory");
        assert_eq!(snapshot.collection_status, CollectionStatus::Complete);
        assert_eq!(snapshot.total, 4);
        assert_eq!(snapshot.units[0].name, "bad.service");
        assert_eq!(snapshot.failed_units.len(), 1);
        let only = snapshot
            .units
            .iter()
            .find(|unit| unit.name == "only.service")
            .expect("installed-only unit");
        assert!(!only.runtime_present);
        assert_eq!(only.unit_file_state.as_deref(), Some("masked"));
        let calls = runner.calls.lock().expect("calls");
        assert_eq!(calls[0].1, LIST_UNITS_ARGS);
        assert_eq!(calls[1].1, LIST_UNIT_FILES_ARGS);
        assert_eq!(
            calls[2].1,
            vec![
                "show",
                SHOW_ALL_PATTERN,
                "--all",
                "--no-pager",
                "--property",
                SHOW_PROPERTIES,
            ]
        );
        assert!(calls.iter().all(|call| call.2 == COMMAND_TIMEOUT));
        assert!(calls.iter().all(|call| call.3 == SERVICE_STDOUT_LIMIT));
        assert!(calls.iter().all(|call| call.4 == SERVICE_STDERR_LIMIT));
    }

    #[test]
    fn source_failure_is_partial_and_both_failures_are_failed() {
        let partial_runner = FixtureRunner::new(vec![
            output("ssh.service loaded active running SSH\n"),
            Err(io::Error::new(io::ErrorKind::NotFound, "missing")),
            output(""),
        ]);
        let partial = query_services_with_runner(&ServiceQuery::default(), &partial_runner)
            .expect("partial inventory");
        assert_eq!(partial.collection_status, CollectionStatus::Partial);
        assert_eq!(partial.total, 1);
        assert!(!partial.filter_complete);

        let failed_runner = FixtureRunner::new(vec![
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
            Err(io::Error::new(io::ErrorKind::NotFound, "missing")),
            Err(io::Error::new(io::ErrorKind::TimedOut, "timed out")),
        ]);
        let failed = query_services_with_runner(&ServiceQuery::default(), &failed_runner)
            .expect("failed inventory remains structured");
        assert_eq!(failed.collection_status, CollectionStatus::Failed);
        assert!(!failed.available || failed.source_statuses[0].available);
    }

    #[test]
    fn filters_and_limits_after_merge_and_include_all_filters_merged_inventory() {
        let runner = FixtureRunner::new(vec![
            output("a.service loaded active running A\nb.service loaded inactive dead B\n"),
            output("a.service enabled\nb.service disabled\nc.service static\n"),
            output(""),
        ]);
        let snapshot = query_services_with_runner(
            &ServiceQuery {
                limit: Some(2),
                ..ServiceQuery::default()
            },
            &runner,
        )
        .expect("limited inventory");
        assert_eq!(snapshot.total, 3);
        assert_eq!(snapshot.returned_count, 2);
        assert_eq!(snapshot.omitted_count, 1);
        assert!(snapshot.truncated);

        let active_only_runner = FixtureRunner::new(vec![
            output("a.service loaded active running A\n"),
            output("a.service enabled\ninstalled.service enabled\n"),
            output(""),
        ]);
        let active_only = query_services_with_runner(
            &ServiceQuery {
                include_all: false,
                ..ServiceQuery::default()
            },
            &active_only_runner,
        )
        .expect("runtime inventory");
        assert_eq!(active_only.total, 1);
        assert_eq!(active_only.source_statuses.len(), 3);
        assert_eq!(active_only_runner.calls.lock().expect("calls").len(), 3);
    }

    #[test]
    fn malformed_duplicates_conflicts_and_bounds_are_visible() {
        let mut runtime = String::new();
        runtime.push_str("dup.service loaded active running First\n");
        runtime.push_str("dup.service loaded active running First\n");
        runtime.push_str("dup.service loaded inactive dead Different\n");
        runtime.push_str("malformed\n");
        for index in 0..(MAX_SERVICE_LIMIT + 1) {
            runtime.push_str(&format!(
                "u{index}.service loaded inactive dead Unit {index}\n"
            ));
        }
        let parsed = parse_list_units_output(&runtime, false);
        assert!(parsed.truncated);
        assert!(parsed.duplicate_count >= 1);
        assert!(parsed.conflict_count >= 1);
        assert!(parsed.parse_failure_count >= 1);
        assert!(parsed.units.len() <= MAX_SERVICE_LIMIT);
    }

    #[test]
    fn validates_queries_and_parses_show_compatibly() {
        for name in [
            "--failed.service",
            "ssh",
            "../ssh.service",
            "bad name.service",
        ] {
            assert!(ServiceQuery {
                name: Some(name.to_string()),
                ..ServiceQuery::default()
            }
            .validate()
            .is_err());
        }
        for name in [
            "ssh.service",
            "foo@.service",
            "foo@bar.service",
            "foo\\x2dbar.service",
        ] {
            assert!(validate_unit_name(name).is_ok(), "{name}");
        }
        assert!(ServiceQuery {
            limit: Some(0),
            ..ServiceQuery::default()
        }
        .validate()
        .is_err());
        assert!(ServiceQuery {
            health_probes: vec![
                TcpProbeRequest {
                    host: "localhost".to_string(),
                    port: 1,
                    timeout_ms: Some(1),
                };
                MAX_HEALTH_PROBES + 1
            ],
            ..ServiceQuery::default()
        }
        .validate()
        .is_err());

        let unit = parse_systemctl_show(
            "Id=ssh.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\nRequires=network.target\nAfter=network.target auditd.service\n",
            "ssh.service",
        );
        assert_eq!(unit.requires, vec!["network.target"]);
        assert_eq!(unit.after, vec!["network.target", "auditd.service"]);
        assert_eq!(unit.exec_main_status, Some(0));
    }

    #[test]
    fn name_query_runs_bounded_show_and_inserts_unenumerated_instance() {
        let runner = FixtureRunner::new(vec![
            output("other.service loaded active running Other\n"),
            output("other.service enabled enabled\n"),
            output(
                "Id=worker@42.service\n\
                 LoadState=loaded\n\
                 ActiveState=active\n\
                 SubState=running\n\
                 UnitFileState=enabled\n\
                 Description=Worker instance 42\n\
                 Result=exit-code\n\
                 ExecMainStatus=7\n\
                 FragmentPath=/etc/systemd/system/worker@.service\n\
                 Requires=network.target\n\
                 Wants=time-sync.target\n\
                 After=network.target time-sync.target\n\
                 Before=multi-user.target\n",
            ),
        ]);
        let snapshot = query_services_with_runner(
            &ServiceQuery {
                name: Some("worker@42.service".to_string()),
                ..ServiceQuery::default()
            },
            &runner,
        )
        .expect("show inventory");

        assert_eq!(snapshot.collection_status, CollectionStatus::Complete);
        assert_eq!(snapshot.source_statuses.len(), 3);
        assert_eq!(snapshot.source_statuses[2].source, ServiceSource::Show);
        assert_eq!(snapshot.units.len(), 1);
        let unit = &snapshot.units[0];
        assert_eq!(unit.name, "worker@42.service");
        assert_eq!(unit.result.as_deref(), Some("exit-code"));
        assert_eq!(unit.exec_main_status, Some(7));
        assert_eq!(unit.requires, vec!["network.target"]);
        assert_eq!(unit.wants, vec!["time-sync.target"]);
        assert_eq!(unit.after, vec!["network.target", "time-sync.target"]);
        assert_eq!(unit.before, vec!["multi-user.target"]);
        assert_eq!(unit.sources, vec![ServiceSource::Show]);
        assert_eq!(snapshot.failed_total, 1);
        assert_eq!(snapshot.failed_returned_count, 1);
        assert_eq!(snapshot.failed_units[0].name, "worker@42.service");

        let calls = runner.calls.lock().expect("calls");
        assert_eq!(calls.len(), 3);
        assert_eq!(calls[0].1, LIST_UNITS_ARGS);
        assert_eq!(calls[1].1, LIST_UNIT_FILES_ARGS);
        assert_eq!(
            calls[2].1,
            vec![
                "show",
                "worker@42.service",
                "--no-pager",
                "--property",
                SHOW_PROPERTIES,
            ]
        );
        assert_eq!(calls[2].2, COMMAND_TIMEOUT);
        assert_eq!(calls[2].3, SERVICE_STDOUT_LIMIT);
        assert_eq!(calls[2].4, SERVICE_STDERR_LIMIT);
    }

    #[test]
    fn show_merges_exact_fields_and_preserves_inventory_preset() {
        let runner = FixtureRunner::new(vec![
            output("ssh.service loaded active running Inventory description\n"),
            output("ssh.service enabled disabled\n"),
            output(
                "Id=ssh.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nUnitFileState=disabled\nDescription=Exact description\nResult=signal\nExecMainStatus=9\nRequires=network.target\n",
            ),
        ]);
        let snapshot = query_services_with_runner(
            &ServiceQuery {
                name: Some("ssh.service".to_string()),
                ..ServiceQuery::default()
            },
            &runner,
        )
        .expect("merged show inventory");
        let unit = &snapshot.units[0];
        assert_eq!(unit.active_state.as_deref(), Some("failed"));
        assert_eq!(unit.unit_file_state.as_deref(), Some("disabled"));
        assert_eq!(unit.unit_file_preset.as_deref(), Some("disabled"));
        assert_eq!(unit.description.as_deref(), Some("Exact description"));
        assert_eq!(
            unit.sources,
            vec![
                ServiceSource::ListUnits,
                ServiceSource::ListUnitFiles,
                ServiceSource::Show,
            ]
        );
    }

    #[test]
    fn show_failure_is_structured_and_affects_top_level_status() {
        let command_failure = || {
            Ok(LimitedCommandOutput {
                success: false,
                exit_code: Some(5),
                stdout: String::new(),
                stderr: "show denied".to_string(),
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            })
        };
        let partial_runner = FixtureRunner::new(vec![
            output("ssh.service loaded active running SSH\n"),
            output("ssh.service enabled enabled\n"),
            command_failure(),
        ]);
        let partial = query_services_with_runner(
            &ServiceQuery {
                name: Some("ssh.service".to_string()),
                ..ServiceQuery::default()
            },
            &partial_runner,
        )
        .expect("structured show failure");
        assert_eq!(partial.collection_status, CollectionStatus::Partial);
        assert_eq!(partial.units.len(), 1);
        let show = &partial.source_statuses[2];
        assert_eq!(show.source, ServiceSource::Show);
        assert_eq!(show.status, CollectionStatus::Failed);
        assert_eq!(show.exit_code, Some(5));
        assert!(show.total_unknown);
        assert!(show
            .error
            .as_deref()
            .is_some_and(|error| error.contains("show denied")));

        let failed_runner = FixtureRunner::new(vec![
            command_failure(),
            command_failure(),
            command_failure(),
        ]);
        let failed = query_services_with_runner(
            &ServiceQuery {
                name: Some("ssh.service".to_string()),
                ..ServiceQuery::default()
            },
            &failed_runner,
        )
        .expect("all failures remain structured");
        assert_eq!(failed.collection_status, CollectionStatus::Failed);
        assert!(!failed.available);
        assert!(failed.units.is_empty());
    }

    #[test]
    fn failed_units_are_computed_before_result_limit() {
        let runner = FixtureRunner::new(vec![
            output(
                "a.service loaded active running Healthy\n\
                 z.service loaded failed failed Failed outside result page\n",
            ),
            output("a.service enabled enabled\nz.service enabled enabled\n"),
            output(""),
        ]);
        let snapshot = query_services_with_runner(
            &ServiceQuery {
                limit: Some(1),
                ..ServiceQuery::default()
            },
            &runner,
        )
        .expect("limited inventory");
        assert_eq!(snapshot.units.len(), 1);
        assert_eq!(snapshot.units[0].name, "a.service");
        assert_eq!(snapshot.failed_total, 1);
        assert_eq!(snapshot.failed_returned_count, 1);
        assert_eq!(snapshot.failed_omitted_count, 0);
        assert_eq!(snapshot.failed_units[0].name, "z.service");
    }

    #[test]
    fn description_boundary_marks_only_513_chars_partial() {
        let exact_description = "x".repeat(MAX_SERVICE_DESCRIPTION_CHARS);
        let exact = parse_list_units_output(
            &format!("exact.service loaded active running {exact_description}\n"),
            false,
        );
        assert!(!exact.truncated);
        assert!(!exact.units["exact.service"].description_truncated);
        assert_eq!(
            exact.units["exact.service"]
                .description
                .as_deref()
                .map(str::chars)
                .map(Iterator::count),
            Some(MAX_SERVICE_DESCRIPTION_CHARS)
        );

        let long_description = "y".repeat(MAX_SERVICE_DESCRIPTION_CHARS + 1);
        let runner = FixtureRunner::new(vec![
            output(format!(
                "long.service loaded active running {long_description}\n"
            )),
            output("long.service enabled enabled\n"),
            output(""),
        ]);
        let snapshot = query_services_with_runner(&ServiceQuery::default(), &runner)
            .expect("bounded description inventory");
        assert_eq!(snapshot.collection_status, CollectionStatus::Partial);
        assert_eq!(
            snapshot.source_statuses[0].status,
            CollectionStatus::Partial
        );
        assert!(snapshot.source_statuses[0].truncated);
        assert!(snapshot.units[0].description_truncated);
        assert_eq!(
            snapshot.units[0]
                .description
                .as_deref()
                .map(str::chars)
                .map(Iterator::count),
            Some(MAX_SERVICE_DESCRIPTION_CHARS)
        );
    }

    #[test]
    fn unique_unit_cap_uses_4097th_entry_as_lookahead() {
        fn inventory(count: usize) -> String {
            let mut content = String::new();
            for index in 0..count {
                content.push_str(&format!(
                    "u{index:04}.service loaded inactive dead Unit {index}\n"
                ));
            }
            content
        }

        let exact_runner = FixtureRunner::new(vec![
            output(inventory(MAX_SERVICE_LIMIT)),
            output(""),
            output(""),
        ]);
        let exact = query_services_with_runner(&ServiceQuery::default(), &exact_runner)
            .expect("exactly capped inventory");
        assert_eq!(exact.source_statuses[0].status, CollectionStatus::Complete);
        assert_eq!(exact.source_statuses[0].entry_count, MAX_SERVICE_LIMIT);
        assert_eq!(exact.source_statuses[0].omitted_count, 0);
        assert!(!exact.source_statuses[0].total_unknown);
        assert!(!exact.source_statuses[0].truncated);
        assert!(!exact.truncated);

        let overflow_runner = FixtureRunner::new(vec![
            output(inventory(MAX_SERVICE_LIMIT + 1)),
            output(""),
            output(""),
        ]);
        let overflow = query_services_with_runner(&ServiceQuery::default(), &overflow_runner)
            .expect("lookahead inventory");
        assert_eq!(
            overflow.source_statuses[0].status,
            CollectionStatus::Partial
        );
        assert_eq!(overflow.source_statuses[0].entry_count, MAX_SERVICE_LIMIT);
        assert!(overflow.source_statuses[0].omitted_count >= 1);
        assert!(overflow.source_statuses[0].total_unknown);
        assert!(overflow.source_statuses[0].truncated);
        assert!(overflow.truncated);
    }

    #[test]
    fn batch_show_merges_multiple_records_and_detects_result_failure() {
        let runner = FixtureRunner::new(vec![
            output(
                "bad-result.service loaded active running Still active\nhealthy.service loaded inactive dead Healthy inactive\n",
            ),
            output("bad-result.service enabled enabled\nhealthy.service enabled enabled\n"),
            output(
                "Id=healthy.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=\n\nId=bad-result.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=exit-code\nExecMainStatus=3\n",
            ),
        ]);
        let snapshot = query_services_with_runner(&ServiceQuery::default(), &runner)
            .expect("batch show inventory");

        assert_eq!(snapshot.collection_status, CollectionStatus::Complete);
        assert!(snapshot.failed_filter_complete);
        assert_eq!(snapshot.failed_total, 1);
        assert_eq!(snapshot.failed_units[0].name, "bad-result.service");
        assert_eq!(
            snapshot.failed_units[0].active_state.as_deref(),
            Some("active")
        );
        assert_eq!(
            snapshot.failed_units[0].result.as_deref(),
            Some("exit-code")
        );
        assert_eq!(snapshot.source_statuses[2].source, ServiceSource::Show);
        assert_eq!(snapshot.source_statuses[2].entry_count, 2);
        let inactive = snapshot
            .units
            .iter()
            .find(|unit| unit.name == "healthy.service")
            .expect("inactive runtime unit");
        assert_eq!(inactive.active_state.as_deref(), Some("inactive"));
    }

    #[test]
    fn batch_show_missing_runtime_record_makes_failure_filter_incomplete() {
        let runner = FixtureRunner::new(vec![
            output(
                "active.service loaded active running Active\ninactive.service loaded inactive dead Inactive\n",
            ),
            output("active.service enabled enabled\ninactive.service disabled enabled\n"),
            output(
                "Id=active.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=success\n",
            ),
        ]);
        let snapshot = query_services_with_runner(&ServiceQuery::default(), &runner)
            .expect("incomplete batch show coverage");

        assert_eq!(
            snapshot.source_statuses[0].status,
            CollectionStatus::Complete
        );
        assert_eq!(
            snapshot.source_statuses[2].status,
            CollectionStatus::Complete
        );
        assert!(snapshot.filter_complete);
        assert!(!snapshot.failed_filter_complete);
        let calls = runner.calls.lock().expect("calls");
        assert_eq!(
            calls[2].1,
            vec![
                "show",
                SHOW_ALL_PATTERN,
                "--all",
                "--no-pager",
                "--property",
                SHOW_PROPERTIES,
            ]
        );
    }

    #[test]
    fn batch_show_failure_or_truncation_marks_failure_filter_incomplete() {
        let failed_runner = FixtureRunner::new(vec![
            output("ssh.service loaded active running SSH\n"),
            output("ssh.service enabled enabled\n"),
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
        ]);
        let failed = query_services_with_runner(&ServiceQuery::default(), &failed_runner)
            .expect("structured batch show failure");
        assert_eq!(failed.collection_status, CollectionStatus::Partial);
        assert!(!failed.failed_filter_complete);
        assert!(!failed.filter_complete);
        assert_eq!(failed.source_statuses[2].status, CollectionStatus::Failed);

        let truncated_runner = FixtureRunner::new(vec![
            output("ssh.service loaded active running SSH\n"),
            output("ssh.service enabled enabled\n"),
            truncated_output(
                "Id=ssh.service\nLoadState=loaded\nActiveState=active\nResult=success\n",
            ),
        ]);
        let truncated = query_services_with_runner(&ServiceQuery::default(), &truncated_runner)
            .expect("structured batch show truncation");
        assert_eq!(truncated.collection_status, CollectionStatus::Partial);
        assert!(!truncated.failed_filter_complete);
        assert!(!truncated.filter_complete);
        assert!(truncated.source_statuses[2].truncated);
        assert!(truncated.source_statuses[2].total_unknown);
    }

    #[test]
    fn malformed_nonempty_inventory_rows_increment_omitted_counts() {
        let runner = FixtureRunner::new(vec![
            output("valid.service loaded active running Valid\nmalformed\nalso malformed\n"),
            output("valid.service enabled enabled\nmalformed\ntoo many columns here\n"),
            output(""),
        ]);
        let snapshot = query_services_with_runner(&ServiceQuery::default(), &runner)
            .expect("partial malformed inventory");

        for status in &snapshot.source_statuses[..2] {
            assert_eq!(status.entry_count, 1);
            assert_eq!(status.parse_failure_count, 2);
            assert_eq!(status.omitted_count, 2);
            assert!(status.total_unknown);
            assert!(status.truncated);
            assert_eq!(status.status, CollectionStatus::Partial);
        }
        assert!(snapshot.truncated);
        assert!(!snapshot.filter_complete);
    }

    #[test]
    fn legacy_service_json_derives_missing_counts_and_unit_provenance() {
        let legacy_unit = serde_json::json!({
            "name": "legacy.service",
            "load_state": "loaded",
            "active_state": "active",
            "sub_state": "exited",
            "unit_file_state": "enabled",
            "description": "Legacy service",
            "result": "exit-code",
            "exec_main_status": 4,
            "fragment_path": "/usr/lib/systemd/system/legacy.service",
            "requires": ["network.target"],
            "wants": [],
            "after": ["network.target"],
            "before": [],
            "ports": []
        });
        let legacy = serde_json::json!({
            "meta": {
                "collected_at_ms": 1,
                "source": "services",
                "platform": {
                    "os": "linux",
                    "arch": "x86_64",
                    "kernel_version": null,
                    "loongarch": {
                        "detected": false,
                        "cpu_model": null,
                        "hwmon_paths": []
                    }
                },
                "warnings": []
            },
            "available": true,
            "truncated": false,
            "units": [legacy_unit],
            "failed_units": [],
            "health_probes": []
        });
        let snapshot =
            serde_json::from_value::<ServiceSnapshot>(legacy).expect("legacy service snapshot");

        assert_eq!(snapshot.total, 1);
        assert_eq!(snapshot.returned_count, 1);
        assert_eq!(snapshot.omitted_count, 0);
        assert_eq!(snapshot.failed_total, 1);
        assert_eq!(snapshot.failed_returned_count, 0);
        assert_eq!(snapshot.failed_omitted_count, 1);
        assert!(!snapshot.failed_filter_complete);
        assert!(snapshot.units[0].loaded);
        assert!(snapshot.units[0].runtime_present);
        assert_eq!(
            snapshot.units[0].sources,
            vec![ServiceSource::ListUnits, ServiceSource::ListUnitFiles]
        );

        let mut explicit = serde_json::to_value(&snapshot).expect("new service JSON");
        assert!(explicit.get("failed_filter_complete").is_some());
        assert!(explicit["units"][0].get("loaded").is_some());
        explicit["total"] = serde_json::json!(0);
        explicit["returned_count"] = serde_json::json!(0);
        explicit["failed_total"] = serde_json::json!(0);
        explicit["failed_filter_complete"] = serde_json::json!(true);
        explicit["units"][0]["loaded"] = serde_json::json!(false);
        explicit["units"][0]["runtime_present"] = serde_json::json!(false);
        explicit["units"][0]["sources"] = serde_json::json!([]);
        let explicit =
            serde_json::from_value::<ServiceSnapshot>(explicit).expect("explicit new service JSON");
        assert_eq!(explicit.total, 0);
        assert_eq!(explicit.returned_count, 0);
        assert_eq!(explicit.failed_total, 0);
        assert!(explicit.failed_filter_complete);
        assert!(!explicit.units[0].loaded);
        assert!(!explicit.units[0].runtime_present);
        assert!(explicit.units[0].sources.is_empty());
    }
}
