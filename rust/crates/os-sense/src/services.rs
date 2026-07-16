use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::command::{run_limited_command, LimitedCommandOutput};
use crate::error::{OsSenseError, Result};
use crate::model::{
    CollectionStatus, HealthProbeResult, ServiceHealthStatus, ServiceProblem,
    ServiceProblemEvidence, ServiceProblemKind, ServiceSnapshot, ServiceSource,
    ServiceSourceStatus, ServiceUnit,
};
use crate::network::{probe_tcp, NetworkQuery, TcpProbeRequest};
use crate::procfs::basic_meta;
use crate::redaction::redact_sensitive_text;

const MAX_SERVICE_LIMIT: usize = 4_096;
const MAX_SERVICE_DETAIL_LIMIT: usize = 128;
const MAX_SERVICE_SOURCE_LINES: usize = 8_192;
const MAX_SERVICE_WARNINGS: usize = 32;
const MAX_SERVICE_ERROR_CHARS: usize = 256;
const MAX_SERVICE_NAME_CHARS: usize = 256;
const MAX_SERVICE_DESCRIPTION_CHARS: usize = 512;
const MAX_SERVICE_EVIDENCE_TEXT_CHARS: usize = 256;
const MAX_SERVICE_PROPERTY_TOKEN_CHARS: usize = 64;
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
const SHOW_PROPERTIES: &str = "Id,LoadState,ActiveState,SubState,UnitFileState,Description,Result,ExecMainCode,ExecMainStatus,StatusText,StatusErrno,NRestarts,LoadError,FragmentPath,Requires,Wants,After,Before";
const SERVICE_PROBLEM_CORE_PROPERTIES: [&str; 8] = [
    "LoadState",
    "ActiveState",
    "SubState",
    "Result",
    "ExecMainCode",
    "ExecMainStatus",
    "StatusErrno",
    "LoadError",
];
const SERVICE_PROBLEM_OPTIONAL_PROPERTIES: [&str; 2] = ["StatusText", "NRestarts"];

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
    problem_evaluable_names: BTreeSet<String>,
    parse_failure_count: usize,
    duplicate_count: usize,
    conflict_count: usize,
    omitted_count: usize,
    total_unknown: bool,
    truncated: bool,
}

#[derive(Default)]
struct ServiceSourceCoverage {
    failure_evaluable_names: BTreeSet<String>,
    problem_evaluable_names: BTreeSet<String>,
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
    let (show_units, show_status, show_coverage) = if let Some(name) = query.name.as_deref() {
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
    let required_runtime_names = if query.name.is_some() {
        show_unit_name.iter().cloned().collect::<BTreeSet<String>>()
    } else {
        runtime_unit_names
    };
    let show_failure_coverage_complete =
        required_runtime_names.is_subset(&show_coverage.failure_evaluable_names);
    let show_problem_coverage_complete =
        required_runtime_names.is_subset(&show_coverage.problem_evaluable_names);
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
    let problem_filter_complete = source_statuses.iter().any(|status| {
        status.source == ServiceSource::ListUnits && status.status == CollectionStatus::Complete
    }) && source_statuses.iter().any(|status| {
        status.source == ServiceSource::Show && status.status == CollectionStatus::Complete
    }) && show_problem_coverage_complete;
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
    let limit = query.limit.unwrap_or(MAX_SERVICE_LIMIT);
    let detail_limit = limit.min(MAX_SERVICE_DETAIL_LIMIT);
    let mut failed_units = units
        .iter()
        .filter(|unit| service_failed(unit))
        .cloned()
        .collect::<Vec<_>>();
    let failed_total = failed_units.len();
    failed_units.truncate(detail_limit);
    let failed_returned_count = failed_units.len();
    let failed_omitted_count = failed_total.saturating_sub(failed_returned_count);
    let mut problem_units = units
        .iter()
        .filter(|unit| service_has_problem(unit))
        .cloned()
        .collect::<Vec<_>>();
    let problem_total = problem_units.len();
    problem_units.truncate(detail_limit);
    let problem_returned_count = problem_units.len();
    let problem_omitted_count = problem_total.saturating_sub(problem_returned_count);
    let omitted_count = total.saturating_sub(limit);
    units.truncate(limit);
    let returned_count = units.len();
    let truncated = source_truncated
        || omitted_count > 0
        || failed_omitted_count > 0
        || problem_omitted_count > 0;
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
        problem_total,
        problem_returned_count,
        problem_omitted_count,
        problem_filter_complete,
        filter_complete,
        omitted_warning_count,
        units,
        failed_units,
        problem_units,
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
    ServiceSourceCoverage,
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
                ServiceSourceCoverage::default(),
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
            ServiceSourceCoverage::default(),
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
    let coverage = ServiceSourceCoverage {
        failure_evaluable_names: parsed.failure_evaluable_names,
        problem_evaluable_names: parsed.problem_evaluable_names,
    };
    (parsed.units, source_status, coverage)
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
        let evidence = ServiceProblemEvidence {
            load_state: Some(fields[1].to_string()),
            active_state: Some(fields[2].to_string()),
            sub_state: Some(fields[3].to_string()),
            incomplete_properties: service_problem_property_names(),
            ..ServiceProblemEvidence::default()
        };
        let (health_status, problems) = analyze_service_health(&evidence);
        let problem_evidence = (!problems.is_empty()).then_some(evidence);
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
            health_status,
            problems,
            problem_evidence,
            problem_complete: false,
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
            health_status: ServiceHealthStatus::Inactive,
            problems: Vec::new(),
            problem_evidence: None,
            problem_complete: true,
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
            existing.health_status = incoming.health_status;
            existing.problems = incoming.problems;
            existing.problem_evidence = incoming.problem_evidence;
            existing.problem_complete = incoming.problem_complete;
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
        parsed
            .problem_evaluable_names
            .extend(record.problem_evaluable_names);
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
    let mut incomplete_properties = SERVICE_PROBLEM_CORE_PROPERTIES
        .iter()
        .filter(|property| !values.contains_key(**property))
        .map(|property| (*property).to_string())
        .collect::<Vec<_>>();
    let mut unavailable_properties = SERVICE_PROBLEM_OPTIONAL_PROPERTIES
        .iter()
        .filter(|property| !values.contains_key(**property))
        .map(|property| (*property).to_string())
        .collect::<Vec<_>>();
    if input_truncated || content.contains('\u{fffd}') {
        incomplete_properties.push("source_output".to_string());
    }
    let (active_state, active_state_truncated) =
        bounded_property_token(&values, "ActiveState", MAX_SERVICE_PROPERTY_TOKEN_CHARS);
    let (result, result_truncated) =
        bounded_property_token(&values, "Result", MAX_SERVICE_PROPERTY_TOKEN_CHARS);
    let (load_state, load_state_truncated) =
        bounded_property_token(&values, "LoadState", MAX_SERVICE_PROPERTY_TOKEN_CHARS);
    let (sub_state, sub_state_truncated) =
        bounded_property_token(&values, "SubState", MAX_SERVICE_PROPERTY_TOKEN_CHARS);
    if active_state_truncated {
        incomplete_properties.push("ActiveState".to_string());
        parsed.truncated = true;
    }
    if result_truncated {
        incomplete_properties.push("Result".to_string());
        parsed.truncated = true;
    }
    if load_state_truncated {
        incomplete_properties.push("LoadState".to_string());
        parsed.truncated = true;
    }
    if sub_state_truncated {
        incomplete_properties.push("SubState".to_string());
        parsed.truncated = true;
    }
    let failure_evaluable = active_state.is_some()
        && values.contains_key("Result")
        && !active_state_truncated
        && !result_truncated;
    let (description, description_truncated) = non_empty(&values, "Description")
        .map(|value| bounded_service_text(&value, MAX_SERVICE_DESCRIPTION_CHARS))
        .map_or((None, false), |(description, truncated)| {
            (Some(description), truncated)
        });
    parsed.truncated |= description_truncated;
    let exec_main_code = parse_i32_property(
        &values,
        "ExecMainCode",
        &mut parsed,
        &mut incomplete_properties,
    );
    let exec_main_status = parse_i32_property(
        &values,
        "ExecMainStatus",
        &mut parsed,
        &mut incomplete_properties,
    );
    let status_errno = parse_i32_property(
        &values,
        "StatusErrno",
        &mut parsed,
        &mut incomplete_properties,
    );
    let n_restarts = parse_optional_u64_property(
        &values,
        "NRestarts",
        &mut parsed,
        &mut incomplete_properties,
        &mut unavailable_properties,
    );
    let (status_text, status_text_truncated) =
        bounded_sensitive_property(&values, "StatusText", MAX_SERVICE_EVIDENCE_TEXT_CHARS);
    let (load_error, load_error_truncated) =
        bounded_sensitive_property(&values, "LoadError", MAX_SERVICE_EVIDENCE_TEXT_CHARS);
    if status_text_truncated {
        incomplete_properties.push("StatusText".to_string());
        parsed.truncated = true;
    }
    if load_error_truncated {
        incomplete_properties.push("LoadError".to_string());
        parsed.truncated = true;
    }
    if load_state.is_none() {
        incomplete_properties.push("LoadState".to_string());
    }
    if active_state.is_none() {
        incomplete_properties.push("ActiveState".to_string());
    }
    if sub_state.is_none() {
        incomplete_properties.push("SubState".to_string());
    }
    incomplete_properties.sort();
    incomplete_properties.dedup();
    unavailable_properties.sort();
    unavailable_properties.dedup();
    let evidence = ServiceProblemEvidence {
        load_state: load_state.clone(),
        active_state: active_state.clone(),
        sub_state: sub_state.clone(),
        result: result.clone(),
        exec_main_code,
        exec_main_status,
        status_text,
        status_text_truncated,
        status_errno,
        n_restarts,
        load_error,
        load_error_truncated,
        incomplete_properties,
        unavailable_properties,
    };
    let problem_complete = evidence.incomplete_properties.is_empty();
    let problem_evaluable = !evidence.incomplete_properties.iter().any(|property| {
        property == "source_output" || SERVICE_PROBLEM_CORE_PROPERTIES.contains(&property.as_str())
    });
    let (health_status, problems) = analyze_service_health(&evidence);
    let problem_evidence = (!problems.is_empty()).then_some(evidence);
    let unit = ServiceUnit {
        name: name.clone(),
        loaded: load_state.as_deref() == Some("loaded"),
        load_state,
        active_state,
        sub_state,
        unit_file_state: non_empty(&values, "UnitFileState"),
        unit_file_preset: None,
        runtime_present: true,
        sources: vec![ServiceSource::Show],
        description,
        description_truncated,
        result,
        exec_main_status,
        fragment_path: non_empty(&values, "FragmentPath"),
        requires: split_units(values.get("Requires")),
        wants: split_units(values.get("Wants")),
        after: split_units(values.get("After")),
        before: split_units(values.get("Before")),
        ports: Vec::new(),
        health_status,
        problems,
        problem_evidence,
        problem_complete,
    };
    if failure_evaluable {
        parsed.failure_evaluable_names.insert(name.clone());
    }
    if problem_evaluable {
        parsed.problem_evaluable_names.insert(name.clone());
    }
    parsed.units.insert(name, unit);
    parsed
}

fn non_empty(values: &BTreeMap<String, String>, key: &str) -> Option<String> {
    values.get(key).filter(|value| !value.is_empty()).cloned()
}

fn service_problem_property_names() -> Vec<String> {
    SERVICE_PROBLEM_CORE_PROPERTIES
        .iter()
        .map(|property| (*property).to_string())
        .collect()
}

fn bounded_property_token(
    values: &BTreeMap<String, String>,
    key: &str,
    maximum: usize,
) -> (Option<String>, bool) {
    let Some(value) = values.get(key).filter(|value| !value.is_empty()) else {
        return (None, false);
    };
    let invalid = value.chars().any(char::is_control);
    let truncated = value.chars().count() > maximum || invalid;
    let bounded = value
        .chars()
        .filter(|character| !character.is_control())
        .take(maximum)
        .collect::<String>();
    ((!bounded.is_empty()).then_some(bounded), truncated)
}

fn bounded_sensitive_property(
    values: &BTreeMap<String, String>,
    key: &str,
    maximum: usize,
) -> (Option<String>, bool) {
    let Some(value) = values.get(key).filter(|value| !value.is_empty()) else {
        return (None, false);
    };
    let assigned_redacted = redact_service_assignments(value);
    let redacted = redact_sensitive_text(&assigned_redacted, maximum);
    let truncated = value.chars().count() > maximum || redacted.chars().count() > maximum;
    let bounded = redacted.chars().take(maximum).collect::<String>();
    (Some(bounded), truncated)
}

fn redact_service_assignments(input: &str) -> String {
    let chars = input.chars().collect::<Vec<_>>();
    let mut output = String::with_capacity(input.len());
    let mut index = 0usize;

    while index < chars.len() {
        let quoted_key = matches!(chars[index], '\'' | '"');
        let quote = quoted_key.then_some(chars[index]);
        let key_start = index + usize::from(quoted_key);
        if key_start >= chars.len()
            || (!chars[key_start].is_ascii_alphanumeric()
                && chars[key_start] != '_'
                && chars[key_start] != '-')
            || (!quoted_key
                && index > 0
                && (chars[index - 1].is_ascii_alphanumeric() || chars[index - 1] == '_'))
        {
            output.push(chars[index]);
            index += 1;
            continue;
        }

        let mut key_end = key_start;
        while key_end < chars.len()
            && (chars[key_end].is_ascii_alphanumeric() || matches!(chars[key_end], '_' | '-'))
        {
            key_end += 1;
        }
        let key = chars[key_start..key_end]
            .iter()
            .collect::<String>()
            .trim_start_matches('-')
            .replace('-', "_")
            .to_ascii_lowercase();
        if !is_service_sensitive_key(&key) {
            output.push(chars[index]);
            index += 1;
            continue;
        }

        let mut cursor = key_end;
        if let Some(quote) = quote {
            if chars.get(cursor) != Some(&quote) {
                output.push(chars[index]);
                index += 1;
                continue;
            }
            cursor += 1;
        }
        while chars
            .get(cursor)
            .is_some_and(|character| character.is_whitespace())
        {
            cursor += 1;
        }
        if !matches!(chars.get(cursor), Some('=' | ':')) {
            output.push(chars[index]);
            index += 1;
            continue;
        }
        cursor += 1;
        while chars
            .get(cursor)
            .is_some_and(|character| character.is_whitespace())
        {
            cursor += 1;
        }

        output.extend(chars[index..cursor].iter());
        if let Some(value_quote @ ('\'' | '"')) = chars.get(cursor).copied() {
            output.push(value_quote);
            output.push_str("[REDACTED]");
            cursor += 1;
            while cursor < chars.len() && chars[cursor] != value_quote {
                cursor += 1;
            }
            if cursor < chars.len() {
                output.push(value_quote);
                cursor += 1;
            }
            index = cursor;
            continue;
        }

        let value_start = cursor;
        while cursor < chars.len() && !service_secret_value_end(chars[cursor]) {
            cursor += 1;
        }
        if matches!(key.as_str(), "authorization" | "auth") {
            let scheme = chars[value_start..cursor]
                .iter()
                .collect::<String>()
                .to_ascii_lowercase();
            if matches!(scheme.as_str(), "bearer" | "basic") {
                while chars
                    .get(cursor)
                    .is_some_and(|character| character.is_whitespace())
                {
                    cursor += 1;
                }
                while cursor < chars.len() && !service_secret_value_end(chars[cursor]) {
                    cursor += 1;
                }
            }
        }
        output.push_str("[REDACTED]");
        index = cursor;
    }

    output
}

fn is_service_sensitive_key(key: &str) -> bool {
    [
        "password",
        "passwd",
        "pwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "access_key",
        "auth",
        "authorization",
    ]
    .iter()
    .any(|candidate| key == *candidate || key.ends_with(&format!("_{candidate}")))
}

fn service_secret_value_end(character: char) -> bool {
    character.is_whitespace() || matches!(character, '&' | ',' | ';' | '}' | ']' | '#' | '\'' | '"')
}

fn parse_i32_property(
    values: &BTreeMap<String, String>,
    key: &str,
    parsed: &mut ParsedServiceSource,
    incomplete: &mut Vec<String>,
) -> Option<i32> {
    let Some(value) = values.get(key).filter(|value| !value.is_empty()) else {
        incomplete.push(key.to_string());
        return None;
    };
    match value
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| value.parse::<i32>())
        .transpose()
    {
        Ok(Some(value)) => Some(value),
        _ => {
            parsed.parse_failure_count = parsed.parse_failure_count.saturating_add(1);
            incomplete.push(key.to_string());
            None
        }
    }
}

fn parse_optional_u64_property(
    values: &BTreeMap<String, String>,
    key: &str,
    parsed: &mut ParsedServiceSource,
    incomplete: &mut Vec<String>,
    unavailable: &mut Vec<String>,
) -> Option<u64> {
    if !values.contains_key(key) {
        unavailable.push(key.to_string());
        return None;
    }
    let Some(value) = values.get(key).filter(|value| !value.is_empty()) else {
        return None;
    };
    match value
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| value.parse::<u64>())
        .transpose()
    {
        Ok(Some(value)) => Some(value),
        _ => {
            parsed.parse_failure_count = parsed.parse_failure_count.saturating_add(1);
            incomplete.push(key.to_string());
            None
        }
    }
}

fn analyze_service_health(
    evidence: &ServiceProblemEvidence,
) -> (ServiceHealthStatus, Vec<ServiceProblem>) {
    let result = evidence.result.as_deref().unwrap_or_default();
    let result_failed = !result.is_empty() && result != "success";
    let explicitly_failed = evidence.active_state.as_deref() == Some("failed") || result_failed;
    let load_problem = matches!(
        evidence.load_state.as_deref(),
        Some("error" | "not-found" | "bad-setting")
    ) || evidence.load_error.is_some();
    let auto_restart = evidence.sub_state.as_deref() == Some("auto-restart");
    let maintenance = evidence.active_state.as_deref() == Some("maintenance");

    let mut kinds = BTreeSet::new();
    if result_failed {
        kinds.insert(problem_kind_from_result(result));
    }
    if explicitly_failed {
        if let Some(kind) = problem_kind_from_status_text(evidence.status_text.as_deref()) {
            kinds.insert(kind);
        }
        if !kinds.iter().any(|kind| {
            matches!(
                kind,
                ServiceProblemKind::ExitCode
                    | ServiceProblemKind::Signal
                    | ServiceProblemKind::CoreDump
                    | ServiceProblemKind::Timeout
                    | ServiceProblemKind::Watchdog
                    | ServiceProblemKind::StartLimit
                    | ServiceProblemKind::Dependency
                    | ServiceProblemKind::Resource
                    | ServiceProblemKind::Oom
            )
        }) {
            let fallback = match (evidence.exec_main_code, evidence.exec_main_status) {
                (Some(3), _) => ServiceProblemKind::CoreDump,
                (Some(2), _) => ServiceProblemKind::Signal,
                (Some(1), Some(status)) if status != 0 => ServiceProblemKind::ExitCode,
                _ => ServiceProblemKind::Unknown,
            };
            kinds.insert(fallback);
        }
    }
    if load_problem {
        kinds.insert(ServiceProblemKind::Load);
    }
    if auto_restart {
        kinds.insert(ServiceProblemKind::AutoRestart);
    }
    if maintenance {
        kinds.insert(ServiceProblemKind::Maintenance);
    }
    if let Some(kind) = evidence.status_errno.and_then(problem_kind_from_errno) {
        kinds.insert(kind);
    }

    let health_status = if explicitly_failed {
        ServiceHealthStatus::Failed
    } else if load_problem || auto_restart || maintenance || !kinds.is_empty() {
        ServiceHealthStatus::Degraded
    } else {
        match evidence.active_state.as_deref() {
            Some("active") => ServiceHealthStatus::Healthy,
            Some("inactive") => ServiceHealthStatus::Inactive,
            Some("activating" | "deactivating" | "reloading" | "refreshing") => {
                ServiceHealthStatus::Transitional
            }
            Some(_) | None => ServiceHealthStatus::Unknown,
        }
    };
    if health_status == ServiceHealthStatus::Unknown && kinds.is_empty() {
        kinds.insert(ServiceProblemKind::Unknown);
    }
    let problems = kinds
        .into_iter()
        .map(|kind| ServiceProblem { kind })
        .collect();
    (health_status, problems)
}

fn problem_kind_from_errno(errno: i32) -> Option<ServiceProblemKind> {
    match errno {
        0 => None,
        12 | 23 | 24 | 28 => Some(ServiceProblemKind::Resource),
        1 | 13 => Some(ServiceProblemKind::Permission),
        2 => Some(ServiceProblemKind::NotFound),
        22 => Some(ServiceProblemKind::InvalidArgument),
        _ => Some(ServiceProblemKind::Errno),
    }
}

fn problem_kind_from_result(result: &str) -> ServiceProblemKind {
    match result {
        "exit-code" => ServiceProblemKind::ExitCode,
        "signal" => ServiceProblemKind::Signal,
        "core-dump" => ServiceProblemKind::CoreDump,
        value if value.contains("timeout") => ServiceProblemKind::Timeout,
        "watchdog" => ServiceProblemKind::Watchdog,
        "start-limit-hit" => ServiceProblemKind::StartLimit,
        "dependency" => ServiceProblemKind::Dependency,
        "resources" | "resource" => ServiceProblemKind::Resource,
        "oom-kill" | "oom" => ServiceProblemKind::Oom,
        _ => ServiceProblemKind::Unknown,
    }
}

fn problem_kind_from_status_text(status_text: Option<&str>) -> Option<ServiceProblemKind> {
    let text = status_text?.to_ascii_lowercase();
    if text.contains("core dump") || text.contains("coredump") {
        Some(ServiceProblemKind::CoreDump)
    } else if text.contains("out of memory") || text.contains("oom") {
        Some(ServiceProblemKind::Oom)
    } else if text.contains("watchdog") {
        Some(ServiceProblemKind::Watchdog)
    } else if text.contains("start-limit") || text.contains("repeated too quickly") {
        Some(ServiceProblemKind::StartLimit)
    } else if text.contains("dependency") {
        Some(ServiceProblemKind::Dependency)
    } else if text.contains("timed out") || text.contains("timeout") {
        Some(ServiceProblemKind::Timeout)
    } else if text.contains("resource")
        || text.contains("no space")
        || text.contains("cannot allocate")
    {
        Some(ServiceProblemKind::Resource)
    } else if text.contains("signal") {
        Some(ServiceProblemKind::Signal)
    } else {
        None
    }
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

fn service_has_problem(unit: &ServiceUnit) -> bool {
    !unit.problems.is_empty()
        || matches!(
            unit.health_status,
            ServiceHealthStatus::Degraded | ServiceHealthStatus::Failed
        )
        || (unit.health_status == ServiceHealthStatus::Unknown
            && (!unit.problem_complete || unit.problem_evidence.is_some()))
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
        assert_eq!(calls.len(), 3);
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
        assert_eq!(
            SHOW_PROPERTIES,
            "Id,LoadState,ActiveState,SubState,UnitFileState,Description,Result,ExecMainCode,ExecMainStatus,StatusText,StatusErrno,NRestarts,LoadError,FragmentPath,Requires,Wants,After,Before"
        );
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
        assert_eq!(snapshot.problem_total, 1);
        assert_eq!(snapshot.problem_returned_count, 1);
        assert_eq!(snapshot.problem_omitted_count, 0);
        assert_eq!(snapshot.problem_units[0].name, "z.service");
        assert_eq!(snapshot.failed_units.len(), 1);
        assert_eq!(snapshot.problem_units.len(), 1);
    }

    #[test]
    fn problem_details_have_an_independent_hard_limit() {
        let count = MAX_SERVICE_DETAIL_LIMIT + 17;
        let mut runtime = String::new();
        let mut show = String::new();
        for index in 0..count {
            runtime.push_str(&format!(
                "p{index:03}.service loaded failed failed Problem {index}\n"
            ));
            show.push_str(&format!(
                "Id=p{index:03}.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=1\nStatusText=failed\nStatusErrno=0\nNRestarts=0\nLoadError=\n\n"
            ));
        }
        let runner = FixtureRunner::new(vec![output(runtime), output(""), output(show)]);
        let snapshot = query_services_with_runner(&ServiceQuery::default(), &runner)
            .expect("bounded problem details");

        assert_eq!(snapshot.failed_total, count);
        assert_eq!(snapshot.failed_returned_count, MAX_SERVICE_DETAIL_LIMIT);
        assert_eq!(snapshot.failed_omitted_count, 17);
        assert_eq!(snapshot.problem_total, count);
        assert_eq!(snapshot.problem_returned_count, MAX_SERVICE_DETAIL_LIMIT);
        assert_eq!(snapshot.problem_omitted_count, 17);
        assert!(snapshot.truncated);
        assert!(snapshot
            .problem_units
            .iter()
            .all(|unit| unit.problem_evidence.is_some()));
        let serialized = serde_json::to_value(&snapshot).expect("bounded service JSON");
        assert!(serialized["problem_units"]
            .as_array()
            .expect("problem array")
            .iter()
            .flat_map(|unit| unit["problems"].as_array().expect("problems"))
            .all(|problem| problem.get("evidence").is_none()));
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
                "Id=healthy.service\nLoadState=loaded\nActiveState=inactive\nSubState=dead\nResult=\nExecMainCode=0\nExecMainStatus=0\nStatusText=\nStatusErrno=0\nNRestarts=0\nLoadError=\n\nId=bad-result.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=exit-code\nExecMainCode=1\nExecMainStatus=3\nStatusText=process exited\nStatusErrno=0\nNRestarts=0\nLoadError=\n",
            ),
        ]);
        let snapshot = query_services_with_runner(&ServiceQuery::default(), &runner)
            .expect("batch show inventory");

        assert_eq!(snapshot.collection_status, CollectionStatus::Complete);
        assert!(snapshot.failed_filter_complete);
        assert!(snapshot.problem_filter_complete);
        assert_eq!(snapshot.failed_total, 1);
        assert_eq!(snapshot.problem_total, 1);
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
                "Id=active.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainCode=1\nExecMainStatus=0\nStatusText=\nStatusErrno=0\nNRestarts=0\nLoadError=\n",
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
    fn batch_show_missing_status_errno_makes_problem_filter_incomplete() {
        let runner = FixtureRunner::new(vec![
            output("probe.service loaded activating auto-restart Probe\n"),
            output("probe.service enabled enabled\n"),
            output("Id=probe.service\nLoadState=loaded\nActiveState=activating\nSubState=auto-restart\nResult=success\nExecMainCode=1\nExecMainStatus=0\nLoadError=\n"),
        ]);
        let snapshot = query_services_with_runner(&ServiceQuery::default(), &runner)
            .expect("batch show without StatusErrno");
        let unit = &snapshot.units[0];

        assert!(!unit.problem_complete);
        assert!(!snapshot.problem_filter_complete);
        assert!(unit
            .problem_evidence
            .as_ref()
            .expect("problem evidence")
            .incomplete_properties
            .iter()
            .any(|property| property == "StatusErrno"));

        let empty_runner = FixtureRunner::new(vec![
            output("probe.service loaded activating auto-restart Probe\n"),
            output("probe.service enabled enabled\n"),
            output("Id=probe.service\nLoadState=loaded\nActiveState=activating\nSubState=auto-restart\nResult=success\nExecMainCode=1\nExecMainStatus=0\nStatusErrno=\nLoadError=\n"),
        ]);
        let empty = query_services_with_runner(&ServiceQuery::default(), &empty_runner)
            .expect("batch show with empty StatusErrno");
        assert!(!empty.units[0].problem_complete);
        assert!(!empty.problem_filter_complete);
    }

    #[test]
    fn batch_show_missing_load_error_makes_problem_filter_incomplete() {
        let runner = FixtureRunner::new(vec![
            output("probe.service loaded activating auto-restart Probe\n"),
            output("probe.service enabled enabled\n"),
            output("Id=probe.service\nLoadState=loaded\nActiveState=activating\nSubState=auto-restart\nResult=success\nExecMainCode=1\nExecMainStatus=0\nStatusErrno=0\n"),
        ]);
        let snapshot = query_services_with_runner(&ServiceQuery::default(), &runner)
            .expect("batch show without LoadError");
        let unit = &snapshot.units[0];

        assert!(!unit.problem_complete);
        assert!(!snapshot.problem_filter_complete);
        assert!(unit
            .problem_evidence
            .as_ref()
            .expect("problem evidence")
            .incomplete_properties
            .iter()
            .any(|property| property == "LoadError"));
    }

    #[test]
    fn batch_show_empty_load_error_is_complete() {
        let runner = FixtureRunner::new(vec![
            output("probe.service loaded activating auto-restart Probe\n"),
            output("probe.service enabled enabled\n"),
            output("Id=probe.service\nLoadState=loaded\nActiveState=activating\nSubState=auto-restart\nResult=success\nExecMainCode=1\nExecMainStatus=0\nStatusErrno=0\nLoadError=\n"),
        ]);
        let snapshot = query_services_with_runner(&ServiceQuery::default(), &runner)
            .expect("batch show with empty LoadError");
        let unit = &snapshot.units[0];

        assert!(unit.problem_complete);
        assert!(snapshot.problem_filter_complete);
        assert!(unit
            .problem_evidence
            .as_ref()
            .expect("problem evidence")
            .load_error
            .is_none());
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
        assert!(!failed.problem_filter_complete);
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
        assert!(!truncated.problem_filter_complete);
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
    fn maps_all_typed_failure_reasons() {
        let mappings = [
            ("exit-code", ServiceProblemKind::ExitCode),
            ("signal", ServiceProblemKind::Signal),
            ("core-dump", ServiceProblemKind::CoreDump),
            ("timeout-start", ServiceProblemKind::Timeout),
            ("watchdog", ServiceProblemKind::Watchdog),
            ("start-limit-hit", ServiceProblemKind::StartLimit),
            ("dependency", ServiceProblemKind::Dependency),
            ("resources", ServiceProblemKind::Resource),
            ("oom-kill", ServiceProblemKind::Oom),
            ("unclassified-result", ServiceProblemKind::Unknown),
        ];
        for (result, expected) in mappings {
            let evidence = ServiceProblemEvidence {
                load_state: Some("loaded".to_string()),
                active_state: Some("failed".to_string()),
                sub_state: Some("failed".to_string()),
                result: Some(result.to_string()),
                exec_main_code: Some(0),
                exec_main_status: Some(0),
                status_errno: Some(0),
                n_restarts: Some(0),
                ..ServiceProblemEvidence::default()
            };
            let (health, problems) = analyze_service_health(&evidence);
            assert_eq!(health, ServiceHealthStatus::Failed, "{result}");
            assert!(
                problems.iter().any(|problem| problem.kind == expected),
                "{result}: {problems:?}"
            );
        }

        let load = ServiceProblemEvidence {
            load_state: Some("error".to_string()),
            active_state: Some("inactive".to_string()),
            sub_state: Some("dead".to_string()),
            load_error: Some("unit file is invalid".to_string()),
            ..ServiceProblemEvidence::default()
        };
        let (health, problems) = analyze_service_health(&load);
        assert_eq!(health, ServiceHealthStatus::Degraded);
        assert!(problems
            .iter()
            .any(|problem| problem.kind == ServiceProblemKind::Load));
    }

    #[test]
    fn classifies_health_and_restart_maintenance_anomalies() {
        for (active_state, expected) in [
            (Some("active"), ServiceHealthStatus::Healthy),
            (Some("inactive"), ServiceHealthStatus::Inactive),
            (Some("activating"), ServiceHealthStatus::Transitional),
            (None, ServiceHealthStatus::Unknown),
        ] {
            let evidence = ServiceProblemEvidence {
                load_state: Some("loaded".to_string()),
                active_state: active_state.map(str::to_string),
                sub_state: Some("running".to_string()),
                result: Some("success".to_string()),
                ..ServiceProblemEvidence::default()
            };
            assert_eq!(analyze_service_health(&evidence).0, expected);
        }

        let restart = ServiceProblemEvidence {
            load_state: Some("loaded".to_string()),
            active_state: Some("activating".to_string()),
            sub_state: Some("auto-restart".to_string()),
            result: None,
            n_restarts: Some(4),
            ..ServiceProblemEvidence::default()
        };
        let (restart_health, restart_problems) = analyze_service_health(&restart);
        assert_eq!(restart_health, ServiceHealthStatus::Degraded);
        assert!(restart_problems
            .iter()
            .any(|problem| problem.kind == ServiceProblemKind::AutoRestart));

        let maintenance = ServiceProblemEvidence {
            load_state: Some("loaded".to_string()),
            active_state: Some("maintenance".to_string()),
            sub_state: Some("dead".to_string()),
            result: Some("success".to_string()),
            ..ServiceProblemEvidence::default()
        };
        let (maintenance_health, maintenance_problems) = analyze_service_health(&maintenance);
        assert_eq!(maintenance_health, ServiceHealthStatus::Degraded);
        assert!(maintenance_problems
            .iter()
            .any(|problem| problem.kind == ServiceProblemKind::Maintenance));

        let historical_restarts = ServiceProblemEvidence {
            load_state: Some("loaded".to_string()),
            active_state: Some("active".to_string()),
            sub_state: Some("running".to_string()),
            result: Some("success".to_string()),
            n_restarts: Some(9),
            ..ServiceProblemEvidence::default()
        };
        let (health, problems) = analyze_service_health(&historical_restarts);
        assert_eq!(health, ServiceHealthStatus::Healthy);
        assert!(problems.is_empty());

        let transitional = ServiceProblemEvidence {
            load_state: Some("loaded".to_string()),
            active_state: Some("activating".to_string()),
            sub_state: Some("start".to_string()),
            result: Some("success".to_string()),
            ..ServiceProblemEvidence::default()
        };
        let (health, problems) = analyze_service_health(&transitional);
        assert_eq!(health, ServiceHealthStatus::Transitional);
        assert!(problems.is_empty());
    }

    #[test]
    fn redacts_and_hard_limits_failure_evidence() {
        let long_text = format!(
            "Authorization: Bearer topsecret; Authorization: Basic YmFzaWM= {{\"token\":\"jsonsecret\",\"password\":\"quotedsecret\"}} https://host/path?api_key=urlsecret&password=urlpass {}",
            "x".repeat(400)
        );
        let long_error = format!(
            "password hunter2 api_key='quoted-api-secret' {}",
            "y".repeat(400)
        );
        let content = format!(
            "Id=secret.service\nLoadState=error\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainCode=1\nExecMainStatus=2\nStatusText={long_text}\nStatusErrno=13\nNRestarts=2\nLoadError={long_error}\n"
        );
        let parsed = parse_show_output(&content, "secret.service", false);
        let unit = &parsed.units["secret.service"];
        let evidence = unit.problem_evidence.as_ref().expect("problem evidence");

        assert!(parsed.truncated);
        assert!(!unit.problem_complete);
        assert!(evidence.status_text_truncated);
        assert!(evidence.load_error_truncated);
        assert!(evidence
            .status_text
            .as_deref()
            .is_some_and(|text| text.chars().count() <= MAX_SERVICE_EVIDENCE_TEXT_CHARS));
        assert!(evidence
            .load_error
            .as_deref()
            .is_some_and(|text| text.chars().count() <= MAX_SERVICE_EVIDENCE_TEXT_CHARS));
        let serialized = serde_json::to_string(evidence).expect("serialized evidence");
        for secret in [
            "topsecret",
            "YmFzaWM=",
            "jsonsecret",
            "quotedsecret",
            "urlsecret",
            "urlpass",
            "hunter2",
            "quoted-api-secret",
        ] {
            assert!(!serialized.contains(secret), "leaked {secret}");
        }
        assert!(serialized.contains("[REDACTED]"));
    }

    #[test]
    fn invalid_numeric_properties_are_partial_and_incomplete() {
        let parsed = parse_show_output(
            "Id=numeric.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainCode=abc\nExecMainStatus=-1\nStatusText=failed\nStatusErrno=not-a-number\nNRestarts=-2\nLoadError=\n",
            "numeric.service",
            false,
        );
        let unit = &parsed.units["numeric.service"];
        let evidence = unit.problem_evidence.as_ref().expect("problem evidence");
        assert_eq!(parsed.parse_failure_count, 4);
        assert!(!unit.problem_complete);
        for property in ["ExecMainCode", "ExecMainStatus", "StatusErrno", "NRestarts"] {
            assert!(evidence
                .incomplete_properties
                .iter()
                .any(|candidate| candidate == property));
        }
    }

    #[test]
    fn errno_kinds_do_not_overclassify_resources() {
        for (errno, expected) in [
            (12, ServiceProblemKind::Resource),
            (23, ServiceProblemKind::Resource),
            (24, ServiceProblemKind::Resource),
            (28, ServiceProblemKind::Resource),
            (13, ServiceProblemKind::Permission),
            (2, ServiceProblemKind::NotFound),
            (22, ServiceProblemKind::InvalidArgument),
            (5, ServiceProblemKind::Errno),
        ] {
            let evidence = ServiceProblemEvidence {
                load_state: Some("loaded".to_string()),
                active_state: Some("active".to_string()),
                sub_state: Some("running".to_string()),
                result: Some("success".to_string()),
                status_errno: Some(errno),
                ..ServiceProblemEvidence::default()
            };
            let (_, problems) = analyze_service_health(&evidence);
            assert!(problems.iter().any(|problem| problem.kind == expected));
            if !matches!(errno, 12 | 23 | 24 | 28) {
                assert!(!problems
                    .iter()
                    .any(|problem| problem.kind == ServiceProblemKind::Resource));
            }
        }
    }

    #[test]
    fn optional_nrestarts_and_empty_active_state_affect_completeness_correctly() {
        let runner = FixtureRunner::new(vec![
            output("old.service loaded activating auto-restart Old systemd\n"),
            output("old.service enabled enabled\n"),
            output("Id=old.service\nLoadState=loaded\nActiveState=activating\nSubState=auto-restart\nResult=success\nExecMainCode=1\nExecMainStatus=0\nStatusText=\nStatusErrno=0\nLoadError=\n"),
        ]);
        let old_systemd = query_services_with_runner(&ServiceQuery::default(), &runner)
            .expect("old systemd without NRestarts");
        let old_unit = &old_systemd.units[0];
        assert!(old_unit.problem_complete);
        assert!(old_systemd.problem_filter_complete);
        let old_evidence = old_unit
            .problem_evidence
            .as_ref()
            .expect("auto-restart evidence");
        assert!(old_evidence
            .unavailable_properties
            .iter()
            .any(|property| property == "NRestarts"));

        let empty_active = parse_show_output(
            "Id=empty.service\nLoadState=loaded\nActiveState=\nSubState=dead\nResult=success\nExecMainCode=1\nExecMainStatus=0\nStatusText=\nStatusErrno=0\nLoadError=\n",
            "empty.service",
            false,
        );
        let empty_unit = &empty_active.units["empty.service"];
        assert!(!empty_unit.problem_complete);
        assert!(!empty_active
            .problem_evaluable_names
            .contains("empty.service"));
        let evidence = empty_unit
            .problem_evidence
            .as_ref()
            .expect("unknown evidence");
        assert!(evidence
            .incomplete_properties
            .iter()
            .any(|property| property == "ActiveState"));
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
        assert_eq!(snapshot.problem_total, 1);
        assert_eq!(snapshot.problem_returned_count, 1);
        assert_eq!(snapshot.problem_omitted_count, 0);
        assert!(!snapshot.problem_filter_complete);
        assert!(snapshot.units[0].loaded);
        assert!(snapshot.units[0].runtime_present);
        assert_eq!(
            snapshot.units[0].sources,
            vec![ServiceSource::ListUnits, ServiceSource::ListUnitFiles]
        );
        assert_eq!(snapshot.units[0].health_status, ServiceHealthStatus::Failed);
        assert_eq!(
            snapshot.units[0].problems[0].kind,
            ServiceProblemKind::ExitCode
        );
        assert!(!snapshot.units[0].problem_complete);
        assert!(snapshot.units[0].problem_evidence.is_some());
        assert_eq!(snapshot.problem_units[0].name, "legacy.service");

        let previous_new_unit = serde_json::json!({
            "name": "prior.service",
            "health_status": "failed",
            "problems": [{
                "kind": "permission",
                "evidence": {
                    "active_state": "failed",
                    "status_errno": 13,
                    "incomplete_properties": []
                }
            }],
            "problem_complete": true
        });
        let previous_new_unit = serde_json::from_value::<ServiceUnit>(previous_new_unit)
            .expect("previous FR-1.18 unit JSON");
        assert_eq!(
            previous_new_unit.problems[0].kind,
            ServiceProblemKind::Permission
        );
        assert_eq!(
            previous_new_unit
                .problem_evidence
                .as_ref()
                .and_then(|evidence| evidence.status_errno),
            Some(13)
        );
        let migrated = serde_json::to_value(&previous_new_unit).expect("migrated unit JSON");
        assert!(migrated["problems"][0].get("evidence").is_none());
        assert!(migrated.get("problem_evidence").is_some());

        let mut explicit = serde_json::to_value(&snapshot).expect("new service JSON");
        assert!(explicit.get("failed_filter_complete").is_some());
        assert!(explicit["units"][0].get("loaded").is_some());
        explicit["total"] = serde_json::json!(0);
        explicit["returned_count"] = serde_json::json!(0);
        explicit["failed_total"] = serde_json::json!(0);
        explicit["failed_filter_complete"] = serde_json::json!(true);
        explicit["problem_total"] = serde_json::json!(0);
        explicit["problem_returned_count"] = serde_json::json!(0);
        explicit["problem_omitted_count"] = serde_json::json!(0);
        explicit["problem_filter_complete"] = serde_json::json!(true);
        explicit["problem_units"] = serde_json::json!([]);
        explicit["units"][0]["loaded"] = serde_json::json!(false);
        explicit["units"][0]["runtime_present"] = serde_json::json!(false);
        explicit["units"][0]["sources"] = serde_json::json!([]);
        explicit["units"][0]["health_status"] = serde_json::json!("healthy");
        explicit["units"][0]["problems"] = serde_json::json!([]);
        explicit["units"][0]["problem_complete"] = serde_json::json!(true);
        let explicit =
            serde_json::from_value::<ServiceSnapshot>(explicit).expect("explicit new service JSON");
        assert_eq!(explicit.total, 0);
        assert_eq!(explicit.returned_count, 0);
        assert_eq!(explicit.failed_total, 0);
        assert!(explicit.failed_filter_complete);
        assert_eq!(explicit.problem_total, 0);
        assert!(explicit.problem_filter_complete);
        assert!(explicit.problem_units.is_empty());
        assert!(!explicit.units[0].loaded);
        assert!(!explicit.units[0].runtime_present);
        assert!(explicit.units[0].sources.is_empty());
        assert_eq!(
            explicit.units[0].health_status,
            ServiceHealthStatus::Healthy
        );
        assert!(explicit.units[0].problems.is_empty());
        assert!(explicit.units[0].problem_complete);
    }

    #[test]
    fn legacy_limited_units_merge_separate_failed_units_into_problems() {
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
            "truncated": true,
            "total": 2,
            "returned_count": 1,
            "omitted_count": 1,
            "units": [{
                "name": "a.service",
                "load_state": "loaded",
                "active_state": "active",
                "sub_state": "running",
                "result": "success"
            }],
            "failed_units": [{
                "name": "z-failed.service",
                "load_state": "loaded",
                "active_state": "failed",
                "sub_state": "failed",
                "result": "exit-code",
                "exec_main_status": 9
            }],
            "health_probes": []
        });

        let snapshot = serde_json::from_value::<ServiceSnapshot>(legacy)
            .expect("limited FR-1.17 service snapshot");
        assert_eq!(snapshot.units.len(), 1);
        assert_eq!(snapshot.units[0].name, "a.service");
        assert_eq!(snapshot.problem_total, 1);
        assert_eq!(snapshot.problem_returned_count, 1);
        assert_eq!(snapshot.problem_omitted_count, 0);
        assert_eq!(snapshot.problem_units.len(), 1);
        assert_eq!(snapshot.problem_units[0].name, "z-failed.service");
        assert_eq!(
            snapshot.problem_total,
            snapshot.problem_returned_count + snapshot.problem_omitted_count
        );
    }
}
