use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::command::run_limited_command;
use crate::model::{HealthProbeResult, ServiceSnapshot, ServiceUnit};
use crate::network::{probe_tcp, TcpProbeRequest};
use crate::procfs::basic_meta;

const DEFAULT_SERVICE_LIMIT: usize = 100;
const MAX_SERVICE_LIMIT: usize = 500;
const MAX_HEALTH_PROBES: usize = 5;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

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
            limit: Some(DEFAULT_SERVICE_LIMIT),
        }
    }
}

#[must_use]
pub fn query_services(query: &ServiceQuery) -> ServiceSnapshot {
    let mut warnings = Vec::new();
    let mut available = true;
    let mut units = if let Some(name) = &query.name {
        match validate_unit_name(name) {
            Ok(()) => match read_service_show(name, &mut warnings) {
                Some(unit) => vec![unit],
                None => Vec::new(),
            },
            Err(message) => {
                warnings.push(message);
                Vec::new()
            }
        }
    } else {
        match read_service_list(query, &mut warnings) {
            Some(units) => units,
            None => {
                available = false;
                Vec::new()
            }
        }
    };

    if !query.include_dependencies {
        for unit in &mut units {
            unit.requires.clear();
            unit.wants.clear();
            unit.after.clear();
            unit.before.clear();
        }
    }
    if query.include_ports {
        warnings.push(
            "service-to-port mapping is an extension point in this version; use os_network_connections for port inventory"
                .to_string(),
        );
    }
    let unit_limit = query
        .limit
        .unwrap_or(DEFAULT_SERVICE_LIMIT)
        .clamp(1, MAX_SERVICE_LIMIT);
    let mut truncated = units.len() > unit_limit;
    units.truncate(unit_limit);
    if query.health_probes.len() > MAX_HEALTH_PROBES {
        truncated = true;
        warnings.push(format!(
            "health_probes truncated to {MAX_HEALTH_PROBES} entries"
        ));
    }
    let failed_units = units
        .iter()
        .filter(|unit| {
            unit.active_state.as_deref() == Some("failed")
                || unit
                    .result
                    .as_deref()
                    .is_some_and(|result| result != "success")
        })
        .cloned()
        .collect::<Vec<_>>();
    let health_probes = query
        .health_probes
        .iter()
        .take(MAX_HEALTH_PROBES)
        .map(probe_tcp)
        .collect::<Vec<_>>();

    ServiceSnapshot {
        meta: basic_meta("services", warnings),
        available,
        truncated,
        units,
        failed_units,
        health_probes,
    }
}

fn read_service_list(query: &ServiceQuery, warnings: &mut Vec<String>) -> Option<Vec<ServiceUnit>> {
    let mut args = vec![
        "list-units",
        "--type=service",
        "--no-pager",
        "--plain",
        "--no-legend",
    ];
    if query.include_all {
        args.push("--all");
    }
    match run_limited_command("systemctl", &args, COMMAND_TIMEOUT, 512 * 1024, 32 * 1024) {
        Ok(output) if output.success => Some(parse_systemctl_list_units(&output.stdout)),
        Ok(output) => {
            if output.timed_out {
                warnings.push("systemctl list-units timed out".to_string());
            } else {
                warnings.push(format!(
                    "systemctl list-units failed: {}",
                    output.stderr.trim()
                ));
            }
            None
        }
        Err(error) => {
            warnings.push(format!("systemctl unavailable: {error}"));
            None
        }
    }
}

fn read_service_show(name: &str, warnings: &mut Vec<String>) -> Option<ServiceUnit> {
    let properties = [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "UnitFileState",
        "Description",
        "Result",
        "ExecMainStatus",
        "FragmentPath",
        "Requires",
        "Wants",
        "After",
        "Before",
    ]
    .join(",");
    match run_limited_command(
        "systemctl",
        &[
            "show",
            name,
            "--no-pager",
            "--property",
            properties.as_str(),
        ],
        COMMAND_TIMEOUT,
        256 * 1024,
        32 * 1024,
    ) {
        Ok(output) if output.success => Some(parse_systemctl_show(&output.stdout, name)),
        Ok(output) => {
            if output.timed_out {
                warnings.push(format!("systemctl show {name} timed out"));
            } else {
                warnings.push(format!(
                    "systemctl show {name} failed: {}",
                    output.stderr.trim()
                ));
            }
            None
        }
        Err(error) => {
            warnings.push(format!("systemctl unavailable: {error}"));
            None
        }
    }
}

#[must_use]
pub fn parse_systemctl_list_units(content: &str) -> Vec<ServiceUnit> {
    content
        .lines()
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 4 {
                return None;
            }
            Some(ServiceUnit {
                name: parts[0].to_string(),
                load_state: Some(parts[1].to_string()),
                active_state: Some(parts[2].to_string()),
                sub_state: Some(parts[3].to_string()),
                unit_file_state: None,
                description: (parts.len() > 4).then(|| parts[4..].join(" ")),
                result: None,
                exec_main_status: None,
                fragment_path: None,
                requires: Vec::new(),
                wants: Vec::new(),
                after: Vec::new(),
                before: Vec::new(),
                ports: Vec::new(),
            })
        })
        .collect()
}

#[must_use]
pub fn parse_systemctl_show(content: &str, fallback_name: &str) -> ServiceUnit {
    let values = content
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            Some((key.to_string(), value.to_string()))
        })
        .collect::<BTreeMap<_, _>>();
    ServiceUnit {
        name: values
            .get("Id")
            .filter(|value| !value.is_empty())
            .cloned()
            .unwrap_or_else(|| fallback_name.to_string()),
        load_state: non_empty(&values, "LoadState"),
        active_state: non_empty(&values, "ActiveState"),
        sub_state: non_empty(&values, "SubState"),
        unit_file_state: non_empty(&values, "UnitFileState"),
        description: non_empty(&values, "Description"),
        result: non_empty(&values, "Result"),
        exec_main_status: values
            .get("ExecMainStatus")
            .and_then(|value| value.parse::<i32>().ok()),
        fragment_path: non_empty(&values, "FragmentPath"),
        requires: split_units(values.get("Requires")),
        wants: split_units(values.get("Wants")),
        after: split_units(values.get("After")),
        before: split_units(values.get("Before")),
        ports: Vec::new(),
    }
}

fn non_empty(values: &BTreeMap<String, String>, key: &str) -> Option<String> {
    values.get(key).filter(|value| !value.is_empty()).cloned()
}

fn split_units(value: Option<&String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split_whitespace()
                .filter(|part| !part.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn validate_unit_name(name: &str) -> std::result::Result<(), String> {
    if name.starts_with('-') || name.is_empty() {
        return Err("service name must not be empty or start with '-'".to_string());
    }
    let valid = name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '@' | '_' | '-'));
    if valid {
        Ok(())
    } else {
        Err("service name contains unsupported characters".to_string())
    }
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

    #[test]
    fn parses_systemctl_list_units() {
        let content = "ssh.service loaded active running OpenSSH server daemon\nbad.service loaded failed failed Broken service\n";
        let units = parse_systemctl_list_units(content);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].name, "ssh.service");
        assert_eq!(units[1].active_state.as_deref(), Some("failed"));
    }

    #[test]
    fn parses_systemctl_show_dependencies() {
        let content = "Id=ssh.service\nLoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\nRequires=network.target\nAfter=network.target auditd.service\n";
        let unit = parse_systemctl_show(content, "ssh.service");
        assert_eq!(unit.name, "ssh.service");
        assert_eq!(unit.requires, vec!["network.target"]);
        assert_eq!(unit.after, vec!["network.target", "auditd.service"]);
        assert_eq!(unit.exec_main_status, Some(0));
    }

    #[test]
    fn rejects_option_like_service_name() {
        assert!(validate_unit_name("--failed").is_err());
        assert!(validate_unit_name("ssh.service").is_ok());
    }
}
