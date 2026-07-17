use std::collections::{BTreeMap, BTreeSet};

use crate::context::{ContextInput, ContextInputs};
use crate::model::{
    ContextCapability, ContextConnectionPayload, ContextDependencyImpactPayload, ContextDimension,
    ContextDiskDevicePayload, ContextDiskPayload, ContextFirewallPayload, ContextLoadPayload,
    ContextLogEntryPayload, ContextLogPatternPayload, ContextLogPayload, ContextMemoryPayload,
    ContextMetricsPayload, ContextNetworkInterfacePayload, ContextNetworkPayload, ContextPage,
    ContextPayload, ContextProbePayload, ContextProcessItem, ContextProcessPayload,
    ContextServicePayload, ContextServicePortPayload, ContextServiceUnitPayload,
    ContextThermalPayload, MetricSnapshot, NetworkSnapshot, ProcessList, ServicePortBinding,
    ServiceSnapshot,
};
use crate::redaction::redact_sensitive_text;

pub(crate) const MAX_CONTEXT_INPUT_ITEMS: usize = 4_096;
pub(crate) const MAX_CONTEXT_INPUT_BYTES: usize = 256 * 1024;
pub(crate) const MAX_GLOBAL_INPUT_ITEMS: usize = 8_192;
pub(crate) const MAX_GLOBAL_INPUT_BYTES: usize = 512 * 1024;
const MAX_IDENTIFIER_CHARS: usize = 128;
const MAX_TEXT_CHARS: usize = 192;
const TRUNCATION_MARKER_LEN: usize = "...[truncated]".len();

const MAX_DISKS: usize = 12;
const MAX_DISK_DEVICES: usize = 12;
const MAX_INTERFACES: usize = 12;
const MAX_THERMAL: usize = 12;
const MAX_PROCESSES: usize = 16;
const MAX_LOG_ENTRIES: usize = 12;
const MAX_LOG_PATTERNS: usize = 8;
const MAX_CONNECTIONS: usize = 16;
const MAX_DNS_CHECKS: usize = 8;
const MAX_PROBES: usize = 5;
const MAX_FIREWALL: usize = 4;
const MAX_SERVICE_UNITS: usize = 12;
const MAX_SERVICE_NAMES: usize = 16;
const MAX_SERVICE_PORTS: usize = 16;
const MAX_DEPENDENCY_IMPACTS: usize = 12;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct PageAccounting {
    pub total: usize,
    pub returned_count: usize,
    pub omitted_count: usize,
    pub total_unknown: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PayloadAccounting {
    pub dimensions: BTreeMap<ContextDimension, PageAccounting>,
    pub capabilities: BTreeMap<ContextCapability, PageAccounting>,
    pub input_truncated: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct BudgetOutcome {
    pub input_len: usize,
    pub retained_len: usize,
    pub omitted_count: usize,
    pub total_unknown: bool,
    pub truncated: bool,
}

#[derive(Debug)]
pub(crate) struct ContextInputBudget {
    remaining_items: usize,
    remaining_bytes: usize,
}

impl Default for ContextInputBudget {
    fn default() -> Self {
        Self {
            remaining_items: MAX_GLOBAL_INPUT_ITEMS,
            remaining_bytes: MAX_GLOBAL_INPUT_BYTES,
        }
    }
}

impl ContextInputBudget {
    pub(crate) fn bound_vec_with_limit<T>(
        &mut self,
        items: &mut Vec<T>,
        limit: usize,
        cost: impl Fn(&T) -> usize,
    ) -> BudgetOutcome {
        let input_len = items.len();
        let item_limit = limit.min(MAX_CONTEXT_INPUT_ITEMS).min(self.remaining_items);
        let byte_limit = MAX_CONTEXT_INPUT_BYTES.min(self.remaining_bytes);
        let mut retained_len = 0usize;
        let mut retained_bytes = 0usize;
        for item in items.iter().take(item_limit) {
            let item_cost = cost(item).min(MAX_CONTEXT_INPUT_BYTES.saturating_add(1));
            if retained_bytes.saturating_add(item_cost) > byte_limit {
                break;
            }
            retained_len += 1;
            retained_bytes = retained_bytes.saturating_add(item_cost);
        }
        self.remaining_items = self.remaining_items.saturating_sub(retained_len);
        self.remaining_bytes = self.remaining_bytes.saturating_sub(retained_bytes);
        if retained_len < items.len() {
            items.truncate(retained_len);
        }
        BudgetOutcome {
            input_len,
            retained_len,
            omitted_count: input_len.saturating_sub(retained_len),
            total_unknown: retained_len < input_len,
            truncated: retained_len < input_len,
        }
    }
}

pub(crate) fn build_context_payload(inputs: &ContextInputs) -> (ContextPayload, PayloadAccounting) {
    let mut accounting = PayloadAccounting::default();
    let metrics = match &inputs.metrics {
        ContextInput::Collected(snapshot) => Some(build_metrics_payload(snapshot, &mut accounting)),
        _ => None,
    };
    let processes = match &inputs.processes {
        ContextInput::Collected(snapshot) => Some(build_process_payload(snapshot, &mut accounting)),
        _ => None,
    };
    let logs = match &inputs.logs {
        ContextInput::Collected(snapshot) => {
            let declared_omitted = snapshot
                .source_statuses
                .iter()
                .take(16)
                .map(|source| source.matched_entry_count)
                .sum::<usize>()
                .saturating_sub(snapshot.entries.len());
            let entries = bounded_page(
                snapshot.entries.iter(),
                snapshot.entries.len(),
                declared_omitted,
                MAX_LOG_ENTRIES,
                |entry| {
                    bounded_cost([
                        entry.source.len(),
                        entry.timestamp.as_ref().map_or(0, String::len),
                        entry.severity.as_ref().map_or(0, String::len),
                        entry.unit.as_ref().map_or(0, String::len),
                        entry.message.len(),
                    ])
                },
                |entry| {
                    (
                        safe_identifier(&entry.timestamp.clone().unwrap_or_default()),
                        safe_identifier(&entry.source),
                        safe_identifier(&entry.unit.clone().unwrap_or_default()),
                        safe_text(&entry.message),
                    )
                },
                |entry| ContextLogEntryPayload {
                    source: safe_identifier(&entry.source),
                    timestamp: entry.timestamp.as_deref().map(safe_identifier),
                    severity: entry.severity.as_deref().map(safe_identifier),
                    unit: entry.unit.as_deref().map(safe_identifier),
                    message: safe_text(&entry.message),
                },
            );
            let patterns = bounded_page(
                snapshot.patterns.iter(),
                snapshot.patterns.len(),
                snapshot.omitted_pattern_count,
                MAX_LOG_PATTERNS,
                |pattern| bounded_cost([pattern.kind.len(), pattern.message.len()]),
                |pattern| {
                    (
                        safe_identifier(&pattern.kind),
                        safe_identifier(
                            &pattern
                                .evidence
                                .as_ref()
                                .and_then(|evidence| evidence.unit.clone())
                                .unwrap_or_default(),
                        ),
                    )
                },
                |pattern| ContextLogPatternPayload {
                    kind: safe_identifier(&pattern.kind),
                    count: pattern.count,
                    score: pattern.score,
                    unit: pattern
                        .evidence
                        .as_ref()
                        .and_then(|evidence| evidence.unit.as_deref())
                        .map(safe_identifier),
                },
            );
            accounting
                .dimensions
                .insert(ContextDimension::Logs, page_accounting(&entries));
            Some(ContextLogPayload {
                entries,
                patterns,
                filter_complete: snapshot.filter_complete,
            })
        }
        _ => None,
    };
    let network = match &inputs.network {
        ContextInput::Collected(snapshot) => Some(build_network_payload(snapshot, &mut accounting)),
        _ => None,
    };
    let services = match &inputs.services {
        ContextInput::Collected(snapshot) => Some(build_service_payload(snapshot, &mut accounting)),
        _ => None,
    };
    accounting.input_truncated = accounting
        .dimensions
        .values()
        .chain(accounting.capabilities.values())
        .any(|page| page.total_unknown);
    (
        ContextPayload {
            metrics,
            processes,
            logs,
            network,
            services,
        },
        accounting,
    )
}

fn build_metrics_payload(
    snapshot: &MetricSnapshot,
    accounting: &mut PayloadAccounting,
) -> ContextMetricsPayload {
    let disks = bounded_page(
        snapshot.disks.iter(),
        snapshot.disks.len(),
        0,
        MAX_DISKS,
        |disk| bounded_cost([disk.mount_point.len(), disk.filesystem.len()]),
        |disk| safe_identifier(&disk.mount_point),
        |disk| ContextDiskPayload {
            mount_point: safe_identifier(&disk.mount_point),
            filesystem: safe_identifier(&disk.filesystem),
            total_bytes: disk.total_bytes,
            available_bytes: disk.available_bytes,
            used_percent: disk
                .used_percent
                .map(|value| value.clamp(0.0, 100.0).round() as u64),
        },
    );
    let disk_devices = bounded_page(
        snapshot.disk_devices.iter(),
        snapshot.disk_devices.len(),
        0,
        MAX_DISK_DEVICES,
        |device| device.name.len(),
        |device| safe_identifier(&device.name),
        |device| ContextDiskDevicePayload {
            name: safe_identifier(&device.name),
            read_bytes_per_sec: finite(device.read_bytes_per_sec),
            write_bytes_per_sec: finite(device.write_bytes_per_sec),
            read_iops: finite(device.read_iops),
            write_iops: finite(device.write_iops),
            io_in_progress: device.io_in_progress,
        },
    );
    let interfaces = bounded_page(
        snapshot.network.interfaces.iter(),
        snapshot.network.interfaces.len(),
        0,
        MAX_INTERFACES,
        |interface| interface.name.len(),
        |interface| safe_identifier(&interface.name),
        |interface| ContextNetworkInterfacePayload {
            name: safe_identifier(&interface.name),
            receive_bytes_per_sec: finite(interface.receive_bytes_per_sec),
            transmit_bytes_per_sec: finite(interface.transmit_bytes_per_sec),
            receive_errors_total: interface.receive_errors_total,
            transmit_errors_total: interface.transmit_errors_total,
            receive_dropped_total: interface.receive_dropped_total,
            transmit_dropped_total: interface.transmit_dropped_total,
        },
    );
    let thermal = thermal_page(snapshot);
    accounting.dimensions.insert(
        ContextDimension::Disk,
        combine_accounting(&disks, &disk_devices),
    );
    accounting
        .dimensions
        .insert(ContextDimension::Thermal, page_accounting(&thermal));
    accounting.dimensions.insert(
        ContextDimension::NetworkMetrics,
        page_accounting(&interfaces),
    );
    accounting
        .capabilities
        .insert(ContextCapability::ThermalSensors, page_accounting(&thermal));
    accounting.capabilities.insert(
        ContextCapability::NetworkMetrics,
        page_accounting(&interfaces),
    );
    ContextMetricsPayload {
        cpu: crate::model::ContextCpuPayload {
            usage_percent: finite(snapshot.cpu.usage_percent),
            cpu_count: snapshot.cpu.cpu_count,
            sample_interval_ms: snapshot.cpu.sample_interval_ms,
        },
        memory: ContextMemoryPayload {
            total_kb: snapshot.memory.total_kb,
            available_kb: snapshot.memory.available_kb,
            used_kb: snapshot.memory.used_kb,
            used_percent: finite(snapshot.memory.used_percent),
            swap_total_kb: snapshot.memory.swap_total_kb,
            swap_used_kb: snapshot.memory.swap_used_kb,
        },
        load: snapshot.load.as_ref().map(|load| ContextLoadPayload {
            one: finite_value(load.one),
            five: finite_value(load.five),
            fifteen: finite_value(load.fifteen),
            runnable_tasks: load.runnable_tasks,
            total_tasks: load.total_tasks,
        }),
        disks,
        disk_devices,
        network_interfaces: interfaces,
        thermal_sensors: thermal,
    }
}

fn build_process_payload(
    snapshot: &ProcessList,
    accounting: &mut PayloadAccounting,
) -> ContextProcessPayload {
    let declared_omitted = snapshot.total.saturating_sub(snapshot.processes.len());
    let processes = bounded_page(
        snapshot.processes.iter(),
        snapshot.processes.len(),
        declared_omitted,
        MAX_PROCESSES,
        |process| {
            bounded_cost([
                process.name.len(),
                process.state.len(),
                process.user.as_ref().map_or(0, String::len),
                process.command.as_ref().map_or(0, String::len),
                process.executable_path.as_ref().map_or(0, String::len),
            ])
        },
        |process| process.pid,
        |process| ContextProcessItem {
            pid: process.pid,
            ppid: process.ppid,
            name: safe_identifier(&process.name),
            state: safe_identifier(&process.state),
            user: process.user.as_deref().map(safe_identifier),
            cpu_usage_percent: finite(process.cpu_usage_percent),
            memory_rss_kb: process.memory_rss_kb,
            memory_percent: finite(process.memory_percent),
            authorized: process.authorized,
        },
    );
    accounting
        .dimensions
        .insert(ContextDimension::Processes, page_accounting(&processes));
    ContextProcessPayload {
        processes,
        anomaly_total: snapshot.anomaly_count.max(snapshot.anomalies.len()),
        unauthorized_total: snapshot.unauthorized_total,
        filter_complete: snapshot.filter_complete,
    }
}

fn build_network_payload(
    snapshot: &NetworkSnapshot,
    accounting: &mut PayloadAccounting,
) -> ContextNetworkPayload {
    let connections = bounded_page(
        snapshot.connections.iter(),
        snapshot.connections.len(),
        snapshot.total.saturating_sub(snapshot.connections.len()),
        MAX_CONNECTIONS,
        |connection| {
            bounded_cost([
                connection.protocol.len(),
                connection.local_address.len(),
                connection.local_addr.len(),
                connection.remote_address.len(),
                connection.remote_addr.len(),
                connection.state.len(),
            ])
        },
        |connection| {
            (
                safe_identifier(&connection.protocol),
                canonical_address(&connection.local_address, &connection.local_addr),
                connection.local_port,
                canonical_address(&connection.remote_address, &connection.remote_addr),
                connection.remote_port,
                safe_identifier(&connection.state),
            )
        },
        |connection| ContextConnectionPayload {
            protocol: safe_identifier(&connection.protocol),
            local_address: canonical_address(&connection.local_address, &connection.local_addr),
            local_port: connection.local_port,
            remote_address: canonical_address(&connection.remote_address, &connection.remote_addr),
            remote_port: connection.remote_port,
            state: safe_identifier(&connection.state),
            uid: connection.uid,
        },
    );
    let dns_checks = bounded_page(
        snapshot.dns_checks.iter(),
        snapshot.dns_checks.len(),
        0,
        MAX_DNS_CHECKS,
        |check| {
            bounded_cost([
                check.name.len(),
                check.error.as_ref().map_or(0, String::len),
            ])
        },
        |check| safe_identifier(&check.name),
        |check| ContextProbePayload {
            status: format!("{:?}", check.status).to_ascii_lowercase(),
            stage: "resolution".to_string(),
            ok: check.ok,
            latency_ms: check.latency_ms,
            status_code: None,
            error_kind: None,
        },
    );
    let tcp_probes = bounded_page(
        snapshot.tcp_probes.iter(),
        snapshot.tcp_probes.len(),
        0,
        MAX_PROBES,
        |probe| {
            bounded_cost([
                probe.target.len(),
                probe.error.as_ref().map_or(0, String::len),
            ])
        },
        |probe| safe_identifier(&probe.target),
        tcp_probe_payload,
    );
    let firewall = bounded_page(
        snapshot.firewall.iter(),
        snapshot.firewall.len(),
        0,
        MAX_FIREWALL,
        |firewall| {
            bounded_cost([
                firewall.backend.len(),
                firewall.error.as_ref().map_or(0, String::len),
            ])
        },
        |firewall| safe_identifier(&firewall.backend),
        |firewall| ContextFirewallPayload {
            backend: safe_identifier(&firewall.backend),
            available: firewall.available,
            active: firewall.active,
            status: firewall.status,
            rule_count: firewall.rule_count,
            omitted_rule_count: firewall.omitted_rule_count,
            truncated: firewall.truncated,
            error_kind: firewall.error_kind,
        },
    );
    accounting
        .dimensions
        .insert(ContextDimension::Network, page_accounting(&connections));
    accounting
        .capabilities
        .insert(ContextCapability::DnsChecks, page_accounting(&dns_checks));
    accounting.capabilities.insert(
        ContextCapability::NetworkTcpProbes,
        page_accounting(&tcp_probes),
    );
    accounting
        .capabilities
        .insert(ContextCapability::Firewall, page_accounting(&firewall));
    ContextNetworkPayload {
        connections,
        dns_resolver_status: if snapshot.dns_resolver.available {
            collection_status(snapshot.dns_resolver.status)
        } else {
            crate::model::ContextDimensionStatus::Unavailable
        },
        dns_checks,
        tcp_probes,
        firewall,
        anomaly_total: snapshot.anomaly_total.max(snapshot.anomalies.len()),
        filter_complete: snapshot.filter_complete,
    }
}

fn build_service_payload(
    snapshot: &ServiceSnapshot,
    accounting: &mut PayloadAccounting,
) -> ContextServicePayload {
    let units = bounded_page(
        snapshot.units.iter(),
        snapshot.units.len(),
        snapshot
            .omitted_count
            .max(snapshot.total.saturating_sub(snapshot.returned_count)),
        MAX_SERVICE_UNITS,
        service_unit_cost,
        |unit| safe_identifier(&unit.name),
        service_unit_payload,
    );
    let failed_units = bounded_page(
        snapshot.failed_units.iter(),
        snapshot.failed_units.len(),
        snapshot.failed_omitted_count,
        MAX_SERVICE_NAMES,
        service_unit_cost,
        |unit| safe_identifier(&unit.name),
        |unit| safe_identifier(&unit.name),
    );
    let problem_units = bounded_page(
        snapshot.problem_units.iter(),
        snapshot.problem_units.len(),
        snapshot.problem_omitted_count,
        MAX_SERVICE_NAMES,
        service_unit_cost,
        |unit| safe_identifier(&unit.name),
        |unit| safe_identifier(&unit.name),
    );
    let (port_bindings, port_input_len, ports_force_unknown) = bounded_port_refs(snapshot);
    let mut ports = bounded_page(
        port_bindings.into_iter(),
        port_input_len,
        snapshot.port_collection.omitted_count,
        MAX_SERVICE_PORTS,
        port_binding_cost,
        |binding| {
            if binding.binding_id.is_empty() {
                format!(
                    "{:?}:{}:{}:{}",
                    binding.protocol, binding.local_address, binding.port, binding.inode
                )
            } else {
                safe_identifier(&binding.binding_id)
            }
        },
        service_port_payload,
    );
    if ports_force_unknown {
        force_page_unknown(&mut ports);
    }
    let dependency_impacts =
        snapshot
            .dependency_analysis
            .as_ref()
            .map_or_else(ContextPage::default, |analysis| {
                bounded_page(
                    analysis.impacts.iter(),
                    analysis.impacts.len(),
                    analysis.omitted_count,
                    MAX_DEPENDENCY_IMPACTS,
                    |impact| {
                        impact.service.len().saturating_add(
                            impact
                                .path
                                .iter()
                                .take(16)
                                .map(|edge| {
                                    edge.dependency.len().saturating_add(edge.dependent.len())
                                })
                                .sum::<usize>(),
                        )
                    },
                    |impact| safe_identifier(&impact.service),
                    |impact| ContextDependencyImpactPayload {
                        service: safe_identifier(&impact.service),
                        depth: impact.depth,
                        severity: Some(impact.severity),
                        has_direct_relation: impact.has_direct_relation,
                        path: impact
                            .path
                            .iter()
                            .take(8)
                            .map(|edge| {
                                format!(
                                    "{}>{}:{:?}",
                                    safe_identifier(&edge.dependency),
                                    safe_identifier(&edge.dependent),
                                    edge.relation
                                )
                                .to_ascii_lowercase()
                            })
                            .collect(),
                    },
                )
            });
    let tcp_probes = bounded_page(
        snapshot.health_probes.iter(),
        snapshot.health_probes.len(),
        0,
        MAX_PROBES,
        |probe| {
            bounded_cost([
                probe.target.len(),
                probe.error.as_ref().map_or(0, String::len),
            ])
        },
        |probe| safe_identifier(&probe.target),
        tcp_probe_payload,
    );
    let http_probes = bounded_page(
        snapshot.http_probes.iter(),
        snapshot.http_probes.len(),
        0,
        MAX_PROBES,
        |probe| {
            bounded_cost([
                probe.target.len(),
                probe.error.as_ref().map_or(0, String::len),
            ])
        },
        |probe| safe_identifier(&probe.target),
        |probe| ContextProbePayload {
            status: format!("{:?}", probe.status).to_ascii_lowercase(),
            stage: format!("{:?}", probe.stage).to_ascii_lowercase(),
            ok: probe.ok,
            latency_ms: probe.latency_ms,
            status_code: probe.status_code,
            error_kind: probe
                .error_kind
                .map(|kind| format!("{kind:?}").to_ascii_lowercase()),
        },
    );
    accounting
        .dimensions
        .insert(ContextDimension::Services, page_accounting(&units));
    for (capability, page) in [
        (
            ContextCapability::ServiceFailureAnalysis,
            page_accounting(&failed_units),
        ),
        (
            ContextCapability::ServiceProblemAnalysis,
            page_accounting(&problem_units),
        ),
        (ContextCapability::ServicePorts, page_accounting(&ports)),
        (
            ContextCapability::ServiceDependencies,
            page_accounting(&dependency_impacts),
        ),
        (
            ContextCapability::ServiceTcpProbes,
            page_accounting(&tcp_probes),
        ),
        (
            ContextCapability::ServiceHttpProbes,
            page_accounting(&http_probes),
        ),
    ] {
        accounting.capabilities.insert(capability, page);
    }
    ContextServicePayload {
        units,
        failed_units,
        problem_units,
        ports,
        dependency_impacts,
        tcp_probes,
        http_probes,
        failed_filter_complete: snapshot.failed_filter_complete,
        problem_filter_complete: snapshot.problem_filter_complete,
    }
}

#[allow(clippy::too_many_arguments)]
fn bounded_page<'a, T: 'a, K, U, I, FCost, FKey, FMap>(
    items: I,
    _input_len: usize,
    declared_omitted: usize,
    output_limit: usize,
    cost: FCost,
    key: FKey,
    map: FMap,
) -> ContextPage<U>
where
    K: Ord,
    I: IntoIterator<Item = &'a T>,
    FCost: Fn(&T) -> usize,
    FKey: Fn(&T) -> K,
    FMap: Fn(&T) -> U,
{
    let mut unique = BTreeMap::<K, &T>::new();
    for item in items {
        let _ = cost(item);
        unique.entry(key(item)).or_insert(item);
    }
    let known_unique = unique.len();
    let total_unknown = false;
    let total = known_unique.saturating_add(declared_omitted);
    let items = unique
        .into_values()
        .take(output_limit)
        .map(map)
        .collect::<Vec<_>>();
    let returned_count = items.len();
    let omitted_count = total.saturating_sub(returned_count);
    ContextPage {
        total,
        returned_count,
        omitted_count,
        total_unknown,
        truncated: omitted_count > 0 || total_unknown,
        items,
    }
}

fn thermal_page(snapshot: &MetricSnapshot) -> ContextPage<ContextThermalPayload> {
    let mut unique = BTreeMap::<String, ContextThermalPayload>::new();
    for temperature in &snapshot.thermal.temperatures {
        let _ = bounded_cost([
            temperature.source.len(),
            temperature.label.as_ref().map_or(0, String::len),
            temperature.path.len(),
        ]);
        let key = format!(
            "temperature:{}:{}",
            safe_identifier(&temperature.source),
            safe_identifier(&temperature.label.clone().unwrap_or_default())
        );
        unique.entry(key).or_insert_with(|| ContextThermalPayload {
            source: safe_identifier(&temperature.source),
            label: temperature.label.as_deref().map(safe_identifier),
            value: temperature.millidegrees_celsius,
            unit: "millidegrees_celsius".to_string(),
        });
    }
    for fan in &snapshot.thermal.fans {
        let _ = bounded_cost([
            fan.source.len(),
            fan.label.as_ref().map_or(0, String::len),
            fan.path.len(),
        ]);
        let key = format!(
            "fan:{}:{}",
            safe_identifier(&fan.source),
            safe_identifier(&fan.label.clone().unwrap_or_default())
        );
        unique.entry(key).or_insert_with(|| ContextThermalPayload {
            source: safe_identifier(&fan.source),
            label: fan.label.as_deref().map(safe_identifier),
            value: i64::try_from(fan.rpm).unwrap_or(i64::MAX),
            unit: "rpm".to_string(),
        });
    }
    let total_unknown = false;
    let total = unique.len();
    let items = unique.into_values().take(MAX_THERMAL).collect::<Vec<_>>();
    let returned_count = items.len();
    let omitted_count = total.saturating_sub(returned_count);
    ContextPage {
        total,
        returned_count,
        omitted_count,
        total_unknown,
        truncated: omitted_count > 0 || total_unknown,
        items,
    }
}

fn bounded_port_refs(snapshot: &ServiceSnapshot) -> (Vec<&ServicePortBinding>, usize, bool) {
    let mut refs = Vec::new();
    let mut input_len = 0usize;
    let mut total_unknown = snapshot.units.len() > MAX_CONTEXT_INPUT_ITEMS;
    for unit in snapshot.units.iter().take(MAX_CONTEXT_INPUT_ITEMS) {
        input_len = input_len.saturating_add(unit.port_bindings.len().min(64));
        total_unknown |= unit.port_bindings.len() > 64;
        refs.extend(unit.port_bindings.iter().take(64));
        if refs.len() >= MAX_CONTEXT_INPUT_ITEMS {
            refs.truncate(MAX_CONTEXT_INPUT_ITEMS);
            total_unknown = true;
            break;
        }
    }
    let remaining = MAX_CONTEXT_INPUT_ITEMS.saturating_sub(refs.len());
    input_len = input_len.saturating_add(
        snapshot
            .port_collection
            .unowned_bindings
            .len()
            .min(remaining),
    );
    total_unknown |= snapshot.port_collection.unowned_bindings.len() > remaining;
    refs.extend(
        snapshot
            .port_collection
            .unowned_bindings
            .iter()
            .take(remaining),
    );
    (refs, input_len, total_unknown)
}

fn service_unit_payload(unit: &crate::model::ServiceUnit) -> ContextServiceUnitPayload {
    let mut ports = unit
        .port_bindings
        .iter()
        .take(16)
        .map(|binding| binding.port)
        .collect::<Vec<_>>();
    ports.sort_unstable();
    ports.dedup();
    ContextServiceUnitPayload {
        name: safe_identifier(&unit.name),
        load_state: unit.load_state.as_deref().map(safe_identifier),
        active_state: unit.active_state.as_deref().map(safe_identifier),
        sub_state: unit.sub_state.as_deref().map(safe_identifier),
        unit_file_state: unit.unit_file_state.as_deref().map(safe_identifier),
        health_status: unit.health_status,
        problems: unit
            .problems
            .iter()
            .take(8)
            .map(|problem| problem.kind)
            .collect(),
        ports,
        requires: bounded_names(&unit.requires, 8),
        wants: bounded_names(&unit.wants, 8),
    }
}

fn service_port_payload(binding: &ServicePortBinding) -> ContextServicePortPayload {
    ContextServicePortPayload {
        binding_id: safe_identifier(&binding.binding_id),
        protocol: binding.protocol,
        local_address: safe_identifier(&binding.local_address),
        port: binding.port,
        ownership_status: binding.ownership_status,
        owner_services: bounded_names(&binding.owner_services, 8),
    }
}

fn tcp_probe_payload(probe: &crate::model::HealthProbeResult) -> ContextProbePayload {
    ContextProbePayload {
        status: format!("{:?}", probe.status).to_ascii_lowercase(),
        stage: format!("{:?}", probe.stage).to_ascii_lowercase(),
        ok: probe.ok,
        latency_ms: probe.latency_ms,
        status_code: None,
        error_kind: probe
            .error_kind
            .map(|kind| format!("{kind:?}").to_ascii_lowercase()),
    }
}

fn page_accounting<T>(page: &ContextPage<T>) -> PageAccounting {
    PageAccounting {
        total: page.total,
        returned_count: page.items.len(),
        omitted_count: page.total.saturating_sub(page.items.len()),
        total_unknown: page.total_unknown,
        truncated: page.truncated || page.total > page.items.len(),
    }
}

fn combine_accounting<T, U>(left: &ContextPage<T>, right: &ContextPage<U>) -> PageAccounting {
    PageAccounting {
        total: left.total.saturating_add(right.total),
        returned_count: left.items.len().saturating_add(right.items.len()),
        omitted_count: left
            .total
            .saturating_add(right.total)
            .saturating_sub(left.items.len().saturating_add(right.items.len())),
        total_unknown: left.total_unknown || right.total_unknown,
        truncated: left.truncated || right.truncated,
    }
}

fn force_page_unknown<T>(page: &mut ContextPage<T>) {
    if !page.total_unknown {
        page.total = page.total.saturating_add(1);
        page.omitted_count = page.total.saturating_sub(page.items.len());
    }
    page.total_unknown = true;
    page.truncated = true;
}

fn service_unit_cost(unit: &crate::model::ServiceUnit) -> usize {
    bounded_cost([
        unit.name.len(),
        unit.description.as_ref().map_or(0, String::len),
        unit.load_state.as_ref().map_or(0, String::len),
        unit.active_state.as_ref().map_or(0, String::len),
        unit.sub_state.as_ref().map_or(0, String::len),
        unit.requires
            .iter()
            .take(16)
            .map(String::len)
            .sum::<usize>(),
        unit.wants.iter().take(16).map(String::len).sum::<usize>(),
    ])
}

fn port_binding_cost(binding: &ServicePortBinding) -> usize {
    bounded_cost([
        binding.binding_id.len(),
        binding.local_address.len(),
        binding
            .owner_services
            .iter()
            .take(16)
            .map(String::len)
            .sum::<usize>(),
    ])
}

fn bounded_names(values: &[String], limit: usize) -> Vec<String> {
    let mut names = BTreeSet::new();
    for value in values.iter().take(limit.saturating_mul(4).min(64)) {
        names.insert(safe_identifier(value));
        if names.len() >= limit {
            break;
        }
    }
    names.into_iter().collect()
}

fn bounded_cost<const N: usize>(parts: [usize; N]) -> usize {
    parts.into_iter().fold(0usize, usize::saturating_add)
}

fn safe_identifier(value: &str) -> String {
    safe_bounded_text(value, MAX_IDENTIFIER_CHARS)
}

fn safe_text(value: &str) -> String {
    safe_bounded_text(value, MAX_TEXT_CHARS)
}

fn safe_bounded_text(value: &str, max_chars: usize) -> String {
    let scan_chars = max_chars.saturating_mul(2).max(max_chars);
    let prefix = value
        .chars()
        .take(scan_chars)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    redact_sensitive_text(&prefix, max_chars.saturating_sub(TRUNCATION_MARKER_LEN))
}

fn canonical_address(primary: &str, legacy: &str) -> String {
    if primary.is_empty() {
        safe_identifier(legacy)
    } else {
        safe_identifier(primary)
    }
}

fn finite(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite())
}

fn finite_value(value: f64) -> f64 {
    if value.is_finite() {
        value
    } else {
        0.0
    }
}

fn collection_status(
    status: crate::model::CollectionStatus,
) -> crate::model::ContextDimensionStatus {
    match status {
        crate::model::CollectionStatus::Complete => crate::model::ContextDimensionStatus::Complete,
        crate::model::CollectionStatus::Partial => crate::model::ContextDimensionStatus::Partial,
        crate::model::CollectionStatus::Failed => crate::model::ContextDimensionStatus::Failed,
    }
}
