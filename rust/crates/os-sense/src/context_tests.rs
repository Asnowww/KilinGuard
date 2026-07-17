use super::*;
use serde_json::{json, Value};

fn meta_json(source: &str, collected_at_ms: u64) -> Value {
    json!({
        "collected_at_ms": collected_at_ms,
        "source": source,
        "platform": {
            "os": "linux",
            "arch": "x86_64",
            "kernel_version": "6.1",
            "loongarch": {
                "detected": false,
                "cpu_model": null,
                "hwmon_paths": [],
                "hwmon_sensors": []
            }
        },
        "warnings": []
    })
}

fn metrics_fixture() -> MetricSnapshot {
    serde_json::from_value(json!({
            "meta": meta_json("procfs+sysfs", 110),
            "mode": "on_demand",
            "started_at_ms": 100,
            "completed_at_ms": 110,
            "status": "complete",
            "dimension_results": [
                {"dimension":"cpu","status":"complete","retryable":false,"message":null},
                {"dimension":"memory","status":"complete","retryable":false,"message":null},
                {"dimension":"disk","status":"complete","retryable":false,"message":null},
                {"dimension":"network","status":"complete","retryable":false,"message":null},
                {"dimension":"thermal","status":"complete","retryable":false,"message":null}
            ],
            "attempted_dimensions": ["cpu","memory","disk","network","thermal"],
            "updated_dimensions": ["cpu","memory","disk","network","thermal"],
            "cpu": {"collected_at_ms":110,"usage_percent":12.5,"total_jiffies":100,"idle_jiffies":80,"cpu_count":1,"cores":[]},
            "memory": {"collected_at_ms":110,"total_kb":1000,"available_kb":500,"used_kb":500,"used_percent":50.0},
            "load": {"one":0.1,"five":0.2,"fifteen":0.3,"runnable_tasks":1,"total_tasks":10,"last_pid":9},
            "disks": [],
            "disk_devices": [],
            "network": {"collected_at_ms":110,"connection_count":0,"interfaces":[]},
            "thermal": {"collected_at_ms":110,"availability":"available","thermal_zone_available":true,"hwmon_available":false,"hwmon_sensors":[],"temperatures":[],"fans":[]},
            "alerts": []
        }))
        .expect("metric fixture")
}

fn process_fixture(anomalies: Vec<crate::model::ProcessAnomaly>) -> ProcessList {
    serde_json::from_value(json!({
        "meta": meta_json("procfs", 120),
        "total": 0,
        "truncated": false,
        "collection_status": "complete",
        "processes": [],
        "anomalies": anomalies,
        "anomaly_count": anomalies.len(),
        "filter_complete": true,
        "unauthorized": []
    }))
    .expect("process fixture")
}

fn logs_fixture(patterns: Vec<crate::model::LogPattern>) -> LogQueryResult {
    serde_json::from_value(json!({
        "meta": meta_json("journalctl+log-files", 130),
        "truncated": false,
        "collection_status": "complete",
        "source_statuses": [],
        "filter_complete": true,
        "entries": [],
        "patterns": patterns,
        "pattern_input_count": patterns.len(),
        "omitted_pattern_count": 0,
        "summary": null
    }))
    .expect("log fixture")
}

fn network_fixture(anomalies: Vec<crate::model::NetworkAnomaly>) -> NetworkSnapshot {
    serde_json::from_value(json!({
            "meta": meta_json("procfs+resolv.conf", 140),
            "truncated": false,
            "collection_status": "complete",
            "source_statuses": [],
            "total": 0,
            "filter_complete": true,
            "connections": [],
            "dns_resolver": {"status":"complete","available":true,"actual_path":"/etc/resolv.conf","nameservers":[],"search_domains":[],"options":[]},
            "dns_checks": [],
            "tcp_probes": [],
            "firewall": [],
            "anomalies": anomalies,
            "anomaly_total": anomalies.len(),
            "anomalies_truncated": false,
            "omitted_anomaly_count": 0
        }))
        .expect("network fixture")
}

fn service_problem_unit(index: usize) -> crate::model::ServiceUnit {
    serde_json::from_value(json!({
        "name": format!("problem-{index:03}.service"),
        "load_state": "loaded",
        "active_state": "failed",
        "sub_state": "failed",
        "result": "exit-code",
        "health_status": "failed",
        "problems": [{"kind":"exit_code"}],
        "problem_complete": true
    }))
    .expect("service unit fixture")
}

fn services_fixture(problem_units: Vec<crate::model::ServiceUnit>) -> ServiceSnapshot {
    serde_json::from_value(json!({
        "meta": meta_json("systemctl", 150),
        "available": true,
        "truncated": false,
        "collection_status": "complete",
        "source_statuses": [],
        "total": 0,
        "returned_count": 0,
        "omitted_count": 0,
        "failed_total": problem_units.len(),
        "failed_returned_count": problem_units.len(),
        "failed_omitted_count": 0,
        "failed_filter_complete": true,
        "problem_total": problem_units.len(),
        "problem_returned_count": problem_units.len(),
        "problem_omitted_count": 0,
        "problem_filter_complete": true,
        "filter_complete": true,
        "units": [],
        "failed_units": problem_units,
        "problem_units": problem_units,
        "health_probes": [],
        "http_probes": []
    }))
    .expect("service fixture")
}

fn complete_inputs() -> ContextInputs {
    ContextInputs {
        collected_at_ms: 200,
        metrics: ContextInput::Collected(metrics_fixture()),
        processes: ContextInput::Collected(process_fixture(Vec::new())),
        logs: ContextInput::Collected(logs_fixture(Vec::new())),
        network: ContextInput::Collected(network_fixture(Vec::new())),
        services: ContextInput::Collected(services_fixture(Vec::new())),
    }
}

fn dimension(context: &LlmOsContext, wanted: ContextDimension) -> &ContextDimensionMetadata {
    context
        .dimensions
        .iter()
        .find(|dimension| dimension.dimension == wanted)
        .expect("dimension metadata")
}

fn process_item(pid: u32, name: &str) -> crate::model::ProcessInfo {
    serde_json::from_value(json!({
        "pid": pid,
        "ppid": 1,
        "name": name,
        "state": "S",
        "user": "root",
        "cpu_time_jiffies": 10,
        "memory_rss_kb": 128,
        "virtual_memory_kb": 256,
        "uptime_seconds": 10.0,
        "command": "worker",
        "anomalies": [],
        "authorized": true
    }))
    .expect("process item")
}

fn connection(port: u16) -> crate::model::NetworkConnection {
    crate::model::NetworkConnection {
        protocol: "tcp".to_string(),
        local_addr: "127.0.0.1".to_string(),
        local_address: "127.0.0.1".to_string(),
        local_port: port,
        remote_addr: "127.0.0.1".to_string(),
        remote_address: "127.0.0.1".to_string(),
        remote_port: 40_000,
        state: "LISTEN".to_string(),
        inode: Some("42".to_string()),
        uid: Some(0),
    }
}

fn port_binding(id: &str, port: u16) -> crate::model::ServicePortBinding {
    crate::model::ServicePortBinding {
        binding_id: id.to_string(),
        network_namespace: Some(1),
        protocol: crate::model::ServicePortProtocol::Tcp,
        local_address: "127.0.0.1".to_string(),
        port,
        inode: 42,
        pids: vec![10],
        pid_total: 1,
        omitted_pid_count: 0,
        unowned_pids: Vec::new(),
        unowned_pid_total: 0,
        omitted_unowned_pid_count: 0,
        owner_services: vec!["demo.service".to_string()],
        owner_service_total: 1,
        omitted_owner_service_count: 0,
        ownership_complete: true,
        ownership_status: crate::model::ServicePortOwnershipStatus::Owned,
    }
}

fn dependency_analysis() -> crate::model::ServiceDependencyAnalysis {
    crate::model::ServiceDependencyAnalysis {
        target: "database.service".to_string(),
        target_found: true,
        collection_status: CollectionStatus::Complete,
        complete: true,
        direct_total: 1,
        total: 1,
        returned_count: 1,
        omitted_count: 0,
        cycle_detected: false,
        depth_truncated: false,
        traversal_truncated: false,
        total_unknown: false,
        truncated: false,
        impacts: vec![crate::model::ServiceDependencyImpact {
            service: "api.service".to_string(),
            depth: 1,
            direct: true,
            has_direct_relation: true,
            selected_path_direct: true,
            direct_relations: vec![crate::model::DependencyRelationKind::Requires],
            severity: crate::model::DependencyImpactSeverity::Hard,
            reason: crate::model::DependencyImpactReason::RequiredDependency,
            path: vec![crate::model::ServiceDependencyPathEdge {
                dependency: "database.service".to_string(),
                dependent: "api.service".to_string(),
                relation: crate::model::DependencyRelationKind::Requires,
                severity: crate::model::DependencyImpactSeverity::Hard,
            }],
        }],
    }
}

#[test]
fn crops_dimensions_by_network_intent() {
    let dims = dimensions_for_intent(Some("check dns and firewall"));
    assert_eq!(dims, vec!["network"]);
}

#[test]
fn health_intent_collects_all_dimensions() {
    let dims = dimensions_for_intent(Some("overall health"));
    assert_eq!(dims, all_dimensions());
}

#[test]
fn network_summary_reports_total_and_omitted_anomalies() {
    let network = crate::model::NetworkSnapshot {
        meta: crate::procfs::basic_meta("network", Vec::new()),
        truncated: false,
        collection_status: crate::model::CollectionStatus::Complete,
        source_statuses: Vec::new(),
        total: 7,
        filter_complete: true,
        omitted_warning_count: 0,
        connections: Vec::new(),
        dns_resolver: crate::model::DnsResolverStatus::default(),
        dns_checks: Vec::new(),
        tcp_probes: Vec::new(),
        firewall: vec![
            crate::model::FirewallStatus {
                backend: "firewalld".to_string(),
                available: true,
                active: true,
                status: crate::model::CollectionStatus::Complete,
                rule_count: 5,
                ..crate::model::FirewallStatus::default()
            },
            crate::model::FirewallStatus {
                backend: "nftables".to_string(),
                available: true,
                active: false,
                status: crate::model::CollectionStatus::Partial,
                rule_count: 7,
                truncated: true,
                omitted_rule_count: 4,
                ..crate::model::FirewallStatus::default()
            },
            crate::model::FirewallStatus {
                backend: "iptables".to_string(),
                status: crate::model::CollectionStatus::Failed,
                ..crate::model::FirewallStatus::default()
            },
        ],
        anomalies: Vec::new(),
        anomaly_total: 35,
        anomalies_truncated: true,
        omitted_anomaly_count: 3,
    };
    let summary = build_health_summary(None, None, None, Some(&network), None, 0);
    assert!(summary.contains("35 anomalies (3 omitted from returned details)"));
    assert!(summary.contains("DNS resolver Partial with 0 nameserver(s)"));
    assert!(summary.contains(
            "firewall 1 active, 1 partial, 1 failed, 12 rules, 1 truncated backend(s), 4 omitted rule(s)"
        ));
}

#[test]
fn aggregates_all_dimensions_and_sub_capabilities() {
    let context = aggregate_context(complete_inputs());
    assert_eq!(context.llm_context.schema, CONTEXT_SCHEMA);
    assert_eq!(context.llm_context.version, CONTEXT_SCHEMA_VERSION);
    assert_eq!(context.llm_context.trust, "untrusted");
    assert_eq!(context.llm_context.handling, "data_only");
    assert!(!context.llm_context.instructions_allowed);
    assert_eq!(context.llm_context.status, ContextDimensionStatus::Complete);
    assert!(context.llm_context.complete);
    assert_eq!(
        context.llm_context.dimensions.len(),
        ContextDimension::ALL.len()
    );
    assert!(context
        .llm_context
        .dimensions
        .iter()
        .all(|dimension| dimension.requested && dimension.complete));

    let network = dimension(&context.llm_context, ContextDimension::Network);
    assert!(network
        .capabilities
        .iter()
        .any(
            |capability| capability.capability == ContextCapability::DnsResolver
                && capability.complete
        ));
    let services = dimension(&context.llm_context, ContextDimension::Services);
    assert!(services.capabilities.iter().any(|capability| {
        capability.capability == ContextCapability::ServiceFailureAnalysis && capability.complete
    }));
    assert!(services.capabilities.iter().any(|capability| {
        capability.capability == ContextCapability::ServicePorts
            && capability.status == ContextDimensionStatus::NotRequested
    }));
}

#[test]
fn distinguishes_missing_unavailable_failed_partial_and_complete() {
    let missing = aggregate_context(ContextInputs::new(10));
    assert_eq!(
        missing.llm_context.status,
        ContextDimensionStatus::NotRequested
    );
    assert!(!missing.llm_context.complete);
    assert!(missing
        .llm_context
        .dimensions
        .iter()
        .all(|dimension| !dimension.requested
            && dimension.status == ContextDimensionStatus::NotRequested));

    let unavailable = aggregate_context(ContextInputs {
        collected_at_ms: 10,
        logs: ContextInput::Unavailable {
            source: "journalctl".to_string(),
            reason: Some("not installed".to_string()),
        },
        ..ContextInputs::default()
    });
    assert_eq!(
        unavailable.llm_context.status,
        ContextDimensionStatus::Unavailable
    );

    let failed = aggregate_context(ContextInputs {
        collected_at_ms: 10,
        processes: ContextInput::Failed {
            source: "procfs".to_string(),
            error: "permission denied".to_string(),
        },
        ..ContextInputs::default()
    });
    assert_eq!(failed.llm_context.status, ContextDimensionStatus::Failed);

    let partial = aggregate_context(ContextInputs {
        collected_at_ms: 10,
        metrics: ContextInput::Collected(metrics_fixture()),
        processes: ContextInput::Failed {
            source: "procfs".to_string(),
            error: "process scan failed".to_string(),
        },
        ..ContextInputs::default()
    });
    assert_eq!(partial.llm_context.status, ContextDimensionStatus::Partial);
    assert!(!partial.llm_context.complete);
    assert_eq!(
        dimension(&partial.llm_context, ContextDimension::Processes).status,
        ContextDimensionStatus::Failed
    );
    assert!(
        partial.metrics.is_some(),
        "a failed dimension must not discard others"
    );
}

#[test]
fn counts_evidence_before_per_dimension_and_global_limits() {
    let process_anomalies = (0..40)
        .map(|index| crate::model::ProcessAnomaly {
            pid: 1_000 + index,
            kind: format!("process-{index:03}"),
            message: "raw process detail".to_string(),
            score: 0.9,
            evidence: None,
        })
        .collect::<Vec<_>>();
    let log_patterns = (0..40)
        .map(|index| crate::model::LogPattern {
            kind: format!("log-{index:03}"),
            count: 1,
            message: "raw log detail".to_string(),
            score: Some(90),
            evidence: None,
        })
        .collect::<Vec<_>>();
    let network_anomalies = (0..40)
        .map(|index| crate::model::NetworkAnomaly {
            kind: format!("network-{index:03}"),
            message: "raw network detail".to_string(),
            count: 1,
            score: 0.9,
            source: None,
            subject: None,
            evidence: None,
        })
        .collect::<Vec<_>>();
    let service_units = (0..40).map(service_problem_unit).collect::<Vec<_>>();
    let context = aggregate_context(ContextInputs {
        collected_at_ms: 200,
        processes: ContextInput::Collected(process_fixture(process_anomalies)),
        logs: ContextInput::Collected(logs_fixture(log_patterns)),
        network: ContextInput::Collected(network_fixture(network_anomalies)),
        services: ContextInput::Collected(services_fixture(service_units)),
        ..ContextInputs::default()
    });
    assert_eq!(context.llm_context.evidence_total, 160);
    assert_eq!(
        context.llm_context.evidence_returned_count,
        MAX_CONTEXT_EVIDENCE
    );
    assert_eq!(context.llm_context.evidence_omitted_count, 96);
    assert!(context.llm_context.truncated);
    assert_eq!(
        context.llm_context.evidence_total,
        context
            .llm_context
            .evidence_returned_count
            .saturating_add(context.llm_context.evidence_omitted_count)
    );
}

#[test]
fn aggregation_is_deterministic_and_deduplicates_evidence() {
    let mut anomalies = vec![
        crate::model::ProcessAnomaly {
            pid: 2,
            kind: "zombie".to_string(),
            message: "second".to_string(),
            score: 0.8,
            evidence: None,
        },
        crate::model::ProcessAnomaly {
            pid: 1,
            kind: "cpu".to_string(),
            message: "first".to_string(),
            score: 0.9,
            evidence: None,
        },
    ];
    let first = aggregate_context(ContextInputs {
        collected_at_ms: 200,
        processes: ContextInput::Collected(process_fixture(anomalies.clone())),
        ..ContextInputs::default()
    });
    anomalies.reverse();
    let second = aggregate_context(ContextInputs {
        collected_at_ms: 200,
        processes: ContextInput::Collected(process_fixture(anomalies)),
        ..ContextInputs::default()
    });
    assert_eq!(first.llm_context, second.llm_context);
}

#[test]
fn final_context_and_alert_context_are_redacted_bounded_and_data_only() {
    let secret = "Authorization: Bearer topsecret password=quoted X-Amz-Signature=signed";
    let context = aggregate_context(ContextInputs {
        collected_at_ms: 200,
        metrics: ContextInput::Collected(metrics_fixture()),
        logs: ContextInput::Failed {
            source: "journalctl".to_string(),
            error: secret.repeat(200),
        },
        ..ContextInputs::default()
    });
    let json = serde_json::to_string_pretty(&context.llm_context).expect("context JSON");
    assert!(json.len() <= MAX_LLM_CONTEXT_JSON_BYTES);
    assert!(!json.contains("topsecret"));
    assert!(!json.contains("quoted"));
    assert!(!json.contains("signed"));
    assert!(json.contains("untrusted"));
    assert!(json.contains("data_only"));

    let alert_context = build_alert_context(
        &[Alert {
            dimension: "cpu".to_string(),
            subject: None,
            severity: "warning".to_string(),
            message: secret.to_string(),
            value: 99.0,
            threshold: 90.0,
        }],
        200,
    )
    .expect("alert context");
    let alert_json = serde_json::to_string(&alert_context).expect("alert JSON");
    assert!(!alert_json.contains("topsecret"));
    assert!(!alert_json.contains("quoted"));
    assert!(!alert_json.contains("signed"));
    assert!(alert_context.llm_context.contains("UNTRUSTED DATA ONLY"));
    assert!(alert_context.llm_context.chars().count() <= MAX_ALERT_CONTEXT_CHARS);
}

#[test]
fn legacy_context_json_derives_conservative_structured_metadata() {
    let legacy = json!({
        "meta": meta_json("context", 200),
        "dimensions": ["metrics", "processes"],
        "metrics": metrics_fixture(),
        "processes": process_fixture(Vec::new()),
        "logs": null,
        "network": null,
        "services": null,
        "alerts": [],
        "alert_context": null,
        "summary": "legacy summary",
        "cropped_dimensions": ["logs", "network", "services"]
    });
    let parsed: OsContext = serde_json::from_value(legacy).expect("legacy context");
    assert_eq!(parsed.llm_context.schema, CONTEXT_SCHEMA);
    assert_eq!(parsed.llm_context.version, CONTEXT_SCHEMA_VERSION);
    assert_eq!(
        parsed.llm_context.payload,
        crate::model::ContextPayload::default()
    );
    assert_eq!(
        dimension(&parsed.llm_context, ContextDimension::Cpu).status,
        ContextDimensionStatus::Complete
    );
    assert_eq!(
        dimension(&parsed.llm_context, ContextDimension::Services).status,
        ContextDimensionStatus::NotRequested
    );
    assert!(!dimension(&parsed.llm_context, ContextDimension::Services).requested);

    let mut explicit = serde_json::to_value(parsed).expect("new context JSON");
    explicit["llm_context"]["status"] = json!("failed");
    explicit["llm_context"]["complete"] = json!(false);
    let reparsed: OsContext = serde_json::from_value(explicit).expect("new context");
    assert_eq!(reparsed.llm_context.status, ContextDimensionStatus::Failed);
    assert!(!reparsed.llm_context.complete);

    let mut intermediate = serde_json::to_value(reparsed).expect("intermediate JSON");
    intermediate["llm_context"]
        .as_object_mut()
        .expect("LLM object")
        .remove("trust");
    intermediate["llm_context"]
        .as_object_mut()
        .expect("LLM object")
        .remove("handling");
    intermediate["llm_context"]
        .as_object_mut()
        .expect("LLM object")
        .remove("instructions_allowed");
    let defaulted: OsContext = serde_json::from_value(intermediate).expect("intermediate context");
    assert_eq!(defaulted.llm_context.trust, "untrusted");
    assert_eq!(defaulted.llm_context.handling, "data_only");
    assert!(!defaulted.llm_context.instructions_allowed);
}

#[test]
fn payload_contains_bounded_structured_data_for_every_collected_dimension() {
    let mut inputs = complete_inputs();
    let ContextInput::Collected(metrics) = &mut inputs.metrics else {
        panic!("metrics fixture")
    };
    metrics.disks.push(crate::model::DiskSnapshot {
        collected_at_ms: 110,
        mount_point: "/".to_string(),
        filesystem: "ext4".to_string(),
        total_bytes: Some(1_000),
        used_bytes: Some(500),
        available_bytes: Some(500),
        used_percent: Some(50.0),
    });
    let ContextInput::Collected(processes) = &mut inputs.processes else {
        panic!("process fixture")
    };
    processes.total = 1;
    processes.processes.push(process_item(10, "worker"));
    let ContextInput::Collected(logs) = &mut inputs.logs else {
        panic!("log fixture")
    };
    logs.entries.push(crate::model::LogEntry {
        source: "journalctl".to_string(),
        timestamp: Some("2026-01-01T00:00:00Z".to_string()),
        severity: Some("error".to_string()),
        unit: Some("demo.service".to_string()),
        message: "bounded failure".to_string(),
    });
    let ContextInput::Collected(network) = &mut inputs.network else {
        panic!("network fixture")
    };
    network.total = 1;
    network.connections.push(connection(8080));
    network.firewall.push(crate::model::FirewallStatus {
        backend: "nftables".to_string(),
        available: true,
        active: true,
        status: CollectionStatus::Complete,
        rule_count: 2,
        ..crate::model::FirewallStatus::default()
    });
    let ContextInput::Collected(services) = &mut inputs.services else {
        panic!("service fixture")
    };
    let mut unit = service_problem_unit(1);
    unit.name = "demo.service".to_string();
    unit.requires = vec!["network.target".to_string()];
    unit.wants = vec!["logging.service".to_string()];
    unit.port_bindings = vec![port_binding("tcp:8080:42", 8080)];
    services.units = vec![unit];
    services.total = 1;
    services.returned_count = 1;
    services.port_collection.requested = true;
    services.port_collection.available = true;
    services.port_collection.status = CollectionStatus::Complete;
    services.port_collection.complete = true;
    services.port_collection.total = 1;
    services.port_collection.returned_count = 1;
    services.dependency_analysis = Some(dependency_analysis());

    let context = aggregate_context(inputs);
    let payload = &context.llm_context.payload;
    assert_eq!(
        payload.metrics.as_ref().expect("metrics").disks.items.len(),
        1
    );
    assert_eq!(
        payload
            .processes
            .as_ref()
            .expect("processes")
            .processes
            .items
            .len(),
        1
    );
    assert_eq!(payload.logs.as_ref().expect("logs").entries.items.len(), 1);
    let network = payload.network.as_ref().expect("network");
    assert_eq!(network.connections.items.len(), 1);
    assert_eq!(network.firewall.items.len(), 1);
    let services = payload.services.as_ref().expect("services");
    assert_eq!(services.units.items.len(), 1);
    assert_eq!(services.ports.items.len(), 1);
    assert_eq!(services.dependency_impacts.items.len(), 1);
    assert!(
        serde_json::to_vec_pretty(&context.llm_context)
            .expect("payload JSON")
            .len()
            <= MAX_LLM_CONTEXT_JSON_BYTES
    );
}

#[test]
fn output_limit_recomputes_status_and_page_counts() {
    let mut llm = LlmOsContext {
        status: ContextDimensionStatus::Complete,
        complete: true,
        dimensions: vec![ContextDimensionMetadata {
            dimension: ContextDimension::Logs,
            status: ContextDimensionStatus::Complete,
            requested: true,
            sources: vec!["fixture".to_string()],
            collected_at_ms: Some(1),
            complete: true,
            truncated: false,
            total_unknown: false,
            total: 80,
            returned_count: 80,
            omitted_count: 0,
            errors: Vec::new(),
            capabilities: Vec::new(),
        }],
        payload: crate::model::ContextPayload {
            logs: Some(crate::model::ContextLogPayload {
                entries: crate::model::ContextPage {
                    total: 80,
                    returned_count: 80,
                    omitted_count: 0,
                    total_unknown: false,
                    truncated: false,
                    items: (0..80)
                        .map(|index| crate::model::ContextLogEntryPayload {
                            source: "journalctl".to_string(),
                            timestamp: Some(index.to_string()),
                            severity: Some("error".to_string()),
                            unit: Some("large.service".to_string()),
                            message: "x".repeat(1_024),
                        })
                        .collect(),
                },
                patterns: crate::model::ContextPage::default(),
                filter_complete: true,
            }),
            ..crate::model::ContextPayload::default()
        },
        ..LlmOsContext::default()
    };
    enforce_llm_json_limit(&mut llm);
    let page = &llm.payload.logs.as_ref().expect("logs").entries;
    assert!(serde_json::to_vec_pretty(&llm).expect("JSON").len() <= MAX_LLM_CONTEXT_JSON_BYTES);
    assert_eq!(llm.status, ContextDimensionStatus::Partial);
    assert!(!llm.complete);
    assert!(llm.truncated);
    assert_eq!(page.returned_count, page.items.len());
    assert_eq!(page.total, page.returned_count + page.omitted_count);
    let logs = dimension(&llm, ContextDimension::Logs);
    assert_eq!(logs.status, ContextDimensionStatus::Partial);
    assert!(!logs.complete);
    assert_eq!(logs.returned_count, page.items.len());
    assert_eq!(logs.total, logs.returned_count + logs.omitted_count);
}

#[test]
fn payload_counts_unique_items_before_cropping_across_dimensions() {
    let mut inputs = complete_inputs();
    let ContextInput::Collected(metrics) = &mut inputs.metrics else {
        panic!("metrics")
    };
    let disk = crate::model::DiskSnapshot {
        collected_at_ms: 1,
        mount_point: "/data".to_string(),
        filesystem: "xfs".to_string(),
        total_bytes: Some(1),
        used_bytes: Some(0),
        available_bytes: Some(1),
        used_percent: Some(0.0),
    };
    metrics.disks = vec![disk.clone(), disk];
    let ContextInput::Collected(processes) = &mut inputs.processes else {
        panic!("processes")
    };
    processes.total = 2;
    processes.processes = vec![process_item(7, "same"), process_item(7, "same")];
    let ContextInput::Collected(logs) = &mut inputs.logs else {
        panic!("logs")
    };
    let entry = crate::model::LogEntry {
        source: "journalctl".to_string(),
        timestamp: Some("1".to_string()),
        severity: Some("warning".to_string()),
        unit: Some("same.service".to_string()),
        message: "same".to_string(),
    };
    logs.entries = vec![entry.clone(), entry];
    let ContextInput::Collected(network) = &mut inputs.network else {
        panic!("network")
    };
    network.total = 2;
    network.connections = vec![connection(9000), connection(9000)];
    let ContextInput::Collected(services) = &mut inputs.services else {
        panic!("services")
    };
    let mut unit = service_problem_unit(2);
    unit.name = "same.service".to_string();
    unit.port_bindings = vec![
        port_binding("same-binding", 9000),
        port_binding("same-binding", 9000),
    ];
    services.units = vec![unit.clone(), unit];
    services.total = 2;
    services.returned_count = 2;
    services.port_collection.requested = true;
    services.port_collection.available = true;
    services.port_collection.status = CollectionStatus::Complete;
    services.port_collection.complete = true;
    services.port_collection.total = 2;
    services.port_collection.returned_count = 2;

    let context = aggregate_context(inputs);
    let payload = &context.llm_context.payload;
    assert_eq!(payload.metrics.as_ref().expect("metrics").disks.total, 1);
    assert_eq!(
        payload
            .processes
            .as_ref()
            .expect("processes")
            .processes
            .total,
        1
    );
    assert_eq!(payload.logs.as_ref().expect("logs").entries.total, 1);
    assert_eq!(
        payload.network.as_ref().expect("network").connections.total,
        1
    );
    let services = payload.services.as_ref().expect("services");
    assert_eq!(services.units.total, 1);
    assert_eq!(services.ports.total, 1);
    assert_eq!(services.ports.returned_count, services.ports.items.len());
    assert_eq!(
        services.ports.total,
        services.ports.returned_count + services.ports.omitted_count
    );
}

#[test]
fn malicious_large_inputs_are_bounded_before_sorting_and_redaction() {
    let mut logs = logs_fixture(Vec::new());
    logs.entries = (0..5_000)
        .map(|index| crate::model::LogEntry {
            source: "journalctl".to_string(),
            timestamp: Some(format!("{index:05}")),
            severity: Some("error".to_string()),
            unit: Some("large.service".to_string()),
            message: "x".repeat(256),
        })
        .collect();
    let context = aggregate_context(ContextInputs {
        collected_at_ms: 1,
        logs: ContextInput::Collected(logs),
        services: ContextInput::Failed {
            source: "systemctl".to_string(),
            error: format!(
                "Authorization:Bearer topsecret {}",
                "y".repeat(2 * 1024 * 1024)
            ),
        },
        ..ContextInputs::default()
    });
    let entries = &context
        .llm_context
        .payload
        .logs
        .as_ref()
        .expect("logs")
        .entries;
    assert!(entries.items.len() <= 12);
    assert!(entries.total_unknown);
    assert!(entries.omitted_count >= 1);
    assert!(dimension(&context.llm_context, ContextDimension::Logs).total_unknown);
    let json = serde_json::to_string(&context.llm_context).expect("JSON");
    assert!(!json.contains("topsecret"));
    assert!(json.len() <= MAX_LLM_CONTEXT_JSON_BYTES);
}

#[test]
fn shared_input_budget_marks_cpu_and_alert_evidence_partial() {
    let mut metrics = metrics_fixture();
    metrics.cpu.cores = (0..5_000)
        .map(|index| crate::model::CpuCoreSnapshot {
            name: format!("cpu-{index:05}-{}", "x".repeat(512)),
            usage_percent: Some(10.0),
            total_jiffies: 100,
            idle_jiffies: 90,
        })
        .collect();
    metrics.alerts = (0..5_000)
        .map(|index| Alert {
            dimension: "cpu".to_string(),
            subject: Some(format!("cpu-{index}")),
            severity: "warning".to_string(),
            message: format!("Authorization:Bearer secret-{index} {}", "y".repeat(512)),
            value: 90.0,
            threshold: 80.0,
        })
        .collect();

    let context = aggregate_context(ContextInputs {
        collected_at_ms: 1,
        metrics: ContextInput::Collected(metrics),
        ..ContextInputs::default()
    });
    let cpu = dimension(&context.llm_context, ContextDimension::Cpu);
    assert_eq!(cpu.status, ContextDimensionStatus::Partial);
    assert!(!cpu.complete);
    assert!(cpu.truncated);
    assert!(cpu.total_unknown);
    assert!(cpu.total > cpu.returned_count);
    assert_eq!(context.llm_context.evidence_total, 5_000);
    assert!(context.llm_context.evidence_omitted_count >= 4_936);
    assert_eq!(context.llm_context.status, ContextDimensionStatus::Partial);
    let json = serde_json::to_string(&context.llm_context).expect("JSON");
    assert!(!json.contains("secret-"));
    assert!(json.len() <= MAX_LLM_CONTEXT_JSON_BYTES);
}

#[test]
fn shared_input_budget_marks_network_anomalies_and_dns_capabilities_partial() {
    let mut network = network_fixture(Vec::new());
    network.anomaly_total = 0;
    network.anomalies = (0..5_000)
        .map(|index| crate::model::NetworkAnomaly {
            kind: format!("network-{index:05}"),
            message: "large anomaly".to_string(),
            count: 1,
            score: 0.9,
            source: Some("procfs".to_string()),
            subject: None,
            evidence: None,
        })
        .collect();
    network.dns_resolver.nameservers = (0..5_000)
        .map(|index| format!("nameserver-{index:05}.example"))
        .collect();
    network.dns_resolver.search_domains = (0..5_000)
        .map(|index| format!("search-{index:05}.example"))
        .collect();
    network.dns_resolver.options = (0..5_000)
        .map(|index| format!("option-{index:05}"))
        .collect();
    network.dns_checks.push(crate::model::DnsCheck {
        name: "example.com".to_string(),
        resolved_addrs: (0..5_000)
            .map(|index| format!("2001:db8::{index:x}"))
            .collect(),
        ok: true,
        error: None,
        status: crate::model::DnsResolutionStatus::Resolved,
        latency_ms: Some(1),
        source: crate::model::DnsResolutionSource::GetentAhosts,
        truncated: false,
        omitted_address_count: 0,
        parse_failure_count: 0,
    });

    let context = aggregate_context(ContextInputs {
        collected_at_ms: 1,
        network: ContextInput::Collected(network),
        ..ContextInputs::default()
    });
    let network = dimension(&context.llm_context, ContextDimension::Network);
    assert_eq!(network.status, ContextDimensionStatus::Partial);
    assert!(!network.complete);
    assert!(network.truncated);
    assert!(network.total_unknown);
    for wanted in [ContextCapability::DnsResolver, ContextCapability::DnsChecks] {
        let capability = network
            .capabilities
            .iter()
            .find(|capability| capability.capability == wanted)
            .expect("capability");
        assert_eq!(capability.status, ContextDimensionStatus::Partial);
        assert!(!capability.complete);
        assert!(capability.truncated);
        assert!(capability.total_unknown);
        assert!(capability.omitted_count > 0);
    }
    assert_eq!(context.llm_context.evidence_total, 5_000);
    assert!(context.llm_context.evidence_omitted_count >= 4_976);
    let payload = context
        .llm_context
        .payload
        .network
        .expect("network payload");
    assert!(payload.dns_checks.total_unknown);
    assert!(payload.dns_checks.truncated);
    assert!(payload.dns_checks.omitted_count > 0);
}

#[test]
fn shared_input_budget_preserves_service_problem_evidence_lower_bound() {
    let problem_units = (0..5_000).map(service_problem_unit).collect::<Vec<_>>();
    let mut services = services_fixture(problem_units);
    services.problem_total = 0;
    services.problem_returned_count = 0;
    services.problem_omitted_count = 0;
    services.problem_filter_complete = true;

    let context = aggregate_context(ContextInputs {
        collected_at_ms: 1,
        services: ContextInput::Collected(services),
        ..ContextInputs::default()
    });
    assert_eq!(context.llm_context.evidence_total, 5_000);
    assert!(context.llm_context.evidence_omitted_count >= 4_968);
    assert!(context.llm_context.total_unknown);
    let services = dimension(&context.llm_context, ContextDimension::Services);
    assert_eq!(services.status, ContextDimensionStatus::Partial);
    assert!(!services.complete);
    assert!(services.truncated);
    assert!(services.total_unknown);
    let problem_capability = services
        .capabilities
        .iter()
        .find(|capability| capability.capability == ContextCapability::ServiceProblemAnalysis)
        .expect("problem capability");
    assert_eq!(problem_capability.total, 5_000);
    assert!(problem_capability.omitted_count >= 4_968);
    assert!(!problem_capability.complete);
    let page = &context
        .llm_context
        .payload
        .services
        .as_ref()
        .expect("service payload")
        .problem_units;
    assert!(page.total_unknown);
    assert!(page.truncated);
    assert!(page.omitted_count >= 4_968);
}

fn assert_summary_is_bounded(summary: &ContextHealthSummary) {
    assert!(summary.text.chars().count() <= MAX_CONTEXT_HEALTH_SUMMARY_TEXT_CHARS);
    assert!(summary.text.len() <= MAX_CONTEXT_HEALTH_SUMMARY_TEXT_BYTES);
    assert!(summary.text.is_char_boundary(summary.text.len()));
    assert!(!summary.text.contains('\n'));
    assert!(!summary.text.contains('\r'));
    assert_eq!(summary.collection_status, summary.status);
    assert_eq!(
        summary.omitted_count,
        summary
            .metadata_omitted_count
            .max(summary.evidence_omitted_count)
            .saturating_add(summary.summary_omitted_count)
    );
    if summary.context_truncated || summary.text_truncated || summary.summary_omitted_count > 0 {
        assert!(summary.truncated);
    }
}

#[test]
fn health_summary_reports_healthy_complete_context() {
    let context = aggregate_context(complete_inputs());
    let summary = summarize_llm_context(&context.llm_context);
    assert_eq!(summary.schema, CONTEXT_HEALTH_SUMMARY_SCHEMA);
    assert_eq!(summary.version, CONTEXT_HEALTH_SUMMARY_SCHEMA_VERSION);
    assert_eq!(summary.mode, ContextHealthSummaryMode::RuleBased);
    assert_eq!(summary.status, ContextDimensionStatus::Complete);
    assert_eq!(summary.collection_status, ContextDimensionStatus::Complete);
    assert_eq!(summary.health_status, ContextHealthStatus::Healthy);
    assert!(summary.complete);
    assert!(!summary.truncated);
    assert!(!summary.context_truncated);
    assert!(!summary.text_truncated);
    assert!(!summary.total_unknown);
    assert_eq!(
        summary.covered_dimensions.len(),
        ContextDimension::ALL.len()
    );
    assert!(summary.evidence_ids.is_empty());
    assert!(summary.failure_reason.is_none());
    assert!(summary.text.starts_with("System health appears healthy"));
    assert!(summary.text.contains("Resource snapshot"));
    assert_summary_is_bounded(&summary);
}

#[test]
fn health_summary_reports_partial_without_claiming_health() {
    let context = aggregate_context(ContextInputs {
        collected_at_ms: 10,
        metrics: ContextInput::Collected(metrics_fixture()),
        logs: ContextInput::Failed {
            source: "journalctl".to_string(),
            error: "permission denied".to_string(),
        },
        ..ContextInputs::default()
    });
    let summary = summarize_llm_context(&context.llm_context);
    assert_eq!(summary.status, ContextDimensionStatus::Partial);
    assert_eq!(summary.health_status, ContextHealthStatus::Unknown);
    assert!(!summary.complete);
    assert_eq!(
        summary.failure_reason.as_deref(),
        Some("context_partial_or_unknown")
    );
    assert!(summary.text.contains("partially known"));
    assert!(!summary.text.contains("appears healthy"));
    assert!(summary.text.contains("failed dimension"));
    assert_summary_is_bounded(&summary);
}

#[test]
fn health_summary_distinguishes_failed_unavailable_and_not_requested() {
    let missing = aggregate_context(ContextInputs::new(10));
    let missing_summary = summarize_llm_context(&missing.llm_context);
    assert_eq!(missing_summary.status, ContextDimensionStatus::NotRequested);
    assert_eq!(missing_summary.health_status, ContextHealthStatus::Unknown);
    assert_eq!(
        missing_summary.failure_reason.as_deref(),
        Some("no_dimensions_requested")
    );
    assert!(missing_summary.text.contains("not assessed"));

    let failed = aggregate_context(ContextInputs {
        collected_at_ms: 10,
        processes: ContextInput::Failed {
            source: "procfs".to_string(),
            error: "scan failed".to_string(),
        },
        ..ContextInputs::default()
    });
    let failed_summary = summarize_llm_context(&failed.llm_context);
    assert_eq!(failed_summary.status, ContextDimensionStatus::Failed);
    assert_eq!(failed_summary.health_status, ContextHealthStatus::Failed);
    assert_eq!(
        failed_summary.failure_reason.as_deref(),
        Some("requested_dimensions_failed")
    );
    assert!(failed_summary.text.contains("failed or were unavailable"));

    let unavailable = aggregate_context(ContextInputs {
        collected_at_ms: 10,
        logs: ContextInput::Unavailable {
            source: "journalctl".to_string(),
            reason: Some("not installed".to_string()),
        },
        ..ContextInputs::default()
    });
    let unavailable_summary = summarize_llm_context(&unavailable.llm_context);
    assert_eq!(
        unavailable_summary.status,
        ContextDimensionStatus::Unavailable
    );
    assert_eq!(
        unavailable_summary.health_status,
        ContextHealthStatus::Unknown
    );
    assert_eq!(
        unavailable_summary.failure_reason.as_deref(),
        Some("requested_dimensions_unavailable")
    );
    assert!(unavailable_summary.text.contains("unavailable"));
}

#[test]
fn health_summary_uses_actionable_severity_for_degraded_status() {
    let mut context = aggregate_context(complete_inputs()).llm_context;
    context.evidence = vec![
        ContextEvidence {
            id: "cpu-info".to_string(),
            dimension: ContextDimension::Cpu,
            kind: ContextEvidenceKind::MetricAlert,
            severity: "info".to_string(),
            subject: None,
            message: "cpu sample is within baseline".to_string(),
            count: 1,
        },
        ContextEvidence {
            id: "logs-notice".to_string(),
            dimension: ContextDimension::Logs,
            kind: ContextEvidenceKind::LogPattern,
            severity: "notice".to_string(),
            subject: None,
            message: "routine notice".to_string(),
            count: 1,
        },
    ];
    let info_summary = summarize_llm_context(&context);
    assert_eq!(info_summary.status, ContextDimensionStatus::Complete);
    assert_eq!(info_summary.health_status, ContextHealthStatus::Healthy);
    assert!(info_summary
        .text
        .starts_with("System health appears healthy"));
    assert!(!info_summary.text.contains("System health is degraded"));
    assert_summary_is_bounded(&info_summary);

    context.evidence.push(ContextEvidence {
        id: "unknown-severity".to_string(),
        dimension: ContextDimension::Services,
        kind: ContextEvidenceKind::ServiceProblem,
        severity: "surprise".to_string(),
        subject: None,
        message: "unclassified signal".to_string(),
        count: 1,
    });
    let unknown_summary = summarize_llm_context(&context);
    assert_eq!(unknown_summary.health_status, ContextHealthStatus::Unknown);
    assert!(unknown_summary.text.starts_with("System health is unknown"));
    assert!(!unknown_summary.text.contains("appears healthy"));
    assert_summary_is_bounded(&unknown_summary);
}

#[test]
fn health_summary_sorts_typed_evidence_by_severity_then_stable_keys() {
    let mut context = aggregate_context(complete_inputs()).llm_context;
    context.evidence = vec![
        ContextEvidence {
            id: "network-warning".to_string(),
            dimension: ContextDimension::Network,
            kind: ContextEvidenceKind::NetworkAnomaly,
            severity: "warning".to_string(),
            subject: None,
            message: "network anomaly: many_time_wait".to_string(),
            count: 2,
        },
        ContextEvidence {
            id: "service-error".to_string(),
            dimension: ContextDimension::Services,
            kind: ContextEvidenceKind::ServiceProblem,
            severity: "error".to_string(),
            subject: None,
            message: "service problem: exit_code".to_string(),
            count: 1,
        },
        ContextEvidence {
            id: "log-error".to_string(),
            dimension: ContextDimension::Logs,
            kind: ContextEvidenceKind::LogPattern,
            severity: "error".to_string(),
            subject: None,
            message: "log pattern: spike".to_string(),
            count: 3,
        },
    ];
    context.evidence_total = context.evidence.len();
    context.evidence_returned_count = context.evidence.len();
    context.evidence_omitted_count = 0;
    let summary = summarize_llm_context(&context);
    assert_eq!(summary.health_status, ContextHealthStatus::Degraded);
    assert_eq!(
        summary.evidence_ids,
        vec![
            "log-error".to_string(),
            "service-error".to_string(),
            "network-warning".to_string()
        ]
    );
    let log_index = summary.text.find("log-error").expect("log id");
    let service_index = summary.text.find("service-error").expect("service id");
    let warning_index = summary.text.find("network-warning").expect("warning id");
    assert!(log_index < service_index);
    assert!(service_index < warning_index);
}

#[test]
fn health_summary_reports_truncation_and_omitted_lower_bounds() {
    let mut metrics = metrics_fixture();
    metrics.alerts = (0..5_000)
        .map(|index| Alert {
            dimension: "cpu".to_string(),
            subject: None,
            severity: "warning".to_string(),
            message: format!("cpu threshold token=secret-{index}"),
            value: 99.0,
            threshold: 90.0,
        })
        .collect();
    let context = aggregate_context(ContextInputs {
        collected_at_ms: 1,
        metrics: ContextInput::Collected(metrics),
        ..ContextInputs::default()
    });
    let summary = summarize_llm_context(&context.llm_context);
    assert_eq!(summary.status, ContextDimensionStatus::Partial);
    assert_eq!(summary.health_status, ContextHealthStatus::Degraded);
    assert!(summary.context_truncated);
    assert!(!summary.text_truncated);
    assert!(summary.truncated);
    assert!(summary.total_unknown);
    assert!(summary.evidence_omitted_count >= 4_936);
    assert!(summary.omitted_count >= 4_936);
    assert_eq!(
        summary.failure_reason.as_deref(),
        Some("context_partial_or_truncated")
    );
    assert!(summary.text.contains("omitted item"));
    assert!(summary.text.contains("truncated context"));
    assert!(!summary.text.contains("secret-"));
    assert_summary_is_bounded(&summary);
}

#[test]
fn health_summary_budgets_evidence_before_redaction_sorting_and_text_processing() {
    let mut context = aggregate_context(complete_inputs()).llm_context;
    context.evidence = vec![
        ContextEvidence {
            id: "huge-message".to_string(),
            dimension: ContextDimension::Logs,
            kind: ContextEvidenceKind::LogPattern,
            severity: "warning".to_string(),
            subject: None,
            message: format!(
                "{}TAIL_SHOULD_NOT_BE_READ token=secret-tail",
                "x".repeat(20_000)
            ),
            count: 1,
        },
        ContextEvidence {
            id: "later-error".to_string(),
            dimension: ContextDimension::Services,
            kind: ContextEvidenceKind::ServiceProblem,
            severity: "error".to_string(),
            subject: None,
            message: "this later item should be omitted after budget stop".to_string(),
            count: 1,
        },
    ];
    context.evidence_total = context.evidence.len();
    context.evidence_returned_count = context.evidence.len();
    let summary = summarize_llm_context(&context);
    assert_eq!(summary.collection_status, ContextDimensionStatus::Complete);
    assert_eq!(summary.health_status, ContextHealthStatus::Unknown);
    assert!(!summary.context_truncated);
    assert!(summary.truncated);
    assert!(summary.total_unknown);
    assert!(!summary.complete);
    assert!(summary.summary_omitted_count >= 2);
    assert_eq!(
        summary.failure_reason.as_deref(),
        Some("summary_input_truncated")
    );
    assert!(summary.evidence_ids.is_empty());
    assert!(!summary.text.contains("TAIL_SHOULD_NOT_BE_READ"));
    assert!(!summary.text.contains("secret-tail"));
    assert_summary_is_bounded(&summary);
}

#[test]
fn health_summary_stops_all_summary_input_when_dimensions_exhaust_budget() {
    let mut context = aggregate_context(complete_inputs()).llm_context;
    context.dimensions.insert(
        0,
        ContextDimensionMetadata {
            dimension: ContextDimension::Cpu,
            status: ContextDimensionStatus::Complete,
            requested: true,
            sources: vec![String::new(); 3_000],
            collected_at_ms: None,
            complete: true,
            truncated: false,
            total_unknown: false,
            total: 0,
            returned_count: 0,
            omitted_count: 0,
            errors: Vec::new(),
            capabilities: Vec::new(),
        },
    );
    context.evidence = vec![ContextEvidence {
        id: "must-not-process".to_string(),
        dimension: ContextDimension::Services,
        kind: ContextEvidenceKind::ServiceProblem,
        severity: "error".to_string(),
        subject: None,
        message: "this evidence is after an exhausted dimensions budget".to_string(),
        count: 1,
    }];
    context.evidence_total = context.evidence.len();
    context.evidence_returned_count = context.evidence.len();
    let summary = summarize_llm_context(&context);
    assert_eq!(summary.health_status, ContextHealthStatus::Unknown);
    assert!(summary.truncated);
    assert!(summary.total_unknown);
    assert_eq!(
        summary.failure_reason.as_deref(),
        Some("summary_input_truncated")
    );
    assert!(summary.evidence_ids.is_empty());
    assert!(!summary.text.contains("must-not-process"));
    assert!(!summary.text.contains("after an exhausted"));
    assert!(summary.summary_omitted_count >= context.dimensions.len() + context.evidence.len());
    assert_summary_is_bounded(&summary);
}

#[test]
fn health_summary_marks_text_truncation_separately_from_context_truncation() {
    let mut context = aggregate_context(complete_inputs()).llm_context;
    context.evidence = (0..6)
        .map(|index| ContextEvidence {
            id: format!("long-warning-{index}"),
            dimension: ContextDimension::Logs,
            kind: ContextEvidenceKind::LogPattern,
            severity: "warning".to_string(),
            subject: None,
            message: format!(
                "repeatable warning detail {index} {}",
                "safe-detail".repeat(24)
            ),
            count: 1,
        })
        .collect();
    context.evidence_total = context.evidence.len();
    context.evidence_returned_count = context.evidence.len();
    let summary = summarize_llm_context(&context);
    assert_eq!(summary.status, ContextDimensionStatus::Complete);
    assert_eq!(summary.health_status, ContextHealthStatus::Degraded);
    assert!(!summary.context_truncated);
    assert!(summary.text_truncated);
    assert!(summary.truncated);
    assert!(!summary.complete);
    assert!(summary.summary_omitted_count >= 1);
    assert_eq!(summary.metadata_omitted_count, 0);
    assert_eq!(summary.evidence_omitted_count, 0);
    assert!(summary.text.ends_with("...[truncated]"));
    assert_summary_is_bounded(&summary);
}

#[test]
fn health_summary_redacts_untrusted_text_and_url_queries() {
    let mut context = aggregate_context(complete_inputs()).llm_context;
    context.evidence = vec![ContextEvidence {
        id: "service-redaction".to_string(),
        dimension: ContextDimension::Services,
        kind: ContextEvidenceKind::ServiceProblem,
        severity: "error".to_string(),
        subject: Some("Authorization:Bearer topsecret".to_string()),
        message: "Authorization: Bearer topsecret /etc/shadow C:\\Users\\patri\\secret.txt password=quoted https://host/path?api_key=secret"
            .to_string(),
        count: 1,
    }];
    let summary = summarize_llm_context(&context);
    let json = serde_json::to_string(&summary).expect("summary JSON");
    assert!(!json.contains("topsecret"));
    assert!(!json.contains("quoted"));
    assert!(!json.contains("api_key=secret"));
    assert!(!json.contains("/etc/shadow"));
    assert!(!json.contains("C:\\Users\\patri"));
    assert!(!json.contains("token=secret"));
    assert!(json.contains("[REDACTED]"));
    assert!(json.contains("[REDACTED_PATH]"));
    assert_eq!(summary.evidence_ids, ["service-redaction"]);
    assert_summary_is_bounded(&summary);
}

#[test]
fn health_summary_bounds_long_utf8_without_invalid_text() {
    let mut context = aggregate_context(complete_inputs()).llm_context;
    context.evidence = vec![ContextEvidence {
        id: "log-long".to_string(),
        dimension: ContextDimension::Logs,
        kind: ContextEvidenceKind::LogPattern,
        severity: "error".to_string(),
        subject: None,
        message: "故障".repeat(500),
        count: 1,
    }];
    let summary = summarize_llm_context(&context);
    assert_summary_is_bounded(&summary);
    assert!(summary.text.is_char_boundary(summary.text.len()));
}

#[test]
fn health_summary_is_deterministic_and_side_effect_free() {
    let mut context = aggregate_context(complete_inputs()).llm_context;
    context.evidence = vec![
        ContextEvidence {
            id: "z-warning".to_string(),
            dimension: ContextDimension::Processes,
            kind: ContextEvidenceKind::ProcessAnomaly,
            severity: "warning".to_string(),
            subject: None,
            message: "process anomaly: cpu".to_string(),
            count: 1,
        },
        ContextEvidence {
            id: "a-error".to_string(),
            dimension: ContextDimension::Logs,
            kind: ContextEvidenceKind::LogPattern,
            severity: "error".to_string(),
            subject: None,
            message: "log pattern: failure".to_string(),
            count: 1,
        },
    ];
    let before = context.clone();
    let first = summarize_llm_context(&context);
    let second = summarize_llm_context(&context);
    assert_eq!(first, second);
    assert_eq!(context, before);
    context.evidence.reverse();
    assert_eq!(first, summarize_llm_context(&context));
}

#[test]
fn health_summary_legacy_json_and_collect_context_string_are_compatible() {
    let legacy = json!({
        "meta": meta_json("context", 200),
        "dimensions": ["metrics"],
        "metrics": metrics_fixture(),
        "processes": null,
        "logs": null,
        "network": null,
        "services": null,
        "alerts": [],
        "alert_context": null,
        "summary": "legacy summary Authorization: Bearer topsecret",
        "cropped_dimensions": ["processes", "logs", "network", "services"]
    });
    let parsed: OsContext = serde_json::from_value(legacy).expect("legacy context");
    assert_eq!(parsed.health_summary.schema, CONTEXT_HEALTH_SUMMARY_SCHEMA);
    assert_eq!(
        parsed.health_summary.status,
        ContextDimensionStatus::Complete
    );
    assert_eq!(
        parsed.health_summary.collection_status,
        ContextDimensionStatus::Complete
    );
    assert_eq!(
        parsed.health_summary.health_status,
        ContextHealthStatus::Healthy
    );
    assert!(parsed.health_summary.text.contains("legacy summary"));
    assert!(!parsed.health_summary.text.contains("topsecret"));

    let mut context = aggregate_context(complete_inputs());
    populate_legacy_context_consumers(&mut context);
    assert_eq!(context.summary, context.health_summary.text);
    assert_eq!(summarize_context(&context), context.health_summary);
    assert!(context.summary.starts_with("System health"));
}

#[test]
fn explicit_health_summary_json_is_normalized_on_deserialize() {
    let mut evidence_ids = (0..40)
        .map(|index| format!("evidence-{index}"))
        .collect::<Vec<_>>();
    evidence_ids.push("Authorization:Bearer topsecret".to_string());
    evidence_ids.push("evidence-1".to_string());
    let raw = json!({
        "schema": "os-sense.health-summary",
        "version": 1,
        "mode": "rule_based",
        "generated_at_ms": 10,
        "status": "partial",
        "health_status": "healthy",
        "complete": true,
        "truncated": true,
        "total_unknown": false,
        "covered_dimensions": [
            "cpu", "cpu", "memory", "disk", "thermal", "network_metrics",
            "network", "processes", "logs", "services", "services"
        ],
        "evidence_ids": evidence_ids,
        "metadata_omitted_count": 2,
        "evidence_omitted_count": 5,
        "summary_omitted_count": 0,
        "omitted_count": 0,
        "failure_reason": "Authorization:Bearer topsecret",
        "text": format!(
            "line one\nAuthorization: Bearer topsecret https://host/path?api_key=secret /etc/shadow {}",
            "健康".repeat(1_000)
        )
    });
    let summary: ContextHealthSummary =
        serde_json::from_value(raw).expect("normalized health summary");
    assert_eq!(summary.status, ContextDimensionStatus::Partial);
    assert_eq!(summary.collection_status, ContextDimensionStatus::Partial);
    assert_eq!(summary.health_status, ContextHealthStatus::Unknown);
    assert!(summary.truncated);
    assert!(summary.text_truncated);
    assert!(!summary.complete);
    assert!(summary.total_unknown);
    assert!(summary.covered_dimensions.len() <= 16);
    assert!(summary.evidence_ids.len() <= 16);
    let unique_ids = summary
        .evidence_ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(unique_ids.len(), summary.evidence_ids.len());
    assert!(!summary.text.contains('\n'));
    assert!(!summary.text.contains("topsecret"));
    assert!(!summary.text.contains("api_key=secret"));
    assert!(!summary.text.contains("/etc/shadow"));
    assert!(!summary
        .failure_reason
        .as_deref()
        .unwrap_or("")
        .contains("topsecret"));
    assert!(summary.text.contains("[REDACTED_PATH]"));
    assert_summary_is_bounded(&summary);
}

#[test]
fn explicit_health_summary_status_combinations_are_conservative() {
    let parse_status = |status: &str,
                        health_status: &str,
                        complete: bool,
                        truncated: bool,
                        total_unknown: bool,
                        evidence_ids: Vec<&str>| {
        let raw = json!({
            "schema": "os-sense.health-summary",
            "version": 1,
            "mode": "rule_based",
            "status": status,
            "health_status": health_status,
            "complete": complete,
            "truncated": truncated,
            "total_unknown": total_unknown,
            "evidence_ids": evidence_ids,
            "text": "status combination"
        });
        serde_json::from_value::<ContextHealthSummary>(raw)
            .expect("normalized health summary")
            .health_status
    };

    assert_eq!(
        parse_status("not_requested", "degraded", false, false, false, vec!["e1"]),
        ContextHealthStatus::Unknown
    );
    assert_eq!(
        parse_status("unavailable", "failed", false, false, false, vec!["e1"]),
        ContextHealthStatus::Unknown
    );
    assert_eq!(
        parse_status("failed", "healthy", true, false, false, vec![]),
        ContextHealthStatus::Failed
    );
    assert_eq!(
        parse_status("partial", "healthy", true, false, false, vec!["e1"]),
        ContextHealthStatus::Unknown
    );
    assert_eq!(
        parse_status("partial", "degraded", false, true, true, vec!["e1"]),
        ContextHealthStatus::Unknown
    );
    assert_eq!(
        parse_status("complete", "healthy", true, true, false, vec![]),
        ContextHealthStatus::Unknown
    );
    assert_eq!(
        parse_status("complete", "partial", true, false, false, vec![]),
        ContextHealthStatus::Unknown
    );
    assert_eq!(
        parse_status("complete", "degraded", true, false, false, vec!["e1"]),
        ContextHealthStatus::Unknown
    );
}

#[test]
fn network_metrics_is_independent_from_unrequested_network_inventory() {
    let context = aggregate_context(ContextInputs {
        collected_at_ms: 200,
        metrics: ContextInput::Collected(metrics_fixture()),
        ..ContextInputs::default()
    });
    let metrics = dimension(&context.llm_context, ContextDimension::NetworkMetrics);
    let network = dimension(&context.llm_context, ContextDimension::Network);
    assert!(metrics.requested);
    assert_eq!(metrics.status, ContextDimensionStatus::Complete);
    assert!(!network.requested);
    assert_eq!(network.status, ContextDimensionStatus::NotRequested);
    assert!(network
        .capabilities
        .iter()
        .all(|capability| !capability.requested));
    assert_eq!(context.llm_context.status, ContextDimensionStatus::Complete);
}

#[test]
fn pure_aggregation_does_not_apply_summary_or_intent_consumers() {
    let context = aggregate_context(complete_inputs());
    assert!(context.summary.is_empty());
    assert!(context.health_summary.text.is_empty());
    assert!(context.alert_context.is_none());
    assert!(context.cropped_dimensions.is_empty());
    assert!(context.llm_context.payload.metrics.is_some());
    assert!(context.llm_context.payload.services.is_some());
}
