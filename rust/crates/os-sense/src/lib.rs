//! OS environment sensing primitives used by read-only tools.
//!
//! The crate keeps collection code separate from tool execution so parsers,
//! storage, scheduling, and context aggregation can be tested without a live
//! Linux host.

mod command;
pub mod context;
mod context_payload;
pub mod error;
pub mod http_probe;
pub mod logs;
pub mod model;
pub mod network;
pub mod procfs;
mod redaction;
pub mod runtime;
pub mod scheduler;
mod service_ports;
pub mod services;
pub mod storage;

pub use context::{
    aggregate_context, build_alert_context, collect_context, ContextInput, ContextInputs,
    ContextRequest, CONTEXT_SCHEMA, CONTEXT_SCHEMA_VERSION, MAX_LLM_CONTEXT_JSON_BYTES,
};
pub use error::{OsSenseError, Result};
pub use http_probe::HttpProbeRequest;
pub use logs::{
    query_logs, query_logs_with_summary_generator, render_log_summary_prompt, LogQuery,
    LogSummaryGenerator,
};
pub use model::{
    ActiveAlert, ActiveAlertDimension, ActiveAlertSnapshot, Alert, AlertContext,
    AlertEvaluationFreshness, CollectionMode, CollectionStatus, ContextCapability,
    ContextCapabilityMetadata, ContextConnectionPayload, ContextCpuPayload,
    ContextDependencyImpactPayload, ContextDimension, ContextDimensionMetadata,
    ContextDimensionStatus, ContextDiskDevicePayload, ContextDiskPayload, ContextEvidence,
    ContextEvidenceKind, ContextFirewallPayload, ContextLoadPayload, ContextLogEntryPayload,
    ContextLogPatternPayload, ContextLogPayload, ContextMemoryPayload, ContextMetricsPayload,
    ContextNetworkInterfacePayload, ContextNetworkPayload, ContextPage, ContextPayload,
    ContextProbePayload, ContextProcessItem, ContextProcessPayload, ContextServicePayload,
    ContextServicePortPayload, ContextServiceUnitPayload, ContextThermalPayload, ContextTimeWindow,
    CorruptSampleDetail, CpuCoreSnapshot, CpuSnapshot, DependencyImpactReason,
    DependencyImpactSeverity, DependencyRelationKind, DimensionCollectionResult,
    DiskDeviceSnapshot, DiskSnapshot, DnsResolutionSource, DnsResolutionStatus, DnsResolverStatus,
    FanReading, FirewallErrorKind, FirewallStatus, HealthProbeResult, HttpProbeErrorKind,
    HttpProbeResult, HttpProbeStage, HttpProbeStatus, HwmonSensorReading, LlmOsContext,
    LoadAverage, LogEntry, LogLlmSummaryOutput, LogPattern, LogPatternEvidence, LogQueryResult,
    LogSourceStatus, LogSummary, LogSummaryBoundary, LogSummaryEvidence, LogSummaryMode,
    LogSummaryRequest, LogSummaryTimeRange, MemorySnapshot, MetricSnapshot, NetworkAnomalyEvidence,
    NetworkBaseline, NetworkBaselineEntry, NetworkConnection, NetworkInterfaceSnapshot,
    NetworkMetricsSnapshot, NetworkSnapshot, NetworkSourceStatus, OsContext, OsSampleMeta,
    PlatformInfo, ProcessAnomalyEvidence, ProcessBaseline, ProcessBaselineEntry, ProcessInfo,
    ProcessList, RateStatus, ResourceDimension, SensorAvailability, ServiceDependencyAnalysis,
    ServiceDependencyImpact, ServiceDependencyPathEdge, ServiceHealthStatus, ServicePortBinding,
    ServicePortCollection, ServicePortOwnershipStatus, ServicePortProtocol, ServiceProblem,
    ServiceProblemEvidence, ServiceProblemKind, ServiceSnapshot, ServiceSource,
    ServiceSourceStatus, ServiceUnit, TcpProbeErrorKind, TcpProbeStage, TcpProbeStatus,
    TemperatureReading, ThermalSnapshot,
};
pub use network::{
    collect_network, NetworkQuery, TcpProbeRequest, MAX_NETWORK_BASELINE_ENTRIES,
    MAX_NETWORK_BASELINE_JSON_BYTES, NETWORK_BASELINE_VERSION, OS_NETWORK_BASELINE_FILE_ENV,
};
pub use procfs::{
    collect_metrics, collect_processes, Clock, KylinPartitionUsageProvider,
    KylinProcessUserResolver, MetricsThresholds, MonotonicClock, PartitionUsageProvider,
    ProcessQuery, ProcessSystemParameters, ProcessUserResolver, ProcfsCollector, SystemClock,
    SystemMonotonicClock, MAX_PROCESS_BASELINE_ENTRIES, MAX_PROCESS_BASELINE_JSON_BYTES,
    OS_PROCESS_BASELINE_FILE_ENV, OS_SENSE_THRESHOLDS_ENV, PROCESS_BASELINE_VERSION,
};
pub use runtime::{
    current_time_ms, default_database_path, ActiveAlertStore, MetricsHistory, OsSenseRuntime,
    OsSenseRuntimeConfig, TimeSeriesWindow, ACTIVE_ALERT_TTL_MS, MAX_ACTIVE_ALERTS,
    MAX_ACTIVE_ALERT_JSON_BYTES, MAX_TRACKED_ACTIVE_ALERTS,
};
pub use scheduler::{
    CollectionIntervals, CollectionScheduler, SchedulerConfig, CPU_INTERVAL_MS, DISK_INTERVAL_MS,
    MEMORY_INTERVAL_MS, NETWORK_INTERVAL_MS, THERMAL_INTERVAL_MS,
};
pub use services::{query_services, ServiceQuery};
pub use storage::{OsSenseStore, MAX_HISTORY_POINTS};
