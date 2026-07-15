//! OS environment sensing primitives used by read-only tools.
//!
//! The crate keeps collection code separate from tool execution so parsers,
//! storage, scheduling, and context aggregation can be tested without a live
//! Linux host.

mod command;
pub mod context;
pub mod error;
pub mod logs;
pub mod model;
pub mod network;
pub mod procfs;
mod redaction;
pub mod runtime;
pub mod scheduler;
pub mod services;
pub mod storage;

pub use context::{build_alert_context, collect_context, ContextRequest};
pub use error::{OsSenseError, Result};
pub use logs::{query_logs, LogQuery};
pub use model::{
    ActiveAlert, ActiveAlertDimension, ActiveAlertSnapshot, Alert, AlertContext,
    AlertEvaluationFreshness, CollectionMode, CollectionStatus, CorruptSampleDetail,
    CpuCoreSnapshot, CpuSnapshot, DimensionCollectionResult, DiskDeviceSnapshot, DiskSnapshot,
    FanReading, HealthProbeResult, HwmonSensorReading, LoadAverage, LogEntry, LogPattern,
    LogQueryResult, LogSourceStatus, MemorySnapshot, MetricSnapshot, NetworkConnection,
    NetworkInterfaceSnapshot, NetworkMetricsSnapshot, NetworkSnapshot, OsContext, OsSampleMeta,
    PlatformInfo, ProcessAnomalyEvidence, ProcessBaseline, ProcessBaselineEntry, ProcessInfo,
    ProcessList, RateStatus, ResourceDimension, SensorAvailability, ServiceSnapshot, ServiceUnit,
    TemperatureReading, ThermalSnapshot,
};
pub use network::{collect_network, NetworkQuery, TcpProbeRequest};
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
