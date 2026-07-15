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
    Alert, AlertContext, CollectionMode, CollectionStatus, CpuCoreSnapshot, CpuSnapshot,
    DimensionCollectionResult, DiskDeviceSnapshot, DiskSnapshot, FanReading, HealthProbeResult,
    HwmonSensorReading, LoadAverage, LogEntry, LogPattern, LogQueryResult, MemorySnapshot,
    MetricSnapshot, NetworkConnection, NetworkInterfaceSnapshot, NetworkMetricsSnapshot,
    NetworkSnapshot, OsContext, OsSampleMeta, PlatformInfo, ProcessInfo, ProcessList, RateStatus,
    ResourceDimension, SensorAvailability, ServiceSnapshot, ServiceUnit, TemperatureReading,
    ThermalSnapshot,
};
pub use network::{collect_network, NetworkQuery, TcpProbeRequest};
pub use procfs::{
    collect_metrics, collect_processes, Clock, KylinPartitionUsageProvider, MetricsThresholds,
    PartitionUsageProvider, ProcessQuery, ProcfsCollector, SystemClock,
};
pub use runtime::{
    current_time_ms, default_database_path, MetricsHistory, OsSenseRuntime, OsSenseRuntimeConfig,
    TimeSeriesWindow,
};
pub use scheduler::{
    CollectionIntervals, CollectionScheduler, SchedulerConfig, CPU_INTERVAL_MS, DISK_INTERVAL_MS,
    MEMORY_INTERVAL_MS, NETWORK_INTERVAL_MS, THERMAL_INTERVAL_MS,
};
pub use services::{query_services, ServiceQuery};
pub use storage::OsSenseStore;
