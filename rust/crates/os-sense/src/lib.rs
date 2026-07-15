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
    Alert, AlertContext, CpuSnapshot, DiskSnapshot, HealthProbeResult, HwmonSensorReading,
    LoadAverage, LogEntry, LogPattern, LogQueryResult, MemorySnapshot, MetricSnapshot,
    NetworkConnection, NetworkSnapshot, OsContext, OsSampleMeta, PlatformInfo, ProcessInfo,
    ProcessList, ServiceSnapshot, ServiceUnit,
};
pub use network::{collect_network, NetworkQuery, TcpProbeRequest};
pub use procfs::{collect_metrics, collect_processes, MetricsThresholds, ProcessQuery};
pub use runtime::{
    current_time_ms, default_database_path, MetricsHistory, OsSenseRuntime, OsSenseRuntimeConfig,
    TimeSeriesWindow,
};
pub use scheduler::{CollectionScheduler, SchedulerConfig};
pub use services::{query_services, ServiceQuery};
pub use storage::OsSenseStore;
