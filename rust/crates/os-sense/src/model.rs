use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ResourceDimension {
    Cpu,
    Memory,
    Disk,
    Network,
    Thermal,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionMode {
    #[default]
    OnDemand,
    Scheduled,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionStatus {
    Complete,
    #[default]
    Partial,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RateStatus {
    WarmingUp,
    Ready,
    CounterReset,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DimensionCollectionResult {
    pub dimension: ResourceDimension,
    pub status: CollectionStatus,
    #[serde(default)]
    pub rate_status: Option<RateStatus>,
    #[serde(default)]
    pub retryable: bool,
    pub message: Option<String>,
}

impl ResourceDimension {
    pub const ALL: [Self; 5] = [
        Self::Cpu,
        Self::Memory,
        Self::Disk,
        Self::Network,
        Self::Thermal,
    ];
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsSampleMeta {
    pub collected_at_ms: u64,
    pub source: String,
    pub platform: PlatformInfo,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlatformInfo {
    pub os: String,
    pub arch: String,
    pub kernel_version: Option<String>,
    pub loongarch: LoongArchInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoongArchInfo {
    pub detected: bool,
    pub cpu_model: Option<String>,
    pub hwmon_paths: Vec<String>,
    #[serde(default)]
    pub hwmon_sensors: Vec<HwmonSensorReading>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HwmonSensorReading {
    pub device: String,
    pub sensor: String,
    pub label: Option<String>,
    pub value: i64,
    pub unit: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricSnapshot {
    pub meta: OsSampleMeta,
    #[serde(default)]
    pub mode: CollectionMode,
    #[serde(default)]
    pub started_at_ms: u64,
    #[serde(default)]
    pub completed_at_ms: u64,
    #[serde(default)]
    pub status: CollectionStatus,
    #[serde(default)]
    pub dimension_results: Vec<DimensionCollectionResult>,
    #[serde(default)]
    pub attempted_dimensions: Vec<ResourceDimension>,
    #[serde(default)]
    pub updated_dimensions: Vec<ResourceDimension>,
    pub cpu: CpuSnapshot,
    pub memory: MemorySnapshot,
    pub load: Option<LoadAverage>,
    pub disks: Vec<DiskSnapshot>,
    #[serde(default)]
    pub disk_devices: Vec<DiskDeviceSnapshot>,
    #[serde(default)]
    pub network: NetworkMetricsSnapshot,
    #[serde(default)]
    pub thermal: ThermalSnapshot,
    pub alerts: Vec<Alert>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CpuSnapshot {
    #[serde(default)]
    pub collected_at_ms: u64,
    #[serde(default)]
    pub sample_interval_ms: Option<u64>,
    pub usage_percent: Option<f64>,
    pub total_jiffies: u64,
    pub idle_jiffies: u64,
    pub cpu_count: usize,
    #[serde(default)]
    pub cores: Vec<CpuCoreSnapshot>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CpuCoreSnapshot {
    pub name: String,
    pub usage_percent: Option<f64>,
    pub total_jiffies: u64,
    pub idle_jiffies: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MemorySnapshot {
    #[serde(default)]
    pub collected_at_ms: u64,
    pub total_kb: u64,
    pub available_kb: u64,
    pub used_kb: u64,
    pub used_percent: Option<f64>,
    #[serde(default)]
    pub buffers_kb: u64,
    #[serde(default)]
    pub cached_kb: u64,
    #[serde(default)]
    pub swap_total_kb: u64,
    #[serde(default)]
    pub swap_free_kb: u64,
    #[serde(default)]
    pub swap_used_kb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoadAverage {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
    pub runnable_tasks: Option<u64>,
    pub total_tasks: Option<u64>,
    pub last_pid: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiskSnapshot {
    #[serde(default)]
    pub collected_at_ms: u64,
    pub mount_point: String,
    pub filesystem: String,
    pub total_bytes: Option<u64>,
    pub used_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub used_percent: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct DiskDeviceSnapshot {
    pub name: String,
    pub collected_at_ms: u64,
    pub sample_interval_ms: Option<u64>,
    pub reads_completed_total: u64,
    pub writes_completed_total: u64,
    pub sectors_read_total: u64,
    pub sectors_written_total: u64,
    pub io_in_progress: u64,
    pub read_bytes_per_sec: Option<f64>,
    pub write_bytes_per_sec: Option<f64>,
    pub read_iops: Option<f64>,
    pub write_iops: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NetworkMetricsSnapshot {
    pub collected_at_ms: u64,
    pub connection_count: usize,
    pub interfaces: Vec<NetworkInterfaceSnapshot>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct NetworkInterfaceSnapshot {
    pub name: String,
    pub collected_at_ms: u64,
    pub sample_interval_ms: Option<u64>,
    pub receive_bytes_total: u64,
    pub receive_packets_total: u64,
    pub receive_errors_total: u64,
    pub receive_dropped_total: u64,
    pub transmit_bytes_total: u64,
    pub transmit_packets_total: u64,
    pub transmit_errors_total: u64,
    pub transmit_dropped_total: u64,
    pub receive_bytes_per_sec: Option<f64>,
    pub transmit_bytes_per_sec: Option<f64>,
    pub receive_packets_per_sec: Option<f64>,
    pub transmit_packets_per_sec: Option<f64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ThermalSnapshot {
    pub collected_at_ms: u64,
    #[serde(default)]
    pub availability: SensorAvailability,
    #[serde(default)]
    pub thermal_zone_available: bool,
    #[serde(default)]
    pub hwmon_available: bool,
    pub temperatures: Vec<TemperatureReading>,
    pub fans: Vec<FanReading>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SensorAvailability {
    Available,
    #[default]
    Unavailable,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemperatureReading {
    pub source: String,
    pub label: Option<String>,
    pub millidegrees_celsius: i64,
    pub path: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FanReading {
    pub source: String,
    pub label: Option<String>,
    pub rpm: u64,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub dimension: String,
    pub severity: String,
    pub message: String,
    pub value: f64,
    pub threshold: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertContext {
    pub generated_at_ms: u64,
    pub source: String,
    pub alerts: Vec<Alert>,
    pub llm_context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessList {
    pub meta: OsSampleMeta,
    pub total: usize,
    pub truncated: bool,
    pub processes: Vec<ProcessInfo>,
    pub anomalies: Vec<ProcessAnomaly>,
    pub unauthorized: Vec<ProcessInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub state: String,
    pub user: Option<String>,
    pub cpu_time_jiffies: u64,
    pub memory_rss_kb: Option<u64>,
    pub virtual_memory_kb: Option<u64>,
    pub uptime_seconds: Option<f64>,
    pub command: Option<String>,
    pub anomalies: Vec<ProcessAnomaly>,
    pub authorized: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessAnomaly {
    pub pid: u32,
    pub kind: String,
    pub message: String,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LogQueryResult {
    pub meta: OsSampleMeta,
    pub truncated: bool,
    pub entries: Vec<LogEntry>,
    pub patterns: Vec<LogPattern>,
    pub summary: Option<LogSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    pub source: String,
    pub timestamp: Option<String>,
    pub severity: Option<String>,
    pub unit: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogPattern {
    pub kind: String,
    pub count: usize,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogSummary {
    pub kind: String,
    pub text: String,
    pub by_source: Vec<CountByKey>,
    pub by_severity: Vec<CountByKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CountByKey {
    pub key: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkSnapshot {
    pub meta: OsSampleMeta,
    pub truncated: bool,
    pub connections: Vec<NetworkConnection>,
    pub dns_checks: Vec<DnsCheck>,
    pub tcp_probes: Vec<HealthProbeResult>,
    pub firewall: Vec<FirewallStatus>,
    pub anomalies: Vec<NetworkAnomaly>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkConnection {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub inode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsCheck {
    pub name: String,
    pub resolved_addrs: Vec<String>,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthProbeResult {
    pub target: String,
    pub ok: bool,
    pub latency_ms: Option<u128>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirewallStatus {
    pub backend: String,
    pub available: bool,
    pub status: String,
    pub rules_sample: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkAnomaly {
    pub kind: String,
    pub message: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServiceSnapshot {
    pub meta: OsSampleMeta,
    pub available: bool,
    pub truncated: bool,
    pub units: Vec<ServiceUnit>,
    pub failed_units: Vec<ServiceUnit>,
    pub health_probes: Vec<HealthProbeResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceUnit {
    pub name: String,
    pub load_state: Option<String>,
    pub active_state: Option<String>,
    pub sub_state: Option<String>,
    pub unit_file_state: Option<String>,
    pub description: Option<String>,
    pub result: Option<String>,
    pub exec_main_status: Option<i32>,
    pub fragment_path: Option<String>,
    pub requires: Vec<String>,
    pub wants: Vec<String>,
    pub after: Vec<String>,
    pub before: Vec<String>,
    pub ports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OsContext {
    pub meta: OsSampleMeta,
    pub dimensions: Vec<String>,
    pub metrics: Option<MetricSnapshot>,
    pub processes: Option<ProcessList>,
    pub logs: Option<LogQueryResult>,
    pub network: Option<NetworkSnapshot>,
    pub services: Option<ServiceSnapshot>,
    pub alerts: Vec<Alert>,
    pub alert_context: Option<AlertContext>,
    pub summary: String,
    pub cropped_dimensions: Vec<String>,
}
