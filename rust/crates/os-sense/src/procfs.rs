use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::command::run_limited_command;
use crate::error::{OsSenseError, Result};
use crate::model::{
    Alert, AlertEvaluationFreshness, CollectionMode, CollectionStatus, CpuCoreSnapshot,
    CpuSnapshot, DimensionCollectionResult, DiskDeviceSnapshot, DiskSnapshot, FanReading,
    HwmonSensorReading, LoadAverage, LoongArchInfo, MemorySnapshot, MetricSnapshot,
    NetworkInterfaceSnapshot, NetworkMetricsSnapshot, OsSampleMeta, PlatformInfo, ProcessAnomaly,
    ProcessAnomalyEvidence, ProcessBaseline, ProcessInfo, ProcessList, RateStatus,
    ResourceDimension, SensorAvailability, TemperatureReading, ThermalSnapshot,
};
use crate::redaction::redact_sensitive_text;

const DEFAULT_PROC_ROOT: &str = "/proc";
const DEFAULT_SYS_ROOT: &str = "/sys";
const FALLBACK_CLK_TCK: u64 = 100;
const FALLBACK_PAGE_SIZE_BYTES: u64 = 4_096;
const DEFAULT_PROCESS_LIMIT: usize = 100;
const MAX_PROCESS_LIMIT: usize = 500;
const MAX_PROCESS_WARNINGS: usize = 32;
const PROCESS_BASELINE_TTL_MS: u64 = 10 * 60 * 1_000;
const MAX_PROCESS_BASELINES: usize = 32_768;
const POSITIVE_USER_CACHE_TTL_MS: u64 = 60 * 60 * 1_000;
const NEGATIVE_USER_CACHE_TTL_MS: u64 = 30 * 1_000;
const MAX_PROCESS_USER_CACHE_ENTRIES: usize = 4_096;
const MAX_NSS_LOOKUPS_PER_COLLECTION: usize = 16;
const MAX_PROCESS_LIST_ANOMALIES: usize = 128;
const MAX_UNAUTHORIZED_PROCESS_SUMMARY: usize = 128;
const PROCESS_ANOMALY_STATE_TTL_MS: u64 = 10 * 60 * 1_000;
const MAX_PROCESS_ANOMALY_STATES: usize = 32_768;
const PROCESS_PATTERN_MIN_SAMPLES: usize = 3;
const MEMORY_LEAK_MIN_DURATION_MS: u64 = 60_000;
const MEMORY_LEAK_MIN_ABSOLUTE_GROWTH_KB: u64 = 64 * 1_024;
const MEMORY_LEAK_MIN_RELATIVE_GROWTH_PERCENT: f64 = 20.0;
const CPU_BUSY_LOOP_MIN_DURATION_MS: u64 = 60_000;
const CPU_BUSY_LOOP_MIN_USAGE_PERCENT: f64 = 90.0;
const MAX_CMDLINE_CHARS: usize = 256;
const MAX_EXECUTABLE_PATH_BYTES: usize = 4_096;
const MAX_HWMON_SENSORS: usize = 128;
const DISK_SECTOR_BYTES: u64 = 512;
pub const PROCESS_BASELINE_VERSION: u32 = 1;
pub const MAX_PROCESS_BASELINE_ENTRIES: usize = 200;
pub const MAX_PROCESS_BASELINE_JSON_BYTES: usize = 64 * 1_024;
pub const OS_PROCESS_BASELINE_FILE_ENV: &str = "CLAW_OS_PROCESS_BASELINE_FILE";
const MAX_PROCESS_BASELINE_ID_CHARS: usize = 64;
const MAX_PROCESS_BASELINE_NAME_CHARS: usize = 128;

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub trait MonotonicClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub trait PartitionUsageProvider: Send + Sync {
    fn read_df_output(&self) -> Result<String>;
}

pub trait ProcessUserResolver: Send + Sync {
    fn resolve_local(&self, _uid: u32) -> Option<String> {
        None
    }

    fn resolve(&self, uid: u32) -> std::result::Result<Option<String>, String>;
}

#[derive(Debug)]
pub struct KylinProcessUserResolver {
    passwd_users: BTreeMap<u32, String>,
}

impl Default for KylinProcessUserResolver {
    fn default() -> Self {
        Self {
            passwd_users: load_passwd_users(),
        }
    }
}

impl ProcessUserResolver for KylinProcessUserResolver {
    fn resolve_local(&self, uid: u32) -> Option<String> {
        self.passwd_users.get(&uid).cloned()
    }

    fn resolve(&self, uid: u32) -> std::result::Result<Option<String>, String> {
        resolve_user_with_getent(uid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessSystemParameters {
    pub clock_ticks_per_second: u64,
    pub page_size_bytes: u64,
}

impl Default for ProcessSystemParameters {
    fn default() -> Self {
        Self {
            clock_ticks_per_second: FALLBACK_CLK_TCK,
            page_size_bytes: FALLBACK_PAGE_SIZE_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ProcessCpuBaseline {
    start_time_jiffies: u64,
    cpu_time_jiffies: u64,
    sampled_at_ms: u64,
    scan_id: u64,
}

#[derive(Debug, Clone, Copy)]
struct MemoryGrowthState {
    started_at_ms: u64,
    initial_rss_kb: u64,
    latest_rss_kb: u64,
    sample_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct CpuBusyState {
    started_at_ms: u64,
    minimum_usage_percent: f64,
    latest_usage_percent: f64,
    sample_count: usize,
}

#[derive(Debug, Clone, Copy)]
struct ProcessAnomalyState {
    start_time_jiffies: u64,
    sampled_at_ms: u64,
    scan_id: u64,
    memory_growth: Option<MemoryGrowthState>,
    cpu_busy: Option<CpuBusyState>,
}

#[derive(Debug, Clone)]
struct CachedUserResolution {
    user: String,
    warning: Option<String>,
    cached_at_ms: u64,
    positive: bool,
    definitive: bool,
}

struct ProcessReadOutcome {
    process: ProcessInfo,
    sampled_at_ms: u64,
    status_available: bool,
    cmdline_available: bool,
    warnings: Vec<String>,
}

struct EffectiveProcessBaseline<'a> {
    configured: Option<&'a ProcessBaseline>,
    legacy_names: &'a BTreeSet<String>,
}

enum ProcessAuthorizationDecision {
    Inactive,
    Authorized,
    Unauthorized,
    Indeterminate(String),
}

enum ProcessFilterDecision {
    Matches,
    DoesNotMatch,
    Indeterminate(&'static str),
}

struct ProcessCandidate {
    process: ProcessInfo,
    partial: bool,
}

trait ProcessFileReader: Send + Sync {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String>;
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>>;
    fn read_link(&self, path: &Path) -> std::io::Result<PathBuf>;
}

#[derive(Debug, Default)]
struct SystemProcessFileReader;

impl ProcessFileReader for SystemProcessFileReader {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
        fs::read_to_string(path)
    }

    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
        fs::read_link(path)
    }
}

enum ProcessReadFailure {
    Exited,
    Failed(OsSenseError),
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        now_ms()
    }
}

#[derive(Debug)]
pub struct SystemMonotonicClock {
    started_at: Instant,
}

impl Default for SystemMonotonicClock {
    fn default() -> Self {
        Self {
            started_at: Instant::now(),
        }
    }
}

impl MonotonicClock for SystemMonotonicClock {
    fn now_ms(&self) -> u64 {
        self.started_at.elapsed().as_millis() as u64
    }
}

#[derive(Debug, Default)]
pub struct KylinPartitionUsageProvider;

impl PartitionUsageProvider for KylinPartitionUsageProvider {
    fn read_df_output(&self) -> Result<String> {
        let output = run_limited_command(
            "df",
            &["-P", "-B1"],
            Duration::from_secs(2),
            64 * 1024,
            16 * 1024,
        )?;
        if output.timed_out {
            return Err(OsSenseError::Command("df -P -B1 timed out".to_string()));
        }
        if !output.success {
            return Err(OsSenseError::Command(format!(
                "df -P -B1 failed: {}",
                output.stderr.trim()
            )));
        }
        if output.stdout_truncated {
            return Err(OsSenseError::Command(
                "df -P -B1 output exceeded the collection limit".to_string(),
            ));
        }
        Ok(output.stdout)
    }
}

fn detect_process_system_parameters() -> (ProcessSystemParameters, Vec<String>) {
    let mut parameters = ProcessSystemParameters::default();
    let mut warnings = Vec::new();
    match read_getconf_value("CLK_TCK") {
        Ok(value) => parameters.clock_ticks_per_second = value,
        Err(error) => warnings.push(format!(
            "getconf CLK_TCK unavailable; using fallback {FALLBACK_CLK_TCK}: {error}"
        )),
    }
    match read_getconf_value("PAGESIZE") {
        Ok(value) => parameters.page_size_bytes = value,
        Err(error) => warnings.push(format!(
            "getconf PAGESIZE unavailable; using fallback {FALLBACK_PAGE_SIZE_BYTES}: {error}"
        )),
    }
    (parameters, warnings)
}

fn read_getconf_value(name: &str) -> std::result::Result<u64, String> {
    let output = run_limited_command("getconf", &[name], Duration::from_millis(500), 128, 512)
        .map_err(|error| error.to_string())?;
    if output.timed_out {
        return Err("command timed out".to_string());
    }
    if !output.success || output.stdout_truncated {
        return Err("command failed or exceeded output limit".to_string());
    }
    output
        .stdout
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| "command returned an invalid value".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsThresholds {
    pub cpu_percent: Option<f64>,
    pub memory_percent: Option<f64>,
    pub disk_percent: Option<f64>,
    pub load1: Option<f64>,
}

pub const OS_SENSE_THRESHOLDS_ENV: &str = "CLAW_OS_SENSE_THRESHOLDS";

impl Default for MetricsThresholds {
    fn default() -> Self {
        Self {
            cpu_percent: Some(90.0),
            memory_percent: Some(90.0),
            disk_percent: Some(90.0),
            load1: None,
        }
    }
}

impl MetricsThresholds {
    pub fn from_environment() -> Result<Self> {
        match std::env::var(OS_SENSE_THRESHOLDS_ENV) {
            Ok(value) => Self::from_json(&value),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(std::env::VarError::NotUnicode(_)) => Err(OsSenseError::Configuration(format!(
                "{OS_SENSE_THRESHOLDS_ENV} must contain UTF-8 JSON"
            ))),
        }
    }

    pub fn from_json(value: &str) -> Result<Self> {
        let thresholds = serde_json::from_str::<Self>(value).map_err(|error| {
            OsSenseError::Configuration(format!("invalid {OS_SENSE_THRESHOLDS_ENV} JSON: {error}"))
        })?;
        thresholds.validate()?;
        Ok(thresholds)
    }

    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("cpu_percent", self.cpu_percent),
            ("memory_percent", self.memory_percent),
            ("disk_percent", self.disk_percent),
        ] {
            if value.is_some_and(|value| !value.is_finite() || !(0.0..=100.0).contains(&value)) {
                return Err(OsSenseError::Configuration(format!(
                    "{OS_SENSE_THRESHOLDS_ENV}.{name} must be finite and between 0 and 100"
                )));
            }
        }
        if self
            .load1
            .is_some_and(|value| !value.is_finite() || value < 0.0)
        {
            return Err(OsSenseError::Configuration(format!(
                "{OS_SENSE_THRESHOLDS_ENV}.load1 must be finite and non-negative"
            )));
        }
        Ok(())
    }
}

impl ProcessBaseline {
    pub fn from_json_bytes(value: &[u8]) -> Result<Self> {
        if value.len() > MAX_PROCESS_BASELINE_JSON_BYTES {
            return Err(OsSenseError::Configuration(format!(
                "process baseline JSON must not exceed {MAX_PROCESS_BASELINE_JSON_BYTES} bytes"
            )));
        }
        let baseline = serde_json::from_slice::<Self>(value).map_err(|error| {
            OsSenseError::Configuration(format!("invalid process baseline JSON: {error}"))
        })?;
        baseline.validate()?;
        Ok(baseline)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != PROCESS_BASELINE_VERSION {
            return Err(OsSenseError::Configuration(format!(
                "unsupported process baseline version {}; expected {PROCESS_BASELINE_VERSION}",
                self.version
            )));
        }
        if self.id.trim().is_empty()
            || self.id.chars().count() > MAX_PROCESS_BASELINE_ID_CHARS
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(OsSenseError::Configuration(format!(
                "process baseline id must contain 1 to {MAX_PROCESS_BASELINE_ID_CHARS} ASCII letters, digits, '.', '_', or '-'"
            )));
        }
        if self.entries.len() > MAX_PROCESS_BASELINE_ENTRIES {
            return Err(OsSenseError::Configuration(format!(
                "process baseline must not contain more than {MAX_PROCESS_BASELINE_ENTRIES} entries"
            )));
        }
        for (index, entry) in self.entries.iter().enumerate() {
            if entry.name.trim().is_empty()
                || !entry.name.is_ascii()
                || entry.name.contains('\0')
                || entry.name.chars().count() > MAX_PROCESS_BASELINE_NAME_CHARS
            {
                return Err(OsSenseError::Configuration(format!(
                    "process baseline entries[{index}].name must contain 1 to {MAX_PROCESS_BASELINE_NAME_CHARS} ASCII characters without NUL"
                )));
            }
            if let Some(path) = &entry.path {
                if !is_valid_absolute_linux_path(path) {
                    return Err(OsSenseError::Configuration(format!(
                        "process baseline entries[{index}].path must be an absolute Linux path without '..' or NUL and at most {MAX_EXECUTABLE_PATH_BYTES} bytes"
                    )));
                }
            }
        }
        let encoded = serde_json::to_vec(self).map_err(|error| {
            OsSenseError::Configuration(format!("failed to encode process baseline: {error}"))
        })?;
        if encoded.len() > MAX_PROCESS_BASELINE_JSON_BYTES {
            return Err(OsSenseError::Configuration(format!(
                "process baseline JSON must not exceed {MAX_PROCESS_BASELINE_JSON_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessQuery {
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub name_contains: Option<String>,
    pub user: Option<String>,
    pub state: Option<String>,
    pub anomaly_kind: Option<String>,
    pub authorized: Option<bool>,
    pub allowed_names: Vec<String>,
    pub limit: Option<usize>,
}

impl ProcessQuery {
    pub fn validate(&self) -> Result<()> {
        self.validate_for_collection(false)
    }

    fn validate_for_collection(&self, configured_baseline_active: bool) -> Result<()> {
        for (name, value, max_chars) in [
            ("name_contains", self.name_contains.as_deref(), 128),
            ("user", self.user.as_deref(), 64),
            ("anomaly_kind", self.anomaly_kind.as_deref(), 64),
        ] {
            if let Some(value) = value {
                if value.trim().is_empty() {
                    return Err(OsSenseError::Configuration(format!(
                        "process query {name} must not be blank"
                    )));
                }
                if value.chars().count() > max_chars {
                    return Err(OsSenseError::Configuration(format!(
                        "process query {name} must not exceed {max_chars} characters"
                    )));
                }
            }
        }
        if self.allowed_names.len() > 200 {
            return Err(OsSenseError::Configuration(
                "process query allowed_names must not contain more than 200 entries".to_string(),
            ));
        }
        for (index, name) in self.allowed_names.iter().enumerate() {
            if name.trim().is_empty() {
                return Err(OsSenseError::Configuration(format!(
                    "process query allowed_names[{index}] must not be blank"
                )));
            }
            if name.chars().count() > 128 {
                return Err(OsSenseError::Configuration(format!(
                    "process query allowed_names[{index}] must not exceed 128 characters"
                )));
            }
        }
        if configured_baseline_active && !self.allowed_names.is_empty() {
            return Err(OsSenseError::Configuration(
                "process query allowed_names cannot be used when a configured process baseline is active"
                    .to_string(),
            ));
        }
        if self.authorized.is_some() && self.allowed_names.is_empty() && !configured_baseline_active
        {
            return Err(OsSenseError::Configuration(
                "process query authorized requires a configured process baseline or non-empty allowed_names baseline"
                    .to_string(),
            ));
        }
        if let Some(state) = &self.state {
            if normalized_linux_process_state(state).is_none() {
                return Err(OsSenseError::Configuration(
                    "process query state must be one Linux process state character: R, S, D, Z, T, t, W, X, x, K, P, or I"
                        .to_string(),
                ));
            }
        }
        if let Some(limit) = self.limit {
            if !(1..=MAX_PROCESS_LIMIT).contains(&limit) {
                return Err(OsSenseError::Configuration(format!(
                    "process query limit must be between 1 and {MAX_PROCESS_LIMIT}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Default)]
struct MetricsState {
    cpu: Option<CpuSnapshot>,
    memory: Option<MemorySnapshot>,
    load: Option<LoadAverage>,
    disks: Vec<DiskSnapshot>,
    disk_devices: Vec<DiskDeviceSnapshot>,
    network: Option<NetworkMetricsSnapshot>,
    thermal: Option<ThermalSnapshot>,
}

#[derive(Default)]
struct MetricsByMode {
    on_demand: MetricsState,
    scheduled: MetricsState,
}

pub struct ProcfsCollector {
    proc_root: PathBuf,
    sys_root: PathBuf,
    clock: Arc<dyn Clock>,
    process_clock: Arc<dyn MonotonicClock>,
    partition_usage: Arc<dyn PartitionUsageProvider>,
    metrics: MetricsByMode,
    process_system_parameters: ProcessSystemParameters,
    process_system_warnings: Vec<String>,
    process_scan_id: u64,
    process_cpu_baselines: BTreeMap<u32, ProcessCpuBaseline>,
    process_cpu_baseline_order: BTreeSet<(u64, u32)>,
    process_anomaly_states: BTreeMap<u32, ProcessAnomalyState>,
    process_anomaly_state_order: BTreeSet<(u64, u32)>,
    process_user_resolver: Arc<dyn ProcessUserResolver>,
    process_user_cache: BTreeMap<u32, CachedUserResolution>,
    process_file_reader: Arc<dyn ProcessFileReader>,
    process_baseline: Option<ProcessBaseline>,
}

impl Default for ProcfsCollector {
    fn default() -> Self {
        let (process_system_parameters, process_system_warnings) =
            detect_process_system_parameters();
        Self {
            proc_root: PathBuf::from(DEFAULT_PROC_ROOT),
            sys_root: PathBuf::from(DEFAULT_SYS_ROOT),
            clock: Arc::new(SystemClock),
            process_clock: Arc::new(SystemMonotonicClock::default()),
            partition_usage: Arc::new(KylinPartitionUsageProvider),
            metrics: MetricsByMode::default(),
            process_system_parameters,
            process_system_warnings,
            process_scan_id: 0,
            process_cpu_baselines: BTreeMap::new(),
            process_cpu_baseline_order: BTreeSet::new(),
            process_anomaly_states: BTreeMap::new(),
            process_anomaly_state_order: BTreeSet::new(),
            process_user_resolver: Arc::new(KylinProcessUserResolver::default()),
            process_user_cache: BTreeMap::new(),
            process_file_reader: Arc::new(SystemProcessFileReader),
            process_baseline: None,
        }
    }
}

impl ProcfsCollector {
    #[must_use]
    pub fn new(proc_root: impl Into<PathBuf>, sys_root: impl Into<PathBuf>) -> Self {
        let (process_system_parameters, process_system_warnings) =
            detect_process_system_parameters();
        Self {
            proc_root: proc_root.into(),
            sys_root: sys_root.into(),
            clock: Arc::new(SystemClock),
            process_clock: Arc::new(SystemMonotonicClock::default()),
            partition_usage: Arc::new(KylinPartitionUsageProvider),
            metrics: MetricsByMode::default(),
            process_system_parameters,
            process_system_warnings,
            process_scan_id: 0,
            process_cpu_baselines: BTreeMap::new(),
            process_cpu_baseline_order: BTreeSet::new(),
            process_anomaly_states: BTreeMap::new(),
            process_anomaly_state_order: BTreeSet::new(),
            process_user_resolver: Arc::new(KylinProcessUserResolver::default()),
            process_user_cache: BTreeMap::new(),
            process_file_reader: Arc::new(SystemProcessFileReader),
            process_baseline: None,
        }
    }

    #[must_use]
    pub fn with_dependencies(
        proc_root: impl Into<PathBuf>,
        sys_root: impl Into<PathBuf>,
        clock: Arc<dyn Clock>,
        partition_usage: Arc<dyn PartitionUsageProvider>,
    ) -> Self {
        let (process_system_parameters, process_system_warnings) =
            detect_process_system_parameters();
        Self {
            proc_root: proc_root.into(),
            sys_root: sys_root.into(),
            clock,
            process_clock: Arc::new(SystemMonotonicClock::default()),
            partition_usage,
            metrics: MetricsByMode::default(),
            process_system_parameters,
            process_system_warnings,
            process_scan_id: 0,
            process_cpu_baselines: BTreeMap::new(),
            process_cpu_baseline_order: BTreeSet::new(),
            process_anomaly_states: BTreeMap::new(),
            process_anomaly_state_order: BTreeSet::new(),
            process_user_resolver: Arc::new(KylinProcessUserResolver::default()),
            process_user_cache: BTreeMap::new(),
            process_file_reader: Arc::new(SystemProcessFileReader),
            process_baseline: None,
        }
    }

    #[must_use]
    pub fn with_process_dependencies(
        proc_root: impl Into<PathBuf>,
        sys_root: impl Into<PathBuf>,
        clock: Arc<dyn Clock>,
        process_clock: Arc<dyn MonotonicClock>,
        partition_usage: Arc<dyn PartitionUsageProvider>,
        process_system_parameters: ProcessSystemParameters,
        process_user_resolver: Arc<dyn ProcessUserResolver>,
    ) -> Self {
        Self {
            proc_root: proc_root.into(),
            sys_root: sys_root.into(),
            clock,
            process_clock,
            partition_usage,
            metrics: MetricsByMode::default(),
            process_system_parameters,
            process_system_warnings: Vec::new(),
            process_scan_id: 0,
            process_cpu_baselines: BTreeMap::new(),
            process_cpu_baseline_order: BTreeSet::new(),
            process_anomaly_states: BTreeMap::new(),
            process_anomaly_state_order: BTreeSet::new(),
            process_user_resolver,
            process_user_cache: BTreeMap::new(),
            process_file_reader: Arc::new(SystemProcessFileReader),
            process_baseline: None,
        }
    }

    pub fn set_process_baseline(&mut self, baseline: Option<ProcessBaseline>) -> Result<()> {
        if let Some(baseline) = &baseline {
            baseline.validate()?;
        }
        self.process_baseline = baseline;
        Ok(())
    }

    pub fn collect_metrics(&mut self, thresholds: &MetricsThresholds) -> MetricSnapshot {
        self.collect_dimensions(
            CollectionMode::OnDemand,
            &ResourceDimension::ALL,
            thresholds,
        )
    }

    pub fn collect_dimensions(
        &mut self,
        mode: CollectionMode,
        dimensions: &[ResourceDimension],
        thresholds: &MetricsThresholds,
    ) -> MetricSnapshot {
        let started_at_ms = self.clock.now_ms();
        let mut warnings = Vec::new();
        let mut platform = self.platform_info(&mut warnings);
        let mut dimension_results = Vec::new();
        let mut alert_evaluations = AlertEvaluationFreshness::default();

        if dimensions.contains(&ResourceDimension::Cpu) {
            let (result, cpu_usage, load1) = self.collect_cpu(mode, started_at_ms, &mut warnings);
            alert_evaluations.cpu_usage = cpu_usage;
            alert_evaluations.load1 = load1;
            dimension_results.push(result);
        }
        if dimensions.contains(&ResourceDimension::Memory) {
            let (result, memory) = self.collect_memory(mode, started_at_ms, &mut warnings);
            alert_evaluations.memory = memory;
            dimension_results.push(result);
        }
        if dimensions.contains(&ResourceDimension::Disk) {
            let (result, disk_capacity) = self.collect_disk(mode, started_at_ms, &mut warnings);
            alert_evaluations.disk_capacity = disk_capacity;
            dimension_results.push(result);
        }
        if dimensions.contains(&ResourceDimension::Network) {
            dimension_results.push(self.collect_network_metrics(
                mode,
                started_at_ms,
                &mut warnings,
            ));
        }
        if dimensions.contains(&ResourceDimension::Thermal) {
            let (thermal, transient_failure) =
                collect_thermal(&self.sys_root, started_at_ms, &mut warnings);
            let thermal_available = thermal.availability == SensorAvailability::Available;
            self.metrics_mut(mode).thermal = Some(thermal);
            dimension_results.push(DimensionCollectionResult {
                dimension: ResourceDimension::Thermal,
                status: if thermal_available {
                    CollectionStatus::Complete
                } else {
                    CollectionStatus::Failed
                },
                rate_status: None,
                retryable: !thermal_available && transient_failure,
                message: (!thermal_available).then(|| {
                    "no valid reading from /sys/class/thermal or /sys/class/hwmon".to_string()
                }),
            });
        }

        let metrics = self.metrics(mode);
        let cpu = metrics.cpu.clone().unwrap_or_default();
        let memory = metrics.memory.clone().unwrap_or_default();
        let load = metrics.load.clone();
        let disks = metrics.disks.clone();
        let disk_devices = metrics.disk_devices.clone();
        let network = metrics.network.clone().unwrap_or_default();
        let thermal = metrics.thermal.clone().unwrap_or_default();
        if platform.loongarch.detected {
            platform.loongarch.hwmon_sensors = thermal.hwmon_sensors.clone();
        }
        let alerts = build_metric_alerts(&cpu, &memory, load.as_ref(), &disks, thresholds);
        let completed_at_ms = self.clock.now_ms();
        let status = collection_status(dimensions, &dimension_results);
        let updated_dimensions = dimension_results
            .iter()
            .filter(|result| result.status != CollectionStatus::Failed)
            .map(|result| result.dimension)
            .collect();

        MetricSnapshot {
            meta: OsSampleMeta {
                collected_at_ms: completed_at_ms,
                source: "procfs+sysfs".to_string(),
                platform,
                warnings,
            },
            mode,
            started_at_ms,
            completed_at_ms,
            status,
            dimension_results,
            attempted_dimensions: dimensions.to_vec(),
            updated_dimensions,
            alert_evaluations,
            cpu,
            memory,
            load,
            disks,
            disk_devices,
            network,
            thermal,
            alerts,
        }
    }

    fn collect_cpu(
        &mut self,
        mode: CollectionMode,
        collected_at_ms: u64,
        warnings: &mut Vec<String>,
    ) -> (DimensionCollectionResult, bool, bool) {
        let mut rate_status = None;
        let mut cpu_usage_evaluated = false;
        let stat_collected = match fs::read_to_string(self.proc_root.join("stat")) {
            Ok(content) => match parse_cpu_stat(&content) {
                Some(mut cpu) => {
                    cpu.collected_at_ms = collected_at_ms;
                    let status = apply_cpu_delta(&mut cpu, self.metrics(mode).cpu.as_ref());
                    cpu_usage_evaluated = status == RateStatus::Ready
                        && cpu.usage_percent.is_some_and(f64::is_finite);
                    rate_status = Some(status);
                    self.metrics_mut(mode).cpu = Some(cpu);
                    true
                }
                None => {
                    warnings.push("failed to parse /proc/stat".to_string());
                    false
                }
            },
            Err(error) => {
                warnings.push(format!("failed to read /proc/stat: {error}"));
                false
            }
        };

        let load_collected = match fs::read_to_string(self.proc_root.join("loadavg")) {
            Ok(content) => match parse_loadavg(&content) {
                Some(load) => {
                    self.metrics_mut(mode).load = Some(load);
                    true
                }
                None => {
                    warnings.push("failed to parse /proc/loadavg".to_string());
                    false
                }
            },
            Err(error) => {
                warnings.push(format!("failed to read /proc/loadavg: {error}"));
                false
            }
        };
        (
            source_result(
                ResourceDimension::Cpu,
                stat_collected as usize + load_collected as usize,
                2,
                rate_status,
                "CPU counters or load average could not be collected",
            ),
            cpu_usage_evaluated,
            load_collected,
        )
    }

    fn collect_memory(
        &mut self,
        mode: CollectionMode,
        collected_at_ms: u64,
        warnings: &mut Vec<String>,
    ) -> (DimensionCollectionResult, bool) {
        let collected = match fs::read_to_string(self.proc_root.join("meminfo")) {
            Ok(content) => match parse_meminfo(&content) {
                Some(mut memory) => {
                    memory.collected_at_ms = collected_at_ms;
                    self.metrics_mut(mode).memory = Some(memory);
                    true
                }
                None => {
                    warnings.push("failed to parse /proc/meminfo".to_string());
                    false
                }
            },
            Err(error) => {
                warnings.push(format!("failed to read /proc/meminfo: {error}"));
                false
            }
        };
        (
            source_result(
                ResourceDimension::Memory,
                usize::from(collected),
                1,
                None,
                "/proc/meminfo could not be collected",
            ),
            collected,
        )
    }

    fn collect_disk(
        &mut self,
        mode: CollectionMode,
        collected_at_ms: u64,
        warnings: &mut Vec<String>,
    ) -> (DimensionCollectionResult, bool) {
        let mut rate_status = None;
        let diskstats_collected = match fs::read_to_string(self.proc_root.join("diskstats")) {
            Ok(content) => {
                let mut devices = parse_diskstats(&content);
                if devices.is_empty() {
                    warnings.push("/proc/diskstats contained no valid device rows".to_string());
                    false
                } else {
                    rate_status = Some(apply_disk_deltas(
                        &mut devices,
                        &self.metrics(mode).disk_devices,
                        collected_at_ms,
                    ));
                    self.metrics_mut(mode).disk_devices = devices;
                    true
                }
            }
            Err(error) => {
                warnings.push(format!("failed to read /proc/diskstats: {error}"));
                false
            }
        };

        let usage_collected = match self.partition_usage.read_df_output() {
            Ok(content) => {
                let mut disks = parse_df_output(&content);
                if disks.is_empty() {
                    warnings.push("df -P -B1 contained no valid partition rows".to_string());
                    false
                } else {
                    for disk in &mut disks {
                        disk.collected_at_ms = collected_at_ms;
                    }
                    self.metrics_mut(mode).disks = disks;
                    true
                }
            }
            Err(error) => {
                warnings.push(format!("failed to collect partition usage: {error}"));
                false
            }
        };
        (
            source_result(
                ResourceDimension::Disk,
                diskstats_collected as usize + usage_collected as usize,
                2,
                rate_status,
                "disk counters or partition usage could not be collected",
            ),
            usage_collected,
        )
    }

    fn collect_network_metrics(
        &mut self,
        mode: CollectionMode,
        collected_at_ms: u64,
        warnings: &mut Vec<String>,
    ) -> DimensionCollectionResult {
        let mut connection_sources_collected = false;
        let mut rate_status = None;
        let dev_collected = match fs::read_to_string(self.proc_root.join("net/dev")) {
            Ok(content) => {
                let mut interfaces = parse_net_dev(&content);
                if interfaces.is_empty() {
                    warnings.push("/proc/net/dev contained no valid interfaces".to_string());
                    return source_result(
                        ResourceDimension::Network,
                        0,
                        2,
                        None,
                        "network counters or connection tables could not be collected",
                    );
                }
                let previous = self
                    .metrics(mode)
                    .network
                    .as_ref()
                    .map(|network| network.interfaces.as_slice())
                    .unwrap_or_default();
                rate_status = Some(apply_network_deltas(
                    &mut interfaces,
                    previous,
                    collected_at_ms,
                ));
                let (connection_count, connections_available) =
                    count_network_connections(&self.proc_root, warnings);
                connection_sources_collected = connections_available;
                self.metrics_mut(mode).network = Some(NetworkMetricsSnapshot {
                    collected_at_ms,
                    connection_count,
                    interfaces,
                });
                true
            }
            Err(error) => {
                warnings.push(format!("failed to read /proc/net/dev: {error}"));
                false
            }
        };
        source_result(
            ResourceDimension::Network,
            dev_collected as usize + connection_sources_collected as usize,
            2,
            rate_status,
            "network counters or connection tables could not be collected",
        )
    }

    fn metrics(&self, mode: CollectionMode) -> &MetricsState {
        match mode {
            CollectionMode::OnDemand => &self.metrics.on_demand,
            CollectionMode::Scheduled => &self.metrics.scheduled,
        }
    }

    fn metrics_mut(&mut self, mode: CollectionMode) -> &mut MetricsState {
        match mode {
            CollectionMode::OnDemand => &mut self.metrics.on_demand,
            CollectionMode::Scheduled => &mut self.metrics.scheduled,
        }
    }

    pub fn collect_processes(&mut self, query: &ProcessQuery) -> Result<ProcessList> {
        query.validate_for_collection(self.process_baseline.is_some())?;
        Ok(self.collect_processes_unchecked(query))
    }

    #[cfg(test)]
    fn collect_processes_for_test(&mut self, query: &ProcessQuery) -> ProcessList {
        self.collect_processes(query)
            .expect("valid process collection test query")
    }

    fn collect_processes_unchecked(&mut self, query: &ProcessQuery) -> ProcessList {
        let scan_started_at_ms = self.clock.now_ms();
        let scan_started_at_monotonic_ms = self.process_clock.now_ms();
        self.process_scan_id = self.process_scan_id.wrapping_add(1);
        if self.process_scan_id == 0 {
            self.process_cpu_baselines.clear();
            self.process_cpu_baseline_order.clear();
            self.process_anomaly_states.clear();
            self.process_anomaly_state_order.clear();
            self.process_scan_id = 1;
        }
        let process_scan_id = self.process_scan_id;
        prune_process_cpu_baselines(
            &mut self.process_cpu_baselines,
            &mut self.process_cpu_baseline_order,
            scan_started_at_monotonic_ms,
            PROCESS_BASELINE_TTL_MS,
            MAX_PROCESS_BASELINES,
        );
        prune_process_anomaly_states(
            &mut self.process_anomaly_states,
            &mut self.process_anomaly_state_order,
            scan_started_at_monotonic_ms,
            PROCESS_ANOMALY_STATE_TTL_MS,
            MAX_PROCESS_ANOMALY_STATES,
        );
        let mut warnings = self.process_system_warnings.clone();
        let platform = self.platform_info(&mut warnings);
        let mut omitted_warning_count = warnings.len().saturating_sub(MAX_PROCESS_WARNINGS);
        warnings.truncate(MAX_PROCESS_WARNINGS);
        let mut source_partial = !warnings.is_empty() || omitted_warning_count > 0;
        let uptime = match fs::read_to_string(self.proc_root.join("uptime")) {
            Ok(content) => match content
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<f64>().ok())
                .filter(|value| value.is_finite() && *value >= 0.0)
            {
                Some(value) => Some(value),
                None => {
                    source_partial = true;
                    push_process_warning(
                        &mut warnings,
                        &mut omitted_warning_count,
                        "failed to parse /proc/uptime for process uptime".to_string(),
                    );
                    None
                }
            },
            Err(error) => {
                source_partial = true;
                push_process_warning(
                    &mut warnings,
                    &mut omitted_warning_count,
                    format!("failed to read /proc/uptime for process uptime: {error}"),
                );
                None
            }
        };
        let total_memory_kb = match fs::read_to_string(self.proc_root.join("meminfo")) {
            Ok(content) => match parse_meminfo(&content)
                .map(|memory| memory.total_kb)
                .filter(|total| *total > 0)
            {
                Some(total) => Some(total),
                None => {
                    source_partial = true;
                    push_process_warning(
                        &mut warnings,
                        &mut omitted_warning_count,
                        "failed to parse MemTotal from /proc/meminfo".to_string(),
                    );
                    None
                }
            },
            Err(error) => {
                source_partial = true;
                push_process_warning(
                    &mut warnings,
                    &mut omitted_warning_count,
                    format!("failed to read /proc/meminfo for process memory usage: {error}"),
                );
                None
            }
        };
        let configured_baseline = self.process_baseline.clone();
        let legacy_allowed_names = query
            .allowed_names
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let effective_baseline = EffectiveProcessBaseline {
            configured: configured_baseline.as_ref(),
            legacy_names: &legacy_allowed_names,
        };

        let mut candidates = BTreeMap::new();
        let mut bounded_anomalies = BTreeMap::new();
        let mut bounded_unauthorized = BTreeMap::new();
        let mut total = 0usize;
        let mut anomaly_count = 0usize;
        let mut unauthorized_total = 0usize;
        let mut authorization_indeterminate_count = 0usize;
        let mut partial_process_count = 0usize;
        let mut indeterminate_filter_count = 0usize;
        let mut remaining_nss_lookups = MAX_NSS_LOOKUPS_PER_COLLECTION;
        let mut failed_process_count = 0;
        let mut exited_during_scan_count = 0;
        let mut scan_failed = false;
        let mut filter_incomplete = false;
        match fs::read_dir(&self.proc_root) {
            Ok(entries) => {
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            source_partial = true;
                            filter_incomplete = true;
                            push_process_warning(
                                &mut warnings,
                                &mut omitted_warning_count,
                                format!("failed to enumerate a /proc process entry: {error}"),
                            );
                            continue;
                        }
                    };
                    let Some(pid) = entry
                        .file_name()
                        .to_str()
                        .and_then(|name| name.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    match self.read_process(pid, uptime) {
                        Ok(outcome) => {
                            let ProcessReadOutcome {
                                mut process,
                                sampled_at_ms,
                                status_available,
                                cmdline_available,
                                warnings: read_warnings,
                            } = outcome;
                            apply_process_cpu_rate(
                                &mut process,
                                self.process_cpu_baselines.get(&pid).copied(),
                                sampled_at_ms,
                                self.process_system_parameters.clock_ticks_per_second,
                            );
                            insert_process_cpu_baseline(
                                &mut self.process_cpu_baselines,
                                &mut self.process_cpu_baseline_order,
                                pid,
                                ProcessCpuBaseline {
                                    start_time_jiffies: process.start_time_jiffies,
                                    cpu_time_jiffies: process.cpu_time_jiffies,
                                    sampled_at_ms,
                                    scan_id: process_scan_id,
                                },
                                MAX_PROCESS_BASELINES,
                            );
                            let mut anomalies = update_bounded_process_anomaly_state(
                                &mut self.process_anomaly_states,
                                &mut self.process_anomaly_state_order,
                                &process,
                                sampled_at_ms,
                                MAX_PROCESS_ANOMALY_STATES,
                            );
                            if let Some(state) = self.process_anomaly_states.get_mut(&pid) {
                                state.scan_id = process_scan_id;
                            }
                            anomalies.append(&mut process.anomalies);
                            process.anomalies = anomalies;
                            process.memory_percent = process
                                .memory_rss_kb
                                .zip(total_memory_kb)
                                .map(|(rss, total)| round2((rss as f64 / total as f64) * 100.0));
                            match evaluate_process_authorization(
                                self.process_file_reader.as_ref(),
                                &self.proc_root,
                                &mut process,
                                status_available,
                                &effective_baseline,
                                self.process_system_parameters,
                            ) {
                                ProcessAuthorizationDecision::Inactive => {}
                                ProcessAuthorizationDecision::Authorized => {
                                    process.authorized = Some(true);
                                }
                                ProcessAuthorizationDecision::Unauthorized => {
                                    process.authorized = Some(false);
                                    process.anomalies.push(unauthorized_process_anomaly(
                                        &process,
                                        &effective_baseline,
                                    ));
                                }
                                ProcessAuthorizationDecision::Indeterminate(reason) => {
                                    process.authorized = None;
                                    filter_incomplete = true;
                                    authorization_indeterminate_count =
                                        authorization_indeterminate_count.saturating_add(1);
                                    push_process_warning(
                                        &mut warnings,
                                        &mut omitted_warning_count,
                                        format!(
                                            "authorization for process {} is indeterminate; {reason}",
                                            process.pid
                                        ),
                                    );
                                }
                            }
                            match process_matches_without_user(
                                &process,
                                query,
                                status_available,
                                cmdline_available,
                            ) {
                                ProcessFilterDecision::Matches => {}
                                ProcessFilterDecision::DoesNotMatch => continue,
                                ProcessFilterDecision::Indeterminate(reason) => {
                                    filter_incomplete = true;
                                    indeterminate_filter_count =
                                        indeterminate_filter_count.saturating_add(1);
                                    push_process_warning(
                                        &mut warnings,
                                        &mut omitted_warning_count,
                                        format!(
                                            "process filter for process {} is indeterminate because {reason}; candidate omitted",
                                            process.pid
                                        ),
                                    );
                                    continue;
                                }
                            }

                            let mut candidate_warnings = read_warnings;
                            if let Some(expected_user) = &query.user {
                                let Some(uid) = process.uid.filter(|_| status_available) else {
                                    filter_incomplete = true;
                                    indeterminate_filter_count =
                                        indeterminate_filter_count.saturating_add(1);
                                    push_process_warning(
                                        &mut warnings,
                                        &mut omitted_warning_count,
                                        format!(
                                            "user filter for process {} is indeterminate because UID is unavailable; candidate omitted",
                                            process.pid
                                        ),
                                    );
                                    continue;
                                };
                                let resolution =
                                    self.resolve_process_user(uid, &mut remaining_nss_lookups);
                                let matches = resolution.user == *expected_user;
                                process.user = Some(resolution.user);
                                if !resolution.definitive {
                                    filter_incomplete = true;
                                    indeterminate_filter_count =
                                        indeterminate_filter_count.saturating_add(1);
                                    push_process_warning(
                                        &mut warnings,
                                        &mut omitted_warning_count,
                                        format!(
                                            "user filter for process {} is indeterminate; candidate omitted: {}",
                                            process.pid,
                                            resolution.warning.as_deref().unwrap_or(
                                                "user resolution did not produce a definitive result"
                                            )
                                        ),
                                    );
                                    continue;
                                }
                                if !matches {
                                    continue;
                                }
                                if let Some(warning) = resolution.warning {
                                    candidate_warnings.push(warning);
                                }
                            }
                            record_process_candidate(
                                &mut candidates,
                                &mut bounded_anomalies,
                                &mut bounded_unauthorized,
                                &mut total,
                                &mut anomaly_count,
                                &mut unauthorized_total,
                                &mut partial_process_count,
                                &mut warnings,
                                &mut omitted_warning_count,
                                process,
                                candidate_warnings,
                                MAX_PROCESS_LIMIT,
                                MAX_PROCESS_LIST_ANOMALIES,
                                MAX_UNAUTHORIZED_PROCESS_SUMMARY,
                            );
                        }
                        Err(ProcessReadFailure::Exited) => {
                            filter_incomplete = true;
                            remove_process_cpu_baseline(
                                &mut self.process_cpu_baselines,
                                &mut self.process_cpu_baseline_order,
                                pid,
                            );
                            remove_process_anomaly_state(
                                &mut self.process_anomaly_states,
                                &mut self.process_anomaly_state_order,
                                pid,
                            );
                            exited_during_scan_count += 1;
                        }
                        Err(ProcessReadFailure::Failed(error)) => {
                            filter_incomplete = true;
                            remove_process_cpu_baseline(
                                &mut self.process_cpu_baselines,
                                &mut self.process_cpu_baseline_order,
                                pid,
                            );
                            remove_process_anomaly_state(
                                &mut self.process_anomaly_states,
                                &mut self.process_anomaly_state_order,
                                pid,
                            );
                            failed_process_count += 1;
                            push_process_warning(
                                &mut warnings,
                                &mut omitted_warning_count,
                                format!("failed to read process {pid}: {error}"),
                            );
                        }
                    }
                }
            }
            Err(error) => {
                scan_failed = true;
                filter_incomplete = true;
                push_process_warning(
                    &mut warnings,
                    &mut omitted_warning_count,
                    format!("failed to read /proc process list: {error}"),
                );
            }
        }
        if !scan_failed {
            retain_process_cpu_baselines_for_scan(
                &mut self.process_cpu_baselines,
                &mut self.process_cpu_baseline_order,
                process_scan_id,
            );
            retain_process_anomaly_states_for_scan(
                &mut self.process_anomaly_states,
                &mut self.process_anomaly_state_order,
                process_scan_id,
            );
        }
        let anomalies = bounded_anomalies.into_values().collect::<Vec<_>>();
        let omitted_anomaly_count = anomaly_count.saturating_sub(anomalies.len());
        let anomalies_truncated = omitted_anomaly_count > 0;

        let limit = query
            .limit
            .unwrap_or(DEFAULT_PROCESS_LIMIT)
            .min(MAX_PROCESS_LIMIT);
        let truncated = total > limit;
        truncate_process_candidates(&mut candidates, limit);

        if query.user.is_none() {
            for candidate in candidates.values_mut() {
                let Some(uid) = candidate.process.uid else {
                    continue;
                };
                let resolution = self.resolve_process_user(uid, &mut remaining_nss_lookups);
                candidate.process.user = Some(resolution.user);
                if let Some(warning) = resolution.warning {
                    if !candidate.partial {
                        partial_process_count += 1;
                        candidate.partial = true;
                    }
                    push_process_warning(&mut warnings, &mut omitted_warning_count, warning);
                }
            }
        }

        let processes = candidates
            .into_iter()
            .map(|(_, candidate)| candidate.process)
            .collect::<Vec<_>>();
        let unauthorized = bounded_unauthorized.into_values().collect::<Vec<_>>();
        let omitted_unauthorized_count = unauthorized_total.saturating_sub(unauthorized.len());
        let unauthorized_truncated = omitted_unauthorized_count > 0;
        let collection_status = if scan_failed {
            CollectionStatus::Failed
        } else if source_partial
            || failed_process_count > 0
            || partial_process_count > 0
            || indeterminate_filter_count > 0
            || authorization_indeterminate_count > 0
            || exited_during_scan_count > 0
        {
            CollectionStatus::Partial
        } else {
            CollectionStatus::Complete
        };
        ProcessList {
            meta: OsSampleMeta {
                collected_at_ms: scan_started_at_ms,
                source: "procfs".to_string(),
                platform,
                warnings,
            },
            total,
            truncated,
            failed_process_count,
            partial_process_count,
            exited_during_scan_count,
            omitted_warning_count,
            scan_failed,
            collection_status,
            processes,
            anomalies,
            anomaly_count,
            anomalies_truncated,
            omitted_anomaly_count,
            indeterminate_filter_count,
            filter_complete: !filter_incomplete
                && !scan_failed
                && failed_process_count == 0
                && exited_during_scan_count == 0
                && indeterminate_filter_count == 0
                && authorization_indeterminate_count == 0,
            authorization_indeterminate_count,
            unauthorized_total,
            unauthorized_truncated,
            omitted_unauthorized_count,
            unauthorized,
        }
    }

    fn read_process(
        &self,
        pid: u32,
        uptime: Option<f64>,
    ) -> std::result::Result<ProcessReadOutcome, ProcessReadFailure> {
        let proc_dir = self.proc_root.join(pid.to_string());
        let stat = self
            .process_file_reader
            .read_to_string(&proc_dir.join("stat"))
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    ProcessReadFailure::Exited
                } else {
                    ProcessReadFailure::Failed(OsSenseError::Io(error.to_string()))
                }
            })?;
        let sampled_at_ms = self.process_clock.now_ms();
        let mut info = parse_process_stat(pid, &stat, uptime, self.process_system_parameters)
            .map_err(ProcessReadFailure::Failed)?;
        let mut read_warnings = Vec::new();
        let status_available = match self
            .process_file_reader
            .read_to_string(&proc_dir.join("status"))
        {
            Ok(status) => {
                apply_process_status(&mut info, &status);
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProcessReadFailure::Exited)
            }
            Err(error) => {
                read_warnings.push(format!("failed to read process {pid} status: {error}"));
                false
            }
        };
        let cmdline_available = match self.process_file_reader.read(&proc_dir.join("cmdline")) {
            Ok(bytes) => {
                let command = bytes
                    .split(|byte| *byte == 0)
                    .filter(|part| !part.is_empty())
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ");
                info.command = (!command.is_empty())
                    .then(|| redact_sensitive_text(&command, MAX_CMDLINE_CHARS));
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ProcessReadFailure::Exited)
            }
            Err(error) => {
                read_warnings.push(format!(
                    "failed to read process {pid} command line: {error}"
                ));
                false
            }
        };
        Ok(ProcessReadOutcome {
            process: info,
            sampled_at_ms,
            status_available,
            cmdline_available,
            warnings: read_warnings,
        })
    }

    fn resolve_process_user(
        &mut self,
        uid: u32,
        remaining_nss_lookups: &mut usize,
    ) -> CachedUserResolution {
        let now_ms = self.process_clock.now_ms();
        if let Some(cached) = self.process_user_cache.get(&uid) {
            let ttl_ms = if cached.positive {
                POSITIVE_USER_CACHE_TTL_MS
            } else {
                NEGATIVE_USER_CACHE_TTL_MS
            };
            if now_ms.saturating_sub(cached.cached_at_ms) < ttl_ms {
                return cached.clone();
            }
        }
        self.process_user_cache.remove(&uid);
        if let Some(user) = self
            .process_user_resolver
            .resolve_local(uid)
            .filter(|user| !user.is_empty())
        {
            let resolution = CachedUserResolution {
                user,
                warning: None,
                cached_at_ms: self.process_clock.now_ms(),
                positive: true,
                definitive: true,
            };
            self.process_user_cache.insert(uid, resolution.clone());
            enforce_process_user_cache_limit(
                &mut self.process_user_cache,
                MAX_PROCESS_USER_CACHE_ENTRIES,
            );
            return resolution;
        }
        if *remaining_nss_lookups == 0 {
            return CachedUserResolution {
                user: uid.to_string(),
                warning: Some(format!(
                    "NSS lookup budget exhausted for UID {uid}; using numeric UID"
                )),
                cached_at_ms: now_ms,
                positive: false,
                definitive: false,
            };
        }
        *remaining_nss_lookups -= 1;
        let resolution = match self.process_user_resolver.resolve(uid) {
            Ok(Some(user)) if !user.is_empty() => CachedUserResolution {
                user,
                warning: None,
                cached_at_ms: self.process_clock.now_ms(),
                positive: true,
                definitive: true,
            },
            Ok(_) => CachedUserResolution {
                user: uid.to_string(),
                warning: Some(format!(
                    "user lookup returned no NSS entry for UID {uid}; using numeric UID"
                )),
                cached_at_ms: self.process_clock.now_ms(),
                positive: false,
                definitive: true,
            },
            Err(error) => CachedUserResolution {
                user: uid.to_string(),
                warning: Some(format!(
                    "user lookup failed for UID {uid}; using numeric UID: {error}"
                )),
                cached_at_ms: self.process_clock.now_ms(),
                positive: false,
                definitive: false,
            },
        };
        self.process_user_cache.insert(uid, resolution.clone());
        enforce_process_user_cache_limit(
            &mut self.process_user_cache,
            MAX_PROCESS_USER_CACHE_ENTRIES,
        );
        resolution
    }

    fn platform_info(&self, warnings: &mut Vec<String>) -> PlatformInfo {
        let kernel_version = fs::read_to_string(self.proc_root.join("sys/kernel/osrelease"))
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let cpuinfo = fs::read_to_string(self.proc_root.join("cpuinfo")).unwrap_or_default();
        let cpu_model = cpuinfo
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                let key = key.trim().to_ascii_lowercase();
                (key.contains("model name") || key == "cpu").then(|| value.trim().to_string())
            })
            .filter(|value| !value.is_empty());
        let arch = std::env::consts::ARCH.to_string();
        let detected =
            arch.contains("loongarch") || cpuinfo.to_ascii_lowercase().contains("loongarch");
        let hwmon_root = self.sys_root.join("class/hwmon");
        let hwmon_paths = fs::read_dir(&hwmon_root)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.path().display().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|error| {
                if detected {
                    warnings.push(format!(
                        "LoongArch hardware monitor path unavailable at {}: {error}",
                        hwmon_root.display()
                    ));
                }
                Vec::new()
            });
        PlatformInfo {
            os: std::env::consts::OS.to_string(),
            arch,
            kernel_version,
            loongarch: LoongArchInfo {
                detected,
                cpu_model,
                hwmon_paths,
                hwmon_sensors: Vec::new(),
            },
        }
    }
}

fn collect_hwmon_sensors(
    root: &Path,
    warnings: &mut Vec<String>,
) -> (Vec<HwmonSensorReading>, bool) {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return (Vec::new(), root.exists()),
    };
    let mut device_paths = entries
        .flatten()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    device_paths.sort();

    let mut sensors = Vec::new();
    let mut transient_failure = false;
    for device_path in device_paths {
        let device = fs::read_to_string(device_path.join("name"))
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| {
                device_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or("hwmon")
                    .to_string()
            });
        let Ok(files) = fs::read_dir(&device_path) else {
            transient_failure = true;
            continue;
        };
        let mut input_paths = files
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(is_supported_hwmon_input)
            })
            .collect::<Vec<_>>();
        input_paths.sort();

        for input_path in input_paths {
            if sensors.len() >= MAX_HWMON_SENSORS {
                warnings.push(format!(
                    "hwmon sensor list was capped at {MAX_HWMON_SENSORS} entries"
                ));
                return (sensors, transient_failure);
            }
            let Some(sensor) = input_path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            let Ok(raw) = fs::read_to_string(&input_path) else {
                transient_failure = true;
                continue;
            };
            let Ok(value) = raw.trim().parse::<i64>() else {
                warnings.push(format!(
                    "failed to parse hwmon sensor {}",
                    input_path.display()
                ));
                transient_failure = true;
                continue;
            };
            let label_path = input_path.with_file_name(sensor.replace("_input", "_label"));
            let label = fs::read_to_string(label_path)
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            sensors.push(HwmonSensorReading {
                device: device.clone(),
                unit: hwmon_unit(&sensor).to_string(),
                sensor,
                label,
                value,
                path: input_path.display().to_string(),
            });
        }
    }
    (sensors, transient_failure)
}

fn is_supported_hwmon_input(name: &str) -> bool {
    let Some(stem) = name.strip_suffix("_input") else {
        return false;
    };
    let digit_index = stem
        .char_indices()
        .find_map(|(index, ch)| ch.is_ascii_digit().then_some(index));
    let Some(digit_index) = digit_index else {
        return false;
    };
    let (kind, index) = stem.split_at(digit_index);
    matches!(
        kind,
        "temp" | "fan" | "in" | "curr" | "power" | "energy" | "humidity" | "freq"
    ) && !index.is_empty()
        && index.chars().all(|ch| ch.is_ascii_digit())
}

fn hwmon_unit(sensor: &str) -> &'static str {
    if sensor.starts_with("temp") {
        "millidegrees_celsius"
    } else if sensor.starts_with("fan") {
        "rpm"
    } else if sensor.starts_with("in") {
        "millivolts"
    } else if sensor.starts_with("curr") {
        "milliamps"
    } else if sensor.starts_with("power") {
        "microwatts"
    } else if sensor.starts_with("energy") {
        "microjoules"
    } else if sensor.starts_with("humidity") {
        "milli_percent"
    } else if sensor.starts_with("freq") {
        "hertz"
    } else {
        "raw"
    }
}

fn collect_thermal(
    sys_root: &Path,
    collected_at_ms: u64,
    warnings: &mut Vec<String>,
) -> (ThermalSnapshot, bool) {
    let mut temperatures = Vec::new();
    let mut transient_failure = false;
    let thermal_root = sys_root.join("class/thermal");
    let thermal_entries = fs::read_dir(&thermal_root);
    if thermal_entries.is_err() && thermal_root.exists() {
        transient_failure = true;
    }
    if let Ok(entries) = thermal_entries {
        let mut zones = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("thermal_zone"))
            })
            .collect::<Vec<_>>();
        zones.sort();
        for zone in zones {
            let temp_path = zone.join("temp");
            let Ok(raw) = fs::read_to_string(&temp_path) else {
                transient_failure |= temp_path.exists();
                continue;
            };
            let Ok(value) = raw.trim().parse::<i64>() else {
                warnings.push(format!(
                    "failed to parse thermal sensor {}",
                    temp_path.display()
                ));
                transient_failure = true;
                continue;
            };
            let label = fs::read_to_string(zone.join("type"))
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty());
            temperatures.push(TemperatureReading {
                source: "thermal_zone".to_string(),
                label,
                millidegrees_celsius: value,
                path: temp_path.display().to_string(),
            });
        }
    }

    let mut fans = Vec::new();
    let hwmon_root = sys_root.join("class/hwmon");
    let (hwmon_sensors, hwmon_transient_failure) = collect_hwmon_sensors(&hwmon_root, warnings);
    transient_failure |= hwmon_transient_failure;
    for sensor in &hwmon_sensors {
        if sensor.sensor.starts_with("temp") {
            temperatures.push(TemperatureReading {
                source: sensor.device.clone(),
                label: sensor.label.clone(),
                millidegrees_celsius: sensor.value,
                path: sensor.path.clone(),
            });
        } else if sensor.sensor.starts_with("fan") {
            if let Ok(rpm) = u64::try_from(sensor.value) {
                fans.push(FanReading {
                    source: sensor.device.clone(),
                    label: sensor.label.clone(),
                    rpm,
                    path: sensor.path.clone(),
                });
            } else {
                transient_failure = true;
            }
        }
    }
    let thermal_zone_available = temperatures
        .iter()
        .any(|reading| reading.source == "thermal_zone");
    let hwmon_available = !hwmon_sensors.is_empty();
    let availability = if thermal_zone_available || hwmon_available {
        SensorAvailability::Available
    } else {
        SensorAvailability::Unavailable
    };

    (
        ThermalSnapshot {
            collected_at_ms,
            availability,
            thermal_zone_available,
            hwmon_available,
            hwmon_sensors,
            temperatures,
            fans,
        },
        transient_failure,
    )
}

#[must_use]
pub fn collect_metrics(thresholds: &MetricsThresholds) -> MetricSnapshot {
    ProcfsCollector::default().collect_metrics(thresholds)
}

#[must_use]
pub fn collect_processes(query: &ProcessQuery) -> Result<ProcessList> {
    let mut collector = ProcfsCollector::default();
    collector.collect_processes(query)
}

#[must_use]
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[must_use]
pub(crate) fn basic_meta(source: &str, warnings: Vec<String>) -> OsSampleMeta {
    let collector = ProcfsCollector::default();
    let mut platform_warnings = Vec::new();
    let platform = collector.platform_info(&mut platform_warnings);
    let mut all_warnings = warnings;
    all_warnings.extend(platform_warnings);
    OsSampleMeta {
        collected_at_ms: now_ms(),
        source: source.to_string(),
        platform,
        warnings: all_warnings,
    }
}

#[must_use]
pub fn parse_cpu_stat(content: &str) -> Option<CpuSnapshot> {
    let mut cpu_lines = content.lines().filter(|line| line.starts_with("cpu"));
    let aggregate = parse_cpu_line(cpu_lines.next()?)?;
    if aggregate.name != "cpu" {
        return None;
    }
    let cores = cpu_lines.filter_map(parse_cpu_line).collect::<Vec<_>>();
    Some(CpuSnapshot {
        collected_at_ms: 0,
        sample_interval_ms: None,
        usage_percent: None,
        total_jiffies: aggregate.total_jiffies,
        idle_jiffies: aggregate.idle_jiffies,
        cpu_count: cores.len(),
        cores,
    })
}

fn parse_cpu_line(line: &str) -> Option<CpuCoreSnapshot> {
    let mut parts = line.split_whitespace();
    let name = parts.next()?.to_string();
    let values = parts
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    if values.len() < 4 {
        return None;
    }
    let idle_jiffies =
        values.get(3).copied().unwrap_or_default() + values.get(4).copied().unwrap_or_default();
    Some(CpuCoreSnapshot {
        name,
        usage_percent: None,
        total_jiffies: values.iter().sum(),
        idle_jiffies,
    })
}

fn apply_cpu_delta(current: &mut CpuSnapshot, previous: Option<&CpuSnapshot>) -> RateStatus {
    let Some(previous) = previous else {
        return RateStatus::WarmingUp;
    };
    let Some(elapsed_ms) = current
        .collected_at_ms
        .checked_sub(previous.collected_at_ms)
    else {
        return RateStatus::CounterReset;
    };
    if elapsed_ms == 0 {
        return RateStatus::WarmingUp;
    }
    current.sample_interval_ms = Some(elapsed_ms);
    let counters_reset = current.total_jiffies < previous.total_jiffies
        || current.idle_jiffies < previous.idle_jiffies;
    current.usage_percent = cpu_usage_percent(
        current.total_jiffies,
        current.idle_jiffies,
        previous.total_jiffies,
        previous.idle_jiffies,
    );
    let mut warming_up = current.usage_percent.is_none() && !counters_reset;
    let mut counters_reset = counters_reset;
    for core in &mut current.cores {
        if let Some(previous_core) = previous.cores.iter().find(|item| item.name == core.name) {
            if core.total_jiffies < previous_core.total_jiffies
                || core.idle_jiffies < previous_core.idle_jiffies
            {
                counters_reset = true;
            }
            core.usage_percent = cpu_usage_percent(
                core.total_jiffies,
                core.idle_jiffies,
                previous_core.total_jiffies,
                previous_core.idle_jiffies,
            );
            warming_up |= core.usage_percent.is_none() && !counters_reset;
        } else {
            warming_up = true;
        }
    }
    if counters_reset {
        RateStatus::CounterReset
    } else if warming_up {
        RateStatus::WarmingUp
    } else {
        RateStatus::Ready
    }
}

fn cpu_usage_percent(
    total: u64,
    idle: u64,
    previous_total: u64,
    previous_idle: u64,
) -> Option<f64> {
    let total_delta = total.checked_sub(previous_total)?;
    let idle_delta = idle.checked_sub(previous_idle)?;
    (total_delta > 0).then(|| {
        let busy_delta = total_delta.saturating_sub(idle_delta);
        round2((busy_delta as f64 / total_delta as f64) * 100.0)
    })
}

#[must_use]
pub fn parse_meminfo(content: &str) -> Option<MemorySnapshot> {
    let values = content
        .lines()
        .filter_map(|line| {
            let (key, rest) = line.split_once(':')?;
            let value = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            Some((key.to_string(), value))
        })
        .collect::<BTreeMap<_, _>>();
    let total = *values.get("MemTotal")?;
    let available = values
        .get("MemAvailable")
        .copied()
        .or_else(|| values.get("MemFree").copied())
        .unwrap_or_default();
    let used = total.saturating_sub(available);
    let used_percent = (total > 0).then(|| round2((used as f64 / total as f64) * 100.0));
    let buffers = values.get("Buffers").copied().unwrap_or_default();
    let cached = values
        .get("Cached")
        .copied()
        .unwrap_or_default()
        .saturating_add(values.get("SReclaimable").copied().unwrap_or_default())
        .saturating_sub(values.get("Shmem").copied().unwrap_or_default());
    let swap_total = values.get("SwapTotal").copied().unwrap_or_default();
    let swap_free = values.get("SwapFree").copied().unwrap_or_default();
    Some(MemorySnapshot {
        collected_at_ms: 0,
        total_kb: total,
        available_kb: available,
        used_kb: used,
        used_percent,
        buffers_kb: buffers,
        cached_kb: cached,
        swap_total_kb: swap_total,
        swap_free_kb: swap_free,
        swap_used_kb: swap_total.saturating_sub(swap_free),
    })
}

#[must_use]
pub fn parse_loadavg(content: &str) -> Option<LoadAverage> {
    let parts = content.split_whitespace().collect::<Vec<_>>();
    let task_counts = parts.get(3).and_then(|tasks| {
        let (runnable, total) = tasks.split_once('/')?;
        Some((runnable.parse().ok()?, total.parse().ok()?))
    });
    Some(LoadAverage {
        one: parts.first()?.parse().ok()?,
        five: parts.get(1)?.parse().ok()?,
        fifteen: parts.get(2)?.parse().ok()?,
        runnable_tasks: task_counts.map(|(runnable, _)| runnable),
        total_tasks: task_counts.map(|(_, total)| total),
        last_pid: parts.get(4).and_then(|part| part.parse().ok()),
    })
}

#[must_use]
pub fn parse_df_output(content: &str) -> Vec<DiskSnapshot> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 6 {
                return None;
            }
            let total_bytes = parts.get(1)?.parse::<u64>().ok();
            let used_bytes = parts.get(2)?.parse::<u64>().ok();
            let available_bytes = parts.get(3)?.parse::<u64>().ok();
            let used_percent = parts
                .get(4)
                .and_then(|value| value.trim_end_matches('%').parse::<f64>().ok());
            Some(DiskSnapshot {
                collected_at_ms: 0,
                filesystem: parts[0].to_string(),
                total_bytes,
                used_bytes,
                available_bytes,
                used_percent,
                mount_point: parts[5..].join(" "),
            })
        })
        .collect()
}

#[must_use]
pub fn parse_diskstats(content: &str) -> Vec<DiskDeviceSnapshot> {
    content
        .lines()
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 14 {
                return None;
            }
            Some(DiskDeviceSnapshot {
                name: parts.get(2)?.to_string(),
                reads_completed_total: parts.get(3)?.parse().ok()?,
                sectors_read_total: parts.get(5)?.parse().ok()?,
                writes_completed_total: parts.get(7)?.parse().ok()?,
                sectors_written_total: parts.get(9)?.parse().ok()?,
                io_in_progress: parts.get(11)?.parse().ok()?,
                ..DiskDeviceSnapshot::default()
            })
        })
        .collect()
}

fn apply_disk_deltas(
    current: &mut [DiskDeviceSnapshot],
    previous: &[DiskDeviceSnapshot],
    collected_at_ms: u64,
) -> RateStatus {
    let mut warming_up = previous.is_empty();
    let mut counters_reset = false;
    for device in current {
        device.collected_at_ms = collected_at_ms;
        let Some(previous) = previous.iter().find(|item| item.name == device.name) else {
            warming_up = true;
            continue;
        };
        let Some(elapsed_ms) = collected_at_ms.checked_sub(previous.collected_at_ms) else {
            counters_reset = true;
            continue;
        };
        if elapsed_ms == 0 {
            warming_up = true;
            continue;
        }
        device.sample_interval_ms = Some(elapsed_ms);
        counters_reset |= device.reads_completed_total < previous.reads_completed_total
            || device.writes_completed_total < previous.writes_completed_total
            || device.sectors_read_total < previous.sectors_read_total
            || device.sectors_written_total < previous.sectors_written_total;
        device.read_iops = counter_rate(
            device.reads_completed_total,
            previous.reads_completed_total,
            elapsed_ms,
            1,
        );
        device.write_iops = counter_rate(
            device.writes_completed_total,
            previous.writes_completed_total,
            elapsed_ms,
            1,
        );
        device.read_bytes_per_sec = counter_rate(
            device.sectors_read_total,
            previous.sectors_read_total,
            elapsed_ms,
            DISK_SECTOR_BYTES,
        );
        device.write_bytes_per_sec = counter_rate(
            device.sectors_written_total,
            previous.sectors_written_total,
            elapsed_ms,
            DISK_SECTOR_BYTES,
        );
    }
    if counters_reset {
        RateStatus::CounterReset
    } else if warming_up {
        RateStatus::WarmingUp
    } else {
        RateStatus::Ready
    }
}

#[must_use]
pub fn parse_net_dev(content: &str) -> Vec<NetworkInterfaceSnapshot> {
    content
        .lines()
        .skip(2)
        .filter_map(|line| {
            let (name, counters) = line.split_once(':')?;
            let values = counters
                .split_whitespace()
                .map(|value| value.parse::<u64>().ok())
                .collect::<Option<Vec<_>>>()?;
            if values.len() < 16 {
                return None;
            }
            Some(NetworkInterfaceSnapshot {
                name: name.trim().to_string(),
                receive_bytes_total: values[0],
                receive_packets_total: values[1],
                receive_errors_total: values[2],
                receive_dropped_total: values[3],
                transmit_bytes_total: values[8],
                transmit_packets_total: values[9],
                transmit_errors_total: values[10],
                transmit_dropped_total: values[11],
                ..NetworkInterfaceSnapshot::default()
            })
        })
        .collect()
}

fn apply_network_deltas(
    current: &mut [NetworkInterfaceSnapshot],
    previous: &[NetworkInterfaceSnapshot],
    collected_at_ms: u64,
) -> RateStatus {
    let mut warming_up = previous.is_empty();
    let mut counters_reset = false;
    for interface in current {
        interface.collected_at_ms = collected_at_ms;
        let Some(previous) = previous.iter().find(|item| item.name == interface.name) else {
            warming_up = true;
            continue;
        };
        let Some(elapsed_ms) = collected_at_ms.checked_sub(previous.collected_at_ms) else {
            counters_reset = true;
            continue;
        };
        if elapsed_ms == 0 {
            warming_up = true;
            continue;
        }
        interface.sample_interval_ms = Some(elapsed_ms);
        counters_reset |= interface.receive_bytes_total < previous.receive_bytes_total
            || interface.receive_packets_total < previous.receive_packets_total
            || interface.transmit_bytes_total < previous.transmit_bytes_total
            || interface.transmit_packets_total < previous.transmit_packets_total;
        interface.receive_bytes_per_sec = counter_rate(
            interface.receive_bytes_total,
            previous.receive_bytes_total,
            elapsed_ms,
            1,
        );
        interface.transmit_bytes_per_sec = counter_rate(
            interface.transmit_bytes_total,
            previous.transmit_bytes_total,
            elapsed_ms,
            1,
        );
        interface.receive_packets_per_sec = counter_rate(
            interface.receive_packets_total,
            previous.receive_packets_total,
            elapsed_ms,
            1,
        );
        interface.transmit_packets_per_sec = counter_rate(
            interface.transmit_packets_total,
            previous.transmit_packets_total,
            elapsed_ms,
            1,
        );
    }
    if counters_reset {
        RateStatus::CounterReset
    } else if warming_up {
        RateStatus::WarmingUp
    } else {
        RateStatus::Ready
    }
}

fn counter_rate(current: u64, previous: u64, elapsed_ms: u64, scale: u64) -> Option<f64> {
    let delta = current.checked_sub(previous)?;
    (elapsed_ms > 0).then(|| round2((delta as f64 * scale as f64 * 1_000.0) / elapsed_ms as f64))
}

fn count_network_connections(proc_root: &Path, warnings: &mut Vec<String>) -> (usize, bool) {
    let mut available_sources = 0;
    let count = ["net/tcp", "net/tcp6", "net/udp", "net/udp6"]
        .into_iter()
        .map(|relative_path| {
            let path = proc_root.join(relative_path);
            match fs::read_to_string(&path) {
                Ok(content) => {
                    available_sources += 1;
                    content
                        .lines()
                        .skip(1)
                        .filter(|line| !line.trim().is_empty())
                        .count()
                }
                Err(error) => {
                    warnings.push(format!("failed to read /proc/{relative_path}: {error}"));
                    0
                }
            }
        })
        .sum();
    (count, available_sources == 4)
}

fn source_result(
    dimension: ResourceDimension,
    collected_sources: usize,
    expected_sources: usize,
    rate_status: Option<RateStatus>,
    failure_message: &str,
) -> DimensionCollectionResult {
    let source_status = if collected_sources == expected_sources {
        CollectionStatus::Complete
    } else if collected_sources == 0 {
        CollectionStatus::Failed
    } else {
        CollectionStatus::Partial
    };
    let status = if source_status == CollectionStatus::Complete
        && rate_status.is_some_and(|status| status != RateStatus::Ready)
    {
        CollectionStatus::Partial
    } else {
        source_status
    };
    let message = if source_status != CollectionStatus::Complete {
        Some(failure_message.to_string())
    } else {
        match rate_status {
            Some(RateStatus::WarmingUp) => Some("rate baseline is warming up".to_string()),
            Some(RateStatus::CounterReset) => {
                Some("counter reset detected; rate was not calculated".to_string())
            }
            _ => None,
        }
    };
    DimensionCollectionResult {
        dimension,
        status,
        rate_status,
        retryable: source_status == CollectionStatus::Failed,
        message,
    }
}

fn collection_status(
    dimensions: &[ResourceDimension],
    results: &[DimensionCollectionResult],
) -> CollectionStatus {
    if dimensions.is_empty()
        || results.len() != dimensions.len()
        || results
            .iter()
            .all(|result| result.status == CollectionStatus::Failed)
    {
        return CollectionStatus::Failed;
    }
    if results
        .iter()
        .all(|result| result.status == CollectionStatus::Complete)
    {
        return CollectionStatus::Complete;
    }
    CollectionStatus::Partial
}

fn build_metric_alerts(
    cpu: &CpuSnapshot,
    memory: &MemorySnapshot,
    load: Option<&LoadAverage>,
    disks: &[DiskSnapshot],
    thresholds: &MetricsThresholds,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    if let (Some(value), Some(threshold)) = (cpu.usage_percent, thresholds.cpu_percent) {
        if value >= threshold {
            alerts.push(Alert {
                dimension: "cpu".to_string(),
                subject: Some("total".to_string()),
                severity: "warning".to_string(),
                message: format!("CPU usage {value:.2}% exceeds threshold {threshold:.2}%"),
                value,
                threshold,
            });
        }
    }
    if let (Some(value), Some(threshold)) = (memory.used_percent, thresholds.memory_percent) {
        if value >= threshold {
            alerts.push(Alert {
                dimension: "memory".to_string(),
                subject: Some("total".to_string()),
                severity: "warning".to_string(),
                message: format!("memory usage {value:.2}% exceeds threshold {threshold:.2}%"),
                value,
                threshold,
            });
        }
    }
    if let (Some(load), Some(threshold)) = (load, thresholds.load1) {
        if load.one >= threshold {
            alerts.push(Alert {
                dimension: "load".to_string(),
                subject: Some("1m".to_string()),
                severity: "warning".to_string(),
                message: format!("load1 {:.2} exceeds threshold {threshold:.2}", load.one),
                value: load.one,
                threshold,
            });
        }
    }
    if let Some(threshold) = thresholds.disk_percent {
        for disk in disks {
            if let Some(value) = disk.used_percent {
                if value >= threshold {
                    alerts.push(Alert {
                        dimension: "disk".to_string(),
                        subject: Some(disk.mount_point.clone()),
                        severity: "warning".to_string(),
                        message: format!(
                            "disk {} usage {value:.2}% exceeds threshold {threshold:.2}%",
                            disk.mount_point
                        ),
                        value,
                        threshold,
                    });
                }
            }
        }
    }
    alerts
}

fn parse_process_stat(
    pid: u32,
    stat: &str,
    uptime: Option<f64>,
    system: ProcessSystemParameters,
) -> Result<ProcessInfo> {
    let open = stat
        .find('(')
        .ok_or_else(|| OsSenseError::Parse("missing process name start".to_string()))?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| OsSenseError::Parse("missing process name end".to_string()))?;
    let name = stat[open + 1..close].to_string();
    let parts = stat[close + 1..].split_whitespace().collect::<Vec<_>>();
    if parts.len() < 22 {
        return Err(OsSenseError::Parse(
            "process stat has too few fields".to_string(),
        ));
    }
    let state = parts[0].to_string();
    let ppid = parts.get(1).and_then(|part| part.parse::<u32>().ok());
    let utime = parts
        .get(11)
        .and_then(|part| part.parse::<u64>().ok())
        .unwrap_or_default();
    let stime = parts
        .get(12)
        .and_then(|part| part.parse::<u64>().ok())
        .unwrap_or_default();
    let start_time_jiffies = parts
        .get(19)
        .and_then(|part| part.parse::<u64>().ok())
        .ok_or_else(|| OsSenseError::Parse("invalid process start time".to_string()))?;
    let virtual_memory_kb = parts
        .get(20)
        .and_then(|part| part.parse::<u64>().ok())
        .map(|bytes| bytes / 1024);
    let memory_rss_kb = parts
        .get(21)
        .and_then(|part| part.parse::<i64>().ok())
        .and_then(|pages| u64::try_from(pages).ok())
        .map(|pages| pages.saturating_mul(system.page_size_bytes) / 1024);
    let uptime_seconds = uptime.map(|uptime| {
        let started_after_boot =
            start_time_jiffies as f64 / system.clock_ticks_per_second.max(1) as f64;
        round2((uptime - started_after_boot).max(0.0))
    });

    Ok(ProcessInfo {
        pid,
        ppid,
        name,
        state,
        user: None,
        uid: None,
        cpu_time_jiffies: utime + stime,
        start_time_jiffies,
        cpu_usage_percent: None,
        cpu_sample_interval_ms: None,
        cpu_rate_status: None,
        memory_rss_kb,
        memory_percent: None,
        virtual_memory_kb,
        uptime_seconds,
        command: None,
        executable_path: None,
        anomalies: Vec::new(),
        authorized: None,
    })
}

fn apply_process_status(info: &mut ProcessInfo, status: &str) {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(uid) = rest.split_whitespace().next() {
                info.uid = uid.parse().ok();
            }
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            if let Some(kb) = rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
            {
                info.memory_rss_kb = Some(kb);
            }
        } else if let Some(rest) = line.strip_prefix("VmSize:") {
            if let Some(kb) = rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
            {
                info.virtual_memory_kb = Some(kb);
            }
        }
    }
}

fn update_process_anomaly_state(
    states: &mut BTreeMap<u32, ProcessAnomalyState>,
    info: &ProcessInfo,
    sampled_at_ms: u64,
) -> Vec<ProcessAnomaly> {
    let state = states.entry(info.pid).or_insert(ProcessAnomalyState {
        start_time_jiffies: info.start_time_jiffies,
        sampled_at_ms,
        scan_id: 0,
        memory_growth: None,
        cpu_busy: None,
    });
    if state.start_time_jiffies != info.start_time_jiffies {
        *state = ProcessAnomalyState {
            start_time_jiffies: info.start_time_jiffies,
            sampled_at_ms,
            scan_id: 0,
            memory_growth: None,
            cpu_busy: None,
        };
    }
    state.sampled_at_ms = sampled_at_ms;

    state.memory_growth = match (state.memory_growth, info.memory_rss_kb) {
        (Some(previous), Some(rss_kb)) if rss_kb >= previous.latest_rss_kb => {
            Some(MemoryGrowthState {
                latest_rss_kb: rss_kb,
                sample_count: previous.sample_count.saturating_add(1),
                ..previous
            })
        }
        (_, Some(rss_kb)) => Some(MemoryGrowthState {
            started_at_ms: sampled_at_ms,
            initial_rss_kb: rss_kb,
            latest_rss_kb: rss_kb,
            sample_count: 1,
        }),
        (_, None) => None,
    };

    let ready_high_cpu = info.cpu_usage_percent.filter(|usage| {
        info.cpu_rate_status == Some(RateStatus::Ready)
            && usage.is_finite()
            && *usage >= CPU_BUSY_LOOP_MIN_USAGE_PERCENT
    });
    state.cpu_busy = match (state.cpu_busy, ready_high_cpu) {
        (Some(previous), Some(usage)) => Some(CpuBusyState {
            minimum_usage_percent: previous.minimum_usage_percent.min(usage),
            latest_usage_percent: usage,
            sample_count: previous.sample_count.saturating_add(1),
            ..previous
        }),
        (_, Some(usage)) => Some(CpuBusyState {
            started_at_ms: sampled_at_ms,
            minimum_usage_percent: usage,
            latest_usage_percent: usage,
            sample_count: 1,
        }),
        (_, None) => None,
    };

    let mut anomalies = Vec::new();
    if info.state == "Z" {
        anomalies.push(ProcessAnomaly {
            pid: info.pid,
            kind: "zombie_process".to_string(),
            message: format!("process `{}` is in zombie state", info.name),
            score: 1.0,
            evidence: Some(ProcessAnomalyEvidence::ProcessState {
                state: "Z".to_string(),
            }),
        });
    }

    if let Some(memory) = state.memory_growth {
        let observed_duration_ms = sampled_at_ms.saturating_sub(memory.started_at_ms);
        let absolute_growth_kb = memory.latest_rss_kb.saturating_sub(memory.initial_rss_kb);
        let relative_growth_percent = if memory.initial_rss_kb == 0 {
            if memory.latest_rss_kb > 0 {
                100.0
            } else {
                0.0
            }
        } else {
            round2(absolute_growth_kb as f64 * 100.0 / memory.initial_rss_kb as f64)
        };
        if memory.sample_count >= PROCESS_PATTERN_MIN_SAMPLES
            && observed_duration_ms >= MEMORY_LEAK_MIN_DURATION_MS
            && absolute_growth_kb >= MEMORY_LEAK_MIN_ABSOLUTE_GROWTH_KB
            && relative_growth_percent >= MEMORY_LEAK_MIN_RELATIVE_GROWTH_PERCENT
        {
            anomalies.push(ProcessAnomaly {
                pid: info.pid,
                kind: "memory_leak_pattern".to_string(),
                message: format!(
                    "process `{}` RSS grew from {} kB to {} kB over {} ms across {} samples",
                    info.name,
                    memory.initial_rss_kb,
                    memory.latest_rss_kb,
                    observed_duration_ms,
                    memory.sample_count
                ),
                score: 0.9,
                evidence: Some(ProcessAnomalyEvidence::MemoryRss {
                    sample_count: memory.sample_count,
                    observed_duration_ms,
                    initial_rss_kb: memory.initial_rss_kb,
                    latest_rss_kb: memory.latest_rss_kb,
                    absolute_growth_kb,
                    relative_growth_percent,
                    minimum_duration_ms: MEMORY_LEAK_MIN_DURATION_MS,
                    minimum_absolute_growth_kb: MEMORY_LEAK_MIN_ABSOLUTE_GROWTH_KB,
                    minimum_relative_growth_percent: MEMORY_LEAK_MIN_RELATIVE_GROWTH_PERCENT,
                }),
            });
        }
    }

    if let Some(cpu) = state.cpu_busy {
        let observed_duration_ms = sampled_at_ms.saturating_sub(cpu.started_at_ms);
        if cpu.sample_count >= PROCESS_PATTERN_MIN_SAMPLES
            && observed_duration_ms >= CPU_BUSY_LOOP_MIN_DURATION_MS
        {
            anomalies.push(ProcessAnomaly {
                pid: info.pid,
                kind: "cpu_busy_loop".to_string(),
                message: format!(
                    "process `{}` sustained at least {:.2}% CPU for {} ms across {} samples",
                    info.name, cpu.minimum_usage_percent, observed_duration_ms, cpu.sample_count
                ),
                score: 0.9,
                evidence: Some(ProcessAnomalyEvidence::CpuUsage {
                    sample_count: cpu.sample_count,
                    observed_duration_ms,
                    minimum_usage_percent: cpu.minimum_usage_percent,
                    latest_usage_percent: cpu.latest_usage_percent,
                    minimum_duration_ms: CPU_BUSY_LOOP_MIN_DURATION_MS,
                    threshold_percent: CPU_BUSY_LOOP_MIN_USAGE_PERCENT,
                }),
            });
        }
    }

    anomalies
}

fn update_bounded_process_anomaly_state(
    states: &mut BTreeMap<u32, ProcessAnomalyState>,
    order: &mut BTreeSet<(u64, u32)>,
    info: &ProcessInfo,
    sampled_at_ms: u64,
    max_entries: usize,
) -> Vec<ProcessAnomaly> {
    if let Some(previous) = states.get(&info.pid) {
        order.remove(&(previous.sampled_at_ms, info.pid));
    }
    let anomalies = update_process_anomaly_state(states, info, sampled_at_ms);
    if let Some(state) = states.get(&info.pid) {
        order.insert((state.sampled_at_ms, info.pid));
    }
    enforce_process_anomaly_state_limit(states, order, max_entries);
    anomalies
}

fn apply_process_cpu_rate(
    process: &mut ProcessInfo,
    previous: Option<ProcessCpuBaseline>,
    sampled_at_ms: u64,
    clock_ticks_per_second: u64,
) {
    let Some(previous) = previous else {
        process.cpu_rate_status = Some(RateStatus::WarmingUp);
        return;
    };
    if previous.start_time_jiffies != process.start_time_jiffies {
        process.cpu_rate_status = Some(RateStatus::WarmingUp);
        return;
    }
    let interval_ms = sampled_at_ms.saturating_sub(previous.sampled_at_ms);
    process.cpu_sample_interval_ms = Some(interval_ms);
    if process.cpu_time_jiffies < previous.cpu_time_jiffies {
        process.cpu_rate_status = Some(RateStatus::CounterReset);
        return;
    }
    if interval_ms == 0 || clock_ticks_per_second == 0 {
        process.cpu_rate_status = Some(RateStatus::WarmingUp);
        process.cpu_sample_interval_ms = None;
        return;
    }
    let delta_jiffies = process.cpu_time_jiffies - previous.cpu_time_jiffies;
    process.cpu_usage_percent = Some(round2(
        delta_jiffies as f64 * 100_000.0 / (interval_ms as f64 * clock_ticks_per_second as f64),
    ));
    process.cpu_rate_status = Some(RateStatus::Ready);
}

fn prune_process_cpu_baselines(
    baselines: &mut BTreeMap<u32, ProcessCpuBaseline>,
    order: &mut BTreeSet<(u64, u32)>,
    now_ms: u64,
    ttl_ms: u64,
    max_entries: usize,
) {
    while let Some((sampled_at_ms, pid)) = order.iter().next().copied() {
        if now_ms.saturating_sub(sampled_at_ms) < ttl_ms {
            break;
        }
        remove_process_cpu_baseline(baselines, order, pid);
    }
    enforce_process_cpu_baseline_limit(baselines, order, max_entries);
}

fn insert_process_cpu_baseline(
    baselines: &mut BTreeMap<u32, ProcessCpuBaseline>,
    order: &mut BTreeSet<(u64, u32)>,
    pid: u32,
    baseline: ProcessCpuBaseline,
    max_entries: usize,
) {
    if let Some(previous) = baselines.get(&pid) {
        order.remove(&(previous.sampled_at_ms, pid));
    }
    order.insert((baseline.sampled_at_ms, pid));
    baselines.insert(pid, baseline);
    enforce_process_cpu_baseline_limit(baselines, order, max_entries);
}

fn remove_process_cpu_baseline(
    baselines: &mut BTreeMap<u32, ProcessCpuBaseline>,
    order: &mut BTreeSet<(u64, u32)>,
    pid: u32,
) -> Option<ProcessCpuBaseline> {
    let baseline = baselines.remove(&pid)?;
    order.remove(&(baseline.sampled_at_ms, pid));
    Some(baseline)
}

fn enforce_process_cpu_baseline_limit(
    baselines: &mut BTreeMap<u32, ProcessCpuBaseline>,
    order: &mut BTreeSet<(u64, u32)>,
    max_entries: usize,
) {
    while baselines.len() > max_entries {
        let Some((_, pid)) = order.iter().next().copied() else {
            break;
        };
        remove_process_cpu_baseline(baselines, order, pid);
    }
}

fn retain_process_cpu_baselines_for_scan(
    baselines: &mut BTreeMap<u32, ProcessCpuBaseline>,
    order: &mut BTreeSet<(u64, u32)>,
    scan_id: u64,
) {
    baselines.retain(|pid, baseline| {
        let retain = baseline.scan_id == scan_id;
        if !retain {
            order.remove(&(baseline.sampled_at_ms, *pid));
        }
        retain
    });
}

fn prune_process_anomaly_states(
    states: &mut BTreeMap<u32, ProcessAnomalyState>,
    order: &mut BTreeSet<(u64, u32)>,
    now_ms: u64,
    ttl_ms: u64,
    max_entries: usize,
) {
    while let Some((sampled_at_ms, pid)) = order.iter().next().copied() {
        if now_ms.saturating_sub(sampled_at_ms) < ttl_ms {
            break;
        }
        remove_process_anomaly_state(states, order, pid);
    }
    enforce_process_anomaly_state_limit(states, order, max_entries);
}

fn remove_process_anomaly_state(
    states: &mut BTreeMap<u32, ProcessAnomalyState>,
    order: &mut BTreeSet<(u64, u32)>,
    pid: u32,
) -> Option<ProcessAnomalyState> {
    let state = states.remove(&pid)?;
    order.remove(&(state.sampled_at_ms, pid));
    Some(state)
}

fn enforce_process_anomaly_state_limit(
    states: &mut BTreeMap<u32, ProcessAnomalyState>,
    order: &mut BTreeSet<(u64, u32)>,
    max_entries: usize,
) {
    while states.len() > max_entries {
        let Some((_, pid)) = order.iter().next().copied() else {
            break;
        };
        remove_process_anomaly_state(states, order, pid);
    }
}

fn retain_process_anomaly_states_for_scan(
    states: &mut BTreeMap<u32, ProcessAnomalyState>,
    order: &mut BTreeSet<(u64, u32)>,
    scan_id: u64,
) {
    states.retain(|pid, state| {
        let retain = state.scan_id == scan_id;
        if !retain {
            order.remove(&(state.sampled_at_ms, *pid));
        }
        retain
    });
}

#[allow(clippy::too_many_arguments)]
fn record_process_candidate(
    candidates: &mut BTreeMap<u32, ProcessCandidate>,
    bounded_anomalies: &mut BTreeMap<(u32, usize), ProcessAnomaly>,
    bounded_unauthorized: &mut BTreeMap<u32, ProcessInfo>,
    total: &mut usize,
    anomaly_count: &mut usize,
    unauthorized_total: &mut usize,
    partial_process_count: &mut usize,
    warnings: &mut Vec<String>,
    omitted_warning_count: &mut usize,
    process: ProcessInfo,
    process_warnings: Vec<String>,
    max_candidates: usize,
    max_anomalies: usize,
    max_unauthorized: usize,
) {
    *total = total.saturating_add(1);
    let partial = !process_warnings.is_empty();
    if partial {
        *partial_process_count = partial_process_count.saturating_add(1);
        for warning in process_warnings {
            push_process_warning(warnings, omitted_warning_count, warning);
        }
    }
    for (index, anomaly) in process.anomalies.iter().cloned().enumerate() {
        *anomaly_count = anomaly_count.saturating_add(1);
        bounded_anomalies.insert((process.pid, index), anomaly);
        while bounded_anomalies.len() > max_anomalies {
            let Some(key) = bounded_anomalies.keys().next_back().copied() else {
                break;
            };
            bounded_anomalies.remove(&key);
        }
    }
    if process.authorized == Some(false) {
        *unauthorized_total = unauthorized_total.saturating_add(1);
        let mut summary = process.clone();
        summary.command = None;
        bounded_unauthorized.insert(process.pid, summary);
        truncate_processes_by_pid(bounded_unauthorized, max_unauthorized);
    }
    candidates.insert(process.pid, ProcessCandidate { process, partial });
    truncate_process_candidates(candidates, max_candidates);
}

fn truncate_process_candidates(
    candidates: &mut BTreeMap<u32, ProcessCandidate>,
    max_candidates: usize,
) {
    while candidates.len() > max_candidates {
        let Some(pid) = candidates.keys().next_back().copied() else {
            break;
        };
        candidates.remove(&pid);
    }
}

fn truncate_processes_by_pid(processes: &mut BTreeMap<u32, ProcessInfo>, max_processes: usize) {
    while processes.len() > max_processes {
        let Some(pid) = processes.keys().next_back().copied() else {
            break;
        };
        processes.remove(&pid);
    }
}

fn enforce_process_user_cache_limit(
    cache: &mut BTreeMap<u32, CachedUserResolution>,
    max_entries: usize,
) {
    let remove_count = cache.len().saturating_sub(max_entries);
    if remove_count == 0 {
        return;
    }
    let mut oldest = cache
        .iter()
        .map(|(uid, resolution)| (resolution.cached_at_ms, *uid))
        .collect::<Vec<_>>();
    oldest.sort_unstable();
    for (_, uid) in oldest.into_iter().take(remove_count) {
        cache.remove(&uid);
    }
}

fn push_process_warning(
    warnings: &mut Vec<String>,
    omitted_warning_count: &mut usize,
    warning: String,
) {
    if warnings.len() < MAX_PROCESS_WARNINGS {
        warnings.push(warning);
    } else {
        *omitted_warning_count = omitted_warning_count.saturating_add(1);
    }
}

fn process_matches_without_user(
    process: &ProcessInfo,
    query: &ProcessQuery,
    status_available: bool,
    cmdline_available: bool,
) -> ProcessFilterDecision {
    if query.pid.is_some_and(|pid| process.pid != pid) {
        return ProcessFilterDecision::DoesNotMatch;
    }
    if query.ppid.is_some_and(|ppid| process.ppid != Some(ppid)) {
        return ProcessFilterDecision::DoesNotMatch;
    }
    if let Some(state) = &query.state {
        let Some(state) = normalized_linux_process_state(state) else {
            return ProcessFilterDecision::DoesNotMatch;
        };
        if process.state != state.to_string() {
            return ProcessFilterDecision::DoesNotMatch;
        }
    }
    if let Some(anomaly_kind) = &query.anomaly_kind {
        if anomaly_kind.trim().is_empty()
            || !process
                .anomalies
                .iter()
                .any(|anomaly| anomaly.kind == *anomaly_kind)
        {
            return ProcessFilterDecision::DoesNotMatch;
        }
    }
    let mut indeterminate_reason = None;
    if let Some(authorized) = query.authorized {
        match process.authorized {
            Some(actual) if actual == authorized => {}
            Some(_) => return ProcessFilterDecision::DoesNotMatch,
            None => indeterminate_reason = Some("process authorization is unavailable"),
        }
    }
    if let Some(uid) = query.uid {
        if !status_available || process.uid.is_none() {
            indeterminate_reason = Some("process status or UID is unavailable");
        } else if process.uid != Some(uid) {
            return ProcessFilterDecision::DoesNotMatch;
        }
    }
    if let Some(name) = &query.name_contains {
        let needle = name.to_ascii_lowercase();
        let name_matches = process.name.to_ascii_lowercase().contains(&needle);
        let command_matches = process
            .command
            .as_ref()
            .is_some_and(|command| command.to_ascii_lowercase().contains(&needle));
        if !name_matches && !command_matches {
            if !cmdline_available {
                indeterminate_reason = Some("process command line is unavailable");
            } else {
                return ProcessFilterDecision::DoesNotMatch;
            }
        }
    }
    indeterminate_reason.map_or(
        ProcessFilterDecision::Matches,
        ProcessFilterDecision::Indeterminate,
    )
}

fn evaluate_process_authorization(
    reader: &dyn ProcessFileReader,
    proc_root: &Path,
    process: &mut ProcessInfo,
    status_available: bool,
    baseline: &EffectiveProcessBaseline<'_>,
    system: ProcessSystemParameters,
) -> ProcessAuthorizationDecision {
    if baseline.configured.is_none() && baseline.legacy_names.is_empty() {
        return ProcessAuthorizationDecision::Inactive;
    }
    if baseline
        .legacy_names
        .contains(&process.name.to_ascii_lowercase())
    {
        return ProcessAuthorizationDecision::Authorized;
    }

    let Some(configured) = baseline.configured else {
        return ProcessAuthorizationDecision::Unauthorized;
    };
    let mut uid_indeterminate = false;
    let mut expected_paths = Vec::new();
    for entry in &configured.entries {
        if !entry.name.eq_ignore_ascii_case(&process.name) {
            continue;
        }
        if let Some(expected_uid) = entry.uid {
            if !status_available || process.uid.is_none() {
                uid_indeterminate = true;
                continue;
            }
            if process.uid != Some(expected_uid) {
                continue;
            }
        }
        if let Some(path) = &entry.path {
            expected_paths.push(path.as_str());
        } else {
            return ProcessAuthorizationDecision::Authorized;
        }
    }

    if expected_paths.is_empty() {
        return if uid_indeterminate {
            ProcessAuthorizationDecision::Indeterminate(
                "a matching baseline entry requires an unavailable UID".to_string(),
            )
        } else {
            ProcessAuthorizationDecision::Unauthorized
        };
    }

    match read_process_executable_path(reader, proc_root, process, system) {
        Ok(path) => {
            process.executable_path = Some(path.clone());
            if expected_paths.iter().any(|expected| *expected == path) {
                ProcessAuthorizationDecision::Authorized
            } else if uid_indeterminate {
                ProcessAuthorizationDecision::Indeterminate(
                    "a matching baseline entry requires an unavailable UID".to_string(),
                )
            } else {
                ProcessAuthorizationDecision::Unauthorized
            }
        }
        Err(reason) => ProcessAuthorizationDecision::Indeterminate(reason),
    }
}

fn read_process_executable_path(
    reader: &dyn ProcessFileReader,
    proc_root: &Path,
    process: &ProcessInfo,
    system: ProcessSystemParameters,
) -> std::result::Result<String, String> {
    let process_root = proc_root.join(process.pid.to_string());
    let executable = process_root.join("exe");
    let first_target = read_executable_target(reader, &executable)?;
    let stat = reader
        .read_to_string(&process_root.join("stat"))
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "the process exited while its executable identity was being verified".to_string()
            } else {
                format!("/proc/<pid>/stat could not be re-read: {error}")
            }
        })?;
    let identity = parse_process_stat(process.pid, &stat, None, system)
        .map_err(|error| format!("/proc/<pid>/stat identity could not be verified: {error}"))?;
    if identity.start_time_jiffies != process.start_time_jiffies || identity.name != process.name {
        return Err("process identity changed while /proc/<pid>/exe was being read".to_string());
    }
    let second_target = read_executable_target(reader, &executable)?;
    if first_target != second_target {
        return Err("process executable target changed during identity verification".to_string());
    }
    Ok(first_target)
}

fn read_executable_target(
    reader: &dyn ProcessFileReader,
    executable: &Path,
) -> std::result::Result<String, String> {
    let target = reader.read_link(executable).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "the process exited before /proc/<pid>/exe could be read".to_string()
        } else {
            format!("/proc/<pid>/exe could not be read: {error}")
        }
    })?;
    let target = target
        .to_str()
        .ok_or_else(|| "/proc/<pid>/exe is not valid UTF-8".to_string())?;
    if target.ends_with(" (deleted)") {
        return Err("/proc/<pid>/exe refers to a deleted executable".to_string());
    }
    if !is_valid_absolute_linux_path(target) {
        return Err(format!(
            "/proc/<pid>/exe is not a valid absolute Linux path of at most {MAX_EXECUTABLE_PATH_BYTES} bytes"
        ));
    }
    Ok(target.to_string())
}

fn unauthorized_process_anomaly(
    process: &ProcessInfo,
    baseline: &EffectiveProcessBaseline<'_>,
) -> ProcessAnomaly {
    let (baseline_id, baseline_version) = baseline.configured.map_or(
        ("query.allowed_names", PROCESS_BASELINE_VERSION),
        |baseline| (baseline.id.as_str(), baseline.version),
    );
    ProcessAnomaly {
        pid: process.pid,
        kind: "unauthorized_process".to_string(),
        message: format!(
            "process `{}` does not match active baseline `{baseline_id}` version {baseline_version}",
            process.name
        ),
        score: 0.8,
        evidence: Some(ProcessAnomalyEvidence::Authorization {
            baseline_id: baseline_id.to_string(),
            baseline_version,
            name: process.name.clone(),
            uid: process.uid,
            executable_path: process.executable_path.clone(),
        }),
    }
}

fn is_valid_absolute_linux_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains('\0')
        && path.as_bytes().len() <= MAX_EXECUTABLE_PATH_BYTES
        && !path.split('/').any(|component| component == "..")
}

fn normalized_linux_process_state(value: &str) -> Option<char> {
    let mut chars = value.trim().chars();
    let state = chars.next()?;
    if chars.next().is_some() || !"RSDZTtWXxKPI".contains(state) {
        return None;
    }
    Some(state)
}

fn load_passwd_users() -> BTreeMap<u32, String> {
    fs::read_to_string("/etc/passwd")
        .map(|content| {
            content
                .lines()
                .filter_map(|line| {
                    let parts = line.split(':').collect::<Vec<_>>();
                    Some((parts.get(2)?.parse().ok()?, parts.first()?.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn resolve_user_with_getent(uid: u32) -> std::result::Result<Option<String>, String> {
    let uid = uid.to_string();
    let output = run_limited_command(
        "getent",
        &["passwd", uid.as_str()],
        Duration::from_millis(500),
        4 * 1024,
        1024,
    )
    .map_err(|error| error.to_string())?;
    if output.timed_out {
        return Err("getent passwd timed out".to_string());
    }
    if output.stdout_truncated {
        return Err("getent passwd output exceeded the limit".to_string());
    }
    if !output.success {
        return Ok(None);
    }
    let entry = output.stdout.lines().find(|line| !line.trim().is_empty());
    let Some(entry) = entry else {
        return Ok(None);
    };
    let fields = entry.split(':').collect::<Vec<_>>();
    let resolved_uid = fields.get(2).and_then(|value| value.parse::<u32>().ok());
    if resolved_uid != uid.parse().ok() {
        return Err("getent passwd returned a mismatched UID".to_string());
    }
    Ok(fields
        .first()
        .filter(|name| !name.is_empty())
        .map(|name| (*name).to_string()))
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[allow(dead_code)]
fn path_exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use crate::model::ProcessBaselineEntry;

    use super::*;

    #[test]
    fn parses_and_validates_automatic_threshold_json() {
        assert_eq!(
            MetricsThresholds::from_json("{}").expect("default thresholds"),
            MetricsThresholds::default()
        );
        let thresholds = MetricsThresholds::from_json(
            r#"{"cpu_percent":0.0,"memory_percent":100.0,"disk_percent":null,"load1":2.5}"#,
        )
        .expect("valid thresholds");
        assert_eq!(thresholds.cpu_percent, Some(0.0));
        assert_eq!(thresholds.memory_percent, Some(100.0));
        assert_eq!(thresholds.disk_percent, None);
        assert_eq!(thresholds.load1, Some(2.5));
        let disabled = MetricsThresholds::from_json(
            r#"{"cpu_percent":null,"memory_percent":null,"disk_percent":null,"load1":null}"#,
        )
        .expect("disabled thresholds");
        assert_eq!(disabled.cpu_percent, None);
        assert_eq!(disabled.memory_percent, None);
        assert_eq!(disabled.disk_percent, None);
        assert_eq!(disabled.load1, None);
    }

    #[test]
    fn rejects_invalid_automatic_threshold_json_and_values() {
        for value in [
            r#"{"cpu_percent":101}"#,
            r#"{"memory_percent":-1}"#,
            r#"{"load1":-0.1}"#,
            r#"{"unknown":1}"#,
            "null",
            "not-json",
        ] {
            let error = MetricsThresholds::from_json(value).expect_err("invalid thresholds");
            assert!(error.to_string().contains(OS_SENSE_THRESHOLDS_ENV));
        }
    }

    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn new(now_ms: u64) -> Self {
            Self(AtomicU64::new(now_ms))
        }

        fn set(&self, now_ms: u64) {
            self.0.store(now_ms, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    impl MonotonicClock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    struct AdvancingClock {
        now_ms: AtomicU64,
        step_ms: u64,
    }

    impl AdvancingClock {
        fn advance(&self, delta_ms: u64) {
            self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
        }
    }

    impl Clock for AdvancingClock {
        fn now_ms(&self) -> u64 {
            self.now_ms.fetch_add(self.step_ms, Ordering::SeqCst)
        }
    }

    impl MonotonicClock for AdvancingClock {
        fn now_ms(&self) -> u64 {
            self.now_ms.fetch_add(self.step_ms, Ordering::SeqCst)
        }
    }

    struct StaticPartitionUsage(&'static str);

    impl PartitionUsageProvider for StaticPartitionUsage {
        fn read_df_output(&self) -> Result<String> {
            Ok(self.0.to_string())
        }
    }

    struct FailingPartitionUsage;

    impl PartitionUsageProvider for FailingPartitionUsage {
        fn read_df_output(&self) -> Result<String> {
            Err(OsSenseError::Command("fixture failure".to_string()))
        }
    }

    const DF_FIXTURE: &str =
        "Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/sda1 1000 400 600 40% /\n";

    fn write_resource_fixture(root: &Path) -> (PathBuf, PathBuf) {
        let proc_root = root.join("proc");
        let sys_root = root.join("sys");
        fs::create_dir_all(proc_root.join("sys/kernel")).expect("proc kernel fixture");
        fs::create_dir_all(proc_root.join("net")).expect("proc net fixture");
        fs::create_dir_all(sys_root.join("class/thermal/thermal_zone0")).expect("thermal fixture");
        fs::create_dir_all(sys_root.join("class/hwmon/hwmon0")).expect("hwmon fixture");
        fs::write(
            proc_root.join("stat"),
            "cpu 100 0 0 900 0 0 0 0\ncpu0 60 0 0 440 0 0 0 0\ncpu1 40 0 0 460 0 0 0 0\n",
        )
        .expect("stat fixture");
        fs::write(
            proc_root.join("meminfo"),
            "MemTotal: 1000 kB\nMemAvailable: 400 kB\nBuffers: 50 kB\nCached: 120 kB\nSReclaimable: 20 kB\nShmem: 10 kB\nSwapTotal: 500 kB\nSwapFree: 300 kB\n",
        )
        .expect("meminfo fixture");
        fs::write(proc_root.join("loadavg"), "0.1 0.2 0.3 1/10 42\n").expect("load fixture");
        fs::write(
            proc_root.join("diskstats"),
            "8 0 sda 10 0 100 0 20 0 200 0 0 0 0 0 0 0 0\n",
        )
        .expect("diskstats fixture");
        fs::write(
            proc_root.join("net/dev"),
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n",
        )
        .expect("net dev fixture");
        let socket_header = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
        fs::write(
            proc_root.join("net/tcp"),
            format!("{socket_header} 0: 0100007F:0016 00000000:0000 0A 0 0 0 0 0 1\n"),
        )
        .expect("tcp fixture");
        for name in ["tcp6", "udp", "udp6"] {
            fs::write(proc_root.join("net").join(name), socket_header).expect("socket fixture");
        }
        fs::write(proc_root.join("cpuinfo"), "model name: LoongArch 3A6000\n")
            .expect("cpuinfo fixture");
        fs::write(proc_root.join("sys/kernel/osrelease"), "6.6.0-kylin\n").expect("kernel fixture");
        let thermal = sys_root.join("class/thermal/thermal_zone0");
        fs::write(thermal.join("type"), "cpu-thermal\n").expect("thermal type");
        fs::write(thermal.join("temp"), "46000\n").expect("thermal temp");
        let hwmon = sys_root.join("class/hwmon/hwmon0");
        fs::write(hwmon.join("name"), "loongson_hwmon\n").expect("hwmon name");
        for (sensor, value, label) in [
            ("temp1", "47500\n", "CPU Package\n"),
            ("fan1", "1800\n", "Chassis Fan\n"),
            ("in1", "12000\n", "Core Voltage\n"),
            ("curr1", "2500\n", "CPU Current\n"),
            ("power1", "65000000\n", "Package Power\n"),
            ("energy1", "123456789\n", "Package Energy\n"),
            ("humidity1", "45500\n", "Ambient Humidity\n"),
            ("freq1", "2400000000\n", "Core Clock\n"),
        ] {
            fs::write(hwmon.join(format!("{sensor}_input")), value).expect("hwmon input");
            fs::write(hwmon.join(format!("{sensor}_label")), label).expect("hwmon label");
        }
        (proc_root, sys_root)
    }

    struct FixtureUserResolver {
        responses: BTreeMap<u32, std::result::Result<Option<String>, String>>,
        calls: Mutex<Vec<u32>>,
    }

    impl ProcessUserResolver for FixtureUserResolver {
        fn resolve(&self, uid: u32) -> std::result::Result<Option<String>, String> {
            self.calls.lock().expect("resolver calls").push(uid);
            self.responses
                .get(&uid)
                .cloned()
                .unwrap_or_else(|| Ok(None))
        }
    }

    struct LocalFixtureUserResolver {
        local: BTreeMap<u32, String>,
        calls: Mutex<Vec<u32>>,
    }

    impl ProcessUserResolver for LocalFixtureUserResolver {
        fn resolve_local(&self, uid: u32) -> Option<String> {
            self.local.get(&uid).cloned()
        }

        fn resolve(&self, uid: u32) -> std::result::Result<Option<String>, String> {
            self.calls.lock().expect("resolver calls").push(uid);
            Ok(None)
        }
    }

    struct ClockAdvancingUserResolver {
        clock: Arc<AdvancingClock>,
        delay_ms: u64,
    }

    impl ProcessUserResolver for ClockAdvancingUserResolver {
        fn resolve(&self, uid: u32) -> std::result::Result<Option<String>, String> {
            self.clock.advance(self.delay_ms);
            Ok(Some(format!("user-{uid}")))
        }
    }

    struct StatusFailureReader {
        failures: BTreeMap<u32, std::io::ErrorKind>,
        fail_all: Option<std::io::ErrorKind>,
    }

    impl ProcessFileReader for StatusFailureReader {
        fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
            if path.file_name().and_then(|name| name.to_str()) == Some("status") {
                let pid = path
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.parse::<u32>().ok());
                if let Some(kind) = pid
                    .and_then(|pid| self.failures.get(&pid).copied())
                    .or(self.fail_all)
                {
                    return Err(std::io::Error::new(kind, "fixture status failure"));
                }
            }
            fs::read_to_string(path)
        }

        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            fs::read(path)
        }

        fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
            fs::read_link(path)
        }
    }

    struct CmdlineFailureReader;

    impl ProcessFileReader for CmdlineFailureReader {
        fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
            fs::read_to_string(path)
        }

        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            if path.file_name().and_then(|name| name.to_str()) == Some("cmdline") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "fixture command line failure",
                ));
            }
            fs::read(path)
        }

        fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
            fs::read_link(path)
        }
    }

    #[derive(Clone)]
    enum ExecutablePathFixture {
        Path(&'static str),
        Error(std::io::ErrorKind),
    }

    struct ExecutablePathReader {
        fixtures: BTreeMap<u32, Vec<ExecutablePathFixture>>,
        stat_after_first_link: BTreeMap<u32, String>,
        calls: Mutex<Vec<u32>>,
    }

    impl ProcessFileReader for ExecutablePathReader {
        fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
            if path.file_name().and_then(|name| name.to_str()) == Some("stat") {
                let pid = path
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.parse::<u32>().ok());
                if let Some(stat) = pid.and_then(|pid| {
                    self.calls
                        .lock()
                        .expect("executable calls")
                        .contains(&pid)
                        .then(|| self.stat_after_first_link.get(&pid))
                        .flatten()
                }) {
                    return Ok(stat.clone());
                }
            }
            fs::read_to_string(path)
        }

        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            fs::read(path)
        }

        fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
            let pid = path
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                .and_then(|name| name.parse::<u32>().ok())
                .expect("fixture executable PID");
            let mut calls = self.calls.lock().expect("executable calls");
            let index = calls.iter().filter(|called| **called == pid).count();
            calls.push(pid);
            let fixture = self
                .fixtures
                .get(&pid)
                .and_then(|fixtures| fixtures.get(index).or_else(|| fixtures.last()));
            match fixture {
                Some(ExecutablePathFixture::Path(path)) => Ok(PathBuf::from(path)),
                Some(ExecutablePathFixture::Error(kind)) => {
                    Err(std::io::Error::new(*kind, "fixture executable failure"))
                }
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "missing executable fixture",
                )),
            }
        }
    }

    fn process_stat(
        pid: u32,
        name: &str,
        utime: u64,
        stime: u64,
        start_time: u64,
        rss_pages: i64,
    ) -> String {
        process_stat_with_state(pid, name, "S", utime, stime, start_time, rss_pages)
    }

    fn process_stat_with_state(
        pid: u32,
        name: &str,
        state: &str,
        utime: u64,
        stime: u64,
        start_time: u64,
        rss_pages: i64,
    ) -> String {
        process_stat_with_ppid(pid, name, state, 1, utime, stime, start_time, rss_pages)
    }

    #[allow(clippy::too_many_arguments)]
    fn process_stat_with_ppid(
        pid: u32,
        name: &str,
        state: &str,
        ppid: u32,
        utime: u64,
        stime: u64,
        start_time: u64,
        rss_pages: i64,
    ) -> String {
        format!(
            "{pid} ({name}) {state} {ppid} 2 3 4 5 0 0 0 0 0 {utime} {stime} 0 0 20 0 1 0 {start_time} 409600 {rss_pages} 0 0\n"
        )
    }

    fn process_info_for_anomaly(
        pid: u32,
        start_time_jiffies: u64,
        state: &str,
        rss_kb: Option<u64>,
        cpu_usage_percent: Option<f64>,
        cpu_rate_status: Option<RateStatus>,
    ) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid: Some(1),
            name: format!("process-{pid}"),
            state: state.to_string(),
            user: None,
            uid: None,
            cpu_time_jiffies: 0,
            start_time_jiffies,
            cpu_usage_percent,
            cpu_sample_interval_ms: Some(30_000),
            cpu_rate_status,
            memory_rss_kb: rss_kb,
            memory_percent: None,
            virtual_memory_kb: None,
            uptime_seconds: None,
            command: None,
            executable_path: None,
            anomalies: Vec::new(),
            authorized: None,
        }
    }

    fn write_process_fixture(
        proc_root: &Path,
        pid: u32,
        stat: &str,
        uid: u32,
        status_rss_kb: Option<u64>,
    ) {
        let process = proc_root.join(pid.to_string());
        fs::create_dir_all(&process).expect("process fixture");
        fs::write(process.join("stat"), stat).expect("process stat");
        let mut status = format!("Name:\tfixture\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n");
        if let Some(rss_kb) = status_rss_kb {
            status.push_str(&format!("VmRSS:\t{rss_kb} kB\n"));
        }
        fs::write(process.join("status"), status).expect("process status");
        fs::write(process.join("cmdline"), b"fixture\0--serve\0").expect("process cmdline");
    }

    fn process_collector(
        root: &Path,
        clock: Arc<ManualClock>,
        system: ProcessSystemParameters,
        resolver: Arc<dyn ProcessUserResolver>,
    ) -> ProcfsCollector {
        let proc_root = root.join("proc");
        let sys_root = root.join("sys");
        fs::create_dir_all(proc_root.join("sys/kernel")).expect("proc fixture");
        fs::create_dir_all(&sys_root).expect("sys fixture");
        fs::write(proc_root.join("uptime"), "100.0 0.0\n").expect("uptime fixture");
        fs::write(
            proc_root.join("meminfo"),
            "MemTotal: 10000 kB\nMemAvailable: 5000 kB\n",
        )
        .expect("meminfo fixture");
        ProcfsCollector::with_process_dependencies(
            proc_root,
            sys_root,
            clock.clone(),
            clock,
            Arc::new(StaticPartitionUsage(DF_FIXTURE)),
            system,
            resolver,
        )
    }

    fn process_collector_with_clocks(
        root: &Path,
        wall_clock: Arc<dyn Clock>,
        process_clock: Arc<dyn MonotonicClock>,
        system: ProcessSystemParameters,
        resolver: Arc<dyn ProcessUserResolver>,
    ) -> ProcfsCollector {
        let proc_root = root.join("proc");
        let sys_root = root.join("sys");
        fs::create_dir_all(proc_root.join("sys/kernel")).expect("proc fixture");
        fs::create_dir_all(&sys_root).expect("sys fixture");
        fs::write(proc_root.join("uptime"), "100.0 0.0\n").expect("uptime fixture");
        fs::write(
            proc_root.join("meminfo"),
            "MemTotal: 1000000 kB\nMemAvailable: 500000 kB\n",
        )
        .expect("meminfo fixture");
        ProcfsCollector::with_process_dependencies(
            proc_root,
            sys_root,
            wall_clock,
            process_clock,
            Arc::new(StaticPartitionUsage(DF_FIXTURE)),
            system,
            resolver,
        )
    }

    #[test]
    fn parses_cpu_stat() {
        let stat = "cpu  100 0 50 850 0 0 0 0 0 0\ncpu0 100 0 50 850 0 0 0 0 0 0\n";
        let parsed = parse_cpu_stat(stat).expect("cpu stat");
        assert_eq!(parsed.total_jiffies, 1000);
        assert_eq!(parsed.idle_jiffies, 850);
        assert_eq!(parsed.usage_percent, None);
        assert_eq!(parsed.cpu_count, 1);
        assert_eq!(parsed.cores[0].name, "cpu0");
    }

    #[test]
    fn parses_meminfo() {
        let meminfo = "MemTotal: 1000 kB\nMemAvailable: 250 kB\nBuffers: 20 kB\nCached: 100 kB\nSReclaimable: 30 kB\nShmem: 10 kB\nSwapTotal: 500 kB\nSwapFree: 125 kB\n";
        let parsed = parse_meminfo(meminfo).expect("meminfo");
        assert_eq!(parsed.used_kb, 750);
        assert_eq!(parsed.used_percent, Some(75.0));
        assert_eq!(parsed.buffers_kb, 20);
        assert_eq!(parsed.cached_kb, 120);
        assert_eq!(parsed.swap_used_kb, 375);
    }

    #[test]
    fn parses_loadavg() {
        let parsed = parse_loadavg("0.10 0.20 0.30 2/100 99").expect("loadavg");
        assert_eq!(parsed.one, 0.10);
        assert_eq!(parsed.runnable_tasks, Some(2));
        assert_eq!(parsed.total_tasks, Some(100));
        assert_eq!(parsed.last_pid, Some(99));
    }

    #[test]
    fn parses_df_output() {
        let df = "Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/sda1 100 91 9 91% /\n";
        let disks = parse_df_output(df);
        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].mount_point, "/");
        assert_eq!(disks[0].used_percent, Some(91.0));
    }

    #[test]
    fn parses_disk_and_network_counters_without_treating_them_as_rates() {
        let disks = parse_diskstats("8 0 sda 10 0 100 0 20 0 200 0 1 0 0 0 0 0 0\n");
        assert_eq!(disks[0].reads_completed_total, 10);
        assert_eq!(disks[0].sectors_written_total, 200);
        assert_eq!(disks[0].read_bytes_per_sec, None);

        let interfaces = parse_net_dev(
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n",
        );
        assert_eq!(interfaces[0].receive_errors_total, 1);
        assert_eq!(interfaces[0].transmit_dropped_total, 4);
        assert_eq!(interfaces[0].receive_bytes_per_sec, None);
    }

    #[test]
    fn parses_process_stat_with_name_containing_space() {
        let stat = "123 (my proc) S 1 2 3 4 5 0 0 0 0 0 10 20 0 0 20 0 1 0 100 409600 25 0 0";
        let parsed = parse_process_stat(123, stat, Some(10.0), ProcessSystemParameters::default())
            .expect("process stat");
        assert_eq!(parsed.name, "my proc");
        assert_eq!(parsed.ppid, Some(1));
        assert_eq!(parsed.cpu_time_jiffies, 30);
        assert_eq!(parsed.virtual_memory_kb, Some(400));
        assert_eq!(parsed.memory_rss_kb, Some(100));
    }

    #[test]
    fn process_samples_use_runtime_ticks_page_size_status_rss_and_memory_total() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let clock = Arc::new(ManualClock::new(1_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::from([(42, Ok(Some("alice".to_string())))]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock.clone(),
            ProcessSystemParameters {
                clock_ticks_per_second: 250,
                page_size_bytes: 8_192,
            },
            resolver.clone(),
        );
        fs::write(proc_root.join("uptime"), "100.0 0.0\n").expect("uptime");
        fs::write(
            proc_root.join("meminfo"),
            "MemTotal: 10000 kB\nMemAvailable: 5000 kB\n",
        )
        .expect("meminfo");
        write_process_fixture(
            &proc_root,
            7,
            &process_stat(7, "worker", 500, 0, 1_000, 3),
            42,
            Some(1_000),
        );

        let first = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(first.collection_status, CollectionStatus::Complete);
        let first = &first.processes[0];
        assert_eq!(first.start_time_jiffies, 1_000);
        assert_eq!(first.cpu_usage_percent, None);
        assert_eq!(first.cpu_sample_interval_ms, None);
        assert_eq!(first.cpu_rate_status, Some(RateStatus::WarmingUp));
        assert_eq!(first.uptime_seconds, Some(96.0));
        assert_eq!(first.memory_rss_kb, Some(1_000));
        assert_eq!(first.memory_percent, Some(10.0));
        assert_eq!(first.uid, Some(42));
        assert_eq!(first.user.as_deref(), Some("alice"));

        clock.set(3_000);
        write_process_fixture(
            &proc_root,
            7,
            &process_stat(7, "worker", 625, 0, 1_000, 3),
            42,
            None,
        );
        let second = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(second.collection_status, CollectionStatus::Complete);
        let second = &second.processes[0];
        assert_eq!(second.cpu_usage_percent, Some(25.0));
        assert_eq!(second.cpu_sample_interval_ms, Some(2_000));
        assert_eq!(second.cpu_rate_status, Some(RateStatus::Ready));
        assert_eq!(second.memory_rss_kb, Some(24));
        assert_eq!(second.memory_percent, Some(0.24));
        assert_eq!(
            resolver.calls.lock().expect("resolver calls").as_slice(),
            &[42]
        );
    }

    #[test]
    fn wall_clock_jumps_do_not_affect_process_rates_or_cache_ttls() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let wall_clock = Arc::new(ManualClock::new(1_000));
        let monotonic_clock = Arc::new(ManualClock::new(10_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::from([(42, Ok(Some("alice".to_string())))]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            wall_clock.clone(),
            ProcessSystemParameters::default(),
            resolver.clone(),
        );
        collector.process_clock = monotonic_clock.clone();
        write_process_fixture(
            &proc_root,
            7,
            &process_stat(7, "worker", 100, 0, 1_000, 1),
            42,
            None,
        );

        let first = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(first.meta.collected_at_ms, 1_000);
        wall_clock.set(9_000_000_000);
        monotonic_clock.set(12_000);
        write_process_fixture(
            &proc_root,
            7,
            &process_stat(7, "worker", 200, 0, 1_000, 1),
            42,
            None,
        );
        let forward = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(forward.meta.collected_at_ms, 9_000_000_000);
        assert_eq!(forward.processes[0].cpu_sample_interval_ms, Some(2_000));
        assert_eq!(forward.processes[0].cpu_usage_percent, Some(50.0));

        wall_clock.set(10);
        monotonic_clock.set(14_000);
        write_process_fixture(
            &proc_root,
            7,
            &process_stat(7, "worker", 300, 0, 1_000, 1),
            42,
            None,
        );
        let backward = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(backward.meta.collected_at_ms, 10);
        assert_eq!(backward.processes[0].cpu_sample_interval_ms, Some(2_000));
        assert_eq!(backward.processes[0].cpu_usage_percent, Some(50.0));
        assert_eq!(resolver.calls.lock().expect("resolver calls").len(), 1);

        monotonic_clock.set(614_000);
        let expired_baseline = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(
            expired_baseline.processes[0].cpu_rate_status,
            Some(RateStatus::WarmingUp)
        );
        assert_eq!(resolver.calls.lock().expect("resolver calls").len(), 1);

        monotonic_clock.set(3_610_000);
        collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(resolver.calls.lock().expect("resolver calls").len(), 2);
    }

    #[test]
    fn per_pid_sampling_precedes_nss_clock_changes_and_remains_order_independent() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let clock = Arc::new(AdvancingClock {
            now_ms: AtomicU64::new(1_000),
            step_ms: 10,
        });
        let resolver = Arc::new(ClockAdvancingUserResolver {
            clock: clock.clone(),
            delay_ms: 10_000,
        });
        let mut collector = ProcfsCollector::with_process_dependencies(
            proc_root.clone(),
            root.path().join("sys"),
            clock.clone(),
            clock.clone(),
            Arc::new(StaticPartitionUsage(DF_FIXTURE)),
            ProcessSystemParameters::default(),
            resolver,
        );
        fs::create_dir_all(proc_root.join("sys/kernel")).expect("proc fixture");
        fs::create_dir_all(root.path().join("sys")).expect("sys fixture");
        fs::write(proc_root.join("uptime"), "100.0 0.0\n").expect("uptime");
        fs::write(
            proc_root.join("meminfo"),
            "MemTotal: 10000 kB\nMemAvailable: 5000 kB\n",
        )
        .expect("meminfo");
        for pid in [2, 1] {
            write_process_fixture(
                &proc_root,
                pid,
                &process_stat(pid, "worker", 100, 0, pid as u64, 1),
                pid,
                None,
            );
        }

        collector.collect_processes_for_test(&ProcessQuery::default());
        let first_samples = collector.process_cpu_baselines.clone();
        for pid in [1, 2] {
            assert!(
                first_samples[&pid].sampled_at_ms < collector.process_user_cache[&pid].cached_at_ms,
                "PID sample must be recorded before NSS resolution changes the clock"
            );
            write_process_fixture(
                &proc_root,
                pid,
                &process_stat(pid, "worker", 200, 0, pid as u64, 1),
                pid,
                None,
            );
        }
        clock.advance(2_000);

        let second = collector.collect_processes_for_test(&ProcessQuery::default());
        for process in &second.processes {
            let first_sample = first_samples[&process.pid].sampled_at_ms;
            let second_sample = collector.process_cpu_baselines[&process.pid].sampled_at_ms;
            let interval_ms = second_sample - first_sample;
            assert_eq!(process.cpu_sample_interval_ms, Some(interval_ms));
            assert_eq!(
                process.cpu_usage_percent,
                Some(round2(100.0 * 100_000.0 / (interval_ms as f64 * 100.0)))
            );
            assert_eq!(process.cpu_rate_status, Some(RateStatus::Ready));
        }
    }

    #[test]
    fn process_baseline_ttl_and_cap_evict_oldest_then_lowest_pid() {
        let baseline = |sampled_at_ms| ProcessCpuBaseline {
            start_time_jiffies: 1,
            cpu_time_jiffies: 1,
            sampled_at_ms,
            scan_id: 1,
        };
        let mut baselines = BTreeMap::new();
        let mut order = BTreeSet::new();
        for (pid, baseline) in [(1, baseline(0)), (2, baseline(100)), (3, baseline(100))] {
            insert_process_cpu_baseline(&mut baselines, &mut order, pid, baseline, 3);
        }

        prune_process_cpu_baselines(&mut baselines, &mut order, 500, 450, 1);

        assert_eq!(baselines.keys().copied().collect::<Vec<_>>(), vec![3]);
        assert_eq!(order, BTreeSet::from([(100, 3)]));
    }

    #[test]
    fn process_user_cache_uses_positive_negative_ttls_and_stable_cap() {
        let root = tempfile::tempdir().expect("tempdir");
        let clock = Arc::new(ManualClock::new(1_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::from([(7, Ok(None)), (8, Ok(Some("known".to_string())))]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock.clone(),
            ProcessSystemParameters::default(),
            resolver.clone(),
        );

        let mut lookup_budget = 100;
        collector.resolve_process_user(7, &mut lookup_budget);
        collector.resolve_process_user(8, &mut lookup_budget);
        clock.set(30_999);
        collector.resolve_process_user(7, &mut lookup_budget);
        clock.set(31_000);
        collector.resolve_process_user(7, &mut lookup_budget);
        clock.set(3_600_999);
        collector.resolve_process_user(8, &mut lookup_budget);
        clock.set(3_601_000);
        collector.resolve_process_user(8, &mut lookup_budget);
        let mut calls = resolver.calls.lock().expect("resolver calls").clone();
        calls.sort_unstable();
        assert_eq!(calls, vec![7, 7, 8, 8]);

        let cached = |cached_at_ms| CachedUserResolution {
            user: "user".to_string(),
            warning: None,
            cached_at_ms,
            positive: true,
            definitive: true,
        };
        let mut cache = BTreeMap::from([(1, cached(0)), (2, cached(10)), (3, cached(10))]);
        enforce_process_user_cache_limit(&mut cache, 1);
        assert_eq!(cache.keys().copied().collect::<Vec<_>>(), vec![3]);
    }

    #[test]
    fn process_cpu_pid_reuse_counter_reset_and_exit_all_reset_the_baseline() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let clock = Arc::new(ManualClock::new(1_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::from([(0, Ok(Some("root".to_string())))]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock.clone(),
            ProcessSystemParameters::default(),
            resolver,
        );
        write_process_fixture(
            &proc_root,
            8,
            &process_stat(8, "worker", 100, 0, 1_000, 1),
            0,
            None,
        );
        assert_eq!(
            collector
                .collect_processes_for_test(&ProcessQuery::default())
                .processes[0]
                .cpu_rate_status,
            Some(RateStatus::WarmingUp)
        );

        clock.set(2_000);
        write_process_fixture(
            &proc_root,
            8,
            &process_stat(8, "worker", 50, 0, 2_000, 1),
            0,
            None,
        );
        let reused = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(
            reused.processes[0].cpu_rate_status,
            Some(RateStatus::WarmingUp)
        );
        assert_eq!(reused.processes[0].cpu_usage_percent, None);

        clock.set(3_000);
        write_process_fixture(
            &proc_root,
            8,
            &process_stat(8, "worker", 40, 0, 2_000, 1),
            0,
            None,
        );
        let reset = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(
            reset.processes[0].cpu_rate_status,
            Some(RateStatus::CounterReset)
        );
        assert_eq!(reset.processes[0].cpu_usage_percent, None);

        fs::remove_dir_all(proc_root.join("8")).expect("process exit");
        clock.set(4_000);
        assert!(collector
            .collect_processes_for_test(&ProcessQuery::default())
            .processes
            .is_empty());
        write_process_fixture(
            &proc_root,
            8,
            &process_stat(8, "worker", 500, 0, 2_000, 1),
            0,
            None,
        );
        clock.set(5_000);
        let restarted = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(
            restarted.processes[0].cpu_rate_status,
            Some(RateStatus::WarmingUp)
        );
    }

    #[test]
    fn nss_results_are_cached_and_unknown_uid_falls_back_to_decimal() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let clock = Arc::new(ManualClock::new(1_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::from([(42, Ok(Some("alice".to_string()))), (43, Ok(None))]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock.clone(),
            ProcessSystemParameters::default(),
            resolver.clone(),
        );
        write_process_fixture(
            &proc_root,
            42,
            &process_stat(42, "known", 1, 0, 1, 1),
            42,
            None,
        );
        write_process_fixture(
            &proc_root,
            43,
            &process_stat(43, "unknown", 1, 0, 1, 1),
            43,
            None,
        );

        let first = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(first.processes[0].user.as_deref(), Some("alice"));
        assert_eq!(first.processes[1].user.as_deref(), Some("43"));
        assert!(first
            .meta
            .warnings
            .iter()
            .any(|warning| warning.contains("UID 43")));
        clock.set(2_000);
        collector.collect_processes_for_test(&ProcessQuery::default());
        let mut calls = resolver.calls.lock().expect("resolver calls").clone();
        calls.sort_unstable();
        assert_eq!(calls, vec![42, 43]);
    }

    #[test]
    fn process_scan_counts_exits_and_surfaces_status_permission_errors() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let clock = Arc::new(ManualClock::new(1_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::new(),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock,
            ProcessSystemParameters::default(),
            resolver.clone(),
        );
        for pid in [10, 11] {
            write_process_fixture(
                &proc_root,
                pid,
                &process_stat(pid, "worker", 1, 0, 1, 1),
                0,
                None,
            );
        }
        collector.process_file_reader = Arc::new(StatusFailureReader {
            failures: BTreeMap::from([
                (10, std::io::ErrorKind::PermissionDenied),
                (11, std::io::ErrorKind::NotFound),
            ]),
            fail_all: None,
        });

        let list = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(list.processes.len(), 1);
        assert_eq!(list.processes[0].pid, 10);
        assert_eq!(list.failed_process_count, 0);
        assert_eq!(list.partial_process_count, 1);
        assert_eq!(list.exited_during_scan_count, 1);
        assert!(!list.filter_complete);
        assert_eq!(list.collection_status, CollectionStatus::Partial);
        assert_eq!(list.meta.warnings.len(), 1);
        assert!(list.meta.warnings[0].contains("process 10 status"));
    }

    #[test]
    fn unavailable_status_makes_uid_and_user_filters_indeterminate() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::from([(42, Ok(Some("alice".to_string())))]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            Arc::new(ManualClock::new(1_000)),
            ProcessSystemParameters::default(),
            resolver.clone(),
        );
        write_process_fixture(
            &proc_root,
            42,
            &process_stat(42, "worker", 1, 0, 42, 1),
            42,
            None,
        );
        collector.process_file_reader = Arc::new(StatusFailureReader {
            failures: BTreeMap::new(),
            fail_all: Some(std::io::ErrorKind::PermissionDenied),
        });

        for query in [
            ProcessQuery {
                uid: Some(42),
                ..ProcessQuery::default()
            },
            ProcessQuery {
                user: Some("alice".to_string()),
                ..ProcessQuery::default()
            },
        ] {
            let list = collector.collect_processes_for_test(&query);
            assert_eq!(list.total, 0);
            assert!(list.processes.is_empty());
            assert_eq!(list.indeterminate_filter_count, 1);
            assert!(!list.filter_complete);
            assert_eq!(list.collection_status, CollectionStatus::Partial);
            assert!(list
                .meta
                .warnings
                .iter()
                .any(|warning| warning.contains("indeterminate")));
        }
        assert!(resolver.calls.lock().expect("resolver calls").is_empty());
    }

    #[test]
    fn unavailable_cmdline_only_makes_name_filter_indeterminate_when_name_misses() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let mut collector = process_collector(
            root.path(),
            Arc::new(ManualClock::new(1_000)),
            ProcessSystemParameters::default(),
            Arc::new(FixtureUserResolver {
                responses: BTreeMap::from([(0, Ok(Some("root".to_string())))]),
                calls: Mutex::new(Vec::new()),
            }),
        );
        write_process_fixture(
            &proc_root,
            7,
            &process_stat(7, "worker", 1, 0, 7, 1),
            0,
            None,
        );
        collector.process_file_reader = Arc::new(CmdlineFailureReader);

        let indeterminate = collector.collect_processes_for_test(&ProcessQuery {
            name_contains: Some("--serve".to_string()),
            ..ProcessQuery::default()
        });
        assert_eq!(indeterminate.total, 0);
        assert_eq!(indeterminate.indeterminate_filter_count, 1);
        assert!(!indeterminate.filter_complete);
        assert_eq!(indeterminate.collection_status, CollectionStatus::Partial);

        let name_match = collector.collect_processes_for_test(&ProcessQuery {
            name_contains: Some("WORK".to_string()),
            ..ProcessQuery::default()
        });
        assert_eq!(name_match.total, 1);
        assert_eq!(name_match.processes[0].pid, 7);
        assert_eq!(name_match.indeterminate_filter_count, 0);
        assert!(name_match.filter_complete);
        assert_eq!(name_match.collection_status, CollectionStatus::Partial);
    }

    #[test]
    fn uptime_and_meminfo_failures_are_visible_and_make_collection_partial() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let clock = Arc::new(ManualClock::new(1_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::from([(0, Ok(Some("root".to_string())))]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock,
            ProcessSystemParameters::default(),
            resolver,
        );
        fs::write(proc_root.join("uptime"), "invalid\n").expect("invalid uptime");
        fs::write(proc_root.join("meminfo"), "MemFree: 1 kB\n").expect("invalid meminfo");
        write_process_fixture(
            &proc_root,
            12,
            &process_stat(12, "worker", 1, 0, 1, 1),
            0,
            Some(10),
        );

        let list = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(list.collection_status, CollectionStatus::Partial);
        assert!(!list.scan_failed);
        assert_eq!(list.failed_process_count, 0);
        assert_eq!(list.partial_process_count, 0);
        assert_eq!(list.processes[0].uptime_seconds, None);
        assert_eq!(list.processes[0].memory_percent, None);
        assert!(list
            .meta
            .warnings
            .iter()
            .any(|warning| warning.contains("/proc/uptime")));
        assert!(list
            .meta
            .warnings
            .iter()
            .any(|warning| warning.contains("MemTotal")));
    }

    #[test]
    fn top_level_proc_scan_failure_is_failed_and_bounded() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc-file");
        let sys_root = root.path().join("sys");
        fs::write(&proc_root, "not a directory\n").expect("proc fixture");
        fs::create_dir_all(&sys_root).expect("sys fixture");
        let mut collector = ProcfsCollector::with_process_dependencies(
            proc_root,
            sys_root,
            Arc::new(ManualClock::new(1_000)),
            Arc::new(ManualClock::new(1_000)),
            Arc::new(StaticPartitionUsage(DF_FIXTURE)),
            ProcessSystemParameters::default(),
            Arc::new(FixtureUserResolver {
                responses: BTreeMap::new(),
                calls: Mutex::new(Vec::new()),
            }),
        );

        let list = collector.collect_processes_for_test(&ProcessQuery::default());
        assert!(list.scan_failed);
        assert!(!list.filter_complete);
        assert_eq!(list.collection_status, CollectionStatus::Failed);
        assert_eq!(list.failed_process_count, 0);
        assert!(list.meta.warnings.len() <= MAX_PROCESS_WARNINGS);
        assert!(list
            .meta
            .warnings
            .iter()
            .any(|warning| warning.contains("process list")));
    }

    #[test]
    fn process_limit_sorting_and_nss_lookup_budget_are_bounded() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let clock = Arc::new(ManualClock::new(1_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: (1..=505)
                .map(|uid| (uid, Ok(Some(format!("user-{uid}")))))
                .collect(),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock,
            ProcessSystemParameters::default(),
            resolver.clone(),
        );
        for pid in (1..=505).rev() {
            write_process_fixture(
                &proc_root,
                pid,
                &process_stat(pid, "worker", 1, 0, 1, 1),
                pid,
                None,
            );
        }

        let query = ProcessQuery {
            limit: Some(MAX_PROCESS_LIMIT),
            ..ProcessQuery::default()
        };
        let list = collector.collect_processes_for_test(&query);
        assert_eq!(list.total, 505);
        assert!(list.truncated);
        assert_eq!(list.processes.len(), MAX_PROCESS_LIMIT);
        assert_eq!(list.processes.first().map(|process| process.pid), Some(1));
        assert_eq!(list.processes.last().map(|process| process.pid), Some(500));
        assert_eq!(list.failed_process_count, 0);
        assert_eq!(
            list.partial_process_count,
            MAX_PROCESS_LIMIT - MAX_NSS_LOOKUPS_PER_COLLECTION
        );
        assert_eq!(list.collection_status, CollectionStatus::Partial);
        assert_eq!(list.meta.warnings.len(), MAX_PROCESS_WARNINGS);
        assert_eq!(
            list.omitted_warning_count,
            MAX_PROCESS_LIMIT - MAX_NSS_LOOKUPS_PER_COLLECTION - MAX_PROCESS_WARNINGS
        );
        assert_eq!(
            resolver.calls.lock().expect("resolver calls").len(),
            MAX_NSS_LOOKUPS_PER_COLLECTION
        );
        assert!(list.processes.iter().any(|process| {
            process.user.as_deref() == Some(process.uid.expect("uid").to_string().as_str())
        }));

        let second = collector.collect_processes_for_test(&query);
        assert_eq!(
            resolver.calls.lock().expect("resolver calls").len(),
            2 * MAX_NSS_LOOKUPS_PER_COLLECTION
        );
        assert_eq!(
            second.partial_process_count,
            MAX_PROCESS_LIMIT - 2 * MAX_NSS_LOOKUPS_PER_COLLECTION
        );
    }

    #[test]
    fn pid_filter_resolves_only_the_returned_process_user() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let clock = Arc::new(ManualClock::new(1_000));
        let target_uid = 10_000;
        let resolver = Arc::new(FixtureUserResolver {
            responses: (1..=40)
                .map(|uid| (uid, Ok(Some(format!("user-{uid}")))))
                .chain([(target_uid, Ok(Some("target-user".to_string())))])
                .collect(),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock,
            ProcessSystemParameters::default(),
            resolver.clone(),
        );
        for pid in 1..=40 {
            write_process_fixture(
                &proc_root,
                pid,
                &process_stat(pid, "unrelated", 1, 0, pid as u64, 1),
                pid,
                None,
            );
        }
        write_process_fixture(
            &proc_root,
            1_000,
            &process_stat(1_000, "target", 1, 0, 1_000, 1),
            target_uid,
            None,
        );

        let list = collector.collect_processes_for_test(&ProcessQuery {
            pid: Some(1_000),
            ..ProcessQuery::default()
        });

        assert_eq!(list.total, 1);
        assert_eq!(list.processes[0].user.as_deref(), Some("target-user"));
        assert_eq!(list.partial_process_count, 0);
        assert_eq!(list.collection_status, CollectionStatus::Complete);
        assert_eq!(
            resolver.calls.lock().expect("resolver calls").as_slice(),
            &[target_uid]
        );
    }

    #[test]
    fn process_filters_support_each_dimension_and_composable_and_semantics() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let clock = Arc::new(ManualClock::new(1_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::from([
                (100, Ok(Some("alice".to_string()))),
                (200, Ok(Some("bob".to_string()))),
                (300, Ok(Some("alice".to_string()))),
            ]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock,
            ProcessSystemParameters::default(),
            resolver.clone(),
        );
        for (pid, name, state, ppid, uid) in [
            (10, "AlphaWorker", "R", 1, 100),
            (20, "beta", "Z", 10, 200),
            (30, "gamma", "S", 10, 300),
        ] {
            write_process_fixture(
                &proc_root,
                pid,
                &process_stat_with_ppid(pid, name, state, ppid, 1, 0, pid as u64, 1),
                uid,
                None,
            );
        }

        let uid = collector.collect_processes_for_test(&ProcessQuery {
            uid: Some(200),
            ..ProcessQuery::default()
        });
        assert_eq!(
            uid.processes
                .iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>(),
            vec![20]
        );
        assert_eq!(
            resolver.calls.lock().expect("resolver calls").as_slice(),
            &[200]
        );

        let name = collector.collect_processes_for_test(&ProcessQuery {
            name_contains: Some("ALPHA".to_string()),
            ..ProcessQuery::default()
        });
        assert_eq!(name.processes[0].pid, 10);
        let command = collector.collect_processes_for_test(&ProcessQuery {
            name_contains: Some("--SERVE".to_string()),
            ..ProcessQuery::default()
        });
        assert_eq!(command.total, 3);

        let parent = collector.collect_processes_for_test(&ProcessQuery {
            ppid: Some(10),
            limit: Some(1),
            ..ProcessQuery::default()
        });
        assert_eq!(parent.total, 2);
        assert_eq!(parent.processes.len(), 1);
        assert_eq!(parent.anomaly_count, 1);

        let state = collector.collect_processes_for_test(&ProcessQuery {
            state: Some(" Z ".to_string()),
            ..ProcessQuery::default()
        });
        assert_eq!(state.processes[0].pid, 20);
        let anomaly = collector.collect_processes_for_test(&ProcessQuery {
            anomaly_kind: Some("zombie_process".to_string()),
            ..ProcessQuery::default()
        });
        assert_eq!(anomaly.processes[0].pid, 20);

        let unauthorized = collector.collect_processes_for_test(&ProcessQuery {
            authorized: Some(false),
            allowed_names: vec!["AlphaWorker".to_string()],
            ..ProcessQuery::default()
        });
        assert_eq!(
            unauthorized
                .processes
                .iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>(),
            vec![20, 30]
        );

        let alice = collector.collect_processes_for_test(&ProcessQuery {
            user: Some("alice".to_string()),
            ..ProcessQuery::default()
        });
        assert_eq!(
            alice
                .processes
                .iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>(),
            vec![10, 30]
        );
        let wrong_case = collector.collect_processes_for_test(&ProcessQuery {
            user: Some("Alice".to_string()),
            ..ProcessQuery::default()
        });
        assert_eq!(wrong_case.total, 0);

        let combined_query = ProcessQuery {
            pid: Some(20),
            ppid: Some(10),
            uid: Some(200),
            name_contains: Some("BETA".to_string()),
            user: Some("bob".to_string()),
            state: Some("Z".to_string()),
            anomaly_kind: Some("zombie_process".to_string()),
            authorized: Some(false),
            allowed_names: vec!["AlphaWorker".to_string()],
            limit: Some(1),
        };
        combined_query.validate().expect("combined query");
        let combined = collector.collect_processes_for_test(&combined_query);
        assert_eq!(combined.processes.len(), 1);
        assert_eq!(combined.processes[0].pid, 20);
        assert_eq!(combined.total, 1);
        assert!(combined.filter_complete);
    }

    #[test]
    fn process_query_validation_rejects_invalid_filters_and_limits() {
        let invalid = [
            ProcessQuery {
                name_contains: Some("  ".to_string()),
                ..ProcessQuery::default()
            },
            ProcessQuery {
                user: Some("\t".to_string()),
                ..ProcessQuery::default()
            },
            ProcessQuery {
                anomaly_kind: Some(String::new()),
                ..ProcessQuery::default()
            },
            ProcessQuery {
                name_contains: Some("n".repeat(129)),
                ..ProcessQuery::default()
            },
            ProcessQuery {
                user: Some("u".repeat(65)),
                ..ProcessQuery::default()
            },
            ProcessQuery {
                anomaly_kind: Some("a".repeat(65)),
                ..ProcessQuery::default()
            },
            ProcessQuery {
                allowed_names: vec!["name".to_string(); 201],
                ..ProcessQuery::default()
            },
            ProcessQuery {
                allowed_names: vec![" ".to_string()],
                ..ProcessQuery::default()
            },
            ProcessQuery {
                allowed_names: vec!["n".repeat(129)],
                ..ProcessQuery::default()
            },
            ProcessQuery {
                authorized: Some(true),
                ..ProcessQuery::default()
            },
            ProcessQuery {
                state: Some("Q".to_string()),
                ..ProcessQuery::default()
            },
            ProcessQuery {
                state: Some("SS".to_string()),
                ..ProcessQuery::default()
            },
            ProcessQuery {
                limit: Some(0),
                ..ProcessQuery::default()
            },
            ProcessQuery {
                limit: Some(MAX_PROCESS_LIMIT + 1),
                ..ProcessQuery::default()
            },
        ];
        for query in invalid {
            assert!(matches!(
                query.validate(),
                Err(OsSenseError::Configuration(_))
            ));
        }
        ProcessQuery {
            state: Some(" t ".to_string()),
            limit: Some(MAX_PROCESS_LIMIT),
            ..ProcessQuery::default()
        }
        .validate()
        .expect("valid Linux process state");

        let mut collector = ProcfsCollector::default();
        let error = collector
            .collect_processes(&ProcessQuery {
                limit: Some(0),
                ..ProcessQuery::default()
            })
            .expect_err("public collector entry validates queries");
        assert!(matches!(error, OsSenseError::Configuration(_)));
    }

    #[test]
    fn process_baseline_validation_is_versioned_strict_and_bounded() {
        let valid = ProcessBaseline::from_json_bytes(
            br#"{"version":1,"id":"kylin-prod","entries":[{"name":"worker","uid":42,"path":"/usr/bin/worker"}]}"#,
        )
        .expect("valid baseline");
        assert_eq!(valid.entries.len(), 1);
        ProcessBaseline {
            version: PROCESS_BASELINE_VERSION,
            id: "deny-all".to_string(),
            entries: Vec::new(),
        }
        .validate()
        .expect("explicit empty baseline");

        for value in [
            br#"{"version":2,"id":"bad-version","entries":[]}"#.as_slice(),
            br#"{"version":1,"id":"unknown","entries":[],"extra":true}"#.as_slice(),
            br#"{"version":1,"id":"relative","entries":[{"name":"worker","path":"usr/bin/worker"}]}"#.as_slice(),
            br#"{"version":1,"id":"parent","entries":[{"name":"worker","path":"/usr/../bin/worker"}]}"#.as_slice(),
        ] {
            assert!(matches!(
                ProcessBaseline::from_json_bytes(value),
                Err(OsSenseError::Configuration(_))
            ));
        }
        let too_many = ProcessBaseline {
            version: PROCESS_BASELINE_VERSION,
            id: "too-many".to_string(),
            entries: vec![
                ProcessBaselineEntry {
                    name: "worker".to_string(),
                    uid: None,
                    path: None,
                };
                MAX_PROCESS_BASELINE_ENTRIES + 1
            ],
        };
        assert!(too_many.validate().is_err());
        assert!(
            ProcessBaseline::from_json_bytes(&vec![b' '; MAX_PROCESS_BASELINE_JSON_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn structured_baseline_matches_and_rejects_legacy_override() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let mut collector = process_collector(
            root.path(),
            Arc::new(ManualClock::new(1_000)),
            ProcessSystemParameters::default(),
            Arc::new(FixtureUserResolver {
                responses: BTreeMap::new(),
                calls: Mutex::new(Vec::new()),
            }),
        );
        for (pid, name, uid) in [
            (1, "Worker", 100),
            (2, "Worker", 101),
            (3, "Worker", 100),
            (4, "helper", 200),
            (5, "legacy", 300),
        ] {
            write_process_fixture(
                &proc_root,
                pid,
                &process_stat(pid, name, 1, 0, pid as u64, 1),
                uid,
                None,
            );
        }
        let reader = Arc::new(ExecutablePathReader {
            fixtures: BTreeMap::from([
                (1, vec![ExecutablePathFixture::Path("/usr/bin/worker")]),
                (3, vec![ExecutablePathFixture::Path("/opt/worker")]),
            ]),
            stat_after_first_link: BTreeMap::new(),
            calls: Mutex::new(Vec::new()),
        });
        collector.process_file_reader = reader.clone();

        let without_baseline = collector.collect_processes_for_test(&ProcessQuery::default());
        assert!(without_baseline
            .processes
            .iter()
            .all(|process| process.authorized.is_none()));
        assert_eq!(without_baseline.unauthorized_total, 0);
        let legacy = collector.collect_processes_for_test(&ProcessQuery {
            allowed_names: vec!["legacy".to_string()],
            ..ProcessQuery::default()
        });
        assert_eq!(legacy.processes[4].authorized, Some(true));

        collector
            .set_process_baseline(Some(ProcessBaseline {
                version: PROCESS_BASELINE_VERSION,
                id: "kylin-prod".to_string(),
                entries: vec![
                    ProcessBaselineEntry {
                        name: "worker".to_string(),
                        uid: Some(100),
                        path: Some("/usr/bin/worker".to_string()),
                    },
                    ProcessBaselineEntry {
                        name: "helper".to_string(),
                        uid: Some(200),
                        path: None,
                    },
                ],
            }))
            .expect("configured baseline");
        assert!(matches!(
            collector.collect_processes(&ProcessQuery {
                allowed_names: vec!["legacy".to_string()],
                ..ProcessQuery::default()
            }),
            Err(OsSenseError::Configuration(_))
        ));
        let list = collector.collect_processes_for_test(&ProcessQuery::default());

        assert_eq!(
            list.processes
                .iter()
                .map(|process| (process.pid, process.authorized))
                .collect::<Vec<_>>(),
            vec![
                (1, Some(true)),
                (2, Some(false)),
                (3, Some(false)),
                (4, Some(true)),
                (5, Some(false)),
            ]
        );
        assert_eq!(
            list.processes[0].executable_path.as_deref(),
            Some("/usr/bin/worker")
        );
        assert_eq!(list.unauthorized_total, 3);
        assert_eq!(
            list.unauthorized
                .iter()
                .map(|process| process.pid)
                .collect::<Vec<_>>(),
            vec![2, 3, 5]
        );
        assert!(list
            .unauthorized
            .iter()
            .all(|process| process.command.is_none()));
        assert_eq!(
            reader.calls.lock().expect("executable calls").as_slice(),
            &[1, 1, 3, 3]
        );
        assert!(matches!(
            list.unauthorized[0]
                .anomalies
                .iter()
                .find(|anomaly| anomaly.kind == "unauthorized_process")
                .and_then(|anomaly| anomaly.evidence.as_ref()),
            Some(ProcessAnomalyEvidence::Authorization {
                baseline_id,
                baseline_version: PROCESS_BASELINE_VERSION,
                name,
                uid: Some(101),
                executable_path: None,
            }) if baseline_id == "kylin-prod" && name == "Worker"
        ));
        collector
            .set_process_baseline(Some(ProcessBaseline {
                version: PROCESS_BASELINE_VERSION,
                id: "deny-all".to_string(),
                entries: Vec::new(),
            }))
            .expect("empty configured baseline");
        assert!(matches!(
            collector.collect_processes(&ProcessQuery {
                allowed_names: vec!["worker".to_string()],
                ..ProcessQuery::default()
            }),
            Err(OsSenseError::Configuration(_))
        ));
    }

    #[test]
    fn authorization_failures_are_indeterminate_and_summary_is_hard_bounded() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let mut collector = process_collector(
            root.path(),
            Arc::new(ManualClock::new(1_000)),
            ProcessSystemParameters::default(),
            Arc::new(FixtureUserResolver {
                responses: BTreeMap::new(),
                calls: Mutex::new(Vec::new()),
            }),
        );
        for pid in 1..=6 {
            write_process_fixture(
                &proc_root,
                pid,
                &process_stat(pid, "worker", 1, 0, pid as u64, 1),
                42,
                None,
            );
        }
        fs::write(proc_root.join("3/status"), "Name:\tworker\n").expect("missing UID status");
        collector.process_file_reader = Arc::new(ExecutablePathReader {
            fixtures: BTreeMap::from([
                (
                    1,
                    vec![ExecutablePathFixture::Error(
                        std::io::ErrorKind::PermissionDenied,
                    )],
                ),
                (
                    2,
                    vec![ExecutablePathFixture::Error(std::io::ErrorKind::NotFound)],
                ),
                (
                    4,
                    vec![ExecutablePathFixture::Path("/usr/bin/worker (deleted)")],
                ),
                (5, vec![ExecutablePathFixture::Path("/usr/bin/worker")]),
                (
                    6,
                    vec![
                        ExecutablePathFixture::Path("/usr/bin/worker"),
                        ExecutablePathFixture::Path("/opt/worker"),
                    ],
                ),
            ]),
            stat_after_first_link: BTreeMap::from([(5, process_stat(5, "worker", 1, 0, 999, 1))]),
            calls: Mutex::new(Vec::new()),
        });
        collector
            .set_process_baseline(Some(ProcessBaseline {
                version: PROCESS_BASELINE_VERSION,
                id: "strict".to_string(),
                entries: vec![ProcessBaselineEntry {
                    name: "worker".to_string(),
                    uid: Some(42),
                    path: Some("/usr/bin/worker".to_string()),
                }],
            }))
            .expect("strict baseline");
        let indeterminate = collector.collect_processes_for_test(&ProcessQuery {
            authorized: Some(false),
            ..ProcessQuery::default()
        });
        assert_eq!(indeterminate.authorization_indeterminate_count, 6);
        assert_eq!(indeterminate.indeterminate_filter_count, 6);
        assert_eq!(indeterminate.unauthorized_total, 0);
        assert!(!indeterminate.filter_complete);
        assert_eq!(indeterminate.collection_status, CollectionStatus::Partial);

        let large_root = tempfile::tempdir().expect("large tempdir");
        let large_proc = large_root.path().join("proc");
        let mut large = process_collector(
            large_root.path(),
            Arc::new(ManualClock::new(1_000)),
            ProcessSystemParameters::default(),
            Arc::new(LocalFixtureUserResolver {
                local: BTreeMap::from([(0, "root".to_string())]),
                calls: Mutex::new(Vec::new()),
            }),
        );
        for pid in 1..=140 {
            write_process_fixture(
                &large_proc,
                pid,
                &process_stat(pid, "worker", 1, 0, pid as u64, 1),
                0,
                None,
            );
        }
        large
            .set_process_baseline(Some(ProcessBaseline {
                version: PROCESS_BASELINE_VERSION,
                id: "deny-all".to_string(),
                entries: Vec::new(),
            }))
            .expect("deny-all baseline");
        let bounded = large.collect_processes_for_test(&ProcessQuery {
            limit: Some(1),
            ..ProcessQuery::default()
        });
        assert_eq!(bounded.processes.len(), 1);
        assert_eq!(bounded.unauthorized_total, 140);
        assert_eq!(bounded.unauthorized.len(), MAX_UNAUTHORIZED_PROCESS_SUMMARY);
        assert!(bounded.unauthorized_truncated);
        assert_eq!(bounded.omitted_unauthorized_count, 12);
        assert_eq!(
            bounded.unauthorized.first().map(|process| process.pid),
            Some(1)
        );
        assert_eq!(
            bounded.unauthorized.last().map(|process| process.pid),
            Some(128)
        );
        let filtered = large.collect_processes_for_test(&ProcessQuery {
            pid: Some(140),
            user: Some("root".to_string()),
            limit: Some(1),
            ..ProcessQuery::default()
        });
        assert_eq!(filtered.total, 1);
        assert_eq!(filtered.unauthorized_total, 1);
        assert_eq!(filtered.unauthorized[0].pid, 140);
    }

    #[test]
    fn local_and_cached_user_hits_do_not_consume_nss_budget() {
        let root = tempfile::tempdir().expect("tempdir");
        let clock = Arc::new(ManualClock::new(1_000));
        let resolver = Arc::new(LocalFixtureUserResolver {
            local: BTreeMap::from([(7, "local-user".to_string())]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock,
            ProcessSystemParameters::default(),
            resolver.clone(),
        );
        let mut budget = 0;
        let local = collector.resolve_process_user(7, &mut budget);
        assert_eq!(local.user, "local-user");
        assert_eq!(budget, 0);
        let cached = collector.resolve_process_user(7, &mut budget);
        assert_eq!(cached.user, "local-user");
        assert_eq!(budget, 0);
        assert!(resolver.calls.lock().expect("resolver calls").is_empty());
    }

    #[test]
    fn user_filter_budget_omits_indeterminate_candidates_and_marks_partial() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let clock = Arc::new(ManualClock::new(1_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: (1..=20)
                .map(|uid| (uid, Ok(Some("resolved-other-user".to_string()))))
                .collect(),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock,
            ProcessSystemParameters::default(),
            resolver.clone(),
        );
        for pid in 1..=20 {
            write_process_fixture(
                &proc_root,
                pid,
                &process_stat(pid, "worker", 1, 0, pid as u64, 1),
                pid,
                None,
            );
        }

        let list = collector.collect_processes_for_test(&ProcessQuery {
            user: Some("target-user".to_string()),
            ..ProcessQuery::default()
        });

        assert_eq!(
            resolver.calls.lock().expect("resolver calls").len(),
            MAX_NSS_LOOKUPS_PER_COLLECTION
        );
        assert_eq!(list.total, 0);
        assert_eq!(list.partial_process_count, 0);
        assert_eq!(
            list.indeterminate_filter_count,
            20 - MAX_NSS_LOOKUPS_PER_COLLECTION
        );
        assert!(!list.filter_complete);
        assert_eq!(list.collection_status, CollectionStatus::Partial);
        assert!(list.processes.is_empty());
        assert!(list.meta.warnings.iter().any(|warning| {
            warning.contains("user filter")
                && warning.contains("indeterminate")
                && warning.contains("omitted")
        }));
    }

    #[test]
    fn failed_process_read_breaks_anomaly_continuity() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let process_root = proc_root.join("77");
        let clock = Arc::new(ManualClock::new(0));
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::from([(0, Ok(Some("root".to_string())))]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock.clone(),
            ProcessSystemParameters::default(),
            resolver,
        );

        for (sampled_at_ms, rss_kb) in [(0, 100_000), (30_000, 140_000)] {
            clock.set(sampled_at_ms);
            write_process_fixture(
                &proc_root,
                77,
                &process_stat(77, "worker", sampled_at_ms / 10, 0, 700, 1),
                0,
                Some(rss_kb),
            );
            assert!(collector
                .collect_processes_for_test(&ProcessQuery::default())
                .anomalies
                .is_empty());
        }

        clock.set(60_000);
        fs::write(process_root.join("stat"), "malformed process stat\n")
            .expect("malformed stat fixture");
        let failed = collector.collect_processes_for_test(&ProcessQuery::default());
        assert_eq!(failed.failed_process_count, 1);
        assert!(!failed.filter_complete);
        assert!(!collector.process_anomaly_states.contains_key(&77));

        for (sampled_at_ms, rss_kb) in [(90_000, 180_000), (150_000, 260_000)] {
            clock.set(sampled_at_ms);
            write_process_fixture(
                &proc_root,
                77,
                &process_stat(77, "worker", sampled_at_ms / 10, 0, 700, 1),
                0,
                Some(rss_kb),
            );
            let recovered = collector.collect_processes_for_test(&ProcessQuery::default());
            assert!(recovered
                .anomalies
                .iter()
                .all(|anomaly| anomaly.kind != "memory_leak_pattern"));
        }
        assert_eq!(
            collector.process_anomaly_states[&77]
                .memory_growth
                .expect("recovered memory state")
                .sample_count,
            2
        );
    }

    #[test]
    fn process_list_anomalies_cover_the_filtered_domain_with_a_hard_limit() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let clock = Arc::new(ManualClock::new(1_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::from([(0, Ok(Some("root".to_string())))]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector(
            root.path(),
            clock,
            ProcessSystemParameters::default(),
            resolver,
        );
        for pid in 1..=130 {
            write_process_fixture(
                &proc_root,
                pid,
                &process_stat_with_state(pid, "zombie", "Z", 1, 0, pid as u64, 1),
                0,
                None,
            );
        }

        let list = collector.collect_processes_for_test(&ProcessQuery {
            limit: Some(1),
            ..ProcessQuery::default()
        });

        assert_eq!(list.processes.len(), 1);
        assert_eq!(list.processes[0].pid, 1);
        assert_eq!(list.anomaly_count, 130);
        assert_eq!(list.anomalies.len(), MAX_PROCESS_LIST_ANOMALIES);
        assert!(list.anomalies_truncated);
        assert_eq!(list.omitted_anomaly_count, 2);
        assert_eq!(list.anomalies.last().map(|anomaly| anomaly.pid), Some(128));
    }

    #[test]
    fn legacy_process_json_defaults_new_sample_fields() {
        let process: ProcessInfo = serde_json::from_str(
            r#"{"pid":1,"ppid":null,"name":"init","state":"S","user":"root","cpu_time_jiffies":10,"memory_rss_kb":20,"virtual_memory_kb":30,"uptime_seconds":40.0,"command":null,"anomalies":[],"authorized":null}"#,
        )
        .expect("legacy process");
        assert_eq!(process.start_time_jiffies, 0);
        assert_eq!(process.cpu_usage_percent, None);
        assert_eq!(process.cpu_rate_status, None);
        assert_eq!(process.memory_percent, None);
        assert_eq!(process.uid, None);
        assert_eq!(process.executable_path, None);

        let list: ProcessList = serde_json::from_value(serde_json::json!({
            "meta": basic_meta("procfs", Vec::new()),
            "total": 1,
            "truncated": false,
            "processes": [process],
            "anomalies": [],
            "unauthorized": []
        }))
        .expect("legacy process list");
        assert_eq!(list.failed_process_count, 0);
        assert_eq!(list.partial_process_count, 0);
        assert_eq!(list.exited_during_scan_count, 0);
        assert_eq!(list.omitted_warning_count, 0);
        assert_eq!(list.anomaly_count, 0);
        assert!(!list.anomalies_truncated);
        assert_eq!(list.omitted_anomaly_count, 0);
        assert_eq!(list.indeterminate_filter_count, 0);
        assert_eq!(list.authorization_indeterminate_count, 0);
        assert_eq!(list.unauthorized_total, 0);
        assert!(!list.unauthorized_truncated);
        assert_eq!(list.omitted_unauthorized_count, 0);
        assert!(list.filter_complete);
        assert!(!list.scan_failed);
        assert_eq!(list.collection_status, CollectionStatus::Partial);

        let query: ProcessQuery =
            serde_json::from_value(serde_json::json!({"pid": 1})).expect("legacy query");
        assert_eq!(query.pid, Some(1));
        assert_eq!(query.ppid, None);
        assert_eq!(query.uid, None);
        assert_eq!(query.state, None);
        assert_eq!(query.anomaly_kind, None);
        assert_eq!(query.authorized, None);
    }

    #[test]
    fn detects_zombie_and_unauthorized_process() {
        let mut info = ProcessInfo {
            pid: 42,
            ppid: Some(1),
            name: "unknown".to_string(),
            state: "Z".to_string(),
            user: None,
            uid: None,
            cpu_time_jiffies: 0,
            start_time_jiffies: 0,
            cpu_usage_percent: None,
            cpu_sample_interval_ms: None,
            cpu_rate_status: None,
            memory_rss_kb: None,
            memory_percent: None,
            virtual_memory_kb: None,
            uptime_seconds: None,
            command: None,
            executable_path: None,
            anomalies: Vec::new(),
            authorized: Some(false),
        };
        info.anomalies = update_process_anomaly_state(&mut BTreeMap::new(), &info, 1_000);
        assert!(info
            .anomalies
            .iter()
            .any(|anomaly| anomaly.kind == "zombie_process"));
        assert!(matches!(
            info.anomalies[0].evidence,
            Some(ProcessAnomalyEvidence::ProcessState { ref state }) if state == "Z"
        ));
    }

    #[test]
    fn sustained_samples_detect_memory_leak_and_cpu_busy_loop_with_evidence() {
        let mut states = BTreeMap::new();
        let samples = [
            (0, 100_000, 95.0),
            (30_000, 140_000, 100.0),
            (60_000, 180_000, 125.0),
        ];

        for (index, (sampled_at_ms, rss_kb, cpu_percent)) in samples.into_iter().enumerate() {
            let process = process_info_for_anomaly(
                42,
                1_000,
                "S",
                Some(rss_kb),
                Some(cpu_percent),
                Some(RateStatus::Ready),
            );
            let anomalies = update_process_anomaly_state(&mut states, &process, sampled_at_ms);
            if index < 2 {
                assert!(anomalies.is_empty(), "two samples must remain insufficient");
                continue;
            }

            assert_eq!(
                anomalies
                    .iter()
                    .map(|anomaly| anomaly.kind.as_str())
                    .collect::<Vec<_>>(),
                vec!["memory_leak_pattern", "cpu_busy_loop"]
            );
            assert_eq!(anomalies[0].score, 0.9);
            assert_eq!(
                anomalies[0].message,
                "process `process-42` RSS grew from 100000 kB to 180000 kB over 60000 ms across 3 samples"
            );
            assert!(matches!(
                anomalies[0].evidence,
                Some(ProcessAnomalyEvidence::MemoryRss {
                    sample_count: 3,
                    observed_duration_ms: 60_000,
                    absolute_growth_kb: 80_000,
                    relative_growth_percent: 80.0,
                    ..
                })
            ));
            assert_eq!(anomalies[1].score, 0.9);
            assert_eq!(
                anomalies[1].message,
                "process `process-42` sustained at least 95.00% CPU for 60000 ms across 3 samples"
            );
            assert!(matches!(
                anomalies[1].evidence,
                Some(ProcessAnomalyEvidence::CpuUsage {
                    sample_count: 3,
                    observed_duration_ms: 60_000,
                    minimum_usage_percent: 95.0,
                    latest_usage_percent: 125.0,
                    ..
                })
            ));
            assert!(anomalies.iter().all(|anomaly| {
                anomaly.kind != "high_memory_process" && anomaly.kind != "possible_cpu_spin"
            }));
        }
    }

    #[test]
    fn process_pattern_state_resets_on_invalid_samples_and_pid_reuse() {
        let mut memory_states = BTreeMap::new();
        for (sampled_at_ms, rss_kb) in [(0, Some(100_000)), (30_000, Some(140_000))] {
            let process =
                process_info_for_anomaly(7, 100, "S", rss_kb, None, Some(RateStatus::WarmingUp));
            assert!(
                update_process_anomaly_state(&mut memory_states, &process, sampled_at_ms)
                    .is_empty()
            );
        }
        let declined =
            process_info_for_anomaly(7, 100, "S", Some(90_000), None, Some(RateStatus::WarmingUp));
        assert!(update_process_anomaly_state(&mut memory_states, &declined, 60_000).is_empty());
        assert_eq!(
            memory_states[&7]
                .memory_growth
                .expect("memory state after decline")
                .sample_count,
            1
        );
        let missing =
            process_info_for_anomaly(7, 100, "S", None, None, Some(RateStatus::WarmingUp));
        update_process_anomaly_state(&mut memory_states, &missing, 90_000);
        assert!(memory_states[&7].memory_growth.is_none());

        let mut cpu_states = BTreeMap::new();
        for sampled_at_ms in [0, 30_000] {
            let process = process_info_for_anomaly(
                9,
                200,
                "S",
                Some(1_000),
                Some(100.0),
                Some(RateStatus::Ready),
            );
            assert!(
                update_process_anomaly_state(&mut cpu_states, &process, sampled_at_ms)
                    .iter()
                    .all(|anomaly| anomaly.kind != "cpu_busy_loop")
            );
        }
        let low = process_info_for_anomaly(
            9,
            200,
            "S",
            Some(1_000),
            Some(10.0),
            Some(RateStatus::Ready),
        );
        update_process_anomaly_state(&mut cpu_states, &low, 60_000);
        assert!(cpu_states[&9].cpu_busy.is_none());

        for (sampled_at_ms, status) in [
            (90_000, RateStatus::Ready),
            (120_000, RateStatus::Ready),
            (150_000, RateStatus::WarmingUp),
            (180_000, RateStatus::Ready),
            (210_000, RateStatus::Ready),
            (240_000, RateStatus::CounterReset),
        ] {
            let process =
                process_info_for_anomaly(9, 200, "S", Some(1_000), Some(100.0), Some(status));
            assert!(
                update_process_anomaly_state(&mut cpu_states, &process, sampled_at_ms)
                    .iter()
                    .all(|anomaly| anomaly.kind != "cpu_busy_loop")
            );
        }
        assert!(cpu_states[&9].cpu_busy.is_none());

        let reused = process_info_for_anomaly(
            9,
            201,
            "S",
            Some(500_000),
            Some(100.0),
            Some(RateStatus::Ready),
        );
        let anomalies = update_process_anomaly_state(&mut cpu_states, &reused, 300_000);
        assert!(anomalies.is_empty());
        assert_eq!(cpu_states[&9].start_time_jiffies, 201);
        assert_eq!(
            cpu_states[&9]
                .cpu_busy
                .expect("reused CPU state")
                .sample_count,
            1
        );
        assert_eq!(
            cpu_states[&9]
                .memory_growth
                .expect("reused memory state")
                .sample_count,
            1
        );
    }

    #[test]
    fn process_anomaly_state_ttl_and_cap_are_stable() {
        let mut states = BTreeMap::new();
        let mut order = BTreeSet::new();
        for (pid, sampled_at_ms) in [(1, 100), (2, 200), (3, 200)] {
            let process = process_info_for_anomaly(
                pid,
                pid as u64,
                "S",
                Some(1_000),
                None,
                Some(RateStatus::WarmingUp),
            );
            update_bounded_process_anomaly_state(
                &mut states,
                &mut order,
                &process,
                sampled_at_ms,
                3,
            );
        }

        enforce_process_anomaly_state_limit(&mut states, &mut order, 2);
        assert_eq!(states.keys().copied().collect::<Vec<_>>(), vec![2, 3]);
        let process =
            process_info_for_anomaly(4, 4, "S", Some(1_000), None, Some(RateStatus::WarmingUp));
        update_bounded_process_anomaly_state(&mut states, &mut order, &process, 200, 2);
        assert_eq!(states.keys().copied().collect::<Vec<_>>(), vec![3, 4]);

        prune_process_anomaly_states(
            &mut states,
            &mut order,
            200 + PROCESS_ANOMALY_STATE_TTL_MS,
            PROCESS_ANOMALY_STATE_TTL_MS,
            2,
        );
        assert!(states.is_empty(), "states expire at the exact TTL boundary");
        assert!(order.is_empty());
    }

    #[test]
    fn process_scan_buffers_and_states_enforce_small_caps_after_each_insert() {
        let mut candidates = BTreeMap::new();
        let mut anomalies = BTreeMap::new();
        let mut unauthorized = BTreeMap::new();
        let mut total = 0;
        let mut anomaly_count = 0;
        let mut unauthorized_total = 0;
        let mut partial_process_count = 0;
        let mut warnings = Vec::new();
        let mut omitted_warning_count = 0;
        for pid in (1..=6).rev() {
            let mut process = process_info_for_anomaly(
                pid,
                pid as u64,
                "Z",
                Some(1_000),
                None,
                Some(RateStatus::WarmingUp),
            );
            process.anomalies = vec![ProcessAnomaly {
                pid,
                kind: "zombie_process".to_string(),
                message: "fixture".to_string(),
                score: 1.0,
                evidence: None,
            }];
            record_process_candidate(
                &mut candidates,
                &mut anomalies,
                &mut unauthorized,
                &mut total,
                &mut anomaly_count,
                &mut unauthorized_total,
                &mut partial_process_count,
                &mut warnings,
                &mut omitted_warning_count,
                process,
                Vec::new(),
                3,
                2,
                2,
            );
            assert!(candidates.len() <= 3);
            assert!(anomalies.len() <= 2);
        }
        assert_eq!(total, 6);
        assert_eq!(anomaly_count, 6);
        assert_eq!(anomaly_count - anomalies.len(), 4);
        assert_eq!(
            candidates.keys().copied().collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            anomalies.keys().map(|(pid, _)| *pid).collect::<Vec<_>>(),
            vec![1, 2]
        );

        let mut baselines = BTreeMap::new();
        let mut baseline_order = BTreeSet::new();
        for pid in (1..=256).rev() {
            insert_process_cpu_baseline(
                &mut baselines,
                &mut baseline_order,
                pid,
                ProcessCpuBaseline {
                    start_time_jiffies: pid as u64,
                    cpu_time_jiffies: 1,
                    sampled_at_ms: 100,
                    scan_id: 1,
                },
                7,
            );
            assert!(baselines.len() <= 7);
            assert_eq!(baselines.len(), baseline_order.len());
            assert_eq!(
                baseline_order,
                baselines
                    .iter()
                    .map(|(pid, baseline)| (baseline.sampled_at_ms, *pid))
                    .collect()
            );
        }
        assert_eq!(
            baselines.keys().copied().collect::<Vec<_>>(),
            (250..=256).collect::<Vec<_>>()
        );

        let mut states = BTreeMap::new();
        let mut state_order = BTreeSet::new();
        for pid in (1..=256).rev() {
            let process = process_info_for_anomaly(
                pid,
                pid as u64,
                "S",
                Some(1_000),
                None,
                Some(RateStatus::WarmingUp),
            );
            update_bounded_process_anomaly_state(&mut states, &mut state_order, &process, 100, 7);
            assert!(states.len() <= 7);
            assert_eq!(states.len(), state_order.len());
            assert_eq!(
                state_order,
                states
                    .iter()
                    .map(|(pid, state)| (state.sampled_at_ms, *pid))
                    .collect()
            );
        }
        assert_eq!(
            states.keys().copied().collect::<Vec<_>>(),
            (250..=256).collect::<Vec<_>>()
        );
    }

    #[test]
    fn process_patterns_use_monotonic_time_and_survive_filtering_and_limit() {
        let root = tempfile::tempdir().expect("tempdir");
        let proc_root = root.path().join("proc");
        let wall_clock = Arc::new(ManualClock::new(1_000));
        let monotonic_clock = Arc::new(ManualClock::new(10_000));
        let resolver = Arc::new(FixtureUserResolver {
            responses: BTreeMap::from([(0, Ok(Some("root".to_string())))]),
            calls: Mutex::new(Vec::new()),
        });
        let mut collector = process_collector_with_clocks(
            root.path(),
            wall_clock.clone(),
            monotonic_clock.clone(),
            ProcessSystemParameters::default(),
            resolver,
        );
        write_process_fixture(
            &proc_root,
            1,
            &process_stat(1, "stable", 0, 0, 100, 10),
            0,
            Some(1_000),
        );

        let walls = [1_000, 9_000_000_000, 10, 500];
        let rss_samples = [100_000, 140_000, 180_000, 200_000];
        for (index, (&wall_ms, &rss_kb)) in walls.iter().zip(&rss_samples).enumerate() {
            wall_clock.set(wall_ms);
            monotonic_clock.set(10_000 + index as u64 * 30_000);
            write_process_fixture(
                &proc_root,
                2,
                &process_stat(2, "target", index as u64 * 3_000, 0, 200, 10),
                0,
                Some(rss_kb),
            );
            let query = if index < 3 {
                ProcessQuery {
                    pid: Some(1),
                    limit: Some(1),
                    ..ProcessQuery::default()
                }
            } else {
                ProcessQuery {
                    limit: Some(1),
                    ..ProcessQuery::default()
                }
            };
            let list = collector.collect_processes_for_test(&query);
            assert_eq!(list.meta.collected_at_ms, wall_ms);
            assert_eq!(list.processes.len(), 1);
            assert_eq!(list.processes[0].pid, 1);
            if index == 3 {
                assert_eq!(list.anomaly_count, 2);
                assert!(!list.anomalies_truncated);
                assert_eq!(list.omitted_anomaly_count, 0);
                assert!(list.anomalies.iter().all(|anomaly| anomaly.pid == 2));
                assert!(list
                    .anomalies
                    .iter()
                    .any(|anomaly| anomaly.kind == "memory_leak_pattern"));
                assert!(list
                    .anomalies
                    .iter()
                    .any(|anomaly| anomaly.kind == "cpu_busy_loop"));
            }
        }
        assert!(collector.process_anomaly_states[&2]
            .memory_growth
            .is_some_and(|state| state.sample_count == 4));
        assert!(collector.process_anomaly_states[&2]
            .cpu_busy
            .is_some_and(|state| state.sample_count == 3));

        wall_clock.set(25);
        monotonic_clock.set(130_000);
        write_process_fixture(
            &proc_root,
            2,
            &process_stat(2, "target", 12_000, 0, 200, 10),
            0,
            Some(220_000),
        );
        let target = collector.collect_processes_for_test(&ProcessQuery {
            pid: Some(2),
            ..ProcessQuery::default()
        });
        assert_eq!(target.meta.collected_at_ms, 25);
        assert_eq!(target.processes.len(), 1);
        assert_eq!(target.processes[0].pid, 2);
        assert!(target
            .anomalies
            .iter()
            .any(|anomaly| { anomaly.pid == 2 && anomaly.kind == "memory_leak_pattern" }));
        assert!(target
            .anomalies
            .iter()
            .any(|anomaly| anomaly.pid == 2 && anomaly.kind == "cpu_busy_loop"));

        fs::remove_dir_all(proc_root.join("2")).expect("remove exited process fixture");
        monotonic_clock.set(160_000);
        collector.collect_processes_for_test(&ProcessQuery::default());
        assert!(!collector.process_anomaly_states.contains_key(&2));
    }

    #[test]
    fn legacy_process_anomaly_json_defaults_evidence() {
        let anomaly: ProcessAnomaly = serde_json::from_value(serde_json::json!({
            "pid": 9,
            "kind": "zombie_process",
            "message": "legacy",
            "score": 1.0
        }))
        .expect("legacy anomaly");
        assert_eq!(anomaly.evidence, None);
    }

    #[test]
    fn loongarch_platform_reads_hwmon_sensor_values() {
        let root = tempfile::tempdir().expect("tempdir");
        let (proc_root, sys_root) = write_resource_fixture(root.path());
        let hwmon_root = sys_root.join("class/hwmon").join("hwmon0");
        let clock = Arc::new(ManualClock::new(1_000));
        let mut collector = ProcfsCollector::with_dependencies(
            proc_root,
            sys_root,
            clock,
            Arc::new(StaticPartitionUsage(DF_FIXTURE)),
        );

        let snapshot = collector.collect_metrics(&MetricsThresholds::default());
        let platform = &snapshot.meta.platform;
        assert!(platform.loongarch.detected);
        assert!(snapshot.thermal.hwmon_available);
        assert_eq!(
            platform.loongarch.hwmon_sensors,
            snapshot.thermal.hwmon_sensors
        );

        let expected = [
            ("curr1_input", "CPU Current", 2_500, "milliamps"),
            (
                "energy1_input",
                "Package Energy",
                123_456_789,
                "microjoules",
            ),
            ("fan1_input", "Chassis Fan", 1_800, "rpm"),
            ("freq1_input", "Core Clock", 2_400_000_000, "hertz"),
            (
                "humidity1_input",
                "Ambient Humidity",
                45_500,
                "milli_percent",
            ),
            ("in1_input", "Core Voltage", 12_000, "millivolts"),
            ("power1_input", "Package Power", 65_000_000, "microwatts"),
            ("temp1_input", "CPU Package", 47_500, "millidegrees_celsius"),
        ];
        assert_eq!(platform.loongarch.hwmon_sensors.len(), expected.len());
        for (sensor, (name, label, value, unit)) in
            platform.loongarch.hwmon_sensors.iter().zip(expected)
        {
            assert_eq!(sensor.device, "loongson_hwmon");
            assert_eq!(sensor.sensor, name);
            assert_eq!(sensor.label.as_deref(), Some(label));
            assert_eq!(sensor.value, value);
            assert_eq!(sensor.unit, unit);
            assert_eq!(sensor.path, hwmon_root.join(name).display().to_string());
        }
    }

    #[test]
    fn power_or_voltage_alone_makes_hwmon_available() {
        for (sensor, value, unit) in [
            ("power1_input", "65000000\n", "microwatts"),
            ("in1_input", "12000\n", "millivolts"),
        ] {
            let root = tempfile::tempdir().expect("tempdir");
            let sys_root = root.path().join("sys");
            let hwmon = sys_root.join("class/hwmon/hwmon0");
            fs::create_dir_all(&hwmon).expect("hwmon fixture");
            fs::write(hwmon.join("name"), "fixture_hwmon\n").expect("hwmon name");
            fs::write(hwmon.join(sensor), value).expect("hwmon input");
            let mut warnings = Vec::new();

            let (thermal, transient_failure) = collect_thermal(&sys_root, 1_000, &mut warnings);

            assert_eq!(thermal.availability, SensorAvailability::Available);
            assert!(thermal.hwmon_available);
            assert!(!thermal.thermal_zone_available);
            assert!(thermal.temperatures.is_empty());
            assert!(thermal.fans.is_empty());
            assert_eq!(thermal.hwmon_sensors.len(), 1);
            assert_eq!(thermal.hwmon_sensors[0].sensor, sensor);
            assert_eq!(thermal.hwmon_sensors[0].unit, unit);
            assert!(!transient_failure);
            assert!(warnings.is_empty());
        }
    }

    #[test]
    fn invalid_hwmon_item_does_not_hide_other_valid_sensors() {
        let root = tempfile::tempdir().expect("tempdir");
        let sys_root = root.path().join("sys");
        let hwmon = sys_root.join("class/hwmon/hwmon0");
        fs::create_dir_all(&hwmon).expect("hwmon fixture");
        fs::write(hwmon.join("name"), "fixture_hwmon\n").expect("hwmon name");
        fs::write(hwmon.join("power1_input"), "65000000\n").expect("valid hwmon");
        fs::write(hwmon.join("temp1_input"), "invalid\n").expect("invalid hwmon");
        let mut warnings = Vec::new();

        let (thermal, transient_failure) = collect_thermal(&sys_root, 1_000, &mut warnings);

        assert_eq!(thermal.availability, SensorAvailability::Available);
        assert!(thermal.hwmon_available);
        assert_eq!(thermal.hwmon_sensors.len(), 1);
        assert_eq!(thermal.hwmon_sensors[0].sensor, "power1_input");
        assert!(transient_failure);
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("temp1_input")));
    }

    #[test]
    #[ignore = "requires a LoongArch Kylin host with readable hwmon sensors"]
    fn loongarch_host_default_collector_matches_supported_hwmon_inputs() {
        let mut expected_warnings = Vec::new();
        let (expected, _) = collect_hwmon_sensors(
            Path::new(DEFAULT_SYS_ROOT).join("class/hwmon").as_path(),
            &mut expected_warnings,
        );
        assert!(
            !expected.is_empty(),
            "no readable and parseable supported *_input sensors under /sys/class/hwmon"
        );

        let mut collector = ProcfsCollector::default();
        let snapshot = collector.collect_dimensions(
            CollectionMode::OnDemand,
            &[ResourceDimension::Thermal],
            &MetricsThresholds::default(),
        );
        assert!(snapshot.meta.platform.loongarch.detected);
        assert!(snapshot.thermal.hwmon_available);
        assert_eq!(
            snapshot.meta.platform.loongarch.hwmon_sensors,
            snapshot.thermal.hwmon_sensors
        );

        let identities = |sensors: &[HwmonSensorReading]| {
            sensors
                .iter()
                .map(|sensor| {
                    (
                        sensor.device.clone(),
                        sensor.sensor.clone(),
                        sensor.unit.clone(),
                        sensor.path.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            identities(&snapshot.thermal.hwmon_sensors),
            identities(&expected),
            "default collector did not preserve every readable supported hwmon input"
        );
    }

    #[test]
    fn fixture_collection_uses_adjacent_samples_for_cpu_disk_and_network_rates() {
        let root = tempfile::tempdir().expect("tempdir");
        let (proc_root, sys_root) = write_resource_fixture(root.path());
        let clock = Arc::new(ManualClock::new(1_000));
        let mut collector = ProcfsCollector::with_dependencies(
            proc_root.clone(),
            sys_root,
            clock.clone(),
            Arc::new(StaticPartitionUsage(DF_FIXTURE)),
        );

        let first = collector.collect_dimensions(
            CollectionMode::Scheduled,
            &ResourceDimension::ALL,
            &MetricsThresholds::default(),
        );
        assert_eq!(first.mode, CollectionMode::Scheduled);
        assert_eq!(first.status, CollectionStatus::Partial);
        assert_eq!(first.started_at_ms, 1_000);
        assert_eq!(first.completed_at_ms, 1_000);
        assert_eq!(first.cpu.usage_percent, None);
        assert_eq!(first.cpu.cores[0].usage_percent, None);
        assert_eq!(first.disk_devices[0].read_iops, None);
        assert_eq!(first.network.interfaces[0].receive_bytes_per_sec, None);
        for dimension in [
            ResourceDimension::Cpu,
            ResourceDimension::Disk,
            ResourceDimension::Network,
        ] {
            assert!(first.dimension_results.iter().any(|result| {
                result.dimension == dimension
                    && result.status == CollectionStatus::Partial
                    && result.rate_status == Some(RateStatus::WarmingUp)
            }));
        }

        fs::write(
            proc_root.join("stat"),
            "cpu 150 0 0 950 0 0 0 0\ncpu0 90 0 0 460 0 0 0 0\ncpu1 60 0 0 490 0 0 0 0\n",
        )
        .expect("updated stat");
        fs::write(
            proc_root.join("net/dev"),
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 6000 35 1 2 0 0 0 0 7000 50 3 4 0 0 0 0\n",
        )
        .expect("updated net dev");
        clock.set(6_000);
        let five_second = collector.collect_dimensions(
            CollectionMode::Scheduled,
            &[ResourceDimension::Cpu, ResourceDimension::Network],
            &MetricsThresholds::default(),
        );
        assert_eq!(five_second.status, CollectionStatus::Complete);
        assert_eq!(
            five_second.attempted_dimensions,
            vec![ResourceDimension::Cpu, ResourceDimension::Network]
        );
        assert_eq!(
            five_second.updated_dimensions,
            five_second.attempted_dimensions
        );
        assert_eq!(five_second.cpu.sample_interval_ms, Some(5_000));
        assert_eq!(five_second.cpu.usage_percent, Some(50.0));
        assert_eq!(five_second.cpu.cores[0].usage_percent, Some(60.0));
        assert_eq!(
            five_second.network.interfaces[0].receive_bytes_per_sec,
            Some(1_000.0)
        );
        assert_eq!(
            five_second.network.interfaces[0].transmit_packets_per_sec,
            Some(6.0)
        );

        fs::write(
            proc_root.join("diskstats"),
            "8 0 sda 30 0 300 0 50 0 500 0 0 0 0 0 0 0 0\n",
        )
        .expect("updated diskstats");
        clock.set(11_000);
        let ten_second = collector.collect_dimensions(
            CollectionMode::Scheduled,
            &[ResourceDimension::Disk],
            &MetricsThresholds::default(),
        );
        assert_eq!(ten_second.disk_devices[0].sample_interval_ms, Some(10_000));
        assert_eq!(ten_second.disk_devices[0].read_iops, Some(2.0));
        assert_eq!(ten_second.disk_devices[0].write_iops, Some(3.0));
        assert_eq!(
            ten_second.disk_devices[0].read_bytes_per_sec,
            Some(10_240.0)
        );
        assert_eq!(
            ten_second.disk_devices[0].write_bytes_per_sec,
            Some(15_360.0)
        );
    }

    #[test]
    fn counter_decrease_is_treated_as_a_reset_without_a_bogus_rate() {
        let root = tempfile::tempdir().expect("tempdir");
        let (proc_root, sys_root) = write_resource_fixture(root.path());
        let clock = Arc::new(ManualClock::new(1_000));
        let mut collector = ProcfsCollector::with_dependencies(
            proc_root.clone(),
            sys_root,
            clock.clone(),
            Arc::new(StaticPartitionUsage(DF_FIXTURE)),
        );
        collector.collect_metrics(&MetricsThresholds::default());

        fs::write(
            proc_root.join("stat"),
            "cpu 10 0 0 90 0 0 0 0\ncpu0 5 0 0 45 0 0 0 0\n",
        )
        .expect("reset stat");
        fs::write(
            proc_root.join("diskstats"),
            "8 0 sda 1 0 10 0 2 0 20 0 0 0 0 0 0 0 0\n",
        )
        .expect("reset diskstats");
        fs::write(
            proc_root.join("net/dev"),
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n",
        )
        .expect("reset net dev");
        clock.set(6_000);
        let reset = collector.collect_metrics(&MetricsThresholds::default());

        assert_eq!(reset.status, CollectionStatus::Partial);
        assert_eq!(reset.cpu.usage_percent, None);
        assert_eq!(reset.disk_devices[0].read_bytes_per_sec, None);
        assert_eq!(reset.network.interfaces[0].receive_bytes_per_sec, None);
        for dimension in [
            ResourceDimension::Cpu,
            ResourceDimension::Disk,
            ResourceDimension::Network,
        ] {
            assert!(reset.dimension_results.iter().any(|result| {
                result.dimension == dimension
                    && result.status == CollectionStatus::Partial
                    && result.rate_status == Some(RateStatus::CounterReset)
            }));
        }
    }

    #[test]
    fn missing_sources_are_reported_as_structured_partial_results() {
        let root = tempfile::tempdir().expect("tempdir");
        let (proc_root, sys_root) = write_resource_fixture(root.path());
        fs::remove_file(proc_root.join("meminfo")).expect("remove meminfo fixture");
        fs::remove_dir_all(sys_root.join("class/thermal")).expect("remove thermal fixture");
        fs::remove_dir_all(sys_root.join("class/hwmon")).expect("remove hwmon fixture");
        let clock = Arc::new(ManualClock::new(1_000));
        let mut collector = ProcfsCollector::with_dependencies(
            proc_root,
            sys_root,
            clock,
            Arc::new(FailingPartitionUsage),
        );

        let snapshot = collector.collect_metrics(&MetricsThresholds::default());

        assert_eq!(snapshot.status, CollectionStatus::Partial);
        assert_eq!(snapshot.attempted_dimensions, ResourceDimension::ALL);
        assert!(!snapshot
            .updated_dimensions
            .contains(&ResourceDimension::Memory));
        assert!(!snapshot
            .updated_dimensions
            .contains(&ResourceDimension::Thermal));
        assert_eq!(
            snapshot.thermal.availability,
            SensorAvailability::Unavailable
        );
        assert!(!snapshot.thermal.thermal_zone_available);
        assert!(!snapshot.thermal.hwmon_available);
        assert!(snapshot.dimension_results.iter().any(|result| {
            result.dimension == ResourceDimension::Memory
                && result.status == CollectionStatus::Failed
                && result.message.is_some()
        }));
        assert!(snapshot.dimension_results.iter().any(|result| {
            result.dimension == ResourceDimension::Disk
                && result.status == CollectionStatus::Partial
        }));
        assert!(snapshot.dimension_results.iter().any(|result| {
            result.dimension == ResourceDimension::Thermal
                && result.status == CollectionStatus::Failed
        }));
    }

    #[test]
    fn empty_or_invalid_thermal_sources_are_unavailable_and_not_updated() {
        for invalid_values in [false, true] {
            let root = tempfile::tempdir().expect("tempdir");
            let proc_root = root.path().join("proc");
            let sys_root = root.path().join("sys");
            fs::create_dir_all(proc_root.join("sys/kernel")).expect("proc fixture");
            fs::create_dir_all(sys_root.join("class/thermal/thermal_zone0"))
                .expect("thermal fixture");
            fs::create_dir_all(sys_root.join("class/hwmon/hwmon0")).expect("hwmon fixture");
            if invalid_values {
                fs::write(
                    sys_root.join("class/thermal/thermal_zone0/temp"),
                    "invalid\n",
                )
                .expect("invalid thermal");
                fs::write(sys_root.join("class/hwmon/hwmon0/temp1_input"), "invalid\n")
                    .expect("invalid hwmon");
            }
            let clock = Arc::new(ManualClock::new(1_000));
            let mut collector = ProcfsCollector::with_dependencies(
                proc_root,
                sys_root,
                clock,
                Arc::new(StaticPartitionUsage(DF_FIXTURE)),
            );

            let snapshot = collector.collect_dimensions(
                CollectionMode::OnDemand,
                &[ResourceDimension::Thermal],
                &MetricsThresholds::default(),
            );

            assert_eq!(snapshot.status, CollectionStatus::Failed);
            assert_eq!(
                snapshot.thermal.availability,
                SensorAvailability::Unavailable
            );
            assert_eq!(
                snapshot.attempted_dimensions,
                vec![ResourceDimension::Thermal]
            );
            assert!(snapshot.updated_dimensions.is_empty());
        }
    }
}
