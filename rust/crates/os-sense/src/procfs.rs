use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::command::run_limited_command;
use crate::error::{OsSenseError, Result};
use crate::model::{
    Alert, AlertEvaluationFreshness, CollectionMode, CollectionStatus, CpuCoreSnapshot,
    CpuSnapshot, DimensionCollectionResult, DiskDeviceSnapshot, DiskSnapshot, FanReading,
    HwmonSensorReading, LoadAverage, LoongArchInfo, MemorySnapshot, MetricSnapshot,
    NetworkInterfaceSnapshot, NetworkMetricsSnapshot, OsSampleMeta, PlatformInfo, ProcessAnomaly,
    ProcessInfo, ProcessList, RateStatus, ResourceDimension, SensorAvailability,
    TemperatureReading, ThermalSnapshot,
};
use crate::redaction::redact_sensitive_text;

const DEFAULT_PROC_ROOT: &str = "/proc";
const DEFAULT_SYS_ROOT: &str = "/sys";
const ASSUMED_CLK_TCK: f64 = 100.0;
const DEFAULT_PROCESS_LIMIT: usize = 100;
const MAX_PROCESS_LIMIT: usize = 500;
const MAX_CMDLINE_CHARS: usize = 256;
const MAX_HWMON_SENSORS: usize = 128;
const DISK_SECTOR_BYTES: u64 = 512;

pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub trait PartitionUsageProvider: Send + Sync {
    fn read_df_output(&self) -> Result<String>;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        now_ms()
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

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessQuery {
    pub pid: Option<u32>,
    pub name_contains: Option<String>,
    pub user: Option<String>,
    pub allowed_names: Vec<String>,
    pub limit: Option<usize>,
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
    partition_usage: Arc<dyn PartitionUsageProvider>,
    metrics: MetricsByMode,
}

impl Default for ProcfsCollector {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from(DEFAULT_PROC_ROOT),
            sys_root: PathBuf::from(DEFAULT_SYS_ROOT),
            clock: Arc::new(SystemClock),
            partition_usage: Arc::new(KylinPartitionUsageProvider),
            metrics: MetricsByMode::default(),
        }
    }
}

impl ProcfsCollector {
    #[must_use]
    pub fn new(proc_root: impl Into<PathBuf>, sys_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            sys_root: sys_root.into(),
            clock: Arc::new(SystemClock),
            partition_usage: Arc::new(KylinPartitionUsageProvider),
            metrics: MetricsByMode::default(),
        }
    }

    #[must_use]
    pub fn with_dependencies(
        proc_root: impl Into<PathBuf>,
        sys_root: impl Into<PathBuf>,
        clock: Arc<dyn Clock>,
        partition_usage: Arc<dyn PartitionUsageProvider>,
    ) -> Self {
        Self {
            proc_root: proc_root.into(),
            sys_root: sys_root.into(),
            clock,
            partition_usage,
            metrics: MetricsByMode::default(),
        }
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

    pub fn collect_processes(&self, query: &ProcessQuery) -> ProcessList {
        let mut warnings = Vec::new();
        let platform = self.platform_info(&mut warnings);
        let users = load_passwd_users();
        let uptime = fs::read_to_string(self.proc_root.join("uptime"))
            .ok()
            .and_then(|content| content.split_whitespace().next()?.parse::<f64>().ok());
        let allowed = query
            .allowed_names
            .iter()
            .take(200)
            .map(|name| name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();

        let mut processes = Vec::new();
        match fs::read_dir(&self.proc_root) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    let Some(pid) = entry
                        .file_name()
                        .to_str()
                        .and_then(|name| name.parse::<u32>().ok())
                    else {
                        continue;
                    };
                    if query.pid.is_some_and(|wanted| wanted != pid) {
                        continue;
                    }
                    match self.read_process(pid, uptime, &users, &allowed) {
                        Ok(process) if process_matches(&process, query) => processes.push(process),
                        Ok(_) => {}
                        Err(error) => {
                            warnings.push(format!("failed to read process {pid}: {error}"))
                        }
                    }
                }
            }
            Err(error) => warnings.push(format!("failed to read /proc process list: {error}")),
        }

        processes.sort_by_key(|process| process.pid);
        let total = processes.len();
        let limit = query
            .limit
            .unwrap_or(DEFAULT_PROCESS_LIMIT)
            .min(MAX_PROCESS_LIMIT);
        let truncated = processes.len() > limit;
        processes.truncate(limit);

        let anomalies = processes
            .iter()
            .flat_map(|process| process.anomalies.clone())
            .collect::<Vec<_>>();
        let unauthorized = processes
            .iter()
            .filter(|process| process.authorized == Some(false))
            .cloned()
            .collect::<Vec<_>>();
        ProcessList {
            meta: OsSampleMeta {
                collected_at_ms: now_ms(),
                source: "procfs".to_string(),
                platform,
                warnings,
            },
            total,
            truncated,
            processes,
            anomalies,
            unauthorized,
        }
    }

    fn read_process(
        &self,
        pid: u32,
        uptime: Option<f64>,
        users: &BTreeMap<String, String>,
        allowed: &BTreeSet<String>,
    ) -> Result<ProcessInfo> {
        let proc_dir = self.proc_root.join(pid.to_string());
        let stat = fs::read_to_string(proc_dir.join("stat"))?;
        let mut info = parse_process_stat(pid, &stat, uptime)?;
        if let Ok(status) = fs::read_to_string(proc_dir.join("status")) {
            apply_process_status(&mut info, &status, users);
        }
        info.command = fs::read(proc_dir.join("cmdline")).ok().and_then(|bytes| {
            let command = bytes
                .split(|byte| *byte == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect::<Vec<_>>()
                .join(" ");
            (!command.is_empty()).then(|| redact_sensitive_text(&command, MAX_CMDLINE_CHARS))
        });
        info.anomalies = detect_process_anomalies(&info);
        if !allowed.is_empty() {
            info.authorized = Some(allowed.contains(&info.name.to_ascii_lowercase()));
            if info.authorized == Some(false) {
                info.anomalies.push(ProcessAnomaly {
                    pid,
                    kind: "unauthorized_process".to_string(),
                    message: format!(
                        "process `{}` is not present in the provided baseline",
                        info.name
                    ),
                    score: 0.8,
                });
            }
        }
        Ok(info)
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
pub fn collect_processes(query: &ProcessQuery) -> ProcessList {
    ProcfsCollector::default().collect_processes(query)
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

fn parse_process_stat(pid: u32, stat: &str, uptime: Option<f64>) -> Result<ProcessInfo> {
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
    let starttime = parts.get(19).and_then(|part| part.parse::<u64>().ok());
    let virtual_memory_kb = parts
        .get(20)
        .and_then(|part| part.parse::<u64>().ok())
        .map(|bytes| bytes / 1024);
    let memory_rss_kb = parts
        .get(21)
        .and_then(|part| part.parse::<i64>().ok())
        .and_then(|pages| u64::try_from(pages).ok())
        .map(|pages| pages * 4);
    let uptime_seconds = uptime.zip(starttime).map(|(uptime, start)| {
        let started_after_boot = start as f64 / ASSUMED_CLK_TCK;
        round2((uptime - started_after_boot).max(0.0))
    });

    Ok(ProcessInfo {
        pid,
        ppid,
        name,
        state,
        user: None,
        cpu_time_jiffies: utime + stime,
        memory_rss_kb,
        virtual_memory_kb,
        uptime_seconds,
        command: None,
        anomalies: Vec::new(),
        authorized: None,
    })
}

fn apply_process_status(info: &mut ProcessInfo, status: &str, users: &BTreeMap<String, String>) {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(uid) = rest.split_whitespace().next() {
                info.user = Some(users.get(uid).cloned().unwrap_or_else(|| uid.to_string()));
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

fn detect_process_anomalies(info: &ProcessInfo) -> Vec<ProcessAnomaly> {
    let mut anomalies = Vec::new();
    if info.state == "Z" {
        anomalies.push(ProcessAnomaly {
            pid: info.pid,
            kind: "zombie_process".to_string(),
            message: format!("process `{}` is in zombie state", info.name),
            score: 1.0,
        });
    }
    if info.memory_rss_kb.is_some_and(|rss| rss >= 1024 * 1024) {
        anomalies.push(ProcessAnomaly {
            pid: info.pid,
            kind: "high_memory_process".to_string(),
            message: format!("process `{}` RSS exceeds 1 GiB", info.name),
            score: 0.6,
        });
    }
    if let Some(uptime_seconds) = info.uptime_seconds {
        if uptime_seconds > 0.0 {
            let cpu_seconds = info.cpu_time_jiffies as f64 / ASSUMED_CLK_TCK;
            if cpu_seconds / uptime_seconds > 0.9 && uptime_seconds > 60.0 {
                anomalies.push(ProcessAnomaly {
                    pid: info.pid,
                    kind: "possible_cpu_spin".to_string(),
                    message: format!(
                        "process `{}` has high CPU time relative to uptime",
                        info.name
                    ),
                    score: 0.5,
                });
            }
        }
    }
    anomalies
}

fn process_matches(process: &ProcessInfo, query: &ProcessQuery) -> bool {
    if let Some(name) = &query.name_contains {
        let needle = name.to_ascii_lowercase();
        if !process.name.to_ascii_lowercase().contains(&needle)
            && !process
                .command
                .as_ref()
                .is_some_and(|command| command.to_ascii_lowercase().contains(&needle))
        {
            return false;
        }
    }
    if let Some(user) = &query.user {
        if process.user.as_deref() != Some(user.as_str()) {
            return false;
        }
    }
    true
}

fn load_passwd_users() -> BTreeMap<String, String> {
    fs::read_to_string("/etc/passwd")
        .map(|content| {
            content
                .lines()
                .filter_map(|line| {
                    let parts = line.split(':').collect::<Vec<_>>();
                    Some((parts.get(2)?.to_string(), parts.first()?.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
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
        let parsed = parse_process_stat(123, stat, Some(10.0)).expect("process stat");
        assert_eq!(parsed.name, "my proc");
        assert_eq!(parsed.ppid, Some(1));
        assert_eq!(parsed.cpu_time_jiffies, 30);
        assert_eq!(parsed.virtual_memory_kb, Some(400));
        assert_eq!(parsed.memory_rss_kb, Some(100));
    }

    #[test]
    fn detects_zombie_and_unauthorized_process() {
        let mut info = ProcessInfo {
            pid: 42,
            ppid: Some(1),
            name: "unknown".to_string(),
            state: "Z".to_string(),
            user: None,
            cpu_time_jiffies: 0,
            memory_rss_kb: None,
            virtual_memory_kb: None,
            uptime_seconds: None,
            command: None,
            anomalies: Vec::new(),
            authorized: Some(false),
        };
        info.anomalies = detect_process_anomalies(&info);
        assert!(info
            .anomalies
            .iter()
            .any(|anomaly| anomaly.kind == "zombie_process"));
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
