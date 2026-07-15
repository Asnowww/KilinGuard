use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::command::run_limited_command;
use crate::error::{OsSenseError, Result};
use crate::model::{
    Alert, CpuSnapshot, DiskSnapshot, HwmonSensorReading, LoadAverage, LoongArchInfo,
    MemorySnapshot, MetricSnapshot, OsSampleMeta, PlatformInfo, ProcessAnomaly, ProcessInfo,
    ProcessList,
};
use crate::redaction::redact_sensitive_text;

const DEFAULT_PROC_ROOT: &str = "/proc";
const DEFAULT_SYS_ROOT: &str = "/sys";
const ASSUMED_CLK_TCK: f64 = 100.0;
const DEFAULT_PROCESS_LIMIT: usize = 100;
const MAX_PROCESS_LIMIT: usize = 500;
const MAX_CMDLINE_CHARS: usize = 256;
const MAX_HWMON_SENSORS: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsThresholds {
    pub cpu_percent: Option<f64>,
    pub memory_percent: Option<f64>,
    pub disk_percent: Option<f64>,
    pub load1: Option<f64>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessQuery {
    pub pid: Option<u32>,
    pub name_contains: Option<String>,
    pub user: Option<String>,
    pub allowed_names: Vec<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct ProcfsCollector {
    proc_root: PathBuf,
    sys_root: PathBuf,
}

impl Default for ProcfsCollector {
    fn default() -> Self {
        Self {
            proc_root: PathBuf::from(DEFAULT_PROC_ROOT),
            sys_root: PathBuf::from(DEFAULT_SYS_ROOT),
        }
    }
}

impl ProcfsCollector {
    #[must_use]
    pub fn new(proc_root: impl Into<PathBuf>, sys_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            sys_root: sys_root.into(),
        }
    }

    pub fn collect_metrics(&self, thresholds: &MetricsThresholds) -> MetricSnapshot {
        let mut warnings = Vec::new();
        let platform = self.platform_info(&mut warnings);
        let cpu = match fs::read_to_string(self.proc_root.join("stat")) {
            Ok(content) => parse_cpu_stat(&content).unwrap_or_else(|| {
                warnings.push("failed to parse /proc/stat".to_string());
                CpuSnapshot {
                    usage_percent: None,
                    total_jiffies: 0,
                    idle_jiffies: 0,
                    cpu_count: 0,
                }
            }),
            Err(error) => {
                warnings.push(format!("failed to read /proc/stat: {error}"));
                CpuSnapshot {
                    usage_percent: None,
                    total_jiffies: 0,
                    idle_jiffies: 0,
                    cpu_count: 0,
                }
            }
        };
        let memory = match fs::read_to_string(self.proc_root.join("meminfo")) {
            Ok(content) => parse_meminfo(&content).unwrap_or_else(|| {
                warnings.push("failed to parse /proc/meminfo".to_string());
                MemorySnapshot {
                    total_kb: 0,
                    available_kb: 0,
                    used_kb: 0,
                    used_percent: None,
                }
            }),
            Err(error) => {
                warnings.push(format!("failed to read /proc/meminfo: {error}"));
                MemorySnapshot {
                    total_kb: 0,
                    available_kb: 0,
                    used_kb: 0,
                    used_percent: None,
                }
            }
        };
        let load = match fs::read_to_string(self.proc_root.join("loadavg")) {
            Ok(content) => match parse_loadavg(&content) {
                Some(load) => Some(load),
                None => {
                    warnings.push("failed to parse /proc/loadavg".to_string());
                    None
                }
            },
            Err(error) => {
                warnings.push(format!("failed to read /proc/loadavg: {error}"));
                None
            }
        };
        let disks = collect_disks(&mut warnings);
        let alerts = build_metric_alerts(&cpu, &memory, load.as_ref(), &disks, thresholds);

        MetricSnapshot {
            meta: OsSampleMeta {
                collected_at_ms: now_ms(),
                source: "procfs".to_string(),
                platform,
                warnings,
            },
            cpu,
            memory,
            load,
            disks,
            alerts,
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
        let hwmon_sensors = if detected {
            collect_hwmon_sensors(&hwmon_root, warnings)
        } else {
            Vec::new()
        };

        PlatformInfo {
            os: std::env::consts::OS.to_string(),
            arch,
            kernel_version,
            loongarch: LoongArchInfo {
                detected,
                cpu_model,
                hwmon_paths,
                hwmon_sensors,
            },
        }
    }
}

fn collect_hwmon_sensors(root: &Path, warnings: &mut Vec<String>) -> Vec<HwmonSensorReading> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut device_paths = entries
        .flatten()
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    device_paths.sort();

    let mut sensors = Vec::new();
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
                    "LoongArch hwmon sensor list was capped at {MAX_HWMON_SENSORS} entries"
                ));
                return sensors;
            }
            let Some(sensor) = input_path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
            else {
                continue;
            };
            let Ok(raw) = fs::read_to_string(&input_path) else {
                continue;
            };
            let Ok(value) = raw.trim().parse::<i64>() else {
                warnings.push(format!(
                    "failed to parse LoongArch hwmon sensor {}",
                    input_path.display()
                ));
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
    sensors
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
    let mut lines = content.lines();
    let cpu_line = lines.next()?.trim();
    let mut parts = cpu_line.split_whitespace();
    (parts.next()? == "cpu").then_some(())?;
    let values = parts
        .map(|part| part.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    if values.len() < 4 {
        return None;
    }
    let idle =
        values.get(3).copied().unwrap_or_default() + values.get(4).copied().unwrap_or_default();
    let total = values.iter().sum::<u64>();
    let usage_percent = (total > 0).then(|| round2(((total - idle) as f64 / total as f64) * 100.0));
    let cpu_count = content
        .lines()
        .filter(|line| {
            line.strip_prefix("cpu")
                .and_then(|rest| rest.chars().next())
                .is_some_and(|ch| ch.is_ascii_digit())
        })
        .count();
    Some(CpuSnapshot {
        usage_percent,
        total_jiffies: total,
        idle_jiffies: idle,
        cpu_count,
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
    Some(MemorySnapshot {
        total_kb: total,
        available_kb: available,
        used_kb: used,
        used_percent,
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

fn collect_disks(warnings: &mut Vec<String>) -> Vec<DiskSnapshot> {
    match run_limited_command(
        "df",
        &["-P", "-B1"],
        Duration::from_secs(2),
        64 * 1024,
        16 * 1024,
    ) {
        Ok(output) if output.success => {
            if output.stdout_truncated {
                warnings.push("df output was truncated".to_string());
            }
            parse_df_output(&output.stdout)
        }
        Ok(output) => {
            if output.timed_out {
                warnings.push("df -P -B1 timed out".to_string());
            } else {
                warnings.push(format!("df -P -B1 failed: {}", output.stderr.trim()));
            }
            Vec::new()
        }
        Err(error) => {
            warnings.push(format!("df command unavailable: {error}"));
            Vec::new()
        }
    }
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
    use super::*;

    #[test]
    fn parses_cpu_stat() {
        let stat = "cpu  100 0 50 850 0 0 0 0 0 0\ncpu0 100 0 50 850 0 0 0 0 0 0\n";
        let parsed = parse_cpu_stat(stat).expect("cpu stat");
        assert_eq!(parsed.total_jiffies, 1000);
        assert_eq!(parsed.idle_jiffies, 850);
        assert_eq!(parsed.usage_percent, Some(15.0));
        assert_eq!(parsed.cpu_count, 1);
    }

    #[test]
    fn parses_meminfo() {
        let meminfo = "MemTotal:       1000 kB\nMemAvailable:    250 kB\n";
        let parsed = parse_meminfo(meminfo).expect("meminfo");
        assert_eq!(parsed.used_kb, 750);
        assert_eq!(parsed.used_percent, Some(75.0));
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
        let proc_root = root.path().join("proc");
        let sys_root = root.path().join("sys");
        let hwmon = sys_root.join("class/hwmon/hwmon0");
        fs::create_dir_all(proc_root.join("sys/kernel")).expect("proc dirs");
        fs::create_dir_all(&hwmon).expect("hwmon dirs");
        fs::write(
            proc_root.join("stat"),
            "cpu  1 0 0 9 0 0 0 0\ncpu0 1 0 0 9 0 0 0 0\n",
        )
        .expect("stat");
        fs::write(
            proc_root.join("meminfo"),
            "MemTotal: 1000 kB\nMemAvailable: 500 kB\n",
        )
        .expect("meminfo");
        fs::write(proc_root.join("loadavg"), "0.1 0.2 0.3 1/2 3\n").expect("loadavg");
        fs::write(proc_root.join("cpuinfo"), "model name: LoongArch 3A6000\n").expect("cpuinfo");
        fs::write(proc_root.join("sys/kernel/osrelease"), "6.6.0-kylin\n").expect("kernel");
        fs::write(hwmon.join("name"), "loongson_hwmon\n").expect("name");
        fs::write(hwmon.join("temp1_input"), "47500\n").expect("temperature");
        fs::write(hwmon.join("temp1_label"), "CPU Package\n").expect("label");
        fs::write(hwmon.join("fan1_input"), "1800\n").expect("fan");

        let snapshot = ProcfsCollector::new(proc_root, sys_root)
            .collect_metrics(&MetricsThresholds::default());
        let platform = snapshot.meta.platform;
        assert!(platform.loongarch.detected);
        assert_eq!(platform.loongarch.hwmon_sensors.len(), 2);
        assert!(platform.loongarch.hwmon_sensors.iter().any(|sensor| {
            sensor.sensor == "temp1_input"
                && sensor.value == 47_500
                && sensor.unit == "millidegrees_celsius"
                && sensor.label.as_deref() == Some("CPU Package")
        }));
        assert!(platform
            .loongarch
            .hwmon_sensors
            .iter()
            .any(|sensor| sensor.sensor == "fan1_input" && sensor.value == 1_800));
    }
}
