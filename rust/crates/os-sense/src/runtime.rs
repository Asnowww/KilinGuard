use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::context::{build_alert_context, collect_context_with, ContextRequest};
use crate::error::Result;
use crate::model::{
    AlertContext, CollectionMode, CorruptSampleDetail, MetricSnapshot, OsContext, ResourceDimension,
};
use crate::procfs::{now_ms, MetricsThresholds, ProcfsCollector};
use crate::scheduler::{CollectionScheduler, SchedulerConfig};
use crate::storage::OsSenseStore;

const HOUR_MS: u64 = 60 * 60 * 1_000;
const RETENTION_MS: u64 = 7 * 24 * HOUR_MS;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimeSeriesWindow {
    #[serde(rename = "1h")]
    OneHour,
    #[serde(rename = "24h")]
    TwentyFourHours,
    #[serde(rename = "7d")]
    SevenDays,
}

impl TimeSeriesWindow {
    #[must_use]
    pub const fn duration_ms(self) -> u64 {
        match self {
            Self::OneHour => HOUR_MS,
            Self::TwentyFourHours => 24 * HOUR_MS,
            Self::SevenDays => RETENTION_MS,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::OneHour => "1h",
            Self::TwentyFourHours => "24h",
            Self::SevenDays => "7d",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MetricsHistory {
    pub window: TimeSeriesWindow,
    pub since_ms: u64,
    pub until_ms: u64,
    pub source_sample_count: u64,
    pub returned_sample_count: u64,
    pub bucket_width_ms: u64,
    pub downsampled: bool,
    pub skipped_corrupt_samples: u64,
    pub corrupt_sample_details: Vec<CorruptSampleDetail>,
    pub warnings: Vec<String>,
    pub samples: Vec<MetricSnapshot>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OsSenseRuntimeConfig {
    pub scheduler: SchedulerConfig,
    pub thresholds: MetricsThresholds,
}

pub struct OsSenseRuntime {
    collector: ProcfsCollector,
    store: OsSenseStore,
    scheduler: CollectionScheduler,
    config: OsSenseRuntimeConfig,
}

impl OsSenseRuntime {
    pub fn open(path: &Path, config: OsSenseRuntimeConfig) -> Result<Self> {
        Self::with_parts(
            ProcfsCollector::default(),
            OsSenseStore::open(path)?,
            config,
            current_time_ms(),
        )
    }

    pub fn open_default(config: OsSenseRuntimeConfig) -> Result<Self> {
        Self::open(&default_database_path(), config)
    }

    pub fn in_memory(config: OsSenseRuntimeConfig) -> Result<Self> {
        Self::with_parts(
            ProcfsCollector::default(),
            OsSenseStore::in_memory()?,
            config,
            current_time_ms(),
        )
    }

    pub fn with_parts(
        collector: ProcfsCollector,
        store: OsSenseStore,
        config: OsSenseRuntimeConfig,
        start_ms: u64,
    ) -> Result<Self> {
        store.delete_metrics_before(start_ms.saturating_sub(RETENTION_MS))?;
        let scheduler = CollectionScheduler::new(config.scheduler.clone(), start_ms)?;
        Ok(Self {
            collector,
            store,
            scheduler,
            config,
        })
    }

    pub fn collect_context_on_demand(&mut self, request: &ContextRequest) -> Result<OsContext> {
        let context = collect_context_with(request, &mut self.collector, &self.config.thresholds);
        if let Some(metrics) = &context.metrics {
            self.persist_metrics(metrics)?;
        }
        Ok(context)
    }

    pub fn collect_metrics_on_demand(
        &mut self,
        thresholds: Option<&MetricsThresholds>,
    ) -> Result<MetricSnapshot> {
        self.collect_metrics(CollectionMode::OnDemand, current_time_ms(), thresholds)?
            .ok_or_else(|| {
                crate::error::OsSenseError::Configuration(
                    "on-demand collection did not produce a sample".to_string(),
                )
            })
    }

    pub fn tick(&mut self, current_time_ms: u64) -> Result<Option<MetricSnapshot>> {
        self.collect_metrics(CollectionMode::Scheduled, current_time_ms, None)
    }

    pub fn collect_metrics(
        &mut self,
        mode: CollectionMode,
        current_time_ms: u64,
        thresholds: Option<&MetricsThresholds>,
    ) -> Result<Option<MetricSnapshot>> {
        let dimensions = match mode {
            CollectionMode::OnDemand => ResourceDimension::ALL.to_vec(),
            CollectionMode::Scheduled => self.scheduler.due_dimensions(current_time_ms),
        };
        if dimensions.is_empty() {
            return Ok(None);
        }
        let thresholds = thresholds.unwrap_or(&self.config.thresholds);
        let snapshot = self
            .collector
            .collect_dimensions(mode, &dimensions, thresholds);
        self.persist_metrics(&snapshot)?;
        if mode == CollectionMode::Scheduled {
            let mut cadence_dimensions = snapshot.updated_dimensions.clone();
            for result in &snapshot.dimension_results {
                if !result.retryable && !cadence_dimensions.contains(&result.dimension) {
                    cadence_dimensions.push(result.dimension);
                }
            }
            self.scheduler.mark_attempted(
                current_time_ms,
                &snapshot.attempted_dimensions,
                &cadence_dimensions,
            );
        }
        Ok(Some(snapshot))
    }

    pub fn query_history(
        &self,
        window: TimeSeriesWindow,
        current_time_ms: u64,
    ) -> Result<MetricsHistory> {
        let since_ms = current_time_ms.saturating_sub(window.duration_ms());
        let query = self.store.query_history_range(since_ms, current_time_ms)?;
        Ok(MetricsHistory {
            window,
            since_ms,
            until_ms: current_time_ms,
            source_sample_count: query.source_sample_count,
            returned_sample_count: query.returned_sample_count,
            bucket_width_ms: query.bucket_width_ms,
            downsampled: query.downsampled,
            skipped_corrupt_samples: query.skipped_corrupt_samples,
            corrupt_sample_details: query.corrupt_sample_details,
            warnings: query.warnings,
            samples: query.samples,
        })
    }

    #[must_use]
    pub fn alert_context(snapshot: &MetricSnapshot) -> Option<AlertContext> {
        build_alert_context(&snapshot.alerts, snapshot.meta.collected_at_ms)
    }

    #[must_use]
    pub fn next_due_ms(&self) -> u64 {
        self.scheduler.next_due_ms()
    }

    fn persist_metrics(&mut self, snapshot: &MetricSnapshot) -> Result<()> {
        self.store.insert_metrics_and_prune(
            snapshot,
            snapshot.meta.collected_at_ms.saturating_sub(RETENTION_MS),
        )?;
        Ok(())
    }
}

#[must_use]
pub fn default_database_path() -> PathBuf {
    if let Some(path) = std::env::var_os("CLAW_OS_SENSE_DB").filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    if let Some(state_home) = std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
        return PathBuf::from(state_home)
            .join("claw")
            .join("os-sense.sqlite3");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|value| !value.is_empty()) {
        return PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("claw")
            .join("os-sense.sqlite3");
    }
    std::env::temp_dir().join("claw").join("os-sense.sqlite3")
}

#[must_use]
pub fn current_time_ms() -> u64 {
    now_ms()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use crate::error::OsSenseError;
    use crate::procfs::{Clock, PartitionUsageProvider};

    use super::*;

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

    struct FixturePartitionUsage;

    impl PartitionUsageProvider for FixturePartitionUsage {
        fn read_df_output(&self) -> Result<String> {
            Ok("Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/sda1 1000 400 600 40% /\n".to_string())
        }
    }

    fn fixture_collector(root: &Path, clock: Arc<ManualClock>) -> ProcfsCollector {
        let proc_root = root.join("proc");
        let sys_root = root.join("sys");
        fs::create_dir_all(proc_root.join("sys/kernel")).expect("proc fixture");
        fs::create_dir_all(proc_root.join("net")).expect("net fixture");
        fs::create_dir_all(sys_root.join("class/thermal/thermal_zone0")).expect("thermal fixture");
        fs::create_dir_all(sys_root.join("class/hwmon")).expect("hwmon fixture");
        fs::write(
            proc_root.join("stat"),
            "cpu 10 0 0 90 0 0 0 0\ncpu0 10 0 0 90 0 0 0 0\n",
        )
        .expect("stat fixture");
        fs::write(
            proc_root.join("meminfo"),
            "MemTotal: 1000 kB\nMemAvailable: 500 kB\nBuffers: 10 kB\nCached: 100 kB\nSwapTotal: 200 kB\nSwapFree: 150 kB\n",
        )
        .expect("meminfo fixture");
        fs::write(proc_root.join("loadavg"), "0.1 0.2 0.3 1/2 3\n").expect("load fixture");
        fs::write(
            proc_root.join("diskstats"),
            "8 0 sda 1 0 10 0 2 0 20 0 0 0 0 0 0 0 0\n",
        )
        .expect("disk fixture");
        fs::write(
            proc_root.join("net/dev"),
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n",
        )
        .expect("network fixture");
        let socket_header = "sl local_address rem_address st\n";
        for name in ["tcp", "tcp6", "udp", "udp6"] {
            fs::write(proc_root.join("net").join(name), socket_header).expect("socket fixture");
        }
        fs::write(proc_root.join("cpuinfo"), "model name: fixture\n").expect("cpuinfo");
        fs::write(proc_root.join("sys/kernel/osrelease"), "6.6.0-kylin\n").expect("kernel");
        fs::write(
            sys_root.join("class/thermal/thermal_zone0/type"),
            "cpu-thermal\n",
        )
        .expect("thermal type");
        fs::write(sys_root.join("class/thermal/thermal_zone0/temp"), "45000\n")
            .expect("thermal temp");

        ProcfsCollector::with_dependencies(
            proc_root,
            sys_root,
            clock,
            Arc::new(FixturePartitionUsage),
        )
    }

    #[test]
    fn scheduled_tick_persists_and_fixed_windows_query_samples() {
        let root = tempfile::tempdir().expect("tempdir");
        let start_ms = 1_000;
        let clock = Arc::new(ManualClock::new(start_ms));
        let mut runtime = OsSenseRuntime::with_parts(
            fixture_collector(root.path(), clock),
            OsSenseStore::in_memory().expect("store"),
            OsSenseRuntimeConfig::default(),
            start_ms,
        )
        .expect("runtime");

        let snapshot = runtime.tick(start_ms).expect("tick").expect("due snapshot");
        assert!(runtime
            .tick(start_ms.saturating_add(4_999))
            .expect("early tick")
            .is_none());
        let history = runtime
            .query_history(TimeSeriesWindow::OneHour, snapshot.meta.collected_at_ms)
            .expect("history");
        assert_eq!(history.window.label(), "1h");
        assert_eq!(history.samples.len(), 1);
        assert_eq!(history.source_sample_count, 1);
        assert_eq!(history.returned_sample_count, 1);
        assert_eq!(history.bucket_width_ms, 0);
        assert!(!history.downsampled);
        assert_eq!(history.skipped_corrupt_samples, 0);
    }

    #[test]
    fn runtime_startup_prunes_older_rows_and_keeps_the_seven_day_boundary() {
        let root = tempfile::tempdir().expect("tempdir");
        let start_ms = RETENTION_MS + 1_000;
        let cutoff_ms = start_ms - RETENTION_MS;
        let clock = Arc::new(ManualClock::new(start_ms));
        let mut collector = fixture_collector(root.path(), clock);
        let template = collector.collect_metrics(&MetricsThresholds::default());
        let store = OsSenseStore::in_memory().expect("store");
        for timestamp in [cutoff_ms - 1, cutoff_ms, start_ms] {
            let mut snapshot = template.clone();
            snapshot.meta.collected_at_ms = timestamp;
            snapshot.started_at_ms = timestamp;
            snapshot.completed_at_ms = timestamp;
            store.insert_metrics(&snapshot).expect("insert startup row");
        }

        let runtime =
            OsSenseRuntime::with_parts(collector, store, OsSenseRuntimeConfig::default(), start_ms)
                .expect("runtime");
        let result = runtime
            .store
            .query_history_range(0, start_ms)
            .expect("query retained rows");
        let timestamps = result
            .samples
            .iter()
            .map(|snapshot| snapshot.meta.collected_at_ms)
            .collect::<Vec<_>>();

        assert_eq!(timestamps, vec![cutoff_ms, start_ms]);
    }

    #[test]
    fn on_demand_collection_does_not_delay_the_scheduled_mode() {
        let root = tempfile::tempdir().expect("tempdir");
        let start_ms = 1_000;
        let clock = Arc::new(ManualClock::new(start_ms));
        let mut runtime = OsSenseRuntime::with_parts(
            fixture_collector(root.path(), clock.clone()),
            OsSenseStore::in_memory().expect("store"),
            OsSenseRuntimeConfig::default(),
            start_ms,
        )
        .expect("runtime");

        let initial = runtime
            .tick(start_ms)
            .expect("initial tick")
            .expect("sample");
        assert_eq!(initial.updated_dimensions, ResourceDimension::ALL);
        assert_eq!(runtime.next_due_ms(), 6_000);

        clock.set(3_000);
        let on_demand = runtime
            .collect_metrics(CollectionMode::OnDemand, 3_000, None)
            .expect("on-demand collection");

        assert!(on_demand.is_some());
        assert_eq!(on_demand.expect("sample").mode, CollectionMode::OnDemand);
        assert_eq!(runtime.next_due_ms(), 6_000);
        assert!(runtime.tick(5_999).expect("early tick").is_none());

        let proc_root = root.path().join("proc");
        fs::write(
            proc_root.join("stat"),
            "cpu 20 0 0 180 0 0 0 0\ncpu0 20 0 0 180 0 0 0 0\n",
        )
        .expect("updated stat");
        fs::write(
            proc_root.join("net/dev"),
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 600 6 0 0 0 0 0 0 700 7 0 0 0 0 0 0\n",
        )
        .expect("updated network");
        clock.set(6_000);
        let scheduled = runtime
            .collect_metrics(CollectionMode::Scheduled, 6_000, None)
            .expect("scheduled collection")
            .expect("scheduled sample");
        assert_eq!(
            scheduled.updated_dimensions,
            vec![
                ResourceDimension::Cpu,
                ResourceDimension::Memory,
                ResourceDimension::Network,
            ]
        );
        assert_eq!(scheduled.mode, CollectionMode::Scheduled);
        assert_eq!(scheduled.status, crate::model::CollectionStatus::Complete);
        assert_eq!(scheduled.cpu.sample_interval_ms, Some(5_000));
        assert_eq!(
            scheduled.network.interfaces[0].sample_interval_ms,
            Some(5_000)
        );
        assert_eq!(runtime.next_due_ms(), 11_000);

        fs::write(
            proc_root.join("stat"),
            "cpu 30 0 0 270 0 0 0 0\ncpu0 30 0 0 270 0 0 0 0\n",
        )
        .expect("second stat update");
        fs::write(
            proc_root.join("diskstats"),
            "8 0 sda 3 0 30 0 4 0 40 0 0 0 0 0 0 0 0\n",
        )
        .expect("updated disk");
        fs::write(
            proc_root.join("net/dev"),
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 1100 11 0 0 0 0 0 0 1200 12 0 0 0 0 0 0\n",
        )
        .expect("second network update");
        clock.set(11_000);
        let ten_second = runtime
            .tick(11_000)
            .expect("ten-second tick")
            .expect("ten-second sample");
        assert_eq!(ten_second.cpu.sample_interval_ms, Some(5_000));
        assert_eq!(ten_second.disk_devices[0].sample_interval_ms, Some(10_000));
    }

    #[test]
    fn empty_thermal_directories_use_the_normal_thirty_second_cadence() {
        let root = tempfile::tempdir().expect("tempdir");
        let start_ms = 1_000;
        let clock = Arc::new(ManualClock::new(start_ms));
        let collector = fixture_collector(root.path(), clock);
        fs::remove_file(root.path().join("sys/class/thermal/thermal_zone0/temp"))
            .expect("remove thermal reading");
        let mut runtime = OsSenseRuntime::with_parts(
            collector,
            OsSenseStore::in_memory().expect("store"),
            OsSenseRuntimeConfig::default(),
            start_ms,
        )
        .expect("runtime");

        let snapshot = runtime
            .tick(start_ms)
            .expect("tick")
            .expect("scheduled snapshot");
        let thermal = snapshot
            .dimension_results
            .iter()
            .find(|result| result.dimension == ResourceDimension::Thermal)
            .expect("thermal result");

        assert_eq!(
            snapshot.thermal.availability,
            crate::model::SensorAvailability::Unavailable
        );
        assert_eq!(thermal.status, crate::model::CollectionStatus::Failed);
        assert!(!thermal.retryable);
        assert_eq!(
            runtime
                .scheduler
                .next_due_ms_for(ResourceDimension::Thermal),
            31_000
        );
    }

    #[test]
    fn transient_thermal_parse_failure_retries_after_one_second() {
        let root = tempfile::tempdir().expect("tempdir");
        let start_ms = 1_000;
        let clock = Arc::new(ManualClock::new(start_ms));
        let collector = fixture_collector(root.path(), clock);
        fs::write(
            root.path().join("sys/class/thermal/thermal_zone0/temp"),
            "invalid\n",
        )
        .expect("invalid thermal reading");
        let mut runtime = OsSenseRuntime::with_parts(
            collector,
            OsSenseStore::in_memory().expect("store"),
            OsSenseRuntimeConfig::default(),
            start_ms,
        )
        .expect("runtime");

        let snapshot = runtime
            .tick(start_ms)
            .expect("tick")
            .expect("scheduled snapshot");
        let thermal = snapshot
            .dimension_results
            .iter()
            .find(|result| result.dimension == ResourceDimension::Thermal)
            .expect("thermal result");

        assert_eq!(
            snapshot.thermal.availability,
            crate::model::SensorAvailability::Unavailable
        );
        assert_eq!(thermal.status, crate::model::CollectionStatus::Failed);
        assert!(thermal.retryable);
        assert_eq!(
            runtime
                .scheduler
                .next_due_ms_for(ResourceDimension::Thermal),
            2_000
        );
    }

    #[test]
    fn invalid_schedule_is_rejected_when_runtime_is_created() {
        let mut config = OsSenseRuntimeConfig::default();
        config.scheduler.intervals.network_ms = 0;
        let error = match OsSenseRuntime::in_memory(config) {
            Ok(_) => panic!("invalid schedule must fail"),
            Err(error) => error,
        };

        assert!(matches!(error, OsSenseError::Configuration(_)));
        assert!(error.to_string().contains("network"));
    }

    #[test]
    fn database_path_uses_linux_state_directory_contract() {
        let path = default_database_path();
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("os-sense.sqlite3")
        );
        assert!(path.to_string_lossy().contains("claw"));
    }
}
