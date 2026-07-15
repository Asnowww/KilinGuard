use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::context::{build_alert_context, collect_context_with, ContextRequest};
use crate::error::Result;
use crate::model::{AlertContext, MetricSnapshot, OsContext};
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
    pub samples: Vec<MetricSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OsSenseRuntimeConfig {
    pub scheduler: SchedulerConfig,
    pub thresholds: MetricsThresholds,
}

impl Default for OsSenseRuntimeConfig {
    fn default() -> Self {
        Self {
            scheduler: SchedulerConfig::default(),
            thresholds: MetricsThresholds::default(),
        }
    }
}

pub struct OsSenseRuntime {
    collector: ProcfsCollector,
    store: OsSenseStore,
    scheduler: CollectionScheduler,
    config: OsSenseRuntimeConfig,
}

impl OsSenseRuntime {
    pub fn open(path: &Path, config: OsSenseRuntimeConfig) -> Result<Self> {
        Ok(Self::with_parts(
            ProcfsCollector::default(),
            OsSenseStore::open(path)?,
            config,
            current_time_ms(),
        ))
    }

    pub fn open_default(config: OsSenseRuntimeConfig) -> Result<Self> {
        Self::open(&default_database_path(), config)
    }

    pub fn in_memory(config: OsSenseRuntimeConfig) -> Result<Self> {
        Ok(Self::with_parts(
            ProcfsCollector::default(),
            OsSenseStore::in_memory()?,
            config,
            current_time_ms(),
        ))
    }

    #[must_use]
    pub fn with_parts(
        collector: ProcfsCollector,
        store: OsSenseStore,
        config: OsSenseRuntimeConfig,
        start_ms: u64,
    ) -> Self {
        let scheduler = CollectionScheduler::new(config.scheduler.clone(), start_ms);
        Self {
            collector,
            store,
            scheduler,
            config,
        }
    }

    pub fn collect_context_on_demand(&mut self, request: &ContextRequest) -> Result<OsContext> {
        let context = collect_context_with(request, &self.collector, &self.config.thresholds);
        if let Some(metrics) = &context.metrics {
            self.persist_metrics(metrics)?;
            self.scheduler.mark_collected(metrics.meta.collected_at_ms);
        }
        Ok(context)
    }

    pub fn collect_metrics_on_demand(
        &mut self,
        thresholds: Option<&MetricsThresholds>,
    ) -> Result<MetricSnapshot> {
        let thresholds = thresholds.unwrap_or(&self.config.thresholds);
        let snapshot = self.collector.collect_metrics(thresholds);
        self.persist_metrics(&snapshot)?;
        self.scheduler.mark_collected(snapshot.meta.collected_at_ms);
        Ok(snapshot)
    }

    pub fn tick(&mut self, current_time_ms: u64) -> Result<Option<MetricSnapshot>> {
        if !self.scheduler.is_due(current_time_ms) {
            return Ok(None);
        }
        let snapshot = self.collector.collect_metrics(&self.config.thresholds);
        self.persist_metrics(&snapshot)?;
        self.scheduler.mark_collected(current_time_ms);
        Ok(Some(snapshot))
    }

    pub fn query_history(
        &self,
        window: TimeSeriesWindow,
        current_time_ms: u64,
    ) -> Result<MetricsHistory> {
        let since_ms = current_time_ms.saturating_sub(window.duration_ms());
        Ok(MetricsHistory {
            window,
            since_ms,
            until_ms: current_time_ms,
            samples: self.store.query_metrics_range(since_ms, current_time_ms)?,
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

    fn persist_metrics(&self, snapshot: &MetricSnapshot) -> Result<()> {
        self.store.insert_metrics(snapshot)?;
        self.store
            .delete_metrics_before(snapshot.meta.collected_at_ms.saturating_sub(RETENTION_MS))?;
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
    use super::*;

    #[test]
    fn scheduled_tick_persists_and_fixed_windows_query_samples() {
        let start_ms = now_ms();
        let mut runtime = OsSenseRuntime::with_parts(
            ProcfsCollector::default(),
            OsSenseStore::in_memory().expect("store"),
            OsSenseRuntimeConfig {
                scheduler: SchedulerConfig {
                    interval_ms: 1_000,
                    max_runs: None,
                },
                thresholds: MetricsThresholds::default(),
            },
            start_ms,
        );

        let snapshot = runtime.tick(start_ms).expect("tick").expect("due snapshot");
        assert!(runtime
            .tick(start_ms.saturating_add(999))
            .expect("early tick")
            .is_none());
        let history = runtime
            .query_history(TimeSeriesWindow::OneHour, snapshot.meta.collected_at_ms)
            .expect("history");
        assert_eq!(history.window.label(), "1h");
        assert_eq!(history.samples.len(), 1);
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
