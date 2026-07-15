use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{OsSenseError, Result};
use crate::model::ResourceDimension;

pub const CPU_INTERVAL_MS: u64 = 5_000;
pub const MEMORY_INTERVAL_MS: u64 = 5_000;
pub const DISK_INTERVAL_MS: u64 = 10_000;
pub const NETWORK_INTERVAL_MS: u64 = 5_000;
pub const THERMAL_INTERVAL_MS: u64 = 30_000;
pub const FAILURE_RETRY_INTERVAL_MS: u64 = 1_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CollectionIntervals {
    pub cpu_ms: u64,
    pub memory_ms: u64,
    pub disk_ms: u64,
    pub network_ms: u64,
    pub thermal_ms: u64,
}

impl Default for CollectionIntervals {
    fn default() -> Self {
        Self {
            cpu_ms: CPU_INTERVAL_MS,
            memory_ms: MEMORY_INTERVAL_MS,
            disk_ms: DISK_INTERVAL_MS,
            network_ms: NETWORK_INTERVAL_MS,
            thermal_ms: THERMAL_INTERVAL_MS,
        }
    }
}

impl CollectionIntervals {
    #[must_use]
    pub const fn for_dimension(&self, dimension: ResourceDimension) -> u64 {
        match dimension {
            ResourceDimension::Cpu => self.cpu_ms,
            ResourceDimension::Memory => self.memory_ms,
            ResourceDimension::Disk => self.disk_ms,
            ResourceDimension::Network => self.network_ms,
            ResourceDimension::Thermal => self.thermal_ms,
        }
    }

    fn validate(&self) -> Result<()> {
        for dimension in ResourceDimension::ALL {
            if self.for_dimension(dimension) == 0 {
                return Err(OsSenseError::Configuration(format!(
                    "{} collection interval must be greater than zero",
                    dimension_name(dimension)
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct SchedulerConfig {
    pub intervals: CollectionIntervals,
    pub failure_retry_ms: u64,
    pub max_runs: Option<usize>,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            intervals: CollectionIntervals::default(),
            failure_retry_ms: FAILURE_RETRY_INTERVAL_MS,
            max_runs: None,
        }
    }
}

impl SchedulerConfig {
    pub fn validate(&self) -> Result<()> {
        self.intervals.validate()?;
        if self.failure_retry_ms == 0 {
            return Err(OsSenseError::Configuration(
                "failure_retry_ms must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DimensionDeadline {
    cadence_due_ms: u64,
    retry_due_ms: Option<u64>,
}

impl DimensionDeadline {
    fn effective_due_ms(self) -> u64 {
        self.retry_due_ms.unwrap_or(self.cadence_due_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionScheduler {
    config: SchedulerConfig,
    deadlines: BTreeMap<ResourceDimension, DimensionDeadline>,
    completed_runs: usize,
}

impl CollectionScheduler {
    pub fn new(config: SchedulerConfig, start_ms: u64) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            deadlines: ResourceDimension::ALL
                .into_iter()
                .map(|dimension| {
                    (
                        dimension,
                        DimensionDeadline {
                            cadence_due_ms: start_ms,
                            retry_due_ms: None,
                        },
                    )
                })
                .collect(),
            config,
            completed_runs: 0,
        })
    }

    #[must_use]
    pub fn is_due(&self, now_ms: u64) -> bool {
        !self.due_dimensions(now_ms).is_empty()
    }

    #[must_use]
    pub fn due_dimensions(&self, now_ms: u64) -> Vec<ResourceDimension> {
        if self.has_reached_run_limit() {
            return Vec::new();
        }
        ResourceDimension::ALL
            .into_iter()
            .filter(|dimension| {
                self.deadlines
                    .get(dimension)
                    .is_some_and(|deadline| now_ms >= deadline.effective_due_ms())
            })
            .collect()
    }

    pub fn mark_collected(&mut self, now_ms: u64, dimensions: &[ResourceDimension]) {
        self.mark_attempted(now_ms, dimensions, dimensions);
    }

    pub fn mark_attempted(
        &mut self,
        now_ms: u64,
        attempted: &[ResourceDimension],
        updated: &[ResourceDimension],
    ) {
        if attempted.is_empty() {
            return;
        }
        self.completed_runs += 1;
        for dimension in attempted {
            let deadline = self
                .deadlines
                .entry(*dimension)
                .or_insert(DimensionDeadline {
                    cadence_due_ms: now_ms,
                    retry_due_ms: None,
                });
            if updated.contains(dimension) {
                let interval_ms = self.config.intervals.for_dimension(*dimension);
                let elapsed_ms = now_ms.saturating_sub(deadline.cadence_due_ms);
                let elapsed_intervals = elapsed_ms / interval_ms;
                let intervals_to_advance = elapsed_intervals.saturating_add(1);
                deadline.cadence_due_ms = deadline
                    .cadence_due_ms
                    .saturating_add(interval_ms.saturating_mul(intervals_to_advance));
                deadline.retry_due_ms = None;
            } else {
                deadline.retry_due_ms = Some(now_ms.saturating_add(self.config.failure_retry_ms));
            }
        }
    }

    #[must_use]
    pub fn completed_runs(&self) -> usize {
        self.completed_runs
    }

    #[must_use]
    pub fn next_due_ms(&self) -> u64 {
        if self.has_reached_run_limit() {
            return u64::MAX;
        }
        self.deadlines
            .values()
            .map(|deadline| deadline.effective_due_ms())
            .min()
            .unwrap_or(u64::MAX)
    }

    #[cfg(test)]
    pub(crate) fn next_due_ms_for(&self, dimension: ResourceDimension) -> u64 {
        self.deadlines
            .get(&dimension)
            .map(|deadline| deadline.effective_due_ms())
            .unwrap_or(u64::MAX)
    }

    fn has_reached_run_limit(&self) -> bool {
        self.config
            .max_runs
            .is_some_and(|max_runs| self.completed_runs >= max_runs)
    }
}

fn dimension_name(dimension: ResourceDimension) -> &'static str {
    match dimension {
        ResourceDimension::Cpu => "cpu",
        ResourceDimension::Memory => "memory",
        ResourceDimension::Disk => "disk",
        ResourceDimension::Network => "network",
        ResourceDimension::Thermal => "thermal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CollectionMode;

    #[test]
    fn default_schedule_matches_the_requirement_table() {
        let config = SchedulerConfig::default();
        assert_eq!(config.intervals.cpu_ms, 5_000);
        assert_eq!(config.intervals.memory_ms, 5_000);
        assert_eq!(config.intervals.disk_ms, 10_000);
        assert_eq!(config.intervals.network_ms, 5_000);
        assert_eq!(config.intervals.thermal_ms, 30_000);
    }

    #[test]
    fn scheduler_returns_only_dimensions_due_at_each_frequency() {
        let mut scheduler =
            CollectionScheduler::new(SchedulerConfig::default(), 1_000).expect("valid schedule");

        assert_eq!(
            scheduler.due_dimensions(1_000),
            ResourceDimension::ALL.to_vec()
        );
        scheduler.mark_collected(1_000, &ResourceDimension::ALL);

        let five_second_dimensions = scheduler.due_dimensions(6_000);
        assert_eq!(
            five_second_dimensions,
            vec![
                ResourceDimension::Cpu,
                ResourceDimension::Memory,
                ResourceDimension::Network,
            ]
        );
        scheduler.mark_collected(6_000, &five_second_dimensions);

        let ten_second_dimensions = scheduler.due_dimensions(11_000);
        assert_eq!(
            ten_second_dimensions,
            vec![
                ResourceDimension::Cpu,
                ResourceDimension::Memory,
                ResourceDimension::Disk,
                ResourceDimension::Network,
            ]
        );
        assert!(!ten_second_dimensions.contains(&ResourceDimension::Thermal));
    }

    #[test]
    fn delayed_collection_preserves_each_dimension_cadence() {
        let mut scheduler =
            CollectionScheduler::new(SchedulerConfig::default(), 1_000).expect("valid schedule");

        scheduler.mark_collected(13_500, &[ResourceDimension::Disk]);

        assert_eq!(
            scheduler
                .deadlines
                .get(&ResourceDimension::Disk)
                .map(|deadline| deadline.cadence_due_ms),
            Some(21_000)
        );
    }

    #[test]
    fn failed_dimension_retries_without_advancing_its_cadence() {
        let mut scheduler =
            CollectionScheduler::new(SchedulerConfig::default(), 1_000).expect("valid schedule");
        let updated = [
            ResourceDimension::Memory,
            ResourceDimension::Disk,
            ResourceDimension::Network,
            ResourceDimension::Thermal,
        ];
        scheduler.mark_attempted(1_000, &ResourceDimension::ALL, &updated);

        assert!(!scheduler
            .due_dimensions(1_999)
            .contains(&ResourceDimension::Cpu));
        assert!(scheduler
            .due_dimensions(2_000)
            .contains(&ResourceDimension::Cpu));
        assert_eq!(
            scheduler
                .deadlines
                .get(&ResourceDimension::Cpu)
                .map(|deadline| deadline.cadence_due_ms),
            Some(1_000)
        );

        scheduler.mark_attempted(2_000, &[ResourceDimension::Cpu], &[ResourceDimension::Cpu]);
        assert_eq!(
            scheduler
                .deadlines
                .get(&ResourceDimension::Cpu)
                .map(|deadline| deadline.effective_due_ms()),
            Some(6_000)
        );
    }

    #[test]
    fn rejects_a_zero_dimension_interval() {
        let mut config = SchedulerConfig::default();
        config.intervals.network_ms = 0;
        let error =
            CollectionScheduler::new(config, 1_000).expect_err("zero interval must be rejected");

        assert!(error.to_string().contains("network"));
    }

    #[test]
    fn collection_modes_have_stable_configuration_names() {
        assert_eq!(
            serde_json::to_string(&CollectionMode::OnDemand).expect("serialize mode"),
            "\"on_demand\""
        );
        assert_eq!(
            serde_json::to_string(&CollectionMode::Scheduled).expect("serialize mode"),
            "\"scheduled\""
        );
    }
}
