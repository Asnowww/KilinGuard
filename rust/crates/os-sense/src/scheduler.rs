use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchedulerConfig {
    pub interval_ms: u64,
    pub max_runs: Option<usize>,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            interval_ms: 60_000,
            max_runs: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionScheduler {
    config: SchedulerConfig,
    next_due_ms: u64,
    completed_runs: usize,
}

impl CollectionScheduler {
    #[must_use]
    pub fn new(config: SchedulerConfig, start_ms: u64) -> Self {
        Self {
            next_due_ms: start_ms,
            config,
            completed_runs: 0,
        }
    }

    #[must_use]
    pub fn is_due(&self, now_ms: u64) -> bool {
        if self
            .config
            .max_runs
            .is_some_and(|max_runs| self.completed_runs >= max_runs)
        {
            return false;
        }
        now_ms >= self.next_due_ms
    }

    pub fn mark_collected(&mut self, now_ms: u64) {
        self.completed_runs += 1;
        self.next_due_ms = now_ms.saturating_add(self.config.interval_ms);
    }

    #[must_use]
    pub fn completed_runs(&self) -> usize {
        self.completed_runs
    }

    #[must_use]
    pub fn next_due_ms(&self) -> u64 {
        self.next_due_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_tracks_due_time_and_max_runs() {
        let mut scheduler = CollectionScheduler::new(
            SchedulerConfig {
                interval_ms: 100,
                max_runs: Some(1),
            },
            1_000,
        );
        assert!(!scheduler.is_due(999));
        assert!(scheduler.is_due(1_000));
        scheduler.mark_collected(1_000);
        assert_eq!(scheduler.next_due_ms(), 1_100);
        assert!(!scheduler.is_due(1_100));
        assert_eq!(scheduler.completed_runs(), 1);
    }
}
