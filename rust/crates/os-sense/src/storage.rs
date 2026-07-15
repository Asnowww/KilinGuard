use std::path::Path;

use rusqlite::{params, Connection};

use crate::error::{OsSenseError, Result};
use crate::model::MetricSnapshot;

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS metric_snapshots (
    sample_id INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at_ms INTEGER NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_metric_snapshots_collected_at
ON metric_snapshots(collected_at_ms);
";

pub struct OsSenseStore {
    conn: Connection,
}

impl OsSenseStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        init(&conn)?;
        Ok(Self { conn })
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        init(&conn)?;
        Ok(Self { conn })
    }

    pub fn insert_metrics(&self, snapshot: &MetricSnapshot) -> Result<()> {
        let payload = serde_json::to_string(snapshot)?;
        let collected_at_ms = i64::try_from(snapshot.meta.collected_at_ms)
            .map_err(|_| OsSenseError::Storage("timestamp is too large for SQLite".to_string()))?;
        self.conn.execute(
            r"
INSERT INTO metric_snapshots(collected_at_ms, payload)
VALUES (?1, ?2)
",
            params![collected_at_ms, payload],
        )?;
        Ok(())
    }

    pub fn query_metrics_since(&self, since_ms: u64) -> Result<Vec<MetricSnapshot>> {
        self.query_metrics_range(since_ms, u64::MAX)
    }

    pub fn query_metrics_range(&self, since_ms: u64, until_ms: u64) -> Result<Vec<MetricSnapshot>> {
        let since_ms = sqlite_timestamp(since_ms)?;
        let until_ms = sqlite_timestamp(until_ms.min(i64::MAX as u64))?;
        let mut stmt = self.conn.prepare(
            r"
SELECT payload FROM metric_snapshots
WHERE collected_at_ms >= ?1 AND collected_at_ms <= ?2
ORDER BY collected_at_ms ASC, sample_id ASC
",
        )?;
        let rows = stmt.query_map(params![since_ms, until_ms], |row| row.get::<_, String>(0))?;
        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(serde_json::from_str(&row?)?);
        }
        Ok(snapshots)
    }

    pub fn delete_metrics_before(&self, before_ms: u64) -> Result<usize> {
        let before_ms = sqlite_timestamp(before_ms)?;
        Ok(self.conn.execute(
            "DELETE FROM metric_snapshots WHERE collected_at_ms < ?1",
            params![before_ms],
        )?)
    }
}

fn sqlite_timestamp(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| OsSenseError::Storage("timestamp is too large for SQLite".to_string()))
}

fn init(conn: &Connection) -> Result<()> {
    conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    if is_legacy_schema(conn)? {
        migrate_legacy_schema(conn)?;
    }
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

fn is_legacy_schema(conn: &Connection) -> Result<bool> {
    let mut stmt = conn.prepare("PRAGMA table_info(metric_snapshots)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let columns = columns.collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(!columns.is_empty() && !columns.iter().any(|column| column == "sample_id"))
}

fn migrate_legacy_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r"
BEGIN IMMEDIATE;
ALTER TABLE metric_snapshots RENAME TO metric_snapshots_legacy;
CREATE TABLE metric_snapshots (
    sample_id INTEGER PRIMARY KEY AUTOINCREMENT,
    collected_at_ms INTEGER NOT NULL,
    payload TEXT NOT NULL
);
INSERT INTO metric_snapshots(collected_at_ms, payload)
SELECT collected_at_ms, payload FROM metric_snapshots_legacy;
DROP TABLE metric_snapshots_legacy;
CREATE INDEX idx_metric_snapshots_collected_at
ON metric_snapshots(collected_at_ms);
COMMIT;
",
    )
    .map_err(|error| {
        let _ = conn.execute_batch("ROLLBACK;");
        OsSenseError::from(error)
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::model::{
        CpuSnapshot, LoongArchInfo, MemorySnapshot, MetricSnapshot, OsSampleMeta, PlatformInfo,
    };

    use super::*;

    fn sample(ts: u64, mode: crate::model::CollectionMode) -> MetricSnapshot {
        MetricSnapshot {
            meta: OsSampleMeta {
                collected_at_ms: ts,
                source: "test".to_string(),
                platform: PlatformInfo {
                    os: "linux".to_string(),
                    arch: "x86_64".to_string(),
                    kernel_version: None,
                    loongarch: LoongArchInfo {
                        detected: false,
                        cpu_model: None,
                        hwmon_paths: Vec::new(),
                        hwmon_sensors: Vec::new(),
                    },
                },
                warnings: Vec::new(),
            },
            mode,
            started_at_ms: ts,
            completed_at_ms: ts,
            status: crate::model::CollectionStatus::Complete,
            dimension_results: Vec::new(),
            attempted_dimensions: Vec::new(),
            updated_dimensions: Vec::new(),
            cpu: CpuSnapshot {
                usage_percent: Some(1.0),
                total_jiffies: 1,
                idle_jiffies: 0,
                cpu_count: 1,
                ..CpuSnapshot::default()
            },
            memory: MemorySnapshot {
                total_kb: 10,
                available_kb: 5,
                used_kb: 5,
                used_percent: Some(50.0),
                ..MemorySnapshot::default()
            },
            load: None,
            disks: Vec::new(),
            disk_devices: Vec::new(),
            network: crate::model::NetworkMetricsSnapshot::default(),
            thermal: crate::model::ThermalSnapshot::default(),
            alerts: Vec::new(),
        }
    }

    #[test]
    fn stores_and_queries_metric_snapshots_by_time() {
        let store = OsSenseStore::in_memory().expect("store");
        store
            .insert_metrics(&sample(100, crate::model::CollectionMode::OnDemand))
            .expect("insert old");
        store
            .insert_metrics(&sample(200, crate::model::CollectionMode::Scheduled))
            .expect("insert new");
        let rows = store.query_metrics_since(150).expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].meta.collected_at_ms, 200);
    }

    #[test]
    fn migrates_legacy_database_and_keeps_two_modes_in_the_same_millisecond() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("os-sense.sqlite3");
        let legacy = Connection::open(&path).expect("legacy database");
        legacy
            .execute_batch(
                r"
CREATE TABLE metric_snapshots (
    collected_at_ms INTEGER PRIMARY KEY,
    payload TEXT NOT NULL
);
CREATE INDEX idx_metric_snapshots_collected_at
ON metric_snapshots(collected_at_ms);
",
            )
            .expect("legacy schema");
        let on_demand = sample(1_000, crate::model::CollectionMode::OnDemand);
        legacy
            .execute(
                "INSERT INTO metric_snapshots(collected_at_ms, payload) VALUES (?1, ?2)",
                params![
                    1_000_i64,
                    serde_json::to_string(&on_demand).expect("payload")
                ],
            )
            .expect("legacy row");
        drop(legacy);

        let store = OsSenseStore::open(&path).expect("migrated store");
        store
            .insert_metrics(&sample(1_000, crate::model::CollectionMode::Scheduled))
            .expect("same-millisecond scheduled row");

        let rows = store.query_metrics_range(1_000, 1_000).expect("query");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].mode, crate::model::CollectionMode::OnDemand);
        assert_eq!(rows[1].mode, crate::model::CollectionMode::Scheduled);
    }
}
