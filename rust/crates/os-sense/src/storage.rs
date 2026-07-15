use std::path::Path;

use rusqlite::{params, Connection};

use crate::error::{OsSenseError, Result};
use crate::model::MetricSnapshot;

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS metric_snapshots (
    collected_at_ms INTEGER PRIMARY KEY,
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
INSERT OR REPLACE INTO metric_snapshots(collected_at_ms, payload)
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
ORDER BY collected_at_ms ASC
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
    conn.execute_batch(SCHEMA)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::model::{
        CpuSnapshot, LoongArchInfo, MemorySnapshot, MetricSnapshot, OsSampleMeta, PlatformInfo,
    };

    use super::*;

    fn sample(ts: u64) -> MetricSnapshot {
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
            cpu: CpuSnapshot {
                usage_percent: Some(1.0),
                total_jiffies: 1,
                idle_jiffies: 0,
                cpu_count: 1,
            },
            memory: MemorySnapshot {
                total_kb: 10,
                available_kb: 5,
                used_kb: 5,
                used_percent: Some(50.0),
            },
            load: None,
            disks: Vec::new(),
            alerts: Vec::new(),
        }
    }

    #[test]
    fn stores_and_queries_metric_snapshots_by_time() {
        let store = OsSenseStore::in_memory().expect("store");
        store.insert_metrics(&sample(100)).expect("insert old");
        store.insert_metrics(&sample(200)).expect("insert new");
        let rows = store.query_metrics_since(150).expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].meta.collected_at_ms, 200);
    }
}
