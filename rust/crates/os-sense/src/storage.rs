use std::path::Path;
use std::time::Duration;

use rusqlite::types::ValueRef;
use rusqlite::{params, Connection};

use crate::error::{OsSenseError, Result};
use crate::model::{CorruptSampleDetail, MetricSnapshot};

pub const MAX_HISTORY_POINTS: usize = 720;
const MAX_HISTORY_POINTS_U64: u64 = 720;
const MAX_MIDDLE_HISTORY_POINTS_U64: u64 = MAX_HISTORY_POINTS_U64 - 2;
const MAX_CORRUPT_SAMPLE_DETAILS: usize = 10;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_millis(1_000);

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

pub struct HistoryQueryResult {
    pub samples: Vec<MetricSnapshot>,
    pub source_sample_count: u64,
    pub returned_sample_count: u64,
    pub bucket_width_ms: u64,
    pub downsampled: bool,
    pub skipped_corrupt_samples: u64,
    pub corrupt_sample_details: Vec<CorruptSampleDetail>,
    pub warnings: Vec<String>,
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
        let (collected_at_ms, payload) = stored_snapshot(snapshot)?;
        self.conn.execute(
            r"
INSERT INTO metric_snapshots(collected_at_ms, payload)
VALUES (?1, ?2)
",
            params![collected_at_ms, payload],
        )?;
        Ok(())
    }

    pub fn insert_metrics_and_prune(
        &mut self,
        snapshot: &MetricSnapshot,
        before_ms: u64,
    ) -> Result<usize> {
        let (collected_at_ms, payload) = stored_snapshot(snapshot)?;
        let before_ms = sqlite_timestamp(before_ms)?;
        let transaction = self.conn.transaction()?;
        transaction.execute(
            r"
INSERT INTO metric_snapshots(collected_at_ms, payload)
VALUES (?1, ?2)
",
            params![collected_at_ms, payload],
        )?;
        let deleted = transaction.execute(
            "DELETE FROM metric_snapshots WHERE collected_at_ms < ?1",
            params![before_ms],
        )?;
        transaction.commit()?;
        Ok(deleted)
    }

    pub fn query_metrics_since(&self, since_ms: u64) -> Result<Vec<MetricSnapshot>> {
        self.query_metrics_range(since_ms, u64::MAX)
    }

    pub fn query_metrics_range(&self, since_ms: u64, until_ms: u64) -> Result<Vec<MetricSnapshot>> {
        Ok(self.query_history_range(since_ms, until_ms)?.samples)
    }

    pub fn query_history_range(&self, since_ms: u64, until_ms: u64) -> Result<HistoryQueryResult> {
        if since_ms > until_ms {
            return Ok(empty_history_query());
        }
        let sqlite_since_ms = sqlite_timestamp(since_ms)?;
        let sqlite_until_ms = sqlite_timestamp(until_ms.min(i64::MAX as u64))?;
        let transaction = self.conn.unchecked_transaction()?;
        let (source_sample_count, first_row_ms, last_row_ms) = transaction.query_row(
            r"
SELECT COUNT(*), MIN(collected_at_ms), MAX(collected_at_ms) FROM metric_snapshots
WHERE collected_at_ms >= ?1 AND collected_at_ms <= ?2
",
            params![sqlite_since_ms, sqlite_until_ms],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<i64>>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )?;
        let source_sample_count = u64::try_from(source_sample_count)
            .map_err(|_| OsSenseError::Storage("negative SQLite row count".to_string()))?;
        let downsampled = source_sample_count > MAX_HISTORY_POINTS_U64;
        let bucket_width_ms = if downsampled {
            let first_row_ms = stored_timestamp(first_row_ms, "missing first sample timestamp")?;
            let last_row_ms = stored_timestamp(last_row_ms, "missing last sample timestamp")?;
            let span_ms = last_row_ms.saturating_sub(first_row_ms).saturating_add(1);
            span_ms / MAX_MIDDLE_HISTORY_POINTS_U64
                + u64::from(span_ms % MAX_MIDDLE_HISTORY_POINTS_U64 != 0)
        } else {
            0
        };
        let bucket_origin_ms = first_row_ms
            .map(|timestamp| {
                u64::try_from(timestamp)
                    .map_err(|_| OsSenseError::Storage("negative sample timestamp".to_string()))
            })
            .transpose()?
            .unwrap_or(0);

        let mut stmt = transaction.prepare(
            r"
SELECT sample_id, collected_at_ms, payload FROM metric_snapshots
WHERE collected_at_ms >= ?1 AND collected_at_ms <= ?2
ORDER BY collected_at_ms ASC, sample_id ASC
",
        )?;
        let mut rows = stmt.query(params![sqlite_since_ms, sqlite_until_ms])?;
        let mut middle_samples = Vec::with_capacity(
            MAX_HISTORY_POINTS
                .min(usize::try_from(source_sample_count).unwrap_or(MAX_HISTORY_POINTS)),
        );
        let mut skipped_corrupt_samples = 0_u64;
        let mut corrupt_sample_details = Vec::new();
        let mut selected_bucket = None;
        let mut first_sample = None;
        let mut last_sample = None;
        while let Some(row) = rows.next()? {
            let sample_id = row.get::<_, i64>(0)?;
            let collected_at_ms = u64::try_from(row.get::<_, i64>(1)?)
                .map_err(|_| OsSenseError::Storage("negative sample timestamp".to_string()))?;
            let decoded = match row.get_ref(2) {
                Ok(payload) => decode_metric_payload(payload),
                Err(_) => {
                    Err("invalid metric snapshot payload (unreadable SQLite value)".to_string())
                }
            };
            match decoded {
                Ok(snapshot) => {
                    if first_sample.is_none() {
                        first_sample = Some(snapshot);
                        continue;
                    }
                    if let Some((middle_timestamp, middle_snapshot)) =
                        last_sample.replace((collected_at_ms, snapshot))
                    {
                        let bucket = if downsampled {
                            Some((middle_timestamp - bucket_origin_ms) / bucket_width_ms)
                        } else {
                            None
                        };
                        if !downsampled || bucket != selected_bucket {
                            middle_samples.push(middle_snapshot);
                            selected_bucket = bucket;
                        }
                    }
                }
                Err(error) => {
                    skipped_corrupt_samples = skipped_corrupt_samples.saturating_add(1);
                    if corrupt_sample_details.len() < MAX_CORRUPT_SAMPLE_DETAILS {
                        corrupt_sample_details.push(CorruptSampleDetail {
                            sample_id,
                            collected_at_ms,
                            error,
                        });
                    }
                }
            }
        }
        drop(rows);
        drop(stmt);
        transaction.commit()?;

        let mut samples = Vec::with_capacity(
            2 + middle_samples
                .len()
                .min(MAX_HISTORY_POINTS.saturating_sub(2)),
        );
        if let Some(first_sample) = first_sample {
            samples.push(first_sample);
        }
        samples.extend(middle_samples);
        if let Some((_, last_sample)) = last_sample {
            samples.push(last_sample);
        }

        let returned_sample_count = u64::try_from(samples.len())
            .map_err(|_| OsSenseError::Storage("history result is too large".to_string()))?;
        let warnings = if skipped_corrupt_samples == 0 {
            Vec::new()
        } else {
            vec![format!(
                "skipped {skipped_corrupt_samples} corrupt metric sample(s); details are limited to {MAX_CORRUPT_SAMPLE_DETAILS}"
            )]
        };
        Ok(HistoryQueryResult {
            samples,
            source_sample_count,
            returned_sample_count,
            bucket_width_ms,
            downsampled,
            skipped_corrupt_samples,
            corrupt_sample_details,
            warnings,
        })
    }

    pub fn delete_metrics_before(&self, before_ms: u64) -> Result<usize> {
        let before_ms = sqlite_timestamp(before_ms)?;
        Ok(self.conn.execute(
            "DELETE FROM metric_snapshots WHERE collected_at_ms < ?1",
            params![before_ms],
        )?)
    }
}

fn empty_history_query() -> HistoryQueryResult {
    HistoryQueryResult {
        samples: Vec::new(),
        source_sample_count: 0,
        returned_sample_count: 0,
        bucket_width_ms: 0,
        downsampled: false,
        skipped_corrupt_samples: 0,
        corrupt_sample_details: Vec::new(),
        warnings: Vec::new(),
    }
}

fn stored_snapshot(snapshot: &MetricSnapshot) -> Result<(i64, String)> {
    let payload = serde_json::to_string(snapshot)?;
    let collected_at_ms = sqlite_timestamp(snapshot.meta.collected_at_ms)?;
    Ok((collected_at_ms, payload))
}

fn stored_timestamp(value: Option<i64>, missing_message: &str) -> Result<u64> {
    let value = value.ok_or_else(|| OsSenseError::Storage(missing_message.to_string()))?;
    u64::try_from(value).map_err(|_| OsSenseError::Storage("negative sample timestamp".to_string()))
}

fn decode_metric_payload(value: ValueRef<'_>) -> std::result::Result<MetricSnapshot, String> {
    let bytes = match value {
        ValueRef::Text(bytes) => bytes,
        ValueRef::Blob(_) => {
            return Err(
                "invalid metric snapshot payload (SQLite BLOB, expected UTF-8 text)".to_string(),
            );
        }
        ValueRef::Null => {
            return Err(
                "invalid metric snapshot payload (SQLite NULL, expected UTF-8 text)".to_string(),
            );
        }
        ValueRef::Integer(_) => {
            return Err(
                "invalid metric snapshot payload (SQLite integer, expected UTF-8 text)".to_string(),
            );
        }
        ValueRef::Real(_) => {
            return Err(
                "invalid metric snapshot payload (SQLite real, expected UTF-8 text)".to_string(),
            );
        }
    };
    let payload = std::str::from_utf8(bytes)
        .map_err(|_| "invalid metric snapshot payload (text is not valid UTF-8)".to_string())?;
    serde_json::from_str(payload).map_err(|error| describe_corrupt_payload(&error))
}

fn describe_corrupt_payload(error: &serde_json::Error) -> String {
    let category = match error.classify() {
        serde_json::error::Category::Io => "I/O",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "EOF",
    };
    format!(
        "invalid metric snapshot ({category} error at line {}, column {})",
        error.line(),
        error.column()
    )
}

fn sqlite_timestamp(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| OsSenseError::Storage("timestamp is too large for SQLite".to_string()))
}

fn init(conn: &Connection) -> Result<()> {
    conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
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
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::model::{
        CollectionMode, CollectionStatus, CpuSnapshot, LoongArchInfo, MemorySnapshot,
        MetricSnapshot, OsSampleMeta, PlatformInfo, SensorAvailability,
    };
    use crate::runtime::TimeSeriesWindow;

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
            alert_evaluations: crate::model::AlertEvaluationFreshness::default(),
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
    fn all_history_windows_include_both_endpoints_only() {
        for window in [
            TimeSeriesWindow::OneHour,
            TimeSeriesWindow::TwentyFourHours,
            TimeSeriesWindow::SevenDays,
        ] {
            let duration_ms = window.duration_ms();
            let store = OsSenseStore::in_memory().expect("store");
            let until_ms = duration_ms + 10_000;
            let since_ms = until_ms - duration_ms;
            for timestamp in [since_ms - 1, since_ms, until_ms, until_ms + 1] {
                store
                    .insert_metrics(&sample(timestamp, CollectionMode::Scheduled))
                    .expect("insert boundary sample");
            }

            let result = store
                .query_history_range(since_ms, until_ms)
                .expect("query window");
            let timestamps = result
                .samples
                .iter()
                .map(|snapshot| snapshot.meta.collected_at_ms)
                .collect::<Vec<_>>();
            assert_eq!(timestamps, vec![since_ms, until_ms]);
            assert_eq!(result.source_sample_count, 2);
            assert_eq!(result.returned_sample_count, 2);
        }
    }

    #[test]
    fn history_downsamples_into_stable_time_buckets_with_a_fixed_limit() {
        let store = OsSenseStore::in_memory().expect("store");
        let last_timestamp = MAX_HISTORY_POINTS_U64 * 1_000;
        for index in 0..=MAX_HISTORY_POINTS_U64 {
            store
                .insert_metrics(&sample(index * 1_000, CollectionMode::Scheduled))
                .expect("insert sample");
        }

        let first = store
            .query_history_range(0, last_timestamp)
            .expect("first query");
        let second = store
            .query_history_range(0, last_timestamp)
            .expect("second query");

        assert_eq!(first.source_sample_count, MAX_HISTORY_POINTS_U64 + 1);
        assert!(first.returned_sample_count <= MAX_HISTORY_POINTS_U64);
        assert_eq!(first.returned_sample_count, first.samples.len() as u64);
        assert!(first.bucket_width_ms > 0);
        assert!(first.downsampled);
        assert_eq!(first.samples, second.samples);
        assert_eq!(first.bucket_width_ms, second.bucket_width_ms);
    }

    #[test]
    fn downsampling_keeps_first_and_last_when_the_last_two_share_a_bucket() {
        let store = OsSenseStore::in_memory().expect("store");
        let last_timestamp = (MAX_HISTORY_POINTS_U64 - 1) * 1_000;
        for index in 0..MAX_HISTORY_POINTS_U64 {
            store
                .insert_metrics(&sample(index * 1_000, CollectionMode::OnDemand))
                .expect("insert sample");
        }
        store
            .insert_metrics(&sample(last_timestamp, CollectionMode::Scheduled))
            .expect("insert final same-bucket sample");

        let samples = store.query_metrics_since(0).expect("query since");
        let history = store
            .query_history_range(0, u64::MAX)
            .expect("query history");

        assert!(samples.len() <= MAX_HISTORY_POINTS);
        assert_eq!(samples.first().expect("first").meta.collected_at_ms, 0);
        let last = samples.last().expect("last");
        assert_eq!(last.meta.collected_at_ms, last_timestamp);
        assert_eq!(last.mode, CollectionMode::Scheduled);
        assert_eq!(history.source_sample_count, MAX_HISTORY_POINTS_U64 + 1);
        assert_eq!(history.samples, samples);
        assert!(history.bucket_width_ms <= 2_000);
    }

    #[test]
    fn corrupt_payloads_are_skipped_with_bounded_audit_details() {
        let store = OsSenseStore::in_memory().expect("store");
        store
            .insert_metrics(&sample(100, CollectionMode::Scheduled))
            .expect("valid sample");
        let secret = "raw-secret-must-not-be-returned";
        for offset in 0..12_i64 {
            store
                .conn
                .execute(
                    "INSERT INTO metric_snapshots(collected_at_ms, payload) VALUES (?1, ?2)",
                    params![101_i64 + offset, format!("{secret}{{")],
                )
                .expect("corrupt row");
        }

        let result = store.query_history_range(0, 1_000).expect("query");

        assert_eq!(result.source_sample_count, 13);
        assert_eq!(result.returned_sample_count, 1);
        assert_eq!(result.skipped_corrupt_samples, 12);
        assert_eq!(
            result.corrupt_sample_details.len(),
            MAX_CORRUPT_SAMPLE_DETAILS
        );
        assert!(!result.warnings.is_empty());
        for detail in &result.corrupt_sample_details {
            assert!(detail.sample_id > 0);
            assert!((101..=112).contains(&detail.collected_at_ms));
            assert!(!detail.error.contains(secret));
        }
        assert!(result
            .warnings
            .iter()
            .all(|warning| !warning.contains(secret)));
    }

    #[test]
    fn blob_and_non_utf8_payloads_are_skipped_without_leaking_content() {
        let store = OsSenseStore::in_memory().expect("store");
        store
            .insert_metrics(&sample(100, CollectionMode::OnDemand))
            .expect("first valid sample");
        let blob_secret = "blob-secret-must-not-leak";
        store
            .conn
            .execute(
                "INSERT INTO metric_snapshots(collected_at_ms, payload) VALUES (?1, ?2)",
                params![200_i64, blob_secret.as_bytes()],
            )
            .expect("BLOB payload");
        let utf8_secret = "utf8-secret-must-not-leak";
        let mut invalid_utf8 = utf8_secret.as_bytes().to_vec();
        invalid_utf8.push(0xff);
        store
            .conn
            .execute(
                "INSERT INTO metric_snapshots(collected_at_ms, payload) VALUES (?1, CAST(?2 AS TEXT))",
                params![201_i64, invalid_utf8],
            )
            .expect("non-UTF-8 text payload");
        store
            .insert_metrics(&sample(300, CollectionMode::Scheduled))
            .expect("last valid sample");

        let result = store.query_history_range(0, 1_000).expect("query");

        assert_eq!(result.source_sample_count, 4);
        assert_eq!(result.returned_sample_count, 2);
        assert_eq!(result.skipped_corrupt_samples, 2);
        assert_eq!(result.corrupt_sample_details.len(), 2);
        assert!(result.corrupt_sample_details[0].error.contains("BLOB"));
        assert!(result.corrupt_sample_details[1].error.contains("UTF-8"));
        for detail in &result.corrupt_sample_details {
            assert!(!detail.error.contains(blob_secret));
            assert!(!detail.error.contains(utf8_secret));
        }
        assert!(result
            .warnings
            .iter()
            .all(|warning| { !warning.contains(blob_secret) && !warning.contains(utf8_secret) }));
        assert_eq!(result.samples[0].meta.collected_at_ms, 100);
        assert_eq!(result.samples[1].meta.collected_at_ms, 300);
    }

    #[test]
    fn file_database_can_be_closed_and_reopened() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("os-sense.sqlite3");
        {
            let store = OsSenseStore::open(&path).expect("open store");
            store
                .insert_metrics(&sample(123, CollectionMode::Scheduled))
                .expect("insert");
        }

        let reopened = OsSenseStore::open(&path).expect("reopen store");
        let result = reopened.query_history_range(123, 123).expect("query");
        assert_eq!(result.returned_sample_count, 1);
        assert_eq!(result.samples[0].meta.collected_at_ms, 123);
    }

    #[test]
    fn old_payload_without_new_metric_fields_remains_readable() {
        let store = OsSenseStore::in_memory().expect("store");
        let old_payload = r#"{
            "meta": {
                "collected_at_ms": 500,
                "source": "procfs",
                "platform": {
                    "os": "linux",
                    "arch": "loongarch64",
                    "kernel_version": "6.6.0-kylin",
                    "loongarch": {
                        "detected": true,
                        "cpu_model": "Loongson-3A5000",
                        "hwmon_paths": []
                    }
                },
                "warnings": []
            },
            "cpu": {
                "usage_percent": 25.0,
                "total_jiffies": 100,
                "idle_jiffies": 75,
                "cpu_count": 1
            },
            "memory": {
                "total_kb": 1024,
                "available_kb": 512,
                "used_kb": 512,
                "used_percent": 50.0
            },
            "load": null,
            "disks": [],
            "thermal": {
                "collected_at_ms": 500,
                "availability": "unavailable",
                "thermal_zone_available": false,
                "hwmon_available": false,
                "temperatures": [],
                "fans": []
            },
            "alerts": [{
                "dimension": "disk",
                "severity": "warning",
                "message": "legacy alert",
                "value": 95.0,
                "threshold": 90.0
            }]
        }"#;
        store
            .conn
            .execute(
                "INSERT INTO metric_snapshots(collected_at_ms, payload) VALUES (?1, ?2)",
                params![500_i64, old_payload],
            )
            .expect("old payload");

        let result = store.query_history_range(500, 500).expect("query");

        assert_eq!(result.skipped_corrupt_samples, 0);
        assert_eq!(result.returned_sample_count, 1);
        let snapshot = &result.samples[0];
        assert_eq!(snapshot.mode, CollectionMode::OnDemand);
        assert_eq!(snapshot.status, CollectionStatus::Partial);
        assert_eq!(snapshot.alerts.len(), 1);
        assert_eq!(snapshot.alerts[0].subject, None);
        assert!(snapshot.disk_devices.is_empty());
        assert!(snapshot.network.interfaces.is_empty());
        assert_eq!(
            snapshot.thermal.availability,
            SensorAvailability::Unavailable
        );
        assert!(snapshot.thermal.hwmon_sensors.is_empty());
    }

    #[test]
    fn transactional_prune_keeps_the_exact_retention_boundary() {
        let mut store = OsSenseStore::in_memory().expect("store");
        store
            .insert_metrics(&sample(999, CollectionMode::Scheduled))
            .expect("older sample");
        store
            .insert_metrics(&sample(1_000, CollectionMode::Scheduled))
            .expect("boundary sample");

        let deleted = store
            .insert_metrics_and_prune(&sample(2_000, CollectionMode::Scheduled), 1_000)
            .expect("atomic insert and prune");
        let result = store.query_history_range(0, 2_000).expect("query");
        let timestamps = result
            .samples
            .iter()
            .map(|snapshot| snapshot.meta.collected_at_ms)
            .collect::<Vec<_>>();

        assert_eq!(deleted, 1);
        assert_eq!(timestamps, vec![1_000, 2_000]);
    }

    #[test]
    fn wal_allows_a_writer_while_another_connection_is_reading() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("os-sense.sqlite3");
        let reader = OsSenseStore::open(&path).expect("reader");
        let writer = OsSenseStore::open(&path).expect("writer");
        reader
            .conn
            .execute_batch("BEGIN DEFERRED;")
            .expect("begin read transaction");
        let initial_count = reader
            .conn
            .query_row("SELECT COUNT(*) FROM metric_snapshots", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("read snapshot");
        assert_eq!(initial_count, 0);

        writer
            .insert_metrics(&sample(100, CollectionMode::Scheduled))
            .expect("WAL writer");
        reader.conn.execute_batch("COMMIT;").expect("commit reader");

        let result = reader.query_history_range(0, 100).expect("query");
        assert_eq!(result.returned_sample_count, 1);
    }

    #[test]
    fn busy_timeout_recovers_from_a_short_lock_and_errors_on_a_long_lock() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("os-sense.sqlite3");
        let locker = OsSenseStore::open(&path).expect("locker");
        let contender = OsSenseStore::open(&path).expect("contender");
        locker
            .conn
            .execute_batch("BEGIN IMMEDIATE;")
            .expect("short write lock");
        let handle = thread::spawn(move || {
            let result = contender.insert_metrics(&sample(100, CollectionMode::Scheduled));
            (contender, result)
        });
        thread::sleep(Duration::from_millis(100));
        locker
            .conn
            .execute_batch("COMMIT;")
            .expect("release short lock");
        let (contender, recovered) = handle.join().expect("join writer");
        recovered.expect("writer should recover after short lock");

        locker
            .conn
            .execute_batch("BEGIN IMMEDIATE;")
            .expect("long write lock");
        let started = Instant::now();
        let error = contender
            .insert_metrics(&sample(200, CollectionMode::Scheduled))
            .expect_err("writer must time out while lock is held");
        let elapsed = started.elapsed();
        locker
            .conn
            .execute_batch("ROLLBACK;")
            .expect("release long lock");

        assert!(elapsed >= SQLITE_BUSY_TIMEOUT.saturating_sub(Duration::from_millis(200)));
        assert!(error.to_string().contains("locked") || error.to_string().contains("busy"));
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
        let on_demand = sample(1_000, CollectionMode::OnDemand);
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
            .insert_metrics(&sample(1_000, CollectionMode::Scheduled))
            .expect("same-millisecond scheduled row");

        let rows = store.query_metrics_range(1_000, 1_000).expect("query");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].mode, CollectionMode::OnDemand);
        assert_eq!(rows[1].mode, CollectionMode::Scheduled);
    }
}
