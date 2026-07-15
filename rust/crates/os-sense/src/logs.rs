use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::command::{run_limited_command, LimitedCommandOutput};
use crate::error::{OsSenseError, Result};
use crate::model::{
    CollectionStatus, CountByKey, LogEntry, LogPattern, LogQueryResult, LogSourceStatus, LogSummary,
};
use crate::procfs::basic_meta;
use crate::redaction::redact_sensitive_text;

const DEFAULT_LOG_LIMIT: usize = 100;
const MAX_LOG_LIMIT: usize = 500;
const MAX_LOG_FILE_BYTES: u64 = 512 * 1024;
const MAX_LOG_COMMAND_BYTES: usize = 512 * 1024;
const MAX_LOG_MESSAGE_CHARS: usize = 512;
const MAX_LOG_RAW_LINE_BYTES: usize = 4 * 1024;
const MAX_LOG_WARNINGS: usize = 32;
const MAX_LOG_ERROR_CHARS: usize = 256;
const MAX_LOG_SOURCES: usize = 4;
const SYSLOG_PATHS: [&str; 2] = ["/var/log/messages", "/var/log/syslog"];
const AUTH_LOG_PATHS: [&str; 2] = ["/var/log/secure", "/var/log/auth.log"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct LogQuery {
    pub sources: Vec<String>,
    pub keyword: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub severity: Option<String>,
    pub limit: Option<usize>,
    pub summarize: bool,
}

impl Default for LogQuery {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            keyword: None,
            since: None,
            until: None,
            severity: None,
            limit: Some(DEFAULT_LOG_LIMIT),
            summarize: true,
        }
    }
}

impl LogQuery {
    pub fn validate(&self) -> Result<()> {
        if self.sources.len() > MAX_LOG_SOURCES {
            return Err(OsSenseError::Configuration(format!(
                "log query sources must not contain more than {MAX_LOG_SOURCES} entries"
            )));
        }
        normalize_sources(&self.sources)?;
        for (name, value, max_chars) in [
            ("keyword", self.keyword.as_deref(), 128),
            ("since", self.since.as_deref(), 64),
            ("until", self.until.as_deref(), 64),
        ] {
            if let Some(value) = value {
                if value.contains('\0') || value.chars().count() > max_chars {
                    return Err(OsSenseError::Configuration(format!(
                        "log query {name} must not contain NUL or exceed {max_chars} characters"
                    )));
                }
            }
        }
        if let Some(severity) = &self.severity {
            if priority_for_severity(severity).is_none() {
                return Err(OsSenseError::Configuration(format!(
                    "unsupported log severity `{}`",
                    bounded_error(severity)
                )));
            }
        }
        if let Some(limit) = self.limit {
            if !(1..=MAX_LOG_LIMIT).contains(&limit) {
                return Err(OsSenseError::Configuration(format!(
                    "log query limit must be between 1 and {MAX_LOG_LIMIT}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LogicalLogSource {
    Journalctl,
    Syslog,
    Dmesg,
    Auth,
}

impl LogicalLogSource {
    const DEFAULT: [Self; 4] = [Self::Journalctl, Self::Syslog, Self::Dmesg, Self::Auth];

    const fn name(self) -> &'static str {
        match self {
            Self::Journalctl => "journalctl",
            Self::Syslog => "syslog",
            Self::Dmesg => "dmesg",
            Self::Auth => "auth",
        }
    }
}

struct SourceCollection {
    status: LogSourceStatus,
    entries: Vec<LogEntry>,
    warnings: Vec<String>,
}

struct TailBytes {
    bytes: Vec<u8>,
    truncated: bool,
}

trait LogCommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> std::io::Result<LimitedCommandOutput>;
}

struct SystemLogCommandRunner;

impl LogCommandRunner for SystemLogCommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> std::io::Result<LimitedCommandOutput> {
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        run_limited_command(program, &args, timeout, stdout_limit, stderr_limit)
    }
}

trait LogFileReader {
    fn read_tail(&self, path: &Path, max_bytes: u64) -> std::io::Result<TailBytes>;
}

struct SystemLogFileReader;

impl LogFileReader for SystemLogFileReader {
    fn read_tail(&self, path: &Path, max_bytes: u64) -> std::io::Result<TailBytes> {
        read_tail_bytes(path, max_bytes)
    }
}

pub fn query_logs(query: &LogQuery) -> Result<LogQueryResult> {
    query_logs_with(query, &SystemLogCommandRunner, &SystemLogFileReader)
}

fn query_logs_with(
    query: &LogQuery,
    command_runner: &dyn LogCommandRunner,
    file_reader: &dyn LogFileReader,
) -> Result<LogQueryResult> {
    query.validate()?;
    let sources = normalize_sources(&query.sources)?;
    let limit = effective_log_limit(query.limit);
    let mut warnings = Vec::new();
    let mut omitted_warning_count = 0usize;
    let mut entries_by_source = Vec::with_capacity(sources.len());
    let mut source_statuses = Vec::with_capacity(sources.len());
    for source in sources {
        let collected = match source {
            LogicalLogSource::Journalctl => read_journalctl(query, command_runner),
            LogicalLogSource::Syslog => read_log_files(source, &SYSLOG_PATHS, query, file_reader),
            LogicalLogSource::Dmesg => read_dmesg(query, command_runner),
            LogicalLogSource::Auth => read_log_files(source, &AUTH_LOG_PATHS, query, file_reader),
        };
        for warning in collected.warnings {
            push_log_warning(&mut warnings, &mut omitted_warning_count, warning);
        }
        entries_by_source.push(filter_entries(collected.entries, query));
        source_statuses.push(collected.status);
    }

    let source_truncated = source_statuses.iter().any(|status| status.truncated);
    let (entries, merge_truncated) = merge_entries_round_robin(entries_by_source, limit);
    let truncated = source_truncated || merge_truncated;
    let collection_status = if source_statuses
        .iter()
        .all(|status| status.status == CollectionStatus::Failed)
    {
        CollectionStatus::Failed
    } else if source_statuses
        .iter()
        .all(|status| status.status == CollectionStatus::Complete)
    {
        CollectionStatus::Complete
    } else {
        CollectionStatus::Partial
    };
    let patterns = detect_log_patterns(&entries);
    let summary = query.summarize.then(|| summarize_logs(&entries));
    let mut meta = basic_meta("logs", warnings);
    if meta.warnings.len() > MAX_LOG_WARNINGS {
        omitted_warning_count = omitted_warning_count
            .saturating_add(meta.warnings.len().saturating_sub(MAX_LOG_WARNINGS));
        meta.warnings.truncate(MAX_LOG_WARNINGS);
    }

    Ok(LogQueryResult {
        meta,
        truncated,
        collection_status,
        source_statuses,
        omitted_warning_count,
        entries,
        patterns,
        summary,
    })
}

fn merge_entries_round_robin(
    entries_by_source: Vec<Vec<LogEntry>>,
    limit: usize,
) -> (Vec<LogEntry>, bool) {
    let matching_entry_count = entries_by_source.iter().map(Vec::len).sum::<usize>();
    let mut queues = entries_by_source
        .into_iter()
        .map(VecDeque::from)
        .collect::<Vec<_>>();
    let mut merged = Vec::with_capacity(limit.min(matching_entry_count));
    while merged.len() < limit {
        let previous_len = merged.len();
        for queue in &mut queues {
            if merged.len() == limit {
                break;
            }
            if let Some(entry) = queue.pop_front() {
                merged.push(entry);
            }
        }
        if merged.len() == previous_len {
            break;
        }
    }
    (merged, matching_entry_count > limit)
}

fn normalize_sources(sources: &[String]) -> Result<Vec<LogicalLogSource>> {
    if sources.is_empty() {
        return Ok(LogicalLogSource::DEFAULT.to_vec());
    }
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::new();
    for source in sources {
        let source = match source.trim().to_ascii_lowercase().as_str() {
            "journalctl" | "journal" => LogicalLogSource::Journalctl,
            "syslog" => LogicalLogSource::Syslog,
            "dmesg" => LogicalLogSource::Dmesg,
            "auth" | "auth.log" => LogicalLogSource::Auth,
            other => {
                return Err(OsSenseError::Configuration(format!(
                    "unsupported log source `{}`",
                    bounded_error(other)
                )))
            }
        };
        if seen.insert(source) {
            normalized.push(source);
        }
    }
    Ok(normalized)
}

fn read_journalctl(query: &LogQuery, runner: &dyn LogCommandRunner) -> SourceCollection {
    let limit = effective_log_limit(query.limit);
    let requested_limit = limit.saturating_add(1).to_string();
    let mut args = vec![
        "--no-pager".to_string(),
        "--output=short-iso".to_string(),
        "-n".to_string(),
        requested_limit,
    ];
    if let Some(since) = &query.since {
        args.push("--since".to_string());
        args.push(since.clone());
    }
    if let Some(until) = &query.until {
        args.push("--until".to_string());
        args.push(until.clone());
    }
    if let Some(priority) = query.severity.as_deref().and_then(priority_for_severity) {
        args.push("-p".to_string());
        args.push(priority.to_string());
    }

    read_command_source(
        LogicalLogSource::Journalctl,
        "journalctl",
        args,
        runner,
        limit,
    )
}

fn read_dmesg(query: &LogQuery, runner: &dyn LogCommandRunner) -> SourceCollection {
    let mut args = vec!["--time-format".to_string(), "iso".to_string()];
    if let Some(priority) = query.severity.as_deref().and_then(dmesg_level_for_severity) {
        args.push("--level".to_string());
        args.push(priority.to_string());
    }
    read_command_source(
        LogicalLogSource::Dmesg,
        "dmesg",
        args,
        runner,
        effective_log_limit(query.limit),
    )
}

fn read_log_files(
    source: LogicalLogSource,
    paths: &[&str],
    query: &LogQuery,
    reader: &dyn LogFileReader,
) -> SourceCollection {
    let mut failures = Vec::new();
    for path in paths {
        match reader.read_tail(Path::new(path), MAX_LOG_FILE_BYTES) {
            Ok(tail) => {
                let (entries, line_truncated) =
                    parse_log_bytes(path, &tail.bytes, effective_log_limit(query.limit));
                let truncated = tail.truncated || line_truncated;
                let mut warnings = failures;
                if truncated {
                    warnings.push(format!("{path} was read from a bounded tail"));
                }
                return SourceCollection {
                    status: LogSourceStatus {
                        logical_source: source.name().to_string(),
                        actual_source: Some((*path).to_string()),
                        available: true,
                        status: if truncated {
                            CollectionStatus::Partial
                        } else {
                            CollectionStatus::Complete
                        },
                        error: None,
                        entry_count: entries.len(),
                        truncated,
                    },
                    entries,
                    warnings,
                };
            }
            Err(error) => failures.push(format!(
                "failed to read {path}: {}",
                bounded_error(&error.to_string())
            )),
        }
    }
    let error = bounded_error(&failures.join("; "));
    SourceCollection {
        status: LogSourceStatus {
            logical_source: source.name().to_string(),
            actual_source: None,
            available: false,
            status: CollectionStatus::Failed,
            error: Some(error.clone()),
            entry_count: 0,
            truncated: false,
        },
        entries: Vec::new(),
        warnings: vec![format!("{} log source failed: {error}", source.name())],
    }
}

fn read_command_source(
    source: LogicalLogSource,
    program: &str,
    args: Vec<String>,
    runner: &dyn LogCommandRunner,
    limit: usize,
) -> SourceCollection {
    match runner.run(
        program,
        &args,
        Duration::from_secs(3),
        MAX_LOG_COMMAND_BYTES,
        32 * 1024,
    ) {
        Ok(output) if output.success && !output.timed_out => {
            let (entries, line_truncated) =
                parse_log_bytes(program, output.stdout.as_bytes(), limit);
            let truncated = output.stdout_truncated || output.stderr_truncated || line_truncated;
            let warnings = truncated
                .then(|| format!("{program} output was bounded or truncated"))
                .into_iter()
                .collect();
            SourceCollection {
                status: LogSourceStatus {
                    logical_source: source.name().to_string(),
                    actual_source: Some(program.to_string()),
                    available: true,
                    status: if truncated {
                        CollectionStatus::Partial
                    } else {
                        CollectionStatus::Complete
                    },
                    error: None,
                    entry_count: entries.len(),
                    truncated,
                },
                entries,
                warnings,
            }
        }
        Ok(output) => {
            let error = if output.timed_out {
                format!("{program} timed out")
            } else {
                format!("{program} failed: {}", bounded_error(output.stderr.trim()))
            };
            SourceCollection {
                status: LogSourceStatus {
                    logical_source: source.name().to_string(),
                    actual_source: Some(program.to_string()),
                    available: true,
                    status: CollectionStatus::Failed,
                    error: Some(error.clone()),
                    entry_count: 0,
                    truncated: output.stdout_truncated || output.stderr_truncated,
                },
                entries: Vec::new(),
                warnings: vec![error],
            }
        }
        Err(error) => {
            let error = format!(
                "{program} unavailable: {}",
                bounded_error(&error.to_string())
            );
            SourceCollection {
                status: LogSourceStatus {
                    logical_source: source.name().to_string(),
                    actual_source: None,
                    available: false,
                    status: CollectionStatus::Failed,
                    error: Some(error.clone()),
                    entry_count: 0,
                    truncated: false,
                },
                entries: Vec::new(),
                warnings: vec![error],
            }
        }
    }
}

fn parse_log_bytes(source: &str, bytes: &[u8], limit: usize) -> (Vec<LogEntry>, bool) {
    let mut entries = VecDeque::with_capacity(limit.min(bytes.len()));
    let mut truncated = false;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let bounded = if line.len() > MAX_LOG_RAW_LINE_BYTES {
            truncated = true;
            &line[..MAX_LOG_RAW_LINE_BYTES]
        } else {
            line
        };
        let line = String::from_utf8_lossy(bounded);
        entries.push_back(parse_log_line(source, &line));
        if entries.len() > limit {
            entries.pop_front();
            truncated = true;
        }
    }
    (entries.into_iter().collect(), truncated)
}

fn push_log_warning(warnings: &mut Vec<String>, omitted: &mut usize, warning: String) {
    if warnings.len() < MAX_LOG_WARNINGS {
        warnings.push(bounded_error(&warning));
    } else {
        *omitted = omitted.saturating_add(1);
    }
}

fn bounded_error(value: &str) -> String {
    redact_log_text(value, MAX_LOG_ERROR_CHARS)
}

fn redact_log_text(value: &str, max_chars: usize) -> String {
    const TRUNCATION_MARKER_CHARS: usize = "...[truncated]".len();
    redact_sensitive_text(value, max_chars.saturating_sub(TRUNCATION_MARKER_CHARS))
}

fn parse_log_line(source: &str, line: &str) -> LogEntry {
    let severity = infer_severity(line);
    let timestamp = infer_timestamp(source, line);
    LogEntry {
        source: source.to_string(),
        timestamp,
        severity,
        unit: infer_unit(line),
        message: redact_log_text(line.trim(), MAX_LOG_MESSAGE_CHARS),
    }
}

fn filter_entries(entries: Vec<LogEntry>, query: &LogQuery) -> Vec<LogEntry> {
    entries
        .into_iter()
        .filter(|entry| {
            if let Some(keyword) = &query.keyword {
                if !entry
                    .message
                    .to_ascii_lowercase()
                    .contains(&keyword.to_ascii_lowercase())
                {
                    return false;
                }
            }
            if let Some(severity) = &query.severity {
                let wanted = severity.to_ascii_lowercase();
                if !entry.severity.as_ref().is_some_and(|actual| {
                    actual.eq_ignore_ascii_case(&wanted)
                        || severity_rank(actual) <= severity_rank(&wanted)
                }) {
                    return false;
                }
            }
            true
        })
        .collect()
}

fn detect_log_patterns(entries: &[LogEntry]) -> Vec<LogPattern> {
    let mut patterns = Vec::new();
    let error_count = entries
        .iter()
        .filter(|entry| {
            entry
                .severity
                .as_deref()
                .is_some_and(|severity| severity_rank(severity) <= severity_rank("error"))
        })
        .count();
    if error_count >= 5 {
        patterns.push(LogPattern {
            kind: "error_frequency".to_string(),
            count: error_count,
            message: "error-level log volume is elevated in the queried sample".to_string(),
        });
    }

    let mut repeated = BTreeMap::<String, usize>::new();
    for entry in entries {
        *repeated
            .entry(normalize_message(&entry.message))
            .or_default() += 1;
    }
    if let Some((message, count)) = repeated
        .into_iter()
        .filter(|(_, count)| *count >= 3)
        .max_by_key(|(_, count)| *count)
    {
        patterns.push(LogPattern {
            kind: "repeating_message".to_string(),
            count,
            message,
        });
    }
    patterns
}

fn summarize_logs(entries: &[LogEntry]) -> LogSummary {
    let by_source = counts_by(entries.iter().map(|entry| entry.source.as_str()));
    let by_severity = counts_by(
        entries
            .iter()
            .map(|entry| entry.severity.as_deref().unwrap_or("unknown")),
    );
    let errors = entries
        .iter()
        .filter(|entry| {
            entry
                .severity
                .as_deref()
                .is_some_and(|severity| severity_rank(severity) <= severity_rank("error"))
        })
        .count();
    let text = if entries.is_empty() {
        "No log entries matched the query.".to_string()
    } else if errors > 0 {
        format!(
            "{} log entries matched; {} are error-level or higher. Inspect patterns and newest entries first.",
            entries.len(),
            errors
        )
    } else {
        format!(
            "{} log entries matched with no error-level events detected in the sample.",
            entries.len()
        )
    };
    LogSummary {
        kind: "rule_based_llm_ready_summary".to_string(),
        text,
        by_source,
        by_severity,
    }
}

fn counts_by<'a>(values: impl Iterator<Item = &'a str>) -> Vec<CountByKey> {
    let mut counts = BTreeMap::<String, usize>::new();
    for value in values {
        *counts.entry(value.to_string()).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(key, count)| CountByKey { key, count })
        .collect()
}

fn effective_log_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(DEFAULT_LOG_LIMIT).clamp(1, MAX_LOG_LIMIT)
}

fn read_tail_bytes(path: &Path, max_bytes: u64) -> std::io::Result<TailBytes> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let truncated = len > max_bytes;
    if truncated {
        file.seek(SeekFrom::Start(len - max_bytes))?;
    }
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024) as usize);
    file.take(max_bytes).read_to_end(&mut bytes)?;
    if truncated {
        if let Some(index) = bytes.iter().position(|byte| *byte == b'\n') {
            bytes.drain(..=index);
        } else {
            bytes.clear();
        }
    }
    Ok(TailBytes { bytes, truncated })
}

fn infer_timestamp(source: &str, line: &str) -> Option<String> {
    if source == "journalctl" {
        let timestamp = line
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        return (!timestamp.is_empty()).then_some(timestamp);
    }
    if source == "dmesg" {
        return line.find(']').map(|idx| {
            line[..=idx]
                .trim()
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string()
        });
    }
    let mut parts = line.split_whitespace();
    let month = parts.next()?;
    let day = parts.next()?;
    let time = parts.next()?;
    Some(format!("{month} {day} {time}"))
}

fn infer_unit(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|part| {
            let clean = part.trim_matches(|ch| matches!(ch, '[' | ']' | ':'));
            clean.ends_with(".service") || clean.ends_with(".timer") || clean.ends_with(".socket")
        })
        .map(|part| {
            part.trim_matches(|ch| matches!(ch, '[' | ']' | ':'))
                .to_string()
        })
}

fn infer_severity(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    [
        ("emerg", "emergency"),
        ("panic", "critical"),
        ("crit", "critical"),
        ("fatal", "critical"),
        ("error", "error"),
        ("err", "error"),
        ("failed", "error"),
        ("denied", "warning"),
        ("warn", "warning"),
        ("notice", "notice"),
        ("info", "info"),
        ("debug", "debug"),
    ]
    .iter()
    .find_map(|(needle, severity)| lower.contains(needle).then(|| (*severity).to_string()))
}

fn priority_for_severity(severity: &str) -> Option<&'static str> {
    match severity.to_ascii_lowercase().as_str() {
        "emergency" | "emerg" => Some("emerg"),
        "alert" => Some("alert"),
        "critical" | "crit" => Some("crit"),
        "error" | "err" => Some("err"),
        "warning" | "warn" => Some("warning"),
        "notice" => Some("notice"),
        "info" => Some("info"),
        "debug" => Some("debug"),
        _ => None,
    }
}

fn dmesg_level_for_severity(severity: &str) -> Option<&'static str> {
    match severity.to_ascii_lowercase().as_str() {
        "emergency" | "emerg" => Some("emerg"),
        "alert" => Some("alert"),
        "critical" | "crit" => Some("crit"),
        "error" | "err" => Some("err"),
        "warning" | "warn" => Some("warn"),
        "notice" => Some("notice"),
        "info" => Some("info"),
        "debug" => Some("debug"),
        _ => None,
    }
}

fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "emergency" | "emerg" => 0,
        "alert" => 1,
        "critical" | "crit" => 2,
        "error" | "err" => 3,
        "warning" | "warn" => 4,
        "notice" => 5,
        "info" => 6,
        "debug" => 7,
        _ => 8,
    }
}

fn normalize_message(message: &str) -> String {
    message
        .split_whitespace()
        .map(|token| {
            if token.chars().any(|ch| ch.is_ascii_digit()) {
                "#"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;
    use std::sync::Mutex;

    use super::*;

    #[derive(Clone)]
    enum CommandFixture {
        Output(LimitedCommandOutput),
        Error(ErrorKind),
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct CommandCall {
        program: String,
        args: Vec<String>,
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    }

    #[derive(Default)]
    struct FixtureCommandRunner {
        fixtures: BTreeMap<String, CommandFixture>,
        calls: Mutex<Vec<CommandCall>>,
    }

    impl FixtureCommandRunner {
        fn with_output(mut self, program: &str, output: LimitedCommandOutput) -> Self {
            self.fixtures
                .insert(program.to_string(), CommandFixture::Output(output));
            self
        }

        fn with_error(mut self, program: &str, kind: ErrorKind) -> Self {
            self.fixtures
                .insert(program.to_string(), CommandFixture::Error(kind));
            self
        }

        fn calls(&self) -> Vec<CommandCall> {
            self.calls.lock().expect("command calls").clone()
        }
    }

    impl LogCommandRunner for FixtureCommandRunner {
        fn run(
            &self,
            program: &str,
            args: &[String],
            timeout: Duration,
            stdout_limit: usize,
            stderr_limit: usize,
        ) -> std::io::Result<LimitedCommandOutput> {
            self.calls.lock().expect("command calls").push(CommandCall {
                program: program.to_string(),
                args: args.to_vec(),
                timeout,
                stdout_limit,
                stderr_limit,
            });
            match self.fixtures.get(program) {
                Some(CommandFixture::Output(output)) => Ok(output.clone()),
                Some(CommandFixture::Error(kind)) => {
                    Err(std::io::Error::new(*kind, "fixture command failure"))
                }
                None => Err(std::io::Error::new(
                    ErrorKind::NotFound,
                    "missing command fixture",
                )),
            }
        }
    }

    #[derive(Clone)]
    enum FileFixture {
        Tail(Vec<u8>, bool),
        Error(ErrorKind),
    }

    #[derive(Default)]
    struct FixtureLogFileReader {
        fixtures: BTreeMap<String, FileFixture>,
        calls: Mutex<Vec<(String, u64)>>,
    }

    impl FixtureLogFileReader {
        fn with_tail(mut self, path: &str, bytes: impl Into<Vec<u8>>, truncated: bool) -> Self {
            self.fixtures
                .insert(path.to_string(), FileFixture::Tail(bytes.into(), truncated));
            self
        }

        fn with_error(mut self, path: &str, kind: ErrorKind) -> Self {
            self.fixtures
                .insert(path.to_string(), FileFixture::Error(kind));
            self
        }

        fn calls(&self) -> Vec<(String, u64)> {
            self.calls.lock().expect("file calls").clone()
        }
    }

    impl LogFileReader for FixtureLogFileReader {
        fn read_tail(&self, path: &Path, max_bytes: u64) -> std::io::Result<TailBytes> {
            let path = path.to_string_lossy().into_owned();
            self.calls
                .lock()
                .expect("file calls")
                .push((path.clone(), max_bytes));
            match self.fixtures.get(&path) {
                Some(FileFixture::Tail(bytes, truncated)) => Ok(TailBytes {
                    bytes: bytes.clone(),
                    truncated: *truncated,
                }),
                Some(FileFixture::Error(kind)) => {
                    Err(std::io::Error::new(*kind, "fixture file failure"))
                }
                None => Err(std::io::Error::new(
                    ErrorKind::NotFound,
                    "missing file fixture",
                )),
            }
        }
    }

    fn command_output(stdout: impl Into<String>) -> LimitedCommandOutput {
        LimitedCommandOutput {
            success: true,
            stdout: stdout.into(),
            stderr: String::new(),
            timed_out: false,
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    fn failed_command(timed_out: bool) -> LimitedCommandOutput {
        LimitedCommandOutput {
            success: false,
            stdout: String::new(),
            stderr: "permission denied".to_string(),
            timed_out,
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    #[test]
    fn infers_log_severity_and_unit() {
        let entry = parse_log_line(
            "journalctl",
            "2026-01-01 host sshd.service: Failed password",
        );
        assert_eq!(entry.severity.as_deref(), Some("error"));
        assert_eq!(entry.unit.as_deref(), Some("sshd.service"));
    }

    #[test]
    fn detects_error_frequency_and_repeats() {
        let entries = (0..6)
            .map(|idx| LogEntry {
                source: "syslog".to_string(),
                timestamp: None,
                severity: Some("error".to_string()),
                unit: None,
                message: format!("service failed with code {idx}"),
            })
            .collect::<Vec<_>>();
        let patterns = detect_log_patterns(&entries);
        assert!(patterns
            .iter()
            .any(|pattern| pattern.kind == "error_frequency"));
        assert!(patterns
            .iter()
            .any(|pattern| pattern.kind == "repeating_message"));
    }

    #[test]
    fn builds_rule_based_summary() {
        let entries = vec![LogEntry {
            source: "auth".to_string(),
            timestamp: None,
            severity: Some("warning".to_string()),
            unit: None,
            message: "denied".to_string(),
        }];
        let summary = summarize_logs(&entries);
        assert_eq!(summary.kind, "rule_based_llm_ready_summary");
        assert!(summary.text.contains("1 log entries"));
    }

    #[test]
    fn collects_four_sources_with_fixed_commands_and_kylin_fallbacks() {
        let commands = FixtureCommandRunner::default()
            .with_output(
                "journalctl",
                command_output("2026-01-01 10:00:00 host kernel: info journal event\n"),
            )
            .with_output("dmesg", command_output("[2026-01-01T10:00:00] info boot\n"));
        let files = FixtureLogFileReader::default()
            .with_error("/var/log/messages", ErrorKind::NotFound)
            .with_tail(
                "/var/log/syslog",
                b"Jan 1 10:00:01 host daemon: info syslog event\n".to_vec(),
                false,
            )
            .with_error("/var/log/secure", ErrorKind::PermissionDenied)
            .with_tail(
                "/var/log/auth.log",
                b"Jan 1 10:00:02 host sshd: denied invalid \xff user\n".to_vec(),
                false,
            );
        let query = LogQuery {
            limit: Some(10),
            ..LogQuery::default()
        };

        let result = query_logs_with(&query, &commands, &files).expect("log query");

        assert_eq!(result.collection_status, CollectionStatus::Complete);
        assert_eq!(result.source_statuses.len(), 4);
        assert_eq!(
            result
                .source_statuses
                .iter()
                .map(|status| (
                    status.logical_source.as_str(),
                    status.actual_source.as_deref()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("journalctl", Some("journalctl")),
                ("syslog", Some("/var/log/syslog")),
                ("dmesg", Some("dmesg")),
                ("auth", Some("/var/log/auth.log")),
            ]
        );
        assert!(
            result
                .entries
                .iter()
                .any(|entry| entry.source == "/var/log/auth.log"
                    && entry.message.contains('\u{fffd}'))
        );

        let calls = commands.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].program, "journalctl");
        assert_eq!(
            calls[0].args,
            ["--no-pager", "--output=short-iso", "-n", "11"]
        );
        assert_eq!(calls[0].timeout, Duration::from_secs(3));
        assert_eq!(calls[0].stdout_limit, MAX_LOG_COMMAND_BYTES);
        assert_eq!(calls[1].program, "dmesg");
        assert_eq!(calls[1].args, ["--time-format", "iso"]);

        assert_eq!(
            files.calls(),
            vec![
                ("/var/log/messages".to_string(), MAX_LOG_FILE_BYTES),
                ("/var/log/syslog".to_string(), MAX_LOG_FILE_BYTES),
                ("/var/log/secure".to_string(), MAX_LOG_FILE_BYTES),
                ("/var/log/auth.log".to_string(), MAX_LOG_FILE_BYTES),
            ]
        );
    }

    #[test]
    fn round_robin_merge_prevents_later_sources_from_starving() {
        let journal = (0..8)
            .map(|index| format!("2026-01-01 10:00:0{index} journal event {index}\n"))
            .collect::<String>();
        let commands = FixtureCommandRunner::default()
            .with_output("journalctl", command_output(journal))
            .with_output("dmesg", command_output("[2026-01-01] dmesg event\n"));
        let files = FixtureLogFileReader::default()
            .with_tail(
                "/var/log/messages",
                b"Jan 1 10:00:00 syslog event\n".to_vec(),
                false,
            )
            .with_tail(
                "/var/log/secure",
                b"Jan 1 10:00:00 auth event\n".to_vec(),
                false,
            );

        let result = query_logs_with(
            &LogQuery {
                limit: Some(8),
                ..LogQuery::default()
            },
            &commands,
            &files,
        )
        .expect("fair multi-source query");

        assert_eq!(result.entries.len(), 8);
        assert!(result.truncated);
        for source in [
            "journalctl",
            "/var/log/messages",
            "dmesg",
            "/var/log/secure",
        ] {
            assert!(result.entries.iter().any(|entry| entry.source == source));
        }
        assert_eq!(
            result
                .entries
                .iter()
                .take(4)
                .map(|entry| entry.source.as_str())
                .collect::<Vec<_>>(),
            [
                "journalctl",
                "/var/log/messages",
                "dmesg",
                "/var/log/secure"
            ]
        );
        assert_eq!(
            result
                .source_statuses
                .iter()
                .map(|status| status.entry_count)
                .collect::<Vec<_>>(),
            [8, 1, 1, 1]
        );
    }

    #[test]
    fn single_source_merge_preserves_entry_order_without_false_truncation() {
        let commands = FixtureCommandRunner::default().with_output(
            "journalctl",
            command_output(
                "2026-01-01 10:00:00 event zero\n2026-01-01 10:00:01 event one\n2026-01-01 10:00:02 event two\n",
            ),
        );

        let result = query_logs_with(
            &LogQuery {
                sources: vec!["journalctl".to_string()],
                limit: Some(3),
                ..LogQuery::default()
            },
            &commands,
            &FixtureLogFileReader::default(),
        )
        .expect("single-source query");

        assert!(!result.truncated);
        assert_eq!(result.entries.len(), 3);
        assert!(result.entries[0].message.ends_with("event zero"));
        assert!(result.entries[1].message.ends_with("event one"));
        assert!(result.entries[2].message.ends_with("event two"));
    }

    #[test]
    fn journalctl_uses_fixed_time_and_priority_arguments() {
        let commands = FixtureCommandRunner::default()
            .with_output("journalctl", command_output("2026-01-01 event\n"));
        let query = LogQuery {
            sources: vec!["journalctl".to_string()],
            since: Some("2026-01-01 00:00:00".to_string()),
            until: Some("2026-01-02 00:00:00".to_string()),
            severity: Some("warning".to_string()),
            limit: Some(5),
            ..LogQuery::default()
        };

        query_logs_with(&query, &commands, &FixtureLogFileReader::default())
            .expect("journal query");

        assert_eq!(
            commands.calls()[0].args,
            [
                "--no-pager",
                "--output=short-iso",
                "-n",
                "6",
                "--since",
                "2026-01-01 00:00:00",
                "--until",
                "2026-01-02 00:00:00",
                "-p",
                "warning",
            ]
        );
    }

    #[test]
    fn journalctl_extra_probe_row_detects_truncation_without_false_positive() {
        let query = LogQuery {
            sources: vec!["journalctl".to_string()],
            limit: Some(2),
            ..LogQuery::default()
        };
        let three_rows = FixtureCommandRunner::default().with_output(
            "journalctl",
            command_output("2026-01-01 event one\n2026-01-01 event two\n2026-01-01 event three\n"),
        );
        let truncated = query_logs_with(&query, &three_rows, &FixtureLogFileReader::default())
            .expect("three journal rows");
        assert_eq!(three_rows.calls()[0].args[3], "3");
        assert_eq!(truncated.entries.len(), 2);
        assert!(truncated.truncated);
        assert!(truncated.source_statuses[0].truncated);

        let two_rows = FixtureCommandRunner::default().with_output(
            "journalctl",
            command_output("2026-01-01 event one\n2026-01-01 event two\n"),
        );
        let complete = query_logs_with(&query, &two_rows, &FixtureLogFileReader::default())
            .expect("two journal rows");
        assert_eq!(complete.entries.len(), 2);
        assert!(!complete.truncated);
        assert!(!complete.source_statuses[0].truncated);
    }

    #[test]
    fn dmesg_uses_util_linux_level_names() {
        let commands = FixtureCommandRunner::default()
            .with_output("dmesg", command_output("[2026-01-01] event\n"));
        for severity in ["warning", "warn", "error", "err", "critical", "crit"] {
            read_dmesg(
                &LogQuery {
                    severity: Some(severity.to_string()),
                    ..LogQuery::default()
                },
                &commands,
            );
        }

        assert_eq!(
            commands
                .calls()
                .into_iter()
                .map(|call| call.args)
                .collect::<Vec<_>>(),
            vec![
                vec!["--time-format", "iso", "--level", "warn"],
                vec!["--time-format", "iso", "--level", "warn"],
                vec!["--time-format", "iso", "--level", "err"],
                vec!["--time-format", "iso", "--level", "err"],
                vec!["--time-format", "iso", "--level", "crit"],
                vec!["--time-format", "iso", "--level", "crit"],
            ]
        );
    }

    #[test]
    fn aliases_deduplicate_and_invalid_queries_fail_before_collection() {
        let commands = FixtureCommandRunner::default()
            .with_output("journalctl", command_output("2026-01-01 event\n"));
        let files = FixtureLogFileReader::default().with_tail(
            "/var/log/secure",
            b"Jan 1 10:00:00 auth event\n".to_vec(),
            false,
        );
        let query = LogQuery {
            sources: vec![
                "journal".to_string(),
                "journalctl".to_string(),
                "auth".to_string(),
                "auth.log".to_string(),
            ],
            ..LogQuery::default()
        };

        let result = query_logs_with(&query, &commands, &files).expect("deduplicated query");
        assert_eq!(result.source_statuses.len(), 2);
        assert_eq!(commands.calls().len(), 1);
        assert_eq!(files.calls().len(), 1);

        for invalid in [
            LogQuery {
                sources: vec!["kern.log".to_string()],
                ..LogQuery::default()
            },
            LogQuery {
                sources: vec!["journalctl".to_string(); MAX_LOG_SOURCES + 1],
                ..LogQuery::default()
            },
            LogQuery {
                limit: Some(0),
                ..LogQuery::default()
            },
        ] {
            assert!(matches!(
                query_logs(&invalid),
                Err(OsSenseError::Configuration(_))
            ));
        }
    }

    #[test]
    fn source_failures_report_partial_and_failed_statuses() {
        let commands = FixtureCommandRunner::default()
            .with_output("journalctl", failed_command(true))
            .with_error("dmesg", ErrorKind::PermissionDenied);
        let files = FixtureLogFileReader::default();
        let failed =
            query_logs_with(&LogQuery::default(), &commands, &files).expect("structured failures");
        assert_eq!(failed.collection_status, CollectionStatus::Failed);
        assert!(failed.entries.is_empty());
        assert!(failed
            .source_statuses
            .iter()
            .all(|status| status.status == CollectionStatus::Failed));

        let mut bounded = command_output(format!("error {}\n", "x".repeat(8 * 1024)));
        bounded.stdout_truncated = true;
        let commands = FixtureCommandRunner::default().with_output("journalctl", bounded);
        let partial = query_logs_with(
            &LogQuery {
                sources: vec!["journalctl".to_string(), "syslog".to_string()],
                ..LogQuery::default()
            },
            &commands,
            &FixtureLogFileReader::default(),
        )
        .expect("partial query");
        assert_eq!(partial.collection_status, CollectionStatus::Partial);
        assert!(partial.truncated);
        assert!(partial.entries[0].message.chars().count() <= MAX_LOG_MESSAGE_CHARS);
        assert!(partial.meta.warnings.len() <= MAX_LOG_WARNINGS);
    }

    #[test]
    fn warnings_and_entries_remain_hard_bounded() {
        let mut warnings = Vec::new();
        let mut omitted = 0;
        for index in 0..100 {
            push_log_warning(&mut warnings, &mut omitted, format!("warning {index}"));
        }
        assert_eq!(warnings.len(), MAX_LOG_WARNINGS);
        assert_eq!(omitted, 100 - MAX_LOG_WARNINGS);

        let input = (0..700)
            .map(|index| format!("Jan 1 10:00:00 line {index}\n"))
            .collect::<String>();
        let (entries, truncated) = parse_log_bytes("syslog", input.as_bytes(), MAX_LOG_LIMIT);
        assert_eq!(entries.len(), MAX_LOG_LIMIT);
        assert!(truncated);
        assert!(entries[0].message.ends_with("line 200"));
    }

    #[test]
    fn legacy_log_result_defaults_new_collection_fields() {
        let value = serde_json::json!({
            "meta": basic_meta("logs", Vec::new()),
            "truncated": false,
            "entries": [],
            "patterns": [],
            "summary": null
        });
        let result: LogQueryResult = serde_json::from_value(value).expect("legacy log result");
        assert_eq!(result.collection_status, CollectionStatus::Partial);
        assert!(result.source_statuses.is_empty());
        assert_eq!(result.omitted_warning_count, 0);
    }
}
