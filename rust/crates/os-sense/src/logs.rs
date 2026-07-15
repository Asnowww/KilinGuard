use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::command::run_limited_command;
use crate::model::{CountByKey, LogEntry, LogPattern, LogQueryResult, LogSummary};
use crate::procfs::basic_meta;
use crate::redaction::redact_sensitive_text;

const DEFAULT_LOG_LIMIT: usize = 100;
const MAX_LOG_LIMIT: usize = 500;
const MAX_LOG_FILE_BYTES: u64 = 512 * 1024;
const MAX_LOG_COMMAND_BYTES: usize = 512 * 1024;
const MAX_LOG_MESSAGE_CHARS: usize = 512;

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

#[must_use]
pub fn query_logs(query: &LogQuery) -> LogQueryResult {
    let mut warnings = Vec::new();
    let limit = effective_log_limit(query.limit);
    let sources = if query.sources.is_empty() {
        vec![
            "journalctl".to_string(),
            "syslog".to_string(),
            "dmesg".to_string(),
            "auth".to_string(),
        ]
    } else {
        if query.sources.len() > 4 {
            warnings.push("log sources truncated to 4 entries".to_string());
        }
        query.sources.iter().take(4).cloned().collect()
    };
    let mut entries = Vec::new();

    for source in sources {
        match source.to_ascii_lowercase().as_str() {
            "journalctl" | "journal" => entries.extend(read_journalctl(query, &mut warnings)),
            "syslog" => entries.extend(read_log_files(
                "syslog",
                &["/var/log/syslog", "/var/log/messages"],
                query,
                &mut warnings,
            )),
            "auth" | "auth.log" => entries.extend(read_log_files(
                "auth",
                &["/var/log/auth.log", "/var/log/secure"],
                query,
                &mut warnings,
            )),
            "dmesg" => entries.extend(read_dmesg(query, &mut warnings)),
            other => warnings.push(format!("unsupported log source `{other}`")),
        }
    }

    entries = filter_entries(entries, query);
    let truncated =
        entries.len() > limit || warnings.iter().any(|warning| warning.contains("truncated"));
    entries.truncate(limit);
    let patterns = detect_log_patterns(&entries);
    let summary = query.summarize.then(|| summarize_logs(&entries));

    LogQueryResult {
        meta: basic_meta("logs", warnings),
        truncated,
        entries,
        patterns,
        summary,
    }
}

fn read_journalctl(query: &LogQuery, warnings: &mut Vec<String>) -> Vec<LogEntry> {
    let limit = effective_log_limit(query.limit).to_string();
    let mut args = vec![
        "--no-pager".to_string(),
        "--output=short-iso".to_string(),
        "-n".to_string(),
        limit,
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

    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    match run_limited_command(
        "journalctl",
        &arg_refs,
        Duration::from_secs(3),
        MAX_LOG_COMMAND_BYTES,
        32 * 1024,
    ) {
        Ok(output) if output.success => {
            if output.stdout_truncated {
                warnings.push("journalctl output was truncated".to_string());
            }
            output
                .stdout
                .lines()
                .map(|line| parse_log_line("journalctl", line))
                .collect()
        }
        Ok(output) => {
            if output.timed_out {
                warnings.push("journalctl timed out".to_string());
            } else {
                warnings.push(format!("journalctl failed: {}", output.stderr.trim()));
            }
            Vec::new()
        }
        Err(error) => {
            warnings.push(format!("journalctl unavailable: {error}"));
            Vec::new()
        }
    }
}

fn read_dmesg(query: &LogQuery, warnings: &mut Vec<String>) -> Vec<LogEntry> {
    let mut args = vec!["--time-format".to_string(), "iso".to_string()];
    if let Some(priority) = query.severity.as_deref().and_then(priority_for_severity) {
        args.push("--level".to_string());
        args.push(priority.to_string());
    }
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    match run_limited_command(
        "dmesg",
        &arg_refs,
        Duration::from_secs(3),
        MAX_LOG_COMMAND_BYTES,
        32 * 1024,
    ) {
        Ok(output) if output.success => {
            let lines = output
                .stdout
                .lines()
                .map(|line| parse_log_line("dmesg", line))
                .collect::<Vec<_>>();
            if output.stdout_truncated {
                warnings.push("dmesg output was truncated".to_string());
            }
            take_recent(lines, effective_log_limit(query.limit))
        }
        Ok(output) => {
            if output.timed_out {
                warnings.push("dmesg timed out".to_string());
            } else {
                warnings.push(format!("dmesg failed: {}", output.stderr.trim()));
            }
            Vec::new()
        }
        Err(error) => {
            warnings.push(format!("dmesg unavailable: {error}"));
            Vec::new()
        }
    }
}

fn read_log_files(
    source: &str,
    paths: &[&str],
    query: &LogQuery,
    warnings: &mut Vec<String>,
) -> Vec<LogEntry> {
    let Some(path) = paths
        .iter()
        .find(|path| std::path::Path::new(*path).exists())
    else {
        warnings.push(format!("no {source} log file found"));
        return Vec::new();
    };
    match read_tail_string(std::path::Path::new(*path), MAX_LOG_FILE_BYTES) {
        Ok((content, truncated)) => {
            if truncated {
                warnings.push(format!("{} was read from the tail and truncated", *path));
            }
            let entries = content
                .lines()
                .map(|line| parse_log_line(source, line))
                .collect::<Vec<_>>();
            take_recent(entries, effective_log_limit(query.limit))
        }
        Err(error) => {
            warnings.push(format!("failed to read {}: {error}", *path));
            Vec::new()
        }
    }
}

fn parse_log_line(source: &str, line: &str) -> LogEntry {
    let severity = infer_severity(line);
    let timestamp = infer_timestamp(source, line);
    LogEntry {
        source: source.to_string(),
        timestamp,
        severity,
        unit: infer_unit(line),
        message: redact_sensitive_text(line.trim(), MAX_LOG_MESSAGE_CHARS),
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

fn take_recent<T>(items: Vec<T>, limit: usize) -> Vec<T> {
    let len = items.len();
    items.into_iter().skip(len.saturating_sub(limit)).collect()
}

fn effective_log_limit(limit: Option<usize>) -> usize {
    limit.unwrap_or(DEFAULT_LOG_LIMIT).clamp(1, MAX_LOG_LIMIT)
}

fn read_tail_string(path: &std::path::Path, max_bytes: u64) -> std::io::Result<(String, bool)> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let truncated = len > max_bytes;
    if truncated {
        file.seek(SeekFrom::Start(len - max_bytes))?;
    }
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    if truncated {
        if let Some(idx) = content.find('\n') {
            content = content[idx + 1..].to_string();
        }
    }
    Ok((content, truncated))
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
    use super::*;

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
}
