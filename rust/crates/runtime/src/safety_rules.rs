//! Runtime safety rule snapshots and hot-reloadable rule store.
//!
//! The rule engine intentionally supports only bounded literal/token/glob/path
//! prefix matching. It does not execute regular expressions.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::Read as _;
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::safety_intent::{
    ImpactScope, IntentTarget, IntentTargetKind, RiskLevel, RiskPolicy, SafetyAction,
};

pub const SAFETY_RULE_SCHEMA_VERSION: u32 = 1;
const MAX_RULE_FILE_BYTES: u64 = 1_048_576;
const MAX_RULE_COUNT: usize = 512;
const MAX_RULE_ID_BYTES: usize = 96;
const MAX_RULE_PATTERN_BYTES: usize = 512;
const MAX_RULE_EVIDENCE_BYTES: usize = 512;
const MAX_SOURCE_SUMMARY_BYTES: usize = 160;

const BUILTIN_RULE_IDS: &[&str] = &[
    "builtin.rm-root-system",
    "builtin.mkfs",
    "builtin.wipefs",
    "builtin.dd-block-overwrite",
    "builtin.fork-bomb",
    "builtin.chmod-777",
    "builtin.chown-root",
    "builtin.suid-bit",
    "builtin.credential-read",
    "builtin.key-exfiltration",
    "builtin.sensitive-path-write",
    "builtin.rm-recursive-glob",
    "builtin.path-traversal",
    "builtin.option-injection-target",
    "builtin.shell-expansion",
    "builtin.redirection-sensitive-path",
    "builtin.encoded-pipe-shell",
    "builtin.remote-script-pipe",
    "builtin.nested-exec",
    "builtin.eval-exec",
];

const SENSITIVE_WRITE_PATHS: &[&str] = &[
    "/boot",
    "/boot/efi",
    "/etc/fstab",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/usr/bin",
    "/usr/sbin",
    "/proc",
    "/sys",
    "/dev",
];

const SENSITIVE_CREDENTIAL_PATHS: &[&str] = &["/etc/shadow", "/etc/sudoers", "/root/.ssh", "/home"];

/// A validated, immutable rules snapshot.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyRuleSnapshot {
    pub schema_version: u32,
    pub generation: u64,
    pub rules: Vec<SafetyRuleDefinition>,
    pub builtin_rule_count: usize,
    pub content_hash: String,
    pub updated_at_epoch_ms: u128,
    pub source_summary: String,
}

impl SafetyRuleSnapshot {
    /// Evaluate all rules against one structured intent input.
    #[must_use]
    pub fn evaluate(&self, input: &SafetyRuleInput<'_>) -> Vec<SafetyRuleMatch> {
        self.rules
            .iter()
            .filter_map(|rule| rule_match(rule, input))
            .collect()
    }
}

/// Runtime rule input. Raw text is private and must not be copied to reports.
#[derive(Debug, Clone, Copy)]
pub struct SafetyRuleInput<'a> {
    pub action: SafetyAction,
    pub impact_scope: ImpactScope,
    pub raw_text: &'a str,
    pub targets: &'a [IntentTarget],
}

/// A rule match safe for public reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyRuleMatch {
    pub rule_id: String,
    pub level: RiskLevel,
    pub policy: RiskPolicy,
    pub match_kind: SafetyRuleMatchKind,
    pub hard: bool,
    pub evidence: Vec<String>,
}

/// Strict JSON rule file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafetyRuleConfigFile {
    pub schema_version: u32,
    pub generation: u64,
    #[serde(default)]
    pub rules: Vec<SafetyRuleDefinition>,
}

/// One bounded safety rule definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafetyRuleDefinition {
    pub id: String,
    pub level: RiskLevel,
    pub policy: RiskPolicy,
    pub match_kind: SafetyRuleMatchKind,
    pub pattern: String,
    pub evidence: String,
    #[serde(default)]
    pub hard: bool,
    #[serde(default)]
    pub builtin: bool,
}

/// Supported rule match kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyRuleMatchKind {
    Literal,
    Token,
    Glob,
    PathPrefix,
    Builtin,
}

/// Thread-safe rule store with atomic Arc snapshot replacement.
#[derive(Debug)]
pub struct SafetyRuleStore {
    inner: RwLock<Arc<SafetyRuleSnapshot>>,
}

impl Default for SafetyRuleStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyRuleStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(builtin_safety_rule_snapshot()),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<SafetyRuleSnapshot> {
        self.inner
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn reload_from_str(
        &self,
        source_summary: impl AsRef<str>,
        content: &str,
    ) -> Result<Arc<SafetyRuleSnapshot>, SafetyRuleError> {
        self.reload_from_bytes(source_summary, content.as_bytes())
    }

    pub fn reload_from_bytes(
        &self,
        source_summary: impl AsRef<str>,
        bytes: &[u8],
    ) -> Result<Arc<SafetyRuleSnapshot>, SafetyRuleError> {
        if bytes.len() as u64 > MAX_RULE_FILE_BYTES {
            return Err(SafetyRuleError::limit_exceeded(format!(
                "rule file exceeds byte limit {MAX_RULE_FILE_BYTES}"
            )));
        }
        let current = self.snapshot();
        let snapshot = build_snapshot_from_bytes(source_summary.as_ref(), bytes, &current)?;
        let snapshot = Arc::new(snapshot);
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if snapshot.generation <= guard.generation {
            return Err(SafetyRuleError::invalid_rules(
                "rule generation must be strictly greater than current generation",
            ));
        }
        *guard = snapshot.clone();
        Ok(snapshot)
    }

    pub fn reload_from_trusted_file(
        &self,
        path: &Path,
    ) -> Result<Arc<SafetyRuleSnapshot>, SafetyRuleError> {
        let _lstat = reject_symlink_or_special_file(path)?;
        let mut file = File::open(path)
            .map_err(|error| SafetyRuleError::io(format!("failed to open rule file: {error}")))?;
        let metadata = file
            .metadata()
            .map_err(|error| SafetyRuleError::io(format!("failed to stat rule file: {error}")))?;
        if !metadata.is_file() {
            return Err(SafetyRuleError::invalid_rules(
                "rule file must be a regular file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if _lstat.dev() != metadata.dev() || _lstat.ino() != metadata.ino() {
                return Err(SafetyRuleError::invalid_rules(
                    "rule file changed during validation",
                ));
            }
        }
        if metadata.len() > MAX_RULE_FILE_BYTES {
            return Err(SafetyRuleError::limit_exceeded(format!(
                "rule file exceeds byte limit {MAX_RULE_FILE_BYTES}"
            )));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| SafetyRuleError::io(format!("failed to read rule file: {error}")))?;
        if bytes.len() as u64 > MAX_RULE_FILE_BYTES {
            return Err(SafetyRuleError::limit_exceeded(format!(
                "rule file exceeds byte limit {MAX_RULE_FILE_BYTES}"
            )));
        }
        self.reload_from_bytes(path_summary(path), &bytes)
    }
}

/// Built-in immutable default snapshot.
#[must_use]
pub fn builtin_safety_rule_snapshot() -> Arc<SafetyRuleSnapshot> {
    static SNAPSHOT: OnceLock<Arc<SafetyRuleSnapshot>> = OnceLock::new();
    SNAPSHOT
        .get_or_init(|| Arc::new(build_builtin_snapshot()))
        .clone()
}

fn build_builtin_snapshot() -> SafetyRuleSnapshot {
    let rules = builtin_rule_definitions();
    validate_rules(&rules, true).expect("built-in safety rules must validate");
    let builtin_ids = rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<BTreeSet<_>>();
    for expected in BUILTIN_RULE_IDS {
        assert!(
            builtin_ids.contains(expected),
            "built-in safety rule `{expected}` is missing"
        );
    }
    SafetyRuleSnapshot {
        schema_version: SAFETY_RULE_SCHEMA_VERSION,
        generation: 0,
        builtin_rule_count: rules.len(),
        content_hash: hash_bytes(
            serde_json::to_vec(&rules)
                .expect("built-in safety rules should serialize")
                .as_slice(),
        ),
        updated_at_epoch_ms: now_epoch_ms(),
        source_summary: "builtin".to_string(),
        rules,
    }
}

fn build_snapshot_from_bytes(
    source_summary: &str,
    bytes: &[u8],
    current: &SafetyRuleSnapshot,
) -> Result<SafetyRuleSnapshot, SafetyRuleError> {
    let parsed: SafetyRuleConfigFile = serde_json::from_slice(bytes)
        .map_err(|error| SafetyRuleError::invalid_rules(format!("invalid rule JSON: {error}")))?;
    if parsed.schema_version != SAFETY_RULE_SCHEMA_VERSION {
        return Err(SafetyRuleError::invalid_rules(format!(
            "unsupported safety rule schemaVersion {}",
            parsed.schema_version
        )));
    }
    if parsed.generation <= current.generation {
        return Err(SafetyRuleError::invalid_rules(
            "rule generation must be strictly greater than current generation",
        ));
    }
    validate_rules(&parsed.rules, false)?;
    let mut rules = builtin_rule_definitions();
    let builtin_count = rules.len();
    rules.extend(parsed.rules);
    validate_rules(&rules, true)?;
    Ok(SafetyRuleSnapshot {
        schema_version: SAFETY_RULE_SCHEMA_VERSION,
        generation: parsed.generation,
        builtin_rule_count: builtin_count,
        content_hash: hash_bytes(bytes),
        updated_at_epoch_ms: now_epoch_ms(),
        source_summary: redact_summary(source_summary),
        rules,
    })
}

fn validate_rules(
    rules: &[SafetyRuleDefinition],
    allow_builtin: bool,
) -> Result<(), SafetyRuleError> {
    if rules.len() > MAX_RULE_COUNT {
        return Err(SafetyRuleError::limit_exceeded(format!(
            "rule count exceeds limit {MAX_RULE_COUNT}"
        )));
    }
    let mut seen = BTreeSet::new();
    for rule in rules {
        validate_rule_string("rule id", &rule.id, MAX_RULE_ID_BYTES)?;
        validate_rule_string("rule pattern", &rule.pattern, MAX_RULE_PATTERN_BYTES)?;
        validate_rule_string("rule evidence", &rule.evidence, MAX_RULE_EVIDENCE_BYTES)?;
        validate_rule_id(&rule.id)?;
        validate_level_policy(rule.level, rule.policy)?;
        if !seen.insert(rule.id.clone()) {
            return Err(SafetyRuleError::invalid_rules(format!(
                "duplicate safety rule id `{}`",
                rule.id
            )));
        }
        if rule.id.starts_with("builtin.") && !rule.builtin {
            return Err(SafetyRuleError::invalid_rules(
                "custom rules cannot use built-in rule ids",
            ));
        }
        if rule.builtin && !allow_builtin {
            return Err(SafetyRuleError::invalid_rules(
                "custom rule files cannot declare built-in rules",
            ));
        }
        if rule.hard && !rule.builtin {
            return Err(SafetyRuleError::invalid_rules(
                "custom rules cannot declare immutable hard rules",
            ));
        }
        if !rule.builtin && rule.match_kind == SafetyRuleMatchKind::Builtin {
            return Err(SafetyRuleError::invalid_rules(
                "custom rules cannot use built-in match kind",
            ));
        }
        if !rule.builtin && rule.match_kind == SafetyRuleMatchKind::PathPrefix {
            validate_path_prefix_pattern(&rule.pattern)?;
        }
    }
    Ok(())
}

fn validate_rule_id(id: &str) -> Result<(), SafetyRuleError> {
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return Err(SafetyRuleError::invalid_rules("rule id must not be empty"));
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(SafetyRuleError::invalid_rules(
            "rule id must start with [a-z0-9]",
        ));
    }
    if !chars
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(SafetyRuleError::invalid_rules(
            "rule id must contain only [a-z0-9._-]",
        ));
    }
    Ok(())
}

fn validate_level_policy(level: RiskLevel, policy: RiskPolicy) -> Result<(), SafetyRuleError> {
    let expected = match level {
        RiskLevel::L1 => RiskPolicy::Allow,
        RiskLevel::L2 => RiskPolicy::Audit,
        RiskLevel::L3 => RiskPolicy::Confirm,
        RiskLevel::L4 => RiskPolicy::Deny,
    };
    if policy != expected {
        return Err(SafetyRuleError::invalid_rules(
            "rule level and policy are inconsistent",
        ));
    }
    Ok(())
}

fn validate_path_prefix_pattern(pattern: &str) -> Result<(), SafetyRuleError> {
    if !pattern.starts_with('/') {
        return Err(SafetyRuleError::invalid_rules(
            "pathPrefix pattern must be absolute",
        ));
    }
    if token_has_shell_expansion(pattern) || pattern.contains("..") {
        return Err(SafetyRuleError::invalid_rules(
            "pathPrefix pattern must not contain glob or traversal",
        ));
    }
    if normalize_path(pattern) != pattern.trim_end_matches('/').to_string()
        && !(pattern == "/" && normalize_path(pattern) == "/")
    {
        return Err(SafetyRuleError::invalid_rules(
            "pathPrefix pattern must be normalized",
        ));
    }
    Ok(())
}

fn validate_rule_string(field: &str, value: &str, max: usize) -> Result<(), SafetyRuleError> {
    if value.trim().is_empty() {
        return Err(SafetyRuleError::invalid_rules(format!(
            "{field} must not be empty"
        )));
    }
    if value.len() > max {
        return Err(SafetyRuleError::limit_exceeded(format!(
            "{field} exceeds byte limit {max}"
        )));
    }
    Ok(())
}

fn builtin_rule_definitions() -> Vec<SafetyRuleDefinition> {
    BUILTIN_RULE_IDS
        .iter()
        .map(|id| SafetyRuleDefinition {
            id: (*id).to_string(),
            level: match *id {
                "builtin.path-traversal"
                | "builtin.option-injection-target"
                | "builtin.shell-expansion"
                | "builtin.remote-script-pipe"
                | "builtin.nested-exec"
                | "builtin.eval-exec" => RiskLevel::L3,
                _ => RiskLevel::L4,
            },
            policy: match *id {
                "builtin.path-traversal"
                | "builtin.option-injection-target"
                | "builtin.shell-expansion"
                | "builtin.remote-script-pipe"
                | "builtin.nested-exec"
                | "builtin.eval-exec" => RiskPolicy::Confirm,
                _ => RiskPolicy::Deny,
            },
            match_kind: SafetyRuleMatchKind::Builtin,
            pattern: (*id).to_string(),
            evidence: builtin_rule_evidence(id).to_string(),
            hard: matches!(
                *id,
                "builtin.rm-root-system"
                    | "builtin.mkfs"
                    | "builtin.wipefs"
                    | "builtin.dd-block-overwrite"
                    | "builtin.fork-bomb"
                    | "builtin.credential-read"
                    | "builtin.key-exfiltration"
                    | "builtin.sensitive-path-write"
                    | "builtin.redirection-sensitive-path"
                    | "builtin.encoded-pipe-shell"
            ),
            builtin: true,
        })
        .collect()
}

fn builtin_rule_evidence(id: &str) -> &'static str {
    match id {
        "builtin.rm-root-system" => "recursive forced removal targets root or system paths",
        "builtin.mkfs" => "filesystem format command",
        "builtin.wipefs" => "filesystem signature wipe command",
        "builtin.dd-block-overwrite" => "dd writes zeroes or data to a block device",
        "builtin.fork-bomb" => "fork bomb command pattern",
        "builtin.chmod-777" => "world-writable chmod mode",
        "builtin.chown-root" => "ownership change to root",
        "builtin.suid-bit" => "SUID/SGID permission bit change",
        "builtin.credential-read" => "read targets credential or private key path",
        "builtin.key-exfiltration" => "network command references credential or key path",
        "builtin.sensitive-path-write" => "write/delete/restore targets sensitive system path",
        "builtin.rm-recursive-glob" => "recursive rm targets shell glob or brace expansion",
        "builtin.path-traversal" => "path contains parent traversal",
        "builtin.option-injection-target" => "structured target begins with '-'",
        "builtin.shell-expansion" => "state-changing command uses shell glob or brace expansion",
        "builtin.redirection-sensitive-path" => "redirection writes to sensitive path",
        "builtin.encoded-pipe-shell" => "encoded payload is piped to a shell/interpreter",
        "builtin.remote-script-pipe" => "remote script is piped to a shell/interpreter",
        "builtin.nested-exec" => "nested command execution",
        "builtin.eval-exec" => "eval or equivalent dynamic execution",
        _ => "built-in safety rule",
    }
}

fn rule_match(rule: &SafetyRuleDefinition, input: &SafetyRuleInput<'_>) -> Option<SafetyRuleMatch> {
    let mut evidence = if rule.builtin {
        match_builtin_rule(rule.id.as_str(), input)
    } else if match_configurable_rule(rule, input) {
        Some(vec![redact_summary(&rule.evidence)])
    } else {
        None
    }?;
    let mut level = rule.level;
    let mut policy = rule.policy;
    let mut hard = rule.hard;
    if rule.id == "builtin.nested-exec" && nested_exec_contains_l4_semantics(input) {
        level = RiskLevel::L4;
        policy = RiskPolicy::Deny;
        hard = true;
        evidence.push("nested execution contains hard L4 dangerous semantics".to_string());
    }
    Some(SafetyRuleMatch {
        rule_id: rule.id.clone(),
        level,
        policy,
        match_kind: rule.match_kind,
        hard,
        evidence,
    })
}

fn match_configurable_rule(rule: &SafetyRuleDefinition, input: &SafetyRuleInput<'_>) -> bool {
    match rule.match_kind {
        SafetyRuleMatchKind::Literal => input
            .raw_text
            .to_ascii_lowercase()
            .contains(&rule.pattern.to_ascii_lowercase()),
        SafetyRuleMatchKind::Token => command_tokens(input.raw_text)
            .iter()
            .any(|token| token.eq_ignore_ascii_case(&rule.pattern)),
        SafetyRuleMatchKind::Glob => bounded_glob_match(
            &rule.pattern.to_ascii_lowercase(),
            &input.raw_text.to_ascii_lowercase(),
        ),
        SafetyRuleMatchKind::PathPrefix => candidate_paths(input)
            .iter()
            .any(|path| path_has_prefix(path, &normalize_path(&rule.pattern))),
        SafetyRuleMatchKind::Builtin => false,
    }
}

fn match_builtin_rule(id: &str, input: &SafetyRuleInput<'_>) -> Option<Vec<String>> {
    let raw_lower = input.raw_text.to_ascii_lowercase();
    let tokens = command_tokens(input.raw_text);
    let lower_tokens = tokens
        .iter()
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let first = first_command(&lower_tokens);
    let paths = candidate_paths(input);
    match id {
        "builtin.rm-root-system" => {
            if first == "rm"
                && has_flag(&lower_tokens, "r")
                && has_flag(&lower_tokens, "f")
                && paths
                    .iter()
                    .any(|path| is_sensitive_write_path(path) || path == "/")
            {
                Some(vec![
                    "rm -rf targets root or sensitive system path".to_string()
                ])
            } else {
                None
            }
        }
        "builtin.mkfs" => (first.starts_with("mkfs")
            || lower_tokens.iter().any(|t| t.starts_with("mkfs.")))
        .then(|| vec!["mkfs command detected".to_string()]),
        "builtin.wipefs" => {
            (first == "wipefs").then(|| vec!["wipefs command detected".to_string()])
        }
        "builtin.dd-block-overwrite" => {
            if first == "dd"
                && lower_tokens
                    .iter()
                    .any(|token| token.starts_with("of=/dev/"))
            {
                Some(vec!["dd writes to /dev block target".to_string()])
            } else {
                None
            }
        }
        "builtin.fork-bomb" => raw_lower
            .contains(":(){")
            .then(|| vec!["fork bomb token sequence detected".to_string()]),
        "builtin.chmod-777" => {
            if first == "chmod" && lower_tokens.iter().any(|token| token == "777") {
                Some(vec!["chmod 777 detected".to_string()])
            } else {
                None
            }
        }
        "builtin.chown-root" => {
            if first == "chown"
                && lower_tokens
                    .iter()
                    .skip(1)
                    .any(|token| matches!(token.as_str(), "root" | "root:" | "root:root" | ":root"))
            {
                Some(vec!["chown target owner/group is root".to_string()])
            } else {
                None
            }
        }
        "builtin.suid-bit" => {
            if first == "chmod"
                && lower_tokens
                    .iter()
                    .any(|token| token.contains("+s") || is_suid_numeric_mode(token))
            {
                Some(vec!["chmod changes SUID/SGID bit".to_string()])
            } else {
                None
            }
        }
        "builtin.credential-read" => {
            if matches!(input.action, SafetyAction::Read)
                && paths.iter().any(|path| is_credential_or_key_path(path))
            {
                Some(vec!["read targets credential or key path".to_string()])
            } else {
                None
            }
        }
        "builtin.key-exfiltration" => {
            if command_uses_network(&first)
                && paths.iter().any(|path| is_credential_or_key_path(path))
            {
                Some(vec![
                    "network command references credential or key path".to_string()
                ])
            } else {
                None
            }
        }
        "builtin.sensitive-path-write" => {
            if is_state_changing_action(input.action)
                && paths.iter().any(|path| is_sensitive_write_path(path))
            {
                Some(vec![
                    "state-changing action targets sensitive path".to_string()
                ])
            } else {
                None
            }
        }
        "builtin.rm-recursive-glob" => {
            if first == "rm"
                && has_flag(&lower_tokens, "r")
                && lower_tokens
                    .iter()
                    .any(|token| token_has_shell_expansion(token))
            {
                Some(vec!["recursive rm uses glob or brace expansion".to_string()])
            } else {
                None
            }
        }
        "builtin.path-traversal" => paths
            .iter()
            .any(|path| path.contains("../") || path.starts_with(".."))
            .then(|| vec!["path contains parent traversal".to_string()]),
        "builtin.option-injection-target" => {
            if is_state_changing_action(input.action)
                && input
                    .targets
                    .iter()
                    .any(|target| target.value.trim_start().starts_with('-'))
            {
                Some(vec!["structured target begins with '-'".to_string()])
            } else {
                None
            }
        }
        "builtin.shell-expansion" => {
            if is_state_changing_action(input.action)
                && lower_tokens
                    .iter()
                    .any(|token| token_has_shell_expansion(token))
            {
                Some(vec![
                    "state-changing command uses shell expansion".to_string()
                ])
            } else {
                None
            }
        }
        "builtin.redirection-sensitive-path" => redirection_paths(&tokens)
            .iter()
            .any(|path| is_sensitive_write_path(path))
            .then(|| vec!["redirection writes to sensitive path".to_string()]),
        "builtin.encoded-pipe-shell" => {
            if raw_lower.contains("base64")
                && (raw_lower.contains("| sh")
                    || raw_lower.contains("|sh")
                    || raw_lower.contains("| bash")
                    || raw_lower.contains("|bash")
                    || raw_lower.contains("| python")
                    || raw_lower.contains("|python"))
            {
                Some(vec![
                    "base64 decode pipeline reaches interpreter".to_string()
                ])
            } else {
                None
            }
        }
        "builtin.remote-script-pipe" => remote_script_pipe(&raw_lower)
            .then(|| vec!["remote download pipeline reaches interpreter".to_string()]),
        "builtin.nested-exec" => is_nested_execution(&lower_tokens)
            .then(|| vec!["wrapper executes nested command text".to_string()]),
        "builtin.eval-exec" => (first == "eval" || raw_lower.contains(" invoke-expression"))
            .then(|| vec!["dynamic eval execution detected".to_string()]),
        _ => None,
    }
}

fn command_tokens(command: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in command.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' || ch == '`' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        tokens.push_if_separator(&mut current, ch);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

trait PushShellToken {
    fn push_if_separator(&mut self, current: &mut String, ch: char);
}

impl PushShellToken for Vec<String> {
    fn push_if_separator(&mut self, current: &mut String, ch: char) {
        if matches!(ch, ';' | '|' | '&') {
            if !current.is_empty() {
                self.push(std::mem::take(current));
            }
            return;
        }
        if ch == '>' || ch == '<' {
            if !current.is_empty() {
                self.push(std::mem::take(current));
            }
            current.push(ch);
            return;
        }
        current.push(ch);
    }
}

pub(crate) fn first_command_basename_after_wrappers(tokens: &[String]) -> String {
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].to_ascii_lowercase();
        if token.contains('=') && token.find('=').is_some_and(|pos| pos > 0) {
            index += 1;
            continue;
        }
        if token == "sudo" {
            index += 1;
            index = skip_sudo_args(tokens, index);
            continue;
        }
        if matches!(token.as_str(), "env" | "command" | "nohup" | "nice") {
            index += 1;
            index = skip_transparent_wrapper_args(&token, tokens, index);
            continue;
        }
        return command_basename(&token);
    }
    String::new()
}

fn first_command(tokens: &[String]) -> String {
    first_command_basename_after_wrappers(tokens)
}

fn skip_sudo_args(tokens: &[String], mut index: usize) -> usize {
    while index < tokens.len() {
        let token = tokens[index].to_ascii_lowercase();
        if token == "--" {
            return index + 1;
        }
        if option_consumes_inline(
            &token,
            &[
                "--user=",
                "--group=",
                "--host=",
                "--prompt=",
                "--chdir=",
                "--chroot=",
                "--command-timeout=",
            ],
        ) {
            index += 1;
            continue;
        }
        if matches!(
            token.as_str(),
            "--user"
                | "--group"
                | "--host"
                | "--prompt"
                | "--chdir"
                | "--chroot"
                | "--command-timeout"
        ) {
            index = index.saturating_add(2);
            continue;
        }
        if short_option_consumes_inline(&token, &["-u", "-g", "-h", "-p", "-c", "-r", "-t"]) {
            index += 1;
            continue;
        }
        if matches!(
            token.as_str(),
            "-u" | "-g" | "-h" | "-p" | "-c" | "-r" | "-t"
        ) {
            index = index.saturating_add(2);
            continue;
        }
        if token.starts_with('-') {
            index += 1;
            continue;
        }
        break;
    }
    index
}

fn skip_transparent_wrapper_args(wrapper: &str, tokens: &[String], mut index: usize) -> usize {
    match wrapper {
        "env" => {
            while index < tokens.len() {
                let token = tokens[index].to_ascii_lowercase();
                if token == "--" {
                    index += 1;
                    break;
                }
                if token.contains('=') && token.find('=').is_some_and(|pos| pos > 0) {
                    index += 1;
                    continue;
                }
                if option_consumes_inline(&token, &["--unset=", "--chdir=", "--split-string="]) {
                    index += 1;
                    continue;
                }
                if matches!(token.as_str(), "--unset" | "--chdir" | "--split-string") {
                    index = index.saturating_add(2);
                    continue;
                }
                if short_option_consumes_inline(&token, &["-u", "-c", "-s"]) {
                    index += 1;
                    continue;
                }
                if matches!(token.as_str(), "-u" | "-c" | "-s") {
                    index = index.saturating_add(2);
                    continue;
                }
                if token.starts_with('-') {
                    index += 1;
                    continue;
                }
                break;
            }
        }
        "command" => {
            while index < tokens.len() {
                let token = tokens[index].to_ascii_lowercase();
                if token == "--" {
                    index += 1;
                    break;
                }
                if !token.starts_with('-') {
                    break;
                }
                index += 1;
            }
        }
        "nice" => {
            while index < tokens.len() {
                let token = tokens[index].to_ascii_lowercase();
                if token == "--" {
                    index += 1;
                    break;
                }
                if token == "-n" || token == "--adjustment" {
                    index = index.saturating_add(2);
                    continue;
                }
                if token.starts_with("-n") || token.starts_with("--adjustment=") {
                    index += 1;
                    continue;
                }
                if token.starts_with('-') {
                    index += 1;
                    continue;
                }
                break;
            }
        }
        "nohup" => {}
        _ => {}
    }
    index
}

fn option_consumes_inline(token: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| token.starts_with(prefix))
}

fn short_option_consumes_inline(token: &str, prefixes: &[&str]) -> bool {
    prefixes
        .iter()
        .any(|prefix| token.starts_with(prefix) && token.len() > prefix.len())
}

fn command_basename(token: &str) -> String {
    token.rsplit('/').next().unwrap_or(token).to_string()
}

fn is_suid_numeric_mode(token: &str) -> bool {
    token.len() == 4
        && matches!(token.as_bytes().first(), Some(b'2' | b'4' | b'6'))
        && token.chars().all(|ch| matches!(ch, '0'..='7'))
}

fn has_flag(tokens: &[String], flag: &str) -> bool {
    let short = format!("-{flag}");
    let long = match flag {
        "r" => "--recursive",
        "f" => "--force",
        _ => "",
    };
    tokens.iter().any(|token| {
        token == &short
            || token == long
            || (token.starts_with('-') && !token.starts_with("--") && token.contains(flag))
    })
}

fn candidate_paths(input: &SafetyRuleInput<'_>) -> Vec<String> {
    let mut paths = Vec::new();
    for target in input.targets {
        if matches!(
            target.kind,
            IntentTargetKind::Path | IntentTargetKind::Device | IntentTargetKind::Unknown
        ) {
            push_candidate_path(&mut paths, &target.value);
        }
    }
    let tokens = command_tokens(input.raw_text);
    for token in &tokens {
        if let Some(path) = token_path(token) {
            push_candidate_path(&mut paths, path);
        }
    }
    for path in redirection_paths(&tokens) {
        push_candidate_path(&mut paths, &path);
    }
    paths.sort();
    paths.dedup();
    paths
}

fn push_candidate_path(paths: &mut Vec<String>, path: &str) {
    let lexical = normalize_path(path);
    if !lexical.is_empty() {
        paths.push(lexical.clone());
    }
    if let Ok(canonical) = fs::canonicalize(&lexical) {
        paths.push(normalize_path(&canonical.to_string_lossy()));
    }
}

fn token_path(token: &str) -> Option<&str> {
    let trimmed = token.trim_matches(|ch| matches!(ch, '"' | '\''));
    if trimmed.starts_with('/')
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with("~/")
        || trimmed.starts_with("/dev/")
    {
        Some(trimmed)
    } else if let Some(index) = trimmed.find("@/") {
        Some(&trimmed[index + 1..])
    } else if let Some(index) = trimmed.find("/etc/") {
        Some(&trimmed[index..])
    } else if let Some(index) = trimmed.find("/root/") {
        Some(&trimmed[index..])
    } else {
        None
    }
}

fn redirection_paths(tokens: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if matches!(token, ">" | ">>" | "1>" | "2>" | "&>") {
            if let Some(next) = tokens.get(index + 1) {
                paths.push(normalize_path(next));
            }
        } else if let Some(path) = token
            .strip_prefix(">")
            .or_else(|| token.strip_prefix(">>"))
            .or_else(|| token.strip_prefix("1>"))
            .or_else(|| token.strip_prefix("2>"))
            .or_else(|| token.strip_prefix("&>"))
        {
            if !path.is_empty() {
                paths.push(normalize_path(path));
            }
        }
        index += 1;
    }
    paths
}

fn normalize_path(value: &str) -> String {
    let value = value.trim_matches(|ch| matches!(ch, '"' | '\'' | '<' | '>'));
    let absolute = value.starts_with('/');
    let mut parts = Vec::new();
    for part in value.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if let Some(last) = parts.last() {
                if *last != ".." {
                    parts.pop();
                    continue;
                }
            }
            if !absolute {
                parts.push(part);
            }
            continue;
        }
        parts.push(part);
    }
    if absolute {
        if parts.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", parts.join("/"))
        }
    } else {
        parts.join("/")
    }
}

fn is_sensitive_write_path(path: &str) -> bool {
    let normalized = normalize_path(path);
    SENSITIVE_WRITE_PATHS
        .iter()
        .any(|prefix| path_has_prefix(&normalized, prefix))
}

fn is_credential_or_key_path(path: &str) -> bool {
    let normalized = normalize_path(path);
    SENSITIVE_CREDENTIAL_PATHS
        .iter()
        .any(|prefix| path_has_prefix(&normalized, prefix))
        && (normalized.contains("shadow")
            || normalized.contains("sudoers")
            || normalized.contains(".ssh")
            || normalized.ends_with(".pem")
            || normalized.ends_with(".key")
            || normalized.ends_with("id_rsa")
            || normalized.ends_with("id_ed25519"))
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    let path = normalize_path(path);
    let prefix = normalize_path(prefix);
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn is_state_changing_action(action: SafetyAction) -> bool {
    matches!(
        action,
        SafetyAction::Write
            | SafetyAction::Delete
            | SafetyAction::PackageInstall
            | SafetyAction::PackageUpdate
            | SafetyAction::PackageRemove
            | SafetyAction::ServiceStart
            | SafetyAction::ServiceStop
            | SafetyAction::ServiceRestart
            | SafetyAction::UserCreate
            | SafetyAction::UserDelete
            | SafetyAction::UserModify
            | SafetyAction::LogRuleChange
            | SafetyAction::FirewallChange
            | SafetyAction::CronChange
            | SafetyAction::Restore
    )
}

fn command_uses_network(first: &str) -> bool {
    matches!(
        first,
        "curl" | "wget" | "scp" | "rsync" | "nc" | "ncat" | "ftp" | "sftp"
    )
}

fn is_shell_interpreter(command: &str) -> bool {
    matches!(command, "sh" | "bash" | "dash" | "zsh" | "ksh")
}

fn is_nested_execution(tokens: &[String]) -> bool {
    let first = first_command(tokens);
    if is_shell_interpreter(&first)
        && tokens
            .iter()
            .any(|token| token == "-c" || token.starts_with("-c"))
    {
        return true;
    }
    if first == "find"
        && tokens
            .iter()
            .any(|token| matches!(token.as_str(), "-exec" | "-execdir"))
    {
        return true;
    }
    first == "xargs"
}

fn nested_exec_contains_l4_semantics(input: &SafetyRuleInput<'_>) -> bool {
    let raw_lower = input.raw_text.to_ascii_lowercase();
    if raw_lower.contains(":(){") || encoded_pipe_shell(&raw_lower) {
        return true;
    }
    let tokens = command_tokens(&raw_lower);
    nested_payloads(&tokens)
        .iter()
        .any(|payload| payload_has_l4_semantics(payload, &raw_lower))
}

fn nested_payloads(tokens: &[String]) -> Vec<Vec<String>> {
    let mut payloads = Vec::new();
    let first = first_command(tokens);
    if is_shell_interpreter(&first) {
        let mut index = 0;
        while index < tokens.len() {
            let token = &tokens[index];
            if token == "-c" {
                if let Some(command) = tokens.get(index + 1) {
                    payloads.push(command_tokens(command));
                }
            } else if let Some(command) = token.strip_prefix("-c") {
                if !command.is_empty() {
                    payloads.push(command_tokens(command));
                }
            }
            index += 1;
        }
    } else if first == "find" {
        let mut index = 0;
        while index < tokens.len() {
            if matches!(tokens[index].as_str(), "-exec" | "-execdir") {
                let mut payload = Vec::new();
                index += 1;
                while index < tokens.len()
                    && !matches!(tokens[index].as_str(), ";" | "\\;" | "+" | "{}")
                {
                    payload.push(tokens[index].clone());
                    index += 1;
                }
                if !payload.is_empty() {
                    payloads.push(payload);
                }
            } else {
                index += 1;
            }
        }
    } else if first == "xargs" {
        let mut index = 1;
        while index < tokens.len() {
            let token = &tokens[index];
            if token == "--" {
                index += 1;
                break;
            }
            if token == "-I" || token == "-n" || token == "-P" || token == "-s" {
                index = index.saturating_add(2);
                continue;
            }
            if token.starts_with('-') {
                index += 1;
                continue;
            }
            break;
        }
        if index < tokens.len() {
            payloads.push(tokens[index..].to_vec());
        }
    }
    payloads
}

fn payload_has_l4_semantics(tokens: &[String], raw_lower: &str) -> bool {
    let first = first_command(tokens);
    let paths = paths_from_tokens(tokens);
    if first == "rm"
        && has_flag(tokens, "r")
        && has_flag(tokens, "f")
        && paths
            .iter()
            .any(|path| path == "/" || is_sensitive_write_path(path))
    {
        return true;
    }
    if first.starts_with("mkfs") || first == "wipefs" {
        return true;
    }
    if first == "dd" && tokens.iter().any(|token| token.starts_with("of=/dev/")) {
        return true;
    }
    if command_uses_network(&first) && paths.iter().any(|path| is_credential_or_key_path(path)) {
        return true;
    }
    raw_lower.contains("rm -rf /") || raw_lower.contains("rm -fr /")
}

fn paths_from_tokens(tokens: &[String]) -> Vec<String> {
    let mut paths = Vec::new();
    for token in tokens {
        if let Some(path) = token_path(token) {
            push_candidate_path(&mut paths, path);
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn remote_script_pipe(raw_lower: &str) -> bool {
    let segments = pipeline_segments(raw_lower);
    segments.windows(2).any(|window| {
        let producer = first_command(&window[0]);
        let consumer = first_command(&window[1]);
        matches!(producer.as_str(), "curl" | "wget")
            && matches!(
                consumer.as_str(),
                "sh" | "bash" | "dash" | "zsh" | "ksh" | "python" | "python3"
            )
    })
}

fn encoded_pipe_shell(raw_lower: &str) -> bool {
    raw_lower.contains("base64")
        && (raw_lower.contains("| sh")
            || raw_lower.contains("|sh")
            || raw_lower.contains("| bash")
            || raw_lower.contains("|bash")
            || raw_lower.contains("| python")
            || raw_lower.contains("|python"))
}

fn pipeline_segments(command: &str) -> Vec<Vec<String>> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in command.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' || ch == '`' {
            current.push(ch);
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            current.push(ch);
            if ch == active {
                quote = None;
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            current.push(ch);
            quote = Some(ch);
            continue;
        }
        if ch == '|' {
            let tokens = command_tokens(current.trim());
            if !tokens.is_empty() {
                segments.push(tokens);
            }
            current.clear();
            continue;
        }
        current.push(ch);
    }
    let tokens = command_tokens(current.trim());
    if !tokens.is_empty() {
        segments.push(tokens);
    }
    segments
}

fn token_has_shell_expansion(token: &str) -> bool {
    token.contains('*')
        || token.contains('?')
        || token.contains('[')
        || token.contains('{') && token.contains('}')
}

fn bounded_glob_match(pattern: &str, value: &str) -> bool {
    if pattern.len() > MAX_RULE_PATTERN_BYTES || value.len() > MAX_RULE_FILE_BYTES as usize {
        return false;
    }
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut pattern_index = 0;
    let mut value_index = 0;
    let mut star_index = None;
    let mut star_value_index = 0;

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn reject_symlink_or_special_file(path: &Path) -> Result<fs::Metadata, SafetyRuleError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| SafetyRuleError::io(format!("failed to inspect rule file: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(SafetyRuleError::invalid_rules(
            "rule file must not be a symlink",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(SafetyRuleError::invalid_rules(
                "rule file must not be a reparse point",
            ));
        }
    }
    if !metadata.file_type().is_file() {
        return Err(SafetyRuleError::invalid_rules(
            "rule file must be a regular file",
        ));
    }
    Ok(metadata)
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn path_summary(path: &Path) -> String {
    redact_summary(&path.to_string_lossy())
}

fn redact_summary(value: &str) -> String {
    let mut redacted = value.to_string();
    for marker in [
        "authorization:",
        "bearer ",
        "token=",
        "api_key=",
        "apikey=",
        "secret=",
        "password=",
    ] {
        redacted = redact_after_ascii_marker(&redacted, marker);
    }
    bounded_preview(&redacted, MAX_SOURCE_SUMMARY_BYTES)
}

fn redact_after_ascii_marker(value: &str, marker: &str) -> String {
    let bytes = value.as_bytes();
    let marker_bytes = marker.as_bytes();
    if marker_bytes.is_empty() || bytes.len() < marker_bytes.len() {
        return value.to_string();
    }
    let mut output = String::new();
    let mut cursor = 0;
    while cursor <= bytes.len().saturating_sub(marker_bytes.len()) {
        if ascii_eq_ignore_case(&bytes[cursor..cursor + marker_bytes.len()], marker_bytes) {
            let marker_end = cursor + marker_bytes.len();
            let mut secret_start = marker_end;
            while secret_start < bytes.len() && bytes[secret_start].is_ascii_whitespace() {
                secret_start += 1;
            }
            let mut end = secret_start;
            while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            output.push_str(&value[cursor..marker_end]);
            output.push_str("[REDACTED]");
            cursor = end;
            continue;
        }
        let Some(ch) = value[cursor..].chars().next() else {
            break;
        };
        output.push(ch);
        cursor += ch.len_utf8();
    }
    output.push_str(&value[cursor..]);
    output
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn bounded_preview(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[truncated]", &value[..end])
}

/// Structured rule store error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyRuleError {
    pub code: SafetyRuleErrorCode,
    pub message: String,
}

impl SafetyRuleError {
    fn invalid_rules(message: impl Into<String>) -> Self {
        Self {
            code: SafetyRuleErrorCode::InvalidRules,
            message: message.into(),
        }
    }

    fn limit_exceeded(message: impl Into<String>) -> Self {
        Self {
            code: SafetyRuleErrorCode::LimitExceeded,
            message: message.into(),
        }
    }

    fn io(message: impl Into<String>) -> Self {
        Self {
            code: SafetyRuleErrorCode::Io,
            message: message.into(),
        }
    }
}

impl fmt::Display for SafetyRuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for SafetyRuleError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyRuleErrorCode {
    InvalidRules,
    LimitExceeded,
    Io,
}

impl SafetyRuleErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRules => "invalid_rules",
            Self::LimitExceeded => "limit_exceeded",
            Self::Io => "io",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(
        action: SafetyAction,
        raw_text: &str,
        targets: Vec<IntentTarget>,
    ) -> SafetyRuleInput<'_> {
        SafetyRuleInput {
            action,
            impact_scope: ImpactScope::Unknown,
            raw_text,
            targets: Box::leak(targets.into_boxed_slice()),
        }
    }

    fn target(kind: IntentTargetKind, value: &str) -> IntentTarget {
        IntentTarget {
            kind,
            value: value.to_string(),
        }
    }

    #[test]
    fn safety_rules_builtin_snapshot_self_checks() {
        let snapshot = builtin_safety_rule_snapshot();
        assert_eq!(snapshot.generation, 0);
        assert_eq!(snapshot.builtin_rule_count, BUILTIN_RULE_IDS.len());
        for id in BUILTIN_RULE_IDS {
            assert!(snapshot.rules.iter().any(|rule| rule.id == *id));
        }
    }

    #[test]
    fn safety_rules_sensitive_path_normalization_and_traversal() {
        let snapshot = builtin_safety_rule_snapshot();
        let matches = snapshot.evaluate(&input(
            SafetyAction::Delete,
            "rm -rf ////etc/../etc/shadow",
            vec![target(IntentTargetKind::Path, "////etc/../etc/shadow")],
        ));
        assert!(matches
            .iter()
            .any(|m| m.rule_id == "builtin.rm-root-system"));
        assert!(matches
            .iter()
            .any(|m| m.rule_id == "builtin.sensitive-path-write"));

        let traversal = snapshot.evaluate(&input(
            SafetyAction::Read,
            "cat ../../etc/passwd",
            vec![target(IntentTargetKind::Path, "../../etc/passwd")],
        ));
        assert!(traversal
            .iter()
            .any(|m| m.rule_id == "builtin.path-traversal" && m.policy == RiskPolicy::Confirm));
    }

    #[cfg(unix)]
    #[test]
    fn safety_rules_existing_symlink_target_is_evaluated_after_canonicalize() {
        use std::os::unix::fs::symlink;

        if !Path::new("/etc/passwd").exists() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let link = dir.path().join("link-to-etc");
        symlink("/etc", &link).expect("symlink");
        let target_path = link.join("passwd");

        let snapshot = builtin_safety_rule_snapshot();
        let matches = snapshot.evaluate(&input(
            SafetyAction::Write,
            "write symlink",
            vec![target(
                IntentTargetKind::Path,
                &target_path.to_string_lossy(),
            )],
        ));
        assert!(matches
            .iter()
            .any(|m| m.rule_id == "builtin.sensitive-path-write"));
    }

    #[test]
    fn safety_rules_hot_update_is_atomic_and_generation_checked() {
        let store = SafetyRuleStore::new();
        let before = store.snapshot();
        let updated = store
            .reload_from_str(
                "rules token=SECRET",
                r#"{
                    "schemaVersion": 1,
                    "generation": 1,
                    "rules": [{
                        "id": "custom.block-nc",
                        "level": "l4",
                        "policy": "deny",
                        "matchKind": "token",
                        "pattern": "nc",
                        "evidence": "netcat is blocked"
                    }]
                }"#,
            )
            .expect("reload");
        assert_eq!(updated.generation, 1);
        assert!(!updated.source_summary.contains("SECRET"));
        assert!(updated
            .rules
            .iter()
            .any(|rule| rule.id == "custom.block-nc"));
        assert!(store
            .reload_from_str("older", r#"{"schemaVersion":1,"generation":1,"rules":[]}"#)
            .is_err());
        assert_eq!(store.snapshot().generation, 1);
        assert_ne!(before.content_hash, updated.content_hash);
    }

    #[test]
    fn safety_rules_reject_duplicate_unknown_and_builtin_override() {
        let store = SafetyRuleStore::new();
        assert!(store
            .reload_from_str(
                "dup",
                r#"{"schemaVersion":1,"generation":1,"rules":[
                    {"id":"custom.same","level":"l3","policy":"confirm","matchKind":"literal","pattern":"a","evidence":"a"},
                    {"id":"custom.same","level":"l3","policy":"confirm","matchKind":"literal","pattern":"b","evidence":"b"}
                ]}"#
            )
            .is_err());
        assert!(store
            .reload_from_str(
                "unknown",
                r#"{"schemaVersion":1,"generation":1,"extra":true,"rules":[]}"#
            )
            .is_err());
        assert!(store
            .reload_from_str(
                "override",
                r#"{"schemaVersion":1,"generation":1,"rules":[
                    {"id":"builtin.mkfs","level":"l1","policy":"allow","matchKind":"literal","pattern":"mkfs","evidence":"bad"}
                ]}"#
            )
            .is_err());
        assert!(store
            .reload_from_str(
                "bad-policy",
                r#"{"schemaVersion":1,"generation":1,"rules":[
                    {"id":"custom.bad-policy","level":"l4","policy":"allow","matchKind":"literal","pattern":"x","evidence":"x"}
                ]}"#
            )
            .is_err());
        assert!(store
            .reload_from_str(
                "bad-id",
                r#"{"schemaVersion":1,"generation":1,"rules":[
                    {"id":"Token=SECRET","level":"l3","policy":"confirm","matchKind":"literal","pattern":"x","evidence":"x"}
                ]}"#
            )
            .is_err());
        assert!(store
            .reload_from_str(
                "bad-kind",
                r#"{"schemaVersion":1,"generation":1,"rules":[
                    {"id":"custom.bad-kind","level":"l3","policy":"confirm","matchKind":"builtin","pattern":"x","evidence":"x"}
                ]}"#
            )
            .is_err());
        assert!(store
            .reload_from_str(
                "bad-prefix",
                r#"{"schemaVersion":1,"generation":1,"rules":[
                    {"id":"custom.bad-prefix","level":"l3","policy":"confirm","matchKind":"path_prefix","pattern":"/etc/../shadow","evidence":"x"}
                ]}"#
            )
            .is_err());
    }

    #[test]
    fn safety_rules_bounded_glob_match_handles_malicious_pattern_without_recursion() {
        let pattern = format!("{}z", "*".repeat(511));
        let value = "a".repeat(512);
        assert!(!bounded_glob_match(&pattern, &value));
        assert!(bounded_glob_match(&"*a?c", "xxabc"));
    }

    #[test]
    fn safety_rules_suid_numeric_modes_are_precise() {
        let snapshot = builtin_safety_rule_snapshot();
        let safe = snapshot.evaluate(&input(SafetyAction::Write, "chmod 277 ./file", Vec::new()));
        assert!(!safe.iter().any(|m| m.rule_id == "builtin.suid-bit"));

        let deny = snapshot.evaluate(&input(SafetyAction::Write, "chmod 4755 ./file", Vec::new()));
        assert!(deny.iter().any(|m| m.rule_id == "builtin.suid-bit"));

        let both = snapshot.evaluate(&input(SafetyAction::Write, "chmod 6755 ./file", Vec::new()));
        assert!(both.iter().any(|m| m.rule_id == "builtin.suid-bit"));

        let ordinary =
            snapshot.evaluate(&input(SafetyAction::Write, "chmod 0755 ./file", Vec::new()));
        assert!(!ordinary.iter().any(|m| m.rule_id == "builtin.suid-bit"));
    }

    #[test]
    fn safety_rules_concurrent_readers_see_complete_generations() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::thread;

        let store = Arc::new(SafetyRuleStore::new());
        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let store = store.clone();
            let stop = stop.clone();
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let snapshot = store.snapshot();
                    assert!(
                        snapshot.generation == 0 || snapshot.generation == 1,
                        "partial generation {}",
                        snapshot.generation
                    );
                    assert!(snapshot.rules.len() >= snapshot.builtin_rule_count);
                }
            }));
        }
        store
            .reload_from_str(
                "concurrent",
                r#"{"schemaVersion":1,"generation":1,"rules":[]}"#,
            )
            .expect("reload");
        stop.store(true, Ordering::SeqCst);
        for handle in handles {
            handle.join().expect("reader");
        }
    }

    #[cfg(unix)]
    #[test]
    fn safety_rules_reject_symlink_rule_file() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("rules.json");
        let link = dir.path().join("link.json");
        fs::write(&real, r#"{"schemaVersion":1,"generation":1,"rules":[]}"#).expect("write");
        symlink(&real, &link).expect("symlink");
        let store = SafetyRuleStore::new();
        let error = store
            .reload_from_trusted_file(&link)
            .expect_err("symlink should fail");
        assert_eq!(error.code, SafetyRuleErrorCode::InvalidRules);
    }
}
