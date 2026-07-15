use std::env;
use std::io;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::process::Command as TokioCommand;
use tokio::runtime::Builder;
use tokio::time::timeout;

use crate::lane_events::{LaneEvent, ShipMergeMethod, ShipProvenance};
use crate::sandbox::{
    build_linux_sandbox_command, default_overlay_root, resolve_sandbox_status_for_request,
    FilesystemIsolationMode, SandboxConfig, SandboxStatus,
};
use crate::ConfigLoader;

/// Input schema for the built-in bash execution tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BashCommandInput {
    pub command: String,
    pub timeout: Option<u64>,
    pub description: Option<String>,
    #[serde(rename = "run_in_background")]
    pub run_in_background: Option<bool>,
    #[serde(rename = "dangerouslyDisableSandbox")]
    pub dangerously_disable_sandbox: Option<bool>,
    #[serde(rename = "namespaceRestrictions")]
    pub namespace_restrictions: Option<bool>,
    #[serde(rename = "isolateNetwork")]
    pub isolate_network: Option<bool>,
    #[serde(rename = "filesystemMode")]
    pub filesystem_mode: Option<FilesystemIsolationMode>,
    #[serde(rename = "allowedMounts")]
    pub allowed_mounts: Option<Vec<String>>,
}

/// Output returned from a bash tool invocation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BashCommandOutput {
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "rawOutputPath")]
    pub raw_output_path: Option<String>,
    pub interrupted: bool,
    #[serde(rename = "isImage")]
    pub is_image: Option<bool>,
    #[serde(rename = "backgroundTaskId")]
    pub background_task_id: Option<String>,
    #[serde(rename = "backgroundedByUser")]
    pub backgrounded_by_user: Option<bool>,
    #[serde(rename = "assistantAutoBackgrounded")]
    pub assistant_auto_backgrounded: Option<bool>,
    #[serde(rename = "dangerouslyDisableSandbox")]
    pub dangerously_disable_sandbox: Option<bool>,
    #[serde(rename = "returnCodeInterpretation")]
    pub return_code_interpretation: Option<String>,
    #[serde(rename = "noOutputExpected")]
    pub no_output_expected: Option<bool>,
    #[serde(rename = "structuredContent")]
    pub structured_content: Option<Vec<serde_json::Value>>,
    #[serde(rename = "persistedOutputPath")]
    pub persisted_output_path: Option<String>,
    #[serde(rename = "persistedOutputSize")]
    pub persisted_output_size: Option<u64>,
    #[serde(rename = "sandboxStatus")]
    pub sandbox_status: Option<SandboxStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxAuditEventKind {
    Timeout,
    OutputLimitExceeded,
    ResourceLimitExceeded,
    SandboxFallback,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxAuditEvent {
    pub event: SandboxAuditEventKind,
    pub message: String,
    pub data: serde_json::Value,
}

/// Executes a shell command with the requested sandbox settings.
pub fn execute_bash(input: BashCommandInput) -> io::Result<BashCommandOutput> {
    let cwd = env::current_dir()?;
    let sandbox_status = sandbox_status_for_input(&input, &cwd).with_invocation(&cwd);

    if input.run_in_background.unwrap_or(false) {
        let mut child = prepare_command(&input.command, &cwd, &sandbox_status, true);
        let child = child
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        return Ok(BashCommandOutput {
            stdout: String::new(),
            stderr: String::new(),
            raw_output_path: None,
            interrupted: false,
            is_image: None,
            background_task_id: Some(child.id().to_string()),
            backgrounded_by_user: Some(false),
            assistant_auto_backgrounded: Some(false),
            dangerously_disable_sandbox: input.dangerously_disable_sandbox,
            return_code_interpretation: None,
            no_output_expected: Some(true),
            structured_content: None,
            persisted_output_path: None,
            persisted_output_size: None,
            sandbox_status: Some(sandbox_status),
        });
    }

    let runtime = Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(execute_bash_async(input, sandbox_status, cwd))
}

/// Detect git push to main and emit ship provenance event
fn detect_and_emit_ship_prepared(command: &str) {
    let trimmed = command.trim();
    // Simple detection: git push with main/master
    if trimmed.contains("git push") && (trimmed.contains("main") || trimmed.contains("master")) {
        // Emit ship.prepared event
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let provenance = ShipProvenance {
            source_branch: get_current_branch().unwrap_or_else(|| "unknown".to_string()),
            base_commit: get_head_commit().unwrap_or_default(),
            commit_count: 0, // Would need to calculate from range
            commit_range: "unknown..HEAD".to_string(),
            merge_method: ShipMergeMethod::DirectPush,
            actor: get_git_actor().unwrap_or_else(|| "unknown".to_string()),
            pr_number: None,
        };
        let _event = LaneEvent::ship_prepared(format!("{now}"), &provenance);
        // Log to stderr as interim routing before event stream integration
        eprintln!(
            "[ship.prepared] branch={} -> main, commits={}, actor={}",
            provenance.source_branch, provenance.commit_count, provenance.actor
        );
    }
}

fn get_current_branch() -> Option<String> {
    let output = Command::new("git")
        .args(["branch", "--show-current"])
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

fn get_head_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

fn get_git_actor() -> Option<String> {
    let name = Command::new("git")
        .args(["config", "user.name"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())?;
    Some(name)
}

async fn execute_bash_async(
    input: BashCommandInput,
    sandbox_status: SandboxStatus,
    cwd: std::path::PathBuf,
) -> io::Result<BashCommandOutput> {
    // Detect and emit ship provenance for git push operations
    detect_and_emit_ship_prepared(&input.command);

    let mut command = prepare_tokio_command(&input.command, &cwd, &sandbox_status, true);
    command.kill_on_drop(true);

    let timeout_ms = input.timeout.unwrap_or(sandbox_status.default_timeout_ms);
    let output_result =
        if let Ok(result) = timeout(Duration::from_millis(timeout_ms), command.output()).await {
            (result?, false)
        } else {
            cleanup_sandbox_dirs(&cwd, &sandbox_status);
            return Ok(timeout_output(&input, timeout_ms, sandbox_status));
        };

    let (output, interrupted) = output_result;
    let (stdout, stdout_truncated) = truncate_output_with_limit(
        &String::from_utf8_lossy(&output.stdout),
        sandbox_status.output_limit_bytes,
    );
    let (stderr, stderr_truncated) = truncate_output_with_limit(
        &String::from_utf8_lossy(&output.stderr),
        sandbox_status.output_limit_bytes,
    );
    let structured_content = audit_events_for_completed_command(
        &input.command,
        &sandbox_status,
        stdout_truncated,
        stderr_truncated,
        &output.status,
    );
    let no_output_expected = Some(stdout.trim().is_empty() && stderr.trim().is_empty());
    let return_code_interpretation = output.status.code().and_then(|code| {
        if code == 0 {
            None
        } else {
            Some(format!("exit_code:{code}"))
        }
    });

    cleanup_sandbox_dirs(&cwd, &sandbox_status);
    Ok(BashCommandOutput {
        stdout,
        stderr,
        raw_output_path: None,
        interrupted,
        is_image: None,
        background_task_id: None,
        backgrounded_by_user: None,
        assistant_auto_backgrounded: None,
        dangerously_disable_sandbox: input.dangerously_disable_sandbox,
        return_code_interpretation,
        no_output_expected,
        structured_content,
        persisted_output_path: None,
        persisted_output_size: None,
        sandbox_status: Some(sandbox_status),
    })
}

fn timeout_output(
    input: &BashCommandInput,
    timeout_ms: u64,
    sandbox_status: SandboxStatus,
) -> BashCommandOutput {
    let is_test = is_test_command(&input.command);
    let return_code_interpretation = if is_test { "test.hung" } else { "timeout" };
    BashCommandOutput {
        stdout: String::new(),
        stderr: format!("Command exceeded timeout of {timeout_ms} ms"),
        raw_output_path: None,
        interrupted: true,
        is_image: None,
        background_task_id: None,
        backgrounded_by_user: None,
        assistant_auto_backgrounded: None,
        dangerously_disable_sandbox: input.dangerously_disable_sandbox,
        return_code_interpretation: Some(String::from(return_code_interpretation)),
        no_output_expected: Some(true),
        structured_content: Some(vec![
            test_timeout_provenance(&input.command, timeout_ms, is_test),
            sandbox_audit_value(SandboxAuditEvent {
                event: SandboxAuditEventKind::Timeout,
                message: format!("command exceeded timeout of {timeout_ms} ms and was terminated"),
                data: json!({
                    "command": input.command,
                    "timeoutMs": timeout_ms,
                    "provenance": "bash.timeout",
                    "invocationId": sandbox_status.invocation.as_ref().map(|invocation| invocation.id.as_str()),
                }),
            }),
        ]),
        persisted_output_path: None,
        persisted_output_size: None,
        sandbox_status: Some(sandbox_status),
    }
}

fn is_test_command(command: &str) -> bool {
    let normalized = command
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    normalized.contains("cargo test")
        || normalized.contains("cargo nextest")
        || normalized.contains("npm test")
        || normalized.contains("pnpm test")
        || normalized.contains("yarn test")
        || normalized.contains("pytest")
}

fn test_timeout_provenance(
    command: &str,
    timeout_ms: u64,
    classified_as_test_hang: bool,
) -> serde_json::Value {
    json!({
        "event": if classified_as_test_hang { "test.hung" } else { "command.timeout" },
        "failureClass": if classified_as_test_hang { "test_hang" } else { "timeout" },
        "data": {
            "command": command,
            "timeoutMs": timeout_ms,
            "provenance": "bash.timeout",
            "classification": if classified_as_test_hang { "test.hung" } else { "timeout" }
        }
    })
}

fn audit_events_for_completed_command(
    command: &str,
    sandbox_status: &SandboxStatus,
    stdout_truncated: bool,
    stderr_truncated: bool,
    exit_status: &std::process::ExitStatus,
) -> Option<Vec<serde_json::Value>> {
    let mut events = Vec::new();
    if let Some(reason) = sandbox_status.fallback_reason.as_deref() {
        events.push(sandbox_audit_value(SandboxAuditEvent {
            event: SandboxAuditEventKind::SandboxFallback,
            message: reason.to_string(),
            data: json!({
                "command": command,
                "fallbackReason": reason,
                "requested": sandbox_status.requested,
            }),
        }));
    }
    if let Some(reason) = resource_limit_reason(exit_status) {
        events.push(sandbox_audit_value(SandboxAuditEvent {
            event: SandboxAuditEventKind::ResourceLimitExceeded,
            message: format!("command terminated by sandbox resource limit: {reason}"),
            data: json!({
                "command": command,
                "reason": reason,
                "timeoutMs": sandbox_status.default_timeout_ms,
                "memoryLimitBytes": sandbox_status.memory_limit_bytes,
                "outputLimitBytes": sandbox_status.output_limit_bytes,
                "invocationId": sandbox_status.invocation.as_ref().map(|invocation| invocation.id.as_str()),
            }),
        }));
    }
    if stdout_truncated || stderr_truncated {
        events.push(sandbox_audit_value(SandboxAuditEvent {
            event: SandboxAuditEventKind::OutputLimitExceeded,
            message: format!(
                "command output exceeded {} byte limit and was truncated",
                sandbox_status.output_limit_bytes
            ),
            data: json!({
                "command": command,
                "outputLimitBytes": sandbox_status.output_limit_bytes,
                "stdoutTruncated": stdout_truncated,
                "stderrTruncated": stderr_truncated,
            }),
        }));
    }
    (!events.is_empty()).then_some(events)
}

fn resource_limit_reason(status: &std::process::ExitStatus) -> Option<String> {
    if let Some(code) = status.code() {
        if matches!(code, 9 | 137 | 143) {
            return Some(format!("exit_code:{code}"));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            if matches!(signal, 9 | 24 | 25) {
                return Some(format!("signal:{signal}"));
            }
        }
    }
    None
}

fn sandbox_audit_value(event: SandboxAuditEvent) -> serde_json::Value {
    serde_json::to_value(event).expect("sandbox audit event should serialize")
}

fn sandbox_status_for_input(input: &BashCommandInput, cwd: &std::path::Path) -> SandboxStatus {
    let config = ConfigLoader::default_for(cwd).load().map_or_else(
        |_| SandboxConfig::default(),
        |runtime_config| runtime_config.sandbox().clone(),
    );
    let request = config.resolve_request(
        input.dangerously_disable_sandbox.map(|disabled| !disabled),
        input.namespace_restrictions,
        input.isolate_network,
        input.filesystem_mode,
        input.allowed_mounts.clone(),
    );
    resolve_sandbox_status_for_request(&request, cwd)
}

fn prepare_command(
    command: &str,
    cwd: &std::path::Path,
    sandbox_status: &SandboxStatus,
    create_dirs: bool,
) -> Command {
    if create_dirs {
        prepare_sandbox_dirs(cwd, sandbox_status);
    }

    if let Some(launcher) = build_linux_sandbox_command(command, cwd, sandbox_status) {
        let mut prepared = Command::new(launcher.program);
        prepared.args(launcher.args);
        prepared.current_dir(cwd);
        prepared.envs(launcher.env);
        return prepared;
    }

    let mut prepared = shell_command();
    prepared.args(shell_args(command)).current_dir(cwd);
    if sandbox_status.filesystem_active {
        prepared.env("HOME", sandbox_home_dir(cwd, sandbox_status));
        prepared.env("TMPDIR", sandbox_temp_dir(cwd, sandbox_status));
    }
    apply_sandbox_limit_env(&mut prepared, sandbox_status);
    prepared
}

fn prepare_tokio_command(
    command: &str,
    cwd: &std::path::Path,
    sandbox_status: &SandboxStatus,
    create_dirs: bool,
) -> TokioCommand {
    if create_dirs {
        prepare_sandbox_dirs(cwd, sandbox_status);
    }

    if let Some(launcher) = build_linux_sandbox_command(command, cwd, sandbox_status) {
        let mut prepared = TokioCommand::new(launcher.program);
        prepared.args(launcher.args);
        prepared.current_dir(cwd);
        prepared.envs(launcher.env);
        return prepared;
    }

    let mut prepared = tokio_shell_command();
    prepared.args(shell_args(command)).current_dir(cwd);
    if sandbox_status.filesystem_active {
        prepared.env("HOME", sandbox_home_dir(cwd, sandbox_status));
        prepared.env("TMPDIR", sandbox_temp_dir(cwd, sandbox_status));
    }
    apply_tokio_sandbox_limit_env(&mut prepared, sandbox_status);
    prepared
}

fn apply_sandbox_limit_env(command: &mut Command, status: &SandboxStatus) {
    command.env(
        "CLAWD_SANDBOX_TIMEOUT_MS",
        status.default_timeout_ms.to_string(),
    );
    command.env(
        "CLAWD_SANDBOX_MEMORY_LIMIT_BYTES",
        status.memory_limit_bytes.to_string(),
    );
    command.env(
        "CLAWD_SANDBOX_OUTPUT_LIMIT_BYTES",
        status.output_limit_bytes.to_string(),
    );
}

fn apply_tokio_sandbox_limit_env(command: &mut TokioCommand, status: &SandboxStatus) {
    command.env(
        "CLAWD_SANDBOX_TIMEOUT_MS",
        status.default_timeout_ms.to_string(),
    );
    command.env(
        "CLAWD_SANDBOX_MEMORY_LIMIT_BYTES",
        status.memory_limit_bytes.to_string(),
    );
    command.env(
        "CLAWD_SANDBOX_OUTPUT_LIMIT_BYTES",
        status.output_limit_bytes.to_string(),
    );
}

#[cfg(windows)]
fn shell_program() -> &'static str {
    for path in [
        r"C:\msys64\usr\bin\bash.exe",
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\msys64\usr\bin\sh.exe",
        r"C:\Program Files\Git\bin\sh.exe",
    ] {
        if std::path::Path::new(path).exists() {
            return path;
        }
    }
    "sh"
}

#[cfg(not(windows))]
fn shell_program() -> &'static str {
    "sh"
}

fn shell_args(command: &str) -> Vec<&str> {
    if cfg!(windows) {
        vec!["--noprofile", "--norc", "-lc", command]
    } else {
        vec!["-lc", command]
    }
}

fn shell_command() -> Command {
    Command::new(shell_program())
}

fn tokio_shell_command() -> TokioCommand {
    TokioCommand::new(shell_program())
}

fn sandbox_home_dir(cwd: &std::path::Path, sandbox_status: &SandboxStatus) -> std::path::PathBuf {
    sandbox_status.invocation.as_ref().map_or_else(
        || cwd.join(".sandbox-home"),
        |invocation| invocation.home_dir.clone(),
    )
}

fn sandbox_temp_dir(cwd: &std::path::Path, sandbox_status: &SandboxStatus) -> std::path::PathBuf {
    sandbox_status.invocation.as_ref().map_or_else(
        || cwd.join(".sandbox-tmp"),
        |invocation| invocation.temp_dir.clone(),
    )
}

fn prepare_sandbox_dirs(cwd: &std::path::Path, sandbox_status: &SandboxStatus) {
    if !sandbox_status.filesystem_active {
        return;
    }

    if let Some(invocation) = &sandbox_status.invocation {
        for dir in [&invocation.home_dir, &invocation.temp_dir] {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Some(plan) = &invocation.overlay_plan {
            for dir in [&plan.upper_dir, &plan.work_dir, &plan.merged_dir] {
                let _ = std::fs::create_dir_all(dir);
            }
        }
        let _ = std::fs::write(
            invocation.root_dir.join(".claw-managed-sandbox-dir"),
            b"managed",
        );
        return;
    }

    for dir in [cwd.join(".sandbox-home"), cwd.join(".sandbox-tmp")] {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join(".claw-managed-sandbox-dir"), b"managed");
    }
}

fn cleanup_sandbox_dirs(cwd: &std::path::Path, sandbox_status: &SandboxStatus) {
    if sandbox_status.filesystem_active {
        if let Some(invocation) = &sandbox_status.invocation {
            if invocation
                .root_dir
                .join(".claw-managed-sandbox-dir")
                .exists()
            {
                let _ = std::fs::remove_dir_all(&invocation.root_dir);
            }
            return;
        }
        for dir in [cwd.join(".sandbox-home"), cwd.join(".sandbox-tmp")] {
            if dir.join(".claw-managed-sandbox-dir").exists() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
        let overlay_root = default_overlay_root(cwd);
        if overlay_root.join(".claw-overlay-layer").exists() {
            let _ = std::fs::remove_dir_all(overlay_root);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{execute_bash, BashCommandInput};
    use crate::sandbox::FilesystemIsolationMode;

    #[test]
    fn executes_simple_command() {
        let output = execute_bash(BashCommandInput {
            command: String::from("printf 'hello'"),
            timeout: Some(1_000),
            description: None,
            run_in_background: Some(false),
            dangerously_disable_sandbox: Some(false),
            namespace_restrictions: Some(false),
            isolate_network: Some(false),
            filesystem_mode: Some(FilesystemIsolationMode::WorkspaceOnly),
            allowed_mounts: None,
        })
        .expect("bash command should execute");

        assert_eq!(output.stdout, "hello");
        assert!(!output.interrupted);
        assert!(output.sandbox_status.is_some());
    }

    #[test]
    fn disables_sandbox_when_requested() {
        let output = execute_bash(BashCommandInput {
            command: String::from("printf 'hello'"),
            timeout: Some(1_000),
            description: None,
            run_in_background: Some(false),
            dangerously_disable_sandbox: Some(true),
            namespace_restrictions: None,
            isolate_network: None,
            filesystem_mode: None,
            allowed_mounts: None,
        })
        .expect("bash command should execute");

        assert!(!output.sandbox_status.expect("sandbox status").enabled);
    }

    #[test]
    fn timed_out_test_command_is_classified_as_hung_test_with_provenance() {
        let output = execute_bash(BashCommandInput {
            command: String::from("sleep 1 # cargo test slow_case"),
            timeout: Some(1),
            description: None,
            run_in_background: Some(false),
            dangerously_disable_sandbox: Some(false),
            namespace_restrictions: Some(false),
            isolate_network: Some(false),
            filesystem_mode: Some(FilesystemIsolationMode::WorkspaceOnly),
            allowed_mounts: None,
        })
        .expect("bash command should return structured timeout");

        assert!(output.interrupted);
        assert_eq!(
            output.return_code_interpretation.as_deref(),
            Some("test.hung")
        );
        let structured = output.structured_content.expect("structured content");
        assert_eq!(structured[0]["event"], "test.hung");
        assert_eq!(structured[0]["data"]["provenance"], "bash.timeout");
    }

    #[test]
    fn foreground_command_cleans_sandbox_temp_dirs() {
        let cwd = std::env::current_dir().expect("cwd");
        let output = execute_bash(BashCommandInput {
            command: String::from("printf 'hello'"),
            timeout: Some(1_000),
            description: None,
            run_in_background: Some(false),
            dangerously_disable_sandbox: Some(false),
            namespace_restrictions: Some(false),
            isolate_network: Some(false),
            filesystem_mode: Some(FilesystemIsolationMode::WorkspaceOnly),
            allowed_mounts: None,
        })
        .expect("bash command should execute");

        let sandbox_root = output
            .sandbox_status
            .as_ref()
            .and_then(|status| status.invocation.as_ref())
            .map(|invocation| invocation.root_dir.clone())
            .expect("foreground command should have an invocation sandbox");
        assert_eq!(output.stdout, "hello");
        assert!(!cwd.join(".sandbox-home").exists());
        assert!(!cwd.join(".sandbox-tmp").exists());
        assert!(!sandbox_root.exists());
    }
}

/// Maximum output bytes before truncation (16 KiB, matching upstream).
#[cfg(test)]
const MAX_OUTPUT_BYTES: usize = crate::sandbox::DEFAULT_OUTPUT_LIMIT_BYTES;

/// Truncate output to `MAX_OUTPUT_BYTES`, appending a marker when trimmed.
#[cfg(test)]
fn truncate_output(s: &str) -> String {
    if s.len() <= MAX_OUTPUT_BYTES {
        return s.to_string();
    }
    // Find the last valid UTF-8 boundary at or before MAX_OUTPUT_BYTES
    let mut end = MAX_OUTPUT_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = s[..end].to_string();
    truncated.push_str("\n\n[output truncated — exceeded 16384 bytes]");
    truncated
}

fn truncate_output_with_limit(s: &str, limit: usize) -> (String, bool) {
    if s.len() <= limit {
        return (s.to_string(), false);
    }
    let mut end = limit;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut truncated = s[..end].to_string();
    truncated.push_str(&format!("\n\n[output truncated - exceeded {limit} bytes]"));
    (truncated, true)
}

#[cfg(test)]
mod truncation_tests {
    use super::*;

    #[test]
    fn short_output_unchanged() {
        let s = "hello world";
        assert_eq!(truncate_output(s), s);
    }

    #[test]
    fn long_output_truncated() {
        let s = "x".repeat(20_000);
        let result = truncate_output(&s);
        assert!(result.len() < 20_000);
        assert!(result.ends_with("[output truncated — exceeded 16384 bytes]"));
    }

    #[test]
    fn exact_boundary_unchanged() {
        let s = "a".repeat(MAX_OUTPUT_BYTES);
        assert_eq!(truncate_output(&s), s);
    }

    #[test]
    fn one_over_boundary_truncated() {
        let s = "a".repeat(MAX_OUTPUT_BYTES + 1);
        let result = truncate_output(&s);
        assert!(result.contains("[output truncated"));
    }

    #[test]
    fn configured_output_limit_is_honored() {
        let s = "a".repeat(32);
        let (result, truncated) = truncate_output_with_limit(&s, 8);
        assert!(truncated);
        assert!(result.starts_with("aaaaaaaa"));
        assert!(result.ends_with("[output truncated - exceeded 8 bytes]"));
    }

    #[test]
    fn sandbox_audit_records_output_limit() {
        let status = crate::sandbox::SandboxConfig::default().resolve_request(
            Some(true),
            Some(false),
            Some(false),
            None,
            None,
        );
        let status =
            crate::sandbox::resolve_sandbox_status_for_request(&status, std::path::Path::new("."));
        let exit_status = shell_command()
            .args(shell_args("exit 0"))
            .status()
            .expect("shell should run");
        let events =
            audit_events_for_completed_command("printf long", &status, true, false, &exit_status)
                .expect("audit events");

        let output_event = events
            .iter()
            .find(|event| event["event"] == "output-limit-exceeded")
            .expect("output limit audit event");
        assert_eq!(output_event["data"]["stdoutTruncated"], true);
    }
}
