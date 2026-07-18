mod hooks;
#[cfg(test)]
pub mod test_isolation;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use hooks::{HookEvent, HookRunResult, HookRunner};

const EXTERNAL_MARKETPLACE: &str = "external";
const BUILTIN_MARKETPLACE: &str = "builtin";
const BUNDLED_MARKETPLACE: &str = "bundled";
const SETTINGS_FILE_NAME: &str = "settings.json";
const REGISTRY_FILE_NAME: &str = "installed.json";
const MANIFEST_FILE_NAME: &str = "plugin.json";
const MANIFEST_RELATIVE_PATH: &str = ".claude-plugin/plugin.json";
const BUILTIN_OPS_PLACEHOLDER_COMMAND: &str = "__claw_builtin_ops_placeholder__";
const BUILTIN_OPS_EXECUTOR_COMMAND: &str = "__claw_builtin_ops_executor__";
const PLUGIN_TOOL_TIMEOUT_MS: u64 = 30_000;
const PLUGIN_LIFECYCLE_TIMEOUT_MS: u64 = 30_000;
const PLUGIN_CHILD_POLL_MS: u64 = 25;
const MIN_PLUGIN_MCP_TIMEOUT_MS: u64 = 1;
const MAX_PLUGIN_MCP_TIMEOUT_MS: u64 = 300_000;
const MIN_PLUGIN_MCP_HEARTBEAT_INTERVAL_MS: u64 = 1;
const MAX_PLUGIN_MCP_HEARTBEAT_INTERVAL_MS: u64 = 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginKind {
    Builtin,
    Bundled,
    External,
}

impl Display for PluginKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Builtin => write!(f, "builtin"),
            Self::Bundled => write!(f, "bundled"),
            Self::External => write!(f, "external"),
        }
    }
}

impl PluginKind {
    #[must_use]
    fn marketplace(self) -> &'static str {
        match self {
            Self::Builtin => BUILTIN_MARKETPLACE,
            Self::Bundled => BUNDLED_MARKETPLACE,
            Self::External => EXTERNAL_MARKETPLACE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub kind: PluginKind,
    pub source: String,
    pub default_enabled: bool,
    pub root: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginHooks {
    #[serde(rename = "PreToolUse", default)]
    pub pre_tool_use: Vec<String>,
    #[serde(rename = "PostToolUse", default)]
    pub post_tool_use: Vec<String>,
    #[serde(rename = "PostToolUseFailure", default)]
    pub post_tool_use_failure: Vec<String>,
}

impl PluginHooks {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pre_tool_use.is_empty()
            && self.post_tool_use.is_empty()
            && self.post_tool_use_failure.is_empty()
    }

    #[must_use]
    pub fn merged_with(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        merged
            .pre_tool_use
            .extend(other.pre_tool_use.iter().cloned());
        merged
            .post_tool_use
            .extend(other.post_tool_use.iter().cloned());
        merged
            .post_tool_use_failure
            .extend(other.post_tool_use_failure.iter().cloned());
        merged
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginLifecycle {
    #[serde(rename = "Init", default)]
    pub init: Vec<String>,
    #[serde(rename = "Shutdown", default)]
    pub shutdown: Vec<String>,
}

impl PluginLifecycle {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.init.is_empty() && self.shutdown.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub permissions: Vec<PluginPermission>,
    #[serde(rename = "defaultEnabled", default)]
    pub default_enabled: bool,
    #[serde(default)]
    pub hooks: PluginHooks,
    #[serde(default)]
    pub lifecycle: PluginLifecycle,
    #[serde(rename = "executionPolicy", default)]
    pub execution_policy: PluginExecutionPolicy,
    #[serde(default)]
    pub tools: Vec<PluginToolManifest>,
    #[serde(default)]
    pub commands: Vec<PluginCommandManifest>,
    #[serde(default)]
    pub capabilities: PluginCapabilities,
    #[serde(rename = "mcpServers", default)]
    pub mcp_servers: BTreeMap<String, PluginMcpServerManifest>,
    #[serde(default)]
    pub dependencies: Vec<PluginDependency>,
    #[serde(default)]
    pub rollback: PluginRollbackPlan,
    #[serde(rename = "versionPolicy", default)]
    pub version_policy: PluginVersionPolicy,
    #[serde(rename = "opsPermissions", default)]
    pub ops_permissions: Vec<PluginOpsPermission>,
    #[serde(default)]
    pub resources: Vec<PluginResourceManifest>,
    #[serde(default)]
    pub prompts: Vec<PluginPromptManifest>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginExecutionPolicy {
    #[serde(default)]
    pub allow_external_subprocess: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginPermission {
    Read,
    Write,
    Execute,
}

impl PluginPermission {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "execute",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "execute" => Some(Self::Execute),
            _ => None,
        }
    }
}

impl AsRef<str> for PluginPermission {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginToolManifest {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "outputSchema", default)]
    pub output_schema: Option<Value>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub required_permission: PluginToolPermission,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginCapabilities {
    #[serde(default)]
    pub tools: bool,
    #[serde(default)]
    pub resources: bool,
    #[serde(default)]
    pub prompts: bool,
    #[serde(default)]
    pub workflows: bool,
    #[serde(rename = "hotReload", default)]
    pub hot_reload: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginToolPermission {
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
}

impl PluginToolPermission {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WorkspaceWrite => "workspace-write",
            Self::DangerFullAccess => "danger-full-access",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "read-only" => Some(Self::ReadOnly),
            "workspace-write" => Some(Self::WorkspaceWrite),
            "danger-full-access" => Some(Self::DangerFullAccess),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginToolDefinition {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "outputSchema", default)]
    pub output_schema: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginResourceManifest {
    pub uri: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "mimeType", default)]
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginPromptManifest {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub arguments: Vec<PluginPromptArgument>,
    #[serde(default)]
    pub template: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginPromptArgument {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default = "default_json_object")]
    pub schema: Value,
}

fn default_json_object() -> Value {
    Value::Object(Map::new())
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginMcpCapabilities {
    #[serde(default)]
    pub tools: Vec<PluginToolDefinition>,
    #[serde(default)]
    pub resources: Vec<PluginResourceManifest>,
    #[serde(default)]
    pub prompts: Vec<PluginPromptManifest>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginMcpTransport {
    #[default]
    Stdio,
    Sse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginMcpHeartbeat {
    #[serde(default = "default_mcp_heartbeat_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_mcp_heartbeat_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for PluginMcpHeartbeat {
    fn default() -> Self {
        Self {
            interval_ms: default_mcp_heartbeat_interval_ms(),
            timeout_ms: default_mcp_heartbeat_timeout_ms(),
        }
    }
}

fn default_mcp_heartbeat_interval_ms() -> u64 {
    PLUGIN_TOOL_TIMEOUT_MS
}

fn default_mcp_heartbeat_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginMcpServerManifest {
    #[serde(default)]
    pub transport: PluginMcpTransport,
    #[serde(rename = "requiredPermission", default)]
    pub required_permission: Option<PluginToolPermission>,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub protocol_version: Option<String>,
    #[serde(default)]
    pub tool_call_timeout_ms: Option<u64>,
    #[serde(default)]
    pub heartbeat: PluginMcpHeartbeat,
    #[serde(default)]
    pub capabilities: PluginMcpCapabilities,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginDependency {
    pub name: String,
    #[serde(default)]
    pub version_requirement: Option<String>,
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginRollbackStrategy {
    #[default]
    None,
    Manual,
    Command,
    Checkpoint,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRollbackPlan {
    #[serde(default)]
    pub strategy: PluginRollbackStrategy,
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginVersionPolicy {
    #[serde(default = "default_keep_versions")]
    pub keep_versions: usize,
    #[serde(default)]
    pub rollback_on_failure: bool,
}

fn default_keep_versions() -> usize {
    3
}

impl Default for PluginVersionPolicy {
    fn default() -> Self {
        Self {
            keep_versions: default_keep_versions(),
            rollback_on_failure: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PluginRiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginOpsPermission {
    pub permission: PluginToolPermission,
    pub scope: String,
    #[serde(default)]
    pub risk: PluginRiskLevel,
    pub reason: String,
    #[serde(default)]
    pub rollback_required: bool,
    #[serde(default)]
    pub rollback_command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginCommandManifest {
    pub name: String,
    pub description: String,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct RawPluginManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(rename = "defaultEnabled", default)]
    pub default_enabled: bool,
    #[serde(default)]
    pub hooks: PluginHooks,
    #[serde(default)]
    pub lifecycle: PluginLifecycle,
    #[serde(rename = "executionPolicy", default)]
    pub execution_policy: PluginExecutionPolicy,
    #[serde(default)]
    pub tools: Vec<RawPluginToolManifest>,
    #[serde(default)]
    pub commands: Vec<PluginCommandManifest>,
    #[serde(default)]
    pub capabilities: PluginCapabilities,
    #[serde(rename = "mcpServers", default)]
    pub mcp_servers: BTreeMap<String, PluginMcpServerManifest>,
    #[serde(default)]
    pub dependencies: Vec<PluginDependency>,
    #[serde(default)]
    pub rollback: PluginRollbackPlan,
    #[serde(rename = "versionPolicy", default)]
    pub version_policy: PluginVersionPolicy,
    #[serde(rename = "opsPermissions", default)]
    pub ops_permissions: Vec<PluginOpsPermission>,
    #[serde(default)]
    pub resources: Vec<PluginResourceManifest>,
    #[serde(default)]
    pub prompts: Vec<PluginPromptManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RawPluginToolManifest {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(rename = "outputSchema", default)]
    pub output_schema: Option<Value>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(
        rename = "requiredPermission",
        default = "missing_tool_permission_label"
    )]
    pub required_permission: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PluginTool {
    plugin_id: String,
    plugin_name: String,
    definition: PluginToolDefinition,
    command: String,
    args: Vec<String>,
    required_permission: PluginToolPermission,
    root: Option<PathBuf>,
    external_subprocess_allowed: bool,
    os_sandbox_required: bool,
}

impl PluginTool {
    #[must_use]
    pub fn new(
        plugin_id: impl Into<String>,
        plugin_name: impl Into<String>,
        definition: PluginToolDefinition,
        command: impl Into<String>,
        args: Vec<String>,
        required_permission: PluginToolPermission,
        root: Option<PathBuf>,
    ) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            plugin_name: plugin_name.into(),
            definition,
            command: command.into(),
            args,
            required_permission,
            root,
            external_subprocess_allowed: true,
            os_sandbox_required: false,
        }
    }

    #[must_use]
    pub fn with_external_subprocess_allowed(mut self, allowed: bool) -> Self {
        self.external_subprocess_allowed = allowed;
        self
    }

    #[must_use]
    pub fn with_os_sandbox_required(mut self, required: bool) -> Self {
        self.os_sandbox_required = required;
        self
    }

    #[must_use]
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    #[must_use]
    pub fn definition(&self) -> &PluginToolDefinition {
        &self.definition
    }

    #[must_use]
    pub fn required_permission(&self) -> &str {
        self.required_permission.as_str()
    }

    pub fn execute(&self, input: &Value) -> Result<String, PluginError> {
        validate_json_schema_value(&self.definition.input_schema, input, "input")?;

        if self.command == BUILTIN_OPS_PLACEHOLDER_COMMAND
            || self.command == BUILTIN_OPS_EXECUTOR_COMMAND
        {
            return execute_builtin_ops_tool(
                &self.plugin_id,
                &self.definition.name,
                self.required_permission,
                input,
            )
            .map(|value| value.to_string());
        }

        let input_json = input.to_string();
        let output = run_controlled_child(ControlledChildRequest {
            command: self.command.clone(),
            args: self.args.clone(),
            stdin: Some(input_json.clone()),
            cwd: self.root.clone(),
            timeout: Duration::from_millis(PLUGIN_TOOL_TIMEOUT_MS),
            permission: self.required_permission,
            external_subprocess_allowed: self.external_subprocess_allowed,
            os_sandbox_required: self.os_sandbox_required,
            env: BTreeMap::from([
                ("CLAWD_PLUGIN_ID".to_string(), self.plugin_id.clone()),
                ("CLAWD_PLUGIN_NAME".to_string(), self.plugin_name.clone()),
                ("CLAWD_TOOL_NAME".to_string(), self.definition.name.clone()),
                ("CLAWD_TOOL_INPUT".to_string(), input_json),
            ]),
        })?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if let Some(output_schema) = &self.definition.output_schema {
                let value: Value = serde_json::from_str(&stdout).map_err(|error| {
                    PluginError::CommandFailed(format!(
                        "plugin tool `{}` from `{}` returned non-JSON output for outputSchema validation: {error}",
                        self.definition.name, self.plugin_id
                    ))
                })?;
                validate_json_schema_value(output_schema, &value, "output")?;
            }
            Ok(stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(PluginError::CommandFailed(format!(
                "plugin tool `{}` from `{}` failed for `{}`: {}",
                self.definition.name,
                self.plugin_id,
                self.command,
                if stderr.is_empty() {
                    format!("exit status {}", output.status)
                } else {
                    stderr
                }
            )))
        }
    }
}

#[derive(Debug)]
struct ControlledChildRequest {
    command: String,
    args: Vec<String>,
    stdin: Option<String>,
    cwd: Option<PathBuf>,
    timeout: Duration,
    permission: PluginToolPermission,
    external_subprocess_allowed: bool,
    os_sandbox_required: bool,
    env: BTreeMap<String, String>,
}

fn run_controlled_child(request: ControlledChildRequest) -> Result<Output, PluginError> {
    if !request.external_subprocess_allowed {
        return Err(PluginError::CommandFailed(format!(
            "external plugin subprocess `{}` was refused: FR-2.13 requires an OS sandbox, and this runner only provides process policy guards; set executionPolicy.allowExternalSubprocess=true only for explicitly trusted plugins",
            request.command
        )));
    }
    if matches!(request.permission, PluginToolPermission::DangerFullAccess) {
        return Err(PluginError::CommandFailed(format!(
            "command `{}` requires danger-full-access and was rejected because no explicit operator approval policy is attached",
            request.command
        )));
    }

    let mut process = if request.os_sandbox_required {
        linux_plugin_sandbox_command(&request)?
    } else {
        controlled_command(&request.command, &request.args)
    };
    process
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("CLAWD_SANDBOX", "process-isolated")
        .env("CLAWD_NETWORK_DISABLED", "1")
        .env("CLAWD_PERMISSION", request.permission.as_str());

    copy_allowed_host_env(&mut process);
    for (key, value) in &request.env {
        process.env(key, value);
    }
    if let Some(cwd) = &request.cwd {
        process
            .current_dir(cwd)
            .env("CLAWD_PLUGIN_ROOT", cwd.display().to_string());
    }

    let mut child = process.spawn()?;
    if let Some(stdin_payload) = request.stdin {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_payload.as_bytes())?;
        }
    } else {
        drop(child.stdin.take());
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| PluginError::CommandFailed("controlled child stdout missing".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| PluginError::CommandFailed("controlled child stderr missing".to_string()))?;
    let stdout_reader = thread::spawn(move || read_pipe(stdout));
    let stderr_reader = thread::spawn(move || read_pipe(stderr));

    let deadline = Instant::now() + request.timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            terminate_child_tree(&mut child);
            let _ = child.wait();
            let stdout = join_pipe_reader(stdout_reader)?;
            let stderr = join_pipe_reader(stderr_reader)?;
            return Err(PluginError::CommandFailed(format!(
                "command `{}` timed out after {} ms; process was terminated; stdout: {}; stderr: {}",
                request.command,
                request.timeout.as_millis(),
                String::from_utf8_lossy(&stdout).trim(),
                String::from_utf8_lossy(&stderr).trim()
            )));
        }
        thread::sleep(Duration::from_millis(PLUGIN_CHILD_POLL_MS));
    };

    let stdout = join_pipe_reader(stdout_reader)?;
    let stderr = join_pipe_reader(stderr_reader)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(target_os = "linux")]
fn linux_plugin_sandbox_command(request: &ControlledChildRequest) -> Result<Command, PluginError> {
    const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
    if !Path::new(SYSTEMD_RUN).is_file() {
        return Err(PluginError::CommandFailed(format!(
            "external plugin subprocess `{}` was refused: required Linux sandbox launcher {SYSTEMD_RUN} is unavailable",
            request.command
        )));
    }

    let mut command = Command::new(SYSTEMD_RUN);
    command.args([
        "--user",
        "--pipe",
        "--wait",
        "--collect",
        "--quiet",
        "--property=PrivateNetwork=yes",
        "--property=PrivateTmp=yes",
        "--property=PrivateDevices=yes",
        "--property=PrivateUsers=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=read-only",
        "--property=NoNewPrivileges=yes",
        "--property=CapabilityBoundingSet=",
        "--property=AmbientCapabilities=",
        "--property=MemoryMax=256M",
        "--property=CPUQuota=100%",
        "--property=IOWeight=100",
        "--property=TasksMax=64",
        "--property=RestrictAddressFamilies=AF_UNIX",
        "--property=SystemCallArchitectures=native",
        "--property=SystemCallFilter=@system-service",
        "--property=SystemCallErrorNumber=EPERM",
    ]);
    if let Some(cwd) = &request.cwd {
        command.arg(format!("--working-directory={}", cwd.display()));
        append_systemd_environment(
            &mut command,
            "CLAWD_PLUGIN_ROOT",
            &cwd.display().to_string(),
        )?;
        if matches!(request.permission, PluginToolPermission::WorkspaceWrite) {
            command.arg(format!("--property=ReadWritePaths={}", cwd.display()));
        } else {
            command.arg(format!("--property=ReadOnlyPaths={}", cwd.display()));
        }
    }
    for (key, value) in &request.env {
        append_systemd_environment(&mut command, key, value)?;
    }
    for (key, value) in [
        ("CLAWD_SANDBOX", "systemd-transient-unit"),
        ("CLAWD_NETWORK_DISABLED", "1"),
        ("CLAWD_PERMISSION", request.permission.as_str()),
    ] {
        append_systemd_environment(&mut command, key, value)?;
    }
    command.arg("--").arg(&request.command).args(&request.args);
    Ok(command)
}

#[cfg(target_os = "linux")]
fn append_systemd_environment(
    command: &mut Command,
    key: &str,
    value: &str,
) -> Result<(), PluginError> {
    if value.chars().any(|ch| matches!(ch, '\0' | '\n' | '\r')) {
        return Err(PluginError::CommandFailed(format!(
            "external plugin environment `{key}` contains forbidden control characters"
        )));
    }
    command.arg(format!("--setenv={key}={value}"));
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn linux_plugin_sandbox_command(request: &ControlledChildRequest) -> Result<Command, PluginError> {
    Err(PluginError::CommandFailed(format!(
        "external plugin subprocess `{}` was refused: FR-2.13 requires the Linux/systemd sandbox available on Kylin Advanced Server OS",
        request.command
    )))
}

fn controlled_command(command: &str, args: &[String]) -> Command {
    #[cfg(windows)]
    {
        if command.ends_with(".sh") {
            if let Some(shell) = windows_sh() {
                let mut process = Command::new(shell);
                process
                    .arg("--noprofile")
                    .arg("--norc")
                    .arg(command.replace('\\', "/"))
                    .args(args);
                return process;
            }
        }
    }

    let mut process = Command::new(command);
    process.args(args);
    process
}

#[cfg(windows)]
fn windows_sh() -> Option<&'static str> {
    for path in [
        r"C:\msys64\usr\bin\bash.exe",
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\msys64\usr\bin\sh.exe",
        r"C:\Program Files\Git\bin\sh.exe",
    ] {
        if Path::new(path).exists() {
            return Some(path);
        }
    }
    None
}

fn copy_allowed_host_env(command: &mut Command) {
    for key in [
        "PATH",
        "Path",
        "SystemRoot",
        "WINDIR",
        "TMP",
        "TEMP",
        "HOME",
        "USERPROFILE",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

fn read_pipe(mut pipe: impl std::io::Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pipe.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn join_pipe_reader(
    handle: thread::JoinHandle<std::io::Result<Vec<u8>>>,
) -> Result<Vec<u8>, PluginError> {
    handle
        .join()
        .map_err(|_| {
            PluginError::CommandFailed("controlled child pipe reader panicked".to_string())
        })?
        .map_err(PluginError::Io)
}

fn terminate_child_tree(child: &mut Child) {
    if cfg!(windows) {
        let _ = Command::new("taskkill")
            .arg("/PID")
            .arg(child.id().to_string())
            .arg("/T")
            .arg("/F")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
}

fn validate_json_schema_value(
    schema: &Value,
    value: &Value,
    location: &str,
) -> Result<(), PluginError> {
    let Some(schema_object) = schema.as_object() else {
        return Err(PluginError::InvalidManifest(format!(
            "{location} schema must be a JSON object"
        )));
    };

    if let Some(schema_type) = schema_object.get("type") {
        let type_matches = if let Some(schema_type) = schema_type.as_str() {
            json_schema_type_matches(schema_type, value)
        } else if let Some(types) = schema_type.as_array() {
            types
                .iter()
                .filter_map(Value::as_str)
                .any(|schema_type| json_schema_type_matches(schema_type, value))
        } else {
            true
        };
        if !type_matches {
            return Err(PluginError::CommandFailed(format!(
                "{location} does not match schema type `{schema_type}`"
            )));
        }
    }

    if let Some(allowed_values) = schema_object.get("enum").and_then(Value::as_array) {
        if !allowed_values.iter().any(|allowed| allowed == value) {
            return Err(PluginError::CommandFailed(format!(
                "{location} is not one of the allowed enum values"
            )));
        }
    }

    for keyword in ["allOf"] {
        if let Some(schemas) = schema_object.get(keyword).and_then(Value::as_array) {
            for nested in schemas {
                validate_json_schema_value(nested, value, location)?;
            }
        }
    }

    if let Some(schemas) = schema_object.get("anyOf").and_then(Value::as_array) {
        if !schemas
            .iter()
            .any(|nested| validate_json_schema_value(nested, value, location).is_ok())
        {
            return Err(PluginError::CommandFailed(format!(
                "{location} does not match any anyOf schema"
            )));
        }
    }

    if let Some(schemas) = schema_object.get("oneOf").and_then(Value::as_array) {
        let matches = schemas
            .iter()
            .filter(|nested| validate_json_schema_value(nested, value, location).is_ok())
            .count();
        if matches != 1 {
            return Err(PluginError::CommandFailed(format!(
                "{location} matches {matches} oneOf schemas; expected exactly 1"
            )));
        }
    }

    if let Some(number) = value.as_f64() {
        if let Some(minimum) = schema_object.get("minimum").and_then(Value::as_f64) {
            if number < minimum {
                return Err(PluginError::CommandFailed(format!(
                    "{location} is below minimum {minimum}"
                )));
            }
        }
        if let Some(maximum) = schema_object.get("maximum").and_then(Value::as_f64) {
            if number > maximum {
                return Err(PluginError::CommandFailed(format!(
                    "{location} is above maximum {maximum}"
                )));
            }
        }
    }

    if let Some(text) = value.as_str() {
        if let Some(pattern) = schema_object.get("pattern").and_then(Value::as_str) {
            if !json_schema_pattern_matches(pattern, text) {
                return Err(PluginError::CommandFailed(format!(
                    "{location} does not match pattern `{pattern}`"
                )));
            }
        }
    }

    if let Some(array) = value.as_array() {
        if let Some(item_schema) = schema_object.get("items") {
            for (index, item) in array.iter().enumerate() {
                validate_json_schema_value(item_schema, item, &format!("{location}[{index}]"))?;
            }
        }
    }

    if let Some(value_object) = value.as_object() {
        if let Some(required) = schema_object.get("required").and_then(Value::as_array) {
            for field in required.iter().filter_map(Value::as_str) {
                if !value_object.contains_key(field) {
                    return Err(PluginError::CommandFailed(format!(
                        "{location} is missing required field `{field}`"
                    )));
                }
            }
        }

        if let Some(properties) = schema_object.get("properties").and_then(Value::as_object) {
            for (field, field_schema) in properties {
                if let Some(field_value) = value_object.get(field) {
                    validate_json_schema_value(
                        field_schema,
                        field_value,
                        &format!("{location}.{field}"),
                    )?;
                }
            }
        }

        if matches!(
            schema_object
                .get("additionalProperties")
                .and_then(Value::as_bool),
            Some(false)
        ) {
            let allowed = schema_object
                .get("properties")
                .and_then(Value::as_object)
                .map(|properties| properties.keys().cloned().collect::<BTreeSet<_>>())
                .unwrap_or_default();
            if let Some(extra) = value_object
                .keys()
                .find(|key| !allowed.contains(key.as_str()))
            {
                return Err(PluginError::CommandFailed(format!(
                    "{location} contains undeclared field `{extra}`"
                )));
            }
        }
    }

    Ok(())
}

fn json_schema_type_matches(schema_type: &str, value: &Value) -> bool {
    match schema_type {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "null" => value.is_null(),
        _ => true,
    }
}

fn json_schema_pattern_matches(pattern: &str, value: &str) -> bool {
    if let Some(stripped) = pattern.strip_prefix('^').and_then(|p| p.strip_suffix('$')) {
        return value == stripped;
    }
    if let Some(stripped) = pattern.strip_prefix('^') {
        return value.starts_with(stripped);
    }
    if let Some(stripped) = pattern.strip_suffix('$') {
        return value.ends_with(stripped);
    }
    value.contains(pattern)
}

#[derive(Debug, Clone)]
struct BuiltinOpsCommand {
    program: &'static str,
    args: Vec<String>,
    mutating: bool,
}

fn execute_builtin_ops_tool(
    plugin_id: &str,
    tool_name: &str,
    permission: PluginToolPermission,
    input: &Value,
) -> Result<Value, PluginError> {
    let plugin_name = plugin_id.split('@').next().unwrap_or(plugin_id);
    let action = input
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("inspect");
    let dry_run = input.get("dryRun").and_then(Value::as_bool).unwrap_or(true);
    let confirmed = input
        .get("confirm")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if action == "rollback" {
        return execute_builtin_ops_rollback(plugin_id, tool_name, permission, input, confirmed);
    }
    let command = build_builtin_ops_command(plugin_name, action, input)?;
    let target = input.get("target").cloned().unwrap_or(Value::Null);
    let command_json = serde_json::json!({
        "program": command.program,
        "args": command.args,
        "shell": false
    });

    if command.mutating && !confirmed {
        return Ok(serde_json::json!({
            "status": "requires_confirmation",
            "mode": "apply",
            "plugin": plugin_id,
            "tool": tool_name,
            "permission": permission.as_str(),
            "dryRun": dry_run,
            "confirmed": false,
            "audit": { "mutationPerformed": false, "reason": "confirm=true is required before any mutation" },
            "plan": [{ "step": "execute", "command": command_json, "target": target }],
            "rollback": { "available": rollback_action(plugin_name, action).is_some(), "performed": false }
        }));
    }

    if dry_run {
        return Ok(serde_json::json!({
            "status": "dry_run",
            "mode": if command.mutating { "apply" } else { "inspect" },
            "plugin": plugin_id,
            "tool": tool_name,
            "permission": permission.as_str(),
            "dryRun": true,
            "confirmed": confirmed,
            "audit": { "mutationPerformed": false, "reason": "validated fixed argv; dry-run does not spawn a process" },
            "plan": [{ "step": "execute", "command": command_json, "target": target }],
            "rollback": { "available": rollback_action(plugin_name, action).is_some(), "performed": false }
        }));
    }

    let checkpoint = if command.mutating {
        let rollback = rollback_action(plugin_name, action).ok_or_else(|| {
            PluginError::CommandFailed(format!(
                "{plugin_name} action `{action}` was refused because no deterministic rollback is available"
            ))
        })?;
        Some(write_builtin_ops_checkpoint(
            plugin_id, tool_name, action, input, rollback,
        )?)
    } else {
        None
    };
    let output = run_fixed_builtin_command(&command)?;
    let success = output.status.success();
    Ok(serde_json::json!({
        "status": if success { "ok" } else { "command_failed" },
        "mode": if command.mutating { "apply" } else { "inspect" },
        "plugin": plugin_id,
        "tool": tool_name,
        "permission": permission.as_str(),
        "dryRun": false,
        "confirmed": confirmed,
        "audit": {
            "mutationPerformed": command.mutating && success,
            "program": command.program,
            "exitCode": output.status.code(),
            "stdoutTruncated": output.stdout_truncated,
            "stderrTruncated": output.stderr_truncated
        },
        "plan": [{ "step": "execute", "command": command_json, "target": target }],
        "result": {
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr)
        },
        "rollback": {
            "available": checkpoint.is_some(),
            "checkpoint": checkpoint,
            "performed": false
        }
    }))
}

fn build_builtin_ops_command(
    plugin: &str,
    action: &str,
    input: &Value,
) -> Result<BuiltinOpsCommand, PluginError> {
    let target = input.get("target").and_then(Value::as_str);
    let command = match plugin {
        "disk_cleaner" => {
            require_action(action, &["inspect", "plan"])?;
            let root = target.unwrap_or("/tmp");
            if !matches!(
                root,
                "/tmp" | "/var/tmp" | "/var/cache/dnf" | "/var/log/journal"
            ) {
                return Err(invalid_ops_input(
                    "disk target is not in the Kylin cleanup allowlist",
                ));
            }
            let days = input
                .get("olderThanDays")
                .and_then(Value::as_u64)
                .unwrap_or(7);
            if !(1..=365).contains(&days) {
                return Err(invalid_ops_input("olderThanDays must be between 1 and 365"));
            }
            fixed_command(
                "/usr/bin/find",
                [root, "-xdev", "-type", "f", "-mtime"]
                    .into_iter()
                    .map(str::to_string)
                    .chain([format!("+{days}"), "-print".to_string()])
                    .collect(),
                false,
            )
        }
        "service_manager" => {
            let unit = validate_systemd_unit(require_target(target)?, ".service")?;
            match action {
                "inspect" | "plan" => fixed_command(
                    "/usr/bin/systemctl",
                    vec![
                        "show".into(),
                        "--no-pager".into(),
                        "--property=Id,LoadState,ActiveState,SubState,Result,ExecMainStatus".into(),
                        "--".into(),
                        unit,
                    ],
                    false,
                ),
                "start" | "stop" | "restart" => fixed_command(
                    "/usr/bin/systemctl",
                    vec![action.into(), "--".into(), unit],
                    true,
                ),
                _ => return Err(unsupported_ops_action(plugin, action)),
            }
        }
        "user_manager" => {
            let user = validate_account_name(require_target(target)?)?;
            match action {
                "inspect" | "plan" => {
                    fixed_command("/usr/bin/getent", vec!["passwd".into(), user], false)
                }
                "lock" => fixed_command("/usr/sbin/usermod", vec!["--lock".into(), user], true),
                "unlock" => fixed_command("/usr/sbin/usermod", vec!["--unlock".into(), user], true),
                _ => return Err(unsupported_ops_action(plugin, action)),
            }
        }
        "log_analyzer" => {
            require_action(action, &["inspect", "plan"])?;
            let limit = input
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(200)
                .clamp(1, 1_000);
            let mut args = vec![
                "--no-pager".into(),
                "--output=short-iso".into(),
                format!("--lines={limit}"),
            ];
            if let Some(unit) = target {
                args.push(format!(
                    "--unit={}",
                    validate_systemd_unit(unit, ".service")?
                ));
            }
            fixed_command("/usr/bin/journalctl", args, false)
        }
        "package_manager" => {
            let package = validate_package_name(require_target(target)?)?;
            match action {
                "inspect" | "plan" => fixed_command(
                    "/usr/bin/rpm",
                    vec!["--query".into(), "--".into(), package],
                    false,
                ),
                "install" | "remove" => fixed_command(
                    "/usr/bin/dnf",
                    vec!["--assumeyes".into(), action.into(), "--".into(), package],
                    true,
                ),
                _ => return Err(unsupported_ops_action(plugin, action)),
            }
        }
        "firewall_manager" => {
            require_action(action, &["inspect", "plan"])?;
            fixed_command(
                "/usr/sbin/nft",
                vec!["--json".into(), "list".into(), "ruleset".into()],
                false,
            )
        }
        "cron_manager" => match action {
            "inspect" | "plan" if target.is_none() => fixed_command(
                "/usr/bin/systemctl",
                vec!["list-timers".into(), "--all".into(), "--no-pager".into()],
                false,
            ),
            "inspect" | "plan" => fixed_command(
                "/usr/bin/systemctl",
                vec![
                    "show".into(),
                    "--no-pager".into(),
                    "--".into(),
                    validate_systemd_unit(require_target(target)?, ".timer")?,
                ],
                false,
            ),
            "enable" | "disable" | "start" | "stop" | "restart" => fixed_command(
                "/usr/bin/systemctl",
                vec![
                    action.into(),
                    "--".into(),
                    validate_systemd_unit(require_target(target)?, ".timer")?,
                ],
                true,
            ),
            _ => return Err(unsupported_ops_action(plugin, action)),
        },
        "network_diagnostics" => match action {
            "inspect" | "plan" => fixed_command(
                "/usr/sbin/ss",
                vec![
                    "--tcp".into(),
                    "--udp".into(),
                    "--numeric".into(),
                    "--processes".into(),
                ],
                false,
            ),
            "dns" => fixed_command(
                "/usr/bin/getent",
                vec!["ahosts".into(), validate_host(require_target(target)?)?],
                false,
            ),
            "ping" => fixed_command(
                "/usr/bin/ping",
                vec![
                    "-c".into(),
                    "3".into(),
                    "-W".into(),
                    "2".into(),
                    "--".into(),
                    validate_host(require_target(target)?)?,
                ],
                false,
            ),
            _ => return Err(unsupported_ops_action(plugin, action)),
        },
        "backup_manager" => {
            let path = validate_workspace_path(require_target(target)?, false)?;
            match action {
                "inspect" | "plan" => fixed_command(
                    "/usr/bin/find",
                    vec![
                        path,
                        "-maxdepth".into(),
                        "1".into(),
                        "-printf".into(),
                        "%M %u %g %s %TY-%Tm-%TdT%TH:%TM:%TS %p\\n".into(),
                    ],
                    false,
                ),
                "backup" => {
                    let destination = input
                        .get("destination")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid_ops_input("backup requires destination"))?;
                    let destination = validate_workspace_path(destination, true)?;
                    fixed_command(
                        "/usr/bin/tar",
                        vec![
                            "--create".into(),
                            "--file".into(),
                            destination,
                            "--".into(),
                            path,
                        ],
                        true,
                    )
                }
                _ => return Err(unsupported_ops_action(plugin, action)),
            }
        }
        _ => return Err(invalid_ops_input("unknown built-in operations plugin")),
    };
    Ok(command)
}

fn fixed_command(program: &'static str, args: Vec<String>, mutating: bool) -> BuiltinOpsCommand {
    BuiltinOpsCommand {
        program,
        args,
        mutating,
    }
}

fn require_action(action: &str, allowed: &[&str]) -> Result<(), PluginError> {
    if allowed.contains(&action) {
        Ok(())
    } else {
        Err(invalid_ops_input("action is not supported for this plugin"))
    }
}

fn require_target(target: Option<&str>) -> Result<&str, PluginError> {
    target
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_ops_input("target is required"))
}

fn validate_systemd_unit(value: &str, suffix: &str) -> Result<String, PluginError> {
    if value.starts_with('-')
        || value.len() > 256
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@' | ':'))
    {
        return Err(invalid_ops_input("invalid systemd unit name"));
    }
    Ok(if value.ends_with(suffix) {
        value.to_string()
    } else {
        format!("{value}{suffix}")
    })
}

fn validate_account_name(value: &str) -> Result<String, PluginError> {
    let valid = (1..=32).contains(&value.len())
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_lowercase() || ch == '_')
        && value
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-'));
    valid
        .then(|| value.to_string())
        .ok_or_else(|| invalid_ops_input("invalid Linux account name"))
}

fn validate_package_name(value: &str) -> Result<String, PluginError> {
    let valid = (1..=128).contains(&value.len())
        && !value.starts_with('-')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '_' | '-' | '.' | ':'));
    valid
        .then(|| value.to_string())
        .ok_or_else(|| invalid_ops_input("invalid RPM package name"))
}

fn validate_host(value: &str) -> Result<String, PluginError> {
    let valid = (1..=253).contains(&value.len())
        && !value.starts_with('-')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '.' | ':'));
    valid
        .then(|| value.to_string())
        .ok_or_else(|| invalid_ops_input("invalid DNS host or address"))
}

fn validate_workspace_path(value: &str, allow_missing: bool) -> Result<String, PluginError> {
    let cwd = fs::canonicalize(std::env::current_dir()?)?;
    let candidate = PathBuf::from(value);
    let resolved = if allow_missing && !candidate.exists() {
        let parent = candidate
            .parent()
            .ok_or_else(|| invalid_ops_input("destination requires a parent directory"))?;
        fs::canonicalize(parent)?.join(
            candidate
                .file_name()
                .ok_or_else(|| invalid_ops_input("destination requires a file name"))?,
        )
    } else {
        fs::canonicalize(&candidate)?
    };
    if !resolved.starts_with(&cwd) {
        return Err(invalid_ops_input(
            "path must remain inside the current workspace",
        ));
    }
    Ok(resolved.display().to_string())
}

fn unsupported_ops_action(plugin: &str, action: &str) -> PluginError {
    PluginError::CommandFailed(format!(
        "built-in plugin `{plugin}` does not support action `{action}`"
    ))
}

fn invalid_ops_input(message: &str) -> PluginError {
    PluginError::CommandFailed(message.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BuiltinOpsCheckpoint {
    plugin_id: String,
    tool_name: String,
    action: String,
    rollback_action: String,
    input: Value,
    created_at_ms: u64,
}

fn rollback_action(plugin: &str, action: &str) -> Option<&'static str> {
    match (plugin, action) {
        ("service_manager", "start") => Some("stop"),
        ("service_manager", "stop") => Some("start"),
        ("service_manager", "restart") => Some("restart"),
        ("user_manager", "lock") => Some("unlock"),
        ("user_manager", "unlock") => Some("lock"),
        ("package_manager", "install") => Some("remove"),
        ("package_manager", "remove") => Some("install"),
        ("cron_manager", "enable") => Some("disable"),
        ("cron_manager", "disable") => Some("enable"),
        ("cron_manager", "start") => Some("stop"),
        ("cron_manager", "stop") => Some("start"),
        ("cron_manager", "restart") => Some("restart"),
        _ => None,
    }
}

fn checkpoint_root() -> PathBuf {
    std::env::var_os("CLAW_OPS_CHECKPOINT_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/claw/ops-checkpoints"))
}

fn next_unique_id() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn write_builtin_ops_checkpoint(
    plugin_id: &str,
    tool_name: &str,
    action: &str,
    input: &Value,
    rollback_action: &str,
) -> Result<Value, PluginError> {
    let root = checkpoint_root();
    fs::create_dir_all(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    let created_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default();
    let id = format!(
        "{created_at_ms}-{}-{}.json",
        std::process::id(),
        next_unique_id()
    );
    let path = root.join(&id);
    let checkpoint = BuiltinOpsCheckpoint {
        plugin_id: plugin_id.to_string(),
        tool_name: tool_name.to_string(),
        action: action.to_string(),
        rollback_action: rollback_action.to_string(),
        input: input.clone(),
        created_at_ms,
    };
    fs::write(&path, serde_json::to_vec_pretty(&checkpoint)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(serde_json::json!({
        "id": id,
        "path": path,
        "rollbackAction": rollback_action,
        "createdAtMs": created_at_ms
    }))
}

fn execute_builtin_ops_rollback(
    plugin_id: &str,
    tool_name: &str,
    permission: PluginToolPermission,
    input: &Value,
    confirmed: bool,
) -> Result<Value, PluginError> {
    let id = input
        .get("checkpointId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_ops_input("rollback requires checkpointId"))?;
    if id.len() > 128
        || !id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        || id.contains("..")
    {
        return Err(invalid_ops_input("invalid rollback checkpointId"));
    }
    if !confirmed {
        return Ok(serde_json::json!({
            "status": "requires_confirmation",
            "mode": "rollback",
            "plugin": plugin_id,
            "tool": tool_name,
            "permission": permission.as_str(),
            "audit": { "mutationPerformed": false },
            "plan": [{ "step": "rollback", "checkpointId": id }],
            "rollback": { "available": true, "performed": false }
        }));
    }
    let path = checkpoint_root().join(id);
    let checkpoint: BuiltinOpsCheckpoint = serde_json::from_slice(&fs::read(&path)?)?;
    if checkpoint.plugin_id != plugin_id || checkpoint.tool_name != tool_name {
        return Err(invalid_ops_input(
            "checkpoint does not belong to this plugin tool",
        ));
    }
    let plugin_name = plugin_id.split('@').next().unwrap_or(plugin_id);
    let command =
        build_builtin_ops_command(plugin_name, &checkpoint.rollback_action, &checkpoint.input)?;
    if !command.mutating {
        return Err(invalid_ops_input(
            "checkpoint rollback did not resolve to a mutation",
        ));
    }
    let output = run_fixed_builtin_command(&command)?;
    Ok(serde_json::json!({
        "status": if output.status.success() { "rolled_back" } else { "rollback_failed" },
        "mode": "rollback",
        "plugin": plugin_id,
        "tool": tool_name,
        "permission": permission.as_str(),
        "audit": {
            "mutationPerformed": output.status.success(),
            "program": command.program,
            "exitCode": output.status.code(),
            "stdoutTruncated": output.stdout_truncated,
            "stderrTruncated": output.stderr_truncated
        },
        "plan": [{ "step": "rollback", "checkpointId": id, "program": command.program, "args": command.args, "shell": false }],
        "result": {
            "stdout": String::from_utf8_lossy(&output.stdout),
            "stderr": String::from_utf8_lossy(&output.stderr)
        },
        "rollback": { "available": true, "performed": output.status.success() }
    }))
}

struct FixedCommandOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

fn run_fixed_builtin_command(
    command: &BuiltinOpsCommand,
) -> Result<FixedCommandOutput, PluginError> {
    const OUTPUT_LIMIT: usize = 1024 * 1024;
    if !Path::new(command.program).is_file() {
        return Err(PluginError::CommandFailed(format!(
            "required Kylin/Linux executable `{}` is unavailable",
            command.program
        )));
    }
    let mut process = Command::new(command.program);
    process
        .args(&command.args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = process.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| invalid_ops_input("fixed command stdout missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| invalid_ops_input("fixed command stderr missing"))?;
    let stdout_reader = thread::spawn(move || read_pipe_capped(stdout, OUTPUT_LIMIT));
    let stderr_reader = thread::spawn(move || read_pipe_capped(stderr, OUTPUT_LIMIT));
    let deadline = Instant::now() + Duration::from_millis(PLUGIN_TOOL_TIMEOUT_MS);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            terminate_child_tree(&mut child);
            let _ = child.wait();
            return Err(PluginError::CommandFailed(format!(
                "fixed command `{}` timed out after {PLUGIN_TOOL_TIMEOUT_MS} ms and was terminated",
                command.program
            )));
        }
        thread::sleep(Duration::from_millis(PLUGIN_CHILD_POLL_MS));
    };
    let (stdout, stdout_truncated) = stdout_reader
        .join()
        .map_err(|_| invalid_ops_input("fixed command stdout reader panicked"))??;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| invalid_ops_input("fixed command stderr reader panicked"))??;
    Ok(FixedCommandOutput {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

fn read_pipe_capped(
    mut pipe: impl std::io::Read,
    limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let read = pipe.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = limit.saturating_sub(output.len());
        let keep = read.min(remaining);
        output.extend_from_slice(&buffer[..keep]);
        truncated |= keep < read;
    }
    Ok((output, truncated))
}

fn missing_tool_permission_label() -> String {
    String::new()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PluginInstallSource {
    LocalPath { path: PathBuf },
    GitUrl { url: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPluginRecord {
    #[serde(default = "default_plugin_kind")]
    pub kind: PluginKind,
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub install_path: PathBuf,
    pub source: PluginInstallSource,
    #[serde(rename = "versionPolicy", default)]
    pub version_policy: PluginVersionPolicy,
    pub installed_at_unix_ms: u128,
    pub updated_at_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPluginVersionRecord {
    pub version: String,
    pub description: String,
    pub install_path: PathBuf,
    pub archived_at_unix_ms: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPluginRegistry {
    #[serde(default)]
    pub plugins: BTreeMap<String, InstalledPluginRecord>,
    #[serde(default)]
    pub versions: BTreeMap<String, Vec<InstalledPluginVersionRecord>>,
}

fn default_plugin_kind() -> PluginKind {
    PluginKind::External
}

#[derive(Debug, Clone, PartialEq)]
pub struct BuiltinPlugin {
    metadata: PluginMetadata,
    hooks: PluginHooks,
    lifecycle: PluginLifecycle,
    execution_policy: PluginExecutionPolicy,
    permissions: Vec<PluginPermission>,
    tools: Vec<PluginTool>,
    resources: Vec<PluginResourceManifest>,
    prompts: Vec<PluginPromptManifest>,
    capabilities: PluginCapabilities,
    mcp_servers: BTreeMap<String, PluginMcpServerManifest>,
    dependencies: Vec<PluginDependency>,
    rollback: PluginRollbackPlan,
    version_policy: PluginVersionPolicy,
    ops_permissions: Vec<PluginOpsPermission>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BundledPlugin {
    metadata: PluginMetadata,
    hooks: PluginHooks,
    lifecycle: PluginLifecycle,
    execution_policy: PluginExecutionPolicy,
    permissions: Vec<PluginPermission>,
    tools: Vec<PluginTool>,
    resources: Vec<PluginResourceManifest>,
    prompts: Vec<PluginPromptManifest>,
    capabilities: PluginCapabilities,
    mcp_servers: BTreeMap<String, PluginMcpServerManifest>,
    dependencies: Vec<PluginDependency>,
    rollback: PluginRollbackPlan,
    version_policy: PluginVersionPolicy,
    ops_permissions: Vec<PluginOpsPermission>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExternalPlugin {
    metadata: PluginMetadata,
    hooks: PluginHooks,
    lifecycle: PluginLifecycle,
    execution_policy: PluginExecutionPolicy,
    permissions: Vec<PluginPermission>,
    tools: Vec<PluginTool>,
    resources: Vec<PluginResourceManifest>,
    prompts: Vec<PluginPromptManifest>,
    capabilities: PluginCapabilities,
    mcp_servers: BTreeMap<String, PluginMcpServerManifest>,
    dependencies: Vec<PluginDependency>,
    rollback: PluginRollbackPlan,
    version_policy: PluginVersionPolicy,
    ops_permissions: Vec<PluginOpsPermission>,
}

pub trait Plugin {
    fn metadata(&self) -> &PluginMetadata;
    fn hooks(&self) -> &PluginHooks;
    fn lifecycle(&self) -> &PluginLifecycle;
    fn execution_policy(&self) -> &PluginExecutionPolicy;
    fn permissions(&self) -> &[PluginPermission];
    fn tools(&self) -> &[PluginTool];
    fn resources(&self) -> &[PluginResourceManifest];
    fn prompts(&self) -> &[PluginPromptManifest];
    fn capabilities(&self) -> &PluginCapabilities;
    fn mcp_servers(&self) -> &BTreeMap<String, PluginMcpServerManifest>;
    fn dependencies(&self) -> &[PluginDependency];
    fn rollback(&self) -> &PluginRollbackPlan;
    fn version_policy(&self) -> &PluginVersionPolicy;
    fn ops_permissions(&self) -> &[PluginOpsPermission];
    fn validate(&self) -> Result<(), PluginError>;
    fn initialize(&self) -> Result<(), PluginError>;
    fn shutdown(&self) -> Result<(), PluginError>;
}

#[derive(Debug, Clone, PartialEq)]
pub enum PluginDefinition {
    Builtin(BuiltinPlugin),
    Bundled(BundledPlugin),
    External(ExternalPlugin),
}

impl Plugin for BuiltinPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn hooks(&self) -> &PluginHooks {
        &self.hooks
    }

    fn lifecycle(&self) -> &PluginLifecycle {
        &self.lifecycle
    }

    fn execution_policy(&self) -> &PluginExecutionPolicy {
        &self.execution_policy
    }

    fn permissions(&self) -> &[PluginPermission] {
        &self.permissions
    }

    fn tools(&self) -> &[PluginTool] {
        &self.tools
    }

    fn resources(&self) -> &[PluginResourceManifest] {
        &self.resources
    }

    fn prompts(&self) -> &[PluginPromptManifest] {
        &self.prompts
    }

    fn capabilities(&self) -> &PluginCapabilities {
        &self.capabilities
    }

    fn mcp_servers(&self) -> &BTreeMap<String, PluginMcpServerManifest> {
        &self.mcp_servers
    }

    fn dependencies(&self) -> &[PluginDependency] {
        &self.dependencies
    }

    fn rollback(&self) -> &PluginRollbackPlan {
        &self.rollback
    }

    fn version_policy(&self) -> &PluginVersionPolicy {
        &self.version_policy
    }

    fn ops_permissions(&self) -> &[PluginOpsPermission] {
        &self.ops_permissions
    }

    fn validate(&self) -> Result<(), PluginError> {
        Ok(())
    }

    fn initialize(&self) -> Result<(), PluginError> {
        Ok(())
    }

    fn shutdown(&self) -> Result<(), PluginError> {
        Ok(())
    }
}

impl Plugin for BundledPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn hooks(&self) -> &PluginHooks {
        &self.hooks
    }

    fn lifecycle(&self) -> &PluginLifecycle {
        &self.lifecycle
    }

    fn execution_policy(&self) -> &PluginExecutionPolicy {
        &self.execution_policy
    }

    fn permissions(&self) -> &[PluginPermission] {
        &self.permissions
    }

    fn tools(&self) -> &[PluginTool] {
        &self.tools
    }

    fn resources(&self) -> &[PluginResourceManifest] {
        &self.resources
    }

    fn prompts(&self) -> &[PluginPromptManifest] {
        &self.prompts
    }

    fn capabilities(&self) -> &PluginCapabilities {
        &self.capabilities
    }

    fn mcp_servers(&self) -> &BTreeMap<String, PluginMcpServerManifest> {
        &self.mcp_servers
    }

    fn dependencies(&self) -> &[PluginDependency] {
        &self.dependencies
    }

    fn rollback(&self) -> &PluginRollbackPlan {
        &self.rollback
    }

    fn version_policy(&self) -> &PluginVersionPolicy {
        &self.version_policy
    }

    fn ops_permissions(&self) -> &[PluginOpsPermission] {
        &self.ops_permissions
    }

    fn validate(&self) -> Result<(), PluginError> {
        validate_hook_paths(self.metadata.root.as_deref(), &self.hooks)?;
        validate_lifecycle_paths(self.metadata.root.as_deref(), &self.lifecycle)?;
        validate_tool_paths(self.metadata.root.as_deref(), &self.tools)
    }

    fn initialize(&self) -> Result<(), PluginError> {
        run_lifecycle_commands(
            self.metadata(),
            self.lifecycle(),
            self.execution_policy(),
            self.permissions(),
            "init",
            &self.lifecycle.init,
        )
    }

    fn shutdown(&self) -> Result<(), PluginError> {
        run_lifecycle_commands(
            self.metadata(),
            self.lifecycle(),
            self.execution_policy(),
            self.permissions(),
            "shutdown",
            &self.lifecycle.shutdown,
        )
    }
}

impl Plugin for ExternalPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    fn hooks(&self) -> &PluginHooks {
        &self.hooks
    }

    fn lifecycle(&self) -> &PluginLifecycle {
        &self.lifecycle
    }

    fn execution_policy(&self) -> &PluginExecutionPolicy {
        &self.execution_policy
    }

    fn permissions(&self) -> &[PluginPermission] {
        &self.permissions
    }

    fn tools(&self) -> &[PluginTool] {
        &self.tools
    }

    fn resources(&self) -> &[PluginResourceManifest] {
        &self.resources
    }

    fn prompts(&self) -> &[PluginPromptManifest] {
        &self.prompts
    }

    fn capabilities(&self) -> &PluginCapabilities {
        &self.capabilities
    }

    fn mcp_servers(&self) -> &BTreeMap<String, PluginMcpServerManifest> {
        &self.mcp_servers
    }

    fn dependencies(&self) -> &[PluginDependency] {
        &self.dependencies
    }

    fn rollback(&self) -> &PluginRollbackPlan {
        &self.rollback
    }

    fn version_policy(&self) -> &PluginVersionPolicy {
        &self.version_policy
    }

    fn ops_permissions(&self) -> &[PluginOpsPermission] {
        &self.ops_permissions
    }

    fn validate(&self) -> Result<(), PluginError> {
        validate_hook_paths(self.metadata.root.as_deref(), &self.hooks)?;
        validate_lifecycle_paths(self.metadata.root.as_deref(), &self.lifecycle)?;
        validate_tool_paths(self.metadata.root.as_deref(), &self.tools)
    }

    fn initialize(&self) -> Result<(), PluginError> {
        run_lifecycle_commands(
            self.metadata(),
            self.lifecycle(),
            self.execution_policy(),
            self.permissions(),
            "init",
            &self.lifecycle.init,
        )
    }

    fn shutdown(&self) -> Result<(), PluginError> {
        run_lifecycle_commands(
            self.metadata(),
            self.lifecycle(),
            self.execution_policy(),
            self.permissions(),
            "shutdown",
            &self.lifecycle.shutdown,
        )
    }
}

impl Plugin for PluginDefinition {
    fn metadata(&self) -> &PluginMetadata {
        match self {
            Self::Builtin(plugin) => plugin.metadata(),
            Self::Bundled(plugin) => plugin.metadata(),
            Self::External(plugin) => plugin.metadata(),
        }
    }

    fn hooks(&self) -> &PluginHooks {
        match self {
            Self::Builtin(plugin) => plugin.hooks(),
            Self::Bundled(plugin) => plugin.hooks(),
            Self::External(plugin) => plugin.hooks(),
        }
    }

    fn lifecycle(&self) -> &PluginLifecycle {
        match self {
            Self::Builtin(plugin) => plugin.lifecycle(),
            Self::Bundled(plugin) => plugin.lifecycle(),
            Self::External(plugin) => plugin.lifecycle(),
        }
    }

    fn tools(&self) -> &[PluginTool] {
        match self {
            Self::Builtin(plugin) => plugin.tools(),
            Self::Bundled(plugin) => plugin.tools(),
            Self::External(plugin) => plugin.tools(),
        }
    }

    fn execution_policy(&self) -> &PluginExecutionPolicy {
        match self {
            Self::Builtin(plugin) => plugin.execution_policy(),
            Self::Bundled(plugin) => plugin.execution_policy(),
            Self::External(plugin) => plugin.execution_policy(),
        }
    }

    fn permissions(&self) -> &[PluginPermission] {
        match self {
            Self::Builtin(plugin) => plugin.permissions(),
            Self::Bundled(plugin) => plugin.permissions(),
            Self::External(plugin) => plugin.permissions(),
        }
    }

    fn resources(&self) -> &[PluginResourceManifest] {
        match self {
            Self::Builtin(plugin) => plugin.resources(),
            Self::Bundled(plugin) => plugin.resources(),
            Self::External(plugin) => plugin.resources(),
        }
    }

    fn prompts(&self) -> &[PluginPromptManifest] {
        match self {
            Self::Builtin(plugin) => plugin.prompts(),
            Self::Bundled(plugin) => plugin.prompts(),
            Self::External(plugin) => plugin.prompts(),
        }
    }

    fn capabilities(&self) -> &PluginCapabilities {
        match self {
            Self::Builtin(plugin) => plugin.capabilities(),
            Self::Bundled(plugin) => plugin.capabilities(),
            Self::External(plugin) => plugin.capabilities(),
        }
    }

    fn mcp_servers(&self) -> &BTreeMap<String, PluginMcpServerManifest> {
        match self {
            Self::Builtin(plugin) => plugin.mcp_servers(),
            Self::Bundled(plugin) => plugin.mcp_servers(),
            Self::External(plugin) => plugin.mcp_servers(),
        }
    }

    fn dependencies(&self) -> &[PluginDependency] {
        match self {
            Self::Builtin(plugin) => plugin.dependencies(),
            Self::Bundled(plugin) => plugin.dependencies(),
            Self::External(plugin) => plugin.dependencies(),
        }
    }

    fn rollback(&self) -> &PluginRollbackPlan {
        match self {
            Self::Builtin(plugin) => plugin.rollback(),
            Self::Bundled(plugin) => plugin.rollback(),
            Self::External(plugin) => plugin.rollback(),
        }
    }

    fn version_policy(&self) -> &PluginVersionPolicy {
        match self {
            Self::Builtin(plugin) => plugin.version_policy(),
            Self::Bundled(plugin) => plugin.version_policy(),
            Self::External(plugin) => plugin.version_policy(),
        }
    }

    fn ops_permissions(&self) -> &[PluginOpsPermission] {
        match self {
            Self::Builtin(plugin) => plugin.ops_permissions(),
            Self::Bundled(plugin) => plugin.ops_permissions(),
            Self::External(plugin) => plugin.ops_permissions(),
        }
    }

    fn validate(&self) -> Result<(), PluginError> {
        match self {
            Self::Builtin(plugin) => plugin.validate(),
            Self::Bundled(plugin) => plugin.validate(),
            Self::External(plugin) => plugin.validate(),
        }
    }

    fn initialize(&self) -> Result<(), PluginError> {
        match self {
            Self::Builtin(plugin) => plugin.initialize(),
            Self::Bundled(plugin) => plugin.initialize(),
            Self::External(plugin) => plugin.initialize(),
        }
    }

    fn shutdown(&self) -> Result<(), PluginError> {
        match self {
            Self::Builtin(plugin) => plugin.shutdown(),
            Self::Bundled(plugin) => plugin.shutdown(),
            Self::External(plugin) => plugin.shutdown(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RegisteredPlugin {
    definition: PluginDefinition,
    enabled: bool,
}

impl RegisteredPlugin {
    #[must_use]
    pub fn new(definition: PluginDefinition, enabled: bool) -> Self {
        Self {
            definition,
            enabled,
        }
    }

    #[must_use]
    pub fn metadata(&self) -> &PluginMetadata {
        self.definition.metadata()
    }

    #[must_use]
    pub fn hooks(&self) -> &PluginHooks {
        self.definition.hooks()
    }

    #[must_use]
    pub fn tools(&self) -> &[PluginTool] {
        self.definition.tools()
    }

    #[must_use]
    pub fn resources(&self) -> &[PluginResourceManifest] {
        self.definition.resources()
    }

    #[must_use]
    pub fn prompts(&self) -> &[PluginPromptManifest] {
        self.definition.prompts()
    }

    #[must_use]
    pub fn capabilities(&self) -> &PluginCapabilities {
        self.definition.capabilities()
    }

    #[must_use]
    pub fn mcp_servers(&self) -> &BTreeMap<String, PluginMcpServerManifest> {
        self.definition.mcp_servers()
    }

    #[must_use]
    pub fn dependencies(&self) -> &[PluginDependency] {
        self.definition.dependencies()
    }

    #[must_use]
    pub fn rollback(&self) -> &PluginRollbackPlan {
        self.definition.rollback()
    }

    #[must_use]
    pub fn version_policy(&self) -> &PluginVersionPolicy {
        self.definition.version_policy()
    }

    #[must_use]
    pub fn ops_permissions(&self) -> &[PluginOpsPermission] {
        self.definition.ops_permissions()
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn validate(&self) -> Result<(), PluginError> {
        self.definition.validate()
    }

    pub fn initialize(&self) -> Result<(), PluginError> {
        self.definition.initialize()
    }

    pub fn shutdown(&self) -> Result<(), PluginError> {
        self.definition.shutdown()
    }

    #[must_use]
    pub fn summary(&self) -> PluginSummary {
        PluginSummary {
            metadata: self.metadata().clone(),
            enabled: self.enabled,
            lifecycle: self.definition.lifecycle().clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSummary {
    pub metadata: PluginMetadata,
    pub enabled: bool,
    pub lifecycle: PluginLifecycle,
}

impl PluginSummary {
    #[must_use]
    pub fn lifecycle_state(&self) -> &'static str {
        if self.enabled {
            "ready"
        } else {
            "disabled"
        }
    }
}

#[derive(Debug)]
pub struct PluginLoadFailure {
    pub plugin_root: PathBuf,
    pub kind: PluginKind,
    pub source: String,
    error: Box<PluginError>,
}

impl PluginLoadFailure {
    #[must_use]
    pub fn new(plugin_root: PathBuf, kind: PluginKind, source: String, error: PluginError) -> Self {
        Self {
            plugin_root,
            kind,
            source,
            error: Box::new(error),
        }
    }

    #[must_use]
    pub fn error(&self) -> &PluginError {
        self.error.as_ref()
    }
}

impl Display for PluginLoadFailure {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "failed to load {} plugin from `{}` (source: {}): {}",
            self.kind,
            self.plugin_root.display(),
            self.source,
            self.error()
        )
    }
}

#[derive(Debug)]
pub struct PluginRegistryReport {
    registry: PluginRegistry,
    failures: Vec<PluginLoadFailure>,
}

impl PluginRegistryReport {
    #[must_use]
    pub fn new(registry: PluginRegistry, failures: Vec<PluginLoadFailure>) -> Self {
        Self { registry, failures }
    }

    #[must_use]
    pub fn registry(&self) -> &PluginRegistry {
        &self.registry
    }

    #[must_use]
    pub fn failures(&self) -> &[PluginLoadFailure] {
        &self.failures
    }

    #[must_use]
    pub fn has_failures(&self) -> bool {
        !self.failures.is_empty()
    }

    #[must_use]
    pub fn summaries(&self) -> Vec<PluginSummary> {
        self.registry.summaries()
    }

    pub fn into_registry(self) -> Result<PluginRegistry, PluginError> {
        if self.failures.is_empty() {
            Ok(self.registry)
        } else {
            Err(PluginError::LoadFailures(self.failures))
        }
    }
}

#[derive(Debug, Default)]
struct PluginDiscovery {
    plugins: Vec<PluginDefinition>,
    failures: Vec<PluginLoadFailure>,
}

impl PluginDiscovery {
    fn push_plugin(&mut self, plugin: PluginDefinition) {
        self.plugins.push(plugin);
    }

    fn push_failure(&mut self, failure: PluginLoadFailure) {
        self.failures.push(failure);
    }

    fn extend(&mut self, other: Self) {
        self.plugins.extend(other.plugins);
        self.failures.extend(other.failures);
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PluginRegistry {
    plugins: Vec<RegisteredPlugin>,
}

impl PluginRegistry {
    #[must_use]
    pub fn new(mut plugins: Vec<RegisteredPlugin>) -> Self {
        plugins.sort_by(|left, right| left.metadata().id.cmp(&right.metadata().id));
        Self { plugins }
    }

    #[must_use]
    pub fn plugins(&self) -> &[RegisteredPlugin] {
        &self.plugins
    }

    #[must_use]
    pub fn get(&self, plugin_id: &str) -> Option<&RegisteredPlugin> {
        self.plugins
            .iter()
            .find(|plugin| plugin.metadata().id == plugin_id)
    }

    #[must_use]
    pub fn contains(&self, plugin_id: &str) -> bool {
        self.get(plugin_id).is_some()
    }

    #[must_use]
    pub fn summaries(&self) -> Vec<PluginSummary> {
        self.plugins.iter().map(RegisteredPlugin::summary).collect()
    }

    pub fn aggregated_hooks(&self) -> Result<PluginHooks, PluginError> {
        self.dependency_order()?
            .into_iter()
            .try_fold(PluginHooks::default(), |acc, plugin_id| {
                let plugin = self.get(&plugin_id).ok_or_else(|| {
                    PluginError::InvalidManifest(format!(
                        "dependency order referenced missing plugin `{plugin_id}`"
                    ))
                })?;
                plugin.validate()?;
                Ok(acc.merged_with(plugin.hooks()))
            })
    }

    pub fn aggregated_tools(&self) -> Result<Vec<PluginTool>, PluginError> {
        let mut tools = Vec::new();
        let mut seen_names = BTreeMap::new();
        for plugin_id in self.dependency_order()? {
            let plugin = self.get(&plugin_id).ok_or_else(|| {
                PluginError::InvalidManifest(format!(
                    "dependency order referenced missing plugin `{plugin_id}`"
                ))
            })?;
            plugin.validate()?;
            for tool in plugin.tools() {
                if let Some(existing_plugin) =
                    seen_names.insert(tool.definition().name.clone(), tool.plugin_id().to_string())
                {
                    return Err(PluginError::InvalidManifest(format!(
                        "plugin tool `{}` is defined by both `{existing_plugin}` and `{}`",
                        tool.definition().name,
                        tool.plugin_id()
                    )));
                }
                tools.push(tool.clone());
            }
        }
        Ok(tools)
    }

    pub fn aggregated_resources(&self) -> Result<Vec<PluginResourceManifest>, PluginError> {
        let mut resources = Vec::new();
        let mut seen_uris = BTreeMap::new();
        for plugin_id in self.dependency_order()? {
            let plugin = self.get(&plugin_id).ok_or_else(|| {
                PluginError::InvalidManifest(format!(
                    "dependency order referenced missing plugin `{plugin_id}`"
                ))
            })?;
            plugin.validate()?;
            for resource in plugin.resources() {
                if let Some(existing_plugin) =
                    seen_uris.insert(resource.uri.clone(), plugin.metadata().id.clone())
                {
                    return Err(PluginError::InvalidManifest(format!(
                        "plugin resource `{}` is defined by both `{existing_plugin}` and `{}`",
                        resource.uri,
                        plugin.metadata().id
                    )));
                }
                resources.push(resource.clone());
            }
        }
        Ok(resources)
    }

    pub fn aggregated_prompts(&self) -> Result<Vec<PluginPromptManifest>, PluginError> {
        let mut prompts = Vec::new();
        let mut seen_names = BTreeMap::new();
        for plugin_id in self.dependency_order()? {
            let plugin = self.get(&plugin_id).ok_or_else(|| {
                PluginError::InvalidManifest(format!(
                    "dependency order referenced missing plugin `{plugin_id}`"
                ))
            })?;
            plugin.validate()?;
            for prompt in plugin.prompts() {
                if let Some(existing_plugin) =
                    seen_names.insert(prompt.name.clone(), plugin.metadata().id.clone())
                {
                    return Err(PluginError::InvalidManifest(format!(
                        "plugin prompt `{}` is defined by both `{existing_plugin}` and `{}`",
                        prompt.name,
                        plugin.metadata().id
                    )));
                }
                prompts.push(prompt.clone());
            }
        }
        Ok(prompts)
    }

    pub fn aggregated_mcp_servers(
        &self,
    ) -> Result<BTreeMap<String, PluginMcpServerManifest>, PluginError> {
        let mut servers = BTreeMap::new();
        for plugin_id in self.dependency_order()? {
            let plugin = self.get(&plugin_id).ok_or_else(|| {
                PluginError::InvalidManifest(format!(
                    "dependency order referenced missing plugin `{plugin_id}`"
                ))
            })?;
            plugin.validate()?;
            for (server_name, server) in plugin.mcp_servers() {
                let qualified_name = format!("{}::{server_name}", plugin.metadata().id);
                if servers
                    .insert(qualified_name.clone(), server.clone())
                    .is_some()
                {
                    return Err(PluginError::InvalidManifest(format!(
                        "plugin MCP server `{qualified_name}` is duplicated"
                    )));
                }
            }
        }
        Ok(servers)
    }

    pub fn dependency_order(&self) -> Result<Vec<String>, PluginError> {
        dependency_order_for_plugins(&self.plugins)
    }

    pub fn initialize(&self) -> Result<(), PluginError> {
        let order = self.dependency_order()?;
        for plugin_id in order {
            let plugin = self.get(&plugin_id).ok_or_else(|| {
                PluginError::InvalidManifest(format!(
                    "dependency order referenced missing plugin `{plugin_id}`"
                ))
            })?;
            plugin.validate()?;
            plugin.initialize()?;
        }
        Ok(())
    }

    pub fn shutdown(&self) -> Result<(), PluginError> {
        let mut order = self.dependency_order()?;
        order.reverse();
        for plugin_id in order {
            let plugin = self.get(&plugin_id).ok_or_else(|| {
                PluginError::InvalidManifest(format!(
                    "dependency order referenced missing plugin `{plugin_id}`"
                ))
            })?;
            plugin.shutdown()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManagerConfig {
    pub config_home: PathBuf,
    pub enabled_plugins: BTreeMap<String, bool>,
    pub external_dirs: Vec<PathBuf>,
    pub install_root: Option<PathBuf>,
    pub registry_path: Option<PathBuf>,
    pub bundled_root: Option<PathBuf>,
}

impl PluginManagerConfig {
    #[must_use]
    pub fn new(config_home: impl Into<PathBuf>) -> Self {
        Self {
            config_home: config_home.into(),
            enabled_plugins: BTreeMap::new(),
            external_dirs: Vec::new(),
            install_root: None,
            registry_path: None,
            bundled_root: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManager {
    config: PluginManagerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOutcome {
    pub plugin_id: String,
    pub version: String,
    pub install_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateOutcome {
    pub plugin_id: String,
    pub old_version: String,
    pub new_version: String,
    pub install_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackOutcome {
    pub plugin_id: String,
    pub previous_version: String,
    pub active_version: String,
    pub install_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginManifestValidationError {
    EmptyField {
        field: &'static str,
    },
    EmptyEntryField {
        kind: &'static str,
        field: &'static str,
        name: Option<String>,
    },
    InvalidPermission {
        permission: String,
    },
    DuplicatePermission {
        permission: String,
    },
    DuplicateEntry {
        kind: &'static str,
        name: String,
    },
    MissingPath {
        kind: &'static str,
        path: PathBuf,
    },
    PathIsDirectory {
        kind: &'static str,
        path: PathBuf,
    },
    InvalidToolInputSchema {
        tool_name: String,
    },
    InvalidToolRequiredPermission {
        tool_name: String,
        permission: String,
    },
    MissingDeclaredPermission {
        tool_name: String,
        required_permission: PluginToolPermission,
    },
    InvalidJsonSchema {
        kind: &'static str,
        name: String,
    },
    InvalidMcpServerConfig {
        server_name: String,
        detail: String,
    },
    MissingRollbackForHighRisk {
        scope: String,
    },
    UnsupportedManifestContract {
        detail: String,
    },
}

impl Display for PluginManifestValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField { field } => {
                write!(f, "plugin manifest {field} cannot be empty")
            }
            Self::EmptyEntryField { kind, field, name } => match name {
                Some(name) if !name.is_empty() => {
                    write!(f, "plugin {kind} `{name}` {field} cannot be empty")
                }
                _ => write!(f, "plugin {kind} {field} cannot be empty"),
            },
            Self::InvalidPermission { permission } => {
                write!(
                    f,
                    "plugin manifest permission `{permission}` must be one of read, write, or execute"
                )
            }
            Self::DuplicatePermission { permission } => {
                write!(f, "plugin manifest permission `{permission}` is duplicated")
            }
            Self::DuplicateEntry { kind, name } => {
                write!(f, "plugin {kind} `{name}` is duplicated")
            }
            Self::MissingPath { kind, path } => {
                write!(f, "{kind} path `{}` does not exist", path.display())
            }
            Self::PathIsDirectory { kind, path } => {
                write!(f, "{kind} path `{}` must point to a file", path.display())
            }
            Self::InvalidToolInputSchema { tool_name } => {
                write!(
                    f,
                    "plugin tool `{tool_name}` inputSchema must be a JSON object"
                )
            }
            Self::InvalidToolRequiredPermission {
                tool_name,
                permission,
            } => write!(
                f,
                "plugin tool `{tool_name}` requiredPermission `{permission}` must be read-only, workspace-write, or danger-full-access"
            ),
            Self::MissingDeclaredPermission {
                tool_name,
                required_permission,
            } => write!(
                f,
                "plugin tool `{tool_name}` requires `{}` but the plugin permissions list does not declare `{}`",
                required_permission.as_str(),
                manifest_permission_for_tool(*required_permission).as_str()
            ),
            Self::InvalidJsonSchema { kind, name } => {
                write!(f, "plugin {kind} `{name}` schema must be a JSON object")
            }
            Self::InvalidMcpServerConfig {
                server_name,
                detail,
            } => write!(f, "plugin MCP server `{server_name}` is invalid: {detail}"),
            Self::MissingRollbackForHighRisk { scope } => write!(
                f,
                "high-risk ops permission `{scope}` must declare rollbackRequired or a rollback command"
            ),
            Self::UnsupportedManifestContract { detail } => f.write_str(detail),
        }
    }
}

#[derive(Debug)]
pub enum PluginError {
    Io(std::io::Error),
    Json(serde_json::Error),
    ManifestValidation(Vec<PluginManifestValidationError>),
    LoadFailures(Vec<PluginLoadFailure>),
    InvalidManifest(String),
    NotFound(String),
    CommandFailed(String),
}

impl Display for PluginError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Json(error) => write!(f, "{error}"),
            Self::ManifestValidation(errors) => {
                for (index, error) in errors.iter().enumerate() {
                    if index > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{error}")?;
                }
                Ok(())
            }
            Self::LoadFailures(failures) => {
                for (index, failure) in failures.iter().enumerate() {
                    if index > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{failure}")?;
                }
                Ok(())
            }
            Self::InvalidManifest(message)
            | Self::NotFound(message)
            | Self::CommandFailed(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for PluginError {}

impl From<std::io::Error> for PluginError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for PluginError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl PluginManager {
    #[must_use]
    pub fn new(config: PluginManagerConfig) -> Self {
        Self { config }
    }

    /// Returns the default bundled plugins root directory.
    ///
    /// Resolution order (first existing path wins):
    /// 1. `<exe_dir>/../share/claw/plugins/bundled` — standard install layout
    /// 2. `<exe_dir>/bundled` — simple relocated layout
    /// 3. `CARGO_MANIFEST_DIR/bundled` — dev/source-tree fallback (only if it exists)
    /// 4. `<exe_dir>/../share/claw/plugins/bundled` — canonical default even if missing
    ///
    /// This avoids baking in a compile-time source-tree path that may be
    /// inaccessible at runtime (e.g. a root-owned repo directory).
    #[must_use]
    pub fn bundled_root() -> PathBuf {
        // Candidate 1: standard FHS install layout — <prefix>/bin/claw -> <prefix>/share/claw/plugins/bundled
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                let share_path = exe_dir
                    .join("..")
                    .join("share")
                    .join("claw")
                    .join("plugins")
                    .join("bundled");
                if share_path.exists() {
                    return share_path;
                }

                // Candidate 2: simple adjacent layout — <exe_dir>/bundled
                let adjacent = exe_dir.join("bundled");
                if adjacent.exists() {
                    return adjacent;
                }
            }
        }

        // Candidate 3: dev/source-tree fallback — only if the directory actually exists
        let dev_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundled");
        if dev_path.exists() {
            return dev_path;
        }

        // Default (nothing found): return the canonical install path even if missing,
        // so callers get an empty plugin list rather than a permission error.
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                return exe_dir
                    .join("..")
                    .join("share")
                    .join("claw")
                    .join("plugins")
                    .join("bundled");
            }
        }

        // Last resort fallback
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundled")
    }

    #[must_use]
    pub fn install_root(&self) -> PathBuf {
        self.config
            .install_root
            .clone()
            .unwrap_or_else(|| self.config.config_home.join("plugins").join("installed"))
    }

    #[must_use]
    pub fn registry_path(&self) -> PathBuf {
        self.config.registry_path.clone().unwrap_or_else(|| {
            self.config
                .config_home
                .join("plugins")
                .join(REGISTRY_FILE_NAME)
        })
    }

    #[must_use]
    pub fn settings_path(&self) -> PathBuf {
        self.config.config_home.join(SETTINGS_FILE_NAME)
    }

    pub fn plugin_registry(&self) -> Result<PluginRegistry, PluginError> {
        self.plugin_registry_report()?.into_registry()
    }

    pub fn plugin_registry_report(&self) -> Result<PluginRegistryReport, PluginError> {
        self.sync_bundled_plugins()?;

        let mut discovery = PluginDiscovery::default();
        discovery.plugins.extend(builtin_plugins());

        let installed = self.discover_installed_plugins_with_failures()?;
        discovery.extend(installed);

        let external =
            self.discover_external_directory_plugins_with_failures(&discovery.plugins)?;
        discovery.extend(external);

        Ok(self.build_registry_report(discovery))
    }

    pub fn list_plugins(&self) -> Result<Vec<PluginSummary>, PluginError> {
        Ok(self.plugin_registry()?.summaries())
    }

    pub fn list_installed_plugins(&self) -> Result<Vec<PluginSummary>, PluginError> {
        Ok(self.installed_plugin_registry()?.summaries())
    }

    pub fn discover_plugins(&self) -> Result<Vec<PluginDefinition>, PluginError> {
        Ok(self
            .plugin_registry()?
            .plugins
            .into_iter()
            .map(|plugin| plugin.definition)
            .collect())
    }

    pub fn aggregated_hooks(&self) -> Result<PluginHooks, PluginError> {
        self.plugin_registry()?.aggregated_hooks()
    }

    pub fn aggregated_tools(&self) -> Result<Vec<PluginTool>, PluginError> {
        self.plugin_registry()?.aggregated_tools()
    }

    pub fn aggregated_resources(&self) -> Result<Vec<PluginResourceManifest>, PluginError> {
        self.plugin_registry()?.aggregated_resources()
    }

    pub fn aggregated_prompts(&self) -> Result<Vec<PluginPromptManifest>, PluginError> {
        self.plugin_registry()?.aggregated_prompts()
    }

    pub fn aggregated_mcp_servers(
        &self,
    ) -> Result<BTreeMap<String, PluginMcpServerManifest>, PluginError> {
        self.plugin_registry()?.aggregated_mcp_servers()
    }

    pub fn validate_plugin_source(&self, source: &str) -> Result<PluginManifest, PluginError> {
        let path = resolve_local_source(source)?;
        load_plugin_from_directory(&path)
    }

    pub fn hot_load(&mut self, source: &str) -> Result<InstallOutcome, PluginError> {
        self.install(source)
    }

    pub fn hot_unload(&mut self, plugin_id: &str) -> Result<(), PluginError> {
        self.disable(plugin_id)
    }

    pub fn install(&mut self, source: &str) -> Result<InstallOutcome, PluginError> {
        let install_source = parse_install_source(source)?;
        let temp_root = self.install_root().join(".tmp");
        let staged_source = materialize_source(&install_source, &temp_root)?;
        let cleanup_source = matches!(install_source, PluginInstallSource::GitUrl { .. });
        let manifest = load_plugin_from_directory(&staged_source)?;

        let plugin_id = plugin_id(&manifest.name, EXTERNAL_MARKETPLACE);
        let install_path = self.install_root().join(sanitize_plugin_id(&plugin_id));
        let mut registry = self.load_registry()?;
        if let Some(existing_record) = registry.plugins.get(&plugin_id).cloned() {
            self.archive_installed_version(
                &mut registry,
                &existing_record,
                manifest.version_policy.keep_versions,
            )?;
        }
        if install_path.exists() {
            fs::remove_dir_all(&install_path)?;
        }
        copy_dir_all(&staged_source, &install_path)?;
        if cleanup_source {
            let _ = fs::remove_dir_all(&staged_source);
        }

        let now = unix_time_ms();
        let record = InstalledPluginRecord {
            kind: PluginKind::External,
            id: plugin_id.clone(),
            name: manifest.name,
            version: manifest.version.clone(),
            description: manifest.description,
            install_path: install_path.clone(),
            source: install_source,
            version_policy: manifest.version_policy,
            installed_at_unix_ms: now,
            updated_at_unix_ms: now,
        };

        registry.plugins.insert(plugin_id.clone(), record);
        self.store_registry(&registry)?;
        self.write_enabled_state(&plugin_id, Some(true))?;
        self.config.enabled_plugins.insert(plugin_id.clone(), true);

        Ok(InstallOutcome {
            plugin_id,
            version: manifest.version,
            install_path,
        })
    }

    pub fn enable(&mut self, plugin_id: &str) -> Result<(), PluginError> {
        self.ensure_known_plugin(plugin_id)?;
        self.write_enabled_state(plugin_id, Some(true))?;
        self.config
            .enabled_plugins
            .insert(plugin_id.to_string(), true);
        Ok(())
    }

    pub fn disable(&mut self, plugin_id: &str) -> Result<(), PluginError> {
        self.ensure_known_plugin(plugin_id)?;
        self.write_enabled_state(plugin_id, Some(false))?;
        self.config
            .enabled_plugins
            .insert(plugin_id.to_string(), false);
        Ok(())
    }

    pub fn uninstall(&mut self, plugin_id: &str) -> Result<(), PluginError> {
        let mut registry = self.load_registry()?;
        let record = registry.plugins.remove(plugin_id).ok_or_else(|| {
            PluginError::NotFound(format!("plugin `{plugin_id}` is not installed"))
        })?;
        if record.kind == PluginKind::Bundled {
            registry.plugins.insert(plugin_id.to_string(), record);
            return Err(PluginError::CommandFailed(format!(
                "plugin `{plugin_id}` is bundled and managed automatically; disable it instead"
            )));
        }
        if record.install_path.exists() {
            fs::remove_dir_all(&record.install_path)?;
        }
        if let Some(versions) = registry.versions.remove(plugin_id) {
            for version in versions {
                if version.install_path.exists() {
                    fs::remove_dir_all(version.install_path)?;
                }
            }
        }
        self.store_registry(&registry)?;
        self.write_enabled_state(plugin_id, None)?;
        self.config.enabled_plugins.remove(plugin_id);
        Ok(())
    }

    pub fn update(&mut self, plugin_id: &str) -> Result<UpdateOutcome, PluginError> {
        let mut registry = self.load_registry()?;
        let record = registry.plugins.get(plugin_id).cloned().ok_or_else(|| {
            PluginError::NotFound(format!("plugin `{plugin_id}` is not installed"))
        })?;

        let temp_root = self.install_root().join(".tmp");
        let staged_source = materialize_source(&record.source, &temp_root)?;
        let cleanup_source = matches!(record.source, PluginInstallSource::GitUrl { .. });
        let manifest = load_plugin_from_directory(&staged_source)?;

        let archived_record = self.archive_installed_version(
            &mut registry,
            &record,
            manifest.version_policy.keep_versions,
        )?;
        let replace_result = (|| -> Result<(), PluginError> {
            if record.install_path.exists() {
                fs::remove_dir_all(&record.install_path)?;
            }
            copy_dir_all(&staged_source, &record.install_path)?;
            Ok(())
        })();
        if let Err(error) = replace_result {
            if manifest.version_policy.rollback_on_failure {
                if let Some(archived_record) = archived_record {
                    self.restore_archived_version(&record, &archived_record)?;
                }
            }
            return Err(error);
        }
        if cleanup_source {
            let _ = fs::remove_dir_all(&staged_source);
        }

        let updated_record = InstalledPluginRecord {
            version: manifest.version.clone(),
            description: manifest.description,
            version_policy: manifest.version_policy,
            updated_at_unix_ms: unix_time_ms(),
            ..record.clone()
        };
        registry
            .plugins
            .insert(plugin_id.to_string(), updated_record);
        self.store_registry(&registry)?;

        Ok(UpdateOutcome {
            plugin_id: plugin_id.to_string(),
            old_version: record.version,
            new_version: manifest.version,
            install_path: record.install_path,
        })
    }

    pub fn list_versions(&self, plugin_id: &str) -> Result<Vec<String>, PluginError> {
        let registry = self.load_registry()?;
        let mut versions = registry
            .versions
            .get(plugin_id)
            .into_iter()
            .flatten()
            .map(|record| record.version.clone())
            .collect::<BTreeSet<_>>();
        if let Some(record) = registry.plugins.get(plugin_id) {
            versions.insert(record.version.clone());
        }
        if versions.is_empty() {
            return Err(PluginError::NotFound(format!(
                "plugin `{plugin_id}` is not installed"
            )));
        }
        Ok(versions.into_iter().collect())
    }

    pub fn rollback(
        &mut self,
        plugin_id: &str,
        version: &str,
    ) -> Result<RollbackOutcome, PluginError> {
        let mut registry = self.load_registry()?;
        let active = registry.plugins.get(plugin_id).cloned().ok_or_else(|| {
            PluginError::NotFound(format!("plugin `{plugin_id}` is not installed"))
        })?;
        let archived = registry
            .versions
            .get(plugin_id)
            .and_then(|records| records.iter().find(|record| record.version == version))
            .cloned()
            .ok_or_else(|| {
                PluginError::NotFound(format!(
                    "plugin `{plugin_id}` has no archived version `{version}`"
                ))
            })?;

        self.archive_installed_version(
            &mut registry,
            &active,
            active.version_policy.keep_versions,
        )?;
        if active.install_path.exists() {
            fs::remove_dir_all(&active.install_path)?;
        }
        copy_dir_all(&archived.install_path, &active.install_path)?;
        let manifest = load_plugin_from_directory(&active.install_path)?;
        let rolled_back = InstalledPluginRecord {
            version: manifest.version.clone(),
            description: manifest.description,
            version_policy: manifest.version_policy,
            updated_at_unix_ms: unix_time_ms(),
            ..active.clone()
        };
        registry.plugins.insert(plugin_id.to_string(), rolled_back);
        self.store_registry(&registry)?;

        Ok(RollbackOutcome {
            plugin_id: plugin_id.to_string(),
            previous_version: active.version,
            active_version: manifest.version,
            install_path: active.install_path,
        })
    }

    fn discover_installed_plugins_with_failures(&self) -> Result<PluginDiscovery, PluginError> {
        let mut registry = self.load_registry()?;
        let mut discovery = PluginDiscovery::default();
        let mut seen_ids = BTreeSet::<String>::new();
        let mut seen_paths = BTreeSet::<PathBuf>::new();
        let mut stale_registry_ids = Vec::new();

        for install_path in discover_plugin_dirs(&self.install_root())? {
            let matched_record = registry
                .plugins
                .values()
                .find(|record| record.install_path == install_path);
            let kind = matched_record.map_or(PluginKind::External, |record| record.kind);
            let source = matched_record.map_or_else(
                || install_path.display().to_string(),
                |record| describe_install_source(&record.source),
            );
            match load_plugin_definition(&install_path, kind, source.clone(), kind.marketplace()) {
                Ok(plugin) => {
                    if seen_ids.insert(plugin.metadata().id.clone()) {
                        seen_paths.insert(install_path);
                        discovery.push_plugin(plugin);
                    }
                }
                Err(error) => {
                    discovery.push_failure(PluginLoadFailure::new(
                        install_path,
                        kind,
                        source,
                        error,
                    ));
                }
            }
        }

        for record in registry.plugins.values() {
            if seen_paths.contains(&record.install_path) {
                continue;
            }
            if !record.install_path.exists() || plugin_manifest_path(&record.install_path).is_err()
            {
                stale_registry_ids.push(record.id.clone());
                continue;
            }
            let source = describe_install_source(&record.source);
            match load_plugin_definition(
                &record.install_path,
                record.kind,
                source.clone(),
                record.kind.marketplace(),
            ) {
                Ok(plugin) => {
                    if seen_ids.insert(plugin.metadata().id.clone()) {
                        seen_paths.insert(record.install_path.clone());
                        discovery.push_plugin(plugin);
                    }
                }
                Err(error) => {
                    discovery.push_failure(PluginLoadFailure::new(
                        record.install_path.clone(),
                        record.kind,
                        source,
                        error,
                    ));
                }
            }
        }

        if !stale_registry_ids.is_empty() {
            for plugin_id in stale_registry_ids {
                registry.plugins.remove(&plugin_id);
            }
            self.store_registry(&registry)?;
        }

        Ok(discovery)
    }

    fn discover_external_directory_plugins_with_failures(
        &self,
        existing_plugins: &[PluginDefinition],
    ) -> Result<PluginDiscovery, PluginError> {
        let mut discovery = PluginDiscovery::default();

        for directory in &self.config.external_dirs {
            for root in discover_plugin_dirs(directory)? {
                let source = root.display().to_string();
                match load_plugin_definition(
                    &root,
                    PluginKind::External,
                    source.clone(),
                    EXTERNAL_MARKETPLACE,
                ) {
                    Ok(plugin) => {
                        if existing_plugins
                            .iter()
                            .chain(discovery.plugins.iter())
                            .all(|existing| existing.metadata().id != plugin.metadata().id)
                        {
                            discovery.push_plugin(plugin);
                        }
                    }
                    Err(error) => {
                        discovery.push_failure(PluginLoadFailure::new(
                            root,
                            PluginKind::External,
                            source,
                            error,
                        ));
                    }
                }
            }
        }

        Ok(discovery)
    }

    pub fn installed_plugin_registry_report(&self) -> Result<PluginRegistryReport, PluginError> {
        self.sync_bundled_plugins()?;
        Ok(self.build_registry_report(self.discover_installed_plugins_with_failures()?))
    }

    fn sync_bundled_plugins(&self) -> Result<(), PluginError> {
        let explicit_root = self.config.bundled_root.is_some();
        let bundled_root = self
            .config
            .bundled_root
            .clone()
            .unwrap_or_else(Self::bundled_root);
        let bundled_plugins = match discover_plugin_dirs(&bundled_root) {
            Ok(plugins) => plugins,
            // When the bundled root is the auto-detected default and the directory is
            // inaccessible (e.g. a root-owned source tree), treat it as empty rather
            // than fatally failing.  An explicit config override still surfaces errors.
            Err(PluginError::Io(ref error))
                if !explicit_root && error.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                Vec::new()
            }
            Err(error) => return Err(error),
        };
        let mut registry = self.load_registry()?;
        let mut changed = false;
        let install_root = self.install_root();
        let mut active_bundled_ids = BTreeSet::new();

        for source_root in bundled_plugins {
            let manifest = load_plugin_from_directory(&source_root)?;
            let plugin_id = plugin_id(&manifest.name, BUNDLED_MARKETPLACE);
            active_bundled_ids.insert(plugin_id.clone());
            let install_path = install_root.join(sanitize_plugin_id(&plugin_id));
            let now = unix_time_ms();
            let existing_record = registry.plugins.get(&plugin_id);
            let installed_copy_is_valid =
                install_path.exists() && load_plugin_from_directory(&install_path).is_ok();
            let needs_sync = existing_record.is_none_or(|record| {
                record.kind != PluginKind::Bundled
                    || record.version != manifest.version
                    || record.name != manifest.name
                    || record.description != manifest.description
                    || record.install_path != install_path
                    || !record.install_path.exists()
                    || !installed_copy_is_valid
            });

            if !needs_sync {
                continue;
            }

            if install_path.exists() {
                fs::remove_dir_all(&install_path)?;
            }
            copy_dir_all(&source_root, &install_path)?;

            let installed_at_unix_ms =
                existing_record.map_or(now, |record| record.installed_at_unix_ms);
            registry.plugins.insert(
                plugin_id.clone(),
                InstalledPluginRecord {
                    kind: PluginKind::Bundled,
                    id: plugin_id,
                    name: manifest.name,
                    version: manifest.version,
                    description: manifest.description,
                    install_path,
                    source: PluginInstallSource::LocalPath { path: source_root },
                    version_policy: manifest.version_policy,
                    installed_at_unix_ms,
                    updated_at_unix_ms: now,
                },
            );
            changed = true;
        }

        let stale_bundled_ids = registry
            .plugins
            .iter()
            .filter_map(|(plugin_id, record)| {
                (record.kind == PluginKind::Bundled && !active_bundled_ids.contains(plugin_id))
                    .then_some(plugin_id.clone())
            })
            .collect::<Vec<_>>();

        for plugin_id in stale_bundled_ids {
            if let Some(record) = registry.plugins.remove(&plugin_id) {
                if record.install_path.exists() {
                    fs::remove_dir_all(&record.install_path)?;
                }
                changed = true;
            }
        }

        if changed {
            self.store_registry(&registry)?;
        }

        Ok(())
    }

    fn is_enabled(&self, metadata: &PluginMetadata) -> bool {
        self.config
            .enabled_plugins
            .get(&metadata.id)
            .copied()
            .unwrap_or(match metadata.kind {
                PluginKind::External => false,
                PluginKind::Builtin | PluginKind::Bundled => metadata.default_enabled,
            })
    }

    fn ensure_known_plugin(&self, plugin_id: &str) -> Result<(), PluginError> {
        if self.plugin_registry()?.contains(plugin_id) {
            Ok(())
        } else {
            Err(PluginError::NotFound(format!(
                "plugin `{plugin_id}` is not installed or discoverable"
            )))
        }
    }

    fn load_registry(&self) -> Result<InstalledPluginRegistry, PluginError> {
        let path = self.registry_path();
        match fs::read_to_string(&path) {
            Ok(contents) if contents.trim().is_empty() => Ok(InstalledPluginRegistry::default()),
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(InstalledPluginRegistry::default())
            }
            Err(error) => Err(PluginError::Io(error)),
        }
    }

    fn store_registry(&self, registry: &InstalledPluginRegistry) -> Result<(), PluginError> {
        let path = self.registry_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(registry)?)?;
        Ok(())
    }

    fn archive_installed_version(
        &self,
        registry: &mut InstalledPluginRegistry,
        record: &InstalledPluginRecord,
        keep_versions: usize,
    ) -> Result<Option<InstalledPluginVersionRecord>, PluginError> {
        if !record.install_path.exists() {
            return Ok(None);
        }

        let archive_path = self
            .install_root()
            .join(".versions")
            .join(sanitize_plugin_id(&record.id))
            .join(sanitize_plugin_id(&record.version));
        if archive_path.exists() {
            fs::remove_dir_all(&archive_path)?;
        }
        copy_dir_all(&record.install_path, &archive_path)?;

        let versions = registry.versions.entry(record.id.clone()).or_default();
        versions.retain(|archived| archived.version != record.version);
        let archived_record = InstalledPluginVersionRecord {
            version: record.version.clone(),
            description: record.description.clone(),
            install_path: archive_path,
            archived_at_unix_ms: unix_time_ms(),
        };
        versions.push(archived_record.clone());
        prune_archived_versions(versions, keep_versions);
        Ok(Some(archived_record))
    }

    fn restore_archived_version(
        &self,
        record: &InstalledPluginRecord,
        archived: &InstalledPluginVersionRecord,
    ) -> Result<(), PluginError> {
        if record.install_path.exists() {
            fs::remove_dir_all(&record.install_path)?;
        }
        copy_dir_all(&archived.install_path, &record.install_path)
    }

    fn write_enabled_state(
        &self,
        plugin_id: &str,
        enabled: Option<bool>,
    ) -> Result<(), PluginError> {
        update_settings_json(&self.settings_path(), |root| {
            let enabled_plugins = ensure_object(root, "enabledPlugins");
            match enabled {
                Some(value) => {
                    enabled_plugins.insert(plugin_id.to_string(), Value::Bool(value));
                }
                None => {
                    enabled_plugins.remove(plugin_id);
                }
            }
        })
    }

    fn installed_plugin_registry(&self) -> Result<PluginRegistry, PluginError> {
        self.installed_plugin_registry_report()?.into_registry()
    }

    fn build_registry_report(&self, discovery: PluginDiscovery) -> PluginRegistryReport {
        PluginRegistryReport::new(
            PluginRegistry::new(
                discovery
                    .plugins
                    .into_iter()
                    .map(|plugin| {
                        let enabled = self.is_enabled(plugin.metadata());
                        RegisteredPlugin::new(plugin, enabled)
                    })
                    .collect(),
            ),
            discovery.failures,
        )
    }
}

#[must_use]
pub fn builtin_plugins() -> Vec<PluginDefinition> {
    let mut plugins = vec![builtin_plugin_from_manifest(PluginManifest {
        name: "example-builtin".to_string(),
        version: "0.1.0".to_string(),
        description: "Example built-in plugin scaffold for the Rust plugin system".to_string(),
        permissions: Vec::new(),
        default_enabled: false,
        hooks: PluginHooks::default(),
        lifecycle: PluginLifecycle::default(),
        execution_policy: PluginExecutionPolicy::default(),
        tools: Vec::new(),
        commands: Vec::new(),
        capabilities: PluginCapabilities::default(),
        mcp_servers: BTreeMap::new(),
        dependencies: Vec::new(),
        rollback: PluginRollbackPlan::default(),
        version_policy: PluginVersionPolicy::default(),
        ops_permissions: Vec::new(),
        resources: Vec::new(),
        prompts: Vec::new(),
    })];
    plugins.extend(
        builtin_ops_manifests()
            .into_iter()
            .map(builtin_plugin_from_manifest),
    );
    plugins
}

#[must_use]
pub fn builtin_ops_manifests() -> Vec<PluginManifest> {
    [
        (
            "disk_cleaner",
            "Disk cleanup planning and dry-run reporting.",
            "ops_disk_cleaner",
            PluginToolPermission::WorkspaceWrite,
            PluginRiskLevel::High,
        ),
        (
            "service_manager",
            "Service status, start, stop, and restart orchestration.",
            "ops_service_manager",
            PluginToolPermission::DangerFullAccess,
            PluginRiskLevel::High,
        ),
        (
            "user_manager",
            "User and group management planning.",
            "ops_user_manager",
            PluginToolPermission::DangerFullAccess,
            PluginRiskLevel::Critical,
        ),
        (
            "log_analyzer",
            "Read-only operational log analysis.",
            "ops_log_analyzer",
            PluginToolPermission::ReadOnly,
            PluginRiskLevel::Low,
        ),
        (
            "package_manager",
            "Package install, remove, and update planning.",
            "ops_package_manager",
            PluginToolPermission::DangerFullAccess,
            PluginRiskLevel::High,
        ),
        (
            "firewall_manager",
            "Firewall rule inspection and change planning.",
            "ops_firewall_manager",
            PluginToolPermission::DangerFullAccess,
            PluginRiskLevel::Critical,
        ),
        (
            "cron_manager",
            "Cron and scheduled task management planning.",
            "ops_cron_manager",
            PluginToolPermission::WorkspaceWrite,
            PluginRiskLevel::High,
        ),
        (
            "network_diagnostics",
            "Read-only network diagnostics.",
            "ops_network_diagnostics",
            PluginToolPermission::ReadOnly,
            PluginRiskLevel::Low,
        ),
        (
            "backup_manager",
            "Backup and restore workflow planning.",
            "ops_backup_manager",
            PluginToolPermission::DangerFullAccess,
            PluginRiskLevel::High,
        ),
    ]
    .into_iter()
    .map(|(name, description, tool_name, permission, risk)| {
        let high_risk = matches!(risk, PluginRiskLevel::High | PluginRiskLevel::Critical);
        PluginManifest {
            name: name.to_string(),
            version: "0.1.0".to_string(),
            description: description.to_string(),
            permissions: vec![manifest_permission_for_tool(permission)],
            default_enabled: false,
            hooks: PluginHooks::default(),
            lifecycle: PluginLifecycle::default(),
            execution_policy: PluginExecutionPolicy::default(),
            tools: vec![PluginToolManifest {
                name: tool_name.to_string(),
                description: format!("{description} Uses fixed Kylin/Linux executables without a shell; dry-run returns validated argv and mutations require confirmation plus a rollback checkpoint."),
                input_schema: builtin_ops_input_schema(name),
                output_schema: Some(serde_json::json!({
                    "type": "object",
                    "required": ["status", "plugin", "tool", "audit", "plan", "rollback"],
                    "properties": {
                        "status": { "type": "string" },
                        "plugin": { "type": "string" },
                        "tool": { "type": "string" },
                        "mode": { "type": "string" },
                        "audit": { "type": "object" },
                        "plan": { "type": "array" },
                        "rollback": { "type": "object" }
                    },
                    "additionalProperties": true
                })),
                command: BUILTIN_OPS_EXECUTOR_COMMAND.to_string(),
                args: Vec::new(),
                required_permission: permission,
            }],
            commands: Vec::new(),
            capabilities: PluginCapabilities {
                tools: true,
                resources: false,
                prompts: false,
                workflows: true,
                hot_reload: true,
            },
            mcp_servers: BTreeMap::new(),
            dependencies: Vec::new(),
            rollback: if high_risk {
                PluginRollbackPlan {
                    strategy: PluginRollbackStrategy::Manual,
                    commands: vec!["restore from captured pre-change checkpoint".to_string()],
                    notes: Some("Mutations are restricted to fixed argv and require a persisted checkpoint before execution.".to_string()),
                }
            } else {
                PluginRollbackPlan::default()
            },
            version_policy: PluginVersionPolicy::default(),
            ops_permissions: vec![PluginOpsPermission {
                permission,
                scope: format!("ops.{name}"),
                risk,
                reason: "Built-in operations plugin capability declaration.".to_string(),
                rollback_required: high_risk,
                rollback_command: high_risk
                    .then(|| "restore from captured pre-change checkpoint".to_string()),
            }],
            resources: Vec::new(),
            prompts: Vec::new(),
        }
    })
    .collect()
}

fn builtin_ops_input_schema(plugin: &str) -> Value {
    let actions = match plugin {
        "disk_cleaner" | "log_analyzer" | "firewall_manager" => {
            vec!["inspect", "plan"]
        }
        "service_manager" => vec!["inspect", "plan", "start", "stop", "restart", "rollback"],
        "user_manager" => vec!["inspect", "plan", "lock", "unlock", "rollback"],
        "package_manager" => vec!["inspect", "plan", "install", "remove", "rollback"],
        "cron_manager" => vec![
            "inspect", "plan", "enable", "disable", "start", "stop", "restart", "rollback",
        ],
        "network_diagnostics" => vec!["inspect", "plan", "dns", "ping"],
        "backup_manager" => vec!["inspect", "plan", "backup"],
        _ => vec!["inspect"],
    };
    serde_json::json!({
        "type": "object",
        "properties": {
            "target": { "type": "string", "maxLength": 512 },
            "destination": { "type": "string", "maxLength": 512 },
            "action": { "type": "string", "enum": actions },
            "dryRun": { "type": "boolean" },
            "confirm": { "type": "boolean" },
            "checkpointId": { "type": "string", "maxLength": 128 },
            "olderThanDays": { "type": "integer", "minimum": 1, "maximum": 365 },
            "limit": { "type": "integer", "minimum": 1, "maximum": 1000 }
        },
        "additionalProperties": false
    })
}

fn builtin_plugin_from_manifest(manifest: PluginManifest) -> PluginDefinition {
    let metadata = PluginMetadata {
        id: plugin_id(&manifest.name, BUILTIN_MARKETPLACE),
        name: manifest.name,
        version: manifest.version,
        description: manifest.description,
        kind: PluginKind::Builtin,
        source: BUILTIN_MARKETPLACE.to_string(),
        default_enabled: manifest.default_enabled,
        root: None,
    };
    let tools = manifest
        .tools
        .iter()
        .map(|tool| {
            PluginTool::new(
                metadata.id.clone(),
                metadata.name.clone(),
                PluginToolDefinition {
                    name: tool.name.clone(),
                    description: Some(tool.description.clone()),
                    input_schema: tool.input_schema.clone(),
                    output_schema: tool.output_schema.clone(),
                },
                tool.command.clone(),
                tool.args.clone(),
                tool.required_permission,
                None,
            )
        })
        .collect();

    PluginDefinition::Builtin(BuiltinPlugin {
        metadata,
        hooks: manifest.hooks,
        lifecycle: manifest.lifecycle,
        execution_policy: manifest.execution_policy,
        permissions: manifest.permissions,
        tools,
        resources: manifest.resources,
        prompts: manifest.prompts,
        capabilities: manifest.capabilities,
        mcp_servers: manifest.mcp_servers,
        dependencies: manifest.dependencies,
        rollback: manifest.rollback,
        version_policy: manifest.version_policy,
        ops_permissions: manifest.ops_permissions,
    })
}

fn load_plugin_definition(
    root: &Path,
    kind: PluginKind,
    source: String,
    marketplace: &str,
) -> Result<PluginDefinition, PluginError> {
    let manifest = load_plugin_from_directory(root)?;
    let metadata = PluginMetadata {
        id: plugin_id(&manifest.name, marketplace),
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        description: manifest.description.clone(),
        kind,
        source,
        default_enabled: manifest.default_enabled,
        root: Some(root.to_path_buf()),
    };
    let hooks = resolve_hooks(root, &manifest.hooks);
    let lifecycle = resolve_lifecycle(root, &manifest.lifecycle);
    let external_subprocess_allowed =
        kind != PluginKind::External || manifest.execution_policy.allow_external_subprocess;
    let tools = resolve_tools(
        root,
        &metadata.id,
        &metadata.name,
        &manifest.tools,
        external_subprocess_allowed,
        kind == PluginKind::External,
    );
    Ok(match kind {
        PluginKind::Builtin => PluginDefinition::Builtin(BuiltinPlugin {
            metadata,
            hooks,
            lifecycle,
            execution_policy: manifest.execution_policy,
            permissions: manifest.permissions,
            tools,
            resources: manifest.resources,
            prompts: manifest.prompts,
            capabilities: manifest.capabilities,
            mcp_servers: manifest.mcp_servers,
            dependencies: manifest.dependencies,
            rollback: manifest.rollback,
            version_policy: manifest.version_policy,
            ops_permissions: manifest.ops_permissions,
        }),
        PluginKind::Bundled => PluginDefinition::Bundled(BundledPlugin {
            metadata,
            hooks,
            lifecycle,
            execution_policy: manifest.execution_policy,
            permissions: manifest.permissions,
            tools,
            resources: manifest.resources,
            prompts: manifest.prompts,
            capabilities: manifest.capabilities,
            mcp_servers: manifest.mcp_servers,
            dependencies: manifest.dependencies,
            rollback: manifest.rollback,
            version_policy: manifest.version_policy,
            ops_permissions: manifest.ops_permissions,
        }),
        PluginKind::External => PluginDefinition::External(ExternalPlugin {
            metadata,
            hooks,
            lifecycle,
            execution_policy: manifest.execution_policy,
            permissions: manifest.permissions,
            tools,
            resources: manifest.resources,
            prompts: manifest.prompts,
            capabilities: manifest.capabilities,
            mcp_servers: manifest.mcp_servers,
            dependencies: manifest.dependencies,
            rollback: manifest.rollback,
            version_policy: manifest.version_policy,
            ops_permissions: manifest.ops_permissions,
        }),
    })
}

pub fn load_plugin_from_directory(root: &Path) -> Result<PluginManifest, PluginError> {
    load_manifest_from_directory(root)
}

fn load_manifest_from_directory(root: &Path) -> Result<PluginManifest, PluginError> {
    let manifest_path = plugin_manifest_path(root)?;
    load_manifest_from_path(root, &manifest_path)
}

fn load_manifest_from_path(
    root: &Path,
    manifest_path: &Path,
) -> Result<PluginManifest, PluginError> {
    let contents = fs::read_to_string(manifest_path).map_err(|error| {
        PluginError::NotFound(format!(
            "plugin manifest not found at {}: {error}",
            manifest_path.display()
        ))
    })?;
    let raw_json: Value = serde_json::from_str(&contents)?;
    let compatibility_errors = detect_claude_code_manifest_contract_gaps(&raw_json);
    if !compatibility_errors.is_empty() {
        return Err(PluginError::ManifestValidation(compatibility_errors));
    }
    let raw_manifest: RawPluginManifest = serde_json::from_value(raw_json)?;
    build_plugin_manifest(root, raw_manifest)
}

fn detect_claude_code_manifest_contract_gaps(
    raw_manifest: &Value,
) -> Vec<PluginManifestValidationError> {
    let Some(root) = raw_manifest.as_object() else {
        return Vec::new();
    };

    let mut errors = Vec::new();

    for (field, detail) in [
        (
            "skills",
            "plugin manifest field `skills` uses the Claude Code plugin contract; `claw` does not load plugin-managed skills and instead discovers skills from local roots such as `.claw/skills`, `.omc/skills`, `.agents/skills`, `~/.omc/skills`, and `~/.claude/skills/omc-learned`.",
        ),
        (
            "agents",
            "plugin manifest field `agents` uses the Claude Code plugin contract; `claw` does not load plugin-managed agent markdown catalogs from plugin manifests.",
        ),
    ] {
        if root.contains_key(field) {
            errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                detail: detail.to_string(),
            });
        }
    }

    if root
        .get("mcpServers")
        .is_some_and(|mcp_servers| !mcp_servers.is_object())
    {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: "plugin manifest field `mcpServers` must be an object map of Claw MCP server declarations; Claude Code-style string paths are not imported.".to_string(),
        });
    }

    if root
        .get("commands")
        .and_then(Value::as_array)
        .is_some_and(|commands| commands.iter().any(Value::is_string))
    {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: "plugin manifest field `commands` uses Claude Code-style directory globs; `claw` slash dispatch is still built-in and does not load plugin slash command markdown files.".to_string(),
        });
    }

    if let Some(hooks) = root.get("hooks").and_then(Value::as_object) {
        for hook_name in hooks.keys() {
            if !matches!(
                hook_name.as_str(),
                "PreToolUse" | "PostToolUse" | "PostToolUseFailure"
            ) {
                errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                    detail: format!(
                        "plugin hook `{hook_name}` uses the Claude Code lifecycle contract; `claw` plugins currently support only PreToolUse, PostToolUse, and PostToolUseFailure."
                    ),
                });
            }
        }
    }

    errors
}

fn plugin_manifest_path(root: &Path) -> Result<PathBuf, PluginError> {
    let direct_path = root.join(MANIFEST_FILE_NAME);
    if direct_path.exists() {
        return Ok(direct_path);
    }

    let packaged_path = root.join(MANIFEST_RELATIVE_PATH);
    if packaged_path.exists() {
        return Ok(packaged_path);
    }

    Err(PluginError::NotFound(format!(
        "plugin manifest not found at {} or {}",
        direct_path.display(),
        packaged_path.display()
    )))
}

fn build_plugin_manifest(
    root: &Path,
    raw: RawPluginManifest,
) -> Result<PluginManifest, PluginError> {
    let mut errors = Vec::new();

    validate_required_manifest_field("name", &raw.name, &mut errors);
    validate_required_manifest_field("version", &raw.version, &mut errors);
    validate_required_manifest_field("description", &raw.description, &mut errors);

    let permissions = build_manifest_permissions(&raw.permissions, &mut errors);
    validate_command_entries(root, raw.hooks.pre_tool_use.iter(), "hook", &mut errors);
    validate_command_entries(root, raw.hooks.post_tool_use.iter(), "hook", &mut errors);
    validate_command_entries(
        root,
        raw.hooks.post_tool_use_failure.iter(),
        "hook",
        &mut errors,
    );
    validate_command_entries(
        root,
        raw.lifecycle.init.iter(),
        "lifecycle command",
        &mut errors,
    );
    validate_command_entries(
        root,
        raw.lifecycle.shutdown.iter(),
        "lifecycle command",
        &mut errors,
    );
    let tools = build_manifest_tools(root, raw.tools, &mut errors);
    let commands = build_manifest_commands(root, raw.commands, &mut errors);
    validate_tool_permissions(&permissions, &tools, &mut errors);
    let resources = build_manifest_resources(raw.resources, &mut errors);
    let prompts = build_manifest_prompts(raw.prompts, &mut errors);
    let mcp_servers = build_manifest_mcp_servers(root, raw.mcp_servers, &permissions, &mut errors);
    let dependencies = build_manifest_dependencies(raw.dependencies, &mut errors);
    validate_ops_permissions(&raw.ops_permissions, &raw.rollback, &mut errors);

    if !errors.is_empty() {
        return Err(PluginError::ManifestValidation(errors));
    }

    Ok(PluginManifest {
        name: raw.name,
        version: raw.version,
        description: raw.description,
        permissions,
        default_enabled: raw.default_enabled,
        hooks: raw.hooks,
        lifecycle: raw.lifecycle,
        execution_policy: raw.execution_policy,
        tools,
        commands,
        capabilities: raw.capabilities,
        mcp_servers,
        dependencies,
        rollback: raw.rollback,
        version_policy: raw.version_policy,
        ops_permissions: raw.ops_permissions,
        resources,
        prompts,
    })
}

fn validate_required_manifest_field(
    field: &'static str,
    value: &str,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    if value.trim().is_empty() {
        errors.push(PluginManifestValidationError::EmptyField { field });
    }
}

fn build_manifest_permissions(
    permissions: &[String],
    errors: &mut Vec<PluginManifestValidationError>,
) -> Vec<PluginPermission> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::new();

    for permission in permissions {
        let permission = permission.trim();
        if permission.is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "permission",
                field: "value",
                name: None,
            });
            continue;
        }
        if !seen.insert(permission.to_string()) {
            errors.push(PluginManifestValidationError::DuplicatePermission {
                permission: permission.to_string(),
            });
            continue;
        }
        match PluginPermission::parse(permission) {
            Some(permission) => validated.push(permission),
            None => errors.push(PluginManifestValidationError::InvalidPermission {
                permission: permission.to_string(),
            }),
        }
    }

    validated
}

fn manifest_permission_for_tool(permission: PluginToolPermission) -> PluginPermission {
    match permission {
        PluginToolPermission::ReadOnly => PluginPermission::Read,
        PluginToolPermission::WorkspaceWrite => PluginPermission::Write,
        PluginToolPermission::DangerFullAccess => PluginPermission::Execute,
    }
}

fn validate_tool_permissions(
    permissions: &[PluginPermission],
    tools: &[PluginToolManifest],
    errors: &mut Vec<PluginManifestValidationError>,
) {
    let declared = permissions.iter().copied().collect::<BTreeSet<_>>();
    for tool in tools {
        let required_manifest_permission = manifest_permission_for_tool(tool.required_permission);
        if !declared.contains(&required_manifest_permission) {
            errors.push(PluginManifestValidationError::MissingDeclaredPermission {
                tool_name: tool.name.clone(),
                required_permission: tool.required_permission,
            });
        }
    }
}

fn build_manifest_tools(
    root: &Path,
    tools: Vec<RawPluginToolManifest>,
    errors: &mut Vec<PluginManifestValidationError>,
) -> Vec<PluginToolManifest> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::new();

    for tool in tools {
        let name = tool.name.trim().to_string();
        if name.is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "tool",
                field: "name",
                name: None,
            });
            continue;
        }
        if !seen.insert(name.clone()) {
            errors.push(PluginManifestValidationError::DuplicateEntry { kind: "tool", name });
            continue;
        }
        if tool.description.trim().is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "tool",
                field: "description",
                name: Some(name.clone()),
            });
        }
        if tool.command.trim().is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "tool",
                field: "command",
                name: Some(name.clone()),
            });
        } else {
            validate_command_entry(root, &tool.command, "tool", errors);
        }
        if !tool.input_schema.is_object() {
            errors.push(PluginManifestValidationError::InvalidToolInputSchema {
                tool_name: name.clone(),
            });
        }
        if tool
            .output_schema
            .as_ref()
            .is_some_and(|schema| !schema.is_object())
        {
            errors.push(PluginManifestValidationError::InvalidJsonSchema {
                kind: "tool output",
                name: name.clone(),
            });
        }
        let Some(required_permission) =
            PluginToolPermission::parse(tool.required_permission.trim())
        else {
            errors.push(
                PluginManifestValidationError::InvalidToolRequiredPermission {
                    tool_name: name.clone(),
                    permission: tool.required_permission.trim().to_string(),
                },
            );
            continue;
        };

        validated.push(PluginToolManifest {
            name,
            description: tool.description,
            input_schema: tool.input_schema,
            output_schema: tool.output_schema,
            command: tool.command,
            args: tool.args,
            required_permission,
        });
    }

    validated
}

fn build_manifest_commands(
    root: &Path,
    commands: Vec<PluginCommandManifest>,
    errors: &mut Vec<PluginManifestValidationError>,
) -> Vec<PluginCommandManifest> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::new();

    for command in commands {
        let name = command.name.trim().to_string();
        if name.is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "command",
                field: "name",
                name: None,
            });
            continue;
        }
        if !seen.insert(name.clone()) {
            errors.push(PluginManifestValidationError::DuplicateEntry {
                kind: "command",
                name,
            });
            continue;
        }
        if command.description.trim().is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "command",
                field: "description",
                name: Some(name.clone()),
            });
        }
        if command.command.trim().is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "command",
                field: "command",
                name: Some(name.clone()),
            });
        } else {
            validate_command_entry(root, &command.command, "command", errors);
        }
        validated.push(command);
    }

    validated
}

fn build_manifest_resources(
    resources: Vec<PluginResourceManifest>,
    errors: &mut Vec<PluginManifestValidationError>,
) -> Vec<PluginResourceManifest> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::new();

    for resource in resources {
        let uri = resource.uri.trim().to_string();
        if uri.is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "resource",
                field: "uri",
                name: None,
            });
            continue;
        }
        if !seen.insert(uri.clone()) {
            errors.push(PluginManifestValidationError::DuplicateEntry {
                kind: "resource",
                name: uri,
            });
            continue;
        }
        if resource.name.trim().is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "resource",
                field: "name",
                name: Some(resource.uri.clone()),
            });
        }
        validated.push(PluginResourceManifest { uri, ..resource });
    }

    validated
}

fn build_manifest_prompts(
    prompts: Vec<PluginPromptManifest>,
    errors: &mut Vec<PluginManifestValidationError>,
) -> Vec<PluginPromptManifest> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::new();

    for mut prompt in prompts {
        let name = prompt.name.trim().to_string();
        if name.is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "prompt",
                field: "name",
                name: None,
            });
            continue;
        }
        if !seen.insert(name.clone()) {
            errors.push(PluginManifestValidationError::DuplicateEntry {
                kind: "prompt",
                name,
            });
            continue;
        }
        if prompt.description.trim().is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "prompt",
                field: "description",
                name: Some(prompt.name.clone()),
            });
        }
        for argument in &prompt.arguments {
            if argument.name.trim().is_empty() {
                errors.push(PluginManifestValidationError::EmptyEntryField {
                    kind: "prompt argument",
                    field: "name",
                    name: Some(prompt.name.clone()),
                });
            }
            if !argument.schema.is_object() {
                errors.push(PluginManifestValidationError::InvalidJsonSchema {
                    kind: "prompt argument",
                    name: format!("{}:{}", prompt.name, argument.name),
                });
            }
        }
        prompt.name = name;
        validated.push(prompt);
    }

    validated
}

fn build_manifest_mcp_servers(
    root: &Path,
    mut mcp_servers: BTreeMap<String, PluginMcpServerManifest>,
    permissions: &[PluginPermission],
    errors: &mut Vec<PluginManifestValidationError>,
) -> BTreeMap<String, PluginMcpServerManifest> {
    let declared = permissions.iter().copied().collect::<BTreeSet<_>>();
    for (server_name, server) in &mut mcp_servers {
        if server_name.trim().is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "mcp server",
                field: "name",
                name: None,
            });
            continue;
        }
        let Some(required_permission) = server.required_permission else {
            errors.push(PluginManifestValidationError::InvalidMcpServerConfig {
                server_name: server_name.clone(),
                detail: "plugin MCP server requires requiredPermission".to_string(),
            });
            continue;
        };
        let required_manifest_permission = manifest_permission_for_tool(required_permission);
        if !declared.contains(&required_manifest_permission) {
            errors.push(PluginManifestValidationError::InvalidMcpServerConfig {
                server_name: server_name.clone(),
                detail: format!(
                    "requiredPermission `{}` requires manifest permission `{}`",
                    required_permission.as_str(),
                    required_manifest_permission.as_str()
                ),
            });
        }
        if !matches!(required_permission, PluginToolPermission::ReadOnly) {
            errors.push(PluginManifestValidationError::InvalidMcpServerConfig {
                server_name: server_name.clone(),
                detail: "plugin MCP servers are limited to read-only until an OS sandboxed runner is available".to_string(),
            });
        }
        validate_manifest_mcp_heartbeat(server_name, server, errors);
        match server.transport {
            PluginMcpTransport::Stdio => {
                if server
                    .command
                    .as_deref()
                    .unwrap_or_default()
                    .trim()
                    .is_empty()
                {
                    errors.push(PluginManifestValidationError::InvalidMcpServerConfig {
                        server_name: server_name.clone(),
                        detail: "stdio transport requires command".to_string(),
                    });
                } else if let Some(command) = server.command.clone() {
                    if is_literal_command(&command) {
                        errors.push(PluginManifestValidationError::InvalidMcpServerConfig {
                            server_name: server_name.clone(),
                            detail: "stdio command must be a plugin-relative or absolute executable path so it can be policy checked".to_string(),
                        });
                    }
                    validate_command_entry(root, &command, "mcp server", errors);
                    if !is_literal_command(&command) {
                        server.command = Some(resolve_hook_entry(root, &command));
                    }
                    server
                        .env
                        .insert("CLAWD_SANDBOX".to_string(), "process-isolated".to_string());
                    server
                        .env
                        .insert("CLAWD_NETWORK_DISABLED".to_string(), "1".to_string());
                    server.env.insert(
                        "CLAWD_PERMISSION".to_string(),
                        required_permission.as_str().to_string(),
                    );
                    server.tool_call_timeout_ms = Some(
                        server
                            .tool_call_timeout_ms
                            .unwrap_or(PLUGIN_TOOL_TIMEOUT_MS),
                    );
                }
            }
            PluginMcpTransport::Sse => {
                if server.url.as_deref().unwrap_or_default().trim().is_empty() {
                    errors.push(PluginManifestValidationError::InvalidMcpServerConfig {
                        server_name: server_name.clone(),
                        detail: "sse transport requires url".to_string(),
                    });
                }
                if required_permission != PluginToolPermission::ReadOnly {
                    errors.push(PluginManifestValidationError::InvalidMcpServerConfig {
                        server_name: server_name.clone(),
                        detail: "plugin SSE MCP servers must be read-only and are surfaced as degraded until the network client is enabled".to_string(),
                    });
                }
            }
        }
        for tool in &server.capabilities.tools {
            if !tool.input_schema.is_object() {
                errors.push(PluginManifestValidationError::InvalidJsonSchema {
                    kind: "mcp tool",
                    name: format!("{server_name}:{}", tool.name),
                });
            }
        }
    }
    mcp_servers
}

fn validate_manifest_mcp_heartbeat(
    server_name: &str,
    server: &PluginMcpServerManifest,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    if server.heartbeat.interval_ms < MIN_PLUGIN_MCP_HEARTBEAT_INTERVAL_MS
        || server.heartbeat.interval_ms > MAX_PLUGIN_MCP_HEARTBEAT_INTERVAL_MS
    {
        errors.push(PluginManifestValidationError::InvalidMcpServerConfig {
            server_name: server_name.to_string(),
            detail: format!(
                "heartbeat.intervalMs must be between {MIN_PLUGIN_MCP_HEARTBEAT_INTERVAL_MS} and {MAX_PLUGIN_MCP_HEARTBEAT_INTERVAL_MS}"
            ),
        });
    }
    if server.heartbeat.timeout_ms < MIN_PLUGIN_MCP_TIMEOUT_MS
        || server.heartbeat.timeout_ms > MAX_PLUGIN_MCP_TIMEOUT_MS
    {
        errors.push(PluginManifestValidationError::InvalidMcpServerConfig {
            server_name: server_name.to_string(),
            detail: format!(
                "heartbeat.timeoutMs must be between {MIN_PLUGIN_MCP_TIMEOUT_MS} and {MAX_PLUGIN_MCP_TIMEOUT_MS}"
            ),
        });
    }
}

fn build_manifest_dependencies(
    dependencies: Vec<PluginDependency>,
    errors: &mut Vec<PluginManifestValidationError>,
) -> Vec<PluginDependency> {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::new();

    for dependency in dependencies {
        let name = dependency.name.trim().to_string();
        if name.is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "dependency",
                field: "name",
                name: None,
            });
            continue;
        }
        if !seen.insert(name.clone()) {
            errors.push(PluginManifestValidationError::DuplicateEntry {
                kind: "dependency",
                name,
            });
            continue;
        }
        validated.push(PluginDependency { name, ..dependency });
    }

    validated
}

fn validate_ops_permissions(
    ops_permissions: &[PluginOpsPermission],
    rollback: &PluginRollbackPlan,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    for permission in ops_permissions {
        if permission.scope.trim().is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "ops permission",
                field: "scope",
                name: None,
            });
        }
        if permission.reason.trim().is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "ops permission",
                field: "reason",
                name: Some(permission.scope.clone()),
            });
        }
        if matches!(
            permission.risk,
            PluginRiskLevel::High | PluginRiskLevel::Critical
        ) && !permission.rollback_required
            && permission.rollback_command.is_none()
            && rollback.commands.is_empty()
        {
            errors.push(PluginManifestValidationError::MissingRollbackForHighRisk {
                scope: permission.scope.clone(),
            });
        }
    }
}

fn validate_command_entries<'a>(
    root: &Path,
    entries: impl Iterator<Item = &'a String>,
    kind: &'static str,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    for entry in entries {
        validate_command_entry(root, entry, kind, errors);
    }
}

fn validate_command_entry(
    root: &Path,
    entry: &str,
    kind: &'static str,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    if entry.trim().is_empty() {
        errors.push(PluginManifestValidationError::EmptyEntryField {
            kind,
            field: "command",
            name: None,
        });
        return;
    }
    if is_literal_command(entry) {
        return;
    }

    let path = if Path::new(entry).is_absolute() {
        PathBuf::from(entry)
    } else {
        root.join(entry)
    };
    if !path.exists() {
        errors.push(PluginManifestValidationError::MissingPath { kind, path });
    } else if !path.is_file() {
        errors.push(PluginManifestValidationError::PathIsDirectory { kind, path });
    }
}

fn resolve_hooks(root: &Path, hooks: &PluginHooks) -> PluginHooks {
    PluginHooks {
        pre_tool_use: hooks
            .pre_tool_use
            .iter()
            .map(|entry| resolve_hook_entry(root, entry))
            .collect(),
        post_tool_use: hooks
            .post_tool_use
            .iter()
            .map(|entry| resolve_hook_entry(root, entry))
            .collect(),
        post_tool_use_failure: hooks
            .post_tool_use_failure
            .iter()
            .map(|entry| resolve_hook_entry(root, entry))
            .collect(),
    }
}

fn resolve_lifecycle(root: &Path, lifecycle: &PluginLifecycle) -> PluginLifecycle {
    PluginLifecycle {
        init: lifecycle
            .init
            .iter()
            .map(|entry| resolve_hook_entry(root, entry))
            .collect(),
        shutdown: lifecycle
            .shutdown
            .iter()
            .map(|entry| resolve_hook_entry(root, entry))
            .collect(),
    }
}

fn resolve_tools(
    root: &Path,
    plugin_id: &str,
    plugin_name: &str,
    tools: &[PluginToolManifest],
    external_subprocess_allowed: bool,
    os_sandbox_required: bool,
) -> Vec<PluginTool> {
    tools
        .iter()
        .map(|tool| {
            PluginTool::new(
                plugin_id,
                plugin_name,
                PluginToolDefinition {
                    name: tool.name.clone(),
                    description: Some(tool.description.clone()),
                    input_schema: tool.input_schema.clone(),
                    output_schema: tool.output_schema.clone(),
                },
                resolve_hook_entry(root, &tool.command),
                tool.args.clone(),
                tool.required_permission,
                Some(root.to_path_buf()),
            )
            .with_external_subprocess_allowed(external_subprocess_allowed)
            .with_os_sandbox_required(os_sandbox_required)
        })
        .collect()
}

fn validate_hook_paths(root: Option<&Path>, hooks: &PluginHooks) -> Result<(), PluginError> {
    let Some(root) = root else {
        return Ok(());
    };
    for entry in hooks
        .pre_tool_use
        .iter()
        .chain(hooks.post_tool_use.iter())
        .chain(hooks.post_tool_use_failure.iter())
    {
        validate_command_path(root, entry, "hook")?;
    }
    Ok(())
}

fn validate_lifecycle_paths(
    root: Option<&Path>,
    lifecycle: &PluginLifecycle,
) -> Result<(), PluginError> {
    let Some(root) = root else {
        return Ok(());
    };
    for entry in lifecycle.init.iter().chain(lifecycle.shutdown.iter()) {
        validate_command_path(root, entry, "lifecycle command")?;
    }
    Ok(())
}

fn validate_tool_paths(root: Option<&Path>, tools: &[PluginTool]) -> Result<(), PluginError> {
    let Some(root) = root else {
        return Ok(());
    };
    for tool in tools {
        validate_command_path(root, &tool.command, "tool")?;
    }
    Ok(())
}

fn validate_command_path(root: &Path, entry: &str, kind: &str) -> Result<(), PluginError> {
    if is_literal_command(entry) {
        return Ok(());
    }
    let path = if Path::new(entry).is_absolute() {
        PathBuf::from(entry)
    } else {
        root.join(entry)
    };
    if !path.exists() {
        return Err(PluginError::InvalidManifest(format!(
            "{kind} path `{}` does not exist",
            path.display()
        )));
    }
    if !path.is_file() {
        return Err(PluginError::InvalidManifest(format!(
            "{kind} path `{}` must point to a file",
            path.display()
        )));
    }
    Ok(())
}

fn resolve_hook_entry(root: &Path, entry: &str) -> String {
    if is_literal_command(entry) {
        entry.to_string()
    } else {
        root.join(entry).display().to_string()
    }
}

fn is_literal_command(entry: &str) -> bool {
    !entry.starts_with("./") && !entry.starts_with("../") && !Path::new(entry).is_absolute()
}

fn run_lifecycle_commands(
    metadata: &PluginMetadata,
    lifecycle: &PluginLifecycle,
    execution_policy: &PluginExecutionPolicy,
    permissions: &[PluginPermission],
    phase: &str,
    commands: &[String],
) -> Result<(), PluginError> {
    if lifecycle.is_empty() || commands.is_empty() {
        return Ok(());
    }

    for command in commands {
        let (runner, args) = if cfg!(windows) {
            if command.ends_with(".sh") {
                (command.clone(), Vec::new())
            } else {
                ("cmd".to_string(), vec!["/C".to_string(), command.clone()])
            }
        } else {
            ("sh".to_string(), vec!["-lc".to_string(), command.clone()])
        };
        let output = run_controlled_child(ControlledChildRequest {
            command: runner,
            args,
            stdin: None,
            cwd: metadata.root.clone(),
            timeout: Duration::from_millis(PLUGIN_LIFECYCLE_TIMEOUT_MS),
            permission: lifecycle_child_permission(permissions),
            external_subprocess_allowed: metadata.kind != PluginKind::External
                || execution_policy.allow_external_subprocess,
            os_sandbox_required: metadata.kind == PluginKind::External,
            env: BTreeMap::from([
                ("CLAWD_PLUGIN_ID".to_string(), metadata.id.clone()),
                ("CLAWD_PLUGIN_NAME".to_string(), metadata.name.clone()),
                ("CLAWD_LIFECYCLE_PHASE".to_string(), phase.to_string()),
            ]),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(PluginError::CommandFailed(format!(
                "plugin `{}` {} failed for `{}`: {}",
                metadata.id,
                phase,
                command,
                if stderr.is_empty() {
                    format!("exit status {}", output.status)
                } else {
                    stderr
                }
            )));
        }
    }

    Ok(())
}

fn resolve_local_source(source: &str) -> Result<PathBuf, PluginError> {
    let path = PathBuf::from(source);
    if path.exists() {
        Ok(path)
    } else {
        Err(PluginError::NotFound(format!(
            "plugin source `{source}` was not found"
        )))
    }
}

fn parse_install_source(source: &str) -> Result<PluginInstallSource, PluginError> {
    if source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("git@")
        || Path::new(source)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("git"))
    {
        Ok(PluginInstallSource::GitUrl {
            url: source.to_string(),
        })
    } else {
        Ok(PluginInstallSource::LocalPath {
            path: resolve_local_source(source)?,
        })
    }
}

fn materialize_source(
    source: &PluginInstallSource,
    temp_root: &Path,
) -> Result<PathBuf, PluginError> {
    fs::create_dir_all(temp_root)?;
    match source {
        PluginInstallSource::LocalPath { path } => Ok(path.clone()),
        PluginInstallSource::GitUrl { url } => {
            static MATERIALIZE_COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = MATERIALIZE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let destination = temp_root.join(format!("plugin-{nanos}-{unique}"));
            let output = Command::new("git")
                .arg("clone")
                .arg("--depth")
                .arg("1")
                .arg(url)
                .arg(&destination)
                .output()?;
            if !output.status.success() {
                return Err(PluginError::CommandFailed(format!(
                    "git clone failed for `{url}`: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )));
            }
            Ok(destination)
        }
    }
}

fn discover_plugin_dirs(root: &Path) -> Result<Vec<PathBuf>, PluginError> {
    match fs::read_dir(root) {
        Ok(entries) => {
            let mut paths = Vec::new();
            for entry in entries {
                let path = entry?.path();
                if path.is_dir() && plugin_manifest_path(&path).is_ok() {
                    paths.push(path);
                }
            }
            paths.sort();
            Ok(paths)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(PluginError::Io(error)),
    }
}

fn lifecycle_child_permission(permissions: &[PluginPermission]) -> PluginToolPermission {
    if permissions.contains(&PluginPermission::Write) {
        PluginToolPermission::WorkspaceWrite
    } else {
        PluginToolPermission::ReadOnly
    }
}

fn dependency_order_for_plugins(plugins: &[RegisteredPlugin]) -> Result<Vec<String>, PluginError> {
    let enabled_plugins = plugins
        .iter()
        .filter(|plugin| plugin.is_enabled())
        .collect::<Vec<_>>();
    let mut ids = BTreeSet::new();
    let mut by_name = BTreeMap::<String, String>::new();

    for plugin in &enabled_plugins {
        let id = plugin.metadata().id.clone();
        ids.insert(id.clone());
        by_name.insert(plugin.metadata().name.clone(), id);
    }

    let mut indegree = ids
        .iter()
        .map(|id| (id.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    let mut dependents = ids
        .iter()
        .map(|id| (id.clone(), Vec::<String>::new()))
        .collect::<BTreeMap<_, _>>();

    for plugin in &enabled_plugins {
        for dependency in plugin.dependencies() {
            let dependency_id = if ids.contains(&dependency.name) {
                Some(dependency.name.clone())
            } else {
                by_name.get(&dependency.name).cloned()
            };

            let Some(dependency_id) = dependency_id else {
                if dependency.optional {
                    continue;
                }
                return Err(PluginError::InvalidManifest(format!(
                    "plugin `{}` depends on missing plugin `{}`",
                    plugin.metadata().id,
                    dependency.name
                )));
            };

            if dependency_id == plugin.metadata().id {
                return Err(PluginError::InvalidManifest(format!(
                    "plugin `{}` depends on itself",
                    plugin.metadata().id
                )));
            }

            if let Some(requirement) = dependency.version_requirement.as_deref() {
                let dependency_plugin = enabled_plugins
                    .iter()
                    .find(|candidate| candidate.metadata().id == dependency_id)
                    .expect("dependency id should map to enabled plugin");
                if !semver_requirement_matches(requirement, &dependency_plugin.metadata().version)?
                {
                    return Err(PluginError::InvalidManifest(format!(
                        "plugin `{}` depends on `{}` version `{}` but active version is `{}`",
                        plugin.metadata().id,
                        dependency.name,
                        requirement,
                        dependency_plugin.metadata().version
                    )));
                }
            }

            *indegree
                .get_mut(&plugin.metadata().id)
                .expect("enabled plugin should have indegree") += 1;
            dependents
                .get_mut(&dependency_id)
                .expect("dependency should have dependents list")
                .push(plugin.metadata().id.clone());
        }
    }

    let mut ready = indegree
        .iter()
        .filter_map(|(id, count)| (*count == 0).then_some(id.clone()))
        .collect::<BTreeSet<_>>();
    let mut ordered = Vec::new();

    while let Some(id) = ready.iter().next().cloned() {
        ready.remove(&id);
        ordered.push(id.clone());
        for dependent in dependents.remove(&id).unwrap_or_default() {
            let count = indegree
                .get_mut(&dependent)
                .expect("dependent should have indegree");
            *count = count.saturating_sub(1);
            if *count == 0 {
                ready.insert(dependent);
            }
        }
    }

    if ordered.len() != ids.len() {
        let blocked = indegree
            .into_iter()
            .filter_map(|(id, count)| (count > 0).then_some(id))
            .collect::<Vec<_>>();
        return Err(PluginError::InvalidManifest(format!(
            "plugin dependency cycle detected among: {}",
            blocked.join(", ")
        )));
    }

    Ok(ordered)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Semver {
    major: u64,
    minor: u64,
    patch: u64,
}

fn semver_requirement_matches(requirement: &str, version: &str) -> Result<bool, PluginError> {
    let requirement = requirement.trim();
    if requirement.is_empty() || requirement == "*" {
        return Ok(true);
    }

    let version = parse_semver(version)?;
    for clause in requirement
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let matches = if let Some(expected) = clause.strip_prefix(">=") {
            version >= parse_semver(expected.trim())?
        } else if let Some(expected) = clause.strip_prefix("<=") {
            version <= parse_semver(expected.trim())?
        } else if let Some(expected) = clause.strip_prefix('>') {
            version > parse_semver(expected.trim())?
        } else if let Some(expected) = clause.strip_prefix('<') {
            version < parse_semver(expected.trim())?
        } else if let Some(expected) = clause.strip_prefix('=') {
            version == parse_semver(expected.trim())?
        } else if let Some(expected) = clause.strip_prefix('^') {
            let expected = parse_semver(expected.trim())?;
            version >= expected
                && version
                    < (Semver {
                        major: expected.major + 1,
                        minor: 0,
                        patch: 0,
                    })
        } else {
            version == parse_semver(clause)?
        };
        if !matches {
            return Ok(false);
        }
    }

    Ok(true)
}

fn parse_semver(value: &str) -> Result<Semver, PluginError> {
    let trimmed = value.trim().trim_start_matches('v');
    let core = trimmed.split_once('-').map_or(trimmed, |(core, _)| core);
    let core = core.split_once('+').map_or(core, |(core, _)| core);
    let mut parts = core.split('.');
    let major = parse_semver_part(parts.next(), value)?;
    let minor = parse_semver_part(parts.next(), value)?;
    let patch = parse_semver_part(parts.next(), value)?;
    if parts.next().is_some() {
        return Err(PluginError::InvalidManifest(format!(
            "invalid semver version `{value}`"
        )));
    }
    Ok(Semver {
        major,
        minor,
        patch,
    })
}

fn parse_semver_part(part: Option<&str>, value: &str) -> Result<u64, PluginError> {
    part.ok_or_else(|| PluginError::InvalidManifest(format!("invalid semver version `{value}`")))?
        .parse::<u64>()
        .map_err(|_| PluginError::InvalidManifest(format!("invalid semver version `{value}`")))
}

fn plugin_id(name: &str, marketplace: &str) -> String {
    format!("{name}@{marketplace}")
}

fn sanitize_plugin_id(plugin_id: &str) -> String {
    plugin_id
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | '@' | ':' => '-',
            other => other,
        })
        .collect()
}

fn describe_install_source(source: &PluginInstallSource) -> String {
    match source {
        PluginInstallSource::LocalPath { path } => path.display().to_string(),
        PluginInstallSource::GitUrl { url } => url.clone(),
    }
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be after epoch")
        .as_millis()
}

fn copy_dir_all(source: &Path, destination: &Path) -> Result<(), PluginError> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn prune_archived_versions(versions: &mut Vec<InstalledPluginVersionRecord>, keep_versions: usize) {
    versions.sort_by(|left, right| {
        left.archived_at_unix_ms
            .cmp(&right.archived_at_unix_ms)
            .then_with(|| left.version.cmp(&right.version))
    });
    while versions.len() > keep_versions {
        let removed = versions.remove(0);
        if removed.install_path.exists() {
            let _ = fs::remove_dir_all(removed.install_path);
        }
    }
}

fn update_settings_json(
    path: &Path,
    mut update: impl FnMut(&mut Map<String, Value>),
) -> Result<(), PluginError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut root = match fs::read_to_string(path) {
        Ok(contents) if !contents.trim().is_empty() => serde_json::from_str::<Value>(&contents)?,
        Ok(_) => Value::Object(Map::new()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Value::Object(Map::new()),
        Err(error) => return Err(PluginError::Io(error)),
    };

    let object = root.as_object_mut().ok_or_else(|| {
        PluginError::InvalidManifest(format!(
            "settings file {} must contain a JSON object",
            path.display()
        ))
    })?;
    update(object);
    fs::write(path, serde_json::to_string_pretty(&root)?)?;
    Ok(())
}

fn ensure_object<'a>(root: &'a mut Map<String, Value>, key: &str) -> &'a mut Map<String, Value> {
    if !root.get(key).is_some_and(Value::is_object) {
        root.insert(key.to_string(), Value::Object(Map::new()));
    }
    root.get_mut(key)
        .and_then(Value::as_object_mut)
        .expect("object should exist")
}

/// Environment variable lock for test isolation.
/// Guards against concurrent modification of `CLAW_CONFIG_HOME`.
#[cfg(test)]
fn env_lock() -> &'static std::sync::Mutex<()> {
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &ENV_LOCK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("plugins-{label}-{nanos}"))
    }

    #[test]
    fn env_guard_recovers_after_poisoning() {
        let poisoned = std::thread::spawn(|| {
            let _guard = env_guard();
            panic!("poison env lock");
        })
        .join();
        assert!(poisoned.is_err(), "poisoning thread should panic");

        let _guard = env_guard();
    }

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent dir");
        }
        fs::write(path, contents).expect("write file");
    }

    fn write_loader_plugin(root: &Path) {
        write_file(
            root.join("hooks").join("pre.sh").as_path(),
            "#!/bin/sh\nprintf 'pre'\n",
        );
        write_file(
            root.join("tools").join("echo-tool.sh").as_path(),
            "#!/bin/sh\ncat\n",
        );
        write_file(
            root.join("commands").join("sync.sh").as_path(),
            "#!/bin/sh\nprintf 'sync'\n",
        );
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "loader-demo",
  "version": "1.2.3",
  "description": "Manifest loader test plugin",
  "permissions": ["read", "write"],
  "hooks": {
    "PreToolUse": ["./hooks/pre.sh"]
  },
  "tools": [
    {
      "name": "echo_tool",
      "description": "Echoes JSON input",
      "inputSchema": {
        "type": "object"
      },
      "command": "./tools/echo-tool.sh",
      "requiredPermission": "workspace-write"
    }
  ],
  "commands": [
    {
      "name": "sync",
      "description": "Sync command",
      "command": "./commands/sync.sh"
    }
  ]
}"#,
        );
    }

    fn write_external_plugin(root: &Path, name: &str, version: &str) {
        write_file(
            root.join("hooks").join("pre.sh").as_path(),
            "#!/bin/sh\nprintf 'pre'\n",
        );
        write_file(
            root.join("hooks").join("post.sh").as_path(),
            "#!/bin/sh\nprintf 'post'\n",
        );
        write_file(
            root.join(MANIFEST_RELATIVE_PATH).as_path(),
            format!(
                "{{\n  \"name\": \"{name}\",\n  \"version\": \"{version}\",\n  \"description\": \"test plugin\",\n  \"hooks\": {{\n    \"PreToolUse\": [\"./hooks/pre.sh\"],\n    \"PostToolUse\": [\"./hooks/post.sh\"]\n  }}\n}}"
            )
            .as_str(),
        );
    }

    fn write_broken_plugin(root: &Path, name: &str) {
        write_file(
            root.join(MANIFEST_RELATIVE_PATH).as_path(),
            format!(
                "{{\n  \"name\": \"{name}\",\n  \"version\": \"1.0.0\",\n  \"description\": \"broken plugin\",\n  \"hooks\": {{\n    \"PreToolUse\": [\"./hooks/missing.sh\"]\n  }}\n}}"
            )
            .as_str(),
        );
    }

    fn write_directory_path_plugin(root: &Path, name: &str) {
        fs::create_dir_all(root.join("hooks").join("pre-dir")).expect("hook dir");
        fs::create_dir_all(root.join("tools").join("tool-dir")).expect("tool dir");
        fs::create_dir_all(root.join("commands").join("sync-dir")).expect("command dir");
        fs::create_dir_all(root.join("lifecycle").join("init-dir")).expect("lifecycle dir");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            format!(
                "{{\n  \"name\": \"{name}\",\n  \"version\": \"1.0.0\",\n  \"description\": \"directory path plugin\",\n  \"permissions\": [\"write\"],\n  \"hooks\": {{\n    \"PreToolUse\": [\"./hooks/pre-dir\"]\n  }},\n  \"lifecycle\": {{\n    \"Init\": [\"./lifecycle/init-dir\"]\n  }},\n  \"tools\": [\n    {{\n      \"name\": \"dir_tool\",\n      \"description\": \"Directory tool\",\n      \"inputSchema\": {{\"type\": \"object\"}},\n      \"command\": \"./tools/tool-dir\",\n      \"requiredPermission\": \"workspace-write\"\n    }}\n  ],\n  \"commands\": [\n    {{\n      \"name\": \"sync\",\n      \"description\": \"Directory command\",\n      \"command\": \"./commands/sync-dir\"\n    }}\n  ]\n}}"
            )
            .as_str(),
        );
    }

    fn write_broken_failure_hook_plugin(root: &Path, name: &str) {
        write_file(
            root.join(MANIFEST_RELATIVE_PATH).as_path(),
            format!(
                "{{\n  \"name\": \"{name}\",\n  \"version\": \"1.0.0\",\n  \"description\": \"broken plugin\",\n  \"hooks\": {{\n    \"PostToolUseFailure\": [\"./hooks/missing-failure.sh\"]\n  }}\n}}"
            )
            .as_str(),
        );
    }

    fn write_lifecycle_plugin(root: &Path, name: &str, version: &str) -> PathBuf {
        let log_path = root.join("lifecycle.log");
        write_file(
            root.join("lifecycle").join("init.sh").as_path(),
            "#!/bin/sh\nprintf 'init\\n' >> lifecycle.log\n",
        );
        write_file(
            root.join("lifecycle").join("shutdown.sh").as_path(),
            "#!/bin/sh\nprintf 'shutdown\\n' >> lifecycle.log\n",
        );
        write_file(
            root.join(MANIFEST_RELATIVE_PATH).as_path(),
            format!(
                "{{\n  \"name\": \"{name}\",\n  \"version\": \"{version}\",\n  \"description\": \"lifecycle plugin\",\n  \"executionPolicy\": {{ \"allowExternalSubprocess\": true, \"reason\": \"test fixture\" }},\n  \"lifecycle\": {{\n    \"Init\": [\"./lifecycle/init.sh\"],\n    \"Shutdown\": [\"./lifecycle/shutdown.sh\"]\n  }}\n}}"
            )
            .as_str(),
        );
        log_path
    }

    fn write_tool_plugin(root: &Path, name: &str, version: &str) {
        write_tool_plugin_with_name(root, name, version, "plugin_echo");
    }

    fn write_tool_plugin_with_name(root: &Path, name: &str, version: &str, tool_name: &str) {
        let script_path = root.join("tools").join("echo-json.sh");
        write_file(
            &script_path,
            "#!/bin/sh\nINPUT=$(cat)\nprintf '{\"plugin\":\"%s\",\"tool\":\"%s\",\"input\":%s}\\n' \"$CLAWD_PLUGIN_ID\" \"$CLAWD_TOOL_NAME\" \"$INPUT\"\n",
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(&script_path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&script_path, permissions).expect("chmod");
        }
        write_file(
            root.join(MANIFEST_RELATIVE_PATH).as_path(),
            format!(
                "{{\n  \"name\": \"{name}\",\n  \"version\": \"{version}\",\n  \"description\": \"tool plugin\",\n  \"permissions\": [\"write\"],\n  \"executionPolicy\": {{ \"allowExternalSubprocess\": true, \"reason\": \"test fixture\" }},\n  \"tools\": [\n    {{\n      \"name\": \"{tool_name}\",\n      \"description\": \"Echo JSON input\",\n      \"inputSchema\": {{\"type\": \"object\", \"properties\": {{\"message\": {{\"type\": \"string\"}}}}, \"required\": [\"message\"], \"additionalProperties\": false}},\n      \"command\": \"./tools/echo-json.sh\",\n      \"requiredPermission\": \"workspace-write\"\n    }}\n  ]\n}}"
            )
            .as_str(),
        );
    }

    fn write_bundled_plugin(root: &Path, name: &str, version: &str, default_enabled: bool) {
        write_file(
            root.join(MANIFEST_RELATIVE_PATH).as_path(),
            format!(
                "{{\n  \"name\": \"{name}\",\n  \"version\": \"{version}\",\n  \"description\": \"bundled plugin\",\n  \"defaultEnabled\": {}\n}}",
                if default_enabled { "true" } else { "false" }
            )
            .as_str(),
        );
    }

    fn load_enabled_plugins(path: &Path) -> BTreeMap<String, bool> {
        let contents = fs::read_to_string(path).expect("settings should exist");
        let root: Value = serde_json::from_str(&contents).expect("settings json");
        root.get("enabledPlugins")
            .and_then(Value::as_object)
            .map(|enabled_plugins| {
                enabled_plugins
                    .iter()
                    .map(|(plugin_id, value)| {
                        (
                            plugin_id.clone(),
                            value.as_bool().expect("plugin state should be a bool"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn load_plugin_from_directory_validates_required_fields() {
        let _guard = env_guard();
        let root = temp_dir("manifest-required");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{"name":"","version":"1.0.0","description":"desc"}"#,
        );

        let error = load_plugin_from_directory(&root).expect_err("empty name should fail");
        assert!(error.to_string().contains("name cannot be empty"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_reads_root_manifest_and_validates_entries() {
        let _guard = env_guard();
        let root = temp_dir("manifest-root");
        write_loader_plugin(&root);

        let manifest = load_plugin_from_directory(&root).expect("manifest should load");
        assert_eq!(manifest.name, "loader-demo");
        assert_eq!(manifest.version, "1.2.3");
        assert_eq!(
            manifest
                .permissions
                .iter()
                .map(|permission| permission.as_str())
                .collect::<Vec<_>>(),
            vec!["read", "write"]
        );
        assert_eq!(manifest.hooks.pre_tool_use, vec!["./hooks/pre.sh"]);
        assert_eq!(manifest.tools.len(), 1);
        assert_eq!(manifest.tools[0].name, "echo_tool");
        assert_eq!(
            manifest.tools[0].required_permission,
            PluginToolPermission::WorkspaceWrite
        );
        assert_eq!(manifest.commands.len(), 1);
        assert_eq!(manifest.commands[0].name, "sync");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_supports_packaged_manifest_path() {
        let _guard = env_guard();
        let root = temp_dir("manifest-packaged");
        write_external_plugin(&root, "packaged-demo", "1.0.0");

        let manifest = load_plugin_from_directory(&root).expect("packaged manifest should load");
        assert_eq!(manifest.name, "packaged-demo");
        assert!(manifest.tools.is_empty());
        assert!(manifest.commands.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_defaults_optional_fields() {
        let _guard = env_guard();
        let root = temp_dir("manifest-defaults");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "minimal",
  "version": "0.1.0",
  "description": "Minimal manifest"
}"#,
        );

        let manifest = load_plugin_from_directory(&root).expect("minimal manifest should load");
        assert!(manifest.permissions.is_empty());
        assert!(manifest.hooks.is_empty());
        assert!(manifest.tools.is_empty());
        assert!(manifest.commands.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_rejects_duplicate_permissions_and_commands() {
        let _guard = env_guard();
        let root = temp_dir("manifest-duplicates");
        write_file(
            root.join("commands").join("sync.sh").as_path(),
            "#!/bin/sh\nprintf 'sync'\n",
        );
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "duplicate-manifest",
  "version": "1.0.0",
  "description": "Duplicate validation",
  "permissions": ["read", "read"],
  "commands": [
    {"name": "sync", "description": "Sync one", "command": "./commands/sync.sh"},
    {"name": "sync", "description": "Sync two", "command": "./commands/sync.sh"}
  ]
}"#,
        );

        let error = load_plugin_from_directory(&root).expect_err("duplicates should fail");
        match error {
            PluginError::ManifestValidation(errors) => {
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::DuplicatePermission { permission }
                    if permission == "read"
                )));
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::DuplicateEntry { kind, name }
                    if *kind == "command" && name == "sync"
                )));
            }
            other => panic!("expected manifest validation errors, got {other}"),
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_rejects_claude_code_manifest_contracts_with_guidance() {
        let root = temp_dir("manifest-claude-code-contract");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "oh-my-claudecode",
  "version": "4.10.2",
  "description": "Claude Code plugin manifest",
  "hooks": {
    "SessionStart": ["scripts/session-start.mjs"]
  },
  "agents": ["agents/*.md"],
  "commands": ["commands/**/*.md"],
  "skills": "./skills/",
  "mcpServers": "./.mcp.json"
}"#,
        );

        let error = load_plugin_from_directory(&root)
            .expect_err("Claude Code plugin manifest should fail with guidance");
        let rendered = error.to_string();
        assert!(rendered.contains("field `skills` uses the Claude Code plugin contract"));
        assert!(rendered.contains("field `mcpServers` must be an object map"));
        assert!(rendered.contains("field `agents` uses the Claude Code plugin contract"));
        assert!(rendered.contains("field `commands` uses Claude Code-style directory globs"));
        assert!(rendered.contains("hook `SessionStart` uses the Claude Code lifecycle contract"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_rejects_missing_tool_or_command_paths() {
        let root = temp_dir("manifest-paths");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "missing-paths",
  "version": "1.0.0",
  "description": "Missing path validation",
  "permissions": ["write"],
  "tools": [
    {
      "name": "tool_one",
      "description": "Missing tool script",
      "inputSchema": {"type": "object"},
      "command": "./tools/missing.sh",
      "requiredPermission": "workspace-write"
    }
  ]
}"#,
        );

        let error = load_plugin_from_directory(&root).expect_err("missing paths should fail");
        assert!(error.to_string().contains("does not exist"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_rejects_missing_lifecycle_paths() {
        // given
        let root = temp_dir("manifest-lifecycle-paths");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "missing-lifecycle-paths",
  "version": "1.0.0",
  "description": "Missing lifecycle path validation",
  "lifecycle": {
    "Init": ["./lifecycle/init.sh"],
    "Shutdown": ["./lifecycle/shutdown.sh"]
  }
}"#,
        );

        // when
        let error =
            load_plugin_from_directory(&root).expect_err("missing lifecycle paths should fail");

        // then
        match error {
            PluginError::ManifestValidation(errors) => {
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::MissingPath { kind, path }
                    if *kind == "lifecycle command"
                        && path.ends_with(Path::new("lifecycle/init.sh"))
                )));
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::MissingPath { kind, path }
                    if *kind == "lifecycle command"
                        && path.ends_with(Path::new("lifecycle/shutdown.sh"))
                )));
            }
            other => panic!("expected manifest validation errors, got {other}"),
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_rejects_directory_command_paths() {
        // given
        let root = temp_dir("manifest-directory-paths");
        write_directory_path_plugin(&root, "directory-paths");

        // when
        let error =
            load_plugin_from_directory(&root).expect_err("directory command paths should fail");

        // then
        match error {
            PluginError::ManifestValidation(errors) => {
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::PathIsDirectory { kind, path }
                    if *kind == "hook" && path.ends_with(Path::new("hooks/pre-dir"))
                )));
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::PathIsDirectory { kind, path }
                    if *kind == "lifecycle command"
                        && path.ends_with(Path::new("lifecycle/init-dir"))
                )));
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::PathIsDirectory { kind, path }
                    if *kind == "tool" && path.ends_with(Path::new("tools/tool-dir"))
                )));
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::PathIsDirectory { kind, path }
                    if *kind == "command" && path.ends_with(Path::new("commands/sync-dir"))
                )));
            }
            other => panic!("expected manifest validation errors, got {other}"),
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_rejects_invalid_permissions() {
        let root = temp_dir("manifest-invalid-permissions");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "invalid-permissions",
  "version": "1.0.0",
  "description": "Invalid permission validation",
  "permissions": ["admin"]
}"#,
        );

        let error = load_plugin_from_directory(&root).expect_err("invalid permissions should fail");
        match error {
            PluginError::ManifestValidation(errors) => {
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::InvalidPermission { permission }
                    if permission == "admin"
                )));
            }
            other => panic!("expected manifest validation errors, got {other}"),
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_rejects_invalid_tool_required_permission() {
        let root = temp_dir("manifest-invalid-tool-permission");
        write_file(
            root.join("tools").join("echo.sh").as_path(),
            "#!/bin/sh\ncat\n",
        );
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "invalid-tool-permission",
  "version": "1.0.0",
  "description": "Invalid tool permission validation",
  "tools": [
    {
      "name": "echo_tool",
      "description": "Echo tool",
      "inputSchema": {"type": "object"},
      "command": "./tools/echo.sh",
      "requiredPermission": "admin"
    }
  ]
}"#,
        );

        let error =
            load_plugin_from_directory(&root).expect_err("invalid tool permission should fail");
        match error {
            PluginError::ManifestValidation(errors) => {
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::InvalidToolRequiredPermission {
                        tool_name,
                        permission
                    } if tool_name == "echo_tool" && permission == "admin"
                )));
            }
            other => panic!("expected manifest validation errors, got {other}"),
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_accumulates_multiple_validation_errors() {
        let root = temp_dir("manifest-multi-error");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "",
  "version": "1.0.0",
  "description": "",
  "permissions": ["admin"],
  "commands": [
    {"name": "", "description": "", "command": "./commands/missing.sh"}
  ]
}"#,
        );

        let error =
            load_plugin_from_directory(&root).expect_err("multiple manifest errors should fail");
        match error {
            PluginError::ManifestValidation(errors) => {
                assert!(errors.len() >= 4);
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::EmptyField { field } if *field == "name"
                )));
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::EmptyField { field }
                    if *field == "description"
                )));
                assert!(errors.iter().any(|error| matches!(
                    error,
                    PluginManifestValidationError::InvalidPermission { permission }
                    if permission == "admin"
                )));
            }
            other => panic!("expected manifest validation errors, got {other}"),
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn discovers_builtin_and_bundled_plugins() {
        let _guard = env_guard();
        let manager = PluginManager::new(PluginManagerConfig::new(temp_dir("discover")));
        let plugins = manager.list_plugins().expect("plugins should list");
        assert!(plugins
            .iter()
            .any(|plugin| plugin.metadata.kind == PluginKind::Builtin));
        assert!(plugins
            .iter()
            .any(|plugin| plugin.metadata.kind == PluginKind::Bundled));
    }

    #[test]
    fn installs_enables_updates_and_uninstalls_external_plugins() {
        let _guard = env_guard();
        let config_home = temp_dir("home");
        let source_root = temp_dir("source");
        write_external_plugin(&source_root, "demo", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let install = manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install should succeed");
        assert_eq!(install.plugin_id, "demo@external");
        assert!(manager
            .list_plugins()
            .expect("list plugins")
            .iter()
            .any(|plugin| plugin.metadata.id == "demo@external" && plugin.enabled));

        let hooks = manager.aggregated_hooks().expect("hooks should aggregate");
        assert_eq!(hooks.pre_tool_use.len(), 1);
        assert!(hooks.pre_tool_use[0].contains("pre.sh"));

        manager
            .disable("demo@external")
            .expect("disable should work");
        assert!(manager
            .aggregated_hooks()
            .expect("hooks after disable")
            .is_empty());
        manager.enable("demo@external").expect("enable should work");

        write_external_plugin(&source_root, "demo", "2.0.0");
        let update = manager.update("demo@external").expect("update should work");
        assert_eq!(update.old_version, "1.0.0");
        assert_eq!(update.new_version, "2.0.0");

        manager
            .uninstall("demo@external")
            .expect("uninstall should work");
        assert!(!manager
            .list_plugins()
            .expect("list plugins")
            .iter()
            .any(|plugin| plugin.metadata.id == "demo@external"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn auto_installs_bundled_plugins_into_the_registry() {
        let _guard = env_guard();
        let config_home = temp_dir("bundled-home");
        let bundled_root = temp_dir("bundled-root");
        write_bundled_plugin(&bundled_root.join("starter"), "starter", "0.1.0", false);

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        let manager = PluginManager::new(config);

        let installed = manager
            .list_installed_plugins()
            .expect("bundled plugins should auto-install");
        assert!(installed.iter().any(|plugin| {
            plugin.metadata.id == "starter@bundled"
                && plugin.metadata.kind == PluginKind::Bundled
                && !plugin.enabled
        }));

        let registry = manager.load_registry().expect("registry should exist");
        let record = registry
            .plugins
            .get("starter@bundled")
            .expect("bundled plugin should be recorded");
        assert_eq!(record.kind, PluginKind::Bundled);
        assert!(record.install_path.exists());

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    #[test]
    fn default_bundled_root_loads_repo_bundles_as_installed_plugins() {
        let _guard = env_guard();
        let config_home = temp_dir("default-bundled-home");

        // Use the repo bundled path explicitly so the test is reliable regardless
        // of where the binary runs from.
        let repo_bundled = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundled");
        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(repo_bundled.clone());
        let manager = PluginManager::new(config);

        if repo_bundled.exists() {
            let installed = manager
                .list_installed_plugins()
                .expect("bundled plugins should auto-install from repo path");
            assert!(installed
                .iter()
                .any(|plugin| plugin.metadata.id == "example-bundled@bundled"));
            assert!(installed
                .iter()
                .any(|plugin| plugin.metadata.id == "sample-hooks@bundled"));
        }

        let _ = fs::remove_dir_all(config_home);
    }

    #[test]
    fn default_bundled_root_is_not_blindly_cargo_manifest_dir() {
        // Verify that bundled_root() no longer unconditionally returns
        // CARGO_MANIFEST_DIR/bundled.  The returned path must either exist
        // (a valid runtime or dev location was found) OR differ from the
        // compile-time source path (a runtime-relative default was chosen).
        let resolved = PluginManager::bundled_root();
        let compile_time_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("bundled");

        // If the compile-time path does not exist (e.g. installed binary running
        // outside the source tree), the resolved path must NOT be the CARGO_MANIFEST_DIR
        // path, because that would re-introduce the original bug.
        if !compile_time_path.exists() {
            assert_ne!(
                resolved, compile_time_path,
                "bundled_root() must not fall back to CARGO_MANIFEST_DIR when that path \
                 does not exist — this would regress the root-owned-dir permission bug"
            );
        }
        // Either the path exists (dev scenario) or we got a runtime-relative path.
        // Either way the function should not panic or return an obviously wrong value.
        assert!(
            !resolved.as_os_str().is_empty(),
            "bundled_root() should return a non-empty path"
        );
    }

    #[test]
    fn override_bundled_root_is_used_exactly() {
        let _guard = env_guard();
        let config_home = temp_dir("override-bundled-home");
        let bundled_root = temp_dir("override-bundled-root");
        write_bundled_plugin(
            &bundled_root.join("override-plugin"),
            "override-plugin",
            "1.0.0",
            false,
        );

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        let manager = PluginManager::new(config);

        let installed = manager
            .list_installed_plugins()
            .expect("override bundled_root should be used");
        assert!(
            installed
                .iter()
                .any(|plugin| plugin.metadata.id == "override-plugin@bundled"),
            "only the override bundled root should be scanned, not CARGO_MANIFEST_DIR"
        );

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    #[test]
    fn explicit_nonexistent_bundled_root_does_not_fail() {
        // When bundled_root is explicitly configured to a path that does not exist,
        // plugin list should succeed with an empty bundled section rather than
        // returning an error (discover_plugin_dirs treats NotFound as empty).
        let _guard = env_guard();
        let config_home = temp_dir("missing-bundled-home");

        let nonexistent = temp_dir("nonexistent-bundled-XXXXXXXX");
        assert!(
            !nonexistent.exists(),
            "test precondition: path must not exist"
        );

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(nonexistent);
        let manager = PluginManager::new(config);

        // Should succeed with zero bundled plugins, not crash with ENOENT.
        let result = manager.list_installed_plugins();
        assert!(
            result.is_ok(),
            "nonexistent explicit bundled root should not fail: {result:?}"
        );
        let installed = result.unwrap();
        assert!(
            installed
                .iter()
                .all(|p| p.metadata.kind != PluginKind::Bundled),
            "no bundled plugins should be installed when bundled root path does not exist"
        );

        let _ = fs::remove_dir_all(config_home);
    }

    #[test]
    fn no_bundled_root_config_uses_auto_detection_without_panic() {
        // When bundled_root is not set (None), auto-detection runs.  The resolved
        // path should either exist (dev environment) or be a runtime-relative path
        // that doesn't cause a panic or EACCES crash.
        let _guard = env_guard();
        let config_home = temp_dir("auto-detect-bundled-home");

        // No bundled_root set — forces auto-detection in bundled_root().
        let config = PluginManagerConfig::new(&config_home);
        let manager = PluginManager::new(config);

        // Should not panic or return a hard IO error.
        let result = manager.list_installed_plugins();
        assert!(
            result.is_ok(),
            "auto-detected bundled root resolution must not fail: {result:?}"
        );

        let _ = fs::remove_dir_all(config_home);
    }

    #[test]
    fn bundled_sync_prunes_removed_bundled_registry_entries() {
        let _guard = env_guard();
        let config_home = temp_dir("bundled-prune-home");
        let bundled_root = temp_dir("bundled-prune-root");
        let stale_install_path = config_home
            .join("plugins")
            .join("installed")
            .join("stale-bundled-external");
        write_bundled_plugin(&bundled_root.join("active"), "active", "0.1.0", false);
        write_file(
            stale_install_path.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "stale",
  "version": "0.1.0",
  "description": "stale bundled plugin"
}"#,
        );

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        config.install_root = Some(config_home.join("plugins").join("installed"));
        let manager = PluginManager::new(config);

        let mut registry = InstalledPluginRegistry::default();
        registry.plugins.insert(
            "stale@bundled".to_string(),
            InstalledPluginRecord {
                kind: PluginKind::Bundled,
                id: "stale@bundled".to_string(),
                name: "stale".to_string(),
                version: "0.1.0".to_string(),
                description: "stale bundled plugin".to_string(),
                install_path: stale_install_path.clone(),
                source: PluginInstallSource::LocalPath {
                    path: bundled_root.join("stale"),
                },
                version_policy: PluginVersionPolicy::default(),
                installed_at_unix_ms: 1,
                updated_at_unix_ms: 1,
            },
        );
        manager.store_registry(&registry).expect("store registry");
        manager
            .write_enabled_state("stale@bundled", Some(true))
            .expect("seed bundled enabled state");

        let installed = manager
            .list_installed_plugins()
            .expect("bundled sync should succeed");
        assert!(installed
            .iter()
            .any(|plugin| plugin.metadata.id == "active@bundled"));
        assert!(!installed
            .iter()
            .any(|plugin| plugin.metadata.id == "stale@bundled"));

        let registry = manager.load_registry().expect("load registry");
        assert!(!registry.plugins.contains_key("stale@bundled"));
        assert!(!stale_install_path.exists());

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    #[test]
    fn installed_plugin_discovery_keeps_registry_entries_outside_install_root() {
        let _guard = env_guard();
        let config_home = temp_dir("registry-fallback-home");
        let bundled_root = temp_dir("registry-fallback-bundled");
        let install_root = config_home.join("plugins").join("installed");
        let external_install_path = temp_dir("registry-fallback-external");
        write_file(
            external_install_path.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "registry-fallback",
  "version": "1.0.0",
  "description": "Registry fallback plugin"
}"#,
        );

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        config.install_root = Some(install_root.clone());
        let manager = PluginManager::new(config);

        let mut registry = InstalledPluginRegistry::default();
        registry.plugins.insert(
            "registry-fallback@external".to_string(),
            InstalledPluginRecord {
                kind: PluginKind::External,
                id: "registry-fallback@external".to_string(),
                name: "registry-fallback".to_string(),
                version: "1.0.0".to_string(),
                description: "Registry fallback plugin".to_string(),
                install_path: external_install_path.clone(),
                source: PluginInstallSource::LocalPath {
                    path: external_install_path.clone(),
                },
                version_policy: PluginVersionPolicy::default(),
                installed_at_unix_ms: 1,
                updated_at_unix_ms: 1,
            },
        );
        manager.store_registry(&registry).expect("store registry");
        manager
            .write_enabled_state("stale-external@external", Some(true))
            .expect("seed stale external enabled state");

        let installed = manager
            .list_installed_plugins()
            .expect("registry fallback plugin should load");
        assert!(installed
            .iter()
            .any(|plugin| plugin.metadata.id == "registry-fallback@external"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
        let _ = fs::remove_dir_all(external_install_path);
    }

    #[test]
    fn installed_plugin_discovery_prunes_stale_registry_entries() {
        let _guard = env_guard();
        let config_home = temp_dir("registry-prune-home");
        let bundled_root = temp_dir("registry-prune-bundled");
        let install_root = config_home.join("plugins").join("installed");
        let missing_install_path = temp_dir("registry-prune-missing");

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        config.install_root = Some(install_root);
        let manager = PluginManager::new(config);

        let mut registry = InstalledPluginRegistry::default();
        registry.plugins.insert(
            "stale-external@external".to_string(),
            InstalledPluginRecord {
                kind: PluginKind::External,
                id: "stale-external@external".to_string(),
                name: "stale-external".to_string(),
                version: "1.0.0".to_string(),
                description: "stale external plugin".to_string(),
                install_path: missing_install_path.clone(),
                source: PluginInstallSource::LocalPath {
                    path: missing_install_path.clone(),
                },
                version_policy: PluginVersionPolicy::default(),
                installed_at_unix_ms: 1,
                updated_at_unix_ms: 1,
            },
        );
        manager.store_registry(&registry).expect("store registry");

        let installed = manager
            .list_installed_plugins()
            .expect("stale registry entries should be pruned");
        assert!(!installed
            .iter()
            .any(|plugin| plugin.metadata.id == "stale-external@external"));

        let registry = manager.load_registry().expect("load registry");
        assert!(!registry.plugins.contains_key("stale-external@external"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    #[test]
    fn persists_bundled_plugin_enable_state_across_reloads() {
        let _guard = env_guard();
        let config_home = temp_dir("bundled-state-home");
        let bundled_root = temp_dir("bundled-state-root");
        write_bundled_plugin(&bundled_root.join("starter"), "starter", "0.1.0", false);

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        let mut manager = PluginManager::new(config.clone());

        manager
            .enable("starter@bundled")
            .expect("enable bundled plugin should succeed");
        assert_eq!(
            load_enabled_plugins(&manager.settings_path()).get("starter@bundled"),
            Some(&true)
        );

        let mut reloaded_config = PluginManagerConfig::new(&config_home);
        reloaded_config.bundled_root = Some(bundled_root.clone());
        reloaded_config.enabled_plugins = load_enabled_plugins(&manager.settings_path());
        let reloaded_manager = PluginManager::new(reloaded_config);
        let reloaded = reloaded_manager
            .list_installed_plugins()
            .expect("bundled plugins should still be listed");
        assert!(reloaded
            .iter()
            .any(|plugin| { plugin.metadata.id == "starter@bundled" && plugin.enabled }));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    #[test]
    fn persists_bundled_plugin_disable_state_across_reloads() {
        let _guard = env_guard();
        let config_home = temp_dir("bundled-disabled-home");
        let bundled_root = temp_dir("bundled-disabled-root");
        write_bundled_plugin(&bundled_root.join("starter"), "starter", "0.1.0", true);

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        let mut manager = PluginManager::new(config);

        manager
            .disable("starter@bundled")
            .expect("disable bundled plugin should succeed");
        assert_eq!(
            load_enabled_plugins(&manager.settings_path()).get("starter@bundled"),
            Some(&false)
        );

        let mut reloaded_config = PluginManagerConfig::new(&config_home);
        reloaded_config.bundled_root = Some(bundled_root.clone());
        reloaded_config.enabled_plugins = load_enabled_plugins(&manager.settings_path());
        let reloaded_manager = PluginManager::new(reloaded_config);
        let reloaded = reloaded_manager
            .list_installed_plugins()
            .expect("bundled plugins should still be listed");
        assert!(reloaded
            .iter()
            .any(|plugin| { plugin.metadata.id == "starter@bundled" && !plugin.enabled }));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    #[test]
    fn validates_plugin_source_before_install() {
        let _guard = env_guard();
        let config_home = temp_dir("validate-home");
        let source_root = temp_dir("validate-source");
        write_external_plugin(&source_root, "validator", "1.0.0");
        let manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let manifest = manager
            .validate_plugin_source(source_root.to_str().expect("utf8 path"))
            .expect("manifest should validate");
        assert_eq!(manifest.name, "validator");
        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn plugin_registry_tracks_enabled_state_and_lookup() {
        let _guard = env_guard();
        let config_home = temp_dir("registry-home");
        let source_root = temp_dir("registry-source");
        write_external_plugin(&source_root, "registry-demo", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install should succeed");
        manager
            .disable("registry-demo@external")
            .expect("disable should succeed");

        let registry = manager.plugin_registry().expect("registry should build");
        let plugin = registry
            .get("registry-demo@external")
            .expect("installed plugin should be discoverable");
        assert_eq!(plugin.metadata().name, "registry-demo");
        assert!(!plugin.is_enabled());
        assert!(registry.contains("registry-demo@external"));
        assert!(!registry.contains("missing@external"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn plugin_registry_report_collects_load_failures_without_dropping_valid_plugins() {
        let _guard = env_guard();
        // given
        let config_home = temp_dir("report-home");
        let external_root = temp_dir("report-external");
        write_external_plugin(&external_root.join("valid"), "valid-report", "1.0.0");
        write_broken_plugin(&external_root.join("broken"), "broken-report");

        let mut config = PluginManagerConfig::new(&config_home);
        config.external_dirs = vec![external_root.clone()];
        let manager = PluginManager::new(config);

        // when
        let report = manager
            .plugin_registry_report()
            .expect("report should tolerate invalid external plugins");

        // then
        assert!(report.registry().contains("valid-report@external"));
        assert_eq!(report.failures().len(), 1);
        assert_eq!(report.failures()[0].kind, PluginKind::External);
        assert!(report.failures()[0]
            .plugin_root
            .ends_with(Path::new("broken")));
        assert!(report.failures()[0]
            .error()
            .to_string()
            .contains("does not exist"));

        let error = manager
            .plugin_registry()
            .expect_err("strict registry should surface load failures");
        match error {
            PluginError::LoadFailures(failures) => {
                assert_eq!(failures.len(), 1);
                assert!(failures[0].plugin_root.ends_with(Path::new("broken")));
            }
            other => panic!("expected load failures, got {other}"),
        }

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(external_root);
    }

    #[test]
    fn installed_plugin_registry_report_collects_load_failures_from_install_root() {
        let _guard = env_guard();
        // given
        let config_home = temp_dir("installed-report-home");
        let bundled_root = temp_dir("installed-report-bundled");
        let install_root = config_home.join("plugins").join("installed");
        write_lifecycle_plugin(&install_root.join("valid"), "installed-valid", "1.0.0");
        write_broken_plugin(&install_root.join("broken"), "installed-broken");

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        config.install_root = Some(install_root);
        let manager = PluginManager::new(config);

        // when
        let report = manager
            .installed_plugin_registry_report()
            .expect("installed report should tolerate invalid installed plugins");

        // then
        assert!(report.registry().contains("installed-valid@external"));
        let summaries = report.summaries();
        let valid = summaries
            .iter()
            .find(|summary| summary.metadata.id == "installed-valid@external")
            .expect("valid plugin summary should be present");
        assert_eq!(valid.lifecycle_state(), "disabled");
        assert_eq!(valid.lifecycle.init.len(), 1);
        assert_eq!(valid.lifecycle.shutdown.len(), 1);
        assert_eq!(report.failures().len(), 1);
        assert!(report.failures()[0]
            .plugin_root
            .ends_with(Path::new("broken")));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    #[test]
    fn rejects_plugin_sources_with_missing_hook_paths() {
        let _guard = env_guard();
        // given
        let config_home = temp_dir("broken-home");
        let source_root = temp_dir("broken-source");
        write_broken_plugin(&source_root, "broken");

        let manager = PluginManager::new(PluginManagerConfig::new(&config_home));

        // when
        let error = manager
            .validate_plugin_source(source_root.to_str().expect("utf8 path"))
            .expect_err("missing hook file should fail validation");

        // then
        assert!(error.to_string().contains("does not exist"));

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let install_error = manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect_err("install should reject invalid hook paths");
        assert!(install_error.to_string().contains("does not exist"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn rejects_plugin_sources_with_missing_failure_hook_paths() {
        let _guard = env_guard();
        // given
        let config_home = temp_dir("broken-failure-home");
        let source_root = temp_dir("broken-failure-source");
        write_broken_failure_hook_plugin(&source_root, "broken-failure");

        let manager = PluginManager::new(PluginManagerConfig::new(&config_home));

        // when
        let error = manager
            .validate_plugin_source(source_root.to_str().expect("utf8 path"))
            .expect_err("missing failure hook file should fail validation");

        // then
        assert!(error.to_string().contains("does not exist"));

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let install_error = manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect_err("install should reject invalid failure hook paths");
        assert!(install_error.to_string().contains("does not exist"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn plugin_registry_runs_initialize_and_shutdown_for_enabled_plugins() {
        let _guard = env_guard();
        let config_home = temp_dir("lifecycle-home");
        let source_root = temp_dir("lifecycle-source");
        let _ = write_lifecycle_plugin(&source_root, "lifecycle-demo", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let install = manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install should succeed");
        let log_path = install.install_path.join("lifecycle.log");

        let registry = manager.plugin_registry().expect("registry should build");
        let initialized = registry.initialize();
        #[cfg(target_os = "linux")]
        match initialized {
            Ok(()) => {
                registry.shutdown().expect("shutdown should succeed");
                let log = fs::read_to_string(&log_path).expect("lifecycle log should exist");
                assert_eq!(log, "init\nshutdown\n");
            }
            Err(error) => assert!(
                is_expected_linux_sandbox_refusal(&error.to_string()),
                "unexpected Linux sandbox error: {error}"
            ),
        }
        #[cfg(not(target_os = "linux"))]
        {
            let error = initialized.expect_err("non-Linux external lifecycle must fail closed");
            assert!(error
                .to_string()
                .contains("requires the Linux/systemd sandbox"));
            assert!(!log_path.exists());
        }

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn aggregates_and_executes_plugin_tools() {
        let _guard = env_guard();
        let config_home = temp_dir("tool-home");
        let source_root = temp_dir("tool-source");
        write_tool_plugin(&source_root, "tool-demo", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install should succeed");

        let tools = manager.aggregated_tools().expect("tools should aggregate");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].definition().name, "plugin_echo");
        assert_eq!(tools[0].required_permission(), "workspace-write");

        let execution = tools[0].execute(&serde_json::json!({ "message": "hello" }));
        #[cfg(target_os = "linux")]
        match execution {
            Ok(output) => {
                let payload: Value = serde_json::from_str(&output).expect("valid json");
                assert_eq!(payload["plugin"], "tool-demo@external");
                assert_eq!(payload["tool"], "plugin_echo");
                assert_eq!(payload["input"]["message"], "hello");
            }
            Err(error) => assert!(
                is_expected_linux_sandbox_refusal(&error.to_string()),
                "unexpected Linux sandbox error: {error}"
            ),
        }
        #[cfg(not(target_os = "linux"))]
        {
            let error = execution.expect_err("non-Linux external tool must fail closed");
            assert!(error
                .to_string()
                .contains("requires the Linux/systemd sandbox"));
        }

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn external_plugin_tool_without_subprocess_opt_in_is_refused() {
        let _guard = env_guard();
        let config_home = temp_dir("tool-no-opt-home");
        let source_root = temp_dir("tool-no-opt-source");
        let script_path = source_root.join("tools").join("echo-json.sh");
        write_file(&script_path, "#!/bin/sh\ncat\n");
        write_file(
            source_root.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "tool-no-opt",
  "version": "1.0.0",
  "description": "tool plugin without subprocess opt-in",
  "permissions": ["read"],
  "tools": [
    {
      "name": "plugin_echo",
      "description": "Echo JSON input",
      "inputSchema": { "type": "object" },
      "command": "./tools/echo-json.sh",
      "requiredPermission": "read-only"
    }
  ]
}"#,
        );

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install should succeed");
        let tools = manager.aggregated_tools().expect("tools should aggregate");
        let error = tools[0]
            .execute(&serde_json::json!({ "message": "hello" }))
            .expect_err("default external subprocess should be refused");
        assert!(error.to_string().contains("FR-2.13 requires an OS sandbox"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn external_plugin_lifecycle_without_subprocess_opt_in_is_refused() {
        let _guard = env_guard();
        let config_home = temp_dir("lifecycle-no-opt-home");
        let source_root = temp_dir("lifecycle-no-opt-source");
        write_file(
            source_root.join("lifecycle").join("init.sh").as_path(),
            "#!/bin/sh\nprintf 'should-not-run\\n' > lifecycle.log\n",
        );
        write_file(
            source_root.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "lifecycle-no-opt",
  "version": "1.0.0",
  "description": "lifecycle plugin without subprocess opt-in",
  "lifecycle": {
    "Init": ["./lifecycle/init.sh"]
  }
}"#,
        );

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let install = manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install should succeed");
        let registry = manager.plugin_registry().expect("registry should build");
        let error = registry
            .initialize()
            .expect_err("default external lifecycle subprocess should be refused");
        assert!(error.to_string().contains("FR-2.13 requires an OS sandbox"));
        assert!(!install.install_path.join("lifecycle.log").exists());

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn list_installed_plugins_scans_install_root_without_registry_entries() {
        let _guard = env_guard();
        let config_home = temp_dir("installed-scan-home");
        let bundled_root = temp_dir("installed-scan-bundled");
        let install_root = config_home.join("plugins").join("installed");
        let installed_plugin_root = install_root.join("scan-demo");
        write_file(
            installed_plugin_root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "scan-demo",
  "version": "1.0.0",
  "description": "Scanned from install root"
}"#,
        );

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        config.install_root = Some(install_root);
        let manager = PluginManager::new(config);

        let installed = manager
            .list_installed_plugins()
            .expect("installed plugins should scan directories");
        assert!(installed
            .iter()
            .any(|plugin| plugin.metadata.id == "scan-demo@external"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    #[test]
    fn list_installed_plugins_scans_packaged_manifests_in_install_root() {
        let _guard = env_guard();
        let config_home = temp_dir("installed-packaged-scan-home");
        let bundled_root = temp_dir("installed-packaged-scan-bundled");
        let install_root = config_home.join("plugins").join("installed");
        let installed_plugin_root = install_root.join("scan-packaged");
        write_file(
            installed_plugin_root.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "scan-packaged",
  "version": "1.0.0",
  "description": "Packaged manifest in install root"
}"#,
        );

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        config.install_root = Some(install_root);
        let manager = PluginManager::new(config);

        let installed = manager
            .list_installed_plugins()
            .expect("installed plugins should scan packaged manifests");
        assert!(installed
            .iter()
            .any(|plugin| plugin.metadata.id == "scan-packaged@external"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    /// Regression test for ROADMAP #41: verify that `CLAW_CONFIG_HOME` isolation prevents
    /// host `~/.claw/plugins/` from bleeding into test runs.
    #[test]
    fn claw_config_home_isolation_prevents_host_plugin_leakage() {
        let _guard = env_guard();

        // Create a temp directory to act as our isolated CLAW_CONFIG_HOME
        let config_home = temp_dir("isolated-home");
        let bundled_root = temp_dir("isolated-bundled");

        // Set CLAW_CONFIG_HOME to our temp directory
        std::env::set_var("CLAW_CONFIG_HOME", &config_home);

        // Create a test fixture plugin in the isolated config home
        let install_root = config_home.join("plugins").join("installed");
        let fixture_plugin_root = install_root.join("isolated-test-plugin");
        write_file(
            fixture_plugin_root.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "isolated-test-plugin",
  "version": "1.0.0",
  "description": "Test fixture plugin in isolated config home"
}"#,
        );

        // Create PluginManager with isolated bundled_root - it should use the temp config_home, not host ~/.claw/
        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        let manager = PluginManager::new(config);

        // List installed plugins - should only see the test fixture, not host plugins
        let installed = manager
            .list_installed_plugins()
            .expect("installed plugins should list");

        // Verify we only see the test fixture plugin
        assert_eq!(
            installed.len(),
            1,
            "should only see the test fixture plugin, not host ~/.claw/plugins/"
        );
        assert_eq!(
            installed[0].metadata.id, "isolated-test-plugin@external",
            "should see the test fixture plugin"
        );

        // Cleanup
        std::env::remove_var("CLAW_CONFIG_HOME");
        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    #[test]
    fn plugin_lifecycle_handles_parallel_execution() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use std::sync::Arc;
        use std::thread;

        let _guard = env_guard();

        // Shared base directory for all threads
        let base_dir = temp_dir("parallel-base");

        // Track successful installations and any errors
        let success_count = Arc::new(AtomicUsize::new(0));
        let error_count = Arc::new(AtomicUsize::new(0));
        let refusal_count = Arc::new(AtomicUsize::new(0));

        // Spawn multiple threads to install plugins simultaneously
        let mut handles = Vec::new();
        for thread_id in 0..5 {
            let base_dir = base_dir.clone();
            let success_count = Arc::clone(&success_count);
            let error_count = Arc::clone(&error_count);
            let refusal_count = Arc::clone(&refusal_count);

            let handle = thread::spawn(move || {
                // Create unique directories for this thread
                let config_home = base_dir.join(format!("config-{thread_id}"));
                let source_root = base_dir.join(format!("source-{thread_id}"));

                // Write lifecycle plugin for this thread
                let _log_path =
                    write_lifecycle_plugin(&source_root, &format!("parallel-{thread_id}"), "1.0.0");

                // Create PluginManager and install
                let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
                let install_result = manager.install(source_root.to_str().expect("utf8 path"));

                match install_result {
                    Ok(install) => {
                        let log_path = install.install_path.join("lifecycle.log");

                        // Initialize and shutdown the registry to trigger lifecycle hooks
                        let registry = manager.plugin_registry();
                        match registry {
                            Ok(registry) => match registry.initialize() {
                                Ok(()) if registry.shutdown().is_ok() => {
                                    if fs::read_to_string(&log_path)
                                        .is_ok_and(|log| log == "init\nshutdown\n")
                                    {
                                        success_count.fetch_add(1, AtomicOrdering::Relaxed);
                                    } else {
                                        error_count.fetch_add(1, AtomicOrdering::Relaxed);
                                    }
                                }
                                Err(error)
                                    if is_expected_linux_sandbox_refusal(&error.to_string())
                                        || (!cfg!(target_os = "linux")
                                            && error.to_string().contains(
                                                "requires the Linux/systemd sandbox",
                                            )) =>
                                {
                                    refusal_count.fetch_add(1, AtomicOrdering::Relaxed);
                                }
                                _ => {
                                    error_count.fetch_add(1, AtomicOrdering::Relaxed);
                                }
                            },
                            Err(_) => {
                                error_count.fetch_add(1, AtomicOrdering::Relaxed);
                            }
                        }
                    }
                    Err(_) => {
                        error_count.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                }
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("thread should complete");
        }

        // Verify all threads succeeded without collisions
        let successes = success_count.load(AtomicOrdering::Relaxed);
        let errors = error_count.load(AtomicOrdering::Relaxed);
        let refusals = refusal_count.load(AtomicOrdering::Relaxed);

        #[cfg(target_os = "linux")]
        assert_eq!(
            successes + refusals,
            5,
            "each Linux execution must run sandboxed or fail closed"
        );
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(
                successes, 0,
                "non-Linux external lifecycle must not execute"
            );
            assert_eq!(refusals, 5, "all non-Linux executions must fail closed");
        }
        assert_eq!(
            errors, 0,
            "no errors should occur during parallel execution"
        );

        // Cleanup
        let _ = fs::remove_dir_all(base_dir);
    }

    fn is_expected_linux_sandbox_refusal(message: &str) -> bool {
        message.contains("systemd-run")
            || message.contains("Failed to connect to bus")
            || message.contains("No medium found")
            || message.contains("required Linux sandbox launcher")
    }

    #[test]
    fn loads_manifest_extensions_and_prompts() {
        let _guard = env_guard();
        let root = temp_dir("manifest-extensions");
        write_file(
            root.join("tools").join("inspect.sh").as_path(),
            "#!/bin/sh\ncat\n",
        );
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "ext-demo",
  "version": "1.0.0",
  "description": "Extended manifest",
  "permissions": ["read"],
  "capabilities": { "tools": true, "prompts": true, "workflows": true },
  "tools": [
    {
      "name": "inspect",
      "description": "Inspect input",
      "inputSchema": { "type": "object" },
      "command": "./tools/inspect.sh",
      "requiredPermission": "read-only"
    }
  ],
  "mcpServers": {
    "triage": {
      "transport": "sse",
      "requiredPermission": "read-only",
      "url": "https://example.invalid/mcp",
      "protocolVersion": "2025-03-26",
      "heartbeat": { "intervalMs": 1500, "timeoutMs": 4000 },
      "capabilities": {
        "prompts": [
          {
            "name": "triage",
            "description": "Triage prompt",
            "arguments": [
              { "name": "service", "required": true, "schema": { "type": "string" } }
            ]
          }
        ]
      }
    }
  },
  "prompts": [
    {
      "name": "restart-plan",
      "description": "Restart plan prompt",
      "arguments": [
        { "name": "service", "required": true, "schema": { "type": "string" } }
      ]
    }
  ]
}"#,
        );

        let manifest = load_plugin_from_directory(&root).expect("manifest should load");
        assert!(manifest.capabilities.prompts);
        assert_eq!(manifest.prompts.len(), 1);
        assert_eq!(manifest.mcp_servers.len(), 1);
        let server = manifest.mcp_servers.get("triage").expect("mcp server");
        assert_eq!(server.transport, PluginMcpTransport::Sse);
        assert_eq!(server.heartbeat.interval_ms, 1500);
        assert_eq!(server.capabilities.prompts.len(), 1);

        let config_home = temp_dir("manifest-extensions-home");
        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(root.to_str().expect("utf8 path"))
            .expect("install should work");
        assert_eq!(
            manager.aggregated_prompts().expect("prompts"),
            manifest.prompts
        );
        assert_eq!(
            manager.aggregated_mcp_servers().expect("mcp servers").len(),
            1
        );

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_rejects_invalid_mcp_heartbeat_bounds_and_types() {
        let cases = [
            (
                "zero-interval",
                r#""heartbeat": { "intervalMs": 0, "timeoutMs": 5000 }"#,
                "heartbeat.intervalMs",
            ),
            (
                "oversize-timeout",
                r#""heartbeat": { "intervalMs": 30000, "timeoutMs": 300001 }"#,
                "heartbeat.timeoutMs",
            ),
            (
                "malformed-interval",
                r#""heartbeat": { "intervalMs": "bad", "timeoutMs": 5000 }"#,
                "invalid type",
            ),
        ];

        for (label, heartbeat, expected) in cases {
            let _guard = env_guard();
            let root = temp_dir(&format!("manifest-mcp-heartbeat-{label}"));
            write_file(
                root.join("tools").join("inspect.sh").as_path(),
                "#!/bin/sh\ncat\n",
            );
            write_file(
                root.join(MANIFEST_FILE_NAME).as_path(),
                format!(
                    r#"{{
  "name": "mcp-heartbeat-{label}",
  "version": "1.0.0",
  "description": "MCP heartbeat bounds",
  "permissions": ["read"],
  "mcpServers": {{
    "triage": {{
      "transport": "stdio",
      "requiredPermission": "read-only",
      "command": "./tools/inspect.sh",
      {heartbeat},
      "capabilities": {{
        "tools": [
          {{
            "name": "inspect",
            "description": "Inspect input",
            "inputSchema": {{ "type": "object" }}
          }}
        ]
      }}
    }}
  }}
}}"#
                )
                .as_str(),
            );

            let error =
                load_plugin_from_directory(&root).expect_err("invalid heartbeat should fail");
            assert!(
                error.to_string().contains(expected),
                "{label} error did not contain {expected}: {error}"
            );

            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn rejects_missing_declared_permission_for_tools() {
        let _guard = env_guard();
        let root = temp_dir("manifest-permission");
        write_file(
            root.join("tools").join("inspect.sh").as_path(),
            "#!/bin/sh\ncat\n",
        );
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "perm-demo",
  "version": "1.0.0",
  "description": "Permission manifest",
  "tools": [
    {
      "name": "inspect",
      "description": "Inspect input",
      "inputSchema": { "type": "object" },
      "command": "./tools/inspect.sh",
      "requiredPermission": "workspace-write"
    }
  ]
}"#,
        );

        let error = load_plugin_from_directory(&root).expect_err("missing permission should fail");
        assert!(error.to_string().contains("does not declare `write`"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plugin_tool_validates_input_schema_before_spawn() {
        let tool = PluginTool::new(
            "schema-demo@external",
            "schema-demo",
            PluginToolDefinition {
                name: "inspect".to_string(),
                description: None,
                input_schema: serde_json::json!({
                    "type": "object",
                    "required": ["target"],
                    "properties": {
                        "target": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
                output_schema: None,
            },
            "missing-command-that-should-not-start",
            Vec::new(),
            PluginToolPermission::ReadOnly,
            None,
        );

        let error = tool
            .execute(&serde_json::json!({ "extra": true }))
            .expect_err("schema validation should fail before spawn");
        assert!(error
            .to_string()
            .contains("missing required field `target`"));
    }

    #[test]
    fn json_schema_validator_covers_common_keywords() {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["name", "ports", "mode", "count"],
            "properties": {
                "name": { "type": "string", "pattern": "^svc" },
                "ports": {
                    "type": "array",
                    "items": { "type": "integer", "minimum": 1, "maximum": 65535 }
                },
                "mode": { "enum": ["inspect", "plan"] },
                "count": {
                    "allOf": [
                        { "type": "integer" },
                        { "minimum": 1 }
                    ]
                },
                "selector": {
                    "oneOf": [
                        { "type": "string", "pattern": "service$" },
                        { "type": "integer" }
                    ]
                },
                "filter": {
                    "anyOf": [
                        { "type": "string", "pattern": "log" },
                        { "type": "null" }
                    ]
                }
            },
            "additionalProperties": false
        });
        let valid = serde_json::json!({
            "name": "svc-a",
            "ports": [80, 443],
            "mode": "inspect",
            "count": 1,
            "selector": "main-service",
            "filter": null
        });
        validate_json_schema_value(&schema, &valid, "input").expect("schema should pass");

        let invalid = serde_json::json!({
            "name": "db-a",
            "ports": [70000],
            "mode": "mutate",
            "count": 0,
            "selector": "main-service",
            "filter": "metrics"
        });
        let error =
            validate_json_schema_value(&schema, &invalid, "input").expect_err("schema should fail");
        let rendered = error.to_string();
        assert!(
            rendered.contains("pattern")
                || rendered.contains("maximum")
                || rendered.contains("enum")
                || rendered.contains("minimum"),
            "schema failure should cite the violated keyword, got: {rendered}"
        );
    }

    #[test]
    fn plugin_tool_rejects_danger_full_access_without_approval_policy() {
        let tool = PluginTool::new(
            "danger-demo@external",
            "danger-demo",
            PluginToolDefinition {
                name: "mutate".to_string(),
                description: None,
                input_schema: serde_json::json!({ "type": "object" }),
                output_schema: None,
            },
            "missing-command-that-should-not-start",
            Vec::new(),
            PluginToolPermission::DangerFullAccess,
            None,
        );

        let error = tool
            .execute(&serde_json::json!({}))
            .expect_err("danger-full-access should be rejected before spawn");
        assert!(error.to_string().contains("explicit operator approval"));
    }

    #[test]
    fn lifecycle_permission_is_derived_from_manifest_permissions() {
        assert_eq!(
            lifecycle_child_permission(&[PluginPermission::Read]),
            PluginToolPermission::ReadOnly
        );
        assert_eq!(
            lifecycle_child_permission(&[PluginPermission::Read, PluginPermission::Write]),
            PluginToolPermission::WorkspaceWrite
        );
    }

    #[test]
    fn plugin_mcp_servers_require_read_only_policy_and_are_hardened() {
        let _guard = env_guard();
        let root = temp_dir("plugin-mcp-policy");
        write_file(root.join("server.sh").as_path(), "#!/bin/sh\ncat\n");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "mcp-policy",
  "version": "1.0.0",
  "description": "MCP policy",
  "permissions": ["read"],
  "mcpServers": {
    "local": {
      "transport": "stdio",
      "requiredPermission": "read-only",
      "command": "./server.sh"
    }
  }
}"#,
        );

        let manifest = load_plugin_from_directory(&root).expect("manifest should load");
        let server = manifest.mcp_servers.get("local").expect("server");
        assert_eq!(
            server.required_permission,
            Some(PluginToolPermission::ReadOnly)
        );
        assert_eq!(server.env["CLAWD_SANDBOX"], "process-isolated");
        assert_eq!(server.env["CLAWD_NETWORK_DISABLED"], "1");
        assert!(server
            .command
            .as_deref()
            .expect("command")
            .contains("server.sh"));
        assert_eq!(server.tool_call_timeout_ms, Some(PLUGIN_TOOL_TIMEOUT_MS));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plugin_mcp_servers_reject_missing_or_dangerous_policy() {
        let _guard = env_guard();
        let root = temp_dir("plugin-mcp-policy-reject");
        write_file(root.join("server.sh").as_path(), "#!/bin/sh\ncat\n");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "mcp-policy-reject",
  "version": "1.0.0",
  "description": "MCP policy reject",
  "permissions": ["read", "execute"],
  "mcpServers": {
    "missing": {
      "transport": "stdio",
      "command": "./server.sh"
    },
    "danger": {
      "transport": "stdio",
      "requiredPermission": "danger-full-access",
      "command": "./server.sh"
    }
  }
}"#,
        );

        let error = load_plugin_from_directory(&root).expect_err("manifest should fail");
        let rendered = error.to_string();
        assert!(rendered.contains("requires requiredPermission"));
        assert!(rendered.contains("limited to read-only"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn resolves_dependency_order_and_rejects_cycles() {
        let _guard = env_guard();
        let config_home = temp_dir("dependency-home");
        let source_root = temp_dir("dependency-source");
        let first = source_root.join("first");
        let second = source_root.join("second");

        write_file(
            first.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "first",
  "version": "1.0.0",
  "description": "First plugin"
}"#,
        );
        write_file(
            second.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "second",
  "version": "1.0.0",
  "description": "Second plugin",
  "dependencies": [
    { "name": "first" }
  ]
}"#,
        );

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(first.to_str().expect("utf8 path"))
            .expect("install first");
        manager
            .install(second.to_str().expect("utf8 path"))
            .expect("install second");
        let registry = manager.plugin_registry().expect("registry should build");
        let order = registry.dependency_order().expect("order should resolve");
        let first_index = order
            .iter()
            .position(|plugin_id| plugin_id == "first@external")
            .expect("first should be ordered");
        let second_index = order
            .iter()
            .position(|plugin_id| plugin_id == "second@external")
            .expect("second should be ordered");
        assert!(first_index < second_index);

        let cycle_a = source_root.join("cycle-a");
        let cycle_b = source_root.join("cycle-b");
        write_file(
            cycle_a.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "cycle-a",
  "version": "1.0.0",
  "description": "Cycle A",
  "dependencies": [
    { "name": "cycle-b" }
  ]
}"#,
        );
        write_file(
            cycle_b.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "cycle-b",
  "version": "1.0.0",
  "description": "Cycle B",
  "dependencies": [
    { "name": "cycle-a" }
  ]
}"#,
        );
        let mut cycle_manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        cycle_manager
            .install(cycle_a.to_str().expect("utf8 path"))
            .expect("install cycle a");
        cycle_manager
            .install(cycle_b.to_str().expect("utf8 path"))
            .expect("install cycle b");
        let cycle_registry = cycle_manager
            .plugin_registry()
            .expect("registry should load");
        let error = cycle_registry
            .dependency_order()
            .expect_err("cycle should fail");
        assert!(error.to_string().contains("cycle"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn rejects_dependency_version_mismatch() {
        let _guard = env_guard();
        let config_home = temp_dir("dependency-version-home");
        let source_root = temp_dir("dependency-version-source");
        let first = source_root.join("first");
        let second = source_root.join("second");

        write_file(
            first.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "first",
  "version": "1.0.0",
  "description": "First plugin"
}"#,
        );
        write_file(
            second.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "second",
  "version": "1.0.0",
  "description": "Second plugin",
  "dependencies": [
    { "name": "first", "versionRequirement": ">=2.0.0" }
  ]
}"#,
        );

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(first.to_str().expect("utf8 path"))
            .expect("install first");
        manager
            .install(second.to_str().expect("utf8 path"))
            .expect("install second");
        let registry = manager.plugin_registry().expect("registry should build");
        let error = registry
            .dependency_order()
            .expect_err("version mismatch should fail");
        assert!(error.to_string().contains("active version is `1.0.0`"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn supports_version_rollback_and_multi_version_listing() {
        let _guard = env_guard();
        let config_home = temp_dir("rollback-home");
        let source_root = temp_dir("rollback-source");
        write_external_plugin(&source_root, "rollback-demo", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install should succeed");
        write_external_plugin(&source_root, "rollback-demo", "2.0.0");
        manager.update("rollback-demo@external").expect("update");

        let versions = manager
            .list_versions("rollback-demo@external")
            .expect("versions should list");
        assert!(versions.iter().any(|version| version == "1.0.0"));
        assert!(versions.iter().any(|version| version == "2.0.0"));

        let rollback = manager
            .rollback("rollback-demo@external", "1.0.0")
            .expect("rollback should succeed");
        assert_eq!(rollback.previous_version, "2.0.0");
        assert_eq!(rollback.active_version, "1.0.0");

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn prunes_archived_versions_using_keep_versions_policy() {
        let _guard = env_guard();
        let config_home = temp_dir("version-prune-home");
        let source_root = temp_dir("version-prune-source");
        for version in ["1.0.0", "2.0.0", "3.0.0"] {
            write_file(
                source_root.join(MANIFEST_RELATIVE_PATH).as_path(),
                format!(
                    r#"{{
  "name": "prune-demo",
  "version": "{version}",
  "description": "Prune demo",
  "versionPolicy": {{ "keepVersions": 1 }}
}}"#
                )
                .as_str(),
            );
            let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
            if version == "1.0.0" {
                manager
                    .install(source_root.to_str().expect("utf8 path"))
                    .expect("install should succeed");
            } else {
                manager.update("prune-demo@external").expect("update");
            }
        }

        let manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let versions = manager
            .list_versions("prune-demo@external")
            .expect("versions should list");
        assert_eq!(versions, vec!["2.0.0".to_string(), "3.0.0".to_string()]);

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn builtin_ops_plugins_are_declared() {
        let ops = builtin_ops_manifests();
        assert_eq!(ops.len(), 9);
        assert!(ops.iter().any(|plugin| plugin.name == "disk_cleaner"));
        assert!(ops
            .iter()
            .any(|plugin| plugin.ops_permissions[0].rollback_required));
    }

    #[test]
    fn builtin_ops_executor_returns_audited_plan_without_mutation() {
        let plugin = builtin_plugins()
            .into_iter()
            .find(|plugin| plugin.metadata().id == "service_manager@builtin")
            .expect("service manager builtin");
        let tool = plugin.tools().first().expect("ops tool");
        let output = tool
            .execute(&serde_json::json!({
                "target": "demo",
                "action": "restart",
                "dryRun": false,
                "confirm": false
            }))
            .expect("builtin ops execution should return plan");
        let value: Value = serde_json::from_str(&output).expect("json output");
        assert_eq!(value["status"], "requires_confirmation");
        assert_eq!(value["audit"]["mutationPerformed"], false);
        assert_eq!(value["rollback"]["available"], true);
    }

    #[test]
    fn every_builtin_ops_plugin_has_a_fixed_linux_dry_run_command() {
        let cases = [
            ("disk_cleaner", serde_json::json!({"action": "inspect"})),
            (
                "service_manager",
                serde_json::json!({"action": "inspect", "target": "sshd"}),
            ),
            (
                "user_manager",
                serde_json::json!({"action": "inspect", "target": "root"}),
            ),
            ("log_analyzer", serde_json::json!({"action": "inspect"})),
            (
                "package_manager",
                serde_json::json!({"action": "inspect", "target": "bash"}),
            ),
            ("firewall_manager", serde_json::json!({"action": "inspect"})),
            ("cron_manager", serde_json::json!({"action": "inspect"})),
            (
                "network_diagnostics",
                serde_json::json!({"action": "inspect"}),
            ),
            (
                "backup_manager",
                serde_json::json!({"action": "inspect", "target": "."}),
            ),
        ];
        let plugins = builtin_plugins();
        for (name, input) in cases {
            let plugin = plugins
                .iter()
                .find(|plugin| plugin.metadata().id == format!("{name}@builtin"))
                .unwrap_or_else(|| panic!("missing {name}"));
            let output = plugin.tools()[0]
                .execute(&input)
                .unwrap_or_else(|error| panic!("{name} dry-run failed: {error}"));
            let value: Value = serde_json::from_str(&output).expect("json");
            assert_eq!(value["status"], "dry_run", "{name}");
            assert_eq!(value["audit"]["mutationPerformed"], false, "{name}");
            assert_eq!(value["plan"][0]["command"]["shell"], false, "{name}");
            let program = value["plan"][0]["command"]["program"]
                .as_str()
                .expect("program");
            assert!(program.starts_with("/usr/"), "{name}: {program}");
            assert!(!output.contains("cmd.exe"), "{name}");
            assert!(!output.contains("PowerShell"), "{name}");
        }
    }

    #[test]
    fn builtin_ops_rejects_option_injection_before_spawning() {
        let plugin = builtin_plugins()
            .into_iter()
            .find(|plugin| plugin.metadata().id == "service_manager@builtin")
            .expect("service manager");
        let error = plugin.tools()[0]
            .execute(&serde_json::json!({
                "action": "inspect",
                "target": "--system"
            }))
            .expect_err("option-like target must fail");
        assert!(error.to_string().contains("invalid systemd unit"));
    }
}
