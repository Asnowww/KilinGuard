mod hooks;
#[cfg(test)]
pub mod test_isolation;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub use hooks::{HookEvent, HookRunResult, HookRunner};

const EXTERNAL_MARKETPLACE: &str = "external";
const BUILTIN_MARKETPLACE: &str = "builtin";
const BUNDLED_MARKETPLACE: &str = "bundled";
const SETTINGS_FILE_NAME: &str = "settings.json";
const REGISTRY_FILE_NAME: &str = "installed.json";
const PLUGIN_VERSIONS_DIR_NAME: &str = ".versions";
const MANIFEST_FILE_NAME: &str = "plugin.json";
const MANIFEST_RELATIVE_PATH: &str = ".claude-plugin/plugin.json";
const BUILTIN_OPS_PLACEHOLDER_COMMAND: &str = "__claw_builtin_ops_placeholder__";
const BUILTIN_OPS_EXECUTOR_COMMAND: &str = "__claw_builtin_ops_executor__";
const PLUGIN_TOOL_TIMEOUT_MS: u64 = 30_000;
const PLUGIN_LIFECYCLE_TIMEOUT_MS: u64 = 30_000;
pub const PLUGIN_HOT_RELOAD_DEADLINE_MS: u64 = 3_000;
const PLUGIN_COMMAND_MAX_ARGS: usize = 32;
const PLUGIN_COMMAND_MAX_ARG_BYTES: usize = 4096;
const PLUGIN_CHILD_POLL_MS: u64 = 25;
const MIN_PLUGIN_MCP_TIMEOUT_MS: u64 = 1;
const MAX_PLUGIN_MCP_TIMEOUT_MS: u64 = 300_000;
const MIN_PLUGIN_MCP_HEARTBEAT_INTERVAL_MS: u64 = 1;
const MAX_PLUGIN_MCP_HEARTBEAT_INTERVAL_MS: u64 = 3_600_000;
const PLUGIN_MANIFEST_SCHEMA_VERSION: u64 = 1;
const PLUGIN_MANIFEST_MAX_BYTES: u64 = 256 * 1024;
const PLUGIN_MANIFEST_NAME_MAX_CHARS: usize = 64;
const PLUGIN_MANIFEST_ID_MAX_CHARS: usize = 64;
const PLUGIN_MANIFEST_VERSION_MAX_CHARS: usize = 64;
const PLUGIN_MANIFEST_DESCRIPTION_MAX_CHARS: usize = 4096;
const PLUGIN_MANIFEST_SIGNATURE_MAX_CHARS: usize = 4096;
const PLUGIN_MANIFEST_MAX_DECLARATIONS: usize = 128;
const PLUGIN_PERMISSION_VALUE_MAX_CHARS: usize = 512;
const PLUGIN_ERROR_SURFACE_MAX_CHARS: usize = 2048;
const PLUGIN_CHILD_OUTPUT_LIMIT: usize = 1024 * 1024;
const PLUGIN_LOCK_TIMEOUT_MS: u64 = 5_000;
const PLUGIN_LOCK_POLL_MS: u64 = 25;
const PLUGIN_SCAN_MAX_DEPTH: usize = 4;
const PLUGIN_SCAN_MAX_ENTRIES: usize = 1024;
const PLUGIN_SCAN_MAX_ROOTS: usize = 64;
const PLUGIN_SCAN_MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
const PLUGIN_SCAN_MAX_DURATION_MS: u128 = 5_000;
const PLUGIN_SCAN_MAX_WARNINGS: usize = 64;
const PLUGIN_SCAN_WARNING_MAX_CHARS: usize = 512;

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
    pub manifest: PluginManifestMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifestMetadata {
    pub schema_version: u64,
    pub legacy: bool,
    pub hash: String,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub signature_verified: bool,
    #[serde(default)]
    pub signature_warning: Option<String>,
    #[serde(default)]
    pub declared_id: Option<String>,
    #[serde(default)]
    pub entrypoint: Option<PluginEntrypoint>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl PluginManifestMetadata {
    #[must_use]
    pub fn builtin() -> Self {
        Self {
            schema_version: PLUGIN_MANIFEST_SCHEMA_VERSION,
            legacy: false,
            hash: "builtin".to_string(),
            signature: None,
            signature_verified: false,
            signature_warning: None,
            declared_id: None,
            entrypoint: None,
            warnings: Vec::new(),
        }
    }
}

impl Default for PluginManifestMetadata {
    fn default() -> Self {
        Self {
            schema_version: PLUGIN_MANIFEST_SCHEMA_VERSION,
            legacy: true,
            hash: String::new(),
            signature: None,
            signature_verified: false,
            signature_warning: None,
            declared_id: None,
            entrypoint: None,
            warnings: vec![
                "legacy manifest omitted schemaVersion; normalized to schemaVersion 1".to_string(),
            ],
        }
    }
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
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: u64,
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub version: String,
    pub description: String,
    pub permissions: Vec<PluginPermission>,
    #[serde(rename = "permissionDeclarations", default)]
    pub permission_declarations: Vec<PluginPermissionDeclaration>,
    #[serde(default)]
    pub entrypoint: Option<PluginEntrypoint>,
    #[serde(rename = "manifestMetadata", default)]
    pub manifest_metadata: PluginManifestMetadata,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginEntrypoint {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginFilesystemPermissionMode {
    Read,
    Write,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum PluginPermissionDeclaration {
    Legacy {
        permission: PluginPermission,
    },
    Filesystem {
        paths: Vec<String>,
        mode: PluginFilesystemPermissionMode,
    },
    Network {
        origins: Vec<String>,
    },
    Process {
        commands: Vec<String>,
    },
    Systemd {
        units: Vec<String>,
        actions: Vec<String>,
    },
    Package {
        managers: Vec<String>,
        actions: Vec<String>,
        packages: Vec<String>,
    },
    User {
        users: Vec<String>,
        actions: Vec<String>,
    },
    Firewall {
        scopes: Vec<String>,
        actions: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum RawPluginPermissionDeclaration {
    Legacy(String),
    Structured(PluginPermissionDeclaration),
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
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: Option<u64>,
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub version: String,
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<RawPluginPermissionDeclaration>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub entrypoint: Option<PluginEntrypoint>,
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
    pub capabilities: Option<PluginCapabilities>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestSchemaEnvelope {
    schema_version: u64,
    legacy: bool,
    explicit_capabilities: bool,
    hash: String,
    warnings: Vec<String>,
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
                        "plugin tool `{}` from `{}` returned non-JSON output for outputSchema validation{}: {error}",
                        self.definition.name,
                        self.plugin_id,
                        truncated_suffix(output.stdout_truncated)
                    ))
                })?;
                validate_json_schema_value(output_schema, &value, "output")?;
            }
            Ok(stdout)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(PluginError::CommandFailed(format!(
                "plugin tool `{}` from `{}` failed for `{}`{}: {}",
                self.definition.name,
                self.plugin_id,
                self.command,
                truncated_suffix(output.stderr_truncated),
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

struct ControlledChildOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

fn run_controlled_child(
    request: ControlledChildRequest,
) -> Result<ControlledChildOutput, PluginError> {
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
    let stdout_reader = thread::spawn(move || read_pipe_capped(stdout, PLUGIN_CHILD_OUTPUT_LIMIT));
    let stderr_reader = thread::spawn(move || read_pipe_capped(stderr, PLUGIN_CHILD_OUTPUT_LIMIT));

    let deadline = Instant::now() + request.timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            terminate_child_tree(&mut child);
            let _ = child.wait();
            let (stdout, stdout_truncated) = join_pipe_reader(stdout_reader)?;
            let (stderr, stderr_truncated) = join_pipe_reader(stderr_reader)?;
            return Err(PluginError::CommandFailed(format!(
                "command `{}` timed out after {} ms; process was terminated; stdout{}: {}; stderr{}: {}",
                request.command,
                request.timeout.as_millis(),
                truncated_suffix(stdout_truncated),
                String::from_utf8_lossy(&stdout).trim(),
                truncated_suffix(stderr_truncated),
                String::from_utf8_lossy(&stderr).trim()
            )));
        }
        thread::sleep(Duration::from_millis(PLUGIN_CHILD_POLL_MS));
    };

    let (stdout, stdout_truncated) = join_pipe_reader(stdout_reader)?;
    let (stderr, stderr_truncated) = join_pipe_reader(stderr_reader)?;
    Ok(ControlledChildOutput {
        status,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
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

fn join_pipe_reader(
    handle: thread::JoinHandle<std::io::Result<(Vec<u8>, bool)>>,
) -> Result<(Vec<u8>, bool), PluginError> {
    handle
        .join()
        .map_err(|_| {
            PluginError::CommandFailed("controlled child pipe reader panicked".to_string())
        })?
        .map_err(PluginError::Io)
}

fn truncated_suffix(truncated: bool) -> &'static str {
    if truncated {
        " [truncated]"
    } else {
        ""
    }
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
    #[serde(rename = "archiveId", default)]
    pub archive_id: String,
    pub version: String,
    pub description: String,
    pub install_path: PathBuf,
    #[serde(default)]
    pub source: String,
    #[serde(rename = "contentHash", default)]
    pub content_hash: String,
    pub archived_at_unix_ms: u128,
}

const INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION: u32 = 2;
const LEGACY_INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION: u32 = 0;

fn legacy_installed_plugin_registry_schema_version() -> u32 {
    LEGACY_INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION
}

fn is_legacy_installed_plugin_registry_schema_version(value: &u32) -> bool {
    *value == LEGACY_INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledPluginRegistry {
    #[serde(
        rename = "schemaVersion",
        default = "legacy_installed_plugin_registry_schema_version",
        skip_serializing_if = "is_legacy_installed_plugin_registry_schema_version"
    )]
    pub schema_version: u32,
    #[serde(default)]
    pub plugins: BTreeMap<String, InstalledPluginRecord>,
    #[serde(default)]
    pub versions: BTreeMap<String, Vec<InstalledPluginVersionRecord>>,
    #[serde(skip)]
    pub migration_warnings: Vec<String>,
    #[serde(skip)]
    migration_blocked_plugin_ids: BTreeSet<String>,
}

impl Default for InstalledPluginRegistry {
    fn default() -> Self {
        Self {
            schema_version: INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION,
            plugins: BTreeMap::new(),
            versions: BTreeMap::new(),
            migration_warnings: Vec::new(),
            migration_blocked_plugin_ids: BTreeSet::new(),
        }
    }
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
    permission_declarations: Vec<PluginPermissionDeclaration>,
    tools: Vec<PluginTool>,
    commands: Vec<PluginCommandManifest>,
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
    permission_declarations: Vec<PluginPermissionDeclaration>,
    tools: Vec<PluginTool>,
    commands: Vec<PluginCommandManifest>,
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
    permission_declarations: Vec<PluginPermissionDeclaration>,
    tools: Vec<PluginTool>,
    commands: Vec<PluginCommandManifest>,
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
    fn permission_declarations(&self) -> &[PluginPermissionDeclaration];
    fn tools(&self) -> &[PluginTool];
    fn commands(&self) -> &[PluginCommandManifest];
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
    fn initialize_with_deadline(&self, deadline: Option<Instant>) -> Result<(), PluginError>;
    fn shutdown(&self) -> Result<(), PluginError>;
    fn shutdown_with_deadline(&self, deadline: Option<Instant>) -> Result<(), PluginError>;
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

    fn permission_declarations(&self) -> &[PluginPermissionDeclaration] {
        &self.permission_declarations
    }

    fn tools(&self) -> &[PluginTool] {
        &self.tools
    }

    fn commands(&self) -> &[PluginCommandManifest] {
        &self.commands
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

    fn initialize_with_deadline(&self, _deadline: Option<Instant>) -> Result<(), PluginError> {
        Ok(())
    }

    fn shutdown(&self) -> Result<(), PluginError> {
        Ok(())
    }

    fn shutdown_with_deadline(&self, _deadline: Option<Instant>) -> Result<(), PluginError> {
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

    fn permission_declarations(&self) -> &[PluginPermissionDeclaration] {
        &self.permission_declarations
    }

    fn tools(&self) -> &[PluginTool] {
        &self.tools
    }

    fn commands(&self) -> &[PluginCommandManifest] {
        &self.commands
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
        validate_command_manifest_paths(self.metadata.root.as_deref(), &self.commands)?;
        validate_tool_paths(self.metadata.root.as_deref(), &self.tools)
    }

    fn initialize(&self) -> Result<(), PluginError> {
        self.initialize_with_deadline(None)
    }

    fn initialize_with_deadline(&self, deadline: Option<Instant>) -> Result<(), PluginError> {
        run_lifecycle_commands(
            self.metadata(),
            self.lifecycle(),
            self.execution_policy(),
            self.permissions(),
            "init",
            &self.lifecycle.init,
            deadline,
        )
    }

    fn shutdown(&self) -> Result<(), PluginError> {
        self.shutdown_with_deadline(None)
    }

    fn shutdown_with_deadline(&self, deadline: Option<Instant>) -> Result<(), PluginError> {
        run_lifecycle_commands(
            self.metadata(),
            self.lifecycle(),
            self.execution_policy(),
            self.permissions(),
            "shutdown",
            &self.lifecycle.shutdown,
            deadline,
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

    fn permission_declarations(&self) -> &[PluginPermissionDeclaration] {
        &self.permission_declarations
    }

    fn tools(&self) -> &[PluginTool] {
        &self.tools
    }

    fn commands(&self) -> &[PluginCommandManifest] {
        &self.commands
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
        validate_command_manifest_paths(self.metadata.root.as_deref(), &self.commands)?;
        validate_tool_paths(self.metadata.root.as_deref(), &self.tools)
    }

    fn initialize(&self) -> Result<(), PluginError> {
        self.initialize_with_deadline(None)
    }

    fn initialize_with_deadline(&self, deadline: Option<Instant>) -> Result<(), PluginError> {
        run_lifecycle_commands(
            self.metadata(),
            self.lifecycle(),
            self.execution_policy(),
            self.permissions(),
            "init",
            &self.lifecycle.init,
            deadline,
        )
    }

    fn shutdown(&self) -> Result<(), PluginError> {
        self.shutdown_with_deadline(None)
    }

    fn shutdown_with_deadline(&self, deadline: Option<Instant>) -> Result<(), PluginError> {
        run_lifecycle_commands(
            self.metadata(),
            self.lifecycle(),
            self.execution_policy(),
            self.permissions(),
            "shutdown",
            &self.lifecycle.shutdown,
            deadline,
        )
    }
}

impl PluginDefinition {
    fn metadata_mut(&mut self) -> &mut PluginMetadata {
        match self {
            Self::Builtin(plugin) => &mut plugin.metadata,
            Self::Bundled(plugin) => &mut plugin.metadata,
            Self::External(plugin) => &mut plugin.metadata,
        }
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

    fn commands(&self) -> &[PluginCommandManifest] {
        match self {
            Self::Builtin(plugin) => plugin.commands(),
            Self::Bundled(plugin) => plugin.commands(),
            Self::External(plugin) => plugin.commands(),
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

    fn permission_declarations(&self) -> &[PluginPermissionDeclaration] {
        match self {
            Self::Builtin(plugin) => plugin.permission_declarations(),
            Self::Bundled(plugin) => plugin.permission_declarations(),
            Self::External(plugin) => plugin.permission_declarations(),
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

    fn initialize_with_deadline(&self, deadline: Option<Instant>) -> Result<(), PluginError> {
        match self {
            Self::Builtin(plugin) => plugin.initialize_with_deadline(deadline),
            Self::Bundled(plugin) => plugin.initialize_with_deadline(deadline),
            Self::External(plugin) => plugin.initialize_with_deadline(deadline),
        }
    }

    fn shutdown(&self) -> Result<(), PluginError> {
        match self {
            Self::Builtin(plugin) => plugin.shutdown(),
            Self::Bundled(plugin) => plugin.shutdown(),
            Self::External(plugin) => plugin.shutdown(),
        }
    }

    fn shutdown_with_deadline(&self, deadline: Option<Instant>) -> Result<(), PluginError> {
        match self {
            Self::Builtin(plugin) => plugin.shutdown_with_deadline(deadline),
            Self::Bundled(plugin) => plugin.shutdown_with_deadline(deadline),
            Self::External(plugin) => plugin.shutdown_with_deadline(deadline),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RegisteredPlugin {
    definition: PluginDefinition,
    enabled: bool,
    available_versions: BTreeSet<String>,
}

impl RegisteredPlugin {
    #[must_use]
    pub fn new(definition: PluginDefinition, enabled: bool) -> Self {
        let mut available_versions = BTreeSet::new();
        available_versions.insert(definition.metadata().version.clone());
        Self {
            definition,
            enabled,
            available_versions,
        }
    }

    #[must_use]
    pub fn with_available_versions(mut self, available_versions: BTreeSet<String>) -> Self {
        if !available_versions.is_empty() {
            self.available_versions = available_versions;
        }
        self
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
    pub fn commands(&self) -> &[PluginCommandManifest] {
        self.definition.commands()
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

    pub fn initialize_with_deadline(&self, deadline: Option<Instant>) -> Result<(), PluginError> {
        self.definition.initialize_with_deadline(deadline)
    }

    pub fn shutdown(&self) -> Result<(), PluginError> {
        self.definition.shutdown()
    }

    pub fn shutdown_with_deadline(&self, deadline: Option<Instant>) -> Result<(), PluginError> {
        self.definition.shutdown_with_deadline(deadline)
    }

    #[must_use]
    pub fn summary(&self) -> PluginSummary {
        PluginSummary {
            metadata: self.metadata().clone(),
            enabled: self.enabled,
            lifecycle: self.definition.lifecycle().clone(),
            permissions: self.definition.permissions().to_vec(),
            permission_declarations: self.definition.permission_declarations().to_vec(),
            permission_declaration_statuses: permission_declaration_statuses_for_plugin(
                &self.definition,
            ),
            capabilities: self.definition.capabilities().clone(),
            actual_surfaces: actual_surfaces_for_plugin(&self.definition),
            degraded_reason: degraded_reason_for_plugin(&self.definition),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginSummary {
    pub metadata: PluginMetadata,
    pub enabled: bool,
    pub lifecycle: PluginLifecycle,
    pub permissions: Vec<PluginPermission>,
    pub permission_declarations: Vec<PluginPermissionDeclaration>,
    pub permission_declaration_statuses: Vec<PluginPermissionDeclarationStatus>,
    pub capabilities: PluginCapabilities,
    pub actual_surfaces: PluginActualSurfaces,
    pub degraded_reason: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginPermissionDeclarationStatus {
    pub index: usize,
    pub permission_type: String,
    pub enforced: bool,
    pub declaration_only: bool,
    #[serde(default)]
    pub enforced_permission: Option<PluginPermission>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginActualSurfaces {
    pub tools: usize,
    pub commands: usize,
    pub resources: usize,
    pub prompts: usize,
    pub mcp_servers: usize,
    pub mcp_tools: usize,
    pub mcp_resources: usize,
    pub mcp_prompts: usize,
    pub ops_permissions: usize,
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
            sanitize_plugin_error(&self.plugin_root.display().to_string()),
            sanitize_plugin_error(&self.source),
            sanitize_plugin_error(&self.error().to_string())
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PluginScanRootSource {
    Installed,
    Bundled,
    System,
    UserConfig,
    UserData,
    Project,
    ExplicitConfig,
}

impl Display for PluginScanRootSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Installed => write!(f, "installed"),
            Self::Bundled => write!(f, "bundled"),
            Self::System => write!(f, "system"),
            Self::UserConfig => write!(f, "userConfig"),
            Self::UserData => write!(f, "userData"),
            Self::Project => write!(f, "project"),
            Self::ExplicitConfig => write!(f, "explicitConfig"),
        }
    }
}

impl PluginScanRootSource {
    #[must_use]
    fn priority(self) -> u8 {
        match self {
            Self::Installed => 80,
            Self::Bundled => 70,
            Self::System => 10,
            Self::UserConfig => 20,
            Self::UserData => 30,
            Self::Project => 40,
            Self::ExplicitConfig => 50,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginScanRoot {
    pub path: PathBuf,
    pub source: PluginScanRootSource,
    pub priority: u8,
}

impl PluginScanRoot {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, source: PluginScanRootSource) -> Self {
        Self {
            path: path.into(),
            source,
            priority: source.priority(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginScanRootReport {
    pub path: String,
    pub source: String,
    pub priority: u8,
    pub manifest_count: usize,
    pub plugin_count: usize,
    pub failure_count: usize,
    pub skipped_count: usize,
    pub omitted_count: usize,
    pub truncated: bool,
    pub duration_ms: u128,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginScanReport {
    pub roots: Vec<PluginScanRootReport>,
    pub plugin_count: usize,
    pub failure_count: usize,
    pub skipped_count: usize,
    pub omitted_count: usize,
    pub truncated: bool,
    pub duration_ms: u128,
    pub warnings: Vec<String>,
}

impl PluginScanReport {
    fn push_root(&mut self, root: PluginScanRootReport) {
        self.plugin_count += root.plugin_count;
        self.failure_count += root.failure_count;
        self.skipped_count += root.skipped_count;
        self.omitted_count += root.omitted_count;
        self.truncated |= root.truncated;
        for warning in &root.warnings {
            if !push_scan_warning(&mut self.warnings, warning) {
                self.truncated = true;
                self.omitted_count += 1;
            }
        }
        self.roots.push(root);
    }
}

#[derive(Debug)]
pub struct PluginRegistryReport {
    registry: PluginRegistry,
    failures: Vec<PluginLoadFailure>,
    scan_report: PluginScanReport,
    blocked_plugin_ids: BTreeSet<String>,
}

impl PluginRegistryReport {
    #[must_use]
    pub fn new(registry: PluginRegistry, failures: Vec<PluginLoadFailure>) -> Self {
        Self {
            registry,
            failures,
            scan_report: PluginScanReport::default(),
            blocked_plugin_ids: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn with_scan_report(
        registry: PluginRegistry,
        failures: Vec<PluginLoadFailure>,
        scan_report: PluginScanReport,
    ) -> Self {
        Self {
            registry,
            failures,
            scan_report,
            blocked_plugin_ids: BTreeSet::new(),
        }
    }

    #[must_use]
    pub fn with_blocked_plugins(mut self, blocked_plugin_ids: BTreeSet<String>) -> Self {
        self.blocked_plugin_ids = blocked_plugin_ids;
        self
    }

    #[must_use]
    pub fn registry(&self) -> &PluginRegistry {
        &self.registry
    }

    #[must_use]
    pub fn healthy_registry(&self) -> PluginRegistry {
        self.registry.without_plugins(&self.blocked_plugin_ids)
    }

    #[must_use]
    pub fn failures(&self) -> &[PluginLoadFailure] {
        &self.failures
    }

    #[must_use]
    pub fn scan_report(&self) -> &PluginScanReport {
        &self.scan_report
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
            if self.scan_report.failure_count > 0 || self.scan_report.truncated {
                return Err(PluginError::InvalidManifest(format!(
                    "plugin discovery scan degraded: failures={}, omitted={}, truncated={}",
                    self.scan_report.failure_count,
                    self.scan_report.omitted_count,
                    self.scan_report.truncated
                )));
            }
            self.registry.validate_registration_conflicts()?;
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
    scan_report: PluginScanReport,
    blocked_plugin_ids: BTreeSet<String>,
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
        self.blocked_plugin_ids.extend(other.blocked_plugin_ids);
        self.scan_report.roots.extend(other.scan_report.roots);
        self.scan_report.plugin_count += other.scan_report.plugin_count;
        self.scan_report.failure_count += other.scan_report.failure_count;
        self.scan_report.skipped_count += other.scan_report.skipped_count;
        self.scan_report.omitted_count += other.scan_report.omitted_count;
        self.scan_report.truncated |= other.scan_report.truncated;
        self.scan_report.duration_ms += other.scan_report.duration_ms;
        for warning in other.scan_report.warnings {
            record_scan_warning(&mut self.scan_report, &warning);
        }
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
            validate_registered_capability_gate(plugin)?;
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

    pub fn aggregated_commands(&self) -> Result<Vec<PluginCommandManifest>, PluginError> {
        let mut commands = Vec::new();
        let mut seen_names = BTreeMap::new();
        for plugin_id in self.dependency_order()? {
            let plugin = self.get(&plugin_id).ok_or_else(|| {
                PluginError::InvalidManifest(format!(
                    "dependency order referenced missing plugin `{plugin_id}`"
                ))
            })?;
            plugin.validate()?;
            for command in plugin.commands() {
                if let Some(existing_plugin) =
                    seen_names.insert(command.name.clone(), plugin.metadata().id.clone())
                {
                    return Err(PluginError::InvalidManifest(format!(
                        "plugin command `{}` is defined by both `{existing_plugin}` and `{}`",
                        command.name,
                        plugin.metadata().id
                    )));
                }
                commands.push(command.clone());
            }
        }
        Ok(commands)
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
            validate_registered_capability_gate(plugin)?;
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
            validate_registered_capability_gate(plugin)?;
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
            validate_registered_capability_gate(plugin)?;
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
        let mut initialized = Vec::<String>::new();
        for plugin_id in order {
            let plugin = self.get(&plugin_id).ok_or_else(|| {
                PluginError::InvalidManifest(format!(
                    "dependency order referenced missing plugin `{plugin_id}`"
                ))
            })?;
            let result = plugin.validate().and_then(|()| plugin.initialize());
            if let Err(error) = result {
                let rollback_error = self.shutdown_plugins_by_id(initialized.into_iter().rev());
                return match rollback_error {
                    Ok(()) => Err(error),
                    Err(rollback_error) => Err(PluginError::CommandFailed(format!(
                        "{}; initialized plugin rollback also failed: {}",
                        sanitize_plugin_error(&error.to_string()),
                        sanitize_plugin_error(&rollback_error.to_string())
                    ))),
                };
            }
            initialized.push(plugin_id);
        }
        Ok(())
    }

    pub fn shutdown(&self) -> Result<(), PluginError> {
        let mut order = self.dependency_order()?;
        order.reverse();
        self.shutdown_plugins_by_id(order)
    }

    fn shutdown_plugins_by_id<I>(&self, order: I) -> Result<(), PluginError>
    where
        I: IntoIterator<Item = String>,
    {
        let mut errors = Vec::new();
        for plugin_id in order {
            let plugin = self.get(&plugin_id).ok_or_else(|| {
                PluginError::InvalidManifest(format!(
                    "dependency order referenced missing plugin `{plugin_id}`"
                ))
            })?;
            if let Err(error) = plugin.shutdown() {
                errors.push(format!(
                    "{}: {}",
                    plugin_id,
                    sanitize_plugin_error(&error.to_string())
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(PluginError::CommandFailed(format!(
                "plugin shutdown failed for {} plugin(s): {}",
                errors.len(),
                errors.join("; ")
            )))
        }
    }

    pub fn validate_registration_conflicts(&self) -> Result<(), PluginError> {
        let mut names = BTreeMap::<String, String>::new();
        for plugin in &self.plugins {
            if let Some(existing_id) =
                names.insert(plugin.metadata().name.clone(), plugin.metadata().id.clone())
            {
                return Err(PluginError::InvalidManifest(format!(
                    "plugin name `{}` is declared by both `{existing_id}` and `{}`",
                    plugin.metadata().name,
                    plugin.metadata().id
                )));
            }
            validate_registered_capability_gate(plugin)?;
        }
        Ok(())
    }

    fn without_plugin(&self, plugin_id: &str) -> Self {
        Self::new(
            self.plugins
                .iter()
                .filter(|plugin| plugin.metadata().id != plugin_id)
                .cloned()
                .collect(),
        )
    }

    fn without_plugins(&self, plugin_ids: &BTreeSet<String>) -> Self {
        if plugin_ids.is_empty() {
            return self.clone();
        }
        Self::new(
            self.plugins
                .iter()
                .filter(|plugin| !plugin_ids.contains(&plugin.metadata().id))
                .cloned()
                .collect(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRuntimeStatus {
    pub generation: u64,
    pub phase: String,
    pub plugin_count: usize,
    pub tool_count: usize,
    pub command_count: usize,
    pub hook_count: usize,
    pub resource_count: usize,
    pub prompt_count: usize,
    pub mcp_server_count: usize,
    pub blocked_plugins: Vec<String>,
    pub in_flight: BTreeMap<String, usize>,
    pub last_operation: Option<String>,
    pub last_error: Option<String>,
    pub degraded_plugins: Vec<PluginRuntimeDegradation>,
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRuntimeDegradation {
    pub plugin_id: String,
    pub reason: String,
}

#[derive(Debug)]
pub struct PreparedPluginRuntimeReplace {
    accepted_registry: PluginRegistry,
    changed_plugins: BTreeSet<String>,
    degraded_plugins: Vec<PluginRuntimeDegradation>,
    base_generation: u64,
}

impl PreparedPluginRuntimeReplace {
    #[must_use]
    pub fn accepted_registry(&self) -> &PluginRegistry {
        &self.accepted_registry
    }

    #[must_use]
    pub fn base_generation(&self) -> u64 {
        self.base_generation
    }
}

pub trait PluginRuntimeSupervisor {
    fn prepare_hot_replace_registry(
        &self,
        registry: PluginRegistry,
    ) -> Result<PreparedPluginRuntimeReplace, PluginError>;

    fn commit_prepared_hot_replace(
        &self,
        prepared: PreparedPluginRuntimeReplace,
    ) -> Result<PluginRuntimeStatus, PluginError>;

    fn hot_replace_registry(
        &self,
        registry: PluginRegistry,
    ) -> Result<PluginRuntimeStatus, PluginError>;
    fn hot_unload_plugin(&self, plugin_id: &str) -> Result<PluginRuntimeStatus, PluginError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginHotLoadOutcome {
    pub plugin_id: String,
    pub version: String,
    pub install_path: PathBuf,
    pub runtime_status: PluginRuntimeStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginHotUnloadOutcome {
    pub plugin_id: String,
    pub runtime_status: PluginRuntimeStatus,
}

impl PluginRuntimeStatus {
    fn from_inner(inner: &PluginRuntimeInner) -> Self {
        let snapshot = inner.snapshot.as_ref();
        let (tool_count, command_count, resource_count, prompt_count, mcp_server_count) =
            runtime_capability_counts(snapshot);
        Self {
            generation: inner.generation,
            phase: inner.phase.clone(),
            plugin_count: snapshot.plugins.len(),
            tool_count,
            command_count,
            hook_count: runtime_hook_count(snapshot),
            resource_count,
            prompt_count,
            mcp_server_count,
            blocked_plugins: inner.blocked_plugins.iter().cloned().collect(),
            in_flight: inner.in_flight.clone(),
            last_operation: inner.last_operation.clone(),
            last_error: inner.last_error.clone(),
            degraded_plugins: inner.degraded_plugins.clone(),
            deadline_ms: PLUGIN_HOT_RELOAD_DEADLINE_MS,
        }
    }
}

fn runtime_status_with_cleanup_warning(
    mut status: PluginRuntimeStatus,
    cleanup_warning: Option<String>,
) -> PluginRuntimeStatus {
    if let Some(warning) = cleanup_warning {
        status.phase = "degraded".to_string();
        status.last_error = Some(match status.last_error.take() {
            Some(existing) if !existing.is_empty() => format!("{existing}; {warning}"),
            _ => warning,
        });
    }
    status
}

#[derive(Debug)]
struct PluginRuntimeInner {
    snapshot: Arc<PluginRegistry>,
    generation: u64,
    phase: String,
    mutating: bool,
    blocked_plugins: BTreeSet<String>,
    in_flight: BTreeMap<String, usize>,
    last_operation: Option<String>,
    last_error: Option<String>,
    degraded_plugins: Vec<PluginRuntimeDegradation>,
}

#[derive(Debug, Clone)]
pub struct PluginRuntimeRegistry {
    inner: Arc<(Mutex<PluginRuntimeInner>, Condvar)>,
}

impl PluginRuntimeRegistry {
    #[must_use]
    pub fn new(registry: PluginRegistry) -> Self {
        Self {
            inner: Arc::new((
                Mutex::new(PluginRuntimeInner {
                    snapshot: Arc::new(registry),
                    generation: 0,
                    phase: "ready".to_string(),
                    mutating: false,
                    blocked_plugins: BTreeSet::new(),
                    in_flight: BTreeMap::new(),
                    last_operation: None,
                    last_error: None,
                    degraded_plugins: Vec::new(),
                }),
                Condvar::new(),
            )),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Arc<PluginRegistry> {
        let (lock, _) = &*self.inner;
        lock.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot
            .clone()
    }

    #[must_use]
    pub fn status(&self) -> PluginRuntimeStatus {
        let (lock, _) = &*self.inner;
        let inner = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        PluginRuntimeStatus::from_inner(&inner)
    }

    pub fn execute_tool(&self, tool_name: &str, input: &Value) -> Result<String, PluginError> {
        let (lock, cvar) = &*self.inner;
        let mut inner = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tool = inner
            .snapshot
            .aggregated_tools()?
            .into_iter()
            .find(|tool| tool.definition().name == tool_name)
            .ok_or_else(|| PluginError::NotFound(format!("plugin tool `{tool_name}` not found")))?;
        let plugin_id = tool.plugin_id().to_string();
        if inner.blocked_plugins.contains(&plugin_id) {
            return Err(PluginError::CommandFailed(format!(
                "plugin `{plugin_id}` is unloading; new calls are blocked"
            )));
        }
        *inner.in_flight.entry(plugin_id.clone()).or_default() += 1;
        drop(inner);

        let result = tool.execute(input);
        let mut inner = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = inner.in_flight.get_mut(&plugin_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.in_flight.remove(&plugin_id);
            }
        }
        cvar.notify_all();
        result
    }

    pub fn command_specs(&self) -> Result<Vec<PluginCommandManifest>, PluginError> {
        self.snapshot().aggregated_commands()
    }

    pub fn execute_command(
        &self,
        command_name: &str,
        args: &[String],
    ) -> Result<String, PluginError> {
        validate_plugin_command_args(args)?;
        let (lock, cvar) = &*self.inner;
        let mut inner = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (plugin, command) = find_runtime_command(inner.snapshot.as_ref(), command_name)?;
        let plugin_id = plugin.metadata().id.clone();
        if inner.blocked_plugins.contains(&plugin_id) {
            return Err(PluginError::CommandFailed(format!(
                "plugin `{plugin_id}` is unloading; new calls are blocked"
            )));
        }
        *inner.in_flight.entry(plugin_id.clone()).or_default() += 1;
        drop(inner);

        let result = execute_registered_command(&plugin, &command, args);
        let mut inner = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = inner.in_flight.get_mut(&plugin_id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.in_flight.remove(&plugin_id);
            }
        }
        cvar.notify_all();
        result
    }

    pub fn hot_replace(
        &self,
        registry: PluginRegistry,
    ) -> Result<PluginRuntimeStatus, PluginError> {
        self.hot_replace_with_timeout(
            registry,
            Duration::from_millis(PLUGIN_HOT_RELOAD_DEADLINE_MS),
        )
    }

    pub fn hot_replace_with_timeout(
        &self,
        registry: PluginRegistry,
        timeout: Duration,
    ) -> Result<PluginRuntimeStatus, PluginError> {
        let prepared = self.prepare_hot_replace_with_timeout(registry, timeout)?;
        self.commit_prepared_hot_replace_with_timeout(prepared, timeout)
    }

    pub fn prepare_hot_replace(
        &self,
        registry: PluginRegistry,
    ) -> Result<PreparedPluginRuntimeReplace, PluginError> {
        self.prepare_hot_replace_with_timeout(
            registry,
            Duration::from_millis(PLUGIN_HOT_RELOAD_DEADLINE_MS),
        )
    }

    pub fn prepare_hot_replace_with_timeout(
        &self,
        registry: PluginRegistry,
        timeout: Duration,
    ) -> Result<PreparedPluginRuntimeReplace, PluginError> {
        let deadline = hot_reload_deadline(timeout)?;
        let requested_snapshot = Arc::new(registry);
        let (lock, cvar) = &*self.inner;
        let mut inner = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner = wait_for_runtime_mutation_slot(inner, cvar, deadline)?;
        let old_snapshot = inner.snapshot.clone();
        let base_generation = inner.generation;
        drop(inner);

        let (prepared_registry, degradations) =
            prepare_runtime_snapshot(old_snapshot.as_ref(), requested_snapshot.as_ref());
        let changed_plugins = changed_enabled_plugins(old_snapshot.as_ref(), &prepared_registry);

        if let Err(error) =
            validate_hot_reload_allowed(old_snapshot.as_ref(), &prepared_registry, &changed_plugins)
        {
            return Err(error);
        }

        validate_runtime_snapshot(&prepared_registry)?;

        Ok(PreparedPluginRuntimeReplace {
            accepted_registry: prepared_registry,
            changed_plugins,
            degraded_plugins: degradations,
            base_generation,
        })
    }

    pub fn commit_prepared_hot_replace(
        &self,
        prepared: PreparedPluginRuntimeReplace,
    ) -> Result<PluginRuntimeStatus, PluginError> {
        self.commit_prepared_hot_replace_with_timeout(
            prepared,
            Duration::from_millis(PLUGIN_HOT_RELOAD_DEADLINE_MS),
        )
    }

    pub fn commit_prepared_hot_replace_with_timeout(
        &self,
        prepared: PreparedPluginRuntimeReplace,
        timeout: Duration,
    ) -> Result<PluginRuntimeStatus, PluginError> {
        let deadline = hot_reload_deadline(timeout)?;
        let new_snapshot = Arc::new(prepared.accepted_registry);
        let changed_plugins = prepared.changed_plugins;
        let degradations = prepared.degraded_plugins;
        let base_generation = prepared.base_generation;
        let (lock, cvar) = &*self.inner;
        let mut inner = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner = wait_for_runtime_mutation_slot(inner, cvar, deadline)?;
        if inner.generation != base_generation {
            return Err(PluginError::CommandFailed(format!(
                "plugin hot reload token generation mismatch: prepared at generation {base_generation}, current generation {}",
                inner.generation
            )));
        }
        inner.mutating = true;
        inner.phase = "loading".to_string();
        inner.last_operation = Some("hot_replace".to_string());
        inner.last_error = None;
        inner.degraded_plugins = degradations.clone();
        let old_snapshot = inner.snapshot.clone();

        inner
            .blocked_plugins
            .extend(changed_plugins.iter().cloned());
        inner = match wait_for_runtime_in_flight(inner, cvar, &changed_plugins, deadline) {
            Ok(inner) => inner,
            Err(error) => {
                let mut inner = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                finish_runtime_mutation(
                    &mut inner,
                    cvar,
                    "degraded",
                    Some(sanitize_plugin_error(&error.to_string())),
                );
                return Err(error);
            }
        };
        drop(inner);

        let mut initialized = Vec::<RegisteredPlugin>::new();
        let initialize_result = initialize_changed_plugins(
            old_snapshot.as_ref(),
            new_snapshot.as_ref(),
            &changed_plugins,
            deadline,
            &mut initialized,
        );
        if let Err(error) = initialize_result {
            for plugin in initialized.into_iter().rev() {
                let _ = plugin.shutdown_with_deadline(Some(deadline));
            }
            let mut inner = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            finish_runtime_mutation(
                &mut inner,
                cvar,
                "degraded",
                Some(sanitize_plugin_error(&error.to_string())),
            );
            return Err(error);
        }

        let mut inner = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.snapshot = new_snapshot.clone();
        inner.generation = inner.generation.saturating_add(1);
        inner.blocked_plugins.clear();
        let phase = if inner.degraded_plugins.is_empty() {
            "ready"
        } else {
            "degraded"
        };
        let quarantine_error = (!inner.degraded_plugins.is_empty()).then(|| {
            format!(
                "quarantined {} plugin(s) during hot reload",
                inner.degraded_plugins.len()
            )
        });
        finish_runtime_mutation(&mut inner, cvar, phase, quarantine_error);
        let status = PluginRuntimeStatus::from_inner(&inner);
        drop(inner);

        let shutdown_error =
            shutdown_replaced_plugins(old_snapshot.as_ref(), &changed_plugins, Some(deadline));
        if let Some(error) = shutdown_error {
            let mut inner = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.phase = "degraded".to_string();
            inner.last_error = Some(error);
            return Ok(PluginRuntimeStatus::from_inner(&inner));
        }
        Ok(status)
    }

    pub fn hot_unload(&self, plugin_id: &str) -> Result<PluginRuntimeStatus, PluginError> {
        self.hot_unload_with_timeout(
            plugin_id,
            Duration::from_millis(PLUGIN_HOT_RELOAD_DEADLINE_MS),
        )
    }

    pub fn hot_unload_with_timeout(
        &self,
        plugin_id: &str,
        timeout: Duration,
    ) -> Result<PluginRuntimeStatus, PluginError> {
        let deadline = hot_reload_deadline(timeout)?;
        let (lock, cvar) = &*self.inner;
        let mut inner = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner = wait_for_runtime_mutation_slot(inner, cvar, deadline)?;
        inner.mutating = true;
        inner.phase = "unloading".to_string();
        inner.last_operation = Some(format!("hot_unload:{plugin_id}"));
        inner.last_error = None;
        inner.degraded_plugins.clear();
        let Some(plugin) = inner.snapshot.get(plugin_id).cloned() else {
            finish_runtime_mutation(&mut inner, cvar, "ready", None);
            return Ok(PluginRuntimeStatus::from_inner(&inner));
        };
        inner.blocked_plugins.insert(plugin_id.to_string());
        if !plugin.capabilities().hot_reload {
            let error = PluginError::CommandFailed(format!(
                "plugin `{plugin_id}` does not declare capabilities.hotReload=true; online unload is refused"
            ));
            finish_runtime_mutation(
                &mut inner,
                cvar,
                "degraded",
                Some(sanitize_plugin_error(&error.to_string())),
            );
            return Err(error);
        }
        let dependents = transitive_runtime_dependents_of(inner.snapshot.as_ref(), plugin_id);
        if !dependents.is_empty() {
            let error = PluginError::CommandFailed(format!(
                "plugin `{plugin_id}` cannot be hot-unloaded because enabled dependents remain: {}",
                dependents.into_iter().collect::<Vec<_>>().join(", ")
            ));
            finish_runtime_mutation(
                &mut inner,
                cvar,
                "degraded",
                Some(sanitize_plugin_error(&error.to_string())),
            );
            return Err(error);
        }
        let remaining_snapshot = inner.snapshot.without_plugin(plugin_id);
        if let Err(error) = validate_runtime_snapshot(&remaining_snapshot) {
            finish_runtime_mutation(
                &mut inner,
                cvar,
                "degraded",
                Some(sanitize_plugin_error(&error.to_string())),
            );
            return Err(error);
        }
        let mut ids = BTreeSet::new();
        ids.insert(plugin_id.to_string());
        inner = match wait_for_runtime_in_flight(inner, cvar, &ids, deadline) {
            Ok(inner) => inner,
            Err(error) => {
                let mut inner = lock
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                finish_runtime_mutation(
                    &mut inner,
                    cvar,
                    "degraded",
                    Some(sanitize_plugin_error(&error.to_string())),
                );
                return Err(error);
            }
        };
        drop(inner);

        if let Err(error) = plugin.shutdown_with_deadline(Some(deadline)) {
            let mut inner = lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            finish_runtime_mutation(
                &mut inner,
                cvar,
                "degraded",
                Some(sanitize_plugin_error(&error.to_string())),
            );
            return Err(error);
        }

        let mut inner = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.snapshot = Arc::new(inner.snapshot.without_plugin(plugin_id));
        inner.generation = inner.generation.saturating_add(1);
        finish_runtime_mutation(&mut inner, cvar, "ready", None);
        Ok(PluginRuntimeStatus::from_inner(&inner))
    }
}

fn find_runtime_command(
    registry: &PluginRegistry,
    command_name: &str,
) -> Result<(RegisteredPlugin, PluginCommandManifest), PluginError> {
    for plugin_id in registry.dependency_order()? {
        let plugin = registry.get(&plugin_id).ok_or_else(|| {
            PluginError::InvalidManifest(format!(
                "dependency order referenced missing plugin `{plugin_id}`"
            ))
        })?;
        plugin.validate()?;
        for command in plugin.commands() {
            if command.name == command_name {
                return Ok((plugin.clone(), command.clone()));
            }
        }
    }
    Err(PluginError::NotFound(format!(
        "plugin command `{command_name}` not found"
    )))
}

fn validate_plugin_command_args(args: &[String]) -> Result<(), PluginError> {
    if args.len() > PLUGIN_COMMAND_MAX_ARGS {
        return Err(PluginError::CommandFailed(format!(
            "plugin command arguments exceed {PLUGIN_COMMAND_MAX_ARGS} item limit"
        )));
    }
    let mut total = 0usize;
    for arg in args {
        total = total.saturating_add(arg.len());
        if total > PLUGIN_COMMAND_MAX_ARG_BYTES {
            return Err(PluginError::CommandFailed(format!(
                "plugin command arguments exceed {PLUGIN_COMMAND_MAX_ARG_BYTES} byte limit"
            )));
        }
        if arg.is_empty() || contains_control_character(arg) {
            return Err(PluginError::CommandFailed(
                "plugin command arguments must be non-empty and contain no control characters"
                    .to_string(),
            ));
        }
        if arg.starts_with('-')
            || arg.contains('/')
            || arg.contains('\\')
            || arg == "."
            || arg == ".."
            || arg.contains("..")
        {
            return Err(PluginError::CommandFailed(format!(
                "plugin command argument `{}` was rejected by the argv safety policy",
                sanitize_plugin_error(arg)
            )));
        }
    }
    Ok(())
}

fn execute_registered_command(
    plugin: &RegisteredPlugin,
    command: &PluginCommandManifest,
    command_args: &[String],
) -> Result<String, PluginError> {
    plugin.validate()?;
    let metadata = plugin.metadata();
    let command_path = metadata.root.as_ref().map_or_else(
        || command.command.clone(),
        |root| {
            if Path::new(&command.command).is_absolute() {
                command.command.clone()
            } else {
                root.join(&command.command).display().to_string()
            }
        },
    );
    let (runner, args) = if cfg!(windows) && !command_path.ends_with(".sh") {
        let mut args = vec!["/C".to_string(), command_path.clone()];
        args.extend(command_args.iter().cloned());
        ("cmd".to_string(), args)
    } else {
        (command_path.clone(), command_args.to_vec())
    };
    let output = run_controlled_child(ControlledChildRequest {
        command: runner,
        args,
        stdin: None,
        cwd: metadata.root.clone(),
        timeout: Duration::from_millis(PLUGIN_TOOL_TIMEOUT_MS),
        permission: lifecycle_child_permission(plugin.definition.permissions()),
        external_subprocess_allowed: metadata.kind != PluginKind::External
            || plugin
                .definition
                .execution_policy()
                .allow_external_subprocess,
        os_sandbox_required: metadata.kind == PluginKind::External,
        env: BTreeMap::from([
            ("CLAWD_PLUGIN_ID".to_string(), metadata.id.clone()),
            ("CLAWD_PLUGIN_NAME".to_string(), metadata.name.clone()),
            ("CLAWD_COMMAND_NAME".to_string(), command.name.clone()),
            (
                "CLAWD_COMMAND_ARGV_JSON".to_string(),
                serde_json::to_string(command_args).unwrap_or_else(|_| "[]".to_string()),
            ),
        ]),
    })?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(PluginError::CommandFailed(format!(
            "plugin command `{}` from `{}` failed for `{}`{}: {}",
            command.name,
            metadata.id,
            command.command,
            truncated_suffix(output.stderr_truncated),
            if stderr.is_empty() {
                format!("exit status {}", output.status)
            } else {
                stderr
            }
        )))
    }
}

impl PluginRuntimeSupervisor for PluginRuntimeRegistry {
    fn prepare_hot_replace_registry(
        &self,
        registry: PluginRegistry,
    ) -> Result<PreparedPluginRuntimeReplace, PluginError> {
        PluginRuntimeRegistry::prepare_hot_replace(self, registry)
    }

    fn commit_prepared_hot_replace(
        &self,
        prepared: PreparedPluginRuntimeReplace,
    ) -> Result<PluginRuntimeStatus, PluginError> {
        PluginRuntimeRegistry::commit_prepared_hot_replace(self, prepared)
    }

    fn hot_replace_registry(
        &self,
        registry: PluginRegistry,
    ) -> Result<PluginRuntimeStatus, PluginError> {
        self.hot_replace(registry)
    }

    fn hot_unload_plugin(&self, plugin_id: &str) -> Result<PluginRuntimeStatus, PluginError> {
        self.hot_unload(plugin_id)
    }
}

fn runtime_hook_count(registry: &PluginRegistry) -> usize {
    registry
        .plugins
        .iter()
        .filter(|plugin| plugin.is_enabled())
        .map(|plugin| {
            plugin.hooks().pre_tool_use.len()
                + plugin.hooks().post_tool_use.len()
                + plugin.hooks().post_tool_use_failure.len()
        })
        .sum()
}

fn runtime_capability_counts(registry: &PluginRegistry) -> (usize, usize, usize, usize, usize) {
    registry
        .plugins
        .iter()
        .filter(|plugin| plugin.is_enabled())
        .fold(
            (0, 0, 0, 0, 0),
            |(tools, commands, resources, prompts, mcp), plugin| {
                (
                    tools + plugin.tools().len(),
                    commands + plugin.commands().len(),
                    resources + plugin.resources().len(),
                    prompts + plugin.prompts().len(),
                    mcp + plugin.mcp_servers().len(),
                )
            },
        )
}

#[derive(Debug, Default)]
struct RuntimeConflictSeen {
    plugin_names: BTreeMap<String, String>,
    tool_names: BTreeMap<String, String>,
    command_names: BTreeMap<String, String>,
    resource_uris: BTreeMap<String, String>,
    prompt_names: BTreeMap<String, String>,
}

fn prepare_runtime_snapshot(
    old: &PluginRegistry,
    requested: &PluginRegistry,
) -> (PluginRegistry, Vec<PluginRuntimeDegradation>) {
    let old_by_id = old
        .plugins
        .iter()
        .map(|plugin| (plugin.metadata().id.clone(), plugin.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut seen = RuntimeConflictSeen::default();
    let mut accepted = Vec::new();
    let mut degradations = Vec::new();
    let mut processed = BTreeSet::<String>::new();

    for plugin in &requested.plugins {
        if old_by_id
            .get(&plugin.metadata().id)
            .is_none_or(|old_plugin| old_plugin != plugin)
        {
            continue;
        }
        if runtime_plugin_conflict_reason(plugin, &seen).is_none() {
            record_runtime_plugin(plugin.clone(), &mut seen, &mut accepted);
            processed.insert(plugin.metadata().id.clone());
        }
    }

    for plugin in &requested.plugins {
        if processed.contains(&plugin.metadata().id) {
            continue;
        }
        match runtime_plugin_conflict_reason(plugin, &seen) {
            None => record_runtime_plugin(plugin.clone(), &mut seen, &mut accepted),
            Some(reason) => {
                degradations.push(PluginRuntimeDegradation {
                    plugin_id: plugin.metadata().id.clone(),
                    reason: reason.clone(),
                });
                if let Some(old_plugin) = old_by_id.get(&plugin.metadata().id) {
                    if runtime_plugin_conflict_reason(old_plugin, &seen).is_none() {
                        record_runtime_plugin(old_plugin.clone(), &mut seen, &mut accepted);
                    } else {
                        degradations.push(PluginRuntimeDegradation {
                            plugin_id: old_plugin.metadata().id.clone(),
                            reason: format!(
                                "old generation could not be retained after candidate quarantine: {reason}"
                            ),
                        });
                    }
                }
            }
        }
    }

    propagate_runtime_dependency_quarantine(&mut accepted, &mut degradations);

    (PluginRegistry::new(accepted), degradations)
}

fn propagate_runtime_dependency_quarantine(
    accepted: &mut Vec<RegisteredPlugin>,
    degradations: &mut Vec<PluginRuntimeDegradation>,
) {
    loop {
        let mut rejected = Vec::<(String, String)>::new();
        for plugin in accepted.iter().filter(|plugin| plugin.is_enabled()) {
            for dependency in plugin.dependencies() {
                let Some(dependency_plugin) = resolve_dependency_plugin(accepted, dependency)
                else {
                    if dependency.optional {
                        continue;
                    }
                    rejected.push((
                        plugin.metadata().id.clone(),
                        format!("required dependency `{}` is not available", dependency.name),
                    ));
                    break;
                };
                if let Some(requirement) = dependency.version_requirement.as_deref() {
                    match semver_requirement_matches(
                        requirement,
                        &dependency_plugin.metadata().version,
                    ) {
                        Ok(true) => {}
                        Ok(false) => {
                            rejected.push((
                                plugin.metadata().id.clone(),
                                format_dependency_conflict_reason(
                                    plugin,
                                    dependency,
                                    dependency_plugin,
                                    requirement,
                                ),
                            ));
                            break;
                        }
                        Err(error) => {
                            rejected.push((
                                plugin.metadata().id.clone(),
                                sanitize_plugin_error(&error.to_string()),
                            ));
                            break;
                        }
                    }
                }
            }
        }
        if rejected.is_empty() {
            break;
        }
        let rejected_ids = rejected
            .iter()
            .map(|(plugin_id, _)| plugin_id.clone())
            .collect::<BTreeSet<_>>();
        accepted.retain(|plugin| !rejected_ids.contains(&plugin.metadata().id));
        for (plugin_id, reason) in rejected {
            degradations.push(PluginRuntimeDegradation { plugin_id, reason });
        }
    }
}

fn runtime_plugin_conflict_reason(
    plugin: &RegisteredPlugin,
    seen: &RuntimeConflictSeen,
) -> Option<String> {
    if let Some(existing) = seen.plugin_names.get(&plugin.metadata().name) {
        return Some(format!(
            "plugin name `{}` conflicts with `{existing}`",
            plugin.metadata().name
        ));
    }
    if !plugin.is_enabled() {
        return None;
    }
    if let Err(error) = plugin.validate() {
        return Some(sanitize_plugin_error(&error.to_string()));
    }
    if let Err(error) = validate_registered_capability_gate(plugin) {
        return Some(sanitize_plugin_error(&error.to_string()));
    }
    for tool in plugin.tools() {
        if let Some(existing) = seen.tool_names.get(&tool.definition().name) {
            return Some(format!(
                "tool `{}` conflicts with `{existing}`",
                tool.definition().name
            ));
        }
    }
    for command in plugin.commands() {
        if let Some(existing) = seen.command_names.get(&command.name) {
            return Some(format!(
                "command `{}` conflicts with `{existing}`",
                command.name
            ));
        }
    }
    for resource in plugin.resources() {
        if let Some(existing) = seen.resource_uris.get(&resource.uri) {
            return Some(format!(
                "resource `{}` conflicts with `{existing}`",
                resource.uri
            ));
        }
    }
    for prompt in plugin.prompts() {
        if let Some(existing) = seen.prompt_names.get(&prompt.name) {
            return Some(format!(
                "prompt `{}` conflicts with `{existing}`",
                prompt.name
            ));
        }
    }
    None
}

fn record_runtime_plugin(
    plugin: RegisteredPlugin,
    seen: &mut RuntimeConflictSeen,
    accepted: &mut Vec<RegisteredPlugin>,
) {
    seen.plugin_names
        .insert(plugin.metadata().name.clone(), plugin.metadata().id.clone());
    if plugin.is_enabled() {
        for tool in plugin.tools() {
            seen.tool_names
                .insert(tool.definition().name.clone(), plugin.metadata().id.clone());
        }
        for command in plugin.commands() {
            seen.command_names
                .insert(command.name.clone(), plugin.metadata().id.clone());
        }
        for resource in plugin.resources() {
            seen.resource_uris
                .insert(resource.uri.clone(), plugin.metadata().id.clone());
        }
        for prompt in plugin.prompts() {
            seen.prompt_names
                .insert(prompt.name.clone(), plugin.metadata().id.clone());
        }
    }
    accepted.push(plugin);
}

fn validate_runtime_snapshot(registry: &PluginRegistry) -> Result<(), PluginError> {
    registry.validate_registration_conflicts()?;
    let _ = registry.dependency_order()?;
    let _ = registry.aggregated_hooks()?;
    let _ = registry.aggregated_tools()?;
    let _ = registry.aggregated_commands()?;
    let _ = registry.aggregated_resources()?;
    let _ = registry.aggregated_prompts()?;
    let _ = registry.aggregated_mcp_servers()?;
    Ok(())
}

fn hot_reload_deadline(timeout: Duration) -> Result<Instant, PluginError> {
    if timeout.is_zero() {
        return Err(PluginError::CommandFailed(
            "plugin hot reload timeout must be greater than 0 ms".to_string(),
        ));
    }
    Instant::now().checked_add(timeout).ok_or_else(|| {
        PluginError::CommandFailed("plugin hot reload timeout is too large".to_string())
    })
}

fn remaining_until(deadline: Instant) -> Result<Duration, PluginError> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| {
            PluginError::CommandFailed(format!(
                "plugin hot reload exceeded {} ms deadline",
                PLUGIN_HOT_RELOAD_DEADLINE_MS
            ))
        })
}

fn wait_for_runtime_mutation_slot<'a>(
    mut inner: std::sync::MutexGuard<'a, PluginRuntimeInner>,
    cvar: &Condvar,
    deadline: Instant,
) -> Result<std::sync::MutexGuard<'a, PluginRuntimeInner>, PluginError> {
    while inner.mutating {
        let remaining = remaining_until(deadline)?;
        let wait = remaining.min(Duration::from_millis(PLUGIN_LOCK_POLL_MS));
        inner = cvar
            .wait_timeout(inner, wait)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0;
    }
    Ok(inner)
}

fn wait_for_runtime_in_flight<'a>(
    mut inner: std::sync::MutexGuard<'a, PluginRuntimeInner>,
    cvar: &Condvar,
    plugin_ids: &BTreeSet<String>,
    deadline: Instant,
) -> Result<std::sync::MutexGuard<'a, PluginRuntimeInner>, PluginError> {
    while plugin_ids
        .iter()
        .any(|plugin_id| inner.in_flight.get(plugin_id).copied().unwrap_or(0) > 0)
    {
        let remaining = remaining_until(deadline)?;
        let wait = remaining.min(Duration::from_millis(PLUGIN_LOCK_POLL_MS));
        inner = cvar
            .wait_timeout(inner, wait)
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0;
    }
    Ok(inner)
}

fn finish_runtime_mutation(
    inner: &mut PluginRuntimeInner,
    cvar: &Condvar,
    phase: &str,
    error: Option<String>,
) {
    inner.phase = phase.to_string();
    inner.last_error = error;
    inner.blocked_plugins.clear();
    inner.mutating = false;
    cvar.notify_all();
}

fn changed_enabled_plugins(old: &PluginRegistry, new: &PluginRegistry) -> BTreeSet<String> {
    let old_plugins = old
        .plugins
        .iter()
        .filter(|plugin| plugin.is_enabled())
        .map(|plugin| (plugin.metadata().id.clone(), plugin.clone()))
        .collect::<BTreeMap<_, _>>();
    let new_plugins = new
        .plugins
        .iter()
        .filter(|plugin| plugin.is_enabled())
        .map(|plugin| (plugin.metadata().id.clone(), plugin.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut changed = old_plugins
        .keys()
        .chain(new_plugins.keys())
        .filter(|plugin_id| old_plugins.get(*plugin_id) != new_plugins.get(*plugin_id))
        .cloned()
        .collect::<BTreeSet<_>>();
    expand_changed_with_dependents(old, &mut changed);
    expand_changed_with_dependents(new, &mut changed);
    changed
}

fn expand_changed_with_dependents(registry: &PluginRegistry, changed: &mut BTreeSet<String>) {
    loop {
        let mut additions = BTreeSet::new();
        for plugin_id in changed.iter() {
            additions.extend(runtime_dependents_of(registry, plugin_id));
        }
        let before = changed.len();
        changed.extend(additions);
        if changed.len() == before {
            break;
        }
    }
}

fn validate_hot_reload_allowed(
    old: &PluginRegistry,
    new: &PluginRegistry,
    changed: &BTreeSet<String>,
) -> Result<(), PluginError> {
    for plugin_id in changed {
        for registry in [old, new] {
            let Some(plugin) = registry.get(plugin_id) else {
                continue;
            };
            if !plugin.is_enabled() {
                continue;
            }
            if !plugin.capabilities().hot_reload {
                return Err(PluginError::CommandFailed(format!(
                    "plugin `{plugin_id}` does not declare capabilities.hotReload=true; online plugin reload is refused"
                )));
            }
        }
    }
    Ok(())
}

fn runtime_dependents_of(registry: &PluginRegistry, plugin_id: &str) -> BTreeSet<String> {
    let Some(target) = registry.get(plugin_id) else {
        return BTreeSet::new();
    };
    let target_name = &target.metadata().name;
    registry
        .plugins
        .iter()
        .filter(|plugin| plugin.is_enabled() && plugin.metadata().id != plugin_id)
        .filter(|plugin| {
            plugin.dependencies().iter().any(|dependency| {
                dependency.name == plugin_id || dependency.name.as_str() == target_name
            })
        })
        .map(|plugin| plugin.metadata().id.clone())
        .collect()
}

fn transitive_runtime_dependents_of(
    registry: &PluginRegistry,
    plugin_id: &str,
) -> BTreeSet<String> {
    let mut dependents = BTreeSet::new();
    let mut frontier = BTreeSet::from([plugin_id.to_string()]);
    loop {
        let mut next = BTreeSet::new();
        for blocked in &frontier {
            next.extend(runtime_dependents_of(registry, blocked));
        }
        next.retain(|id| !dependents.contains(id));
        if next.is_empty() {
            break;
        }
        dependents.extend(next.iter().cloned());
        frontier = next;
    }
    dependents
}

fn initialize_changed_plugins(
    old: &PluginRegistry,
    new: &PluginRegistry,
    changed: &BTreeSet<String>,
    deadline: Instant,
    initialized: &mut Vec<RegisteredPlugin>,
) -> Result<(), PluginError> {
    let old_plugins = old
        .plugins
        .iter()
        .map(|plugin| (plugin.metadata().id.clone(), plugin))
        .collect::<BTreeMap<_, _>>();
    for plugin_id in new.dependency_order()? {
        if remaining_until(deadline).is_err() {
            return Err(PluginError::CommandFailed(format!(
                "plugin hot reload exceeded {} ms deadline before initializing `{plugin_id}`",
                PLUGIN_HOT_RELOAD_DEADLINE_MS
            )));
        }
        if !changed.contains(&plugin_id) {
            continue;
        }
        let plugin = new.get(&plugin_id).ok_or_else(|| {
            PluginError::InvalidManifest(format!(
                "dependency order referenced missing plugin `{plugin_id}`"
            ))
        })?;
        if old_plugins
            .get(&plugin_id)
            .is_some_and(|old| *old == plugin)
        {
            continue;
        }
        plugin.validate()?;
        plugin.initialize_with_deadline(Some(deadline))?;
        initialized.push(plugin.clone());
    }
    Ok(())
}

fn shutdown_replaced_plugins(
    old: &PluginRegistry,
    changed: &BTreeSet<String>,
    deadline: Option<Instant>,
) -> Option<String> {
    let mut order = old.dependency_order().unwrap_or_default();
    order.reverse();
    let mut errors = Vec::new();
    for plugin_id in order {
        if !changed.contains(&plugin_id) {
            continue;
        }
        let Some(plugin) = old.get(&plugin_id) else {
            continue;
        };
        if let Err(error) = plugin.shutdown_with_deadline(deadline) {
            errors.push(format!(
                "{}: {}",
                plugin_id,
                sanitize_plugin_error(&error.to_string())
            ));
        }
    }
    (!errors.is_empty()).then(|| {
        format!(
            "plugin shutdown failed for {} replaced plugin(s): {}",
            errors.len(),
            errors.join("; ")
        )
    })
}

fn hot_load_backup_root(install_root: &Path, timestamp_ms: u128, process_id: u32) -> PathBuf {
    install_root
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!(".hot-load-backup-{process_id}-{timestamp_ms}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManagerConfig {
    pub config_home: PathBuf,
    pub enabled_plugins: BTreeMap<String, bool>,
    pub external_dirs: Vec<PathBuf>,
    pub discovery_roots: Vec<PluginScanRoot>,
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
            discovery_roots: Vec::new(),
            install_root: None,
            registry_path: None,
            bundled_root: None,
        }
    }

    #[must_use]
    pub fn default_discovery_roots(project_root: Option<&Path>) -> Vec<PluginScanRoot> {
        default_plugin_discovery_roots(project_root)
    }

    pub fn enable_default_discovery(&mut self, project_root: Option<&Path>) {
        self.discovery_roots = Self::default_discovery_roots(project_root);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManager {
    config: PluginManagerConfig,
    mutation_locks_held: bool,
    cleanup_warning: Option<String>,
}

pub struct PreparedPluginHotReload<T> {
    result: T,
    candidate_registry: Option<PluginRegistry>,
    registry_backup: InstalledPluginRegistry,
    enabled_backup: BTreeMap<String, bool>,
    install_root: PathBuf,
    backup_root: PathBuf,
    install_root_had_contents: bool,
    _mutation_locks: PluginMutationLocks,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginHotReloadFinish<T> {
    pub result: T,
    pub cleanup_warning: Option<String>,
}

impl<T> PreparedPluginHotReload<T> {
    #[must_use]
    pub fn candidate_registry(&self) -> Option<&PluginRegistry> {
        self.candidate_registry.as_ref()
    }
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
        Self {
            config,
            mutation_locks_held: false,
            cleanup_warning: None,
        }
    }

    pub fn take_cleanup_warning(&mut self) -> Option<String> {
        self.cleanup_warning.take()
    }

    fn push_cleanup_warning(&mut self, warning: impl Into<String>) {
        append_cleanup_warning(&mut self.cleanup_warning, warning.into());
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
        let mut discovery = PluginDiscovery::default();
        discovery.plugins.extend(builtin_plugins());
        discovery.extend(self.sync_bundled_plugins()?);

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
        Ok(self.installed_plugin_registry_report()?.summaries())
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
        let manifest = load_plugin_from_directory(&path)?;
        validate_plugin_registration_policy(PluginKind::External, &manifest)?;
        Ok(manifest)
    }

    pub fn hot_load(&mut self, source: &str) -> Result<InstallOutcome, PluginError> {
        self.install(source)
    }

    pub fn hot_reload_transaction<S, T, F>(
        &mut self,
        supervisor: &S,
        mutation: F,
    ) -> Result<(T, Option<PluginRuntimeStatus>), PluginError>
    where
        S: PluginRuntimeSupervisor,
        F: FnOnce(&mut Self) -> Result<(T, bool), PluginError>,
    {
        let prepared = self.prepare_hot_reload_transaction(mutation)?;
        let Some(candidate_registry) = prepared.candidate_registry().cloned() else {
            let finish = self.finish_prepared_hot_reload(prepared);
            return Ok((finish.result, None));
        };
        let runtime_prepare = match supervisor.prepare_hot_replace_registry(candidate_registry) {
            Ok(prepared) => prepared,
            Err(error) => {
                if let Err(restore_error) = self.rollback_prepared_hot_reload(prepared) {
                    return Err(PluginError::CommandFailed(format!(
                        "{}; hot-reload transaction rollback failed: {}",
                        sanitize_plugin_error(&error.to_string()),
                        sanitize_plugin_error(&restore_error.to_string())
                    )));
                }
                return Err(error);
            }
        };
        match supervisor.commit_prepared_hot_replace(runtime_prepare) {
            Ok(status) => {
                let finish = self.finish_prepared_hot_reload(prepared);
                let status = runtime_status_with_cleanup_warning(status, finish.cleanup_warning);
                Ok((finish.result, Some(status)))
            }
            Err(error) => {
                if let Err(restore_error) = self.rollback_prepared_hot_reload(prepared) {
                    return Err(PluginError::CommandFailed(format!(
                        "{}; hot-reload transaction rollback failed: {}",
                        sanitize_plugin_error(&error.to_string()),
                        sanitize_plugin_error(&restore_error.to_string())
                    )));
                }
                Err(error)
            }
        }
    }

    pub fn prepare_hot_reload_transaction<T, F>(
        &mut self,
        mutation: F,
    ) -> Result<PreparedPluginHotReload<T>, PluginError>
    where
        F: FnOnce(&mut Self) -> Result<(T, bool), PluginError>,
    {
        let mutation_locks = self.acquire_mutation_locks()?;
        let previous_locks_held = self.mutation_locks_held;
        self.mutation_locks_held = true;
        let registry_backup = self.load_registry_under_exclusive_lock()?;
        let enabled_backup = self.config.enabled_plugins.clone();
        let install_root = self.install_root();
        let backup_root = hot_load_backup_root(&install_root, unix_time_ms(), std::process::id());
        let install_root_had_contents = install_root.exists();
        let prepared = (|| {
            if install_root_had_contents {
                if backup_root.exists() {
                    fs::remove_dir_all(&backup_root)?;
                }
                copy_dir_all(&install_root, &backup_root)?;
            }

            let (result, reload_runtime) = match mutation(self) {
                Ok(result) => result,
                Err(error) => {
                    if let Err(restore_error) = self.restore_hot_load_backup(
                        &registry_backup,
                        &enabled_backup,
                        &install_root,
                        &backup_root,
                        install_root_had_contents,
                    ) {
                        return Err(PluginError::CommandFailed(format!(
                            "{}; hot-reload transaction rollback failed: {}",
                            sanitize_plugin_error(&error.to_string()),
                            sanitize_plugin_error(&restore_error.to_string())
                        )));
                    }
                    return Err(error);
                }
            };
            if !reload_runtime {
                return Ok(PreparedPluginHotReload {
                    result,
                    candidate_registry: None,
                    registry_backup,
                    enabled_backup,
                    install_root,
                    backup_root,
                    install_root_had_contents,
                    _mutation_locks: mutation_locks,
                });
            }

            let registry = match self.plugin_registry() {
                Ok(registry) => registry,
                Err(error) => {
                    let restore_error = self.restore_hot_load_backup(
                        &registry_backup,
                        &enabled_backup,
                        &install_root,
                        &backup_root,
                        install_root_had_contents,
                    );
                    if let Err(restore_error) = restore_error {
                        return Err(PluginError::CommandFailed(format!(
                            "{}; hot-reload transaction rollback failed: {}",
                            sanitize_plugin_error(&error.to_string()),
                            sanitize_plugin_error(&restore_error.to_string())
                        )));
                    }
                    return Err(error);
                }
            };
            Ok(PreparedPluginHotReload {
                result,
                candidate_registry: Some(registry),
                registry_backup,
                enabled_backup,
                install_root,
                backup_root,
                install_root_had_contents,
                _mutation_locks: mutation_locks,
            })
        })();
        self.mutation_locks_held = previous_locks_held;
        prepared
    }

    pub fn finish_prepared_hot_reload<T>(
        &mut self,
        prepared: PreparedPluginHotReload<T>,
    ) -> PluginHotReloadFinish<T> {
        let mut cleanup_warning = self.take_cleanup_warning();
        if prepared.backup_root.exists() {
            fs::remove_dir_all(&prepared.backup_root)
                .err()
                .map(|error| {
                    truncate_plugin_error(&format!(
                        "hot-reload backup cleanup failed for `{}`: {}",
                        prepared.backup_root.display(),
                        sanitize_plugin_error(&error.to_string())
                    ))
                })
                .into_iter()
                .for_each(|warning| append_cleanup_warning(&mut cleanup_warning, warning));
        };
        PluginHotReloadFinish {
            result: prepared.result,
            cleanup_warning,
        }
    }

    pub fn rollback_prepared_hot_reload<T>(
        &mut self,
        prepared: PreparedPluginHotReload<T>,
    ) -> Result<(), PluginError> {
        let restore_error = self.restore_hot_load_backup(
            &prepared.registry_backup,
            &prepared.enabled_backup,
            &prepared.install_root,
            &prepared.backup_root,
            prepared.install_root_had_contents,
        );
        drop(prepared);
        restore_error
    }

    pub fn hot_load_with_supervisor<S: PluginRuntimeSupervisor>(
        &mut self,
        source: &str,
        supervisor: &S,
    ) -> Result<PluginHotLoadOutcome, PluginError> {
        let prepared = self.prepare_hot_reload_transaction(|manager| {
            let install = manager.install(source)?;
            Ok((install, true))
        })?;
        let registry = prepared.candidate_registry().cloned().ok_or_else(|| {
            PluginError::CommandFailed(
                "hot-load transaction did not build a runtime candidate".to_string(),
            )
        })?;
        let runtime_prepare = match supervisor.prepare_hot_replace_registry(registry) {
            Ok(prepared) => prepared,
            Err(error) => {
                if let Err(restore_error) = self.rollback_prepared_hot_reload(prepared) {
                    return Err(PluginError::CommandFailed(format!(
                        "{}; hot-load rollback failed: {}",
                        sanitize_plugin_error(&error.to_string()),
                        sanitize_plugin_error(&restore_error.to_string())
                    )));
                }
                return Err(error);
            }
        };
        match supervisor.commit_prepared_hot_replace(runtime_prepare) {
            Ok(runtime_status) => {
                let finish = self.finish_prepared_hot_reload(prepared);
                let install = finish.result;
                let runtime_status =
                    runtime_status_with_cleanup_warning(runtime_status, finish.cleanup_warning);
                Ok(PluginHotLoadOutcome {
                    plugin_id: install.plugin_id,
                    version: install.version,
                    install_path: install.install_path,
                    runtime_status,
                })
            }
            Err(error) => {
                if let Err(restore_error) = self.rollback_prepared_hot_reload(prepared) {
                    return Err(PluginError::CommandFailed(format!(
                        "{}; hot-load rollback failed: {}",
                        sanitize_plugin_error(&error.to_string()),
                        sanitize_plugin_error(&restore_error.to_string())
                    )));
                }
                Err(error)
            }
        }
    }

    pub fn hot_unload(&mut self, plugin_id: &str) -> Result<(), PluginError> {
        self.disable(plugin_id)
    }

    pub fn hot_unload_with_supervisor<S: PluginRuntimeSupervisor>(
        &mut self,
        plugin_id: &str,
        supervisor: &S,
    ) -> Result<PluginHotUnloadOutcome, PluginError> {
        let plugin_id = plugin_id.to_string();
        let prepared = self.prepare_hot_reload_transaction(|manager| {
            manager.ensure_known_plugin(&plugin_id)?;
            manager.disable(&plugin_id)?;
            Ok((plugin_id.clone(), true))
        })?;
        let registry = prepared.candidate_registry().cloned().ok_or_else(|| {
            PluginError::CommandFailed(
                "hot-unload transaction did not build a runtime candidate".to_string(),
            )
        })?;
        let runtime_prepare = match supervisor.prepare_hot_replace_registry(registry) {
            Ok(prepared) => prepared,
            Err(error) => {
                if let Err(restore_error) = self.rollback_prepared_hot_reload(prepared) {
                    return Err(PluginError::CommandFailed(format!(
                        "{}; hot-unload rollback failed: {}",
                        sanitize_plugin_error(&error.to_string()),
                        sanitize_plugin_error(&restore_error.to_string())
                    )));
                }
                return Err(error);
            }
        };
        match supervisor.commit_prepared_hot_replace(runtime_prepare) {
            Ok(runtime_status) => {
                let finish = self.finish_prepared_hot_reload(prepared);
                let plugin_id = finish.result;
                let runtime_status =
                    runtime_status_with_cleanup_warning(runtime_status, finish.cleanup_warning);
                Ok(PluginHotUnloadOutcome {
                    plugin_id,
                    runtime_status,
                })
            }
            Err(error) => {
                if let Err(restore_error) = self.rollback_prepared_hot_reload(prepared) {
                    return Err(PluginError::CommandFailed(format!(
                        "{}; hot-unload rollback failed: {}",
                        sanitize_plugin_error(&error.to_string()),
                        sanitize_plugin_error(&restore_error.to_string())
                    )));
                }
                Err(error)
            }
        }
    }

    pub fn install(&mut self, source: &str) -> Result<InstallOutcome, PluginError> {
        let _mutation_locks = self.acquire_mutation_locks_if_needed()?;
        let install_source = parse_install_source(source)?;
        let temp_root = self.install_root().join(".tmp");
        let staged_source = materialize_source(&install_source, &temp_root)?;
        let cleanup_source = matches!(install_source, PluginInstallSource::GitUrl { .. });
        let manifest = load_plugin_from_directory(&staged_source)?;
        validate_plugin_registration_policy(PluginKind::External, &manifest)?;

        let plugin_id = plugin_id(&manifest.name, EXTERNAL_MARKETPLACE);
        let install_path = self.versioned_plugin_install_path(&plugin_id, &manifest.version)?;
        let mut registry = self.load_registry_under_exclusive_lock()?;
        self.validate_installed_version_records(&registry)?;
        let registry_backup = registry.clone();
        let enabled_backup = self.config.enabled_plugins.clone();
        if install_path.exists() {
            return Err(PluginError::InvalidManifest(format!(
                "plugin `{plugin_id}` version `{}` is already installed at immutable version slot `{}`",
                manifest.version,
                install_path.display()
            )));
        }
        copy_dir_all_atomic(&staged_source, &install_path)?;
        if cleanup_source {
            let _ = fs::remove_dir_all(&staged_source);
        }

        let now = unix_time_ms();
        let record_name = manifest.name.clone();
        let record_version = manifest.version.clone();
        let record_description = manifest.description.clone();
        let record_policy = manifest.version_policy.clone();
        let record = InstalledPluginRecord {
            kind: PluginKind::External,
            id: plugin_id.clone(),
            name: record_name,
            version: record_version.clone(),
            description: record_description,
            install_path: install_path.clone(),
            source: install_source.clone(),
            version_policy: record_policy,
            installed_at_unix_ms: now,
            updated_at_unix_ms: now,
        };

        if let Some(existing_record) = registry.plugins.get(&plugin_id).cloned() {
            self.archive_installed_version(
                &mut registry,
                &existing_record,
                manifest.version_policy.keep_versions,
                &[manifest.version.as_str(), existing_record.version.as_str()],
            )?;
        }
        self.upsert_installed_version_record(
            &mut registry,
            &plugin_id,
            &manifest,
            &install_path,
            &install_source,
            now,
            &[manifest.version.as_str()],
        )?;
        registry.plugins.insert(plugin_id.clone(), record);
        let mut enabled_overrides = BTreeMap::new();
        enabled_overrides.insert(plugin_id.clone(), true);
        if let Err(error) =
            self.validate_installed_registry_candidate(&registry, &enabled_overrides)
        {
            let _ = fs::remove_dir_all(&install_path);
            return Err(error);
        }
        if let Err(error) = self.store_registry_under_registry_lock(&registry) {
            let _ = fs::remove_dir_all(&install_path);
            return Err(error);
        }
        if let Err(error) = self.write_enabled_state(&plugin_id, Some(true)) {
            let _ = self.store_registry_under_registry_lock(&registry_backup);
            let _ = self.write_enabled_plugins(&enabled_backup);
            let _ = fs::remove_dir_all(&install_path);
            return Err(error);
        }
        self.config.enabled_plugins.insert(plugin_id.clone(), true);

        Ok(InstallOutcome {
            plugin_id,
            version: record_version,
            install_path,
        })
    }

    pub fn enable(&mut self, plugin_id: &str) -> Result<(), PluginError> {
        self.ensure_known_plugin(plugin_id)?;
        let _mutation_locks = self.acquire_mutation_locks_if_needed()?;
        let registry = self.load_registry_under_exclusive_lock()?;
        self.validate_installed_version_records(&registry)?;
        let mut enabled_overrides = BTreeMap::new();
        enabled_overrides.insert(plugin_id.to_string(), true);
        self.validate_installed_registry_candidate(&registry, &enabled_overrides)?;
        self.write_enabled_state(plugin_id, Some(true))?;
        self.config
            .enabled_plugins
            .insert(plugin_id.to_string(), true);
        Ok(())
    }

    pub fn disable(&mut self, plugin_id: &str) -> Result<(), PluginError> {
        self.ensure_known_plugin(plugin_id)?;
        let _mutation_locks = self.acquire_mutation_locks_if_needed()?;
        let registry = self.load_registry_under_exclusive_lock()?;
        self.validate_installed_version_records(&registry)?;
        let dependents = self.enabled_dependents_for_candidate(&registry, plugin_id)?;
        if !dependents.is_empty() {
            return Err(PluginError::InvalidManifest(format!(
                "cannot disable plugin `{plugin_id}` while enabled plugin(s) depend on it: {}",
                dependents.join(", ")
            )));
        }
        self.write_enabled_state(plugin_id, Some(false))?;
        self.config
            .enabled_plugins
            .insert(plugin_id.to_string(), false);
        Ok(())
    }

    pub fn uninstall(&mut self, plugin_id: &str) -> Result<(), PluginError> {
        let _mutation_locks = self.acquire_mutation_locks_if_needed()?;
        let mut registry = self.load_registry_under_exclusive_lock()?;
        self.validate_installed_version_records(&registry)?;
        let dependents = self.enabled_dependents_for_candidate(&registry, plugin_id)?;
        if !dependents.is_empty() {
            return Err(PluginError::InvalidManifest(format!(
                "cannot uninstall plugin `{plugin_id}` while enabled plugin(s) depend on it: {}",
                dependents.join(", ")
            )));
        }
        let registry_backup = registry.clone();
        let enabled_backup = self.config.enabled_plugins.clone();
        let record = registry.plugins.remove(plugin_id).ok_or_else(|| {
            PluginError::NotFound(format!("plugin `{plugin_id}` is not installed"))
        })?;
        if record.kind == PluginKind::Bundled {
            registry.plugins.insert(plugin_id.to_string(), record);
            return Err(PluginError::CommandFailed(format!(
                "plugin `{plugin_id}` is bundled and managed automatically; disable it instead"
            )));
        }
        let mut remove_paths = BTreeSet::new();
        if record.install_path.exists() {
            remove_paths.insert(record.install_path.clone());
        }
        if let Some(versions) = registry.versions.remove(plugin_id) {
            for version in versions {
                if version.install_path.exists() {
                    remove_paths.insert(version.install_path);
                }
            }
        }
        let trash = move_plugin_paths_to_uninstall_trash(&remove_paths, &self.install_root())?;
        if let Err(error) = self.store_registry_under_registry_lock(&registry) {
            return Err(self.restore_failed_uninstall(
                error,
                &registry_backup,
                &enabled_backup,
                trash,
            ));
        }
        if let Err(error) = self.write_enabled_state(plugin_id, None) {
            return Err(self.restore_failed_uninstall(
                error,
                &registry_backup,
                &enabled_backup,
                trash,
            ));
        }
        self.config.enabled_plugins.remove(plugin_id);
        if let Some(trash) = trash {
            if let Err(error) = cleanup_uninstall_trash(&trash.trash_root) {
                self.push_cleanup_warning(format!(
                    "plugin uninstall trash cleanup failed for `{}`: {}",
                    trash.trash_root.display(),
                    sanitize_plugin_error(&error.to_string())
                ));
            }
        }
        Ok(())
    }

    pub fn update(&mut self, plugin_id: &str) -> Result<UpdateOutcome, PluginError> {
        let _mutation_locks = self.acquire_mutation_locks_if_needed()?;
        let mut registry = self.load_registry_under_exclusive_lock()?;
        self.validate_installed_version_records(&registry)?;
        let record = registry.plugins.get(plugin_id).cloned().ok_or_else(|| {
            PluginError::NotFound(format!("plugin `{plugin_id}` is not installed"))
        })?;

        let temp_root = self.install_root().join(".tmp");
        let staged_source = materialize_source(&record.source, &temp_root)?;
        let cleanup_source = matches!(record.source, PluginInstallSource::GitUrl { .. });
        let manifest = load_plugin_from_directory(&staged_source)?;
        validate_plugin_registration_policy(record.kind, &manifest)?;
        let expected_plugin_id = plugin_package_id(&manifest.name, record.kind.marketplace());
        if expected_plugin_id != plugin_id {
            return Err(PluginError::InvalidManifest(format!(
                "updated plugin source declares `{expected_plugin_id}` but `{plugin_id}` was requested"
            )));
        }
        let install_path = self.versioned_plugin_install_path(plugin_id, &manifest.version)?;
        if install_path.exists() {
            return Err(PluginError::InvalidManifest(format!(
                "plugin `{plugin_id}` version `{}` is already installed at immutable version slot `{}`",
                manifest.version,
                install_path.display()
            )));
        }

        self.archive_installed_version(
            &mut registry,
            &record,
            manifest.version_policy.keep_versions,
            &[record.version.as_str(), manifest.version.as_str()],
        )?;
        let replace_result = (|| -> Result<(), PluginError> {
            copy_dir_all_atomic(&staged_source, &install_path)?;
            Ok(())
        })();
        if let Err(error) = replace_result {
            return Err(error);
        }
        if cleanup_source {
            let _ = fs::remove_dir_all(&staged_source);
        }

        let updated_at_unix_ms = unix_time_ms();
        let new_version = manifest.version.clone();
        let updated_record = InstalledPluginRecord {
            version: new_version.clone(),
            description: manifest.description.clone(),
            install_path: install_path.clone(),
            version_policy: manifest.version_policy.clone(),
            updated_at_unix_ms,
            ..record.clone()
        };
        self.upsert_installed_version_record(
            &mut registry,
            plugin_id,
            &manifest,
            &install_path,
            &record.source,
            updated_at_unix_ms,
            &[manifest.version.as_str()],
        )?;
        registry
            .plugins
            .insert(plugin_id.to_string(), updated_record);
        if let Err(error) = self.validate_installed_registry_candidate(&registry, &BTreeMap::new())
        {
            let _ = fs::remove_dir_all(&install_path);
            return Err(error);
        }
        if let Err(error) = self.store_registry_under_registry_lock(&registry) {
            let _ = fs::remove_dir_all(&install_path);
            return Err(error);
        }

        Ok(UpdateOutcome {
            plugin_id: plugin_id.to_string(),
            old_version: record.version,
            new_version,
            install_path,
        })
    }

    pub fn list_versions(&self, plugin_id: &str) -> Result<Vec<String>, PluginError> {
        let registry = self.load_registry()?;
        self.validate_installed_version_records(&registry)?;
        let versions = registry
            .versions
            .get(plugin_id)
            .into_iter()
            .flatten()
            .map(|record| record.version.clone())
            .collect::<BTreeSet<_>>();
        let mut versions = versions.into_iter().collect::<Vec<_>>();
        if let Some(record) = registry.plugins.get(plugin_id) {
            versions.push(record.version.clone());
        }
        if versions.is_empty() {
            return Err(PluginError::NotFound(format!(
                "plugin `{plugin_id}` is not installed"
            )));
        }
        versions.sort_by(|left, right| compare_semver_strings(left, right));
        versions.dedup();
        for version in &versions {
            let _ = parse_semver(version)?;
        }
        Ok(versions)
    }

    pub fn rollback(
        &mut self,
        plugin_id: &str,
        version: &str,
    ) -> Result<RollbackOutcome, PluginError> {
        let _ = parse_semver(version)?;
        let _mutation_locks = self.acquire_mutation_locks_if_needed()?;
        let mut registry = self.load_registry_under_exclusive_lock()?;
        self.validate_installed_version_records(&registry)?;
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
            &[active.version.as_str(), archived.version.as_str()],
        )?;
        let manifest = load_plugin_from_directory(&archived.install_path)?;
        validate_plugin_registration_policy(active.kind, &manifest)?;
        let expected_plugin_id = plugin_package_id(&manifest.name, active.kind.marketplace());
        if expected_plugin_id != plugin_id || manifest.version != archived.version {
            return Err(PluginError::InvalidManifest(format!(
                "archived plugin `{plugin_id}` version `{}` does not match requested rollback version `{version}`",
                archived.version
            )));
        }
        let active_version = manifest.version.clone();
        let rolled_back = InstalledPluginRecord {
            version: active_version.clone(),
            description: manifest.description.clone(),
            install_path: archived.install_path.clone(),
            version_policy: manifest.version_policy.clone(),
            updated_at_unix_ms: unix_time_ms(),
            ..active.clone()
        };
        registry.plugins.insert(plugin_id.to_string(), rolled_back);
        self.validate_installed_registry_candidate(&registry, &BTreeMap::new())?;
        self.store_registry_under_registry_lock(&registry)?;

        Ok(RollbackOutcome {
            plugin_id: plugin_id.to_string(),
            previous_version: active.version,
            active_version,
            install_path: archived.install_path,
        })
    }

    fn discover_installed_plugins_with_failures(&self) -> Result<PluginDiscovery, PluginError> {
        let mut registry = self.load_registry()?;
        if !stale_installed_registry_ids(&registry).is_empty() {
            self.cleanup_stale_registry_entries()?;
            registry = self.load_registry()?;
        }
        self.validate_installed_version_records(&registry)?;
        let mut discovery = PluginDiscovery::default();
        record_uncommitted_registry_migration(&registry, &mut discovery);
        let mut seen_ids = BTreeSet::<String>::new();
        let mut seen_paths = BTreeSet::<PathBuf>::new();
        let mut stale_registry_ids = Vec::new();

        let install_scan_root =
            PluginScanRoot::new(self.install_root(), PluginScanRootSource::Installed);
        let (install_paths, root_report) = discover_plugin_dirs_bounded(&install_scan_root);
        add_scan_root_report(&mut discovery.scan_report, root_report);

        for install_path in install_paths {
            let install_seen_path = canonical_seen_path(&install_path);
            let matched_record = registry.plugins.values().find(|record| {
                record.install_path == install_path
                    || canonical_seen_path(&record.install_path) == install_seen_path
            });
            let kind = matched_record.map_or(PluginKind::External, |record| record.kind);
            let source = matched_record.map_or_else(
                || install_path.display().to_string(),
                |record| describe_install_source(&record.source),
            );
            match load_plugin_definition(&install_path, kind, source.clone(), kind.marketplace()) {
                Ok(mut plugin) => {
                    append_manifest_warnings(&mut plugin, &registry.migration_warnings);
                    if seen_ids.insert(plugin.metadata().id.clone()) {
                        seen_paths.insert(install_seen_path.clone());
                        discovery.push_plugin(plugin);
                    } else if seen_paths.contains(&install_seen_path) {
                        continue;
                    } else {
                        discovery.push_failure(PluginLoadFailure::new(
                            install_path.clone(),
                            kind,
                            source.clone(),
                            PluginError::InvalidManifest(format!(
                                "installed plugin `{}` is duplicated",
                                plugin.metadata().id
                            )),
                        ));
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
            let record_seen_path = canonical_seen_path(&record.install_path);
            if seen_paths.contains(&record_seen_path) {
                continue;
            }
            if !record.install_path.exists() || plugin_manifest_path(&record.install_path).is_err()
            {
                stale_registry_ids.push(record.id.clone());
                continue;
            }
            let record_scan_root =
                PluginScanRoot::new(record.install_path.clone(), PluginScanRootSource::Installed);
            let (record_roots, root_report) = discover_plugin_dirs_bounded(&record_scan_root);
            add_scan_root_report(&mut discovery.scan_report, root_report);
            if record_roots.is_empty() {
                if self
                    .config
                    .enabled_plugins
                    .get(&record.id)
                    .copied()
                    .unwrap_or(false)
                {
                    discovery.push_failure(PluginLoadFailure::new(
                        record.install_path.clone(),
                        record.kind,
                        describe_install_source(&record.source),
                        PluginError::InvalidManifest(format!(
                            "enabled installed plugin `{}` failed bounded scan trust checks",
                            record.id
                        )),
                    ));
                }
                continue;
            }
            let source = describe_install_source(&record.source);
            for record_root in record_roots {
                let record_root_seen_path = canonical_seen_path(&record_root);
                match load_plugin_definition(
                    &record_root,
                    record.kind,
                    source.clone(),
                    record.kind.marketplace(),
                ) {
                    Ok(mut plugin) => {
                        append_manifest_warnings(&mut plugin, &registry.migration_warnings);
                        if seen_ids.insert(plugin.metadata().id.clone()) {
                            seen_paths.insert(record_root_seen_path.clone());
                            discovery.push_plugin(plugin);
                        } else if seen_paths.contains(&record_root_seen_path) {
                            continue;
                        } else {
                            discovery.push_failure(PluginLoadFailure::new(
                                record_root,
                                record.kind,
                                source.clone(),
                                PluginError::InvalidManifest(format!(
                                    "installed plugin `{}` is duplicated",
                                    record.id
                                )),
                            ));
                        }
                    }
                    Err(error) => {
                        discovery.push_failure(PluginLoadFailure::new(
                            record_root,
                            record.kind,
                            source.clone(),
                            error,
                        ));
                    }
                }
            }
        }

        if !stale_registry_ids.is_empty() {
            self.cleanup_stale_registry_entries()?;
        }

        Ok(discovery)
    }

    fn discover_external_directory_plugins_with_failures(
        &self,
        existing_plugins: &[PluginDefinition],
    ) -> Result<PluginDiscovery, PluginError> {
        let mut discovery = PluginDiscovery::default();
        let mut scan_roots = self.config.discovery_roots.clone();
        scan_roots.extend(
            self.config
                .external_dirs
                .iter()
                .cloned()
                .map(|path| PluginScanRoot::new(path, PluginScanRootSource::ExplicitConfig)),
        );
        stable_dedup_scan_roots(&mut scan_roots);
        if scan_roots.len() > PLUGIN_SCAN_MAX_ROOTS {
            record_scan_warning(
                &mut discovery.scan_report,
                &format!(
                    "plugin discovery roots exceed {PLUGIN_SCAN_MAX_ROOTS}; extra roots were skipped"
                ),
            );
            discovery.scan_report.omitted_count += scan_roots.len() - PLUGIN_SCAN_MAX_ROOTS;
            discovery.scan_report.truncated = true;
            scan_roots.truncate(PLUGIN_SCAN_MAX_ROOTS);
        }

        let mut selected = BTreeMap::<String, ScannedPluginCandidate>::new();
        for scan_root in &scan_roots {
            let (roots, root_report) = discover_plugin_dirs_bounded(scan_root);
            add_scan_root_report(&mut discovery.scan_report, root_report);
            for root in roots {
                let source = root.display().to_string();
                match load_plugin_definition(
                    &root,
                    PluginKind::External,
                    discovered_plugin_source(scan_root, &root),
                    EXTERNAL_MARKETPLACE,
                ) {
                    Ok(plugin) => {
                        let id = plugin.metadata().id.clone();
                        let candidate = ScannedPluginCandidate {
                            plugin,
                            root: root.clone(),
                            source,
                            priority: scan_root.priority,
                        };
                        match selected.get(&id) {
                            Some(existing) if existing.priority > candidate.priority => {
                                discovery.scan_report.skipped_count += 1;
                                record_scan_warning(
                                    &mut discovery.scan_report,
                                    &format!(
                                        "plugin `{id}` duplicate resolved: winner priority {} `{}`, loser priority {} `{}` from {} root",
                                        existing.priority,
                                        existing.root.display(),
                                        candidate.priority,
                                        root.display(),
                                        scan_root.source,
                                    ),
                                );
                            }
                            Some(existing) if existing.priority == candidate.priority => {
                                discovery.scan_report.failure_count += 1;
                                discovery.push_failure(PluginLoadFailure::new(
                                    root,
                                    PluginKind::External,
                                    candidate.source,
                                    PluginError::InvalidManifest(format!(
                                        "plugin `{id}` is duplicated in equal-priority discovery roots at priority {}: `{}` and `{}`",
                                        candidate.priority,
                                        existing.root.display(),
                                        candidate.root.display()
                                    )),
                                ));
                            }
                            Some(existing) => {
                                discovery.scan_report.skipped_count += 1;
                                record_scan_warning(
                                    &mut discovery.scan_report,
                                    &format!(
                                        "plugin `{id}` duplicate resolved: winner priority {} `{}`, loser priority {} `{}` from {} root",
                                        candidate.priority,
                                        root.display(),
                                        existing.priority,
                                        existing.root.display(),
                                        scan_root.source,
                                    ),
                                );
                                selected.insert(id, candidate);
                            }
                            None => {
                                selected.insert(id, candidate);
                            }
                        }
                    }
                    Err(error) => {
                        discovery.scan_report.failure_count += 1;
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

        for (_, candidate) in selected {
            if let Some(existing) = existing_plugins
                .iter()
                .find(|existing| existing.metadata().id == candidate.plugin.metadata().id)
            {
                discovery.scan_report.failure_count += 1;
                discovery.push_failure(PluginLoadFailure::new(
                    candidate.root,
                    PluginKind::External,
                    candidate.source,
                    PluginError::InvalidManifest(format!(
                        "discovered plugin `{}` conflicts with existing plugin `{}`",
                        candidate.plugin.metadata().id,
                        existing.metadata().id
                    )),
                ));
                continue;
            }
            if let Some(existing) = existing_plugins
                .iter()
                .find(|existing| existing.metadata().name == candidate.plugin.metadata().name)
            {
                discovery.scan_report.failure_count += 1;
                discovery.push_failure(PluginLoadFailure::new(
                    candidate.root,
                    PluginKind::External,
                    candidate.source,
                    PluginError::InvalidManifest(format!(
                        "discovered plugin name `{}` conflicts with existing plugin `{}`",
                        candidate.plugin.metadata().name,
                        existing.metadata().id
                    )),
                ));
                continue;
            }
            discovery.push_plugin(candidate.plugin);
        }

        Ok(discovery)
    }

    pub fn installed_plugin_registry_report(&self) -> Result<PluginRegistryReport, PluginError> {
        let mut discovery = self.sync_bundled_plugins()?;
        discovery.extend(self.discover_installed_plugins_with_failures()?);
        Ok(self.build_registry_report(discovery))
    }

    fn sync_bundled_plugins(&self) -> Result<PluginDiscovery, PluginError> {
        let _mutation_locks = self.acquire_mutation_locks_if_needed()?;
        let mut discovery = PluginDiscovery::default();
        let bundled_root = self
            .config
            .bundled_root
            .clone()
            .unwrap_or_else(Self::bundled_root);
        let scan_root = PluginScanRoot::new(&bundled_root, PluginScanRootSource::Bundled);
        let (bundled_plugins, root_report) = discover_plugin_dirs_bounded(&scan_root);
        let bundled_scan_truncated = root_report.truncated;
        add_scan_root_report(&mut discovery.scan_report, root_report);
        let mut registry = self.load_registry_under_exclusive_lock()?;
        let mut changed = false;
        let mut active_bundled_ids = BTreeSet::new();

        for source_root in bundled_plugins {
            let manifest = match load_plugin_from_directory(&source_root) {
                Ok(manifest) => manifest,
                Err(error) => {
                    discovery.push_failure(PluginLoadFailure::new(
                        source_root.clone(),
                        PluginKind::Bundled,
                        source_root.display().to_string(),
                        error,
                    ));
                    continue;
                }
            };
            let plugin_id = plugin_id(&manifest.name, BUNDLED_MARKETPLACE);
            active_bundled_ids.insert(plugin_id.clone());
            let install_path = self.versioned_plugin_install_path(&plugin_id, &manifest.version)?;
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

            if !install_path.exists() {
                if let Err(error) = copy_dir_all_atomic(&source_root, &install_path) {
                    discovery.push_failure(PluginLoadFailure::new(
                        source_root.clone(),
                        PluginKind::Bundled,
                        source_root.display().to_string(),
                        error,
                    ));
                    continue;
                }
            } else if !installed_copy_is_valid {
                discovery.push_failure(PluginLoadFailure::new(
                    source_root.clone(),
                    PluginKind::Bundled,
                    source_root.display().to_string(),
                    PluginError::InvalidManifest(format!(
                        "bundled plugin immutable version slot `{}` is invalid",
                        install_path.display()
                    )),
                ));
                continue;
            }

            let installed_at_unix_ms =
                existing_record.map_or(now, |record| record.installed_at_unix_ms);
            self.upsert_installed_version_record(
                &mut registry,
                &plugin_id,
                &manifest,
                &install_path,
                &PluginInstallSource::LocalPath {
                    path: source_root.clone(),
                },
                now,
                &[manifest.version.as_str()],
            )?;
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
                (!bundled_scan_truncated
                    && record.kind == PluginKind::Bundled
                    && !active_bundled_ids.contains(plugin_id))
                .then_some(plugin_id.clone())
            })
            .collect::<Vec<_>>();

        for plugin_id in stale_bundled_ids {
            if let Some(record) = registry.plugins.remove(&plugin_id) {
                if record.install_path.exists() {
                    fs::remove_dir_all(&record.install_path)?;
                }
                if let Some(versions) = registry.versions.remove(&plugin_id) {
                    for version in versions {
                        if version.install_path.exists() {
                            fs::remove_dir_all(version.install_path)?;
                        }
                    }
                }
                changed = true;
            }
        }

        if changed {
            self.store_registry_under_registry_lock(&registry)?;
        }

        Ok(discovery)
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
        self.load_registry_inner(true)
    }

    fn load_registry_under_exclusive_lock(&self) -> Result<InstalledPluginRegistry, PluginError> {
        self.load_registry_inner(false)
    }

    fn load_registry_inner(
        &self,
        acquire_migration_lock: bool,
    ) -> Result<InstalledPluginRegistry, PluginError> {
        let path = self.registry_path();
        match read_registry_at_path(&path) {
            Ok(registry) => {
                let original = registry.clone();
                let migrated = self.migrate_legacy_installed_registry(registry)?;
                let sanitized = sanitize_registry_for_storage(&migrated);
                if sanitized == original {
                    return Ok(sanitized);
                }
                if acquire_migration_lock {
                    let _migration_guard = self.acquire_registry_lock()?;
                    let fresh_registry = read_registry_at_path(&path)?;
                    let fresh_migrated = self.migrate_legacy_installed_registry(fresh_registry)?;
                    let fresh_sanitized = sanitize_registry_for_storage(&fresh_migrated);
                    return migrate_registry_source_metadata_under_lock(&path, fresh_sanitized);
                }
                migrate_registry_source_metadata_under_lock(&path, sanitized)
            }
            Err(PluginError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(InstalledPluginRegistry::default())
            }
            Err(error) => Err(error),
        }
    }

    #[cfg(test)]
    fn store_registry(&self, registry: &InstalledPluginRegistry) -> Result<(), PluginError> {
        let _registry_guard = self.acquire_registry_lock()?;
        self.store_registry_under_registry_lock(registry)
    }

    fn store_registry_under_registry_lock(
        &self,
        registry: &InstalledPluginRegistry,
    ) -> Result<(), PluginError> {
        let path = self.registry_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let sanitized = sanitize_registry_for_storage(registry);
        store_registry_at_path(&path, &sanitized)?;
        Ok(())
    }

    fn migrate_legacy_installed_registry(
        &self,
        mut registry: InstalledPluginRegistry,
    ) -> Result<InstalledPluginRegistry, PluginError> {
        match registry.schema_version {
            INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION => return Ok(registry),
            LEGACY_INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION => {}
            other => {
                return Err(PluginError::InvalidManifest(format!(
                    "unsupported plugin registry schemaVersion `{other}`"
                )));
            }
        }

        if !registry.versions.is_empty() {
            return Err(PluginError::InvalidManifest(
                "legacy plugin registry cannot contain immutable version records; refusing schema downgrade migration"
                    .to_string(),
            ));
        }

        for (plugin_id, active) in &registry.plugins {
            let expected_slot = self.versioned_plugin_install_path(plugin_id, &active.version)?;
            if canonical_seen_path(&active.install_path) == canonical_seen_path(&expected_slot) {
                return Err(PluginError::InvalidManifest(format!(
                    "legacy plugin registry active plugin `{plugin_id}` already uses current immutable version slot layout; refusing schema downgrade migration"
                )));
            }
        }

        registry.schema_version = INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION;
        let plugin_ids = registry.plugins.keys().cloned().collect::<Vec<_>>();
        for plugin_id in plugin_ids {
            let Some(active) = registry.plugins.get(&plugin_id).cloned() else {
                continue;
            };
            if !active.install_path.exists() || plugin_manifest_path(&active.install_path).is_err()
            {
                continue;
            }
            let manifest = load_plugin_from_directory(&active.install_path)?;
            validate_plugin_registration_policy(active.kind, &manifest)?;
            let expected_plugin_id = plugin_package_id(&manifest.name, active.kind.marketplace());
            if expected_plugin_id != plugin_id || manifest.version != active.version {
                return Err(PluginError::InvalidManifest(format!(
                    "legacy registry active plugin `{plugin_id}` does not match manifest at `{}`",
                    sanitize_plugin_error(&active.install_path.display().to_string())
                )));
            }
            let version_records = registry.versions.entry(plugin_id.clone()).or_default();
            version_records.retain(|record| record.version != active.version);
            version_records.push(InstalledPluginVersionRecord {
                archive_id: installed_archive_id(&plugin_id, &active.version),
                version: active.version.clone(),
                description: manifest.description,
                install_path: active.install_path.clone(),
                source: describe_install_source(&active.source),
                content_hash: plugin_tree_hash(&active.install_path)?,
                archived_at_unix_ms: active.updated_at_unix_ms,
            });
        }
        Ok(registry)
    }

    fn cleanup_stale_registry_entries(&self) -> Result<(), PluginError> {
        let _registry_guard = self.acquire_registry_lock()?;
        let mut registry = self.load_registry_under_exclusive_lock()?;
        let stale_ids = stale_installed_registry_ids(&registry);
        if stale_ids.is_empty() {
            return Ok(());
        }
        for plugin_id in stale_ids {
            registry.plugins.remove(&plugin_id);
            registry.versions.remove(&plugin_id);
        }
        self.store_registry_under_registry_lock(&registry)
    }

    fn versioned_plugin_install_path(
        &self,
        plugin_id: &str,
        version: &str,
    ) -> Result<PathBuf, PluginError> {
        let _ = parse_semver(version)?;
        Ok(self
            .install_root()
            .join(PLUGIN_VERSIONS_DIR_NAME)
            .join(sanitize_plugin_id(plugin_id))
            .join(version))
    }

    fn upsert_installed_version_record(
        &self,
        registry: &mut InstalledPluginRegistry,
        plugin_id: &str,
        manifest: &PluginManifest,
        install_path: &Path,
        source: &PluginInstallSource,
        archived_at_unix_ms: u128,
        protected_versions: &[&str],
    ) -> Result<InstalledPluginVersionRecord, PluginError> {
        let _ = parse_semver(&manifest.version)?;
        let content_hash = plugin_tree_hash(install_path)?;
        let archived_record = InstalledPluginVersionRecord {
            archive_id: installed_archive_id(plugin_id, &manifest.version),
            version: manifest.version.clone(),
            description: manifest.description.clone(),
            install_path: install_path.to_path_buf(),
            source: describe_install_source(source),
            content_hash,
            archived_at_unix_ms,
        };
        let versions = registry.versions.entry(plugin_id.to_string()).or_default();
        versions.retain(|existing| existing.version != archived_record.version);
        versions.push(archived_record.clone());
        prune_archived_versions(
            versions,
            manifest.version_policy.keep_versions,
            protected_versions,
        );
        Ok(archived_record)
    }

    fn archive_installed_version(
        &self,
        registry: &mut InstalledPluginRegistry,
        record: &InstalledPluginRecord,
        keep_versions: usize,
        protected_versions: &[&str],
    ) -> Result<Option<InstalledPluginVersionRecord>, PluginError> {
        if !record.install_path.exists() {
            return Ok(None);
        }

        let archive_path = self.versioned_plugin_install_path(&record.id, &record.version)?;
        let source_seen = canonical_seen_path(&record.install_path);
        let archive_seen = canonical_seen_path(&archive_path);
        if source_seen != archive_seen {
            if archive_path.exists() {
                let archived_manifest = load_plugin_from_directory(&archive_path)?;
                let expected_plugin_id =
                    plugin_id(&archived_manifest.name, record.kind.marketplace());
                if expected_plugin_id != record.id || archived_manifest.version != record.version {
                    return Err(PluginError::InvalidManifest(format!(
                        "immutable version slot `{}` does not match plugin `{}` version `{}`",
                        archive_path.display(),
                        record.id,
                        record.version
                    )));
                }
            } else {
                copy_dir_all_atomic(&record.install_path, &archive_path)?;
            }
        }

        let manifest = load_plugin_from_directory(&archive_path)?;
        validate_plugin_registration_policy(record.kind, &manifest)?;
        let expected_plugin_id = plugin_id(&manifest.name, record.kind.marketplace());
        if expected_plugin_id != record.id || manifest.version != record.version {
            return Err(PluginError::InvalidManifest(format!(
                "archived plugin `{}` version `{}` does not match source record",
                record.id, record.version
            )));
        }
        let content_hash = plugin_tree_hash(&archive_path)?;
        let archived_record = InstalledPluginVersionRecord {
            archive_id: installed_archive_id(&record.id, &record.version),
            version: record.version.clone(),
            description: manifest.description,
            install_path: archive_path,
            source: describe_install_source(&record.source),
            content_hash,
            archived_at_unix_ms: unix_time_ms(),
        };
        let versions = registry.versions.entry(record.id.clone()).or_default();
        versions.retain(|archived| archived.version != record.version);
        versions.push(archived_record.clone());
        prune_archived_versions(versions, keep_versions, protected_versions);
        Ok(Some(archived_record))
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

    fn write_enabled_plugins(&self, enabled: &BTreeMap<String, bool>) -> Result<(), PluginError> {
        update_settings_json(&self.settings_path(), |root| {
            let enabled_plugins = ensure_object(root, "enabledPlugins");
            enabled_plugins.clear();
            enabled_plugins.extend(
                enabled
                    .iter()
                    .map(|(plugin_id, value)| (plugin_id.clone(), Value::Bool(*value))),
            );
        })
    }

    fn restore_hot_load_backup(
        &mut self,
        registry_backup: &InstalledPluginRegistry,
        enabled_backup: &BTreeMap<String, bool>,
        install_root: &Path,
        backup_root: &Path,
        install_root_had_contents: bool,
    ) -> Result<(), PluginError> {
        if install_root.exists() {
            fs::remove_dir_all(install_root)?;
        }
        if install_root_had_contents {
            copy_dir_all(backup_root, install_root)?;
            if backup_root.exists() {
                fs::remove_dir_all(backup_root)?;
            }
        }
        self.store_registry_under_registry_lock(registry_backup)?;
        self.write_enabled_plugins(enabled_backup)?;
        self.config.enabled_plugins = enabled_backup.clone();
        Ok(())
    }

    fn restore_failed_uninstall(
        &mut self,
        original_error: PluginError,
        registry_backup: &InstalledPluginRegistry,
        enabled_backup: &BTreeMap<String, bool>,
        trash: Option<UninstallTrash>,
    ) -> PluginError {
        let mut restore_errors = Vec::new();
        if let Err(error) = self.store_registry_under_registry_lock(registry_backup) {
            restore_errors.push(format!(
                "registry: {}",
                sanitize_plugin_error(&error.to_string())
            ));
        }
        if let Err(error) = self.write_enabled_plugins(enabled_backup) {
            restore_errors.push(format!(
                "settings: {}",
                sanitize_plugin_error(&error.to_string())
            ));
        }
        self.config.enabled_plugins = enabled_backup.clone();
        if let Some(trash) = trash {
            if let Err(error) = restore_uninstall_trash(&trash) {
                restore_errors.push(format!(
                    "install tree: {}",
                    sanitize_plugin_error(&error.to_string())
                ));
            }
        }
        if restore_errors.is_empty() {
            original_error
        } else {
            PluginError::CommandFailed(truncate_plugin_error(&format!(
                "{}; uninstall rollback failed: {}",
                sanitize_plugin_error(&original_error.to_string()),
                restore_errors.join("; ")
            )))
        }
    }

    fn acquire_registry_lock(&self) -> Result<PluginFileLock, PluginError> {
        acquire_plugin_file_lock_at(
            &registry_lock_path(&self.registry_path()),
            "plugin registry",
            Duration::from_millis(PLUGIN_LOCK_TIMEOUT_MS),
        )
    }

    fn acquire_mutation_locks(&self) -> Result<PluginMutationLocks, PluginError> {
        let registry_lock_path = registry_lock_path(&self.registry_path());
        let install_lock_path = install_tree_lock_path(&self.install_root());
        let registry = acquire_plugin_file_lock_at(
            &registry_lock_path,
            "plugin registry",
            Duration::from_millis(PLUGIN_LOCK_TIMEOUT_MS),
        )?;
        let install = (!same_lock_path(&registry_lock_path, &install_lock_path)).then(|| {
            acquire_plugin_file_lock_at(
                &install_lock_path,
                "plugin install tree",
                Duration::from_millis(PLUGIN_LOCK_TIMEOUT_MS),
            )
        });
        let install = match install {
            Some(lock) => Some(lock?),
            None => None,
        };
        Ok(PluginMutationLocks {
            _registry: registry,
            _install: install,
        })
    }

    fn acquire_mutation_locks_if_needed(&self) -> Result<Option<PluginMutationLocks>, PluginError> {
        if self.mutation_locks_held {
            Ok(None)
        } else {
            self.acquire_mutation_locks().map(Some)
        }
    }

    fn validate_installed_registry_candidate(
        &self,
        registry: &InstalledPluginRegistry,
        enabled_overrides: &BTreeMap<String, bool>,
    ) -> Result<(), PluginError> {
        self.validate_installed_version_records(registry)?;
        let candidate = self.installed_registry_from_records(registry, enabled_overrides)?;
        validate_runtime_snapshot(&candidate)
    }

    fn installed_registry_from_records(
        &self,
        registry: &InstalledPluginRegistry,
        enabled_overrides: &BTreeMap<String, bool>,
    ) -> Result<PluginRegistry, PluginError> {
        let available_versions = installed_available_versions_by_id(registry);
        let mut plugins = Vec::new();
        for record in registry.plugins.values() {
            let plugin = load_plugin_definition(
                &record.install_path,
                record.kind,
                describe_install_source(&record.source),
                record.kind.marketplace(),
            )?;
            validate_installed_record_identity(record, &plugin)?;
            let enabled = enabled_overrides
                .get(&record.id)
                .copied()
                .unwrap_or_else(|| self.is_enabled(plugin.metadata()));
            let versions = available_versions
                .get(&record.id)
                .cloned()
                .unwrap_or_else(|| BTreeSet::from([record.version.clone()]));
            plugins.push(RegisteredPlugin::new(plugin, enabled).with_available_versions(versions));
        }
        Ok(PluginRegistry::new(plugins))
    }

    fn validate_installed_version_records(
        &self,
        registry: &InstalledPluginRegistry,
    ) -> Result<(), PluginError> {
        if registry.schema_version != INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION {
            return Err(PluginError::InvalidManifest(format!(
                "unsupported plugin registry schemaVersion `{}`",
                registry.schema_version
            )));
        }
        for (plugin_id, active) in &registry.plugins {
            let _ = parse_semver(&active.version)?;
            let records = registry.versions.get(plugin_id).ok_or_else(|| {
                PluginError::InvalidManifest(format!(
                    "active plugin `{plugin_id}` version `{}` is missing its immutable version slot record",
                    sanitize_plugin_error(&active.version)
                ))
            })?;
            let matching = records
                .iter()
                .filter(|record| record.version == active.version)
                .collect::<Vec<_>>();
            if matching.is_empty() {
                return Err(PluginError::InvalidManifest(format!(
                    "active plugin `{plugin_id}` version `{}` is missing its immutable version slot record",
                    sanitize_plugin_error(&active.version)
                )));
            }
            if matching.len() > 1 {
                return Err(PluginError::InvalidManifest(format!(
                    "active plugin `{plugin_id}` version `{}` has duplicate immutable version slot records",
                    sanitize_plugin_error(&active.version)
                )));
            }
            let active_path = canonical_seen_path(&active.install_path);
            let version_path = canonical_seen_path(&matching[0].install_path);
            if version_path != active_path {
                return Err(PluginError::InvalidManifest(format!(
                    "active plugin `{plugin_id}` version `{}` has immutable version slot path mismatch",
                    sanitize_plugin_error(&active.version)
                )));
            }
        }
        for (plugin_id, records) in &registry.versions {
            let Some(active) = registry.plugins.get(plugin_id) else {
                return Err(PluginError::InvalidManifest(format!(
                    "archived versions exist for unknown plugin `{plugin_id}`"
                )));
            };
            for record in records {
                let _ = parse_semver(&record.version)?;
                let expected_archive_id = installed_archive_id(plugin_id, &record.version);
                if record.archive_id != expected_archive_id {
                    return Err(PluginError::InvalidManifest(format!(
                        "version slot `{}` for plugin `{plugin_id}` has archiveId `{}` but expected `{expected_archive_id}`",
                        record.version,
                        sanitize_plugin_error(&record.archive_id)
                    )));
                }
                let manifest = load_plugin_from_directory(&record.install_path)?;
                validate_plugin_registration_policy(active.kind, &manifest)?;
                let expected_plugin_id =
                    plugin_package_id(&manifest.name, active.kind.marketplace());
                if expected_plugin_id != *plugin_id || manifest.version != record.version {
                    return Err(PluginError::InvalidManifest(format!(
                        "version slot `{}` does not match plugin `{plugin_id}` version `{}`",
                        sanitize_plugin_error(&record.install_path.display().to_string()),
                        record.version
                    )));
                }
                let actual_hash = plugin_tree_hash(&record.install_path)?;
                if record.content_hash.is_empty() {
                    return Err(PluginError::InvalidManifest(format!(
                        "version slot `{}` for plugin `{plugin_id}` is missing contentHash",
                        record.version
                    )));
                }
                if record.content_hash != actual_hash {
                    return Err(PluginError::InvalidManifest(format!(
                        "version slot `{}` for plugin `{plugin_id}` contentHash mismatch: expected `{}` actual `{actual_hash}`",
                        record.version,
                        sanitize_plugin_error(&record.content_hash)
                    )));
                }
            }
        }
        Ok(())
    }

    fn enabled_dependents_for_candidate(
        &self,
        registry: &InstalledPluginRegistry,
        plugin_id: &str,
    ) -> Result<Vec<String>, PluginError> {
        let candidate = self.installed_registry_from_records(registry, &BTreeMap::new())?;
        let mut blocked = BTreeSet::from([plugin_id.to_string()]);
        let mut dependents = BTreeSet::new();
        loop {
            let mut changed = false;
            for plugin in candidate
                .plugins()
                .iter()
                .filter(|plugin| plugin.is_enabled())
            {
                if blocked.contains(&plugin.metadata().id) {
                    continue;
                }
                if plugin.dependencies().iter().any(|dependency| {
                    blocked.iter().any(|blocked_id| {
                        candidate.get(blocked_id).is_some_and(|blocked_plugin| {
                            dependency_refers_to_plugin(dependency, blocked_plugin)
                        })
                    })
                }) {
                    blocked.insert(plugin.metadata().id.clone());
                    dependents.insert(plugin.metadata().id.clone());
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        Ok(dependents.into_iter().collect())
    }

    fn build_registry_report(&self, discovery: PluginDiscovery) -> PluginRegistryReport {
        let available_versions = self
            .load_registry()
            .map(|registry| installed_available_versions_by_id(&registry))
            .unwrap_or_default();
        PluginRegistryReport::with_scan_report(
            PluginRegistry::new(
                discovery
                    .plugins
                    .into_iter()
                    .map(|plugin| {
                        let enabled = self.is_enabled(plugin.metadata());
                        let versions = available_versions
                            .get(&plugin.metadata().id)
                            .cloned()
                            .unwrap_or_else(|| BTreeSet::from([plugin.metadata().version.clone()]));
                        RegisteredPlugin::new(plugin, enabled).with_available_versions(versions)
                    })
                    .collect(),
            ),
            discovery.failures,
            discovery.scan_report,
        )
        .with_blocked_plugins(discovery.blocked_plugin_ids)
    }
}

#[must_use]
pub fn builtin_plugins() -> Vec<PluginDefinition> {
    let mut plugins = vec![builtin_plugin_from_manifest(PluginManifest {
        schema_version: PLUGIN_MANIFEST_SCHEMA_VERSION,
        id: None,
        name: "example-builtin".to_string(),
        version: "0.1.0".to_string(),
        description: "Example built-in plugin scaffold for the Rust plugin system".to_string(),
        permissions: Vec::new(),
        permission_declarations: Vec::new(),
        entrypoint: None,
        manifest_metadata: PluginManifestMetadata::builtin(),
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
            schema_version: PLUGIN_MANIFEST_SCHEMA_VERSION,
            id: None,
            name: name.to_string(),
            version: "0.1.0".to_string(),
            description: description.to_string(),
            permissions: vec![manifest_permission_for_tool(permission)],
            permission_declarations: vec![PluginPermissionDeclaration::Legacy {
                permission: manifest_permission_for_tool(permission),
            }],
            entrypoint: None,
            manifest_metadata: PluginManifestMetadata::builtin(),
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
        manifest: manifest.manifest_metadata,
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
        permission_declarations: manifest.permission_declarations,
        tools,
        commands: manifest.commands,
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
    validate_plugin_registration_policy(kind, &manifest)?;
    let metadata = PluginMetadata {
        id: plugin_id(&manifest.name, marketplace),
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        description: manifest.description.clone(),
        kind,
        source,
        default_enabled: manifest.default_enabled,
        root: Some(root.to_path_buf()),
        manifest: manifest.manifest_metadata.clone(),
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
            permission_declarations: manifest.permission_declarations,
            tools,
            commands: manifest.commands,
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
            permission_declarations: manifest.permission_declarations,
            tools,
            commands: manifest.commands,
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
            permission_declarations: manifest.permission_declarations,
            tools,
            commands: manifest.commands,
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

fn validate_plugin_registration_policy(
    kind: PluginKind,
    manifest: &PluginManifest,
) -> Result<(), PluginError> {
    if kind == PluginKind::External && !manifest.hooks.is_empty() {
        return Err(PluginError::InvalidManifest(
            "external plugin hooks are rejected by default: FR-2.5 requires a unified sandboxed hook runner before external hooks can be registered".to_string(),
        ));
    }
    Ok(())
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
    audit_plugin_tree(root)?;
    let metadata = fs::symlink_metadata(manifest_path)?;
    if metadata.len() > PLUGIN_MANIFEST_MAX_BYTES {
        return Err(PluginError::ManifestValidation(vec![
            PluginManifestValidationError::UnsupportedManifestContract {
                detail: format!("plugin manifest exceeds {PLUGIN_MANIFEST_MAX_BYTES} byte limit"),
            },
        ]));
    }
    let contents = fs::read_to_string(manifest_path).map_err(|error| {
        PluginError::NotFound(format!(
            "plugin manifest not found at {}: {error}",
            manifest_path.display()
        ))
    })?;
    let raw_json: Value = serde_json::from_str(&contents)?;
    let schema = validate_manifest_schema_envelope(&raw_json)?;
    let compatibility_errors = detect_claude_code_manifest_contract_gaps(&raw_json);
    if !compatibility_errors.is_empty() {
        return Err(PluginError::ManifestValidation(compatibility_errors));
    }
    let raw_manifest: RawPluginManifest = serde_json::from_value(raw_json)?;
    build_plugin_manifest(root, raw_manifest, schema)
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

fn validate_manifest_schema_envelope(
    raw_manifest: &Value,
) -> Result<ManifestSchemaEnvelope, PluginError> {
    let Some(root) = raw_manifest.as_object() else {
        return Err(PluginError::ManifestValidation(vec![
            PluginManifestValidationError::UnsupportedManifestContract {
                detail: "plugin manifest root must be a JSON object".to_string(),
            },
        ]));
    };

    let explicit_schema = root.contains_key("schemaVersion");
    let schema_version = match root.get("schemaVersion") {
        Some(Value::Number(value)) => value.as_u64(),
        Some(_) => None,
        None => Some(PLUGIN_MANIFEST_SCHEMA_VERSION),
    }
    .ok_or_else(|| {
        PluginError::ManifestValidation(vec![
            PluginManifestValidationError::UnsupportedManifestContract {
                detail: "plugin manifest schemaVersion must be an unsigned integer".to_string(),
            },
        ])
    })?;

    if schema_version != PLUGIN_MANIFEST_SCHEMA_VERSION {
        return Err(PluginError::ManifestValidation(vec![
            PluginManifestValidationError::UnsupportedManifestContract {
                detail: format!(
                    "plugin manifest schemaVersion {schema_version} is unsupported; supported versions: [{PLUGIN_MANIFEST_SCHEMA_VERSION}]"
                ),
            },
        ]));
    }

    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    validate_manifest_unknown_fields(
        raw_manifest,
        &[],
        explicit_schema,
        schema_version,
        &mut warnings,
        &mut errors,
    );
    if !errors.is_empty() {
        return Err(PluginError::ManifestValidation(errors));
    }

    if !explicit_schema {
        warnings.insert(
            0,
            "legacy manifest omitted schemaVersion; normalized to schemaVersion 1".to_string(),
        );
    }

    Ok(ManifestSchemaEnvelope {
        schema_version,
        legacy: !explicit_schema,
        explicit_capabilities: root.contains_key("capabilities"),
        hash: canonical_manifest_hash(raw_manifest),
        warnings,
    })
}

fn validate_manifest_unknown_fields(
    value: &Value,
    path: &[&str],
    explicit_schema: bool,
    schema_version: u64,
    warnings: &mut Vec<String>,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    match value {
        Value::Object(object) => {
            if let Some(known_fields) = known_manifest_fields_for_path(path) {
                for key in object.keys() {
                    if known_fields.contains(&key.as_str()) {
                        continue;
                    }
                    let field_path = manifest_field_path(path, key);
                    if explicit_schema {
                        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                            detail: format!(
                                "plugin manifest schemaVersion {schema_version} rejects unknown field `{field_path}`"
                            ),
                        });
                    } else if is_sensitive_unknown_manifest_field(key) {
                        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                            detail: format!(
                                "legacy plugin manifest unknown security-sensitive field `{field_path}` is rejected; add schemaVersion and use the structured permissions contract"
                            ),
                        });
                    } else {
                        push_manifest_warning(
                            warnings,
                            format!(
                                "legacy manifest ignored unknown field `{field_path}` while normalizing to schemaVersion 1"
                            ),
                        );
                    }
                }
            }

            for (key, child) in object {
                if should_skip_manifest_unknown_recursion(path, key) {
                    continue;
                }
                if path.is_empty() && key == "mcpServers" {
                    if let Value::Object(servers) = child {
                        for server in servers.values() {
                            validate_manifest_unknown_fields(
                                server,
                                &["mcpServers", "*"],
                                explicit_schema,
                                schema_version,
                                warnings,
                                errors,
                            );
                        }
                    }
                    continue;
                }
                let next = next_manifest_path(path, key, child);
                validate_manifest_unknown_fields(
                    child,
                    &next,
                    explicit_schema,
                    schema_version,
                    warnings,
                    errors,
                );
            }
        }
        Value::Array(values) => {
            let next = array_manifest_path(path);
            for child in values {
                validate_manifest_unknown_fields(
                    child,
                    &next,
                    explicit_schema,
                    schema_version,
                    warnings,
                    errors,
                );
            }
        }
        _ => {}
    }
}

fn push_manifest_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 32 && !warnings.iter().any(|existing| existing == &warning) {
        warnings.push(truncate_plugin_error(&warning));
    }
}

fn manifest_field_path(path: &[&str], key: &str) -> String {
    if path.is_empty() {
        key.to_string()
    } else {
        format!("{}.{}", path.join("."), key)
    }
}

fn should_skip_manifest_unknown_recursion(path: &[&str], key: &str) -> bool {
    matches!(
        key,
        "inputSchema" | "outputSchema" | "schema" | "env" | "headers"
    ) || matches!(path, ["rollback"]) && key == "notes"
}

fn next_manifest_path<'a>(path: &[&'a str], key: &'a str, _child: &Value) -> Vec<&'a str> {
    let mut next = path.to_vec();
    next.push(key);
    next
}

fn array_manifest_path<'a>(path: &[&'a str]) -> Vec<&'a str> {
    let mut next = path.to_vec();
    next.push("[]");
    next
}

fn known_manifest_fields_for_path(path: &[&str]) -> Option<&'static [&'static str]> {
    match path {
        [] => Some(&[
            "schemaVersion",
            "id",
            "name",
            "version",
            "description",
            "permissions",
            "signature",
            "entrypoint",
            "defaultEnabled",
            "hooks",
            "lifecycle",
            "executionPolicy",
            "tools",
            "commands",
            "capabilities",
            "mcpServers",
            "dependencies",
            "rollback",
            "versionPolicy",
            "opsPermissions",
            "resources",
            "prompts",
        ]),
        ["hooks"] => Some(&["PreToolUse", "PostToolUse", "PostToolUseFailure"]),
        ["lifecycle"] => Some(&["Init", "Shutdown"]),
        ["executionPolicy"] => Some(&["allowExternalSubprocess", "reason"]),
        ["entrypoint"] => Some(&["command", "args"]),
        ["tools", "[]"] => Some(&[
            "name",
            "description",
            "inputSchema",
            "outputSchema",
            "command",
            "args",
            "requiredPermission",
        ]),
        ["commands", "[]"] => Some(&["name", "description", "command"]),
        ["capabilities"] => Some(&["tools", "resources", "prompts", "workflows", "hotReload"]),
        ["mcpServers", "*"] => Some(&[
            "transport",
            "requiredPermission",
            "command",
            "args",
            "env",
            "url",
            "headers",
            "protocolVersion",
            "toolCallTimeoutMs",
            "heartbeat",
            "capabilities",
        ]),
        ["mcpServers", "*", "heartbeat"] => Some(&["intervalMs", "timeoutMs"]),
        ["mcpServers", "*", "capabilities"] => Some(&["tools", "resources", "prompts"]),
        ["mcpServers", "*", "capabilities", "tools", "[]"] => {
            Some(&["name", "description", "inputSchema", "outputSchema"])
        }
        ["mcpServers", "*", "capabilities", "resources", "[]"] => {
            Some(&["uri", "name", "description", "mimeType"])
        }
        ["mcpServers", "*", "capabilities", "prompts", "[]"] => {
            Some(&["name", "description", "arguments", "template"])
        }
        ["mcpServers", "*", "capabilities", "prompts", "[]", "arguments", "[]"] => {
            Some(&["name", "description", "required", "schema"])
        }
        ["dependencies", "[]"] => Some(&["name", "versionRequirement", "optional"]),
        ["rollback"] => Some(&["strategy", "commands", "notes"]),
        ["versionPolicy"] => Some(&["keepVersions", "rollbackOnFailure"]),
        ["opsPermissions", "[]"] => Some(&[
            "permission",
            "scope",
            "risk",
            "reason",
            "rollbackRequired",
            "rollbackCommand",
        ]),
        ["resources", "[]"] => Some(&["uri", "name", "description", "mimeType"]),
        ["prompts", "[]"] => Some(&["name", "description", "arguments", "template"]),
        ["prompts", "[]", "arguments", "[]"] => {
            Some(&["name", "description", "required", "schema"])
        }
        ["permissions", "[]"] => Some(&[
            "type",
            "permission",
            "paths",
            "mode",
            "origins",
            "commands",
            "units",
            "actions",
            "managers",
            "packages",
            "users",
            "scopes",
        ]),
        _ => None,
    }
}

fn is_sensitive_unknown_manifest_field(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    [
        "permission",
        "secret",
        "token",
        "credential",
        "authorization",
        "privilege",
        "sudo",
        "sandbox",
        "security",
        "capability",
        "env",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

fn canonical_manifest_hash(value: &Value) -> String {
    let mut sanitized = value.clone();
    if let Some(object) = sanitized.as_object_mut() {
        object.remove("signature");
    }
    let mut encoded = String::new();
    write_canonical_json(&sanitized, &mut encoded);
    format!("fnv1a64:{:016x}", fnv1a64(encoded.as_bytes()))
}

fn write_canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => out.push_str(&value.to_string()),
        Value::String(value) => out.push_str(
            &serde_json::to_string(value).expect("JSON string serialization should succeed"),
        ),
        Value::Array(values) => {
            out.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical_json(value, out);
            }
            out.push(']');
        }
        Value::Object(values) => {
            out.push('{');
            for (index, (key, value)) in
                values.iter().collect::<BTreeMap<_, _>>().iter().enumerate()
            {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(key).expect("JSON key serialization should succeed"),
                );
                out.push(':');
                write_canonical_json(value, out);
            }
            out.push('}');
        }
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
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
    schema: ManifestSchemaEnvelope,
) -> Result<PluginManifest, PluginError> {
    let mut errors = Vec::new();

    validate_manifest_slug_field(
        "name",
        &raw.name,
        PLUGIN_MANIFEST_NAME_MAX_CHARS,
        &mut errors,
    );
    if let Some(id) = raw.id.as_deref() {
        validate_manifest_slug_field("id", id, PLUGIN_MANIFEST_ID_MAX_CHARS, &mut errors);
        if id.trim() != raw.name.trim() {
            errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                detail: format!(
                    "plugin manifest id `{}` must match name `{}` to avoid confused-deputy registration",
                    id.trim(),
                    raw.name.trim()
                ),
            });
        }
    }
    validate_manifest_version_field("version", &raw.version, &mut errors);
    validate_manifest_text_field(
        "description",
        &raw.description,
        PLUGIN_MANIFEST_DESCRIPTION_MAX_CHARS,
        &mut errors,
    );
    if let Some(signature) = raw.signature.as_deref() {
        validate_manifest_text_field(
            "signature",
            signature,
            PLUGIN_MANIFEST_SIGNATURE_MAX_CHARS,
            &mut errors,
        );
    }

    validate_collection_limit("permissions", raw.permissions.len(), &mut errors);
    validate_collection_limit("tools", raw.tools.len(), &mut errors);
    validate_collection_limit("commands", raw.commands.len(), &mut errors);
    validate_collection_limit("mcpServers", raw.mcp_servers.len(), &mut errors);
    validate_collection_limit("dependencies", raw.dependencies.len(), &mut errors);
    validate_collection_limit("opsPermissions", raw.ops_permissions.len(), &mut errors);
    validate_collection_limit("resources", raw.resources.len(), &mut errors);
    validate_collection_limit("prompts", raw.prompts.len(), &mut errors);

    if let Some(entrypoint) = raw.entrypoint.as_ref() {
        validate_entrypoint(root, entrypoint, &mut errors);
    }

    let (permissions, permission_declarations) =
        build_manifest_permissions(root, &raw.permissions, &mut errors);
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
    let actual_surfaces = actual_surfaces_from_manifest_parts(
        tools.len(),
        commands.len(),
        resources.len(),
        prompts.len(),
        &mcp_servers,
        raw.ops_permissions.len(),
    );
    let capabilities = normalize_manifest_capabilities(
        raw.capabilities,
        schema.explicit_capabilities,
        &actual_surfaces,
        &mut errors,
    );

    if !errors.is_empty() {
        return Err(PluginError::ManifestValidation(errors));
    }

    let manifest_metadata = PluginManifestMetadata {
        schema_version: schema.schema_version,
        legacy: schema.legacy,
        hash: schema.hash,
        signature: raw.signature.clone(),
        signature_verified: false,
        signature_warning: raw
            .signature
            .as_ref()
            .map(|_| "manifest signature is present but has not been verified".to_string()),
        declared_id: raw.id.clone(),
        entrypoint: raw.entrypoint.clone(),
        warnings: schema.warnings,
    };

    Ok(PluginManifest {
        schema_version: schema.schema_version,
        id: raw.id,
        name: raw.name,
        version: raw.version,
        description: raw.description,
        permissions,
        permission_declarations,
        entrypoint: raw.entrypoint,
        manifest_metadata,
        default_enabled: raw.default_enabled,
        hooks: raw.hooks,
        lifecycle: raw.lifecycle,
        execution_policy: raw.execution_policy,
        tools,
        commands,
        capabilities,
        mcp_servers,
        dependencies,
        rollback: raw.rollback,
        version_policy: raw.version_policy,
        ops_permissions: raw.ops_permissions,
        resources,
        prompts,
    })
}

fn validate_manifest_text_field(
    field: &'static str,
    value: &str,
    max_chars: usize,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        errors.push(PluginManifestValidationError::EmptyField { field });
        return;
    }
    if trimmed.chars().count() > max_chars || contains_control_character(trimmed) {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!(
                "plugin manifest {field} must be non-control text no longer than {max_chars} characters"
            ),
        });
    }
}

fn validate_manifest_slug_field(
    field: &'static str,
    value: &str,
    max_chars: usize,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    validate_manifest_text_field(field, value, max_chars, errors);
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    let is_reserved = matches!(
        trimmed,
        "." | ".." | "builtin" | "bundled" | "external" | "root" | "admin" | "system"
    );
    if is_reserved
        || !trimmed
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_'))
    {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!(
                "plugin manifest {field} `{trimmed}` must be an ASCII slug using lowercase letters, digits, '-' or '_' and must not be reserved"
            ),
        });
    }
}

fn validate_manifest_version_field(
    field: &'static str,
    value: &str,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    validate_manifest_text_field(field, value, PLUGIN_MANIFEST_VERSION_MAX_CHARS, errors);
    if value.trim().is_empty() {
        return;
    }
    if parse_semver(value).is_err() {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!(
                "plugin manifest {field} `{}` must be semver-compatible",
                value.trim()
            ),
        });
    }
}

fn validate_collection_limit(
    field: &'static str,
    count: usize,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    if count > PLUGIN_MANIFEST_MAX_DECLARATIONS {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!(
                "plugin manifest {field} has {count} entries, exceeding limit {PLUGIN_MANIFEST_MAX_DECLARATIONS}"
            ),
        });
    }
}

fn validate_entrypoint(
    root: &Path,
    entrypoint: &PluginEntrypoint,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    if entrypoint.command.trim().is_empty() {
        errors.push(PluginManifestValidationError::EmptyEntryField {
            kind: "entrypoint",
            field: "command",
            name: None,
        });
        return;
    }
    validate_command_entry(root, &entrypoint.command, "entrypoint", errors);
    validate_collection_limit("entrypoint.args", entrypoint.args.len(), errors);
    for arg in &entrypoint.args {
        if arg.chars().count() > PLUGIN_PERMISSION_VALUE_MAX_CHARS
            || contains_control_character(arg)
        {
            errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                detail: "plugin entrypoint args must be bounded and contain no control characters"
                    .to_string(),
            });
        }
    }
}

fn contains_control_character(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn path_has_parent_component(path: &Path) -> bool {
    path.components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
}

fn build_manifest_permissions(
    root: &Path,
    permissions: &[RawPluginPermissionDeclaration],
    errors: &mut Vec<PluginManifestValidationError>,
) -> (Vec<PluginPermission>, Vec<PluginPermissionDeclaration>) {
    let mut seen = BTreeSet::new();
    let mut validated = Vec::new();
    let mut declarations = Vec::new();

    for permission in permissions {
        let (declaration, duplicate_label) = match permission {
            RawPluginPermissionDeclaration::Legacy(permission) => {
                let permission = permission.trim();
                if permission.is_empty() {
                    errors.push(PluginManifestValidationError::EmptyEntryField {
                        kind: "permission",
                        field: "value",
                        name: None,
                    });
                    continue;
                }
                match PluginPermission::parse(permission) {
                    Some(parsed) => (
                        PluginPermissionDeclaration::Legacy { permission: parsed },
                        permission.to_string(),
                    ),
                    None => {
                        errors.push(PluginManifestValidationError::InvalidPermission {
                            permission: permission.to_string(),
                        });
                        continue;
                    }
                }
            }
            RawPluginPermissionDeclaration::Structured(declaration) => {
                let key = serde_json::to_string(declaration)
                    .unwrap_or_else(|_| format!("{declaration:?}"));
                (declaration.clone(), key)
            }
        };

        if !seen.insert(duplicate_label.clone()) {
            errors.push(PluginManifestValidationError::DuplicatePermission {
                permission: duplicate_label,
            });
            continue;
        }
        validate_permission_declaration(root, &declaration, errors);
        let manifest_permission = manifest_permission_for_declaration(&declaration);
        if !validated.contains(&manifest_permission) {
            validated.push(manifest_permission);
        }
        declarations.push(declaration);
    }

    validated.sort();
    (validated, declarations)
}

fn manifest_permission_for_tool(permission: PluginToolPermission) -> PluginPermission {
    match permission {
        PluginToolPermission::ReadOnly => PluginPermission::Read,
        PluginToolPermission::WorkspaceWrite => PluginPermission::Write,
        PluginToolPermission::DangerFullAccess => PluginPermission::Execute,
    }
}

fn manifest_permission_for_declaration(
    declaration: &PluginPermissionDeclaration,
) -> PluginPermission {
    match declaration {
        PluginPermissionDeclaration::Legacy { permission } => *permission,
        PluginPermissionDeclaration::Filesystem { mode, .. } => match mode {
            PluginFilesystemPermissionMode::Read => PluginPermission::Read,
            PluginFilesystemPermissionMode::Write | PluginFilesystemPermissionMode::ReadWrite => {
                PluginPermission::Write
            }
        },
        PluginPermissionDeclaration::Network { .. } => PluginPermission::Read,
        PluginPermissionDeclaration::Process { .. }
        | PluginPermissionDeclaration::Systemd { .. }
        | PluginPermissionDeclaration::Package { .. }
        | PluginPermissionDeclaration::User { .. }
        | PluginPermissionDeclaration::Firewall { .. } => PluginPermission::Execute,
    }
}

fn validate_permission_declaration(
    root: &Path,
    declaration: &PluginPermissionDeclaration,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    match declaration {
        PluginPermissionDeclaration::Legacy { .. } => {}
        PluginPermissionDeclaration::Filesystem { paths, .. } => {
            validate_permission_values("filesystem permission", "paths", paths, errors);
            for path in paths {
                validate_declared_filesystem_path(root, path, errors);
            }
        }
        PluginPermissionDeclaration::Network { origins } => {
            validate_permission_values("network permission", "origins", origins, errors);
            for origin in origins {
                validate_network_origin(origin, errors);
            }
        }
        PluginPermissionDeclaration::Process { commands } => {
            validate_permission_values("process permission", "commands", commands, errors);
            for command in commands {
                validate_process_permission_command(root, command, errors);
            }
        }
        PluginPermissionDeclaration::Systemd { units, actions } => {
            validate_permission_values("systemd permission", "units", units, errors);
            validate_permission_values("systemd permission", "actions", actions, errors);
        }
        PluginPermissionDeclaration::Package {
            managers,
            actions,
            packages,
        } => {
            validate_permission_values("package permission", "managers", managers, errors);
            validate_permission_values("package permission", "actions", actions, errors);
            validate_permission_values("package permission", "packages", packages, errors);
        }
        PluginPermissionDeclaration::User { users, actions } => {
            validate_permission_values("user permission", "users", users, errors);
            validate_permission_values("user permission", "actions", actions, errors);
        }
        PluginPermissionDeclaration::Firewall { scopes, actions } => {
            validate_permission_values("firewall permission", "scopes", scopes, errors);
            validate_permission_values("firewall permission", "actions", actions, errors);
        }
    }
}

fn validate_permission_values(
    kind: &'static str,
    field: &'static str,
    values: &[String],
    errors: &mut Vec<PluginManifestValidationError>,
) {
    if values.is_empty() || values.len() > PLUGIN_MANIFEST_MAX_DECLARATIONS {
        errors.push(PluginManifestValidationError::EmptyEntryField {
            kind,
            field,
            name: None,
        });
        return;
    }
    let mut seen = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty()
            || trimmed == "*"
            || trimmed.chars().count() > PLUGIN_PERMISSION_VALUE_MAX_CHARS
            || contains_control_character(trimmed)
            || !seen.insert(trimmed.to_string())
        {
            errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                detail: format!(
                    "plugin {kind} {field} entry must be unique, non-empty, bounded, and must not use wildcard bypasses"
                ),
            });
        }
    }
}

fn validate_declared_filesystem_path(
    root: &Path,
    value: &str,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    if Path::new(trimmed).is_absolute()
        || trimmed.contains('*')
        || path_has_parent_component(Path::new(trimmed))
    {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!(
                "plugin filesystem permission path `{trimmed}` must be plugin-relative and contained within the plugin root"
            ),
        });
        return;
    }
    let path = root.join(trimmed);
    if let Ok(metadata) = fs::symlink_metadata(&path) {
        if metadata.file_type().is_symlink() || !(metadata.is_file() || metadata.is_dir()) {
            errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                detail: format!(
                    "plugin filesystem permission path `{trimmed}` must not reference a symlink or special file"
                ),
            });
        }
    }
}

fn validate_network_origin(origin: &str, errors: &mut Vec<PluginManifestValidationError>) {
    let trimmed = origin.trim();
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!("plugin network origin `{trimmed}` must use http:// or https://"),
        });
        return;
    };
    if !matches!(scheme, "http" | "https")
        || rest.is_empty()
        || rest.contains('@')
        || rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('*')
        || contains_control_character(trimmed)
    {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!(
                "plugin network origin `{}` must be an origin without userinfo, path, query, fragment, or wildcard",
                sanitize_plugin_error(trimmed)
            ),
        });
    }
}

fn validate_process_permission_command(
    root: &Path,
    command: &str,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    let trimmed = command.trim();
    if trimmed.starts_with("./") {
        validate_command_entry(root, trimmed, "process permission", errors);
        return;
    }
    if trimmed.contains(std::path::MAIN_SEPARATOR)
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.split_whitespace().count() != 1
        || trimmed.contains('*')
        || contains_control_character(trimmed)
        || matches!(
            trimmed,
            "sh" | "bash" | "zsh" | "fish" | "cmd" | "powershell"
        )
    {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!(
                "plugin process permission command `{trimmed}` must be a single bounded command token or plugin-relative path, not a shell or wildcard"
            ),
        });
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

fn actual_surfaces_for_plugin(plugin: &PluginDefinition) -> PluginActualSurfaces {
    actual_surfaces_from_manifest_parts(
        plugin.tools().len(),
        plugin.commands().len(),
        plugin.resources().len(),
        plugin.prompts().len(),
        plugin.mcp_servers(),
        plugin.ops_permissions().len(),
    )
}

fn actual_surfaces_from_manifest_parts(
    tools: usize,
    commands: usize,
    resources: usize,
    prompts: usize,
    mcp_servers: &BTreeMap<String, PluginMcpServerManifest>,
    ops_permissions: usize,
) -> PluginActualSurfaces {
    PluginActualSurfaces {
        tools,
        commands,
        resources,
        prompts,
        mcp_servers: mcp_servers.len(),
        mcp_tools: mcp_servers
            .values()
            .map(|server| server.capabilities.tools.len())
            .sum(),
        mcp_resources: mcp_servers
            .values()
            .map(|server| server.capabilities.resources.len())
            .sum(),
        mcp_prompts: mcp_servers
            .values()
            .map(|server| server.capabilities.prompts.len())
            .sum(),
        ops_permissions,
    }
}

fn degraded_reason_for_plugin(plugin: &PluginDefinition) -> Option<String> {
    let warnings = &plugin.metadata().manifest.warnings;
    (!warnings.is_empty()).then(|| warnings.join("; "))
}

fn append_manifest_warnings(plugin: &mut PluginDefinition, warnings: &[String]) {
    if warnings.is_empty() {
        return;
    }
    let metadata = plugin.metadata_mut();
    for warning in warnings {
        push_manifest_warning(
            &mut metadata.manifest.warnings,
            sanitize_plugin_error(warning),
        );
    }
}

fn permission_declaration_statuses_for_plugin(
    plugin: &PluginDefinition,
) -> Vec<PluginPermissionDeclarationStatus> {
    plugin
        .permission_declarations()
        .iter()
        .enumerate()
        .map(|(index, declaration)| {
            let enforced = matches!(declaration, PluginPermissionDeclaration::Legacy { .. });
            PluginPermissionDeclarationStatus {
                index,
                permission_type: permission_declaration_type(declaration).to_string(),
                enforced,
                declaration_only: !enforced,
                enforced_permission: enforced
                    .then(|| manifest_permission_for_declaration(declaration)),
            }
        })
        .collect()
}

fn permission_declaration_type(declaration: &PluginPermissionDeclaration) -> &'static str {
    match declaration {
        PluginPermissionDeclaration::Legacy { .. } => "legacy",
        PluginPermissionDeclaration::Filesystem { .. } => "filesystem",
        PluginPermissionDeclaration::Network { .. } => "network",
        PluginPermissionDeclaration::Process { .. } => "process",
        PluginPermissionDeclaration::Systemd { .. } => "systemd",
        PluginPermissionDeclaration::Package { .. } => "package",
        PluginPermissionDeclaration::User { .. } => "user",
        PluginPermissionDeclaration::Firewall { .. } => "firewall",
    }
}

fn validate_registered_capability_gate(plugin: &RegisteredPlugin) -> Result<(), PluginError> {
    let actual = actual_surfaces_for_plugin(&plugin.definition);
    let capabilities = plugin.capabilities();
    for (capability, declared, has_surface) in [
        (
            "tools",
            capabilities.tools,
            actual.tools > 0 || actual.mcp_tools > 0 || actual.ops_permissions > 0,
        ),
        (
            "resources",
            capabilities.resources,
            actual.resources > 0 || actual.mcp_resources > 0,
        ),
        (
            "prompts",
            capabilities.prompts,
            actual.prompts > 0 || actual.mcp_prompts > 0,
        ),
    ] {
        if declared != has_surface {
            return Err(PluginError::InvalidManifest(format!(
                "plugin `{}` capabilities.{capability}={declared} does not match registered {capability} surfaces",
                plugin.metadata().id
            )));
        }
    }
    Ok(())
}

fn normalize_manifest_capabilities(
    raw_capabilities: Option<PluginCapabilities>,
    explicit_capabilities: bool,
    actual: &PluginActualSurfaces,
    errors: &mut Vec<PluginManifestValidationError>,
) -> PluginCapabilities {
    let inferred = PluginCapabilities {
        tools: actual.tools > 0 || actual.mcp_tools > 0 || actual.ops_permissions > 0,
        resources: actual.resources > 0 || actual.mcp_resources > 0,
        prompts: actual.prompts > 0 || actual.mcp_prompts > 0,
        workflows: false,
        hot_reload: false,
    };

    let Some(mut capabilities) = raw_capabilities else {
        return inferred;
    };

    if explicit_capabilities {
        validate_capability_matches_surface("tools", capabilities.tools, inferred.tools, errors);
        validate_capability_matches_surface(
            "resources",
            capabilities.resources,
            inferred.resources,
            errors,
        );
        validate_capability_matches_surface(
            "prompts",
            capabilities.prompts,
            inferred.prompts,
            errors,
        );
    }

    capabilities.tools = inferred.tools;
    capabilities.resources = inferred.resources;
    capabilities.prompts = inferred.prompts;
    capabilities
}

fn validate_capability_matches_surface(
    capability: &'static str,
    declared: bool,
    actual: bool,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    if declared != actual {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!(
                "plugin capabilities.{capability}={declared} does not match declared {capability} surfaces"
            ),
        });
    }
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
        let version_requirement = dependency.version_requirement.map(|requirement| {
            let trimmed = requirement.trim().to_string();
            if trimmed.is_empty() {
                errors.push(PluginManifestValidationError::EmptyEntryField {
                    kind: "dependency",
                    field: "versionRequirement",
                    name: Some(name.clone()),
                });
            } else if VersionReq::parse(&trimmed).is_err() {
                errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                    detail: format!(
                        "plugin dependency `{name}` versionRequirement `{}` must be a valid semver requirement",
                        sanitize_plugin_error(&trimmed)
                    ),
                });
            }
            trimmed
        });
        validated.push(PluginDependency {
            name,
            version_requirement,
            ..dependency
        });
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
        if permission.scope.contains('*')
            || permission.scope.chars().count() > PLUGIN_PERMISSION_VALUE_MAX_CHARS
            || contains_control_character(&permission.scope)
            || !matches!(
                permission.scope.split('.').next().unwrap_or_default(),
                "ops" | "systemd" | "service" | "package" | "user" | "firewall"
            )
        {
            errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                detail: format!(
                    "plugin ops permission scope `{}` must be bounded, structured, and must not use wildcards",
                    permission.scope
                ),
            });
        }
        if permission.reason.trim().is_empty() {
            errors.push(PluginManifestValidationError::EmptyEntryField {
                kind: "ops permission",
                field: "reason",
                name: Some(permission.scope.clone()),
            });
        }
        if permission.reason.chars().count() > PLUGIN_MANIFEST_DESCRIPTION_MAX_CHARS
            || contains_control_character(&permission.reason)
        {
            errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                detail: format!(
                    "plugin ops permission `{}` reason must be bounded and contain no control characters",
                    permission.scope
                ),
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
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!(
                "plugin {kind} command `{entry}` must be a plugin-contained file path, not a bare command"
            ),
        });
        return;
    }

    validate_contained_file_path(root, entry, kind, errors);
}

fn validate_contained_file_path(
    root: &Path,
    entry: &str,
    kind: &'static str,
    errors: &mut Vec<PluginManifestValidationError>,
) {
    if contains_control_character(entry) || path_has_parent_component(Path::new(entry)) {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!(
                "plugin {kind} path `{entry}` must not contain control characters or parent-directory traversal"
            ),
        });
        return;
    }
    let path = if Path::new(entry).is_absolute() {
        PathBuf::from(entry)
    } else {
        root.join(entry)
    };
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            errors.push(PluginManifestValidationError::MissingPath { kind, path });
            return;
        }
        Err(error) => {
            errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                detail: format!(
                    "plugin {kind} path `{}` cannot be inspected: {error}",
                    path.display()
                ),
            });
            return;
        }
    };
    if metadata.file_type().is_symlink() {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: format!(
                "plugin {kind} path `{}` must not be a symlink",
                path.display()
            ),
        });
        return;
    }
    if !metadata.is_file() {
        if metadata.is_dir() {
            errors.push(PluginManifestValidationError::PathIsDirectory { kind, path });
        } else {
            errors.push(PluginManifestValidationError::UnsupportedManifestContract {
                detail: format!(
                    "plugin {kind} path `{}` must be a regular file",
                    path.display()
                ),
            });
        }
        return;
    }
    if let Err(error) = validate_canonical_containment(root, &path, kind) {
        errors.push(PluginManifestValidationError::UnsupportedManifestContract {
            detail: error.to_string(),
        });
    }
}

fn validate_canonical_containment(root: &Path, path: &Path, kind: &str) -> Result<(), PluginError> {
    let canonical_root = root.canonicalize()?;
    let canonical_path = path.canonicalize()?;
    if canonical_path.starts_with(&canonical_root) {
        Ok(())
    } else {
        Err(PluginError::InvalidManifest(format!(
            "{kind} path `{}` resolves outside plugin root `{}`",
            path.display(),
            canonical_root.display()
        )))
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

fn validate_command_manifest_paths(
    root: Option<&Path>,
    commands: &[PluginCommandManifest],
) -> Result<(), PluginError> {
    let Some(root) = root else {
        return Ok(());
    };
    for command in commands {
        validate_command_path(root, &command.command, "command")?;
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
        return Err(PluginError::InvalidManifest(format!(
            "{kind} command `{entry}` must be a plugin-contained file path, not a bare command"
        )));
    }
    let path = if Path::new(entry).is_absolute() {
        PathBuf::from(entry)
    } else {
        root.join(entry)
    };
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(PluginError::InvalidManifest(format!(
                "{kind} path `{}` does not exist",
                path.display()
            )));
        }
        Err(error) => return Err(PluginError::Io(error)),
    };
    if metadata.file_type().is_symlink() {
        return Err(PluginError::InvalidManifest(format!(
            "{kind} path `{}` must not be a symlink",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(PluginError::InvalidManifest(format!(
            "{kind} path `{}` must point to a file",
            path.display()
        )));
    }
    validate_canonical_containment(root, &path, kind)?;
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
    deadline: Option<Instant>,
) -> Result<(), PluginError> {
    if lifecycle.is_empty() || commands.is_empty() {
        return Ok(());
    }

    for command in commands {
        let timeout = lifecycle_command_timeout(deadline, &metadata.id, phase)?;
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
            timeout,
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
                "plugin `{}` {} failed for `{}`{}: {}",
                metadata.id,
                phase,
                command,
                truncated_suffix(output.stderr_truncated),
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

fn lifecycle_command_timeout(
    deadline: Option<Instant>,
    plugin_id: &str,
    phase: &str,
) -> Result<Duration, PluginError> {
    let lifecycle_timeout = Duration::from_millis(PLUGIN_LIFECYCLE_TIMEOUT_MS);
    let Some(deadline) = deadline else {
        return Ok(lifecycle_timeout);
    };
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| {
            PluginError::CommandFailed(format!(
            "plugin hot reload exceeded {} ms deadline before {phase} lifecycle for `{plugin_id}`",
            PLUGIN_HOT_RELOAD_DEADLINE_MS
        ))
        })?;
    if remaining.is_zero() {
        return Err(PluginError::CommandFailed(format!(
            "plugin hot reload exceeded {} ms deadline before {phase} lifecycle for `{plugin_id}`",
            PLUGIN_HOT_RELOAD_DEADLINE_MS
        )));
    }
    Ok(remaining.min(lifecycle_timeout))
}

fn resolve_local_source(source: &str) -> Result<PathBuf, PluginError> {
    if contains_control_character(source) {
        return Err(PluginError::NotFound(
            "plugin source contains forbidden control characters".to_string(),
        ));
    }
    let path = PathBuf::from(source);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PluginError::NotFound(format!(
                "plugin source `{}` was not found",
                sanitize_plugin_error(source)
            ))
        } else {
            PluginError::Io(error)
        }
    })?;
    validate_plugin_entry_metadata(&path, &metadata)?;
    if !metadata.is_dir() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin source `{}` must be a directory",
            sanitize_plugin_error(source)
        )));
    }
    Ok(path.canonicalize()?)
}

fn parse_install_source(source: &str) -> Result<PluginInstallSource, PluginError> {
    if source.starts_with("http://")
        || source.starts_with("https://")
        || source.starts_with("ssh://")
        || source.starts_with("git@")
        || Path::new(source)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("git"))
    {
        let sanitized_url = validate_and_sanitize_git_install_url(source)?;
        Ok(PluginInstallSource::GitUrl { url: sanitized_url })
    } else {
        Ok(PluginInstallSource::LocalPath {
            path: resolve_local_source(source)?,
        })
    }
}

fn validate_and_sanitize_git_install_url(source: &str) -> Result<String, PluginError> {
    let trimmed = source.trim();
    if trimmed.is_empty() || contains_control_character(trimmed) {
        return Err(PluginError::InvalidManifest(
            "plugin Git install URL must be non-empty and contain no control characters"
                .to_string(),
        ));
    }
    let lowered = trimmed.to_ascii_lowercase();
    if contains_credential_marker(trimmed) {
        return Err(PluginError::InvalidManifest(
            "plugin Git install URL must not embed credentials or tokens".to_string(),
        ));
    }
    if let Some((scheme, after_scheme)) = trimmed.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        let authority_end = after_scheme
            .find(|ch| matches!(ch, '/' | '?' | '#'))
            .unwrap_or(after_scheme.len());
        let authority = &after_scheme[..authority_end];
        let suffix = &after_scheme[authority_end..];
        if suffix.contains('?') || suffix.contains('#') {
            return Err(PluginError::InvalidManifest(format!(
                "plugin Git install URL `{}` must not contain query or fragment; use git credential helper for credentials",
                sanitize_plugin_error(trimmed)
            )));
        }
        if matches!(scheme.as_str(), "http" | "https") && authority.contains('@') {
            return Err(PluginError::InvalidManifest(format!(
                "plugin Git install URL `{}` must not contain HTTP(S) userinfo; use git credential helper for credentials",
                sanitize_plugin_error(trimmed)
            )));
        }
        if scheme == "ssh" {
            if let Some((userinfo, _host)) = authority.rsplit_once('@') {
                if !valid_git_url_user(userinfo) {
                    return Err(PluginError::InvalidManifest(format!(
                        "plugin Git install URL `{}` must not contain an SSH password; use git credential helper or SSH agent credentials",
                        sanitize_plugin_error(trimmed)
                    )));
                }
            }
        }
    } else if let Some(scp) = parse_scp_git_url(trimmed) {
        if trimmed.contains('?') || trimmed.contains('#') {
            return Err(PluginError::InvalidManifest(format!(
                "plugin Git install URL `{}` must not contain query or fragment; use git credential helper for credentials",
                sanitize_plugin_error(trimmed)
            )));
        }
        if let Some(user) = scp.user {
            if !valid_git_url_user(user) {
                return Err(PluginError::InvalidManifest(format!(
                    "plugin Git install URL `{}` must not contain an scp-style password or credential marker; use git credential helper or SSH agent credentials",
                    sanitize_plugin_error(trimmed)
                )));
            }
        }
        if scp.host.is_empty()
            || contains_control_character(scp.host)
            || scp.host.contains(':')
            || contains_credential_marker(scp.host)
        {
            return Err(PluginError::InvalidManifest(format!(
                "plugin Git install URL `{}` has an invalid scp-style host",
                sanitize_plugin_error(trimmed)
            )));
        }
    } else if (trimmed.starts_with("git@") || lowered.ends_with(".git"))
        && (trimmed.contains('?') || trimmed.contains('#'))
    {
        return Err(PluginError::InvalidManifest(format!(
            "plugin Git install URL `{}` must not contain query or fragment; use git credential helper for credentials",
            sanitize_plugin_error(trimmed)
        )));
    }
    sanitize_git_install_url_for_storage(trimmed)
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
                    "git clone failed for `{}`: {}",
                    sanitize_plugin_error(url),
                    sanitize_plugin_error(String::from_utf8_lossy(&output.stderr).trim())
                )));
            }
            let git_metadata_path = destination.join(".git");
            match fs::symlink_metadata(&git_metadata_path) {
                Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(&git_metadata_path)?,
                Ok(_) => fs::remove_file(&git_metadata_path)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(PluginError::Io(error)),
            }
            Ok(destination)
        }
    }
}

#[derive(Debug, Clone)]
struct ScanBudget {
    started: Instant,
    files: usize,
    dirs: usize,
    total_bytes: u64,
}

impl ScanBudget {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            files: 0,
            dirs: 0,
            total_bytes: 0,
        }
    }

    fn elapsed_ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    // Cooperative deadline: checked between filesystem calls; it does not
    // preempt a blocking OS syscall already in progress.
    fn check_cooperative_deadline(&self, path: &Path) -> Result<(), PluginError> {
        if self.elapsed_ms() > PLUGIN_SCAN_MAX_DURATION_MS {
            return Err(PluginError::InvalidManifest(format!(
                "plugin scan cooperative deadline exceeded {PLUGIN_SCAN_MAX_DURATION_MS} ms while scanning `{}`",
                path.display()
            )));
        }
        Ok(())
    }

    fn count_dir(&mut self, path: &Path, depth: usize) -> Result<(), PluginError> {
        self.check_cooperative_deadline(path)?;
        if depth > PLUGIN_SCAN_MAX_DEPTH {
            return Err(PluginError::InvalidManifest(format!(
                "plugin scan budget exceeded depth limit {PLUGIN_SCAN_MAX_DEPTH} at `{}`",
                path.display()
            )));
        }
        if self.dirs >= PLUGIN_SCAN_MAX_ENTRIES {
            return Err(PluginError::InvalidManifest(format!(
                "plugin scan budget exceeded {PLUGIN_SCAN_MAX_ENTRIES} directories at `{}`",
                path.display()
            )));
        }
        self.dirs += 1;
        Ok(())
    }

    fn count_file(&mut self, path: &Path, len: u64) -> Result<(), PluginError> {
        self.check_cooperative_deadline(path)?;
        if self.files >= PLUGIN_SCAN_MAX_ENTRIES {
            return Err(PluginError::InvalidManifest(format!(
                "plugin scan budget exceeded {PLUGIN_SCAN_MAX_ENTRIES} files at `{}`",
                path.display()
            )));
        }
        self.files += 1;
        self.total_bytes = self.total_bytes.saturating_add(len);
        if self.total_bytes > PLUGIN_SCAN_MAX_TOTAL_BYTES {
            return Err(PluginError::InvalidManifest(format!(
                "plugin scan budget exceeded {PLUGIN_SCAN_MAX_TOTAL_BYTES} total bytes at `{}`",
                path.display()
            )));
        }
        Ok(())
    }

    fn count_metadata(
        &mut self,
        path: &Path,
        metadata: &fs::Metadata,
        depth: usize,
    ) -> Result<(), PluginError> {
        if metadata.is_dir() {
            self.count_dir(path, depth)
        } else if metadata.is_file() {
            self.count_file(path, metadata.len())
        } else {
            Err(PluginError::InvalidManifest(format!(
                "plugin tree contains forbidden special file `{}`",
                path.display()
            )))
        }
    }
}

#[derive(Debug)]
struct ScannedPluginCandidate {
    plugin: PluginDefinition,
    root: PathBuf,
    source: String,
    priority: u8,
}

fn default_plugin_discovery_roots(project_root: Option<&Path>) -> Vec<PluginScanRoot> {
    let mut roots = Vec::new();

    #[cfg(unix)]
    {
        for path in [
            "/usr/share/kilin/claw/plugins",
            "/usr/share/claw/plugins",
            "/etc/kilin/claw/plugins",
            "/etc/claw/plugins",
        ] {
            roots.push(PluginScanRoot::new(path, PluginScanRootSource::System));
        }
    }

    if let Some(config_home) =
        env_path("XDG_CONFIG_HOME").or_else(|| home_dir().map(|home| home.join(".config")))
    {
        roots.push(PluginScanRoot::new(
            config_home.join("claw").join("plugins"),
            PluginScanRootSource::UserConfig,
        ));
    }
    if let Some(data_home) = env_path("XDG_DATA_HOME")
        .or_else(|| home_dir().map(|home| home.join(".local").join("share")))
    {
        roots.push(PluginScanRoot::new(
            data_home.join("claw").join("plugins"),
            PluginScanRootSource::UserData,
        ));
    }
    if let Some(project_root) = project_root {
        roots.push(PluginScanRoot::new(
            project_root.join(".claw").join("plugins"),
            PluginScanRootSource::Project,
        ));
    }

    stable_dedup_scan_roots(&mut roots);
    roots
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).and_then(|value| {
        if value.is_empty() {
            None
        } else {
            Some(PathBuf::from(value))
        }
    })
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        env_path("USERPROFILE").or_else(|| {
            match (std::env::var_os("HOMEDRIVE"), std::env::var_os("HOMEPATH")) {
                (Some(drive), Some(path)) if !drive.is_empty() && !path.is_empty() => {
                    let mut combined = PathBuf::from(drive);
                    combined.push(path);
                    Some(combined)
                }
                _ => None,
            }
        })
    }
    #[cfg(not(windows))]
    {
        env_path("HOME")
    }
}

fn stable_dedup_scan_roots(roots: &mut Vec<PluginScanRoot>) {
    roots.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.path.cmp(&right.path))
    });
    let mut seen = BTreeSet::new();
    roots.retain(|root| seen.insert(root.path.clone()));
}

fn discovered_plugin_source(scan_root: &PluginScanRoot, plugin_root: &Path) -> String {
    format!(
        "discovered:{}:{}",
        scan_root.source,
        sanitize_plugin_error(&plugin_root.display().to_string())
    )
}

fn canonical_seen_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn discover_plugin_dirs_bounded(
    scan_root: &PluginScanRoot,
) -> (Vec<PathBuf>, PluginScanRootReport) {
    let started = Instant::now();
    let mut report = PluginScanRootReport {
        path: sanitize_plugin_error(&scan_root.path.display().to_string()),
        source: scan_root.source.to_string(),
        priority: scan_root.priority,
        ..PluginScanRootReport::default()
    };

    let metadata = match fs::symlink_metadata(&scan_root.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            record_scan_root_warning(
                &mut report,
                &format!(
                    "plugin discovery root `{}` does not exist",
                    scan_root.path.display()
                ),
            );
            report.duration_ms = started.elapsed().as_millis();
            return (Vec::new(), report);
        }
        Err(error) => {
            report.failure_count += 1;
            record_scan_root_warning(
                &mut report,
                &format!(
                    "plugin discovery root `{}` could not be read: {error}",
                    scan_root.path.display()
                ),
            );
            report.duration_ms = started.elapsed().as_millis();
            return (Vec::new(), report);
        }
    };
    if let Err(error) = validate_discovery_entry_metadata(&scan_root.path, &metadata) {
        report.failure_count += 1;
        record_scan_root_warning(&mut report, &error.to_string());
        report.duration_ms = started.elapsed().as_millis();
        return (Vec::new(), report);
    }
    let mut budget = ScanBudget::new();
    if let Err(error) = budget.count_dir(&scan_root.path, 0) {
        report.failure_count += 1;
        report.truncated = true;
        report.omitted_count += 1;
        record_scan_root_warning(&mut report, &error.to_string());
        report.duration_ms = started.elapsed().as_millis();
        return (Vec::new(), report);
    }
    if !metadata.is_dir() {
        report.failure_count += 1;
        record_scan_root_warning(
            &mut report,
            &format!(
                "plugin discovery root `{}` must be a directory",
                scan_root.path.display()
            ),
        );
        report.duration_ms = started.elapsed().as_millis();
        return (Vec::new(), report);
    }

    let canonical_root = match scan_root.path.canonicalize() {
        Ok(path) => path,
        Err(error) => {
            report.failure_count += 1;
            record_scan_root_warning(
                &mut report,
                &format!(
                    "plugin discovery root `{}` could not be canonicalized: {error}",
                    scan_root.path.display()
                ),
            );
            report.duration_ms = started.elapsed().as_millis();
            return (Vec::new(), report);
        }
    };
    if let Err(error) = validate_discovery_ancestors(&canonical_root) {
        report.failure_count += 1;
        record_scan_root_warning(&mut report, &error.to_string());
        report.duration_ms = started.elapsed().as_millis();
        return (Vec::new(), report);
    }

    let mut found = Vec::new();
    let mut queue = VecDeque::from([(scan_root.path.clone(), 0usize)]);
    let mut fingerprints = BTreeSet::new();
    while let Some((directory, depth)) = queue.pop_front() {
        if let Err(error) = budget.check_cooperative_deadline(&directory) {
            report.omitted_count += queue.len() + 1;
            report.truncated = true;
            record_scan_root_warning(&mut report, &error.to_string());
            break;
        }

        let canonical_directory = match directory.canonicalize() {
            Ok(path) => path,
            Err(error) => {
                report.failure_count += 1;
                record_scan_root_warning(
                    &mut report,
                    &format!(
                        "plugin discovery path `{}` could not be canonicalized: {error}",
                        directory.display()
                    ),
                );
                continue;
            }
        };
        if !canonical_directory.starts_with(&canonical_root) {
            report.failure_count += 1;
            record_scan_root_warning(
                &mut report,
                &format!(
                    "plugin discovery path `{}` escaped root `{}`",
                    directory.display(),
                    scan_root.path.display()
                ),
            );
            continue;
        }

        if let Ok(manifest_path) = plugin_manifest_path(&directory) {
            report.manifest_count += 1;
            match fs::symlink_metadata(&manifest_path) {
                Ok(manifest_metadata)
                    if manifest_metadata.len() <= PLUGIN_MANIFEST_MAX_BYTES
                        && validate_discovery_entry_metadata(
                            &manifest_path,
                            &manifest_metadata,
                        )
                        .is_ok() =>
                {
                    if let Err(error) = budget.count_file(&manifest_path, manifest_metadata.len()) {
                        report.omitted_count += 1;
                        report.truncated = true;
                        record_scan_root_warning(&mut report, &error.to_string());
                        continue;
                    }
                    if !fingerprints.insert(plugin_manifest_fingerprint(
                        &manifest_path,
                        &manifest_metadata,
                    )) {
                        report.omitted_count += 1;
                        record_scan_root_warning(
                            &mut report,
                            &format!(
                                "plugin manifest `{}` was already seen in this scan",
                                manifest_path.display()
                            ),
                        );
                        continue;
                    }
                    found.push(directory);
                    report.plugin_count += 1;
                }
                Ok(manifest_metadata) if manifest_metadata.len() > PLUGIN_MANIFEST_MAX_BYTES => {
                    report.failure_count += 1;
                    record_scan_root_warning(
                        &mut report,
                        &format!(
                            "plugin manifest `{}` exceeds {PLUGIN_MANIFEST_MAX_BYTES} byte limit",
                            manifest_path.display()
                        ),
                    );
                }
                Ok(manifest_metadata) => {
                    report.failure_count += 1;
                    if let Err(error) =
                        validate_discovery_entry_metadata(&manifest_path, &manifest_metadata)
                    {
                        record_scan_root_warning(&mut report, &error.to_string());
                    }
                }
                Err(error) => {
                    report.failure_count += 1;
                    record_scan_root_warning(
                        &mut report,
                        &format!(
                            "plugin manifest `{}` could not be inspected: {error}",
                            manifest_path.display()
                        ),
                    );
                }
            }
            continue;
        }

        if depth >= PLUGIN_SCAN_MAX_DEPTH {
            report.omitted_count += 1;
            report.truncated = true;
            record_scan_root_warning(
                &mut report,
                &format!(
                    "plugin discovery path `{}` exceeded depth limit {PLUGIN_SCAN_MAX_DEPTH}",
                    directory.display()
                ),
            );
            continue;
        }

        let mut children = match fs::read_dir(&directory) {
            Ok(entries) => {
                let mut children = Vec::new();
                for entry in entries {
                    if let Err(error) = budget.check_cooperative_deadline(&directory) {
                        report.omitted_count += 1;
                        report.truncated = true;
                        record_scan_root_warning(&mut report, &error.to_string());
                        break;
                    }
                    if children.len() > PLUGIN_SCAN_MAX_ENTRIES {
                        report.omitted_count += 1;
                        report.truncated = true;
                        record_scan_root_warning(
                            &mut report,
                            &format!(
                                "plugin discovery directory `{}` exceeded bounded collection limit {PLUGIN_SCAN_MAX_ENTRIES}",
                                directory.display()
                            ),
                        );
                        break;
                    }
                    match entry {
                        Ok(entry) => children.push(entry.path()),
                        Err(error) => {
                            report.failure_count += 1;
                            record_scan_root_warning(
                                &mut report,
                                &format!(
                                    "plugin discovery directory `{}` contained unreadable entry: {error}",
                                    directory.display()
                                ),
                            );
                        }
                    }
                }
                children
            }
            Err(error) => {
                report.failure_count += 1;
                record_scan_root_warning(
                    &mut report,
                    &format!(
                        "plugin discovery directory `{}` could not be read: {error}",
                        directory.display()
                    ),
                );
                continue;
            }
        };
        children.sort();
        for child in children {
            let child_metadata = match fs::symlink_metadata(&child) {
                Ok(metadata) => metadata,
                Err(error) => {
                    report.failure_count += 1;
                    record_scan_root_warning(
                        &mut report,
                        &format!(
                            "plugin discovery path `{}` could not be inspected: {error}",
                            child.display()
                        ),
                    );
                    continue;
                }
            };
            if let Err(error) = validate_discovery_entry_metadata(&child, &child_metadata) {
                report.failure_count += 1;
                record_scan_root_warning(&mut report, &error.to_string());
                continue;
            }
            if scan_root.source == PluginScanRootSource::Installed
                && child_metadata.is_dir()
                && is_installed_scan_manager_dir(&child)
            {
                report.skipped_count += 1;
                continue;
            }
            if child_metadata.is_dir() {
                if let Err(error) = budget.count_dir(&child, depth + 1) {
                    report.omitted_count += 1;
                    report.truncated = true;
                    record_scan_root_warning(&mut report, &error.to_string());
                    continue;
                }
                queue.push_back((child, depth + 1));
            } else if child_metadata.is_file() {
                if let Err(error) = budget.count_file(&child, child_metadata.len()) {
                    report.omitted_count += 1;
                    report.truncated = true;
                    record_scan_root_warning(&mut report, &error.to_string());
                    continue;
                }
                report.skipped_count += 1;
            }
        }
    }

    found.sort();
    report.duration_ms = started.elapsed().as_millis();
    (found, report)
}

fn is_installed_scan_manager_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, ".tmp" | ".versions"))
}

fn validate_discovery_entry_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), PluginError> {
    validate_plugin_entry_metadata(path, metadata)?;
    validate_posix_discovery_metadata(path, metadata, false)?;
    Ok(())
}

fn validate_discovery_ancestors(canonical_root: &Path) -> Result<(), PluginError> {
    let _ = canonical_root;
    #[cfg(target_os = "linux")]
    {
        for ancestor in canonical_root.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)?;
            validate_posix_discovery_metadata(ancestor, &metadata, true)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_posix_discovery_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    ancestor: bool,
) -> Result<(), PluginError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let uid = metadata.uid();
    let current_uid = rustix::process::geteuid().as_raw();
    if uid != current_uid && uid != 0 {
        return Err(PluginError::InvalidManifest(format!(
            "plugin discovery path `{}` is owned by uid {uid}, not current uid {current_uid} or root",
            path.display()
        )));
    }

    let mode = metadata.permissions().mode();
    let group_or_world_writable = mode & 0o022 != 0;
    let sticky_ancestor = ancestor && mode & 0o1000 != 0;
    if group_or_world_writable && !sticky_ancestor {
        return Err(PluginError::InvalidManifest(format!(
            "plugin discovery path `{}` is group/world-writable",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn validate_posix_discovery_metadata(
    _path: &Path,
    _metadata: &fs::Metadata,
    _ancestor: bool,
) -> Result<(), PluginError> {
    Ok(())
}

fn plugin_manifest_fingerprint(path: &Path, metadata: &fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        format!(
            "{}:{}:{}:{}:{}",
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec()
        )
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        format!(
            "{}:{}:{}",
            path.display(),
            metadata.file_size(),
            metadata.last_write_time()
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        format!("{}:{}", path.display(), metadata.len())
    }
}

fn push_scan_warning(warnings: &mut Vec<String>, warning: &str) -> bool {
    if warnings.len() >= PLUGIN_SCAN_MAX_WARNINGS {
        return false;
    }
    warnings.push(bound_plugin_surface(
        &sanitize_plugin_error(warning),
        PLUGIN_SCAN_WARNING_MAX_CHARS,
    ));
    true
}

fn record_scan_warning(report: &mut PluginScanReport, warning: &str) {
    if !push_scan_warning(&mut report.warnings, warning) {
        report.truncated = true;
        report.omitted_count += 1;
    }
}

fn add_scan_root_report(report: &mut PluginScanReport, root_report: PluginScanRootReport) {
    report.duration_ms += root_report.duration_ms;
    report.push_root(root_report);
}

fn record_scan_root_warning(report: &mut PluginScanRootReport, warning: &str) {
    if !push_scan_warning(&mut report.warnings, warning) {
        report.truncated = true;
        report.omitted_count += 1;
    }
}

fn bound_plugin_surface(value: &str, max_chars: usize) -> String {
    let mut out = value
        .chars()
        .filter(|ch| !matches!(ch, '\0'))
        .take(max_chars)
        .collect::<String>();
    if value.chars().count() > max_chars {
        out.push_str("...[truncated]");
    }
    out
}

fn lifecycle_child_permission(permissions: &[PluginPermission]) -> PluginToolPermission {
    if permissions.contains(&PluginPermission::Write) {
        PluginToolPermission::WorkspaceWrite
    } else {
        PluginToolPermission::ReadOnly
    }
}

fn validate_installed_record_identity(
    record: &InstalledPluginRecord,
    plugin: &PluginDefinition,
) -> Result<(), PluginError> {
    if plugin.metadata().id != record.id
        || plugin.metadata().name != record.name
        || plugin.metadata().version != record.version
    {
        return Err(PluginError::InvalidManifest(format!(
            "installed plugin record `{}` does not match manifest `{}` version `{}` at `{}`",
            record.id,
            plugin.metadata().id,
            plugin.metadata().version,
            record.install_path.display()
        )));
    }
    Ok(())
}

fn dependency_refers_to_plugin(dependency: &PluginDependency, plugin: &RegisteredPlugin) -> bool {
    dependency.name == plugin.metadata().id || dependency.name == plugin.metadata().name
}

fn format_dependency_conflict_reason(
    plugin: &RegisteredPlugin,
    dependency: &PluginDependency,
    dependency_plugin: &RegisteredPlugin,
    requirement: &str,
) -> String {
    format!(
        "plugin `{}` depends on `{}` version `{}` but single active runtime version is `{}`; available installed slots are `{}`; rollback `{}` to a compatible active version or update dependent constraints",
        plugin.metadata().id,
        dependency.name,
        requirement,
        dependency_plugin.metadata().version,
        dependency_plugin
            .available_versions
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        dependency_plugin.metadata().id
    )
}

fn resolve_dependency_plugin<'a>(
    plugins: &'a [RegisteredPlugin],
    dependency: &PluginDependency,
) -> Option<&'a RegisteredPlugin> {
    plugins
        .iter()
        .filter(|plugin| plugin.is_enabled())
        .find(|plugin| dependency_refers_to_plugin(dependency, plugin))
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
        if let Some(existing_id) = by_name.insert(plugin.metadata().name.clone(), id.clone()) {
            return Err(PluginError::InvalidManifest(format!(
                "plugin name `{}` is declared by both `{existing_id}` and `{id}`",
                plugin.metadata().name
            )));
        }
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
                        "{}",
                        format_dependency_conflict_reason(
                            plugin,
                            dependency,
                            dependency_plugin,
                            requirement
                        )
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

fn semver_requirement_matches(requirement: &str, version: &str) -> Result<bool, PluginError> {
    let requirement = requirement.trim();
    if requirement.is_empty() {
        return Err(PluginError::InvalidManifest(
            "invalid semver requirement: empty versionRequirement".to_string(),
        ));
    }
    if requirement == "*" {
        return Ok(true);
    }

    let version = parse_semver(version)?;
    let requirement = VersionReq::parse(requirement).map_err(|_| {
        PluginError::InvalidManifest(format!("invalid semver requirement `{requirement}`"))
    })?;
    Ok(requirement.matches(&version))
}

fn parse_semver(value: &str) -> Result<Version, PluginError> {
    if value.trim() != value
        || value.is_empty()
        || value.len() > PLUGIN_MANIFEST_VERSION_MAX_CHARS
        || contains_control_character(value)
        || value.contains(['/', '\\', ':'])
    {
        return Err(PluginError::InvalidManifest(format!(
            "invalid semver version `{}`",
            sanitize_plugin_error(value)
        )));
    }
    Version::parse(value).map_err(|_| {
        PluginError::InvalidManifest(format!(
            "invalid semver version `{}`",
            sanitize_plugin_error(value)
        ))
    })
}

fn plugin_id(name: &str, marketplace: &str) -> String {
    format!("{name}@{marketplace}")
}

fn plugin_package_id(name: &str, marketplace: &str) -> String {
    plugin_id(name, marketplace)
}

fn installed_archive_id(plugin_id: &str, version: &str) -> String {
    format!("{plugin_id}#{version}")
}

fn compare_semver_strings(left: &str, right: &str) -> std::cmp::Ordering {
    match (Version::parse(left), Version::parse(right)) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

#[must_use]
pub fn sanitize_plugin_error(value: &str) -> String {
    let mut redacted = redact_scp_credentials(redact_url_credentials_and_query(value));
    for marker in [
        "Authorization: Bearer ",
        "authorization: Bearer ",
        "Bearer ",
        "token=",
        "access_token=",
        "refresh_token=",
        "api_key=",
        "apikey=",
        "key=",
        "secret=",
        "password=",
    ] {
        redacted = redact_after_marker(&redacted, marker);
    }
    truncate_plugin_error(&redacted)
}

fn truncate_plugin_error(value: &str) -> String {
    let mut out = value
        .chars()
        .filter(|ch| !matches!(ch, '\0'))
        .take(PLUGIN_ERROR_SURFACE_MAX_CHARS)
        .collect::<String>();
    if value.chars().count() > PLUGIN_ERROR_SURFACE_MAX_CHARS {
        out.push_str("...[truncated]");
    }
    out
}

fn append_cleanup_warning(target: &mut Option<String>, warning: String) {
    let warning = truncate_plugin_error(&sanitize_plugin_error(&warning));
    match target {
        Some(existing) if !existing.is_empty() => {
            existing.push_str("; ");
            existing.push_str(&warning);
            *existing = truncate_plugin_error(existing);
        }
        _ => {
            *target = Some(warning);
        }
    }
}

fn redact_after_marker(value: &str, marker: &str) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(index) = find_ascii_case_insensitive(rest, marker) {
        let before = &rest[..index + marker.len()];
        out.push_str(before);
        out.push_str("[redacted]");
        let after_marker = &rest[index + marker.len()..];
        let secret_end = after_marker
            .find(|ch: char| {
                ch.is_whitespace() || matches!(ch, '"' | '\'' | '&' | ';' | ',' | '/' | '?' | '#')
            })
            .unwrap_or(after_marker.len());
        rest = &after_marker[secret_end..];
    }
    out.push_str(rest);
    out
}

fn find_ascii_case_insensitive(value: &str, marker: &str) -> Option<usize> {
    let marker = marker.as_bytes();
    if marker.is_empty() {
        return None;
    }
    value.as_bytes().windows(marker.len()).position(|window| {
        window
            .iter()
            .zip(marker)
            .all(|(left, right)| ascii_bytes_equal_ignore_case(*left, *right))
    })
}

fn ascii_bytes_equal_ignore_case(left: u8, right: u8) -> bool {
    left == right
        || (left.is_ascii_alphabetic()
            && right.is_ascii_alphabetic()
            && left.to_ascii_lowercase() == right.to_ascii_lowercase())
}

fn redact_scp_credentials(value: String) -> String {
    let mut out = String::new();
    let mut rest = value.as_str();
    while let Some(at_index) = rest.find('@') {
        let token_start = rest[..at_index]
            .rfind(|ch: char| {
                ch.is_whitespace() || matches!(ch, '"' | '\'' | '`' | '(' | '[' | '<')
            })
            .map_or(0, |index| index + 1);
        let userinfo = &rest[token_start..at_index];
        let after_at = &rest[at_index + 1..];
        let token_end = after_at
            .find(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '`' | ')' | ']' | '>'))
            .unwrap_or(after_at.len());
        let after_token = &after_at[..token_end];
        if userinfo.contains(':') && after_token.contains(':') {
            out.push_str(&rest[..token_start]);
            out.push_str("[redacted]@");
            out.push_str(after_token);
            rest = &after_at[token_end..];
        } else {
            out.push_str(&rest[..at_index + 1]);
            rest = after_at;
        }
    }
    out.push_str(rest);
    out
}

fn redact_url_credentials_and_query(value: &str) -> String {
    let mut out = String::new();
    let mut rest = value;
    while let Some(scheme_index) = rest.find("://") {
        let prefix_start = rest[..scheme_index]
            .rfind(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '(' | '[' | '<'))
            .map_or(0, |index| index + 1);
        out.push_str(&rest[..prefix_start]);
        let candidate = &rest[prefix_start..];
        let end = candidate
            .find(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | ')' | ']' | '>'))
            .unwrap_or(candidate.len());
        out.push_str(&redact_single_url_like(&candidate[..end]));
        rest = &candidate[end..];
    }
    out.push_str(rest);
    out
}

fn redact_single_url_like(value: &str) -> String {
    let Some((scheme, after_scheme)) = value.split_once("://") else {
        return value.to_string();
    };
    let mut authority_and_rest = after_scheme.to_string();
    let path_start = authority_and_rest
        .find(|ch| matches!(ch, '/' | '?' | '#'))
        .unwrap_or(authority_and_rest.len());
    let (authority, suffix) = authority_and_rest.split_at(path_start);
    let redacted_authority = authority.rsplit_once('@').map_or_else(
        || authority.to_string(),
        |(_, host)| format!("[redacted]@{host}"),
    );
    let mut redacted = format!("{scheme}://{redacted_authority}");
    if let Some(path) = suffix.split(['?', '#']).next() {
        redacted.push_str(path);
    }
    if suffix.contains('?') {
        redacted.push_str("?[redacted]");
    }
    if suffix.contains('#') {
        redacted.push_str("#[redacted]");
    }
    authority_and_rest.clear();
    redacted
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
        PluginInstallSource::GitUrl { url } => sanitize_plugin_error(url),
    }
}

fn installed_available_versions_by_id(
    registry: &InstalledPluginRegistry,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut versions = BTreeMap::<String, BTreeSet<String>>::new();
    for (plugin_id, record) in &registry.plugins {
        versions
            .entry(plugin_id.clone())
            .or_default()
            .insert(record.version.clone());
    }
    for (plugin_id, records) in &registry.versions {
        let entry = versions.entry(plugin_id.clone()).or_default();
        for record in records {
            entry.insert(record.version.clone());
        }
    }
    versions
}

fn stale_installed_registry_ids(registry: &InstalledPluginRegistry) -> Vec<String> {
    registry
        .plugins
        .values()
        .filter_map(|record| {
            (!record.install_path.exists() || plugin_manifest_path(&record.install_path).is_err())
                .then_some(record.id.clone())
        })
        .collect()
}

fn record_uncommitted_registry_migration(
    registry: &InstalledPluginRegistry,
    discovery: &mut PluginDiscovery,
) {
    if registry.migration_blocked_plugin_ids.is_empty() || registry.migration_warnings.is_empty() {
        return;
    }
    let warning = registry
        .migration_warnings
        .iter()
        .map(|warning| sanitize_plugin_error(warning))
        .collect::<Vec<_>>()
        .join("; ");
    record_scan_warning(&mut discovery.scan_report, &warning);
    for plugin_id in &registry.migration_blocked_plugin_ids {
        let Some(record) = registry.plugins.get(plugin_id) else {
            continue;
        };
        discovery.blocked_plugin_ids.insert(plugin_id.clone());
        discovery.scan_report.failure_count += 1;
        discovery.push_failure(PluginLoadFailure::new(
            record.install_path.clone(),
            record.kind,
            describe_install_source(&record.source),
            PluginError::InvalidManifest(format!(
                "plugin registry migration for `{plugin_id}` is not persisted; runtime loading is disabled: {warning}"
            )),
        ));
    }
}

fn sanitize_registry_for_storage(registry: &InstalledPluginRegistry) -> InstalledPluginRegistry {
    let mut sanitized = registry.clone();
    sanitized.schema_version = INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION;
    for record in sanitized.plugins.values_mut() {
        record.source = sanitize_install_source_for_storage(&record.source);
    }
    for versions in sanitized.versions.values_mut() {
        for record in versions {
            record.source = sanitize_plugin_error(&record.source);
        }
    }
    sanitized
}

fn sanitize_install_source_for_storage(source: &PluginInstallSource) -> PluginInstallSource {
    match source {
        PluginInstallSource::LocalPath { path } => {
            PluginInstallSource::LocalPath { path: path.clone() }
        }
        PluginInstallSource::GitUrl { url } => PluginInstallSource::GitUrl {
            url: sanitize_git_install_url_for_storage(url)
                .unwrap_or_else(|_| sanitize_plugin_error(url)),
        },
    }
}

fn sanitize_git_install_url_for_storage(source: &str) -> Result<String, PluginError> {
    let trimmed = source.trim();
    if trimmed.is_empty() || contains_control_character(trimmed) {
        return Err(PluginError::InvalidManifest(
            "plugin Git install URL must be non-empty and contain no control characters"
                .to_string(),
        ));
    }
    if let Some((scheme, after_scheme)) = trimmed.split_once("://") {
        let authority_end = after_scheme
            .find(|ch| matches!(ch, '/' | '?' | '#'))
            .unwrap_or(after_scheme.len());
        let authority = &after_scheme[..authority_end];
        let suffix = &after_scheme[authority_end..];
        let path = suffix.split(['?', '#']).next().unwrap_or_default();
        let scheme_lower = scheme.to_ascii_lowercase();
        let sanitized_authority = authority.rsplit_once('@').map_or_else(
            || authority.to_string(),
            |(userinfo, host)| {
                if scheme_lower == "ssh" && !userinfo.is_empty() && !userinfo.contains(':') {
                    format!("{userinfo}@{host}")
                } else {
                    host.to_string()
                }
            },
        );
        Ok(sanitize_storage_markers_and_bound(&format!(
            "{scheme}://{sanitized_authority}{path}"
        )))
    } else if let Some(scp) = parse_scp_git_url(trimmed) {
        let prefix = scp.user.map_or_else(String::new, |user| format!("{user}@"));
        Ok(sanitize_plugin_error(&format!(
            "{prefix}{}:{}",
            scp.host,
            scp.path.split(['?', '#']).next().unwrap_or(scp.path)
        )))
    } else {
        Ok(sanitize_plugin_error(
            trimmed.split(['?', '#']).next().unwrap_or(trimmed),
        ))
    }
}

#[derive(Debug, Clone, Copy)]
struct ScpGitUrl<'a> {
    user: Option<&'a str>,
    host: &'a str,
    path: &'a str,
}

fn parse_scp_git_url(value: &str) -> Option<ScpGitUrl<'_>> {
    if value.contains("://") {
        return None;
    }
    let first_separator = value
        .find('@')
        .and_then(|at| value[at + 1..].find(':').map(|colon| at + 1 + colon))
        .or_else(|| value.find(':'))?;
    let before_colon = &value[..first_separator];
    let path = &value[first_separator + 1..];
    if before_colon.is_empty()
        || path.is_empty()
        || before_colon.contains('/')
        || before_colon.contains('\\')
    {
        return None;
    }
    let (user, host) = before_colon
        .rsplit_once('@')
        .map_or((None, before_colon), |(user, host)| (Some(user), host));
    Some(ScpGitUrl { user, host, path })
}

fn valid_git_url_user(user: &str) -> bool {
    !user.is_empty()
        && !contains_control_character(user)
        && !user.contains(':')
        && !contains_credential_marker(user)
}

fn contains_credential_marker(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    [
        "token=",
        "access_token=",
        "refresh_token=",
        "api_key=",
        "apikey=",
        "password=",
        "secret=",
    ]
    .iter()
    .any(|marker| lowered.contains(marker))
}

fn sanitize_storage_markers_and_bound(value: &str) -> String {
    let mut redacted = value.to_string();
    for marker in [
        "Authorization: Bearer ",
        "authorization: Bearer ",
        "Bearer ",
        "token=",
        "access_token=",
        "refresh_token=",
        "api_key=",
        "apikey=",
        "key=",
        "secret=",
        "password=",
    ] {
        redacted = redact_after_marker(&redacted, marker);
    }
    truncate_plugin_error(&redacted)
}

fn read_registry_at_path(path: &Path) -> Result<InstalledPluginRegistry, PluginError> {
    match fs::read_to_string(path) {
        Ok(contents) if contents.trim().is_empty() => Ok(InstalledPluginRegistry::default()),
        Ok(contents) => Ok(serde_json::from_str::<InstalledPluginRegistry>(&contents)?),
        Err(error) => Err(PluginError::Io(error)),
    }
}

fn migrate_registry_source_metadata_under_lock(
    path: &Path,
    mut sanitized: InstalledPluginRegistry,
) -> Result<InstalledPluginRegistry, PluginError> {
    if let Err(error) = store_registry_at_path(path, &sanitized) {
        sanitized.migration_blocked_plugin_ids = sanitized.plugins.keys().cloned().collect();
        push_manifest_warning(
            &mut sanitized.migration_warnings,
            format!(
                "plugin registry source metadata migration failed for `{}`: {}",
                path.display(),
                sanitize_plugin_error(&error.to_string())
            ),
        );
    }
    Ok(sanitized)
}

fn store_registry_at_path(
    path: &Path,
    registry: &InstalledPluginRegistry,
) -> Result<(), PluginError> {
    maybe_fail_registry_store_for_test()?;
    let Some(parent) = path.parent() else {
        return Err(PluginError::InvalidManifest(format!(
            "plugin registry path `{}` has no parent directory",
            path.display()
        )));
    };
    fs::create_dir_all(parent)?;
    let payload = serde_json::to_vec_pretty(registry)?;
    let mut output = atomic_write_file::AtomicWriteFile::open(path)?;
    output.as_file_mut().write_all(&payload)?;
    output.commit()?;
    Ok(())
}

#[cfg(test)]
static FAIL_REGISTRY_STORE_FOR_TEST: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
fn set_fail_registry_store_for_test(value: bool) {
    FAIL_REGISTRY_STORE_FOR_TEST.store(value, Ordering::SeqCst);
}

#[cfg(test)]
fn maybe_fail_registry_store_for_test() -> Result<(), PluginError> {
    if FAIL_REGISTRY_STORE_FOR_TEST.load(Ordering::SeqCst) {
        Err(PluginError::CommandFailed(
            "injected plugin registry store failure token=[redacted]".to_string(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(test))]
fn maybe_fail_registry_store_for_test() -> Result<(), PluginError> {
    Ok(())
}

fn unix_time_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should be after epoch")
        .as_millis()
}

fn copy_dir_all(source: &Path, destination: &Path) -> Result<(), PluginError> {
    audit_plugin_tree(source)?;
    let source_metadata = fs::symlink_metadata(source)?;
    if destination.exists() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin install target `{}` already exists",
            destination.display()
        )));
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(destination)?;
    let canonical_source_root = source.canonicalize()?;
    let mut budget = ScanBudget::new();
    budget.count_dir(source, 0)?;
    copy_dir_all_inner(source, &canonical_source_root, destination, &mut budget, 0)?;
    fs::set_permissions(destination, source_metadata.permissions())?;
    audit_plugin_tree(destination)?;
    Ok(())
}

fn copy_dir_all_atomic(source: &Path, destination: &Path) -> Result<(), PluginError> {
    if destination.exists() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin install target `{}` already exists",
            destination.display()
        )));
    }
    let parent = destination.parent().ok_or_else(|| {
        PluginError::InvalidManifest(format!(
            "plugin install target `{}` has no parent directory",
            destination.display()
        ))
    })?;
    fs::create_dir_all(parent)?;
    static COPY_DIR_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let temp_destination = parent.join(format!(
        ".{}.tmp-{}-{}",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("plugin-dir"),
        std::process::id(),
        COPY_DIR_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let cleanup = TempDirCleanupGuard::new(temp_destination.clone());
    copy_dir_all(source, &temp_destination)?;
    if destination.exists() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin install target `{}` already exists",
            destination.display()
        )));
    }
    fs::rename(&temp_destination, destination)?;
    cleanup.disarm();
    Ok(())
}

#[derive(Debug)]
struct UninstallTrash {
    trash_root: PathBuf,
    entries: Vec<TrashedPluginPath>,
}

#[derive(Debug)]
struct TrashedPluginPath {
    original: PathBuf,
    trashed: PathBuf,
}

fn move_plugin_paths_to_uninstall_trash(
    paths: &BTreeSet<PathBuf>,
    install_root: &Path,
) -> Result<Option<UninstallTrash>, PluginError> {
    if paths.is_empty() {
        return Ok(None);
    }
    let trash_parent = install_root.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(trash_parent)?;
    static UNINSTALL_TRASH_COUNTER: AtomicU64 = AtomicU64::new(0);
    let trash_root = trash_parent.join(format!(
        ".uninstall-trash-{}-{}-{}",
        std::process::id(),
        unix_time_ms(),
        UNINSTALL_TRASH_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&trash_root)?;
    let mut trash = UninstallTrash {
        trash_root,
        entries: Vec::new(),
    };

    for (index, path) in paths.iter().enumerate() {
        if !path.exists() {
            continue;
        }
        let trashed = trash.trash_root.join(format!("entry-{index}"));
        if let Err(error) = fs::rename(path, &trashed) {
            let restore_error = restore_uninstall_trash(&trash).err();
            let _ = fs::remove_dir_all(&trash.trash_root);
            if let Some(restore_error) = restore_error {
                return Err(PluginError::CommandFailed(truncate_plugin_error(&format!(
                    "{}; uninstall staging rollback failed: {}",
                    sanitize_plugin_error(&error.to_string()),
                    sanitize_plugin_error(&restore_error.to_string())
                ))));
            }
            return Err(error.into());
        }
        trash.entries.push(TrashedPluginPath {
            original: path.clone(),
            trashed,
        });
    }

    Ok(Some(trash))
}

fn restore_uninstall_trash(trash: &UninstallTrash) -> Result<(), PluginError> {
    let mut errors = Vec::new();
    for entry in trash.entries.iter().rev() {
        if let Some(parent) = entry.original.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                errors.push(format!(
                    "create `{}`: {}",
                    parent.display(),
                    sanitize_plugin_error(&error.to_string())
                ));
                continue;
            }
        }
        if let Err(error) = fs::rename(&entry.trashed, &entry.original) {
            errors.push(format!(
                "restore `{}`: {}",
                entry.original.display(),
                sanitize_plugin_error(&error.to_string())
            ));
        }
    }
    if trash.trash_root.exists() {
        let _ = fs::remove_dir_all(&trash.trash_root);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(PluginError::CommandFailed(truncate_plugin_error(
            &errors.join("; "),
        )))
    }
}

fn cleanup_uninstall_trash(trash_root: &Path) -> Result<(), PluginError> {
    maybe_fail_uninstall_trash_cleanup_for_test()?;
    if trash_root.exists() {
        fs::remove_dir_all(trash_root)?;
    }
    Ok(())
}

fn plugin_tree_hash(root: &Path) -> Result<String, PluginError> {
    audit_plugin_tree(root)?;
    let canonical_root = root.canonicalize()?;
    let mut hasher = Sha256::new();
    let mut budget = ScanBudget::new();
    budget.count_dir(root, 0)?;
    hash_plugin_tree_inner(root, &canonical_root, &mut hasher, &mut budget, 0)?;
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn hash_plugin_tree_inner(
    root: &Path,
    canonical_root: &Path,
    hasher: &mut Sha256,
    budget: &mut ScanBudget,
    depth: usize,
) -> Result<(), PluginError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(root)? {
        budget.check_cooperative_deadline(root)?;
        let entry = entry?;
        entries.push(entry.path());
    }
    entries.sort_by(|left, right| {
        relative_hash_path(canonical_root, left).cmp(&relative_hash_path(canonical_root, right))
    });

    for path in entries {
        let metadata = fs::symlink_metadata(&path)?;
        validate_plugin_entry_metadata(&path, &metadata)?;
        ensure_source_path_within_root(canonical_root, &path)?;
        budget.count_metadata(&path, &metadata, depth + 1)?;
        let relative = relative_hash_path(canonical_root, &path);
        if metadata.is_dir() {
            hash_record_header(hasher, "dir", &relative, &metadata);
            hash_plugin_tree_inner(&path, canonical_root, hasher, budget, depth + 1)?;
        } else if metadata.is_file() {
            hash_record_header(hasher, "file", &relative, &metadata);
            let mut file = fs::File::open(&path)?;
            let mut buffer = [0_u8; 8192];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        } else {
            return Err(PluginError::InvalidManifest(format!(
                "plugin tree contains forbidden special file `{}`",
                path.display()
            )));
        }
    }
    Ok(())
}

fn hash_record_header(hasher: &mut Sha256, kind: &str, relative: &str, metadata: &fs::Metadata) {
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(relative.as_bytes());
    hasher.update([0]);
    hasher.update(plugin_metadata_mode(metadata).to_string().as_bytes());
    hasher.update([0]);
}

fn relative_hash_path(root: &Path, path: &Path) -> String {
    path.canonicalize()
        .ok()
        .and_then(|canonical| canonical.strip_prefix(root).ok().map(Path::to_path_buf))
        .unwrap_or_else(|| path.to_path_buf())
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(unix)]
fn plugin_metadata_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn plugin_metadata_mode(metadata: &fs::Metadata) -> u32 {
    u32::from(metadata.permissions().readonly())
}

fn copy_dir_all_inner(
    source: &Path,
    canonical_source_root: &Path,
    destination: &Path,
    budget: &mut ScanBudget,
    depth: usize,
) -> Result<(), PluginError> {
    for entry in fs::read_dir(source)? {
        budget.check_cooperative_deadline(source)?;
        let entry = entry?;
        let source_path = entry.path();
        let metadata = fs::symlink_metadata(&source_path)?;
        validate_plugin_entry_metadata(&source_path, &metadata)?;
        ensure_source_path_within_root(canonical_source_root, &source_path)?;
        budget.count_metadata(&source_path, &metadata, depth + 1)?;
        let target = destination.join(entry.file_name());
        if metadata.is_dir() {
            fs::create_dir(&target)?;
            copy_dir_all_inner(
                &source_path,
                canonical_source_root,
                &target,
                budget,
                depth + 1,
            )?;
            fs::set_permissions(&target, metadata.permissions())?;
        } else if metadata.is_file() {
            copy_file_atomic(&source_path, canonical_source_root, &target, &metadata)?;
        } else {
            return Err(PluginError::InvalidManifest(format!(
                "plugin tree contains forbidden special file `{}`",
                source_path.display()
            )));
        }
    }
    Ok(())
}

fn audit_plugin_tree(root: &Path) -> Result<(), PluginError> {
    let metadata = fs::symlink_metadata(root)?;
    validate_plugin_entry_metadata(root, &metadata)?;
    if !metadata.is_dir() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin tree root `{}` must be a directory",
            root.display()
        )));
    }
    let mut budget = ScanBudget::new();
    budget.count_dir(root, 0)?;
    audit_plugin_tree_inner(root, &mut budget, 0)
}

fn audit_plugin_tree_inner(
    root: &Path,
    budget: &mut ScanBudget,
    depth: usize,
) -> Result<(), PluginError> {
    for entry in fs::read_dir(root)? {
        budget.check_cooperative_deadline(root)?;
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        validate_plugin_entry_metadata(&path, &metadata)?;
        budget.count_metadata(&path, &metadata, depth + 1)?;
        if metadata.is_dir() {
            audit_plugin_tree_inner(&path, budget, depth + 1)?;
        } else if !metadata.is_file() {
            return Err(PluginError::InvalidManifest(format!(
                "plugin tree contains forbidden special file `{}`",
                path.display()
            )));
        }
    }
    Ok(())
}

fn validate_plugin_entry_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), PluginError> {
    if metadata.file_type().is_symlink() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin tree contains forbidden symlink `{}`",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        if metadata.is_file() && metadata.nlink() > 1 {
            return Err(PluginError::InvalidManifest(format!(
                "plugin tree contains forbidden hardlink `{}`",
                path.display()
            )));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(PluginError::InvalidManifest(format!(
                "plugin tree contains forbidden reparse point `{}`",
                path.display()
            )));
        }
    }
    if !metadata.is_dir() && !metadata.is_file() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin tree contains forbidden special file `{}`",
            path.display()
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PluginFileSnapshot {
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    nlink: u64,
}

impl PluginFileSnapshot {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            #[cfg(unix)]
            dev: {
                use std::os::unix::fs::MetadataExt;
                metadata.dev()
            },
            #[cfg(unix)]
            ino: {
                use std::os::unix::fs::MetadataExt;
                metadata.ino()
            },
            #[cfg(unix)]
            nlink: {
                use std::os::unix::fs::MetadataExt;
                metadata.nlink()
            },
        }
    }

    fn ensure_same(&self, path: &Path, metadata: &fs::Metadata) -> Result<(), PluginError> {
        let current = Self::from_metadata(metadata);
        if &current != self {
            return Err(PluginError::InvalidManifest(format!(
                "plugin source file `{}` changed during install copy",
                path.display()
            )));
        }
        Ok(())
    }
}

fn ensure_source_path_within_root(
    canonical_source_root: &Path,
    path: &Path,
) -> Result<PathBuf, PluginError> {
    let canonical_path = path.canonicalize()?;
    if !canonical_path.starts_with(canonical_source_root) {
        return Err(PluginError::InvalidManifest(format!(
            "plugin source path `{}` escaped the source root",
            path.display()
        )));
    }
    Ok(canonical_path)
}

fn copy_file_atomic(
    source_path: &Path,
    canonical_source_root: &Path,
    target: &Path,
    before_metadata: &fs::Metadata,
) -> Result<(), PluginError> {
    validate_plugin_entry_metadata(source_path, before_metadata)?;
    ensure_source_path_within_root(canonical_source_root, source_path)?;
    if target.exists() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin install target `{}` already exists",
            target.display()
        )));
    }

    let before = PluginFileSnapshot::from_metadata(before_metadata);
    let mut input = fs::File::open(source_path)?;
    let opened_metadata = input.metadata()?;
    validate_plugin_entry_metadata(source_path, &opened_metadata)?;
    before.ensure_same(source_path, &opened_metadata)?;

    static COPY_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
    let temp_target = target.with_file_name(format!(
        ".{}.tmp-{}-{}",
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("plugin-file"),
        std::process::id(),
        COPY_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_target)?;
    let cleanup = TempPathCleanupGuard::new(temp_target.clone());
    let copy_result = (|| -> Result<(), PluginError> {
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        drop(output);
        fs::set_permissions(&temp_target, before_metadata.permissions())?;
        Ok(())
    })();
    if let Err(error) = copy_result {
        return Err(error);
    }

    let after_metadata = fs::symlink_metadata(source_path)?;
    validate_plugin_entry_metadata(source_path, &after_metadata)?;
    before.ensure_same(source_path, &after_metadata)?;

    promote_temp_file_no_replace(cleanup, target)
}

struct TempPathCleanupGuard {
    path: PathBuf,
    active: bool,
}

impl TempPathCleanupGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, active: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(mut self) {
        self.active = false;
    }
}

impl Drop for TempPathCleanupGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct TempDirCleanupGuard {
    path: PathBuf,
    active: bool,
}

impl TempDirCleanupGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, active: true }
    }

    fn disarm(mut self) {
        self.active = false;
    }
}

impl Drop for TempDirCleanupGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn promote_temp_file_no_replace(
    cleanup: TempPathCleanupGuard,
    target: &Path,
) -> Result<(), PluginError> {
    if target.exists() {
        return Err(PluginError::InvalidManifest(format!(
            "plugin install target `{}` already exists",
            target.display()
        )));
    }
    #[cfg(unix)]
    {
        fs::hard_link(cleanup.path(), target).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                PluginError::InvalidManifest(format!(
                    "plugin install target `{}` already exists",
                    target.display()
                ))
            } else {
                PluginError::Io(error)
            }
        })?;
        fs::remove_file(cleanup.path())?;
        cleanup.disarm();
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::rename(cleanup.path(), target).map_err(PluginError::Io)?;
        cleanup.disarm();
        Ok(())
    }
}

fn prune_archived_versions(
    versions: &mut Vec<InstalledPluginVersionRecord>,
    keep_versions: usize,
    protected_versions: &[&str],
) {
    let protected_versions = protected_versions.iter().copied().collect::<BTreeSet<_>>();
    versions.sort_by(|left, right| {
        left.archived_at_unix_ms
            .cmp(&right.archived_at_unix_ms)
            .then_with(|| compare_semver_strings(&left.version, &right.version))
            .then_with(|| left.version.cmp(&right.version))
    });
    while versions
        .iter()
        .filter(|record| !protected_versions.contains(record.version.as_str()))
        .count()
        > keep_versions
    {
        let Some(index) = versions
            .iter()
            .position(|record| !protected_versions.contains(record.version.as_str()))
        else {
            break;
        };
        let removed = versions.remove(index);
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
    maybe_fail_settings_store_for_test()?;
    let payload = serde_json::to_vec_pretty(&root)?;
    let mut output = atomic_write_file::AtomicWriteFile::open(path)?;
    output.as_file_mut().write_all(&payload)?;
    output.commit()?;
    Ok(())
}

#[cfg(test)]
static FAIL_SETTINGS_STORE_FOR_TEST: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
fn set_fail_settings_store_for_test(value: bool) {
    FAIL_SETTINGS_STORE_FOR_TEST.store(value, Ordering::SeqCst);
}

#[cfg(test)]
fn maybe_fail_settings_store_for_test() -> Result<(), PluginError> {
    if FAIL_SETTINGS_STORE_FOR_TEST.load(Ordering::SeqCst) {
        Err(PluginError::CommandFailed(
            "injected plugin settings store failure token=[redacted]".to_string(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(test))]
fn maybe_fail_settings_store_for_test() -> Result<(), PluginError> {
    Ok(())
}

#[cfg(test)]
static FAIL_UNINSTALL_TRASH_CLEANUP_FOR_TEST: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
fn set_fail_uninstall_trash_cleanup_for_test(value: bool) {
    FAIL_UNINSTALL_TRASH_CLEANUP_FOR_TEST.store(value, Ordering::SeqCst);
}

#[cfg(test)]
fn maybe_fail_uninstall_trash_cleanup_for_test() -> Result<(), PluginError> {
    if FAIL_UNINSTALL_TRASH_CLEANUP_FOR_TEST.load(Ordering::SeqCst) {
        Err(PluginError::CommandFailed(
            "injected uninstall trash cleanup failure token=[redacted]".to_string(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(test))]
fn maybe_fail_uninstall_trash_cleanup_for_test() -> Result<(), PluginError> {
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

struct PluginFileLock {
    file: fs::File,
}

impl Drop for PluginFileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

struct PluginMutationLocks {
    _registry: PluginFileLock,
    _install: Option<PluginFileLock>,
}

fn registry_lock_path(registry_path: &Path) -> PathBuf {
    let parent = registry_path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = registry_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(REGISTRY_FILE_NAME);
    parent.join(format!(".{file_name}.lock"))
}

fn install_tree_lock_path(install_root: &Path) -> PathBuf {
    let parent = install_root.parent().unwrap_or_else(|| Path::new("."));
    let file_name = install_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("plugins");
    parent.join(format!(".{file_name}.install.lock"))
}

fn same_lock_path(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    let normalize = |path: &Path| {
        path.parent()
            .and_then(|parent| parent.canonicalize().ok())
            .map(|parent| {
                path.file_name()
                    .map_or(parent.clone(), |file_name| parent.join(file_name))
            })
    };
    matches!((normalize(left), normalize(right)), (Some(left), Some(right)) if left == right)
}

fn acquire_plugin_file_lock_at(
    path: &Path,
    label: &str,
    timeout: Duration,
) -> Result<PluginFileLock, PluginError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;
    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(PluginFileLock { file }),
            Err(error) if is_file_lock_contended(&error) => {
                if Instant::now() >= deadline {
                    return Err(PluginError::CommandFailed(format!(
                        "timed out after {} ms waiting for {label} lock `{}`",
                        timeout.as_millis(),
                        path.display()
                    )));
                }
                thread::sleep(Duration::from_millis(PLUGIN_LOCK_POLL_MS));
            }
            Err(error) => {
                return Err(PluginError::CommandFailed(format!(
                    "failed to acquire {label} lock `{}`: {}",
                    path.display(),
                    sanitize_plugin_error(&error.to_string())
                )));
            }
        }
    }
}

fn is_file_lock_contended(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        // ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION are how Windows
        // reports a contended fs2 lock.
        matches!(error.raw_os_error(), Some(32 | 33))
    }
    #[cfg(not(windows))]
    {
        false
    }
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
            root.join(MANIFEST_RELATIVE_PATH).as_path(),
            format!(
                "{{\n  \"name\": \"{name}\",\n  \"version\": \"{version}\",\n  \"description\": \"test plugin\"\n}}"
            )
            .as_str(),
        );
    }

    fn write_hot_reload_external_plugin(root: &Path, name: &str, version: &str) {
        write_file(
            root.join(MANIFEST_RELATIVE_PATH).as_path(),
            format!(
                "{{\n  \"name\": \"{name}\",\n  \"version\": \"{version}\",\n  \"description\": \"test plugin\",\n  \"capabilities\": {{\"hotReload\": true}}\n}}"
            )
            .as_str(),
        );
    }

    fn write_lifecycle_script(root: &Path, name: &str, body: &str) -> String {
        let extension = if cfg!(windows) { "cmd" } else { "sh" };
        let path = root.join("lifecycle").join(format!("{name}.{extension}"));
        write_file(&path, body);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(&path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&path, permissions).expect("chmod");
        }
        path.display().to_string()
    }

    fn lifecycle_append_command(root: &Path, path: &Path, label: &str) -> String {
        if cfg!(windows) {
            write_lifecycle_script(
                root,
                &format!("append-{label}"),
                &format!("@echo off\r\necho {label}>>\"{}\"\r\n", path.display()),
            )
        } else {
            write_lifecycle_script(
                root,
                &format!("append-{label}"),
                &format!("#!/bin/sh\nprintf '{label}\\n' >> '{}'\n", path.display()),
            )
        }
    }

    fn lifecycle_fail_command(root: &Path, label: &str) -> String {
        if cfg!(windows) {
            write_lifecycle_script(root, &format!("fail-{label}"), "@echo off\r\nexit /B 7\r\n")
        } else {
            write_lifecycle_script(root, &format!("fail-{label}"), "#!/bin/sh\nexit 7\n")
        }
    }

    fn lifecycle_sleep_command(root: &Path, label: &str, millis: u64) -> String {
        if cfg!(windows) {
            write_lifecycle_script(
                root,
                &format!("sleep-{label}"),
                &format!(
                    "@echo off\r\npowershell -NoProfile -Command \"Start-Sleep -Milliseconds {millis}\"\r\n"
                ),
            )
        } else {
            write_lifecycle_script(
                root,
                &format!("sleep-{label}"),
                &format!("#!/bin/sh\nsleep {}\n", millis as f64 / 1000.0),
            )
        }
    }

    fn test_metadata(
        id: &str,
        name: &str,
        kind: PluginKind,
        root: Option<PathBuf>,
    ) -> PluginMetadata {
        PluginMetadata {
            id: id.to_string(),
            name: name.to_string(),
            version: "1.0.0".to_string(),
            description: "runtime test plugin".to_string(),
            kind,
            source: "test".to_string(),
            default_enabled: true,
            root,
            manifest: PluginManifestMetadata::builtin(),
        }
    }

    fn runtime_tool(plugin_id: &str, name: &str, sleep_ms: u64) -> PluginTool {
        let (command, args) = if cfg!(windows) {
            (
                "powershell".to_string(),
                vec![
                    "-NoProfile".to_string(),
                    "-Command".to_string(),
                    format!("Start-Sleep -Milliseconds {sleep_ms}; $input | Write-Output"),
                ],
            )
        } else {
            (
                "sh".to_string(),
                vec![
                    "-c".to_string(),
                    format!("sleep {}; cat", sleep_ms as f64 / 1000.0),
                ],
            )
        };
        PluginTool::new(
            plugin_id,
            plugin_id.split('@').next().unwrap_or(plugin_id),
            PluginToolDefinition {
                name: name.to_string(),
                description: Some("runtime test tool".to_string()),
                input_schema: serde_json::json!({"type": "object"}),
                output_schema: None,
            },
            command,
            args,
            PluginToolPermission::ReadOnly,
            None,
        )
    }

    fn runtime_command(name: &str) -> PluginCommandManifest {
        PluginCommandManifest {
            name: name.to_string(),
            description: "runtime test command".to_string(),
            command: "./commands/test.sh".to_string(),
        }
    }

    fn runtime_plugin(id: &str, name: &str, tools: Vec<PluginTool>) -> RegisteredPlugin {
        runtime_plugin_with_commands(id, name, tools, Vec::new())
    }

    fn runtime_plugin_with_commands(
        id: &str,
        name: &str,
        tools: Vec<PluginTool>,
        commands: Vec<PluginCommandManifest>,
    ) -> RegisteredPlugin {
        runtime_plugin_with_options(id, name, tools, commands, true, Vec::new())
    }

    fn runtime_plugin_with_options(
        id: &str,
        name: &str,
        tools: Vec<PluginTool>,
        commands: Vec<PluginCommandManifest>,
        hot_reload: bool,
        dependencies: Vec<PluginDependency>,
    ) -> RegisteredPlugin {
        let capabilities = PluginCapabilities {
            tools: !tools.is_empty(),
            resources: false,
            prompts: false,
            workflows: false,
            hot_reload,
        };
        RegisteredPlugin::new(
            PluginDefinition::Builtin(BuiltinPlugin {
                metadata: test_metadata(id, name, PluginKind::Builtin, None),
                hooks: PluginHooks::default(),
                lifecycle: PluginLifecycle::default(),
                execution_policy: PluginExecutionPolicy::default(),
                permissions: Vec::new(),
                permission_declarations: Vec::new(),
                tools,
                commands,
                resources: Vec::new(),
                prompts: Vec::new(),
                capabilities,
                mcp_servers: BTreeMap::new(),
                dependencies,
                rollback: PluginRollbackPlan::default(),
                version_policy: PluginVersionPolicy::default(),
                ops_permissions: Vec::new(),
            }),
            true,
        )
    }

    fn lifecycle_plugin(
        id: &str,
        name: &str,
        root: &Path,
        init: Vec<String>,
        shutdown: Vec<String>,
    ) -> RegisteredPlugin {
        RegisteredPlugin::new(
            PluginDefinition::Bundled(BundledPlugin {
                metadata: test_metadata(id, name, PluginKind::Bundled, Some(root.to_path_buf())),
                hooks: PluginHooks::default(),
                lifecycle: PluginLifecycle { init, shutdown },
                execution_policy: PluginExecutionPolicy::default(),
                permissions: vec![PluginPermission::Write],
                permission_declarations: vec![PluginPermissionDeclaration::Legacy {
                    permission: PluginPermission::Write,
                }],
                tools: Vec::new(),
                commands: Vec::new(),
                resources: Vec::new(),
                prompts: Vec::new(),
                capabilities: PluginCapabilities {
                    hot_reload: true,
                    ..PluginCapabilities::default()
                },
                mcp_servers: BTreeMap::new(),
                dependencies: Vec::new(),
                rollback: PluginRollbackPlan::default(),
                version_policy: PluginVersionPolicy::default(),
                ops_permissions: Vec::new(),
            }),
            true,
        )
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
    fn load_plugin_from_directory_accepts_versioned_structured_manifest() {
        let _guard = env_guard();
        let root = temp_dir("manifest-structured");
        write_file(
            root.join("bin").join("entry.sh").as_path(),
            "#!/bin/sh\ncat\n",
        );
        write_file(root.join("data").join("readme.txt").as_path(), "ok\n");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "schemaVersion": 1,
  "id": "structured-demo",
  "name": "structured-demo",
  "version": "1.2.3",
  "description": "Structured manifest",
  "signature": "test-signature",
  "entrypoint": { "command": "./bin/entry.sh", "args": ["--json"] },
  "permissions": [
    { "type": "filesystem", "paths": ["./data/readme.txt"], "mode": "read" },
    { "type": "network", "origins": ["https://example.com"] },
    { "type": "process", "commands": ["./bin/entry.sh"] }
  ],
  "capabilities": { "tools": false, "resources": true, "prompts": false },
  "resources": [
    { "uri": "file://structured/readme", "name": "readme" }
  ]
}"#,
        );

        let manifest = load_plugin_from_directory(&root).expect("structured manifest should load");
        assert_eq!(manifest.schema_version, 1);
        assert_eq!(manifest.id.as_deref(), Some("structured-demo"));
        assert_eq!(manifest.permission_declarations.len(), 3);
        assert!(manifest.permissions.contains(&PluginPermission::Read));
        assert!(manifest.permissions.contains(&PluginPermission::Execute));
        assert!(manifest.capabilities.resources);
        assert!(!manifest.capabilities.tools);
        assert!(!manifest.manifest_metadata.legacy);
        assert!(manifest.manifest_metadata.hash.starts_with("fnv1a64:"));
        assert_eq!(
            manifest.manifest_metadata.signature.as_deref(),
            Some("test-signature")
        );
        assert!(!manifest.manifest_metadata.signature_verified);
        assert!(manifest
            .manifest_metadata
            .signature_warning
            .as_deref()
            .is_some_and(|warning| warning.contains("not been verified")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plugin_summary_exposes_permission_declarations_and_enforcement_status() {
        let _guard = env_guard();
        let structured_root = temp_dir("summary-structured-permissions");
        write_file(
            structured_root.join("data").join("readme.txt").as_path(),
            "ok\n",
        );
        write_file(
            structured_root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "schemaVersion": 1,
  "name": "summary-structured",
  "version": "1.0.0",
  "description": "Structured permission summary",
  "permissions": [
    { "type": "filesystem", "paths": ["./data/readme.txt"], "mode": "read" },
    { "type": "network", "origins": ["https://example.com"] }
  ]
}"#,
        );
        let structured = load_plugin_definition(
            &structured_root,
            PluginKind::External,
            "structured-source".to_string(),
            EXTERNAL_MARKETPLACE,
        )
        .expect("structured plugin should load");
        let structured_summary = RegisteredPlugin::new(structured, true).summary();
        assert_eq!(structured_summary.permission_declarations.len(), 2);
        assert_eq!(structured_summary.permission_declaration_statuses.len(), 2);
        assert!(structured_summary
            .permission_declaration_statuses
            .iter()
            .all(|status| !status.enforced && status.declaration_only));

        let legacy_root = temp_dir("summary-legacy-permissions");
        write_file(
            legacy_root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "summary-legacy",
  "version": "1.0.0",
  "description": "Legacy permission summary",
  "permissions": ["read"]
}"#,
        );
        let legacy = load_plugin_definition(
            &legacy_root,
            PluginKind::External,
            "legacy-source".to_string(),
            EXTERNAL_MARKETPLACE,
        )
        .expect("legacy plugin should load");
        let legacy_summary = RegisteredPlugin::new(legacy, true).summary();
        assert_eq!(legacy_summary.permission_declarations.len(), 1);
        assert!(legacy_summary.permission_declaration_statuses[0].enforced);
        assert!(!legacy_summary.permission_declaration_statuses[0].declaration_only);
        assert_eq!(
            legacy_summary.permission_declaration_statuses[0]
                .enforced_permission
                .as_ref()
                .map(|permission| permission.as_str()),
            Some("read")
        );

        let _ = fs::remove_dir_all(structured_root);
        let _ = fs::remove_dir_all(legacy_root);
    }

    #[test]
    fn legacy_manifest_gets_schema_v1_warning_and_normalized_capabilities() {
        let _guard = env_guard();
        let root = temp_dir("manifest-legacy-normalized");
        write_file(
            root.join("tools").join("inspect.sh").as_path(),
            "#!/bin/sh\ncat\n",
        );
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "legacy-normalized",
  "version": "1.0.0",
  "description": "Legacy manifest",
  "permissions": ["read"],
  "tools": [
    {
      "name": "inspect",
      "description": "Inspect",
      "inputSchema": { "type": "object" },
      "command": "./tools/inspect.sh",
      "requiredPermission": "read-only",
      "displayHint": "legacy extension"
    }
  ],
  "historicalExtension": true
}"#,
        );

        let manifest = load_plugin_from_directory(&root).expect("legacy manifest should load");
        assert_eq!(manifest.schema_version, 1);
        assert!(manifest.manifest_metadata.legacy);
        assert!(manifest.capabilities.tools);
        assert!(manifest
            .manifest_metadata
            .warnings
            .iter()
            .any(|warning| warning.contains("normalized to schemaVersion 1")));
        assert!(manifest
            .manifest_metadata
            .warnings
            .iter()
            .any(|warning| warning.contains("tools.[].displayHint")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_plugin_from_directory_rejects_schema_and_unknown_field_policy_violations() {
        for (label, manifest, expected) in [
            (
                "unknown-version",
                r#"{"schemaVersion":2,"name":"schema-bad","version":"1.0.0","description":"bad"}"#,
                "unsupported",
            ),
            (
                "explicit-unknown",
                r#"{"schemaVersion":1,"name":"schema-extra","version":"1.0.0","description":"bad","extra":true}"#,
                "rejects unknown field `extra`",
            ),
            (
                "explicit-nested-unknown",
                r#"{
  "schemaVersion": 1,
  "name": "schema-nested-extra",
  "version": "1.0.0",
  "description": "bad",
  "tools": [
    {
      "name": "inspect",
      "description": "Inspect",
      "inputSchema": { "type": "object" },
      "command": "./tools/inspect.sh",
      "requiredPermission": "read-only",
      "displayHint": true
    }
  ]
}"#,
                "tools.[].displayHint",
            ),
            (
                "legacy-sensitive",
                r#"{"name":"legacy-sensitive","version":"1.0.0","description":"bad","secretToken":"value"}"#,
                "security-sensitive",
            ),
            (
                "legacy-nested-sensitive",
                r#"{
  "name": "legacy-nested-sensitive",
  "version": "1.0.0",
  "description": "bad",
  "tools": [
    {
      "name": "inspect",
      "description": "Inspect",
      "inputSchema": { "type": "object" },
      "command": "./tools/inspect.sh",
      "requiredPermission": "read-only",
      "permissionBypass": true
    }
  ]
}"#,
                "security-sensitive",
            ),
        ] {
            let _guard = env_guard();
            let root = temp_dir(&format!("manifest-schema-{label}"));
            write_file(root.join(MANIFEST_FILE_NAME).as_path(), manifest);

            let error = load_plugin_from_directory(&root).expect_err("manifest should fail");
            assert!(
                error.to_string().contains(expected),
                "{label} did not contain {expected}: {error}"
            );

            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn load_plugin_from_directory_rejects_name_version_and_capability_mismatch() {
        let cases = [
            (
                "reserved-name",
                r#"{"schemaVersion":1,"name":"admin","version":"1.0.0","description":"bad"}"#,
                "reserved",
            ),
            (
                "bad-version",
                r#"{"schemaVersion":1,"name":"bad-version","version":"latest","description":"bad"}"#,
                "semver",
            ),
            (
                "id-mismatch",
                r#"{"schemaVersion":1,"id":"other","name":"id-mismatch","version":"1.0.0","description":"bad"}"#,
                "must match name",
            ),
            (
                "capability-false",
                r#"{
  "schemaVersion": 1,
  "name": "capability-false",
  "version": "1.0.0",
  "description": "bad",
  "permissions": ["read"],
  "capabilities": { "tools": false, "resources": false, "prompts": false },
  "tools": [
    {
      "name": "inspect",
      "description": "Inspect",
      "inputSchema": { "type": "object" },
      "command": "./tools/inspect.sh",
      "requiredPermission": "read-only"
    }
  ]
}"#,
                "capabilities.tools",
            ),
        ];

        for (label, manifest, expected) in cases {
            let _guard = env_guard();
            let root = temp_dir(&format!("manifest-boundary-{label}"));
            write_file(
                root.join("tools").join("inspect.sh").as_path(),
                "#!/bin/sh\ncat\n",
            );
            write_file(root.join(MANIFEST_FILE_NAME).as_path(), manifest);

            let error = load_plugin_from_directory(&root).expect_err("manifest should fail");
            assert!(
                error.to_string().contains(expected),
                "{label} did not contain {expected}: {error}"
            );

            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn external_plugin_hooks_are_rejected_during_registration() {
        let _guard = env_guard();
        let config_home = temp_dir("external-hooks-home");
        let root = temp_dir("external-hooks");
        write_file(
            root.join("hooks").join("pre.sh").as_path(),
            "#!/bin/sh\ntrue\n",
        );
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "name": "external-hooks",
  "version": "1.0.0",
  "description": "External hooks",
  "hooks": { "PreToolUse": ["./hooks/pre.sh"] }
}"#,
        );

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let validate_error = manager
            .validate_plugin_source(root.to_str().expect("utf8 path"))
            .expect_err("external hook source should fail validation");
        assert!(validate_error.to_string().contains("external plugin hooks"));
        let install_error = manager
            .install(root.to_str().expect("utf8 path"))
            .expect_err("external hook install should fail");
        assert!(install_error.to_string().contains("external plugin hooks"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn command_paths_must_stay_inside_plugin_root() {
        let _guard = env_guard();
        let parent = temp_dir("path-traversal-parent");
        let root = parent.join("plugin");
        write_file(parent.join("outside.sh").as_path(), "#!/bin/sh\ntrue\n");
        write_file(
            root.join(MANIFEST_FILE_NAME).as_path(),
            r#"{
  "schemaVersion": 1,
  "name": "path-traversal",
  "version": "1.0.0",
  "description": "Traversal",
  "permissions": ["read"],
  "tools": [
    {
      "name": "inspect",
      "description": "Inspect",
      "inputSchema": { "type": "object" },
      "command": "../outside.sh",
      "requiredPermission": "read-only"
    }
  ]
}"#,
        );

        let error = load_plugin_from_directory(&root).expect_err("traversal should fail");
        assert!(error.to_string().contains("parent-directory traversal"));

        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn oversized_manifest_is_rejected_before_registration() {
        let _guard = env_guard();
        let root = temp_dir("manifest-oversize");
        let oversized = "x".repeat((PLUGIN_MANIFEST_MAX_BYTES as usize) + 1);
        write_file(root.join(MANIFEST_FILE_NAME).as_path(), &oversized);

        let error = load_plugin_from_directory(&root).expect_err("oversize should fail");
        assert!(error.to_string().contains("byte limit"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn duplicate_plugin_names_fail_registry_closed() {
        let _guard = env_guard();
        let config_home = temp_dir("duplicate-name-home");
        let source_root = temp_dir("duplicate-name-source");
        write_external_plugin(&source_root, "example-builtin", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install should succeed");
        let error = manager
            .plugin_registry()
            .expect_err("duplicate name should fail registry");
        assert!(error.to_string().contains("plugin name `example-builtin`"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn plugin_error_sanitizer_redacts_secrets_and_bounds_output() {
        let secret = "SECRET-value-that-must-not-leak";
        let input = format!(
            "failed {}TOKEN={secret} https://user:{secret}@example.com/path?Token={secret} Authorization: Bearer {secret} stderr Secret={secret} API_KEY={secret} {}",
            "\u{0130}",
            "x".repeat(3000)
        );
        let sanitized = sanitize_plugin_error(&input);

        assert!(!sanitized.contains(secret));
        assert!(!sanitized.contains("TOKEN=SECRET"));
        assert!(!sanitized.contains("Secret=SECRET"));
        assert!(!sanitized.contains("API_KEY=SECRET"));
        assert!(sanitized.contains("[redacted]"));
        assert!(
            sanitized.chars().count()
                <= PLUGIN_ERROR_SURFACE_MAX_CHARS + "...[truncated]".chars().count()
        );
    }

    #[test]
    fn plugin_error_sanitizer_redacts_scp_style_passwords() {
        let secret = "SECRET-token-value";
        let sanitized = sanitize_plugin_error(&format!(
            "git failed for user:{secret}@example.com:team/repo.git TOKEN={secret}"
        ));

        assert!(!sanitized.contains(secret));
        assert!(sanitized.contains("[redacted]@example.com:team/repo.git"));
        assert!(sanitized.contains("TOKEN=[redacted]"));
    }

    #[test]
    fn describe_install_source_redacts_ascii_case_markers() {
        let secret = "SECRET-source-value";
        let source = PluginInstallSource::GitUrl {
            url: format!(
                "ssh://git@example.com/team/TOKEN={secret}/Secret={secret}/repo.git?API_KEY={secret}"
            ),
        };
        let rendered = describe_install_source(&source);

        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("TOKEN=SECRET"));
        assert!(!rendered.contains("Secret=SECRET"));
        assert!(!rendered.contains("API_KEY=SECRET"));
        assert!(rendered.contains("TOKEN=[redacted]"));
        assert!(rendered.contains("Secret=[redacted]"));
    }

    #[test]
    fn plugin_child_pipe_reader_caps_output_and_reports_truncation() {
        let payload = vec![b'x'; PLUGIN_CHILD_OUTPUT_LIMIT + 17];
        let (output, truncated) =
            read_pipe_capped(std::io::Cursor::new(payload), PLUGIN_CHILD_OUTPUT_LIMIT)
                .expect("capped pipe read should succeed");

        assert_eq!(output.len(), PLUGIN_CHILD_OUTPUT_LIMIT);
        assert!(truncated);
        assert_eq!(truncated_suffix(truncated), " [truncated]");
    }

    #[test]
    fn git_install_source_rejects_embedded_credentials_without_leaking_values() {
        let secret = "secret-token-value";
        for source in [
            format!("https://user:{secret}@example.com/repo.git"),
            format!("https://example.com/repo.git?token={secret}"),
            format!("https://example.com/repo.git#{secret}"),
            format!("ssh://user:{secret}@example.com/repo.git"),
            format!("user:{secret}@example.com:team/repo.git"),
            format!("token={secret}@example.com:team/repo.git"),
        ] {
            let error = parse_install_source(&source).expect_err("credential URL should fail");
            let rendered = error.to_string();
            assert!(
                !rendered.contains(secret),
                "error leaked credential for {source}: {rendered}"
            );
            assert!(
                rendered.contains("credential")
                    || rendered.contains("userinfo")
                    || rendered.contains("query")
                    || rendered.contains("fragment"),
                "error should explain credential policy: {rendered}"
            );
        }
    }

    #[test]
    fn git_install_source_allows_passwordless_ssh_and_scp_forms() {
        let ssh = parse_install_source("ssh://git@example.com/team/repo.git")
            .expect("passwordless ssh URL should parse");
        assert_eq!(
            ssh,
            PluginInstallSource::GitUrl {
                url: "ssh://git@example.com/team/repo.git".to_string()
            }
        );

        let scp =
            parse_install_source("git@example.com:team/repo.git").expect("scp form should parse");
        assert_eq!(
            scp,
            PluginInstallSource::GitUrl {
                url: "git@example.com:team/repo.git".to_string()
            }
        );

        let scp_without_user =
            parse_install_source("example.com:team/repo.git").expect("scp host form should parse");
        assert_eq!(
            scp_without_user,
            PluginInstallSource::GitUrl {
                url: "example.com:team/repo.git".to_string()
            }
        );
    }

    #[test]
    fn git_install_registry_and_summary_store_only_sanitized_source_metadata() {
        let _guard = env_guard();
        let config_home = temp_dir("git-install-clean-home");
        let parent = temp_dir("git-install-clean-parent");
        let repo = parent.join("clean.git");
        write_external_plugin(&repo, "git-clean", "1.0.0");

        if !run_git(&repo, &["init"])
            || !run_git(&repo, &["add", "."])
            || !run_git(
                &repo,
                &[
                    "-c",
                    "user.name=Claw Test",
                    "-c",
                    "user.email=claw-test@example.invalid",
                    "commit",
                    "-m",
                    "initial",
                ],
            )
        {
            let _ = fs::remove_dir_all(config_home);
            let _ = fs::remove_dir_all(parent);
            return;
        }

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(repo.to_str().expect("git fixture path should be utf8"))
            .expect("local git install should succeed");

        let registry_text =
            fs::read_to_string(manager.registry_path()).expect("registry should exist");
        for forbidden in ["user:", "password=", "token=", "access_token=", "secret="] {
            assert!(
                !registry_text.contains(forbidden),
                "registry leaked forbidden marker {forbidden}: {registry_text}"
            );
        }
        let summaries = manager
            .list_installed_plugins()
            .expect("installed plugin summaries should load");
        let summary = summaries
            .iter()
            .find(|plugin| plugin.metadata.id == "git-clean@external")
            .expect("git plugin summary should be present");
        for forbidden in ["user:", "password=", "token=", "access_token=", "secret="] {
            assert!(
                !summary.metadata.source.contains(forbidden),
                "summary source leaked forbidden marker {forbidden}: {}",
                summary.metadata.source
            );
        }

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(parent);
    }

    #[test]
    fn load_registry_migrates_historical_git_source_secrets_on_disk() {
        let _guard = env_guard();
        let config_home = temp_dir("registry-source-migration-home");
        let install_path = config_home.join("plugins").join("installed").join("legacy");
        let scp_install_path = config_home
            .join("plugins")
            .join("installed")
            .join("legacy-scp");
        let manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let secret = "SECRET-token-value";
        let mut registry = InstalledPluginRegistry::default();
        registry.schema_version = LEGACY_INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION;
        registry.plugins.insert(
            "legacy@external".to_string(),
            InstalledPluginRecord {
                kind: PluginKind::External,
                id: "legacy@external".to_string(),
                name: "legacy".to_string(),
                version: "1.0.0".to_string(),
                description: "legacy registry".to_string(),
                install_path,
                source: PluginInstallSource::GitUrl {
                    url: format!(
                        "https://user:{secret}@example.com/team/TOKEN={secret}/Secret={secret}/repo.git?API_KEY={secret}#frag"
                    ),
                },
                version_policy: PluginVersionPolicy::default(),
                installed_at_unix_ms: 1,
                updated_at_unix_ms: 1,
            },
        );
        registry.plugins.insert(
            "legacy-scp@external".to_string(),
            InstalledPluginRecord {
                kind: PluginKind::External,
                id: "legacy-scp@external".to_string(),
                name: "legacy-scp".to_string(),
                version: "1.0.0".to_string(),
                description: "legacy scp registry".to_string(),
                install_path: scp_install_path,
                source: PluginInstallSource::GitUrl {
                    url: format!("user:{secret}@example.com:team/Secret={secret}/repo.git"),
                },
                version_policy: PluginVersionPolicy::default(),
                installed_at_unix_ms: 1,
                updated_at_unix_ms: 1,
            },
        );
        if let Some(parent) = manager.registry_path().parent() {
            fs::create_dir_all(parent).expect("registry parent");
        }
        fs::write(
            manager.registry_path(),
            serde_json::to_string_pretty(&registry).expect("registry json"),
        )
        .expect("write raw registry");

        let loaded = manager.load_registry().expect("registry should migrate");
        let PluginInstallSource::GitUrl { url } = &loaded.plugins["legacy@external"].source else {
            panic!("source should remain git");
        };
        assert_eq!(
            url,
            "https://example.com/team/TOKEN=[redacted]/Secret=[redacted]/repo.git"
        );
        let PluginInstallSource::GitUrl { url: scp_url } =
            &loaded.plugins["legacy-scp@external"].source
        else {
            panic!("scp source should remain git");
        };
        assert_eq!(
            scp_url,
            "[redacted]@example.com:team/Secret=[redacted]/repo.git"
        );

        let disk = fs::read_to_string(manager.registry_path()).expect("registry disk");
        assert!(!disk.contains(secret));
        assert!(!disk.contains("TOKEN=SECRET"));
        assert!(!disk.contains("Secret=SECRET"));
        assert!(!disk.contains("API_KEY=SECRET"));
        assert!(!disk.contains("user:"));
        assert!(
            disk.contains("https://example.com/team/TOKEN=[redacted]/Secret=[redacted]/repo.git")
        );
        assert!(disk.contains("[redacted]@example.com:team/Secret=[redacted]/repo.git"));

        let _ = fs::remove_dir_all(config_home);
    }

    #[test]
    fn load_registry_migration_store_failure_keeps_readonly_list_degraded() {
        let _guard = env_guard();
        let config_home = temp_dir("registry-migration-fail-home");
        let bundled_root = temp_dir("registry-migration-fail-bundled");
        let install_path = config_home
            .join("plugins")
            .join("installed")
            .join("legacy-list");
        write_external_plugin(&install_path, "legacy-list", "1.0.0");
        let manager_config = {
            let mut config = PluginManagerConfig::new(&config_home);
            config.bundled_root = Some(bundled_root.clone());
            config
        };
        let manager = PluginManager::new(manager_config);
        let secret = "SECRET-token-value";
        let mut registry = InstalledPluginRegistry::default();
        registry.schema_version = LEGACY_INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION;
        registry.plugins.insert(
            "legacy-list@external".to_string(),
            InstalledPluginRecord {
                kind: PluginKind::External,
                id: "legacy-list@external".to_string(),
                name: "legacy-list".to_string(),
                version: "1.0.0".to_string(),
                description: "legacy list registry".to_string(),
                install_path,
                source: PluginInstallSource::GitUrl {
                    url: format!(
                        "https://user:{secret}@example.com/team/TOKEN={secret}/repo.git?Secret={secret}"
                    ),
                },
                version_policy: PluginVersionPolicy::default(),
                installed_at_unix_ms: 1,
                updated_at_unix_ms: 1,
            },
        );
        if let Some(parent) = manager.registry_path().parent() {
            fs::create_dir_all(parent).expect("registry parent");
        }
        fs::write(
            manager.registry_path(),
            serde_json::to_string_pretty(&registry).expect("registry json"),
        )
        .expect("write raw registry");

        set_fail_registry_store_for_test(true);
        let _reset = RegistryStoreFailureReset;
        let summaries = manager
            .list_installed_plugins()
            .expect("readonly list should not fail when migration write fails");
        let summary = summaries
            .iter()
            .find(|plugin| plugin.metadata.id == "legacy-list@external")
            .expect("legacy plugin should be listed");
        assert!(!summary.metadata.source.contains(secret));
        assert!(!summary.metadata.source.contains("TOKEN=SECRET"));
        assert!(!summary.metadata.source.contains("Secret=SECRET"));
        let degraded = summary
            .degraded_reason
            .as_deref()
            .expect("migration warning should be surfaced");
        assert!(degraded.contains("migration failed"));
        assert!(!degraded.contains(secret));

        let report = manager
            .installed_plugin_registry_report()
            .expect("readonly report should be available");
        assert!(report
            .failures()
            .iter()
            .any(|failure| failure.error().to_string().contains("not persisted")));
        assert!(report.scan_report().failure_count > 0);
        assert!(!report.healthy_registry().contains("legacy-list@external"));
        let runtime_error = manager
            .plugin_registry()
            .expect_err("runtime registry must reject unpersisted migration");
        assert!(runtime_error.to_string().contains("not persisted"));

        let store_error = manager
            .store_registry(&InstalledPluginRegistry::default())
            .expect_err("explicit store should still fail closed");
        assert!(store_error
            .to_string()
            .contains("injected plugin registry store failure"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    struct RegistryStoreFailureReset;

    impl Drop for RegistryStoreFailureReset {
        fn drop(&mut self) {
            set_fail_registry_store_for_test(false);
        }
    }

    fn run_git(repo: &Path, args: &[&str]) -> bool {
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    #[cfg(unix)]
    #[test]
    fn install_rejects_symlink_entries_in_plugin_tree() {
        use std::os::unix::fs as unix_fs;

        let _guard = env_guard();
        let config_home = temp_dir("symlink-install-home");
        let source_root = temp_dir("symlink-install-source");
        write_external_plugin(&source_root, "symlink-plugin", "1.0.0");
        write_file(source_root.join("target.txt").as_path(), "target\n");
        unix_fs::symlink("target.txt", source_root.join("linked.txt")).expect("create symlink");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let error = manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect_err("symlink source should fail");
        assert!(error.to_string().contains("forbidden symlink"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn copy_file_atomic_refuses_existing_target_without_overwrite() {
        let source_root = temp_dir("copy-no-overwrite-source");
        let destination_root = temp_dir("copy-no-overwrite-dest");
        write_file(source_root.join("file.txt").as_path(), "new\n");
        fs::create_dir_all(&destination_root).expect("destination root");
        let target = destination_root.join("file.txt");
        write_file(target.as_path(), "existing\n");

        let metadata = fs::symlink_metadata(source_root.join("file.txt")).expect("metadata");
        let canonical_source = source_root.canonicalize().expect("canonical source");
        let error = copy_file_atomic(
            &source_root.join("file.txt"),
            &canonical_source,
            &target,
            &metadata,
        )
        .expect_err("existing target should fail");
        assert!(error.to_string().contains("already exists"));
        assert_eq!(
            fs::read_to_string(target).expect("target remains readable"),
            "existing\n"
        );

        let _ = fs::remove_dir_all(source_root);
        let _ = fs::remove_dir_all(destination_root);
    }

    #[cfg(unix)]
    #[test]
    fn copy_dir_all_preserves_unix_executable_and_private_mode() {
        use std::os::unix::fs::PermissionsExt;

        let source_root = temp_dir("copy-mode-source");
        let destination_root = temp_dir("copy-mode-dest");
        let source_file = source_root.join("bin").join("private-tool");
        write_file(source_file.as_path(), "#!/bin/sh\nexit 0\n");
        let mut root_permissions = fs::metadata(&source_root)
            .expect("root metadata")
            .permissions();
        root_permissions.set_mode(0o700);
        fs::set_permissions(&source_root, root_permissions).expect("set root mode");
        let mut bin_permissions = fs::metadata(source_root.join("bin"))
            .expect("bin metadata")
            .permissions();
        bin_permissions.set_mode(0o750);
        fs::set_permissions(source_root.join("bin"), bin_permissions).expect("set bin mode");
        let mut permissions = fs::metadata(&source_file).expect("metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&source_file, permissions).expect("set source mode");

        copy_dir_all(&source_root, &destination_root).expect("copy should succeed");

        let root_mode = fs::metadata(&destination_root)
            .expect("copied root metadata")
            .permissions()
            .mode()
            & 0o777;
        let bin_mode = fs::metadata(destination_root.join("bin"))
            .expect("copied bin metadata")
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(destination_root.join("bin").join("private-tool"))
            .expect("copied metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(root_mode, 0o700);
        assert_eq!(bin_mode, 0o750);
        assert_eq!(file_mode, 0o700);

        let _ = fs::remove_dir_all(source_root);
        let _ = fs::remove_dir_all(destination_root);
    }

    #[cfg(unix)]
    #[test]
    fn copy_dir_all_applies_readonly_directory_permissions_after_children() {
        use std::os::unix::fs::PermissionsExt;

        let source_root = temp_dir("copy-readonly-source");
        let destination_root = temp_dir("copy-readonly-dest");
        let nested_dir = source_root.join("readonly");
        write_file(nested_dir.join("data.txt").as_path(), "copied\n");

        let mut nested_permissions = fs::metadata(&nested_dir)
            .expect("nested metadata")
            .permissions();
        nested_permissions.set_mode(0o555);
        fs::set_permissions(&nested_dir, nested_permissions).expect("set nested readonly mode");
        let mut root_permissions = fs::metadata(&source_root)
            .expect("root metadata")
            .permissions();
        root_permissions.set_mode(0o555);
        fs::set_permissions(&source_root, root_permissions).expect("set root readonly mode");

        copy_dir_all(&source_root, &destination_root).expect("copy should succeed");

        assert_eq!(
            fs::read_to_string(destination_root.join("readonly").join("data.txt"))
                .expect("copied file"),
            "copied\n"
        );
        let root_mode = fs::metadata(&destination_root)
            .expect("copied root metadata")
            .permissions()
            .mode()
            & 0o777;
        let nested_mode = fs::metadata(destination_root.join("readonly"))
            .expect("copied nested metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(root_mode, 0o555);
        assert_eq!(nested_mode, 0o555);

        let mut cleanup_permissions = fs::metadata(&source_root)
            .expect("source cleanup metadata")
            .permissions();
        cleanup_permissions.set_mode(0o755);
        fs::set_permissions(&source_root, cleanup_permissions).expect("restore source root mode");
        let mut cleanup_nested_permissions = fs::metadata(&nested_dir)
            .expect("nested cleanup metadata")
            .permissions();
        cleanup_nested_permissions.set_mode(0o755);
        fs::set_permissions(&nested_dir, cleanup_nested_permissions)
            .expect("restore source nested mode");
        let mut destination_permissions = fs::metadata(&destination_root)
            .expect("destination cleanup metadata")
            .permissions();
        destination_permissions.set_mode(0o755);
        fs::set_permissions(&destination_root, destination_permissions)
            .expect("restore destination root mode");
        let mut destination_nested_permissions = fs::metadata(destination_root.join("readonly"))
            .expect("destination nested cleanup metadata")
            .permissions();
        destination_nested_permissions.set_mode(0o755);
        fs::set_permissions(
            destination_root.join("readonly"),
            destination_nested_permissions,
        )
        .expect("restore destination nested mode");

        let _ = fs::remove_dir_all(source_root);
        let _ = fs::remove_dir_all(destination_root);
    }

    #[test]
    fn plugin_file_lock_times_out_and_reacquires_after_drop() {
        let lock_root = temp_dir("plugin-lock-timeout");
        let lock_path = lock_root.join(".plugin.lock");
        let first =
            acquire_plugin_file_lock_at(&lock_path, "test plugin", Duration::from_millis(250))
                .expect("first lock should succeed");

        let error =
            match acquire_plugin_file_lock_at(&lock_path, "test plugin", Duration::from_millis(50))
            {
                Ok(lock) => {
                    drop(lock);
                    panic!("second handle should time out while lock is held");
                }
                Err(error) => error,
            };
        assert!(error.to_string().contains("timed out"));

        drop(first);
        let _second =
            acquire_plugin_file_lock_at(&lock_path, "test plugin", Duration::from_millis(250))
                .expect("lock should be reacquired after drop");

        let _ = fs::remove_dir_all(lock_root);
    }

    #[test]
    fn concurrent_registry_mutations_do_not_drop_records() {
        let _guard = env_guard();
        let config_home = temp_dir("concurrent-registry-home");
        let alpha_source = temp_dir("concurrent-alpha-source");
        let beta_source = temp_dir("concurrent-beta-source");
        write_external_plugin(&alpha_source, "parallel-alpha", "1.0.0");
        write_external_plugin(&beta_source, "parallel-beta", "1.0.0");

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let alpha_config = config_home.clone();
        let beta_config = config_home.clone();
        let alpha_barrier = std::sync::Arc::clone(&barrier);
        let beta_barrier = std::sync::Arc::clone(&barrier);
        let alpha_source_for_thread = alpha_source.clone();
        let beta_source_for_thread = beta_source.clone();

        let alpha = std::thread::spawn(move || {
            alpha_barrier.wait();
            let mut manager = PluginManager::new(PluginManagerConfig::new(&alpha_config));
            manager
                .install(alpha_source_for_thread.to_str().expect("utf8 path"))
                .expect("alpha install")
        });
        let beta = std::thread::spawn(move || {
            beta_barrier.wait();
            let mut manager = PluginManager::new(PluginManagerConfig::new(&beta_config));
            manager
                .install(beta_source_for_thread.to_str().expect("utf8 path"))
                .expect("beta install")
        });

        alpha.join().expect("alpha thread");
        beta.join().expect("beta thread");

        let manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let installed = manager
            .list_installed_plugins()
            .expect("installed plugins should list");
        assert!(installed
            .iter()
            .any(|plugin| plugin.metadata.id == "parallel-alpha@external"));
        assert!(installed
            .iter()
            .any(|plugin| plugin.metadata.id == "parallel-beta@external"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(alpha_source);
        let _ = fs::remove_dir_all(beta_source);
    }

    #[cfg(windows)]
    #[test]
    fn registry_atomic_store_preserves_existing_file_when_open_fails() {
        let _guard = env_guard();
        let root = temp_dir("windows-registry-replace-fail");
        let target = root.join(REGISTRY_FILE_NAME);
        write_file(&target, "old\n");

        set_fail_registry_store_for_test(true);
        let error = store_registry_at_path(&target, &InstalledPluginRegistry::default())
            .expect_err("injected store failure should fail before replacement");
        set_fail_registry_store_for_test(false);
        assert!(error.to_string().contains("injected"));
        assert_eq!(
            fs::read_to_string(&target).expect("target remains readable"),
            "old\n"
        );

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn registry_atomic_store_replaces_existing_target() {
        let _guard = env_guard();
        set_fail_registry_store_for_test(false);
        let root = temp_dir("windows-registry-replace-success");
        let target = root.join(REGISTRY_FILE_NAME);
        write_file(&target, "old\n");

        let mut registry = InstalledPluginRegistry::default();
        registry.plugins.insert(
            "windows-replace@external".to_string(),
            InstalledPluginRecord {
                kind: PluginKind::External,
                id: "windows-replace@external".to_string(),
                name: "windows-replace".to_string(),
                version: "1.0.0".to_string(),
                description: "replace test".to_string(),
                install_path: root.join("installed"),
                source: PluginInstallSource::LocalPath {
                    path: root.join("source"),
                },
                version_policy: PluginVersionPolicy::default(),
                installed_at_unix_ms: 1,
                updated_at_unix_ms: 1,
            },
        );

        store_registry_at_path(&target, &registry).expect("replace succeeds");
        let stored = read_registry_at_path(&target).expect("registry should read");
        assert!(stored.plugins.contains_key("windows-replace@external"));

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn install_rejects_hardlink_entries_in_plugin_tree() {
        let _guard = env_guard();
        let config_home = temp_dir("hardlink-install-home");
        let source_root = temp_dir("hardlink-install-source");
        write_external_plugin(&source_root, "hardlink-plugin", "1.0.0");
        write_file(source_root.join("target.txt").as_path(), "target\n");
        fs::hard_link(
            source_root.join("target.txt"),
            source_root.join("linked-hardlink.txt"),
        )
        .expect("create hardlink");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let error = manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect_err("hardlink source should fail");
        assert!(error.to_string().contains("forbidden hardlink"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
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
        assert!(hooks.is_empty());

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
        registry.schema_version = LEGACY_INSTALLED_PLUGIN_REGISTRY_SCHEMA_VERSION;
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
        if let Some(parent) = manager.registry_path().parent() {
            fs::create_dir_all(parent).expect("registry parent");
        }
        fs::write(
            manager.registry_path(),
            serde_json::to_string_pretty(&registry).expect("registry json"),
        )
        .expect("write legacy registry");
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
    fn plugin_registry_initialize_rolls_back_partially_initialized_plugins() {
        let root = temp_dir("hot-init-rollback");
        fs::create_dir_all(&root).expect("root");
        let log = root.join("lifecycle.log");
        let first = lifecycle_plugin(
            "first@bundled",
            "first",
            &root,
            vec![lifecycle_append_command(&root, &log, "first-init")],
            vec![lifecycle_append_command(&root, &log, "first-shutdown")],
        );
        let second = lifecycle_plugin(
            "second@bundled",
            "second",
            &root,
            vec![lifecycle_fail_command(&root, "second-init")],
            vec![lifecycle_append_command(&root, &log, "second-shutdown")],
        );
        let registry = PluginRegistry::new(vec![first, second]);

        let _error = registry
            .initialize()
            .expect_err("second init should fail and roll back first");
        let log = fs::read_to_string(&log).expect("rollback log");
        assert!(log.contains("first-init"));
        assert!(log.contains("first-shutdown"));
        assert!(!log.contains("second-shutdown"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plugin_registry_initialize_rolls_back_when_later_validate_fails() {
        let root = temp_dir("hot-validate-rollback");
        fs::create_dir_all(&root).expect("root");
        let log = root.join("lifecycle.log");
        let first = lifecycle_plugin(
            "first@bundled",
            "first",
            &root,
            vec![lifecycle_append_command(&root, &log, "first-init")],
            vec![lifecycle_append_command(&root, &log, "first-shutdown")],
        );
        let second = lifecycle_plugin(
            "second@bundled",
            "second",
            &root,
            vec![root.join("missing-init.cmd").display().to_string()],
            Vec::new(),
        );
        let registry = PluginRegistry::new(vec![first, second]);

        let error = registry
            .initialize()
            .expect_err("second validate should fail and roll back first");
        assert!(error.to_string().contains("does not exist"));
        let log = fs::read_to_string(&log).expect("rollback log");
        assert!(log.contains("first-init"));
        assert!(log.contains("first-shutdown"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plugin_registry_shutdown_is_best_effort_and_aggregates_errors() {
        let root = temp_dir("hot-shutdown-best-effort");
        fs::create_dir_all(&root).expect("root");
        let first = lifecycle_plugin(
            "first@bundled",
            "first",
            &root,
            Vec::new(),
            vec![lifecycle_fail_command(&root, "first-shutdown")],
        );
        let second = lifecycle_plugin(
            "second@bundled",
            "second",
            &root,
            Vec::new(),
            vec![lifecycle_fail_command(&root, "second-shutdown")],
        );
        let registry = PluginRegistry::new(vec![first, second]);

        let error = registry
            .shutdown()
            .expect_err("shutdown should report aggregate failures");
        let error = error.to_string();
        assert!(error.contains("first@bundled"), "{error}");
        assert!(error.contains("second@bundled"), "{error}");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plugin_runtime_hot_replace_failure_keeps_old_snapshot_and_rolls_back_init() {
        let root = temp_dir("hot-replace-rollback");
        fs::create_dir_all(&root).expect("root");
        let log = root.join("runtime.log");
        let old = runtime_plugin(
            "old@builtin",
            "old",
            vec![runtime_tool("old@builtin", "old_echo", 0)],
        );
        let runtime = PluginRuntimeRegistry::new(PluginRegistry::new(vec![old.clone()]));
        let good_new = lifecycle_plugin(
            "a-good@bundled",
            "good",
            &root,
            vec![lifecycle_append_command(&root, &log, "good-init")],
            vec![lifecycle_append_command(&root, &log, "good-shutdown")],
        );
        let bad_new = lifecycle_plugin(
            "b-bad@bundled",
            "bad",
            &root,
            vec![lifecycle_fail_command(&root, "bad-init")],
            Vec::new(),
        );

        let error = runtime
            .hot_replace(PluginRegistry::new(vec![old, good_new, bad_new]))
            .expect_err("bad init should reject hot replace");
        assert!(error.to_string().contains("failed") || error.to_string().contains("exit"));
        assert!(runtime.snapshot().contains("old@builtin"));
        assert!(!runtime.snapshot().contains("a-good@bundled"));
        assert!(runtime
            .execute_tool("old_echo", &serde_json::json!({"ok": true}))
            .expect("old tool should remain callable")
            .contains("ok"));
        let log = fs::read_to_string(&log).expect("runtime log");
        assert!(log.contains("good-init"));
        assert!(log.contains("good-shutdown"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plugin_runtime_lifecycle_child_timeout_is_cut_by_total_hot_reload_deadline() {
        let root = temp_dir("hot-replace-deadline");
        fs::create_dir_all(&root).expect("root");
        let old = runtime_plugin(
            "old@builtin",
            "old",
            vec![runtime_tool("old@builtin", "old_echo", 0)],
        );
        let runtime = PluginRuntimeRegistry::new(PluginRegistry::new(vec![old.clone()]));
        let slow = lifecycle_plugin(
            "slow@bundled",
            "slow",
            &root,
            vec![lifecycle_sleep_command(&root, "slow-init", 5_000)],
            Vec::new(),
        );

        let started = Instant::now();
        let error = runtime
            .hot_replace_with_timeout(
                PluginRegistry::new(vec![old, slow]),
                Duration::from_millis(75),
            )
            .expect_err("slow lifecycle should be cut off by total deadline");
        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(
            started.elapsed() < Duration::from_millis(2_900),
            "deadline should stay below the 3s hot-reload product budget and cut lifecycle before standalone 5s sleep"
        );
        assert!(runtime.snapshot().contains("old@builtin"));
        assert!(!runtime.snapshot().contains("slow@bundled"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plugin_runtime_hot_reload_false_refuses_online_replace() {
        let old = runtime_plugin(
            "old@builtin",
            "old",
            vec![runtime_tool("old@builtin", "old_echo", 0)],
        );
        let cold = runtime_plugin_with_options(
            "cold@builtin",
            "cold",
            vec![runtime_tool("cold@builtin", "cold_echo", 0)],
            Vec::new(),
            false,
            Vec::new(),
        );
        let runtime = PluginRuntimeRegistry::new(PluginRegistry::new(vec![old.clone()]));

        let error = runtime
            .hot_replace(PluginRegistry::new(vec![old, cold]))
            .expect_err("hotReload=false plugin should not be online-loaded");
        assert!(error.to_string().contains("hotReload=true"), "{error}");
        assert!(!runtime.snapshot().contains("cold@builtin"));
    }

    #[test]
    fn plugin_runtime_prepared_token_quarantines_and_rejects_stale_generation() {
        let old = runtime_plugin(
            "old@builtin",
            "old",
            vec![runtime_tool("old@builtin", "shared_tool", 0)],
        );
        let healthy = runtime_plugin(
            "healthy@builtin",
            "healthy",
            vec![runtime_tool("healthy@builtin", "fresh_tool", 0)],
        );
        let conflict = runtime_plugin(
            "conflict@builtin",
            "conflict",
            vec![runtime_tool("conflict@builtin", "shared_tool", 0)],
        );
        let runtime = PluginRuntimeRegistry::new(PluginRegistry::new(vec![old.clone()]));

        let prepared = runtime
            .prepare_hot_replace(PluginRegistry::new(vec![
                old.clone(),
                healthy.clone(),
                conflict,
            ]))
            .expect("prepare should quarantine conflicts without side effects");

        assert_eq!(prepared.base_generation(), 0);
        assert!(prepared.accepted_registry().contains("old@builtin"));
        assert!(prepared.accepted_registry().contains("healthy@builtin"));
        assert!(!prepared.accepted_registry().contains("conflict@builtin"));
        assert!(!runtime.snapshot().contains("healthy@builtin"));

        runtime
            .hot_replace(PluginRegistry::new(vec![old, healthy]))
            .expect("independent commit should advance the generation");
        let error = runtime
            .commit_prepared_hot_replace(prepared)
            .expect_err("prepared token from an old generation must not commit");
        assert!(error.to_string().contains("generation mismatch"), "{error}");
        assert!(runtime.snapshot().contains("healthy@builtin"));
        assert!(!runtime.snapshot().contains("conflict@builtin"));
    }

    #[test]
    fn plugin_runtime_quarantines_conflicting_plugin_and_keeps_healthy_tools() {
        let old = runtime_plugin(
            "old@builtin",
            "old",
            vec![runtime_tool("old@builtin", "shared_tool", 0)],
        );
        let healthy = runtime_plugin(
            "healthy@builtin",
            "healthy",
            vec![runtime_tool("healthy@builtin", "fresh_tool", 0)],
        );
        let conflict = runtime_plugin(
            "conflict@builtin",
            "conflict",
            vec![runtime_tool("conflict@builtin", "shared_tool", 0)],
        );
        let runtime = PluginRuntimeRegistry::new(PluginRegistry::new(vec![old.clone()]));

        let status = runtime
            .hot_replace(PluginRegistry::new(vec![old, healthy, conflict]))
            .expect("conflict should be quarantined, not fatal");
        assert_eq!(status.phase, "degraded");
        assert_eq!(status.degraded_plugins[0].plugin_id, "conflict@builtin");
        assert!(runtime.snapshot().contains("old@builtin"));
        assert!(runtime.snapshot().contains("healthy@builtin"));
        assert!(!runtime.snapshot().contains("conflict@builtin"));
        assert!(runtime
            .execute_tool("shared_tool", &serde_json::json!({"old": true}))
            .expect("old tool should be retained")
            .contains("old"));
        assert!(runtime
            .execute_tool("fresh_tool", &serde_json::json!({"fresh": true}))
            .expect("healthy new tool should be available")
            .contains("fresh"));
    }

    #[test]
    fn plugin_runtime_snapshot_syncs_command_surface_and_quarantines_conflicts() {
        let old = runtime_plugin_with_commands(
            "old@builtin",
            "old",
            Vec::new(),
            vec![runtime_command("sync")],
        );
        let healthy = runtime_plugin_with_commands(
            "healthy@builtin",
            "healthy",
            Vec::new(),
            vec![runtime_command("build")],
        );
        let conflict = runtime_plugin_with_commands(
            "conflict@builtin",
            "conflict",
            Vec::new(),
            vec![runtime_command("sync")],
        );
        let runtime = PluginRuntimeRegistry::new(PluginRegistry::new(vec![old.clone()]));

        let status = runtime
            .hot_replace(PluginRegistry::new(vec![old, healthy, conflict]))
            .expect("command conflict should be quarantined");
        assert_eq!(status.phase, "degraded");
        assert_eq!(status.command_count, 2);
        assert_eq!(status.degraded_plugins[0].plugin_id, "conflict@builtin");
        assert!(status.degraded_plugins[0].reason.contains("command `sync`"));
        assert!(runtime.snapshot().contains("old@builtin"));
        assert!(runtime.snapshot().contains("healthy@builtin"));
        assert!(!runtime.snapshot().contains("conflict@builtin"));
        let commands = runtime
            .snapshot()
            .aggregated_commands()
            .expect("commands should aggregate from active generation");
        let command_names = commands
            .into_iter()
            .map(|command| command.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            command_names,
            BTreeSet::from(["build".to_string(), "sync".to_string()])
        );
    }

    #[test]
    fn plugin_runtime_executes_command_through_controlled_supervisor() {
        let root = temp_dir("runtime-command-exec");
        fs::create_dir_all(&root).expect("root");
        let command_path = if cfg!(windows) {
            write_lifecycle_script(
                &root,
                "say-command",
                "@echo off\r\necho plugin-command-ok:%1:%2\r\n",
            )
        } else {
            write_lifecycle_script(
                &root,
                "say-command",
                "#!/bin/sh\nprintf 'plugin-command-ok:%s:%s\\n' \"$1\" \"$2\"\n",
            )
        };
        let plugin = RegisteredPlugin::new(
            PluginDefinition::Bundled(BundledPlugin {
                metadata: test_metadata(
                    "command@bundled",
                    "command",
                    PluginKind::Bundled,
                    Some(root.clone()),
                ),
                hooks: PluginHooks::default(),
                lifecycle: PluginLifecycle::default(),
                execution_policy: PluginExecutionPolicy::default(),
                permissions: vec![PluginPermission::Read],
                permission_declarations: vec![PluginPermissionDeclaration::Legacy {
                    permission: PluginPermission::Read,
                }],
                tools: Vec::new(),
                commands: vec![PluginCommandManifest {
                    name: "say-command".to_string(),
                    description: "Say command".to_string(),
                    command: command_path,
                }],
                resources: Vec::new(),
                prompts: Vec::new(),
                capabilities: PluginCapabilities {
                    hot_reload: true,
                    ..PluginCapabilities::default()
                },
                mcp_servers: BTreeMap::new(),
                dependencies: Vec::new(),
                rollback: PluginRollbackPlan::default(),
                version_policy: PluginVersionPolicy::default(),
                ops_permissions: Vec::new(),
            }),
            true,
        );
        let runtime = PluginRuntimeRegistry::new(PluginRegistry::new(vec![plugin]));

        let specs = runtime.command_specs().expect("command specs");
        assert_eq!(specs[0].name, "say-command");
        assert_eq!(
            runtime
                .execute_command("say-command", &["alpha".to_string(), "beta".to_string()])
                .expect("command should execute"),
            "plugin-command-ok:alpha:beta"
        );
        let error = runtime
            .execute_command("say-command", &["--inject".to_string()])
            .expect_err("option-like args should be rejected");
        assert!(error.to_string().contains("argv safety policy"), "{error}");
        let oversized_args = (0..=PLUGIN_COMMAND_MAX_ARGS)
            .map(|index| format!("arg{index}"))
            .collect::<Vec<_>>();
        let error = runtime
            .execute_command("say-command", &oversized_args)
            .expect_err("too many args should be rejected");
        assert!(error.to_string().contains("item limit"), "{error}");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn plugin_runtime_unload_blocks_new_calls_and_waits_for_in_flight() {
        let slow = runtime_plugin(
            "slow@builtin",
            "slow",
            vec![runtime_tool("slow@builtin", "slow_tool", 250)],
        );
        let runtime = PluginRuntimeRegistry::new(PluginRegistry::new(vec![slow]));
        let running = runtime.clone();
        let call = thread::spawn(move || {
            running
                .execute_tool("slow_tool", &serde_json::json!({"slow": true}))
                .expect("slow call")
        });
        while runtime.status().in_flight.get("slow@builtin").copied() != Some(1) {
            thread::sleep(Duration::from_millis(5));
        }
        let unloading = runtime.clone();
        let unload = thread::spawn(move || unloading.hot_unload("slow@builtin"));
        let deadline = Instant::now() + Duration::from_secs(1);
        while !runtime
            .status()
            .blocked_plugins
            .iter()
            .any(|plugin| plugin == "slow@builtin")
        {
            assert!(Instant::now() < deadline, "unload did not block plugin");
            thread::sleep(Duration::from_millis(5));
        }
        let error = runtime
            .execute_tool("slow_tool", &serde_json::json!({}))
            .expect_err("new calls should be blocked while unloading");
        assert!(error.to_string().contains("unloading"));
        assert!(call.join().expect("call thread").contains("slow"));
        let status = unload.join().expect("unload thread").expect("unload ok");
        assert_eq!(status.generation, 1);
        assert!(!runtime.snapshot().contains("slow@builtin"));
    }

    #[test]
    fn plugin_runtime_unload_timeout_preserves_old_snapshot() {
        let slow = runtime_plugin(
            "slow@builtin",
            "slow",
            vec![runtime_tool("slow@builtin", "slow_tool", 200)],
        );
        let runtime = PluginRuntimeRegistry::new(PluginRegistry::new(vec![slow]));
        let running = runtime.clone();
        let call = thread::spawn(move || {
            running
                .execute_tool("slow_tool", &serde_json::json!({"slow": true}))
                .expect("slow call")
        });
        while runtime.status().in_flight.get("slow@builtin").copied() != Some(1) {
            thread::sleep(Duration::from_millis(5));
        }
        let error = runtime
            .hot_unload_with_timeout("slow@builtin", Duration::from_millis(20))
            .expect_err("unload should time out");
        assert!(error.to_string().contains("deadline"));
        assert!(runtime.snapshot().contains("slow@builtin"));
        assert!(call.join().expect("call thread").contains("slow"));
        assert!(runtime
            .execute_tool("slow_tool", &serde_json::json!({"again": true}))
            .expect("tool should remain after timeout")
            .contains("again"));
    }

    #[test]
    fn plugin_runtime_hot_unload_rejects_enabled_dependents() {
        let base = runtime_plugin(
            "base@builtin",
            "base",
            vec![runtime_tool("base@builtin", "base_tool", 0)],
        );
        let dependent = runtime_plugin_with_options(
            "dependent@builtin",
            "dependent",
            vec![runtime_tool("dependent@builtin", "dependent_tool", 0)],
            Vec::new(),
            true,
            vec![PluginDependency {
                name: "base@builtin".to_string(),
                version_requirement: None,
                optional: false,
            }],
        );
        let runtime =
            PluginRuntimeRegistry::new(PluginRegistry::new(vec![base.clone(), dependent.clone()]));

        let error = runtime
            .hot_unload("base@builtin")
            .expect_err("dependent should block unload");
        assert!(error.to_string().contains("dependent@builtin"), "{error}");
        assert!(runtime.snapshot().contains("base@builtin"));
        assert!(runtime.snapshot().contains("dependent@builtin"));
    }

    struct FailingSupervisor;

    impl PluginRuntimeSupervisor for FailingSupervisor {
        fn prepare_hot_replace_registry(
            &self,
            _registry: PluginRegistry,
        ) -> Result<PreparedPluginRuntimeReplace, PluginError> {
            Err(PluginError::CommandFailed(
                "injected supervisor failure".to_string(),
            ))
        }

        fn commit_prepared_hot_replace(
            &self,
            _prepared: PreparedPluginRuntimeReplace,
        ) -> Result<PluginRuntimeStatus, PluginError> {
            Err(PluginError::CommandFailed(
                "injected supervisor failure".to_string(),
            ))
        }

        fn hot_replace_registry(
            &self,
            _registry: PluginRegistry,
        ) -> Result<PluginRuntimeStatus, PluginError> {
            Err(PluginError::CommandFailed(
                "injected supervisor failure".to_string(),
            ))
        }

        fn hot_unload_plugin(&self, _plugin_id: &str) -> Result<PluginRuntimeStatus, PluginError> {
            Err(PluginError::CommandFailed(
                "injected supervisor failure".to_string(),
            ))
        }
    }

    #[test]
    fn plugin_manager_hot_load_updates_runtime_supervisor_snapshot() {
        let _guard = env_guard();
        let config_home = temp_dir("hot-load-supervisor-home");
        let source_root = temp_dir("hot-load-supervisor-source");
        write_hot_reload_external_plugin(&source_root, "hot-load-demo", "1.0.0");
        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let supervisor = PluginRuntimeRegistry::new(PluginRegistry::new(Vec::new()));

        let outcome = manager
            .hot_load_with_supervisor(source_root.to_str().expect("source path"), &supervisor)
            .expect("hot load should install and replace runtime snapshot");

        assert_eq!(outcome.plugin_id, "hot-load-demo@external");
        assert!(outcome.runtime_status.generation >= 1);
        assert!(supervisor.snapshot().contains("hot-load-demo@external"));
        let plugin = manager
            .list_installed_plugins()
            .expect("installed plugins")
            .into_iter()
            .find(|plugin| plugin.metadata.id == "hot-load-demo@external")
            .expect("plugin installed");
        assert!(plugin.enabled);

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn plugin_manager_hot_load_supervisor_failure_restores_install_state() {
        let _guard = env_guard();
        let config_home = temp_dir("hot-load-restore-home");
        let source_root = temp_dir("hot-load-restore-source");
        write_hot_reload_external_plugin(&source_root, "hot-restore", "1.0.0");
        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));

        let error = manager
            .hot_load_with_supervisor(
                source_root.to_str().expect("source path"),
                &FailingSupervisor,
            )
            .expect_err("supervisor failure should roll back install");
        assert!(error.to_string().contains("supervisor failure"));
        assert!(!manager
            .list_installed_plugins()
            .expect("installed plugins")
            .iter()
            .any(|plugin| plugin.metadata.id == "hot-restore@external"));
        assert!(!manager
            .install_root()
            .join(sanitize_plugin_id("hot-restore@external"))
            .exists());
        assert!(
            !load_enabled_plugins(&manager.settings_path()).contains_key("hot-restore@external")
        );

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn plugin_manager_hot_load_with_supervisor_respects_mutation_lock_contention() {
        let _guard = env_guard();
        let config_home = temp_dir("hot-load-lock-contention-home");
        let source_root = temp_dir("hot-load-lock-contention-source");
        write_hot_reload_external_plugin(&source_root, "hot-contention", "1.0.0");
        let manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let _locks = manager
            .acquire_mutation_locks()
            .expect("first manager should hold mutation locks");
        let mut blocked_manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        let supervisor = PluginRuntimeRegistry::new(PluginRegistry::new(Vec::new()));

        let error = blocked_manager
            .hot_load_with_supervisor(source_root.to_str().expect("source path"), &supervisor)
            .expect_err("hot load should fail while mutation locks are held");
        assert!(error.to_string().contains("timed out"), "{error}");
        assert!(!supervisor.snapshot().contains("hot-contention@external"));

        drop(_locks);
        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn plugin_manager_prepared_hot_reload_holds_locks_and_rolls_back_mutation() {
        let _guard = env_guard();
        let config_home = temp_dir("hot-reload-lock-home");
        let source_root = temp_dir("hot-reload-lock-source");
        write_external_plugin(&source_root, "hot-lock", "1.0.0");
        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));

        let prepared = manager
            .prepare_hot_reload_transaction(|manager| {
                let outcome = manager.install(source_root.to_str().expect("source path"))?;
                Ok((outcome.plugin_id, true))
            })
            .expect("nested mutation should reuse outer hot-reload locks");
        assert_eq!(prepared.result, "hot-lock@external");
        assert!(
            prepared
                .candidate_registry()
                .expect("candidate registry")
                .contains("hot-lock@external"),
            "candidate should include the installed plugin before commit"
        );

        manager
            .rollback_prepared_hot_reload(prepared)
            .expect("rollback should restore registry and install tree");
        assert!(!manager
            .list_installed_plugins()
            .expect("installed plugins")
            .iter()
            .any(|plugin| plugin.metadata.id == "hot-lock@external"));
        assert!(!manager
            .install_root()
            .join(sanitize_plugin_id("hot-lock@external"))
            .exists());

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn plugin_manager_hot_unload_reverts_disable_when_runtime_supervisor_fails() {
        let _guard = env_guard();
        let config_home = temp_dir("hot-unload-revert-home");
        let source_root = temp_dir("hot-unload-revert-source");
        write_external_plugin(&source_root, "hot-revert", "1.0.0");
        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("source path"))
            .expect("install plugin");

        let error = manager
            .hot_unload_with_supervisor("hot-revert@external", &FailingSupervisor)
            .expect_err("runtime supervisor failure should fail hot unload");
        assert!(error.to_string().contains("supervisor failure"));
        let plugin = manager
            .list_installed_plugins()
            .expect("installed plugins")
            .into_iter()
            .find(|plugin| plugin.metadata.id == "hot-revert@external")
            .expect("plugin remains installed");
        assert!(plugin.enabled, "disable should be reverted");

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn plugin_discovery_scan_uses_stable_priority_overrides() {
        let _guard = env_guard();
        let config_home = temp_dir("scan-priority-home");
        let low_root = temp_dir("scan-priority-low");
        let high_root = temp_dir("scan-priority-high");
        write_external_plugin(&low_root.join("plugin"), "scan-priority", "1.0.0");
        write_external_plugin(&high_root.join("plugin"), "scan-priority", "2.0.0");

        let mut config = PluginManagerConfig::new(&config_home);
        config.discovery_roots = vec![
            PluginScanRoot::new(&high_root, PluginScanRootSource::Project),
            PluginScanRoot::new(&low_root, PluginScanRootSource::System),
        ];
        let manager = PluginManager::new(config);

        let report = manager
            .plugin_registry_report()
            .expect("priority override should not fail discovery");
        let summaries = report.summaries();
        let plugin = summaries
            .iter()
            .find(|plugin| plugin.metadata.id == "scan-priority@external")
            .expect("plugin should be discovered");
        assert_eq!(plugin.metadata.version, "2.0.0");
        assert!(plugin.metadata.source.starts_with("discovered:project:"));
        let explicit_plugin_count: usize = report
            .scan_report()
            .roots
            .iter()
            .filter(|root| root.source == "project" || root.source == "system")
            .map(|root| root.plugin_count)
            .sum();
        assert_eq!(explicit_plugin_count, 2);
        assert!(report.scan_report().skipped_count >= 1);

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(low_root);
        let _ = fs::remove_dir_all(high_root);
    }

    #[test]
    fn plugin_discovery_scan_isolates_bad_manifest_and_reports_root_stats() {
        let _guard = env_guard();
        let config_home = temp_dir("scan-isolation-home");
        let scan_root = temp_dir("scan-isolation-root");
        write_external_plugin(&scan_root.join("valid"), "scan-valid", "1.0.0");
        write_broken_plugin(&scan_root.join("broken"), "scan-broken");

        let mut config = PluginManagerConfig::new(&config_home);
        config.discovery_roots = vec![PluginScanRoot::new(
            &scan_root,
            PluginScanRootSource::UserData,
        )];
        let manager = PluginManager::new(config);

        let report = manager
            .plugin_registry_report()
            .expect("report should keep valid plugin alongside bad discovered plugin");
        assert!(report.registry().contains("scan-valid@external"));
        assert!(report.failures().iter().any(|failure| {
            failure.kind == PluginKind::External && failure.plugin_root.ends_with("broken")
        }));
        let root_report = report
            .scan_report()
            .roots
            .iter()
            .find(|root| root.source == "userData")
            .expect("userData scan root should be reported");
        assert_eq!(root_report.manifest_count, 2);

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(scan_root);
    }

    #[test]
    fn plugin_discovery_scan_equal_priority_duplicate_fails_closed() {
        let _guard = env_guard();
        let config_home = temp_dir("scan-duplicate-home");
        let left_root = temp_dir("scan-duplicate-left");
        let right_root = temp_dir("scan-duplicate-right");
        write_external_plugin(&left_root.join("plugin"), "scan-duplicate", "1.0.0");
        write_external_plugin(&right_root.join("plugin"), "scan-duplicate", "1.0.0");

        let mut config = PluginManagerConfig::new(&config_home);
        config.discovery_roots = vec![
            PluginScanRoot::new(&right_root, PluginScanRootSource::ExplicitConfig),
            PluginScanRoot::new(&left_root, PluginScanRootSource::ExplicitConfig),
        ];
        let manager = PluginManager::new(config);

        let report = manager
            .plugin_registry_report()
            .expect("report should carry structured duplicate failure");
        assert_eq!(report.failures().len(), 1);
        assert!(report.failures()[0]
            .error()
            .to_string()
            .contains("duplicated"));
        let error = report
            .into_registry()
            .expect_err("strict registry should fail closed on duplicate scan result");
        assert!(error.to_string().contains("duplicated"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(left_root);
        let _ = fs::remove_dir_all(right_root);
    }

    #[test]
    fn plugin_discovery_scan_bounds_manifest_size_and_redacts_report_paths() {
        let _guard = env_guard();
        let secret = "SECRET-scan-value";
        let config_home = temp_dir("scan-redaction-home");
        let scan_root = temp_dir(&format!("scan-TOKEN={secret}"));
        let plugin_root = scan_root.join("oversize");
        fs::create_dir_all(plugin_root.join(".claude-plugin")).expect("manifest dir");
        fs::write(
            plugin_root.join(MANIFEST_RELATIVE_PATH),
            " ".repeat((PLUGIN_MANIFEST_MAX_BYTES + 1) as usize),
        )
        .expect("oversize manifest");

        let mut config = PluginManagerConfig::new(&config_home);
        config.discovery_roots = vec![PluginScanRoot::new(
            &scan_root,
            PluginScanRootSource::ExplicitConfig,
        )];
        let manager = PluginManager::new(config);

        let report = manager
            .plugin_registry_report()
            .expect("oversize discovered plugin should be isolated");
        let rendered = serde_json::to_string(report.scan_report()).expect("scan report json");
        assert!(!rendered.contains(secret));
        assert!(rendered.contains("[redacted]"));
        assert_eq!(report.scan_report().failure_count, 1);

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(scan_root);
    }

    #[test]
    fn plugin_discovery_scan_reports_omitted_and_truncated_for_depth_limit() {
        let _guard = env_guard();
        let config_home = temp_dir("scan-depth-home");
        let scan_root = temp_dir("scan-depth-root");
        let deep = scan_root.join("a").join("b").join("c").join("d").join("e");
        fs::create_dir_all(&deep).expect("deep directory");

        let mut config = PluginManagerConfig::new(&config_home);
        config.discovery_roots = vec![PluginScanRoot::new(
            &scan_root,
            PluginScanRootSource::ExplicitConfig,
        )];
        let manager = PluginManager::new(config);

        let report = manager
            .plugin_registry_report()
            .expect("depth-limited scan should report truncation");
        let root_report = report
            .scan_report()
            .roots
            .iter()
            .find(|root| root.source == "explicitConfig")
            .expect("explicit scan root should be reported");
        assert!(root_report.truncated);
        assert!(root_report.omitted_count > 0);
        assert!(report.scan_report().truncated);
        assert!(report.scan_report().omitted_count > 0);
        assert!(root_report
            .warnings
            .iter()
            .any(|warning| warning.contains("depth limit")));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(scan_root);
    }

    #[test]
    fn load_plugin_from_directory_enforces_scan_budget_depth() {
        let _guard = env_guard();
        let root = temp_dir("load-budget-depth");
        write_external_plugin(&root, "load-budget-depth", "1.0.0");
        let mut deep = root.clone();
        for segment in ["a", "b", "c", "d", "e"] {
            deep = deep.join(segment);
        }
        fs::create_dir_all(&deep).expect("deep path");

        let error = load_plugin_from_directory(&root).expect_err("deep tree should fail budget");
        assert!(error.to_string().contains("scan budget exceeded depth"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn default_plugin_discovery_roots_include_xdg_and_project_paths() {
        let _guard = env_guard();
        let xdg_config = temp_dir("scan-xdg-config");
        let xdg_data = temp_dir("scan-xdg-data");
        let project_root = temp_dir("scan-project");
        std::env::set_var("XDG_CONFIG_HOME", &xdg_config);
        std::env::set_var("XDG_DATA_HOME", &xdg_data);

        let roots = PluginManagerConfig::default_discovery_roots(Some(&project_root));

        assert!(roots.iter().any(|root| {
            root.source == PluginScanRootSource::UserConfig
                && root.path == xdg_config.join("claw").join("plugins")
        }));
        assert!(roots.iter().any(|root| {
            root.source == PluginScanRootSource::UserData
                && root.path == xdg_data.join("claw").join("plugins")
        }));
        assert!(roots.iter().any(|root| {
            root.source == PluginScanRootSource::Project
                && root.path == project_root.join(".claw").join("plugins")
        }));

        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("XDG_DATA_HOME");
        let _ = fs::remove_dir_all(xdg_config);
        let _ = fs::remove_dir_all(xdg_data);
        let _ = fs::remove_dir_all(project_root);
    }

    #[cfg(unix)]
    #[test]
    fn plugin_discovery_scan_rejects_symlink_roots() {
        let _guard = env_guard();
        use std::os::unix::fs as unix_fs;

        let config_home = temp_dir("scan-symlink-home");
        let real_root = temp_dir("scan-symlink-real");
        let symlink_root = temp_dir("scan-symlink-link");
        fs::create_dir_all(&real_root).expect("real root");
        unix_fs::symlink(&real_root, &symlink_root).expect("symlink root");

        let mut config = PluginManagerConfig::new(&config_home);
        config.discovery_roots = vec![PluginScanRoot::new(
            &symlink_root,
            PluginScanRootSource::ExplicitConfig,
        )];
        let manager = PluginManager::new(config);

        let report = manager
            .plugin_registry_report()
            .expect("symlink root should be reported without loading plugins");
        assert!(report.scan_report().roots[0]
            .warnings
            .iter()
            .any(|warning| warning.contains("forbidden symlink")));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(real_root);
        let _ = fs::remove_file(symlink_root);
    }

    #[cfg(windows)]
    #[test]
    fn plugin_discovery_scan_rejects_windows_reparse_roots_when_available() {
        let _guard = env_guard();
        use std::os::windows::fs as windows_fs;

        let config_home = temp_dir("scan-windows-reparse-home");
        let real_root = temp_dir("scan-windows-reparse-real");
        let symlink_root = temp_dir("scan-windows-reparse-link");
        fs::create_dir_all(&real_root).expect("real root");
        if let Err(error) = windows_fs::symlink_dir(&real_root, &symlink_root) {
            eprintln!("skipping Windows reparse test; symlink_dir unavailable: {error}");
            let _ = fs::remove_dir_all(config_home);
            let _ = fs::remove_dir_all(real_root);
            return;
        }

        let mut config = PluginManagerConfig::new(&config_home);
        config.discovery_roots = vec![PluginScanRoot::new(
            &symlink_root,
            PluginScanRootSource::ExplicitConfig,
        )];
        let manager = PluginManager::new(config);

        let report = manager
            .plugin_registry_report()
            .expect("reparse root should be reported without loading plugins");
        assert!(report.scan_report().roots[0]
            .warnings
            .iter()
            .any(|warning| {
                warning.contains("forbidden symlink") || warning.contains("forbidden reparse point")
            }));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(real_root);
        let _ = fs::remove_dir_all(symlink_root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn plugin_discovery_scan_rejects_group_world_writable_roots() {
        let _guard = env_guard();
        use std::os::unix::fs::PermissionsExt;

        let config_home = temp_dir("scan-world-writable-home");
        let scan_root = temp_dir("scan-world-writable-root");
        fs::create_dir_all(&scan_root).expect("scan root");
        let mut permissions = fs::metadata(&scan_root).expect("metadata").permissions();
        permissions.set_mode(0o777);
        fs::set_permissions(&scan_root, permissions).expect("chmod");

        let mut config = PluginManagerConfig::new(&config_home);
        config.discovery_roots = vec![PluginScanRoot::new(
            &scan_root,
            PluginScanRootSource::ExplicitConfig,
        )];
        let manager = PluginManager::new(config);

        let report = manager
            .plugin_registry_report()
            .expect("unsafe root should degrade without loading");
        assert!(report.scan_report().roots[0]
            .warnings
            .iter()
            .any(|warning| warning.contains("group/world-writable")));

        let mut permissions = fs::metadata(&scan_root).expect("metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&scan_root, permissions).expect("chmod restore");
        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(scan_root);
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
    fn bundled_scan_isolates_bad_entries_without_aborting_registry_report() {
        let _guard = env_guard();
        let config_home = temp_dir("bundled-scan-isolation-home");
        let bundled_root = temp_dir("bundled-scan-isolation-root");
        write_bundled_plugin(
            &bundled_root.join("valid"),
            "bundled-valid-scan",
            "1.0.0",
            true,
        );
        write_broken_plugin(&bundled_root.join("broken"), "bundled-broken-scan");

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        let manager = PluginManager::new(config);

        let report = manager
            .plugin_registry_report()
            .expect("bad bundled entry should not abort report");
        assert!(report.registry().contains("bundled-valid-scan@bundled"));
        assert!(report
            .failures()
            .iter()
            .any(|failure| failure.kind == PluginKind::Bundled));
        assert!(report
            .scan_report()
            .roots
            .iter()
            .any(|root| root.source == "bundled" && root.plugin_count >= 2));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
    }

    #[cfg(unix)]
    #[test]
    fn enabled_untrusted_installed_record_fails_entry_but_report_continues() {
        let _guard = env_guard();
        use std::os::unix::fs as unix_fs;

        let config_home = temp_dir("enabled-untrusted-home");
        let bundled_root = temp_dir("enabled-untrusted-bundled");
        let real_root = temp_dir("enabled-untrusted-real");
        let symlink_root = temp_dir("enabled-untrusted-link");
        write_external_plugin(&real_root, "enabled-untrusted", "1.0.0");
        unix_fs::symlink(&real_root, &symlink_root).expect("symlink plugin root");

        let mut config = PluginManagerConfig::new(&config_home);
        config.bundled_root = Some(bundled_root.clone());
        let manager = PluginManager::new(config);
        let mut registry = InstalledPluginRegistry::default();
        registry.plugins.insert(
            "enabled-untrusted@external".to_string(),
            InstalledPluginRecord {
                kind: PluginKind::External,
                id: "enabled-untrusted@external".to_string(),
                name: "enabled-untrusted".to_string(),
                version: "1.0.0".to_string(),
                description: "enabled untrusted".to_string(),
                install_path: symlink_root.clone(),
                source: PluginInstallSource::LocalPath {
                    path: symlink_root.clone(),
                },
                version_policy: PluginVersionPolicy::default(),
                installed_at_unix_ms: 1,
                updated_at_unix_ms: 1,
            },
        );
        manager.store_registry(&registry).expect("store registry");
        manager
            .write_enabled_state("enabled-untrusted@external", Some(true))
            .expect("enable untrusted record");

        let report = manager
            .installed_plugin_registry_report()
            .expect("untrusted enabled entry should degrade report, not abort");
        assert!(!report.registry().contains("enabled-untrusted@external"));
        assert!(report.failures().iter().any(|failure| failure
            .error()
            .to_string()
            .contains("failed bounded scan trust checks")));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(bundled_root);
        let _ = fs::remove_dir_all(real_root);
        let _ = fs::remove_file(symlink_root);
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
        let cycle_registry = PluginRegistry::new(vec![
            RegisteredPlugin::new(
                load_plugin_definition(
                    &cycle_a,
                    PluginKind::External,
                    cycle_a.display().to_string(),
                    EXTERNAL_MARKETPLACE,
                )
                .expect("load cycle a"),
                true,
            ),
            RegisteredPlugin::new(
                load_plugin_definition(
                    &cycle_b,
                    PluginKind::External,
                    cycle_b.display().to_string(),
                    EXTERNAL_MARKETPLACE,
                )
                .expect("load cycle b"),
                true,
            ),
        ]);
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
        let error = manager
            .install(second.to_str().expect("utf8 path"))
            .expect_err("dependency mismatch should fail closed");
        let rendered = error.to_string();
        assert!(rendered.contains("single active runtime version is `1.0.0`"));
        assert!(rendered.contains("available installed slots are `1.0.0`"));
        assert!(rendered.contains("rollback `first@external`"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn supports_version_rollback_and_multi_version_listing() {
        let _guard = env_guard();
        let config_home = temp_dir("rollback-home");
        let source_root = temp_dir("rollback-source");
        write_file(source_root.join("payload.txt").as_path(), "v1");
        write_external_plugin(&source_root, "rollback-demo", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install should succeed");
        let installed_v1 = manager
            .load_registry()
            .expect("registry")
            .plugins
            .get("rollback-demo@external")
            .expect("installed record")
            .install_path
            .clone();
        assert!(installed_v1
            .components()
            .any(|component| component.as_os_str() == PLUGIN_VERSIONS_DIR_NAME));
        write_external_plugin(&source_root, "rollback-demo", "2.0.0");
        let update = manager.update("rollback-demo@external").expect("update");
        assert_ne!(installed_v1, update.install_path);
        assert!(installed_v1.exists(), "old immutable version remains");

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
        assert_eq!(rollback.install_path, installed_v1);
        let registry = manager.load_registry().expect("registry");
        let archived_versions = registry
            .versions
            .get("rollback-demo@external")
            .expect("version records");
        let v1_record = archived_versions
            .iter()
            .find(|record| record.version == "1.0.0")
            .expect("v1 record");
        assert_eq!(v1_record.archive_id, "rollback-demo@external#1.0.0");
        assert!(!v1_record.content_hash.is_empty());
        assert!(!v1_record.source.is_empty());

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn archive_id_and_content_hash_tamper_are_rejected() {
        let _guard = env_guard();
        let config_home = temp_dir("archive-tamper-home");
        let source_root = temp_dir("archive-tamper-source");
        write_file(source_root.join("payload.txt").as_path(), "v1");
        write_external_plugin(&source_root, "tamper-demo", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install v1");
        write_file(source_root.join("payload.txt").as_path(), "v2");
        write_external_plugin(&source_root, "tamper-demo", "2.0.0");
        manager.update("tamper-demo@external").expect("update v2");

        let mut registry = manager.load_registry().expect("registry");
        {
            let v1_record = registry
                .versions
                .get_mut("tamper-demo@external")
                .and_then(|records| records.iter_mut().find(|record| record.version == "1.0.0"))
                .expect("v1 record");
            v1_record.archive_id = "tamper-demo@external#wrong".to_string();
        }
        manager
            .store_registry(&registry)
            .expect("store tampered id");
        let error = manager
            .list_versions("tamper-demo@external")
            .expect_err("tampered archiveId should fail");
        assert!(error.to_string().contains("archiveId"));

        registry
            .versions
            .get_mut("tamper-demo@external")
            .and_then(|records| records.iter_mut().find(|record| record.version == "1.0.0"))
            .expect("v1 record")
            .archive_id = "tamper-demo@external#1.0.0".to_string();
        manager.store_registry(&registry).expect("store fixed id");
        let v1_path = registry
            .versions
            .get("tamper-demo@external")
            .and_then(|records| records.iter().find(|record| record.version == "1.0.0"))
            .expect("v1 record")
            .install_path
            .clone();
        write_file(v1_path.join("payload.txt").as_path(), "tampered");
        let error = manager
            .list_versions("tamper-demo@external")
            .expect_err("tampered content should fail");
        assert!(error.to_string().contains("contentHash mismatch"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn version_slot_hash_covers_tmp_named_plugin_files() {
        let _guard = env_guard();
        let config_home = temp_dir("archive-tmp-tamper-home");
        let source_root = temp_dir("archive-tmp-tamper-source");
        write_file(source_root.join(".tmp").as_path(), "guarded tmp payload");
        let tmp_executable = source_root.join("bin").join("runner.tmp-tool");
        write_file(&tmp_executable, "guarded executable payload");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(&tmp_executable)
                .expect("tmp executable metadata")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&tmp_executable, permissions).expect("chmod tmp executable");
        }
        write_external_plugin(&source_root, "tmp-hash-demo", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install v1");
        write_external_plugin(&source_root, "tmp-hash-demo", "2.0.0");
        manager.update("tmp-hash-demo@external").expect("update v2");
        let v1_path = manager
            .load_registry()
            .expect("registry")
            .versions
            .get("tmp-hash-demo@external")
            .and_then(|records| records.iter().find(|record| record.version == "1.0.0"))
            .expect("v1 record")
            .install_path
            .clone();

        write_file(v1_path.join(".tmp").as_path(), "tampered tmp payload");
        let error = manager
            .list_versions("tmp-hash-demo@external")
            .expect_err(".tmp tamper should fail");
        assert!(error.to_string().contains("contentHash mismatch"));

        write_file(v1_path.join(".tmp").as_path(), "guarded tmp payload");
        write_file(
            v1_path.join("bin").join("runner.tmp-tool").as_path(),
            "tampered executable payload",
        );
        let error = manager
            .list_versions("tmp-hash-demo@external")
            .expect_err("*.tmp-* executable tamper should fail");
        assert!(error.to_string().contains("contentHash mismatch"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn active_version_slot_record_is_required_before_runtime_load() {
        let _guard = env_guard();
        let config_home = temp_dir("active-version-slot-required-home");
        let source_root = temp_dir("active-version-slot-required-source");
        write_file(source_root.join("payload.txt").as_path(), "active payload");
        write_external_plugin(&source_root, "active-audit", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install");
        let original_registry = manager.load_registry().expect("registry");
        let active_path = original_registry
            .plugins
            .get("active-audit@external")
            .expect("active record")
            .install_path
            .clone();
        let mut missing_record_registry = original_registry.clone();
        missing_record_registry
            .versions
            .get_mut("active-audit@external")
            .expect("version records")
            .retain(|record| record.version != "1.0.0");
        manager
            .store_registry(&missing_record_registry)
            .expect("store missing active version record");

        let error = manager
            .plugin_registry_report()
            .expect_err("registry report should fail without active version record");
        assert!(error
            .to_string()
            .contains("missing its immutable version slot record"));
        let error = manager
            .list_installed_plugins()
            .expect_err("runtime list should fail without active version record");
        assert!(error
            .to_string()
            .contains("missing its immutable version slot record"));

        manager
            .store_registry(&original_registry)
            .expect("restore active version record");
        write_file(
            active_path.join("payload.txt").as_path(),
            "tampered active payload",
        );
        let error = manager
            .plugin_registry_report()
            .expect_err("registry report should reject active slot tamper");
        assert!(error.to_string().contains("contentHash mismatch"));
        let error = manager
            .list_installed_plugins()
            .expect_err("runtime list should reject active slot tamper");
        assert!(error.to_string().contains("contentHash mismatch"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn schema_downgrade_with_version_records_and_tamper_is_rejected() {
        let _guard = env_guard();
        let config_home = temp_dir("schema-downgrade-tamper-home");
        let source_root = temp_dir("schema-downgrade-tamper-source");
        write_file(source_root.join("payload.txt").as_path(), "active payload");
        write_external_plugin(&source_root, "downgrade-audit", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install");
        let registry = manager.load_registry().expect("registry");
        let active_path = registry
            .plugins
            .get("downgrade-audit@external")
            .expect("active record")
            .install_path
            .clone();
        write_file(
            active_path.join("payload.txt").as_path(),
            "tampered payload",
        );
        let mut raw = serde_json::to_value(&registry).expect("registry json");
        raw["schemaVersion"] = serde_json::json!(0);
        fs::write(
            manager.registry_path(),
            serde_json::to_string_pretty(&raw).expect("raw registry json"),
        )
        .expect("write downgraded registry");

        let error = manager
            .plugin_registry_report()
            .expect_err("schema downgrade with version records must be rejected");
        assert!(error.to_string().contains("schema downgrade"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn install_rolls_back_registry_and_slot_when_settings_store_fails() {
        let _guard = env_guard();
        let config_home = temp_dir("install-settings-rollback-home");
        let source_root = temp_dir("install-settings-rollback-source");
        write_external_plugin(&source_root, "settings-fail", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        set_fail_settings_store_for_test(true);
        let error = manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect_err("settings failure should fail install");
        set_fail_settings_store_for_test(false);
        assert!(error.to_string().contains("settings store failure"));
        let registry = manager.load_registry().expect("registry");
        assert!(!registry.plugins.contains_key("settings-fail@external"));
        assert!(!manager
            .install_root()
            .join(PLUGIN_VERSIONS_DIR_NAME)
            .join("settings-fail-external")
            .join("1.0.0")
            .exists());

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn uninstall_moves_install_tree_back_when_settings_commit_fails() {
        let _guard = env_guard();
        let config_home = temp_dir("uninstall-settings-rollback-home");
        let source_root = temp_dir("uninstall-settings-rollback-source");
        write_external_plugin(&source_root, "uninstall-settings", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install");
        let install_path = manager
            .load_registry()
            .expect("registry")
            .plugins
            .get("uninstall-settings@external")
            .expect("record")
            .install_path
            .clone();
        assert!(install_path.exists());

        set_fail_settings_store_for_test(true);
        let error = manager
            .uninstall("uninstall-settings@external")
            .expect_err("settings commit failure should roll back uninstall");
        set_fail_settings_store_for_test(false);
        assert!(error.to_string().contains("settings store failure"));
        assert!(install_path.exists(), "install tree should be moved back");
        assert!(manager
            .load_registry()
            .expect("registry")
            .plugins
            .contains_key("uninstall-settings@external"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn uninstall_cleanup_failure_is_reported_as_warning_after_commit() {
        let _guard = env_guard();
        let config_home = temp_dir("uninstall-cleanup-warning-home");
        let source_root = temp_dir("uninstall-cleanup-warning-source");
        write_external_plugin(&source_root, "uninstall-cleanup", "1.0.0");

        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(source_root.to_str().expect("utf8 path"))
            .expect("install");
        set_fail_uninstall_trash_cleanup_for_test(true);
        manager
            .uninstall("uninstall-cleanup@external")
            .expect("cleanup failure should not revert committed uninstall");
        set_fail_uninstall_trash_cleanup_for_test(false);
        let warning = manager
            .take_cleanup_warning()
            .expect("cleanup warning should be captured");
        assert!(warning.contains("uninstall trash cleanup failed"));
        assert!(warning.contains("[redacted]"));
        assert!(!manager
            .load_registry()
            .expect("registry")
            .plugins
            .contains_key("uninstall-cleanup@external"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn inactive_version_slots_do_not_satisfy_runtime_dependencies() {
        let _guard = env_guard();
        let config_home = temp_dir("dependency-version-slots-home");
        let source_root = temp_dir("dependency-version-slots-source");
        let base = source_root.join("base");
        let old_consumer = source_root.join("old-consumer");
        let new_consumer = source_root.join("new-consumer");

        write_external_plugin(&base, "base-lib", "1.5.0");
        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(base.to_str().expect("utf8 path"))
            .expect("install base v1");
        write_external_plugin(&base, "base-lib", "2.1.0");
        manager.update("base-lib@external").expect("update base v2");
        write_file(
            old_consumer.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "old-consumer",
  "version": "1.0.0",
  "description": "Old consumer",
  "dependencies": [
    { "name": "base-lib", "versionRequirement": "<2.0.0" }
  ]
}"#,
        );
        write_file(
            new_consumer.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "new-consumer",
  "version": "1.0.0",
  "description": "New consumer",
  "dependencies": [
    { "name": "base-lib", "versionRequirement": ">=2.0.0, <3.0.0" }
  ]
}"#,
        );

        let error = manager
            .install(old_consumer.to_str().expect("utf8 path"))
            .expect_err("inactive archived v1 must not satisfy runtime dependency");
        let rendered = error.to_string();
        assert!(rendered.contains("single active runtime version is `2.1.0`"));
        assert!(rendered.contains("available installed slots are `1.5.0, 2.1.0`"));
        assert!(rendered.contains("rollback `base-lib@external`"));
        manager
            .install(new_consumer.to_str().expect("utf8 path"))
            .expect("new consumer can use active v2 slot");
        let registry = manager.plugin_registry().expect("registry should build");
        let order = registry.dependency_order().expect("dependency order");
        assert!(
            order.iter().position(|id| id == "base-lib@external")
                < order.iter().position(|id| id == "new-consumer@external")
        );

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn archived_dependency_versions_with_surfaces_are_still_inactive() {
        let _guard = env_guard();
        let config_home = temp_dir("dependency-surface-slots-home");
        let source_root = temp_dir("dependency-surface-slots-source");
        let base = source_root.join("base");
        let consumer = source_root.join("consumer");

        write_file(
            base.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "surface-lib",
  "version": "1.0.0",
  "description": "Surface dependency",
  "capabilities": { "resources": true },
  "resources": [
    { "uri": "claw://surface-lib/v1", "name": "Surface v1" }
  ]
}"#,
        );
        let mut manager = PluginManager::new(PluginManagerConfig::new(&config_home));
        manager
            .install(base.to_str().expect("utf8 path"))
            .expect("install base v1");
        write_external_plugin(&base, "surface-lib", "2.0.0");
        manager
            .update("surface-lib@external")
            .expect("update base v2");
        write_file(
            consumer.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "surface-consumer",
  "version": "1.0.0",
  "description": "Surface consumer",
  "dependencies": [
    { "name": "surface-lib", "versionRequirement": "<2.0.0" }
  ]
}"#,
        );

        let error = manager
            .install(consumer.to_str().expect("utf8 path"))
            .expect_err("non-active surface dependency should fail");
        let rendered = error.to_string();
        assert!(rendered.contains("single active runtime version is `2.0.0`"));
        assert!(rendered.contains("available installed slots are `1.0.0, 2.0.0`"));
        assert!(rendered.contains("rollback `surface-lib@external`"));

        let _ = fs::remove_dir_all(config_home);
        let _ = fs::remove_dir_all(source_root);
    }

    #[test]
    fn semver_uses_crate_ranges_and_rejects_version_path_injection() {
        assert!(semver_requirement_matches("^0.2.0", "0.2.5").expect("range"));
        assert!(!semver_requirement_matches("^0.2.0", "0.3.0").expect("range"));
        assert!(semver_requirement_matches("=1.0.0-alpha.1", "1.0.0-alpha.1").expect("pre"));
        assert!(semver_requirement_matches("*", "9.9.9").expect("explicit wildcard"));
        assert!(semver_requirement_matches("   ", "1.0.0").is_err());
        assert!(parse_semver("v1.0.0").is_err());
        assert!(parse_semver("1.0.0/../../evil").is_err());
    }

    #[test]
    fn load_plugin_from_directory_rejects_blank_dependency_version_requirement() {
        let _guard = env_guard();
        let root = temp_dir("blank-dependency-requirement");
        write_file(
            root.join(MANIFEST_RELATIVE_PATH).as_path(),
            r#"{
  "name": "blank-dep",
  "version": "1.0.0",
  "description": "Blank dependency",
  "dependencies": [
    { "name": "base", "versionRequirement": "   " }
  ]
}"#,
        );
        let error = load_plugin_from_directory(&root).expect_err("blank requirement should fail");
        assert!(error.to_string().contains("versionRequirement"));
        let _ = fs::remove_dir_all(root);
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
