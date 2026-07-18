use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io;
use std::io::Read as StdRead;
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use reqwest::blocking::{Client as ReqwestBlockingClient, Response as ReqwestBlockingResponse};
use reqwest::header::{
    HeaderMap, HeaderName, HeaderValue, ACCEPT, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH,
    CONTENT_TYPE, TRANSFER_ENCODING,
};
use reqwest::redirect;
use reqwest::{Client as ReqwestAsyncClient, Response as ReqwestAsyncResponse, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::timeout;

use crate::config::{McpServerConfig, McpTransport, RuntimeConfig, ScopedMcpServerConfig};
use crate::mcp::mcp_tool_name;
use crate::mcp_client::{
    negotiate_mcp_protocol_version, select_mcp_protocol_version, McpClientBootstrap,
    McpClientTransport, McpProtocolSelection, McpProtocolTransportPolicy, McpProtocolVersionError,
    McpRemoteTransport, McpStdioTransport, LATEST_STDIO_MCP_PROTOCOL_VERSION,
};
use crate::mcp_lifecycle_hardened::{
    McpDegradedReport, McpErrorSurface, McpFailedServer, McpLifecyclePhase,
};
use crate::sse::SseEvent;

#[cfg(test)]
const MCP_INITIALIZE_TIMEOUT_MS: u64 = 1_000;
#[cfg(not(test))]
const MCP_INITIALIZE_TIMEOUT_MS: u64 = 10_000;

#[cfg(test)]
const MCP_LIST_TOOLS_TIMEOUT_MS: u64 = 300;
#[cfg(not(test))]
const MCP_LIST_TOOLS_TIMEOUT_MS: u64 = 30_000;

const MCP_MAX_JSONRPC_FRAME_BYTES: usize = 1024 * 1024;
const MCP_MAX_PAGINATION_PAGES: usize = 64;
const MCP_MAX_PAGINATION_ITEMS: usize = 1024;
const MCP_MAX_CURSOR_BYTES: usize = 4096;
const MCP_MAX_CATALOG_ITEM_JSON_BYTES: usize = 64 * 1024;
const MCP_MAX_RESULT_JSON_BYTES: usize = 1024 * 1024;
const MCP_MAX_RESOURCE_CONTENTS: usize = 64;
const MCP_MAX_PROMPT_MESSAGES: usize = 128;
const MCP_SSE_MAX_OPERATION_TIMEOUT_MS: u64 = u32::MAX as u64;
const MCP_SSE_MAX_URL_BYTES: usize = 8 * 1024;
const MCP_SSE_MAX_HEADER_BYTES: usize = 16 * 1024;
const MCP_SSE_MAX_EVENT_BYTES: usize = MCP_MAX_JSONRPC_FRAME_BYTES + 4096;
const MCP_SSE_MAX_HTTP_RESPONSE_BODY_BYTES: usize = 64 * 1024;
const MCP_SSE_READ_CHUNK_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum JsonRpcId {
    Number(u64),
    String(String),
    Null,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcRequest<T = JsonValue> {
    pub jsonrpc: String,
    pub id: JsonRpcId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<T>,
}

impl<T> JsonRpcRequest<T> {
    #[must_use]
    pub fn new(id: JsonRpcId, method: impl Into<String>, params: Option<T>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcNotification<T = JsonValue> {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<T>,
}

impl<T> JsonRpcNotification<T> {
    #[must_use]
    pub fn new(method: impl Into<String>, params: Option<T>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcResponse<T = JsonValue> {
    pub jsonrpc: String,
    pub id: JsonRpcId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpInitializeParams {
    pub protocol_version: String,
    pub capabilities: JsonValue,
    pub client_info: McpInitializeClientInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpInitializeClientInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpInitializeResult {
    pub protocol_version: String,
    pub capabilities: JsonValue,
    pub server_info: McpInitializeServerInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct McpInitializeServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpListToolsParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpTool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema", skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<JsonValue>,
    #[serde(rename = "outputSchema", skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<JsonValue>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpListToolsResult {
    pub tools: Vec<McpTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpToolCallParams {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<JsonValue>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpToolCallContent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub data: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpToolCallResult {
    #[serde(default)]
    pub content: Vec<McpToolCallContent>,
    #[serde(default)]
    pub structured_content: Option<JsonValue>,
    #[serde(default)]
    pub is_error: Option<bool>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpListResourcesParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpResource {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<JsonValue>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpListResourcesResult {
    pub resources: Vec<McpResource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpListResourceTemplatesParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpResourceTemplate {
    #[serde(rename = "uriTemplate")]
    pub uri_template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<JsonValue>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpListResourceTemplatesResult {
    #[serde(default)]
    pub resource_templates: Vec<McpResourceTemplate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpListPromptsParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpPromptArgument {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpPrompt {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub arguments: Vec<McpPromptArgument>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpListPromptsResult {
    pub prompts: Vec<McpPrompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpGetPromptParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpPromptMessage {
    pub role: String,
    pub content: JsonValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpGetPromptResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub messages: Vec<McpPromptMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpReadResourceParams {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpResourceContents {
    pub uri: String,
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<JsonValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpReadResourceResult {
    pub contents: Vec<McpResourceContents>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagedMcpTool {
    pub server_name: String,
    pub qualified_name: String,
    pub raw_name: String,
    pub tool: McpTool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagedMcpResource {
    pub server_name: String,
    pub uri: String,
    pub resource: McpResource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagedMcpResourceTemplate {
    pub server_name: String,
    pub uri_template: String,
    pub resource_template: McpResourceTemplate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManagedMcpPrompt {
    pub server_name: String,
    pub name: String,
    pub prompt: McpPrompt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpCapabilityKind {
    Tools,
    Resources,
    ResourceTemplates,
    Prompts,
}

impl McpCapabilityKind {
    fn method(self) -> &'static str {
        match self {
            Self::Tools => "tools/list",
            Self::Resources => "resources/list",
            Self::ResourceTemplates => "resources/templates/list",
            Self::Prompts => "prompts/list",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Tools => "tools",
            Self::Resources | Self::ResourceTemplates => "resources",
            Self::Prompts => "prompts",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpServerCapabilities {
    pub tools: bool,
    pub resources: bool,
    pub prompts: bool,
    pub raw: JsonValue,
}

impl Default for McpServerCapabilities {
    fn default() -> Self {
        Self {
            tools: false,
            resources: false,
            prompts: false,
            raw: JsonValue::Null,
        }
    }
}

impl McpServerCapabilities {
    fn from_raw(raw: JsonValue) -> Self {
        Self {
            tools: capability_declared(&raw, "tools"),
            resources: capability_declared(&raw, "resources"),
            prompts: capability_declared(&raw, "prompts"),
            raw,
        }
    }

    fn supports(&self, capability: McpCapabilityKind) -> bool {
        match capability {
            McpCapabilityKind::Tools => self.tools,
            McpCapabilityKind::Resources | McpCapabilityKind::ResourceTemplates => self.resources,
            McpCapabilityKind::Prompts => self.prompts,
        }
    }
}

fn capability_declared(raw: &JsonValue, key: &str) -> bool {
    raw.as_object()
        .and_then(|object| object.get(key))
        .is_some_and(JsonValue::is_object)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct McpServerCatalog {
    pub server_name: String,
    pub server_info: Option<McpInitializeServerInfo>,
    pub capabilities: Option<McpServerCapabilities>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_protocol_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiated_protocol_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_transport_policy: Option<McpProtocolTransportPolicy>,
    #[serde(default)]
    pub protocol_configured_preferred: bool,
    pub tools: Vec<ManagedMcpTool>,
    pub resources: Vec<ManagedMcpResource>,
    pub resource_templates: Vec<ManagedMcpResourceTemplate>,
    pub prompts: Vec<ManagedMcpPrompt>,
    pub tools_complete: bool,
    pub resources_complete: bool,
    pub resource_templates_complete: bool,
    pub prompts_complete: bool,
}

impl McpServerCatalog {
    fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            server_info: None,
            capabilities: None,
            requested_protocol_version: None,
            negotiated_protocol_version: None,
            protocol_transport_policy: None,
            protocol_configured_preferred: false,
            tools: Vec::new(),
            resources: Vec::new(),
            resource_templates: Vec::new(),
            prompts: Vec::new(),
            tools_complete: false,
            resources_complete: false,
            resource_templates_complete: false,
            prompts_complete: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedMcpServer {
    pub server_name: String,
    pub transport: McpTransport,
    pub required: bool,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpDiscoveryFailure {
    pub server_name: String,
    pub phase: McpLifecyclePhase,
    pub required: bool,
    pub error: String,
    pub recoverable: bool,
    pub context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpCapabilityDegradation {
    pub server_name: String,
    pub phase: McpLifecyclePhase,
    pub required: bool,
    pub capability: McpCapabilityKind,
    pub method: &'static str,
    pub reason: String,
    pub context: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpToolDiscoveryReport {
    pub tools: Vec<ManagedMcpTool>,
    pub failed_servers: Vec<McpDiscoveryFailure>,
    pub unsupported_servers: Vec<UnsupportedMcpServer>,
    pub heartbeat: Vec<McpServerHeartbeat>,
    pub degraded_startup: Option<McpDegradedReport>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct McpCapabilityDiscoveryReport {
    pub catalogs: Vec<McpServerCatalog>,
    pub tools: Vec<ManagedMcpTool>,
    pub resources: Vec<ManagedMcpResource>,
    pub resource_templates: Vec<ManagedMcpResourceTemplate>,
    pub prompts: Vec<ManagedMcpPrompt>,
    pub failed_servers: Vec<McpDiscoveryFailure>,
    pub degraded_capabilities: Vec<McpCapabilityDegradation>,
    pub unsupported_servers: Vec<UnsupportedMcpServer>,
    pub heartbeat: Vec<McpServerHeartbeat>,
    pub degraded_startup: Option<McpDegradedReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpHeartbeatStatus {
    NotConfigured,
    Unknown,
    Healthy,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerHeartbeat {
    pub server_name: String,
    pub status: McpHeartbeatStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_protocol_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiated_protocol_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_transport_policy: Option<McpProtocolTransportPolicy>,
    #[serde(default)]
    pub protocol_configured_preferred: bool,
    pub last_checked_at_ms: Option<u64>,
    pub last_success_at_ms: Option<u64>,
    pub last_failure_at_ms: Option<u64>,
    pub last_failure_reason: Option<String>,
}

impl McpServerHeartbeat {
    fn new(server_name: impl Into<String>, status: McpHeartbeatStatus) -> Self {
        Self {
            server_name: server_name.into(),
            status,
            requested_protocol_version: None,
            negotiated_protocol_version: None,
            protocol_transport_policy: None,
            protocol_configured_preferred: false,
            last_checked_at_ms: None,
            last_success_at_ms: None,
            last_failure_at_ms: None,
            last_failure_reason: None,
        }
    }

    fn mark_success(&mut self) {
        let now = unix_time_ms();
        self.status = McpHeartbeatStatus::Healthy;
        self.last_checked_at_ms = Some(now);
        self.last_success_at_ms = Some(now);
        self.last_failure_reason = None;
    }

    fn mark_success_with_protocol_version(
        &mut self,
        protocol_selection: &McpProtocolSelection,
        negotiated_protocol_version: Option<String>,
    ) {
        self.mark_success();
        self.mark_protocol_state(Some(protocol_selection), negotiated_protocol_version);
    }

    fn mark_protocol_state(
        &mut self,
        protocol_selection: Option<&McpProtocolSelection>,
        negotiated_protocol_version: Option<String>,
    ) {
        if let Some(protocol_selection) = protocol_selection {
            self.requested_protocol_version =
                Some(protocol_selection.requested_protocol_version.clone());
            self.protocol_transport_policy = Some(protocol_selection.transport_policy);
            self.protocol_configured_preferred = protocol_selection.configured_preferred;
        } else {
            self.requested_protocol_version = None;
            self.protocol_transport_policy = None;
            self.protocol_configured_preferred = false;
        }
        self.negotiated_protocol_version = negotiated_protocol_version;
    }

    fn mark_failure(&mut self, reason: impl Into<String>) {
        let now = unix_time_ms();
        self.status = McpHeartbeatStatus::Failed;
        self.last_checked_at_ms = Some(now);
        self.last_failure_at_ms = Some(now);
        self.last_failure_reason = Some(reason.into());
    }
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Debug)]
pub enum McpServerManagerError {
    Io(io::Error),
    Transport {
        server_name: String,
        method: &'static str,
        source: io::Error,
    },
    JsonRpc {
        server_name: String,
        method: &'static str,
        error: JsonRpcError,
    },
    InvalidResponse {
        server_name: String,
        method: &'static str,
        details: String,
    },
    Timeout {
        server_name: String,
        method: &'static str,
        timeout_ms: u64,
    },
    UnknownTool {
        qualified_name: String,
    },
    UnknownResource {
        server_name: String,
        uri: String,
    },
    UnknownPrompt {
        server_name: String,
        name: String,
    },
    UnknownServer {
        server_name: String,
    },
    UnsupportedCapability {
        server_name: String,
        capability: McpCapabilityKind,
    },
    LimitExceeded {
        server_name: String,
        method: &'static str,
        limit: usize,
        details: String,
    },
}

impl std::fmt::Display for McpServerManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Transport {
                server_name,
                method,
                source,
            } => write!(
                f,
                "MCP server `{server_name}` transport failed during {method}: {source}"
            ),
            Self::JsonRpc {
                server_name,
                method,
                error,
            } => write!(
                f,
                "MCP server `{server_name}` returned JSON-RPC error for {method}: {} ({})",
                error.message, error.code
            ),
            Self::InvalidResponse {
                server_name,
                method,
                details,
            } => write!(
                f,
                "MCP server `{server_name}` returned invalid response for {method}: {details}"
            ),
            Self::Timeout {
                server_name,
                method,
                timeout_ms,
            } => write!(
                f,
                "MCP server `{server_name}` timed out after {timeout_ms} ms while handling {method}"
            ),
            Self::UnknownTool { qualified_name } => {
                write!(f, "unknown MCP tool `{qualified_name}`")
            }
            Self::UnknownResource { server_name, uri } => {
                write!(f, "unknown MCP resource `{uri}` on server `{server_name}`")
            }
            Self::UnknownPrompt { server_name, name } => {
                write!(f, "unknown MCP prompt `{name}` on server `{server_name}`")
            }
            Self::UnknownServer { server_name } => write!(f, "unknown MCP server `{server_name}`"),
            Self::UnsupportedCapability {
                server_name,
                capability,
            } => write!(
                f,
                "MCP server `{server_name}` did not declare `{}` capability",
                capability.as_str()
            ),
            Self::LimitExceeded {
                server_name,
                method,
                limit,
                details,
            } => write!(
                f,
                "MCP server `{server_name}` exceeded {method} limit {limit}: {details}"
            ),
        }
    }
}

impl std::error::Error for McpServerManagerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Transport { source, .. } => Some(source),
            Self::JsonRpc { .. }
            | Self::InvalidResponse { .. }
            | Self::Timeout { .. }
            | Self::UnknownTool { .. }
            | Self::UnknownResource { .. }
            | Self::UnknownPrompt { .. }
            | Self::UnknownServer { .. }
            | Self::UnsupportedCapability { .. }
            | Self::LimitExceeded { .. } => None,
        }
    }
}

impl From<io::Error> for McpServerManagerError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl McpServerManagerError {
    fn lifecycle_phase(&self) -> McpLifecyclePhase {
        match self {
            Self::Io(_) => McpLifecyclePhase::SpawnConnect,
            Self::Transport { method, .. }
            | Self::JsonRpc { method, .. }
            | Self::InvalidResponse { method, .. }
            | Self::Timeout { method, .. }
            | Self::LimitExceeded { method, .. } => lifecycle_phase_for_method(method),
            Self::UnknownTool { .. } | Self::UnknownPrompt { .. } => {
                McpLifecyclePhase::ToolDiscovery
            }
            Self::UnknownResource { .. } => McpLifecyclePhase::ResourceDiscovery,
            Self::UnknownServer { .. } => McpLifecyclePhase::ServerRegistration,
            Self::UnsupportedCapability { capability, .. } => {
                lifecycle_phase_for_method(capability.method())
            }
        }
    }

    fn recoverable(&self) -> bool {
        !matches!(
            self.lifecycle_phase(),
            McpLifecyclePhase::InitializeHandshake
        ) && matches!(self, Self::Transport { .. } | Self::Timeout { .. })
    }

    fn discovery_failure(&self, server_name: &str, required: bool) -> McpDiscoveryFailure {
        let phase = self.lifecycle_phase();
        let recoverable = self.recoverable();
        let context = self.error_context();

        McpDiscoveryFailure {
            server_name: server_name.to_string(),
            phase,
            required,
            error: self.to_string(),
            recoverable,
            context,
        }
    }

    fn error_context(&self) -> BTreeMap<String, String> {
        match self {
            Self::Io(error) => BTreeMap::from([("kind".to_string(), error.kind().to_string())]),
            Self::Transport {
                server_name,
                method,
                source,
            } => BTreeMap::from([
                ("server".to_string(), server_name.clone()),
                ("method".to_string(), (*method).to_string()),
                ("io_kind".to_string(), source.kind().to_string()),
            ]),
            Self::JsonRpc {
                server_name,
                method,
                error,
            } => BTreeMap::from([
                ("server".to_string(), server_name.clone()),
                ("method".to_string(), (*method).to_string()),
                ("jsonrpc_code".to_string(), error.code.to_string()),
            ]),
            Self::InvalidResponse {
                server_name,
                method,
                details,
            } => BTreeMap::from([
                ("server".to_string(), server_name.clone()),
                ("method".to_string(), (*method).to_string()),
                ("details".to_string(), details.clone()),
            ]),
            Self::Timeout {
                server_name,
                method,
                timeout_ms,
            } => BTreeMap::from([
                ("server".to_string(), server_name.clone()),
                ("method".to_string(), (*method).to_string()),
                ("timeout_ms".to_string(), timeout_ms.to_string()),
            ]),
            Self::UnknownTool { qualified_name } => {
                BTreeMap::from([("qualified_tool".to_string(), qualified_name.clone())])
            }
            Self::UnknownResource { server_name, uri } => BTreeMap::from([
                ("server".to_string(), server_name.clone()),
                ("uri".to_string(), uri.clone()),
            ]),
            Self::UnknownPrompt { server_name, name } => BTreeMap::from([
                ("server".to_string(), server_name.clone()),
                ("prompt".to_string(), name.clone()),
            ]),
            Self::UnknownServer { server_name } => {
                BTreeMap::from([("server".to_string(), server_name.clone())])
            }
            Self::UnsupportedCapability {
                server_name,
                capability,
            } => BTreeMap::from([
                ("server".to_string(), server_name.clone()),
                ("capability".to_string(), capability.as_str().to_string()),
            ]),
            Self::LimitExceeded {
                server_name,
                method,
                limit,
                details,
            } => BTreeMap::from([
                ("server".to_string(), server_name.clone()),
                ("method".to_string(), (*method).to_string()),
                ("limit".to_string(), limit.to_string()),
                ("details".to_string(), details.clone()),
            ]),
        }
    }
}

fn protocol_version_error(
    server_name: &str,
    method: &'static str,
    error: McpProtocolVersionError,
) -> McpServerManagerError {
    McpServerManagerError::InvalidResponse {
        server_name: server_name.to_string(),
        method,
        details: error.to_string(),
    }
}

fn negotiate_initialize_protocol_version(
    server_name: &str,
    transport_policy: McpProtocolTransportPolicy,
    requested_protocol_version: &str,
    server_protocol_version: &str,
) -> Result<String, McpServerManagerError> {
    negotiate_mcp_protocol_version(
        transport_policy,
        requested_protocol_version,
        server_protocol_version,
    )
    .map(|negotiation| negotiation.server_protocol_version)
    .map_err(|error| protocol_version_error(server_name, "initialize", error))
}

fn lifecycle_phase_for_method(method: &str) -> McpLifecyclePhase {
    match method {
        "initialize" => McpLifecyclePhase::InitializeHandshake,
        "tools/list" => McpLifecyclePhase::ToolDiscovery,
        "prompts/list" => McpLifecyclePhase::ToolDiscovery,
        "prompts/get" => McpLifecyclePhase::Invocation,
        "resources/list" | "resources/templates/list" => McpLifecyclePhase::ResourceDiscovery,
        "resources/read" | "tools/call" => McpLifecyclePhase::Invocation,
        _ => McpLifecyclePhase::ErrorSurfacing,
    }
}

fn unsupported_server_failed_server(server: &UnsupportedMcpServer) -> McpFailedServer {
    McpFailedServer {
        server_name: server.server_name.clone(),
        phase: McpLifecyclePhase::ServerRegistration,
        error: McpErrorSurface::new(
            McpLifecyclePhase::ServerRegistration,
            Some(server.server_name.clone()),
            server.reason.clone(),
            BTreeMap::from([
                ("transport".to_string(), format!("{:?}", server.transport)),
                ("required".to_string(), server.required.to_string()),
            ]),
            false,
        ),
    }
}

fn degraded_startup_report(
    working_servers: &[String],
    failed_servers: &[McpDiscoveryFailure],
    unsupported_servers: &[UnsupportedMcpServer],
    available_tools: Vec<String>,
) -> Option<McpDegradedReport> {
    let degraded_failed_servers = failed_servers
        .iter()
        .map(|failure| McpFailedServer {
            server_name: failure.server_name.clone(),
            phase: failure.phase,
            error: McpErrorSurface::new(
                failure.phase,
                Some(failure.server_name.clone()),
                failure.error.clone(),
                {
                    let mut context = failure.context.clone();
                    context.insert("required".to_string(), failure.required.to_string());
                    context
                },
                failure.recoverable,
            ),
        })
        .chain(
            unsupported_servers
                .iter()
                .map(unsupported_server_failed_server),
        )
        .collect::<Vec<_>>();

    (!working_servers.is_empty() && !degraded_failed_servers.is_empty()).then(|| {
        McpDegradedReport::new(
            working_servers.to_vec(),
            degraded_failed_servers,
            available_tools,
            Vec::new(),
        )
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolRoute {
    server_name: String,
    raw_name: String,
}

#[derive(Debug)]
struct ManagedMcpServer {
    bootstrap: McpClientBootstrap,
    process: Option<McpStdioProcess>,
    initialized: bool,
    required: bool,
    catalog: McpServerCatalog,
}

struct McpCatalogDiscoveryOutcome {
    catalog: McpServerCatalog,
    degraded_capabilities: Vec<McpCapabilityDegradation>,
}

impl ManagedMcpServer {
    fn new(server_name: impl Into<String>, bootstrap: McpClientBootstrap, required: bool) -> Self {
        Self {
            bootstrap,
            process: None,
            initialized: false,
            required,
            catalog: McpServerCatalog::new(server_name),
        }
    }
}

#[derive(Debug)]
pub struct McpServerManager {
    servers: BTreeMap<String, ManagedMcpServer>,
    unsupported_servers: Vec<UnsupportedMcpServer>,
    heartbeat: BTreeMap<String, McpServerHeartbeat>,
    tool_index: BTreeMap<String, ToolRoute>,
    next_request_id: u64,
}

impl McpServerManager {
    #[must_use]
    pub fn from_runtime_config(config: &RuntimeConfig) -> Self {
        Self::from_servers(config.mcp().servers())
    }

    #[must_use]
    pub fn from_servers(servers: &BTreeMap<String, ScopedMcpServerConfig>) -> Self {
        let mut managed_servers = BTreeMap::new();
        let mut unsupported_servers = Vec::new();
        let mut heartbeat = BTreeMap::new();

        for (server_name, server_config) in servers {
            if matches!(
                server_config.transport(),
                McpTransport::Stdio | McpTransport::Sse
            ) {
                let bootstrap = McpClientBootstrap::from_scoped_config(server_name, server_config);
                let heartbeat_status = match &bootstrap.transport {
                    McpClientTransport::Stdio(transport)
                        if !transport.env.contains_key("CLAWD_MCP_HEARTBEAT_TIMEOUT_MS") =>
                    {
                        McpHeartbeatStatus::NotConfigured
                    }
                    _ => McpHeartbeatStatus::Unknown,
                };
                heartbeat.insert(
                    server_name.clone(),
                    McpServerHeartbeat::new(server_name.clone(), heartbeat_status),
                );
                managed_servers.insert(
                    server_name.clone(),
                    ManagedMcpServer::new(server_name.clone(), bootstrap, server_config.required),
                );
            } else {
                let reason = match &server_config.config {
                    McpServerConfig::Sdk(config) => format!(
                        "SDK transport `{}` is not supported by McpServerManager",
                        config.name
                    ),
                    _ => format!(
                        "transport {:?} is not supported by McpServerManager",
                        server_config.transport()
                    ),
                };
                unsupported_servers.push(UnsupportedMcpServer {
                    server_name: server_name.clone(),
                    transport: server_config.transport(),
                    required: server_config.required,
                    reason,
                });
                heartbeat.insert(
                    server_name.clone(),
                    McpServerHeartbeat::new(server_name.clone(), McpHeartbeatStatus::NotConfigured),
                );
            }
        }

        Self {
            servers: managed_servers,
            unsupported_servers,
            heartbeat,
            tool_index: BTreeMap::new(),
            next_request_id: 1,
        }
    }

    #[must_use]
    pub fn unsupported_servers(&self) -> &[UnsupportedMcpServer] {
        &self.unsupported_servers
    }

    #[must_use]
    pub fn server_names(&self) -> Vec<String> {
        self.servers.keys().cloned().collect()
    }

    #[must_use]
    pub fn heartbeat_report(&self) -> Vec<McpServerHeartbeat> {
        self.heartbeat.values().cloned().collect()
    }

    #[must_use]
    pub fn server_catalogs(&self) -> Vec<McpServerCatalog> {
        self.servers
            .values()
            .map(|server| server.catalog.clone())
            .collect()
    }

    pub async fn discover_catalogs(
        &mut self,
    ) -> Result<Vec<McpServerCatalog>, McpServerManagerError> {
        let server_names = self.servers.keys().cloned().collect::<Vec<_>>();
        let mut catalogs = Vec::new();

        for server_name in server_names {
            match self.discover_catalog_for_server(&server_name).await {
                Ok(catalog) => {
                    self.replace_routes_for_catalog(&catalog);
                    catalogs.push(catalog);
                }
                Err(error) => {
                    self.clear_routes_for_server(&server_name);
                    return Err(error);
                }
            }
        }

        Ok(catalogs)
    }

    pub async fn discover_catalogs_best_effort(&mut self) -> McpCapabilityDiscoveryReport {
        let server_names = self.server_names();
        let mut catalogs = Vec::new();
        let mut tools = Vec::new();
        let mut resources = Vec::new();
        let mut resource_templates = Vec::new();
        let mut prompts = Vec::new();
        let mut working_servers = Vec::new();
        let mut failed_servers = Vec::new();
        let mut degraded_capabilities = Vec::new();

        for server_name in server_names {
            match self
                .discover_catalog_for_server_best_effort(&server_name)
                .await
            {
                Ok(outcome) => {
                    let catalog = outcome.catalog;
                    working_servers.push(server_name.clone());
                    self.replace_routes_for_catalog(&catalog);
                    tools.extend(catalog.tools.clone());
                    resources.extend(catalog.resources.clone());
                    resource_templates.extend(catalog.resource_templates.clone());
                    prompts.extend(catalog.prompts.clone());
                    degraded_capabilities.extend(outcome.degraded_capabilities);
                    catalogs.push(catalog);
                }
                Err(error) => {
                    self.clear_routes_for_server(&server_name);
                    let required = self
                        .servers
                        .get(&server_name)
                        .is_some_and(|server| server.required);
                    failed_servers.push(error.discovery_failure(&server_name, required));
                }
            }
        }

        let degraded_startup = degraded_startup_report(
            &working_servers,
            &failed_servers,
            &self.unsupported_servers,
            tools
                .iter()
                .map(|tool| tool.qualified_name.clone())
                .collect(),
        );

        McpCapabilityDiscoveryReport {
            catalogs,
            tools,
            resources,
            resource_templates,
            prompts,
            failed_servers,
            degraded_capabilities,
            unsupported_servers: self.unsupported_servers.clone(),
            heartbeat: self.heartbeat_report(),
            degraded_startup,
        }
    }

    pub async fn discover_tools(&mut self) -> Result<Vec<ManagedMcpTool>, McpServerManagerError> {
        let server_names = self.servers.keys().cloned().collect::<Vec<_>>();
        let mut discovered_tools = Vec::new();

        for server_name in server_names {
            let server_tools = self.discover_tools_for_server(&server_name).await?;
            self.clear_routes_for_server(&server_name);

            for tool in server_tools {
                self.tool_index.insert(
                    tool.qualified_name.clone(),
                    ToolRoute {
                        server_name: tool.server_name.clone(),
                        raw_name: tool.raw_name.clone(),
                    },
                );
                discovered_tools.push(tool);
            }
        }

        Ok(discovered_tools)
    }

    pub async fn discover_tools_best_effort(&mut self) -> McpToolDiscoveryReport {
        let server_names = self.server_names();
        let mut discovered_tools = Vec::new();
        let mut working_servers = Vec::new();
        let mut failed_servers = Vec::new();

        for server_name in server_names {
            match self.discover_tools_for_server(&server_name).await {
                Ok(server_tools) => {
                    working_servers.push(server_name.clone());
                    self.clear_routes_for_server(&server_name);
                    for tool in server_tools {
                        self.tool_index.insert(
                            tool.qualified_name.clone(),
                            ToolRoute {
                                server_name: tool.server_name.clone(),
                                raw_name: tool.raw_name.clone(),
                            },
                        );
                        discovered_tools.push(tool);
                    }
                }
                Err(error) => {
                    self.clear_routes_for_server(&server_name);
                    let required = self
                        .servers
                        .get(&server_name)
                        .is_some_and(|server| server.required);
                    failed_servers.push(error.discovery_failure(&server_name, required));
                }
            }
        }

        let degraded_startup = degraded_startup_report(
            &working_servers,
            &failed_servers,
            &self.unsupported_servers,
            discovered_tools
                .iter()
                .map(|tool| tool.qualified_name.clone())
                .collect(),
        );

        McpToolDiscoveryReport {
            tools: discovered_tools,
            failed_servers,
            unsupported_servers: self.unsupported_servers.clone(),
            heartbeat: self.heartbeat_report(),
            degraded_startup,
        }
    }

    pub async fn call_tool(
        &mut self,
        qualified_tool_name: &str,
        arguments: Option<JsonValue>,
    ) -> Result<JsonRpcResponse<McpToolCallResult>, McpServerManagerError> {
        let route = self
            .tool_index
            .get(qualified_tool_name)
            .cloned()
            .ok_or_else(|| McpServerManagerError::UnknownTool {
                qualified_name: qualified_tool_name.to_string(),
            })?;

        let timeout_ms = self.tool_call_timeout_ms(&route.server_name)?;

        if let Some(transport) = self.sse_transport(&route.server_name)? {
            let request_id = self.take_request_id_block(3);
            let server_name_owned = route.server_name.clone();
            let raw_name = route.raw_name.clone();
            let response = tokio::task::spawn_blocking(move || {
                call_sse_tool(
                    &server_name_owned,
                    &transport,
                    request_id,
                    raw_name,
                    arguments,
                    timeout_ms,
                )
            })
            .await
            .map_err(|error| McpServerManagerError::InvalidResponse {
                server_name: route.server_name.clone(),
                method: "tools/call",
                details: format!("SSE worker task failed: {error}"),
            })?;
            self.record_heartbeat_result(&route.server_name, &response);
            self.clear_catalog_if_initialize_failed(&route.server_name, &response)?;
            if let Ok(response) = &response {
                Self::validate_json_size(
                    &route.server_name,
                    "tools/call",
                    response,
                    MCP_MAX_RESULT_JSON_BYTES,
                    "tools/call response JSON",
                )?;
            }
            return response;
        }

        self.ensure_server_ready(&route.server_name).await?;
        self.ensure_capability(&route.server_name, McpCapabilityKind::Tools)?;
        self.ping_if_configured(&route.server_name).await?;
        let request_id = self.take_request_id();
        let response =
            {
                let server = self.server_mut(&route.server_name)?;
                let process = server.process.as_mut().ok_or_else(|| {
                    McpServerManagerError::InvalidResponse {
                        server_name: route.server_name.clone(),
                        method: "tools/call",
                        details: "server process missing after initialization".to_string(),
                    }
                })?;
                Self::run_process_request(
                    &route.server_name,
                    "tools/call",
                    timeout_ms,
                    process.call_tool(
                        request_id,
                        McpToolCallParams {
                            name: route.raw_name,
                            arguments,
                            meta: None,
                        },
                    ),
                )
                .await
            };

        if let Err(error) = &response {
            if Self::should_reset_server(error) {
                self.reset_server(&route.server_name).await?;
            }
        } else if let Ok(response) = &response {
            Self::validate_json_size(
                &route.server_name,
                "tools/call",
                response,
                MCP_MAX_RESULT_JSON_BYTES,
                "tools/call response JSON",
            )?;
        }

        response
    }

    pub async fn list_resources(
        &mut self,
        server_name: &str,
    ) -> Result<McpListResourcesResult, McpServerManagerError> {
        let mut attempts = 0;

        loop {
            match self.list_resources_once(server_name).await {
                Ok(resources) => return Ok(resources),
                Err(error) if attempts == 0 && Self::is_retryable_error(&error) => {
                    self.reset_server(server_name).await?;
                    attempts += 1;
                }
                Err(error) => {
                    if Self::should_reset_server(&error) {
                        self.reset_server(server_name).await?;
                    }
                    return Err(error);
                }
            }
        }
    }

    pub async fn read_resource(
        &mut self,
        server_name: &str,
        uri: &str,
    ) -> Result<McpReadResourceResult, McpServerManagerError> {
        let mut attempts = 0;

        loop {
            match self.read_resource_once(server_name, uri).await {
                Ok(resource) => return Ok(resource),
                Err(error) if attempts == 0 && Self::is_retryable_error(&error) => {
                    self.reset_server(server_name).await?;
                    attempts += 1;
                }
                Err(error) => {
                    if Self::should_reset_server(&error) {
                        self.reset_server(server_name).await?;
                    }
                    return Err(error);
                }
            }
        }
    }

    pub async fn list_resource_templates(
        &mut self,
        server_name: &str,
    ) -> Result<McpListResourceTemplatesResult, McpServerManagerError> {
        let mut attempts = 0;

        loop {
            match self.list_resource_templates_once(server_name).await {
                Ok(templates) => return Ok(templates),
                Err(error) if attempts == 0 && Self::is_retryable_error(&error) => {
                    self.reset_server(server_name).await?;
                    attempts += 1;
                }
                Err(error) => {
                    if Self::should_reset_server(&error) {
                        self.reset_server(server_name).await?;
                    }
                    return Err(error);
                }
            }
        }
    }

    pub async fn list_prompts(
        &mut self,
        server_name: &str,
    ) -> Result<McpListPromptsResult, McpServerManagerError> {
        let mut attempts = 0;

        loop {
            match self.list_prompts_once(server_name).await {
                Ok(prompts) => return Ok(prompts),
                Err(error) if attempts == 0 && Self::is_retryable_error(&error) => {
                    self.reset_server(server_name).await?;
                    attempts += 1;
                }
                Err(error) => {
                    if Self::should_reset_server(&error) {
                        self.reset_server(server_name).await?;
                    }
                    return Err(error);
                }
            }
        }
    }

    pub async fn get_prompt(
        &mut self,
        server_name: &str,
        name: &str,
        arguments: Option<JsonValue>,
    ) -> Result<McpGetPromptResult, McpServerManagerError> {
        let mut attempts = 0;

        loop {
            match self
                .get_prompt_once(server_name, name, arguments.clone())
                .await
            {
                Ok(prompt) => return Ok(prompt),
                Err(error) if attempts == 0 && Self::is_retryable_error(&error) => {
                    self.reset_server(server_name).await?;
                    attempts += 1;
                }
                Err(error) => {
                    if Self::should_reset_server(&error) {
                        self.reset_server(server_name).await?;
                    }
                    return Err(error);
                }
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), McpServerManagerError> {
        let server_names = self.servers.keys().cloned().collect::<Vec<_>>();
        for server_name in server_names {
            let server = self.server_mut(&server_name)?;
            if let Some(process) = server.process.as_mut() {
                process.shutdown().await?;
            }
            server.process = None;
            server.initialized = false;
            server.catalog.requested_protocol_version = None;
            server.catalog.negotiated_protocol_version = None;
            server.catalog.protocol_transport_policy = None;
            server.catalog.protocol_configured_preferred = false;
            if let Some(heartbeat) = self.heartbeat.get_mut(&server_name) {
                heartbeat.mark_protocol_state(None, None);
            }
        }
        Ok(())
    }

    fn clear_routes_for_server(&mut self, server_name: &str) {
        self.tool_index
            .retain(|_, route| route.server_name != server_name);
    }

    fn replace_routes_for_catalog(&mut self, catalog: &McpServerCatalog) {
        self.clear_routes_for_server(&catalog.server_name);
        for tool in &catalog.tools {
            self.tool_index.insert(
                tool.qualified_name.clone(),
                ToolRoute {
                    server_name: tool.server_name.clone(),
                    raw_name: tool.raw_name.clone(),
                },
            );
        }
    }

    fn server_catalog(&self, server_name: &str) -> Result<McpServerCatalog, McpServerManagerError> {
        self.servers
            .get(server_name)
            .map(|server| server.catalog.clone())
            .ok_or_else(|| McpServerManagerError::UnknownServer {
                server_name: server_name.to_string(),
            })
    }

    fn server_mut(
        &mut self,
        server_name: &str,
    ) -> Result<&mut ManagedMcpServer, McpServerManagerError> {
        self.servers
            .get_mut(server_name)
            .ok_or_else(|| McpServerManagerError::UnknownServer {
                server_name: server_name.to_string(),
            })
    }

    fn take_request_id(&mut self) -> JsonRpcId {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        JsonRpcId::Number(id)
    }

    fn take_request_id_block(&mut self, count: u64) -> u64 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(count);
        id
    }

    fn tool_call_timeout_ms(&self, server_name: &str) -> Result<u64, McpServerManagerError> {
        let server =
            self.servers
                .get(server_name)
                .ok_or_else(|| McpServerManagerError::UnknownServer {
                    server_name: server_name.to_string(),
                })?;
        match &server.bootstrap.transport {
            McpClientTransport::Stdio(transport) => Ok(transport.resolved_tool_call_timeout_ms()),
            McpClientTransport::Sse(transport) => Ok(transport
                .tool_call_timeout_ms
                .unwrap_or(MCP_LIST_TOOLS_TIMEOUT_MS)),
            other => Err(McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "tools/call",
                details: format!("unsupported MCP transport for stdio manager: {other:?}"),
            }),
        }
    }

    fn record_heartbeat_result<T>(
        &mut self,
        server_name: &str,
        result: &Result<T, McpServerManagerError>,
    ) {
        match result {
            Ok(_) => self.record_heartbeat_success(server_name),
            Err(error) => self.record_heartbeat_failure(server_name, error.to_string()),
        }
    }

    fn record_heartbeat_success(&mut self, server_name: &str) {
        if let Some(heartbeat) = self.heartbeat.get_mut(server_name) {
            heartbeat.mark_success();
        }
    }

    fn record_heartbeat_failure(&mut self, server_name: &str, reason: impl Into<String>) {
        if let Some(heartbeat) = self.heartbeat.get_mut(server_name) {
            heartbeat.mark_failure(reason);
        }
    }

    fn clear_catalog_after_initialize_failure(
        &mut self,
        server_name: &str,
    ) -> Result<(), McpServerManagerError> {
        self.clear_routes_for_server(server_name);
        let server = self.server_mut(server_name)?;
        server.initialized = false;
        server.catalog = McpServerCatalog::new(server_name);
        if let Some(heartbeat) = self.heartbeat.get_mut(server_name) {
            heartbeat.mark_protocol_state(None, None);
        }
        Ok(())
    }

    fn clear_catalog_if_initialize_failed<T>(
        &mut self,
        server_name: &str,
        result: &Result<T, McpServerManagerError>,
    ) -> Result<(), McpServerManagerError> {
        if result
            .as_ref()
            .is_err_and(|error| error.lifecycle_phase() == McpLifecyclePhase::InitializeHandshake)
        {
            self.clear_catalog_after_initialize_failure(server_name)?;
        }
        Ok(())
    }

    fn server_process_exited(&mut self, server_name: &str) -> Result<bool, McpServerManagerError> {
        let server = self.server_mut(server_name)?;
        match server.process.as_mut() {
            Some(process) => Ok(process.has_exited()?),
            None => Ok(false),
        }
    }

    fn sse_transport(
        &self,
        server_name: &str,
    ) -> Result<Option<McpRemoteTransport>, McpServerManagerError> {
        let server =
            self.servers
                .get(server_name)
                .ok_or_else(|| McpServerManagerError::UnknownServer {
                    server_name: server_name.to_string(),
                })?;
        Ok(match &server.bootstrap.transport {
            McpClientTransport::Sse(transport) => Some(transport.clone()),
            _ => None,
        })
    }

    fn ensure_capability(
        &self,
        server_name: &str,
        capability: McpCapabilityKind,
    ) -> Result<(), McpServerManagerError> {
        let server =
            self.servers
                .get(server_name)
                .ok_or_else(|| McpServerManagerError::UnknownServer {
                    server_name: server_name.to_string(),
                })?;
        let capabilities = server.catalog.capabilities.as_ref().ok_or_else(|| {
            McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: capability.method(),
                details: "server capabilities unavailable before initialize".to_string(),
            }
        })?;
        if capabilities.supports(capability) {
            Ok(())
        } else {
            Err(McpServerManagerError::UnsupportedCapability {
                server_name: server_name.to_string(),
                capability,
            })
        }
    }

    fn update_tool_catalog(
        &mut self,
        server_name: &str,
        tools: Vec<ManagedMcpTool>,
    ) -> Result<(), McpServerManagerError> {
        let server = self.server_mut(server_name)?;
        server.catalog.tools = tools;
        server.catalog.tools_complete = true;
        Ok(())
    }

    fn update_initialize_catalog(
        &mut self,
        server_name: &str,
        result: McpInitializeResult,
    ) -> Result<(), McpServerManagerError> {
        let protocol_selection = self
            .servers
            .get(server_name)
            .ok_or_else(|| McpServerManagerError::UnknownServer {
                server_name: server_name.to_string(),
            })?
            .bootstrap
            .select_protocol_version()
            .map_err(|error| protocol_version_error(server_name, "initialize", error))?;
        let negotiated_protocol_version = negotiate_initialize_protocol_version(
            server_name,
            protocol_selection.transport_policy,
            &protocol_selection.requested_protocol_version,
            &result.protocol_version,
        )?;
        let server_info = result.server_info;
        let capabilities = McpServerCapabilities::from_raw(result.capabilities);
        let server = self.server_mut(server_name)?;
        server.catalog.server_info = Some(server_info);
        server.catalog.capabilities = Some(capabilities);
        server.catalog.requested_protocol_version =
            Some(protocol_selection.requested_protocol_version.clone());
        server.catalog.negotiated_protocol_version = Some(negotiated_protocol_version.clone());
        server.catalog.protocol_transport_policy = Some(protocol_selection.transport_policy);
        server.catalog.protocol_configured_preferred = protocol_selection.configured_preferred;
        server.initialized = true;
        if let Some(heartbeat) = self.heartbeat.get_mut(server_name) {
            heartbeat
                .mark_protocol_state(Some(&protocol_selection), Some(negotiated_protocol_version));
        }
        Ok(())
    }

    fn required_for_server(&self, server_name: &str) -> bool {
        self.servers
            .get(server_name)
            .is_some_and(|server| server.required)
    }

    fn capability_degradation_for_error(
        &self,
        server_name: &str,
        capability: McpCapabilityKind,
        method: &'static str,
        error: &McpServerManagerError,
    ) -> McpCapabilityDegradation {
        let mut context = error.error_context();
        context.insert("capability".to_string(), capability.as_str().to_string());
        context.insert("method".to_string(), method.to_string());
        McpCapabilityDegradation {
            server_name: server_name.to_string(),
            phase: lifecycle_phase_for_method(method),
            required: self.required_for_server(server_name),
            capability,
            method,
            reason: error.to_string(),
            context,
        }
    }

    fn clear_resource_catalog(
        &mut self,
        server_name: &str,
        complete: bool,
    ) -> Result<(), McpServerManagerError> {
        let server = self.server_mut(server_name)?;
        server.catalog.resources.clear();
        server.catalog.resources_complete = complete;
        Ok(())
    }

    fn clear_resource_template_catalog(
        &mut self,
        server_name: &str,
        complete: bool,
    ) -> Result<(), McpServerManagerError> {
        let server = self.server_mut(server_name)?;
        server.catalog.resource_templates.clear();
        server.catalog.resource_templates_complete = complete;
        Ok(())
    }

    fn clear_prompt_catalog(
        &mut self,
        server_name: &str,
        complete: bool,
    ) -> Result<(), McpServerManagerError> {
        let server = self.server_mut(server_name)?;
        server.catalog.prompts.clear();
        server.catalog.prompts_complete = complete;
        Ok(())
    }

    fn update_resource_catalog(
        &mut self,
        server_name: &str,
        resources: Vec<McpResource>,
    ) -> Result<(), McpServerManagerError> {
        let managed = resources
            .into_iter()
            .map(|resource| ManagedMcpResource {
                server_name: server_name.to_string(),
                uri: resource.uri.clone(),
                resource,
            })
            .collect();
        let server = self.server_mut(server_name)?;
        server.catalog.resources = managed;
        server.catalog.resources_complete = true;
        Ok(())
    }

    fn update_resource_template_catalog(
        &mut self,
        server_name: &str,
        resource_templates: Vec<McpResourceTemplate>,
    ) -> Result<(), McpServerManagerError> {
        let managed = resource_templates
            .into_iter()
            .map(|resource_template| ManagedMcpResourceTemplate {
                server_name: server_name.to_string(),
                uri_template: resource_template.uri_template.clone(),
                resource_template,
            })
            .collect();
        let server = self.server_mut(server_name)?;
        server.catalog.resource_templates = managed;
        server.catalog.resource_templates_complete = true;
        Ok(())
    }

    fn update_prompt_catalog(
        &mut self,
        server_name: &str,
        prompts: Vec<McpPrompt>,
    ) -> Result<(), McpServerManagerError> {
        let managed = prompts
            .into_iter()
            .map(|prompt| ManagedMcpPrompt {
                server_name: server_name.to_string(),
                name: prompt.name.clone(),
                prompt,
            })
            .collect();
        let server = self.server_mut(server_name)?;
        server.catalog.prompts = managed;
        server.catalog.prompts_complete = true;
        Ok(())
    }

    fn update_sse_catalog_from_discovery(
        &mut self,
        server_name: &str,
        discovery: McpSseCatalogDiscovery,
    ) -> Result<McpCatalogDiscoveryOutcome, McpServerManagerError> {
        let protocol_selection = self
            .servers
            .get(server_name)
            .ok_or_else(|| McpServerManagerError::UnknownServer {
                server_name: server_name.to_string(),
            })?
            .bootstrap
            .select_protocol_version()
            .map_err(|error| protocol_version_error(server_name, "initialize", error))?;
        let negotiated_protocol_version = negotiate_initialize_protocol_version(
            server_name,
            protocol_selection.transport_policy,
            &protocol_selection.requested_protocol_version,
            &discovery.initialize_result.protocol_version,
        )?;
        let capabilities =
            McpServerCapabilities::from_raw(discovery.initialize_result.capabilities);
        let tools = discovery.tools;
        let resources = discovery
            .resources
            .into_iter()
            .map(|resource| ManagedMcpResource {
                server_name: server_name.to_string(),
                uri: resource.uri.clone(),
                resource,
            })
            .collect::<Vec<_>>();
        let resource_templates = discovery
            .resource_templates
            .into_iter()
            .map(|resource_template| ManagedMcpResourceTemplate {
                server_name: server_name.to_string(),
                uri_template: resource_template.uri_template.clone(),
                resource_template,
            })
            .collect::<Vec<_>>();
        let prompts = discovery
            .prompts
            .into_iter()
            .map(|prompt| ManagedMcpPrompt {
                server_name: server_name.to_string(),
                name: prompt.name.clone(),
                prompt,
            })
            .collect::<Vec<_>>();
        let degraded_capabilities = discovery.degraded_capabilities;
        let catalog = {
            let server = self.server_mut(server_name)?;
            server.catalog.server_info = Some(discovery.initialize_result.server_info);
            server.catalog.capabilities = Some(capabilities);
            server.catalog.requested_protocol_version =
                Some(protocol_selection.requested_protocol_version.clone());
            server.catalog.negotiated_protocol_version = Some(negotiated_protocol_version.clone());
            server.catalog.protocol_transport_policy = Some(protocol_selection.transport_policy);
            server.catalog.protocol_configured_preferred = protocol_selection.configured_preferred;
            server.catalog.tools = tools;
            server.catalog.resources = resources;
            server.catalog.resource_templates = resource_templates;
            server.catalog.prompts = prompts;
            server.catalog.tools_complete = discovery.tools_complete;
            server.catalog.resources_complete = discovery.resources_complete;
            server.catalog.resource_templates_complete = discovery.resource_templates_complete;
            server.catalog.prompts_complete = discovery.prompts_complete;
            server.initialized = true;
            server.catalog.clone()
        };
        if let Some(heartbeat) = self.heartbeat.get_mut(server_name) {
            heartbeat.mark_success_with_protocol_version(
                &protocol_selection,
                Some(negotiated_protocol_version),
            );
        }
        Ok(McpCatalogDiscoveryOutcome {
            catalog,
            degraded_capabilities,
        })
    }

    async fn ensure_prompt_catalog(
        &mut self,
        server_name: &str,
    ) -> Result<(), McpServerManagerError> {
        let complete = self
            .servers
            .get(server_name)
            .ok_or_else(|| McpServerManagerError::UnknownServer {
                server_name: server_name.to_string(),
            })?
            .catalog
            .prompts_complete;
        if !complete {
            let _ = self.list_prompts(server_name).await?;
        }
        Ok(())
    }

    fn ensure_prompt_known(
        &self,
        server_name: &str,
        name: &str,
    ) -> Result<(), McpServerManagerError> {
        let server =
            self.servers
                .get(server_name)
                .ok_or_else(|| McpServerManagerError::UnknownServer {
                    server_name: server_name.to_string(),
                })?;
        if server
            .catalog
            .prompts
            .iter()
            .any(|prompt| prompt.name == name)
        {
            Ok(())
        } else {
            Err(McpServerManagerError::UnknownPrompt {
                server_name: server_name.to_string(),
                name: name.to_string(),
            })
        }
    }

    fn validate_json_size<T: Serialize>(
        server_name: &str,
        method: &'static str,
        value: &T,
        limit: usize,
        details: impl Into<String>,
    ) -> Result<(), McpServerManagerError> {
        let bytes = Self::json_size(server_name, method, value)?;
        if bytes.len() > limit {
            Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method,
                limit,
                details: format!("{} ({} bytes)", details.into(), bytes.len()),
            })
        } else {
            Ok(())
        }
    }

    fn json_size<T: Serialize>(
        server_name: &str,
        method: &'static str,
        value: &T,
    ) -> Result<Vec<u8>, McpServerManagerError> {
        serde_json::to_vec(value).map_err(|error| McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method,
            details: format!("failed to measure JSON payload: {error}"),
        })
    }

    fn validate_aggregate_json_size(
        server_name: &str,
        method: &'static str,
        total_bytes: usize,
    ) -> Result<(), McpServerManagerError> {
        if total_bytes > MCP_MAX_RESULT_JSON_BYTES {
            Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method,
                limit: MCP_MAX_RESULT_JSON_BYTES,
                details: format!("paginated aggregate reached {total_bytes} bytes"),
            })
        } else {
            Ok(())
        }
    }

    fn duplicate_catalog_item(
        server_name: &str,
        method: &'static str,
        field: &str,
        value: &str,
    ) -> McpServerManagerError {
        McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method,
            details: format!("duplicate {field} `{value}` in catalog"),
        }
    }

    fn validate_next_cursor(
        server_name: &str,
        method: &'static str,
        next_cursor: String,
        seen_cursors: &mut BTreeSet<String>,
    ) -> Result<String, McpServerManagerError> {
        if next_cursor.is_empty() {
            return Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method,
                limit: MCP_MAX_CURSOR_BYTES,
                details: "server returned an empty pagination cursor".to_string(),
            });
        }
        if next_cursor.len() > MCP_MAX_CURSOR_BYTES {
            return Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method,
                limit: MCP_MAX_CURSOR_BYTES,
                details: format!("pagination cursor was {} bytes", next_cursor.len()),
            });
        }
        if !seen_cursors.insert(next_cursor.clone()) {
            return Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method,
                limit: MCP_MAX_PAGINATION_PAGES,
                details: "server repeated a pagination cursor".to_string(),
            });
        }
        Ok(next_cursor)
    }

    fn validate_page_limit(
        server_name: &str,
        method: &'static str,
        page_count: usize,
    ) -> Result<(), McpServerManagerError> {
        if page_count >= MCP_MAX_PAGINATION_PAGES {
            Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method,
                limit: MCP_MAX_PAGINATION_PAGES,
                details: "pagination page limit reached".to_string(),
            })
        } else {
            Ok(())
        }
    }

    fn validate_total_items(
        server_name: &str,
        method: &'static str,
        total: usize,
    ) -> Result<(), McpServerManagerError> {
        if total > MCP_MAX_PAGINATION_ITEMS {
            Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method,
                limit: MCP_MAX_PAGINATION_ITEMS,
                details: format!("server returned {total} catalog items"),
            })
        } else {
            Ok(())
        }
    }

    fn is_method_not_found(error: &McpServerManagerError, method: &'static str) -> bool {
        matches!(
            error,
            McpServerManagerError::JsonRpc {
                method: error_method,
                error,
                ..
            } if *error_method == method && error.code == -32601
        )
    }

    async fn discover_catalog_for_server(
        &mut self,
        server_name: &str,
    ) -> Result<McpServerCatalog, McpServerManagerError> {
        if let Some(transport) = self.sse_transport(server_name)? {
            return Ok(self
                .discover_sse_catalog_for_server_once(
                    server_name,
                    transport,
                    SseDiscoveryMode::Strict,
                )
                .await?
                .catalog);
        }

        self.ensure_server_ready(server_name).await?;
        let capabilities = self
            .server_catalog(server_name)?
            .capabilities
            .clone()
            .unwrap_or_default();

        if capabilities.tools {
            let _ = self.discover_tools_for_server_once(server_name).await?;
        } else {
            self.clear_routes_for_server(server_name);
        }

        if capabilities.resources {
            let _ = self.list_resources(server_name).await?;
            match self.list_resource_templates(server_name).await {
                Ok(_) => {}
                Err(error) if Self::is_method_not_found(&error, "resources/templates/list") => {
                    let server = self.server_mut(server_name)?;
                    server.catalog.resource_templates.clear();
                    server.catalog.resource_templates_complete = true;
                }
                Err(error) => return Err(error),
            }
        }

        if capabilities.prompts {
            let _ = self.list_prompts(server_name).await?;
        }

        self.server_catalog(server_name)
    }

    async fn discover_catalog_for_server_best_effort(
        &mut self,
        server_name: &str,
    ) -> Result<McpCatalogDiscoveryOutcome, McpServerManagerError> {
        if let Some(transport) = self.sse_transport(server_name)? {
            return self
                .discover_sse_catalog_for_server_once(
                    server_name,
                    transport,
                    SseDiscoveryMode::BestEffort,
                )
                .await;
        }

        self.ensure_server_ready(server_name).await?;
        let capabilities = self
            .server_catalog(server_name)?
            .capabilities
            .clone()
            .unwrap_or_default();

        if capabilities.tools {
            let _ = self.discover_tools_for_server_once(server_name).await?;
        } else {
            self.clear_routes_for_server(server_name);
            self.update_tool_catalog(server_name, Vec::new())?;
        }

        let mut degraded_capabilities = Vec::new();

        if capabilities.resources {
            match self.list_resources(server_name).await {
                Ok(_) => match self.list_resource_templates(server_name).await {
                    Ok(_) => {}
                    Err(error) if Self::is_method_not_found(&error, "resources/templates/list") => {
                        self.clear_resource_template_catalog(server_name, true)?;
                    }
                    Err(error) => {
                        self.clear_resource_template_catalog(server_name, false)?;
                        degraded_capabilities.push(self.capability_degradation_for_error(
                            server_name,
                            McpCapabilityKind::ResourceTemplates,
                            "resources/templates/list",
                            &error,
                        ));
                    }
                },
                Err(error) => {
                    self.clear_resource_catalog(server_name, false)?;
                    self.clear_resource_template_catalog(server_name, false)?;
                    degraded_capabilities.push(self.capability_degradation_for_error(
                        server_name,
                        McpCapabilityKind::Resources,
                        "resources/list",
                        &error,
                    ));
                }
            }
        } else {
            self.clear_resource_catalog(server_name, true)?;
            self.clear_resource_template_catalog(server_name, true)?;
        }

        if capabilities.prompts {
            match self.list_prompts(server_name).await {
                Ok(_) => {}
                Err(error) => {
                    self.clear_prompt_catalog(server_name, false)?;
                    degraded_capabilities.push(self.capability_degradation_for_error(
                        server_name,
                        McpCapabilityKind::Prompts,
                        "prompts/list",
                        &error,
                    ));
                }
            }
        } else {
            self.clear_prompt_catalog(server_name, true)?;
        }

        Ok(McpCatalogDiscoveryOutcome {
            catalog: self.server_catalog(server_name)?,
            degraded_capabilities,
        })
    }

    async fn discover_tools_for_server(
        &mut self,
        server_name: &str,
    ) -> Result<Vec<ManagedMcpTool>, McpServerManagerError> {
        let mut attempts = 0;

        loop {
            match self.discover_tools_for_server_once(server_name).await {
                Ok(tools) => return Ok(tools),
                Err(error) if attempts == 0 && Self::is_retryable_error(&error) => {
                    self.record_heartbeat_failure(server_name, error.to_string());
                    self.reset_server(server_name).await?;
                    attempts += 1;
                }
                Err(error) => {
                    self.record_heartbeat_failure(server_name, error.to_string());
                    if Self::should_reset_server(&error) {
                        self.reset_server(server_name).await?;
                    }
                    return Err(error);
                }
            }
        }
    }

    async fn discover_tools_for_server_once(
        &mut self,
        server_name: &str,
    ) -> Result<Vec<ManagedMcpTool>, McpServerManagerError> {
        if let Some(transport) = self.sse_transport(server_name)? {
            return self
                .discover_sse_tools_for_server_once(server_name, transport)
                .await;
        }

        self.ensure_server_ready(server_name).await?;
        self.ensure_capability(server_name, McpCapabilityKind::Tools)?;
        self.ping_if_configured(server_name).await?;

        let mut discovered_tools = Vec::new();
        let mut cursor = None;
        let mut page_count = 0;
        let mut total_json_bytes = 0_usize;
        let mut seen_cursors = BTreeSet::new();
        let mut seen_names = BTreeSet::new();
        loop {
            Self::validate_page_limit(server_name, "tools/list", page_count)?;
            page_count += 1;
            let request_id = self.take_request_id();
            let response = {
                let server = self.server_mut(server_name)?;
                let process = server.process.as_mut().ok_or_else(|| {
                    McpServerManagerError::InvalidResponse {
                        server_name: server_name.to_string(),
                        method: "tools/list",
                        details: "server process missing after initialization".to_string(),
                    }
                })?;
                Self::run_process_request(
                    server_name,
                    "tools/list",
                    MCP_LIST_TOOLS_TIMEOUT_MS,
                    process.list_tools(
                        request_id,
                        Some(McpListToolsParams {
                            cursor: cursor.clone(),
                        }),
                    ),
                )
                .await?
            };

            if let Some(error) = response.error {
                return Err(McpServerManagerError::JsonRpc {
                    server_name: server_name.to_string(),
                    method: "tools/list",
                    error,
                });
            }

            let result = response
                .result
                .ok_or_else(|| McpServerManagerError::InvalidResponse {
                    server_name: server_name.to_string(),
                    method: "tools/list",
                    details: "missing result payload".to_string(),
                })?;

            let page_json = Self::json_size(server_name, "tools/list", &result)?;
            Self::validate_json_size(
                server_name,
                "tools/list",
                &result,
                MCP_MAX_RESULT_JSON_BYTES,
                "tools/list page JSON",
            )?;
            total_json_bytes = total_json_bytes.saturating_add(page_json.len());
            Self::validate_aggregate_json_size(server_name, "tools/list", total_json_bytes)?;

            for tool in &result.tools {
                Self::validate_json_size(
                    server_name,
                    "tools/list",
                    tool,
                    MCP_MAX_CATALOG_ITEM_JSON_BYTES,
                    "tool catalog item JSON",
                )?;
                if !seen_names.insert(tool.name.clone()) {
                    return Err(Self::duplicate_catalog_item(
                        server_name,
                        "tools/list",
                        "tool name",
                        &tool.name,
                    ));
                }
            }

            for tool in result.tools {
                let qualified_name = mcp_tool_name(server_name, &tool.name);
                discovered_tools.push(ManagedMcpTool {
                    server_name: server_name.to_string(),
                    qualified_name,
                    raw_name: tool.name.clone(),
                    tool,
                });
            }
            Self::validate_total_items(server_name, "tools/list", discovered_tools.len())?;

            match result.next_cursor {
                Some(next_cursor) => {
                    cursor = Some(Self::validate_next_cursor(
                        server_name,
                        "tools/list",
                        next_cursor,
                        &mut seen_cursors,
                    )?);
                }
                None => break,
            }
        }

        Self::validate_json_size(
            server_name,
            "tools/list",
            &discovered_tools,
            MCP_MAX_RESULT_JSON_BYTES,
            "tools/list aggregate JSON",
        )?;
        self.update_tool_catalog(server_name, discovered_tools.clone())?;
        Ok(discovered_tools)
    }

    async fn discover_sse_tools_for_server_once(
        &mut self,
        server_name: &str,
        transport: McpRemoteTransport,
    ) -> Result<Vec<ManagedMcpTool>, McpServerManagerError> {
        let request_id = self.take_request_id_block((MCP_MAX_PAGINATION_PAGES + 2) as u64);
        let server_name_owned = server_name.to_string();
        let discovery = tokio::task::spawn_blocking(move || {
            discover_sse_tools(&server_name_owned, &transport, request_id)
        })
        .await
        .map_err(|error| McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method: "sse",
            details: format!("SSE worker task failed: {error}"),
        })?;
        self.record_heartbeat_result(server_name, &discovery);
        self.clear_catalog_if_initialize_failed(server_name, &discovery)?;
        let discovery = discovery?;
        self.update_initialize_catalog(server_name, discovery.initialize_result)?;
        self.update_tool_catalog(server_name, discovery.tools.clone())?;
        Ok(discovery.tools)
    }

    async fn discover_sse_catalog_for_server_once(
        &mut self,
        server_name: &str,
        transport: McpRemoteTransport,
        mode: SseDiscoveryMode,
    ) -> Result<McpCatalogDiscoveryOutcome, McpServerManagerError> {
        let request_id = self.take_request_id_block(2 + (MCP_MAX_PAGINATION_PAGES as u64 * 4));
        let server_name_owned = server_name.to_string();
        let required = self.required_for_server(server_name);
        let discovery = tokio::task::spawn_blocking(move || {
            discover_sse_catalog(&server_name_owned, required, &transport, request_id, mode)
        })
        .await
        .map_err(|error| McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method: "sse",
            details: format!("SSE worker task failed: {error}"),
        })?;
        self.record_heartbeat_result(server_name, &discovery);
        self.clear_catalog_if_initialize_failed(server_name, &discovery)?;
        let discovery = discovery?;
        self.update_sse_catalog_from_discovery(server_name, discovery)
    }

    async fn list_resources_once(
        &mut self,
        server_name: &str,
    ) -> Result<McpListResourcesResult, McpServerManagerError> {
        if let Some(transport) = self.sse_transport(server_name)? {
            let request_id = self.take_request_id_block((MCP_MAX_PAGINATION_PAGES + 2) as u64);
            let server_name_owned = server_name.to_string();
            let response = tokio::task::spawn_blocking(move || {
                list_sse_resources(&server_name_owned, &transport, request_id)
            })
            .await
            .map_err(|error| McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "resources/list",
                details: format!("SSE worker task failed: {error}"),
            })?;
            self.record_heartbeat_result(server_name, &response);
            self.clear_catalog_if_initialize_failed(server_name, &response)?;
            let response = response?;
            self.update_initialize_catalog(server_name, response.initialize_result)?;
            self.update_resource_catalog(server_name, response.result.resources.clone())?;
            return Ok(response.result);
        }

        self.ensure_server_ready(server_name).await?;
        self.ensure_capability(server_name, McpCapabilityKind::Resources)?;

        let mut resources = Vec::new();
        let mut cursor = None;
        let mut page_count = 0;
        let mut total_json_bytes = 0_usize;
        let mut seen_cursors = BTreeSet::new();
        let mut seen_uris = BTreeSet::new();
        loop {
            Self::validate_page_limit(server_name, "resources/list", page_count)?;
            page_count += 1;
            let request_id = self.take_request_id();
            let response = {
                let server = self.server_mut(server_name)?;
                let process = server.process.as_mut().ok_or_else(|| {
                    McpServerManagerError::InvalidResponse {
                        server_name: server_name.to_string(),
                        method: "resources/list",
                        details: "server process missing after initialization".to_string(),
                    }
                })?;
                Self::run_process_request(
                    server_name,
                    "resources/list",
                    MCP_LIST_TOOLS_TIMEOUT_MS,
                    process.list_resources(
                        request_id,
                        Some(McpListResourcesParams {
                            cursor: cursor.clone(),
                        }),
                    ),
                )
                .await?
            };

            if let Some(error) = response.error {
                return Err(McpServerManagerError::JsonRpc {
                    server_name: server_name.to_string(),
                    method: "resources/list",
                    error,
                });
            }

            let result = response
                .result
                .ok_or_else(|| McpServerManagerError::InvalidResponse {
                    server_name: server_name.to_string(),
                    method: "resources/list",
                    details: "missing result payload".to_string(),
                })?;

            let page_json = Self::json_size(server_name, "resources/list", &result)?;
            Self::validate_json_size(
                server_name,
                "resources/list",
                &result,
                MCP_MAX_RESULT_JSON_BYTES,
                "resources/list page JSON",
            )?;
            total_json_bytes = total_json_bytes.saturating_add(page_json.len());
            Self::validate_aggregate_json_size(server_name, "resources/list", total_json_bytes)?;

            for resource in &result.resources {
                Self::validate_json_size(
                    server_name,
                    "resources/list",
                    resource,
                    MCP_MAX_CATALOG_ITEM_JSON_BYTES,
                    "resource catalog item JSON",
                )?;
                if !seen_uris.insert(resource.uri.clone()) {
                    return Err(Self::duplicate_catalog_item(
                        server_name,
                        "resources/list",
                        "resource uri",
                        &resource.uri,
                    ));
                }
            }

            resources.extend(result.resources);
            Self::validate_total_items(server_name, "resources/list", resources.len())?;

            match result.next_cursor {
                Some(next_cursor) => {
                    cursor = Some(Self::validate_next_cursor(
                        server_name,
                        "resources/list",
                        next_cursor,
                        &mut seen_cursors,
                    )?);
                }
                None => break,
            }
        }

        let result = McpListResourcesResult {
            resources,
            next_cursor: None,
        };
        Self::validate_json_size(
            server_name,
            "resources/list",
            &result,
            MCP_MAX_RESULT_JSON_BYTES,
            "resources/list aggregate JSON",
        )?;
        self.update_resource_catalog(server_name, result.resources.clone())?;
        Ok(result)
    }

    async fn list_resource_templates_once(
        &mut self,
        server_name: &str,
    ) -> Result<McpListResourceTemplatesResult, McpServerManagerError> {
        if let Some(transport) = self.sse_transport(server_name)? {
            let request_id = self.take_request_id_block((MCP_MAX_PAGINATION_PAGES + 2) as u64);
            let server_name_owned = server_name.to_string();
            let response = tokio::task::spawn_blocking(move || {
                list_sse_resource_templates(&server_name_owned, &transport, request_id)
            })
            .await
            .map_err(|error| McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "resources/templates/list",
                details: format!("SSE worker task failed: {error}"),
            })?;
            self.record_heartbeat_result(server_name, &response);
            self.clear_catalog_if_initialize_failed(server_name, &response)?;
            let response = response?;
            self.update_initialize_catalog(server_name, response.initialize_result)?;
            self.update_resource_template_catalog(
                server_name,
                response.result.resource_templates.clone(),
            )?;
            return Ok(response.result);
        }

        self.ensure_server_ready(server_name).await?;
        self.ensure_capability(server_name, McpCapabilityKind::ResourceTemplates)?;

        let mut resource_templates = Vec::new();
        let mut cursor = None;
        let mut page_count = 0;
        let mut total_json_bytes = 0_usize;
        let mut seen_cursors = BTreeSet::new();
        let mut seen_templates = BTreeSet::new();
        loop {
            Self::validate_page_limit(server_name, "resources/templates/list", page_count)?;
            page_count += 1;
            let request_id = self.take_request_id();
            let response = {
                let server = self.server_mut(server_name)?;
                let process = server.process.as_mut().ok_or_else(|| {
                    McpServerManagerError::InvalidResponse {
                        server_name: server_name.to_string(),
                        method: "resources/templates/list",
                        details: "server process missing after initialization".to_string(),
                    }
                })?;
                Self::run_process_request(
                    server_name,
                    "resources/templates/list",
                    MCP_LIST_TOOLS_TIMEOUT_MS,
                    process.list_resource_templates(
                        request_id,
                        Some(McpListResourceTemplatesParams {
                            cursor: cursor.clone(),
                        }),
                    ),
                )
                .await?
            };

            if let Some(error) = response.error {
                return Err(McpServerManagerError::JsonRpc {
                    server_name: server_name.to_string(),
                    method: "resources/templates/list",
                    error,
                });
            }

            let result = response
                .result
                .ok_or_else(|| McpServerManagerError::InvalidResponse {
                    server_name: server_name.to_string(),
                    method: "resources/templates/list",
                    details: "missing result payload".to_string(),
                })?;

            let page_json = Self::json_size(server_name, "resources/templates/list", &result)?;
            Self::validate_json_size(
                server_name,
                "resources/templates/list",
                &result,
                MCP_MAX_RESULT_JSON_BYTES,
                "resources/templates/list page JSON",
            )?;
            total_json_bytes = total_json_bytes.saturating_add(page_json.len());
            Self::validate_aggregate_json_size(
                server_name,
                "resources/templates/list",
                total_json_bytes,
            )?;

            for template in &result.resource_templates {
                Self::validate_json_size(
                    server_name,
                    "resources/templates/list",
                    template,
                    MCP_MAX_CATALOG_ITEM_JSON_BYTES,
                    "resource template catalog item JSON",
                )?;
                if !seen_templates.insert(template.uri_template.clone()) {
                    return Err(Self::duplicate_catalog_item(
                        server_name,
                        "resources/templates/list",
                        "resource template uriTemplate",
                        &template.uri_template,
                    ));
                }
            }

            resource_templates.extend(result.resource_templates);
            Self::validate_total_items(
                server_name,
                "resources/templates/list",
                resource_templates.len(),
            )?;

            match result.next_cursor {
                Some(next_cursor) => {
                    cursor = Some(Self::validate_next_cursor(
                        server_name,
                        "resources/templates/list",
                        next_cursor,
                        &mut seen_cursors,
                    )?);
                }
                None => break,
            }
        }

        let result = McpListResourceTemplatesResult {
            resource_templates,
            next_cursor: None,
        };
        Self::validate_json_size(
            server_name,
            "resources/templates/list",
            &result,
            MCP_MAX_RESULT_JSON_BYTES,
            "resources/templates/list aggregate JSON",
        )?;
        self.update_resource_template_catalog(server_name, result.resource_templates.clone())?;
        Ok(result)
    }

    async fn read_resource_once(
        &mut self,
        server_name: &str,
        uri: &str,
    ) -> Result<McpReadResourceResult, McpServerManagerError> {
        if let Some(transport) = self.sse_transport(server_name)? {
            let request_id = self.take_request_id_block(3);
            let server_name_owned = server_name.to_string();
            let uri = uri.to_string();
            let response = tokio::task::spawn_blocking(move || {
                read_sse_resource(&server_name_owned, &transport, request_id, uri)
            })
            .await
            .map_err(|error| McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "resources/read",
                details: format!("SSE worker task failed: {error}"),
            })?;
            self.record_heartbeat_result(server_name, &response);
            self.clear_catalog_if_initialize_failed(server_name, &response)?;
            let response = response?;
            self.update_initialize_catalog(server_name, response.initialize_result)?;
            return Ok(response.result);
        }

        self.ensure_server_ready(server_name).await?;
        self.ensure_capability(server_name, McpCapabilityKind::Resources)?;

        let request_id = self.take_request_id();
        let response =
            {
                let server = self.server_mut(server_name)?;
                let process = server.process.as_mut().ok_or_else(|| {
                    McpServerManagerError::InvalidResponse {
                        server_name: server_name.to_string(),
                        method: "resources/read",
                        details: "server process missing after initialization".to_string(),
                    }
                })?;
                Self::run_process_request(
                    server_name,
                    "resources/read",
                    MCP_LIST_TOOLS_TIMEOUT_MS,
                    process.read_resource(
                        request_id,
                        McpReadResourceParams {
                            uri: uri.to_string(),
                        },
                    ),
                )
                .await?
            };

        if let Some(error) = response.error {
            return Err(McpServerManagerError::JsonRpc {
                server_name: server_name.to_string(),
                method: "resources/read",
                error,
            });
        }

        let result = response
            .result
            .ok_or_else(|| McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "resources/read",
                details: "missing result payload".to_string(),
            })?;
        if result.contents.len() > MCP_MAX_RESOURCE_CONTENTS {
            return Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method: "resources/read",
                limit: MCP_MAX_RESOURCE_CONTENTS,
                details: format!(
                    "server returned {} resource contents",
                    result.contents.len()
                ),
            });
        }
        Self::validate_json_size(
            server_name,
            "resources/read",
            &result,
            MCP_MAX_RESULT_JSON_BYTES,
            "resources/read result JSON",
        )?;
        for content in &result.contents {
            Self::validate_json_size(
                server_name,
                "resources/read",
                content,
                MCP_MAX_CATALOG_ITEM_JSON_BYTES,
                "resource content JSON",
            )?;
        }
        Ok(result)
    }

    async fn list_prompts_once(
        &mut self,
        server_name: &str,
    ) -> Result<McpListPromptsResult, McpServerManagerError> {
        if let Some(transport) = self.sse_transport(server_name)? {
            let request_id = self.take_request_id_block((MCP_MAX_PAGINATION_PAGES + 2) as u64);
            let server_name_owned = server_name.to_string();
            let response = tokio::task::spawn_blocking(move || {
                list_sse_prompts(&server_name_owned, &transport, request_id)
            })
            .await
            .map_err(|error| McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "prompts/list",
                details: format!("SSE worker task failed: {error}"),
            })?;
            self.record_heartbeat_result(server_name, &response);
            self.clear_catalog_if_initialize_failed(server_name, &response)?;
            let response = response?;
            self.update_initialize_catalog(server_name, response.initialize_result)?;
            self.update_prompt_catalog(server_name, response.result.prompts.clone())?;
            return Ok(response.result);
        }

        self.ensure_server_ready(server_name).await?;
        self.ensure_capability(server_name, McpCapabilityKind::Prompts)?;

        let mut prompts = Vec::new();
        let mut cursor = None;
        let mut page_count = 0;
        let mut total_json_bytes = 0_usize;
        let mut seen_cursors = BTreeSet::new();
        let mut seen_names = BTreeSet::new();
        loop {
            Self::validate_page_limit(server_name, "prompts/list", page_count)?;
            page_count += 1;
            let request_id = self.take_request_id();
            let response = {
                let server = self.server_mut(server_name)?;
                let process = server.process.as_mut().ok_or_else(|| {
                    McpServerManagerError::InvalidResponse {
                        server_name: server_name.to_string(),
                        method: "prompts/list",
                        details: "server process missing after initialization".to_string(),
                    }
                })?;
                Self::run_process_request(
                    server_name,
                    "prompts/list",
                    MCP_LIST_TOOLS_TIMEOUT_MS,
                    process.list_prompts(
                        request_id,
                        Some(McpListPromptsParams {
                            cursor: cursor.clone(),
                        }),
                    ),
                )
                .await?
            };

            if let Some(error) = response.error {
                return Err(McpServerManagerError::JsonRpc {
                    server_name: server_name.to_string(),
                    method: "prompts/list",
                    error,
                });
            }

            let result = response
                .result
                .ok_or_else(|| McpServerManagerError::InvalidResponse {
                    server_name: server_name.to_string(),
                    method: "prompts/list",
                    details: "missing result payload".to_string(),
                })?;

            let page_json = Self::json_size(server_name, "prompts/list", &result)?;
            Self::validate_json_size(
                server_name,
                "prompts/list",
                &result,
                MCP_MAX_RESULT_JSON_BYTES,
                "prompts/list page JSON",
            )?;
            total_json_bytes = total_json_bytes.saturating_add(page_json.len());
            Self::validate_aggregate_json_size(server_name, "prompts/list", total_json_bytes)?;

            for prompt in &result.prompts {
                Self::validate_json_size(
                    server_name,
                    "prompts/list",
                    prompt,
                    MCP_MAX_CATALOG_ITEM_JSON_BYTES,
                    "prompt catalog item JSON",
                )?;
                if !seen_names.insert(prompt.name.clone()) {
                    return Err(Self::duplicate_catalog_item(
                        server_name,
                        "prompts/list",
                        "prompt name",
                        &prompt.name,
                    ));
                }
            }

            prompts.extend(result.prompts);
            Self::validate_total_items(server_name, "prompts/list", prompts.len())?;

            match result.next_cursor {
                Some(next_cursor) => {
                    cursor = Some(Self::validate_next_cursor(
                        server_name,
                        "prompts/list",
                        next_cursor,
                        &mut seen_cursors,
                    )?);
                }
                None => break,
            }
        }

        let result = McpListPromptsResult {
            prompts,
            next_cursor: None,
        };
        Self::validate_json_size(
            server_name,
            "prompts/list",
            &result,
            MCP_MAX_RESULT_JSON_BYTES,
            "prompts/list aggregate JSON",
        )?;
        self.update_prompt_catalog(server_name, result.prompts.clone())?;
        Ok(result)
    }

    async fn get_prompt_once(
        &mut self,
        server_name: &str,
        name: &str,
        arguments: Option<JsonValue>,
    ) -> Result<McpGetPromptResult, McpServerManagerError> {
        if let Some(transport) = self.sse_transport(server_name)? {
            self.ensure_prompt_catalog(server_name).await?;
            self.ensure_prompt_known(server_name, name)?;
            let request_id = self.take_request_id_block(3);
            let server_name_owned = server_name.to_string();
            let name = name.to_string();
            let response = tokio::task::spawn_blocking(move || {
                get_sse_prompt(&server_name_owned, &transport, request_id, name, arguments)
            })
            .await
            .map_err(|error| McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "prompts/get",
                details: format!("SSE worker task failed: {error}"),
            })?;
            self.record_heartbeat_result(server_name, &response);
            self.clear_catalog_if_initialize_failed(server_name, &response)?;
            let response = response?;
            self.update_initialize_catalog(server_name, response.initialize_result)?;
            return Ok(response.result);
        }

        self.ensure_server_ready(server_name).await?;
        self.ensure_capability(server_name, McpCapabilityKind::Prompts)?;
        self.ensure_prompt_catalog(server_name).await?;
        self.ensure_prompt_known(server_name, name)?;

        let request_id = self.take_request_id();
        let timeout_ms = self.tool_call_timeout_ms(server_name)?;
        let response =
            {
                let server = self.server_mut(server_name)?;
                let process = server.process.as_mut().ok_or_else(|| {
                    McpServerManagerError::InvalidResponse {
                        server_name: server_name.to_string(),
                        method: "prompts/get",
                        details: "server process missing after initialization".to_string(),
                    }
                })?;
                Self::run_process_request(
                    server_name,
                    "prompts/get",
                    timeout_ms,
                    process.get_prompt(
                        request_id,
                        Some(McpGetPromptParams {
                            name: name.to_string(),
                            arguments,
                        }),
                    ),
                )
                .await?
            };

        if let Some(error) = response.error {
            return Err(McpServerManagerError::JsonRpc {
                server_name: server_name.to_string(),
                method: "prompts/get",
                error,
            });
        }

        let result = response
            .result
            .ok_or_else(|| McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "prompts/get",
                details: "missing result payload".to_string(),
            })?;
        if result.messages.len() > MCP_MAX_PROMPT_MESSAGES {
            return Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method: "prompts/get",
                limit: MCP_MAX_PROMPT_MESSAGES,
                details: format!("server returned {} prompt messages", result.messages.len()),
            });
        }
        Self::validate_json_size(
            server_name,
            "prompts/get",
            &result,
            MCP_MAX_RESULT_JSON_BYTES,
            "prompts/get result JSON",
        )?;
        for message in &result.messages {
            Self::validate_json_size(
                server_name,
                "prompts/get",
                message,
                MCP_MAX_CATALOG_ITEM_JSON_BYTES,
                "prompt message JSON",
            )?;
        }
        Ok(result)
    }

    async fn reset_server(&mut self, server_name: &str) -> Result<(), McpServerManagerError> {
        let mut process = {
            let server = self.server_mut(server_name)?;
            server.initialized = false;
            server.catalog.requested_protocol_version = None;
            server.catalog.negotiated_protocol_version = None;
            server.catalog.protocol_transport_policy = None;
            server.catalog.protocol_configured_preferred = false;
            server.process.take()
        };

        if let Some(heartbeat) = self.heartbeat.get_mut(server_name) {
            heartbeat.mark_protocol_state(None, None);
        }

        if let Some(process) = process.as_mut() {
            let _ = process.shutdown().await;
        }

        Ok(())
    }

    fn is_retryable_error(error: &McpServerManagerError) -> bool {
        matches!(
            error,
            McpServerManagerError::Transport { .. } | McpServerManagerError::Timeout { .. }
        )
    }

    fn should_reset_server(error: &McpServerManagerError) -> bool {
        matches!(
            error,
            McpServerManagerError::Transport { .. }
                | McpServerManagerError::Timeout { .. }
                | McpServerManagerError::InvalidResponse { .. }
        )
    }

    async fn run_process_request<T, F>(
        server_name: &str,
        method: &'static str,
        timeout_ms: u64,
        future: F,
    ) -> Result<T, McpServerManagerError>
    where
        F: Future<Output = io::Result<T>>,
    {
        match timeout(Duration::from_millis(timeout_ms), future).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) if error.kind() == io::ErrorKind::InvalidData => {
                Err(McpServerManagerError::InvalidResponse {
                    server_name: server_name.to_string(),
                    method,
                    details: error.to_string(),
                })
            }
            Ok(Err(source)) => Err(McpServerManagerError::Transport {
                server_name: server_name.to_string(),
                method,
                source,
            }),
            Err(_) => Err(McpServerManagerError::Timeout {
                server_name: server_name.to_string(),
                method,
                timeout_ms,
            }),
        }
    }

    async fn ping_if_configured(&mut self, server_name: &str) -> Result<(), McpServerManagerError> {
        let timeout_ms = {
            let server = self.server_mut(server_name)?;
            match &server.bootstrap.transport {
                McpClientTransport::Stdio(transport) => transport
                    .env
                    .get("CLAWD_MCP_HEARTBEAT_TIMEOUT_MS")
                    .and_then(|value| value.parse::<u64>().ok()),
                _ => None,
            }
        };
        let Some(timeout_ms) = timeout_ms else {
            return Ok(());
        };
        let request_id = self.take_request_id();
        let response_result =
            {
                let server = self.server_mut(server_name)?;
                let process = server.process.as_mut().ok_or_else(|| {
                    McpServerManagerError::InvalidResponse {
                        server_name: server_name.to_string(),
                        method: "ping",
                        details: "server process missing before ping".to_string(),
                    }
                })?;
                Self::run_process_request(
                    server_name,
                    "ping",
                    timeout_ms,
                    process.request::<_, JsonValue>(
                        request_id,
                        "ping",
                        Some(JsonValue::Object(serde_json::Map::new())),
                    ),
                )
                .await
            };
        let response = match response_result {
            Ok(response) => response,
            Err(error) => {
                self.record_heartbeat_failure(server_name, error.to_string());
                return Err(error);
            }
        };
        if let Some(error) = response.error {
            let error = McpServerManagerError::JsonRpc {
                server_name: server_name.to_string(),
                method: "ping",
                error,
            };
            self.record_heartbeat_failure(server_name, error.to_string());
            return Err(error);
        }
        self.record_heartbeat_success(server_name);
        Ok(())
    }

    async fn ensure_server_ready(
        &mut self,
        server_name: &str,
    ) -> Result<(), McpServerManagerError> {
        if self.server_process_exited(server_name)? {
            self.reset_server(server_name).await?;
        }

        let mut attempts = 0;
        loop {
            let needs_spawn = self
                .servers
                .get(server_name)
                .map(|server| server.process.is_none())
                .ok_or_else(|| McpServerManagerError::UnknownServer {
                    server_name: server_name.to_string(),
                })?;

            if needs_spawn {
                let bootstrap = &self
                    .servers
                    .get(server_name)
                    .ok_or_else(|| McpServerManagerError::UnknownServer {
                        server_name: server_name.to_string(),
                    })?
                    .bootstrap;
                initialize_params_for_bootstrap(bootstrap)
                    .map_err(|error| protocol_version_error(server_name, "initialize", error))?;
                let server = self.server_mut(server_name)?;
                server.process = Some(spawn_mcp_stdio_process(&server.bootstrap)?);
                server.initialized = false;
            }

            let needs_initialize = self
                .servers
                .get(server_name)
                .map(|server| !server.initialized)
                .ok_or_else(|| McpServerManagerError::UnknownServer {
                    server_name: server_name.to_string(),
                })?;

            if !needs_initialize {
                return Ok(());
            }

            let request_id = self.take_request_id();
            let bootstrap = &self
                .servers
                .get(server_name)
                .ok_or_else(|| McpServerManagerError::UnknownServer {
                    server_name: server_name.to_string(),
                })?
                .bootstrap;
            let initialize_params = match initialize_params_for_bootstrap(bootstrap) {
                Ok(params) => params,
                Err(error) => {
                    let error = protocol_version_error(server_name, "initialize", error);
                    self.reset_server(server_name).await?;
                    return Err(error);
                }
            };
            let requested_protocol_version = initialize_params.protocol_version.clone();
            let response = {
                let server = self.server_mut(server_name)?;
                let process = server.process.as_mut().ok_or_else(|| {
                    McpServerManagerError::InvalidResponse {
                        server_name: server_name.to_string(),
                        method: "initialize",
                        details: "server process missing before initialize".to_string(),
                    }
                })?;
                Self::run_process_request(
                    server_name,
                    "initialize",
                    MCP_INITIALIZE_TIMEOUT_MS,
                    process.initialize(request_id, initialize_params),
                )
                .await
            };

            let response = match response {
                Ok(response) => response,
                Err(error) if attempts == 0 && Self::is_retryable_error(&error) => {
                    self.reset_server(server_name).await?;
                    attempts += 1;
                    continue;
                }
                Err(error) => {
                    if Self::should_reset_server(&error) {
                        self.reset_server(server_name).await?;
                    }
                    return Err(error);
                }
            };

            if let Some(error) = response.error {
                let error = McpServerManagerError::JsonRpc {
                    server_name: server_name.to_string(),
                    method: "initialize",
                    error,
                };
                self.reset_server(server_name).await?;
                return Err(error);
            }

            let Some(result) = response.result else {
                let error = McpServerManagerError::InvalidResponse {
                    server_name: server_name.to_string(),
                    method: "initialize",
                    details: "missing result payload".to_string(),
                };
                self.reset_server(server_name).await?;
                return Err(error);
            };

            let negotiated_protocol_version = negotiate_initialize_protocol_version(
                server_name,
                McpProtocolTransportPolicy::Stdio,
                &requested_protocol_version,
                &result.protocol_version,
            );
            let _negotiated_protocol_version = match negotiated_protocol_version {
                Ok(version) => version,
                Err(error) => {
                    self.reset_server(server_name).await?;
                    return Err(error);
                }
            };

            {
                let server = self.server_mut(server_name)?;
                let process = server.process.as_mut().ok_or_else(|| {
                    McpServerManagerError::InvalidResponse {
                        server_name: server_name.to_string(),
                        method: "notifications/initialized",
                        details: "server process missing before initialized notification"
                            .to_string(),
                    }
                })?;
                Self::run_process_request(
                    server_name,
                    "notifications/initialized",
                    MCP_INITIALIZE_TIMEOUT_MS,
                    process.notify(
                        "notifications/initialized",
                        Some(JsonValue::Object(serde_json::Map::new())),
                    ),
                )
                .await?;
            }

            self.update_initialize_catalog(server_name, result)?;
            return Ok(());
        }
    }
}

struct McpSseSession {
    server_name: String,
    post_client: ReqwestBlockingClient,
    headers: HeaderMap,
    stream: LimitedSseStream,
    post_url: Url,
}

impl McpSseSession {
    fn connect(
        server_name: &str,
        transport: McpRemoteTransport,
        timeout_ms: u64,
    ) -> Result<Self, McpServerManagerError> {
        validate_sse_operation_timeout(server_name, "sse/connect", timeout_ms)?;
        let base_url = parse_and_validate_sse_url(server_name, "sse/connect", &transport.url)?;
        let headers = build_sse_headers(server_name, "sse/connect", &transport.headers)?;
        let get_runtime =
            build_sse_get_runtime().map_err(|source| McpServerManagerError::Transport {
                server_name: server_name.to_string(),
                method: "sse/connect",
                source,
            })?;
        let get_client = build_sse_get_client(timeout_ms).map_err(|source| {
            McpServerManagerError::Transport {
                server_name: server_name.to_string(),
                method: "sse/connect",
                source,
            }
        })?;
        let post_client = build_sse_post_client(timeout_ms).map_err(|source| {
            McpServerManagerError::Transport {
                server_name: server_name.to_string(),
                method: "sse/connect",
                source,
            }
        })?;
        let response = get_runtime
            .block_on(async {
                get_client
                    .get(base_url.clone())
                    .headers(headers.clone())
                    .header(ACCEPT, "text/event-stream")
                    .header(CACHE_CONTROL, "no-cache")
                    .send()
                    .await
            })
            .map_err(|error| McpServerManagerError::Transport {
                server_name: server_name.to_string(),
                method: "sse/connect",
                source: reqwest_error_to_io(error),
            })?;
        validate_sse_get_response(server_name, response.status(), response.headers())?;
        let mut stream = LimitedSseStream::new(server_name.to_string(), get_runtime, response);
        let post_url = read_sse_endpoint_event(server_name, &base_url, &mut stream, timeout_ms)?;
        Ok(Self {
            server_name: server_name.to_string(),
            post_client,
            headers,
            stream,
            post_url,
        })
    }

    fn request<TParams: Serialize, TResult: DeserializeOwned>(
        &mut self,
        id: JsonRpcId,
        method: &'static str,
        params: Option<TParams>,
        timeout_ms: u64,
    ) -> Result<JsonRpcResponse<TResult>, McpServerManagerError> {
        let request = JsonRpcRequest::new(id.clone(), method, params);
        self.post_jsonrpc(&request, method, timeout_ms)?;
        self.read_response(id, method, timeout_ms)
    }

    fn notify<TParams: Serialize>(
        &mut self,
        method: &'static str,
        params: Option<TParams>,
        timeout_ms: u64,
    ) -> Result<(), McpServerManagerError> {
        let notification = JsonRpcNotification::new(method, params);
        self.post_jsonrpc(&notification, method, timeout_ms)
    }

    fn post_jsonrpc<T: Serialize>(
        &self,
        message: &T,
        method: &'static str,
        timeout_ms: u64,
    ) -> Result<(), McpServerManagerError> {
        let body = serde_json::to_vec(message).map_err(|error| {
            McpServerManagerError::InvalidResponse {
                server_name: self.server_name.clone(),
                method,
                details: format!("failed to serialize JSON-RPC request: {error}"),
            }
        })?;
        if body.len() > MCP_MAX_JSONRPC_FRAME_BYTES {
            return Err(McpServerManagerError::LimitExceeded {
                server_name: self.server_name.clone(),
                method,
                limit: MCP_MAX_JSONRPC_FRAME_BYTES,
                details: format!("JSON-RPC request body was {} bytes", body.len()),
            });
        }

        let mut response = self
            .post_client
            .post(self.post_url.clone())
            .headers(self.headers.clone())
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .timeout(Duration::from_millis(timeout_ms))
            .send()
            .map_err(|error| McpServerManagerError::Transport {
                server_name: self.server_name.clone(),
                method,
                source: reqwest_error_to_io(error),
            })?;
        validate_sse_post_response(&self.server_name, method, &mut response)
    }

    fn read_response<TResult: DeserializeOwned>(
        &mut self,
        id: JsonRpcId,
        method: &'static str,
        timeout_ms: u64,
    ) -> Result<JsonRpcResponse<TResult>, McpServerManagerError> {
        let deadline = sse_operation_deadline(&self.server_name, method, timeout_ms)?;
        loop {
            let event = self.stream.next_event_until(method, deadline, timeout_ms)?;
            if event.event.as_deref() != Some("message") {
                continue;
            }
            if event.data.trim().is_empty() {
                return Err(McpServerManagerError::InvalidResponse {
                    server_name: self.server_name.clone(),
                    method,
                    details: "empty SSE message event for JSON-RPC response".to_string(),
                });
            }
            if event.data.len() > MCP_MAX_JSONRPC_FRAME_BYTES {
                return Err(McpServerManagerError::LimitExceeded {
                    server_name: self.server_name.clone(),
                    method,
                    limit: MCP_MAX_JSONRPC_FRAME_BYTES,
                    details: format!("SSE JSON-RPC response was {} bytes", event.data.len()),
                });
            }
            let value = serde_json::from_str::<JsonValue>(&event.data).map_err(|error| {
                McpServerManagerError::InvalidResponse {
                    server_name: self.server_name.clone(),
                    method,
                    details: format!("invalid SSE JSON data: {error}"),
                }
            })?;
            if value.get("id").is_none() {
                continue;
            }
            let response =
                serde_json::from_value::<JsonRpcResponse<TResult>>(value).map_err(|error| {
                    McpServerManagerError::InvalidResponse {
                        server_name: self.server_name.clone(),
                        method,
                        details: format!("invalid SSE JSON-RPC response: {error}"),
                    }
                })?;
            if response.jsonrpc != "2.0" {
                return Err(McpServerManagerError::InvalidResponse {
                    server_name: self.server_name.clone(),
                    method,
                    details: format!(
                        "SSE JSON-RPC response used unsupported jsonrpc version `{}`",
                        response.jsonrpc
                    ),
                });
            }
            if response.id != id {
                return Err(McpServerManagerError::InvalidResponse {
                    server_name: self.server_name.clone(),
                    method,
                    details: format!(
                        "SSE JSON-RPC response used mismatched id: expected {id:?}, got {:?}",
                        response.id
                    ),
                });
            }
            return Ok(response);
        }
    }
}

struct LimitedSseStream {
    server_name: String,
    runtime: tokio::runtime::Runtime,
    response: ReqwestAsyncResponse,
    buffer: Vec<u8>,
    event_name: Option<String>,
    data_lines: Vec<String>,
    id: Option<String>,
    retry: Option<u64>,
    event_bytes: usize,
}

impl LimitedSseStream {
    fn new(
        server_name: String,
        runtime: tokio::runtime::Runtime,
        response: ReqwestAsyncResponse,
    ) -> Self {
        Self {
            server_name,
            runtime,
            response,
            buffer: Vec::new(),
            event_name: None,
            data_lines: Vec::new(),
            id: None,
            retry: None,
            event_bytes: 0,
        }
    }

    fn next_event_until(
        &mut self,
        method: &'static str,
        deadline: Instant,
        timeout_ms: u64,
    ) -> Result<SseEvent, McpServerManagerError> {
        loop {
            remaining_sse_operation_time(&self.server_name, method, timeout_ms, deadline)?;
            if let Some(index) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let mut line = self.buffer.drain(..=index).collect::<Vec<_>>();
                self.event_bytes = self.event_bytes.saturating_add(line.len());
                if self.event_bytes > MCP_SSE_MAX_EVENT_BYTES {
                    return Err(McpServerManagerError::LimitExceeded {
                        server_name: self.server_name.clone(),
                        method,
                        limit: MCP_SSE_MAX_EVENT_BYTES,
                        details: "SSE event exceeded byte limit".to_string(),
                    });
                }
                if line.ends_with(b"\n") {
                    line.pop();
                }
                if line.ends_with(b"\r") {
                    line.pop();
                }
                if line.is_empty() {
                    if let Some(event) = self.take_event() {
                        self.event_bytes = 0;
                        return Ok(event);
                    }
                    self.event_bytes = 0;
                    continue;
                }
                self.process_line(method, line)?;
                continue;
            }

            if self.buffer.len().saturating_add(MCP_SSE_READ_CHUNK_BYTES) > MCP_SSE_MAX_EVENT_BYTES
            {
                return Err(McpServerManagerError::LimitExceeded {
                    server_name: self.server_name.clone(),
                    method,
                    limit: MCP_SSE_MAX_EVENT_BYTES,
                    details: "SSE event line exceeded byte limit before delimiter".to_string(),
                });
            }
            let remaining =
                remaining_sse_operation_time(&self.server_name, method, timeout_ms, deadline)?;
            let maybe_chunk = self
                .runtime
                .block_on(async { tokio::time::timeout(remaining, self.response.chunk()).await });
            let maybe_chunk = match maybe_chunk {
                Ok(Ok(chunk)) => chunk,
                Ok(Err(error)) => {
                    return Err(McpServerManagerError::Transport {
                        server_name: self.server_name.clone(),
                        method,
                        source: reqwest_error_to_io(error),
                    });
                }
                Err(_) => {
                    return Err(McpServerManagerError::Timeout {
                        server_name: self.server_name.clone(),
                        method,
                        timeout_ms,
                    });
                }
            };
            let Some(chunk) = maybe_chunk else {
                return Err(McpServerManagerError::InvalidResponse {
                    server_name: self.server_name.clone(),
                    method,
                    details: "SSE stream ended before expected event".to_string(),
                });
            };
            if chunk.len() > MCP_SSE_MAX_EVENT_BYTES {
                return Err(McpServerManagerError::LimitExceeded {
                    server_name: self.server_name.clone(),
                    method,
                    limit: MCP_SSE_MAX_EVENT_BYTES,
                    details: "SSE event read chunk exceeded byte limit".to_string(),
                });
            }
            if self.buffer.len().saturating_add(chunk.len()) > MCP_SSE_MAX_EVENT_BYTES {
                return Err(McpServerManagerError::LimitExceeded {
                    server_name: self.server_name.clone(),
                    method,
                    limit: MCP_SSE_MAX_EVENT_BYTES,
                    details: "SSE event buffer exceeded byte limit".to_string(),
                });
            }
            self.buffer.extend_from_slice(&chunk);
        }
    }

    fn process_line(
        &mut self,
        method: &'static str,
        line: Vec<u8>,
    ) -> Result<(), McpServerManagerError> {
        let line =
            String::from_utf8(line).map_err(|error| McpServerManagerError::InvalidResponse {
                server_name: self.server_name.clone(),
                method,
                details: format!("SSE stream used invalid UTF-8: {error}"),
            })?;
        if line.starts_with(':') {
            return Ok(());
        }
        let (field, value) = line
            .split_once(':')
            .map_or((line.as_str(), ""), |(field, value)| {
                (field, value.strip_prefix(' ').unwrap_or(value))
            });
        match field {
            "event" => self.event_name = Some(value.to_string()),
            "data" => self.data_lines.push(value.to_string()),
            "id" => self.id = Some(value.to_string()),
            "retry" => self.retry = value.parse::<u64>().ok(),
            _ => {}
        }
        Ok(())
    }

    fn take_event(&mut self) -> Option<SseEvent> {
        if self.data_lines.is_empty()
            && self.event_name.is_none()
            && self.id.is_none()
            && self.retry.is_none()
        {
            return None;
        }
        let data = self.data_lines.join("\n");
        self.data_lines.clear();
        Some(SseEvent {
            event: self.event_name.take(),
            data,
            id: self.id.take(),
            retry: self.retry.take(),
        })
    }
}

fn build_sse_get_runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))
}

fn build_sse_get_client(timeout_ms: u64) -> io::Result<ReqwestAsyncClient> {
    let timeout = Duration::from_millis(timeout_ms);
    ReqwestAsyncClient::builder()
        .use_rustls_tls()
        .tls_built_in_native_certs(true)
        .redirect(redirect::Policy::none())
        .connect_timeout(timeout)
        .read_timeout(timeout)
        .build()
        .map_err(reqwest_error_to_io)
}

fn build_sse_post_client(timeout_ms: u64) -> io::Result<ReqwestBlockingClient> {
    let timeout = Duration::from_millis(timeout_ms);
    ReqwestBlockingClient::builder()
        .use_rustls_tls()
        .tls_built_in_native_certs(true)
        .redirect(redirect::Policy::none())
        .connect_timeout(timeout)
        .build()
        .map_err(reqwest_error_to_io)
}

#[cfg(test)]
fn build_sse_client(timeout_ms: u64) -> io::Result<ReqwestBlockingClient> {
    build_sse_post_client(timeout_ms)
}

fn sse_operation_deadline(
    server_name: &str,
    method: &'static str,
    timeout_ms: u64,
) -> Result<Instant, McpServerManagerError> {
    validate_sse_operation_timeout(server_name, method, timeout_ms)?;
    Instant::now()
        .checked_add(Duration::from_millis(timeout_ms))
        .ok_or_else(|| McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method,
            details: format!("SSE operation timeout {timeout_ms} ms is too large to represent"),
        })
}

fn validate_sse_operation_timeout(
    server_name: &str,
    method: &'static str,
    timeout_ms: u64,
) -> Result<(), McpServerManagerError> {
    if timeout_ms == 0 {
        return Err(McpServerManagerError::Timeout {
            server_name: server_name.to_string(),
            method,
            timeout_ms,
        });
    }
    if timeout_ms > MCP_SSE_MAX_OPERATION_TIMEOUT_MS {
        return Err(McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method,
            details: format!(
                "SSE operation timeout {timeout_ms} ms is too large to represent safely"
            ),
        });
    }
    Ok(())
}

fn remaining_sse_operation_time(
    server_name: &str,
    method: &'static str,
    timeout_ms: u64,
    deadline: Instant,
) -> Result<Duration, McpServerManagerError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| McpServerManagerError::Timeout {
            server_name: server_name.to_string(),
            method,
            timeout_ms,
        })
}

fn parse_and_validate_sse_url(
    server_name: &str,
    method: &'static str,
    raw_url: &str,
) -> Result<Url, McpServerManagerError> {
    if raw_url.len() > MCP_SSE_MAX_URL_BYTES {
        return Err(McpServerManagerError::LimitExceeded {
            server_name: server_name.to_string(),
            method,
            limit: MCP_SSE_MAX_URL_BYTES,
            details: format!("SSE URL was {} bytes", raw_url.len()),
        });
    }
    let url = Url::parse(raw_url).map_err(|error| McpServerManagerError::InvalidResponse {
        server_name: server_name.to_string(),
        method,
        details: format!("invalid SSE URL: {error}"),
    })?;
    validate_sse_url(server_name, method, url)
}

fn validate_sse_url(
    server_name: &str,
    method: &'static str,
    url: Url,
) -> Result<Url, McpServerManagerError> {
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method,
            details: "SSE URLs must use http:// or https://".to_string(),
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method,
            details: "SSE URLs must not contain userinfo".to_string(),
        });
    }
    if url.fragment().is_some() {
        return Err(McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method,
            details: "SSE URLs must not contain fragments".to_string(),
        });
    }
    Ok(url)
}

fn build_sse_headers(
    server_name: &str,
    method: &'static str,
    headers: &BTreeMap<String, String>,
) -> Result<HeaderMap, McpServerManagerError> {
    let mut total_bytes = 0_usize;
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        total_bytes = total_bytes
            .saturating_add(name.len())
            .saturating_add(value.len())
            .saturating_add(4);
        if total_bytes > MCP_SSE_MAX_HEADER_BYTES {
            return Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method,
                limit: MCP_SSE_MAX_HEADER_BYTES,
                details: "SSE custom headers exceeded byte budget".to_string(),
            });
        }
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            return Err(McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method,
                details: "SSE custom headers must not contain line breaks".to_string(),
            });
        }
        let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method,
                details: format!("invalid SSE custom header name: {error}"),
            }
        })?;
        if is_blocked_sse_custom_header(&header_name) {
            return Err(McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method,
                details: format!(
                    "SSE custom header `{}` is reserved by the transport",
                    header_name.as_str()
                ),
            });
        }
        let header_value = HeaderValue::from_str(value).map_err(|error| {
            McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method,
                details: format!("invalid SSE custom header value: {error}"),
            }
        })?;
        map.insert(header_name, header_value);
    }
    Ok(map)
}

fn is_blocked_sse_custom_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "connection"
            | "content-length"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "proxy-connection"
            | "proxy-authorization"
            | "keep-alive"
            | "expect"
            | "accept"
            | "content-type"
            | "cache-control"
    )
}

fn validate_sse_get_response(
    server_name: &str,
    status: reqwest::StatusCode,
    headers: &HeaderMap,
) -> Result<(), McpServerManagerError> {
    validate_sse_response_header_budget(server_name, "sse/connect", headers)?;
    if !status.is_success() {
        return Err(McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method: "sse/connect",
            details: format!("SSE GET returned non-2xx status {status}"),
        });
    }
    let Some(content_type) = headers.get(CONTENT_TYPE) else {
        return Err(McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method: "sse/connect",
            details: "SSE GET response missing Content-Type".to_string(),
        });
    };
    let content_type =
        content_type
            .to_str()
            .map_err(|error| McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "sse/connect",
                details: format!("invalid SSE Content-Type header: {error}"),
            })?;
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    if !media_type.eq_ignore_ascii_case("text/event-stream") {
        return Err(McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method: "sse/connect",
            details: format!("SSE GET Content-Type was `{media_type}`"),
        });
    }
    Ok(())
}

fn validate_sse_post_response(
    server_name: &str,
    method: &'static str,
    response: &mut ReqwestBlockingResponse,
) -> Result<(), McpServerManagerError> {
    validate_sse_response_header_budget(server_name, method, response.headers())?;
    if !response.status().is_success() {
        return Err(McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method,
            details: format!("SSE POST returned non-2xx status {}", response.status()),
        });
    }
    validate_sse_post_response_framing(server_name, method, response.headers())?;
    let status = response.status();
    let body_bytes = read_limited_sse_http_response_body(server_name, method, response)?;
    if status == reqwest::StatusCode::ACCEPTED && body_bytes != 0 {
        return Err(McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method,
            details: "SSE POST 202 Accepted response must not include a body".to_string(),
        });
    }
    Ok(())
}

fn validate_sse_post_response_framing(
    server_name: &str,
    method: &'static str,
    headers: &HeaderMap,
) -> Result<(), McpServerManagerError> {
    let has_content_length = headers.get(CONTENT_LENGTH).is_some();
    let has_transfer_encoding = headers.get(TRANSFER_ENCODING).is_some();
    if has_content_length
        || has_transfer_encoding
        || header_contains_token(headers, CONNECTION, "close")
    {
        return Ok(());
    }
    Err(McpServerManagerError::InvalidResponse {
        server_name: server_name.to_string(),
        method,
        details: "SSE POST response must use Content-Length, Transfer-Encoding, or Connection: close framing".to_string(),
    })
}

fn header_contains_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().ok().is_some_and(|raw| {
            raw.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    })
}

fn validate_sse_response_header_budget(
    server_name: &str,
    method: &'static str,
    headers: &HeaderMap,
) -> Result<(), McpServerManagerError> {
    let mut total_bytes = 0_usize;
    for (name, value) in headers {
        total_bytes = total_bytes
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4);
        if total_bytes > MCP_SSE_MAX_HEADER_BYTES {
            return Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method,
                limit: MCP_SSE_MAX_HEADER_BYTES,
                details: "SSE response headers exceeded byte budget".to_string(),
            });
        }
    }
    Ok(())
}

fn read_limited_sse_http_response_body(
    server_name: &str,
    method: &'static str,
    response: &mut ReqwestBlockingResponse,
) -> Result<usize, McpServerManagerError> {
    let mut total_bytes = 0_usize;
    let mut buffer = [0_u8; MCP_SSE_READ_CHUNK_BYTES];
    loop {
        let remaining = MCP_SSE_MAX_HTTP_RESPONSE_BODY_BYTES
            .saturating_add(1)
            .saturating_sub(total_bytes);
        if remaining == 0 {
            return Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method,
                limit: MCP_SSE_MAX_HTTP_RESPONSE_BODY_BYTES,
                details: "SSE POST response body exceeded byte budget".to_string(),
            });
        }
        let read_len = remaining.min(buffer.len());
        let read = response.read(&mut buffer[..read_len]).map_err(|source| {
            McpServerManagerError::Transport {
                server_name: server_name.to_string(),
                method,
                source,
            }
        })?;
        if read == 0 {
            return Ok(total_bytes);
        }
        total_bytes = total_bytes.saturating_add(read);
        if total_bytes > MCP_SSE_MAX_HTTP_RESPONSE_BODY_BYTES {
            return Err(McpServerManagerError::LimitExceeded {
                server_name: server_name.to_string(),
                method,
                limit: MCP_SSE_MAX_HTTP_RESPONSE_BODY_BYTES,
                details: "SSE POST response body exceeded byte budget".to_string(),
            });
        }
    }
}

fn read_sse_endpoint_event(
    server_name: &str,
    base_url: &Url,
    stream: &mut LimitedSseStream,
    timeout_ms: u64,
) -> Result<Url, McpServerManagerError> {
    let deadline = sse_operation_deadline(server_name, "sse/endpoint", timeout_ms)?;
    loop {
        let event = stream.next_event_until("sse/endpoint", deadline, timeout_ms)?;
        if event.event.as_deref() != Some("endpoint") {
            return Err(McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "sse/endpoint",
                details: "first SSE event before JSON-RPC endpoint was not endpoint".to_string(),
            });
        }
        if event.data.trim().is_empty() {
            return Err(McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "sse/endpoint",
                details: "SSE endpoint event had empty data".to_string(),
            });
        }
        return resolve_sse_endpoint(server_name, base_url, event.data.trim());
    }
}

fn resolve_sse_endpoint(
    server_name: &str,
    base_url: &Url,
    endpoint: &str,
) -> Result<Url, McpServerManagerError> {
    if endpoint.len() > MCP_SSE_MAX_URL_BYTES {
        return Err(McpServerManagerError::LimitExceeded {
            server_name: server_name.to_string(),
            method: "sse/endpoint",
            limit: MCP_SSE_MAX_URL_BYTES,
            details: format!("SSE endpoint URL was {} bytes", endpoint.len()),
        });
    }
    let endpoint_url =
        base_url
            .join(endpoint)
            .map_err(|error| McpServerManagerError::InvalidResponse {
                server_name: server_name.to_string(),
                method: "sse/endpoint",
                details: format!("invalid SSE endpoint URL: {error}"),
            })?;
    let endpoint_url = validate_sse_url(server_name, "sse/endpoint", endpoint_url)?;
    if !same_origin(base_url, &endpoint_url) {
        return Err(McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method: "sse/endpoint",
            details:
                "SSE endpoint URL must have the same scheme, host, and effective port as config URL"
                    .to_string(),
        });
    }
    Ok(endpoint_url)
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn reqwest_error_to_io(error: reqwest::Error) -> io::Error {
    let is_timeout = error.is_timeout();
    let is_connect = error.is_connect();
    let status = error.status();
    let kind = if is_timeout {
        io::ErrorKind::TimedOut
    } else if is_connect {
        io::ErrorKind::ConnectionRefused
    } else {
        io::ErrorKind::Other
    };
    let safe_error = error.without_url().to_string();
    let details = if is_timeout {
        format!("reqwest SSE transport timed out: {safe_error}")
    } else if is_connect {
        format!("reqwest SSE connect failed: {safe_error}")
    } else if let Some(status) = status {
        format!("reqwest SSE transport failed with HTTP status {status}: {safe_error}")
    } else {
        format!("reqwest SSE transport failed: {safe_error}")
    };
    io::Error::new(kind, details)
}

fn jsonrpc_result<T>(
    server_name: &str,
    method: &'static str,
    response: JsonRpcResponse<T>,
) -> Result<T, McpServerManagerError> {
    if let Some(error) = response.error {
        return Err(McpServerManagerError::JsonRpc {
            server_name: server_name.to_string(),
            method,
            error,
        });
    }
    response
        .result
        .ok_or_else(|| McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method,
            details: "missing result payload".to_string(),
        })
}

fn connect_initialized_sse_session(
    server_name: &str,
    transport: &McpRemoteTransport,
    request_id: u64,
    timeout_ms: u64,
) -> Result<(McpSseSession, McpInitializeResult, McpServerCapabilities), McpServerManagerError> {
    let protocol_selection = select_mcp_protocol_version(
        transport.protocol_version.as_deref(),
        McpProtocolTransportPolicy::LegacySse,
    )
    .map_err(|error| protocol_version_error(server_name, "initialize", error))?;
    let mut session = McpSseSession::connect(server_name, transport.clone(), timeout_ms)?;
    let initialize_result = initialize_sse_session(
        server_name,
        transport,
        &mut session,
        request_id,
        timeout_ms,
        &protocol_selection,
    )?;
    session.notify(
        "notifications/initialized",
        Some(JsonValue::Object(serde_json::Map::new())),
        timeout_ms,
    )?;
    let capabilities = McpServerCapabilities::from_raw(initialize_result.capabilities.clone());
    Ok((session, initialize_result, capabilities))
}

fn ping_sse_session(
    server_name: &str,
    transport: &McpRemoteTransport,
    session: &mut McpSseSession,
    request_id: u64,
    timeout_ms: u64,
) -> Result<(), McpServerManagerError> {
    let heartbeat_timeout_ms = transport.heartbeat_timeout_ms.unwrap_or(timeout_ms);
    let response = session.request::<_, JsonValue>(
        JsonRpcId::Number(request_id),
        "ping",
        Some(JsonValue::Object(serde_json::Map::new())),
        heartbeat_timeout_ms,
    )?;
    let _ = jsonrpc_result(server_name, "ping", response)?;
    Ok(())
}

fn list_sse_tools_pages(
    server_name: &str,
    session: &mut McpSseSession,
    request_id: u64,
    timeout_ms: u64,
) -> Result<Vec<ManagedMcpTool>, McpServerManagerError> {
    let mut tools = Vec::new();
    let mut cursor = None;
    let mut page_count = 0;
    let mut total_json_bytes = 0_usize;
    let mut seen_cursors = BTreeSet::new();
    let mut seen_names = BTreeSet::new();
    loop {
        McpServerManager::validate_page_limit(server_name, "tools/list", page_count)?;
        let page_request_id = request_id + page_count as u64;
        page_count += 1;

        let list = session.request::<_, McpListToolsResult>(
            JsonRpcId::Number(page_request_id),
            "tools/list",
            Some(McpListToolsParams {
                cursor: cursor.clone(),
            }),
            timeout_ms,
        )?;
        let result = jsonrpc_result(server_name, "tools/list", list)?;

        let page_json = McpServerManager::json_size(server_name, "tools/list", &result)?;
        McpServerManager::validate_json_size(
            server_name,
            "tools/list",
            &result,
            MCP_MAX_RESULT_JSON_BYTES,
            "tools/list page JSON",
        )?;
        total_json_bytes = total_json_bytes.saturating_add(page_json.len());
        McpServerManager::validate_aggregate_json_size(
            server_name,
            "tools/list",
            total_json_bytes,
        )?;

        for tool in &result.tools {
            McpServerManager::validate_json_size(
                server_name,
                "tools/list",
                tool,
                MCP_MAX_CATALOG_ITEM_JSON_BYTES,
                "tool catalog item JSON",
            )?;
            if !seen_names.insert(tool.name.clone()) {
                return Err(McpServerManager::duplicate_catalog_item(
                    server_name,
                    "tools/list",
                    "tool name",
                    &tool.name,
                ));
            }
        }

        for tool in result.tools {
            tools.push(ManagedMcpTool {
                server_name: server_name.to_string(),
                qualified_name: mcp_tool_name(server_name, &tool.name),
                raw_name: tool.name.clone(),
                tool,
            });
        }
        McpServerManager::validate_total_items(server_name, "tools/list", tools.len())?;

        match result.next_cursor {
            Some(next_cursor) => {
                cursor = Some(McpServerManager::validate_next_cursor(
                    server_name,
                    "tools/list",
                    next_cursor,
                    &mut seen_cursors,
                )?);
            }
            None => break,
        }
    }

    McpServerManager::validate_json_size(
        server_name,
        "tools/list",
        &tools,
        MCP_MAX_RESULT_JSON_BYTES,
        "tools/list aggregate JSON",
    )?;
    Ok(tools)
}

fn list_sse_resources_pages(
    server_name: &str,
    session: &mut McpSseSession,
    request_id: u64,
    timeout_ms: u64,
) -> Result<McpListResourcesResult, McpServerManagerError> {
    let mut resources = Vec::new();
    let mut cursor = None;
    let mut page_count = 0;
    let mut total_json_bytes = 0_usize;
    let mut seen_cursors = BTreeSet::new();
    let mut seen_uris = BTreeSet::new();
    loop {
        McpServerManager::validate_page_limit(server_name, "resources/list", page_count)?;
        let page_request_id = request_id + page_count as u64;
        page_count += 1;

        let list = session.request::<_, McpListResourcesResult>(
            JsonRpcId::Number(page_request_id),
            "resources/list",
            Some(McpListResourcesParams {
                cursor: cursor.clone(),
            }),
            timeout_ms,
        )?;
        let result = jsonrpc_result(server_name, "resources/list", list)?;

        let page_json = McpServerManager::json_size(server_name, "resources/list", &result)?;
        McpServerManager::validate_json_size(
            server_name,
            "resources/list",
            &result,
            MCP_MAX_RESULT_JSON_BYTES,
            "resources/list page JSON",
        )?;
        total_json_bytes = total_json_bytes.saturating_add(page_json.len());
        McpServerManager::validate_aggregate_json_size(
            server_name,
            "resources/list",
            total_json_bytes,
        )?;

        for resource in &result.resources {
            McpServerManager::validate_json_size(
                server_name,
                "resources/list",
                resource,
                MCP_MAX_CATALOG_ITEM_JSON_BYTES,
                "resource catalog item JSON",
            )?;
            if !seen_uris.insert(resource.uri.clone()) {
                return Err(McpServerManager::duplicate_catalog_item(
                    server_name,
                    "resources/list",
                    "resource uri",
                    &resource.uri,
                ));
            }
        }

        resources.extend(result.resources);
        McpServerManager::validate_total_items(server_name, "resources/list", resources.len())?;

        match result.next_cursor {
            Some(next_cursor) => {
                cursor = Some(McpServerManager::validate_next_cursor(
                    server_name,
                    "resources/list",
                    next_cursor,
                    &mut seen_cursors,
                )?);
            }
            None => break,
        }
    }

    let result = McpListResourcesResult {
        resources,
        next_cursor: None,
    };
    McpServerManager::validate_json_size(
        server_name,
        "resources/list",
        &result,
        MCP_MAX_RESULT_JSON_BYTES,
        "resources/list aggregate JSON",
    )?;
    Ok(result)
}

fn list_sse_resource_templates_pages(
    server_name: &str,
    session: &mut McpSseSession,
    request_id: u64,
    timeout_ms: u64,
) -> Result<McpListResourceTemplatesResult, McpServerManagerError> {
    let mut resource_templates = Vec::new();
    let mut cursor = None;
    let mut page_count = 0;
    let mut total_json_bytes = 0_usize;
    let mut seen_cursors = BTreeSet::new();
    let mut seen_templates = BTreeSet::new();
    loop {
        McpServerManager::validate_page_limit(server_name, "resources/templates/list", page_count)?;
        let page_request_id = request_id + page_count as u64;
        page_count += 1;

        let list = session.request::<_, McpListResourceTemplatesResult>(
            JsonRpcId::Number(page_request_id),
            "resources/templates/list",
            Some(McpListResourceTemplatesParams {
                cursor: cursor.clone(),
            }),
            timeout_ms,
        )?;
        let result = jsonrpc_result(server_name, "resources/templates/list", list)?;

        let page_json =
            McpServerManager::json_size(server_name, "resources/templates/list", &result)?;
        McpServerManager::validate_json_size(
            server_name,
            "resources/templates/list",
            &result,
            MCP_MAX_RESULT_JSON_BYTES,
            "resources/templates/list page JSON",
        )?;
        total_json_bytes = total_json_bytes.saturating_add(page_json.len());
        McpServerManager::validate_aggregate_json_size(
            server_name,
            "resources/templates/list",
            total_json_bytes,
        )?;

        for template in &result.resource_templates {
            McpServerManager::validate_json_size(
                server_name,
                "resources/templates/list",
                template,
                MCP_MAX_CATALOG_ITEM_JSON_BYTES,
                "resource template catalog item JSON",
            )?;
            if !seen_templates.insert(template.uri_template.clone()) {
                return Err(McpServerManager::duplicate_catalog_item(
                    server_name,
                    "resources/templates/list",
                    "resource template uriTemplate",
                    &template.uri_template,
                ));
            }
        }

        resource_templates.extend(result.resource_templates);
        McpServerManager::validate_total_items(
            server_name,
            "resources/templates/list",
            resource_templates.len(),
        )?;

        match result.next_cursor {
            Some(next_cursor) => {
                cursor = Some(McpServerManager::validate_next_cursor(
                    server_name,
                    "resources/templates/list",
                    next_cursor,
                    &mut seen_cursors,
                )?);
            }
            None => break,
        }
    }

    let result = McpListResourceTemplatesResult {
        resource_templates,
        next_cursor: None,
    };
    McpServerManager::validate_json_size(
        server_name,
        "resources/templates/list",
        &result,
        MCP_MAX_RESULT_JSON_BYTES,
        "resources/templates/list aggregate JSON",
    )?;
    Ok(result)
}

fn list_sse_prompts_pages(
    server_name: &str,
    session: &mut McpSseSession,
    request_id: u64,
    timeout_ms: u64,
) -> Result<McpListPromptsResult, McpServerManagerError> {
    let mut prompts = Vec::new();
    let mut cursor = None;
    let mut page_count = 0;
    let mut total_json_bytes = 0_usize;
    let mut seen_cursors = BTreeSet::new();
    let mut seen_names = BTreeSet::new();
    loop {
        McpServerManager::validate_page_limit(server_name, "prompts/list", page_count)?;
        let page_request_id = request_id + page_count as u64;
        page_count += 1;

        let list = session.request::<_, McpListPromptsResult>(
            JsonRpcId::Number(page_request_id),
            "prompts/list",
            Some(McpListPromptsParams {
                cursor: cursor.clone(),
            }),
            timeout_ms,
        )?;
        let result = jsonrpc_result(server_name, "prompts/list", list)?;

        let page_json = McpServerManager::json_size(server_name, "prompts/list", &result)?;
        McpServerManager::validate_json_size(
            server_name,
            "prompts/list",
            &result,
            MCP_MAX_RESULT_JSON_BYTES,
            "prompts/list page JSON",
        )?;
        total_json_bytes = total_json_bytes.saturating_add(page_json.len());
        McpServerManager::validate_aggregate_json_size(
            server_name,
            "prompts/list",
            total_json_bytes,
        )?;

        for prompt in &result.prompts {
            McpServerManager::validate_json_size(
                server_name,
                "prompts/list",
                prompt,
                MCP_MAX_CATALOG_ITEM_JSON_BYTES,
                "prompt catalog item JSON",
            )?;
            if !seen_names.insert(prompt.name.clone()) {
                return Err(McpServerManager::duplicate_catalog_item(
                    server_name,
                    "prompts/list",
                    "prompt name",
                    &prompt.name,
                ));
            }
        }

        prompts.extend(result.prompts);
        McpServerManager::validate_total_items(server_name, "prompts/list", prompts.len())?;

        match result.next_cursor {
            Some(next_cursor) => {
                cursor = Some(McpServerManager::validate_next_cursor(
                    server_name,
                    "prompts/list",
                    next_cursor,
                    &mut seen_cursors,
                )?);
            }
            None => break,
        }
    }

    let result = McpListPromptsResult {
        prompts,
        next_cursor: None,
    };
    McpServerManager::validate_json_size(
        server_name,
        "prompts/list",
        &result,
        MCP_MAX_RESULT_JSON_BYTES,
        "prompts/list aggregate JSON",
    )?;
    Ok(result)
}

struct SseOperationResult<T> {
    initialize_result: McpInitializeResult,
    result: T,
}

fn ensure_sse_capability(
    server_name: &str,
    capabilities: &McpServerCapabilities,
    capability: McpCapabilityKind,
) -> Result<(), McpServerManagerError> {
    if capabilities.supports(capability) {
        Ok(())
    } else {
        Err(McpServerManagerError::UnsupportedCapability {
            server_name: server_name.to_string(),
            capability,
        })
    }
}

fn discover_sse_tools(
    server_name: &str,
    transport: &McpRemoteTransport,
    request_id: u64,
) -> Result<McpSseToolDiscovery, McpServerManagerError> {
    let timeout_ms = sse_operation_timeout_ms(transport);
    let (mut session, initialize_result, capabilities) =
        connect_initialized_sse_session(server_name, transport, request_id, timeout_ms)?;
    if !capabilities.tools {
        return Ok(McpSseToolDiscovery {
            initialize_result,
            tools: Vec::new(),
        });
    }
    ping_sse_session(
        server_name,
        transport,
        &mut session,
        request_id + 1,
        timeout_ms,
    )?;
    let tools = list_sse_tools_pages(server_name, &mut session, request_id + 2, timeout_ms)?;
    Ok(McpSseToolDiscovery {
        initialize_result,
        tools,
    })
}

fn call_sse_tool(
    server_name: &str,
    transport: &McpRemoteTransport,
    request_id: u64,
    raw_name: String,
    arguments: Option<JsonValue>,
    timeout_ms: u64,
) -> Result<JsonRpcResponse<McpToolCallResult>, McpServerManagerError> {
    let (mut session, _initialize_result, capabilities) =
        connect_initialized_sse_session(server_name, transport, request_id, timeout_ms)?;
    ensure_sse_capability(server_name, &capabilities, McpCapabilityKind::Tools)?;
    ping_sse_session(
        server_name,
        transport,
        &mut session,
        request_id + 1,
        timeout_ms,
    )?;
    session.request(
        JsonRpcId::Number(request_id + 2),
        "tools/call",
        Some(McpToolCallParams {
            name: raw_name,
            arguments,
            meta: None,
        }),
        timeout_ms,
    )
}

fn list_sse_resources(
    server_name: &str,
    transport: &McpRemoteTransport,
    request_id: u64,
) -> Result<SseOperationResult<McpListResourcesResult>, McpServerManagerError> {
    let timeout_ms = sse_operation_timeout_ms(transport);
    let (mut session, initialize_result, capabilities) =
        connect_initialized_sse_session(server_name, transport, request_id, timeout_ms)?;
    ensure_sse_capability(server_name, &capabilities, McpCapabilityKind::Resources)?;
    ping_sse_session(
        server_name,
        transport,
        &mut session,
        request_id + 1,
        timeout_ms,
    )?;
    let result = list_sse_resources_pages(server_name, &mut session, request_id + 2, timeout_ms)?;
    Ok(SseOperationResult {
        initialize_result,
        result,
    })
}

fn list_sse_resource_templates(
    server_name: &str,
    transport: &McpRemoteTransport,
    request_id: u64,
) -> Result<SseOperationResult<McpListResourceTemplatesResult>, McpServerManagerError> {
    let timeout_ms = sse_operation_timeout_ms(transport);
    let (mut session, initialize_result, capabilities) =
        connect_initialized_sse_session(server_name, transport, request_id, timeout_ms)?;
    ensure_sse_capability(
        server_name,
        &capabilities,
        McpCapabilityKind::ResourceTemplates,
    )?;
    ping_sse_session(
        server_name,
        transport,
        &mut session,
        request_id + 1,
        timeout_ms,
    )?;
    let result =
        list_sse_resource_templates_pages(server_name, &mut session, request_id + 2, timeout_ms)?;
    Ok(SseOperationResult {
        initialize_result,
        result,
    })
}

fn read_sse_resource(
    server_name: &str,
    transport: &McpRemoteTransport,
    request_id: u64,
    uri: String,
) -> Result<SseOperationResult<McpReadResourceResult>, McpServerManagerError> {
    let timeout_ms = sse_operation_timeout_ms(transport);
    let (mut session, initialize_result, capabilities) =
        connect_initialized_sse_session(server_name, transport, request_id, timeout_ms)?;
    ensure_sse_capability(server_name, &capabilities, McpCapabilityKind::Resources)?;
    ping_sse_session(
        server_name,
        transport,
        &mut session,
        request_id + 1,
        timeout_ms,
    )?;
    let response: JsonRpcResponse<McpReadResourceResult> = session.request(
        JsonRpcId::Number(request_id + 2),
        "resources/read",
        Some(McpReadResourceParams { uri }),
        timeout_ms,
    )?;
    let result: McpReadResourceResult = jsonrpc_result(server_name, "resources/read", response)?;
    if result.contents.len() > MCP_MAX_RESOURCE_CONTENTS {
        return Err(McpServerManagerError::LimitExceeded {
            server_name: server_name.to_string(),
            method: "resources/read",
            limit: MCP_MAX_RESOURCE_CONTENTS,
            details: format!(
                "server returned {} resource contents",
                result.contents.len()
            ),
        });
    }
    McpServerManager::validate_json_size(
        server_name,
        "resources/read",
        &result,
        MCP_MAX_RESULT_JSON_BYTES,
        "resources/read result JSON",
    )?;
    for content in &result.contents {
        McpServerManager::validate_json_size(
            server_name,
            "resources/read",
            content,
            MCP_MAX_CATALOG_ITEM_JSON_BYTES,
            "resource content JSON",
        )?;
    }
    Ok(SseOperationResult {
        initialize_result,
        result,
    })
}

fn list_sse_prompts(
    server_name: &str,
    transport: &McpRemoteTransport,
    request_id: u64,
) -> Result<SseOperationResult<McpListPromptsResult>, McpServerManagerError> {
    let timeout_ms = sse_operation_timeout_ms(transport);
    let (mut session, initialize_result, capabilities) =
        connect_initialized_sse_session(server_name, transport, request_id, timeout_ms)?;
    ensure_sse_capability(server_name, &capabilities, McpCapabilityKind::Prompts)?;
    ping_sse_session(
        server_name,
        transport,
        &mut session,
        request_id + 1,
        timeout_ms,
    )?;
    let result = list_sse_prompts_pages(server_name, &mut session, request_id + 2, timeout_ms)?;
    Ok(SseOperationResult {
        initialize_result,
        result,
    })
}

fn get_sse_prompt(
    server_name: &str,
    transport: &McpRemoteTransport,
    request_id: u64,
    name: String,
    arguments: Option<JsonValue>,
) -> Result<SseOperationResult<McpGetPromptResult>, McpServerManagerError> {
    let timeout_ms = sse_operation_timeout_ms(transport);
    let (mut session, initialize_result, capabilities) =
        connect_initialized_sse_session(server_name, transport, request_id, timeout_ms)?;
    ensure_sse_capability(server_name, &capabilities, McpCapabilityKind::Prompts)?;
    ping_sse_session(
        server_name,
        transport,
        &mut session,
        request_id + 1,
        timeout_ms,
    )?;
    let response: JsonRpcResponse<McpGetPromptResult> = session.request(
        JsonRpcId::Number(request_id + 2),
        "prompts/get",
        Some(McpGetPromptParams { name, arguments }),
        timeout_ms,
    )?;
    let result: McpGetPromptResult = jsonrpc_result(server_name, "prompts/get", response)?;
    if result.messages.len() > MCP_MAX_PROMPT_MESSAGES {
        return Err(McpServerManagerError::LimitExceeded {
            server_name: server_name.to_string(),
            method: "prompts/get",
            limit: MCP_MAX_PROMPT_MESSAGES,
            details: format!("server returned {} prompt messages", result.messages.len()),
        });
    }
    McpServerManager::validate_json_size(
        server_name,
        "prompts/get",
        &result,
        MCP_MAX_RESULT_JSON_BYTES,
        "prompts/get result JSON",
    )?;
    for message in &result.messages {
        McpServerManager::validate_json_size(
            server_name,
            "prompts/get",
            message,
            MCP_MAX_CATALOG_ITEM_JSON_BYTES,
            "prompt message JSON",
        )?;
    }
    Ok(SseOperationResult {
        initialize_result,
        result,
    })
}

struct McpSseToolDiscovery {
    initialize_result: McpInitializeResult,
    tools: Vec<ManagedMcpTool>,
}

struct McpSseCatalogDiscovery {
    initialize_result: McpInitializeResult,
    tools: Vec<ManagedMcpTool>,
    resources: Vec<McpResource>,
    resource_templates: Vec<McpResourceTemplate>,
    prompts: Vec<McpPrompt>,
    tools_complete: bool,
    resources_complete: bool,
    resource_templates_complete: bool,
    prompts_complete: bool,
    degraded_capabilities: Vec<McpCapabilityDegradation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SseDiscoveryMode {
    Strict,
    BestEffort,
}

impl SseDiscoveryMode {
    fn best_effort(self) -> bool {
        matches!(self, Self::BestEffort)
    }
}

fn sse_operation_timeout_ms(transport: &McpRemoteTransport) -> u64 {
    transport
        .tool_call_timeout_ms
        .or(transport.heartbeat_timeout_ms)
        .unwrap_or(MCP_LIST_TOOLS_TIMEOUT_MS)
}

fn discover_sse_catalog(
    server_name: &str,
    required: bool,
    transport: &McpRemoteTransport,
    request_id: u64,
    mode: SseDiscoveryMode,
) -> Result<McpSseCatalogDiscovery, McpServerManagerError> {
    let timeout_ms = sse_operation_timeout_ms(transport);
    let (mut session, initialize_result, capabilities) =
        connect_initialized_sse_session(server_name, transport, request_id, timeout_ms)?;
    let mut tools = Vec::new();
    let mut resources = Vec::new();
    let mut resource_templates = Vec::new();
    let mut prompts = Vec::new();
    let mut tools_complete = true;
    let mut resources_complete = true;
    let mut resource_templates_complete = true;
    let mut prompts_complete = true;
    let mut degraded_capabilities = Vec::new();

    let should_ping = capabilities.tools || capabilities.resources || capabilities.prompts;
    if should_ping {
        ping_sse_session(
            server_name,
            transport,
            &mut session,
            request_id + 1,
            timeout_ms,
        )?;
    }

    if capabilities.tools {
        tools = list_sse_tools_pages(server_name, &mut session, request_id + 2, timeout_ms)?;
    }

    if capabilities.resources {
        match list_sse_resources_pages(
            server_name,
            &mut session,
            request_id + 2 + MCP_MAX_PAGINATION_PAGES as u64,
            timeout_ms,
        ) {
            Ok(result) => {
                resources = result.resources;
                match list_sse_resource_templates_pages(
                    server_name,
                    &mut session,
                    request_id + 2 + (MCP_MAX_PAGINATION_PAGES as u64 * 2),
                    timeout_ms,
                ) {
                    Ok(result) => resource_templates = result.resource_templates,
                    Err(error)
                        if McpServerManager::is_method_not_found(
                            &error,
                            "resources/templates/list",
                        ) =>
                    {
                        resource_templates.clear();
                    }
                    Err(error) if mode.best_effort() => {
                        resource_templates_complete = false;
                        degraded_capabilities.push(capability_degradation_for_sse_error(
                            server_name,
                            required,
                            McpCapabilityKind::ResourceTemplates,
                            "resources/templates/list",
                            &error,
                        ));
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) if mode.best_effort() => {
                resources_complete = false;
                resource_templates_complete = false;
                degraded_capabilities.push(capability_degradation_for_sse_error(
                    server_name,
                    required,
                    McpCapabilityKind::Resources,
                    "resources/list",
                    &error,
                ));
            }
            Err(error) => return Err(error),
        }
    }

    if capabilities.prompts {
        match list_sse_prompts_pages(
            server_name,
            &mut session,
            request_id + 2 + (MCP_MAX_PAGINATION_PAGES as u64 * 3),
            timeout_ms,
        ) {
            Ok(result) => prompts = result.prompts,
            Err(error) if mode.best_effort() => {
                prompts_complete = false;
                degraded_capabilities.push(capability_degradation_for_sse_error(
                    server_name,
                    required,
                    McpCapabilityKind::Prompts,
                    "prompts/list",
                    &error,
                ));
            }
            Err(error) => return Err(error),
        }
    }

    if !capabilities.tools {
        tools_complete = true;
    }
    if !capabilities.resources {
        resources_complete = true;
        resource_templates_complete = true;
    }
    if !capabilities.prompts {
        prompts_complete = true;
    }

    Ok(McpSseCatalogDiscovery {
        initialize_result,
        tools,
        resources,
        resource_templates,
        prompts,
        tools_complete,
        resources_complete,
        resource_templates_complete,
        prompts_complete,
        degraded_capabilities,
    })
}

fn capability_degradation_for_sse_error(
    server_name: &str,
    required: bool,
    capability: McpCapabilityKind,
    method: &'static str,
    error: &McpServerManagerError,
) -> McpCapabilityDegradation {
    let mut context = error.error_context();
    context.insert("capability".to_string(), capability.as_str().to_string());
    context.insert("method".to_string(), method.to_string());
    context.insert("transport".to_string(), "sse".to_string());
    McpCapabilityDegradation {
        server_name: server_name.to_string(),
        phase: lifecycle_phase_for_method(method),
        required,
        capability,
        method,
        reason: error.to_string(),
        context,
    }
}

fn initialize_sse_session(
    server_name: &str,
    transport: &McpRemoteTransport,
    session: &mut McpSseSession,
    request_id: u64,
    timeout_ms: u64,
    protocol_selection: &McpProtocolSelection,
) -> Result<McpInitializeResult, McpServerManagerError> {
    let requested_protocol_version = protocol_selection.requested_protocol_version.clone();
    let initialize = session.request::<_, McpInitializeResult>(
        JsonRpcId::Number(request_id),
        "initialize",
        Some(McpInitializeParams {
            protocol_version: requested_protocol_version.clone(),
            capabilities: transport.capabilities.clone(),
            client_info: McpInitializeClientInfo {
                name: "runtime".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        }),
        timeout_ms,
    )?;
    if let Some(error) = initialize.error {
        return Err(McpServerManagerError::JsonRpc {
            server_name: server_name.to_string(),
            method: "initialize",
            error,
        });
    }
    let Some(result) = initialize.result else {
        return Err(McpServerManagerError::InvalidResponse {
            server_name: server_name.to_string(),
            method: "initialize",
            details: "missing result payload".to_string(),
        });
    };
    let _negotiated_protocol_version = negotiate_initialize_protocol_version(
        server_name,
        protocol_selection.transport_policy,
        &requested_protocol_version,
        &result.protocol_version,
    )?;
    Ok(result)
}

#[derive(Debug)]
pub struct McpStdioProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl McpStdioProcess {
    pub fn spawn(transport: &McpStdioTransport) -> io::Result<Self> {
        let mut command = stdio_command(&transport.command, &transport.args);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        apply_env(&mut command, &transport.env);

        let mut child = command.spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("stdio MCP process missing stdin pipe"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("stdio MCP process missing stdout pipe"))?;

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    pub async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.stdin.write_all(bytes).await
    }

    pub async fn flush(&mut self) -> io::Result<()> {
        self.stdin.flush().await
    }

    pub async fn write_line(&mut self, line: &str) -> io::Result<()> {
        self.write_all(line.as_bytes()).await?;
        self.write_all(b"\n").await?;
        self.flush().await
    }

    pub async fn read_line(&mut self) -> io::Result<String> {
        let mut line = String::new();
        let bytes_read = self.stdout.read_line(&mut line).await?;
        if bytes_read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "MCP stdio stream closed while reading line",
            ));
        }
        Ok(line)
    }

    pub async fn read_available(&mut self) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0_u8; 4096];
        let read = self.stdout.read(&mut buffer).await?;
        buffer.truncate(read);
        Ok(buffer)
    }

    pub async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        if payload.len() > MCP_MAX_JSONRPC_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "MCP stdio JSON-RPC line exceeded {} byte limit: {}",
                    MCP_MAX_JSONRPC_FRAME_BYTES,
                    payload.len()
                ),
            ));
        }
        if payload.contains(&b'\n') || payload.contains(&b'\r') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MCP stdio JSON-RPC messages must be single-line JSON",
            ));
        }
        self.write_all(payload).await?;
        self.write_all(b"\n").await?;
        self.flush().await
    }

    pub async fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        read_limited_jsonrpc_line(&mut self.stdout)
            .await?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "MCP stdio stream closed while reading JSON-RPC line",
                )
            })
    }

    pub async fn write_jsonrpc_message<T: Serialize>(&mut self, message: &T) -> io::Result<()> {
        let body = serde_json::to_vec(message)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if body.len() > MCP_MAX_JSONRPC_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "MCP stdio JSON-RPC request exceeded {} byte limit: {}",
                    MCP_MAX_JSONRPC_FRAME_BYTES,
                    body.len()
                ),
            ));
        }
        self.write_frame(&body).await
    }

    pub async fn read_jsonrpc_message<T: DeserializeOwned>(&mut self) -> io::Result<T> {
        let payload = self.read_frame().await?;
        serde_json::from_slice(&payload)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub async fn send_request<T: Serialize>(
        &mut self,
        request: &JsonRpcRequest<T>,
    ) -> io::Result<()> {
        self.write_jsonrpc_message(request).await
    }

    pub async fn notify<T: Serialize>(
        &mut self,
        method: impl Into<String>,
        params: Option<T>,
    ) -> io::Result<()> {
        let notification = JsonRpcNotification::new(method, params);
        self.write_jsonrpc_message(&notification).await
    }

    pub async fn read_response<T: DeserializeOwned>(&mut self) -> io::Result<JsonRpcResponse<T>> {
        self.read_jsonrpc_message().await
    }

    pub async fn request<TParams: Serialize, TResult: DeserializeOwned>(
        &mut self,
        id: JsonRpcId,
        method: impl Into<String>,
        params: Option<TParams>,
    ) -> io::Result<JsonRpcResponse<TResult>> {
        let method = method.into();
        let request = JsonRpcRequest::new(id.clone(), method.clone(), params);
        self.send_request(&request).await?;
        let response = self.read_response().await?;

        if response.jsonrpc != "2.0" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "MCP response for {method} used unsupported jsonrpc version `{}`",
                    response.jsonrpc
                ),
            ));
        }

        if response.id != id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "MCP response for {method} used mismatched id: expected {id:?}, got {:?}",
                    response.id
                ),
            ));
        }

        Ok(response)
    }

    pub async fn initialize(
        &mut self,
        id: JsonRpcId,
        params: McpInitializeParams,
    ) -> io::Result<JsonRpcResponse<McpInitializeResult>> {
        self.request(id, "initialize", Some(params)).await
    }

    pub async fn list_tools(
        &mut self,
        id: JsonRpcId,
        params: Option<McpListToolsParams>,
    ) -> io::Result<JsonRpcResponse<McpListToolsResult>> {
        self.request(id, "tools/list", params).await
    }

    pub async fn call_tool(
        &mut self,
        id: JsonRpcId,
        params: McpToolCallParams,
    ) -> io::Result<JsonRpcResponse<McpToolCallResult>> {
        self.request(id, "tools/call", Some(params)).await
    }

    pub async fn list_resources(
        &mut self,
        id: JsonRpcId,
        params: Option<McpListResourcesParams>,
    ) -> io::Result<JsonRpcResponse<McpListResourcesResult>> {
        self.request(id, "resources/list", params).await
    }

    pub async fn list_resource_templates(
        &mut self,
        id: JsonRpcId,
        params: Option<McpListResourceTemplatesParams>,
    ) -> io::Result<JsonRpcResponse<McpListResourceTemplatesResult>> {
        self.request(id, "resources/templates/list", params).await
    }

    pub async fn read_resource(
        &mut self,
        id: JsonRpcId,
        params: McpReadResourceParams,
    ) -> io::Result<JsonRpcResponse<McpReadResourceResult>> {
        self.request(id, "resources/read", Some(params)).await
    }

    pub async fn list_prompts(
        &mut self,
        id: JsonRpcId,
        params: Option<McpListPromptsParams>,
    ) -> io::Result<JsonRpcResponse<McpListPromptsResult>> {
        self.request(id, "prompts/list", params).await
    }

    pub async fn get_prompt(
        &mut self,
        id: JsonRpcId,
        params: Option<McpGetPromptParams>,
    ) -> io::Result<JsonRpcResponse<McpGetPromptResult>> {
        self.request(id, "prompts/get", params).await
    }

    pub async fn terminate(&mut self) -> io::Result<()> {
        self.child.kill().await
    }

    pub async fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        self.child.wait().await
    }

    pub fn has_exited(&mut self) -> io::Result<bool> {
        Ok(self.child.try_wait()?.is_some())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        if self.child.try_wait()?.is_none() {
            match self.child.kill().await {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
                Err(error) => return Err(error),
            }
        }
        let _ = self.child.wait().await?;
        Ok(())
    }
}

fn stdio_command(command: &str, args: &[String]) -> Command {
    #[cfg(windows)]
    {
        if command == "python3" {
            let mut process = Command::new("python");
            process.args(args);
            return process;
        }
        if command.ends_with(".py") {
            let mut process = Command::new("python");
            process.arg(command);
            process.args(args);
            return process;
        }
        if command == "/bin/sh" || command.ends_with(".sh") {
            if let Some(shell) = windows_shell() {
                let mut process = Command::new(shell);
                process.arg("--noprofile").arg("--norc");
                if command == "/bin/sh" {
                    process.args(args.iter().map(|arg| arg.replace('\\', "/")));
                } else {
                    process.arg(command.replace('\\', "/"));
                    process.args(args);
                }
                return process;
            }
        }
    }

    let mut process = Command::new(command);
    process.args(args);
    process
}

#[cfg(windows)]
fn windows_shell() -> Option<&'static str> {
    for path in [
        r"C:\msys64\usr\bin\bash.exe",
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\msys64\usr\bin\sh.exe",
        r"C:\Program Files\Git\bin\sh.exe",
    ] {
        if std::path::Path::new(path).exists() {
            return Some(path);
        }
    }
    None
}

pub fn spawn_mcp_stdio_process(bootstrap: &McpClientBootstrap) -> io::Result<McpStdioProcess> {
    match &bootstrap.transport {
        McpClientTransport::Stdio(transport) => McpStdioProcess::spawn(transport),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "MCP bootstrap transport for {} is not stdio: {other:?}",
                bootstrap.server_name
            ),
        )),
    }
}

fn apply_env(command: &mut Command, env: &BTreeMap<String, String>) {
    for (key, value) in env {
        command.env(key, value);
    }
}

async fn read_limited_jsonrpc_line<R>(reader: &mut R) -> io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let mut payload = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if payload.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "MCP stdio stream closed before JSON-RPC newline",
            ));
        }

        if let Some(newline_index) = available.iter().position(|byte| *byte == b'\n') {
            if payload.len().saturating_add(newline_index) > MCP_MAX_JSONRPC_FRAME_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "MCP stdio JSON-RPC line exceeded {} byte limit",
                        MCP_MAX_JSONRPC_FRAME_BYTES
                    ),
                ));
            }
            payload.extend_from_slice(&available[..newline_index]);
            reader.consume(newline_index + 1);
            if payload.last() == Some(&b'\r') {
                payload.pop();
            }
            if payload.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MCP stdio JSON-RPC line must not be empty",
                ));
            }
            if payload.contains(&b'\r') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "MCP stdio JSON-RPC line must not contain carriage returns",
                ));
            }
            std::str::from_utf8(&payload)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            return Ok(Some(payload));
        }

        if payload.len().saturating_add(available.len()) > MCP_MAX_JSONRPC_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "MCP stdio JSON-RPC line exceeded {} byte limit",
                    MCP_MAX_JSONRPC_FRAME_BYTES
                ),
            ));
        }
        let available_len = available.len();
        payload.extend_from_slice(available);
        reader.consume(available_len);
    }
}

fn default_initialize_params() -> McpInitializeParams {
    McpInitializeParams {
        protocol_version: LATEST_STDIO_MCP_PROTOCOL_VERSION.to_string(),
        capabilities: JsonValue::Object(serde_json::Map::new()),
        client_info: McpInitializeClientInfo {
            name: "runtime".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    }
}

fn initialize_params_for_bootstrap(
    bootstrap: &McpClientBootstrap,
) -> Result<McpInitializeParams, McpProtocolVersionError> {
    let mut params = default_initialize_params();
    params.protocol_version = bootstrap
        .select_protocol_version()?
        .requested_protocol_version;
    match &bootstrap.transport {
        McpClientTransport::Stdio(transport) => {
            if let Some(capabilities) = transport.env.get("CLAWD_MCP_CAPABILITIES") {
                if let Ok(value) = serde_json::from_str::<JsonValue>(capabilities) {
                    params.capabilities = value;
                }
            }
        }
        McpClientTransport::Sse(transport) => {
            params.capabilities = transport.capabilities.clone();
        }
        _ => {}
    }
    Ok(params)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::ErrorKind;
    use std::io::{Read as _, Write as _};
    use std::net::{TcpListener, TcpStream};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use serde_json::json;
    use tokio::io::BufReader;
    use tokio::runtime::Builder;

    use crate::config::{
        ConfigSource, McpRemoteServerConfig, McpSdkServerConfig, McpServerConfig,
        McpStdioServerConfig, McpWebSocketServerConfig, ScopedMcpServerConfig,
    };
    use crate::mcp::mcp_tool_name;
    use crate::mcp_client::{
        McpClientAuth, McpClientBootstrap, McpProtocolTransportPolicy, McpRemoteTransport,
    };

    use super::{
        build_sse_client, build_sse_get_client, build_sse_get_runtime, build_sse_headers,
        parse_and_validate_sse_url, read_limited_jsonrpc_line, resolve_sse_endpoint,
        spawn_mcp_stdio_process, sse_operation_deadline, unsupported_server_failed_server,
        validate_sse_get_response, validate_sse_response_header_budget, JsonRpcId, JsonRpcRequest,
        JsonRpcResponse, McpGetPromptParams, McpHeartbeatStatus, McpInitializeClientInfo,
        McpInitializeParams, McpInitializeResult, McpInitializeServerInfo, McpListPromptsParams,
        McpListResourceTemplatesParams, McpListResourcesParams, McpListToolsParams,
        McpReadResourceParams, McpReadResourceResult, McpServerManager, McpServerManagerError,
        McpSseSession, McpStdioProcess, McpToolCallParams, MCP_MAX_JSONRPC_FRAME_BYTES,
        MCP_SSE_MAX_HEADER_BYTES, MCP_SSE_MAX_HTTP_RESPONSE_BODY_BYTES, MCP_SSE_MAX_URL_BYTES,
    };
    use crate::{McpCapabilityKind, McpLifecyclePhase};

    fn temp_dir() -> PathBuf {
        static NEXT_TEMP_DIR_ID: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be after epoch")
            .as_nanos();
        let unique_id = NEXT_TEMP_DIR_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("runtime-mcp-stdio-{nanos}-{unique_id}"))
    }

    fn write_echo_script() -> PathBuf {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("temp dir");
        let script_path = root.join("echo-mcp.sh");
        fs::write(
            &script_path,
            "#!/bin/sh\nprintf 'READY:%s\\n' \"$MCP_TEST_TOKEN\"\nIFS= read -r line\nprintf 'ECHO:%s\\n' \"$line\"\n",
        )
        .expect("write script");
        make_executable(&script_path);
        script_path
    }

    fn write_jsonrpc_script() -> PathBuf {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("temp dir");
        let script_path = root.join("jsonrpc-mcp.py");
        let script = [
            "#!/usr/bin/env python3",
            "import json, os, sys",
            "MISMATCHED_RESPONSE_ID = os.environ.get('MCP_MISMATCHED_RESPONSE_ID') == '1'",
            "RESPONSE_NEWLINE = b'\\r\\n' if os.environ.get('MCP_RESPONSE_CRLF') == '1' else b'\\n'",
            "line = sys.stdin.buffer.readline()",
            "if not line:",
            "        raise SystemExit(1)",
            "request = json.loads(line.decode())",
            r"assert request['jsonrpc'] == '2.0'",
            r"assert request['method'] == 'initialize'",
            "response_id = 'wrong-id' if MISMATCHED_RESPONSE_ID else request['id']",
            r"response = json.dumps({",
            r"    'jsonrpc': '2.0',",
            r"    'id': response_id,",
            r"    'result': {",
            r"        'protocolVersion': request['params']['protocolVersion'],",
            r"        'capabilities': {'tools': {}},",
            r"        'serverInfo': {'name': 'fake-mcp', 'version': '0.1.0'}",
            r"    }",
            r"}).encode()",
            "sys.stdout.buffer.write(response + RESPONSE_NEWLINE)",
            "sys.stdout.buffer.flush()",
            "",
        ]
        .join("\n");
        fs::write(&script_path, script).expect("write script");
        make_executable(&script_path);
        script_path
    }

    #[allow(clippy::too_many_lines)]
    fn write_mcp_server_script() -> PathBuf {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("temp dir");
        let script_path = root.join("fake-mcp-server.py");
        let script = [
            "#!/usr/bin/env python3",
            "import json, os, sys, time",
            "TOOL_CALL_DELAY_MS = int(os.environ.get('MCP_TOOL_CALL_DELAY_MS', '0'))",
            "INVALID_TOOL_CALL_RESPONSE = os.environ.get('MCP_INVALID_TOOL_CALL_RESPONSE') == '1'",
            "OMIT_RESULT_METHOD = os.environ.get('MCP_OMIT_RESULT_METHOD')",
            "PAGINATION_LOOP_METHOD = os.environ.get('MCP_PAGINATION_LOOP_METHOD')",
            "EMPTY_CURSOR_METHOD = os.environ.get('MCP_EMPTY_CURSOR_METHOD')",
            "DUPLICATE_LIST_METHOD = os.environ.get('MCP_DUPLICATE_LIST_METHOD')",
            "LOG_PATH = os.environ.get('MCP_LOG_PATH')",
            "CAPABILITIES = {'tools': {}, 'resources': {}, 'prompts': {}}",
            "if os.environ.get('MCP_DISABLE_TOOLS') == '1':",
            "    CAPABILITIES.pop('tools', None)",
            "if os.environ.get('MCP_DISABLE_RESOURCES') == '1':",
            "    CAPABILITIES.pop('resources', None)",
            "if os.environ.get('MCP_DISABLE_PROMPTS') == '1':",
            "    CAPABILITIES.pop('prompts', None)",
            "capability_overrides = os.environ.get('MCP_CAPABILITY_OVERRIDES')",
            "if capability_overrides:",
            "    CAPABILITIES.update(json.loads(capability_overrides))",
            "",
            "def log(method):",
            "    if LOG_PATH:",
            "        with open(LOG_PATH, 'a', encoding='utf-8') as handle:",
            "            handle.write(f'{method}\\n')",
            "",
            "def read_message():",
            "    line = sys.stdin.buffer.readline()",
            "    if not line:",
            "        return None",
            "    return json.loads(line.decode())",
            "",
            "def send_message(message):",
            "    payload = json.dumps(message).encode()",
            "    sys.stdout.buffer.write(payload + b'\\n')",
            "    sys.stdout.buffer.flush()",
            "",
            "while True:",
            "    request = read_message()",
            "    if request is None:",
            "        break",
            "    method = request['method']",
            "    log(method)",
            "    if 'id' not in request:",
            "        continue",
            "    if method == OMIT_RESULT_METHOD:",
            "        send_message({'jsonrpc': '2.0', 'id': request['id']})",
            "        continue",
            "    if method == 'initialize':",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'result': {",
            "                'protocolVersion': request['params']['protocolVersion'],",
            "                'capabilities': CAPABILITIES,",
            "                'serverInfo': {'name': 'fake-mcp', 'version': '0.2.0'}",
            "            }",
            "        })",
            "    elif method == 'tools/list':",
            "        cursor = (request.get('params') or {}).get('cursor')",
            "        if cursor is None:",
            "            tools = [{",
            "                'name': 'echo',",
            "                'description': 'Echoes text',",
            "                'inputSchema': {",
            "                    'type': 'object',",
            "                    'properties': {'text': {'type': 'string'}},",
            "                    'required': ['text']",
            "                }",
            "            }]",
            "            next_cursor = 'tools-page-2'",
            "        else:",
            "            tools = [{",
            "                'name': 'inspect',",
            "                'description': 'Inspect fixture state',",
            "                'inputSchema': {'type': 'object'},",
            "                'outputSchema': {'type': 'object'}",
            "            }]",
            "            next_cursor = None",
            "        if PAGINATION_LOOP_METHOD == method:",
            "            next_cursor = 'loop'",
            "        if EMPTY_CURSOR_METHOD == method:",
            "            next_cursor = ''",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'result': {'tools': tools, 'nextCursor': next_cursor}",
            "        })",
            "    elif method == 'tools/call':",
            "        if INVALID_TOOL_CALL_RESPONSE:",
            "            sys.stdout.buffer.write(b'nope!\\n')",
            "            sys.stdout.buffer.flush()",
            "            continue",
            "        if TOOL_CALL_DELAY_MS:",
            "            time.sleep(TOOL_CALL_DELAY_MS / 1000)",
            "        args = request['params'].get('arguments') or {}",
            "        if request['params']['name'] == 'fail':",
            "            send_message({",
            "                'jsonrpc': '2.0',",
            "                'id': request['id'],",
            "                'error': {'code': -32001, 'message': 'tool failed'},",
            "            })",
            "        else:",
            "            text = args.get('text', '')",
            "            send_message({",
            "                'jsonrpc': '2.0',",
            "                'id': request['id'],",
            "                'result': {",
            "                    'content': [{'type': 'text', 'text': f'echo:{text}'}],",
            "                    'structuredContent': {'echoed': text},",
            "                    'isError': False",
            "                }",
            "            })",
            "    elif method == 'resources/list':",
            "        cursor = (request.get('params') or {}).get('cursor')",
            "        if cursor is None:",
            "            resources = [{",
            "                'uri': 'file://guide.txt',",
            "                'name': 'guide',",
            "                'title': 'Guide',",
            "                'description': 'Guide text',",
            "                'mimeType': 'text/plain'",
            "            }]",
            "            next_cursor = 'resources-page-2'",
            "        else:",
            "            resources = [{",
            "                'uri': 'file://guide.txt' if DUPLICATE_LIST_METHOD == method else 'file://status.json',",
            "                'name': 'status',",
            "                'description': 'Status JSON',",
            "                'mimeType': 'application/json',",
            "                'size': 17",
            "            }]",
            "            next_cursor = None",
            "        if PAGINATION_LOOP_METHOD == method:",
            "            next_cursor = 'loop'",
            "        if EMPTY_CURSOR_METHOD == method:",
            "            next_cursor = ''",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'result': {'resources': resources, 'nextCursor': next_cursor}",
            "        })",
            "    elif method == 'resources/templates/list':",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'result': {",
            "                'resourceTemplates': [{",
            "                    'uriTemplate': 'file://logs/{unit}.txt',",
            "                    'name': 'unit-log',",
            "                    'description': 'Unit log'",
            "                }]",
            "            }",
            "        })",
            "    elif method == 'prompts/list':",
            "        cursor = (request.get('params') or {}).get('cursor')",
            "        if cursor is None:",
            "            prompts = [{",
            "                'name': 'triage',",
            "                'title': 'Triage',",
            "                'description': 'Build a triage prompt',",
            "                'arguments': [{'name': 'service', 'required': True}]",
            "            }]",
            "            next_cursor = 'prompts-page-2'",
            "        else:",
            "            prompts = [{",
            "                'name': 'repair',",
            "                'description': 'Build a repair prompt',",
            "                'arguments': []",
            "            }]",
            "            next_cursor = None",
            "        if PAGINATION_LOOP_METHOD == method:",
            "            next_cursor = 'loop'",
            "        if EMPTY_CURSOR_METHOD == method:",
            "            next_cursor = ''",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'result': {'prompts': prompts, 'nextCursor': next_cursor}",
            "        })",
            "    elif method == 'prompts/get':",
            "        args = request['params'].get('arguments') or {}",
            "        prompt_name = request['params']['name']",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'result': {",
            "                'description': f'Prompt for {prompt_name}',",
            "                'messages': [",
            "                    {",
            "                        'role': 'user',",
            "                        'content': {'type': 'text', 'text': f\"{prompt_name}:{json.dumps(args, sort_keys=True)}\"}",
            "                    }",
            "                ]",
            "            }",
            "        })",
            "    elif method == 'resources/read':",
            "        uri = request['params']['uri']",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'result': {",
            "                'contents': [",
            "                    {",
            "                        'uri': uri,",
            "                        'mimeType': 'text/plain',",
            "                        'text': f'contents for {uri}'",
            "                    }",
            "                ]",
            "            }",
            "        })",
            "    else:",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'error': {'code': -32601, 'message': f'unknown method: {method}'},",
            "        })",
            "",
        ]
        .join("\n");
        fs::write(&script_path, script).expect("write script");
        make_executable(&script_path);
        script_path
    }

    #[allow(clippy::too_many_lines)]
    fn write_manager_mcp_server_script() -> PathBuf {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("temp dir");
        let script_path = root.join("manager-mcp-server.py");
        let script = [
            "#!/usr/bin/env python3",
            "import json, os, sys, time",
            "",
            "LABEL = os.environ.get('MCP_SERVER_LABEL', 'server')",
            "LOG_PATH = os.environ.get('MCP_LOG_PATH')",
            "EXIT_AFTER_TOOLS_LIST = os.environ.get('MCP_EXIT_AFTER_TOOLS_LIST') == '1'",
            "FAIL_ONCE_MODE = os.environ.get('MCP_FAIL_ONCE_MODE')",
            "FAIL_ONCE_MARKER = os.environ.get('MCP_FAIL_ONCE_MARKER')",
            "INITIALIZE_JSONRPC_ERROR = os.environ.get('MCP_INITIALIZE_JSONRPC_ERROR') == '1'",
            "INITIALIZE_JSONRPC_ERROR_ONCE = os.environ.get('MCP_INITIALIZE_JSONRPC_ERROR_ONCE') == '1'",
            "OMIT_PROTOCOL_VERSION = os.environ.get('MCP_OMIT_PROTOCOL_VERSION') == '1'",
            "PROTOCOL_VERSION_SET = 'MCP_PROTOCOL_VERSION' in os.environ",
            "PROTOCOL_VERSION = os.environ.get('MCP_PROTOCOL_VERSION')",
            "initialize_count = 0",
            "",
            "def log(method):",
            "    if LOG_PATH:",
            "        with open(LOG_PATH, 'a', encoding='utf-8') as handle:",
            "            handle.write(f'{method}\\n')",
            "",
            "def should_fail_once():",
            "    if not FAIL_ONCE_MODE or not FAIL_ONCE_MARKER:",
            "        return False",
            "    if os.path.exists(FAIL_ONCE_MARKER):",
            "        return False",
            "    with open(FAIL_ONCE_MARKER, 'w', encoding='utf-8') as handle:",
            "        handle.write(FAIL_ONCE_MODE)",
            "    return True",
            "",
            "def read_message():",
            "    line = sys.stdin.buffer.readline()",
            "    if not line:",
            "        return None",
            "    return json.loads(line.decode())",
            "",
            "def send_message(message):",
            "    payload = json.dumps(message).encode()",
            "    sys.stdout.buffer.write(payload + b'\\n')",
            "    sys.stdout.buffer.flush()",
            "",
            "while True:",
            "    request = read_message()",
            "    if request is None:",
            "        break",
            "    method = request['method']",
            "    log(method)",
            "    if 'id' not in request:",
            "        continue",
            "    if method == 'initialize':",
            "        if FAIL_ONCE_MODE == 'initialize_hang' and should_fail_once():",
            "            log('initialize-hang')",
            "            while True:",
            "                time.sleep(1)",
            "        if INITIALIZE_JSONRPC_ERROR or (INITIALIZE_JSONRPC_ERROR_ONCE and should_fail_once()):",
            "            send_message({",
            "                'jsonrpc': '2.0',",
            "                'id': request['id'],",
            "                'error': {'code': -32002, 'message': 'initialize rejected'}",
            "            })",
            "            continue",
            "        initialize_count += 1",
            "        result = {",
            "            'capabilities': {'tools': {}},",
            "            'serverInfo': {'name': LABEL, 'version': '1.0.0'}",
            "        }",
            "        if not OMIT_PROTOCOL_VERSION:",
            "            result['protocolVersion'] = PROTOCOL_VERSION if PROTOCOL_VERSION_SET else request['params']['protocolVersion']",
            "        send_message({'jsonrpc': '2.0', 'id': request['id'], 'result': result})",
            "    elif method == 'tools/list':",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'result': {",
            "                'tools': [",
            "                    {",
            "                        'name': 'echo',",
            "                        'description': f'Echo tool for {LABEL}',",
            "                        'inputSchema': {",
            "                            'type': 'object',",
            "                            'properties': {'text': {'type': 'string'}},",
            "                            'required': ['text']",
            "                        }",
            "                    }",
            "                ]",
            "            }",
            "        })",
            "        if EXIT_AFTER_TOOLS_LIST:",
            "            raise SystemExit(0)",
            "    elif method == 'tools/call':",
            "        if FAIL_ONCE_MODE == 'tool_call_disconnect' and should_fail_once():",
            "            log('tools/call-disconnect')",
            "            raise SystemExit(0)",
            "        args = request['params'].get('arguments') or {}",
            "        text = args.get('text', '')",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'result': {",
            "                'content': [{'type': 'text', 'text': f'{LABEL}:{text}'}],",
            "                'structuredContent': {",
            "                    'server': LABEL,",
            "                    'echoed': text,",
            "                    'initializeCount': initialize_count",
            "                },",
            "                'isError': False",
            "            }",
            "        })",
            "    elif method == 'prompts/list':",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'result': {",
            "                'prompts': [",
            "                    {",
            "                        'name': 'triage',",
            "                        'description': f'Triage prompt for {LABEL}',",
            "                        'arguments': [",
            "                            {",
            "                                'name': 'service',",
            "                                'description': 'Service name',",
            "                                'required': True",
            "                            }",
            "                        ]",
            "                    }",
            "                ],",
            "                'nextCursor': None",
            "            }",
            "        })",
            "    elif method == 'prompts/get':",
            "        args = request['params'].get('arguments') or {}",
            "        prompt_name = request['params']['name']",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'result': {",
            "                'description': f'Prompt for {LABEL}:{prompt_name}',",
            "                'messages': [",
            "                    {",
            "                        'role': 'user',",
            "                        'content': {'type': 'text', 'text': f\"{prompt_name}:{json.dumps(args, sort_keys=True)}\"}",
            "                    }",
            "                ]",
            "            }",
            "        })",
            "    else:",
            "        send_message({",
            "            'jsonrpc': '2.0',",
            "            'id': request['id'],",
            "            'error': {'code': -32601, 'message': f'unknown method: {method}'},",
            "        })",
            "",
        ]
        .join("\n");
        fs::write(&script_path, script).expect("write script");
        make_executable(&script_path);
        script_path
    }

    fn sample_bootstrap(script_path: &Path) -> McpClientBootstrap {
        let config = ScopedMcpServerConfig {
            required: false,
            scope: ConfigSource::Local,
            config: McpServerConfig::Stdio(McpStdioServerConfig {
                command: "/bin/sh".to_string(),
                args: vec![script_path.to_string_lossy().into_owned()],
                env: BTreeMap::from([("MCP_TEST_TOKEN".to_string(), "secret-value".to_string())]),
                tool_call_timeout_ms: None,
            }),
        };
        McpClientBootstrap::from_scoped_config("stdio server", &config)
    }

    fn script_transport(script_path: &Path) -> crate::mcp_client::McpStdioTransport {
        script_transport_with_env(script_path, BTreeMap::new())
    }

    fn script_transport_with_env(
        script_path: &Path,
        env: BTreeMap<String, String>,
    ) -> crate::mcp_client::McpStdioTransport {
        crate::mcp_client::McpStdioTransport {
            command: "python3".to_string(),
            args: vec![script_path.to_string_lossy().into_owned()],
            env,
            tool_call_timeout_ms: None,
        }
    }

    fn cleanup_script(script_path: &Path) {
        if let Err(error) = fs::remove_file(script_path) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "cleanup script: {error}"
            );
        }
        if let Err(error) = fs::remove_dir_all(script_path.parent().expect("script parent")) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "cleanup dir: {error}"
            );
        }
    }

    fn read_sse_http_request(stream: &mut TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set read timeout");
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    buffer.extend_from_slice(&chunk[..read]);
                    let request = String::from_utf8_lossy(&buffer);
                    if let Some((headers, body)) = request.split_once("\r\n\r\n") {
                        let content_length = headers.lines().find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        });
                        if content_length
                            .map(|length| body.as_bytes().len() >= length)
                            .unwrap_or(true)
                        {
                            return request.into_owned();
                        }
                    }
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    break;
                }
                Err(error) => panic!("read SSE POST: {error}"),
            }
        }
        String::from_utf8(buffer).expect("utf8 request")
    }

    fn parse_sse_post_json(request: &str) -> serde_json::Value {
        let body = request
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.trim())
            .unwrap_or("");
        serde_json::from_str(body)
            .unwrap_or_else(|error| panic!("json body from request {request:?}: {error}"))
    }

    fn read_sse_get_request(stream: &mut TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .expect("set read timeout");
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    buffer.extend_from_slice(&chunk[..read]);
                    if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                    assert!(
                        buffer.len() <= 16 * 1024,
                        "SSE GET request headers exceeded fixture limit"
                    );
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    break;
                }
                Err(error) => panic!("read SSE GET: {error}"),
            }
        }
        String::from_utf8(buffer).expect("utf8 request")
    }

    fn write_sse_headers(stream: &mut TcpStream) {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
            )
            .expect("write SSE headers");
    }

    fn write_sse_event(stream: &mut TcpStream, event: &str) {
        let bytes = event.as_bytes();
        stream
            .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
            .expect("write SSE chunk length");
        stream.write_all(bytes).expect("write SSE chunk");
        stream.write_all(b"\r\n").expect("finish SSE chunk");
        stream.flush().expect("flush SSE chunk");
    }

    fn try_write_sse_event(stream: &mut TcpStream, event: &str) -> std::io::Result<()> {
        let bytes = event.as_bytes();
        stream.write_all(format!("{:x}\r\n", bytes.len()).as_bytes())?;
        stream.write_all(bytes)?;
        stream.write_all(b"\r\n")?;
        stream.flush()
    }

    fn write_sse_post_ack(stream: &mut TcpStream) {
        stream
            .write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .expect("write SSE POST ack");
        stream.flush().expect("flush SSE POST ack");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown SSE POST ack");
    }

    fn write_sse_post_chunked_body(stream: &mut TcpStream, status: &str, body: &[u8]) {
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .expect("write SSE POST chunked headers");
        stream
            .write_all(format!("{:x}\r\n", body.len()).as_bytes())
            .expect("write SSE POST chunk length");
        stream.write_all(body).expect("write SSE POST chunk");
        stream
            .write_all(b"\r\n0\r\n\r\n")
            .expect("finish SSE POST chunked body");
        stream.flush().expect("flush SSE POST chunked body");
        stream
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown SSE POST chunked body");
    }

    fn sse_transport_for_url(
        url: String,
        headers: BTreeMap<String, String>,
        timeout_ms: u64,
    ) -> McpRemoteTransport {
        McpRemoteTransport {
            url,
            headers,
            headers_helper: None,
            auth: McpClientAuth::None,
            tool_call_timeout_ms: Some(timeout_ms),
            heartbeat_timeout_ms: Some(timeout_ms),
            protocol_version: Some("2024-11-05".to_string()),
            capabilities: json!({}),
        }
    }

    fn accept_sse_stream(listener: &TcpListener) -> TcpStream {
        let (mut sse, _) = listener.accept().expect("accept sse");
        let request = read_sse_get_request(&mut sse);
        assert!(request.starts_with("GET "), "expected GET, got {request:?}");
        write_sse_headers(&mut sse);
        write_sse_event(&mut sse, "event: endpoint\ndata: /message\r\n\r\n");
        sse
    }

    fn write_sse_jsonrpc_result(
        sse: &mut TcpStream,
        id: serde_json::Value,
        result: serde_json::Value,
    ) {
        let frame = format!(
            "event: message\ndata: {}\r\n\r\n",
            json!({"jsonrpc": "2.0", "id": id, "result": result})
        );
        write_sse_event(sse, &frame);
    }

    fn write_sse_jsonrpc_error(
        sse: &mut TcpStream,
        id: serde_json::Value,
        code: i64,
        message: &str,
    ) {
        let frame = format!(
            "event: message\ndata: {}\r\n\r\n",
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": {
                    "code": code,
                    "message": message
                }
            })
        );
        write_sse_event(sse, &frame);
    }

    fn complete_sse_initialize_and_ping(
        listener: &TcpListener,
        methods: &Arc<Mutex<Vec<String>>>,
        sse: &mut TcpStream,
        capabilities: serde_json::Value,
    ) {
        let (mut initialize, initialize_request) = accept_sse_post(listener, methods, sse);
        write_sse_post_ack(&mut initialize);
        write_sse_jsonrpc_result(
            sse,
            initialize_request["id"].clone(),
            json!({
                "protocolVersion": "2024-11-05",
                "capabilities": capabilities,
                "serverInfo": { "name": "legacy-sse", "version": "1.0.0" }
            }),
        );

        let (mut notification, _) = accept_sse_post(listener, methods, sse);
        write_sse_post_ack(&mut notification);

        let (mut ping, ping_request) = accept_sse_post(listener, methods, sse);
        write_sse_post_ack(&mut ping);
        write_sse_jsonrpc_result(sse, ping_request["id"].clone(), json!({}));
    }

    fn accept_sse_post(
        listener: &TcpListener,
        methods: &Arc<Mutex<Vec<String>>>,
        sse: &mut TcpStream,
    ) -> (TcpStream, serde_json::Value) {
        loop {
            let (mut post, _) = listener.accept().expect("accept post");
            let request = read_sse_http_request(&mut post);
            if request.starts_with("GET ") {
                *sse = post;
                write_sse_headers(sse);
                write_sse_event(sse, "event: endpoint\ndata: /message\r\n\r\n");
                continue;
            }
            let value = parse_sse_post_json(&request);
            let method = value
                .get("method")
                .and_then(serde_json::Value::as_str)
                .expect("method")
                .to_string();
            methods.lock().expect("methods lock").push(method);
            return (post, value);
        }
    }

    fn manager_server_config(
        script_path: &Path,
        label: &str,
        log_path: &Path,
    ) -> ScopedMcpServerConfig {
        manager_server_config_with_env(script_path, label, log_path, BTreeMap::new())
    }

    fn manager_server_config_with_env(
        script_path: &Path,
        label: &str,
        log_path: &Path,
        extra_env: BTreeMap<String, String>,
    ) -> ScopedMcpServerConfig {
        let mut env = BTreeMap::from([
            ("MCP_SERVER_LABEL".to_string(), label.to_string()),
            (
                "MCP_LOG_PATH".to_string(),
                log_path.to_string_lossy().into_owned(),
            ),
        ]);
        env.extend(extra_env);
        ScopedMcpServerConfig {
            required: false,
            scope: ConfigSource::Local,
            config: McpServerConfig::Stdio(McpStdioServerConfig {
                command: "python3".to_string(),
                args: vec![script_path.to_string_lossy().into_owned()],
                env,
                tool_call_timeout_ms: None,
            }),
        }
    }

    #[test]
    fn spawns_stdio_process_and_round_trips_io() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_echo_script();
            let bootstrap = sample_bootstrap(&script_path);
            let mut process = spawn_mcp_stdio_process(&bootstrap).expect("spawn stdio process");

            let ready = process.read_line().await.expect("read ready");
            assert_eq!(ready, "READY:secret-value\n");

            process
                .write_line("ping from client")
                .await
                .expect("write line");

            let echoed = process.read_line().await.expect("read echo");
            assert_eq!(echoed, "ECHO:ping from client\n");

            let status = process.wait().await.expect("wait for exit");
            assert!(status.success());

            cleanup_script(&script_path);
        });
    }

    #[test]
    fn rejects_non_stdio_bootstrap() {
        let config = ScopedMcpServerConfig {
            required: false,
            scope: ConfigSource::Local,
            config: McpServerConfig::Sdk(crate::config::McpSdkServerConfig {
                name: "sdk-server".to_string(),
            }),
        };
        let bootstrap = McpClientBootstrap::from_scoped_config("sdk server", &config);
        let error = spawn_mcp_stdio_process(&bootstrap).expect_err("non-stdio should fail");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn round_trips_initialize_request_and_response_over_stdio_frames() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_jsonrpc_script();
            let transport = script_transport(&script_path);
            let mut process = McpStdioProcess::spawn(&transport).expect("spawn transport directly");

            let response = process
                .initialize(
                    JsonRpcId::Number(1),
                    McpInitializeParams {
                        protocol_version: "2025-03-26".to_string(),
                        capabilities: json!({"roots": {}}),
                        client_info: McpInitializeClientInfo {
                            name: "runtime-tests".to_string(),
                            version: "0.1.0".to_string(),
                        },
                    },
                )
                .await
                .expect("initialize roundtrip");

            assert_eq!(response.id, JsonRpcId::Number(1));
            assert_eq!(response.error, None);
            assert_eq!(
                response.result,
                Some(McpInitializeResult {
                    protocol_version: "2025-03-26".to_string(),
                    capabilities: json!({"tools": {}}),
                    server_info: McpInitializeServerInfo {
                        name: "fake-mcp".to_string(),
                        version: "0.1.0".to_string(),
                    },
                })
            );

            let status = process.wait().await.expect("wait for exit");
            assert!(status.success());

            cleanup_script(&script_path);
        });
    }

    #[test]
    fn write_jsonrpc_request_interops_with_standard_newline_server() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_jsonrpc_script();
            let transport = script_transport(&script_path);
            let mut process = McpStdioProcess::spawn(&transport).expect("spawn transport directly");
            let request = JsonRpcRequest::new(
                JsonRpcId::Number(7),
                "initialize",
                Some(json!({
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "runtime-tests", "version": "0.1.0"}
                })),
            );

            process.send_request(&request).await.expect("send request");
            let response: JsonRpcResponse<serde_json::Value> =
                process.read_response().await.expect("read response");

            assert_eq!(response.id, JsonRpcId::Number(7));
            assert_eq!(response.jsonrpc, "2.0");

            let status = process.wait().await.expect("wait for exit");
            assert!(status.success());

            cleanup_script(&script_path);
        });
    }

    #[test]
    fn given_standard_newline_server_when_initialize_then_response_parses() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_jsonrpc_script();
            let transport = script_transport(&script_path);
            let mut process = McpStdioProcess::spawn(&transport).expect("spawn transport directly");

            let response = process
                .initialize(
                    JsonRpcId::Number(8),
                    McpInitializeParams {
                        protocol_version: "2025-03-26".to_string(),
                        capabilities: json!({"roots": {}}),
                        client_info: McpInitializeClientInfo {
                            name: "runtime-tests".to_string(),
                            version: "0.1.0".to_string(),
                        },
                    },
                )
                .await
                .expect("initialize roundtrip");

            assert_eq!(response.id, JsonRpcId::Number(8));
            assert_eq!(response.error, None);
            assert!(response.result.is_some());

            let status = process.wait().await.expect("wait for exit");
            assert!(status.success());

            cleanup_script(&script_path);
        });
    }

    #[test]
    fn overlong_jsonrpc_line_is_rejected_before_json_parse() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let mut bytes = vec![b'{'; MCP_MAX_JSONRPC_FRAME_BYTES + 1];
            bytes.push(b'\n');
            let mut reader = BufReader::new(bytes.as_slice());
            let error = read_limited_jsonrpc_line(&mut reader)
                .await
                .expect_err("overlong line must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert!(error.to_string().contains("exceeded"));
        });
    }

    #[test]
    fn empty_jsonrpc_line_is_rejected() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let mut reader = BufReader::new(&b"\n"[..]);
            let error = read_limited_jsonrpc_line(&mut reader)
                .await
                .expect_err("empty line must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert!(error.to_string().contains("must not be empty"));
        });
    }

    #[test]
    fn crlf_jsonrpc_line_strips_delimiter_carriage_return() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let mut reader = BufReader::new(&b"{\"jsonrpc\":\"2.0\"}\r\n"[..]);
            let payload = read_limited_jsonrpc_line(&mut reader)
                .await
                .expect("CRLF line should parse")
                .expect("payload");
            assert_eq!(payload, br#"{"jsonrpc":"2.0"}"#);
        });
    }

    #[test]
    fn embedded_carriage_return_jsonrpc_line_is_rejected() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let mut reader = BufReader::new(&b"{\"jsonrpc\":\"2.0\r\"}\n"[..]);
            let error = read_limited_jsonrpc_line(&mut reader)
                .await
                .expect_err("embedded carriage return must be rejected");
            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert!(error.to_string().contains("carriage returns"));
        });
    }

    #[test]
    fn given_crlf_response_when_initialize_then_response_parses() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_jsonrpc_script();
            let transport = script_transport_with_env(
                &script_path,
                BTreeMap::from([("MCP_RESPONSE_CRLF".to_string(), "1".to_string())]),
            );
            let mut process = McpStdioProcess::spawn(&transport).expect("spawn transport directly");
            let response = process
                .initialize(
                    JsonRpcId::Number(9),
                    McpInitializeParams {
                        protocol_version: "2025-03-26".to_string(),
                        capabilities: json!({"roots": {}}),
                        client_info: McpInitializeClientInfo {
                            name: "runtime-tests".to_string(),
                            version: "0.1.0".to_string(),
                        },
                    },
                )
                .await
                .expect("initialize should parse CRLF response");

            assert_eq!(response.id, JsonRpcId::Number(9));
            assert_eq!(response.error, None);
            assert!(response.result.is_some());

            let status = process.wait().await.expect("wait for exit");
            assert!(status.success());
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn given_mismatched_response_id_when_initialize_then_invalid_data_is_returned() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_jsonrpc_script();
            let transport = script_transport_with_env(
                &script_path,
                BTreeMap::from([("MCP_MISMATCHED_RESPONSE_ID".to_string(), "1".to_string())]),
            );
            let mut process = McpStdioProcess::spawn(&transport).expect("spawn transport directly");

            let error = process
                .initialize(
                    JsonRpcId::Number(9),
                    McpInitializeParams {
                        protocol_version: "2025-03-26".to_string(),
                        capabilities: json!({"roots": {}}),
                        client_info: McpInitializeClientInfo {
                            name: "runtime-tests".to_string(),
                            version: "0.1.0".to_string(),
                        },
                    },
                )
                .await
                .expect_err("mismatched response id should fail");

            assert_eq!(error.kind(), ErrorKind::InvalidData);
            assert!(error.to_string().contains("mismatched id"));

            let status = process.wait().await.expect("wait for exit");
            assert!(status.success());

            cleanup_script(&script_path);
        });
    }

    #[test]
    fn direct_spawn_uses_transport_env() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_echo_script();
            let transport = crate::mcp_client::McpStdioTransport {
                command: "/bin/sh".to_string(),
                args: vec![script_path.to_string_lossy().into_owned()],
                env: BTreeMap::from([("MCP_TEST_TOKEN".to_string(), "direct-secret".to_string())]),
                tool_call_timeout_ms: None,
            };
            let mut process = McpStdioProcess::spawn(&transport).expect("spawn transport directly");
            let ready = process.read_available().await.expect("read ready");
            assert_eq!(String::from_utf8_lossy(&ready), "READY:direct-secret\n");
            process.terminate().await.expect("terminate child");
            let _ = process.wait().await.expect("wait after kill");

            cleanup_script(&script_path);
        });
    }

    #[test]
    fn lists_tools_calls_tool_and_reads_resources_over_jsonrpc() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_mcp_server_script();
            let transport = script_transport(&script_path);
            let mut process = McpStdioProcess::spawn(&transport).expect("spawn fake mcp server");

            let initialize = process
                .initialize(
                    JsonRpcId::Number(1),
                    McpInitializeParams {
                        protocol_version: "2025-03-26".to_string(),
                        capabilities: json!({}),
                        client_info: McpInitializeClientInfo {
                            name: "runtime-tests".to_string(),
                            version: "0.1.0".to_string(),
                        },
                    },
                )
                .await
                .expect("initialize");
            let initialize_result = initialize.result.expect("initialize result");
            assert!(initialize_result.capabilities.get("tools").is_some());
            assert!(initialize_result.capabilities.get("resources").is_some());
            assert!(initialize_result.capabilities.get("prompts").is_some());
            process
                .notify("notifications/initialized", Some(json!({})))
                .await
                .expect("initialized notification");

            let tools = process
                .list_tools(JsonRpcId::Number(2), None)
                .await
                .expect("list tools");
            assert_eq!(tools.error, None);
            assert_eq!(tools.id, JsonRpcId::Number(2));
            let tools_result = tools.result.expect("tools result");
            assert_eq!(tools_result.tools[0].name, "echo");
            assert_eq!(tools_result.next_cursor.as_deref(), Some("tools-page-2"));
            let tools_second = process
                .list_tools(
                    JsonRpcId::Number(21),
                    Some(McpListToolsParams {
                        cursor: tools_result.next_cursor,
                    }),
                )
                .await
                .expect("list tools second page")
                .result
                .expect("tools second page");
            assert_eq!(tools_second.tools[0].name, "inspect");
            assert_eq!(tools_second.next_cursor, None);

            let call = process
                .call_tool(
                    JsonRpcId::String("call-1".to_string()),
                    McpToolCallParams {
                        name: "echo".to_string(),
                        arguments: Some(json!({"text": "hello"})),
                        meta: None,
                    },
                )
                .await
                .expect("call tool");
            assert_eq!(call.error, None);
            let call_result = call.result.expect("tool result");
            assert_eq!(call_result.is_error, Some(false));
            assert_eq!(
                call_result.structured_content,
                Some(json!({"echoed": "hello"}))
            );
            assert_eq!(call_result.content.len(), 1);
            assert_eq!(call_result.content[0].kind, "text");
            assert_eq!(
                call_result.content[0].data.get("text"),
                Some(&json!("echo:hello"))
            );

            let resources = process
                .list_resources(JsonRpcId::Number(3), None)
                .await
                .expect("list resources");
            let resources_result = resources.result.expect("resources result");
            assert_eq!(resources_result.resources.len(), 1);
            assert_eq!(resources_result.resources[0].uri, "file://guide.txt");
            assert_eq!(
                resources_result.next_cursor.as_deref(),
                Some("resources-page-2")
            );
            assert_eq!(
                resources_result.resources[0].mime_type.as_deref(),
                Some("text/plain")
            );
            let resources_second = process
                .list_resources(
                    JsonRpcId::Number(31),
                    Some(McpListResourcesParams {
                        cursor: resources_result.next_cursor,
                    }),
                )
                .await
                .expect("list resources second page")
                .result
                .expect("resources second page");
            assert_eq!(resources_second.resources[0].uri, "file://status.json");

            let resource_templates = process
                .list_resource_templates(
                    JsonRpcId::Number(32),
                    Some(McpListResourceTemplatesParams { cursor: None }),
                )
                .await
                .expect("list resource templates")
                .result
                .expect("resource templates result");
            assert_eq!(
                resource_templates.resource_templates[0].uri_template,
                "file://logs/{unit}.txt"
            );

            let read = process
                .read_resource(
                    JsonRpcId::Number(4),
                    McpReadResourceParams {
                        uri: "file://guide.txt".to_string(),
                    },
                )
                .await
                .expect("read resource");
            assert_eq!(
                read.result,
                Some(McpReadResourceResult {
                    contents: vec![super::McpResourceContents {
                        uri: "file://guide.txt".to_string(),
                        mime_type: Some("text/plain".to_string()),
                        text: Some("contents for file://guide.txt".to_string()),
                        blob: None,
                        meta: None,
                    }],
                })
            );

            let prompts = process
                .list_prompts(JsonRpcId::Number(5), None)
                .await
                .expect("list prompts");
            assert_eq!(prompts.error, None);
            let prompts_result = prompts.result.expect("prompts result");
            assert_eq!(prompts_result.prompts[0].name, "triage");
            assert_eq!(
                prompts_result.next_cursor.as_deref(),
                Some("prompts-page-2")
            );
            let prompts_second = process
                .list_prompts(
                    JsonRpcId::Number(51),
                    Some(McpListPromptsParams {
                        cursor: prompts_result.next_cursor,
                    }),
                )
                .await
                .expect("list prompts second page")
                .result
                .expect("prompts second page");
            assert_eq!(prompts_second.prompts[0].name, "repair");

            let prompt = process
                .get_prompt(
                    JsonRpcId::Number(6),
                    Some(McpGetPromptParams {
                        name: "triage".to_string(),
                        arguments: Some(json!({"service": "api"})),
                    }),
                )
                .await
                .expect("get prompt");
            let prompt_result = prompt.result.expect("prompt result");
            assert_eq!(
                prompt_result.description.as_deref(),
                Some("Prompt for triage")
            );
            assert_eq!(prompt_result.messages.len(), 1);
            assert_eq!(prompt_result.messages[0].role, "user");

            process.terminate().await.expect("terminate child");
            let _ = process.wait().await.expect("wait after kill");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn surfaces_jsonrpc_errors_from_tool_calls() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_mcp_server_script();
            let transport = script_transport(&script_path);
            let mut process = McpStdioProcess::spawn(&transport).expect("spawn fake mcp server");

            let response = process
                .call_tool(
                    JsonRpcId::Number(9),
                    McpToolCallParams {
                        name: "fail".to_string(),
                        arguments: None,
                        meta: None,
                    },
                )
                .await
                .expect("call tool with error response");

            assert_eq!(response.id, JsonRpcId::Number(9));
            assert!(response.result.is_none());
            assert_eq!(response.error.as_ref().map(|e| e.code), Some(-32001));
            assert_eq!(
                response.error.as_ref().map(|e| e.message.as_str()),
                Some("tool failed")
            );

            process.terminate().await.expect("terminate child");
            let _ = process.wait().await.expect("wait after kill");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn manager_discovers_tools_from_stdio_config() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("alpha.log");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config(&script_path, "alpha", &log_path),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            let tools = manager.discover_tools().await.expect("discover tools");

            assert_eq!(tools.len(), 1);
            assert_eq!(tools[0].server_name, "alpha");
            assert_eq!(tools[0].raw_name, "echo");
            assert_eq!(tools[0].qualified_name, mcp_tool_name("alpha", "echo"));
            assert_eq!(tools[0].tool.name, "echo");
            assert!(manager.unsupported_servers().is_empty());

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    fn make_executable(path: &Path) {
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(path).expect("metadata").permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).expect("chmod");
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    #[test]
    fn manager_rejects_incompatible_protocol_version() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("protocol.log");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config_with_env(
                    &script_path,
                    "alpha",
                    &log_path,
                    BTreeMap::from([(
                        "MCP_PROTOCOL_VERSION".to_string(),
                        "unsupported-version".to_string(),
                    )]),
                ),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            let error = manager
                .discover_tools()
                .await
                .expect_err("incompatible protocol must fail initialization");

            assert!(error
                .to_string()
                .contains("malformed protocolVersion `unsupported-version`"));
            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn manager_rejects_missing_malformed_oversize_and_known_unsupported_protocol_versions() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let variants = [
                (
                    "missing",
                    BTreeMap::from([("MCP_OMIT_PROTOCOL_VERSION".to_string(), "1".to_string())]),
                    "protocolVersion",
                ),
                (
                    "empty",
                    BTreeMap::from([("MCP_PROTOCOL_VERSION".to_string(), String::new())]),
                    "missing protocolVersion",
                ),
                (
                    "oversize",
                    BTreeMap::from([("MCP_PROTOCOL_VERSION".to_string(), "1".repeat(33))]),
                    "exceeds maximum",
                ),
                (
                    "malformed",
                    BTreeMap::from([(
                        "MCP_PROTOCOL_VERSION".to_string(),
                        "2025/06/18".to_string(),
                    )]),
                    "malformed protocolVersion",
                ),
                (
                    "unsupported-2025-06-18",
                    BTreeMap::from([(
                        "MCP_PROTOCOL_VERSION".to_string(),
                        "2025-06-18".to_string(),
                    )]),
                    "unsupported protocolVersion `2025-06-18`",
                ),
                (
                    "unsupported-2025-11-25",
                    BTreeMap::from([(
                        "MCP_PROTOCOL_VERSION".to_string(),
                        "2025-11-25".to_string(),
                    )]),
                    "unsupported protocolVersion `2025-11-25`",
                ),
            ];

            for (label, env, expected_error) in variants {
                let log_path = root.join(format!("{label}.log"));
                let servers = BTreeMap::from([(
                    "alpha".to_string(),
                    manager_server_config_with_env(&script_path, "alpha", &log_path, env),
                )]);
                let mut manager = McpServerManager::from_servers(&servers);

                let error = manager
                    .discover_tools()
                    .await
                    .expect_err("invalid protocol version must fail closed");
                assert!(
                    error.to_string().contains(expected_error),
                    "{label}: {error}"
                );
                let log = fs::read_to_string(&log_path).unwrap_or_default();
                assert_eq!(
                    log.lines().collect::<Vec<_>>(),
                    vec!["initialize"],
                    "{label}"
                );
                let catalog = manager.server_catalogs().pop().expect("catalog");
                assert!(catalog.requested_protocol_version.is_none(), "{label}");
                assert!(catalog.negotiated_protocol_version.is_none(), "{label}");
                assert!(catalog.protocol_transport_policy.is_none(), "{label}");
                let server = manager.servers.get("alpha").expect("managed server");
                assert!(server.process.is_none(), "{label}");
                manager.shutdown().await.expect("shutdown");
            }

            cleanup_script(&script_path);
        });
    }

    #[test]
    fn manager_accepts_stdio_server_downgrade_and_records_protocol_state() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("protocol-downgrade.log");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config_with_env(
                    &script_path,
                    "alpha",
                    &log_path,
                    BTreeMap::from([(
                        "MCP_PROTOCOL_VERSION".to_string(),
                        "2024-11-05".to_string(),
                    )]),
                ),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            let tools = manager
                .discover_tools()
                .await
                .expect("stdio server downgrade should be accepted");

            assert_eq!(tools.len(), 1);
            let catalog = manager
                .server_catalogs()
                .into_iter()
                .find(|catalog| catalog.server_name == "alpha")
                .expect("catalog");
            assert_eq!(
                catalog.requested_protocol_version.as_deref(),
                Some("2025-03-26")
            );
            assert_eq!(
                catalog.negotiated_protocol_version.as_deref(),
                Some("2024-11-05")
            );
            assert_eq!(
                catalog.protocol_transport_policy,
                Some(McpProtocolTransportPolicy::Stdio)
            );
            assert!(!catalog.protocol_configured_preferred);

            let heartbeat = manager
                .heartbeat_report()
                .into_iter()
                .find(|entry| entry.server_name == "alpha")
                .expect("heartbeat");
            assert_eq!(
                heartbeat.requested_protocol_version.as_deref(),
                Some("2025-03-26")
            );
            assert_eq!(
                heartbeat.negotiated_protocol_version.as_deref(),
                Some("2024-11-05")
            );
            assert_eq!(
                heartbeat.protocol_transport_policy,
                Some(McpProtocolTransportPolicy::Stdio)
            );

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn stdio_configured_protocol_version_is_preferred_not_pinned() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("protocol-preferred.log");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config_with_env(
                    &script_path,
                    "alpha",
                    &log_path,
                    BTreeMap::from([
                        (
                            "CLAWD_MCP_PROTOCOL_VERSION".to_string(),
                            "2024-11-05".to_string(),
                        ),
                        ("MCP_PROTOCOL_VERSION".to_string(), "2025-03-26".to_string()),
                    ]),
                ),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            let tools = manager
                .discover_tools()
                .await
                .expect("server may choose any locally supported stdio version");
            assert_eq!(tools.len(), 1);
            let catalog = manager.server_catalogs().pop().expect("catalog");
            assert_eq!(
                catalog.requested_protocol_version.as_deref(),
                Some("2024-11-05")
            );
            assert_eq!(
                catalog.negotiated_protocol_version.as_deref(),
                Some("2025-03-26")
            );
            assert_eq!(
                catalog.protocol_transport_policy,
                Some(McpProtocolTransportPolicy::Stdio)
            );
            assert!(catalog.protocol_configured_preferred);

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn manager_resets_stdio_child_after_initialize_jsonrpc_error() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("initialize-error.log");
            let marker_path = root.join("initialize-error.marker");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config_with_env(
                    &script_path,
                    "alpha",
                    &log_path,
                    BTreeMap::from([
                        (
                            "MCP_INITIALIZE_JSONRPC_ERROR_ONCE".to_string(),
                            "1".to_string(),
                        ),
                        (
                            "MCP_FAIL_ONCE_MODE".to_string(),
                            "initialize_jsonrpc_error".to_string(),
                        ),
                        (
                            "MCP_FAIL_ONCE_MARKER".to_string(),
                            marker_path.to_string_lossy().into_owned(),
                        ),
                    ]),
                ),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            let error = manager
                .discover_tools()
                .await
                .expect_err("first initialize should return JSON-RPC error");
            assert!(error.to_string().contains("initialize rejected"));
            assert!(manager
                .server_catalogs()
                .into_iter()
                .all(|catalog| catalog.negotiated_protocol_version.is_none()));

            let tools = manager
                .discover_tools()
                .await
                .expect("second discovery should spawn and initialize again");
            assert_eq!(tools.len(), 1);

            let log = fs::read_to_string(&log_path).expect("log");
            assert_eq!(log.lines().filter(|line| *line == "initialize").count(), 2);
            assert!(log.contains("notifications/initialized"));

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn manager_routes_tool_calls_to_correct_server() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let alpha_log = root.join("alpha.log");
            let beta_log = root.join("beta.log");
            let servers = BTreeMap::from([
                (
                    "alpha".to_string(),
                    manager_server_config(&script_path, "alpha", &alpha_log),
                ),
                (
                    "beta".to_string(),
                    manager_server_config(&script_path, "beta", &beta_log),
                ),
            ]);
            let mut manager = McpServerManager::from_servers(&servers);

            let tools = manager.discover_tools().await.expect("discover tools");
            assert_eq!(tools.len(), 2);

            let alpha = manager
                .call_tool(
                    &mcp_tool_name("alpha", "echo"),
                    Some(json!({"text": "hello"})),
                )
                .await
                .expect("call alpha tool");
            let beta = manager
                .call_tool(
                    &mcp_tool_name("beta", "echo"),
                    Some(json!({"text": "world"})),
                )
                .await
                .expect("call beta tool");

            assert_eq!(
                alpha
                    .result
                    .as_ref()
                    .and_then(|result| result.structured_content.as_ref())
                    .and_then(|value| value.get("server")),
                Some(&json!("alpha"))
            );
            assert_eq!(
                beta.result
                    .as_ref()
                    .and_then(|result| result.structured_content.as_ref())
                    .and_then(|value| value.get("server")),
                Some(&json!("beta"))
            );

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn manager_times_out_slow_tool_calls() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("timeout.log");
            let servers = BTreeMap::from([(
                "slow".to_string(),
                ScopedMcpServerConfig {
                    required: false,
                    scope: ConfigSource::Local,
                    config: McpServerConfig::Stdio(McpStdioServerConfig {
                        command: "python3".to_string(),
                        args: vec![script_path.to_string_lossy().into_owned()],
                        env: BTreeMap::from([(
                            "MCP_TOOL_CALL_DELAY_MS".to_string(),
                            "200".to_string(),
                        )]),
                        tool_call_timeout_ms: Some(25),
                    }),
                },
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            manager.discover_tools().await.expect("discover tools");
            let error = manager
                .call_tool(
                    &mcp_tool_name("slow", "echo"),
                    Some(json!({"text": "slow"})),
                )
                .await
                .expect_err("slow tool call should time out");

            match error {
                McpServerManagerError::Timeout {
                    server_name,
                    method,
                    timeout_ms,
                } => {
                    assert_eq!(server_name, "slow");
                    assert_eq!(method, "tools/call");
                    assert_eq!(timeout_ms, 25);
                }
                other => panic!("expected timeout error, got {other:?}"),
            }

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
            let _ = fs::remove_file(log_path);
        });
    }

    #[test]
    fn manager_surfaces_parse_errors_from_tool_calls() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_mcp_server_script();
            let servers = BTreeMap::from([(
                "broken".to_string(),
                ScopedMcpServerConfig {
                    required: false,
                    scope: ConfigSource::Local,
                    config: McpServerConfig::Stdio(McpStdioServerConfig {
                        command: "python3".to_string(),
                        args: vec![script_path.to_string_lossy().into_owned()],
                        env: BTreeMap::from([(
                            "MCP_INVALID_TOOL_CALL_RESPONSE".to_string(),
                            "1".to_string(),
                        )]),
                        tool_call_timeout_ms: Some(1_000),
                    }),
                },
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            manager.discover_tools().await.expect("discover tools");
            let error = manager
                .call_tool(
                    &mcp_tool_name("broken", "echo"),
                    Some(json!({"text": "invalid-json"})),
                )
                .await
                .expect_err("invalid json should fail");

            match error {
                McpServerManagerError::InvalidResponse {
                    server_name,
                    method,
                    details,
                } => {
                    assert_eq!(server_name, "broken");
                    assert_eq!(method, "tools/call");
                    assert!(
                        details.contains("expected ident") || details.contains("expected value")
                    );
                }
                other => panic!("expected invalid response error, got {other:?}"),
            }

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn given_child_exits_after_discovery_when_calling_twice_then_second_call_succeeds_after_reset()
    {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("dropping.log");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config_with_env(
                    &script_path,
                    "alpha",
                    &log_path,
                    BTreeMap::from([("MCP_EXIT_AFTER_TOOLS_LIST".to_string(), "1".to_string())]),
                ),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            manager.discover_tools().await.expect("discover tools");
            let first_error = manager
                .call_tool(
                    &mcp_tool_name("alpha", "echo"),
                    Some(json!({"text": "reconnect"})),
                )
                .await
                .expect_err("first call should fail after transport drops");

            match first_error {
                McpServerManagerError::Transport {
                    server_name,
                    method,
                    source,
                } => {
                    assert_eq!(server_name, "alpha");
                    assert_eq!(method, "tools/call");
                    assert_eq!(source.kind(), ErrorKind::UnexpectedEof);
                }
                other => panic!("expected transport error, got {other:?}"),
            }

            let response = manager
                .call_tool(
                    &mcp_tool_name("alpha", "echo"),
                    Some(json!({"text": "reconnect"})),
                )
                .await
                .expect("second tool call should succeed after reset");

            assert_eq!(
                response
                    .result
                    .as_ref()
                    .and_then(|result| result.structured_content.as_ref())
                    .and_then(|value| value.get("server")),
                Some(&json!("alpha"))
            );
            let log = fs::read_to_string(&log_path).expect("read log");
            assert_eq!(
                log.lines().collect::<Vec<_>>(),
                vec![
                    "initialize",
                    "notifications/initialized",
                    "tools/list",
                    "initialize",
                    "notifications/initialized",
                    "tools/call",
                ]
            );

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn given_initialize_hangs_once_when_discover_tools_then_manager_retries_and_succeeds() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("initialize-hang.log");
            let marker_path = root.join("initialize-hang.marker");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config_with_env(
                    &script_path,
                    "alpha",
                    &log_path,
                    BTreeMap::from([
                        (
                            "MCP_FAIL_ONCE_MODE".to_string(),
                            "initialize_hang".to_string(),
                        ),
                        (
                            "MCP_FAIL_ONCE_MARKER".to_string(),
                            marker_path.to_string_lossy().into_owned(),
                        ),
                    ]),
                ),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            let tools = manager
                .discover_tools()
                .await
                .expect("discover tools after retry");

            assert_eq!(tools.len(), 1);
            assert_eq!(tools[0].qualified_name, mcp_tool_name("alpha", "echo"));
            let log = fs::read_to_string(&log_path).expect("read log");
            assert_eq!(
                log.lines().collect::<Vec<_>>(),
                vec![
                    "initialize",
                    "initialize-hang",
                    "initialize",
                    "notifications/initialized",
                    "tools/list",
                ]
            );

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn given_tool_call_disconnects_once_when_calling_twice_then_manager_resets_and_next_call_succeeds(
    ) {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("tool-call-disconnect.log");
            let marker_path = root.join("tool-call-disconnect.marker");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config_with_env(
                    &script_path,
                    "alpha",
                    &log_path,
                    BTreeMap::from([
                        (
                            "MCP_FAIL_ONCE_MODE".to_string(),
                            "tool_call_disconnect".to_string(),
                        ),
                        (
                            "MCP_FAIL_ONCE_MARKER".to_string(),
                            marker_path.to_string_lossy().into_owned(),
                        ),
                    ]),
                ),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            manager.discover_tools().await.expect("discover tools");
            let first_error = manager
                .call_tool(
                    &mcp_tool_name("alpha", "echo"),
                    Some(json!({"text": "first"})),
                )
                .await
                .expect_err("first tool call should fail when transport drops");

            match first_error {
                McpServerManagerError::Transport {
                    server_name,
                    method,
                    source,
                } => {
                    assert_eq!(server_name, "alpha");
                    assert_eq!(method, "tools/call");
                    assert_eq!(source.kind(), ErrorKind::UnexpectedEof);
                }
                other => panic!("expected transport error, got {other:?}"),
            }

            let response = manager
                .call_tool(
                    &mcp_tool_name("alpha", "echo"),
                    Some(json!({"text": "second"})),
                )
                .await
                .expect("second tool call should succeed after reset");

            assert_eq!(
                response
                    .result
                    .as_ref()
                    .and_then(|result| result.structured_content.as_ref())
                    .and_then(|value| value.get("echoed")),
                Some(&json!("second"))
            );
            let log = fs::read_to_string(&log_path).expect("read log");
            assert_eq!(
                log.lines().collect::<Vec<_>>(),
                vec![
                    "initialize",
                    "notifications/initialized",
                    "tools/list",
                    "tools/call",
                    "tools/call-disconnect",
                    "initialize",
                    "notifications/initialized",
                    "tools/call",
                ]
            );

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn manager_lists_and_reads_resources_from_stdio_servers() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("resources.log");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config(&script_path, "alpha", &log_path),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            let listed = manager
                .list_resources("alpha")
                .await
                .expect("list resources");
            assert_eq!(listed.resources.len(), 2);
            assert_eq!(listed.resources[0].uri, "file://guide.txt");

            let templates = manager
                .list_resource_templates("alpha")
                .await
                .expect("list resource templates");
            assert_eq!(templates.resource_templates.len(), 1);
            assert_eq!(
                templates.resource_templates[0].uri_template,
                "file://logs/{unit}.txt"
            );

            let read = manager
                .read_resource("alpha", "file://logs/api.txt")
                .await
                .expect("read concrete template resource");
            assert_eq!(read.contents.len(), 1);
            assert_eq!(
                read.contents[0].text.as_deref(),
                Some("contents for file://logs/api.txt")
            );

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn manager_discovers_three_capability_catalog_and_invokes_real_results() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("catalog.log");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config(&script_path, "alpha", &log_path),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            let catalogs = manager
                .discover_catalogs()
                .await
                .expect("discover catalogs");
            assert_eq!(catalogs.len(), 1);
            let catalog = &catalogs[0];
            assert!(catalog
                .capabilities
                .as_ref()
                .is_some_and(|capabilities| capabilities.tools
                    && capabilities.resources
                    && capabilities.prompts));
            assert_eq!(catalog.tools.len(), 2);
            assert_eq!(catalog.resources.len(), 2);
            assert_eq!(catalog.resource_templates.len(), 1);
            assert_eq!(catalog.prompts.len(), 2);

            let tool = manager
                .call_tool(&mcp_tool_name("alpha", "echo"), Some(json!({"text": "ok"})))
                .await
                .expect("call discovered tool")
                .result
                .expect("tool result");
            assert_eq!(tool.structured_content, Some(json!({"echoed": "ok"})));

            let resource = manager
                .read_resource("alpha", "file://guide.txt")
                .await
                .expect("read listed resource");
            assert_eq!(
                resource.contents[0].text.as_deref(),
                Some("contents for file://guide.txt")
            );

            let prompt = manager
                .get_prompt("alpha", "triage", Some(json!({"service": "api"})))
                .await
                .expect("get listed prompt");
            assert_eq!(prompt.messages.len(), 1);
            assert_eq!(prompt.messages[0].role, "user");

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn manager_rejects_missing_and_non_object_capabilities_before_calling_methods() {
        let invalid_values = [
            ("missing", None),
            ("array", Some(json!([]))),
            ("string", Some(json!("yes"))),
            ("number", Some(json!(1))),
            ("bool-true", Some(json!(true))),
            ("bool-false", Some(json!(false))),
            ("null", Some(json!(null))),
        ];
        let probes = [
            (
                "tools",
                McpCapabilityKind::Tools,
                &["tools/list", "tools/call"][..],
            ),
            (
                "resources",
                McpCapabilityKind::Resources,
                &["resources/list", "resources/read"][..],
            ),
            (
                "prompts",
                McpCapabilityKind::Prompts,
                &["prompts/list", "prompts/get"][..],
            ),
        ];
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            for (capability_key, expected_capability, forbidden_methods) in probes {
                for (value_label, override_value) in &invalid_values {
                    let script_path = write_mcp_server_script();
                    let root = script_path.parent().expect("script parent");
                    let log_path =
                        root.join(format!("{capability_key}-{value_label}-fail-closed.log"));
                    let mut env = BTreeMap::new();
                    if let Some(override_value) = override_value {
                        let mut overrides = serde_json::Map::new();
                        overrides.insert(capability_key.to_string(), override_value.clone());
                        env.insert(
                            "MCP_CAPABILITY_OVERRIDES".to_string(),
                            serde_json::Value::Object(overrides).to_string(),
                        );
                    } else {
                        env.insert(
                            format!("MCP_DISABLE_{}", capability_key.to_ascii_uppercase()),
                            "1".to_string(),
                        );
                    }
                    let servers = BTreeMap::from([(
                        "alpha".to_string(),
                        manager_server_config_with_env(&script_path, "alpha", &log_path, env),
                    )]);
                    let mut manager = McpServerManager::from_servers(&servers);

                    let error = match expected_capability {
                        McpCapabilityKind::Tools => manager
                            .discover_tools()
                            .await
                            .map(|_| ())
                            .expect_err("tools capability must fail closed"),
                        McpCapabilityKind::Resources => manager
                            .read_resource("alpha", "file://guide.txt")
                            .await
                            .map(|_| ())
                            .expect_err("resources capability must fail closed"),
                        McpCapabilityKind::Prompts => manager
                            .get_prompt("alpha", "triage", None)
                            .await
                            .map(|_| ())
                            .expect_err("prompts capability must fail closed"),
                        McpCapabilityKind::ResourceTemplates => unreachable!(),
                    };
                    assert!(
                        matches!(
                            error,
                            McpServerManagerError::UnsupportedCapability { capability, .. }
                                if capability == expected_capability
                        ),
                        "{capability_key}={value_label} returned unexpected error: {error:?}"
                    );

                    manager.shutdown().await.expect("shutdown");
                    let log = fs::read_to_string(&log_path).expect("read log");
                    for method in forbidden_methods {
                        assert!(
                            !log.lines().any(|line| line == *method),
                            "{capability_key}={value_label} unexpectedly called {method}; log: {log:?}"
                        );
                    }
                    cleanup_script(&script_path);
                }
            }
        });
    }

    #[test]
    fn manager_rejects_paginated_list_limit_violations() {
        let cases = [
            (
                "loop",
                BTreeMap::from([(
                    "MCP_PAGINATION_LOOP_METHOD".to_string(),
                    "resources/list".to_string(),
                )]),
                "repeated",
            ),
            (
                "empty",
                BTreeMap::from([(
                    "MCP_EMPTY_CURSOR_METHOD".to_string(),
                    "resources/list".to_string(),
                )]),
                "empty",
            ),
            (
                "missing-result",
                BTreeMap::from([(
                    "MCP_OMIT_RESULT_METHOD".to_string(),
                    "resources/list".to_string(),
                )]),
                "missing result",
            ),
            (
                "duplicate",
                BTreeMap::from([(
                    "MCP_DUPLICATE_LIST_METHOD".to_string(),
                    "resources/list".to_string(),
                )]),
                "duplicate resource uri",
            ),
        ];

        for (label, env, expected) in cases {
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            runtime.block_on(async {
                let script_path = write_mcp_server_script();
                let root = script_path.parent().expect("script parent");
                let servers = BTreeMap::from([(
                    "alpha".to_string(),
                    manager_server_config_with_env(
                        &script_path,
                        "alpha",
                        &root.join(format!("{label}.log")),
                        env,
                    ),
                )]);
                let mut manager = McpServerManager::from_servers(&servers);

                let error = manager
                    .list_resources("alpha")
                    .await
                    .expect_err("invalid pagination should fail");
                assert!(
                    error.to_string().contains(expected),
                    "{label} error did not contain {expected}: {error}"
                );

                manager.shutdown().await.expect("shutdown");
                cleanup_script(&script_path);
            });
        }
    }

    fn write_initialize_disconnect_script() -> PathBuf {
        let root = temp_dir();
        fs::create_dir_all(&root).expect("temp dir");
        let script_path = root.join("initialize-disconnect.py");
        let script = [
            "#!/usr/bin/env python3",
            "import sys",
            "line = sys.stdin.buffer.readline()",
            "if not line:",
            "    raise SystemExit(1)",
            "raise SystemExit(0)",
            "",
        ]
        .join("\n");
        fs::write(&script_path, script).expect("write script");
        make_executable(&script_path);
        script_path
    }

    #[test]
    fn manager_discovery_report_keeps_healthy_servers_when_one_server_fails() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let alpha_log = root.join("alpha.log");
            let broken_script_path = write_initialize_disconnect_script();
            let servers = BTreeMap::from([
                (
                    "alpha".to_string(),
                    manager_server_config(&script_path, "alpha", &alpha_log),
                ),
                (
                    "broken".to_string(),
                    ScopedMcpServerConfig {
                        required: true,
                        scope: ConfigSource::Local,
                        config: McpServerConfig::Stdio(McpStdioServerConfig {
                            command: broken_script_path.display().to_string(),
                            args: Vec::new(),
                            env: BTreeMap::new(),
                            tool_call_timeout_ms: None,
                        }),
                    },
                ),
            ]);
            let mut manager = McpServerManager::from_servers(&servers);

            let report = manager.discover_tools_best_effort().await;

            assert_eq!(report.tools.len(), 1);
            assert_eq!(report.heartbeat.len(), 2);
            assert!(report.heartbeat.iter().any(|heartbeat| {
                heartbeat.server_name == "alpha"
                    && heartbeat.status == McpHeartbeatStatus::NotConfigured
            }));
            assert_eq!(
                report.tools[0].qualified_name,
                mcp_tool_name("alpha", "echo")
            );
            assert_eq!(report.failed_servers.len(), 1);
            assert_eq!(report.failed_servers[0].server_name, "broken");
            assert!(report.failed_servers[0].required);
            assert_eq!(
                report.failed_servers[0].phase,
                McpLifecyclePhase::InitializeHandshake
            );
            assert!(!report.failed_servers[0].recoverable);
            assert_eq!(
                report.failed_servers[0]
                    .context
                    .get("method")
                    .map(String::as_str),
                Some("initialize")
            );
            assert!(report.failed_servers[0].error.contains("initialize"));
            let degraded = report
                .degraded_startup
                .as_ref()
                .expect("partial startup should surface degraded report");
            assert_eq!(degraded.working_servers, vec!["alpha".to_string()]);
            assert_eq!(degraded.failed_servers.len(), 1);
            assert_eq!(degraded.failed_servers[0].server_name, "broken");
            assert_eq!(
                degraded.failed_servers[0]
                    .error
                    .context
                    .get("required")
                    .map(String::as_str),
                Some("true")
            );
            assert_eq!(
                degraded.failed_servers[0].phase,
                McpLifecyclePhase::InitializeHandshake
            );
            assert_eq!(
                degraded.available_tools,
                vec![mcp_tool_name("alpha", "echo")]
            );
            assert!(degraded.missing_tools.is_empty());

            let response = manager
                .call_tool(&mcp_tool_name("alpha", "echo"), Some(json!({"text": "ok"})))
                .await
                .expect("healthy server should remain callable");
            assert_eq!(
                response
                    .result
                    .as_ref()
                    .and_then(|result| result.structured_content.as_ref())
                    .and_then(|value| value.get("echoed")),
                Some(&json!("ok"))
            );

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
            cleanup_script(&broken_script_path);
        });
    }

    #[test]
    fn manager_records_unsupported_non_stdio_servers_without_panicking() {
        let servers = BTreeMap::from([
            (
                "http".to_string(),
                ScopedMcpServerConfig {
                    required: true,
                    scope: ConfigSource::Local,
                    config: McpServerConfig::Http(McpRemoteServerConfig {
                        url: "https://example.test/mcp".to_string(),
                        headers: BTreeMap::new(),
                        headers_helper: None,
                        oauth: None,
                        tool_call_timeout_ms: None,
                        heartbeat_timeout_ms: None,
                        protocol_version: None,
                        capabilities: crate::JsonValue::Object(BTreeMap::new()),
                    }),
                },
            ),
            (
                "https-sse".to_string(),
                ScopedMcpServerConfig {
                    required: true,
                    scope: ConfigSource::Local,
                    config: McpServerConfig::Sse(McpRemoteServerConfig {
                        url: "https://example.test/sse".to_string(),
                        headers: BTreeMap::new(),
                        headers_helper: None,
                        oauth: None,
                        tool_call_timeout_ms: None,
                        heartbeat_timeout_ms: Some(500),
                        protocol_version: None,
                        capabilities: crate::JsonValue::Object(BTreeMap::new()),
                    }),
                },
            ),
            (
                "sdk".to_string(),
                ScopedMcpServerConfig {
                    required: false,
                    scope: ConfigSource::Local,
                    config: McpServerConfig::Sdk(McpSdkServerConfig {
                        name: "sdk-server".to_string(),
                    }),
                },
            ),
            (
                "ws".to_string(),
                ScopedMcpServerConfig {
                    required: false,
                    scope: ConfigSource::Local,
                    config: McpServerConfig::Ws(McpWebSocketServerConfig {
                        url: "wss://example.test/mcp".to_string(),
                        headers: BTreeMap::new(),
                        headers_helper: None,
                    }),
                },
            ),
        ]);

        let manager = McpServerManager::from_servers(&servers);
        let unsupported = manager.unsupported_servers();

        assert_eq!(unsupported.len(), 3);
        assert_eq!(unsupported[0].server_name, "http");
        assert!(unsupported[0].required);
        assert_eq!(unsupported[1].server_name, "sdk");
        assert_eq!(unsupported[2].server_name, "ws");
        assert!(manager.server_names().contains(&"https-sse".to_string()));
        let heartbeat = manager.heartbeat_report();
        assert!(heartbeat.iter().any(|entry| {
            entry.server_name == "https-sse" && entry.status == McpHeartbeatStatus::Unknown
        }));
        let failed = unsupported_server_failed_server(&unsupported[0]);
        assert_eq!(failed.phase, McpLifecyclePhase::ServerRegistration);
        assert_eq!(
            failed.error.context.get("required").map(String::as_str),
            Some("true")
        );
    }

    #[test]
    fn manager_records_heartbeat_failure_reason_when_stdio_ping_fails() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let servers = BTreeMap::from([(
                "ping-fails".to_string(),
                manager_server_config_with_env(
                    &script_path,
                    "ping-fails",
                    &root.join("ping-fails.log"),
                    BTreeMap::from([(
                        "CLAWD_MCP_HEARTBEAT_TIMEOUT_MS".to_string(),
                        "100".to_string(),
                    )]),
                ),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            let report = manager.discover_tools_best_effort().await;

            assert!(report.tools.is_empty());
            assert_eq!(report.failed_servers.len(), 1);
            let heartbeat = report
                .heartbeat
                .iter()
                .find(|entry| entry.server_name == "ping-fails")
                .expect("heartbeat entry");
            assert_eq!(heartbeat.status, McpHeartbeatStatus::Failed);
            assert!(heartbeat.last_failure_at_ms.is_some());
            assert!(heartbeat
                .last_failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("ping")));

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn minimal_sse_client_discovers_tools_from_local_fixture() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let handle = thread::spawn(move || {
            let methods = Arc::new(Mutex::new(Vec::new()));
            let (mut sse, _) = listener.accept().expect("accept sse");
            let _ = read_sse_get_request(&mut sse);
            write_sse_headers(&mut sse);
            write_sse_event(&mut sse, "event: endpoint\ndata: /message\r\n\r\n");

            let (mut initialize, initialize_request) =
                accept_sse_post(&listener, &methods, &mut sse);
            write_sse_post_ack(&mut initialize);
            let frame = format!(
                "event: message\ndata: {}\r\n\r\n",
                json!({
                    "jsonrpc": "2.0",
                    "id": initialize_request["id"].clone(),
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "fixture", "version": "1.0.0" }
                    }
                })
            );
            write_sse_event(&mut sse, &frame);

            let (mut notification, _) = accept_sse_post(&listener, &methods, &mut sse);
            write_sse_post_ack(&mut notification);

            let (mut ping, ping_request) = accept_sse_post(&listener, &methods, &mut sse);
            write_sse_post_ack(&mut ping);
            let frame = format!(
                "event: message\ndata: {}\r\n\r\n",
                json!({"jsonrpc":"2.0","id":ping_request["id"].clone(),"result":{}})
            );
            write_sse_event(&mut sse, &frame);

            let (mut tools, tools_request) = accept_sse_post(&listener, &methods, &mut sse);
            assert_eq!(
                tools_request
                    .get("params")
                    .and_then(|params| params.get("cursor"))
                    .and_then(serde_json::Value::as_str),
                None
            );
            write_sse_post_ack(&mut tools);
            let frame = format!(
                "event: message\ndata: {}\r\n\r\n",
                json!({
                    "jsonrpc": "2.0",
                    "id": tools_request["id"].clone(),
                    "result": {
                        "tools": [
                            {
                                "name": "inspect",
                                "description": "Inspect fixture",
                                "inputSchema": { "type": "object" }
                            }
                        ]
                    }
                })
            );
            write_sse_event(&mut sse, &frame);
        });

        let servers = BTreeMap::from([(
            "remote".to_string(),
            ScopedMcpServerConfig {
                required: true,
                scope: ConfigSource::Local,
                config: McpServerConfig::Sse(McpRemoteServerConfig {
                    url: format!("http://{addr}/sse"),
                    headers: BTreeMap::new(),
                    headers_helper: None,
                    oauth: None,
                    tool_call_timeout_ms: Some(1_000),
                    heartbeat_timeout_ms: Some(1_000),
                    protocol_version: Some("2024-11-05".to_string()),
                    capabilities: crate::JsonValue::Object(BTreeMap::new()),
                }),
            },
        )]);
        let mut manager = McpServerManager::from_servers(&servers);
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let tools = runtime
            .block_on(manager.discover_tools())
            .expect("sse discovery should work");
        assert_eq!(tools[0].qualified_name, "mcp__remote__inspect");
        let heartbeat = manager.heartbeat_report();
        assert_eq!(heartbeat.len(), 1);
        assert_eq!(heartbeat[0].server_name, "remote");
        assert_eq!(heartbeat[0].status, McpHeartbeatStatus::Healthy);
        assert!(heartbeat[0].last_success_at_ms.is_some());
        handle.join().expect("fixture thread");
    }

    #[test]
    fn legacy_sse_configured_newer_protocol_fails_before_network_accept() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        listener.set_nonblocking(true).expect("fixture nonblocking");
        let addr = listener.local_addr().expect("fixture addr");
        let servers = BTreeMap::from([(
            "remote".to_string(),
            ScopedMcpServerConfig {
                required: true,
                scope: ConfigSource::Local,
                config: McpServerConfig::Sse(McpRemoteServerConfig {
                    url: format!("http://{addr}/sse"),
                    headers: BTreeMap::new(),
                    headers_helper: None,
                    oauth: None,
                    tool_call_timeout_ms: Some(1_000),
                    heartbeat_timeout_ms: Some(1_000),
                    protocol_version: Some("2025-03-26".to_string()),
                    capabilities: crate::JsonValue::Object(BTreeMap::new()),
                }),
            },
        )]);
        let mut manager = McpServerManager::from_servers(&servers);
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");

        let report = runtime.block_on(manager.discover_catalogs_best_effort());

        assert!(report.catalogs.is_empty());
        assert_eq!(report.failed_servers.len(), 1);
        assert!(report.failed_servers[0].error.contains("legacy_sse"));
        assert!(report.failed_servers[0].error.contains("2025-03-26"));
        let heartbeat = report
            .heartbeat
            .iter()
            .find(|entry| entry.server_name == "remote")
            .expect("heartbeat");
        assert_eq!(heartbeat.status, McpHeartbeatStatus::Failed);
        assert!(heartbeat
            .last_failure_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("legacy_sse")));
        match listener.accept() {
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Ok((_, peer)) => panic!("legacy SSE protocol validation unexpectedly opened {peer}"),
            Err(error) => panic!("fixture accept failed: {error}"),
        }
    }

    #[test]
    fn legacy_sse_initialize_error_after_success_clears_stale_catalog_and_reconnects() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let methods = Arc::new(Mutex::new(Vec::new()));
        let fixture_methods = Arc::clone(&methods);
        let handle = thread::spawn(move || {
            let capabilities = json!({ "tools": {} });

            let mut first_sse = accept_sse_stream(&listener);
            complete_sse_initialize_and_ping(
                &listener,
                &fixture_methods,
                &mut first_sse,
                capabilities.clone(),
            );
            let (mut first_tools, first_tools_request) =
                accept_sse_post(&listener, &fixture_methods, &mut first_sse);
            write_sse_post_ack(&mut first_tools);
            write_sse_jsonrpc_result(
                &mut first_sse,
                first_tools_request["id"].clone(),
                json!({
                    "tools": [{
                        "name": "inspect",
                        "description": "Inspect fixture",
                        "inputSchema": { "type": "object" }
                    }]
                }),
            );

            let mut error_sse = accept_sse_stream(&listener);
            let (mut initialize, initialize_request) =
                accept_sse_post(&listener, &fixture_methods, &mut error_sse);
            write_sse_post_ack(&mut initialize);
            write_sse_jsonrpc_error(
                &mut error_sse,
                initialize_request["id"].clone(),
                -32002,
                "initialize rejected",
            );

            let mut third_sse = accept_sse_stream(&listener);
            complete_sse_initialize_and_ping(
                &listener,
                &fixture_methods,
                &mut third_sse,
                capabilities,
            );
            let (mut third_tools, third_tools_request) =
                accept_sse_post(&listener, &fixture_methods, &mut third_sse);
            write_sse_post_ack(&mut third_tools);
            write_sse_jsonrpc_result(
                &mut third_sse,
                third_tools_request["id"].clone(),
                json!({
                    "tools": [{
                        "name": "inspect",
                        "description": "Inspect fixture",
                        "inputSchema": { "type": "object" }
                    }]
                }),
            );
        });

        let servers = BTreeMap::from([(
            "remote".to_string(),
            ScopedMcpServerConfig {
                required: true,
                scope: ConfigSource::Local,
                config: McpServerConfig::Sse(McpRemoteServerConfig {
                    url: format!("http://{addr}/sse"),
                    headers: BTreeMap::new(),
                    headers_helper: None,
                    oauth: None,
                    tool_call_timeout_ms: Some(1_000),
                    heartbeat_timeout_ms: Some(1_000),
                    protocol_version: Some("2024-11-05".to_string()),
                    capabilities: crate::JsonValue::Object(BTreeMap::new()),
                }),
            },
        )]);
        let mut manager = McpServerManager::from_servers(&servers);
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");

        let first_tools = runtime
            .block_on(manager.discover_tools())
            .expect("first discovery should work");
        assert_eq!(first_tools.len(), 1);
        let first_catalog = manager.server_catalogs().pop().expect("catalog");
        assert_eq!(
            first_catalog.negotiated_protocol_version.as_deref(),
            Some("2024-11-05")
        );

        let report = runtime.block_on(manager.discover_catalogs_best_effort());
        assert!(report.catalogs.is_empty());
        assert_eq!(report.failed_servers.len(), 1);
        assert_eq!(
            report.failed_servers[0].phase,
            McpLifecyclePhase::InitializeHandshake
        );
        assert!(report.failed_servers[0]
            .error
            .contains("initialize rejected"));
        let failed_catalog = manager.server_catalogs().pop().expect("catalog");
        assert!(failed_catalog.tools.is_empty());
        assert!(failed_catalog.requested_protocol_version.is_none());
        assert!(failed_catalog.negotiated_protocol_version.is_none());
        assert!(failed_catalog.protocol_transport_policy.is_none());
        let heartbeat = manager
            .heartbeat_report()
            .into_iter()
            .find(|entry| entry.server_name == "remote")
            .expect("heartbeat");
        assert_eq!(heartbeat.status, McpHeartbeatStatus::Failed);
        assert!(heartbeat.requested_protocol_version.is_none());
        assert!(heartbeat.negotiated_protocol_version.is_none());

        let third_tools = runtime
            .block_on(manager.discover_tools())
            .expect("third discovery should reconnect and renegotiate");
        assert_eq!(third_tools.len(), 1);
        let third_catalog = manager.server_catalogs().pop().expect("catalog");
        assert_eq!(
            third_catalog.negotiated_protocol_version.as_deref(),
            Some("2024-11-05")
        );

        let methods = methods.lock().expect("methods").clone();
        assert_eq!(
            methods,
            vec![
                "initialize".to_string(),
                "notifications/initialized".to_string(),
                "ping".to_string(),
                "tools/list".to_string(),
                "initialize".to_string(),
                "initialize".to_string(),
                "notifications/initialized".to_string(),
                "ping".to_string(),
                "tools/list".to_string()
            ]
        );
        handle.join().expect("fixture thread");
    }

    #[test]
    fn http_sse_discovers_three_capabilities_and_invokes_operations() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let methods = Arc::new(Mutex::new(Vec::new()));
        let fixture_methods = Arc::clone(&methods);
        let handle = thread::spawn(move || {
            let capabilities = json!({ "tools": {}, "resources": {}, "prompts": {} });

            let mut sse = accept_sse_stream(&listener);
            complete_sse_initialize_and_ping(
                &listener,
                &fixture_methods,
                &mut sse,
                capabilities.clone(),
            );
            for (expected_method, result) in [
                (
                    "tools/list",
                    json!({
                        "tools": [{
                            "name": "inspect",
                            "description": "Inspect fixture",
                            "inputSchema": { "type": "object" }
                        }]
                    }),
                ),
                (
                    "resources/list",
                    json!({
                        "resources": [{
                            "uri": "file://guide.txt",
                            "name": "guide",
                            "mimeType": "text/plain"
                        }]
                    }),
                ),
                (
                    "resources/templates/list",
                    json!({
                        "resourceTemplates": [{
                            "uriTemplate": "file://logs/{unit}.txt",
                            "name": "unit-log"
                        }]
                    }),
                ),
                (
                    "prompts/list",
                    json!({
                        "prompts": [{
                            "name": "triage",
                            "description": "Triage a service",
                            "arguments": [{"name": "service", "required": true}]
                        }]
                    }),
                ),
            ] {
                let (mut post, request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
                assert_eq!(request["method"], expected_method);
                write_sse_post_ack(&mut post);
                write_sse_jsonrpc_result(&mut sse, request["id"].clone(), result);
            }

            let mut sse = accept_sse_stream(&listener);
            complete_sse_initialize_and_ping(
                &listener,
                &fixture_methods,
                &mut sse,
                capabilities.clone(),
            );
            let (mut call, request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
            assert_eq!(request["method"], "tools/call");
            assert_eq!(request["params"]["name"], "inspect");
            write_sse_post_ack(&mut call);
            write_sse_jsonrpc_result(
                &mut sse,
                request["id"].clone(),
                json!({
                    "content": [{"type": "text", "text": "inspected"}],
                    "structuredContent": {"ok": true},
                    "isError": false
                }),
            );

            let mut sse = accept_sse_stream(&listener);
            complete_sse_initialize_and_ping(
                &listener,
                &fixture_methods,
                &mut sse,
                capabilities.clone(),
            );
            let (mut read, request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
            assert_eq!(request["method"], "resources/read");
            assert_eq!(request["params"]["uri"], "file://logs/api.txt");
            write_sse_post_ack(&mut read);
            write_sse_jsonrpc_result(
                &mut sse,
                request["id"].clone(),
                json!({
                    "contents": [{
                        "uri": "file://logs/api.txt",
                        "mimeType": "text/plain",
                        "text": "api log"
                    }]
                }),
            );

            let mut sse = accept_sse_stream(&listener);
            complete_sse_initialize_and_ping(&listener, &fixture_methods, &mut sse, capabilities);
            let (mut prompt, request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
            assert_eq!(request["method"], "prompts/get");
            assert_eq!(request["params"]["name"], "triage");
            write_sse_post_ack(&mut prompt);
            write_sse_jsonrpc_result(
                &mut sse,
                request["id"].clone(),
                json!({
                    "description": "Triage a service",
                    "messages": [{
                        "role": "user",
                        "content": {"type": "text", "text": "triage api"}
                    }]
                }),
            );
        });

        let servers = BTreeMap::from([(
            "remote".to_string(),
            ScopedMcpServerConfig {
                required: true,
                scope: ConfigSource::Local,
                config: McpServerConfig::Sse(McpRemoteServerConfig {
                    url: format!("http://{addr}/sse"),
                    headers: BTreeMap::from([(
                        "Authorization".to_string(),
                        "Bearer secret-token".to_string(),
                    )]),
                    headers_helper: None,
                    oauth: None,
                    tool_call_timeout_ms: Some(1_000),
                    heartbeat_timeout_ms: Some(1_000),
                    protocol_version: Some("2024-11-05".to_string()),
                    capabilities: crate::JsonValue::Object(BTreeMap::new()),
                }),
            },
        )]);
        let mut manager = McpServerManager::from_servers(&servers);
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        runtime.block_on(async {
            let catalogs = manager.discover_catalogs().await.expect("discover catalog");
            let catalog = &catalogs[0];
            assert_eq!(catalog.tools.len(), 1);
            assert_eq!(catalog.resources.len(), 1);
            assert_eq!(catalog.resource_templates.len(), 1);
            assert_eq!(catalog.prompts.len(), 1);
            assert!(catalog.tools_complete);
            assert!(catalog.resources_complete);
            assert!(catalog.resource_templates_complete);
            assert!(catalog.prompts_complete);

            let call = manager
                .call_tool(
                    &mcp_tool_name("remote", "inspect"),
                    Some(json!({"target": "api"})),
                )
                .await
                .expect("call tool")
                .result
                .expect("tool result");
            assert_eq!(call.structured_content, Some(json!({"ok": true})));

            let resource = manager
                .read_resource("remote", "file://logs/api.txt")
                .await
                .expect("read resource");
            assert_eq!(resource.contents[0].text.as_deref(), Some("api log"));

            let prompt = manager
                .get_prompt("remote", "triage", Some(json!({"service": "api"})))
                .await
                .expect("get prompt");
            assert_eq!(prompt.messages.len(), 1);
        });

        handle.join().expect("fixture thread");
        assert!(methods
            .lock()
            .expect("methods lock")
            .contains(&"resources/templates/list".to_string()));
    }

    #[test]
    fn sse_endpoint_rejects_cross_origin_urls_without_blocking_loopback() {
        let base = reqwest::Url::parse("http://127.0.0.1:8000/sse").expect("base url");
        let same_origin =
            resolve_sse_endpoint("remote", &base, "/message").expect("same-origin endpoint");
        assert_eq!(same_origin.as_str(), "http://127.0.0.1:8000/message");

        let error = resolve_sse_endpoint("remote", &base, "http://127.0.0.1:8001/message")
            .expect_err("different effective port should be rejected");
        assert!(error
            .to_string()
            .contains("same scheme, host, and effective port"));

        let userinfo = parse_and_validate_sse_url(
            "remote",
            "sse/connect",
            "http://user:pass@127.0.0.1:8000/sse",
        )
        .expect_err("userinfo should be rejected");
        assert!(userinfo.to_string().contains("userinfo"));
    }

    #[test]
    fn sse_custom_headers_reject_reserved_names_without_leaking_values() {
        let allowed = build_sse_headers(
            "remote",
            "sse/connect",
            &BTreeMap::from([(
                "Authorization".to_string(),
                "Bearer secret-token".to_string(),
            )]),
        )
        .expect("authorization header should be allowed");
        assert_eq!(
            allowed
                .get(reqwest::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer secret-token")
        );

        for name in [
            "Host",
            "Connection",
            "Content-Length",
            "Transfer-Encoding",
            "TE",
            "Trailer",
            "Upgrade",
            "Proxy-Connection",
            "Proxy-Authorization",
            "Keep-Alive",
            "eXpEcT",
            "Accept",
            "Content-Type",
            "Cache-Control",
        ] {
            let error = build_sse_headers(
                "remote",
                "sse/connect",
                &BTreeMap::from([(name.to_string(), "secret-token".to_string())]),
            )
            .expect_err("reserved SSE transport header should be rejected");
            let text = error.to_string();
            assert!(text.contains("reserved"));
            assert!(!text.contains("secret-token"));
        }
    }

    #[test]
    fn sse_limits_reject_bad_content_type_and_oversize_headers_or_urls() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            reqwest::header::HeaderValue::from_static("application/json"),
        );
        let content_type = validate_sse_get_response("remote", reqwest::StatusCode::OK, &headers)
            .expect_err("SSE GET content-type must be event-stream");
        assert!(content_type.to_string().contains("Content-Type"));

        let status = validate_sse_get_response(
            "remote",
            reqwest::StatusCode::FOUND,
            &reqwest::header::HeaderMap::new(),
        )
        .expect_err("SSE GET redirect must be a non-2xx failure");
        assert!(status.to_string().contains("non-2xx status"));

        let mut oversized_response_headers = reqwest::header::HeaderMap::new();
        oversized_response_headers.insert(
            reqwest::header::HeaderName::from_static("x-large"),
            reqwest::header::HeaderValue::from_str(&"x".repeat(MCP_SSE_MAX_HEADER_BYTES + 1))
                .expect("oversized header value should parse"),
        );
        let response_headers = validate_sse_response_header_budget(
            "remote",
            "tools/list",
            &oversized_response_headers,
        )
        .expect_err("oversized response headers should be rejected");
        assert!(response_headers.to_string().contains("limit"));

        let oversized_header = build_sse_headers(
            "remote",
            "sse/connect",
            &BTreeMap::from([(
                "X-Large".to_string(),
                "x".repeat(MCP_SSE_MAX_HEADER_BYTES + 1),
            )]),
        )
        .expect_err("oversize headers should be rejected");
        assert!(oversized_header.to_string().contains("limit"));

        let oversized_url = parse_and_validate_sse_url(
            "remote",
            "sse/connect",
            &format!(
                "http://example.test/{}",
                "x".repeat(MCP_SSE_MAX_URL_BYTES + 1)
            ),
        )
        .expect_err("oversize URL should be rejected");
        assert!(oversized_url.to_string().contains("limit"));
    }

    #[test]
    fn sse_redirects_are_not_followed_or_leak_credentials() {
        for same_origin in [true, false] {
            let source = TcpListener::bind("127.0.0.1:0").expect("bind source fixture");
            let source_addr = source.local_addr().expect("source addr");
            let target = TcpListener::bind("127.0.0.1:0").expect("bind target fixture");
            let target_addr = target.local_addr().expect("target addr");
            target
                .set_nonblocking(true)
                .expect("target fixture nonblocking");
            let target_handle = thread::spawn(move || {
                let start = Instant::now();
                let mut requests = Vec::new();
                while start.elapsed() < Duration::from_millis(250) {
                    match target.accept() {
                        Ok((mut stream, _)) => requests.push(read_sse_get_request(&mut stream)),
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("target accept: {error}"),
                    }
                }
                requests
            });

            let location = if same_origin {
                format!("http://{source_addr}/target")
            } else {
                format!("http://{target_addr}/target")
            };
            let source_handle = thread::spawn(move || {
                let (mut stream, _) = source.accept().expect("accept source request");
                let request = read_sse_get_request(&mut stream);
                assert!(request.starts_with("GET /sse "));
                assert!(request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer secret-token"));
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                        .as_bytes(),
                    )
                    .expect("write redirect response");
                stream.flush().expect("flush redirect response");
                source
                    .set_nonblocking(true)
                    .expect("source fixture nonblocking");
                let start = Instant::now();
                let mut followups = Vec::new();
                while start.elapsed() < Duration::from_millis(250) {
                    match source.accept() {
                        Ok((mut stream, _)) => followups.push(read_sse_get_request(&mut stream)),
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(error) => panic!("source follow-up accept: {error}"),
                    }
                }
                followups
            });

            let error = match McpSseSession::connect(
                "remote",
                sse_transport_for_url(
                    format!("http://{source_addr}/sse"),
                    BTreeMap::from([(
                        "Authorization".to_string(),
                        "Bearer secret-token".to_string(),
                    )]),
                    500,
                ),
                500,
            ) {
                Ok(_) => panic!("SSE redirect should not be followed"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("non-2xx status 302"));

            let source_followups = source_handle.join().expect("source fixture thread");
            let target_requests = target_handle.join().expect("target fixture thread");
            assert!(
                source_followups.is_empty(),
                "same-origin redirect target must not receive requests or credentials: {source_followups:?}"
            );
            assert!(
                target_requests.is_empty(),
                "cross-origin redirect target must not receive requests or credentials: {target_requests:?}"
            );
        }
    }

    #[test]
    fn sse_get_stream_timeout_is_idle_not_total_lifecycle() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let methods = Arc::new(Mutex::new(Vec::new()));
        let fixture_methods = Arc::clone(&methods);
        let handle = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept sse");
            let _ = read_sse_get_request(&mut sse);
            write_sse_headers(&mut sse);
            write_sse_event(&mut sse, "event: endpoint\ndata: /message\r\n\r\n");
            for _ in 0..6 {
                thread::sleep(Duration::from_millis(120));
                try_write_sse_event(&mut sse, ": keepalive\r\n\r\n")
                    .expect("write keepalive before request");
            }
            let (mut post, request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
            assert_eq!(request["method"], "ping");
            write_sse_post_ack(&mut post);
            write_sse_jsonrpc_result(&mut sse, request["id"].clone(), json!({}));
        });

        let mut session = McpSseSession::connect(
            "remote",
            sse_transport_for_url(format!("http://{addr}/sse"), BTreeMap::new(), 200),
            200,
        )
        .expect("SSE endpoint should connect");
        thread::sleep(Duration::from_millis(800));
        session
            .request::<serde_json::Value, serde_json::Value>(
                JsonRpcId::Number(77),
                "ping",
                None,
                200,
            )
            .expect("active long-lived SSE stream should not hit a total GET lifecycle timeout");
        handle.join().expect("fixture thread");
    }

    #[test]
    fn sse_endpoint_wait_has_operation_deadline_despite_comments() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let handle = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept sse");
            let _ = read_sse_get_request(&mut sse);
            write_sse_headers(&mut sse);
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(300) {
                if try_write_sse_event(&mut sse, ": keepalive\r\n\r\n").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(30));
            }
        });

        let start = Instant::now();
        let error = match McpSseSession::connect(
            "remote",
            sse_transport_for_url(format!("http://{addr}/sse"), BTreeMap::new(), 120),
            120,
        ) {
            Ok(_) => panic!("endpoint comments should not bypass operation timeout"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            McpServerManagerError::Timeout {
                method: "sse/endpoint",
                ..
            }
        ));
        assert!(start.elapsed() < Duration::from_millis(500));
        handle.join().expect("fixture thread");
    }

    #[test]
    fn sse_get_stream_idle_timeout_fails_without_data() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let handle = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept sse");
            let _ = read_sse_get_request(&mut sse);
            write_sse_headers(&mut sse);
            thread::sleep(Duration::from_millis(300));
        });

        let error = match McpSseSession::connect(
            "remote",
            sse_transport_for_url(format!("http://{addr}/sse"), BTreeMap::new(), 100),
            100,
        ) {
            Ok(_) => panic!("idle SSE stream should time out while waiting for endpoint"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("timed out"));
        handle.join().expect("fixture thread");
    }

    #[test]
    fn sse_endpoint_rejects_first_non_comment_event_when_not_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let handle = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept sse");
            let _ = read_sse_get_request(&mut sse);
            write_sse_headers(&mut sse);
            write_sse_event(&mut sse, ": keepalive\r\n\r\n");
            write_sse_event(&mut sse, "\r\n");
            write_sse_event(&mut sse, "event: notice\ndata: {}\r\n\r\n");
        });

        let error = match McpSseSession::connect(
            "remote",
            sse_transport_for_url(format!("http://{addr}/sse"), BTreeMap::new(), 500),
            500,
        ) {
            Ok(_) => panic!("first non-comment SSE event must be endpoint"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("not endpoint"));
        handle.join().expect("fixture thread");
    }

    #[test]
    fn sse_post_rejects_chunked_oversized_body() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let methods = Arc::new(Mutex::new(Vec::new()));
        let fixture_methods = Arc::clone(&methods);
        let handle = thread::spawn(move || {
            let mut sse = accept_sse_stream(&listener);
            let (mut post, request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
            assert_eq!(request["method"], "notifications/initialized");
            let body = vec![b'x'; MCP_SSE_MAX_HTTP_RESPONSE_BODY_BYTES + 1];
            write_sse_post_chunked_body(&mut post, "202 Accepted", &body);
        });

        let mut session = McpSseSession::connect(
            "remote",
            sse_transport_for_url(format!("http://{addr}/sse"), BTreeMap::new(), 500),
            500,
        )
        .expect("connect SSE session");
        let error = session
            .notify::<serde_json::Value>("notifications/initialized", None, 500)
            .expect_err("oversized chunked POST response body should be rejected");
        assert!(error.to_string().contains("limit"));
        handle.join().expect("fixture thread");
    }

    #[test]
    fn sse_response_wait_has_operation_deadline_despite_comments_and_notifications() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let methods = Arc::new(Mutex::new(Vec::new()));
        let fixture_methods = Arc::clone(&methods);
        let handle = thread::spawn(move || {
            let mut sse = accept_sse_stream(&listener);
            let (mut post, request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
            assert_eq!(request["method"], "ping");
            write_sse_post_ack(&mut post);
            let notification = format!(
                "event: message\ndata: {}\r\n\r\n",
                json!({"jsonrpc":"2.0","method":"notifications/progress","params":{"tick":1}})
            );
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(350) {
                if try_write_sse_event(&mut sse, ": keepalive\r\n\r\n").is_err() {
                    break;
                }
                if try_write_sse_event(&mut sse, &notification).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(30));
            }
        });

        let mut session = McpSseSession::connect(
            "remote",
            sse_transport_for_url(format!("http://{addr}/sse"), BTreeMap::new(), 500),
            500,
        )
        .expect("connect SSE session");
        let start = Instant::now();
        let error = session
            .request::<serde_json::Value, serde_json::Value>(
                JsonRpcId::Number(123),
                "ping",
                None,
                120,
            )
            .expect_err("comments and no-id notifications should not bypass response timeout");
        assert!(matches!(
            error,
            McpServerManagerError::Timeout { method: "ping", .. }
        ));
        assert!(start.elapsed() < Duration::from_millis(500));
        handle.join().expect("fixture thread");
    }

    #[test]
    fn sse_post_rejects_keep_alive_without_response_framing_quickly() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let methods = Arc::new(Mutex::new(Vec::new()));
        let fixture_methods = Arc::clone(&methods);
        let handle = thread::spawn(move || {
            let mut sse = accept_sse_stream(&listener);
            let (mut post, request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
            assert_eq!(request["method"], "notifications/initialized");
            post.write_all(b"HTTP/1.1 202 Accepted\r\nConnection: keep-alive\r\n\r\n")
                .expect("write ambiguous keep-alive response");
            post.flush().expect("flush ambiguous keep-alive response");
            thread::sleep(Duration::from_millis(300));
        });

        let mut session = McpSseSession::connect(
            "remote",
            sse_transport_for_url(format!("http://{addr}/sse"), BTreeMap::new(), 2_000),
            2_000,
        )
        .expect("connect SSE session");
        let start = Instant::now();
        let error = session
            .notify::<serde_json::Value>("notifications/initialized", None, 2_000)
            .expect_err("ambiguous keep-alive POST response framing should be rejected");
        assert!(error.to_string().contains("Content-Length"));
        assert!(
            start.elapsed() < Duration::from_millis(500),
            "ambiguous framing should fail before operation timeout"
        );
        handle.join().expect("fixture thread");
    }

    #[test]
    fn https_sse_url_is_attemptable_and_reqwest_rustls_client_builds() {
        let url = parse_and_validate_sse_url("remote", "sse/connect", "https://example.test/sse")
            .expect("https SSE URL should be accepted");
        assert_eq!(url.scheme(), "https");

        build_sse_client(1_000).expect("reqwest rustls blocking client should build");
        build_sse_get_runtime().expect("SSE GET runtime should build");
        build_sse_get_client(1_000).expect("reqwest rustls async GET client should build");
    }

    #[test]
    fn sse_operation_deadline_rejects_zero_and_huge_timeout_without_panic() {
        let zero = sse_operation_deadline("remote", "tools/list", 0)
            .expect_err("zero SSE operation timeout should immediately time out");
        assert!(matches!(
            zero,
            McpServerManagerError::Timeout {
                server_name,
                method: "tools/list",
                timeout_ms: 0
            } if server_name == "remote"
        ));

        let huge =
            std::panic::catch_unwind(|| sse_operation_deadline("remote", "tools/list", u64::MAX));
        let huge = huge.expect("huge SSE operation timeout must not panic");
        let error = huge.expect_err("huge SSE operation timeout should be rejected structurally");
        assert!(matches!(
            error,
            McpServerManagerError::InvalidResponse {
                ref server_name,
                method: "tools/list",
                ..
            } if server_name == "remote"
        ));
        assert!(error.to_string().contains("too large"));
    }

    #[test]
    fn sse_connect_timeout_validation_fails_before_network_io() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        listener.set_nonblocking(true).expect("fixture nonblocking");
        let addr = listener.local_addr().expect("fixture addr");
        let url = format!("http://{addr}/sse");

        let zero = match McpSseSession::connect(
            "remote",
            sse_transport_for_url(url.clone(), BTreeMap::new(), 0),
            0,
        ) {
            Ok(_) => panic!("zero SSE connect timeout should fail before network IO"),
            Err(error) => error,
        };
        assert!(matches!(
            zero,
            McpServerManagerError::Timeout {
                server_name,
                method: "sse/connect",
                timeout_ms: 0
            } if server_name == "remote"
        ));

        let huge = match McpSseSession::connect(
            "remote",
            sse_transport_for_url(url, BTreeMap::new(), u64::MAX),
            u64::MAX,
        ) {
            Ok(_) => panic!("huge SSE connect timeout should fail before network IO"),
            Err(error) => error,
        };
        assert!(matches!(
            huge,
            McpServerManagerError::InvalidResponse {
                ref server_name,
                method: "sse/connect",
                ..
            } if server_name == "remote"
        ));
        assert!(huge.to_string().contains("too large"));

        match listener.accept() {
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Ok((_, peer)) => panic!("connect timeout validation unexpectedly opened {peer}"),
            Err(error) => panic!("fixture accept failed: {error}"),
        }
    }

    #[test]
    fn legacy_sse_without_object_tools_capability_does_not_request_tools_list() {
        for (label, capabilities) in [
            ("missing", json!({})),
            ("array", json!({ "tools": [] })),
            ("string", json!({ "tools": "yes" })),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
            let addr = listener.local_addr().expect("fixture addr");
            let methods = Arc::new(Mutex::new(Vec::new()));
            let fixture_methods = Arc::clone(&methods);
            let handle = thread::spawn(move || {
                let (mut sse, _) = listener.accept().expect("accept sse");
                let _ = read_sse_get_request(&mut sse);
                write_sse_headers(&mut sse);
                write_sse_event(&mut sse, "event: endpoint\ndata: /message\r\n\r\n");

                let (mut initialize, initialize_request) =
                    accept_sse_post(&listener, &fixture_methods, &mut sse);
                write_sse_post_ack(&mut initialize);
                let frame = format!(
                    "event: message\ndata: {}\r\n\r\n",
                    json!({
                        "jsonrpc": "2.0",
                        "id": initialize_request["id"].clone(),
                        "result": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": capabilities,
                            "serverInfo": { "name": "legacy-sse", "version": "1.0.0" }
                        }
                    })
                );
                write_sse_event(&mut sse, &frame);

                let (mut notification, _) = accept_sse_post(&listener, &fixture_methods, &mut sse);
                write_sse_post_ack(&mut notification);
            });

            let servers = BTreeMap::from([(
                "remote".to_string(),
                ScopedMcpServerConfig {
                    required: true,
                    scope: ConfigSource::Local,
                    config: McpServerConfig::Sse(McpRemoteServerConfig {
                        url: format!("http://{addr}/sse"),
                        headers: BTreeMap::new(),
                        headers_helper: None,
                        oauth: None,
                        tool_call_timeout_ms: Some(1_000),
                        heartbeat_timeout_ms: Some(1_000),
                        protocol_version: Some("2024-11-05".to_string()),
                        capabilities: crate::JsonValue::Object(BTreeMap::new()),
                    }),
                },
            )]);
            let mut manager = McpServerManager::from_servers(&servers);
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt");
            let report = runtime.block_on(manager.discover_catalogs_best_effort());

            assert!(report.failed_servers.is_empty(), "{label}");
            assert!(report.tools.is_empty(), "{label}");
            let catalog = report.catalogs.first().expect("catalog");
            assert!(catalog.tools_complete, "{label}");
            assert!(catalog.tools.is_empty(), "{label}");
            assert!(catalog
                .capabilities
                .as_ref()
                .is_some_and(|capabilities| !capabilities.tools));
            let methods = methods.lock().expect("methods lock").clone();
            assert_eq!(
                methods,
                vec![
                    "initialize".to_string(),
                    "notifications/initialized".to_string()
                ],
                "{label}"
            );
            handle.join().expect("fixture thread");
        }
    }

    #[test]
    fn legacy_sse_tools_list_follows_cursor_pagination() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let methods = Arc::new(Mutex::new(Vec::new()));
        let fixture_methods = Arc::clone(&methods);
        let handle = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept sse");
            let _ = read_sse_get_request(&mut sse);
            write_sse_headers(&mut sse);
            write_sse_event(&mut sse, "event: endpoint\ndata: /message\r\n\r\n");

            let (mut initialize, initialize_request) =
                accept_sse_post(&listener, &fixture_methods, &mut sse);
            write_sse_post_ack(&mut initialize);
            let frame = format!(
                "event: message\ndata: {}\r\n\r\n",
                json!({
                    "jsonrpc": "2.0",
                    "id": initialize_request["id"].clone(),
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "legacy-sse", "version": "1.0.0" }
                    }
                })
            );
            write_sse_event(&mut sse, &frame);

            let (mut notification, _) = accept_sse_post(&listener, &fixture_methods, &mut sse);
            write_sse_post_ack(&mut notification);

            let (mut ping, ping_request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
            write_sse_post_ack(&mut ping);
            let frame = format!(
                "event: message\ndata: {}\r\n\r\n",
                json!({"jsonrpc":"2.0","id":ping_request["id"].clone(),"result":{}})
            );
            write_sse_event(&mut sse, &frame);

            for (expected_cursor, tool_name, next_cursor) in [
                (None, "inspect", Some("page-2")),
                (Some("page-2"), "repair", None),
            ] {
                let (mut post, request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
                assert_eq!(
                    request
                        .get("params")
                        .and_then(|params| params.get("cursor"))
                        .and_then(serde_json::Value::as_str),
                    expected_cursor
                );
                write_sse_post_ack(&mut post);
                let frame = format!(
                    "event: message\ndata: {}\r\n\r\n",
                    json!({
                        "jsonrpc": "2.0",
                        "id": request["id"].clone(),
                        "result": {
                            "tools": [{
                                "name": tool_name,
                                "description": "fixture tool",
                                "inputSchema": { "type": "object" }
                            }],
                            "nextCursor": next_cursor
                        }
                    })
                );
                write_sse_event(&mut sse, &frame);
            }
        });

        let servers = BTreeMap::from([(
            "remote".to_string(),
            ScopedMcpServerConfig {
                required: true,
                scope: ConfigSource::Local,
                config: McpServerConfig::Sse(McpRemoteServerConfig {
                    url: format!("http://{addr}/sse"),
                    headers: BTreeMap::new(),
                    headers_helper: None,
                    oauth: None,
                    tool_call_timeout_ms: Some(1_000),
                    heartbeat_timeout_ms: Some(1_000),
                    protocol_version: Some("2024-11-05".to_string()),
                    capabilities: crate::JsonValue::Object(BTreeMap::new()),
                }),
            },
        )]);
        let mut manager = McpServerManager::from_servers(&servers);
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let report = runtime.block_on(manager.discover_catalogs_best_effort());

        assert!(report.failed_servers.is_empty());
        assert_eq!(report.tools.len(), 2);
        assert_eq!(report.tools[0].raw_name, "inspect");
        assert_eq!(report.tools[1].raw_name, "repair");
        assert_eq!(
            methods.lock().expect("methods lock").clone(),
            vec![
                "initialize".to_string(),
                "notifications/initialized".to_string(),
                "ping".to_string(),
                "tools/list".to_string(),
                "tools/list".to_string()
            ]
        );
        handle.join().expect("fixture thread");
    }

    #[test]
    fn legacy_sse_tools_list_rejects_repeated_cursor() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let methods = Arc::new(Mutex::new(Vec::new()));
        let fixture_methods = Arc::clone(&methods);
        let handle = thread::spawn(move || {
            let (mut sse, _) = listener.accept().expect("accept sse");
            let _ = read_sse_get_request(&mut sse);
            write_sse_headers(&mut sse);
            write_sse_event(&mut sse, "event: endpoint\ndata: /message\r\n\r\n");

            let (mut initialize, initialize_request) =
                accept_sse_post(&listener, &fixture_methods, &mut sse);
            write_sse_post_ack(&mut initialize);
            let frame = format!(
                "event: message\ndata: {}\r\n\r\n",
                json!({
                    "jsonrpc": "2.0",
                    "id": initialize_request["id"].clone(),
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "legacy-sse", "version": "1.0.0" }
                    }
                })
            );
            write_sse_event(&mut sse, &frame);

            let (mut notification, _) = accept_sse_post(&listener, &fixture_methods, &mut sse);
            write_sse_post_ack(&mut notification);

            let (mut ping, ping_request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
            write_sse_post_ack(&mut ping);
            let frame = format!(
                "event: message\ndata: {}\r\n\r\n",
                json!({"jsonrpc":"2.0","id":ping_request["id"].clone(),"result":{}})
            );
            write_sse_event(&mut sse, &frame);

            for tool_name in ["inspect", "repair"] {
                let (mut post, request) = accept_sse_post(&listener, &fixture_methods, &mut sse);
                write_sse_post_ack(&mut post);
                let frame = format!(
                    "event: message\ndata: {}\r\n\r\n",
                    json!({
                        "jsonrpc": "2.0",
                        "id": request["id"].clone(),
                        "result": {
                            "tools": [{
                                "name": tool_name,
                                "description": "fixture tool",
                                "inputSchema": { "type": "object" }
                            }],
                            "nextCursor": "repeat"
                        }
                    })
                );
                write_sse_event(&mut sse, &frame);
            }
        });

        let servers = BTreeMap::from([(
            "remote".to_string(),
            ScopedMcpServerConfig {
                required: true,
                scope: ConfigSource::Local,
                config: McpServerConfig::Sse(McpRemoteServerConfig {
                    url: format!("http://{addr}/sse"),
                    headers: BTreeMap::new(),
                    headers_helper: None,
                    oauth: None,
                    tool_call_timeout_ms: Some(1_000),
                    heartbeat_timeout_ms: Some(1_000),
                    protocol_version: Some("2024-11-05".to_string()),
                    capabilities: crate::JsonValue::Object(BTreeMap::new()),
                }),
            },
        )]);
        let mut manager = McpServerManager::from_servers(&servers);
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let error = runtime
            .block_on(manager.discover_tools())
            .expect_err("repeated SSE cursor should fail");

        assert!(error.to_string().contains("repeated"));
        assert_eq!(
            methods.lock().expect("methods lock").clone(),
            vec![
                "initialize".to_string(),
                "notifications/initialized".to_string(),
                "ping".to_string(),
                "tools/list".to_string(),
                "tools/list".to_string()
            ]
        );
        handle.join().expect("fixture thread");
    }

    #[test]
    fn discover_catalogs_best_effort_keeps_legacy_sse_tools_with_capability_degradations() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let addr = listener.local_addr().expect("fixture addr");
        let handle = thread::spawn(move || {
            let methods = Arc::new(Mutex::new(Vec::new()));
            let (mut sse, _) = listener.accept().expect("accept sse");
            let _ = read_sse_get_request(&mut sse);
            write_sse_headers(&mut sse);
            write_sse_event(&mut sse, "event: endpoint\ndata: /message\r\n\r\n");

            let (mut initialize, initialize_request) =
                accept_sse_post(&listener, &methods, &mut sse);
            write_sse_post_ack(&mut initialize);
            let frame = format!(
                "event: message\ndata: {}\r\n\r\n",
                json!({
                    "jsonrpc": "2.0",
                    "id": initialize_request["id"].clone(),
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {},
                            "resources": {},
                            "prompts": {}
                        },
                        "serverInfo": { "name": "legacy-sse", "version": "1.0.0" }
                    }
                })
            );
            write_sse_event(&mut sse, &frame);

            let (mut notification, _) = accept_sse_post(&listener, &methods, &mut sse);
            write_sse_post_ack(&mut notification);

            let (mut ping, ping_request) = accept_sse_post(&listener, &methods, &mut sse);
            write_sse_post_ack(&mut ping);
            let frame = format!(
                "event: message\ndata: {}\r\n\r\n",
                json!({"jsonrpc":"2.0","id":ping_request["id"].clone(),"result":{}})
            );
            write_sse_event(&mut sse, &frame);

            let (mut tools, tools_request) = accept_sse_post(&listener, &methods, &mut sse);
            write_sse_post_ack(&mut tools);
            let frame = format!(
                "event: message\ndata: {}\r\n\r\n",
                json!({
                    "jsonrpc": "2.0",
                    "id": tools_request["id"].clone(),
                    "result": {
                        "tools": [
                            {
                                "name": "inspect",
                                "description": "Inspect fixture",
                                "inputSchema": { "type": "object" }
                            }
                        ]
                    }
                })
            );
            write_sse_event(&mut sse, &frame);
        });

        let servers = BTreeMap::from([(
            "remote".to_string(),
            ScopedMcpServerConfig {
                required: true,
                scope: ConfigSource::Local,
                config: McpServerConfig::Sse(McpRemoteServerConfig {
                    url: format!("http://{addr}/sse"),
                    headers: BTreeMap::new(),
                    headers_helper: None,
                    oauth: None,
                    tool_call_timeout_ms: Some(1_000),
                    heartbeat_timeout_ms: Some(1_000),
                    protocol_version: Some("2024-11-05".to_string()),
                    capabilities: crate::JsonValue::Object(BTreeMap::new()),
                }),
            },
        )]);
        let mut manager = McpServerManager::from_servers(&servers);
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("rt");
        let report = runtime.block_on(manager.discover_catalogs_best_effort());

        assert!(report.failed_servers.is_empty());
        assert_eq!(report.tools.len(), 1);
        assert_eq!(report.tools[0].qualified_name, "mcp__remote__inspect");
        assert_eq!(report.catalogs.len(), 1);
        let catalog = &report.catalogs[0];
        assert_eq!(
            catalog.server_info.as_ref().map(|info| info.name.as_str()),
            Some("legacy-sse")
        );
        assert!(catalog
            .capabilities
            .as_ref()
            .is_some_and(|capabilities| capabilities.tools
                && capabilities.resources
                && capabilities.prompts));
        assert!(catalog.tools_complete);
        assert!(!catalog.resources_complete);
        assert!(!catalog.resource_templates_complete);
        assert!(!catalog.prompts_complete);
        assert_eq!(report.degraded_capabilities.len(), 2);
        assert!(report
            .degraded_capabilities
            .iter()
            .any(|degradation| degradation.method == "resources/list"
                && degradation.capability == McpCapabilityKind::Resources));
        assert!(report
            .degraded_capabilities
            .iter()
            .any(|degradation| degradation.method == "prompts/list"
                && degradation.capability == McpCapabilityKind::Prompts));
        assert!(report.degraded_startup.is_none());
        handle.join().expect("fixture thread");
    }

    #[test]
    fn manager_shutdown_terminates_spawned_children_and_is_idempotent() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("alpha.log");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config(&script_path, "alpha", &log_path),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            manager.discover_tools().await.expect("discover tools");
            manager.shutdown().await.expect("first shutdown");
            manager.shutdown().await.expect("second shutdown");

            cleanup_script(&script_path);
        });
    }

    #[test]
    fn manager_reuses_spawned_server_between_discovery_and_call() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("alpha.log");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config(&script_path, "alpha", &log_path),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            manager.discover_tools().await.expect("discover tools");
            let response = manager
                .call_tool(
                    &mcp_tool_name("alpha", "echo"),
                    Some(json!({"text": "reuse"})),
                )
                .await
                .expect("call tool");

            assert_eq!(
                response
                    .result
                    .as_ref()
                    .and_then(|result| result.structured_content.as_ref())
                    .and_then(|value| value.get("initializeCount")),
                Some(&json!(1))
            );

            let log = fs::read_to_string(&log_path).expect("read log");
            assert_eq!(log.lines().filter(|line| *line == "initialize").count(), 1);
            assert_eq!(
                log.lines().collect::<Vec<_>>(),
                vec![
                    "initialize",
                    "notifications/initialized",
                    "tools/list",
                    "tools/call",
                ]
            );

            manager.shutdown().await.expect("shutdown");
            cleanup_script(&script_path);
        });
    }

    #[test]
    fn manager_reports_unknown_qualified_tool_name() {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let script_path = write_manager_mcp_server_script();
            let root = script_path.parent().expect("script parent");
            let log_path = root.join("alpha.log");
            let servers = BTreeMap::from([(
                "alpha".to_string(),
                manager_server_config(&script_path, "alpha", &log_path),
            )]);
            let mut manager = McpServerManager::from_servers(&servers);

            let error = manager
                .call_tool(
                    &mcp_tool_name("alpha", "missing"),
                    Some(json!({"text": "nope"})),
                )
                .await
                .expect_err("unknown qualified tool should fail");

            match error {
                McpServerManagerError::UnknownTool { qualified_name } => {
                    assert_eq!(qualified_name, mcp_tool_name("alpha", "missing"));
                }
                other => panic!("expected unknown tool error, got {other:?}"),
            }

            cleanup_script(&script_path);
        });
    }
}
