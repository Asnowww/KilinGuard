use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::{McpOAuthConfig, McpServerConfig, ScopedMcpServerConfig};
use crate::json::JsonValue as RuntimeJsonValue;
use crate::mcp::{mcp_server_signature, mcp_tool_prefix, normalize_name_for_mcp};

pub const DEFAULT_MCP_TOOL_CALL_TIMEOUT_MS: u64 = 60_000;
pub const DEFAULT_MCP_HEARTBEAT_TIMEOUT_MS: u64 = 5_000;
pub const SUPPORTED_MCP_PROTOCOL_VERSIONS: &[&str] = &["2025-03-26", "2024-11-05"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpClientTransport {
    Stdio(McpStdioTransport),
    Sse(McpRemoteTransport),
    Http(McpRemoteTransport),
    WebSocket(McpRemoteTransport),
    Sdk(McpSdkTransport),
    ManagedProxy(McpManagedProxyTransport),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpStdioTransport {
    pub command: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub tool_call_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRemoteTransport {
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub headers_helper: Option<String>,
    pub auth: McpClientAuth,
    pub tool_call_timeout_ms: Option<u64>,
    pub heartbeat_timeout_ms: Option<u64>,
    pub protocol_version: Option<String>,
    pub capabilities: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSdkTransport {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpManagedProxyTransport {
    pub url: String,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpClientAuth {
    None,
    OAuth(McpOAuthConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpClientBootstrap {
    pub server_name: String,
    pub normalized_name: String,
    pub tool_prefix: String,
    pub signature: Option<String>,
    pub transport: McpClientTransport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpProtocolNegotiation {
    pub requested_protocol_version: String,
    pub server_protocol_version: String,
    pub compatible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransportHealthStatus {
    Healthy,
    Degraded,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpTransportHealthcheck {
    pub server_name: String,
    pub status: McpTransportHealthStatus,
    pub heartbeat_timeout_ms: u64,
    pub message: String,
}

impl McpClientBootstrap {
    #[must_use]
    pub fn from_scoped_config(server_name: &str, config: &ScopedMcpServerConfig) -> Self {
        Self {
            server_name: server_name.to_string(),
            normalized_name: normalize_name_for_mcp(server_name),
            tool_prefix: mcp_tool_prefix(server_name),
            signature: mcp_server_signature(&config.config),
            transport: McpClientTransport::from_config(&config.config),
        }
    }

    #[must_use]
    pub fn negotiate_protocol(
        &self,
        requested_protocol_version: &str,
        server_protocol_version: &str,
    ) -> McpProtocolNegotiation {
        McpProtocolNegotiation {
            requested_protocol_version: requested_protocol_version.to_string(),
            server_protocol_version: server_protocol_version.to_string(),
            compatible: requested_protocol_version == server_protocol_version
                && SUPPORTED_MCP_PROTOCOL_VERSIONS.contains(&server_protocol_version),
        }
    }

    #[must_use]
    pub fn healthcheck_model(&self) -> McpTransportHealthcheck {
        match &self.transport {
            McpClientTransport::Stdio(transport) => McpTransportHealthcheck {
                server_name: self.server_name.clone(),
                status: McpTransportHealthStatus::Healthy,
                heartbeat_timeout_ms: transport.resolved_tool_call_timeout_ms(),
                message: "stdio MCP transport is handled by the local process manager".to_string(),
            },
            McpClientTransport::Sse(transport) => McpTransportHealthcheck {
                server_name: self.server_name.clone(),
                status: McpTransportHealthStatus::Degraded,
                heartbeat_timeout_ms: transport
                    .heartbeat_timeout_ms
                    .unwrap_or(DEFAULT_MCP_HEARTBEAT_TIMEOUT_MS),
                message: format!(
                    "SSE MCP endpoint at {} is configured; runtime will attempt the legacy SSE + POST JSON-RPC transport over http:// or https:// and surface degraded errors on connection failure",
                    sanitized_remote_origin(&transport.url)
                ),
            },
            other => McpTransportHealthcheck {
                server_name: self.server_name.clone(),
                status: McpTransportHealthStatus::Unsupported,
                heartbeat_timeout_ms: DEFAULT_MCP_HEARTBEAT_TIMEOUT_MS,
                message: format!("MCP transport {other:?} is not handled by the stdio manager"),
            },
        }
    }
}

fn sanitized_remote_origin(raw_url: &str) -> String {
    reqwest::Url::parse(raw_url).map_or_else(
        |_| "<invalid-url>".to_string(),
        |url| {
            let scheme = url.scheme();
            let Some(host) = url.host_str() else {
                return format!("{scheme}://<unknown-host>");
            };
            let host = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]")
            } else {
                host.to_string()
            };
            url.port_or_known_default().map_or_else(
                || format!("{scheme}://{host}"),
                |port| format!("{scheme}://{host}:{port}"),
            )
        },
    )
}

impl McpClientTransport {
    #[must_use]
    pub fn from_config(config: &McpServerConfig) -> Self {
        match config {
            McpServerConfig::Stdio(config) => Self::Stdio(McpStdioTransport {
                command: config.command.clone(),
                args: config.args.clone(),
                env: config.env.clone(),
                tool_call_timeout_ms: config.tool_call_timeout_ms,
            }),
            McpServerConfig::Sse(config) => Self::Sse(McpRemoteTransport {
                url: config.url.clone(),
                headers: config.headers.clone(),
                headers_helper: config.headers_helper.clone(),
                auth: McpClientAuth::from_oauth(config.oauth.clone()),
                tool_call_timeout_ms: config.tool_call_timeout_ms,
                heartbeat_timeout_ms: config.heartbeat_timeout_ms,
                protocol_version: config.protocol_version.clone(),
                capabilities: runtime_json_to_serde(&config.capabilities),
            }),
            McpServerConfig::Http(config) => Self::Http(McpRemoteTransport {
                url: config.url.clone(),
                headers: config.headers.clone(),
                headers_helper: config.headers_helper.clone(),
                auth: McpClientAuth::from_oauth(config.oauth.clone()),
                tool_call_timeout_ms: config.tool_call_timeout_ms,
                heartbeat_timeout_ms: config.heartbeat_timeout_ms,
                protocol_version: config.protocol_version.clone(),
                capabilities: runtime_json_to_serde(&config.capabilities),
            }),
            McpServerConfig::Ws(config) => Self::WebSocket(McpRemoteTransport {
                url: config.url.clone(),
                headers: config.headers.clone(),
                headers_helper: config.headers_helper.clone(),
                auth: McpClientAuth::None,
                tool_call_timeout_ms: None,
                heartbeat_timeout_ms: None,
                protocol_version: None,
                capabilities: serde_json::json!({}),
            }),
            McpServerConfig::Sdk(config) => Self::Sdk(McpSdkTransport {
                name: config.name.clone(),
            }),
            McpServerConfig::ManagedProxy(config) => Self::ManagedProxy(McpManagedProxyTransport {
                url: config.url.clone(),
                id: config.id.clone(),
            }),
        }
    }
}

fn runtime_json_to_serde(value: &RuntimeJsonValue) -> serde_json::Value {
    match value {
        RuntimeJsonValue::Null => serde_json::Value::Null,
        RuntimeJsonValue::Bool(value) => serde_json::Value::Bool(*value),
        RuntimeJsonValue::Number(value) => serde_json::Value::Number((*value).into()),
        RuntimeJsonValue::String(value) => serde_json::Value::String(value.clone()),
        RuntimeJsonValue::Array(values) => {
            serde_json::Value::Array(values.iter().map(runtime_json_to_serde).collect())
        }
        RuntimeJsonValue::Object(entries) => serde_json::Value::Object(
            entries
                .iter()
                .map(|(key, value)| (key.clone(), runtime_json_to_serde(value)))
                .collect(),
        ),
    }
}

impl McpStdioTransport {
    #[must_use]
    pub fn resolved_tool_call_timeout_ms(&self) -> u64 {
        self.tool_call_timeout_ms
            .unwrap_or(DEFAULT_MCP_TOOL_CALL_TIMEOUT_MS)
    }
}

impl McpClientAuth {
    #[must_use]
    pub fn from_oauth(oauth: Option<McpOAuthConfig>) -> Self {
        oauth.map_or(Self::None, Self::OAuth)
    }

    #[must_use]
    pub const fn requires_user_auth(&self) -> bool {
        matches!(self, Self::OAuth(_))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::config::{
        ConfigSource, McpOAuthConfig, McpRemoteServerConfig, McpSdkServerConfig, McpServerConfig,
        McpStdioServerConfig, McpWebSocketServerConfig, ScopedMcpServerConfig,
    };

    use super::{McpClientAuth, McpClientBootstrap, McpClientTransport, McpTransportHealthStatus};

    #[test]
    fn bootstraps_stdio_servers_into_transport_targets() {
        let config = ScopedMcpServerConfig {
            required: false,
            scope: ConfigSource::User,
            config: McpServerConfig::Stdio(McpStdioServerConfig {
                command: "uvx".to_string(),
                args: vec!["mcp-server".to_string()],
                env: BTreeMap::from([("TOKEN".to_string(), "secret".to_string())]),
                tool_call_timeout_ms: Some(15_000),
            }),
        };

        let bootstrap = McpClientBootstrap::from_scoped_config("stdio-server", &config);
        assert_eq!(bootstrap.normalized_name, "stdio-server");
        assert_eq!(bootstrap.tool_prefix, "mcp__stdio-server__");
        assert_eq!(
            bootstrap.signature.as_deref(),
            Some("stdio:[uvx|mcp-server]")
        );
        match bootstrap.transport {
            McpClientTransport::Stdio(transport) => {
                assert_eq!(transport.command, "uvx");
                assert_eq!(transport.args, vec!["mcp-server"]);
                assert_eq!(
                    transport.env.get("TOKEN").map(String::as_str),
                    Some("secret")
                );
                assert_eq!(transport.tool_call_timeout_ms, Some(15_000));
            }
            other => panic!("expected stdio transport, got {other:?}"),
        }
    }

    #[test]
    fn bootstraps_remote_servers_with_oauth_auth() {
        let config = ScopedMcpServerConfig {
            required: false,
            scope: ConfigSource::Project,
            config: McpServerConfig::Http(McpRemoteServerConfig {
                url: "https://vendor.example/mcp".to_string(),
                headers: BTreeMap::from([("X-Test".to_string(), "1".to_string())]),
                headers_helper: Some("helper.sh".to_string()),
                oauth: Some(McpOAuthConfig {
                    client_id: Some("client-id".to_string()),
                    callback_port: Some(7777),
                    auth_server_metadata_url: Some(
                        "https://issuer.example/.well-known/oauth-authorization-server".to_string(),
                    ),
                    xaa: Some(true),
                }),
                tool_call_timeout_ms: None,
                heartbeat_timeout_ms: None,
                protocol_version: None,
                capabilities: crate::JsonValue::Object(BTreeMap::new()),
            }),
        };

        let bootstrap = McpClientBootstrap::from_scoped_config("remote server", &config);
        assert_eq!(bootstrap.normalized_name, "remote_server");
        match bootstrap.transport {
            McpClientTransport::Http(transport) => {
                assert_eq!(transport.url, "https://vendor.example/mcp");
                assert_eq!(transport.headers_helper.as_deref(), Some("helper.sh"));
                assert!(transport.auth.requires_user_auth());
                match transport.auth {
                    McpClientAuth::OAuth(oauth) => {
                        assert_eq!(oauth.client_id.as_deref(), Some("client-id"));
                    }
                    other @ McpClientAuth::None => panic!("expected oauth auth, got {other:?}"),
                }
            }
            other => panic!("expected http transport, got {other:?}"),
        }
    }

    #[test]
    fn sse_transport_reports_degraded_health_model() {
        let config = ScopedMcpServerConfig {
            required: false,
            scope: ConfigSource::Project,
            config: McpServerConfig::Sse(McpRemoteServerConfig {
                url: "http://vendor.example/sse".to_string(),
                headers: BTreeMap::new(),
                headers_helper: None,
                oauth: None,
                tool_call_timeout_ms: Some(15_000),
                heartbeat_timeout_ms: Some(2_500),
                protocol_version: Some("2025-03-26".to_string()),
                capabilities: crate::JsonValue::parse(r#"{"tools":{}}"#).expect("json"),
            }),
        };

        let bootstrap = McpClientBootstrap::from_scoped_config("remote sse", &config);
        let health = bootstrap.healthcheck_model();
        assert_eq!(health.status, McpTransportHealthStatus::Degraded);
        assert!(health.message.contains("SSE MCP endpoint"));

        let negotiation = bootstrap.negotiate_protocol("2025-03-26", "2025-03-26");
        assert!(negotiation.compatible);

        let legacy_negotiation = bootstrap.negotiate_protocol("2024-11-05", "2024-11-05");
        assert!(legacy_negotiation.compatible);
    }

    #[test]
    fn https_sse_transport_reports_attemptable_health_model() {
        let config = ScopedMcpServerConfig {
            required: false,
            scope: ConfigSource::Project,
            config: McpServerConfig::Sse(McpRemoteServerConfig {
                url: "https://vendor.example/sse".to_string(),
                headers: BTreeMap::new(),
                headers_helper: None,
                oauth: None,
                tool_call_timeout_ms: Some(15_000),
                heartbeat_timeout_ms: Some(2_500),
                protocol_version: Some("2025-03-26".to_string()),
                capabilities: crate::JsonValue::parse(r#"{"tools":{}}"#).expect("json"),
            }),
        };

        let bootstrap = McpClientBootstrap::from_scoped_config("remote sse", &config);
        let health = bootstrap.healthcheck_model();
        assert_eq!(health.status, McpTransportHealthStatus::Degraded);
        assert!(health.message.contains("https://"));
        assert!(health.message.contains("attempt"));
    }

    #[test]
    fn sse_health_model_does_not_echo_url_userinfo() {
        let config = ScopedMcpServerConfig {
            required: false,
            scope: ConfigSource::Project,
            config: McpServerConfig::Sse(McpRemoteServerConfig {
                url: "https://user:secret@vendor.example/sse".to_string(),
                headers: BTreeMap::new(),
                headers_helper: None,
                oauth: None,
                tool_call_timeout_ms: Some(15_000),
                heartbeat_timeout_ms: Some(2_500),
                protocol_version: Some("2025-03-26".to_string()),
                capabilities: crate::JsonValue::parse(r#"{"tools":{}}"#).expect("json"),
            }),
        };

        let bootstrap = McpClientBootstrap::from_scoped_config("remote sse", &config);
        let health = bootstrap.healthcheck_model();
        assert_eq!(health.status, McpTransportHealthStatus::Degraded);
        assert!(health.message.contains("https://vendor.example"));
        assert!(!health.message.contains("user"));
        assert!(!health.message.contains("secret"));
    }

    #[test]
    fn bootstraps_websocket_and_sdk_transports_without_oauth() {
        let ws = ScopedMcpServerConfig {
            required: false,
            scope: ConfigSource::Local,
            config: McpServerConfig::Ws(McpWebSocketServerConfig {
                url: "wss://vendor.example/mcp".to_string(),
                headers: BTreeMap::new(),
                headers_helper: None,
            }),
        };
        let sdk = ScopedMcpServerConfig {
            required: false,
            scope: ConfigSource::Local,
            config: McpServerConfig::Sdk(McpSdkServerConfig {
                name: "sdk-server".to_string(),
            }),
        };

        let ws_bootstrap = McpClientBootstrap::from_scoped_config("ws server", &ws);
        match ws_bootstrap.transport {
            McpClientTransport::WebSocket(transport) => {
                assert_eq!(transport.url, "wss://vendor.example/mcp");
                assert!(!transport.auth.requires_user_auth());
            }
            other => panic!("expected websocket transport, got {other:?}"),
        }

        let sdk_bootstrap = McpClientBootstrap::from_scoped_config("sdk server", &sdk);
        assert_eq!(sdk_bootstrap.signature, None);
        match sdk_bootstrap.transport {
            McpClientTransport::Sdk(transport) => {
                assert_eq!(transport.name, "sdk-server");
            }
            other => panic!("expected sdk transport, got {other:?}"),
        }
    }
}
