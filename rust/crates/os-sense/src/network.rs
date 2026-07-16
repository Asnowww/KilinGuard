use std::fs::File;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::command::run_limited_command;
use crate::error::{OsSenseError, Result};
use crate::model::{
    CollectionStatus, DnsCheck, FirewallStatus, HealthProbeResult, NetworkAnomaly,
    NetworkConnection, NetworkSnapshot, NetworkSourceStatus,
};
use crate::procfs::basic_meta;

const DEFAULT_CONNECTION_LIMIT: usize = 200;
const MAX_CONNECTION_LIMIT: usize = 1000;
const MAX_DNS_CHECKS: usize = 8;
const MAX_TCP_PROBES: usize = 5;
const MAX_PROBE_TIMEOUT_MS: u64 = 3_000;
const MAX_NETWORK_WARNINGS: usize = 32;
const MAX_NETWORK_ERROR_CHARS: usize = 256;
const MAX_PROC_NET_BYTES_PER_SOURCE: usize = 512 * 1024;
const MAX_PROC_NET_LINES_PER_SOURCE: usize = 16_384;
const MAX_CONNECTIONS_PER_SOURCE: usize = 4_096;
const MAX_REMOTE_FILTER_CHARS: usize = 128;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const PROC_NET_SOURCES: [(&str, &str); 4] = [
    ("/proc/net/tcp", "tcp"),
    ("/proc/net/tcp6", "tcp6"),
    ("/proc/net/udp", "udp"),
    ("/proc/net/udp6", "udp6"),
];

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkQuery {
    pub protocol: Option<String>,
    pub state: Option<String>,
    pub remote_contains: Option<String>,
    pub limit: Option<usize>,
    pub dns_names: Vec<String>,
    pub tcp_probes: Vec<TcpProbeRequest>,
    pub include_firewall: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TcpProbeRequest {
    pub host: String,
    pub port: u16,
    pub timeout_ms: Option<u64>,
}

impl NetworkQuery {
    pub fn validate(&self) -> Result<()> {
        normalize_protocol(self.protocol.as_deref())?;
        normalize_state(self.state.as_deref())?;
        if let Some(remote) = self.remote_contains.as_deref() {
            validate_nonblank_bounded("remote_contains", remote, MAX_REMOTE_FILTER_CHARS)?;
        }
        if let Some(limit) = self.limit {
            if !(1..=MAX_CONNECTION_LIMIT).contains(&limit) {
                return Err(OsSenseError::Configuration(format!(
                    "network query limit must be between 1 and {MAX_CONNECTION_LIMIT}"
                )));
            }
        }
        if self.dns_names.len() > MAX_DNS_CHECKS {
            return Err(OsSenseError::Configuration(format!(
                "network query dns_names must not contain more than {MAX_DNS_CHECKS} entries"
            )));
        }
        for name in &self.dns_names {
            validate_nonblank_bounded("dns_names entry", name, 253)?;
        }
        if self.tcp_probes.len() > MAX_TCP_PROBES {
            return Err(OsSenseError::Configuration(format!(
                "network query tcp_probes must not contain more than {MAX_TCP_PROBES} entries"
            )));
        }
        for probe in &self.tcp_probes {
            validate_nonblank_bounded("tcp_probes host", &probe.host, 253)?;
            if probe.port == 0 {
                return Err(OsSenseError::Configuration(
                    "network query tcp_probes port must be between 1 and 65535".to_string(),
                ));
            }
            if probe
                .timeout_ms
                .is_some_and(|timeout| !(1..=MAX_PROBE_TIMEOUT_MS).contains(&timeout))
            {
                return Err(OsSenseError::Configuration(format!(
                    "network query tcp_probes timeout_ms must be between 1 and {MAX_PROBE_TIMEOUT_MS}"
                )));
            }
        }
        Ok(())
    }
}

pub fn collect_network(query: &NetworkQuery) -> Result<NetworkSnapshot> {
    collect_network_with_reader(query, &SystemNetworkFileReader)
}

fn collect_network_with_reader(
    query: &NetworkQuery,
    reader: &dyn NetworkFileReader,
) -> Result<NetworkSnapshot> {
    query.validate()?;
    let filter = ValidatedNetworkFilter::from_query(query)?;
    let mut warnings = Vec::new();
    let mut omitted_warning_count = 0usize;
    let (mut connections, source_statuses) =
        collect_proc_net_connections(reader, &mut warnings, &mut omitted_warning_count);
    sort_and_deduplicate_connections(&mut connections);
    connections.retain(|connection| filter.matches(connection));
    let total = connections.len();
    let connection_limit = query.limit.unwrap_or(DEFAULT_CONNECTION_LIMIT);
    let mut relevant_source_statuses = source_statuses.iter().filter(|status| {
        filter
            .protocol
            .is_none_or(|protocol| status.protocol == protocol)
    });
    let source_truncated = relevant_source_statuses
        .clone()
        .any(|status| status.truncated);
    let truncated = source_truncated || total > connection_limit;
    let filter_complete = relevant_source_statuses
        .clone()
        .all(|status| status.status == CollectionStatus::Complete);
    let collection_status =
        if relevant_source_statuses.all(|status| status.status == CollectionStatus::Failed) {
            CollectionStatus::Failed
        } else if filter_complete {
            CollectionStatus::Complete
        } else {
            CollectionStatus::Partial
        };
    let anomalies = detect_network_anomalies(&connections);
    connections.truncate(connection_limit);

    let dns_checks = query
        .dns_names
        .iter()
        .map(|name| resolve_dns(name))
        .collect::<Vec<_>>();
    let tcp_probes = query.tcp_probes.iter().map(probe_tcp).collect::<Vec<_>>();
    let firewall = if query.include_firewall {
        collect_firewall_status()
    } else {
        Vec::new()
    };
    let mut meta = basic_meta("network", warnings);
    if meta.warnings.len() > MAX_NETWORK_WARNINGS {
        omitted_warning_count = omitted_warning_count
            .saturating_add(meta.warnings.len().saturating_sub(MAX_NETWORK_WARNINGS));
        meta.warnings.truncate(MAX_NETWORK_WARNINGS);
    }

    Ok(NetworkSnapshot {
        meta,
        truncated,
        collection_status,
        source_statuses,
        total,
        filter_complete,
        omitted_warning_count,
        connections,
        dns_checks,
        tcp_probes,
        firewall,
        anomalies,
    })
}

#[must_use]
pub fn parse_proc_net(content: &str, protocol: &str) -> Vec<NetworkConnection> {
    parse_proc_net_bytes(content.as_bytes(), protocol, false).connections
}

trait NetworkFileReader: Send + Sync {
    fn read_bounded(&self, path: &str, maximum_bytes: usize) -> io::Result<BoundedNetworkFile>;
}

struct SystemNetworkFileReader;

impl NetworkFileReader for SystemNetworkFileReader {
    fn read_bounded(&self, path: &str, maximum_bytes: usize) -> io::Result<BoundedNetworkFile> {
        let file = File::open(path)?;
        let mut bytes = Vec::with_capacity(maximum_bytes.min(64 * 1024));
        file.take((maximum_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        let truncated = bytes.len() > maximum_bytes;
        bytes.truncate(maximum_bytes);
        Ok(BoundedNetworkFile { bytes, truncated })
    }
}

struct BoundedNetworkFile {
    bytes: Vec<u8>,
    truncated: bool,
}

struct ParsedProcNet {
    connections: Vec<NetworkConnection>,
    parse_failure_count: usize,
    truncated: bool,
}

fn collect_proc_net_connections(
    reader: &dyn NetworkFileReader,
    warnings: &mut Vec<String>,
    omitted_warning_count: &mut usize,
) -> (Vec<NetworkConnection>, Vec<NetworkSourceStatus>) {
    let mut out = Vec::new();
    let mut statuses = Vec::with_capacity(PROC_NET_SOURCES.len());
    for (path, protocol) in PROC_NET_SOURCES {
        match reader.read_bounded(path, MAX_PROC_NET_BYTES_PER_SOURCE) {
            Ok(file) => {
                let parsed = parse_proc_net_bytes(&file.bytes, protocol, file.truncated);
                let status = if parsed.parse_failure_count > 0 || parsed.truncated {
                    CollectionStatus::Partial
                } else {
                    CollectionStatus::Complete
                };
                let error = (parsed.parse_failure_count > 0)
                    .then(|| format!("{} malformed rows were skipped", parsed.parse_failure_count));
                if let Some(error) = &error {
                    push_network_warning(
                        warnings,
                        omitted_warning_count,
                        format!("{path}: {error}"),
                    );
                }
                if parsed.truncated {
                    push_network_warning(
                        warnings,
                        omitted_warning_count,
                        format!("{path} exceeded the bounded collection limit"),
                    );
                }
                let entry_count = parsed.connections.len();
                out.extend(parsed.connections);
                statuses.push(NetworkSourceStatus {
                    protocol: protocol.to_string(),
                    actual_path: path.to_string(),
                    available: true,
                    status,
                    error,
                    entry_count,
                    parse_failure_count: parsed.parse_failure_count,
                    truncated: parsed.truncated,
                });
            }
            Err(error) => {
                let error = bounded_network_error(&error.to_string());
                push_network_warning(
                    warnings,
                    omitted_warning_count,
                    format!("failed to read {path}: {error}"),
                );
                statuses.push(NetworkSourceStatus {
                    protocol: protocol.to_string(),
                    actual_path: path.to_string(),
                    available: false,
                    status: CollectionStatus::Failed,
                    error: Some(error),
                    entry_count: 0,
                    parse_failure_count: 0,
                    truncated: false,
                });
            }
        }
    }
    (out, statuses)
}

fn parse_proc_net_bytes(bytes: &[u8], protocol: &str, input_truncated: bool) -> ParsedProcNet {
    let mut connections = Vec::new();
    let mut parse_failure_count = 0usize;
    let mut truncated = input_truncated;
    for (line_index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line_index == 0 || line.is_empty() {
            continue;
        }
        if line_index > MAX_PROC_NET_LINES_PER_SOURCE {
            truncated = true;
            break;
        }
        if connections.len() == MAX_CONNECTIONS_PER_SOURCE {
            truncated = true;
            break;
        }
        if line.len() > MAX_LOGICAL_PROC_NET_LINE_BYTES {
            parse_failure_count = parse_failure_count.saturating_add(1);
            truncated = true;
            continue;
        }
        let line = String::from_utf8_lossy(line);
        match parse_proc_net_line(&line, protocol) {
            Ok(connection) => connections.push(connection),
            Err(()) => parse_failure_count = parse_failure_count.saturating_add(1),
        }
    }
    ParsedProcNet {
        connections,
        parse_failure_count,
        truncated,
    }
}

const MAX_LOGICAL_PROC_NET_LINE_BYTES: usize = 4 * 1024;

fn parse_proc_net_line(line: &str, protocol: &str) -> std::result::Result<NetworkConnection, ()> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    let local = *parts.get(1).ok_or(())?;
    let remote = *parts.get(2).ok_or(())?;
    let state_code = *parts.get(3).ok_or(())?;
    let uid = parts.get(7).ok_or(())?.parse::<u32>().map_err(|_| ())?;
    let inode = parts.get(9).ok_or(())?.parse::<u64>().map_err(|_| ())?;
    let ipv6 = matches!(protocol, "tcp6" | "udp6");
    if !matches!(protocol, "tcp" | "tcp6" | "udp" | "udp6") {
        return Err(());
    }
    let (local_address, local_port) = parse_endpoint(local, ipv6).ok_or(())?;
    let (remote_address, remote_port) = parse_endpoint(remote, ipv6).ok_or(())?;
    let state = socket_state_name(protocol, state_code).ok_or(())?;
    Ok(NetworkConnection {
        protocol: protocol.to_string(),
        local_addr: local_address.clone(),
        local_address,
        local_port,
        remote_addr: remote_address.clone(),
        remote_address,
        remote_port,
        state,
        inode: Some(inode.to_string()),
        uid: Some(uid),
    })
}

fn parse_endpoint(value: &str, ipv6: bool) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = value.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let address = if ipv6 {
        if addr_hex.len() != 32 {
            return None;
        }
        let mut bytes = [0u8; 16];
        for (index, word) in addr_hex.as_bytes().chunks_exact(8).enumerate() {
            let word = std::str::from_utf8(word).ok()?;
            let value = u32::from_str_radix(word, 16).ok()?;
            bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        Ipv6Addr::from(bytes).to_string()
    } else {
        if addr_hex.len() != 8 {
            return None;
        }
        let raw = u32::from_str_radix(addr_hex, 16).ok()?;
        Ipv4Addr::from(raw.to_le_bytes()).to_string()
    };
    Some((address, port))
}

fn socket_state_name(protocol: &str, code: &str) -> Option<String> {
    let code = code.to_ascii_uppercase();
    if u8::from_str_radix(&code, 16).is_err() || code.len() != 2 {
        return None;
    }
    let state = if protocol.starts_with("udp") {
        match code.as_str() {
            "01" => "ESTABLISHED".to_string(),
            "07" => "UNCONNECTED".to_string(),
            _ => format!("UNKNOWN_{code}"),
        }
    } else {
        match code.as_str() {
            "01" => "ESTABLISHED",
            "02" => "SYN_SENT",
            "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",
            "05" => "FIN_WAIT2",
            "06" => "TIME_WAIT",
            "07" => "CLOSE",
            "08" => "CLOSE_WAIT",
            "09" => "LAST_ACK",
            "0A" => "LISTEN",
            "0B" => "CLOSING",
            "0C" => "NEW_SYN_RECV",
            _ => return Some(format!("UNKNOWN_{code}")),
        }
        .to_string()
    };
    Some(state)
}

struct ValidatedNetworkFilter {
    protocol: Option<&'static str>,
    state: Option<String>,
    remote_ascii_lower: Option<String>,
}

impl ValidatedNetworkFilter {
    fn from_query(query: &NetworkQuery) -> Result<Self> {
        Ok(Self {
            protocol: normalize_protocol(query.protocol.as_deref())?,
            state: normalize_state(query.state.as_deref())?,
            remote_ascii_lower: query
                .remote_contains
                .as_deref()
                .map(|remote| remote.trim().to_ascii_lowercase()),
        })
    }

    fn matches(&self, connection: &NetworkConnection) -> bool {
        self.protocol
            .is_none_or(|protocol| connection.protocol == protocol)
            && self
                .state
                .as_deref()
                .is_none_or(|state| connection.state == state)
            && self.remote_ascii_lower.as_deref().is_none_or(|remote| {
                connection
                    .remote_address
                    .to_ascii_lowercase()
                    .contains(remote)
            })
    }
}

fn normalize_protocol(protocol: Option<&str>) -> Result<Option<&'static str>> {
    let Some(protocol) = protocol else {
        return Ok(None);
    };
    validate_nonblank_bounded("protocol", protocol, 16)?;
    match protocol.trim().to_ascii_lowercase().as_str() {
        "all" => Ok(None),
        "tcp" | "tcp4" => Ok(Some("tcp")),
        "tcp6" | "tcpv6" => Ok(Some("tcp6")),
        "udp" | "udp4" => Ok(Some("udp")),
        "udp6" | "udpv6" => Ok(Some("udp6")),
        _ => Err(OsSenseError::Configuration(format!(
            "unsupported network protocol `{}`",
            bounded_network_error(protocol)
        ))),
    }
}

fn normalize_state(state: Option<&str>) -> Result<Option<String>> {
    let Some(state) = state else {
        return Ok(None);
    };
    validate_nonblank_bounded("state", state, 32)?;
    let compact = state.trim().to_ascii_uppercase().replace(['-', ' '], "_");
    let normalized = match compact.as_str() {
        "ESTABLISHED" => "ESTABLISHED",
        "SYN_SENT" | "SYNSENT" => "SYN_SENT",
        "SYN_RECV" | "SYN_RECEIVED" | "SYNRECV" => "SYN_RECV",
        "FIN_WAIT1" | "FIN_WAIT_1" => "FIN_WAIT1",
        "FIN_WAIT2" | "FIN_WAIT_2" => "FIN_WAIT2",
        "TIME_WAIT" | "TIMEWAIT" => "TIME_WAIT",
        "CLOSE" | "CLOSED" => "CLOSE",
        "CLOSE_WAIT" | "CLOSEWAIT" => "CLOSE_WAIT",
        "LAST_ACK" | "LASTACK" => "LAST_ACK",
        "LISTEN" | "LISTENING" => "LISTEN",
        "CLOSING" => "CLOSING",
        "NEW_SYN_RECV" | "NEWSYNRECV" => "NEW_SYN_RECV",
        "UNCONNECTED" | "UNCONN" => "UNCONNECTED",
        _ => {
            return Err(OsSenseError::Configuration(format!(
                "unsupported network state `{}`",
                bounded_network_error(state)
            )));
        }
    };
    Ok(Some(normalized.to_string()))
}

fn validate_nonblank_bounded(name: &str, value: &str, maximum_chars: usize) -> Result<()> {
    let count = value.chars().count();
    if value.trim().is_empty() || count > maximum_chars || value.contains('\0') {
        return Err(OsSenseError::Configuration(format!(
            "network query {name} must be non-blank and at most {maximum_chars} characters"
        )));
    }
    Ok(())
}

fn sort_and_deduplicate_connections(connections: &mut Vec<NetworkConnection>) {
    connections.sort_by(|left, right| {
        protocol_rank(&left.protocol)
            .cmp(&protocol_rank(&right.protocol))
            .then_with(|| left.local_address.cmp(&right.local_address))
            .then_with(|| left.local_port.cmp(&right.local_port))
            .then_with(|| left.remote_address.cmp(&right.remote_address))
            .then_with(|| left.remote_port.cmp(&right.remote_port))
            .then_with(|| left.state.cmp(&right.state))
            .then_with(|| left.uid.cmp(&right.uid))
            .then_with(|| left.inode.cmp(&right.inode))
    });
    connections.dedup();
}

fn protocol_rank(protocol: &str) -> u8 {
    match protocol {
        "tcp" => 0,
        "tcp6" => 1,
        "udp" => 2,
        "udp6" => 3,
        _ => 4,
    }
}

fn push_network_warning(warnings: &mut Vec<String>, omitted: &mut usize, warning: String) {
    if warnings.len() < MAX_NETWORK_WARNINGS {
        warnings.push(bounded_network_error(&warning));
    } else {
        *omitted = omitted.saturating_add(1);
    }
}

fn bounded_network_error(error: &str) -> String {
    error.chars().take(MAX_NETWORK_ERROR_CHARS).collect()
}

fn resolve_dns(name: &str) -> DnsCheck {
    if !probe_target_allowed(name) {
        return DnsCheck {
            name: name.to_string(),
            ok: false,
            resolved_addrs: Vec::new(),
            error: Some(
                "DNS checks are limited to localhost, .local names, and private IP literals"
                    .to_string(),
            ),
        };
    }
    match (name, 0).to_socket_addrs() {
        Ok(addrs) => {
            let resolved_addrs = addrs
                .map(|addr| addr.ip().to_string())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            DnsCheck {
                name: name.to_string(),
                ok: !resolved_addrs.is_empty(),
                resolved_addrs,
                error: None,
            }
        }
        Err(error) => DnsCheck {
            name: name.to_string(),
            ok: false,
            resolved_addrs: Vec::new(),
            error: Some(error.to_string()),
        },
    }
}

pub(crate) fn probe_tcp(request: &TcpProbeRequest) -> HealthProbeResult {
    let target = format!("{}:{}", request.host, request.port);
    if !probe_target_allowed(&request.host) {
        return HealthProbeResult {
            target,
            ok: false,
            latency_ms: None,
            error: Some(
                "TCP probes are limited to localhost, .local names, and private IP literals"
                    .to_string(),
            ),
        };
    }
    let timeout = Duration::from_millis(
        request
            .timeout_ms
            .unwrap_or(1000)
            .clamp(1, MAX_PROBE_TIMEOUT_MS),
    );
    let started = Instant::now();
    let addr = match target
        .as_str()
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
    {
        Some(addr) => addr,
        None => {
            return HealthProbeResult {
                target,
                ok: false,
                latency_ms: None,
                error: Some("DNS resolution returned no socket address".to_string()),
            };
        }
    };
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => HealthProbeResult {
            target,
            ok: true,
            latency_ms: Some(started.elapsed().as_millis()),
            error: None,
        },
        Err(error) => HealthProbeResult {
            target,
            ok: false,
            latency_ms: Some(started.elapsed().as_millis()),
            error: Some(error.to_string()),
        },
    }
}

fn collect_firewall_status() -> Vec<FirewallStatus> {
    vec![
        run_firewall_command("firewalld", "firewall-cmd", &["--state"]),
        run_firewall_command("nftables", "nft", &["list", "ruleset"]),
        run_firewall_command("iptables", "iptables", &["-S"]),
    ]
}

fn run_firewall_command(backend: &str, command: &str, args: &[&str]) -> FirewallStatus {
    match run_limited_command(command, args, COMMAND_TIMEOUT, 64 * 1024, 16 * 1024) {
        Ok(output) if output.success => FirewallStatus {
            backend: backend.to_string(),
            available: true,
            status: if output.stdout_truncated {
                "ok (output truncated)".to_string()
            } else {
                output
                    .stdout
                    .lines()
                    .next()
                    .unwrap_or("ok")
                    .trim()
                    .to_string()
            },
            rules_sample: output.stdout.lines().take(20).map(str::to_string).collect(),
        },
        Ok(output) => FirewallStatus {
            backend: backend.to_string(),
            available: true,
            status: if output.timed_out {
                "timed out".to_string()
            } else {
                format!("failed: {}", output.stderr.trim())
            },
            rules_sample: Vec::new(),
        },
        Err(error) => FirewallStatus {
            backend: backend.to_string(),
            available: false,
            status: error.to_string(),
            rules_sample: Vec::new(),
        },
    }
}

fn probe_target_allowed(host: &str) -> bool {
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".local") {
        return true;
    }
    if let Ok(addr) = host.parse::<IpAddr>() {
        return match addr {
            IpAddr::V4(addr) => {
                addr.is_loopback()
                    || addr.is_private()
                    || addr.is_link_local()
                    || addr.octets()[0] == 0
            }
            IpAddr::V6(addr) => {
                let first = addr.segments()[0];
                addr.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
            }
        };
    }
    false
}

fn detect_network_anomalies(connections: &[NetworkConnection]) -> Vec<NetworkAnomaly> {
    let mut anomalies = Vec::new();
    let time_wait = connections
        .iter()
        .filter(|connection| connection.state == "TIME_WAIT")
        .count();
    if time_wait >= 100 {
        anomalies.push(NetworkAnomaly {
            kind: "many_time_wait".to_string(),
            message: "TIME_WAIT connection count is elevated".to_string(),
            count: time_wait,
        });
    }
    let external_established = connections
        .iter()
        .filter(|connection| connection.state == "ESTABLISHED")
        .filter(|connection| !is_private_or_local(connection_remote_address(connection)))
        .count();
    if external_established >= 20 {
        anomalies.push(NetworkAnomaly {
            kind: "many_external_connections".to_string(),
            message: "established external connection count is elevated".to_string(),
            count: external_established,
        });
    }
    anomalies
}

fn is_private_or_local(addr: &str) -> bool {
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(addr)) => {
            addr.is_unspecified() || addr.is_loopback() || addr.is_private() || addr.is_link_local()
        }
        Ok(IpAddr::V6(addr)) => {
            addr.is_unspecified()
                || addr.is_loopback()
                || (addr.segments()[0] & 0xfe00) == 0xfc00
                || (addr.segments()[0] & 0xffc0) == 0xfe80
                || addr
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback() || mapped.is_private())
        }
        Err(_) => false,
    }
}

fn connection_remote_address(connection: &NetworkConnection) -> &str {
    if connection.remote_address.is_empty() {
        &connection.remote_addr
    } else {
        &connection.remote_address
    }
}

#[allow(dead_code)]
fn socket_addr_to_string(addr: SocketAddr) -> String {
    addr.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::ErrorKind;

    const HEADER: &str =
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

    #[derive(Clone)]
    enum FixtureRead {
        Bytes(Vec<u8>, bool),
        Error(ErrorKind),
    }

    #[derive(Default)]
    struct FixtureNetworkFileReader {
        files: BTreeMap<String, FixtureRead>,
    }

    impl FixtureNetworkFileReader {
        fn complete() -> Self {
            let mut reader = Self::default();
            for (path, _) in PROC_NET_SOURCES {
                reader = reader.with_text(path, HEADER);
            }
            reader
        }

        fn with_text(mut self, path: &str, content: impl Into<String>) -> Self {
            self.files.insert(
                path.to_string(),
                FixtureRead::Bytes(content.into().into_bytes(), false),
            );
            self
        }

        fn with_bytes(mut self, path: &str, bytes: Vec<u8>) -> Self {
            self.files
                .insert(path.to_string(), FixtureRead::Bytes(bytes, false));
            self
        }

        fn with_truncated_text(mut self, path: &str, content: impl Into<String>) -> Self {
            self.files.insert(
                path.to_string(),
                FixtureRead::Bytes(content.into().into_bytes(), true),
            );
            self
        }

        fn with_error(mut self, path: &str, kind: ErrorKind) -> Self {
            self.files
                .insert(path.to_string(), FixtureRead::Error(kind));
            self
        }
    }

    impl NetworkFileReader for FixtureNetworkFileReader {
        fn read_bounded(&self, path: &str, maximum_bytes: usize) -> io::Result<BoundedNetworkFile> {
            match self.files.get(path) {
                Some(FixtureRead::Bytes(bytes, forced_truncated)) => {
                    let mut bytes = bytes.clone();
                    let truncated = *forced_truncated || bytes.len() > maximum_bytes;
                    bytes.truncate(maximum_bytes);
                    Ok(BoundedNetworkFile { bytes, truncated })
                }
                Some(FixtureRead::Error(kind)) => Err(io::Error::from(*kind)),
                None => Err(io::Error::from(ErrorKind::NotFound)),
            }
        }
    }

    fn proc_row(
        slot: usize,
        local: &str,
        remote: &str,
        state: &str,
        uid: u32,
        inode: u64,
    ) -> String {
        format!(
            "{slot:4}: {local} {remote} {state} 00000000:00000000 00:00000000 00000000 {uid:5} 0 {inode} 1 0000000000000000 100 0 0 10 0\n"
        )
    }

    fn table(rows: impl IntoIterator<Item = String>) -> String {
        let mut output = HEADER.to_string();
        output.extend(rows);
        output
    }

    #[test]
    fn parses_proc_net_ipv4_ports_uid_and_inode() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 0200007F:01BB 01 00000000:00000000 00:00000000 00000000   100        0 12345 1 0000000000000000 100 0 0 10 0\n";
        let connections = parse_proc_net(content, "tcp");
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].local_addr, "127.0.0.1");
        assert_eq!(connections[0].local_address, "127.0.0.1");
        assert_eq!(connections[0].local_port, 8080);
        assert_eq!(connections[0].remote_addr, "127.0.0.2");
        assert_eq!(connections[0].remote_address, "127.0.0.2");
        assert_eq!(connections[0].remote_port, 443);
        assert_eq!(connections[0].state, "ESTABLISHED");
        assert_eq!(connections[0].inode.as_deref(), Some("12345"));
        assert_eq!(connections[0].uid, Some(100));
    }

    #[test]
    fn parses_all_four_proc_tables_with_ipv6_word_order_and_wildcards() {
        let reader = FixtureNetworkFileReader::complete()
            .with_text(
                "/proc/net/tcp",
                table([proc_row(0, "00000000:0016", "00000000:0000", "0A", 0, 10)]),
            )
            .with_text(
                "/proc/net/tcp6",
                table([proc_row(
                    0,
                    "00000000000000000000000001000000:1F90",
                    "0000000000000000FFFF00000100007F:01BB",
                    "01",
                    1000,
                    11,
                )]),
            )
            .with_text(
                "/proc/net/udp",
                table([proc_row(0, "00000000:0035", "00000000:0000", "07", 53, 12)]),
            )
            .with_text(
                "/proc/net/udp6",
                table([proc_row(
                    0,
                    "00000000000000000000000000000000:14E9",
                    "00000000000000000000000001000000:14E9",
                    "01",
                    1001,
                    13,
                )]),
            );
        let snapshot = collect_network_with_reader(&NetworkQuery::default(), &reader)
            .expect("four proc net tables");

        assert_eq!(snapshot.collection_status, CollectionStatus::Complete);
        assert!(snapshot.filter_complete);
        assert_eq!(snapshot.total, 4);
        assert_eq!(
            snapshot
                .connections
                .iter()
                .map(|connection| connection.protocol.as_str())
                .collect::<Vec<_>>(),
            ["tcp", "tcp6", "udp", "udp6"]
        );
        assert_eq!(snapshot.connections[0].local_address, "0.0.0.0");
        assert_eq!(snapshot.connections[0].state, "LISTEN");
        assert_eq!(snapshot.connections[1].local_address, "::1");
        assert_eq!(snapshot.connections[1].remote_address, "::ffff:127.0.0.1");
        assert_eq!(snapshot.connections[2].state, "UNCONNECTED");
        assert_eq!(snapshot.connections[3].local_address, "::");
        assert_eq!(snapshot.connections[3].remote_address, "::1");
        assert!(snapshot
            .source_statuses
            .iter()
            .all(|status| status.status == CollectionStatus::Complete));
    }

    #[test]
    fn maps_all_linux_tcp_states_and_keeps_udp_semantics_separate() {
        let expected = [
            ("01", "ESTABLISHED"),
            ("02", "SYN_SENT"),
            ("03", "SYN_RECV"),
            ("04", "FIN_WAIT1"),
            ("05", "FIN_WAIT2"),
            ("06", "TIME_WAIT"),
            ("07", "CLOSE"),
            ("08", "CLOSE_WAIT"),
            ("09", "LAST_ACK"),
            ("0A", "LISTEN"),
            ("0B", "CLOSING"),
            ("0C", "NEW_SYN_RECV"),
        ];
        for (code, state) in expected {
            let parsed = parse_proc_net(
                &table([proc_row(0, "0100007F:0016", "00000000:0000", code, 0, 1)]),
                "tcp",
            );
            assert_eq!(parsed[0].state, state);
        }
        let udp = parse_proc_net(
            &table([proc_row(0, "00000000:0035", "00000000:0000", "07", 0, 2)]),
            "udp",
        );
        assert_eq!(udp[0].state, "UNCONNECTED");
    }

    #[test]
    fn reports_parse_permission_and_missing_source_failures_without_losing_valid_rows() {
        let mut tcp = table([proc_row(0, "0100007F:0016", "00000000:0000", "0A", 0, 21)]);
        tcp.push_str("malformed row\n");
        let reader = FixtureNetworkFileReader::complete()
            .with_text("/proc/net/tcp", tcp)
            .with_error("/proc/net/tcp6", ErrorKind::PermissionDenied)
            .with_error("/proc/net/udp", ErrorKind::NotFound)
            .with_text(
                "/proc/net/udp6",
                table([proc_row(
                    0,
                    "00000000000000000000000000000000:0035",
                    "00000000000000000000000000000000:0000",
                    "07",
                    0,
                    22,
                )]),
            );
        let snapshot = collect_network_with_reader(&NetworkQuery::default(), &reader)
            .expect("partial collection");
        assert_eq!(snapshot.collection_status, CollectionStatus::Partial);
        assert!(!snapshot.filter_complete);
        assert_eq!(snapshot.total, 2);
        assert_eq!(snapshot.connections.len(), 2);
        assert_eq!(snapshot.source_statuses[0].parse_failure_count, 1);
        assert_eq!(
            snapshot.source_statuses[0].status,
            CollectionStatus::Partial
        );
        assert_eq!(snapshot.source_statuses[1].status, CollectionStatus::Failed);
        assert_eq!(snapshot.source_statuses[2].status, CollectionStatus::Failed);
        assert!(snapshot.meta.warnings.len() <= MAX_NETWORK_WARNINGS);

        let failed_reader = FixtureNetworkFileReader::default();
        let failed = collect_network_with_reader(&NetworkQuery::default(), &failed_reader)
            .expect("all failures remain structured output");
        assert_eq!(failed.collection_status, CollectionStatus::Failed);
        assert_eq!(failed.total, 0);
        assert!(failed.connections.is_empty());
    }

    #[test]
    fn protocol_filter_status_uses_only_the_relevant_source() {
        let query = NetworkQuery {
            protocol: Some("tcp".to_string()),
            ..NetworkQuery::default()
        };
        let tcp_table = table([proc_row(0, "0100007F:0016", "00000000:0000", "0A", 0, 30)]);

        let unrelated_failures = FixtureNetworkFileReader::complete()
            .with_text("/proc/net/tcp", tcp_table.clone())
            .with_error("/proc/net/tcp6", ErrorKind::PermissionDenied)
            .with_error("/proc/net/udp", ErrorKind::NotFound)
            .with_truncated_text("/proc/net/udp6", HEADER);
        let complete = collect_network_with_reader(&query, &unrelated_failures)
            .expect("target source complete");
        assert_eq!(complete.collection_status, CollectionStatus::Complete);
        assert!(complete.filter_complete);
        assert!(!complete.truncated);
        assert_eq!(complete.source_statuses.len(), 4);

        let target_failed = FixtureNetworkFileReader::complete()
            .with_error("/proc/net/tcp", ErrorKind::PermissionDenied);
        let failed =
            collect_network_with_reader(&query, &target_failed).expect("target source failed");
        assert_eq!(failed.collection_status, CollectionStatus::Failed);
        assert!(!failed.filter_complete);
        assert!(!failed.truncated);

        let mut malformed = tcp_table.clone();
        malformed.push_str("malformed row\n");
        let target_partial =
            FixtureNetworkFileReader::complete().with_text("/proc/net/tcp", malformed);
        let partial =
            collect_network_with_reader(&query, &target_partial).expect("target source partial");
        assert_eq!(partial.collection_status, CollectionStatus::Partial);
        assert!(!partial.filter_complete);
        assert!(!partial.truncated);

        let target_truncated =
            FixtureNetworkFileReader::complete().with_truncated_text("/proc/net/tcp", tcp_table);
        let truncated = collect_network_with_reader(&query, &target_truncated)
            .expect("target source truncated");
        assert_eq!(truncated.collection_status, CollectionStatus::Partial);
        assert!(!truncated.filter_complete);
        assert!(truncated.truncated);
    }

    #[test]
    fn filters_are_combined_before_limit_and_aliases_are_case_insensitive() {
        let rows = (0..4)
            .map(|index| {
                proc_row(
                    index,
                    &format!("0100007F:{:04X}", 8_000 + index),
                    &format!("{:02X}080808:01BB", index + 1),
                    if index == 3 { "0A" } else { "01" },
                    1000,
                    100 + index as u64,
                )
            })
            .collect::<Vec<_>>();
        let reader = FixtureNetworkFileReader::complete()
            .with_text("/proc/net/tcp", table(rows))
            .with_text(
                "/proc/net/udp",
                table([proc_row(0, "00000000:0035", "00000000:0000", "07", 0, 200)]),
            );
        let snapshot = collect_network_with_reader(
            &NetworkQuery {
                protocol: Some("TcP4".to_string()),
                state: Some("established".to_string()),
                remote_contains: Some("8.8".to_string()),
                limit: Some(1),
                ..NetworkQuery::default()
            },
            &reader,
        )
        .expect("filtered network query");
        assert_eq!(snapshot.total, 3);
        assert_eq!(snapshot.connections.len(), 1);
        assert!(snapshot.truncated);
        assert!(snapshot.filter_complete);
        assert_eq!(snapshot.connections[0].protocol, "tcp");
        assert_eq!(snapshot.connections[0].state, "ESTABLISHED");

        let udp = collect_network_with_reader(
            &NetworkQuery {
                protocol: Some("UDP4".to_string()),
                state: Some("unconn".to_string()),
                ..NetworkQuery::default()
            },
            &reader,
        )
        .expect("UDP state query");
        assert_eq!(udp.total, 1);
        assert_eq!(udp.connections[0].state, "UNCONNECTED");
    }

    #[test]
    fn validates_network_query_without_silent_clamping_or_truncation() {
        for query in [
            NetworkQuery {
                protocol: Some("sctp".to_string()),
                ..NetworkQuery::default()
            },
            NetworkQuery {
                state: Some("mystery".to_string()),
                ..NetworkQuery::default()
            },
            NetworkQuery {
                remote_contains: Some("  ".to_string()),
                ..NetworkQuery::default()
            },
            NetworkQuery {
                limit: Some(0),
                ..NetworkQuery::default()
            },
            NetworkQuery {
                limit: Some(MAX_CONNECTION_LIMIT + 1),
                ..NetworkQuery::default()
            },
            NetworkQuery {
                dns_names: vec!["host.local".to_string(); MAX_DNS_CHECKS + 1],
                ..NetworkQuery::default()
            },
            NetworkQuery {
                tcp_probes: vec![
                    TcpProbeRequest {
                        host: "localhost".to_string(),
                        port: 1,
                        timeout_ms: Some(1),
                    };
                    MAX_TCP_PROBES + 1
                ],
                ..NetworkQuery::default()
            },
        ] {
            assert!(matches!(
                query.validate(),
                Err(OsSenseError::Configuration(_))
            ));
        }
    }

    #[test]
    fn proc_table_bytes_lines_connections_and_warnings_are_hard_bounded() {
        let rows = (0..(MAX_CONNECTIONS_PER_SOURCE + 100))
            .map(|index| {
                proc_row(
                    index,
                    "0100007F:0016",
                    "00000000:0000",
                    "0A",
                    0,
                    index as u64,
                )
            })
            .collect::<Vec<_>>();
        let mut bytes = table(rows).into_bytes();
        bytes.extend_from_slice(b"\xff\xfe malformed\n");
        let reader = FixtureNetworkFileReader::complete().with_bytes("/proc/net/tcp", bytes);
        let snapshot = collect_network_with_reader(
            &NetworkQuery {
                limit: Some(MAX_CONNECTION_LIMIT),
                ..NetworkQuery::default()
            },
            &reader,
        )
        .expect("bounded proc table");
        assert!(snapshot.total <= MAX_CONNECTIONS_PER_SOURCE);
        assert!(snapshot.connections.len() <= MAX_CONNECTION_LIMIT);
        assert!(snapshot.truncated);
        assert!(!snapshot.filter_complete);
        assert!(snapshot.meta.warnings.len() <= MAX_NETWORK_WARNINGS);
    }

    #[test]
    fn legacy_network_json_defaults_new_fields_and_keeps_old_addresses() {
        let legacy = serde_json::json!({
            "meta": {
                "collected_at_ms": 1,
                "source": "network",
                "platform": {
                    "os": "linux",
                    "arch": "loongarch64",
                    "kernel_version": null,
                    "loongarch": {
                        "detected": true,
                        "cpu_model": null,
                        "hwmon_paths": []
                    }
                },
                "warnings": []
            },
            "truncated": false,
            "connections": [{
                "protocol": "tcp",
                "local_addr": "127.0.0.1",
                "local_port": 22,
                "remote_addr": "10.0.0.2",
                "remote_port": 40000,
                "state": "ESTABLISHED",
                "inode": "42"
            }],
            "dns_checks": [],
            "tcp_probes": [],
            "firewall": [],
            "anomalies": []
        });
        let snapshot: NetworkSnapshot =
            serde_json::from_value(legacy).expect("legacy network snapshot");
        assert_eq!(snapshot.collection_status, CollectionStatus::Partial);
        assert!(snapshot.filter_complete);
        assert_eq!(snapshot.total, 0);
        assert_eq!(snapshot.connections[0].local_addr, "127.0.0.1");
        assert!(snapshot.connections[0].local_address.is_empty());
        assert_eq!(snapshot.connections[0].uid, None);
    }

    #[test]
    fn detects_many_time_wait_connections() {
        let connections = (0..100)
            .map(|idx| NetworkConnection {
                protocol: "tcp".to_string(),
                local_addr: "127.0.0.1".to_string(),
                local_address: "127.0.0.1".to_string(),
                local_port: idx,
                remote_addr: "127.0.0.1".to_string(),
                remote_address: "127.0.0.1".to_string(),
                remote_port: 80,
                state: "TIME_WAIT".to_string(),
                inode: None,
                uid: None,
            })
            .collect::<Vec<_>>();
        let anomalies = detect_network_anomalies(&connections);
        assert!(anomalies.iter().any(|item| item.kind == "many_time_wait"));
    }
}
