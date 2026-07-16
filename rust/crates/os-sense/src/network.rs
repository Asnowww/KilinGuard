use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Component, Path};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::command::run_limited_command;
use crate::error::{OsSenseError, Result};
use crate::model::{
    CollectionStatus, DnsCheck, FirewallStatus, HealthProbeResult, NetworkAnomaly,
    NetworkAnomalyEvidence, NetworkBaseline, NetworkBaselineEntry, NetworkConnection,
    NetworkSnapshot, NetworkSourceStatus,
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
const MAX_NETWORK_ANOMALIES: usize = 32;
const TIME_WAIT_GROUP_THRESHOLD: usize = 20;
const PORT_SCAN_DISTINCT_PORT_THRESHOLD: usize = 10;
const MAX_NETWORK_BASELINE_ID_CHARS: usize = 64;
const MAX_NETWORK_BASELINE_PATH_BYTES: usize = 4 * 1024;
pub const NETWORK_BASELINE_VERSION: u32 = 1;
pub const MAX_NETWORK_BASELINE_ENTRIES: usize = 256;
pub const MAX_NETWORK_BASELINE_JSON_BYTES: usize = 64 * 1024;
pub const OS_NETWORK_BASELINE_FILE_ENV: &str = "CLAW_OS_NETWORK_BASELINE_FILE";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
const PROC_NET_SOURCES: [(&str, &str); 4] = [
    ("/proc/net/tcp", "tcp"),
    ("/proc/net/tcp6", "tcp6"),
    ("/proc/net/udp", "udp"),
    ("/proc/net/udp6", "udp6"),
];

static CONFIGURED_NETWORK_BASELINE: LazyLock<std::result::Result<Option<NetworkBaseline>, String>> =
    LazyLock::new(|| {
        load_network_baseline_from_environment()
            .map_err(|error| bounded_network_error(&error.to_string()))
    });

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

impl NetworkBaseline {
    pub fn from_json_bytes(value: &[u8]) -> Result<Self> {
        if value.len() > MAX_NETWORK_BASELINE_JSON_BYTES {
            return Err(OsSenseError::Configuration(format!(
                "network baseline JSON must not exceed {MAX_NETWORK_BASELINE_JSON_BYTES} bytes"
            )));
        }
        let baseline = serde_json::from_slice::<Self>(value).map_err(|error| {
            OsSenseError::Configuration(format!("invalid network baseline JSON: {error}"))
        })?;
        baseline.validate()?;
        Ok(baseline)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != NETWORK_BASELINE_VERSION {
            return Err(OsSenseError::Configuration(format!(
                "network baseline version must be {NETWORK_BASELINE_VERSION}"
            )));
        }
        if self.id.is_empty()
            || self.id.chars().count() > MAX_NETWORK_BASELINE_ID_CHARS
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(OsSenseError::Configuration(format!(
                "network baseline id must contain 1 to {MAX_NETWORK_BASELINE_ID_CHARS} ASCII letters, digits, '.', '_', or '-'"
            )));
        }
        if self.entries.len() > MAX_NETWORK_BASELINE_ENTRIES {
            return Err(OsSenseError::Configuration(format!(
                "network baseline must not contain more than {MAX_NETWORK_BASELINE_ENTRIES} entries"
            )));
        }
        for (index, entry) in self.entries.iter().enumerate() {
            validate_network_baseline_entry(entry).map_err(|error| {
                OsSenseError::Configuration(format!(
                    "network baseline entries[{index}] is invalid: {error}"
                ))
            })?;
        }
        let encoded = serde_json::to_vec(self).map_err(|error| {
            OsSenseError::Configuration(format!("failed to encode network baseline: {error}"))
        })?;
        if encoded.len() > MAX_NETWORK_BASELINE_JSON_BYTES {
            return Err(OsSenseError::Configuration(format!(
                "network baseline JSON must not exceed {MAX_NETWORK_BASELINE_JSON_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Clone)]
struct ValidatedOutboundRule {
    protocol: String,
    destination: IpNet,
    port_range: Option<(u16, u16)>,
}

fn validate_network_baseline_entry(entry: &NetworkBaselineEntry) -> Result<ValidatedOutboundRule> {
    let protocol = match entry.protocol.as_str() {
        "tcp" | "tcp6" | "udp" | "udp6" => entry.protocol.clone(),
        _ => {
            return Err(OsSenseError::Configuration(
                "protocol must be one of tcp, tcp6, udp, or udp6".to_string(),
            ));
        }
    };
    if entry.destination.is_empty()
        || entry.destination.chars().count() > 128
        || entry.destination.contains('\0')
    {
        return Err(OsSenseError::Configuration(
            "destination must contain 1 to 128 characters without NUL".to_string(),
        ));
    }
    let destination = parse_baseline_destination(&entry.destination)?;
    let protocol_is_v6 = protocol.ends_with('6');
    if protocol_is_v6 != matches!(destination, IpNet::V6(_)) {
        return Err(OsSenseError::Configuration(
            "protocol address family must match destination".to_string(),
        ));
    }
    let port_range = match (entry.port_start, entry.port_end) {
        (None, None) => None,
        (Some(start), Some(end)) if start > 0 && start <= end => Some((start, end)),
        _ => {
            return Err(OsSenseError::Configuration(
                "port_start and port_end must either both be absent or define an ordered range from 1 to 65535"
                    .to_string(),
            ));
        }
    };
    Ok(ValidatedOutboundRule {
        protocol,
        destination,
        port_range,
    })
}

fn parse_baseline_destination(value: &str) -> Result<IpNet> {
    if let Some((address, _)) = value.split_once('/') {
        let address = address.parse::<IpAddr>().map_err(|_| {
            OsSenseError::Configuration("destination CIDR address is invalid".to_string())
        })?;
        let network = value.parse::<IpNet>().map_err(|_| {
            OsSenseError::Configuration("destination CIDR prefix is invalid".to_string())
        })?;
        if network.network() != address {
            return Err(OsSenseError::Configuration(
                "destination CIDR must use the canonical network address".to_string(),
            ));
        }
        Ok(network)
    } else {
        let address = value.parse::<IpAddr>().map_err(|_| {
            OsSenseError::Configuration("destination IP address is invalid".to_string())
        })?;
        let prefix = if address.is_ipv4() { 32 } else { 128 };
        IpNet::new(address, prefix).map_err(|error| {
            OsSenseError::Configuration(format!("destination IP address is invalid: {error}"))
        })
    }
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
    let baseline = match &*CONFIGURED_NETWORK_BASELINE {
        Ok(baseline) => baseline.as_ref(),
        Err(error) => return Err(OsSenseError::Configuration(error.clone())),
    };
    collect_network_with_reader_and_baseline(query, &SystemNetworkFileReader, baseline)
}

#[cfg(test)]
fn collect_network_with_reader(
    query: &NetworkQuery,
    reader: &dyn NetworkFileReader,
) -> Result<NetworkSnapshot> {
    collect_network_with_reader_and_baseline(query, reader, None)
}

fn collect_network_with_reader_and_baseline(
    query: &NetworkQuery,
    reader: &dyn NetworkFileReader,
    baseline: Option<&NetworkBaseline>,
) -> Result<NetworkSnapshot> {
    query.validate()?;
    let filter = ValidatedNetworkFilter::from_query(query)?;
    let mut warnings = Vec::new();
    let mut omitted_warning_count = 0usize;
    let (mut connections, source_statuses) =
        collect_proc_net_connections(reader, &mut warnings, &mut omitted_warning_count);
    sort_and_deduplicate_connections(&mut connections);
    let detected_anomalies = detect_network_anomalies(&connections, &source_statuses, baseline)?;
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
    let anomaly_total = detected_anomalies.total;
    let omitted_anomaly_count = detected_anomalies.omitted_count;
    let anomalies_truncated = omitted_anomaly_count > 0;
    let anomalies = detected_anomalies.anomalies;
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
        anomaly_total,
        anomalies_truncated,
        omitted_anomaly_count,
    })
}

fn load_network_baseline_from_environment() -> Result<Option<NetworkBaseline>> {
    let Some(path) = std::env::var_os(OS_NETWORK_BASELINE_FILE_ENV) else {
        return Ok(None);
    };
    if path.is_empty() {
        return Err(OsSenseError::Configuration(format!(
            "{OS_NETWORK_BASELINE_FILE_ENV} must name a baseline JSON file"
        )));
    }
    load_network_baseline_file(Path::new(&path)).map(Some)
}

fn load_network_baseline_file(path: &Path) -> Result<NetworkBaseline> {
    validate_network_baseline_file_path(path)?;
    let mut file = open_network_baseline_file(path)?;
    let mut bytes = Vec::with_capacity(MAX_NETWORK_BASELINE_JSON_BYTES.min(8 * 1024));
    file.by_ref()
        .take((MAX_NETWORK_BASELINE_JSON_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            OsSenseError::Configuration(format!(
                "failed to read network baseline file {}: {error}",
                path.display()
            ))
        })?;
    if bytes.len() > MAX_NETWORK_BASELINE_JSON_BYTES {
        return Err(OsSenseError::Configuration(format!(
            "network baseline file {} exceeds {MAX_NETWORK_BASELINE_JSON_BYTES} bytes",
            path.display()
        )));
    }
    NetworkBaseline::from_json_bytes(&bytes).map_err(|error| {
        OsSenseError::Configuration(format!(
            "invalid network baseline file {}: {error}",
            path.display()
        ))
    })
}

fn validate_network_baseline_file_path(path: &Path) -> Result<()> {
    let path_bytes = path.as_os_str().to_string_lossy().len();
    #[cfg(unix)]
    let valid_encoding = path.to_str().is_some_and(|path| !path.contains('\0'));
    #[cfg(not(unix))]
    let valid_encoding = true;
    let valid = valid_encoding
        && path.is_absolute()
        && path_bytes <= MAX_NETWORK_BASELINE_PATH_BYTES
        && !path
            .components()
            .any(|component| component == Component::ParentDir);
    if !valid {
        return Err(OsSenseError::Configuration(format!(
            "network baseline file path {} must be absolute, valid, at most {MAX_NETWORK_BASELINE_PATH_BYTES} bytes, and without '..'",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn open_network_baseline_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            OsSenseError::Configuration(format!(
                "failed to securely open network baseline file {}: {error}",
                path.display()
            ))
        })?;
    let metadata = file.metadata().map_err(|error| {
        OsSenseError::Configuration(format!(
            "failed to inspect network baseline file {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(OsSenseError::Configuration(format!(
            "network baseline file {} must be a regular file",
            path.display()
        )));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(OsSenseError::Configuration(format!(
            "network baseline file {} must not be group- or world-writable",
            path.display()
        )));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_network_baseline_file(path: &Path) -> Result<File> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        OsSenseError::Configuration(format!(
            "failed to inspect network baseline file {}: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(OsSenseError::Configuration(format!(
            "network baseline file {} must be a regular non-symlink file",
            path.display()
        )));
    }
    OpenOptions::new().read(true).open(path).map_err(|error| {
        OsSenseError::Configuration(format!(
            "failed to securely open network baseline file {}: {error}",
            path.display()
        ))
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

struct DetectedNetworkAnomalies {
    anomalies: Vec<NetworkAnomaly>,
    total: usize,
    omitted_count: usize,
}

#[derive(Default)]
struct ScanGroup {
    local_ports: BTreeSet<u16>,
    connection_count: usize,
    states: BTreeSet<String>,
}

fn detect_network_anomalies(
    connections: &[NetworkConnection],
    source_statuses: &[NetworkSourceStatus],
    baseline: Option<&NetworkBaseline>,
) -> Result<DetectedNetworkAnomalies> {
    let validated_rules = baseline
        .map(|baseline| {
            baseline.validate()?;
            baseline
                .entries
                .iter()
                .map(validate_network_baseline_entry)
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    let mut candidates = Vec::new();
    detect_time_wait_groups(connections, source_statuses, &mut candidates);
    if let (Some(baseline), Some(rules)) = (baseline, validated_rules.as_deref()) {
        detect_unknown_outbound(
            connections,
            source_statuses,
            baseline,
            rules,
            &mut candidates,
        );
    }
    detect_inbound_port_scans(connections, source_statuses, &mut candidates);
    Ok(select_network_anomalies_fair(candidates))
}

fn detect_time_wait_groups(
    connections: &[NetworkConnection],
    source_statuses: &[NetworkSourceStatus],
    candidates: &mut Vec<NetworkAnomaly>,
) {
    let mut groups = BTreeMap::<(String, IpAddr, u16), usize>::new();
    let mut total_time_wait_count = 0usize;
    for connection in connections.iter().filter(|connection| {
        matches!(connection.protocol.as_str(), "tcp" | "tcp6") && connection.state == "TIME_WAIT"
    }) {
        let Some((remote_address, remote_port)) = network_remote_endpoint(connection) else {
            continue;
        };
        total_time_wait_count = total_time_wait_count.saturating_add(1);
        *groups
            .entry((connection.protocol.clone(), remote_address, remote_port))
            .or_default() += 1;
    }

    for ((protocol, remote_address, remote_port), group_count) in groups {
        if group_count < TIME_WAIT_GROUP_THRESHOLD {
            continue;
        }
        let subject = endpoint_subject(&protocol, remote_address, remote_port);
        let input_complete = network_input_complete(source_statuses, &protocol);
        candidates.push(NetworkAnomaly {
            kind: "many_time_wait".to_string(),
            message: format!(
                "{group_count} TIME_WAIT connections are aggregated at remote endpoint {subject}"
            ),
            count: group_count,
            score: if input_complete { 0.7 } else { 0.55 },
            source: network_source_path(source_statuses, &protocol),
            subject: Some(subject.clone()),
            evidence: Some(NetworkAnomalyEvidence::TimeWaitGroup {
                aggregation: "remote_endpoint".to_string(),
                subject,
                group_count,
                total_time_wait_count,
                threshold: TIME_WAIT_GROUP_THRESHOLD,
                confidence: anomaly_confidence(input_complete).to_string(),
                input_complete,
            }),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn detect_unknown_outbound(
    connections: &[NetworkConnection],
    source_statuses: &[NetworkSourceStatus],
    baseline: &NetworkBaseline,
    rules: &[ValidatedOutboundRule],
    candidates: &mut Vec<NetworkAnomaly>,
) {
    let mut groups = BTreeMap::<(String, IpAddr, u16), usize>::new();
    for connection in connections {
        let Some((remote_address, remote_port)) = outbound_remote_endpoint(connection) else {
            continue;
        };
        if rules.iter().any(|rule| {
            rule.protocol == connection.protocol
                && rule.destination.contains(&remote_address)
                && rule
                    .port_range
                    .is_none_or(|(start, end)| (start..=end).contains(&remote_port))
        }) {
            continue;
        }
        *groups
            .entry((connection.protocol.clone(), remote_address, remote_port))
            .or_default() += 1;
    }

    for ((protocol, remote_address, remote_port), connection_count) in groups {
        let subject = endpoint_subject(&protocol, remote_address, remote_port);
        let input_complete = network_input_complete(source_statuses, &protocol);
        candidates.push(NetworkAnomaly {
            kind: "unknown_outbound".to_string(),
            message: format!(
                "outbound endpoint {subject} does not match network baseline `{}`",
                baseline.id
            ),
            count: connection_count,
            score: if input_complete { 0.9 } else { 0.7 },
            source: network_source_path(source_statuses, &protocol),
            subject: Some(subject),
            evidence: Some(NetworkAnomalyEvidence::UnknownOutbound {
                baseline_id: baseline.id.clone(),
                baseline_version: baseline.version,
                protocol,
                remote_address: remote_address.to_string(),
                remote_port,
                connection_count,
                confidence: anomaly_confidence(input_complete).to_string(),
                input_complete,
            }),
        });
    }
}

fn detect_inbound_port_scans(
    connections: &[NetworkConnection],
    source_statuses: &[NetworkSourceStatus],
    candidates: &mut Vec<NetworkAnomaly>,
) {
    let mut groups = BTreeMap::<(String, IpAddr), ScanGroup>::new();
    for connection in connections.iter().filter(|connection| {
        matches!(connection.protocol.as_str(), "tcp" | "tcp6")
            && matches!(connection.state.as_str(), "SYN_RECV" | "NEW_SYN_RECV")
            && connection.local_port > 0
    }) {
        let Some((remote_address, _)) = valid_remote_endpoint(connection) else {
            continue;
        };
        let group = groups
            .entry((connection.protocol.clone(), remote_address))
            .or_default();
        group.local_ports.insert(connection.local_port);
        group.connection_count = group.connection_count.saturating_add(1);
        group.states.insert(connection.state.clone());
    }

    for ((protocol, remote_address), group) in groups {
        let distinct_local_port_count = group.local_ports.len();
        if distinct_local_port_count < PORT_SCAN_DISTINCT_PORT_THRESHOLD {
            continue;
        }
        let input_complete = network_input_complete(source_statuses, &protocol);
        let subject = remote_address.to_string();
        candidates.push(NetworkAnomaly {
            kind: "inbound_port_scan".to_string(),
            message: format!(
                "remote address {subject} has SYN_RECV connections across {distinct_local_port_count} distinct local ports"
            ),
            count: distinct_local_port_count,
            score: if input_complete { 0.95 } else { 0.75 },
            source: network_source_path(source_statuses, &protocol),
            subject: Some(subject.clone()),
            evidence: Some(NetworkAnomalyEvidence::PortScanIndication {
                protocol,
                remote_address: subject,
                distinct_local_port_count,
                connection_count: group.connection_count,
                distinct_port_threshold: PORT_SCAN_DISTINCT_PORT_THRESHOLD,
                states: group.states.into_iter().collect(),
                confidence: anomaly_confidence(input_complete).to_string(),
                input_complete,
            }),
        });
    }
}

fn outbound_remote_endpoint(connection: &NetworkConnection) -> Option<(IpAddr, u16)> {
    if !matches!(
        (connection.protocol.as_str(), connection.state.as_str()),
        ("tcp" | "tcp6", "SYN_SENT") | ("udp" | "udp6", "ESTABLISHED")
    ) {
        return None;
    }
    valid_remote_endpoint(connection)
}

fn valid_remote_endpoint(connection: &NetworkConnection) -> Option<(IpAddr, u16)> {
    let endpoint = network_remote_endpoint(connection)?;
    is_true_remote_address(endpoint.0).then_some(endpoint)
}

fn network_remote_endpoint(connection: &NetworkConnection) -> Option<(IpAddr, u16)> {
    if connection.remote_port == 0 {
        return None;
    }
    let address = connection_remote_address(connection)
        .parse::<IpAddr>()
        .ok()?;
    let family_matches = match connection.protocol.as_str() {
        "tcp" | "udp" => address.is_ipv4(),
        "tcp6" | "udp6" => address.is_ipv6(),
        _ => false,
    };
    if !family_matches || address.is_unspecified() {
        return None;
    }
    Some((address, connection.remote_port))
}

fn is_true_remote_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => !address.is_unspecified() && !address.is_loopback(),
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address
                    .to_ipv4_mapped()
                    .is_some_and(|mapped| mapped.is_loopback())
        }
    }
}

fn network_input_complete(source_statuses: &[NetworkSourceStatus], protocol: &str) -> bool {
    let mut matching = source_statuses
        .iter()
        .filter(|status| status.protocol == protocol);
    let Some(status) = matching.next() else {
        return false;
    };
    matching.next().is_none()
        && status.status == CollectionStatus::Complete
        && !status.truncated
        && status.parse_failure_count == 0
}

fn network_source_path(source_statuses: &[NetworkSourceStatus], protocol: &str) -> Option<String> {
    source_statuses
        .iter()
        .find(|status| status.protocol == protocol)
        .map(|status| status.actual_path.clone())
        .or_else(|| {
            PROC_NET_SOURCES
                .iter()
                .find(|(_, source_protocol)| *source_protocol == protocol)
                .map(|(path, _)| (*path).to_string())
        })
}

fn anomaly_confidence(input_complete: bool) -> &'static str {
    if input_complete {
        "high"
    } else {
        "limited"
    }
}

fn endpoint_subject(protocol: &str, address: IpAddr, port: u16) -> String {
    match address {
        IpAddr::V4(address) => format!("{protocol}://{address}:{port}"),
        IpAddr::V6(address) => format!("{protocol}://[{address}]:{port}"),
    }
}

fn select_network_anomalies_fair(candidates: Vec<NetworkAnomaly>) -> DetectedNetworkAnomalies {
    let total = candidates.len();
    let mut groups = BTreeMap::<(String, String), Vec<NetworkAnomaly>>::new();
    for anomaly in candidates {
        groups
            .entry((
                anomaly.kind.clone(),
                anomaly.source.clone().unwrap_or_default(),
            ))
            .or_default()
            .push(anomaly);
    }
    let mut groups = groups
        .into_iter()
        .map(|(key, mut anomalies)| {
            anomalies.sort_by(|left, right| {
                right
                    .score
                    .total_cmp(&left.score)
                    .then_with(|| right.count.cmp(&left.count))
                    .then_with(|| left.subject.cmp(&right.subject))
                    .then_with(|| left.message.cmp(&right.message))
            });
            (key, VecDeque::from(anomalies))
        })
        .collect::<Vec<_>>();
    let mut anomalies = Vec::with_capacity(total.min(MAX_NETWORK_ANOMALIES));
    while anomalies.len() < MAX_NETWORK_ANOMALIES {
        let previous_len = anomalies.len();
        for (_, group) in &mut groups {
            if anomalies.len() == MAX_NETWORK_ANOMALIES {
                break;
            }
            if let Some(anomaly) = group.pop_front() {
                anomalies.push(anomaly);
            }
        }
        if anomalies.len() == previous_len {
            break;
        }
    }
    DetectedNetworkAnomalies {
        omitted_count: total.saturating_sub(anomalies.len()),
        anomalies,
        total,
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

    fn complete_source_statuses() -> Vec<NetworkSourceStatus> {
        PROC_NET_SOURCES
            .iter()
            .map(|(path, protocol)| NetworkSourceStatus {
                protocol: (*protocol).to_string(),
                actual_path: (*path).to_string(),
                available: true,
                status: CollectionStatus::Complete,
                error: None,
                entry_count: 0,
                parse_failure_count: 0,
                truncated: false,
            })
            .collect()
    }

    fn connection(
        protocol: &str,
        local_address: &str,
        local_port: u16,
        remote_address: &str,
        remote_port: u16,
        state: &str,
        inode: u64,
    ) -> NetworkConnection {
        NetworkConnection {
            protocol: protocol.to_string(),
            local_addr: local_address.to_string(),
            local_address: local_address.to_string(),
            local_port,
            remote_addr: remote_address.to_string(),
            remote_address: remote_address.to_string(),
            remote_port,
            state: state.to_string(),
            inode: Some(inode.to_string()),
            uid: Some(1_000),
        }
    }

    fn baseline(entries: Vec<NetworkBaselineEntry>) -> NetworkBaseline {
        NetworkBaseline {
            version: NETWORK_BASELINE_VERSION,
            id: "network-test".to_string(),
            entries,
        }
    }

    fn rule(protocol: &str, destination: &str, port: Option<u16>) -> NetworkBaselineEntry {
        NetworkBaselineEntry {
            protocol: protocol.to_string(),
            destination: destination.to_string(),
            port_start: port,
            port_end: port,
        }
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
            "anomalies": [{
                "kind": "legacy_network_anomaly",
                "message": "legacy anomaly",
                "count": 1
            }]
        });
        let snapshot: NetworkSnapshot =
            serde_json::from_value(legacy).expect("legacy network snapshot");
        assert_eq!(snapshot.collection_status, CollectionStatus::Partial);
        assert!(snapshot.filter_complete);
        assert_eq!(snapshot.total, 0);
        assert_eq!(snapshot.connections[0].local_addr, "127.0.0.1");
        assert!(snapshot.connections[0].local_address.is_empty());
        assert_eq!(snapshot.connections[0].uid, None);
        assert_eq!(snapshot.anomaly_total, 0);
        assert!(!snapshot.anomalies_truncated);
        assert_eq!(snapshot.omitted_anomaly_count, 0);
        assert_eq!(snapshot.anomalies[0].score, 0.0);
        assert_eq!(snapshot.anomalies[0].source, None);
        assert_eq!(snapshot.anomalies[0].subject, None);
        assert_eq!(snapshot.anomalies[0].evidence, None);
    }

    #[test]
    fn time_wait_aggregation_uses_the_twenty_connection_boundary() {
        let connections = (0..TIME_WAIT_GROUP_THRESHOLD)
            .map(|index| {
                connection(
                    "tcp",
                    "10.0.0.1",
                    40_000 + index as u16,
                    "198.51.100.10",
                    443,
                    "TIME_WAIT",
                    index as u64,
                )
            })
            .collect::<Vec<_>>();
        let statuses = complete_source_statuses();
        let below = detect_network_anomalies(
            &connections[..TIME_WAIT_GROUP_THRESHOLD - 1],
            &statuses,
            None,
        )
        .expect("below TIME_WAIT threshold");
        assert!(!below
            .anomalies
            .iter()
            .any(|anomaly| anomaly.kind == "many_time_wait"));

        let result = detect_network_anomalies(&connections, &statuses, None)
            .expect("network anomaly detection");
        let anomaly = result
            .anomalies
            .iter()
            .find(|anomaly| anomaly.kind == "many_time_wait")
            .expect("TIME_WAIT aggregate");
        assert_eq!(anomaly.count, TIME_WAIT_GROUP_THRESHOLD);
        assert!(matches!(
            anomaly.evidence.as_ref(),
            Some(NetworkAnomalyEvidence::TimeWaitGroup {
                group_count: TIME_WAIT_GROUP_THRESHOLD,
                threshold: TIME_WAIT_GROUP_THRESHOLD,
                input_complete: true,
                ..
            })
        ));
    }

    #[test]
    fn inbound_scan_requires_ten_distinct_syn_recv_local_ports() {
        let mut connections = (0..(PORT_SCAN_DISTINCT_PORT_THRESHOLD - 1))
            .map(|index| {
                connection(
                    "tcp",
                    "10.0.0.1",
                    1_000 + index as u16,
                    "198.51.100.20",
                    50_000 + index as u16,
                    "SYN_RECV",
                    index as u64,
                )
            })
            .collect::<Vec<_>>();
        connections.push(connection(
            "tcp",
            "10.0.0.1",
            1_000,
            "198.51.100.20",
            60_000,
            "SYN_RECV",
            100,
        ));
        for (index, state) in ["ESTABLISHED", "TIME_WAIT", "SYN_SENT"]
            .into_iter()
            .enumerate()
        {
            connections.push(connection(
                "tcp",
                "10.0.0.1",
                2_000 + index as u16,
                "198.51.100.20",
                61_000 + index as u16,
                state,
                200 + index as u64,
            ));
        }
        let statuses = complete_source_statuses();
        let below =
            detect_network_anomalies(&connections, &statuses, None).expect("below scan threshold");
        assert!(!below
            .anomalies
            .iter()
            .any(|anomaly| anomaly.kind == "inbound_port_scan"));

        connections.push(connection(
            "tcp",
            "10.0.0.1",
            1_000 + (PORT_SCAN_DISTINCT_PORT_THRESHOLD - 1) as u16,
            "198.51.100.20",
            62_000,
            "SYN_RECV",
            300,
        ));
        let result =
            detect_network_anomalies(&connections, &statuses, None).expect("scan threshold");
        let anomaly = result
            .anomalies
            .iter()
            .find(|anomaly| anomaly.kind == "inbound_port_scan")
            .expect("inbound scan anomaly");
        assert!(matches!(
            anomaly.evidence.as_ref(),
            Some(NetworkAnomalyEvidence::PortScanIndication {
                distinct_local_port_count: PORT_SCAN_DISTINCT_PORT_THRESHOLD,
                connection_count: 11,
                states,
                ..
            }) if states == &["SYN_RECV".to_string()]
        ));
    }

    #[test]
    fn query_filters_and_limit_do_not_change_the_anomaly_domain() {
        let mut rows = (0..TIME_WAIT_GROUP_THRESHOLD)
            .map(|index| {
                proc_row(
                    index,
                    &format!("0100000A:{:04X}", 40_000 + index),
                    "0A6433C6:01BB",
                    "06",
                    1_000,
                    index as u64,
                )
            })
            .collect::<Vec<_>>();
        rows.push(proc_row(
            100,
            "00000000:0050",
            "00000000:0000",
            "0A",
            0,
            100,
        ));
        rows.push(proc_row(
            101,
            "00000000:0051",
            "00000000:0000",
            "0A",
            0,
            101,
        ));
        let reader = FixtureNetworkFileReader::complete().with_text("/proc/net/tcp", table(rows));
        let snapshot = collect_network_with_reader(
            &NetworkQuery {
                state: Some("LISTEN".to_string()),
                limit: Some(1),
                ..NetworkQuery::default()
            },
            &reader,
        )
        .expect("filtered network collection");

        assert_eq!(snapshot.total, 2);
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.anomaly_total, 1);
        assert_eq!(snapshot.anomalies[0].kind, "many_time_wait");
        assert_eq!(snapshot.anomalies[0].count, TIME_WAIT_GROUP_THRESHOLD);
    }

    #[test]
    fn baseline_none_disables_unknown_empty_denies_all_and_invalid_fails_closed() {
        let connections = vec![connection(
            "tcp",
            "10.0.0.1",
            40_000,
            "198.51.100.30",
            443,
            "SYN_SENT",
            1,
        )];
        let statuses = complete_source_statuses();
        let disabled = detect_network_anomalies(&connections, &statuses, None)
            .expect("disabled outbound baseline");
        assert!(!disabled
            .anomalies
            .iter()
            .any(|anomaly| anomaly.kind == "unknown_outbound"));

        let deny_all = baseline(Vec::new());
        let denied = detect_network_anomalies(&connections, &statuses, Some(&deny_all))
            .expect("empty baseline is deny-all");
        assert_eq!(
            denied
                .anomalies
                .iter()
                .filter(|anomaly| anomaly.kind == "unknown_outbound")
                .count(),
            1
        );

        let invalid = NetworkBaseline {
            version: NETWORK_BASELINE_VERSION + 1,
            ..deny_all
        };
        assert!(matches!(
            detect_network_anomalies(&connections, &statuses, Some(&invalid)),
            Err(OsSenseError::Configuration(_))
        ));
    }

    #[test]
    fn unknown_outbound_uses_only_syn_sent_tcp_and_connected_udp() {
        let mut connections = ["ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT"]
            .into_iter()
            .enumerate()
            .map(|(index, state)| {
                connection(
                    "tcp",
                    "10.0.0.1",
                    40_000 + index as u16,
                    &format!("198.51.100.{}", 40 + index),
                    443,
                    state,
                    index as u64,
                )
            })
            .collect::<Vec<_>>();
        connections.push(connection(
            "tcp",
            "10.0.0.1",
            41_000,
            "198.51.100.50",
            443,
            "SYN_SENT",
            10,
        ));
        connections.push(connection(
            "udp",
            "10.0.0.1",
            42_000,
            "198.51.100.51",
            53,
            "ESTABLISHED",
            11,
        ));
        connections.push(connection(
            "udp",
            "0.0.0.0",
            53,
            "0.0.0.0",
            0,
            "UNCONNECTED",
            12,
        ));
        let result = detect_network_anomalies(
            &connections,
            &complete_source_statuses(),
            Some(&baseline(Vec::new())),
        )
        .expect("direction-safe outbound detection");
        let mut protocols = result
            .anomalies
            .iter()
            .filter_map(|anomaly| match anomaly.evidence.as_ref() {
                Some(NetworkAnomalyEvidence::UnknownOutbound { protocol, .. }) => {
                    Some(protocol.as_str())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        protocols.sort_unstable();
        assert_eq!(protocols, ["tcp", "udp"]);
    }

    #[test]
    fn ipv4_ipv6_and_mapped_tcp6_rules_match_cidr_address_and_port() {
        let configured = baseline(vec![
            rule("tcp", "203.0.113.0/24", Some(443)),
            rule("tcp6", "2001:db8::/32", Some(443)),
            rule("tcp6", "::ffff:192.0.2.10/128", Some(443)),
        ]);
        configured.validate().expect("valid dual-stack baseline");
        let cases = [
            ("tcp", "203.0.113.10", 443),
            ("tcp", "203.0.114.10", 443),
            ("tcp", "203.0.113.10", 444),
            ("tcp6", "2001:db8::10", 443),
            ("tcp6", "2001:db9::10", 443),
            ("tcp6", "::ffff:192.0.2.10", 443),
        ];
        let connections = cases
            .into_iter()
            .enumerate()
            .map(|(index, (protocol, remote, port))| {
                connection(
                    protocol,
                    if protocol == "tcp" {
                        "10.0.0.1"
                    } else {
                        "2001:db8:ffff::1"
                    },
                    40_000 + index as u16,
                    remote,
                    port,
                    "SYN_SENT",
                    index as u64,
                )
            })
            .collect::<Vec<_>>();
        let result =
            detect_network_anomalies(&connections, &complete_source_statuses(), Some(&configured))
                .expect("CIDR matching");
        let rejected = result
            .anomalies
            .iter()
            .filter_map(|anomaly| match anomaly.evidence.as_ref() {
                Some(NetworkAnomalyEvidence::UnknownOutbound {
                    remote_address,
                    remote_port,
                    ..
                }) => Some((remote_address.as_str(), *remote_port)),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            rejected,
            BTreeSet::from([
                ("2001:db9::10", 443),
                ("203.0.113.10", 444),
                ("203.0.114.10", 443),
            ])
        );
    }

    #[test]
    fn anomaly_completeness_uses_only_the_unique_protocol_source() {
        let connections = vec![connection(
            "tcp",
            "10.0.0.1",
            40_000,
            "198.51.100.60",
            443,
            "SYN_SENT",
            1,
        )];
        let configured = baseline(Vec::new());
        let mut statuses = complete_source_statuses();
        let udp = statuses
            .iter_mut()
            .find(|status| status.protocol == "udp")
            .expect("UDP status");
        udp.status = CollectionStatus::Failed;
        udp.available = false;
        let complete = detect_network_anomalies(&connections, &statuses, Some(&configured))
            .expect("unrelated source failure");
        assert!(matches!(
            complete.anomalies[0].evidence.as_ref(),
            Some(NetworkAnomalyEvidence::UnknownOutbound {
                input_complete: true,
                ..
            })
        ));

        let tcp = statuses
            .iter_mut()
            .find(|status| status.protocol == "tcp")
            .expect("TCP status");
        tcp.status = CollectionStatus::Partial;
        tcp.parse_failure_count = 1;
        let partial = detect_network_anomalies(&connections, &statuses, Some(&configured))
            .expect("relevant source partial");
        assert!(matches!(
            partial.anomalies[0].evidence.as_ref(),
            Some(NetworkAnomalyEvidence::UnknownOutbound {
                input_complete: false,
                ..
            })
        ));

        statuses.push(statuses[0].clone());
        let duplicate = detect_network_anomalies(&connections, &statuses, Some(&configured))
            .expect("duplicate source status");
        assert!(matches!(
            duplicate.anomalies[0].evidence.as_ref(),
            Some(NetworkAnomalyEvidence::UnknownOutbound {
                input_complete: false,
                ..
            })
        ));
    }

    #[test]
    fn network_anomaly_output_is_fair_and_hard_bounded() {
        let mut connections = (0..40)
            .map(|index| {
                connection(
                    "tcp",
                    "10.0.0.1",
                    40_000 + index as u16,
                    &format!("198.51.100.{}", index + 1),
                    443,
                    "SYN_SENT",
                    index as u64,
                )
            })
            .collect::<Vec<_>>();
        connections.extend((0..TIME_WAIT_GROUP_THRESHOLD).map(|index| {
            connection(
                "tcp",
                "10.0.0.1",
                50_000 + index as u16,
                "203.0.113.200",
                443,
                "TIME_WAIT",
                100 + index as u64,
            )
        }));
        connections.extend((0..PORT_SCAN_DISTINCT_PORT_THRESHOLD).map(|index| {
            connection(
                "tcp",
                "10.0.0.1",
                1_000 + index as u16,
                "192.0.2.200",
                60_000 + index as u16,
                "SYN_RECV",
                200 + index as u64,
            )
        }));
        let result = detect_network_anomalies(
            &connections,
            &complete_source_statuses(),
            Some(&baseline(Vec::new())),
        )
        .expect("bounded fair anomaly output");

        assert_eq!(result.total, 42);
        assert_eq!(result.anomalies.len(), MAX_NETWORK_ANOMALIES);
        assert_eq!(result.omitted_count, 10);
        for kind in ["unknown_outbound", "many_time_wait", "inbound_port_scan"] {
            assert!(result.anomalies.iter().any(|anomaly| anomaly.kind == kind));
        }
    }
}
