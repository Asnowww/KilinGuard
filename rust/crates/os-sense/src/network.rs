use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::path::{Component, Path};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::command::{run_limited_command, LimitedCommandOutput};
use crate::error::{OsSenseError, Result};
use crate::model::{
    CollectionStatus, DnsCheck, DnsResolutionSource, DnsResolutionStatus, DnsResolverStatus,
    FirewallErrorKind, FirewallStatus, HealthProbeResult, NetworkAnomaly, NetworkAnomalyEvidence,
    NetworkBaseline, NetworkBaselineEntry, NetworkConnection, NetworkSnapshot, NetworkSourceStatus,
    TcpProbeErrorKind, TcpProbeStage, TcpProbeStatus,
};
use crate::procfs::basic_meta;
use crate::redaction::redact_sensitive_text;

const DEFAULT_CONNECTION_LIMIT: usize = 200;
const MAX_CONNECTION_LIMIT: usize = 1000;
const MAX_DNS_CHECKS: usize = 8;
const MAX_TCP_PROBES: usize = 5;
const MAX_PROBE_TIMEOUT_MS: u64 = 3_000;
const MAX_DNS_ADDRESSES: usize = 8;
const MAX_DNS_COMMAND_STDOUT_BYTES: usize = 16 * 1024;
const MAX_DNS_COMMAND_STDERR_BYTES: usize = 4 * 1024;
const MAX_DNS_OUTPUT_LINES: usize = 256;
const MAX_RESOLV_CONF_BYTES: usize = 16 * 1024;
const MAX_RESOLV_CONF_LINES: usize = 256;
const MAX_RESOLV_NAMESERVERS: usize = 3;
const MAX_RESOLV_SEARCH_DOMAINS: usize = 6;
const MAX_RESOLV_OPTIONS: usize = 16;
const MAX_RESOLV_OPTION_CHARS: usize = 64;
const MAX_FIREWALL_STDOUT_BYTES: usize = 64 * 1024;
const MAX_FIREWALL_STDERR_BYTES: usize = 8 * 1024;
const MAX_FIREWALL_OUTPUT_LINES: usize = 2_048;
const MAX_FIREWALL_RULE_SAMPLES: usize = 32;
const MAX_FIREWALL_RULE_CHARS: usize = 256;
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
const DNS_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_TCP_CONNECT_BUDGET: Duration = Duration::from_millis(1);
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
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
            validate_dns_target("dns_names entry", name)?;
        }
        if self.tcp_probes.len() > MAX_TCP_PROBES {
            return Err(OsSenseError::Configuration(format!(
                "network query tcp_probes must not contain more than {MAX_TCP_PROBES} entries"
            )));
        }
        for probe in &self.tcp_probes {
            validate_dns_target("tcp_probes host", &probe.host)?;
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
    let clock = SystemProbeClock::new();
    collect_network_with_components(
        query,
        &SystemNetworkFileReader,
        baseline,
        &SystemDnsResolver,
        &SystemTcpConnector,
        &clock,
        &SystemFirewallCommandRunner,
    )
}

#[cfg(test)]
fn collect_network_with_reader(
    query: &NetworkQuery,
    reader: &dyn NetworkFileReader,
) -> Result<NetworkSnapshot> {
    let clock = SystemProbeClock::new();
    collect_network_with_components(
        query,
        reader,
        None,
        &SystemDnsResolver,
        &SystemTcpConnector,
        &clock,
        &SystemFirewallCommandRunner,
    )
}

#[allow(clippy::too_many_arguments)]
fn collect_network_with_components(
    query: &NetworkQuery,
    reader: &dyn NetworkFileReader,
    baseline: Option<&NetworkBaseline>,
    dns_resolver: &dyn DnsResolver,
    tcp_connector: &dyn TcpConnector,
    clock: &dyn ProbeClock,
    firewall_runner: &dyn FirewallCommandRunner,
) -> Result<NetworkSnapshot> {
    query.validate()?;
    let filter = ValidatedNetworkFilter::from_query(query)?;
    let mut warnings = Vec::new();
    let mut omitted_warning_count = 0usize;
    let dns_resolver_status =
        collect_dns_resolver_status(reader, &mut warnings, &mut omitted_warning_count);
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
    let mut truncated = source_truncated || total > connection_limit;
    let filter_complete = relevant_source_statuses
        .clone()
        .all(|status| status.status == CollectionStatus::Complete);
    let mut collection_status =
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
        .map(|name| resolve_dns(name, dns_resolver))
        .collect::<Vec<_>>();
    let tcp_probes = query
        .tcp_probes
        .iter()
        .map(|request| probe_tcp_with(request, dns_resolver, tcp_connector, clock))
        .collect::<Vec<_>>();
    truncated |= dns_resolver_status.truncated
        || dns_checks.iter().any(|check| check.truncated)
        || tcp_probes.iter().any(|probe| probe.truncated);
    let firewall = if query.include_firewall {
        collect_firewall_status(firewall_runner)
    } else {
        Vec::new()
    };
    if collection_status != CollectionStatus::Failed
        && firewall
            .iter()
            .any(|status| status.status != CollectionStatus::Complete)
    {
        collection_status = CollectionStatus::Partial;
    }
    truncated |= firewall.iter().any(|status| status.truncated);
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
        dns_resolver: dns_resolver_status,
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
        let file = open_network_source(path)?;
        let mut bytes = Vec::with_capacity(maximum_bytes.min(64 * 1024));
        file.take((maximum_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        let truncated = bytes.len() > maximum_bytes;
        bytes.truncate(maximum_bytes);
        let actual_path = std::fs::canonicalize(path)
            .ok()
            .and_then(|path| path.to_str().map(str::to_string))
            .unwrap_or_else(|| path.to_string());
        Ok(BoundedNetworkFile {
            bytes,
            truncated,
            actual_path: actual_path
                .chars()
                .take(MAX_NETWORK_BASELINE_PATH_BYTES)
                .collect(),
        })
    }
}

#[cfg(unix)]
fn open_network_source(path: &str) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "network source must be a regular file",
        ));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_network_source(path: &str) -> io::Result<File> {
    let file = File::open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "network source must be a regular file",
        ));
    }
    Ok(file)
}

struct BoundedNetworkFile {
    bytes: Vec<u8>,
    truncated: bool,
    actual_path: String,
}

fn collect_dns_resolver_status(
    reader: &dyn NetworkFileReader,
    warnings: &mut Vec<String>,
    omitted_warning_count: &mut usize,
) -> DnsResolverStatus {
    match reader.read_bounded(RESOLV_CONF_PATH, MAX_RESOLV_CONF_BYTES) {
        Ok(file) => {
            let mut status = parse_resolv_conf(&file.bytes, file.truncated);
            status.actual_path = file.actual_path;
            if status.status != CollectionStatus::Complete {
                push_network_warning(
                    warnings,
                    omitted_warning_count,
                    format!(
                        "{}: {}",
                        status.actual_path,
                        status
                            .error
                            .as_deref()
                            .unwrap_or("DNS resolver configuration is partial")
                    ),
                );
            }
            status
        }
        Err(error) => {
            let error = bounded_network_error(&error.to_string());
            push_network_warning(
                warnings,
                omitted_warning_count,
                format!("failed to read {RESOLV_CONF_PATH}: {error}"),
            );
            DnsResolverStatus {
                status: CollectionStatus::Failed,
                available: false,
                actual_path: RESOLV_CONF_PATH.to_string(),
                error: Some(error),
                ..DnsResolverStatus::default()
            }
        }
    }
}

fn parse_resolv_conf(bytes: &[u8], input_truncated: bool) -> DnsResolverStatus {
    let mut nameservers = Vec::new();
    let mut search_domains = Vec::new();
    let mut options = Vec::new();
    let mut nameserver_set = BTreeSet::new();
    let mut search_set = BTreeSet::new();
    let mut option_set = BTreeSet::new();
    let mut parse_failure_count = usize::from(std::str::from_utf8(bytes).is_err());
    let mut truncated = input_truncated;
    let mut omitted_nameserver_count = 0usize;
    let mut omitted_search_domain_count = 0usize;
    let mut omitted_option_count = 0usize;

    for (line_index, raw_line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line_index >= MAX_RESOLV_CONF_LINES {
            truncated = true;
            break;
        }
        let line = String::from_utf8_lossy(raw_line);
        let line = line.split(['#', ';']).next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        match fields.first().copied() {
            Some("nameserver") => {
                if fields.len() != 2 {
                    parse_failure_count = parse_failure_count.saturating_add(1);
                    continue;
                }
                let Ok(address) = fields[1].parse::<IpAddr>() else {
                    parse_failure_count = parse_failure_count.saturating_add(1);
                    continue;
                };
                push_bounded_unique(
                    address.to_string(),
                    &mut nameservers,
                    &mut nameserver_set,
                    MAX_RESOLV_NAMESERVERS,
                    &mut omitted_nameserver_count,
                    &mut truncated,
                );
            }
            Some("search") => {
                if fields.len() < 2 {
                    parse_failure_count = parse_failure_count.saturating_add(1);
                    continue;
                }
                for domain in &fields[1..] {
                    if !is_valid_dns_name(domain, false) {
                        parse_failure_count = parse_failure_count.saturating_add(1);
                        continue;
                    }
                    push_bounded_unique(
                        domain.to_ascii_lowercase(),
                        &mut search_domains,
                        &mut search_set,
                        MAX_RESOLV_SEARCH_DOMAINS,
                        &mut omitted_search_domain_count,
                        &mut truncated,
                    );
                }
            }
            Some("options") => {
                if fields.len() < 2 {
                    parse_failure_count = parse_failure_count.saturating_add(1);
                    continue;
                }
                for option in &fields[1..] {
                    if !is_valid_resolver_option(option) {
                        parse_failure_count = parse_failure_count.saturating_add(1);
                        continue;
                    }
                    push_bounded_unique(
                        option.to_ascii_lowercase(),
                        &mut options,
                        &mut option_set,
                        MAX_RESOLV_OPTIONS,
                        &mut omitted_option_count,
                        &mut truncated,
                    );
                }
            }
            _ => {}
        }
    }

    let error = if nameservers.is_empty() {
        Some("DNS resolver configuration has no valid nameserver".to_string())
    } else if parse_failure_count > 0 {
        Some(format!(
            "{parse_failure_count} malformed DNS resolver configuration item(s) were skipped"
        ))
    } else if truncated {
        Some("DNS resolver configuration exceeded bounded collection limits".to_string())
    } else {
        None
    };
    let status = if error.is_none() {
        CollectionStatus::Complete
    } else {
        CollectionStatus::Partial
    };
    DnsResolverStatus {
        status,
        available: true,
        actual_path: RESOLV_CONF_PATH.to_string(),
        nameservers,
        search_domains,
        options,
        parse_failure_count,
        truncated,
        omitted_nameserver_count,
        omitted_search_domain_count,
        omitted_option_count,
        error: error.map(|error| bounded_network_error(&error)),
    }
}

fn push_bounded_unique(
    value: String,
    values: &mut Vec<String>,
    seen: &mut BTreeSet<String>,
    maximum: usize,
    omitted: &mut usize,
    truncated: &mut bool,
) {
    if !seen.insert(value.clone()) {
        return;
    }
    if values.len() < maximum {
        values.push(value);
    } else {
        *omitted = omitted.saturating_add(1);
        *truncated = true;
    }
}

fn is_valid_resolver_option(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_RESOLV_OPTION_CHARS
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
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
                    actual_path: file.actual_path,
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

fn validate_dns_target(name: &str, value: &str) -> Result<()> {
    if !is_valid_dns_name(value, true) {
        return Err(OsSenseError::Configuration(format!(
            "network query {name} must be a valid IP literal, localhost, .local name, or conventional FQDN of at most 253 ASCII characters"
        )));
    }
    Ok(())
}

fn is_valid_dns_name(value: &str, require_fqdn: bool) -> bool {
    if value.is_empty()
        || value.len() > 253
        || value.starts_with('-')
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return false;
    }
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let labels = value.split('.').collect::<Vec<_>>();
    if (require_fqdn && labels.len() < 2)
        || labels.is_empty()
        || labels
            .iter()
            .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
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

#[derive(Debug, Clone)]
struct DnsResolution {
    addresses: Vec<IpAddr>,
    status: DnsResolutionStatus,
    latency_ms: Option<u128>,
    source: DnsResolutionSource,
    truncated: bool,
    omitted_address_count: usize,
    parse_failure_count: usize,
    error: Option<String>,
}

trait DnsResolver {
    fn resolve(&self, name: &str, timeout: Duration) -> DnsResolution;
}

trait DnsCommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> io::Result<LimitedCommandOutput>;
}

struct SystemDnsCommandRunner;

impl DnsCommandRunner for SystemDnsCommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> io::Result<LimitedCommandOutput> {
        let args = args.iter().map(String::as_str).collect::<Vec<_>>();
        run_limited_command(program, &args, timeout, stdout_limit, stderr_limit)
    }
}

struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, name: &str, timeout: Duration) -> DnsResolution {
        resolve_dns_with_runner(name, timeout, &SystemDnsCommandRunner)
    }
}

fn resolve_dns(name: &str, resolver: &dyn DnsResolver) -> DnsCheck {
    let mut resolution = if let Ok(address) = name.parse::<IpAddr>() {
        literal_dns_resolution(address)
    } else {
        resolver.resolve(name, DNS_RESOLUTION_TIMEOUT)
    };
    let (addresses, additionally_omitted) = interleave_and_limit_addresses(resolution.addresses);
    resolution.addresses = addresses;
    resolution.omitted_address_count = resolution
        .omitted_address_count
        .saturating_add(additionally_omitted);
    resolution.truncated |= additionally_omitted > 0;
    if additionally_omitted > 0 && resolution.status == DnsResolutionStatus::Resolved {
        resolution.status = DnsResolutionStatus::Partial;
    }
    DnsCheck {
        name: name.chars().take(253).collect(),
        ok: matches!(
            resolution.status,
            DnsResolutionStatus::Resolved
                | DnsResolutionStatus::Partial
                | DnsResolutionStatus::Literal
        ) && !resolution.addresses.is_empty(),
        resolved_addrs: resolution
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect(),
        error: resolution.error,
        status: resolution.status,
        latency_ms: resolution.latency_ms,
        source: resolution.source,
        truncated: resolution.truncated,
        omitted_address_count: resolution.omitted_address_count,
        parse_failure_count: resolution.parse_failure_count,
    }
}

fn resolve_dns_with_runner(
    name: &str,
    timeout: Duration,
    runner: &dyn DnsCommandRunner,
) -> DnsResolution {
    let started = Instant::now();
    let args = vec!["ahosts".to_string(), name.to_string()];
    let output = match runner.run(
        "getent",
        &args,
        timeout.min(DNS_RESOLUTION_TIMEOUT),
        MAX_DNS_COMMAND_STDOUT_BYTES,
        MAX_DNS_COMMAND_STDERR_BYTES,
    ) {
        Ok(output) => output,
        Err(error) => {
            return DnsResolution {
                addresses: Vec::new(),
                status: DnsResolutionStatus::ResolverUnavailable,
                latency_ms: Some(started.elapsed().as_millis()),
                source: DnsResolutionSource::GetentAhosts,
                truncated: false,
                omitted_address_count: 0,
                parse_failure_count: 0,
                error: Some(bounded_network_error(&format!(
                    "failed to execute getent ahosts: {error}"
                ))),
            };
        }
    };
    let latency_ms = Some(started.elapsed().as_millis());
    let command_truncated = output.stdout_truncated || output.stderr_truncated;
    if output.timed_out {
        return DnsResolution {
            addresses: Vec::new(),
            status: DnsResolutionStatus::TimedOut,
            latency_ms,
            source: DnsResolutionSource::GetentAhosts,
            truncated: command_truncated,
            omitted_address_count: 0,
            parse_failure_count: 0,
            error: Some("getent ahosts timed out".to_string()),
        };
    }
    let mut addresses = Vec::new();
    let mut seen = BTreeSet::new();
    let mut parse_failure_count = 0usize;
    let mut truncated = command_truncated;
    for (line_index, line) in output.stdout.lines().enumerate() {
        if line_index >= MAX_DNS_OUTPUT_LINES {
            truncated = true;
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let valid_kind = fields
            .get(1)
            .is_some_and(|kind| matches!(*kind, "STREAM" | "DGRAM" | "RAW"));
        let Some(address) = fields
            .first()
            .and_then(|value| value.parse::<IpAddr>().ok())
            .filter(|_| valid_kind)
        else {
            parse_failure_count = parse_failure_count.saturating_add(1);
            continue;
        };
        if seen.insert(address) {
            addresses.push(address);
        }
    }
    let (addresses, omitted_address_count) = interleave_and_limit_addresses(addresses);
    truncated |= omitted_address_count > 0;
    if !output.success {
        let not_found = output.exit_code == Some(2) && addresses.is_empty();
        let detail = output.stderr.trim();
        let error = if not_found {
            "getent ahosts returned no addresses".to_string()
        } else if detail.is_empty() {
            "getent ahosts failed".to_string()
        } else {
            format!("getent ahosts failed: {detail}")
        };
        return DnsResolution {
            addresses: Vec::new(),
            status: if not_found {
                DnsResolutionStatus::NoAddresses
            } else {
                DnsResolutionStatus::CommandFailed
            },
            latency_ms,
            source: DnsResolutionSource::GetentAhosts,
            truncated,
            omitted_address_count,
            parse_failure_count,
            error: Some(bounded_network_error(&error)),
        };
    }
    let status = if addresses.is_empty() {
        if parse_failure_count > 0 {
            DnsResolutionStatus::InvalidOutput
        } else {
            DnsResolutionStatus::NoAddresses
        }
    } else if parse_failure_count > 0 || truncated {
        DnsResolutionStatus::Partial
    } else {
        DnsResolutionStatus::Resolved
    };
    let error = match status {
        DnsResolutionStatus::NoAddresses => Some("getent ahosts returned no addresses".to_string()),
        DnsResolutionStatus::InvalidOutput => {
            Some("getent ahosts returned no valid address rows".to_string())
        }
        DnsResolutionStatus::Partial if parse_failure_count > 0 => Some(format!(
            "getent ahosts output was partial; {parse_failure_count} malformed row(s) skipped"
        )),
        DnsResolutionStatus::Partial => {
            Some("getent ahosts output exceeded bounded result limits".to_string())
        }
        _ => None,
    };
    DnsResolution {
        addresses,
        status,
        latency_ms,
        source: DnsResolutionSource::GetentAhosts,
        truncated,
        omitted_address_count,
        parse_failure_count,
        error: error.map(|error| bounded_network_error(&error)),
    }
}

fn literal_dns_resolution(address: IpAddr) -> DnsResolution {
    DnsResolution {
        addresses: vec![address],
        status: DnsResolutionStatus::Literal,
        latency_ms: Some(0),
        source: DnsResolutionSource::IpLiteral,
        truncated: false,
        omitted_address_count: 0,
        parse_failure_count: 0,
        error: None,
    }
}

fn interleave_and_limit_addresses(addresses: Vec<IpAddr>) -> (Vec<IpAddr>, usize) {
    let mut ipv4 = VecDeque::new();
    let mut ipv6 = VecDeque::new();
    let mut seen = BTreeSet::new();
    let mut start_with_ipv6 = None;
    for address in addresses {
        if !seen.insert(address) {
            continue;
        }
        start_with_ipv6.get_or_insert(address.is_ipv6());
        match address {
            IpAddr::V4(_) => ipv4.push_back(address),
            IpAddr::V6(_) => ipv6.push_back(address),
        }
    }
    let total = ipv4.len().saturating_add(ipv6.len());
    let mut bounded = Vec::with_capacity(total.min(MAX_DNS_ADDRESSES));
    while bounded.len() < MAX_DNS_ADDRESSES && (!ipv4.is_empty() || !ipv6.is_empty()) {
        let queues = if start_with_ipv6.unwrap_or(false) {
            [&mut ipv6, &mut ipv4]
        } else {
            [&mut ipv4, &mut ipv6]
        };
        for queue in queues {
            if let Some(address) = queue.pop_front() {
                bounded.push(address);
            }
            if bounded.len() == MAX_DNS_ADDRESSES {
                break;
            }
        }
    }
    (bounded, total.saturating_sub(MAX_DNS_ADDRESSES))
}

trait TcpConnector {
    fn connect(&self, address: SocketAddr, timeout: Duration) -> io::Result<()>;
}

struct SystemTcpConnector;

impl TcpConnector for SystemTcpConnector {
    fn connect(&self, address: SocketAddr, timeout: Duration) -> io::Result<()> {
        TcpStream::connect_timeout(&address, timeout).map(|_| ())
    }
}

trait ProbeClock {
    fn elapsed(&self) -> Duration;
}

struct SystemProbeClock {
    started: Instant,
}

impl SystemProbeClock {
    fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl ProbeClock for SystemProbeClock {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

pub(crate) fn probe_tcp(request: &TcpProbeRequest) -> HealthProbeResult {
    let clock = SystemProbeClock::new();
    probe_tcp_with(request, &SystemDnsResolver, &SystemTcpConnector, &clock)
}

fn probe_tcp_with(
    request: &TcpProbeRequest,
    resolver: &dyn DnsResolver,
    connector: &dyn TcpConnector,
    clock: &dyn ProbeClock,
) -> HealthProbeResult {
    let bounded_host = request.host.chars().take(253).collect::<String>();
    let target = match bounded_host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{bounded_host}]:{}", request.port),
        _ => format!("{bounded_host}:{}", request.port),
    };
    let started = clock.elapsed();
    let timeout = Duration::from_millis(
        request
            .timeout_ms
            .unwrap_or(1_000)
            .clamp(1, MAX_PROBE_TIMEOUT_MS),
    );
    let deadline = started.saturating_add(timeout);
    let mut result = empty_probe_result(target);
    if validate_dns_target("tcp_probes host", &request.host).is_err() || request.port == 0 {
        result.status = TcpProbeStatus::InvalidTarget;
        result.stage = TcpProbeStage::Validation;
        result.error_kind = Some(TcpProbeErrorKind::InvalidTarget);
        result.error = Some("TCP probe target is invalid".to_string());
        return result;
    }

    let resolution = if let Ok(address) = request.host.parse::<IpAddr>() {
        literal_dns_resolution(address)
    } else {
        let remaining = deadline.saturating_sub(clock.elapsed());
        if remaining.is_zero() {
            return finish_probe_timeout(result, clock, started, TcpProbeStage::Resolution);
        }
        resolver.resolve(&request.host, remaining)
    };
    let (addresses, additionally_omitted) = interleave_and_limit_addresses(resolution.addresses);
    result.resolution_status =
        if additionally_omitted > 0 && resolution.status == DnsResolutionStatus::Resolved {
            DnsResolutionStatus::Partial
        } else {
            resolution.status
        };
    result.resolution_source = resolution.source;
    result.resolved_addrs = addresses.iter().map(ToString::to_string).collect();
    result.omitted_address_count = resolution
        .omitted_address_count
        .saturating_add(additionally_omitted);
    result.truncated = resolution.truncated || additionally_omitted > 0;
    if clock.elapsed() >= deadline {
        return finish_probe_timeout(result, clock, started, TcpProbeStage::Resolution);
    }
    let resolution_usable = matches!(
        result.resolution_status,
        DnsResolutionStatus::Resolved | DnsResolutionStatus::Partial | DnsResolutionStatus::Literal
    );
    if addresses.is_empty() || !resolution_usable {
        result.status = if resolution.status == DnsResolutionStatus::TimedOut {
            TcpProbeStatus::TimedOut
        } else {
            TcpProbeStatus::ResolutionFailed
        };
        result.stage = TcpProbeStage::Resolution;
        result.error_kind = Some(match resolution.status {
            DnsResolutionStatus::TimedOut => TcpProbeErrorKind::ResolutionTimedOut,
            DnsResolutionStatus::ResolverUnavailable => TcpProbeErrorKind::ResolverUnavailable,
            DnsResolutionStatus::NoAddresses => TcpProbeErrorKind::NoAddresses,
            _ => TcpProbeErrorKind::ResolutionFailed,
        });
        result.error = resolution
            .error
            .or_else(|| Some("DNS resolution failed".to_string()))
            .map(|error| bounded_network_error(&error));
        result.latency_ms = Some(clock.elapsed().saturating_sub(started).as_millis());
        return result;
    }

    let allowed = addresses
        .into_iter()
        .filter(|address| probe_ip_allowed(*address))
        .collect::<Vec<_>>();
    if allowed.is_empty() {
        result.status = TcpProbeStatus::PolicyDenied;
        result.stage = TcpProbeStage::Policy;
        result.error_kind = Some(TcpProbeErrorKind::PolicyDenied);
        result.error = Some(
            "all resolved addresses are outside the local/private/link-local TCP probe policy"
                .to_string(),
        );
        result.latency_ms = Some(clock.elapsed().saturating_sub(started).as_millis());
        return result;
    }

    let mut last_error = None;
    let mut last_timed_out = false;
    let address_count = allowed.len();
    for (index, address) in allowed.into_iter().enumerate() {
        let remaining = deadline.saturating_sub(clock.elapsed());
        if remaining < MIN_TCP_CONNECT_BUDGET {
            return finish_probe_timeout(result, clock, started, TcpProbeStage::Connect);
        }
        let remaining_address_count = address_count.saturating_sub(index).max(1);
        let connect_timeout = (remaining / (remaining_address_count as u32))
            .max(MIN_TCP_CONNECT_BUDGET)
            .min(remaining);
        result.attempted_addrs.push(address.to_string());
        match connector.connect(SocketAddr::new(address, request.port), connect_timeout) {
            Ok(()) => {
                result.ok = true;
                result.status = TcpProbeStatus::Reachable;
                result.stage = TcpProbeStage::Complete;
                result.selected_addr = Some(address.to_string());
                result.latency_ms = Some(clock.elapsed().saturating_sub(started).as_millis());
                return result;
            }
            Err(error) => {
                last_timed_out = error.kind() == io::ErrorKind::TimedOut;
                last_error = Some(bounded_network_error(&error.to_string()));
            }
        }
    }
    if clock.elapsed() >= deadline {
        return finish_probe_timeout(result, clock, started, TcpProbeStage::Connect);
    }
    result.status = TcpProbeStatus::Failed;
    result.stage = TcpProbeStage::Connect;
    result.error_kind = Some(if last_timed_out {
        TcpProbeErrorKind::ConnectTimedOut
    } else {
        TcpProbeErrorKind::ConnectFailed
    });
    result.error = last_error.or_else(|| Some("TCP connection failed".to_string()));
    result.latency_ms = Some(clock.elapsed().saturating_sub(started).as_millis());
    result
}

fn empty_probe_result(target: String) -> HealthProbeResult {
    HealthProbeResult {
        target,
        ok: false,
        latency_ms: None,
        error: None,
        status: TcpProbeStatus::Unknown,
        stage: TcpProbeStage::Unknown,
        error_kind: None,
        resolution_status: DnsResolutionStatus::Unknown,
        resolution_source: DnsResolutionSource::Unknown,
        resolved_addrs: Vec::new(),
        attempted_addrs: Vec::new(),
        selected_addr: None,
        truncated: false,
        omitted_address_count: 0,
    }
}

fn finish_probe_timeout(
    mut result: HealthProbeResult,
    clock: &dyn ProbeClock,
    started: Duration,
    stage: TcpProbeStage,
) -> HealthProbeResult {
    result.status = TcpProbeStatus::TimedOut;
    result.stage = stage;
    result.error_kind = Some(TcpProbeErrorKind::DeadlineExceeded);
    result.error = Some("TCP probe total deadline was exhausted".to_string());
    result.latency_ms = Some(clock.elapsed().saturating_sub(started).as_millis());
    result
}

trait FirewallCommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> io::Result<LimitedCommandOutput>;
}

struct SystemFirewallCommandRunner;

impl FirewallCommandRunner for SystemFirewallCommandRunner {
    fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    ) -> io::Result<LimitedCommandOutput> {
        run_limited_command(program, args, timeout, stdout_limit, stderr_limit)
    }
}

#[derive(Default)]
struct FirewallRuleAccumulator {
    rule_count: usize,
    rules_sample: Vec<String>,
    truncated: bool,
    invalid_output: bool,
}

impl FirewallRuleAccumulator {
    fn observe_output(&mut self, output: &LimitedCommandOutput) {
        self.truncated |= output.stdout_truncated || output.stderr_truncated;
        self.invalid_output |= output.stdout.contains('\u{fffd}');
    }

    fn push_rule(&mut self, source: Option<&str>, raw: &str) {
        let prefixed = source.map_or_else(|| raw.to_string(), |source| format!("{source}: {raw}"));
        let (line, invalid) = sanitize_firewall_rule(&prefixed);
        self.invalid_output |= invalid;
        self.rule_count = self.rule_count.saturating_add(1);
        if self.rules_sample.len() < MAX_FIREWALL_RULE_SAMPLES {
            self.rules_sample.push(line);
        }
    }

    fn apply(self, status: &mut FirewallStatus) {
        status.rule_count = self.rule_count;
        status.rules_sample = self.rules_sample;
        status.omitted_rule_count = status.rule_count.saturating_sub(status.rules_sample.len());
        status.truncated |= self.truncated;
        if self.invalid_output && status.error_kind.is_none() {
            status.error_kind = Some(FirewallErrorKind::InvalidOutput);
            status.error = Some("firewall command output contained invalid text".to_string());
        }
    }
}

fn collect_firewall_status(runner: &dyn FirewallCommandRunner) -> Vec<FirewallStatus> {
    vec![
        collect_firewalld_status(runner),
        collect_nftables_status(runner),
        collect_iptables_status(runner),
    ]
}

fn collect_firewalld_status(runner: &dyn FirewallCommandRunner) -> FirewallStatus {
    let mut status = firewall_status(
        "firewalld",
        Some("firewall-cmd"),
        &["--state"],
        "firewall-cmd",
    );
    let state_output = match run_firewall_command(runner, "firewall-cmd", &["--state"]) {
        Ok(output) => output,
        Err(error) => {
            apply_firewall_io_failure(&mut status, "firewall-cmd --state", &error);
            return status;
        }
    };
    status.available = true;
    status.exit_code = state_output.exit_code;
    status.timed_out = state_output.timed_out;
    status.truncated = state_output.stdout_truncated || state_output.stderr_truncated;
    if state_output.timed_out {
        apply_firewall_output_failure(&mut status, "firewall-cmd --state", &state_output);
        return status;
    }
    let state_text =
        format!("{}\n{}", state_output.stdout, state_output.stderr).to_ascii_lowercase();
    if state_text.contains("not running") {
        status.active = false;
        status.status = if status.truncated {
            CollectionStatus::Partial
        } else {
            CollectionStatus::Complete
        };
        status.error_kind = Some(FirewallErrorKind::NotRunning);
        status.error = Some("firewalld is not running".to_string());
        return status;
    }
    if !state_output.success {
        apply_firewall_output_failure(&mut status, "firewall-cmd --state", &state_output);
        return status;
    }
    if state_output.stdout.trim() != "running" {
        status.status = CollectionStatus::Partial;
        status.error_kind = Some(FirewallErrorKind::InvalidOutput);
        status.error = Some("firewall-cmd --state returned an unrecognized state".to_string());
        return status;
    }

    status.active = true;
    status.args.push("--list-all-zones".to_string());
    let zones_output = match run_firewall_command(runner, "firewall-cmd", &["--list-all-zones"]) {
        Ok(output) => output,
        Err(error) => {
            apply_firewall_io_failure(&mut status, "firewall-cmd --list-all-zones", &error);
            status.status = CollectionStatus::Partial;
            return status;
        }
    };
    status.exit_code = zones_output.exit_code;
    status.timed_out |= zones_output.timed_out;
    status.truncated |= zones_output.stdout_truncated || zones_output.stderr_truncated;
    if zones_output.timed_out || !zones_output.success {
        apply_firewall_output_failure(&mut status, "firewall-cmd --list-all-zones", &zones_output);
        status.status = CollectionStatus::Partial;
        return status;
    }

    let mut rules = FirewallRuleAccumulator::default();
    rules.observe_output(&zones_output);
    parse_firewalld_rules(&zones_output.stdout, &mut rules);
    rules.apply(&mut status);
    finalize_successful_firewall_status(&mut status);
    status
}

fn collect_nftables_status(runner: &dyn FirewallCommandRunner) -> FirewallStatus {
    let mut status = firewall_status(
        "nftables",
        Some("nft"),
        &["list", "ruleset"],
        "nft list ruleset",
    );
    let output = match run_firewall_command(runner, "nft", &["list", "ruleset"]) {
        Ok(output) => output,
        Err(error) => {
            apply_firewall_io_failure(&mut status, "nft list ruleset", &error);
            return status;
        }
    };
    status.available = true;
    status.exit_code = output.exit_code;
    status.timed_out = output.timed_out;
    status.truncated = output.stdout_truncated || output.stderr_truncated;
    if output.timed_out || !output.success {
        apply_firewall_output_failure(&mut status, "nft list ruleset", &output);
        return status;
    }

    let mut rules = FirewallRuleAccumulator::default();
    rules.observe_output(&output);
    parse_nftables_rules(&output.stdout, &mut rules);
    rules.apply(&mut status);
    status.active = status.rule_count > 0;
    finalize_successful_firewall_status(&mut status);
    status
}

fn collect_iptables_status(runner: &dyn FirewallCommandRunner) -> FirewallStatus {
    let mut status = firewall_status("iptables", None, &[], "iptables -S; ip6tables -S");
    let mut rules = FirewallRuleAccumulator::default();
    let mut success_count = 0usize;
    let mut output_exit_codes = Vec::new();
    let mut errors = Vec::new();

    for (source, command) in [("iptables", "iptables"), ("ip6tables", "ip6tables")] {
        match run_firewall_command(runner, command, &["-S"]) {
            Ok(output) => {
                status.available = true;
                status.timed_out |= output.timed_out;
                status.truncated |= output.stdout_truncated || output.stderr_truncated;
                output_exit_codes.push(output.exit_code);
                if output.timed_out || !output.success {
                    let (kind, error) = firewall_output_failure(source, &output);
                    merge_firewall_error_kind(&mut status.error_kind, kind);
                    errors.push(error);
                } else {
                    success_count = success_count.saturating_add(1);
                    rules.observe_output(&output);
                    parse_iptables_rules(source, &output.stdout, &mut rules);
                }
            }
            Err(error) => {
                let (available, timed_out, kind, error) = firewall_io_failure(source, &error);
                status.available |= available;
                status.timed_out |= timed_out;
                merge_firewall_error_kind(&mut status.error_kind, kind);
                errors.push(error);
            }
        }
    }

    status.exit_code = aggregate_firewall_exit_code(&output_exit_codes);
    rules.apply(&mut status);
    status.active = status.rule_count > 0;
    if success_count == 0 {
        status.status = CollectionStatus::Failed;
    } else if success_count < 2 || status.truncated || status.error_kind.is_some() {
        status.status = CollectionStatus::Partial;
    } else {
        status.status = CollectionStatus::Complete;
    }
    if !errors.is_empty() {
        status.error = Some(bounded_firewall_error(&errors.join("; ")));
    } else if status.rule_count == 0 {
        status.error_kind = Some(FirewallErrorKind::EmptyRules);
    }
    status
}

fn firewall_status(
    backend: &str,
    command: Option<&str>,
    args: &[&str],
    source: &str,
) -> FirewallStatus {
    FirewallStatus {
        backend: backend.to_string(),
        command: command.map(str::to_string),
        args: args.iter().map(|arg| (*arg).to_string()).collect(),
        source: source.to_string(),
        ..FirewallStatus::default()
    }
}

fn run_firewall_command(
    runner: &dyn FirewallCommandRunner,
    command: &str,
    args: &[&str],
) -> io::Result<LimitedCommandOutput> {
    runner.run(
        command,
        args,
        COMMAND_TIMEOUT,
        MAX_FIREWALL_STDOUT_BYTES,
        MAX_FIREWALL_STDERR_BYTES,
    )
}

#[derive(Clone, Copy)]
enum FirewalldRuleSection {
    ForwardPorts,
    SourcePorts,
    RichRules,
}

fn parse_firewalld_rules(output: &str, rules: &mut FirewallRuleAccumulator) {
    let mut in_zone = false;
    let mut section = None;
    for (index, raw) in output.lines().enumerate() {
        if index >= MAX_FIREWALL_OUTPUT_LINES {
            rules.truncated = true;
            break;
        }
        if firewall_line_has_invalid_text(raw) {
            rules.invalid_output = true;
        }
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let indent = raw.len().saturating_sub(raw.trim_start().len());
        if indent == 0 {
            if !is_firewalld_zone_header(line) {
                rules.invalid_output = true;
            }
            in_zone = true;
            section = None;
            continue;
        }
        if !in_zone || raw[..indent].contains('\t') {
            rules.invalid_output = true;
            continue;
        }
        if indent >= 4 {
            match section {
                Some(FirewalldRuleSection::ForwardPorts) if is_firewalld_port_mapping(line) => {
                    rules.push_rule(None, &format!("forward-ports: {line}"));
                }
                Some(FirewalldRuleSection::SourcePorts) if is_firewalld_source_port(line) => {
                    rules.push_rule(None, &format!("source-ports: {line}"));
                }
                Some(FirewalldRuleSection::RichRules) if line.starts_with("rule ") => {
                    rules.push_rule(None, line);
                }
                _ => rules.invalid_output = true,
            }
            continue;
        }
        if indent != 2 {
            rules.invalid_output = true;
            continue;
        }
        section = None;
        let Some((key, value)) = line.split_once(':') else {
            rules.invalid_output = true;
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "target" | "interfaces" | "sources" | "icmp-block-inversion" => {}
            "services" | "ports" | "protocols" | "icmp-blocks" => {
                for item in value.split_whitespace() {
                    rules.push_rule(None, &format!("{key}: {item}"));
                }
            }
            "forward" | "masquerade" => match value {
                "yes" => rules.push_rule(None, line),
                "no" => {}
                _ => rules.invalid_output = true,
            },
            "forward-ports" => {
                section = Some(FirewalldRuleSection::ForwardPorts);
                for item in value.split_whitespace() {
                    if is_firewalld_port_mapping(item) {
                        rules.push_rule(None, &format!("forward-ports: {item}"));
                    } else {
                        rules.invalid_output = true;
                    }
                }
            }
            "source-ports" => {
                section = Some(FirewalldRuleSection::SourcePorts);
                for item in value.split_whitespace() {
                    if is_firewalld_source_port(item) {
                        rules.push_rule(None, &format!("source-ports: {item}"));
                    } else {
                        rules.invalid_output = true;
                    }
                }
            }
            "rich rules" if value.is_empty() => {
                section = Some(FirewalldRuleSection::RichRules);
            }
            "rich rules" => rules.invalid_output = true,
            _ => rules.invalid_output = true,
        }
    }
}

fn is_firewalld_zone_header(line: &str) -> bool {
    let name = line.strip_suffix(" (active)").unwrap_or(line);
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn is_firewalld_port_mapping(line: &str) -> bool {
    line.starts_with("port=") && line.contains(":proto=")
}

fn is_firewalld_source_port(line: &str) -> bool {
    let Some((port, protocol)) = line.split_once('/') else {
        return false;
    };
    !port.is_empty()
        && !protocol.is_empty()
        && port
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-')
        && protocol.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

#[derive(Clone, Copy)]
enum NftBlockKind {
    Table,
    Chain,
    Structure,
}

#[derive(Clone, Copy)]
struct NftBlock {
    kind: NftBlockKind,
    base_depth: usize,
}

fn parse_nftables_rules(output: &str, rules: &mut FirewallRuleAccumulator) {
    let mut blocks: Vec<NftBlock> = Vec::new();
    let mut brace_depth = 0usize;
    for (index, raw) in output.lines().enumerate() {
        if index >= MAX_FIREWALL_OUTPUT_LINES {
            rules.truncated = true;
            break;
        }
        if firewall_line_has_invalid_text(raw) {
            rules.invalid_output = true;
        }
        let line = strip_nft_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let closing_only = line.chars().all(|character| matches!(character, '}' | ';'));
        let current = blocks.last().map(|block| block.kind);
        let declaration = match current {
            None if is_nft_declaration(line, "table") => Some(NftBlockKind::Table),
            Some(NftBlockKind::Table) if is_nft_declaration(line, "chain") => {
                Some(NftBlockKind::Chain)
            }
            Some(NftBlockKind::Table)
                if ["set", "map", "flowtable"]
                    .iter()
                    .any(|kind| is_nft_declaration(line, kind)) =>
            {
                Some(NftBlockKind::Structure)
            }
            _ => None,
        };
        if !closing_only && declaration.is_none() {
            match current {
                Some(NftBlockKind::Chain) if is_nft_base_chain_declaration(line) => {
                    if !is_valid_nft_base_chain_declaration(line) {
                        rules.invalid_output = true;
                    } else if nft_line_has_policy(line) {
                        rules.push_rule(None, line);
                    }
                }
                Some(NftBlockKind::Chain) => rules.push_rule(None, line),
                Some(NftBlockKind::Structure) => {}
                _ => rules.invalid_output = true,
            }
        }

        let (opens, closes) = nft_brace_counts(line);
        if closes > brace_depth.saturating_add(opens) {
            rules.invalid_output = true;
            brace_depth = 0;
            blocks.clear();
            continue;
        }
        let base_depth = brace_depth;
        brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
        if let Some(kind) = declaration {
            if opens == 0 {
                rules.invalid_output = true;
            } else if brace_depth > base_depth {
                blocks.push(NftBlock { kind, base_depth });
            }
        }
        while blocks
            .last()
            .is_some_and(|block| brace_depth <= block.base_depth)
        {
            blocks.pop();
        }
    }
    if !rules.truncated && (brace_depth != 0 || !blocks.is_empty()) {
        rules.invalid_output = true;
    }
}

fn strip_nft_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '#' if !quoted => return &line[..index],
            _ => {}
        }
    }
    line
}

fn is_nft_declaration(line: &str, kind: &str) -> bool {
    let declaration = line.trim_end_matches([' ', '\t', '{']).trim_end();
    let mut fields = declaration.split_whitespace();
    fields.next() == Some(kind) && fields.next().is_some() && line.trim_end().ends_with('{')
}

fn is_nft_base_chain_declaration(line: &str) -> bool {
    let line = line.trim();
    line.starts_with("type ") || line.starts_with("policy ")
}

fn is_valid_nft_base_chain_declaration(line: &str) -> bool {
    let line = line.trim();
    let policy_mentioned = line
        .split_whitespace()
        .any(|field| field.trim_end_matches(';') == "policy");
    if line.starts_with("policy ") {
        return nft_line_has_policy(line);
    }
    line.starts_with("type ")
        && line.split_whitespace().any(|field| field == "hook")
        && line.split_whitespace().any(|field| field == "priority")
        && (!policy_mentioned || nft_line_has_policy(line))
}

fn nft_line_has_policy(line: &str) -> bool {
    line.split(';').any(|statement| {
        let mut fields = statement.split_whitespace();
        fields.next() == Some("policy") && fields.next().is_some() && fields.next().is_none()
    })
}

fn nft_brace_counts(line: &str) -> (usize, usize) {
    let mut quoted = false;
    let mut escaped = false;
    let mut opens = 0usize;
    let mut closes = 0usize;
    for character in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '{' if !quoted => opens = opens.saturating_add(1),
            '}' if !quoted => closes = closes.saturating_add(1),
            _ => {}
        }
    }
    (opens, closes)
}

fn parse_iptables_rules(source: &str, output: &str, rules: &mut FirewallRuleAccumulator) {
    for (index, raw) in output.lines().enumerate() {
        if index >= MAX_FIREWALL_OUTPUT_LINES {
            rules.truncated = true;
            break;
        }
        let line = raw.trim();
        if line.starts_with("-P ") || line.starts_with("-A ") {
            rules.push_rule(Some(source), line);
        } else if line.starts_with("-N ") || line.is_empty() {
        } else {
            rules.invalid_output = true;
        }
    }
}

fn firewall_line_has_invalid_text(raw: &str) -> bool {
    raw.chars()
        .any(|character| character == '\u{fffd}' || (character.is_control() && character != '\t'))
}

fn sanitize_firewall_rule(raw: &str) -> (String, bool) {
    let mut invalid = false;
    let cleaned = raw
        .chars()
        .map(|character| {
            if character == '\u{fffd}' || (character.is_control() && character != '\t') {
                invalid = true;
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    let redaction_limit = MAX_FIREWALL_RULE_CHARS.saturating_sub(16);
    let redacted = redact_sensitive_text(cleaned.trim(), redaction_limit);
    (
        redacted.chars().take(MAX_FIREWALL_RULE_CHARS).collect(),
        invalid,
    )
}

fn finalize_successful_firewall_status(status: &mut FirewallStatus) {
    if status.error_kind == Some(FirewallErrorKind::InvalidOutput) || status.truncated {
        status.status = CollectionStatus::Partial;
    } else {
        status.status = CollectionStatus::Complete;
    }
    if status.rule_count == 0 && status.error_kind.is_none() {
        status.error_kind = Some(FirewallErrorKind::EmptyRules);
    }
}

fn apply_firewall_io_failure(status: &mut FirewallStatus, source: &str, error: &io::Error) {
    let (available, timed_out, kind, error) = firewall_io_failure(source, error);
    status.available |= available;
    status.timed_out |= timed_out;
    status.status = CollectionStatus::Failed;
    status.error_kind = Some(kind);
    status.error = Some(error);
}

fn firewall_io_failure(source: &str, error: &io::Error) -> (bool, bool, FirewallErrorKind, String) {
    let (available, timed_out, kind) = match error.kind() {
        io::ErrorKind::NotFound => (false, false, FirewallErrorKind::CommandNotFound),
        io::ErrorKind::PermissionDenied => (true, false, FirewallErrorKind::PermissionDenied),
        io::ErrorKind::TimedOut => (true, true, FirewallErrorKind::TimedOut),
        _ => (false, false, FirewallErrorKind::CommandFailed),
    };
    (
        available,
        timed_out,
        kind,
        bounded_firewall_error(&format!("{source}: {error}")),
    )
}

fn apply_firewall_output_failure(
    status: &mut FirewallStatus,
    source: &str,
    output: &LimitedCommandOutput,
) {
    let (kind, error) = firewall_output_failure(source, output);
    status.available = true;
    status.timed_out |= output.timed_out;
    status.truncated |= output.stdout_truncated || output.stderr_truncated;
    status.exit_code = output.exit_code;
    status.status = CollectionStatus::Failed;
    status.error_kind = Some(kind);
    status.error = Some(error);
}

fn firewall_output_failure(
    source: &str,
    output: &LimitedCommandOutput,
) -> (FirewallErrorKind, String) {
    let detail = format!("{}\n{}", output.stderr, output.stdout);
    let lower = detail.to_ascii_lowercase();
    let kind = if output.timed_out {
        FirewallErrorKind::TimedOut
    } else if lower.contains("permission denied") || lower.contains("operation not permitted") {
        FirewallErrorKind::PermissionDenied
    } else {
        FirewallErrorKind::CommandFailed
    };
    let detail = detail.trim();
    let error = if output.timed_out {
        format!("{source}: command timed out")
    } else if detail.is_empty() {
        format!("{source}: command failed")
    } else {
        format!("{source}: {detail}")
    };
    (kind, bounded_firewall_error(&error))
}

fn merge_firewall_error_kind(
    current: &mut Option<FirewallErrorKind>,
    candidate: FirewallErrorKind,
) {
    let priority = |kind: FirewallErrorKind| match kind {
        FirewallErrorKind::TimedOut => 7,
        FirewallErrorKind::PermissionDenied => 6,
        FirewallErrorKind::CommandFailed => 5,
        FirewallErrorKind::CommandNotFound => 4,
        FirewallErrorKind::InvalidOutput => 3,
        FirewallErrorKind::NotRunning => 2,
        FirewallErrorKind::EmptyRules => 1,
    };
    if current.is_none_or(|kind| priority(candidate) > priority(kind)) {
        *current = Some(candidate);
    }
}

fn aggregate_firewall_exit_code(codes: &[Option<i32>]) -> Option<i32> {
    codes
        .iter()
        .flatten()
        .copied()
        .find(|code| *code != 0)
        .or_else(|| codes.iter().flatten().copied().next())
}

fn bounded_firewall_error(error: &str) -> String {
    let redacted = redact_sensitive_text(error, MAX_NETWORK_ERROR_CHARS.saturating_sub(16));
    bounded_network_error(&redacted)
}

fn probe_ip_allowed(address: IpAddr) -> bool {
    if address.is_unspecified() {
        return false;
    }
    match address {
        IpAddr::V4(address) => {
            address.is_loopback() || address.is_private() || address.is_link_local()
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return probe_ip_allowed(IpAddr::V4(mapped));
            }
            let first = address.segments()[0];
            address.is_loopback() || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80
        }
    }
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
    use std::cell::{Cell, RefCell};
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
            reader.with_text(RESOLV_CONF_PATH, "nameserver 127.0.0.53\n")
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
                    Ok(BoundedNetworkFile {
                        bytes,
                        truncated,
                        actual_path: path.to_string(),
                    })
                }
                Some(FixtureRead::Error(kind)) => Err(io::Error::from(*kind)),
                None => Err(io::Error::from(ErrorKind::NotFound)),
            }
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct DnsCommandCall {
        program: String,
        args: Vec<String>,
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    }

    struct FixtureDnsCommandRunner {
        output: std::result::Result<LimitedCommandOutput, ErrorKind>,
        calls: RefCell<Vec<DnsCommandCall>>,
    }

    impl FixtureDnsCommandRunner {
        fn output(output: LimitedCommandOutput) -> Self {
            Self {
                output: Ok(output),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn error(kind: ErrorKind) -> Self {
            Self {
                output: Err(kind),
                calls: RefCell::new(Vec::new()),
            }
        }
    }

    impl DnsCommandRunner for FixtureDnsCommandRunner {
        fn run(
            &self,
            program: &str,
            args: &[String],
            timeout: Duration,
            stdout_limit: usize,
            stderr_limit: usize,
        ) -> io::Result<LimitedCommandOutput> {
            self.calls.borrow_mut().push(DnsCommandCall {
                program: program.to_string(),
                args: args.to_vec(),
                timeout,
                stdout_limit,
                stderr_limit,
            });
            self.output
                .as_ref()
                .cloned()
                .map_err(|kind| io::Error::from(*kind))
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct FirewallCommandCall {
        program: String,
        args: Vec<String>,
        timeout: Duration,
        stdout_limit: usize,
        stderr_limit: usize,
    }

    struct FixtureFirewallStep {
        program: String,
        args: Vec<String>,
        result: std::result::Result<LimitedCommandOutput, ErrorKind>,
    }

    struct FixtureFirewallCommandRunner {
        steps: RefCell<VecDeque<FixtureFirewallStep>>,
        calls: RefCell<Vec<FirewallCommandCall>>,
    }

    impl FixtureFirewallCommandRunner {
        fn new(steps: Vec<FixtureFirewallStep>) -> Self {
            Self {
                steps: RefCell::new(VecDeque::from(steps)),
                calls: RefCell::new(Vec::new()),
            }
        }

        fn assert_finished(&self) {
            assert!(
                self.steps.borrow().is_empty(),
                "unused firewall fixture steps"
            );
        }
    }

    impl FirewallCommandRunner for FixtureFirewallCommandRunner {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            timeout: Duration,
            stdout_limit: usize,
            stderr_limit: usize,
        ) -> io::Result<LimitedCommandOutput> {
            self.calls.borrow_mut().push(FirewallCommandCall {
                program: program.to_string(),
                args: args.iter().map(|arg| (*arg).to_string()).collect(),
                timeout,
                stdout_limit,
                stderr_limit,
            });
            let step = self
                .steps
                .borrow_mut()
                .pop_front()
                .expect("fixture firewall command step");
            assert_eq!(program, step.program);
            assert_eq!(args, step.args);
            step.result.map_err(io::Error::from)
        }
    }

    #[derive(Default)]
    struct FixtureProbeClock {
        elapsed_ms: Cell<u64>,
    }

    impl FixtureProbeClock {
        fn advance(&self, duration: Duration) {
            self.elapsed_ms.set(
                self.elapsed_ms
                    .get()
                    .saturating_add(duration.as_millis().min(u128::from(u64::MAX)) as u64),
            );
        }
    }

    impl ProbeClock for FixtureProbeClock {
        fn elapsed(&self) -> Duration {
            Duration::from_millis(self.elapsed_ms.get())
        }
    }

    struct FixtureDnsResolver<'a> {
        resolution: DnsResolution,
        clock: Option<&'a FixtureProbeClock>,
        elapsed: Duration,
        calls: Cell<usize>,
        timeouts: RefCell<Vec<Duration>>,
    }

    impl<'a> FixtureDnsResolver<'a> {
        fn new(resolution: DnsResolution) -> Self {
            Self {
                resolution,
                clock: None,
                elapsed: Duration::ZERO,
                calls: Cell::new(0),
                timeouts: RefCell::new(Vec::new()),
            }
        }

        fn with_elapsed(mut self, clock: &'a FixtureProbeClock, elapsed: Duration) -> Self {
            self.clock = Some(clock);
            self.elapsed = elapsed;
            self
        }
    }

    impl DnsResolver for FixtureDnsResolver<'_> {
        fn resolve(&self, _name: &str, timeout: Duration) -> DnsResolution {
            self.calls.set(self.calls.get().saturating_add(1));
            self.timeouts.borrow_mut().push(timeout);
            if let Some(clock) = self.clock {
                clock.advance(self.elapsed);
            }
            self.resolution.clone()
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum FixtureConnectResult {
        Success,
        Failed(ErrorKind),
    }

    #[derive(Debug, Clone, Copy)]
    struct FixtureConnectStep {
        address: IpAddr,
        elapsed: Duration,
        result: FixtureConnectResult,
    }

    struct FixtureTcpConnector<'a> {
        clock: &'a FixtureProbeClock,
        steps: RefCell<VecDeque<FixtureConnectStep>>,
        attempts: RefCell<Vec<(SocketAddr, Duration)>>,
    }

    impl<'a> FixtureTcpConnector<'a> {
        fn new(clock: &'a FixtureProbeClock, steps: Vec<FixtureConnectStep>) -> Self {
            Self {
                clock,
                steps: RefCell::new(VecDeque::from(steps)),
                attempts: RefCell::new(Vec::new()),
            }
        }
    }

    impl TcpConnector for FixtureTcpConnector<'_> {
        fn connect(&self, address: SocketAddr, timeout: Duration) -> io::Result<()> {
            self.attempts.borrow_mut().push((address, timeout));
            let step = self
                .steps
                .borrow_mut()
                .pop_front()
                .expect("fixture connect step");
            assert_eq!(address.ip(), step.address);
            assert!(step.elapsed <= timeout, "fixture exceeded connect budget");
            self.clock.advance(step.elapsed);
            match step.result {
                FixtureConnectResult::Success => Ok(()),
                FixtureConnectResult::Failed(kind) => Err(io::Error::from(kind)),
            }
        }
    }

    fn dns_command_output(
        success: bool,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
    ) -> LimitedCommandOutput {
        LimitedCommandOutput {
            success,
            exit_code: Some(if success { 0 } else { 1 }),
            stdout: stdout.into(),
            stderr: stderr.into(),
            timed_out: false,
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    fn firewall_step(
        program: &str,
        args: &[&str],
        result: std::result::Result<LimitedCommandOutput, ErrorKind>,
    ) -> FixtureFirewallStep {
        FixtureFirewallStep {
            program: program.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
            result,
        }
    }

    fn resolved_fixture(addresses: &[&str]) -> DnsResolution {
        DnsResolution {
            addresses: addresses
                .iter()
                .map(|address| address.parse::<IpAddr>().expect("fixture IP"))
                .collect(),
            status: DnsResolutionStatus::Resolved,
            latency_ms: Some(0),
            source: DnsResolutionSource::GetentAhosts,
            truncated: false,
            omitted_address_count: 0,
            parse_failure_count: 0,
            error: None,
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
    fn firewall_collects_three_coexisting_backends_with_realistic_rules() {
        let runner = FixtureFirewallCommandRunner::new(vec![
            firewall_step(
                "firewall-cmd",
                &["--state"],
                Ok(dns_command_output(true, "running\n", "")),
            ),
            firewall_step(
                "firewall-cmd",
                &["--list-all-zones"],
                Ok(dns_command_output(
                    true,
                    concat!(
                        "public (active)\n",
                        "  target: default\n",
                        "  interfaces: eth0\n",
                        "  sources: 10.0.0.0/8\n",
                        "  services: ssh dhcpv6-client\n",
                        "  ports: 8443/tcp\n",
                        "  protocols: icmp\n",
                        "  forward: yes\n",
                        "  masquerade: yes\n",
                        "  forward-ports:\n",
                        "    port=80:proto=tcp:toport=8080:toaddr=10.0.0.2\n",
                        "  source-ports: 5353/udp\n",
                        "  icmp-blocks: echo-request echo-reply\n",
                        "  rich rules:\n",
                        "    rule family=\"ipv4\" source address=\"10.0.0.0/8\" accept\n",
                        "    rule family=\"ipv6\" service name=\"ssh\" accept\n",
                    ),
                    "",
                )),
            ),
            firewall_step(
                "nft",
                &["list", "ruleset"],
                Ok(dns_command_output(
                    true,
                    concat!(
                        "table inet filter {\n",
                        "  set blocked {\n",
                        "    type ipv4_addr\n",
                        "    elements = { 192.0.2.1, 192.0.2.2 }\n",
                        "  }\n",
                        "  map verdicts {\n",
                        "    type ipv4_addr : verdict\n",
                        "  }\n",
                        "  flowtable fastpath {\n",
                        "    hook ingress priority filter\n",
                        "    devices = { eth0 }\n",
                        "  }\n",
                        "  chain input {\n",
                        "    type filter hook input priority filter; policy drop;\n",
                        "    # generated comment\n",
                        "    ct state established,related accept\n",
                        "  }\n",
                        "}\n",
                    ),
                    "",
                )),
            ),
            firewall_step(
                "iptables",
                &["-S"],
                Ok(dns_command_output(
                    true,
                    concat!(
                        "-P INPUT DROP\n",
                        "-N CUSTOM\n",
                        "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n",
                        "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n",
                    ),
                    "",
                )),
            ),
            firewall_step(
                "ip6tables",
                &["-S"],
                Ok(dns_command_output(
                    true,
                    "-P INPUT DROP\n-A INPUT -p ipv6-icmp -j ACCEPT\n",
                    "",
                )),
            ),
        ]);

        let statuses = collect_firewall_status(&runner);
        runner.assert_finished();
        assert_eq!(
            statuses
                .iter()
                .map(|status| status.backend.as_str())
                .collect::<Vec<_>>(),
            ["firewalld", "nftables", "iptables"]
        );
        assert!(statuses.iter().all(|status| status.available));
        assert!(statuses.iter().all(|status| status.active));
        assert!(statuses
            .iter()
            .all(|status| status.status == CollectionStatus::Complete));
        assert_eq!(statuses[0].rule_count, 12);
        assert_eq!(statuses[1].rule_count, 2);
        assert_eq!(statuses[2].rule_count, 5);
        assert!(statuses[0]
            .rules_sample
            .iter()
            .all(|rule| !rule.starts_with("target:")
                && !rule.starts_with("interfaces:")
                && !rule.starts_with("sources:")
                && !rule.starts_with("public")));
        assert!(statuses[1]
            .rules_sample
            .iter()
            .all(|rule| !rule.starts_with("table ") && !rule.starts_with("chain ")));
        assert!(statuses[2]
            .rules_sample
            .iter()
            .any(|rule| rule.starts_with("iptables: -A INPUT")));
        assert!(statuses[2]
            .rules_sample
            .iter()
            .any(|rule| rule.starts_with("ip6tables: -A INPUT")));
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 5);
        assert!(calls.iter().all(|call| call.timeout == COMMAND_TIMEOUT));
        assert!(calls
            .iter()
            .all(|call| call.stdout_limit == MAX_FIREWALL_STDOUT_BYTES));
        assert!(calls
            .iter()
            .all(|call| call.stderr_limit == MAX_FIREWALL_STDERR_BYTES));
    }

    #[test]
    fn firewalld_unknown_fields_and_dangling_rich_rules_are_partial() {
        let runner = FixtureFirewallCommandRunner::new(vec![
            firewall_step(
                "firewall-cmd",
                &["--state"],
                Ok(dns_command_output(true, "running\n", "")),
            ),
            firewall_step(
                "firewall-cmd",
                &["--list-all-zones"],
                Ok(dns_command_output(
                    true,
                    concat!(
                        "public (active)\n",
                        "  target: default\n",
                        "    rule family=\"ipv4\" accept\n",
                        "  unknown-item: value\n",
                    ),
                    "",
                )),
            ),
        ]);
        let status = collect_firewalld_status(&runner);
        runner.assert_finished();
        assert_eq!(status.status, CollectionStatus::Partial);
        assert_eq!(status.error_kind, Some(FirewallErrorKind::InvalidOutput));
        assert_eq!(status.rule_count, 0);
        assert!(status.rules_sample.is_empty());
    }

    #[test]
    fn inactive_firewalld_skips_zone_command_and_empty_rules_are_distinct() {
        let mut inactive = dns_command_output(false, "not running\n", "");
        inactive.exit_code = Some(252);
        let runner = FixtureFirewallCommandRunner::new(vec![
            firewall_step("firewall-cmd", &["--state"], Ok(inactive)),
            firewall_step(
                "nft",
                &["list", "ruleset"],
                Ok(dns_command_output(
                    true,
                    "table inet filter {\n  chain input {\n  }\n}\n",
                    "",
                )),
            ),
            firewall_step("iptables", &["-S"], Ok(dns_command_output(true, "", ""))),
            firewall_step("ip6tables", &["-S"], Ok(dns_command_output(true, "", ""))),
        ]);

        let statuses = collect_firewall_status(&runner);
        runner.assert_finished();
        assert_eq!(runner.calls.borrow().len(), 4);
        assert_eq!(statuses[0].status, CollectionStatus::Complete);
        assert!(!statuses[0].active);
        assert_eq!(statuses[0].error_kind, Some(FirewallErrorKind::NotRunning));
        assert_eq!(statuses[0].args, ["--state"]);
        for status in &statuses[1..] {
            assert_eq!(status.status, CollectionStatus::Complete);
            assert!(!status.active);
            assert_eq!(status.error_kind, Some(FirewallErrorKind::EmptyRules));
        }
    }

    #[test]
    fn nft_empty_structures_are_inactive_and_syntax_errors_are_partial() {
        let runner = FixtureFirewallCommandRunner::new(vec![
            firewall_step(
                "nft",
                &["list", "ruleset"],
                Ok(dns_command_output(
                    true,
                    concat!(
                        "table inet filter {\n",
                        "  chain input {\n",
                        "    type filter hook input priority filter; policy drop;\n",
                        "    ct state established,related accept\n",
                        "  }\n",
                    ),
                    "",
                )),
            ),
            firewall_step(
                "nft",
                &["list", "ruleset"],
                Ok(dns_command_output(true, "flush ruleset\n", "")),
            ),
        ]);

        let unbalanced = collect_nftables_status(&runner);
        assert!(unbalanced.active);
        assert_eq!(unbalanced.rule_count, 2);
        assert_eq!(unbalanced.status, CollectionStatus::Partial);
        assert_eq!(
            unbalanced.error_kind,
            Some(FirewallErrorKind::InvalidOutput)
        );
        let top_level_unknown = collect_nftables_status(&runner);
        runner.assert_finished();
        assert!(!top_level_unknown.active);
        assert_eq!(top_level_unknown.rule_count, 0);
        assert_eq!(top_level_unknown.status, CollectionStatus::Partial);
        assert_eq!(
            top_level_unknown.error_kind,
            Some(FirewallErrorKind::InvalidOutput)
        );
    }

    #[test]
    fn iptables_counts_duplicates_ignores_chains_and_rejects_unknown_rows() {
        let long_rule = format!(
            "-A INPUT -m comment --comment token=supersecret {} -j ACCEPT\n",
            "x".repeat(MAX_FIREWALL_RULE_CHARS * 2)
        );
        let mut duplicate_rules = String::from("-N CUSTOM\n");
        for _ in 0..40 {
            duplicate_rules.push_str(&long_rule);
        }
        let runner = FixtureFirewallCommandRunner::new(vec![
            firewall_step(
                "iptables",
                &["-S"],
                Ok(dns_command_output(true, duplicate_rules, "")),
            ),
            firewall_step("ip6tables", &["-S"], Ok(dns_command_output(true, "", ""))),
            firewall_step(
                "iptables",
                &["-S"],
                Ok(dns_command_output(
                    true,
                    "-N CUSTOM\n-P INPUT DROP\n-X CUSTOM\n",
                    "",
                )),
            ),
            firewall_step("ip6tables", &["-S"], Ok(dns_command_output(true, "", ""))),
        ]);

        let duplicates = collect_iptables_status(&runner);
        assert_eq!(duplicates.status, CollectionStatus::Complete);
        assert!(duplicates.active);
        assert!(!duplicates.truncated);
        assert_eq!(duplicates.rule_count, 40);
        assert_eq!(duplicates.rules_sample.len(), MAX_FIREWALL_RULE_SAMPLES);
        assert_eq!(
            duplicates.omitted_rule_count,
            duplicates.rule_count - duplicates.rules_sample.len()
        );
        assert!(duplicates.rules_sample.iter().all(|rule| {
            rule.starts_with("iptables: -A INPUT")
                && rule.chars().count() <= MAX_FIREWALL_RULE_CHARS
        }));
        let rendered = duplicates.rules_sample.join("\n");
        assert!(rendered.contains("token=[REDACTED]"));
        assert!(!rendered.contains("supersecret"));

        let unknown = collect_iptables_status(&runner);
        runner.assert_finished();
        assert_eq!(unknown.status, CollectionStatus::Partial);
        assert_eq!(unknown.error_kind, Some(FirewallErrorKind::InvalidOutput));
        assert_eq!(unknown.rule_count, 1);
        assert_eq!(unknown.rules_sample, ["iptables: -P INPUT DROP"]);
    }

    #[test]
    fn firewall_failures_are_classified_and_isolated_by_backend() {
        let permission = dns_command_output(false, "", "Operation not permitted");
        let mut timed_out = dns_command_output(false, "", "late");
        timed_out.exit_code = None;
        timed_out.timed_out = true;
        let runner = FixtureFirewallCommandRunner::new(vec![
            firewall_step("firewall-cmd", &["--state"], Err(ErrorKind::NotFound)),
            firewall_step("nft", &["list", "ruleset"], Ok(permission)),
            firewall_step("iptables", &["-S"], Ok(timed_out)),
            firewall_step(
                "ip6tables",
                &["-S"],
                Ok(dns_command_output(
                    true,
                    "-P INPUT DROP\n-A INPUT -p ipv6-icmp -j ACCEPT\n",
                    "",
                )),
            ),
        ]);

        let statuses = collect_firewall_status(&runner);
        runner.assert_finished();
        assert_eq!(statuses[0].status, CollectionStatus::Failed);
        assert!(!statuses[0].available);
        assert_eq!(
            statuses[0].error_kind,
            Some(FirewallErrorKind::CommandNotFound)
        );
        assert_eq!(statuses[1].status, CollectionStatus::Failed);
        assert!(statuses[1].available);
        assert_eq!(
            statuses[1].error_kind,
            Some(FirewallErrorKind::PermissionDenied)
        );
        assert_eq!(statuses[2].status, CollectionStatus::Partial);
        assert!(statuses[2].available);
        assert!(statuses[2].active);
        assert!(statuses[2].timed_out);
        assert_eq!(statuses[2].error_kind, Some(FirewallErrorKind::TimedOut));
        assert_eq!(statuses[2].rule_count, 2);
    }

    #[test]
    fn firewall_output_is_redacted_and_hard_bounded() {
        let mut output = String::from("table inet filter {\n  chain input {\n");
        output.push_str(&format!(
            "    tcp dport 443 token=supersecret {} \u{fffd} accept\n",
            "x".repeat(MAX_FIREWALL_RULE_CHARS * 2)
        ));
        for index in 1..=MAX_FIREWALL_OUTPUT_LINES + 10 {
            output.push_str(&format!(
                "    tcp dport {} accept\n",
                10_000usize.saturating_add(index)
            ));
        }
        output.push_str("  }\n}\n");
        let mut command_output = dns_command_output(true, output, "");
        command_output.stdout_truncated = true;
        let runner = FixtureFirewallCommandRunner::new(vec![firewall_step(
            "nft",
            &["list", "ruleset"],
            Ok(command_output),
        )]);

        let status = collect_nftables_status(&runner);
        runner.assert_finished();
        assert_eq!(status.status, CollectionStatus::Partial);
        assert_eq!(status.error_kind, Some(FirewallErrorKind::InvalidOutput));
        assert!(status.truncated);
        assert_eq!(status.rule_count, MAX_FIREWALL_OUTPUT_LINES - 2);
        assert_eq!(status.rules_sample.len(), MAX_FIREWALL_RULE_SAMPLES);
        assert_eq!(
            status.omitted_rule_count,
            status.rule_count - status.rules_sample.len()
        );
        assert!(status
            .rules_sample
            .iter()
            .all(|rule| rule.chars().count() <= MAX_FIREWALL_RULE_CHARS));
        let rendered = status.rules_sample.join("\n");
        assert!(rendered.contains("token=[REDACTED]"));
        assert!(!rendered.contains("supersecret"));
    }

    #[test]
    fn firewall_legacy_json_defaults_structured_fields() {
        struct LegacyCase {
            name: &'static str,
            backend: &'static str,
            available: bool,
            legacy_status: &'static str,
            rules_sample: &'static [&'static str],
            input_truncated: bool,
            expected_status: CollectionStatus,
            active: bool,
            truncated: bool,
            timed_out: bool,
            error_kind: Option<FirewallErrorKind>,
            error: Option<&'static str>,
        }

        let cases = [
            LegacyCase {
                name: "running",
                backend: "firewalld",
                available: true,
                legacy_status: "running",
                rules_sample: &["legacy rule"],
                input_truncated: true,
                expected_status: CollectionStatus::Complete,
                active: true,
                truncated: false,
                timed_out: false,
                error_kind: None,
                error: None,
            },
            LegacyCase {
                name: "not running",
                backend: "firewalld",
                available: true,
                legacy_status: "not running",
                rules_sample: &["legacy rule"],
                input_truncated: true,
                expected_status: CollectionStatus::Complete,
                active: false,
                truncated: false,
                timed_out: false,
                error_kind: Some(FirewallErrorKind::NotRunning),
                error: Some("firewalld is not running"),
            },
            LegacyCase {
                name: "timed out",
                backend: "nftables",
                available: true,
                legacy_status: "timed out",
                rules_sample: &["legacy partial rule"],
                input_truncated: true,
                expected_status: CollectionStatus::Failed,
                active: false,
                truncated: false,
                timed_out: true,
                error_kind: Some(FirewallErrorKind::TimedOut),
                error: Some("firewall command timed out"),
            },
            LegacyCase {
                name: "truncated output with rules",
                backend: "iptables",
                available: true,
                legacy_status: "ok(output truncated)",
                rules_sample: &["-P INPUT ACCEPT", "-A INPUT -j ACCEPT"],
                input_truncated: false,
                expected_status: CollectionStatus::Partial,
                active: true,
                truncated: true,
                timed_out: false,
                error_kind: None,
                error: None,
            },
            LegacyCase {
                name: "failed permission denied",
                backend: "iptables",
                available: true,
                legacy_status: "failed: Permission denied",
                rules_sample: &["legacy partial rule"],
                input_truncated: true,
                expected_status: CollectionStatus::Failed,
                active: false,
                truncated: false,
                timed_out: false,
                error_kind: Some(FirewallErrorKind::PermissionDenied),
                error: Some("failed: Permission denied"),
            },
            LegacyCase {
                name: "legacy nft first output line",
                backend: "nftables",
                available: true,
                legacy_status: "table inet filter {",
                rules_sample: &["table inet filter {", "  chain input {"],
                input_truncated: false,
                expected_status: CollectionStatus::Complete,
                active: true,
                truncated: false,
                timed_out: false,
                error_kind: None,
                error: None,
            },
            LegacyCase {
                name: "legacy iptables first output line",
                backend: "iptables",
                available: true,
                legacy_status: "-P INPUT ACCEPT",
                rules_sample: &["-P INPUT ACCEPT", "-A INPUT -j ACCEPT"],
                input_truncated: false,
                expected_status: CollectionStatus::Complete,
                active: true,
                truncated: false,
                timed_out: false,
                error_kind: None,
                error: None,
            },
            LegacyCase {
                name: "legacy nft truncated field",
                backend: "nftables",
                available: true,
                legacy_status: "table inet filter {",
                rules_sample: &["table inet filter {", "  chain input {"],
                input_truncated: true,
                expected_status: CollectionStatus::Partial,
                active: true,
                truncated: true,
                timed_out: false,
                error_kind: None,
                error: None,
            },
            LegacyCase {
                name: "legacy empty successful output",
                backend: "iptables",
                available: true,
                legacy_status: "ok",
                rules_sample: &[],
                input_truncated: false,
                expected_status: CollectionStatus::Complete,
                active: false,
                truncated: false,
                timed_out: false,
                error_kind: Some(FirewallErrorKind::EmptyRules),
                error: None,
            },
            LegacyCase {
                name: "legacy command not found",
                backend: "nftables",
                available: false,
                legacy_status: "No such file or directory",
                rules_sample: &[],
                input_truncated: false,
                expected_status: CollectionStatus::Failed,
                active: false,
                truncated: false,
                timed_out: false,
                error_kind: Some(FirewallErrorKind::CommandNotFound),
                error: Some("No such file or directory"),
            },
            LegacyCase {
                name: "legacy prefixed command not found",
                backend: "nftables",
                available: false,
                legacy_status: "failed: cannot find nft executable",
                rules_sample: &[],
                input_truncated: false,
                expected_status: CollectionStatus::Failed,
                active: false,
                truncated: false,
                timed_out: false,
                error_kind: Some(FirewallErrorKind::CommandNotFound),
                error: Some("failed: cannot find nft executable"),
            },
            LegacyCase {
                name: "legacy unavailable permission denied",
                backend: "iptables",
                available: false,
                legacy_status: "Permission denied while starting command",
                rules_sample: &[],
                input_truncated: false,
                expected_status: CollectionStatus::Failed,
                active: false,
                truncated: false,
                timed_out: false,
                error_kind: Some(FirewallErrorKind::PermissionDenied),
                error: Some("Permission denied while starting command"),
            },
            LegacyCase {
                name: "legacy unavailable command failure",
                backend: "iptables",
                available: false,
                legacy_status: "unable to launch firewall helper",
                rules_sample: &[],
                input_truncated: false,
                expected_status: CollectionStatus::Failed,
                active: false,
                truncated: false,
                timed_out: false,
                error_kind: Some(FirewallErrorKind::CommandFailed),
                error: Some("unable to launch firewall helper"),
            },
        ];
        for case in cases {
            let legacy: FirewallStatus = serde_json::from_value(serde_json::json!({
                "backend": case.backend,
                "available": case.available,
                "active": false,
                "status": case.legacy_status,
                "rule_count": 0,
                "rules_sample": case.rules_sample,
                "truncated": case.input_truncated,
                "omitted_rule_count": 0,
                "timed_out": false,
                "error": "stale error",
                "error_kind": "command_failed"
            }))
            .expect("legacy firewall status");
            assert_eq!(legacy.status, case.expected_status, "{}", case.name);
            assert_eq!(legacy.active, case.active, "{}", case.name);
            assert_eq!(legacy.truncated, case.truncated, "{}", case.name);
            assert_eq!(legacy.timed_out, case.timed_out, "{}", case.name);
            assert_eq!(legacy.error_kind, case.error_kind, "{}", case.name);
            assert_eq!(legacy.error.as_deref(), case.error, "{}", case.name);
            assert!(
                legacy.rule_count >= legacy.rules_sample.len(),
                "{}",
                case.name
            );
            assert!(
                legacy.omitted_rule_count
                    >= legacy.rule_count.saturating_sub(legacy.rules_sample.len()),
                "{}",
                case.name
            );
            if case.rules_sample.is_empty() && case.available {
                assert_eq!(legacy.rule_count, 0, "{}", case.name);
            }
            if legacy.status == CollectionStatus::Failed {
                assert!(!legacy.active, "{}", case.name);
            }
        }

        let long_error = format!("legacy launch failure: {}", "x".repeat(512));
        let unavailable: FirewallStatus = serde_json::from_value(serde_json::json!({
            "available": false,
            "status": long_error,
        }))
        .expect("bounded legacy firewall error");
        let error = unavailable.error.expect("legacy error text");
        assert_eq!(unavailable.status, CollectionStatus::Failed);
        assert_eq!(
            unavailable.error_kind,
            Some(FirewallErrorKind::CommandFailed)
        );
        assert_eq!(error.chars().count(), MAX_NETWORK_ERROR_CHARS);
        assert!(long_error.starts_with(&error));

        let normalized_structured: FirewallStatus = serde_json::from_value(serde_json::json!({
            "available": true,
            "active": true,
            "status": "failed",
            "rule_count": 5,
            "rules_sample": ["rule one", "rule two"],
            "omitted_rule_count": 0,
        }))
        .expect("normalize structured firewall status");
        assert!(!normalized_structured.active);
        assert_eq!(normalized_structured.rule_count, 5);
        assert_eq!(normalized_structured.omitted_rule_count, 3);

        let structured = FirewallStatus {
            backend: "nftables".to_string(),
            available: true,
            active: true,
            status: CollectionStatus::Partial,
            command: Some("nft".to_string()),
            args: vec!["list".to_string(), "ruleset".to_string()],
            source: "nft list ruleset".to_string(),
            rule_count: 7,
            rules_sample: vec!["policy drop".to_string()],
            truncated: false,
            omitted_rule_count: 6,
            exit_code: Some(0),
            timed_out: true,
            error: Some("structured error".to_string()),
            error_kind: Some(FirewallErrorKind::CommandFailed),
        };
        let round_trip: FirewallStatus = serde_json::from_value(
            serde_json::to_value(&structured).expect("serialize structured firewall status"),
        )
        .expect("deserialize structured firewall status");
        assert_eq!(round_trip, structured);
    }

    #[test]
    fn include_firewall_false_executes_no_firewall_commands() {
        let reader = FixtureNetworkFileReader::complete();
        let resolver = FixtureDnsResolver::new(resolved_fixture(&[]));
        let clock = FixtureProbeClock::default();
        let connector = FixtureTcpConnector::new(&clock, Vec::new());
        let firewall_runner = FixtureFirewallCommandRunner::new(Vec::new());
        let snapshot = collect_network_with_components(
            &NetworkQuery::default(),
            &reader,
            None,
            &resolver,
            &connector,
            &clock,
            &firewall_runner,
        )
        .expect("network snapshot without firewall");
        assert!(snapshot.firewall.is_empty());
        assert!(firewall_runner.calls.borrow().is_empty());
        firewall_runner.assert_finished();
    }

    #[test]
    fn included_firewall_failures_and_partial_results_degrade_snapshot_status() {
        let query = NetworkQuery {
            include_firewall: true,
            ..NetworkQuery::default()
        };

        let reader = FixtureNetworkFileReader::complete();
        let resolver = FixtureDnsResolver::new(resolved_fixture(&[]));
        let clock = FixtureProbeClock::default();
        let connector = FixtureTcpConnector::new(&clock, Vec::new());
        let all_failed_runner = FixtureFirewallCommandRunner::new(vec![
            firewall_step("firewall-cmd", &["--state"], Err(ErrorKind::NotFound)),
            firewall_step("nft", &["list", "ruleset"], Err(ErrorKind::NotFound)),
            firewall_step("iptables", &["-S"], Err(ErrorKind::NotFound)),
            firewall_step("ip6tables", &["-S"], Err(ErrorKind::NotFound)),
        ]);
        let all_failed = collect_network_with_components(
            &query,
            &reader,
            None,
            &resolver,
            &connector,
            &clock,
            &all_failed_runner,
        )
        .expect("snapshot with failed firewall backends");
        all_failed_runner.assert_finished();
        assert_eq!(all_failed.collection_status, CollectionStatus::Partial);
        assert!(all_failed
            .firewall
            .iter()
            .all(|status| status.status == CollectionStatus::Failed));

        let reader = FixtureNetworkFileReader::complete();
        let resolver = FixtureDnsResolver::new(resolved_fixture(&[]));
        let clock = FixtureProbeClock::default();
        let connector = FixtureTcpConnector::new(&clock, Vec::new());
        let mut inactive = dns_command_output(false, "not running\n", "");
        inactive.exit_code = Some(252);
        let one_partial_runner = FixtureFirewallCommandRunner::new(vec![
            firewall_step("firewall-cmd", &["--state"], Ok(inactive)),
            firewall_step(
                "nft",
                &["list", "ruleset"],
                Ok(dns_command_output(
                    true,
                    "table inet filter {\n  chain input {\n  }\n",
                    "",
                )),
            ),
            firewall_step("iptables", &["-S"], Ok(dns_command_output(true, "", ""))),
            firewall_step("ip6tables", &["-S"], Ok(dns_command_output(true, "", ""))),
        ]);
        let one_partial = collect_network_with_components(
            &query,
            &reader,
            None,
            &resolver,
            &connector,
            &clock,
            &one_partial_runner,
        )
        .expect("snapshot with one partial firewall backend");
        one_partial_runner.assert_finished();
        assert_eq!(one_partial.collection_status, CollectionStatus::Partial);
        assert_eq!(one_partial.firewall[0].status, CollectionStatus::Complete);
        assert_eq!(one_partial.firewall[1].status, CollectionStatus::Partial);
        assert_eq!(one_partial.firewall[2].status, CollectionStatus::Complete);

        let reader = FixtureNetworkFileReader::default()
            .with_text(RESOLV_CONF_PATH, "nameserver 127.0.0.53\n");
        let resolver = FixtureDnsResolver::new(resolved_fixture(&[]));
        let clock = FixtureProbeClock::default();
        let connector = FixtureTcpConnector::new(&clock, Vec::new());
        let failed_source_runner = FixtureFirewallCommandRunner::new(vec![
            firewall_step("firewall-cmd", &["--state"], Err(ErrorKind::NotFound)),
            firewall_step("nft", &["list", "ruleset"], Err(ErrorKind::NotFound)),
            firewall_step("iptables", &["-S"], Err(ErrorKind::NotFound)),
            firewall_step("ip6tables", &["-S"], Err(ErrorKind::NotFound)),
        ]);
        let failed_source = collect_network_with_components(
            &query,
            &reader,
            None,
            &resolver,
            &connector,
            &clock,
            &failed_source_runner,
        )
        .expect("failed socket collection remains failed");
        failed_source_runner.assert_finished();
        assert_eq!(failed_source.collection_status, CollectionStatus::Failed);
    }

    #[test]
    fn resolv_conf_parses_comments_duplicates_and_supported_directives() {
        let status = parse_resolv_conf(
            br#"
                # generated resolver configuration
                nameserver 10.0.0.53
                nameserver 10.0.0.53 # duplicate
                nameserver 2001:db8::53 ; IPv6
                search Example.COM corp.local example.com
                options ndots:5 timeout:1 rotate ndots:5
                sortlist 10.0.0.0/8
            "#,
            false,
        );
        assert_eq!(status.status, CollectionStatus::Complete);
        assert_eq!(status.nameservers, ["10.0.0.53", "2001:db8::53"]);
        assert_eq!(status.search_domains, ["example.com", "corp.local"]);
        assert_eq!(status.options, ["ndots:5", "timeout:1", "rotate"]);
        assert_eq!(status.parse_failure_count, 0);
        assert!(!status.truncated);
    }

    #[test]
    fn resolv_conf_reports_malformed_missing_and_bounded_inputs() {
        let malformed = parse_resolv_conf(
            b"nameserver 10.0.0.53\nnameserver invalid\nsearch ok.local bad_label\noptions ndots:5 --bad\n",
            false,
        );
        assert_eq!(malformed.status, CollectionStatus::Partial);
        assert_eq!(malformed.nameservers, ["10.0.0.53"]);
        assert_eq!(malformed.search_domains, ["ok.local"]);
        assert_eq!(malformed.options, ["ndots:5"]);
        assert_eq!(malformed.parse_failure_count, 3);

        let mut warnings = Vec::new();
        let mut omitted_warnings = 0;
        let missing = collect_dns_resolver_status(
            &FixtureNetworkFileReader::default(),
            &mut warnings,
            &mut omitted_warnings,
        );
        assert_eq!(missing.status, CollectionStatus::Failed);
        assert!(!missing.available);
        assert_eq!(missing.actual_path, RESOLV_CONF_PATH);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].chars().count() <= MAX_NETWORK_ERROR_CHARS);

        let mut content = String::new();
        for index in 1..=10 {
            content.push_str(&format!("nameserver 10.0.0.{index}\n"));
        }
        content.push_str("search a.example b.example c.example d.example e.example f.example g.example h.example\n");
        content
            .push_str("options o1 o2 o3 o4 o5 o6 o7 o8 o9 o10 o11 o12 o13 o14 o15 o16 o17 o18\n");
        while content.len() <= MAX_RESOLV_CONF_BYTES + 100 {
            content.push_str("# bounded padding\n");
        }
        let reader = FixtureNetworkFileReader::default().with_text(RESOLV_CONF_PATH, content);
        let bounded = collect_dns_resolver_status(&reader, &mut Vec::new(), &mut 0);
        assert_eq!(bounded.status, CollectionStatus::Partial);
        assert!(bounded.truncated);
        assert_eq!(bounded.nameservers.len(), MAX_RESOLV_NAMESERVERS);
        assert_eq!(bounded.omitted_nameserver_count, 7);
        assert_eq!(bounded.search_domains.len(), MAX_RESOLV_SEARCH_DOMAINS);
        assert_eq!(bounded.omitted_search_domain_count, 2);
        assert_eq!(bounded.options.len(), MAX_RESOLV_OPTIONS);
        assert_eq!(bounded.omitted_option_count, 2);
    }

    #[test]
    fn getent_resolution_is_fixed_deduplicated_dual_stack_and_bounded() {
        let stdout = concat!(
            "198.51.100.1 STREAM example.com\n",
            "198.51.100.1 DGRAM example.com\n",
            "2001:db8::1 STREAM example.com\n",
            "198.51.100.2 STREAM example.com\n",
            "2001:db8::2 STREAM example.com\n",
            "198.51.100.3 STREAM example.com\n",
            "2001:db8::3 STREAM example.com\n",
            "198.51.100.4 STREAM example.com\n",
            "2001:db8::4 STREAM example.com\n",
            "198.51.100.5 STREAM example.com\n",
            "2001:db8::5 STREAM example.com\n",
        );
        let runner = FixtureDnsCommandRunner::output(dns_command_output(true, stdout, ""));
        let result = resolve_dns_with_runner("example.com", Duration::from_secs(9), &runner);
        assert_eq!(result.status, DnsResolutionStatus::Partial);
        assert_eq!(result.addresses.len(), MAX_DNS_ADDRESSES);
        assert_eq!(result.omitted_address_count, 2);
        assert_eq!(
            result.addresses[..4],
            [
                "198.51.100.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap(),
                "198.51.100.2".parse::<IpAddr>().unwrap(),
                "2001:db8::2".parse::<IpAddr>().unwrap(),
            ]
        );
        let calls = runner.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].program, "getent");
        assert_eq!(calls[0].args, ["ahosts", "example.com"]);
        assert_eq!(calls[0].timeout, DNS_RESOLUTION_TIMEOUT);
        assert_eq!(calls[0].stdout_limit, MAX_DNS_COMMAND_STDOUT_BYTES);
        assert_eq!(calls[0].stderr_limit, MAX_DNS_COMMAND_STDERR_BYTES);
    }

    #[test]
    fn getent_resolution_classifies_empty_timeout_failure_and_malformed_output() {
        let empty = FixtureDnsCommandRunner::output(dns_command_output(true, "", ""));
        assert_eq!(
            resolve_dns_with_runner("empty.example", DNS_RESOLUTION_TIMEOUT, &empty).status,
            DnsResolutionStatus::NoAddresses
        );

        let mut timed_out_output = dns_command_output(false, "", "late");
        timed_out_output.timed_out = true;
        timed_out_output.exit_code = Some(2);
        let timed_out = FixtureDnsCommandRunner::output(timed_out_output);
        assert_eq!(
            resolve_dns_with_runner("slow.example", DNS_RESOLUTION_TIMEOUT, &timed_out).status,
            DnsResolutionStatus::TimedOut
        );

        let mut not_found_output =
            dns_command_output(false, "not-an-ip STREAM missing.example\n", "");
        not_found_output.exit_code = Some(2);
        not_found_output.stdout_truncated = true;
        let not_found = FixtureDnsCommandRunner::output(not_found_output);
        let not_found =
            resolve_dns_with_runner("missing.example", DNS_RESOLUTION_TIMEOUT, &not_found);
        assert_eq!(not_found.status, DnsResolutionStatus::NoAddresses);
        assert_eq!(not_found.parse_failure_count, 1);
        assert!(not_found.truncated);

        let failed = FixtureDnsCommandRunner::output(dns_command_output(
            false,
            "",
            "x".repeat(MAX_NETWORK_ERROR_CHARS * 2),
        ));
        let failed = resolve_dns_with_runner("failed.example", DNS_RESOLUTION_TIMEOUT, &failed);
        assert_eq!(failed.status, DnsResolutionStatus::CommandFailed);
        assert!(failed.error.unwrap().chars().count() <= MAX_NETWORK_ERROR_CHARS);

        let malformed = FixtureDnsCommandRunner::output(dns_command_output(
            true,
            "not-an-ip STREAM bad.example\n10.0.0.1 UNKNOWN bad.example\n",
            "",
        ));
        let malformed = resolve_dns_with_runner("bad.example", DNS_RESOLUTION_TIMEOUT, &malformed);
        assert_eq!(malformed.status, DnsResolutionStatus::InvalidOutput);
        assert_eq!(malformed.parse_failure_count, 2);

        let unavailable = FixtureDnsCommandRunner::error(ErrorKind::NotFound);
        assert_eq!(
            resolve_dns_with_runner("missing.example", DNS_RESOLUTION_TIMEOUT, &unavailable).status,
            DnsResolutionStatus::ResolverUnavailable
        );
    }

    #[test]
    fn public_dns_lookup_is_allowed_but_tcp_policy_checks_resolved_addresses() {
        let resolution = resolved_fixture(&["93.184.216.34"]);
        let resolver = FixtureDnsResolver::new(resolution);
        let check = resolve_dns("example.com", &resolver);
        assert!(check.ok);
        assert_eq!(check.status, DnsResolutionStatus::Resolved);
        assert_eq!(check.resolved_addrs, ["93.184.216.34"]);

        let clock = FixtureProbeClock::default();
        let connector = FixtureTcpConnector::new(&clock, Vec::new());
        for host in ["example.com", "printer.local"] {
            let result = probe_tcp_with(
                &TcpProbeRequest {
                    host: host.to_string(),
                    port: 443,
                    timeout_ms: Some(1_000),
                },
                &resolver,
                &connector,
                &clock,
            );
            assert_eq!(result.status, TcpProbeStatus::PolicyDenied);
            assert_eq!(result.stage, TcpProbeStage::Policy);
            assert_eq!(result.resolved_addrs, ["93.184.216.34"]);
            assert!(result.attempted_addrs.is_empty());
        }
        assert!(connector.attempts.borrow().is_empty());
    }

    #[test]
    fn tcp_probe_policy_rejects_unspecified_and_zero_network_addresses() {
        for address in ["0.0.0.0", "0.1.2.3", "::"] {
            assert!(!probe_ip_allowed(address.parse().unwrap()), "{address}");
        }
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(probe_ip_allowed(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn tcp_probe_ip_literal_skips_dns_and_multi_address_probe_shares_deadline() {
        let clock = FixtureProbeClock::default();
        let unused_resolver = FixtureDnsResolver::new(resolved_fixture(&["93.184.216.34"]));
        let literal_connector = FixtureTcpConnector::new(
            &clock,
            vec![FixtureConnectStep {
                address: "10.0.0.5".parse().unwrap(),
                elapsed: Duration::from_millis(20),
                result: FixtureConnectResult::Success,
            }],
        );
        let literal = probe_tcp_with(
            &TcpProbeRequest {
                host: "10.0.0.5".to_string(),
                port: 22,
                timeout_ms: Some(1_000),
            },
            &unused_resolver,
            &literal_connector,
            &clock,
        );
        assert!(literal.ok);
        assert_eq!(literal.resolution_source, DnsResolutionSource::IpLiteral);
        assert_eq!(unused_resolver.calls.get(), 0);

        let clock = FixtureProbeClock::default();
        let resolver = FixtureDnsResolver::new(resolved_fixture(&["10.0.0.1", "fd00::1"]))
            .with_elapsed(&clock, Duration::from_millis(200));
        let connector = FixtureTcpConnector::new(
            &clock,
            vec![
                FixtureConnectStep {
                    address: "10.0.0.1".parse().unwrap(),
                    elapsed: Duration::from_millis(400),
                    result: FixtureConnectResult::Failed(ErrorKind::TimedOut),
                },
                FixtureConnectStep {
                    address: "fd00::1".parse().unwrap(),
                    elapsed: Duration::from_millis(100),
                    result: FixtureConnectResult::Success,
                },
            ],
        );
        let result = probe_tcp_with(
            &TcpProbeRequest {
                host: "service.local".to_string(),
                port: 8443,
                timeout_ms: Some(1_000),
            },
            &resolver,
            &connector,
            &clock,
        );
        assert!(result.ok);
        assert_eq!(result.attempted_addrs, ["10.0.0.1", "fd00::1"]);
        assert_eq!(result.selected_addr.as_deref(), Some("fd00::1"));
        assert_eq!(result.latency_ms, Some(700));
        assert!(result.latency_ms.unwrap() <= 1_000);
        assert_eq!(
            resolver.timeouts.borrow().as_slice(),
            [Duration::from_secs(1)]
        );
        let attempts = connector.attempts.borrow();
        assert_eq!(attempts[0].1, Duration::from_millis(400));
        assert_eq!(attempts[1].1, Duration::from_millis(400));
    }

    #[test]
    fn tcp_probe_slices_deadline_after_ipv6_timeout_before_ipv4_success() {
        let clock = FixtureProbeClock::default();
        let resolver = FixtureDnsResolver::new(resolved_fixture(&["fd00::1", "10.0.0.1"]))
            .with_elapsed(&clock, Duration::from_millis(200));
        let connector = FixtureTcpConnector::new(
            &clock,
            vec![
                FixtureConnectStep {
                    address: "fd00::1".parse().unwrap(),
                    elapsed: Duration::from_millis(400),
                    result: FixtureConnectResult::Failed(ErrorKind::TimedOut),
                },
                FixtureConnectStep {
                    address: "10.0.0.1".parse().unwrap(),
                    elapsed: Duration::from_millis(50),
                    result: FixtureConnectResult::Success,
                },
            ],
        );
        let result = probe_tcp_with(
            &TcpProbeRequest {
                host: "service.local".to_string(),
                port: 8443,
                timeout_ms: Some(1_000),
            },
            &resolver,
            &connector,
            &clock,
        );
        assert!(result.ok);
        assert_eq!(result.attempted_addrs, ["fd00::1", "10.0.0.1"]);
        assert_eq!(result.selected_addr.as_deref(), Some("10.0.0.1"));
        assert_eq!(result.latency_ms, Some(650));
        assert!(result.latency_ms.unwrap() <= 1_000);
        let attempts = connector.attempts.borrow();
        assert_eq!(attempts[0].1, Duration::from_millis(400));
        assert_eq!(attempts[1].1, Duration::from_millis(400));
    }

    #[test]
    fn tcp_probe_stops_when_the_shared_deadline_is_exhausted() {
        let clock = FixtureProbeClock::default();
        let resolver = FixtureDnsResolver::new(resolved_fixture(&["10.0.0.1", "10.0.0.2"]))
            .with_elapsed(&clock, Duration::from_millis(200));
        let connector = FixtureTcpConnector::new(
            &clock,
            vec![
                FixtureConnectStep {
                    address: "10.0.0.1".parse().unwrap(),
                    elapsed: Duration::from_millis(400),
                    result: FixtureConnectResult::Failed(ErrorKind::TimedOut),
                },
                FixtureConnectStep {
                    address: "10.0.0.2".parse().unwrap(),
                    elapsed: Duration::from_millis(400),
                    result: FixtureConnectResult::Failed(ErrorKind::TimedOut),
                },
            ],
        );
        let result = probe_tcp_with(
            &TcpProbeRequest {
                host: "service.local".to_string(),
                port: 443,
                timeout_ms: Some(1_000),
            },
            &resolver,
            &connector,
            &clock,
        );
        assert_eq!(result.status, TcpProbeStatus::TimedOut);
        assert_eq!(result.error_kind, Some(TcpProbeErrorKind::DeadlineExceeded));
        assert_eq!(result.attempted_addrs, ["10.0.0.1", "10.0.0.2"]);
        let attempts = connector.attempts.borrow();
        assert_eq!(attempts.len(), 2);
        assert_eq!(attempts[0].1, Duration::from_millis(400));
        assert_eq!(attempts[1].1, Duration::from_millis(400));
        assert_eq!(result.latency_ms, Some(1_000));
    }

    #[test]
    fn dns_and_tcp_legacy_json_default_new_typed_fields() {
        let dns: DnsCheck = serde_json::from_value(serde_json::json!({
            "name": "legacy.local",
            "resolved_addrs": ["10.0.0.1"],
            "ok": true,
            "error": null
        }))
        .expect("legacy DNS check");
        assert_eq!(dns.status, DnsResolutionStatus::Unknown);
        assert_eq!(dns.source, DnsResolutionSource::Unknown);
        assert_eq!(dns.latency_ms, None);
        assert!(!dns.truncated);

        let probe: HealthProbeResult = serde_json::from_value(serde_json::json!({
            "target": "10.0.0.1:22",
            "ok": true,
            "latency_ms": 1,
            "error": null
        }))
        .expect("legacy TCP probe");
        assert_eq!(probe.status, TcpProbeStatus::Unknown);
        assert_eq!(probe.stage, TcpProbeStage::Unknown);
        assert!(probe.resolved_addrs.is_empty());
        assert!(probe.attempted_addrs.is_empty());
    }

    #[test]
    fn dns_target_validation_accepts_public_names_and_rejects_unsafe_or_malformed_values() {
        for value in [
            "example.com",
            "example.com.",
            "localhost",
            "printer.local",
            "8.8.8.8",
            "2001:db8::1",
        ] {
            assert!(validate_dns_target("target", value).is_ok(), "{value}");
        }
        for value in [
            "",
            " example.com",
            "example.com\n",
            "--help",
            "singlelabel",
            "bad..example",
            "-bad.example",
            "bad-.example",
            "bad_label.example",
            "999.999.999.999",
        ] {
            assert!(validate_dns_target("target", value).is_err(), "{value}");
        }

        let valid = NetworkQuery {
            dns_names: vec!["example.com".to_string(); MAX_DNS_CHECKS],
            tcp_probes: vec![
                TcpProbeRequest {
                    host: "service.local".to_string(),
                    port: 443,
                    timeout_ms: Some(MAX_PROBE_TIMEOUT_MS),
                };
                MAX_TCP_PROBES
            ],
            ..NetworkQuery::default()
        };
        assert!(valid.validate().is_ok());
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
        assert_eq!(snapshot.dns_resolver.status, CollectionStatus::Complete);
        assert_eq!(snapshot.dns_resolver.nameservers, ["127.0.0.53"]);
        assert!(snapshot.dns_checks.is_empty());
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
        assert_eq!(snapshot.dns_resolver, DnsResolverStatus::default());
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
