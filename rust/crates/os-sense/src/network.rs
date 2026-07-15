use std::fs;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::command::run_limited_command;
use crate::model::{
    DnsCheck, FirewallStatus, HealthProbeResult, NetworkAnomaly, NetworkConnection, NetworkSnapshot,
};
use crate::procfs::basic_meta;

const DEFAULT_CONNECTION_LIMIT: usize = 200;
const MAX_CONNECTION_LIMIT: usize = 1000;
const MAX_DNS_CHECKS: usize = 8;
const MAX_TCP_PROBES: usize = 5;
const MAX_PROBE_TIMEOUT_MS: u64 = 3_000;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

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

#[must_use]
pub fn collect_network(query: &NetworkQuery) -> NetworkSnapshot {
    let mut warnings = Vec::new();
    let mut connections = collect_proc_net_connections(&mut warnings);
    connections = filter_connections(connections, query);
    let connection_limit = query
        .limit
        .unwrap_or(DEFAULT_CONNECTION_LIMIT)
        .clamp(1, MAX_CONNECTION_LIMIT);
    let mut truncated = connections.len() > connection_limit;
    connections.truncate(connection_limit);
    if query.dns_names.len() > MAX_DNS_CHECKS {
        truncated = true;
        warnings.push(format!("dns_names truncated to {MAX_DNS_CHECKS} entries"));
    }
    if query.tcp_probes.len() > MAX_TCP_PROBES {
        truncated = true;
        warnings.push(format!("tcp_probes truncated to {MAX_TCP_PROBES} entries"));
    }

    let dns_checks = query
        .dns_names
        .iter()
        .take(MAX_DNS_CHECKS)
        .map(|name| resolve_dns(name))
        .collect::<Vec<_>>();
    let tcp_probes = query
        .tcp_probes
        .iter()
        .take(MAX_TCP_PROBES)
        .map(probe_tcp)
        .collect::<Vec<_>>();
    let firewall = if query.include_firewall {
        collect_firewall_status()
    } else {
        Vec::new()
    };
    let anomalies = detect_network_anomalies(&connections);

    NetworkSnapshot {
        meta: basic_meta("network", warnings),
        truncated,
        connections,
        dns_checks,
        tcp_probes,
        firewall,
        anomalies,
    }
}

#[must_use]
pub fn parse_proc_net(content: &str, protocol: &str) -> Vec<NetworkConnection> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| parse_proc_net_line(line, protocol))
        .collect()
}

fn collect_proc_net_connections(warnings: &mut Vec<String>) -> Vec<NetworkConnection> {
    let files = [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp6"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp6"),
    ];
    let mut out = Vec::new();
    for (path, protocol) in files {
        match fs::read_to_string(path) {
            Ok(content) => out.extend(parse_proc_net(&content, protocol)),
            Err(error) => warnings.push(format!("failed to read {path}: {error}")),
        }
    }
    out
}

fn parse_proc_net_line(line: &str, protocol: &str) -> Option<NetworkConnection> {
    let parts = line.split_whitespace().collect::<Vec<_>>();
    let local = *parts.get(1)?;
    let remote = *parts.get(2)?;
    let state = *parts.get(3)?;
    let inode = parts.get(9).map(|value| (*value).to_string());
    let (local_addr, local_port) = parse_endpoint(local)?;
    let (remote_addr, remote_port) = parse_endpoint(remote)?;
    Some(NetworkConnection {
        protocol: protocol.to_string(),
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state: tcp_state_name(state).to_string(),
        inode,
    })
}

fn parse_endpoint(value: &str) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = value.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = if addr_hex.len() == 8 {
        let raw = u32::from_str_radix(addr_hex, 16).ok()?;
        let bytes = raw.to_le_bytes();
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else {
        format!("ipv6:{addr_hex}")
    };
    Some((addr, port))
}

fn tcp_state_name(code: &str) -> &'static str {
    match code {
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
        _ => "UNKNOWN",
    }
}

fn filter_connections(
    connections: Vec<NetworkConnection>,
    query: &NetworkQuery,
) -> Vec<NetworkConnection> {
    connections
        .into_iter()
        .filter(|connection| {
            if let Some(protocol) = &query.protocol {
                if protocol != "all" && !connection.protocol.eq_ignore_ascii_case(protocol) {
                    return false;
                }
            }
            if let Some(state) = &query.state {
                if !connection.state.eq_ignore_ascii_case(state) {
                    return false;
                }
            }
            if let Some(remote) = &query.remote_contains {
                if !connection.remote_addr.contains(remote) {
                    return false;
                }
            }
            true
        })
        .collect()
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
        .filter(|connection| !is_private_or_local(&connection.remote_addr))
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
    if addr == "0.0.0.0"
        || addr == "127.0.0.1"
        || addr.starts_with("127.")
        || addr.starts_with("ipv6:")
    {
        return true;
    }
    if addr.starts_with("10.") || addr.starts_with("192.168.") {
        return true;
    }
    if let Some(second) = addr
        .strip_prefix("172.")
        .and_then(|rest| rest.split('.').next())
        .and_then(|value| value.parse::<u8>().ok())
    {
        return (16..=31).contains(&second);
    }
    false
}

#[allow(dead_code)]
fn socket_addr_to_string(addr: SocketAddr) -> String {
    addr.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_net_tcp_line() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 0200007F:01BB 01 00000000:00000000 00:00000000 00000000   100        0 12345 1 0000000000000000 100 0 0 10 0\n";
        let connections = parse_proc_net(content, "tcp");
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].local_addr, "127.0.0.1");
        assert_eq!(connections[0].local_port, 8080);
        assert_eq!(connections[0].remote_addr, "127.0.0.2");
        assert_eq!(connections[0].remote_port, 443);
        assert_eq!(connections[0].state, "ESTABLISHED");
        assert_eq!(connections[0].inode.as_deref(), Some("12345"));
    }

    #[test]
    fn detects_many_time_wait_connections() {
        let connections = (0..100)
            .map(|idx| NetworkConnection {
                protocol: "tcp".to_string(),
                local_addr: "127.0.0.1".to_string(),
                local_port: idx,
                remote_addr: "127.0.0.1".to_string(),
                remote_port: 80,
                state: "TIME_WAIT".to_string(),
                inode: None,
            })
            .collect::<Vec<_>>();
        let anomalies = detect_network_anomalies(&connections);
        assert!(anomalies.iter().any(|item| item.kind == "many_time_wait"));
    }
}
