#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use crate::model::{
    CollectionStatus, ServicePortBinding, ServicePortCollection, ServicePortOwnershipStatus,
    ServicePortProtocol,
};
use crate::network::parse_proc_net_bytes;
use crate::redaction::redact_sensitive_text;

const PROC_NET_FILES: [(&str, &str); 4] = [
    ("tcp", "tcp"),
    ("tcp6", "tcp6"),
    ("udp", "udp"),
    ("udp6", "udp6"),
];
const MAX_PROC_NET_BYTES: usize = 512 * 1024;
const MAX_PROC_NET_BYTES_TOTAL: usize = 8 * 1024 * 1024;
const MAX_SOCKET_RECORDS: usize = 4_096;
const MAX_NETWORK_NAMESPACES: usize = 128;
const MAX_PIDS: usize = 4_096;
const MAX_FDS_PER_PID: usize = 4_096;
const MAX_FDS_TOTAL: usize = 65_536;
const MAX_CGROUP_BYTES: usize = 16 * 1024;
const MAX_CGROUP_BYTES_TOTAL: usize = 4 * 1024 * 1024;
const MAX_FD_LINK_BYTES: usize = 4 * 1024;
const MAX_PIDS_PER_BINDING: usize = 64;
const MAX_SERVICES_PER_BINDING: usize = 64;
pub(crate) const MAX_PORT_BINDINGS_PER_SERVICE: usize = 128;
const MAX_UNOWNED_BINDING_DETAILS: usize = 128;
const MAX_PORT_ERROR_CHARS: usize = 256;

#[derive(Debug, Clone)]
pub(crate) struct CollectedServicePorts {
    pub(crate) services: BTreeMap<String, ServiceBindings>,
    pub(crate) all_binding_ids: BTreeSet<String>,
    pub(crate) collection: ServicePortCollection,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ServiceBindings {
    pub(crate) bindings: Vec<ServicePortBinding>,
    pub(crate) binding_ids: BTreeSet<String>,
    pub(crate) total: usize,
    pub(crate) complete: bool,
    pub(crate) ownership_status: ServicePortOwnershipStatus,
}

#[derive(Debug)]
struct BoundedBytes {
    bytes: Vec<u8>,
    truncated: bool,
}

#[derive(Debug)]
struct BoundedNames {
    names: Vec<String>,
    truncated: bool,
}

trait ServicePortReader {
    fn read_file(&self, path: &str, limit: usize) -> io::Result<BoundedBytes>;
    fn read_dir_names(&self, path: &str, limit: usize) -> io::Result<BoundedNames>;
    fn read_link(&self, path: &str) -> io::Result<String>;
}

struct ProcServicePortReader;

#[cfg(unix)]
impl ServicePortReader for ProcServicePortReader {
    fn read_file(&self, path: &str, limit: usize) -> io::Result<BoundedBytes> {
        use std::io::Read;

        let file = std::fs::File::open(path)?;
        let mut bytes = Vec::with_capacity(limit.min(64 * 1024).saturating_add(1));
        file.take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)?;
        let truncated = bytes.len() > limit;
        bytes.truncate(limit);
        Ok(BoundedBytes { bytes, truncated })
    }

    fn read_dir_names(&self, path: &str, limit: usize) -> io::Result<BoundedNames> {
        let mut names = Vec::new();
        let mut truncated = false;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if names.len() == limit {
                truncated = true;
                break;
            }
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(BoundedNames { names, truncated })
    }

    fn read_link(&self, path: &str) -> io::Result<String> {
        Ok(std::fs::read_link(path)?.to_string_lossy().into_owned())
    }
}

#[cfg(not(unix))]
impl ServicePortReader for ProcServicePortReader {
    fn read_file(&self, _path: &str, _limit: usize) -> io::Result<BoundedBytes> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "/proc is unavailable",
        ))
    }

    fn read_dir_names(&self, _path: &str, _limit: usize) -> io::Result<BoundedNames> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "/proc is unavailable",
        ))
    }

    fn read_link(&self, _path: &str) -> io::Result<String> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "/proc is unavailable",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SocketKey {
    network_namespace: u64,
    protocol: ServicePortProtocol,
    local_address: String,
    port: u16,
    inode: u64,
}

#[derive(Default)]
struct PortStats {
    truncated: bool,
    total_unknown: bool,
    parse_failures: usize,
    permission_denied: usize,
    disappeared: usize,
    scanned_pids: usize,
    scanned_fds: usize,
    duplicate_sockets: usize,
    scanned_namespaces: usize,
    omitted_namespaces: usize,
    namespace_total_unknown: bool,
    global_ownership_unknown: bool,
    first_error: Option<String>,
}

pub(crate) fn collect_service_ports() -> CollectedServicePorts {
    collect_service_ports_with(&ProcServicePortReader)
}

fn collect_service_ports_with(reader: &dyn ServicePortReader) -> CollectedServicePorts {
    #[cfg(not(unix))]
    {
        let _ = reader;
        return CollectedServicePorts {
            services: BTreeMap::new(),
            all_binding_ids: BTreeSet::new(),
            collection: ServicePortCollection {
                requested: true,
                available: false,
                status: CollectionStatus::Failed,
                complete: false,
                error: Some("service port ownership is unavailable on this platform".to_string()),
                ..ServicePortCollection::default()
            },
        };
    }

    #[cfg(unix)]
    {
        collect_service_ports_unix(reader)
    }
}

fn collect_service_ports_unix(reader: &dyn ServicePortReader) -> CollectedServicePorts {
    let mut stats = PortStats::default();
    let pids = match reader.read_dir_names("/proc", MAX_PIDS) {
        Ok(pids) => {
            stats.truncated |= pids.truncated;
            stats.total_unknown |= pids.truncated;
            stats.namespace_total_unknown |= pids.truncated;
            stats.global_ownership_unknown |= pids.truncated;
            pids.names
                .into_iter()
                .filter_map(|value| value.parse::<u32>().ok())
                .collect::<BTreeSet<_>>()
        }
        Err(error) => {
            record_io_error(&mut stats, &error, false);
            stats.namespace_total_unknown = true;
            stats.global_ownership_unknown = true;
            BTreeSet::new()
        }
    };
    stats.scanned_pids = pids.len();

    let mut pid_namespaces = BTreeMap::<u32, u64>::new();
    let mut namespace_sources = BTreeMap::<u64, String>::new();
    match reader.read_link("/proc/self/ns/net") {
        Ok(link) => match parse_network_namespace_link(&link) {
            Some(namespace) => {
                namespace_sources.insert(namespace, "/proc/net".to_string());
            }
            None => {
                stats.parse_failures = stats.parse_failures.saturating_add(1);
                stats.total_unknown = true;
                stats.namespace_total_unknown = true;
                stats.global_ownership_unknown = true;
                namespace_sources.insert(0, "/proc/net".to_string());
            }
        },
        Err(error) => {
            record_io_error(&mut stats, &error, false);
            stats.namespace_total_unknown = true;
            stats.global_ownership_unknown = true;
            namespace_sources.insert(0, "/proc/net".to_string());
        }
    }
    let mut omitted_namespaces = BTreeSet::new();
    for pid in &pids {
        match reader.read_link(&format!("/proc/{pid}/ns/net")) {
            Ok(link) => {
                let Some(namespace) = parse_network_namespace_link(&link) else {
                    stats.parse_failures = stats.parse_failures.saturating_add(1);
                    stats.total_unknown = true;
                    stats.namespace_total_unknown = true;
                    stats.global_ownership_unknown = true;
                    continue;
                };
                pid_namespaces.insert(*pid, namespace);
                if namespace_sources.contains_key(&namespace)
                    || omitted_namespaces.contains(&namespace)
                {
                    continue;
                }
                if namespace_sources.len() == MAX_NETWORK_NAMESPACES {
                    omitted_namespaces.insert(namespace);
                    stats.truncated = true;
                    stats.total_unknown = true;
                    stats.namespace_total_unknown = true;
                    continue;
                }
                namespace_sources.insert(namespace, format!("/proc/{pid}/net"));
            }
            Err(error) => {
                record_io_error(&mut stats, &error, true);
                stats.namespace_total_unknown = true;
                stats.global_ownership_unknown = true;
            }
        }
    }
    stats.omitted_namespaces = omitted_namespaces.len();

    let mut sockets = BTreeSet::new();
    let mut available_sources = 0usize;
    let mut proc_net_bytes = 0usize;
    'namespace_scan: for (namespace, prefix) in &namespace_sources {
        stats.scanned_namespaces = stats.scanned_namespaces.saturating_add(1);
        for (file_name, protocol) in PROC_NET_FILES {
            if proc_net_bytes == MAX_PROC_NET_BYTES_TOTAL {
                stats.truncated = true;
                stats.total_unknown = true;
                stats.namespace_total_unknown = true;
                break 'namespace_scan;
            }
            let path = format!("{prefix}/{file_name}");
            let byte_limit =
                MAX_PROC_NET_BYTES.min(MAX_PROC_NET_BYTES_TOTAL.saturating_sub(proc_net_bytes));
            match reader.read_file(&path, byte_limit) {
                Ok(file) => {
                    available_sources = available_sources.saturating_add(1);
                    proc_net_bytes = proc_net_bytes.saturating_add(file.bytes.len());
                    let parsed = parse_proc_net_bytes(&file.bytes, protocol, file.truncated);
                    stats.parse_failures = stats
                        .parse_failures
                        .saturating_add(parsed.parse_failure_count);
                    stats.truncated |= parsed.truncated;
                    stats.total_unknown |= parsed.truncated || parsed.parse_failure_count > 0;
                    stats.namespace_total_unknown |=
                        parsed.truncated || parsed.parse_failure_count > 0;
                    for connection in parsed.connections {
                        if (protocol.starts_with("tcp") && connection.state != "LISTEN")
                            || (protocol.starts_with("udp")
                                && (connection.state != "UNCONNECTED"
                                    || connection.local_port == 0))
                        {
                            continue;
                        }
                        let Some(inode) = connection
                            .inode
                            .as_deref()
                            .and_then(|value| value.parse::<u64>().ok())
                        else {
                            stats.parse_failures = stats.parse_failures.saturating_add(1);
                            stats.total_unknown = true;
                            continue;
                        };
                        let key = SocketKey {
                            network_namespace: *namespace,
                            protocol: parse_protocol(protocol),
                            local_address: connection.local_address,
                            port: connection.local_port,
                            inode,
                        };
                        if sockets.contains(&key) {
                            stats.duplicate_sockets = stats.duplicate_sockets.saturating_add(1);
                            continue;
                        }
                        if sockets.len() == MAX_SOCKET_RECORDS {
                            stats.truncated = true;
                            stats.total_unknown = true;
                            stats.namespace_total_unknown = true;
                            break 'namespace_scan;
                        }
                        sockets.insert(key);
                    }
                }
                Err(error) => {
                    record_io_error(&mut stats, &error, prefix != "/proc/net");
                    stats.namespace_total_unknown = true;
                }
            }
        }
    }
    stats.omitted_namespaces = stats.omitted_namespaces.saturating_add(
        namespace_sources
            .len()
            .saturating_sub(stats.scanned_namespaces),
    );
    let socket_inventory_complete =
        !stats.total_unknown && !stats.truncated && !stats.namespace_total_unknown;

    if available_sources == 0 {
        return CollectedServicePorts {
            services: BTreeMap::new(),
            all_binding_ids: BTreeSet::new(),
            collection: ServicePortCollection {
                requested: true,
                available: false,
                status: CollectionStatus::Failed,
                complete: false,
                truncated: stats.truncated,
                total_unknown: true,
                parse_failure_count: stats.parse_failures,
                permission_denied_count: stats.permission_denied,
                process_disappeared_count: stats.disappeared,
                scanned_pid_count: stats.scanned_pids,
                scanned_network_namespace_count: stats.scanned_namespaces,
                omitted_network_namespace_count: stats.omitted_namespaces,
                network_namespace_total_unknown: stats.namespace_total_unknown,
                error: stats.first_error,
                ..ServicePortCollection::default()
            },
        };
    }
    if sockets.is_empty() {
        let complete = !stats.total_unknown && !stats.truncated;
        return CollectedServicePorts {
            services: BTreeMap::new(),
            all_binding_ids: BTreeSet::new(),
            collection: ServicePortCollection {
                requested: true,
                available: true,
                status: if complete {
                    CollectionStatus::Complete
                } else {
                    CollectionStatus::Partial
                },
                complete,
                truncated: stats.truncated,
                total_unknown: stats.total_unknown,
                duplicate_socket_count: stats.duplicate_sockets,
                parse_failure_count: stats.parse_failures,
                permission_denied_count: stats.permission_denied,
                process_disappeared_count: stats.disappeared,
                scanned_pid_count: stats.scanned_pids,
                scanned_network_namespace_count: stats.scanned_namespaces,
                omitted_network_namespace_count: stats.omitted_namespaces,
                network_namespace_total_unknown: stats.namespace_total_unknown,
                error: stats.first_error,
                ..ServicePortCollection::default()
            },
        };
    }

    let wanted_sockets = sockets
        .iter()
        .map(|socket| (socket.network_namespace, socket.inode))
        .collect::<BTreeSet<_>>();
    let wanted_namespaces = sockets
        .iter()
        .map(|socket| socket.network_namespace)
        .collect::<BTreeSet<_>>();
    let mut owners = BTreeMap::<(u64, u64), BTreeMap<u32, Option<String>>>::new();
    let mut cgroup_bytes_total = 0usize;
    'pids: for pid in pids {
        let Some(namespace) = pid_namespaces.get(&pid).copied() else {
            continue;
        };
        if !wanted_namespaces.contains(&namespace) {
            continue;
        }
        let fd_path = format!("/proc/{pid}/fd");
        let fds = match reader.read_dir_names(&fd_path, MAX_FDS_PER_PID) {
            Ok(fds) => {
                stats.truncated |= fds.truncated;
                stats.total_unknown |= fds.truncated;
                stats.global_ownership_unknown |= fds.truncated;
                fds.names
            }
            Err(error) => {
                record_io_error(&mut stats, &error, true);
                stats.global_ownership_unknown = true;
                continue;
            }
        };
        let mut matched_inodes = BTreeSet::new();
        for fd in fds {
            if stats.scanned_fds == MAX_FDS_TOTAL {
                stats.truncated = true;
                stats.total_unknown = true;
                stats.global_ownership_unknown = true;
                break 'pids;
            }
            stats.scanned_fds = stats.scanned_fds.saturating_add(1);
            match reader.read_link(&format!("{fd_path}/{fd}")) {
                Ok(target) => {
                    if target.len() > MAX_FD_LINK_BYTES {
                        stats.parse_failures = stats.parse_failures.saturating_add(1);
                        stats.total_unknown = true;
                        stats.global_ownership_unknown = true;
                        continue;
                    }
                    if let Some(inode) = parse_socket_link(&target) {
                        if wanted_sockets.contains(&(namespace, inode)) {
                            matched_inodes.insert(inode);
                        }
                    }
                }
                Err(error) => {
                    record_io_error(&mut stats, &error, true);
                    stats.global_ownership_unknown = true;
                }
            }
        }
        if matched_inodes.is_empty() {
            continue;
        }
        let cgroup_path = format!("/proc/{pid}/cgroup");
        let service = if cgroup_bytes_total >= MAX_CGROUP_BYTES_TOTAL {
            stats.truncated = true;
            None
        } else {
            match reader.read_file(&cgroup_path, MAX_CGROUP_BYTES) {
                Ok(file) => {
                    cgroup_bytes_total = cgroup_bytes_total.saturating_add(file.bytes.len());
                    stats.truncated |= file.truncated;
                    if file.truncated {
                        None
                    } else {
                        match parse_cgroup_service(&file.bytes) {
                            Ok(service) => service,
                            Err(()) => {
                                stats.parse_failures = stats.parse_failures.saturating_add(1);
                                None
                            }
                        }
                    }
                }
                Err(error) => {
                    record_owner_io_error(&mut stats, &error);
                    None
                }
            }
        };
        for inode in matched_inodes {
            owners
                .entry((namespace, inode))
                .or_default()
                .insert(pid, service.clone());
        }
    }

    let all_binding_ids = sockets
        .iter()
        .map(format_binding_id)
        .collect::<BTreeSet<_>>();
    let scan_complete = !stats.global_ownership_unknown;
    let mut by_service = BTreeMap::<String, BTreeMap<String, ServicePortBinding>>::new();
    let mut unowned_bindings = Vec::new();
    let mut unowned_count = 0usize;
    let mut partial_ownership_count = 0usize;
    let mut shared_count = 0usize;
    for socket in &sockets {
        let pid_owners = owners.get(&(socket.network_namespace, socket.inode));
        let mut pids = pid_owners
            .map(|owners| owners.keys().copied().collect::<Vec<_>>())
            .unwrap_or_default();
        let pid_total = pids.len();
        pids.truncate(MAX_PIDS_PER_BINDING);
        let omitted_pid_count = pid_total.saturating_sub(pids.len());
        let mut unowned_pids = pid_owners
            .into_iter()
            .flat_map(|owners| owners.iter())
            .filter_map(|(pid, service)| service.is_none().then_some(*pid))
            .collect::<Vec<_>>();
        let unowned_pid_total = unowned_pids.len();
        unowned_pids.truncate(MAX_PIDS_PER_BINDING);
        let omitted_unowned_pid_count = unowned_pid_total.saturating_sub(unowned_pids.len());
        let mut owner_services = pid_owners
            .into_iter()
            .flat_map(|owners| owners.values())
            .flatten()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let owner_service_total = owner_services.len();
        if owner_service_total > 1 {
            shared_count = shared_count.saturating_add(1);
        }
        let ownership_status = if owner_service_total == 0 {
            unowned_count = unowned_count.saturating_add(1);
            ServicePortOwnershipStatus::Unowned
        } else if unowned_pid_total > 0 {
            partial_ownership_count = partial_ownership_count.saturating_add(1);
            ServicePortOwnershipStatus::Partial
        } else if owner_service_total > 1 {
            ServicePortOwnershipStatus::Shared
        } else {
            ServicePortOwnershipStatus::Owned
        };
        owner_services.truncate(MAX_SERVICES_PER_BINDING);
        let omitted_owner_service_count = owner_service_total.saturating_sub(owner_services.len());
        let ownership_complete = scan_complete
            && ownership_status != ServicePortOwnershipStatus::Unowned
            && ownership_status != ServicePortOwnershipStatus::Partial
            && omitted_pid_count == 0
            && omitted_unowned_pid_count == 0
            && omitted_owner_service_count == 0;
        stats.truncated |= omitted_pid_count > 0
            || omitted_unowned_pid_count > 0
            || omitted_owner_service_count > 0;
        stats.total_unknown |= omitted_owner_service_count > 0;
        let binding_id = format_binding_id(socket);
        let binding = ServicePortBinding {
            binding_id: binding_id.clone(),
            network_namespace: Some(socket.network_namespace),
            protocol: socket.protocol,
            local_address: socket.local_address.clone(),
            port: socket.port,
            inode: socket.inode,
            pids,
            pid_total,
            omitted_pid_count,
            unowned_pids,
            unowned_pid_total,
            omitted_unowned_pid_count,
            owner_services: owner_services.clone(),
            owner_service_total,
            omitted_owner_service_count,
            ownership_complete,
            ownership_status,
        };
        if owner_service_total == 0 {
            if unowned_bindings.len() < MAX_UNOWNED_BINDING_DETAILS {
                unowned_bindings.push(binding.clone());
            }
        }
        for service in owner_services {
            by_service
                .entry(service)
                .or_default()
                .insert(binding_id.clone(), binding.clone());
        }
    }

    let services = by_service
        .into_iter()
        .map(|(service, bindings_by_id)| {
            let binding_ids = bindings_by_id.keys().cloned().collect::<BTreeSet<_>>();
            let total = binding_ids.len();
            let mut bindings = bindings_by_id.into_values().collect::<Vec<_>>();
            bindings.truncate(MAX_PORT_BINDINGS_PER_SERVICE);
            let binding_details_complete =
                bindings.iter().all(|binding| binding.ownership_complete);
            let ownership_status = if bindings.iter().any(|binding| {
                binding.ownership_status == ServicePortOwnershipStatus::Partial
                    || binding.ownership_status == ServicePortOwnershipStatus::Unowned
            }) {
                ServicePortOwnershipStatus::Partial
            } else if bindings
                .iter()
                .any(|binding| binding.ownership_status == ServicePortOwnershipStatus::Shared)
            {
                ServicePortOwnershipStatus::Shared
            } else {
                ServicePortOwnershipStatus::Owned
            };
            (
                service,
                ServiceBindings {
                    bindings,
                    binding_ids,
                    total,
                    complete: socket_inventory_complete
                        && binding_details_complete
                        && total <= MAX_PORT_BINDINGS_PER_SERVICE,
                    ownership_status,
                },
            )
        })
        .collect();
    unowned_bindings.sort();
    let unowned_returned_count = unowned_bindings.len();
    let unowned_omitted_count = unowned_count.saturating_sub(unowned_returned_count);
    stats.truncated |= unowned_omitted_count > 0;
    let complete = socket_inventory_complete
        && scan_complete
        && unowned_count == 0
        && partial_ownership_count == 0
        && unowned_omitted_count == 0;
    CollectedServicePorts {
        services,
        all_binding_ids,
        collection: ServicePortCollection {
            requested: true,
            available: true,
            status: if complete {
                CollectionStatus::Complete
            } else {
                CollectionStatus::Partial
            },
            complete,
            truncated: stats.truncated,
            total_unknown: stats.total_unknown,
            total: sockets.len(),
            returned_count: unowned_returned_count,
            omitted_count: sockets.len().saturating_sub(unowned_returned_count),
            unowned_count,
            unowned_bindings,
            unowned_returned_count,
            unowned_omitted_count,
            partial_ownership_count,
            shared_socket_count: shared_count,
            duplicate_socket_count: stats.duplicate_sockets,
            parse_failure_count: stats.parse_failures,
            permission_denied_count: stats.permission_denied,
            process_disappeared_count: stats.disappeared,
            scanned_pid_count: stats.scanned_pids,
            scanned_fd_count: stats.scanned_fds,
            scanned_network_namespace_count: stats.scanned_namespaces,
            omitted_network_namespace_count: stats.omitted_namespaces,
            network_namespace_total_unknown: stats.namespace_total_unknown,
            error: stats.first_error,
        },
    }
}

fn parse_protocol(protocol: &str) -> ServicePortProtocol {
    match protocol {
        "tcp" => ServicePortProtocol::Tcp,
        "tcp6" => ServicePortProtocol::Tcp6,
        "udp" => ServicePortProtocol::Udp,
        "udp6" => ServicePortProtocol::Udp6,
        _ => ServicePortProtocol::Unknown,
    }
}

fn format_binding_id(socket: &SocketKey) -> String {
    let protocol = match socket.protocol {
        ServicePortProtocol::Tcp => "tcp",
        ServicePortProtocol::Tcp6 => "tcp6",
        ServicePortProtocol::Udp => "udp",
        ServicePortProtocol::Udp6 => "udp6",
        ServicePortProtocol::Unknown => "unknown",
    };
    format!(
        "{}:{protocol}:{}:{}:{}",
        socket.network_namespace, socket.local_address, socket.port, socket.inode
    )
}

fn parse_network_namespace_link(target: &str) -> Option<u64> {
    target
        .strip_prefix("net:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn parse_socket_link(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

fn parse_cgroup_service(bytes: &[u8]) -> Result<Option<String>, ()> {
    let content = std::str::from_utf8(bytes).map_err(|_| ())?;
    let mut found = None;
    for raw in content.lines() {
        let (_, rest) = raw.split_once(':').ok_or(())?;
        let (_, path) = rest.split_once(':').ok_or(())?;
        for component in path.split('/').filter(|component| !component.is_empty()) {
            let decoded = decode_systemd_component(component)?;
            if decoded.ends_with(".service") && valid_service_component(&decoded) {
                found = Some(decoded);
            }
        }
    }
    Ok(found)
}

fn decode_systemd_component(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if bytes.get(index + 1) != Some(&b'x') || index + 3 >= bytes.len() {
                return Err(());
            }
            let high = hex_value(bytes[index + 2]).ok_or(())?;
            let low = hex_value(bytes[index + 3]).ok_or(())?;
            decoded.push((high << 4) | low);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| ())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_service_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.is_ascii()
        && value.ends_with(".service")
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace() && byte != b'/')
}

fn record_io_error(stats: &mut PortStats, error: &io::Error, process_scoped: bool) {
    match error.kind() {
        io::ErrorKind::PermissionDenied => {
            stats.permission_denied = stats.permission_denied.saturating_add(1);
        }
        io::ErrorKind::NotFound if process_scoped => {
            stats.disappeared = stats.disappeared.saturating_add(1);
        }
        _ => {
            stats.parse_failures = stats.parse_failures.saturating_add(1);
        }
    }
    stats.total_unknown = true;
    stats
        .first_error
        .get_or_insert_with(|| redact_sensitive_text(&error.to_string(), MAX_PORT_ERROR_CHARS));
}

fn record_owner_io_error(stats: &mut PortStats, error: &io::Error) {
    match error.kind() {
        io::ErrorKind::PermissionDenied => {
            stats.permission_denied = stats.permission_denied.saturating_add(1);
        }
        io::ErrorKind::NotFound => {
            stats.disappeared = stats.disappeared.saturating_add(1);
        }
        _ => {
            stats.parse_failures = stats.parse_failures.saturating_add(1);
        }
    }
    stats
        .first_error
        .get_or_insert_with(|| redact_sensitive_text(&error.to_string(), MAX_PORT_ERROR_CHARS));
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    #[derive(Default)]
    struct MockReader {
        files: BTreeMap<String, Vec<u8>>,
        dirs: BTreeMap<String, BoundedNames>,
        links: BTreeMap<String, std::result::Result<String, io::ErrorKind>>,
        reads: RefCell<Vec<String>>,
    }

    impl ServicePortReader for MockReader {
        fn read_file(&self, path: &str, limit: usize) -> io::Result<BoundedBytes> {
            self.reads.borrow_mut().push(path.to_string());
            let bytes = self
                .files
                .get(path)
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            Ok(BoundedBytes {
                bytes: bytes.iter().copied().take(limit).collect(),
                truncated: bytes.len() > limit,
            })
        }

        fn read_dir_names(&self, path: &str, _limit: usize) -> io::Result<BoundedNames> {
            self.reads.borrow_mut().push(path.to_string());
            self.dirs
                .get(path)
                .map(|names| BoundedNames {
                    names: names.names.clone(),
                    truncated: names.truncated,
                })
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }

        fn read_link(&self, path: &str) -> io::Result<String> {
            self.reads.borrow_mut().push(path.to_string());
            match self.links.get(path) {
                Some(Ok(target)) => Ok(target.clone()),
                Some(Err(kind)) => Err(io::Error::from(*kind)),
                None => Err(io::Error::from(io::ErrorKind::NotFound)),
            }
        }
    }

    fn proc_row(address: &str, state: &str, inode: u64) -> String {
        let remote = if address
            .split_once(':')
            .is_some_and(|(address, _)| address.len() == 32)
        {
            "00000000000000000000000000000000:0000"
        } else {
            "00000000:0000"
        };
        format!(
            "  0: {address} {remote} {state} 00000000:00000000 00:00000000 00000000 1000 0 {inode} 1\n"
        )
    }

    fn proc_file(row: String) -> Vec<u8> {
        format!("sl local_address rem_address st queues timer retr uid timeout inode\n{row}")
            .into_bytes()
    }

    fn add_host_namespace(reader: &mut MockReader, pids: &[u32]) {
        reader
            .links
            .insert("/proc/self/ns/net".to_string(), Ok("net:[100]".to_string()));
        for pid in pids {
            reader
                .links
                .insert(format!("/proc/{pid}/ns/net"), Ok("net:[100]".to_string()));
        }
    }

    fn add_empty_proc_net(reader: &mut MockReader, prefix: &str) {
        for (file, _) in PROC_NET_FILES {
            reader
                .files
                .insert(format!("{prefix}/{file}"), proc_file(String::new()));
        }
    }

    #[test]
    fn parses_v1_v2_cgroups_and_strict_systemd_escapes() {
        assert_eq!(
            parse_cgroup_service(b"0::/system.slice/demo\\x2dapi.service\n").unwrap(),
            Some("demo-api.service".to_string())
        );
        assert_eq!(
            parse_cgroup_service(b"1:name=systemd:/system.slice/legacy.service\n").unwrap(),
            Some("legacy.service".to_string())
        );
        assert!(parse_cgroup_service(b"0::/system.slice/bad\\x2.service\n").is_err());
    }

    #[test]
    fn socket_link_parser_does_not_accept_extra_text() {
        assert_eq!(parse_socket_link("socket:[123]"), Some(123));
        assert_eq!(parse_socket_link("socket:[123]/tail"), None);
        assert_eq!(parse_socket_link("anon_inode:[eventpoll]"), None);
        assert_eq!(parse_network_namespace_link("net:[123]"), Some(123));
        assert_eq!(parse_network_namespace_link("mnt:[123]"), None);
    }

    #[test]
    fn collects_tcp_udp_ipv4_ipv6_and_shared_inode_with_bounded_reader() {
        let mut reader = MockReader::default();
        reader.files.insert(
            "/proc/net/tcp".to_string(),
            proc_file(proc_row("0100007F:1F90", "0A", 111)),
        );
        reader.files.insert(
            "/proc/net/tcp6".to_string(),
            proc_file(proc_row("00000000000000000000000000000000:1F91", "0A", 333)),
        );
        reader.files.insert(
            "/proc/net/udp".to_string(),
            proc_file(format!(
                "{}{}",
                proc_row("00000000:14E9", "07", 222),
                proc_row("00000000:270F", "01", 555)
            )),
        );
        reader.files.insert(
            "/proc/net/udp6".to_string(),
            proc_file(proc_row("00000000000000000000000000000000:14EA", "07", 444)),
        );
        reader.dirs.insert(
            "/proc".to_string(),
            BoundedNames {
                names: vec!["10".to_string(), "11".to_string()],
                truncated: false,
            },
        );
        add_host_namespace(&mut reader, &[10, 11]);
        for (pid, service) in [(10, "demo.service"), (11, "peer.service")] {
            reader.files.insert(
                format!("/proc/{pid}/cgroup"),
                format!("0::/system.slice/{service}\n").into_bytes(),
            );
            reader.dirs.insert(
                format!("/proc/{pid}/fd"),
                BoundedNames {
                    names: if pid == 10 {
                        vec!["1".to_string(), "2".to_string(), "3".to_string()]
                    } else {
                        vec!["1".to_string(), "2".to_string()]
                    },
                    truncated: false,
                },
            );
        }
        for (path, inode) in [
            ("/proc/10/fd/1", 111),
            ("/proc/10/fd/2", 222),
            ("/proc/10/fd/3", 333),
            ("/proc/11/fd/1", 333),
            ("/proc/11/fd/2", 444),
        ] {
            reader
                .links
                .insert(path.to_string(), Ok(format!("socket:[{inode}]")));
        }

        let collected = collect_service_ports_unix(&reader);
        let demo = &collected.services["demo.service"];
        assert_eq!(demo.total, 3, "bindings: {:?}", demo.bindings);
        assert!(demo.bindings.iter().any(|binding| {
            binding.protocol == ServicePortProtocol::Tcp && binding.port == 8080
        }));
        assert!(demo.bindings.iter().any(|binding| {
            binding.protocol == ServicePortProtocol::Udp && binding.port == 5353
        }));
        let shared = demo
            .bindings
            .iter()
            .find(|binding| binding.inode == 333)
            .unwrap();
        assert_eq!(shared.protocol, ServicePortProtocol::Tcp6);
        assert_eq!(shared.owner_services, ["demo.service", "peer.service"]);
        assert_eq!(shared.ownership_status, ServicePortOwnershipStatus::Shared);
        assert_eq!(collected.collection.shared_socket_count, 1);
        assert_eq!(collected.collection.unowned_count, 0);
        assert!(!demo.bindings.iter().any(|binding| binding.inode == 555));
        assert_eq!(collected.collection.scanned_network_namespace_count, 1);
    }

    #[test]
    fn observes_permission_disappearance_and_directory_budget() {
        let mut reader = MockReader::default();
        add_empty_proc_net(&mut reader, "/proc/net");
        reader.files.insert(
            "/proc/net/tcp".to_string(),
            proc_file(proc_row("0100007F:1F90", "0A", 111)),
        );
        reader.dirs.insert(
            "/proc".to_string(),
            BoundedNames {
                names: vec!["10".to_string()],
                truncated: true,
            },
        );
        add_host_namespace(&mut reader, &[10]);
        reader.files.insert(
            "/proc/10/cgroup".to_string(),
            b"0::/system.slice/demo.service\n".to_vec(),
        );
        reader.dirs.insert(
            "/proc/10/fd".to_string(),
            BoundedNames {
                names: vec!["1".to_string(), "2".to_string()],
                truncated: true,
            },
        );
        reader.links.insert(
            "/proc/10/fd/1".to_string(),
            Err(io::ErrorKind::PermissionDenied),
        );
        reader
            .links
            .insert("/proc/10/fd/2".to_string(), Err(io::ErrorKind::NotFound));

        let collected = collect_service_ports_unix(&reader);
        assert!(collected.collection.truncated);
        assert!(collected.collection.total_unknown);
        assert_eq!(collected.collection.permission_denied_count, 1);
        assert_eq!(collected.collection.process_disappeared_count, 1);
        assert_eq!(collected.collection.status, CollectionStatus::Partial);
    }

    #[test]
    fn scans_each_network_namespace_once_and_keeps_inode_scoped_to_namespace() {
        let mut reader = MockReader::default();
        add_empty_proc_net(&mut reader, "/proc/net");
        reader.files.insert(
            "/proc/net/tcp".to_string(),
            proc_file(proc_row("0100007F:1F90", "0A", 111)),
        );
        add_empty_proc_net(&mut reader, "/proc/20/net");
        reader.files.insert(
            "/proc/20/net/tcp".to_string(),
            proc_file(proc_row("0100007F:2328", "0A", 111)),
        );
        reader.dirs.insert(
            "/proc".to_string(),
            BoundedNames {
                names: vec!["10".to_string(), "20".to_string(), "30".to_string()],
                truncated: false,
            },
        );
        reader
            .links
            .insert("/proc/self/ns/net".to_string(), Ok("net:[100]".to_string()));
        for (pid, namespace) in [(10, 100), (20, 200), (30, 200)] {
            reader.links.insert(
                format!("/proc/{pid}/ns/net"),
                Ok(format!("net:[{namespace}]")),
            );
            reader.files.insert(
                format!("/proc/{pid}/cgroup"),
                format!("0::/system.slice/p{pid}.service\n").into_bytes(),
            );
            reader.dirs.insert(
                format!("/proc/{pid}/fd"),
                BoundedNames {
                    names: vec!["1".to_string()],
                    truncated: false,
                },
            );
            reader
                .links
                .insert(format!("/proc/{pid}/fd/1"), Ok("socket:[111]".to_string()));
        }

        let collected = collect_service_ports_unix(&reader);
        assert_eq!(collected.collection.scanned_network_namespace_count, 2);
        assert_eq!(collected.collection.total, 2);
        assert_eq!(collected.services["p10.service"].bindings[0].port, 8080);
        assert_eq!(collected.services["p20.service"].bindings[0].port, 9000);
        assert_eq!(collected.services["p30.service"].bindings[0].port, 9000);
        assert_ne!(
            collected.services["p10.service"].bindings[0].binding_id,
            collected.services["p20.service"].bindings[0].binding_id
        );
        let reads = reader.reads.borrow();
        assert_eq!(
            reads
                .iter()
                .filter(|path| path.as_str() == "/proc/20/net/tcp")
                .count(),
            1
        );
        assert!(!reads.iter().any(|path| path == "/proc/30/net/tcp"));
    }

    #[test]
    fn network_namespace_cap_marks_known_lower_bound_incomplete() {
        let mut reader = MockReader::default();
        add_empty_proc_net(&mut reader, "/proc/net");
        reader
            .links
            .insert("/proc/self/ns/net".to_string(), Ok("net:[100]".to_string()));
        let pids = (1..=MAX_NETWORK_NAMESPACES)
            .map(|pid| pid.to_string())
            .collect::<Vec<_>>();
        reader.dirs.insert(
            "/proc".to_string(),
            BoundedNames {
                names: pids,
                truncated: false,
            },
        );
        for pid in 1..=MAX_NETWORK_NAMESPACES {
            reader.links.insert(
                format!("/proc/{pid}/ns/net"),
                Ok(format!("net:[{}]", 1_000 + pid)),
            );
            add_empty_proc_net(&mut reader, &format!("/proc/{pid}/net"));
        }

        let collected = collect_service_ports_unix(&reader);
        assert_eq!(
            collected.collection.scanned_network_namespace_count,
            MAX_NETWORK_NAMESPACES
        );
        assert_eq!(collected.collection.omitted_network_namespace_count, 1);
        assert!(collected.collection.network_namespace_total_unknown);
        assert!(collected.collection.total_unknown);
        assert!(!collected.collection.complete);
    }

    #[test]
    fn mixed_unowned_pid_only_marks_its_binding_partial() {
        let mut reader = MockReader::default();
        add_empty_proc_net(&mut reader, "/proc/net");
        reader.files.insert(
            "/proc/net/tcp".to_string(),
            proc_file(format!(
                "{}{}",
                proc_row("0100007F:1F90", "0A", 111),
                proc_row("0100007F:1F91", "0A", 222)
            )),
        );
        reader.dirs.insert(
            "/proc".to_string(),
            BoundedNames {
                names: vec!["10".to_string(), "11".to_string(), "12".to_string()],
                truncated: false,
            },
        );
        add_host_namespace(&mut reader, &[10, 11, 12]);
        for (pid, inode, cgroup) in [
            (10, 111, "0::/system.slice/demo.service\n"),
            (11, 111, "0::/user.slice/session.scope\n"),
            (12, 222, "0::/system.slice/peer.service\n"),
        ] {
            reader
                .files
                .insert(format!("/proc/{pid}/cgroup"), cgroup.as_bytes().to_vec());
            reader.dirs.insert(
                format!("/proc/{pid}/fd"),
                BoundedNames {
                    names: vec!["1".to_string()],
                    truncated: false,
                },
            );
            reader
                .links
                .insert(format!("/proc/{pid}/fd/1"), Ok(format!("socket:[{inode}]")));
        }

        let collected = collect_service_ports_unix(&reader);
        let mixed = &collected.services["demo.service"].bindings[0];
        assert_eq!(mixed.ownership_status, ServicePortOwnershipStatus::Partial);
        assert_eq!(mixed.unowned_pids, [11]);
        assert!(!mixed.ownership_complete);
        let peer = &collected.services["peer.service"];
        assert_eq!(peer.ownership_status, ServicePortOwnershipStatus::Owned);
        assert!(peer.complete);
        assert!(peer.bindings[0].ownership_complete);
        assert_eq!(collected.collection.partial_ownership_count, 1);
        assert_eq!(collected.collection.unowned_count, 0);
    }

    #[test]
    fn unowned_only_socket_has_self_consistent_detail_counts() {
        let mut reader = MockReader::default();
        add_empty_proc_net(&mut reader, "/proc/net");
        reader.files.insert(
            "/proc/net/udp".to_string(),
            proc_file(proc_row("00000000:14E9", "07", 333)),
        );
        reader.dirs.insert(
            "/proc".to_string(),
            BoundedNames {
                names: Vec::new(),
                truncated: false,
            },
        );
        add_host_namespace(&mut reader, &[]);

        let collected = collect_service_ports_unix(&reader);
        assert_eq!(collected.collection.unowned_count, 1);
        assert_eq!(collected.collection.unowned_returned_count, 1);
        assert_eq!(collected.collection.unowned_omitted_count, 0);
        assert_eq!(collected.collection.total, 1);
        assert_eq!(collected.collection.returned_count, 1);
        assert_eq!(collected.collection.omitted_count, 0);
        assert_eq!(collected.collection.unowned_bindings.len(), 1);
        assert_eq!(
            collected.collection.unowned_bindings[0].ownership_status,
            ServicePortOwnershipStatus::Unowned
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn production_collector_is_structured_unavailable_off_unix() {
        let collected = collect_service_ports();
        assert!(collected.collection.requested);
        assert!(!collected.collection.available);
        assert_eq!(collected.collection.status, CollectionStatus::Failed);
    }
}
