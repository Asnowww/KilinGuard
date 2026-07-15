use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

pub const DEFAULT_TOOL_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_OUTPUT_LIMIT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemIsolationMode {
    Off,
    #[default]
    WorkspaceOnly,
    AllowList,
    #[serde(rename = "overlayfs", alias = "overlay-fs")]
    OverlayFs,
}

impl FilesystemIsolationMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::WorkspaceOnly => "workspace-only",
            Self::AllowList => "allow-list",
            Self::OverlayFs => "overlayfs",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SandboxConfig {
    pub enabled: Option<bool>,
    pub namespace_restrictions: Option<bool>,
    pub network_isolation: Option<bool>,
    pub filesystem_mode: Option<FilesystemIsolationMode>,
    pub allowed_mounts: Vec<String>,
    pub default_timeout_ms: Option<u64>,
    pub memory_limit_bytes: Option<u64>,
    pub output_limit_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SandboxRequest {
    pub enabled: bool,
    pub namespace_restrictions: bool,
    pub network_isolation: bool,
    pub filesystem_mode: FilesystemIsolationMode,
    pub allowed_mounts: Vec<String>,
    pub default_timeout_ms: u64,
    pub memory_limit_bytes: u64,
    pub output_limit_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ContainerEnvironment {
    pub in_container: bool,
    pub markers: Vec<String>,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SandboxStatus {
    pub enabled: bool,
    pub requested: SandboxRequest,
    pub supported: bool,
    pub active: bool,
    pub namespace_supported: bool,
    pub namespace_active: bool,
    pub network_supported: bool,
    pub network_active: bool,
    pub cgroup_supported: bool,
    pub cgroup_active: bool,
    pub seccomp_supported: bool,
    pub seccomp_active: bool,
    pub capability_supported: bool,
    pub capability_drop_active: bool,
    pub filesystem_mode: FilesystemIsolationMode,
    pub filesystem_active: bool,
    pub overlayfs_supported: bool,
    pub overlayfs_active: bool,
    pub overlayfs_merge_required: bool,
    pub allowed_mounts: Vec<String>,
    pub invocation: Option<SandboxInvocation>,
    pub default_timeout_ms: u64,
    pub memory_limit_bytes: u64,
    pub output_limit_bytes: usize,
    pub in_container: bool,
    pub container_markers: Vec<String>,
    pub fallback_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxDetectionInputs<'a> {
    pub env_pairs: Vec<(String, String)>,
    pub dockerenv_exists: bool,
    pub containerenv_exists: bool,
    pub proc_1_cgroup: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSandboxCommand {
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxInvocation {
    pub id: String,
    pub root_dir: PathBuf,
    pub home_dir: PathBuf,
    pub temp_dir: PathBuf,
    pub overlay_plan: Option<OverlayFsPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverlayFsPlan {
    pub lower_dir: PathBuf,
    pub upper_dir: PathBuf,
    pub work_dir: PathBuf,
    pub merged_dir: PathBuf,
    pub marker_path: PathBuf,
}

impl OverlayFsPlan {
    #[must_use]
    pub fn mount_options(&self) -> String {
        format!(
            "lowerdir={},upperdir={},workdir={}",
            self.lower_dir.display(),
            self.upper_dir.display(),
            self.work_dir.display()
        )
    }
}

impl SandboxStatus {
    #[must_use]
    pub fn with_invocation(mut self, cwd: &Path) -> Self {
        if !self.enabled {
            return self;
        }
        self.invocation = Some(build_sandbox_invocation(cwd, self.overlayfs_active));
        self
    }
}

impl SandboxConfig {
    #[must_use]
    pub fn resolve_request(
        &self,
        enabled_override: Option<bool>,
        namespace_override: Option<bool>,
        network_override: Option<bool>,
        filesystem_mode_override: Option<FilesystemIsolationMode>,
        allowed_mounts_override: Option<Vec<String>>,
    ) -> SandboxRequest {
        SandboxRequest {
            enabled: enabled_override.unwrap_or(self.enabled.unwrap_or(true)),
            namespace_restrictions: namespace_override
                .unwrap_or(self.namespace_restrictions.unwrap_or(true)),
            network_isolation: network_override.unwrap_or(self.network_isolation.unwrap_or(true)),
            filesystem_mode: filesystem_mode_override
                .or(self.filesystem_mode)
                .unwrap_or_default(),
            allowed_mounts: allowed_mounts_override.unwrap_or_else(|| self.allowed_mounts.clone()),
            default_timeout_ms: self.default_timeout_ms.unwrap_or(DEFAULT_TOOL_TIMEOUT_MS),
            memory_limit_bytes: self
                .memory_limit_bytes
                .unwrap_or(DEFAULT_MEMORY_LIMIT_BYTES),
            output_limit_bytes: self
                .output_limit_bytes
                .unwrap_or(DEFAULT_OUTPUT_LIMIT_BYTES),
        }
    }
}

#[must_use]
pub fn detect_container_environment() -> ContainerEnvironment {
    let proc_1_cgroup = fs::read_to_string("/proc/1/cgroup").ok();
    detect_container_environment_from(SandboxDetectionInputs {
        env_pairs: env::vars().collect(),
        dockerenv_exists: Path::new("/.dockerenv").exists(),
        containerenv_exists: Path::new("/run/.containerenv").exists(),
        proc_1_cgroup: proc_1_cgroup.as_deref(),
    })
}

#[must_use]
pub fn detect_container_environment_from(
    inputs: SandboxDetectionInputs<'_>,
) -> ContainerEnvironment {
    let mut markers = Vec::new();
    if inputs.dockerenv_exists {
        markers.push("/.dockerenv".to_string());
    }
    if inputs.containerenv_exists {
        markers.push("/run/.containerenv".to_string());
    }
    for (key, value) in inputs.env_pairs {
        let normalized = key.to_ascii_lowercase();
        if matches!(
            normalized.as_str(),
            "container" | "docker" | "podman" | "kubernetes_service_host"
        ) && !value.is_empty()
        {
            markers.push(format!("env:{key}={value}"));
        }
    }
    if let Some(cgroup) = inputs.proc_1_cgroup {
        for needle in ["docker", "containerd", "kubepods", "podman", "libpod"] {
            if cgroup.contains(needle) {
                markers.push(format!("/proc/1/cgroup:{needle}"));
            }
        }
    }
    markers.sort();
    markers.dedup();
    ContainerEnvironment {
        in_container: !markers.is_empty(),
        markers,
    }
}

#[must_use]
pub fn resolve_sandbox_status(config: &SandboxConfig, cwd: &Path) -> SandboxStatus {
    let request = config.resolve_request(None, None, None, None, None);
    resolve_sandbox_status_for_request(&request, cwd)
}

#[must_use]
pub fn resolve_sandbox_status_for_request(request: &SandboxRequest, cwd: &Path) -> SandboxStatus {
    let container = detect_container_environment();
    let namespace_supported = cfg!(target_os = "linux") && unshare_user_namespace_works();
    let network_supported = namespace_supported;
    let cgroup_supported = cfg!(target_os = "linux") && Path::new("/sys/fs/cgroup").exists();
    let seccomp_supported = cfg!(target_os = "linux") && Path::new("/proc/self/status").exists();
    let capability_supported = cfg!(target_os = "linux") && command_exists("capsh");
    let filesystem_active =
        request.enabled && request.filesystem_mode != FilesystemIsolationMode::Off;
    let overlayfs_supported = cfg!(target_os = "linux") && overlayfs_supported();
    let overlayfs_requested = filesystem_active;
    let overlayfs_active =
        request.enabled && overlayfs_requested && namespace_supported && overlayfs_supported;
    let mut fallback_reasons = Vec::new();

    if request.enabled && request.namespace_restrictions && !namespace_supported {
        fallback_reasons
            .push("namespace isolation unavailable (requires Linux with `unshare`)".to_string());
    }
    if request.enabled && request.network_isolation && !network_supported {
        fallback_reasons
            .push("network isolation unavailable (requires Linux with `unshare`)".to_string());
    }
    if request.enabled && !cgroup_supported {
        fallback_reasons.push("cgroup resource limits unavailable".to_string());
    }
    if request.enabled && !seccomp_supported {
        fallback_reasons.push("seccomp status unavailable".to_string());
    }
    if request.enabled && !capability_supported {
        fallback_reasons.push("capability drop unavailable (requires `capsh`)".to_string());
    }
    if request.enabled && overlayfs_requested && !overlayfs_supported {
        fallback_reasons.push(
            "overlayfs workspace layer unavailable (requires Linux overlayfs and `mount`)"
                .to_string(),
        );
    } else if request.enabled && overlayfs_requested && !namespace_supported {
        fallback_reasons
            .push("overlayfs layer inactive because mount namespace is unavailable".to_string());
    }
    if request.enabled
        && request.filesystem_mode == FilesystemIsolationMode::AllowList
        && request.allowed_mounts.is_empty()
    {
        fallback_reasons
            .push("filesystem allow-list requested without configured mounts".to_string());
    }

    let active = request.enabled
        && (!request.namespace_restrictions || namespace_supported)
        && (!request.network_isolation || network_supported)
        && (!overlayfs_requested || overlayfs_active);

    let allowed_mounts = normalize_mounts(&request.allowed_mounts, cwd);

    SandboxStatus {
        enabled: request.enabled,
        requested: request.clone(),
        supported: namespace_supported,
        active,
        namespace_supported,
        namespace_active: request.enabled && request.namespace_restrictions && namespace_supported,
        network_supported,
        network_active: request.enabled && request.network_isolation && network_supported,
        cgroup_supported,
        cgroup_active: request.enabled && cgroup_supported,
        seccomp_supported,
        seccomp_active: request.enabled && seccomp_supported,
        capability_supported,
        capability_drop_active: request.enabled && capability_supported,
        filesystem_mode: request.filesystem_mode,
        filesystem_active,
        overlayfs_supported,
        overlayfs_active,
        overlayfs_merge_required: overlayfs_active,
        allowed_mounts,
        invocation: None,
        default_timeout_ms: request.default_timeout_ms,
        memory_limit_bytes: request.memory_limit_bytes,
        output_limit_bytes: request.output_limit_bytes,
        in_container: container.in_container,
        container_markers: container.markers,
        fallback_reason: (!fallback_reasons.is_empty()).then(|| fallback_reasons.join("; ")),
    }
}

#[must_use]
pub fn build_linux_sandbox_command(
    command: &str,
    cwd: &Path,
    status: &SandboxStatus,
) -> Option<LinuxSandboxCommand> {
    if !cfg!(target_os = "linux")
        || !status.enabled
        || (!status.namespace_active && !status.network_active && !status.overlayfs_active)
    {
        return None;
    }

    let mut args = vec![
        "--user".to_string(),
        "--map-root-user".to_string(),
        "--mount".to_string(),
        "--ipc".to_string(),
        "--pid".to_string(),
        "--uts".to_string(),
        "--fork".to_string(),
    ];
    if status.network_active {
        args.push("--net".to_string());
    }
    if request_has_resource_limits(status) && command_exists("prlimit") {
        args.push("prlimit".to_string());
        args.push(format!("--as={}", status.memory_limit_bytes));
        args.push(format!(
            "--cpu={}",
            status.default_timeout_ms.div_ceil(1_000).max(1)
        ));
        args.push("--".to_string());
    }
    if status.capability_drop_active && command_exists("capsh") {
        args.push("capsh".to_string());
        args.push("--drop=all".to_string());
        args.push("--".to_string());
    }
    let overlay_plan = status
        .overlayfs_active
        .then(|| {
            status
                .invocation
                .as_ref()
                .and_then(|invocation| invocation.overlay_plan.as_ref())
        })
        .flatten();
    let launcher_command = overlay_plan.as_ref().map_or_else(
        || command.to_string(),
        |plan| overlay_launcher_command(command, plan),
    );

    args.push("sh".to_string());
    args.push("-lc".to_string());
    args.push(launcher_command);

    let sandbox_home = status.invocation.as_ref().map_or_else(
        || cwd.join(".sandbox-home"),
        |invocation| invocation.home_dir.clone(),
    );
    let sandbox_tmp = status.invocation.as_ref().map_or_else(
        || cwd.join(".sandbox-tmp"),
        |invocation| invocation.temp_dir.clone(),
    );
    let mut env = vec![
        ("HOME".to_string(), sandbox_home.display().to_string()),
        ("TMPDIR".to_string(), sandbox_tmp.display().to_string()),
        (
            "CLAWD_SANDBOX_FILESYSTEM_MODE".to_string(),
            status.filesystem_mode.as_str().to_string(),
        ),
        (
            "CLAWD_SANDBOX_ALLOWED_MOUNTS".to_string(),
            status.allowed_mounts.join(":"),
        ),
        (
            "CLAWD_SANDBOX_TIMEOUT_MS".to_string(),
            status.default_timeout_ms.to_string(),
        ),
        (
            "CLAWD_SANDBOX_MEMORY_LIMIT_BYTES".to_string(),
            status.memory_limit_bytes.to_string(),
        ),
        (
            "CLAWD_SANDBOX_OUTPUT_LIMIT_BYTES".to_string(),
            status.output_limit_bytes.to_string(),
        ),
        (
            "CLAWD_SANDBOX_CGROUP_ACTIVE".to_string(),
            status.cgroup_active.to_string(),
        ),
        (
            "CLAWD_SANDBOX_SECCOMP_ACTIVE".to_string(),
            status.seccomp_active.to_string(),
        ),
        (
            "CLAWD_SANDBOX_CAPABILITY_DROP_ACTIVE".to_string(),
            status.capability_drop_active.to_string(),
        ),
        (
            "CLAWD_SANDBOX_OVERLAYFS_ACTIVE".to_string(),
            status.overlayfs_active.to_string(),
        ),
        (
            "CLAWD_SANDBOX_OVERLAYFS_MERGE_REQUIRED".to_string(),
            status.overlayfs_merge_required.to_string(),
        ),
    ];
    if let Some(invocation) = &status.invocation {
        env.push((
            "CLAWD_SANDBOX_INVOCATION_ID".to_string(),
            invocation.id.clone(),
        ));
        env.push((
            "CLAWD_SANDBOX_ROOT".to_string(),
            invocation.root_dir.display().to_string(),
        ));
    }
    if let Ok(path) = env::var("PATH") {
        env.push(("PATH".to_string(), path));
    }
    if let Some(plan) = &overlay_plan {
        env.push((
            "CLAWD_SANDBOX_OVERLAY_LOWER".to_string(),
            plan.lower_dir.display().to_string(),
        ));
        env.push((
            "CLAWD_SANDBOX_OVERLAY_UPPER".to_string(),
            plan.upper_dir.display().to_string(),
        ));
        env.push((
            "CLAWD_SANDBOX_OVERLAY_WORK".to_string(),
            plan.work_dir.display().to_string(),
        ));
        env.push((
            "CLAWD_SANDBOX_OVERLAY_MERGED".to_string(),
            plan.merged_dir.display().to_string(),
        ));
    }

    Some(LinuxSandboxCommand {
        program: "unshare".to_string(),
        args,
        env,
    })
}

fn request_has_resource_limits(status: &SandboxStatus) -> bool {
    status.default_timeout_ms > 0 || status.memory_limit_bytes > 0
}

fn normalize_mounts(mounts: &[String], cwd: &Path) -> Vec<String> {
    let cwd = cwd.to_path_buf();
    mounts
        .iter()
        .map(|mount| {
            let path = PathBuf::from(mount);
            if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            }
        })
        .map(|path| path.display().to_string())
        .collect()
}

#[must_use]
pub fn build_overlayfs_plan(workspace_root: &Path, layer_root: &Path) -> OverlayFsPlan {
    OverlayFsPlan {
        lower_dir: workspace_root.to_path_buf(),
        upper_dir: layer_root.join("upper"),
        work_dir: layer_root.join("work"),
        merged_dir: layer_root.join("merged"),
        marker_path: layer_root.join(".claw-overlay-layer"),
    }
}

#[must_use]
pub fn default_overlay_root(workspace_root: &Path) -> PathBuf {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in workspace_root.to_string_lossy().as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    env::temp_dir()
        .join("clawd-overlay")
        .join(format!("{hash:x}"))
}

#[must_use]
pub fn build_sandbox_invocation(workspace_root: &Path, overlay_enabled: bool) -> SandboxInvocation {
    let id = next_invocation_id();
    let root_dir = env::temp_dir().join("clawd-sandbox").join(&id);
    let overlay_plan =
        overlay_enabled.then(|| build_overlayfs_plan(workspace_root, &root_dir.join("overlay")));
    SandboxInvocation {
        id,
        home_dir: root_dir.join("home"),
        temp_dir: root_dir.join("tmp"),
        root_dir,
        overlay_plan,
    }
}

fn next_invocation_id() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("tool-{}-{now}-{seq}", std::process::id())
}

fn overlay_launcher_command(command: &str, plan: &OverlayFsPlan) -> String {
    format!(
        "mkdir -p {upper} {work} {merged} && printf managed > {marker} && mount -t overlay overlay -o {opts} {merged} && cd {merged} && sh -lc {command}",
        upper = shell_quote_path(&plan.upper_dir),
        work = shell_quote_path(&plan.work_dir),
        merged = shell_quote_path(&plan.merged_dir),
        marker = shell_quote_path(&plan.marker_path),
        opts = shell_quote(&plan.mount_options()),
        command = shell_quote(command),
    )
}

fn shell_quote_path(path: &Path) -> String {
    shell_quote(&path.display().to_string())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn command_exists(command: &str) -> bool {
    env::var_os("PATH")
        .is_some_and(|paths| env::split_paths(&paths).any(|path| path.join(command).exists()))
}

fn overlayfs_supported() -> bool {
    if !command_exists("mount") {
        return false;
    }
    fs::read_to_string("/proc/filesystems").is_ok_and(|filesystems| {
        filesystems.lines().any(|line| {
            let line = line.trim();
            line == "overlay" || line == "nodev\toverlay"
        })
    })
}

/// Check whether `unshare --user` actually works on this system.
/// On some CI environments (e.g. GitHub Actions), the binary exists but
/// user namespaces are restricted, causing silent failures.
fn unshare_user_namespace_works() -> bool {
    use std::sync::OnceLock;
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        if !command_exists("unshare") {
            return false;
        }
        std::process::Command::new("unshare")
            .args(["--user", "--map-root-user", "true"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    })
}

#[cfg(test)]
mod tests {
    use super::{
        build_linux_sandbox_command, build_overlayfs_plan, default_overlay_root,
        detect_container_environment_from, FilesystemIsolationMode, SandboxConfig,
        SandboxDetectionInputs, DEFAULT_MEMORY_LIMIT_BYTES, DEFAULT_OUTPUT_LIMIT_BYTES,
        DEFAULT_TOOL_TIMEOUT_MS,
    };
    use std::path::Path;

    #[test]
    fn detects_container_markers_from_multiple_sources() {
        let detected = detect_container_environment_from(SandboxDetectionInputs {
            env_pairs: vec![("container".to_string(), "docker".to_string())],
            dockerenv_exists: true,
            containerenv_exists: false,
            proc_1_cgroup: Some("12:memory:/docker/abc"),
        });

        assert!(detected.in_container);
        assert!(detected
            .markers
            .iter()
            .any(|marker| marker == "/.dockerenv"));
        assert!(detected
            .markers
            .iter()
            .any(|marker| marker == "env:container=docker"));
        assert!(detected
            .markers
            .iter()
            .any(|marker| marker == "/proc/1/cgroup:docker"));
    }

    #[test]
    fn resolves_request_with_overrides() {
        let config = SandboxConfig {
            enabled: Some(true),
            namespace_restrictions: Some(true),
            network_isolation: Some(false),
            filesystem_mode: Some(FilesystemIsolationMode::WorkspaceOnly),
            allowed_mounts: vec!["logs".to_string()],
            ..SandboxConfig::default()
        };

        let request = config.resolve_request(
            Some(true),
            Some(false),
            Some(true),
            Some(FilesystemIsolationMode::AllowList),
            Some(vec!["tmp".to_string()]),
        );

        assert!(request.enabled);
        assert!(!request.namespace_restrictions);
        assert!(request.network_isolation);
        assert_eq!(request.filesystem_mode, FilesystemIsolationMode::AllowList);
        assert_eq!(request.allowed_mounts, vec!["tmp"]);
        assert_eq!(request.default_timeout_ms, DEFAULT_TOOL_TIMEOUT_MS);
        assert_eq!(request.memory_limit_bytes, DEFAULT_MEMORY_LIMIT_BYTES);
        assert_eq!(request.output_limit_bytes, DEFAULT_OUTPUT_LIMIT_BYTES);
    }

    #[test]
    fn default_request_enables_network_isolation_and_resource_limits() {
        let request = SandboxConfig::default().resolve_request(None, None, None, None, None);

        assert!(request.enabled);
        assert!(request.namespace_restrictions);
        assert!(request.network_isolation);
        assert_eq!(request.default_timeout_ms, 30_000);
        assert_eq!(request.memory_limit_bytes, DEFAULT_MEMORY_LIMIT_BYTES);
        assert_eq!(request.output_limit_bytes, DEFAULT_OUTPUT_LIMIT_BYTES);
    }

    #[test]
    fn builds_linux_launcher_with_network_flag_when_requested() {
        let config = SandboxConfig::default();
        let status = super::resolve_sandbox_status_for_request(
            &config.resolve_request(
                Some(true),
                Some(true),
                Some(true),
                Some(FilesystemIsolationMode::WorkspaceOnly),
                None,
            ),
            Path::new("/workspace"),
        )
        .with_invocation(Path::new("/workspace"));

        if let Some(launcher) =
            build_linux_sandbox_command("printf hi", Path::new("/workspace"), &status)
        {
            assert_eq!(launcher.program, "unshare");
            assert!(launcher.args.iter().any(|arg| arg == "--mount"));
            assert!(launcher.args.iter().any(|arg| arg == "--net") == status.network_active);
            assert!(launcher
                .env
                .iter()
                .any(|(key, value)| key == "CLAWD_SANDBOX_MEMORY_LIMIT_BYTES"
                    && value == &DEFAULT_MEMORY_LIMIT_BYTES.to_string()));
            assert!(launcher
                .env
                .iter()
                .any(|(key, _)| key == "CLAWD_SANDBOX_CGROUP_ACTIVE"));
            assert!(launcher
                .env
                .iter()
                .any(|(key, _)| key == "CLAWD_SANDBOX_INVOCATION_ID"));
            if status.overlayfs_active {
                assert!(launcher
                    .env
                    .iter()
                    .any(|(key, _)| key == "CLAWD_SANDBOX_OVERLAY_UPPER"));
                assert!(launcher
                    .args
                    .iter()
                    .any(|arg| arg.contains("mount -t overlay overlay")));
            }
        }
    }

    #[test]
    fn overlay_plan_keeps_writes_in_temp_layer_until_merge() {
        let workspace = Path::new("/workspace/project");
        let layer = Path::new("/tmp/clawd-overlay/test");
        let plan = build_overlayfs_plan(workspace, layer);

        assert_eq!(plan.lower_dir, workspace.to_path_buf());
        assert_eq!(plan.upper_dir, layer.join("upper"));
        assert_eq!(plan.work_dir, layer.join("work"));
        assert_eq!(plan.merged_dir, layer.join("merged"));
        assert!(plan.mount_options().contains("lowerdir=/workspace/project"));
        assert_eq!(
            default_overlay_root(workspace),
            default_overlay_root(workspace),
            "overlay layer path should be stable per workspace for cleanup"
        );
    }

    #[test]
    fn invocation_paths_are_unique_per_tool_call() {
        let status = SandboxConfig::default().resolve_request(
            Some(true),
            Some(false),
            Some(false),
            None,
            None,
        );
        let first = super::resolve_sandbox_status_for_request(&status, Path::new("/workspace"))
            .with_invocation(Path::new("/workspace"));
        let second = super::resolve_sandbox_status_for_request(&status, Path::new("/workspace"))
            .with_invocation(Path::new("/workspace"));

        let first_invocation = first.invocation.expect("first invocation");
        let second_invocation = second.invocation.expect("second invocation");
        assert_ne!(first_invocation.id, second_invocation.id);
        assert_ne!(first_invocation.root_dir, second_invocation.root_dir);
        assert!(first_invocation.root_dir.ends_with(&first_invocation.id));
        assert_ne!(first_invocation.root_dir, Path::new("/workspace"));
    }
}
