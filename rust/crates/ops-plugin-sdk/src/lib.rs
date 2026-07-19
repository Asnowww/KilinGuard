use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::thread;

use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::json;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SdkLanguage {
    Python,
    Rust,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldRequest {
    pub language: SdkLanguage,
    pub plugin_name: String,
    pub tool_name: String,
    pub required_permission: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldFile {
    pub path: String,
    pub contents: String,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaffoldOutput {
    pub files: Vec<ScaffoldFile>,
}

pub fn write_scaffold(root: &Path, output: &ScaffoldOutput) -> std::io::Result<Vec<PathBuf>> {
    let canonical_root = prepare_scaffold_root(root)?;
    let mut written = Vec::new();
    for file in &output.files {
        let relative = Path::new(&file.path);
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("scaffold path `{}` escapes the destination", file.path),
            ));
        }
        let path = canonical_root.join(relative);
        if let Some(parent) = path.parent() {
            create_scaffold_parent_dirs(&canonical_root, parent)?;
        }
        write_scaffold_file(&path, file.contents.as_bytes(), file.executable)?;
        written.push(path);
    }
    Ok(written)
}

fn prepare_scaffold_root(root: &Path) -> std::io::Result<PathBuf> {
    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    let mut missing = Vec::new();
    let mut cursor = absolute.as_path();
    while !cursor.exists() {
        missing.push(cursor.to_path_buf());
        cursor = cursor.parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "scaffold destination has no existing parent",
            )
        })?;
    }
    ensure_safe_scaffold_dir(cursor)?;
    for path in missing.iter().rev() {
        fs::create_dir(path)?;
        ensure_safe_scaffold_dir(path)?;
    }
    let canonical = fs::canonicalize(&absolute)?;
    ensure_safe_scaffold_dir(&canonical)?;
    Ok(canonical)
}

fn create_scaffold_parent_dirs(root: &Path, parent: &Path) -> std::io::Result<()> {
    if parent == root {
        return Ok(());
    }
    let relative = parent.strip_prefix(root).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "scaffold parent escapes destination root",
        )
    })?;
    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "scaffold parent contains unsupported path component",
            ));
        };
        cursor.push(name);
        if cursor.exists() {
            ensure_safe_scaffold_dir(&cursor)?;
        } else {
            fs::create_dir(&cursor)?;
            ensure_safe_scaffold_dir(&cursor)?;
        }
    }
    if !fs::canonicalize(parent)?.starts_with(root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "scaffold parent escapes through a symlink",
        ));
    }
    Ok(())
}

fn write_scaffold_file(path: &Path, contents: &[u8], executable: bool) -> std::io::Result<()> {
    if path.exists() {
        ensure_safe_scaffold_file(path)?;
        let existing = fs::read(path)?;
        if existing == contents {
            set_scaffold_permissions(path, executable)?;
            return Ok(());
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "scaffold file `{}` already exists with different contents",
                path.display()
            ),
        ));
    }

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "scaffold file requires a parent directory",
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "scaffold file name must be valid UTF-8",
            )
        })?;
    let temp = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        unique_scaffold_id()
    ));
    let cleanup = TempScaffoldFile { path: temp.clone() };
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    set_scaffold_permissions(&temp, executable)?;
    match fs::hard_link(&temp, path) {
        Ok(()) => {
            cleanup.disarm();
            fs::remove_file(&temp)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure_safe_scaffold_file(path)?;
            let existing = fs::read(path)?;
            if existing == contents {
                set_scaffold_permissions(path, executable)?;
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "scaffold file `{}` already exists with different contents",
                        path.display()
                    ),
                ))
            }
        }
        Err(error) => Err(error),
    }
}

struct TempScaffoldFile {
    path: PathBuf,
}

impl TempScaffoldFile {
    fn disarm(&self) {}
}

impl Drop for TempScaffoldFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn unique_scaffold_id() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

fn ensure_safe_scaffold_dir(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) || !metadata.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "scaffold directory `{}` must be a real directory",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn ensure_safe_scaffold_file(path: &Path) -> std::io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("scaffold file `{}` must be a regular file", path.display()),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn set_scaffold_permissions(path: &Path, executable: bool) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = if executable { 0o755 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, executable);
    }
    Ok(())
}

pub fn generate_scaffold(request: &ScaffoldRequest) -> ScaffoldOutput {
    match request.language {
        SdkLanguage::Python => python_scaffold(request),
        SdkLanguage::Rust => rust_scaffold(request),
    }
}

fn manifest_template(request: &ScaffoldRequest) -> String {
    let (command, tool_args, mcp_command, mcp_args, process_commands) = match request.language {
        SdkLanguage::Python => (
            "/usr/bin/python3",
            vec!["./run.py"],
            "/usr/bin/python3",
            vec!["./mcp.py"],
            vec!["python3"],
        ),
        SdkLanguage::Rust => (
            "./bin/tool",
            Vec::new(),
            "./bin/mcp",
            Vec::new(),
            vec!["./bin/tool", "./bin/mcp"],
        ),
    };
    let mut permissions = vec![Value::String("read".to_string())];
    let manifest_permission = manifest_permission_for_tool(&request.required_permission);
    if manifest_permission != "read" {
        permissions.push(Value::String(manifest_permission.to_string()));
    }
    permissions.push(serde_json::json!({
        "type": "process",
        "commands": process_commands
    }));
    if matches!(
        request.required_permission.as_str(),
        "workspace-write" | "danger-full-access"
    ) {
        permissions.push(serde_json::json!({
            "type": "filesystem",
            "paths": ["."],
            "mode": if request.required_permission == "workspace-write" { "read-write" } else { "read" }
        }));
    }
    serde_json::to_string_pretty(&serde_json::json!({
        "schemaVersion": 1,
        "name": request.plugin_name,
        "version": "0.1.0",
        "description": "Operations plugin scaffold",
        "manifestMetadata": {
            "sourceOnly": matches!(request.language, SdkLanguage::Rust),
            "buildRequired": matches!(request.language, SdkLanguage::Rust),
            "registrationReady": !matches!(request.language, SdkLanguage::Rust)
        },
        "executionPolicy": {
            "allowExternalSubprocess": true,
            "reason": "Generated plugin entrypoint runs inside the required Kylin Linux sandbox"
        },
        "permissions": permissions,
        "capabilities": {
            "tools": true,
            "resources": false,
            "prompts": true,
            "workflows": true,
            "hotReload": true
        },
        "tools": [{
            "name": request.tool_name,
            "description": "Scaffolded operations tool",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": { "type": "string", "enum": ["inspect", "plan"] },
                    "target": { "type": "string", "maxLength": 256 }
                },
                "additionalProperties": false
            },
            "outputSchema": {
                "type": "object",
                "required": ["schema", "status", "audit"],
                "properties": {
                    "schema": { "type": "string", "enum": ["claw.plugin.tool.output.v1"] },
                    "status": { "type": "string", "enum": ["ok", "unsupported", "error"] },
                    "audit": {
                        "type": "object",
                        "required": ["mutationPerformed", "shell"],
                        "properties": {
                            "mutationPerformed": { "type": "boolean" },
                            "shell": { "type": "boolean" },
                            "stdoutTruncated": { "type": "boolean" },
                            "stderrTruncated": { "type": "boolean" }
                        },
                        "additionalProperties": false
                    },
                    "input": { "type": ["object", "null"] },
                    "error": { "type": ["object", "null"] }
                },
                "additionalProperties": false
            },
            "command": command,
            "args": tool_args,
            "requiredPermission": request.required_permission
        }],
        "mcpServers": {
            "scaffold": {
                "transport": "stdio",
                "requiredPermission": "read-only",
                "command": mcp_command,
                "args": mcp_args,
                "heartbeat": { "intervalMs": 30000, "timeoutMs": 5000 },
                "capabilities": {
                    "tools": [{
                        "name": format!("{}_mcp", request.tool_name),
                        "description": "Read-only scaffolded MCP tool",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": false
                        },
                        "outputSchema": {
                            "type": "object",
                            "required": ["schema", "status", "audit"],
                            "properties": {
                                "schema": { "type": "string", "enum": ["claw.plugin.mcp.output.v1"] },
                                "status": { "type": "string", "enum": ["ok", "unsupported", "error"] },
                                "audit": {
                                    "type": "object",
                                    "required": ["mutationPerformed", "shell"],
                                    "properties": {
                                        "mutationPerformed": { "type": "boolean" },
                                        "shell": { "type": "boolean" }
                                    },
                                    "additionalProperties": false
                                }
                            },
                            "additionalProperties": false
                        }
                    }]
                }
            }
        },
        "opsPermissions": [{
            "permission": request.required_permission,
            "scope": format!("ops.{}", request.plugin_name),
            "risk": scaffold_risk(&request.required_permission),
            "reason": "Scaffolded permission declaration",
            "rollbackRequired": request.required_permission != "read-only",
            "rollbackCommand": if request.required_permission == "read-only" {
                Value::Null
            } else {
                Value::String("implement a deterministic rollback checkpoint before enabling mutation".to_string())
            }
        }],
        "prompts": [{
            "name": format!("{}_operator_prompt", request.tool_name),
            "description": "Prompt template for operator review",
            "arguments": [{
                "name": "target",
                "required": false,
                "schema": { "type": "string" }
            }]
        }]
    }))
    .expect("scaffold manifest uses serializable values")
}

fn manifest_permission_for_tool(required_permission: &str) -> &'static str {
    match required_permission {
        "read-only" => "read",
        "workspace-write" => "write",
        "danger-full-access" => "execute",
        _ => "read",
    }
}

fn scaffold_risk(required_permission: &str) -> &'static str {
    match required_permission {
        "danger-full-access" => "high",
        "workspace-write" => "medium",
        _ => "low",
    }
}

fn python_scaffold(request: &ScaffoldRequest) -> ScaffoldOutput {
    ScaffoldOutput {
        files: vec![
            ScaffoldFile {
                path: "plugin.json".to_string(),
                contents: manifest_template(request),
                executable: false,
            },
            ScaffoldFile {
                path: "run.py".to_string(),
                contents: [
                    "import json",
                    "import sys",
                    "",
                    "def main():",
                    "    payload = json.load(sys.stdin)",
                    "    print(json.dumps({",
                    "        \"schema\": \"claw.plugin.tool.output.v1\",",
                    "        \"status\": \"ok\",",
                    "        \"input\": payload,",
                    "        \"audit\": {\"mutationPerformed\": False, \"shell\": False},",
                    "    }, separators=(\",\", \":\")))",
                    "",
                    "if __name__ == \"__main__\":",
                    "    main()",
                    "",
                ]
                .join("\n"),
                executable: false,
            },
            ScaffoldFile {
                path: "mcp.py".to_string(),
                contents: python_mcp_scaffold(request),
                executable: false,
            },
            ScaffoldFile {
                path: "tests/test_contract.py".to_string(),
                contents: [
                    "import json",
                    "import subprocess",
                    "import sys",
                    "from pathlib import Path",
                    "",
                    "ROOT = Path(__file__).resolve().parents[1]",
                    "",
                    "def test_tool_output_contract():",
                    "    proc = subprocess.run(",
                    "        [sys.executable, str(ROOT / 'run.py')],",
                    "        input=json.dumps({'action': 'inspect'}),",
                    "        text=True,",
                    "        capture_output=True,",
                    "        check=True,",
                    "        timeout=5,",
                    "    )",
                    "    payload = json.loads(proc.stdout)",
                    "    assert payload['schema'] == 'claw.plugin.tool.output.v1'",
                    "    assert payload['audit']['shell'] is False",
                    "",
                ]
                .join("\n"),
                executable: false,
            },
            ScaffoldFile {
                path: "README_KYLIN.md".to_string(),
                contents: kylin_readme(request),
                executable: false,
            },
        ],
    }
}

fn rust_scaffold(request: &ScaffoldRequest) -> ScaffoldOutput {
    ScaffoldOutput {
        files: vec![
            ScaffoldFile {
                path: "plugin.json".to_string(),
                contents: manifest_template(request),
                executable: false,
            },
            ScaffoldFile {
                path: "Cargo.toml".to_string(),
                contents: format!(
                    "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nserde_json = \"1\"\n\n[[bin]]\nname = \"tool\"\npath = \"src/main.rs\"\n\n[[bin]]\nname = \"mcp\"\npath = \"src/bin/mcp.rs\"\n",
                    request.plugin_name.replace('_', "-")
                ),
                executable: false,
            },
            ScaffoldFile {
                path: "src/main.rs".to_string(),
                contents: [
                    "use std::io::{self, Read};",
                    "use serde_json::{json, Value};",
                    "",
                    "fn main() {",
                    "    let mut input = String::new();",
                    "    io::stdin().read_to_string(&mut input).expect(\"read stdin\");",
                    "    let payload: Value = serde_json::from_str(&input).unwrap_or(Value::Null);",
                    "    println!(\"{}\", json!({",
                    "        \"schema\": \"claw.plugin.tool.output.v1\",",
                    "        \"status\": \"ok\",",
                    "        \"input\": payload,",
                    "        \"audit\": {\"mutationPerformed\": false, \"shell\": false},",
                    "    }));",
                    "}",
                    "",
                ]
                .join("\n"),
                executable: false,
            },
            ScaffoldFile {
                path: "src/bin/mcp.rs".to_string(),
                contents: rust_mcp_scaffold(request),
                executable: false,
            },
            ScaffoldFile {
                path: "bin/tool".to_string(),
                contents: "Build with `cargo build --release --bin tool` and replace this file with target/release/tool before registration.\n".to_string(),
                executable: false,
            },
            ScaffoldFile {
                path: "bin/mcp".to_string(),
                contents: "Build with `cargo build --release --bin mcp` and replace this file with target/release/mcp before registration.\n".to_string(),
                executable: false,
            },
            ScaffoldFile {
                path: "tests/contract.rs".to_string(),
                contents: [
                    "use std::io::Write;",
                    "use std::process::{Command, Stdio};",
                    "",
                    "#[test]",
                    "fn tool_output_contract() {",
                    "    let mut child = Command::new(env!(\"CARGO_BIN_EXE_tool\"))",
                    "        .stdin(Stdio::piped())",
                    "        .stdout(Stdio::piped())",
                    "        .spawn()",
                    "        .expect(\"spawn tool\");",
                    "    child",
                    "        .stdin",
                    "        .as_mut()",
                    "        .expect(\"stdin\")",
                    "        .write_all(br#\"{\"action\":\"inspect\"}\"#)",
                    "        .expect(\"write stdin\");",
                    "    let output = child.wait_with_output().expect(\"wait\");",
                    "    assert!(output.status.success());",
                    "    let payload: serde_json::Value = serde_json::from_slice(&output.stdout).expect(\"json\");",
                    "    assert_eq!(payload[\"schema\"], \"claw.plugin.tool.output.v1\");",
                    "    assert_eq!(payload[\"audit\"][\"shell\"], false);",
                    "}",
                    "",
                ]
                .join("\n"),
                executable: false,
            },
            ScaffoldFile {
                path: "README_KYLIN.md".to_string(),
                contents: kylin_readme(request),
                executable: false,
            },
        ],
    }
}

fn python_mcp_scaffold(request: &ScaffoldRequest) -> String {
    format!(
        r#"import json
import sys

TOOL_NAME = "{tool_name}_mcp"
PLUGIN_NAME = "{plugin_name}"
SUPPORTED_PROTOCOL_VERSIONS = {{"2025-03-26", "2024-11-05"}}
initialize_seen = False
initialized = False

def send(message_id, result=None, error=None):
    response = {{"jsonrpc": "2.0", "id": message_id}}
    if error is None:
        response["result"] = result
    else:
        response["error"] = error
    print(json.dumps(response, separators=(",", ":")), flush=True)

def tool_spec():
    return {{
        "name": TOOL_NAME,
        "description": "Read-only scaffolded MCP tool",
        "inputSchema": {{"type": "object", "properties": {{}}, "additionalProperties": False}},
    }}

def valid_request(message):
    if not isinstance(message, dict):
        return False
    if message.get("jsonrpc") != "2.0":
        return False
    method = message.get("method")
    if not isinstance(method, str):
        return False
    if method.startswith("notifications/"):
        return "id" not in message
    return isinstance(message.get("id"), (str, int))

for raw_line in sys.stdin:
    line = raw_line.rstrip("\n")
    if not line:
        sys.exit(1)
    try:
        message = json.loads(line)
    except json.JSONDecodeError:
        sys.exit(1)
    if not valid_request(message):
        sys.exit(1)
    method = message.get("method")
    message_id = message.get("id")
    if method.startswith("notifications/"):
        if method == "notifications/initialized":
            if not initialize_seen:
                sys.exit(1)
            initialized = True
        continue
    if method == "initialize":
        if initialize_seen:
            send(message_id, error={{"code": -32002, "message": "initialize already completed"}})
            sys.exit(1)
        params = message.get("params")
        if not isinstance(params, dict):
            send(message_id, error={{"code": -32602, "message": "initialize params required"}})
            sys.exit(1)
        requested = params.get("protocolVersion")
        if not isinstance(requested, str) or requested not in SUPPORTED_PROTOCOL_VERSIONS:
            send(message_id, error={{"code": -32002, "message": "unsupported protocol version"}})
            sys.exit(1)
        send(message_id, {{
            "protocolVersion": requested,
            "capabilities": {{"tools": {{}}}},
            "serverInfo": {{"name": PLUGIN_NAME, "version": "0.1.0"}},
        }})
        initialize_seen = True
    elif not initialized:
        send(message_id, error={{"code": -32002, "message": "initialized notification required"}})
    elif method == "ping":
        send(message_id, {{}})
    elif method == "tools/list":
        send(message_id, {{"tools": [tool_spec()]}})
    elif method == "tools/call":
        send(message_id, {{
            "content": [{{
                "type": "text",
                "text": json.dumps({{
                    "schema": "claw.plugin.mcp.output.v1",
                    "status": "ok",
                    "audit": {{"mutationPerformed": False, "shell": False}},
                }}, separators=(",", ":")),
            }}]
        }})
    else:
        send(message_id, error={{"code": -32601, "message": "method not found"}})
"#,
        plugin_name = request.plugin_name,
        tool_name = request.tool_name
    )
}

fn rust_mcp_scaffold(request: &ScaffoldRequest) -> String {
    format!(
        r#"use std::io::BufRead;

use serde_json::{{json, Value}};

const TOOL_NAME: &str = "{tool_name}_mcp";
const PLUGIN_NAME: &str = "{plugin_name}";
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-03-26", "2024-11-05"];

fn send(id: Value, result: Result<Value, Value>) {{
    let response = match result {{
        Ok(result) => json!({{"jsonrpc": "2.0", "id": id, "result": result}}),
        Err(error) => json!({{"jsonrpc": "2.0", "id": id, "error": error}}),
    }};
    println!("{{}}", response);
}}

fn valid_request(message: &Value) -> bool {{
    let Some(object) = message.as_object() else {{
        return false;
    }};
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {{
        return false;
    }}
    let Some(method) = object.get("method").and_then(Value::as_str) else {{
        return false;
    }};
    if method.starts_with("notifications/") {{
        return !object.contains_key("id");
    }}
    matches!(object.get("id"), Some(Value::String(_)) | Some(Value::Number(_)))
}}

fn main() {{
    let stdin = std::io::stdin();
    let mut initialize_seen = false;
    let mut initialized = false;
    for line in stdin.lock().lines() {{
        let line = line.expect("read line");
        if line.is_empty() {{
            std::process::exit(1);
        }}
        let message: Value = serde_json::from_str(&line).unwrap_or_else(|_| std::process::exit(1));
        if !valid_request(&message) {{
            std::process::exit(1);
        }}
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        if method.starts_with("notifications/") {{
            if method == "notifications/initialized" {{
                if !initialize_seen {{
                    std::process::exit(1);
                }}
                initialized = true;
            }}
            continue;
        }}
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let result = match method {{
            "initialize" => {{
                if initialize_seen {{
                    send(id, Err(json!({{"code": -32002, "message": "initialize already completed"}})));
                    std::process::exit(1);
                }}
                let Some(requested) = message
                    .get("params")
                    .and_then(|params| params.get("protocolVersion"))
                    .and_then(Value::as_str)
                else {{
                    send(id, Err(json!({{"code": -32602, "message": "initialize params required"}})));
                    std::process::exit(1);
                }};
                if !SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) {{
                    send(id, Err(json!({{"code": -32002, "message": "unsupported protocol version"}})));
                    std::process::exit(1);
                }}
                initialize_seen = true;
                Ok(json!({{
                    "protocolVersion": requested,
                    "capabilities": {{"tools": {{}}}},
                    "serverInfo": {{"name": PLUGIN_NAME, "version": "0.1.0"}},
                }}))
            }}
            _ if !initialized => Err(json!({{"code": -32002, "message": "initialized notification required"}})),
            "ping" => Ok(json!({{}})),
            "tools/list" => Ok(json!({{
                "tools": [{{
                    "name": TOOL_NAME,
                    "description": "Read-only scaffolded MCP tool",
                    "inputSchema": {{"type": "object", "properties": {{}}, "additionalProperties": false}},
                }}]
            }})),
            "tools/call" => Ok(json!({{
                "content": [{{
                    "type": "text",
                    "text": json!({{
                        "schema": "claw.plugin.mcp.output.v1",
                        "status": "ok",
                        "audit": {{"mutationPerformed": false, "shell": false}},
                    }}).to_string(),
                }}]
            }})),
            _ => Err(json!({{"code": -32601, "message": "method not found"}})),
        }};
        send(id, result);
    }}
}}
"#,
        plugin_name = request.plugin_name,
        tool_name = request.tool_name
    )
}

fn kylin_readme(request: &ScaffoldRequest) -> String {
    format!(
        r#"# {plugin_name}

This generated operations plugin targets Kylin/Linux.

- Tool entrypoints are fixed executable files with explicit argv; do not invoke a shell from plugin code.
- The stdio MCP example uses newline-delimited JSON-RPC and compact single-line responses.
- Permissions are declared in `plugin.json`; undeclared tools, MCP servers, hooks, and lifecycle commands must fail closed during registration.
- Mutating operations should return a plan first, require L3 operator confirmation, and persist enough checkpoint data for rollback.
- Keep stdout/stderr bounded and return JSON matching the declared schemas.
- Rust scaffolds keep Cargo as a build step only: build `tool` and `mcp`, then install the resulting binaries as `bin/tool` and `bin/mcp` before registering the plugin.

Generated tool: `{tool_name}`.
"#,
        plugin_name = request.plugin_name,
        tool_name = request.tool_name
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStepMode {
    Sequential,
    Parallel,
}

impl Default for WorkflowStepMode {
    fn default() -> Self {
        Self::Sequential
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub name: String,
    #[serde(default)]
    pub steps: Vec<WorkflowStep>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowStep {
    pub id: String,
    pub tool: String,
    #[serde(default)]
    pub mode: WorkflowStepMode,
    #[serde(default)]
    pub input: Value,
    #[serde(default)]
    pub input_from: Option<WorkflowInputSource>,
    #[serde(default)]
    pub rollback: Option<WorkflowRollbackStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowInputSource {
    pub step_id: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub target_field: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowRollbackStep {
    pub id: String,
    pub tool: String,
    #[serde(default)]
    pub input: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowCheckpoint {
    pub next_index: usize,
    pub completed: BTreeMap<String, Value>,
    pub failed_step: Option<String>,
    pub rollback_plan: Vec<WorkflowRollbackStep>,
    #[serde(default)]
    pub rollback_results: Vec<WorkflowRollbackResult>,
}

impl Default for WorkflowCheckpoint {
    fn default() -> Self {
        Self {
            next_index: 0,
            completed: BTreeMap::new(),
            failed_step: None,
            rollback_plan: Vec::new(),
            rollback_results: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowRollbackResult {
    pub id: String,
    pub tool: String,
    pub succeeded: bool,
    pub output: Option<Value>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatus {
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowRunResult {
    pub status: WorkflowStatus,
    pub outputs: BTreeMap<String, Value>,
    pub checkpoint: WorkflowCheckpoint,
    pub error: Option<String>,
}

type ToolHandler = Arc<dyn Fn(Value) -> Result<Value, String> + Send + Sync>;

#[derive(Clone, Default)]
pub struct WorkflowRunner {
    handlers: BTreeMap<String, ToolHandler>,
}

impl WorkflowRunner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_tool(
        &mut self,
        name: impl Into<String>,
        handler: impl Fn(Value) -> Result<Value, String> + Send + Sync + 'static,
    ) {
        self.handlers.insert(name.into(), Arc::new(handler));
    }

    pub fn run(&self, workflow: &WorkflowDefinition) -> WorkflowRunResult {
        self.resume(workflow, WorkflowCheckpoint::default())
    }

    pub fn resume(
        &self,
        workflow: &WorkflowDefinition,
        checkpoint: WorkflowCheckpoint,
    ) -> WorkflowRunResult {
        let mut state = checkpoint;
        if state.next_index > workflow.steps.len() {
            let next_index = state.next_index;
            let step_count = workflow.steps.len();
            state.failed_step = None;
            return failed_result(
                state,
                format!(
                    "checkpoint next_index {} exceeds workflow step count {}",
                    next_index, step_count
                ),
            );
        }
        state.failed_step = None;
        let mut index = state.next_index;

        while index < workflow.steps.len() {
            if workflow.steps[index].mode == WorkflowStepMode::Parallel {
                let end = workflow.steps[index..]
                    .iter()
                    .position(|step| step.mode != WorkflowStepMode::Parallel)
                    .map_or(workflow.steps.len(), |offset| index + offset);
                match self.run_parallel_group(&workflow.steps[index..end], &state.completed) {
                    Ok(outputs) => {
                        for (step_id, output, rollback) in outputs {
                            state.completed.insert(step_id, output);
                            if let Some(rollback) = rollback {
                                state.rollback_plan.insert(0, rollback);
                            }
                        }
                        index = end;
                        state.next_index = index;
                    }
                    Err((step_id, error, partial_outputs)) => {
                        for (step_id, output, rollback) in partial_outputs {
                            state.completed.insert(step_id, output);
                            if let Some(rollback) = rollback {
                                state.rollback_plan.insert(0, rollback);
                            }
                        }
                        state.failed_step = Some(step_id);
                        state.next_index = index;
                        return failed_result(state, error);
                    }
                }
                continue;
            }

            let step = &workflow.steps[index];
            if state.completed.contains_key(&step.id) {
                index += 1;
                state.next_index = index;
                continue;
            }

            match self.run_step(step, &state.completed) {
                Ok(output) => {
                    state.completed.insert(step.id.clone(), output);
                    if let Some(rollback) = &step.rollback {
                        state.rollback_plan.insert(0, rollback.clone());
                    }
                    index += 1;
                    state.next_index = index;
                }
                Err(error) => {
                    state.failed_step = Some(step.id.clone());
                    state.next_index = index;
                    return failed_result(state, error);
                }
            }
        }

        WorkflowRunResult {
            status: WorkflowStatus::Completed,
            outputs: state.completed.clone(),
            checkpoint: state,
            error: None,
        }
    }

    pub fn rollback(&self, checkpoint: &WorkflowCheckpoint) -> Vec<Result<Value, String>> {
        checkpoint
            .rollback_plan
            .iter()
            .map(|step| {
                self.handlers
                    .get(&step.tool)
                    .ok_or_else(|| format!("missing rollback tool `{}`", step.tool))
                    .and_then(|handler| handler(step.input.clone()))
            })
            .collect()
    }

    pub fn rollback_and_record(
        &self,
        checkpoint: &mut WorkflowCheckpoint,
    ) -> Vec<WorkflowRollbackResult> {
        let results = checkpoint
            .rollback_plan
            .iter()
            .map(|step| {
                let result = self
                    .handlers
                    .get(&step.tool)
                    .ok_or_else(|| format!("missing rollback tool `{}`", step.tool))
                    .and_then(|handler| handler(step.input.clone()));
                match result {
                    Ok(output) => WorkflowRollbackResult {
                        id: step.id.clone(),
                        tool: step.tool.clone(),
                        succeeded: true,
                        output: Some(output),
                        error: None,
                    },
                    Err(error) => WorkflowRollbackResult {
                        id: step.id.clone(),
                        tool: step.tool.clone(),
                        succeeded: false,
                        output: None,
                        error: Some(error),
                    },
                }
            })
            .collect::<Vec<_>>();
        checkpoint.rollback_results.extend(results.clone());
        results
    }

    fn run_parallel_group(
        &self,
        steps: &[WorkflowStep],
        completed: &BTreeMap<String, Value>,
    ) -> Result<
        Vec<(String, Value, Option<WorkflowRollbackStep>)>,
        (
            String,
            String,
            Vec<(String, Value, Option<WorkflowRollbackStep>)>,
        ),
    > {
        let mut prepared = Vec::new();
        for step in steps {
            if completed.contains_key(&step.id) {
                continue;
            }
            let handler = self.handlers.get(&step.tool).cloned().ok_or_else(|| {
                (
                    step.id.clone(),
                    format!("missing tool `{}`", step.tool),
                    Vec::new(),
                )
            })?;
            let input = prepare_input(step, completed)
                .map_err(|error| (step.id.clone(), error, Vec::new()))?;
            prepared.push((step.id.clone(), handler, input, step.rollback.clone()));
        }

        let mut handles = Vec::new();
        for (step_id, handler, input, rollback) in prepared {
            handles.push(thread::spawn(move || {
                let result = handler(input);
                (step_id, result, rollback)
            }));
        }

        let mut outputs = Vec::new();
        let mut failure: Option<(String, String)> = None;
        for handle in handles {
            let (step_id, result, rollback) = match handle.join() {
                Ok(value) => value,
                Err(_) => {
                    if failure.is_none() {
                        failure =
                            Some(("parallel".to_string(), "parallel step panicked".to_string()));
                    }
                    continue;
                }
            };
            match result {
                Ok(output) => outputs.push((step_id, output, rollback)),
                Err(error) => {
                    if failure.is_none() {
                        failure = Some((step_id, error));
                    }
                }
            }
        }
        if let Some((step_id, error)) = failure {
            return Err((step_id, error, outputs));
        }
        Ok(outputs)
    }

    fn run_step(
        &self,
        step: &WorkflowStep,
        completed: &BTreeMap<String, Value>,
    ) -> Result<Value, String> {
        let input = prepare_input(step, completed)?;
        let handler = self
            .handlers
            .get(&step.tool)
            .ok_or_else(|| format!("missing tool `{}`", step.tool))?;
        handler(input)
    }
}

fn failed_result(checkpoint: WorkflowCheckpoint, error: String) -> WorkflowRunResult {
    WorkflowRunResult {
        status: WorkflowStatus::Failed,
        outputs: checkpoint.completed.clone(),
        checkpoint,
        error: Some(error),
    }
}

fn prepare_input(
    step: &WorkflowStep,
    completed: &BTreeMap<String, Value>,
) -> Result<Value, String> {
    let Some(source) = &step.input_from else {
        return Ok(step.input.clone());
    };
    let output = completed.get(&source.step_id).ok_or_else(|| {
        format!(
            "step `{}` requires output from incomplete step `{}`",
            step.id, source.step_id
        )
    })?;
    let selected = select_path(output, source.path.as_deref())?;

    if let Some(target_field) = &source.target_field {
        let mut input = match step.input.clone() {
            Value::Object(map) => map,
            Value::Null => Map::new(),
            other => {
                return Err(format!(
                    "step `{}` targetField requires object input, got {other}",
                    step.id
                ));
            }
        };
        input.insert(target_field.clone(), selected);
        Ok(Value::Object(input))
    } else {
        Ok(selected)
    }
}

fn select_path(value: &Value, path: Option<&str>) -> Result<Value, String> {
    let Some(path) = path.filter(|path| !path.trim().is_empty()) else {
        return Ok(value.clone());
    };
    let mut cursor = value;
    for segment in path.split('.') {
        cursor = cursor
            .get(segment)
            .ok_or_else(|| format!("missing output path segment `{segment}` in `{path}`"))?;
    }
    Ok(cursor.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_contains_manifest_permissions_and_schema() {
        let output = generate_scaffold(&ScaffoldRequest {
            language: SdkLanguage::Python,
            plugin_name: "ops_demo".to_string(),
            tool_name: "inspect".to_string(),
            required_permission: "read-only".to_string(),
        });
        let manifest = output
            .files
            .iter()
            .find(|file| file.path == "plugin.json")
            .expect("manifest should exist");
        let manifest_json: Value =
            serde_json::from_str(&manifest.contents).expect("manifest json should parse");
        assert_eq!(manifest_json["schemaVersion"], 1);
        assert!(manifest.contents.contains("\"opsPermissions\""));
        assert!(manifest.contents.contains("\"inputSchema\""));
        assert!(manifest.contents.contains("\"outputSchema\""));
        assert!(manifest.contents.contains("\"mcpServers\""));
        assert!(manifest.contents.contains("\"prompts\""));
        assert!(manifest.contents.contains("\"executionPolicy\""));
        let runner = output
            .files
            .iter()
            .find(|file| file.path == "run.py")
            .expect("python runner");
        assert!(!runner.contents.starts_with("#!"));
        assert!(!runner.executable);
        assert_eq!(manifest_json["tools"][0]["command"], "/usr/bin/python3");
        assert_eq!(manifest_json["tools"][0]["args"][0], "./run.py");
        assert!(output
            .files
            .iter()
            .any(|file| file.path == "mcp.py" && !file.executable));
        let mcp = output
            .files
            .iter()
            .find(|file| file.path == "mcp.py")
            .expect("python mcp");
        assert!(mcp.contents.contains("SUPPORTED_PROTOCOL_VERSIONS"));
        assert!(mcp.contents.contains("initialized notification required"));
        assert!(output
            .files
            .iter()
            .any(|file| file.path == "tests/test_contract.py"));
        assert!(output
            .files
            .iter()
            .any(|file| file.path == "README_KYLIN.md"));
    }

    #[test]
    fn rust_scaffold_uses_fixed_built_binaries_and_cargo_build_step() {
        let output = generate_scaffold(&ScaffoldRequest {
            language: SdkLanguage::Rust,
            plugin_name: "ops_demo".to_string(),
            tool_name: "inspect".to_string(),
            required_permission: "read-only".to_string(),
        });
        let paths = output
            .files
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>();
        assert!(paths.contains(&"Cargo.toml"));
        assert!(paths.contains(&"src/main.rs"));
        assert!(paths.contains(&"src/bin/mcp.rs"));
        assert!(paths.contains(&"bin/tool"));
        assert!(paths.contains(&"bin/mcp"));
        assert!(paths.contains(&"tests/contract.rs"));
        assert!(!paths.contains(&"run.sh"));
        assert!(!paths.contains(&"mcp.sh"));
        assert!(!paths.contains(&"run.cmd"));
        let manifest = output
            .files
            .iter()
            .find(|file| file.path == "plugin.json")
            .expect("manifest should exist");
        let manifest_json: Value =
            serde_json::from_str(&manifest.contents).expect("manifest json should parse");
        assert_eq!(manifest_json["tools"][0]["command"], "./bin/tool");
        assert_eq!(manifest_json["manifestMetadata"]["sourceOnly"], true);
        assert_eq!(manifest_json["manifestMetadata"]["buildRequired"], true);
        assert_eq!(
            manifest_json["manifestMetadata"]["registrationReady"],
            false
        );
        assert_eq!(
            manifest_json["tools"][0]["args"]
                .as_array()
                .expect("args array")
                .len(),
            0
        );
        assert_eq!(
            manifest_json["mcpServers"]["scaffold"]["command"],
            "./bin/mcp"
        );
        let mcp = output
            .files
            .iter()
            .find(|file| file.path == "src/bin/mcp.rs")
            .expect("mcp source");
        assert!(mcp.contents.contains("SUPPORTED_PROTOCOL_VERSIONS"));
        assert!(mcp.contents.contains("initialized notification required"));
    }

    #[test]
    fn scaffold_marks_danger_permission_high_risk_with_rollback_required() {
        let output = generate_scaffold(&ScaffoldRequest {
            language: SdkLanguage::Python,
            plugin_name: "danger_ops".to_string(),
            tool_name: "mutate".to_string(),
            required_permission: "danger-full-access".to_string(),
        });
        let manifest = output
            .files
            .iter()
            .find(|file| file.path == "plugin.json")
            .expect("manifest should exist");
        let manifest_json: Value =
            serde_json::from_str(&manifest.contents).expect("manifest json should parse");
        assert_eq!(manifest_json["opsPermissions"][0]["risk"], "high");
        assert_eq!(manifest_json["opsPermissions"][0]["rollbackRequired"], true);
        assert!(manifest_json["opsPermissions"][0]["rollbackCommand"].is_string());
    }

    #[test]
    fn write_scaffold_rejects_traversal_and_materializes_entrypoint() {
        let root = std::env::temp_dir().join(format!(
            "ops-plugin-sdk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let output = generate_scaffold(&ScaffoldRequest {
            language: SdkLanguage::Rust,
            plugin_name: "ops_demo".to_string(),
            tool_name: "inspect".to_string(),
            required_permission: "read-only".to_string(),
        });
        let written = write_scaffold(&root, &output).expect("write scaffold");
        assert!(written.iter().any(|path| path.ends_with("Cargo.toml")));
        assert!(!root.join("run.cmd").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(root.join("src").join("main.rs"))
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o111, 0);
        }

        let escaped = ScaffoldOutput {
            files: vec![ScaffoldFile {
                path: "../escape".to_string(),
                contents: String::new(),
                executable: false,
            }],
        };
        assert!(write_scaffold(&root, &escaped).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn write_scaffold_is_idempotent_and_conflicts_on_different_contents() {
        let root = std::env::temp_dir().join(format!(
            "ops-plugin-sdk-idempotent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let output = generate_scaffold(&ScaffoldRequest {
            language: SdkLanguage::Python,
            plugin_name: "ops_demo".to_string(),
            tool_name: "inspect".to_string(),
            required_permission: "read-only".to_string(),
        });
        write_scaffold(&root, &output).expect("first write");
        write_scaffold(&root, &output).expect("same scaffold should be a no-op");

        let mut changed = output.clone();
        changed.files[0].contents.push('\n');
        let error = write_scaffold(&root, &changed).expect_err("different contents should fail");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn write_scaffold_rejects_symlink_destination_root() {
        use std::os::unix::fs::symlink;

        let base = std::env::temp_dir().join(format!(
            "ops-plugin-sdk-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let real = base.join("real");
        let link = base.join("link");
        std::fs::create_dir_all(&real).expect("real dir");
        symlink(&real, &link).expect("symlink");
        let output = generate_scaffold(&ScaffoldRequest {
            language: SdkLanguage::Python,
            plugin_name: "ops_demo".to_string(),
            tool_name: "inspect".to_string(),
            required_permission: "read-only".to_string(),
        });
        let error = write_scaffold(&link, &output).expect_err("symlink root should fail");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn workflow_pipes_previous_output_into_next_step() {
        let mut runner = WorkflowRunner::new();
        runner.register_tool("first", |_| Ok(json!({"value": 41})));
        runner.register_tool("second", |input| {
            Ok(json!({"value": input["n"].as_i64().unwrap_or_default() + 1}))
        });

        let workflow = WorkflowDefinition {
            name: "pipe".to_string(),
            steps: vec![
                WorkflowStep {
                    id: "a".to_string(),
                    tool: "first".to_string(),
                    mode: WorkflowStepMode::Sequential,
                    input: Value::Null,
                    input_from: None,
                    rollback: None,
                },
                WorkflowStep {
                    id: "b".to_string(),
                    tool: "second".to_string(),
                    mode: WorkflowStepMode::Sequential,
                    input: json!({}),
                    input_from: Some(WorkflowInputSource {
                        step_id: "a".to_string(),
                        path: Some("value".to_string()),
                        target_field: Some("n".to_string()),
                    }),
                    rollback: None,
                },
            ],
        };

        let result = runner.run(&workflow);
        assert_eq!(result.status, WorkflowStatus::Completed);
        assert_eq!(result.outputs["b"]["value"], 42);
    }

    #[test]
    fn workflow_failure_checkpoint_can_resume_and_preserves_rollback_plan() {
        let mut failing_runner = WorkflowRunner::new();
        failing_runner.register_tool("ok", |_| Ok(json!({"token": "checkpoint"})));
        failing_runner.register_tool("fail", |_| Err("boom".to_string()));
        failing_runner.register_tool("undo", |_| Ok(json!({"rolledBack": true})));

        let workflow = WorkflowDefinition {
            name: "resume".to_string(),
            steps: vec![
                WorkflowStep {
                    id: "prepare".to_string(),
                    tool: "ok".to_string(),
                    mode: WorkflowStepMode::Sequential,
                    input: Value::Null,
                    input_from: None,
                    rollback: Some(WorkflowRollbackStep {
                        id: "undo_prepare".to_string(),
                        tool: "undo".to_string(),
                        input: json!({"step": "prepare"}),
                    }),
                },
                WorkflowStep {
                    id: "apply".to_string(),
                    tool: "fail".to_string(),
                    mode: WorkflowStepMode::Sequential,
                    input: json!({}),
                    input_from: Some(WorkflowInputSource {
                        step_id: "prepare".to_string(),
                        path: Some("token".to_string()),
                        target_field: Some("token".to_string()),
                    }),
                    rollback: None,
                },
            ],
        };

        let failed = failing_runner.run(&workflow);
        assert_eq!(failed.status, WorkflowStatus::Failed);
        assert_eq!(failed.checkpoint.failed_step.as_deref(), Some("apply"));
        assert_eq!(failed.checkpoint.rollback_plan.len(), 1);

        let mut resumed_runner = WorkflowRunner::new();
        resumed_runner.register_tool("ok", |_| Ok(json!({"token": "checkpoint"})));
        resumed_runner.register_tool("fail", |input| Ok(json!({"used": input["token"]})));
        resumed_runner.register_tool("undo", |_| Ok(json!({"rolledBack": true})));

        let resumed = resumed_runner.resume(&workflow, failed.checkpoint.clone());
        assert_eq!(resumed.status, WorkflowStatus::Completed);
        assert_eq!(resumed.outputs["apply"]["used"], "checkpoint");

        let rollback = resumed_runner.rollback(&failed.checkpoint);
        assert_eq!(rollback.len(), 1);
        assert!(rollback[0].is_ok());
    }

    #[test]
    fn workflow_parallel_group_runs_all_steps() {
        let mut runner = WorkflowRunner::new();
        runner.register_tool("echo", |input| Ok(input));
        let workflow = WorkflowDefinition {
            name: "parallel".to_string(),
            steps: vec![
                WorkflowStep {
                    id: "left".to_string(),
                    tool: "echo".to_string(),
                    mode: WorkflowStepMode::Parallel,
                    input: json!({"side": "left"}),
                    input_from: None,
                    rollback: None,
                },
                WorkflowStep {
                    id: "right".to_string(),
                    tool: "echo".to_string(),
                    mode: WorkflowStepMode::Parallel,
                    input: json!({"side": "right"}),
                    input_from: None,
                    rollback: None,
                },
            ],
        };

        let result = runner.run(&workflow);
        assert_eq!(result.status, WorkflowStatus::Completed);
        assert_eq!(result.outputs["left"]["side"], "left");
        assert_eq!(result.outputs["right"]["side"], "right");
    }

    #[test]
    fn workflow_rejects_checkpoint_next_index_beyond_step_count() {
        let runner = WorkflowRunner::new();
        let workflow = WorkflowDefinition {
            name: "bounds".to_string(),
            steps: vec![WorkflowStep {
                id: "one".to_string(),
                tool: "missing".to_string(),
                mode: WorkflowStepMode::Sequential,
                input: json!({}),
                input_from: None,
                rollback: None,
            }],
        };
        let checkpoint = WorkflowCheckpoint {
            next_index: 2,
            ..WorkflowCheckpoint::default()
        };

        let result = runner.resume(&workflow, checkpoint);
        assert_eq!(result.status, WorkflowStatus::Failed);
        assert!(result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("exceeds workflow step count")));
    }
}
