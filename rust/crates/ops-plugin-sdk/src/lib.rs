use std::collections::BTreeMap;
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
    std::fs::create_dir_all(root)?;
    let canonical_root = std::fs::canonicalize(root)?;
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
            std::fs::create_dir_all(parent)?;
            if !std::fs::canonicalize(parent)?.starts_with(&canonical_root) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("scaffold path `{}` escapes through a symlink", file.path),
                ));
            }
        }
        std::fs::write(&path, file.contents.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = if file.executable { 0o755 } else { 0o644 };
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        }
        written.push(path);
    }
    Ok(written)
}

pub fn generate_scaffold(request: &ScaffoldRequest) -> ScaffoldOutput {
    match request.language {
        SdkLanguage::Python => python_scaffold(request),
        SdkLanguage::Rust => rust_scaffold(request),
    }
}

fn manifest_template(request: &ScaffoldRequest) -> String {
    let command = match request.language {
        SdkLanguage::Python => "./run.py",
        SdkLanguage::Rust => "./run.sh",
    };
    serde_json::to_string_pretty(&serde_json::json!({
        "name": request.plugin_name,
        "version": "0.1.0",
        "description": "Operations plugin scaffold",
        "executionPolicy": {
            "allowExternalSubprocess": true,
            "reason": "Generated plugin entrypoint runs inside the required Kylin Linux sandbox"
        },
        "permissions": [manifest_permission_for_tool(&request.required_permission)],
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
                "properties": {},
                "additionalProperties": true
            },
            "command": command,
            "requiredPermission": request.required_permission
        }],
        "opsPermissions": [{
            "permission": request.required_permission,
            "scope": format!("ops.{}", request.plugin_name),
            "risk": "low",
            "reason": "Scaffolded permission declaration",
            "rollbackRequired": false
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
                    "#!/usr/bin/env python3",
                    "import json",
                    "import sys",
                    "",
                    "def main():",
                    "    payload = json.load(sys.stdin)",
                    "    print(json.dumps({\"status\": \"ok\", \"input\": payload}))",
                    "",
                    "if __name__ == \"__main__\":",
                    "    main()",
                    "",
                ]
                .join("\n"),
                executable: true,
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
                    "[package]\nname = \"{}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
                    request.plugin_name.replace('_', "-")
                ),
                executable: false,
            },
            ScaffoldFile {
                path: "run.sh".to_string(),
                contents: [
                    "#!/bin/sh",
                    "set -eu",
                    "DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)",
                    "cargo run --quiet --manifest-path \"$DIR/Cargo.toml\"",
                    "",
                ]
                .join("\n"),
                executable: true,
            },
            ScaffoldFile {
                path: "src/main.rs".to_string(),
                contents: [
                    "use std::io::{self, Read};",
                    "",
                    "fn main() {",
                    "    let mut input = String::new();",
                    "    io::stdin().read_to_string(&mut input).expect(\"read stdin\");",
                    "    println!(\"{input}\");",
                    "}",
                    "",
                ]
                .join("\n"),
                executable: false,
            },
        ],
    }
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
        assert!(manifest.contents.contains("\"opsPermissions\""));
        assert!(manifest.contents.contains("\"inputSchema\""));
        assert!(manifest.contents.contains("\"prompts\""));
        assert!(manifest.contents.contains("\"executionPolicy\""));
        let runner = output
            .files
            .iter()
            .find(|file| file.path == "run.py")
            .expect("python runner");
        assert!(runner.contents.starts_with("#!/usr/bin/env python3\n"));
        assert!(runner.executable);
    }

    #[test]
    fn rust_scaffold_uses_cargo_binary_and_start_script() {
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
        assert!(paths.contains(&"run.sh"));
        assert!(!paths.contains(&"run.cmd"));
        let manifest = output
            .files
            .iter()
            .find(|file| file.path == "plugin.json")
            .expect("manifest should exist");
        assert!(manifest.contents.contains("\"command\": \"./run.sh\""));
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
        assert!(written.iter().any(|path| path.ends_with("run.sh")));
        assert!(!root.join("run.cmd").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(root.join("run.sh"))
                .expect("metadata")
                .permissions()
                .mode();
            assert_ne!(mode & 0o111, 0);
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
