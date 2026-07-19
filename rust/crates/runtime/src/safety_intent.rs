//! Structured safety intent extraction and risk scoring for tool execution plans.
//!
//! The entry points in this module accept structured tool call plans. They do
//! not infer intent from free-form natural language.

use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::bash_validation::{classify_command, CommandIntent};

const DEFAULT_MAX_OPERATIONS: usize = 64;
const DEFAULT_MAX_COMPOUND_SEGMENTS: usize = 32;
const DEFAULT_MAX_STRING_BYTES: usize = 4096;
const DEFAULT_MAX_PARAMETER_JSON_BYTES: usize = 65_536;
const DEFAULT_MAX_TARGETS: usize = 32;
const MAX_ALLOWED_OPERATIONS: usize = 1024;
const MAX_ALLOWED_COMPOUND_SEGMENTS: usize = 256;
const MAX_ALLOWED_STRING_BYTES: usize = 65_536;
const MAX_ALLOWED_PARAMETER_JSON_BYTES: usize = 1_048_576;
const MAX_ALLOWED_TARGETS: usize = 1024;
const ERROR_PAYLOAD_PREVIEW_BYTES: usize = 160;

/// A structured execution plan emitted by a model or planner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolExecutionPlan {
    /// Optional structured source label, such as the model response id.
    #[serde(default)]
    pub source: Option<String>,
    /// Ordered tool calls to analyze.
    pub tool_calls: Vec<ToolCallPlan>,
}

/// A single structured tool call in a plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolCallPlan {
    /// Runtime tool name, for example `Bash`, `PowerShell`, or `package_manager`.
    pub tool_name: String,
    /// Optional source label for the individual call.
    #[serde(default)]
    pub source: Option<String>,
    /// JSON arguments passed to the tool.
    #[serde(default)]
    pub arguments: Value,
}

/// Analyzer configuration. Unknown fields are rejected by Serde.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafetyIntentConfig {
    /// Risk factor weights used for the weighted score.
    pub weights: RiskFactorWeights,
    /// Level thresholds in the 0..100 score range.
    pub thresholds: RiskThresholds,
    /// Resource limits for plan analysis.
    pub limits: SafetyIntentLimits,
}

impl Default for SafetyIntentConfig {
    fn default() -> Self {
        Self {
            weights: RiskFactorWeights::default(),
            thresholds: RiskThresholds::default(),
            limits: SafetyIntentLimits::default(),
        }
    }
}

impl SafetyIntentConfig {
    /// Validate administrator-provided safety intent configuration.
    pub fn validate(&self) -> Result<(), SafetyIntentError> {
        self.weights.validate()?;
        self.thresholds.validate()?;
        self.limits.validate()?;
        Ok(())
    }
}

/// Four-factor risk weights.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RiskFactorWeights {
    pub command_type: f64,
    pub target_path: f64,
    pub parameter_danger: f64,
    pub impact_scope: f64,
}

impl Default for RiskFactorWeights {
    fn default() -> Self {
        Self {
            command_type: 0.35,
            target_path: 0.20,
            parameter_danger: 0.25,
            impact_scope: 0.20,
        }
    }
}

impl RiskFactorWeights {
    fn validate(&self) -> Result<(), SafetyIntentError> {
        for (name, value) in [
            ("commandType", self.command_type),
            ("targetPath", self.target_path),
            ("parameterDanger", self.parameter_danger),
            ("impactScope", self.impact_scope),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(SafetyIntentError::invalid_config(format!(
                    "risk weight `{name}` must be finite and non-negative"
                )));
            }
        }
        let total =
            self.command_type + self.target_path + self.parameter_danger + self.impact_scope;
        if !total.is_finite() || total <= 0.0 {
            return Err(SafetyIntentError::invalid_config(
                "risk weight total must be finite and greater than zero",
            ));
        }
        Ok(())
    }

    fn total(self) -> f64 {
        self.command_type + self.target_path + self.parameter_danger + self.impact_scope
    }
}

/// Risk thresholds in ascending order.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RiskThresholds {
    pub l1: f64,
    pub l2: f64,
    pub l3: f64,
    pub l4: f64,
}

impl Default for RiskThresholds {
    fn default() -> Self {
        Self {
            l1: 0.0,
            l2: 30.0,
            l3: 65.0,
            l4: 90.0,
        }
    }
}

impl RiskThresholds {
    fn validate(&self) -> Result<(), SafetyIntentError> {
        for (name, value) in [
            ("l1", self.l1),
            ("l2", self.l2),
            ("l3", self.l3),
            ("l4", self.l4),
        ] {
            if !value.is_finite() || !(0.0..=100.0).contains(&value) {
                return Err(SafetyIntentError::invalid_config(format!(
                    "risk threshold `{name}` must be finite and within 0..100"
                )));
            }
        }
        if !(self.l1 <= self.l2 && self.l2 <= self.l3 && self.l3 <= self.l4) {
            return Err(SafetyIntentError::invalid_config(
                "risk thresholds must be monotonic: l1 <= l2 <= l3 <= l4",
            ));
        }
        Ok(())
    }
}

/// Analyzer resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SafetyIntentLimits {
    pub max_operations: usize,
    pub max_compound_segments: usize,
    pub max_string_bytes: usize,
    pub max_parameter_json_bytes: usize,
    pub max_targets: usize,
}

impl Default for SafetyIntentLimits {
    fn default() -> Self {
        Self {
            max_operations: DEFAULT_MAX_OPERATIONS,
            max_compound_segments: DEFAULT_MAX_COMPOUND_SEGMENTS,
            max_string_bytes: DEFAULT_MAX_STRING_BYTES,
            max_parameter_json_bytes: DEFAULT_MAX_PARAMETER_JSON_BYTES,
            max_targets: DEFAULT_MAX_TARGETS,
        }
    }
}

impl SafetyIntentLimits {
    fn validate(&self) -> Result<(), SafetyIntentError> {
        for (name, value) in [
            ("maxOperations", self.max_operations),
            ("maxCompoundSegments", self.max_compound_segments),
            ("maxStringBytes", self.max_string_bytes),
            ("maxParameterJsonBytes", self.max_parameter_json_bytes),
            ("maxTargets", self.max_targets),
        ] {
            if value == 0 {
                return Err(SafetyIntentError::invalid_config(format!(
                    "limit `{name}` must be greater than zero"
                )));
            }
        }
        for (name, value, maximum) in [
            ("maxOperations", self.max_operations, MAX_ALLOWED_OPERATIONS),
            (
                "maxCompoundSegments",
                self.max_compound_segments,
                MAX_ALLOWED_COMPOUND_SEGMENTS,
            ),
            (
                "maxStringBytes",
                self.max_string_bytes,
                MAX_ALLOWED_STRING_BYTES,
            ),
            (
                "maxParameterJsonBytes",
                self.max_parameter_json_bytes,
                MAX_ALLOWED_PARAMETER_JSON_BYTES,
            ),
            ("maxTargets", self.max_targets, MAX_ALLOWED_TARGETS),
        ] {
            if value > maximum {
                return Err(SafetyIntentError::invalid_config(format!(
                    "limit `{name}` exceeds maximum {maximum}"
                )));
            }
        }
        Ok(())
    }
}

/// Full analysis report for a structured plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyIntentReport {
    pub intents: Vec<SafetyIntent>,
    pub risks: Vec<IntentRiskAssessment>,
    pub overall_level: RiskLevel,
    pub overall_policy: RiskPolicy,
    pub truncated: bool,
}

/// One extracted safety intent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyIntent {
    pub order: usize,
    pub action: SafetyAction,
    pub targets: Vec<IntentTarget>,
    pub parameters: Value,
    pub impact_scope: ImpactScope,
    pub raw_tool: String,
    pub source: Option<String>,
    pub implicit_operations: Vec<ImplicitOperation>,
    pub uncertainty: IntentUncertainty,
    pub evidence: Vec<String>,
    #[serde(skip)]
    risk_signals: RiskSignals,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct RiskSignals {
    hard_rules: Vec<String>,
    danger_markers: Vec<RiskDangerMarker>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RiskDangerMarker {
    ForceFlag,
    RecursiveFlag,
    WorldWritablePermission,
    RecursiveForcedDelete,
    FormatFilesystem,
    WipeFilesystem,
}

/// High-level action represented by an intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyAction {
    Read,
    Write,
    Delete,
    ExecuteProcess,
    NetworkAccess,
    PackageInstall,
    PackageUpdate,
    PackageRemove,
    ServiceStatus,
    ServiceStart,
    ServiceStop,
    ServiceRestart,
    UserCreate,
    UserDelete,
    UserModify,
    LogRuleChange,
    FirewallRead,
    FirewallChange,
    CronRead,
    CronChange,
    Backup,
    Restore,
    Unknown,
}

/// Target type for an intent target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentTargetKind {
    Path,
    Device,
    Url,
    Package,
    Service,
    User,
    Host,
    Command,
    Unknown,
}

/// Bounded, redacted target evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentTarget {
    pub kind: IntentTargetKind,
    pub value: String,
}

/// Impact scope used by risk scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactScope {
    LocalRead,
    Workspace,
    Network,
    Process,
    Service,
    System,
    Global,
    Unknown,
}

/// Operation implied by the explicit tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplicitOperation {
    FileSystemRead,
    FileSystemWrite,
    FileSystemDelete,
    NetworkAccess,
    ProcessExecution,
    ProcessManagement,
    PackageDatabaseMutation,
    ServiceStateChange,
    UserStateChange,
    FirewallPolicyChange,
    SchedulerStateChange,
}

/// Confidence in the extraction result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntentUncertainty {
    Low,
    Medium,
    High,
}

/// Scored risk assessment for one intent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentRiskAssessment {
    pub order: usize,
    pub factors: Vec<RiskFactorAssessment>,
    pub total_score: f64,
    pub level: RiskLevel,
    pub policy: RiskPolicy,
    pub hard_rule: Option<String>,
}

/// One risk factor score and evidence list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskFactorAssessment {
    pub factor: RiskFactor,
    pub score: f64,
    pub evidence: Vec<String>,
}

/// Four risk factors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFactor {
    CommandType,
    TargetPath,
    ParameterDanger,
    ImpactScope,
}

/// Risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    L1,
    L2,
    L3,
    L4,
}

/// Runtime safety policy implied by risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskPolicy {
    Allow,
    Audit,
    Confirm,
    Deny,
}

/// Structured analyzer error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafetyIntentError {
    pub code: SafetyIntentErrorCode,
    pub message: String,
}

impl SafetyIntentError {
    fn invalid_config(message: impl Into<String>) -> Self {
        Self {
            code: SafetyIntentErrorCode::InvalidConfig,
            message: message.into(),
        }
    }

    fn invalid_plan(message: impl Into<String>) -> Self {
        Self {
            code: SafetyIntentErrorCode::InvalidPlan,
            message: message.into(),
        }
    }

    fn limit_exceeded(message: impl Into<String>) -> Self {
        Self {
            code: SafetyIntentErrorCode::LimitExceeded,
            message: message.into(),
        }
    }
}

impl fmt::Display for SafetyIntentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for SafetyIntentError {}

/// Stable error code for safety intent failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyIntentErrorCode {
    InvalidConfig,
    InvalidPlan,
    LimitExceeded,
}

impl SafetyIntentErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::InvalidPlan => "invalid_plan",
            Self::LimitExceeded => "limit_exceeded",
        }
    }
}

/// Analyze a structured plan with the safe default configuration.
pub fn analyze_plan(plan: &ToolExecutionPlan) -> Result<SafetyIntentReport, SafetyIntentError> {
    analyze_plan_with_config(plan, &SafetyIntentConfig::default())
}

/// Analyze a structured plan using the supplied validated configuration.
pub fn analyze_plan_with_config(
    plan: &ToolExecutionPlan,
    config: &SafetyIntentConfig,
) -> Result<SafetyIntentReport, SafetyIntentError> {
    config.validate()?;
    validate_plan_bounds(plan, &config.limits)?;
    if plan.tool_calls.is_empty() {
        return Err(SafetyIntentError::invalid_plan(
            "tool execution plan must contain at least one tool call",
        ));
    }

    let mut intents = Vec::new();
    for call in &plan.tool_calls {
        let mut call_intents = extract_call_intents(call, plan.source.as_deref(), &config.limits)?;
        if intents.len() + call_intents.len() > config.limits.max_operations {
            return Err(SafetyIntentError::limit_exceeded(format!(
                "tool execution plan exceeds operation limit {}",
                config.limits.max_operations
            )));
        }
        intents.append(&mut call_intents);
    }

    for (order, intent) in intents.iter_mut().enumerate() {
        intent.order = order;
    }

    let risks = intents
        .iter()
        .map(|intent| score_intent(intent, config))
        .collect::<Vec<_>>();
    let overall_level = risks
        .iter()
        .map(|risk| risk.level)
        .max()
        .unwrap_or(RiskLevel::L4);
    let overall_policy = policy_for_level(overall_level);

    Ok(SafetyIntentReport {
        intents,
        risks,
        overall_level,
        overall_policy,
        truncated: false,
    })
}

fn validate_plan_bounds(
    plan: &ToolExecutionPlan,
    limits: &SafetyIntentLimits,
) -> Result<(), SafetyIntentError> {
    if plan.tool_calls.len() > limits.max_operations {
        return Err(SafetyIntentError::limit_exceeded(format!(
            "tool call count exceeds operation limit {}",
            limits.max_operations
        )));
    }
    validate_optional_string(
        "plan source",
        plan.source.as_deref(),
        limits.max_string_bytes,
    )?;
    for call in &plan.tool_calls {
        validate_string("tool name", &call.tool_name, limits.max_string_bytes)?;
        if call.tool_name.trim().is_empty() {
            return Err(SafetyIntentError::invalid_plan(
                "tool name must not be empty",
            ));
        }
        validate_optional_string(
            "tool source",
            call.source.as_deref(),
            limits.max_string_bytes,
        )?;
        let encoded = serde_json::to_vec(&call.arguments).map_err(|_| {
            SafetyIntentError::invalid_plan("tool arguments could not be encoded as JSON")
        })?;
        if encoded.len() > limits.max_parameter_json_bytes {
            return Err(SafetyIntentError::limit_exceeded(format!(
                "tool arguments for `{}` exceed JSON byte limit {}",
                redact_string(&call.tool_name),
                limits.max_parameter_json_bytes
            )));
        }
    }
    Ok(())
}

fn validate_optional_string(
    field: &str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<(), SafetyIntentError> {
    if let Some(value) = value {
        validate_string(field, value, max_bytes)?;
    }
    Ok(())
}

fn validate_string(field: &str, value: &str, max_bytes: usize) -> Result<(), SafetyIntentError> {
    if value.len() > max_bytes {
        return Err(SafetyIntentError::limit_exceeded(format!(
            "{field} exceeds string byte limit {max_bytes}"
        )));
    }
    Ok(())
}

fn extract_call_intents(
    call: &ToolCallPlan,
    plan_source: Option<&str>,
    limits: &SafetyIntentLimits,
) -> Result<Vec<SafetyIntent>, SafetyIntentError> {
    let source = call
        .source
        .clone()
        .or_else(|| plan_source.map(ToOwned::to_owned));
    if let Some(shell_kind) = shell_kind_for_tool(&call.tool_name) {
        let Some(command) = command_argument(&call.arguments) else {
            return Ok(vec![unknown_intent(
                &call.tool_name,
                source,
                redact_value(&call.arguments),
                "shell tool call missing structured command argument",
            )]);
        };
        validate_string("shell command", command, limits.max_string_bytes)?;
        if let Some(reason) = detect_unsafe_shell_substitution(shell_kind, command) {
            let mut intent = unknown_intent(
                &call.tool_name,
                source,
                json!({"commandPreview": redact_string(command)}),
                reason,
            );
            intent
                .risk_signals
                .hard_rules
                .push("shell substitution executes nested command".to_string());
            return Ok(vec![intent]);
        }
        let segments = match split_compound_command(command, limits.max_compound_segments) {
            Ok(segments) => segments,
            Err(CommandSplitFailure::Unknown(reason)) => {
                return Ok(vec![unknown_intent(
                    &call.tool_name,
                    source,
                    json!({"commandPreview": redact_string(command)}),
                    reason,
                )]);
            }
            Err(CommandSplitFailure::LimitExceeded(error)) => return Err(error),
        };
        return Ok(segments
            .into_iter()
            .map(|segment| shell_segment_intent(&call.tool_name, source.clone(), &segment, limits))
            .collect());
    }

    Ok(vec![structured_tool_intent(call, source, limits)])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShellKind {
    BashLike,
    PowerShell,
    Cmd,
}

fn shell_kind_for_tool(tool_name: &str) -> Option<ShellKind> {
    let normalized = tool_name.to_ascii_lowercase();
    match normalized.as_str() {
        "bash" | "shell" | "sh" => Some(ShellKind::BashLike),
        "powershell" | "pwsh" => Some(ShellKind::PowerShell),
        "cmd" => Some(ShellKind::Cmd),
        _ => None,
    }
}

fn command_argument(arguments: &Value) -> Option<&str> {
    arguments
        .get("command")
        .or_else(|| arguments.get("cmd"))
        .or_else(|| arguments.get("script"))
        .and_then(Value::as_str)
}

fn detect_unsafe_shell_substitution(shell_kind: ShellKind, command: &str) -> Option<String> {
    let chars = command.chars().collect::<Vec<_>>();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if escaped {
            escaped = false;
            index += 1;
            continue;
        }
        if ch == '\\' || (shell_kind == ShellKind::PowerShell && ch == '`') {
            escaped = true;
            index += 1;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
                index += 1;
                continue;
            }
            if active == '\'' {
                index += 1;
                continue;
            }
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            index += 1;
            continue;
        }
        if ch == '$' && chars.get(index + 1) == Some(&'(') {
            return Some(match shell_kind {
                ShellKind::PowerShell => {
                    "PowerShell subexpression detected; nested execution intent is unknown"
                        .to_string()
                }
                ShellKind::BashLike | ShellKind::Cmd => {
                    "shell command substitution detected; nested execution intent is unknown"
                        .to_string()
                }
            });
        }
        if shell_kind == ShellKind::BashLike && ch == '`' {
            return Some(
                "backtick command substitution detected; nested execution intent is unknown"
                    .to_string(),
            );
        }
        if shell_kind == ShellKind::BashLike
            && (ch == '<' || ch == '>')
            && chars.get(index + 1) == Some(&'(')
        {
            return Some(
                "shell process substitution detected; nested execution intent is unknown"
                    .to_string(),
            );
        }
        index += 1;
    }
    None
}

fn shell_segment_intent(
    tool_name: &str,
    source: Option<String>,
    segment: &str,
    limits: &SafetyIntentLimits,
) -> SafetyIntent {
    let command_intent = classify_command(segment);
    let tokens = tokenize_command(segment).unwrap_or_default();
    let first = first_meaningful_command(&tokens).unwrap_or_default();
    let action = action_for_command(segment, &tokens, command_intent);
    let mut evidence = vec![format!(
        "bash_validation classified segment as {command_intent:?}"
    )];
    if !first.is_empty() {
        evidence.push(format!("first command `{}`", redact_string(&first)));
    }
    let targets = extract_targets(&tokens, limits);
    let impact_scope = infer_impact_scope(action, &targets);
    let implicit_operations = implicit_operations_for_action(action);
    let risk_signals = risk_signals_for_raw_text(segment);
    SafetyIntent {
        order: 0,
        action,
        targets,
        parameters: json!({"command": redact_string(segment)}),
        impact_scope,
        raw_tool: redact_string(tool_name),
        source: redact_optional_string(source),
        implicit_operations,
        uncertainty: if action == SafetyAction::Unknown {
            IntentUncertainty::High
        } else {
            IntentUncertainty::Low
        },
        evidence,
        risk_signals,
    }
}

fn structured_tool_intent(
    call: &ToolCallPlan,
    source: Option<String>,
    limits: &SafetyIntentLimits,
) -> SafetyIntent {
    let action_name = call
        .arguments
        .get("action")
        .and_then(Value::as_str)
        .or_else(|| call.arguments.get("operation").and_then(Value::as_str));
    let action = action_for_structured_tool(&call.tool_name, action_name);
    let mut evidence = vec![format!(
        "structured tool `{}`",
        redact_string(&call.tool_name)
    )];
    if let Some(action_name) = action_name {
        evidence.push(format!("declared action `{}`", redact_string(action_name)));
    }
    let targets = extract_structured_targets(&call.arguments, action, limits);
    let impact_scope = infer_impact_scope(action, &targets);
    let implicit_operations = implicit_operations_for_action(action);
    let risk_signals =
        risk_signals_for_raw_text(&serde_json::to_string(&call.arguments).unwrap_or_default());
    SafetyIntent {
        order: 0,
        action,
        targets,
        parameters: redact_value(&call.arguments),
        impact_scope,
        raw_tool: redact_string(&call.tool_name),
        source: redact_optional_string(source),
        implicit_operations,
        uncertainty: if action == SafetyAction::Unknown {
            IntentUncertainty::High
        } else {
            IntentUncertainty::Medium
        },
        evidence,
        risk_signals,
    }
}

fn unknown_intent(
    tool_name: &str,
    source: Option<String>,
    parameters: Value,
    reason: impl Into<String>,
) -> SafetyIntent {
    SafetyIntent {
        order: 0,
        action: SafetyAction::Unknown,
        targets: Vec::new(),
        parameters,
        impact_scope: ImpactScope::Unknown,
        raw_tool: redact_string(tool_name),
        source: redact_optional_string(source),
        implicit_operations: Vec::new(),
        uncertainty: IntentUncertainty::High,
        evidence: vec![reason.into()],
        risk_signals: RiskSignals {
            hard_rules: vec!["unknown or unparsed intent fails closed".to_string()],
            danger_markers: Vec::new(),
        },
    }
}

enum CommandSplitFailure {
    Unknown(String),
    LimitExceeded(SafetyIntentError),
}

fn split_compound_command(
    command: &str,
    max_segments: usize,
) -> Result<Vec<String>, CommandSplitFailure> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let chars = command.chars().collect::<Vec<_>>();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if escaped {
            current.push(ch);
            escaped = false;
            index += 1;
            continue;
        }
        if ch == '\\' || ch == '`' {
            current.push(ch);
            escaped = true;
            index += 1;
            continue;
        }
        if let Some(active) = quote {
            current.push(ch);
            if ch == active {
                quote = None;
            }
            index += 1;
            continue;
        }
        if ch == '\'' || ch == '"' {
            current.push(ch);
            quote = Some(ch);
            index += 1;
            continue;
        }
        let delimiter_width = match ch {
            ';' | '\n' => Some(1),
            '&' if chars.get(index + 1) == Some(&'&') => Some(2),
            '&' if is_single_ampersand_delimiter(&chars, index) => Some(1),
            '|' if chars.get(index + 1) == Some(&'|') => Some(2),
            '|' => Some(1),
            _ => None,
        };
        if let Some(width) = delimiter_width {
            push_command_segment(&mut segments, &current, max_segments)?;
            current.clear();
            index += width;
            continue;
        }
        current.push(ch);
        index += 1;
    }
    if quote.is_some() || escaped {
        return Err(CommandSplitFailure::Unknown(
            "command contains unterminated quote or escape; intent is unknown".to_string(),
        ));
    }
    push_command_segment(&mut segments, &current, max_segments)?;
    if segments.is_empty() {
        return Err(CommandSplitFailure::Unknown(
            "command contains no executable segment; intent is unknown".to_string(),
        ));
    }
    Ok(segments)
}

fn is_single_ampersand_delimiter(chars: &[char], index: usize) -> bool {
    if chars.get(index) != Some(&'&') {
        return false;
    }
    if chars.get(index + 1) == Some(&'&') {
        return false;
    }
    if chars.get(index + 1) == Some(&'>') {
        return false;
    }
    !matches!(
        index.checked_sub(1).and_then(|prev| chars.get(prev)),
        Some(previous) if matches!(*previous, '>' | '<')
    )
}

fn push_command_segment(
    segments: &mut Vec<String>,
    candidate: &str,
    max_segments: usize,
) -> Result<(), CommandSplitFailure> {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    if segments.len() >= max_segments {
        return Err(CommandSplitFailure::LimitExceeded(
            SafetyIntentError::limit_exceeded(format!(
                "compound command exceeds segment limit {max_segments}"
            )),
        ));
    }
    segments.push(trimmed.to_string());
    Ok(())
}

fn tokenize_command(command: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in command.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' || ch == '`' {
            escaped = true;
            continue;
        }
        if let Some(active) = quote {
            if ch == active {
                quote = None;
            } else {
                current.push(ch);
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch.is_whitespace() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        current.push(ch);
    }
    if quote.is_some() || escaped {
        return Err("unterminated token".to_string());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

fn first_meaningful_command(tokens: &[String]) -> Option<String> {
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if token.contains('=') && token.find('=').is_some_and(|pos| pos > 0) {
            index += 1;
            continue;
        }
        if token == "sudo" {
            index += 1;
            while index < tokens.len() && tokens[index].starts_with('-') {
                index += 1;
            }
            continue;
        }
        return Some(token.clone());
    }
    None
}

fn action_for_command(
    segment: &str,
    tokens: &[String],
    command_intent: CommandIntent,
) -> SafetyAction {
    let lower_tokens = tokens
        .iter()
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let first = first_meaningful_command(tokens)
        .unwrap_or_default()
        .to_ascii_lowercase();

    if matches!(first.as_str(), "apt" | "apt-get" | "dnf" | "yum" | "pacman") {
        if lower_tokens.iter().any(|token| {
            matches!(
                token.as_str(),
                "install" | "reinstall" | "localinstall" | "add"
            )
        }) {
            return SafetyAction::PackageInstall;
        }
        if lower_tokens
            .iter()
            .any(|token| matches!(token.as_str(), "update" | "upgrade"))
        {
            return SafetyAction::PackageUpdate;
        }
        if lower_tokens
            .iter()
            .any(|token| matches!(token.as_str(), "remove" | "erase" | "purge"))
        {
            return SafetyAction::PackageRemove;
        }
    }

    if matches!(first.as_str(), "systemctl" | "service") {
        if lower_tokens.iter().any(|token| token == "status") {
            return SafetyAction::ServiceStatus;
        }
        if lower_tokens.iter().any(|token| token == "start") {
            return SafetyAction::ServiceStart;
        }
        if lower_tokens.iter().any(|token| token == "stop") {
            return SafetyAction::ServiceStop;
        }
        if lower_tokens.iter().any(|token| token == "restart") {
            return SafetyAction::ServiceRestart;
        }
    }

    if matches!(first.as_str(), "useradd") {
        return SafetyAction::UserCreate;
    }
    if matches!(first.as_str(), "userdel") {
        return SafetyAction::UserDelete;
    }
    if matches!(first.as_str(), "usermod" | "passwd" | "chage") {
        return SafetyAction::UserModify;
    }
    if matches!(first.as_str(), "iptables" | "ufw" | "firewall-cmd" | "nft") {
        return SafetyAction::FirewallChange;
    }
    if first == "crontab" {
        return SafetyAction::CronChange;
    }
    if first == "rm" || segment.contains("rm -rf") {
        return SafetyAction::Delete;
    }

    match command_intent {
        CommandIntent::ReadOnly => SafetyAction::Read,
        CommandIntent::Write => SafetyAction::Write,
        CommandIntent::Destructive => SafetyAction::Delete,
        CommandIntent::Network => SafetyAction::NetworkAccess,
        CommandIntent::ProcessManagement => SafetyAction::ExecuteProcess,
        CommandIntent::PackageManagement => SafetyAction::PackageUpdate,
        CommandIntent::SystemAdmin => SafetyAction::ExecuteProcess,
        CommandIntent::Unknown => SafetyAction::Unknown,
    }
}

fn action_for_structured_tool(tool_name: &str, action_name: Option<&str>) -> SafetyAction {
    let tool = normalize_name(tool_name);
    let action = normalize_action_name(action_name.unwrap_or(""));
    match tool.as_str() {
        name if name.contains("package_manager") || name == "packagemanager" => {
            match action.as_str() {
                "inspect" | "plan" | "deps" | "dependencies" => SafetyAction::Read,
                "install" => SafetyAction::PackageInstall,
                "remove" => SafetyAction::PackageRemove,
                "update" | "rollback" => SafetyAction::PackageUpdate,
                _ => SafetyAction::Unknown,
            }
        }
        name if name.contains("service_manager") || name == "servicemanager" => {
            match action.as_str() {
                "inspect" | "plan" | "status" | "log" => SafetyAction::ServiceStatus,
                "start" => SafetyAction::ServiceStart,
                "stop" => SafetyAction::ServiceStop,
                "restart" | "rollback" => SafetyAction::ServiceRestart,
                _ => SafetyAction::Unknown,
            }
        }
        name if name.contains("user_manager") || name == "usermanager" => match action.as_str() {
            "inspect" | "plan" | "permissions" | "sessions" | "password_policy" => {
                SafetyAction::Read
            }
            "terminate_session"
            | "set_password_policy"
            | "modify_permissions"
            | "lock"
            | "unlock"
            | "rollback" => SafetyAction::UserModify,
            "create" => SafetyAction::UserCreate,
            "delete" => SafetyAction::UserDelete,
            _ => SafetyAction::Unknown,
        },
        name if name.contains("log_analyzer") || name == "loganalyzer" => match action.as_str() {
            "inspect" | "plan" | "search" | "pattern" | "alert" | "alert_list"
            | "alert_validate" => SafetyAction::Read,
            "alert_create" | "alert_update" | "alert_delete" | "rollback" => {
                SafetyAction::LogRuleChange
            }
            _ => SafetyAction::Unknown,
        },
        name if name.contains("firewall_manager") || name == "firewallmanager" => {
            match action.as_str() {
                "inspect" | "plan" | "list" | "validate_policy" => SafetyAction::FirewallRead,
                "add_rule" | "update_rule" | "delete_rule" | "rollback" => {
                    SafetyAction::FirewallChange
                }
                _ => SafetyAction::Unknown,
            }
        }
        name if name.contains("cron_manager") || name == "cronmanager" => match action.as_str() {
            "inspect" | "plan" | "list" | "status" | "execution_records" | "log" => {
                SafetyAction::CronRead
            }
            "create" | "modify" | "delete" | "enable" | "disable" | "start" | "stop"
            | "restart" | "rollback" => SafetyAction::CronChange,
            _ => SafetyAction::Unknown,
        },
        name if name.contains("backup_manager") || name == "backupmanager" => {
            match action.as_str() {
                "inspect" | "plan" | "config" => SafetyAction::Read,
                "backup" | "snapshot" => SafetyAction::Backup,
                "restore" | "rollback" => SafetyAction::Restore,
                _ => SafetyAction::Unknown,
            }
        }
        name if name.contains("disk_cleaner") || name == "diskcleaner" => match action.as_str() {
            "inspect" | "plan" => SafetyAction::Read,
            "archive_logs" | "clean_temp" | "clean_package_cache" | "rollback" => {
                SafetyAction::Delete
            }
            _ => SafetyAction::Unknown,
        },
        name if name.contains("network_diagnostics") || name == "networkdiagnostics" => {
            match action.as_str() {
                "inspect" | "plan" => SafetyAction::Read,
                "dns" | "ping" | "traceroute" | "port_scan" => SafetyAction::NetworkAccess,
                _ => SafetyAction::Unknown,
            }
        }
        _ => SafetyAction::Unknown,
    }
}

fn normalize_action_name(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn normalize_name(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .flat_map(char::to_lowercase)
        .collect()
}

fn extract_targets(tokens: &[String], limits: &SafetyIntentLimits) -> Vec<IntentTarget> {
    let mut targets = Vec::new();
    for token in tokens.iter().skip(1) {
        if targets.len() >= limits.max_targets {
            break;
        }
        if token.starts_with('-') || token.contains('=') {
            continue;
        }
        if token.starts_with("http://") || token.starts_with("https://") {
            targets.push(IntentTarget {
                kind: IntentTargetKind::Url,
                value: redact_string(token),
            });
        } else if token.starts_with("/dev/") {
            targets.push(IntentTarget {
                kind: IntentTargetKind::Device,
                value: redact_string(token),
            });
        } else if token.starts_with('/')
            || token.starts_with("./")
            || token.starts_with("../")
            || token.starts_with("~/")
        {
            targets.push(IntentTarget {
                kind: IntentTargetKind::Path,
                value: redact_string(token),
            });
        } else if looks_like_host(token) {
            targets.push(IntentTarget {
                kind: IntentTargetKind::Host,
                value: redact_string(token),
            });
        } else if !token.trim().is_empty() {
            targets.push(IntentTarget {
                kind: IntentTargetKind::Unknown,
                value: bounded_preview(&redact_string(token)),
            });
        }
    }
    targets
}

fn extract_structured_targets(
    arguments: &Value,
    action: SafetyAction,
    limits: &SafetyIntentLimits,
) -> Vec<IntentTarget> {
    let mut targets = Vec::new();
    collect_target_key(arguments, "path", &mut targets, limits);
    collect_target_key(arguments, "target", &mut targets, limits);
    collect_target_key(arguments, "destination", &mut targets, limits);
    collect_target_key(arguments, "service", &mut targets, limits);
    collect_target_key(arguments, "user", &mut targets, limits);
    collect_target_key(arguments, "package", &mut targets, limits);
    collect_target_key(arguments, "host", &mut targets, limits);
    collect_target_key(arguments, "origin", &mut targets, limits);

    for target in &mut targets {
        if target.kind == IntentTargetKind::Unknown {
            target.kind = match action {
                SafetyAction::PackageInstall
                | SafetyAction::PackageUpdate
                | SafetyAction::PackageRemove => IntentTargetKind::Package,
                SafetyAction::ServiceStart
                | SafetyAction::ServiceStop
                | SafetyAction::ServiceRestart
                | SafetyAction::ServiceStatus => IntentTargetKind::Service,
                SafetyAction::UserCreate | SafetyAction::UserDelete | SafetyAction::UserModify => {
                    IntentTargetKind::User
                }
                SafetyAction::NetworkAccess => IntentTargetKind::Host,
                _ => IntentTargetKind::Unknown,
            };
        }
    }
    targets
}

fn collect_target_key(
    value: &Value,
    key: &str,
    targets: &mut Vec<IntentTarget>,
    limits: &SafetyIntentLimits,
) {
    if targets.len() >= limits.max_targets {
        return;
    }
    match value {
        Value::Object(map) => {
            for (entry_key, entry_value) in map {
                if entry_key.eq_ignore_ascii_case(key) {
                    collect_target_value(entry_value, targets, limits);
                } else if entry_value.is_object() || entry_value.is_array() {
                    collect_target_key(entry_value, key, targets, limits);
                }
                if targets.len() >= limits.max_targets {
                    return;
                }
            }
        }
        Value::Array(values) => {
            for entry in values {
                collect_target_key(entry, key, targets, limits);
                if targets.len() >= limits.max_targets {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn collect_target_value(
    value: &Value,
    targets: &mut Vec<IntentTarget>,
    limits: &SafetyIntentLimits,
) {
    if targets.len() >= limits.max_targets {
        return;
    }
    match value {
        Value::String(text) => targets.push(IntentTarget {
            kind: target_kind_for_value(text),
            value: bounded_preview(&redact_string(text)),
        }),
        Value::Array(values) => {
            for entry in values {
                collect_target_value(entry, targets, limits);
                if targets.len() >= limits.max_targets {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn target_kind_for_value(value: &str) -> IntentTargetKind {
    if value.starts_with("http://") || value.starts_with("https://") {
        IntentTargetKind::Url
    } else if value.starts_with("/dev/") {
        IntentTargetKind::Device
    } else if value.starts_with('/') || value.starts_with("./") || value.starts_with("../") {
        IntentTargetKind::Path
    } else if looks_like_host(value) {
        IntentTargetKind::Host
    } else {
        IntentTargetKind::Unknown
    }
}

fn looks_like_host(value: &str) -> bool {
    value.contains('.')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':' | '[' | ']'))
}

fn infer_impact_scope(action: SafetyAction, targets: &[IntentTarget]) -> ImpactScope {
    if action == SafetyAction::Unknown {
        return ImpactScope::Unknown;
    }
    if targets
        .iter()
        .any(|target| target.kind == IntentTargetKind::Device || is_global_path(&target.value))
    {
        return ImpactScope::Global;
    }
    match action {
        SafetyAction::Read | SafetyAction::FirewallRead | SafetyAction::CronRead => {
            ImpactScope::LocalRead
        }
        SafetyAction::Write | SafetyAction::Delete | SafetyAction::Backup => ImpactScope::Workspace,
        SafetyAction::NetworkAccess => ImpactScope::Network,
        SafetyAction::ExecuteProcess => ImpactScope::Process,
        SafetyAction::ServiceStatus
        | SafetyAction::ServiceStart
        | SafetyAction::ServiceStop
        | SafetyAction::ServiceRestart => ImpactScope::Service,
        SafetyAction::PackageInstall
        | SafetyAction::PackageUpdate
        | SafetyAction::PackageRemove
        | SafetyAction::UserCreate
        | SafetyAction::UserDelete
        | SafetyAction::UserModify
        | SafetyAction::LogRuleChange
        | SafetyAction::FirewallChange
        | SafetyAction::CronChange
        | SafetyAction::Restore => ImpactScope::System,
        SafetyAction::Unknown => ImpactScope::Unknown,
    }
}

fn implicit_operations_for_action(action: SafetyAction) -> Vec<ImplicitOperation> {
    match action {
        SafetyAction::Read | SafetyAction::ServiceStatus | SafetyAction::FirewallRead => {
            vec![ImplicitOperation::FileSystemRead]
        }
        SafetyAction::Write => vec![
            ImplicitOperation::FileSystemWrite,
            ImplicitOperation::ProcessExecution,
        ],
        SafetyAction::Delete => vec![
            ImplicitOperation::FileSystemDelete,
            ImplicitOperation::ProcessExecution,
        ],
        SafetyAction::NetworkAccess => vec![
            ImplicitOperation::NetworkAccess,
            ImplicitOperation::ProcessExecution,
        ],
        SafetyAction::ExecuteProcess => vec![ImplicitOperation::ProcessExecution],
        SafetyAction::PackageInstall
        | SafetyAction::PackageUpdate
        | SafetyAction::PackageRemove => vec![
            ImplicitOperation::NetworkAccess,
            ImplicitOperation::FileSystemWrite,
            ImplicitOperation::ProcessExecution,
            ImplicitOperation::PackageDatabaseMutation,
        ],
        SafetyAction::ServiceStart | SafetyAction::ServiceStop | SafetyAction::ServiceRestart => {
            vec![
                ImplicitOperation::ProcessExecution,
                ImplicitOperation::ServiceStateChange,
            ]
        }
        SafetyAction::UserCreate | SafetyAction::UserDelete | SafetyAction::UserModify => vec![
            ImplicitOperation::ProcessExecution,
            ImplicitOperation::FileSystemWrite,
            ImplicitOperation::UserStateChange,
        ],
        SafetyAction::LogRuleChange => vec![
            ImplicitOperation::FileSystemWrite,
            ImplicitOperation::ProcessExecution,
        ],
        SafetyAction::FirewallChange => vec![
            ImplicitOperation::ProcessExecution,
            ImplicitOperation::FirewallPolicyChange,
        ],
        SafetyAction::CronRead => vec![ImplicitOperation::FileSystemRead],
        SafetyAction::CronChange => vec![
            ImplicitOperation::ProcessExecution,
            ImplicitOperation::FileSystemWrite,
            ImplicitOperation::SchedulerStateChange,
        ],
        SafetyAction::Backup => vec![
            ImplicitOperation::FileSystemRead,
            ImplicitOperation::FileSystemWrite,
            ImplicitOperation::ProcessExecution,
        ],
        SafetyAction::Restore => vec![
            ImplicitOperation::FileSystemWrite,
            ImplicitOperation::ProcessExecution,
        ],
        SafetyAction::Unknown => Vec::new(),
    }
}

fn score_intent(intent: &SafetyIntent, config: &SafetyIntentConfig) -> IntentRiskAssessment {
    if let Some(rule) = hard_l4_rule(intent) {
        return IntentRiskAssessment {
            order: intent.order,
            factors: vec![
                RiskFactorAssessment {
                    factor: RiskFactor::CommandType,
                    score: 100.0,
                    evidence: vec![rule.clone()],
                },
                RiskFactorAssessment {
                    factor: RiskFactor::TargetPath,
                    score: 100.0,
                    evidence: vec!["hard L4 target or command pattern".to_string()],
                },
                RiskFactorAssessment {
                    factor: RiskFactor::ParameterDanger,
                    score: 100.0,
                    evidence: vec!["hard L4 rule cannot be downgraded by configuration".to_string()],
                },
                RiskFactorAssessment {
                    factor: RiskFactor::ImpactScope,
                    score: 100.0,
                    evidence: vec!["global destructive impact".to_string()],
                },
            ],
            total_score: 100.0,
            level: RiskLevel::L4,
            policy: RiskPolicy::Deny,
            hard_rule: Some(rule),
        };
    }

    let command_type = command_type_factor(intent);
    let target_path = target_path_factor(intent);
    let parameter_danger = parameter_danger_factor(intent);
    let impact_scope = impact_scope_factor(intent);
    let total = weighted_total(
        config.weights,
        command_type.score,
        target_path.score,
        parameter_danger.score,
        impact_scope.score,
    );
    let level = level_for_score(total, config.thresholds);
    IntentRiskAssessment {
        order: intent.order,
        factors: vec![command_type, target_path, parameter_danger, impact_scope],
        total_score: total,
        level,
        policy: policy_for_level(level),
        hard_rule: None,
    }
}

fn risk_signals_for_raw_text(value: &str) -> RiskSignals {
    let lower = value.to_ascii_lowercase();
    let mut signals = RiskSignals::default();
    for (needle, marker) in [
        ("--force", RiskDangerMarker::ForceFlag),
        (" -f", RiskDangerMarker::ForceFlag),
        (" -r", RiskDangerMarker::RecursiveFlag),
        ("--recursive", RiskDangerMarker::RecursiveFlag),
        ("chmod 777", RiskDangerMarker::WorldWritablePermission),
        ("rm -rf", RiskDangerMarker::RecursiveForcedDelete),
        ("rm -fr", RiskDangerMarker::RecursiveForcedDelete),
        ("mkfs", RiskDangerMarker::FormatFilesystem),
        ("wipefs", RiskDangerMarker::WipeFilesystem),
    ] {
        if lower.contains(needle) && !signals.danger_markers.contains(&marker) {
            signals.danger_markers.push(marker);
        }
    }
    for (needle, label) in [
        ("mkfs", "filesystem format command"),
        ("wipefs", "filesystem signature wipe command"),
        ("shred /dev/", "raw device shred command"),
        ("of=/dev/", "direct write to raw device"),
        (":(){", "fork bomb pattern"),
    ] {
        if lower.contains(needle) {
            signals.hard_rules.push(label.to_string());
        }
    }
    signals
}

fn weighted_total(
    weights: RiskFactorWeights,
    command: f64,
    target: f64,
    danger: f64,
    scope: f64,
) -> f64 {
    let total = weights.total();
    ((command * weights.command_type)
        + (target * weights.target_path)
        + (danger * weights.parameter_danger)
        + (scope * weights.impact_scope))
        / total
}

fn level_for_score(score: f64, thresholds: RiskThresholds) -> RiskLevel {
    if score >= thresholds.l4 {
        RiskLevel::L4
    } else if score >= thresholds.l3 {
        RiskLevel::L3
    } else if score >= thresholds.l2 {
        RiskLevel::L2
    } else {
        RiskLevel::L1
    }
}

fn policy_for_level(level: RiskLevel) -> RiskPolicy {
    match level {
        RiskLevel::L1 => RiskPolicy::Allow,
        RiskLevel::L2 => RiskPolicy::Audit,
        RiskLevel::L3 => RiskPolicy::Confirm,
        RiskLevel::L4 => RiskPolicy::Deny,
    }
}

fn command_type_factor(intent: &SafetyIntent) -> RiskFactorAssessment {
    let score = match intent.action {
        SafetyAction::Read
        | SafetyAction::ServiceStatus
        | SafetyAction::FirewallRead
        | SafetyAction::CronRead => 5.0,
        SafetyAction::Write | SafetyAction::Backup => 35.0,
        SafetyAction::NetworkAccess | SafetyAction::ExecuteProcess => 45.0,
        SafetyAction::ServiceStart | SafetyAction::ServiceStop | SafetyAction::ServiceRestart => {
            65.0
        }
        SafetyAction::PackageInstall
        | SafetyAction::PackageUpdate
        | SafetyAction::PackageRemove => 70.0,
        SafetyAction::FirewallChange | SafetyAction::CronChange | SafetyAction::Restore => 80.0,
        SafetyAction::UserCreate
        | SafetyAction::UserDelete
        | SafetyAction::UserModify
        | SafetyAction::LogRuleChange => 85.0,
        SafetyAction::Delete => 90.0,
        SafetyAction::Unknown => 90.0,
    };
    RiskFactorAssessment {
        factor: RiskFactor::CommandType,
        score,
        evidence: vec![format!("action {:?}", intent.action)],
    }
}

fn target_path_factor(intent: &SafetyIntent) -> RiskFactorAssessment {
    let mut score: f64 = if intent.targets.is_empty() {
        20.0
    } else {
        10.0
    };
    let mut evidence = Vec::new();
    for target in &intent.targets {
        let candidate = match target.kind {
            IntentTargetKind::Device => {
                evidence.push(format!(
                    "raw device target `{}`",
                    bounded_preview(&target.value)
                ));
                100.0
            }
            IntentTargetKind::Path if is_global_path(&target.value) => {
                evidence.push(format!(
                    "system path target `{}`",
                    bounded_preview(&target.value)
                ));
                90.0
            }
            IntentTargetKind::Path
                if target.value.starts_with("/tmp") || target.value.starts_with("/var/tmp") =>
            {
                evidence.push(format!(
                    "temporary path target `{}`",
                    bounded_preview(&target.value)
                ));
                25.0
            }
            IntentTargetKind::Url | IntentTargetKind::Host => {
                evidence.push(format!(
                    "network target `{}`",
                    bounded_preview(&target.value)
                ));
                55.0
            }
            IntentTargetKind::Unknown => {
                evidence.push(format!(
                    "unclassified target `{}`",
                    bounded_preview(&target.value)
                ));
                45.0
            }
            _ => 20.0,
        };
        score = score.max(candidate);
    }
    if evidence.is_empty() {
        evidence.push("no high-risk target path detected".to_string());
    }
    RiskFactorAssessment {
        factor: RiskFactor::TargetPath,
        score,
        evidence,
    }
}

fn parameter_danger_factor(intent: &SafetyIntent) -> RiskFactorAssessment {
    let mut score: f64 = match intent.uncertainty {
        IntentUncertainty::Low => 5.0,
        IntentUncertainty::Medium => 25.0,
        IntentUncertainty::High => 90.0,
    };
    let mut evidence = Vec::new();
    for marker in &intent.risk_signals.danger_markers {
        let (value, label) = match marker {
            RiskDangerMarker::ForceFlag => (35.0, "force flag"),
            RiskDangerMarker::RecursiveFlag => (35.0, "recursive flag"),
            RiskDangerMarker::WorldWritablePermission => (70.0, "world-writable permission change"),
            RiskDangerMarker::RecursiveForcedDelete => (90.0, "recursive forced delete"),
            RiskDangerMarker::FormatFilesystem => (100.0, "filesystem format command"),
            RiskDangerMarker::WipeFilesystem => (100.0, "filesystem signature wipe command"),
        };
        score = score.max(value);
        if !evidence.iter().any(|existing| existing == label) {
            evidence.push(label.to_string());
        }
    }
    if evidence.is_empty() {
        evidence.push(format!("uncertainty {:?}", intent.uncertainty));
    }
    RiskFactorAssessment {
        factor: RiskFactor::ParameterDanger,
        score,
        evidence,
    }
}

fn impact_scope_factor(intent: &SafetyIntent) -> RiskFactorAssessment {
    let score = match intent.impact_scope {
        ImpactScope::LocalRead => 5.0,
        ImpactScope::Workspace => 30.0,
        ImpactScope::Network => 45.0,
        ImpactScope::Process => 50.0,
        ImpactScope::Service => 65.0,
        ImpactScope::System => 80.0,
        ImpactScope::Global | ImpactScope::Unknown => 95.0,
    };
    RiskFactorAssessment {
        factor: RiskFactor::ImpactScope,
        score,
        evidence: vec![format!("impact scope {:?}", intent.impact_scope)],
    }
}

fn hard_l4_rule(intent: &SafetyIntent) -> Option<String> {
    if intent.action == SafetyAction::Unknown {
        return Some("unknown or unparsed intent fails closed".to_string());
    }
    if let Some(rule) = intent.risk_signals.hard_rules.first() {
        return Some(format!("hard L4 {rule}"));
    }
    let target_values = intent
        .targets
        .iter()
        .map(|target| target.value.to_ascii_lowercase())
        .collect::<Vec<_>>();

    if intent.action == SafetyAction::Delete
        && target_values.iter().any(|target| {
            matches!(
                target.as_str(),
                "/" | "/*" | "/." | "/boot" | "/etc" | "/usr" | "/var" | "/dev"
            )
        })
    {
        return Some("hard L4 destructive root or system target".to_string());
    }
    None
}

fn is_global_path(value: &str) -> bool {
    matches!(
        value,
        "/" | "/boot" | "/etc" | "/usr" | "/var" | "/dev" | "/proc" | "/sys"
    ) || value.starts_with("/boot/")
        || value.starts_with("/etc/")
        || value.starts_with("/usr/")
        || value.starts_with("/var/")
        || value.starts_with("/dev/")
        || value.starts_with("/proc/")
        || value.starts_with("/sys/")
}

fn redact_value(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact_string(text)),
        Value::Array(values) => Value::Array(values.iter().map(redact_value).collect()),
        Value::Object(map) => {
            let redacted = map
                .iter()
                .map(|(key, value)| {
                    if is_secret_key(key) {
                        (key.clone(), Value::String("[REDACTED]".to_string()))
                    } else {
                        (key.clone(), redact_value(value))
                    }
                })
                .collect();
            Value::Object(redacted)
        }
        other => other.clone(),
    }
}

fn redact_string(value: &str) -> String {
    let mut redacted = value.to_string();
    for marker in [
        "authorization:",
        "bearer ",
        "token=",
        "api_key=",
        "apikey=",
        "secret=",
        "password=",
    ] {
        redacted = redact_after_ascii_marker(&redacted, marker);
    }
    bounded_preview(&redacted)
}

fn redact_optional_string(value: Option<String>) -> Option<String> {
    value.map(|value| redact_string(&value))
}

fn redact_after_ascii_marker(value: &str, marker: &str) -> String {
    let bytes = value.as_bytes();
    let marker_bytes = marker.as_bytes();
    if marker_bytes.is_empty() || bytes.len() < marker_bytes.len() {
        return value.to_string();
    }
    let mut output = String::new();
    let mut cursor = 0;
    while cursor <= bytes.len().saturating_sub(marker_bytes.len()) {
        let index = cursor;
        if ascii_eq_ignore_case(&bytes[index..index + marker_bytes.len()], marker_bytes) {
            let marker_end = index + marker_bytes.len();
            let mut secret_start = marker_end;
            while secret_start < bytes.len() && bytes[secret_start].is_ascii_whitespace() {
                secret_start += 1;
            }
            let mut end = secret_start;
            while end < bytes.len() && !bytes[end].is_ascii_whitespace() {
                end += 1;
            }
            output.push_str(&value[cursor..marker_end]);
            output.push_str("[REDACTED]");
            cursor = end;
            continue;
        }
        let Some(ch) = value[cursor..].chars().next() else {
            break;
        };
        output.push(ch);
        cursor += ch.len_utf8();
    }
    output.push_str(&value[cursor..]);
    output
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("authorization")
        || lower.contains("api_key")
        || lower.contains("apikey")
}

fn bounded_preview(value: &str) -> String {
    if value.len() <= ERROR_PAYLOAD_PREVIEW_BYTES {
        return value.to_string();
    }
    let mut end = ERROR_PAYLOAD_PREVIEW_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[truncated]", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn call(tool_name: &str, arguments: Value) -> ToolCallPlan {
        ToolCallPlan {
            tool_name: tool_name.to_string(),
            source: None,
            arguments,
        }
    }

    fn plan(calls: Vec<ToolCallPlan>) -> ToolExecutionPlan {
        ToolExecutionPlan {
            source: Some("unit-test".to_string()),
            tool_calls: calls,
        }
    }

    #[test]
    fn safety_intent_multi_tool_plan_preserves_order() {
        let report = analyze_plan(&plan(vec![
            call("Bash", json!({"command": "cat Cargo.toml"})),
            call(
                "package_manager",
                json!({"action": "install", "package": "vim"}),
            ),
            call(
                "service_manager",
                json!({"action": "restart", "service": "nginx"}),
            ),
        ]))
        .expect("plan should analyze");

        let actions = report
            .intents
            .iter()
            .map(|intent| intent.action)
            .collect::<Vec<_>>();
        assert_eq!(
            actions,
            vec![
                SafetyAction::Read,
                SafetyAction::PackageInstall,
                SafetyAction::ServiceRestart
            ]
        );
        assert_eq!(report.intents[0].order, 0);
        assert_eq!(report.intents[1].order, 1);
        assert_eq!(report.intents[2].order, 2);
    }

    #[test]
    fn safety_intent_quoted_delimiters_do_not_split() {
        let report = analyze_plan(&plan(vec![call(
            "Bash",
            json!({"command": "printf 'a;b && c | d' && cat ./safe.txt"}),
        )]))
        .expect("plan should analyze");

        assert_eq!(report.intents.len(), 2);
        assert_eq!(report.intents[0].action, SafetyAction::Read);
        assert!(report.intents[0].parameters["command"]
            .as_str()
            .is_some_and(|command| command.contains("a;b && c | d")));
        assert_eq!(report.intents[1].action, SafetyAction::Read);
    }

    #[test]
    fn safety_intent_compound_tail_dangerous_command_is_not_lost() {
        let report = analyze_plan(&plan(vec![call(
            "Bash",
            json!({"command": "echo ok && rm -rf /"}),
        )]))
        .expect("plan should analyze");

        assert_eq!(report.intents.len(), 2);
        assert_eq!(report.intents[1].action, SafetyAction::Delete);
        assert_eq!(report.risks[1].level, RiskLevel::L4);
        assert_eq!(report.risks[1].policy, RiskPolicy::Deny);
        assert!(report.risks[1].hard_rule.is_some());
    }

    #[test]
    fn safety_intent_shell_substitution_fails_closed() {
        for command in [
            "echo $(rm -rf /)",
            "echo `rm -rf /`",
            "cat <(rm -rf /)",
            "echo ok & rm -rf /",
        ] {
            let report = analyze_plan(&plan(vec![call("Bash", json!({"command": command}))]))
                .expect("plan should analyze");
            assert_eq!(report.overall_policy, RiskPolicy::Deny, "{command}");
            assert_eq!(report.overall_level, RiskLevel::L4, "{command}");
        }

        let report = analyze_plan(&plan(vec![call(
            "PowerShell",
            json!({"command": "Write-Output $(Remove-Item -Recurse C:\\temp)"}),
        )]))
        .expect("plan should analyze");
        assert_eq!(report.intents[0].action, SafetyAction::Unknown);
        assert_eq!(report.risks[0].policy, RiskPolicy::Deny);
    }

    #[test]
    fn safety_intent_long_safe_prefix_cannot_hide_dangerous_tail() {
        let command = format!("echo {} $(rm -rf /)", "a".repeat(220));
        let report = analyze_plan(&plan(vec![call("Bash", json!({"command": command}))]))
            .expect("plan should analyze");
        assert_eq!(report.risks[0].level, RiskLevel::L4);
        assert_eq!(report.risks[0].policy, RiskPolicy::Deny);
        let preview = report.intents[0].parameters["commandPreview"]
            .as_str()
            .expect("preview");
        assert!(preview.len() < 220);
        assert!(!preview.contains("rm -rf /"));
    }

    #[test]
    fn safety_intent_package_install_adds_implicit_operations() {
        let report = analyze_plan(&plan(vec![call(
            "Bash",
            json!({"command": "sudo dnf install nginx"}),
        )]))
        .expect("plan should analyze");

        let intent = &report.intents[0];
        assert_eq!(intent.action, SafetyAction::PackageInstall);
        assert!(intent
            .implicit_operations
            .contains(&ImplicitOperation::NetworkAccess));
        assert!(intent
            .implicit_operations
            .contains(&ImplicitOperation::FileSystemWrite));
        assert!(intent
            .implicit_operations
            .contains(&ImplicitOperation::ProcessExecution));
    }

    #[test]
    fn safety_intent_risk_report_contains_four_factor_evidence() {
        let report = analyze_plan(&plan(vec![call(
            "firewall_manager",
            json!({"action": "add_rule", "host": "example.com"}),
        )]))
        .expect("plan should analyze");

        let risk = &report.risks[0];
        let factors = risk
            .factors
            .iter()
            .map(|factor| factor.factor)
            .collect::<BTreeSet<_>>();
        assert_eq!(factors.len(), 4);
        assert!(factors.contains(&RiskFactor::CommandType));
        assert!(factors.contains(&RiskFactor::TargetPath));
        assert!(factors.contains(&RiskFactor::ParameterDanger));
        assert!(factors.contains(&RiskFactor::ImpactScope));
        assert!(risk
            .factors
            .iter()
            .all(|factor| !factor.evidence.is_empty()));
    }

    #[test]
    fn safety_intent_configurable_weights_and_thresholds_affect_policy() {
        let mut config = SafetyIntentConfig::default();
        config.weights = RiskFactorWeights {
            command_type: 1.0,
            target_path: 0.0,
            parameter_danger: 0.0,
            impact_scope: 0.0,
        };
        config.thresholds = RiskThresholds {
            l1: 0.0,
            l2: 10.0,
            l3: 40.0,
            l4: 95.0,
        };
        let report = analyze_plan_with_config(
            &plan(vec![call(
                "service_manager",
                json!({"action": "restart", "service": "sshd"}),
            )]),
            &config,
        )
        .expect("plan should analyze");

        assert_eq!(report.risks[0].level, RiskLevel::L3);
        assert_eq!(report.risks[0].policy, RiskPolicy::Confirm);
    }

    #[test]
    fn safety_intent_rejects_invalid_config() {
        let mut config = SafetyIntentConfig::default();
        config.weights.command_type = -1.0;
        assert_eq!(
            config.validate().expect_err("negative weight").code,
            SafetyIntentErrorCode::InvalidConfig
        );

        let mut config = SafetyIntentConfig::default();
        config.thresholds = RiskThresholds {
            l1: 0.0,
            l2: 70.0,
            l3: 40.0,
            l4: 90.0,
        };
        assert_eq!(
            config
                .validate()
                .expect_err("non-monotonic thresholds")
                .code,
            SafetyIntentErrorCode::InvalidConfig
        );

        let mut config = SafetyIntentConfig::default();
        config.weights = RiskFactorWeights {
            command_type: 0.0,
            target_path: 0.0,
            parameter_danger: 0.0,
            impact_scope: 0.0,
        };
        assert_eq!(
            config.validate().expect_err("zero total weight").code,
            SafetyIntentErrorCode::InvalidConfig
        );
    }

    #[test]
    fn safety_intent_config_denies_unknown_fields() {
        let mut value = serde_json::to_value(SafetyIntentConfig::default()).expect("config json");
        value["unexpected"] = json!(true);
        assert!(serde_json::from_value::<SafetyIntentConfig>(value).is_err());
    }

    #[test]
    fn safety_intent_rejects_empty_tool_name() {
        let error = analyze_plan(&ToolExecutionPlan {
            source: Some(String::new()),
            tool_calls: vec![ToolCallPlan {
                tool_name: "   ".to_string(),
                source: Some(String::new()),
                arguments: json!({}),
            }],
        })
        .expect_err("empty tool must fail closed");
        assert_eq!(error.code, SafetyIntentErrorCode::InvalidPlan);
    }

    #[test]
    fn safety_intent_report_serialization_redacts_repeated_secrets() {
        let report = analyze_plan(&ToolExecutionPlan {
            source: Some("Bearer SOURCE_SECRET token=source_two".to_string()),
            tool_calls: vec![ToolCallPlan {
                tool_name: "Bash token=TOOL_SECRET".to_string(),
                source: Some("token=first token=second Bearer third".to_string()),
                arguments: json!({
                    "command": "echo token=first token=second Bearer third Authorization: fourth"
                }),
            }],
        })
        .expect("plan should analyze");
        let encoded = serde_json::to_string(&report).expect("report json");
        for secret in [
            "first",
            "second",
            "third",
            "fourth",
            "SOURCE_SECRET",
            "source_two",
            "TOOL_SECRET",
        ] {
            assert!(!encoded.contains(secret), "{secret} leaked in {encoded}");
        }
        assert!(encoded.contains("token=[REDACTED]"));
        assert!(encoded.contains("Bearer [REDACTED]"));
    }

    #[test]
    fn safety_intent_sensitive_source_tool_and_unknown_preview_are_redacted() {
        let report = analyze_plan(&ToolExecutionPlan {
            source: Some("token=PLAN_SECRET".to_string()),
            tool_calls: vec![
                ToolCallPlan {
                    tool_name: "package_manager token=TOOL_SECRET".to_string(),
                    source: Some("Bearer CALL_SECRET".to_string()),
                    arguments: json!({"action": "inspect"}),
                },
                ToolCallPlan {
                    tool_name: "Bash".to_string(),
                    source: Some("token=CALL_COMMAND_SECRET".to_string()),
                    arguments: json!({
                        "command": "echo $(curl https://example.com?token=COMMAND_SECRET)"
                    }),
                },
            ],
        })
        .expect("plan should analyze");
        let raw_tool_intent = &report.intents[0];
        let preview_intent = &report.intents[1];
        assert_eq!(preview_intent.action, SafetyAction::Unknown);
        let encoded = serde_json::to_string(&report).expect("report json");
        for secret in [
            "PLAN_SECRET",
            "TOOL_SECRET",
            "CALL_SECRET",
            "CALL_COMMAND_SECRET",
            "COMMAND_SECRET",
        ] {
            assert!(!encoded.contains(secret), "{secret} leaked in {encoded}");
        }
        assert!(raw_tool_intent.raw_tool.contains("[REDACTED]"));
        assert!(raw_tool_intent
            .source
            .as_deref()
            .is_some_and(|source| source.contains("[REDACTED]")));
        assert!(preview_intent.parameters["commandPreview"]
            .as_str()
            .is_some_and(|preview| preview.contains("[REDACTED]")));
    }

    #[test]
    fn safety_intent_bash_ampersand_redirect_does_not_split() {
        let report = analyze_plan(&plan(vec![call(
            "Bash",
            json!({"command": "echo ok &> ./out.txt"}),
        )]))
        .expect("plan should analyze");
        assert_eq!(report.intents.len(), 1);
        assert_eq!(report.intents[0].action, SafetyAction::Read);
    }

    #[test]
    fn safety_intent_builtin_actions_match_registered_ops_contract() {
        let cases = [
            ("package_manager", "inspect", SafetyAction::Read),
            ("package_manager", "deps", SafetyAction::Read),
            ("package_manager", "install", SafetyAction::PackageInstall),
            ("package_manager", "remove", SafetyAction::PackageRemove),
            ("package_manager", "update", SafetyAction::PackageUpdate),
            ("package_manager", "rollback", SafetyAction::PackageUpdate),
            ("package_manager", "unknown", SafetyAction::Unknown),
            ("service_manager", "status", SafetyAction::ServiceStatus),
            ("service_manager", "log", SafetyAction::ServiceStatus),
            ("service_manager", "start", SafetyAction::ServiceStart),
            ("service_manager", "stop", SafetyAction::ServiceStop),
            ("service_manager", "restart", SafetyAction::ServiceRestart),
            ("service_manager", "rollback", SafetyAction::ServiceRestart),
            ("service_manager", "unknown", SafetyAction::Unknown),
            ("user_manager", "permissions", SafetyAction::Read),
            ("user_manager", "sessions", SafetyAction::Read),
            ("user_manager", "password_policy", SafetyAction::Read),
            (
                "user_manager",
                "terminate_session",
                SafetyAction::UserModify,
            ),
            (
                "user_manager",
                "set_password_policy",
                SafetyAction::UserModify,
            ),
            (
                "user_manager",
                "modify_permissions",
                SafetyAction::UserModify,
            ),
            ("user_manager", "lock", SafetyAction::UserModify),
            ("user_manager", "unlock", SafetyAction::UserModify),
            ("user_manager", "create", SafetyAction::UserCreate),
            ("user_manager", "delete", SafetyAction::UserDelete),
            ("user_manager", "rollback", SafetyAction::UserModify),
            ("user_manager", "unknown", SafetyAction::Unknown),
            ("log_analyzer", "search", SafetyAction::Read),
            ("log_analyzer", "alert_validate", SafetyAction::Read),
            ("log_analyzer", "alert_create", SafetyAction::LogRuleChange),
            ("log_analyzer", "alert_update", SafetyAction::LogRuleChange),
            ("log_analyzer", "alert_delete", SafetyAction::LogRuleChange),
            ("log_analyzer", "rollback", SafetyAction::LogRuleChange),
            ("log_analyzer", "unknown", SafetyAction::Unknown),
            ("firewall_manager", "list", SafetyAction::FirewallRead),
            (
                "firewall_manager",
                "validate_policy",
                SafetyAction::FirewallRead,
            ),
            ("firewall_manager", "add_rule", SafetyAction::FirewallChange),
            (
                "firewall_manager",
                "update_rule",
                SafetyAction::FirewallChange,
            ),
            (
                "firewall_manager",
                "delete_rule",
                SafetyAction::FirewallChange,
            ),
            ("firewall_manager", "rollback", SafetyAction::FirewallChange),
            ("firewall_manager", "unknown", SafetyAction::Unknown),
            ("cron_manager", "execution_records", SafetyAction::CronRead),
            ("cron_manager", "log", SafetyAction::CronRead),
            ("cron_manager", "create", SafetyAction::CronChange),
            ("cron_manager", "modify", SafetyAction::CronChange),
            ("cron_manager", "delete", SafetyAction::CronChange),
            ("cron_manager", "enable", SafetyAction::CronChange),
            ("cron_manager", "rollback", SafetyAction::CronChange),
            ("cron_manager", "unknown", SafetyAction::Unknown),
            ("backup_manager", "config", SafetyAction::Read),
            ("backup_manager", "backup", SafetyAction::Backup),
            ("backup_manager", "snapshot", SafetyAction::Backup),
            ("backup_manager", "restore", SafetyAction::Restore),
            ("backup_manager", "rollback", SafetyAction::Restore),
            ("backup_manager", "unknown", SafetyAction::Unknown),
            ("disk_cleaner", "inspect", SafetyAction::Read),
            ("disk_cleaner", "archive_logs", SafetyAction::Delete),
            ("disk_cleaner", "clean_temp", SafetyAction::Delete),
            ("disk_cleaner", "clean_package_cache", SafetyAction::Delete),
            ("disk_cleaner", "rollback", SafetyAction::Delete),
            ("disk_cleaner", "unknown", SafetyAction::Unknown),
            ("network_diagnostics", "inspect", SafetyAction::Read),
            ("network_diagnostics", "dns", SafetyAction::NetworkAccess),
            ("network_diagnostics", "ping", SafetyAction::NetworkAccess),
            (
                "network_diagnostics",
                "traceroute",
                SafetyAction::NetworkAccess,
            ),
            (
                "network_diagnostics",
                "port_scan",
                SafetyAction::NetworkAccess,
            ),
            ("network_diagnostics", "unknown", SafetyAction::Unknown),
        ];

        for (tool, action, expected) in cases {
            let report = analyze_plan(&plan(vec![call(tool, json!({"action": action}))]))
                .expect("plan should analyze");
            assert_eq!(report.intents[0].action, expected, "{tool}:{action}");
            if expected == SafetyAction::Unknown {
                assert_eq!(report.risks[0].policy, RiskPolicy::Deny);
            }
        }
    }

    #[test]
    fn safety_intent_cron_read_does_not_imply_scheduler_mutation() {
        let report = analyze_plan(&plan(vec![call(
            "cron_manager",
            json!({"action": "execution_records"}),
        )]))
        .expect("plan should analyze");

        assert_eq!(report.intents[0].action, SafetyAction::CronRead);
        assert_eq!(
            report.intents[0].implicit_operations,
            vec![ImplicitOperation::FileSystemRead]
        );
    }

    #[test]
    fn safety_intent_unknown_parse_fail_closed() {
        let report = analyze_plan(&plan(vec![call(
            "Bash",
            json!({"command": "echo 'unterminated && rm -rf /tmp/x"}),
        )]))
        .expect("parse failure should produce conservative unknown intent");

        assert_eq!(report.intents.len(), 1);
        assert_eq!(report.intents[0].action, SafetyAction::Unknown);
        assert_eq!(report.intents[0].uncertainty, IntentUncertainty::High);
        assert_eq!(report.risks[0].policy, RiskPolicy::Deny);
    }

    #[test]
    fn safety_intent_unknown_is_hard_deny_under_extreme_config() {
        let mut config = SafetyIntentConfig::default();
        config.weights = RiskFactorWeights {
            command_type: 1.0,
            target_path: 0.0,
            parameter_danger: 0.0,
            impact_scope: 0.0,
        };
        config.thresholds = RiskThresholds {
            l1: 0.0,
            l2: 99.0,
            l3: 99.5,
            l4: 100.0,
        };
        let report = analyze_plan_with_config(
            &plan(vec![call("unknown_tool", json!({"safe": true}))]),
            &config,
        )
        .expect("plan should analyze");
        assert_eq!(report.risks[0].level, RiskLevel::L4);
        assert_eq!(report.risks[0].policy, RiskPolicy::Deny);
    }

    #[test]
    fn safety_intent_hard_l4_cannot_be_downgraded_by_zero_weights() {
        let mut config = SafetyIntentConfig::default();
        config.weights = RiskFactorWeights {
            command_type: 0.0,
            target_path: 0.0,
            parameter_danger: 0.0,
            impact_scope: 1.0,
        };
        config.thresholds = RiskThresholds {
            l1: 0.0,
            l2: 99.0,
            l3: 99.5,
            l4: 100.0,
        };
        let report = analyze_plan_with_config(
            &plan(vec![call("Bash", json!({"command": "rm -rf /"}))]),
            &config,
        )
        .expect("plan should analyze");

        assert_eq!(report.risks[0].level, RiskLevel::L4);
        assert_eq!(report.risks[0].policy, RiskPolicy::Deny);
        assert!(report.risks[0].hard_rule.is_some());
    }

    #[test]
    fn safety_intent_limits_operation_count_and_segments() {
        let mut config = SafetyIntentConfig::default();
        config.limits.max_operations = usize::MAX;
        assert_eq!(
            config
                .validate()
                .expect_err("unbounded operation limit")
                .code,
            SafetyIntentErrorCode::InvalidConfig
        );

        let mut config = SafetyIntentConfig::default();
        config.limits.max_operations = 1;
        let error = analyze_plan_with_config(
            &plan(vec![
                call("Bash", json!({"command": "echo one"})),
                call("Bash", json!({"command": "echo two"})),
            ]),
            &config,
        )
        .expect_err("too many tool calls");
        assert_eq!(error.code, SafetyIntentErrorCode::LimitExceeded);

        let mut config = SafetyIntentConfig::default();
        config.limits.max_string_bytes = 4;
        let error = analyze_plan_with_config(
            &plan(vec![call("Bash", json!({"command": "echo ok"}))]),
            &config,
        )
        .expect_err("tool name exceeds limit");
        assert_eq!(error.code, SafetyIntentErrorCode::LimitExceeded);

        let mut config = SafetyIntentConfig::default();
        config.limits.max_parameter_json_bytes = 24;
        let error = analyze_plan_with_config(
            &plan(vec![call(
                "Bash",
                json!({"command": "echo ok", "token": "SECRET_VALUE_SHOULD_NOT_APPEAR"}),
            )]),
            &config,
        )
        .expect_err("parameter json exceeds limit");
        assert_eq!(error.code, SafetyIntentErrorCode::LimitExceeded);
        assert!(!error.message.contains("SECRET_VALUE"));

        let mut config = SafetyIntentConfig::default();
        config.limits.max_compound_segments = 2;
        let error = analyze_plan_with_config(
            &plan(vec![call(
                "Bash",
                json!({"command": "echo one; echo two; echo three"}),
            )]),
            &config,
        )
        .expect_err("too many compound segments");
        assert_eq!(error.code, SafetyIntentErrorCode::LimitExceeded);
        assert!(!error.message.contains("echo three"));
    }
}
