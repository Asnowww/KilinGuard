use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::RuntimePermissionRuleConfig;

/// Permission level assigned to a tool invocation or runtime session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PermissionMode {
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
    Prompt,
    Allow,
}

impl PermissionMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WorkspaceWrite => "workspace-write",
            Self::DangerFullAccess => "danger-full-access",
            Self::Prompt => "prompt",
            Self::Allow => "allow",
        }
    }

    #[must_use]
    pub fn from_label(value: &str) -> Option<Self> {
        match value {
            "default" | "plan" | "read-only" | "p1" => Some(Self::ReadOnly),
            "acceptEdits" | "auto" | "workspace-write" | "p2" | "p3" => Some(Self::WorkspaceWrite),
            "dontAsk" | "bypassPermissions" | "danger-full-access" | "privileged" | "p4" => {
                Some(Self::DangerFullAccess)
            }
            "prompt" => Some(Self::Prompt),
            "allow" => Some(Self::Allow),
            _ => None,
        }
    }

    #[must_use]
    pub fn privilege_rank(self) -> u8 {
        match self {
            Self::Prompt => 0,
            Self::ReadOnly => 1,
            Self::WorkspaceWrite => 2,
            Self::DangerFullAccess | Self::Allow => 4,
        }
    }

    #[must_use]
    pub fn satisfies(self, required: Self) -> bool {
        self == Self::Allow || self.privilege_rank() >= required.privilege_rank()
    }

    #[must_use]
    pub fn clamp_to(self, max_mode: Self) -> Self {
        if self.privilege_rank() > max_mode.privilege_rank() {
            max_mode
        } else {
            self
        }
    }
}

impl Default for PermissionMode {
    fn default() -> Self {
        Self::ReadOnly
    }
}

/// Hook-provided override applied before standard permission evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionOverride {
    Allow,
    Deny,
    Ask,
}

/// Additional permission context supplied by hooks or higher-level orchestration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionContext {
    override_decision: Option<PermissionOverride>,
    override_reason: Option<String>,
}

impl PermissionContext {
    #[must_use]
    pub fn new(
        override_decision: Option<PermissionOverride>,
        override_reason: Option<String>,
    ) -> Self {
        Self {
            override_decision,
            override_reason,
        }
    }

    #[must_use]
    pub fn override_decision(&self) -> Option<PermissionOverride> {
        self.override_decision
    }

    #[must_use]
    pub fn override_reason(&self) -> Option<&str> {
        self.override_reason.as_deref()
    }
}

/// Full authorization request presented to a permission prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRequest {
    pub tool_name: String,
    pub input: String,
    pub current_mode: PermissionMode,
    pub required_mode: PermissionMode,
    pub reason: Option<String>,
}

/// User-facing decision returned by a [`PermissionPrompter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionPromptDecision {
    Allow,
    AllowOnce,
    AllowForSession,
    Deny { reason: String },
}

/// Prompting interface used when policy requires interactive approval.
pub trait PermissionPrompter {
    fn decide(&mut self, request: &PermissionRequest) -> PermissionPromptDecision;
}

/// Final authorization result after evaluating static rules and prompts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionOutcome {
    Allow,
    Deny { reason: String },
}

/// Authorization scope for a granted privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionGrantScope {
    Once,
    Session,
}

/// Structured privilege escalation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionEscalationRequest {
    pub operator: String,
    pub target_mode: PermissionMode,
    pub reason: String,
    pub scope: String,
    pub grant_scope: PermissionGrantScope,
    pub lease_expires_at_ms: Option<u64>,
    pub tool_name: Option<String>,
}

/// Recorded privilege grant. This is intentionally serializable so callers can
/// persist it as an audit record without inventing another schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionGrant {
    pub id: String,
    pub operator: String,
    pub mode: String,
    pub previous_mode: String,
    pub reason: String,
    pub scope: String,
    pub grant_scope: PermissionGrantScope,
    pub lease_expires_at_ms: Option<u64>,
    pub tool_name: Option<String>,
    pub active: bool,
    pub used: bool,
}

/// Append-only audit event emitted for permission lifecycle transitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionAuditEvent {
    pub timestamp_ms: u64,
    pub actor: String,
    pub action: String,
    pub mode: String,
    pub scope: String,
    pub reason: String,
    pub grant_id: Option<String>,
}

/// Reusable permission bundle for common operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionPolicyTemplate {
    pub name: String,
    pub mode: PermissionMode,
    pub reason: String,
    pub scope: String,
    pub grant_scope: PermissionGrantScope,
    pub lease_ms: Option<u64>,
}

/// Mutable least-privilege session state for FR-4.1..FR-4.24.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeastPrivilegeSession {
    base_mode: PermissionMode,
    active_mode: PermissionMode,
    max_mode: PermissionMode,
    operator: String,
    now_ms: u64,
    grant_counter: u64,
    session_expires_at_ms: Option<u64>,
    grants: Vec<PermissionGrant>,
    audit_log: Vec<PermissionAuditEvent>,
    templates: BTreeMap<String, PermissionPolicyTemplate>,
    frozen_reason: Option<String>,
}

impl Default for LeastPrivilegeSession {
    fn default() -> Self {
        Self::new("system")
    }
}

impl LeastPrivilegeSession {
    #[must_use]
    pub fn new(operator: impl Into<String>) -> Self {
        Self {
            base_mode: PermissionMode::ReadOnly,
            active_mode: PermissionMode::ReadOnly,
            max_mode: PermissionMode::Allow,
            operator: operator.into(),
            now_ms: 0,
            grant_counter: 0,
            session_expires_at_ms: None,
            grants: Vec::new(),
            audit_log: Vec::new(),
            templates: BTreeMap::new(),
            frozen_reason: None,
        }
    }

    #[must_use]
    pub fn with_max_mode(mut self, max_mode: PermissionMode) -> Self {
        self.max_mode = max_mode;
        self.active_mode = self.active_mode.clamp_to(max_mode);
        self
    }

    #[must_use]
    pub fn with_session_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.session_expires_at_ms = Some(self.now_ms + timeout_ms);
        self
    }

    #[must_use]
    pub fn active_mode(&self) -> PermissionMode {
        self.active_mode
    }

    #[must_use]
    pub fn max_mode(&self) -> PermissionMode {
        self.max_mode
    }

    #[must_use]
    pub fn grants(&self) -> &[PermissionGrant] {
        &self.grants
    }

    #[must_use]
    pub fn audit_log(&self) -> &[PermissionAuditEvent] {
        &self.audit_log
    }

    #[must_use]
    pub fn session_expires_at_ms(&self) -> Option<u64> {
        self.session_expires_at_ms
    }

    pub fn set_now_ms(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        self.revoke_expired();
    }

    pub fn register_template(&mut self, template: PermissionPolicyTemplate) {
        self.templates.insert(template.name.clone(), template);
    }

    pub fn apply_template(&mut self, name: &str, operator: &str) -> PermissionOutcome {
        let Some(template) = self.templates.get(name).cloned() else {
            return PermissionOutcome::Deny {
                reason: format!("permission template '{name}' is not defined"),
            };
        };
        self.request_escalation(PermissionEscalationRequest {
            operator: operator.to_string(),
            target_mode: template.mode,
            reason: template.reason,
            scope: template.scope,
            grant_scope: template.grant_scope,
            lease_expires_at_ms: template.lease_ms.map(|lease_ms| self.now_ms + lease_ms),
            tool_name: None,
        })
    }

    pub fn request_escalation(
        &mut self,
        request: PermissionEscalationRequest,
    ) -> PermissionOutcome {
        self.revoke_expired();
        if let Some(reason) = &self.frozen_reason {
            return PermissionOutcome::Deny {
                reason: format!("permissions are frozen: {reason}"),
            };
        }
        if !self.max_mode.satisfies(request.target_mode) {
            return PermissionOutcome::Deny {
                reason: format!(
                    "requested permission {} exceeds role maximum {}",
                    request.target_mode.as_str(),
                    self.max_mode.as_str()
                ),
            };
        }
        if request.reason.trim().is_empty() || request.scope.trim().is_empty() {
            return PermissionOutcome::Deny {
                reason: "permission escalation requires non-empty reason and scope".to_string(),
            };
        }

        self.grant_counter += 1;
        let id = format!("grant-{}", self.grant_counter);
        let previous_mode = self.active_mode;
        self.active_mode = request.target_mode;
        self.grants.push(PermissionGrant {
            id: id.clone(),
            operator: request.operator.clone(),
            mode: request.target_mode.as_str().to_string(),
            previous_mode: previous_mode.as_str().to_string(),
            reason: request.reason.clone(),
            scope: request.scope.clone(),
            grant_scope: request.grant_scope,
            lease_expires_at_ms: request.lease_expires_at_ms,
            tool_name: request.tool_name,
            active: true,
            used: false,
        });
        self.audit(
            &request.operator,
            "grant",
            request.target_mode,
            &request.scope,
            &request.reason,
            Some(id),
        );
        PermissionOutcome::Allow
    }

    #[must_use]
    pub fn authorize(
        &mut self,
        tool_name: &str,
        required_mode: PermissionMode,
    ) -> PermissionOutcome {
        self.revoke_expired();
        if let Some(reason) = &self.frozen_reason {
            return PermissionOutcome::Deny {
                reason: format!("permissions are frozen: {reason}"),
            };
        }
        if !self.max_mode.satisfies(required_mode) {
            return PermissionOutcome::Deny {
                reason: format!(
                    "tool '{tool_name}' requires {}, above role maximum {}",
                    required_mode.as_str(),
                    self.max_mode.as_str()
                ),
            };
        }
        if self.active_mode.satisfies(required_mode) {
            return PermissionOutcome::Allow;
        }
        PermissionOutcome::Deny {
            reason: format!(
                "tool '{tool_name}' requires {} permission; current mode is {}",
                required_mode.as_str(),
                self.active_mode.as_str()
            ),
        }
    }

    pub fn complete_operation(&mut self, tool_name: &str) {
        let mut drop_to = None;
        let mut audit_event = None;
        for grant in self.grants.iter_mut().rev() {
            if grant.active
                && grant.grant_scope == PermissionGrantScope::Once
                && grant
                    .tool_name
                    .as_deref()
                    .is_none_or(|tool| tool == tool_name)
            {
                grant.active = false;
                grant.used = true;
                drop_to = Some(parse_permission_mode_for_session(&grant.previous_mode));
                audit_event = Some((
                    grant.operator.clone(),
                    grant.previous_mode.clone(),
                    grant.scope.clone(),
                    grant.id.clone(),
                ));
                break;
            }
        }
        if let Some(mode) = drop_to.flatten() {
            self.active_mode = mode;
        } else if drop_to.is_some() {
            self.active_mode = self.base_mode;
        }
        if let Some((actor, mode, scope, id)) = audit_event {
            self.audit(
                &actor,
                "auto-drop",
                self.active_mode,
                &scope,
                &mode,
                Some(id),
            );
        }
    }

    pub fn expire_session(&mut self, reason: &str) {
        for grant in &mut self.grants {
            grant.active = false;
        }
        self.active_mode = self.base_mode;
        self.session_expires_at_ms = None;
        let operator = self.operator.clone();
        self.audit(
            &operator,
            "session-expire",
            self.active_mode,
            "session",
            reason,
            None,
        );
    }

    pub fn freeze_on_anomaly(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        self.frozen_reason = Some(reason.clone());
        self.active_mode = self.base_mode;
        let operator = self.operator.clone();
        self.audit(
            &operator,
            "freeze",
            self.active_mode,
            "session",
            &reason,
            None,
        );
    }

    fn revoke_expired(&mut self) {
        if self
            .session_expires_at_ms
            .is_some_and(|expires_at| expires_at <= self.now_ms)
        {
            for grant in &mut self.grants {
                grant.active = false;
            }
            self.active_mode = self.base_mode;
            self.session_expires_at_ms = None;
            let operator = self.operator.clone();
            self.audit(
                &operator,
                "session-expire",
                self.active_mode,
                "session",
                "session timeout expired",
                None,
            );
            return;
        }

        let mut revoked = Vec::new();
        for grant in &mut self.grants {
            if grant.active
                && grant
                    .lease_expires_at_ms
                    .is_some_and(|expires_at| expires_at <= self.now_ms)
            {
                grant.active = false;
                revoked.push((
                    grant.operator.clone(),
                    grant.scope.clone(),
                    grant.id.clone(),
                ));
            }
        }
        if !revoked.is_empty() {
            self.active_mode = self
                .grants
                .iter()
                .rev()
                .find(|grant| grant.active)
                .and_then(|grant| parse_permission_mode_for_session(&grant.mode))
                .unwrap_or(self.base_mode);
            for (actor, scope, id) in revoked {
                self.audit(
                    &actor,
                    "lease-expire",
                    self.active_mode,
                    &scope,
                    "permission lease expired",
                    Some(id),
                );
            }
        }
    }

    fn audit(
        &mut self,
        actor: &str,
        action: &str,
        mode: PermissionMode,
        scope: &str,
        reason: &str,
        grant_id: Option<String>,
    ) {
        self.audit_log.push(PermissionAuditEvent {
            timestamp_ms: self.now_ms,
            actor: actor.to_string(),
            action: action.to_string(),
            mode: mode.as_str().to_string(),
            scope: scope.to_string(),
            reason: reason.to_string(),
            grant_id,
        });
    }
}

fn parse_permission_mode_for_session(value: &str) -> Option<PermissionMode> {
    match value {
        "read-only" => Some(PermissionMode::ReadOnly),
        "workspace-write" => Some(PermissionMode::WorkspaceWrite),
        "danger-full-access" => Some(PermissionMode::DangerFullAccess),
        "prompt" => Some(PermissionMode::Prompt),
        "allow" => Some(PermissionMode::Allow),
        _ => None,
    }
}

/// Evaluates permission mode requirements plus allow/deny/ask rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionPolicy {
    active_mode: PermissionMode,
    role_max_mode: Option<PermissionMode>,
    tool_requirements: BTreeMap<String, PermissionMode>,
    allow_rules: Vec<PermissionRule>,
    deny_rules: Vec<PermissionRule>,
    ask_rules: Vec<PermissionRule>,
    /// #159: simple tool-name denials. Tools in this list are unconditionally
    /// denied regardless of permission mode, checked before the rule-based
    /// deny/allow/ask evaluation.
    denied_tools: Vec<String>,
    policy_templates: BTreeMap<String, PermissionPolicyTemplate>,
}

impl PermissionPolicy {
    #[must_use]
    pub fn new(active_mode: PermissionMode) -> Self {
        Self {
            active_mode,
            role_max_mode: None,
            tool_requirements: BTreeMap::new(),
            allow_rules: Vec::new(),
            deny_rules: Vec::new(),
            ask_rules: Vec::new(),
            denied_tools: Vec::new(),
            policy_templates: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn least_privilege() -> Self {
        Self::new(PermissionMode::ReadOnly)
    }

    #[must_use]
    pub fn with_tool_requirement(
        mut self,
        tool_name: impl Into<String>,
        required_mode: PermissionMode,
    ) -> Self {
        self.tool_requirements
            .insert(tool_name.into(), required_mode);
        self
    }

    #[must_use]
    pub fn with_permission_rules(mut self, config: &RuntimePermissionRuleConfig) -> Self {
        self.allow_rules = config
            .allow()
            .iter()
            .map(|rule| PermissionRule::parse(rule))
            .collect();
        self.deny_rules = config
            .deny()
            .iter()
            .map(|rule| PermissionRule::parse(rule))
            .collect();
        self.ask_rules = config
            .ask()
            .iter()
            .map(|rule| PermissionRule::parse(rule))
            .collect();
        self.denied_tools = config.denied_tools().to_vec();
        if let Some(max_mode) = config.max_mode().and_then(PermissionMode::from_label) {
            self.role_max_mode = Some(max_mode);
        }
        self.policy_templates = config
            .templates()
            .iter()
            .filter_map(|(name, template)| {
                let mode = template
                    .max_mode()
                    .and_then(PermissionMode::from_label)
                    .or_else(|| config.max_mode().and_then(PermissionMode::from_label))?;
                Some((
                    name.clone(),
                    PermissionPolicyTemplate {
                        name: name.clone(),
                        mode,
                        reason: format!("permission template {name}"),
                        scope: name.clone(),
                        grant_scope: PermissionGrantScope::Session,
                        lease_ms: config
                            .default_lease_seconds()
                            .map(|seconds| seconds * 1_000),
                    },
                ))
            })
            .collect();
        self
    }

    #[must_use]
    pub fn with_permission_rules_for_role(
        self,
        config: &RuntimePermissionRuleConfig,
        role: &str,
    ) -> Self {
        let mut policy = self.with_permission_rules(config);
        if let Some(max_mode) = config
            .role_max()
            .get(role)
            .and_then(|value| PermissionMode::from_label(value))
        {
            policy.role_max_mode = Some(max_mode);
        }
        policy
    }

    #[must_use]
    pub fn with_role_max_mode(mut self, mode: PermissionMode) -> Self {
        self.role_max_mode = Some(mode);
        self
    }

    #[must_use]
    pub fn with_policy_template(mut self, template: PermissionPolicyTemplate) -> Self {
        self.policy_templates
            .insert(template.name.clone(), template);
        self
    }

    pub fn apply_policy_template(mut self, name: &str) -> Result<Self, String> {
        let template = self
            .policy_templates
            .get(name)
            .cloned()
            .ok_or_else(|| format!("permission policy template '{name}' not found"))?;
        self.role_max_mode = Some(template.mode);
        Ok(self)
    }

    #[must_use]
    pub fn active_mode(&self) -> PermissionMode {
        self.active_mode
    }

    #[must_use]
    pub fn role_max_mode(&self) -> Option<PermissionMode> {
        self.role_max_mode
    }

    #[must_use]
    pub fn effective_active_mode(&self) -> PermissionMode {
        self.role_max_mode.map_or(self.active_mode, |max_mode| {
            self.active_mode.clamp_to(max_mode)
        })
    }

    #[must_use]
    pub fn build_escalation_request(
        &self,
        tool_name: &str,
        required_mode: PermissionMode,
        reason: impl Into<String>,
        scope: impl Into<String>,
    ) -> PermissionEscalationRequest {
        PermissionEscalationRequest {
            operator: "agent".to_string(),
            target_mode: required_mode,
            reason: reason.into(),
            scope: scope.into(),
            grant_scope: PermissionGrantScope::Once,
            lease_expires_at_ms: None,
            tool_name: Some(tool_name.to_string()),
        }
    }

    #[must_use]
    pub fn required_mode_for(&self, tool_name: &str) -> PermissionMode {
        self.tool_requirements
            .get(tool_name)
            .copied()
            .unwrap_or(PermissionMode::DangerFullAccess)
    }

    #[must_use]
    pub fn authorize(
        &self,
        tool_name: &str,
        input: &str,
        prompter: Option<&mut dyn PermissionPrompter>,
    ) -> PermissionOutcome {
        self.authorize_with_context(tool_name, input, &PermissionContext::default(), prompter)
    }

    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn authorize_with_context(
        &self,
        tool_name: &str,
        input: &str,
        context: &PermissionContext,
        prompter: Option<&mut dyn PermissionPrompter>,
    ) -> PermissionOutcome {
        self.authorize_with_context_at(tool_name, input, context, prompter, 0)
    }

    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn authorize_with_context_at(
        &self,
        tool_name: &str,
        input: &str,
        context: &PermissionContext,
        prompter: Option<&mut dyn PermissionPrompter>,
        _now_epoch_seconds: u64,
    ) -> PermissionOutcome {
        // #159: check denied_tools before rule-based evaluation. Tools listed
        // in the denied_tools config are unconditionally denied regardless of
        // permission mode.
        if self.denied_tools.iter().any(|t| t == tool_name) {
            return PermissionOutcome::Deny {
                reason: format!("tool '{tool_name}' has been denied by denied_tools configuration"),
            };
        }

        if let Some(rule) = Self::find_matching_rule(&self.deny_rules, tool_name, input) {
            return PermissionOutcome::Deny {
                reason: format!(
                    "Permission to use {tool_name} has been denied by rule '{}'",
                    rule.raw
                ),
            };
        }

        let current_mode = self.effective_active_mode();
        let required_mode = self.required_mode_for(tool_name);
        if let Some(max_mode) = self.role_max_mode {
            if !max_mode.satisfies(required_mode) {
                return PermissionOutcome::Deny {
                    reason: format!(
                        "tool '{tool_name}' requires {} permission, exceeding role maximum {}",
                        required_mode.as_str(),
                        max_mode.as_str()
                    ),
                };
            }
        }
        let ask_rule = Self::find_matching_rule(&self.ask_rules, tool_name, input);
        let allow_rule = Self::find_matching_rule(&self.allow_rules, tool_name, input);

        match context.override_decision() {
            Some(PermissionOverride::Deny) => {
                return PermissionOutcome::Deny {
                    reason: context.override_reason().map_or_else(
                        || format!("tool '{tool_name}' denied by hook"),
                        ToOwned::to_owned,
                    ),
                };
            }
            Some(PermissionOverride::Ask) => {
                let reason = context.override_reason().map_or_else(
                    || format!("tool '{tool_name}' requires approval due to hook guidance"),
                    ToOwned::to_owned,
                );
                return Self::prompt_or_deny(
                    tool_name,
                    input,
                    current_mode,
                    required_mode,
                    Some(reason),
                    prompter,
                );
            }
            Some(PermissionOverride::Allow) => {
                if let Some(rule) = ask_rule {
                    let reason = format!(
                        "tool '{tool_name}' requires approval due to ask rule '{}'",
                        rule.raw
                    );
                    return Self::prompt_or_deny(
                        tool_name,
                        input,
                        current_mode,
                        required_mode,
                        Some(reason),
                        prompter,
                    );
                }
                if allow_rule.is_some()
                    || current_mode == PermissionMode::Allow
                    || current_mode.satisfies(required_mode)
                {
                    return PermissionOutcome::Allow;
                }
            }
            None => {}
        }

        if let Some(rule) = ask_rule {
            let reason = format!(
                "tool '{tool_name}' requires approval due to ask rule '{}'",
                rule.raw
            );
            return Self::prompt_or_deny(
                tool_name,
                input,
                current_mode,
                required_mode,
                Some(reason),
                prompter,
            );
        }

        if allow_rule.is_some()
            || current_mode == PermissionMode::Allow
            || current_mode.satisfies(required_mode)
        {
            return PermissionOutcome::Allow;
        }

        if current_mode == PermissionMode::Prompt || !current_mode.satisfies(required_mode) {
            let reason = Some(format!(
                "tool '{tool_name}' requires {} permission and explicit approval to escalate from {} to {}",
                required_mode.as_str(),
                current_mode.as_str(),
                required_mode.as_str()
            ));
            return Self::prompt_or_deny(
                tool_name,
                input,
                current_mode,
                required_mode,
                reason,
                prompter,
            );
        }

        PermissionOutcome::Deny {
            reason: format!(
                "tool '{tool_name}' requires {} permission; current mode is {}",
                required_mode.as_str(),
                current_mode.as_str()
            ),
        }
    }

    fn prompt_or_deny(
        tool_name: &str,
        input: &str,
        current_mode: PermissionMode,
        required_mode: PermissionMode,
        reason: Option<String>,
        mut prompter: Option<&mut dyn PermissionPrompter>,
    ) -> PermissionOutcome {
        let request = PermissionRequest {
            tool_name: tool_name.to_string(),
            input: input.to_string(),
            current_mode,
            required_mode,
            reason: reason.clone(),
        };

        match prompter.as_mut() {
            Some(prompter) => match prompter.decide(&request) {
                PermissionPromptDecision::Allow
                | PermissionPromptDecision::AllowOnce
                | PermissionPromptDecision::AllowForSession => PermissionOutcome::Allow,
                PermissionPromptDecision::Deny { reason } => PermissionOutcome::Deny { reason },
            },
            None => PermissionOutcome::Deny {
                reason: reason.unwrap_or_else(|| {
                    format!(
                        "tool '{tool_name}' requires approval to run while mode is {}",
                        current_mode.as_str()
                    )
                }),
            },
        }
    }

    fn find_matching_rule<'a>(
        rules: &'a [PermissionRule],
        tool_name: &str,
        input: &str,
    ) -> Option<&'a PermissionRule> {
        rules.iter().find(|rule| rule.matches(tool_name, input))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PermissionRule {
    raw: String,
    tool_name: String,
    matcher: PermissionRuleMatcher,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PermissionRuleMatcher {
    Any,
    Exact(String),
    Prefix(String),
}

impl PermissionRule {
    fn parse(raw: &str) -> Self {
        let trimmed = raw.trim();
        let open = find_first_unescaped(trimmed, '(');
        let close = find_last_unescaped(trimmed, ')');

        if let (Some(open), Some(close)) = (open, close) {
            if close == trimmed.len() - 1 && open < close {
                let tool_name = trimmed[..open].trim();
                let content = &trimmed[open + 1..close];
                if !tool_name.is_empty() {
                    let matcher = parse_rule_matcher(content);
                    return Self {
                        raw: trimmed.to_string(),
                        tool_name: tool_name.to_string(),
                        matcher,
                    };
                }
            }
        }

        Self {
            raw: trimmed.to_string(),
            tool_name: trimmed.to_string(),
            matcher: PermissionRuleMatcher::Any,
        }
    }

    fn matches(&self, tool_name: &str, input: &str) -> bool {
        if self.tool_name != tool_name {
            return false;
        }

        match &self.matcher {
            PermissionRuleMatcher::Any => true,
            PermissionRuleMatcher::Exact(expected) => {
                extract_permission_subject(input).is_some_and(|candidate| candidate == *expected)
            }
            PermissionRuleMatcher::Prefix(prefix) => extract_permission_subject(input)
                .is_some_and(|candidate| candidate.starts_with(prefix)),
        }
    }
}

fn parse_rule_matcher(content: &str) -> PermissionRuleMatcher {
    let unescaped = unescape_rule_content(content.trim());
    if unescaped.is_empty() || unescaped == "*" {
        PermissionRuleMatcher::Any
    } else if let Some(prefix) = unescaped.strip_suffix(":*") {
        PermissionRuleMatcher::Prefix(prefix.to_string())
    } else {
        PermissionRuleMatcher::Exact(unescaped)
    }
}

fn unescape_rule_content(content: &str) -> String {
    content
        .replace(r"\(", "(")
        .replace(r"\)", ")")
        .replace(r"\\", r"\")
}

fn find_first_unescaped(value: &str, needle: char) -> Option<usize> {
    let mut escaped = false;
    for (idx, ch) in value.char_indices() {
        if ch == '\\' {
            escaped = !escaped;
            continue;
        }
        if ch == needle && !escaped {
            return Some(idx);
        }
        escaped = false;
    }
    None
}

fn find_last_unescaped(value: &str, needle: char) -> Option<usize> {
    let chars = value.char_indices().collect::<Vec<_>>();
    for (pos, (idx, ch)) in chars.iter().enumerate().rev() {
        if *ch != needle {
            continue;
        }
        let mut backslashes = 0;
        for (_, prev) in chars[..pos].iter().rev() {
            if *prev == '\\' {
                backslashes += 1;
            } else {
                break;
            }
        }
        if backslashes % 2 == 0 {
            return Some(*idx);
        }
    }
    None
}

fn extract_permission_subject(input: &str) -> Option<String> {
    let parsed = serde_json::from_str::<Value>(input).ok();
    if let Some(Value::Object(object)) = parsed {
        for key in [
            "command",
            "path",
            "file_path",
            "filePath",
            "notebook_path",
            "notebookPath",
            "url",
            "pattern",
            "code",
            "message",
        ] {
            if let Some(value) = object.get(key).and_then(Value::as_str) {
                return Some(value.to_string());
            }
        }
    }

    (!input.trim().is_empty()).then(|| input.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        LeastPrivilegeSession, PermissionContext, PermissionEscalationRequest,
        PermissionGrantScope, PermissionMode, PermissionOutcome, PermissionOverride,
        PermissionPolicy, PermissionPolicyTemplate, PermissionPromptDecision, PermissionPrompter,
        PermissionRequest,
    };
    use crate::config::RuntimePermissionRuleConfig;

    struct RecordingPrompter {
        seen: Vec<PermissionRequest>,
        allow: bool,
    }

    impl PermissionPrompter for RecordingPrompter {
        fn decide(&mut self, request: &PermissionRequest) -> PermissionPromptDecision {
            self.seen.push(request.clone());
            if self.allow {
                PermissionPromptDecision::Allow
            } else {
                PermissionPromptDecision::Deny {
                    reason: "not now".to_string(),
                }
            }
        }
    }

    #[test]
    fn allows_tools_when_active_mode_meets_requirement() {
        let policy = PermissionPolicy::new(PermissionMode::WorkspaceWrite)
            .with_tool_requirement("read_file", PermissionMode::ReadOnly)
            .with_tool_requirement("write_file", PermissionMode::WorkspaceWrite);

        assert_eq!(
            policy.authorize("read_file", "{}", None),
            PermissionOutcome::Allow
        );
        assert_eq!(
            policy.authorize("write_file", "{}", None),
            PermissionOutcome::Allow
        );
    }

    #[test]
    fn denies_read_only_escalations_without_prompt() {
        let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
            .with_tool_requirement("write_file", PermissionMode::WorkspaceWrite)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess);

        assert!(matches!(
            policy.authorize("write_file", "{}", None),
            PermissionOutcome::Deny { reason } if reason.contains("requires workspace-write permission")
        ));
        assert!(matches!(
            policy.authorize("bash", "{}", None),
            PermissionOutcome::Deny { reason } if reason.contains("requires danger-full-access permission")
        ));
    }

    #[test]
    fn prompts_for_workspace_write_to_danger_full_access_escalation() {
        let policy = PermissionPolicy::new(PermissionMode::WorkspaceWrite)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess);
        let mut prompter = RecordingPrompter {
            seen: Vec::new(),
            allow: true,
        };

        let outcome = policy.authorize("bash", "echo hi", Some(&mut prompter));

        assert_eq!(outcome, PermissionOutcome::Allow);
        assert_eq!(prompter.seen.len(), 1);
        assert_eq!(prompter.seen[0].tool_name, "bash");
        assert_eq!(
            prompter.seen[0].current_mode,
            PermissionMode::WorkspaceWrite
        );
        assert_eq!(
            prompter.seen[0].required_mode,
            PermissionMode::DangerFullAccess
        );
    }

    #[test]
    fn honors_prompt_rejection_reason() {
        let policy = PermissionPolicy::new(PermissionMode::WorkspaceWrite)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess);
        let mut prompter = RecordingPrompter {
            seen: Vec::new(),
            allow: false,
        };

        assert!(matches!(
            policy.authorize("bash", "echo hi", Some(&mut prompter)),
            PermissionOutcome::Deny { reason } if reason == "not now"
        ));
    }

    #[test]
    fn applies_rule_based_denials_and_allows() {
        let rules = RuntimePermissionRuleConfig::new(
            vec!["bash(git:*)".to_string()],
            vec!["bash(rm -rf:*)".to_string()],
            Vec::new(),
            Vec::new(),
        );
        let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess)
            .with_permission_rules(&rules);

        assert_eq!(
            policy.authorize("bash", r#"{"command":"git status"}"#, None),
            PermissionOutcome::Allow
        );
        assert!(matches!(
            policy.authorize("bash", r#"{"command":"rm -rf /tmp/x"}"#, None),
            PermissionOutcome::Deny { reason } if reason.contains("denied by rule")
        ));
    }

    #[test]
    fn denied_tools_denies_listed_tools_unconditionally() {
        let rules = RuntimePermissionRuleConfig::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec!["bash".to_string(), "write_file".to_string()],
        );
        let policy = PermissionPolicy::new(PermissionMode::Allow).with_permission_rules(&rules);

        let result = policy.authorize("bash", "echo hello", None);
        assert!(matches!(
            result,
            PermissionOutcome::Deny { reason } if reason.contains("denied_tools")
        ));

        let result = policy.authorize("write_file", "{}", None);
        assert!(matches!(
            result,
            PermissionOutcome::Deny { reason } if reason.contains("denied_tools")
        ));

        let result = policy.authorize("read_file", "{}", None);
        assert_eq!(result, PermissionOutcome::Allow);
    }

    #[test]
    fn ask_rules_force_prompt_even_when_mode_allows() {
        let rules = RuntimePermissionRuleConfig::new(
            Vec::new(),
            Vec::new(),
            vec!["bash(git:*)".to_string()],
            Vec::new(),
        );
        let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess)
            .with_permission_rules(&rules);
        let mut prompter = RecordingPrompter {
            seen: Vec::new(),
            allow: true,
        };

        let outcome = policy.authorize("bash", r#"{"command":"git status"}"#, Some(&mut prompter));

        assert_eq!(outcome, PermissionOutcome::Allow);
        assert_eq!(prompter.seen.len(), 1);
        assert!(prompter.seen[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("ask rule")));
    }

    #[test]
    fn hook_allow_still_respects_ask_rules() {
        let rules = RuntimePermissionRuleConfig::new(
            Vec::new(),
            Vec::new(),
            vec!["bash(git:*)".to_string()],
            Vec::new(),
        );
        let policy = PermissionPolicy::new(PermissionMode::ReadOnly)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess)
            .with_permission_rules(&rules);
        let context = PermissionContext::new(
            Some(PermissionOverride::Allow),
            Some("hook approved".to_string()),
        );
        let mut prompter = RecordingPrompter {
            seen: Vec::new(),
            allow: true,
        };

        let outcome = policy.authorize_with_context(
            "bash",
            r#"{"command":"git status"}"#,
            &context,
            Some(&mut prompter),
        );

        assert_eq!(outcome, PermissionOutcome::Allow);
        assert_eq!(prompter.seen.len(), 1);
    }

    #[test]
    fn hook_deny_short_circuits_permission_flow() {
        let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess);
        let context = PermissionContext::new(
            Some(PermissionOverride::Deny),
            Some("blocked by hook".to_string()),
        );

        assert_eq!(
            policy.authorize_with_context("bash", "{}", &context, None),
            PermissionOutcome::Deny {
                reason: "blocked by hook".to_string(),
            }
        );
    }

    #[test]
    fn hook_ask_forces_prompt() {
        let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess);
        let context = PermissionContext::new(
            Some(PermissionOverride::Ask),
            Some("hook requested confirmation".to_string()),
        );
        let mut prompter = RecordingPrompter {
            seen: Vec::new(),
            allow: true,
        };

        let outcome = policy.authorize_with_context("bash", "{}", &context, Some(&mut prompter));

        assert_eq!(outcome, PermissionOutcome::Allow);
        assert_eq!(prompter.seen.len(), 1);
        assert_eq!(
            prompter.seen[0].reason.as_deref(),
            Some("hook requested confirmation")
        );
    }

    #[test]
    fn role_maximum_caps_static_policy_authorization() {
        let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
            .with_role_max_mode(PermissionMode::WorkspaceWrite)
            .with_tool_requirement("bash", PermissionMode::DangerFullAccess)
            .with_tool_requirement("write_file", PermissionMode::WorkspaceWrite);

        assert_eq!(
            policy.authorize("write_file", "{}", None),
            PermissionOutcome::Allow
        );
        assert!(matches!(
            policy.authorize("bash", "{}", None),
            PermissionOutcome::Deny { reason } if reason.contains("role maximum")
        ));
    }

    #[test]
    fn permission_rule_config_can_apply_role_maximum() {
        let rules =
            RuntimePermissionRuleConfig::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
                .with_limits(
                    Some("danger-full-access".to_string()),
                    [("viewer".to_string(), "read-only".to_string())]
                        .into_iter()
                        .collect(),
                );
        let policy = PermissionPolicy::new(PermissionMode::DangerFullAccess)
            .with_permission_rules_for_role(&rules, "viewer")
            .with_tool_requirement("write_file", PermissionMode::WorkspaceWrite);

        assert_eq!(policy.role_max_mode(), Some(PermissionMode::ReadOnly));
        assert!(matches!(
            policy.authorize("write_file", "{}", None),
            PermissionOutcome::Deny { reason } if reason.contains("role maximum")
        ));
    }

    #[test]
    fn least_privilege_session_defaults_to_read_only_and_requires_reasoned_scope() {
        let mut session = LeastPrivilegeSession::new("alice");

        assert_eq!(session.active_mode(), PermissionMode::ReadOnly);
        assert_eq!(
            session.authorize("read_file", PermissionMode::ReadOnly),
            PermissionOutcome::Allow
        );
        assert!(matches!(
            session.authorize("write_file", PermissionMode::WorkspaceWrite),
            PermissionOutcome::Deny { reason } if reason.contains("current mode is read-only")
        ));
        assert!(matches!(
            session.request_escalation(PermissionEscalationRequest {
                operator: "alice".to_string(),
                target_mode: PermissionMode::WorkspaceWrite,
                reason: String::new(),
                scope: "workspace".to_string(),
                grant_scope: PermissionGrantScope::Once,
                lease_expires_at_ms: Some(100),
                tool_name: Some("write_file".to_string()),
            }),
            PermissionOutcome::Deny { reason } if reason.contains("reason and scope")
        ));
    }

    #[test]
    fn least_privilege_once_grant_auto_drops_after_operation() {
        let mut session = LeastPrivilegeSession::new("alice");

        assert_eq!(
            session.request_escalation(PermissionEscalationRequest {
                operator: "alice".to_string(),
                target_mode: PermissionMode::WorkspaceWrite,
                reason: "edit config fixture".to_string(),
                scope: "workspace:/tmp/project".to_string(),
                grant_scope: PermissionGrantScope::Once,
                lease_expires_at_ms: Some(1_000),
                tool_name: Some("write_file".to_string()),
            }),
            PermissionOutcome::Allow
        );
        assert_eq!(session.active_mode(), PermissionMode::WorkspaceWrite);
        assert_eq!(
            session.authorize("write_file", PermissionMode::WorkspaceWrite),
            PermissionOutcome::Allow
        );

        session.complete_operation("write_file");

        assert_eq!(session.active_mode(), PermissionMode::ReadOnly);
        assert!(session.grants()[0].used);
        assert!(session
            .audit_log()
            .iter()
            .any(|event| event.action == "auto-drop"));
    }

    #[test]
    fn least_privilege_prompt_mode_does_not_satisfy_write_permission() {
        let mut session = LeastPrivilegeSession::new("alice");

        assert_eq!(
            session.request_escalation(PermissionEscalationRequest {
                operator: "alice".to_string(),
                target_mode: PermissionMode::Prompt,
                reason: "require explicit confirmation".to_string(),
                scope: "workspace:/tmp/project".to_string(),
                grant_scope: PermissionGrantScope::Session,
                lease_expires_at_ms: None,
                tool_name: None,
            }),
            PermissionOutcome::Allow
        );

        assert!(matches!(
            session.authorize("write_file", PermissionMode::WorkspaceWrite),
            PermissionOutcome::Deny { reason } if reason.contains("current mode is prompt")
        ));
    }

    #[test]
    fn least_privilege_enforces_role_ceiling_lease_expiry_and_freeze() {
        let mut session =
            LeastPrivilegeSession::new("alice").with_max_mode(PermissionMode::WorkspaceWrite);
        session.set_now_ms(10);

        assert!(matches!(
            session.request_escalation(PermissionEscalationRequest {
                operator: "alice".to_string(),
                target_mode: PermissionMode::DangerFullAccess,
                reason: "restart service".to_string(),
                scope: "service:sshd".to_string(),
                grant_scope: PermissionGrantScope::Session,
                lease_expires_at_ms: Some(20),
                tool_name: None,
            }),
            PermissionOutcome::Deny { reason } if reason.contains("role maximum")
        ));

        assert_eq!(
            session.request_escalation(PermissionEscalationRequest {
                operator: "alice".to_string(),
                target_mode: PermissionMode::WorkspaceWrite,
                reason: "write temp report".to_string(),
                scope: "workspace:/tmp/project".to_string(),
                grant_scope: PermissionGrantScope::Session,
                lease_expires_at_ms: Some(20),
                tool_name: None,
            }),
            PermissionOutcome::Allow
        );
        session.set_now_ms(20);
        assert_eq!(session.active_mode(), PermissionMode::ReadOnly);
        assert!(session
            .audit_log()
            .iter()
            .any(|event| event.action == "lease-expire"));

        session.freeze_on_anomaly("cumulative risk threshold exceeded");
        assert!(matches!(
            session.authorize("read_file", PermissionMode::ReadOnly),
            PermissionOutcome::Deny { reason } if reason.contains("frozen")
        ));
    }

    #[test]
    fn least_privilege_session_timeout_revokes_permissions() {
        let mut session = LeastPrivilegeSession::new("alice").with_session_timeout_ms(25);
        assert_eq!(session.session_expires_at_ms(), Some(25));

        assert_eq!(
            session.request_escalation(PermissionEscalationRequest {
                operator: "alice".to_string(),
                target_mode: PermissionMode::WorkspaceWrite,
                reason: "edit generated workspace artifact".to_string(),
                scope: "workspace:/tmp/project".to_string(),
                grant_scope: PermissionGrantScope::Session,
                lease_expires_at_ms: None,
                tool_name: None,
            }),
            PermissionOutcome::Allow
        );

        session.set_now_ms(25);

        assert_eq!(session.active_mode(), PermissionMode::ReadOnly);
        assert!(session.grants().iter().all(|grant| !grant.active));
        assert!(session
            .audit_log()
            .iter()
            .any(|event| event.action == "session-expire"));
    }

    #[test]
    fn least_privilege_templates_issue_audited_session_grants() {
        let mut session = LeastPrivilegeSession::new("ops");
        session.register_template(PermissionPolicyTemplate {
            name: "tmp-cleanup".to_string(),
            mode: PermissionMode::WorkspaceWrite,
            reason: "clean temporary workspace files".to_string(),
            scope: "workspace:/tmp".to_string(),
            grant_scope: PermissionGrantScope::Session,
            lease_ms: Some(60_000),
        });

        assert_eq!(
            session.apply_template("tmp-cleanup", "alice"),
            PermissionOutcome::Allow
        );

        assert_eq!(session.active_mode(), PermissionMode::WorkspaceWrite);
        assert_eq!(session.grants()[0].operator, "alice");
        assert_eq!(session.grants()[0].lease_expires_at_ms, Some(60_000));
        assert_eq!(session.audit_log()[0].action, "grant");
    }
}
