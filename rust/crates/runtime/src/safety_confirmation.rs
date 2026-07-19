//! Structured confirmation requests and one-shot authorization for L3 safety risks.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::approval_tokens::{
    ApprovalScope, ApprovalTokenAudit, ApprovalTokenError, ApprovalTokenGrant, ApprovalTokenLedger,
};
use crate::safety_intent::{
    ImpactScope, IntentRiskAssessment, IntentTarget, RiskFactorAssessment, RiskLevel, RiskPolicy,
    SafetyAction, SafetyIntent, SafetyIntentReport,
};
use crate::safety_rules::SafetyRuleMatch;

const DEFAULT_CONFIRMATION_TTL_SECONDS: u64 = 60;
const MIN_CONFIRMATION_TTL_SECONDS: u64 = 1;
const MAX_CONFIRMATION_TTL_SECONDS: u64 = 600;
const DEFAULT_MAX_PENDING_CONFIRMATIONS: usize = 128;
const MAX_PENDING_CONFIRMATIONS: usize = 1024;
const MAX_SUMMARY_BYTES: usize = 512;
const MAX_EVIDENCE_ITEMS: usize = 16;
const MAX_REQUEST_ITEMS: usize = 128;
const TOKEN_GENERATION_ATTEMPTS: usize = 8;

/// Confirmation policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationMode {
    /// Each L3 intent requires an independent request and one-shot token.
    PerItem,
    /// One request and token covers the complete ordered plan.
    Batch,
}

impl ConfirmationMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::PerItem => "per_item",
            Self::Batch => "batch",
        }
    }
}

/// Strict runtime configuration for confirmation TTL and pending capacity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationConfig {
    pub ttl_seconds: u64,
    pub max_pending: usize,
}

impl Default for ConfirmationConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: DEFAULT_CONFIRMATION_TTL_SECONDS,
            max_pending: DEFAULT_MAX_PENDING_CONFIRMATIONS,
        }
    }
}

impl ConfirmationConfig {
    pub fn validate(&self) -> Result<(), ConfirmationError> {
        if !(MIN_CONFIRMATION_TTL_SECONDS..=MAX_CONFIRMATION_TTL_SECONDS)
            .contains(&self.ttl_seconds)
        {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::InvalidConfig,
                format!(
                    "ttlSeconds must be in {MIN_CONFIRMATION_TTL_SECONDS}..={MAX_CONFIRMATION_TTL_SECONDS}"
                ),
            ));
        }
        if self.max_pending == 0 || self.max_pending > MAX_PENDING_CONFIRMATIONS {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::InvalidConfig,
                format!("maxPending must be in 1..={MAX_PENDING_CONFIRMATIONS}"),
            ));
        }
        Ok(())
    }
}

/// Caller-supplied rollback facts verified outside the safety confirmation layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedRollbackMetadata {
    #[serde(default)]
    pub items: Vec<VerifiedRollbackItem>,
}

impl VerifiedRollbackMetadata {
    #[must_use]
    pub fn none() -> Self {
        Self { items: Vec::new() }
    }

    pub fn validate(&self) -> Result<(), ConfirmationError> {
        if self.items.len() > MAX_REQUEST_ITEMS {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::LimitExceeded,
                format!("rollback metadata exceeds item limit {MAX_REQUEST_ITEMS}"),
            ));
        }
        let mut seen = BTreeSet::new();
        for item in &self.items {
            if !seen.insert(item.intent_order) {
                return Err(ConfirmationError::new(
                    ConfirmationErrorCode::InvalidRequest,
                    "duplicate rollback metadata intent order",
                ));
            }
            match item.status {
                RollbackStatus::Verified => {
                    let summary = item.summary.as_deref().unwrap_or("");
                    validate_non_empty_summary("rollback summary", summary)?;
                    if item.irreversible_reason.is_some() {
                        return Err(ConfirmationError::new(
                            ConfirmationErrorCode::InvalidRequest,
                            "verified rollback metadata must not include irreversible reason",
                        ));
                    }
                }
                RollbackStatus::Irreversible => {
                    let reason = item.irreversible_reason.as_deref().unwrap_or("");
                    validate_non_empty_summary("irreversible reason", reason)?;
                    if item.summary.is_some() {
                        return Err(ConfirmationError::new(
                            ConfirmationErrorCode::InvalidRequest,
                            "irreversible rollback metadata must not include rollback summary",
                        ));
                    }
                }
                RollbackStatus::Unknown => {
                    if item.summary.is_some() || item.irreversible_reason.is_some() {
                        return Err(ConfirmationError::new(
                            ConfirmationErrorCode::InvalidRequest,
                            "unknown rollback metadata must not include verified details",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn item_for(&self, order: usize) -> Option<&VerifiedRollbackItem> {
        self.items.iter().find(|item| item.intent_order == order)
    }
}

/// Verified rollback facts for one intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifiedRollbackItem {
    pub intent_order: usize,
    pub status: RollbackStatus,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub irreversible_reason: Option<String>,
}

impl VerifiedRollbackItem {
    #[must_use]
    pub fn verified(intent_order: usize, summary: impl Into<String>) -> Self {
        Self {
            intent_order,
            status: RollbackStatus::Verified,
            summary: Some(summary.into()),
            irreversible_reason: None,
        }
    }

    #[must_use]
    pub fn irreversible(intent_order: usize, reason: impl Into<String>) -> Self {
        Self {
            intent_order,
            status: RollbackStatus::Irreversible,
            summary: None,
            irreversible_reason: Some(reason.into()),
        }
    }
}

/// Rollback status represented in a confirmation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackStatus {
    Verified,
    Irreversible,
    Unknown,
}

/// Rollback advice included in user-facing requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RollbackAdvice {
    pub status: RollbackStatus,
    pub verified: bool,
    pub irreversible: bool,
    pub summary: String,
}

/// One bounded confirmation request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationRequest {
    pub session_id: String,
    pub request_id: String,
    pub mode: ConfirmationMode,
    pub plan_hash: String,
    pub input_summary_hash: String,
    pub request_summary_hash: String,
    pub rule_generation: u64,
    pub expires_at_epoch_seconds: u64,
    pub items: Vec<ConfirmationRequestItem>,
}

/// One L3 intent summary inside a confirmation request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationRequestItem {
    pub intent_order: usize,
    pub action: SafetyAction,
    pub targets: Vec<IntentTarget>,
    pub parameters_summary: String,
    pub impact_scope: ImpactScope,
    pub risk_level: RiskLevel,
    pub total_score: f64,
    pub factors: Vec<RiskFactorAssessment>,
    pub matched_rules: Vec<ConfirmationRuleEvidence>,
    pub rollback_advice: RollbackAdvice,
    pub irreversible: bool,
}

/// Bounded matched-rule evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationRuleEvidence {
    pub rule_id: String,
    pub evidence: Vec<String>,
}

/// Strict user decision. Casual free-form strings do not deserialize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "camelCase", deny_unknown_fields)]
pub enum ConfirmationDecision {
    AllowOnce {},
    Deny { reason: String },
}

/// Decision result returned to callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationDecisionOutcome {
    pub request_id: String,
    pub status: ConfirmationDecisionStatus,
    pub token: Option<String>,
    pub expires_at_epoch_seconds: Option<u64>,
}

/// Decision status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationDecisionStatus {
    AllowedOnce,
    Denied,
}

/// Output of checking whether a report needs confirmation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub enum ConfirmationRequirement {
    NotRequired,
    Required { requests: Vec<ConfirmationRequest> },
    Rejected { reason: String },
}

/// Confirmation service with bounded pending requests and one-shot ledger tokens.
#[derive(Clone)]
pub struct ConfirmationGate {
    config: ConfirmationConfig,
    pending: BTreeMap<String, PendingConfirmation>,
    issued: BTreeMap<String, IssuedConfirmation>,
    ledger: ApprovalTokenLedger,
    counter: u64,
}

impl fmt::Debug for ConfirmationGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmationGate")
            .field("config", &self.config)
            .field("pending_count", &self.pending.len())
            .field("active_token_count", &self.issued.len())
            .finish()
    }
}

impl Default for ConfirmationGate {
    fn default() -> Self {
        Self::new(ConfirmationConfig::default()).expect("default confirmation config is valid")
    }
}

impl ConfirmationGate {
    pub fn new(config: ConfirmationConfig) -> Result<Self, ConfirmationError> {
        config.validate()?;
        Ok(Self {
            config,
            pending: BTreeMap::new(),
            issued: BTreeMap::new(),
            ledger: ApprovalTokenLedger::new(),
            counter: 0,
        })
    }

    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn active_token_count(&self) -> usize {
        self.issued.len()
    }

    pub fn require_confirmation(
        &mut self,
        session_id: &str,
        report: &SafetyIntentReport,
        mode: ConfirmationMode,
        rollback: Option<&VerifiedRollbackMetadata>,
        now_epoch_seconds: u64,
    ) -> Result<ConfirmationRequirement, ConfirmationError> {
        self.config.validate()?;
        self.clear_expired(now_epoch_seconds);
        validate_session(session_id)?;
        if has_l4(report)
            || report.overall_policy == RiskPolicy::Deny
            || report.overall_level == RiskLevel::L4
        {
            return Ok(ConfirmationRequirement::Rejected {
                reason: "L4 risk is denied and cannot issue confirmation token".to_string(),
            });
        }

        let confirm_orders = l3_confirm_orders(report);
        if confirm_orders.is_empty() {
            return Ok(ConfirmationRequirement::NotRequired);
        }
        if confirm_orders.len() > MAX_REQUEST_ITEMS {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::LimitExceeded,
                format!("confirmation request exceeds item limit {MAX_REQUEST_ITEMS}"),
            ));
        }
        let needed = match mode {
            ConfirmationMode::PerItem => confirm_orders.len(),
            ConfirmationMode::Batch => 1,
        };
        if self.counter.checked_add(needed as u64).is_none() {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::LimitExceeded,
                "confirmation request counter overflow",
            ));
        }
        if self.pending.len() + self.issued.len() + needed > self.config.max_pending {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::LimitExceeded,
                "pending confirmation limit exceeded",
            ));
        }

        let rollback = rollback
            .cloned()
            .unwrap_or_else(VerifiedRollbackMetadata::none);
        rollback.validate()?;
        validate_rollback_metadata_for_report(&rollback, report)?;
        let requests = match mode {
            ConfirmationMode::PerItem => confirm_orders
                .into_iter()
                .map(|order| {
                    self.build_request(
                        session_id,
                        report,
                        mode,
                        &[order],
                        &rollback,
                        now_epoch_seconds,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?,
            ConfirmationMode::Batch => self
                .build_request(
                    session_id,
                    report,
                    mode,
                    &confirm_orders,
                    &rollback,
                    now_epoch_seconds,
                )
                .map(|request| vec![request])?,
        };

        Ok(ConfirmationRequirement::Required { requests })
    }

    pub fn decide(
        &mut self,
        request_id: &str,
        decision: ConfirmationDecision,
        authenticated_actor_id: &str,
        executor_id: &str,
        now_epoch_seconds: u64,
    ) -> Result<ConfirmationDecisionOutcome, ConfirmationError> {
        self.decide_with_nonce_provider(
            request_id,
            decision,
            authenticated_actor_id,
            executor_id,
            now_epoch_seconds,
            secure_nonce,
        )
    }

    fn decide_with_nonce_provider<F>(
        &mut self,
        request_id: &str,
        decision: ConfirmationDecision,
        authenticated_actor_id: &str,
        executor_id: &str,
        now_epoch_seconds: u64,
        mut nonce_provider: F,
    ) -> Result<ConfirmationDecisionOutcome, ConfirmationError>
    where
        F: FnMut() -> Result<[u8; 32], ConfirmationError>,
    {
        validate_identity("authenticatedActorId", authenticated_actor_id)?;
        if let ConfirmationDecision::Deny { reason } = &decision {
            validate_non_empty_summary("deny reason", reason)?;
        } else {
            validate_identity("executorId", executor_id)?;
        }
        if self
            .pending
            .get(request_id)
            .is_some_and(|pending| now_epoch_seconds >= pending.request.expires_at_epoch_seconds)
        {
            self.pending.remove(request_id);
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::RequestExpired,
                "confirmation request expired",
            ));
        }
        self.clear_expired(now_epoch_seconds);
        let Some(pending) = self.pending.get(request_id) else {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::RequestNotFound,
                "confirmation request not found",
            ));
        };
        if now_epoch_seconds >= pending.request.expires_at_epoch_seconds {
            self.pending.remove(request_id);
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::RequestExpired,
                "confirmation request expired",
            ));
        }

        match decision {
            ConfirmationDecision::Deny { .. } => {
                self.pending.remove(request_id);
                Ok(ConfirmationDecisionOutcome {
                    request_id: request_id.to_string(),
                    status: ConfirmationDecisionStatus::Denied,
                    token: None,
                    expires_at_epoch_seconds: None,
                })
            }
            ConfirmationDecision::AllowOnce {} => {
                let token = self.mint_unique_token_with(pending, &mut nonce_provider)?;
                let pending = self.pending.remove(request_id).ok_or_else(|| {
                    ConfirmationError::new(
                        ConfirmationErrorCode::RequestNotFound,
                        "confirmation request not found",
                    )
                })?;
                self.issued.insert(
                    token.clone(),
                    IssuedConfirmation {
                        actor_id: authenticated_actor_id.to_string(),
                        executor_id: executor_id.to_string(),
                        expires_at_epoch_seconds: pending.request.expires_at_epoch_seconds,
                    },
                );
                self.ledger.insert(
                    ApprovalTokenGrant::granted(
                        token.clone(),
                        pending.scope.clone(),
                        authenticated_actor_id.to_string(),
                        executor_id.to_string(),
                    )
                    .expires_at(pending.request.expires_at_epoch_seconds)
                    .with_max_uses(1),
                );
                Ok(ConfirmationDecisionOutcome {
                    request_id: request_id.to_string(),
                    status: ConfirmationDecisionStatus::AllowedOnce,
                    token: Some(token),
                    expires_at_epoch_seconds: Some(pending.request.expires_at_epoch_seconds),
                })
            }
        }
    }

    pub fn consume(
        &mut self,
        token: &str,
        session_id: &str,
        report: &SafetyIntentReport,
        mode: ConfirmationMode,
        intent_order: Option<usize>,
        actor_id: &str,
        executor_id: &str,
        now_epoch_seconds: u64,
    ) -> Result<ApprovalTokenAudit, ConfirmationError> {
        validate_identity("actorId", actor_id)?;
        validate_identity("executorId", executor_id)?;
        if has_l4(report)
            || report.overall_policy == RiskPolicy::Deny
            || report.overall_level == RiskLevel::L4
        {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::DeniedRisk,
                "L4 risk is denied and cannot consume confirmation token",
            ));
        }
        let Some(issued) = self.issued.get(token) else {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::TokenNotFound,
                "approval token not found",
            ));
        };
        if now_epoch_seconds >= issued.expires_at_epoch_seconds {
            self.issued.remove(token);
            self.ledger.remove(token);
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::TokenExpired,
                "approval token expired",
            ));
        }
        if issued.actor_id != actor_id || issued.executor_id != executor_id {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::ScopeMismatch,
                "approval token actor or executor mismatch",
            ));
        }
        let orders = match mode {
            ConfirmationMode::PerItem => vec![intent_order.ok_or_else(|| {
                ConfirmationError::new(
                    ConfirmationErrorCode::InvalidRequest,
                    "per-item token consumption requires intent order",
                )
            })?],
            ConfirmationMode::Batch => {
                if intent_order.is_some() {
                    return Err(ConfirmationError::new(
                        ConfirmationErrorCode::InvalidRequest,
                        "batch token consumption must not include per-item order",
                    ));
                }
                l3_confirm_orders(report)
            }
        };
        let scope = scope_for_report(session_id, report, mode, &orders)?;
        let audit = match self
            .ledger
            .consume(token, &scope, executor_id, now_epoch_seconds)
        {
            Ok(audit) => audit,
            Err(error @ ApprovalTokenError::ApprovalExpired) => {
                self.issued.remove(token);
                self.ledger.remove(token);
                return Err(ConfirmationError::from(error));
            }
            Err(error @ ApprovalTokenError::ApprovalAlreadyConsumed) => {
                self.issued.remove(token);
                self.ledger.remove(token);
                return Err(ConfirmationError::from(error));
            }
            Err(error) => return Err(ConfirmationError::from(error)),
        };
        self.issued.remove(token);
        self.ledger.remove(token);
        Ok(audit)
    }

    fn clear_expired(&mut self, now_epoch_seconds: u64) {
        self.pending
            .retain(|_, pending| now_epoch_seconds < pending.request.expires_at_epoch_seconds);
        let expired_tokens = self
            .issued
            .iter()
            .filter_map(|(token, issued)| {
                (now_epoch_seconds >= issued.expires_at_epoch_seconds).then(|| token.clone())
            })
            .collect::<Vec<_>>();
        for token in expired_tokens {
            self.issued.remove(&token);
            self.ledger.remove(&token);
        }
    }

    fn build_request(
        &mut self,
        session_id: &str,
        report: &SafetyIntentReport,
        mode: ConfirmationMode,
        orders: &[usize],
        rollback: &VerifiedRollbackMetadata,
        now_epoch_seconds: u64,
    ) -> Result<ConfirmationRequest, ConfirmationError> {
        let next_counter = self.counter.checked_add(1).ok_or_else(|| {
            ConfirmationError::new(
                ConfirmationErrorCode::LimitExceeded,
                "confirmation request counter overflow",
            )
        })?;
        let scope = scope_for_report(session_id, report, mode, orders)?;
        let expires_at_epoch_seconds = now_epoch_seconds
            .checked_add(self.config.ttl_seconds)
            .ok_or_else(|| {
                ConfirmationError::new(
                    ConfirmationErrorCode::InvalidConfig,
                    "confirmation TTL overflow",
                )
            })?;
        let items = orders
            .iter()
            .map(|order| request_item(report, *order, rollback))
            .collect::<Result<Vec<_>, _>>()?;
        let request_summary_hash = request_items_hash(&items);
        let request_id = request_id(
            session_id,
            report,
            mode,
            orders,
            next_counter,
            now_epoch_seconds,
        );
        let request = ConfirmationRequest {
            session_id: sanitize_summary(session_id),
            request_id: request_id.clone(),
            mode,
            plan_hash: sanitize_summary(&report.input_summary_hash),
            input_summary_hash: sanitize_summary(&report.input_summary_hash),
            request_summary_hash,
            rule_generation: report.rule_generation,
            expires_at_epoch_seconds,
            items,
        };
        self.pending.insert(
            request_id,
            PendingConfirmation {
                request: request.clone(),
                scope,
            },
        );
        self.counter = next_counter;
        Ok(request)
    }

    fn mint_unique_token_with<F>(
        &self,
        pending: &PendingConfirmation,
        nonce_provider: &mut F,
    ) -> Result<String, ConfirmationError>
    where
        F: FnMut() -> Result<[u8; 32], ConfirmationError>,
    {
        for _ in 0..TOKEN_GENERATION_ATTEMPTS {
            let nonce = nonce_provider()?;
            let token = token_id_from_nonce(pending, &nonce);
            if !self.issued.contains_key(&token) && self.ledger.get(&token).is_none() {
                return Ok(token);
            }
        }
        Err(ConfirmationError::new(
            ConfirmationErrorCode::RandomFailed,
            "unique token generation exhausted",
        ))
    }
}

#[derive(Debug, Clone)]
struct PendingConfirmation {
    request: ConfirmationRequest,
    scope: ApprovalScope,
}

#[derive(Debug, Clone)]
struct IssuedConfirmation {
    actor_id: String,
    executor_id: String,
    expires_at_epoch_seconds: u64,
}

fn l3_confirm_orders(report: &SafetyIntentReport) -> Vec<usize> {
    report
        .risks
        .iter()
        .filter(|risk| risk.level == RiskLevel::L3 && risk.policy == RiskPolicy::Confirm)
        .map(|risk| risk.order)
        .collect()
}

fn has_l4(report: &SafetyIntentReport) -> bool {
    report
        .risks
        .iter()
        .any(|risk| risk.level == RiskLevel::L4 || risk.policy == RiskPolicy::Deny)
}

fn scope_for_report(
    session_id: &str,
    report: &SafetyIntentReport,
    mode: ConfirmationMode,
    orders: &[usize],
) -> Result<ApprovalScope, ConfirmationError> {
    validate_session(session_id)?;
    if orders.is_empty() {
        return Err(ConfirmationError::new(
            ConfirmationErrorCode::InvalidRequest,
            "confirmation scope requires at least one intent",
        ));
    }
    validate_orders(report, mode, orders)?;
    let binding = confirmation_binding_hash(session_id, report, mode, orders)?;
    Ok(ApprovalScope::new(
        "safety_confirmation",
        format!("{}:{binding}", mode.as_str()),
    ))
}

fn validate_orders(
    report: &SafetyIntentReport,
    mode: ConfirmationMode,
    orders: &[usize],
) -> Result<(), ConfirmationError> {
    let mut seen = BTreeSet::new();
    for order in orders {
        if !seen.insert(*order) {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::InvalidRequest,
                "duplicate confirmation intent order",
            ));
        }
        let risk = risk_for_order(report, *order)?;
        if risk.level != RiskLevel::L3 || risk.policy != RiskPolicy::Confirm {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::InvalidRequest,
                "only L3 confirm intents may receive confirmation",
            ));
        }
    }
    if mode == ConfirmationMode::Batch && orders != l3_confirm_orders(report).as_slice() {
        return Err(ConfirmationError::new(
            ConfirmationErrorCode::ScopeMismatch,
            "batch confirmation must bind the complete ordered L3 plan",
        ));
    }
    Ok(())
}

fn request_item(
    report: &SafetyIntentReport,
    order: usize,
    rollback: &VerifiedRollbackMetadata,
) -> Result<ConfirmationRequestItem, ConfirmationError> {
    let intent = intent_for_order(report, order)?;
    let risk = risk_for_order(report, order)?;
    Ok(ConfirmationRequestItem {
        intent_order: order,
        action: intent.action,
        targets: sanitize_targets(&intent.targets),
        parameters_summary: sanitize_json_summary(&intent.parameters),
        impact_scope: intent.impact_scope,
        risk_level: risk.level,
        total_score: risk.total_score,
        factors: sanitize_factors(&risk.factors),
        matched_rules: sanitize_rules(&risk.matched_rules),
        rollback_advice: rollback_advice(rollback.item_for(order)),
        irreversible: rollback
            .item_for(order)
            .is_some_and(|item| item.status == RollbackStatus::Irreversible),
    })
}

fn validate_rollback_metadata_for_report(
    rollback: &VerifiedRollbackMetadata,
    report: &SafetyIntentReport,
) -> Result<(), ConfirmationError> {
    for item in &rollback.items {
        intent_for_order(report, item.intent_order)?;
        let risk = risk_for_order(report, item.intent_order)?;
        if risk.level != RiskLevel::L3 || risk.policy != RiskPolicy::Confirm {
            return Err(ConfirmationError::new(
                ConfirmationErrorCode::InvalidRequest,
                "rollback metadata may only describe L3 confirmation intents",
            ));
        }
    }
    Ok(())
}

fn rollback_advice(item: Option<&VerifiedRollbackItem>) -> RollbackAdvice {
    match item {
        Some(item) if item.status == RollbackStatus::Verified => RollbackAdvice {
            status: RollbackStatus::Verified,
            verified: true,
            irreversible: false,
            summary: item
                .summary
                .as_deref()
                .map(sanitize_summary)
                .unwrap_or_else(|| "verified rollback metadata available".to_string()),
        },
        Some(item) if item.status == RollbackStatus::Irreversible => RollbackAdvice {
            status: RollbackStatus::Irreversible,
            verified: false,
            irreversible: true,
            summary: item
                .irreversible_reason
                .as_deref()
                .map(sanitize_summary)
                .unwrap_or_else(|| "operation is explicitly irreversible".to_string()),
        },
        _ => RollbackAdvice {
            status: RollbackStatus::Unknown,
            verified: false,
            irreversible: false,
            summary: "no verified rollback available".to_string(),
        },
    }
}

fn intent_for_order(
    report: &SafetyIntentReport,
    order: usize,
) -> Result<&SafetyIntent, ConfirmationError> {
    report
        .intents
        .iter()
        .find(|intent| intent.order == order)
        .ok_or_else(|| {
            ConfirmationError::new(
                ConfirmationErrorCode::InvalidRequest,
                "confirmation intent order missing from report",
            )
        })
}

fn risk_for_order(
    report: &SafetyIntentReport,
    order: usize,
) -> Result<&IntentRiskAssessment, ConfirmationError> {
    report
        .risks
        .iter()
        .find(|risk| risk.order == order)
        .ok_or_else(|| {
            ConfirmationError::new(
                ConfirmationErrorCode::InvalidRequest,
                "confirmation risk order missing from report",
            )
        })
}

fn confirmation_binding_hash(
    session_id: &str,
    report: &SafetyIntentReport,
    mode: ConfirmationMode,
    orders: &[usize],
) -> Result<String, ConfirmationError> {
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(mode.as_str().as_bytes());
    hasher.update(report.input_summary_hash.as_bytes());
    hasher.update(report.rule_generation.to_le_bytes());
    for order in orders {
        let intent = intent_for_order(report, *order)?;
        let risk = risk_for_order(report, *order)?;
        let bytes = serde_json::to_vec(&(intent, risk)).map_err(|_| {
            ConfirmationError::new(
                ConfirmationErrorCode::InvalidRequest,
                "confirmation scope could not encode intent summary",
            )
        })?;
        hasher.update(order.to_le_bytes());
        hasher.update(bytes);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn request_id(
    session_id: &str,
    report: &SafetyIntentReport,
    mode: ConfirmationMode,
    orders: &[usize],
    counter: u64,
    now_epoch_seconds: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"request");
    hasher.update(session_id.as_bytes());
    hasher.update(mode.as_str().as_bytes());
    hasher.update(report.input_summary_hash.as_bytes());
    hasher.update(report.rule_generation.to_le_bytes());
    for order in orders {
        hasher.update(order.to_le_bytes());
    }
    hasher.update(counter.to_le_bytes());
    hasher.update(now_epoch_seconds.to_le_bytes());
    format!("confirm-{:x}", hasher.finalize())
}

fn secure_nonce() -> Result<[u8; 32], ConfirmationError> {
    let mut nonce = [0_u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|_| {
        ConfirmationError::new(
            ConfirmationErrorCode::RandomFailed,
            "secure random token generation failed",
        )
    })?;
    Ok(nonce)
}

fn token_id_from_nonce(pending: &PendingConfirmation, nonce: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"token");
    hasher.update(nonce);
    hasher.update(pending.request.request_id.as_bytes());
    hasher.update(pending.scope.action.as_bytes());
    format!("safety-token-{:x}", hasher.finalize())
}

fn request_items_hash(items: &[ConfirmationRequestItem]) -> String {
    let bytes = serde_json::to_vec(items).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn sanitize_targets(targets: &[IntentTarget]) -> Vec<IntentTarget> {
    targets
        .iter()
        .take(MAX_EVIDENCE_ITEMS)
        .map(|target| IntentTarget {
            kind: target.kind,
            value: sanitize_summary(&target.value),
        })
        .collect()
}

fn sanitize_factors(factors: &[RiskFactorAssessment]) -> Vec<RiskFactorAssessment> {
    factors
        .iter()
        .take(MAX_EVIDENCE_ITEMS)
        .map(|factor| RiskFactorAssessment {
            factor: factor.factor,
            score: factor.score,
            evidence: sanitize_strings(&factor.evidence),
        })
        .collect()
}

fn sanitize_rules(rules: &[SafetyRuleMatch]) -> Vec<ConfirmationRuleEvidence> {
    rules
        .iter()
        .take(MAX_EVIDENCE_ITEMS)
        .map(|rule| ConfirmationRuleEvidence {
            rule_id: sanitize_summary(&rule.rule_id),
            evidence: sanitize_strings(&rule.evidence),
        })
        .collect()
}

fn sanitize_strings(values: &[String]) -> Vec<String> {
    values
        .iter()
        .take(MAX_EVIDENCE_ITEMS)
        .map(|value| sanitize_summary(value))
        .collect()
}

fn sanitize_json_summary(value: &Value) -> String {
    bounded_preview(
        &serde_json::to_string(&sanitize_json_value(value)).unwrap_or_default(),
        MAX_SUMMARY_BYTES,
    )
}

fn sanitize_json_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| {
                    let sanitized = if is_secret_json_key(key) {
                        Value::String("[REDACTED]".to_string())
                    } else {
                        sanitize_json_value(value)
                    };
                    (key.clone(), sanitized)
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(sanitize_json_value).collect()),
        Value::String(value) => Value::String(sanitize_summary(value)),
        other => other.clone(),
    }
}

fn is_secret_json_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let normalized = lower.replace(['-', '_'], "");
    matches!(
        lower.as_str(),
        "token" | "secret" | "password" | "authorization" | "api_key" | "apikey"
    ) || normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("authorization")
        || normalized.contains("apikey")
}

fn sanitize_summary(value: &str) -> String {
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
    bounded_preview(&redacted, MAX_SUMMARY_BYTES)
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
        if ascii_eq_ignore_case(&bytes[cursor..cursor + marker_bytes.len()], marker_bytes) {
            let marker_end = cursor + marker_bytes.len();
            let mut end = marker_end;
            while end < bytes.len() && bytes[end].is_ascii_whitespace() {
                end += 1;
            }
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

fn bounded_preview(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...[truncated]", &value[..end])
}

fn validate_session(session_id: &str) -> Result<(), ConfirmationError> {
    if session_id.trim() != session_id
        || session_id.is_empty()
        || session_id.len() > MAX_SUMMARY_BYTES
        || session_id.chars().any(char::is_control)
    {
        return Err(ConfirmationError::new(
            ConfirmationErrorCode::InvalidRequest,
            "sessionId must be non-empty, bounded, and free of control characters",
        ));
    }
    Ok(())
}

fn validate_identity(field: &str, value: &str) -> Result<(), ConfirmationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '@' | ':' | '-'))
    {
        return Err(ConfirmationError::new(
            ConfirmationErrorCode::InvalidRequest,
            format!("{field} must be a stable ASCII identifier"),
        ));
    }
    Ok(())
}

fn validate_non_empty_summary(field: &str, value: &str) -> Result<(), ConfirmationError> {
    if value.trim().is_empty() || value.len() > MAX_SUMMARY_BYTES {
        return Err(ConfirmationError::new(
            ConfirmationErrorCode::InvalidRequest,
            format!("{field} must be non-empty and no more than {MAX_SUMMARY_BYTES} bytes"),
        ));
    }
    Ok(())
}

/// Structured confirmation error with stable code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmationError {
    pub code: ConfirmationErrorCode,
    pub message: String,
}

impl ConfirmationError {
    fn new(code: ConfirmationErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: sanitize_summary(&message.into()),
        }
    }
}

impl From<ApprovalTokenError> for ConfirmationError {
    fn from(error: ApprovalTokenError) -> Self {
        let code = match error {
            ApprovalTokenError::NoApproval => ConfirmationErrorCode::TokenNotFound,
            ApprovalTokenError::ApprovalExpired => ConfirmationErrorCode::TokenExpired,
            ApprovalTokenError::ApprovalAlreadyConsumed => ConfirmationErrorCode::TokenReplayed,
            ApprovalTokenError::ScopeMismatch { .. }
            | ApprovalTokenError::UnauthorizedDelegate { .. } => {
                ConfirmationErrorCode::ScopeMismatch
            }
            ApprovalTokenError::ApprovalPending | ApprovalTokenError::ApprovalRevoked => {
                ConfirmationErrorCode::ApprovalToken
            }
        };
        Self::new(code, error.as_str())
    }
}

impl fmt::Display for ConfirmationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for ConfirmationError {}

/// Stable confirmation error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationErrorCode {
    InvalidConfig,
    InvalidRequest,
    RequestNotFound,
    RequestExpired,
    TokenNotFound,
    TokenExpired,
    TokenReplayed,
    LimitExceeded,
    ScopeMismatch,
    ApprovalToken,
    RandomFailed,
    DeniedRisk,
}

impl ConfirmationErrorCode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::InvalidRequest => "invalid_request",
            Self::RequestNotFound => "request_not_found",
            Self::RequestExpired => "request_expired",
            Self::TokenNotFound => "token_not_found",
            Self::TokenExpired => "token_expired",
            Self::TokenReplayed => "token_replayed",
            Self::LimitExceeded => "limit_exceeded",
            Self::ScopeMismatch => "scope_mismatch",
            Self::ApprovalToken => "approval_token",
            Self::RandomFailed => "random_failed",
            Self::DeniedRisk => "denied_risk",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval_tokens::ApprovalTokenStatus;
    use crate::safety_intent::{analyze_plan, ToolCallPlan, ToolExecutionPlan};
    use serde_json::json;

    fn shell_report(command: &str) -> SafetyIntentReport {
        analyze_plan(&ToolExecutionPlan {
            source: Some("test-session token=SOURCE_SECRET".to_string()),
            tool_calls: vec![ToolCallPlan {
                tool_name: "Bash".to_string(),
                source: None,
                arguments: json!({ "command": command }),
            }],
        })
        .expect("plan should analyze")
    }

    fn two_l3_report(first: &str, second: &str) -> SafetyIntentReport {
        analyze_plan(&ToolExecutionPlan {
            source: None,
            tool_calls: vec![
                ToolCallPlan {
                    tool_name: "Bash".to_string(),
                    source: None,
                    arguments: json!({ "command": first }),
                },
                ToolCallPlan {
                    tool_name: "Bash".to_string(),
                    source: None,
                    arguments: json!({ "command": second }),
                },
            ],
        })
        .expect("plan should analyze")
    }

    fn required_requests(requirement: ConfirmationRequirement) -> Vec<ConfirmationRequest> {
        match requirement {
            ConfirmationRequirement::Required { requests } => requests,
            other => panic!("expected required confirmation, got {other:?}"),
        }
    }

    fn allow_request(
        gate: &mut ConfirmationGate,
        request: &ConfirmationRequest,
        now: u64,
    ) -> String {
        gate.decide(
            &request.request_id,
            ConfirmationDecision::AllowOnce {},
            "human-owner",
            "agent-exec",
            now,
        )
        .expect("decision should allow")
        .token
        .expect("allow-once should issue token")
    }

    #[test]
    fn safety_confirmation_l3_request_contains_bounded_redacted_context() {
        let report = shell_report("bash -c 'printf token=SECRET Bearer SECRET2 ok'");
        assert_eq!(report.overall_policy, RiskPolicy::Confirm);
        let mut gate = ConfirmationGate::default();
        let rollback = VerifiedRollbackMetadata {
            items: vec![VerifiedRollbackItem::verified(0, "restore generated file")],
        };

        let requests = required_requests(
            gate.require_confirmation(
                "session-1",
                &report,
                ConfirmationMode::PerItem,
                Some(&rollback),
                100,
            )
            .expect("confirmation request"),
        );

        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.session_id, "session-1");
        assert_eq!(request.mode, ConfirmationMode::PerItem);
        assert_eq!(request.input_summary_hash, report.input_summary_hash);
        assert_eq!(request.plan_hash, report.input_summary_hash);
        assert_eq!(request.rule_generation, report.rule_generation);
        assert_eq!(request.expires_at_epoch_seconds, 160);
        assert_eq!(request.items.len(), 1);
        let item = &request.items[0];
        assert_eq!(item.intent_order, 0);
        assert_eq!(item.action, SafetyAction::ExecuteProcess);
        assert_eq!(item.impact_scope, ImpactScope::Process);
        assert_eq!(item.risk_level, RiskLevel::L3);
        assert!(!item.factors.is_empty());
        assert!(item
            .matched_rules
            .iter()
            .any(|rule| rule.rule_id == "builtin.nested-exec"));
        assert_eq!(item.rollback_advice.status, RollbackStatus::Verified);
        assert!(item.rollback_advice.verified);

        let encoded = serde_json::to_string(request).expect("request json");
        assert!(!encoded.contains("SECRET"), "{encoded}");
        assert!(encoded.contains("token=[REDACTED]"));
        assert!(encoded.contains("Bearer [REDACTED]"));
    }

    #[test]
    fn safety_confirmation_parameters_summary_recursively_redacts_secret_keys() {
        let mut report = shell_report("bash -c 'printf ok'");
        report.intents[0].parameters = json!({
            "nested": {
                "password": "PW_SECRET",
                "items": [
                    {
                        "token": "TOK_SECRET",
                        "apiKey": "API_SECRET",
                        "message": "Bearer BEAR_SECRET token=MARKER_SECRET"
                    }
                ]
            }
        });
        let mut gate = ConfirmationGate::default();
        let request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 10)
                .expect("request"),
        )
        .remove(0);

        let encoded = serde_json::to_string(&request).expect("request json");
        for secret in [
            "PW_SECRET",
            "TOK_SECRET",
            "API_SECRET",
            "BEAR_SECRET",
            "MARKER_SECRET",
        ] {
            assert!(!encoded.contains(secret), "{secret} leaked in {encoded}");
        }
        let summary = &request.items[0].parameters_summary;
        assert!(summary.contains("\"password\":\"[REDACTED]\""), "{summary}");
        assert!(summary.contains("\"token\":\"[REDACTED]\""), "{summary}");
        assert!(summary.contains("\"apiKey\":\"[REDACTED]\""), "{summary}");
        assert!(summary.contains("Bearer [REDACTED]"), "{summary}");
    }

    #[test]
    fn safety_confirmation_l4_rejects_and_l1_l2_need_no_request() {
        let mut gate = ConfirmationGate::default();
        let l4 = shell_report("rm -rf /");
        let rejected = gate
            .require_confirmation("session-1", &l4, ConfirmationMode::PerItem, None, 10)
            .expect("l4 decision");
        assert!(matches!(rejected, ConfirmationRequirement::Rejected { .. }));
        assert_eq!(gate.pending_count(), 0);

        let low = shell_report("printf ok");
        let not_required = gate
            .require_confirmation("session-1", &low, ConfirmationMode::PerItem, None, 10)
            .expect("low decision");
        assert_eq!(not_required, ConfirmationRequirement::NotRequired);
    }

    #[test]
    fn safety_confirmation_strict_decision_allow_deny_and_request_expiry() {
        assert!(serde_json::from_str::<ConfirmationDecision>(r#""continue""#).is_err());
        assert_eq!(
            serde_json::from_str::<ConfirmationDecision>(r#"{"decision":"allowOnce"}"#)
                .expect("allow once"),
            ConfirmationDecision::AllowOnce {}
        );
        assert!(serde_json::from_str::<ConfirmationDecision>(
            r#"{"decision":"allowOnce","actorId":"owner","executorId":"agent","extra":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ConfirmationDecision>(
            r#"{"decision":"allowOnce","actorId":"owner"}"#
        )
        .is_err());

        let report = shell_report("bash -c 'printf ok'");
        let mut gate = ConfirmationGate::default();
        let request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 100)
                .expect("request"),
        )
        .remove(0);
        let denied = gate
            .decide(
                &request.request_id,
                ConfirmationDecision::Deny {
                    reason: "not approved".to_string(),
                },
                "owner",
                "",
                159,
            )
            .expect("deny decision");
        assert_eq!(denied.status, ConfirmationDecisionStatus::Denied);
        assert!(denied.token.is_none());

        let request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 100)
                .expect("request"),
        )
        .remove(0);
        let token = allow_request(&mut gate, &request, 159);
        let audit = gate
            .consume(
                &token,
                "session-1",
                &report,
                ConfirmationMode::PerItem,
                Some(0),
                "human-owner",
                "agent-exec",
                159,
            )
            .expect("token should consume before expiry");
        assert_eq!(audit.status, ApprovalTokenStatus::Consumed);

        let request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 100)
                .expect("request"),
        )
        .remove(0);
        let expired = gate
            .decide(
                &request.request_id,
                ConfirmationDecision::AllowOnce {},
                "owner",
                "agent-exec",
                160,
            )
            .expect_err("request expires when now equals expiresAt");
        assert_eq!(expired.code, ConfirmationErrorCode::RequestExpired);

        let request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 200)
                .expect("request"),
        )
        .remove(0);
        let token = allow_request(&mut gate, &request, 259);
        let expired = gate
            .consume(
                &token,
                "session-1",
                &report,
                ConfirmationMode::PerItem,
                Some(0),
                "human-owner",
                "agent-exec",
                260,
            )
            .expect_err("token expires when now equals expiresAt");
        assert_eq!(expired.code, ConfirmationErrorCode::TokenExpired);
    }

    #[test]
    fn safety_confirmation_invalid_decision_or_identity_preserves_pending() {
        let report = shell_report("bash -c 'printf ok'");
        let mut gate = ConfirmationGate::default();
        let request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 10)
                .expect("request"),
        )
        .remove(0);
        assert_eq!(gate.pending_count(), 1);

        let empty_reason = gate
            .decide(
                &request.request_id,
                ConfirmationDecision::Deny {
                    reason: "   ".to_string(),
                },
                "owner",
                "agent-exec",
                11,
            )
            .expect_err("empty deny reason rejected before pending removal");
        assert_eq!(empty_reason.code, ConfirmationErrorCode::InvalidRequest);
        assert_eq!(gate.pending_count(), 1);

        let bad_identity = gate
            .decide(
                &request.request_id,
                ConfirmationDecision::AllowOnce {},
                "owner token=SECRET",
                "agent-exec",
                11,
            )
            .expect_err("identity redaction collision rejected");
        assert_eq!(bad_identity.code, ConfirmationErrorCode::InvalidRequest);
        assert_eq!(gate.pending_count(), 1);

        let token = gate
            .decide(
                &request.request_id,
                ConfirmationDecision::AllowOnce {},
                "owner",
                "agent-exec",
                11,
            )
            .expect("valid decision should still work")
            .token
            .expect("token");
        assert_eq!(gate.pending_count(), 0);
        assert_eq!(gate.active_token_count(), 1);
        assert!(token.starts_with("safety-token-"));
    }

    #[test]
    fn safety_confirmation_tokens_use_random_nonce_and_do_not_leak_in_debug() {
        let report = shell_report("bash -c 'printf ok'");
        let mut gate = ConfirmationGate::default();
        let first_request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 10)
                .expect("request"),
        )
        .remove(0);
        let second_request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 10)
                .expect("request"),
        )
        .remove(0);

        let first = gate
            .decide(
                &first_request.request_id,
                ConfirmationDecision::AllowOnce {},
                "owner",
                "agent-exec",
                11,
            )
            .expect("first token")
            .token
            .expect("token");
        let second = gate
            .decide(
                &second_request.request_id,
                ConfirmationDecision::AllowOnce {},
                "owner",
                "agent-exec",
                11,
            )
            .expect("second token")
            .token
            .expect("token");

        assert_ne!(first, second);
        let debug = format!("{gate:?}");
        assert!(!debug.contains(&first));
        assert!(!debug.contains(&second));
        assert!(debug.contains("active_token_count"));
    }

    #[test]
    fn safety_confirmation_random_failure_or_collision_exhaustion_preserves_pending() {
        let report = shell_report("bash -c 'printf ok'");
        let mut gate = ConfirmationGate::default();
        let request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 10)
                .expect("request"),
        )
        .remove(0);

        let rng_error = gate
            .decide_with_nonce_provider(
                &request.request_id,
                ConfirmationDecision::AllowOnce {},
                "owner",
                "agent-exec",
                11,
                || {
                    Err(ConfirmationError::new(
                        ConfirmationErrorCode::RandomFailed,
                        "rng unavailable",
                    ))
                },
            )
            .expect_err("rng failure must fail closed");
        assert_eq!(rng_error.code, ConfirmationErrorCode::RandomFailed);
        assert_eq!(gate.pending_count(), 1);
        assert_eq!(gate.active_token_count(), 0);

        let pending = gate.pending.get(&request.request_id).expect("pending");
        let collision_nonce = [7_u8; 32];
        let collision = token_id_from_nonce(pending, &collision_nonce);
        gate.issued.insert(
            collision.clone(),
            IssuedConfirmation {
                actor_id: "owner".to_string(),
                executor_id: "agent-exec".to_string(),
                expires_at_epoch_seconds: 70,
            },
        );
        let exhausted = gate
            .decide_with_nonce_provider(
                &request.request_id,
                ConfirmationDecision::AllowOnce {},
                "owner",
                "agent-exec",
                11,
                || Ok(collision_nonce),
            )
            .expect_err("collision exhaustion must fail closed");
        assert_eq!(exhausted.code, ConfirmationErrorCode::RandomFailed);
        assert_eq!(gate.pending_count(), 1);

        let mut attempts = 0;
        let token = gate
            .decide_with_nonce_provider(
                &request.request_id,
                ConfirmationDecision::AllowOnce {},
                "owner",
                "agent-exec",
                11,
                || {
                    attempts += 1;
                    if attempts == 1 {
                        Ok(collision_nonce)
                    } else {
                        Ok([8_u8; 32])
                    }
                },
            )
            .expect("retry should skip collision")
            .token
            .expect("token");
        assert_ne!(token, collision);
        assert_eq!(attempts, 2);
        assert_eq!(gate.pending_count(), 0);
    }

    #[test]
    fn safety_confirmation_request_counter_overflow_fails_without_inserting() {
        let report = shell_report("bash -c 'printf ok'");
        let mut gate = ConfirmationGate::default();
        gate.counter = u64::MAX;
        let error = gate
            .require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 10)
            .expect_err("counter overflow");
        assert_eq!(error.code, ConfirmationErrorCode::LimitExceeded);
        assert_eq!(gate.pending_count(), 0);
    }

    #[test]
    fn safety_confirmation_rejects_replay_actor_executor_and_scope_mismatch() {
        let report = shell_report("bash -c 'printf ok'");
        let mut gate = ConfirmationGate::default();
        let request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 10)
                .expect("request"),
        )
        .remove(0);
        let token = allow_request(&mut gate, &request, 20);

        let actor_mismatch = gate
            .consume(
                &token,
                "session-1",
                &report,
                ConfirmationMode::PerItem,
                Some(0),
                "other-owner",
                "agent-exec",
                21,
            )
            .expect_err("actor mismatch");
        assert_eq!(actor_mismatch.code, ConfirmationErrorCode::ScopeMismatch);

        let executor_mismatch = gate
            .consume(
                &token,
                "session-1",
                &report,
                ConfirmationMode::PerItem,
                Some(0),
                "human-owner",
                "other-agent",
                21,
            )
            .expect_err("executor mismatch");
        assert_eq!(executor_mismatch.code, ConfirmationErrorCode::ScopeMismatch);

        let changed_report = shell_report("bash -c 'printf changed'");
        let scope_mismatch = gate
            .consume(
                &token,
                "session-1",
                &changed_report,
                ConfirmationMode::PerItem,
                Some(0),
                "human-owner",
                "agent-exec",
                21,
            )
            .expect_err("plan mutation must mismatch scope");
        assert_eq!(scope_mismatch.code, ConfirmationErrorCode::ScopeMismatch);

        gate.consume(
            &token,
            "session-1",
            &report,
            ConfirmationMode::PerItem,
            Some(0),
            "human-owner",
            "agent-exec",
            21,
        )
        .expect("first valid consume");
        let replay = gate
            .consume(
                &token,
                "session-1",
                &report,
                ConfirmationMode::PerItem,
                Some(0),
                "human-owner",
                "agent-exec",
                22,
            )
            .expect_err("replay should fail");
        assert_eq!(replay.code, ConfirmationErrorCode::TokenNotFound);
    }

    #[test]
    fn safety_confirmation_per_item_and_batch_scopes_are_not_interchangeable() {
        let report = two_l3_report("bash -c 'printf one'", "bash -c 'printf two'");
        let mut gate = ConfirmationGate::default();
        let per_item = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 10)
                .expect("per-item requests"),
        );
        assert_eq!(per_item.len(), 2);
        let per_token = allow_request(&mut gate, &per_item[0], 11);
        let batch_mismatch = gate
            .consume(
                &per_token,
                "session-1",
                &report,
                ConfirmationMode::Batch,
                None,
                "human-owner",
                "agent-exec",
                12,
            )
            .expect_err("per-item token must not authorize batch");
        assert_eq!(batch_mismatch.code, ConfirmationErrorCode::ScopeMismatch);

        let batch = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::Batch, None, 20)
                .expect("batch request"),
        )
        .remove(0);
        assert_eq!(batch.items.len(), 2);
        let batch_token = allow_request(&mut gate, &batch, 21);
        let per_mismatch = gate
            .consume(
                &batch_token,
                "session-1",
                &report,
                ConfirmationMode::PerItem,
                Some(0),
                "human-owner",
                "agent-exec",
                22,
            )
            .expect_err("batch token must not authorize one item");
        assert_eq!(per_mismatch.code, ConfirmationErrorCode::ScopeMismatch);

        let reversed = two_l3_report("bash -c 'printf two'", "bash -c 'printf one'");
        let order_mismatch = gate
            .consume(
                &batch_token,
                "session-1",
                &reversed,
                ConfirmationMode::Batch,
                None,
                "human-owner",
                "agent-exec",
                22,
            )
            .expect_err("batch token binds ordered plan");
        assert_eq!(order_mismatch.code, ConfirmationErrorCode::ScopeMismatch);

        let mut generation_changed = report.clone();
        generation_changed.rule_generation += 1;
        let generation_mismatch = gate
            .consume(
                &batch_token,
                "session-1",
                &generation_changed,
                ConfirmationMode::Batch,
                None,
                "human-owner",
                "agent-exec",
                22,
            )
            .expect_err("batch token binds rule generation");
        assert_eq!(
            generation_mismatch.code,
            ConfirmationErrorCode::ScopeMismatch
        );
    }

    #[test]
    fn safety_confirmation_batch_with_l4_and_pending_limit_fail_closed() {
        let mut gate = ConfirmationGate::new(ConfirmationConfig {
            ttl_seconds: 60,
            max_pending: 1,
        })
        .expect("config");
        let report = two_l3_report("bash -c 'printf one'", "bash -c 'printf two'");
        let limited = gate
            .require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 10)
            .expect_err("two per-item requests exceed pending limit");
        assert_eq!(limited.code, ConfirmationErrorCode::LimitExceeded);

        let mixed = analyze_plan(&ToolExecutionPlan {
            source: None,
            tool_calls: vec![
                ToolCallPlan {
                    tool_name: "Bash".to_string(),
                    source: None,
                    arguments: json!({ "command": "bash -c 'printf ok'" }),
                },
                ToolCallPlan {
                    tool_name: "Bash".to_string(),
                    source: None,
                    arguments: json!({ "command": "rm -rf /" }),
                },
            ],
        })
        .expect("mixed plan");
        assert!(matches!(
            gate.require_confirmation("session-1", &mixed, ConfirmationMode::Batch, None, 10)
                .expect("mixed rejected"),
            ConfirmationRequirement::Rejected { .. }
        ));
    }

    #[test]
    fn safety_confirmation_active_token_capacity_recovers_after_consume_or_expiry() {
        let report = shell_report("bash -c 'printf ok'");
        let mut gate = ConfirmationGate::new(ConfirmationConfig {
            ttl_seconds: 60,
            max_pending: 1,
        })
        .expect("config");
        let request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 10)
                .expect("request"),
        )
        .remove(0);
        let token = allow_request(&mut gate, &request, 11);
        assert_eq!(gate.pending_count(), 0);
        assert_eq!(gate.active_token_count(), 1);

        let limited = gate
            .require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 12)
            .expect_err("active token consumes capacity");
        assert_eq!(limited.code, ConfirmationErrorCode::LimitExceeded);

        gate.consume(
            &token,
            "session-1",
            &report,
            ConfirmationMode::PerItem,
            Some(0),
            "human-owner",
            "agent-exec",
            13,
        )
        .expect("consume");
        assert_eq!(gate.active_token_count(), 0);
        assert!(matches!(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 14)
                .expect("capacity recovered"),
            ConfirmationRequirement::Required { .. }
        ));

        let mut expiry_gate = ConfirmationGate::new(ConfirmationConfig {
            ttl_seconds: 60,
            max_pending: 1,
        })
        .expect("config");
        let request = required_requests(
            expiry_gate
                .require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 100)
                .expect("request"),
        )
        .remove(0);
        let token = allow_request(&mut expiry_gate, &request, 101);
        assert_eq!(expiry_gate.active_token_count(), 1);
        let expired = expiry_gate
            .consume(
                &token,
                "session-1",
                &report,
                ConfirmationMode::PerItem,
                Some(0),
                "human-owner",
                "agent-exec",
                160,
            )
            .expect_err("expiry cleans active token");
        assert_eq!(expired.code, ConfirmationErrorCode::TokenExpired);
        assert_eq!(expiry_gate.active_token_count(), 0);
    }

    #[test]
    fn safety_confirmation_rejects_forged_overall_when_any_risk_is_l4() {
        let mut forged = shell_report("rm -rf /");
        forged.overall_level = RiskLevel::L1;
        forged.overall_policy = RiskPolicy::Allow;
        let mut gate = ConfirmationGate::default();
        assert!(matches!(
            gate.require_confirmation("session-1", &forged, ConfirmationMode::PerItem, None, 10)
                .expect("forged report rejected"),
            ConfirmationRequirement::Rejected { .. }
        ));

        let report = shell_report("bash -c 'printf ok'");
        let request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 20)
                .expect("request"),
        )
        .remove(0);
        let token = allow_request(&mut gate, &request, 21);
        let denied = gate
            .consume(
                &token,
                "session-1",
                &forged,
                ConfirmationMode::PerItem,
                Some(0),
                "human-owner",
                "agent-exec",
                22,
            )
            .expect_err("consume also rejects l4 report");
        assert_eq!(denied.code, ConfirmationErrorCode::DeniedRisk);

        let mut forged_overall = report.clone();
        forged_overall.overall_level = RiskLevel::L4;
        forged_overall.overall_policy = RiskPolicy::Deny;
        let denied = gate
            .consume(
                &token,
                "session-1",
                &forged_overall,
                ConfirmationMode::PerItem,
                Some(0),
                "human-owner",
                "agent-exec",
                22,
            )
            .expect_err("consume rejects forged overall l4/deny");
        assert_eq!(denied.code, ConfirmationErrorCode::DeniedRisk);
    }

    #[test]
    fn safety_confirmation_rejects_inconsistent_rollback_metadata() {
        let report = shell_report("bash -c 'printf ok'");
        let mut gate = ConfirmationGate::default();
        for rollback in [
            VerifiedRollbackMetadata {
                items: vec![
                    VerifiedRollbackItem::verified(0, "restore"),
                    VerifiedRollbackItem::verified(0, "restore again"),
                ],
            },
            VerifiedRollbackMetadata {
                items: vec![VerifiedRollbackItem {
                    intent_order: 0,
                    status: RollbackStatus::Verified,
                    summary: None,
                    irreversible_reason: None,
                }],
            },
            VerifiedRollbackMetadata {
                items: vec![VerifiedRollbackItem {
                    intent_order: 0,
                    status: RollbackStatus::Irreversible,
                    summary: None,
                    irreversible_reason: Some(" ".to_string()),
                }],
            },
            VerifiedRollbackMetadata {
                items: vec![VerifiedRollbackItem {
                    intent_order: 0,
                    status: RollbackStatus::Unknown,
                    summary: Some("fake verified".to_string()),
                    irreversible_reason: None,
                }],
            },
        ] {
            let error = gate
                .require_confirmation(
                    "session-1",
                    &report,
                    ConfirmationMode::PerItem,
                    Some(&rollback),
                    10,
                )
                .expect_err("invalid rollback metadata");
            assert_eq!(error.code, ConfirmationErrorCode::InvalidRequest);
            assert_eq!(gate.pending_count(), 0);
        }
    }

    #[test]
    fn safety_confirmation_missing_rollback_is_explicitly_unknown() {
        let report = shell_report("bash -c 'printf ok'");
        let mut gate = ConfirmationGate::default();
        let request = required_requests(
            gate.require_confirmation("session-1", &report, ConfirmationMode::PerItem, None, 10)
                .expect("request"),
        )
        .remove(0);
        assert_eq!(
            request.items[0].rollback_advice.status,
            RollbackStatus::Unknown
        );
        assert!(!request.items[0].rollback_advice.verified);
        assert!(!request.items[0].rollback_advice.irreversible);
        assert_eq!(
            request.items[0].rollback_advice.summary,
            "no verified rollback available"
        );
    }
}
