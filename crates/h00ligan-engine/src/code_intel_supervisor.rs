//! Deterministic scheduling core for manual and watched index publication.
//!
//! Filesystem notifications are hints, not indexing authority. This module
//! records a monotonic observation epoch and schedules complete source
//! reconciliation until a successful publication covers the newest observed
//! epoch. Adapters own presentation and the eventual runtime driver; they do
//! not get to invent competing lifecycle rules.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use parking_lot::Mutex;
use thiserror::Error;
use tokio::sync::{Notify, oneshot, watch};
use uuid::Uuid;

use crate::code_intel_cancellation::IndexCancellation;
use crate::code_intel_indexing::{
    BoundIndexAdmission, BoundIndexPlan, BoundIndexPlanError, BoundIndexRequest, ProviderIntent,
};
use crate::code_intel_publication::{
    CapabilityFloorPolicy, IndexGenerationPublicationError, LiveGenerationBasis,
    PublicationControlToken, PublicationControlWitness, PublicationError, PublicationRecovery,
    PublicationStepTiming, PublishedIndexGeneration, publication_control_token,
    publication_control_witness,
};
#[cfg(test)]
use crate::code_intel_rust_semantic_provider::RustSemanticProviderConfig;
use crate::code_intel_semantic_provider_registry::{
    SemanticProviderConfig, SemanticProviderRegistry, SemanticProviderRegistryError,
};
use crate::code_intel_toolchain::ToolchainResolver;
use crate::index_pipeline::{IndexPhaseTiming, IndexPipelineError, IndexProgressEvent};
use crate::project_binding::ProjectBinding;

/// Stable process-local identity for one supervised indexing attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IndexOperationId {
    supervisor_id: Uuid,
    sequence: u64,
}

impl IndexOperationId {
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

impl fmt::Display for IndexOperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "index-{}-{}",
            self.supervisor_id.simple(),
            self.sequence
        )
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("invalid index operation ID")]
pub struct IndexOperationIdParseError;

impl FromStr for IndexOperationId {
    type Err = IndexOperationIdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let body = value
            .strip_prefix("index-")
            .ok_or(IndexOperationIdParseError)?;
        let (supervisor, sequence) = body.rsplit_once('-').ok_or(IndexOperationIdParseError)?;
        if supervisor.len() != 32 || sequence.is_empty() {
            return Err(IndexOperationIdParseError);
        }
        Ok(Self {
            supervisor_id: Uuid::parse_str(supervisor).map_err(|_| IndexOperationIdParseError)?,
            sequence: sequence
                .parse::<u64>()
                .map_err(|_| IndexOperationIdParseError)?,
        })
    }
}

/// Why a supervised indexing attempt exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexOperationTrigger {
    /// An operator or API client explicitly requested indexing.
    Manual,
    /// One or more filesystem hints require authoritative reconciliation.
    Watch,
}

/// Why an active attempt must stop at its next safe cancellation boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexCancellationReason {
    /// A newer filesystem epoch supersedes a WATCH candidate.
    Superseded,
    /// A manual request takes priority over background WATCH work.
    ManualPriority,
    /// The exact operation was explicitly cancelled.
    Requested,
    /// The owning supervisor is shutting down.
    Shutdown,
}

/// One effect the runtime driver must perform after a state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexScheduleAction {
    /// Begin one indexing attempt that reconciles all inputs visible through
    /// `covered_epoch`.
    Start {
        operation_id: IndexOperationId,
        trigger: IndexOperationTrigger,
        covered_epoch: u64,
    },
    /// Cooperatively cancel one exact active attempt.
    Cancel {
        operation_id: IndexOperationId,
        reason: IndexCancellationReason,
    },
    /// Complete a queued manual request without starting an indexing attempt.
    CancelQueued {
        operation_id: IndexOperationId,
        reason: IndexCancellationReason,
    },
}

/// Result category returned to the scheduling core. Publication details live
/// in the runtime receipt and never influence scheduling authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexAttemptResult {
    Published,
    Failed,
    Cancelled,
}

/// Bounded, adapter-neutral scheduling snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexScheduleSnapshot {
    pub desired_epoch: u64,
    pub published_epoch: u64,
    pub active_operation: Option<IndexOperationId>,
    pub active_trigger: Option<IndexOperationTrigger>,
    pub manual_queued: bool,
    pub watch_enabled: bool,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IndexScheduleError {
    #[error("one manual indexing operation is already active or queued")]
    ManualBusy,
    #[error("operation {requested:?} is not the active operation")]
    OperationNotActive { requested: IndexOperationId },
}

#[derive(Debug, Clone, Copy)]
struct ActiveOperation {
    id: IndexOperationId,
    trigger: IndexOperationTrigger,
    covered_epoch: u64,
    /// This candidate began while at least one direct source epoch remained
    /// unpublished. A newer source hint may supersede it. Periodic no-work
    /// probes deliberately finish so their provider exchange is not
    /// quarantined merely to start the queued changed epoch a few milliseconds
    /// sooner.
    change_driven: bool,
    cancellation_requested: Option<IndexCancellationReason>,
}

/// Pure scheduling state machine used by the async supervisor runtime.
///
/// Keeping this core independent from Tokio and filesystem APIs makes the
/// no-missed-update and priority rules exhaustively testable.
#[derive(Debug)]
pub struct IndexSchedule {
    supervisor_id: Uuid,
    next_operation_id: u64,
    desired_epoch: u64,
    published_epoch: u64,
    /// Most recent epoch created by initial or direct filesystem authority.
    /// Periodic integrity epochs do not advance this coordinate.
    latest_change_epoch: u64,
    /// Highest source epoch that terminated unsuccessfully without a newer
    /// reconciliation request. It parks that exact epoch so a persistent
    /// failure cannot hot-loop; any later hint advances `desired_epoch` and
    /// becomes independently runnable.
    failed_epoch: u64,
    active: Option<ActiveOperation>,
    pending_manual: Option<IndexOperationId>,
    watch_enabled: bool,
    recent_terminal: VecDeque<IndexOperationId>,
}

impl Default for IndexSchedule {
    fn default() -> Self {
        Self {
            supervisor_id: Uuid::new_v4(),
            next_operation_id: 0,
            desired_epoch: 0,
            published_epoch: 0,
            latest_change_epoch: 0,
            failed_epoch: 0,
            active: None,
            pending_manual: None,
            watch_enabled: false,
            recent_terminal: VecDeque::new(),
        }
    }
}

impl IndexSchedule {
    #[must_use]
    pub fn snapshot(&self) -> IndexScheduleSnapshot {
        IndexScheduleSnapshot {
            desired_epoch: self.desired_epoch,
            published_epoch: self.published_epoch,
            active_operation: self.active.map(|active| active.id),
            active_trigger: self.active.map(|active| active.trigger),
            manual_queued: self.pending_manual.is_some(),
            watch_enabled: self.watch_enabled,
        }
    }

    /// Enable background reconciliation. `initial_reconciliation` requests a
    /// first authoritative scan even if no filesystem event has yet arrived.
    pub fn enable_watch(&mut self, initial_reconciliation: bool) -> Vec<IndexScheduleAction> {
        self.watch_enabled = true;
        if initial_reconciliation {
            self.desired_epoch = self.desired_epoch.saturating_add(1);
            self.latest_change_epoch = self.desired_epoch;
        }
        self.schedule_next()
    }

    /// Disable future WATCH attempts and cancel an active WATCH attempt. An
    /// explicit manual attempt is never cancelled by this transition.
    pub fn disable_watch(&mut self) -> Vec<IndexScheduleAction> {
        self.watch_enabled = false;
        if self
            .active
            .is_some_and(|active| active.trigger == IndexOperationTrigger::Watch)
        {
            self.request_active_cancellation(IndexCancellationReason::Requested)
        } else {
            Vec::new()
        }
    }

    /// Record a filesystem hint. The caller may coalesce paths for telemetry,
    /// but correctness depends only on this monotonic epoch.
    pub fn observe_change(&mut self) -> Vec<IndexScheduleAction> {
        self.request_reconciliation(true)
    }

    /// Request an authoritative reconciliation. Direct filesystem hints may
    /// supersede a change-driven WATCH candidate for lower latency. A bounded
    /// periodic no-work probe finishes before its changed successor so a
    /// cancellation cannot needlessly quarantine an in-flight provider
    /// authority exchange. Periodic safety scans also only queue successors so
    /// a long build cannot be starved by its own watchdog.
    pub fn request_reconciliation(
        &mut self,
        supersede_active_watch: bool,
    ) -> Vec<IndexScheduleAction> {
        self.desired_epoch = self.desired_epoch.saturating_add(1);
        if supersede_active_watch {
            self.latest_change_epoch = self.desired_epoch;
        }
        match self.active {
            Some(active)
                if supersede_active_watch
                    && active.trigger == IndexOperationTrigger::Watch
                    && active.change_driven =>
            {
                self.request_active_cancellation(IndexCancellationReason::Superseded)
            }
            Some(_) => Vec::new(),
            None => self.schedule_next(),
        }
    }

    /// Queue one explicit request. Manual work supersedes background WATCH
    /// work but never silently supersedes another manual request.
    pub fn request_manual(
        &mut self,
    ) -> Result<(IndexOperationId, Vec<IndexScheduleAction>), IndexScheduleError> {
        if self.pending_manual.is_some()
            || self
                .active
                .is_some_and(|active| active.trigger == IndexOperationTrigger::Manual)
        {
            return Err(IndexScheduleError::ManualBusy);
        }

        let id = self.allocate_operation_id();
        self.pending_manual = Some(id);
        let actions = match self.active {
            Some(_) => self.request_active_cancellation(IndexCancellationReason::ManualPriority),
            None => self.schedule_next(),
        };
        Ok((id, actions))
    }

    /// Explicitly cancel the active operation with the exact supplied ID.
    pub fn cancel(
        &mut self,
        operation_id: IndexOperationId,
    ) -> Result<Vec<IndexScheduleAction>, IndexScheduleError> {
        if self.pending_manual == Some(operation_id) {
            self.pending_manual = None;
            self.remember_terminal(operation_id);
            return Ok(vec![IndexScheduleAction::CancelQueued {
                operation_id,
                reason: IndexCancellationReason::Requested,
            }]);
        }
        let active = self.active.ok_or(IndexScheduleError::OperationNotActive {
            requested: operation_id,
        })?;
        if active.id != operation_id {
            return Err(IndexScheduleError::OperationNotActive {
                requested: operation_id,
            });
        }
        Ok(self.request_active_cancellation(IndexCancellationReason::Requested))
    }

    /// Record a source-current publication produced by the active operation
    /// without ending that operation. Semantic WATCH uses this after its
    /// structural stage becomes the visible generation and before provider
    /// enrichment completes. The active identity remains the only authority
    /// allowed to advance the covered publication epoch.
    fn mark_active_publication(
        &mut self,
        operation_id: IndexOperationId,
    ) -> Result<(), IndexScheduleError> {
        let active = self.active.ok_or(IndexScheduleError::OperationNotActive {
            requested: operation_id,
        })?;
        if active.id != operation_id {
            return Err(IndexScheduleError::OperationNotActive {
                requested: operation_id,
            });
        }
        self.published_epoch = self.published_epoch.max(active.covered_epoch);
        Ok(())
    }

    /// Complete the exact active operation and return any immediately runnable
    /// successor. A successful terminal publication advances the epoch; an
    /// already-recorded structural stage remains published if later enrichment
    /// is cancelled or fails.
    pub fn finish(
        &mut self,
        operation_id: IndexOperationId,
        result: IndexAttemptResult,
    ) -> Result<Vec<IndexScheduleAction>, IndexScheduleError> {
        let active = self.active.ok_or(IndexScheduleError::OperationNotActive {
            requested: operation_id,
        })?;
        if active.id != operation_id {
            return Err(IndexScheduleError::OperationNotActive {
                requested: operation_id,
            });
        }
        self.active = None;
        match result {
            IndexAttemptResult::Published => {
                self.published_epoch = self.published_epoch.max(active.covered_epoch);
                if self.failed_epoch <= self.published_epoch {
                    self.failed_epoch = 0;
                }
            }
            IndexAttemptResult::Failed => {
                self.failed_epoch = self.failed_epoch.max(active.covered_epoch);
            }
            IndexAttemptResult::Cancelled => {}
        }
        self.remember_terminal(operation_id);
        Ok(self.schedule_next())
    }

    /// Cancel active work and prevent any further automatic scheduling.
    pub fn shutdown(&mut self) -> Vec<IndexScheduleAction> {
        self.watch_enabled = false;
        let mut actions = self.request_active_cancellation(IndexCancellationReason::Shutdown);
        if let Some(operation_id) = self.pending_manual.take() {
            self.remember_terminal(operation_id);
            actions.push(IndexScheduleAction::CancelQueued {
                operation_id,
                reason: IndexCancellationReason::Shutdown,
            });
        }
        actions
    }

    fn schedule_next(&mut self) -> Vec<IndexScheduleAction> {
        if self.active.is_some() {
            return Vec::new();
        }
        if let Some(operation_id) = self.pending_manual.take() {
            return self.start(operation_id, IndexOperationTrigger::Manual);
        }
        let settled_epoch = self.published_epoch.max(self.failed_epoch);
        if self.watch_enabled && settled_epoch < self.desired_epoch {
            let operation_id = self.allocate_operation_id();
            return self.start(operation_id, IndexOperationTrigger::Watch);
        }
        Vec::new()
    }

    fn start(
        &mut self,
        operation_id: IndexOperationId,
        trigger: IndexOperationTrigger,
    ) -> Vec<IndexScheduleAction> {
        let covered_epoch = self.desired_epoch;
        let change_driven = self.latest_change_epoch > self.published_epoch;
        self.active = Some(ActiveOperation {
            id: operation_id,
            trigger,
            covered_epoch,
            change_driven,
            cancellation_requested: None,
        });
        vec![IndexScheduleAction::Start {
            operation_id,
            trigger,
            covered_epoch,
        }]
    }

    const fn allocate_operation_id(&mut self) -> IndexOperationId {
        self.next_operation_id = self.next_operation_id.saturating_add(1);
        IndexOperationId {
            supervisor_id: self.supervisor_id,
            sequence: self.next_operation_id,
        }
    }

    fn request_active_cancellation(
        &mut self,
        reason: IndexCancellationReason,
    ) -> Vec<IndexScheduleAction> {
        let Some(active) = self.active.as_mut() else {
            return Vec::new();
        };
        if active.cancellation_requested.is_some() {
            return Vec::new();
        }
        active.cancellation_requested = Some(reason);
        vec![IndexScheduleAction::Cancel {
            operation_id: active.id,
            reason,
        }]
    }

    fn remember_terminal(&mut self, operation_id: IndexOperationId) {
        self.recent_terminal.push_back(operation_id);
        while self.recent_terminal.len() > 32 {
            self.recent_terminal.pop_front();
        }
    }
}

const MAX_PROGRESS_EVENTS: usize = 24;
const MAX_OPERATION_RECEIPTS: usize = 32;
const MAX_DIRTY_HINTS: usize = 256;

/// Adapter-neutral inputs for one supervised publication. Runtime-owned
/// progress and cancellation channels are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSupervisorRequest {
    pub providers: ProviderIntent,
    pub force: bool,
    pub require_complete_calls: bool,
    pub jobs: Option<usize>,
    pub debug: bool,
    pub profile: bool,
    pub source_revision: Option<String>,
    pub publication_recovery: PublicationRecovery,
    pub capability_floor: CapabilityFloorPolicy,
}

impl Default for IndexSupervisorRequest {
    fn default() -> Self {
        Self {
            providers: ProviderIntent::StructuralOnly,
            force: false,
            require_complete_calls: false,
            jobs: None,
            debug: false,
            profile: false,
            source_revision: None,
            publication_recovery: PublicationRecovery::Strict,
            capability_floor: CapabilityFloorPolicy::Preserve,
        }
    }
}

impl IndexSupervisorRequest {
    fn into_bound_request(
        self,
        progress: tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>,
        cancellation: IndexCancellation,
    ) -> BoundIndexRequest {
        BoundIndexRequest {
            providers: self.providers,
            force: self.force,
            require_complete_calls: self.require_complete_calls,
            jobs: self.jobs,
            debug: self.debug,
            profile: self.profile,
            progress: Some(progress),
            cancellation,
            source_revision: self.source_revision,
            publication_recovery: self.publication_recovery,
            capability_floor: self.capability_floor,
        }
    }
}

/// Public lifecycle of one process-local supervised operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexOperationState {
    Queued,
    Running,
    CancelRequested,
    SupersedeRequested,
    Succeeded,
    Failed,
    Cancelled,
    Superseded,
}

impl IndexOperationState {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::Superseded
        )
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::CancelRequested => "cancel_requested",
            Self::SupersedeRequested => "supersede_requested",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Superseded => "superseded",
        }
    }
}

/// Current lifecycle of semantic enrichment for an operation that already
/// made a source-current structural generation visible.
///
/// This is deliberately distinct from Calls capability status. `Completed`
/// means the enrichment attempt reached its terminal publication boundary;
/// the resulting capability receipt still decides whether semantic authority
/// is complete, partial, unavailable, or not applicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticEnrichmentState {
    Pending,
    Completed,
    Failed,
    Cancelled,
    Superseded,
}

impl SemanticEnrichmentState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Superseded => "superseded",
        }
    }

    #[must_use]
    pub const fn is_pending(self) -> bool {
        matches!(self, Self::Pending)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexOperationFailureKind {
    Preparation,
    Publication,
    BackgroundTask,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexOperationFailureCode {
    ProjectBinding,
    ProjectPath,
    PublicationControl,
    PublicationFailed,
    BackgroundTaskFailed,
}

impl IndexOperationFailureCode {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ProjectBinding => "project_binding",
            Self::ProjectPath => "project_path",
            Self::PublicationControl => "publication_control",
            Self::PublicationFailed => "publication_failed",
            Self::BackgroundTaskFailed => "background_task_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexOperationFailure {
    pub kind: IndexOperationFailureKind,
    pub code: IndexOperationFailureCode,
    pub message: String,
}

/// Bounded publication facts retained in operation status. Full immutable
/// publication data is delivered only to the exact operation handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexPublicationReceipt {
    pub generation_id: String,
    pub repository_id: String,
    pub sequence: u64,
    pub reused_generation: bool,
    pub files_discovered: usize,
    pub files_changed: usize,
    pub symbols_extracted: usize,
    pub nodes_added: usize,
    pub nodes_total: usize,
    pub edges_added: usize,
    pub edges_total: usize,
    pub live_structural_basis_reused: bool,
    pub reachability: Option<crate::graph_stats::ReachabilitySummary>,
    /// Compact capability assessment computed from the exact co-published
    /// graph, receipts, provider payloads, and project inventory.
    pub calls_authority: crate::code_intel_domain::CapabilityCoverage,
    pub callable_liveness_authority: crate::code_intel_domain::CapabilityCoverage,
    /// Bounded manifest receipts needed by CLI/MCP terminal output. Provider
    /// payload bodies are intentionally not retained in operation history.
    pub capability_receipts: Vec<crate::code_intel_domain::CapabilityReceipt>,
    pub maintenance: crate::code_intel_publication::PublicationMaintenance,
    pub duration: Duration,
    /// Complete bounded operation phases retained for WATCH/MCP diagnostics.
    pub phase_timings: Vec<IndexPhaseTiming>,
    /// Bounded durable-publication detail retained for opt-in profiling.
    pub publication_timings: Vec<PublicationStepTiming>,
    /// Typed persistent-provider lifecycle work performed by this operation.
    pub semantic_provider_refreshes: Vec<crate::index_pipeline::SemanticProviderActivityTelemetry>,
}

impl From<&PublishedIndexGeneration> for IndexPublicationReceipt {
    fn from(published: &PublishedIndexGeneration) -> Self {
        Self {
            generation_id: published.publication.manifest.generation_id.0.clone(),
            repository_id: published.publication.manifest.repository_id.0.clone(),
            sequence: published.publication.head.body.sequence,
            reused_generation: published.telemetry.reused_generation,
            files_discovered: published.telemetry.files_discovered,
            files_changed: published.telemetry.files_changed,
            symbols_extracted: published.telemetry.symbols_extracted,
            nodes_added: published.telemetry.nodes_added,
            nodes_total: published.telemetry.nodes_total,
            edges_added: published.telemetry.edges_added,
            edges_total: published.telemetry.edges_total,
            live_structural_basis_reused: published.telemetry.live_structural_basis_reused,
            reachability: published.telemetry.reachability.clone(),
            calls_authority: published.calls_authority.clone(),
            callable_liveness_authority: published.callable_liveness_authority.clone(),
            capability_receipts: published.publication.manifest.receipts.clone(),
            maintenance: published.publication.maintenance.clone(),
            duration: published.telemetry.duration,
            phase_timings: published.telemetry.phase_timings.clone(),
            publication_timings: published.publication_timings.clone(),
            semantic_provider_refreshes: published.telemetry.semantic_provider_refreshes.clone(),
        }
    }
}

/// Exact process-local status for one operation ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexOperationSnapshot {
    pub operation_id: IndexOperationId,
    pub trigger: IndexOperationTrigger,
    pub covered_epoch: u64,
    pub state: IndexOperationState,
    pub request: IndexSupervisorRequest,
    pub created_at_unix_ms: u64,
    pub started_at_unix_ms: Option<u64>,
    pub finished_at_unix_ms: Option<u64>,
    pub elapsed: Duration,
    pub progress: Vec<IndexProgressEvent>,
    pub cancellation_reason: Option<IndexCancellationReason>,
    pub dirty_hint_count: usize,
    pub dirty_hints_overflowed: bool,
    /// Source-current structural publication made visible while semantic
    /// provider enrichment for this WATCH operation is still running.
    pub structural_publication: Option<IndexPublicationReceipt>,
    pub publication: Option<IndexPublicationReceipt>,
    pub failure: Option<IndexOperationFailure>,
}

impl IndexOperationSnapshot {
    /// Return the current enrichment lifecycle only for a real two-stage
    /// operation. The structural receipt proves enrichment was pending when
    /// that stage was published; this value describes what is true when the
    /// snapshot is observed, which may already be terminal.
    #[must_use]
    pub fn semantic_enrichment_state(&self) -> Option<SemanticEnrichmentState> {
        self.structural_publication.as_ref()?;
        Some(match self.state {
            IndexOperationState::Queued
            | IndexOperationState::Running
            | IndexOperationState::CancelRequested
            | IndexOperationState::SupersedeRequested => SemanticEnrichmentState::Pending,
            IndexOperationState::Succeeded => SemanticEnrichmentState::Completed,
            IndexOperationState::Failed => SemanticEnrichmentState::Failed,
            IndexOperationState::Cancelled => SemanticEnrichmentState::Cancelled,
            IndexOperationState::Superseded => SemanticEnrichmentState::Superseded,
        })
    }
}

/// Result delivered once to the exact operation submitter.
#[derive(Debug)]
pub enum IndexOperationOutcome {
    Published(Arc<PublishedIndexGeneration>),
    Failed(IndexOperationFailure),
    Cancelled {
        reason: Option<IndexCancellationReason>,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IndexSupervisorError {
    #[error("one manual indexing operation is already active or queued")]
    ManualBusy,
    #[error("index supervisor is shutting down")]
    ShuttingDown,
    #[error("index supervisor requires a Tokio runtime")]
    RuntimeUnavailable,
    #[error("this index supervisor has no retained operations")]
    NoOperations,
    #[error("index operation {operation_id} was not found in this supervisor")]
    OperationNotFound { operation_id: IndexOperationId },
    #[error("index operation {operation_id} result channel closed")]
    ResultChannelClosed { operation_id: IndexOperationId },
}

pub struct IndexOperationHandle {
    operation_id: IndexOperationId,
    outcome: oneshot::Receiver<IndexOperationOutcome>,
}

impl IndexOperationHandle {
    #[must_use]
    pub const fn operation_id(&self) -> IndexOperationId {
        self.operation_id
    }

    pub async fn wait(self) -> Result<IndexOperationOutcome, IndexSupervisorError> {
        self.outcome
            .await
            .map_err(|_| IndexSupervisorError::ResultChannelClosed {
                operation_id: self.operation_id,
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchObservation {
    pub desired_epoch: u64,
    pub active_operation: Option<IndexOperationId>,
    pub active_trigger: Option<IndexOperationTrigger>,
    pub dirty_hint_count: usize,
    pub dirty_hints_overflowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexCancellationReceipt {
    pub accepted: bool,
    pub operation: IndexOperationSnapshot,
}

#[async_trait]
trait IndexRunner: Send + Sync + 'static {
    async fn run(
        &self,
        binding: ProjectBinding,
        request: IndexSupervisorRequest,
        reuse_hints: Arc<[PathBuf]>,
        cancellation: IndexCancellation,
        progress: tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>,
    ) -> RunnerOutcome;

    async fn shutdown(&self) {}
}

#[derive(Default)]
struct BoundIndexRunner {
    live_basis: Mutex<Option<LiveGenerationBasis>>,
    semantic_providers: Mutex<SemanticProviderRegistry>,
    toolchain_resolver: Option<Arc<dyn ToolchainResolver>>,
}

impl BoundIndexRunner {
    fn with_toolchain_resolver(toolchain_resolver: Arc<dyn ToolchainResolver>) -> Self {
        Self {
            live_basis: Mutex::new(None),
            semantic_providers: Mutex::new(SemanticProviderRegistry::default()),
            toolchain_resolver: Some(toolchain_resolver),
        }
    }

    fn with_semantic_providers(
        providers: Vec<SemanticProviderConfig>,
        toolchain_resolver: Option<Arc<dyn ToolchainResolver>>,
    ) -> Result<Self, SemanticProviderRegistryError> {
        Ok(Self {
            live_basis: Mutex::new(None),
            semantic_providers: Mutex::new(SemanticProviderRegistry::from_configs(providers)?),
            toolchain_resolver,
        })
    }
}

#[async_trait]
impl IndexRunner for BoundIndexRunner {
    async fn run(
        &self,
        binding: ProjectBinding,
        request: IndexSupervisorRequest,
        reuse_hints: Arc<[PathBuf]>,
        cancellation: IndexCancellation,
        progress: tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>,
    ) -> RunnerOutcome {
        let session_jobs = request.jobs;
        let plan = match BoundIndexPlan::prepare_with_toolchain_resolver(
            &binding,
            request.into_bound_request(progress, cancellation),
            self.toolchain_resolver.clone(),
            reuse_hints,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                let code = match &error {
                    BoundIndexPlanError::Binding(_) => IndexOperationFailureCode::ProjectBinding,
                    BoundIndexPlanError::Path(_) => IndexOperationFailureCode::ProjectPath,
                    BoundIndexPlanError::Publication(_) => {
                        IndexOperationFailureCode::PublicationControl
                    }
                };
                return RunnerOutcome::Failed(IndexOperationFailure {
                    kind: IndexOperationFailureKind::Preparation,
                    code,
                    message: error.to_string(),
                });
            }
        };
        let mut semantic_providers = std::mem::take(&mut *self.semantic_providers.lock());
        semantic_providers.set_session_jobs(session_jobs);
        let live_authority = self
            .live_basis
            .lock()
            .as_ref()
            .and_then(LiveGenerationBasis::authority_snapshot);
        match plan
            .probe_reuse(live_authority, &mut semantic_providers)
            .await
        {
            Ok(BoundIndexAdmission::Reused(published, hydrated_basis)) => {
                let mut live_basis = self.live_basis.lock();
                if let Some(hydrated_basis) = hydrated_basis {
                    *live_basis = Some(*hydrated_basis);
                } else if live_basis
                    .as_ref()
                    .is_some_and(|basis| !basis.matches_published(&published.publication))
                {
                    live_basis.take();
                }
                drop(live_basis);
                *self.semantic_providers.lock() = semantic_providers;
                RunnerOutcome::Published(Arc::new(published))
            }
            Ok(BoundIndexAdmission::Fresh(prepared)) => {
                // Only a fresh candidate receives unique ownership of the
                // process-local basis. Once transferred, a failed operation
                // drops the consumed cache and its successor safely falls back
                // to the immutable generation validated from disk.
                let live_basis = self.live_basis.lock().take();
                match prepared
                    .publish_with_live_basis(live_basis, &mut semantic_providers)
                    .await
                {
                    Ok((published, next_live_basis)) => {
                        for activity in &published.telemetry.semantic_provider_refreshes {
                            semantic_providers.mark_publication_committed(activity.language_id());
                        }
                        *self.live_basis.lock() = next_live_basis;
                        *self.semantic_providers.lock() = semantic_providers;
                        RunnerOutcome::Published(Arc::new(published))
                    }
                    Err(IndexGenerationPublicationError::Pipeline(
                        IndexPipelineError::Cancelled,
                    )) => {
                        // Provider coordinators own their transactional state:
                        // a cancelled refresh either restores its previously
                        // admitted population or resets itself before returning.
                        // Cancellation after a coherent refresh may retain that
                        // un-published candidate as acceleration for the next
                        // epoch, but never grants publication authority. A
                        // blanket supervisor reset here destroyed healthy
                        // sibling sessions after a root-local candidate was
                        // superseded.
                        *self.semantic_providers.lock() = semantic_providers;
                        RunnerOutcome::Cancelled
                    }
                    Err(error) => {
                        semantic_providers.reset_all().await;
                        *self.semantic_providers.lock() = semantic_providers;
                        RunnerOutcome::Failed(IndexOperationFailure {
                            kind: IndexOperationFailureKind::Publication,
                            code: IndexOperationFailureCode::PublicationFailed,
                            message: error.to_string(),
                        })
                    }
                }
            }
            Err(IndexGenerationPublicationError::Pipeline(IndexPipelineError::Cancelled)) => {
                // Exact-generation probes either leave a matching live
                // population untouched, retain a coherent basis for the
                // already-published generation, or reset themselves before
                // refusing reuse. A superseding epoch therefore must not
                // erase provider state merely because cancellation arrived
                // while this read/admission probe was in flight.
                *self.semantic_providers.lock() = semantic_providers;
                RunnerOutcome::Cancelled
            }
            Err(error) => {
                semantic_providers.reset_all().await;
                *self.semantic_providers.lock() = semantic_providers;
                RunnerOutcome::Failed(IndexOperationFailure {
                    kind: IndexOperationFailureKind::Publication,
                    code: IndexOperationFailureCode::PublicationFailed,
                    message: error.to_string(),
                })
            }
        }
    }

    async fn shutdown(&self) {
        let mut semantic_providers = std::mem::take(&mut *self.semantic_providers.lock());
        semantic_providers.reset_all().await;
        self.live_basis.lock().take();
    }
}

enum RunnerOutcome {
    Published(Arc<PublishedIndexGeneration>),
    Failed(IndexOperationFailure),
    Cancelled,
}

struct OperationRecord {
    operation_id: IndexOperationId,
    trigger: IndexOperationTrigger,
    covered_epoch: u64,
    state: IndexOperationState,
    request: IndexSupervisorRequest,
    created_at: Instant,
    finished_elapsed: Option<Duration>,
    created_at_unix_ms: u64,
    started_at_unix_ms: Option<u64>,
    finished_at_unix_ms: Option<u64>,
    progress: VecDeque<IndexProgressEvent>,
    cancellation_reason: Option<IndexCancellationReason>,
    dirty_hint_count: usize,
    dirty_hints_overflowed: bool,
    structural_publication: Option<IndexPublicationReceipt>,
    publication: Option<IndexPublicationReceipt>,
    failure: Option<IndexOperationFailure>,
}

impl OperationRecord {
    fn snapshot(&self) -> IndexOperationSnapshot {
        IndexOperationSnapshot {
            operation_id: self.operation_id,
            trigger: self.trigger,
            covered_epoch: self.covered_epoch,
            state: self.state,
            request: self.request.clone(),
            created_at_unix_ms: self.created_at_unix_ms,
            started_at_unix_ms: self.started_at_unix_ms,
            finished_at_unix_ms: self.finished_at_unix_ms,
            elapsed: self
                .finished_elapsed
                .unwrap_or_else(|| self.created_at.elapsed()),
            progress: self.progress.iter().cloned().collect(),
            cancellation_reason: self.cancellation_reason,
            dirty_hint_count: self.dirty_hint_count,
            dirty_hints_overflowed: self.dirty_hints_overflowed,
            structural_publication: self.structural_publication.clone(),
            publication: self.publication.clone(),
            failure: self.failure.clone(),
        }
    }
}

struct PendingOperation {
    request: IndexSupervisorRequest,
    completion: oneshot::Sender<IndexOperationOutcome>,
    progress_observer: Option<tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>>,
}

struct ActiveRuntime {
    operation_id: IndexOperationId,
    trigger: IndexOperationTrigger,
    dirty_hints_overflowed: bool,
    reuse_hints: Arc<[PathBuf]>,
    request: IndexSupervisorRequest,
    cancellation: IndexCancellation,
    cancellation_reason: Option<IndexCancellationReason>,
    completion: Option<oneshot::Sender<IndexOperationOutcome>>,
    progress_observer: Option<tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>>,
    started: bool,
}

#[derive(Default)]
struct SupervisorRuntimeState {
    schedule: IndexSchedule,
    watch_request: Option<IndexSupervisorRequest>,
    pending: HashMap<IndexOperationId, PendingOperation>,
    active: Option<ActiveRuntime>,
    records: VecDeque<OperationRecord>,
    dirty_hints: BTreeSet<PathBuf>,
    dirty_hints_overflowed: bool,
    shutting_down: bool,
}

struct SupervisorInner {
    binding: ProjectBinding,
    runner: Arc<dyn IndexRunner>,
    state: Mutex<SupervisorRuntimeState>,
    wake: Arc<Notify>,
    worker_done: Arc<Notify>,
    publication_updates: watch::Sender<Option<Arc<PublishedIndexGeneration>>>,
    worker_running: AtomicBool,
}

impl Drop for SupervisorInner {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        state.shutting_down = true;
        if let Some(active) = &state.active {
            active.cancellation.cancel();
        }
        state.pending.clear();
        self.wake.notify_one();
    }
}

/// One process-local scheduler shared by manual, MCP, and WATCH adapters.
/// Cross-process exclusion remains the immutable publisher lock.
#[derive(Clone)]
pub struct IndexSupervisor {
    inner: Arc<SupervisorInner>,
}

impl IndexSupervisor {
    #[must_use]
    pub fn new(binding: ProjectBinding) -> Self {
        Self::with_runner(binding, Arc::new(BoundIndexRunner::default()))
    }

    /// Construct a supervisor with product-owned one-shot semantic toolchain
    /// resolution but no persistent Rust provider session.
    #[must_use]
    pub fn with_toolchain_resolver(
        binding: ProjectBinding,
        toolchain_resolver: Arc<dyn ToolchainResolver>,
    ) -> Self {
        Self::with_runner(
            binding,
            Arc::new(BoundIndexRunner::with_toolchain_resolver(
                toolchain_resolver,
            )),
        )
    }

    /// Construct a supervisor whose serialized runner owns the configured
    /// persistent language providers for their complete process lifecycles.
    ///
    /// Duplicate language keys are refused before a worker can start.
    pub fn with_semantic_providers(
        binding: ProjectBinding,
        providers: Vec<SemanticProviderConfig>,
        toolchain_resolver: Option<Arc<dyn ToolchainResolver>>,
    ) -> Result<Self, SemanticProviderRegistryError> {
        Ok(Self::with_runner(
            binding,
            Arc::new(BoundIndexRunner::with_semantic_providers(
                providers,
                toolchain_resolver,
            )?),
        ))
    }

    fn with_runner(binding: ProjectBinding, runner: Arc<dyn IndexRunner>) -> Self {
        let (publication_updates, _) = watch::channel(None);
        Self {
            inner: Arc::new(SupervisorInner {
                binding,
                runner,
                state: Mutex::new(SupervisorRuntimeState::default()),
                wake: Arc::new(Notify::new()),
                worker_done: Arc::new(Notify::new()),
                publication_updates,
                worker_running: AtomicBool::new(false),
            }),
        }
    }

    /// Start or queue an exact manual request. A manual request preempts an
    /// active WATCH candidate but is refused while another manual request is
    /// active or queued.
    pub fn start_manual(
        &self,
        request: IndexSupervisorRequest,
    ) -> Result<IndexOperationHandle, IndexSupervisorError> {
        self.start_manual_inner(request, None)
    }

    pub fn start_manual_with_progress(
        &self,
        request: IndexSupervisorRequest,
        progress: tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>,
    ) -> Result<IndexOperationHandle, IndexSupervisorError> {
        self.start_manual_inner(request, Some(progress))
    }

    fn start_manual_inner(
        &self,
        request: IndexSupervisorRequest,
        progress_observer: Option<tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>>,
    ) -> Result<IndexOperationHandle, IndexSupervisorError> {
        self.ensure_worker()?;
        let (completion, outcome) = oneshot::channel();
        let mut state = self.inner.state.lock();
        if state.shutting_down {
            return Err(IndexSupervisorError::ShuttingDown);
        }
        let (operation_id, actions) = state
            .schedule
            .request_manual()
            .map_err(|_| IndexSupervisorError::ManualBusy)?;
        let snapshot = state.schedule.snapshot();
        let record_request = request.clone();
        state.pending.insert(
            operation_id,
            PendingOperation {
                request,
                completion,
                progress_observer,
            },
        );
        state.records.push_back(OperationRecord {
            operation_id,
            trigger: IndexOperationTrigger::Manual,
            covered_epoch: snapshot.desired_epoch,
            state: IndexOperationState::Queued,
            request: record_request,
            created_at: Instant::now(),
            finished_elapsed: None,
            created_at_unix_ms: unix_ms(),
            started_at_unix_ms: None,
            finished_at_unix_ms: None,
            progress: VecDeque::new(),
            cancellation_reason: None,
            dirty_hint_count: 0,
            dirty_hints_overflowed: false,
            structural_publication: None,
            publication: None,
            failure: None,
        });
        apply_schedule_actions(&mut state, actions);
        trim_records(&mut state.records);
        drop(state);
        self.inner.wake.notify_one();
        Ok(IndexOperationHandle {
            operation_id,
            outcome,
        })
    }

    /// Enable WATCH with one explicit publication policy. The initial scan is
    /// a normal complete reconciliation, not authority derived from watcher
    /// paths.
    pub fn enable_watch(
        &self,
        request: IndexSupervisorRequest,
        initial_reconciliation: bool,
    ) -> Result<Vec<IndexScheduleAction>, IndexSupervisorError> {
        self.ensure_worker()?;
        let mut state = self.inner.state.lock();
        if state.shutting_down {
            return Err(IndexSupervisorError::ShuttingDown);
        }
        state.watch_request = Some(request);
        let actions = state.schedule.enable_watch(initial_reconciliation);
        apply_schedule_actions(&mut state, actions.clone());
        drop(state);
        self.inner.wake.notify_one();
        Ok(actions)
    }

    pub fn disable_watch(&self) -> Vec<IndexScheduleAction> {
        let mut state = self.inner.state.lock();
        state.watch_request = None;
        let actions = state.schedule.disable_watch();
        apply_schedule_actions(&mut state, actions.clone());
        drop(state);
        self.inner.wake.notify_one();
        actions
    }

    /// Record a coalesced set of changed paths for telemetry and advance the
    /// correctness epoch exactly once. Paths are bounded and never trusted as
    /// the complete change population.
    pub fn observe_changes<I>(&self, paths: I) -> Result<WatchObservation, IndexSupervisorError>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        self.ensure_worker()?;
        let mut state = self.inner.state.lock();
        if state.shutting_down {
            return Err(IndexSupervisorError::ShuttingDown);
        }
        for path in paths {
            if state.dirty_hints.len() < MAX_DIRTY_HINTS {
                state.dirty_hints.insert(path);
            } else if !state.dirty_hints.contains(&path) {
                state.dirty_hints_overflowed = true;
            }
        }
        let actions = state.schedule.request_reconciliation(true);
        apply_schedule_actions(&mut state, actions);
        let observation = watch_observation(&state);
        drop(state);
        self.inner.wake.notify_one();
        Ok(observation)
    }

    /// Queue a periodic safety reconciliation without cancelling active work.
    pub fn request_periodic_reconciliation(
        &self,
    ) -> Result<WatchObservation, IndexSupervisorError> {
        self.ensure_worker()?;
        let mut state = self.inner.state.lock();
        if state.shutting_down {
            return Err(IndexSupervisorError::ShuttingDown);
        }
        let actions = state.schedule.request_reconciliation(false);
        apply_schedule_actions(&mut state, actions);
        let observation = watch_observation(&state);
        drop(state);
        self.inner.wake.notify_one();
        Ok(observation)
    }

    pub fn snapshot(
        &self,
        operation_id: IndexOperationId,
    ) -> Result<IndexOperationSnapshot, IndexSupervisorError> {
        let state = self.inner.state.lock();
        state
            .records
            .iter()
            .find(|record| record.operation_id == operation_id)
            .map(OperationRecord::snapshot)
            .ok_or(IndexSupervisorError::OperationNotFound { operation_id })
    }

    pub fn latest_snapshot(&self) -> Result<IndexOperationSnapshot, IndexSupervisorError> {
        self.inner
            .state
            .lock()
            .records
            .back()
            .map(OperationRecord::snapshot)
            .ok_or(IndexSupervisorError::NoOperations)
    }

    /// Return the bounded retained operation population in creation order.
    ///
    /// Long-lived adapters use this instead of sampling only the active/latest
    /// record: one operation may become terminal and schedule its successor
    /// between two adapter polls. Returning the complete bounded population
    /// prevents that valid terminal receipt from disappearing from the stream.
    #[must_use]
    pub fn retained_snapshots(&self) -> Vec<IndexOperationSnapshot> {
        self.inner
            .state
            .lock()
            .records
            .iter()
            .map(OperationRecord::snapshot)
            .collect()
    }

    /// Wait until an explicitly disabled WATCH no longer owns active work.
    /// Manual work may remain active; it has independent operator authority.
    pub async fn wait_for_watch_idle(&self) {
        while self.schedule_snapshot().active_trigger == Some(IndexOperationTrigger::Watch) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[must_use]
    pub fn schedule_snapshot(&self) -> IndexScheduleSnapshot {
        self.inner.state.lock().schedule.snapshot()
    }

    /// Subscribe to exact successful final publications from this supervisor.
    ///
    /// The channel retains the latest immutable result so a WATCH consumer
    /// cannot miss the transition between subscription and its first await.
    /// Structural staging publications are intentionally excluded: their
    /// provider input authority is not final yet.
    pub(crate) fn subscribe_publications(
        &self,
    ) -> watch::Receiver<Option<Arc<PublishedIndexGeneration>>> {
        self.inner.publication_updates.subscribe()
    }

    /// Read the bounded publication-control token for WATCH drift detection.
    ///
    /// This deliberately does not open or hash the immutable generation
    /// database. A changed token is only a hint that schedules the ordinary
    /// authoritative reconciliation path; it never grants query or writer
    /// authority by itself.
    pub fn publication_control_token(&self) -> Result<PublicationControlToken, PublicationError> {
        publication_control_token(self.inner.binding.graph_dir(), self.inner.binding.root())
    }

    /// Capture the cheap metadata witness used to sparsify WATCH control reads.
    ///
    /// The witness is only a change hint. It never replaces the validated
    /// control token or the authoritative reconciliation path.
    #[must_use]
    pub fn publication_control_witness(&self) -> PublicationControlWitness {
        publication_control_witness(self.inner.binding.graph_dir())
    }

    pub fn cancel(
        &self,
        operation_id: IndexOperationId,
    ) -> Result<IndexCancellationReceipt, IndexSupervisorError> {
        let mut state = self.inner.state.lock();
        if state
            .records
            .iter()
            .find(|record| record.operation_id == operation_id)
            .is_some_and(|record| record.state.is_terminal())
        {
            return state
                .records
                .iter()
                .find(|record| record.operation_id == operation_id)
                .map(|record| IndexCancellationReceipt {
                    accepted: false,
                    operation: record.snapshot(),
                })
                .ok_or(IndexSupervisorError::OperationNotFound { operation_id });
        }
        let actions = state
            .schedule
            .cancel(operation_id)
            .map_err(|_| IndexSupervisorError::OperationNotFound { operation_id })?;
        apply_schedule_actions(&mut state, actions);
        let snapshot = state
            .records
            .iter()
            .find(|record| record.operation_id == operation_id)
            .map(OperationRecord::snapshot)
            .ok_or(IndexSupervisorError::OperationNotFound { operation_id })?;
        drop(state);
        self.inner.wake.notify_one();
        Ok(IndexCancellationReceipt {
            accepted: true,
            operation: snapshot,
        })
    }

    pub fn shutdown(&self) {
        let mut state = self.inner.state.lock();
        if state.shutting_down {
            return;
        }
        state.shutting_down = true;
        state.watch_request = None;
        let actions = state.schedule.shutdown();
        apply_schedule_actions(&mut state, actions);
        drop(state);
        // There is exactly one worker. `notify_one` stores a permit when the
        // worker is between its state check and `notified().await`; using
        // `notify_waiters` here can lose shutdown and strand the process.
        self.inner.wake.notify_one();
    }

    pub async fn shutdown_and_wait(&self) {
        self.shutdown();
        loop {
            let done = self.inner.worker_done.notified();
            tokio::pin!(done);
            // `notify_waiters` deliberately does not retain a permit. Register
            // this waiter before reading the completion predicate so worker
            // exit cannot land in the check-to-await gap.
            done.as_mut().enable();
            if !self.inner.worker_running.load(Ordering::Acquire) {
                return;
            }
            done.await;
        }
    }

    fn ensure_worker(&self) -> Result<(), IndexSupervisorError> {
        if self.inner.worker_running.load(Ordering::Acquire) {
            return Ok(());
        }
        let handle = tokio::runtime::Handle::try_current()
            .map_err(|_| IndexSupervisorError::RuntimeUnavailable)?;
        if self
            .inner
            .worker_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let weak = Arc::downgrade(&self.inner);
            handle.spawn(run_supervisor(weak));
        }
        Ok(())
    }
}

fn watch_observation(state: &SupervisorRuntimeState) -> WatchObservation {
    let schedule = state.schedule.snapshot();
    WatchObservation {
        desired_epoch: schedule.desired_epoch,
        active_operation: schedule.active_operation,
        active_trigger: schedule.active_trigger,
        dirty_hint_count: state.dirty_hints.len(),
        dirty_hints_overflowed: state.dirty_hints_overflowed,
    }
}

fn apply_schedule_actions(state: &mut SupervisorRuntimeState, actions: Vec<IndexScheduleAction>) {
    for action in actions {
        match action {
            IndexScheduleAction::Start {
                operation_id,
                trigger,
                covered_epoch,
            } => {
                debug_assert!(state.active.is_none());
                let (request, completion, progress_observer) = match trigger {
                    IndexOperationTrigger::Manual => {
                        let pending = state
                            .pending
                            .remove(&operation_id)
                            .expect("manual schedule payload must exist");
                        (
                            pending.request,
                            Some(pending.completion),
                            pending.progress_observer,
                        )
                    }
                    IndexOperationTrigger::Watch => (
                        state
                            .watch_request
                            .clone()
                            .expect("WATCH schedule policy must exist"),
                        None,
                        None,
                    ),
                };
                let reuse_hints = Arc::<[PathBuf]>::from(
                    std::mem::take(&mut state.dirty_hints)
                        .into_iter()
                        .collect::<Vec<_>>(),
                );
                let dirty_hint_count = reuse_hints.len();
                let dirty_hints_overflowed = state.dirty_hints_overflowed;
                state.dirty_hints_overflowed = false;
                if trigger == IndexOperationTrigger::Watch {
                    state.records.push_back(OperationRecord {
                        operation_id,
                        trigger,
                        covered_epoch,
                        state: IndexOperationState::Running,
                        request: request.clone(),
                        created_at: Instant::now(),
                        finished_elapsed: None,
                        created_at_unix_ms: unix_ms(),
                        started_at_unix_ms: Some(unix_ms()),
                        finished_at_unix_ms: None,
                        progress: VecDeque::new(),
                        cancellation_reason: None,
                        dirty_hint_count,
                        dirty_hints_overflowed,
                        structural_publication: None,
                        publication: None,
                        failure: None,
                    });
                } else if let Some(record) = record_mut(state, operation_id) {
                    record.covered_epoch = covered_epoch;
                    record.dirty_hint_count = dirty_hint_count;
                    record.dirty_hints_overflowed = dirty_hints_overflowed;
                    record.state = IndexOperationState::Running;
                    record.started_at_unix_ms.get_or_insert_with(unix_ms);
                }
                state.active = Some(ActiveRuntime {
                    operation_id,
                    trigger,
                    dirty_hints_overflowed,
                    reuse_hints,
                    request,
                    cancellation: IndexCancellation::new(),
                    cancellation_reason: None,
                    completion,
                    progress_observer,
                    started: false,
                });
                trim_records(&mut state.records);
            }
            IndexScheduleAction::Cancel {
                operation_id,
                reason,
            } => {
                if let Some(active) = state
                    .active
                    .as_mut()
                    .filter(|active| active.operation_id == operation_id)
                {
                    active.cancellation_reason = Some(reason);
                    active.cancellation.cancel();
                }
                if let Some(record) = record_mut(state, operation_id) {
                    record.cancellation_reason = Some(reason);
                    record.state = if reason == IndexCancellationReason::Superseded {
                        IndexOperationState::SupersedeRequested
                    } else {
                        IndexOperationState::CancelRequested
                    };
                }
            }
            IndexScheduleAction::CancelQueued {
                operation_id,
                reason,
            } => {
                if let Some(pending) = state.pending.remove(&operation_id) {
                    let _ = pending.completion.send(IndexOperationOutcome::Cancelled {
                        reason: Some(reason),
                    });
                }
                if let Some(record) = record_mut(state, operation_id) {
                    record.cancellation_reason = Some(reason);
                    record.state = IndexOperationState::Cancelled;
                    record.finished_at_unix_ms = Some(unix_ms());
                    record.finished_elapsed = Some(record.created_at.elapsed());
                }
            }
        }
    }
}

async fn run_supervisor(inner: Weak<SupervisorInner>) {
    loop {
        let Some(strong) = inner.upgrade() else {
            return;
        };
        let wake = Arc::clone(&strong.wake);
        let run = {
            let mut state = strong.state.lock();
            let run = if state.shutting_down && state.active.is_none() {
                None
            } else {
                let spec = state.active.as_mut().and_then(|active| {
                    if active.started {
                        return None;
                    }
                    active.started = true;
                    Some(RunSpec {
                        operation_id: active.operation_id,
                        trigger: active.trigger,
                        reuse_hints: Arc::clone(&active.reuse_hints),
                        binding: strong.binding.clone(),
                        runner: Arc::clone(&strong.runner),
                        request: active.request.clone(),
                        cancellation: active.cancellation.clone(),
                        progress_observer: active.progress_observer.clone(),
                    })
                });
                if let Some(spec) = &spec
                    && let Some(record) = record_mut(&mut state, spec.operation_id)
                    && record.state == IndexOperationState::Queued
                {
                    record.state = IndexOperationState::Running;
                    record.started_at_unix_ms = Some(unix_ms());
                }
                spec
            };
            drop(state);
            run
        };
        let shutting_down_without_run = {
            let state = strong.state.lock();
            state.shutting_down && state.active.is_none()
        };
        drop(strong);

        if shutting_down_without_run {
            break;
        }
        if let Some(run) = run {
            execute_run(&inner, run).await;
            continue;
        }
        wake.notified().await;
    }

    if let Some(strong) = inner.upgrade() {
        let runner = Arc::clone(&strong.runner);
        runner.shutdown().await;
        strong.worker_running.store(false, Ordering::Release);
        strong.worker_done.notify_waiters();
    }
}

struct RunSpec {
    operation_id: IndexOperationId,
    trigger: IndexOperationTrigger,
    reuse_hints: Arc<[PathBuf]>,
    binding: ProjectBinding,
    runner: Arc<dyn IndexRunner>,
    request: IndexSupervisorRequest,
    cancellation: IndexCancellation,
    progress_observer: Option<tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>>,
}

fn staged_watch_structural_request(run: &RunSpec) -> Option<IndexSupervisorRequest> {
    let should_stage = run.trigger == IndexOperationTrigger::Watch
        && !run.reuse_hints.is_empty()
        && run.request.providers == ProviderIntent::Refresh
        && !run.request.require_complete_calls
        && run.request.capability_floor == CapabilityFloorPolicy::AllowDowngrade;
    should_stage.then(|| {
        let mut request = run.request.clone();
        request.providers = ProviderIntent::StructuralOnly;
        request.require_complete_calls = false;
        request
    })
}

async fn execute_run(inner: &Weak<SupervisorInner>, run: RunSpec) {
    let (progress, mut progress_events) =
        tokio::sync::mpsc::unbounded_channel::<IndexProgressEvent>();
    let progress_inner = inner.clone();
    let operation_id = run.operation_id;
    let progress_observer = run.progress_observer.clone();
    let progress_task = tokio::spawn(async move {
        while let Some(event) = progress_events.recv().await {
            if let Some(observer) = &progress_observer {
                let _ = observer.send(event.clone());
            }
            let Some(inner) = progress_inner.upgrade() else {
                return;
            };
            let mut state = inner.state.lock();
            if let Some(record) = record_mut(&mut state, operation_id) {
                if record.progress.len() == MAX_PROGRESS_EVENTS {
                    record.progress.pop_front();
                }
                record.progress.push_back(event);
            }
        }
    });

    let task_inner = inner.clone();
    let task = tokio::spawn(async move {
        if let Some(structural_request) = staged_watch_structural_request(&run) {
            let structural = run
                .runner
                .run(
                    run.binding.clone(),
                    structural_request,
                    Arc::clone(&run.reuse_hints),
                    run.cancellation.clone(),
                    progress.clone(),
                )
                .await;
            match structural {
                RunnerOutcome::Published(published) => {
                    retain_structural_publication(
                        &task_inner,
                        run.operation_id,
                        published.as_ref(),
                    );
                    if run.cancellation.is_cancelled() {
                        RunnerOutcome::Cancelled
                    } else {
                        run.runner
                            .run(
                                run.binding,
                                run.request,
                                run.reuse_hints,
                                run.cancellation,
                                progress,
                            )
                            .await
                    }
                }
                other => other,
            }
        } else {
            run.runner
                .run(
                    run.binding,
                    run.request,
                    run.reuse_hints,
                    run.cancellation,
                    progress,
                )
                .await
        }
    });
    let outcome = match task.await {
        Ok(outcome) => outcome,
        Err(error) => RunnerOutcome::Failed(IndexOperationFailure {
            kind: IndexOperationFailureKind::BackgroundTask,
            code: IndexOperationFailureCode::BackgroundTaskFailed,
            message: format!("supervised indexing task failed: {error}"),
        }),
    };
    let _ = progress_task.await;

    let Some(inner) = inner.upgrade() else {
        return;
    };
    finish_runtime_operation(&inner, operation_id, outcome);
}

fn retain_structural_publication(
    inner: &Weak<SupervisorInner>,
    operation_id: IndexOperationId,
    published: &PublishedIndexGeneration,
) {
    let Some(inner) = inner.upgrade() else {
        return;
    };
    let mut state = inner.state.lock();
    state
        .schedule
        .mark_active_publication(operation_id)
        .expect("only the active operation may retain a structural publication");
    if let Some(record) = record_mut(&mut state, operation_id) {
        record.structural_publication = Some(IndexPublicationReceipt::from(published));
    }
    drop(state);
}

fn finish_runtime_operation(
    inner: &SupervisorInner,
    operation_id: IndexOperationId,
    outcome: RunnerOutcome,
) {
    let mut state = inner.state.lock();
    let Some(active) = state.active.take() else {
        return;
    };
    if active.operation_id != operation_id {
        state.active = Some(active);
        return;
    }

    let (attempt_result, public_outcome, operation_state, publication, publication_update, failure) =
        match outcome {
            RunnerOutcome::Published(published) => (
                IndexAttemptResult::Published,
                IndexOperationOutcome::Published(Arc::clone(&published)),
                IndexOperationState::Succeeded,
                Some(IndexPublicationReceipt::from(published.as_ref())),
                Some(published),
                None,
            ),
            RunnerOutcome::Failed(failure) => (
                IndexAttemptResult::Failed,
                IndexOperationOutcome::Failed(failure.clone()),
                IndexOperationState::Failed,
                None,
                None,
                Some(failure),
            ),
            RunnerOutcome::Cancelled => {
                let operation_state =
                    if active.cancellation_reason == Some(IndexCancellationReason::Superseded) {
                        IndexOperationState::Superseded
                    } else {
                        IndexOperationState::Cancelled
                    };
                (
                    IndexAttemptResult::Cancelled,
                    IndexOperationOutcome::Cancelled {
                        reason: active.cancellation_reason,
                    },
                    operation_state,
                    None,
                    None,
                    None,
                )
            }
        };
    if attempt_result != IndexAttemptResult::Published {
        retain_unpublished_change_hints(&mut state, &active);
    }
    if let Some(record) = record_mut(&mut state, operation_id) {
        record.state = operation_state;
        record.finished_at_unix_ms = Some(unix_ms());
        record.finished_elapsed = Some(record.created_at.elapsed());
        record.publication = publication;
        record.failure = failure;
        record.cancellation_reason = active.cancellation_reason;
    }
    let actions = state
        .schedule
        .finish(operation_id, attempt_result)
        .expect("runtime and scheduling operation identities must agree");
    if let Some(completion) = active.completion {
        let _ = completion.send(public_outcome);
    }
    apply_schedule_actions(&mut state, actions);
    trim_records(&mut state.records);
    drop(state);
    if let Some(published) = publication_update {
        inner.publication_updates.send_replace(Some(published));
    }
    inner.wake.notify_one();
}

/// Return bounded source-change evidence to the supervisor when its private
/// consumer did not publish. An operation temporarily borrows these paths for
/// acceleration; only a successful terminal may consume them. Merging before
/// schedule actions also gives a superseding WATCH or manual-priority run the
/// complete path population accumulated since the last successful terminal.
fn retain_unpublished_change_hints(state: &mut SupervisorRuntimeState, active: &ActiveRuntime) {
    state.dirty_hints_overflowed |= active.dirty_hints_overflowed;
    for path in active.reuse_hints.iter() {
        if state.dirty_hints.contains(path) {
            continue;
        }
        if state.dirty_hints.len() == MAX_DIRTY_HINTS {
            state.dirty_hints_overflowed = true;
            continue;
        }
        state.dirty_hints.insert(path.clone());
    }
}

fn record_mut(
    state: &mut SupervisorRuntimeState,
    operation_id: IndexOperationId,
) -> Option<&mut OperationRecord> {
    state
        .records
        .iter_mut()
        .find(|record| record.operation_id == operation_id)
}

fn trim_records(records: &mut VecDeque<OperationRecord>) {
    while records.len() > MAX_OPERATION_RECEIPTS {
        let removable = records.iter().position(|record| record.state.is_terminal());
        let Some(index) = removable else {
            break;
        };
        records.remove(index);
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index_pipeline::IndexProgressPhase;
    use tempfile::TempDir;
    use tokio::sync::{mpsc, oneshot};
    use tokio::time::{Duration, timeout};

    fn one_start(
        actions: &[IndexScheduleAction],
    ) -> (IndexOperationId, IndexOperationTrigger, u64) {
        assert_eq!(actions.len(), 1, "expected exactly one scheduling action");
        match actions[0] {
            IndexScheduleAction::Start {
                operation_id,
                trigger,
                covered_epoch,
            } => (operation_id, trigger, covered_epoch),
            action => panic!("expected start action, got {action:?}"),
        }
    }

    #[test]
    fn change_during_watch_cancels_stale_candidate_and_reconciles_new_epoch() {
        let mut schedule = IndexSchedule::default();
        let initial = schedule.enable_watch(true);
        let (first, trigger, first_epoch) = one_start(&initial);
        assert_eq!(trigger, IndexOperationTrigger::Watch);
        assert_eq!(first_epoch, 1);

        assert_eq!(
            schedule.observe_change(),
            vec![IndexScheduleAction::Cancel {
                operation_id: first,
                reason: IndexCancellationReason::Superseded,
            }],
            "a change during WATCH must supersede the stale private candidate"
        );
        let successor = schedule
            .finish(first, IndexAttemptResult::Cancelled)
            .expect("finish superseded candidate");
        let (second, second_trigger, second_epoch) = one_start(&successor);
        assert_ne!(second, first);
        assert_eq!(second_trigger, IndexOperationTrigger::Watch);
        assert_eq!(second_epoch, 2);

        assert!(
            schedule
                .finish(second, IndexAttemptResult::Published)
                .expect("publish current candidate")
                .is_empty()
        );
        let snapshot = schedule.snapshot();
        assert_eq!(snapshot.desired_epoch, 2);
        assert_eq!(snapshot.published_epoch, 2);
        assert_eq!(snapshot.active_operation, None);
    }

    #[test]
    fn manual_priority_does_not_lose_change_observed_during_manual_run() {
        let mut schedule = IndexSchedule::default();
        let watch = schedule.enable_watch(true);
        let (watch_id, _, _) = one_start(&watch);

        let (manual_id, preemption) = schedule.request_manual().expect("queue manual request");
        assert_eq!(
            preemption,
            vec![IndexScheduleAction::Cancel {
                operation_id: watch_id,
                reason: IndexCancellationReason::ManualPriority,
            }]
        );
        let manual_start = schedule
            .finish(watch_id, IndexAttemptResult::Cancelled)
            .expect("finish preempted watch");
        let (started_manual, manual_trigger, manual_epoch) = one_start(&manual_start);
        assert_eq!(started_manual, manual_id);
        assert_eq!(manual_trigger, IndexOperationTrigger::Manual);
        assert_eq!(manual_epoch, 1);

        assert!(
            schedule.observe_change().is_empty(),
            "manual work is not cancelled by a background hint"
        );
        let follow_up = schedule
            .finish(manual_id, IndexAttemptResult::Published)
            .expect("finish manual publication");
        let (_, trigger, covered_epoch) = one_start(&follow_up);
        assert_eq!(trigger, IndexOperationTrigger::Watch);
        assert_eq!(covered_epoch, 2);
    }

    #[test]
    fn periodic_reconciliation_queues_a_successor_without_starving_active_watch() {
        let mut schedule = IndexSchedule::default();
        let initial = schedule.enable_watch(true);
        let (first, trigger, covered_epoch) = one_start(&initial);
        assert_eq!(trigger, IndexOperationTrigger::Watch);
        assert_eq!(covered_epoch, 1);

        assert!(
            schedule.request_reconciliation(false).is_empty(),
            "a periodic safety scan must not cancel active WATCH work"
        );
        assert_eq!(schedule.snapshot().active_operation, Some(first));
        assert_eq!(schedule.snapshot().desired_epoch, 2);

        let successor = schedule
            .finish(first, IndexAttemptResult::Published)
            .expect("publish first periodic generation");
        let (second, second_trigger, second_epoch) = one_start(&successor);
        assert_ne!(second, first);
        assert_eq!(second_trigger, IndexOperationTrigger::Watch);
        assert_eq!(second_epoch, 2);
    }

    /// RIGHT-REASON REGRESSION: a source hint that arrives during a bounded
    /// periodic no-work reconciliation must queue the changed epoch instead of
    /// cancelling a healthy provider authority probe. Cancelling that probe
    /// quarantines the one-use provider exchange and makes the successor pay a
    /// full process/session restart for no correctness benefit.
    #[test]
    fn change_queues_behind_an_active_periodic_reconciliation() {
        let mut schedule = IndexSchedule::default();
        let initial = schedule.enable_watch(true);
        let (first, _, _) = one_start(&initial);
        assert!(schedule.request_reconciliation(false).is_empty());

        let periodic = schedule
            .finish(first, IndexAttemptResult::Published)
            .expect("finish initial reconciliation");
        let (periodic_id, trigger, periodic_epoch) = one_start(&periodic);
        assert_eq!(trigger, IndexOperationTrigger::Watch);
        assert_eq!(periodic_epoch, 2);

        assert!(
            schedule.observe_change().is_empty(),
            "a periodic no-work probe must finish with its provider session intact before the changed successor starts"
        );
        assert_eq!(
            schedule.snapshot().active_operation,
            Some(periodic_id),
            "the periodic reconciliation must remain active"
        );
        let successor = schedule
            .finish(periodic_id, IndexAttemptResult::Published)
            .expect("finish periodic reconciliation");
        let (_, successor_trigger, successor_epoch) = one_start(&successor);
        assert_eq!(successor_trigger, IndexOperationTrigger::Watch);
        assert_eq!(successor_epoch, 3);
    }

    /// RIGHT-REASON REGRESSION: a failed WATCH attempt has already covered
    /// its exact desired epoch. Retrying that same epoch immediately creates
    /// an unbounded hot loop when a provider or capability floor remains
    /// unavailable. A later filesystem hint or integrity reconciliation is a
    /// new epoch and must still retry promptly.
    #[test]
    fn failed_watch_epoch_parks_until_new_reconciliation_authority() {
        let mut schedule = IndexSchedule::default();
        let initial = schedule.enable_watch(true);
        let (first, trigger, covered_epoch) = one_start(&initial);
        assert_eq!(trigger, IndexOperationTrigger::Watch);
        assert_eq!(covered_epoch, 1);

        assert!(
            schedule
                .finish(first, IndexAttemptResult::Failed)
                .expect("finish failed WATCH attempt")
                .is_empty(),
            "the identical failed epoch must not immediately schedule itself forever"
        );
        let parked = schedule.snapshot();
        assert_eq!(parked.desired_epoch, 1);
        assert_eq!(parked.published_epoch, 0);
        assert_eq!(parked.active_operation, None);

        let retry = schedule.request_reconciliation(false);
        let (second, second_trigger, second_epoch) = one_start(&retry);
        assert_ne!(second, first);
        assert_eq!(second_trigger, IndexOperationTrigger::Watch);
        assert_eq!(second_epoch, 2);
    }

    #[test]
    fn second_manual_request_is_refused_until_first_is_terminal() {
        let mut schedule = IndexSchedule::default();
        let (first, start) = schedule.request_manual().expect("first manual request");
        one_start(&start);
        assert_eq!(
            schedule.request_manual(),
            Err(IndexScheduleError::ManualBusy)
        );
        schedule
            .finish(first, IndexAttemptResult::Failed)
            .expect("terminal first request");
        assert!(schedule.request_manual().is_ok());
    }

    #[test]
    fn wrong_operation_id_has_no_cancellation_or_completion_authority() {
        let mut schedule = IndexSchedule::default();
        let (active, start) = schedule.request_manual().expect("manual request");
        one_start(&start);
        let foreign = IndexOperationId {
            supervisor_id: Uuid::new_v4(),
            sequence: active.sequence(),
        };
        assert_eq!(
            schedule.cancel(foreign),
            Err(IndexScheduleError::OperationNotActive { requested: foreign })
        );
        assert_eq!(
            schedule.finish(foreign, IndexAttemptResult::Published),
            Err(IndexScheduleError::OperationNotActive { requested: foreign })
        );
        assert_eq!(schedule.snapshot().active_operation, Some(active));
        assert_eq!(schedule.snapshot().published_epoch, 0);
    }

    #[test]
    fn staged_publication_advances_epoch_without_ending_active_enrichment() {
        let mut schedule = IndexSchedule::default();
        let start = schedule.enable_watch(true);
        let (active, trigger, covered_epoch) = one_start(&start);
        assert_eq!(trigger, IndexOperationTrigger::Watch);
        assert_eq!(covered_epoch, 1);

        schedule
            .mark_active_publication(active)
            .expect("record active staged publication");
        let staged = schedule.snapshot();
        assert_eq!(staged.published_epoch, 1);
        assert_eq!(staged.active_operation, Some(active));
        assert!(
            schedule
                .mark_active_publication(IndexOperationId {
                    supervisor_id: Uuid::new_v4(),
                    sequence: active.sequence(),
                })
                .is_err(),
            "foreign identity must not advance publication authority"
        );

        schedule.disable_watch();
        assert!(
            schedule
                .finish(active, IndexAttemptResult::Cancelled)
                .expect("finish cancelled enrichment")
                .is_empty()
        );
        assert_eq!(
            schedule.snapshot().published_epoch,
            1,
            "cancelling enrichment must not erase an already-visible structural generation"
        );
    }

    struct RunProbe {
        request: IndexSupervisorRequest,
        reuse_hints: Arc<[PathBuf]>,
        cancellation: IndexCancellation,
        release: oneshot::Sender<()>,
    }

    struct GatedBoundRunner {
        started: mpsc::UnboundedSender<RunProbe>,
    }

    struct FailingHintRunner {
        started: mpsc::UnboundedSender<Arc<[PathBuf]>>,
    }

    #[async_trait]
    impl IndexRunner for FailingHintRunner {
        async fn run(
            &self,
            _binding: ProjectBinding,
            _request: IndexSupervisorRequest,
            reuse_hints: Arc<[PathBuf]>,
            _cancellation: IndexCancellation,
            _progress: mpsc::UnboundedSender<IndexProgressEvent>,
        ) -> RunnerOutcome {
            self.started
                .send(reuse_hints)
                .expect("test controls every failed run");
            RunnerOutcome::Failed(IndexOperationFailure {
                kind: IndexOperationFailureKind::Publication,
                code: IndexOperationFailureCode::PublicationFailed,
                message: "deliberately failed candidate".into(),
            })
        }
    }

    #[async_trait]
    impl IndexRunner for GatedBoundRunner {
        async fn run(
            &self,
            binding: ProjectBinding,
            request: IndexSupervisorRequest,
            reuse_hints: Arc<[PathBuf]>,
            cancellation: IndexCancellation,
            progress: mpsc::UnboundedSender<IndexProgressEvent>,
        ) -> RunnerOutcome {
            let (release, released) = oneshot::channel();
            self.started
                .send(RunProbe {
                    request: request.clone(),
                    reuse_hints: Arc::clone(&reuse_hints),
                    cancellation: cancellation.clone(),
                    release,
                })
                .expect("test controls every started run");
            let _ = released.await;
            if cancellation.is_cancelled() {
                RunnerOutcome::Cancelled
            } else {
                BoundIndexRunner::default()
                    .run(binding, request, reuse_hints, cancellation, progress)
                    .await
            }
        }
    }

    fn supervisor_fixture() -> (TempDir, IndexSupervisor, mpsc::UnboundedReceiver<RunProbe>) {
        let temporary = TempDir::new().expect("supervisor scratch");
        let root = temporary.path().join("repo");
        let data = temporary.path().join("data");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(&data).expect("data directory");
        std::fs::write(root.join("src/lib.rs"), "pub fn watched() -> u8 { 1 }\n")
            .expect("source fixture");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"watched-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest fixture");
        let binding = ProjectBinding::explicit(&root, &data).expect("explicit test binding");
        let (started, starts) = mpsc::unbounded_channel();
        let supervisor =
            IndexSupervisor::with_runner(binding, Arc::new(GatedBoundRunner { started }));
        (temporary, supervisor, starts)
    }

    async fn next_probe(starts: &mut mpsc::UnboundedReceiver<RunProbe>) -> RunProbe {
        timeout(Duration::from_secs(10), starts.recv())
            .await
            .expect("supervisor did not start the next run")
            .expect("supervisor start channel closed")
    }

    /// RIGHT-REASON REGRESSION: bounded paths accelerate reconciliation but
    /// are not expendable merely because one private candidate failed. The
    /// scheduler intentionally parks that epoch until a later hint or safety
    /// reconciliation grants retry authority; that authorized successor must
    /// still receive every retained path since the last successful terminal.
    #[tokio::test]
    async fn failed_operation_retains_change_hints_for_authorized_retry() {
        let temporary = TempDir::new().expect("supervisor scratch");
        let root = temporary.path().join("repo");
        let data = temporary.path().join("data");
        std::fs::create_dir_all(&root).expect("source root");
        std::fs::create_dir_all(&data).expect("data directory");
        let binding = ProjectBinding::explicit(&root, &data).expect("explicit test binding");
        let (started, mut starts) = mpsc::unbounded_channel();
        let supervisor =
            IndexSupervisor::with_runner(binding, Arc::new(FailingHintRunner { started }));
        supervisor
            .enable_watch(IndexSupervisorRequest::default(), false)
            .expect("enable WATCH without initial reconciliation");

        let changed = PathBuf::from("alpha/module.go");
        supervisor
            .observe_changes([changed.clone()])
            .expect("observe exact changed path");
        let first = timeout(Duration::from_secs(10), starts.recv())
            .await
            .expect("first failed operation did not start")
            .expect("runner channel closed");
        assert_eq!(
            first.as_ref(),
            std::slice::from_ref(&changed),
            "positive hint control"
        );

        supervisor
            .request_periodic_reconciliation()
            .expect("authorize one safety retry");
        let retry = timeout(Duration::from_secs(10), starts.recv())
            .await
            .expect("authorized retry did not start")
            .expect("runner channel closed");
        assert_eq!(
            retry.as_ref(),
            [changed],
            "a failed private candidate must not consume unpublished change evidence"
        );

        supervisor.disable_watch();
        supervisor.shutdown_and_wait().await;
    }

    async fn wait_for_published_epoch(supervisor: &IndexSupervisor, expected: u64) {
        let result = timeout(Duration::from_secs(20), async {
            loop {
                let snapshot = supervisor.schedule_snapshot();
                if snapshot.published_epoch == expected && snapshot.active_operation.is_none() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            result.is_ok(),
            "supervisor did not publish epoch {expected}: schedule={:?}",
            supervisor.schedule_snapshot()
        );
    }

    /// FALSIFIER for low-latency semantic WATCH: a real filesystem epoch must
    /// not disappear behind one monolithic provider refresh. The first private
    /// run publishes current structural truth with an explicit capability
    /// downgrade; provider enrichment follows as separately cancellable work.
    #[tokio::test]
    async fn changed_semantic_watch_starts_with_structural_publication() {
        let (_temporary, supervisor, mut starts) = supervisor_fixture();
        let semantic_request = IndexSupervisorRequest {
            providers: ProviderIntent::Refresh,
            capability_floor: CapabilityFloorPolicy::AllowDowngrade,
            ..IndexSupervisorRequest::default()
        };
        supervisor
            .enable_watch(semantic_request, false)
            .expect("enable semantic WATCH without an initial scan");
        supervisor
            .observe_changes([PathBuf::from("src/lib.rs")])
            .expect("observe changed source");

        let first = next_probe(&mut starts).await;
        let first_request = first.request.clone();
        let first_reuse_hints = Arc::clone(&first.reuse_hints);
        first
            .release
            .send(())
            .expect("release controlled WATCH run");

        let provider = next_probe(&mut starts).await;
        let provider_request = provider.request.clone();
        let provider_reuse_hints = Arc::clone(&provider.reuse_hints);
        let running = supervisor.latest_snapshot().expect("running WATCH receipt");
        let structural = running.structural_publication.as_ref().expect(
            "source-current structural publication must be retained before provider release",
        );
        assert_eq!(structural.files_changed, 1, "positive changed-file control");
        let staged_schedule = supervisor.schedule_snapshot();
        assert_eq!(staged_schedule.published_epoch, 1);
        assert_eq!(staged_schedule.active_operation, Some(running.operation_id));

        supervisor.disable_watch();
        assert!(
            provider.cancellation.is_cancelled(),
            "cleanup must cancel the controlled provider run"
        );
        provider
            .release
            .send(())
            .expect("release controlled provider run");
        supervisor.wait_for_watch_idle().await;
        supervisor.shutdown_and_wait().await;

        assert_eq!(
            first_request.providers,
            ProviderIntent::StructuralOnly,
            "a changed semantic WATCH epoch must publish structural truth before the slow provider"
        );
        assert_eq!(
            first_request.capability_floor,
            CapabilityFloorPolicy::AllowDowngrade,
            "the fast structural publication must describe its temporary capability downgrade explicitly"
        );
        assert_eq!(
            provider_request.providers,
            ProviderIntent::Refresh,
            "provider enrichment must follow the visible structural publication"
        );
        assert_eq!(
            first_reuse_hints.as_ref(),
            [PathBuf::from("src/lib.rs")],
            "the structural stage must receive the exact bounded hint population"
        );
        assert_eq!(
            provider_reuse_hints, first_reuse_hints,
            "both stages of one WATCH epoch must retain the same bounded hint evidence"
        );
        let terminal = supervisor
            .latest_snapshot()
            .expect("terminal WATCH receipt");
        assert_eq!(
            terminal.structural_publication,
            Some(structural.clone()),
            "cancellation must not erase the already-published structural receipt"
        );
        assert_eq!(
            terminal.semantic_enrichment_state(),
            Some(SemanticEnrichmentState::Cancelled),
            "the retained structural stage and current enrichment outcome are distinct lifecycle coordinates"
        );
        assert_eq!(
            supervisor.schedule_snapshot().published_epoch,
            1,
            "the visible structural stage must remain the current source epoch"
        );
    }

    #[tokio::test]
    async fn semantic_watch_keeps_atomic_policy_for_preserve_strict_and_hintless_runs() {
        let cases = [
            (
                "preserve-floor",
                IndexSupervisorRequest {
                    providers: ProviderIntent::Refresh,
                    ..IndexSupervisorRequest::default()
                },
                false,
            ),
            (
                "strict-complete",
                IndexSupervisorRequest {
                    providers: ProviderIntent::Refresh,
                    require_complete_calls: true,
                    capability_floor: CapabilityFloorPolicy::AllowDowngrade,
                    ..IndexSupervisorRequest::default()
                },
                false,
            ),
            (
                "hintless-integrity",
                IndexSupervisorRequest {
                    providers: ProviderIntent::Refresh,
                    capability_floor: CapabilityFloorPolicy::AllowDowngrade,
                    ..IndexSupervisorRequest::default()
                },
                true,
            ),
        ];

        for (name, request, initial_reconciliation) in cases {
            let (_temporary, supervisor, mut starts) = supervisor_fixture();
            supervisor
                .enable_watch(request, initial_reconciliation)
                .expect("enable semantic WATCH");
            if !initial_reconciliation {
                supervisor
                    .observe_changes([PathBuf::from("src/lib.rs")])
                    .expect("observe changed source");
            }

            let first = next_probe(&mut starts).await;
            let first_request = first.request.clone();
            let first_reuse_hints = Arc::clone(&first.reuse_hints);
            supervisor.disable_watch();
            assert!(first.cancellation.is_cancelled(), "{name} cleanup control");
            first.release.send(()).expect("release controlled run");
            supervisor.wait_for_watch_idle().await;
            let receipt = supervisor.latest_snapshot().expect("WATCH receipt");
            supervisor.shutdown_and_wait().await;

            assert_eq!(
                first_request.providers,
                ProviderIntent::Refresh,
                "{name} must retain one atomic provider-enriched publication"
            );
            assert!(
                receipt.structural_publication.is_none(),
                "{name} must not expose an unrequested structural downgrade"
            );
            assert_eq!(
                first_reuse_hints.is_empty(),
                initial_reconciliation,
                "only a hintless integrity reconciliation may enter the runner without bounded change hints"
            );
        }
    }

    /// RIGHT-REASON PERFORMANCE REGRESSION: a long-lived WATCH runner already
    /// owns parsed authority for the exact generation that supplied its live
    /// graph and semantic basis. A byte-different indexed hint needs only the
    /// bounded controls plus exact database digest to prove reuse impossible;
    /// reparsing the immutable provider payload before writer admission is
    /// duplicate work. The ordinary cold resolver remains the positive
    /// population control and must still perform complete payload validation.
    #[tokio::test]
    async fn hinted_refresh_reuses_parsed_generation_authority() {
        let temporary = TempDir::new().expect("supervisor scratch");
        let root = temporary.path().join("repo");
        let data = temporary.path().join("data");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(&data).expect("data directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"retained-authority\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest fixture");
        let source = root.join("src/lib.rs");
        std::fs::write(&source, "pub fn before() -> u8 { 1 }\n").expect("source fixture");

        let binding = ProjectBinding::explicit(&root, &data).expect("explicit test binding");
        BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("prepare external seed")
            .publish()
            .await
            .expect("publish external seed");
        let runner = BoundIndexRunner::default();
        let (progress, _events) = mpsc::unbounded_channel();
        assert!(
            runner.live_basis.lock().is_none(),
            "positive control: the runner did not publish the external seed"
        );
        let reused = runner
            .run(
                binding.clone(),
                IndexSupervisorRequest::default(),
                Arc::default(),
                IndexCancellation::new(),
                progress.clone(),
            )
            .await;
        let reused = match reused {
            RunnerOutcome::Published(published) => published,
            RunnerOutcome::Failed(failure) => panic!("initial exact reuse failed: {failure:?}"),
            RunnerOutcome::Cancelled => panic!("initial exact reuse was cancelled"),
        };
        assert!(
            reused.telemetry.reused_generation,
            "positive control requires reuse of the externally seeded generation"
        );
        let reused_inventory_allocation =
            Arc::as_ptr(&reused.publication.project_inventory) as usize;
        let live_inventory_allocation = runner
            .live_basis
            .lock()
            .as_ref()
            .map(LiveGenerationBasis::project_inventory_allocation)
            .expect("exact-reuse live inventory allocation");
        assert_eq!(
            live_inventory_allocation, reused_inventory_allocation,
            "exact reuse must share one immutable project-inventory allocation between its result and live authority"
        );
        assert!(
            runner
                .live_basis
                .lock()
                .as_ref()
                .and_then(LiveGenerationBasis::authority_snapshot)
                .is_some(),
            "positive control requires exact parsed authority bound to the live basis"
        );

        let (_resolved, cold_timings) =
            crate::code_intel_publication::resolve_generation_with_control_token_profiled(
                &data, &root,
            );
        assert!(
            cold_timings
                .iter()
                .any(|timing| timing.label == "reuse provider payload validation"),
            "positive control: the ordinary cold resolver must retain complete payload validation"
        );

        std::fs::write(&source, "pub fn after() -> u8 { 2 }\n").expect("hinted source update");
        let refreshed = runner
            .run(
                binding,
                IndexSupervisorRequest::default(),
                Arc::from([source]),
                IndexCancellation::new(),
                progress,
            )
            .await;
        let refreshed = match refreshed {
            RunnerOutcome::Published(published) => published,
            RunnerOutcome::Failed(failure) => panic!("hinted refresh failed: {failure:?}"),
            RunnerOutcome::Cancelled => panic!("hinted refresh was cancelled"),
        };
        assert_eq!(refreshed.telemetry.files_changed, 1);
        let reuse_labels = refreshed
            .telemetry
            .phase_timings
            .iter()
            .filter(|timing| timing.phase == IndexProgressPhase::Reuse)
            .map(|timing| timing.label.as_str())
            .collect::<Vec<_>>();
        assert!(
            reuse_labels.contains(&"reuse retained immutable database digest"),
            "retained authority must remain bound by an exact database digest: {reuse_labels:?}"
        );
        assert!(
            !reuse_labels.contains(&"reuse provider payload validation"),
            "the hinted warm path reparsed authority it already retained: {reuse_labels:?}"
        );

        use std::io::Write as _;
        std::fs::OpenOptions::new()
            .append(true)
            .open(&refreshed.publication.database_path)
            .expect("open current immutable database for tamper control")
            .write_all(b"retained-authority-tamper-control")
            .expect("alter current immutable database bytes");
        let source = root.join("src/lib.rs");
        std::fs::write(&source, "pub fn after_tamper() -> u8 { 3 }\n")
            .expect("post-tamper source update");
        let recovered = runner
            .run(
                ProjectBinding::explicit(&root, &data).expect("recovery binding"),
                IndexSupervisorRequest::default(),
                Arc::from([source]),
                IndexCancellation::new(),
                mpsc::unbounded_channel().0,
            )
            .await;
        let recovered = match recovered {
            RunnerOutcome::Published(published) => published,
            RunnerOutcome::Failed(failure) => {
                panic!("valid older-head recovery failed after tamper rejection: {failure:?}")
            }
            RunnerOutcome::Cancelled => panic!("tamper recovery was cancelled"),
        };
        assert!(
            !recovered.telemetry.live_structural_basis_reused,
            "byte-altered immutable authority must reject the retained live basis"
        );
        assert!(
            recovered
                .telemetry
                .phase_timings
                .iter()
                .any(|timing| timing.label == "reuse provider payload validation"),
            "digest mismatch must fall back to ordinary complete generation resolution"
        );
    }

    /// PERFORMANCE FALSIFIER: one long-lived supervisor owns consecutive
    /// generations and therefore has an exact in-memory structural basis after
    /// the first successful publication. Changing one document must not force
    /// the next operation to rematerialize every unchanged source node.
    #[tokio::test]
    async fn long_lived_supervisor_rematerializes_only_the_changed_document() {
        let temporary = TempDir::new().expect("supervisor scratch");
        let root = temporary.path().join("repo");
        let data = temporary.path().join("data");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(&data).expect("data directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"live-basis\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest fixture");
        std::fs::write(
            root.join("src/lib.rs"),
            "macro_rules! generate { ($name:ident) => { pub struct $name; } }\ngenerate!(Generated);\npub mod target;\npub use crate::target::changed;\npub fn unchanged_one() -> u8 { 1 }\npub fn unchanged_two() -> u8 { unchanged_one() }\n",
        )
        .expect("unchanged source fixture");
        let target = root.join("src/target.rs");
        std::fs::write(&target, "pub fn changed() -> u8 { 1 }\n").expect("changed source fixture");

        let binding = ProjectBinding::explicit(&root, &data).expect("explicit test binding");
        let runner = Arc::new(BoundIndexRunner::default());
        let supervisor = IndexSupervisor::with_runner(binding, runner.clone());
        let first = supervisor
            .start_manual(IndexSupervisorRequest::default())
            .expect("start initial publication")
            .wait()
            .await
            .expect("receive initial publication");
        let first = match first {
            IndexOperationOutcome::Published(published) => published,
            other => panic!("initial operation did not publish: {other:?}"),
        };
        assert!(
            first.publication.manifest.receipts.iter().any(|receipt| {
                receipt.capability_id == "structural_graph"
                    && receipt.status == crate::code_intel_domain::CapabilityStatus::Partial
                    && matches!(
                        &receipt.scope,
                        crate::code_intel_domain::CapabilityScope::Language {
                            language_id,
                            ..
                        } if language_id.0 == "rust"
                    )
            }),
            "positive control: the live basis must carry truthful Partial Rust coverage"
        );
        let published_inventory_allocation =
            Arc::as_ptr(&first.publication.project_inventory) as usize;
        let live_inventory_allocation = runner
            .live_basis
            .lock()
            .as_ref()
            .map(LiveGenerationBasis::project_inventory_allocation)
            .expect("initial live inventory allocation");
        assert_eq!(
            live_inventory_allocation, published_inventory_allocation,
            "published and live authority must share one immutable project-inventory allocation"
        );
        let unchanged_allocation_before = runner
            .live_basis
            .lock()
            .as_ref()
            .and_then(|basis| basis.source_symbol_name_allocation("unchanged_one"))
            .expect("unchanged node allocation in initial live basis");

        std::fs::write(
            &target,
            "pub fn changed() -> u8 { 2 }\npub fn added() -> u8 { changed() }\n",
        )
        .expect("modify exactly one source document");
        let second = supervisor
            .start_manual(IndexSupervisorRequest::default())
            .expect("start incremental publication")
            .wait()
            .await
            .expect("receive incremental publication");
        let second = match second {
            IndexOperationOutcome::Published(published) => published,
            other => panic!("incremental operation did not publish: {other:?}"),
        };
        let unchanged_allocation_after = runner
            .live_basis
            .lock()
            .as_ref()
            .and_then(|basis| basis.source_symbol_name_allocation("unchanged_one"))
            .expect("unchanged node allocation in successor live basis");

        assert_eq!(second.telemetry.files_changed, 1);
        assert!(
            first.telemetry.nodes_total > second.telemetry.symbols_extracted,
            "positive control requires unchanged nodes outside the changed document"
        );
        assert!(
            second.telemetry.symbols_extracted > 0,
            "positive control requires a nonempty changed-document population"
        );
        assert!(
            second.telemetry.live_structural_basis_reused,
            "the second operation must prove it used the exact in-memory basis"
        );
        assert_eq!(
            second.telemetry.nodes_added, second.telemetry.symbols_extracted,
            "a long-lived supervisor must rematerialize changed-document nodes only"
        );
        assert_eq!(
            unchanged_allocation_after, unchanged_allocation_before,
            "the disposable live basis must transfer ownership instead of deep-cloning every unchanged node"
        );

        std::fs::write(&target, "pub fn replacement() -> u8 { 3 }\n")
            .expect("replace the changed document population");
        let third = supervisor
            .start_manual(IndexSupervisorRequest::default())
            .expect("start deletion/replacement publication")
            .wait()
            .await
            .expect("receive deletion/replacement publication");
        let third = match third {
            IndexOperationOutcome::Published(published) => published,
            other => panic!("deletion/replacement operation did not publish: {other:?}"),
        };
        assert!(third.telemetry.live_structural_basis_reused);
        assert_eq!(third.telemetry.files_changed, 1);
        assert_eq!(third.telemetry.nodes_added, 1);
        let database = Arc::new(
            redb::ReadOnlyDatabase::open(&third.publication.database_path)
                .expect("open deletion/replacement publication"),
        );
        let graph = crate::graph_store::GraphStore::new_read_only(database)
            .load_snapshot_checked(&root)
            .await
            .expect("load deletion/replacement graph")
            .expect("deletion/replacement graph snapshot");
        assert!(
            graph
                .all_nodes()
                .into_iter()
                .any(|node| node.symbol_name == "replacement")
        );
        for removed in ["changed", "added"] {
            assert!(
                graph
                    .all_nodes()
                    .into_iter()
                    .all(|node| node.symbol_name != removed),
                "deleted `{removed}` must not survive the live basis"
            );
        }
        assert!(
            graph
                .all_nodes()
                .into_iter()
                .any(|node| node.symbol_name == "unchanged_two"),
            "unchanged-document nodes must remain in the complete graph"
        );

        supervisor.shutdown_and_wait().await;
    }

    #[tokio::test]
    #[ignore = "requires the explicitly built installed rust-analyzer sidecar"]
    async fn installed_persistent_provider_reaches_immutable_publication_and_watch_fast_lane() {
        let binary = PathBuf::from(
            std::env::var_os("H00_TEST_RA_PROVIDER_BINARY").expect("H00_TEST_RA_PROVIDER_BINARY"),
        );
        let receipt = PathBuf::from(
            std::env::var_os("H00_TEST_RA_PROVIDER_RECEIPT").expect("H00_TEST_RA_PROVIDER_RECEIPT"),
        );
        let temporary = TempDir::new().expect("provider publication scratch");
        let root = temporary.path().join("repo");
        let data = temporary.path().join("data");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(&data).expect("data directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"provider-publication\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        std::fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"provider-publication\"\nversion = \"0.1.0\"\n",
        )
        .expect("lockfile");
        let source = root.join("src/lib.rs");
        std::fs::write(
            &source,
            "pub fn target() -> usize { 1 }\npub fn caller() -> usize { target() }\n",
        )
        .expect("initial source");

        let receipt_value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&receipt).expect("provider receipt"))
                .expect("provider receipt JSON");
        let receipt_text = |field: &str| {
            receipt_value[field]
                .as_str()
                .unwrap_or_else(|| panic!("provider receipt field {field}"))
                .to_owned()
        };
        let identity = h00ligan_provider_protocol::ProviderIdentity {
            protocol: receipt_text("protocol"),
            provider_id: receipt_text("provider_id"),
            language: receipt_text("language"),
            implementation_version: h00ligan_provider_protocol::H00_RUST_ANALYZER_IMPLEMENTATION_V5
                .into(),
            source_components: h00ligan_provider_protocol::rust_analyzer_source_components(),
            patch_sha256: receipt_text("patch_sha256"),
            executable_sha256: h00ligan_provider_protocol::sha256_hex(
                &std::fs::read(&binary).expect("provider binary"),
            ),
        };
        let toolchain_resolver =
            crate::code_intel_toolchain::TestToolchainResolver::from_current_process(&[
                "PATH",
                "HOME",
                "CARGO_HOME",
                "RUSTUP_HOME",
                "TMPDIR",
            ])
            .with_environment("RUSTUP_TOOLCHAIN", "1.97.1")
            .with_environment("CARGO_TERM_COLOR", "never")
            .with_installed_rust_programs();
        let mut provider_config =
            RustSemanticProviderConfig::new(binary, identity, Arc::new(toolchain_resolver))
                .expect("provider config");
        provider_config.request_timeout = Duration::from_secs(60);

        let binding = ProjectBinding::explicit(&root, &data).expect("explicit binding");
        let toolchain_resolver = Some(Arc::clone(&provider_config.toolchain_resolver));
        let runner = Arc::new(
            BoundIndexRunner::with_semantic_providers(
                vec![provider_config.into()],
                toolchain_resolver,
            )
            .expect("unique Rust provider registry"),
        );
        let supervisor = IndexSupervisor::with_runner(binding, runner.clone());
        let request = IndexSupervisorRequest {
            providers: ProviderIntent::Refresh,
            require_complete_calls: true,
            capability_floor: CapabilityFloorPolicy::AllowDowngrade,
            ..IndexSupervisorRequest::default()
        };
        let first = supervisor
            .start_manual(request.clone())
            .expect("start full provider publication")
            .wait()
            .await
            .expect("receive full provider publication");
        let first = match first {
            IndexOperationOutcome::Published(published) => published,
            other => panic!("full provider operation did not publish: {other:?}"),
        };
        assert!(
            first.publication.manifest.receipts.iter().any(|receipt| {
                receipt.capability_id == "calls"
                    && receipt.provider_id.0
                        == h00ligan_provider_protocol::H00_RUST_ANALYZER_PROVIDER_ID
                    && receipt.status == crate::code_intel_domain::CapabilityStatus::Complete
            }),
            "persistent semantic publication must retain the exact provider receipt: {:#?}",
            first.publication.manifest.receipts
        );
        assert!(matches!(
            first.telemetry.semantic_provider_refreshes.as_slice(),
            [crate::index_pipeline::SemanticProviderActivityTelemetry::Admitted {
                language_id,
                lane: crate::index_pipeline::SemanticProviderRefreshLane::Full,
                operation: h00ligan_provider_protocol::ProviderOperation::CertifyFull,
                ..
            }] if language_id == "rust"
        ));

        std::fs::write(
            &source,
            "pub fn target() -> usize { 2 }\npub fn caller() -> usize { target() }\n",
        )
        .expect("body-only source edit");
        let second = supervisor
            .start_manual(request)
            .expect("start affected provider publication")
            .wait()
            .await
            .expect("receive affected provider publication");
        let second = match second {
            IndexOperationOutcome::Published(published) => published,
            other => panic!("affected provider operation did not publish: {other:?}"),
        };
        assert_eq!(second.telemetry.files_changed, 1);
        assert!(matches!(
            second.telemetry.semantic_provider_refreshes.as_slice(),
            [crate::index_pipeline::SemanticProviderActivityTelemetry::Admitted {
                language_id,
                lane: crate::index_pipeline::SemanticProviderRefreshLane::AffectedDocuments,
                operation: h00ligan_provider_protocol::ProviderOperation::RefreshAffected,
                documents,
                ..
            }] if language_id == "rust" && documents == &["src/lib.rs"]
        ));
        supervisor.shutdown_and_wait().await;
        let semantic_providers = runner.semantic_providers.lock();
        assert!(semantic_providers.contains("rust"));
        drop(semantic_providers);
    }

    #[tokio::test]
    async fn cancelled_reuse_probe_retains_unconsumed_live_basis() {
        let temporary = TempDir::new().expect("supervisor scratch");
        let root = temporary.path().join("repo");
        let data = temporary.path().join("data");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(&data).expect("data directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"cancelled-reuse-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest fixture");
        std::fs::write(root.join("src/lib.rs"), "pub fn retained() -> u8 { 1 }\n")
            .expect("source fixture");

        let binding = ProjectBinding::explicit(&root, &data).expect("explicit test binding");
        let runner = BoundIndexRunner::default();
        let (progress, _events) = mpsc::unbounded_channel();
        let first = runner
            .run(
                binding.clone(),
                IndexSupervisorRequest::default(),
                Arc::default(),
                IndexCancellation::new(),
                progress.clone(),
            )
            .await;
        assert!(
            matches!(first, RunnerOutcome::Published(_)),
            "positive control must establish a published generation"
        );
        assert!(
            runner.live_basis.lock().is_some(),
            "positive control requires a populated process-local basis"
        );

        let cancellation = IndexCancellation::new();
        cancellation.cancel();
        assert!(
            matches!(
                runner
                    .run(
                        binding.clone(),
                        IndexSupervisorRequest::default(),
                        Arc::default(),
                        cancellation,
                        progress.clone(),
                    )
                    .await,
                RunnerOutcome::Cancelled
            ),
            "the cancelled probe must not publish"
        );
        assert!(
            runner.live_basis.lock().is_some(),
            "cancellation before fresh-candidate admission must not consume the live basis"
        );

        let successor = runner
            .run(
                binding,
                IndexSupervisorRequest::default(),
                Arc::default(),
                IndexCancellation::new(),
                progress,
            )
            .await;
        let successor = match successor {
            RunnerOutcome::Published(published) => published,
            RunnerOutcome::Failed(failure) => panic!("successor failed: {failure:?}"),
            RunnerOutcome::Cancelled => panic!("successor was cancelled"),
        };
        assert!(
            successor.telemetry.reused_generation,
            "the successor must reuse the exact immutable generation"
        );
        assert!(
            runner.live_basis.lock().is_some(),
            "exact reuse must retain the matching live acceleration basis"
        );
    }

    #[tokio::test]
    async fn failed_operation_discards_live_cache_and_successor_uses_published_basis() {
        let temporary = TempDir::new().expect("supervisor scratch");
        let root = temporary.path().join("repo");
        let data = temporary.path().join("data");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(&data).expect("data directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"failed-live-basis\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest fixture");
        let source = root.join("src/lib.rs");
        std::fs::write(&source, "pub fn before() -> u8 { 1 }\n").expect("initial source");

        let binding = ProjectBinding::explicit(&root, &data).expect("explicit test binding");
        let runner = Arc::new(BoundIndexRunner::default());
        let supervisor = IndexSupervisor::with_runner(binding, runner.clone());
        let first = supervisor
            .start_manual(IndexSupervisorRequest::default())
            .expect("start initial publication")
            .wait()
            .await
            .expect("receive initial publication");
        let first = match first {
            IndexOperationOutcome::Published(published) => published,
            other => panic!("initial operation did not publish: {other:?}"),
        };
        assert!(
            runner.live_basis.lock().is_some(),
            "positive control requires a populated process-local basis"
        );

        std::fs::write(&source, "pub fn after_failure() -> u8 { 2 }\n")
            .expect("change source before the rejected candidate");
        let rejected = supervisor
            .start_manual(IndexSupervisorRequest {
                require_complete_calls: true,
                ..IndexSupervisorRequest::default()
            })
            .expect("start deliberately unsatisfied publication")
            .wait()
            .await
            .expect("receive rejected publication");
        let failure = match rejected {
            IndexOperationOutcome::Failed(failure) => failure,
            other => panic!("strict structural-only operation was not rejected: {other:?}"),
        };
        assert_eq!(failure.kind, IndexOperationFailureKind::Publication);
        assert_eq!(failure.code, IndexOperationFailureCode::PublicationFailed);
        assert!(
            failure
                .message
                .contains("required complete Calls authority")
                && failure.message.contains("provider_not_requested"),
            "the failure must come from the post-transfer semantic-authority gate: {failure:?}"
        );
        assert!(
            runner.live_basis.lock().is_none(),
            "a failed operation must drop its consumed acceleration cache"
        );
        let retained = crate::code_intel_publication::resolve_generation(&data, &root)
            .expect("last-good generation remains resolvable");
        assert_eq!(
            retained.manifest.generation_id, first.publication.manifest.generation_id,
            "a rejected private candidate must not advance immutable authority"
        );

        let recovered = supervisor
            .start_manual(IndexSupervisorRequest::default())
            .expect("start successor publication")
            .wait()
            .await
            .expect("receive successor publication");
        let recovered = match recovered {
            IndexOperationOutcome::Published(published) => published,
            other => panic!("successor operation did not publish: {other:?}"),
        };
        assert!(
            !recovered.telemetry.live_structural_basis_reused,
            "without a trusted live cache, the successor must rebuild from published source facts"
        );
        assert!(
            runner.live_basis.lock().is_some(),
            "the successful successor must establish a fresh live cache"
        );
        let database = Arc::new(
            redb::ReadOnlyDatabase::open(&recovered.publication.database_path)
                .expect("open successor publication"),
        );
        let graph = crate::graph_store::GraphStore::new_read_only(database)
            .load_snapshot_checked(&root)
            .await
            .expect("load successor graph")
            .expect("successor graph snapshot");
        assert!(
            graph
                .all_nodes()
                .into_iter()
                .any(|node| node.symbol_name == "after_failure"),
            "the immutable-basis fallback must publish the changed source"
        );
        assert!(
            graph
                .all_nodes()
                .into_iter()
                .all(|node| node.symbol_name != "before"),
            "the immutable-basis fallback must not resurrect replaced source nodes"
        );

        supervisor.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn stale_live_basis_is_rejected_after_an_external_publication() {
        let temporary = TempDir::new().expect("supervisor scratch");
        let root = temporary.path().join("repo");
        let data = temporary.path().join("data");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(&data).expect("data directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"stale-live-basis\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest fixture");
        let lib = root.join("src/lib.rs");
        let target = root.join("src/target.rs");
        std::fs::write(&lib, "pub mod target;\npub fn original() {}\n").expect("library fixture");
        std::fs::write(&target, "pub fn target() {}\n").expect("target fixture");

        let binding = ProjectBinding::explicit(&root, &data).expect("explicit test binding");
        let supervisor = IndexSupervisor::new(binding.clone());
        let first = supervisor
            .start_manual(IndexSupervisorRequest::default())
            .expect("start initial publication")
            .wait()
            .await
            .expect("receive initial publication");
        assert!(matches!(first, IndexOperationOutcome::Published(_)));

        std::fs::write(&target, "pub fn target() {}\npub fn external_only() {}\n")
            .expect("external source change");
        BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("prepare external publisher")
            .publish()
            .await
            .expect("external publisher advances the immutable head");

        std::fs::write(
            &lib,
            "pub mod target;\npub fn original() {}\npub fn supervisor_only() {}\n",
        )
        .expect("supervisor source change");
        let second = supervisor
            .start_manual(IndexSupervisorRequest::default())
            .expect("start publication after external advance")
            .wait()
            .await
            .expect("receive publication after external advance");
        let second = match second {
            IndexOperationOutcome::Published(published) => published,
            other => panic!("operation after external advance did not publish: {other:?}"),
        };
        assert!(
            !second.telemetry.live_structural_basis_reused,
            "a basis bound to the superseded head must have no reuse authority"
        );

        let database = Arc::new(
            redb::ReadOnlyDatabase::open(&second.publication.database_path)
                .expect("open final publication"),
        );
        let graph = crate::graph_store::GraphStore::new_read_only(database)
            .load_snapshot_checked(&root)
            .await
            .expect("load final graph")
            .expect("final graph snapshot");
        for symbol in ["external_only", "supervisor_only"] {
            assert!(
                graph
                    .all_nodes()
                    .into_iter()
                    .any(|node| node.symbol_name == symbol),
                "fallback must retain independently published `{symbol}`"
            );
        }

        supervisor.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn runtime_supersedes_active_watch_and_publishes_the_newest_epoch() {
        let (_temporary, supervisor, mut starts) = supervisor_fixture();
        let initial = supervisor
            .enable_watch(IndexSupervisorRequest::default(), true)
            .expect("enable watch");
        let (first, _, _) = one_start(&initial);
        let first_probe = next_probe(&mut starts).await;

        supervisor
            .observe_changes([PathBuf::from("src/lib.rs")])
            .expect("observe newer source epoch");
        assert!(
            first_probe.cancellation.is_cancelled(),
            "newer epoch must cancel the stale private WATCH candidate"
        );
        first_probe.release.send(()).expect("release first run");

        let second_probe = next_probe(&mut starts).await;
        let second = supervisor
            .schedule_snapshot()
            .active_operation
            .expect("replacement WATCH operation");
        assert_ne!(second, first);
        assert!(!second_probe.cancellation.is_cancelled());
        second_probe.release.send(()).expect("release second run");
        wait_for_published_epoch(&supervisor, 2).await;

        assert_eq!(
            supervisor.snapshot(first).expect("first receipt").state,
            IndexOperationState::Superseded
        );
        assert_eq!(
            supervisor.snapshot(second).expect("second receipt").state,
            IndexOperationState::Succeeded
        );
        supervisor.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn runtime_superseded_watch_restores_borrowed_and_concurrent_hints() {
        let (_temporary, supervisor, mut starts) = supervisor_fixture();
        supervisor
            .enable_watch(IndexSupervisorRequest::default(), false)
            .expect("enable watch without an initial reconciliation");

        let borrowed = PathBuf::from("src/borrowed.rs");
        let concurrent = PathBuf::from("src/concurrent.rs");
        supervisor
            .observe_changes([borrowed.clone()])
            .expect("start a WATCH operation with one borrowed hint");
        let first = supervisor
            .schedule_snapshot()
            .active_operation
            .expect("first WATCH operation");
        let first_probe = next_probe(&mut starts).await;
        assert_eq!(
            first_probe.reuse_hints.as_ref(),
            std::slice::from_ref(&borrowed)
        );

        supervisor
            .observe_changes([concurrent.clone()])
            .expect("observe a concurrent change while the first run owns its hint");
        assert!(first_probe.cancellation.is_cancelled());
        first_probe
            .release
            .send(())
            .expect("release superseded run");

        let second_probe = next_probe(&mut starts).await;
        let mut received = second_probe.reuse_hints.to_vec();
        received.sort();
        let mut expected = vec![borrowed, concurrent];
        expected.sort();
        assert_eq!(
            received, expected,
            "the successor must receive borrowed and concurrently observed hints"
        );
        let second = supervisor
            .schedule_snapshot()
            .active_operation
            .expect("successor WATCH operation");
        assert_eq!(
            supervisor
                .snapshot(second)
                .expect("successor receipt")
                .dirty_hint_count,
            2
        );
        second_probe
            .release
            .send(())
            .expect("release successor run");
        wait_for_published_epoch(&supervisor, 2).await;
        assert_eq!(
            supervisor.snapshot(first).expect("first receipt").state,
            IndexOperationState::Superseded
        );
        supervisor.shutdown_and_wait().await;
    }

    /// A caller-requested cancellation terminates one private attempt, not the
    /// changed-path evidence that authorized it. A later safety reconciliation
    /// must therefore receive the exact borrowed hint again.
    #[tokio::test]
    async fn runtime_explicit_cancellation_restores_borrowed_hints() {
        let (_temporary, supervisor, mut starts) = supervisor_fixture();
        supervisor
            .enable_watch(IndexSupervisorRequest::default(), false)
            .expect("enable watch without an initial reconciliation");

        let changed = PathBuf::from("src/explicitly-cancelled.rs");
        supervisor
            .observe_changes([changed.clone()])
            .expect("start one hinted WATCH operation");
        let cancelled = supervisor
            .schedule_snapshot()
            .active_operation
            .expect("active hinted operation");
        let cancelled_probe = next_probe(&mut starts).await;
        assert_eq!(
            cancelled_probe.reuse_hints.as_ref(),
            std::slice::from_ref(&changed),
            "positive borrowed-hint control"
        );

        let cancellation = supervisor
            .cancel(cancelled)
            .expect("cancel exact active operation");
        assert!(cancellation.accepted);
        assert!(cancelled_probe.cancellation.is_cancelled());
        cancelled_probe
            .release
            .send(())
            .expect("release explicitly cancelled run");
        let retry_probe = next_probe(&mut starts).await;
        assert_eq!(
            supervisor
                .snapshot(cancelled)
                .expect("cancelled operation receipt")
                .state,
            IndexOperationState::Cancelled,
            "the requested operation must become terminal before its successor runs"
        );
        let retry = supervisor
            .schedule_snapshot()
            .active_operation
            .expect("continuous WATCH successor");
        assert_ne!(
            retry, cancelled,
            "a cancelled identity must never be replayed"
        );
        assert_eq!(
            retry_probe.reuse_hints.as_ref(),
            [changed],
            "explicit cancellation must not consume unpublished change evidence"
        );
        retry_probe.release.send(()).expect("release retry run");
        wait_for_published_epoch(&supervisor, 1).await;
        supervisor.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn runtime_superseded_watch_restores_borrowed_overflow_authority() {
        let (_temporary, supervisor, mut starts) = supervisor_fixture();
        supervisor
            .enable_watch(IndexSupervisorRequest::default(), false)
            .expect("enable watch without an initial reconciliation");

        let changed = (0..=MAX_DIRTY_HINTS)
            .map(|index| PathBuf::from(format!("src/generated-{index}.rs")))
            .collect::<Vec<_>>();
        supervisor
            .observe_changes(changed.clone())
            .expect("start an overflowing WATCH operation");
        let first = supervisor
            .schedule_snapshot()
            .active_operation
            .expect("overflowing WATCH operation");
        assert!(
            supervisor
                .snapshot(first)
                .expect("overflowing operation receipt")
                .dirty_hints_overflowed,
            "positive overflow control"
        );
        let first_probe = next_probe(&mut starts).await;
        assert_eq!(first_probe.reuse_hints.len(), MAX_DIRTY_HINTS);

        supervisor
            .observe_changes([changed[0].clone()])
            .expect("supersede with a duplicate hint that cannot recreate overflow");
        assert!(first_probe.cancellation.is_cancelled());
        first_probe
            .release
            .send(())
            .expect("release overflowing run");

        let second_probe = next_probe(&mut starts).await;
        let second = supervisor
            .schedule_snapshot()
            .active_operation
            .expect("overflow successor");
        let second_receipt = supervisor.snapshot(second).expect("successor receipt");
        assert_eq!(second_probe.reuse_hints.len(), MAX_DIRTY_HINTS);
        assert!(
            second_receipt.dirty_hints_overflowed,
            "a cancelled private run must restore conservative overflow authority"
        );
        second_probe
            .release
            .send(())
            .expect("release overflow successor");
        wait_for_published_epoch(&supervisor, 2).await;
        supervisor.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn runtime_manual_priority_inherits_preempted_watch_hints() {
        let (_temporary, supervisor, mut starts) = supervisor_fixture();
        supervisor
            .enable_watch(IndexSupervisorRequest::default(), false)
            .expect("enable watch without an initial reconciliation");

        let borrowed = PathBuf::from("src/manual-priority.rs");
        supervisor
            .observe_changes([borrowed.clone()])
            .expect("start hinted WATCH operation");
        let watch_probe = next_probe(&mut starts).await;
        assert_eq!(
            watch_probe.reuse_hints.as_ref(),
            std::slice::from_ref(&borrowed)
        );

        let manual = supervisor
            .start_manual(IndexSupervisorRequest::default())
            .expect("queue priority manual request");
        assert!(watch_probe.cancellation.is_cancelled());
        watch_probe
            .release
            .send(())
            .expect("release preempted WATCH operation");

        let manual_probe = next_probe(&mut starts).await;
        assert_eq!(
            manual_probe.reuse_hints.as_ref(),
            [borrowed],
            "manual priority must inherit unpublished WATCH evidence"
        );
        manual_probe.release.send(()).expect("release manual run");
        assert!(matches!(
            manual.wait().await.expect("manual terminal result"),
            IndexOperationOutcome::Published(_)
        ));
        supervisor.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn runtime_manual_priority_preserves_a_change_observed_during_manual_run() {
        let (_temporary, supervisor, mut starts) = supervisor_fixture();
        supervisor
            .enable_watch(IndexSupervisorRequest::default(), true)
            .expect("enable watch");
        let first_watch = next_probe(&mut starts).await;

        let manual = supervisor
            .start_manual(IndexSupervisorRequest::default())
            .expect("queue priority manual request");
        assert!(first_watch.cancellation.is_cancelled());
        first_watch.release.send(()).expect("release first watch");

        let manual_probe = next_probe(&mut starts).await;
        assert_eq!(
            supervisor.schedule_snapshot().active_operation,
            Some(manual.operation_id())
        );
        supervisor
            .observe_changes([PathBuf::from("src/lib.rs")])
            .expect("observe change during manual run");
        assert!(
            !manual_probe.cancellation.is_cancelled(),
            "background hints must not cancel explicit manual work"
        );
        manual_probe.release.send(()).expect("release manual run");
        let manual_outcome = manual.wait().await.expect("manual result");
        assert!(
            matches!(manual_outcome, IndexOperationOutcome::Published(_)),
            "manual publication failed: {manual_outcome:?}"
        );

        let follow_up = next_probe(&mut starts).await;
        assert_eq!(
            supervisor.schedule_snapshot().active_trigger,
            Some(IndexOperationTrigger::Watch)
        );
        follow_up.release.send(()).expect("release follow-up watch");
        wait_for_published_epoch(&supervisor, 2).await;
        supervisor.shutdown_and_wait().await;
    }

    #[tokio::test]
    async fn runtime_periodic_reconciliation_does_not_cancel_active_watch() {
        let (_temporary, supervisor, mut starts) = supervisor_fixture();
        supervisor
            .enable_watch(IndexSupervisorRequest::default(), true)
            .expect("enable watch");
        let first = supervisor
            .schedule_snapshot()
            .active_operation
            .expect("initial WATCH operation");
        let first_probe = next_probe(&mut starts).await;

        let observation = supervisor
            .request_periodic_reconciliation()
            .expect("queue periodic reconciliation");
        assert_eq!(observation.desired_epoch, 2);
        assert!(
            !first_probe.cancellation.is_cancelled(),
            "the watchdog must not repeatedly abort long-running reconciliation"
        );
        assert_eq!(supervisor.schedule_snapshot().active_operation, Some(first));

        first_probe.release.send(()).expect("release first WATCH");
        let second_probe = next_probe(&mut starts).await;
        let second = supervisor
            .schedule_snapshot()
            .active_operation
            .expect("periodic successor WATCH");
        assert_ne!(second, first);
        second_probe
            .release
            .send(())
            .expect("release successor WATCH");
        wait_for_published_epoch(&supervisor, 2).await;
        supervisor.shutdown_and_wait().await;
    }

    /// Production-boundary complement to
    /// `change_queues_behind_an_active_periodic_reconciliation`: the async
    /// supervisor must preserve the cancellation token of a periodic no-work
    /// run, finish it, and then start the queued source epoch. This prevents a
    /// harmless integrity check from quarantining a healthy one-use semantic
    /// provider exchange.
    #[tokio::test]
    async fn runtime_change_queues_behind_active_periodic_reconciliation() {
        let (temporary, supervisor, mut starts) = supervisor_fixture();
        supervisor
            .enable_watch(IndexSupervisorRequest::default(), true)
            .expect("enable watch");
        let initial_probe = next_probe(&mut starts).await;

        supervisor
            .request_periodic_reconciliation()
            .expect("queue periodic reconciliation");
        initial_probe
            .release
            .send(())
            .expect("release initial WATCH");

        let periodic_probe = next_probe(&mut starts).await;
        let periodic = supervisor
            .schedule_snapshot()
            .active_operation
            .expect("active periodic WATCH operation");
        std::fs::write(
            temporary.path().join("repo/src/lib.rs"),
            "pub fn watched() -> u8 { 2 }\n",
        )
        .expect("change watched source");
        let observation = supervisor
            .observe_changes([PathBuf::from("src/lib.rs")])
            .expect("observe source change during periodic reconciliation");
        assert_eq!(observation.desired_epoch, 3);
        assert!(
            !periodic_probe.cancellation.is_cancelled(),
            "a changed epoch must queue behind the bounded periodic probe instead of quarantining its provider exchange"
        );

        periodic_probe
            .release
            .send(())
            .expect("release periodic WATCH");
        let changed_probe = next_probe(&mut starts).await;
        let changed = supervisor
            .schedule_snapshot()
            .active_operation
            .expect("queued changed WATCH operation");
        assert_ne!(changed, periodic);
        assert!(!changed_probe.cancellation.is_cancelled());
        changed_probe
            .release
            .send(())
            .expect("release changed WATCH");
        wait_for_published_epoch(&supervisor, 3).await;

        assert_eq!(
            supervisor
                .snapshot(periodic)
                .expect("periodic receipt")
                .state,
            IndexOperationState::Succeeded
        );
        assert_eq!(
            supervisor.snapshot(changed).expect("changed receipt").state,
            IndexOperationState::Succeeded
        );
        supervisor.shutdown_and_wait().await;
    }

    /// FALSIFIER for bounded terminal-operation retention: once the exact
    /// one-use caller and latest-publication observer release a successful
    /// result, operation history must retain only its compact receipt. Keeping
    /// the complete published generation here also keeps normalized semantic
    /// provider payloads alive for every historical operation.
    #[tokio::test]
    async fn terminal_receipt_does_not_pin_complete_published_generation() {
        let (_temporary, supervisor, mut starts) = supervisor_fixture();
        let operation = supervisor
            .start_manual(IndexSupervisorRequest::default())
            .expect("start controlled manual operation");
        let operation_id = operation.operation_id();
        let probe = next_probe(&mut starts).await;
        probe.release.send(()).expect("release controlled run");

        let published = match operation.wait().await.expect("one-use operation result") {
            IndexOperationOutcome::Published(published) => published,
            other => panic!("controlled operation did not publish: {other:?}"),
        };
        let retained_generation = Arc::downgrade(&published);
        assert!(
            retained_generation.upgrade().is_some(),
            "positive control: the one-use caller owns the published generation"
        );
        let terminal = supervisor.snapshot(operation_id).expect("terminal receipt");
        assert_eq!(terminal.state, IndexOperationState::Succeeded);
        assert!(
            terminal.publication.is_some(),
            "positive control: bounded terminal publication facts remain available"
        );

        drop(published);
        drop(supervisor.inner.publication_updates.send_replace(None));
        assert!(
            retained_generation.upgrade().is_none(),
            "terminal operation history retained the complete published generation instead of only its bounded receipt"
        );
        assert!(
            supervisor
                .snapshot(operation_id)
                .expect("receipt after payload release")
                .publication
                .is_some(),
            "releasing heavyweight publication data must not erase the terminal receipt"
        );
        supervisor.shutdown_and_wait().await;
    }
}
