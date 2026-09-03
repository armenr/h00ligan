//! Immutable, store-free state presented to code-intelligence handlers.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use h00ligan_engine::code_intel_publication::{
    PublicationControlToken, PublicationError, PublicationRecovery, PublishedGeneration,
    ResolvedGeneration, publication_control_token, resolve_generation,
    revalidate_generation_database, validate_open_generation_authority,
};
use h00ligan_engine::graph::KnowledgeGraph;
use h00ligan_engine::graph_stats::IndexBaseline;
use h00ligan_engine::graph_store::{ClassifiedBy, GraphGenerationMetadata};
use h00ligan_engine::project_binding::ProjectBinding;
use h00ligan_engine::reachability::ReachabilityEvidence;
use h00ligan_engine::structural_ir::{SymbolRole, symbol_kind_has_role};
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;

#[cfg(test)]
type PublicationLoadHook = Box<dyn FnOnce() + Send + 'static>;

#[cfg(test)]
static PUBLICATION_LOAD_AFTER_RESOLVE_HOOK: std::sync::LazyLock<
    std::sync::Mutex<Option<(PathBuf, PublicationLoadHook)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
static PUBLICATION_LOAD_BEFORE_REVALIDATE_HOOK: std::sync::LazyLock<
    std::sync::Mutex<Option<(PathBuf, PublicationLoadHook)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
static REFRESH_BEFORE_COMMIT_HOOK: std::sync::LazyLock<
    std::sync::Mutex<Option<(String, PublicationLoadHook)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
fn run_publication_load_after_resolve_hook(database_path: &Path) {
    run_publication_load_hook(&PUBLICATION_LOAD_AFTER_RESOLVE_HOOK, database_path);
}

#[cfg(test)]
fn run_publication_load_before_revalidate_hook(database_path: &Path) {
    run_publication_load_hook(&PUBLICATION_LOAD_BEFORE_REVALIDATE_HOOK, database_path);
}

#[cfg(test)]
fn run_publication_load_hook(
    hook_slot: &std::sync::Mutex<Option<(PathBuf, PublicationLoadHook)>>,
    database_path: &Path,
) {
    let hook = {
        let mut slot = hook_slot.lock().expect("publication load test hook lock");
        if slot
            .as_ref()
            .is_some_and(|(expected_path, _)| expected_path == database_path)
        {
            slot.take().map(|(_, hook)| hook)
        } else {
            None
        }
    };
    if let Some(hook) = hook {
        hook();
    }
}

#[cfg(test)]
fn run_refresh_before_commit_hook(generation_id: &str) {
    let hook = {
        let mut slot = REFRESH_BEFORE_COMMIT_HOOK
            .lock()
            .expect("refresh test hook lock");
        if slot
            .as_ref()
            .is_some_and(|(expected_generation, _)| expected_generation == generation_id)
        {
            slot.take().map(|(_, hook)| hook)
        } else {
            None
        }
    };
    if let Some(hook) = hook {
        hook();
    }
}

/// How the process-wide graph load resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphLoadState {
    Unindexed,
    Loaded { origin: Option<PathBuf> },
    LoadFailed { error: String },
    OriginMismatch { stored: PathBuf, bound: PathBuf },
}

/// Per-capability state for generation-local reachability evidence.
///
/// A malformed or absent reachability document does not erase unrelated graph
/// and Calls capabilities from the same immutable generation. Reachability
/// itself still fails closed with this recorded reason.
#[derive(Debug, Clone)]
pub enum ReachabilityEvidenceState {
    Available(Arc<ReachabilityEvidence>),
    Unavailable { reason: Arc<str> },
}

impl Default for ReachabilityEvidenceState {
    fn default() -> Self {
        Self::Unavailable {
            reason: Arc::from("no persisted reachability evidence"),
        }
    }
}

impl ReachabilityEvidenceState {
    fn from_load(
        result: Result<Option<ReachabilityEvidence>, h00ligan_engine::graph_store::GraphStoreError>,
    ) -> Self {
        match result {
            Ok(Some(evidence)) => Self::Available(Arc::new(evidence)),
            Ok(None) => Self::default(),
            Err(error) => Self::Unavailable {
                reason: Arc::from(format!(
                    "persisted reachability evidence is invalid: {error}"
                )),
            },
        }
    }

    pub fn get(&self) -> Result<&ReachabilityEvidence, &str> {
        match self {
            Self::Available(evidence) => Ok(evidence),
            Self::Unavailable { reason } => Err(reason),
        }
    }
}

/// Exact per-file source content authority loaded from the immutable
/// generation's index-state table.
#[derive(Debug, Clone)]
pub enum IndexedSourceState {
    Available(Arc<h00ligan_engine::index_state::IndexedSourceSnapshot>),
    Unavailable { reason: Arc<str> },
}

impl Default for IndexedSourceState {
    fn default() -> Self {
        Self::Unavailable {
            reason: Arc::from("no persisted indexed-source snapshot"),
        }
    }
}

impl IndexedSourceState {
    pub fn authority(&self) -> Result<&h00ligan_engine::index_state::IndexedSourceSnapshot, &str> {
        match self {
            Self::Available(authority) => Ok(authority),
            Self::Unavailable { reason } => Err(reason),
        }
    }

    pub fn files(&self) -> Result<&[(String, h00ligan_engine::index_state::FileRecord)], &str> {
        self.authority()
            .map(h00ligan_engine::index_state::IndexedSourceSnapshot::files)
    }
}

/// One live observation currently owned by an immutable snapshot.
struct InFlightLiveInputObservation {
    id: u64,
    result: tokio::sync::watch::Sender<Option<h00ligan_engine::graph_stats::StalenessVerdict>>,
}

/// Snapshot-local coordination for exact live-input observations.
///
/// Only requests that overlap the same owned observation share work. The slot
/// is cleared before its result is published, so a later request cannot reuse
/// a completed freshness verdict. The producer is detached from every caller:
/// cancelling one CLI/MCP request neither cancels the shared observation nor
/// strands its peers.
#[derive(Default)]
struct LiveInputObservationCoordinator {
    state: tokio::sync::Mutex<Option<InFlightLiveInputObservation>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl LiveInputObservationCoordinator {
    async fn observe<F, Fut>(
        self: &Arc<Self>,
        fallback: h00ligan_engine::graph_stats::StalenessVerdict,
        observation: F,
    ) -> h00ligan_engine::graph_stats::StalenessVerdict
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: std::future::Future<Output = h00ligan_engine::graph_stats::StalenessVerdict>
            + Send
            + 'static,
    {
        let (mut result, launch) = {
            let mut state = self.state.lock().await;
            let launch = if state.is_none() {
                let id = self
                    .next_id
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (sender, _receiver) = tokio::sync::watch::channel(None);
                *state = Some(InFlightLiveInputObservation {
                    id,
                    result: sender.clone(),
                });
                Some((id, sender))
            } else {
                None
            };
            let result = state
                .as_ref()
                .expect("live-input coordinator initialized an in-flight slot")
                .result
                .subscribe();
            drop(state);
            (result, launch)
        };

        if let Some((id, sender)) = launch {
            let coordinator = Arc::clone(self);
            tokio::spawn(async move {
                // Isolate an unexpected observer panic from the shared slot.
                // Every waiter receives the explicit fail-closed fallback and
                // the next request remains able to start a new observation.
                let producer = tokio::spawn(async move { observation().await });
                let verdict = producer.await.unwrap_or(fallback);
                let publish = {
                    let mut state = coordinator.state.lock().await;
                    if state.as_ref().is_some_and(|in_flight| in_flight.id == id) {
                        *state = None;
                        true
                    } else {
                        false
                    }
                };
                if publish {
                    sender.send_replace(Some(verdict));
                }
            });
        }

        loop {
            let observed = *result.borrow_and_update();
            if let Some(verdict) = observed {
                return verdict;
            }
            if result.changed().await.is_err() {
                return fallback;
            }
        }
    }
}

/// One coherent loaded generation. Every handler clones one `Arc` before use.
#[derive(Clone)]
pub struct CodeIntelSnapshot {
    pub graph: Option<Arc<KnowledgeGraph>>,
    pub reachability_evidence: ReachabilityEvidenceState,
    /// Validated persisted authority that owns `graph`, when the process loaded
    /// an immutable publication rather than the transitional legacy bundle.
    pub semantic_generation: Option<Arc<ResolvedGeneration>>,
    query_index: Option<Arc<h00ligan_engine::code_intel_query_index::GenerationQueryIndex>>,
    project_inventory_witness:
        Option<Arc<h00ligan_engine::code_intel_inventory::ProjectInventoryWitness>>,
    live_input_observations: Arc<LiveInputObservationCoordinator>,
    pub publication_control_token: Option<PublicationControlToken>,
    pub load_state: GraphLoadState,
    pub index_baseline: IndexBaseline,
    pub indexed_sources: IndexedSourceState,
    pub generation_metadata: Option<GraphGenerationMetadata>,
}

/// Adapter-owned attachment point for live-input evidence. The engine use
/// cases remain deterministic over one immutable generation; the shipped
/// boundaries add the independently observed relation to the current
/// worktree without rewriting generation-scoped authority.
trait GenerationBoundResult {
    const OPERATION: &'static str;

    fn repository_mut(&mut self) -> &mut h00ligan_engine::code_intel_domain::RepositoryBinding;
    fn warnings_mut(&mut self) -> &mut Vec<String>;
}

macro_rules! generation_bound_result {
    ($result:ty, $operation:literal) => {
        impl GenerationBoundResult for $result {
            const OPERATION: &'static str = $operation;

            fn repository_mut(
                &mut self,
            ) -> &mut h00ligan_engine::code_intel_domain::RepositoryBinding {
                &mut self.repository
            }

            fn warnings_mut(&mut self) -> &mut Vec<String> {
                &mut self.warnings
            }
        }
    };
}

generation_bound_result!(h00ligan_engine::code_intel_find::ExactFindResult, "find");
generation_bound_result!(
    h00ligan_engine::code_intel_assess::ExactAssessResult,
    "assess"
);
generation_bound_result!(h00ligan_engine::code_intel_calls::ExactCallsResult, "calls");
generation_bound_result!(h00ligan_engine::code_intel_tests::ExactTestsResult, "tests");
generation_bound_result!(h00ligan_engine::code_intel_dead::ExactDeadResult, "dead");
generation_bound_result!(h00ligan_engine::code_intel_type::ExactTypeResult, "type");
generation_bound_result!(h00ligan_engine::code_intel_read::ExactReadResult, "read");
generation_bound_result!(
    h00ligan_engine::code_intel_overview::ExactOverviewResult,
    "overview"
);
generation_bound_result!(h00ligan_engine::code_intel_audit::ExactAuditResult, "audit");
generation_bound_result!(
    h00ligan_engine::code_intel_dependencies::ExactDependenciesResult,
    "dependencies"
);

impl GenerationBoundResult for h00ligan_engine::code_intel_inspect::ExactInspectResult {
    const OPERATION: &'static str = "inspect";

    fn repository_mut(&mut self) -> &mut h00ligan_engine::code_intel_domain::RepositoryBinding {
        &mut self.repository
    }

    fn warnings_mut(&mut self) -> &mut Vec<String> {
        &mut self.notices
    }
}

impl CodeIntelSnapshot {
    pub fn unindexed() -> Self {
        Self {
            graph: None,
            reachability_evidence: ReachabilityEvidenceState::default(),
            semantic_generation: None,
            query_index: None,
            project_inventory_witness: None,
            live_input_observations: Arc::new(LiveInputObservationCoordinator::default()),
            publication_control_token: None,
            load_state: GraphLoadState::Unindexed,
            index_baseline: IndexBaseline::default(),
            indexed_sources: IndexedSourceState::default(),
            generation_metadata: None,
        }
    }

    /// Preserve a failed publication load as health evidence instead of
    /// collapsing it into an indistinguishable unindexed state.
    pub fn load_failed(error: impl Into<String>) -> Self {
        let mut snapshot = Self::unindexed();
        snapshot.load_state = GraphLoadState::LoadFailed {
            error: error.into(),
        };
        snapshot
    }

    /// Whether this snapshot is a complete generation that can remain pinned
    /// while a newer on-disk candidate is being written or rejected.
    pub const fn is_queryable_generation(&self) -> bool {
        self.graph.is_some()
            && self.semantic_generation.is_some()
            && self.publication_control_token.is_some()
            && self.generation_metadata.is_some()
            && matches!(self.load_state, GraphLoadState::Loaded { .. })
    }

    pub fn immutable_generation(&self) -> Option<&ResolvedGeneration> {
        self.semantic_generation.as_deref()
    }

    pub const fn generation_metadata(&self) -> Option<&GraphGenerationMetadata> {
        self.generation_metadata.as_ref()
    }

    pub fn oracle_ran_ok(&self) -> Option<bool> {
        self.generation_metadata
            .as_ref()
            .map(|metadata| metadata.oracle_ran_ok)
    }

    pub fn classified_by(&self) -> Option<&ClassifiedBy> {
        self.generation_metadata
            .as_ref()
            .map(|metadata| &metadata.classified_by)
    }

    /// Produce the exact Status contract from this one coherent snapshot.
    pub async fn status_result(
        &self,
        binding: &ProjectBinding,
    ) -> h00ligan_engine::code_intel_status::ExactStatusResult {
        use h00ligan_engine::code_intel_status::{StatusObservation, StatusOriginMismatch};
        use h00ligan_engine::project_binding::{GraphSource, RootSource};

        let freshness = self.source_freshness(binding.root()).await;
        let generation = self.immutable_generation();
        let (load_error, origin_mismatch) = match &self.load_state {
            GraphLoadState::LoadFailed { error } => (Some(error.clone()), None),
            GraphLoadState::OriginMismatch { stored, bound } => (
                None,
                Some(StatusOriginMismatch {
                    stored: stored.clone(),
                    bound: bound.clone(),
                }),
            ),
            GraphLoadState::Unindexed | GraphLoadState::Loaded { .. } => (None, None),
        };
        let root_source = match binding.root_source() {
            RootSource::Explicit => "explicit",
            RootSource::Discovered => "discovered",
        };
        let graph_source = match binding.graph_source() {
            GraphSource::Cli => "cli",
            GraphSource::ProjectConfig => "project_config",
            GraphSource::UserConfig => "user_config",
            GraphSource::RepoDefault => "repo_default",
        };

        h00ligan_engine::code_intel_status::status_result(StatusObservation {
            root: binding.root(),
            graph_directory: binding.graph_dir(),
            root_source,
            graph_source,
            generation_id: generation.map(|value| value.manifest.generation_id.clone()),
            repository_id: generation.map(|value| value.manifest.repository_id.clone()),
            graph: self.graph.as_deref(),
            graph_exists: !matches!(self.load_state, GraphLoadState::Unindexed),
            load_error,
            origin_mismatch,
            freshness,
            indexed_at: self.index_baseline.baseline,
            incremental_drift: self.index_baseline.incremental_drift,
            calls: self.calls_coverage(),
            callable_liveness: self.callable_liveness_coverage(),
            classified_by: self.classified_by(),
            classification_authority_available: self.require_reachability_evidence().is_ok(),
        })
    }

    /// Verify the live selected source population, project inputs, provider
    /// inputs, and bytes against this immutable generation. Structural graph
    /// completeness is an independent authority axis: an unchanged source can
    /// be current even when one of its declaration shapes is not represented.
    /// Timestamps are never freshness authority.
    pub async fn source_freshness(
        &self,
        root: &Path,
    ) -> h00ligan_engine::graph_stats::StalenessVerdict {
        use h00ligan_engine::graph_stats::{StalenessReason, StalenessVerdict};

        let Some(generation) = self.immutable_generation() else {
            return StalenessVerdict::Unknown {
                reason: StalenessReason::IndexedSourceSnapshotUnavailable,
                files_checked: 0,
            };
        };
        let indexed_sources = match &self.indexed_sources {
            IndexedSourceState::Available(authority) => Arc::clone(authority),
            IndexedSourceState::Unavailable { .. } => {
                return StalenessVerdict::Unknown {
                    reason: StalenessReason::IndexedSourceSnapshotUnavailable,
                    files_checked: 0,
                };
            }
        };
        let files = indexed_sources.files();

        let root = root.to_path_buf();
        let Some(project_inventory_witness) = self.project_inventory_witness.as_ref().cloned()
        else {
            return StalenessVerdict::Unknown {
                reason: StalenessReason::SourceVerificationFailed,
                files_checked: files.len(),
            };
        };
        let expected_inventory = generation.project_inventory.clone();
        let expected_provider_payloads = generation.provider_payloads.clone();
        let fallback = StalenessVerdict::Unknown {
            reason: StalenessReason::SourceVerificationFailed,
            files_checked: 0,
        };
        self.live_input_observations
            .observe(fallback, move || async move {
                tokio::task::spawn_blocking(move || {
                    let observation_started = std::time::Instant::now();
                    let files = indexed_sources.files();
                    let source_started = std::time::Instant::now();
                    let Ok(freshness) =
                        h00ligan_engine::graph_stats::check_indexed_source_freshness(&root, files)
                    else {
                        tracing::trace!(
                            target: "h00ligan::live_inputs",
                            indexed_files = files.len(),
                            source_ms = source_started.elapsed().as_secs_f64() * 1_000.0,
                            total_ms = observation_started.elapsed().as_secs_f64() * 1_000.0,
                            "live-input source verification failed"
                        );
                        return StalenessVerdict::Unknown {
                            reason: StalenessReason::SourceVerificationFailed,
                            files_checked: 0,
                        };
                    };
                    let source_elapsed = source_started.elapsed();
                    if freshness != StalenessVerdict::Fresh {
                        tracing::trace!(
                            target: "h00ligan::live_inputs",
                            indexed_files = files.len(),
                            source_ms = source_elapsed.as_secs_f64() * 1_000.0,
                            total_ms = observation_started.elapsed().as_secs_f64() * 1_000.0,
                            verdict = ?freshness,
                            "live-input observation ended at source verification"
                        );
                        return freshness;
                    }
                    let inventory_started = std::time::Instant::now();
                    let inventory_freshness = project_inventory_witness.observe(&root);
                    let inventory_elapsed = inventory_started.elapsed();
                    if inventory_freshness
                        == h00ligan_engine::code_intel_inventory::ProjectInventoryFreshness::Stale
                    {
                        tracing::trace!(
                            target: "h00ligan::live_inputs",
                            indexed_files = files.len(),
                            project_inputs = expected_inventory.inputs.len(),
                            source_ms = source_elapsed.as_secs_f64() * 1_000.0,
                            inventory_ms = inventory_elapsed.as_secs_f64() * 1_000.0,
                            total_ms = observation_started.elapsed().as_secs_f64() * 1_000.0,
                            "live-input observation found project-inventory drift"
                        );
                        return StalenessVerdict::Stale;
                    }
                    let provider_started = std::time::Instant::now();
                    let verdict = match h00ligan_engine::code_intel_payload::provider_payload_semantic_paths_are_current(
                        &root,
                        &expected_provider_payloads,
                    ) {
                        Ok(true) => StalenessVerdict::Fresh,
                        Ok(false) => StalenessVerdict::Stale,
                        Err(_) => StalenessVerdict::Unknown {
                            reason: StalenessReason::ProviderSemanticInputsUnverifiable,
                            files_checked: files.len(),
                        },
                    };
                    let provider_elapsed = provider_started.elapsed();
                    tracing::trace!(
                        target: "h00ligan::live_inputs",
                        indexed_files = files.len(),
                        project_inputs = expected_inventory.inputs.len(),
                        provider_payloads = expected_provider_payloads.len(),
                        source_ms = source_elapsed.as_secs_f64() * 1_000.0,
                        inventory_ms = inventory_elapsed.as_secs_f64() * 1_000.0,
                        provider_ms = provider_elapsed.as_secs_f64() * 1_000.0,
                        total_ms = observation_started.elapsed().as_secs_f64() * 1_000.0,
                        verdict = ?verdict,
                        "live-input observation completed"
                    );
                    verdict
                })
                .await
                .unwrap_or(fallback)
            })
            .await
    }

    async fn observe_generation_result<T>(
        &self,
        binding: &ProjectBinding,
        mut result: T,
    ) -> Result<T, h00ligan_engine::code_intel_domain::DomainError>
    where
        T: GenerationBoundResult + serde::Serialize,
    {
        let observation = self.live_input_observation(binding).await;
        if let Some(qualification) = observation.generation_qualification() {
            result.warnings_mut().push(qualification);
        }
        result.repository_mut().live_inputs = Some(observation);
        let actual_chars = serde_json::to_string(&result)
            .map_err(|error| {
                h00ligan_engine::code_intel_domain::DomainError::PublishedGenerationInvalid {
                    reason: format!(
                        "serialize {} result after live-input observation: {error}",
                        T::OPERATION
                    ),
                }
            })?
            .chars()
            .count();
        let max_chars = h00ligan_engine::code_intel_domain::MAX_CODE_INTEL_RESULT_CHARS;
        if actual_chars > max_chars {
            return Err(
                h00ligan_engine::code_intel_domain::DomainError::result_too_large(
                    T::OPERATION,
                    actual_chars,
                    max_chars,
                    "Narrow the query scope or request fewer optional sections; if the smallest page still fails, required fixed metadata exceeds the product envelope",
                ),
            );
        }
        Ok(result)
    }

    /// Observe the current repository inputs relative to this immutable
    /// generation. This is also available to legacy projections while they
    /// are being replaced by shared exact result contracts.
    pub async fn live_input_observation(
        &self,
        binding: &ProjectBinding,
    ) -> h00ligan_engine::code_intel_domain::LiveInputObservation {
        let indexed_file_count = match &self.indexed_sources {
            IndexedSourceState::Available(authority) => authority.files().len(),
            IndexedSourceState::Unavailable { .. } => 0,
        };
        h00ligan_engine::code_intel_domain::LiveInputObservation::from_staleness(
            self.source_freshness(binding.root()).await,
            indexed_file_count,
        )
    }

    /// Calls coverage derived from this snapshot's immutable receipt and
    /// inventory authority, partitioned by the callable languages actually
    /// present in its graph.
    pub fn calls_coverage(&self) -> h00ligan_engine::code_intel_domain::CapabilityCoverage {
        use h00ligan_engine::code_intel_calls::assess_calls_capability;
        use h00ligan_engine::code_intel_domain::{
            CapabilityCoverage, CapabilityCoverageStatus, CapabilityEvidenceGap, CapabilityStatus,
            LanguageCapabilityCoverage, LanguageId,
        };

        if let (Some(graph), Some(generation)) =
            (self.graph.as_deref(), self.immutable_generation())
        {
            return assess_calls_capability(
                graph,
                &generation.manifest.receipts,
                &generation.provider_payloads,
                &generation.project_inventory,
            );
        }

        let languages = self
            .graph
            .iter()
            .flat_map(|graph| graph.all_nodes())
            .filter(|node| symbol_kind_has_role(&node.kind, SymbolRole::Callable))
            .filter_map(h00ligan_engine::graph_stats::node_language)
            .map(LanguageId::new)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|language_id| LanguageCapabilityCoverage {
                language_id,
                status: CapabilityCoverageStatus::Unavailable,
                provider_id: None,
                gaps: vec![CapabilityEvidenceGap {
                    provider_id: None,
                    status: CapabilityStatus::Unavailable,
                    reason_code: "immutable_generation_unavailable".into(),
                    reason: "no validated immutable generation carries Calls authority".into(),
                }],
                qualifications: Vec::new(),
            })
            .collect::<Vec<_>>();
        CapabilityCoverage {
            capability_id: "calls".into(),
            status: if languages.is_empty() {
                CapabilityCoverageStatus::NotApplicable
            } else {
                CapabilityCoverageStatus::Unavailable
            },
            languages,
        }
    }

    /// Compiler-native callable-liveness coverage carried by this exact
    /// immutable generation. The capability is currently applicable to Go;
    /// absence from an old or invalid generation remains explicit.
    pub fn callable_liveness_coverage(
        &self,
    ) -> h00ligan_engine::code_intel_domain::CapabilityCoverage {
        use h00ligan_engine::code_intel_callable_liveness::assess_callable_liveness_capability;
        use h00ligan_engine::code_intel_domain::{
            CapabilityCoverage, CapabilityCoverageStatus, CapabilityEvidenceGap, CapabilityStatus,
            LanguageCapabilityCoverage, LanguageId,
        };

        if let (Some(graph), Some(generation)) =
            (self.graph.as_deref(), self.immutable_generation())
        {
            return assess_callable_liveness_capability(
                graph,
                &generation.manifest.receipts,
                &generation.provider_payloads,
                &generation.project_inventory,
            );
        }

        let languages = self
            .graph
            .iter()
            .flat_map(|graph| graph.all_nodes())
            .filter_map(h00ligan_engine::graph_stats::node_language)
            .filter(|language| *language == "go")
            .map(LanguageId::new)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|language_id| LanguageCapabilityCoverage {
                language_id,
                status: CapabilityCoverageStatus::Unavailable,
                provider_id: None,
                gaps: vec![CapabilityEvidenceGap {
                    provider_id: None,
                    status: CapabilityStatus::Unavailable,
                    reason_code: "immutable_generation_unavailable".into(),
                    reason: "no validated immutable generation carries callable-liveness authority"
                        .into(),
                }],
                qualifications: Vec::new(),
            })
            .collect::<Vec<_>>();
        CapabilityCoverage {
            capability_id: "callable_liveness".into(),
            status: if languages.is_empty() {
                CapabilityCoverageStatus::NotApplicable
            } else {
                CapabilityCoverageStatus::Unavailable
            },
            languages,
        }
    }

    /// Require generation-local reachability evidence without consulting live
    /// manifests or reconstructing a weaker report from graph nodes.
    pub fn require_reachability_evidence(&self) -> Result<&ReachabilityEvidence, &str> {
        self.reachability_evidence.get()
    }

    fn structural_query_parts(
        &self,
    ) -> Result<
        (&KnowledgeGraph, &ResolvedGeneration),
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let unavailable =
            |reason: String| {
                h00ligan_engine::code_intel_domain::DomainError::CapabilityUnavailable {
                    capability: "structural_graph".into(),
                    evidence: vec![h00ligan_engine::code_intel_domain::CapabilityEvidenceGap {
                        provider_id: None,
                        status: h00ligan_engine::code_intel_domain::CapabilityStatus::Unavailable,
                        reason_code: "immutable_generation_unavailable".into(),
                        reason: reason.clone(),
                    }],
                    reason,
                    scopes: vec![h00ligan_engine::code_intel_domain::CapabilityScope::Repository {
                    configuration_id: h00ligan_engine::code_intel_domain::ConfigurationId::new(
                        h00ligan_engine::code_intel_domain::STRUCTURAL_GRAPH_CONFIGURATION_ID,
                    ),
                }],
                }
            };
        let graph = self.graph.as_deref().ok_or_else(|| {
            unavailable(match &self.load_state {
                GraphLoadState::Unindexed => "no published structural generation".into(),
                GraphLoadState::LoadFailed { error } => error.clone(),
                GraphLoadState::OriginMismatch { stored, bound } => format!(
                    "published graph origin {} does not match {}",
                    stored.display(),
                    bound.display()
                ),
                GraphLoadState::Loaded { .. } => "published generation has no graph".into(),
            })
        })?;
        let generation = self.semantic_generation.as_deref().ok_or_else(|| {
            unavailable(
                "no validated immutable generation carries structural receipts and inventory"
                    .into(),
            )
        })?;
        Ok((graph, generation))
    }

    fn calls_query_parts(
        &self,
    ) -> Result<
        (&KnowledgeGraph, &ResolvedGeneration),
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let unavailable = |reason: String| {
            h00ligan_engine::code_intel_domain::DomainError::CapabilityUnavailable {
                capability: "calls".into(),
                evidence: vec![h00ligan_engine::code_intel_domain::CapabilityEvidenceGap {
                    provider_id: None,
                    status: h00ligan_engine::code_intel_domain::CapabilityStatus::Unavailable,
                    reason_code: "immutable_generation_unavailable".into(),
                    reason: reason.clone(),
                }],
                reason,
                scopes: vec![
                    h00ligan_engine::code_intel_domain::CapabilityScope::Repository {
                        configuration_id: h00ligan_engine::code_intel_domain::ConfigurationId::new(
                            h00ligan_engine::code_intel_domain::CALLS_CONFIGURATION_ID,
                        ),
                    },
                ],
            }
        };
        let graph = self.graph.as_deref().ok_or_else(|| {
            unavailable(match &self.load_state {
                GraphLoadState::Unindexed => "no published semantic generation".into(),
                GraphLoadState::LoadFailed { error } => error.clone(),
                GraphLoadState::OriginMismatch { stored, bound } => format!(
                    "published graph origin {} does not match {}",
                    stored.display(),
                    bound.display()
                ),
                GraphLoadState::Loaded { .. } => "published generation has no graph".into(),
            })
        })?;
        let generation = self.semantic_generation.as_deref().ok_or_else(|| {
            unavailable(
                "no validated immutable generation carries scoped Calls receipts and payloads"
                    .into(),
            )
        })?;
        Ok((graph, generation))
    }

    /// Execute the exact Calls use case over the graph and authority pinned in
    /// this one process snapshot. No adapter can substitute a live manifest,
    /// legacy success bit, or graph-only relationship population.
    pub async fn query_calls(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_domain::CallsRequest,
    ) -> Result<
        h00ligan_engine::code_intel_calls::ExactCallsResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let (graph, generation) = self.calls_query_parts()?;
        let result = match self.query_index.as_deref() {
            Some(index) => index.query_calls(binding, request)?,
            None => h00ligan_engine::code_intel_calls::query_published_calls(
                graph, generation, binding, request,
            )?,
        };
        self.observe_generation_result(binding, result).await
    }

    /// Execute provider-backed test-root reachability over the same immutable
    /// Calls population used by `query_calls`. Test classification comes from
    /// the co-published structural graph; adapters cannot substitute legacy
    /// relationship edges or independent coverage heuristics.
    pub async fn query_tests(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_tests::TestsRequest,
    ) -> Result<
        h00ligan_engine::code_intel_tests::ExactTestsResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let (graph, generation) = self.calls_query_parts()?;
        let result = match self.query_index.as_deref() {
            Some(index) => h00ligan_engine::code_intel_tests::query_published_tests_indexed(
                index, binding, request,
            )?,
            None => h00ligan_engine::code_intel_tests::query_published_tests(
                graph, generation, binding, request,
            )?,
        };
        self.observe_generation_result(binding, result).await
    }

    /// Execute the shared authority-qualified change-impact use case over this
    /// process's immutable graph and semantic generation.
    pub async fn query_assess(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_assess::AssessRequest,
    ) -> Result<
        h00ligan_engine::code_intel_assess::ExactAssessResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let (graph, generation) = self.structural_query_parts()?;
        let result = match self.query_index.as_deref() {
            Some(index) => h00ligan_engine::code_intel_assess::query_published_assess_indexed(
                index, binding, request,
            )?,
            None => h00ligan_engine::code_intel_assess::query_published_assess(
                graph, generation, binding, request,
            )?,
        };
        self.observe_generation_result(binding, result).await
    }

    /// Execute the shared Dead v1 use case over one immutable graph,
    /// generation, and generation-bound reachability document. Missing or
    /// malformed reachability evidence withholds the capability rather than
    /// falling back to bare persisted node labels.
    pub async fn query_dead(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_dead::DeadRequest,
    ) -> Result<
        h00ligan_engine::code_intel_dead::ExactDeadResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let (graph, generation) = self.structural_query_parts()?;
        let reachability =
            self.require_reachability_evidence().map_err(|reason| {
                h00ligan_engine::code_intel_domain::DomainError::CapabilityUnavailable {
                    capability: "dead".into(),
                    reason: reason.into(),
                    scopes: vec![h00ligan_engine::code_intel_domain::CapabilityScope::Repository {
                    configuration_id: h00ligan_engine::code_intel_domain::ConfigurationId::new(
                        h00ligan_engine::code_intel_domain::STRUCTURAL_GRAPH_CONFIGURATION_ID,
                    ),
                }],
                    evidence: vec![h00ligan_engine::code_intel_domain::CapabilityEvidenceGap {
                        provider_id: None,
                        status: h00ligan_engine::code_intel_domain::CapabilityStatus::Unavailable,
                        reason_code: "reachability_evidence_unavailable".into(),
                        reason: reason.into(),
                    }],
                }
            })?;
        let result = h00ligan_engine::code_intel_dead::query_published_dead(
            graph,
            generation,
            binding,
            reachability,
            request,
        )?;
        self.observe_generation_result(binding, result).await
    }

    /// Compose the bounded Inspect dossier from this process's one immutable
    /// graph, semantic generation, and indexed-source population. Individual
    /// facets invoke the same engine use cases as their standalone tools.
    pub async fn query_inspect(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_inspect::InspectRequest,
    ) -> Result<
        h00ligan_engine::code_intel_inspect::ExactInspectResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let (graph, generation) = self.structural_query_parts()?;
        let indexed_sources = self.indexed_sources.files();
        let result = match self.query_index.as_deref() {
            Some(index) => {
                h00ligan_engine::code_intel_inspect::query_published_inspect_indexed(
                    index,
                    binding,
                    indexed_sources,
                    request,
                )
                .await?
            }
            None => {
                h00ligan_engine::code_intel_inspect::query_published_inspect(
                    graph,
                    generation,
                    binding,
                    indexed_sources,
                    request,
                )
                .await?
            }
        };
        self.observe_generation_result(binding, result).await
    }

    /// Execute the shared structural Type use case over the same graph,
    /// manifest, inventory, and generation identity pinned in this snapshot.
    pub async fn query_type(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_domain::TypeRequest,
    ) -> Result<
        h00ligan_engine::code_intel_type::ExactTypeResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let (graph, generation) = self.structural_query_parts()?;
        let result = h00ligan_engine::code_intel_type::query_published_type(
            graph, generation, binding, request,
        )?;
        self.observe_generation_result(binding, result).await
    }

    /// Execute the shared generation-bound Find use case. Mode resolution,
    /// authority, ordering, and continuation all live below the adapters.
    pub async fn query_find(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_find::FindRequest,
    ) -> Result<
        h00ligan_engine::code_intel_find::ExactFindResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let (graph, generation) = self.structural_query_parts()?;
        let result = h00ligan_engine::code_intel_find::query_published_find(
            graph, generation, binding, request,
        )?;
        self.observe_generation_result(binding, result).await
    }

    /// Execute the shared bounded Read use case over one pinned graph,
    /// generation, and indexed-source population.
    pub async fn query_read(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_read::ReadRequest,
    ) -> Result<
        h00ligan_engine::code_intel_read::ExactReadResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let (graph, generation) = self.structural_query_parts()?;
        let indexed_sources = self.indexed_sources.files();
        let result = h00ligan_engine::code_intel_read::query_published_read(
            graph,
            generation,
            binding,
            indexed_sources,
            request,
        )
        .await?;
        self.observe_generation_result(binding, result).await
    }

    /// Execute the shared architecture overview and attach the same live-input
    /// observation used by every other generation-bound query surface.
    pub async fn query_overview(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_overview::OverviewRequest,
    ) -> Result<
        h00ligan_engine::code_intel_overview::ExactOverviewResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let (graph, generation) = self.structural_query_parts()?;
        let result = h00ligan_engine::code_intel_overview::query_published_overview(
            graph,
            generation,
            binding,
            self.reachability_evidence.get().ok(),
            request,
        )?;
        self.observe_generation_result(binding, result).await
    }

    /// Execute the shared scoped Audit use case and attach the same live-input
    /// observation used by every other generation-bound query surface.
    pub async fn query_audit(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_audit::AuditRequest,
    ) -> Result<
        h00ligan_engine::code_intel_audit::ExactAuditResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let (graph, generation) = self.structural_query_parts()?;
        let result = h00ligan_engine::code_intel_audit::query_published_audit(
            graph,
            generation,
            binding,
            self.reachability_evidence.get().ok(),
            request,
        )?;
        self.observe_generation_result(binding, result).await
    }

    /// Execute the shared direct-dependency projection with one attached
    /// live-input observation rather than adapter-specific freshness prose.
    pub async fn query_dependencies(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_dependencies::DependenciesRequest,
    ) -> Result<
        h00ligan_engine::code_intel_dependencies::ExactDependenciesResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        let (graph, generation) = self.structural_query_parts()?;
        let result = h00ligan_engine::code_intel_dependencies::query_published_dependencies(
            graph, generation, binding, request,
        )?;
        self.observe_generation_result(binding, result).await
    }

    /// Compare this one pinned immutable structural generation with the live
    /// worktree. The snapshot owns the complete baseline authority join and
    /// blocking-task lifecycle so CLI and MCP cannot assemble subtly different
    /// graph, generation, or indexed-source populations.
    ///
    /// Unlike generation-bound queries, Diff already reports its live
    /// candidate authority and per-file non-atomic consistency explicitly. It
    /// therefore does not attach the separate generation live-input witness.
    pub async fn query_diff(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_diff::DiffRequest,
    ) -> Result<
        h00ligan_engine::code_intel_diff::ExactDiffResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        self.structural_query_parts()?;

        let snapshot = self.clone();
        let binding = binding.clone();
        let request = request.clone();
        tokio::task::spawn_blocking(move || {
            let (graph, generation) = snapshot.structural_query_parts()?;
            h00ligan_engine::code_intel_diff::query_live_diff(
                graph,
                generation,
                &binding,
                snapshot.indexed_sources.authority(),
                request,
            )
        })
        .await
        .map_err(|error| {
            h00ligan_engine::code_intel_domain::DomainError::CandidateObservationFailed {
                operation: "diff",
                reason: format!("diff task join: {error}"),
            }
        })?
    }

    /// Execute live, ignore-aware source search and bind graph context from
    /// this snapshot's exact immutable generation. The snapshot owns both the
    /// blocking task boundary and the search/generation join so CLI and MCP
    /// cannot drift in path normalization, indexed-source authority, or error
    /// classification.
    pub async fn query_source_search(
        &self,
        binding: &ProjectBinding,
        request: &h00ligan_engine::code_intel_source_search::SourceSearchRequest,
    ) -> Result<
        h00ligan_engine::code_intel_source_search::ExactSourceSearchResult,
        h00ligan_engine::code_intel_domain::DomainError,
    > {
        h00ligan_engine::code_intel_source_search::validate_source_search_request(request)?;
        self.structural_query_parts()?;

        let search_root = binding
            .resolve_existing_path(Path::new(&request.path))
            .map_err(|error| {
                h00ligan_engine::code_intel_domain::DomainError::SourcePath(error.to_string())
            })?;
        let relative_path = search_root
            .strip_prefix(binding.root())
            .map_err(|error| {
                h00ligan_engine::code_intel_domain::DomainError::SourcePath(error.to_string())
            })?
            .to_string_lossy()
            .replace('\\', "/");
        let mut request = request.clone();
        request.path = if relative_path.is_empty() {
            ".".into()
        } else {
            relative_path
        };

        let snapshot = self.clone();
        let binding = binding.clone();
        tokio::task::spawn_blocking(move || {
            let (graph, generation) = snapshot.structural_query_parts()?;
            let report = h00ligan_engine::source_search::search_registered_source(
                &binding,
                &search_root,
                h00ligan_engine::source_search::SourcePattern::Regex(&request.pattern),
                h00ligan_engine::code_intel_source_search::SourceSearchOptions {
                    max_matches: request.limit,
                    max_matches_per_file: request.limit,
                    context_lines: request.context_lines,
                },
            )
            .map_err(|error| {
                h00ligan_engine::code_intel_domain::DomainError::CandidateObservationFailed {
                    operation: "source_search",
                    reason: error,
                }
            })?;
            h00ligan_engine::code_intel_source_search::bind_source_search_result(
                graph,
                generation,
                &binding,
                snapshot.indexed_sources.files(),
                request,
                report,
            )
        })
        .await
        .map_err(|error| {
            h00ligan_engine::code_intel_domain::DomainError::CandidateObservationFailed {
                operation: "source_search",
                reason: format!("source-search task join: {error}"),
            }
        })?
    }

    /// Load one coherent generation without creating either redb file.
    pub async fn load(binding: &ProjectBinding) -> Result<Self, CodeIntelLoadError> {
        Self::load_tracked(binding)
            .await
            .map(|(snapshot, _)| snapshot)
    }

    async fn load_tracked(
        binding: &ProjectBinding,
    ) -> Result<(Self, SnapshotFingerprint), CodeIntelLoadError> {
        match capture_snapshot_fingerprint(binding)? {
            SnapshotFingerprint::Publication(control) => {
                Self::load_publication_tracked(binding, control).await
            }
            SnapshotFingerprint::Unpublished => {
                Ok((Self::unindexed(), SnapshotFingerprint::Unpublished))
            }
        }
    }

    async fn load_publication_tracked(
        binding: &ProjectBinding,
        control_before: PublicationControlToken,
    ) -> Result<(Self, SnapshotFingerprint), CodeIntelLoadError> {
        let graph_directory = binding.graph_dir().to_path_buf();
        let repository_root = binding.root().to_path_buf();
        let resolved = tokio::task::spawn_blocking(move || {
            resolve_generation(&graph_directory, &repository_root)
        })
        .await
        .map_err(|error| CodeIntelLoadError::PublicationTask(error.to_string()))?
        .map_err(|error| CodeIntelLoadError::Publication(error.to_string()))?;

        #[cfg(test)]
        run_publication_load_after_resolve_hook(&resolved.database_path);

        let database_path = resolved.database_path.clone();
        let open_path = database_path.clone();
        let database = tokio::task::spawn_blocking(move || redb::ReadOnlyDatabase::open(open_path))
            .await
            .map_err(|error| CodeIntelLoadError::PublicationTask(error.to_string()))?
            .map_err(|error| CodeIntelLoadError::Publication(error.to_string()))?;
        let database = Arc::new(database);
        let validation_root = binding.root().to_path_buf();
        let (opened, resolved) = tokio::task::spawn_blocking(move || {
            let opened = validate_open_generation_authority(database, &resolved, &validation_root)?;
            Ok::<_, PublicationError>((opened, resolved))
        })
        .await
        .map_err(|error| CodeIntelLoadError::PublicationTask(error.to_string()))?
        .map_err(|error| CodeIntelLoadError::Publication(error.to_string()))?;
        let graph = opened.graph;
        let origin = Some(opened.origin);
        let generation_metadata = opened.generation_metadata;
        let reachability_evidence =
            ReachabilityEvidenceState::from_load(opened.reachability_evidence);
        let indexed_sources = IndexedSourceState::Available(Arc::new(opened.indexed_sources));
        let index_baseline =
            opened
                .index_metadata
                .as_ref()
                .map_or_else(IndexBaseline::default, |metadata| IndexBaseline {
                    baseline: metadata
                        .last_update
                        .or(metadata.last_full_scan)
                        .and_then(|millis| u64::try_from(millis).ok())
                        .map(|millis| {
                            std::time::SystemTime::UNIX_EPOCH + Duration::from_millis(millis)
                        }),
                    incremental_drift: matches!(
                        (metadata.last_update, metadata.last_full_scan),
                        (Some(update), Some(full)) if update > full
                    ),
                });

        #[cfg(test)]
        run_publication_load_before_revalidate_hook(&resolved.database_path);

        let resolved = tokio::task::spawn_blocking(move || {
            revalidate_generation_database(&resolved)?;
            Ok::<_, PublicationError>(resolved)
        })
        .await
        .map_err(|error| CodeIntelLoadError::PublicationTask(error.to_string()))?
        .map_err(|error| CodeIntelLoadError::Publication(error.to_string()))?;

        let control_after = publication_control_token(binding.graph_dir(), binding.root())
            .map_err(|error| CodeIntelLoadError::Publication(error.to_string()))?;
        if control_before != control_after {
            return Err(CodeIntelLoadError::PublicationChanged {
                graph_dir: binding.graph_dir().to_path_buf(),
            });
        }
        let resolved = Arc::new(resolved);
        let graph = Arc::new(graph);
        let query_index = Arc::new(
            h00ligan_engine::code_intel_query_index::GenerationQueryIndex::new(
                Arc::clone(&graph),
                Arc::clone(&resolved),
            ),
        );
        let project_inventory_sources = indexed_sources
            .files()
            .expect("validated generation owns an indexed-source snapshot")
            .iter()
            .map(|(path, record)| {
                h00ligan_engine::code_intel_inventory::InventorySource::new(path, &record.language)
            })
            .collect::<Vec<_>>();
        let project_inventory_witness = Arc::new(
            h00ligan_engine::code_intel_inventory::ProjectInventoryWitness::new(
                project_inventory_sources,
                Arc::clone(&resolved.project_inventory),
            ),
        );
        Ok((
            Self {
                graph: Some(graph),
                reachability_evidence,
                semantic_generation: Some(resolved),
                query_index: Some(query_index),
                project_inventory_witness: Some(project_inventory_witness),
                live_input_observations: Arc::new(LiveInputObservationCoordinator::default()),
                publication_control_token: Some(control_after.clone()),
                load_state: GraphLoadState::Loaded { origin },
                index_baseline,
                indexed_sources,
                generation_metadata: Some(generation_metadata),
            },
            SnapshotFingerprint::Publication(control_after),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SnapshotFingerprint {
    Publication(PublicationControlToken),
    Unpublished,
}

fn capture_snapshot_fingerprint(
    binding: &ProjectBinding,
) -> Result<SnapshotFingerprint, CodeIntelLoadError> {
    match publication_control_token(binding.graph_dir(), binding.root()) {
        Ok(control) => Ok(SnapshotFingerprint::Publication(control)),
        Err(PublicationError::Unpublished { .. }) => Ok(SnapshotFingerprint::Unpublished),
        Err(error) => Err(CodeIntelLoadError::Publication(error.to_string())),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CodeIntelLoadError {
    #[error("graph metadata load failed: {0}")]
    Metadata(String),
    #[error("semantic publication load failed: {0}")]
    Publication(String),
    #[error("semantic publication load task failed: {0}")]
    PublicationTask(String),
    #[error("semantic publication changed while loading {graph_dir}; retry the request")]
    PublicationChanged { graph_dir: PathBuf },
    #[error("refusing to replace the last good code-intelligence snapshot: {0}")]
    RefreshRejected(String),
    #[error(
        "published generation {expected} was not the exact generation loaded by the process (observed {observed})"
    )]
    PublishedGenerationMismatch { expected: String, observed: String },
}

struct SnapshotSlot {
    snapshot: Arc<CodeIntelSnapshot>,
    fingerprint: Option<SnapshotFingerprint>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum IndexWatchControlError {
    #[error("code-intelligence WATCH is already running for this MCP process")]
    AlreadyRunning,
    #[error("code-intelligence WATCH is still stopping for this MCP process")]
    Stopping,
    #[error("code-intelligence WATCH failed: {0}")]
    Watcher(#[from] h00ligan_engine::watcher::WatcherError),
    #[error("code-intelligence WATCH stop task failed: {0}")]
    StopTask(String),
}

enum IndexWatchLifecycle {
    Stopped,
    Running(h00ligan_engine::watcher::IndexWatchService),
    Stopping(h00ligan_engine::watcher::IndexWatchStatus),
}

struct SharedIndexWatch {
    lifecycle: tokio::sync::Mutex<IndexWatchLifecycle>,
    changed: tokio::sync::Notify,
}

/// Process-wide code-intelligence authority. It deliberately has no store.
pub struct CodeIntelContext {
    binding: ProjectBinding,
    cancel_token: CancellationToken,
    slot: Arc<RwLock<SnapshotSlot>>,
    index_supervisor: Arc<h00ligan_engine::code_intel_supervisor::IndexSupervisor>,
    index_watch: Arc<SharedIndexWatch>,
}

fn new_index_supervisor(
    binding: &ProjectBinding,
) -> Arc<h00ligan_engine::code_intel_supervisor::IndexSupervisor> {
    Arc::new(h00ligan_engine::code_intel_supervisor::IndexSupervisor::new(binding.clone()))
}

fn new_index_watch() -> Arc<SharedIndexWatch> {
    Arc::new(SharedIndexWatch {
        lifecycle: tokio::sync::Mutex::new(IndexWatchLifecycle::Stopped),
        changed: tokio::sync::Notify::new(),
    })
}

impl CodeIntelContext {
    /// Construct an unloaded context. The first request resolves the bound
    /// publication; callers cannot seed semantic graph or authority state.
    pub fn unloaded(binding: ProjectBinding, cancel_token: CancellationToken) -> Self {
        let index_supervisor = new_index_supervisor(&binding);
        Self::unloaded_with_supervisor(binding, cancel_token, index_supervisor)
    }

    pub fn unloaded_with_supervisor(
        binding: ProjectBinding,
        cancel_token: CancellationToken,
        index_supervisor: Arc<h00ligan_engine::code_intel_supervisor::IndexSupervisor>,
    ) -> Self {
        Self {
            binding,
            cancel_token,
            slot: Arc::new(RwLock::new(SnapshotSlot {
                snapshot: Arc::new(CodeIntelSnapshot::unindexed()),
                fingerprint: None,
            })),
            index_supervisor,
            index_watch: new_index_watch(),
        }
    }

    /// Construct a context that retains a failed startup load for `status`
    /// while leaving explicit publication recovery reachable.
    pub fn load_failed(
        binding: ProjectBinding,
        cancel_token: CancellationToken,
        error: impl Into<String>,
    ) -> Self {
        let index_supervisor = new_index_supervisor(&binding);
        Self::load_failed_with_supervisor(binding, cancel_token, error, index_supervisor)
    }

    pub fn load_failed_with_supervisor(
        binding: ProjectBinding,
        cancel_token: CancellationToken,
        error: impl Into<String>,
        index_supervisor: Arc<h00ligan_engine::code_intel_supervisor::IndexSupervisor>,
    ) -> Self {
        Self {
            binding,
            cancel_token,
            slot: Arc::new(RwLock::new(SnapshotSlot {
                snapshot: Arc::new(CodeIntelSnapshot::load_failed(error)),
                fingerprint: None,
            })),
            index_supervisor,
            index_watch: new_index_watch(),
        }
    }

    /// Unit-test-only constructor for focused handler fixtures that do not
    /// cross adapter admission. Production and integration boundaries must
    /// load a real immutable publication.
    #[cfg(all(test, feature = "code-intel"))]
    pub(crate) fn from_test_snapshot(
        binding: ProjectBinding,
        cancel_token: CancellationToken,
        snapshot: Arc<CodeIntelSnapshot>,
    ) -> Self {
        let index_supervisor = new_index_supervisor(&binding);
        Self {
            binding,
            cancel_token,
            slot: Arc::new(RwLock::new(SnapshotSlot {
                snapshot,
                fingerprint: None,
            })),
            index_supervisor,
            index_watch: new_index_watch(),
        }
    }

    /// Load the initial process snapshot and its exact bundle fingerprint as
    /// one tracked generation.
    pub async fn load(
        binding: ProjectBinding,
        cancel_token: CancellationToken,
    ) -> Result<Self, CodeIntelLoadError> {
        let index_supervisor = new_index_supervisor(&binding);
        Self::load_with_supervisor(binding, cancel_token, index_supervisor).await
    }

    pub async fn load_with_supervisor(
        binding: ProjectBinding,
        cancel_token: CancellationToken,
        index_supervisor: Arc<h00ligan_engine::code_intel_supervisor::IndexSupervisor>,
    ) -> Result<Self, CodeIntelLoadError> {
        let (snapshot, fingerprint) = CodeIntelSnapshot::load_tracked(&binding).await?;
        Ok(Self {
            binding,
            cancel_token,
            slot: Arc::new(RwLock::new(SnapshotSlot {
                snapshot: Arc::new(snapshot),
                fingerprint: Some(fingerprint),
            })),
            index_supervisor,
            index_watch: new_index_watch(),
        })
    }

    pub const fn binding(&self) -> &ProjectBinding {
        &self.binding
    }

    pub const fn cancel_token(&self) -> &CancellationToken {
        &self.cancel_token
    }

    pub(crate) const fn index_supervisor(
        &self,
    ) -> &Arc<h00ligan_engine::code_intel_supervisor::IndexSupervisor> {
        &self.index_supervisor
    }

    pub(crate) async fn start_index_watch(
        &self,
        request: h00ligan_engine::code_intel_supervisor::IndexSupervisorRequest,
        debounce_ms: u64,
        publication_probe_interval: Duration,
        reconciliation_interval: Duration,
    ) -> Result<h00ligan_engine::watcher::IndexWatchStatus, IndexWatchControlError> {
        let mut lifecycle = self.index_watch.lifecycle.lock().await;
        match &*lifecycle {
            IndexWatchLifecycle::Stopped => {}
            IndexWatchLifecycle::Running(_) => {
                return Err(IndexWatchControlError::AlreadyRunning);
            }
            IndexWatchLifecycle::Stopping(_) => {
                return Err(IndexWatchControlError::Stopping);
            }
        }
        let config = h00ligan_engine::watcher::WatcherConfig::new(
            self.binding.root().to_path_buf(),
            debounce_ms,
        )
        .exclude_root(self.binding.graph_dir().to_path_buf());
        let service = h00ligan_engine::watcher::IndexWatchService::start(
            self.index_supervisor.as_ref().clone(),
            config,
            request,
            h00ligan_engine::watcher::WatchCadence::new(
                publication_probe_interval,
                reconciliation_interval,
            ),
        )?;
        let status = service.status();
        *lifecycle = IndexWatchLifecycle::Running(service);
        drop(lifecycle);
        Ok(status)
    }

    pub(crate) async fn index_watch_status(
        &self,
    ) -> Option<h00ligan_engine::watcher::IndexWatchStatus> {
        match &*self.index_watch.lifecycle.lock().await {
            IndexWatchLifecycle::Stopped => None,
            IndexWatchLifecycle::Running(service) => Some(service.status()),
            IndexWatchLifecycle::Stopping(status) => Some(status.clone()),
        }
    }

    pub(crate) async fn stop_index_watch(
        &self,
    ) -> Result<Option<h00ligan_engine::watcher::IndexWatchStatus>, IndexWatchControlError> {
        enum StopAction {
            AlreadyStopped,
            Wait,
            Stop(h00ligan_engine::watcher::IndexWatchService),
        }

        loop {
            let changed = self.index_watch.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();

            let action = {
                let mut lifecycle = self.index_watch.lifecycle.lock().await;
                let action = match std::mem::replace(&mut *lifecycle, IndexWatchLifecycle::Stopped)
                {
                    IndexWatchLifecycle::Stopped => StopAction::AlreadyStopped,
                    IndexWatchLifecycle::Stopping(status) => {
                        *lifecycle = IndexWatchLifecycle::Stopping(status);
                        StopAction::Wait
                    }
                    IndexWatchLifecycle::Running(service) => {
                        let mut status = service.status();
                        status.running = false;
                        *lifecycle = IndexWatchLifecycle::Stopping(status);
                        StopAction::Stop(service)
                    }
                };
                drop(lifecycle);
                action
            };

            let service = match action {
                StopAction::AlreadyStopped => return Ok(None),
                StopAction::Wait => {
                    changed.await;
                    continue;
                }
                StopAction::Stop(service) => service,
            };

            // Finish the transition in an owned task. Cancelling the MCP
            // request must not strand the shared lifecycle in `Stopping` or
            // leak an active watcher.
            let shared = Arc::clone(&self.index_watch);
            let stop_task = tokio::spawn(async move {
                let result = service.stop().await;
                *shared.lifecycle.lock().await = IndexWatchLifecycle::Stopped;
                shared.changed.notify_waiters();
                result
            });
            return stop_task
                .await
                .map_err(|error| IndexWatchControlError::StopTask(error.to_string()))?
                .map(Some)
                .map_err(Into::into);
        }
    }

    pub(crate) async fn shutdown_indexing(&self) -> Result<(), IndexWatchControlError> {
        let watch_result = self.stop_index_watch().await;
        self.index_supervisor.shutdown_and_wait().await;
        watch_result.map(|_| ())
    }

    pub fn snapshot(&self) -> Arc<CodeIntelSnapshot> {
        Arc::clone(&self.slot.read().snapshot)
    }

    /// Observe the current publication for Status without replacing a pinned
    /// last-good query snapshot with failed candidate state.
    pub async fn status_snapshot(&self) -> Arc<CodeIntelSnapshot> {
        self.refresh_if_changed()
            .await
            .unwrap_or_else(|error| Arc::new(CodeIntelSnapshot::load_failed(error.to_string())))
    }

    /// Resolve the on-disk publication for the next request. A clean changed
    /// bundle is loaded and atomically swapped; an incomplete or unreadable
    /// candidate never replaces the last good snapshot.
    pub async fn refresh_if_changed(&self) -> Result<Arc<CodeIntelSnapshot>, CodeIntelLoadError> {
        let observed = capture_snapshot_fingerprint(&self.binding)?;
        {
            let current = self.slot.read();
            if current.fingerprint.as_ref() == Some(&observed) {
                return Ok(Arc::clone(&current.snapshot));
            }
        }

        let (replacement, loaded_fingerprint) =
            CodeIntelSnapshot::load_tracked(&self.binding).await?;
        if let GraphLoadState::LoadFailed { error } = &replacement.load_state {
            return Err(CodeIntelLoadError::RefreshRejected(error.clone()));
        }
        let replacement_rejection =
            (!replacement.is_queryable_generation()).then(|| match &replacement.load_state {
                GraphLoadState::Unindexed => {
                    "candidate contains no published graph generation".into()
                }
                GraphLoadState::Loaded { .. } => {
                    "candidate metadata says loaded but carries no queryable graph".into()
                }
                GraphLoadState::OriginMismatch { stored, bound } => format!(
                    "candidate origin {} does not match {}",
                    stored.display(),
                    bound.display()
                ),
                GraphLoadState::LoadFailed { error } => error.clone(),
            });
        let confirmed = capture_snapshot_fingerprint(&self.binding)?;
        if confirmed != loaded_fingerprint {
            return Err(CodeIntelLoadError::PublicationChanged {
                graph_dir: self.binding.graph_dir().to_path_buf(),
            });
        }

        #[cfg(test)]
        if let Some(generation) = replacement.semantic_generation.as_deref() {
            run_refresh_before_commit_hook(&generation.manifest.generation_id.0);
        }

        let mut current = self.slot.write();
        if current.fingerprint.as_ref() == Some(&confirmed) {
            return Ok(Arc::clone(&current.snapshot));
        }
        if let (Some(current_generation), Some(replacement_generation)) = (
            current.snapshot.semantic_generation.as_deref(),
            replacement.semantic_generation.as_deref(),
        ) {
            let current_sequence = current_generation.head.body.sequence;
            let replacement_sequence = replacement_generation.head.body.sequence;
            if replacement_sequence < current_sequence {
                return Ok(Arc::clone(&current.snapshot));
            }
            if replacement_sequence == current_sequence
                && replacement_generation.manifest.generation_id
                    != current_generation.manifest.generation_id
            {
                return Err(CodeIntelLoadError::RefreshRejected(format!(
                    "immutable sequence {current_sequence} identifies both generation {} and {}",
                    current_generation.manifest.generation_id,
                    replacement_generation.manifest.generation_id,
                )));
            }
        }
        if current.snapshot.semantic_generation.is_some()
            && replacement.semantic_generation.is_none()
        {
            return Err(CodeIntelLoadError::RefreshRejected(
                "candidate would downgrade immutable generation authority to unpublished state"
                    .into(),
            ));
        }
        if current.snapshot.is_queryable_generation()
            && let Some(reason) = replacement_rejection
        {
            return Err(CodeIntelLoadError::RefreshRejected(reason));
        }
        current.snapshot = Arc::new(replacement);
        current.fingerprint = Some(confirmed);
        Ok(Arc::clone(&current.snapshot))
    }

    /// Load and atomically install the exact generation returned by a
    /// successful publisher.
    ///
    /// Ordinary publication retains monotonic sequence protection. Explicit
    /// recovery establishes a newly validated authority epoch and may restart
    /// its local head sequence; its exact manifest, head, database path, and
    /// final control fingerprint must still match before process authority is
    /// replaced.
    pub async fn install_published_generation(
        &self,
        expected: &PublishedGeneration,
        recovery: PublicationRecovery,
    ) -> Result<Arc<CodeIntelSnapshot>, CodeIntelLoadError> {
        let (replacement, loaded_fingerprint) =
            CodeIntelSnapshot::load_tracked(&self.binding).await?;
        let actual = replacement.semantic_generation.as_deref().ok_or_else(|| {
            CodeIntelLoadError::PublishedGenerationMismatch {
                expected: expected.manifest.generation_id.0.clone(),
                observed: "unpublished".into(),
            }
        })?;
        if actual.manifest != expected.manifest
            || actual.head != expected.head
            || actual.database_path != expected.database_path
            || !replacement.is_queryable_generation()
        {
            return Err(CodeIntelLoadError::PublishedGenerationMismatch {
                expected: expected.manifest.generation_id.0.clone(),
                observed: actual.manifest.generation_id.0.clone(),
            });
        }

        let mut current = self.slot.write();
        let confirmed = capture_snapshot_fingerprint(&self.binding)?;
        if confirmed != loaded_fingerprint {
            return Err(CodeIntelLoadError::PublicationChanged {
                graph_dir: self.binding.graph_dir().to_path_buf(),
            });
        }
        if current.fingerprint.as_ref() == Some(&confirmed) {
            let installed = current
                .snapshot
                .immutable_generation()
                .map(|generation| generation.manifest.generation_id.0.as_str());
            if installed == Some(expected.manifest.generation_id.0.as_str()) {
                return Ok(Arc::clone(&current.snapshot));
            }
            return Err(CodeIntelLoadError::PublishedGenerationMismatch {
                expected: expected.manifest.generation_id.0.clone(),
                observed: installed.unwrap_or("unpublished").to_owned(),
            });
        }

        if recovery == PublicationRecovery::Strict
            && let Some(current_generation) = current.snapshot.immutable_generation()
        {
            let current_sequence = current_generation.head.body.sequence;
            let replacement_sequence = actual.head.body.sequence;
            if replacement_sequence < current_sequence {
                return Err(CodeIntelLoadError::RefreshRejected(format!(
                    "refusing to install published sequence {replacement_sequence} behind live sequence {current_sequence}"
                )));
            }
            if replacement_sequence == current_sequence
                && actual.manifest.generation_id != current_generation.manifest.generation_id
            {
                return Err(CodeIntelLoadError::RefreshRejected(format!(
                    "immutable sequence {current_sequence} identifies both generation {} and {}",
                    current_generation.manifest.generation_id, actual.manifest.generation_id,
                )));
            }
        }

        current.snapshot = Arc::new(replacement);
        current.fingerprint = Some(confirmed);
        Ok(Arc::clone(&current.snapshot))
    }

    /// Share the same binding/snapshot authority with a request-scoped token.
    pub fn with_cancellation(&self, cancel_token: CancellationToken) -> Self {
        Self {
            binding: self.binding.clone(),
            cancel_token,
            slot: Arc::clone(&self.slot),
            index_supervisor: Arc::clone(&self.index_supervisor),
            index_watch: Arc::clone(&self.index_watch),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;
    use h00ligan_engine::code_intel_domain::{
        CapabilityScope, CapabilityStatus, ProjectInventory, ProjectInventoryCoverage,
    };
    use h00ligan_engine::code_intel_indexing::{BoundIndexPlan, BoundIndexRequest};
    use h00ligan_engine::code_intel_publication::{
        GenerationDraft, PUBLICATION_DIRECTORY, PublishedGeneration, SemanticPublisher,
    };
    use h00ligan_engine::graph::GraphNode;
    use h00ligan_engine::graph_store::{GraphGenerationMetadata, GraphStore};
    use h00ligan_engine::reachability::ReachabilityClass;

    #[derive(Debug, serde::Serialize)]
    struct ProductEnvelopeProbe {
        repository: h00ligan_engine::code_intel_domain::RepositoryBinding,
        warnings: Vec<String>,
        payload: String,
    }

    impl GenerationBoundResult for ProductEnvelopeProbe {
        const OPERATION: &'static str = "product_envelope_probe";

        fn repository_mut(&mut self) -> &mut h00ligan_engine::code_intel_domain::RepositoryBinding {
            &mut self.repository
        }

        fn warnings_mut(&mut self) -> &mut Vec<String> {
            &mut self.warnings
        }
    }

    fn product_envelope_probe(payload_chars: usize) -> ProductEnvelopeProbe {
        ProductEnvelopeProbe {
            repository: h00ligan_engine::code_intel_domain::RepositoryBinding {
                repository_id: h00ligan_engine::code_intel_domain::RepositoryId::new(
                    "product-envelope-probe",
                ),
                root_label: "repository".into(),
                live_inputs: None,
            },
            warnings: Vec::new(),
            payload: "x".repeat(payload_chars),
        }
    }

    /// FALSIFIER for machine-surface parity: both CLI JSON and MCP consume
    /// this snapshot boundary, so no successful generation result may leave
    /// it above the product envelope and become an MCP-only transport error.
    #[tokio::test]
    async fn generation_result_bound_is_owned_before_transport_dispatch() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        let snapshot = CodeIntelSnapshot::unindexed();

        let small = snapshot
            .observe_generation_result(&binding, product_envelope_probe(16))
            .await
            .expect("known-positive bounded result");
        assert!(small.repository.live_inputs.is_some());

        let error = snapshot
            .observe_generation_result(
                &binding,
                product_envelope_probe(
                    h00ligan_engine::code_intel_domain::MAX_CODE_INTEL_RESULT_CHARS + 1,
                ),
            )
            .await
            .expect_err("oversized result must fail before either transport sees it");
        let h00ligan_engine::code_intel_domain::DomainError::ResultTooLarge {
            operation,
            actual_chars,
            max_chars,
            ..
        } = &error
        else {
            panic!("expected typed result bound, got {error}");
        };
        assert_eq!(*operation, "product_envelope_probe");
        assert!(*actual_chars > *max_chars, "positive oversize control");
        let envelope = serde_json::to_value(error.envelope()).expect("typed error envelope");
        assert_eq!(envelope["error"]["code"], "result_too_large");
        assert_eq!(envelope["error"]["actual_chars"], *actual_chars);
        assert_eq!(envelope["error"]["max_chars"], *max_chars);
    }

    /// FALSIFIER: requests that overlap one exact live observation may share
    /// that work, but a request arriving after completion must observe again.
    /// The first caller's cancellation is covered separately because shared
    /// work must be owned by the snapshot rather than by any one request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_input_observation_shares_only_simultaneous_work() {
        use h00ligan_engine::graph_stats::{StalenessReason, StalenessVerdict};

        let coordinator = Arc::new(LiveInputObservationCoordinator::default());
        let executions = Arc::new(AtomicUsize::new(0));
        let first_started = Arc::new(tokio::sync::Notify::new());
        let (release_first, release_first_receiver) = tokio::sync::oneshot::channel();
        let fallback = StalenessVerdict::Unknown {
            reason: StalenessReason::SourceVerificationFailed,
            files_checked: 0,
        };

        let first = {
            let coordinator = Arc::clone(&coordinator);
            let executions = Arc::clone(&executions);
            let first_started = Arc::clone(&first_started);
            tokio::spawn(async move {
                coordinator
                    .observe(fallback, move || async move {
                        executions.fetch_add(1, Ordering::SeqCst);
                        first_started.notify_one();
                        release_first_receiver
                            .await
                            .expect("test owns the first observation release");
                        StalenessVerdict::Fresh
                    })
                    .await
            })
        };
        first_started.notified().await;

        let second = {
            let coordinator = Arc::clone(&coordinator);
            let executions = Arc::clone(&executions);
            tokio::spawn(async move {
                coordinator
                    .observe(fallback, move || async move {
                        executions.fetch_add(1, Ordering::SeqCst);
                        StalenessVerdict::Stale
                    })
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let joined = coordinator
                    .state
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|in_flight| in_flight.result.receiver_count() == 2);
                if joined {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the overlapping waiter must join the in-flight observation");
        release_first
            .send(())
            .expect("release the first observation exactly once");
        let second = second.await.expect("second observation request");
        let first = first.await.expect("first observation request");

        assert_eq!(first, StalenessVerdict::Fresh);
        assert_eq!(
            second,
            StalenessVerdict::Fresh,
            "the overlapping request must join the already-running exact observation"
        );
        assert_eq!(
            executions.load(Ordering::SeqCst),
            1,
            "one in-flight observation must execute exactly once"
        );

        let third = coordinator
            .observe(fallback, {
                let executions = Arc::clone(&executions);
                move || async move {
                    executions.fetch_add(1, Ordering::SeqCst);
                    StalenessVerdict::Stale
                }
            })
            .await;
        assert_eq!(third, StalenessVerdict::Stale);
        assert_eq!(
            executions.load(Ordering::SeqCst),
            2,
            "a completed result must never become a freshness cache entry"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_input_observation_survives_one_waiter_cancellation() {
        use h00ligan_engine::graph_stats::{StalenessReason, StalenessVerdict};

        let coordinator = Arc::new(LiveInputObservationCoordinator::default());
        let executions = Arc::new(AtomicUsize::new(0));
        let producer_started = Arc::new(tokio::sync::Notify::new());
        let (release_producer, release_producer_receiver) = tokio::sync::oneshot::channel();
        let fallback = StalenessVerdict::Unknown {
            reason: StalenessReason::SourceVerificationFailed,
            files_checked: 0,
        };

        let cancelled_waiter = {
            let coordinator = Arc::clone(&coordinator);
            let executions = Arc::clone(&executions);
            let producer_started = Arc::clone(&producer_started);
            tokio::spawn(async move {
                coordinator
                    .observe(fallback, move || async move {
                        executions.fetch_add(1, Ordering::SeqCst);
                        producer_started.notify_one();
                        release_producer_receiver
                            .await
                            .expect("test owns the producer release");
                        StalenessVerdict::Fresh
                    })
                    .await
            })
        };
        producer_started.notified().await;
        cancelled_waiter.abort();
        assert!(
            cancelled_waiter
                .await
                .expect_err("request must be cancelled")
                .is_cancelled(),
            "positive request-cancellation control"
        );

        let surviving_waiter = {
            let coordinator = Arc::clone(&coordinator);
            let executions = Arc::clone(&executions);
            tokio::spawn(async move {
                coordinator
                    .observe(fallback, move || async move {
                        executions.fetch_add(1, Ordering::SeqCst);
                        StalenessVerdict::Stale
                    })
                    .await
            })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let joined = coordinator
                    .state
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|in_flight| in_flight.result.receiver_count() == 1);
                if joined {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("surviving waiter must join the in-flight observation");
        release_producer
            .send(())
            .expect("release the snapshot-owned observation exactly once");

        assert_eq!(
            surviving_waiter.await.expect("surviving request"),
            StalenessVerdict::Fresh,
            "request cancellation must not revoke snapshot-owned work"
        );
        assert_eq!(
            executions.load(Ordering::SeqCst),
            1,
            "the surviving waiter must join rather than restart the observation"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn live_input_observation_panic_fails_closed_and_releases_the_next_request() {
        use h00ligan_engine::graph_stats::{StalenessReason, StalenessVerdict};

        let coordinator = Arc::new(LiveInputObservationCoordinator::default());
        let fallback = StalenessVerdict::Unknown {
            reason: StalenessReason::SourceVerificationFailed,
            files_checked: 0,
        };
        let failed = coordinator
            .observe(fallback, || async move {
                panic!("intentional live-observation crash boundary")
            })
            .await;
        assert_eq!(failed, fallback, "observer crash must fail closed");

        let recovered = coordinator
            .observe(fallback, || async move { StalenessVerdict::Fresh })
            .await;
        assert_eq!(
            recovered,
            StalenessVerdict::Fresh,
            "a failed producer must not strand the snapshot's in-flight slot"
        );
    }

    fn test_binding(temporary: &TempDir) -> ProjectBinding {
        let root = temporary.path().join("repo");
        let graph_dir = temporary.path().join("bundle");
        std::fs::create_dir_all(&root).expect("repository root");
        std::fs::create_dir_all(&graph_dir).expect("graph directory");
        ProjectBinding::explicit(&root, &graph_dir).expect("test project binding")
    }

    fn graph_with_symbol(symbol: &str) -> KnowledgeGraph {
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(GraphNode {
                memory_id: Uuid::new_v4(),
                symbol_name: symbol.into(),
                kind: "Function".into(),
                file_path: "src/lib.rs".into(),
                content_hash: format!("hash:{symbol}"),
                signature: String::new(),
                reachability_class: ReachabilityClass::Wired,
                line_start: None,
                line_end: None,
                has_body: Some(true),
                visibility: "pub".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("graph node");
        graph
    }

    /// FALSIFIER: input currency and graph completeness are independent axes.
    /// The indexer persists the exact bytes of every discovered source even
    /// when one declaration shape is not represented structurally. An
    /// unchanged macro-bearing source must therefore remain `Fresh` while its
    /// structural receipt independently remains `Partial`.
    #[tokio::test]
    async fn structural_capture_gap_does_not_obscure_exact_source_freshness() {
        use h00ligan_engine::graph_stats::StalenessVerdict;

        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        std::fs::create_dir_all(binding.root().join("src")).expect("source directory");
        std::fs::write(
            binding.root().join("Cargo.toml"),
            "[package]\nname = \"freshness-axes\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        std::fs::write(
            binding.root().join("src/lib.rs"),
            "macro_rules! generate { ($name:ident) => { pub struct $name; } }\n\
             generate!(Generated);\n\
             pub fn indexed_anchor() {}\n",
        )
        .expect("macro-bearing source");

        BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("bound structural index")
            .publish()
            .await
            .expect("published structural generation");
        let snapshot = CodeIntelSnapshot::load(&binding)
            .await
            .expect("load immutable generation");
        let generation = snapshot
            .immutable_generation()
            .expect("generation authority");
        let structural = generation
            .manifest
            .receipts
            .iter()
            .find(|receipt| {
                receipt.capability_id == "structural_graph"
                    && matches!(
                        &receipt.scope,
                        CapabilityScope::Language { language_id, .. }
                            if language_id.0 == "rust"
                    )
            })
            .expect("Rust structural receipt");
        assert_eq!(
            structural.status,
            CapabilityStatus::Partial,
            "positive control: the source must retain an actual structural gap"
        );
        assert_eq!(
            structural.reason_code.as_deref(),
            Some("structural_capture_incomplete")
        );
        assert_eq!(
            generation.project_inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            "positive control: every indexed document still has exact ownership"
        );
        assert_eq!(
            snapshot
                .indexed_sources
                .files()
                .expect("persisted indexed-source authority")
                .len(),
            1,
            "positive control: the macro-bearing file must retain byte authority"
        );

        assert_eq!(
            snapshot.source_freshness(binding.root()).await,
            StalenessVerdict::Fresh,
            "an incomplete graph cannot obscure an exact unchanged source population"
        );
    }

    async fn publish(binding: &ProjectBinding, graph: &KnowledgeGraph) {
        let database =
            redb::Database::create(binding.graph_dir().join("graph.redb")).expect("graph database");
        let store = h00ligan_engine::graph_store::GraphStore::new(Arc::new(database));
        store
            .save_snapshot(graph)
            .await
            .expect("save graph snapshot");
        store
            .set_origin(binding.root())
            .await
            .expect("stamp graph origin");
        store
            .set_generation_metadata(GraphGenerationMetadata::now(false))
            .await
            .expect("stamp complete graph metadata");
    }

    async fn publish_with_invalid_reachability(binding: &ProjectBinding, graph: &KnowledgeGraph) {
        let mut publisher = SemanticPublisher::acquire(binding.graph_dir(), binding.root())
            .expect("semantic publisher");
        let workspace = publisher.begin_generation().expect("generation workspace");
        let database = workspace.database();
        let store = GraphStore::new(Arc::clone(&database));
        store
            .save_snapshot(graph)
            .await
            .expect("save graph snapshot");
        store
            .set_origin(binding.root())
            .await
            .expect("stamp graph origin");
        store
            .set_generation_metadata(GraphGenerationMetadata::now(false))
            .await
            .expect("stamp complete generation metadata");
        let transaction = database.begin_write().expect("evidence transaction");
        {
            let definition: redb::TableDefinition<&str, &[u8]> =
                redb::TableDefinition::new("graph_reachability_evidence");
            let mut table = transaction
                .open_table(definition)
                .expect("reachability evidence table");
            table
                .insert("latest", b"{not-json".as_slice())
                .expect("invalid reachability evidence");
        }
        transaction.commit().expect("commit invalid evidence");
        drop(store);
        drop(database);
        publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("invalid-reachability-test".into()),
                    project_inventory: ProjectInventory {
                        coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
                        project_topology: h00ligan_engine::code_intel_domain::ProjectTopology {
                            units: Vec::new(),
                            memberships: Vec::new(),
                            relationships: Vec::new(),
                            exact_workspace_member_sets: Vec::new(),
                            dependency_graphs: Vec::new(),
                        },
                        analysis_context_graphs: Vec::new(),
                        inputs: Vec::new(),
                        issues: Vec::new(),
                    },
                    receipts: Vec::new(),
                    provider_payloads: Vec::new(),
                },
            )
            .expect("publish immutable graph with invalid optional evidence");
    }

    async fn publish_immutable(
        binding: &ProjectBinding,
        graph: &KnowledgeGraph,
    ) -> PublishedGeneration {
        let mut publisher = SemanticPublisher::acquire(binding.graph_dir(), binding.root())
            .expect("semantic publisher");
        let workspace = publisher.begin_generation().expect("generation workspace");
        let store = GraphStore::new(workspace.database());
        store
            .save_snapshot(graph)
            .await
            .expect("save immutable graph snapshot");
        store
            .set_origin(binding.root())
            .await
            .expect("stamp immutable graph origin");
        store
            .set_generation_metadata(GraphGenerationMetadata::now(false))
            .await
            .expect("stamp complete immutable metadata");
        drop(store);
        publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("snapshot-test".into()),
                    project_inventory: ProjectInventory {
                        coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
                        project_topology: h00ligan_engine::code_intel_domain::ProjectTopology {
                            units: Vec::new(),
                            memberships: Vec::new(),
                            relationships: Vec::new(),
                            exact_workspace_member_sets: Vec::new(),
                            dependency_graphs: Vec::new(),
                        },
                        analysis_context_graphs: Vec::new(),
                        inputs: Vec::new(),
                        issues: Vec::new(),
                    },
                    receipts: Vec::new(),
                    provider_payloads: Vec::new(),
                },
            )
            .expect("publish immutable graph generation")
    }

    #[tokio::test]
    async fn legacy_bundle_is_not_query_authority_but_immutable_publication_is() {
        let legacy_temporary = TempDir::new().expect("legacy temporary directory");
        let legacy_binding = test_binding(&legacy_temporary);
        publish(&legacy_binding, &graph_with_symbol("legacy_only")).await;

        let legacy = CodeIntelSnapshot::load(&legacy_binding)
            .await
            .expect("legacy artifacts are an unpublished state, not a loader failure");
        assert!(
            !legacy.is_queryable_generation(),
            "root-level graph.redb/index.redb must not become semantic query authority"
        );
        assert!(
            legacy.graph.is_none(),
            "an unpublished legacy graph must not enter the process snapshot"
        );
        assert!(legacy.immutable_generation().is_none());

        let mut synthetic = CodeIntelSnapshot::unindexed();
        synthetic.graph = Some(Arc::new(graph_with_symbol("synthetic")));
        synthetic.load_state = GraphLoadState::Loaded {
            origin: Some(legacy_binding.root().to_path_buf()),
        };
        assert!(
            !synthetic.is_queryable_generation(),
            "an arbitrary in-memory graph cannot manufacture publication authority"
        );

        let published_temporary = TempDir::new().expect("published temporary directory");
        let published_binding = test_binding(&published_temporary);
        publish_immutable(&published_binding, &graph_with_symbol("published")).await;

        let published = CodeIntelSnapshot::load(&published_binding)
            .await
            .expect("immutable publication load");
        assert!(
            published.is_queryable_generation(),
            "positive control: the immutable publication must remain queryable"
        );
        assert!(published.immutable_generation().is_some());
        assert!(
            published
                .graph
                .as_deref()
                .is_some_and(|graph| graph.node_by_name("published").is_some()),
            "positive control: the exact co-published graph must load"
        );
    }

    #[tokio::test]
    async fn unchanged_fingerprint_returns_the_same_snapshot_arc() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        publish_immutable(&binding, &graph_with_symbol("first")).await;
        let context = CodeIntelContext::load(binding, CancellationToken::new())
            .await
            .expect("initial context");
        let before = context.snapshot();

        let refreshed = context.refresh_if_changed().await.expect("no-op refresh");
        assert!(
            Arc::ptr_eq(&before, &refreshed),
            "an unchanged publication must not churn the process snapshot"
        );
    }

    #[tokio::test]
    async fn invalid_reachability_evidence_does_not_erase_other_snapshot_capabilities() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        publish_with_invalid_reachability(&binding, &graph_with_symbol("still_available")).await;

        let snapshot = CodeIntelSnapshot::load(&binding)
            .await
            .expect("invalid optional evidence must not reject the whole snapshot");
        let graph = snapshot
            .graph
            .as_deref()
            .expect("unrelated graph capability remains available");
        assert!(
            graph
                .all_nodes()
                .iter()
                .any(|node| node.symbol_name == "still_available"),
            "positive control: the independently loaded graph must remain queryable"
        );
        let reason = snapshot
            .require_reachability_evidence()
            .expect_err("reachability itself must fail closed");
        assert!(reason.contains("persisted reachability evidence is invalid"));
        assert!(
            snapshot.immutable_generation().is_some(),
            "invalid optional reachability evidence must not erase generation authority"
        );
    }

    #[tokio::test]
    async fn clean_changed_publication_atomically_replaces_the_snapshot() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        publish_immutable(&binding, &graph_with_symbol("first")).await;
        let context = CodeIntelContext::load(binding.clone(), CancellationToken::new())
            .await
            .expect("initial context");
        let before = context.snapshot();
        assert!(
            before
                .graph
                .as_deref()
                .is_some_and(|graph| graph.node_by_name("first").is_some())
        );

        publish_immutable(&binding, &graph_with_symbol("second")).await;
        let refreshed = context.refresh_if_changed().await.expect("clean refresh");
        assert!(!Arc::ptr_eq(&before, &refreshed));
        let graph = refreshed.graph.as_deref().expect("reloaded graph");
        assert!(graph.node_by_name("second").is_some());
        assert!(graph.node_by_name("first").is_none());
        assert!(Arc::ptr_eq(&refreshed, &context.snapshot()));
    }

    #[tokio::test]
    async fn immutable_head_reload_swaps_one_generation_and_its_control_token() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        let first_publication = publish_immutable(&binding, &graph_with_symbol("first")).await;
        let context = CodeIntelContext::load(binding.clone(), CancellationToken::new())
            .await
            .expect("initial immutable context");
        let before = context.snapshot();
        assert_eq!(
            before
                .immutable_generation()
                .expect("resolved immutable generation")
                .manifest
                .generation_id,
            first_publication.manifest.generation_id
        );
        let control_before = publication_control_token(binding.graph_dir(), binding.root())
            .expect("initial publication control");
        assert_eq!(
            before.publication_control_token.as_ref(),
            Some(&control_before)
        );

        let second_publication = publish_immutable(&binding, &graph_with_symbol("second")).await;
        let control_after = publication_control_token(binding.graph_dir(), binding.root())
            .expect("changed publication control");
        assert_ne!(control_before, control_after);
        let refreshed = context
            .refresh_if_changed()
            .await
            .expect("valid immutable refresh");

        assert!(!Arc::ptr_eq(&before, &refreshed));
        assert_eq!(
            refreshed
                .immutable_generation()
                .expect("reloaded immutable generation")
                .manifest
                .generation_id,
            second_publication.manifest.generation_id
        );
        assert_eq!(
            refreshed.publication_control_token.as_ref(),
            Some(&control_after)
        );
        let graph = refreshed.graph.as_deref().expect("reloaded graph");
        assert!(graph.node_by_name("second").is_some());
        assert!(graph.node_by_name("first").is_none());
    }

    #[tokio::test]
    async fn immutable_private_workspace_does_not_revoke_the_last_good_snapshot() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        publish_immutable(&binding, &graph_with_symbol("last_good")).await;
        let context = CodeIntelContext::load(binding.clone(), CancellationToken::new())
            .await
            .expect("initial immutable context");
        let before = context.snapshot();

        let publisher = SemanticPublisher::acquire(binding.graph_dir(), binding.root())
            .expect("candidate publisher");
        let _workspace = publisher
            .begin_generation()
            .expect("private candidate workspace");
        let refreshed = context
            .refresh_if_changed()
            .await
            .expect("private staging is not a publication");

        assert!(Arc::ptr_eq(&before, &refreshed));
        assert!(
            refreshed
                .graph
                .as_deref()
                .is_some_and(|graph| graph.node_by_name("last_good").is_some())
        );
    }

    #[tokio::test]
    async fn rejected_immutable_head_resolves_to_the_last_good_generation() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        let initial = publish_immutable(&binding, &graph_with_symbol("last_good")).await;
        let context = CodeIntelContext::load(binding.clone(), CancellationToken::new())
            .await
            .expect("initial immutable context");

        let candidate = publish_immutable(&binding, &graph_with_symbol("rejected")).await;
        let held_database = candidate.database_path.with_extension("redb.held");
        std::fs::rename(&candidate.database_path, &held_database).expect("hold candidate database");
        std::fs::write(&candidate.database_path, b"not a redb database")
            .expect("corrupt candidate database");
        let refreshed = context
            .refresh_if_changed()
            .await
            .expect("resolver falls back to the last valid immutable head");
        std::fs::remove_file(&candidate.database_path).expect("remove corrupt candidate");
        std::fs::rename(&held_database, &candidate.database_path)
            .expect("restore candidate database");

        assert_eq!(
            refreshed
                .immutable_generation()
                .expect("retained immutable generation")
                .manifest
                .generation_id,
            initial.manifest.generation_id
        );
        assert!(
            refreshed
                .graph
                .as_deref()
                .is_some_and(|graph| graph.node_by_name("last_good").is_some())
        );
        assert!(
            refreshed
                .graph
                .as_deref()
                .is_some_and(|graph| graph.node_by_name("rejected").is_none())
        );

        let unchanged = context
            .refresh_if_changed()
            .await
            .expect("restoring rejected bytes in place does not create a new publication");
        assert!(
            Arc::ptr_eq(&refreshed, &unchanged),
            "an unchanged head token must keep the validated fallback pinned"
        );

        let replacement = publish_immutable(&binding, &graph_with_symbol("replacement")).await;
        let advanced = context
            .refresh_if_changed()
            .await
            .expect("a newly published head advances beyond the fallback");
        assert_eq!(
            advanced
                .immutable_generation()
                .expect("replacement generation")
                .manifest
                .generation_id,
            replacement.manifest.generation_id
        );
    }

    #[tokio::test]
    async fn immutable_snapshot_refuses_a_legacy_bundle_downgrade() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        publish_immutable(&binding, &graph_with_symbol("immutable")).await;
        let context = CodeIntelContext::load(binding.clone(), CancellationToken::new())
            .await
            .expect("initial immutable context");
        let before = context.snapshot();

        let publication_directory = binding.graph_dir().join(PUBLICATION_DIRECTORY);
        let held_publication = temporary.path().join("held-publication");
        std::fs::rename(&publication_directory, &held_publication)
            .expect("hold immutable publication aside");
        publish(&binding, &graph_with_symbol("legacy")).await;
        let error = match context.refresh_if_changed().await {
            Ok(_) => panic!("immutable authority must not downgrade to the legacy bundle"),
            Err(error) => error,
        };
        std::fs::rename(&held_publication, &publication_directory)
            .expect("restore immutable publication");

        assert!(matches!(error, CodeIntelLoadError::RefreshRejected(_)));
        let retained = context.snapshot();
        assert!(Arc::ptr_eq(&before, &retained));
        assert!(retained.semantic_generation.is_some());
        assert!(
            retained
                .graph
                .as_deref()
                .is_some_and(|graph| graph.node_by_name("immutable").is_some())
        );
    }

    #[tokio::test]
    async fn immutable_loader_rejects_database_replaced_after_resolution() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        let published = publish_immutable(&binding, &graph_with_symbol("resolved")).await;
        let original_bytes =
            std::fs::read(&published.database_path).expect("original immutable generation bytes");

        let positive = CodeIntelSnapshot::load(&binding)
            .await
            .expect("positive immutable load control");
        assert!(
            positive
                .graph
                .as_deref()
                .is_some_and(|graph| graph.node_by_name("resolved").is_some())
        );

        let alternate_path = temporary.path().join("alternate.redb");
        let alternate_database =
            redb::Database::create(&alternate_path).expect("alternate redb database");
        let alternate_store = GraphStore::new(Arc::new(alternate_database));
        alternate_store
            .save_snapshot(&graph_with_symbol("substituted"))
            .await
            .expect("alternate graph snapshot");
        alternate_store
            .set_origin(binding.root())
            .await
            .expect("alternate graph origin");
        alternate_store
            .set_generation_metadata(GraphGenerationMetadata::now(false))
            .await
            .expect("alternate graph metadata");
        drop(alternate_store);

        let held_original = temporary.path().join("held-original.redb");
        let published_path = published.database_path.clone();
        let hook_published_path = published_path.clone();
        let hook_held_original = held_original.clone();
        let hook_alternate_path = alternate_path.clone();
        *PUBLICATION_LOAD_AFTER_RESOLVE_HOOK
            .lock()
            .expect("install publication load test hook") = Some((
            published_path.clone(),
            Box::new(move || {
                std::fs::rename(&hook_published_path, &hook_held_original)
                    .expect("hold resolved generation after validation");
                std::fs::rename(&hook_alternate_path, &hook_published_path)
                    .expect("substitute another valid graph database");
            }),
        ));

        let loaded = CodeIntelSnapshot::load(&binding).await;
        let substituted_after = temporary.path().join("substituted-after.redb");
        std::fs::rename(&published_path, &substituted_after)
            .expect("remove substituted generation after load");
        std::fs::rename(&held_original, &published_path)
            .expect("restore resolved immutable generation");
        assert_eq!(
            std::fs::read(&published_path).expect("restored immutable generation"),
            original_bytes
        );

        match loaded {
            Err(
                CodeIntelLoadError::Publication(_) | CodeIntelLoadError::PublicationChanged { .. },
            ) => {}
            Err(error) => panic!("replacement must produce a publication-integrity error: {error}"),
            Ok(snapshot) => panic!(
                "loader paired resolved authority with substituted graph: resolved_present={}, substituted_present={}",
                snapshot
                    .graph
                    .as_deref()
                    .is_some_and(|graph| graph.node_by_name("resolved").is_some()),
                snapshot
                    .graph
                    .as_deref()
                    .is_some_and(|graph| graph.node_by_name("substituted").is_some()),
            ),
        }
    }

    #[tokio::test]
    async fn immutable_loader_rejects_database_changed_after_graph_load() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        let published = publish_immutable(&binding, &graph_with_symbol("loaded")).await;
        let original_bytes =
            std::fs::read(&published.database_path).expect("original immutable generation bytes");

        let alternate_path = temporary.path().join("alternate-after-load.redb");
        let alternate_database =
            redb::Database::create(&alternate_path).expect("alternate redb database");
        let alternate_store = GraphStore::new(Arc::new(alternate_database));
        alternate_store
            .save_snapshot(&graph_with_symbol("changed_after_load"))
            .await
            .expect("alternate graph snapshot");
        alternate_store
            .set_origin(binding.root())
            .await
            .expect("alternate graph origin");
        alternate_store
            .set_generation_metadata(GraphGenerationMetadata::now(false))
            .await
            .expect("alternate graph metadata");
        drop(alternate_store);

        let held_original = temporary.path().join("held-after-load.redb");
        let published_path = published.database_path.clone();
        let hook_published_path = published_path.clone();
        let hook_held_original = held_original.clone();
        let hook_alternate_path = alternate_path.clone();
        *PUBLICATION_LOAD_BEFORE_REVALIDATE_HOOK
            .lock()
            .expect("install pre-revalidation hook") = Some((
            published_path.clone(),
            Box::new(move || {
                std::fs::rename(&hook_published_path, &hook_held_original)
                    .expect("hold generation after graph load");
                std::fs::rename(&hook_alternate_path, &hook_published_path)
                    .expect("replace generation before post-load validation");
            }),
        ));

        let loaded = CodeIntelSnapshot::load(&binding).await;
        let replaced_after = temporary.path().join("replacement-after-load.redb");
        std::fs::rename(&published_path, &replaced_after).expect("remove post-load replacement");
        std::fs::rename(&held_original, &published_path).expect("restore original generation");
        assert_eq!(
            std::fs::read(&published_path).expect("restored generation bytes"),
            original_bytes
        );

        match loaded {
            Err(
                CodeIntelLoadError::Publication(_) | CodeIntelLoadError::PublicationChanged { .. },
            ) => {}
            Err(error) => panic!("post-load replacement must be an integrity error: {error}"),
            Ok(snapshot) => panic!(
                "loader admitted a generation whose referenced path changed after graph load: loaded_present={}",
                snapshot
                    .graph
                    .as_deref()
                    .is_some_and(|graph| graph.node_by_name("loaded").is_some()),
            ),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slower_refresh_cannot_replace_a_newer_immutable_generation() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        publish_immutable(&binding, &graph_with_symbol("first")).await;
        let context = CodeIntelContext::load(binding.clone(), CancellationToken::new())
            .await
            .expect("initial immutable context");

        let second = publish_immutable(&binding, &graph_with_symbol("second")).await;
        let reached_commit = Arc::new(std::sync::Barrier::new(2));
        let release_commit = Arc::new(std::sync::Barrier::new(2));
        let hook_reached = Arc::clone(&reached_commit);
        let hook_release = Arc::clone(&release_commit);
        *REFRESH_BEFORE_COMMIT_HOOK
            .lock()
            .expect("install delayed refresh hook") = Some((
            second.manifest.generation_id.0.clone(),
            Box::new(move || {
                hook_reached.wait();
                hook_release.wait();
            }),
        ));

        let delayed_context = context.with_cancellation(CancellationToken::new());
        let delayed = tokio::spawn(async move { delayed_context.refresh_if_changed().await });
        tokio::task::spawn_blocking(move || reached_commit.wait())
            .await
            .expect("wait for delayed refresh");

        let third = publish_immutable(&binding, &graph_with_symbol("third")).await;
        let newest = context
            .refresh_if_changed()
            .await
            .expect("install newest immutable generation");
        assert_eq!(
            newest
                .immutable_generation()
                .expect("newest generation authority")
                .manifest
                .generation_id,
            third.manifest.generation_id
        );

        tokio::task::spawn_blocking(move || release_commit.wait())
            .await
            .expect("release delayed refresh");
        let delayed_result = delayed
            .await
            .expect("join delayed refresh")
            .expect("delayed refresh result");
        let final_snapshot = context.snapshot();
        assert_eq!(
            delayed_result
                .immutable_generation()
                .expect("delayed result authority")
                .manifest
                .generation_id,
            third.manifest.generation_id,
            "a delayed request must observe the already-installed newer generation"
        );
        assert_eq!(
            final_snapshot
                .immutable_generation()
                .expect("final generation authority")
                .manifest
                .generation_id,
            third.manifest.generation_id,
            "a slower refresh must not roll the process snapshot backward"
        );
        assert!(
            final_snapshot
                .graph
                .as_deref()
                .is_some_and(|graph| graph.node_by_name("third").is_some())
        );
        assert!(
            final_snapshot
                .graph
                .as_deref()
                .is_some_and(|graph| graph.node_by_name("second").is_none())
        );
    }

    #[tokio::test]
    async fn synthetic_context_cannot_claim_an_unloaded_publication_fingerprint() {
        let temporary = TempDir::new().expect("temporary directory");
        let binding = test_binding(&temporary);
        let published = publish_immutable(&binding, &graph_with_symbol("published")).await;
        let context = CodeIntelContext::from_test_snapshot(
            binding,
            CancellationToken::new(),
            Arc::new(CodeIntelSnapshot::unindexed()),
        );

        let refreshed = context
            .refresh_if_changed()
            .await
            .expect("synthetic context must load the existing publication");
        assert_eq!(
            refreshed
                .immutable_generation()
                .expect("loaded immutable authority")
                .manifest
                .generation_id,
            published.manifest.generation_id
        );
        assert!(
            refreshed
                .graph
                .as_deref()
                .is_some_and(|graph| graph.node_by_name("published").is_some())
        );
    }
}
