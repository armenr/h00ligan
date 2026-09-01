//! One project-bound code-intelligence indexing use case.
//!
//! CLI and MCP adapters select inputs and render results. This module owns the
//! effect-bearing contract between them: managed-output hygiene, provider
//! intent, safe pipeline defaults, and immutable publication.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::code_intel_callable_liveness::assess_callable_liveness_capability;
use crate::code_intel_calls::assess_calls_capability;
use crate::code_intel_cancellation::IndexCancellation;
use crate::code_intel_domain::CapabilityCoverage;
use crate::code_intel_inventory::{
    InventorySource, build_project_inventory, semantic_provider_execution_roots,
};
use crate::code_intel_payload::{
    NormalizedProviderPayload, ProviderExecutionAuthority, ProviderPayload,
    provider_payload_semantic_paths_are_current,
};
use crate::code_intel_publication::{
    CapabilityFloorPolicy, IndexGenerationPublicationError, LiveGenerationAuthority,
    LiveGenerationBasis, LivePublicationRuntime, PreparedPublicationRoot, PublicationError,
    PublicationMaintenance, PublicationRecovery, PublishedGeneration, PublishedIndexGeneration,
    publication_control_token, publish_prepared_index_generation_with_live_basis,
    resolve_generation_with_control_token_profiled, revalidate_live_generation_authority_profiled,
    validate_open_generation_authority,
};
use crate::code_intel_semantic_cache::load_cached_canonical_semantic_bases;
use crate::code_intel_semantic_provider_registry::SemanticProviderRegistry;
use crate::code_intel_toolchain::{
    SCIP_GO_REUSE_CONTRACT_ID, ToolchainBoundAuthorityInput, ToolchainResolver,
    resolve_toolchain_population, toolchain_bound_execution_authority,
    toolchain_provider_configuration_population, toolchain_provider_implementation_sha256,
};
use crate::graph_stats::{StalenessVerdict, check_indexed_source_freshness};
use crate::index_pipeline::{
    IndexConfig, IndexPhaseTiming, IndexProgressEvent, IndexProgressPhase, IndexProgressState,
    IndexReport, IndexTimingAggregation, ScipMode, emit_progress,
    structural_receipts_match_records,
};
use crate::index_state::{FileRecord, IndexState};
use crate::project_binding::{
    IMMUTABLE_PUBLICATION_DIRECTORY, PROVIDER_CACHE_DIRECTORY, ProjectBinding, ProjectPathError,
    ProjectRootError,
};
use crate::scip_normalizer::CanonicalSemanticBasis;

/// Whether a shipped adapter may execute external semantic providers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProviderIntent {
    /// Structural indexing only; do not probe providers or load their artifacts.
    #[default]
    StructuralOnly,
    /// Attempt every eligible provider admitted by the indexing pipeline and
    /// retain honest per-scope gaps when some providers cannot run.
    Refresh,
}

impl ProviderIntent {
    const fn scip_mode(self) -> ScipMode {
        match self {
            Self::StructuralOnly => ScipMode::Disabled,
            Self::Refresh => ScipMode::Refresh,
        }
    }
}

/// Adapter-supplied inputs for one current immutable generation.
#[derive(Debug, Clone, Default)]
pub struct BoundIndexRequest {
    pub providers: ProviderIntent,
    /// Rebuild even when exact current-generation evidence satisfies this
    /// request. Normal requests reuse only after fail-closed verification.
    pub force: bool,
    /// Require complete Calls authority for every callable language in the
    /// candidate generation. Best-effort provider enrichment is the default.
    pub require_complete_calls: bool,
    pub jobs: Option<usize>,
    pub debug: bool,
    pub profile: bool,
    pub progress: Option<tokio::sync::mpsc::UnboundedSender<IndexProgressEvent>>,
    pub cancellation: IndexCancellation,
    pub source_revision: Option<String>,
    pub publication_recovery: PublicationRecovery,
    pub capability_floor: CapabilityFloorPolicy,
}

#[derive(Debug, Error)]
pub enum BoundIndexPlanError {
    #[error("project binding error: {0}")]
    Binding(#[from] ProjectRootError),
    #[error("project path error: {0}")]
    Path(#[from] ProjectPathError),
    #[error("semantic publication error: {0}")]
    Publication(#[from] PublicationError),
}

/// A fully preflighted indexing operation bound to one root and data directory.
///
/// Construction performs every adapter-independent path/hygiene check. Calling
/// [`Self::publish`] consumes the plan so the checked request cannot be reused
/// or silently retargeted.
#[derive(Debug)]
pub struct BoundIndexPlan {
    publication_root: PreparedPublicationRoot,
    graph_directory: std::path::PathBuf,
    config: IndexConfig,
    providers: ProviderIntent,
    force: bool,
    source_revision: Option<String>,
    publication_recovery: PublicationRecovery,
    capability_floor: CapabilityFloorPolicy,
    /// Bounded, non-authoritative WATCH paths used only to prove quickly that
    /// exact reuse is impossible. Inconclusive hints always fall through to
    /// the complete source/inventory verification.
    reuse_hints: Arc<[std::path::PathBuf]>,
}

impl BoundIndexPlan {
    /// Bind a request to the process-wide project decision without publishing.
    pub fn prepare(
        binding: &ProjectBinding,
        request: BoundIndexRequest,
    ) -> Result<Self, BoundIndexPlanError> {
        Self::prepare_with_toolchain_resolver(binding, request, None, Arc::default())
    }

    pub(crate) fn prepare_with_toolchain_resolver(
        binding: &ProjectBinding,
        request: BoundIndexRequest,
        toolchain_resolver: Option<Arc<dyn ToolchainResolver>>,
        reuse_hints: Arc<[std::path::PathBuf]>,
    ) -> Result<Self, BoundIndexPlanError> {
        binding.ensure_graph_directory_write(IMMUTABLE_PUBLICATION_DIRECTORY)?;
        binding.ensure_graph_directory_write(PROVIDER_CACHE_DIRECTORY)?;

        let scip = request.providers.scip_mode();
        let graph_directory = binding.graph_dir().to_path_buf();

        binding.prepare_graph_directory_write()?;
        let publication_root = PreparedPublicationRoot::capture(binding.graph_dir())?;
        let config = IndexConfig {
            root: binding.root().to_path_buf(),
            // A private generation may import only verified file records and
            // extraction facts from the current generation. Source discovery
            // and hashing remain authoritative; materialized graphs, provider
            // payloads, receipts, and publication controls are rebuilt.
            full: false,
            scip,
            require_complete_calls: request.require_complete_calls,
            provider_data_root: Some(binding.graph_dir().to_path_buf()),
            toolchain_resolver,
            jobs: request.jobs,
            debug: request.debug,
            profile: request.profile,
            progress: request.progress,
            cancellation: request.cancellation,
            ..IndexConfig::default()
        };

        Ok(Self {
            publication_root,
            graph_directory,
            config,
            providers: request.providers,
            force: request.force,
            source_revision: request.source_revision,
            publication_recovery: request.publication_recovery,
            capability_floor: request.capability_floor,
            reuse_hints,
        })
    }

    /// Return an exactly reusable current generation or atomically publish a
    /// fresh one.
    pub async fn publish(
        self,
    ) -> Result<PublishedIndexGeneration, IndexGenerationPublicationError> {
        let mut semantic_providers = SemanticProviderRegistry::default();
        self.publish_with_live_basis(None, &mut semantic_providers)
            .await
            .map(|(published, _)| published)
    }

    pub(crate) async fn publish_with_live_basis(
        self,
        live_basis: Option<LiveGenerationBasis>,
        semantic_providers: &mut SemanticProviderRegistry,
    ) -> Result<
        (PublishedIndexGeneration, Option<LiveGenerationBasis>),
        IndexGenerationPublicationError,
    > {
        let live_authority = live_basis
            .as_ref()
            .and_then(LiveGenerationBasis::authority_snapshot);
        match self.probe_reuse(live_authority, semantic_providers).await? {
            BoundIndexAdmission::Reused(reused, hydrated_basis) => {
                let retained_basis = hydrated_basis.map(|basis| *basis).or_else(|| {
                    live_basis.filter(|basis| basis.matches_published(&reused.publication))
                });
                Ok((reused, retained_basis))
            }
            BoundIndexAdmission::Fresh(prepared) => {
                prepared
                    .publish_with_live_basis(live_basis, semantic_providers)
                    .await
            }
        }
    }

    /// Decide whether the immutable current generation is exactly reusable
    /// before any process-local live basis is transferred into a fresh
    /// candidate. The supervisor keeps that basis parked while this async
    /// probe runs, so cancellation or failure before admission cannot consume
    /// acceleration state that the operation never used.
    pub(crate) async fn probe_reuse(
        self,
        live_authority: Option<LiveGenerationAuthority>,
        semantic_providers: &mut SemanticProviderRegistry,
    ) -> Result<BoundIndexAdmission, IndexGenerationPublicationError> {
        if self.config.cancellation.is_cancelled() {
            return Err(crate::index_pipeline::IndexPipelineError::Cancelled.into());
        }
        let operation_start = Instant::now();
        let reuse_start = Instant::now();
        emit_progress(
            &self.config.progress,
            IndexProgressPhase::Reuse,
            IndexProgressState::Started,
            "checking current generation",
            "verifying exact source, project-input, engine, and capability evidence",
            None,
        );
        // A capability floor controls whether a newly built candidate may
        // replace stronger current evidence. It is permission, not a rebuild
        // request: an exact current generation already satisfies either floor.
        // `force` remains the explicit ordinary reuse bypass.
        let reuse_allowed = !self.force && self.publication_recovery == PublicationRecovery::Strict;
        let (prevalidated_current, reuse_phase_timings) = if reuse_allowed {
            let CurrentGenerationProbe {
                reused,
                reused_live_basis,
                prevalidated_current,
                phase_timings,
            } = try_reuse_current_generation(
                &self.graph_directory,
                &self.config,
                self.providers,
                self.source_revision.as_deref(),
                &self.reuse_hints,
                CurrentGenerationRuntime {
                    live_authority,
                    semantic_providers,
                },
            )
            .await;
            if let Some(reused) = reused {
                if self.config.cancellation.is_cancelled() {
                    return Err(crate::index_pipeline::IndexPipelineError::Cancelled.into());
                }
                let duration = reuse_start.elapsed();
                emit_progress(
                    &self.config.progress,
                    IndexProgressPhase::Reuse,
                    IndexProgressState::Completed,
                    "checking current generation",
                    format!(
                        "generation {} already satisfies this request",
                        reused.publication.manifest.generation_id
                    ),
                    Some(duration),
                );
                return Ok(BoundIndexAdmission::Reused(reused, reused_live_basis));
            }
            (prevalidated_current, phase_timings)
        } else {
            (None, Vec::new())
        };
        if self.config.cancellation.is_cancelled() {
            return Err(crate::index_pipeline::IndexPipelineError::Cancelled.into());
        }
        let reuse_duration = reuse_start.elapsed();
        emit_progress(
            &self.config.progress,
            IndexProgressPhase::Reuse,
            IndexProgressState::Skipped,
            "checking current generation",
            if self.force {
                "explicit force requested a fresh generation"
            } else if !reuse_allowed {
                "publication recovery authorization requires a fresh generation"
            } else {
                "current generation does not exactly satisfy this request"
            },
            Some(reuse_duration),
        );

        Ok(BoundIndexAdmission::Fresh(PreparedBoundIndexPublication {
            publication_root: self.publication_root,
            config: self.config,
            source_revision: self.source_revision,
            publication_recovery: self.publication_recovery,
            capability_floor: self.capability_floor,
            prevalidated_current,
            operation_start,
            reuse_duration,
            reuse_phase_timings,
        }))
    }
}

pub(crate) enum BoundIndexAdmission {
    Reused(PublishedIndexGeneration, Option<Box<LiveGenerationBasis>>),
    Fresh(PreparedBoundIndexPublication),
}

pub(crate) struct PreparedBoundIndexPublication {
    publication_root: PreparedPublicationRoot,
    config: IndexConfig,
    source_revision: Option<String>,
    publication_recovery: PublicationRecovery,
    capability_floor: CapabilityFloorPolicy,
    prevalidated_current: Option<crate::code_intel_publication::ResolvedGeneration>,
    operation_start: Instant,
    reuse_duration: std::time::Duration,
    reuse_phase_timings: Vec<IndexPhaseTiming>,
}

impl PreparedBoundIndexPublication {
    pub(crate) async fn publish_with_live_basis(
        self,
        live_basis: Option<LiveGenerationBasis>,
        semantic_providers: &mut SemanticProviderRegistry,
    ) -> Result<
        (PublishedIndexGeneration, Option<LiveGenerationBasis>),
        IndexGenerationPublicationError,
    > {
        let Self {
            publication_root,
            config,
            source_revision,
            publication_recovery,
            capability_floor,
            prevalidated_current,
            operation_start,
            reuse_duration,
            mut reuse_phase_timings,
        } = self;
        let (mut published, next_live_basis) = publish_prepared_index_generation_with_live_basis(
            publication_root,
            &config,
            source_revision,
            publication_recovery,
            capability_floor,
            LivePublicationRuntime {
                prevalidated_current,
                live_basis,
                semantic_providers,
            },
        )
        .await?;
        let mut measured_reuse = Vec::with_capacity(reuse_phase_timings.len() + 1);
        measured_reuse.push(IndexPhaseTiming {
            phase: IndexProgressPhase::Reuse,
            label: "checking current generation".into(),
            duration: reuse_duration,
            aggregation: if reuse_phase_timings.is_empty() {
                IndexTimingAggregation::Exclusive
            } else {
                IndexTimingAggregation::ConcurrentSpan
            },
        });
        measured_reuse.append(&mut reuse_phase_timings);
        published
            .telemetry
            .phase_timings
            .splice(0..0, measured_reuse);
        published.telemetry.duration = operation_start.elapsed();
        Ok((published, Some(next_live_basis)))
    }
}

#[derive(Default)]
struct CurrentGenerationProbe {
    reused: Option<PublishedIndexGeneration>,
    reused_live_basis: Option<Box<LiveGenerationBasis>>,
    prevalidated_current: Option<crate::code_intel_publication::ResolvedGeneration>,
    phase_timings: Vec<IndexPhaseTiming>,
}

fn check_complete_indexed_source_freshness(
    root: &std::path::Path,
    indexed_files: &[(String, FileRecord)],
) -> Result<StalenessVerdict, crate::graph_stats::IndexedSourceFreshnessError> {
    check_indexed_source_freshness(root, indexed_files)
}

/// Return `true` only when a bounded WATCH hint proves that one source from
/// the immutable indexed population no longer has its recorded bytes.
///
/// Hints are deliberately insufficient to prove freshness: an unknown path,
/// byte-identical path, non-UTF-8 path, or path outside the repository is
/// inconclusive and the caller must perform complete discovery and hashing.
fn hinted_indexed_source_change(
    root: &std::path::Path,
    indexed_files: &[(String, FileRecord)],
    reuse_hints: &[std::path::PathBuf],
) -> bool {
    let indexed = indexed_files
        .iter()
        .map(|(path, record)| (path.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    reuse_hints.iter().any(|hint| {
        let relative = if hint.is_absolute() {
            let Ok(relative) = hint.strip_prefix(root) else {
                return false;
            };
            relative
        } else {
            hint.as_path()
        };
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return false;
        }
        let Some(relative) = relative.to_str() else {
            return false;
        };
        let Some(record) = indexed.get(relative) else {
            return false;
        };
        let Ok(bytes) = std::fs::read(root.join(relative)) else {
            return true;
        };
        blake3::hash(&bytes).to_hex().as_str() != record.blake3_hash
    })
}

impl CurrentGenerationProbe {
    const fn miss(
        prevalidated_current: Option<crate::code_intel_publication::ResolvedGeneration>,
        phase_timings: Vec<IndexPhaseTiming>,
    ) -> Self {
        Self {
            reused: None,
            reused_live_basis: None,
            prevalidated_current,
            phase_timings,
        }
    }
}

fn reuse_stage_timing(label: &'static str, duration: Duration) -> IndexPhaseTiming {
    IndexPhaseTiming {
        phase: IndexProgressPhase::Reuse,
        label: label.into(),
        duration,
        aggregation: IndexTimingAggregation::Exclusive,
    }
}

fn retained_reuse_stage_label(label: &'static str) -> &'static str {
    match label {
        "reuse publication control resolution" => "reuse retained publication control validation",
        "reuse generation identity validation" => "reuse retained generation identity validation",
        "reuse immutable database digest" => "reuse retained immutable database digest",
        other => other,
    }
}

fn indexed_source_evidence_from_generation<P: AsRef<ProviderPayload>>(
    indexed_files: &[(String, FileRecord)],
    payloads: &[P],
) -> Option<Vec<crate::scip_normalizer::IndexedSourceEvidence>> {
    let mut surfaces = BTreeMap::<(String, String), String>::new();
    for payload in payloads {
        for document in payload.as_ref().documents() {
            let key = (
                document.document_path.clone(),
                document.language_id.0.clone(),
            );
            if surfaces
                .insert(key, document.cross_document_surface_sha256.clone())
                .is_some_and(|prior| prior != document.cross_document_surface_sha256)
            {
                return None;
            }
        }
    }
    Some(
        indexed_files
            .iter()
            .map(
                |(path, record)| crate::scip_normalizer::IndexedSourceEvidence {
                    relative_path: path.clone(),
                    language: record.language.clone(),
                    blake3_hash: record.blake3_hash.clone(),
                    cross_document_surface_sha256: surfaces
                        .get(&(path.clone(), record.language.clone()))
                        .cloned(),
                },
            )
            .collect(),
    )
}

async fn semantic_generation_reuse_is_authorized(
    config: &IndexConfig,
    inventory: &crate::code_intel_domain::ProjectInventory,
    indexed_sources: &[crate::scip_normalizer::IndexedSourceEvidence],
    payloads: &[NormalizedProviderPayload],
    canonical_bases: &[CanonicalSemanticBasis],
    semantic_providers: &mut SemanticProviderRegistry,
) -> bool {
    if !matches!(
        provider_payload_semantic_paths_are_current(&config.root, payloads),
        Ok(true)
    ) {
        return false;
    }

    let go_roots = semantic_provider_execution_roots(inventory, "go", "go")
        .into_iter()
        .map(|relative| config.root.join(relative))
        .collect::<Vec<_>>();
    let persistent_go = semantic_providers.contains("go");

    // Invocation-bound evidence never crosses an indexing operation. Every
    // complete toolchain-bound payload must have the exact registered provider
    // that owns its language and provider identity. Stock `scip-go` is the sole
    // one-shot exception and is re-authorized below through its explicit
    // reconstruction contract.
    for payload in payloads {
        let payload = payload.payload();
        let receipt = payload.receipt();
        if receipt.status != crate::code_intel_domain::CapabilityStatus::Complete {
            continue;
        }
        if matches!(
            payload.execution_authority(),
            ProviderExecutionAuthority::InvocationBound { .. }
        ) {
            // Invocation-bound evidence is usable only in the operation that
            // produced it. Persisted bytes describe the old invocation; no
            // fresh or retained runtime can reconstruct cross-operation reuse.
            return false;
        }
        let Some(language) = receipt.scope.language_id() else {
            return false;
        };
        let stock_scip_go = language.0 == "go" && receipt.provider_id.0 == "scip-go";
        if !stock_scip_go
            && !semantic_providers.contains_provider(&language.0, &receipt.provider_id.0)
        {
            return false;
        }
    }

    let persistent_authorizations = semantic_providers
        .map_providers(|provider| {
            let applicable = !semantic_provider_execution_roots(
                inventory,
                provider.language(),
                provider.ecosystem(),
            )
            .is_empty();
            Box::pin(async move {
                !applicable
                    || provider
                        .authorize_and_hydrate_exact_generation_reuse(
                            &config.root,
                            inventory,
                            indexed_sources,
                            payloads,
                            canonical_bases,
                            &config.cancellation,
                        )
                        .await
            })
        })
        .await;
    if persistent_authorizations
        .into_iter()
        .any(|authorized| !authorized)
    {
        return false;
    }
    if go_roots.is_empty() || persistent_go {
        return true;
    }

    {
        let mut go_payloads = payloads
            .iter()
            .filter_map(|payload| match payload.payload() {
                ProviderPayload::Calls(payload)
                    if payload.receipt.capability_id == "calls"
                        && payload.receipt.provider_id.0 == "scip-go"
                        && payload.receipt.status
                            == crate::code_intel_domain::CapabilityStatus::Complete =>
                {
                    Some(payload)
                }
                _ => None,
            });
        let Some(go_payload) = go_payloads.next() else {
            return false;
        };
        if go_payloads.next().is_some() {
            return false;
        }
        let ProviderExecutionAuthority::ToolchainBound {
            resolver_policy_id,
            ecosystem_id,
            reuse_contract_id,
            ..
        } = &go_payload.execution_authority
        else {
            return false;
        };
        let Some(resolver) = config.toolchain_resolver.as_ref() else {
            return false;
        };
        let Ok(current_resolver_policy_id) = resolver.policy_id("go") else {
            return false;
        };
        if ecosystem_id.0 != "go"
            || current_resolver_policy_id != resolver_policy_id
            || reuse_contract_id != SCIP_GO_REUSE_CONTRACT_ID
        {
            return false;
        }
        let Ok(toolchains) =
            resolve_toolchain_population(Some(resolver), "go", &go_roots, &config.cancellation)
                .await
        else {
            return false;
        };
        toolchain_provider_implementation_sha256(&toolchains, "scip-go")
            .and_then(|provider_implementation| {
                let configurations = toolchain_provider_configuration_population(
                    &config.root,
                    SCIP_GO_REUSE_CONTRACT_ID,
                    &toolchains,
                )?;
                toolchain_bound_execution_authority(ToolchainBoundAuthorityInput {
                    repository_root: &config.root,
                    inventory,
                    language: "go",
                    ecosystem: "go",
                    resolver_policy_id: current_resolver_policy_id,
                    reuse_contract_id: SCIP_GO_REUSE_CONTRACT_ID,
                    provider_implementation_sha256: &provider_implementation,
                    provider_configurations_sha256: &configurations,
                    reconstruction_descriptors: None,
                    toolchains: &toolchains,
                })
            })
            .is_ok_and(|observed| observed == go_payload.execution_authority)
    }
}

struct CurrentGenerationRuntime<'a> {
    live_authority: Option<LiveGenerationAuthority>,
    semantic_providers: &'a mut SemanticProviderRegistry,
}

async fn try_reuse_current_generation(
    graph_directory: &std::path::Path,
    config: &IndexConfig,
    providers: ProviderIntent,
    source_revision: Option<&str>,
    reuse_hints: &[std::path::PathBuf],
    runtime: CurrentGenerationRuntime<'_>,
) -> CurrentGenerationProbe {
    let CurrentGenerationRuntime {
        live_authority,
        semantic_providers,
    } = runtime;
    let started = Instant::now();
    let mut phase_timings = Vec::new();
    let graph_directory = graph_directory.to_path_buf();
    let graph_directory_for_measurement = graph_directory.clone();
    let root = config.root.clone();
    let source_revision = source_revision.map(str::to_owned);
    let reuse_hints = reuse_hints.to_vec();
    let prepared = tokio::task::spawn_blocking(move || {
        let mut timings = Vec::new();
        if !reuse_hints.is_empty()
            && let Some(authority) = live_authority.as_ref()
        {
            let (retained, retained_timings) = revalidate_live_generation_authority_profiled(
                &graph_directory_for_measurement,
                &root,
                authority,
            );
            timings.extend(retained_timings.into_iter().map(|timing| {
                tracing::debug!(
                    label = timing.label,
                    duration_ms = timing.duration.as_secs_f64() * 1_000.0,
                    work_items = timing.work_items,
                    work_unit = timing.work_unit,
                    "profiled retained-generation authority component"
                );
                reuse_stage_timing(retained_reuse_stage_label(timing.label), timing.duration)
            }));
            if let Some((resolved, initial_control_token)) = retained {
                if resolved.manifest.source_revision != source_revision {
                    return (Some((resolved, initial_control_token, None)), timings);
                }
                let stage_started = Instant::now();
                let database = redb::ReadOnlyDatabase::open(&resolved.database_path)
                    .ok()
                    .map(Arc::new);
                let indexed_files = database.as_ref().and_then(|database| {
                    IndexState::new_read_only(Arc::clone(database))
                        .all_files()
                        .ok()
                });
                timings.push(reuse_stage_timing(
                    "reuse retained change-hint hydration",
                    stage_started.elapsed(),
                ));
                if let (Some(database), Some(indexed_files)) = (database, indexed_files) {
                    let stage_started = Instant::now();
                    let hinted_rejection =
                        hinted_indexed_source_change(&root, &indexed_files, &reuse_hints);
                    timings.push(reuse_stage_timing(
                        if hinted_rejection {
                            "reuse indexed change-hint rejection"
                        } else {
                            "reuse indexed change-hint check"
                        },
                        stage_started.elapsed(),
                    ));
                    if hinted_rejection {
                        return (Some((resolved, initial_control_token, None)), timings);
                    }
                    return (
                        Some((resolved, initial_control_token, Some(database))),
                        timings,
                    );
                }
            }
        }
        let (resolved, resolution_timings) =
            resolve_generation_with_control_token_profiled(&graph_directory_for_measurement, &root);
        timings.extend(resolution_timings.into_iter().map(|timing| {
            tracing::debug!(
                label = timing.label,
                duration_ms = timing.duration.as_secs_f64() * 1_000.0,
                work_items = timing.work_items,
                work_unit = timing.work_unit,
                "profiled immutable-generation resolution component"
            );
            reuse_stage_timing(timing.label, timing.duration)
        }));
        let resolved = resolved.ok();
        let Some((resolved, initial_control_token)) = resolved else {
            return (None, timings);
        };
        if resolved.manifest.source_revision != source_revision {
            return (Some((resolved, initial_control_token, None)), timings);
        }
        let stage_started = Instant::now();
        let database = redb::ReadOnlyDatabase::open(&resolved.database_path)
            .ok()
            .map(Arc::new);
        let Some(database) = database else {
            timings.push(reuse_stage_timing(
                "reuse generation handle open",
                stage_started.elapsed(),
            ));
            return (None, timings);
        };
        if !reuse_hints.is_empty() {
            let state = IndexState::new_read_only(Arc::clone(&database));
            let indexed_files = state.all_files().ok();
            timings.push(reuse_stage_timing(
                "reuse resolved change-hint hydration",
                stage_started.elapsed(),
            ));
            let Some(indexed_files) = indexed_files else {
                return (None, timings);
            };
            let stage_started = Instant::now();
            let hinted_rejection =
                hinted_indexed_source_change(&root, &indexed_files, &reuse_hints);
            timings.push(reuse_stage_timing(
                if hinted_rejection {
                    "reuse indexed change-hint rejection"
                } else {
                    "reuse indexed change-hint check"
                },
                stage_started.elapsed(),
            ));
            if hinted_rejection {
                return (Some((resolved, initial_control_token, None)), timings);
            }
        }
        (
            Some((resolved, initial_control_token, Some(database))),
            timings,
        )
    })
    .await;
    let Ok((prepared, prepared_timings)) = prepared else {
        return CurrentGenerationProbe::miss(None, phase_timings);
    };
    phase_timings.extend(prepared_timings);
    let Some((resolved, initial_control_token, prepared_reuse)) = prepared else {
        return CurrentGenerationProbe::miss(None, phase_timings);
    };
    let Some(database) = prepared_reuse else {
        return CurrentGenerationProbe::miss(Some(resolved), phase_timings);
    };

    let stage_started = Instant::now();
    let opened = validate_open_generation_authority(database, &resolved, &config.root).ok();
    phase_timings.push(reuse_stage_timing(
        "reuse authenticated generation hydration",
        stage_started.elapsed(),
    ));
    let Some(opened) = opened else {
        return CurrentGenerationProbe::miss(None, phase_timings);
    };
    let indexed_files = opened.indexed_sources.files().to_vec();
    let graph = opened.graph;
    let live_source_basis = opened.incremental_basis;
    let stage_started = Instant::now();
    let calls_authority = assess_calls_capability(
        &graph,
        &resolved.manifest.receipts,
        &resolved.provider_payloads,
        &resolved.project_inventory,
    );
    let callable_liveness_authority = assess_callable_liveness_capability(
        &graph,
        &resolved.manifest.receipts,
        &resolved.provider_payloads,
        &resolved.project_inventory,
    );
    let provider_evidence_satisfied =
        provider_evidence_satisfies(providers, config.require_complete_calls, &calls_authority);
    phase_timings.push(reuse_stage_timing(
        "reuse capability admission",
        stage_started.elapsed(),
    ));
    if !provider_evidence_satisfied {
        return CurrentGenerationProbe::miss(Some(resolved), phase_timings);
    }

    let stage_started = Instant::now();
    let root = config.root.clone();
    let exclude = config.exclude.clone();
    let expected_inventory = Arc::clone(&resolved.project_inventory);
    let structural_receipts = resolved.manifest.receipts.clone();
    let source_verification = tokio::task::spawn_blocking(move || {
        let freshness = check_complete_indexed_source_freshness(&root, &indexed_files).ok()?;
        let current = if freshness == StalenessVerdict::Fresh {
            let live_inventory = build_project_inventory(
                &root,
                &indexed_files
                    .iter()
                    .map(|(path, record)| InventorySource::new(path, &record.language))
                    .collect::<Vec<_>>(),
            );
            live_inventory.eq(expected_inventory.as_ref())
                && structural_receipts_match_records(&structural_receipts, &indexed_files, &exclude)
        } else {
            false
        };
        Some((indexed_files, current))
    })
    .await
    .ok()
    .flatten();
    phase_timings.push(reuse_stage_timing(
        "reuse complete source and inventory validation",
        stage_started.elapsed(),
    ));
    let Some((indexed_files, source_and_inventory_current)) = source_verification else {
        return CurrentGenerationProbe::miss(None, phase_timings);
    };
    if !source_and_inventory_current {
        return CurrentGenerationProbe::miss(Some(resolved), phase_timings);
    }
    let mut live_semantic_bases = Vec::new();
    if providers != ProviderIntent::StructuralOnly {
        let stage_started = Instant::now();
        let indexed_sources =
            indexed_source_evidence_from_generation(&indexed_files, &resolved.provider_payloads);
        let Some(indexed_sources) = indexed_sources else {
            phase_timings.push(reuse_stage_timing(
                "reuse semantic basis hydration",
                stage_started.elapsed(),
            ));
            return CurrentGenerationProbe::miss(Some(resolved), phase_timings);
        };
        live_semantic_bases = load_cached_canonical_semantic_bases(
            &graph_directory,
            &config.root,
            &resolved.provider_payloads,
        );
        phase_timings.push(reuse_stage_timing(
            "reuse semantic basis hydration",
            stage_started.elapsed(),
        ));
        let stage_started = Instant::now();
        let semantic_reuse_authorized = semantic_generation_reuse_is_authorized(
            config,
            &resolved.project_inventory,
            &indexed_sources,
            &resolved.provider_payloads,
            &live_semantic_bases,
            semantic_providers,
        )
        .await;
        phase_timings.push(reuse_stage_timing(
            "reuse semantic authority recertification",
            stage_started.elapsed(),
        ));
        if !semantic_reuse_authorized {
            return CurrentGenerationProbe::miss(Some(resolved), phase_timings);
        }
    }

    // A fresh bounded control read is the reuse linearization point. The
    // initial token came from the exact scan that selected and fully validated
    // `resolved`; if a concurrent writer changed either head while inputs were
    // measured, rebuild through the normal writer path instead of returning
    // stale "current". Repeating full generation validation here would hash
    // and reparse the same immutable payload a second time.
    let stage_started = Instant::now();
    let current_control_token = publication_control_token(&graph_directory, &config.root);
    phase_timings.push(reuse_stage_timing(
        "reuse control linearization",
        stage_started.elapsed(),
    ));
    let Ok(current_control_token) = current_control_token else {
        return CurrentGenerationProbe::miss(None, phase_timings);
    };
    if current_control_token != initial_control_token {
        return CurrentGenerationProbe::miss(None, phase_timings);
    }
    let stage_started = Instant::now();
    let reachability = crate::graph_stats::compute_reachability_summary(&graph);
    phase_timings.push(reuse_stage_timing(
        "reuse reachability summary",
        stage_started.elapsed(),
    ));
    let duration = started.elapsed();
    let files_discovered = indexed_files.len();
    let nodes_total = graph.node_count();
    let edges_total = graph.edge_count();
    let reused_live_basis = Some(Box::new(LiveGenerationBasis::from_resolved(
        &resolved,
        current_control_token,
        live_source_basis,
        graph,
        live_semantic_bases,
    )));
    phase_timings.insert(
        0,
        IndexPhaseTiming {
            phase: IndexProgressPhase::Reuse,
            label: "checking current generation".into(),
            duration,
            aggregation: IndexTimingAggregation::ConcurrentSpan,
        },
    );
    CurrentGenerationProbe {
        reused: Some(PublishedIndexGeneration {
            telemetry: IndexReport {
                reused_generation: true,
                files_discovered,
                files_unchanged: files_discovered,
                nodes_total,
                edges_total,
                reachability: Some(reachability),
                duration,
                phase_timings,
                ..IndexReport::default()
            },
            publication: PublishedGeneration {
                slot: resolved.slot,
                head: resolved.head,
                manifest: resolved.manifest,
                project_inventory: resolved.project_inventory,
                provider_payloads: resolved.provider_payloads,
                database_path: resolved.database_path,
                maintenance: PublicationMaintenance::default(),
            },
            calls_authority,
            callable_liveness_authority,
            publication_timings: Vec::new(),
        }),
        reused_live_basis,
        prevalidated_current: None,
        phase_timings: Vec::new(),
    }
}

fn provider_evidence_satisfies(
    providers: ProviderIntent,
    require_complete_calls: bool,
    calls: &CapabilityCoverage,
) -> bool {
    if providers == ProviderIntent::StructuralOnly {
        return true;
    }
    if require_complete_calls {
        return calls.all_callable_languages_complete();
    }
    calls.satisfies_best_effort_provider_intent()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;

    use super::*;
    use crate::code_intel_publication::{
        generations_validated, reset_generations_validated, resolve_generation,
    };
    use crate::scip_normalizer::ScipArtifactSetNormalization;

    #[derive(Debug)]
    struct ReuseProbeProvider {
        language: &'static str,
        ecosystem: &'static str,
        authorizations: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl crate::code_intel_semantic_provider_registry::PersistentSemanticProvider
        for ReuseProbeProvider
    {
        fn language(&self) -> &'static str {
            self.language
        }

        fn ecosystem(&self) -> &'static str {
            self.ecosystem
        }

        fn provider_id(&self) -> &str {
            "h00-reuse-probe"
        }

        fn operation_label(&self) -> &'static str {
            "reuse probe"
        }

        fn set_session_jobs(&mut self, _jobs: Option<usize>) {}

        fn take_last_activity(
            &mut self,
        ) -> Option<crate::code_intel_semantic_provider_coordinator::SemanticProviderActivityRecord>
        {
            None
        }

        fn active_cache_directories(&self) -> BTreeSet<PathBuf> {
            BTreeSet::new()
        }

        async fn authorize_and_hydrate_exact_generation_reuse(
            &mut self,
            _repository_root: &Path,
            _inventory: &crate::code_intel_domain::ProjectInventory,
            _indexed_sources: &[crate::scip_normalizer::IndexedSourceEvidence],
            _provider_payloads: &[NormalizedProviderPayload],
            _prior_bases: &[CanonicalSemanticBasis],
            _cancellation: &crate::code_intel_cancellation::IndexCancellation,
        ) -> bool {
            self.authorizations.fetch_add(1, Ordering::Relaxed);
            true
        }

        async fn reuse_exact_canonical_basis(
            &mut self,
            _repository_root: &Path,
            _inventory: &crate::code_intel_domain::ProjectInventory,
            _indexed_sources: &[crate::scip_normalizer::IndexedSourceEvidence],
            _prior_bases: &[CanonicalSemanticBasis],
            _cancellation: &crate::code_intel_cancellation::IndexCancellation,
        ) -> Option<ScipArtifactSetNormalization> {
            None
        }

        async fn refresh(
            &mut self,
            _repository_root: &Path,
            _execution_roots: &[PathBuf],
            _indexed_sources: &[crate::scip_normalizer::IndexedSourceEvidence],
            _inventory: &crate::code_intel_domain::ProjectInventory,
            _cancellation: &crate::code_intel_cancellation::IndexCancellation,
        ) -> Result<
            ScipArtifactSetNormalization,
            crate::code_intel_semantic_provider_coordinator::SemanticProviderError,
        > {
            unreachable!("reuse admission must not execute provider refresh")
        }

        fn mark_publication_committed(&mut self) {}

        async fn reset(&mut self) {}
    }

    #[tokio::test]
    async fn exact_generation_reuse_authorizes_every_applicable_registered_language() {
        use crate::code_intel_domain::{
            DocumentMembership, DocumentMembershipKind, EcosystemId, LanguageId, ProjectInventory,
            ProjectInventoryCoverage, ProjectTopology, ProjectUnit, ProjectUnitId, ProjectUnitKind,
        };

        let root = tempfile::tempdir().expect("reuse root");
        let unit_id = ProjectUnitId::new("fixture:python:package");
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: ProjectTopology {
                units: vec![ProjectUnit {
                    project_unit_id: unit_id.clone(),
                    language_id: LanguageId::new("python"),
                    ecosystem_id: EcosystemId::new("python"),
                    kind: ProjectUnitKind::Package,
                    root_path: "py".into(),
                    manifest_path: Some("py/pyproject.toml".into()),
                    compilation_root_paths: Vec::new(),
                }],
                memberships: vec![DocumentMembership {
                    document_path: "py/main.py".into(),
                    language_id: LanguageId::new("python"),
                    project_unit_id: unit_id,
                    kind: DocumentMembershipKind::SourceOwner,
                }],
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: Vec::new(),
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: Vec::new(),
        };
        assert_eq!(
            crate::code_intel_inventory::semantic_provider_execution_roots(
                &inventory, "python", "python"
            ),
            vec![PathBuf::from("py")],
            "positive control: the inventory contains one applicable Python provider root"
        );
        let authorizations = Arc::new(AtomicUsize::new(0));
        let mut providers = SemanticProviderRegistry::default();
        providers
            .register(ReuseProbeProvider {
                language: "python",
                ecosystem: "python",
                authorizations: Arc::clone(&authorizations),
            })
            .expect("register Python reuse probe");
        assert_eq!(providers.languages(), vec!["python"]);

        let config = IndexConfig {
            root: root.path().to_path_buf(),
            ..IndexConfig::default()
        };
        assert!(
            semantic_generation_reuse_is_authorized(
                &config,
                &inventory,
                &[],
                &[],
                &[],
                &mut providers,
            )
            .await,
            "an applicable registered provider that grants exact reuse should admit the generation"
        );
        assert_eq!(
            authorizations.load(Ordering::Relaxed),
            1,
            "exact-generation reuse must not silently skip a registered language"
        );
    }

    #[test]
    fn semantic_reuse_recovers_exact_persisted_source_surfaces() {
        let files = vec![
            (
                "src/lib.rs".into(),
                FileRecord {
                    blake3_hash: "rust-blake3".into(),
                    last_indexed: 1,
                    symbol_count: 1,
                    language: "rust".into(),
                },
            ),
            (
                "main.go".into(),
                FileRecord {
                    blake3_hash: "go-blake3".into(),
                    last_indexed: 1,
                    symbol_count: 1,
                    language: "go".into(),
                },
            ),
        ];
        let receipt = crate::code_intel_domain::CapabilityReceipt::complete(
            "calls",
            "h00-rust-analyzer-scip",
            "1.97.1",
            crate::code_intel_domain::CapabilityScope::Language {
                language_id: crate::code_intel_domain::LanguageId::new("rust"),
                configuration_id: crate::code_intel_domain::ConfigurationId::new(
                    crate::code_intel_domain::CALLS_CONFIGURATION_ID,
                ),
            },
            "f".repeat(64),
        );
        let mut rust_payload = crate::code_intel_payload::CallsProviderPayload::new(receipt);
        rust_payload.documents = vec![crate::code_intel_payload::ProviderDocument {
            document_path: "src/lib.rs".into(),
            language_id: crate::code_intel_domain::LanguageId::new("rust"),
            content_sha256: "c".repeat(64),
            cross_document_surface_sha256: "a".repeat(64),
            byte_length: 12,
        }];

        let evidence = indexed_source_evidence_from_generation(
            &files,
            &[ProviderPayload::Calls(rust_payload.clone())],
        )
        .expect("one canonical persisted surface population");
        assert_eq!(evidence.len(), 2, "positive indexed-file population");
        assert_eq!(
            evidence[0].cross_document_surface_sha256,
            Some("a".repeat(64)),
            "semantic reuse must recover the persisted Rust surface identity"
        );
        assert_eq!(
            evidence[1].cross_document_surface_sha256, None,
            "a provider cannot invent surface authority for an unrelated language"
        );

        let mut conflicting = rust_payload;
        conflicting.documents[0].cross_document_surface_sha256 = "b".repeat(64);
        assert!(
            indexed_source_evidence_from_generation(
                &files,
                &[
                    ProviderPayload::Calls(conflicting),
                    ProviderPayload::Calls({
                        let mut original = crate::code_intel_payload::CallsProviderPayload::new(
                            crate::code_intel_domain::CapabilityReceipt::complete(
                                "calls",
                                "alternate-rust-provider",
                                "1.0.0",
                                crate::code_intel_domain::CapabilityScope::Language {
                                    language_id: crate::code_intel_domain::LanguageId::new("rust"),
                                    configuration_id:
                                        crate::code_intel_domain::ConfigurationId::new(
                                            crate::code_intel_domain::CALLS_CONFIGURATION_ID,
                                        ),
                                },
                                "e".repeat(64),
                            ),
                        );
                        original.documents = vec![crate::code_intel_payload::ProviderDocument {
                            document_path: "src/lib.rs".into(),
                            language_id: crate::code_intel_domain::LanguageId::new("rust"),
                            content_sha256: "c".repeat(64),
                            cross_document_surface_sha256: "a".repeat(64),
                            byte_length: 12,
                        }];
                        original
                    }),
                ],
            )
            .is_none(),
            "conflicting persisted surface authority must fail closed"
        );
    }

    /// RIGHT-REASON REGRESSION: capability downgrade is publication
    /// permission, not a request to replace an exact current generation.
    /// `force` is the only ordinary control that demands a fresh generation.
    #[tokio::test]
    async fn capability_downgrade_authority_does_not_disable_exact_reuse() {
        let temporary = tempfile::tempdir().expect("temporary workspace");
        let root = temporary.path().join("repo");
        let graph = temporary.path().join("graph");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"reuse-permission\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest fixture");
        std::fs::write(
            root.join("src/lib.rs"),
            "pub fn exact_current_generation() {}\n",
        )
        .expect("source fixture");

        let binding = ProjectBinding::explicit(&root, &graph).expect("explicit binding");
        let seed = BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("prepare seed")
            .publish()
            .await
            .expect("publish seed");

        let reused = BoundIndexPlan::prepare(
            &binding,
            BoundIndexRequest {
                capability_floor: CapabilityFloorPolicy::AllowDowngrade,
                ..BoundIndexRequest::default()
            },
        )
        .expect("prepare permissive request")
        .publish()
        .await
        .expect("reuse exact current generation");

        assert!(
            reused.telemetry.reused_generation,
            "downgrade authority alone must not manufacture a fresh generation"
        );
        assert_eq!(
            reused.publication.manifest.generation_id, seed.publication.manifest.generation_id,
            "exact current evidence must remain the visible generation"
        );
    }

    /// PERFORMANCE FALSIFIER: exact reuse already validates the complete
    /// immutable generation while preparing the read-only snapshot. The
    /// terminal linearization check must inspect only the bounded publication
    /// controls; repeating `resolve_generation` on the async caller thread
    /// hashes and reparses the same generation a second time.
    #[tokio::test(flavor = "current_thread")]
    async fn exact_reuse_does_not_repeat_full_validation_at_linearization() {
        let temporary = tempfile::tempdir().expect("temporary workspace");
        let root = temporary.path().join("repo");
        let graph = temporary.path().join("graph");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"single-validation\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest fixture");
        std::fs::write(root.join("src/lib.rs"), "pub fn exact_once() {}\n")
            .expect("source fixture");

        let binding = ProjectBinding::explicit(&root, &graph).expect("explicit binding");
        let seed = BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("prepare seed")
            .publish()
            .await
            .expect("publish seed");

        reset_generations_validated();
        let positive = resolve_generation(&graph, &root).expect("positive validation control");
        assert_eq!(
            positive.manifest.generation_id,
            seed.publication.manifest.generation_id
        );
        assert_eq!(
            generations_validated(),
            1,
            "positive control: a caller-thread resolution must register one full validation"
        );

        reset_generations_validated();
        let reused = BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("prepare exact reuse")
            .publish()
            .await
            .expect("reuse exact generation");
        assert!(reused.telemetry.reused_generation);
        assert_eq!(
            reused.publication.manifest.generation_id, seed.publication.manifest.generation_id,
            "reuse must return the identical validated generation"
        );
        assert_eq!(
            generations_validated(),
            0,
            "the terminal reuse check repeated full generation validation on the caller thread"
        );
        let summary = reused
            .telemetry
            .phase_timings
            .iter()
            .find(|timing| timing.label == "checking current generation")
            .expect("exact-reuse summary timing");
        assert_eq!(
            summary.aggregation,
            IndexTimingAggregation::ConcurrentSpan,
            "the total reuse span must not be addable beside its nested exclusive stages"
        );
        let stages = reused
            .telemetry
            .phase_timings
            .iter()
            .filter(|timing| timing.aggregation == IndexTimingAggregation::Exclusive)
            .map(|timing| timing.label.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            stages,
            [
                "reuse publication control resolution",
                "reuse generation identity validation",
                "reuse immutable database digest",
                "reuse generation manifest validation",
                "reuse project inventory validation",
                "reuse provider payload validation",
                "reuse generation cross-authority validation",
                "reuse authenticated generation hydration",
                "reuse capability admission",
                "reuse complete source and inventory validation",
                "reuse control linearization",
                "reuse reachability summary",
            ],
            "a successful structural reuse must expose every disjoint admission cost"
        );
        assert!(
            reused
                .telemetry
                .phase_timings
                .iter()
                .all(|timing| timing.duration <= reused.telemetry.duration),
            "nested timing controls must remain bounded by the measured operation"
        );
    }

    /// PERFORMANCE FALSIFIER: native WATCH paths are bounded hints, never
    /// complete source authority. A byte-different path that already belongs
    /// to the immutable indexed population can nevertheless prove that exact
    /// reuse is impossible without rediscovering and hashing the repository.
    /// Inconclusive and spurious hints must retain the complete fallback.
    #[tokio::test(flavor = "current_thread")]
    async fn changed_indexed_hint_short_circuits_only_the_impossible_reuse_case() {
        let temporary = tempfile::tempdir().expect("temporary workspace");
        let root = temporary.path().join("repo");
        let graph = temporary.path().join("graph");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"hinted-reuse\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        let source = root.join("src/lib.rs");
        std::fs::write(&source, "pub fn first() {}\n").expect("initial source");

        let binding = ProjectBinding::explicit(&root, &graph).expect("explicit binding");
        let source = binding.root().join("src/lib.rs");
        BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("prepare seed")
            .publish()
            .await
            .expect("publish seed");

        std::fs::write(&source, "pub fn second() {}\n").expect("hinted source change");
        let hinted = BoundIndexPlan::prepare_with_toolchain_resolver(
            &binding,
            BoundIndexRequest::default(),
            None,
            Arc::from([source.clone()]),
        )
        .expect("prepare hinted refresh")
        .publish()
        .await
        .expect("publish hinted refresh");
        assert_eq!(
            hinted.telemetry.files_changed, 1,
            "positive changed-file control"
        );
        assert!(
            !hinted
                .telemetry
                .phase_timings
                .iter()
                .any(|timing| { timing.label == "reuse complete source and inventory validation" }),
            "a byte-different indexed hint already proves exact reuse impossible"
        );

        std::fs::write(&source, "pub fn third() {}\n").expect("unhinted source change");
        let unhinted = BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("prepare unhinted refresh")
            .publish()
            .await
            .expect("publish unhinted refresh");
        assert_eq!(unhinted.telemetry.files_changed, 1);
        assert!(
            unhinted
                .telemetry
                .phase_timings
                .iter()
                .any(|timing| { timing.label == "reuse complete source and inventory validation" }),
            "positive fallback control: an unhinted operation requires complete verification"
        );

        let readme = root.join("README.md");
        std::fs::write(&readme, "non-source watch noise\n").expect("spurious hint fixture");
        let spurious = BoundIndexPlan::prepare_with_toolchain_resolver(
            &binding,
            BoundIndexRequest::default(),
            None,
            Arc::from([readme]),
        )
        .expect("prepare spurious hint probe")
        .publish()
        .await
        .expect("reuse through spurious hint");
        assert!(
            spurious.telemetry.reused_generation,
            "an unrelated hint must not manufacture a fresh generation"
        );
        assert!(
            spurious
                .telemetry
                .phase_timings
                .iter()
                .any(|timing| { timing.label == "reuse complete source and inventory validation" }),
            "an inconclusive hint must fall through to complete verification"
        );
    }

    /// PERFORMANCE FALSIFIER: if the immutable current generation cannot
    /// satisfy a stronger provider request, complete live-source freshness is
    /// irrelevant to that negative admission decision. Immutable generation
    /// and graph authority must still be validated; only the needless full
    /// repository discovery/hash pass may be skipped.
    #[tokio::test(flavor = "current_thread")]
    async fn missing_provider_capability_rejects_reuse_before_complete_source_scan() {
        let temporary = tempfile::tempdir().expect("temporary workspace");
        let root = temporary.path().join("repo");
        let graph = temporary.path().join("graph");
        std::fs::create_dir_all(&root).expect("source directory");
        std::fs::write(
            root.join("go.mod"),
            "module example.com/capability\n\ngo 1.27\n",
        )
        .expect("Go manifest");
        std::fs::write(
            root.join("main.go"),
            "package main\nfunc helper() {}\nfunc main() { helper() }\n",
        )
        .expect("Go source");

        let binding = ProjectBinding::explicit(&root, &graph).expect("explicit binding");
        BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("prepare structural seed")
            .publish()
            .await
            .expect("publish structural seed");

        let exact_structural = BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("prepare exact structural reuse")
            .publish()
            .await
            .expect("reuse structural generation");
        assert!(exact_structural.telemetry.reused_generation);
        assert!(
            exact_structural
                .telemetry
                .phase_timings
                .iter()
                .any(|timing| { timing.label == "reuse complete source and inventory validation" }),
            "positive control: an otherwise admissible generation still requires complete source freshness"
        );

        let semantic = BoundIndexPlan::prepare(
            &binding,
            BoundIndexRequest {
                providers: ProviderIntent::Refresh,
                ..BoundIndexRequest::default()
            },
        )
        .expect("prepare stronger semantic request")
        .publish()
        .await
        .expect("publish semantic attempt");
        assert!(
            !semantic.telemetry.reused_generation,
            "positive control: structural evidence cannot satisfy an available Go provider request"
        );
        assert!(
            !semantic
                .telemetry
                .phase_timings
                .iter()
                .any(|timing| { timing.label == "reuse complete source and inventory validation" }),
            "known-ineligible provider evidence must reject reuse before complete source scanning"
        );
    }

    /// PERFORMANCE FALSIFIER: the shipped stale-input path must carry the
    /// reuse probe's fully validated current generation into writer admission.
    /// Final publication independently rechecks the locked head and exact
    /// database digest, so no second full parse is required when both remain
    /// byte-identical.
    #[tokio::test(flavor = "current_thread")]
    async fn stale_bound_plan_reuses_prevalidated_current_at_writer_admission() {
        let temporary = tempfile::tempdir().expect("temporary workspace");
        let root = temporary.path().join("repo");
        let graph = temporary.path().join("graph");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"admission-handoff\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        let source = root.join("src/lib.rs");
        std::fs::write(&source, "pub fn before() {}\n").expect("initial source");

        let binding = ProjectBinding::explicit(&root, &graph).expect("explicit binding");
        let seed = BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("prepare seed")
            .publish()
            .await
            .expect("publish seed");

        reset_generations_validated();
        let resolved = resolve_generation(&graph, &root).expect("positive validation control");
        assert_eq!(
            generations_validated(),
            1,
            "positive control: the counter must observe a full generation validation"
        );
        assert_eq!(
            resolved.manifest.generation_id,
            seed.publication.manifest.generation_id
        );

        std::fs::write(&source, "pub fn after() {}\n").expect("stale source update");
        reset_generations_validated();
        let refreshed = BoundIndexPlan::prepare(&binding, BoundIndexRequest::default())
            .expect("prepare stale-input refresh")
            .publish()
            .await
            .expect("publish stale-input refresh");

        assert!(!refreshed.telemetry.reused_generation);
        assert_eq!(refreshed.telemetry.files_changed, 1);
        assert_ne!(
            refreshed.publication.manifest.generation_id, seed.publication.manifest.generation_id,
            "positive control: the stale source must publish a new generation"
        );
        assert_eq!(
            generations_validated(),
            0,
            "the publishing thread repeated full generation validation after exact preflight, locked-head, and database-digest agreement"
        );
        let reuse_summary = refreshed
            .telemetry
            .phase_timings
            .iter()
            .find(|timing| timing.label == "checking current generation")
            .expect("stale-source reuse summary timing");
        assert_eq!(
            reuse_summary.aggregation,
            IndexTimingAggregation::ConcurrentSpan,
            "the miss-path summary must become non-additive when detailed stages are retained"
        );
        let reuse_stages = refreshed
            .telemetry
            .phase_timings
            .iter()
            .filter(|timing| {
                timing.phase == IndexProgressPhase::Reuse
                    && timing.aggregation == IndexTimingAggregation::Exclusive
            })
            .map(|timing| timing.label.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            reuse_stages,
            [
                "reuse publication control resolution",
                "reuse generation identity validation",
                "reuse immutable database digest",
                "reuse generation manifest validation",
                "reuse project inventory validation",
                "reuse provider payload validation",
                "reuse generation cross-authority validation",
                "reuse authenticated generation hydration",
                "reuse capability admission",
                "reuse complete source and inventory validation",
            ],
            "a stale-source miss must retain the exact completed reuse stage instead of hiding its cost in an opaque summary"
        );
    }
}
