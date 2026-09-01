//! Authority-qualified dead-code candidates over one immutable generation.
//!
//! Dead v2 deliberately separates two populations that the earlier surface
//! conflated. Callable liveness is monotonically reconciled with the canonical
//! provider Calls graph. Non-callable structural candidates remain visible, but
//! carry a qualified verdict and never inherit callable or deletion authority.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::code_intel_callable_liveness::{
    PublishedCallableLiveness, assess_callable_liveness_capability,
    capability_applies_to as callable_liveness_applies_to,
};
use crate::code_intel_calls::{
    ExactCapabilityAuthority, ExecutionRootClass, PublishedCallsGraph, assess_calls_capability,
    required_calls_documents_for_project_unit,
};
use crate::code_intel_cursor::{page_window, request_digest};
use crate::code_intel_domain::{
    AuthorityStatus, CapabilityCoverage, CapabilityCoverageStatus, CapabilityQualification,
    DomainError, ExecutionRootContext, GenerationId, LanguageCapabilityCoverage, LanguageId,
    MAX_GENERATION_ENGINE_RESULT_CHARS, Page, ProjectInventoryCoverage, ProjectUnitId,
    RepositoryBinding, UnitGraph, assess_structural_graph_capability,
};
use crate::code_intel_inventory::project_unit_graph;
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::{generation_file_context, language_id_for_path, repository_binding};
use crate::code_intel_symbol::{NameFileSelection, resolve_symbol_selector};
use crate::code_intel_type::{StructuralSymbol, structural_symbol};
use crate::graph::{GraphNode, KnowledgeGraph};
use crate::graph_query::is_test_file;
use crate::project_binding::ProjectBinding;
use crate::reachability::{ReachabilityClass, ReachabilityEvidence, ReachabilityRootSets};
use crate::structural_ir::{
    SymbolKind, SymbolRole, symbol_is_executable_callable_declaration, symbol_kind_has_role,
};

pub const DEAD_SCHEMA_VERSION: &str = "h00/code-intel/dead/v2";
pub const DEFAULT_DEAD_PAGE_SIZE: usize = 50;
pub const MAX_DEAD_PAGE_SIZE: usize = 100;
pub const MAX_DEAD_SYMBOL_BYTES: usize = 4_096;
pub const MAX_DEAD_FILE_BYTES: usize = 4_096;
pub const MAX_DEAD_CURSOR_BYTES: usize = 8_192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadRequest {
    pub symbol: Option<String>,
    pub file: Option<String>,
    pub production_only: bool,
    pub limit: usize,
    pub cursor: Option<String>,
}

impl Default for DeadRequest {
    fn default() -> Self {
        Self {
            symbol: None,
            file: None,
            production_only: false,
            limit: DEFAULT_DEAD_PAGE_SIZE,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeadQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    pub production_only: bool,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadVerdict {
    LiveProduction,
    LiveTest,
    /// No call or callable-value-binding path from a retained production or
    /// test root was observed in the complete provider-backed liveness
    /// population. This is a review candidate, not proof that runtime dispatch
    /// can never reach the symbol.
    UnreachedCallable,
    /// Persisted structural analysis nominated a non-callable symbol, but the
    /// provider Calls population cannot prove structural deadness.
    StructuralCandidate,
    RetainedStructural,
    Excluded,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadEvidenceStatus {
    Complete,
    Qualified,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadEvidenceBasis {
    ProviderCallableLiveness,
    ProviderCallsReconciled,
    PersistedStructuralReachability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadRecommendation {
    Keep,
    Review,
    Withheld,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeadItemEvidence {
    pub status: DeadEvidenceStatus,
    pub basis: DeadEvidenceBasis,
    pub reason_code: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeadItem {
    pub symbol: StructuralSymbol,
    pub callable: bool,
    pub persisted_reachability: ReachabilityClass,
    pub verdict: DeadVerdict,
    /// Whether an exact provider call path reaches this callable from a retained
    /// production or test root. `null` means the fact is unavailable or does
    /// not apply to this non-callable item.
    pub reachable_from_retained_root: Option<bool>,
    pub recommendation: DeadRecommendation,
    pub evidence: DeadItemEvidence,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DeadSummary {
    /// Items evaluated before paging. An exact-symbol query can observe a live
    /// item that is not a candidate.
    pub observed_items: usize,
    /// Items that would appear in the full candidate report, including unknown
    /// residuals whose recommendation is withheld.
    pub candidate_items: usize,
    pub unreached_callables: usize,
    pub qualified_structural_candidates: usize,
    pub unknown_candidates: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeadLanguageAuthority {
    pub language_id: LanguageId,
    pub status: DeadEvidenceStatus,
    pub unjoined_source_callables: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calls: Option<ExactCapabilityAuthority>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callable_liveness: Option<LanguageCapabilityCoverage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeadAuthority {
    pub status: AuthorityStatus,
    pub population: String,
    pub calls: CapabilityCoverage,
    pub callable_liveness: CapabilityCoverage,
    pub structural_graph: CapabilityCoverage,
    pub project_inventory_coverage: ProjectInventoryCoverage,
    pub reachability_evidence_schema: String,
    pub callable_population_complete: bool,
    pub structural_candidates_qualified: bool,
    pub item_evidence_complete: bool,
    pub population_complete: bool,
    pub languages: Vec<DeadLanguageAuthority>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExactDeadResult {
    pub schema_version: String,
    pub capability: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub unit_graph: UnitGraph,
    pub query: DeadQuery,
    pub authority: DeadAuthority,
    pub summary: DeadSummary,
    pub items: Vec<DeadItem>,
    pub page: Page,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub fn validate_dead_request(request: &DeadRequest) -> Result<(), DomainError> {
    if let Some(symbol) = request.symbol.as_deref() {
        if symbol.trim().is_empty() {
            return Err(invalid_request("symbol", "must not be empty"));
        }
        if symbol.len() > MAX_DEAD_SYMBOL_BYTES {
            return Err(invalid_request(
                "symbol",
                format!("must be at most {MAX_DEAD_SYMBOL_BYTES} UTF-8 bytes"),
            ));
        }
    }
    if let Some(file) = request.file.as_deref() {
        if request.symbol.is_none() {
            return Err(invalid_request("file", "requires a symbol"));
        }
        if file.trim().is_empty() {
            return Err(invalid_request("file", "must not be empty"));
        }
        if file.len() > MAX_DEAD_FILE_BYTES {
            return Err(invalid_request(
                "file",
                format!("must be at most {MAX_DEAD_FILE_BYTES} UTF-8 bytes"),
            ));
        }
    }
    if !(1..=MAX_DEAD_PAGE_SIZE).contains(&request.limit) {
        return Err(invalid_request(
            "limit",
            format!("must be between 1 and {MAX_DEAD_PAGE_SIZE}"),
        ));
    }
    if request
        .cursor
        .as_ref()
        .is_some_and(|cursor| cursor.len() > MAX_DEAD_CURSOR_BYTES)
    {
        return Err(invalid_request(
            "cursor",
            format!("must be at most {MAX_DEAD_CURSOR_BYTES} UTF-8 bytes"),
        ));
    }
    if request.symbol.is_some() && request.cursor.is_some() {
        return Err(invalid_request(
            "cursor",
            "is only valid for the full candidate report",
        ));
    }
    if request.symbol.is_some() && request.production_only {
        return Err(invalid_request(
            "production_only",
            "is only valid for the full candidate report",
        ));
    }
    Ok(())
}

struct CallableLiveness {
    basis: DeadEvidenceBasis,
    negative_authority_complete: bool,
    negative_reason_code: String,
    negative_reason: String,
    mapped: BTreeSet<Uuid>,
    excluded: BTreeMap<Uuid, Vec<String>>,
    production: BTreeSet<Uuid>,
    tests: BTreeSet<Uuid>,
    qualified_production: BTreeSet<Uuid>,
    qualified_tests: BTreeSet<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectUnitCallableVerdict {
    LiveProduction,
    LiveTest,
    QualifiedLiveProduction,
    QualifiedLiveTest,
    RetainedTest,
    Unreached,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectUnitCallableItem {
    pub memory_id: Uuid,
    pub verdict: ProjectUnitCallableVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectUnitCallableLiveness {
    pub items: Vec<ProjectUnitCallableItem>,
}

impl ProjectUnitCallableLiveness {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.items.iter().all(|item| {
            !matches!(
                item.verdict,
                ProjectUnitCallableVerdict::Unknown
                    | ProjectUnitCallableVerdict::QualifiedLiveProduction
                    | ProjectUnitCallableVerdict::QualifiedLiveTest
            )
        })
    }

    #[must_use]
    pub fn count(&self, verdict: ProjectUnitCallableVerdict) -> usize {
        self.items
            .iter()
            .filter(|item| item.verdict == verdict)
            .count()
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CallableRootSets {
    production: BTreeSet<Uuid>,
    tests: BTreeSet<Uuid>,
}

pub(crate) fn callable_root_sets(
    graph: &KnowledgeGraph,
    reachability: &ReachabilityEvidence,
) -> Result<CallableRootSets, DomainError> {
    reachability.validate(graph).map_err(|error| {
        invalid_generation(format!(
            "callable liveness requires generation-local reachability evidence: {error}"
        ))
    })?;
    Ok(callable_root_sets_from_resolved(
        reachability.analyzer(graph).resolved_roots(),
    ))
}

fn callable_root_sets_from_resolved(roots: ReachabilityRootSets) -> CallableRootSets {
    let mut production = roots.production.into_iter().collect::<BTreeSet<_>>();
    production.extend(roots.public_api);
    CallableRootSets {
        production,
        tests: roots.tests.into_iter().collect(),
    }
}

/// Query one immutable publication.
///
/// Persisted reachability evidence supplies typed entry-point provenance;
/// structural root facts are resolved without consulting per-node persisted
/// reachability labels. Exact provider Calls edges then establish liveness or
/// bounded negative evidence. An unrooted caller or cycle cannot make itself
/// live.
pub fn query_published_dead(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    reachability: &ReachabilityEvidence,
    request: &DeadRequest,
) -> Result<ExactDeadResult, DomainError> {
    validate_dead_request(request)?;
    reachability.validate(graph).map_err(|error| {
        invalid_generation(format!(
            "Dead requires generation-local reachability evidence: {error}"
        ))
    })?;

    let normalized_file = request
        .file
        .as_deref()
        .map(|file| generation_file_context(binding, file))
        .transpose()?
        .map(|context| context.file_path().to_owned());
    let selected = request
        .symbol
        .as_deref()
        .map(|symbol| resolve_target(graph, generation, symbol, normalized_file.as_deref()))
        .transpose()?;

    let calls_coverage = assess_calls_capability(
        graph,
        &generation.manifest.receipts,
        &generation.provider_payloads,
        &generation.project_inventory,
    );
    let callable_liveness_coverage = assess_callable_liveness_capability(
        graph,
        &generation.manifest.receipts,
        &generation.provider_payloads,
        &generation.project_inventory,
    );
    let structural_coverage = assess_structural_graph_capability(
        graph,
        &generation.manifest.receipts,
        &generation.project_inventory,
    );
    let roots = callable_root_sets_from_resolved(reachability.analyzer(graph).resolved_roots());

    let mut languages = graph
        .all_nodes()
        .into_iter()
        .filter(|node| symbol_kind_has_role(&node.kind, SymbolRole::Callable))
        .map(|node| language_id_for_path(&node.file_path))
        .collect::<BTreeSet<_>>();
    if let Some(target) = selected {
        languages.retain(|language| *language == language_id_for_path(&target.file_path));
    }
    let selected_languages = languages.clone();

    let mut liveness = BTreeMap::new();
    let mut missing_liveness_basis = BTreeMap::new();
    let mut language_authorities = Vec::new();
    let mut selected_calls_coverage = None;
    let mut selected_callable_liveness_coverage = None;
    for language in languages {
        let all_source_documents = generation
            .project_inventory
            .project_topology
            .memberships
            .iter()
            .filter(|membership| {
                membership.language_id == language
                    && generation
                        .project_inventory
                        .is_semantic_source_owner(membership)
            })
            .map(|membership| membership.document_path.as_str())
            .collect::<BTreeSet<_>>();
        let selected_target =
            selected.filter(|target| language_id_for_path(&target.file_path) == language);

        let language_calls_status = calls_coverage.language_status(&language.0);
        let calls_cannot_resolve = match selected_target {
            Some(_) => matches!(
                language_calls_status,
                None | Some(CapabilityCoverageStatus::Unavailable)
                    | Some(CapabilityCoverageStatus::NotApplicable)
            ),
            None => !calls_coverage.language_is_usable(&language.0),
        };
        let calls = if calls_cannot_resolve {
            None
        } else {
            Some(match selected_target {
                Some(target) => {
                    PublishedCallsGraph::build_for_target(graph, generation, &language, target)?
                }
                None => PublishedCallsGraph::build(graph, generation, &language)?,
            })
        };
        let calls_authority = calls.as_ref().map(PublishedCallsGraph::authority);
        if selected_target.is_some() {
            selected_calls_coverage = Some(calls_authority.as_ref().map_or_else(
                || selected_language_coverage(&calls_coverage, &language),
                |authority| scoped_calls_coverage(&language, authority),
            ));
        }

        let native_liveness = if callable_liveness_applies_to(&language) {
            let result = selected_target.map_or_else(
                || PublishedCallableLiveness::build(graph, generation, &language),
                |target| {
                    PublishedCallableLiveness::build_for_target(
                        graph, generation, &language, target,
                    )
                },
            );
            match result {
                Ok(published) => Some(published),
                Err(DomainError::CapabilityUnavailable { .. })
                | Err(DomainError::CapabilityNotApplicable { .. }) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        let native_coverage = native_liveness
            .as_ref()
            .map(PublishedCallableLiveness::language_coverage)
            .or_else(|| {
                callable_liveness_coverage
                    .languages
                    .iter()
                    .find(|coverage| coverage.language_id == language)
                    .cloned()
            });
        if selected_target.is_some() && callable_liveness_applies_to(&language) {
            selected_callable_liveness_coverage = Some(CapabilityCoverage {
                capability_id: "callable_liveness".into(),
                status: native_coverage
                    .as_ref()
                    .map_or(CapabilityCoverageStatus::Unavailable, |coverage| {
                        coverage.status
                    }),
                languages: native_coverage.iter().cloned().collect(),
            });
        }

        let (language_liveness, unjoined_source_callables, status, reason) = if let Some(native) =
            native_liveness
        {
            let coverage = native.language_coverage();
            let status = evidence_status(coverage.status);
            let reason = language_coverage_reason(&coverage);
            let unjoined = native.unjoined_source_callables();
            (
                reconcile_provider_callable_liveness(&native),
                unjoined,
                status,
                reason,
            )
        } else if let Some(calls) = calls.as_ref() {
            let (language_liveness, unjoined) = reconcile_callable_liveness(
                graph,
                calls,
                &language,
                &roots,
                calls.required_source_documents(),
            );
            let status = if language_liveness.negative_authority_complete {
                DeadEvidenceStatus::Complete
            } else {
                DeadEvidenceStatus::Qualified
            };
            let reason = (!language_liveness.negative_authority_complete)
                .then(|| language_liveness.negative_reason.clone());
            (language_liveness, unjoined, status, reason)
        } else {
            let expected_source_callables = graph
                .all_nodes()
                .into_iter()
                .filter(|node| {
                    (if callable_liveness_applies_to(&language) {
                        symbol_is_executable_callable_declaration(&node.kind, node.has_body)
                    } else {
                        symbol_kind_has_role(&node.kind, SymbolRole::Callable)
                    }) && language_id_for_path(&node.file_path) == language
                        && all_source_documents.contains(node.file_path.as_str())
                })
                .count();
            let basis = if callable_liveness_applies_to(&language) {
                DeadEvidenceBasis::ProviderCallableLiveness
            } else {
                DeadEvidenceBasis::ProviderCallsReconciled
            };
            missing_liveness_basis.insert(language.clone(), basis);
            language_authorities.push(DeadLanguageAuthority {
                language_id: language,
                status: DeadEvidenceStatus::Unavailable,
                unjoined_source_callables: expected_source_callables,
                calls: None,
                callable_liveness: native_coverage.clone(),
                reason: Some(
                    language_coverage_reason_opt(native_coverage.as_ref()).unwrap_or_else(|| {
                        "no complete provider evidence covers this callable population".into()
                    }),
                ),
            });
            continue;
        };

        language_authorities.push(DeadLanguageAuthority {
            language_id: language.clone(),
            status,
            unjoined_source_callables,
            calls: calls_authority,
            callable_liveness: native_coverage,
            reason,
        });
        liveness.insert(language, language_liveness);
    }

    let source_nodes = selected.map_or_else(|| graph.all_nodes(), |target| vec![target]);
    let mut items = Vec::new();
    for node in source_nodes {
        if request.symbol.is_none() && request.production_only && node_is_test_population(node) {
            continue;
        }
        let item = dead_item(graph, generation, node, &liveness, &missing_liveness_basis)?;
        if request.symbol.is_some() || item_is_full_candidate(&item) {
            items.push(item);
        }
    }
    items.sort_by(|left, right| {
        (
            left.symbol.document_path.as_str(),
            left.symbol.name.as_str(),
            left.symbol.kind.as_str(),
            left.symbol.symbol_id.as_str(),
        )
            .cmp(&(
                right.symbol.document_path.as_str(),
                right.symbol.name.as_str(),
                right.symbol.kind.as_str(),
                right.symbol.symbol_id.as_str(),
            ))
    });

    let summary = summarize(&items);
    let structural_candidates_qualified = items
        .iter()
        .any(|item| item.verdict == DeadVerdict::StructuralCandidate);
    let item_evidence_complete = items
        .iter()
        .all(|item| item.evidence.status == DeadEvidenceStatus::Complete);
    let callable_population_complete = language_authorities
        .iter()
        .all(|language| language.status == DeadEvidenceStatus::Complete);
    let inventory_coverage = generation
        .project_inventory
        .coverage_for_languages(&selected_languages);
    let inventory_complete =
        inventory_coverage == ProjectInventoryCoverage::IndexedSourcePopulationComplete;
    let structural_complete = selected_languages.iter().all(|language| {
        structural_coverage.language_status(&language.0) == Some(CapabilityCoverageStatus::Complete)
    });
    let population_complete = callable_population_complete
        && inventory_complete
        && structural_complete
        && item_evidence_complete;
    let authority = DeadAuthority {
        status: if population_complete {
            AuthorityStatus::Complete
        } else {
            AuthorityStatus::Qualified
        },
        population: "exact provider calls and callable-value bindings from generation-local production/public/test roots; structural-only conclusions are qualified"
            .into(),
        calls: selected_calls_coverage.unwrap_or(calls_coverage),
        callable_liveness: selected_callable_liveness_coverage
            .unwrap_or(callable_liveness_coverage),
        structural_graph: structural_coverage,
        project_inventory_coverage: inventory_coverage,
        reachability_evidence_schema: reachability.schema.clone(),
        callable_population_complete,
        structural_candidates_qualified,
        item_evidence_complete,
        population_complete,
        languages: language_authorities,
    };

    let digest = request_digest(
        "dead",
        &[
            request.symbol.as_deref().unwrap_or_default(),
            normalized_file.as_deref().unwrap_or_default(),
            if request.production_only {
                "production"
            } else {
                "all"
            },
        ],
    );
    let mut smallest_result_chars = 0;
    for effective_limit in (1..=request.limit).rev() {
        let window = page_window(
            "dead",
            &generation.manifest.generation_id,
            &digest,
            request.cursor.as_deref(),
            effective_limit,
            items.len(),
        )?;
        let page_items = items[window.range.clone()].to_vec();
        let mut warnings = base_warnings(&authority, effective_limit, request.limit, &window.page);
        if request.symbol.is_some() && page_items.is_empty() {
            warnings.push("the selected symbol is outside the requested candidate page".into());
        }
        let result = ExactDeadResult {
            schema_version: DEAD_SCHEMA_VERSION.into(),
            capability: "dead".into(),
            generation_id: generation.manifest.generation_id.clone(),
            repository: repository_binding(binding, generation),
            unit_graph: project_unit_graph(
                &generation.project_inventory,
                page_items
                    .iter()
                    .filter(|item| item.symbol.source_backed)
                    .map(|item| item.symbol.document_path.as_str()),
            ),
            query: DeadQuery {
                symbol: request.symbol.clone(),
                file: normalized_file.clone(),
                production_only: request.production_only,
                limit: request.limit,
            },
            authority: authority.clone(),
            summary: summary.clone(),
            items: page_items,
            page: window.page,
            warnings,
        };
        let result_chars = serde_json::to_string(&result)
            .map_err(|error| invalid_generation(format!("serialize Dead result: {error}")))?
            .chars()
            .count();
        smallest_result_chars = result_chars;
        if result_chars <= MAX_GENERATION_ENGINE_RESULT_CHARS {
            return Ok(result);
        }
    }
    Err(DomainError::result_too_large(
        "dead",
        smallest_result_chars,
        MAX_GENERATION_ENGINE_RESULT_CHARS,
        "Narrow the symbol, file, or candidate scope; required Dead authority and summary metadata do not fit even when the page limit is one",
    ))
}

fn scoped_calls_coverage(
    language_id: &LanguageId,
    authority: &ExactCapabilityAuthority,
) -> CapabilityCoverage {
    let status = if authority.status == AuthorityStatus::Complete {
        CapabilityCoverageStatus::Complete
    } else {
        CapabilityCoverageStatus::Qualified
    };
    CapabilityCoverage {
        capability_id: "calls".into(),
        status,
        languages: vec![LanguageCapabilityCoverage {
            language_id: language_id.clone(),
            status,
            provider_id: Some(authority.provider_id.clone()),
            gaps: Vec::new(),
            qualifications: authority
                .coverage_exclusions
                .iter()
                .map(|exclusion| CapabilityQualification {
                    provider_id: authority.provider_id.clone(),
                    reason_code: exclusion.reason_code.clone(),
                    reason: format!(
                        "provider evidence excludes {} source region(s) across {} document(s) in the selected possible-caller population",
                        exclusion.region_count, exclusion.document_count
                    ),
                })
                .collect(),
        }],
    }
}

fn selected_language_coverage(
    coverage: &CapabilityCoverage,
    language_id: &LanguageId,
) -> CapabilityCoverage {
    let languages = coverage
        .languages
        .iter()
        .filter(|language| language.language_id == *language_id)
        .cloned()
        .collect::<Vec<_>>();
    let status = languages
        .first()
        .map_or(CapabilityCoverageStatus::Unavailable, |language| {
            language.status
        });
    CapabilityCoverage {
        capability_id: coverage.capability_id.clone(),
        status,
        languages,
    }
}

const fn evidence_status(status: CapabilityCoverageStatus) -> DeadEvidenceStatus {
    match status {
        CapabilityCoverageStatus::Complete => DeadEvidenceStatus::Complete,
        CapabilityCoverageStatus::Qualified | CapabilityCoverageStatus::Partial => {
            DeadEvidenceStatus::Qualified
        }
        CapabilityCoverageStatus::NotApplicable | CapabilityCoverageStatus::Unavailable => {
            DeadEvidenceStatus::Unavailable
        }
    }
}

fn language_coverage_reason(coverage: &LanguageCapabilityCoverage) -> Option<String> {
    let mut reasons = coverage
        .gaps
        .iter()
        .map(|gap| format!("{}: {}", gap.reason_code, gap.reason))
        .chain(coverage.qualifications.iter().map(|qualification| {
            format!("{}: {}", qualification.reason_code, qualification.reason)
        }))
        .collect::<Vec<_>>();
    reasons.sort();
    reasons.dedup();
    (!reasons.is_empty()).then(|| reasons.join("; "))
}

fn language_coverage_reason_opt(coverage: Option<&LanguageCapabilityCoverage>) -> Option<String> {
    coverage.and_then(language_coverage_reason)
}

fn resolve_target<'a>(
    graph: &'a KnowledgeGraph,
    generation: &ResolvedGeneration,
    symbol: &str,
    file: Option<&str>,
) -> Result<&'a GraphNode, DomainError> {
    resolve_symbol_selector(graph, generation, symbol, file, NameFileSelection::Locality)
}

pub(crate) struct ProjectUnitCallableLivenessResolver<'a> {
    graph: &'a KnowledgeGraph,
    generation: &'a ResolvedGeneration,
    roots: &'a CallableRootSets,
    full_language_native: BTreeMap<LanguageId, Option<PublishedCallableLiveness>>,
    full_language_calls: BTreeMap<LanguageId, Option<PublishedCallsGraph>>,
}

impl<'a> ProjectUnitCallableLivenessResolver<'a> {
    #[must_use]
    pub const fn new(
        graph: &'a KnowledgeGraph,
        generation: &'a ResolvedGeneration,
        roots: &'a CallableRootSets,
    ) -> Self {
        Self {
            graph,
            generation,
            roots,
            full_language_native: BTreeMap::new(),
            full_language_calls: BTreeMap::new(),
        }
    }

    pub fn resolve(
        &mut self,
        project_unit_id: &ProjectUnitId,
    ) -> Result<ProjectUnitCallableLiveness, DomainError> {
        let unit = self
            .generation
            .project_inventory
            .project_topology
            .units
            .iter()
            .find(|unit| unit.project_unit_id == *project_unit_id)
            .ok_or_else(|| DomainError::ProjectInventoryMismatch {
                document_path: format!("<project unit {project_unit_id}>"),
                reason: "project unit is absent from the persisted inventory".into(),
            })?;
        let target_documents =
            project_unit_source_documents(self.generation, &unit.language_id, project_unit_id)?;
        let target_nodes = project_unit_callable_nodes(self.graph, &target_documents);
        if target_nodes.is_empty() {
            return Ok(ProjectUnitCallableLiveness { items: Vec::new() });
        }

        if callable_liveness_applies_to(&unit.language_id) {
            if !self.full_language_native.contains_key(&unit.language_id) {
                let full = match PublishedCallableLiveness::build(
                    self.graph,
                    self.generation,
                    &unit.language_id,
                ) {
                    Ok(published) => Some(published),
                    Err(DomainError::CapabilityUnavailable { .. })
                    | Err(DomainError::CapabilityNotApplicable { .. }) => None,
                    Err(error) => return Err(error),
                };
                self.full_language_native
                    .insert(unit.language_id.clone(), full);
            }
            if let Some(native) = self
                .full_language_native
                .get(&unit.language_id)
                .and_then(Option::as_ref)
            {
                return Ok(project_unit_liveness_from_native(native, target_nodes));
            }
            match PublishedCallableLiveness::build_for_project_unit(
                self.graph,
                self.generation,
                &unit.language_id,
                project_unit_id,
            ) {
                Ok(native) => {
                    return Ok(project_unit_liveness_from_native(&native, target_nodes));
                }
                Err(DomainError::CapabilityUnavailable { .. })
                | Err(DomainError::CapabilityNotApplicable { .. }) => {}
                Err(error) => return Err(error),
            }
        }

        if !self.full_language_calls.contains_key(&unit.language_id) {
            // A complete language projection is the fast path. If provider
            // selection or an unrelated unit prevents it, retain the original
            // exact per-unit build so partial multi-provider repositories and
            // isolated invalid populations still fail closed as before.
            let full =
                PublishedCallsGraph::build(self.graph, self.generation, &unit.language_id).ok();
            self.full_language_calls
                .insert(unit.language_id.clone(), full);
        }
        if let Some(calls) = self
            .full_language_calls
            .get(&unit.language_id)
            .and_then(Option::as_ref)
        {
            let required_documents = required_calls_documents_for_project_unit(
                &self.generation.project_inventory,
                &unit.language_id,
                project_unit_id,
            )?;
            calls.validate_possible_caller_documents(&required_documents)?;
            return project_unit_liveness_from_calls(
                self.graph,
                calls,
                &unit.language_id,
                self.roots,
                &required_documents,
                target_nodes,
            );
        }

        project_unit_callable_liveness_fallback(
            self.graph,
            self.generation,
            project_unit_id,
            self.roots,
        )
    }
}

fn project_unit_liveness_from_native(
    native: &PublishedCallableLiveness,
    target_nodes: Vec<&GraphNode>,
) -> ProjectUnitCallableLiveness {
    let mut items = target_nodes
        .into_iter()
        .map(|node| ProjectUnitCallableItem {
            memory_id: node.memory_id,
            verdict: native.record(&node.memory_id).map_or(
                ProjectUnitCallableVerdict::Unknown,
                |record| {
                    if record.production_reachable {
                        ProjectUnitCallableVerdict::LiveProduction
                    } else if record.test_reachable {
                        ProjectUnitCallableVerdict::LiveTest
                    } else {
                        ProjectUnitCallableVerdict::Unreached
                    }
                },
            ),
        })
        .collect::<Vec<_>>();
    items.sort_by_key(|item| item.memory_id);
    ProjectUnitCallableLiveness { items }
}

fn project_unit_callable_liveness_fallback(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    project_unit_id: &ProjectUnitId,
    roots: &CallableRootSets,
) -> Result<ProjectUnitCallableLiveness, DomainError> {
    let unit = generation
        .project_inventory
        .project_topology
        .units
        .iter()
        .find(|unit| unit.project_unit_id == *project_unit_id)
        .ok_or_else(|| DomainError::ProjectInventoryMismatch {
            document_path: format!("<project unit {project_unit_id}>"),
            reason: "project unit is absent from the persisted inventory".into(),
        })?;
    let target_documents =
        project_unit_source_documents(generation, &unit.language_id, project_unit_id)?;
    let target_nodes = project_unit_callable_nodes(graph, &target_documents);
    if target_nodes.is_empty() {
        return Ok(ProjectUnitCallableLiveness { items: Vec::new() });
    }

    let calls = match PublishedCallsGraph::build_for_project_unit(
        graph,
        generation,
        &unit.language_id,
        project_unit_id,
    ) {
        Ok(calls) => calls,
        Err(DomainError::CapabilityUnavailable { .. })
        | Err(DomainError::CapabilityNotApplicable { .. }) => {
            return Ok(ProjectUnitCallableLiveness {
                items: target_nodes
                    .into_iter()
                    .map(|node| ProjectUnitCallableItem {
                        memory_id: node.memory_id,
                        verdict: ProjectUnitCallableVerdict::Unknown,
                    })
                    .collect(),
            });
        }
        Err(error) => return Err(error),
    };
    project_unit_liveness_from_calls(
        graph,
        &calls,
        &unit.language_id,
        roots,
        calls.required_source_documents(),
        target_nodes,
    )
}

fn project_unit_source_documents(
    generation: &ResolvedGeneration,
    language_id: &LanguageId,
    project_unit_id: &ProjectUnitId,
) -> Result<BTreeSet<String>, DomainError> {
    let documents = generation
        .project_inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.project_unit_id == *project_unit_id
                && membership.language_id == *language_id
                && generation
                    .project_inventory
                    .is_semantic_source_owner(membership)
        })
        .map(|membership| membership.document_path.clone())
        .collect::<BTreeSet<_>>();
    if documents.is_empty() {
        return Err(DomainError::ProjectInventoryMismatch {
            document_path: format!("<project unit {project_unit_id}>"),
            reason: "project unit has no exact source-owner document population".into(),
        });
    }
    Ok(documents)
}

fn project_unit_callable_nodes<'a>(
    graph: &'a KnowledgeGraph,
    target_documents: &BTreeSet<String>,
) -> Vec<&'a GraphNode> {
    graph
        .all_nodes()
        .into_iter()
        .filter(|node| {
            symbol_kind_has_role(&node.kind, SymbolRole::Callable)
                && target_documents.contains(&node.file_path)
        })
        .collect()
}

fn project_unit_liveness_from_calls(
    graph: &KnowledgeGraph,
    calls: &PublishedCallsGraph,
    language_id: &LanguageId,
    roots: &CallableRootSets,
    required_documents: &BTreeSet<String>,
    target_nodes: Vec<&GraphNode>,
) -> Result<ProjectUnitCallableLiveness, DomainError> {
    let (liveness, _) =
        reconcile_callable_liveness(graph, calls, language_id, roots, required_documents);
    let mut items = target_nodes
        .into_iter()
        .map(|node| ProjectUnitCallableItem {
            memory_id: node.memory_id,
            verdict: project_unit_callable_verdict(node, &liveness),
        })
        .collect::<Vec<_>>();
    items.sort_by_key(|item| item.memory_id);
    Ok(ProjectUnitCallableLiveness { items })
}

fn reconcile_provider_callable_liveness(published: &PublishedCallableLiveness) -> CallableLiveness {
    let mapped = published
        .records()
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    let production = published
        .records()
        .filter(|(_, record)| record.production_reachable)
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    let tests = published
        .records()
        .filter(|(_, record)| record.test_reachable && !record.production_reachable)
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    let excluded = published
        .exclusions()
        .map(|(node_id, reasons)| (*node_id, reasons.to_vec()))
        .collect::<BTreeMap<_, _>>();
    CallableLiveness {
        basis: DeadEvidenceBasis::ProviderCallableLiveness,
        // Every joined record carries an explicit production/test RTA verdict.
        // Population-level gaps remain visible separately and do not erase a
        // mapped declaration's exact compiler result.
        negative_authority_complete: true,
        negative_reason_code: "callable_liveness_record_unavailable".into(),
        negative_reason: "this declaration has no joined compiler-native callable-liveness record"
            .into(),
        mapped,
        excluded,
        production,
        tests,
        qualified_production: BTreeSet::new(),
        qualified_tests: BTreeSet::new(),
    }
}

fn reconcile_callable_liveness(
    graph: &KnowledgeGraph,
    calls: &PublishedCallsGraph,
    language: &LanguageId,
    roots: &CallableRootSets,
    required_documents: &BTreeSet<String>,
) -> (CallableLiveness, usize) {
    let expected_source_callables = graph
        .all_nodes()
        .into_iter()
        .filter(|node| {
            symbol_kind_has_role(&node.kind, SymbolRole::Callable)
                && language_id_for_path(&node.file_path) == *language
                && required_documents.contains(&node.file_path)
        })
        .map(|node| node.memory_id)
        .collect::<BTreeSet<_>>();
    let mapped = calls
        .nodes()
        .filter(|node| required_documents.contains(&node.structural.file_path))
        .map(|node| node.structural.memory_id)
        .collect::<BTreeSet<_>>();
    let excluded = expected_source_callables
        .iter()
        .filter_map(|node_id| graph.node(node_id))
        .filter_map(|node| {
            let reasons = calls.coverage_exclusion_reason_codes(graph, node);
            (!reasons.is_empty()).then_some((node.memory_id, reasons))
        })
        .collect::<BTreeMap<_, _>>();
    let unjoined_source_callables =
        calls.unjoined_source_callable_count_in_documents(graph, language, required_documents);
    let negative_authority_complete = calls
        .negative_claims_are_complete_in_documents(required_documents)
        && unjoined_source_callables == 0;
    let (negative_reason_code, negative_reason) = if unjoined_source_callables > 0 {
        (
            "provider_population_join_incomplete".into(),
            format!(
                "{unjoined_source_callables} source-owned structural callable(s) have no joined provider definition; negative liveness claims are withheld for this language"
            ),
        )
    } else {
        (
            "provider_coverage_exclusions".into(),
            "provider exclusions make absence of a root path non-authoritative".into(),
        )
    };
    let mut production_seeds = BTreeSet::new();
    let mut test_seeds = BTreeSet::new();
    for node in calls.nodes() {
        let structural = &node.structural;
        if !required_documents.contains(&structural.file_path) {
            continue;
        }
        if roots.tests.contains(&structural.memory_id) {
            test_seeds.insert(structural.memory_id);
        } else if roots.production.contains(&structural.memory_id) {
            production_seeds.insert(structural.memory_id);
        }
    }
    let root_targets = |class, context| {
        calls
            .root_invocation_target_ids(class, context)
            .into_iter()
            .filter(|node_id| {
                graph
                    .node(node_id)
                    .is_some_and(|node| required_documents.contains(&node.file_path))
            })
            .collect::<BTreeSet<_>>()
    };
    production_seeds.extend(root_targets(
        ExecutionRootClass::Production,
        ExecutionRootContext::ModuleInitialization,
    ));
    test_seeds.extend(root_targets(
        ExecutionRootClass::Test,
        ExecutionRootContext::ModuleInitialization,
    ));
    let qualified_production_seeds = root_targets(
        ExecutionRootClass::Production,
        ExecutionRootContext::AnonymousCallable,
    );
    let qualified_test_seeds = root_targets(
        ExecutionRootClass::Test,
        ExecutionRootContext::AnonymousCallable,
    );

    let mut production = forward_reachable(graph, calls, &production_seeds, required_documents);
    let mut qualified_production = forward_reachable(
        graph,
        calls,
        &qualified_production_seeds,
        required_documents,
    );
    qualified_production.retain(|node_id| !production.contains(node_id));
    production.extend(qualified_production.iter().copied());

    let mut tests = forward_reachable(graph, calls, &test_seeds, required_documents);
    tests.retain(|node_id| !production.contains(node_id));
    let mut qualified_tests =
        forward_reachable(graph, calls, &qualified_test_seeds, required_documents);
    qualified_tests.retain(|node_id| !production.contains(node_id) && !tests.contains(node_id));
    tests.extend(qualified_tests.iter().copied());
    (
        CallableLiveness {
            basis: DeadEvidenceBasis::ProviderCallsReconciled,
            negative_authority_complete,
            negative_reason_code,
            negative_reason,
            mapped,
            excluded,
            production,
            tests,
            qualified_production,
            qualified_tests,
        },
        unjoined_source_callables,
    )
}

fn project_unit_callable_verdict(
    node: &GraphNode,
    liveness: &CallableLiveness,
) -> ProjectUnitCallableVerdict {
    if !liveness.mapped.contains(&node.memory_id) {
        return ProjectUnitCallableVerdict::Unknown;
    }
    if liveness.production.contains(&node.memory_id) {
        return if liveness.qualified_production.contains(&node.memory_id) {
            ProjectUnitCallableVerdict::QualifiedLiveProduction
        } else {
            ProjectUnitCallableVerdict::LiveProduction
        };
    }
    if liveness.tests.contains(&node.memory_id) {
        return if liveness.qualified_tests.contains(&node.memory_id) {
            ProjectUnitCallableVerdict::QualifiedLiveTest
        } else {
            ProjectUnitCallableVerdict::LiveTest
        };
    }
    if node.reachability_class == ReachabilityClass::TestOnly && node_is_test_population(node) {
        return ProjectUnitCallableVerdict::RetainedTest;
    }
    if liveness.negative_authority_complete {
        ProjectUnitCallableVerdict::Unreached
    } else {
        ProjectUnitCallableVerdict::Unknown
    }
}

fn forward_reachable(
    graph: &KnowledgeGraph,
    calls: &PublishedCallsGraph,
    seeds: &BTreeSet<Uuid>,
    required_documents: &BTreeSet<String>,
) -> BTreeSet<Uuid> {
    let mut reached = seeds.clone();
    let mut queue = VecDeque::from_iter(seeds.iter().copied());
    while let Some(caller) = queue.pop_front() {
        for callee in calls.liveness_successors(caller) {
            if !graph
                .node(&callee)
                .is_some_and(|node| required_documents.contains(&node.file_path))
            {
                continue;
            }
            if reached.insert(callee) {
                queue.push_back(callee);
            }
        }
    }
    reached
}

fn dead_item(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    node: &GraphNode,
    liveness: &BTreeMap<LanguageId, CallableLiveness>,
    missing_liveness_basis: &BTreeMap<LanguageId, DeadEvidenceBasis>,
) -> Result<DeadItem, DomainError> {
    let persisted = node.reachability_class;
    let symbol = structural_symbol(graph, node, generation)?;
    if symbol_kind_has_role(&node.kind, SymbolRole::Callable) {
        let language = language_id_for_path(&node.file_path);
        if callable_liveness_applies_to(&language)
            && !symbol_is_executable_callable_declaration(&node.kind, node.has_body)
        {
            return Ok(non_executable_callable_item(symbol, node, persisted));
        }
        let Some(language_liveness) = liveness.get(&language) else {
            let basis = missing_liveness_basis
                .get(&language)
                .copied()
                .unwrap_or(DeadEvidenceBasis::ProviderCallsReconciled);
            return Ok(DeadItem {
                symbol,
                callable: true,
                persisted_reachability: persisted,
                verdict: DeadVerdict::Unknown,
                reachable_from_retained_root: None,
                recommendation: DeadRecommendation::Withheld,
                evidence: DeadItemEvidence {
                    status: DeadEvidenceStatus::Unavailable,
                    basis,
                    reason_code: match basis {
                        DeadEvidenceBasis::ProviderCallableLiveness => {
                            "callable_liveness_authority_unavailable"
                        }
                        DeadEvidenceBasis::ProviderCallsReconciled
                        | DeadEvidenceBasis::PersistedStructuralReachability => {
                            "calls_authority_unavailable"
                        }
                    }
                    .into(),
                    reason: match basis {
                        DeadEvidenceBasis::ProviderCallableLiveness => {
                            "no complete compiler-native callable-liveness population covers this callable"
                        }
                        DeadEvidenceBasis::ProviderCallsReconciled
                        | DeadEvidenceBasis::PersistedStructuralReachability => {
                            "no complete provider Calls population can reconcile this callable"
                        }
                    }
                    .into(),
                },
            });
        };
        if !language_liveness.mapped.contains(&node.memory_id) {
            if let Some(reason_codes) = language_liveness.excluded.get(&node.memory_id) {
                return Ok(DeadItem {
                    symbol,
                    callable: true,
                    persisted_reachability: persisted,
                    verdict: DeadVerdict::Unknown,
                    reachable_from_retained_root: None,
                    recommendation: DeadRecommendation::Withheld,
                    evidence: DeadItemEvidence {
                        status: DeadEvidenceStatus::Qualified,
                        basis: language_liveness.basis,
                        reason_code: "provider_coverage_exclusions".into(),
                        reason: format!(
                            "the structural callable is inside explicit provider coverage exclusion(s): {}",
                            reason_codes.join(", ")
                        ),
                    },
                });
            }
            return Ok(DeadItem {
                symbol,
                callable: true,
                persisted_reachability: persisted,
                verdict: DeadVerdict::Unknown,
                reachable_from_retained_root: None,
                recommendation: DeadRecommendation::Withheld,
                evidence: DeadItemEvidence {
                    status: DeadEvidenceStatus::Unavailable,
                    basis: language_liveness.basis,
                    reason_code: "callable_outside_provider_population".into(),
                    reason: "the structural callable has no joined provider definition".into(),
                },
            });
        }
        if language_liveness.production.contains(&node.memory_id) {
            let qualified = language_liveness
                .qualified_production
                .contains(&node.memory_id);
            let (status, reason_code, reason) = if qualified {
                (
                    DeadEvidenceStatus::Qualified,
                    "reached_from_anonymous_production_callable",
                    "a provider-resolved path reaches this callable from an anonymous production callable; the symbol remains conservatively live, but execution depends on that anonymous callable running",
                )
            } else {
                (
                    DeadEvidenceStatus::Complete,
                    "reached_from_retained_production_root",
                    match language_liveness.basis {
                        DeadEvidenceBasis::ProviderCallableLiveness => {
                            "compiler-native whole-program analysis reaches this callable from a retained production or public-API root"
                        }
                        DeadEvidenceBasis::ProviderCallsReconciled
                        | DeadEvidenceBasis::PersistedStructuralReachability => {
                            "a provider-resolved invocation and callable-value binding path reaches this callable from a retained production root"
                        }
                    },
                )
            };
            return Ok(live_item(
                symbol,
                persisted,
                DeadVerdict::LiveProduction,
                language_liveness.basis,
                status,
                reason_code,
                reason,
            ));
        }
        if language_liveness.tests.contains(&node.memory_id) {
            let qualified = language_liveness.qualified_tests.contains(&node.memory_id);
            let (status, reason_code, reason) = if qualified {
                (
                    DeadEvidenceStatus::Qualified,
                    "reached_from_anonymous_test_callable",
                    "a provider-resolved path reaches this callable from an anonymous test callable; the symbol remains conservatively test-live, but execution depends on that anonymous callable running",
                )
            } else {
                (
                    DeadEvidenceStatus::Complete,
                    "reached_from_test_root",
                    match language_liveness.basis {
                        DeadEvidenceBasis::ProviderCallableLiveness => {
                            "compiler-native whole-program analysis reaches this callable from a retained test root"
                        }
                        DeadEvidenceBasis::ProviderCallsReconciled
                        | DeadEvidenceBasis::PersistedStructuralReachability => {
                            "a provider-resolved invocation and callable-value binding path reaches this callable from a persisted test root"
                        }
                    },
                )
            };
            return Ok(live_item(
                symbol,
                persisted,
                DeadVerdict::LiveTest,
                language_liveness.basis,
                status,
                reason_code,
                reason,
            ));
        }
        if language_liveness.basis == DeadEvidenceBasis::ProviderCallsReconciled
            && persisted == ReachabilityClass::TestOnly
            && node_is_test_population(node)
        {
            return Ok(DeadItem {
                symbol,
                callable: true,
                persisted_reachability: persisted,
                verdict: DeadVerdict::RetainedStructural,
                reachable_from_retained_root: None,
                recommendation: DeadRecommendation::Keep,
                evidence: DeadItemEvidence {
                    status: DeadEvidenceStatus::Qualified,
                    basis: DeadEvidenceBasis::PersistedStructuralReachability,
                    reason_code: "test_callable_retained_by_structural_reachability".into(),
                    reason: "the explicit provider invocation population has no root path, but generation-local structural analysis retains this callable in test-owned source; runtime dispatch is outside Calls authority, so it is not nominated as dead"
                        .into(),
                },
            });
        }
        if language_liveness.negative_authority_complete {
            return Ok(DeadItem {
                symbol,
                callable: true,
                persisted_reachability: persisted,
                verdict: DeadVerdict::UnreachedCallable,
                reachable_from_retained_root: Some(false),
                recommendation: DeadRecommendation::Review,
                evidence: DeadItemEvidence {
                    status: DeadEvidenceStatus::Complete,
                    basis: language_liveness.basis,
                    reason_code: match language_liveness.basis {
                        DeadEvidenceBasis::ProviderCallableLiveness => {
                            "unreached_in_compiler_callable_liveness_population"
                        }
                        DeadEvidenceBasis::ProviderCallsReconciled
                        | DeadEvidenceBasis::PersistedStructuralReachability => {
                            "unreached_in_explicit_invocation_population"
                        }
                    }
                    .into(),
                    reason: match language_liveness.basis {
                        DeadEvidenceBasis::ProviderCallableLiveness => {
                            "compiler-native whole-program analysis reaches this declaration from neither production nor test roots"
                        }
                        DeadEvidenceBasis::ProviderCallsReconciled
                        | DeadEvidenceBasis::PersistedStructuralReachability => {
                            "no provider call or callable-value binding reaches this symbol from a retained root; runtime dispatch is outside this claim"
                        }
                    }
                    .into(),
                },
            });
        }
        return Ok(DeadItem {
            symbol,
            callable: true,
            persisted_reachability: persisted,
            verdict: DeadVerdict::Unknown,
            reachable_from_retained_root: None,
            recommendation: DeadRecommendation::Withheld,
            evidence: DeadItemEvidence {
                status: DeadEvidenceStatus::Qualified,
                basis: language_liveness.basis,
                reason_code: language_liveness.negative_reason_code.clone(),
                reason: language_liveness.negative_reason.clone(),
            },
        });
    }

    let candidate = matches!(
        persisted,
        ReachabilityClass::Dead | ReachabilityClass::Orphan | ReachabilityClass::Suspected
    );
    Ok(DeadItem {
        symbol,
        callable: false,
        persisted_reachability: persisted,
        verdict: if persisted == ReachabilityClass::Excluded {
            DeadVerdict::Excluded
        } else if candidate {
            DeadVerdict::StructuralCandidate
        } else if persisted == ReachabilityClass::Unclassified {
            DeadVerdict::Unknown
        } else {
            DeadVerdict::RetainedStructural
        },
        reachable_from_retained_root: None,
        recommendation: if candidate {
            DeadRecommendation::Review
        } else if persisted == ReachabilityClass::Unclassified {
            DeadRecommendation::Withheld
        } else {
            DeadRecommendation::Keep
        },
        evidence: DeadItemEvidence {
            status: DeadEvidenceStatus::Qualified,
            basis: DeadEvidenceBasis::PersistedStructuralReachability,
            reason_code: if candidate {
                "structural_candidate_not_provider_reconciled"
            } else {
                "persisted_structural_classification"
            }
            .into(),
            reason: "Calls authority applies to callable invocation paths; this structural verdict remains qualified until an equivalent structural liveness contract exists"
                .into(),
        },
    })
}

/// Callable contracts and callable-value bindings participate in dispatch but
/// are not executable declaration records in compiler whole-program liveness.
/// Keep exact-symbol inspection useful without allowing either population to
/// create a false language-wide join gap or an RTA-backed deletion claim.
fn non_executable_callable_item(
    symbol: StructuralSymbol,
    node: &GraphNode,
    persisted: ReachabilityClass,
) -> DeadItem {
    let callable_value = node.kind == SymbolKind::CallableValue.label();
    let structural_candidate = callable_value
        && matches!(
            persisted,
            ReachabilityClass::Dead | ReachabilityClass::Orphan | ReachabilityClass::Suspected
        );
    let unknown = callable_value && persisted == ReachabilityClass::Unclassified;
    DeadItem {
        symbol,
        callable: true,
        persisted_reachability: persisted,
        verdict: if structural_candidate {
            DeadVerdict::StructuralCandidate
        } else if unknown {
            DeadVerdict::Unknown
        } else {
            DeadVerdict::RetainedStructural
        },
        reachable_from_retained_root: None,
        recommendation: if structural_candidate {
            DeadRecommendation::Review
        } else if unknown {
            DeadRecommendation::Withheld
        } else {
            DeadRecommendation::Keep
        },
        evidence: DeadItemEvidence {
            status: if callable_value {
                DeadEvidenceStatus::Qualified
            } else {
                DeadEvidenceStatus::Complete
            },
            basis: DeadEvidenceBasis::PersistedStructuralReachability,
            reason_code: if callable_value {
                "callable_value_not_executable_declaration"
            } else {
                "callable_contract_not_executable_declaration"
            }
            .into(),
            reason: if callable_value {
                "this source binding names a callable value but is not itself a compiler liveness declaration; its verdict remains structural"
            } else {
                "this callable contract has no executable body of its own; inspect the owning abstraction instead of treating the signature as dead code"
            }
            .into(),
        },
    }
}

fn live_item(
    symbol: StructuralSymbol,
    persisted: ReachabilityClass,
    verdict: DeadVerdict,
    basis: DeadEvidenceBasis,
    status: DeadEvidenceStatus,
    reason_code: &str,
    reason: &str,
) -> DeadItem {
    DeadItem {
        symbol,
        callable: true,
        persisted_reachability: persisted,
        verdict,
        reachable_from_retained_root: Some(true),
        recommendation: DeadRecommendation::Keep,
        evidence: DeadItemEvidence {
            status,
            basis,
            reason_code: reason_code.into(),
            reason: reason.into(),
        },
    }
}

fn node_is_test_population(node: &GraphNode) -> bool {
    node.is_test_root || node.is_test_only == Some(true) || is_test_file(&node.file_path)
}

fn item_is_full_candidate(item: &DeadItem) -> bool {
    // Synthetic traits and other external anchors support graph navigation,
    // while import/use/export records preserve dependency syntax. Neither
    // population is a source definition for which structural reachability can
    // nominate removable code. Keep exact-symbol inspection available while
    // excluding both from the user-owned full candidate population and totals.
    if !item.symbol.source_backed
        || !symbol_kind_has_role(&item.symbol.kind, SymbolRole::Definition)
    {
        return false;
    }
    match item.verdict {
        DeadVerdict::UnreachedCallable | DeadVerdict::StructuralCandidate => true,
        DeadVerdict::Unknown => {
            item.callable
                || matches!(
                    item.persisted_reachability,
                    ReachabilityClass::Dead
                        | ReachabilityClass::Orphan
                        | ReachabilityClass::Suspected
                        | ReachabilityClass::Unclassified
                )
        }
        DeadVerdict::LiveProduction
        | DeadVerdict::LiveTest
        | DeadVerdict::RetainedStructural
        | DeadVerdict::Excluded => false,
    }
}

fn summarize(items: &[DeadItem]) -> DeadSummary {
    DeadSummary {
        observed_items: items.len(),
        candidate_items: items
            .iter()
            .filter(|item| item_is_full_candidate(item))
            .count(),
        unreached_callables: items
            .iter()
            .filter(|item| item.verdict == DeadVerdict::UnreachedCallable)
            .count(),
        qualified_structural_candidates: items
            .iter()
            .filter(|item| item.verdict == DeadVerdict::StructuralCandidate)
            .count(),
        unknown_candidates: items
            .iter()
            .filter(|item| item.verdict == DeadVerdict::Unknown)
            .count(),
    }
}

fn base_warnings(
    authority: &DeadAuthority,
    effective_limit: usize,
    requested_limit: usize,
    page: &Page,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if authority.structural_candidates_qualified {
        warnings.push(
            "non-callable structural candidates are preserved for review but are not provider-reconciled deadness claims"
                .into(),
        );
    }
    if !authority.item_evidence_complete {
        warnings.push(
            "one or more selected items carry qualified or unavailable evidence; population completeness is withheld"
                .into(),
        );
    }
    if !authority.callable_population_complete {
        warnings.push(
            "one or more callable language populations lack complete negative Calls authority; unknown is not a clean result"
                .into(),
        );
    }
    if effective_limit < requested_limit && page.returned == effective_limit {
        warnings.push(format!(
            "serialized-result bounds reduced this page from the requested ceiling of {requested_limit} to {effective_limit} candidates"
        ));
    }
    if page.has_more {
        warnings.push(format!(
            "showing {} of {} candidates in this page; continue with next_cursor",
            page.returned, page.total_items
        ));
    }
    warnings
}

fn invalid_request(field: &'static str, reason: impl Into<String>) -> DomainError {
    DomainError::InvalidRequest {
        operation: "dead",
        field,
        reason: reason.into(),
    }
}

const fn invalid_generation(reason: String) -> DomainError {
    DomainError::PublishedGenerationInvalid { reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_root_invocation_seeds_callable_liveness_without_a_structural_root() {
        let fixture = crate::code_intel_calls::tests::fixture_with_production_root_invocation();
        let calls = PublishedCallsGraph::build(
            &fixture.graph,
            &fixture.generation,
            &LanguageId::new("rust"),
        )
        .expect("published Calls graph");
        let target = fixture.graph.node_by_name("target").expect("target node");
        let (liveness, unjoined) = reconcile_callable_liveness(
            &fixture.graph,
            &calls,
            &LanguageId::new("rust"),
            &CallableRootSets::default(),
            calls.required_source_documents(),
        );

        assert_eq!(unjoined, 0);
        assert!(liveness.mapped.contains(&target.memory_id));
        assert!(
            liveness.production.contains(&target.memory_id),
            "an exact production root invocation must retain its structural callee"
        );
        assert!(
            !liveness.qualified_production.contains(&target.memory_id),
            "module initialization is an unconditional source execution root"
        );
        assert!(!liveness.tests.contains(&target.memory_id));
    }

    #[test]
    fn anonymous_callable_root_retains_liveness_without_claiming_unconditional_execution() {
        let fixture = crate::code_intel_calls::tests::fixture_with_root_invocation(
            ExecutionRootContext::AnonymousCallable,
        );
        let calls = PublishedCallsGraph::build(
            &fixture.graph,
            &fixture.generation,
            &LanguageId::new("rust"),
        )
        .expect("published Calls graph");
        let target = fixture.graph.node_by_name("target").expect("target node");
        let (liveness, unjoined) = reconcile_callable_liveness(
            &fixture.graph,
            &calls,
            &LanguageId::new("rust"),
            &CallableRootSets::default(),
            calls.required_source_documents(),
        );

        assert_eq!(unjoined, 0);
        assert!(
            liveness.production.contains(&target.memory_id),
            "anonymous-callable evidence must conservatively prevent a false-dead claim"
        );
        assert!(
            liveness.qualified_production.contains(&target.memory_id),
            "positive control: anonymous execution is conditional"
        );
        let item = dead_item(
            &fixture.graph,
            &fixture.generation,
            target,
            &BTreeMap::from([(LanguageId::new("rust"), liveness)]),
            &BTreeMap::new(),
        )
        .expect("qualified Dead item");
        assert_eq!(item.verdict, DeadVerdict::LiveProduction);
        assert_eq!(item.recommendation, DeadRecommendation::Keep);
        assert_eq!(item.evidence.status, DeadEvidenceStatus::Qualified);
        assert_eq!(
            item.evidence.reason_code,
            "reached_from_anonymous_production_callable"
        );
    }
}
