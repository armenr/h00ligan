//! Exact Calls queries over one validated immutable semantic generation.
//!
//! This is the shared use case behind every shipped transport. Authority,
//! ownership, occurrences, and generation identity all come from the same
//! resolved publication; the co-published graph contributes structural symbol
//! resolution and reachability only.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use uuid::Uuid;

use crate::code_intel_cursor::{page_window, request_digest};
use crate::code_intel_domain::{
    AuthorityStatus, CALLS_CONFIGURATION_ID, CallerFilter, CallsPopulation, CallsRequest,
    CapabilityCoverage, CapabilityCoverageStatus, CapabilityEvidenceGap, CapabilityQualification,
    CapabilityScope, CapabilityStatus, ConfigurationId, DomainError, GenerationId, LanguageId,
    MAX_CALLS_PAGE_SIZE, Page, ProjectInventory, ProjectInventoryCoverage, ProjectUnitId,
    ProviderId, RepositoryBinding, ResolvedCapabilityProvider, SourceSpan, SymbolIdentity,
    UnitGraph, aggregate_capability_coverage_status, assess_calls_receipt_coverage,
    capability_resolution_domain_error, resolve_capability_provider,
};
use crate::code_intel_inventory::project_unit_graph;
use crate::code_intel_payload::{
    CallableLivenessProviderPayload, CallsProviderPayload, NormalizedSourceSpan,
    ProviderCallableLiveness, ProviderCoverageExclusion, ProviderLocation, ProviderPayload,
    ProviderSymbol,
};
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::{generation_file_context, language_id_for_path, repository_binding};
use crate::code_intel_query_index::GenerationQueryIndex;
use crate::code_intel_symbol::{
    NameFileSelection, exact_symbol_id, resolve_symbol_selector, resolve_symbol_selector_matching,
};
use crate::graph::{EdgeKind, EdgeScope, EdgeSource, GraphEdge, GraphNode, KnowledgeGraph};
use crate::project_binding::ProjectBinding;
use crate::reachability::ReachabilityClass;
use crate::structural_ir::{SymbolRole, symbol_kind_has_role};

const CALLS_SCHEMA_VERSION: &str = "h00/code-intel/calls/v9";

#[cfg(test)]
std::thread_local! {
    static PUBLISHED_CALLS_GRAPH_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn reset_published_calls_graph_builds() {
    PUBLISHED_CALLS_GRAPH_BUILDS.set(0);
}

#[cfg(test)]
fn published_calls_graph_builds() -> usize {
    PUBLISHED_CALLS_GRAPH_BUILDS.get()
}

/// Assess user-visible Calls authority from both receipt accounting and the
/// exact persisted provider payloads that qualify that accounting.
///
/// A complete receipt proves that one provider accounted for every required
/// source-owner scope. It does not erase explicit source regions that provider
/// excluded. Those remain usable but `qualified`, and strict publication must
/// not promote them to complete negative authority.
pub fn assess_calls_capability<P: AsRef<ProviderPayload>>(
    graph: &KnowledgeGraph,
    receipts: &[crate::code_intel_domain::CapabilityReceipt],
    provider_payloads: &[P],
    inventory: &ProjectInventory,
) -> CapabilityCoverage {
    let provider_payloads = provider_payloads
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>();
    assess_calls_capability_refs(graph, receipts, &provider_payloads, inventory)
}

pub(crate) fn assess_calls_capability_refs(
    graph: &KnowledgeGraph,
    receipts: &[crate::code_intel_domain::CapabilityReceipt],
    provider_payloads: &[&ProviderPayload],
    inventory: &ProjectInventory,
) -> CapabilityCoverage {
    let mut coverage = assess_calls_receipt_coverage(graph, receipts, inventory);
    for language in &mut coverage.languages {
        if language.status != CapabilityCoverageStatus::Complete {
            continue;
        }
        let provider_id = language.provider_id.clone();
        let required_scopes = match required_calls_scopes(inventory, &language.language_id) {
            Ok(scopes) => scopes,
            Err(error) => {
                language.status = CapabilityCoverageStatus::Partial;
                language.gaps.push(CapabilityEvidenceGap {
                    provider_id,
                    status: CapabilityStatus::Partial,
                    reason_code: "project_inventory_mismatch".into(),
                    reason: error.to_string(),
                });
                continue;
            }
        };
        let provider = match resolve_capability_provider(
            receipts,
            "calls",
            &required_scopes,
            provider_id.as_ref(),
        ) {
            Ok(provider) => provider,
            Err(error) => {
                language.status = CapabilityCoverageStatus::Partial;
                language.gaps.push(CapabilityEvidenceGap {
                    provider_id,
                    status: CapabilityStatus::Partial,
                    reason_code: error.evidence_reason_code().into(),
                    reason: error.public_reason(),
                });
                continue;
            }
        };
        let payloads =
            match selected_payloads(provider_payloads.iter().copied(), &provider.receipts) {
                Ok(payloads) => payloads,
                Err(error) => {
                    language.status = CapabilityCoverageStatus::Partial;
                    language.gaps.push(CapabilityEvidenceGap {
                        provider_id: Some(provider.provider_id),
                        status: CapabilityStatus::Partial,
                        reason_code: "provider_payload_unavailable".into(),
                        reason: error.to_string(),
                    });
                    continue;
                }
            };

        let mut excluded_by_reason = BTreeMap::<String, BTreeSet<ProviderLocation>>::new();
        for payload in payloads {
            let document_languages = payload
                .documents
                .iter()
                .map(|document| {
                    (
                        document.document_path.as_str(),
                        document.language_id.clone(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            for exclusion in &payload.coverage_exclusions {
                if document_languages.get(exclusion.location.document_path.as_str())
                    == Some(&language.language_id)
                {
                    excluded_by_reason
                        .entry(exclusion.reason_code.clone())
                        .or_default()
                        .insert(exclusion.location.clone());
                }
            }
        }
        if excluded_by_reason.is_empty() {
            continue;
        }

        language.status = CapabilityCoverageStatus::Qualified;
        language.qualifications = excluded_by_reason
            .into_iter()
            .map(|(reason_code, locations)| {
                let document_count = locations
                    .iter()
                    .map(|location| location.document_path.as_str())
                    .collect::<BTreeSet<_>>()
                    .len();
                CapabilityQualification {
                    provider_id: provider.provider_id.clone(),
                    reason_code,
                    reason: format!(
                        "provider evidence excludes {} source region(s) across {document_count} document(s)",
                        locations.len()
                    ),
                }
            })
            .collect();
    }

    coverage.status = aggregate_capability_coverage_status(&coverage.languages);
    coverage
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactCapabilityAuthority {
    pub status: AuthorityStatus,
    /// Exact population for which `status` and zero-result claims apply.
    pub population: CallsPopulation,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub scopes: Vec<CapabilityScope>,
    pub input_fingerprints: Vec<String>,
    /// Bounded summaries of exact persisted source regions outside provider
    /// authority. Their presence qualifies zero and reduced caller results.
    pub coverage_exclusions: Vec<AuthorityCoverageExclusion>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthorityCoverageExclusion {
    pub language_id: LanguageId,
    pub reason_code: String,
    pub document_count: usize,
    pub region_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactCallReference {
    pub caller: SymbolIdentity,
    pub call_span: SourceSpan,
    pub context: String,
}

/// One exact provider-resolved invocation in an execution path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactCallStep {
    pub caller: SymbolIdentity,
    pub callee: SymbolIdentity,
    pub call_span: SourceSpan,
}

/// One exact local callable-value assignment.
///
/// Used as qualified execution-path evidence. The assignment is source-backed
/// and provider-resolved, but it is not proof that runtime dispatch actually
/// invoked `target`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallableValueBindingStep {
    pub binding: SymbolIdentity,
    pub target: SymbolIdentity,
    pub binding_span: SourceSpan,
}

/// One step in a provider-backed possible execution path.
///
/// The chain is ordered from the affected caller or binding toward the queried
/// target. Exact invocations and qualified callable-value assignments remain
/// distinct all the way through machine and human results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "relation", content = "evidence", rename_all = "snake_case")]
pub enum CallablePathStep {
    ExactInvocation(ExactCallStep),
    CallableValueBinding(CallableValueBindingStep),
}

impl CallablePathStep {
    #[must_use]
    pub const fn source(&self) -> &SymbolIdentity {
        match self {
            Self::ExactInvocation(step) => &step.caller,
            Self::CallableValueBinding(step) => &step.binding,
        }
    }

    #[must_use]
    pub const fn target(&self) -> &SymbolIdentity {
        match self {
            Self::ExactInvocation(step) => &step.callee,
            Self::CallableValueBinding(step) => &step.target,
        }
    }

    #[must_use]
    pub const fn is_qualified(&self) -> bool {
        matches!(self, Self::CallableValueBinding(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactCallsResult {
    pub schema_version: String,
    pub capability: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub unit_graph: UnitGraph,
    pub resolved_symbol: SymbolIdentity,
    pub authority: ExactCapabilityAuthority,
    pub items: Vec<ExactCallReference>,
    pub total_callers: usize,
    pub filtered_callers: usize,
    /// Exact provider-resolved callable-value assignments targeting this
    /// symbol after the requested reachability filter. These are qualified
    /// possible-dispatch evidence, never direct call occurrences.
    pub callable_value_bindings: usize,
    pub filtered_callable_value_bindings: usize,
    pub page: Page,
    pub warnings: Vec<String>,
}

/// One canonical provider-backed call index for a target-language population.
///
/// Both direct Calls queries and derived use cases build this once, then share
/// the exact same provider selection, provider-to-structural join, authority,
/// and incoming-edge population. Transports receive typed product results,
/// never raw provider payloads.
pub(crate) struct PublishedCallsGraph {
    provider: ResolvedCapabilityProvider,
    population: CallsPopulation,
    input_fingerprints: Vec<String>,
    coverage_exclusions: Vec<AuthorityCoverageExclusion>,
    coverage_exclusion_regions: Vec<ProviderCoverageExclusion>,
    excluded_documents: BTreeSet<String>,
    required_documents: BTreeSet<String>,
    nodes: BTreeMap<Uuid, PublishedCallNode>,
    provider_join_failures: BTreeMap<(LanguageId, String, String), BTreeSet<String>>,
    incoming: BTreeMap<Uuid, Vec<PublishedIncomingCall>>,
    outgoing: BTreeMap<Uuid, Vec<Uuid>>,
    callable_bindings: BTreeMap<Uuid, Vec<Uuid>>,
    incoming_callable_bindings: BTreeMap<Uuid, Vec<PublishedIncomingCallableBinding>>,
}

pub(crate) struct PublishedCallNode {
    pub structural: GraphNode,
    pub identity: SymbolIdentity,
}

pub(crate) struct PublishedIncomingCall {
    pub caller_id: Uuid,
    pub caller_reachability: ReachabilityClass,
    pub caller: SymbolIdentity,
    pub call_span: SourceSpan,
}

pub(crate) struct PublishedIncomingCallableBinding {
    pub binding_id: Uuid,
    pub binding_reachability: ReachabilityClass,
    pub binding: SymbolIdentity,
    pub target: SymbolIdentity,
    pub binding_span: SourceSpan,
}

pub(crate) struct PublishedCallPath {
    pub caller_id: Uuid,
    pub caller_is_test_root: bool,
    pub caller: SymbolIdentity,
    pub depth: usize,
    pub chain: Vec<CallablePathStep>,
}

pub(crate) struct PublishedReverseCallTraversal {
    pub paths: Vec<PublishedCallPath>,
    pub depth_cutoff_nodes: usize,
}

impl PublishedCallsGraph {
    pub(crate) fn build(
        graph: &KnowledgeGraph,
        generation: &ResolvedGeneration,
        target_language: &LanguageId,
    ) -> Result<Self, DomainError> {
        Self::build_inner(graph, generation, target_language, None)
    }

    /// Build exact positive Calls evidence for one target even when a single
    /// provider covers only a strict subset of the language's possible caller
    /// scopes. Missing scopes qualify the result and therefore cannot authorize
    /// an unqualified zero-caller claim.
    pub(crate) fn build_for_target(
        graph: &KnowledgeGraph,
        generation: &ResolvedGeneration,
        target_language: &LanguageId,
        target: &GraphNode,
    ) -> Result<Self, DomainError> {
        let target_scopes = source_owner_ids(
            &generation.project_inventory,
            &target.file_path,
            target_language,
        )?
        .into_iter()
        .map(|project_unit_id| CapabilityScope::ProjectUnit {
            language_id: target_language.clone(),
            project_unit_id,
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        })
        .collect::<Vec<_>>();
        Self::build_inner(graph, generation, target_language, Some(&target_scopes))
    }

    pub(crate) fn build_for_project_unit(
        graph: &KnowledgeGraph,
        generation: &ResolvedGeneration,
        language_id: &LanguageId,
        project_unit_id: &ProjectUnitId,
    ) -> Result<Self, DomainError> {
        let target_scopes = [CapabilityScope::ProjectUnit {
            language_id: language_id.clone(),
            project_unit_id: project_unit_id.clone(),
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        }];
        Self::build_inner(graph, generation, language_id, Some(&target_scopes))
    }

    fn build_inner(
        graph: &KnowledgeGraph,
        generation: &ResolvedGeneration,
        target_language: &LanguageId,
        target_scopes: Option<&[CapabilityScope]>,
    ) -> Result<Self, DomainError> {
        #[cfg(test)]
        PUBLISHED_CALLS_GRAPH_BUILDS.set(PUBLISHED_CALLS_GRAPH_BUILDS.get() + 1);

        // Calls authority is about the possible caller population, not merely
        // the unit defining the callee. A complete persisted local-dependency
        // graph can narrow that population to the selected unit plus every
        // transitive dependent. Missing, partial, or inconsistent topology
        // deliberately preserves the language-wide fail-closed population.
        let required_scopes = match target_scopes {
            Some(target_scopes) => required_calls_scopes_for_target(
                &generation.project_inventory,
                target_language,
                target_scopes,
            )?,
            None => required_calls_scopes(&generation.project_inventory, target_language)?,
        };
        let (provider, missing_scopes) = resolve_calls_provider_population(
            &generation.manifest.receipts,
            &required_scopes,
            target_scopes,
        )?;
        let payloads = selected_payloads(
            generation.provider_payloads.iter().map(AsRef::as_ref),
            &provider.receipts,
        )?;
        let population = payloads
            .first()
            .map(|payload| payload.population)
            .ok_or_else(|| invalid_generation("selected Calls provider has no payloads".into()))?;
        if payloads
            .iter()
            .any(|payload| payload.population != population)
        {
            return Err(invalid_generation(
                "selected Calls provider payloads disagree on their authorized population".into(),
            ));
        }
        let required_documents = required_scope_documents(
            &generation.project_inventory,
            target_language,
            &required_scopes,
        )?;

        let mut excluded_regions = BTreeMap::<
            (LanguageId, String),
            BTreeSet<crate::code_intel_payload::ProviderLocation>,
        >::new();
        let mut coverage_exclusion_regions = BTreeSet::new();
        let mut excluded_documents = BTreeSet::new();
        let mut scope_coverage_exclusions = Vec::new();
        if !missing_scopes.is_empty() {
            let missing_documents = missing_scope_documents(
                &generation.project_inventory,
                target_language,
                &missing_scopes,
            )?;
            excluded_documents.extend(missing_documents.iter().cloned());
            scope_coverage_exclusions.push(AuthorityCoverageExclusion {
                language_id: target_language.clone(),
                reason_code: "provider_scope_population_incomplete".into(),
                document_count: missing_documents.len(),
                // A missing whole-document caller population is one excluded
                // region per document; no synthetic byte offsets are created.
                region_count: missing_documents.len(),
            });
        }
        for payload in &payloads {
            let document_languages = payload
                .documents
                .iter()
                .map(|document| {
                    (
                        document.document_path.as_str(),
                        document.language_id.clone(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            for exclusion in &payload.coverage_exclusions {
                let language_id = document_languages
                    .get(exclusion.location.document_path.as_str())
                    .ok_or_else(|| {
                        invalid_generation(format!(
                            "provider exclusion references missing document {}",
                            exclusion.location.document_path
                        ))
                    })?
                    .clone();
                if !required_documents.contains(&exclusion.location.document_path) {
                    continue;
                }
                excluded_regions
                    .entry((language_id, exclusion.reason_code.clone()))
                    .or_default()
                    .insert(exclusion.location.clone());
                coverage_exclusion_regions.insert(exclusion.clone());
                excluded_documents.insert(exclusion.location.document_path.clone());
            }
        }
        let mut coverage_exclusions = scope_coverage_exclusions;
        coverage_exclusions.extend(excluded_regions.into_iter().map(
            |((language_id, reason_code), regions)| {
                let document_count = regions
                    .iter()
                    .map(|location| location.document_path.as_str())
                    .collect::<BTreeSet<_>>()
                    .len();
                AuthorityCoverageExclusion {
                    language_id,
                    reason_code,
                    document_count,
                    region_count: regions.len(),
                }
            },
        ));
        let mut input_fingerprints = provider
            .receipts
            .iter()
            .filter_map(|receipt| receipt.input_fingerprint.clone())
            .collect::<Vec<_>>();
        input_fingerprints.sort();
        input_fingerprints.dedup();

        let structural_targets = structural_invocation_target_index(graph);
        let mut nodes = BTreeMap::<Uuid, PublishedCallNode>::new();
        let mut provider_join_failures =
            BTreeMap::<(LanguageId, String, String), BTreeSet<String>>::new();
        let mut incoming = BTreeMap::<Uuid, BTreeMap<ReferenceKey, PublishedIncomingCall>>::new();
        let mut callable_bindings = BTreeMap::<Uuid, BTreeSet<Uuid>>::new();
        let mut incoming_callable_bindings =
            BTreeMap::<Uuid, BTreeMap<ReferenceKey, PublishedIncomingCallableBinding>>::new();
        for payload in &payloads {
            let mut payload_nodes = BTreeMap::<&str, Uuid>::new();
            let mut mapping_failures = BTreeMap::<&str, String>::new();
            let mut provider_symbols = BTreeMap::<&str, &ProviderSymbol>::new();
            for symbol in &payload.symbols {
                if provider_symbols
                    .insert(symbol.provider_symbol_id.as_str(), symbol)
                    .is_some()
                {
                    return Err(invalid_generation(format!(
                        "provider {} repeated symbol identity {} in one payload",
                        provider.provider_id, symbol.provider_symbol_id
                    )));
                }
                if symbol.language_id != *target_language
                    || symbol.definition.is_none()
                    || symbol.structural_extent.is_none()
                {
                    continue;
                }
                if !symbol.definition.as_ref().is_some_and(|definition| {
                    required_documents.contains(&definition.document_path)
                }) {
                    continue;
                }
                let structural = match graph_node_for_provider_symbol(&structural_targets, symbol) {
                    Ok(structural) => structural,
                    Err(error) => {
                        // Provider payloads may carry unrelated same-name or
                        // external symbols. Preserve the mapping failure so a
                        // referenced local caller still fails closed, while an
                        // unused symbol cannot poison an otherwise exact query.
                        mapping_failures
                            .insert(symbol.provider_symbol_id.as_str(), error.to_string());
                        if let Some(definition) = &symbol.definition {
                            provider_join_failures
                                .entry((
                                    symbol.language_id.clone(),
                                    definition.document_path.clone(),
                                    symbol.name.clone(),
                                ))
                                .or_default()
                                .insert(error.to_string());
                        }
                        continue;
                    }
                };
                let identity = symbol_identity(
                    symbol,
                    structural,
                    &generation.project_inventory,
                    &generation.manifest.repository_id,
                    &generation.manifest.generation_id,
                )?;
                if let Some(existing) = nodes.get(&structural.memory_id)
                    && existing.identity != identity
                {
                    return Err(invalid_generation(format!(
                        "provider {} returned conflicting identities for {} in {}",
                        provider.provider_id, structural.symbol_name, structural.file_path
                    )));
                }
                nodes
                    .entry(structural.memory_id)
                    .or_insert_with(|| PublishedCallNode {
                        structural: structural.clone(),
                        identity,
                    });
                if let Some(existing) =
                    payload_nodes.insert(symbol.provider_symbol_id.as_str(), structural.memory_id)
                    && existing != structural.memory_id
                {
                    return Err(invalid_generation(format!(
                        "provider {} reused symbol identity {} for multiple structural nodes",
                        provider.provider_id, symbol.provider_symbol_id
                    )));
                }
            }

            for call in &payload.calls {
                let caller_symbol = provider_symbols
                    .get(call.caller_symbol_id.as_str())
                    .ok_or_else(|| {
                        invalid_generation(format!(
                            "provider call references missing caller {}",
                            call.caller_symbol_id
                        ))
                    })?;
                let callee_symbol = provider_symbols
                    .get(call.callee_symbol_id.as_str())
                    .ok_or_else(|| {
                        invalid_generation(format!(
                            "provider call references missing callee {}",
                            call.callee_symbol_id
                        ))
                    })?;
                if caller_symbol.language_id != *target_language
                    || callee_symbol.language_id != *target_language
                {
                    continue;
                }
                let caller_selected = caller_symbol.definition.as_ref().is_some_and(|definition| {
                    required_documents.contains(&definition.document_path)
                });
                let callee_selected = callee_symbol.definition.as_ref().is_some_and(|definition| {
                    required_documents.contains(&definition.document_path)
                });
                if !caller_selected {
                    if callee_selected {
                        return Err(invalid_generation(format!(
                            "provider call from {} into {} contradicts the persisted possible-caller dependency population",
                            caller_symbol
                                .definition
                                .as_ref()
                                .map_or("<external>", |definition| definition
                                    .document_path
                                    .as_str()),
                            callee_symbol
                                .definition
                                .as_ref()
                                .map_or("<external>", |definition| definition
                                    .document_path
                                    .as_str())
                        )));
                    }
                    continue;
                }
                if !callee_selected {
                    continue;
                }
                let Some(&caller_id) = payload_nodes.get(call.caller_symbol_id.as_str()) else {
                    if let Some(reason) = mapping_failures.get(call.caller_symbol_id.as_str()) {
                        return Err(invalid_generation(format!(
                            "provider caller {} cannot join its co-published structural definition: {reason}",
                            call.caller_symbol_id
                        )));
                    }
                    return Err(invalid_generation(format!(
                        "provider call references caller {} without a local callable definition in the selected language",
                        call.caller_symbol_id
                    )));
                };
                // Calls to external or differently configured language symbols
                // are outside this target-language authority population.
                let Some(&callee_id) = payload_nodes.get(call.callee_symbol_id.as_str()) else {
                    continue;
                };
                let caller = nodes.get(&caller_id).ok_or_else(|| {
                    invalid_generation(format!(
                        "provider caller {} disappeared from the canonical call index",
                        call.caller_symbol_id
                    ))
                })?;
                if call.call_site.document_path != caller.structural.file_path {
                    return Err(invalid_generation(format!(
                        "provider call site for {} is in {}, outside caller document {}",
                        call.caller_symbol_id,
                        call.call_site.document_path,
                        caller.structural.file_path
                    )));
                }
                let item = PublishedIncomingCall {
                    caller_id: caller.structural.memory_id,
                    caller_reachability: caller.structural.reachability_class,
                    caller: caller.identity.clone(),
                    call_span: source_span(&call.call_site.span)?,
                };
                let key = ReferenceKey::from_parts(&item.caller, &item.call_span);
                match incoming.entry(callee_id).or_default().entry(key) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(item);
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if entry.get().caller == item.caller
                            && entry.get().call_span == item.call_span => {}
                    std::collections::btree_map::Entry::Occupied(_) => {
                        return Err(invalid_generation(
                            "conflicting provider records occupy one exact call occurrence".into(),
                        ));
                    }
                }
            }
            for binding in &payload.callable_bindings {
                let binding_symbol = provider_symbols
                    .get(binding.binding_symbol_id.as_str())
                    .ok_or_else(|| {
                        invalid_generation(format!(
                            "provider callable binding references missing source {}",
                            binding.binding_symbol_id
                        ))
                    })?;
                let target_symbol = provider_symbols
                    .get(binding.target_symbol_id.as_str())
                    .ok_or_else(|| {
                        invalid_generation(format!(
                            "provider callable binding references missing target {}",
                            binding.target_symbol_id
                        ))
                    })?;
                let binding_selected =
                    binding_symbol
                        .definition
                        .as_ref()
                        .is_some_and(|definition| {
                            required_documents.contains(&definition.document_path)
                        });
                let target_selected = target_symbol.definition.as_ref().is_some_and(|definition| {
                    required_documents.contains(&definition.document_path)
                });
                if !binding_selected {
                    if target_selected {
                        return Err(invalid_generation(format!(
                            "provider callable binding from {} into {} contradicts the persisted possible-caller dependency population",
                            binding_symbol
                                .definition
                                .as_ref()
                                .map_or("<external>", |definition| definition
                                    .document_path
                                    .as_str()),
                            target_symbol
                                .definition
                                .as_ref()
                                .map_or("<external>", |definition| definition
                                    .document_path
                                    .as_str())
                        )));
                    }
                    continue;
                }
                if !target_selected {
                    continue;
                }
                let binding_id = payload_nodes
                    .get(binding.binding_symbol_id.as_str())
                    .copied()
                    .ok_or_else(|| {
                        let detail = mapping_failures
                            .get(binding.binding_symbol_id.as_str())
                            .map_or(String::new(), |reason| format!(": {reason}"));
                        invalid_generation(format!(
                            "provider callable binding source {} cannot join its co-published structural definition{detail}",
                            binding.binding_symbol_id
                        ))
                    })?;
                let target_id = payload_nodes
                    .get(binding.target_symbol_id.as_str())
                    .copied()
                    .ok_or_else(|| {
                        let detail = mapping_failures
                            .get(binding.target_symbol_id.as_str())
                            .map_or(String::new(), |reason| format!(": {reason}"));
                        invalid_generation(format!(
                            "provider callable binding target {} cannot join its co-published structural definition{detail}",
                            binding.target_symbol_id
                        ))
                    })?;
                if binding_id == target_id {
                    return Err(invalid_generation(
                        "provider callable binding collapsed to one structural node".into(),
                    ));
                }
                let binding_node = nodes.get(&binding_id).ok_or_else(|| {
                    invalid_generation(format!(
                        "provider callable binding source {} disappeared from the canonical call index",
                        binding.binding_symbol_id
                    ))
                })?;
                let target_node = nodes.get(&target_id).ok_or_else(|| {
                    invalid_generation(format!(
                        "provider callable binding target {} disappeared from the canonical call index",
                        binding.target_symbol_id
                    ))
                })?;
                if binding.binding_site.document_path != binding_node.structural.file_path {
                    return Err(invalid_generation(format!(
                        "provider callable binding site for {} is in {}, outside binding document {}",
                        binding.binding_symbol_id,
                        binding.binding_site.document_path,
                        binding_node.structural.file_path
                    )));
                }
                let item = PublishedIncomingCallableBinding {
                    binding_id: binding_node.structural.memory_id,
                    binding_reachability: binding_node.structural.reachability_class,
                    binding: binding_node.identity.clone(),
                    target: target_node.identity.clone(),
                    binding_span: source_span(&binding.binding_site.span)?,
                };
                let key = ReferenceKey::from_parts(&item.binding, &item.binding_span);
                match incoming_callable_bindings
                    .entry(target_id)
                    .or_default()
                    .entry(key)
                {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(item);
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if entry.get().binding == item.binding
                            && entry.get().target == item.target
                            && entry.get().binding_span == item.binding_span => {}
                    std::collections::btree_map::Entry::Occupied(_) => {
                        return Err(invalid_generation(
                            "conflicting provider records occupy one exact callable-value assignment occurrence"
                                .into(),
                        ));
                    }
                }
                callable_bindings
                    .entry(binding_id)
                    .or_default()
                    .insert(target_id);
            }
        }
        let incoming = incoming
            .into_iter()
            .map(|(callee, calls)| (callee, calls.into_values().collect()))
            .collect::<BTreeMap<_, Vec<_>>>();
        let mut outgoing = BTreeMap::<Uuid, BTreeSet<Uuid>>::new();
        for (callee_id, calls) in &incoming {
            for call in calls {
                outgoing
                    .entry(call.caller_id)
                    .or_default()
                    .insert(*callee_id);
            }
        }
        let outgoing = outgoing
            .into_iter()
            .map(|(caller, callees)| (caller, callees.into_iter().collect()))
            .collect();
        let callable_bindings = callable_bindings
            .into_iter()
            .map(|(binding, targets)| (binding, targets.into_iter().collect()))
            .collect();
        let incoming_callable_bindings = incoming_callable_bindings
            .into_iter()
            .map(|(target, bindings)| (target, bindings.into_values().collect()))
            .collect();

        Ok(Self {
            provider,
            population,
            input_fingerprints,
            coverage_exclusions,
            coverage_exclusion_regions: coverage_exclusion_regions.into_iter().collect(),
            excluded_documents,
            required_documents,
            nodes,
            provider_join_failures,
            incoming,
            outgoing,
            callable_bindings,
            incoming_callable_bindings,
        })
    }

    pub(crate) fn node(
        &self,
        graph: &KnowledgeGraph,
        target_node: &GraphNode,
    ) -> Result<&PublishedCallNode, DomainError> {
        if let Some(node) = self.nodes.get(&target_node.memory_id) {
            return Ok(node);
        }
        let target_exclusion_reasons = self.coverage_exclusion_reason_codes(graph, target_node);
        if !target_exclusion_reasons.is_empty() {
            return Err(DomainError::SymbolOutsideProviderCoverage {
                symbol: target_node.symbol_name.clone(),
                provider_id: self.provider.provider_id.clone(),
                reason_codes: target_exclusion_reasons,
            });
        }
        let target_language = language_id_for_path(&target_node.file_path);
        if let Some((_, failures)) = self.provider_join_failures.iter().find(
            |((language_id, document_path, provider_name), _)| {
                *language_id == target_language
                    && *document_path == target_node.file_path
                    && provider_declared_name_matches_node(provider_name, &target_node.symbol_name)
            },
        ) {
            return Err(invalid_generation(format!(
                "selected provider {} supplied an unjoinable target identity for {} in {}: {}",
                self.provider.provider_id,
                target_node.symbol_name,
                target_node.file_path,
                failures.iter().cloned().collect::<Vec<_>>().join("; ")
            )));
        }
        Err(DomainError::SymbolOutsideProviderPopulation {
            symbol: target_node.symbol_name.clone(),
            provider_id: self.provider.provider_id.clone(),
        })
    }

    pub(crate) fn incoming(&self, callee_id: Uuid) -> &[PublishedIncomingCall] {
        self.incoming.get(&callee_id).map_or(&[], Vec::as_slice)
    }

    pub(crate) fn incoming_callable_bindings(
        &self,
        target_id: Uuid,
    ) -> &[PublishedIncomingCallableBinding] {
        self.incoming_callable_bindings
            .get(&target_id)
            .map_or(&[], Vec::as_slice)
    }

    /// Provider-backed callable definitions in deterministic structural-id order.
    pub(crate) fn nodes(&self) -> impl Iterator<Item = &PublishedCallNode> {
        self.nodes.values()
    }

    pub(crate) const fn required_source_documents(&self) -> &BTreeSet<String> {
        &self.required_documents
    }

    pub(crate) fn unjoined_source_callable_count_in_documents(
        &self,
        graph: &KnowledgeGraph,
        language_id: &LanguageId,
        required_documents: &BTreeSet<String>,
    ) -> usize {
        graph
            .all_nodes()
            .into_iter()
            .filter(|node| {
                structural_node_is_callable_kind(&node.kind)
                    && language_id_for_path(&node.file_path) == *language_id
                    && required_documents.contains(&node.file_path)
            })
            .filter(|node| {
                !self.nodes.contains_key(&node.memory_id)
                    && self.coverage_exclusion_reason_codes(graph, node).is_empty()
            })
            .count()
    }

    pub(crate) fn negative_claims_are_complete_in_documents(
        &self,
        required_documents: &BTreeSet<String>,
    ) -> bool {
        required_documents.is_disjoint(&self.excluded_documents)
    }

    /// Reject a scoped caller closure when the complete language projection
    /// contains an invocation or callable-value binding from outside that
    /// closure into it. This is the batched equivalent of the filtering guard
    /// in `build_inner`; batching must never weaken dependency authority.
    pub(crate) fn validate_possible_caller_documents(
        &self,
        required_documents: &BTreeSet<String>,
    ) -> Result<(), DomainError> {
        for (callee_id, incoming) in &self.incoming {
            let Some(callee) = self.nodes.get(callee_id) else {
                return Err(invalid_generation(format!(
                    "provider call target {callee_id} disappeared from the canonical call index"
                )));
            };
            if !required_documents.contains(&callee.structural.file_path) {
                continue;
            }
            if let Some(call) = incoming
                .iter()
                .find(|call| !required_documents.contains(&call.caller.document_path))
            {
                return Err(invalid_generation(format!(
                    "provider call from {} into {} contradicts the persisted possible-caller dependency population",
                    call.caller.document_path, callee.structural.file_path
                )));
            }
        }
        for (target_id, incoming) in &self.incoming_callable_bindings {
            let Some(target) = self.nodes.get(target_id) else {
                return Err(invalid_generation(format!(
                    "provider callable binding target {target_id} disappeared from the canonical call index"
                )));
            };
            if !required_documents.contains(&target.structural.file_path) {
                continue;
            }
            if let Some(binding) = incoming
                .iter()
                .find(|binding| !required_documents.contains(&binding.binding.document_path))
            {
                return Err(invalid_generation(format!(
                    "provider callable binding from {} into {} contradicts the persisted possible-caller dependency population",
                    binding.binding.document_path, target.structural.file_path
                )));
            }
        }
        Ok(())
    }

    /// Stable reasons proving that one structural callable lies inside an
    /// explicit provider coverage exclusion. Callers use this to distinguish
    /// an explained cfg/generated omission from an unexplained failed join.
    pub(crate) fn coverage_exclusion_reason_codes(
        &self,
        graph: &KnowledgeGraph,
        node: &GraphNode,
    ) -> Vec<String> {
        self.coverage_exclusion_regions
            .iter()
            .filter(|exclusion| coverage_exclusion_covers_node(graph, exclusion, node))
            .map(|exclusion| exclusion.reason_code.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Provider-resolved callees reached by at least one exact source invocation.
    /// Multiple call sites between the same pair collapse to one traversal edge;
    /// occurrence multiplicity remains available through [`Self::incoming`].
    pub(crate) fn outgoing(&self, caller_id: Uuid) -> &[Uuid] {
        self.outgoing.get(&caller_id).map_or(&[], Vec::as_slice)
    }

    pub(crate) fn liveness_successors(&self, caller_id: Uuid) -> Vec<Uuid> {
        self.outgoing(caller_id)
            .iter()
            .chain(self.callable_bindings.get(&caller_id).into_iter().flatten())
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Return one deterministic shortest provider-backed path for every
    /// reachable caller, bounded by `max_depth`.
    pub(crate) fn reverse_reachable(
        &self,
        graph: &KnowledgeGraph,
        target_node: &GraphNode,
        max_depth: usize,
    ) -> Result<PublishedReverseCallTraversal, DomainError> {
        let target = self.node(graph, target_node)?.identity.clone();
        let mut queue = VecDeque::from([(target_node.memory_id, 0usize, Vec::new())]);
        let mut visited = BTreeSet::from([target_node.memory_id]);
        let mut paths = Vec::new();
        let mut depth_cutoffs = BTreeSet::new();

        while let Some((callee_id, depth, reverse_chain)) = queue.pop_front() {
            let callee = if callee_id == target_node.memory_id {
                target.clone()
            } else {
                let callee_node = graph.node(&callee_id).ok_or_else(|| {
                    invalid_generation(format!(
                        "Calls traversal node {callee_id} is absent from its immutable graph"
                    ))
                })?;
                self.node(graph, callee_node)?.identity.clone()
            };
            for incoming in self.incoming(callee_id) {
                let next_depth = depth + 1;
                if next_depth > max_depth {
                    if !visited.contains(&incoming.caller_id) {
                        depth_cutoffs.insert(incoming.caller.symbol_id.clone());
                    }
                    continue;
                }
                let mut next_reverse_chain = reverse_chain.clone();
                next_reverse_chain.push(CallablePathStep::ExactInvocation(ExactCallStep {
                    caller: incoming.caller.clone(),
                    callee: callee.clone(),
                    call_span: incoming.call_span.clone(),
                }));
                if visited.insert(incoming.caller_id) {
                    let caller_node = graph.node(&incoming.caller_id).ok_or_else(|| {
                        invalid_generation(format!(
                            "Calls traversal caller {} is absent from its immutable graph",
                            incoming.caller_id
                        ))
                    })?;
                    let mut chain = next_reverse_chain.clone();
                    chain.reverse();
                    paths.push(PublishedCallPath {
                        caller_id: incoming.caller_id,
                        caller_is_test_root: caller_node.is_test_root,
                        caller: incoming.caller.clone(),
                        depth: next_depth,
                        chain,
                    });
                    queue.push_back((incoming.caller_id, next_depth, next_reverse_chain));
                }
            }
            for incoming in self.incoming_callable_bindings(callee_id) {
                let next_depth = depth + 1;
                if next_depth > max_depth {
                    if !visited.contains(&incoming.binding_id) {
                        depth_cutoffs.insert(incoming.binding.symbol_id.clone());
                    }
                    continue;
                }
                let mut next_reverse_chain = reverse_chain.clone();
                next_reverse_chain.push(CallablePathStep::CallableValueBinding(
                    CallableValueBindingStep {
                        binding: incoming.binding.clone(),
                        target: incoming.target.clone(),
                        binding_span: incoming.binding_span.clone(),
                    },
                ));
                if visited.insert(incoming.binding_id) {
                    let binding_node = graph.node(&incoming.binding_id).ok_or_else(|| {
                        invalid_generation(format!(
                            "Calls traversal binding {} is absent from its immutable graph",
                            incoming.binding_id
                        ))
                    })?;
                    let mut chain = next_reverse_chain.clone();
                    chain.reverse();
                    paths.push(PublishedCallPath {
                        caller_id: incoming.binding_id,
                        caller_is_test_root: binding_node.is_test_root,
                        caller: incoming.binding.clone(),
                        depth: next_depth,
                        chain,
                    });
                    queue.push_back((incoming.binding_id, next_depth, next_reverse_chain));
                }
            }
        }
        paths.sort_by(|left, right| {
            (
                left.depth,
                left.caller.document_path.as_str(),
                left.caller.name.as_str(),
                left.caller.symbol_id.as_str(),
            )
                .cmp(&(
                    right.depth,
                    right.caller.document_path.as_str(),
                    right.caller.name.as_str(),
                    right.caller.symbol_id.as_str(),
                ))
        });
        Ok(PublishedReverseCallTraversal {
            paths,
            depth_cutoff_nodes: depth_cutoffs.len(),
        })
    }

    pub(crate) fn authority(&self) -> ExactCapabilityAuthority {
        ExactCapabilityAuthority {
            status: if self.coverage_exclusions.is_empty() {
                AuthorityStatus::Complete
            } else {
                AuthorityStatus::Qualified
            },
            population: self.population,
            provider_id: self.provider.provider_id.clone(),
            provider_version: self.provider.provider_version.clone(),
            scopes: self.provider.required_scopes.clone(),
            input_fingerprints: self.input_fingerprints.clone(),
            coverage_exclusions: self.coverage_exclusions.clone(),
        }
    }

    pub(crate) fn coverage_warning(&self) -> Option<String> {
        (!self.coverage_exclusions.is_empty()).then(|| {
            let region_count = self
                .coverage_exclusions
                .iter()
                .map(|exclusion| exclusion.region_count)
                .sum::<usize>();
            format!(
                "Calls authority has {region_count} excluded source region(s) across {} document(s); results are complete only for provider-covered source.",
                self.excluded_documents.len()
            )
        })
    }
}

/// Query one exact immutable generation. `graph` must be the graph loaded from
/// `generation.database_path`; callers establish that invariant once while
/// constructing their process snapshot.
pub fn query_published_calls(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    request: &CallsRequest,
) -> Result<ExactCallsResult, DomainError> {
    query_published_calls_with_index(None, graph, generation, binding, request)
}

pub(crate) fn query_published_calls_indexed(
    index: &GenerationQueryIndex,
    binding: &ProjectBinding,
    request: &CallsRequest,
) -> Result<ExactCallsResult, DomainError> {
    query_published_calls_with_index(
        Some(index),
        index.graph(),
        index.generation(),
        binding,
        request,
    )
}

fn query_published_calls_with_index(
    index: Option<&GenerationQueryIndex>,
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    request: &CallsRequest,
) -> Result<ExactCallsResult, DomainError> {
    if request.limit == 0 || request.limit > MAX_CALLS_PAGE_SIZE {
        return Err(DomainError::InvalidRequest {
            operation: "calls",
            field: "limit",
            reason: format!("must be between 1 and {MAX_CALLS_PAGE_SIZE}"),
        });
    }

    let normalized_file = request
        .file
        .as_deref()
        .filter(|file| !file.is_empty())
        .map(|file| generation_file_context(binding, file))
        .transpose()?
        .map(|context| context.file_path().to_owned());
    let target_node = resolve_calls_target_candidate(
        graph,
        generation,
        &request.symbol,
        normalized_file.as_deref(),
    )?;
    let target_language = language_id_for_path(&target_node.file_path);
    if generation
        .project_inventory
        .is_structural_only_source_document(&target_node.file_path, &target_language)
    {
        return Err(DomainError::CapabilityNotApplicable {
            capability: "calls".into(),
            reason: format!(
                "{} is structurally indexed source data without a semantic project execution unit; declare supported project configuration for that source to opt it into Calls indexing",
                target_node.file_path
            ),
        });
    }
    let calls = match index {
        Some(index) => index.calls_for_target(&target_language, target_node)?,
        None => std::sync::Arc::new(PublishedCallsGraph::build_for_target(
            graph,
            generation,
            &target_language,
            target_node,
        )?),
    };
    let resolved_symbol = match calls.node(graph, target_node) {
        Ok(node) => node.identity.clone(),
        Err(DomainError::SymbolOutsideProviderPopulation { .. })
            if !structural_node_is_invocation_target(target_node) =>
        {
            return Err(DomainError::SymbolNotCallable {
                symbol: target_node.symbol_name.clone(),
                kind: target_node.kind.clone(),
            });
        }
        Err(error) => return Err(error),
    };
    let mut references = Vec::new();
    let mut filtered_callers = BTreeSet::new();
    for incoming in calls.incoming(target_node.memory_id) {
        if !filter_admits(request.filter, incoming.caller_reachability) {
            filtered_callers.insert(incoming.caller.symbol_id.clone());
            continue;
        }
        references.push(ExactCallReference {
            caller: incoming.caller.clone(),
            call_span: incoming.call_span.clone(),
            context: "exact provider-resolved call occurrence".into(),
        });
    }
    let mut callable_value_bindings = 0usize;
    let mut filtered_callable_value_bindings = 0usize;
    for binding in calls.incoming_callable_bindings(target_node.memory_id) {
        if filter_admits(request.filter, binding.binding_reachability) {
            callable_value_bindings += 1;
        } else {
            filtered_callable_value_bindings += 1;
        }
    }

    let all_items = references;
    let total_items = all_items.len();
    let generation_id = generation.manifest.generation_id.clone();
    let request_digest = calls_request_digest(request);
    let window = page_window(
        "calls",
        &generation_id,
        &request_digest,
        request.cursor.as_deref(),
        request.limit,
        total_items,
    )?;
    let items = all_items[window.range.clone()].to_vec();
    let total_callers = all_items
        .iter()
        .map(|reference| reference.caller.symbol_id.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let mut projected_documents = items
        .iter()
        .map(|item| item.caller.document_path.as_str())
        .collect::<Vec<_>>();
    projected_documents.push(&resolved_symbol.document_path);
    let unit_graph = project_unit_graph(&generation.project_inventory, projected_documents);
    let mut warnings = Vec::new();
    if generation.project_inventory.coverage
        == ProjectInventoryCoverage::IndexedSourcePopulationPartial
    {
        warnings.push(format!(
            "Project inventory is partial and reports {} issue(s).",
            generation.project_inventory.issues.len()
        ));
    }
    if let Some(warning) = calls.coverage_warning() {
        warnings.push(warning);
    }
    if callable_value_bindings > 0 {
        warnings.push(format!(
            "{callable_value_bindings} exact callable-value assignment(s) target this symbol; they are qualified possible-dispatch evidence, not direct invocation records; Assess follows them without relabelling them as calls"
        ));
    }

    Ok(ExactCallsResult {
        schema_version: CALLS_SCHEMA_VERSION.into(),
        capability: "calls".into(),
        generation_id,
        repository: repository_binding(binding, generation),
        unit_graph,
        resolved_symbol,
        authority: calls.authority(),
        items,
        total_callers,
        filtered_callers: filtered_callers.len(),
        callable_value_bindings,
        filtered_callable_value_bindings,
        page: window.page,
        warnings,
    })
}

pub(crate) fn resolve_invocation_target<'a>(
    graph: &'a KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    symbol: &str,
    file: Option<&str>,
) -> Result<&'a GraphNode, DomainError> {
    resolve_invocation_target_with_index(None, graph, generation, binding, symbol, file)
}

pub(crate) fn resolve_invocation_target_indexed<'a>(
    index: &'a GenerationQueryIndex,
    binding: &ProjectBinding,
    symbol: &str,
    file: Option<&str>,
) -> Result<&'a GraphNode, DomainError> {
    resolve_invocation_target_with_index(
        Some(index),
        index.graph(),
        index.generation(),
        binding,
        symbol,
        file,
    )
}

fn resolve_invocation_target_with_index<'a>(
    index: Option<&GenerationQueryIndex>,
    graph: &'a KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    symbol: &str,
    file: Option<&str>,
) -> Result<&'a GraphNode, DomainError> {
    let normalized_file = file
        .filter(|file| !file.is_empty())
        .map(|file| generation_file_context(binding, file))
        .transpose()?
        .map(|context| context.file_path().to_owned());
    let node =
        resolve_calls_target_candidate(graph, generation, symbol, normalized_file.as_deref())?;
    if match index {
        Some(index) => published_node_is_invocation_target_indexed(index, node)?,
        None => published_node_is_invocation_target(graph, generation, node)?,
    } {
        Ok(node)
    } else {
        Err(DomainError::SymbolNotCallable {
            symbol: node.symbol_name.clone(),
            kind: node.kind.clone(),
        })
    }
}

pub(crate) fn published_node_is_invocation_target(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    node: &GraphNode,
) -> Result<bool, DomainError> {
    published_node_is_invocation_target_with_index(None, graph, generation, node)
}

pub(crate) fn published_node_is_invocation_target_indexed(
    index: &GenerationQueryIndex,
    node: &GraphNode,
) -> Result<bool, DomainError> {
    published_node_is_invocation_target_with_index(
        Some(index),
        index.graph(),
        index.generation(),
        node,
    )
}

fn published_node_is_invocation_target_with_index(
    index: Option<&GenerationQueryIndex>,
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    node: &GraphNode,
) -> Result<bool, DomainError> {
    if structural_node_is_invocation_target(node) {
        return Ok(true);
    }
    if node.kind != "static" {
        return Ok(false);
    }
    let language = language_id_for_path(&node.file_path);
    // A callable-valued static needs semantic evidence for this exact target,
    // not complete negative authority over every possible caller in the
    // language. Keep this on the same target-scoped authority path as Calls,
    // Tests, and Assess so one uncovered project unit does not create a second
    // transport-specific notion of callability.
    let calls = match index {
        Some(index) => index.calls_for_target(&language, node)?,
        None => std::sync::Arc::new(PublishedCallsGraph::build_for_target(
            graph, generation, &language, node,
        )?),
    };
    Ok(calls.nodes.contains_key(&node.memory_id))
}

fn selected_payloads<'a>(
    payloads: impl Iterator<Item = &'a ProviderPayload> + Clone,
    receipts: &[crate::code_intel_domain::CapabilityReceipt],
) -> Result<Vec<&'a CallsProviderPayload>, DomainError> {
    let mut selected = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        let matches = payloads
            .clone()
            .filter_map(|payload| match payload {
                ProviderPayload::Calls(payload) if &payload.receipt == receipt => Some(payload),
                ProviderPayload::Calls(_) => None,
                ProviderPayload::CallableLiveness(_) => None,
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(invalid_generation(format!(
                "selected complete receipt from {} has {} matching Calls payloads",
                receipt.provider_id,
                matches.len()
            )));
        }
        selected.push(matches[0]);
    }
    Ok(selected)
}

const fn invalid_generation(reason: String) -> DomainError {
    DomainError::PublishedGenerationInvalid { reason }
}

/// SCIP providers report a method's declared name (`increment`, `Hello`),
/// while the structural graph qualifies that same declaration by its parent
/// (`impl Counter::increment`, `Greeter::Hello`). The exact document, language,
/// definition line, exact syntax-derived callable extent, and callable-kind
/// checks remain the identity anchors; this comparison reconciles only the
/// common qualified/unqualified presentation.
fn provider_declared_name_matches_node(provider_name: &str, structural_name: &str) -> bool {
    provider_name == structural_name
        || structural_name
            .rsplit("::")
            .next()
            .is_some_and(|declared_name| provider_name == declared_name)
}

pub(crate) fn structural_node_is_invocation_target(node: &GraphNode) -> bool {
    structural_kind_is_invocation_target(&language_id_for_path(&node.file_path).0, &node.kind)
}

fn structural_kind_is_invocation_target(language_id: &str, kind: &str) -> bool {
    structural_node_is_callable_kind(kind) || (language_id == "python" && kind == "class")
}

fn potential_calls_target(node: &GraphNode) -> bool {
    structural_node_is_invocation_target(node) || node.kind == "static"
}

/// Prefer the role-eligible Calls population without misreporting an existing
/// ordinary-name symbol as absent. The filtered pass lets a callable win over
/// same-name imports or value bindings. Only when that population is empty do
/// we resolve the role-neutral name to distinguish a true miss, an ambiguity,
/// and one exact non-callable occurrence.
fn resolve_calls_target_candidate<'a>(
    graph: &'a KnowledgeGraph,
    generation: &ResolvedGeneration,
    symbol: &str,
    normalized_file: Option<&str>,
) -> Result<&'a GraphNode, DomainError> {
    match resolve_symbol_selector_matching(
        graph,
        generation,
        symbol,
        normalized_file,
        NameFileSelection::Locality,
        potential_calls_target,
    ) {
        Err(not_found @ DomainError::SymbolNotFound { .. }) => {
            match resolve_symbol_selector(
                graph,
                generation,
                symbol,
                normalized_file,
                NameFileSelection::Locality,
            ) {
                Ok(node) if !potential_calls_target(node) => Err(DomainError::SymbolNotCallable {
                    symbol: node.symbol_name.clone(),
                    kind: node.kind.clone(),
                }),
                Ok(_) | Err(DomainError::SymbolNotFound { .. }) => Err(not_found),
                Err(error) => Err(error),
            }
        }
        result => result,
    }
}

fn structural_node_is_callable_kind(kind: &str) -> bool {
    symbol_kind_has_role(kind, SymbolRole::Callable)
}

#[cfg(test)]
mod polyglot_symbol_role_tests {
    use super::{structural_kind_is_invocation_target, structural_node_is_callable_kind};

    /// FALSIFIER for provider/structural joins: language adapters may preserve
    /// the source-level distinction between a function, method, and
    /// constructor, but all three must enter the exact callable population.
    #[test]
    fn callable_role_is_not_a_rust_go_function_spelling_check() {
        assert!(
            structural_node_is_callable_kind("function"),
            "known-positive control"
        );
        assert!(structural_node_is_callable_kind("method"));
        assert!(structural_node_is_callable_kind("constructor"));
        assert!(
            !structural_node_is_callable_kind("class"),
            "a class does not own a language-neutral callable body"
        );
        assert!(
            structural_kind_is_invocation_target("python", "class"),
            "Python class objects are direct invocation targets"
        );
        assert!(
            !structural_kind_is_invocation_target("typescript", "class"),
            "TypeScript construction must not inherit Python invocation policy"
        );
    }
}

fn coverage_exclusion_covers_node(
    graph: &KnowledgeGraph,
    exclusion: &ProviderCoverageExclusion,
    node: &GraphNode,
) -> bool {
    let Some(graph_span) = graph.source_span(&node.memory_id) else {
        return false;
    };
    exclusion.location.document_path == node.file_path
        && usize::try_from(exclusion.location.span.start_byte)
            .ok()
            .is_some_and(|start| start <= graph_span.start_byte)
        && usize::try_from(exclusion.location.span.end_byte)
            .ok()
            .is_some_and(|end| graph_span.end_byte <= end)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StructuralInvocationTargetKey {
    language_id: LanguageId,
    document_path: String,
    start_byte: usize,
    end_byte: usize,
}

/// Prove that every source-backed callable in a normalized Calls payload has
/// one exact structural definition in the graph that will be co-published with
/// it. Normalization establishes provider/source agreement; this final join
/// establishes provider/structural agreement before either payload can be
/// advertised as complete.
fn calls_payload_structural_join(
    graph: &KnowledgeGraph,
    payload: &CallsProviderPayload,
) -> Result<BTreeMap<String, Uuid>, DomainError> {
    let structural_targets = structural_invocation_target_index(graph);
    let mut joined = BTreeMap::new();
    let symbols = payload
        .symbols
        .iter()
        .map(|symbol| (symbol.provider_symbol_id.as_str(), symbol))
        .collect::<BTreeMap<_, _>>();
    let mut required_local_symbols = BTreeSet::new();
    for call in &payload.calls {
        required_local_symbols.insert(call.caller_symbol_id.as_str());
        if symbols
            .get(call.callee_symbol_id.as_str())
            .is_some_and(|symbol| symbol.definition.is_some() && symbol.structural_extent.is_some())
        {
            required_local_symbols.insert(call.callee_symbol_id.as_str());
        }
    }
    for binding in &payload.callable_bindings {
        required_local_symbols.insert(binding.binding_symbol_id.as_str());
        required_local_symbols.insert(binding.target_symbol_id.as_str());
    }
    for provider_symbol_id in required_local_symbols {
        let symbol = symbols.get(provider_symbol_id).ok_or_else(|| {
            invalid_generation(format!(
                "provider relationship references missing symbol {provider_symbol_id}"
            ))
        })?;
        let node = graph_node_for_provider_symbol(&structural_targets, symbol)?;
        joined.insert(provider_symbol_id.to_owned(), node.memory_id);
    }
    Ok(joined)
}

/// Validate the exact provider/structural join without mutating the graph.
///
/// The public raw publication lane uses this after normalizing its payloads;
/// the proof-backed indexing lane already calls the projecting form before it
/// seals the candidate graph.
pub(crate) fn validate_calls_payload_structural_join(
    graph: &KnowledgeGraph,
    payload: &CallsProviderPayload,
) -> Result<(), DomainError> {
    calls_payload_structural_join(graph, payload).map(drop)
}

/// Join every compiler-classified named function/method to exactly one
/// co-published structural declaration. The capability intentionally says
/// nothing about function-valued variables or anonymous closures; those may
/// carry dispatch during RTA without becoming deletion candidates themselves.
pub(crate) fn callable_liveness_payload_structural_join(
    graph: &KnowledgeGraph,
    payload: &CallableLivenessProviderPayload,
) -> Result<BTreeMap<Uuid, ProviderCallableLiveness>, DomainError> {
    let language_id = payload.receipt.scope.language_id().ok_or_else(|| {
        invalid_generation("callable-liveness receipt does not identify a source language".into())
    })?;
    let structural_targets = structural_invocation_target_index(graph);
    let mut joined = BTreeMap::new();
    for callable in &payload.callables {
        let definition = &callable.definition;
        let extent = &callable.structural_extent;
        if definition.document_path != extent.document_path {
            return Err(invalid_generation(format!(
                "callable-liveness declaration {} names different definition and extent documents",
                callable.name
            )));
        }
        let start_byte = usize::try_from(extent.span.start_byte).map_err(|_| {
            invalid_generation(format!(
                "callable-liveness start byte for {} does not fit this platform",
                callable.name
            ))
        })?;
        let end_byte = usize::try_from(extent.span.end_byte).map_err(|_| {
            invalid_generation(format!(
                "callable-liveness end byte for {} does not fit this platform",
                callable.name
            ))
        })?;
        let key = StructuralInvocationTargetKey {
            language_id: language_id.clone(),
            document_path: extent.document_path.clone(),
            start_byte,
            end_byte,
        };
        let candidates = structural_targets
            .get(&key)
            .into_iter()
            .flatten()
            .copied()
            .filter(|node| provider_declared_name_matches_node(&callable.name, &node.symbol_name))
            .filter(|node| structural_node_is_invocation_target(node))
            .filter(|node| {
                let (Some(start), Some(end)) = (node.line_start, node.line_end) else {
                    return false;
                };
                start <= definition.span.start_line as usize
                    && definition.span.end_line as usize <= end
            })
            .collect::<Vec<_>>();
        let node = match candidates.as_slice() {
            [node] => *node,
            [] => {
                return Err(invalid_generation(format!(
                    "callable-liveness declaration {} has no co-published structural node",
                    callable.name
                )));
            }
            _ => {
                return Err(invalid_generation(format!(
                    "callable-liveness declaration {} maps to multiple co-published structural nodes",
                    callable.name
                )));
            }
        };
        if joined.insert(node.memory_id, callable.clone()).is_some() {
            return Err(invalid_generation(format!(
                "multiple callable-liveness records map to structural declaration {}",
                node.symbol_name
            )));
        }
    }
    Ok(joined)
}

pub(crate) fn validate_callable_liveness_payload_structural_join(
    graph: &KnowledgeGraph,
    payload: &CallableLivenessProviderPayload,
) -> Result<(), DomainError> {
    callable_liveness_payload_structural_join(graph, payload).map(drop)
}

/// Result of projecting normalized provider Calls into the co-published graph.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CallsGraphProjectionStats {
    pub novel_edges: usize,
}

/// Project only structurally joined, normalized explicit invocations into the
/// graph. Raw SCIP occurrence shape cannot distinguish a function value
/// reference (`let f = target`) from an invocation (`target()`), so this is the
/// sole semantic authority allowed to create provider-backed `Calls` edges.
pub(crate) fn project_calls_payload_structural_join(
    graph: &mut KnowledgeGraph,
    payload: &CallsProviderPayload,
) -> Result<CallsGraphProjectionStats, DomainError> {
    const CONFIDENCE_SCIP: f32 = 0.9;

    // Complete the entire immutable join and edge-plan validation before
    // mutating the graph. Bad provider identity or conflicting structural
    // scope therefore cannot leave a partially projected relation.
    let joined = calls_payload_structural_join(graph, payload)?;
    let symbols = payload
        .symbols
        .iter()
        .map(|symbol| (symbol.provider_symbol_id.as_str(), symbol))
        .collect::<BTreeMap<_, _>>();
    let mut projected = BTreeMap::<(Uuid, Uuid), EdgeScope>::new();
    for call in &payload.calls {
        let caller = joined.get(&call.caller_symbol_id).copied().ok_or_else(|| {
            invalid_generation(format!(
                "provider call references unjoined local caller {}",
                call.caller_symbol_id
            ))
        })?;
        let callee_symbol = symbols.get(call.callee_symbol_id.as_str()).ok_or_else(|| {
            invalid_generation(format!(
                "provider call references missing callee symbol {}",
                call.callee_symbol_id
            ))
        })?;
        if callee_symbol.definition.is_none() || callee_symbol.structural_extent.is_none() {
            // External calls remain exact provider evidence, but the local graph
            // deliberately has no fabricated external node to receive an edge.
            continue;
        }
        let callee = joined.get(&call.callee_symbol_id).copied().ok_or_else(|| {
            invalid_generation(format!(
                "provider call references unjoined local callee {}",
                call.callee_symbol_id
            ))
        })?;
        let scope = if crate::extractor::file_is_test(&call.call_site.document_path) {
            EdgeScope::Test
        } else {
            EdgeScope::Production
        };
        match projected.entry((caller, callee)) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(scope);
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                if *entry.get() != scope {
                    return Err(invalid_generation(format!(
                        "provider calls between {caller} and {callee} disagree on source scope"
                    )));
                }
            }
        }
    }

    let mut existing_calls = BTreeMap::<(Uuid, Uuid), EdgeScope>::new();
    for (caller, callee, edge) in graph
        .all_edges()
        .into_iter()
        .filter(|(_, _, edge)| edge.kind == EdgeKind::Calls)
    {
        if edge.source != EdgeSource::Scip {
            return Err(invalid_generation(format!(
                "graph contains non-canonical Calls between {caller} and {callee}; normalized provider payloads are the sole Calls authority"
            )));
        }
        if existing_calls
            .insert((caller, callee), edge.scope)
            .is_some()
        {
            return Err(invalid_generation(format!(
                "graph contains duplicate canonical Calls between {caller} and {callee}"
            )));
        }
    }
    for &(caller, callee) in projected.keys() {
        if existing_calls.contains_key(&(caller, callee)) {
            return Err(invalid_generation(format!(
                "multiple provider payloads claim the same Calls edge between {caller} and {callee}"
            )));
        }
    }

    let mut stats = CallsGraphProjectionStats::default();
    for ((caller, callee), scope) in projected {
        graph
            .add_edge(
                caller,
                callee,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    weight: 1.0,
                    source: EdgeSource::Scip,
                    confidence: CONFIDENCE_SCIP,
                    scope,
                    ..Default::default()
                },
            )
            .map_err(|error| {
                invalid_generation(format!(
                    "normalized Calls projection references a missing structural node: {error}"
                ))
            })?;
        stats.novel_edges += 1;
    }
    Ok(stats)
}

fn structural_invocation_target_index(
    graph: &KnowledgeGraph,
) -> BTreeMap<StructuralInvocationTargetKey, Vec<&GraphNode>> {
    let mut index = BTreeMap::<StructuralInvocationTargetKey, Vec<&GraphNode>>::new();
    for node in graph
        .all_nodes()
        .iter()
        .filter(|node| structural_node_is_invocation_target(node) || node.kind == "static")
    {
        let (Some(_line_start), Some(_line_end), Some(span)) = (
            node.line_start,
            node.line_end,
            graph.source_span(&node.memory_id),
        ) else {
            continue;
        };
        index
            .entry(StructuralInvocationTargetKey {
                language_id: language_id_for_path(&node.file_path),
                document_path: node.file_path.clone(),
                start_byte: span.start_byte,
                end_byte: span.end_byte,
            })
            .or_default()
            .push(node);
    }
    index
}

fn graph_node_for_provider_symbol<'a>(
    index: &BTreeMap<StructuralInvocationTargetKey, Vec<&'a GraphNode>>,
    symbol: &ProviderSymbol,
) -> Result<&'a GraphNode, DomainError> {
    let definition = symbol.definition.as_ref().ok_or_else(|| {
        invalid_generation(format!(
            "provider callable symbol {} has no local definition",
            symbol.provider_symbol_id
        ))
    })?;
    let extent = symbol.structural_extent.as_ref().ok_or_else(|| {
        invalid_generation(format!(
            "provider invocation target {} has no local structural extent",
            symbol.provider_symbol_id
        ))
    })?;
    if definition.document_path != extent.document_path {
        return Err(invalid_generation(format!(
            "provider callable symbol {} definition and callable extent name different documents",
            symbol.provider_symbol_id
        )));
    }
    if definition.span.start_byte < extent.span.start_byte
        || definition.span.end_byte > extent.span.end_byte
        || definition.span.start_line < extent.span.start_line
        || definition.span.end_line > extent.span.end_line
    {
        return Err(invalid_generation(format!(
            "provider callable symbol {} definition is outside its callable extent",
            symbol.provider_symbol_id
        )));
    }
    let convert = |field: &'static str, value: u64| {
        usize::try_from(value).map_err(|_| {
            invalid_generation(format!(
                "provider {field} for {} does not fit this platform",
                symbol.provider_symbol_id
            ))
        })
    };
    let key = StructuralInvocationTargetKey {
        language_id: symbol.language_id.clone(),
        document_path: definition.document_path.clone(),
        start_byte: convert("callable start_byte", extent.span.start_byte)?,
        end_byte: convert("callable end_byte", extent.span.end_byte)?,
    };
    let candidates = index
        .get(&key)
        .into_iter()
        .flatten()
        .copied()
        .filter(|node| provider_declared_name_matches_node(&symbol.name, &node.symbol_name))
        .filter(|node| {
            structural_node_is_invocation_target(node)
                || (node.kind == "static"
                    && matches!(
                        symbol.provider_kind.as_str(),
                        "variable" | "staticvariable" | "constant" | "field"
                    ))
        })
        .filter(|node| {
            let (Some(start), Some(end)) = (node.line_start, node.line_end) else {
                return false;
            };
            start <= definition.span.start_line as usize && definition.span.end_line as usize <= end
        })
        .collect::<Vec<_>>();
    match candidates.as_slice() {
        [node] => Ok(*node),
        [] => Err(invalid_generation(format!(
            "provider callable symbol {} has no co-published structural node",
            symbol.provider_symbol_id
        ))),
        _ => Err(invalid_generation(format!(
            "provider callable symbol {} maps to multiple co-published structural nodes",
            symbol.provider_symbol_id
        ))),
    }
}

fn symbol_identity(
    symbol: &ProviderSymbol,
    structural_node: &GraphNode,
    inventory: &ProjectInventory,
    repository_id: &crate::code_intel_domain::RepositoryId,
    generation_id: &GenerationId,
) -> Result<SymbolIdentity, DomainError> {
    let definition = symbol.definition.as_ref().ok_or_else(|| {
        invalid_generation(format!(
            "provider symbol {} has no local definition",
            symbol.provider_symbol_id
        ))
    })?;
    let project_unit_ids =
        source_owner_ids(inventory, &definition.document_path, &symbol.language_id)?;
    Ok(SymbolIdentity {
        symbol_id: exact_symbol_id(repository_id, generation_id, structural_node.memory_id),
        name: symbol.name.clone(),
        kind: structural_node.kind.clone(),
        document_path: definition.document_path.clone(),
        language_id: symbol.language_id.clone(),
        project_unit_ids,
        configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        definition_span: Some(source_span(&definition.span)?),
    })
}

fn source_owner_ids(
    inventory: &ProjectInventory,
    document_path: &str,
    language_id: &LanguageId,
) -> Result<Vec<ProjectUnitId>, DomainError> {
    let project_unit_ids = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.document_path == document_path
                && membership.language_id == *language_id
                && inventory.is_semantic_source_owner(membership)
        })
        .map(|membership| membership.project_unit_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if project_unit_ids.is_empty() {
        if inventory
            .project_topology
            .memberships
            .iter()
            .any(|membership| {
                membership.document_path == document_path
                    && membership.language_id == *language_id
                    && membership.kind
                        == crate::code_intel_domain::DocumentMembershipKind::SourceOwner
                    && !inventory.is_semantic_source_owner(membership)
            })
        {
            return Err(DomainError::CapabilityNotApplicable {
                capability: "calls".into(),
                reason: format!(
                    "the indexed {language_id} source population is structural-only and has no semantic project unit"
                ),
            });
        }
        return Err(DomainError::ProjectInventoryMismatch {
            document_path: document_path.into(),
            reason: format!("no source-owner membership exists for language {language_id}"),
        });
    }
    for project_unit_id in &project_unit_ids {
        if !inventory.project_topology.units.iter().any(|unit| {
            unit.project_unit_id == *project_unit_id && unit.language_id == *language_id
        }) {
            return Err(DomainError::ProjectInventoryMismatch {
                document_path: document_path.into(),
                reason: format!(
                    "source-owner unit {project_unit_id} is missing or has a different language"
                ),
            });
        }
    }
    Ok(project_unit_ids)
}

fn language_source_owner_ids(
    inventory: &ProjectInventory,
    language_id: &LanguageId,
) -> Result<Vec<ProjectUnitId>, DomainError> {
    let project_unit_ids = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.language_id == *language_id && inventory.is_semantic_source_owner(membership)
        })
        .map(|membership| membership.project_unit_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if project_unit_ids.is_empty() {
        if inventory
            .project_topology
            .memberships
            .iter()
            .any(|membership| {
                membership.language_id == *language_id
                    && membership.kind
                        == crate::code_intel_domain::DocumentMembershipKind::SourceOwner
                    && !inventory.is_semantic_source_owner(membership)
            })
        {
            return Err(DomainError::CapabilityNotApplicable {
                capability: "calls".into(),
                reason: format!(
                    "the indexed {language_id} source population is structural-only and has no semantic project unit"
                ),
            });
        }
        return Err(DomainError::ProjectInventoryMismatch {
            document_path: format!("<all {language_id} source owners>"),
            reason: "no source-owner membership exists for the target language".into(),
        });
    }
    for project_unit_id in &project_unit_ids {
        if !inventory.project_topology.units.iter().any(|unit| {
            unit.project_unit_id == *project_unit_id && unit.language_id == *language_id
        }) {
            return Err(DomainError::ProjectInventoryMismatch {
                document_path: format!("<all {language_id} source owners>"),
                reason: format!(
                    "source-owner unit {project_unit_id} is missing or has a different language"
                ),
            });
        }
    }
    Ok(project_unit_ids)
}

fn required_calls_scopes(
    inventory: &ProjectInventory,
    language_id: &LanguageId,
) -> Result<Vec<CapabilityScope>, DomainError> {
    Ok(language_source_owner_ids(inventory, language_id)?
        .into_iter()
        .map(|project_unit_id| CapabilityScope::ProjectUnit {
            language_id: language_id.clone(),
            project_unit_id,
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        })
        .collect())
}

fn required_calls_scopes_for_target(
    inventory: &ProjectInventory,
    language_id: &LanguageId,
    target_scopes: &[CapabilityScope],
) -> Result<Vec<CapabilityScope>, DomainError> {
    let language_units = language_source_owner_ids(inventory, language_id)?;
    let target_units = target_scopes
        .iter()
        .map(|scope| match scope {
            CapabilityScope::ProjectUnit {
                language_id: scope_language,
                project_unit_id,
                configuration_id,
            } if scope_language == language_id && configuration_id.0 == CALLS_CONFIGURATION_ID => {
                Ok(project_unit_id.clone())
            }
            _ => Err(invalid_generation(
                "Calls target scope is not a matching project-unit scope".into(),
            )),
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if target_units.is_empty()
        || !target_units
            .iter()
            .all(|unit_id| language_units.contains(unit_id))
    {
        return Err(invalid_generation(
            "Calls target scope is outside the indexed source-owner population".into(),
        ));
    }

    let complete_graphs = inventory
        .project_topology
        .dependency_graphs
        .iter()
        .filter(|graph| {
            graph.language_id == *language_id
                && graph.coverage
                    == crate::code_intel_domain::ProjectUnitDependencyGraphCoverage::Complete
                && graph.gaps.is_empty()
                && graph.project_unit_ids == language_units
                && target_units
                    .iter()
                    .all(|unit_id| graph.project_unit_ids.contains(unit_id))
        })
        .collect::<Vec<_>>();
    let [graph] = complete_graphs.as_slice() else {
        return required_calls_scopes(inventory, language_id);
    };
    let graph_units = graph.project_unit_ids.iter().collect::<BTreeSet<_>>();
    if graph.dependencies.iter().any(|dependency| {
        dependency.dependent_project_unit_id == dependency.dependency_project_unit_id
            || !graph_units.contains(&dependency.dependent_project_unit_id)
            || !graph_units.contains(&dependency.dependency_project_unit_id)
    }) {
        return required_calls_scopes(inventory, language_id);
    }

    let mut possible_callers = target_units;
    loop {
        let before = possible_callers.len();
        for dependency in &graph.dependencies {
            if possible_callers.contains(&dependency.dependency_project_unit_id) {
                possible_callers.insert(dependency.dependent_project_unit_id.clone());
            }
        }
        if possible_callers.len() == before {
            break;
        }
    }
    Ok(possible_callers
        .into_iter()
        .map(|project_unit_id| CapabilityScope::ProjectUnit {
            language_id: language_id.clone(),
            project_unit_id,
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        })
        .collect())
}

pub(crate) fn required_calls_documents_for_project_unit(
    inventory: &ProjectInventory,
    language_id: &LanguageId,
    project_unit_id: &ProjectUnitId,
) -> Result<BTreeSet<String>, DomainError> {
    let target_scopes = [CapabilityScope::ProjectUnit {
        language_id: language_id.clone(),
        project_unit_id: project_unit_id.clone(),
        configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
    }];
    let required_scopes = required_calls_scopes_for_target(inventory, language_id, &target_scopes)?;
    required_scope_documents(inventory, language_id, &required_scopes)
}

/// Select one provider for the entire Calls population when possible. A
/// target-scoped query may otherwise use the unique provider covering all of
/// the target's owners and the largest caller-scope subset, while retaining
/// every uncovered scope as an explicit authority qualification. Evidence is
/// never combined across providers.
fn resolve_calls_provider_population(
    receipts: &[crate::code_intel_domain::CapabilityReceipt],
    required_scopes: &[CapabilityScope],
    target_scopes: Option<&[CapabilityScope]>,
) -> Result<(ResolvedCapabilityProvider, Vec<CapabilityScope>), DomainError> {
    match resolve_capability_provider(receipts, "calls", required_scopes, None) {
        Ok(provider) => return Ok((provider, Vec::new())),
        Err(error) if target_scopes.is_none() => {
            return Err(capability_resolution_domain_error("calls", error, receipts));
        }
        Err(_) => {}
    }

    let target_scopes = target_scopes.expect("guarded target scopes");
    let provider_ids = receipts
        .iter()
        .filter(|receipt| {
            receipt.capability_id == "calls"
                && receipt.status == CapabilityStatus::Complete
                && required_scopes
                    .iter()
                    .any(|required| receipt.scope.covers(required))
        })
        .map(|receipt| receipt.provider_id.clone())
        .collect::<BTreeSet<_>>();
    let mut candidates = Vec::new();
    for provider_id in provider_ids {
        let covered_scopes = required_scopes
            .iter()
            .filter(|required| {
                receipts.iter().any(|receipt| {
                    receipt.capability_id == "calls"
                        && receipt.status == CapabilityStatus::Complete
                        && receipt.provider_id == provider_id
                        && receipt.scope.covers(required)
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        if !target_scopes
            .iter()
            .all(|target| covered_scopes.contains(target))
        {
            continue;
        }
        let provider =
            resolve_capability_provider(receipts, "calls", &covered_scopes, Some(&provider_id))
                .map_err(|error| capability_resolution_domain_error("calls", error, receipts))?;
        let missing_scopes = required_scopes
            .iter()
            .filter(|required| !covered_scopes.contains(required))
            .cloned()
            .collect::<Vec<_>>();
        candidates.push((covered_scopes.len(), provider, missing_scopes));
    }

    let Some(maximum_coverage) = candidates.iter().map(|candidate| candidate.0).max() else {
        let error = resolve_capability_provider(receipts, "calls", required_scopes, None)
            .expect_err("complete provider was already handled");
        return Err(capability_resolution_domain_error("calls", error, receipts));
    };
    candidates.retain(|candidate| candidate.0 == maximum_coverage);
    if candidates.len() != 1 {
        return Err(DomainError::CapabilityAmbiguous {
            capability: "calls".into(),
            scopes: required_scopes.to_vec(),
            providers: candidates
                .into_iter()
                .map(|(_, provider, _)| provider.provider_id)
                .collect(),
        });
    }
    let (_, provider, missing_scopes) = candidates.pop().expect("one candidate remains");
    Ok((provider, missing_scopes))
}

fn missing_scope_documents(
    inventory: &ProjectInventory,
    language_id: &LanguageId,
    missing_scopes: &[CapabilityScope],
) -> Result<BTreeSet<String>, DomainError> {
    let missing_units = missing_scopes
        .iter()
        .map(|scope| match scope {
            CapabilityScope::ProjectUnit {
                language_id: scope_language,
                project_unit_id,
                configuration_id,
            } if scope_language == language_id && configuration_id.0 == CALLS_CONFIGURATION_ID => {
                Ok(project_unit_id.clone())
            }
            _ => Err(invalid_generation(
                "Calls partial-provider selection produced a non-project-unit scope".into(),
            )),
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let documents = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.language_id == *language_id
                && inventory.is_semantic_source_owner(membership)
                && missing_units.contains(&membership.project_unit_id)
        })
        .map(|membership| membership.document_path.clone())
        .collect::<BTreeSet<_>>();
    if documents.is_empty()
        || missing_units.iter().any(|unit| {
            !inventory
                .project_topology
                .memberships
                .iter()
                .any(|membership| {
                    membership.language_id == *language_id
                        && inventory.is_semantic_source_owner(membership)
                        && membership.project_unit_id == *unit
                })
        })
    {
        return Err(invalid_generation(
            "Calls missing-scope qualification has no exact source-owner population".into(),
        ));
    }
    Ok(documents)
}

fn required_scope_documents(
    inventory: &ProjectInventory,
    language_id: &LanguageId,
    required_scopes: &[CapabilityScope],
) -> Result<BTreeSet<String>, DomainError> {
    let documents = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            if membership.language_id != *language_id
                || !inventory.is_semantic_source_owner(membership)
            {
                return false;
            }
            let source_scope = CapabilityScope::ProjectUnit {
                language_id: language_id.clone(),
                project_unit_id: membership.project_unit_id.clone(),
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            };
            required_scopes
                .iter()
                .any(|required| required.covers(&source_scope))
        })
        .map(|membership| membership.document_path.clone())
        .collect::<BTreeSet<_>>();
    if documents.is_empty() {
        return Err(invalid_generation(
            "Calls required scopes have no exact source-owner document population".into(),
        ));
    }
    Ok(documents)
}

fn source_span(span: &NormalizedSourceSpan) -> Result<SourceSpan, DomainError> {
    let convert = |field: &'static str, value: u64| {
        usize::try_from(value)
            .map_err(|_| invalid_generation(format!("provider {field} does not fit this platform")))
    };
    Ok(SourceSpan {
        start_byte: convert("start_byte", span.start_byte)?,
        end_byte: convert("end_byte", span.end_byte)?,
        start_line: span.start_line as usize,
        start_column: span.start_utf8_byte_column as usize,
        end_line: span.end_line as usize,
        end_column: span.end_utf8_byte_column as usize,
    })
}

pub(crate) fn filter_admits(filter: CallerFilter, reachability: ReachabilityClass) -> bool {
    match filter {
        CallerFilter::All => true,
        CallerFilter::Live => !matches!(
            reachability,
            ReachabilityClass::Dead | ReachabilityClass::Orphan
        ),
        CallerFilter::Dead => matches!(
            reachability,
            ReachabilityClass::Dead | ReachabilityClass::Orphan
        ),
        CallerFilter::TestOnly => reachability == ReachabilityClass::TestOnly,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReferenceKey {
    document_path: String,
    start_byte: usize,
    end_byte: usize,
    caller_symbol_id: String,
}

impl ReferenceKey {
    fn from_parts(caller: &SymbolIdentity, call_span: &SourceSpan) -> Self {
        Self {
            document_path: caller.document_path.clone(),
            start_byte: call_span.start_byte,
            end_byte: call_span.end_byte,
            caller_symbol_id: caller.symbol_id.clone(),
        }
    }
}

pub(crate) fn calls_request_digest(request: &CallsRequest) -> String {
    let filter = format!("{:?}", request.filter);
    request_digest(
        "calls",
        &[
            request.symbol.as_str(),
            request.file.as_deref().unwrap_or_default(),
            filter.as_str(),
        ],
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn path_language_identity_is_derived_from_the_registered_language_boundary() {
        for path in [
            "src/lib.rs",
            "cmd/main.go",
            "web/app.ts",
            "web/app.js",
            "python/tool.py",
            "src/plugin.php",
            "README",
        ] {
            let extension = Path::new(path)
                .extension()
                .and_then(|extension| extension.to_str())
                .unwrap_or_default();
            let expected = crate::language::language_for_extension(extension).unwrap_or("unknown");
            assert_eq!(
                language_id_for_path(path),
                LanguageId::new(expected),
                "Calls must not maintain a second extension registry for {path}"
            );
        }
    }
    use crate::code_intel_domain::{
        CapabilityReceipt, ConfigurationId, DocumentMembership, DocumentMembershipKind,
        EcosystemId, ProjectUnit, ProjectUnitKind, RepositoryId,
    };
    use crate::code_intel_payload::{
        CALLS_PROVIDER_PAYLOAD_SCHEMA, ProviderCall, ProviderCallableBinding,
        ProviderCoverageExclusion, ProviderDocument, ProviderLocation, ProviderSymbolRole,
        normalize_provider_payload_typed, provider_payload_descriptor,
    };
    use crate::code_intel_publication::{GenerationManifest, PublicationHead, PublicationHeadBody};
    use crate::project_binding::ProjectBindingOptions;

    const DOCUMENT: &str = "src/lib.rs";
    const MISSING_DOCUMENT: &str = "providers/provider.rs";
    const INDEPENDENT_DOCUMENT: &str = "providers/src/lib.rs";
    const TARGET_LINE: usize = 9;

    pub struct Fixture {
        _temporary: TempDir,
        pub binding: ProjectBinding,
        pub graph: KnowledgeGraph,
        pub generation: ResolvedGeneration,
    }

    fn graph_node(name: &str, line: usize) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.into(),
            kind: "function".into(),
            file_path: DOCUMENT.into(),
            content_hash: format!("hash-{name}"),
            signature: format!("fn {name}()"),
            reachability_class: ReachabilityClass::Wired,
            line_start: Some(line),
            line_end: Some(line),
            has_body: Some(true),
            visibility: "pub".into(),
            is_test_only: Some(false),
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        }
    }

    fn span(line: usize, start_byte: u64, end_byte: u64) -> NormalizedSourceSpan {
        NormalizedSourceSpan {
            start_byte,
            end_byte,
            start_line: line as u32,
            start_utf8_byte_column: 4,
            end_line: line as u32,
            end_utf8_byte_column: 4 + (end_byte - start_byte) as u32,
        }
    }

    fn location(line: usize, start_byte: u64, end_byte: u64) -> ProviderLocation {
        ProviderLocation {
            document_path: DOCUMENT.into(),
            span: span(line, start_byte, end_byte),
        }
    }

    fn owner_scope(owner: &str) -> CapabilityScope {
        CapabilityScope::ProjectUnit {
            language_id: LanguageId::new("rust"),
            project_unit_id: ProjectUnitId::new(owner),
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        }
    }

    fn complete_receipt(
        provider: &str,
        scope: CapabilityScope,
        fingerprint: char,
    ) -> CapabilityReceipt {
        CapabilityReceipt::complete(
            "calls",
            provider,
            "1.2.3",
            scope,
            fingerprint.to_string().repeat(64),
        )
    }

    fn calls_payload(
        receipt: CapabilityReceipt,
        caller_names: &[&str],
        target_line: usize,
    ) -> ProviderPayload {
        let target_id = "provider-target".to_string();
        let target_byte = 900;
        let target_extent = location(target_line, target_byte, target_byte + 80);
        let mut symbols = vec![ProviderSymbol {
            provider_symbol_id: target_id.clone(),
            name: "target".into(),
            provider_kind: "function".into(),
            language_id: LanguageId::new("rust"),
            role: ProviderSymbolRole::SourceInvocationTarget,
            definition: Some(location(target_line, target_byte + 4, target_byte + 10)),
            structural_extent: Some(target_extent.clone()),
            call_owner_extent: Some(target_extent),
        }];
        let mut calls = Vec::new();
        for (line, caller_name) in caller_names.iter().enumerate() {
            let base = line as u64 * 100;
            let caller_extent = location(line, base, base + 80);
            let caller_id = format!("provider-caller-{caller_name}");
            symbols.push(ProviderSymbol {
                provider_symbol_id: caller_id.clone(),
                name: (*caller_name).into(),
                provider_kind: "function".into(),
                language_id: LanguageId::new("rust"),
                role: ProviderSymbolRole::SourceInvocationTarget,
                definition: Some(location(
                    line,
                    base + 4,
                    base + 4 + caller_name.len() as u64,
                )),
                structural_extent: Some(caller_extent.clone()),
                call_owner_extent: Some(caller_extent),
            });
            calls.push(ProviderCall {
                caller_symbol_id: caller_id,
                callee_symbol_id: target_id.clone(),
                call_site: location(line, base + 40, base + 46),
            });
        }
        ProviderPayload::Calls(CallsProviderPayload {
            schema_version: CALLS_PROVIDER_PAYLOAD_SCHEMA.into(),
            population: CallsPopulation::ProviderResolvedExplicitSourceInvocations,
            receipt,
            semantic_inputs: h00ligan_provider_protocol::ProviderSemanticInputs::empty(),
            execution_authority:
                crate::code_intel_payload::ProviderExecutionAuthority::InvocationBound {
                    provider_configurations_sha256: BTreeMap::new(),
                },
            canonical_snapshot_sha256: None,
            documents: vec![ProviderDocument {
                document_path: DOCUMENT.into(),
                language_id: LanguageId::new("rust"),
                content_sha256: "f".repeat(64),
                cross_document_surface_sha256: "e".repeat(64),
                byte_length: u64::try_from(
                    caller_names
                        .len()
                        .saturating_mul(100)
                        .saturating_add(100)
                        .max(1_024),
                )
                .expect("fixture document length fits u64"),
            }],
            symbols,
            calls,
            callable_bindings: Vec::new(),
            coverage_exclusions: Vec::new(),
        })
    }

    fn set_evidence(
        generation: &mut ResolvedGeneration,
        receipts: Vec<CapabilityReceipt>,
        payloads: Vec<ProviderPayload>,
    ) {
        generation.manifest.receipts = receipts;
        generation.manifest.provider_payloads = payloads
            .iter()
            .map(|payload| provider_payload_descriptor(payload).expect("valid payload descriptor"))
            .collect();
        generation.provider_payloads = payloads
            .iter()
            .map(|payload| normalize_provider_payload_typed(payload).expect("normalized fixture"))
            .collect();
    }

    pub fn fixture(caller_names: &[&str]) -> Fixture {
        let temporary = TempDir::new().expect("temporary directory");
        let root = temporary.path().join("repo");
        let graph_dir = temporary.path().join("bundle");
        std::fs::create_dir_all(root.join("src")).expect("source root");
        std::fs::create_dir_all(&graph_dir).expect("graph directory");
        std::fs::write(root.join(DOCUMENT), b"fixture source").expect("source fixture");
        let binding = ProjectBinding::resolve(
            ProjectBindingOptions::new(&root)
                .explicit_root(&root)
                .global_graph_dir(&graph_dir),
        )
        .expect("project binding");

        let mut graph = KnowledgeGraph::new();
        let target = graph_node("target", TARGET_LINE);
        let target_id = target.memory_id;
        graph.add_node(target).expect("target node");
        graph
            .set_source_span(
                target_id,
                crate::graph::SourceSpan {
                    start_byte: 900,
                    end_byte: 980,
                },
            )
            .expect("target source span");
        for (line, caller_name) in caller_names.iter().enumerate() {
            let caller = graph_node(caller_name, line);
            let caller_id = caller.memory_id;
            graph.add_node(caller).expect("caller node");
            graph
                .set_source_span(
                    caller_id,
                    crate::graph::SourceSpan {
                        start_byte: line * 100,
                        end_byte: line * 100 + 80,
                    },
                )
                .expect("caller source span");
        }

        let owner_ids = ["rust:workspace", "rust:nested"];
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: crate::code_intel_domain::ProjectTopology {
                units: owner_ids
                    .iter()
                    .enumerate()
                    .map(|(index, owner)| ProjectUnit {
                        project_unit_id: ProjectUnitId::new(*owner),
                        language_id: LanguageId::new("rust"),
                        ecosystem_id: EcosystemId::new("cargo"),
                        kind: if index == 0 {
                            ProjectUnitKind::Workspace
                        } else {
                            ProjectUnitKind::Package
                        },
                        root_path: if index == 0 { "" } else { "src" }.into(),
                        manifest_path: None,
                        compilation_root_paths: Vec::new(),
                    })
                    .collect(),
                memberships: owner_ids
                    .iter()
                    .map(|owner| DocumentMembership {
                        document_path: DOCUMENT.into(),
                        language_id: LanguageId::new("rust"),
                        project_unit_id: ProjectUnitId::new(*owner),
                        kind: DocumentMembershipKind::SourceOwner,
                    })
                    .collect(),
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: Vec::new(),
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: Vec::new(),
        };
        let receipt = complete_receipt(
            "provider-a",
            CapabilityScope::Repository {
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            },
            'a',
        );
        let payload = calls_payload(receipt.clone(), caller_names, TARGET_LINE);
        let repository_id = RepositoryId::new("repository-fixture");
        let generation_id = GenerationId::new("generation-a");
        let manifest = GenerationManifest {
            schema_version: "h00/code-intel/generation/v6".into(),
            generation_id: generation_id.clone(),
            repository_id: repository_id.clone(),
            parent_generation_id: None,
            source_revision: Some("fixture".into()),
            payload_blake3: "1".repeat(64),
            graph_publication_proof: crate::graph_store::GraphPublicationProof::test_fixture(),
            index_state_publication_proof:
                crate::index_state::IndexStatePublicationProof::test_fixture(),
            project_inventory_sha256: "2".repeat(64),
            receipts: vec![receipt],
            provider_payloads: vec![
                provider_payload_descriptor(&payload).expect("valid payload descriptor"),
            ],
        };
        let head = PublicationHead {
            body: PublicationHeadBody {
                schema_version: "h00/code-intel/head/v4".into(),
                sequence: 1,
                repository_id,
                generation_id,
                database_blake3: "3".repeat(64),
                manifest_sha256: "4".repeat(64),
                receipt_set_sha256: "5".repeat(64),
                provider_payload_set_sha256: "6".repeat(64),
                previous_generation_id: None,
            },
            digest: "7".repeat(64),
        };
        let generation = ResolvedGeneration {
            slot: 0,
            head,
            manifest,
            project_inventory: inventory.into(),
            provider_payloads: vec![
                normalize_provider_payload_typed(&payload).expect("normalized Calls fixture"),
            ],
            database_path: PathBuf::from("generation.redb"),
        };

        Fixture {
            _temporary: temporary,
            binding,
            graph,
            generation,
        }
    }

    fn configure_partial_owner_population(fixture: &mut Fixture) -> (ProjectUnitId, ProjectUnitId) {
        let covered = ProjectUnitId::new("rust:covered");
        let missing = ProjectUnitId::new("rust:missing");
        let inventory = std::sync::Arc::make_mut(&mut fixture.generation.project_inventory);
        inventory.project_topology.units = vec![
            ProjectUnit {
                project_unit_id: covered.clone(),
                language_id: LanguageId::new("rust"),
                ecosystem_id: EcosystemId::new("cargo"),
                kind: ProjectUnitKind::Package,
                root_path: "src".into(),
                manifest_path: Some("Cargo.toml".into()),
                compilation_root_paths: Vec::new(),
            },
            ProjectUnit {
                project_unit_id: missing.clone(),
                language_id: LanguageId::new("rust"),
                ecosystem_id: EcosystemId::new("cargo"),
                kind: ProjectUnitKind::Package,
                root_path: "providers".into(),
                manifest_path: Some("providers/Cargo.toml".into()),
                compilation_root_paths: Vec::new(),
            },
        ];
        inventory.project_topology.memberships = vec![
            DocumentMembership {
                document_path: DOCUMENT.into(),
                language_id: LanguageId::new("rust"),
                project_unit_id: covered.clone(),
                kind: DocumentMembershipKind::SourceOwner,
            },
            DocumentMembership {
                document_path: MISSING_DOCUMENT.into(),
                language_id: LanguageId::new("rust"),
                project_unit_id: missing.clone(),
                kind: DocumentMembershipKind::SourceOwner,
            },
        ];
        (covered, missing)
    }

    /// FALSIFIER: exact exclusions in a provably independent local package are
    /// outside the possible-caller population of the selected target. Treating
    /// them as target authority makes every multi-package repository only as
    /// precise as its least precise unrelated package.
    #[test]
    fn independent_package_exclusions_do_not_qualify_target_negative_authority() {
        let mut fixture = fixture(&[]);
        std::fs::create_dir_all(fixture.binding.root().join("providers/src"))
            .expect("independent package source directory");
        std::fs::write(
            fixture.binding.root().join("Cargo.toml"),
            "[package]\nname = \"target-package\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("target package manifest");
        std::fs::write(
            fixture.binding.root().join("providers/Cargo.toml"),
            "[package]\nname = \"independent-package\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("independent package manifest");
        std::fs::write(
            fixture.binding.root().join(INDEPENDENT_DOCUMENT),
            "pub fn unrelated_dynamic_region() {}\n",
        )
        .expect("independent package source");

        let inventory = crate::code_intel_inventory::build_project_inventory(
            fixture.binding.root(),
            &[
                crate::code_intel_inventory::InventorySource::new(DOCUMENT, "rust"),
                crate::code_intel_inventory::InventorySource::new(INDEPENDENT_DOCUMENT, "rust"),
            ],
        );
        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            "positive control: both real manifests must be classified"
        );
        let owner_for = |document: &str| {
            inventory
                .project_topology
                .memberships
                .iter()
                .find(|membership| {
                    membership.document_path == document
                        && membership.kind == DocumentMembershipKind::SourceOwner
                })
                .expect("source owner")
                .project_unit_id
                .clone()
        };
        let target_owner = owner_for(DOCUMENT);
        let independent_owner = owner_for(INDEPENDENT_DOCUMENT);
        assert_ne!(target_owner, independent_owner, "two-package control");
        fixture.generation.project_inventory = inventory.into();

        let repository_receipt = complete_receipt(
            "provider-a",
            CapabilityScope::Repository {
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            },
            'a',
        );
        let mut repository_payload = calls_payload(repository_receipt.clone(), &[], TARGET_LINE);
        let ProviderPayload::Calls(repository_calls) = &mut repository_payload else {
            unreachable!("Calls fixture")
        };
        repository_calls.documents.push(ProviderDocument {
            document_path: INDEPENDENT_DOCUMENT.into(),
            language_id: LanguageId::new("rust"),
            content_sha256: "d".repeat(64),
            cross_document_surface_sha256: "c".repeat(64),
            byte_length: 40,
        });
        repository_calls
            .coverage_exclusions
            .push(ProviderCoverageExclusion {
                location: ProviderLocation {
                    document_path: INDEPENDENT_DOCUMENT.into(),
                    span: span(0, 0, 39),
                },
                reason_code: "dynamic_callable_region".into(),
            });
        set_evidence(
            &mut fixture.generation,
            vec![repository_receipt.clone()],
            vec![repository_payload.clone()],
        );

        let result = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("independent package evidence must remain usable");

        assert!(result.items.is_empty(), "target has no callers");
        assert_eq!(
            result.authority.status,
            AuthorityStatus::Complete,
            "an unrelated package exclusion is outside the possible-caller closure"
        );
        assert!(result.authority.coverage_exclusions.is_empty());
        assert_eq!(result.authority.scopes, vec![owner_scope(&target_owner.0)]);

        let mut contradictory_payload = repository_payload.clone();
        let ProviderPayload::Calls(contradictory_calls) = &mut contradictory_payload else {
            unreachable!("Calls fixture")
        };
        contradictory_calls.symbols.push(ProviderSymbol {
            provider_symbol_id: "provider-independent-caller".into(),
            name: "unrelated_dynamic_region".into(),
            provider_kind: "function".into(),
            language_id: LanguageId::new("rust"),
            role: ProviderSymbolRole::SourceInvocationTarget,
            definition: Some(ProviderLocation {
                document_path: INDEPENDENT_DOCUMENT.into(),
                span: span(0, 4, 30),
            }),
            structural_extent: Some(ProviderLocation {
                document_path: INDEPENDENT_DOCUMENT.into(),
                span: span(0, 0, 39),
            }),
            call_owner_extent: Some(ProviderLocation {
                document_path: INDEPENDENT_DOCUMENT.into(),
                span: span(0, 0, 39),
            }),
        });
        contradictory_calls.calls.push(ProviderCall {
            caller_symbol_id: "provider-independent-caller".into(),
            callee_symbol_id: "provider-target".into(),
            call_site: ProviderLocation {
                document_path: INDEPENDENT_DOCUMENT.into(),
                span: span(0, 31, 37),
            },
        });
        set_evidence(
            &mut fixture.generation,
            vec![repository_receipt.clone()],
            vec![contradictory_payload],
        );
        let contradiction = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect_err("a cross-package call must invalidate a supposedly independent topology");
        assert!(
            contradiction
                .to_string()
                .contains("contradicts the persisted possible-caller dependency population"),
            "right-reason dependency-graph contradiction: {contradiction}"
        );
        set_evidence(
            &mut fixture.generation,
            vec![repository_receipt],
            vec![repository_payload],
        );

        std::fs::write(
            fixture.binding.root().join("providers/Cargo.toml"),
            "[package]\nname = \"dependent-package\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\ntarget-package = { path = \"..\" }\n",
        )
        .expect("dependent package manifest");
        fixture.generation.project_inventory =
            crate::code_intel_inventory::build_project_inventory(
                fixture.binding.root(),
                &[
                    crate::code_intel_inventory::InventorySource::new(DOCUMENT, "rust"),
                    crate::code_intel_inventory::InventorySource::new(INDEPENDENT_DOCUMENT, "rust"),
                ],
            )
            .into();
        let dependent = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("declared dependent remains in the possible-caller closure");
        assert_eq!(dependent.authority.status, AuthorityStatus::Qualified);
        assert_eq!(dependent.authority.coverage_exclusions.len(), 1);
        assert_eq!(
            dependent
                .authority
                .scopes
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                owner_scope(&target_owner.0),
                owner_scope(&independent_owner.0),
            ]),
            "reverse dependency direction controls the possible-caller closure"
        );

        let dependency_graph = std::sync::Arc::make_mut(&mut fixture.generation.project_inventory)
            .project_topology
            .dependency_graphs
            .first_mut()
            .expect("Cargo dependency graph");
        dependency_graph.coverage =
            crate::code_intel_domain::ProjectUnitDependencyGraphCoverage::Partial;
        dependency_graph
            .gaps
            .push(crate::code_intel_domain::ProjectUnitDependencyGap {
                reason_code: "falsifier_topology_unknown".into(),
                project_unit_id: None,
                path: "Cargo.toml".into(),
                detail: "positive fail-closed control".into(),
            });
        let partial = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("partial topology preserves conservative positive evidence");
        assert_eq!(partial.authority.status, AuthorityStatus::Qualified);
        assert_eq!(partial.authority.coverage_exclusions.len(), 1);
        assert_eq!(
            partial.authority.scopes.len(),
            2,
            "partial dependency evidence must restore the language-wide caller population"
        );
    }

    #[test]
    fn exact_authority_and_plural_owners_come_from_one_generation() {
        let fixture = fixture(&["caller"]);
        let result = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("exact Calls query");

        let owners = vec![
            ProjectUnitId::new("rust:nested"),
            ProjectUnitId::new("rust:workspace"),
        ];
        assert_eq!(result.generation_id.0, "generation-a");
        assert_eq!(result.repository.repository_id.0, "repository-fixture");
        assert_eq!(result.authority.provider_id.0, "provider-a");
        assert_eq!(result.authority.provider_version, "1.2.3");
        assert_eq!(result.authority.input_fingerprints, vec!["a".repeat(64)]);
        assert_eq!(
            serde_json::to_value(&result).expect("serializable result")["authority"]["population"],
            "provider_resolved_explicit_source_invocations",
            "machine consumers must see the exact population authorized by the result"
        );
        assert_eq!(result.resolved_symbol.project_unit_ids, owners);
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].caller.project_unit_ids, owners);
        assert_eq!(result.items[0].call_span.start_byte, 40);
    }

    /// FALSIFIER: a Calls name selector used to inherit graph-wide ambiguity
    /// from a same-name import binding even when exactly one candidate could
    /// possibly be a Calls target. The shared selector remains ambiguous for
    /// role-neutral verbs; only the Calls verb narrows its ordinary-name
    /// candidate population. Exact symbol IDs remain exact.
    #[test]
    fn calls_name_resolution_ignores_obviously_non_callable_bindings() {
        let mut fixture = fixture(&["caller"]);
        let mut imported = graph_node("target", 0);
        imported.kind = "import".into();
        imported.file_path = "src/caller.ts".into();
        fixture.graph.add_node(imported).expect("import binding");

        assert!(matches!(
            crate::code_intel_symbol::resolve_symbol_selector(
                &fixture.graph,
                &fixture.generation,
                "target",
                None,
                NameFileSelection::Locality,
            ),
            Err(DomainError::AmbiguousSymbol { .. })
        ));

        let result = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("Calls selects the only eligible callable target");
        assert_eq!(result.resolved_symbol.name, "target");
        assert_eq!(result.items.len(), 1, "positive Calls population control");
    }

    /// Right-reason RED: one process snapshot must not reconstruct the same
    /// generation-bound provider/structural projection for every request.
    /// The first assertion is the positive control proving this counter fires;
    /// the second fails on the delegating implementation because it reaches
    /// `PublishedCallsGraph::build_inner` again.
    #[test]
    fn repeated_identical_queries_reuse_one_generation_calls_projection() {
        let fixture = fixture(&["caller"]);
        let index = crate::code_intel_query_index::GenerationQueryIndex::new(
            std::sync::Arc::new(fixture.graph.clone()),
            std::sync::Arc::new(fixture.generation.clone()),
        );
        let request = CallsRequest::new("target");
        reset_published_calls_graph_builds();

        let first = index
            .query_calls(&fixture.binding, &request)
            .expect("first exact Calls query");
        assert_eq!(
            published_calls_graph_builds(),
            1,
            "positive control: the projection-build counter must fire"
        );

        let second = index
            .query_calls(&fixture.binding, &request)
            .expect("repeated exact Calls query");
        assert_eq!(first, second, "projection reuse must not change the result");
        assert_eq!(
            published_calls_graph_builds(),
            1,
            "an immutable generation query index must build this projection only once"
        );
    }

    /// FALSIFIER: the reusable query owner must own the exact immutable graph
    /// and generation it indexes. Accepting either snapshot again at query
    /// time permits a caller to populate or reuse a projection from an
    /// unrelated graph while reporting the selected generation identity.
    #[test]
    fn generation_query_index_owns_one_graph_generation_pair() {
        let fixture = fixture(&["caller"]);
        let graph = std::sync::Arc::new(fixture.graph);
        let generation = std::sync::Arc::new(fixture.generation);
        let index = crate::code_intel_query_index::GenerationQueryIndex::new(
            std::sync::Arc::clone(&graph),
            std::sync::Arc::clone(&generation),
        );
        let query: fn(
            &crate::code_intel_query_index::GenerationQueryIndex,
            &ProjectBinding,
            &CallsRequest,
        ) -> Result<ExactCallsResult, DomainError> =
            crate::code_intel_query_index::GenerationQueryIndex::query_calls;

        let result = query(&index, &fixture.binding, &CallsRequest::new("target"))
            .expect("query over the index-owned immutable snapshot");
        assert_eq!(result.items.len(), 1, "positive Calls population control");
        assert!(
            std::sync::Arc::ptr_eq(index.graph(), &graph),
            "the reusable projection owner must retain the exact graph snapshot"
        );
        assert!(
            std::sync::Arc::ptr_eq(index.generation(), &generation),
            "the reusable projection owner must retain the exact generation snapshot"
        );
    }

    #[test]
    fn generation_query_index_exposes_no_query_time_identity_substitution() {
        let fixture = fixture(&["caller"]);
        let graph = std::sync::Arc::new(fixture.graph.clone());
        let generation = std::sync::Arc::new(fixture.generation.clone());
        let index = crate::code_intel_query_index::GenerationQueryIndex::new(
            std::sync::Arc::clone(&graph),
            std::sync::Arc::clone(&generation),
        );
        let request = CallsRequest::new("target");
        reset_published_calls_graph_builds();
        let baseline = index
            .query_calls(&fixture.binding, &request)
            .expect("populate exact generation cache");
        assert_eq!(published_calls_graph_builds(), 1, "positive build control");

        let mut generation_changed = fixture.generation.clone();
        generation_changed.manifest.generation_id = GenerationId::new("generation-b");
        let mut payload_changed = fixture.generation.clone();
        payload_changed.manifest.payload_blake3 = "9".repeat(64);
        assert_ne!(
            generation_changed.manifest.generation_id,
            generation.manifest.generation_id
        );
        assert_ne!(
            payload_changed.manifest.payload_blake3,
            generation.manifest.payload_blake3
        );
        let repeated = index
            .query_calls(&fixture.binding, &request)
            .expect("only the index-owned identity remains queryable");
        assert_eq!(baseline, repeated);
        assert_eq!(
            published_calls_graph_builds(),
            1,
            "unrelated generation values cannot enter either cache reuse or rebuild"
        );
    }

    #[test]
    fn calls_tests_and_assess_share_the_same_target_projection() {
        let fixture = fixture(&["caller"]);
        let index = crate::code_intel_query_index::GenerationQueryIndex::new(
            std::sync::Arc::new(fixture.graph.clone()),
            std::sync::Arc::new(fixture.generation.clone()),
        );
        reset_published_calls_graph_builds();

        index
            .query_calls(&fixture.binding, &CallsRequest::new("target"))
            .expect("Calls projection");
        crate::code_intel_tests::query_published_tests_indexed(
            &index,
            &fixture.binding,
            &crate::code_intel_tests::TestsRequest::new("target"),
        )
        .expect("Tests projection");
        crate::code_intel_assess::query_published_assess_indexed(
            &index,
            &fixture.binding,
            &crate::code_intel_assess::AssessRequest::new("target"),
        )
        .expect("Assess projection");

        assert_eq!(
            published_calls_graph_builds(),
            1,
            "Calls, Tests, and Assess must consume one generation-owned target projection"
        );
    }

    #[test]
    fn loose_source_calls_are_not_applicable_but_structure_remains() {
        let mut fixture = fixture(&["caller"]);
        for unit in &mut std::sync::Arc::make_mut(&mut fixture.generation.project_inventory)
            .project_topology
            .units
        {
            unit.kind = ProjectUnitKind::LooseSources;
            unit.ecosystem_id = EcosystemId::new("rust");
            unit.manifest_path = None;
        }

        assert!(
            fixture.graph.node_by_name("target").is_some(),
            "positive control: the loose target remains structurally indexed"
        );
        let error = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect_err("an unowned source cannot claim provider-backed Calls authority");
        assert!(matches!(
            error,
            DomainError::CapabilityNotApplicable { ref capability, .. }
                if capability == "calls"
        ));
        assert_eq!(error.envelope().error.code, "capability_not_applicable");
        assert!(
            error
                .to_string()
                .contains("without a semantic project execution unit")
        );
    }

    /// FALSIFIER: one uncovered project unit must qualify negative Calls
    /// authority, not make exact positive evidence from every covered unit
    /// unusable. The selected provider remains singular and every missing
    /// caller population must be explicit in the returned authority.
    #[test]
    fn covered_project_unit_calls_remain_usable_with_an_explicit_missing_scope() {
        let mut fixture = fixture(&["caller"]);
        let (covered, _) = configure_partial_owner_population(&mut fixture);
        let receipt = complete_receipt("provider-a", owner_scope(&covered.0), 'a');
        let payload = calls_payload(receipt.clone(), &["caller"], TARGET_LINE);
        set_evidence(&mut fixture.generation, vec![receipt], vec![payload]);

        let result = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("covered provider evidence remains useful");

        assert_eq!(result.items.len(), 1, "positive Calls control");
        assert_eq!(result.authority.status, AuthorityStatus::Qualified);
        assert_eq!(result.authority.scopes, vec![owner_scope(&covered.0)]);
        assert_eq!(result.authority.coverage_exclusions.len(), 1);
        assert_eq!(
            result.authority.coverage_exclusions[0].reason_code,
            "provider_scope_population_incomplete"
        );
        assert_eq!(result.authority.coverage_exclusions[0].document_count, 1);
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("provider-covered source")),
            "missing caller scope must remain user-visible: {:?}",
            result.warnings
        );
    }

    #[test]
    fn partial_scope_zero_is_qualified_instead_of_claiming_global_absence() {
        let mut fixture = fixture(&[]);
        let (covered, _) = configure_partial_owner_population(&mut fixture);
        let receipt = complete_receipt("provider-a", owner_scope(&covered.0), 'a');
        let payload = calls_payload(receipt.clone(), &[], TARGET_LINE);
        set_evidence(&mut fixture.generation, vec![receipt], vec![payload]);

        let result = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("a covered target may report a qualified provider-local zero");

        assert!(result.items.is_empty(), "provider-local zero control");
        assert_eq!(result.authority.status, AuthorityStatus::Qualified);
        assert_eq!(result.authority.coverage_exclusions.len(), 1);
        assert!(
            result.warnings.iter().any(|warning| {
                warning.contains("results are complete only for provider-covered source")
            }),
            "the zero must not be mistaken for whole-language absence: {:?}",
            result.warnings
        );
    }

    #[test]
    fn provider_proven_static_uses_target_scoped_authority() {
        let mut fixture = fixture(&[]);
        let (covered, _) = configure_partial_owner_population(&mut fixture);
        let target_id = fixture
            .graph
            .node_by_name("target")
            .expect("target node")
            .memory_id;
        fixture
            .graph
            .node_mut(&target_id)
            .expect("mutable target")
            .kind = "static".into();
        let receipt = complete_receipt("provider-a", owner_scope(&covered.0), 'a');
        let mut payload = calls_payload(receipt.clone(), &[], TARGET_LINE);
        let ProviderPayload::Calls(calls) = &mut payload else {
            unreachable!("Calls fixture")
        };
        calls.symbols[0].provider_kind = "variable".into();
        set_evidence(&mut fixture.generation, vec![receipt], vec![payload]);

        let target = fixture.graph.node(&target_id).expect("published target");
        assert!(
            published_node_is_invocation_target(&fixture.graph, &fixture.generation, target)
                .expect("covered target-scoped callability evidence"),
            "a missing unrelated caller scope must not hide provider-proven target callability"
        );
    }

    #[test]
    fn target_scoped_authority_never_combines_disjoint_providers() {
        let covered = owner_scope("rust:covered");
        let missing = owner_scope("rust:missing");
        let receipts = vec![
            complete_receipt("provider-a", covered.clone(), 'a'),
            complete_receipt("provider-b", missing.clone(), 'b'),
        ];

        let (provider, missing_scopes) = resolve_calls_provider_population(
            &receipts,
            &[covered.clone(), missing.clone()],
            Some(std::slice::from_ref(&covered)),
        )
        .expect("one provider independently covers the target");

        assert_eq!(provider.provider_id, ProviderId::new("provider-a"));
        assert_eq!(provider.required_scopes, vec![covered]);
        assert_eq!(missing_scopes, vec![missing]);
        assert_eq!(provider.receipts.len(), 1);
    }

    #[test]
    fn equal_target_scoped_provider_populations_are_ambiguous() {
        let covered = owner_scope("rust:covered");
        let missing = owner_scope("rust:missing");
        let receipts = vec![
            complete_receipt("provider-a", covered.clone(), 'a'),
            complete_receipt("provider-b", covered.clone(), 'b'),
        ];

        let error = resolve_calls_provider_population(
            &receipts,
            &[covered.clone(), missing],
            Some(std::slice::from_ref(&covered)),
        )
        .expect_err("input order must not choose between equal authorities");

        match error {
            DomainError::CapabilityAmbiguous { providers, .. } => assert_eq!(
                providers,
                vec![ProviderId::new("provider-a"), ProviderId::new("provider-b")]
            ),
            other => panic!("expected explicit provider ambiguity, got {other}"),
        }
    }

    #[test]
    fn target_outside_every_provider_scope_fails_closed() {
        let covered = owner_scope("rust:covered");
        let missing = owner_scope("rust:missing");
        let receipt = complete_receipt("provider-a", covered.clone(), 'a');

        let error = resolve_calls_provider_population(
            &[receipt],
            &[covered, missing.clone()],
            Some(std::slice::from_ref(&missing)),
        )
        .expect_err("uncovered target scope has no semantic authority");

        match error {
            DomainError::CapabilityUnavailable { reason, .. } => assert_eq!(
                reason,
                "no single complete provider covers all of 2 required project-unit scopes"
            ),
            other => panic!("expected unavailable target authority, got {other}"),
        }
    }

    #[test]
    fn complete_provider_identity_authorizes_a_zero_caller_result() {
        let fixture = fixture(&[]);
        let result = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("provider-confirmed zero-caller target");

        assert_eq!(result.resolved_symbol.name, "target");
        assert!(result.items.is_empty());
        assert_eq!(result.page.total_items, 0);
        assert_eq!(result.total_callers, 0);
    }

    #[test]
    fn provider_proven_function_variable_is_a_callable_target() {
        let mut fixture = fixture(&["caller"]);
        let target_id = fixture
            .graph
            .node_by_name("target")
            .expect("target node")
            .memory_id;
        let target = fixture
            .graph
            .node_mut(&target_id)
            .expect("mutable target node");
        target.kind = "static".into();
        target.signature = "var target = implementation".into();

        let receipt = fixture.generation.manifest.receipts[0].clone();
        let mut payload = calls_payload(receipt.clone(), &["caller"], TARGET_LINE);
        let ProviderPayload::Calls(calls) = &mut payload else {
            unreachable!("Calls fixture")
        };
        calls.symbols[0].provider_kind = "variable".into();
        set_evidence(&mut fixture.generation, vec![receipt], vec![payload]);

        let result = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("provider-proven function variable must be queryable as callable");

        assert_eq!(result.resolved_symbol.kind, "static");
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].caller.name, "caller");
    }

    #[test]
    fn callable_binding_is_liveness_evidence_not_a_direct_call() {
        let mut fixture = fixture(&["caller"]);
        let alias_id = fixture
            .graph
            .node_by_name("target")
            .expect("alias node")
            .memory_id;
        fixture
            .graph
            .node_mut(&alias_id)
            .expect("mutable alias")
            .kind = "static".into();
        let implementation = graph_node("implementation", 20);
        let implementation_id = implementation.memory_id;
        fixture
            .graph
            .add_node(implementation)
            .expect("implementation node");
        fixture
            .graph
            .set_source_span(
                implementation_id,
                crate::graph::SourceSpan {
                    start_byte: 2_000,
                    end_byte: 2_080,
                },
            )
            .expect("implementation span");

        let receipt = fixture.generation.manifest.receipts[0].clone();
        let mut payload = calls_payload(receipt.clone(), &["caller"], TARGET_LINE);
        let ProviderPayload::Calls(calls) = &mut payload else {
            unreachable!("Calls fixture")
        };
        calls.documents[0].byte_length = 4_096;
        calls.symbols[0].provider_kind = "variable".into();
        calls.symbols.push(ProviderSymbol {
            provider_symbol_id: "provider-implementation".into(),
            name: "implementation".into(),
            provider_kind: "function".into(),
            language_id: LanguageId::new("rust"),
            role: ProviderSymbolRole::SourceInvocationTarget,
            definition: Some(location(20, 2_004, 2_018)),
            structural_extent: Some(location(20, 2_000, 2_080)),
            call_owner_extent: Some(location(20, 2_000, 2_080)),
        });
        calls.callable_bindings.push(ProviderCallableBinding {
            binding_symbol_id: "provider-target".into(),
            target_symbol_id: "provider-implementation".into(),
            binding_site: location(TARGET_LINE, 920, 934),
        });
        set_evidence(&mut fixture.generation, vec![receipt], vec![payload]);

        let published = PublishedCallsGraph::build(
            &fixture.graph,
            &fixture.generation,
            &LanguageId::new("rust"),
        )
        .expect("published calls graph with callable binding");
        assert!(
            published.outgoing(alias_id).is_empty(),
            "a value binding must never be reported as a direct invocation",
        );
        assert_eq!(
            published.liveness_successors(alias_id),
            vec![implementation_id],
            "conservative dead-code liveness must follow the exact value binding",
        );

        let implementation = fixture
            .graph
            .node(&implementation_id)
            .expect("implementation node remains published");
        let reverse = published
            .reverse_reachable(&fixture.graph, implementation, 2)
            .expect("reverse execution traversal");
        assert_eq!(
            reverse
                .paths
                .iter()
                .map(|path| path.caller.name.as_str())
                .collect::<Vec<_>>(),
            vec!["target", "caller"],
            "impact and test reachability must follow the same callable-value relation that authorizes liveness",
        );
        assert!(
            matches!(
                reverse.paths[0].chain.as_slice(),
                [CallablePathStep::CallableValueBinding(_)]
            ),
            "the bound callable must expose one qualified binding step, not an invented call",
        );
        assert!(
            matches!(
                reverse.paths[1].chain.as_slice(),
                [
                    CallablePathStep::ExactInvocation(_),
                    CallablePathStep::CallableValueBinding(_)
                ]
            ),
            "the transitive caller must retain the exact-call then qualified-binding relation sequence",
        );
    }

    #[test]
    fn file_selector_is_resolved_from_the_pinned_generation_not_live_disk() {
        let fixture = fixture(&["caller"]);
        let mut request = CallsRequest::new("target");
        request.file = Some(DOCUMENT.into());

        std::fs::remove_file(fixture.binding.root().join(DOCUMENT))
            .expect("remove the live source after the generation was published");
        assert!(
            !fixture.binding.root().join(DOCUMENT).exists(),
            "the live-path dependency falsifier must be active"
        );

        let result = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &request,
        )
        .expect("a pinned generation must remain queryable after its live source disappears");

        assert_eq!(result.resolved_symbol.document_path, DOCUMENT);
        assert_eq!(result.items.len(), 1);
    }

    #[test]
    fn provider_ambiguity_and_missing_selected_payload_fail_closed() {
        let fixture = fixture(&["caller"]);
        let scope = CapabilityScope::Repository {
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        };
        let receipt_a = complete_receipt("provider-a", scope.clone(), 'a');
        let receipt_b = complete_receipt("provider-b", scope, 'b');
        let mut ambiguous = fixture.generation.clone();
        set_evidence(
            &mut ambiguous,
            vec![receipt_a.clone(), receipt_b.clone()],
            vec![
                calls_payload(receipt_a.clone(), &["caller"], TARGET_LINE),
                calls_payload(receipt_b, &["caller"], TARGET_LINE),
            ],
        );
        let error = query_published_calls(
            &fixture.graph,
            &ambiguous,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect_err("eligible providers must not be selected by order");
        assert!(matches!(error, DomainError::CapabilityAmbiguous { .. }));

        let mut missing_payload = fixture.generation.clone();
        set_evidence(&mut missing_payload, vec![receipt_a], Vec::new());
        let error = query_published_calls(
            &fixture.graph,
            &missing_payload,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect_err("a receipt without its exact payload is not authority");
        assert!(matches!(
            error,
            DomainError::PublishedGenerationInvalid { .. }
        ));
    }

    #[test]
    fn overlapping_scoped_payloads_deduplicate_exact_occurrences() {
        let fixture = fixture(&["caller_a", "caller_b"]);
        let receipt_a = complete_receipt("provider-a", owner_scope("rust:workspace"), 'a');
        let receipt_b = complete_receipt("provider-a", owner_scope("rust:nested"), 'b');
        let mut generation = fixture.generation.clone();
        set_evidence(
            &mut generation,
            vec![receipt_a.clone(), receipt_b.clone()],
            vec![
                calls_payload(receipt_a, &["caller_a", "caller_b"], TARGET_LINE),
                calls_payload(receipt_b, &["caller_a", "caller_b"], TARGET_LINE),
            ],
        );
        let result = query_published_calls(
            &fixture.graph,
            &generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("overlapping provider scopes");

        assert_eq!(result.items.len(), 2, "two payloads must not double count");
        assert_eq!(
            result.authority.input_fingerprints,
            vec!["a".repeat(64), "b".repeat(64)]
        );
    }

    #[test]
    fn overlapping_scoped_payloads_deduplicate_exact_coverage_exclusions() {
        let fixture = fixture(&["caller"]);
        let receipt_a = complete_receipt("provider-a", owner_scope("rust:workspace"), 'a');
        let receipt_b = complete_receipt("provider-a", owner_scope("rust:nested"), 'b');
        let exclusion = ProviderCoverageExclusion {
            location: location(0, 0, 80),
            reason_code: "conditional_compilation".into(),
        };
        let payload = |receipt| {
            let mut payload = calls_payload(receipt, &["caller"], TARGET_LINE);
            let ProviderPayload::Calls(calls) = &mut payload else {
                unreachable!("Calls fixture")
            };
            calls.coverage_exclusions.push(exclusion.clone());
            payload
        };
        let mut generation = fixture.generation.clone();
        set_evidence(
            &mut generation,
            vec![receipt_a.clone(), receipt_b.clone()],
            vec![payload(receipt_a), payload(receipt_b)],
        );

        let result = query_published_calls(
            &fixture.graph,
            &generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("overlapping provider exclusions");

        assert_eq!(result.authority.coverage_exclusions.len(), 1);
        assert_eq!(result.authority.coverage_exclusions[0].document_count, 1);
        assert_eq!(
            result.authority.coverage_exclusions[0].region_count, 1,
            "one exact excluded source region must not be counted once per overlapping payload"
        );
    }

    #[test]
    fn cursor_is_bound_to_the_published_generation() {
        let fixture = fixture(&["caller_a", "caller_b"]);
        let mut first_request = CallsRequest::new("target");
        first_request.limit = 1;
        let first = query_published_calls(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &first_request,
        )
        .expect("first page");
        let cursor = first.page.next_cursor.expect("continuation cursor");

        let mut changed = fixture.generation.clone();
        changed.manifest.generation_id = GenerationId::new("generation-b");
        changed.head.body.generation_id = GenerationId::new("generation-b");
        let mut continuation = first_request;
        continuation.cursor = Some(cursor);
        let error =
            query_published_calls(&fixture.graph, &changed, &fixture.binding, &continuation)
                .expect_err("a cursor cannot cross immutable generations");
        assert!(matches!(error, DomainError::CursorGenerationChanged { .. }));
    }

    #[test]
    fn payload_target_must_match_the_structural_definition() {
        let fixture = fixture(&["caller"]);
        let receipt = fixture.generation.manifest.receipts[0].clone();
        let mut mismatched = fixture.generation.clone();
        set_evidence(
            &mut mismatched,
            vec![receipt.clone()],
            vec![calls_payload(receipt, &["caller"], TARGET_LINE + 20)],
        );

        let error = query_published_calls(
            &fixture.graph,
            &mismatched,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect_err("same-name payload target at another definition cannot be joined");
        assert!(matches!(
            error,
            DomainError::PublishedGenerationInvalid { .. }
        ));
    }

    #[test]
    fn provider_structural_extents_must_match_co_published_graph_spans() {
        for symbol_index in [0, 1] {
            let fixture = fixture(&["caller"]);
            let receipt = fixture.generation.manifest.receipts[0].clone();
            let mut payload = calls_payload(receipt.clone(), &["caller"], TARGET_LINE);
            let ProviderPayload::Calls(calls) = &mut payload else {
                unreachable!("Calls fixture")
            };
            let extent = calls.symbols[symbol_index]
                .structural_extent
                .as_mut()
                .expect("structural extent");
            extent.span.end_byte -= 1;
            calls.symbols[symbol_index]
                .call_owner_extent
                .as_mut()
                .expect("call-owner extent")
                .span
                .end_byte -= 1;
            let mut generation = fixture.generation.clone();
            set_evidence(&mut generation, vec![receipt], vec![payload]);

            let error = query_published_calls(
                &fixture.graph,
                &generation,
                &fixture.binding,
                &CallsRequest::new("target"),
            )
            .expect_err("a provider extent cannot disagree with its co-published syntax node");
            assert!(matches!(
                error,
                DomainError::PublishedGenerationInvalid { .. }
            ));
        }
    }

    #[test]
    fn provider_callable_vocabulary_cannot_invalidate_an_exact_structural_join() {
        for symbol_index in [0, 1] {
            let fixture = fixture(&["caller"]);
            let receipt = fixture.generation.manifest.receipts[0].clone();
            let mut payload = calls_payload(receipt.clone(), &["caller"], TARGET_LINE);
            let ProviderPayload::Calls(calls) = &mut payload else {
                unreachable!("Calls fixture")
            };
            calls.symbols[symbol_index].provider_kind = "staticmethod".into();
            let mut generation = fixture.generation.clone();
            set_evidence(&mut generation, vec![receipt], vec![payload]);

            let result = query_published_calls(
                &fixture.graph,
                &generation,
                &fixture.binding,
                &CallsRequest::new("target"),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "an admitted provider callable kind must join the exact co-published source callable at symbol index {symbol_index}: {error}"
                )
            });

            assert_eq!(result.items.len(), 1);
        }
    }

    #[test]
    fn explicit_provider_exclusion_is_distinct_from_an_uncovered_provider_omission() {
        for (exclusion, expected_exclusion) in [
            (
                ProviderCoverageExclusion {
                    location: location(TARGET_LINE, 900, 980),
                    reason_code: "conditional_compilation".into(),
                },
                true,
            ),
            (
                ProviderCoverageExclusion {
                    location: location(0, 0, 80),
                    reason_code: "unrelated_region".into(),
                },
                false,
            ),
        ] {
            let fixture = fixture(&[]);
            let receipt = fixture.generation.manifest.receipts[0].clone();
            let mut payload = calls_payload(receipt.clone(), &[], TARGET_LINE);
            let ProviderPayload::Calls(calls) = &mut payload else {
                unreachable!("Calls fixture")
            };
            calls.symbols.clear();
            calls.coverage_exclusions.push(exclusion);
            let mut generation = fixture.generation.clone();
            set_evidence(&mut generation, vec![receipt], vec![payload]);

            let error = query_published_calls(
                &fixture.graph,
                &generation,
                &fixture.binding,
                &CallsRequest::new("target"),
            )
            .expect_err("provider target identity is deliberately absent");
            if expected_exclusion {
                assert!(matches!(
                    error,
                    DomainError::SymbolOutsideProviderCoverage { .. }
                ));
                let envelope = error.envelope();
                assert_eq!(envelope.error.code, "symbol_outside_provider_coverage");
                assert_eq!(
                    envelope.error.evidence[0].reason_code,
                    "conditional_compilation"
                );
            } else {
                assert!(matches!(
                    error,
                    DomainError::SymbolOutsideProviderPopulation { .. }
                ));
                assert_eq!(
                    error.envelope().error.code,
                    "symbol_outside_provider_population"
                );
            }
        }
    }

    #[test]
    fn exact_structural_extent_ignores_an_unrelated_same_name_provider_symbol() {
        let fixture = fixture(&["caller"]);
        let receipt = fixture.generation.manifest.receipts[0].clone();
        let mut payload = calls_payload(receipt.clone(), &["caller"], TARGET_LINE);
        let ProviderPayload::Calls(calls) = &mut payload else {
            unreachable!("Calls fixture")
        };
        let mut unrelated = calls.symbols[0].clone();
        unrelated.provider_symbol_id = "provider-unrelated-same-name".into();
        unrelated.definition = Some(location(TARGET_LINE + 20, 950, 956));
        unrelated.structural_extent = Some(location(TARGET_LINE + 20, 940, 1_000));
        unrelated.call_owner_extent = Some(location(TARGET_LINE + 20, 940, 1_000));
        calls.symbols.push(unrelated);
        let mut generation = fixture.generation.clone();
        set_evidence(&mut generation, vec![receipt], vec![payload]);

        let result = query_published_calls(
            &fixture.graph,
            &generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("an unrelated callable extent must not make the exact target ambiguous");

        assert_eq!(result.resolved_symbol.name, "target");
        assert_eq!(result.items.len(), 1);
    }

    #[test]
    fn publication_join_ignores_an_unreferenced_unjoined_local_callable() {
        let fixture = fixture(&["caller"]);
        let receipt = fixture.generation.manifest.receipts[0].clone();
        let mut payload = calls_payload(receipt, &["caller"], TARGET_LINE);
        let ProviderPayload::Calls(calls) = &mut payload else {
            unreachable!("Calls fixture")
        };
        let mut unjoined = calls.symbols[0].clone();
        unjoined.provider_symbol_id = "provider-unjoined-unused-callable".into();
        unjoined.definition = Some(location(TARGET_LINE + 20, 950, 956));
        unjoined.structural_extent = Some(location(TARGET_LINE + 20, 940, 1_000));
        unjoined.call_owner_extent = Some(location(TARGET_LINE + 20, 940, 1_000));
        calls.symbols.push(unjoined);

        calls_payload_structural_join(&fixture.graph, calls)
            .expect("an unused provider-local callable cannot affect the published call relation");
    }

    #[test]
    fn normalized_calls_projection_creates_the_semantic_graph_edge() {
        let mut fixture = fixture(&["caller"]);
        let payload = fixture.generation.provider_payloads[0].clone();
        let ProviderPayload::Calls(calls) = payload.payload() else {
            unreachable!("Calls fixture")
        };
        let caller = fixture
            .graph
            .node_by_name("caller")
            .expect("caller node")
            .memory_id;
        let target = fixture
            .graph
            .node_by_name("target")
            .expect("target node")
            .memory_id;

        assert!(
            fixture
                .graph
                .find_edge_by_kind_mut(caller, target, EdgeKind::Calls)
                .is_none(),
            "positive control: the fixture starts without a Calls edge"
        );
        let stats = project_calls_payload_structural_join(&mut fixture.graph, calls)
            .expect("validated Calls projection");

        assert_eq!(stats.novel_edges, 1);
        let edge = fixture
            .graph
            .find_edge_by_kind_mut(caller, target, EdgeKind::Calls)
            .expect("projected Calls edge");
        assert_eq!(edge.source, EdgeSource::Scip);
        assert_eq!(edge.scope, EdgeScope::Production);
        assert_eq!(edge.confidence, 0.9);
    }

    #[test]
    fn normalized_calls_projection_rejects_a_preexisting_structural_call() {
        let mut fixture = fixture(&["caller"]);
        let payload = fixture.generation.provider_payloads[0].clone();
        let ProviderPayload::Calls(calls) = payload.payload() else {
            unreachable!("Calls fixture")
        };
        let caller = fixture
            .graph
            .node_by_name("caller")
            .expect("caller node")
            .memory_id;
        let target = fixture
            .graph
            .node_by_name("target")
            .expect("target node")
            .memory_id;
        fixture
            .graph
            .add_edge(
                caller,
                target,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    scope: EdgeScope::Production,
                    ..Default::default()
                },
            )
            .expect("structural Calls edge");

        let error = project_calls_payload_structural_join(&mut fixture.graph, calls)
            .expect_err("only normalized provider evidence may populate Calls");
        assert!(matches!(
            error,
            DomainError::PublishedGenerationInvalid { .. }
        ));
        let edge = fixture
            .graph
            .find_edge_by_kind_mut(caller, target, EdgeKind::Calls)
            .expect("pre-existing edge remains untouched");
        assert_eq!(edge.source, EdgeSource::TreeSitter);
        assert_eq!(edge.confidence, 0.7);
    }

    #[test]
    fn normalized_calls_projection_rejects_scope_conflict_before_mutation() {
        let mut fixture = fixture(&["caller"]);
        let payload = fixture.generation.provider_payloads[0].clone();
        let ProviderPayload::Calls(calls) = payload.payload() else {
            unreachable!("Calls fixture")
        };
        let caller = fixture
            .graph
            .node_by_name("caller")
            .expect("caller node")
            .memory_id;
        let target = fixture
            .graph
            .node_by_name("target")
            .expect("target node")
            .memory_id;
        fixture
            .graph
            .add_edge(
                caller,
                target,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    source: EdgeSource::TreeSitter,
                    confidence: 0.7,
                    scope: EdgeScope::Test,
                    ..Default::default()
                },
            )
            .expect("conflicting structural Calls edge");

        let error = project_calls_payload_structural_join(&mut fixture.graph, calls)
            .expect_err("production provider evidence cannot corroborate a test-scoped edge");
        assert!(matches!(
            error,
            DomainError::PublishedGenerationInvalid { .. }
        ));
        let edge = fixture
            .graph
            .find_edge_by_kind_mut(caller, target, EdgeKind::Calls)
            .expect("the original structural edge remains");
        assert_eq!(edge.source, EdgeSource::TreeSitter);
        assert_eq!(edge.scope, EdgeScope::Test);
        assert_eq!(edge.confidence, 0.7);
    }

    #[test]
    fn publication_join_rejects_an_unjoined_referenced_local_caller() {
        let fixture = fixture(&["caller"]);
        let receipt = fixture.generation.manifest.receipts[0].clone();
        let mut payload = calls_payload(receipt, &["caller"], TARGET_LINE);
        let ProviderPayload::Calls(calls) = &mut payload else {
            unreachable!("Calls fixture")
        };
        let mut unjoined = calls.symbols[1].clone();
        unjoined.provider_symbol_id = "provider-unjoined-referenced-caller".into();
        unjoined.definition = Some(location(TARGET_LINE + 20, 950, 956));
        unjoined.structural_extent = Some(location(TARGET_LINE + 20, 940, 1_000));
        unjoined.call_owner_extent = Some(location(TARGET_LINE + 20, 940, 1_000));
        calls.calls[0].caller_symbol_id = unjoined.provider_symbol_id.clone();
        calls.symbols.push(unjoined);

        let error = calls_payload_structural_join(&fixture.graph, calls)
            .expect_err("a referenced local caller must join before publication");
        assert!(matches!(
            error,
            DomainError::PublishedGenerationInvalid { .. }
        ));
        assert!(
            error
                .to_string()
                .contains("provider-unjoined-referenced-caller"),
            "the refusal must identify the exact referenced provider symbol: {error}"
        );
    }

    #[test]
    fn publication_join_uses_structural_extent_when_the_name_starts_on_a_later_line() {
        let mut fixture = fixture(&["caller"]);
        let target_id = fixture
            .graph
            .node_by_name("target")
            .expect("fixture target")
            .memory_id;
        fixture
            .graph
            .node_mut(&target_id)
            .expect("mutable fixture target")
            .line_end = Some(TARGET_LINE + 1);
        let receipt = fixture.generation.manifest.receipts[0].clone();
        let mut payload = calls_payload(receipt, &["caller"], TARGET_LINE);
        let ProviderPayload::Calls(calls) = &mut payload else {
            unreachable!("Calls fixture")
        };
        let definition = calls.symbols[0]
            .definition
            .as_mut()
            .expect("target definition");
        definition.span.start_line += 1;
        definition.span.end_line += 1;
        calls.symbols[0]
            .structural_extent
            .as_mut()
            .expect("target structural extent")
            .span
            .end_line += 1;
        calls.symbols[0]
            .call_owner_extent
            .as_mut()
            .expect("target call-owner extent")
            .span
            .end_line += 1;

        calls_payload_structural_join(&fixture.graph, calls).expect(
            "the exact callable extent must join even when formatting places its name on a later line",
        );
    }

    #[test]
    fn provider_method_display_name_joins_parent_qualified_structural_definition() {
        for qualified_name in ["impl Counter::target", "Greeter::target"] {
            let mut fixture = fixture(&["caller"]);
            let target_id = fixture
                .graph
                .node_by_name("target")
                .expect("fixture target")
                .memory_id;
            let mut target = fixture
                .graph
                .remove_node(&target_id)
                .expect("remove unqualified fixture target");
            target.symbol_name = qualified_name.into();
            let target_id = target.memory_id;
            fixture
                .graph
                .add_node(target)
                .expect("add parent-qualified structural target");
            fixture
                .graph
                .set_source_span(
                    target_id,
                    crate::graph::SourceSpan {
                        start_byte: 900,
                        end_byte: 980,
                    },
                )
                .expect("restore target source span");

            let result = query_published_calls(
                &fixture.graph,
                &fixture.generation,
                &fixture.binding,
                &CallsRequest::new("target"),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "provider method display name must join {qualified_name}'s exact structural definition: {error}"
                )
            });

            assert_eq!(result.resolved_symbol.name, "target");
            assert_eq!(result.items.len(), 1);
        }
    }

    #[test]
    fn raw_provider_kind_does_not_override_exact_structural_callable_identity() {
        let fixture = fixture(&["caller"]);
        let receipt = fixture.generation.manifest.receipts[0].clone();
        let mut payload = calls_payload(receipt.clone(), &["caller"], TARGET_LINE);
        let ProviderPayload::Calls(calls) = &mut payload else {
            unreachable!("Calls fixture")
        };
        calls.symbols[0].provider_kind = "struct".into();
        let mut generation = fixture.generation.clone();
        set_evidence(&mut generation, vec![receipt], vec![payload]);

        let result = query_published_calls(
            &fixture.graph,
            &generation,
            &fixture.binding,
            &CallsRequest::new("target"),
        )
        .expect("the co-published structural function and exact extent own product identity");

        assert_eq!(result.resolved_symbol.kind, "function");
        assert_eq!(result.items.len(), 1);
    }

    #[test]
    fn auxiliary_only_language_reports_calls_not_applicable() {
        let auxiliary_id = ProjectUnitId::new("go:auxiliary:testdata");
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: crate::code_intel_domain::ProjectTopology {
                units: vec![ProjectUnit {
                    project_unit_id: auxiliary_id.clone(),
                    language_id: LanguageId::new("go"),
                    ecosystem_id: EcosystemId::new("go"),
                    kind: ProjectUnitKind::AuxiliarySources,
                    root_path: "testdata".into(),
                    manifest_path: None,
                    compilation_root_paths: Vec::new(),
                }],
                memberships: vec![DocumentMembership {
                    document_path: "testdata/shape.go".into(),
                    language_id: LanguageId::new("go"),
                    project_unit_id: auxiliary_id,
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

        let error = language_source_owner_ids(&inventory, &LanguageId::new("go"))
            .expect_err("auxiliary source visibility must not invent Calls authority");
        assert!(matches!(
            error,
            DomainError::CapabilityNotApplicable { ref capability, .. }
                if capability == "calls"
        ));
        assert_eq!(error.envelope().error.code, "capability_not_applicable");
    }
}
