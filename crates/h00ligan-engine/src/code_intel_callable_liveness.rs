//! Typed whole-program callable-liveness evidence over one immutable generation.
//!
//! Explicit Calls and whole-program liveness answer different questions. Calls
//! preserves exact source invocation records; this module admits a provider's
//! separately typed reachability classification without manufacturing Calls
//! edges for interface dispatch, function values, or conservative method sets.

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::code_intel_calls::callable_liveness_payload_structural_join;
use crate::code_intel_domain::{
    CALLABLE_LIVENESS_CONFIGURATION_ID, CapabilityCoverage, CapabilityCoverageStatus,
    CapabilityEvidenceGap, CapabilityQualification, CapabilityScope, CapabilityStatus,
    ConfigurationId, DomainError, LanguageCapabilityCoverage, LanguageId, ProjectInventory,
    ProjectUnitId, ProviderId, aggregate_capability_coverage_status, assess_language_capability,
    capability_resolution_domain_error, resolve_capability_provider,
};
use crate::code_intel_payload::{
    CallableLivenessPopulation, CallableLivenessProviderPayload, ProviderCallableLiveness,
    ProviderPayload,
};
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::language_id_for_path;
use crate::graph::{GraphNode, KnowledgeGraph};
use crate::structural_ir::symbol_is_executable_callable_declaration;

pub const CALLABLE_LIVENESS_CAPABILITY_ID: &str = "callable_liveness";

/// The first compiler-native implementation is Go RTA. Applicability is a
/// product contract, not inferred from whether a provider happened to emit a
/// receipt: an old or failed Go generation must report unavailable rather than
/// making the capability disappear.
pub(crate) fn capability_applies_to(language_id: &LanguageId) -> bool {
    language_id.0 == "go"
}

/// Assess callable-liveness authority from exact receipts, payload presence,
/// payload/structural joins, and the declared source population.
pub fn assess_callable_liveness_capability<P: AsRef<ProviderPayload>>(
    graph: &KnowledgeGraph,
    receipts: &[crate::code_intel_domain::CapabilityReceipt],
    provider_payloads: &[P],
    inventory: &ProjectInventory,
) -> CapabilityCoverage {
    let languages = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| inventory.is_semantic_source_owner(membership))
        .map(|membership| membership.language_id.clone())
        .filter(capability_applies_to)
        .collect::<BTreeSet<_>>();
    let mut coverage = assess_language_capability(
        receipts,
        inventory,
        CALLABLE_LIVENESS_CAPABILITY_ID,
        CALLABLE_LIVENESS_CONFIGURATION_ID,
        languages,
    );
    if coverage.languages.is_empty() {
        return coverage;
    }

    // Build against the same exact payload population used by queries. A
    // complete receipt without its one matching typed payload is partial
    // evidence, never complete user-facing authority.
    for language in &mut coverage.languages {
        if language.status != CapabilityCoverageStatus::Complete {
            continue;
        }
        match build_from_parts(
            graph,
            receipts,
            provider_payloads,
            inventory,
            &language.language_id,
            None,
        ) {
            Ok(published) => {
                *language = published.language_coverage();
            }
            Err(error) => {
                language.status = CapabilityCoverageStatus::Partial;
                language.gaps.push(CapabilityEvidenceGap {
                    provider_id: language.provider_id.clone(),
                    status: CapabilityStatus::Partial,
                    reason_code: "provider_payload_unavailable".into(),
                    reason: error.to_string(),
                });
            }
        }
    }
    coverage.status = aggregate_capability_coverage_status(&coverage.languages);
    coverage
}

/// One provider's exact, structurally joined liveness population for a bounded
/// language/project-unit scope.
pub(crate) struct PublishedCallableLiveness {
    language_id: LanguageId,
    provider_id: ProviderId,
    mapped: BTreeMap<Uuid, ProviderCallableLiveness>,
    excluded: BTreeMap<Uuid, Vec<String>>,
    exclusions_by_reason: BTreeMap<String, BTreeSet<String>>,
    unjoined_source_callables: usize,
}

impl PublishedCallableLiveness {
    pub(crate) fn build(
        graph: &KnowledgeGraph,
        generation: &ResolvedGeneration,
        language_id: &LanguageId,
    ) -> Result<Self, DomainError> {
        Self::build_inner(graph, generation, language_id, None)
    }

    pub(crate) fn build_for_target(
        graph: &KnowledgeGraph,
        generation: &ResolvedGeneration,
        language_id: &LanguageId,
        target: &GraphNode,
    ) -> Result<Self, DomainError> {
        let units = source_owner_project_unit_ids(
            &generation.project_inventory,
            language_id,
            Some(&target.file_path),
        )?;
        Self::build_inner(graph, generation, language_id, Some(&units))
    }

    pub(crate) fn build_for_project_unit(
        graph: &KnowledgeGraph,
        generation: &ResolvedGeneration,
        language_id: &LanguageId,
        project_unit_id: &ProjectUnitId,
    ) -> Result<Self, DomainError> {
        Self::build_inner(
            graph,
            generation,
            language_id,
            Some(&BTreeSet::from([project_unit_id.clone()])),
        )
    }

    fn build_inner(
        graph: &KnowledgeGraph,
        generation: &ResolvedGeneration,
        language_id: &LanguageId,
        selected_units: Option<&BTreeSet<ProjectUnitId>>,
    ) -> Result<Self, DomainError> {
        build_from_parts(
            graph,
            &generation.manifest.receipts,
            &generation.provider_payloads,
            &generation.project_inventory,
            language_id,
            selected_units,
        )
    }

    pub(crate) fn record(&self, node_id: &Uuid) -> Option<&ProviderCallableLiveness> {
        self.mapped.get(node_id)
    }

    pub(crate) fn records(&self) -> impl Iterator<Item = (&Uuid, &ProviderCallableLiveness)> {
        self.mapped.iter()
    }

    pub(crate) fn exclusions(&self) -> impl Iterator<Item = (&Uuid, &[String])> {
        self.excluded
            .iter()
            .map(|(node_id, reasons)| (node_id, reasons.as_slice()))
    }

    pub(crate) const fn unjoined_source_callables(&self) -> usize {
        self.unjoined_source_callables
    }

    pub(crate) fn language_coverage(&self) -> LanguageCapabilityCoverage {
        let mut coverage = LanguageCapabilityCoverage {
            language_id: self.language_id.clone(),
            status: CapabilityCoverageStatus::Complete,
            provider_id: Some(self.provider_id.clone()),
            gaps: Vec::new(),
            qualifications: Vec::new(),
        };
        if self.unjoined_source_callables > 0 {
            coverage.status = CapabilityCoverageStatus::Partial;
            coverage.gaps.push(CapabilityEvidenceGap {
                provider_id: Some(self.provider_id.clone()),
                status: CapabilityStatus::Partial,
                reason_code: "provider_population_join_incomplete".into(),
                reason: format!(
                    "{} source-owned named function or method declaration(s) have no joined compiler liveness record",
                    self.unjoined_source_callables
                ),
            });
        } else if !self.exclusions_by_reason.is_empty() {
            coverage.status = CapabilityCoverageStatus::Qualified;
            coverage.qualifications = self
                .exclusions_by_reason
                .iter()
                .map(|(reason_code, documents)| CapabilityQualification {
                    provider_id: self.provider_id.clone(),
                    reason_code: reason_code.clone(),
                    reason: format!(
                        "compiler liveness provider omitted {} source document(s) from its admitted analysis population",
                        documents.len()
                    ),
                })
                .collect();
        }
        coverage
    }
}

fn build_from_parts<P: AsRef<ProviderPayload>>(
    graph: &KnowledgeGraph,
    receipts: &[crate::code_intel_domain::CapabilityReceipt],
    provider_payloads: &[P],
    inventory: &ProjectInventory,
    language_id: &LanguageId,
    selected_units: Option<&BTreeSet<ProjectUnitId>>,
) -> Result<PublishedCallableLiveness, DomainError> {
    if !capability_applies_to(language_id) {
        return Err(DomainError::CapabilityNotApplicable {
            capability: CALLABLE_LIVENESS_CAPABILITY_ID.into(),
            reason: format!(
                "no compiler-native callable-liveness backend is configured for {language_id}"
            ),
        });
    }
    let all_units = source_owner_project_unit_ids(inventory, language_id, None)?;
    let required_units = selected_units.cloned().unwrap_or_else(|| all_units.clone());
    if required_units.is_empty() || !required_units.is_subset(&all_units) {
        return Err(invalid_generation(
            "callable-liveness scope is outside the indexed source-owner population".into(),
        ));
    }
    let required_scopes = required_units
        .iter()
        .cloned()
        .map(|project_unit_id| CapabilityScope::ProjectUnit {
            language_id: language_id.clone(),
            project_unit_id,
            configuration_id: ConfigurationId::new(CALLABLE_LIVENESS_CONFIGURATION_ID),
        })
        .collect::<Vec<_>>();
    let provider = resolve_capability_provider(
        receipts,
        CALLABLE_LIVENESS_CAPABILITY_ID,
        &required_scopes,
        None,
    )
    .map_err(|error| {
        capability_resolution_domain_error(CALLABLE_LIVENESS_CAPABILITY_ID, error, receipts)
    })?;
    let selected = selected_payloads(
        provider_payloads.iter().map(AsRef::as_ref),
        &provider.receipts,
    )?;
    let required_documents = source_owner_documents(inventory, language_id, &required_units)?;
    build_selected_population(
        graph,
        language_id,
        provider.provider_id,
        selected,
        &required_documents,
    )
}

fn build_selected_population(
    graph: &KnowledgeGraph,
    language_id: &LanguageId,
    provider_id: ProviderId,
    payloads: Vec<&CallableLivenessProviderPayload>,
    required_documents: &BTreeSet<String>,
) -> Result<PublishedCallableLiveness, DomainError> {
    let mut mapped = BTreeMap::new();
    let mut exclusions_by_reason = BTreeMap::<String, BTreeSet<String>>::new();
    for payload in payloads {
        if payload.population != CallableLivenessPopulation::NamedFunctionAndMethodDeclarations {
            return Err(invalid_generation(
                "selected callable-liveness payload has an unsupported declaration population"
                    .into(),
            ));
        }
        for (node_id, record) in callable_liveness_payload_structural_join(graph, payload)? {
            if required_documents.contains(&record.structural_extent.document_path)
                && mapped.insert(node_id, record).is_some()
            {
                return Err(invalid_generation(
                    "selected callable-liveness payloads overlap one structural declaration".into(),
                ));
            }
        }
        for exclusion in &payload.coverage_exclusions {
            if required_documents.contains(&exclusion.document_path) {
                exclusions_by_reason
                    .entry(exclusion.reason_code.clone())
                    .or_default()
                    .insert(exclusion.document_path.clone());
            }
        }
    }
    let excluded_documents = exclusions_by_reason
        .values()
        .flatten()
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected = graph
        .all_nodes()
        .into_iter()
        .filter(|node| {
            language_id_for_path(&node.file_path) == *language_id
                && required_documents.contains(&node.file_path)
                && symbol_is_executable_callable_declaration(&node.kind, node.has_body)
        })
        .collect::<Vec<_>>();
    let excluded = expected
        .iter()
        .filter(|node| excluded_documents.contains(&node.file_path))
        .map(|node| {
            let reasons = exclusions_by_reason
                .iter()
                .filter(|(_, documents)| documents.contains(&node.file_path))
                .map(|(reason, _)| reason.clone())
                .collect();
            (node.memory_id, reasons)
        })
        .collect();
    let unjoined_source_callables = expected
        .iter()
        .filter(|node| {
            !excluded_documents.contains(&node.file_path) && !mapped.contains_key(&node.memory_id)
        })
        .count();
    Ok(PublishedCallableLiveness {
        language_id: language_id.clone(),
        provider_id,
        mapped,
        excluded,
        exclusions_by_reason,
        unjoined_source_callables,
    })
}

fn selected_payloads<'a>(
    payloads: impl Iterator<Item = &'a ProviderPayload> + Clone,
    receipts: &[crate::code_intel_domain::CapabilityReceipt],
) -> Result<Vec<&'a CallableLivenessProviderPayload>, DomainError> {
    let mut selected = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        let matches = payloads
            .clone()
            .filter_map(|payload| match payload {
                ProviderPayload::CallableLiveness(payload) if &payload.receipt == receipt => {
                    Some(payload)
                }
                ProviderPayload::CallableLiveness(_) | ProviderPayload::Calls(_) => None,
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(invalid_generation(format!(
                "selected complete receipt from {} has {} matching callable-liveness payloads",
                receipt.provider_id,
                matches.len()
            )));
        }
        selected.push(matches[0]);
    }
    Ok(selected)
}

fn source_owner_project_unit_ids(
    inventory: &ProjectInventory,
    language_id: &LanguageId,
    document_path: Option<&str>,
) -> Result<BTreeSet<ProjectUnitId>, DomainError> {
    let units = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.language_id == *language_id
                && document_path.is_none_or(|path| membership.document_path == path)
                && inventory.is_semantic_source_owner(membership)
        })
        .map(|membership| membership.project_unit_id.clone())
        .collect::<BTreeSet<_>>();
    if units.is_empty() {
        return Err(DomainError::CapabilityNotApplicable {
            capability: CALLABLE_LIVENESS_CAPABILITY_ID.into(),
            reason: format!(
                "the indexed {language_id} source population has no semantic project unit"
            ),
        });
    }
    if units.iter().any(|project_unit_id| {
        !inventory.project_topology.units.iter().any(|unit| {
            unit.project_unit_id == *project_unit_id && unit.language_id == *language_id
        })
    }) {
        return Err(DomainError::ProjectInventoryMismatch {
            document_path: document_path.unwrap_or("<language source owners>").into(),
            reason: "source-owner project unit is missing or has a different language".into(),
        });
    }
    Ok(units)
}

fn source_owner_documents(
    inventory: &ProjectInventory,
    language_id: &LanguageId,
    required_units: &BTreeSet<ProjectUnitId>,
) -> Result<BTreeSet<String>, DomainError> {
    let documents = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.language_id == *language_id
                && required_units.contains(&membership.project_unit_id)
                && inventory.is_semantic_source_owner(membership)
        })
        .map(|membership| membership.document_path.clone())
        .collect::<BTreeSet<_>>();
    if documents.is_empty() {
        return Err(DomainError::ProjectInventoryMismatch {
            document_path: format!("<callable-liveness {language_id} population>"),
            reason: "selected project-unit scopes have no source-owner documents".into(),
        });
    }
    Ok(documents)
}

const fn invalid_generation(reason: String) -> DomainError {
    DomainError::PublishedGenerationInvalid { reason }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::code_intel_inventory::{InventorySource, build_project_inventory};
    use crate::code_intel_payload::{
        CALLABLE_LIVENESS_PROVIDER_PAYLOAD_SCHEMA, NormalizedSourceSpan, ProviderDocument,
        ProviderLocation,
    };
    use crate::edge_builder::build_graph;
    use crate::extractor::extract_file;

    const SOURCE: &str = concat!(
        "package main\n\n",
        "type callableContract interface { Contract() }\n",
        "var callableValue = func() {}\n",
        "func callbackOnlyTarget() {}\n",
        "func genuinelyUnreached() {}\n",
        "func invoke(callback func()) { callback() }\n",
        "func main() { invoke(callbackOnlyTarget) }\n",
    );

    struct Fixture {
        _temporary: TempDir,
        graph: KnowledgeGraph,
        inventory: ProjectInventory,
        receipt: crate::code_intel_domain::CapabilityReceipt,
        payload: ProviderPayload,
        callback_id: Uuid,
        unreached_id: Uuid,
    }

    fn sha256(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn fixture() -> Fixture {
        let temporary = TempDir::new().expect("temporary Go project");
        let root = temporary.path().join("repo");
        std::fs::create_dir_all(&root).expect("Go root");
        std::fs::write(
            root.join("go.mod"),
            "module example.com/liveness\n\ngo 1.27\n",
        )
        .expect("Go manifest");
        let source_path = root.join("main.go");
        std::fs::write(&source_path, SOURCE).expect("Go source");
        let extracted = extract_file(&source_path, &root).expect("extract Go source");
        let source_hash = sha256(SOURCE.as_bytes());
        let cross_document_surface_sha256 = extracted.cross_document_surface_sha256.clone();
        let mut graph = KnowledgeGraph::new();
        build_graph(&[extracted], &mut graph).expect("build structural graph");
        let inventory = build_project_inventory(&root, &[InventorySource::new("main.go", "go")]);
        let project_unit_id = inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| inventory.is_semantic_source_owner(membership))
            .expect("Go source owner")
            .project_unit_id
            .clone();
        let receipt = crate::code_intel_domain::CapabilityReceipt::complete(
            CALLABLE_LIVENESS_CAPABILITY_ID,
            "h00-gopls-scip",
            "fixture-v1",
            CapabilityScope::ProjectUnit {
                language_id: LanguageId::new("go"),
                project_unit_id,
                configuration_id: ConfigurationId::new(CALLABLE_LIVENESS_CONFIGURATION_ID),
            },
            std::iter::repeat_n('a', 64).collect::<String>(),
        );
        let records = graph
            .all_nodes()
            .into_iter()
            // Simulate the provider's declared population exactly: RTA walks
            // interface dispatch and function values, but its named records
            // are executable function/method declarations only.
            .filter(|node| {
                node.kind == "function"
                    && !matches!(
                        node.symbol_name.as_str(),
                        "callableContract::Contract" | "callableValue"
                    )
            })
            .map(|node| {
                let span = graph.source_span(&node.memory_id).expect("source span");
                let source_span = NormalizedSourceSpan {
                    start_byte: span.start_byte as u64,
                    end_byte: span.end_byte as u64,
                    start_line: node.line_start.expect("line start") as u32,
                    start_utf8_byte_column: 0,
                    end_line: node.line_end.expect("line end") as u32,
                    end_utf8_byte_column: 0,
                };
                ProviderCallableLiveness {
                    name: node.symbol_name.clone(),
                    definition: ProviderLocation {
                        document_path: "main.go".into(),
                        span: source_span.clone(),
                    },
                    structural_extent: ProviderLocation {
                        document_path: "main.go".into(),
                        span: source_span,
                    },
                    production_reachable: node.symbol_name != "genuinelyUnreached",
                    test_reachable: node.symbol_name != "genuinelyUnreached",
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 4, "positive structural population control");
        assert!(
            graph
                .node_by_name("callableContract::Contract")
                .is_some_and(|node| node.has_body == Some(false)),
            "positive control: a bodyless callable contract is structurally represented"
        );
        assert!(
            graph
                .node_by_name("callableValue")
                .is_some_and(|node| node.has_body == Some(true)),
            "positive control: a function-valued binding is structurally represented"
        );
        let callback_id = graph
            .all_nodes()
            .into_iter()
            .find(|node| node.symbol_name == "callbackOnlyTarget")
            .expect("callback target")
            .memory_id;
        let unreached_id = graph
            .all_nodes()
            .into_iter()
            .find(|node| node.symbol_name == "genuinelyUnreached")
            .expect("unreached target")
            .memory_id;
        let payload = ProviderPayload::CallableLiveness(CallableLivenessProviderPayload {
            schema_version: CALLABLE_LIVENESS_PROVIDER_PAYLOAD_SCHEMA.into(),
            population: CallableLivenessPopulation::NamedFunctionAndMethodDeclarations,
            receipt: receipt.clone(),
            semantic_inputs: h00ligan_provider_protocol::ProviderSemanticInputs::empty(),
            execution_authority:
                crate::code_intel_payload::ProviderExecutionAuthority::InvocationBound {
                    provider_configurations_sha256: BTreeMap::new(),
                },
            documents: vec![ProviderDocument {
                document_path: "main.go".into(),
                language_id: LanguageId::new("go"),
                content_sha256: source_hash,
                cross_document_surface_sha256,
                byte_length: SOURCE.len() as u64,
            }],
            callables: records,
            coverage_exclusions: Vec::new(),
        });
        Fixture {
            _temporary: temporary,
            graph,
            inventory,
            receipt,
            payload,
            callback_id,
            unreached_id,
        }
    }

    #[test]
    fn typed_population_preserves_callback_liveness_without_inventing_calls() {
        let fixture = fixture();
        let coverage = assess_callable_liveness_capability(
            &fixture.graph,
            std::slice::from_ref(&fixture.receipt),
            std::slice::from_ref(&fixture.payload),
            &fixture.inventory,
        );
        assert_eq!(coverage.status, CapabilityCoverageStatus::Complete);
        let published = build_from_parts(
            &fixture.graph,
            std::slice::from_ref(&fixture.receipt),
            std::slice::from_ref(&fixture.payload),
            &fixture.inventory,
            &LanguageId::new("go"),
            None,
        )
        .expect("admit typed callable liveness");
        assert!(
            published
                .record(&fixture.callback_id)
                .is_some_and(|record| record.production_reachable),
            "positive control: function-value dispatch remains live"
        );
        assert!(
            published
                .record(&fixture.unreached_id)
                .is_some_and(|record| !record.production_reachable && !record.test_reachable),
            "negative result is an explicit compiler record"
        );
        assert_eq!(published.unjoined_source_callables(), 0);
    }

    #[test]
    fn missing_or_altered_records_cannot_retain_complete_authority() {
        let fixture = fixture();
        let mut missing = fixture.payload.clone();
        let ProviderPayload::CallableLiveness(missing_payload) = &mut missing else {
            unreachable!("callable-liveness fixture")
        };
        missing_payload
            .callables
            .retain(|record| record.name != "genuinelyUnreached");
        let missing_coverage = assess_callable_liveness_capability(
            &fixture.graph,
            std::slice::from_ref(&fixture.receipt),
            std::slice::from_ref(&missing),
            &fixture.inventory,
        );
        assert_eq!(missing_coverage.status, CapabilityCoverageStatus::Partial);
        assert_eq!(
            missing_coverage.languages[0].gaps[0].reason_code,
            "provider_population_join_incomplete"
        );

        let mut altered = fixture.payload;
        let ProviderPayload::CallableLiveness(altered_payload) = &mut altered else {
            unreachable!("callable-liveness fixture")
        };
        altered_payload.callables[0]
            .structural_extent
            .span
            .start_byte += 1;
        let altered_coverage = assess_callable_liveness_capability(
            &fixture.graph,
            std::slice::from_ref(&fixture.receipt),
            std::slice::from_ref(&altered),
            &fixture.inventory,
        );
        assert_eq!(altered_coverage.status, CapabilityCoverageStatus::Partial);
        assert_eq!(
            altered_coverage.languages[0].gaps[0].reason_code,
            "provider_payload_unavailable"
        );
    }
}
