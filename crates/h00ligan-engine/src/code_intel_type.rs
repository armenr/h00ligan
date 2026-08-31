//! Exact structural Type queries over one validated immutable generation.
//!
//! This is the shared use case behind human CLI, CLI JSON, and MCP. Adapters
//! may render the result, but they do not rediscover members, truncate their own
//! populations, or invent transport-specific fields.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::code_intel_cursor::{page_window, request_digest};
use crate::code_intel_domain::{
    AuthorityStatus, CapabilityScope, ConfigurationId, DomainError, GenerationId, LanguageId,
    MAX_TYPE_PAGE_SIZE, Page, ProjectInventory, ProjectInventoryCoverage, ProjectUnitId,
    ProviderId, RepositoryBinding, STRUCTURAL_GRAPH_CONFIGURATION_ID, TypeRequest,
    capability_resolution_domain_error, resolve_capability_provider,
};
use crate::code_intel_inventory::project_unit_graph;
use crate::code_intel_publication::ResolvedGeneration;
use crate::code_intel_query::{generation_file_context, language_id_for_path, repository_binding};
use crate::code_intel_symbol::{NameFileSelection, exact_symbol_id, resolve_symbol_selector};
use crate::graph::{EdgeKind, GraphNode, KnowledgeGraph};
use crate::graph_query::collect_type_children;
use crate::project_binding::ProjectBinding;
use crate::structural_ir::{SymbolRole, symbol_kind_has_role};

const TYPE_SCHEMA_VERSION: &str = "h00/code-intel/type/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralTypePopulation {
    IndexedTypeMembers,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralAuthority {
    pub status: AuthorityStatus,
    pub population: StructuralTypePopulation,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub scopes: Vec<CapabilityScope>,
    pub input_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralSymbol {
    pub symbol_id: String,
    pub name: String,
    pub kind: String,
    pub document_path: String,
    pub language_id: LanguageId,
    pub project_unit_ids: Vec<ProjectUnitId>,
    pub configuration_id: ConfigurationId,
    pub signature: String,
    pub visibility: String,
    pub start_byte: Option<usize>,
    pub end_byte: Option<usize>,
    pub start_line: Option<usize>,
    pub end_line: Option<usize>,
    pub source_backed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeMemberRole {
    Field,
    FieldTypeReference,
    Variant,
    PublicMethod,
    PrivateMethod,
    RequiredMethod,
    ProvidedMethod,
    ImplementationBlock,
    ImplementedTrait,
    Implementor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeMember {
    pub role: TypeMemberRole,
    pub symbol: StructuralSymbol,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeMemberTotals {
    pub fields: usize,
    pub field_type_references: usize,
    pub variants: usize,
    pub public_methods: usize,
    pub private_methods: usize,
    pub required_methods: usize,
    pub provided_methods: usize,
    pub implementation_blocks: usize,
    pub implemented_traits: usize,
    pub implementors: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactTypeResult {
    pub schema_version: String,
    pub capability: String,
    pub generation_id: GenerationId,
    pub repository: RepositoryBinding,
    pub unit_graph: crate::code_intel_domain::UnitGraph,
    pub resolved_type: StructuralSymbol,
    pub authority: StructuralAuthority,
    pub items: Vec<TypeMember>,
    pub totals: TypeMemberTotals,
    pub page: Page,
    pub warnings: Vec<String>,
}

pub fn query_published_type(
    graph: &KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    request: &TypeRequest,
) -> Result<ExactTypeResult, DomainError> {
    if request.limit == 0 || request.limit > MAX_TYPE_PAGE_SIZE {
        return Err(DomainError::InvalidRequest {
            operation: "type",
            field: "limit",
            reason: format!("must be between 1 and {MAX_TYPE_PAGE_SIZE}"),
        });
    }

    let type_node = resolve_type(graph, generation, binding, request)?;
    let resolved_type = structural_symbol(graph, type_node, generation)?;
    if !resolved_type.source_backed {
        return Err(DomainError::PublishedGenerationInvalid {
            reason: format!(
                "resolved Type target {} is not backed by an indexed source document",
                type_node.symbol_name
            ),
        });
    }
    let required_scopes = required_structural_scopes(type_node)?;
    let provider = resolve_capability_provider(
        &generation.manifest.receipts,
        "structural_graph",
        &required_scopes,
        None,
    )
    .map_err(|error| {
        capability_resolution_domain_error("structural_graph", error, &generation.manifest.receipts)
    })?;

    let members = canonical_members(collect_members(graph, type_node, generation)?)?;

    let totals = member_totals(&members);
    let generation_id = generation.manifest.generation_id.clone();
    let request_digest = type_request_digest(request);
    let window = page_window(
        "type",
        &generation_id,
        &request_digest,
        request.cursor.as_deref(),
        request.limit,
        members.len(),
    )?;
    let items = members[window.range.clone()].to_vec();

    let mut projected_documents = items
        .iter()
        .filter(|item| item.symbol.source_backed)
        .map(|item| item.symbol.document_path.as_str())
        .collect::<Vec<_>>();
    projected_documents.push(&resolved_type.document_path);
    let unit_graph = project_unit_graph(&generation.project_inventory, projected_documents);
    let mut input_fingerprints = provider
        .receipts
        .iter()
        .filter_map(|receipt| receipt.input_fingerprint.clone())
        .collect::<Vec<_>>();
    input_fingerprints.sort();
    input_fingerprints.dedup();
    let mut warnings = Vec::new();
    if generation.project_inventory.coverage
        == ProjectInventoryCoverage::IndexedSourcePopulationPartial
    {
        warnings.push(format!(
            "Project inventory is partial and reports {} issue(s); Type authority is limited to the indexed structural population.",
            generation.project_inventory.issues.len()
        ));
    }

    Ok(ExactTypeResult {
        schema_version: TYPE_SCHEMA_VERSION.into(),
        capability: "structural_graph".into(),
        generation_id,
        repository: repository_binding(binding, generation),
        unit_graph,
        resolved_type,
        authority: StructuralAuthority {
            status: AuthorityStatus::Complete,
            population: StructuralTypePopulation::IndexedTypeMembers,
            provider_id: provider.provider_id,
            provider_version: provider.provider_version,
            scopes: provider.required_scopes,
            input_fingerprints,
        },
        items,
        totals,
        page: window.page,
        warnings,
    })
}

pub(crate) fn type_request_digest(request: &TypeRequest) -> String {
    request_digest(
        "type",
        &[
            request.symbol.as_str(),
            request.file.as_deref().unwrap_or_default(),
        ],
    )
}

fn required_structural_scopes(type_node: &GraphNode) -> Result<Vec<CapabilityScope>, DomainError> {
    let language_id = language_id_for_path(&type_node.file_path);
    if language_id.0 == "unknown" {
        return Err(DomainError::CapabilityUnavailable {
            capability: "structural_graph".into(),
            reason: "the selected type's structural language is unknown".into(),
            scopes: vec![CapabilityScope::Repository {
                configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
            }],
            evidence: Vec::new(),
        });
    }
    Ok(vec![CapabilityScope::Language {
        language_id,
        configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
    }])
}

fn resolve_type<'a>(
    graph: &'a KnowledgeGraph,
    generation: &ResolvedGeneration,
    binding: &ProjectBinding,
    request: &TypeRequest,
) -> Result<&'a GraphNode, DomainError> {
    let normalized_file = request
        .file
        .as_deref()
        .filter(|file| !file.is_empty())
        .map(|file| generation_file_context(binding, file))
        .transpose()?
        .map(|context| context.file_path().to_owned());
    let node = resolve_symbol_selector(
        graph,
        generation,
        &request.symbol,
        normalized_file.as_deref(),
        NameFileSelection::Locality,
    )?;
    require_type(node)
}

fn require_type(node: &GraphNode) -> Result<&GraphNode, DomainError> {
    if !symbol_kind_has_role(&node.kind, SymbolRole::Type) {
        return Err(DomainError::SymbolNotType {
            symbol: node.symbol_name.clone(),
            kind: node.kind.clone(),
        });
    }
    Ok(node)
}

fn collect_members(
    graph: &KnowledgeGraph,
    type_node: &GraphNode,
    generation: &ResolvedGeneration,
) -> Result<Vec<TypeMember>, DomainError> {
    let children = collect_type_children(graph, &type_node.memory_id);
    let mut members = Vec::new();
    for node in &children.fields {
        push_member(&mut members, TypeMemberRole::Field, graph, node, generation)?;
    }
    for node in &children.field_type_refs {
        push_member(
            &mut members,
            TypeMemberRole::FieldTypeReference,
            graph,
            node,
            generation,
        )?;
    }
    for node in &children.variants {
        push_member(
            &mut members,
            TypeMemberRole::Variant,
            graph,
            node,
            generation,
        )?;
    }
    for node in &children.methods {
        let role = if symbol_kind_has_role(&type_node.kind, SymbolRole::Abstraction) {
            if node.has_body == Some(true) {
                TypeMemberRole::ProvidedMethod
            } else {
                TypeMemberRole::RequiredMethod
            }
        } else if is_public(node) {
            TypeMemberRole::PublicMethod
        } else {
            TypeMemberRole::PrivateMethod
        };
        push_member(&mut members, role, graph, node, generation)?;
    }
    for node in &children.impl_blocks {
        push_member(
            &mut members,
            TypeMemberRole::ImplementationBlock,
            graph,
            node,
            generation,
        )?;
    }

    for (source_id, edge) in graph.incoming_neighbors(&type_node.memory_id) {
        let Some(source) = graph.node(&source_id) else {
            continue;
        };
        let role = match edge.kind {
            EdgeKind::Implements
                if symbol_kind_has_role(&type_node.kind, SymbolRole::Abstraction) =>
            {
                TypeMemberRole::Implementor
            }
            EdgeKind::HasImpl
                if !symbol_kind_has_role(&type_node.kind, SymbolRole::Abstraction) =>
            {
                TypeMemberRole::ImplementedTrait
            }
            _ => continue,
        };
        push_member(&mut members, role, graph, source, generation)?;
    }
    Ok(members)
}

fn push_member(
    members: &mut Vec<TypeMember>,
    role: TypeMemberRole,
    graph: &KnowledgeGraph,
    node: &GraphNode,
    generation: &ResolvedGeneration,
) -> Result<(), DomainError> {
    members.push(TypeMember {
        role,
        symbol: structural_symbol(graph, node, generation)?,
    });
    Ok(())
}

pub(crate) fn structural_symbol(
    graph: &KnowledgeGraph,
    node: &GraphNode,
    generation: &ResolvedGeneration,
) -> Result<StructuralSymbol, DomainError> {
    let language_id = language_id_for_path(&node.file_path);
    let source_backed = !node.file_path.is_empty()
        && !node.file_path.starts_with('<')
        && language_id.0 != "unknown";
    let project_unit_ids = if source_backed {
        source_owner_ids(&generation.project_inventory, &node.file_path, &language_id)?
    } else {
        Vec::new()
    };
    let span = graph.source_span(&node.memory_id);

    Ok(StructuralSymbol {
        symbol_id: exact_symbol_id(
            &generation.manifest.repository_id,
            &generation.manifest.generation_id,
            node.memory_id,
        ),
        name: node.symbol_name.clone(),
        kind: node.kind.clone(),
        document_path: node.file_path.clone(),
        language_id,
        project_unit_ids,
        configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
        signature: node.signature.clone(),
        visibility: node.visibility.clone(),
        start_byte: span.map(|span| span.start_byte),
        end_byte: span.map(|span| span.end_byte),
        start_line: node.line_start,
        end_line: node.line_end,
        source_backed,
    })
}

fn source_owner_ids(
    inventory: &ProjectInventory,
    document_path: &str,
    language_id: &LanguageId,
) -> Result<Vec<ProjectUnitId>, DomainError> {
    let ids = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.document_path == document_path
                && membership.language_id == *language_id
                && membership.kind == crate::code_intel_domain::DocumentMembershipKind::SourceOwner
        })
        .map(|membership| membership.project_unit_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if ids.is_empty() {
        if inventory.project_topology.units.is_empty()
            && inventory.project_topology.memberships.is_empty()
        {
            return Ok(ids);
        }
        return Err(DomainError::ProjectInventoryMismatch {
            document_path: document_path.into(),
            reason: format!("no source-owner membership exists for language {language_id}"),
        });
    }
    for project_unit_id in &ids {
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
    Ok(ids)
}

fn is_public(node: &GraphNode) -> bool {
    node.visibility.starts_with("pub")
        || node.signature.starts_with("pub ")
        || node.signature.contains("pub fn")
        || node.signature.contains("pub(")
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MemberOccurrenceKey {
    role: TypeMemberRole,
    document_path: String,
    start_byte: Option<usize>,
    end_byte: Option<usize>,
    fallback_name: Option<String>,
    fallback_kind: Option<String>,
}

fn member_occurrence_key(member: &TypeMember) -> MemberOccurrenceKey {
    let has_exact_span = member.symbol.start_byte.is_some() && member.symbol.end_byte.is_some();
    MemberOccurrenceKey {
        role: member.role,
        document_path: member.symbol.document_path.clone(),
        start_byte: member.symbol.start_byte,
        end_byte: member.symbol.end_byte,
        fallback_name: (!has_exact_span).then(|| member.symbol.name.clone()),
        fallback_kind: (!has_exact_span).then(|| member.symbol.kind.clone()),
    }
}

fn canonical_members(members: Vec<TypeMember>) -> Result<Vec<TypeMember>, DomainError> {
    let mut by_occurrence = BTreeMap::<MemberOccurrenceKey, TypeMember>::new();
    for member in members {
        let key = member_occurrence_key(&member);
        if let Some(existing) = by_occurrence.insert(key, member.clone())
            && existing != member
        {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: format!(
                    "conflicting {:?} records occupy one structural source occurrence in {}",
                    member.role, member.symbol.document_path
                ),
            });
        }
    }
    let mut canonical = by_occurrence.into_values().collect::<Vec<_>>();
    canonical.sort_by(|left, right| member_sort_key(left).cmp(&member_sort_key(right)));
    Ok(canonical)
}

fn member_sort_key(
    member: &TypeMember,
) -> (
    TypeMemberRole,
    &str,
    Option<usize>,
    Option<usize>,
    &str,
    &str,
    &str,
    &str,
) {
    (
        member.role,
        &member.symbol.document_path,
        member.symbol.start_byte,
        member.symbol.end_byte,
        &member.symbol.name,
        &member.symbol.kind,
        &member.symbol.signature,
        &member.symbol.symbol_id,
    )
}

fn member_totals(members: &[TypeMember]) -> TypeMemberTotals {
    let mut totals = TypeMemberTotals::default();
    for member in members {
        match member.role {
            TypeMemberRole::Field => totals.fields += 1,
            TypeMemberRole::FieldTypeReference => totals.field_type_references += 1,
            TypeMemberRole::Variant => totals.variants += 1,
            TypeMemberRole::PublicMethod => totals.public_methods += 1,
            TypeMemberRole::PrivateMethod => totals.private_methods += 1,
            TypeMemberRole::RequiredMethod => totals.required_methods += 1,
            TypeMemberRole::ProvidedMethod => totals.provided_methods += 1,
            TypeMemberRole::ImplementationBlock => totals.implementation_blocks += 1,
            TypeMemberRole::ImplementedTrait => totals.implemented_traits += 1,
            TypeMemberRole::Implementor => totals.implementors += 1,
        }
    }
    totals
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;
    use crate::code_intel_domain::{
        CapabilityReceipt, ProjectInventory, RepositoryId, TypeRequest,
    };
    use crate::code_intel_publication::{GenerationManifest, PublicationHead, PublicationHeadBody};
    use crate::graph::{EdgeScope, GraphEdge, SourceSpan};
    use crate::project_binding::ProjectBindingOptions;
    use crate::reachability::ReachabilityClass;

    struct Fixture {
        _temporary: TempDir,
        binding: ProjectBinding,
        graph: KnowledgeGraph,
        generation: ResolvedGeneration,
    }

    fn node(name: &str, kind: &str, start_line: usize) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.into(),
            kind: kind.into(),
            file_path: "src/lib.rs".into(),
            content_hash: format!("hash-{name}-{kind}"),
            signature: if kind == "field" {
                format!("{name}: Value")
            } else if matches!(kind, "function" | "method") {
                format!("pub fn {name}()")
            } else {
                String::new()
            },
            reachability_class: ReachabilityClass::Unclassified,
            line_start: Some(start_line),
            line_end: Some(start_line),
            has_body: None,
            visibility: if matches!(kind, "field" | "function" | "method") {
                "pub".into()
            } else {
                String::new()
            },
            is_test_only: Some(false),
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        }
    }

    fn add_node(graph: &mut KnowledgeGraph, node: GraphNode) -> Uuid {
        let id = node.memory_id;
        let line = node.line_start.unwrap_or_default();
        graph.add_node(node).expect("graph node");
        graph
            .set_source_span(
                id,
                SourceSpan {
                    start_byte: line * 100,
                    end_byte: line * 100 + 80,
                },
            )
            .expect("source span");
        id
    }

    #[test]
    fn polyglot_type_kinds_are_admitted_by_the_shared_type_role() {
        for kind in ["struct", "class", "trait", "interface", "type_alias"] {
            let candidate = node("Candidate", kind, 0);
            assert!(
                require_type(&candidate).is_ok(),
                "{kind} must be admitted as a structural type"
            );
        }

        let callable = node("not_a_type", "function", 0);
        assert!(matches!(
            require_type(&callable),
            Err(DomainError::SymbolNotType { .. })
        ));
    }

    fn edge(kind: EdgeKind) -> GraphEdge {
        GraphEdge {
            kind,
            weight: 1.0,
            confidence: 1.0,
            scope: EdgeScope::Production,
            ..GraphEdge::default()
        }
    }

    fn fixture(graph: KnowledgeGraph) -> Fixture {
        let temporary = TempDir::new().expect("temporary directory");
        let root = temporary.path().join("repo");
        let graph_dir = temporary.path().join("bundle");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(&graph_dir).expect("graph directory");
        std::fs::write(root.join("src/lib.rs"), "fixture source").expect("source fixture");
        let binding = ProjectBinding::resolve(
            ProjectBindingOptions::new(&root)
                .explicit_root(&root)
                .global_graph_dir(&graph_dir),
        )
        .expect("project binding");

        let repository_id = RepositoryId::new("repository-fixture");
        let generation_id = GenerationId::new("generation-a");
        let receipt = CapabilityReceipt::complete(
            "structural_graph",
            "h00-structural",
            "fixture-provider-v1",
            CapabilityScope::Language {
                language_id: LanguageId::new("rust"),
                configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
            },
            "a".repeat(64),
        );
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
            provider_payloads: Vec::new(),
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
            project_inventory: ProjectInventory {
                coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
                project_topology: crate::code_intel_domain::ProjectTopology {
                    units: Vec::new(),
                    memberships: Vec::new(),
                    relationships: Vec::new(),
                    exact_workspace_member_sets: Vec::new(),
                    dependency_graphs: Vec::new(),
                },
                analysis_context_graphs: Vec::new(),
                inputs: Vec::new(),
                issues: Vec::new(),
            }
            .into(),
            provider_payloads: Vec::new(),
            database_path: PathBuf::from("generation.redb"),
        };
        Fixture {
            _temporary: temporary,
            binding,
            graph,
            generation,
        }
    }

    #[test]
    fn struct_result_is_typed_deterministic_and_role_complete() {
        let mut graph = KnowledgeGraph::new();
        let target = add_node(&mut graph, node("Counter", "struct", 0));
        let field = add_node(&mut graph, node("Counter::value", "field", 1));
        let field_type = add_node(&mut graph, node("Value", "struct", 2));
        let implementation = add_node(&mut graph, node("impl Counter", "impl", 3));
        let method = add_node(&mut graph, node("impl Counter::increment", "method", 4));
        let implemented_trait = add_node(&mut graph, node("Display", "trait", 5));
        graph
            .add_edge(target, field, edge(EdgeKind::Contains))
            .unwrap();
        graph
            .add_edge(target, field_type, edge(EdgeKind::FieldOf))
            .unwrap();
        graph
            .add_edge(target, implementation, edge(EdgeKind::Contains))
            .unwrap();
        graph
            .add_edge(implementation, method, edge(EdgeKind::Contains))
            .unwrap();
        graph
            .add_edge(implemented_trait, target, edge(EdgeKind::HasImpl))
            .unwrap();
        // A Calls edge is deliberately outside the Type member population.
        let caller = add_node(&mut graph, node("caller", "function", 6));
        graph
            .add_edge(caller, target, edge(EdgeKind::Calls))
            .unwrap();

        let fixture = fixture(graph);
        let result = query_published_type(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &TypeRequest::new("Counter"),
        )
        .expect("typed structural result");
        assert_eq!(result.schema_version, TYPE_SCHEMA_VERSION);
        assert_eq!(result.capability, "structural_graph");
        assert_eq!(result.authority.status, AuthorityStatus::Complete);
        assert_eq!(result.resolved_type.name, "Counter");
        assert_eq!(
            result
                .items
                .iter()
                .map(|item| item.role)
                .collect::<Vec<_>>(),
            [
                TypeMemberRole::Field,
                TypeMemberRole::FieldTypeReference,
                TypeMemberRole::PublicMethod,
                TypeMemberRole::ImplementationBlock,
                TypeMemberRole::ImplementedTrait,
            ]
        );
        assert_eq!(result.totals.fields, 1);
        assert_eq!(result.totals.field_type_references, 1);
        assert_eq!(result.totals.public_methods, 1);
        assert_eq!(result.totals.implementation_blocks, 1);
        assert_eq!(result.totals.implemented_traits, 1);
        assert_eq!(result.page.total_items, 5);
        assert!(result.items.iter().all(|item| item.symbol.source_backed));
    }

    #[test]
    fn trait_methods_and_implementors_have_distinct_structural_roles() {
        let mut graph = KnowledgeGraph::new();
        let target = add_node(&mut graph, node("Renderable", "trait", 0));
        let mut required = node("Renderable::draw", "method", 1);
        required.has_body = Some(false);
        let required = add_node(&mut graph, required);
        let mut provided = node("Renderable::resize", "method", 2);
        provided.has_body = Some(true);
        let provided = add_node(&mut graph, provided);
        let implementor = add_node(&mut graph, node("impl Renderable for Canvas", "impl", 3));
        graph
            .add_edge(target, required, edge(EdgeKind::Contains))
            .unwrap();
        graph
            .add_edge(target, provided, edge(EdgeKind::Contains))
            .unwrap();
        graph
            .add_edge(implementor, target, edge(EdgeKind::Implements))
            .unwrap();

        let fixture = fixture(graph);
        let result = query_published_type(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &TypeRequest::new("Renderable"),
        )
        .expect("trait result");
        assert_eq!(result.totals.required_methods, 1);
        assert_eq!(result.totals.provided_methods, 1);
        assert_eq!(result.totals.implementors, 1);
        assert_eq!(
            result
                .items
                .iter()
                .map(|item| item.role)
                .collect::<Vec<_>>(),
            [
                TypeMemberRole::RequiredMethod,
                TypeMemberRole::ProvidedMethod,
                TypeMemberRole::Implementor,
            ]
        );
    }

    #[test]
    fn type_cursor_is_generation_and_request_bound() {
        let mut graph = KnowledgeGraph::new();
        let target = add_node(&mut graph, node("Many", "struct", 0));
        for index in 0..3 {
            let field = add_node(
                &mut graph,
                node(&format!("Many::field_{index}"), "field", index + 1),
            );
            graph
                .add_edge(target, field, edge(EdgeKind::Contains))
                .unwrap();
        }
        add_node(&mut graph, node("Different", "struct", 10));
        let fixture = fixture(graph);
        let mut request = TypeRequest::new("Many");
        request.limit = 1;
        let first = query_published_type(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &request,
        )
        .expect("first page");
        assert_eq!(first.items.len(), 1);
        assert_eq!(first.page.total_items, 3);
        assert!(first.page.has_more);

        request.cursor = first.page.next_cursor.clone();
        let second = query_published_type(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &request,
        )
        .expect("second page");
        assert_eq!(second.page.offset, 1);
        assert_ne!(first.items, second.items);

        request.symbol = "Different".into();
        assert!(matches!(
            query_published_type(
                &fixture.graph,
                &fixture.generation,
                &fixture.binding,
                &request,
            ),
            Err(DomainError::InvalidCursor { .. })
        ));

        request.symbol = "Many".into();
        let mut changed = fixture.generation.clone();
        changed.manifest.generation_id = GenerationId::new("generation-b");
        changed.head.body.generation_id = GenerationId::new("generation-b");
        assert!(matches!(
            query_published_type(&fixture.graph, &changed, &fixture.binding, &request),
            Err(DomainError::CursorGenerationChanged { .. })
        ));
    }

    #[test]
    fn incomplete_structural_authority_and_non_type_targets_fail_closed() {
        let mut graph = KnowledgeGraph::new();
        add_node(&mut graph, node("not_a_type", "function", 0));
        let non_type = fixture(graph);
        assert!(matches!(
            query_published_type(
                &non_type.graph,
                &non_type.generation,
                &non_type.binding,
                &TypeRequest::new("not_a_type"),
            ),
            Err(DomainError::SymbolNotType { .. })
        ));

        let mut graph = KnowledgeGraph::new();
        add_node(&mut graph, node("PartialType", "struct", 0));
        let mut fixture = fixture(graph);
        fixture.generation.manifest.receipts = vec![CapabilityReceipt::partial(
            "structural_graph",
            "h00-structural",
            Some("fixture-provider-v1".into()),
            CapabilityScope::Language {
                language_id: LanguageId::new("rust"),
                configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
            },
            Some("a".repeat(64)),
            "source_extraction_failed",
            "one Rust source file could not be extracted",
        )];
        let error = query_published_type(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &TypeRequest::new("PartialType"),
        )
        .expect_err("partial structural evidence cannot authorize Type");
        match error {
            DomainError::CapabilityUnavailable {
                capability,
                evidence,
                ..
            } => {
                assert_eq!(capability, "structural_graph");
                assert_eq!(evidence[0].reason_code, "source_extraction_failed");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn type_authority_is_scoped_to_the_selected_language() {
        let mut graph = KnowledgeGraph::new();
        add_node(&mut graph, node("RustType", "struct", 0));
        let mut unrelated_go = node("GoType", "struct", 0);
        unrelated_go.file_path = "pkg/type.go".into();
        add_node(&mut graph, unrelated_go);

        let mut fixture = fixture(graph);
        fixture
            .generation
            .manifest
            .receipts
            .push(CapabilityReceipt::unavailable(
                "structural_graph",
                "h00-structural",
                Some("fixture-provider-v1".into()),
                CapabilityScope::Language {
                    language_id: LanguageId::new("go"),
                    configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
                },
                None,
                "unrelated_go_extraction_failed",
                "the unrelated Go population is unavailable",
            ));

        let result = query_published_type(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &TypeRequest::new("RustType"),
        )
        .expect("unrelated language gaps must not poison exact Rust Type authority");
        assert_eq!(result.authority.status, AuthorityStatus::Complete);
        assert_eq!(result.authority.scopes.len(), 1);
        assert!(matches!(
            &result.authority.scopes[0],
            CapabilityScope::Language { language_id, .. } if language_id.0 == "rust"
        ));
    }

    #[test]
    fn synthetic_type_target_is_not_presented_as_a_source_definition() {
        let mut graph = KnowledgeGraph::new();
        let mut synthetic = node("Synthetic", "struct", 0);
        synthetic.file_path = "<synthetic>".into();
        add_node(&mut graph, synthetic);
        // Positive scope control: the generation really does contain a known
        // structural language, so this must fail on target authority rather
        // than vacuously failing receipt selection.
        add_node(&mut graph, node("source_control", "function", 1));

        let fixture = fixture(graph);
        let error = query_published_type(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &TypeRequest::new("Synthetic"),
        )
        .expect_err("a synthetic graph anchor is not a source-backed type definition");
        assert!(matches!(
            error,
            DomainError::PublishedGenerationInvalid { .. }
        ));
    }

    #[test]
    fn conflicting_members_at_one_source_occurrence_invalidate_the_generation() {
        let mut graph = KnowledgeGraph::new();
        let target = add_node(&mut graph, node("Counter", "struct", 0));
        let first = add_node(&mut graph, node("Counter::value", "field", 1));
        let mut contradictory = node("Counter::value", "field", 1);
        contradictory.visibility = "private".into();
        let contradictory = add_node(&mut graph, contradictory);
        graph
            .add_edge(target, first, edge(EdgeKind::Contains))
            .unwrap();
        graph
            .add_edge(target, contradictory, edge(EdgeKind::Contains))
            .unwrap();

        let fixture = fixture(graph);
        let error = query_published_type(
            &fixture.graph,
            &fixture.generation,
            &fixture.binding,
            &TypeRequest::new("Counter"),
        )
        .expect_err("one exact source occurrence cannot carry conflicting member records");
        assert!(matches!(
            error,
            DomainError::PublishedGenerationInvalid { .. }
        ));
    }
}
