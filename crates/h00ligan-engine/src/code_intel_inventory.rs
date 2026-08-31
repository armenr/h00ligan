//! Deterministic project-unit inventory for one indexed source population.
//!
//! Discovery happens at index time. Query handlers consume the persisted
//! inventory that belongs to their immutable generation; they must never walk
//! the live filesystem to guess authority after publication.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use globset::{GlobBuilder, GlobMatcher};
use rayon::prelude::*;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::code_intel_cargo::{CargoPackageLayout, cargo_package_layout};
use crate::code_intel_domain::{
    AnalysisContext, AnalysisContextCoverage, AnalysisContextGap, AnalysisContextGraph,
    AnalysisContextId, AnalysisContextKindId, AnalysisContextMembership,
    AnalysisContextMembershipKind, AnalysisContextRelationship, AnalysisContextRelationshipKind,
    DocumentMembership, DocumentMembershipKind, EcosystemId, LanguageId, ProjectInput,
    ProjectInputRole, ProjectInventory, ProjectInventoryCoverage, ProjectInventoryIssue,
    ProjectTopology, ProjectUnit, ProjectUnitDependency, ProjectUnitDependencyGap,
    ProjectUnitDependencyGraph, ProjectUnitDependencyGraphCoverage, ProjectUnitId, ProjectUnitKind,
    ProjectUnitRelationship, ProjectUnitRelationshipKind, UnitGraph, UnitGraphCoverage,
};
use crate::code_intel_project_inputs::{ProjectInputCandidate, ProjectInputCandidatePath};

#[cfg(test)]
thread_local! {
    /// Successful manifest reads performed while discovering project units.
    static PROJECT_MANIFEST_FILE_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// Project-input candidate plans rebuilt while observing live inputs.
    static PROJECT_INPUT_PLAN_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
#[derive(Default)]
struct TestProjectInputProbeState {
    file_reads: BTreeMap<PathBuf, usize>,
    delayed_roots: BTreeSet<PathBuf>,
    in_flight: BTreeMap<PathBuf, usize>,
    max_in_flight: BTreeMap<PathBuf, usize>,
}

#[cfg(test)]
fn test_project_input_probe_state() -> &'static Mutex<TestProjectInputProbeState> {
    static STATE: OnceLock<Mutex<TestProjectInputProbeState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(TestProjectInputProbeState::default()))
}

#[cfg(test)]
fn reset_project_discovery_read_counts(root: &Path) {
    test_project_input_probe_state()
        .lock()
        .expect("project-input probe state")
        .file_reads
        .remove(root);
    PROJECT_MANIFEST_FILE_READS.with(|count| count.set(0));
    PROJECT_INPUT_PLAN_BUILDS.with(|count| count.set(0));
}

#[cfg(test)]
fn project_discovery_read_counts(root: &Path) -> (usize, usize) {
    (
        test_project_input_probe_state()
            .lock()
            .expect("project-input probe state")
            .file_reads
            .get(root)
            .copied()
            .unwrap_or(0),
        PROJECT_MANIFEST_FILE_READS.with(std::cell::Cell::get),
    )
}

#[cfg(test)]
fn project_input_plan_build_count() -> usize {
    PROJECT_INPUT_PLAN_BUILDS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn record_project_input_plan_build() {
    PROJECT_INPUT_PLAN_BUILDS.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
fn record_project_input_file_read(root: &Path) {
    let mut state = test_project_input_probe_state()
        .lock()
        .expect("project-input probe state");
    let reads = state.file_reads.entry(root.to_path_buf()).or_default();
    *reads = reads.saturating_add(1);
    drop(state);
}

#[cfg(test)]
fn record_project_manifest_file_read() {
    PROJECT_MANIFEST_FILE_READS.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
struct TestProjectInputFlightGuard {
    root: PathBuf,
}

#[cfg(test)]
struct TestProjectInputDelayGuard {
    root: PathBuf,
}

#[cfg(test)]
impl TestProjectInputDelayGuard {
    fn enable(root: &Path) -> Self {
        test_project_input_probe_state()
            .lock()
            .expect("project-input probe state")
            .delayed_roots
            .insert(root.to_path_buf());
        Self {
            root: root.to_path_buf(),
        }
    }
}

#[cfg(test)]
impl Drop for TestProjectInputDelayGuard {
    fn drop(&mut self) {
        test_project_input_probe_state()
            .lock()
            .expect("project-input probe state")
            .delayed_roots
            .remove(&self.root);
    }
}

#[cfg(test)]
impl TestProjectInputFlightGuard {
    fn enter(root: &Path) -> Self {
        let delay = {
            let mut state = test_project_input_probe_state()
                .lock()
                .expect("project-input probe state");
            let root = root.to_path_buf();
            let in_flight = state.in_flight.entry(root.clone()).or_default();
            *in_flight = in_flight.saturating_add(1);
            let current = *in_flight;
            state
                .max_in_flight
                .entry(root.clone())
                .and_modify(|maximum| *maximum = (*maximum).max(current))
                .or_insert(current);
            let delay = state.delayed_roots.contains(&root);
            drop(state);
            delay
        };
        if delay {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        Self {
            root: root.to_path_buf(),
        }
    }
}

#[cfg(test)]
impl Drop for TestProjectInputFlightGuard {
    fn drop(&mut self) {
        let mut state = test_project_input_probe_state()
            .lock()
            .expect("project-input probe state");
        let Some(in_flight) = state.in_flight.get_mut(&self.root) else {
            return;
        };
        if *in_flight <= 1 {
            state.in_flight.remove(&self.root);
        } else {
            *in_flight -= 1;
        }
        drop(state);
    }
}

#[cfg(test)]
fn reset_project_input_concurrency(root: &Path) {
    let mut state = test_project_input_probe_state()
        .lock()
        .expect("project-input probe state");
    state.in_flight.remove(root);
    state.max_in_flight.remove(root);
    drop(state);
}

#[cfg(test)]
fn max_project_inputs_in_flight(root: &Path) -> usize {
    test_project_input_probe_state()
        .lock()
        .expect("project-input probe state")
        .max_in_flight
        .get(root)
        .copied()
        .unwrap_or(0)
}

pub const PROJECT_INVENTORY_SCHEMA_VERSION: &str = "h00/code-intel/project-inventory/v8";
const SEMANTIC_PROVIDER_INVENTORY_SCHEMA_VERSION: &str =
    "h00/code-intel/semantic-provider-inventory/v4";

#[derive(Debug, thiserror::Error)]
pub enum ProjectInventoryError {
    #[error("invalid project inventory: {0}")]
    Invalid(String),
    #[error("serialize project inventory: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize)]
struct PersistedProjectInventory {
    schema_version: String,
    inventory: ProjectInventory,
}

#[derive(Serialize)]
struct SemanticProviderInventoryProjection {
    schema_version: String,
    language_id: LanguageId,
    ecosystem_id: EcosystemId,
    coverage: ProjectInventoryCoverage,
    project_topology: ProjectTopology,
    analysis_context_graphs: Vec<AnalysisContextGraph>,
    inputs: Vec<ProjectInput>,
    /// Inventory issues are conservatively global because their current
    /// persisted shape has no language coordinate. A malformed unrelated
    /// language may therefore force recertification, but ordinary unrelated
    /// units and inputs cannot impersonate provider input drift.
    issues: Vec<ProjectInventoryIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventorySource {
    pub document_path: String,
    pub language_id: LanguageId,
}

impl InventorySource {
    pub fn new(document_path: impl Into<String>, language_id: impl Into<String>) -> Self {
        Self {
            document_path: document_path.into(),
            language_id: LanguageId::new(language_id),
        }
    }
}

#[derive(Debug, Default)]
struct ProjectInventoryFragment {
    units: BTreeMap<ProjectUnitId, ProjectUnit>,
    memberships: BTreeSet<DocumentMembership>,
    relationships: BTreeSet<ProjectUnitRelationship>,
    exact_workspace_member_sets: BTreeSet<ProjectUnitId>,
    analysis_context_graphs: BTreeSet<AnalysisContextGraph>,
    issues: BTreeSet<ProjectInventoryIssue>,
}

/// Language-owned project topology for one exact indexed source population.
///
/// Syntax registration and project-system registration are deliberately
/// separable: a language may become structurally searchable before a package
/// manager or semantic provider exists. Once an adapter is present, all unit
/// ownership and local-dependency evidence flows through this registry instead
/// of another central language switch.
trait ProjectInventoryAdapter: Sync {
    fn language(&self) -> &'static str;

    fn discover(
        &self,
        root: &Path,
        sources: &BTreeMap<String, LanguageId>,
    ) -> ProjectInventoryFragment;

    fn dependency_graph(
        &self,
        root: &Path,
        ecosystem_id: &EcosystemId,
        units: &BTreeMap<ProjectUnitId, ProjectUnit>,
        relationships: &[ProjectUnitRelationship],
        exact_workspace_member_sets: &BTreeSet<ProjectUnitId>,
        project_unit_ids: Vec<ProjectUnitId>,
    ) -> ProjectUnitDependencyGraph;
}

struct RustProjectInventoryAdapter;
struct GoProjectInventoryAdapter;
struct PythonProjectInventoryAdapter;
struct TypeScriptProjectInventoryAdapter;

static RUST_PROJECT_INVENTORY_ADAPTER: RustProjectInventoryAdapter = RustProjectInventoryAdapter;
static GO_PROJECT_INVENTORY_ADAPTER: GoProjectInventoryAdapter = GoProjectInventoryAdapter;
static PYTHON_PROJECT_INVENTORY_ADAPTER: PythonProjectInventoryAdapter =
    PythonProjectInventoryAdapter;
static TYPESCRIPT_PROJECT_INVENTORY_ADAPTER: TypeScriptProjectInventoryAdapter =
    TypeScriptProjectInventoryAdapter;

static PROJECT_INVENTORY_ADAPTERS: &[&dyn ProjectInventoryAdapter] = &[
    &RUST_PROJECT_INVENTORY_ADAPTER,
    &GO_PROJECT_INVENTORY_ADAPTER,
    &PYTHON_PROJECT_INVENTORY_ADAPTER,
    &TYPESCRIPT_PROJECT_INVENTORY_ADAPTER,
];

fn project_inventory_adapter(language: &str) -> Option<&'static dyn ProjectInventoryAdapter> {
    PROJECT_INVENTORY_ADAPTERS
        .iter()
        .copied()
        .find(|adapter| adapter.language() == language)
}

/// Exact relation between one published project inventory and the live
/// project inputs from which that inventory was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectInventoryFreshness {
    Current,
    Stale,
}

#[derive(Debug, Clone)]
enum ProjectInventoryWitnessMode {
    Complete {
        candidates: Arc<[ProjectInputCandidate]>,
        expected_inputs: Arc<[ProjectInput]>,
    },
    Reconstruct,
    InvalidBinding,
}

/// Immutable-generation-bound plan for exact project-input observation.
#[derive(Debug, Clone)]
pub struct ProjectInventoryWitness {
    sources: Arc<[InventorySource]>,
    expected: Arc<ProjectInventory>,
    mode: ProjectInventoryWitnessMode,
}

impl ProjectInventoryWitness {
    #[must_use]
    pub fn new(sources: Vec<InventorySource>, expected: Arc<ProjectInventory>) -> Self {
        let mode = if expected.coverage != ProjectInventoryCoverage::IndexedSourcePopulationComplete
            || !expected.issues.is_empty()
        {
            ProjectInventoryWitnessMode::Reconstruct
        } else if let Some(source_population) =
            complete_source_population_binding(&sources, &expected)
        {
            ProjectInventoryWitnessMode::Complete {
                candidates: plan_project_inputs(&source_population).into(),
                expected_inputs: expected.inputs.clone().into(),
            }
        } else {
            ProjectInventoryWitnessMode::InvalidBinding
        };
        Self {
            sources: sources.into(),
            expected,
            mode,
        }
    }

    #[must_use]
    pub fn observe(&self, root: &Path) -> ProjectInventoryFreshness {
        match &self.mode {
            ProjectInventoryWitnessMode::Complete {
                candidates,
                expected_inputs,
            } => {
                let mut issues = BTreeSet::new();
                let live_inputs =
                    observe_planned_project_inputs_parallel(root, candidates, &mut issues);
                if issues.is_empty()
                    && live_inputs.len() == expected_inputs.len()
                    && live_inputs.iter().eq(expected_inputs.iter())
                {
                    ProjectInventoryFreshness::Current
                } else {
                    ProjectInventoryFreshness::Stale
                }
            }
            ProjectInventoryWitnessMode::Reconstruct => {
                if build_project_inventory(root, &self.sources) == *self.expected {
                    ProjectInventoryFreshness::Current
                } else {
                    ProjectInventoryFreshness::Stale
                }
            }
            ProjectInventoryWitnessMode::InvalidBinding => ProjectInventoryFreshness::Stale,
        }
    }
}

fn complete_source_population_binding(
    sources: &[InventorySource],
    expected: &ProjectInventory,
) -> Option<BTreeMap<String, LanguageId>> {
    let mut source_population = BTreeMap::<String, LanguageId>::new();
    for source in sources {
        if !safe_relative_path(&source.document_path)
            || source_population
                .insert(source.document_path.clone(), source.language_id.clone())
                .is_some()
        {
            return None;
        }
    }
    let mut expected_owners = BTreeMap::<String, LanguageId>::new();
    for membership in expected
        .project_topology
        .memberships
        .iter()
        .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
    {
        if expected_owners
            .insert(
                membership.document_path.clone(),
                membership.language_id.clone(),
            )
            .is_some()
        {
            return None;
        }
    }
    (source_population == expected_owners).then_some(source_population)
}

/// Re-observe the project topology inputs for one already verified source
/// population.
///
/// The caller must first prove that the live source path population and bytes
/// match `sources`. This boundary independently checks the manifests, locks,
/// and tool configuration that can change project ownership or provider
/// execution roots.
#[must_use]
pub fn check_project_inventory_freshness(
    root: &Path,
    sources: &[InventorySource],
    expected: &ProjectInventory,
) -> ProjectInventoryFreshness {
    ProjectInventoryWitness::new(sources.to_vec(), Arc::new(expected.clone())).observe(root)
}

/// Classify the exact source population supplied by the indexing pipeline.
///
/// A source-owner membership requires ecosystem evidence or an explicit
/// loose-source collection for documents with no eligible project unit.
/// Ancestor manifests that merely contain the source path are retained as
/// `PathContext`, which is useful topology but is insufficient to authorize a
/// project-unit capability.
pub fn build_project_inventory(root: &Path, sources: &[InventorySource]) -> ProjectInventory {
    let mut units = BTreeMap::<ProjectUnitId, ProjectUnit>::new();
    let mut memberships = BTreeSet::<DocumentMembership>::new();
    let mut adapter_relationships = BTreeSet::<ProjectUnitRelationship>::new();
    let mut exact_workspace_member_sets = BTreeSet::<ProjectUnitId>::new();
    let mut analysis_context_graphs = BTreeSet::<AnalysisContextGraph>::new();
    let mut issues = BTreeSet::<ProjectInventoryIssue>::new();
    let mut source_population = BTreeMap::<String, LanguageId>::new();

    for source in sources {
        if !safe_relative_path(&source.document_path) {
            issues.insert(ProjectInventoryIssue {
                code: "unsafe_document_path".into(),
                path: source.document_path.clone(),
                detail: "indexed document path must be repository-relative without traversal"
                    .into(),
            });
            continue;
        }
        match source_population.get(&source.document_path) {
            Some(language) if language != &source.language_id => {
                issues.insert(ProjectInventoryIssue {
                    code: "conflicting_document_language".into(),
                    path: source.document_path.clone(),
                    detail: format!(
                        "document was classified as both {} and {}",
                        language, source.language_id
                    ),
                });
            }
            Some(_) => {}
            None => {
                source_population.insert(source.document_path.clone(), source.language_id.clone());
            }
        }
    }

    let inputs = discover_project_inputs(root, &source_population, &mut issues);

    let mut sources_by_language = BTreeMap::<LanguageId, BTreeMap<String, LanguageId>>::new();
    for (document_path, language_id) in source_population {
        sources_by_language
            .entry(language_id.clone())
            .or_default()
            .insert(document_path, language_id);
    }
    for (language_id, language_sources) in sources_by_language {
        let fragment = project_inventory_adapter(&language_id.0).map_or_else(
            || unregistered_project_inventory_fragment(&language_sources),
            |adapter| adapter.discover(root, &language_sources),
        );
        let ProjectInventoryFragment {
            units: fragment_units,
            memberships: fragment_memberships,
            relationships: fragment_relationships,
            exact_workspace_member_sets: fragment_exact_workspace_member_sets,
            analysis_context_graphs: fragment_analysis_context_graphs,
            issues: fragment_issues,
        } = fragment;
        for unit in fragment_units.into_values() {
            if units
                .get(&unit.project_unit_id)
                .is_some_and(|existing| existing != &unit)
            {
                issues.insert(ProjectInventoryIssue {
                    code: "conflicting_project_unit".into(),
                    path: unit
                        .manifest_path
                        .clone()
                        .unwrap_or_else(|| unit.root_path.clone()),
                    detail: format!(
                        "project unit {} was produced with conflicting definitions",
                        unit.project_unit_id.0
                    ),
                });
                continue;
            }
            units.insert(unit.project_unit_id.clone(), unit);
        }
        memberships.extend(fragment_memberships);
        adapter_relationships.extend(fragment_relationships);
        exact_workspace_member_sets.extend(fragment_exact_workspace_member_sets);
        analysis_context_graphs.extend(fragment_analysis_context_graphs);
        issues.extend(fragment_issues);
    }

    let mut relationships = path_relationships(units.values())
        .into_iter()
        .collect::<BTreeSet<_>>();
    relationships.extend(adapter_relationships);
    let relationships = relationships.into_iter().collect::<Vec<_>>();
    let dependency_graphs = project_unit_dependency_graphs(
        root,
        &units,
        &memberships,
        &relationships,
        &exact_workspace_member_sets,
    );
    let issues = issues.into_iter().collect::<Vec<_>>();
    ProjectInventory {
        coverage: if issues.is_empty() {
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        } else {
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        },
        project_topology: ProjectTopology {
            units: units.into_values().collect(),
            memberships: memberships.into_iter().collect(),
            relationships,
            exact_workspace_member_sets: exact_workspace_member_sets.into_iter().collect(),
            dependency_graphs,
        },
        analysis_context_graphs: analysis_context_graphs.into_iter().collect(),
        inputs: inputs.into_iter().collect(),
        issues,
    }
}

/// Derive the minimum deterministic provider execution roots for one language
/// and ecosystem from the exact indexed inventory.
///
/// Each source-owning package/module belongs to its deepest containing
/// workspace when one exists; otherwise the owner itself is an execution root.
/// Path containment is used only to schedule providers. The resulting artifact
/// still has to prove its exact document population before it receives any
/// semantic authority.
pub(crate) fn semantic_provider_execution_roots(
    inventory: &ProjectInventory,
    language: &str,
    ecosystem: &str,
) -> Vec<PathBuf> {
    semantic_provider_document_execution_roots(inventory, language, ecosystem)
        .into_values()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Bind every exact provider-owned document to the execution root governing
/// its semantic session. Loose and auxiliary sources remain structurally
/// visible but cannot enter a project provider merely because their paths sit
/// below one of these roots.
pub(crate) fn semantic_provider_document_execution_roots(
    inventory: &ProjectInventory,
    language: &str,
    ecosystem: &str,
) -> BTreeMap<String, PathBuf> {
    let unit_roots = semantic_provider_unit_execution_roots(inventory, language, ecosystem);
    inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.kind == DocumentMembershipKind::SourceOwner
                && membership.language_id.0 == language
        })
        .filter_map(|membership| {
            unit_roots
                .get(&membership.project_unit_id)
                .cloned()
                .map(|root| (membership.document_path.clone(), root))
        })
        .collect()
}

/// Bind each source-owning package/module to the exact root at which its
/// semantic provider must execute. Consumers use this same mapping both to
/// schedule providers and to admit authority from successful invocations.
/// Document presence is not a substitute for invocation ownership: providers
/// may deliberately omit platform- or build-tag-selected sources and qualify
/// those exact regions in their payload.
pub(crate) fn semantic_provider_unit_execution_roots(
    inventory: &ProjectInventory,
    language: &str,
    ecosystem: &str,
) -> BTreeMap<ProjectUnitId, PathBuf> {
    let units = inventory
        .project_topology
        .units
        .iter()
        .map(|unit| (unit.project_unit_id.clone(), unit))
        .collect::<BTreeMap<_, _>>();
    let owner_ids = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.kind == DocumentMembershipKind::SourceOwner
                && membership.language_id.0 == language
        })
        .map(|membership| membership.project_unit_id.clone())
        .collect::<BTreeSet<_>>();
    let workspaces = inventory
        .project_topology
        .units
        .iter()
        .filter(|unit| {
            unit.language_id.0 == language
                && unit.ecosystem_id.0 == ecosystem
                && unit.kind == ProjectUnitKind::Workspace
        })
        .collect::<Vec<_>>();
    let exact_workspace_member_sets = inventory
        .project_topology
        .exact_workspace_member_sets
        .iter()
        .collect::<BTreeSet<_>>();

    let mut roots = BTreeMap::new();
    for owner_id in owner_ids {
        let Some(owner) = units.get(&owner_id).copied() else {
            continue;
        };
        if owner.ecosystem_id.0 != ecosystem
            || !matches!(
                owner.kind,
                ProjectUnitKind::Package | ProjectUnitKind::Module
            )
        {
            continue;
        }
        let owner_root = Path::new(&owner.root_path);
        let exact_containing_workspaces = workspaces
            .iter()
            .filter(|workspace| {
                exact_workspace_member_sets.contains(&workspace.project_unit_id)
                    && owner_root.starts_with(Path::new(&workspace.root_path))
            })
            .copied()
            .collect::<Vec<_>>();
        let root = if !exact_containing_workspaces.is_empty() {
            let exact_ids = exact_containing_workspaces
                .iter()
                .map(|workspace| &workspace.project_unit_id)
                .collect::<BTreeSet<_>>();
            let memberships = inventory
                .project_topology
                .relationships
                .iter()
                .filter(|relationship| {
                    relationship.kind == ProjectUnitRelationshipKind::WorkspaceMember
                        && relationship.child_project_unit_id == owner.project_unit_id
                })
                .filter_map(|relationship| units.get(&relationship.parent_project_unit_id))
                .filter(|workspace| exact_ids.contains(&workspace.project_unit_id))
                .collect::<Vec<_>>();
            if let [workspace] = memberships.as_slice() {
                workspace.root_path.as_str()
            } else {
                // Zero memberships means an independent package; multiple
                // memberships are ambiguous and must not broaden execution.
                owner.root_path.as_str()
            }
        } else {
            workspaces
                .iter()
                .filter(|workspace| owner_root.starts_with(Path::new(&workspace.root_path)))
                .max_by(|left, right| {
                    path_depth(&left.root_path)
                        .cmp(&path_depth(&right.root_path))
                        .then_with(|| right.project_unit_id.cmp(&left.project_unit_id))
                })
                .map_or(owner.root_path.as_str(), |workspace| {
                    workspace.root_path.as_str()
                })
        };
        roots.insert(owner_id, PathBuf::from(root));
    }
    roots
}

/// Root-local identity of the Go project topology that can influence one
/// independently executable provider partition.
///
/// The publication's whole-language inventory digest remains the authority
/// boundary. This projection is narrower acceleration evidence: a manifest,
/// lock, topology, or dependency change is localized only when every relevant
/// inventory coordinate has one exact execution-root owner. Anything
/// ambiguous is included in every root and therefore conservatively forces a
/// complete Go refresh.
pub(crate) fn go_execution_root_inventory_fingerprints(
    inventory: &ProjectInventory,
    expected_roots: &BTreeSet<String>,
) -> Option<BTreeMap<String, String>> {
    if expected_roots.is_empty() {
        return None;
    }
    let unit_roots = semantic_provider_unit_execution_roots(inventory, "go", "go")
        .into_iter()
        .map(|(unit, root)| (unit, root.to_string_lossy().replace('\\', "/")))
        .collect::<BTreeMap<_, _>>();
    if unit_roots.values().cloned().collect::<BTreeSet<_>>() != *expected_roots {
        return None;
    }

    let input_roots = go_project_input_execution_roots(inventory, expected_roots)?;
    let provider_units = inventory
        .project_topology
        .units
        .iter()
        .filter(|unit| {
            unit.language_id.0 == "go"
                && (unit.ecosystem_id.0 == "go" || !unit.kind.grants_semantic_authority())
        })
        .collect::<Vec<_>>();
    let unit_assignment = |unit: &ProjectUnit| {
        unit_roots.get(&unit.project_unit_id).cloned().or_else(|| {
            (unit.kind == ProjectUnitKind::Workspace && expected_roots.contains(&unit.root_path))
                .then(|| unit.root_path.clone())
        })
    };
    let mut fingerprints = BTreeMap::new();
    for root in expected_roots {
        let mut units = provider_units
            .iter()
            .filter(|unit| {
                unit_assignment(unit)
                    .as_ref()
                    .is_none_or(|owner| owner == root)
            })
            .copied()
            .collect::<Vec<_>>();
        units.sort();
        let selected_units = units
            .iter()
            .map(|unit| unit.project_unit_id.clone())
            .collect::<BTreeSet<_>>();
        let mut memberships = inventory
            .project_topology
            .memberships
            .iter()
            .filter(|membership| selected_units.contains(&membership.project_unit_id))
            .collect::<Vec<_>>();
        memberships.sort();
        let mut relationships = inventory
            .project_topology
            .relationships
            .iter()
            .filter(|relationship| {
                selected_units.contains(&relationship.parent_project_unit_id)
                    || selected_units.contains(&relationship.child_project_unit_id)
            })
            .collect::<Vec<_>>();
        relationships.sort();
        let dependency_graphs = inventory
            .project_topology
            .dependency_graphs
            .iter()
            .filter(|graph| graph.language_id.0 == "go" && graph.ecosystem_id.0 == "go")
            .map(|graph| {
                let mut project_unit_ids = graph
                    .project_unit_ids
                    .iter()
                    .filter(|unit| selected_units.contains(*unit))
                    .collect::<Vec<_>>();
                project_unit_ids.sort();
                let mut dependencies = graph
                    .dependencies
                    .iter()
                    .filter(|dependency| {
                        selected_units.contains(&dependency.dependent_project_unit_id)
                    })
                    .collect::<Vec<_>>();
                dependencies.sort();
                let mut gaps = graph
                    .gaps
                    .iter()
                    .filter(|gap| {
                        gap.project_unit_id
                            .as_ref()
                            .is_none_or(|unit| selected_units.contains(unit))
                    })
                    .collect::<Vec<_>>();
                gaps.sort();
                (graph.coverage, project_unit_ids, dependencies, gaps)
            })
            .collect::<Vec<_>>();
        let mut inputs = inventory
            .inputs
            .iter()
            .filter(|input| {
                input.language_id.0 == "go"
                    && input.ecosystem_id.0 == "go"
                    && input_roots
                        .get(&input.path)
                        .is_some_and(|owners| owners.contains(root))
            })
            .collect::<Vec<_>>();
        inputs.sort();
        let bytes = serde_json::to_vec(&(
            "h00/go-execution-root-inventory/v1",
            root,
            inventory.coverage,
            units,
            memberships,
            relationships,
            dependency_graphs,
            inputs,
            &inventory.issues,
        ))
        .ok()?;
        let digest = Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        fingerprints.insert(root.clone(), digest);
    }
    Some(fingerprints)
}

pub(crate) fn go_project_input_execution_roots(
    inventory: &ProjectInventory,
    expected_roots: &BTreeSet<String>,
) -> Option<BTreeMap<String, BTreeSet<String>>> {
    if expected_roots.is_empty() {
        return None;
    }
    let unit_roots = semantic_provider_unit_execution_roots(inventory, "go", "go")
        .into_iter()
        .map(|(unit, root)| (unit, root.to_string_lossy().replace('\\', "/")))
        .collect::<BTreeMap<_, _>>();
    if unit_roots.values().cloned().collect::<BTreeSet<_>>() != *expected_roots {
        return None;
    }
    let provider_units = inventory
        .project_topology
        .units
        .iter()
        .filter(|unit| unit.language_id.0 == "go" && unit.ecosystem_id.0 == "go")
        .collect::<Vec<_>>();
    let mut result = BTreeMap::new();
    for input in inventory
        .inputs
        .iter()
        .filter(|input| input.language_id.0 == "go" && input.ecosystem_id.0 == "go")
    {
        let path = Path::new(&input.path);
        let parent = path
            .parent()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default();
        let name = path.file_name().and_then(|name| name.to_str());
        let assigned = match name {
            Some("go.mod" | "go.sum") => provider_units
                .iter()
                .find(|unit| unit.kind == ProjectUnitKind::Module && unit.root_path == parent)
                .and_then(|unit| unit_roots.get(&unit.project_unit_id))
                .cloned(),
            Some("modules.txt") if path.ends_with(Path::new("vendor/modules.txt")) => {
                let module_root = path
                    .parent()
                    .and_then(Path::parent)
                    .map(|path| path.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_default();
                provider_units
                    .iter()
                    .find(|unit| {
                        unit.kind == ProjectUnitKind::Module && unit.root_path == module_root
                    })
                    .and_then(|unit| unit_roots.get(&unit.project_unit_id))
                    .cloned()
            }
            Some("go.work" | "go.work.sum") if expected_roots.contains(&parent) => Some(parent),
            _ => None,
        };
        if result
            .insert(
                input.path.clone(),
                assigned.map_or_else(|| expected_roots.clone(), |root| BTreeSet::from([root])),
            )
            .is_some()
        {
            return None;
        }
    }
    Some(result)
}

/// Exact stable project-input candidate population owned by each persistent
/// gopls execution root.
///
/// Existing inventory inputs are retained, while the absent lock/vendor
/// companions of every admitted workspace and module remain explicit missing
/// coordinates. This lets create/delete transitions use the same bounded
/// session manifest instead of silently changing its authority population.
pub(crate) fn go_provider_semantic_input_paths(
    inventory: &ProjectInventory,
    expected_roots: &BTreeSet<String>,
) -> Option<BTreeMap<String, BTreeSet<String>>> {
    if expected_roots.is_empty() {
        return None;
    }
    let unit_roots = semantic_provider_unit_execution_roots(inventory, "go", "go")
        .into_iter()
        .map(|(unit, root)| (unit, root.to_string_lossy().replace('\\', "/")))
        .collect::<BTreeMap<_, _>>();
    if unit_roots.values().cloned().collect::<BTreeSet<_>>() != *expected_roots {
        return None;
    }
    let units = inventory
        .project_topology
        .units
        .iter()
        .map(|unit| (unit.project_unit_id.clone(), unit))
        .collect::<BTreeMap<_, _>>();
    let mut result = expected_roots
        .iter()
        .cloned()
        .map(|root| (root, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();

    let add_candidates = |paths: &mut BTreeSet<String>, root: &str, names: &[&str]| {
        for name in names {
            paths.insert(path_label(&Path::new(root).join(name)));
        }
    };
    for (unit_id, execution_root) in &unit_roots {
        let unit = units.get(unit_id)?;
        if unit.kind == ProjectUnitKind::Module {
            add_candidates(
                result.get_mut(execution_root)?,
                &unit.root_path,
                &["go.mod", "go.sum", "vendor/modules.txt"],
            );
        }
    }
    for workspace in inventory.project_topology.units.iter().filter(|unit| {
        unit.language_id.0 == "go"
            && unit.ecosystem_id.0 == "go"
            && unit.kind == ProjectUnitKind::Workspace
            && expected_roots.contains(&unit.root_path)
    }) {
        add_candidates(
            result.get_mut(&workspace.root_path)?,
            &workspace.root_path,
            &["go.work", "go.work.sum"],
        );
    }

    let input_roots = go_project_input_execution_roots(inventory, expected_roots)?;
    for input in inventory
        .inputs
        .iter()
        .filter(|input| input.language_id.0 == "go" && input.ecosystem_id.0 == "go")
    {
        for owner in input_roots.get(&input.path)? {
            result.get_mut(owner)?.insert(input.path.clone());
        }
    }
    result
        .values()
        .all(|paths| !paths.is_empty())
        .then_some(result)
}

/// Canonical persisted bytes for one validated inventory.
pub fn canonical_project_inventory_bytes(
    inventory: &ProjectInventory,
) -> Result<Vec<u8>, ProjectInventoryError> {
    let inventory = normalize_and_validate_inventory(inventory)?;
    Ok(serde_json::to_vec(&PersistedProjectInventory {
        schema_version: PROJECT_INVENTORY_SCHEMA_VERSION.into(),
        inventory,
    })?)
}

/// Parse, validate, and require the canonical persisted representation.
pub fn parse_project_inventory_bytes(
    bytes: &[u8],
) -> Result<ProjectInventory, ProjectInventoryError> {
    let document: PersistedProjectInventory = serde_json::from_slice(bytes)?;
    if document.schema_version != PROJECT_INVENTORY_SCHEMA_VERSION {
        return Err(ProjectInventoryError::Invalid(format!(
            "unsupported schema {}",
            document.schema_version
        )));
    }
    let normalized = normalize_and_validate_inventory(&document.inventory)?;
    let canonical = serde_json::to_vec(&PersistedProjectInventory {
        schema_version: PROJECT_INVENTORY_SCHEMA_VERSION.into(),
        inventory: normalized.clone(),
    })?;
    if canonical != bytes {
        return Err(ProjectInventoryError::Invalid(
            "persisted bytes are not canonical".into(),
        ));
    }
    Ok(normalized)
}

/// Deterministic identity of the inventory topology and its evidence gaps.
pub fn project_inventory_fingerprint(
    inventory: &ProjectInventory,
) -> Result<String, ProjectInventoryError> {
    let bytes = canonical_project_inventory_bytes(inventory)?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Deterministic identity of the exact project-inventory population governed
/// by one language provider.
///
/// The immutable generation still persists and validates the complete
/// repository inventory. Provider execution and Calls input authority bind a
/// narrower projection so an unrelated language's manifest, lock, unit, or
/// source ownership cannot invalidate or rewrite this provider's identity.
pub fn semantic_provider_inventory_fingerprint(
    inventory: &ProjectInventory,
    language: &str,
    ecosystem: &str,
) -> Result<String, ProjectInventoryError> {
    if language.trim().is_empty()
        || ecosystem.trim().is_empty()
        || language.contains('\0')
        || ecosystem.contains('\0')
    {
        return Err(ProjectInventoryError::Invalid(
            "semantic provider language and ecosystem must be nonempty labels".into(),
        ));
    }
    let normalized = normalize_and_validate_inventory(inventory)?;
    let selected_units = normalized
        .project_topology
        .units
        .iter()
        .filter(|unit| {
            unit.language_id.0 == language
                && (unit.ecosystem_id.0 == ecosystem || !unit.kind.grants_semantic_authority())
        })
        .cloned()
        .collect::<Vec<_>>();
    let selected_ids = selected_units
        .iter()
        .map(|unit| unit.project_unit_id.clone())
        .collect::<BTreeSet<_>>();
    let projection = SemanticProviderInventoryProjection {
        schema_version: SEMANTIC_PROVIDER_INVENTORY_SCHEMA_VERSION.into(),
        language_id: LanguageId::new(language),
        ecosystem_id: EcosystemId::new(ecosystem),
        coverage: normalized.coverage,
        project_topology: ProjectTopology {
            units: selected_units,
            memberships: normalized
                .project_topology
                .memberships
                .into_iter()
                .filter(|membership| {
                    membership.language_id.0 == language
                        && selected_ids.contains(&membership.project_unit_id)
                })
                .collect(),
            relationships: normalized
                .project_topology
                .relationships
                .into_iter()
                .filter(|relationship| {
                    selected_ids.contains(&relationship.parent_project_unit_id)
                        && selected_ids.contains(&relationship.child_project_unit_id)
                })
                .collect(),
            exact_workspace_member_sets: normalized
                .project_topology
                .exact_workspace_member_sets
                .into_iter()
                .filter(|workspace| selected_ids.contains(workspace))
                .collect(),
            dependency_graphs: normalized
                .project_topology
                .dependency_graphs
                .into_iter()
                .filter(|graph| {
                    graph.language_id.0 == language && graph.ecosystem_id.0 == ecosystem
                })
                .collect(),
        },
        analysis_context_graphs: normalized
            .analysis_context_graphs
            .into_iter()
            .filter(|graph| graph.language_id.0 == language && graph.ecosystem_id.0 == ecosystem)
            .collect(),
        inputs: normalized
            .inputs
            .into_iter()
            .filter(|input| input.language_id.0 == language && input.ecosystem_id.0 == ecosystem)
            .collect(),
        issues: normalized.issues,
    };
    let digest = Sha256::digest(serde_json::to_vec(&projection)?);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn normalize_and_validate_inventory(
    inventory: &ProjectInventory,
) -> Result<ProjectInventory, ProjectInventoryError> {
    if matches!(
        inventory.coverage,
        ProjectInventoryCoverage::IndexedSourcePopulationComplete
    ) != inventory.issues.is_empty()
    {
        return Err(ProjectInventoryError::Invalid(
            "complete coverage requires zero issues and partial coverage requires at least one issue"
                .into(),
        ));
    }

    let mut normalized = inventory.clone();
    for unit in &mut normalized.project_topology.units {
        unit.compilation_root_paths.sort();
    }
    normalized.project_topology.units.sort();
    normalized.project_topology.memberships.sort();
    normalized.project_topology.relationships.sort();
    normalized
        .project_topology
        .exact_workspace_member_sets
        .sort();
    for graph in &mut normalized.project_topology.dependency_graphs {
        graph.project_unit_ids.sort();
        graph.dependencies.sort();
        graph.gaps.sort();
    }
    normalized.project_topology.dependency_graphs.sort();
    for graph in &mut normalized.analysis_context_graphs {
        graph.contexts.sort();
        graph.memberships.sort();
        graph.relationships.sort();
        graph.gaps.sort();
    }
    normalized.analysis_context_graphs.sort();
    normalized.inputs.sort();
    normalized.issues.sort();

    if normalized
        .project_topology
        .units
        .windows(2)
        .any(|pair| pair[0].project_unit_id == pair[1].project_unit_id)
    {
        return Err(ProjectInventoryError::Invalid(
            "project-unit IDs must be unique".into(),
        ));
    }
    reject_exact_duplicates(
        "document memberships",
        &normalized.project_topology.memberships,
    )?;
    reject_exact_duplicates(
        "project-unit relationships",
        &normalized.project_topology.relationships,
    )?;
    reject_exact_duplicates(
        "exact workspace member sets",
        &normalized.project_topology.exact_workspace_member_sets,
    )?;
    reject_exact_duplicates(
        "project-unit dependency graphs",
        &normalized.project_topology.dependency_graphs,
    )?;
    reject_exact_duplicates("project inputs", &normalized.inputs)?;
    reject_exact_duplicates("inventory issues", &normalized.issues)?;
    if normalized.inputs.windows(2).any(|pair| {
        pair[0].path == pair[1].path
            && pair[0].language_id == pair[1].language_id
            && pair[0].ecosystem_id == pair[1].ecosystem_id
            && pair[0].role == pair[1].role
    }) {
        return Err(ProjectInventoryError::Invalid(
            "project-input identity must be unique".into(),
        ));
    }

    let units = normalized
        .project_topology
        .units
        .iter()
        .map(|unit| (unit.project_unit_id.clone(), unit))
        .collect::<BTreeMap<_, _>>();
    for unit in &normalized.project_topology.units {
        validate_label("project-unit ID", &unit.project_unit_id.0)?;
        validate_label("language ID", &unit.language_id.0)?;
        validate_label("ecosystem ID", &unit.ecosystem_id.0)?;
        if !unit.root_path.is_empty() && !safe_relative_path(&unit.root_path) {
            return Err(ProjectInventoryError::Invalid(format!(
                "project-unit root path is not canonical and repository-relative: {}",
                unit.root_path
            )));
        }
        if unit
            .manifest_path
            .as_deref()
            .is_some_and(|path| !safe_relative_path(path))
        {
            return Err(ProjectInventoryError::Invalid(format!(
                "project-unit manifest path is not canonical and repository-relative: {:?}",
                unit.manifest_path
            )));
        }
        if unit
            .compilation_root_paths
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(ProjectInventoryError::Invalid(format!(
                "project-unit compilation roots must be unique for {}",
                unit.project_unit_id
            )));
        }
        for path in &unit.compilation_root_paths {
            if !safe_relative_path(path) {
                return Err(ProjectInventoryError::Invalid(format!(
                    "project-unit compilation root is not canonical and repository-relative: {path}"
                )));
            }
        }
    }
    for workspace_id in &normalized.project_topology.exact_workspace_member_sets {
        let Some(workspace) = units.get(workspace_id) else {
            return Err(ProjectInventoryError::Invalid(format!(
                "exact workspace member set references missing project unit {workspace_id}"
            )));
        };
        if workspace.kind != ProjectUnitKind::Workspace {
            return Err(ProjectInventoryError::Invalid(format!(
                "exact workspace member set references non-workspace project unit {workspace_id}"
            )));
        }
    }

    for input in &normalized.inputs {
        if !safe_relative_path(&input.path) {
            return Err(ProjectInventoryError::Invalid(format!(
                "project-input path is not canonical and repository-relative: {}",
                input.path
            )));
        }
        validate_label("project-input language ID", &input.language_id.0)?;
        validate_label("project-input ecosystem ID", &input.ecosystem_id.0)?;
        if input.content_sha256.len() != 64
            || !input
                .content_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ProjectInventoryError::Invalid(format!(
                "project-input digest for {} must be 64 lowercase hexadecimal characters",
                input.path
            )));
        }
    }

    let mut document_languages = BTreeMap::<&str, &LanguageId>::new();
    let mut membership_roles =
        BTreeMap::<(&str, &LanguageId, &ProjectUnitId), DocumentMembershipKind>::new();
    let mut documents = BTreeMap::<(&str, &LanguageId), usize>::new();
    for membership in &normalized.project_topology.memberships {
        if !safe_relative_path(&membership.document_path) {
            return Err(ProjectInventoryError::Invalid(format!(
                "membership document path is not canonical and repository-relative: {}",
                membership.document_path
            )));
        }
        let Some(unit) = units.get(&membership.project_unit_id) else {
            return Err(ProjectInventoryError::Invalid(format!(
                "membership references missing project unit {}",
                membership.project_unit_id
            )));
        };
        if unit.language_id != membership.language_id {
            return Err(ProjectInventoryError::Invalid(format!(
                "membership language {} differs from unit {} language {}",
                membership.language_id, membership.project_unit_id, unit.language_id
            )));
        }
        if let Some(existing) = document_languages
            .insert(&membership.document_path, &membership.language_id)
            .filter(|existing| *existing != &membership.language_id)
        {
            return Err(ProjectInventoryError::Invalid(format!(
                "document {} has conflicting languages {} and {}",
                membership.document_path, existing, membership.language_id
            )));
        }
        let membership_key = (
            membership.document_path.as_str(),
            &membership.language_id,
            &membership.project_unit_id,
        );
        if let Some(existing) = membership_roles
            .insert(membership_key, membership.kind)
            .filter(|existing| *existing != membership.kind)
        {
            return Err(ProjectInventoryError::Invalid(format!(
                "document {} has conflicting membership roles {:?} and {:?} for unit {}",
                membership.document_path, existing, membership.kind, membership.project_unit_id
            )));
        }
        let source_owner_count = documents
            .entry((&membership.document_path, &membership.language_id))
            .or_default();
        if membership.kind == DocumentMembershipKind::SourceOwner {
            *source_owner_count += 1;
        }
    }
    if let Some(((document_path, language_id), source_owner_count)) = documents
        .iter()
        .find(|(_, source_owner_count)| **source_owner_count != 1)
    {
        return Err(ProjectInventoryError::Invalid(format!(
            "document {document_path} ({language_id}) must have exactly one source owner, found {source_owner_count}"
        )));
    }

    for relationship in &normalized.project_topology.relationships {
        if relationship.parent_project_unit_id == relationship.child_project_unit_id {
            return Err(ProjectInventoryError::Invalid(format!(
                "project unit {} cannot be nested within itself",
                relationship.parent_project_unit_id
            )));
        }
        if !units.contains_key(&relationship.parent_project_unit_id)
            || !units.contains_key(&relationship.child_project_unit_id)
        {
            return Err(ProjectInventoryError::Invalid(format!(
                "relationship references a missing project unit: {} -> {}",
                relationship.parent_project_unit_id, relationship.child_project_unit_id
            )));
        }
        let parent = units
            .get(&relationship.parent_project_unit_id)
            .expect("relationship parent validated");
        let child = units
            .get(&relationship.child_project_unit_id)
            .expect("relationship child validated");
        if parent.language_id != child.language_id || parent.ecosystem_id != child.ecosystem_id {
            return Err(ProjectInventoryError::Invalid(format!(
                "relationship crosses language or ecosystem boundaries: {} -> {}",
                relationship.parent_project_unit_id, relationship.child_project_unit_id
            )));
        }
        if relationship.kind == ProjectUnitRelationshipKind::WorkspaceMember {
            if parent.kind != ProjectUnitKind::Workspace
                || !matches!(
                    child.kind,
                    ProjectUnitKind::Package | ProjectUnitKind::Module
                )
            {
                return Err(ProjectInventoryError::Invalid(format!(
                    "workspace membership must connect a workspace to a package/module: {} -> {}",
                    relationship.parent_project_unit_id, relationship.child_project_unit_id
                )));
            }
            if !normalized
                .project_topology
                .exact_workspace_member_sets
                .contains(&relationship.parent_project_unit_id)
            {
                return Err(ProjectInventoryError::Invalid(format!(
                    "workspace membership has no exact member-set authority: {}",
                    relationship.parent_project_unit_id
                )));
            }
            if !Path::new(&child.root_path).starts_with(Path::new(&parent.root_path)) {
                return Err(ProjectInventoryError::Invalid(format!(
                    "workspace member root is outside its workspace: {} -> {}",
                    relationship.parent_project_unit_id, relationship.child_project_unit_id
                )));
            }
        }
    }
    validate_acyclic_relationships(
        &normalized.project_topology.units,
        &normalized.project_topology.relationships,
    )?;

    validate_dependency_graphs(&normalized, &units)?;
    validate_analysis_context_graphs(&normalized)?;

    for issue in &normalized.issues {
        validate_label("inventory issue code", &issue.code)?;
        if issue.path.trim().is_empty() || issue.detail.trim().is_empty() {
            return Err(ProjectInventoryError::Invalid(
                "inventory issue path and detail must not be empty".into(),
            ));
        }
    }
    Ok(normalized)
}

fn reject_exact_duplicates<T: PartialEq>(
    label: &str,
    values: &[T],
) -> Result<(), ProjectInventoryError> {
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ProjectInventoryError::Invalid(format!(
            "{label} must not contain duplicates"
        )));
    }
    Ok(())
}

fn validate_label(label: &str, value: &str) -> Result<(), ProjectInventoryError> {
    if value.trim().is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        return Err(ProjectInventoryError::Invalid(format!(
            "{label} is empty, too long, or contains control characters"
        )));
    }
    Ok(())
}

fn validate_acyclic_relationships(
    units: &[ProjectUnit],
    relationships: &[ProjectUnitRelationship],
) -> Result<(), ProjectInventoryError> {
    let mut remaining_parents = units
        .iter()
        .map(|unit| (unit.project_unit_id.clone(), 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut children = BTreeMap::<ProjectUnitId, Vec<ProjectUnitId>>::new();
    for relationship in relationships {
        *remaining_parents
            .get_mut(&relationship.child_project_unit_id)
            .expect("relationship references were validated") += 1;
        children
            .entry(relationship.parent_project_unit_id.clone())
            .or_default()
            .push(relationship.child_project_unit_id.clone());
    }
    let mut ready = remaining_parents
        .iter()
        .filter_map(|(unit_id, count)| (*count == 0).then_some(unit_id.clone()))
        .collect::<BTreeSet<_>>();
    let mut visited = 0usize;
    while let Some(unit_id) = ready.pop_first() {
        visited += 1;
        for child in children.get(&unit_id).into_iter().flatten() {
            let count = remaining_parents
                .get_mut(child)
                .expect("relationship references were validated");
            *count -= 1;
            if *count == 0 {
                ready.insert(child.clone());
            }
        }
    }
    if visited != units.len() {
        return Err(ProjectInventoryError::Invalid(
            "project-unit relationships contain a cycle".into(),
        ));
    }
    Ok(())
}

fn validate_dependency_graphs(
    inventory: &ProjectInventory,
    units: &BTreeMap<ProjectUnitId, &ProjectUnit>,
) -> Result<(), ProjectInventoryError> {
    let mut graph_keys = BTreeSet::new();
    for graph in &inventory.project_topology.dependency_graphs {
        validate_label("dependency-graph language ID", &graph.language_id.0)?;
        validate_label("dependency-graph ecosystem ID", &graph.ecosystem_id.0)?;
        if !graph_keys.insert((graph.language_id.clone(), graph.ecosystem_id.clone())) {
            return Err(ProjectInventoryError::Invalid(format!(
                "dependency graph is duplicated for {} / {}",
                graph.language_id, graph.ecosystem_id
            )));
        }
        reject_exact_duplicates("dependency-graph project units", &graph.project_unit_ids)?;
        reject_exact_duplicates("local project-unit dependencies", &graph.dependencies)?;
        reject_exact_duplicates("dependency-graph gaps", &graph.gaps)?;
        if graph.project_unit_ids.is_empty() {
            return Err(ProjectInventoryError::Invalid(
                "dependency graph has an empty project-unit population".into(),
            ));
        }
        let expected_units = inventory
            .project_topology
            .memberships
            .iter()
            .filter_map(|membership| {
                let unit = units.get(&membership.project_unit_id)?;
                (membership.kind == DocumentMembershipKind::SourceOwner
                    && unit.kind.grants_semantic_authority()
                    && unit.language_id == graph.language_id
                    && unit.ecosystem_id == graph.ecosystem_id)
                    .then_some(membership.project_unit_id.clone())
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if graph.project_unit_ids != expected_units {
            return Err(ProjectInventoryError::Invalid(format!(
                "dependency graph for {} / {} does not exactly name the semantic source-owner population",
                graph.language_id, graph.ecosystem_id
            )));
        }
        let graph_units = graph.project_unit_ids.iter().collect::<BTreeSet<_>>();
        for dependency in &graph.dependencies {
            if dependency.dependent_project_unit_id == dependency.dependency_project_unit_id {
                return Err(ProjectInventoryError::Invalid(format!(
                    "project unit {} cannot depend on itself",
                    dependency.dependent_project_unit_id
                )));
            }
            if !graph_units.contains(&dependency.dependent_project_unit_id)
                || !graph_units.contains(&dependency.dependency_project_unit_id)
            {
                return Err(ProjectInventoryError::Invalid(format!(
                    "local dependency references a unit outside its exact graph population: {} -> {}",
                    dependency.dependent_project_unit_id, dependency.dependency_project_unit_id
                )));
            }
        }
        if matches!(graph.coverage, ProjectUnitDependencyGraphCoverage::Complete)
            != graph.gaps.is_empty()
        {
            return Err(ProjectInventoryError::Invalid(
                "complete dependency coverage requires zero gaps and partial coverage requires at least one gap"
                    .into(),
            ));
        }
        for gap in &graph.gaps {
            validate_label("dependency gap reason code", &gap.reason_code)?;
            if gap.path.trim().is_empty() || gap.detail.trim().is_empty() {
                return Err(ProjectInventoryError::Invalid(
                    "dependency gap path and detail must not be empty".into(),
                ));
            }
            if gap
                .project_unit_id
                .as_ref()
                .is_some_and(|unit_id| !graph_units.contains(unit_id))
            {
                return Err(ProjectInventoryError::Invalid(
                    "dependency gap references a unit outside its exact graph population".into(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_analysis_context_graphs(
    inventory: &ProjectInventory,
) -> Result<(), ProjectInventoryError> {
    let source_documents = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
        .map(|membership| {
            (
                membership.document_path.clone(),
                membership.language_id.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut graph_keys = BTreeSet::new();

    for graph in &inventory.analysis_context_graphs {
        validate_label("analysis-context graph language ID", &graph.language_id.0)?;
        validate_label("analysis-context graph ecosystem ID", &graph.ecosystem_id.0)?;
        if !graph_keys.insert((graph.language_id.clone(), graph.ecosystem_id.clone())) {
            return Err(ProjectInventoryError::Invalid(format!(
                "analysis-context graph is duplicated for {} / {}",
                graph.language_id, graph.ecosystem_id
            )));
        }
        if !source_documents
            .iter()
            .any(|(_, language_id)| *language_id == graph.language_id)
        {
            return Err(ProjectInventoryError::Invalid(format!(
                "analysis-context graph for {} has no indexed source-owner population",
                graph.language_id
            )));
        }
        if matches!(
            graph.coverage,
            AnalysisContextCoverage::DeclaredConfigurationComplete
        ) != graph.gaps.is_empty()
        {
            return Err(ProjectInventoryError::Invalid(
                "complete analysis-context coverage requires zero gaps and partial coverage requires at least one gap"
                    .into(),
            ));
        }
        if graph.contexts.is_empty()
            && matches!(
                graph.coverage,
                AnalysisContextCoverage::DeclaredConfigurationComplete
            )
        {
            return Err(ProjectInventoryError::Invalid(
                "complete analysis-context coverage requires at least one context".into(),
            ));
        }

        reject_exact_duplicates("analysis contexts", &graph.contexts)?;
        reject_exact_duplicates("analysis-context memberships", &graph.memberships)?;
        reject_exact_duplicates("analysis-context relationships", &graph.relationships)?;
        reject_exact_duplicates("analysis-context gaps", &graph.gaps)?;

        let mut contexts = BTreeMap::new();
        for context in &graph.contexts {
            validate_label("analysis-context ID", &context.analysis_context_id.0)?;
            validate_label("analysis-context language ID", &context.language_id.0)?;
            validate_label("analysis-context ecosystem ID", &context.ecosystem_id.0)?;
            validate_label("analysis-context kind ID", &context.kind_id.0)?;
            if context.language_id != graph.language_id
                || context.ecosystem_id != graph.ecosystem_id
            {
                return Err(ProjectInventoryError::Invalid(format!(
                    "analysis context {} language or ecosystem differs from its graph",
                    context.analysis_context_id
                )));
            }
            if !context.root_path.is_empty() && !safe_relative_path(&context.root_path) {
                return Err(ProjectInventoryError::Invalid(format!(
                    "analysis-context root path is not canonical and repository-relative: {}",
                    context.root_path
                )));
            }
            if !safe_relative_path(&context.configuration_path) {
                return Err(ProjectInventoryError::Invalid(format!(
                    "analysis-context configuration path is not canonical and repository-relative: {}",
                    context.configuration_path
                )));
            }
            if contexts
                .insert(context.analysis_context_id.clone(), context)
                .is_some()
            {
                return Err(ProjectInventoryError::Invalid(
                    "analysis-context IDs must be unique within a graph".into(),
                ));
            }
        }

        for membership in &graph.memberships {
            if !safe_relative_path(&membership.document_path) {
                return Err(ProjectInventoryError::Invalid(format!(
                    "analysis-context membership document path is not canonical and repository-relative: {}",
                    membership.document_path
                )));
            }
            if membership.language_id != graph.language_id {
                return Err(ProjectInventoryError::Invalid(format!(
                    "analysis-context membership language {} differs from graph language {}",
                    membership.language_id, graph.language_id
                )));
            }
            if !contexts.contains_key(&membership.analysis_context_id) {
                return Err(ProjectInventoryError::Invalid(format!(
                    "analysis-context membership references missing analysis context {}",
                    membership.analysis_context_id
                )));
            }
            if !source_documents.contains(&(
                membership.document_path.clone(),
                membership.language_id.clone(),
            )) {
                return Err(ProjectInventoryError::Invalid(format!(
                    "analysis-context membership document is outside the indexed source-owner population: {}",
                    membership.document_path
                )));
            }
        }

        let context_ids = contexts.keys().cloned().collect::<BTreeSet<_>>();
        let mut ordered_targets =
            BTreeMap::<(AnalysisContextId, AnalysisContextRelationshipKind), Vec<usize>>::new();
        let mut target_identities = BTreeSet::new();
        for relationship in &graph.relationships {
            if relationship.source_analysis_context_id == relationship.target_analysis_context_id {
                return Err(ProjectInventoryError::Invalid(format!(
                    "analysis context {} cannot relate to itself",
                    relationship.source_analysis_context_id
                )));
            }
            if !contexts.contains_key(&relationship.source_analysis_context_id)
                || !contexts.contains_key(&relationship.target_analysis_context_id)
            {
                return Err(ProjectInventoryError::Invalid(format!(
                    "analysis-context relationship references a missing analysis context: {} -> {}",
                    relationship.source_analysis_context_id,
                    relationship.target_analysis_context_id
                )));
            }
            if !target_identities.insert((
                relationship.source_analysis_context_id.clone(),
                relationship.target_analysis_context_id.clone(),
                relationship.kind,
            )) {
                return Err(ProjectInventoryError::Invalid(
                    "analysis-context relationship repeats one target with multiple ordinals"
                        .into(),
                ));
            }
            ordered_targets
                .entry((
                    relationship.source_analysis_context_id.clone(),
                    relationship.kind,
                ))
                .or_default()
                .push(relationship.ordinal);
        }
        for ordinals in ordered_targets.values_mut() {
            ordinals.sort_unstable();
            if ordinals.iter().copied().ne(0..ordinals.len()) {
                return Err(ProjectInventoryError::Invalid(
                    "analysis-context relationship ordinals must be contiguous from zero".into(),
                ));
            }
        }
        for kind in [
            AnalysisContextRelationshipKind::ConfigurationExtends,
            AnalysisContextRelationshipKind::ProjectReferences,
        ] {
            if !cyclic_analysis_context_ids(&context_ids, &graph.relationships, kind).is_empty() {
                return Err(ProjectInventoryError::Invalid(format!(
                    "{} relationships contain a cycle",
                    analysis_context_relationship_kind_label(kind)
                )));
            }
        }

        for gap in &graph.gaps {
            validate_label("analysis-context gap reason code", &gap.reason_code)?;
            if gap.detail.trim().is_empty() {
                return Err(ProjectInventoryError::Invalid(
                    "analysis-context gap detail must not be empty".into(),
                ));
            }
            validate_analysis_context_gap_path(&gap.path)?;
            if let Some(context_id) = &gap.analysis_context_id {
                validate_label("analysis-context gap context ID", &context_id.0)?;
                if !contexts.contains_key(context_id) {
                    return Err(ProjectInventoryError::Invalid(format!(
                        "analysis-context gap references a missing analysis context {context_id}"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn validate_analysis_context_gap_path(path: &str) -> Result<(), ProjectInventoryError> {
    let is_sentinel = path.len() >= 3
        && path.starts_with('<')
        && path.ends_with('>')
        && !path[1..path.len() - 1].contains(['<', '>']);
    if !is_sentinel && !safe_relative_path(path) {
        return Err(ProjectInventoryError::Invalid(format!(
            "analysis-context gap path is not canonical: {path}"
        )));
    }
    validate_label("analysis-context gap path", path)
}

const fn analysis_context_relationship_kind_label(
    kind: AnalysisContextRelationshipKind,
) -> &'static str {
    match kind {
        AnalysisContextRelationshipKind::ConfigurationExtends => "configuration_extends",
        AnalysisContextRelationshipKind::ProjectReferences => "project_references",
    }
}

fn cyclic_analysis_context_ids(
    context_ids: &BTreeSet<AnalysisContextId>,
    relationships: &[AnalysisContextRelationship],
    kind: AnalysisContextRelationshipKind,
) -> BTreeSet<AnalysisContextId> {
    let mut remaining_parents = context_ids
        .iter()
        .cloned()
        .map(|context_id| (context_id, 0usize))
        .collect::<BTreeMap<_, _>>();
    let mut targets = BTreeMap::<AnalysisContextId, Vec<AnalysisContextId>>::new();
    for relationship in relationships
        .iter()
        .filter(|relationship| relationship.kind == kind)
    {
        let Some(remaining) = remaining_parents.get_mut(&relationship.target_analysis_context_id)
        else {
            continue;
        };
        if !context_ids.contains(&relationship.source_analysis_context_id) {
            continue;
        }
        *remaining += 1;
        targets
            .entry(relationship.source_analysis_context_id.clone())
            .or_default()
            .push(relationship.target_analysis_context_id.clone());
    }
    let mut ready = remaining_parents
        .iter()
        .filter_map(|(context_id, count)| (*count == 0).then_some(context_id.clone()))
        .collect::<BTreeSet<_>>();
    while let Some(context_id) = ready.pop_first() {
        for target in targets.get(&context_id).into_iter().flatten() {
            let remaining = remaining_parents
                .get_mut(target)
                .expect("analysis-context relationship target population");
            *remaining -= 1;
            if *remaining == 0 {
                ready.insert(target.clone());
            }
        }
        remaining_parents.remove(&context_id);
    }
    remaining_parents.into_keys().collect()
}

/// Return the bounded unit topology relevant to the named documents.
pub fn project_unit_graph(
    inventory: &ProjectInventory,
    document_paths: impl IntoIterator<Item = impl AsRef<str>>,
) -> UnitGraph {
    let documents = document_paths
        .into_iter()
        .map(|path| path.as_ref().to_owned())
        .collect::<BTreeSet<_>>();
    let memberships = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| documents.contains(&membership.document_path))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut unit_ids = memberships
        .iter()
        .map(|membership| membership.project_unit_id.clone())
        .collect::<BTreeSet<_>>();

    loop {
        let before = unit_ids.len();
        for relationship in &inventory.project_topology.relationships {
            if unit_ids.contains(&relationship.child_project_unit_id) {
                unit_ids.insert(relationship.parent_project_unit_id.clone());
            }
        }
        if unit_ids.len() == before {
            break;
        }
    }

    UnitGraph {
        coverage: match inventory.coverage {
            ProjectInventoryCoverage::IndexedSourcePopulationComplete => {
                UnitGraphCoverage::IndexedGenerationQueryProjection
            }
            ProjectInventoryCoverage::IndexedSourcePopulationPartial => {
                UnitGraphCoverage::IndexedGenerationPartialQueryProjection
            }
        },
        units: inventory
            .project_topology
            .units
            .iter()
            .filter(|unit| unit_ids.contains(&unit.project_unit_id))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        memberships,
        relationships: inventory
            .project_topology
            .relationships
            .iter()
            .filter(|relationship| {
                unit_ids.contains(&relationship.parent_project_unit_id)
                    && unit_ids.contains(&relationship.child_project_unit_id)
            })
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    }
}

fn discover_project_inputs(
    root: &Path,
    source_population: &BTreeMap<String, LanguageId>,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> BTreeSet<ProjectInput> {
    let planned = plan_project_inputs(source_population);
    observe_planned_project_inputs(root, &planned, issues)
}

fn plan_project_inputs(
    source_population: &BTreeMap<String, LanguageId>,
) -> Vec<ProjectInputCandidate> {
    #[cfg(test)]
    record_project_input_plan_build();
    // Project-input authority belongs to logical language/ecosystem owners,
    // not to every source document that happens to share it. Collect that
    // deterministic owner population first; the observer below collapses it
    // by physical path so one shared selector is statted, read, and hashed
    // exactly once before its byte witness is fanned out to those owners.
    let mut scheduled = BTreeSet::<ProjectInputCandidate>::new();
    for (document_path, language_id) in source_population {
        for directory in ancestor_directories(document_path) {
            scheduled.extend(
                crate::code_intel_project_inputs::semantic_project_input_candidates(
                    &directory,
                    language_id,
                ),
            );
        }
    }
    scheduled.into_iter().collect()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExpandedProjectInputCandidate {
    relative_path: PathBuf,
    language_id: LanguageId,
    ecosystem: &'static str,
    role: ProjectInputRole,
}

fn expand_project_input_candidates(
    root: &Path,
    scheduled: &[ProjectInputCandidate],
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> Vec<ExpandedProjectInputCandidate> {
    let mut expanded = BTreeSet::new();
    for candidate in scheduled {
        match &candidate.path {
            ProjectInputCandidatePath::Exact(relative_path) => {
                expanded.insert(ExpandedProjectInputCandidate {
                    relative_path: relative_path.clone(),
                    language_id: candidate.language_id.clone(),
                    ecosystem: candidate.ecosystem,
                    role: candidate.role,
                });
            }
            ProjectInputCandidatePath::FileNameFamily {
                directory,
                prefix,
                suffix,
            } => {
                let entries = match std::fs::read_dir(root.join(directory)) {
                    Ok(entries) => entries,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => {
                        issues.insert(ProjectInventoryIssue {
                            code: "project_input_directory_unreadable".into(),
                            path: path_label(directory),
                            detail: error.to_string(),
                        });
                        continue;
                    }
                };
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            issues.insert(ProjectInventoryIssue {
                                code: "project_input_directory_unreadable".into(),
                                path: path_label(directory),
                                detail: error.to_string(),
                            });
                            continue;
                        }
                    };
                    let name = entry.file_name();
                    let Some(name) = name.to_str() else {
                        continue;
                    };
                    if name.starts_with(prefix) && name.ends_with(suffix) {
                        expanded.insert(ExpandedProjectInputCandidate {
                            relative_path: directory.join(name),
                            language_id: candidate.language_id.clone(),
                            ecosystem: candidate.ecosystem,
                            role: candidate.role,
                        });
                    }
                }
            }
        }
    }
    expanded.into_iter().collect()
}

fn observe_planned_project_inputs(
    root: &Path,
    scheduled: &[ProjectInputCandidate],
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> BTreeSet<ProjectInput> {
    let mut inputs = BTreeSet::new();
    let mut observations = BTreeMap::new();
    for candidate in expand_project_input_candidates(root, scheduled, issues) {
        let observation = observations
            .entry(candidate.relative_path.clone())
            .or_insert_with(|| observe_project_input_file(root, &candidate.relative_path));
        capture_project_input_observation(
            observation,
            &candidate.language_id,
            candidate.ecosystem,
            candidate.role,
            &mut inputs,
            issues,
        );
    }
    inputs
}

fn observe_planned_project_inputs_parallel(
    root: &Path,
    scheduled: &[ProjectInputCandidate],
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> BTreeSet<ProjectInput> {
    let expanded = expand_project_input_candidates(root, scheduled, issues);
    let paths = expanded
        .iter()
        .map(|candidate| candidate.relative_path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let observations = paths
        .par_iter()
        .map(|relative_path| {
            (
                relative_path.clone(),
                observe_project_input_file(root, relative_path),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut inputs = BTreeSet::new();
    for candidate in expanded {
        let observation = observations
            .get(&candidate.relative_path)
            .expect("every scheduled project-input path must be observed");
        capture_project_input_observation(
            observation,
            &candidate.language_id,
            candidate.ecosystem,
            candidate.role,
            &mut inputs,
            issues,
        );
    }
    inputs
}

enum ProjectInputFileObservation {
    Missing,
    Content {
        path: String,
        content_sha256: String,
    },
    Issue(ProjectInventoryIssue),
}

fn capture_project_input_observation(
    observation: &ProjectInputFileObservation,
    language_id: &LanguageId,
    ecosystem: &str,
    role: ProjectInputRole,
    inputs: &mut BTreeSet<ProjectInput>,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) {
    match observation {
        ProjectInputFileObservation::Missing => {}
        ProjectInputFileObservation::Content {
            path,
            content_sha256,
        } => {
            inputs.insert(ProjectInput {
                path: path.clone(),
                language_id: language_id.clone(),
                ecosystem_id: EcosystemId::new(ecosystem),
                role,
                content_sha256: content_sha256.clone(),
            });
        }
        ProjectInputFileObservation::Issue(issue) => {
            issues.insert(issue.clone());
        }
    }
}

fn observe_project_input_file(root: &Path, relative_path: &Path) -> ProjectInputFileObservation {
    #[cfg(test)]
    let _flight = TestProjectInputFlightGuard::enter(root);
    let absolute = root.join(relative_path);
    let metadata = match std::fs::symlink_metadata(&absolute) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ProjectInputFileObservation::Missing;
        }
        Err(error) => {
            return ProjectInputFileObservation::Issue(ProjectInventoryIssue {
                code: "project_input_unreadable".into(),
                path: path_label(relative_path),
                detail: error.to_string(),
            });
        }
    };
    if !metadata.file_type().is_file() {
        return ProjectInputFileObservation::Issue(ProjectInventoryIssue {
            code: "project_input_unsafe".into(),
            path: path_label(relative_path),
            detail: "project inputs must be regular repository-local files".into(),
        });
    }
    let bytes = match std::fs::read(&absolute) {
        Ok(bytes) => bytes,
        Err(error) => {
            return ProjectInputFileObservation::Issue(ProjectInventoryIssue {
                code: "project_input_unreadable".into(),
                path: path_label(relative_path),
                detail: error.to_string(),
            });
        }
    };
    #[cfg(test)]
    record_project_input_file_read(root);
    ProjectInputFileObservation::Content {
        path: path_label(relative_path),
        content_sha256: sha256_hex(&bytes),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Clone)]
enum ProjectTopologyCandidate {
    Unit {
        unit: ProjectUnit,
        ownership: CandidateOwnership,
    },
    /// A present but unusable ownership-defining control blocks broader
    /// ancestors without becoming a fabricated persisted project unit.
    OwnershipBarrier { root_path: String },
}

#[derive(Debug, Clone)]
enum CandidateOwnership {
    /// The control is relevant context but cannot own source.
    Never,
    PathContained,
    CargoPackage(CargoPackageLayout),
}

impl ProjectTopologyCandidate {
    const fn unit(unit: ProjectUnit, ownership: CandidateOwnership) -> Self {
        Self::Unit { unit, ownership }
    }

    fn ownership_barrier(root_path: &Path) -> Self {
        Self::OwnershipBarrier {
            root_path: path_label(root_path),
        }
    }

    fn root_path(&self) -> &str {
        match self {
            Self::Unit { unit, .. } => &unit.root_path,
            Self::OwnershipBarrier { root_path } => root_path,
        }
    }

    fn sort_identity(&self) -> &str {
        match self {
            Self::Unit { unit, .. } => &unit.project_unit_id.0,
            Self::OwnershipBarrier { root_path } => root_path,
        }
    }

    fn barrier_root(&self) -> Option<&Path> {
        match self {
            Self::OwnershipBarrier { root_path } => Some(Path::new(root_path)),
            Self::Unit { .. } => None,
        }
    }

    const fn project_unit_id(&self) -> Option<&ProjectUnitId> {
        match self {
            Self::Unit { unit, .. } => Some(&unit.project_unit_id),
            Self::OwnershipBarrier { .. } => None,
        }
    }

    fn owns_document(&self, repository_root: &Path, document_path: &str) -> bool {
        match self {
            Self::OwnershipBarrier { .. }
            | Self::Unit {
                ownership: CandidateOwnership::Never,
                ..
            } => false,
            Self::Unit {
                unit,
                ownership: CandidateOwnership::PathContained,
            } => Path::new(document_path).starts_with(Path::new(&unit.root_path)),
            Self::Unit {
                ownership: CandidateOwnership::CargoPackage(layout),
                ..
            } => layout.owns_document(&repository_root.join(document_path)),
        }
    }

    fn into_unit(self) -> Option<ProjectUnit> {
        match self {
            Self::Unit { unit, .. } => Some(unit),
            Self::OwnershipBarrier { .. } => None,
        }
    }
}

fn discover_candidate_fragment<F, A>(
    root: &Path,
    sources: &BTreeMap<String, LanguageId>,
    mut discover_candidates: F,
    auxiliary_root: A,
) -> ProjectInventoryFragment
where
    F: FnMut(
        &str,
        &LanguageId,
        &mut BTreeSet<ProjectInventoryIssue>,
    ) -> Vec<ProjectTopologyCandidate>,
    A: Fn(&str, &LanguageId) -> Option<PathBuf>,
{
    let mut fragment = ProjectInventoryFragment::default();
    for (document_path, language_id) in sources {
        let auxiliary_root = auxiliary_root(document_path, language_id);
        let mut candidates = discover_candidates(document_path, language_id, &mut fragment.issues);
        candidates.sort_by(|left, right| {
            path_depth(right.root_path())
                .cmp(&path_depth(left.root_path()))
                .then_with(|| left.sort_identity().cmp(right.sort_identity()))
        });
        let ownership_barrier = candidates
            .iter()
            .filter_map(ProjectTopologyCandidate::barrier_root)
            .max_by_key(|root| path_depth(&path_label(root)));
        let owner = candidates
            .iter()
            .find(|candidate| {
                candidate.owns_document(root, document_path)
                    && ownership_barrier
                        .is_none_or(|barrier| Path::new(candidate.root_path()).starts_with(barrier))
                    && auxiliary_root
                        .as_ref()
                        .is_none_or(|root| Path::new(candidate.root_path()).starts_with(root))
            })
            .and_then(ProjectTopologyCandidate::project_unit_id)
            .cloned();

        if owner.is_none() {
            let fallback = auxiliary_root.as_ref().map_or_else(
                || loose_unit(language_id),
                |root| auxiliary_unit(language_id, root),
            );
            let fallback_id = fallback.project_unit_id.clone();
            fragment
                .units
                .entry(fallback_id.clone())
                .or_insert(fallback);
            fragment.memberships.insert(DocumentMembership {
                document_path: document_path.clone(),
                language_id: language_id.clone(),
                project_unit_id: fallback_id,
                kind: DocumentMembershipKind::SourceOwner,
            });
        }

        for candidate in candidates {
            let Some(unit) = candidate.into_unit() else {
                continue;
            };
            let unit_id = unit.project_unit_id.clone();
            fragment.units.entry(unit_id.clone()).or_insert(unit);
            fragment.memberships.insert(DocumentMembership {
                document_path: document_path.clone(),
                language_id: language_id.clone(),
                project_unit_id: unit_id.clone(),
                kind: if owner.as_ref() == Some(&unit_id) {
                    DocumentMembershipKind::SourceOwner
                } else {
                    DocumentMembershipKind::PathContext
                },
            });
        }
    }
    fragment
}

fn unregistered_project_inventory_fragment(
    sources: &BTreeMap<String, LanguageId>,
) -> ProjectInventoryFragment {
    let mut fragment = ProjectInventoryFragment::default();
    for (document_path, language_id) in sources {
        fragment.issues.insert(ProjectInventoryIssue {
            code: "inventory_provider_unavailable".into(),
            path: document_path.clone(),
            detail: format!(
                "no project-inventory provider is registered for language {}",
                language_id
            ),
        });
        let fallback = loose_unit(language_id);
        let fallback_id = fallback.project_unit_id.clone();
        fragment
            .units
            .entry(fallback_id.clone())
            .or_insert(fallback);
        fragment.memberships.insert(DocumentMembership {
            document_path: document_path.clone(),
            language_id: language_id.clone(),
            project_unit_id: fallback_id,
            kind: DocumentMembershipKind::SourceOwner,
        });
    }
    fragment
}

fn unavailable_dependency_graph(
    language_id: LanguageId,
    ecosystem_id: EcosystemId,
    project_unit_ids: Vec<ProjectUnitId>,
) -> ProjectUnitDependencyGraph {
    ProjectUnitDependencyGraph {
        language_id,
        ecosystem_id,
        coverage: ProjectUnitDependencyGraphCoverage::Partial,
        project_unit_ids,
        dependencies: Vec::new(),
        gaps: vec![ProjectUnitDependencyGap {
            reason_code: "dependency_inventory_provider_unavailable".into(),
            project_unit_id: None,
            path: "<project-inventory>".into(),
            detail:
                "no local project-unit dependency adapter is registered for this language and ecosystem"
                    .into(),
        }],
    }
}

impl ProjectInventoryAdapter for RustProjectInventoryAdapter {
    fn language(&self) -> &'static str {
        "rust"
    }

    fn discover(
        &self,
        root: &Path,
        sources: &BTreeMap<String, LanguageId>,
    ) -> ProjectInventoryFragment {
        let mut cache = BTreeMap::<PathBuf, Vec<ProjectTopologyCandidate>>::new();
        let mut fragment = discover_candidate_fragment(
            root,
            sources,
            |document_path, language_id, issues| {
                rust_candidates(root, document_path, language_id, issues, &mut cache)
            },
            auxiliary_source_root,
        );
        let exact_root_owners = fragment
            .memberships
            .iter()
            .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
            .map(|membership| {
                (
                    membership.document_path.clone(),
                    membership.project_unit_id.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        for unit in fragment.units.values_mut() {
            unit.compilation_root_paths.retain(|path| {
                exact_root_owners.contains(&(path.clone(), unit.project_unit_id.clone()))
            });
        }
        fragment
    }

    fn dependency_graph(
        &self,
        root: &Path,
        ecosystem_id: &EcosystemId,
        units: &BTreeMap<ProjectUnitId, ProjectUnit>,
        _relationships: &[ProjectUnitRelationship],
        _exact_workspace_member_sets: &BTreeSet<ProjectUnitId>,
        project_unit_ids: Vec<ProjectUnitId>,
    ) -> ProjectUnitDependencyGraph {
        if ecosystem_id.0 == "cargo" {
            cargo_project_unit_dependencies(root, units, project_unit_ids)
        } else {
            unavailable_dependency_graph(
                LanguageId::new(self.language()),
                ecosystem_id.clone(),
                project_unit_ids,
            )
        }
    }
}

impl ProjectInventoryAdapter for GoProjectInventoryAdapter {
    fn language(&self) -> &'static str {
        "go"
    }

    fn discover(
        &self,
        root: &Path,
        sources: &BTreeMap<String, LanguageId>,
    ) -> ProjectInventoryFragment {
        let mut cache = BTreeMap::<PathBuf, Vec<ProjectTopologyCandidate>>::new();
        discover_candidate_fragment(
            root,
            sources,
            |document_path, language_id, issues| {
                go_candidates(root, document_path, language_id, issues, &mut cache)
            },
            auxiliary_source_root,
        )
    }

    fn dependency_graph(
        &self,
        root: &Path,
        ecosystem_id: &EcosystemId,
        units: &BTreeMap<ProjectUnitId, ProjectUnit>,
        _relationships: &[ProjectUnitRelationship],
        _exact_workspace_member_sets: &BTreeSet<ProjectUnitId>,
        project_unit_ids: Vec<ProjectUnitId>,
    ) -> ProjectUnitDependencyGraph {
        if ecosystem_id.0 == "go" {
            go_project_unit_dependencies(root, units, project_unit_ids)
        } else {
            unavailable_dependency_graph(
                LanguageId::new(self.language()),
                ecosystem_id.clone(),
                project_unit_ids,
            )
        }
    }
}

impl ProjectInventoryAdapter for PythonProjectInventoryAdapter {
    fn language(&self) -> &'static str {
        "python"
    }

    fn discover(
        &self,
        root: &Path,
        sources: &BTreeMap<String, LanguageId>,
    ) -> ProjectInventoryFragment {
        let mut cache = BTreeMap::<PathBuf, PythonDirectoryDiscovery>::new();
        let mut fragment = discover_candidate_fragment(
            root,
            sources,
            |document_path, language_id, issues| {
                python_candidates(root, document_path, language_id, issues, &mut cache)
            },
            |_document_path, _language_id| None,
        );
        attach_exact_workspace_memberships(
            &mut fragment,
            cache
                .values()
                .filter_map(|discovery| discovery.workspace.as_ref())
                .collect(),
            self.language(),
            "python",
            "python_workspace_membership_ambiguous",
            "uv",
        );
        fragment
            .analysis_context_graphs
            .insert(python_analysis_context_graph(sources, &cache));
        fragment
    }

    fn dependency_graph(
        &self,
        root: &Path,
        ecosystem_id: &EcosystemId,
        units: &BTreeMap<ProjectUnitId, ProjectUnit>,
        relationships: &[ProjectUnitRelationship],
        exact_workspace_member_sets: &BTreeSet<ProjectUnitId>,
        project_unit_ids: Vec<ProjectUnitId>,
    ) -> ProjectUnitDependencyGraph {
        if ecosystem_id.0 != "python" {
            return unavailable_dependency_graph(
                LanguageId::new(self.language()),
                ecosystem_id.clone(),
                project_unit_ids,
            );
        }
        python_project_unit_dependencies(
            root,
            units,
            relationships,
            exact_workspace_member_sets,
            project_unit_ids,
        )
    }
}

impl ProjectInventoryAdapter for TypeScriptProjectInventoryAdapter {
    fn language(&self) -> &'static str {
        "typescript"
    }

    fn discover(
        &self,
        root: &Path,
        sources: &BTreeMap<String, LanguageId>,
    ) -> ProjectInventoryFragment {
        let mut cache = BTreeMap::<PathBuf, TypeScriptDirectoryDiscovery>::new();
        let mut fragment = discover_candidate_fragment(
            root,
            sources,
            |document_path, language_id, issues| {
                typescript_candidates(root, document_path, language_id, issues, &mut cache)
            },
            |_document_path, _language_id| None,
        );

        attach_exact_workspace_memberships(
            &mut fragment,
            cache
                .values()
                .filter_map(|discovery| discovery.workspace.as_ref())
                .collect(),
            self.language(),
            "node",
            "typescript_workspace_membership_ambiguous",
            "pnpm",
        );
        fragment
            .analysis_context_graphs
            .insert(typescript_analysis_context_graph(sources, &cache));
        fragment
    }

    fn dependency_graph(
        &self,
        root: &Path,
        ecosystem_id: &EcosystemId,
        units: &BTreeMap<ProjectUnitId, ProjectUnit>,
        relationships: &[ProjectUnitRelationship],
        exact_workspace_member_sets: &BTreeSet<ProjectUnitId>,
        project_unit_ids: Vec<ProjectUnitId>,
    ) -> ProjectUnitDependencyGraph {
        if ecosystem_id.0 == "node" {
            typescript_project_unit_dependencies(
                root,
                units,
                relationships,
                exact_workspace_member_sets,
                project_unit_ids,
            )
        } else {
            unavailable_dependency_graph(
                LanguageId::new(self.language()),
                ecosystem_id.clone(),
                project_unit_ids,
            )
        }
    }
}

fn rust_candidates(
    root: &Path,
    document_path: &str,
    language_id: &LanguageId,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
    cache: &mut BTreeMap<PathBuf, Vec<ProjectTopologyCandidate>>,
) -> Vec<ProjectTopologyCandidate> {
    let mut candidates = Vec::new();
    for directory in ancestor_directories(document_path) {
        let manifest_path = directory.join("Cargo.toml");
        if !cache.contains_key(&manifest_path) {
            let discovered =
                discover_rust_manifest(root, &directory, &manifest_path, language_id, issues);
            cache.insert(manifest_path.clone(), discovered);
        }
        candidates.extend(
            cache
                .get(&manifest_path)
                .expect("manifest discovery cache populated")
                .iter()
                .cloned(),
        );
    }
    candidates
}

fn discover_rust_manifest(
    root: &Path,
    directory: &Path,
    manifest_path: &Path,
    language_id: &LanguageId,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> Vec<ProjectTopologyCandidate> {
    let label = path_label(manifest_path);
    let contents = match read_project_manifest(root, manifest_path, issues) {
        ProjectManifestObservation::Missing => return Vec::new(),
        ProjectManifestObservation::Content(contents) => contents,
        ProjectManifestObservation::Unusable => {
            return vec![ProjectTopologyCandidate::ownership_barrier(directory)];
        }
    };
    let manifest = match toml::from_str::<toml::Value>(&contents) {
        Ok(manifest) => manifest,
        Err(error) => {
            issues.insert(ProjectInventoryIssue {
                code: "manifest_invalid".into(),
                path: label,
                detail: error.to_string(),
            });
            return vec![ProjectTopologyCandidate::ownership_barrier(directory)];
        }
    };
    let mut candidates = Vec::with_capacity(2);
    if manifest.get("workspace").is_some() {
        candidates.push(ProjectTopologyCandidate::unit(
            project_unit(
                language_id,
                "cargo",
                ProjectUnitKind::Workspace,
                directory,
                Some(manifest_path),
            ),
            CandidateOwnership::Never,
        ));
    }
    if manifest.get("package").is_some() {
        let layout = cargo_package_layout(&root.join(directory), &manifest);
        let compilation_root_paths = layout
            .targets()
            .iter()
            .filter_map(|target| target.source_path.strip_prefix(root).ok())
            .map(path_label)
            .filter(|path| safe_relative_path(path))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let mut unit = project_unit(
            language_id,
            "cargo",
            ProjectUnitKind::Package,
            directory,
            Some(manifest_path),
        );
        unit.compilation_root_paths = compilation_root_paths;
        candidates.push(ProjectTopologyCandidate::unit(
            unit,
            CandidateOwnership::CargoPackage(layout),
        ));
    }
    if candidates.is_empty() {
        issues.insert(ProjectInventoryIssue {
            code: "manifest_shape_unclassified".into(),
            path: label,
            detail: "Cargo.toml defines neither [workspace] nor [package]".into(),
        });
        candidates.push(ProjectTopologyCandidate::ownership_barrier(directory));
    }
    candidates
}

fn go_candidates(
    root: &Path,
    document_path: &str,
    language_id: &LanguageId,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
    cache: &mut BTreeMap<PathBuf, Vec<ProjectTopologyCandidate>>,
) -> Vec<ProjectTopologyCandidate> {
    let mut candidates = Vec::new();
    for directory in ancestor_directories(document_path) {
        for (manifest_name, kind, owner_eligible) in [
            ("go.work", ProjectUnitKind::Workspace, false),
            ("go.mod", ProjectUnitKind::Module, true),
        ] {
            let manifest_path = directory.join(manifest_name);
            if !cache.contains_key(&manifest_path) {
                let discovered = discover_go_manifest(
                    root,
                    &directory,
                    &manifest_path,
                    language_id,
                    kind,
                    owner_eligible,
                    issues,
                );
                cache.insert(manifest_path.clone(), discovered);
            }
            candidates.extend(
                cache
                    .get(&manifest_path)
                    .expect("manifest discovery cache populated")
                    .iter()
                    .cloned(),
            );
        }
    }
    candidates
}

#[allow(clippy::too_many_arguments)]
fn discover_go_manifest(
    root: &Path,
    directory: &Path,
    manifest_path: &Path,
    language_id: &LanguageId,
    kind: ProjectUnitKind,
    owner_eligible: bool,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> Vec<ProjectTopologyCandidate> {
    match read_project_manifest(root, manifest_path, issues) {
        ProjectManifestObservation::Missing => return Vec::new(),
        ProjectManifestObservation::Unusable => {
            return vec![ProjectTopologyCandidate::ownership_barrier(directory)];
        }
        ProjectManifestObservation::Content(_) => {}
    }
    vec![ProjectTopologyCandidate::unit(
        project_unit(language_id, "go", kind, directory, Some(manifest_path)),
        if owner_eligible {
            CandidateOwnership::PathContained
        } else {
            CandidateOwnership::Never
        },
    )]
}

struct PythonDirectoryDiscovery {
    candidates: Vec<ProjectTopologyCandidate>,
    workspace: Option<WorkspaceGlobSpec>,
    pyright_configuration: Option<PythonPyrightConfigurationObservation>,
    configuration_gaps: Vec<AnalysisContextGap>,
}

#[derive(Clone)]
struct PythonPyrightConfigurationObservation {
    configuration_path: String,
    root_path: PathBuf,
    document: serde_json::Map<String, serde_json::Value>,
}

fn python_candidates(
    root: &Path,
    document_path: &str,
    language_id: &LanguageId,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
    cache: &mut BTreeMap<PathBuf, PythonDirectoryDiscovery>,
) -> Vec<ProjectTopologyCandidate> {
    let mut candidates = Vec::new();
    for directory in ancestor_directories(document_path) {
        if !cache.contains_key(&directory) {
            let discovered = discover_python_directory(root, &directory, language_id, issues);
            cache.insert(directory.clone(), discovered);
        }
        candidates.extend(
            cache
                .get(&directory)
                .expect("Python directory discovery cache populated")
                .candidates
                .iter()
                .cloned(),
        );
    }
    candidates
}

fn discover_python_directory(
    root: &Path,
    directory: &Path,
    language_id: &LanguageId,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> PythonDirectoryDiscovery {
    let pyproject_path = directory.join("pyproject.toml");
    let pyproject_observation = read_project_manifest(root, &pyproject_path, issues);
    let mut parsed_pyproject = None;
    let mut workspace = None;
    let candidates = match &pyproject_observation {
        ProjectManifestObservation::Content(contents) => {
            match toml::from_str::<toml::Value>(contents) {
                Ok(manifest) => {
                    let tool = manifest.get("tool").and_then(toml::Value::as_table);
                    let uv = tool
                        .and_then(|tool| tool.get("uv"))
                        .and_then(toml::Value::as_table);
                    let uv_package_disabled = uv
                        .and_then(|uv| uv.get("package"))
                        .and_then(toml::Value::as_bool)
                        == Some(false);
                    let workspace_value = uv.and_then(|uv| uv.get("workspace"));
                    let has_package_metadata = manifest.get("project").is_some()
                        || tool.is_some_and(|tool| {
                            tool.contains_key("poetry") || tool.contains_key("pdm")
                        });
                    let mut candidates = Vec::with_capacity(2);
                    if let Some(workspace_value) = workspace_value {
                        let unit = project_unit(
                            language_id,
                            "python",
                            ProjectUnitKind::Workspace,
                            directory,
                            Some(&pyproject_path),
                        );
                        match parse_uv_workspace_spec(workspace_value, &unit) {
                            Ok(spec) => {
                                workspace = Some(spec);
                                candidates.push(ProjectTopologyCandidate::unit(
                                    unit,
                                    CandidateOwnership::Never,
                                ));
                            }
                            Err(detail) => {
                                issues.insert(ProjectInventoryIssue {
                                    code: "manifest_invalid".into(),
                                    path: path_label(&pyproject_path),
                                    detail,
                                });
                            }
                        }
                    }
                    if has_package_metadata && !uv_package_disabled {
                        candidates.push(ProjectTopologyCandidate::unit(
                            project_unit(
                                language_id,
                                "python",
                                ProjectUnitKind::Package,
                                directory,
                                Some(&pyproject_path),
                            ),
                            CandidateOwnership::PathContained,
                        ));
                    }
                    parsed_pyproject = Some(manifest);
                    candidates
                }
                Err(error) => {
                    issues.insert(ProjectInventoryIssue {
                        code: "manifest_invalid".into(),
                        path: path_label(&pyproject_path),
                        detail: error.to_string(),
                    });
                    vec![ProjectTopologyCandidate::ownership_barrier(directory)]
                }
            }
        }
        ProjectManifestObservation::Unusable => {
            vec![ProjectTopologyCandidate::ownership_barrier(directory)]
        }
        ProjectManifestObservation::Missing => {
            discover_python_fallback_candidates(root, directory, language_id, issues)
        }
    };
    let (pyright_configuration, configuration_gaps) =
        discover_python_pyright_configuration(root, directory, parsed_pyproject.as_ref(), issues);
    PythonDirectoryDiscovery {
        candidates,
        workspace,
        pyright_configuration,
        configuration_gaps,
    }
}

fn discover_python_fallback_candidates(
    root: &Path,
    directory: &Path,
    language_id: &LanguageId,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> Vec<ProjectTopologyCandidate> {
    for manifest_name in ["setup.py", "setup.cfg"] {
        let manifest_path = directory.join(manifest_name);
        match read_project_manifest(root, &manifest_path, issues) {
            ProjectManifestObservation::Content(_) => {
                return vec![ProjectTopologyCandidate::unit(
                    project_unit(
                        language_id,
                        "python",
                        ProjectUnitKind::Package,
                        directory,
                        Some(&manifest_path),
                    ),
                    CandidateOwnership::PathContained,
                )];
            }
            ProjectManifestObservation::Unusable => {
                return vec![ProjectTopologyCandidate::ownership_barrier(directory)];
            }
            ProjectManifestObservation::Missing => {}
        }
    }

    let pipfile_path = directory.join("Pipfile");
    match read_project_manifest(root, &pipfile_path, issues) {
        ProjectManifestObservation::Content(_) => return Vec::new(),
        ProjectManifestObservation::Unusable => {
            return vec![ProjectTopologyCandidate::ownership_barrier(directory)];
        }
        ProjectManifestObservation::Missing => {}
    }

    match canonical_requirements_manifest(root, directory, issues) {
        RequirementsManifestObservation::Selected | RequirementsManifestObservation::Missing => {
            Vec::new()
        }
        RequirementsManifestObservation::Unusable => {
            vec![ProjectTopologyCandidate::ownership_barrier(directory)]
        }
    }
}

fn discover_python_pyright_configuration(
    root: &Path,
    directory: &Path,
    parsed_pyproject: Option<&toml::Value>,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> (
    Option<PythonPyrightConfigurationObservation>,
    Vec<AnalysisContextGap>,
) {
    let configuration_path = directory.join("pyrightconfig.json");
    match read_project_manifest(root, &configuration_path, issues) {
        ProjectManifestObservation::Content(contents) => {
            let document = jsonc_parser::parse_to_serde_value::<serde_json::Value>(
                &contents,
                &Default::default(),
            );
            return python_pyright_configuration_from_value(
                directory,
                &configuration_path,
                document.map_err(|error| error.to_string()),
                issues,
            );
        }
        ProjectManifestObservation::Unusable => {
            return (
                None,
                vec![AnalysisContextGap {
                    reason_code: "python_pyright_configuration_unusable".into(),
                    analysis_context_id: None,
                    path: path_label(&configuration_path),
                    detail: "Pyright configuration is not a readable regular repository-local file"
                        .into(),
                }],
            );
        }
        ProjectManifestObservation::Missing => {}
    }

    let Some(pyright) = parsed_pyproject
        .and_then(|manifest| manifest.get("tool"))
        .and_then(|tool| tool.get("pyright"))
    else {
        return (None, Vec::new());
    };
    let value = serde_json::to_value(pyright).map_err(|error| error.to_string());
    python_pyright_configuration_from_value(
        directory,
        &directory.join("pyproject.toml"),
        value,
        issues,
    )
}

fn python_pyright_configuration_from_value(
    directory: &Path,
    configuration_path: &Path,
    value: Result<serde_json::Value, String>,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> (
    Option<PythonPyrightConfigurationObservation>,
    Vec<AnalysisContextGap>,
) {
    match value {
        Ok(serde_json::Value::Object(document)) => (
            Some(PythonPyrightConfigurationObservation {
                configuration_path: path_label(configuration_path),
                root_path: directory.to_path_buf(),
                document,
            }),
            Vec::new(),
        ),
        Ok(_) => {
            let detail = "Pyright configuration must be an object".to_string();
            issues.insert(ProjectInventoryIssue {
                code: "project_configuration_invalid".into(),
                path: path_label(configuration_path),
                detail: detail.clone(),
            });
            (
                None,
                vec![AnalysisContextGap {
                    reason_code: "python_pyright_configuration_invalid".into(),
                    analysis_context_id: None,
                    path: path_label(configuration_path),
                    detail,
                }],
            )
        }
        Err(detail) => {
            issues.insert(ProjectInventoryIssue {
                code: "project_configuration_invalid".into(),
                path: path_label(configuration_path),
                detail: detail.clone(),
            });
            (
                None,
                vec![AnalysisContextGap {
                    reason_code: "python_pyright_configuration_invalid".into(),
                    analysis_context_id: None,
                    path: path_label(configuration_path),
                    detail,
                }],
            )
        }
    }
}

struct ResolvedPythonPyrightConfiguration {
    contexts: Vec<AnalysisContext>,
    default_context_id: AnalysisContextId,
    execution_environments: Vec<(PathBuf, AnalysisContextId)>,
    include: Vec<RepositoryRootSelector>,
    exclude: Vec<RepositoryRootSelector>,
    configuration_root: PathBuf,
}

fn python_analysis_context_graph(
    sources: &BTreeMap<String, LanguageId>,
    cache: &BTreeMap<PathBuf, PythonDirectoryDiscovery>,
) -> AnalysisContextGraph {
    let configurations = cache
        .values()
        .filter_map(|discovery| discovery.pyright_configuration.as_ref())
        .map(|configuration| (configuration.configuration_path.clone(), configuration))
        .collect::<BTreeMap<_, _>>();
    let mut gaps = cache
        .values()
        .flat_map(|discovery| discovery.configuration_gaps.iter().cloned())
        .collect::<BTreeSet<_>>();
    if configurations.is_empty() && gaps.is_empty() {
        gaps.insert(AnalysisContextGap {
            reason_code: "python_analysis_context_resolution_unavailable".into(),
            analysis_context_id: None,
            path: "<python-analysis-context>".into(),
            detail: "Python package controls do not by themselves prove one exact interpreter, import-root, or module-resolution context"
                .into(),
        });
    }

    let mut contexts = BTreeSet::new();
    let mut memberships = BTreeSet::new();
    for configuration in configurations.values() {
        let resolved = match resolve_python_pyright_configuration(configuration) {
            Ok(resolved) => resolved,
            Err((reason_code, detail)) => {
                gaps.insert(AnalysisContextGap {
                    reason_code,
                    analysis_context_id: None,
                    path: configuration.configuration_path.clone(),
                    detail,
                });
                continue;
            }
        };
        contexts.extend(resolved.contexts.iter().cloned());
        for (document_path, language_id) in sources {
            match python_pyright_selection_contains(&resolved, document_path) {
                Ok(false) => {}
                Ok(true) => {
                    let analysis_context_id = resolved
                        .execution_environments
                        .iter()
                        .find(|(root, _)| Path::new(document_path).starts_with(root))
                        .map_or_else(
                            || resolved.default_context_id.clone(),
                            |(_, context_id)| context_id.clone(),
                        );
                    memberships.insert(AnalysisContextMembership {
                        document_path: document_path.clone(),
                        language_id: language_id.clone(),
                        analysis_context_id,
                        kind: AnalysisContextMembershipKind::DeclaredRoot,
                    });
                }
                Err(detail) => {
                    gaps.insert(AnalysisContextGap {
                        reason_code: "python_pyright_root_selection_invalid".into(),
                        analysis_context_id: None,
                        path: configuration.configuration_path.clone(),
                        detail,
                    });
                    break;
                }
            }
        }
    }

    let gaps = gaps.into_iter().collect::<Vec<_>>();
    AnalysisContextGraph {
        language_id: LanguageId::new("python"),
        ecosystem_id: EcosystemId::new("python"),
        coverage: if gaps.is_empty() {
            AnalysisContextCoverage::DeclaredConfigurationComplete
        } else {
            AnalysisContextCoverage::DeclaredConfigurationPartial
        },
        contexts: contexts.into_iter().collect(),
        memberships: memberships.into_iter().collect(),
        relationships: Vec::new(),
        gaps,
    }
}

fn resolve_python_pyright_configuration(
    configuration: &PythonPyrightConfigurationObservation,
) -> Result<ResolvedPythonPyrightConfiguration, (String, String)> {
    if configuration.document.contains_key("extends") {
        return Err((
            "python_pyright_configuration_extends_unresolved".into(),
            "Pyright configuration inheritance must be resolved before declared roots can be authoritative"
                .into(),
        ));
    }
    let include = python_pyright_path_array(configuration, "include")?.unwrap_or_else(|| {
        vec![RepositoryRootSelector {
            origin: configuration.root_path.clone(),
            value: "**/*".into(),
        }]
    });
    let exclude = python_pyright_path_array(configuration, "exclude")?.unwrap_or_default();

    let default_context =
        python_pyright_analysis_context(configuration, None, &configuration.root_path);
    let mut contexts = vec![default_context.clone()];
    let mut execution_environments = Vec::new();
    if let Some(value) = configuration.document.get("executionEnvironments") {
        let environments = value.as_array().ok_or_else(|| {
            (
                "python_pyright_execution_environments_invalid".into(),
                "Pyright executionEnvironments must be an array".into(),
            )
        })?;
        for (ordinal, environment) in environments.iter().enumerate() {
            let environment = environment.as_object().ok_or_else(|| {
                (
                    "python_pyright_execution_environments_invalid".into(),
                    format!("Pyright execution environment {ordinal} must be an object"),
                )
            })?;
            let root = environment
                .get("root")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    (
                        "python_pyright_execution_environments_invalid".into(),
                        format!("Pyright execution environment {ordinal} requires a string root"),
                    )
                })?;
            let root = normalize_repository_relative_join(&configuration.root_path, root).map_err(
                |detail| {
                    (
                        "python_pyright_execution_environments_invalid".into(),
                        detail,
                    )
                },
            )?;
            let context = python_pyright_analysis_context(configuration, Some(ordinal), &root);
            execution_environments.push((root, context.analysis_context_id.clone()));
            contexts.push(context);
        }
    }

    Ok(ResolvedPythonPyrightConfiguration {
        contexts,
        default_context_id: default_context.analysis_context_id,
        execution_environments,
        include,
        exclude,
        configuration_root: configuration.root_path.clone(),
    })
}

fn python_pyright_analysis_context(
    configuration: &PythonPyrightConfigurationObservation,
    ordinal: Option<usize>,
    root: &Path,
) -> AnalysisContext {
    let discriminator = ordinal.map_or_else(
        || "default".to_string(),
        |ordinal| format!("environment-{ordinal}"),
    );
    AnalysisContext {
        analysis_context_id: AnalysisContextId::new(format!(
            "python:python:python_execution_environment:{}:{discriminator}:{}",
            configuration.configuration_path,
            path_label(root)
        )),
        language_id: LanguageId::new("python"),
        ecosystem_id: EcosystemId::new("python"),
        kind_id: AnalysisContextKindId::new("python_execution_environment"),
        root_path: path_label(root),
        configuration_path: configuration.configuration_path.clone(),
    }
}

fn python_pyright_path_array(
    configuration: &PythonPyrightConfigurationObservation,
    field: &str,
) -> Result<Option<Vec<RepositoryRootSelector>>, (String, String)> {
    let Some(value) = configuration.document.get(field) else {
        return Ok(None);
    };
    let values = value.as_array().ok_or_else(|| {
        (
            "python_pyright_root_selection_invalid".into(),
            format!("Pyright {field} must be an array of strings"),
        )
    })?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(|value| RepositoryRootSelector {
                    origin: configuration.root_path.clone(),
                    value: value.to_string(),
                })
                .ok_or_else(|| {
                    (
                        "python_pyright_root_selection_invalid".into(),
                        format!("Pyright {field} must contain only strings"),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn python_pyright_selection_contains(
    configuration: &ResolvedPythonPyrightConfiguration,
    document_path: &str,
) -> Result<bool, String> {
    let included = configuration
        .include
        .iter()
        .map(|selector| repository_pattern_matches(selector, document_path, "Pyright include"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .any(|matched| matched);
    if !included
        || python_pyright_default_excluded(&configuration.configuration_root, document_path)
    {
        return Ok(false);
    }
    let excluded = configuration
        .exclude
        .iter()
        .map(|selector| repository_pattern_matches(selector, document_path, "Pyright exclude"))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .any(|matched| matched);
    Ok(!excluded)
}

fn python_pyright_default_excluded(configuration_root: &Path, document_path: &str) -> bool {
    let path = Path::new(document_path)
        .strip_prefix(configuration_root)
        .unwrap_or_else(|_| Path::new(document_path));
    path.components().any(|component| {
        matches!(component, Component::Normal(name) if {
            let name = name.to_string_lossy();
            name == "node_modules" || name == "__pycache__" || name.starts_with('.')
        })
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ProjectManifestObservation {
    Missing,
    Content(String),
    Unusable,
}

fn read_project_manifest(
    root: &Path,
    manifest_path: &Path,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> ProjectManifestObservation {
    let absolute = root.join(manifest_path);
    match std::fs::symlink_metadata(&absolute) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => {
            issues.insert(ProjectInventoryIssue {
                code: "manifest_unsafe".into(),
                path: path_label(manifest_path),
                detail: "project controls must be regular repository-local files".into(),
            });
            return ProjectManifestObservation::Unusable;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ProjectManifestObservation::Missing;
        }
        Err(error) => {
            issues.insert(ProjectInventoryIssue {
                code: "manifest_unreadable".into(),
                path: path_label(manifest_path),
                detail: error.to_string(),
            });
            return ProjectManifestObservation::Unusable;
        }
    }
    match std::fs::read_to_string(&absolute) {
        Ok(contents) => {
            #[cfg(test)]
            record_project_manifest_file_read();
            ProjectManifestObservation::Content(contents)
        }
        Err(error) => {
            issues.insert(ProjectInventoryIssue {
                code: "manifest_unreadable".into(),
                path: path_label(manifest_path),
                detail: error.to_string(),
            });
            ProjectManifestObservation::Unusable
        }
    }
}

enum RequirementsManifestObservation {
    Missing,
    Selected,
    Unusable,
}

fn canonical_requirements_manifest(
    root: &Path,
    directory: &Path,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> RequirementsManifestObservation {
    let entries = match std::fs::read_dir(root.join(directory)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RequirementsManifestObservation::Missing;
        }
        Err(error) => {
            issues.insert(ProjectInventoryIssue {
                code: "manifest_directory_unreadable".into(),
                path: path_label(directory),
                detail: error.to_string(),
            });
            return RequirementsManifestObservation::Unusable;
        }
    };
    let mut candidates = Vec::new();
    let mut unusable = false;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                issues.insert(ProjectInventoryIssue {
                    code: "manifest_directory_unreadable".into(),
                    path: path_label(directory),
                    detail: error.to_string(),
                });
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with("requirements") && name.ends_with(".txt") {
            let path = directory.join(name);
            match read_project_manifest(root, &path, issues) {
                ProjectManifestObservation::Content(_) => candidates.push(path),
                ProjectManifestObservation::Unusable => unusable = true,
                ProjectManifestObservation::Missing => {
                    issues.insert(ProjectInventoryIssue {
                        code: "manifest_changed_during_observation".into(),
                        path: path_label(&path),
                        detail: "requirements control disappeared during inventory observation"
                            .into(),
                    });
                    unusable = true;
                }
            }
        }
    }
    if unusable {
        return RequirementsManifestObservation::Unusable;
    }
    candidates.sort_by(|left, right| {
        let left_primary =
            left.file_name().and_then(|name| name.to_str()) == Some("requirements.txt");
        let right_primary =
            right.file_name().and_then(|name| name.to_str()) == Some("requirements.txt");
        right_primary
            .cmp(&left_primary)
            .then_with(|| left.cmp(right))
    });
    candidates
        .into_iter()
        .next()
        .map_or(RequirementsManifestObservation::Missing, |_| {
            RequirementsManifestObservation::Selected
        })
}

#[derive(Deserialize)]
struct PnpmWorkspaceManifest {
    #[serde(default)]
    packages: Vec<String>,
}

#[derive(Deserialize)]
struct UvWorkspaceManifest {
    members: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}

struct WorkspaceGlobSpec {
    project_unit_id: ProjectUnitId,
    root_path: PathBuf,
    include: Vec<GlobMatcher>,
    exclude: Vec<GlobMatcher>,
}

impl WorkspaceGlobSpec {
    fn includes_package(&self, package_root: &Path) -> bool {
        if package_root == self.root_path {
            // Both pnpm and uv include the root package when one exists.
            return true;
        }
        let Ok(relative) = package_root.strip_prefix(&self.root_path) else {
            return false;
        };
        !relative.as_os_str().is_empty()
            && self
                .include
                .iter()
                .any(|pattern| pattern.is_match(relative))
            && !self
                .exclude
                .iter()
                .any(|pattern| pattern.is_match(relative))
    }
}

fn attach_exact_workspace_memberships(
    fragment: &mut ProjectInventoryFragment,
    workspace_specs: Vec<&WorkspaceGlobSpec>,
    language: &str,
    ecosystem: &str,
    ambiguity_code: &str,
    workspace_kind: &str,
) {
    fragment.exact_workspace_member_sets.extend(
        workspace_specs
            .iter()
            .map(|workspace| workspace.project_unit_id.clone()),
    );
    let packages = fragment
        .units
        .values()
        .filter(|unit| {
            unit.language_id.0 == language
                && unit.ecosystem_id.0 == ecosystem
                && unit.kind == ProjectUnitKind::Package
        })
        .cloned()
        .collect::<Vec<_>>();
    for package in packages {
        let memberships = workspace_specs
            .iter()
            .filter(|workspace| workspace.includes_package(Path::new(&package.root_path)))
            .collect::<Vec<_>>();
        if memberships.len() > 1 {
            fragment.issues.insert(ProjectInventoryIssue {
                code: ambiguity_code.into(),
                path: package
                    .manifest_path
                    .clone()
                    .unwrap_or_else(|| package.root_path.clone()),
                detail: format!(
                    "package matches {} nested {workspace_kind} workspaces; exact execution ownership is ambiguous",
                    memberships.len()
                ),
            });
        }
        // Preserve every declaration even in the ambiguous case. Downstream
        // root resolution sees multiple exact memberships and safely retains
        // the package root; deleting the edges would erase why it refused.
        for workspace in memberships {
            fragment.relationships.insert(ProjectUnitRelationship {
                parent_project_unit_id: workspace.project_unit_id.clone(),
                child_project_unit_id: package.project_unit_id.clone(),
                kind: ProjectUnitRelationshipKind::WorkspaceMember,
            });
        }
    }
}

struct TypeScriptDirectoryDiscovery {
    candidates: Vec<ProjectTopologyCandidate>,
    workspace: Option<WorkspaceGlobSpec>,
    configurations: Vec<TypeScriptConfigurationObservation>,
    configuration_gaps: Vec<AnalysisContextGap>,
}

#[derive(Clone)]
struct TypeScriptConfigurationObservation {
    context: AnalysisContext,
    document: serde_json::Map<String, serde_json::Value>,
}

fn typescript_candidates(
    root: &Path,
    document_path: &str,
    language_id: &LanguageId,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
    cache: &mut BTreeMap<PathBuf, TypeScriptDirectoryDiscovery>,
) -> Vec<ProjectTopologyCandidate> {
    let mut candidates = Vec::new();
    for directory in ancestor_directories(document_path) {
        if !cache.contains_key(&directory) {
            let discovered = discover_typescript_directory(root, &directory, language_id, issues);
            cache.insert(directory.clone(), discovered);
        }
        candidates.extend(
            cache
                .get(&directory)
                .expect("TypeScript directory discovery cache populated")
                .candidates
                .iter()
                .cloned(),
        );
    }
    candidates
}

fn discover_typescript_directory(
    root: &Path,
    directory: &Path,
    language_id: &LanguageId,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> TypeScriptDirectoryDiscovery {
    let mut candidates = Vec::new();
    let mut workspace = None;

    let workspace_path = directory.join("pnpm-workspace.yaml");
    match read_project_manifest(root, &workspace_path, issues) {
        ProjectManifestObservation::Content(contents) => {
            let unit = project_unit(
                language_id,
                "node",
                ProjectUnitKind::Workspace,
                directory,
                Some(&workspace_path),
            );
            match parse_pnpm_workspace_spec(&contents, &unit) {
                Ok(spec) => {
                    workspace = Some(spec);
                    candidates.push(ProjectTopologyCandidate::unit(
                        unit,
                        CandidateOwnership::Never,
                    ));
                }
                Err(detail) => {
                    issues.insert(ProjectInventoryIssue {
                        code: "manifest_invalid".into(),
                        path: path_label(&workspace_path),
                        detail,
                    });
                }
            }
        }
        ProjectManifestObservation::Unusable => {}
        ProjectManifestObservation::Missing => {}
    }

    let package_path = directory.join("package.json");
    match read_project_manifest(root, &package_path, issues) {
        ProjectManifestObservation::Content(contents) => {
            match serde_json::from_str::<serde_json::Value>(&contents) {
                Ok(serde_json::Value::Object(package))
                    if package.get("name").is_none_or(serde_json::Value::is_string) =>
                {
                    candidates.push(ProjectTopologyCandidate::unit(
                        project_unit(
                            language_id,
                            "node",
                            ProjectUnitKind::Package,
                            directory,
                            Some(&package_path),
                        ),
                        CandidateOwnership::PathContained,
                    ));
                }
                Ok(_) => {
                    issues.insert(ProjectInventoryIssue {
                        code: "manifest_invalid".into(),
                        path: path_label(&package_path),
                        detail: "package.json must be an object and name, when present, must be a string"
                            .into(),
                    });
                    candidates.push(ProjectTopologyCandidate::ownership_barrier(directory));
                }
                Err(error) => {
                    issues.insert(ProjectInventoryIssue {
                        code: "manifest_invalid".into(),
                        path: path_label(&package_path),
                        detail: error.to_string(),
                    });
                    candidates.push(ProjectTopologyCandidate::ownership_barrier(directory));
                }
            }
        }
        ProjectManifestObservation::Unusable => {
            candidates.push(ProjectTopologyCandidate::ownership_barrier(directory));
        }
        ProjectManifestObservation::Missing => {}
    }

    let (configurations, configuration_gaps) =
        discover_typescript_configurations(root, directory, language_id, issues);
    TypeScriptDirectoryDiscovery {
        candidates,
        workspace,
        configurations,
        configuration_gaps,
    }
}

fn discover_typescript_configurations(
    root: &Path,
    directory: &Path,
    language_id: &LanguageId,
    issues: &mut BTreeSet<ProjectInventoryIssue>,
) -> (
    Vec<TypeScriptConfigurationObservation>,
    Vec<AnalysisContextGap>,
) {
    let entries = match std::fs::read_dir(root.join(directory)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (Vec::new(), Vec::new());
        }
        Err(error) => {
            issues.insert(ProjectInventoryIssue {
                code: "project_configuration_directory_unreadable".into(),
                path: path_label(directory),
                detail: error.to_string(),
            });
            return (
                Vec::new(),
                vec![AnalysisContextGap {
                    reason_code: "typescript_configuration_directory_unreadable".into(),
                    analysis_context_id: None,
                    path: path_label(directory),
                    detail: error.to_string(),
                }],
            );
        }
    };
    let mut configurations = Vec::new();
    let mut gaps = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                issues.insert(ProjectInventoryIssue {
                    code: "project_configuration_directory_unreadable".into(),
                    path: path_label(directory),
                    detail: error.to_string(),
                });
                gaps.push(AnalysisContextGap {
                    reason_code: "typescript_configuration_directory_unreadable".into(),
                    analysis_context_id: None,
                    path: path_label(directory),
                    detail: error.to_string(),
                });
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !is_typescript_configuration_name(name) {
            continue;
        }
        let configuration_path = directory.join(name);
        let context = typescript_analysis_context(directory, &configuration_path, language_id);
        match read_project_manifest(root, &configuration_path, issues) {
            ProjectManifestObservation::Content(contents) => {
                match jsonc_parser::parse_to_serde_value::<serde_json::Value>(
                    &contents,
                    &Default::default(),
                ) {
                    Ok(serde_json::Value::Object(document)) => {
                        configurations
                            .push(TypeScriptConfigurationObservation { context, document });
                    }
                    Ok(_) => {
                        let detail = "TypeScript configuration must be a JSONC object".to_string();
                        issues.insert(ProjectInventoryIssue {
                            code: "project_configuration_invalid".into(),
                            path: path_label(&configuration_path),
                            detail: detail.clone(),
                        });
                        gaps.push(AnalysisContextGap {
                            reason_code: "typescript_configuration_invalid".into(),
                            analysis_context_id: None,
                            path: path_label(&configuration_path),
                            detail,
                        });
                    }
                    Err(error) => {
                        let detail = error.to_string();
                        issues.insert(ProjectInventoryIssue {
                            code: "project_configuration_invalid".into(),
                            path: path_label(&configuration_path),
                            detail: detail.clone(),
                        });
                        gaps.push(AnalysisContextGap {
                            reason_code: "typescript_configuration_invalid".into(),
                            analysis_context_id: None,
                            path: path_label(&configuration_path),
                            detail,
                        });
                    }
                }
            }
            ProjectManifestObservation::Missing => {
                let detail =
                    "TypeScript configuration disappeared during inventory observation".to_string();
                issues.insert(ProjectInventoryIssue {
                    code: "project_configuration_changed_during_observation".into(),
                    path: path_label(&configuration_path),
                    detail: detail.clone(),
                });
                gaps.push(AnalysisContextGap {
                    reason_code: "typescript_configuration_changed_during_observation".into(),
                    analysis_context_id: None,
                    path: path_label(&configuration_path),
                    detail,
                });
            }
            ProjectManifestObservation::Unusable => {
                gaps.push(AnalysisContextGap {
                    reason_code: "typescript_configuration_unusable".into(),
                    analysis_context_id: None,
                    path: path_label(&configuration_path),
                    detail:
                        "TypeScript configuration is not a readable regular repository-local file"
                            .into(),
                });
            }
        }
    }
    configurations.sort_by(|left, right| {
        left.context
            .analysis_context_id
            .cmp(&right.context.analysis_context_id)
    });
    gaps.sort();
    (configurations, gaps)
}

fn typescript_analysis_context(
    directory: &Path,
    configuration_path: &Path,
    language_id: &LanguageId,
) -> AnalysisContext {
    let configuration_label = path_label(configuration_path);
    AnalysisContext {
        analysis_context_id: AnalysisContextId::new(format!(
            "{}:node:compiler_project:{configuration_label}",
            language_id.0
        )),
        language_id: language_id.clone(),
        ecosystem_id: EcosystemId::new("node"),
        kind_id: AnalysisContextKindId::new("compiler_project"),
        root_path: path_label(directory),
        configuration_path: configuration_label,
    }
}

#[derive(Clone, Default)]
struct TypeScriptRootSelection {
    files: Option<Vec<RepositoryRootSelector>>,
    include: Option<Vec<RepositoryRootSelector>>,
    exclude: Option<Vec<RepositoryRootSelector>>,
    allow_js: Option<bool>,
    out_dir: Option<RepositoryRootSelector>,
    declaration_dir: Option<RepositoryRootSelector>,
}

impl TypeScriptRootSelection {
    fn overlay(&mut self, other: Self) {
        if other.files.is_some() {
            self.files = other.files;
        }
        if other.include.is_some() {
            self.include = other.include;
        }
        if other.exclude.is_some() {
            self.exclude = other.exclude;
        }
        if other.allow_js.is_some() {
            self.allow_js = other.allow_js;
        }
        if other.out_dir.is_some() {
            self.out_dir = other.out_dir;
        }
        if other.declaration_dir.is_some() {
            self.declaration_dir = other.declaration_dir;
        }
    }
}

#[derive(Clone)]
struct RepositoryRootSelector {
    origin: PathBuf,
    value: String,
}

fn typescript_analysis_context_graph(
    sources: &BTreeMap<String, LanguageId>,
    cache: &BTreeMap<PathBuf, TypeScriptDirectoryDiscovery>,
) -> AnalysisContextGraph {
    let configurations = cache
        .values()
        .flat_map(|discovery| discovery.configurations.iter())
        .map(|configuration| {
            (
                configuration.context.configuration_path.clone(),
                configuration,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut gaps = cache
        .values()
        .flat_map(|discovery| discovery.configuration_gaps.iter().cloned())
        .collect::<BTreeSet<_>>();
    if configurations.is_empty() {
        gaps.insert(AnalysisContextGap {
            reason_code: "typescript_analysis_context_unconfigured".into(),
            analysis_context_id: None,
            path: "<typescript-analysis-context>".into(),
            detail: "indexed TypeScript source has no readable repository-declared tsconfig/jsconfig context"
                .into(),
        });
    }

    let mut invalid_contexts = BTreeSet::new();
    let mut extends = BTreeMap::<String, Vec<String>>::new();
    let mut relationships = BTreeSet::new();
    for (configuration_path, configuration) in &configurations {
        match typescript_configuration_targets(configuration, "extends", &configurations) {
            Ok(targets) => {
                for (ordinal, target_path) in targets.iter().enumerate() {
                    let target = configurations
                        .get(target_path)
                        .expect("resolved TypeScript context target");
                    relationships.insert(AnalysisContextRelationship {
                        source_analysis_context_id: configuration
                            .context
                            .analysis_context_id
                            .clone(),
                        target_analysis_context_id: target.context.analysis_context_id.clone(),
                        kind: AnalysisContextRelationshipKind::ConfigurationExtends,
                        ordinal,
                    });
                }
                extends.insert(configuration_path.clone(), targets);
            }
            Err(detail) => {
                invalid_contexts.insert(configuration_path.clone());
                gaps.insert(AnalysisContextGap {
                    reason_code: "typescript_configuration_extends_unresolved".into(),
                    analysis_context_id: Some(configuration.context.analysis_context_id.clone()),
                    path: configuration_path.clone(),
                    detail,
                });
            }
        }
        match typescript_configuration_targets(configuration, "references", &configurations) {
            Ok(targets) => {
                for (ordinal, target_path) in targets.iter().enumerate() {
                    let target = configurations
                        .get(target_path)
                        .expect("resolved TypeScript project reference");
                    relationships.insert(AnalysisContextRelationship {
                        source_analysis_context_id: configuration
                            .context
                            .analysis_context_id
                            .clone(),
                        target_analysis_context_id: target.context.analysis_context_id.clone(),
                        kind: AnalysisContextRelationshipKind::ProjectReferences,
                        ordinal,
                    });
                }
            }
            Err(detail) => {
                invalid_contexts.insert(configuration_path.clone());
                gaps.insert(AnalysisContextGap {
                    reason_code: "typescript_project_reference_unresolved".into(),
                    analysis_context_id: Some(configuration.context.analysis_context_id.clone()),
                    path: configuration_path.clone(),
                    detail,
                });
            }
        }
    }

    let context_ids = configurations
        .values()
        .map(|configuration| configuration.context.analysis_context_id.clone())
        .collect::<BTreeSet<_>>();
    let configuration_paths = configurations
        .iter()
        .map(|(path, configuration)| {
            (
                configuration.context.analysis_context_id.clone(),
                path.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let declared_relationships = relationships.iter().cloned().collect::<Vec<_>>();
    for kind in [
        AnalysisContextRelationshipKind::ConfigurationExtends,
        AnalysisContextRelationshipKind::ProjectReferences,
    ] {
        for context_id in cyclic_analysis_context_ids(&context_ids, &declared_relationships, kind) {
            let configuration_path = configuration_paths
                .get(&context_id)
                .expect("cyclic context belongs to the discovered configuration population");
            invalid_contexts.insert(configuration_path.clone());
            gaps.insert(AnalysisContextGap {
                reason_code: format!(
                    "typescript_{}_cycle",
                    analysis_context_relationship_kind_label(kind)
                ),
                analysis_context_id: Some(context_id),
                path: configuration_path.clone(),
                detail: format!(
                    "TypeScript {} declarations contain a cycle",
                    analysis_context_relationship_kind_label(kind)
                ),
            });
        }
    }

    let mut memberships = BTreeSet::new();
    let mut selection_cache = BTreeMap::new();
    for (configuration_path, configuration) in &configurations {
        if invalid_contexts.contains(configuration_path) {
            continue;
        }
        let mut visiting = BTreeSet::new();
        let selection = match effective_typescript_root_selection(
            configuration_path,
            &configurations,
            &extends,
            &mut selection_cache,
            &mut visiting,
        ) {
            Ok(selection) => selection,
            Err(detail) => {
                gaps.insert(AnalysisContextGap {
                    reason_code: "typescript_root_selection_invalid".into(),
                    analysis_context_id: Some(configuration.context.analysis_context_id.clone()),
                    path: configuration_path.clone(),
                    detail,
                });
                continue;
            }
        };
        let mut selected = Vec::new();
        let mut selection_error = None;
        for (document_path, language_id) in sources {
            match typescript_selection_contains(&selection, &configuration.context, document_path) {
                Ok(true) => selected.push(AnalysisContextMembership {
                    document_path: document_path.clone(),
                    language_id: language_id.clone(),
                    analysis_context_id: configuration.context.analysis_context_id.clone(),
                    kind: AnalysisContextMembershipKind::DeclaredRoot,
                }),
                Ok(false) => {}
                Err(error) => {
                    selection_error = Some(error);
                    break;
                }
            }
        }
        if let Some(detail) = selection_error {
            gaps.insert(AnalysisContextGap {
                reason_code: "typescript_root_selection_invalid".into(),
                analysis_context_id: Some(configuration.context.analysis_context_id.clone()),
                path: configuration_path.clone(),
                detail,
            });
        } else {
            memberships.extend(selected);
        }
    }

    let invalid_context_ids = invalid_contexts
        .iter()
        .filter_map(|configuration_path| configurations.get(configuration_path))
        .map(|configuration| configuration.context.analysis_context_id.clone())
        .collect::<BTreeSet<_>>();
    relationships.retain(|relationship| {
        !invalid_context_ids.contains(&relationship.source_analysis_context_id)
            && !invalid_context_ids.contains(&relationship.target_analysis_context_id)
    });

    let gaps = gaps.into_iter().collect::<Vec<_>>();
    AnalysisContextGraph {
        language_id: LanguageId::new("typescript"),
        ecosystem_id: EcosystemId::new("node"),
        coverage: if gaps.is_empty() {
            AnalysisContextCoverage::DeclaredConfigurationComplete
        } else {
            AnalysisContextCoverage::DeclaredConfigurationPartial
        },
        contexts: configurations
            .values()
            .map(|configuration| configuration.context.clone())
            .collect(),
        memberships: memberships.into_iter().collect(),
        relationships: relationships.into_iter().collect(),
        gaps,
    }
}

fn typescript_configuration_targets(
    configuration: &TypeScriptConfigurationObservation,
    field: &str,
    configurations: &BTreeMap<String, &TypeScriptConfigurationObservation>,
) -> Result<Vec<String>, String> {
    let Some(value) = configuration.document.get(field) else {
        return Ok(Vec::new());
    };
    let raw_targets = if field == "extends" {
        match value {
            serde_json::Value::String(target) => vec![target.as_str()],
            serde_json::Value::Array(targets) => targets
                .iter()
                .map(|target| {
                    target
                        .as_str()
                        .ok_or_else(|| "TypeScript extends entries must be strings".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("TypeScript extends must be a string or string array".into()),
        }
    } else {
        let references = value
            .as_array()
            .ok_or_else(|| "TypeScript references must be an array".to_string())?;
        references
            .iter()
            .map(|reference| {
                reference
                    .as_object()
                    .and_then(|reference| reference.get("path"))
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        "TypeScript reference entries must contain one string path".to_string()
                    })
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    raw_targets
        .into_iter()
        .map(|raw_target| {
            resolve_typescript_configuration_reference(
                &configuration.context.root_path,
                raw_target,
                configurations,
            )
            .ok_or_else(|| {
                format!(
                    "repository-local TypeScript {field} target {raw_target:?} could not be resolved exactly"
                )
            })
        })
        .collect()
}

fn resolve_typescript_configuration_reference(
    context_root: &str,
    raw_target: &str,
    configurations: &BTreeMap<String, &TypeScriptConfigurationObservation>,
) -> Option<String> {
    let joined = normalize_repository_relative_join(Path::new(context_root), raw_target).ok()?;
    let mut candidates = Vec::new();
    let joined_label = path_label(&joined);
    if joined_label.ends_with(".json") {
        candidates.push(joined);
    } else {
        candidates.push(PathBuf::from(format!("{joined_label}.json")));
        candidates.push(joined.join("tsconfig.json"));
        candidates.push(joined.join("jsconfig.json"));
    }
    candidates
        .into_iter()
        .map(|candidate| path_label(&candidate))
        .find(|candidate| configurations.contains_key(candidate))
}

fn effective_typescript_root_selection(
    configuration_path: &str,
    configurations: &BTreeMap<String, &TypeScriptConfigurationObservation>,
    extends: &BTreeMap<String, Vec<String>>,
    memo: &mut BTreeMap<String, TypeScriptRootSelection>,
    visiting: &mut BTreeSet<String>,
) -> Result<TypeScriptRootSelection, String> {
    if let Some(selection) = memo.get(configuration_path) {
        return Ok(selection.clone());
    }
    if !visiting.insert(configuration_path.to_string()) {
        return Err(format!(
            "TypeScript configuration inheritance contains a cycle at {configuration_path}"
        ));
    }
    let configuration = configurations
        .get(configuration_path)
        .ok_or_else(|| format!("missing TypeScript configuration {configuration_path}"))?;
    let mut selection = TypeScriptRootSelection::default();
    for target in extends.get(configuration_path).into_iter().flatten() {
        selection.overlay(effective_typescript_root_selection(
            target,
            configurations,
            extends,
            memo,
            visiting,
        )?);
    }
    selection.overlay(typescript_own_root_selection(configuration)?);
    visiting.remove(configuration_path);
    memo.insert(configuration_path.to_string(), selection.clone());
    Ok(selection)
}

fn typescript_own_root_selection(
    configuration: &TypeScriptConfigurationObservation,
) -> Result<TypeScriptRootSelection, String> {
    let origin = PathBuf::from(&configuration.context.root_path);
    let string_array = |field: &str| -> Result<Option<Vec<RepositoryRootSelector>>, String> {
        let Some(value) = configuration.document.get(field) else {
            return Ok(None);
        };
        let values = value
            .as_array()
            .ok_or_else(|| format!("TypeScript {field} must be a string array"))?;
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(|value| RepositoryRootSelector {
                        origin: origin.clone(),
                        value: value.to_string(),
                    })
                    .ok_or_else(|| format!("TypeScript {field} entries must be strings"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    };
    let compiler_options = match configuration.document.get("compilerOptions") {
        None => None,
        Some(serde_json::Value::Object(options)) => Some(options),
        Some(_) => return Err("TypeScript compilerOptions must be an object".into()),
    };
    let allow_js = compiler_options
        .and_then(|options| options.get("allowJs"))
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| "TypeScript compilerOptions.allowJs must be a boolean".to_string())
        })
        .transpose()?;
    let compiler_path = |field: &str| -> Result<Option<RepositoryRootSelector>, String> {
        compiler_options
            .and_then(|options| options.get(field))
            .map(|value| {
                value
                    .as_str()
                    .map(|value| RepositoryRootSelector {
                        origin: origin.clone(),
                        value: value.to_string(),
                    })
                    .ok_or_else(|| format!("TypeScript compilerOptions.{field} must be a string"))
            })
            .transpose()
    };
    Ok(TypeScriptRootSelection {
        files: string_array("files")?,
        include: string_array("include")?,
        exclude: string_array("exclude")?,
        allow_js,
        out_dir: compiler_path("outDir")?,
        declaration_dir: compiler_path("declarationDir")?,
    })
}

fn typescript_selection_contains(
    selection: &TypeScriptRootSelection,
    context: &AnalysisContext,
    document_path: &str,
) -> Result<bool, String> {
    if !is_typescript_supported_root(document_path, selection.allow_js.unwrap_or(false)) {
        return Ok(false);
    }
    let explicit_files = selection
        .files
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|selector| {
            normalize_repository_relative_join(&selector.origin, &selector.value)
                .map(|path| path_label(&path))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if explicit_files.iter().any(|path| path == document_path) {
        return Ok(true);
    }
    let default_include;
    let includes: &[RepositoryRootSelector] = match (&selection.include, selection.files.is_some())
    {
        (Some(includes), _) => includes,
        (None, true) => &[],
        (None, false) => {
            default_include = vec![RepositoryRootSelector {
                origin: PathBuf::from(&context.root_path),
                value: "**/*".into(),
            }];
            &default_include
        }
    };
    let included = includes
        .iter()
        .map(|selector| typescript_pattern_matches(selector, document_path))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .any(|matched| matched);
    if !included {
        return Ok(false);
    }
    if selection.exclude.is_none() {
        if has_typescript_default_excluded_component(document_path) {
            return Ok(false);
        }
        for output_directory in [
            selection.out_dir.as_ref(),
            selection.declaration_dir.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            let output_directory = normalize_repository_relative_join(
                &output_directory.origin,
                &output_directory.value,
            )?;
            if Path::new(document_path).starts_with(output_directory) {
                return Ok(false);
            }
        }
    }
    let excluded = selection
        .exclude
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|selector| typescript_pattern_matches(selector, document_path))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .any(|matched| matched);
    Ok(!excluded)
}

fn typescript_pattern_matches(
    selector: &RepositoryRootSelector,
    document_path: &str,
) -> Result<bool, String> {
    repository_pattern_matches(selector, document_path, "TypeScript root")
}

fn repository_pattern_matches(
    selector: &RepositoryRootSelector,
    document_path: &str,
    label: &str,
) -> Result<bool, String> {
    let mut pattern = path_label(&normalize_repository_relative_join(
        &selector.origin,
        &selector.value,
    )?);
    let last = selector.value.rsplit('/').next().unwrap_or_default();
    if !last.contains(['*', '?']) && !last.contains('.') {
        if !pattern.is_empty() {
            pattern.push('/');
        }
        pattern.push_str("**/*");
    }
    let matcher = GlobBuilder::new(&pattern)
        .literal_separator(true)
        .build()
        .map_err(|error| format!("invalid {label} pattern {pattern:?}: {error}"))?
        .compile_matcher();
    Ok(matcher.is_match(Path::new(document_path)))
}

fn normalize_repository_relative_join(base: &Path, raw: &str) -> Result<PathBuf, String> {
    let windows_absolute = raw
        .as_bytes()
        .get(1)
        .is_some_and(|separator| *separator == b':');
    if raw.is_empty() || raw.starts_with('/') || windows_absolute || raw.contains('\\') {
        return Err(format!(
            "configuration path must be non-empty, portable, and repository-relative: {raw:?}"
        ));
    }
    let mut components = base
        .components()
        .filter_map(|component| match component {
            Component::Normal(component) => Some(component.to_os_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    for component in Path::new(raw).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if components.pop().is_none() {
                    return Err(format!(
                        "configuration path escapes the repository: {raw:?}"
                    ));
                }
            }
            Component::Normal(component) => components.push(component.to_os_string()),
            Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "configuration path must remain repository-relative: {raw:?}"
                ));
            }
        }
    }
    Ok(components.into_iter().collect())
}

fn is_typescript_supported_root(document_path: &str, allow_js: bool) -> bool {
    [".ts", ".tsx", ".mts", ".cts"]
        .iter()
        .any(|extension| document_path.ends_with(extension))
        || (allow_js
            && [".js", ".jsx", ".mjs", ".cjs"]
                .iter()
                .any(|extension| document_path.ends_with(extension)))
}

fn has_typescript_default_excluded_component(document_path: &str) -> bool {
    Path::new(document_path).components().any(|component| {
        matches!(component, Component::Normal(name) if ["node_modules", "bower_components", "jspm_packages"].contains(&name.to_string_lossy().as_ref()))
    })
}

fn is_typescript_configuration_name(name: &str) -> bool {
    (name.starts_with("tsconfig") || name.starts_with("jsconfig")) && name.ends_with(".json")
}

fn parse_pnpm_workspace_spec(
    contents: &str,
    workspace_unit: &ProjectUnit,
) -> Result<WorkspaceGlobSpec, String> {
    let manifest = serde_saphyr::from_str::<PnpmWorkspaceManifest>(contents)
        .map_err(|error| error.to_string())?;
    let mut include = Vec::new();
    let mut exclude = Vec::new();
    for raw_pattern in manifest.packages {
        let (excluded, pattern) = raw_pattern
            .strip_prefix('!')
            .map_or((false, raw_pattern.as_str()), |pattern| (true, pattern));
        let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
        validate_workspace_pattern(pattern, "pnpm package")?;
        let matcher = GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|error| format!("invalid pnpm package pattern {raw_pattern:?}: {error}"))?
            .compile_matcher();
        if excluded {
            exclude.push(matcher);
        } else {
            include.push(matcher);
        }
    }
    Ok(WorkspaceGlobSpec {
        project_unit_id: workspace_unit.project_unit_id.clone(),
        root_path: PathBuf::from(&workspace_unit.root_path),
        include,
        exclude,
    })
}

fn parse_uv_workspace_spec(
    workspace_value: &toml::Value,
    workspace_unit: &ProjectUnit,
) -> Result<WorkspaceGlobSpec, String> {
    let manifest = workspace_value
        .clone()
        .try_into::<UvWorkspaceManifest>()
        .map_err(|error| format!("invalid [tool.uv.workspace]: {error}"))?;
    if manifest.members.is_empty() {
        return Err("[tool.uv.workspace].members must contain at least one pattern".into());
    }
    let compile = |raw_pattern: &str, role: &str| {
        let pattern = raw_pattern.strip_prefix("./").unwrap_or(raw_pattern);
        validate_workspace_pattern(pattern, role)?;
        GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|error| format!("invalid {role} pattern {raw_pattern:?}: {error}"))
            .map(|glob| glob.compile_matcher())
    };
    let include = manifest
        .members
        .iter()
        .map(|pattern| compile(pattern, "uv workspace member"))
        .collect::<Result<Vec<_>, _>>()?;
    let exclude = manifest
        .exclude
        .iter()
        .map(|pattern| compile(pattern, "uv workspace exclude"))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WorkspaceGlobSpec {
        project_unit_id: workspace_unit.project_unit_id.clone(),
        root_path: PathBuf::from(&workspace_unit.root_path),
        include,
        exclude,
    })
}

fn validate_workspace_pattern(pattern: &str, role: &str) -> Result<(), String> {
    let windows_absolute = pattern
        .as_bytes()
        .get(1)
        .is_some_and(|separator| *separator == b':');
    if pattern.is_empty()
        || pattern.starts_with('/')
        || windows_absolute
        || pattern.contains('\\')
        || pattern
            .split('/')
            .any(|component| component.is_empty() || component == "..")
    {
        return Err(format!(
            "{role} pattern must be a non-empty repository-relative portable glob: {pattern:?}"
        ));
    }
    Ok(())
}

fn loose_unit(language_id: &LanguageId) -> ProjectUnit {
    project_unit(
        language_id,
        &language_id.0,
        ProjectUnitKind::LooseSources,
        Path::new(""),
        None,
    )
}

fn auxiliary_unit(language_id: &LanguageId, root_path: &Path) -> ProjectUnit {
    project_unit(
        language_id,
        &language_id.0,
        ProjectUnitKind::AuxiliarySources,
        root_path,
        None,
    )
}

/// Return the nearest language-defined auxiliary-source boundary containing a
/// document. This is deliberately a language rule, not a generic directory
/// name heuristic: Python and TypeScript fixture directories can be real
/// import/build inputs, while Go explicitly excludes `testdata` directories
/// from ordinary package discovery.
fn auxiliary_source_root(document_path: &str, language_id: &LanguageId) -> Option<PathBuf> {
    if language_id.0 != "go" {
        return None;
    }
    let mut root = PathBuf::new();
    for component in Path::new(document_path).parent()?.components() {
        let Component::Normal(name) = component else {
            return None;
        };
        root.push(name);
        if name == "testdata" {
            return Some(root);
        }
    }
    None
}

fn project_unit(
    language_id: &LanguageId,
    ecosystem: &str,
    kind: ProjectUnitKind,
    root_path: &Path,
    manifest_path: Option<&Path>,
) -> ProjectUnit {
    let root_label = path_label(root_path);
    let manifest_label = manifest_path.map(path_label);
    let identity_path = manifest_label.as_deref().unwrap_or_else(|| {
        if root_label.is_empty() {
            "<repository>"
        } else {
            &root_label
        }
    });
    ProjectUnit {
        project_unit_id: ProjectUnitId::new(format!(
            "{}:{ecosystem}:{}:{identity_path}",
            language_id.0,
            unit_kind_label(kind)
        )),
        language_id: language_id.clone(),
        ecosystem_id: EcosystemId::new(ecosystem),
        kind,
        root_path: root_label,
        manifest_path: manifest_label,
        compilation_root_paths: Vec::new(),
    }
}

const fn unit_kind_label(kind: ProjectUnitKind) -> &'static str {
    match kind {
        ProjectUnitKind::Workspace => "workspace",
        ProjectUnitKind::Package => "package",
        ProjectUnitKind::Module => "module",
        ProjectUnitKind::LooseSources => "loose_sources",
        ProjectUnitKind::AuxiliarySources => "auxiliary_sources",
    }
}

fn ancestor_directories(document_path: &str) -> Vec<PathBuf> {
    let mut directories = Vec::new();
    let mut current = Path::new(document_path).parent();
    while let Some(directory) = current {
        directories.push(directory.to_path_buf());
        current = directory.parent();
    }
    directories
}

fn safe_relative_path(path: &str) -> bool {
    let path = Path::new(path);
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && !path.as_os_str().to_string_lossy().contains('\\')
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && path_label(path) == path.as_os_str().to_string_lossy()
}

fn path_label(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn path_depth(path: &str) -> usize {
    Path::new(path).components().count()
}

fn path_relationships<'a>(
    units: impl Iterator<Item = &'a ProjectUnit>,
) -> Vec<ProjectUnitRelationship> {
    let units = units.collect::<Vec<_>>();
    let mut relationships = BTreeSet::new();
    for child in &units {
        let child_root = Path::new(&child.root_path);
        let parent = units
            .iter()
            .filter(|candidate| {
                candidate.project_unit_id != child.project_unit_id
                    && candidate.language_id == child.language_id
                    && candidate.ecosystem_id == child.ecosystem_id
                    && candidate.root_path != child.root_path
                    && child_root.starts_with(Path::new(&candidate.root_path))
            })
            .max_by(|left, right| {
                path_depth(&left.root_path)
                    .cmp(&path_depth(&right.root_path))
                    .then_with(|| right.project_unit_id.cmp(&left.project_unit_id))
            });
        if let Some(parent) = parent {
            relationships.insert(ProjectUnitRelationship {
                parent_project_unit_id: parent.project_unit_id.clone(),
                child_project_unit_id: child.project_unit_id.clone(),
                kind: ProjectUnitRelationshipKind::PathNestedWithin,
            });
        }
    }
    relationships.into_iter().collect()
}

fn project_unit_dependency_graphs(
    root: &Path,
    units: &BTreeMap<ProjectUnitId, ProjectUnit>,
    memberships: &BTreeSet<DocumentMembership>,
    relationships: &[ProjectUnitRelationship],
    exact_workspace_member_sets: &BTreeSet<ProjectUnitId>,
) -> Vec<ProjectUnitDependencyGraph> {
    let mut populations = BTreeMap::<(LanguageId, EcosystemId), BTreeSet<ProjectUnitId>>::new();
    for membership in memberships {
        if membership.kind != DocumentMembershipKind::SourceOwner {
            continue;
        }
        let Some(unit) = units.get(&membership.project_unit_id) else {
            continue;
        };
        if unit.kind.grants_semantic_authority() {
            populations
                .entry((unit.language_id.clone(), unit.ecosystem_id.clone()))
                .or_default()
                .insert(unit.project_unit_id.clone());
        }
    }

    populations
        .into_iter()
        .map(|((language_id, ecosystem_id), project_unit_ids)| {
            let project_unit_ids = project_unit_ids.into_iter().collect::<Vec<_>>();
            if let Some(adapter) = project_inventory_adapter(&language_id.0) {
                adapter.dependency_graph(
                    root,
                    &ecosystem_id,
                    units,
                    relationships,
                    exact_workspace_member_sets,
                    project_unit_ids,
                )
            } else {
                unavailable_dependency_graph(language_id, ecosystem_id, project_unit_ids)
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn exact_workspace_memberships_for_population(
    units: &BTreeMap<ProjectUnitId, ProjectUnit>,
    relationships: &[ProjectUnitRelationship],
    exact_workspace_member_sets: &BTreeSet<ProjectUnitId>,
    project_unit_ids: &[ProjectUnitId],
    language_id: &LanguageId,
    ecosystem_id: &EcosystemId,
    reason_prefix: &str,
    gaps: &mut BTreeSet<ProjectUnitDependencyGap>,
) -> BTreeMap<ProjectUnitId, ProjectUnitId> {
    let population = project_unit_ids.iter().cloned().collect::<BTreeSet<_>>();
    let mut candidates = BTreeMap::<ProjectUnitId, BTreeSet<ProjectUnitId>>::new();
    for relationship in relationships.iter().filter(|relationship| {
        relationship.kind == ProjectUnitRelationshipKind::WorkspaceMember
            && population.contains(&relationship.child_project_unit_id)
    }) {
        let valid_workspace =
            units
                .get(&relationship.parent_project_unit_id)
                .is_some_and(|workspace| {
                    workspace.language_id == *language_id
                        && workspace.ecosystem_id == *ecosystem_id
                        && workspace.kind == ProjectUnitKind::Workspace
                });
        if !valid_workspace {
            gaps.insert(dependency_gap(
                &format!("{reason_prefix}_workspace_relationship_invalid"),
                Some(relationship.child_project_unit_id.clone()),
                "<project-inventory>",
                "workspace membership references a unit from the wrong language, ecosystem, or kind",
            ));
            continue;
        }
        if !exact_workspace_member_sets.contains(&relationship.parent_project_unit_id) {
            gaps.insert(dependency_gap(
                &format!("{reason_prefix}_workspace_membership_unproven"),
                Some(relationship.child_project_unit_id.clone()),
                "<project-inventory>",
                "workspace relationship has no exact declared-member-set authority",
            ));
            continue;
        }
        candidates
            .entry(relationship.child_project_unit_id.clone())
            .or_default()
            .insert(relationship.parent_project_unit_id.clone());
    }

    candidates
        .into_iter()
        .filter_map(|(project_unit_id, workspaces)| {
            if workspaces.len() == 1 {
                return Some((
                    project_unit_id,
                    workspaces.into_iter().next().expect("one workspace"),
                ));
            }
            gaps.insert(dependency_gap(
                &format!("{reason_prefix}_workspace_membership_ambiguous"),
                Some(project_unit_id),
                "<project-inventory>",
                format!(
                    "package belongs to {} exact declared workspaces",
                    workspaces.len()
                ),
            ));
            None
        })
        .collect()
}

fn python_project_unit_dependencies(
    root: &Path,
    units: &BTreeMap<ProjectUnitId, ProjectUnit>,
    relationships: &[ProjectUnitRelationship],
    exact_workspace_member_sets: &BTreeSet<ProjectUnitId>,
    project_unit_ids: Vec<ProjectUnitId>,
) -> ProjectUnitDependencyGraph {
    let language_id = LanguageId::new("python");
    let ecosystem_id = EcosystemId::new("python");
    let mut dependencies = BTreeSet::new();
    let mut gaps = BTreeSet::new();
    let unit_roots = canonical_unit_roots(root, units, &project_unit_ids, &mut gaps);
    let workspace_by_unit = exact_workspace_memberships_for_population(
        units,
        relationships,
        exact_workspace_member_sets,
        &project_unit_ids,
        &language_id,
        &ecosystem_id,
        "python",
        &mut gaps,
    );

    let mut manifests = BTreeMap::<ProjectUnitId, PythonDependencyManifest>::new();
    for project_unit_id in &project_unit_ids {
        let Some(unit) = units.get(project_unit_id) else {
            gaps.insert(dependency_gap(
                "python_dependency_unit_missing",
                Some(project_unit_id.clone()),
                "<project-inventory>",
                "source-owning Python unit is absent from the unit population",
            ));
            continue;
        };
        if unit.kind != ProjectUnitKind::Package {
            gaps.insert(dependency_gap(
                "python_dependency_unit_not_package",
                Some(project_unit_id.clone()),
                unit.manifest_path
                    .as_deref()
                    .unwrap_or("<missing-manifest>"),
                "Python local dependency authority requires an exact source-owning package",
            ));
            continue;
        }
        let Some(manifest_path) = unit.manifest_path.as_deref() else {
            gaps.insert(dependency_gap(
                "python_package_manifest_missing",
                Some(project_unit_id.clone()),
                "<missing-manifest>",
                "Python package has no persisted manifest path",
            ));
            continue;
        };
        if !manifest_path.ends_with("pyproject.toml") {
            if project_unit_ids.len() > 1 {
                gaps.insert(dependency_gap(
                    "python_local_dependency_resolution_unavailable",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    "multi-package setup.py/setup.cfg dependency resolution is not yet authoritative",
                ));
            }
            continue;
        }
        match read_python_dependency_manifest(root, manifest_path) {
            Ok(manifest) => {
                manifests.insert(project_unit_id.clone(), manifest);
            }
            Err(detail) => {
                gaps.insert(dependency_gap(
                    "python_package_manifest_invalid",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    detail,
                ));
            }
        }
    }

    let workspace_ids = workspace_by_unit.values().cloned().collect::<BTreeSet<_>>();
    let mut workspace_manifests = BTreeMap::<ProjectUnitId, PythonDependencyManifest>::new();
    for workspace_id in &workspace_ids {
        let Some(workspace) = units.get(workspace_id) else {
            continue;
        };
        let Some(manifest_path) = workspace.manifest_path.as_deref() else {
            gaps.insert(dependency_gap(
                "python_workspace_manifest_missing",
                None,
                "<missing-manifest>",
                format!("exact uv workspace {workspace_id} has no manifest"),
            ));
            continue;
        };
        match read_python_dependency_manifest(root, manifest_path) {
            Ok(manifest) => {
                workspace_manifests.insert(workspace_id.clone(), manifest);
            }
            Err(detail) => {
                gaps.insert(dependency_gap(
                    "python_workspace_manifest_invalid",
                    None,
                    manifest_path,
                    detail,
                ));
            }
        }
    }

    let mut units_by_workspace_name =
        BTreeMap::<(ProjectUnitId, String), Vec<ProjectUnitId>>::new();
    for (project_unit_id, workspace_id) in &workspace_by_unit {
        let Some(manifest) = manifests.get(project_unit_id) else {
            continue;
        };
        let Some(name) = python_project_name(
            &manifest.document,
            project_unit_id,
            &manifest.manifest_path,
            &mut gaps,
        ) else {
            continue;
        };
        units_by_workspace_name
            .entry((workspace_id.clone(), name))
            .or_default()
            .push(project_unit_id.clone());
    }
    for ((_, name), matching_units) in &units_by_workspace_name {
        if matching_units.len() > 1 {
            gaps.insert(dependency_gap(
                "python_workspace_package_name_ambiguous",
                None,
                "<project-inventory>",
                format!(
                    "normalized uv workspace package name {name} resolves to {} indexed units",
                    matching_units.len()
                ),
            ));
        }
    }

    let workspace_sources = workspace_manifests
        .iter()
        .map(|(workspace_id, manifest)| {
            (
                workspace_id.clone(),
                python_uv_sources(manifest, None, &mut gaps),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for project_unit_id in &project_unit_ids {
        let Some(manifest) = manifests.get(project_unit_id) else {
            continue;
        };
        let Some(workspace_id) = workspace_by_unit.get(project_unit_id) else {
            if project_unit_ids.len() > 1 {
                gaps.insert(dependency_gap(
                    "python_local_dependency_resolution_unavailable",
                    Some(project_unit_id.clone()),
                    &manifest.manifest_path,
                    "package is outside every exact uv workspace; other Python local-dependency systems are not yet authoritative",
                ));
            }
            continue;
        };
        let declarations = python_dependency_declarations(
            &manifest.document,
            project_unit_id,
            &manifest.manifest_path,
            &mut gaps,
        );
        let own_sources = python_uv_sources(manifest, Some(project_unit_id), &mut gaps);
        let inherited_sources = workspace_sources.get(workspace_id);
        for dependency_name in declarations {
            let source = own_sources
                .get(&dependency_name)
                .map(|source| (source, manifest))
                .or_else(|| {
                    inherited_sources.and_then(|sources| {
                        sources
                            .get(&dependency_name)
                            .zip(workspace_manifests.get(workspace_id))
                    })
                });
            let Some((source, source_manifest)) = source else {
                continue;
            };
            let resolved = resolve_python_uv_source(
                root,
                source,
                &dependency_name,
                project_unit_id,
                workspace_id,
                source_manifest,
                &units_by_workspace_name,
                &unit_roots,
                &mut gaps,
            );
            if let Some(dependency_project_unit_id) = resolved
                && dependency_project_unit_id != *project_unit_id
            {
                dependencies.insert(ProjectUnitDependency {
                    dependent_project_unit_id: project_unit_id.clone(),
                    dependency_project_unit_id,
                });
            }
        }
    }

    dependency_graph(
        language_id,
        ecosystem_id,
        project_unit_ids,
        dependencies,
        gaps,
    )
}

struct PythonDependencyManifest {
    manifest_path: String,
    declaration_directory: PathBuf,
    document: toml::Value,
}

fn read_python_dependency_manifest(
    root: &Path,
    manifest_path: &str,
) -> Result<PythonDependencyManifest, String> {
    let absolute = root.join(manifest_path);
    if !std::fs::symlink_metadata(&absolute).is_ok_and(|metadata| metadata.file_type().is_file()) {
        return Err("pyproject.toml is not a regular repository-local file".into());
    }
    let contents = std::fs::read_to_string(&absolute).map_err(|error| error.to_string())?;
    let document = toml::from_str::<toml::Value>(&contents).map_err(|error| error.to_string())?;
    Ok(PythonDependencyManifest {
        manifest_path: manifest_path.into(),
        declaration_directory: Path::new(manifest_path)
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_path_buf(),
        document,
    })
}

fn python_project_name(
    document: &toml::Value,
    project_unit_id: &ProjectUnitId,
    manifest_path: &str,
    gaps: &mut BTreeSet<ProjectUnitDependencyGap>,
) -> Option<String> {
    let name = document
        .get("project")
        .and_then(toml::Value::as_table)
        .and_then(|project| project.get("name"))
        .and_then(toml::Value::as_str);
    let Some(name) = name.and_then(normalize_python_distribution_name) else {
        gaps.insert(dependency_gap(
            "python_project_name_invalid",
            Some(project_unit_id.clone()),
            manifest_path,
            "uv workspace package requires a valid [project].name",
        ));
        return None;
    };
    Some(name)
}

fn python_dependency_declarations(
    document: &toml::Value,
    project_unit_id: &ProjectUnitId,
    manifest_path: &str,
    gaps: &mut BTreeSet<ProjectUnitDependencyGap>,
) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if let Some(project) = document.get("project").and_then(toml::Value::as_table) {
        if let Some(dependencies) = project.get("dependencies") {
            collect_python_requirement_array(
                "project.dependencies",
                dependencies,
                project_unit_id,
                manifest_path,
                &mut names,
                gaps,
            );
        }
        if let Some(optional) = project.get("optional-dependencies") {
            if let Some(groups) = optional.as_table() {
                for (group, requirements) in groups {
                    collect_python_requirement_array(
                        &format!("project.optional-dependencies.{group}"),
                        requirements,
                        project_unit_id,
                        manifest_path,
                        &mut names,
                        gaps,
                    );
                }
            } else {
                gaps.insert(dependency_gap(
                    "python_dependency_table_invalid",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    "project.optional-dependencies must be a table",
                ));
            }
        }
    }
    if let Some(groups) = document.get("dependency-groups") {
        if let Some(groups) = groups.as_table() {
            for (group, requirements) in groups {
                collect_python_requirement_array(
                    &format!("dependency-groups.{group}"),
                    requirements,
                    project_unit_id,
                    manifest_path,
                    &mut names,
                    gaps,
                );
            }
        } else {
            gaps.insert(dependency_gap(
                "python_dependency_table_invalid",
                Some(project_unit_id.clone()),
                manifest_path,
                "dependency-groups must be a table",
            ));
        }
    }
    if let Some(build_system) = document.get("build-system").and_then(toml::Value::as_table)
        && let Some(requires) = build_system.get("requires")
    {
        collect_python_requirement_array(
            "build-system.requires",
            requires,
            project_unit_id,
            manifest_path,
            &mut names,
            gaps,
        );
    }
    names
}

fn collect_python_requirement_array(
    label: &str,
    value: &toml::Value,
    project_unit_id: &ProjectUnitId,
    manifest_path: &str,
    names: &mut BTreeSet<String>,
    gaps: &mut BTreeSet<ProjectUnitDependencyGap>,
) {
    let Some(requirements) = value.as_array() else {
        gaps.insert(dependency_gap(
            "python_dependency_table_invalid",
            Some(project_unit_id.clone()),
            manifest_path,
            format!("{label} must be an array"),
        ));
        return;
    };
    for requirement in requirements {
        let Some(requirement) = requirement.as_str() else {
            // PEP 735 dependency groups may contain include-group tables;
            // they add no new package declaration at this location.
            if label.starts_with("dependency-groups.")
                && requirement.as_table().is_some_and(|table| {
                    table.len() == 1 && table.get("include-group").is_some_and(toml::Value::is_str)
                })
            {
                continue;
            }
            gaps.insert(dependency_gap(
                "python_dependency_declaration_invalid",
                Some(project_unit_id.clone()),
                manifest_path,
                format!("{label} contains a non-string requirement"),
            ));
            continue;
        };
        match python_requirement_name(requirement) {
            Some(name) => {
                names.insert(name);
            }
            None => {
                gaps.insert(dependency_gap(
                    "python_dependency_declaration_invalid",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    format!("{label} contains an invalid requirement name"),
                ));
            }
        }
    }
}

fn python_uv_sources(
    manifest: &PythonDependencyManifest,
    project_unit_id: Option<&ProjectUnitId>,
    gaps: &mut BTreeSet<ProjectUnitDependencyGap>,
) -> BTreeMap<String, toml::Value> {
    let Some(sources) = manifest
        .document
        .get("tool")
        .and_then(toml::Value::as_table)
        .and_then(|tool| tool.get("uv"))
        .and_then(toml::Value::as_table)
        .and_then(|uv| uv.get("sources"))
    else {
        return BTreeMap::new();
    };
    let Some(sources) = sources.as_table() else {
        gaps.insert(dependency_gap(
            "python_uv_sources_invalid",
            project_unit_id.cloned(),
            &manifest.manifest_path,
            "tool.uv.sources must be a table",
        ));
        return BTreeMap::new();
    };
    let mut normalized = BTreeMap::new();
    for (name, source) in sources {
        let Some(name) = normalize_python_distribution_name(name) else {
            gaps.insert(dependency_gap(
                "python_uv_source_name_invalid",
                project_unit_id.cloned(),
                &manifest.manifest_path,
                "tool.uv.sources contains an invalid package name",
            ));
            continue;
        };
        if normalized.insert(name.clone(), source.clone()).is_some() {
            gaps.insert(dependency_gap(
                "python_uv_source_name_ambiguous",
                project_unit_id.cloned(),
                &manifest.manifest_path,
                format!("multiple source keys normalize to {name}"),
            ));
        }
    }
    normalized
}

#[allow(clippy::too_many_arguments)]
fn resolve_python_uv_source(
    root: &Path,
    source: &toml::Value,
    dependency_name: &str,
    project_unit_id: &ProjectUnitId,
    workspace_id: &ProjectUnitId,
    source_manifest: &PythonDependencyManifest,
    units_by_workspace_name: &BTreeMap<(ProjectUnitId, String), Vec<ProjectUnitId>>,
    unit_roots: &BTreeMap<PathBuf, ProjectUnitId>,
    gaps: &mut BTreeSet<ProjectUnitDependencyGap>,
) -> Option<ProjectUnitId> {
    let Some(source) = source.as_table() else {
        let Some(variants) = source.as_array() else {
            gaps.insert(dependency_gap(
                "python_uv_source_invalid",
                Some(project_unit_id.clone()),
                &source_manifest.manifest_path,
                format!("dependency {dependency_name} source must be a table or array"),
            ));
            return None;
        };
        let mut valid = !variants.is_empty();
        let mut potentially_local = false;
        for variant in variants {
            let Some(table) = variant.as_table() else {
                valid = false;
                continue;
            };
            let selectors = ["workspace", "path", "git", "url", "index"]
                .into_iter()
                .filter(|selector| table.contains_key(*selector))
                .collect::<Vec<_>>();
            valid &= selectors.len() == 1;
            potentially_local |= selectors
                .first()
                .is_some_and(|selector| matches!(*selector, "workspace" | "path"));
        }
        if !valid || potentially_local {
            gaps.insert(dependency_gap(
                "python_uv_conditional_local_source_unresolved",
                Some(project_unit_id.clone()),
                &source_manifest.manifest_path,
                format!(
                    "dependency {dependency_name} has conditional, empty, or invalid local-source authority"
                ),
            ));
        }
        return None;
    };
    let selector_count = ["workspace", "path", "git", "url", "index"]
        .into_iter()
        .filter(|selector| source.contains_key(*selector))
        .count();
    if selector_count != 1 {
        gaps.insert(dependency_gap(
            "python_uv_source_invalid",
            Some(project_unit_id.clone()),
            &source_manifest.manifest_path,
            format!(
                "dependency {dependency_name} source must declare exactly one workspace, path, git, url, or index selector"
            ),
        ));
        return None;
    }
    let workspace = source.get("workspace");
    let path = source.get("path");
    if let Some(workspace) = workspace {
        if workspace.as_bool() != Some(true) {
            gaps.insert(dependency_gap(
                "python_uv_external_workspace_source_unresolved",
                Some(project_unit_id.clone()),
                &source_manifest.manifest_path,
                format!(
                    "dependency {dependency_name} does not use the exact current-workspace form"
                ),
            ));
            return None;
        }
        return match units_by_workspace_name
            .get(&(workspace_id.clone(), dependency_name.into()))
            .map(Vec::as_slice)
        {
            Some([target]) => Some(target.clone()),
            Some(targets) => {
                gaps.insert(dependency_gap(
                    "python_uv_workspace_dependency_ambiguous",
                    Some(project_unit_id.clone()),
                    &source_manifest.manifest_path,
                    format!(
                        "workspace package {dependency_name} resolves to {} indexed units",
                        targets.len()
                    ),
                ));
                None
            }
            None => {
                gaps.insert(dependency_gap(
                    "python_uv_workspace_dependency_unresolved",
                    Some(project_unit_id.clone()),
                    &source_manifest.manifest_path,
                    format!(
                        "workspace package {dependency_name} is absent from the indexed source-owning population"
                    ),
                ));
                None
            }
        };
    }
    let path = path?;
    let Some(path) = path.as_str() else {
        gaps.insert(dependency_gap(
            "python_uv_path_source_invalid",
            Some(project_unit_id.clone()),
            &source_manifest.manifest_path,
            format!("dependency {dependency_name} has a non-string path source"),
        ));
        return None;
    };
    match resolve_local_dependency_unit(
        root,
        &source_manifest.declaration_directory,
        path,
        true,
        unit_roots,
    ) {
        Ok(target) => target,
        Err(detail) => {
            gaps.insert(dependency_gap(
                "python_uv_path_dependency_unresolved",
                Some(project_unit_id.clone()),
                &source_manifest.manifest_path,
                format!("dependency {dependency_name}: {detail}"),
            ));
            None
        }
    }
}

fn python_requirement_name(requirement: &str) -> Option<String> {
    let requirement = requirement.trim_start();
    let byte_len = requirement
        .char_indices()
        .take_while(|(_, character)| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .map(|(index, character)| index + character.len_utf8())
        .last()?;
    if requirement[byte_len..].chars().next().is_some_and(|next| {
        !next.is_ascii_whitespace()
            && !matches!(next, '[' | '(' | '<' | '>' | '=' | '!' | '~' | '@' | ';')
    }) {
        return None;
    }
    normalize_python_distribution_name(&requirement[..byte_len])
}

fn normalize_python_distribution_name(name: &str) -> Option<String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !name
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return None;
    }
    let mut normalized = String::with_capacity(name.len());
    let mut separator = false;
    for byte in name.bytes() {
        if matches!(byte, b'-' | b'_' | b'.') {
            separator = true;
        } else {
            if separator {
                normalized.push('-');
                separator = false;
            }
            normalized.push(char::from(byte.to_ascii_lowercase()));
        }
    }
    Some(normalized)
}

fn typescript_project_unit_dependencies(
    root: &Path,
    units: &BTreeMap<ProjectUnitId, ProjectUnit>,
    relationships: &[ProjectUnitRelationship],
    exact_workspace_member_sets: &BTreeSet<ProjectUnitId>,
    project_unit_ids: Vec<ProjectUnitId>,
) -> ProjectUnitDependencyGraph {
    let language_id = LanguageId::new("typescript");
    let ecosystem_id = EcosystemId::new("node");
    let mut dependencies = BTreeSet::new();
    let mut gaps = BTreeSet::new();
    let unit_roots = canonical_unit_roots(root, units, &project_unit_ids, &mut gaps);

    let workspace_by_unit = exact_workspace_memberships_for_population(
        units,
        relationships,
        exact_workspace_member_sets,
        &project_unit_ids,
        &language_id,
        &ecosystem_id,
        "typescript",
        &mut gaps,
    );

    let mut manifests =
        BTreeMap::<ProjectUnitId, serde_json::Map<String, serde_json::Value>>::new();
    for project_unit_id in &project_unit_ids {
        let Some(unit) = units.get(project_unit_id) else {
            gaps.insert(dependency_gap(
                "typescript_dependency_unit_missing",
                Some(project_unit_id.clone()),
                "<project-inventory>",
                "source-owning TypeScript unit is absent from the unit population",
            ));
            continue;
        };
        if unit.kind != ProjectUnitKind::Package {
            gaps.insert(dependency_gap(
                "typescript_dependency_unit_not_package",
                Some(project_unit_id.clone()),
                unit.manifest_path
                    .as_deref()
                    .unwrap_or("<missing-manifest>"),
                "TypeScript local dependency authority requires an exact source-owning package",
            ));
            continue;
        }
        let Some(manifest_path) = unit.manifest_path.as_deref() else {
            gaps.insert(dependency_gap(
                "typescript_package_manifest_missing",
                Some(project_unit_id.clone()),
                "<missing-manifest>",
                "TypeScript package has no persisted package.json path",
            ));
            continue;
        };
        match read_typescript_package_object(root, manifest_path) {
            Ok(package) => {
                manifests.insert(project_unit_id.clone(), package);
            }
            Err(detail) => {
                gaps.insert(dependency_gap(
                    "typescript_package_manifest_invalid",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    detail,
                ));
            }
        }
    }

    let mut units_by_workspace_name =
        BTreeMap::<(Option<ProjectUnitId>, String), Vec<ProjectUnitId>>::new();
    for (project_unit_id, package) in &manifests {
        let Some(name) = package.get("name") else {
            continue;
        };
        let Some(name) = name.as_str().filter(|name| !name.is_empty()) else {
            let manifest_path = units
                .get(project_unit_id)
                .and_then(|unit| unit.manifest_path.as_deref())
                .unwrap_or("<missing-manifest>");
            gaps.insert(dependency_gap(
                "typescript_package_name_invalid",
                Some(project_unit_id.clone()),
                manifest_path,
                "package name must be a non-empty string when present",
            ));
            continue;
        };
        units_by_workspace_name
            .entry((workspace_by_unit.get(project_unit_id).cloned(), name.into()))
            .or_default()
            .push(project_unit_id.clone());
    }
    for ((_, name), matching_units) in &units_by_workspace_name {
        if matching_units.len() > 1 {
            gaps.insert(dependency_gap(
                "typescript_workspace_package_name_ambiguous",
                None,
                "<project-inventory>",
                format!(
                    "workspace package name {name} resolves to {} indexed units",
                    matching_units.len()
                ),
            ));
        }
    }

    for (project_unit_id, package) in &manifests {
        let manifest_path = units
            .get(project_unit_id)
            .and_then(|unit| unit.manifest_path.as_deref())
            .unwrap_or("<missing-manifest>");
        let declaration_directory = units
            .get(project_unit_id)
            .map_or_else(|| Path::new(""), |unit| Path::new(&unit.root_path));
        let declarations =
            typescript_dependency_declarations(package, project_unit_id, manifest_path, &mut gaps);
        for (dependency_name, specifications) in declarations {
            if specifications.len() != 1 {
                gaps.insert(dependency_gap(
                    "typescript_dependency_declaration_ambiguous",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    format!(
                        "dependency {dependency_name} has conflicting declarations: {}",
                        specifications.into_iter().collect::<Vec<_>>().join(", ")
                    ),
                ));
                continue;
            }
            let specification = specifications
                .into_iter()
                .next()
                .expect("one dependency specification");
            let Some(workspace_specification) = specification.strip_prefix("workspace:") else {
                // Plain semver may or may not link locally depending on pnpm
                // settings. It is deliberately not claimed as a local edge.
                continue;
            };
            let Some(dependent_workspace) = workspace_by_unit.get(project_unit_id) else {
                gaps.insert(dependency_gap(
                    "typescript_workspace_dependency_without_workspace",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    format!(
                        "dependency {dependency_name} uses workspace: outside an exact workspace membership"
                    ),
                ));
                continue;
            };
            let target = match typescript_workspace_dependency_target(
                &dependency_name,
                workspace_specification,
            ) {
                Ok(target) => target,
                Err(detail) => {
                    gaps.insert(dependency_gap(
                        "typescript_workspace_dependency_invalid",
                        Some(project_unit_id.clone()),
                        manifest_path,
                        format!("dependency {dependency_name}: {detail}"),
                    ));
                    continue;
                }
            };
            let resolved = match target {
                TypeScriptWorkspaceDependencyTarget::Name(target_name) => {
                    let key = (Some(dependent_workspace.clone()), target_name.clone());
                    match units_by_workspace_name.get(&key).map(Vec::as_slice) {
                        Some([target]) => Ok(Some(target.clone())),
                        Some(targets) => Err(format!(
                            "workspace package {target_name} resolves to {} indexed units",
                            targets.len()
                        )),
                        None => Err(format!(
                            "workspace package {target_name} is absent from the indexed source-owning population"
                        )),
                    }
                }
                TypeScriptWorkspaceDependencyTarget::Relative(path) => {
                    resolve_local_dependency_unit(
                        root,
                        declaration_directory,
                        &path,
                        true,
                        &unit_roots,
                    )
                }
            };
            match resolved {
                Ok(Some(dependency_project_unit_id)) => {
                    if workspace_by_unit.get(&dependency_project_unit_id)
                        != Some(dependent_workspace)
                    {
                        gaps.insert(dependency_gap(
                            "typescript_workspace_dependency_crosses_workspace",
                            Some(project_unit_id.clone()),
                            manifest_path,
                            format!(
                                "dependency {dependency_name} resolves outside its pnpm workspace"
                            ),
                        ));
                    } else if dependency_project_unit_id != *project_unit_id {
                        dependencies.insert(ProjectUnitDependency {
                            dependent_project_unit_id: project_unit_id.clone(),
                            dependency_project_unit_id,
                        });
                    }
                }
                Ok(None) => {
                    gaps.insert(dependency_gap(
                        "typescript_workspace_dependency_unresolved",
                        Some(project_unit_id.clone()),
                        manifest_path,
                        format!(
                            "dependency {dependency_name} resolves outside the indexed repository"
                        ),
                    ));
                }
                Err(detail) => {
                    gaps.insert(dependency_gap(
                        "typescript_workspace_dependency_unresolved",
                        Some(project_unit_id.clone()),
                        manifest_path,
                        format!("dependency {dependency_name}: {detail}"),
                    ));
                }
            }
        }
    }

    dependency_graph(
        language_id,
        ecosystem_id,
        project_unit_ids,
        dependencies,
        gaps,
    )
}

fn read_typescript_package_object(
    root: &Path,
    manifest_path: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let absolute = root.join(manifest_path);
    if !std::fs::symlink_metadata(&absolute).is_ok_and(|metadata| metadata.file_type().is_file()) {
        return Err("package.json is not a regular repository-local file".into());
    }
    let contents = std::fs::read_to_string(&absolute).map_err(|error| error.to_string())?;
    match serde_json::from_str::<serde_json::Value>(&contents) {
        Ok(serde_json::Value::Object(package)) => Ok(package),
        Ok(_) => Err("package.json must be a JSON object".into()),
        Err(error) => Err(error.to_string()),
    }
}

fn typescript_dependency_declarations(
    package: &serde_json::Map<String, serde_json::Value>,
    project_unit_id: &ProjectUnitId,
    manifest_path: &str,
    gaps: &mut BTreeSet<ProjectUnitDependencyGap>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut declarations = BTreeMap::<String, BTreeSet<String>>::new();
    for field in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(value) = package.get(field) else {
            continue;
        };
        let Some(table) = value.as_object() else {
            gaps.insert(dependency_gap(
                "typescript_dependency_table_invalid",
                Some(project_unit_id.clone()),
                manifest_path,
                format!("{field} must be an object"),
            ));
            continue;
        };
        for (dependency_name, value) in table {
            let Some(specification) = value.as_str() else {
                gaps.insert(dependency_gap(
                    "typescript_dependency_declaration_invalid",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    format!("{field}.{dependency_name} must be a string"),
                ));
                continue;
            };
            declarations
                .entry(dependency_name.clone())
                .or_default()
                .insert(specification.into());
        }
    }
    declarations
}

enum TypeScriptWorkspaceDependencyTarget {
    Name(String),
    Relative(String),
}

fn typescript_workspace_dependency_target(
    dependency_name: &str,
    specification: &str,
) -> Result<TypeScriptWorkspaceDependencyTarget, String> {
    if specification.starts_with('.') {
        return Ok(TypeScriptWorkspaceDependencyTarget::Relative(
            specification.into(),
        ));
    }
    if specification.starts_with('/')
        || specification.contains('\\')
        || specification
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
    {
        return Err("workspace dependency target must be repository-relative".into());
    }
    if let Some((alias, range)) = specification.rsplit_once('@')
        && !alias.is_empty()
        && !range.is_empty()
    {
        return Ok(TypeScriptWorkspaceDependencyTarget::Name(alias.into()));
    }
    Ok(TypeScriptWorkspaceDependencyTarget::Name(
        dependency_name.into(),
    ))
}

fn cargo_project_unit_dependencies(
    root: &Path,
    units: &BTreeMap<ProjectUnitId, ProjectUnit>,
    project_unit_ids: Vec<ProjectUnitId>,
) -> ProjectUnitDependencyGraph {
    let language_id = LanguageId::new("rust");
    let ecosystem_id = EcosystemId::new("cargo");
    let mut dependencies = BTreeSet::new();
    let mut gaps = BTreeSet::new();
    let unit_roots = canonical_unit_roots(root, units, &project_unit_ids, &mut gaps);
    let workspaces = cargo_workspace_manifests(root, units, &mut gaps);

    for project_unit_id in &project_unit_ids {
        let Some(unit) = units.get(project_unit_id) else {
            continue;
        };
        if unit.kind != ProjectUnitKind::Package {
            gaps.insert(dependency_gap(
                "cargo_dependency_unit_not_package",
                Some(project_unit_id.clone()),
                unit.manifest_path
                    .as_deref()
                    .unwrap_or("<missing-manifest>"),
                "Cargo dependency authority currently requires an exact source-owning package",
            ));
            continue;
        }
        let Some(manifest_path) = unit.manifest_path.as_deref() else {
            gaps.insert(dependency_gap(
                "cargo_dependency_manifest_missing",
                Some(project_unit_id.clone()),
                "<missing-manifest>",
                "Cargo package has no persisted manifest path",
            ));
            continue;
        };
        let absolute_manifest = root.join(manifest_path);
        let contents = match std::fs::read_to_string(&absolute_manifest) {
            Ok(contents) => contents,
            Err(error) => {
                gaps.insert(dependency_gap(
                    "cargo_dependency_manifest_unreadable",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    error.to_string(),
                ));
                continue;
            }
        };
        let manifest = match toml::from_str::<toml::Value>(&contents) {
            Ok(manifest) => manifest,
            Err(error) => {
                gaps.insert(dependency_gap(
                    "cargo_dependency_manifest_invalid",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    error.to_string(),
                ));
                continue;
            }
        };
        if manifest.get("patch").is_some() || manifest.get("replace").is_some() {
            gaps.insert(dependency_gap(
                "cargo_dependency_override_unsupported",
                Some(project_unit_id.clone()),
                manifest_path,
                "[patch] and [replace] may redirect a declared dependency to another local package",
            ));
        }

        let manifest_directory = Path::new(manifest_path)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        for (dependency_name, dependency) in cargo_dependency_entries(&manifest) {
            let Some(table) = dependency.as_table() else {
                if dependency.as_str().is_none() {
                    gaps.insert(dependency_gap(
                        "cargo_dependency_declaration_invalid",
                        Some(project_unit_id.clone()),
                        manifest_path,
                        format!("dependency {dependency_name} is neither a version nor a table"),
                    ));
                }
                continue;
            };
            let workspace_inherited = match table.get("workspace") {
                Some(value) => match value.as_bool() {
                    Some(inherited) => inherited,
                    None => {
                        gaps.insert(dependency_gap(
                            "cargo_workspace_dependency_flag_invalid",
                            Some(project_unit_id.clone()),
                            manifest_path,
                            format!(
                                "dependency {dependency_name} has a non-boolean workspace flag"
                            ),
                        ));
                        continue;
                    }
                },
                None => false,
            };
            let (effective_dependency, declaration_path, declaration_directory) =
                if workspace_inherited {
                    if table.get("path").is_some() {
                        gaps.insert(dependency_gap(
                            "cargo_workspace_dependency_override_invalid",
                            Some(project_unit_id.clone()),
                            manifest_path,
                            format!(
                                "dependency {dependency_name} combines workspace inheritance with a package-local path"
                            ),
                        ));
                        continue;
                    }
                    let Some(workspace) = nearest_cargo_workspace(unit, &workspaces) else {
                        gaps.insert(dependency_gap(
                            "cargo_workspace_dependency_workspace_missing",
                            Some(project_unit_id.clone()),
                            manifest_path,
                            format!(
                                "dependency {dependency_name} inherits from no discovered Cargo workspace"
                            ),
                        ));
                        continue;
                    };
                    let Some(inherited) = workspace.dependencies.get(dependency_name) else {
                        gaps.insert(dependency_gap(
                            "cargo_workspace_dependency_declaration_missing",
                            Some(project_unit_id.clone()),
                            &workspace.manifest_path,
                            format!("workspace dependency {dependency_name} is not declared"),
                        ));
                        continue;
                    };
                    (
                        inherited,
                        workspace.manifest_path.as_str(),
                        workspace.manifest_directory.as_path(),
                    )
                } else {
                    (dependency, manifest_path, manifest_directory)
                };
            let Some(path_value) = effective_dependency
                .as_table()
                .and_then(|table| table.get("path"))
            else {
                if effective_dependency.as_table().is_none()
                    && effective_dependency.as_str().is_none()
                {
                    gaps.insert(dependency_gap(
                        "cargo_dependency_declaration_invalid",
                        Some(project_unit_id.clone()),
                        declaration_path,
                        format!("dependency {dependency_name} is neither a version nor a table"),
                    ));
                }
                continue;
            };
            let Some(path) = path_value.as_str() else {
                gaps.insert(dependency_gap(
                    "cargo_dependency_path_invalid",
                    Some(project_unit_id.clone()),
                    declaration_path,
                    format!("dependency {dependency_name} has a non-string path"),
                ));
                continue;
            };
            match resolve_local_dependency_unit(
                root,
                declaration_directory,
                path,
                true,
                &unit_roots,
            ) {
                Ok(Some(dependency_project_unit_id)) => {
                    if dependency_project_unit_id != *project_unit_id {
                        dependencies.insert(ProjectUnitDependency {
                            dependent_project_unit_id: project_unit_id.clone(),
                            dependency_project_unit_id,
                        });
                    }
                }
                Ok(None) => {}
                Err(detail) => {
                    gaps.insert(dependency_gap(
                        "cargo_local_dependency_unresolved",
                        Some(project_unit_id.clone()),
                        declaration_path,
                        format!("dependency {dependency_name}: {detail}"),
                    ));
                }
            }
        }
    }

    dependency_graph(
        language_id,
        ecosystem_id,
        project_unit_ids,
        dependencies,
        gaps,
    )
}

#[derive(Debug)]
struct CargoWorkspaceManifest {
    root_path: String,
    manifest_path: String,
    manifest_directory: PathBuf,
    dependencies: toml::value::Table,
}

fn cargo_workspace_manifests(
    root: &Path,
    units: &BTreeMap<ProjectUnitId, ProjectUnit>,
    gaps: &mut BTreeSet<ProjectUnitDependencyGap>,
) -> Vec<CargoWorkspaceManifest> {
    let mut workspaces = Vec::new();
    for unit in units.values().filter(|unit| {
        unit.language_id.0 == "rust"
            && unit.ecosystem_id.0 == "cargo"
            && unit.kind == ProjectUnitKind::Workspace
    }) {
        let Some(manifest_path) = unit.manifest_path.as_deref() else {
            gaps.insert(dependency_gap(
                "cargo_workspace_manifest_missing",
                None,
                "<missing-manifest>",
                "Cargo workspace has no persisted manifest path",
            ));
            continue;
        };
        let contents = match std::fs::read_to_string(root.join(manifest_path)) {
            Ok(contents) => contents,
            Err(error) => {
                gaps.insert(dependency_gap(
                    "cargo_workspace_manifest_unreadable",
                    None,
                    manifest_path,
                    error.to_string(),
                ));
                continue;
            }
        };
        let manifest = match toml::from_str::<toml::Value>(&contents) {
            Ok(manifest) => manifest,
            Err(error) => {
                gaps.insert(dependency_gap(
                    "cargo_workspace_manifest_invalid",
                    None,
                    manifest_path,
                    error.to_string(),
                ));
                continue;
            }
        };
        if manifest.get("patch").is_some() || manifest.get("replace").is_some() {
            gaps.insert(dependency_gap(
                "cargo_dependency_override_unsupported",
                None,
                manifest_path,
                "workspace [patch] and [replace] may redirect a declared dependency to another local package",
            ));
        }
        let workspace = manifest.get("workspace").and_then(toml::Value::as_table);
        let dependencies = workspace
            .and_then(|table| table.get("dependencies"))
            .map_or_else(toml::value::Table::new, |value| {
                value.as_table().map_or_else(
                    || {
                        gaps.insert(dependency_gap(
                            "cargo_workspace_dependencies_invalid",
                            None,
                            manifest_path,
                            "workspace.dependencies is not a table",
                        ));
                        toml::value::Table::new()
                    },
                    Clone::clone,
                )
            });
        workspaces.push(CargoWorkspaceManifest {
            root_path: unit.root_path.clone(),
            manifest_path: manifest_path.into(),
            manifest_directory: Path::new(manifest_path)
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .to_path_buf(),
            dependencies,
        });
    }
    workspaces.sort_by(|left, right| {
        path_depth(&left.root_path)
            .cmp(&path_depth(&right.root_path))
            .then_with(|| left.root_path.cmp(&right.root_path))
    });
    workspaces
}

fn nearest_cargo_workspace<'a>(
    unit: &ProjectUnit,
    workspaces: &'a [CargoWorkspaceManifest],
) -> Option<&'a CargoWorkspaceManifest> {
    workspaces
        .iter()
        .filter(|workspace| Path::new(&unit.root_path).starts_with(Path::new(&workspace.root_path)))
        .max_by(|left, right| {
            path_depth(&left.root_path)
                .cmp(&path_depth(&right.root_path))
                .then_with(|| right.root_path.cmp(&left.root_path))
        })
}

fn cargo_dependency_entries(manifest: &toml::Value) -> Vec<(&str, &toml::Value)> {
    const TABLES: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    let mut entries = Vec::new();
    for table_name in TABLES {
        if let Some(table) = manifest.get(table_name).and_then(toml::Value::as_table) {
            entries.extend(table.iter().map(|(name, value)| (name.as_str(), value)));
        }
    }
    if let Some(targets) = manifest.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            for table_name in TABLES {
                if let Some(table) = target.get(table_name).and_then(toml::Value::as_table) {
                    entries.extend(table.iter().map(|(name, value)| (name.as_str(), value)));
                }
            }
        }
    }
    entries
}

#[derive(Debug)]
struct ParsedGoModule {
    module_path: String,
    required_module_paths: BTreeSet<String>,
    replacements: BTreeMap<String, String>,
}

#[derive(Debug)]
struct ParsedGoWorkspace {
    root_path: String,
    manifest_path: String,
    manifest_directory: PathBuf,
    used_project_unit_ids: BTreeSet<ProjectUnitId>,
    replacements: BTreeMap<String, String>,
}

fn go_project_unit_dependencies(
    root: &Path,
    units: &BTreeMap<ProjectUnitId, ProjectUnit>,
    project_unit_ids: Vec<ProjectUnitId>,
) -> ProjectUnitDependencyGraph {
    let language_id = LanguageId::new("go");
    let ecosystem_id = EcosystemId::new("go");
    let mut dependencies = BTreeSet::new();
    let mut gaps = BTreeSet::new();
    let unit_roots = canonical_unit_roots(root, units, &project_unit_ids, &mut gaps);
    let mut parsed = BTreeMap::<ProjectUnitId, (String, ParsedGoModule)>::new();
    let mut units_by_module_path = BTreeMap::<String, ProjectUnitId>::new();
    let workspaces = go_workspace_manifests(root, units, &unit_roots, &mut gaps);

    for project_unit_id in &project_unit_ids {
        let Some(unit) = units.get(project_unit_id) else {
            continue;
        };
        if unit.kind != ProjectUnitKind::Module {
            gaps.insert(dependency_gap(
                "go_dependency_unit_not_module",
                Some(project_unit_id.clone()),
                unit.manifest_path
                    .as_deref()
                    .unwrap_or("<missing-manifest>"),
                "Go dependency authority requires an exact source-owning module",
            ));
            continue;
        }
        let Some(manifest_path) = unit.manifest_path.as_deref() else {
            gaps.insert(dependency_gap(
                "go_dependency_manifest_missing",
                Some(project_unit_id.clone()),
                "<missing-manifest>",
                "Go module has no persisted go.mod path",
            ));
            continue;
        };
        let contents = match std::fs::read_to_string(root.join(manifest_path)) {
            Ok(contents) => contents,
            Err(error) => {
                gaps.insert(dependency_gap(
                    "go_dependency_manifest_unreadable",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    error.to_string(),
                ));
                continue;
            }
        };
        let module = match parse_go_module_file(&contents) {
            Ok(module) => module,
            Err(detail) => {
                gaps.insert(dependency_gap(
                    "go_dependency_manifest_unsupported",
                    Some(project_unit_id.clone()),
                    manifest_path,
                    detail,
                ));
                continue;
            }
        };
        if let Some(existing) = units_by_module_path
            .insert(module.module_path.clone(), project_unit_id.clone())
            .filter(|existing| existing != project_unit_id)
        {
            gaps.insert(dependency_gap(
                "go_module_path_ambiguous",
                Some(project_unit_id.clone()),
                manifest_path,
                format!(
                    "module path {} is also owned by {}",
                    module.module_path, existing
                ),
            ));
        }
        parsed.insert(project_unit_id.clone(), (manifest_path.into(), module));
    }

    for (project_unit_id, (manifest_path, module)) in &parsed {
        let unit = units
            .get(project_unit_id)
            .expect("parsed Go module belongs to a discovered project unit");
        let manifest_directory = Path::new(manifest_path)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let workspace = nearest_go_workspace(unit, &workspaces);
        if let Some(workspace) = workspace
            && !workspace.used_project_unit_ids.contains(project_unit_id)
        {
            gaps.insert(dependency_gap(
                "go_workspace_module_not_used",
                Some(project_unit_id.clone()),
                &workspace.manifest_path,
                format!(
                    "module {} is inside the workspace root but absent from its use population",
                    module.module_path
                ),
            ));
        }
        for required in &module.required_module_paths {
            let replacement = workspace
                .and_then(|workspace| {
                    workspace.replacements.get(required).map(|replacement| {
                        (
                            replacement.as_str(),
                            workspace.manifest_directory.as_path(),
                            workspace.manifest_path.as_str(),
                        )
                    })
                })
                .or_else(|| {
                    module.replacements.get(required).map(|replacement| {
                        (
                            replacement.as_str(),
                            manifest_directory,
                            manifest_path.as_str(),
                        )
                    })
                });
            let dependency = if let Some((replacement, declaration_directory, declaration_path)) =
                replacement
            {
                if replacement.starts_with('.') || Path::new(replacement).is_absolute() {
                    match resolve_local_dependency_unit(
                        root,
                        declaration_directory,
                        replacement,
                        false,
                        &unit_roots,
                    ) {
                        Ok(Some(project_unit_id)) => Some(project_unit_id),
                        Ok(None) => {
                            gaps.insert(dependency_gap(
                                "go_local_replacement_outside_population",
                                Some(project_unit_id.clone()),
                                declaration_path,
                                format!(
                                    "local replacement for {required} is outside the indexed repository population"
                                ),
                            ));
                            None
                        }
                        Err(detail) => {
                            gaps.insert(dependency_gap(
                                "go_local_replacement_unresolved",
                                Some(project_unit_id.clone()),
                                declaration_path,
                                format!("replacement for {required}: {detail}"),
                            ));
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                workspace.and_then(|workspace| {
                    units_by_module_path.get(required).and_then(|candidate| {
                        workspace
                            .used_project_unit_ids
                            .contains(candidate)
                            .then(|| candidate.clone())
                    })
                })
            };
            if let Some(dependency_project_unit_id) = dependency
                && dependency_project_unit_id != *project_unit_id
            {
                dependencies.insert(ProjectUnitDependency {
                    dependent_project_unit_id: project_unit_id.clone(),
                    dependency_project_unit_id,
                });
            }
        }
    }

    dependency_graph(
        language_id,
        ecosystem_id,
        project_unit_ids,
        dependencies,
        gaps,
    )
}

fn go_workspace_manifests(
    root: &Path,
    units: &BTreeMap<ProjectUnitId, ProjectUnit>,
    unit_roots: &BTreeMap<PathBuf, ProjectUnitId>,
    gaps: &mut BTreeSet<ProjectUnitDependencyGap>,
) -> Vec<ParsedGoWorkspace> {
    let mut workspaces = Vec::new();
    for unit in units.values().filter(|unit| {
        unit.language_id.0 == "go"
            && unit.ecosystem_id.0 == "go"
            && unit.kind == ProjectUnitKind::Workspace
    }) {
        let Some(manifest_path) = unit.manifest_path.as_deref() else {
            gaps.insert(dependency_gap(
                "go_workspace_manifest_missing",
                None,
                "<missing-manifest>",
                "Go workspace has no persisted manifest path",
            ));
            continue;
        };
        let contents = match std::fs::read_to_string(root.join(manifest_path)) {
            Ok(contents) => contents,
            Err(error) => {
                gaps.insert(dependency_gap(
                    "go_workspace_manifest_unreadable",
                    None,
                    manifest_path,
                    error.to_string(),
                ));
                continue;
            }
        };
        let (use_paths, replacements) = match parse_go_workspace_file(&contents) {
            Ok(parsed) => parsed,
            Err(detail) => {
                gaps.insert(dependency_gap(
                    "go_workspace_manifest_unsupported",
                    None,
                    manifest_path,
                    detail,
                ));
                continue;
            }
        };
        let manifest_directory = Path::new(manifest_path)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let mut used_project_unit_ids = BTreeSet::new();
        for use_path in use_paths {
            match resolve_local_dependency_unit(
                root,
                manifest_directory,
                &use_path,
                true,
                unit_roots,
            ) {
                Ok(Some(project_unit_id)) => {
                    used_project_unit_ids.insert(project_unit_id);
                }
                Ok(None) => {
                    gaps.insert(dependency_gap(
                        "go_workspace_use_outside_population",
                        None,
                        manifest_path,
                        format!(
                            "workspace use path {use_path} is outside the indexed repository population"
                        ),
                    ));
                }
                Err(detail) => {
                    gaps.insert(dependency_gap(
                        "go_workspace_use_unresolved",
                        None,
                        manifest_path,
                        format!("workspace use path {use_path}: {detail}"),
                    ));
                }
            }
        }
        if used_project_unit_ids.is_empty() {
            gaps.insert(dependency_gap(
                "go_workspace_use_population_empty",
                None,
                manifest_path,
                "Go workspace has no resolved indexed main modules",
            ));
        }
        workspaces.push(ParsedGoWorkspace {
            root_path: unit.root_path.clone(),
            manifest_path: manifest_path.into(),
            manifest_directory: manifest_directory.to_path_buf(),
            used_project_unit_ids,
            replacements,
        });
    }
    workspaces.sort_by(|left, right| {
        path_depth(&left.root_path)
            .cmp(&path_depth(&right.root_path))
            .then_with(|| left.root_path.cmp(&right.root_path))
    });
    workspaces
}

fn nearest_go_workspace<'a>(
    unit: &ProjectUnit,
    workspaces: &'a [ParsedGoWorkspace],
) -> Option<&'a ParsedGoWorkspace> {
    workspaces
        .iter()
        .filter(|workspace| Path::new(&unit.root_path).starts_with(Path::new(&workspace.root_path)))
        .max_by(|left, right| {
            path_depth(&left.root_path)
                .cmp(&path_depth(&right.root_path))
                .then_with(|| right.root_path.cmp(&left.root_path))
        })
}

fn parse_go_module_file(contents: &str) -> Result<ParsedGoModule, String> {
    let mut module_path = None;
    let mut required_module_paths = BTreeSet::new();
    let mut replacements = BTreeMap::new();
    let mut group = None::<String>;
    const GROUPABLE: [&str; 6] = [
        "require", "replace", "exclude", "retract", "tool", "godebug",
    ];
    const SINGLE: [&str; 9] = [
        "module",
        "go",
        "toolchain",
        "require",
        "replace",
        "exclude",
        "retract",
        "tool",
        "godebug",
    ];

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line = raw_line
            .split_once("//")
            .map_or(raw_line, |(before, _)| before)
            .trim();
        if line.is_empty() {
            continue;
        }
        if line.contains(['"', '`']) {
            return Err(format!(
                "quoted go.mod tokens are not yet dependency-authoritative at line {}",
                line_index + 1
            ));
        }
        if line == ")" {
            if group.take().is_none() {
                return Err(format!("unmatched ')' at line {}", line_index + 1));
            }
            continue;
        }
        if let Some(active) = group.as_deref() {
            parse_go_module_directive(
                active,
                line,
                &mut module_path,
                &mut required_module_paths,
                &mut replacements,
                line_index + 1,
            )?;
            continue;
        }

        let mut tokens = line.split_whitespace();
        let directive = tokens
            .next()
            .ok_or_else(|| format!("empty directive at line {}", line_index + 1))?;
        let remainder = line[directive.len()..].trim();
        if remainder == "(" {
            if !GROUPABLE.contains(&directive) {
                return Err(format!(
                    "unsupported grouped directive {directive} at line {}",
                    line_index + 1
                ));
            }
            group = Some(directive.into());
            continue;
        }
        if !SINGLE.contains(&directive) {
            return Err(format!(
                "unknown dependency-affecting directive {directive} at line {}",
                line_index + 1
            ));
        }
        parse_go_module_directive(
            directive,
            remainder,
            &mut module_path,
            &mut required_module_paths,
            &mut replacements,
            line_index + 1,
        )?;
    }
    if let Some(group) = group {
        return Err(format!("unterminated {group} block"));
    }
    let module_path = module_path.ok_or_else(|| "go.mod has no module directive".to_string())?;
    Ok(ParsedGoModule {
        module_path,
        required_module_paths,
        replacements,
    })
}

fn parse_go_workspace_file(
    contents: &str,
) -> Result<(BTreeSet<String>, BTreeMap<String, String>), String> {
    let mut use_paths = BTreeSet::new();
    let mut replacements = BTreeMap::new();
    let mut group = None::<String>;
    const GROUPABLE: [&str; 2] = ["use", "replace"];
    const SINGLE: [&str; 5] = ["go", "toolchain", "godebug", "use", "replace"];

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line = raw_line
            .split_once("//")
            .map_or(raw_line, |(before, _)| before)
            .trim();
        if line.is_empty() {
            continue;
        }
        if line.contains(['"', '`']) {
            return Err(format!(
                "quoted go.work tokens are not yet dependency-authoritative at line {}",
                line_index + 1
            ));
        }
        if line == ")" {
            if group.take().is_none() {
                return Err(format!("unmatched ')' at line {}", line_index + 1));
            }
            continue;
        }
        if let Some(active) = group.as_deref() {
            parse_go_workspace_directive(
                active,
                line,
                &mut use_paths,
                &mut replacements,
                line_index + 1,
            )?;
            continue;
        }

        let mut tokens = line.split_whitespace();
        let directive = tokens
            .next()
            .ok_or_else(|| format!("empty directive at line {}", line_index + 1))?;
        let remainder = line[directive.len()..].trim();
        if remainder == "(" {
            if !GROUPABLE.contains(&directive) {
                return Err(format!(
                    "unsupported grouped directive {directive} at line {}",
                    line_index + 1
                ));
            }
            group = Some(directive.into());
            continue;
        }
        if !SINGLE.contains(&directive) {
            return Err(format!(
                "unknown dependency-affecting directive {directive} at line {}",
                line_index + 1
            ));
        }
        parse_go_workspace_directive(
            directive,
            remainder,
            &mut use_paths,
            &mut replacements,
            line_index + 1,
        )?;
    }
    if let Some(group) = group {
        return Err(format!("unterminated {group} block"));
    }
    Ok((use_paths, replacements))
}

fn parse_go_workspace_directive(
    directive: &str,
    body: &str,
    use_paths: &mut BTreeSet<String>,
    replacements: &mut BTreeMap<String, String>,
    line_number: usize,
) -> Result<(), String> {
    match directive {
        "use" => {
            let mut tokens = body.split_whitespace();
            let path = tokens
                .next()
                .ok_or_else(|| format!("use directive is empty at line {line_number}"))?;
            if tokens.next().is_some() {
                return Err(format!(
                    "use directive has excess tokens at line {line_number}"
                ));
            }
            use_paths.insert(path.into());
        }
        "replace" => {
            let (left, right) = body
                .split_once("=>")
                .ok_or_else(|| format!("replace directive has no => at line {line_number}"))?;
            let old = left
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("replace source is empty at line {line_number}"))?;
            let new = right
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("replace target is empty at line {line_number}"))?;
            if replacements.insert(old.into(), new.into()).is_some() {
                return Err(format!(
                    "replace source {old} is duplicated at line {line_number}"
                ));
            }
        }
        "go" | "toolchain" | "godebug" => {}
        other => {
            return Err(format!(
                "unsupported workspace directive {other} at line {line_number}"
            ));
        }
    }
    Ok(())
}

fn parse_go_module_directive(
    directive: &str,
    body: &str,
    module_path: &mut Option<String>,
    required_module_paths: &mut BTreeSet<String>,
    replacements: &mut BTreeMap<String, String>,
    line_number: usize,
) -> Result<(), String> {
    match directive {
        "module" => {
            let mut tokens = body.split_whitespace();
            let path = tokens
                .next()
                .ok_or_else(|| format!("module directive is empty at line {line_number}"))?;
            if tokens.next().is_some() || module_path.replace(path.into()).is_some() {
                return Err(format!(
                    "module directive must occur exactly once at line {line_number}"
                ));
            }
        }
        "require" => {
            let path = body
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("require directive is empty at line {line_number}"))?;
            required_module_paths.insert(path.into());
        }
        "replace" => {
            let (left, right) = body
                .split_once("=>")
                .ok_or_else(|| format!("replace directive has no => at line {line_number}"))?;
            let old = left
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("replace source is empty at line {line_number}"))?;
            let new = right
                .split_whitespace()
                .next()
                .ok_or_else(|| format!("replace target is empty at line {line_number}"))?;
            replacements.insert(old.into(), new.into());
        }
        "go" | "toolchain" | "exclude" | "retract" | "tool" | "godebug" => {}
        other => {
            return Err(format!(
                "unsupported dependency directive {other} at line {line_number}"
            ));
        }
    }
    Ok(())
}

fn canonical_unit_roots(
    root: &Path,
    units: &BTreeMap<ProjectUnitId, ProjectUnit>,
    project_unit_ids: &[ProjectUnitId],
    gaps: &mut BTreeSet<ProjectUnitDependencyGap>,
) -> BTreeMap<PathBuf, ProjectUnitId> {
    let mut roots = BTreeMap::new();
    for project_unit_id in project_unit_ids {
        let Some(unit) = units.get(project_unit_id) else {
            continue;
        };
        match std::fs::canonicalize(root.join(&unit.root_path)) {
            Ok(path) => {
                if let Some(existing) = roots.insert(path, project_unit_id.clone()) {
                    gaps.insert(dependency_gap(
                        "dependency_unit_root_ambiguous",
                        Some(project_unit_id.clone()),
                        if unit.root_path.is_empty() {
                            "<repository>"
                        } else {
                            &unit.root_path
                        },
                        format!("canonical root is also owned by {existing}"),
                    ));
                }
            }
            Err(error) => {
                gaps.insert(dependency_gap(
                    "dependency_unit_root_unreadable",
                    Some(project_unit_id.clone()),
                    if unit.root_path.is_empty() {
                        "<repository>"
                    } else {
                        &unit.root_path
                    },
                    error.to_string(),
                ));
            }
        }
    }
    roots
}

fn resolve_local_dependency_unit(
    root: &Path,
    declaration_directory: &Path,
    dependency_path: &str,
    allow_bare_relative_path: bool,
    unit_roots: &BTreeMap<PathBuf, ProjectUnitId>,
) -> Result<Option<ProjectUnitId>, String> {
    let path = Path::new(dependency_path);
    if dependency_path.trim().is_empty() {
        return Err("dependency path is empty".into());
    }
    if !allow_bare_relative_path && !path.is_absolute() && !dependency_path.starts_with('.') {
        return Ok(None);
    }
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(declaration_directory).join(path)
    };
    let canonical_root = std::fs::canonicalize(root)
        .map_err(|error| format!("canonicalize repository root: {error}"))?;
    let canonical_candidate = std::fs::canonicalize(&candidate)
        .map_err(|error| format!("canonicalize {}: {error}", candidate.display()))?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Ok(None);
    }
    unit_roots
        .get(&canonical_candidate)
        .cloned()
        .map(Some)
        .ok_or_else(|| {
            format!(
                "repository-local path {} has no indexed source-owning project unit",
                canonical_candidate.display()
            )
        })
}

fn dependency_gap(
    reason_code: &str,
    project_unit_id: Option<ProjectUnitId>,
    path: &str,
    detail: impl Into<String>,
) -> ProjectUnitDependencyGap {
    ProjectUnitDependencyGap {
        reason_code: reason_code.into(),
        project_unit_id,
        path: path.into(),
        detail: detail.into(),
    }
}

fn dependency_graph(
    language_id: LanguageId,
    ecosystem_id: EcosystemId,
    project_unit_ids: Vec<ProjectUnitId>,
    dependencies: BTreeSet<ProjectUnitDependency>,
    gaps: BTreeSet<ProjectUnitDependencyGap>,
) -> ProjectUnitDependencyGraph {
    ProjectUnitDependencyGraph {
        language_id,
        ecosystem_id,
        coverage: if gaps.is_empty() {
            ProjectUnitDependencyGraphCoverage::Complete
        } else {
            ProjectUnitDependencyGraphCoverage::Partial
        },
        project_unit_ids,
        dependencies: dependencies.into_iter().collect(),
        gaps: gaps.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn semantic_provider_inventory_fingerprint_is_language_scoped_and_non_vacuous() {
        let temporary = TempDir::new().expect("mixed inventory repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("rust/src")).expect("Rust source directory");
        std::fs::create_dir_all(root.join("go")).expect("Go source directory");
        std::fs::write(
            root.join("rust/Cargo.toml"),
            "[package]\nname = \"mixed-rust\"\nversion = \"0.1.0\"\n",
        )
        .expect("Rust manifest");
        std::fs::write(root.join("rust/src/lib.rs"), "pub fn rust_item() {}\n")
            .expect("Rust source");
        std::fs::write(root.join("go/go.mod"), "module example.invalid/mixed-go\n")
            .expect("Go manifest");
        std::fs::write(root.join("go/main.go"), "package main\nfunc main() {}\n")
            .expect("Go source");
        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("rust/src/lib.rs", "rust"),
                InventorySource::new("go/main.go", "go"),
            ],
        );
        let global = project_inventory_fingerprint(&inventory).expect("global inventory");
        let rust = semantic_provider_inventory_fingerprint(&inventory, "rust", "cargo")
            .expect("Rust provider inventory");
        let go = semantic_provider_inventory_fingerprint(&inventory, "go", "go")
            .expect("Go provider inventory");

        let mut go_drift = inventory.clone();
        let go_manifest = go_drift
            .inputs
            .iter_mut()
            .find(|input| input.path == "go/go.mod")
            .expect("Go manifest input");
        go_manifest.content_sha256 = "a".repeat(64);
        assert_ne!(
            project_inventory_fingerprint(&go_drift).expect("Go-drift global inventory"),
            global,
            "positive control: global inventory must observe Go drift"
        );
        assert_eq!(
            semantic_provider_inventory_fingerprint(&go_drift, "rust", "cargo")
                .expect("Rust inventory after Go drift"),
            rust,
            "Go-only input drift must not perturb Rust provider authority"
        );
        assert_ne!(
            semantic_provider_inventory_fingerprint(&go_drift, "go", "go")
                .expect("Go inventory after Go drift"),
            go,
            "positive control: Go provider authority must observe its own input drift"
        );

        let mut rust_drift = inventory;
        let rust_manifest = rust_drift
            .inputs
            .iter_mut()
            .find(|input| input.path == "rust/Cargo.toml")
            .expect("Rust manifest input");
        rust_manifest.content_sha256 = "b".repeat(64);
        assert_ne!(
            semantic_provider_inventory_fingerprint(&rust_drift, "rust", "cargo")
                .expect("Rust inventory after Rust drift"),
            rust,
            "positive control: Rust provider authority must observe its own input drift"
        );
        assert_eq!(
            semantic_provider_inventory_fingerprint(&rust_drift, "go", "go")
                .expect("Go inventory after Rust drift"),
            go,
            "Rust-only input drift must not perturb Go provider authority"
        );
    }

    #[test]
    fn nested_cargo_source_has_package_owner_and_workspace_context() {
        let temporary = TempDir::new().expect("temporary repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("crates/member/src")).expect("member source directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/member\"]\n",
        )
        .expect("workspace manifest");
        std::fs::write(
            root.join("crates/member/Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\n",
        )
        .expect("member manifest");
        std::fs::write(
            root.join("crates/member/src/lib.rs"),
            "pub fn member() {}\n",
        )
        .expect("member crate root");

        let inventory = build_project_inventory(
            root,
            &[InventorySource::new("crates/member/src/lib.rs", "rust")],
        );

        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        );
        assert_eq!(inventory.project_topology.units.len(), 2);
        assert_eq!(inventory.project_topology.memberships.len(), 2);
        let owner = inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
            .expect("one source owner");
        assert!(
            owner
                .project_unit_id
                .0
                .contains(":package:crates/member/Cargo.toml")
        );
        let context = inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| membership.kind == DocumentMembershipKind::PathContext)
            .expect("workspace context");
        assert!(context.project_unit_id.0.contains(":workspace:Cargo.toml"));

        let projection = project_unit_graph(&inventory, ["crates/member/src/lib.rs"]);
        assert_eq!(projection.units.len(), 2);
        assert_eq!(projection.memberships.len(), 2);
        assert_eq!(projection.relationships.len(), 1);
    }

    /// FALSIFIER for the old flat domain: `requirements.txt` constrains an
    /// environment but does not identify a physical Python package, exact
    /// import root, or interpreter context. It must remain an observed input
    /// while source ownership and analysis authority stay honestly separate.
    #[test]
    fn python_requirements_control_is_not_a_physical_project_unit() {
        let temporary = TempDir::new().expect("requirements Python repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("app")).expect("application package");
        std::fs::create_dir_all(root.join("tests")).expect("test package");
        std::fs::write(root.join("requirements.txt"), "fastapi==1\n")
            .expect("requirements manifest");
        std::fs::write(root.join("pytest.ini"), "[pytest]\n").expect("test configuration");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("app/service.py", "python"),
                InventorySource::new("tests/test_service.py", "python"),
            ],
        );
        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        );
        assert!(inventory.issues.is_empty());
        let [owner] = inventory.project_topology.units.as_slice() else {
            panic!("requirements-only source population must have one physical owner");
        };
        assert_eq!(owner.language_id, LanguageId::new("python"));
        assert_eq!(owner.kind, ProjectUnitKind::LooseSources);
        assert!(owner.manifest_path.is_none());
        let owned_documents = inventory
            .project_topology
            .memberships
            .iter()
            .filter(|membership| {
                membership.project_unit_id == owner.project_unit_id
                    && membership.kind == DocumentMembershipKind::SourceOwner
            })
            .map(|membership| membership.document_path.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            owned_documents,
            BTreeSet::from(["app/service.py", "tests/test_service.py"])
        );
        assert!(
            inventory.project_topology.dependency_graphs.is_empty(),
            "environment controls cannot manufacture physical dependency authority"
        );
        assert!(inventory.inputs.iter().any(|input| {
            input.path == "requirements.txt"
                && input.language_id == LanguageId::new("python")
                && input.role == ProjectInputRole::Manifest
        }));
        let [analysis] = inventory.analysis_context_graphs.as_slice() else {
            panic!("one Python analysis-context graph expected");
        };
        assert_eq!(
            analysis.coverage,
            AnalysisContextCoverage::DeclaredConfigurationPartial
        );
        assert!(
            analysis
                .gaps
                .iter()
                .any(|gap| { gap.reason_code == "python_analysis_context_resolution_unavailable" })
        );
    }

    /// FALSIFIER from the clean uv/polyglot corpus: the root pyproject is a
    /// workspace context with `package = false`, while the member pyproject is
    /// the semantic source owner. An explicitly excluded sibling remains an
    /// independent package, and a root tooling script is visible structural
    /// source but must not silently join either package.
    #[test]
    fn python_uv_workspace_separates_member_owner_from_loose_root_script() {
        let temporary = TempDir::new().expect("uv Python workspace");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("apps/agents/src/aegis_agents"))
            .expect("member source package");
        std::fs::create_dir_all(root.join("apps/excluded/src/excluded"))
            .expect("excluded source package");
        std::fs::create_dir_all(root.join("scripts")).expect("root scripts");
        std::fs::write(
            root.join("pyproject.toml"),
            "[project]\nname = \"root\"\nversion = \"0.0.0\"\n\n[tool.uv]\npackage = false\n\n[tool.uv.workspace]\nmembers = [\"apps/*\"]\nexclude = [\"apps/excluded\"]\n",
        )
        .expect("uv workspace manifest");
        std::fs::write(root.join("uv.lock"), "version = 1\n").expect("uv lockfile");
        std::fs::write(
            root.join("apps/agents/pyproject.toml"),
            "[project]\nname = \"aegis-agents\"\nversion = \"0.0.0\"\n\n[tool.hatch.build.targets.wheel]\npackages = [\"src/aegis_agents\"]\n",
        )
        .expect("member package manifest");
        std::fs::write(
            root.join("apps/excluded/pyproject.toml"),
            "[project]\nname = \"excluded\"\nversion = \"0.0.0\"\n",
        )
        .expect("excluded package manifest");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("apps/agents/src/aegis_agents/service.py", "python"),
                InventorySource::new("apps/excluded/src/excluded/service.py", "python"),
                InventorySource::new("scripts/tool.py", "python"),
            ],
        );
        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        );
        assert!(inventory.issues.is_empty());
        let workspace = inventory
            .project_topology
            .units
            .iter()
            .find(|unit| {
                unit.language_id.0 == "python"
                    && unit.kind == ProjectUnitKind::Workspace
                    && unit.root_path.is_empty()
                    && unit.manifest_path.as_deref() == Some("pyproject.toml")
            })
            .expect("uv workspace unit");
        let package = inventory
            .project_topology
            .units
            .iter()
            .find(|unit| {
                unit.language_id.0 == "python"
                    && unit.kind == ProjectUnitKind::Package
                    && unit.root_path == "apps/agents"
                    && unit.manifest_path.as_deref() == Some("apps/agents/pyproject.toml")
            })
            .expect("uv member package");
        let excluded = inventory
            .project_topology
            .units
            .iter()
            .find(|unit| {
                unit.language_id.0 == "python"
                    && unit.kind == ProjectUnitKind::Package
                    && unit.root_path == "apps/excluded"
                    && unit.manifest_path.as_deref() == Some("apps/excluded/pyproject.toml")
            })
            .expect("excluded package");
        let loose = inventory
            .project_topology
            .units
            .iter()
            .find(|unit| {
                unit.language_id.0 == "python" && unit.kind == ProjectUnitKind::LooseSources
            })
            .expect("loose root Python source unit");
        assert!(
            inventory
                .project_topology
                .memberships
                .iter()
                .any(|membership| {
                    membership.document_path == "apps/agents/src/aegis_agents/service.py"
                        && membership.project_unit_id == package.project_unit_id
                        && membership.kind == DocumentMembershipKind::SourceOwner
                })
        );
        assert!(
            inventory
                .project_topology
                .memberships
                .iter()
                .any(|membership| {
                    membership.document_path == "apps/agents/src/aegis_agents/service.py"
                        && membership.project_unit_id == workspace.project_unit_id
                        && membership.kind == DocumentMembershipKind::PathContext
                })
        );
        assert!(
            inventory
                .project_topology
                .memberships
                .iter()
                .any(|membership| {
                    membership.document_path == "scripts/tool.py"
                        && membership.project_unit_id == loose.project_unit_id
                        && membership.kind == DocumentMembershipKind::SourceOwner
                })
        );
        assert!(
            !inventory
                .project_topology
                .memberships
                .iter()
                .any(|membership| {
                    membership.document_path == "scripts/tool.py"
                        && membership.project_unit_id == package.project_unit_id
                }),
            "path containment must not smuggle a root script into the member package"
        );
        assert!(
            inventory
                .project_topology
                .relationships
                .iter()
                .any(|relationship| {
                    relationship.parent_project_unit_id == workspace.project_unit_id
                        && relationship.child_project_unit_id == package.project_unit_id
                        && relationship.kind == ProjectUnitRelationshipKind::WorkspaceMember
                })
        );
        assert!(
            !inventory
                .project_topology
                .relationships
                .iter()
                .any(|relationship| {
                    relationship.parent_project_unit_id == workspace.project_unit_id
                        && relationship.child_project_unit_id == excluded.project_unit_id
                        && relationship.kind == ProjectUnitRelationshipKind::WorkspaceMember
                })
        );
        let execution_roots =
            semantic_provider_unit_execution_roots(&inventory, "python", "python");
        assert_eq!(
            execution_roots.get(&package.project_unit_id),
            Some(&PathBuf::new()),
            "declared member runs from the uv workspace root"
        );
        assert_eq!(
            execution_roots.get(&excluded.project_unit_id),
            Some(&PathBuf::from("apps/excluded")),
            "an explicitly excluded package must retain its own provider root"
        );
    }

    #[test]
    fn project_inventory_adapter_registry_is_unique_and_non_vacuous() {
        let languages = PROJECT_INVENTORY_ADAPTERS
            .iter()
            .map(|adapter| adapter.language())
            .collect::<BTreeSet<_>>();
        assert!(
            !languages.is_empty(),
            "positive control: the project-inventory adapter population must be non-empty"
        );
        assert_eq!(
            languages.len(),
            PROJECT_INVENTORY_ADAPTERS.len(),
            "one language must not silently resolve through multiple project-inventory adapters"
        );
        for language in ["rust", "go", "python", "typescript"] {
            assert!(
                project_inventory_adapter(language).is_some(),
                "known-positive adapter is unreachable: {language}"
            );
        }
        assert!(
            project_inventory_adapter("unregistered-language-control").is_none(),
            "negative control: unknown languages must fail closed"
        );
    }

    #[test]
    fn malformed_python_control_cannot_fall_through_to_requirements_ownership() {
        let temporary = TempDir::new().expect("malformed Python repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("app")).expect("Python source directory");
        std::fs::write(root.join("app/pyproject.toml"), "[project\n")
            .expect("malformed Python control");
        std::fs::write(root.join("requirements.txt"), "fastapi==1\n")
            .expect("broader ancestor requirements control");

        let inventory =
            build_project_inventory(root, &[InventorySource::new("app/service.py", "python")]);

        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        );
        assert!(inventory.issues.iter().any(|issue| {
            issue.code == "manifest_invalid" && issue.path == "app/pyproject.toml"
        }));
        let requirements_unit = inventory
            .project_topology
            .units
            .iter()
            .find(|unit| unit.manifest_path.as_deref() == Some("requirements.txt"));
        assert!(
            requirements_unit.is_none_or(|unit| {
                !inventory
                    .project_topology
                    .memberships
                    .iter()
                    .any(|membership| {
                        membership.project_unit_id == unit.project_unit_id
                            && membership.kind == DocumentMembershipKind::SourceOwner
                    })
            }),
            "an invalid nearer control must block broader ancestor ownership fallback"
        );
        let owner = inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
            .expect("structural source owner");
        assert!(inventory.project_topology.units.iter().any(|unit| {
            unit.project_unit_id == owner.project_unit_id
                && unit.kind == ProjectUnitKind::LooseSources
        }));
    }

    /// FALSIFIER: a symlinked project control is present but is not immutable,
    /// repository-local authority. Treating it as absent lets an unrelated
    /// lower-priority file claim the source and hides why authority was denied.
    #[cfg(unix)]
    #[test]
    fn unsafe_python_control_cannot_fall_through_to_requirements_ownership() {
        use std::os::unix::fs::symlink;

        let temporary = TempDir::new().expect("unsafe Python repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("app")).expect("Python source directory");
        std::fs::write(
            root.join("actual-project.toml"),
            "[project]\nname = \"unsafe-control\"\nversion = \"0.1.0\"\n",
        )
        .expect("symlink target");
        symlink("actual-project.toml", root.join("pyproject.toml"))
            .expect("symlinked Python control");
        std::fs::write(root.join("requirements.txt"), "fastapi==1\n")
            .expect("lower-priority requirements control");

        let inventory =
            build_project_inventory(root, &[InventorySource::new("app/service.py", "python")]);

        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        );
        assert!(
            inventory
                .issues
                .iter()
                .any(|issue| { issue.code == "manifest_unsafe" && issue.path == "pyproject.toml" }),
            "the inventory must preserve the exact unsafe-control reason"
        );
        assert!(
            !inventory
                .project_topology
                .units
                .iter()
                .any(|unit| { unit.manifest_path.as_deref() == Some("requirements.txt") }),
            "an unsafe higher-priority control must block lower-priority ownership fallback"
        );
        let owner = inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
            .expect("structural source owner");
        assert!(inventory.project_topology.units.iter().any(|unit| {
            unit.project_unit_id == owner.project_unit_id
                && unit.kind == ProjectUnitKind::LooseSources
        }));
    }

    #[test]
    fn multiple_python_units_report_exact_dependency_authority_gap() {
        let temporary = TempDir::new().expect("multi-package Python repository");
        let root = temporary.path();
        for package in ["alpha", "beta"] {
            std::fs::create_dir_all(root.join(package).join("src")).expect("package source");
            std::fs::write(
                root.join(package).join("pyproject.toml"),
                format!("[project]\nname = \"{package}\"\nversion = \"0.1.0\"\n"),
            )
            .expect("package manifest");
        }

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("alpha/src/alpha.py", "python"),
                InventorySource::new("beta/src/beta.py", "python"),
            ],
        );

        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        );
        let [dependency_graph] = inventory.project_topology.dependency_graphs.as_slice() else {
            panic!("one populated Python dependency graph expected");
        };
        assert_eq!(dependency_graph.project_unit_ids.len(), 2);
        assert_eq!(
            dependency_graph.coverage,
            ProjectUnitDependencyGraphCoverage::Partial
        );
        assert_eq!(
            dependency_graph
                .gaps
                .iter()
                .filter(|gap| gap.reason_code == "python_local_dependency_resolution_unavailable")
                .count(),
            2,
            "each unsupported independent package must retain its own typed authority gap"
        );
        assert_eq!(
            dependency_graph
                .gaps
                .iter()
                .filter_map(|gap| gap.project_unit_id.as_ref())
                .collect::<BTreeSet<_>>()
                .len(),
            2,
            "the gap population must bind both source-owning units"
        );
        assert!(dependency_graph.dependencies.is_empty());
    }

    /// FALSIFIER for the blanket Python dependency gap: uv requires every
    /// workspace-local dependency to be named in the ordinary dependency
    /// tables and explicitly redirected through `tool.uv.sources`. Those two
    /// declarations plus an exact member set are sufficient to prove one
    /// directed local edge without invoking an interpreter.
    #[test]
    fn python_uv_workspace_has_exact_local_dependency_direction() {
        let temporary = TempDir::new().expect("uv dependency workspace");
        let root = temporary.path();
        for package in ["api", "core", "path-lib", "independent"] {
            std::fs::create_dir_all(root.join("packages").join(package).join("src"))
                .expect("package source directory");
        }
        std::fs::write(
            root.join("pyproject.toml"),
            "[project]\nname = \"root\"\nversion = \"0.0.0\"\ndependencies = []\n\n[tool.uv]\npackage = false\n\n[tool.uv.workspace]\nmembers = [\"packages/*\"]\n\n[tool.uv.sources]\ncore = { workspace = true }\n",
        )
        .expect("uv workspace manifest");
        std::fs::write(
            root.join("packages/api/pyproject.toml"),
            "[project]\nname = \"api\"\nversion = \"0.0.0\"\ndependencies = [\"core>=1\", \"path-lib\", \"httpx>=1\"]\n\n[tool.uv.sources]\n\"path.lib\" = { path = \"../path-lib\" }\n",
        )
        .expect("API manifest");
        for (directory, name) in [
            ("core", "core"),
            ("path-lib", "path_lib"),
            ("independent", "independent"),
        ] {
            std::fs::write(
                root.join("packages").join(directory).join("pyproject.toml"),
                format!("[project]\nname = \"{name}\"\nversion = \"0.0.0\"\ndependencies = []\n"),
            )
            .expect("package manifest");
        }

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("packages/api/src/api.py", "python"),
                InventorySource::new("packages/core/src/core.py", "python"),
                InventorySource::new("packages/path-lib/src/path_lib.py", "python"),
                InventorySource::new("packages/independent/src/independent.py", "python"),
            ],
        );
        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        );
        let [dependency_graph] = inventory.project_topology.dependency_graphs.as_slice() else {
            panic!("one populated Python dependency graph expected");
        };
        assert_eq!(
            dependency_graph.project_unit_ids.len(),
            4,
            "population control"
        );
        assert_eq!(
            dependency_graph.coverage,
            ProjectUnitDependencyGraphCoverage::Complete,
            "an exact uv declaration must replace the blanket Python gap: {:?}",
            dependency_graph.gaps
        );
        assert!(dependency_graph.gaps.is_empty());
        let unit_at = |root_path: &str| {
            inventory
                .project_topology
                .units
                .iter()
                .find(|unit| unit.kind == ProjectUnitKind::Package && unit.root_path == root_path)
                .expect("Python package unit")
                .project_unit_id
                .clone()
        };
        assert_eq!(
            dependency_graph.dependencies,
            vec![
                ProjectUnitDependency {
                    dependent_project_unit_id: unit_at("packages/api"),
                    dependency_project_unit_id: unit_at("packages/core"),
                },
                ProjectUnitDependency {
                    dependent_project_unit_id: unit_at("packages/api"),
                    dependency_project_unit_id: unit_at("packages/path-lib"),
                }
            ],
            "remote and independent packages must not become local dependency edges"
        );
        let [workspace_id] = inventory
            .project_topology
            .exact_workspace_member_sets
            .as_slice()
        else {
            panic!("one exact uv workspace member set expected");
        };
        assert!(inventory.project_topology.units.iter().any(|unit| {
            unit.project_unit_id == *workspace_id && unit.kind == ProjectUnitKind::Workspace
        }));
        let canonical = canonical_project_inventory_bytes(&inventory)
            .expect("canonical exact-workspace inventory");
        assert_eq!(
            parse_project_inventory_bytes(&canonical).expect("exact-workspace round trip"),
            inventory
        );

        let mut duplicate = inventory.clone();
        duplicate
            .project_topology
            .exact_workspace_member_sets
            .push(workspace_id.clone());
        let error = canonical_project_inventory_bytes(&duplicate)
            .expect_err("duplicate exact member-set authority must fail closed");
        assert!(error.to_string().contains("must not contain duplicates"));

        let mut unproven_relationships = inventory.clone();
        unproven_relationships
            .project_topology
            .exact_workspace_member_sets
            .clear();
        let error = canonical_project_inventory_bytes(&unproven_relationships)
            .expect_err("workspace edges cannot outlive their exact member-set proof");
        assert!(
            error
                .to_string()
                .contains("workspace membership has no exact member-set authority")
        );

        let mut wrong_kind = inventory.clone();
        wrong_kind.project_topology.exact_workspace_member_sets = vec![unit_at("packages/api")];
        let error = canonical_project_inventory_bytes(&wrong_kind)
            .expect_err("a package cannot impersonate exact workspace authority");
        assert!(error.to_string().contains("non-workspace project unit"));
    }

    #[test]
    fn python_uv_conditional_local_source_is_typed_partial_not_guessed() {
        let temporary = TempDir::new().expect("conditional uv source workspace");
        let root = temporary.path();
        for package in ["api", "core"] {
            std::fs::create_dir_all(root.join("packages").join(package).join("src"))
                .expect("package source directory");
            std::fs::write(
                root.join("packages").join(package).join("pyproject.toml"),
                format!(
                    "[project]\nname = \"{package}\"\nversion = \"0.0.0\"\ndependencies = {}\n",
                    if package == "api" { "[\"core\"]" } else { "[]" }
                ),
            )
            .expect("package manifest");
        }
        std::fs::write(
            root.join("pyproject.toml"),
            "[project]\nname = \"root\"\nversion = \"0.0.0\"\n\n[tool.uv]\npackage = false\n\n[tool.uv.workspace]\nmembers = [\"packages/*\"]\n\n[tool.uv.sources]\ncore = [\n  { workspace = true, marker = \"sys_platform == 'linux'\" },\n  { index = \"pypi\", marker = \"sys_platform != 'linux'\" },\n]\n",
        )
        .expect("conditional workspace source");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("packages/api/src/api.py", "python"),
                InventorySource::new("packages/core/src/core.py", "python"),
            ],
        );
        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            "physical topology remains exact"
        );
        assert_eq!(
            inventory
                .project_topology
                .relationships
                .iter()
                .filter(|relationship| {
                    relationship.kind == ProjectUnitRelationshipKind::WorkspaceMember
                })
                .count(),
            2,
            "positive exact-membership control"
        );
        let [dependency_graph] = inventory.project_topology.dependency_graphs.as_slice() else {
            panic!("one Python dependency graph expected");
        };
        assert_eq!(
            dependency_graph.coverage,
            ProjectUnitDependencyGraphCoverage::Partial
        );
        assert!(dependency_graph.dependencies.is_empty());
        assert!(dependency_graph.gaps.iter().any(|gap| {
            gap.reason_code == "python_uv_conditional_local_source_unresolved"
                && gap.project_unit_id.is_some()
                && gap.path == "pyproject.toml"
        }));
    }

    /// FALSIFIER from the representative pnpm monorepo corpora: project
    /// ownership comes from package/workspace controls, overlapping tsconfigs
    /// remain non-owning context, and only an explicit `workspace:` dependency
    /// may create a directed local dependency edge. Path aliases and exports
    /// are immutable inputs, not permission to guess package relationships.
    #[test]
    fn typescript_pnpm_workspace_has_exact_owners_context_and_dependency_direction() {
        let temporary = TempDir::new().expect("pnpm TypeScript workspace");
        let root = temporary.path();
        for directory in ["apps/web/src", "packages/ui/src"] {
            std::fs::create_dir_all(root.join(directory)).expect("package source directory");
        }
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"@fixture/root","private":true,"type":"module"}"#,
        )
        .expect("workspace root package");
        std::fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'apps/*'\n  - 'packages/*'\n",
        )
        .expect("workspace manifest");
        std::fs::write(
            root.join("tsconfig.json"),
            "{\n  // shared alias is configuration, not a dependency edge\n  \"compilerOptions\": {\"paths\": {\"@ui/*\": [\"packages/ui/src/*\"]}},\n}\n",
        )
        .expect("root JSONC configuration");
        std::fs::write(
            root.join("apps/web/package.json"),
            r#"{"name":"@fixture/web","private":true,"dependencies":{"@fixture/ui":"workspace:*"}}"#,
        )
        .expect("web package manifest");
        std::fs::write(
            root.join("apps/web/tsconfig.json"),
            "{\n  \"extends\": \"../../tsconfig.json\",\n  \"include\": [\"src\"],\n}\n",
        )
        .expect("web JSONC configuration");
        std::fs::write(
            root.join("packages/ui/package.json"),
            r#"{"name":"@fixture/ui","private":true,"exports":{".":"./src/index.ts","./theme.css":"./src/theme.css"}}"#,
        )
        .expect("UI package manifest");
        std::fs::write(
            root.join("packages/ui/tsconfig.build.json"),
            "{\n  \"extends\": \"../../tsconfig.json\",\n  \"include\": [\"src\"],\n}\n",
        )
        .expect("UI JSONC configuration");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("apps/web/src/main.ts", "typescript"),
                InventorySource::new("packages/ui/src/index.ts", "typescript"),
            ],
        );

        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            "a fully described pnpm workspace must not remain unregistered or partial: {:?}",
            inventory.issues
        );
        assert!(inventory.issues.is_empty());
        let unit_at = |root_path: &str, kind: ProjectUnitKind| {
            inventory
                .project_topology
                .units
                .iter()
                .find(|unit| unit.root_path == root_path && unit.kind == kind)
                .expect("expected TypeScript project unit")
        };
        let workspace = unit_at("", ProjectUnitKind::Workspace);
        let web = unit_at("apps/web", ProjectUnitKind::Package);
        let ui = unit_at("packages/ui", ProjectUnitKind::Package);
        for package in [web, ui] {
            assert!(
                inventory
                    .project_topology
                    .relationships
                    .iter()
                    .any(|relationship| {
                        relationship.parent_project_unit_id == workspace.project_unit_id
                            && relationship.child_project_unit_id == package.project_unit_id
                            && relationship.kind == ProjectUnitRelationshipKind::WorkspaceMember
                    })
            );
        }
        for (document, owner) in [
            ("apps/web/src/main.ts", web),
            ("packages/ui/src/index.ts", ui),
        ] {
            assert!(
                inventory
                    .project_topology
                    .memberships
                    .iter()
                    .any(|membership| {
                        membership.document_path == document
                            && membership.project_unit_id == owner.project_unit_id
                            && membership.kind == DocumentMembershipKind::SourceOwner
                    })
            );
            assert!(
                inventory
                    .project_topology
                    .memberships
                    .iter()
                    .any(|membership| {
                        membership.document_path == document
                            && membership.project_unit_id == workspace.project_unit_id
                            && membership.kind == DocumentMembershipKind::PathContext
                    })
            );
        }
        assert!(inventory.project_topology.units.iter().all(|unit| {
            unit.manifest_path.as_deref().is_none_or(|path| {
                !path
                    .rsplit('/')
                    .next()
                    .is_some_and(is_typescript_configuration_name)
            })
        }));
        let [analysis] = inventory.analysis_context_graphs.as_slice() else {
            panic!("one TypeScript analysis-context graph expected");
        };
        assert_eq!(
            analysis.coverage,
            AnalysisContextCoverage::DeclaredConfigurationComplete
        );
        assert_eq!(
            analysis.contexts.len(),
            3,
            "positive overlapping-config control"
        );
        assert_eq!(
            analysis.relationships.len(),
            2,
            "two explicit extends edges"
        );
        assert_eq!(
            analysis.memberships.len(),
            4,
            "root context selects both documents and each package context selects its own"
        );

        let [dependency_graph] = inventory.project_topology.dependency_graphs.as_slice() else {
            panic!("one populated TypeScript dependency graph expected");
        };
        assert_eq!(
            dependency_graph.coverage,
            ProjectUnitDependencyGraphCoverage::Complete
        );
        assert!(dependency_graph.gaps.is_empty());
        assert_eq!(
            dependency_graph.dependencies,
            vec![ProjectUnitDependency {
                dependent_project_unit_id: web.project_unit_id.clone(),
                dependency_project_unit_id: ui.project_unit_id.clone(),
            }],
            "paths/exports must not manufacture any additional local edge"
        );
        for path in [
            "package.json",
            "pnpm-workspace.yaml",
            "tsconfig.json",
            "apps/web/package.json",
            "apps/web/tsconfig.json",
            "packages/ui/package.json",
            "packages/ui/tsconfig.build.json",
        ] {
            assert!(
                inventory.inputs.iter().any(|input| input.path == path),
                "project input is absent from immutable authority: {path}"
            );
        }
        assert_eq!(
            semantic_provider_execution_roots(&inventory, "typescript", "node"),
            vec![PathBuf::new()],
            "explicit pnpm membership, not path containment, governs the future provider root"
        );
    }

    /// FALSIFIER for the old flat inventory domain: package/workspace topology
    /// and compiler/interpreter contexts are different facts and must cross the
    /// immutable publication boundary in separately named structures.
    #[test]
    fn canonical_inventory_separates_project_and_analysis_context_topology() {
        let temporary = TempDir::new().expect("separated topology repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"separated-topology","private":true}"#,
        )
        .expect("package manifest");
        std::fs::write(root.join("tsconfig.json"), r#"{"include":["src"]}"#)
            .expect("TypeScript configuration");

        let inventory =
            build_project_inventory(root, &[InventorySource::new("src/main.ts", "typescript")]);
        let bytes = canonical_project_inventory_bytes(&inventory).expect("canonical inventory");
        let document = serde_json::from_slice::<serde_json::Value>(&bytes)
            .expect("canonical inventory document");
        let persisted = document
            .get("inventory")
            .and_then(serde_json::Value::as_object)
            .expect("persisted inventory object");

        assert!(
            persisted.get("project_topology").is_some(),
            "package/workspace topology must have an explicit persisted owner"
        );
        assert!(
            persisted.get("analysis_context_graphs").is_some(),
            "analysis contexts must not be smuggled through project units"
        );
        for legacy_flat_field in ["units", "memberships", "relationships", "dependency_graphs"] {
            assert!(
                persisted.get(legacy_flat_field).is_none(),
                "flat topology field must be removed: {legacy_flat_field}"
            );
        }
    }

    /// FALSIFIER from AEGIS and ERA: the same source is a declared root of a
    /// root-wide TypeScript context and a package-local context, while package
    /// ownership remains singular. Declared roots schedule/qualify later
    /// provider work; they are not themselves semantic authority.
    #[test]
    fn typescript_declared_context_membership_is_plural_but_package_owner_is_singular() {
        let temporary = TempDir::new().expect("overlapping TypeScript contexts");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("apps/web/src")).expect("web source directory");
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"@fixture/root","private":true}"#,
        )
        .expect("root package manifest");
        std::fs::write(
            root.join("apps/web/package.json"),
            r#"{"name":"@fixture/web","private":true}"#,
        )
        .expect("web package manifest");
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{"include":["apps/**/*.ts"],"exclude":["**/dist/**"]}"#,
        )
        .expect("root TypeScript configuration");
        std::fs::write(
            root.join("apps/web/tsconfig.json"),
            r#"{"extends":"../../tsconfig.json","include":["src"]}"#,
        )
        .expect("web TypeScript configuration");

        let inventory = build_project_inventory(
            root,
            &[InventorySource::new("apps/web/src/main.ts", "typescript")],
        );
        assert_eq!(
            inventory
                .project_topology
                .memberships
                .iter()
                .filter(|membership| {
                    membership.document_path == "apps/web/src/main.ts"
                        && membership.kind == DocumentMembershipKind::SourceOwner
                })
                .count(),
            1,
            "positive control: package ownership remains singular"
        );

        let bytes = canonical_project_inventory_bytes(&inventory).expect("canonical inventory");
        let document = serde_json::from_slice::<serde_json::Value>(&bytes)
            .expect("canonical inventory document");
        let graphs = document["inventory"]["analysis_context_graphs"]
            .as_array()
            .expect("analysis-context graph population");
        let graph = graphs
            .iter()
            .find(|graph| graph["language_id"] == "typescript")
            .expect("TypeScript analysis-context graph");
        assert_eq!(graph["coverage"], "declared_configuration_complete");
        assert_eq!(
            graph["memberships"]
                .as_array()
                .expect("declared context memberships")
                .iter()
                .filter(|membership| {
                    membership["document_path"] == "apps/web/src/main.ts"
                        && membership["kind"] == "declared_root"
                })
                .count(),
            2,
            "one source must retain both root and package-local configured contexts"
        );
    }

    /// FALSIFIER: malformed explicit `files` entries are configuration gaps,
    /// not an authoritative complete context with an accidentally empty root
    /// population.
    #[test]
    fn typescript_invalid_files_selector_is_a_typed_gap() {
        let temporary = TempDir::new().expect("invalid TypeScript files selector");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(root.join("tsconfig.json"), r#"{"files":["../outside.ts"]}"#)
            .expect("TypeScript configuration");

        let inventory =
            build_project_inventory(root, &[InventorySource::new("src/main.ts", "typescript")]);
        let [graph] = inventory.analysis_context_graphs.as_slice() else {
            panic!("one TypeScript analysis-context graph expected");
        };
        assert_eq!(
            graph.coverage,
            AnalysisContextCoverage::DeclaredConfigurationPartial
        );
        assert!(graph.gaps.iter().any(|gap| {
            gap.reason_code == "typescript_root_selection_invalid"
                && gap.detail.contains("escapes the repository")
        }));
        assert!(graph.memberships.is_empty());
    }

    /// TypeScript's explicit `exclude` replaces its defaults, while `files`
    /// bypasses `exclude` entirely and `allowJs` expands the selected extension
    /// population. These are declared roots only, not proof of transitive
    /// compiler-program membership.
    #[test]
    fn typescript_files_and_explicit_exclude_follow_compiler_root_semantics() {
        let temporary = TempDir::new().expect("TypeScript selector semantics");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(root.join("node_modules/pkg")).expect("dependency directory");
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{
                "files":["src/forced.ts"],
                "include":["node_modules/**/*"],
                "exclude":[],
                "compilerOptions":{"allowJs":true}
            }"#,
        )
        .expect("TypeScript configuration");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("src/forced.ts", "typescript"),
                InventorySource::new("node_modules/pkg/index.js", "typescript"),
            ],
        );
        let [graph] = inventory.analysis_context_graphs.as_slice() else {
            panic!("one TypeScript analysis-context graph expected");
        };
        assert_eq!(
            graph.coverage,
            AnalysisContextCoverage::DeclaredConfigurationComplete
        );
        assert_eq!(
            graph
                .memberships
                .iter()
                .map(|membership| membership.document_path.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["node_modules/pkg/index.js", "src/forced.ts"])
        );
    }

    #[test]
    fn typescript_extends_preserves_selector_origins_and_field_overrides() {
        let temporary = TempDir::new().expect("TypeScript inherited selectors");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("shared")).expect("shared source directory");
        std::fs::create_dir_all(root.join("apps/web/src")).expect("web source directory");
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{"include":["**/*"],"exclude":["shared/**/*.test.ts"]}"#,
        )
        .expect("base TypeScript configuration");
        std::fs::write(
            root.join("apps/web/tsconfig.json"),
            r#"{"extends":"../../tsconfig.json","exclude":["src/**/*.test.ts"]}"#,
        )
        .expect("web TypeScript configuration");
        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("shared/lib.ts", "typescript"),
                InventorySource::new("shared/lib.test.ts", "typescript"),
                InventorySource::new("apps/web/src/main.ts", "typescript"),
                InventorySource::new("apps/web/src/main.test.ts", "typescript"),
            ],
        );
        let [graph] = inventory.analysis_context_graphs.as_slice() else {
            panic!("one TypeScript analysis-context graph expected");
        };
        assert_eq!(
            graph.coverage,
            AnalysisContextCoverage::DeclaredConfigurationComplete
        );
        let selected_by = |configuration_path: &str| {
            let context = graph
                .contexts
                .iter()
                .find(|context| context.configuration_path == configuration_path)
                .expect("declared TypeScript context");
            graph
                .memberships
                .iter()
                .filter(|membership| membership.analysis_context_id == context.analysis_context_id)
                .map(|membership| membership.document_path.as_str())
                .collect::<BTreeSet<_>>()
        };
        assert_eq!(
            selected_by("tsconfig.json"),
            BTreeSet::from([
                "apps/web/src/main.test.ts",
                "apps/web/src/main.ts",
                "shared/lib.ts",
            ])
        );
        assert_eq!(
            selected_by("apps/web/tsconfig.json"),
            BTreeSet::from([
                "apps/web/src/main.ts",
                "shared/lib.test.ts",
                "shared/lib.ts"
            ]),
            "the inherited include remains base-relative while the child exclude is child-relative"
        );
    }

    #[test]
    fn typescript_references_and_extends_are_independent_acyclic_relations() {
        let temporary = TempDir::new().expect("TypeScript mixed context relations");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("apps/web/src")).expect("web source directory");
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{"include":["apps/**/*.ts"],"references":[{"path":"apps/web"}]}"#,
        )
        .expect("solution TypeScript configuration");
        std::fs::write(
            root.join("apps/web/tsconfig.json"),
            r#"{"extends":"../../tsconfig.json","include":["src"]}"#,
        )
        .expect("web TypeScript configuration");
        let inventory = build_project_inventory(
            root,
            &[InventorySource::new("apps/web/src/main.ts", "typescript")],
        );
        let [graph] = inventory.analysis_context_graphs.as_slice() else {
            panic!("one TypeScript analysis-context graph expected");
        };
        assert_eq!(
            graph.coverage,
            AnalysisContextCoverage::DeclaredConfigurationComplete
        );
        assert_eq!(
            graph
                .relationships
                .iter()
                .map(|relationship| relationship.kind)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                AnalysisContextRelationshipKind::ConfigurationExtends,
                AnalysisContextRelationshipKind::ProjectReferences,
            ]),
            "the valid cross-kind root/child loop is not a cycle within either relation"
        );
    }

    #[test]
    fn typescript_reference_cycles_are_typed_partial_and_not_persisted_as_edges() {
        let temporary = TempDir::new().expect("TypeScript reference cycle");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("apps/web/src")).expect("web source directory");
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{"references":[{"path":"apps/web"}]}"#,
        )
        .expect("root TypeScript configuration");
        std::fs::write(
            root.join("apps/web/tsconfig.json"),
            r#"{"references":[{"path":"../.."}]}"#,
        )
        .expect("web TypeScript configuration");
        let inventory = build_project_inventory(
            root,
            &[InventorySource::new("apps/web/src/main.ts", "typescript")],
        );
        let [graph] = inventory.analysis_context_graphs.as_slice() else {
            panic!("one TypeScript analysis-context graph expected");
        };
        assert_eq!(
            graph.coverage,
            AnalysisContextCoverage::DeclaredConfigurationPartial
        );
        assert_eq!(
            graph
                .gaps
                .iter()
                .filter(|gap| gap.reason_code == "typescript_project_references_cycle")
                .count(),
            2
        );
        assert!(graph.relationships.is_empty());
        assert!(graph.memberships.is_empty());
        canonical_project_inventory_bytes(&inventory)
            .expect("sanitized partial topology remains canonical");
    }

    #[test]
    fn typescript_unresolved_package_extends_and_default_outputs_are_honest() {
        let unresolved = TempDir::new().expect("unresolved package extends");
        std::fs::create_dir_all(unresolved.path().join("src")).expect("source directory");
        std::fs::write(
            unresolved.path().join("tsconfig.json"),
            r#"{"extends":"@tsconfig/node22/tsconfig.json","include":["src"]}"#,
        )
        .expect("package-extends TypeScript configuration");
        let inventory = build_project_inventory(
            unresolved.path(),
            &[InventorySource::new("src/main.ts", "typescript")],
        );
        let [graph] = inventory.analysis_context_graphs.as_slice() else {
            panic!("one TypeScript analysis-context graph expected");
        };
        assert_eq!(
            graph.coverage,
            AnalysisContextCoverage::DeclaredConfigurationPartial
        );
        assert!(graph.gaps.iter().any(|gap| {
            gap.reason_code == "typescript_configuration_extends_unresolved"
                && gap.detail.contains("could not be resolved exactly")
        }));

        let outputs = TempDir::new().expect("default TypeScript output exclusions");
        for directory in ["src", "dist", "types"] {
            std::fs::create_dir_all(outputs.path().join(directory)).expect("output fixture path");
        }
        std::fs::write(
            outputs.path().join("tsconfig.json"),
            r#"{
                "include":["**/*"],
                "compilerOptions":{"outDir":"dist","declarationDir":"types"}
            }"#,
        )
        .expect("output TypeScript configuration");
        let inventory = build_project_inventory(
            outputs.path(),
            &[
                InventorySource::new("src/main.ts", "typescript"),
                InventorySource::new("dist/main.ts", "typescript"),
                InventorySource::new("types/main.d.ts", "typescript"),
            ],
        );
        let [graph] = inventory.analysis_context_graphs.as_slice() else {
            panic!("one TypeScript analysis-context graph expected");
        };
        assert_eq!(
            graph
                .memberships
                .iter()
                .map(|membership| membership.document_path.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["src/main.ts"])
        );
    }

    /// FALSIFIER: the new analysis-context layer crosses the immutable
    /// publication boundary, so canonicalization must reject ambiguous or
    /// referentially invalid topology rather than merely sorting it.
    #[test]
    fn canonical_inventory_rejects_invalid_analysis_context_authority() {
        let temporary = TempDir::new().expect("analysis-context validation repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("apps/web/src")).expect("web source directory");
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"@fixture/root","private":true}"#,
        )
        .expect("root package manifest");
        std::fs::write(
            root.join("apps/web/package.json"),
            r#"{"name":"@fixture/web","private":true}"#,
        )
        .expect("web package manifest");
        std::fs::write(
            root.join("tsconfig.json"),
            r#"{"include":["apps/**/*.ts"]}"#,
        )
        .expect("root TypeScript configuration");
        std::fs::write(
            root.join("apps/web/tsconfig.json"),
            r#"{"extends":"../../tsconfig.json","include":["src"]}"#,
        )
        .expect("web TypeScript configuration");
        let inventory = build_project_inventory(
            root,
            &[InventorySource::new("apps/web/src/main.ts", "typescript")],
        );
        let canonical = canonical_project_inventory_bytes(&inventory)
            .expect("positive control: discovered analysis topology is canonical");
        assert_eq!(
            parse_project_inventory_bytes(&canonical).expect("positive canonical replay"),
            inventory
        );
        let graph = inventory
            .analysis_context_graphs
            .first()
            .expect("TypeScript analysis-context graph");
        assert_eq!(graph.contexts.len(), 2, "positive context population");
        assert_eq!(graph.relationships.len(), 1, "positive extends edge");
        assert_eq!(graph.memberships.len(), 2, "positive plural membership");

        let mut cases = Vec::<(&str, ProjectInventory, &str)>::new();

        let mut duplicate_graph = inventory.clone();
        duplicate_graph
            .analysis_context_graphs
            .push(duplicate_graph.analysis_context_graphs[0].clone());
        cases.push((
            "duplicate graph key",
            duplicate_graph,
            "analysis-context graph is duplicated",
        ));

        let mut unknown_membership_context = inventory.clone();
        unknown_membership_context.analysis_context_graphs[0].memberships[0].analysis_context_id =
            AnalysisContextId::new("typescript:unknown");
        cases.push((
            "unknown membership context",
            unknown_membership_context,
            "membership references missing analysis context",
        ));

        let mut unindexed_membership = inventory.clone();
        unindexed_membership.analysis_context_graphs[0].memberships[0].document_path =
            "apps/web/src/not-indexed.ts".into();
        cases.push((
            "unindexed membership document",
            unindexed_membership,
            "membership document is outside the indexed source-owner population",
        ));

        let mut mismatched_context_language = inventory.clone();
        mismatched_context_language.analysis_context_graphs[0].contexts[0].language_id =
            LanguageId::new("javascript");
        cases.push((
            "context language mismatch",
            mismatched_context_language,
            "language or ecosystem differs from its graph",
        ));

        let mut unsafe_configuration_path = inventory.clone();
        unsafe_configuration_path.analysis_context_graphs[0].contexts[0].configuration_path =
            "../tsconfig.json".into();
        cases.push((
            "unsafe configuration path",
            unsafe_configuration_path,
            "configuration path is not canonical",
        ));

        let mut unknown_relationship_target = inventory.clone();
        unknown_relationship_target.analysis_context_graphs[0].relationships[0]
            .target_analysis_context_id = AnalysisContextId::new("typescript:unknown");
        cases.push((
            "unknown relationship target",
            unknown_relationship_target,
            "relationship references a missing analysis context",
        ));

        let mut noncontiguous_ordinal = inventory.clone();
        noncontiguous_ordinal.analysis_context_graphs[0].relationships[0].ordinal = 2;
        cases.push((
            "noncontiguous relationship ordinal",
            noncontiguous_ordinal,
            "relationship ordinals must be contiguous",
        ));

        let mut cyclic_extends = inventory.clone();
        let existing = cyclic_extends.analysis_context_graphs[0].relationships[0].clone();
        cyclic_extends.analysis_context_graphs[0]
            .relationships
            .push(AnalysisContextRelationship {
                source_analysis_context_id: existing.target_analysis_context_id,
                target_analysis_context_id: existing.source_analysis_context_id,
                kind: AnalysisContextRelationshipKind::ConfigurationExtends,
                ordinal: 0,
            });
        cases.push((
            "cyclic extends graph",
            cyclic_extends,
            "configuration_extends relationships contain a cycle",
        ));

        let mut complete_with_gap = inventory.clone();
        complete_with_gap.analysis_context_graphs[0]
            .gaps
            .push(AnalysisContextGap {
                reason_code: "falsifier_gap".into(),
                analysis_context_id: None,
                path: "tsconfig.json".into(),
                detail: "complete coverage cannot carry a gap".into(),
            });
        cases.push((
            "complete graph with a gap",
            complete_with_gap,
            "complete analysis-context coverage requires zero gaps",
        ));

        let mut unknown_gap_context = inventory.clone();
        unknown_gap_context.analysis_context_graphs[0].coverage =
            AnalysisContextCoverage::DeclaredConfigurationPartial;
        unknown_gap_context.analysis_context_graphs[0]
            .gaps
            .push(AnalysisContextGap {
                reason_code: "falsifier_gap".into(),
                analysis_context_id: Some(AnalysisContextId::new("typescript:unknown")),
                path: "tsconfig.json".into(),
                detail: "gap identity must resolve to a materialized context".into(),
            });
        cases.push((
            "unknown gap context",
            unknown_gap_context,
            "gap references a missing analysis context",
        ));

        for (name, mutated, expected) in cases {
            let error = canonical_project_inventory_bytes(&mutated)
                .expect_err("invalid analysis-context authority must fail closed");
            assert!(
                error.to_string().contains(expected),
                "{name} failed for the wrong reason: {error}"
            );
        }
    }

    /// FALSIFIER: requirements establish Python package topology but do not
    /// identify one exact interpreter/module-resolution context. The analysis
    /// layer must report that bounded gap instead of silently omitting Python.
    #[test]
    fn unresolved_python_analysis_context_is_a_typed_gap_not_absence() {
        let temporary = TempDir::new().expect("requirements-only Python repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("app")).expect("Python source directory");
        std::fs::write(root.join("requirements.txt"), "fastapi==1\n")
            .expect("requirements manifest");

        let inventory =
            build_project_inventory(root, &[InventorySource::new("app/main.py", "python")]);
        let bytes = canonical_project_inventory_bytes(&inventory).expect("canonical inventory");
        let document = serde_json::from_slice::<serde_json::Value>(&bytes)
            .expect("canonical inventory document");
        let graphs = document["inventory"]["analysis_context_graphs"]
            .as_array()
            .expect("analysis-context graph population");
        let graph = graphs
            .iter()
            .find(|graph| graph["language_id"] == "python")
            .expect("Python analysis-context graph");
        assert_eq!(graph["coverage"], "declared_configuration_partial");
        assert!(graph["gaps"].as_array().is_some_and(|gaps| {
            gaps.iter()
                .any(|gap| gap["reason_code"] == "python_analysis_context_resolution_unavailable")
        }));
    }

    /// FALSIFIER for the blanket Python-context gap: Pyright defines ordered
    /// execution environments, and each selected source belongs to at most the
    /// first environment whose root contains it. Included sources outside every
    /// explicit environment use the configuration's default environment.
    #[test]
    fn python_pyright_execution_environments_are_ordered_exact_contexts() {
        let temporary = TempDir::new().expect("Pyright execution-environment repository");
        let root = temporary.path();
        for directory in ["src/web", "src/lib", "src/generated", "tests"] {
            std::fs::create_dir_all(root.join(directory)).expect("Python source directory");
        }
        std::fs::write(
            root.join("pyproject.toml"),
            "[project]\nname = \"pyright-fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("Python package manifest");
        std::fs::write(
            root.join("pyrightconfig.json"),
            r#"{
                "include": ["src", "tests"],
                "exclude": ["src/generated"],
                "executionEnvironments": [
                    {"root": "src/web", "extraPaths": ["src/shared"]},
                    {"root": "src"}
                ]
            }"#,
        )
        .expect("Pyright configuration");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("src/web/api.py", "python"),
                InventorySource::new("src/lib/shared.py", "python"),
                InventorySource::new("src/top.py", "python"),
                InventorySource::new("src/generated/schema.py", "python"),
                InventorySource::new("tests/test_api.py", "python"),
            ],
        );

        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        );
        assert!(inventory.issues.is_empty());
        let [graph] = inventory.analysis_context_graphs.as_slice() else {
            panic!("one Python analysis-context graph expected");
        };
        assert_eq!(
            graph.coverage,
            AnalysisContextCoverage::DeclaredConfigurationComplete
        );
        assert!(graph.gaps.is_empty());
        assert_eq!(
            graph.contexts.len(),
            3,
            "two explicit plus one default environment"
        );
        assert!(graph.contexts.iter().all(|context| {
            context.kind_id == AnalysisContextKindId::new("python_execution_environment")
                && context.configuration_path == "pyrightconfig.json"
        }));

        let memberships = graph
            .memberships
            .iter()
            .map(|membership| {
                let context = graph
                    .contexts
                    .iter()
                    .find(|context| context.analysis_context_id == membership.analysis_context_id)
                    .expect("membership context");
                (
                    membership.document_path.as_str(),
                    context.root_path.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            memberships,
            BTreeSet::from([
                ("src/lib/shared.py", "src"),
                ("src/top.py", "src"),
                ("src/web/api.py", "src/web"),
                ("tests/test_api.py", ""),
            ]),
            "the first containing environment wins and excluded roots stay unselected"
        );
        assert!(
            !graph
                .memberships
                .iter()
                .any(|membership| membership.document_path == "src/generated/schema.py"),
            "excluded source remains structurally owned but is not a declared Pyright root"
        );
        assert_eq!(
            inventory
                .project_topology
                .memberships
                .iter()
                .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
                .count(),
            5,
            "positive control: all five files remain in the structural source population"
        );
    }

    /// Pyright's repository contract gives `pyrightconfig.json` precedence
    /// over `[tool.pyright]`. A malformed winner must fail closed rather than
    /// borrowing the lower-priority configuration while structural ownership
    /// remains independently useful.
    #[test]
    fn python_pyright_precedence_is_exact_and_invalid_winner_never_falls_back() {
        let temporary = TempDir::new().expect("Pyright precedence repository");
        let root = temporary.path();
        for directory in ["src", "pyproject-only"] {
            std::fs::create_dir_all(root.join(directory)).expect("Python source directory");
        }
        std::fs::write(
            root.join("pyproject.toml"),
            "[project]\nname = \"precedence-fixture\"\nversion = \"0.1.0\"\n\n[tool.pyright]\ninclude = [\"pyproject-only\"]\n",
        )
        .expect("Python package and lower-priority Pyright configuration");
        let sources = [
            InventorySource::new("src/app.py", "python"),
            InventorySource::new("pyproject-only/ignored.py", "python"),
        ];

        let pyproject_fallback = build_project_inventory(root, &sources);
        let [graph] = pyproject_fallback.analysis_context_graphs.as_slice() else {
            panic!("one pyproject-backed Python context graph expected");
        };
        assert!(
            graph
                .contexts
                .iter()
                .all(|context| context.configuration_path == "pyproject.toml")
        );
        assert_eq!(
            graph
                .memberships
                .iter()
                .map(|membership| membership.document_path.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["pyproject-only/ignored.py"]),
            "[tool.pyright] is the exact fallback when no JSON config exists"
        );

        std::fs::write(root.join("pyrightconfig.json"), r#"{"include":["src"]}"#)
            .expect("higher-priority Pyright configuration");

        let selected = build_project_inventory(root, &sources);
        let [graph] = selected.analysis_context_graphs.as_slice() else {
            panic!("one Python analysis-context graph expected");
        };
        assert_eq!(
            graph.coverage,
            AnalysisContextCoverage::DeclaredConfigurationComplete
        );
        assert!(
            graph
                .contexts
                .iter()
                .all(|context| { context.configuration_path == "pyrightconfig.json" })
        );
        assert_eq!(
            graph
                .memberships
                .iter()
                .map(|membership| membership.document_path.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["src/app.py"]),
            "the lower-priority pyproject selection must not merge into the winner"
        );
        for input_path in ["pyproject.toml", "pyrightconfig.json"] {
            assert!(
                selected.inputs.iter().any(|input| input.path == input_path),
                "positive control: precedence input is content-bound: {input_path}"
            );
        }

        std::fs::write(root.join("pyrightconfig.json"), "{not-json")
            .expect("malformed higher-priority configuration");
        let refused = build_project_inventory(root, &sources);
        assert_eq!(
            refused.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        );
        let [graph] = refused.analysis_context_graphs.as_slice() else {
            panic!("one refused Python analysis-context graph expected");
        };
        assert_eq!(
            graph.coverage,
            AnalysisContextCoverage::DeclaredConfigurationPartial
        );
        assert!(graph.contexts.is_empty());
        assert!(graph.memberships.is_empty());
        assert!(graph.gaps.iter().any(|gap| {
            gap.reason_code == "python_pyright_configuration_invalid"
                && gap.path == "pyrightconfig.json"
        }));
        assert_eq!(
            refused
                .project_topology
                .memberships
                .iter()
                .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
                .count(),
            2,
            "analysis refusal must not erase exact structural ownership"
        );
    }

    #[test]
    fn pnpm_exclusion_keeps_independent_package_outside_workspace_authority() {
        let temporary = TempDir::new().expect("pnpm exclusion repository");
        let root = temporary.path();
        for package in ["packages/member", "packages/excluded"] {
            std::fs::create_dir_all(root.join(package).join("src")).expect("package source");
            std::fs::write(
                root.join(package).join("package.json"),
                format!(
                    "{{\"name\":\"@fixture/{}\",\"private\":true}}",
                    package.rsplit('/').next().expect("package name")
                ),
            )
            .expect("package manifest");
        }
        std::fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - 'packages/*'\n  - '!packages/excluded'\n",
        )
        .expect("workspace manifest");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("packages/member/src/index.ts", "typescript"),
                InventorySource::new("packages/excluded/src/index.ts", "typescript"),
            ],
        );
        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        );
        let workspace = inventory
            .project_topology
            .units
            .iter()
            .find(|unit| unit.kind == ProjectUnitKind::Workspace)
            .expect("workspace unit");
        let package_at = |root_path: &str| {
            inventory
                .project_topology
                .units
                .iter()
                .find(|unit| unit.kind == ProjectUnitKind::Package && unit.root_path == root_path)
                .expect("package unit")
        };
        let member = package_at("packages/member");
        let excluded = package_at("packages/excluded");
        assert!(
            inventory
                .project_topology
                .relationships
                .iter()
                .any(|relationship| {
                    relationship.kind == ProjectUnitRelationshipKind::WorkspaceMember
                        && relationship.parent_project_unit_id == workspace.project_unit_id
                        && relationship.child_project_unit_id == member.project_unit_id
                })
        );
        assert!(
            !inventory
                .project_topology
                .relationships
                .iter()
                .any(|relationship| {
                    relationship.kind == ProjectUnitRelationshipKind::WorkspaceMember
                        && relationship.child_project_unit_id == excluded.project_unit_id
                })
        );
        let roots = semantic_provider_unit_execution_roots(&inventory, "typescript", "node");
        assert_eq!(roots.get(&member.project_unit_id), Some(&PathBuf::new()));
        assert_eq!(
            roots.get(&excluded.project_unit_id),
            Some(&PathBuf::from("packages/excluded")),
            "path containment must not impersonate excluded workspace membership"
        );
    }

    #[test]
    fn malformed_typescript_workspace_and_jsonc_remain_partial_and_non_authoritative() {
        let temporary = TempDir::new().expect("malformed TypeScript workspace");
        let root = temporary.path();
        for package in ["apps/web", "packages/ui"] {
            std::fs::create_dir_all(root.join(package).join("src")).expect("package source");
        }
        std::fs::write(root.join("pnpm-workspace.yaml"), "packages: [\n")
            .expect("malformed workspace control");
        std::fs::write(
            root.join("apps/web/package.json"),
            r#"{"name":"@fixture/web","dependencies":{"@fixture/ui":"workspace:*"}}"#,
        )
        .expect("web package manifest");
        std::fs::write(
            root.join("packages/ui/package.json"),
            r#"{"name":"@fixture/ui"}"#,
        )
        .expect("UI package manifest");
        std::fs::write(root.join("apps/web/tsconfig.json"), "{ invalid jsonc")
            .expect("malformed TypeScript configuration");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("apps/web/src/main.ts", "typescript"),
                InventorySource::new("packages/ui/src/index.ts", "typescript"),
            ],
        );

        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        );
        for (code, path) in [
            ("manifest_invalid", "pnpm-workspace.yaml"),
            ("project_configuration_invalid", "apps/web/tsconfig.json"),
        ] {
            assert!(
                inventory
                    .issues
                    .iter()
                    .any(|issue| issue.code == code && issue.path == path),
                "missing exact partial-authority reason {code} at {path}: {:?}",
                inventory.issues
            );
        }
        assert!(
            !inventory
                .project_topology
                .relationships
                .iter()
                .any(|relationship| {
                    relationship.kind == ProjectUnitRelationshipKind::WorkspaceMember
                }),
            "an invalid workspace file cannot grant membership"
        );
        let [dependency_graph] = inventory.project_topology.dependency_graphs.as_slice() else {
            panic!("one populated TypeScript dependency graph expected");
        };
        assert_eq!(
            dependency_graph.coverage,
            ProjectUnitDependencyGraphCoverage::Partial
        );
        assert!(
            dependency_graph.gaps.iter().any(|gap| {
                gap.reason_code == "typescript_workspace_dependency_without_workspace"
            })
        );
    }

    #[test]
    fn invalid_nested_package_manifest_blocks_ancestor_package_ownership() {
        let temporary = TempDir::new().expect("invalid nested Node package");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("app/src")).expect("nested source");
        std::fs::write(root.join("package.json"), r#"{"name":"@fixture/root"}"#)
            .expect("ancestor package manifest");
        std::fs::write(root.join("app/package.json"), "{ invalid json")
            .expect("invalid nested package manifest");

        let inventory = build_project_inventory(
            root,
            &[InventorySource::new("app/src/main.ts", "typescript")],
        );
        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        );
        let ancestor = inventory
            .project_topology
            .units
            .iter()
            .find(|unit| unit.manifest_path.as_deref() == Some("package.json"))
            .expect("ancestor package context");
        assert!(
            !inventory
                .project_topology
                .memberships
                .iter()
                .any(|membership| {
                    membership.project_unit_id == ancestor.project_unit_id
                        && membership.kind == DocumentMembershipKind::SourceOwner
                })
        );
        let owner = inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
            .expect("structural owner");
        assert!(inventory.project_topology.units.iter().any(|unit| {
            unit.project_unit_id == owner.project_unit_id
                && unit.kind == ProjectUnitKind::LooseSources
        }));
    }

    #[test]
    fn unowned_rust_source_is_structural_without_expanding_cargo_authority() {
        let temporary = TempDir::new().expect("temporary repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("crates/host/src")).expect("package source directory");
        std::fs::create_dir_all(root.join("providers")).expect("loose source directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/host\"]\nresolver = \"3\"\n",
        )
        .expect("workspace manifest");
        std::fs::write(
            root.join("crates/host/Cargo.toml"),
            "[package]\nname = \"host\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("package manifest");
        std::fs::write(root.join("crates/host/src/lib.rs"), "pub fn host() {}\n")
            .expect("package source");
        std::fs::write(
            root.join("providers/template.rs"),
            "pub fn generated_template() {}\n",
        )
        .expect("loose source");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("crates/host/src/lib.rs", "rust"),
                InventorySource::new("providers/template.rs", "rust"),
            ],
        );
        let package_owner = inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| {
                membership.document_path == "crates/host/src/lib.rs"
                    && membership.kind == DocumentMembershipKind::SourceOwner
            })
            .expect("package owner");
        let loose_owner = inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| {
                membership.document_path == "providers/template.rs"
                    && membership.kind == DocumentMembershipKind::SourceOwner
            })
            .expect("loose owner");

        assert!(inventory.is_semantic_source_owner(package_owner));
        assert!(!inventory.is_semantic_source_owner(loose_owner));
        assert!(inventory.project_topology.units.iter().any(|unit| {
            unit.project_unit_id == loose_owner.project_unit_id
                && unit.kind == ProjectUnitKind::LooseSources
        }));
        assert_eq!(
            semantic_provider_execution_roots(&inventory, "rust", "cargo"),
            vec![PathBuf::new()],
            "the real Cargo package remains the sole executable semantic root"
        );
    }

    #[test]
    fn detached_cargo_workspace_gets_its_own_provider_execution_root() {
        let temporary = TempDir::new().expect("temporary repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("rootpkg/src")).expect("root package source");
        std::fs::create_dir_all(root.join("detached/src")).expect("detached package source");
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"rootpkg\"]\n",
        )
        .expect("root workspace manifest");
        std::fs::write(
            root.join("rootpkg/Cargo.toml"),
            "[package]\nname = \"rootpkg\"\nversion = \"0.1.0\"\n",
        )
        .expect("root package manifest");
        std::fs::write(
            root.join("detached/Cargo.toml"),
            "[workspace]\n\n[package]\nname = \"detached\"\nversion = \"0.1.0\"\n",
        )
        .expect("detached workspace manifest");
        std::fs::write(root.join("rootpkg/src/lib.rs"), "pub fn rootpkg() {}\n")
            .expect("root package crate root");
        std::fs::write(root.join("detached/src/lib.rs"), "pub fn detached() {}\n")
            .expect("detached crate root");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("rootpkg/src/lib.rs", "rust"),
                InventorySource::new("detached/src/lib.rs", "rust"),
            ],
        );

        assert_eq!(
            semantic_provider_execution_roots(&inventory, "rust", "cargo"),
            vec![PathBuf::new(), PathBuf::from("detached")]
        );
    }

    #[test]
    fn go_testdata_is_auxiliary_unless_it_declares_its_own_module() {
        let temporary = TempDir::new().expect("temporary repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("Rust source directory");
        std::fs::create_dir_all(root.join("testdata")).expect("Go testdata directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"host\"\nversion = \"0.1.0\"\n",
        )
        .expect("host manifest");
        std::fs::write(root.join("go.mod"), "module example.test/host\n\ngo 1.26\n")
            .expect("outer Go module");
        std::fs::write(root.join("src/lib.rs"), "pub fn host() {}\n").expect("host source");
        std::fs::write(root.join("testdata/shape.go"), "package shape\n")
            .expect("ancillary Go source");

        let sources = [
            InventorySource::new("src/lib.rs", "rust"),
            InventorySource::new("testdata/shape.go", "go"),
        ];
        let auxiliary = build_project_inventory(root, &sources);
        assert!(
            !auxiliary.project_topology.units.iter().any(|unit| {
                unit.language_id.0 == "go" && unit.kind == ProjectUnitKind::LooseSources
            }),
            "Go's ignored testdata directory is structurally searchable ancillary data, not an executable loose-source population"
        );
        assert!(
            semantic_provider_execution_roots(&auxiliary, "go", "go").is_empty(),
            "an outer Go module must not claim a subtree the Go tool ignores"
        );
        let auxiliary_owner = auxiliary
            .project_topology
            .memberships
            .iter()
            .find(|membership| {
                membership.document_path == "testdata/shape.go"
                    && membership.kind == DocumentMembershipKind::SourceOwner
            })
            .expect("auxiliary source owner");
        assert!(!auxiliary.is_semantic_source_owner(auxiliary_owner));
        assert!(auxiliary.project_topology.units.iter().any(|unit| {
            unit.project_unit_id == auxiliary_owner.project_unit_id
                && unit.kind == ProjectUnitKind::AuxiliarySources
                && unit.root_path == "testdata"
        }));

        std::fs::write(
            root.join("testdata/go.mod"),
            "module example.test/shape\n\ngo 1.26\n",
        )
        .expect("nested Go module");
        let module = build_project_inventory(root, &sources);
        assert_eq!(
            semantic_provider_execution_roots(&module, "go", "go"),
            vec![PathBuf::from("testdata")],
            "positive control: an explicit nested module makes the same subtree executable"
        );
        assert!(module.project_topology.units.iter().any(|unit| {
            unit.language_id.0 == "go"
                && unit.kind == ProjectUnitKind::Module
                && unit.root_path == "testdata"
        }));
        let module_owner = module
            .project_topology
            .memberships
            .iter()
            .find(|membership| {
                membership.document_path == "testdata/shape.go"
                    && membership.kind == DocumentMembershipKind::SourceOwner
            })
            .expect("nested module source owner");
        assert!(module.is_semantic_source_owner(module_owner));
    }

    #[test]
    fn malformed_manifest_is_partial_and_cannot_become_a_source_owner() {
        let temporary = TempDir::new().expect("temporary repository");
        std::fs::create_dir_all(temporary.path().join("src")).expect("source directory");
        std::fs::write(temporary.path().join("Cargo.toml"), "[package\n")
            .expect("malformed manifest");

        let inventory = build_project_inventory(
            temporary.path(),
            &[InventorySource::new("src/lib.rs", "rust")],
        );

        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        );
        assert!(
            inventory
                .issues
                .iter()
                .any(|issue| issue.code == "manifest_invalid")
        );
        let owners = inventory
            .project_topology
            .memberships
            .iter()
            .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
            .collect::<Vec<_>>();
        assert_eq!(owners.len(), 1);
        assert!(owners[0].project_unit_id.0.contains(":loose_sources:"));
    }

    /// FALSIFIER: an ownership-defining control that exists as a non-regular
    /// repository entry is not equivalent to an absent control. If the nested
    /// Cargo.toml disappears from authority observation, the broader package's
    /// conventional `src` domain incorrectly claims through it.
    #[test]
    fn unsafe_nested_cargo_manifest_blocks_ancestor_package_ownership() {
        let temporary = TempDir::new().expect("unsafe nested Cargo repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src/nested/Cargo.toml"))
            .expect("non-regular nested Cargo control");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"ancestor\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("ancestor Cargo manifest");
        std::fs::write(root.join("src/nested/lib.rs"), "pub fn nested() {}\n")
            .expect("nested Rust source");

        let inventory =
            build_project_inventory(root, &[InventorySource::new("src/nested/lib.rs", "rust")]);

        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        );
        assert!(inventory.issues.iter().any(|issue| {
            issue.code == "manifest_unsafe" && issue.path == "src/nested/Cargo.toml"
        }));
        let ancestor = inventory
            .project_topology
            .units
            .iter()
            .find(|unit| unit.manifest_path.as_deref() == Some("Cargo.toml"))
            .expect("positive control: ancestor Cargo package remains observable");
        assert!(
            !inventory
                .project_topology
                .memberships
                .iter()
                .any(|membership| {
                    membership.project_unit_id == ancestor.project_unit_id
                        && membership.kind == DocumentMembershipKind::SourceOwner
                }),
            "an unsafe nearer Cargo control must block ancestor ownership"
        );
        let owner = inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
            .expect("structural Rust source owner");
        assert!(inventory.project_topology.units.iter().any(|unit| {
            unit.project_unit_id == owner.project_unit_id
                && unit.kind == ProjectUnitKind::LooseSources
        }));
    }

    /// FALSIFIER: Go module containment is broad, so silently treating a
    /// present-but-unsafe nested go.mod as absent grants the ancestor module
    /// authority over a source whose nearest ownership control was unusable.
    #[test]
    fn unsafe_nested_go_mod_blocks_ancestor_module_ownership() {
        let temporary = TempDir::new().expect("unsafe nested Go repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("app/go.mod")).expect("non-regular nested Go control");
        std::fs::write(
            root.join("go.mod"),
            "module example.test/ancestor\n\ngo 1.27\n",
        )
        .expect("ancestor Go module");
        std::fs::write(root.join("app/main.go"), "package app\n").expect("nested Go source");

        let inventory = build_project_inventory(root, &[InventorySource::new("app/main.go", "go")]);

        assert_eq!(
            inventory.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        );
        assert!(
            inventory
                .issues
                .iter()
                .any(|issue| { issue.code == "manifest_unsafe" && issue.path == "app/go.mod" })
        );
        let ancestor = inventory
            .project_topology
            .units
            .iter()
            .find(|unit| unit.manifest_path.as_deref() == Some("go.mod"))
            .expect("positive control: ancestor Go module remains observable");
        assert!(
            !inventory
                .project_topology
                .memberships
                .iter()
                .any(|membership| {
                    membership.project_unit_id == ancestor.project_unit_id
                        && membership.kind == DocumentMembershipKind::SourceOwner
                }),
            "an unsafe nearer Go control must block ancestor ownership"
        );
        let owner = inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
            .expect("structural Go source owner");
        assert!(inventory.project_topology.units.iter().any(|unit| {
            unit.project_unit_id == owner.project_unit_id
                && unit.kind == ProjectUnitKind::LooseSources
        }));
    }

    #[test]
    fn inventory_fingerprint_is_order_independent_but_population_sensitive() {
        let temporary = TempDir::new().expect("temporary repository");
        std::fs::write(
            temporary.path().join("go.mod"),
            "module example.test/inventory\n\ngo 1.25\n",
        )
        .expect("Go manifest");
        let first = build_project_inventory(
            temporary.path(),
            &[
                InventorySource::new("a.go", "go"),
                InventorySource::new("b.go", "go"),
            ],
        );
        let reordered = build_project_inventory(
            temporary.path(),
            &[
                InventorySource::new("b.go", "go"),
                InventorySource::new("a.go", "go"),
            ],
        );
        let smaller =
            build_project_inventory(temporary.path(), &[InventorySource::new("a.go", "go")]);

        assert_eq!(
            project_inventory_fingerprint(&first).expect("first fingerprint"),
            project_inventory_fingerprint(&reordered).expect("reordered fingerprint")
        );
        assert_ne!(
            project_inventory_fingerprint(&first).expect("first fingerprint"),
            project_inventory_fingerprint(&smaller).expect("smaller fingerprint")
        );
        assert_eq!(first.inputs.len(), 1);
        assert_eq!(first.inputs[0].path, "go.mod");
        assert_eq!(first.inputs[0].role, ProjectInputRole::Manifest);

        std::fs::write(
            temporary.path().join("go.mod"),
            "module example.test/changed\n\ngo 1.25\n",
        )
        .expect("change Go manifest without changing unit topology");
        let changed_input = build_project_inventory(
            temporary.path(),
            &[
                InventorySource::new("a.go", "go"),
                InventorySource::new("b.go", "go"),
            ],
        );
        assert_eq!(
            first.project_topology.units,
            changed_input.project_topology.units
        );
        assert_ne!(
            project_inventory_fingerprint(&first).expect("original project inputs"),
            project_inventory_fingerprint(&changed_input).expect("changed project inputs"),
            "manifest bytes must participate even when ownership topology is unchanged"
        );
    }

    /// FALSIFIER: a complete published inventory is a deterministic function
    /// of the exact source population plus its captured project-input bytes.
    /// Rechecking those bytes must not parse the same manifest a second time
    /// merely to reconstruct topology that the generation already owns.
    #[test]
    #[serial_test::serial]
    fn repeated_freshness_checks_do_not_rebuild_complete_project_topology() {
        let temporary = TempDir::new().expect("temporary repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"freshness-fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("Cargo manifest");
        std::fs::write(root.join("src/lib.rs"), "pub fn target() {}\n").expect("Rust source");
        let sources = [InventorySource::new("src/lib.rs", "rust")];
        let expected = build_project_inventory(root, &sources);
        assert_eq!(
            expected.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            "positive control: the fixture must own a complete reusable topology"
        );
        let witness = ProjectInventoryWitness::new(sources.to_vec(), Arc::new(expected));

        reset_project_discovery_read_counts(root);
        assert_eq!(witness.observe(root), ProjectInventoryFreshness::Current);
        assert_eq!(witness.observe(root), ProjectInventoryFreshness::Current);
        let (project_input_reads, project_manifest_reads) = project_discovery_read_counts(root);
        assert_eq!(
            project_input_reads, 2,
            "each exact request must still re-read the manifest bytes"
        );
        assert_eq!(
            project_manifest_reads, 0,
            "verified bytes must not trigger a redundant project-topology rebuild"
        );
        assert_eq!(
            project_input_plan_build_count(),
            0,
            "one immutable generation must plan its bounded input vocabulary once"
        );
    }

    /// FALSIFIER: every candidate remains an exact stat/read/hash observation,
    /// but independent project-input paths must not be observed serially.
    #[test]
    #[serial_test::serial]
    fn project_inventory_witness_observes_independent_candidates_concurrently() {
        let temporary = TempDir::new().expect("temporary repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"parallel-witness\"\nversion = \"0.1.0\"\n",
        )
        .expect("Cargo manifest");
        std::fs::write(root.join("Cargo.lock"), "version = 4\n").expect("Cargo lockfile");
        std::fs::write(
            root.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"stable\"\n",
        )
        .expect("toolchain input");
        std::fs::write(root.join("src/lib.rs"), "pub fn target() {}\n").expect("Rust source");
        let sources = vec![InventorySource::new("src/lib.rs", "rust")];
        let expected = Arc::new(build_project_inventory(root, &sources));
        let witness = ProjectInventoryWitness::new(sources, expected);

        reset_project_input_concurrency(root);
        let _delay = TestProjectInputDelayGuard::enable(root);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .expect("four-thread falsifier pool");
        let verdict = pool.install(|| witness.observe(root));

        assert_eq!(verdict, ProjectInventoryFreshness::Current);
        assert!(
            max_project_inputs_in_flight(root) > 1,
            "positive multi-thread control must observe overlapping project-input candidates"
        );
    }

    #[test]
    fn complete_project_input_witness_detects_bytes_population_and_source_binding_drift() {
        let temporary = TempDir::new().expect("temporary repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        let manifest_path = root.join("Cargo.toml");
        let manifest = "[package]\nname = \"witness-fixture\"\nversion = \"0.1.0\"\n";
        std::fs::write(&manifest_path, manifest).expect("Cargo manifest");
        std::fs::write(root.join("src/lib.rs"), "pub fn target() {}\n").expect("Rust source");
        let sources = [InventorySource::new("src/lib.rs", "rust")];
        let expected = build_project_inventory(root, &sources);
        assert_eq!(
            check_project_inventory_freshness(root, &sources, &expected),
            ProjectInventoryFreshness::Current,
            "positive control: unchanged exact inputs must validate"
        );

        let original_metadata = std::fs::metadata(&manifest_path).expect("manifest metadata");
        let original_accessed = original_metadata.accessed().expect("manifest atime");
        let original_modified = original_metadata.modified().expect("manifest mtime");
        std::fs::write(
            &manifest_path,
            "[package]\nname = \"changed-fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("change manifest bytes");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&manifest_path)
            .expect("open changed manifest")
            .set_times(
                std::fs::FileTimes::new()
                    .set_accessed(original_accessed)
                    .set_modified(original_modified),
            )
            .expect("restore manifest timestamps");
        assert_eq!(
            check_project_inventory_freshness(root, &sources, &expected),
            ProjectInventoryFreshness::Stale,
            "restored metadata cannot conceal changed project-input bytes"
        );

        std::fs::write(&manifest_path, manifest).expect("restore exact manifest bytes");
        assert_eq!(
            check_project_inventory_freshness(root, &sources, &expected),
            ProjectInventoryFreshness::Current,
            "restoring the exact bytes must restore the generation relation"
        );

        std::fs::write(root.join("Cargo.lock"), "version = 4\n")
            .expect("add previously absent project input");
        assert_eq!(
            check_project_inventory_freshness(root, &sources, &expected),
            ProjectInventoryFreshness::Stale,
            "a newly present project input must invalidate the old topology"
        );
        std::fs::remove_file(root.join("Cargo.lock")).expect("remove added lockfile fixture");
        assert_eq!(
            check_project_inventory_freshness(root, &sources, &expected),
            ProjectInventoryFreshness::Current
        );

        assert_eq!(
            check_project_inventory_freshness(
                root,
                &[
                    InventorySource::new("src/lib.rs", "rust"),
                    InventorySource::new("src/other.rs", "rust"),
                ],
                &expected,
            ),
            ProjectInventoryFreshness::Stale,
            "matching project-input bytes cannot authorize a different source population"
        );
    }

    #[test]
    #[serial_test::serial]
    fn partial_project_inventory_uses_exact_reconstruction_fallback() {
        let temporary = TempDir::new().expect("temporary repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(root.join("Cargo.toml"), "[package\n").expect("malformed manifest");
        std::fs::write(root.join("src/lib.rs"), "pub fn target() {}\n").expect("Rust source");
        let sources = [InventorySource::new("src/lib.rs", "rust")];
        let expected = build_project_inventory(root, &sources);
        assert_eq!(
            expected.coverage,
            ProjectInventoryCoverage::IndexedSourcePopulationPartial,
            "positive control: malformed topology must not enter the complete fast path"
        );

        reset_project_discovery_read_counts(root);
        assert_eq!(
            check_project_inventory_freshness(root, &sources, &expected),
            ProjectInventoryFreshness::Current,
            "an unchanged partial observation retains the previous exact behavior"
        );
        assert_eq!(
            project_discovery_read_counts(root),
            (1, 1),
            "partial authority must reconstruct both project-input and parse evidence"
        );
    }

    /// FALSIFIER for the pre-Python/TypeScript project-input seam: WATCH knew
    /// that these filenames could change project meaning, but immutable
    /// inventory recorded none of them. A generation could therefore remain
    /// apparently current after its Python environment, Node workspace,
    /// compiler configuration, or version selector changed.
    #[test]
    fn planned_language_project_inputs_are_immutable_authority_not_watch_only() {
        let temporary = TempDir::new().expect("temporary polyglot repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("python/src")).expect("Python source directory");
        std::fs::create_dir_all(root.join("web/src")).expect("TypeScript source directory");
        std::fs::write(
            root.join("python/pyproject.toml"),
            "[project]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("Python project manifest");
        std::fs::write(root.join("python/requirements.txt"), "fastapi==1\n")
            .expect("Python requirements");
        std::fs::write(
            root.join("python/requirements-dev.txt"),
            "-r requirements.txt\npytest==9\n",
        )
        .expect("Python development requirements");
        std::fs::write(root.join("python/uv.lock"), "version = 1\n")
            .expect("Python dependency lock");
        std::fs::write(root.join("python/.python-version"), "3.13\n")
            .expect("Python version selector");
        std::fs::write(root.join("python/pytest.ini"), "[pytest]\n")
            .expect("Python test configuration");
        std::fs::write(root.join("python/.mypy.ini"), "[mypy]\nstrict = true\n")
            .expect("hidden mypy configuration");
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"fixture-root","private":true,"packageManager":"pnpm@11"}"#,
        )
        .expect("Node workspace manifest");
        std::fs::write(root.join("pnpm-workspace.yaml"), "packages:\n  - web\n")
            .expect("pnpm workspace manifest");
        std::fs::write(root.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n")
            .expect("pnpm dependency lock");
        std::fs::write(root.join(".node-version"), "24\n").expect("Node version selector");
        std::fs::write(
            root.join("web/package.json"),
            r#"{"name":"@fixture/web","private":true,"type":"module"}"#,
        )
        .expect("Node package manifest");
        std::fs::write(root.join("web/tsconfig.json"), r#"{"include":["src"]}"#)
            .expect("TypeScript configuration");
        std::fs::write(
            root.join("web/tsconfig.build.json"),
            r#"{"extends":"./tsconfig.json","exclude":["src/**/*.test.ts"]}"#,
        )
        .expect("TypeScript build configuration");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("python/src/app.py", "python"),
                InventorySource::new("web/src/main.ts", "typescript"),
            ],
        );
        let observed = inventory
            .inputs
            .iter()
            .map(|input| {
                (
                    input.path.as_str(),
                    input.language_id.0.as_str(),
                    input.ecosystem_id.0.as_str(),
                    input.role,
                )
            })
            .collect::<BTreeSet<_>>();
        let expected = BTreeSet::from([
            (
                ".node-version",
                "typescript",
                "node",
                ProjectInputRole::ToolConfiguration,
            ),
            (
                "package.json",
                "typescript",
                "node",
                ProjectInputRole::Manifest,
            ),
            (
                "pnpm-lock.yaml",
                "typescript",
                "node",
                ProjectInputRole::DependencyLock,
            ),
            (
                "pnpm-workspace.yaml",
                "typescript",
                "node",
                ProjectInputRole::Manifest,
            ),
            (
                "python/.python-version",
                "python",
                "python",
                ProjectInputRole::ToolConfiguration,
            ),
            (
                "python/.mypy.ini",
                "python",
                "python",
                ProjectInputRole::ToolConfiguration,
            ),
            (
                "python/pyproject.toml",
                "python",
                "python",
                ProjectInputRole::Manifest,
            ),
            (
                "python/pytest.ini",
                "python",
                "python",
                ProjectInputRole::ToolConfiguration,
            ),
            (
                "python/requirements-dev.txt",
                "python",
                "python",
                ProjectInputRole::Manifest,
            ),
            (
                "python/requirements.txt",
                "python",
                "python",
                ProjectInputRole::Manifest,
            ),
            (
                "python/uv.lock",
                "python",
                "python",
                ProjectInputRole::DependencyLock,
            ),
            (
                "web/package.json",
                "typescript",
                "node",
                ProjectInputRole::Manifest,
            ),
            (
                "web/tsconfig.build.json",
                "typescript",
                "node",
                ProjectInputRole::ToolConfiguration,
            ),
            (
                "web/tsconfig.json",
                "typescript",
                "node",
                ProjectInputRole::ToolConfiguration,
            ),
        ]);

        assert_eq!(observed, expected);
        assert!(
            !observed.iter().any(|(path, ..)| *path == "Cargo.toml"),
            "positive population must remain language scoped"
        );

        let sources = [
            InventorySource::new("python/src/app.py", "python"),
            InventorySource::new("web/src/main.ts", "typescript"),
        ];
        std::fs::write(root.join("python/README.txt"), "not project authority\n")
            .expect("unrelated text file");
        assert_eq!(
            check_project_inventory_freshness(root, &sources, &inventory),
            ProjectInventoryFreshness::Current,
            "an unrelated sibling must not broaden a filename-family selector"
        );

        std::fs::write(root.join("python/requirements-ci.txt"), "pytest-xdist==4\n")
            .expect("new Python requirements family member");
        std::fs::write(
            root.join("web/tsconfig.test.json"),
            r#"{"extends":"./tsconfig.json","include":["src/**/*.test.ts"]}"#,
        )
        .expect("new TypeScript configuration family member");
        assert_eq!(
            check_project_inventory_freshness(root, &sources, &inventory),
            ProjectInventoryFreshness::Stale,
            "a newly introduced matching control must invalidate immutable authority"
        );
        let changed = build_project_inventory(root, &sources);
        for path in ["python/requirements-ci.txt", "web/tsconfig.test.json"] {
            assert!(
                changed.inputs.iter().any(|input| input.path == path),
                "new family member is absent from rebuilt authority: {path}"
            );
        }
    }

    #[test]
    fn rust_project_inputs_include_manifest_lock_and_repo_local_tool_configuration() {
        let temporary = TempDir::new().expect("temporary repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::create_dir_all(root.join(".cargo")).expect("Cargo config directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n",
        )
        .expect("Cargo manifest");
        std::fs::write(root.join("Cargo.lock"), "version = 4\n").expect("Cargo lockfile");
        std::fs::write(
            root.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"stable\"\n",
        )
        .expect("Rust toolchain config");
        std::fs::write(
            root.join(".cargo/config.toml"),
            "[build]\ntarget-dir = \"build-output\"\n",
        )
        .expect("Cargo config");

        let original = build_project_inventory(root, &[InventorySource::new("src/lib.rs", "rust")]);
        let roles = original
            .inputs
            .iter()
            .map(|input| (input.path.as_str(), input.role))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            roles,
            BTreeSet::from([
                (".cargo/config.toml", ProjectInputRole::ToolConfiguration),
                ("Cargo.lock", ProjectInputRole::DependencyLock),
                ("Cargo.toml", ProjectInputRole::Manifest),
                ("rust-toolchain.toml", ProjectInputRole::ToolConfiguration,),
            ])
        );

        std::fs::write(root.join("Cargo.lock"), "version = 4\n# changed\n")
            .expect("change Cargo lockfile");
        let changed = build_project_inventory(root, &[InventorySource::new("src/lib.rs", "rust")]);
        assert_eq!(
            original.project_topology.units,
            changed.project_topology.units
        );
        assert_ne!(
            project_inventory_fingerprint(&original).expect("original project inputs"),
            project_inventory_fingerprint(&changed).expect("changed project inputs"),
            "dependency-lock bytes must participate in project authority"
        );

        std::fs::write(
            root.join(".cargo/config.toml"),
            "[build]\ntarget-dir = \"different-build-output\"\n",
        )
        .expect("change Cargo tool configuration");
        let changed_configuration =
            build_project_inventory(root, &[InventorySource::new("src/lib.rs", "rust")]);
        assert_eq!(
            changed.project_topology.units,
            changed_configuration.project_topology.units
        );
        assert_ne!(
            project_inventory_fingerprint(&changed).expect("prior project inputs"),
            project_inventory_fingerprint(&changed_configuration)
                .expect("changed tool configuration"),
            "repo-local Cargo configuration bytes must invalidate semantic topology authority"
        );
    }

    /// FALSIFIER: project topology and input authority are properties of unique
    /// repository files, not of how many indexed documents happen to share
    /// them. The old document-first walk reread and rehashed both inputs for
    /// every document and reparsed the same manifest before BTreeSet dedup.
    #[test]
    #[serial_test::serial]
    fn project_discovery_reads_each_unique_input_and_manifest_once() {
        let temporary = TempDir::new().expect("temporary repository");
        let root = temporary.path();
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"many-documents\"\nversion = \"0.1.0\"\n",
        )
        .expect("Cargo manifest");
        std::fs::write(root.join("Cargo.lock"), "version = 4\n").expect("Cargo lockfile");
        std::fs::write(root.join("go.mod"), "module example.test/many\n\ngo 1.26\n")
            .expect("Go manifest");
        std::fs::write(
            root.join("go.sum"),
            "example.test/dependency v1.0.0 h1:fixture\n",
        )
        .expect("Go lockfile");
        std::fs::write(root.join(".tool-versions"), "golang 1.26.0\nrust 1.93.0\n")
            .expect("shared version-manager selector");
        std::fs::write(root.join("src/lib.rs"), "pub fn crate_root() {}\n")
            .expect("Cargo target root positive control");
        let mut sources = (0..64)
            .map(|index| InventorySource::new(format!("src/module_{index}.rs"), "rust"))
            .collect::<Vec<_>>();
        sources.extend(
            (0..64).map(|index| InventorySource::new(format!("src/module_{index}.go"), "go")),
        );

        reset_project_discovery_read_counts(root);
        let inventory = build_project_inventory(root, &sources);
        let (input_reads, manifest_reads) = project_discovery_read_counts(root);

        assert_eq!(inventory.project_topology.memberships.len(), sources.len());
        assert_eq!(
            inventory
                .inputs
                .iter()
                .map(|input| input.path.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                ".tool-versions",
                "Cargo.lock",
                "Cargo.toml",
                "go.mod",
                "go.sum",
            ]),
            "positive control: both distinct Cargo and Go project-input families must be captured"
        );
        assert_eq!(
            inventory
                .inputs
                .iter()
                .filter(|input| input.path == ".tool-versions")
                .map(|input| (input.language_id.0.as_str(), input.ecosystem_id.0.as_str()))
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([("go", "go"), ("rust", "cargo")]),
            "one shared selector must retain both language-specific authority records"
        );
        assert_eq!(
            (input_reads, manifest_reads),
            (5, 2),
            "each unique physical input must be read once and each unique manifest parsed once, independent of source count or language ownership"
        );
    }

    #[test]
    fn cargo_dependency_graph_proves_independence_and_directed_local_edges() {
        let temporary = TempDir::new().expect("Cargo dependency repository");
        let root = temporary.path();
        for package in ["target", "caller", "independent"] {
            std::fs::create_dir_all(root.join(package).join("src"))
                .expect("package source directory");
            std::fs::write(
                root.join(package).join("src/lib.rs"),
                format!("pub fn {package}() {{}}\n"),
            )
            .expect("package source");
        }
        std::fs::write(
            root.join("target/Cargo.toml"),
            "[package]\nname = \"target\"\nversion = \"0.1.0\"\n",
        )
        .expect("target manifest");
        std::fs::write(
            root.join("caller/Cargo.toml"),
            "[package]\nname = \"caller\"\nversion = \"0.1.0\"\n\n[dependencies]\ntarget = { path = \"../target\" }\n",
        )
        .expect("caller manifest");
        std::fs::write(
            root.join("independent/Cargo.toml"),
            "[package]\nname = \"independent\"\nversion = \"0.1.0\"\n",
        )
        .expect("independent manifest");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("target/src/lib.rs", "rust"),
                InventorySource::new("caller/src/lib.rs", "rust"),
                InventorySource::new("independent/src/lib.rs", "rust"),
            ],
        );
        let graph = inventory
            .project_topology
            .dependency_graphs
            .iter()
            .find(|graph| graph.language_id.0 == "rust")
            .expect("Cargo dependency graph");
        assert_eq!(graph.coverage, ProjectUnitDependencyGraphCoverage::Complete);
        assert!(graph.gaps.is_empty());
        assert_eq!(graph.project_unit_ids.len(), 3, "population control");
        let unit_at = |root_path: &str| {
            inventory
                .project_topology
                .units
                .iter()
                .find(|unit| unit.root_path == root_path && unit.kind == ProjectUnitKind::Package)
                .expect("package unit")
                .project_unit_id
                .clone()
        };
        assert_eq!(
            graph.dependencies,
            vec![ProjectUnitDependency {
                dependent_project_unit_id: unit_at("caller"),
                dependency_project_unit_id: unit_at("target"),
            }],
            "only the declared path dependency may enter the local graph"
        );
        assert!(
            !graph
                .dependencies
                .iter()
                .any(|edge| edge.dependent_project_unit_id == unit_at("independent")),
            "positive independence control"
        );

        let canonical = canonical_project_inventory_bytes(&inventory)
            .expect("canonical dependency graph inventory");
        assert_eq!(
            parse_project_inventory_bytes(&canonical).expect("canonical round trip"),
            inventory,
            "known-positive persisted dependency graph"
        );

        let mut reordered: PersistedProjectInventory =
            serde_json::from_slice(&canonical).expect("parse canonical inventory JSON");
        reordered.inventory.project_topology.dependency_graphs[0]
            .project_unit_ids
            .reverse();
        let error = parse_project_inventory_bytes(
            &serde_json::to_vec(&reordered).expect("encode reordered dependency graph"),
        )
        .expect_err("persisted dependency graph ordering is part of canonical authority");
        assert!(error.to_string().contains("not canonical"));

        let mut missing_population = inventory.clone();
        missing_population.project_topology.dependency_graphs[0]
            .project_unit_ids
            .pop();
        let error = canonical_project_inventory_bytes(&missing_population)
            .expect_err("dependency graph must name the exact source-owner population");
        assert!(error.to_string().contains("does not exactly name"));

        let mut unknown_endpoint = inventory.clone();
        unknown_endpoint.project_topology.dependency_graphs[0].dependencies[0]
            .dependency_project_unit_id = ProjectUnitId::new("rust:unknown");
        let error = canonical_project_inventory_bytes(&unknown_endpoint)
            .expect_err("local dependency endpoints must belong to the exact graph population");
        assert!(
            error
                .to_string()
                .contains("outside its exact graph population")
        );

        let mut complete_with_gap = inventory.clone();
        complete_with_gap.project_topology.dependency_graphs[0]
            .gaps
            .push(ProjectUnitDependencyGap {
                reason_code: "falsifier_gap".into(),
                project_unit_id: None,
                path: "Cargo.toml".into(),
                detail: "complete coverage cannot carry a gap".into(),
            });
        let error = canonical_project_inventory_bytes(&complete_with_gap)
            .expect_err("complete topology cannot silently retain unresolved gaps");
        assert!(
            error
                .to_string()
                .contains("complete dependency coverage requires zero gaps")
        );

        let mut partial_without_gap = inventory;
        partial_without_gap.project_topology.dependency_graphs[0].coverage =
            ProjectUnitDependencyGraphCoverage::Partial;
        let error = canonical_project_inventory_bytes(&partial_without_gap)
            .expect_err("partial topology must explain what could not be resolved");
        assert!(
            error
                .to_string()
                .contains("partial coverage requires at least one gap")
        );
    }

    #[test]
    fn go_dependency_graph_proves_independence_and_directed_local_edges() {
        let temporary = TempDir::new().expect("Go dependency repository");
        let root = temporary.path();
        for module in ["target", "caller", "independent"] {
            std::fs::create_dir_all(root.join(module)).expect("module directory");
            std::fs::write(
                root.join(module).join("module.go"),
                format!("package {module}\nfunc Exported() {{}}\n"),
            )
            .expect("module source");
        }
        std::fs::write(
            root.join("target/go.mod"),
            "module example.test/target\n\ngo 1.27\n",
        )
        .expect("target module");
        std::fs::write(
            root.join("caller/go.mod"),
            "module example.test/caller\n\ngo 1.27\n\nrequire example.test/target v0.0.0\n",
        )
        .expect("caller module");
        std::fs::write(
            root.join("independent/go.mod"),
            "module example.test/independent\n\ngo 1.27\n",
        )
        .expect("independent module");
        std::fs::write(
            root.join("go.work"),
            "go 1.27\n\nuse (\n    ./target\n    ./caller\n    ./independent\n)\n",
        )
        .expect("Go workspace");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("target/module.go", "go"),
                InventorySource::new("caller/module.go", "go"),
                InventorySource::new("independent/module.go", "go"),
            ],
        );
        let graph = inventory
            .project_topology
            .dependency_graphs
            .iter()
            .find(|graph| graph.language_id.0 == "go")
            .expect("Go dependency graph");
        assert_eq!(graph.coverage, ProjectUnitDependencyGraphCoverage::Complete);
        assert!(graph.gaps.is_empty());
        assert_eq!(graph.project_unit_ids.len(), 3, "population control");
        let unit_at = |root_path: &str| {
            inventory
                .project_topology
                .units
                .iter()
                .find(|unit| unit.root_path == root_path && unit.kind == ProjectUnitKind::Module)
                .expect("module unit")
                .project_unit_id
                .clone()
        };
        assert_eq!(
            graph.dependencies,
            vec![ProjectUnitDependency {
                dependent_project_unit_id: unit_at("caller"),
                dependency_project_unit_id: unit_at("target"),
            }]
        );
        assert!(
            !graph
                .dependencies
                .iter()
                .any(|edge| edge.dependent_project_unit_id == unit_at("independent")),
            "positive independence control"
        );
    }

    #[test]
    fn go_workspace_provider_inputs_include_every_member_and_missing_companion() {
        let temporary = TempDir::new().expect("Go provider-input repository");
        let root = temporary.path();
        for module in ["alpha", "beta"] {
            std::fs::create_dir_all(root.join(module).join("vendor")).expect("module directory");
            std::fs::write(
                root.join(module).join("module.go"),
                format!("package {module}\nfunc Exported() {{}}\n"),
            )
            .expect("module source");
            std::fs::write(
                root.join(module).join("go.mod"),
                format!("module example.test/{module}\n\ngo 1.27\n"),
            )
            .expect("module manifest");
        }
        std::fs::write(
            root.join("alpha/vendor/modules.txt"),
            "# exact vendored dependency control\n",
        )
        .expect("vendor modules control");
        std::fs::write(
            root.join("go.work"),
            "go 1.27\n\nuse (\n    ./alpha\n    ./beta\n)\n",
        )
        .expect("Go workspace");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("alpha/module.go", "go"),
                InventorySource::new("beta/module.go", "go"),
            ],
        );
        assert!(
            inventory
                .inputs
                .iter()
                .any(|input| input.path == "alpha/vendor/modules.txt"),
            "positive control: canonical inventory must hash vendor/modules.txt"
        );
        let paths = go_provider_semantic_input_paths(&inventory, &BTreeSet::from([String::new()]))
            .expect("workspace-root provider input population");
        assert_eq!(
            paths.get("").expect("workspace root"),
            &BTreeSet::from([
                "alpha/go.mod".into(),
                "alpha/go.sum".into(),
                "alpha/vendor/modules.txt".into(),
                "beta/go.mod".into(),
                "beta/go.sum".into(),
                "beta/vendor/modules.txt".into(),
                "go.work".into(),
                "go.work.sum".into(),
            ]),
            "member manifests and absent lock/vendor companions are one exact stable population"
        );
    }

    #[test]
    fn independent_go_module_topology_fingerprint_is_root_local() {
        let temporary = TempDir::new().expect("independent Go topology repository");
        let root = temporary.path();
        for module in ["alpha", "beta"] {
            std::fs::create_dir_all(root.join(module)).expect("module directory");
            std::fs::write(
                root.join(module).join("module.go"),
                format!("package {module}\nfunc Exported() {{}}\n"),
            )
            .expect("module source");
            std::fs::write(
                root.join(module).join("go.mod"),
                format!("module example.test/{module}\n\ngo 1.27\n"),
            )
            .expect("module manifest");
        }
        let sources = [
            InventorySource::new("alpha/module.go", "go"),
            InventorySource::new("beta/module.go", "go"),
        ];
        let expected_roots = BTreeSet::from(["alpha".into(), "beta".into()]);
        let before = go_execution_root_inventory_fingerprints(
            &build_project_inventory(root, &sources),
            &expected_roots,
        )
        .expect("initial root-local topology fingerprints");

        std::fs::write(
            root.join("alpha/go.mod"),
            "module example.test/alpha\n\ngo 1.27\n\n// alpha-only topology drift\n",
        )
        .expect("alpha-only manifest drift");
        let after = go_execution_root_inventory_fingerprints(
            &build_project_inventory(root, &sources),
            &expected_roots,
        )
        .expect("changed root-local topology fingerprints");

        assert_ne!(before["alpha"], after["alpha"], "positive drift control");
        assert_eq!(
            before["beta"], after["beta"],
            "alpha-only project input drift contaminated beta's topology identity"
        );
    }

    #[test]
    fn nested_go_workspace_owns_member_and_missing_companion_inputs() {
        let temporary = TempDir::new().expect("nested Go provider-input repository");
        let root = temporary.path();
        for module in ["alpha", "beta"] {
            let module_root = root.join("sub").join(module);
            std::fs::create_dir_all(&module_root).expect("nested module directory");
            std::fs::write(
                module_root.join("module.go"),
                format!("package {module}\nfunc Exported() {{}}\n"),
            )
            .expect("nested module source");
            std::fs::write(
                module_root.join("go.mod"),
                format!("module example.test/{module}\n\ngo 1.27\n"),
            )
            .expect("nested module manifest");
        }
        std::fs::write(
            root.join("sub/go.work"),
            "go 1.27\n\nuse (\n\t./alpha\n\t./beta\n)\n",
        )
        .expect("nested Go workspace");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("sub/alpha/module.go", "go"),
                InventorySource::new("sub/beta/module.go", "go"),
            ],
        );
        let paths =
            go_provider_semantic_input_paths(&inventory, &BTreeSet::from(["sub".to_owned()]))
                .expect("nested workspace provider input population");
        assert_eq!(
            paths.get("sub").expect("nested workspace root"),
            &BTreeSet::from([
                "sub/alpha/go.mod".into(),
                "sub/alpha/go.sum".into(),
                "sub/alpha/vendor/modules.txt".into(),
                "sub/beta/go.mod".into(),
                "sub/beta/go.sum".into(),
                "sub/beta/vendor/modules.txt".into(),
                "sub/go.work".into(),
                "sub/go.work.sum".into(),
            ])
        );
    }

    #[test]
    fn sibling_go_module_is_not_local_without_workspace_or_replace_authority() {
        let temporary = TempDir::new().expect("independent Go modules");
        let root = temporary.path();
        for module in ["target", "caller"] {
            std::fs::create_dir_all(root.join(module)).expect("module directory");
            std::fs::write(
                root.join(module).join("module.go"),
                format!("package {module}\nfunc Exported() {{}}\n"),
            )
            .expect("module source");
        }
        std::fs::write(
            root.join("target/go.mod"),
            "module example.test/target\n\ngo 1.27\n",
        )
        .expect("target module");
        std::fs::write(
            root.join("caller/go.mod"),
            "module example.test/caller\n\ngo 1.27\n\nrequire example.test/target v0.0.0\n",
        )
        .expect("caller module");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("target/module.go", "go"),
                InventorySource::new("caller/module.go", "go"),
            ],
        );
        let graph = inventory
            .project_topology
            .dependency_graphs
            .iter()
            .find(|graph| graph.language_id.0 == "go")
            .expect("Go dependency graph");
        assert_eq!(graph.coverage, ProjectUnitDependencyGraphCoverage::Complete);
        assert!(graph.gaps.is_empty());
        assert!(
            graph.dependencies.is_empty(),
            "a registry requirement does not resolve to a coincidentally present sibling checkout"
        );
    }

    #[test]
    fn go_module_local_replace_resolves_without_workspace_authority() {
        let temporary = TempDir::new().expect("replaced Go modules");
        let root = temporary.path();
        for module in ["target", "caller"] {
            std::fs::create_dir_all(root.join(module)).expect("module directory");
            std::fs::write(
                root.join(module).join("module.go"),
                format!("package {module}\nfunc Exported() {{}}\n"),
            )
            .expect("module source");
        }
        std::fs::write(
            root.join("target/go.mod"),
            "module example.test/target\n\ngo 1.27\n",
        )
        .expect("target manifest");
        std::fs::write(
            root.join("caller/go.mod"),
            "module example.test/caller\n\ngo 1.27\n\nrequire example.test/target v0.0.0\nreplace example.test/target => ../target\n",
        )
        .expect("caller manifest");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("target/module.go", "go"),
                InventorySource::new("caller/module.go", "go"),
            ],
        );
        let graph = inventory
            .project_topology
            .dependency_graphs
            .iter()
            .find(|graph| graph.language_id.0 == "go")
            .expect("Go dependency graph");
        let unit_at = |root_path: &str| {
            inventory
                .project_topology
                .units
                .iter()
                .find(|unit| unit.root_path == root_path && unit.kind == ProjectUnitKind::Module)
                .expect("module unit")
                .project_unit_id
                .clone()
        };
        assert_eq!(graph.coverage, ProjectUnitDependencyGraphCoverage::Complete);
        assert_eq!(
            graph.dependencies,
            vec![ProjectUnitDependency {
                dependent_project_unit_id: unit_at("caller"),
                dependency_project_unit_id: unit_at("target"),
            }]
        );
    }

    #[test]
    fn incomplete_go_workspace_population_keeps_dependency_authority_partial() {
        let temporary = TempDir::new().expect("partial Go workspace");
        let root = temporary.path();
        for module in ["target", "caller"] {
            std::fs::create_dir_all(root.join(module)).expect("module directory");
            std::fs::write(
                root.join(module).join("module.go"),
                format!("package {module}\nfunc Exported() {{}}\n"),
            )
            .expect("module source");
            std::fs::write(
                root.join(module).join("go.mod"),
                format!("module example.test/{module}\n\ngo 1.27\n"),
            )
            .expect("module manifest");
        }
        std::fs::write(
            root.join("go.work"),
            "go 1.27\n\nuse (\n    ./target\n    ./missing\n)\n",
        )
        .expect("incomplete Go workspace");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("target/module.go", "go"),
                InventorySource::new("caller/module.go", "go"),
            ],
        );
        let graph = inventory
            .project_topology
            .dependency_graphs
            .iter()
            .find(|graph| graph.language_id.0 == "go")
            .expect("Go dependency graph");
        assert_eq!(graph.coverage, ProjectUnitDependencyGraphCoverage::Partial);
        assert!(graph.gaps.iter().any(|gap| {
            gap.reason_code == "go_workspace_use_unresolved" && gap.path == "go.work"
        }));
        assert!(graph.gaps.iter().any(|gap| {
            gap.reason_code == "go_workspace_module_not_used" && gap.project_unit_id.is_some()
        }));
    }

    #[test]
    fn workspace_inherited_cargo_dependency_resolves_to_the_local_unit() {
        let temporary = TempDir::new().expect("partial Cargo dependency repository");
        let root = temporary.path();
        for package in ["target", "caller"] {
            std::fs::create_dir_all(root.join(package).join("src"))
                .expect("package source directory");
            std::fs::write(root.join(package).join("src/lib.rs"), "pub fn item() {}\n")
                .expect("package source");
        }
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"target\", \"caller\"]\n\n[workspace.dependencies]\ntarget = { path = \"target\" }\n",
        )
        .expect("workspace manifest");
        std::fs::write(
            root.join("target/Cargo.toml"),
            "[package]\nname = \"target\"\nversion = \"0.1.0\"\n",
        )
        .expect("target manifest");
        std::fs::write(
            root.join("caller/Cargo.toml"),
            "[package]\nname = \"caller\"\nversion = \"0.1.0\"\n\n[dependencies]\ntarget.workspace = true\n",
        )
        .expect("caller manifest");

        let inventory = build_project_inventory(
            root,
            &[
                InventorySource::new("target/src/lib.rs", "rust"),
                InventorySource::new("caller/src/lib.rs", "rust"),
            ],
        );
        let graph = inventory
            .project_topology
            .dependency_graphs
            .iter()
            .find(|graph| graph.language_id.0 == "rust")
            .expect("Cargo dependency graph");
        assert_eq!(
            graph.coverage,
            ProjectUnitDependencyGraphCoverage::Complete,
            "a canonical workspace path dependency is exact local topology, not an authority gap"
        );
        assert!(graph.gaps.is_empty());
        assert_eq!(
            graph.project_unit_ids.len(),
            2,
            "population remains explicit"
        );
        let unit_at = |root_path: &str| {
            inventory
                .project_topology
                .units
                .iter()
                .find(|unit| unit.root_path == root_path && unit.kind == ProjectUnitKind::Package)
                .expect("workspace package unit")
                .project_unit_id
                .clone()
        };
        assert_eq!(
            graph.dependencies,
            vec![ProjectUnitDependency {
                dependent_project_unit_id: unit_at("caller"),
                dependency_project_unit_id: unit_at("target"),
            }]
        );
    }

    #[test]
    fn persisted_inventory_round_trip_rejects_duplicate_cycle_and_unknown_schema() {
        let temporary = TempDir::new().expect("temporary repository");
        std::fs::create_dir_all(temporary.path().join("crates/member/src"))
            .expect("member source directory");
        std::fs::write(
            temporary.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/member\"]\n",
        )
        .expect("workspace manifest");
        std::fs::write(
            temporary.path().join("crates/member/Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\n",
        )
        .expect("member manifest");
        let inventory = build_project_inventory(
            temporary.path(),
            &[InventorySource::new("crates/member/src/lib.rs", "rust")],
        );
        let bytes =
            canonical_project_inventory_bytes(&inventory).expect("canonical inventory bytes");
        assert_eq!(
            parse_project_inventory_bytes(&bytes).expect("parse canonical inventory"),
            inventory
        );

        let mut duplicate = inventory.clone();
        duplicate
            .project_topology
            .memberships
            .push(duplicate.project_topology.memberships[0].clone());
        let error = canonical_project_inventory_bytes(&duplicate)
            .expect_err("duplicate membership must fail closed");
        assert!(error.to_string().contains("must not contain duplicates"));

        let mut multiple_owners = inventory.clone();
        multiple_owners
            .project_topology
            .memberships
            .iter_mut()
            .find(|membership| membership.kind == DocumentMembershipKind::PathContext)
            .expect("workspace context membership")
            .kind = DocumentMembershipKind::SourceOwner;
        let error = canonical_project_inventory_bytes(&multiple_owners)
            .expect_err("one document cannot have two source owners");
        assert!(error.to_string().contains("exactly one source owner"));

        let mut cycle = inventory;
        let existing = cycle.project_topology.relationships[0].clone();
        cycle
            .project_topology
            .relationships
            .push(ProjectUnitRelationship {
                parent_project_unit_id: existing.child_project_unit_id,
                child_project_unit_id: existing.parent_project_unit_id,
                kind: ProjectUnitRelationshipKind::PathNestedWithin,
            });
        let error = canonical_project_inventory_bytes(&cycle)
            .expect_err("relationship cycle must fail closed");
        assert!(error.to_string().contains("contain a cycle"));

        let mut unknown_schema: serde_json::Value =
            serde_json::from_slice(&bytes).expect("parse persisted document");
        unknown_schema["schema_version"] = serde_json::Value::String("unknown/v9".into());
        let error = parse_project_inventory_bytes(
            &serde_json::to_vec(&unknown_schema).expect("encode unknown schema"),
        )
        .expect_err("unknown schema must fail closed");
        assert!(error.to_string().contains("unsupported schema"));
    }
}
