//! Provider-neutral code-intelligence domain contracts.
//!
//! This module is deliberately below every transport. Human CLI, CLI JSON,
//! and MCP all execute the same use case and serialize the same result. The
//! current graph is an input adapter; its UUIDs, redb layout, and provider
//! metadata are not part of this contract.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::structural_ir::{SymbolRole, symbol_kind_has_role};

pub const CALLS_CONFIGURATION_ID: &str = "calls-v9";
pub const CALLABLE_LIVENESS_CONFIGURATION_ID: &str = "callable-liveness-v1";
pub const STRUCTURAL_GRAPH_CONFIGURATION_ID: &str = "structural-v2";
pub const PROJECT_DEPENDENCIES_CONFIGURATION_ID: &str = "project-dependencies-v1";
pub const DEFAULT_CALLS_PAGE_SIZE: usize = 50;
pub const MAX_CALLS_PAGE_SIZE: usize = 100;
pub const DEFAULT_TYPE_PAGE_SIZE: usize = 50;
pub const MAX_TYPE_PAGE_SIZE: usize = 100;
/// Serialized-character headroom reserved by generation-bound engine results
/// for the adapter's live-input observation and stale/unknown qualification.
///
/// The engine owns immutable-generation computation; the adapter owns the
/// filesystem observation, so bounded use cases must leave this space before
/// crossing that boundary.
pub const LIVE_INPUT_RESULT_RESERVE_CHARS: usize = 768;
/// Final serialized-character ceiling for one successful code-intelligence
/// result on every machine-readable product surface.
///
/// Engine operations may reserve space below this ceiling for adapter-owned
/// live-input evidence; the shared CLI/MCP snapshot boundary enforces the final
/// value.
pub const MAX_CODE_INTEL_RESULT_CHARS: usize = 28_000;
/// Engine-owned generation-result ceiling before the adapter attaches its
/// independently observed live-input evidence.
pub const MAX_GENERATION_ENGINE_RESULT_CHARS: usize =
    MAX_CODE_INTEL_RESULT_CHARS - LIVE_INPUT_RESULT_RESERVE_CHARS;

/// The exact source population over which a complete Calls result has
/// authority. This is intentionally narrower than runtime dispatch or fully
/// expanded macro semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallsPopulation {
    /// Provider-resolved occurrences independently corroborated as explicit
    /// source invocation syntax. Registered language grammars identify normal
    /// calls; inside opaque Rust macro-invocation token trees, the provider
    /// callee token must be followed only by source trivia and then `(`.
    ProviderResolvedExplicitSourceInvocations,
}

/// Syntactic execution context for a provider-resolved call that has no
/// published structural caller.
///
/// This is orthogonal to production/test source classification: module
/// initialization executes when the module is loaded, while an anonymous
/// callable body executes only if that callable runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionRootContext {
    ModuleInitialization,
    AnonymousCallable,
}

impl ExecutionRootContext {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModuleInitialization => "module_initialization",
            Self::AnonymousCallable => "anonymous_callable",
        }
    }
}

impl std::fmt::Display for CallsPopulation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ProviderResolvedExplicitSourceInvocations => {
                formatter.write_str("provider_resolved_explicit_source_invocations")
            }
        }
    }
}

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_id!(RepositoryId);
string_id!(ProjectUnitId);
string_id!(AnalysisContextId);
string_id!(AnalysisContextKindId);
string_id!(EcosystemId);
string_id!(ConfigurationId);
string_id!(LanguageId);
string_id!(ProviderId);
string_id!(GenerationId);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepositoryBinding {
    pub repository_id: RepositoryId,
    pub root_label: String,
    /// Bounded live-input observation made by the shipped adapter for this
    /// request. Pure immutable-generation queries leave this absent; CLI and
    /// MCP boundaries must attach it before returning a generation-bound
    /// result so snapshot authority cannot be mistaken for current-worktree
    /// authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_inputs: Option<LiveInputObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveInputFreshness {
    Fresh,
    Stale,
    Unknown,
}

impl LiveInputFreshness {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveInputConsistency {
    /// Files and project inputs are verified during one bounded request, but
    /// the worktree has no repository-wide read transaction.
    PerFileNonAtomic,
}

/// Exact relation between one immutable generation and the live repository
/// inputs observed at a shipped query boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveInputObservation {
    pub freshness: LiveInputFreshness,
    pub consistency: LiveInputConsistency,
    pub indexed_file_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_checked: Option<usize>,
}

impl LiveInputObservation {
    #[must_use]
    pub fn from_staleness(
        verdict: crate::graph_stats::StalenessVerdict,
        indexed_file_count: usize,
    ) -> Self {
        use crate::graph_stats::{StalenessReason, StalenessVerdict};

        let (freshness, reason, files_checked) = match verdict {
            StalenessVerdict::Fresh => (LiveInputFreshness::Fresh, None, None),
            StalenessVerdict::Stale => (LiveInputFreshness::Stale, None, None),
            StalenessVerdict::Unknown {
                reason,
                files_checked,
            } => (
                LiveInputFreshness::Unknown,
                Some(
                    match reason {
                        StalenessReason::Truncated => "truncated",
                        StalenessReason::NoSourceFound => "no_source_found",
                        StalenessReason::IndexedSourceSnapshotUnavailable => {
                            "indexed_source_snapshot_unavailable"
                        }
                        StalenessReason::SourceVerificationFailed => "source_verification_failed",
                        StalenessReason::ProviderSemanticInputsUnverifiable => {
                            "provider_semantic_inputs_unverifiable"
                        }
                    }
                    .into(),
                ),
                Some(files_checked),
            ),
        };
        Self {
            freshness,
            consistency: LiveInputConsistency::PerFileNonAtomic,
            indexed_file_count,
            reason,
            files_checked,
        }
    }

    /// Human/MCP qualification for a result that remains exact only within
    /// its immutable generation.
    #[must_use]
    pub fn generation_qualification(&self) -> Option<String> {
        match self.freshness {
            LiveInputFreshness::Fresh => None,
            LiveInputFreshness::Stale => Some(
                "live source/project inputs differ from this immutable generation; this result describes the immutable generation, not the current worktree; run `h00ligan index` to refresh"
                    .into(),
            ),
            LiveInputFreshness::Unknown => Some(format!(
                "live source/project input freshness could not be verified ({reason}); this result describes only the immutable generation and may not describe the current worktree",
                reason = self.reason.as_deref().unwrap_or("unknown_reason"),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProjectUnit {
    pub project_unit_id: ProjectUnitId,
    pub language_id: LanguageId,
    pub ecosystem_id: EcosystemId,
    pub kind: ProjectUnitKind,
    /// Repository-relative directory governed by this unit. The repository root
    /// is the empty string; absolute machine paths never enter the domain.
    pub root_path: String,
    pub manifest_path: Option<String>,
    /// Exact indexed source documents that the project system declares as
    /// independent compilation roots for this unit. Rust uses these crate-root
    /// paths to resolve external modules without guessing from filenames.
    /// Other ecosystems leave the set empty until their project adapter has an
    /// equivalent exact concept.
    pub compilation_root_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectUnitKind {
    Workspace,
    Package,
    Module,
    /// An executable application environment that is a semantic-provider
    /// unit but not a distributable language package. Python repositories
    /// rooted by requirements files or a Pipfile use this shape.
    Application,
    /// Repository-owned source with no language project-system execution unit.
    /// It remains structurally searchable but cannot authorize semantic facts.
    LooseSources,
    /// Repository-owned source-shaped data that remains structurally
    /// searchable but is intentionally outside a language project's semantic
    /// provider population. For example, Go tooling ignores directories named
    /// `testdata` unless that subtree declares its own module.
    AuxiliarySources,
}

impl ProjectUnitKind {
    /// Whether this unit may contribute a required semantic-provider scope.
    ///
    /// Structural extraction still includes loose and auxiliary sources. This
    /// predicate separates that useful source visibility from authority for
    /// Calls and other project-system capabilities.
    #[must_use]
    pub const fn grants_semantic_authority(self) -> bool {
        !matches!(self, Self::LooseSources | Self::AuxiliarySources)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentMembershipKind {
    /// The project system identifies this unit as an owner of the document.
    SourceOwner,
    /// The unit is relevant because its root contains the document, but direct
    /// ownership has not been established. This must never authorize a scoped
    /// semantic capability by itself.
    PathContext,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DocumentMembership {
    pub document_path: String,
    pub language_id: LanguageId,
    pub project_unit_id: ProjectUnitId,
    pub kind: DocumentMembershipKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectUnitRelationshipKind {
    /// Filesystem containment only. It does not claim workspace membership,
    /// project references, dependency direction, or configuration inheritance.
    PathNestedWithin,
    /// The owning project system explicitly includes the child package/module
    /// in the parent workspace. This is stronger than path containment and may
    /// govern provider execution roots and local dependency resolution.
    WorkspaceMember,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProjectUnitRelationship {
    pub parent_project_unit_id: ProjectUnitId,
    pub child_project_unit_id: ProjectUnitId,
    pub kind: ProjectUnitRelationshipKind,
}

/// One directed local project-unit dependency.
///
/// The dependent unit may call symbols owned by the dependency unit;
/// query-time possible-caller closure therefore traverses these edges in
/// reverse from the selected target unit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProjectUnitDependency {
    pub dependent_project_unit_id: ProjectUnitId,
    pub dependency_project_unit_id: ProjectUnitId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectUnitDependencyGraphCoverage {
    /// The named project-unit population and every local dependency edge were
    /// resolved from the indexed generation's exact project inputs.
    Complete,
    /// At least one unit, manifest, or dependency declaration could not be
    /// resolved. Consumers must not use missing edges as absence evidence.
    Partial,
}

/// One machine-readable reason a local dependency graph is not complete.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProjectUnitDependencyGap {
    pub reason_code: String,
    pub project_unit_id: Option<ProjectUnitId>,
    pub path: String,
    pub detail: String,
}

/// Exact local dependency authority for one language/ecosystem population.
///
/// The explicit unit population is load-bearing: a complete empty edge set is
/// useful proof only when it also names every semantic source-owning unit that
/// was considered. Missing or partial graphs preserve language-wide authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProjectUnitDependencyGraph {
    pub language_id: LanguageId,
    pub ecosystem_id: EcosystemId,
    pub coverage: ProjectUnitDependencyGraphCoverage,
    pub project_unit_ids: Vec<ProjectUnitId>,
    pub dependencies: Vec<ProjectUnitDependency>,
    pub gaps: Vec<ProjectUnitDependencyGap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInventoryCoverage {
    /// Every document in the exact indexed source population was classified;
    /// this does not claim that ignored or unsupported repository files exist.
    IndexedSourcePopulationComplete,
    /// At least one indexed document or manifest could not be classified. The
    /// issues list carries the stable machine reason for every known gap.
    IndexedSourcePopulationPartial,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProjectInventoryIssueScope {
    Repository,
    Language {
        language_id: LanguageId,
    },
    Ecosystem {
        language_id: LanguageId,
        ecosystem_id: EcosystemId,
    },
}

impl ProjectInventoryIssueScope {
    #[must_use]
    pub fn applies_to_language(&self, language_id: &LanguageId) -> bool {
        match self {
            Self::Repository => true,
            Self::Language {
                language_id: affected,
            }
            | Self::Ecosystem {
                language_id: affected,
                ..
            } => affected == language_id,
        }
    }

    #[must_use]
    pub fn applies_to_provider(
        &self,
        language_id: &LanguageId,
        ecosystem_id: &EcosystemId,
    ) -> bool {
        match self {
            Self::Repository => true,
            Self::Language {
                language_id: affected,
            } => affected == language_id,
            Self::Ecosystem {
                language_id: affected_language,
                ecosystem_id: affected_ecosystem,
            } => affected_language == language_id && affected_ecosystem == ecosystem_id,
        }
    }

    #[must_use]
    pub fn applies_to_languages(&self, language_ids: &BTreeSet<LanguageId>) -> bool {
        match self {
            Self::Repository => true,
            Self::Language { language_id } | Self::Ecosystem { language_id, .. } => {
                language_ids.contains(language_id)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProjectInventoryIssue {
    pub scope: ProjectInventoryIssueScope,
    pub code: String,
    pub path: String,
    pub detail: String,
}

/// Physical package/workspace ownership and dependency topology.
///
/// Every indexed document has exactly one source owner in this layer. That
/// invariant deliberately does not describe compiler/interpreter contexts: a
/// document may participate in zero, one, or many declared analysis contexts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectTopology {
    pub units: Vec<ProjectUnit>,
    pub memberships: Vec<DocumentMembership>,
    pub relationships: Vec<ProjectUnitRelationship>,
    /// Workspace units whose declared member selector was resolved across the
    /// exact indexed package/module population. For these workspaces, absence
    /// of a `WorkspaceMember` edge is authoritative non-membership and path
    /// containment must not broaden a semantic-provider execution root.
    pub exact_workspace_member_sets: Vec<ProjectUnitId>,
    pub dependency_graphs: Vec<ProjectUnitDependencyGraph>,
}

/// One repository-declared compiler, interpreter, or module-resolution
/// configuration that can schedule a later semantic provider invocation.
///
/// This is topology, never semantic authority. Only provider-observed evidence
/// and a capability receipt may prove the complete program population or any
/// semantic relationship.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AnalysisContext {
    pub analysis_context_id: AnalysisContextId,
    pub language_id: LanguageId,
    pub ecosystem_id: EcosystemId,
    pub kind_id: AnalysisContextKindId,
    /// Repository-relative directory against which this context resolves
    /// relative configuration and module paths.
    pub root_path: String,
    pub configuration_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisContextMembershipKind {
    /// The document is selected by the context's effective `files`/`include`
    /// declaration or an equivalent explicit project-system root selector.
    /// Imports and provider-discovered transitive inputs are not implied.
    DeclaredRoot,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AnalysisContextMembership {
    pub document_path: String,
    pub language_id: LanguageId,
    pub analysis_context_id: AnalysisContextId,
    pub kind: AnalysisContextMembershipKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisContextRelationshipKind {
    /// Configuration inheritance. Relative fields retain the base
    /// configuration's own resolution root; this edge does not copy strings.
    ConfigurationExtends,
    /// An explicit compiler-project reference and its build/navigation order.
    ProjectReferences,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AnalysisContextRelationship {
    pub source_analysis_context_id: AnalysisContextId,
    pub target_analysis_context_id: AnalysisContextId,
    pub kind: AnalysisContextRelationshipKind,
    /// Stable declaration order for ordered inheritance/reference lists.
    /// Single-target declarations use zero.
    pub ordinal: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisContextCoverage {
    /// Every repository-declared context and declared root in this exact
    /// indexed language population was resolved. This does not claim complete
    /// compiler-program membership or semantic authority.
    DeclaredConfigurationComplete,
    /// At least one declared context, relationship, or root selector could not
    /// be resolved. Typed gaps name the missing authority.
    DeclaredConfigurationPartial,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AnalysisContextGap {
    pub reason_code: String,
    pub analysis_context_id: Option<AnalysisContextId>,
    pub path: String,
    pub detail: String,
}

/// Language-scoped declared analysis topology for one immutable source and
/// project-input population.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AnalysisContextGraph {
    pub language_id: LanguageId,
    pub ecosystem_id: EcosystemId,
    pub coverage: AnalysisContextCoverage,
    pub contexts: Vec<AnalysisContext>,
    pub memberships: Vec<AnalysisContextMembership>,
    pub relationships: Vec<AnalysisContextRelationship>,
    pub gaps: Vec<AnalysisContextGap>,
}

/// Why one repository-local file influenced project ownership or provider
/// configuration for an immutable generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectInputRole {
    Manifest,
    DependencyLock,
    ToolConfiguration,
}

/// Exact repository-local non-source input consumed by project discovery or a
/// semantic provider configuration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProjectInput {
    pub path: String,
    pub language_id: LanguageId,
    pub ecosystem_id: EcosystemId,
    pub role: ProjectInputRole,
    pub content_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectInventory {
    pub coverage: ProjectInventoryCoverage,
    pub project_topology: ProjectTopology,
    pub analysis_context_graphs: Vec<AnalysisContextGraph>,
    pub inputs: Vec<ProjectInput>,
    pub issues: Vec<ProjectInventoryIssue>,
}

impl ProjectInventory {
    #[must_use]
    pub fn issues_for_language(&self, language_id: &LanguageId) -> Vec<&ProjectInventoryIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.scope.applies_to_language(language_id))
            .collect()
    }

    #[must_use]
    pub fn coverage_for_language(&self, language_id: &LanguageId) -> ProjectInventoryCoverage {
        if self.issues_for_language(language_id).is_empty() {
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        } else {
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        }
    }

    #[must_use]
    pub fn issues_for_languages(
        &self,
        language_ids: &BTreeSet<LanguageId>,
    ) -> Vec<&ProjectInventoryIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.scope.applies_to_languages(language_ids))
            .collect()
    }

    #[must_use]
    pub fn coverage_for_languages(
        &self,
        language_ids: &BTreeSet<LanguageId>,
    ) -> ProjectInventoryCoverage {
        if self.issues_for_languages(language_ids).is_empty() {
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        } else {
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        }
    }

    #[must_use]
    pub fn issues_for_provider(
        &self,
        language_id: &LanguageId,
        ecosystem_id: &EcosystemId,
    ) -> Vec<&ProjectInventoryIssue> {
        self.issues
            .iter()
            .filter(|issue| issue.scope.applies_to_provider(language_id, ecosystem_id))
            .collect()
    }

    #[must_use]
    pub fn coverage_for_provider(
        &self,
        language_id: &LanguageId,
        ecosystem_id: &EcosystemId,
    ) -> ProjectInventoryCoverage {
        if self
            .issues_for_provider(language_id, ecosystem_id)
            .is_empty()
        {
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        } else {
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        }
    }

    /// Whether the exact document has a validated structural-only source owner.
    /// Missing or malformed ownership is never classified this way, so it
    /// remains in fail-closed provider validation instead of disappearing.
    #[must_use]
    pub fn is_structural_only_source_document(
        &self,
        document_path: &str,
        language_id: &LanguageId,
    ) -> bool {
        self.project_topology.memberships.iter().any(|membership| {
            membership.document_path == document_path
                && membership.language_id == *language_id
                && membership.kind == DocumentMembershipKind::SourceOwner
                && self.project_topology.units.iter().any(|unit| {
                    unit.project_unit_id == membership.project_unit_id
                        && !unit.kind.grants_semantic_authority()
                })
        })
    }

    /// Whether a source-owner membership participates in semantic provider
    /// authority rather than structural-only source visibility.
    ///
    /// A missing referenced unit is deliberately treated as semantic here so
    /// malformed inventories cannot make required scope disappear. Canonical
    /// inventory validation rejects that shape at the publication boundary.
    #[must_use]
    pub fn is_semantic_source_owner(&self, membership: &DocumentMembership) -> bool {
        membership.kind == DocumentMembershipKind::SourceOwner
            && self
                .project_topology
                .units
                .iter()
                .find(|unit| unit.project_unit_id == membership.project_unit_id)
                .is_none_or(|unit| unit.kind.grants_semantic_authority())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitGraph {
    /// Whether this projection came from the indexed generation inventory or
    /// from a transitional caller that supplied no inventory at all.
    pub coverage: UnitGraphCoverage,
    pub units: Vec<ProjectUnit>,
    pub memberships: Vec<DocumentMembership>,
    pub relationships: Vec<ProjectUnitRelationship>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitGraphCoverage {
    NoIndexedInventory,
    IndexedGenerationQueryProjection,
    IndexedGenerationPartialQueryProjection,
}

/// The exact semantic scope covered by one capability receipt.
///
/// Language scope is intentionally first-class. A pipeline that has measured
/// Rust and Go source files but has not yet built a complete monorepo unit graph
/// can state honest per-language evidence without inventing repository-shaped
/// project units. Project-unit receipts are reserved for an actual inventory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CapabilityScope {
    Repository {
        configuration_id: ConfigurationId,
    },
    Language {
        language_id: LanguageId,
        configuration_id: ConfigurationId,
    },
    ProjectUnit {
        language_id: LanguageId,
        project_unit_id: ProjectUnitId,
        configuration_id: ConfigurationId,
    },
    /// One provider execution covered this exact set of project units as a
    /// single semantic graph. This preserves cross-unit calls inside a Cargo
    /// workspace (or equivalent polyglot execution root) without claiming
    /// detached units that the provider did not index.
    ProjectUnits {
        language_id: LanguageId,
        project_unit_ids: Vec<ProjectUnitId>,
        configuration_id: ConfigurationId,
    },
}

impl CapabilityScope {
    #[must_use]
    pub const fn language_id(&self) -> Option<&LanguageId> {
        match self {
            Self::Repository { .. } => None,
            Self::Language { language_id, .. }
            | Self::ProjectUnit { language_id, .. }
            | Self::ProjectUnits { language_id, .. } => Some(language_id),
        }
    }

    pub const fn configuration_id(&self) -> &ConfigurationId {
        match self {
            Self::Repository { configuration_id }
            | Self::Language {
                configuration_id, ..
            }
            | Self::ProjectUnit {
                configuration_id, ..
            }
            | Self::ProjectUnits {
                configuration_id, ..
            } => configuration_id,
        }
    }

    pub fn covers(&self, target: &Self) -> bool {
        if self.configuration_id() != target.configuration_id() {
            return false;
        }
        match (self, target) {
            (Self::Repository { .. }, _) => true,
            (
                Self::Language {
                    language_id: covered,
                    ..
                },
                Self::Language {
                    language_id: target,
                    ..
                }
                | Self::ProjectUnit {
                    language_id: target,
                    ..
                }
                | Self::ProjectUnits {
                    language_id: target,
                    ..
                },
            ) => covered == target,
            (
                Self::ProjectUnits {
                    language_id: covered_language,
                    project_unit_ids: covered_units,
                    ..
                },
                Self::ProjectUnit {
                    language_id: target_language,
                    project_unit_id: target_unit,
                    ..
                },
            ) => covered_language == target_language && covered_units.contains(target_unit),
            (
                Self::ProjectUnits {
                    language_id: covered_language,
                    project_unit_ids: covered_units,
                    ..
                },
                Self::ProjectUnits {
                    language_id: target_language,
                    project_unit_ids: target_units,
                    ..
                },
            ) => {
                covered_language == target_language
                    && target_units.iter().all(|unit| covered_units.contains(unit))
            }
            (Self::ProjectUnit { .. }, Self::ProjectUnit { .. }) => self == target,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Complete,
    Partial,
    Unavailable,
}

/// One provider's machine-readable explanation for missing capability authority.
///
/// Values come directly from persisted receipts unless the resolver itself
/// detects an ambiguity or malformed population.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityEvidenceGap {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<ProviderId>,
    pub status: CapabilityStatus,
    pub reason_code: String,
    pub reason: String,
}

/// A bounded qualification on otherwise usable capability evidence.
///
/// Unlike [`CapabilityEvidenceGap`], a qualification does not mean provider
/// evidence is missing or malformed. It records an explicit population the
/// selected provider excludes, so callers can use covered results without
/// silently broadening them into complete authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityQualification {
    pub provider_id: ProviderId,
    pub reason_code: String,
    pub reason: String,
}

/// Calls authority for one callable language in the indexed generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LanguageCapabilityCoverage {
    pub language_id: LanguageId,
    pub status: CapabilityCoverageStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<ProviderId>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<CapabilityEvidenceGap>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub qualifications: Vec<CapabilityQualification>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCoverageStatus {
    NotApplicable,
    Complete,
    Qualified,
    Partial,
    Unavailable,
}

/// Generation-authoritative capability coverage.
///
/// Unlike an aggregate provider-success bit, this cannot turn one successful
/// language into authority for every other language in a mixed repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityCoverage {
    pub capability_id: String,
    pub status: CapabilityCoverageStatus,
    pub languages: Vec<LanguageCapabilityCoverage>,
}

impl CapabilityCoverage {
    #[must_use]
    pub fn complete_languages(&self) -> BTreeSet<LanguageId> {
        self.languages
            .iter()
            .filter(|language| language.status == CapabilityCoverageStatus::Complete)
            .map(|language| language.language_id.clone())
            .collect()
    }

    #[must_use]
    pub const fn all_callable_languages_complete(&self) -> bool {
        matches!(
            self.status,
            CapabilityCoverageStatus::NotApplicable | CapabilityCoverageStatus::Complete
        )
    }

    #[must_use]
    pub fn any_callable_language_complete(&self) -> bool {
        self.languages
            .iter()
            .any(|language| language.status == CapabilityCoverageStatus::Complete)
    }

    #[must_use]
    pub fn language_is_complete(&self, language_id: &str) -> bool {
        self.languages.iter().any(|language| {
            language.language_id.0 == language_id
                && language.status == CapabilityCoverageStatus::Complete
        })
    }

    #[must_use]
    pub fn language_is_usable(&self, language_id: &str) -> bool {
        self.languages.iter().any(|language| {
            language.language_id.0 == language_id
                && matches!(
                    language.status,
                    CapabilityCoverageStatus::Complete | CapabilityCoverageStatus::Qualified
                )
        })
    }

    #[must_use]
    pub fn language_status(&self, language_id: &str) -> Option<CapabilityCoverageStatus> {
        self.languages
            .iter()
            .find(|language| language.language_id.0 == language_id)
            .map(|language| language.status)
    }

    /// Whether a best-effort semantic indexing request has already done all
    /// work available for the discovered project units.
    ///
    /// Structural-only sources do not enter the capability population. A
    /// remaining unavailable execution-root gap therefore represents provider
    /// work that cannot improve until project configuration changes; repeatedly
    /// invoking the same provider cannot improve it.
    #[must_use]
    pub fn satisfies_best_effort_provider_intent(&self) -> bool {
        self.languages.iter().all(|language| {
            matches!(
                language.status,
                CapabilityCoverageStatus::Complete | CapabilityCoverageStatus::Qualified
            ) || (!language.gaps.is_empty()
                && language.gaps.iter().all(|gap| {
                    gap.reason_code == "provider_execution_root_unavailable"
                        && gap.status == CapabilityStatus::Unavailable
                }))
        })
    }
}

/// Derive one aggregate status from an exact per-language capability census.
///
/// Capability adapters may add payload-backed qualifications after generic
/// receipt resolution. Keeping the fold here prevents Calls, callable
/// liveness, and future typed capabilities from inventing subtly different
/// repository-level status semantics.
#[must_use]
pub fn aggregate_capability_coverage_status(
    languages: &[LanguageCapabilityCoverage],
) -> CapabilityCoverageStatus {
    if languages.is_empty() {
        CapabilityCoverageStatus::NotApplicable
    } else if languages
        .iter()
        .all(|language| language.status == CapabilityCoverageStatus::Complete)
    {
        CapabilityCoverageStatus::Complete
    } else if languages.iter().all(|language| {
        matches!(
            language.status,
            CapabilityCoverageStatus::Complete | CapabilityCoverageStatus::Qualified
        )
    }) {
        CapabilityCoverageStatus::Qualified
    } else if languages
        .iter()
        .all(|language| language.status == CapabilityCoverageStatus::Unavailable)
    {
        CapabilityCoverageStatus::Unavailable
    } else {
        CapabilityCoverageStatus::Partial
    }
}

/// Resolve a capability independently for every callable language using the
/// exact generation inventory and receipt population.
pub fn assess_language_capability(
    receipts: &[CapabilityReceipt],
    inventory: &ProjectInventory,
    capability_id: &str,
    configuration_id: &str,
    callable_languages: impl IntoIterator<Item = LanguageId>,
) -> CapabilityCoverage {
    let callable_languages = callable_languages.into_iter().collect::<BTreeSet<_>>();
    let mut languages = Vec::with_capacity(callable_languages.len());
    for language_id in callable_languages {
        let owners = inventory
            .project_topology
            .memberships
            .iter()
            .filter(|membership| {
                membership.language_id == language_id
                    && inventory.is_semantic_source_owner(membership)
            })
            .map(|membership| membership.project_unit_id.clone())
            .collect::<BTreeSet<_>>();
        let required_scopes = if owners.is_empty() {
            vec![CapabilityScope::Language {
                language_id: language_id.clone(),
                configuration_id: ConfigurationId::new(configuration_id),
            }]
        } else {
            owners
                .into_iter()
                .map(|project_unit_id| CapabilityScope::ProjectUnit {
                    language_id: language_id.clone(),
                    project_unit_id,
                    configuration_id: ConfigurationId::new(configuration_id),
                })
                .collect()
        };

        match resolve_capability_provider(receipts, capability_id, &required_scopes, None) {
            Ok(provider) => languages.push(LanguageCapabilityCoverage {
                language_id,
                status: CapabilityCoverageStatus::Complete,
                provider_id: Some(provider.provider_id),
                gaps: Vec::new(),
                qualifications: Vec::new(),
            }),
            Err(error) => {
                let public_reason = error.public_reason();
                let resolution_reason_code = error.evidence_reason_code();
                let mut gaps = receipts
                    .iter()
                    .filter(|receipt| {
                        receipt.capability_id == capability_id
                            && receipt.scope.configuration_id().0 == configuration_id
                            && required_scopes
                                .iter()
                                .any(|required| receipt.scope.covers(required))
                            && receipt.status != CapabilityStatus::Complete
                    })
                    .map(|receipt| CapabilityEvidenceGap {
                        provider_id: Some(receipt.provider_id.clone()),
                        status: receipt.status,
                        reason_code: receipt
                            .reason_code
                            .clone()
                            .unwrap_or_else(|| "provider_evidence_incomplete".into()),
                        reason: receipt
                            .reason
                            .clone()
                            .unwrap_or_else(|| public_reason.clone()),
                    })
                    .collect::<Vec<_>>();
                if gaps.is_empty() {
                    let covered_scopes = required_scopes
                        .iter()
                        .filter(|required| {
                            receipts.iter().any(|receipt| {
                                receipt.capability_id == capability_id
                                    && receipt.status == CapabilityStatus::Complete
                                    && receipt.scope.covers(required)
                            })
                        })
                        .count();
                    if covered_scopes > 0 && covered_scopes < required_scopes.len() {
                        let providers = receipts
                            .iter()
                            .filter(|receipt| {
                                receipt.capability_id == capability_id
                                    && receipt.status == CapabilityStatus::Complete
                                    && required_scopes
                                        .iter()
                                        .any(|required| receipt.scope.covers(required))
                            })
                            .map(|receipt| receipt.provider_id.clone())
                            .collect::<BTreeSet<_>>();
                        gaps.push(CapabilityEvidenceGap {
                            provider_id: (providers.len() == 1)
                                .then(|| providers.into_iter().next())
                                .flatten(),
                            status: CapabilityStatus::Partial,
                            reason_code: "provider_scope_population_incomplete".into(),
                            reason: format!(
                                "complete provider evidence covers {covered_scopes}/{} required project-unit scopes",
                                required_scopes.len()
                            ),
                        });
                    } else {
                        gaps.push(CapabilityEvidenceGap {
                            provider_id: None,
                            status: CapabilityStatus::Unavailable,
                            reason_code: resolution_reason_code.into(),
                            reason: public_reason.clone(),
                        });
                    }
                } else if resolution_reason_code != "provider_evidence_absent" {
                    // Receipt-local failures and the resolver's aggregate
                    // authority diagnosis are independent evidence. Preserve
                    // both: a partial receipt must not erase ambiguity,
                    // conflicting complete evidence, or invalid authority.
                    gaps.push(CapabilityEvidenceGap {
                        provider_id: None,
                        status: CapabilityStatus::Unavailable,
                        reason_code: resolution_reason_code.into(),
                        reason: public_reason,
                    });
                }
                gaps.sort_by(|left, right| {
                    (
                        &left.provider_id,
                        &left.status,
                        &left.reason_code,
                        &left.reason,
                    )
                        .cmp(&(
                            &right.provider_id,
                            &right.status,
                            &right.reason_code,
                            &right.reason,
                        ))
                });
                gaps.dedup();
                let status = if gaps
                    .iter()
                    .any(|gap| gap.status == CapabilityStatus::Partial)
                {
                    CapabilityStatus::Partial
                } else {
                    CapabilityStatus::Unavailable
                };
                languages.push(LanguageCapabilityCoverage {
                    language_id,
                    status: match status {
                        CapabilityStatus::Complete => CapabilityCoverageStatus::Complete,
                        CapabilityStatus::Partial => CapabilityCoverageStatus::Partial,
                        CapabilityStatus::Unavailable => CapabilityCoverageStatus::Unavailable,
                    },
                    provider_id: None,
                    gaps,
                    qualifications: Vec::new(),
                });
            }
        }
    }
    let status = aggregate_capability_coverage_status(&languages);
    CapabilityCoverage {
        capability_id: capability_id.into(),
        status,
        languages,
    }
}

/// Resolve Calls authority for the callable languages present in one immutable
/// graph generation.
///
/// This is the shared adapter used by CLI publication output and long-lived
/// query snapshots. It prevents either transport from inventing its own
/// language census or falling back to the legacy aggregate SCIP bit.
pub fn assess_calls_receipt_coverage(
    graph: &crate::graph::KnowledgeGraph,
    receipts: &[CapabilityReceipt],
    inventory: &ProjectInventory,
) -> CapabilityCoverage {
    let structural_only_documents = structural_only_source_documents(inventory);
    // Semantic project ownership makes Calls an applicable capability even
    // when the structural floor contains no callable declaration. Module-level
    // call syntax and provider-discovered callable values are two ordinary
    // examples; a failed provider must not turn their language into a vacuous
    // `NotApplicable` result. Retain graph callables as a fail-closed union so
    // malformed or partial inventory cannot erase an observed language.
    let mut applicable_languages = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| inventory.is_semantic_source_owner(membership))
        .map(|membership| membership.language_id.clone())
        .collect::<BTreeSet<_>>();
    applicable_languages.extend(
        graph
            .all_nodes()
            .iter()
            .filter(|node| symbol_kind_has_role(&node.kind, SymbolRole::Callable))
            .filter_map(|node| {
                let language_id = LanguageId::new(crate::graph_stats::node_language(node)?);
                (!structural_only_documents
                    .contains(&(language_id.clone(), node.file_path.as_str())))
                .then_some(language_id)
            }),
    );
    assess_language_capability(
        receipts,
        inventory,
        "calls",
        CALLS_CONFIGURATION_ID,
        applicable_languages,
    )
}

fn structural_only_source_documents(inventory: &ProjectInventory) -> BTreeSet<(LanguageId, &str)> {
    inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            inventory.is_structural_only_source_document(
                &membership.document_path,
                &membership.language_id,
            )
        })
        .map(|membership| {
            (
                membership.language_id.clone(),
                membership.document_path.as_str(),
            )
        })
        .collect()
}

/// Resolve structural-graph authority for every language represented by the
/// immutable generation's owned source population or persisted graph.
///
/// The graph union prevents a malformed/partial inventory from turning a real
/// language population into a vacuous `not_applicable` result. Inventory gaps
/// still remain visible through the caller's project-inventory coverage.
pub fn assess_structural_graph_capability(
    graph: &crate::graph::KnowledgeGraph,
    receipts: &[CapabilityReceipt],
    inventory: &ProjectInventory,
) -> CapabilityCoverage {
    let mut languages = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
        .map(|membership| membership.language_id.clone())
        .collect::<BTreeSet<_>>();
    languages.extend(
        graph
            .all_nodes()
            .iter()
            .filter_map(|node| crate::graph_stats::node_language(node))
            .map(LanguageId::new),
    );
    assess_language_capability(
        receipts,
        inventory,
        "structural_graph",
        STRUCTURAL_GRAPH_CONFIGURATION_ID,
        languages,
    )
}

/// Resolve structural-graph authority for exactly one represented language.
///
/// Structural queries select a concrete source language before interpreting
/// completeness. Keeping that projection here prevents each query from
/// inventing a different aggregate-authority rule while preserving the exact
/// persisted gaps for the selected language.
pub fn assess_structural_graph_language_capability(
    graph: &crate::graph::KnowledgeGraph,
    receipts: &[CapabilityReceipt],
    inventory: &ProjectInventory,
    language_id: &LanguageId,
) -> Result<CapabilityCoverage, DomainError> {
    let mut coverage = assess_structural_graph_capability(graph, receipts, inventory);
    coverage
        .languages
        .retain(|language| language.language_id == *language_id);
    coverage.status = match coverage.languages.as_slice() {
        [] => CapabilityCoverageStatus::Unavailable,
        [language] => language.status,
        _ => {
            return Err(DomainError::PublishedGenerationInvalid {
                reason: format!(
                    "structural authority contains duplicate language rows for {language_id}"
                ),
            });
        }
    };
    Ok(coverage)
}

/// Resolve authority for repository-local project/package dependency facts.
///
/// The current Cargo edge builder can contribute observed `DependsOn` rows,
/// but indexing does not yet persist an input-bound completeness receipt for
/// that producer. Deliberately resolving through the receipt population keeps
/// those rows useful without turning their presence—or absence—into authority
/// for Rust, Go, or future language ecosystems.
pub fn assess_project_dependencies_capability(
    graph: &crate::graph::KnowledgeGraph,
    receipts: &[CapabilityReceipt],
    inventory: &ProjectInventory,
) -> CapabilityCoverage {
    let structural_only_documents = structural_only_source_documents(inventory);
    let mut languages = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| inventory.is_semantic_source_owner(membership))
        .map(|membership| membership.language_id.clone())
        .collect::<BTreeSet<_>>();
    languages.extend(graph.all_nodes().iter().filter_map(|node| {
        let language_id = LanguageId::new(crate::graph_stats::node_language(node)?);
        (!structural_only_documents.contains(&(language_id.clone(), node.file_path.as_str())))
            .then_some(language_id)
    }));
    assess_language_capability(
        receipts,
        inventory,
        "project_dependencies",
        PROJECT_DEPENDENCIES_CONFIGURATION_ID,
        languages,
    )
}

/// Provider evidence that can flow unchanged from indexing into an immutable
/// generation manifest and then into query admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityReceipt {
    pub capability_id: String,
    pub provider_id: ProviderId,
    pub provider_version: Option<String>,
    pub scope: CapabilityScope,
    pub status: CapabilityStatus,
    /// SHA-256 of the exact provider inputs and semantic configuration for this
    /// scope. It is evidence identity, not merely a source revision label. An
    /// unavailable provider that was never invoked may have no input receipt.
    pub input_fingerprint: Option<String>,
    /// Stable machine-readable explanation for non-complete evidence.
    pub reason_code: Option<String>,
    /// Human-facing detail for non-complete evidence.
    pub reason: Option<String>,
}

impl CapabilityReceipt {
    pub fn complete(
        capability_id: impl Into<String>,
        provider_id: impl Into<String>,
        provider_version: impl Into<String>,
        scope: CapabilityScope,
        input_fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            capability_id: capability_id.into(),
            provider_id: ProviderId::new(provider_id),
            provider_version: Some(provider_version.into()),
            scope,
            status: CapabilityStatus::Complete,
            input_fingerprint: Some(input_fingerprint.into()),
            reason_code: None,
            reason: None,
        }
    }

    pub fn partial(
        capability_id: impl Into<String>,
        provider_id: impl Into<String>,
        provider_version: Option<String>,
        scope: CapabilityScope,
        input_fingerprint: Option<String>,
        reason_code: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::incomplete(
            capability_id,
            provider_id,
            provider_version,
            scope,
            CapabilityStatus::Partial,
            input_fingerprint,
            reason_code,
            reason,
        )
    }

    pub fn unavailable(
        capability_id: impl Into<String>,
        provider_id: impl Into<String>,
        provider_version: Option<String>,
        scope: CapabilityScope,
        input_fingerprint: Option<String>,
        reason_code: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::incomplete(
            capability_id,
            provider_id,
            provider_version,
            scope,
            CapabilityStatus::Unavailable,
            input_fingerprint,
            reason_code,
            reason,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn incomplete(
        capability_id: impl Into<String>,
        provider_id: impl Into<String>,
        provider_version: Option<String>,
        scope: CapabilityScope,
        status: CapabilityStatus,
        input_fingerprint: Option<String>,
        reason_code: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        debug_assert!(status != CapabilityStatus::Complete);
        Self {
            capability_id: capability_id.into(),
            provider_id: ProviderId::new(provider_id),
            provider_version,
            scope,
            status,
            input_fingerprint,
            reason_code: Some(reason_code.into()),
            reason: Some(reason.into()),
        }
    }
}

/// Canonical ordering used by producers and immutable publication.
pub fn sort_capability_receipts(receipts: &mut [CapabilityReceipt]) {
    receipts.sort_by(|left, right| {
        (&left.capability_id, &left.scope, &left.provider_id)
            .cmp(&(&right.capability_id, &right.scope, &right.provider_id))
            .then_with(|| left.provider_version.cmp(&right.provider_version))
    });
}

/// One provider's independently sufficient evidence for a capability query.
///
/// The selected receipts are the smallest, most-specific evidence population
/// that covers every required scope. They are canonicalized so transport or
/// manifest order cannot affect authority identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedCapabilityProvider {
    pub capability_id: String,
    pub provider_id: ProviderId,
    pub provider_version: String,
    pub required_scopes: Vec<CapabilityScope>,
    pub receipts: Vec<CapabilityReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityResolutionError {
    InvalidRequest {
        field: &'static str,
        reason: String,
    },
    InvalidCompleteReceipt {
        capability_id: String,
        provider_id: ProviderId,
        reason: String,
    },
    ConflictingCompleteEvidence {
        capability_id: String,
        provider_id: ProviderId,
        scope: Box<CapabilityScope>,
    },
    InconsistentProviderVersions {
        capability_id: String,
        provider_id: ProviderId,
        provider_versions: Vec<String>,
    },
    Unavailable {
        capability_id: String,
        required_scopes: Vec<CapabilityScope>,
    },
    PreferredProviderUnavailable {
        capability_id: String,
        provider_id: ProviderId,
        required_scopes: Vec<CapabilityScope>,
    },
    AmbiguousProviders {
        capability_id: String,
        required_scopes: Vec<CapabilityScope>,
        provider_ids: Vec<ProviderId>,
    },
}

impl std::fmt::Display for CapabilityResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.public_reason())
    }
}

impl std::error::Error for CapabilityResolutionError {}

impl CapabilityResolutionError {
    pub(crate) const fn evidence_reason_code(&self) -> &'static str {
        match self {
            Self::AmbiguousProviders { .. }
            | Self::ConflictingCompleteEvidence { .. }
            | Self::InconsistentProviderVersions { .. } => "provider_authority_ambiguous",
            Self::InvalidCompleteReceipt { .. } | Self::InvalidRequest { .. } => {
                "provider_evidence_invalid"
            }
            Self::Unavailable { .. } | Self::PreferredProviderUnavailable { .. } => {
                "provider_evidence_absent"
            }
        }
    }

    /// Bounded explanation safe for CLI, JSON, and MCP results.
    ///
    /// The error retains exact typed scopes and providers for programmatic
    /// consumers. Public prose must not stringify their Rust `Debug` shape or
    /// grow with every project unit in a monorepo.
    pub(crate) fn public_reason(&self) -> String {
        match self {
            Self::InvalidRequest { field, reason } => {
                format!("invalid capability request field '{field}': {reason}")
            }
            Self::InvalidCompleteReceipt {
                capability_id,
                provider_id,
                reason,
            } => format!(
                "provider '{provider_id}' supplied invalid complete evidence for capability '{capability_id}': {reason}"
            ),
            Self::ConflictingCompleteEvidence {
                capability_id,
                provider_id,
                ..
            } => format!(
                "provider '{provider_id}' has conflicting complete evidence for capability '{capability_id}' in one required scope"
            ),
            Self::InconsistentProviderVersions {
                capability_id,
                provider_id,
                provider_versions,
            } => format!(
                "provider '{provider_id}' reports {} versions for capability '{capability_id}'",
                provider_versions.len()
            ),
            Self::Unavailable {
                required_scopes, ..
            } => format!(
                "no single complete provider covers all of {}",
                required_scope_summary(required_scopes)
            ),
            Self::PreferredProviderUnavailable {
                provider_id,
                required_scopes,
                ..
            } => format!(
                "preferred provider '{provider_id}' has no complete evidence covering {}",
                required_scope_summary(required_scopes)
            ),
            Self::AmbiguousProviders {
                provider_ids,
                required_scopes,
                ..
            } => format!(
                "{} complete providers cover {}; select one explicitly",
                provider_ids.len(),
                required_scope_summary(required_scopes)
            ),
        }
    }
}

fn required_scope_summary(scopes: &[CapabilityScope]) -> String {
    let scope_kind = if scopes
        .iter()
        .all(|scope| matches!(scope, CapabilityScope::Repository { .. }))
    {
        "repository"
    } else if scopes
        .iter()
        .all(|scope| matches!(scope, CapabilityScope::Language { .. }))
    {
        "language"
    } else if scopes.iter().all(|scope| {
        matches!(
            scope,
            CapabilityScope::ProjectUnit { .. } | CapabilityScope::ProjectUnits { .. }
        )
    }) {
        "project-unit"
    } else {
        "capability"
    };
    let plural = if scopes.len() == 1 { "" } else { "s" };
    format!("{} required {scope_kind} scope{plural}", scopes.len())
}

/// Resolve complete capability evidence without combining coverage from
/// different providers or allowing input order to choose authority.
pub fn resolve_capability_provider(
    receipts: &[CapabilityReceipt],
    capability_id: &str,
    required_scopes: &[CapabilityScope],
    preferred_provider: Option<&ProviderId>,
) -> Result<ResolvedCapabilityProvider, CapabilityResolutionError> {
    if capability_id.trim().is_empty() {
        return Err(CapabilityResolutionError::InvalidRequest {
            field: "capability_id",
            reason: "must not be empty".into(),
        });
    }
    if required_scopes.is_empty() {
        return Err(CapabilityResolutionError::InvalidRequest {
            field: "required_scopes",
            reason: "must contain at least one scope".into(),
        });
    }
    if preferred_provider.is_some_and(|provider| provider.0.trim().is_empty()) {
        return Err(CapabilityResolutionError::InvalidRequest {
            field: "preferred_provider",
            reason: "must not be empty".into(),
        });
    }

    let mut required_scopes = required_scopes.to_vec();
    required_scopes.sort();
    required_scopes.dedup();
    for scope in &required_scopes {
        validate_resolution_scope(scope).map_err(|reason| {
            CapabilityResolutionError::InvalidRequest {
                field: "required_scopes",
                reason,
            }
        })?;
    }

    let mut by_provider: BTreeMap<ProviderId, Vec<CapabilityReceipt>> = BTreeMap::new();
    for receipt in receipts.iter().filter(|receipt| {
        receipt.capability_id == capability_id && receipt.status == CapabilityStatus::Complete
    }) {
        validate_complete_receipt(receipt)?;
        by_provider
            .entry(receipt.provider_id.clone())
            .or_default()
            .push(receipt.clone());
    }
    for provider_receipts in by_provider.values_mut() {
        provider_receipts.sort_by(|left, right| {
            (&left.scope, &left.provider_version, &left.input_fingerprint).cmp(&(
                &right.scope,
                &right.provider_version,
                &right.input_fingerprint,
            ))
        });
        provider_receipts.dedup();
    }

    if let Some(preferred_provider) = preferred_provider {
        let selected = by_provider
            .get(preferred_provider)
            .map(|provider_receipts| {
                resolve_provider_receipts(
                    capability_id,
                    preferred_provider,
                    provider_receipts,
                    &required_scopes,
                )
            })
            .transpose()?
            .flatten();
        return selected.ok_or_else(|| CapabilityResolutionError::PreferredProviderUnavailable {
            capability_id: capability_id.into(),
            provider_id: preferred_provider.clone(),
            required_scopes,
        });
    }

    let mut eligible = Vec::new();
    for (provider_id, provider_receipts) in &by_provider {
        if let Some(selected) = resolve_provider_receipts(
            capability_id,
            provider_id,
            provider_receipts,
            &required_scopes,
        )? {
            eligible.push(selected);
        }
    }

    match eligible.len() {
        0 => Err(CapabilityResolutionError::Unavailable {
            capability_id: capability_id.into(),
            required_scopes,
        }),
        1 => Ok(eligible.pop().expect("length checked")),
        _ => Err(CapabilityResolutionError::AmbiguousProviders {
            capability_id: capability_id.into(),
            required_scopes,
            provider_ids: eligible
                .into_iter()
                .map(|candidate| candidate.provider_id)
                .collect(),
        }),
    }
}

fn resolve_provider_receipts(
    capability_id: &str,
    provider_id: &ProviderId,
    receipts: &[CapabilityReceipt],
    required_scopes: &[CapabilityScope],
) -> Result<Option<ResolvedCapabilityProvider>, CapabilityResolutionError> {
    let mut best_by_scope = Vec::with_capacity(required_scopes.len());
    for required_scope in required_scopes {
        let covering = receipts
            .iter()
            .filter(|receipt| receipt.scope.covers(required_scope))
            .collect::<Vec<_>>();
        let Some(best_specificity) = covering
            .iter()
            .map(|receipt| scope_specificity(&receipt.scope))
            .max()
        else {
            return Ok(None);
        };
        let best = covering
            .into_iter()
            .filter(|receipt| scope_specificity(&receipt.scope) == best_specificity)
            .collect::<Vec<_>>();
        if best.len() != 1 {
            return Err(CapabilityResolutionError::ConflictingCompleteEvidence {
                capability_id: capability_id.into(),
                provider_id: provider_id.clone(),
                scope: Box::new(best[0].scope.clone()),
            });
        }
        best_by_scope.push(best[0].clone());
    }

    sort_capability_receipts(&mut best_by_scope);
    best_by_scope.dedup();
    let provider_versions = best_by_scope
        .iter()
        .filter_map(|receipt| receipt.provider_version.clone())
        .collect::<BTreeSet<_>>();
    if provider_versions.len() != 1 {
        return Err(CapabilityResolutionError::InconsistentProviderVersions {
            capability_id: capability_id.into(),
            provider_id: provider_id.clone(),
            provider_versions: provider_versions.into_iter().collect(),
        });
    }
    let provider_version = provider_versions
        .into_iter()
        .next()
        .expect("complete receipts have a validated version");

    Ok(Some(ResolvedCapabilityProvider {
        capability_id: capability_id.into(),
        provider_id: provider_id.clone(),
        provider_version,
        required_scopes: required_scopes.to_vec(),
        receipts: best_by_scope,
    }))
}

const fn scope_specificity(scope: &CapabilityScope) -> u8 {
    match scope {
        CapabilityScope::Repository { .. } => 0,
        CapabilityScope::Language { .. } => 1,
        CapabilityScope::ProjectUnits { .. } => 2,
        CapabilityScope::ProjectUnit { .. } => 3,
    }
}

pub(crate) fn validate_complete_receipt(
    receipt: &CapabilityReceipt,
) -> Result<(), CapabilityResolutionError> {
    let invalid = |reason: &str| CapabilityResolutionError::InvalidCompleteReceipt {
        capability_id: receipt.capability_id.clone(),
        provider_id: receipt.provider_id.clone(),
        reason: reason.into(),
    };
    if receipt.status != CapabilityStatus::Complete {
        return Err(invalid("status must be complete"));
    }
    if receipt.provider_id.0.trim().is_empty() {
        return Err(invalid("provider_id must not be empty"));
    }
    let Some(provider_version) = receipt.provider_version.as_deref() else {
        return Err(invalid("provider_version is required"));
    };
    if provider_version.trim().is_empty() {
        return Err(invalid("provider_version must not be empty"));
    }
    let Some(input_fingerprint) = receipt.input_fingerprint.as_deref() else {
        return Err(invalid("input_fingerprint is required"));
    };
    if input_fingerprint.len() != 64
        || !input_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(
            "input_fingerprint must be a 64-character lowercase SHA-256",
        ));
    }
    if receipt.reason_code.is_some() || receipt.reason.is_some() {
        return Err(invalid("complete evidence cannot carry failure reasons"));
    }
    validate_resolution_scope(&receipt.scope).map_err(|reason| invalid(&reason))
}

fn validate_resolution_scope(scope: &CapabilityScope) -> Result<(), String> {
    if scope.configuration_id().0.trim().is_empty() {
        return Err("configuration_id must not be empty".into());
    }
    match scope {
        CapabilityScope::Repository { .. } => Ok(()),
        CapabilityScope::Language { language_id, .. } => {
            if language_id.0.trim().is_empty() {
                Err("language_id must not be empty".into())
            } else {
                Ok(())
            }
        }
        CapabilityScope::ProjectUnit {
            language_id,
            project_unit_id,
            ..
        } => {
            if language_id.0.trim().is_empty() {
                Err("language_id must not be empty".into())
            } else if project_unit_id.0.trim().is_empty() {
                Err("project_unit_id must not be empty".into())
            } else {
                Ok(())
            }
        }
        CapabilityScope::ProjectUnits {
            language_id,
            project_unit_ids,
            ..
        } => {
            if language_id.0.trim().is_empty() {
                return Err("language_id must not be empty".into());
            }
            if project_unit_ids.is_empty() {
                return Err("project_unit_ids must not be empty".into());
            }
            if project_unit_ids
                .iter()
                .any(|project_unit_id| project_unit_id.0.trim().is_empty())
            {
                return Err("project_unit_ids must not contain an empty ID".into());
            }
            if project_unit_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err("project_unit_ids must be sorted and unique".into());
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerFilter {
    #[default]
    Live,
    All,
    Dead,
    TestOnly,
}

impl CallerFilter {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::All => "all",
            Self::Dead => "dead",
            Self::TestOnly => "test_only",
        }
    }
}

impl std::str::FromStr for CallerFilter {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().replace('-', "_").as_str() {
            "live" => Ok(Self::Live),
            "all" => Ok(Self::All),
            "dead" => Ok(Self::Dead),
            "test_only" => Ok(Self::TestOnly),
            _ => Err(format!(
                "unknown calls filter '{value}', expected live, all, dead, or test_only"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallsRequest {
    pub symbol: String,
    pub file: Option<String>,
    pub filter: CallerFilter,
    pub limit: usize,
    pub cursor: Option<String>,
}

impl CallsRequest {
    pub fn new(symbol: impl Into<String>) -> Self {
        Self {
            symbol: symbol.into(),
            file: None,
            filter: CallerFilter::Live,
            limit: DEFAULT_CALLS_PAGE_SIZE,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeRequest {
    pub symbol: String,
    pub file: Option<String>,
    pub limit: usize,
    pub cursor: Option<String>,
}

impl TypeRequest {
    pub fn new(symbol: impl Into<String>) -> Self {
        Self {
            symbol: symbol.into(),
            file: None,
            limit: DEFAULT_TYPE_PAGE_SIZE,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    /// Inclusive UTF-8 byte offset in the exact indexed document bytes.
    pub start_byte: usize,
    /// Exclusive UTF-8 byte offset in the exact indexed document bytes.
    pub end_byte: usize,
    /// Zero-based source line.
    pub start_line: usize,
    /// Zero-based UTF-8 byte column.
    pub start_column: usize,
    /// Zero-based source line.
    pub end_line: usize,
    /// Zero-based UTF-8 byte column.
    pub end_column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolIdentity {
    pub symbol_id: String,
    pub name: String,
    pub kind: String,
    pub document_path: String,
    pub language_id: LanguageId,
    /// Every indexed source owner for this document, in deterministic order.
    /// The transitional no-inventory path leaves this empty rather than
    /// manufacturing a unit from the live filesystem.
    pub project_unit_ids: Vec<ProjectUnitId>,
    pub configuration_id: ConfigurationId,
    pub definition_span: Option<SourceSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityStatus {
    Complete,
    /// Exact within the provider-covered population, with explicit source
    /// regions that may contain additional callers outside that population.
    Qualified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    pub offset: usize,
    pub limit: usize,
    pub returned: usize,
    pub total_items: usize,
    pub has_more: bool,
    pub next_cursor: Option<String>,
    pub expires_at_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainErrorEnvelope {
    pub error: DomainErrorBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainErrorBody {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<CapabilityScope>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<CapabilityEvidenceGap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_chars: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_chars: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("{capability} capability is not applicable: {reason}")]
    CapabilityNotApplicable { capability: String, reason: String },
    #[error("{capability} capability is unavailable: {reason}")]
    CapabilityUnavailable {
        capability: String,
        reason: String,
        scopes: Vec<CapabilityScope>,
        evidence: Vec<CapabilityEvidenceGap>,
    },
    #[error("{capability} capability has multiple eligible providers; select one explicitly")]
    CapabilityAmbiguous {
        capability: String,
        scopes: Vec<CapabilityScope>,
        providers: Vec<ProviderId>,
    },
    #[error("symbol '{symbol}' was not found")]
    SymbolNotFound { symbol: String },
    #[error(
        "symbol '{symbol}' is ambiguous; use Find and pass one result's symbol_id as the symbol selector (or use an exact file for cross-file homonyms)"
    )]
    AmbiguousSymbol {
        symbol: String,
        candidates: Vec<String>,
    },
    #[error(
        "symbol identity '{symbol}' in '{document_path}' represents multiple source occurrences"
    )]
    SymbolIdentityAmbiguous {
        symbol: String,
        document_path: String,
        candidates: Vec<String>,
    },
    #[error("symbol '{symbol}' is not callable (structural kind: {kind})")]
    SymbolNotCallable { symbol: String, kind: String },
    #[error("symbol '{symbol}' is not a type (structural kind: {kind})")]
    SymbolNotType { symbol: String, kind: String },
    #[error(
        "symbol '{symbol}' is outside Calls coverage from provider {provider_id}: {reason_codes:?}"
    )]
    SymbolOutsideProviderCoverage {
        symbol: String,
        provider_id: ProviderId,
        reason_codes: Vec<String>,
    },
    #[error("symbol '{symbol}' is outside the exact Calls population from provider {provider_id}")]
    SymbolOutsideProviderPopulation {
        symbol: String,
        provider_id: ProviderId,
    },
    #[error("invalid cursor: {reason}")]
    InvalidCursor { reason: String },
    #[error("cursor expired")]
    CursorExpired,
    #[error(
        "cursor belongs to generation {cursor_generation}, current generation is {current_generation}"
    )]
    CursorGenerationChanged {
        cursor_generation: String,
        current_generation: String,
    },
    #[error("source path is not valid for the bound repository: {0}")]
    SourcePath(String),
    #[error("symbol '{symbol}' was not found in requested file '{file}'")]
    SymbolNotFoundInFile {
        symbol: String,
        file: String,
        candidates: Vec<String>,
    },
    #[error("source authority for '{symbol}' in '{document_path}' is unavailable: {reason}")]
    SourceAuthorityUnavailable {
        symbol: String,
        document_path: String,
        reason: String,
    },
    #[error("{message}")]
    SourceMaterialization { code: &'static str, message: String },
    #[error("{operation} candidate observation failed: {reason}")]
    CandidateObservationFailed {
        operation: &'static str,
        reason: String,
    },
    #[error("project inventory does not authorize document '{document_path}': {reason}")]
    ProjectInventoryMismatch {
        document_path: String,
        reason: String,
    },
    #[error("project inventory is invalid: {reason}")]
    ProjectInventoryInvalid { reason: String },
    #[error("published semantic generation is invalid: {reason}")]
    PublishedGenerationInvalid { reason: String },
    #[error("invalid {operation} request field '{field}': {reason}")]
    InvalidRequest {
        operation: &'static str,
        field: &'static str,
        reason: String,
    },
    #[error(
        "{operation} result contains {actual_chars} serialized characters; maximum is {max_chars}: {remedy}"
    )]
    ResultTooLarge {
        operation: &'static str,
        actual_chars: usize,
        max_chars: usize,
        remedy: String,
    },
}

impl DomainError {
    pub fn result_too_large(
        operation: &'static str,
        actual_chars: usize,
        max_chars: usize,
        remedy: impl Into<String>,
    ) -> Self {
        Self::ResultTooLarge {
            operation,
            actual_chars,
            max_chars,
            remedy: remedy.into(),
        }
    }

    pub fn envelope(&self) -> DomainErrorEnvelope {
        let (operation, field) = match self {
            Self::InvalidRequest {
                operation, field, ..
            } => (Some((*operation).into()), Some((*field).into())),
            Self::ResultTooLarge { operation, .. } => (Some((*operation).into()), None),
            _ => (None, None),
        };
        let (code, capability, scopes, candidates, evidence) = match self {
            Self::CapabilityNotApplicable { capability, .. } => (
                "capability_not_applicable",
                Some(capability.clone()),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Self::CapabilityUnavailable {
                capability,
                scopes,
                evidence,
                ..
            } => (
                "capability_unavailable",
                Some(capability.clone()),
                scopes.clone(),
                Vec::new(),
                evidence.clone(),
            ),
            Self::CapabilityAmbiguous {
                capability,
                scopes,
                providers,
            } => (
                "capability_ambiguous",
                Some(capability.clone()),
                scopes.clone(),
                providers
                    .iter()
                    .map(|provider| provider.0.clone())
                    .collect(),
                Vec::new(),
            ),
            Self::SymbolNotFound { .. } => {
                ("symbol_not_found", None, Vec::new(), Vec::new(), Vec::new())
            }
            Self::AmbiguousSymbol { candidates, .. } => (
                "ambiguous_symbol",
                None,
                Vec::new(),
                candidates.clone(),
                Vec::new(),
            ),
            Self::SymbolIdentityAmbiguous { candidates, .. } => (
                "symbol_identity_ambiguous",
                Some("structural_graph".into()),
                Vec::new(),
                candidates.clone(),
                Vec::new(),
            ),
            Self::SymbolNotCallable { .. } => (
                "symbol_not_callable",
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Self::SymbolNotType { .. } => {
                ("symbol_not_type", None, Vec::new(), Vec::new(), Vec::new())
            }
            Self::SymbolOutsideProviderCoverage {
                provider_id,
                reason_codes,
                ..
            } => (
                "symbol_outside_provider_coverage",
                Some("calls".into()),
                Vec::new(),
                Vec::new(),
                reason_codes
                    .iter()
                    .map(|reason_code| CapabilityEvidenceGap {
                        provider_id: Some(provider_id.clone()),
                        status: CapabilityStatus::Unavailable,
                        reason_code: reason_code.clone(),
                        reason:
                            "target source span lies in an explicit provider coverage exclusion"
                                .into(),
                    })
                    .collect(),
            ),
            Self::SymbolOutsideProviderPopulation { provider_id, .. } => (
                "symbol_outside_provider_population",
                Some("calls".into()),
                Vec::new(),
                Vec::new(),
                vec![CapabilityEvidenceGap {
                    provider_id: Some(provider_id.clone()),
                    status: CapabilityStatus::Unavailable,
                    reason_code: "callable_outside_provider_population".into(),
                    reason: "selected callable has no exact identity in the provider population"
                        .into(),
                }],
            ),
            Self::InvalidCursor { .. } => {
                ("invalid_cursor", None, Vec::new(), Vec::new(), Vec::new())
            }
            Self::CursorExpired => ("cursor_expired", None, Vec::new(), Vec::new(), Vec::new()),
            Self::CursorGenerationChanged { .. } => (
                "cursor_generation_changed",
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Self::SourcePath(_) => (
                "source_path_invalid",
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Self::SymbolNotFoundInFile { candidates, .. } => (
                "symbol_not_found_in_file",
                None,
                Vec::new(),
                candidates.clone(),
                Vec::new(),
            ),
            Self::SourceAuthorityUnavailable { .. } => (
                "source_authority_unavailable",
                Some("structural_graph".into()),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Self::SourceMaterialization { code, .. } => {
                (*code, None, Vec::new(), Vec::new(), Vec::new())
            }
            Self::CandidateObservationFailed { .. } => (
                "candidate_observation_failed",
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Self::ProjectInventoryMismatch { .. } => (
                "project_inventory_mismatch",
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Self::ProjectInventoryInvalid { .. } => (
                "project_inventory_invalid",
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Self::PublishedGenerationInvalid { .. } => (
                "published_generation_invalid",
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            ),
            Self::InvalidRequest { .. } => {
                ("invalid_request", None, Vec::new(), Vec::new(), Vec::new())
            }
            Self::ResultTooLarge { .. } => {
                ("result_too_large", None, Vec::new(), Vec::new(), Vec::new())
            }
        };
        let (actual_chars, max_chars, remedy) = match self {
            Self::ResultTooLarge {
                actual_chars,
                max_chars,
                remedy,
                ..
            } => (Some(*actual_chars), Some(*max_chars), Some(remedy.clone())),
            _ => (None, None, None),
        };
        DomainErrorEnvelope {
            error: DomainErrorBody {
                code,
                message: self.to_string(),
                operation,
                field,
                capability,
                scopes,
                candidates,
                evidence,
                actual_chars,
                max_chars,
                remedy,
            },
        }
    }
}

/// Translate capability-provider selection into one shared domain error.
///
/// Every operation uses the same evidence population and stable error envelope
/// instead of reconstructing provider failures in its adapter.
pub fn capability_resolution_domain_error(
    capability: &str,
    error: CapabilityResolutionError,
    receipts: &[CapabilityReceipt],
) -> DomainError {
    let reason = error.public_reason();
    match error {
        CapabilityResolutionError::Unavailable {
            required_scopes, ..
        }
        | CapabilityResolutionError::PreferredProviderUnavailable {
            required_scopes, ..
        } => {
            let mut evidence = receipts
                .iter()
                .filter(|receipt| {
                    receipt.capability_id == capability
                        && receipt.status != CapabilityStatus::Complete
                        && required_scopes
                            .iter()
                            .any(|required| receipt.scope.covers(required))
                })
                .map(|receipt| CapabilityEvidenceGap {
                    provider_id: Some(receipt.provider_id.clone()),
                    status: receipt.status,
                    reason_code: receipt
                        .reason_code
                        .clone()
                        .unwrap_or_else(|| "provider_evidence_incomplete".into()),
                    reason: receipt.reason.clone().unwrap_or_else(|| reason.clone()),
                })
                .collect::<Vec<_>>();
            evidence.sort_by(|left, right| {
                (
                    &left.provider_id,
                    &left.status,
                    &left.reason_code,
                    &left.reason,
                )
                    .cmp(&(
                        &right.provider_id,
                        &right.status,
                        &right.reason_code,
                        &right.reason,
                    ))
            });
            evidence.dedup();
            if evidence.is_empty() {
                evidence.push(CapabilityEvidenceGap {
                    provider_id: None,
                    status: CapabilityStatus::Unavailable,
                    reason_code: "provider_evidence_absent".into(),
                    reason: reason.clone(),
                });
            }
            DomainError::CapabilityUnavailable {
                capability: capability.into(),
                reason,
                scopes: required_scopes,
                evidence,
            }
        }
        CapabilityResolutionError::AmbiguousProviders {
            required_scopes,
            provider_ids,
            ..
        } => DomainError::CapabilityAmbiguous {
            capability: capability.into(),
            scopes: required_scopes,
            providers: provider_ids,
        },
        _ => DomainError::PublishedGenerationInvalid { reason },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_issue_authority_is_scoped_to_affected_languages_and_ecosystems() {
        let mut inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationPartial,
            project_topology: ProjectTopology {
                units: Vec::new(),
                memberships: Vec::new(),
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: Vec::new(),
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: vec![ProjectInventoryIssue {
                scope: ProjectInventoryIssueScope::Ecosystem {
                    language_id: LanguageId::new("go"),
                    ecosystem_id: EcosystemId::new("go"),
                },
                code: "manifest_unreadable".into(),
                path: "go/go.mod".into(),
                detail: "positive scoped-issue control".into(),
            }],
        };
        let rust = LanguageId::new("rust");
        let go = LanguageId::new("go");

        assert_eq!(
            inventory.coverage_for_language(&rust),
            ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            "a Go-only issue must not downgrade Rust authority"
        );
        assert_eq!(
            inventory.coverage_for_language(&go),
            ProjectInventoryCoverage::IndexedSourcePopulationPartial,
            "positive affected-language control"
        );
        assert_eq!(
            inventory.coverage_for_provider(&go, &EcosystemId::new("other")),
            ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            "an ecosystem issue must not cross provider ecosystems"
        );
        assert_eq!(
            inventory.coverage_for_provider(&go, &EcosystemId::new("go")),
            ProjectInventoryCoverage::IndexedSourcePopulationPartial,
            "positive affected-provider control"
        );
        assert_eq!(
            inventory.coverage_for_languages(&BTreeSet::from([rust.clone()])),
            ProjectInventoryCoverage::IndexedSourcePopulationComplete
        );
        assert_eq!(
            inventory.coverage_for_languages(&BTreeSet::from([rust, go])),
            ProjectInventoryCoverage::IndexedSourcePopulationPartial
        );

        inventory.issues.push(ProjectInventoryIssue {
            scope: ProjectInventoryIssueScope::Repository,
            code: "repository_population_unknown".into(),
            path: ".".into(),
            detail: "positive repository-wide control".into(),
        });
        assert_eq!(
            inventory.coverage_for_language(&LanguageId::new("rust")),
            ProjectInventoryCoverage::IndexedSourcePopulationPartial,
            "repository issues must qualify every narrower projection"
        );
    }

    fn scoped_complete_receipt(
        provider: &str,
        version: &str,
        scope: CapabilityScope,
    ) -> CapabilityReceipt {
        CapabilityReceipt::complete("calls", provider, version, scope, "0".repeat(64))
    }

    #[test]
    fn multiple_complete_providers_require_explicit_preference() {
        let scope = CapabilityScope::Language {
            language_id: LanguageId::new("rust"),
            configuration_id: ConfigurationId::new("calls-v1"),
        };
        let receipts = vec![
            scoped_complete_receipt("provider-b", "2.0.0", scope.clone()),
            scoped_complete_receipt("provider-a", "1.0.0", scope.clone()),
        ];

        let error =
            resolve_capability_provider(&receipts, "calls", std::slice::from_ref(&scope), None)
                .expect_err("provider order must never select authority");
        assert_eq!(
            error,
            CapabilityResolutionError::AmbiguousProviders {
                capability_id: "calls".into(),
                required_scopes: vec![scope.clone()],
                provider_ids: vec![ProviderId::new("provider-a"), ProviderId::new("provider-b")],
            }
        );

        let selected = resolve_capability_provider(
            &receipts,
            "calls",
            &[scope],
            Some(&ProviderId::new("provider-b")),
        )
        .expect("explicit preference selects one complete provider");
        assert_eq!(selected.provider_id, ProviderId::new("provider-b"));
        assert_eq!(selected.provider_version, "2.0.0");
        assert_eq!(selected.receipts.len(), 1);
    }

    #[test]
    fn provider_coverage_is_never_unionised_across_providers() {
        let owner_a = CapabilityScope::ProjectUnit {
            language_id: LanguageId::new("rust"),
            project_unit_id: ProjectUnitId::new("owner-a"),
            configuration_id: ConfigurationId::new("calls-v1"),
        };
        let owner_b = CapabilityScope::ProjectUnit {
            language_id: LanguageId::new("rust"),
            project_unit_id: ProjectUnitId::new("owner-b"),
            configuration_id: ConfigurationId::new("calls-v1"),
        };
        let split_receipts = vec![
            scoped_complete_receipt("provider-a", "1.0.0", owner_a.clone()),
            scoped_complete_receipt("provider-b", "1.0.0", owner_b.clone()),
        ];

        let error = resolve_capability_provider(
            &split_receipts,
            "calls",
            &[owner_b.clone(), owner_a.clone()],
            None,
        )
        .expect_err("two partial provider populations cannot manufacture one authority");
        assert_eq!(
            error,
            CapabilityResolutionError::Unavailable {
                capability_id: "calls".into(),
                required_scopes: vec![owner_a.clone(), owner_b.clone()],
            }
        );

        let language_scope = CapabilityScope::Language {
            language_id: LanguageId::new("rust"),
            configuration_id: ConfigurationId::new("calls-v1"),
        };
        let complete_receipts = vec![
            split_receipts[0].clone(),
            split_receipts[1].clone(),
            scoped_complete_receipt("provider-c", "3.0.0", language_scope),
        ];
        let selected =
            resolve_capability_provider(&complete_receipts, "calls", &[owner_b, owner_a], None)
                .expect("one provider with broader complete coverage is authoritative");
        assert_eq!(selected.provider_id, ProviderId::new("provider-c"));
        assert_eq!(selected.receipts.len(), 1);
        assert_eq!(selected.required_scopes.len(), 2);
    }

    #[test]
    fn unavailable_capability_explanations_are_bounded_without_losing_typed_scopes() {
        let memberships = ["owner-a", "owner-b"]
            .into_iter()
            .map(|project_unit_id| DocumentMembership {
                document_path: format!("{project_unit_id}/src/lib.rs"),
                language_id: LanguageId::new("rust"),
                project_unit_id: ProjectUnitId::new(project_unit_id),
                kind: DocumentMembershipKind::SourceOwner,
            })
            .collect::<Vec<_>>();
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: ProjectTopology {
                units: Vec::new(),
                memberships,
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: Vec::new(),
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: Vec::new(),
        };
        let expected_reason =
            "no single complete provider covers all of 2 required project-unit scopes";

        let coverage = assess_language_capability(
            &[],
            &inventory,
            "calls",
            CALLS_CONFIGURATION_ID,
            [LanguageId::new("rust")],
        );
        let language = coverage.languages.first().expect("Rust coverage row");
        assert_eq!(language.status, CapabilityCoverageStatus::Unavailable);
        assert_eq!(language.gaps.len(), 1);
        assert_eq!(language.gaps[0].reason_code, "provider_evidence_absent");
        assert_eq!(language.gaps[0].reason, expected_reason);

        let required_scopes = ["owner-a", "owner-b"]
            .into_iter()
            .map(|project_unit_id| CapabilityScope::ProjectUnit {
                language_id: LanguageId::new("rust"),
                project_unit_id: ProjectUnitId::new(project_unit_id),
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            })
            .collect::<Vec<_>>();
        let error = resolve_capability_provider(&[], "calls", &required_scopes, None)
            .expect_err("the empty receipt population cannot authorize Calls");
        let displayed = error.to_string();
        assert_eq!(displayed, expected_reason);
        assert!(displayed.len() < 128, "error Display must stay bounded");
        let envelope = capability_resolution_domain_error("calls", error, &[]).envelope();
        assert_eq!(envelope.error.code, "capability_unavailable");
        assert_eq!(envelope.error.scopes, required_scopes);
        assert_eq!(envelope.error.evidence.len(), 1);
        assert_eq!(envelope.error.evidence[0].reason, expected_reason);
        assert!(
            !envelope.error.message.contains("ProjectUnit")
                && !envelope.error.message.contains("LanguageId")
                && !envelope.error.message.contains("owner-a"),
            "public message leaked internal scope Debug output: {}",
            envelope.error.message
        );
    }

    #[test]
    fn incomplete_receipts_never_authorize_a_provider() {
        let scope = CapabilityScope::Language {
            language_id: LanguageId::new("rust"),
            configuration_id: ConfigurationId::new("calls-v1"),
        };
        let mut receipts = vec![
            CapabilityReceipt::partial(
                "calls",
                "provider-a",
                Some("1.0.0".into()),
                scope.clone(),
                Some("a".repeat(64)),
                "incomplete_inputs",
                "not every indexed input was analyzed",
            ),
            CapabilityReceipt::unavailable(
                "calls",
                "provider-b",
                None,
                scope.clone(),
                None,
                "provider_not_run",
                "the provider did not run",
            ),
            scoped_complete_receipt("provider-c", "1.0.0", scope.clone()),
        ];
        receipts[2].capability_id = "definitions".into();

        let error =
            resolve_capability_provider(&receipts, "calls", std::slice::from_ref(&scope), None)
                .expect_err(
                    "partial, unavailable, and other-capability evidence cannot authorize calls",
                );
        assert_eq!(
            error,
            CapabilityResolutionError::Unavailable {
                capability_id: "calls".into(),
                required_scopes: vec![scope.clone()],
            }
        );

        receipts.push(scoped_complete_receipt("provider-a", "1.0.0", scope));
        let selected = resolve_capability_provider(
            &receipts,
            "calls",
            &[CapabilityScope::Language {
                language_id: LanguageId::new("rust"),
                configuration_id: ConfigurationId::new("calls-v1"),
            }],
            None,
        )
        .expect("the complete control receipt authorizes exactly one provider");
        assert_eq!(selected.provider_id, ProviderId::new("provider-a"));
    }

    #[test]
    fn resolution_uses_canonical_most_specific_evidence() {
        let configuration_id = ConfigurationId::new("calls-v1");
        let owner_a = CapabilityScope::ProjectUnit {
            language_id: LanguageId::new("rust"),
            project_unit_id: ProjectUnitId::new("owner-a"),
            configuration_id: configuration_id.clone(),
        };
        let owner_b = CapabilityScope::ProjectUnit {
            language_id: LanguageId::new("rust"),
            project_unit_id: ProjectUnitId::new("owner-b"),
            configuration_id: configuration_id.clone(),
        };
        let language = CapabilityScope::Language {
            language_id: LanguageId::new("rust"),
            configuration_id: configuration_id.clone(),
        };
        let repository = CapabilityScope::Repository { configuration_id };
        let exact = scoped_complete_receipt("provider-a", "1.0.0", owner_a.clone());
        let mut receipts = vec![
            scoped_complete_receipt("provider-a", "1.0.0", repository),
            scoped_complete_receipt("provider-a", "1.0.0", language.clone()),
            exact.clone(),
            exact,
        ];

        let selected = resolve_capability_provider(
            &receipts,
            "calls",
            &[owner_b.clone(), owner_a.clone(), owner_b.clone()],
            None,
        )
        .expect("one provider independently covers both owners");
        assert_eq!(
            selected.required_scopes,
            vec![owner_a.clone(), owner_b.clone()]
        );
        assert_eq!(selected.receipts.len(), 2, "exact duplicates are collapsed");
        assert_eq!(
            selected
                .receipts
                .iter()
                .map(|receipt| receipt.scope.clone())
                .collect::<Vec<_>>(),
            vec![language, owner_a.clone()]
        );

        receipts.reverse();
        let repeated = resolve_capability_provider(&receipts, "calls", &[owner_a, owner_b], None)
            .expect("input order cannot change selection");
        assert_eq!(repeated, selected);
    }

    #[test]
    fn explicit_preference_never_falls_back_or_borrows_coverage() {
        let configuration_id = ConfigurationId::new("calls-v1");
        let owner_a = CapabilityScope::ProjectUnit {
            language_id: LanguageId::new("rust"),
            project_unit_id: ProjectUnitId::new("owner-a"),
            configuration_id: configuration_id.clone(),
        };
        let owner_b = CapabilityScope::ProjectUnit {
            language_id: LanguageId::new("rust"),
            project_unit_id: ProjectUnitId::new("owner-b"),
            configuration_id: configuration_id.clone(),
        };
        let receipts = vec![
            scoped_complete_receipt(
                "provider-a",
                "1.0.0",
                CapabilityScope::Language {
                    language_id: LanguageId::new("rust"),
                    configuration_id,
                },
            ),
            scoped_complete_receipt("provider-b", "2.0.0", owner_a.clone()),
        ];

        let error = resolve_capability_provider(
            &receipts,
            "calls",
            &[owner_b.clone(), owner_a.clone()],
            Some(&ProviderId::new("provider-b")),
        )
        .expect_err("an ineligible preference must not fall back to provider-a");
        assert_eq!(
            error,
            CapabilityResolutionError::PreferredProviderUnavailable {
                capability_id: "calls".into(),
                provider_id: ProviderId::new("provider-b"),
                required_scopes: vec![owner_a.clone(), owner_b.clone()],
            }
        );

        let selected = resolve_capability_provider(&receipts, "calls", &[owner_a, owner_b], None)
            .expect("provider-a is the only independently eligible provider");
        assert_eq!(selected.provider_id, ProviderId::new("provider-a"));
    }

    #[test]
    fn malformed_complete_receipts_fail_closed() {
        let scope = CapabilityScope::Language {
            language_id: LanguageId::new("rust"),
            configuration_id: ConfigurationId::new("calls-v1"),
        };
        let mut cases = Vec::new();

        let mut missing_version = scoped_complete_receipt("provider-a", "1.0.0", scope.clone());
        missing_version.provider_version = None;
        cases.push((missing_version, "provider_version is required"));

        let mut malformed_fingerprint =
            scoped_complete_receipt("provider-a", "1.0.0", scope.clone());
        malformed_fingerprint.input_fingerprint = Some("A".repeat(64));
        cases.push((
            malformed_fingerprint,
            "input_fingerprint must be a 64-character lowercase SHA-256",
        ));

        let mut contradictory_reason =
            scoped_complete_receipt("provider-a", "1.0.0", scope.clone());
        contradictory_reason.reason_code = Some("unexpected".into());
        cases.push((
            contradictory_reason,
            "complete evidence cannot carry failure reasons",
        ));

        for (receipt, expected_reason) in cases {
            let error = resolve_capability_provider(
                &[receipt],
                "calls",
                std::slice::from_ref(&scope),
                None,
            )
            .expect_err("malformed complete authority must fail closed");
            assert_eq!(
                error,
                CapabilityResolutionError::InvalidCompleteReceipt {
                    capability_id: "calls".into(),
                    provider_id: ProviderId::new("provider-a"),
                    reason: expected_reason.into(),
                }
            );
        }
    }

    #[test]
    fn conflicting_complete_receipts_fail_closed() {
        let scope = CapabilityScope::Language {
            language_id: LanguageId::new("rust"),
            configuration_id: ConfigurationId::new("calls-v1"),
        };
        let first = scoped_complete_receipt("provider-a", "1.0.0", scope.clone());
        let mut second = first.clone();
        second.input_fingerprint = Some("a".repeat(64));

        let error = resolve_capability_provider(
            &[first, second],
            "calls",
            std::slice::from_ref(&scope),
            None,
        )
        .expect_err("two fingerprints cannot both identify the same provider scope");
        assert_eq!(
            error,
            CapabilityResolutionError::ConflictingCompleteEvidence {
                capability_id: "calls".into(),
                provider_id: ProviderId::new("provider-a"),
                scope: Box::new(scope),
            }
        );
    }

    #[test]
    fn selected_provider_versions_must_be_consistent() {
        let owner_a = CapabilityScope::ProjectUnit {
            language_id: LanguageId::new("rust"),
            project_unit_id: ProjectUnitId::new("owner-a"),
            configuration_id: ConfigurationId::new("calls-v1"),
        };
        let owner_b = CapabilityScope::ProjectUnit {
            language_id: LanguageId::new("rust"),
            project_unit_id: ProjectUnitId::new("owner-b"),
            configuration_id: ConfigurationId::new("calls-v1"),
        };
        let receipts = vec![
            scoped_complete_receipt("provider-a", "1.0.0", owner_a.clone()),
            scoped_complete_receipt("provider-a", "2.0.0", owner_b.clone()),
        ];

        let error = resolve_capability_provider(&receipts, "calls", &[owner_b, owner_a], None)
            .expect_err("one authority cannot span two provider versions");
        assert_eq!(
            error,
            CapabilityResolutionError::InconsistentProviderVersions {
                capability_id: "calls".into(),
                provider_id: ProviderId::new("provider-a"),
                provider_versions: vec!["1.0.0".into(), "2.0.0".into()],
            }
        );
    }

    #[test]
    fn empty_resolution_requests_are_rejected_before_vacuous_selection() {
        let scope = CapabilityScope::Repository {
            configuration_id: ConfigurationId::new("calls-v1"),
        };
        let receipts = vec![scoped_complete_receipt(
            "provider-a",
            "1.0.0",
            scope.clone(),
        )];

        assert!(matches!(
            resolve_capability_provider(&receipts, "", &[scope], None),
            Err(CapabilityResolutionError::InvalidRequest {
                field: "capability_id",
                ..
            })
        ));
        assert!(matches!(
            resolve_capability_provider(&receipts, "calls", &[], None),
            Err(CapabilityResolutionError::InvalidRequest {
                field: "required_scopes",
                ..
            })
        ));
    }

    #[test]
    fn mixed_language_coverage_never_promotes_one_complete_provider_to_all_languages() {
        let rust_scope = CapabilityScope::Language {
            language_id: LanguageId::new("rust"),
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        };
        let go_scope = CapabilityScope::Language {
            language_id: LanguageId::new("go"),
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        };
        let receipts = vec![
            scoped_complete_receipt("rust-analyzer-scip", "1.0.0", rust_scope),
            CapabilityReceipt::unavailable(
                "calls",
                "scip-go",
                None,
                go_scope,
                None,
                "provider_failed_or_unavailable",
                "scip-go produced no validated artifact",
            ),
        ];
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: ProjectTopology {
                units: Vec::new(),
                memberships: vec![
                    DocumentMembership {
                        document_path: "src/lib.rs".into(),
                        language_id: LanguageId::new("rust"),
                        project_unit_id: ProjectUnitId::new("rust-unit"),
                        kind: DocumentMembershipKind::SourceOwner,
                    },
                    DocumentMembership {
                        document_path: "main.go".into(),
                        language_id: LanguageId::new("go"),
                        project_unit_id: ProjectUnitId::new("go-unit"),
                        kind: DocumentMembershipKind::SourceOwner,
                    },
                ],
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: Vec::new(),
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: Vec::new(),
        };

        let coverage = assess_language_capability(
            &receipts,
            &inventory,
            "calls",
            CALLS_CONFIGURATION_ID,
            [LanguageId::new("rust"), LanguageId::new("go")],
        );
        assert_eq!(coverage.status, CapabilityCoverageStatus::Partial);
        assert!(!coverage.all_callable_languages_complete());
        assert_eq!(
            coverage.complete_languages(),
            BTreeSet::from([LanguageId::new("rust")])
        );
        let go = coverage
            .languages
            .iter()
            .find(|language| language.language_id == LanguageId::new("go"))
            .expect("Go coverage row");
        assert_eq!(go.status, CapabilityCoverageStatus::Unavailable);
        assert_eq!(go.gaps[0].reason_code, "provider_failed_or_unavailable");
    }

    /// RIGHT-REASON REGRESSION for B01: an unrelated incomplete receipt may
    /// explain one provider's failure, but it must not erase the independently
    /// diagnosed ambiguity between two complete providers.
    #[test]
    fn capability_explanation_retains_resolution_failure_beside_receipt_gaps() {
        let project_unit_id = ProjectUnitId::new("rust-package");
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: ProjectTopology {
                units: Vec::new(),
                memberships: vec![DocumentMembership {
                    document_path: "src/lib.rs".into(),
                    language_id: LanguageId::new("rust"),
                    project_unit_id,
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
        let scope = CapabilityScope::Language {
            language_id: LanguageId::new("rust"),
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        };
        let receipts = vec![
            scoped_complete_receipt("provider-a", "1.0.0", scope.clone()),
            scoped_complete_receipt("provider-b", "1.0.0", scope.clone()),
            CapabilityReceipt::partial(
                "calls",
                "provider-c",
                Some("1.0.0".into()),
                scope,
                Some("c".repeat(64)),
                "provider_c_incomplete",
                "provider C omitted one source region",
            ),
        ];

        let coverage = assess_language_capability(
            &receipts,
            &inventory,
            "calls",
            CALLS_CONFIGURATION_ID,
            [LanguageId::new("rust")],
        );
        let language = coverage.languages.first().expect("Rust coverage row");
        let codes = language
            .gaps
            .iter()
            .map(|gap| gap.reason_code.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            codes,
            BTreeSet::from(["provider_authority_ambiguous", "provider_c_incomplete"]),
            "receipt evidence and the resolver's independent authority diagnosis must both survive"
        );
    }

    /// FALSIFIER: a source file without a language execution root remains
    /// useful structural data, but it cannot create a provider-authority scope
    /// that no project system can execute. Otherwise one orphan Rust file turns
    /// complete Cargo evidence into a permanent partial result and forces every
    /// unchanged best-effort index through the provider again.
    #[test]
    fn loose_rust_source_is_structural_only_beside_a_complete_cargo_population() {
        use crate::graph::GraphNode;
        use crate::reachability::ReachabilityClass;

        let cargo_unit = ProjectUnitId::new("rust:cargo:package:Cargo.toml");
        let loose_unit = ProjectUnitId::new("rust:rust:loose_sources:<repository>");
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: ProjectTopology {
                units: vec![
                    ProjectUnit {
                        project_unit_id: cargo_unit.clone(),
                        language_id: LanguageId::new("rust"),
                        ecosystem_id: EcosystemId::new("cargo"),
                        kind: ProjectUnitKind::Package,
                        root_path: String::new(),
                        manifest_path: Some("Cargo.toml".into()),
                        compilation_root_paths: Vec::new(),
                    },
                    ProjectUnit {
                        project_unit_id: loose_unit.clone(),
                        language_id: LanguageId::new("rust"),
                        ecosystem_id: EcosystemId::new("rust"),
                        kind: ProjectUnitKind::LooseSources,
                        root_path: String::new(),
                        manifest_path: None,
                        compilation_root_paths: Vec::new(),
                    },
                ],
                memberships: vec![
                    DocumentMembership {
                        document_path: "src/lib.rs".into(),
                        language_id: LanguageId::new("rust"),
                        project_unit_id: cargo_unit.clone(),
                        kind: DocumentMembershipKind::SourceOwner,
                    },
                    DocumentMembership {
                        document_path: "providers/template.rs".into(),
                        language_id: LanguageId::new("rust"),
                        project_unit_id: loose_unit,
                        kind: DocumentMembershipKind::SourceOwner,
                    },
                ],
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: Vec::new(),
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: Vec::new(),
        };
        let mut graph = crate::graph::KnowledgeGraph::new();
        for (name, file_path) in [
            ("cargo_entry", "src/lib.rs"),
            ("loose_template", "providers/template.rs"),
        ] {
            graph
                .add_node(GraphNode {
                    memory_id: uuid::Uuid::new_v4(),
                    symbol_name: name.into(),
                    kind: "function".into(),
                    file_path: file_path.into(),
                    content_hash: format!("hash-{name}"),
                    signature: format!("fn {name}()"),
                    reachability_class: ReachabilityClass::Wired,
                    line_start: Some(0),
                    line_end: Some(0),
                    has_body: Some(true),
                    visibility: "pub".into(),
                    is_test_only: Some(false),
                    is_test_root: false,
                    has_platform_cfg: false,
                    rustc_flagged_dead: false,
                    entry_retain: Default::default(),
                    has_uncaptured_items: false,
                    oracle_receipt: None,
                })
                .expect("graph node");
        }
        let loose_membership = inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| membership.document_path == "providers/template.rs")
            .expect("loose source membership");

        assert!(
            graph.node_by_name("loose_template").is_some(),
            "positive control: loose source remains structurally indexed"
        );
        assert!(
            !inventory.is_semantic_source_owner(loose_membership),
            "an unowned source cannot authorize an unexecutable provider scope"
        );

        let receipts = vec![scoped_complete_receipt(
            "rust-analyzer-scip",
            "1.0.0",
            CapabilityScope::ProjectUnit {
                language_id: LanguageId::new("rust"),
                project_unit_id: cargo_unit,
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            },
        )];
        let coverage = assess_calls_receipt_coverage(&graph, &receipts, &inventory);
        assert_eq!(coverage.status, CapabilityCoverageStatus::Complete);
        assert_eq!(coverage.languages.len(), 1);
        assert_eq!(coverage.languages[0].language_id, LanguageId::new("rust"));
        assert!(coverage.languages[0].gaps.is_empty());
    }

    #[test]
    fn auxiliary_callables_do_not_create_repository_calls_authority_scope() {
        use crate::graph::GraphNode;
        use crate::reachability::ReachabilityClass;

        let rust_unit = ProjectUnitId::new("rust-package");
        let go_auxiliary = ProjectUnitId::new("go-testdata");
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: ProjectTopology {
                units: vec![
                    ProjectUnit {
                        project_unit_id: rust_unit.clone(),
                        language_id: LanguageId::new("rust"),
                        ecosystem_id: EcosystemId::new("cargo"),
                        kind: ProjectUnitKind::Package,
                        root_path: "".into(),
                        manifest_path: Some("Cargo.toml".into()),
                        compilation_root_paths: Vec::new(),
                    },
                    ProjectUnit {
                        project_unit_id: go_auxiliary.clone(),
                        language_id: LanguageId::new("go"),
                        ecosystem_id: EcosystemId::new("go"),
                        kind: ProjectUnitKind::AuxiliarySources,
                        root_path: "testdata".into(),
                        manifest_path: None,
                        compilation_root_paths: Vec::new(),
                    },
                ],
                memberships: vec![
                    DocumentMembership {
                        document_path: "src/lib.rs".into(),
                        language_id: LanguageId::new("rust"),
                        project_unit_id: rust_unit,
                        kind: DocumentMembershipKind::SourceOwner,
                    },
                    DocumentMembership {
                        document_path: "testdata/shape.go".into(),
                        language_id: LanguageId::new("go"),
                        project_unit_id: go_auxiliary,
                        kind: DocumentMembershipKind::SourceOwner,
                    },
                ],
                relationships: Vec::new(),
                exact_workspace_member_sets: Vec::new(),
                dependency_graphs: Vec::new(),
            },
            analysis_context_graphs: Vec::new(),
            inputs: Vec::new(),
            issues: Vec::new(),
        };
        let mut graph = crate::graph::KnowledgeGraph::new();
        for (name, file_path) in [
            ("real_rust", "src/lib.rs"),
            ("fixture_go", "testdata/shape.go"),
        ] {
            graph
                .add_node(GraphNode {
                    memory_id: uuid::Uuid::new_v4(),
                    symbol_name: name.into(),
                    kind: "function".into(),
                    file_path: file_path.into(),
                    content_hash: format!("hash-{name}"),
                    signature: format!("fn {name}()"),
                    reachability_class: ReachabilityClass::Wired,
                    line_start: Some(0),
                    line_end: Some(0),
                    has_body: Some(true),
                    visibility: "pub".into(),
                    is_test_only: Some(false),
                    is_test_root: false,
                    has_platform_cfg: false,
                    rustc_flagged_dead: false,
                    entry_retain: Default::default(),
                    has_uncaptured_items: false,
                    oracle_receipt: None,
                })
                .expect("graph node");
        }
        let receipts = vec![scoped_complete_receipt(
            "rust-analyzer-scip",
            "1.0.0",
            CapabilityScope::Language {
                language_id: LanguageId::new("rust"),
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            },
        )];

        let coverage = assess_calls_receipt_coverage(&graph, &receipts, &inventory);
        assert_eq!(coverage.status, CapabilityCoverageStatus::Complete);
        assert_eq!(coverage.languages.len(), 1);
        assert_eq!(coverage.languages[0].language_id, LanguageId::new("rust"));

        let dependency_receipts = vec![CapabilityReceipt::complete(
            "project_dependencies",
            "cargo-metadata",
            "1.0.0",
            CapabilityScope::Language {
                language_id: LanguageId::new("rust"),
                configuration_id: ConfigurationId::new(PROJECT_DEPENDENCIES_CONFIGURATION_ID),
            },
            "1".repeat(64),
        )];
        let dependencies =
            assess_project_dependencies_capability(&graph, &dependency_receipts, &inventory);
        assert_eq!(dependencies.status, CapabilityCoverageStatus::Complete);
        assert_eq!(dependencies.languages.len(), 1);
        assert_eq!(
            dependencies.languages[0].language_id,
            LanguageId::new("rust")
        );

        // Non-vacuity: an unowned graph language is not silently reclassified
        // as auxiliary. The graph union keeps malformed/partial inventory from
        // erasing a real language population.
        let mut inventory_without_auxiliary_evidence = inventory;
        inventory_without_auxiliary_evidence
            .project_topology
            .units
            .retain(|unit| unit.language_id != LanguageId::new("go"));
        inventory_without_auxiliary_evidence
            .project_topology
            .memberships
            .retain(|membership| membership.language_id != LanguageId::new("go"));
        let dependencies = assess_project_dependencies_capability(
            &graph,
            &dependency_receipts,
            &inventory_without_auxiliary_evidence,
        );
        assert_eq!(dependencies.status, CapabilityCoverageStatus::Partial);
        assert_eq!(dependencies.languages.len(), 2);
        assert!(dependencies.languages.iter().any(|language| {
            language.language_id == LanguageId::new("go")
                && language.status == CapabilityCoverageStatus::Unavailable
        }));
    }

    /// RIGHT-REASON REGRESSION for X01: absence of a structurally declared
    /// callable is not proof that Calls is inapplicable. A semantic project can
    /// contain executable module-level call syntax while provider health is
    /// incomplete. Its persisted failure must remain visible instead of being
    /// collapsed to a vacuous `NotApplicable` result.
    #[test]
    fn semantic_project_failure_is_applicable_without_structural_callable_declarations() {
        use crate::graph::GraphNode;
        use crate::reachability::ReachabilityClass;

        let typescript_unit = ProjectUnitId::new("typescript:package:package.json");
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: ProjectTopology {
                units: vec![ProjectUnit {
                    project_unit_id: typescript_unit.clone(),
                    language_id: LanguageId::new("typescript"),
                    ecosystem_id: EcosystemId::new("npm"),
                    kind: ProjectUnitKind::Package,
                    root_path: String::new(),
                    manifest_path: Some("package.json".into()),
                    compilation_root_paths: Vec::new(),
                }],
                memberships: vec![DocumentMembership {
                    document_path: "src/usage.ts".into(),
                    language_id: LanguageId::new("typescript"),
                    project_unit_id: typescript_unit,
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
        let membership = inventory
            .project_topology
            .memberships
            .first()
            .expect("nonempty semantic project control");
        assert!(
            inventory.is_semantic_source_owner(membership),
            "positive control: the TypeScript document is provider-executable"
        );

        let mut graph = crate::graph::KnowledgeGraph::new();
        graph
            .add_node(GraphNode {
                memory_id: uuid::Uuid::new_v4(),
                symbol_name: "result".into(),
                kind: "variable".into(),
                file_path: "src/usage.ts".into(),
                content_hash: "hash-result".into(),
                signature: "export const result = missing()".into(),
                reachability_class: ReachabilityClass::Structural,
                line_start: Some(0),
                line_end: Some(0),
                has_body: Some(false),
                visibility: "public".into(),
                is_test_only: Some(false),
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .expect("non-callable structural node");
        assert!(
            graph
                .all_nodes()
                .iter()
                .all(|node| !symbol_kind_has_role(&node.kind, SymbolRole::Callable)),
            "positive control: no structural callable declaration can accidentally trigger the old census"
        );

        let receipts = vec![CapabilityReceipt::unavailable(
            "calls",
            "typescript-language-service",
            None,
            CapabilityScope::Language {
                language_id: LanguageId::new("typescript"),
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            },
            None,
            "provider_failed_or_unavailable",
            "the TypeScript provider reported incomplete module-resolution health",
        )];

        let coverage = assess_calls_receipt_coverage(&graph, &receipts, &inventory);
        assert_eq!(coverage.status, CapabilityCoverageStatus::Unavailable);
        assert_eq!(coverage.languages.len(), 1);
        assert_eq!(
            coverage.languages[0].language_id,
            LanguageId::new("typescript")
        );
        assert_eq!(
            coverage.languages[0].gaps[0].reason_code,
            "provider_failed_or_unavailable"
        );
    }

    #[test]
    fn live_input_observation_keeps_generation_authority_and_worktree_freshness_separate() {
        use crate::graph_stats::{StalenessReason, StalenessVerdict};

        let fresh = LiveInputObservation::from_staleness(StalenessVerdict::Fresh, 12);
        assert_eq!(fresh.freshness, LiveInputFreshness::Fresh);
        assert_eq!(fresh.indexed_file_count, 12);
        assert_eq!(fresh.generation_qualification(), None);

        let stale = LiveInputObservation::from_staleness(StalenessVerdict::Stale, 12);
        assert_eq!(stale.freshness, LiveInputFreshness::Stale);
        assert!(
            stale
                .generation_qualification()
                .is_some_and(|warning| warning.contains("not the current worktree"))
        );

        let unknown = LiveInputObservation::from_staleness(
            StalenessVerdict::Unknown {
                reason: StalenessReason::SourceVerificationFailed,
                files_checked: 7,
            },
            12,
        );
        assert_eq!(unknown.freshness, LiveInputFreshness::Unknown);
        assert_eq!(
            unknown.reason.as_deref(),
            Some("source_verification_failed")
        );
        assert_eq!(unknown.files_checked, Some(7));
        assert!(unknown.generation_qualification().is_some());

        #[derive(Serialize)]
        struct ResultEnvelope {
            repository: RepositoryBinding,
            warnings: Vec<String>,
        }

        let without_observation = ResultEnvelope {
            repository: RepositoryBinding {
                repository_id: RepositoryId::new("f".repeat(64)),
                root_label: "repository".into(),
                live_inputs: None,
            },
            warnings: vec!["existing warning".into()],
        };
        let with_largest_observation = ResultEnvelope {
            repository: RepositoryBinding {
                repository_id: without_observation.repository.repository_id.clone(),
                root_label: without_observation.repository.root_label.clone(),
                live_inputs: Some(LiveInputObservation::from_staleness(
                    StalenessVerdict::Unknown {
                        reason: StalenessReason::ProviderSemanticInputsUnverifiable,
                        files_checked: usize::MAX,
                    },
                    usize::MAX,
                )),
            },
            warnings: vec![
                "existing warning".into(),
                LiveInputObservation::from_staleness(
                    StalenessVerdict::Unknown {
                        reason: StalenessReason::ProviderSemanticInputsUnverifiable,
                        files_checked: usize::MAX,
                    },
                    usize::MAX,
                )
                .generation_qualification()
                .expect("unknown freshness qualification"),
            ],
        };
        let base_chars = serde_json::to_string(&without_observation)
            .expect("serialize base result")
            .chars()
            .count();
        let observed_chars = serde_json::to_string(&with_largest_observation)
            .expect("serialize observed result")
            .chars()
            .count();
        assert!(
            observed_chars - base_chars <= LIVE_INPUT_RESULT_RESERVE_CHARS,
            "live-input attachment grew by {} characters, beyond the {}-character reserve",
            observed_chars - base_chars,
            LIVE_INPUT_RESULT_RESERVE_CHARS,
        );
    }
}
