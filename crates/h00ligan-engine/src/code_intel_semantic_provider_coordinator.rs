//! Language-neutral persistent semantic-provider coordination.
//!
//! The coordinator owns disposable process/session acceleration only. It
//! reconciles exact structural source evidence, admits provider terminals, and
//! returns one canonical normalization to the existing immutable publisher.
//! It never publishes, persists, or grants authority by itself.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt as _};
use h00ligan_provider_protocol::{
    ExpectedAffectedRefresh, ExpectedFullCertification, ExpectedProviderAnalysis,
    ExpectedProviderDocument, ProviderAnalysisRequest, ProviderAuthority, ProviderFrameLimits,
    ProviderHealthEvidence, ProviderIdentity, ProviderOperation, ProviderRequestBody,
    ProviderResponseBody, ProviderSemanticEnvironmentInput, ProviderSemanticInputCoverage,
    ProviderSemanticInputIssue, ProviderSemanticInputs, ProviderSemanticPathInput,
    ProviderSemanticPathKind, ProviderSemanticPathRoot, ProviderSourceChange,
    ProviderSourceIdentity, RESOLVED_TOOLCHAIN_SHA256_ENV, provider_identity_sha256,
    provider_semantic_inputs_are_current_in_environment, provider_semantic_inputs_sha256,
    resolved_authority_configuration_sha256, resolved_workspace_configuration_sha256, sha256_hex,
    source_population_sha256,
};
#[cfg(test)]
use h00ligan_provider_protocol::{
    H00_GO_IMPLEMENTATION_V4, H00_GO_LANGUAGE, H00_GO_PROVIDER_ID,
    H00_RUST_ANALYZER_IMPLEMENTATION_V6, H00_RUST_ANALYZER_LANGUAGE, H00_RUST_ANALYZER_PROVIDER_ID,
    RESOLVED_CARGO_SHA256_ENV, RESOLVED_RUSTC_SHA256_ENV, RustSemanticProfile,
    SEMANTIC_PROVIDER_CACHE_DIR_ENV, go_provider_source_components,
    rust_analyzer_source_components,
};
use thiserror::Error;

use crate::code_intel_cancellation::IndexCancellation;
use crate::code_intel_domain::{
    CapabilityStatus, EcosystemId, LanguageId, ProjectInventory, ProjectInventoryCoverage,
};
#[cfg(test)]
use crate::code_intel_go_semantic_provider::{GoSemanticProviderConfig, GoSemanticProviderPolicy};
use crate::code_intel_inventory::{
    InventorySource, build_project_inventory, semantic_provider_document_execution_roots,
    semantic_provider_execution_roots, semantic_provider_inventory_fingerprint,
};
use crate::code_intel_payload::{
    CallsProviderPayload, NormalizedProviderPayload, ProviderCall, ProviderExecutionAuthority,
    ProviderExecutionRootAuthority, ProviderGenerationReconstruction, ProviderLocation,
    ProviderPayload, ProviderRootInvocation, normalize_provider_payload_typed,
};
#[cfg(test)]
use crate::code_intel_rust_semantic_provider::{
    RUST_OPEN_SESSION_REUSE_CONTRACT_ID, RustSemanticProviderConfig,
    RustSemanticProviderCoordinator, RustSemanticProviderPolicy,
    rust_provider_reload_sensitive_documents,
};
use crate::code_intel_semantic_provider::{
    AffectedNormalizationBasis, ExecutionRootRecertificationBasis, ProviderAffectedRefresh,
    ProviderFullCertification, SemanticProviderBridgeError,
    normalize_admitted_affected_refreshes_with_source_syntax_cache,
    normalize_admitted_execution_root_recertifications_with_source_syntax_cache,
    normalize_admitted_full_certifications_with_source_syntax_cache,
};
use crate::code_intel_semantic_provider_process::{
    SemanticProviderProcess, SemanticProviderProcessConfig, SemanticProviderProcessError,
};
use crate::code_intel_toolchain::{
    ResolvedToolchain, ToolchainBoundAuthorityInput, ToolchainResolutionError, ToolchainResolver,
    resolve_toolchain_population, toolchain_bound_execution_authority,
};
#[cfg(test)]
use crate::code_intel_workspace_semantic_provider::{
    PYREFLY_WORKSPACE_PROVIDER, TYPESCRIPT_WORKSPACE_PROVIDER, WorkspaceSemanticProviderConfig,
    WorkspaceSemanticProviderPolicy,
};

use crate::code_intel_semantic_refresh::{
    AffectedCandidateEvidence, SemanticDocumentChange, SemanticDocumentVersion,
    SemanticRefreshInput, SemanticRefreshPlan, SemanticTargetDivergence, plan_semantic_refresh,
    validate_affected_candidate,
};
use crate::scip_normalizer::{
    CanonicalScipSnapshot, CanonicalSemanticBasis, CanonicalSourceSyntaxCache,
    IndexedSourceEvidence, ScipArtifactEvidence, ScipArtifactSetNormalization,
    build_canonical_source_syntax_cache,
};

const PROVIDER_CPUS_PER_ROOT: usize = 4;
const MAX_CONCURRENT_PROVIDER_ROOTS: usize = 4;

pub fn provider_root_parallelism_for(
    root_count: usize,
    jobs: Option<usize>,
    available_parallelism: usize,
) -> usize {
    if root_count == 0 {
        return 0;
    }
    let available_parallelism = available_parallelism.max(1);
    let automatic =
        (available_parallelism / PROVIDER_CPUS_PER_ROOT).clamp(1, MAX_CONCURRENT_PROVIDER_ROOTS);
    let requested = jobs
        .unwrap_or(automatic)
        .clamp(1, MAX_CONCURRENT_PROVIDER_ROOTS);
    root_count.min(available_parallelism).min(requested).max(1)
}

pub fn provider_root_parallelism(root_count: usize, jobs: Option<usize>) -> usize {
    provider_root_parallelism_for(
        root_count,
        jobs,
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
    )
}

/// Provider-owned lifecycle for a source change whose cross-document surface
/// requires full certification. Some compiler sessions can safely apply the
/// new epoch and certify in place. Others pin a workspace-resolution witness
/// at session admission and must certify through a replacement population.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceChangedFullCertificationMode {
    ApplyToRetainedSessions,
    ReplaceSessions,
}

/// Scope at which one provider can invalidate and refresh retained session
/// state. This is adapter policy, not a property inferred from the changed
/// source population by the shared coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticProviderInvalidationScope {
    WholeProvider,
    ExecutionRootLocal,
}

/// Static lifecycle choices supplied atomically by one language adapter.
///
/// Dynamic compiler facts, such as whether a particular closed generation can
/// be reconstructed, remain explicit policy methods because they depend on
/// the observed repository and cannot truthfully be collapsed into this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticProviderLifecyclePolicy {
    source_changed_full_certification: SourceChangedFullCertificationMode,
    invalidation_scope: SemanticProviderInvalidationScope,
}

impl SemanticProviderLifecyclePolicy {
    pub(crate) const fn new(
        source_changed_full_certification: SourceChangedFullCertificationMode,
        invalidation_scope: SemanticProviderInvalidationScope,
    ) -> Self {
        Self {
            source_changed_full_certification,
            invalidation_scope,
        }
    }

    pub(crate) const fn supports_root_local_refresh(self) -> bool {
        matches!(
            self.invalidation_scope,
            SemanticProviderInvalidationScope::ExecutionRootLocal
        )
    }
}

/// Adapter-owned behavior needed by the language-neutral persistent-provider
/// lifecycle. Adding a language supplies one policy implementation; it does
/// not add a branch to session, reuse, refresh, or publication ownership.
pub trait SemanticProviderPolicy: Clone + std::fmt::Debug + Send + Sync + 'static {
    fn language(&self) -> &'static str;
    fn ecosystem(&self) -> &'static str;
    fn operation_label(&self) -> &'static str;
    fn reuse_contract_id(&self) -> &'static str;
    fn invocation_schema(&self) -> &'static [u8];
    fn configuration_schema(&self) -> &'static [u8];
    fn required_components(&self) -> &'static [&'static str];

    /// Opaque typed analyses this language provider must return with every
    /// certification terminal. Document export and supplemental analysis are
    /// admitted by the same one-use provider transaction, but retain distinct
    /// capability semantics after the wire boundary.
    fn requested_analyses(&self) -> Vec<ProviderAnalysisRequest> {
        Vec::new()
    }

    fn configure_process(
        &self,
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
        process: &mut SemanticProviderProcessConfig,
    );

    fn active_cache_directories(
        &self,
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
    ) -> Vec<PathBuf>;

    fn execution_root_inventory_fingerprints(
        &self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        inventory: &ProjectInventory,
        whole_inventory_sha256: &str,
    ) -> Result<BTreeMap<PathBuf, String>, SemanticProviderError>;

    fn execution_root_semantic_input_paths(
        &self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        inventory: &ProjectInventory,
    ) -> Result<BTreeMap<PathBuf, BTreeSet<String>>, SemanticProviderError>;

    fn reload_sensitive_documents(
        &self,
        repository_root: &Path,
        inventory: &ProjectInventory,
    ) -> Result<BTreeSet<String>, SemanticProviderError>;

    fn lifecycle_policy(&self) -> SemanticProviderLifecyclePolicy;

    fn closed_generation_inputs_are_reconstructable(
        &self,
        repository_root: &Path,
        inventory: &ProjectInventory,
        execution_roots: &[PathBuf],
    ) -> bool;

    fn capture_expected_semantic_inputs(
        &self,
        repository_root: &Path,
        semantic_input_paths: &BTreeSet<String>,
        provider_environment: &BTreeMap<OsString, OsString>,
        limits: &ProviderFrameLimits,
        inventory: &ProjectInventory,
    ) -> Result<Option<ProviderSemanticInputs>, SemanticProviderError>;

    fn append_invocation_coordinates(
        &self,
        material: &mut Vec<u8>,
    ) -> Result<(), SemanticProviderError>;
}

#[derive(Debug, Clone)]
pub struct PersistentSemanticProviderConfig<P: SemanticProviderPolicy> {
    binary: PathBuf,
    expected_identity: ProviderIdentity,
    arguments: Vec<OsString>,
    toolchain_resolver: Arc<dyn ToolchainResolver>,
    request_timeout: Duration,
    max_stderr_bytes: usize,
    cache_root: Option<PathBuf>,
    policy: P,
    #[cfg(test)]
    prepare_sources_calls: Arc<AtomicUsize>,
}

impl<P: SemanticProviderPolicy> PersistentSemanticProviderConfig<P> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_adapter(
        binary: PathBuf,
        expected_identity: ProviderIdentity,
        arguments: Vec<OsString>,
        toolchain_resolver: Arc<dyn ToolchainResolver>,
        request_timeout: Duration,
        max_stderr_bytes: usize,
        cache_root: Option<PathBuf>,
        policy: P,
    ) -> Self {
        Self {
            binary,
            expected_identity,
            arguments,
            toolchain_resolver,
            request_timeout,
            max_stderr_bytes,
            cache_root,
            policy,
            #[cfg(test)]
            prepare_sources_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn cache_root(&self) -> Option<&Path> {
        self.cache_root.as_deref()
    }

    pub(crate) const fn expected_identity(&self) -> &ProviderIdentity {
        &self.expected_identity
    }

    fn process_config(&self, toolchain: &ResolvedToolchain) -> SemanticProviderProcessConfig {
        let mut config = SemanticProviderProcessConfig::new(
            &self.binary,
            self.expected_identity.clone(),
            toolchain.fingerprint_sha256(),
            &toolchain.execution_root,
        );
        config.arguments = self.arguments.clone();
        config.environment = toolchain.process_environment();
        config.environment.insert(
            RESOLVED_TOOLCHAIN_SHA256_ENV.into(),
            toolchain.fingerprint_sha256().into(),
        );
        self.policy.configure_process(self, toolchain, &mut config);
        config.request_timeout = self.request_timeout;
        config.max_stderr_bytes = self.max_stderr_bytes;
        config
    }

    fn language(&self) -> &'static str {
        self.policy.language()
    }

    fn ecosystem(&self) -> &'static str {
        self.policy.ecosystem()
    }

    fn reuse_contract_id(&self) -> &'static str {
        self.policy.reuse_contract_id()
    }

    fn inventory_fingerprint(
        &self,
        inventory: &ProjectInventory,
    ) -> Result<String, SemanticProviderError> {
        semantic_provider_inventory_fingerprint(inventory, self.language(), self.ecosystem())
            .map_err(|error| SemanticProviderError::Inventory(error.to_string()))
    }

    fn execution_root_inventory_fingerprints(
        &self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        inventory: &ProjectInventory,
        whole_inventory_sha256: &str,
    ) -> Result<BTreeMap<PathBuf, String>, SemanticProviderError> {
        self.policy.execution_root_inventory_fingerprints(
            repository_root,
            execution_roots,
            inventory,
            whole_inventory_sha256,
        )
    }

    fn execution_root_semantic_input_paths(
        &self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        inventory: &ProjectInventory,
    ) -> Result<BTreeMap<PathBuf, BTreeSet<String>>, SemanticProviderError> {
        self.policy
            .execution_root_semantic_input_paths(repository_root, execution_roots, inventory)
    }

    fn execution_roots(&self, inventory: &ProjectInventory) -> Vec<PathBuf> {
        semantic_provider_execution_roots(inventory, self.language(), self.ecosystem())
    }

    fn reload_sensitive_documents(
        &self,
        repository_root: &Path,
        inventory: &ProjectInventory,
    ) -> Result<BTreeSet<String>, SemanticProviderError> {
        self.policy
            .reload_sensitive_documents(repository_root, inventory)
    }

    fn prepare_sources(
        &self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        indexed_sources: &[IndexedSourceEvidence],
        inventory: &ProjectInventory,
    ) -> Result<BTreeMap<String, PreparedSource>, SemanticProviderError> {
        #[cfg(test)]
        self.prepare_sources_calls.fetch_add(1, Ordering::SeqCst);
        prepare_provider_sources(
            repository_root,
            execution_roots,
            indexed_sources,
            inventory,
            self.language(),
            self.ecosystem(),
        )
    }

    #[cfg(test)]
    fn prepare_sources_call_count(&self) -> usize {
        self.prepare_sources_calls.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    fn reset_prepare_sources_call_count(&self) {
        self.prepare_sources_calls.store(0, Ordering::SeqCst);
    }
}

#[derive(Debug, Error)]
pub enum SemanticProviderConfigError {
    #[error("semantic-provider identity is invalid: {0}")]
    Identity(String),
    #[error("semantic-provider policy is invalid: {0}")]
    Policy(String),
}

#[derive(Debug, Error)]
pub enum SemanticProviderError {
    #[error("semantic provider has no eligible execution roots")]
    NoExecutionRoots,
    #[error("semantic provider root is not canonical UTF-8: {0}")]
    InvalidRoot(String),
    #[error("semantic provider source path is unsafe: {0}")]
    InvalidSourcePath(String),
    #[error("semantic provider source is outside every execution root: {0}")]
    SourceOutsideExecutionRoot(String),
    #[error("semantic provider execution root has no exact source population: {0}")]
    EmptyExecutionRoot(String),
    #[error("semantic provider source changed during reconciliation: {0}")]
    SourceIdentityMismatch(String),
    #[error("semantic provider structural identity collision: {0}")]
    SourceIdentityCollision(String),
    #[error("semantic provider filesystem operation failed for {path}: {detail}")]
    Filesystem { path: PathBuf, detail: String },
    #[error("semantic provider inventory is invalid: {0}")]
    Inventory(String),
    #[error(transparent)]
    Process(#[from] SemanticProviderProcessError),
    #[error("semantic provider execution root {root} failed: {source}")]
    ExecutionRoot {
        root: PathBuf,
        #[source]
        source: Box<Self>,
    },
    #[error(transparent)]
    Protocol(#[from] h00ligan_provider_protocol::SemanticProviderProtocolError),
    #[error(transparent)]
    Bridge(#[from] SemanticProviderBridgeError),
    #[error("semantic provider rejected {operation}: {code}: {message}")]
    Rejected {
        operation: &'static str,
        code: String,
        message: String,
    },
    #[error("semantic provider returned an invalid {0} transition")]
    InvalidTransition(&'static str),
    #[error("semantic provider {operation} health does not admit complete authority: {health:?}")]
    IncompleteHealth {
        operation: &'static str,
        health: ProviderHealthEvidence,
    },
    #[error("semantic provider roots reported different build or runtime identities")]
    InconsistentProviderIdentity,
    #[error(transparent)]
    Toolchain(#[from] ToolchainResolutionError),
    #[error("semantic provider resolved a toolchain for the wrong language or execution root")]
    ToolchainBindingMismatch,
    #[error("semantic provider toolchain changed during one indexing operation")]
    ToolchainChanged,
    #[error("semantic provider full certification did not retain a complete canonical snapshot")]
    IncompleteFullCertification,
    #[error(
        "semantic provider discarded a failed candidate without changing prior authority: {source}"
    )]
    PriorAuthorityPreserved {
        #[source]
        source: Box<Self>,
    },
}

/// Bounded failure evidence that may cross the immutable publication boundary.
///
/// Process/session errors retain rich internal types, but generation receipts
/// need one stable machine code plus bounded human detail. Keeping this
/// projection on the owning error type prevents each index adapter from
/// collapsing failures differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticProviderFailureEvidence {
    pub reason_code: String,
    pub reason: String,
}

impl SemanticProviderError {
    #[must_use]
    pub(crate) fn immutable_failure_evidence(&self) -> SemanticProviderFailureEvidence {
        const DETAIL_LIMIT: usize = 1_024;

        let detail = self.to_string();
        let mut reason = detail.chars().take(DETAIL_LIMIT).collect::<String>();
        if detail.chars().count() > DETAIL_LIMIT {
            reason.push('…');
        }
        SemanticProviderFailureEvidence {
            reason_code: self.immutable_failure_reason_code(),
            reason,
        }
    }

    fn immutable_failure_reason_code(&self) -> String {
        match self {
            Self::ExecutionRoot { source, .. } | Self::PriorAuthorityPreserved { source } => {
                source.immutable_failure_reason_code()
            }
            Self::Rejected { code, .. } => provider_failure_fragment(code).map_or_else(
                || "provider_rejected_request".into(),
                |code| format!("provider_rejected_{code}"),
            ),
            Self::IncompleteHealth { health, .. } => health_failure_reason_code(health),
            Self::NoExecutionRoots => "provider_execution_root_unavailable".into(),
            Self::InvalidRoot(_)
            | Self::InvalidSourcePath(_)
            | Self::SourceOutsideExecutionRoot(_)
            | Self::EmptyExecutionRoot(_)
            | Self::Inventory(_) => "provider_inventory_invalid".into(),
            Self::SourceIdentityMismatch(_) | Self::SourceIdentityCollision(_) => {
                "provider_source_identity_changed".into()
            }
            Self::Filesystem { .. } => "provider_filesystem_failed".into(),
            Self::Process(error) => process_failure_reason_code(error).into(),
            Self::Protocol(_) => "provider_protocol_invalid".into(),
            Self::Bridge(error) => bridge_failure_reason_code(error).into(),
            Self::InvalidTransition(_) => "provider_transition_invalid".into(),
            Self::InconsistentProviderIdentity => "provider_identity_inconsistent".into(),
            Self::Toolchain(error) => toolchain_failure_reason_code(error).into(),
            Self::ToolchainBindingMismatch => "provider_toolchain_binding_mismatch".into(),
            Self::ToolchainChanged => "provider_toolchain_changed".into(),
            Self::IncompleteFullCertification => "provider_certification_incomplete".into(),
        }
    }
}

fn provider_failure_fragment(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 96
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        }))
    .then_some(value)
}

fn health_failure_reason_code(health: &ProviderHealthEvidence) -> String {
    let mut degradation_reasons = health
        .degradation_reasons
        .iter()
        .filter_map(|reason| provider_failure_fragment(reason))
        .collect::<Vec<_>>();
    degradation_reasons.sort_unstable();
    degradation_reasons.dedup();
    if degradation_reasons.len() == 1 {
        return format!("provider_health_{}", degradation_reasons[0]);
    }

    let mut unhealthy_components = health
        .components
        .iter()
        .filter(|(_, status)| {
            !matches!(
                status,
                h00ligan_provider_protocol::ProviderComponentHealth::Healthy
                    | h00ligan_provider_protocol::ProviderComponentHealth::NotApplicable
            )
        })
        .filter_map(|(component, _)| provider_failure_fragment(component))
        .collect::<Vec<_>>();
    unhealthy_components.sort_unstable();
    unhealthy_components.dedup();
    if unhealthy_components.len() == 1 {
        format!("provider_health_{}", unhealthy_components[0])
    } else {
        "provider_health_incomplete".into()
    }
}

const fn process_failure_reason_code(error: &SemanticProviderProcessError) -> &'static str {
    match error {
        SemanticProviderProcessError::Timeout => "provider_process_timeout",
        SemanticProviderProcessError::Cancelled => "provider_process_cancelled",
        SemanticProviderProcessError::Exited
        | SemanticProviderProcessError::ProcessFailure { .. } => "provider_process_exited",
        SemanticProviderProcessError::ExecutableIdentityMismatch
        | SemanticProviderProcessError::TerminalIdentityMismatch => {
            "provider_process_identity_mismatch"
        }
        SemanticProviderProcessError::ToolchainIdentityMismatch => {
            "provider_toolchain_identity_mismatch"
        }
        SemanticProviderProcessError::Protocol(_) => "provider_protocol_invalid",
        SemanticProviderProcessError::Spawn(_) => "provider_process_spawn_failed",
        SemanticProviderProcessError::Filesystem(_) => "provider_filesystem_failed",
        SemanticProviderProcessError::InvalidConfiguration(_)
        | SemanticProviderProcessError::RuntimeConfigurationInvalid
        | SemanticProviderProcessError::LimitsMismatch => "provider_process_configuration_invalid",
        SemanticProviderProcessError::UnexpectedTerminal
        | SemanticProviderProcessError::UnexpectedHello => "provider_transition_invalid",
        SemanticProviderProcessError::Quarantined => "provider_process_quarantined",
        SemanticProviderProcessError::CloseFailed => "provider_process_close_failed",
    }
}

const fn bridge_failure_reason_code(error: &SemanticProviderBridgeError) -> &'static str {
    match error {
        SemanticProviderBridgeError::Protocol(_) => "provider_protocol_invalid",
        SemanticProviderBridgeError::CanonicalDocumentDecode(_)
        | SemanticProviderBridgeError::CanonicalAnalysis(_)
        | SemanticProviderBridgeError::CanonicalSnapshot(_)
        | SemanticProviderBridgeError::EmptyCertificationPopulation
        | SemanticProviderBridgeError::OverlappingCertificationPopulation
        | SemanticProviderBridgeError::OverlappingCertificationRoots => "provider_output_invalid",
        SemanticProviderBridgeError::ParentSnapshotMismatch
        | SemanticProviderBridgeError::ProviderLineageMismatch => "provider_authority_mismatch",
    }
}

const fn toolchain_failure_reason_code(error: &ToolchainResolutionError) -> &'static str {
    match error {
        ToolchainResolutionError::Cancelled => "provider_toolchain_resolution_cancelled",
        ToolchainResolutionError::UnsupportedLanguage(_) => "provider_toolchain_unsupported",
        ToolchainResolutionError::Invalid(_) => "provider_toolchain_invalid",
        ToolchainResolutionError::Resolution { .. } => "provider_toolchain_resolution_failed",
    }
}

/// One successfully admitted provider refresh lane. Exact reuse is modeled as
/// a distinct activity so an admitted refresh can never exist without its
/// payload-producing protocol operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticProviderAdmittedRefreshKind {
    Affected { documents: BTreeSet<String> },
    AffectedRoots { roots: BTreeSet<PathBuf> },
    Full,
}

#[derive(Clone)]
struct PreparedSource {
    identity: ProviderSourceIdentity,
    cross_document_surface_sha256: Option<String>,
    execution_root: PathBuf,
    bytes: Vec<u8>,
}

/// One unique immutable basis whose internal receipt, provider identity,
/// snapshot identity, and toolchain-bound authority agree. This is a
/// structurally valid candidate only; live authority admission still happens
/// separately before it may be attached.
struct ExactCanonicalBasisCandidate<'a> {
    basis: &'a CanonicalSemanticBasis,
    payload: &'a NormalizedProviderPayload,
}

struct RootSession {
    process: SemanticProviderProcess,
    toolchain: ResolvedToolchain,
    authority: ProviderAuthority,
    sources: BTreeMap<String, ProviderSourceIdentity>,
    semantic_inputs: ProviderSemanticInputs,
}

/// Whether the retained live provider processes cover the exact execution-root
/// population owned by the retained topology. A partial population is useful
/// repair state, but it cannot witness a complete immutable generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetainedSessionPopulation {
    Empty,
    Complete,
    RepairRequired,
}

struct PreparedEpochTransition {
    next_authority: ProviderAuthority,
    next_sources: BTreeMap<String, ProviderSourceIdentity>,
    changes: Vec<ProviderSourceChange>,
    attachments: Vec<Vec<u8>>,
}

struct AffectedRefreshRequest<'a> {
    repository_root: &'a Path,
    documents: &'a BTreeSet<String>,
    current_sources: &'a BTreeMap<String, PreparedSource>,
    root_topology_sha256: &'a BTreeMap<PathBuf, String>,
    indexed_sources: &'a [IndexedSourceEvidence],
    inventory: &'a ProjectInventory,
    cancellation: &'a IndexCancellation,
}

/// Bounded process-lifecycle telemetry from the most recent session-opening
/// population. It is operational evidence only; provider authority remains
/// bound by the admitted per-root terminals and immutable payload receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticProviderSessionOpenMetrics {
    pub execution_roots: usize,
    pub max_parallelism: usize,
    pub duration: Duration,
}

/// Exclusive work observed inside one persistent-provider refresh.
///
/// These timings are operational evidence only. They partition the coordinator
/// work that encloses provider RPCs, candidate admission, and terminal
/// recertification; they never participate in semantic authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticProviderRefreshTiming {
    pub label: &'static str,
    pub duration: Duration,
}

/// Coherent process-local activity from one provider lane. This is operational
/// evidence, not semantic authority: admitted payloads still require their
/// immutable capability receipt and publication boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticProviderActivity {
    Reused {
        session_open: Option<SemanticProviderSessionOpenMetrics>,
    },
    Admitted {
        refresh: SemanticProviderAdmittedRefreshKind,
        operation: ProviderOperation,
        session_open: Option<SemanticProviderSessionOpenMetrics>,
    },
    Failed {
        attempted_operations: Vec<ProviderOperation>,
        session_open: Option<SemanticProviderSessionOpenMetrics>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticProviderActivityRecord {
    pub activity: SemanticProviderActivity,
    pub timings: Vec<SemanticProviderRefreshTiming>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PendingProviderActivity {
    Reused,
    Admitted {
        refresh: SemanticProviderAdmittedRefreshKind,
        operation: ProviderOperation,
    },
    Failed,
}

#[derive(Debug, Default)]
struct ProviderActivityAttempt {
    attempted_operations: Vec<ProviderOperation>,
    session_open: Option<SemanticProviderSessionOpenMetrics>,
    outcome: Option<PendingProviderActivity>,
}

/// One language-neutral process/session coordinator retained by the serialized
/// index runner. Adapter policy owns language semantics; this type owns only
/// reuse, refresh, cancellation, and publication lifecycle state.
pub struct PersistentSemanticProviderCoordinator<P: SemanticProviderPolicy> {
    config: PersistentSemanticProviderConfig<P>,
    repository_root: Option<PathBuf>,
    topology_sha256: Option<String>,
    root_topology_sha256: BTreeMap<PathBuf, String>,
    sessions: BTreeMap<PathBuf, RootSession>,
    sources: BTreeMap<String, PreparedSource>,
    snapshot: Option<CanonicalScipSnapshot>,
    payload: Option<NormalizedProviderPayload>,
    supplemental_evidence: Vec<ScipArtifactEvidence>,
    source_syntax_cache: Option<CanonicalSourceSyntaxCache>,
    /// Coherent provider state that has not yet crossed the outer immutable
    /// generation publication boundary. It is disposable acceleration only
    /// and cannot authorize exact generation reuse by itself.
    publication_pending: bool,
    session_jobs: Option<usize>,
    activity_attempt: Option<ProviderActivityAttempt>,
    last_activity: Option<SemanticProviderActivityRecord>,
    last_refresh_timings: Vec<SemanticProviderRefreshTiming>,
}

impl<P: SemanticProviderPolicy> PersistentSemanticProviderCoordinator<P> {
    pub(crate) const fn from_config(config: PersistentSemanticProviderConfig<P>) -> Self {
        Self {
            config,
            repository_root: None,
            topology_sha256: None,
            root_topology_sha256: BTreeMap::new(),
            sessions: BTreeMap::new(),
            sources: BTreeMap::new(),
            snapshot: None,
            payload: None,
            supplemental_evidence: Vec::new(),
            source_syntax_cache: None,
            publication_pending: false,
            session_jobs: None,
            activity_attempt: None,
            last_activity: None,
            last_refresh_timings: Vec::new(),
        }
    }

    #[must_use]
    pub fn language(&self) -> &'static str {
        self.config.language()
    }

    fn retained_session_population(&self) -> RetainedSessionPopulation {
        if self.sessions.is_empty() {
            return RetainedSessionPopulation::Empty;
        }
        if !self.root_topology_sha256.is_empty()
            && self.sessions.len() == self.root_topology_sha256.len()
            && self.sessions.keys().eq(self.root_topology_sha256.keys())
        {
            RetainedSessionPopulation::Complete
        } else {
            RetainedSessionPopulation::RepairRequired
        }
    }

    #[must_use]
    pub fn ecosystem(&self) -> &'static str {
        self.config.ecosystem()
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.config.expected_identity.provider_id
    }

    #[must_use]
    pub fn operation_label(&self) -> &'static str {
        self.config.policy.operation_label()
    }

    fn begin_activity_attempt(&mut self) {
        self.activity_attempt = Some(ProviderActivityAttempt::default());
        self.last_activity = None;
        self.last_refresh_timings.clear();
    }

    fn ensure_activity_attempt(&mut self) {
        if self.activity_attempt.is_none() {
            self.begin_activity_attempt();
        }
    }

    fn record_operation_attempt(&mut self, operation: ProviderOperation) {
        self.ensure_activity_attempt();
        let attempt = self
            .activity_attempt
            .as_mut()
            .expect("activity attempt was initialized");
        if !attempt.attempted_operations.contains(&operation) {
            attempt.attempted_operations.push(operation);
        }
    }

    fn record_session_open(&mut self, metrics: Option<SemanticProviderSessionOpenMetrics>) {
        self.ensure_activity_attempt();
        self.activity_attempt
            .as_mut()
            .expect("activity attempt was initialized")
            .session_open = metrics;
    }

    fn mark_reused(&mut self) {
        self.ensure_activity_attempt();
        self.activity_attempt
            .as_mut()
            .expect("activity attempt was initialized")
            .outcome = Some(PendingProviderActivity::Reused);
    }

    fn mark_admitted(
        &mut self,
        refresh: SemanticProviderAdmittedRefreshKind,
        operation: ProviderOperation,
    ) -> Result<(), SemanticProviderError> {
        let expected = match &refresh {
            SemanticProviderAdmittedRefreshKind::Affected { .. } => {
                ProviderOperation::RefreshAffected
            }
            SemanticProviderAdmittedRefreshKind::AffectedRoots { .. }
            | SemanticProviderAdmittedRefreshKind::Full => ProviderOperation::CertifyFull,
        };
        if operation != expected {
            return Err(SemanticProviderError::InvalidTransition(
                "provider-activity-operation-mismatch",
            ));
        }
        self.ensure_activity_attempt();
        let attempt = self
            .activity_attempt
            .as_mut()
            .expect("activity attempt was initialized");
        if !attempt.attempted_operations.contains(&operation) {
            return Err(SemanticProviderError::InvalidTransition(
                "provider-activity-operation-not-attempted",
            ));
        }
        attempt.outcome = Some(PendingProviderActivity::Admitted { refresh, operation });
        Ok(())
    }

    fn store_activity(&mut self, activity: SemanticProviderActivity) {
        self.last_activity = Some(SemanticProviderActivityRecord {
            activity,
            timings: std::mem::take(&mut self.last_refresh_timings),
        });
    }

    fn finish_complete_activity(&mut self) -> Result<(), SemanticProviderError> {
        let attempt =
            self.activity_attempt
                .take()
                .ok_or(SemanticProviderError::InvalidTransition(
                    "provider-activity-attempt-missing",
                ))?;
        let activity = match attempt.outcome {
            Some(PendingProviderActivity::Reused) => SemanticProviderActivity::Reused {
                session_open: attempt.session_open,
            },
            Some(PendingProviderActivity::Admitted { refresh, operation }) => {
                SemanticProviderActivity::Admitted {
                    refresh,
                    operation,
                    session_open: attempt.session_open,
                }
            }
            Some(PendingProviderActivity::Failed) | None => {
                let activity = SemanticProviderActivity::Failed {
                    attempted_operations: attempt.attempted_operations,
                    session_open: attempt.session_open,
                };
                self.store_activity(activity);
                return Err(SemanticProviderError::InvalidTransition(
                    "provider-complete-activity-outcome-missing",
                ));
            }
        };
        self.store_activity(activity);
        Ok(())
    }

    fn finish_failed_activity(&mut self) {
        let Some(mut attempt) = self.activity_attempt.take() else {
            return;
        };
        attempt.outcome = Some(PendingProviderActivity::Failed);
        if attempt.attempted_operations.is_empty() && attempt.session_open.is_none() {
            self.last_activity = None;
            self.last_refresh_timings.clear();
            return;
        }
        self.store_activity(SemanticProviderActivity::Failed {
            attempted_operations: attempt.attempted_operations,
            session_open: attempt.session_open,
        });
    }

    /// Set the adapter-owned scheduling budget for the next serialized
    /// operation. This coordinate affects only disposable process overlap; it
    /// is deliberately excluded from semantic-provider identity and receipts.
    pub fn set_session_jobs(&mut self, jobs: Option<usize>) {
        self.session_jobs = jobs;
        self.begin_activity_attempt();
    }

    pub const fn take_last_activity(&mut self) -> Option<SemanticProviderActivityRecord> {
        self.last_activity.take()
    }

    fn record_refresh_timing(&mut self, label: &'static str, started: Instant) {
        self.push_refresh_timing(label, started.elapsed());
    }

    fn push_refresh_timing(&mut self, label: &'static str, duration: Duration) {
        self.last_refresh_timings
            .push(SemanticProviderRefreshTiming { label, duration });
    }

    /// Exact disposable compilation-cache partitions owned by live sessions.
    /// The publication pipeline protects these paths from post-run eviction;
    /// they remain accelerators rather than semantic authority.
    pub fn active_cache_directories(&self) -> BTreeSet<PathBuf> {
        self.sessions
            .values()
            .flat_map(|session| {
                self.config
                    .policy
                    .active_cache_directories(&self.config, &session.toolchain)
            })
            .collect()
    }

    /// Admit exact semantic-generation reuse only after a live provider
    /// session establishes the persisted payload's exact configuration,
    /// source population, topology, and non-source semantic inputs. A retained
    /// session may prove that directly; a fresh process may perform the
    /// bounded `OpenSession` handshake, but persisted receipts alone never
    /// authorize reuse.
    pub async fn authorizes_exact_generation_reuse<Payload: AsRef<ProviderPayload> + Sync>(
        &mut self,
        repository_root: &Path,
        inventory: &ProjectInventory,
        indexed_sources: &[IndexedSourceEvidence],
        provider_payloads: &[Payload],
        cancellation: &IndexCancellation,
    ) -> bool {
        self.ensure_activity_attempt();
        let current_root = canonical_utf8_directory(repository_root).ok();
        let current_topology = self.config.inventory_fingerprint(inventory).ok();
        let mut complete_calls = provider_payloads.iter().filter(|payload| {
            payload.as_ref().receipt().capability_id == "calls"
                && payload.as_ref().receipt().status == CapabilityStatus::Complete
                && payload.as_ref().receipt().provider_id.0
                    == self.config.expected_identity.provider_id
        });
        let exact_payload = complete_calls
            .next()
            .and_then(|payload| match payload.as_ref() {
                ProviderPayload::Calls(payload)
                    if matches!(
                        &payload.execution_authority,
                        ProviderExecutionAuthority::ToolchainBound { .. }
                    ) =>
                {
                    Some(payload)
                }
                _ => None,
            });
        let current_sources = current_root.as_ref().and_then(|repository_root| {
            let requested_roots = self
                .config
                .execution_roots(inventory)
                .into_iter()
                .map(|relative| repository_root.join(relative))
                .collect::<Vec<_>>();
            let execution_roots =
                canonical_execution_roots(repository_root, &requested_roots).ok()?;
            self.config
                .prepare_sources(
                    repository_root,
                    &execution_roots,
                    indexed_sources,
                    inventory,
                )
                .ok()
        });
        let current_source_epoch_matches_retained = current_sources
            .as_ref()
            .is_some_and(|sources| prepared_source_populations_match(&self.sources, sources));
        let published_payload_matches_current_sources =
            current_sources.as_ref().is_some_and(|sources| {
                exact_payload
                    .as_ref()
                    .is_some_and(|payload| payload_documents_match_sources(payload, sources))
            });
        let complete_calls_unique = complete_calls.next().is_none();
        let retained_session_population = self.retained_session_population();
        let state_matches = current_root.as_ref() == self.repository_root.as_ref()
            && current_topology.as_deref() == self.topology_sha256.as_deref()
            && exact_payload.as_ref().is_some_and(|payload| {
                self.payload
                    .as_ref()
                    .is_some_and(|retained| calls_payload_from_normalized(retained) == *payload)
            })
            && current_source_epoch_matches_retained
            && published_payload_matches_current_sources
            && complete_calls_unique
            && retained_session_population == RetainedSessionPopulation::Complete;
        if state_matches {
            if let Err(error) = self.session_toolchains_are_current(cancellation).await {
                if is_provider_cancellation(&error) {
                    return false;
                }
                self.reset().await;
                return false;
            }
            if let Err(error) = self.probe_session_runtime_authority(cancellation).await {
                if is_provider_cancellation(&error) {
                    return false;
                }
                return false;
            }
            match self.session_semantic_inputs_are_current(
                current_root
                    .as_deref()
                    .expect("matching provider state has a canonical repository root"),
            ) {
                Ok(true) => {
                    self.publication_pending = false;
                    return true;
                }
                Ok(false) | Err(_) => self.reset().await,
            }
        }

        // A quarantined subset is intentionally retained for the refresh
        // transaction that owns root repair. It cannot witness a complete
        // persisted generation, and this read/admission boundary must neither
        // probe the subset as though it were complete nor replace it through a
        // fresh recertification side path.
        if retained_session_population == RetainedSessionPopulation::RepairRequired {
            return false;
        }

        // Exact-basis admission is a read/refusal boundary, not the owner of a
        // successor provider epoch. Preserve a coherent process-local session
        // when current source bytes have advanced; the subsequent refresh
        // re-resolves toolchains, validates the changed population, and owns
        // the affected/full transition. Policies may additionally support
        // root-local topology refresh and a coherent candidate whose provider
        // refresh completed before outer publication was cancelled. No
        // authority is granted here. Fresh-process reconstruction remains
        // fail-closed because it has no live snapshot/session basis.
        let process_local_candidate_is_coherent = self.payload.as_ref().is_some_and(|payload| {
            payload_documents_match_sources(calls_payload_from_normalized(payload), &self.sources)
        });
        let retained_payload_matches_published = exact_payload.as_ref().is_some_and(|payload| {
            self.payload
                .as_ref()
                .is_some_and(|retained| calls_payload_from_normalized(retained) == *payload)
        });
        let source_epoch_changed = current_sources.is_some()
            && !current_source_epoch_matches_retained
            && !published_payload_matches_current_sources;
        tracing::debug!(
            language = self.config.language(),
            same_repository = current_root.as_ref() == self.repository_root.as_ref(),
            topology_changed = current_topology.as_deref() != self.topology_sha256.as_deref(),
            publication_pending = self.publication_pending,
            persisted_payload_present = exact_payload.is_some(),
            retained_payload_matches_published,
            complete_calls_unique,
            snapshot_present = self.snapshot.is_some(),
            retained_sessions = self.sessions.len(),
            retained_root_topologies = self.root_topology_sha256.len(),
            current_sources_present = current_sources.is_some(),
            source_epoch_changed,
            process_local_candidate_is_coherent,
            "evaluated process-local semantic refresh retention"
        );
        let process_local_refresh = current_root.as_ref() == self.repository_root.as_ref()
            && (source_epoch_changed
                || (self
                    .config
                    .policy
                    .lifecycle_policy()
                    .supports_root_local_refresh()
                    && (current_topology.as_deref() != self.topology_sha256.as_deref()
                        || self.publication_pending)))
            && exact_payload.is_some()
            && (retained_payload_matches_published || self.publication_pending)
            && complete_calls_unique
            && self.snapshot.is_some()
            && !self.sessions.is_empty()
            && !self.root_topology_sha256.is_empty()
            && current_sources.is_some()
            && process_local_candidate_is_coherent;
        if process_local_refresh {
            return false;
        }

        let Some(exact_payload) = exact_payload else {
            self.reset().await;
            return false;
        };
        let exact_payload = match normalize_provider_payload_typed(&ProviderPayload::Calls(
            exact_payload.clone(),
        )) {
            Ok(payload) => payload,
            Err(_) => {
                self.reset().await;
                return false;
            }
        };
        let Some(current_sources) = current_sources else {
            self.reset().await;
            return false;
        };
        let recertification = self
            .recertify_persisted_generation(
                repository_root,
                inventory,
                indexed_sources,
                current_sources,
                exact_payload,
                cancellation,
            )
            .await;
        match recertification {
            Ok(()) => true,
            Err(error) => {
                tracing::debug!(
                    language = self.config.language(),
                    %error,
                    "fresh semantic authority recertification refused"
                );
                self.reset().await;
                false
            }
        }
    }

    fn exact_canonical_basis_candidate<'a>(
        &self,
        prior_bases: &'a [CanonicalSemanticBasis],
    ) -> Option<ExactCanonicalBasisCandidate<'a>> {
        let mut candidates = prior_bases.iter().filter(|basis| {
            basis.evidence.language_id.0 == self.config.language()
                && basis.snapshot.provider_id() == self.config.expected_identity.provider_id
        });
        let basis = candidates.next()?;
        if candidates.next().is_some()
            || basis.evidence.receipt.status != CapabilityStatus::Complete
            || basis.evidence.receipt.provider_id.0 != self.config.expected_identity.provider_id
        {
            return None;
        }
        let payload = basis.evidence.payload.as_ref()?;
        let ProviderPayload::Calls(calls) = payload.payload() else {
            return None;
        };
        if calls.receipt != basis.evidence.receipt
            || calls.receipt.provider_version.as_deref()
                != Some(basis.snapshot.executed_provider_version())
            || calls.canonical_snapshot_sha256.as_deref()
                != Some(basis.snapshot.identity_sha256().as_str())
            || !matches!(
                calls.execution_authority,
                ProviderExecutionAuthority::ToolchainBound { .. }
            )
        {
            return None;
        }
        Some(ExactCanonicalBasisCandidate { basis, payload })
    }

    /// Re-admit one exact canonical provider snapshot only after the coordinator's
    /// live authority checks approve the immutable payload that seals it.
    /// Cache bytes remain disposable acceleration: a missing, duplicate,
    /// mismatched, or stale basis simply falls back to provider refresh.
    pub async fn reuse_exact_canonical_basis(
        &mut self,
        repository_root: &Path,
        inventory: &ProjectInventory,
        indexed_sources: &[IndexedSourceEvidence],
        prior_bases: &[CanonicalSemanticBasis],
        cancellation: &IndexCancellation,
    ) -> Option<ScipArtifactSetNormalization> {
        self.ensure_activity_attempt();
        let candidate = self.exact_canonical_basis_candidate(prior_bases)?;
        if !self
            .authorizes_exact_generation_reuse(
                repository_root,
                inventory,
                indexed_sources,
                std::slice::from_ref(candidate.payload),
                cancellation,
            )
            .await
        {
            return None;
        }
        let normalization = self.attach_authorized_exact_canonical_basis(candidate)?;
        self.mark_reused();
        if self.finish_complete_activity().is_err() {
            return None;
        }
        Some(normalization)
    }

    /// Prove exact persisted semantic authority and opportunistically hydrate
    /// its disposable canonical basis into this coordinator. Generation reuse
    /// never depends on cache presence, but priming it here prevents the first
    /// post-restart source edit from reparsing every unchanged document.
    pub async fn authorize_and_hydrate_exact_generation_reuse<
        Payload: AsRef<ProviderPayload> + Sync,
    >(
        &mut self,
        repository_root: &Path,
        inventory: &ProjectInventory,
        indexed_sources: &[IndexedSourceEvidence],
        provider_payloads: &[Payload],
        prior_bases: &[CanonicalSemanticBasis],
        cancellation: &IndexCancellation,
    ) -> bool {
        self.ensure_activity_attempt();
        let Some(candidate) = self.exact_canonical_basis_candidate(prior_bases) else {
            return false;
        };
        if !self
            .authorizes_exact_generation_reuse(
                repository_root,
                inventory,
                indexed_sources,
                provider_payloads,
                cancellation,
            )
            .await
        {
            return false;
        }
        let attached = self
            .attach_authorized_exact_canonical_basis(candidate)
            .is_some();
        if attached && self.source_syntax_cache.is_none() && !cancellation.is_cancelled() {
            // Cross-process cache storage contains only the canonical provider
            // snapshot whose identity is bound into immutable publication.
            // Rebuild syntax acceleration from independently verified current
            // bytes instead of trusting unbound parse structures from disk.
            if let Ok(cache) = build_canonical_source_syntax_cache(
                repository_root,
                self.config.language(),
                indexed_sources,
                inventory,
            ) && !cancellation.is_cancelled()
            {
                self.source_syntax_cache = Some(cache);
            }
        }
        // Cache absence remains an acceleration miss, not semantic authority.
        self.mark_reused();
        if self.finish_complete_activity().is_err() {
            self.reset().await;
            return false;
        }
        true
    }

    fn attach_authorized_exact_canonical_basis(
        &mut self,
        candidate: ExactCanonicalBasisCandidate<'_>,
    ) -> Option<ScipArtifactSetNormalization> {
        if self.payload.as_ref() != Some(candidate.payload) {
            return None;
        }
        self.snapshot = Some(candidate.basis.snapshot.clone());
        self.supplemental_evidence = candidate.basis.supplemental_evidence.clone();
        if let Some(candidate_cache) = candidate.basis.source_syntax_cache.as_ref() {
            self.source_syntax_cache = Some(candidate_cache.clone());
        }
        self.publication_pending = false;
        Some(ScipArtifactSetNormalization {
            evidence: candidate.basis.evidence.clone(),
            supplemental_evidence: candidate.basis.supplemental_evidence.clone(),
            canonical_snapshot: Some(candidate.basis.snapshot.clone()),
            source_syntax_cache: self.source_syntax_cache.clone(),
            timings: Default::default(),
        })
    }

    async fn recertify_persisted_generation(
        &mut self,
        repository_root: &Path,
        inventory: &ProjectInventory,
        indexed_sources: &[IndexedSourceEvidence],
        current_sources: BTreeMap<String, PreparedSource>,
        payload: NormalizedProviderPayload,
        cancellation: &IndexCancellation,
    ) -> Result<(), SemanticProviderError> {
        self.reset_runtime_authority().await;
        let ProviderPayload::Calls(calls) = payload.payload() else {
            return Err(SemanticProviderError::InvalidTransition(
                "persisted-provider-capability",
            ));
        };
        if calls.receipt.provider_id.0 != self.config.expected_identity.provider_id
            || calls.receipt.provider_version.as_deref()
                != Some(
                    self.config
                        .expected_identity
                        .implementation_version
                        .as_str(),
                )
        {
            return Err(SemanticProviderError::InvalidTransition(
                "persisted-provider-identity",
            ));
        }
        let current_implementation = provider_identity_sha256(&self.config.expected_identity)?;
        let (persisted_provider_inventory_sha256, persisted_roots) = {
            let ProviderExecutionAuthority::ToolchainBound {
                resolver_policy_id,
                ecosystem_id,
                reuse_contract_id,
                provider_implementation_sha256,
                provider_inventory_sha256,
                roots,
            } = &calls.execution_authority
            else {
                return Err(SemanticProviderError::InvalidTransition(
                    "persisted-execution-authority",
                ));
            };
            let current_resolver_policy_id = self
                .config
                .toolchain_resolver
                .policy_id(self.config.language())?;
            if resolver_policy_id != current_resolver_policy_id
                || ecosystem_id.0 != self.config.ecosystem()
                || reuse_contract_id != self.config.reuse_contract_id()
                || provider_implementation_sha256 != &current_implementation
            {
                return Err(SemanticProviderError::InvalidTransition(
                    "persisted-reuse-contract",
                ));
            }
            (provider_inventory_sha256.clone(), roots.clone())
        };
        let repository_root = canonical_utf8_directory(repository_root)?;
        let requested_roots = self
            .config
            .execution_roots(inventory)
            .into_iter()
            .map(|relative| repository_root.join(relative))
            .collect::<Vec<_>>();
        let execution_roots = canonical_execution_roots(&repository_root, &requested_roots)?;
        let current_toolchains = self
            .resolve_toolchains(&execution_roots, cancellation)
            .await?;
        if !payload_documents_match_sources(calls, &current_sources) {
            return Err(SemanticProviderError::InvalidTransition(
                "persisted-source-population",
            ));
        }
        let topology_sha256 = self.config.inventory_fingerprint(inventory)?;
        let root_topology_sha256 = self.config.execution_root_inventory_fingerprints(
            &repository_root,
            &execution_roots,
            inventory,
            &topology_sha256,
        )?;
        if topology_sha256 != persisted_provider_inventory_sha256 {
            return Err(SemanticProviderError::InvalidTransition(
                "persisted-provider-inventory",
            ));
        }
        if self
            .reconstruct_closed_generation(
                &repository_root,
                inventory,
                indexed_sources,
                &execution_roots,
                &current_sources,
                &current_toolchains,
                &persisted_roots,
                &calls.execution_authority,
                cancellation,
            )
            .await?
        {
            self.repository_root = Some(repository_root);
            self.topology_sha256 = Some(topology_sha256);
            self.root_topology_sha256 = root_topology_sha256;
            self.sources = current_sources;
            self.payload = Some(payload);
            self.supplemental_evidence.clear();
            self.snapshot = None;
            self.publication_pending = false;
            return Ok(());
        }
        self.open_sessions(
            &repository_root,
            &current_sources,
            current_toolchains,
            &root_topology_sha256,
            inventory,
            cancellation,
        )
        .await?;

        let observed_authority = self.execution_authority(&repository_root, inventory)?;
        if observed_authority != calls.execution_authority
            || combined_semantic_inputs(&self.sessions)? != calls.semantic_inputs
        {
            return Err(SemanticProviderError::InvalidTransition(
                "recertified-generation-authority",
            ));
        }
        self.session_toolchains_are_current(cancellation).await?;
        self.probe_session_runtime_authority(cancellation).await?;
        if !self.session_semantic_inputs_are_current(&repository_root)? {
            return Err(SemanticProviderError::InvalidTransition(
                "recertified-semantic-input-drift",
            ));
        }
        let terminal_sources = self.config.prepare_sources(
            &repository_root,
            &execution_roots,
            indexed_sources,
            inventory,
        )?;
        if !prepared_source_populations_match(&current_sources, &terminal_sources) {
            return Err(SemanticProviderError::InvalidTransition(
                "recertified-source-drift",
            ));
        }

        self.repository_root = Some(repository_root);
        self.topology_sha256 = Some(topology_sha256);
        self.root_topology_sha256 = root_topology_sha256;
        self.sources = current_sources;
        self.payload = Some(payload);
        self.supplemental_evidence.clear();
        self.snapshot = None;
        self.publication_pending = false;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn reconstruct_closed_generation(
        &self,
        repository_root: &Path,
        inventory: &ProjectInventory,
        indexed_sources: &[IndexedSourceEvidence],
        execution_roots: &[PathBuf],
        current_sources: &BTreeMap<String, PreparedSource>,
        current_toolchains: &BTreeMap<PathBuf, ResolvedToolchain>,
        persisted_roots: &[ProviderExecutionRootAuthority],
        persisted_authority: &ProviderExecutionAuthority,
        cancellation: &IndexCancellation,
    ) -> Result<bool, SemanticProviderError> {
        // Closed-generation reconstruction is an adapter capability, not a
        // lifecycle language branch. Adapters without an independently proven
        // closed reconstruction contract must open the real provider session.
        if inventory.coverage_for_provider(
            &LanguageId::new(self.config.policy.language()),
            &EcosystemId::new(self.config.policy.ecosystem()),
        ) != ProjectInventoryCoverage::IndexedSourcePopulationComplete
            || persisted_roots.len() != execution_roots.len()
            || !self
                .config
                .policy
                .closed_generation_inputs_are_reconstructable(
                    repository_root,
                    inventory,
                    execution_roots,
                )
        {
            return Ok(false);
        }

        let limits = ProviderFrameLimits::default();
        let mut configurations = BTreeMap::new();
        let mut reconstructions = BTreeMap::new();
        for root in persisted_roots {
            let ProviderGenerationReconstruction::ObservedWorkspace {
                runtime_configuration_sha256,
                workspace_resolution_sha256,
                semantic_inputs,
            } = &root.generation_reconstruction
            else {
                return Ok(false);
            };
            if semantic_inputs.coverage != ProviderSemanticInputCoverage::Complete {
                return Ok(false);
            }
            let execution_root = repository_root.join(&root.execution_root);
            let toolchain = current_toolchains
                .get(&execution_root)
                .ok_or(SemanticProviderError::ToolchainBindingMismatch)?;
            let environment = self.config.process_config(toolchain).environment;
            if !provider_semantic_inputs_are_current_in_environment(
                repository_root,
                semantic_inputs,
                &environment,
                &limits,
            )? {
                return Err(SemanticProviderError::InvalidTransition(
                    "reconstructed-semantic-input-drift",
                ));
            }
            let semantic_inputs_sha256 = provider_semantic_inputs_sha256(semantic_inputs, &limits)?;
            let resolved_configuration = resolved_workspace_configuration_sha256(
                runtime_configuration_sha256,
                workspace_resolution_sha256,
                &semantic_inputs_sha256,
            )?;
            let provider_configuration =
                provider_configuration_sha256(&self.config, &resolved_configuration)?;
            if configurations
                .insert(root.execution_root.clone(), provider_configuration)
                .is_some()
                || reconstructions
                    .insert(
                        root.execution_root.clone(),
                        root.generation_reconstruction.clone(),
                    )
                    .is_some()
            {
                return Err(SemanticProviderError::InvalidTransition(
                    "reconstructed-root-population",
                ));
            }
        }

        let implementation = provider_identity_sha256(&self.config.expected_identity)?;
        let resolver_policy_id = self
            .config
            .toolchain_resolver
            .policy_id(self.config.language())?;
        let observed_authority =
            toolchain_bound_execution_authority(ToolchainBoundAuthorityInput {
                repository_root,
                inventory,
                language: self.config.language(),
                ecosystem: self.config.ecosystem(),
                resolver_policy_id,
                reuse_contract_id: self.config.reuse_contract_id(),
                provider_implementation_sha256: &implementation,
                provider_configurations_sha256: &configurations,
                reconstruction_descriptors: Some(&reconstructions),
                toolchains: current_toolchains,
            })?;
        if &observed_authority != persisted_authority {
            return Err(SemanticProviderError::InvalidTransition(
                "reconstructed-generation-authority",
            ));
        }

        for execution_root in execution_roots {
            if cancellation.is_cancelled() {
                return Err(SemanticProviderProcessError::Cancelled.into());
            }
            let prefix = execution_prefix(repository_root, execution_root)?;
            let root = persisted_roots
                .iter()
                .find(|root| root.execution_root == prefix)
                .ok_or(SemanticProviderError::InvalidTransition(
                    "reconstructed-runtime-root",
                ))?;
            let ProviderGenerationReconstruction::ObservedWorkspace {
                runtime_configuration_sha256,
                ..
            } = &root.generation_reconstruction
            else {
                return Ok(false);
            };
            let toolchain = current_toolchains
                .get(execution_root)
                .ok_or(SemanticProviderError::ToolchainBindingMismatch)?;
            let process =
                SemanticProviderProcess::spawn(self.config.process_config(toolchain)).await?;
            let runtime_matches = process.runtime_configuration().configuration_sha256
                == *runtime_configuration_sha256;
            process.close().await?;
            if !runtime_matches {
                return Err(SemanticProviderError::InvalidTransition(
                    "reconstructed-runtime-configuration",
                ));
            }
        }

        let terminal_toolchains = self
            .resolve_toolchains(execution_roots, cancellation)
            .await?;
        if &terminal_toolchains != current_toolchains {
            return Err(SemanticProviderError::ToolchainChanged);
        }
        let terminal_sources = self.config.prepare_sources(
            repository_root,
            execution_roots,
            indexed_sources,
            inventory,
        )?;
        if !prepared_source_populations_match(current_sources, &terminal_sources) {
            return Err(SemanticProviderError::InvalidTransition(
                "reconstructed-source-drift",
            ));
        }
        let terminal_inventory_sources = indexed_sources
            .iter()
            .map(|source| InventorySource::new(&source.relative_path, &source.language))
            .collect::<Vec<_>>();
        if build_project_inventory(repository_root, &terminal_inventory_sources) != *inventory {
            return Err(SemanticProviderError::InvalidTransition(
                "reconstructed-project-input-drift",
            ));
        }
        for root in persisted_roots {
            let ProviderGenerationReconstruction::ObservedWorkspace {
                semantic_inputs, ..
            } = &root.generation_reconstruction
            else {
                return Ok(false);
            };
            let execution_root = repository_root.join(&root.execution_root);
            let toolchain = terminal_toolchains
                .get(&execution_root)
                .ok_or(SemanticProviderError::ToolchainBindingMismatch)?;
            let environment = self.config.process_config(toolchain).environment;
            if !provider_semantic_inputs_are_current_in_environment(
                repository_root,
                semantic_inputs,
                &environment,
                &limits,
            )? {
                return Err(SemanticProviderError::InvalidTransition(
                    "reconstructed-terminal-semantic-input-drift",
                ));
            }
        }
        Ok(true)
    }

    /// Reconcile one exact source epoch and return canonical evidence for the
    /// ordinary graph/payload projection lane.
    pub async fn refresh(
        &mut self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        indexed_sources: &[IndexedSourceEvidence],
        inventory: &ProjectInventory,
        cancellation: &IndexCancellation,
    ) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
        self.ensure_activity_attempt();
        let result = self
            .refresh_inner(
                repository_root,
                execution_roots,
                indexed_sources,
                inventory,
                cancellation,
            )
            .await;
        let normalization = match result {
            Ok(normalization) => normalization,
            Err(SemanticProviderError::PriorAuthorityPreserved { source }) => {
                self.finish_failed_activity();
                return Err(*source);
            }
            Err(error) => {
                self.finish_failed_activity();
                self.reset().await;
                return Err(error);
            }
        };
        let complete = normalization.evidence.receipt.status == CapabilityStatus::Complete;
        if !self.sessions.is_empty() {
            let started = Instant::now();
            let result = self.session_toolchains_are_current(cancellation).await;
            self.record_refresh_timing("terminal toolchain authority", started);
            if let Err(error) = result {
                self.finish_failed_activity();
                if !is_provider_cancellation(&error) {
                    self.reset().await;
                }
                return Err(error);
            }
        }
        // An admitted affected-refresh terminal already carries the provider's
        // exact post-work runtime observation. Other lanes still require a
        // dedicated terminal probe because their response shape predates that
        // witnessed transaction.
        if !self.sessions.is_empty()
            && !matches!(
                self.activity_attempt
                    .as_ref()
                    .and_then(|attempt| attempt.outcome.as_ref()),
                Some(PendingProviderActivity::Admitted {
                    refresh: SemanticProviderAdmittedRefreshKind::Affected { .. },
                    ..
                })
            )
        {
            let started = Instant::now();
            let result = self.probe_session_runtime_authority(cancellation).await;
            self.record_refresh_timing("terminal runtime authority", started);
            if let Err(error) = result {
                self.finish_failed_activity();
                return Err(error);
            }
        }
        // Provider-local checks bracket the exact compiler work. This common
        // terminal owns the cross-process publication boundary: every
        // reproducible input manifest must still match after full, affected,
        // or reused work. Providers that explicitly report an unverifiable
        // input population retain that bounded limitation instead of turning
        // an impossible re-observation into false authority.
        if !self.sessions.is_empty() {
            let started = Instant::now();
            let result = self.session_semantic_inputs_are_current(repository_root);
            self.record_refresh_timing("terminal semantic-input authority", started);
            match result {
                Ok(true) => {}
                Ok(false) => {
                    self.finish_failed_activity();
                    self.reset().await;
                    return Err(SemanticProviderError::InvalidTransition(
                        "terminal-semantic-input-drift",
                    ));
                }
                Err(error) => {
                    self.finish_failed_activity();
                    self.reset().await;
                    return Err(error);
                }
            }
        }
        if complete {
            if let Err(error) = self.finish_complete_activity() {
                self.reset().await;
                return Err(error);
            }
        } else {
            self.finish_failed_activity();
        }
        Ok(normalization)
    }

    /// Close every owned child and discard all acceleration state.
    pub async fn reset(&mut self) {
        let sessions = std::mem::take(&mut self.sessions);
        for session in sessions.into_values() {
            let _ = session.process.close().await;
        }
        self.repository_root = None;
        self.topology_sha256 = None;
        self.root_topology_sha256.clear();
        self.sources.clear();
        self.snapshot = None;
        self.payload = None;
        self.supplemental_evidence.clear();
        self.source_syntax_cache = None;
        self.publication_pending = false;
    }

    /// Reset provider-process authority while retaining byte-addressed local
    /// syntax acceleration. A reconstructed provider session must re-prove
    /// toolchain, topology, semantic inputs, and source bytes independently;
    /// the retained cache can only avoid reparsing a document after those
    /// exact current bytes match its BLAKE3, SHA-256, and length coordinates.
    async fn reset_runtime_authority(&mut self) {
        let source_syntax_cache = self.source_syntax_cache.take();
        self.reset().await;
        self.source_syntax_cache = source_syntax_cache;
    }

    async fn refresh_inner(
        &mut self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        indexed_sources: &[IndexedSourceEvidence],
        inventory: &ProjectInventory,
        cancellation: &IndexCancellation,
    ) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
        if cancellation.is_cancelled() {
            return Err(SemanticProviderError::PriorAuthorityPreserved {
                source: Box::new(SemanticProviderProcessError::Cancelled.into()),
            });
        }
        let root_validation_started = Instant::now();
        let repository_root = canonical_utf8_directory(repository_root)?;
        let execution_roots = canonical_execution_roots(&repository_root, execution_roots)?;
        self.record_refresh_timing(
            "request root and execution-root validation",
            root_validation_started,
        );
        let toolchain_resolution_started = Instant::now();
        let current_toolchains = self
            .resolve_toolchains(&execution_roots, cancellation)
            .await;
        self.record_refresh_timing("current toolchain resolution", toolchain_resolution_started);
        let current_toolchains = match current_toolchains {
            Ok(toolchains) => toolchains,
            Err(error) if is_provider_cancellation(&error) => {
                return Err(SemanticProviderError::PriorAuthorityPreserved {
                    source: Box::new(error),
                });
            }
            Err(error) => return Err(error),
        };
        let source_epoch_started = Instant::now();
        let current_sources = self.config.prepare_sources(
            &repository_root,
            &execution_roots,
            indexed_sources,
            inventory,
        )?;
        let topology_sha256 = self.config.inventory_fingerprint(inventory)?;
        let root_topology_sha256 = self.config.execution_root_inventory_fingerprints(
            &repository_root,
            &execution_roots,
            inventory,
            &topology_sha256,
        )?;
        let reload_sensitive_documents = self
            .config
            .reload_sensitive_documents(&repository_root, inventory)?;
        let reload_sensitive_source_changed = reload_sensitive_documents.iter().any(|path| {
            self.sources
                .get(path)
                .zip(current_sources.get(path))
                .is_some_and(|(previous, current)| previous.identity != current.identity)
        });
        let source_changed_documents =
            source_changed_documents_by_execution_root(&self.sources, &current_sources);
        self.record_refresh_timing(
            "source epoch and topology materialization",
            source_epoch_started,
        );

        // An affected provider transaction carries its own terminal runtime
        // witness, so it does not need a speculative Hello first. It still
        // cannot repair a boot that was already dead when planning began:
        // observe exact owned child state locally and remove only terminals
        // that the OS has already witnessed. This is not positive authority;
        // live roots continue through the ordinary provider transaction or
        // independent runtime preflight below.
        let local_exit_started = Instant::now();
        self.discard_observed_exited_sessions()?;
        self.record_refresh_timing("local provider exit observation", local_exit_started);

        // A forced reconciliation bypasses exact-generation reuse, so probe
        // the retained provider here as well. Any toolchain, Cargo build-input,
        // generated-output, or proc-macro drift discards the warm session and
        // recertifies in this same operation instead of returning a stale
        // in-memory snapshot or parking WATCH on a failed epoch.
        let retained_local_topology_changed = self
            .config
            .policy
            .lifecycle_policy()
            .supports_root_local_refresh()
            && self.repository_root.as_ref() == Some(&repository_root)
            && self.root_topology_sha256 != root_topology_sha256;
        if !self.sessions.is_empty() && !retained_local_topology_changed {
            let session_roots_are_retained = self
                .sessions
                .keys()
                .all(|root| execution_roots.contains(root));
            if session_roots_are_retained {
                // A changed root whose documents are disjoint from its exact
                // semantic-input manifest must cross a subsequent provider
                // transaction, and that terminal carries the runtime witness.
                // Cargo build/proc-macro inputs and untouched siblings still
                // require this independent proof: their change invalidates
                // the retained session before any affected-source terminal
                // can authorize it.
                let preflight_roots =
                    self.retained_runtime_preflight_roots(&source_changed_documents);
                if !preflight_roots.is_empty() {
                    let preflight_started = Instant::now();
                    let preflight = self
                        .probe_session_runtime_authority_for_roots(&preflight_roots, cancellation)
                        .await;
                    self.record_refresh_timing(
                        "retained session runtime preflight",
                        preflight_started,
                    );
                    match preflight {
                        Ok(()) if !cancellation.is_cancelled() => {}
                        Ok(()) => {
                            return Err(SemanticProviderError::PriorAuthorityPreserved {
                                source: Box::new(SemanticProviderProcessError::Cancelled.into()),
                            });
                        }
                        Err(error) if is_provider_cancellation(&error) => {
                            return Err(SemanticProviderError::PriorAuthorityPreserved {
                                source: Box::new(error),
                            });
                        }
                        // The probe already quarantined only the failed roots
                        // and continued through every healthy sibling. A
                        // policy with root-local refresh can repair exactly
                        // that population; other policies fall through to
                        // full recertification.
                        Err(_) => {}
                    }
                }
            } else {
                self.reset().await;
            }
        }

        let current_root_population = execution_roots.iter().cloned().collect::<BTreeSet<_>>();
        let session_root_population = self.sessions.keys().cloned().collect::<BTreeSet<_>>();
        let root_topology_population = self
            .root_topology_sha256
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let can_localize_roots = self
            .config
            .policy
            .lifecycle_policy()
            .supports_root_local_refresh()
            && self.repository_root.as_ref() == Some(&repository_root)
            && current_root_population == root_topology_population
            && session_root_population.is_subset(&current_root_population)
            && self.snapshot.is_some()
            && self.payload.is_some()
            && !reload_sensitive_source_changed;
        if can_localize_roots {
            let affected_roots = execution_roots
                .iter()
                .filter(|root| {
                    let prior_paths = self
                        .sources
                        .values()
                        .filter(|source| source.execution_root == **root)
                        .map(|source| source.identity.document_path.as_str())
                        .collect::<BTreeSet<_>>();
                    let current_paths = current_sources
                        .values()
                        .filter(|source| source.execution_root == **root)
                        .map(|source| source.identity.document_path.as_str())
                        .collect::<BTreeSet<_>>();
                    self.root_topology_sha256.get(*root) != root_topology_sha256.get(*root)
                        || self
                            .sessions
                            .get(*root)
                            .zip(current_toolchains.get(*root))
                            .is_none_or(|(session, toolchain)| session.toolchain != *toolchain)
                        || prior_paths != current_paths
                })
                .cloned()
                .collect::<BTreeSet<_>>();
            if !affected_roots.is_empty() {
                return self
                    .refresh_affected_execution_roots(
                        repository_root,
                        execution_roots,
                        affected_roots,
                        current_sources,
                        current_toolchains,
                        topology_sha256,
                        root_topology_sha256,
                        indexed_sources,
                        inventory,
                        cancellation,
                    )
                    .await;
            }
        }
        let requires_new_sessions = self.repository_root.as_ref() != Some(&repository_root)
            || self.topology_sha256.as_deref() != Some(topology_sha256.as_str())
            || self.root_topology_sha256 != root_topology_sha256
            || current_root_population != session_root_population
            || current_toolchains.iter().any(|(root, toolchain)| {
                self.sessions
                    .get(root)
                    .is_none_or(|session| session.toolchain != *toolchain)
            })
            || self.snapshot.is_none()
            || self.payload.is_none()
            || self.sources.keys().collect::<BTreeSet<_>>()
                != current_sources.keys().collect::<BTreeSet<_>>()
            || reload_sensitive_source_changed;
        if requires_new_sessions {
            self.reset().await;
            return self
                .open_and_certify_full(
                    repository_root,
                    execution_roots,
                    current_sources,
                    current_toolchains,
                    topology_sha256,
                    indexed_sources,
                    inventory,
                    cancellation,
                )
                .await;
        }

        let refresh_plan_started = Instant::now();
        let changes = semantic_changes(&self.sources, &current_sources)?;
        let plan = plan_semantic_refresh(&SemanticRefreshInput {
            exact_prior_authority: true,
            provider_identity_unchanged: true,
            provider_configuration_unchanged: true,
            affected_document_languages: BTreeSet::from([LanguageId::new(self.config.language())]),
            changes,
        });
        self.record_refresh_timing("semantic refresh planning", refresh_plan_started);
        match plan {
            SemanticRefreshPlan::ReuseExactPrior => {
                let snapshot = self
                    .snapshot
                    .clone()
                    .ok_or(SemanticProviderError::IncompleteFullCertification)?;
                let payload = self
                    .payload
                    .clone()
                    .ok_or(SemanticProviderError::IncompleteFullCertification)?;
                let calls = calls_payload_from_normalized(&payload);
                let semantic_inputs = combined_semantic_inputs(&self.sessions)?;
                let execution_authority = self.execution_authority(&repository_root, inventory)?;
                if !self.session_semantic_inputs_are_current(&repository_root)?
                    || calls.semantic_inputs != semantic_inputs
                    || calls.execution_authority != execution_authority
                {
                    self.reset().await;
                    return self
                        .open_and_certify_full(
                            repository_root,
                            execution_roots,
                            current_sources,
                            current_toolchains,
                            topology_sha256,
                            indexed_sources,
                            inventory,
                            cancellation,
                        )
                        .await;
                }
                let normalization = ScipArtifactSetNormalization {
                    evidence: ScipArtifactEvidence {
                        language_id: LanguageId::new(self.config.language()),
                        receipt: payload.payload().receipt().clone(),
                        payload: Some(payload),
                    },
                    supplemental_evidence: self.supplemental_evidence.clone(),
                    canonical_snapshot: Some(snapshot),
                    source_syntax_cache: self.source_syntax_cache.clone(),
                    timings: Default::default(),
                };
                self.mark_reused();
                Ok(normalization)
            }
            SemanticRefreshPlan::FullCertification { .. }
                if self
                    .config
                    .policy
                    .lifecycle_policy()
                    .source_changed_full_certification
                    == SourceChangedFullCertificationMode::ReplaceSessions =>
            {
                // Full certification exists precisely because the changed
                // surface may alter resolution outside the edited document.
                // Replace every provider root as one candidate population;
                // keeping an "unaffected" root would assume the dependency
                // boundary that this conservative plan says we cannot prove.
                self.refresh_affected_execution_roots(
                    repository_root,
                    execution_roots.clone(),
                    execution_roots.iter().cloned().collect(),
                    current_sources,
                    current_toolchains,
                    topology_sha256,
                    root_topology_sha256,
                    indexed_sources,
                    inventory,
                    cancellation,
                )
                .await
            }
            SemanticRefreshPlan::FullCertification { .. } => {
                self.record_operation_attempt(ProviderOperation::ApplyEpoch);
                self.apply_replacements(&current_sources, &root_topology_sha256, cancellation)
                    .await?;
                self.certify_current_full(
                    &repository_root,
                    &execution_roots,
                    current_sources,
                    topology_sha256,
                    indexed_sources,
                    inventory,
                    cancellation,
                )
                .await
            }
            SemanticRefreshPlan::AffectedDocuments { documents } => {
                self.record_operation_attempt(ProviderOperation::RefreshAffected);
                let candidate = self
                    .refresh_affected(AffectedRefreshRequest {
                        repository_root: &repository_root,
                        documents: &documents,
                        current_sources: &current_sources,
                        root_topology_sha256: &root_topology_sha256,
                        indexed_sources,
                        inventory,
                        cancellation,
                    })
                    .await?;
                let admission_started = Instant::now();
                let prior_payload = calls_payload_from_normalized(
                    self.payload
                        .as_ref()
                        .ok_or(SemanticProviderError::IncompleteFullCertification)?,
                );
                let candidate_payload = calls_payload(&candidate);
                let divergences = candidate_payload.map_or_else(
                    || {
                        vec![SemanticTargetDivergence {
                            document_path: documents
                                .iter()
                                .next()
                                .cloned()
                                .unwrap_or_else(|| "<missing>".into()),
                            call_site_identity: "candidate_calls_payload_unavailable".into(),
                        }]
                    },
                    |payload| unaffected_call_divergences(prior_payload, payload, &documents),
                );
                let validated = validate_affected_candidate(
                    SemanticRefreshPlan::AffectedDocuments {
                        documents: documents.clone(),
                    },
                    &AffectedCandidateEvidence {
                        exact_source_epoch: true,
                        exact_provider_identity: true,
                        provider_healthy: candidate.evidence.receipt.status
                            == CapabilityStatus::Complete
                            && candidate.canonical_snapshot.is_some(),
                        covered_documents: documents.clone(),
                        target_divergences: divergences,
                    },
                );
                let admitted = if matches!(validated, SemanticRefreshPlan::AffectedDocuments { .. })
                {
                    self.commit_normalization(
                        candidate,
                        repository_root,
                        topology_sha256,
                        current_sources,
                        inventory,
                        SemanticProviderAdmittedRefreshKind::Affected { documents },
                    )
                    .await
                } else {
                    self.certify_current_full(
                        &repository_root,
                        &execution_roots,
                        current_sources,
                        topology_sha256,
                        indexed_sources,
                        inventory,
                        cancellation,
                    )
                    .await
                };
                self.record_refresh_timing("admit affected candidate", admission_started);
                admitted
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn refresh_affected_execution_roots(
        &mut self,
        repository_root: PathBuf,
        execution_roots: Vec<PathBuf>,
        affected_roots: BTreeSet<PathBuf>,
        current_sources: BTreeMap<String, PreparedSource>,
        current_toolchains: BTreeMap<PathBuf, ResolvedToolchain>,
        topology_sha256: String,
        root_topology_sha256: BTreeMap<PathBuf, String>,
        indexed_sources: &[IndexedSourceEvidence],
        inventory: &ProjectInventory,
        cancellation: &IndexCancellation,
    ) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
        let semantic_input_paths = self.config.execution_root_semantic_input_paths(
            &repository_root,
            &execution_roots,
            inventory,
        )?;
        if self.can_reconfigure_affected_execution_roots(
            &affected_roots,
            &current_sources,
            &current_toolchains,
            &root_topology_sha256,
            &semantic_input_paths,
        ) {
            let expected_semantic_inputs = self.capture_reconfigured_semantic_inputs(
                &repository_root,
                &affected_roots,
                &current_toolchains,
                &semantic_input_paths,
                inventory,
            )?;
            if expected_semantic_inputs.iter().all(|(root, expected)| {
                self.sessions.get(root).is_some_and(|session| {
                    semantic_inputs_admit_reconfiguration(&session.semantic_inputs, expected)
                })
            }) {
                return self
                    .refresh_reconfigured_execution_roots(
                        repository_root,
                        execution_roots,
                        affected_roots,
                        current_sources,
                        topology_sha256,
                        root_topology_sha256,
                        indexed_sources,
                        inventory,
                        expected_semantic_inputs,
                        cancellation,
                    )
                    .await;
            }
        }
        let affected_documents = self
            .sources
            .values()
            .chain(current_sources.values())
            .filter(|source| affected_roots.contains(&source.execution_root))
            .map(|source| source.identity.document_path.clone())
            .collect::<BTreeSet<_>>();
        let affected_roots = affected_roots.into_iter().collect::<Vec<_>>();
        self.record_operation_attempt(ProviderOperation::OpenSession);
        let (replacements, metrics) = match self
            .open_replacement_session_population(
                &repository_root,
                &affected_roots,
                &current_sources,
                &current_toolchains,
                &root_topology_sha256,
                &semantic_input_paths,
                inventory,
                cancellation,
            )
            .await
        {
            Ok(opened) => opened,
            Err(source) => {
                return Err(SemanticProviderError::PriorAuthorityPreserved {
                    source: Box::new(source),
                });
            }
        };
        let previous_sessions = self.install_session_population(replacements);
        let refresh_result = self
            .admit_execution_root_recertification(
                &repository_root,
                &execution_roots,
                &affected_roots,
                &affected_documents,
                current_sources,
                topology_sha256,
                indexed_sources,
                inventory,
                cancellation,
            )
            .await;
        match refresh_result {
            Ok(normalization) => {
                Self::close_session_population(previous_sessions).await;
                self.record_session_open(Some(metrics));
                Ok(normalization)
            }
            Err(source) => {
                let discarded = self.remove_session_population(&affected_roots);
                let unexpectedly_replaced = self.install_session_population(previous_sessions);
                debug_assert!(unexpectedly_replaced.is_empty());
                Self::close_session_population(discarded).await;
                Err(SemanticProviderError::PriorAuthorityPreserved {
                    source: Box::new(source),
                })
            }
        }
    }

    fn can_reconfigure_affected_execution_roots(
        &self,
        affected_roots: &BTreeSet<PathBuf>,
        current_sources: &BTreeMap<String, PreparedSource>,
        current_toolchains: &BTreeMap<PathBuf, ResolvedToolchain>,
        root_topology_sha256: &BTreeMap<PathBuf, String>,
        semantic_input_paths: &BTreeMap<PathBuf, BTreeSet<String>>,
    ) -> bool {
        self.config
            .policy
            .lifecycle_policy()
            .supports_root_local_refresh()
            && !affected_roots.is_empty()
            && affected_roots.iter().all(|root| {
                self.sessions.get(root).is_some_and(|session| {
                    current_toolchains.get(root) == Some(&session.toolchain)
                        && session.sources == sources_for_root(current_sources, root)
                        && semantic_input_paths.get(root).is_some_and(|paths| {
                            paths
                                .iter()
                                .cloned()
                                .map(|path| (ProviderSemanticPathRoot::Repository, path))
                                .collect::<BTreeSet<_>>()
                                == semantic_input_path_population(&session.semantic_inputs)
                        })
                        && root_topology_sha256.get(root).is_some_and(|topology| {
                            topology != &session.authority.root_topology_sha256
                        })
                })
            })
    }

    fn capture_reconfigured_semantic_inputs(
        &self,
        repository_root: &Path,
        affected_roots: &BTreeSet<PathBuf>,
        current_toolchains: &BTreeMap<PathBuf, ResolvedToolchain>,
        semantic_input_paths: &BTreeMap<PathBuf, BTreeSet<String>>,
        inventory: &ProjectInventory,
    ) -> Result<BTreeMap<PathBuf, ProviderSemanticInputs>, SemanticProviderError> {
        affected_roots
            .iter()
            .map(|root| {
                let session =
                    self.sessions
                        .get(root)
                        .ok_or(SemanticProviderError::InvalidTransition(
                            "reconfigured-root-session-missing",
                        ))?;
                let toolchain = current_toolchains
                    .get(root)
                    .ok_or(SemanticProviderError::ToolchainBindingMismatch)?;
                let paths = semantic_input_paths.get(root).ok_or(
                    SemanticProviderError::InvalidTransition(
                        "reconfigured-root-semantic-input-population-missing",
                    ),
                )?;
                let environment = self.config.process_config(toolchain).environment;
                let expected = self
                    .config
                    .policy
                    .capture_expected_semantic_inputs(
                        repository_root,
                        paths,
                        &environment,
                        &session.process.limits(),
                        inventory,
                    )?
                    .ok_or(SemanticProviderError::InvalidTransition(
                        "root-local-refresh-semantic-inputs-unavailable",
                    ))?;
                Ok((root.clone(), expected))
            })
            .collect()
    }

    /// Admit a root-scoped provider candidate against the unchanged Calls
    /// population. Session replacement and in-place reconfiguration remain
    /// separate transactions; both converge here only after their candidate
    /// session population is installed.
    #[allow(clippy::too_many_arguments)]
    async fn admit_execution_root_recertification(
        &mut self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        affected_roots: &[PathBuf],
        affected_documents: &BTreeSet<String>,
        current_sources: BTreeMap<String, PreparedSource>,
        topology_sha256: String,
        indexed_sources: &[IndexedSourceEvidence],
        inventory: &ProjectInventory,
        cancellation: &IndexCancellation,
    ) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
        let certifications = self
            .collect_full_certifications(affected_roots, cancellation)
            .await?;
        let limits = common_limits(&self.sessions)?;
        let parent = self
            .snapshot
            .as_ref()
            .ok_or(SemanticProviderError::IncompleteFullCertification)?;
        let candidate =
            normalize_admitted_execution_root_recertifications_with_source_syntax_cache(
                repository_root,
                ExecutionRootRecertificationBasis {
                    snapshot: parent,
                    source_syntax_cache: self.source_syntax_cache.as_ref(),
                    supplemental_evidence: &self.supplemental_evidence,
                },
                certifications,
                &limits,
                indexed_sources,
                inventory,
            )?;
        let execution_authority = self.execution_authority(repository_root, inventory)?;
        let candidate = bind_semantic_inputs(
            candidate,
            combined_semantic_inputs(&self.sessions)?,
            execution_authority,
            repository_root,
            &self.sessions,
        )?;
        let prior_payload = calls_payload_from_normalized(
            self.payload
                .as_ref()
                .ok_or(SemanticProviderError::IncompleteFullCertification)?,
        );
        let candidate_payload = calls_payload(&candidate);
        let unaffected_divergences = candidate_payload.map_or_else(
            || {
                vec![SemanticTargetDivergence {
                    document_path: affected_documents
                        .iter()
                        .next()
                        .cloned()
                        .unwrap_or_else(|| "<missing>".into()),
                    call_site_identity: "root_recertification_calls_payload_unavailable".into(),
                }]
            },
            |payload| unaffected_call_divergences(prior_payload, payload, affected_documents),
        );
        let candidate_healthy = candidate.evidence.receipt.status == CapabilityStatus::Complete
            && candidate.canonical_snapshot.is_some()
            && unaffected_divergences.is_empty();
        if candidate_healthy {
            self.commit_normalization(
                candidate,
                repository_root.to_path_buf(),
                topology_sha256,
                current_sources,
                inventory,
                SemanticProviderAdmittedRefreshKind::AffectedRoots {
                    roots: affected_roots.iter().cloned().collect(),
                },
            )
            .await
        } else {
            tracing::warn!(
                status = ?candidate.evidence.receipt.status,
                snapshot_present = candidate.canonical_snapshot.is_some(),
                target_divergences = ?unaffected_divergences,
                "root-scoped recertification could not preserve exact prior Calls and is falling back to full certification"
            );
            self.certify_current_full(
                repository_root,
                execution_roots,
                current_sources,
                topology_sha256,
                indexed_sources,
                inventory,
                cancellation,
            )
            .await
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn refresh_reconfigured_execution_roots(
        &mut self,
        repository_root: PathBuf,
        execution_roots: Vec<PathBuf>,
        affected_roots: BTreeSet<PathBuf>,
        current_sources: BTreeMap<String, PreparedSource>,
        topology_sha256: String,
        root_topology_sha256: BTreeMap<PathBuf, String>,
        indexed_sources: &[IndexedSourceEvidence],
        inventory: &ProjectInventory,
        expected_semantic_inputs: BTreeMap<PathBuf, ProviderSemanticInputs>,
        cancellation: &IndexCancellation,
    ) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
        let affected_documents = self
            .sources
            .values()
            .chain(current_sources.values())
            .filter(|source| affected_roots.contains(&source.execution_root))
            .map(|source| source.identity.document_path.clone())
            .collect::<BTreeSet<_>>();
        let affected_roots = affected_roots.into_iter().collect::<Vec<_>>();
        let candidates = self.remove_session_population(&affected_roots);
        if candidates.len() != affected_roots.len() {
            let unexpectedly_replaced = self.install_session_population(candidates);
            debug_assert!(unexpectedly_replaced.is_empty());
            return Err(SemanticProviderError::InvalidTransition(
                "reconfigured root session population mismatch",
            ));
        }
        self.record_operation_attempt(ProviderOperation::ReconfigureSession);
        let candidates = match Self::reconfigure_session_population(
            self.session_jobs,
            candidates,
            &root_topology_sha256,
            expected_semantic_inputs,
            cancellation,
        )
        .await
        {
            Ok(candidates) => candidates,
            Err(source) => {
                return Err(SemanticProviderError::PriorAuthorityPreserved {
                    source: Box::new(source),
                });
            }
        };
        for (root, candidate) in candidates {
            match self.sessions.entry(root) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(candidate);
                }
                std::collections::btree_map::Entry::Occupied(_) => {
                    let _ = candidate.process.close().await;
                    return Err(SemanticProviderError::InvalidTransition(
                        "reconfigured root session collision",
                    ));
                }
            }
        }
        self.record_session_open(None);

        let refresh_result = self
            .admit_execution_root_recertification(
                &repository_root,
                &execution_roots,
                &affected_roots,
                &affected_documents,
                current_sources,
                topology_sha256,
                indexed_sources,
                inventory,
                cancellation,
            )
            .await;
        if refresh_result.is_err() {
            let mut discarded = BTreeMap::new();
            for root in &affected_roots {
                if let Some(session) = self.sessions.remove(root) {
                    discarded.insert(root.clone(), session);
                }
            }
            Self::close_session_population(discarded).await;
        }
        refresh_result.map_err(|source| SemanticProviderError::PriorAuthorityPreserved {
            source: Box::new(source),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_and_certify_full(
        &mut self,
        repository_root: PathBuf,
        execution_roots: Vec<PathBuf>,
        current_sources: BTreeMap<String, PreparedSource>,
        current_toolchains: BTreeMap<PathBuf, ResolvedToolchain>,
        topology_sha256: String,
        indexed_sources: &[IndexedSourceEvidence],
        inventory: &ProjectInventory,
        cancellation: &IndexCancellation,
    ) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
        let root_topology_sha256 = self.config.execution_root_inventory_fingerprints(
            &repository_root,
            &execution_roots,
            inventory,
            &topology_sha256,
        )?;
        self.open_sessions(
            &repository_root,
            &current_sources,
            current_toolchains,
            &root_topology_sha256,
            inventory,
            cancellation,
        )
        .await?;
        self.certify_current_full(
            &repository_root,
            &execution_roots,
            current_sources,
            topology_sha256,
            indexed_sources,
            inventory,
            cancellation,
        )
        .await
    }

    async fn open_sessions(
        &mut self,
        repository_root: &Path,
        current_sources: &BTreeMap<String, PreparedSource>,
        current_toolchains: BTreeMap<PathBuf, ResolvedToolchain>,
        root_topology_sha256: &BTreeMap<PathBuf, String>,
        inventory: &ProjectInventory,
        cancellation: &IndexCancellation,
    ) -> Result<(), SemanticProviderError> {
        self.record_session_open(None);
        let execution_roots = root_topology_sha256.keys().cloned().collect::<Vec<_>>();
        if execution_roots.is_empty() {
            return Err(SemanticProviderError::NoExecutionRoots);
        }
        if !self.sessions.is_empty() {
            return Err(SemanticProviderError::InvalidTransition(
                "open-sessions-over-existing-runtime",
            ));
        }
        let semantic_input_paths = self.config.execution_root_semantic_input_paths(
            repository_root,
            &execution_roots,
            inventory,
        )?;
        self.record_operation_attempt(ProviderOperation::OpenSession);
        let (sessions, metrics) = Self::open_session_population(
            &self.config,
            self.session_jobs,
            repository_root,
            &execution_roots,
            current_sources,
            current_toolchains,
            root_topology_sha256,
            semantic_input_paths,
            inventory,
            cancellation,
        )
        .await?;
        self.sessions = sessions;
        self.record_session_open(Some(metrics));
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_session_population(
        config: &PersistentSemanticProviderConfig<P>,
        session_jobs: Option<usize>,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        current_sources: &BTreeMap<String, PreparedSource>,
        mut current_toolchains: BTreeMap<PathBuf, ResolvedToolchain>,
        root_topology_sha256: &BTreeMap<PathBuf, String>,
        mut semantic_input_paths: BTreeMap<PathBuf, BTreeSet<String>>,
        inventory: &ProjectInventory,
        cancellation: &IndexCancellation,
    ) -> Result<
        (
            BTreeMap<PathBuf, RootSession>,
            SemanticProviderSessionOpenMetrics,
        ),
        SemanticProviderError,
    > {
        let root_sha256 = sha256_hex(path_text(repository_root)?.as_bytes());
        let repository_root_text = path_text(repository_root)?.to_owned();
        let mut work = Vec::with_capacity(execution_roots.len());
        for execution_root in execution_roots {
            if cancellation.is_cancelled() {
                return Err(SemanticProviderProcessError::Cancelled.into());
            }
            let toolchain = current_toolchains
                .remove(execution_root)
                .ok_or(SemanticProviderError::ToolchainBindingMismatch)?;
            let topology_sha256 = root_topology_sha256.get(execution_root).cloned().ok_or(
                SemanticProviderError::InvalidTransition("execution-root-topology-missing"),
            )?;
            let sources = sources_for_root(current_sources, execution_root);
            if sources.is_empty() {
                return Err(SemanticProviderError::EmptyExecutionRoot(
                    execution_root.display().to_string(),
                ));
            }
            let semantic_input_paths = semantic_input_paths.remove(execution_root).ok_or(
                SemanticProviderError::InvalidTransition(
                    "execution-root-semantic-input-population-missing",
                ),
            )?;
            work.push((
                execution_root.clone(),
                toolchain,
                topology_sha256,
                sources,
                execution_prefix(repository_root, execution_root)?,
                semantic_input_paths,
            ));
        }
        if !current_toolchains.is_empty() || !semantic_input_paths.is_empty() {
            return Err(SemanticProviderError::ToolchainBindingMismatch);
        }

        let max_parallelism = provider_root_parallelism(work.len(), session_jobs);
        let population_started = Instant::now();
        let outcomes = stream::iter(work.into_iter().map(
            |(
                execution_root,
                toolchain,
                topology_sha256,
                sources,
                execution_prefix,
                semantic_input_paths,
            )| {
                let repository_root_text = repository_root_text.clone();
                let root_sha256 = root_sha256.clone();
                async move {
                    let started = Instant::now();
                    let result = Self::open_root_session(
                        config,
                        repository_root_text,
                        root_sha256,
                        topology_sha256,
                        execution_root.clone(),
                        execution_prefix,
                        toolchain,
                        sources,
                        semantic_input_paths,
                        inventory,
                        cancellation,
                    )
                    .await;
                    (execution_root, started.elapsed(), result)
                }
            },
        ))
        .buffer_unordered(max_parallelism)
        .collect::<Vec<_>>()
        .await;

        let mut failures = Vec::new();
        let mut opened = Vec::new();
        for (execution_root, duration, result) in outcomes {
            match result {
                Ok((identity, session)) => {
                    opened.push((execution_root, duration, identity, session))
                }
                Err(error) => failures.push((execution_root, error)),
            }
        }
        failures.sort_by(|left, right| left.0.cmp(&right.0));
        opened.sort_by(|left, right| left.0.cmp(&right.0));

        let inconsistent_identity = opened
            .first()
            .map(|(_, _, identity, _)| identity)
            .is_some_and(|expected| {
                opened
                    .iter()
                    .any(|(_, _, identity, _)| identity != expected)
            });
        if !failures.is_empty() || inconsistent_identity || cancellation.is_cancelled() {
            for (_, _, _, session) in opened {
                let _ = session.process.close().await;
            }
            if let Some((root, source)) = failures.into_iter().next() {
                return Err(SemanticProviderError::ExecutionRoot {
                    root,
                    source: Box::new(source),
                });
            }
            if inconsistent_identity {
                return Err(SemanticProviderError::InconsistentProviderIdentity);
            }
            return Err(SemanticProviderProcessError::Cancelled.into());
        }

        let execution_root_count = opened.len();
        let sessions = opened
            .into_iter()
            .map(|(execution_root, _, _, session)| (execution_root, session))
            .collect();
        Ok((
            sessions,
            SemanticProviderSessionOpenMetrics {
                execution_roots: execution_root_count,
                max_parallelism,
                duration: population_started.elapsed(),
            },
        ))
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_replacement_session_population(
        &self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        current_sources: &BTreeMap<String, PreparedSource>,
        current_toolchains: &BTreeMap<PathBuf, ResolvedToolchain>,
        root_topology_sha256: &BTreeMap<PathBuf, String>,
        semantic_input_paths: &BTreeMap<PathBuf, BTreeSet<String>>,
        inventory: &ProjectInventory,
        cancellation: &IndexCancellation,
    ) -> Result<
        (
            BTreeMap<PathBuf, RootSession>,
            SemanticProviderSessionOpenMetrics,
        ),
        SemanticProviderError,
    > {
        let affected_toolchains = execution_roots
            .iter()
            .map(|root| {
                current_toolchains
                    .get(root)
                    .cloned()
                    .map(|toolchain| (root.clone(), toolchain))
                    .ok_or(SemanticProviderError::ToolchainBindingMismatch)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let affected_semantic_input_paths = execution_roots
            .iter()
            .map(|root| {
                semantic_input_paths
                    .get(root)
                    .cloned()
                    .map(|paths| (root.clone(), paths))
                    .ok_or(SemanticProviderError::InvalidTransition(
                        "affected-root-semantic-input-population-missing",
                    ))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let (replacements, metrics) = Self::open_session_population(
            &self.config,
            self.session_jobs,
            repository_root,
            execution_roots,
            current_sources,
            affected_toolchains,
            root_topology_sha256,
            affected_semantic_input_paths,
            inventory,
            cancellation,
        )
        .await?;
        let retained_identity = self
            .sessions
            .iter()
            .find(|(root, _)| !execution_roots.contains(root))
            .map(|(_, session)| session.process.identity().clone());
        if retained_identity.as_ref().is_some_and(|expected| {
            replacements
                .values()
                .any(|session| session.process.identity() != expected)
        }) {
            for session in replacements.into_values() {
                let _ = session.process.close().await;
            }
            return Err(SemanticProviderError::InconsistentProviderIdentity);
        }
        let replacement_population_exact = replacements.len() == execution_roots.len()
            && execution_roots
                .iter()
                .all(|root| replacements.contains_key(root));
        if !replacement_population_exact {
            for session in replacements.into_values() {
                let _ = session.process.close().await;
            }
            return Err(SemanticProviderError::InvalidTransition(
                "affected root replacement population mismatch",
            ));
        }
        Ok((replacements, metrics))
    }

    async fn reconfigure_session_population(
        session_jobs: Option<usize>,
        sessions: BTreeMap<PathBuf, RootSession>,
        root_topology_sha256: &BTreeMap<PathBuf, String>,
        mut expected_semantic_inputs: BTreeMap<PathBuf, ProviderSemanticInputs>,
        cancellation: &IndexCancellation,
    ) -> Result<BTreeMap<PathBuf, RootSession>, SemanticProviderError> {
        let mut work = Vec::with_capacity(sessions.len());
        for (root, session) in sessions {
            let topology_sha256 = root_topology_sha256.get(&root).cloned().ok_or(
                SemanticProviderError::InvalidTransition("reconfigured root topology missing"),
            )?;
            let expected_semantic_inputs = expected_semantic_inputs.remove(&root).ok_or(
                SemanticProviderError::InvalidTransition(
                    "reconfigured root semantic inputs missing",
                ),
            )?;
            work.push((root, session, topology_sha256, expected_semantic_inputs));
        }
        if !expected_semantic_inputs.is_empty() {
            return Err(SemanticProviderError::InvalidTransition(
                "reconfigured semantic-input root population mismatch",
            ));
        }
        let max_parallelism = provider_root_parallelism(work.len(), session_jobs);
        let outcomes = stream::iter(work.into_iter().map(
            |(root, mut session, topology_sha256, expected_semantic_inputs)| async move {
                let result = Self::reconfigure_root_session(
                    &mut session,
                    topology_sha256,
                    expected_semantic_inputs,
                    cancellation,
                )
                .await;
                (root, session, result)
            },
        ))
        .buffer_unordered(max_parallelism)
        .collect::<Vec<_>>()
        .await;

        let mut sessions = BTreeMap::new();
        let mut failures = Vec::new();
        for (root, session, result) in outcomes {
            if let Err(error) = result {
                failures.push((root.clone(), error));
            }
            sessions.insert(root, session);
        }
        failures.sort_by(|left, right| left.0.cmp(&right.0));
        if !failures.is_empty() || cancellation.is_cancelled() {
            Self::close_session_population(sessions).await;
            if let Some((root, source)) = failures.into_iter().next() {
                return Err(SemanticProviderError::ExecutionRoot {
                    root,
                    source: Box::new(source),
                });
            }
            return Err(SemanticProviderProcessError::Cancelled.into());
        }
        Ok(sessions)
    }

    async fn reconfigure_root_session(
        session: &mut RootSession,
        root_topology_sha256: String,
        expected_semantic_inputs: ProviderSemanticInputs,
        cancellation: &IndexCancellation,
    ) -> Result<(), SemanticProviderError> {
        let mut next_authority = session.authority.clone();
        next_authority.root_topology_sha256 = root_topology_sha256;
        next_authority.workspace_resolution_sha256 = None;
        next_authority.semantic_inputs_sha256 = None;
        next_authority.source_epoch = next_authority.source_epoch.checked_add(1).ok_or(
            SemanticProviderError::InvalidTransition("reconfigure-session-epoch-overflow"),
        )?;
        let terminal = session
            .process
            .request(
                ProviderRequestBody::ReconfigureSession {
                    previous_authority: session.authority.clone(),
                    next_authority: next_authority.clone(),
                    expected_semantic_inputs: expected_semantic_inputs.clone(),
                },
                Vec::new(),
                Some(cancellation),
            )
            .await?;
        let (authority, semantic_inputs) = admit_reconfigured_session(
            &terminal.metadata.body,
            &next_authority,
            &expected_semantic_inputs,
            &session.process.limits(),
        )?;
        session.authority = authority;
        session.semantic_inputs = semantic_inputs;
        Ok(())
    }

    /// Install an already validated subset without closing either population.
    /// Returned sessions are the exact rollback population; missing prior
    /// roots are legal after a cancelled destructive reconfiguration.
    fn install_session_population(
        &mut self,
        replacements: BTreeMap<PathBuf, RootSession>,
    ) -> BTreeMap<PathBuf, RootSession> {
        let mut previous = BTreeMap::new();
        for (root, replacement) in replacements {
            if let Some(replaced) = self.sessions.insert(root.clone(), replacement) {
                previous.insert(root, replaced);
            }
        }
        previous
    }

    fn remove_session_population(
        &mut self,
        execution_roots: &[PathBuf],
    ) -> BTreeMap<PathBuf, RootSession> {
        execution_roots
            .iter()
            .filter_map(|root| {
                self.sessions
                    .remove(root)
                    .map(|session| (root.clone(), session))
            })
            .collect()
    }

    async fn close_session_population(sessions: BTreeMap<PathBuf, RootSession>) {
        for session in sessions.into_values() {
            let _ = session.process.close().await;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_root_session(
        config: &PersistentSemanticProviderConfig<P>,
        repository_root: String,
        root_sha256: String,
        topology_sha256: String,
        execution_root: PathBuf,
        execution_prefix: String,
        toolchain: ResolvedToolchain,
        sources: BTreeMap<String, ProviderSourceIdentity>,
        semantic_input_paths: BTreeSet<String>,
        inventory: &ProjectInventory,
        cancellation: &IndexCancellation,
    ) -> Result<(ProviderIdentity, RootSession), SemanticProviderError> {
        if cancellation.is_cancelled() {
            return Err(SemanticProviderProcessError::Cancelled.into());
        }
        let process_config = config.process_config(&toolchain);
        let provider_environment = process_config.environment.clone();
        let mut process = SemanticProviderProcess::spawn(process_config).await?;
        let identity = process.identity().clone();
        let limits = process.limits();
        let expected_semantic_inputs = match config.policy.capture_expected_semantic_inputs(
            Path::new(&repository_root),
            &semantic_input_paths,
            &provider_environment,
            &limits,
            inventory,
        ) {
            Ok(expected) => expected,
            Err(error) => {
                let _ = process.close().await;
                return Err(error);
            }
        };
        let authority = ProviderAuthority {
            session_id: process.session_id().into(),
            root_sha256,
            root_topology_sha256: topology_sha256,
            configuration_sha256: process.runtime_configuration().configuration_sha256.clone(),
            workspace_resolution_sha256: None,
            semantic_inputs_sha256: None,
            population_sha256: source_population_sha256(
                &sources.values().cloned().collect::<Vec<_>>(),
                &limits,
            )?,
            source_epoch: 1,
        };
        let opened = process
            .request(
                ProviderRequestBody::OpenSession {
                    repository_root,
                    execution_root: path_text(&execution_root)?.into(),
                    execution_prefix,
                    authority: authority.clone(),
                    sources: sources.values().cloned().collect(),
                    expected_semantic_inputs: expected_semantic_inputs.clone(),
                },
                Vec::new(),
                Some(cancellation),
            )
            .await?;
        let (authority, semantic_inputs) = match admit_open_session(
            &opened.metadata.body,
            &authority,
            expected_semantic_inputs.as_ref(),
            &limits,
        ) {
            Ok(admitted) => admitted,
            Err(error) => {
                let _ = process.close().await;
                return Err(error);
            }
        };
        Ok((
            identity,
            RootSession {
                process,
                toolchain,
                authority,
                sources,
                semantic_inputs,
            },
        ))
    }

    async fn resolve_toolchains(
        &self,
        execution_roots: &[PathBuf],
        cancellation: &IndexCancellation,
    ) -> Result<BTreeMap<PathBuf, ResolvedToolchain>, SemanticProviderError> {
        let resolved = resolve_toolchain_population(
            Some(&self.config.toolchain_resolver),
            self.config.language(),
            execution_roots,
            cancellation,
        )
        .await?;
        if resolved.values().any(|toolchain| {
            self.config
                .policy
                .required_components()
                .iter()
                .any(|role| !toolchain.components.contains_key(*role))
        }) {
            return Err(SemanticProviderError::ToolchainBindingMismatch);
        }
        Ok(resolved)
    }

    async fn session_toolchains_are_current(
        &self,
        cancellation: &IndexCancellation,
    ) -> Result<(), SemanticProviderError> {
        let roots = self.sessions.keys().cloned().collect::<Vec<_>>();
        let current = self.resolve_toolchains(&roots, cancellation).await?;
        if current.iter().any(|(root, toolchain)| {
            self.sessions
                .get(root)
                .is_none_or(|session| session.toolchain != *toolchain)
        }) {
            return Err(SemanticProviderError::ToolchainChanged);
        }
        Ok(())
    }

    fn session_semantic_inputs_are_current(
        &self,
        repository_root: &Path,
    ) -> Result<bool, SemanticProviderError> {
        for session in self.sessions.values() {
            match session.semantic_inputs.coverage {
                ProviderSemanticInputCoverage::Complete => {}
                ProviderSemanticInputCoverage::Unverifiable => continue,
            }
            let environment = self.config.process_config(&session.toolchain).environment;
            if !provider_semantic_inputs_are_current_in_environment(
                repository_root,
                &session.semantic_inputs,
                &environment,
                &session.process.limits(),
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn probe_session_runtime_authority(
        &mut self,
        cancellation: &IndexCancellation,
    ) -> Result<(), SemanticProviderError> {
        let roots = self.sessions.keys().cloned().collect::<BTreeSet<_>>();
        self.probe_session_runtime_authority_for_roots(&roots, cancellation)
            .await
    }

    fn retained_runtime_preflight_roots(
        &self,
        changed_documents: &BTreeMap<PathBuf, BTreeSet<String>>,
    ) -> BTreeSet<PathBuf> {
        self.sessions
            .iter()
            .filter_map(|(root, session)| {
                let transaction_carries_runtime_witness =
                    changed_documents.get(root).is_some_and(|documents| {
                        session.semantic_inputs.coverage == ProviderSemanticInputCoverage::Complete
                            && documents.iter().all(|document| {
                                session.semantic_inputs.paths.iter().all(|input| {
                                    !semantic_input_path_covers_document(input, document)
                                })
                            })
                    });
                (!transaction_carries_runtime_witness).then(|| root.clone())
            })
            .collect()
    }

    fn discard_observed_exited_sessions(
        &mut self,
    ) -> Result<BTreeSet<PathBuf>, SemanticProviderError> {
        let roots = self.sessions.keys().cloned().collect::<Vec<_>>();
        let mut exited_roots = BTreeSet::new();
        for root in roots {
            let exited = self
                .sessions
                .get_mut(&root)
                .ok_or(SemanticProviderError::InvalidTransition(
                    "local-exit-observation-session-missing",
                ))?
                .process
                .observe_local_exit()
                .map_err(|source| SemanticProviderError::ExecutionRoot {
                    root: root.clone(),
                    source: Box::new(source.into()),
                })?;
            if exited {
                let session =
                    self.sessions
                        .remove(&root)
                        .ok_or(SemanticProviderError::InvalidTransition(
                            "local-exit-observation-removal-missing",
                        ))?;
                drop(session);
                exited_roots.insert(root);
            }
        }
        if !exited_roots.is_empty() {
            tracing::warn!(
                language = self.config.language(),
                exited_roots = ?exited_roots,
                retained_roots = self.sessions.len(),
                "discarded already-exited semantic-provider execution roots"
            );
        }
        Ok(exited_roots)
    }

    async fn probe_session_runtime_authority_for_roots(
        &mut self,
        requested_roots: &BTreeSet<PathBuf>,
        cancellation: &IndexCancellation,
    ) -> Result<(), SemanticProviderError> {
        if requested_roots
            .iter()
            .any(|root| !self.sessions.contains_key(root))
        {
            return Err(SemanticProviderError::InvalidTransition(
                "runtime-probe-requested-session-missing",
            ));
        }
        let roots = requested_roots.iter().cloned().collect::<Vec<_>>();
        if !roots.is_empty() {
            self.record_operation_attempt(ProviderOperation::Hello);
        }
        let mut first_failure = None;
        let mut failed_roots = BTreeSet::new();
        for root in roots {
            if cancellation.is_cancelled() {
                return Err(SemanticProviderProcessError::Cancelled.into());
            }
            let probe = {
                let session = self.sessions.get_mut(&root).ok_or(
                    SemanticProviderError::InvalidTransition("runtime-probe-session-missing"),
                )?;
                let expected_limits = session.process.limits();
                let expected_runtime = session.process.runtime_configuration().clone();
                match session
                    .process
                    .request(ProviderRequestBody::Hello, Vec::new(), Some(cancellation))
                    .await
                {
                    Ok(frame) => match frame.metadata.body {
                        ProviderResponseBody::Hello {
                            limits,
                            runtime_configuration,
                        } if limits == expected_limits
                            && runtime_configuration == expected_runtime =>
                        {
                            Ok(())
                        }
                        _ => Err(SemanticProviderError::InvalidTransition(
                            "reuse-authority-probe",
                        )),
                    },
                    Err(error) => Err(error.into()),
                }
            };
            let Err(source) = probe else {
                continue;
            };

            // Any request uncertainty already quarantines the process. A
            // syntactically valid but mismatched Hello is equally unfit for
            // authority, so close that exact root as well. Do this before
            // considering cancellation: once a request began, cancellation
            // also kills that boot and it must not remain registered.
            let session =
                self.sessions
                    .remove(&root)
                    .ok_or(SemanticProviderError::InvalidTransition(
                        "runtime-probe-failed-session-missing",
                    ))?;
            let _ = session.process.close().await;
            let rooted = SemanticProviderError::ExecutionRoot {
                root: root.clone(),
                source: Box::new(source),
            };
            if is_provider_cancellation(&rooted) {
                return Err(rooted);
            }
            failed_roots.insert(root);
            first_failure.get_or_insert(rooted);
        }
        if let Some(error) = first_failure {
            tracing::warn!(
                language = self.config.language(),
                failed_roots = ?failed_roots,
                retained_roots = self.sessions.len(),
                "quarantined failed semantic-provider execution roots"
            );
            Err(error)
        } else {
            Ok(())
        }
    }

    fn execution_authority(
        &self,
        repository_root: &Path,
        inventory: &ProjectInventory,
    ) -> Result<ProviderExecutionAuthority, SemanticProviderError> {
        let mut toolchains = BTreeMap::new();
        let mut configurations = BTreeMap::new();
        let mut reconstructions = BTreeMap::new();
        for (execution_root, session) in &self.sessions {
            let prefix = execution_prefix(repository_root, execution_root)?;
            let resolved = resolved_authority_configuration_sha256(&session.authority)?;
            let configuration = provider_configuration_sha256(&self.config, &resolved)?;
            let workspace_resolution_sha256 = session
                .authority
                .workspace_resolution_sha256
                .clone()
                .ok_or(SemanticProviderError::InvalidTransition(
                    "provider workspace resolution descriptor",
                ))?;
            let semantic_inputs_sha256 = provider_semantic_inputs_sha256(
                &session.semantic_inputs,
                &session.process.limits(),
            )?;
            if session.authority.semantic_inputs_sha256.as_deref()
                != Some(semantic_inputs_sha256.as_str())
            {
                return Err(SemanticProviderError::InvalidTransition(
                    "provider semantic input descriptor",
                ));
            }
            let reconstruction = ProviderGenerationReconstruction::ObservedWorkspace {
                runtime_configuration_sha256: session.authority.configuration_sha256.clone(),
                workspace_resolution_sha256,
                semantic_inputs: session.semantic_inputs.clone(),
            };
            if toolchains
                .insert(execution_root.clone(), session.toolchain.clone())
                .is_some()
                || configurations
                    .insert(prefix.clone(), configuration)
                    .is_some()
                || reconstructions.insert(prefix, reconstruction).is_some()
            {
                return Err(SemanticProviderError::InvalidTransition(
                    "provider-execution-authority-population",
                ));
            }
        }
        let implementation = provider_identity_sha256(&self.config.expected_identity)?;
        let resolver_policy_id = self
            .config
            .toolchain_resolver
            .policy_id(self.config.language())?;
        toolchain_bound_execution_authority(ToolchainBoundAuthorityInput {
            repository_root,
            inventory,
            language: self.config.language(),
            ecosystem: self.config.ecosystem(),
            resolver_policy_id,
            reuse_contract_id: self.config.reuse_contract_id(),
            provider_implementation_sha256: &implementation,
            provider_configurations_sha256: &configurations,
            reconstruction_descriptors: Some(&reconstructions),
            toolchains: &toolchains,
        })
        .map_err(SemanticProviderError::from)
    }

    #[allow(clippy::too_many_arguments)]
    async fn certify_current_full(
        &mut self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        current_sources: BTreeMap<String, PreparedSource>,
        topology_sha256: String,
        indexed_sources: &[IndexedSourceEvidence],
        inventory: &ProjectInventory,
        cancellation: &IndexCancellation,
    ) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
        let certifications = self
            .collect_full_certifications(execution_roots, cancellation)
            .await?;
        let limits = common_limits(&self.sessions)?;
        let normalization = normalize_admitted_full_certifications_with_source_syntax_cache(
            repository_root,
            certifications,
            &limits,
            indexed_sources,
            inventory,
            self.source_syntax_cache.as_ref(),
        )?;
        let execution_authority = self.execution_authority(repository_root, inventory)?;
        let normalization = bind_semantic_inputs(
            normalization,
            combined_semantic_inputs(&self.sessions)?,
            execution_authority,
            repository_root,
            &self.sessions,
        )?;
        self.commit_normalization(
            normalization,
            repository_root.to_path_buf(),
            topology_sha256,
            current_sources,
            inventory,
            SemanticProviderAdmittedRefreshKind::Full,
        )
        .await
    }

    async fn collect_full_certifications(
        &mut self,
        execution_roots: &[PathBuf],
        cancellation: &IndexCancellation,
    ) -> Result<Vec<ProviderFullCertification>, SemanticProviderError> {
        if !execution_roots.is_empty() {
            self.record_operation_attempt(ProviderOperation::CertifyFull);
        }
        let mut certifications = Vec::with_capacity(execution_roots.len());
        for execution_root in execution_roots {
            if !self.sessions.contains_key(execution_root) {
                tracing::error!(
                    missing_root = %execution_root.display(),
                    available_roots = ?self.sessions.keys().collect::<Vec<_>>(),
                    "semantic provider certification requested a missing root session"
                );
            }
            let session = self.sessions.get_mut(execution_root).ok_or(
                SemanticProviderError::InvalidTransition("missing root session"),
            )?;
            let analyses = self.config.policy.requested_analyses();
            let expected_analyses = expected_analyses(&analyses, self.config.language())?;
            let frame = session
                .process
                .request(
                    ProviderRequestBody::CertifyFull {
                        authority: session.authority.clone(),
                        analyses,
                    },
                    Vec::new(),
                    Some(cancellation),
                )
                .await?;
            reject_error("full-certification", &frame.metadata.body)?;
            let expected = ExpectedFullCertification {
                request_id: frame.metadata.request_id,
                provider: session.process.identity().clone(),
                authority: session.authority.clone(),
                documents: expected_documents(&session.sources),
                analyses: expected_analyses,
            };
            certifications.push(ProviderFullCertification {
                execution_root: execution_root.clone(),
                frame,
                expected,
            });
        }
        Ok(certifications)
    }

    fn prepare_epoch_transition(
        execution_root: &Path,
        session: &RootSession,
        current_sources: &BTreeMap<String, PreparedSource>,
        root_topology_sha256: &BTreeMap<PathBuf, String>,
    ) -> Result<Option<PreparedEpochTransition>, SemanticProviderError> {
        let changed = current_sources
            .values()
            .filter(|source| {
                source.execution_root == execution_root
                    && session.sources.get(&source.identity.document_path) != Some(&source.identity)
            })
            .collect::<Vec<_>>();
        if changed.is_empty() {
            return Ok(None);
        }
        let mut next_sources = session.sources.clone();
        let mut changes = Vec::with_capacity(changed.len());
        let mut attachments = Vec::with_capacity(changed.len());
        for source in changed {
            let previous = session.sources.get(&source.identity.document_path).ok_or(
                SemanticProviderError::InvalidTransition("replacement prior source missing"),
            )?;
            if previous.content_identity == source.identity.content_identity
                || previous.content_sha256 == source.identity.content_sha256
            {
                return Err(SemanticProviderError::SourceIdentityCollision(
                    source.identity.document_path.clone(),
                ));
            }
            let attachment_index = attachments.len() as u32;
            attachments.push(source.bytes.clone());
            changes.push(ProviderSourceChange::Replace {
                document_path: source.identity.document_path.clone(),
                language: source.identity.language.clone(),
                previous_content_identity: previous.content_identity.clone(),
                previous_content_sha256: previous.content_sha256.clone(),
                content_identity: source.identity.content_identity.clone(),
                content_sha256: source.identity.content_sha256.clone(),
                attachment_index,
            });
            next_sources.insert(
                source.identity.document_path.clone(),
                source.identity.clone(),
            );
        }
        let limits = session.process.limits();
        let mut next_authority = session.authority.clone();
        next_authority.root_topology_sha256 = root_topology_sha256
            .get(execution_root)
            .cloned()
            .ok_or(SemanticProviderError::InvalidTransition(
                "replacement-execution-root-topology-missing",
            ))?;
        next_authority.population_sha256 =
            source_population_sha256(&next_sources.values().cloned().collect::<Vec<_>>(), &limits)?;
        next_authority.source_epoch = next_authority.source_epoch.checked_add(1).ok_or(
            SemanticProviderError::InvalidTransition("source epoch exhausted"),
        )?;
        Ok(Some(PreparedEpochTransition {
            next_authority,
            next_sources,
            changes,
            attachments,
        }))
    }

    async fn apply_replacements(
        &mut self,
        current_sources: &BTreeMap<String, PreparedSource>,
        root_topology_sha256: &BTreeMap<PathBuf, String>,
        cancellation: &IndexCancellation,
    ) -> Result<(), SemanticProviderError> {
        for (execution_root, session) in &mut self.sessions {
            let Some(transition) = Self::prepare_epoch_transition(
                execution_root,
                session,
                current_sources,
                root_topology_sha256,
            )?
            else {
                continue;
            };
            let PreparedEpochTransition {
                next_authority,
                next_sources,
                changes,
                attachments,
            } = transition;
            let frame = session
                .process
                .request(
                    ProviderRequestBody::ApplyEpoch {
                        previous_authority: session.authority.clone(),
                        next_authority: next_authority.clone(),
                        changes,
                    },
                    attachments,
                    Some(cancellation),
                )
                .await?;
            require_transition("apply-epoch", &frame.metadata.body, &next_authority)?;
            session.authority = next_authority;
            session.sources = next_sources;
        }
        Ok(())
    }

    async fn refresh_affected(
        &mut self,
        request: AffectedRefreshRequest<'_>,
    ) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
        let AffectedRefreshRequest {
            repository_root,
            documents,
            current_sources,
            root_topology_sha256,
            indexed_sources,
            inventory,
            cancellation,
        } = request;
        let parent_snapshot_sha256 = self
            .snapshot
            .as_ref()
            .ok_or(SemanticProviderError::IncompleteFullCertification)?
            .identity_sha256();
        let mut exports = Vec::new();
        let mut covered_documents = BTreeSet::new();
        let rpc_started = Instant::now();
        for (execution_root, session) in &mut self.sessions {
            let Some(transition) = Self::prepare_epoch_transition(
                execution_root,
                session,
                current_sources,
                root_topology_sha256,
            )?
            else {
                continue;
            };
            let PreparedEpochTransition {
                next_authority,
                next_sources,
                changes,
                attachments,
            } = transition;
            let requested = documents
                .iter()
                .filter(|path| next_sources.contains_key(*path))
                .cloned()
                .collect::<Vec<_>>();
            if requested.is_empty() {
                return Err(SemanticProviderError::InvalidTransition(
                    "changed provider root has no affected document",
                ));
            }
            covered_documents.extend(requested.iter().cloned());
            let expected_runtime = session.process.runtime_configuration().clone();
            let analyses = self.config.policy.requested_analyses();
            let expected_analyses = expected_analyses(&analyses, self.config.language())?;
            let frame = session
                .process
                .request(
                    ProviderRequestBody::RefreshAffected {
                        previous_authority: session.authority.clone(),
                        next_authority: next_authority.clone(),
                        changes,
                        parent_snapshot_sha256: parent_snapshot_sha256.clone(),
                        documents: requested.clone(),
                        analyses,
                    },
                    attachments,
                    Some(cancellation),
                )
                .await?;
            reject_error("affected-refresh", &frame.metadata.body)?;
            let expected = ExpectedAffectedRefresh {
                request_id: frame.metadata.request_id,
                provider: session.process.identity().clone(),
                authority: next_authority.clone(),
                parent_snapshot_sha256: parent_snapshot_sha256.clone(),
                documents: requested
                    .iter()
                    .map(|path| {
                        let source = next_sources
                            .get(path)
                            .expect("requested source came from this session");
                        (
                            path.clone(),
                            ExpectedProviderDocument {
                                language: source.language.clone(),
                                content_identity: source.content_identity.clone(),
                            },
                        )
                    })
                    .collect(),
                analyses: expected_analyses,
                terminal_runtime_configuration: expected_runtime,
            };
            exports.push(ProviderAffectedRefresh {
                execution_root: execution_root.clone(),
                frame,
                expected,
            });
            session.authority = next_authority;
            session.sources = next_sources;
        }
        if covered_documents != *documents {
            return Err(SemanticProviderError::InvalidTransition(
                "affected document population is not owned by changed provider roots",
            ));
        }
        let rpc_duration = rpc_started.elapsed();
        let parent = self
            .snapshot
            .as_ref()
            .ok_or(SemanticProviderError::IncompleteFullCertification)?;
        let overlay_started = Instant::now();
        let normalization = normalize_admitted_affected_refreshes_with_source_syntax_cache(
            repository_root,
            parent,
            exports,
            &common_limits(&self.sessions)?,
            indexed_sources,
            inventory,
            AffectedNormalizationBasis {
                source_syntax_cache: self.source_syntax_cache.as_ref(),
                prior_payload: self.payload.as_ref().map(calls_payload_from_normalized),
                prior_supplemental_evidence: &self.supplemental_evidence,
            },
        )
        .map_err(SemanticProviderError::from)?;
        let overlay_duration = overlay_started
            .elapsed()
            .saturating_sub(normalization.timings.total);
        let binding_started = Instant::now();
        let execution_authority = self.execution_authority(repository_root, inventory)?;
        let normalization = bind_semantic_inputs(
            normalization,
            combined_semantic_inputs(&self.sessions)?,
            execution_authority,
            repository_root,
            &self.sessions,
        )?;
        let binding_duration = binding_started.elapsed();
        self.push_refresh_timing("affected refresh transaction RPC", rpc_duration);
        self.push_refresh_timing(
            "affected refresh admission and snapshot overlay",
            overlay_duration,
        );
        self.push_refresh_timing("affected refresh authority binding", binding_duration);
        Ok(normalization)
    }

    async fn commit_normalization(
        &mut self,
        normalization: ScipArtifactSetNormalization,
        repository_root: PathBuf,
        topology_sha256: String,
        current_sources: BTreeMap<String, PreparedSource>,
        inventory: &ProjectInventory,
        refresh_kind: SemanticProviderAdmittedRefreshKind,
    ) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
        if normalization.evidence.receipt.status != CapabilityStatus::Complete {
            self.reset().await;
            return Ok(normalization);
        }
        let snapshot = normalization
            .canonical_snapshot
            .clone()
            .ok_or(SemanticProviderError::IncompleteFullCertification)?;
        calls_payload(&normalization).ok_or(SemanticProviderError::IncompleteFullCertification)?;
        let payload = normalization
            .evidence
            .payload
            .clone()
            .ok_or(SemanticProviderError::IncompleteFullCertification)?;
        if normalization.supplemental_evidence.iter().any(|evidence| {
            evidence.receipt.status != CapabilityStatus::Complete || evidence.payload.is_none()
        }) {
            return Err(SemanticProviderError::IncompleteFullCertification);
        }
        let supplemental_evidence = normalization.supplemental_evidence.clone();
        let source_syntax_cache = normalization.source_syntax_cache.clone();
        let execution_roots = self.sessions.keys().cloned().collect::<Vec<_>>();
        let root_topology_sha256 = self.config.execution_root_inventory_fingerprints(
            &repository_root,
            &execution_roots,
            inventory,
            &topology_sha256,
        )?;
        let operation = match &refresh_kind {
            SemanticProviderAdmittedRefreshKind::Affected { .. } => {
                ProviderOperation::RefreshAffected
            }
            SemanticProviderAdmittedRefreshKind::AffectedRoots { .. }
            | SemanticProviderAdmittedRefreshKind::Full => ProviderOperation::CertifyFull,
        };
        // This is the final fallible admission step. It must run before any
        // retained authority changes so an invalid typed receipt leaves the
        // prior repository/session transaction exactly recoverable.
        self.mark_admitted(refresh_kind, operation)?;
        self.repository_root = Some(repository_root);
        self.topology_sha256 = Some(topology_sha256);
        self.root_topology_sha256 = root_topology_sha256;
        self.sources = current_sources;
        self.snapshot = Some(snapshot);
        self.payload = Some(payload);
        self.supplemental_evidence = supplemental_evidence;
        self.source_syntax_cache = source_syntax_cache;
        self.publication_pending = true;
        Ok(normalization)
    }

    /// Record the outer immutable publication boundary. Provider refresh and
    /// generation publication are separate transactions, so only their
    /// serialized owner may call this after the generation commit succeeds.
    pub const fn mark_publication_committed(&mut self) {
        self.publication_pending = false;
    }
}

#[cfg(test)]
fn rust_provider_inventory_fingerprint(
    inventory: &ProjectInventory,
) -> Result<String, SemanticProviderError> {
    semantic_provider_inventory_fingerprint(inventory, H00_RUST_ANALYZER_LANGUAGE, "cargo")
        .map_err(|error| SemanticProviderError::Inventory(error.to_string()))
}

fn canonical_utf8_directory(path: &Path) -> Result<PathBuf, SemanticProviderError> {
    let canonical = fs::canonicalize(path).map_err(|error| SemanticProviderError::Filesystem {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;
    if !canonical.is_dir() || canonical.to_str().is_none() {
        return Err(SemanticProviderError::InvalidRoot(
            path.display().to_string(),
        ));
    }
    Ok(canonical)
}

fn canonical_execution_roots(
    repository_root: &Path,
    roots: &[PathBuf],
) -> Result<Vec<PathBuf>, SemanticProviderError> {
    if roots.is_empty() {
        return Err(SemanticProviderError::NoExecutionRoots);
    }
    let mut canonical = BTreeSet::new();
    for root in roots {
        let root = canonical_utf8_directory(root)?;
        if !root.starts_with(repository_root) || !canonical.insert(root.clone()) {
            return Err(SemanticProviderError::InvalidRoot(
                root.display().to_string(),
            ));
        }
    }
    Ok(canonical.into_iter().collect())
}

#[cfg(test)]
fn prepare_sources(
    repository_root: &Path,
    execution_roots: &[PathBuf],
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
) -> Result<BTreeMap<String, PreparedSource>, SemanticProviderError> {
    prepare_provider_sources(
        repository_root,
        execution_roots,
        indexed_sources,
        inventory,
        H00_RUST_ANALYZER_LANGUAGE,
        "cargo",
    )
}

fn prepare_provider_sources(
    repository_root: &Path,
    execution_roots: &[PathBuf],
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
    language: &str,
    ecosystem: &str,
) -> Result<BTreeMap<String, PreparedSource>, SemanticProviderError> {
    let execution_root_by_document =
        semantic_provider_document_execution_roots(inventory, language, ecosystem);
    let mut prepared = BTreeMap::new();
    for source in indexed_sources
        .iter()
        .filter(|source| source.language == language)
    {
        let relative = Path::new(&source.relative_path);
        if !safe_relative_path(relative) {
            return Err(SemanticProviderError::InvalidSourcePath(
                source.relative_path.clone(),
            ));
        }
        let Some(execution_root) = execution_root_by_document.get(&source.relative_path) else {
            continue;
        };
        let execution_root = repository_root.join(execution_root);
        if !execution_roots.contains(&execution_root) {
            return Err(SemanticProviderError::SourceOutsideExecutionRoot(
                source.relative_path.clone(),
            ));
        }
        let path = repository_root.join(relative);
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| SemanticProviderError::Filesystem {
                path: path.clone(),
                detail: error.to_string(),
            })?;
        if !metadata.file_type().is_file() {
            return Err(SemanticProviderError::InvalidSourcePath(
                source.relative_path.clone(),
            ));
        }
        let bytes = fs::read(&path).map_err(|error| SemanticProviderError::Filesystem {
            path: path.clone(),
            detail: error.to_string(),
        })?;
        let content_blake3 = blake3::hash(&bytes).to_hex().to_string();
        if content_blake3 != source.blake3_hash {
            return Err(SemanticProviderError::SourceIdentityMismatch(
                source.relative_path.clone(),
            ));
        }
        let identity = ProviderSourceIdentity {
            document_path: source.relative_path.clone(),
            language: source.language.clone(),
            content_identity: format!("blake3:{content_blake3}"),
            content_sha256: sha256_hex(&bytes),
        };
        let candidate = PreparedSource {
            identity,
            cross_document_surface_sha256: source.cross_document_surface_sha256.clone(),
            execution_root,
            bytes,
        };
        if prepared
            .insert(source.relative_path.clone(), candidate)
            .is_some()
        {
            return Err(SemanticProviderError::SourceIdentityCollision(
                source.relative_path.clone(),
            ));
        }
    }
    for root in execution_roots {
        if !prepared
            .values()
            .any(|source| &source.execution_root == root)
        {
            return Err(SemanticProviderError::EmptyExecutionRoot(
                root.display().to_string(),
            ));
        }
    }
    Ok(prepared)
}

fn semantic_changes(
    prior: &BTreeMap<String, PreparedSource>,
    current: &BTreeMap<String, PreparedSource>,
) -> Result<Vec<SemanticDocumentChange>, SemanticProviderError> {
    if prior.keys().collect::<BTreeSet<_>>() != current.keys().collect::<BTreeSet<_>>() {
        return Ok(vec![SemanticDocumentChange::Uncertain {
            path: None,
            reason: "source population changed without a new provider session".into(),
        }]);
    }
    let mut changes = Vec::new();
    for (path, current) in current {
        let previous = prior
            .get(path)
            .ok_or(SemanticProviderError::InvalidTransition(
                "prior source population changed",
            ))?;
        changes.push(SemanticDocumentChange::Modified {
            before: document_version(previous),
            after: document_version(current),
        });
    }
    Ok(changes)
}

fn document_version(source: &PreparedSource) -> SemanticDocumentVersion {
    SemanticDocumentVersion {
        document_path: source.identity.document_path.clone(),
        language_id: LanguageId::new(&source.identity.language),
        content_identity: source.identity.content_identity.clone(),
        cross_document_surface_identity: source.cross_document_surface_sha256.clone(),
    }
}

fn sources_for_root(
    sources: &BTreeMap<String, PreparedSource>,
    execution_root: &Path,
) -> BTreeMap<String, ProviderSourceIdentity> {
    sources
        .iter()
        .filter(|(_, source)| source.execution_root == execution_root)
        .map(|(path, source)| (path.clone(), source.identity.clone()))
        .collect()
}

fn source_changed_documents_by_execution_root(
    prior: &BTreeMap<String, PreparedSource>,
    current: &BTreeMap<String, PreparedSource>,
) -> BTreeMap<PathBuf, BTreeSet<String>> {
    let mut changed = BTreeMap::<PathBuf, BTreeSet<String>>::new();
    for path in prior
        .keys()
        .chain(current.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|path| {
            prior
                .get(*path)
                .zip(current.get(*path))
                .is_none_or(|(left, right)| !prepared_sources_match(left, right))
        })
    {
        for source in prior.get(path).into_iter().chain(current.get(path)) {
            changed
                .entry(source.execution_root.clone())
                .or_default()
                .insert((*path).clone());
        }
    }
    changed
}

fn semantic_input_path_covers_document(input: &ProviderSemanticPathInput, document: &str) -> bool {
    input.root == ProviderSemanticPathRoot::Repository
        && (input.path == document
            || matches!(
                input.kind,
                ProviderSemanticPathKind::Directory | ProviderSemanticPathKind::DirectoryListing
            ) && document
                .strip_prefix(&input.path)
                .is_some_and(|suffix| suffix.starts_with('/')))
}

fn semantic_input_path_population(
    inputs: &ProviderSemanticInputs,
) -> BTreeSet<(ProviderSemanticPathRoot, String)> {
    inputs
        .paths
        .iter()
        .map(|input| (input.root, input.path.clone()))
        .collect()
}

fn semantic_inputs_admit_reconfiguration(
    previous: &ProviderSemanticInputs,
    next: &ProviderSemanticInputs,
) -> bool {
    previous.coverage == ProviderSemanticInputCoverage::Complete
        && next.coverage == ProviderSemanticInputCoverage::Complete
        && previous.issues.is_empty()
        && next.issues.is_empty()
        && semantic_input_path_population(previous) == semantic_input_path_population(next)
        && previous.environment == next.environment
        && previous.paths != next.paths
}

fn payload_documents_match_sources(
    payload: &CallsProviderPayload,
    sources: &BTreeMap<String, PreparedSource>,
) -> bool {
    if payload.documents.len() != sources.len() {
        return false;
    }
    let mut observed = BTreeSet::new();
    payload.documents.iter().all(|document| {
        let Some(source) = sources.get(&document.document_path) else {
            return false;
        };
        observed.insert(document.document_path.as_str())
            && document.language_id.0 == source.identity.language
            && document.content_sha256 == source.identity.content_sha256
            && document.byte_length == source.bytes.len() as u64
            && source
                .cross_document_surface_sha256
                .as_ref()
                .is_none_or(|surface| surface == &document.cross_document_surface_sha256)
    }) && observed.len() == sources.len()
}

fn prepared_source_populations_match(
    left: &BTreeMap<String, PreparedSource>,
    right: &BTreeMap<String, PreparedSource>,
) -> bool {
    left.len() == right.len()
        && left.iter().all(|(path, source)| {
            right
                .get(path)
                .is_some_and(|candidate| prepared_sources_match(source, candidate))
        })
}

fn prepared_sources_match(left: &PreparedSource, right: &PreparedSource) -> bool {
    left.identity == right.identity
        && left.cross_document_surface_sha256 == right.cross_document_surface_sha256
        && left.execution_root == right.execution_root
        && left.bytes == right.bytes
}

fn expected_documents(
    sources: &BTreeMap<String, ProviderSourceIdentity>,
) -> BTreeMap<String, ExpectedProviderDocument> {
    sources
        .iter()
        .map(|(path, source)| {
            (
                path.clone(),
                ExpectedProviderDocument {
                    language: source.language.clone(),
                    content_identity: source.content_identity.clone(),
                },
            )
        })
        .collect()
}

fn expected_analyses(
    requests: &[ProviderAnalysisRequest],
    language: &str,
) -> Result<BTreeMap<String, ExpectedProviderAnalysis>, SemanticProviderError> {
    let mut expected = BTreeMap::new();
    for request in requests {
        if expected
            .insert(
                request.analysis_id.clone(),
                ExpectedProviderAnalysis {
                    schema_version: request.schema_version.clone(),
                    configuration_id: request.configuration_id.clone(),
                    language: language.to_owned(),
                },
            )
            .is_some()
        {
            return Err(SemanticProviderError::InvalidTransition(
                "duplicate requested provider analysis",
            ));
        }
    }
    Ok(expected)
}

fn require_transition(
    operation: &'static str,
    body: &ProviderResponseBody,
    expected: &ProviderAuthority,
) -> Result<(), SemanticProviderError> {
    reject_error(operation, body)?;
    let (authority, health) = match body {
        ProviderResponseBody::EpochApplied { authority, health } if operation == "apply-epoch" => {
            (authority, health)
        }
        _ => return Err(SemanticProviderError::InvalidTransition(operation)),
    };
    if authority != expected {
        return Err(SemanticProviderError::InvalidTransition(operation));
    }
    if !health.admits_complete() {
        return Err(SemanticProviderError::IncompleteHealth {
            operation,
            health: health.clone(),
        });
    }
    Ok(())
}

/// Admit the sole authority transition whose final coordinate is observed by
/// the provider rather than known by the client before execution. Every
/// client-owned field must remain byte-identical; only the previously absent
/// workspace-resolution digest may be populated.
fn admit_open_session(
    body: &ProviderResponseBody,
    requested: &ProviderAuthority,
    expected_semantic_inputs: Option<&ProviderSemanticInputs>,
    limits: &ProviderFrameLimits,
) -> Result<(ProviderAuthority, ProviderSemanticInputs), SemanticProviderError> {
    reject_error("open-session", body)?;
    if requested.workspace_resolution_sha256.is_some() || requested.semantic_inputs_sha256.is_some()
    {
        return Err(SemanticProviderError::InvalidTransition("open-session"));
    }
    let ProviderResponseBody::SessionOpened {
        authority,
        health,
        semantic_inputs,
    } = body
    else {
        return Err(SemanticProviderError::InvalidTransition("open-session"));
    };
    let mut expected = requested.clone();
    expected.workspace_resolution_sha256 = authority.workspace_resolution_sha256.clone();
    expected.semantic_inputs_sha256 = authority.semantic_inputs_sha256.clone();
    if *authority != expected
        || resolved_authority_configuration_sha256(authority).is_err()
        || provider_semantic_inputs_sha256(semantic_inputs, limits)
            .ok()
            .as_ref()
            != authority.semantic_inputs_sha256.as_ref()
        || expected_semantic_inputs.is_some_and(|expected| expected != semantic_inputs)
    {
        return Err(SemanticProviderError::InvalidTransition("open-session"));
    }
    if !health.admits_complete() {
        return Err(SemanticProviderError::IncompleteHealth {
            operation: "open-session",
            health: health.clone(),
        });
    }
    Ok((authority.clone(), semantic_inputs.clone()))
}

fn admit_reconfigured_session(
    body: &ProviderResponseBody,
    requested: &ProviderAuthority,
    expected_semantic_inputs: &ProviderSemanticInputs,
    limits: &ProviderFrameLimits,
) -> Result<(ProviderAuthority, ProviderSemanticInputs), SemanticProviderError> {
    reject_error("reconfigure-session", body)?;
    if requested.workspace_resolution_sha256.is_some() || requested.semantic_inputs_sha256.is_some()
    {
        return Err(SemanticProviderError::InvalidTransition(
            "reconfigure-session",
        ));
    }
    let ProviderResponseBody::SessionReconfigured {
        authority,
        health,
        semantic_inputs,
    } = body
    else {
        return Err(SemanticProviderError::InvalidTransition(
            "reconfigure-session",
        ));
    };
    let mut expected = requested.clone();
    expected.workspace_resolution_sha256 = authority.workspace_resolution_sha256.clone();
    expected.semantic_inputs_sha256 = authority.semantic_inputs_sha256.clone();
    if *authority != expected
        || resolved_authority_configuration_sha256(authority).is_err()
        || provider_semantic_inputs_sha256(semantic_inputs, limits)
            .ok()
            .as_ref()
            != authority.semantic_inputs_sha256.as_ref()
        || semantic_inputs != expected_semantic_inputs
    {
        return Err(SemanticProviderError::InvalidTransition(
            "reconfigure-session",
        ));
    }
    if !health.admits_complete() {
        return Err(SemanticProviderError::IncompleteHealth {
            operation: "reconfigure-session",
            health: health.clone(),
        });
    }
    Ok((authority.clone(), semantic_inputs.clone()))
}

fn reject_error(
    operation: &'static str,
    body: &ProviderResponseBody,
) -> Result<(), SemanticProviderError> {
    if let ProviderResponseBody::Error { code, message, .. } = body {
        return Err(SemanticProviderError::Rejected {
            operation,
            code: code.clone(),
            message: message.clone(),
        });
    }
    Ok(())
}

fn is_provider_cancellation(error: &SemanticProviderError) -> bool {
    match error {
        SemanticProviderError::Process(SemanticProviderProcessError::Cancelled)
        | SemanticProviderError::Toolchain(ToolchainResolutionError::Cancelled) => true,
        SemanticProviderError::ExecutionRoot { source, .. }
        | SemanticProviderError::PriorAuthorityPreserved { source } => {
            is_provider_cancellation(source)
        }
        _ => false,
    }
}

fn common_limits(
    sessions: &BTreeMap<PathBuf, RootSession>,
) -> Result<ProviderFrameLimits, SemanticProviderError> {
    let mut limits = None;
    for session in sessions.values() {
        let current = session.process.limits();
        if limits.is_some_and(|expected| expected != current) {
            return Err(SemanticProviderError::InconsistentProviderIdentity);
        }
        limits.get_or_insert(current);
    }
    limits.ok_or(SemanticProviderError::NoExecutionRoots)
}

fn combined_semantic_inputs(
    sessions: &BTreeMap<PathBuf, RootSession>,
) -> Result<ProviderSemanticInputs, SemanticProviderError> {
    let mut paths =
        BTreeMap::<(ProviderSemanticPathRoot, String), ProviderSemanticPathInput>::new();
    let mut environment = BTreeMap::<String, ProviderSemanticEnvironmentInput>::new();
    let mut issues = BTreeSet::<ProviderSemanticInputIssue>::new();
    for session in sessions.values() {
        for input in &session.semantic_inputs.paths {
            if paths
                .insert((input.root, input.path.clone()), input.clone())
                .is_some_and(|previous| previous != *input)
            {
                return Err(SemanticProviderError::InvalidTransition(
                    "semantic-input path collision",
                ));
            }
        }
        for input in &session.semantic_inputs.environment {
            if environment
                .insert(input.name.clone(), input.clone())
                .is_some_and(|previous| previous != *input)
            {
                return Err(SemanticProviderError::InvalidTransition(
                    "semantic-input environment collision",
                ));
            }
        }
        issues.extend(session.semantic_inputs.issues.iter().cloned());
    }
    let mut inputs = ProviderSemanticInputs::empty();
    inputs.paths = paths.into_values().collect();
    inputs.environment = environment.into_values().collect();
    if !issues.is_empty() {
        inputs.coverage = ProviderSemanticInputCoverage::Unverifiable;
        inputs.issues = issues.into_iter().collect();
    }
    provider_semantic_inputs_sha256(&inputs, &common_limits(sessions)?)?;
    Ok(inputs)
}

fn provider_invocation_sha256<P: SemanticProviderPolicy>(
    config: &PersistentSemanticProviderConfig<P>,
) -> Result<String, SemanticProviderError> {
    let mut material = Vec::new();
    append_authority_field(&mut material, config.policy.invocation_schema());
    append_authority_field(
        &mut material,
        provider_identity_sha256(&config.expected_identity)?.as_bytes(),
    );
    append_authority_field(
        &mut material,
        &(config.arguments.len() as u64).to_be_bytes(),
    );
    for argument in &config.arguments {
        append_authority_field(&mut material, argument.as_encoded_bytes());
    }
    config.policy.append_invocation_coordinates(&mut material)?;
    Ok(sha256_hex(&material))
}

#[cfg(test)]
fn rust_provider_configuration_sha256(
    config: &RustSemanticProviderConfig,
    resolved_authority_sha256: &str,
) -> Result<String, SemanticProviderError> {
    provider_configuration_sha256(
        &config.clone().into_runtime_config(),
        resolved_authority_sha256,
    )
}

fn provider_configuration_sha256<P: SemanticProviderPolicy>(
    config: &PersistentSemanticProviderConfig<P>,
    resolved_authority_sha256: &str,
) -> Result<String, SemanticProviderError> {
    if resolved_authority_sha256.len() != 64
        || !resolved_authority_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SemanticProviderError::InvalidTransition(
            "resolved-provider-configuration",
        ));
    }
    let mut material = Vec::new();
    append_authority_field(&mut material, config.policy.configuration_schema());
    append_authority_field(&mut material, config.reuse_contract_id().as_bytes());
    append_authority_field(
        &mut material,
        provider_invocation_sha256(config)?.as_bytes(),
    );
    append_authority_field(&mut material, resolved_authority_sha256.as_bytes());
    Ok(sha256_hex(&material))
}

pub fn append_authority_field(material: &mut Vec<u8>, field: &[u8]) {
    material.extend_from_slice(&(field.len() as u64).to_be_bytes());
    material.extend_from_slice(field);
}

fn bind_semantic_inputs(
    mut normalization: ScipArtifactSetNormalization,
    semantic_inputs: ProviderSemanticInputs,
    execution_authority: ProviderExecutionAuthority,
    repository_root: &Path,
    sessions: &BTreeMap<PathBuf, RootSession>,
) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
    // A semantic normalization failure is already a typed, truthful
    // non-complete receipt. Preserve it so the caller can report the real
    // reason and `commit_normalization` can reset the retained session. Only a
    // Complete receipt is required to carry the payload we enrich below.
    if normalization.evidence.receipt.status != CapabilityStatus::Complete {
        if normalization.evidence.payload.is_some() || normalization.canonical_snapshot.is_some() {
            return Err(SemanticProviderError::IncompleteFullCertification);
        }
        return Ok(normalization);
    }
    let Some(normalized_payload) = normalization.evidence.payload.as_mut() else {
        return Err(SemanticProviderError::IncompleteFullCertification);
    };
    let ProviderPayload::Calls(payload) = normalized_payload.payload() else {
        return Err(SemanticProviderError::InvalidTransition(
            "normalized semantic-provider capability",
        ));
    };
    let ProviderExecutionAuthority::InvocationBound {
        provider_configurations_sha256: normalized_configurations,
    } = &payload.execution_authority
    else {
        return Err(SemanticProviderError::InvalidTransition(
            "normalized semantic-provider payload execution authority",
        ));
    };
    let mut session_configurations = BTreeMap::new();
    for (execution_root, session) in sessions {
        let prefix = execution_prefix(repository_root, execution_root)?;
        let configuration = resolved_authority_configuration_sha256(&session.authority)?;
        if session_configurations
            .insert(prefix, configuration)
            .is_some()
        {
            return Err(SemanticProviderError::InvalidTransition(
                "normalized semantic-provider configuration population",
            ));
        }
    }
    if *normalized_configurations != session_configurations {
        return Err(SemanticProviderError::InvalidTransition(
            "normalized semantic-provider configurations",
        ));
    }
    for supplemental in &normalization.supplemental_evidence {
        let Some(payload) = supplemental.payload.as_ref() else {
            return Err(SemanticProviderError::IncompleteFullCertification);
        };
        let ProviderExecutionAuthority::InvocationBound {
            provider_configurations_sha256,
        } = payload.payload().execution_authority()
        else {
            return Err(SemanticProviderError::InvalidTransition(
                "normalized supplemental semantic-provider payload execution authority",
            ));
        };
        if supplemental.receipt.status != CapabilityStatus::Complete
            || supplemental.receipt != *payload.payload().receipt()
            || supplemental.receipt.provider_id != normalization.evidence.receipt.provider_id
            || supplemental.receipt.provider_version
                != normalization.evidence.receipt.provider_version
            || provider_configurations_sha256 != &session_configurations
        {
            return Err(SemanticProviderError::InvalidTransition(
                "normalized supplemental semantic-provider evidence",
            ));
        }
    }
    normalized_payload
        .bind_semantic_authority(semantic_inputs.clone(), execution_authority.clone())
        .map_err(|_| {
            SemanticProviderError::InvalidTransition(
                "normalized semantic-provider payload semantic authority",
            )
        })?;
    for supplemental in &mut normalization.supplemental_evidence {
        supplemental
            .payload
            .as_mut()
            .expect("supplemental payload presence was validated")
            .bind_semantic_authority(semantic_inputs.clone(), execution_authority.clone())
            .map_err(|_| {
                SemanticProviderError::InvalidTransition(
                    "normalized supplemental semantic-provider payload semantic authority",
                )
            })?;
    }
    Ok(normalization)
}

fn calls_payload(normalization: &ScipArtifactSetNormalization) -> Option<&CallsProviderPayload> {
    match normalization.evidence.payload.as_ref()?.payload() {
        ProviderPayload::Calls(payload) => Some(payload),
        ProviderPayload::CallableLiveness(_) => None,
    }
}

fn calls_payload_from_normalized(payload: &NormalizedProviderPayload) -> &CallsProviderPayload {
    match payload.payload() {
        ProviderPayload::Calls(payload) => payload,
        ProviderPayload::CallableLiveness(_) => {
            unreachable!("persistent coordinator retains its primary Calls payload separately")
        }
    }
}

fn unaffected_call_divergences(
    prior: &CallsProviderPayload,
    candidate: &CallsProviderPayload,
    affected: &BTreeSet<String>,
) -> Vec<SemanticTargetDivergence> {
    let prior_calls = unaffected_calls(&prior.calls, affected);
    let candidate_calls = unaffected_calls(&candidate.calls, affected);
    let mut divergences = BTreeSet::new();
    let mut prior_index = 0;
    let mut candidate_index = 0;

    while prior_index < prior_calls.len() && candidate_index < candidate_calls.len() {
        match prior_calls[prior_index].cmp(candidate_calls[candidate_index]) {
            std::cmp::Ordering::Less => {
                divergences.insert(call_divergence(prior_calls[prior_index]));
                prior_index += 1;
            }
            std::cmp::Ordering::Greater => {
                divergences.insert(call_divergence(candidate_calls[candidate_index]));
                candidate_index += 1;
            }
            std::cmp::Ordering::Equal => {
                prior_index += 1;
                candidate_index += 1;
            }
        }
    }
    for call in &prior_calls[prior_index..] {
        divergences.insert(call_divergence(call));
    }
    for call in &candidate_calls[candidate_index..] {
        divergences.insert(call_divergence(call));
    }
    divergences.extend(unaffected_root_invocation_divergences(
        &prior.root_invocations,
        &candidate.root_invocations,
        affected,
    ));
    divergences.into_iter().collect()
}

fn unaffected_root_invocation_divergences(
    prior: &[ProviderRootInvocation],
    candidate: &[ProviderRootInvocation],
    affected: &BTreeSet<String>,
) -> BTreeSet<SemanticTargetDivergence> {
    let prior = prior
        .iter()
        .filter(|invocation| !affected.contains(&invocation.call_site.document_path))
        .collect::<BTreeSet<_>>();
    let candidate = candidate
        .iter()
        .filter(|invocation| !affected.contains(&invocation.call_site.document_path))
        .collect::<BTreeSet<_>>();
    prior
        .symmetric_difference(&candidate)
        .map(|invocation| location_divergence(&invocation.call_site))
        .collect()
}

fn location_divergence(location: &ProviderLocation) -> SemanticTargetDivergence {
    SemanticTargetDivergence {
        document_path: location.document_path.clone(),
        call_site_identity: format!(
            "{}:{}-{}",
            location.document_path, location.span.start_byte, location.span.end_byte
        ),
    }
}

fn unaffected_calls<'a>(
    calls: &'a [ProviderCall],
    affected: &BTreeSet<String>,
) -> Vec<&'a ProviderCall> {
    let mut unaffected = calls
        .iter()
        .filter(|call| !affected.contains(&call.call_site.document_path))
        .collect::<Vec<_>>();
    // Production payloads are already canonical, so this is a linear-order
    // confirmation in practice. Sorting references also keeps this authority
    // check exact for deliberately unnormalized adversarial fixtures without
    // cloning every call-site path and endpoint.
    unaffected.sort_unstable();
    unaffected
}

fn call_divergence(call: &ProviderCall) -> SemanticTargetDivergence {
    SemanticTargetDivergence {
        document_path: call.call_site.document_path.clone(),
        call_site_identity: format!(
            "{}:{}-{}",
            call.call_site.document_path,
            call.call_site.span.start_byte,
            call.call_site.span.end_byte
        ),
    }
}

pub fn execution_prefix(
    repository_root: &Path,
    execution_root: &Path,
) -> Result<String, SemanticProviderError> {
    execution_root
        .strip_prefix(repository_root)
        .map(|path| path.to_string_lossy().replace('\\', "/"))
        .map_err(|_| SemanticProviderError::InvalidRoot(execution_root.display().to_string()))
}

fn path_text(path: &Path) -> Result<&str, SemanticProviderError> {
    path.to_str()
        .ok_or_else(|| SemanticProviderError::InvalidRoot(path.display().to_string()))
}

fn safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[cfg(unix)]
    use std::collections::VecDeque;
    #[cfg(unix)]
    use std::sync::Mutex;

    use tempfile::TempDir;

    use super::*;
    use crate::code_intel_inventory::{InventorySource, build_project_inventory};
    use crate::code_intel_payload::{NormalizedSourceSpan, ProviderDocument, ProviderLocation};
    use crate::code_intel_toolchain::TestToolchainResolver;
    use crate::extractor::extract_file;
    use crate::scip_normalizer::{
        CanonicalSemanticBasis, ScipArtifactEvidence, ScipProviderSpec,
        canonical_normalization_count, canonical_scip_snapshot_from_provider_document_sets,
        reset_canonical_normalization_count,
    };

    #[test]
    fn lifecycle_policy_is_explicit_for_every_adapter_family() {
        let retained_repository_wide = SemanticProviderLifecyclePolicy::new(
            SourceChangedFullCertificationMode::ApplyToRetainedSessions,
            SemanticProviderInvalidationScope::WholeProvider,
        );
        let replace_root_local = SemanticProviderLifecyclePolicy::new(
            SourceChangedFullCertificationMode::ReplaceSessions,
            SemanticProviderInvalidationScope::ExecutionRootLocal,
        );

        assert_eq!(
            RustSemanticProviderPolicy {
                semantic_profile: RustSemanticProfile::workspace_default(),
            }
            .lifecycle_policy(),
            retained_repository_wide
        );
        assert_eq!(
            GoSemanticProviderPolicy.lifecycle_policy(),
            replace_root_local
        );
        for descriptor in [PYREFLY_WORKSPACE_PROVIDER, TYPESCRIPT_WORKSPACE_PROVIDER] {
            assert_eq!(
                WorkspaceSemanticProviderPolicy { descriptor }.lifecycle_policy(),
                retained_repository_wide,
                "{} must declare its lifecycle coordinates explicitly",
                descriptor.language
            );
        }
        assert!(!retained_repository_wide.supports_root_local_refresh());
        assert!(replace_root_local.supports_root_local_refresh());
    }

    #[test]
    fn source_changes_are_grouped_exactly_for_modified_added_and_removed_documents() {
        let source = |path: &str, root: &str, bytes: &[u8]| PreparedSource {
            identity: ProviderSourceIdentity {
                document_path: path.into(),
                language: H00_RUST_ANALYZER_LANGUAGE.into(),
                content_identity: format!("blake3:{}", blake3::hash(bytes).to_hex()),
                content_sha256: sha256_hex(bytes),
            },
            cross_document_surface_sha256: Some(sha256_hex(bytes)),
            execution_root: PathBuf::from(root),
            bytes: bytes.to_vec(),
        };
        let unchanged = source("alpha/src/lib.rs", "alpha", b"pub fn alpha() {}\n");
        let prior = BTreeMap::from([
            ("alpha/src/lib.rs".into(), unchanged.clone()),
            (
                "beta/src/lib.rs".into(),
                source("beta/src/lib.rs", "beta", b"pub fn beta() { old(); }\n"),
            ),
            (
                "gamma/src/lib.rs".into(),
                source("gamma/src/lib.rs", "gamma", b"pub fn removed() {}\n"),
            ),
        ]);
        let current = BTreeMap::from([
            ("alpha/src/lib.rs".into(), unchanged),
            (
                "beta/src/lib.rs".into(),
                source("beta/src/lib.rs", "beta", b"pub fn beta() { new(); }\n"),
            ),
            (
                "delta/src/lib.rs".into(),
                source("delta/src/lib.rs", "delta", b"pub fn added() {}\n"),
            ),
        ]);

        assert_eq!(
            source_changed_documents_by_execution_root(&prior, &current),
            BTreeMap::from([
                (
                    PathBuf::from("beta"),
                    BTreeSet::from(["beta/src/lib.rs".into()]),
                ),
                (
                    PathBuf::from("delta"),
                    BTreeSet::from(["delta/src/lib.rs".into()]),
                ),
                (
                    PathBuf::from("gamma"),
                    BTreeSet::from(["gamma/src/lib.rs".into()]),
                ),
            ]),
            "unchanged roots must retain preflight while every changed population owner is transaction-covered"
        );
    }

    /// RIGHT-REASON REGRESSION: committing a candidate normalization is the
    /// final mutation boundary for retained provider authority. If its typed
    /// activity receipt was never attempted, the transition must fail before
    /// replacing any prior repository, topology, snapshot, payload, or
    /// publication state. A caller-side rollback can restore sessions, but it
    /// cannot safely reconstruct these independently retained fields.
    #[tokio::test]
    async fn failed_commit_receipt_admission_preserves_retained_authority() {
        let temporary = TempDir::new().expect("commit-admission scratch");
        let root = temporary.path().join("repo");
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"commit-admission\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        fs::write(root.join("src/lib.rs"), "pub fn retained() {}\n").expect("source");
        let root = fs::canonicalize(root).expect("canonical repository");
        let inventory = build_project_inventory(
            &root,
            &[InventorySource::new(
                "src/lib.rs",
                H00_RUST_ANALYZER_LANGUAGE,
            )],
        );
        let snapshot = canonical_scip_snapshot_from_provider_document_sets(
            &root,
            ScipProviderSpec::rust_analyzer_sidecar(),
            H00_RUST_ANALYZER_IMPLEMENTATION_V6,
            &BTreeMap::from([(root.clone(), "c".repeat(64))]),
            Vec::new(),
            &inventory,
        )
        .expect("canonical normalization snapshot");
        let mut payload =
            CallsProviderPayload::new(crate::code_intel_domain::CapabilityReceipt::complete(
                "calls",
                H00_RUST_ANALYZER_PROVIDER_ID,
                H00_RUST_ANALYZER_IMPLEMENTATION_V6,
                crate::code_intel_domain::CapabilityScope::Language {
                    language_id: LanguageId::new(H00_RUST_ANALYZER_LANGUAGE),
                    configuration_id: crate::code_intel_domain::ConfigurationId::new(
                        "commit-admission",
                    ),
                },
                "d".repeat(64),
            ));
        payload.canonical_snapshot_sha256 = Some(snapshot.identity_sha256());
        let normalized = normalize_provider_payload_typed(&ProviderPayload::Calls(payload))
            .expect("complete candidate payload");
        let receipt = calls_payload_from_normalized(&normalized).receipt.clone();
        let normalization = ScipArtifactSetNormalization {
            evidence: ScipArtifactEvidence {
                language_id: LanguageId::new(H00_RUST_ANALYZER_LANGUAGE),
                receipt,
                payload: Some(normalized.clone()),
            },
            supplemental_evidence: Vec::new(),
            canonical_snapshot: Some(snapshot.clone()),
            source_syntax_cache: None,
            timings: crate::scip_normalizer::ScipNormalizationTimings::default(),
        };

        let identity = ProviderIdentity {
            protocol: h00ligan_provider_protocol::SEMANTIC_PROVIDER_PROTOCOL.into(),
            provider_id: H00_RUST_ANALYZER_PROVIDER_ID.into(),
            language: H00_RUST_ANALYZER_LANGUAGE.into(),
            implementation_version: H00_RUST_ANALYZER_IMPLEMENTATION_V6.into(),
            source_components: rust_analyzer_source_components(),
            patch_sha256: "a".repeat(64),
            executable_sha256: "b".repeat(64),
        };
        let config = RustSemanticProviderConfig::new(
            "/product/h00ligan",
            identity,
            Arc::new(TestToolchainResolver::default()),
        )
        .expect("coordinator config");
        let mut coordinator = RustSemanticProviderCoordinator::new(config);
        coordinator.repository_root = Some(root.clone());
        coordinator.topology_sha256 = Some("prior-topology".into());
        coordinator.root_topology_sha256 =
            BTreeMap::from([(root.clone(), "prior-root-topology".into())]);
        coordinator.snapshot = Some(snapshot.clone());
        coordinator.payload = Some(normalized.clone());
        coordinator.begin_activity_attempt();

        let result = coordinator
            .commit_normalization(
                normalization,
                root.clone(),
                "candidate-topology".into(),
                BTreeMap::new(),
                &inventory,
                SemanticProviderAdmittedRefreshKind::Full,
            )
            .await;
        let error = match result {
            Ok(_) => panic!("an unattempted operation cannot receive an admitted receipt"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SemanticProviderError::InvalidTransition("provider-activity-operation-not-attempted")
        ));
        assert_eq!(coordinator.repository_root.as_deref(), Some(root.as_path()));
        assert_eq!(
            coordinator.topology_sha256.as_deref(),
            Some("prior-topology")
        );
        assert_eq!(
            coordinator.root_topology_sha256,
            BTreeMap::from([(root, "prior-root-topology".into())])
        );
        assert_eq!(
            coordinator
                .snapshot
                .as_ref()
                .map(CanonicalScipSnapshot::identity_sha256),
            Some(snapshot.identity_sha256())
        );
        assert_eq!(coordinator.payload, Some(normalized));
        assert!(!coordinator.publication_pending);
    }

    fn call(path: &str, start: u64, callee: &str) -> ProviderCall {
        ProviderCall {
            caller_symbol_id: "caller".into(),
            callee_symbol_id: callee.into(),
            call_site: ProviderLocation {
                document_path: path.into(),
                span: NormalizedSourceSpan {
                    start_byte: start,
                    end_byte: start + 1,
                    start_line: 0,
                    start_utf8_byte_column: start as u32,
                    end_line: 0,
                    end_utf8_byte_column: start as u32 + 1,
                },
            },
        }
    }

    fn root_invocation(path: &str, start: u64, callee: &str) -> ProviderRootInvocation {
        ProviderRootInvocation {
            callee_symbol_id: callee.into(),
            context: crate::code_intel_domain::ExecutionRootContext::ModuleInitialization,
            call_site: ProviderLocation {
                document_path: path.into(),
                span: NormalizedSourceSpan {
                    start_byte: start,
                    end_byte: start + 1,
                    start_line: 0,
                    start_utf8_byte_column: start as u32,
                    end_line: 0,
                    end_utf8_byte_column: start as u32 + 1,
                },
            },
        }
    }

    #[test]
    fn unaffected_target_divergence_forces_a_full_candidate() {
        let affected = BTreeSet::from(["src/changed.rs".into()]);
        let prior = CallsProviderPayload {
            calls: vec![
                call("src/unchanged.rs", 4, "target-a"),
                call("src/changed.rs", 8, "old-body-target"),
            ],
            ..CallsProviderPayload::new(crate::code_intel_domain::CapabilityReceipt::complete(
                "calls",
                "provider",
                "version",
                crate::code_intel_domain::CapabilityScope::Language {
                    language_id: LanguageId::new("rust"),
                    configuration_id: crate::code_intel_domain::ConfigurationId::new("config"),
                },
                "fingerprint",
            ))
        };
        let mut candidate = prior.clone();
        candidate.calls = vec![
            call("src/unchanged.rs", 4, "target-b"),
            call("src/changed.rs", 8, "new-body-target"),
        ];
        assert_eq!(
            unaffected_call_divergences(&prior, &candidate, &affected),
            vec![SemanticTargetDivergence {
                document_path: "src/unchanged.rs".into(),
                call_site_identity: "src/unchanged.rs:4-5".into(),
            }]
        );
    }

    #[test]
    fn unaffected_multi_target_divergence_cannot_be_hidden_by_call_site_collision() {
        let affected = BTreeSet::from(["src/changed.rs".into()]);
        let receipt = crate::code_intel_domain::CapabilityReceipt::complete(
            "calls",
            "provider",
            "version",
            crate::code_intel_domain::CapabilityScope::Language {
                language_id: LanguageId::new("go"),
                configuration_id: crate::code_intel_domain::ConfigurationId::new("config"),
            },
            "fingerprint",
        );
        let mut prior = CallsProviderPayload::new(receipt.clone());
        prior.calls = vec![
            call("src/unchanged.go", 4, "target-a"),
            call("src/unchanged.go", 4, "target-z"),
        ];
        let mut candidate = CallsProviderPayload::new(receipt);
        candidate.calls = vec![
            call("src/unchanged.go", 4, "target-b"),
            call("src/unchanged.go", 4, "target-z"),
        ];

        assert_eq!(
            unaffected_call_divergences(&prior, &candidate, &affected),
            vec![SemanticTargetDivergence {
                document_path: "src/unchanged.go".into(),
                call_site_identity: "src/unchanged.go:4-5".into(),
            }],
            "every provider-resolved target is part of the unaffected-call authority proof"
        );
    }

    #[test]
    fn changed_document_calls_do_not_fake_cross_document_divergence() {
        let affected = BTreeSet::from(["src/changed.rs".into()]);
        let receipt = crate::code_intel_domain::CapabilityReceipt::complete(
            "calls",
            "provider",
            "version",
            crate::code_intel_domain::CapabilityScope::Language {
                language_id: LanguageId::new("rust"),
                configuration_id: crate::code_intel_domain::ConfigurationId::new("config"),
            },
            "fingerprint",
        );
        let mut prior = CallsProviderPayload::new(receipt.clone());
        prior.calls = vec![call("src/changed.rs", 8, "old-target")];
        let mut candidate = CallsProviderPayload::new(receipt);
        candidate.calls = vec![call("src/changed.rs", 9, "new-target")];
        assert!(unaffected_call_divergences(&prior, &candidate, &affected).is_empty());
    }

    #[test]
    fn unaffected_root_target_or_ownership_change_forces_a_full_candidate() {
        let affected = BTreeSet::from(["src/changed.ts".into()]);
        let receipt = crate::code_intel_domain::CapabilityReceipt::complete(
            "calls",
            "provider",
            "version",
            crate::code_intel_domain::CapabilityScope::Language {
                language_id: LanguageId::new("typescript"),
                configuration_id: crate::code_intel_domain::ConfigurationId::new("config"),
            },
            "fingerprint",
        );
        let mut prior = CallsProviderPayload::new(receipt.clone());
        prior.root_invocations = vec![root_invocation("src/unchanged.ts", 4, "target-a")];
        let mut changed_target = CallsProviderPayload::new(receipt.clone());
        changed_target.root_invocations = vec![root_invocation("src/unchanged.ts", 4, "target-b")];
        let expected = vec![SemanticTargetDivergence {
            document_path: "src/unchanged.ts".into(),
            call_site_identity: "src/unchanged.ts:4-5".into(),
        }];
        assert_eq!(
            unaffected_call_divergences(&prior, &changed_target, &affected),
            expected
        );

        let mut changed_owner = CallsProviderPayload::new(receipt);
        changed_owner.calls = vec![call("src/unchanged.ts", 4, "target-a")];
        assert_eq!(
            unaffected_call_divergences(&prior, &changed_owner, &affected),
            expected,
            "changing a source occurrence between execution-root and callable ownership must invalidate incremental reuse"
        );
    }

    #[test]
    fn provider_config_requires_the_exact_rust_provider_identity() {
        let exact = ProviderIdentity {
            protocol: h00ligan_provider_protocol::SEMANTIC_PROVIDER_PROTOCOL.into(),
            provider_id: H00_RUST_ANALYZER_PROVIDER_ID.into(),
            language: H00_RUST_ANALYZER_LANGUAGE.into(),
            implementation_version: H00_RUST_ANALYZER_IMPLEMENTATION_V6.into(),
            source_components: rust_analyzer_source_components(),
            patch_sha256: "a".repeat(64),
            executable_sha256: "b".repeat(64),
        };
        assert!(
            RustSemanticProviderConfig::new(
                "h00ligan",
                exact.clone(),
                Arc::new(TestToolchainResolver::default()),
            )
            .is_ok()
        );

        let mut wrong = exact;
        wrong.provider_id = "some-other-provider".into();
        assert!(matches!(
            RustSemanticProviderConfig::new(
                "h00ligan",
                wrong,
                Arc::new(TestToolchainResolver::default()),
            ),
            Err(SemanticProviderConfigError::Identity(_))
        ));
    }

    /// RIGHT-REASON REGRESSION: Python and TypeScript use the same persistent
    /// lifecycle contract, and both analyzers are part of the product rather
    /// than ambient compiler discoveries. They need one identity-driven
    /// adapter family whose private caches stay under the selected data
    /// directory; cloning the Rust/Go coordinators would reintroduce the
    /// language-branch lifecycle this refactor removed.
    #[test]
    fn workspace_provider_family_is_identity_driven_and_cache_confined() {
        let identity = |provider_id: &str,
                        language: &str,
                        implementation_version: &str,
                        source_components| ProviderIdentity {
            protocol: h00ligan_provider_protocol::SEMANTIC_PROVIDER_PROTOCOL.into(),
            provider_id: provider_id.into(),
            language: language.into(),
            implementation_version: implementation_version.into(),
            source_components,
            patch_sha256: "a".repeat(64),
            executable_sha256: "b".repeat(64),
        };
        let python_identity = identity(
            h00ligan_provider_protocol::H00_PYREFLY_PROVIDER_ID,
            h00ligan_provider_protocol::H00_PYREFLY_LANGUAGE,
            h00ligan_provider_protocol::H00_PYREFLY_IMPLEMENTATION_V1,
            h00ligan_provider_protocol::pyrefly_source_components(),
        );
        let typescript_identity = identity(
            h00ligan_provider_protocol::H00_TYPESCRIPT_PROVIDER_ID,
            h00ligan_provider_protocol::H00_TYPESCRIPT_LANGUAGE,
            h00ligan_provider_protocol::H00_TYPESCRIPT_IMPLEMENTATION_V2,
            h00ligan_provider_protocol::typescript_source_components(),
        );
        let resolver = Arc::new(TestToolchainResolver::default());
        let mut python = WorkspaceSemanticProviderConfig::pyrefly(
            "/product/h00-python-provider",
            python_identity,
            resolver.clone(),
        )
        .expect("Python provider config");
        let typescript = WorkspaceSemanticProviderConfig::typescript_native(
            "/product/h00-typescript-provider",
            typescript_identity.clone(),
            resolver.clone(),
        )
        .expect("TypeScript provider config");
        assert_eq!(python.language(), "python");
        assert_eq!(typescript.language(), "typescript");
        assert!(matches!(
            WorkspaceSemanticProviderConfig::pyrefly(
                "/product/h00-python-provider",
                typescript_identity,
                resolver,
            ),
            Err(SemanticProviderConfigError::Identity(_))
        ));

        let cache_root = PathBuf::from("/data/provider-cache-v1");
        python.bind_cache_root(&cache_root);
        let toolchain = ResolvedToolchain::new(
            "python",
            "/repo/python-app",
            crate::code_intel_toolchain::ToolchainOrigin::Managed,
            [],
            None,
            BTreeMap::from([("TMPDIR".into(), "/tmp".into())]),
        )
        .expect("managed Python provider environment");
        let runtime = python.into_runtime_config();
        let process = runtime.process_config(&toolchain);
        let cache_directory = PathBuf::from(
            process
                .environment
                .get(std::ffi::OsStr::new(SEMANTIC_PROVIDER_CACHE_DIR_ENV))
                .expect("private provider cache"),
        );
        assert!(cache_directory.starts_with(&cache_root));
        assert_eq!(
            runtime
                .policy
                .active_cache_directories(&runtime, &toolchain),
            vec![cache_directory]
        );
        assert!(
            !process
                .environment
                .contains_key(std::ffi::OsStr::new("HOME"))
        );
    }

    #[test]
    fn product_provider_defaults_to_an_explicit_portable_cargo_profile() {
        let identity = ProviderIdentity {
            protocol: h00ligan_provider_protocol::SEMANTIC_PROVIDER_PROTOCOL.into(),
            provider_id: H00_RUST_ANALYZER_PROVIDER_ID.into(),
            language: H00_RUST_ANALYZER_LANGUAGE.into(),
            implementation_version: H00_RUST_ANALYZER_IMPLEMENTATION_V6.into(),
            source_components: rust_analyzer_source_components(),
            patch_sha256: "a".repeat(64),
            executable_sha256: "b".repeat(64),
        };
        let config = RustSemanticProviderConfig::new(
            "/product/h00ligan",
            identity,
            Arc::new(TestToolchainResolver::default()),
        )
        .expect("provider config");
        let toolchain = ResolvedToolchain::new(
            "rust",
            "/repo",
            crate::code_intel_toolchain::ToolchainOrigin::System,
            [
                crate::code_intel_toolchain::ResolvedToolchainComponent::new(
                    "cargo",
                    "/toolchain/bin/cargo",
                    "c".repeat(64),
                    "cargo 1.97.1",
                )
                .expect("cargo component"),
                crate::code_intel_toolchain::ResolvedToolchainComponent::new(
                    "rustc",
                    "/toolchain/bin/rustc",
                    "d".repeat(64),
                    "rustc 1.97.1",
                )
                .expect("rustc component"),
            ],
            Some(PathBuf::from("/toolchain")),
            BTreeMap::new(),
        )
        .expect("resolved toolchain");

        let process = config.into_runtime_config().process_config(&toolchain);
        assert_eq!(
            process
                .environment
                .get(&OsString::from("H00_RUST_SEMANTIC_PROFILE"))
                .map(|value| value.to_string_lossy()),
            Some(
                r#"{"schema_version":"h00/rust-semantic-profile/v1","cargo_features":"workspace_default","target":null}"#
                    .into()
            ),
            "portable provider configuration must name its Cargo feature/target profile instead of silently enabling every feature"
        );
        assert_eq!(
            process
                .environment
                .get(&OsString::from(RESOLVED_RUSTC_SHA256_ENV))
                .map(|value| value.to_string_lossy()),
            Some("d".repeat(64).into()),
            "the provider must receive the exact product-resolved rustc executable identity"
        );
        assert_eq!(
            process
                .environment
                .get(&OsString::from(RESOLVED_CARGO_SHA256_ENV))
                .map(|value| value.to_string_lossy()),
            Some("c".repeat(64).into()),
            "the provider must receive the exact product-resolved cargo executable identity"
        );
    }

    /// RIGHT-REASON REGRESSION: Cargo target state is not a toolchain-global
    /// cache. Two detached workspaces may select incompatible feature graphs
    /// under the same compiler, so sharing one target directory makes each
    /// provider session invalidate and rebuild the other's artifacts. The
    /// A large root workspace plus its detached benchmark reproduced this
    /// as thousands of rewritten cache files on every unchanged refresh.
    #[test]
    fn provider_compilation_cache_is_isolated_per_execution_root() {
        let identity = ProviderIdentity {
            protocol: h00ligan_provider_protocol::SEMANTIC_PROVIDER_PROTOCOL.into(),
            provider_id: H00_RUST_ANALYZER_PROVIDER_ID.into(),
            language: H00_RUST_ANALYZER_LANGUAGE.into(),
            implementation_version: H00_RUST_ANALYZER_IMPLEMENTATION_V6.into(),
            source_components: rust_analyzer_source_components(),
            patch_sha256: "a".repeat(64),
            executable_sha256: "b".repeat(64),
        };
        let mut config = RustSemanticProviderConfig::new(
            "/product/h00ligan",
            identity,
            Arc::new(TestToolchainResolver::default()),
        )
        .expect("provider config");
        let cache_root = PathBuf::from("/data/provider-cache-v1");
        config.bind_cache_root(&cache_root);

        let resolved = |execution_root: &str| {
            ResolvedToolchain::new(
                "rust",
                execution_root,
                crate::code_intel_toolchain::ToolchainOrigin::System,
                [
                    crate::code_intel_toolchain::ResolvedToolchainComponent::new(
                        "cargo",
                        "/toolchain/bin/cargo",
                        "c".repeat(64),
                        "cargo 1.97.1",
                    )
                    .expect("cargo component"),
                    crate::code_intel_toolchain::ResolvedToolchainComponent::new(
                        "rustc",
                        "/toolchain/bin/rustc",
                        "d".repeat(64),
                        "rustc 1.97.1",
                    )
                    .expect("rustc component"),
                ],
                Some(PathBuf::from("/toolchain")),
                BTreeMap::new(),
            )
            .expect("resolved toolchain")
        };
        let root_workspace = resolved("/repo");
        let detached_workspace = resolved("/repo/benches/detached");
        assert_eq!(
            root_workspace.fingerprint_sha256(),
            detached_workspace.fingerprint_sha256(),
            "positive control: execution-root identity is deliberately separate from toolchain identity"
        );

        let target_directory = |toolchain: &ResolvedToolchain| {
            config
                .clone()
                .into_runtime_config()
                .process_config(toolchain)
                .environment
                .get(&OsString::from("CARGO_TARGET_DIR"))
                .expect("bound provider target directory")
                .clone()
        };
        let first = target_directory(&root_workspace);
        let repeated = target_directory(&root_workspace);
        let detached = target_directory(&detached_workspace);
        let mut alternate_profile = config.clone();
        alternate_profile
            .set_semantic_profile(RustSemanticProfile::all_features())
            .expect("alternate semantic profile");
        let alternate = alternate_profile
            .into_runtime_config()
            .process_config(&root_workspace)
            .environment
            .get(&OsString::from("CARGO_TARGET_DIR"))
            .expect("alternate-profile target directory")
            .clone();
        assert_eq!(first, repeated, "one root must retain a stable cache key");
        assert_ne!(
            first, detached,
            "detached workspaces must not overwrite one another's Cargo target state"
        );
        assert_ne!(
            first, alternate,
            "different semantic profiles must not overwrite one another's Cargo target state"
        );
        for target in [first, detached, alternate] {
            assert!(
                Path::new(&target).starts_with(&cache_root),
                "provider compilation cache escaped the selected data directory"
            );
        }
    }

    /// RIGHT-REASON REGRESSION: gopls and the Go command default their durable
    /// caches to user-global directories. A pre-existing ambient `GOCACHE`
    /// caused the same 65-file module to alternate between Complete Calls and
    /// an all-document omission after process restart. Both caches are
    /// disposable acceleration, so the product must own both beneath the
    /// selected data bundle. gopls workspace state is execution-root local;
    /// Go's concurrency-safe content-addressed build cache is shared only by
    /// sessions using the exact same resolved toolchain.
    #[test]
    fn go_provider_caches_are_owned_by_the_selected_data_directory() {
        let identity = ProviderIdentity {
            protocol: h00ligan_provider_protocol::SEMANTIC_PROVIDER_PROTOCOL.into(),
            provider_id: H00_GO_PROVIDER_ID.into(),
            language: H00_GO_LANGUAGE.into(),
            implementation_version: H00_GO_IMPLEMENTATION_V4.into(),
            source_components: go_provider_source_components(),
            patch_sha256: "a".repeat(64),
            executable_sha256: "b".repeat(64),
        };
        let mut config = GoSemanticProviderConfig::new(
            "/product/h00-go-provider",
            identity,
            Arc::new(TestToolchainResolver::default()),
        )
        .expect("Go provider config");
        let cache_root = PathBuf::from("/data/provider-cache-v1");
        config.bind_cache_root(&cache_root);

        let resolved = |execution_root: &str, digest: char| {
            ResolvedToolchain::new(
                "go",
                execution_root,
                crate::code_intel_toolchain::ToolchainOrigin::System,
                [
                    crate::code_intel_toolchain::ResolvedToolchainComponent::new(
                        "go",
                        "/toolchain/bin/go",
                        digest.to_string().repeat(64),
                        "go version go1.27.0 linux/amd64",
                    )
                    .expect("Go component"),
                ],
                Some(PathBuf::from("/toolchain")),
                BTreeMap::from([
                    ("GOPLSCACHE".into(), "/ambient/global-cache".into()),
                    ("GOCACHE".into(), "/ambient/go-build-cache".into()),
                    ("HOME".into(), "/home/operator".into()),
                    ("PATH".into(), "/toolchain/bin".into()),
                ]),
            )
            .expect("resolved Go toolchain")
        };
        let root_workspace = resolved("/repo", 'c');
        let detached_workspace = root_workspace
            .rebind_execution_root("/repo/tools/detached")
            .expect("detached execution root");
        let changed_toolchain = resolved("/repo", 'd');
        let cache_for = |name: &str, toolchain: &ResolvedToolchain| {
            config
                .clone()
                .into_runtime_config()
                .process_config(toolchain)
                .environment
                .get(&OsString::from(name))
                .unwrap_or_else(|| panic!("product-owned {name}"))
                .clone()
        };

        let assert_product_owned = |name: &str, value: &OsString, ambient: &str| {
            assert_ne!(value, &OsString::from(ambient));
            assert_ne!(value, &OsString::from("/home/operator/.cache"));
            assert!(
                Path::new(value).starts_with(&cache_root),
                "{name} escaped the selected data directory: {value:?}"
            );
        };

        let gopls = cache_for("GOPLSCACHE", &root_workspace);
        assert_eq!(gopls, cache_for("GOPLSCACHE", &root_workspace));
        assert_ne!(gopls, cache_for("GOPLSCACHE", &detached_workspace));
        assert_ne!(gopls, cache_for("GOPLSCACHE", &changed_toolchain));
        assert_product_owned("GOPLSCACHE", &gopls, "/ambient/global-cache");

        let go_build = cache_for("GOCACHE", &root_workspace);
        assert_eq!(go_build, cache_for("GOCACHE", &root_workspace));
        assert_eq!(
            go_build,
            cache_for("GOCACHE", &detached_workspace),
            "independent roots using one exact Go toolchain need one semantic GOCACHE coordinate"
        );
        assert_ne!(go_build, cache_for("GOCACHE", &changed_toolchain));
        assert_product_owned("GOCACHE", &go_build, "/ambient/go-build-cache");
    }

    #[test]
    fn provider_health_failure_preserves_the_machine_reason() {
        let requested = ProviderAuthority {
            session_id: "session".into(),
            root_sha256: "a".repeat(64),
            root_topology_sha256: "b".repeat(64),
            configuration_sha256: "c".repeat(64),
            workspace_resolution_sha256: None,
            semantic_inputs_sha256: None,
            population_sha256: "d".repeat(64),
            source_epoch: 1,
        };
        let mut resolved = requested.clone();
        resolved.workspace_resolution_sha256 = Some("e".repeat(64));
        let limits = ProviderFrameLimits::default();
        let semantic_inputs = ProviderSemanticInputs::empty();
        resolved.semantic_inputs_sha256 = Some(
            provider_semantic_inputs_sha256(&semantic_inputs, &limits)
                .expect("empty semantic-input digest"),
        );
        let health = ProviderHealthEvidence {
            components: BTreeMap::from([
                (
                    "build_scripts".into(),
                    h00ligan_provider_protocol::ProviderComponentHealth::Failed,
                ),
                (
                    "proc_macros".into(),
                    h00ligan_provider_protocol::ProviderComponentHealth::Healthy,
                ),
                (
                    "workspace_model".into(),
                    h00ligan_provider_protocol::ProviderComponentHealth::Healthy,
                ),
            ]),
            diagnostics_complete: false,
            degradation_reasons: vec!["build scripts: sentinel failure".into()],
        };
        let error = admit_open_session(
            &ProviderResponseBody::SessionOpened {
                authority: resolved,
                health: health.clone(),
                semantic_inputs,
            },
            &requested,
            None,
            &limits,
        )
        .expect_err("degraded provider health cannot become complete authority");
        assert!(matches!(
            error,
            SemanticProviderError::IncompleteHealth {
                operation: "open-session",
                health: observed,
            } if observed == health
        ));
    }

    /// RIGHT-REASON REGRESSION: canonical normalization owns its typed
    /// incomplete receipt. Semantic-input binding must not replace that useful
    /// product reason with a generic "snapshot missing" transport error merely
    /// because incomplete results correctly carry no payload.
    #[test]
    fn semantic_input_binding_preserves_noncomplete_normalization_reason() {
        let normalization = ScipArtifactSetNormalization {
            evidence: crate::scip_normalizer::ScipArtifactEvidence {
                language_id: LanguageId::new("go"),
                receipt: crate::code_intel_domain::CapabilityReceipt::unavailable(
                    "calls",
                    H00_GO_PROVIDER_ID,
                    Some(H00_GO_IMPLEMENTATION_V4.into()),
                    crate::code_intel_domain::CapabilityScope::Language {
                        language_id: LanguageId::new("go"),
                        configuration_id: crate::code_intel_domain::ConfigurationId::new(
                            "calls-v7",
                        ),
                    },
                    None,
                    "provider_document_omitted",
                    "fixture reason survives binding",
                ),
                payload: None,
            },
            supplemental_evidence: Vec::new(),
            canonical_snapshot: None,
            source_syntax_cache: None,
            timings: crate::scip_normalizer::ScipNormalizationTimings::default(),
        };
        let bound = bind_semantic_inputs(
            normalization,
            ProviderSemanticInputs::empty(),
            ProviderExecutionAuthority::InvocationBound {
                provider_configurations_sha256: BTreeMap::new(),
            },
            Path::new("/unused-after-noncomplete"),
            &BTreeMap::new(),
        )
        .expect("non-complete evidence must remain a product result");
        assert_eq!(bound.evidence.receipt.status, CapabilityStatus::Unavailable);
        assert_eq!(
            bound.evidence.receipt.reason_code.as_deref(),
            Some("provider_document_omitted")
        );
        assert_eq!(
            bound.evidence.receipt.reason.as_deref(),
            Some("fixture reason survives binding")
        );
        assert!(bound.evidence.payload.is_none());
        assert!(bound.canonical_snapshot.is_none());
    }

    #[test]
    fn open_session_binds_the_exact_semantic_input_manifest() {
        let requested = ProviderAuthority {
            session_id: "session".into(),
            root_sha256: "a".repeat(64),
            root_topology_sha256: "b".repeat(64),
            configuration_sha256: "c".repeat(64),
            workspace_resolution_sha256: None,
            semantic_inputs_sha256: None,
            population_sha256: "d".repeat(64),
            source_epoch: 1,
        };
        let limits = ProviderFrameLimits::default();
        let semantic_inputs = ProviderSemanticInputs::empty();
        let mut resolved = requested.clone();
        resolved.workspace_resolution_sha256 = Some("e".repeat(64));
        resolved.semantic_inputs_sha256 = Some(
            provider_semantic_inputs_sha256(&semantic_inputs, &limits)
                .expect("semantic-input digest"),
        );
        let health = ProviderHealthEvidence {
            components: BTreeMap::from([(
                "workspace_model".into(),
                h00ligan_provider_protocol::ProviderComponentHealth::Healthy,
            )]),
            diagnostics_complete: true,
            degradation_reasons: Vec::new(),
        };
        let body = ProviderResponseBody::SessionOpened {
            authority: resolved.clone(),
            health: health.clone(),
            semantic_inputs: semantic_inputs.clone(),
        };
        assert_eq!(
            admit_open_session(&body, &requested, Some(&semantic_inputs), &limits)
                .expect("matching manifest must be admitted"),
            (resolved.clone(), semantic_inputs.clone()),
            "positive exact-manifest admission control"
        );

        let mut sabotaged = resolved.clone();
        sabotaged.semantic_inputs_sha256 = Some("f".repeat(64));
        let sabotaged = ProviderResponseBody::SessionOpened {
            authority: sabotaged,
            health: health.clone(),
            semantic_inputs: semantic_inputs.clone(),
        };
        assert!(matches!(
            admit_open_session(
                &sabotaged,
                &requested,
                Some(&ProviderSemanticInputs::empty()),
                &limits,
            ),
            Err(SemanticProviderError::InvalidTransition("open-session"))
        ));

        let mut substituted_inputs = ProviderSemanticInputs::empty();
        substituted_inputs.environment = vec![ProviderSemanticEnvironmentInput {
            name: "GOOS".into(),
            value_sha256: None,
        }];
        let mut substituted_authority = resolved;
        substituted_authority.semantic_inputs_sha256 = Some(
            provider_semantic_inputs_sha256(&substituted_inputs, &limits)
                .expect("substituted semantic-input digest"),
        );
        assert!(matches!(
            admit_open_session(
                &ProviderResponseBody::SessionOpened {
                    authority: substituted_authority,
                    health,
                    semantic_inputs: substituted_inputs,
                },
                &requested,
                Some(&semantic_inputs),
                &limits,
            ),
            Err(SemanticProviderError::InvalidTransition("open-session"))
        ));
    }

    #[test]
    fn reconfigured_session_binds_exact_provider_observed_authority() {
        let requested = ProviderAuthority {
            session_id: "session".into(),
            root_sha256: "a".repeat(64),
            root_topology_sha256: "b".repeat(64),
            configuration_sha256: "c".repeat(64),
            workspace_resolution_sha256: None,
            semantic_inputs_sha256: None,
            population_sha256: "d".repeat(64),
            source_epoch: 2,
        };
        let limits = ProviderFrameLimits::default();
        let semantic_inputs = ProviderSemanticInputs::empty();
        let mut resolved = requested.clone();
        resolved.workspace_resolution_sha256 = Some("e".repeat(64));
        resolved.semantic_inputs_sha256 = Some(
            provider_semantic_inputs_sha256(&semantic_inputs, &limits)
                .expect("semantic-input digest"),
        );
        let health = ProviderHealthEvidence {
            components: BTreeMap::from([(
                "workspace_model".into(),
                h00ligan_provider_protocol::ProviderComponentHealth::Healthy,
            )]),
            diagnostics_complete: true,
            degradation_reasons: Vec::new(),
        };
        let body = ProviderResponseBody::SessionReconfigured {
            authority: resolved.clone(),
            health: health.clone(),
            semantic_inputs: semantic_inputs.clone(),
        };
        assert_eq!(
            admit_reconfigured_session(&body, &requested, &semantic_inputs, &limits)
                .expect("matching reconfiguration must be admitted"),
            (resolved.clone(), semantic_inputs.clone()),
            "positive exact-authority admission control"
        );

        let mut wrong_authority = resolved.clone();
        wrong_authority.source_epoch += 1;
        assert!(matches!(
            admit_reconfigured_session(
                &ProviderResponseBody::SessionReconfigured {
                    authority: wrong_authority,
                    health: health.clone(),
                    semantic_inputs: semantic_inputs.clone(),
                },
                &requested,
                &semantic_inputs,
                &limits,
            ),
            Err(SemanticProviderError::InvalidTransition(
                "reconfigure-session"
            ))
        ));

        let mut wrong_digest = resolved.clone();
        wrong_digest.semantic_inputs_sha256 = Some("f".repeat(64));
        assert!(matches!(
            admit_reconfigured_session(
                &ProviderResponseBody::SessionReconfigured {
                    authority: wrong_digest,
                    health: health.clone(),
                    semantic_inputs: semantic_inputs.clone(),
                },
                &requested,
                &semantic_inputs,
                &limits,
            ),
            Err(SemanticProviderError::InvalidTransition(
                "reconfigure-session"
            ))
        ));

        let mut substituted_inputs = ProviderSemanticInputs::empty();
        substituted_inputs.environment = vec![ProviderSemanticEnvironmentInput {
            name: "GOOS".into(),
            value_sha256: None,
        }];
        let mut substituted_authority = resolved.clone();
        substituted_authority.semantic_inputs_sha256 = Some(
            provider_semantic_inputs_sha256(&substituted_inputs, &limits)
                .expect("substituted semantic-input digest"),
        );
        assert!(matches!(
            admit_reconfigured_session(
                &ProviderResponseBody::SessionReconfigured {
                    authority: substituted_authority,
                    health,
                    semantic_inputs: substituted_inputs,
                },
                &requested,
                &semantic_inputs,
                &limits,
            ),
            Err(SemanticProviderError::InvalidTransition(
                "reconfigure-session"
            ))
        ));

        let degraded = ProviderHealthEvidence {
            components: BTreeMap::from([(
                "workspace_model".into(),
                h00ligan_provider_protocol::ProviderComponentHealth::Failed,
            )]),
            diagnostics_complete: false,
            degradation_reasons: vec!["workspace invalidation failed".into()],
        };
        assert!(matches!(
            admit_reconfigured_session(
                &ProviderResponseBody::SessionReconfigured {
                    authority: resolved,
                    health: degraded,
                    semantic_inputs,
                },
                &requested,
                &ProviderSemanticInputs::empty(),
                &limits,
            ),
            Err(SemanticProviderError::IncompleteHealth {
                operation: "reconfigure-session",
                ..
            })
        ));
    }

    #[test]
    fn provider_population_contains_only_exact_inventory_owned_documents() {
        let temporary = TempDir::new().expect("provider population project");
        let root = temporary.path().join("repo");
        fs::create_dir_all(root.join("src")).expect("package source directory");
        fs::create_dir_all(root.join("providers")).expect("template source directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"provider-population\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        fs::write(root.join("src/lib.rs"), "pub fn owned() {}\n").expect("owned source");
        fs::write(
            root.join("providers/template.rs"),
            "pub fn overlay_template() {}\n",
        )
        .expect("template source");
        let inventory = build_project_inventory(
            &root,
            &[
                InventorySource::new("src/lib.rs", "rust"),
                InventorySource::new("providers/template.rs", "rust"),
            ],
        );
        let indexed_sources = [
            indexed_source(&root, "src/lib.rs"),
            indexed_source(&root, "providers/template.rs"),
        ];
        let prepared = prepare_sources(
            &root,
            std::slice::from_ref(&root),
            &indexed_sources,
            &inventory,
        )
        .expect("prepare exact provider population");
        assert_eq!(
            prepared.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["src/lib.rs"],
            "path containment must not promote a loose/template source into Cargo authority"
        );
        assert!(
            inventory
                .project_topology
                .memberships
                .iter()
                .any(|membership| {
                    membership.document_path == "providers/template.rs"
                        && membership.kind
                            == crate::code_intel_domain::DocumentMembershipKind::SourceOwner
                }),
            "positive loose-source ownership control"
        );
    }

    #[test]
    fn cargo_reload_sensitive_population_is_exact_and_non_vacuous() {
        let temporary = TempDir::new().expect("reload-sensitive project");
        let root = temporary.path().join("repo");
        fs::create_dir_all(root.join("core/src")).expect("core source directory");
        fs::create_dir_all(root.join("core/tools")).expect("core tools directory");
        fs::create_dir_all(root.join("macros/src")).expect("macro source directory");
        fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"core\", \"macros\"]\nresolver = \"3\"\n",
        )
        .expect("workspace manifest");
        fs::write(
            root.join("core/Cargo.toml"),
            "[package]\nname = \"core\"\nversion = \"0.1.0\"\nedition = \"2024\"\nbuild = \"tools/build_main.rs\"\n",
        )
        .expect("core manifest");
        fs::write(root.join("core/src/lib.rs"), "pub fn ordinary() {}\n").expect("ordinary source");
        fs::write(root.join("core/tools/build_main.rs"), "fn main() {}\n")
            .expect("custom build script");
        fs::write(
            root.join("macros/Cargo.toml"),
            "[package]\nname = \"macros\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\nproc-macro = true\n",
        )
        .expect("proc-macro manifest");
        fs::write(root.join("macros/src/lib.rs"), "pub fn macro_entry() {}\n")
            .expect("proc-macro source");
        fs::write(root.join("macros/src/helper.rs"), "pub fn helper() {}\n")
            .expect("proc-macro helper");

        let inventory = build_project_inventory(
            &root,
            &[
                InventorySource::new("core/src/lib.rs", H00_RUST_ANALYZER_LANGUAGE),
                InventorySource::new("core/tools/build_main.rs", H00_RUST_ANALYZER_LANGUAGE),
                InventorySource::new("macros/src/lib.rs", H00_RUST_ANALYZER_LANGUAGE),
                InventorySource::new("macros/src/helper.rs", H00_RUST_ANALYZER_LANGUAGE),
            ],
        );
        let sensitive = rust_provider_reload_sensitive_documents(&root, &inventory)
            .expect("derive exact Cargo reload coordinates");
        assert_eq!(
            sensitive,
            BTreeSet::from([
                "core/tools/build_main.rs".into(),
                "macros/src/helper.rs".into(),
                "macros/src/lib.rs".into(),
            ])
        );
        assert!(
            !sensitive.contains("core/src/lib.rs"),
            "ordinary package source remains eligible for affected-document refresh"
        );
    }

    /// RIGHT-REASON CONCURRENCY REGRESSION: execution roots own independent
    /// provider processes and authority coordinates. Each fake process stops
    /// inside `OpenSession` until every root reaches that same boundary. A
    /// serial coordinator therefore times out on the first root; only actual
    /// overlap can release the barrier and admit both sessions.
    #[cfg(unix)]
    #[tokio::test]
    async fn independent_root_sessions_open_concurrently() {
        use crate::code_intel_semantic_provider_process::test_fixture::{
            FakeProvider, process_exists,
        };
        use crate::code_intel_toolchain::{
            ResolvedToolchainComponent, TestToolchainResolver, ToolchainOrigin,
        };

        assert!(
            std::thread::available_parallelism().is_ok_and(|parallelism| parallelism.get() >= 2),
            "explicit two-root provider overlap requires at least two logical CPUs"
        );
        let fixture = FakeProvider::new();
        let temporary = TempDir::new().expect("multi-root provider project");
        let repository_root = temporary.path().join("repo");
        let barrier = temporary.path().join("open-session-barrier");
        let mut inventory_sources = Vec::new();
        let mut indexed_sources = Vec::new();
        let mut execution_roots = Vec::new();
        let mut toolchains = BTreeMap::new();

        for member in ["alpha", "beta"] {
            let execution_root = repository_root.join(member);
            fs::create_dir_all(execution_root.join("src")).expect("member source directory");
            fs::write(
                execution_root.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{member}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"
                ),
            )
            .expect("member manifest");
            fs::write(
                execution_root.join("src/lib.rs"),
                format!("pub fn {member}_target() {{}}\n"),
            )
            .expect("member source");
            let relative_source = format!("{member}/src/lib.rs");
            inventory_sources.push(InventorySource::new(
                &relative_source,
                H00_RUST_ANALYZER_LANGUAGE,
            ));
        }
        let repository_root = fs::canonicalize(repository_root).expect("canonical repository");
        let inventory = build_project_inventory(&repository_root, &inventory_sources);
        for member in ["alpha", "beta"] {
            let execution_root =
                fs::canonicalize(repository_root.join(member)).expect("canonical execution root");
            indexed_sources.push(indexed_source(
                &repository_root,
                &format!("{member}/src/lib.rs"),
            ));
            let executable = std::env::current_exe().expect("test executable");
            let environment = BTreeMap::from([
                ("MODE".into(), "recertify".into()),
                (
                    "PID_FILE".into(),
                    temporary
                        .path()
                        .join(format!("{member}.pid"))
                        .to_string_lossy()
                        .into_owned(),
                ),
                (
                    "ARGV_FILE".into(),
                    temporary
                        .path()
                        .join(format!("{member}.argv"))
                        .to_string_lossy()
                        .into_owned(),
                ),
                (
                    "REQUEST_LOG".into(),
                    temporary
                        .path()
                        .join(format!("{member}.requests"))
                        .to_string_lossy()
                        .into_owned(),
                ),
                (
                    "OPEN_SESSION_BARRIER".into(),
                    barrier.to_string_lossy().into_owned(),
                ),
                ("OPEN_SESSION_BARRIER_MEMBER".into(), member.into()),
                ("OPEN_SESSION_BARRIER_COUNT".into(), "2".into()),
            ]);
            let toolchain = ResolvedToolchain::new(
                H00_RUST_ANALYZER_LANGUAGE,
                &execution_root,
                ToolchainOrigin::System,
                [
                    ResolvedToolchainComponent::new(
                        "cargo",
                        &executable,
                        "a".repeat(64),
                        "cargo concurrency fixture",
                    )
                    .expect("cargo fixture component"),
                    ResolvedToolchainComponent::new(
                        "rustc",
                        &executable,
                        "b".repeat(64),
                        "rustc concurrency fixture",
                    )
                    .expect("rustc fixture component"),
                ],
                None,
                environment,
            )
            .expect("member toolchain");
            execution_roots.push(execution_root.clone());
            toolchains.insert(execution_root, toolchain);
        }

        let mut config = RustSemanticProviderConfig::new(
            &fixture.binary,
            fixture.identity.clone(),
            Arc::new(TestToolchainResolver::default()),
        )
        .expect("provider config");
        config.request_timeout = Duration::from_secs(2);
        let runtime_config = config.clone().into_runtime_config();
        let current_sources = runtime_config
            .prepare_sources(
                &repository_root,
                &execution_roots,
                &indexed_sources,
                &inventory,
            )
            .expect("prepared provider population");
        let topology_sha256 = runtime_config
            .inventory_fingerprint(&inventory)
            .expect("provider topology");
        let root_topology_sha256 = runtime_config
            .execution_root_inventory_fingerprints(
                &repository_root,
                &execution_roots,
                &inventory,
                &topology_sha256,
            )
            .expect("execution-root topology");
        let mut coordinator = RustSemanticProviderCoordinator::new(config);
        coordinator.set_session_jobs(Some(2));
        coordinator
            .open_sessions(
                &repository_root,
                &current_sources,
                toolchains,
                &root_topology_sha256,
                &inventory,
                &IndexCancellation::new(),
            )
            .await
            .expect("independent root sessions must overlap");

        assert_eq!(coordinator.sessions.len(), 2, "both roots are committed");
        let open_metrics = coordinator
            .activity_attempt
            .as_ref()
            .and_then(|attempt| attempt.session_open.as_ref())
            .expect("session-open telemetry");
        assert_eq!(open_metrics.execution_roots, 2);
        assert_eq!(open_metrics.max_parallelism, 2);
        assert!(
            !open_metrics.duration.is_zero(),
            "session-open wall timing is non-vacuous"
        );
        for member in ["alpha", "beta"] {
            assert!(
                barrier.join(format!("{member}.started")).is_file(),
                "positive barrier control missing for {member}"
            );
        }
        let successful_pids = ["alpha", "beta"].map(|member| {
            fs::read_to_string(temporary.path().join(format!("{member}.pid")))
                .expect("successful provider PID")
                .parse::<i32>()
                .expect("numeric successful provider PID")
        });
        coordinator.reset().await;
        assert!(
            successful_pids.into_iter().all(|pid| !process_exists(pid)),
            "reset must reap every successfully opened provider"
        );
        coordinator.begin_activity_attempt();

        // Sabotage one sibling after both children boot. The successful root
        // must be reaped and no partial session population may become live.
        let executable = std::env::current_exe().expect("test executable");
        let mut failing_toolchains = BTreeMap::new();
        for member in ["alpha", "beta"] {
            let execution_root = fs::canonicalize(repository_root.join(member))
                .expect("canonical failure execution root");
            let environment = BTreeMap::from([
                (
                    "MODE".into(),
                    if member == "alpha" {
                        "recertify".into()
                    } else {
                        "normal".into()
                    },
                ),
                (
                    "PID_FILE".into(),
                    temporary
                        .path()
                        .join(format!("failure-{member}.pid"))
                        .to_string_lossy()
                        .into_owned(),
                ),
                (
                    "ARGV_FILE".into(),
                    temporary
                        .path()
                        .join(format!("failure-{member}.argv"))
                        .to_string_lossy()
                        .into_owned(),
                ),
                (
                    "REQUEST_LOG".into(),
                    temporary
                        .path()
                        .join(format!("failure-{member}.requests"))
                        .to_string_lossy()
                        .into_owned(),
                ),
            ]);
            let toolchain = ResolvedToolchain::new(
                H00_RUST_ANALYZER_LANGUAGE,
                &execution_root,
                ToolchainOrigin::System,
                [
                    ResolvedToolchainComponent::new(
                        "cargo",
                        &executable,
                        "a".repeat(64),
                        "cargo failure fixture",
                    )
                    .expect("cargo failure component"),
                    ResolvedToolchainComponent::new(
                        "rustc",
                        &executable,
                        "b".repeat(64),
                        "rustc failure fixture",
                    )
                    .expect("rustc failure component"),
                ],
                None,
                environment,
            )
            .expect("failure toolchain");
            failing_toolchains.insert(execution_root, toolchain);
        }
        let error = coordinator
            .open_sessions(
                &repository_root,
                &current_sources,
                failing_toolchains,
                &root_topology_sha256,
                &inventory,
                &IndexCancellation::new(),
            )
            .await
            .expect_err("one invalid terminal must reject the whole root population");
        match &error {
            SemanticProviderError::ExecutionRoot { root, source } => {
                assert_eq!(root, &repository_root.join("beta"));
                assert!(matches!(
                    source.as_ref(),
                    SemanticProviderError::Rejected {
                        operation: "open-session",
                        ..
                    }
                ));
            }
            other => panic!(
                "a multi-root provider failure must identify its exact execution root: {other:?}"
            ),
        }
        assert!(coordinator.sessions.is_empty());
        assert!(
            coordinator
                .activity_attempt
                .as_ref()
                .is_some_and(|attempt| attempt.session_open.is_none()),
            "a failed session population must not fabricate open metrics"
        );
        let failed_pids = ["alpha", "beta"].map(|member| {
            fs::read_to_string(temporary.path().join(format!("failure-{member}.pid")))
                .expect("failure provider PID")
                .parse::<i32>()
                .expect("numeric failure provider PID")
        });
        assert!(
            failed_pids.into_iter().all(|pid| !process_exists(pid)),
            "failed population admission must reap every sibling process"
        );
    }

    /// RIGHT-REASON REGRESSION: provider processes are owned per execution
    /// root, so a failed runtime witness for one root must not erase or skip
    /// the independently healthy sibling. The failed boot is quarantined,
    /// every remaining root is still probed, and only the healthy root stays
    /// available for a subsequent affected-root repair.
    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_probe_quarantines_only_the_failed_execution_root() {
        use crate::code_intel_semantic_provider_process::test_fixture::{
            FakeProvider, process_exists,
        };
        use crate::code_intel_toolchain::TestToolchainResolver;

        let temporary = TempDir::new().expect("runtime-probe scratch");
        let alpha_root = temporary.path().join("alpha");
        let beta_root = temporary.path().join("beta");
        fs::create_dir_all(&alpha_root).expect("alpha root");
        fs::create_dir_all(&beta_root).expect("beta root");
        let alpha_root = fs::canonicalize(alpha_root).expect("canonical alpha root");
        let beta_root = fs::canonicalize(beta_root).expect("canonical beta root");

        let alpha_fixture = FakeProvider::new();
        let beta_fixture = FakeProvider::new();
        assert_eq!(
            alpha_fixture.identity, beta_fixture.identity,
            "positive control: both roots run the same provider implementation"
        );
        let alpha_toolchain = sequenced_toolchain(&alpha_root, "runtime-probe");
        let beta_toolchain = sequenced_toolchain(&beta_root, "runtime-probe");
        let alpha_process = SemanticProviderProcess::spawn(alpha_fixture.config_for_toolchain(
            "normal",
            Duration::from_secs(2),
            alpha_toolchain.fingerprint_sha256(),
        ))
        .await
        .expect("alpha provider");
        let beta_process = SemanticProviderProcess::spawn(beta_fixture.config_for_toolchain(
            "normal",
            Duration::from_secs(2),
            beta_toolchain.fingerprint_sha256(),
        ))
        .await
        .expect("beta provider");
        let alpha_pid = alpha_fixture.pid();
        let beta_pid = beta_fixture.pid();
        fs::write(&alpha_fixture.request_log, "").expect("clear alpha startup requests");
        fs::write(&beta_fixture.request_log, "").expect("clear beta startup requests");
        fs::write(&alpha_fixture.request_log, "").expect("clear alpha startup requests");
        fs::write(&beta_fixture.request_log, "").expect("clear beta startup requests");

        let root_session =
            |process: SemanticProviderProcess, toolchain: ResolvedToolchain| RootSession {
                authority: ProviderAuthority {
                    session_id: process.session_id().into(),
                    root_sha256: "a".repeat(64),
                    root_topology_sha256: "b".repeat(64),
                    configuration_sha256: process
                        .runtime_configuration()
                        .configuration_sha256
                        .clone(),
                    workspace_resolution_sha256: Some("c".repeat(64)),
                    semantic_inputs_sha256: Some("d".repeat(64)),
                    population_sha256: "e".repeat(64),
                    source_epoch: 1,
                },
                process,
                toolchain,
                sources: BTreeMap::new(),
                semantic_inputs: ProviderSemanticInputs::empty(),
            };
        let mut config = RustSemanticProviderConfig::new(
            &alpha_fixture.binary,
            alpha_fixture.identity.clone(),
            Arc::new(TestToolchainResolver::default()),
        )
        .expect("coordinator config");
        config.request_timeout = Duration::from_secs(2);
        let mut coordinator = RustSemanticProviderCoordinator::new(config);
        coordinator.sessions.insert(
            alpha_root.clone(),
            root_session(alpha_process, alpha_toolchain),
        );
        coordinator.sessions.insert(
            beta_root.clone(),
            root_session(beta_process, beta_toolchain),
        );

        // SAFETY: this is the exact positive child PID written by the private
        // fixture. Killing it models an independently crashed provider root.
        assert_eq!(unsafe { libc::kill(alpha_pid, libc::SIGKILL) }, 0);
        let error = coordinator
            .probe_session_runtime_authority(&IndexCancellation::new())
            .await
            .expect_err("one crashed root must refuse combined runtime authority");
        assert!(matches!(
            error,
            SemanticProviderError::ExecutionRoot { ref root, .. } if root == &alpha_root
        ));
        assert_eq!(
            coordinator.sessions.keys().collect::<BTreeSet<_>>(),
            BTreeSet::from([&beta_root]),
            "only the failed execution root must be removed"
        );
        assert_eq!(
            fs::read_to_string(&beta_fixture.request_log).expect("beta request log"),
            "hello\n",
            "the positive sibling health probe must actually fire"
        );
        assert!(process_exists(beta_pid), "healthy sibling remains owned");
        assert!(!process_exists(alpha_pid), "failed child must be reaped");

        coordinator.reset().await;
        assert!(
            !process_exists(beta_pid),
            "final reset reaps healthy sibling"
        );
    }

    /// RIGHT-REASON REGRESSION: a root whose imminent provider transaction
    /// carries its own terminal runtime witness must not receive an earlier
    /// speculative Hello. Untouched siblings still require that independent
    /// runtime proof, so the requested subset is both exclusion and positive
    /// non-vacuity control.
    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_probe_honors_the_exact_requested_root_subset() {
        use crate::code_intel_semantic_provider_process::test_fixture::{
            FakeProvider, process_exists,
        };
        use crate::code_intel_toolchain::TestToolchainResolver;

        let temporary = TempDir::new().expect("runtime-probe subset scratch");
        let alpha_root = temporary.path().join("alpha");
        let beta_root = temporary.path().join("beta");
        fs::create_dir_all(&alpha_root).expect("alpha root");
        fs::create_dir_all(&beta_root).expect("beta root");
        let alpha_root = fs::canonicalize(alpha_root).expect("canonical alpha root");
        let beta_root = fs::canonicalize(beta_root).expect("canonical beta root");

        let alpha_fixture = FakeProvider::new();
        let beta_fixture = FakeProvider::new();
        assert_eq!(
            alpha_fixture.identity, beta_fixture.identity,
            "positive control: both roots run the same provider implementation"
        );
        let alpha_toolchain = sequenced_toolchain(&alpha_root, "runtime-probe-subset");
        let beta_toolchain = sequenced_toolchain(&beta_root, "runtime-probe-subset");
        let alpha_process = SemanticProviderProcess::spawn(alpha_fixture.config_for_toolchain(
            "normal",
            Duration::from_secs(2),
            alpha_toolchain.fingerprint_sha256(),
        ))
        .await
        .expect("alpha provider");
        let beta_process = SemanticProviderProcess::spawn(beta_fixture.config_for_toolchain(
            "normal",
            Duration::from_secs(2),
            beta_toolchain.fingerprint_sha256(),
        ))
        .await
        .expect("beta provider");
        let alpha_pid = alpha_fixture.pid();
        let beta_pid = beta_fixture.pid();
        fs::write(&alpha_fixture.request_log, "").expect("clear alpha startup requests");
        fs::write(&beta_fixture.request_log, "").expect("clear beta startup requests");

        let root_session =
            |process: SemanticProviderProcess, toolchain: ResolvedToolchain| RootSession {
                authority: ProviderAuthority {
                    session_id: process.session_id().into(),
                    root_sha256: "a".repeat(64),
                    root_topology_sha256: "b".repeat(64),
                    configuration_sha256: process
                        .runtime_configuration()
                        .configuration_sha256
                        .clone(),
                    workspace_resolution_sha256: Some("c".repeat(64)),
                    semantic_inputs_sha256: Some("d".repeat(64)),
                    population_sha256: "e".repeat(64),
                    source_epoch: 1,
                },
                process,
                toolchain,
                sources: BTreeMap::new(),
                semantic_inputs: ProviderSemanticInputs::empty(),
            };
        let mut config = RustSemanticProviderConfig::new(
            &alpha_fixture.binary,
            alpha_fixture.identity.clone(),
            Arc::new(TestToolchainResolver::default()),
        )
        .expect("coordinator config");
        config.request_timeout = Duration::from_secs(2);
        let mut coordinator = RustSemanticProviderCoordinator::new(config);
        coordinator.sessions.insert(
            alpha_root.clone(),
            root_session(alpha_process, alpha_toolchain),
        );
        coordinator.sessions.insert(
            beta_root.clone(),
            root_session(beta_process, beta_toolchain),
        );

        let changed_documents = BTreeMap::from([(
            alpha_root.clone(),
            BTreeSet::from(["alpha/src/lib.rs".into()]),
        )]);
        assert_eq!(
            coordinator.retained_runtime_preflight_roots(&changed_documents),
            BTreeSet::from([beta_root.clone()]),
            "a changed ordinary source is transaction-witnessed while its untouched sibling is probed"
        );

        coordinator
            .probe_session_runtime_authority_for_roots(
                &BTreeSet::from([beta_root.clone()]),
                &IndexCancellation::new(),
            )
            .await
            .expect("the requested sibling runtime is healthy");
        assert_eq!(
            fs::read_to_string(&alpha_fixture.request_log).expect("alpha request log"),
            "",
            "a transaction-owned root must not receive a redundant Hello"
        );
        assert_eq!(
            fs::read_to_string(&beta_fixture.request_log).expect("beta request log"),
            "hello\n",
            "the untouched sibling runtime proof must actually fire"
        );
        assert!(process_exists(alpha_pid) && process_exists(beta_pid));

        coordinator
            .sessions
            .get_mut(&alpha_root)
            .expect("alpha session")
            .semantic_inputs
            .paths
            .push(ProviderSemanticPathInput {
                root: ProviderSemanticPathRoot::Repository,
                path: "alpha/src/lib.rs".into(),
                kind: ProviderSemanticPathKind::File,
                identity_sha256: "f".repeat(64),
                entry_count: 1,
                byte_length: 1,
            });
        assert_eq!(
            coordinator.retained_runtime_preflight_roots(&changed_documents),
            BTreeSet::from([alpha_root.clone(), beta_root.clone()]),
            "a source that is also a compiler/build input must keep its independent preflight witness"
        );

        fs::write(&alpha_fixture.request_log, "").expect("clear alpha subset requests");
        fs::write(&beta_fixture.request_log, "").expect("clear beta subset requests");
        let missing_root = temporary.path().join("missing");
        let error = coordinator
            .probe_session_runtime_authority_for_roots(
                &BTreeSet::from([missing_root]),
                &IndexCancellation::new(),
            )
            .await
            .expect_err("an unowned requested root must fail closed");
        assert!(matches!(
            error,
            SemanticProviderError::InvalidTransition("runtime-probe-requested-session-missing")
        ));
        assert_eq!(
            fs::read_to_string(&alpha_fixture.request_log).expect("alpha rejected subset log"),
            ""
        );
        assert_eq!(
            fs::read_to_string(&beta_fixture.request_log).expect("beta rejected subset log"),
            "",
            "invalid subset authority must be rejected before any process request"
        );

        // RIGHT-REASON CONTROL for the installed WATCH crash regression: the
        // changed root is intentionally absent from the speculative Hello
        // population above. If it has already exited, local owned-child state
        // must still remove exactly that root before refresh planning; the
        // healthy sibling receives neither a restart nor another request.
        // SAFETY: alpha_pid is the exact child PID written by this fixture.
        assert_eq!(unsafe { libc::kill(alpha_pid, libc::SIGKILL) }, 0);
        let deadline = Instant::now() + Duration::from_secs(2);
        let exited = loop {
            let exited = coordinator
                .discard_observed_exited_sessions()
                .expect("observe exact dead child without provider traffic");
            if !exited.is_empty() {
                break exited;
            }
            assert!(
                Instant::now() < deadline,
                "killed provider never became locally observable"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert_eq!(exited, BTreeSet::from([alpha_root.clone()]));
        assert_eq!(
            coordinator.sessions.keys().collect::<BTreeSet<_>>(),
            BTreeSet::from([&beta_root]),
            "only the already-dead changed root is discarded"
        );
        assert_eq!(
            fs::read_to_string(&alpha_fixture.request_log).expect("alpha local-exit log"),
            "",
            "local exit observation must not reintroduce the skipped Hello"
        );
        assert_eq!(
            fs::read_to_string(&beta_fixture.request_log).expect("beta local-exit log"),
            "",
            "healthy sibling must receive no compensating request"
        );
        assert!(!process_exists(alpha_pid) && process_exists(beta_pid));

        coordinator.reset().await;
        assert!(!process_exists(alpha_pid) && !process_exists(beta_pid));
    }

    /// RIGHT-REASON REGRESSION: a quarantined execution root leaves a useful
    /// partial session population for the next repair, but that subset cannot
    /// re-authorize a complete immutable generation. Exact reuse must cover
    /// every root whose topology and payload authority are being admitted.
    #[cfg(unix)]
    #[tokio::test]
    async fn exact_generation_reuse_refuses_a_partial_retained_session_population() {
        use crate::code_intel_semantic_provider_process::test_fixture::{
            FakeProvider, process_exists,
        };

        let temporary = TempDir::new().expect("partial-reuse scratch");
        let repository_root = temporary.path().join("repo");
        let mut inventory_sources = Vec::new();
        for member in ["alpha", "beta"] {
            let execution_root = repository_root.join(member);
            fs::create_dir_all(execution_root.join("src")).expect("member source directory");
            fs::write(
                execution_root.join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{member}\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"
                ),
            )
            .expect("member manifest");
            fs::write(
                execution_root.join("src/lib.rs"),
                format!("pub fn {member}_target() {{}}\n"),
            )
            .expect("member source");
            inventory_sources.push(InventorySource::new(
                format!("{member}/src/lib.rs"),
                H00_RUST_ANALYZER_LANGUAGE,
            ));
        }
        let repository_root = fs::canonicalize(repository_root).expect("canonical repository");
        let execution_roots = ["alpha", "beta"]
            .map(|member| {
                fs::canonicalize(repository_root.join(member)).expect("canonical execution root")
            })
            .to_vec();
        let indexed_sources = ["alpha", "beta"]
            .map(|member| indexed_source(&repository_root, &format!("{member}/src/lib.rs")))
            .to_vec();
        let inventory = build_project_inventory(&repository_root, &inventory_sources);

        let alpha_root = execution_roots[0].clone();
        let beta_root = execution_roots[1].clone();
        let alpha_toolchain = sequenced_toolchain(&alpha_root, "partial-reuse");
        let beta_toolchain = sequenced_toolchain(&beta_root, "partial-reuse");
        let resolver = Arc::new(SequencedToolchainResolver::new([beta_toolchain.clone()]));
        let alpha_fixture = FakeProvider::new();
        let beta_fixture = FakeProvider::new();
        assert_eq!(
            alpha_fixture.identity, beta_fixture.identity,
            "positive control: both roots use the same provider implementation"
        );
        let alpha_process = SemanticProviderProcess::spawn(alpha_fixture.config_for_toolchain(
            "normal",
            Duration::from_secs(2),
            alpha_toolchain.fingerprint_sha256(),
        ))
        .await
        .expect("alpha provider");
        let beta_process = SemanticProviderProcess::spawn(beta_fixture.config_for_toolchain(
            "normal",
            Duration::from_secs(2),
            beta_toolchain.fingerprint_sha256(),
        ))
        .await
        .expect("beta provider");
        let alpha_pid = alpha_fixture.pid();
        let beta_pid = beta_fixture.pid();

        let mut config = RustSemanticProviderConfig::new(
            &alpha_fixture.binary,
            alpha_fixture.identity.clone(),
            resolver.clone(),
        )
        .expect("coordinator config");
        config.request_timeout = Duration::from_secs(2);
        let runtime_config = config.clone().into_runtime_config();
        let prepared = runtime_config
            .prepare_sources(
                &repository_root,
                &execution_roots,
                &indexed_sources,
                &inventory,
            )
            .expect("prepared source population");
        let topology_sha256 = runtime_config
            .inventory_fingerprint(&inventory)
            .expect("provider topology");
        let root_topology_sha256 = runtime_config
            .execution_root_inventory_fingerprints(
                &repository_root,
                &execution_roots,
                &inventory,
                &topology_sha256,
            )
            .expect("execution-root topology");
        let semantic_inputs = ProviderSemanticInputs::empty();
        let root_session = |process: SemanticProviderProcess,
                            toolchain: ResolvedToolchain,
                            root: &Path|
         -> RootSession {
            RootSession {
                authority: ProviderAuthority {
                    session_id: process.session_id().into(),
                    root_sha256: "a".repeat(64),
                    root_topology_sha256: root_topology_sha256
                        .get(root)
                        .expect("root topology")
                        .clone(),
                    configuration_sha256: process
                        .runtime_configuration()
                        .configuration_sha256
                        .clone(),
                    workspace_resolution_sha256: Some("c".repeat(64)),
                    semantic_inputs_sha256: Some(
                        provider_semantic_inputs_sha256(
                            &semantic_inputs,
                            &ProviderFrameLimits::default(),
                        )
                        .expect("semantic input identity"),
                    ),
                    population_sha256: "e".repeat(64),
                    source_epoch: 1,
                },
                process,
                toolchain,
                sources: sources_for_root(&prepared, root),
                semantic_inputs: semantic_inputs.clone(),
            }
        };

        let mut coordinator = RustSemanticProviderCoordinator::new(config);
        coordinator.repository_root = Some(repository_root.clone());
        coordinator.topology_sha256 = Some(topology_sha256.clone());
        coordinator.root_topology_sha256 = root_topology_sha256.clone();
        coordinator.sources = prepared.clone();
        coordinator.sessions.insert(
            alpha_root.clone(),
            root_session(alpha_process, alpha_toolchain, &alpha_root),
        );
        coordinator.sessions.insert(
            beta_root.clone(),
            root_session(beta_process, beta_toolchain, &beta_root),
        );

        let provider_configurations = coordinator
            .sessions
            .iter()
            .map(|(root, session)| {
                (
                    root.clone(),
                    resolved_authority_configuration_sha256(&session.authority)
                        .expect("resolved provider configuration"),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let snapshot = canonical_scip_snapshot_from_provider_document_sets(
            &repository_root,
            ScipProviderSpec::rust_analyzer_sidecar(),
            H00_RUST_ANALYZER_IMPLEMENTATION_V6,
            &provider_configurations,
            Vec::new(),
            &inventory,
        )
        .expect("canonical multi-root snapshot");
        let project_unit_ids = crate::code_intel_inventory::semantic_provider_unit_execution_roots(
            &inventory,
            H00_RUST_ANALYZER_LANGUAGE,
            "cargo",
        )
        .into_keys()
        .collect::<Vec<_>>();
        assert_eq!(
            project_unit_ids.len(),
            2,
            "positive control: both execution roots have project-unit authority"
        );
        let mut payload =
            CallsProviderPayload::new(crate::code_intel_domain::CapabilityReceipt::complete(
                "calls",
                H00_RUST_ANALYZER_PROVIDER_ID,
                H00_RUST_ANALYZER_IMPLEMENTATION_V6,
                crate::code_intel_domain::CapabilityScope::ProjectUnits {
                    language_id: LanguageId::new(H00_RUST_ANALYZER_LANGUAGE),
                    project_unit_ids,
                    configuration_id: crate::code_intel_domain::ConfigurationId::new(
                        "partial-session-reuse",
                    ),
                },
                "f".repeat(64),
            ));
        payload.semantic_inputs =
            combined_semantic_inputs(&coordinator.sessions).expect("combined semantic inputs");
        payload.execution_authority = coordinator
            .execution_authority(&repository_root, &inventory)
            .expect("complete execution authority");
        payload.documents = prepared
            .values()
            .map(|source| ProviderDocument {
                document_path: source.identity.document_path.clone(),
                language_id: LanguageId::new(&source.identity.language),
                content_sha256: source.identity.content_sha256.clone(),
                cross_document_surface_sha256: source
                    .cross_document_surface_sha256
                    .clone()
                    .expect("prepared cross-document surface"),
                byte_length: source.bytes.len() as u64,
            })
            .collect();
        payload.canonical_snapshot_sha256 = Some(snapshot.identity_sha256());
        let normalized = normalize_provider_payload_typed(&ProviderPayload::Calls(payload))
            .expect("complete two-root payload is canonical");
        let persisted_payload = calls_payload_from_normalized(&normalized).clone();
        coordinator.snapshot = Some(snapshot);
        coordinator.payload = Some(normalized);

        assert_eq!(
            coordinator.sessions.keys().collect::<BTreeSet<_>>(),
            coordinator
                .root_topology_sha256
                .keys()
                .collect::<BTreeSet<_>>(),
            "positive control: admitted live sessions initially cover every payload root"
        );
        assert_eq!(
            coordinator.retained_session_population(),
            RetainedSessionPopulation::Complete
        );
        // SAFETY: this is the exact positive child PID written by the private
        // fixture. Killing it models one independently crashed provider root.
        assert_eq!(unsafe { libc::kill(alpha_pid, libc::SIGKILL) }, 0);
        coordinator
            .probe_session_runtime_authority(&IndexCancellation::new())
            .await
            .expect_err("the crashed root must fail the common runtime witness");
        assert_eq!(
            coordinator.sessions.keys().collect::<BTreeSet<_>>(),
            BTreeSet::from([&beta_root]),
            "positive control: only the healthy sibling remains available for repair"
        );
        assert_eq!(
            coordinator.retained_session_population(),
            RetainedSessionPopulation::RepairRequired,
            "the surviving subset must be represented as repair state, not complete authority"
        );
        assert!(!process_exists(alpha_pid));
        assert!(process_exists(beta_pid));
        let beta_probe_log =
            fs::read_to_string(&beta_fixture.request_log).expect("beta quarantine probe log");
        assert!(
            beta_probe_log.lines().all(|request| request == "hello") && !beta_probe_log.is_empty(),
            "positive control: the healthy sibling runtime witness must fire: {beta_probe_log:?}"
        );

        let authorized = coordinator
            .authorizes_exact_generation_reuse(
                &repository_root,
                &inventory,
                &indexed_sources,
                &[ProviderPayload::Calls(persisted_payload)],
                &IndexCancellation::new(),
            )
            .await;
        assert_eq!(
            resolver.remaining(),
            1,
            "partial coverage must refuse before probing only the surviving root"
        );
        assert_eq!(
            fs::read_to_string(&beta_fixture.request_log).expect("beta request log"),
            beta_probe_log,
            "exact reuse must not probe the surviving subset as complete authority"
        );
        coordinator.reset().await;
        assert!(!process_exists(beta_pid), "test cleanup reaps the sibling");
        assert!(
            !authorized,
            "a surviving subset must not authorize the complete two-root generation"
        );
    }

    fn installed_identity(binary: &Path, receipt: &Path) -> ProviderIdentity {
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipt).expect("provider receipt"))
                .expect("provider receipt JSON");
        let field = |name: &str| {
            receipt[name]
                .as_str()
                .unwrap_or_else(|| panic!("provider receipt field {name}"))
                .to_owned()
        };
        ProviderIdentity {
            protocol: field("protocol"),
            provider_id: field("provider_id"),
            language: field("language"),
            implementation_version: H00_RUST_ANALYZER_IMPLEMENTATION_V6.into(),
            source_components: rust_analyzer_source_components(),
            patch_sha256: field("patch_sha256"),
            executable_sha256: sha256_hex(&fs::read(binary).expect("provider binary")),
        }
    }

    fn indexed_source(root: &Path, relative: &str) -> IndexedSourceEvidence {
        let extracted = extract_file(&root.join(relative), root).expect("extract exact source");
        IndexedSourceEvidence {
            relative_path: relative.into(),
            language: H00_RUST_ANALYZER_LANGUAGE.into(),
            blake3_hash: extracted.file_hash,
            cross_document_surface_sha256: Some(extracted.cross_document_surface_sha256),
        }
    }

    #[cfg(unix)]
    #[derive(Debug)]
    struct SequencedToolchainResolver {
        toolchains: Mutex<VecDeque<ResolvedToolchain>>,
    }

    #[cfg(unix)]
    impl SequencedToolchainResolver {
        fn new(toolchains: impl IntoIterator<Item = ResolvedToolchain>) -> Self {
            Self {
                toolchains: Mutex::new(toolchains.into_iter().collect()),
            }
        }

        fn remaining(&self) -> usize {
            self.toolchains.lock().expect("toolchain sequence").len()
        }
    }

    #[cfg(unix)]
    impl ToolchainResolver for SequencedToolchainResolver {
        fn policy_id(&self, language: &str) -> Result<&'static str, ToolchainResolutionError> {
            if language == H00_RUST_ANALYZER_LANGUAGE {
                Ok("h00/test-sequenced-semantic-toolchain/v1")
            } else {
                Err(ToolchainResolutionError::UnsupportedLanguage(
                    language.into(),
                ))
            }
        }

        fn resolve<'a>(
            &'a self,
            language: &'a str,
            execution_root: &'a Path,
            cancellation: &'a IndexCancellation,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<ResolvedToolchain, ToolchainResolutionError>,
                    > + Send
                    + 'a,
            >,
        > {
            let result = if cancellation.is_cancelled() {
                Err(ToolchainResolutionError::Cancelled)
            } else if language != H00_RUST_ANALYZER_LANGUAGE {
                Err(ToolchainResolutionError::UnsupportedLanguage(
                    language.into(),
                ))
            } else {
                self.toolchains
                    .lock()
                    .expect("toolchain sequence")
                    .pop_front()
                    .ok_or_else(|| {
                        ToolchainResolutionError::Invalid(
                            "test toolchain sequence was exhausted".into(),
                        )
                    })
                    .and_then(|toolchain| {
                        if toolchain.execution_root == execution_root {
                            Ok(toolchain)
                        } else {
                            Err(ToolchainResolutionError::Invalid(
                                "test toolchain root differs from requested root".into(),
                            ))
                        }
                    })
            };
            Box::pin(async move { result })
        }
    }

    #[cfg(unix)]
    fn sequenced_toolchain(root: &Path, epoch: &str) -> ResolvedToolchain {
        let executable = std::env::current_exe().expect("current test executable");
        ResolvedToolchain::new(
            H00_RUST_ANALYZER_LANGUAGE,
            root,
            crate::code_intel_toolchain::ToolchainOrigin::System,
            [
                crate::code_intel_toolchain::ResolvedToolchainComponent::new(
                    "cargo",
                    &executable,
                    "a".repeat(64),
                    format!("cargo test fixture {epoch}"),
                )
                .expect("cargo fixture component"),
                crate::code_intel_toolchain::ResolvedToolchainComponent::new(
                    "rustc",
                    executable,
                    "b".repeat(64),
                    format!("rustc test fixture {epoch}"),
                )
                .expect("rustc fixture component"),
            ],
            None,
            BTreeMap::from([("H00_TEST_TOOLCHAIN_EPOCH".into(), epoch.into())]),
        )
        .expect("resolved test toolchain")
    }

    #[cfg(unix)]
    fn sequenced_toolchain_with_native_cc(
        root: &Path,
        native_cc_sha256: String,
    ) -> ResolvedToolchain {
        let executable = std::env::current_exe().expect("current test executable");
        ResolvedToolchain::new(
            H00_RUST_ANALYZER_LANGUAGE,
            root,
            crate::code_intel_toolchain::ToolchainOrigin::System,
            [
                crate::code_intel_toolchain::ResolvedToolchainComponent::new(
                    "cargo",
                    &executable,
                    "a".repeat(64),
                    "cargo test fixture",
                )
                .expect("cargo fixture component"),
                crate::code_intel_toolchain::ResolvedToolchainComponent::new(
                    "rustc",
                    &executable,
                    "b".repeat(64),
                    "rustc test fixture",
                )
                .expect("rustc fixture component"),
                crate::code_intel_toolchain::ResolvedToolchainComponent::new(
                    "native-cc",
                    &executable,
                    native_cc_sha256,
                    "cc fixture 1.0",
                )
                .expect("native CC fixture component"),
            ],
            None,
            BTreeMap::from([("CC".into(), executable.to_string_lossy().into_owned())]),
        )
        .expect("resolved native-build test toolchain")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn terminal_semantic_input_policy_rechecks_complete_and_skips_only_unverifiable() {
        use crate::code_intel_semantic_provider_process::test_fixture::{
            FakeProvider, process_exists,
        };
        use h00ligan_provider_protocol::{
            capture_provider_semantic_inputs, validate_provider_semantic_inputs,
        };

        let temporary = TempDir::new().expect("semantic-input policy project");
        let root = temporary.path().join("repo");
        fs::create_dir_all(&root).expect("project root");
        fs::write(root.join("semantic-input.txt"), "before\n").expect("semantic input");
        let root = fs::canonicalize(root).expect("canonical project root");
        let limits = ProviderFrameLimits::default();
        let complete = capture_provider_semantic_inputs(
            &root,
            &BTreeSet::from(["semantic-input.txt".into()]),
            &BTreeSet::new(),
            &limits,
        )
        .expect("complete semantic inputs");

        let fixture = FakeProvider::new();
        let toolchain = sequenced_toolchain(&root, "semantic-input-policy");
        let process = SemanticProviderProcess::spawn(fixture.config_for_toolchain(
            "normal",
            Duration::from_secs(2),
            toolchain.fingerprint_sha256(),
        ))
        .await
        .expect("supervised provider session");
        let provider_pid = fixture.pid();
        let authority = ProviderAuthority {
            session_id: process.session_id().into(),
            root_sha256: "a".repeat(64),
            root_topology_sha256: "b".repeat(64),
            configuration_sha256: process.runtime_configuration().configuration_sha256.clone(),
            workspace_resolution_sha256: Some("c".repeat(64)),
            semantic_inputs_sha256: Some(
                provider_semantic_inputs_sha256(&complete, &limits)
                    .expect("complete semantic-input identity"),
            ),
            population_sha256: "d".repeat(64),
            source_epoch: 1,
        };
        let resolver = Arc::new(TestToolchainResolver::new(BTreeMap::new()));
        let config =
            RustSemanticProviderConfig::new(&fixture.binary, fixture.identity.clone(), resolver)
                .expect("provider config");
        let mut coordinator = RustSemanticProviderCoordinator::new(config);
        coordinator.sessions.insert(
            root.clone(),
            RootSession {
                process,
                toolchain,
                authority,
                sources: BTreeMap::new(),
                semantic_inputs: complete.clone(),
            },
        );
        assert!(
            coordinator
                .session_semantic_inputs_are_current(&root)
                .expect("complete manifest observation"),
            "positive control: unchanged complete inputs are current"
        );

        fs::write(root.join("semantic-input.txt"), "after\n").expect("drift semantic input");
        assert!(
            !coordinator
                .session_semantic_inputs_are_current(&root)
                .expect("complete manifest drift observation"),
            "a changed complete manifest must fail the terminal authority check"
        );

        let mut unverifiable = complete;
        unverifiable.coverage = ProviderSemanticInputCoverage::Unverifiable;
        unverifiable.issues = vec![ProviderSemanticInputIssue {
            code: "test-unverifiable".into(),
            path: "semantic-input.txt".into(),
            detail: "fixture deliberately models an input that cannot be reproduced".into(),
        }];
        validate_provider_semantic_inputs(&unverifiable, &limits)
            .expect("valid explicit unverifiable manifest");
        coordinator
            .sessions
            .get_mut(&root)
            .expect("owned root session")
            .semantic_inputs = unverifiable;
        assert!(
            coordinator
                .session_semantic_inputs_are_current(&root)
                .expect("unverifiable policy boundary"),
            "only an explicit unverifiable manifest may skip reproducible terminal observation"
        );

        coordinator.reset().await;
        assert!(
            !process_exists(provider_pid),
            "reset must reap the test provider"
        );
    }

    /// RIGHT-REASON REGRESSION: a closed immutable generation must not reload
    /// the Cargo workspace merely to prove that its exact deterministic inputs
    /// and provider runtime are unchanged. A fresh process Hello is the live
    /// identity witness; the persisted reconstruction descriptor plus current
    /// source/project/input observations provide the remaining coordinates.
    #[cfg(unix)]
    #[tokio::test]
    async fn fresh_exact_session_recertifies_generation_without_full_export() {
        use crate::code_intel_semantic_provider_process::test_fixture::{
            FakeProvider, process_exists,
        };
        use h00ligan_provider_protocol::capture_provider_semantic_inputs;

        let temporary = TempDir::new().expect("fresh recertification project");
        let root = temporary.path().join("repo");
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fresh-recertification\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        fs::write(root.join("Cargo.lock"), "version = 4\n").expect("dependency lock");
        fs::write(
            root.join("src/lib.rs"),
            "pub fn target() {}\npub fn caller() { target(); }\n",
        )
        .expect("source");
        let root = fs::canonicalize(root).expect("canonical project root");
        let inventory = build_project_inventory(
            &root,
            &[InventorySource::new(
                "src/lib.rs",
                H00_RUST_ANALYZER_LANGUAGE,
            )],
        );
        let indexed_sources = [indexed_source(&root, "src/lib.rs")];
        let prepared = prepare_sources(
            &root,
            std::slice::from_ref(&root),
            &indexed_sources,
            &inventory,
        )
        .expect("prepared source population");
        let source = prepared.get("src/lib.rs").expect("prepared source");

        let fixture = FakeProvider::new();
        let resolver = Arc::new(TestToolchainResolver::new(BTreeMap::from([
            ("MODE".into(), "recertify".into()),
            (
                "PID_FILE".into(),
                fixture.pid_file.to_string_lossy().into_owned(),
            ),
            (
                "ARGV_FILE".into(),
                fixture.argv_file.to_string_lossy().into_owned(),
            ),
            (
                "REQUEST_LOG".into(),
                fixture.request_log.to_string_lossy().into_owned(),
            ),
        ])));
        let cancellation = IndexCancellation::new();
        let toolchain = resolver
            .resolve(H00_RUST_ANALYZER_LANGUAGE, &root, &cancellation)
            .await
            .expect("resolved toolchain");
        let runtime = h00ligan_provider_protocol::rust_analyzer_runtime_configuration(
            toolchain.fingerprint_sha256(),
            b"fake-rustc-vV",
            b"fake-cargo-V",
            b"fake-sysroot",
            b"fake-cleared-environment",
            b"fake-workspace-configuration",
        )
        .expect("construct fake provider runtime configuration");
        let semantic_inputs = ProviderSemanticInputs::empty();
        let authority = ProviderAuthority {
            session_id: "persisted-session-is-not-authority".into(),
            root_sha256: sha256_hex(path_text(&root).expect("UTF-8 root").as_bytes()),
            root_topology_sha256: rust_provider_inventory_fingerprint(&inventory)
                .expect("provider inventory fingerprint"),
            configuration_sha256: runtime.configuration_sha256,
            workspace_resolution_sha256: Some(sha256_hex(b"fake-workspace-resolution")),
            semantic_inputs_sha256: Some(
                provider_semantic_inputs_sha256(&semantic_inputs, &ProviderFrameLimits::default())
                    .expect("semantic input digest"),
            ),
            population_sha256: source_population_sha256(
                std::slice::from_ref(&source.identity),
                &ProviderFrameLimits::default(),
            )
            .expect("source population digest"),
            source_epoch: 1,
        };
        let resolved_configuration = resolved_authority_configuration_sha256(&authority)
            .expect("resolved provider configuration");
        let mut config = RustSemanticProviderConfig::new(
            &fixture.binary,
            fixture.identity.clone(),
            resolver.clone(),
        )
        .expect("provider config");
        config.request_timeout = Duration::from_secs(2);
        config.arguments = Vec::new();
        let provider_configuration =
            rust_provider_configuration_sha256(&config, &resolved_configuration)
                .expect("durable provider configuration");
        let implementation =
            provider_identity_sha256(&fixture.identity).expect("provider implementation identity");
        let configurations = BTreeMap::from([(String::new(), provider_configuration)]);
        let reconstructions = BTreeMap::from([(
            String::new(),
            ProviderGenerationReconstruction::ObservedWorkspace {
                runtime_configuration_sha256: authority.configuration_sha256.clone(),
                workspace_resolution_sha256: authority
                    .workspace_resolution_sha256
                    .clone()
                    .expect("workspace resolution descriptor"),
                semantic_inputs: semantic_inputs.clone(),
            },
        )]);
        let toolchains = BTreeMap::from([(root.clone(), toolchain)]);
        let execution_authority =
            toolchain_bound_execution_authority(ToolchainBoundAuthorityInput {
                repository_root: &root,
                inventory: &inventory,
                language: H00_RUST_ANALYZER_LANGUAGE,
                ecosystem: "cargo",
                resolver_policy_id: resolver
                    .policy_id(H00_RUST_ANALYZER_LANGUAGE)
                    .expect("Rust resolver policy"),
                reuse_contract_id: RUST_OPEN_SESSION_REUSE_CONTRACT_ID,
                provider_implementation_sha256: &implementation,
                provider_configurations_sha256: &configurations,
                reconstruction_descriptors: Some(&reconstructions),
                toolchains: &toolchains,
            })
            .expect("toolchain-bound provider authority");
        let project_unit_ids: Vec<_> = match &execution_authority {
            ProviderExecutionAuthority::ToolchainBound { roots, .. } => roots
                .iter()
                .flat_map(|root| root.project_unit_ids.iter().cloned())
                .collect(),
            ProviderExecutionAuthority::InvocationBound { .. } => {
                panic!("expected toolchain-bound authority")
            }
        };
        let mut payload =
            CallsProviderPayload::new(crate::code_intel_domain::CapabilityReceipt::complete(
                "calls",
                H00_RUST_ANALYZER_PROVIDER_ID,
                H00_RUST_ANALYZER_IMPLEMENTATION_V6,
                crate::code_intel_domain::CapabilityScope::ProjectUnits {
                    language_id: LanguageId::new(H00_RUST_ANALYZER_LANGUAGE),
                    project_unit_ids: project_unit_ids.clone(),
                    configuration_id: crate::code_intel_domain::ConfigurationId::new(
                        "fresh-recertification",
                    ),
                },
                "f".repeat(64),
            ));
        payload.semantic_inputs = semantic_inputs;
        payload.execution_authority = execution_authority;
        payload.documents = vec![ProviderDocument {
            document_path: source.identity.document_path.clone(),
            language_id: LanguageId::new(&source.identity.language),
            content_sha256: source.identity.content_sha256.clone(),
            cross_document_surface_sha256: source
                .cross_document_surface_sha256
                .clone()
                .expect("cross-document surface"),
            byte_length: source.bytes.len() as u64,
        }];
        let mut canonical_document = scip::types::Document::new();
        canonical_document.relative_path = source.identity.document_path.clone();
        canonical_document.language = source.identity.language.clone();
        canonical_document.text = String::from_utf8(source.bytes.clone()).expect("UTF-8 source");
        let persisted_snapshot = canonical_scip_snapshot_from_provider_document_sets(
            &root,
            ScipProviderSpec::rust_analyzer_sidecar(),
            H00_RUST_ANALYZER_IMPLEMENTATION_V6,
            &BTreeMap::from([(
                root.clone(),
                configurations
                    .get("")
                    .expect("root provider configuration")
                    .clone(),
            )]),
            vec![canonical_document],
            &inventory,
        )
        .expect("persisted canonical snapshot");
        payload.canonical_snapshot_sha256 = Some(persisted_snapshot.identity_sha256());
        let normalized_payload = crate::code_intel_payload::normalize_provider_payload_typed(
            &ProviderPayload::Calls(payload.clone()),
        )
        .expect("persisted recertifiable payload must pass canonical admission");
        let mut supplemental_payload =
            crate::code_intel_payload::CallableLivenessProviderPayload::new(
                crate::code_intel_domain::CapabilityReceipt::complete(
                    "callable_liveness",
                    H00_RUST_ANALYZER_PROVIDER_ID,
                    H00_RUST_ANALYZER_IMPLEMENTATION_V6,
                    crate::code_intel_domain::CapabilityScope::ProjectUnits {
                        language_id: LanguageId::new(H00_RUST_ANALYZER_LANGUAGE),
                        project_unit_ids,
                        configuration_id: crate::code_intel_domain::ConfigurationId::new(
                            crate::code_intel_domain::CALLABLE_LIVENESS_CONFIGURATION_ID,
                        ),
                    },
                    "e".repeat(64),
                ),
            );
        supplemental_payload.semantic_inputs = payload.semantic_inputs.clone();
        supplemental_payload.execution_authority = payload.execution_authority.clone();
        supplemental_payload.documents = payload.documents.clone();
        let normalized_supplemental = crate::code_intel_payload::normalize_provider_payload_typed(
            &ProviderPayload::CallableLiveness(supplemental_payload.clone()),
        )
        .expect("persisted supplemental capability must pass canonical admission");
        let persisted_basis = CanonicalSemanticBasis {
            snapshot: persisted_snapshot,
            evidence: ScipArtifactEvidence {
                language_id: LanguageId::new(H00_RUST_ANALYZER_LANGUAGE),
                receipt: payload.receipt.clone(),
                payload: Some(normalized_payload),
            },
            supplemental_evidence: vec![ScipArtifactEvidence {
                language_id: LanguageId::new(H00_RUST_ANALYZER_LANGUAGE),
                receipt: supplemental_payload.receipt.clone(),
                payload: Some(normalized_supplemental),
            }],
            source_syntax_cache: None,
        };
        assert_eq!(
            persisted_basis.supplemental_evidence.len(),
            1,
            "positive control: the immutable basis carries one admitted supplemental capability"
        );
        assert!(
            persisted_basis.source_syntax_cache.is_none(),
            "positive control: cross-process canonical cache starts without process-local syntax"
        );

        let base_config = config.clone();
        let persisted_payload = payload.clone();
        let mut coordinator = RustSemanticProviderCoordinator::new(config);

        let authorized = coordinator
            .authorize_and_hydrate_exact_generation_reuse(
                &root,
                &inventory,
                &indexed_sources,
                &[ProviderPayload::Calls(payload.clone())],
                std::slice::from_ref(&persisted_basis),
                &cancellation,
            )
            .await;
        let operations = fs::read_to_string(&fixture.request_log)
            .expect("provider request log")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert!(
            authorized,
            "a fresh exact session must recertify the immutable generation: {operations:?}"
        );
        assert_eq!(
            coordinator.supplemental_evidence, persisted_basis.supplemental_evidence,
            "exact cross-process hydration must retain supplemental evidence for the next affected refresh"
        );

        // RIGHT-REASON REGRESSION: exact-basis admission delegates source
        // authority to `authorizes_exact_generation_reuse`. That owner may
        // observe the opening epoch and a terminal epoch around live runtime
        // recertification, but callers must not perform speculative duplicate
        // scans before entering it.
        coordinator.config.reset_prepare_sources_call_count();
        let reused = coordinator
            .reuse_exact_canonical_basis(
                &root,
                &inventory,
                &indexed_sources,
                std::slice::from_ref(&persisted_basis),
                &cancellation,
            )
            .await
            .expect("the exact nonempty canonical basis remains reusable");
        assert!(
            reused.canonical_snapshot.is_some() && reused.evidence.payload.is_some(),
            "positive control: reuse returned the persisted snapshot and evidence"
        );
        assert_eq!(
            coordinator.config.prepare_sources_call_count(),
            2,
            "exact basis reuse must have one authority-owned opening observation and one terminal drift observation"
        );
        assert!(operations.contains(&"hello".into()), "{operations:?}");
        assert!(
            operations.contains(&"close_session".into()),
            "identity-only recertification must close explicitly: {operations:?}"
        );
        assert!(
            !operations.contains(&"open_session".into()),
            "closed-input recertification must not reload the workspace: {operations:?}"
        );
        assert!(
            !operations.contains(&"certify_full".into()),
            "fresh recertification must not export the full graph: {operations:?}"
        );
        assert!(
            coordinator.source_syntax_cache.is_some(),
            "exact cross-process hydration must prime syntax acceleration from verified current bytes"
        );
        assert!(
            coordinator
                .exact_canonical_basis_candidate(std::slice::from_ref(&persisted_basis))
                .and_then(|candidate| {
                    coordinator.attach_authorized_exact_canonical_basis(candidate)
                })
                .is_some(),
            "positive control: the same exact canonical basis remains attachable"
        );
        assert!(
            coordinator.source_syntax_cache.is_some(),
            "an exact-reuse basis without serialized syntax must not erase the live verified cache"
        );
        let provider_pid = fixture.pid();
        assert!(
            !process_exists(provider_pid),
            "identity-only recertification must reap its disposable provider"
        );
        coordinator.reset().await;
        assert!(!process_exists(provider_pid), "reset remains residue-free");

        fs::remove_file(&fixture.request_log).expect("clear positive request log");

        // FALSIFIER for mixed-language WATCH authority: adding an unrelated
        // Go project unit changes the generation-wide repository inventory,
        // but it must not invalidate or rewrite the persisted Rust provider
        // authority. This crosses the real recertification consumer rather
        // than merely rechecking the projection helper.
        fs::write(
            root.join("go.mod"),
            "module example.invalid/unrelated\n\ngo 1.27\n",
        )
        .expect("unrelated Go manifest");
        fs::write(root.join("unrelated.go"), "package unrelated\n").expect("unrelated Go source");
        let mixed_inventory = build_project_inventory(
            &root,
            &[
                InventorySource::new("src/lib.rs", H00_RUST_ANALYZER_LANGUAGE),
                InventorySource::new("unrelated.go", "go"),
            ],
        );
        let go_extracted =
            extract_file(&root.join("unrelated.go"), &root).expect("extract unrelated Go source");
        let mixed_indexed_sources = [
            indexed_sources[0].clone(),
            IndexedSourceEvidence {
                relative_path: "unrelated.go".into(),
                language: "go".into(),
                blake3_hash: go_extracted.file_hash,
                cross_document_surface_sha256: Some(go_extracted.cross_document_surface_sha256),
            },
        ];
        assert_ne!(
            crate::code_intel_inventory::project_inventory_fingerprint(&inventory)
                .expect("Rust-only global inventory"),
            crate::code_intel_inventory::project_inventory_fingerprint(&mixed_inventory)
                .expect("mixed global inventory"),
            "positive control: unrelated Go topology must change repository identity"
        );
        assert_eq!(
            rust_provider_inventory_fingerprint(&inventory).expect("Rust-only provider inventory"),
            rust_provider_inventory_fingerprint(&mixed_inventory)
                .expect("mixed Rust provider inventory"),
            "unrelated Go topology must not change Rust provider identity"
        );
        let mut mixed_coordinator = RustSemanticProviderCoordinator::new(base_config.clone());
        assert!(
            mixed_coordinator
                .authorizes_exact_generation_reuse(
                    &root,
                    &mixed_inventory,
                    &mixed_indexed_sources,
                    &[ProviderPayload::Calls(persisted_payload.clone())],
                    &cancellation,
                )
                .await,
            "unrelated Go inventory drift must preserve exact Rust generation reuse"
        );
        let mixed_operations = fs::read_to_string(&fixture.request_log)
            .expect("mixed-inventory provider request log")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert!(
            mixed_operations.contains(&"hello".into()),
            "{mixed_operations:?}"
        );
        assert!(
            !mixed_operations.contains(&"open_session".into())
                && !mixed_operations.contains(&"certify_full".into()),
            "unrelated Go drift must not reload or re-export Rust: {mixed_operations:?}"
        );
        let mixed_provider_pid = fixture.pid();
        mixed_coordinator.reset().await;
        assert!(
            !process_exists(mixed_provider_pid),
            "mixed-inventory recertification must remain residue-free"
        );
        fs::remove_file(&fixture.request_log).expect("clear mixed-inventory request log");
        fs::remove_file(root.join("go.mod")).expect("remove unrelated Go manifest");
        fs::remove_file(root.join("unrelated.go")).expect("remove unrelated Go source");

        let mut wrong_implementation = persisted_payload.clone();
        let ProviderExecutionAuthority::ToolchainBound {
            provider_implementation_sha256,
            ..
        } = &mut wrong_implementation.execution_authority
        else {
            panic!("recertification fixture authority")
        };
        *provider_implementation_sha256 = "0".repeat(64);
        let mut identity_rejected = RustSemanticProviderCoordinator::new(base_config.clone());
        assert!(
            !identity_rejected
                .authorizes_exact_generation_reuse(
                    &root,
                    &inventory,
                    &indexed_sources,
                    &[ProviderPayload::Calls(wrong_implementation)],
                    &cancellation,
                )
                .await,
            "changed provider implementation identity must refuse reuse"
        );
        assert!(
            !fixture.request_log.exists(),
            "known provider-identity drift must fail before child startup"
        );

        let mut descriptor_drift = persisted_payload.clone();
        let ProviderExecutionAuthority::ToolchainBound { roots, .. } =
            &mut descriptor_drift.execution_authority
        else {
            panic!("recertification fixture authority")
        };
        let ProviderGenerationReconstruction::ObservedWorkspace {
            runtime_configuration_sha256,
            ..
        } = &mut roots[0].generation_reconstruction
        else {
            panic!("observed workspace descriptor")
        };
        *runtime_configuration_sha256 = "0".repeat(64);
        let mut descriptor_rejected = RustSemanticProviderCoordinator::new(base_config.clone());
        assert!(
            !descriptor_rejected
                .authorizes_exact_generation_reuse(
                    &root,
                    &inventory,
                    &indexed_sources,
                    &[ProviderPayload::Calls(descriptor_drift)],
                    &cancellation,
                )
                .await,
            "altered reconstruction descriptor must refuse reuse"
        );
        assert!(
            !fixture.request_log.exists(),
            "descriptor inconsistency must fail before child startup"
        );

        let semantic_input_path = root.join("semantic-input.txt");
        fs::write(&semantic_input_path, "semantic-input-before\n").expect("semantic input fixture");
        let observed_inputs = capture_provider_semantic_inputs(
            &root,
            &BTreeSet::from(["semantic-input.txt".into()]),
            &BTreeSet::new(),
            &ProviderFrameLimits::default(),
        )
        .expect("observed semantic input");
        let mut semantic_input_payload = persisted_payload.clone();
        semantic_input_payload.semantic_inputs = observed_inputs.clone();
        let ProviderExecutionAuthority::ToolchainBound { roots, .. } =
            &mut semantic_input_payload.execution_authority
        else {
            panic!("recertification fixture authority")
        };
        let root_authority = &mut roots[0];
        let ProviderGenerationReconstruction::ObservedWorkspace {
            runtime_configuration_sha256,
            workspace_resolution_sha256,
            semantic_inputs,
        } = &mut root_authority.generation_reconstruction
        else {
            panic!("observed workspace descriptor")
        };
        *semantic_inputs = observed_inputs;
        let semantic_inputs_sha256 =
            provider_semantic_inputs_sha256(semantic_inputs, &ProviderFrameLimits::default())
                .expect("semantic input descriptor digest");
        let resolved_configuration = resolved_workspace_configuration_sha256(
            runtime_configuration_sha256,
            workspace_resolution_sha256,
            &semantic_inputs_sha256,
        )
        .expect("semantic input resolved configuration");
        root_authority.provider_configuration_sha256 =
            rust_provider_configuration_sha256(&base_config, &resolved_configuration)
                .expect("semantic input provider configuration");
        crate::code_intel_payload::normalize_provider_payload(&ProviderPayload::Calls(
            semantic_input_payload.clone(),
        ))
        .expect("semantic-input descriptor composes exactly");
        let mut split_semantic_inputs = semantic_input_payload.clone();
        split_semantic_inputs.semantic_inputs = ProviderSemanticInputs::empty();
        let split_error = crate::code_intel_payload::normalize_provider_payload(
            &ProviderPayload::Calls(split_semantic_inputs),
        )
        .expect_err("partially persisted reconstruction inputs must fail closed");
        assert!(
            split_error.to_string().contains("do not exactly compose"),
            "partial-persistence falsifier fired for the wrong reason: {split_error}"
        );
        fs::write(&semantic_input_path, "semantic-input-after\n").expect("drift semantic input");
        let mut semantic_input_rejected = RustSemanticProviderCoordinator::new(base_config.clone());
        assert!(
            !semantic_input_rejected
                .authorizes_exact_generation_reuse(
                    &root,
                    &inventory,
                    &indexed_sources,
                    &[ProviderPayload::Calls(semantic_input_payload)],
                    &cancellation,
                )
                .await,
            "changed provider-declared semantic input must refuse reuse"
        );
        assert!(
            !fixture.request_log.exists(),
            "known semantic-input drift must fail before child startup"
        );
        fs::remove_file(semantic_input_path).expect("remove semantic input fixture");

        let mut inventory_descriptor_drift = persisted_payload.clone();
        let ProviderExecutionAuthority::ToolchainBound {
            provider_inventory_sha256,
            ..
        } = &mut inventory_descriptor_drift.execution_authority
        else {
            panic!("recertification fixture authority")
        };
        *provider_inventory_sha256 = "0".repeat(64);
        let mut inventory_descriptor_rejected =
            RustSemanticProviderCoordinator::new(base_config.clone());
        assert!(
            !inventory_descriptor_rejected
                .authorizes_exact_generation_reuse(
                    &root,
                    &inventory,
                    &indexed_sources,
                    &[ProviderPayload::Calls(inventory_descriptor_drift)],
                    &cancellation,
                )
                .await,
            "altered project-inventory descriptor must refuse reuse"
        );
        assert!(
            !fixture.request_log.exists(),
            "inventory descriptor drift must fail before child startup"
        );

        let mut argument_drift_config = base_config.clone();
        argument_drift_config
            .arguments
            .push(OsString::from("--changed-private-provider-contract"));
        let mut argument_rejected = RustSemanticProviderCoordinator::new(argument_drift_config);
        assert!(
            !argument_rejected
                .authorizes_exact_generation_reuse(
                    &root,
                    &inventory,
                    &indexed_sources,
                    &[ProviderPayload::Calls(persisted_payload.clone())],
                    &cancellation,
                )
                .await,
            "changed provider invocation must refuse reuse"
        );
        assert!(
            !fixture.request_log.exists(),
            "persisted descriptor must reject invocation drift before child startup"
        );

        let drift_resolver = Arc::new(TestToolchainResolver::new(BTreeMap::from([
            ("MODE".into(), "recertify".into()),
            (
                "PID_FILE".into(),
                fixture.pid_file.to_string_lossy().into_owned(),
            ),
            (
                "ARGV_FILE".into(),
                fixture.argv_file.to_string_lossy().into_owned(),
            ),
            (
                "REQUEST_LOG".into(),
                fixture.request_log.to_string_lossy().into_owned(),
            ),
            ("H00_TEST_TOOLCHAIN_EPOCH".into(), "changed".into()),
        ])));
        let mut drift_config = RustSemanticProviderConfig::new(
            &fixture.binary,
            fixture.identity.clone(),
            drift_resolver,
        )
        .expect("drift provider config");
        drift_config.request_timeout = Duration::from_secs(2);
        let mut toolchain_rejected = RustSemanticProviderCoordinator::new(drift_config);
        assert!(
            !toolchain_rejected
                .authorizes_exact_generation_reuse(
                    &root,
                    &inventory,
                    &indexed_sources,
                    &[ProviderPayload::Calls(persisted_payload.clone())],
                    &cancellation,
                )
                .await,
            "changed resolved toolchain must refuse reuse"
        );
        let toolchain_pid = fixture.pid();
        assert!(
            !process_exists(toolchain_pid),
            "rejected toolchain recertifier must be reaped"
        );
        assert!(
            !fixture.request_log.exists(),
            "known toolchain drift must fail before child startup"
        );

        let source_path = root.join("src/lib.rs");
        let exact_source = fs::read(&source_path).expect("exact source bytes");
        fs::write(&source_path, "pub fn drifted() {}\n").expect("drift source bytes");
        let mut source_rejected = RustSemanticProviderCoordinator::new(base_config.clone());
        assert!(
            !source_rejected
                .authorizes_exact_generation_reuse(
                    &root,
                    &inventory,
                    &indexed_sources,
                    &[ProviderPayload::Calls(persisted_payload.clone())],
                    &cancellation,
                )
                .await,
            "changed source bytes must refuse reuse"
        );
        assert!(
            !fixture.request_log.exists(),
            "known source drift must fail before child startup"
        );
        fs::write(source_path, exact_source).expect("restore fixture source");

        fs::remove_file(root.join("Cargo.lock")).expect("remove dependency lock");
        let lockless_inventory = build_project_inventory(
            &root,
            &[InventorySource::new(
                "src/lib.rs",
                H00_RUST_ANALYZER_LANGUAGE,
            )],
        );
        let mut lockless_payload = persisted_payload;
        let ProviderExecutionAuthority::ToolchainBound {
            provider_inventory_sha256,
            ..
        } = &mut lockless_payload.execution_authority
        else {
            panic!("recertification fixture authority")
        };
        *provider_inventory_sha256 = rust_provider_inventory_fingerprint(&lockless_inventory)
            .expect("lockless provider inventory fingerprint");
        crate::code_intel_payload::normalize_provider_payload(&ProviderPayload::Calls(
            lockless_payload.clone(),
        ))
        .expect("lockless payload remains canonical but is not fast-reconstructible");
        let mut lockless_fallback = RustSemanticProviderCoordinator::new(base_config);
        assert!(
            lockless_fallback
                .authorizes_exact_generation_reuse(
                    &root,
                    &lockless_inventory,
                    &indexed_sources,
                    &[ProviderPayload::Calls(lockless_payload)],
                    &cancellation,
                )
                .await,
            "a lockless generation must retain the full-session fallback"
        );
        let fallback_operations = fs::read_to_string(&fixture.request_log)
            .expect("lockless fallback request log")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert!(
            fallback_operations.contains(&"open_session".into()),
            "lockless fallback must reconstruct through the workspace: {fallback_operations:?}"
        );
        assert_eq!(
            fallback_operations
                .iter()
                .filter(|operation| operation.as_str() == "hello")
                .count(),
            2,
            "lockless fallback must witness startup and terminal runtime identity: {fallback_operations:?}"
        );
        let fallback_pid = fixture.pid();
        assert!(
            process_exists(fallback_pid),
            "full-session fallback remains owned for incremental refresh"
        );
        lockless_fallback.reset().await;
        assert!(
            !process_exists(fallback_pid),
            "reset reaps the lockless fallback session"
        );
    }

    /// PRODUCT CONTROL paired with the product-resolver RED: after an
    /// executable-shaped native build input becomes a typed component, its
    /// same-path byte identity participates in the coordinator's existing
    /// terminal authority check. No provider-specific CC hash owner is needed.
    /// This uses the real coordinator refresh, supervised child, reusable
    /// snapshot, post-result identity check, reset, and child reap.
    #[cfg(unix)]
    #[tokio::test]
    async fn mid_refresh_native_tool_byte_drift_discards_candidate_and_reaps_session() {
        use crate::code_intel_semantic_provider_process::test_fixture::{
            FakeProvider, process_exists,
        };
        use crate::scip_normalizer::{
            ScipProviderSpec, canonical_scip_snapshot_from_provider_document_sets,
        };

        let temporary = TempDir::new().expect("toolchain drift project");
        let root = temporary.path().join("repo");
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"toolchain-drift\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        fs::write(root.join("src/lib.rs"), "pub fn stable() {}\n").expect("source");
        let root = fs::canonicalize(root).expect("canonical project root");
        let inventory = build_project_inventory(
            &root,
            &[InventorySource::new(
                "src/lib.rs",
                H00_RUST_ANALYZER_LANGUAGE,
            )],
        );
        let indexed_sources = [indexed_source(&root, "src/lib.rs")];
        let project_unit_ids = crate::code_intel_inventory::semantic_provider_unit_execution_roots(
            &inventory,
            H00_RUST_ANALYZER_LANGUAGE,
            "cargo",
        )
        .into_keys()
        .collect::<Vec<_>>();
        assert!(
            !project_unit_ids.is_empty(),
            "positive control: the fixture has exact Cargo project-unit authority"
        );
        let prepared = prepare_sources(
            &root,
            std::slice::from_ref(&root),
            &indexed_sources,
            &inventory,
        )
        .expect("prepared source epoch");
        let topology_sha256 = rust_provider_inventory_fingerprint(&inventory)
            .expect("provider inventory fingerprint");

        let first_toolchain = sequenced_toolchain_with_native_cc(&root, "c".repeat(64));
        let changed_toolchain = sequenced_toolchain_with_native_cc(&root, "d".repeat(64));
        assert_eq!(first_toolchain.language, changed_toolchain.language);
        assert_eq!(
            first_toolchain.execution_root,
            changed_toolchain.execution_root
        );
        assert_eq!(first_toolchain.origin, changed_toolchain.origin);
        assert_eq!(first_toolchain.sysroot, changed_toolchain.sysroot);
        assert_eq!(first_toolchain.environment, changed_toolchain.environment);
        assert_eq!(
            first_toolchain.components.len(),
            3,
            "positive component population"
        );
        for stable_role in ["cargo", "rustc"] {
            assert_eq!(
                first_toolchain.components[stable_role], changed_toolchain.components[stable_role],
                "only the native build tool may drift in this control"
            );
        }
        assert_eq!(
            first_toolchain.components["native-cc"].executable,
            changed_toolchain.components["native-cc"].executable,
            "the executable path deliberately stays unchanged"
        );
        assert_eq!(
            first_toolchain.components["native-cc"].version,
            changed_toolchain.components["native-cc"].version,
            "the bounded version report deliberately stays unchanged"
        );
        assert_ne!(
            first_toolchain.components["native-cc"].executable_sha256,
            changed_toolchain.components["native-cc"].executable_sha256,
            "only the native executable byte identity changes"
        );
        assert_ne!(
            first_toolchain.fingerprint_sha256(),
            changed_toolchain.fingerprint_sha256(),
            "native executable bytes must change the complete toolchain authority"
        );
        let resolver = Arc::new(SequencedToolchainResolver::new([
            first_toolchain.clone(),
            first_toolchain.clone(),
            changed_toolchain,
        ]));
        let fixture = FakeProvider::new();
        let process = SemanticProviderProcess::spawn(fixture.config_for_toolchain(
            "normal",
            Duration::from_secs(2),
            first_toolchain.fingerprint_sha256(),
        ))
        .await
        .expect("supervised provider session");
        let provider_pid = fixture.pid();
        let configuration_sha256 = process.runtime_configuration().configuration_sha256.clone();
        let mut payload =
            CallsProviderPayload::new(crate::code_intel_domain::CapabilityReceipt::complete(
                "calls",
                H00_RUST_ANALYZER_PROVIDER_ID,
                H00_RUST_ANALYZER_IMPLEMENTATION_V6,
                crate::code_intel_domain::CapabilityScope::ProjectUnits {
                    language_id: LanguageId::new(H00_RUST_ANALYZER_LANGUAGE),
                    project_unit_ids,
                    configuration_id: crate::code_intel_domain::ConfigurationId::new(
                        "test-toolchain-drift",
                    ),
                },
                "f".repeat(64),
            ));
        let semantic_inputs = ProviderSemanticInputs::empty();
        let authority = ProviderAuthority {
            session_id: process.session_id().into(),
            root_sha256: "a".repeat(64),
            root_topology_sha256: topology_sha256.clone(),
            configuration_sha256,
            workspace_resolution_sha256: Some("e".repeat(64)),
            semantic_inputs_sha256: Some(
                provider_semantic_inputs_sha256(&semantic_inputs, &ProviderFrameLimits::default())
                    .expect("semantic input identity"),
            ),
            population_sha256: "b".repeat(64),
            source_epoch: 1,
        };
        let resolved_configuration = resolved_authority_configuration_sha256(&authority)
            .expect("resolved provider configuration");
        let snapshot = canonical_scip_snapshot_from_provider_document_sets(
            &root,
            ScipProviderSpec::rust_analyzer_sidecar(),
            H00_RUST_ANALYZER_IMPLEMENTATION_V6,
            &BTreeMap::from([(root.clone(), resolved_configuration)]),
            Vec::new(),
            &inventory,
        )
        .expect("reusable canonical snapshot");
        let mut config = RustSemanticProviderConfig::new(
            &fixture.binary,
            fixture.identity.clone(),
            resolver.clone(),
        )
        .expect("coordinator configuration");
        config.request_timeout = Duration::from_secs(2);
        let mut coordinator = RustSemanticProviderCoordinator::new(config);
        coordinator.repository_root = Some(root.clone());
        coordinator.topology_sha256 = Some(topology_sha256.clone());
        coordinator.root_topology_sha256 = BTreeMap::from([(root.clone(), topology_sha256)]);
        coordinator.sources = prepared.clone();
        coordinator.snapshot = Some(snapshot.clone());
        coordinator.last_activity = Some(SemanticProviderActivityRecord {
            activity: SemanticProviderActivity::Admitted {
                refresh: SemanticProviderAdmittedRefreshKind::Full,
                operation: ProviderOperation::CertifyFull,
                session_open: None,
            },
            timings: Vec::new(),
        });
        coordinator.sessions.insert(
            root.clone(),
            RootSession {
                process,
                toolchain: first_toolchain,
                authority,
                sources: sources_for_root(&prepared, &root),
                semantic_inputs,
            },
        );
        payload.semantic_inputs = combined_semantic_inputs(&coordinator.sessions)
            .expect("admitted prior semantic inputs");
        payload.execution_authority = coordinator
            .execution_authority(&root, &inventory)
            .expect("admitted prior execution authority");
        payload.documents = prepared
            .values()
            .map(|source| ProviderDocument {
                document_path: source.identity.document_path.clone(),
                language_id: LanguageId::new(&source.identity.language),
                content_sha256: source.identity.content_sha256.clone(),
                cross_document_surface_sha256: source
                    .cross_document_surface_sha256
                    .clone()
                    .expect("prepared cross-document surface"),
                byte_length: source.bytes.len() as u64,
            })
            .collect();
        payload.canonical_snapshot_sha256 = Some(snapshot.identity_sha256());
        let normalized = normalize_provider_payload_typed(&ProviderPayload::Calls(payload))
            .expect("positive control: retained candidate satisfies the production payload schema");
        let persisted_payload = calls_payload_from_normalized(&normalized).clone();
        let persisted_basis = CanonicalSemanticBasis {
            snapshot: snapshot.clone(),
            evidence: ScipArtifactEvidence {
                language_id: LanguageId::new(H00_RUST_ANALYZER_LANGUAGE),
                receipt: persisted_payload.receipt.clone(),
                payload: Some(normalized.clone()),
            },
            supplemental_evidence: Vec::new(),
            source_syntax_cache: None,
        };
        coordinator.payload = Some(normalized);

        // RIGHT-REASON HOT-PATH REGRESSION: a retained exact provider session
        // owns the only source-population observation needed to re-admit its
        // canonical basis. The basis adapter must not scan the same bytes
        // before delegating to that authority owner.
        coordinator.config.reset_prepare_sources_call_count();
        assert!(
            coordinator
                .reuse_exact_canonical_basis(
                    &root,
                    &inventory,
                    &indexed_sources,
                    std::slice::from_ref(&persisted_basis),
                    &IndexCancellation::new(),
                )
                .await
                .is_some(),
            "positive control: the retained exact session re-admits its bound canonical basis"
        );
        assert_eq!(
            coordinator.config.prepare_sources_call_count(),
            1,
            "process-local basis reuse must prepare its exact source population once"
        );
        assert_eq!(
            resolver.remaining(),
            2,
            "the retained-session probe consumes exactly one stable toolchain observation"
        );

        // RIGHT-REASON REGRESSION: a normal successor source epoch makes the
        // persisted basis ineligible, but that read/admission refusal must not
        // destroy the healthy process-local session needed by the subsequent
        // affected refresh. Refresh owns the state transition.
        let source_path = root.join("src/lib.rs");
        let exact_source = fs::read(&source_path).expect("exact source bytes");
        fs::write(&source_path, "pub fn changed() {}\n").expect("successor source epoch");
        let changed_indexed_sources = [indexed_source(&root, "src/lib.rs")];
        assert!(
            coordinator
                .reuse_exact_canonical_basis(
                    &root,
                    &inventory,
                    &changed_indexed_sources,
                    std::slice::from_ref(&persisted_basis),
                    &IndexCancellation::new(),
                )
                .await
                .is_none(),
            "a changed source epoch must refuse the prior canonical basis"
        );
        assert_eq!(
            coordinator.sessions.len(),
            1,
            "expected source-epoch refusal must preserve the healthy retained session"
        );
        assert!(
            process_exists(provider_pid),
            "expected source-epoch refusal reaped the retained provider"
        );
        assert_eq!(
            resolver.remaining(),
            2,
            "known source mismatch must refuse before probing or consuming toolchain authority"
        );
        fs::write(&source_path, exact_source).expect("restore exact source epoch");

        // RIGHT-REASON REGRESSION: cancellation during an exact-generation
        // reuse probe refuses authority for that operation, but the probe has
        // not consumed or invalidated the already admitted live population.
        // The supervisor may therefore retain it for the successor epoch.
        let cancelled_probe = IndexCancellation::new();
        cancelled_probe.cancel();
        assert!(
            !coordinator
                .authorizes_exact_generation_reuse(
                    &root,
                    &inventory,
                    &indexed_sources,
                    &[ProviderPayload::Calls(persisted_payload)],
                    &cancelled_probe,
                )
                .await,
            "a cancelled probe must never grant generation reuse"
        );
        assert_eq!(
            coordinator.sessions.len(),
            1,
            "a cancelled read/admission probe discarded prior live authority"
        );
        assert!(coordinator.snapshot.is_some());
        assert!(coordinator.payload.is_some());
        assert!(process_exists(provider_pid));
        assert_eq!(
            resolver.remaining(),
            2,
            "pre-cancelled probe must not consume a toolchain observation"
        );

        let error = match coordinator
            .refresh(
                &root,
                std::slice::from_ref(&root),
                &indexed_sources,
                &inventory,
                &IndexCancellation::new(),
            )
            .await
        {
            Ok(_) => panic!("mid-refresh toolchain drift must discard the candidate"),
            Err(error) => error,
        };
        assert!(
            matches!(error, SemanticProviderError::ToolchainChanged),
            "mid-refresh drift must retain its stable error contract, got {error:?}"
        );
        assert_eq!(resolver.remaining(), 0, "both identity checks must execute");
        assert!(coordinator.sessions.is_empty());
        assert!(coordinator.snapshot.is_none());
        assert!(coordinator.payload.is_none());
        let failed_activity = coordinator
            .take_last_activity()
            .expect("failed provider activity must remain observable");
        assert!(matches!(
            failed_activity.activity,
            SemanticProviderActivity::Failed { ref attempted_operations, .. }
                if !attempted_operations.is_empty()
        ));
        assert!(
            !process_exists(provider_pid),
            "discarding the stale candidate must reap its exact provider child"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "requires the explicitly built installed rust-analyzer sidecar"]
    async fn installed_coordinator_uses_full_then_affected_then_reuse() {
        let binary = PathBuf::from(
            std::env::var_os("H00_TEST_RA_PROVIDER_BINARY").expect("H00_TEST_RA_PROVIDER_BINARY"),
        );
        let receipt = PathBuf::from(
            std::env::var_os("H00_TEST_RA_PROVIDER_RECEIPT").expect("H00_TEST_RA_PROVIDER_RECEIPT"),
        );
        let temporary = TempDir::new().expect("coordinator project");
        let root = temporary.path().join("repo");
        fs::create_dir_all(root.join("src")).expect("source directory");
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"coordinator\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        fs::write(
            root.join("Cargo.lock"),
            "# This file is automatically @generated by Cargo.\nversion = 4\n\n[[package]]\nname = \"coordinator\"\nversion = \"0.1.0\"\n",
        )
        .expect("lockfile");
        let source_path = root.join("src/lib.rs");
        let before = b"pub fn target() -> usize { 1 }\npub fn caller() -> usize { target() }\n";
        let after = b"pub fn target() -> usize { 2 }\npub fn caller() -> usize { target() }\n";
        fs::write(&source_path, before).expect("initial source");
        let inventory = build_project_inventory(
            &root,
            &[InventorySource::new(
                "src/lib.rs",
                H00_RUST_ANALYZER_LANGUAGE,
            )],
        );

        let identity = installed_identity(&binary, &receipt);
        let toolchain_resolver = TestToolchainResolver::from_current_process(&[
            "PATH",
            "HOME",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "TMPDIR",
        ])
        .with_environment("RUSTUP_TOOLCHAIN", "1.97.1")
        .with_environment("CARGO_TERM_COLOR", "never")
        .with_installed_rust_programs();
        let mut config =
            RustSemanticProviderConfig::new(binary, identity, Arc::new(toolchain_resolver))
                .expect("provider config");
        config.request_timeout = Duration::from_secs(60);
        let mut coordinator = RustSemanticProviderCoordinator::new(config);
        let cancellation = IndexCancellation::new();
        reset_canonical_normalization_count();
        crate::code_intel_payload::reset_provider_payload_normalizations();

        let first = coordinator
            .refresh(
                &root,
                std::slice::from_ref(&root),
                &[indexed_source(&root, "src/lib.rs")],
                &inventory,
                &cancellation,
            )
            .await
            .expect("full certification");
        assert_eq!(first.evidence.receipt.status, CapabilityStatus::Complete);
        let first_activity = coordinator.take_last_activity().expect("full activity");
        assert!(matches!(
            first_activity.activity,
            SemanticProviderActivity::Admitted {
                refresh: SemanticProviderAdmittedRefreshKind::Full,
                operation: ProviderOperation::CertifyFull,
                session_open: Some(_),
            }
        ));
        let after_full = canonical_normalization_count();
        assert!(after_full > 0, "positive canonical-normalization control");

        fs::write(&source_path, after).expect("body-only edit");
        let affected = coordinator
            .refresh(
                &root,
                std::slice::from_ref(&root),
                &[indexed_source(&root, "src/lib.rs")],
                &inventory,
                &cancellation,
            )
            .await
            .expect("affected refresh");
        assert_eq!(affected.evidence.receipt.status, CapabilityStatus::Complete);
        let affected_activity = coordinator.take_last_activity().expect("affected activity");
        assert!(
            affected_activity
                .timings
                .iter()
                .all(|timing| timing.label != "retained session runtime preflight"),
            "the changed single root is certified by affected-refresh and must not receive a redundant preflight Hello: {:?}",
            affected_activity.timings
        );
        assert_eq!(
            affected_activity.activity,
            SemanticProviderActivity::Admitted {
                refresh: SemanticProviderAdmittedRefreshKind::Affected {
                    documents: BTreeSet::from(["src/lib.rs".into()]),
                },
                operation: ProviderOperation::RefreshAffected,
                session_open: None,
            }
        );
        let after_affected = canonical_normalization_count();
        let payload_normalizations_after_affected =
            crate::code_intel_payload::provider_payload_normalizations();
        assert!(
            after_affected > after_full,
            "positive affected-normalization control"
        );

        coordinator
            .refresh(
                &root,
                std::slice::from_ref(&root),
                &[indexed_source(&root, "src/lib.rs")],
                &inventory,
                &cancellation,
            )
            .await
            .expect("exact reuse");
        let reused_activity = coordinator.take_last_activity().expect("reuse activity");
        assert_eq!(
            reused_activity.activity,
            SemanticProviderActivity::Reused { session_open: None }
        );
        assert_eq!(
            canonical_normalization_count(),
            after_affected,
            "exact unchanged Rust authority must reuse the admitted payload and snapshot instead of reparsing every source"
        );
        assert_eq!(
            crate::code_intel_payload::provider_payload_normalizations(),
            payload_normalizations_after_affected,
            "exact unchanged authority must share the retained normalized payload instead of normalizing it again"
        );
        coordinator.reset().await;
        assert_eq!(
            fs::read(source_path).expect("source after refreshes"),
            after
        );
    }
}
