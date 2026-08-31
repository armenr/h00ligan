//! Canonical, provider-addressable semantic payloads.
//!
//! Provider-native identities remain isolated inside one payload. A payload is
//! linked to exactly one complete capability receipt, content-addressed, and
//! suitable for storage in the same immutable generation as its receipt and
//! indexed project inventory.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use h00ligan_provider_protocol::{
    ProviderFrameLimits, ProviderSemanticInputs, provider_semantic_paths_are_current,
    validate_provider_semantic_inputs,
};

use crate::code_intel_domain::{
    CallsPopulation, CapabilityReceipt, CapabilityScope, EcosystemId, LanguageId, ProjectUnitId,
    ProviderId, validate_complete_receipt,
};
use crate::scip_normalizer::CanonicalScipSnapshot;

pub const CALLS_PROVIDER_PAYLOAD_SCHEMA: &str = "h00/code-intel/provider-payload/calls/v17";
pub const CALLABLE_LIVENESS_PROVIDER_PAYLOAD_SCHEMA: &str =
    "h00/code-intel/provider-payload/callable-liveness/v1";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityReceiptId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProviderPayloadId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NormalizedSourceSpan {
    /// UTF-8 byte offsets in the exact source bytes identified by the document
    /// digest. Provider-specific encodings must be converted before this type
    /// is constructed.
    pub start_byte: u64,
    pub end_byte: u64,
    pub start_line: u32,
    pub start_utf8_byte_column: u32,
    pub end_line: u32,
    pub end_utf8_byte_column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProviderDocument {
    pub document_path: String,
    pub language_id: LanguageId,
    pub content_sha256: String,
    /// Cross-document semantic surface derived from the same exact source
    /// bytes by the structural extractor. This binds incremental refresh
    /// decisions to the immutable provider payload that substantiates them.
    pub cross_document_surface_sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProviderLocation {
    pub document_path: String,
    pub span: NormalizedSourceSpan,
}

/// Canonical source role of a provider symbol used by Calls evidence.
///
/// This explicit discriminant prevents an omitted callable extent from
/// silently changing a local source callable into a dynamic or external
/// target. Provider-native kind vocabulary remains provenance only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSymbolRole {
    /// A source-backed invocation target with an exact structural identity.
    /// It may or may not own a body that can contain calls: functions normally
    /// do, while Python class objects are directly invocable without making
    /// their class suites callable bodies.
    SourceInvocationTarget,
    /// A provider-resolved local invocation target (parameter, closure, or
    /// mutable binding) without its own structural graph identity.
    LocalInvocationTarget,
    /// A symbol outside the payload's source-document population.
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProviderSymbol {
    /// Opaque provider-native identity. It is meaningful only with the
    /// payload's receipt/provider identity and never joins another provider.
    pub provider_symbol_id: String,
    pub name: String,
    /// Provider-native vocabulary retained as provenance. Product-level
    /// callable identity is established independently from the exact source
    /// extent and co-published structural node.
    pub provider_kind: String,
    pub language_id: LanguageId,
    pub role: ProviderSymbolRole,
    pub definition: Option<ProviderLocation>,
    /// Exact source extent used to join this provider identity to one
    /// co-published structural node. Local values and external targets have no
    /// structural extent.
    pub structural_extent: Option<ProviderLocation>,
    /// Exact source body that may own call sites. An invocation target without
    /// a callable body deliberately leaves this absent.
    pub call_owner_extent: Option<ProviderLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCall {
    pub caller_symbol_id: String,
    pub callee_symbol_id: String,
    /// Exact provider-resolved occurrence independently corroborated as the
    /// terminal callee expression of a source-level invocation.
    pub call_site: ProviderLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCallableBinding {
    /// The source-backed variable or binding whose value is callable.
    pub binding_symbol_id: String,
    /// A provider-resolved local callable assigned to the binding.
    pub target_symbol_id: String,
    /// Exact source occurrence of the assigned callable value.
    pub binding_site: ProviderLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCoverageExclusion {
    /// Exact source region intentionally outside this provider configuration's
    /// source-backed callable population.
    pub location: ProviderLocation,
    /// Stable machine-readable classification such as
    /// `conditional_compilation` or `module_initialization`.
    pub reason_code: String,
}

/// Reuse authority carried by one complete semantic payload.
///
/// Current-run evidence may be queried after publication regardless of this
/// strategy. The strategy controls only whether a later indexing operation may
/// reuse that immutable evidence without executing the provider again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProviderExecutionAuthority {
    /// The normalizer validated this invocation and its exact configuration,
    /// but no durable runtime witness can authorize cross-process reuse.
    InvocationBound {
        provider_configurations_sha256: BTreeMap<String, String>,
    },
    /// A provider-specific reuse contract may admit this payload only after a
    /// fresh or retained runtime reconstructs this complete implementation,
    /// toolchain, project-unit, and provider-configuration population. These
    /// bytes describe what must be proven; they never authorize reuse alone.
    ToolchainBound {
        resolver_policy_id: String,
        ecosystem_id: EcosystemId,
        reuse_contract_id: String,
        provider_implementation_sha256: String,
        /// Canonical identity of the exact provider-scoped project units,
        /// manifests, dependency locks, and tool configuration admitted by
        /// this run. The publication manifest separately binds the complete
        /// repository inventory.
        provider_inventory_sha256: String,
        roots: Vec<ProviderExecutionRootAuthority>,
    },
}

/// How one toolchain-bound execution root can be reconstructed later.
///
/// Every variant still requires current source, inventory, implementation,
/// invocation, and toolchain equality. `ObservedWorkspace` additionally lets
/// a fresh provider prove its runtime identity with Hello while the owner
/// re-observes all provider-declared semantic inputs, avoiding a full
/// workspace load merely to reuse an immutable generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderGenerationReconstruction {
    DeterministicInvocation,
    ObservedWorkspace {
        runtime_configuration_sha256: String,
        workspace_resolution_sha256: String,
        semantic_inputs: ProviderSemanticInputs,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionRootAuthority {
    /// Canonical repository-relative execution-root prefix; empty means the
    /// repository root itself.
    pub execution_root: String,
    pub project_unit_ids: Vec<ProjectUnitId>,
    pub toolchain_fingerprint_sha256: String,
    pub provider_configuration_sha256: String,
    pub generation_reconstruction: ProviderGenerationReconstruction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallsProviderPayload {
    pub schema_version: String,
    /// Exact source population substantiated by this payload. This field is
    /// mandatory so transports cannot silently broaden provider evidence into
    /// runtime or expanded-macro authority.
    pub population: CallsPopulation,
    /// The exact complete receipt this payload substantiates.
    pub receipt: CapabilityReceipt,
    /// Exact bounded non-source inputs observed by the provider and safe for a
    /// fresh process to recheck under the selected repository root.
    pub semantic_inputs: ProviderSemanticInputs,
    pub execution_authority: ProviderExecutionAuthority,
    /// Content identity of the canonical SCIP document snapshot from which
    /// this normalized payload was derived. The referenced bytes are a
    /// disposable acceleration cache, never publication authority: a later
    /// process may use them only after reconstructing and exactly matching
    /// this identity from the immutable payload and current repository root.
    pub canonical_snapshot_sha256: Option<String>,
    pub documents: Vec<ProviderDocument>,
    /// Every provider-confirmed callable definition in the covered document
    /// population, plus any additional local call targets referenced by
    /// `calls`. A callable with zero call edges remains addressable here.
    pub symbols: Vec<ProviderSymbol>,
    pub calls: Vec<ProviderCall>,
    /// Exact local callable-value assignments. These are possible dispatch
    /// paths for conservative liveness, never direct invocation records.
    pub callable_bindings: Vec<ProviderCallableBinding>,
    /// Exact source regions omitted from provider-backed symbol authority for
    /// an explicit, query-visible reason.
    pub coverage_exclusions: Vec<ProviderCoverageExclusion>,
}

impl CallsProviderPayload {
    pub fn new(receipt: CapabilityReceipt) -> Self {
        Self {
            schema_version: CALLS_PROVIDER_PAYLOAD_SCHEMA.into(),
            population: CallsPopulation::ProviderResolvedExplicitSourceInvocations,
            receipt,
            semantic_inputs: ProviderSemanticInputs::empty(),
            execution_authority: ProviderExecutionAuthority::InvocationBound {
                provider_configurations_sha256: BTreeMap::new(),
            },
            canonical_snapshot_sha256: None,
            documents: Vec::new(),
            symbols: Vec::new(),
            calls: Vec::new(),
            callable_bindings: Vec::new(),
            coverage_exclusions: Vec::new(),
        }
    }
}

/// One exact source callable classified by a compiler-native whole-program
/// liveness analysis.
///
/// This is deliberately distinct from an explicit call edge: RTA may establish
/// reachability through interfaces, function values, reflection-conservative
/// method sets, and test harness roots without inventing a source-level
/// invocation record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCallableLiveness {
    pub name: String,
    pub definition: ProviderLocation,
    pub structural_extent: ProviderLocation,
    pub production_reachable: bool,
    pub test_reachable: bool,
}

/// One source document intentionally omitted from the selected compiler
/// configuration, such as a mutually exclusive build-tag variant.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCallableLivenessExclusion {
    pub document_path: String,
    pub reason_code: String,
}

/// Exact source declaration population classified by this capability.
///
/// Function-valued variables, closures, fields, and callback parameters are
/// dispatch mechanisms rather than named source declarations in this first Go
/// contract. RTA still traverses them when establishing whether a named
/// function or method is reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallableLivenessPopulation {
    NamedFunctionAndMethodDeclarations,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallableLivenessProviderPayload {
    pub schema_version: String,
    pub population: CallableLivenessPopulation,
    pub receipt: CapabilityReceipt,
    pub semantic_inputs: ProviderSemanticInputs,
    pub execution_authority: ProviderExecutionAuthority,
    pub documents: Vec<ProviderDocument>,
    pub callables: Vec<ProviderCallableLiveness>,
    pub coverage_exclusions: Vec<ProviderCallableLivenessExclusion>,
}

impl CallableLivenessProviderPayload {
    pub fn new(receipt: CapabilityReceipt) -> Self {
        Self {
            schema_version: CALLABLE_LIVENESS_PROVIDER_PAYLOAD_SCHEMA.into(),
            population: CallableLivenessPopulation::NamedFunctionAndMethodDeclarations,
            receipt,
            semantic_inputs: ProviderSemanticInputs::empty(),
            execution_authority: ProviderExecutionAuthority::InvocationBound {
                provider_configurations_sha256: BTreeMap::new(),
            },
            documents: Vec::new(),
            callables: Vec::new(),
            coverage_exclusions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum ProviderPayload {
    Calls(CallsProviderPayload),
    CallableLiveness(CallableLivenessProviderPayload),
}

impl ProviderPayload {
    pub const fn receipt(&self) -> &CapabilityReceipt {
        match self {
            Self::Calls(payload) => &payload.receipt,
            Self::CallableLiveness(payload) => &payload.receipt,
        }
    }

    pub fn schema_version(&self) -> &str {
        match self {
            Self::Calls(payload) => &payload.schema_version,
            Self::CallableLiveness(payload) => &payload.schema_version,
        }
    }

    pub fn documents(&self) -> &[ProviderDocument] {
        match self {
            Self::Calls(payload) => &payload.documents,
            Self::CallableLiveness(payload) => &payload.documents,
        }
    }

    pub const fn semantic_inputs(&self) -> &ProviderSemanticInputs {
        match self {
            Self::Calls(payload) => &payload.semantic_inputs,
            Self::CallableLiveness(payload) => &payload.semantic_inputs,
        }
    }

    pub const fn execution_authority(&self) -> &ProviderExecutionAuthority {
        match self {
            Self::Calls(payload) => &payload.execution_authority,
            Self::CallableLiveness(payload) => &payload.execution_authority,
        }
    }
}

impl AsRef<Self> for ProviderPayload {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// Recheck every provider-declared repository-local path input carried by an
/// immutable generation.
///
/// Provider environment identity belongs to explicit semantic reuse
/// admission, not to a reader process's source-freshness claim. Empty
/// manifests are valid; any observation uncertainty is an error so callers
/// cannot promote it to Fresh.
pub fn provider_payload_semantic_paths_are_current<P: AsRef<ProviderPayload>>(
    repository_root: &Path,
    payloads: &[P],
) -> Result<bool, ProviderPayloadError> {
    let limits = ProviderFrameLimits::default();
    for payload in payloads {
        let inputs = match payload.as_ref() {
            ProviderPayload::Calls(payload) => &payload.semantic_inputs,
            ProviderPayload::CallableLiveness(payload) => &payload.semantic_inputs,
        };
        if !provider_semantic_paths_are_current(repository_root, inputs, &limits)
            .map_err(|error| ProviderPayloadError::Invalid(error.to_string()))?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProviderPayloadDescriptor {
    pub payload_id: ProviderPayloadId,
    pub payload_schema_version: String,
    pub capability_id: String,
    pub provider_id: ProviderId,
    pub receipt_id: CapabilityReceiptId,
    pub payload_sha256: String,
}

/// A provider payload whose ordering and semantic invariants were validated.
///
/// Metadata changes must use the invariant-preserving methods below; callers
/// cannot obtain mutable access to the enclosed payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedProviderPayload {
    payload: Arc<ProviderPayload>,
}

impl NormalizedProviderPayload {
    pub fn payload(&self) -> &ProviderPayload {
        self.payload.as_ref()
    }

    pub fn into_payload(self) -> ProviderPayload {
        Arc::unwrap_or_clone(self.payload)
    }

    #[cfg(test)]
    pub(crate) fn shares_allocation_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.payload, &other.payload)
    }

    pub(crate) fn bind_canonical_snapshot(
        &mut self,
        snapshot: &CanonicalScipSnapshot,
    ) -> Result<(), ProviderPayloadError> {
        let snapshot_sha256 = snapshot.identity_sha256();
        validate_sha256("canonical SCIP snapshot identity", &snapshot_sha256)?;
        match Arc::make_mut(&mut self.payload) {
            ProviderPayload::Calls(payload) => {
                payload.canonical_snapshot_sha256 = Some(snapshot_sha256);
            }
            ProviderPayload::CallableLiveness(_) => {}
        }
        Ok(())
    }

    pub(crate) fn bind_semantic_authority(
        &mut self,
        semantic_inputs: ProviderSemanticInputs,
        execution_authority: ProviderExecutionAuthority,
    ) -> Result<(), ProviderPayloadError> {
        validate_provider_semantic_inputs(&semantic_inputs, &ProviderFrameLimits::default())
            .map_err(|error| ProviderPayloadError::Invalid(error.to_string()))?;
        validate_execution_authority(&execution_authority, self.payload().receipt())?;
        validate_reconstruction_semantic_inputs(&execution_authority, &semantic_inputs)?;
        match Arc::make_mut(&mut self.payload) {
            ProviderPayload::Calls(payload) => {
                payload.semantic_inputs = semantic_inputs;
                payload.execution_authority = execution_authority;
            }
            ProviderPayload::CallableLiveness(payload) => {
                payload.semantic_inputs = semantic_inputs;
                payload.execution_authority = execution_authority;
            }
        }
        Ok(())
    }
}

impl AsRef<ProviderPayload> for NormalizedProviderPayload {
    fn as_ref(&self) -> &ProviderPayload {
        self.payload()
    }
}

/// One internally consistent provider payload representation for boundaries
///
/// that need the normalized value, its exact persisted bytes, and the
/// descriptor binding those bytes. Constructing the three independently can
/// repeat normalization and serialization over multi-megabyte payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalProviderPayload {
    payload: NormalizedProviderPayload,
    descriptor: ProviderPayloadDescriptor,
    bytes: Vec<u8>,
}

impl CanonicalProviderPayload {
    pub fn payload(&self) -> &ProviderPayload {
        self.payload.payload()
    }

    pub const fn descriptor(&self) -> &ProviderPayloadDescriptor {
        &self.descriptor
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_payload(self) -> ProviderPayload {
        self.payload.into_payload()
    }

    pub(crate) fn into_normalized(self) -> NormalizedProviderPayload {
        self.payload
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        NormalizedProviderPayload,
        ProviderPayloadDescriptor,
        Vec<u8>,
    ) {
        (self.payload, self.descriptor, self.bytes)
    }

    pub(crate) fn normalized_clone(&self) -> NormalizedProviderPayload {
        self.payload.clone()
    }
}

impl AsRef<ProviderPayload> for CanonicalProviderPayload {
    fn as_ref(&self) -> &ProviderPayload {
        self.payload()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProviderPayloadCanonicalizationTimings {
    pub(crate) normalization: Duration,
    pub(crate) serialization: Duration,
    pub(crate) descriptor: Duration,
}

pub fn capability_receipt_id(
    receipt: &CapabilityReceipt,
) -> Result<CapabilityReceiptId, ProviderPayloadError> {
    validate_complete_receipt(receipt)
        .map_err(|error| ProviderPayloadError::Invalid(error.to_string()))?;
    let bytes = serde_json::to_vec(&("h00/code-intel/capability-receipt/v1", receipt))
        .map_err(|error| ProviderPayloadError::Serialization(error.to_string()))?;
    Ok(CapabilityReceiptId(format!(
        "receipt-{}",
        sha256_bytes(&bytes)
    )))
}

#[cfg(test)]
thread_local! {
    /// Exact normalization population observed by publication-path
    /// falsifiers. Production has no counter or synchronization overhead.
    static PROVIDER_PAYLOAD_NORMALIZATIONS: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };

    /// One-shot serialization fault used to prove that graph projection
    /// cannot outrun the canonical payload seal. Production has no fault
    /// switch or branch.
    static FAIL_NEXT_PROVIDER_PAYLOAD_SEAL: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(crate) fn reset_provider_payload_normalizations() {
    PROVIDER_PAYLOAD_NORMALIZATIONS.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn provider_payload_normalizations() -> usize {
    PROVIDER_PAYLOAD_NORMALIZATIONS.with(std::cell::Cell::get)
}

#[cfg(test)]
pub(crate) fn fail_next_provider_payload_seal() {
    FAIL_NEXT_PROVIDER_PAYLOAD_SEAL.with(|fail| fail.set(true));
}

pub fn normalize_provider_payload(
    payload: &ProviderPayload,
) -> Result<ProviderPayload, ProviderPayloadError> {
    normalize_provider_payload_typed(payload).map(NormalizedProviderPayload::into_payload)
}

pub(crate) fn normalize_provider_payload_typed(
    payload: &ProviderPayload,
) -> Result<NormalizedProviderPayload, ProviderPayloadError> {
    #[cfg(test)]
    PROVIDER_PAYLOAD_NORMALIZATIONS.with(|count| count.set(count.get() + 1));

    let payload = match payload {
        ProviderPayload::Calls(payload) => {
            normalize_calls_payload(payload).map(ProviderPayload::Calls)
        }
        ProviderPayload::CallableLiveness(payload) => {
            normalize_callable_liveness_payload(payload).map(ProviderPayload::CallableLiveness)
        }
    }?;
    Ok(NormalizedProviderPayload {
        payload: Arc::new(payload),
    })
}

pub fn canonical_provider_payload_bytes(
    payload: &ProviderPayload,
) -> Result<Vec<u8>, ProviderPayloadError> {
    let normalized = normalize_provider_payload(payload)?;
    serde_json::to_vec(&normalized)
        .map_err(|error| ProviderPayloadError::Serialization(error.to_string()))
}

pub fn parse_canonical_provider_payload_bytes(
    bytes: &[u8],
) -> Result<CanonicalProviderPayload, ProviderPayloadError> {
    let payload = serde_json::from_slice(bytes)
        .map_err(|error| ProviderPayloadError::Serialization(error.to_string()))?;
    let canonical = canonicalize_provider_payload(&payload)?;
    if canonical.bytes() != bytes {
        return Err(ProviderPayloadError::Invalid(
            "persisted provider payload bytes are not canonical".into(),
        ));
    }
    Ok(canonical)
}

pub fn provider_payload_descriptor(
    payload: &ProviderPayload,
) -> Result<ProviderPayloadDescriptor, ProviderPayloadError> {
    Ok(canonicalize_provider_payload(payload)?.descriptor)
}

pub(crate) fn canonicalize_provider_payload(
    payload: &ProviderPayload,
) -> Result<CanonicalProviderPayload, ProviderPayloadError> {
    canonicalize_provider_payload_profiled(payload).map(|(canonical, _timings)| canonical)
}

pub(crate) fn canonicalize_provider_payload_profiled(
    payload: &ProviderPayload,
) -> Result<
    (
        CanonicalProviderPayload,
        ProviderPayloadCanonicalizationTimings,
    ),
    ProviderPayloadError,
> {
    let normalization_started = Instant::now();
    let payload = normalize_provider_payload_typed(payload)?;
    let normalization = normalization_started.elapsed();
    let (canonical, mut timings) = canonicalize_normalized_provider_payload_profiled(payload)?;
    timings.normalization = normalization;
    Ok((canonical, timings))
}

pub(crate) fn canonicalize_normalized_provider_payload_profiled(
    payload: NormalizedProviderPayload,
) -> Result<
    (
        CanonicalProviderPayload,
        ProviderPayloadCanonicalizationTimings,
    ),
    ProviderPayloadError,
> {
    #[cfg(test)]
    if FAIL_NEXT_PROVIDER_PAYLOAD_SEAL.with(|fail| fail.replace(false)) {
        return Err(ProviderPayloadError::Serialization(
            "injected canonical provider payload seal failure".into(),
        ));
    }

    let serialization_started = Instant::now();
    let bytes = serde_json::to_vec(payload.payload())
        .map_err(|error| ProviderPayloadError::Serialization(error.to_string()))?;
    let serialization = serialization_started.elapsed();
    let descriptor_started = Instant::now();
    let descriptor = provider_payload_descriptor_from_canonical_bytes(payload.payload(), &bytes)?;
    let descriptor_duration = descriptor_started.elapsed();
    Ok((
        CanonicalProviderPayload {
            payload,
            descriptor,
            bytes,
        },
        ProviderPayloadCanonicalizationTimings {
            normalization: Duration::ZERO,
            serialization,
            descriptor: descriptor_duration,
        },
    ))
}

fn provider_payload_descriptor_from_canonical_bytes(
    payload: &ProviderPayload,
    bytes: &[u8],
) -> Result<ProviderPayloadDescriptor, ProviderPayloadError> {
    let payload_sha256 = sha256_bytes(bytes);
    let receipt = payload.receipt();
    Ok(ProviderPayloadDescriptor {
        payload_id: ProviderPayloadId(format!("payload-{payload_sha256}")),
        payload_schema_version: payload.schema_version().into(),
        capability_id: receipt.capability_id.clone(),
        provider_id: receipt.provider_id.clone(),
        receipt_id: capability_receipt_id(receipt)?,
        payload_sha256,
    })
}

fn normalize_calls_payload(
    payload: &CallsProviderPayload,
) -> Result<CallsProviderPayload, ProviderPayloadError> {
    if payload.schema_version != CALLS_PROVIDER_PAYLOAD_SCHEMA {
        return Err(ProviderPayloadError::Invalid(format!(
            "unsupported Calls provider payload schema {}",
            payload.schema_version
        )));
    }
    capability_receipt_id(&payload.receipt)?;
    validate_provider_semantic_inputs(&payload.semantic_inputs, &ProviderFrameLimits::default())
        .map_err(|error| ProviderPayloadError::Invalid(error.to_string()))?;
    validate_execution_authority(&payload.execution_authority, &payload.receipt)?;
    if let Some(snapshot_sha256) = payload.canonical_snapshot_sha256.as_deref() {
        validate_sha256("canonical SCIP snapshot identity", snapshot_sha256)?;
    }
    validate_reconstruction_semantic_inputs(
        &payload.execution_authority,
        &payload.semantic_inputs,
    )?;
    if payload.receipt.capability_id != "calls" {
        return Err(ProviderPayloadError::Invalid(format!(
            "Calls provider payload cannot substantiate capability {}",
            payload.receipt.capability_id
        )));
    }

    let mut normalized = payload.clone();
    normalized.documents.sort();
    normalized.symbols.sort();
    normalized.calls.sort();
    normalized.callable_bindings.sort();
    normalized.coverage_exclusions.sort();

    if normalized
        .documents
        .windows(2)
        .any(|pair| pair[0].document_path == pair[1].document_path)
    {
        return Err(ProviderPayloadError::Invalid(
            "provider document paths must be unique".into(),
        ));
    }
    if normalized
        .symbols
        .windows(2)
        .any(|pair| pair[0].provider_symbol_id == pair[1].provider_symbol_id)
    {
        return Err(ProviderPayloadError::Invalid(
            "provider-native symbol IDs must be unique within one payload".into(),
        ));
    }
    if normalized.calls.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ProviderPayloadError::Invalid(
            "provider call records must not contain exact duplicates".into(),
        ));
    }
    if normalized
        .callable_bindings
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ProviderPayloadError::Invalid(
            "provider callable binding records must not contain exact duplicates".into(),
        ));
    }
    if normalized
        .coverage_exclusions
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ProviderPayloadError::Invalid(
            "provider coverage exclusions must not contain exact duplicates".into(),
        ));
    }

    let documents = normalized
        .documents
        .iter()
        .map(|document| (document.document_path.as_str(), document))
        .collect::<BTreeMap<_, _>>();
    for document in &normalized.documents {
        if !safe_relative_path(&document.document_path) {
            return Err(ProviderPayloadError::Invalid(format!(
                "provider document path is not canonical and repository-relative: {}",
                document.document_path
            )));
        }
        validate_label("document language ID", &document.language_id.0)?;
        validate_sha256("document content fingerprint", &document.content_sha256)?;
        validate_sha256(
            "document cross-document surface fingerprint",
            &document.cross_document_surface_sha256,
        )?;
        validate_receipt_language(&payload.receipt.scope, &document.language_id)?;
    }

    for exclusion in &normalized.coverage_exclusions {
        validate_label("coverage exclusion reason code", &exclusion.reason_code)?;
        let document = validate_location(&exclusion.location, &documents)?;
        validate_receipt_language(&payload.receipt.scope, &document.language_id)?;
        if exclusion.location.span.start_byte == exclusion.location.span.end_byte {
            return Err(ProviderPayloadError::Invalid(format!(
                "coverage exclusion {} is empty",
                exclusion.reason_code
            )));
        }
    }

    let symbols = normalized
        .symbols
        .iter()
        .map(|symbol| (symbol.provider_symbol_id.as_str(), symbol))
        .collect::<BTreeMap<_, _>>();
    for symbol in &normalized.symbols {
        validate_label("provider-native symbol ID", &symbol.provider_symbol_id)?;
        validate_label("provider symbol name", &symbol.name)?;
        validate_label("provider symbol kind", &symbol.provider_kind)?;
        validate_label("provider symbol language ID", &symbol.language_id.0)?;
        validate_receipt_language(&payload.receipt.scope, &symbol.language_id)?;
        match symbol.role {
            ProviderSymbolRole::SourceInvocationTarget => {
                if symbol.definition.is_none() || symbol.structural_extent.is_none() {
                    return Err(ProviderPayloadError::Invalid(format!(
                        "source invocation target {} lacks a local definition or structural extent",
                        symbol.provider_symbol_id
                    )));
                }
            }
            ProviderSymbolRole::LocalInvocationTarget => {
                if symbol.definition.is_none()
                    || symbol.structural_extent.is_some()
                    || symbol.call_owner_extent.is_some()
                {
                    return Err(ProviderPayloadError::Invalid(format!(
                        "local invocation target {} has invalid structural or call-owner identity",
                        symbol.provider_symbol_id
                    )));
                }
            }
            ProviderSymbolRole::External => {
                if symbol.definition.is_some()
                    || symbol.structural_extent.is_some()
                    || symbol.call_owner_extent.is_some()
                {
                    return Err(ProviderPayloadError::Invalid(format!(
                        "external symbol {} unexpectedly has local source identity",
                        symbol.provider_symbol_id
                    )));
                }
            }
        }
        if let Some(definition) = &symbol.definition {
            let document = validate_location(definition, &documents)?;
            if document.language_id != symbol.language_id {
                return Err(ProviderPayloadError::Invalid(format!(
                    "symbol {} language {} differs from definition document language {}",
                    symbol.provider_symbol_id, symbol.language_id, document.language_id
                )));
            }
        }
        if let Some(structural_extent) = &symbol.structural_extent {
            let document = validate_location(structural_extent, &documents)?;
            if document.language_id != symbol.language_id {
                return Err(ProviderPayloadError::Invalid(format!(
                    "symbol {} language {} differs from structural extent document language {}",
                    symbol.provider_symbol_id, symbol.language_id, document.language_id
                )));
            }
            let Some(definition) = &symbol.definition else {
                return Err(ProviderPayloadError::Invalid(format!(
                    "symbol {} has a structural extent but no local definition",
                    symbol.provider_symbol_id
                )));
            };
            if structural_extent.document_path != definition.document_path
                || !span_contains(&structural_extent.span, &definition.span)
            {
                return Err(ProviderPayloadError::Invalid(format!(
                    "symbol {} definition is outside its structural extent",
                    symbol.provider_symbol_id
                )));
            }
            if structural_extent.span.start_byte == structural_extent.span.end_byte {
                return Err(ProviderPayloadError::Invalid(format!(
                    "symbol {} structural extent is empty",
                    symbol.provider_symbol_id
                )));
            }
        }
        if let Some(call_owner_extent) = &symbol.call_owner_extent {
            if symbol.role != ProviderSymbolRole::SourceInvocationTarget {
                return Err(ProviderPayloadError::Invalid(format!(
                    "symbol {} has a call-owner extent without source invocation identity",
                    symbol.provider_symbol_id
                )));
            }
            let document = validate_location(call_owner_extent, &documents)?;
            if document.language_id != symbol.language_id {
                return Err(ProviderPayloadError::Invalid(format!(
                    "symbol {} language {} differs from call-owner document language {}",
                    symbol.provider_symbol_id, symbol.language_id, document.language_id
                )));
            }
            let Some(structural_extent) = &symbol.structural_extent else {
                return Err(ProviderPayloadError::Invalid(format!(
                    "symbol {} has a call-owner extent but no structural extent",
                    symbol.provider_symbol_id
                )));
            };
            if call_owner_extent.document_path != structural_extent.document_path
                || !span_contains(&structural_extent.span, &call_owner_extent.span)
                || call_owner_extent.span.start_byte == call_owner_extent.span.end_byte
            {
                return Err(ProviderPayloadError::Invalid(format!(
                    "symbol {} call-owner extent is empty or outside its structural extent",
                    symbol.provider_symbol_id
                )));
            }
        }
    }

    for call in &normalized.calls {
        let Some(caller) = symbols.get(call.caller_symbol_id.as_str()) else {
            return Err(ProviderPayloadError::Invalid(format!(
                "call references missing caller symbol {}",
                call.caller_symbol_id
            )));
        };
        let Some(_callee) = symbols.get(call.callee_symbol_id.as_str()) else {
            return Err(ProviderPayloadError::Invalid(format!(
                "call references missing callee symbol {}",
                call.callee_symbol_id
            )));
        };
        let Some(caller_definition) = &caller.definition else {
            return Err(ProviderPayloadError::Invalid(format!(
                "caller symbol {} has no local definition",
                call.caller_symbol_id
            )));
        };
        let Some(caller_extent) = &caller.call_owner_extent else {
            return Err(ProviderPayloadError::Invalid(format!(
                "caller symbol {} has no call-owner extent",
                call.caller_symbol_id
            )));
        };
        validate_location(&call.call_site, &documents)?;
        if call.call_site.span.start_byte == call.call_site.span.end_byte {
            return Err(ProviderPayloadError::Invalid(format!(
                "call site for {} is empty",
                call.caller_symbol_id
            )));
        }
        if call.call_site.document_path != caller_definition.document_path {
            return Err(ProviderPayloadError::Invalid(format!(
                "call site for {} is outside its definition document",
                call.caller_symbol_id
            )));
        }
        if call.call_site.document_path != caller_extent.document_path
            || !span_contains(&caller_extent.span, &call.call_site.span)
        {
            return Err(ProviderPayloadError::Invalid(format!(
                "call site for {} is outside caller callable extent",
                call.caller_symbol_id
            )));
        }
    }

    for binding in &normalized.callable_bindings {
        let Some(binding_symbol) = symbols.get(binding.binding_symbol_id.as_str()) else {
            return Err(ProviderPayloadError::Invalid(format!(
                "callable binding references missing binding symbol {}",
                binding.binding_symbol_id
            )));
        };
        let Some(target_symbol) = symbols.get(binding.target_symbol_id.as_str()) else {
            return Err(ProviderPayloadError::Invalid(format!(
                "callable binding references missing target symbol {}",
                binding.target_symbol_id
            )));
        };
        if binding.binding_symbol_id == binding.target_symbol_id {
            return Err(ProviderPayloadError::Invalid(
                "callable binding cannot target itself".into(),
            ));
        }
        let Some(binding_extent) = &binding_symbol.structural_extent else {
            return Err(ProviderPayloadError::Invalid(format!(
                "callable binding symbol {} has no structural extent",
                binding.binding_symbol_id
            )));
        };
        if target_symbol.structural_extent.is_none() {
            return Err(ProviderPayloadError::Invalid(format!(
                "callable binding target {} has no structural extent",
                binding.target_symbol_id
            )));
        }
        validate_location(&binding.binding_site, &documents)?;
        if binding.binding_site.span.start_byte == binding.binding_site.span.end_byte {
            return Err(ProviderPayloadError::Invalid(format!(
                "callable binding site for {} is empty",
                binding.binding_symbol_id
            )));
        }
        if binding.binding_site.document_path != binding_extent.document_path
            || !span_contains(&binding_extent.span, &binding.binding_site.span)
        {
            return Err(ProviderPayloadError::Invalid(format!(
                "callable binding site for {} is outside its binding extent",
                binding.binding_symbol_id
            )));
        }
    }

    Ok(normalized)
}

fn normalize_callable_liveness_payload(
    payload: &CallableLivenessProviderPayload,
) -> Result<CallableLivenessProviderPayload, ProviderPayloadError> {
    if payload.schema_version != CALLABLE_LIVENESS_PROVIDER_PAYLOAD_SCHEMA {
        return Err(ProviderPayloadError::Invalid(format!(
            "unsupported callable-liveness provider payload schema {}",
            payload.schema_version
        )));
    }
    capability_receipt_id(&payload.receipt)?;
    if payload.receipt.capability_id != "callable_liveness" {
        return Err(ProviderPayloadError::Invalid(format!(
            "callable-liveness payload cannot substantiate capability {}",
            payload.receipt.capability_id
        )));
    }
    validate_provider_semantic_inputs(&payload.semantic_inputs, &ProviderFrameLimits::default())
        .map_err(|error| ProviderPayloadError::Invalid(error.to_string()))?;
    validate_execution_authority(&payload.execution_authority, &payload.receipt)?;
    validate_reconstruction_semantic_inputs(
        &payload.execution_authority,
        &payload.semantic_inputs,
    )?;

    let mut normalized = payload.clone();
    normalized.documents.sort();
    normalized.callables.sort();
    normalized.coverage_exclusions.sort();
    if normalized
        .documents
        .windows(2)
        .any(|pair| pair[0].document_path == pair[1].document_path)
    {
        return Err(ProviderPayloadError::Invalid(
            "callable-liveness document paths must be unique".into(),
        ));
    }
    if normalized
        .callables
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ProviderPayloadError::Invalid(
            "callable-liveness records must not contain exact duplicates".into(),
        ));
    }
    if normalized
        .coverage_exclusions
        .windows(2)
        .any(|pair| pair[0].document_path == pair[1].document_path)
    {
        return Err(ProviderPayloadError::Invalid(
            "callable-liveness document exclusions must be unique".into(),
        ));
    }
    let documents = normalized
        .documents
        .iter()
        .map(|document| (document.document_path.as_str(), document))
        .collect::<BTreeMap<_, _>>();
    if documents.is_empty() {
        return Err(ProviderPayloadError::Invalid(
            "callable-liveness document population is empty".into(),
        ));
    }
    for document in &normalized.documents {
        if !safe_relative_path(&document.document_path) {
            return Err(ProviderPayloadError::Invalid(format!(
                "callable-liveness document path is not canonical and repository-relative: {}",
                document.document_path
            )));
        }
        validate_label("document language ID", &document.language_id.0)?;
        validate_sha256("document content fingerprint", &document.content_sha256)?;
        validate_sha256(
            "document cross-document surface fingerprint",
            &document.cross_document_surface_sha256,
        )?;
        validate_receipt_language(&payload.receipt.scope, &document.language_id)?;
    }
    let excluded = normalized
        .coverage_exclusions
        .iter()
        .map(|exclusion| exclusion.document_path.as_str())
        .collect::<BTreeSet<_>>();
    for exclusion in &normalized.coverage_exclusions {
        if !documents.contains_key(exclusion.document_path.as_str()) {
            return Err(ProviderPayloadError::Invalid(format!(
                "callable-liveness exclusion references unknown document {}",
                exclusion.document_path
            )));
        }
        validate_label(
            "callable-liveness exclusion reason code",
            &exclusion.reason_code,
        )?;
    }
    for callable in &normalized.callables {
        validate_label("callable-liveness name", &callable.name)?;
        let definition = validate_location(&callable.definition, &documents)?;
        let extent = validate_location(&callable.structural_extent, &documents)?;
        if definition.language_id != extent.language_id
            || callable.definition.document_path != callable.structural_extent.document_path
            || excluded.contains(callable.definition.document_path.as_str())
            || callable.definition.span.start_byte < callable.structural_extent.span.start_byte
            || callable.definition.span.end_byte > callable.structural_extent.span.end_byte
            || callable.definition.span.start_line < callable.structural_extent.span.start_line
            || callable.definition.span.end_line > callable.structural_extent.span.end_line
        {
            return Err(ProviderPayloadError::Invalid(format!(
                "callable-liveness record {} has an invalid definition/extent relationship",
                callable.name
            )));
        }
        if callable.production_reachable && !callable.test_reachable {
            return Err(ProviderPayloadError::Invalid(format!(
                "production-reachable callable {} is absent from the superset test analysis",
                callable.name
            )));
        }
    }
    Ok(normalized)
}

fn validate_execution_authority(
    authority: &ProviderExecutionAuthority,
    receipt: &CapabilityReceipt,
) -> Result<(), ProviderPayloadError> {
    match authority {
        ProviderExecutionAuthority::InvocationBound {
            provider_configurations_sha256,
        } => validate_provider_configurations(provider_configurations_sha256, false),
        ProviderExecutionAuthority::ToolchainBound {
            resolver_policy_id,
            ecosystem_id,
            reuse_contract_id,
            provider_implementation_sha256,
            provider_inventory_sha256,
            roots,
        } => {
            if resolver_policy_id.is_empty()
                || resolver_policy_id.len() > 256
                || resolver_policy_id.contains('\0')
                || ecosystem_id.0.trim().is_empty()
                || reuse_contract_id.is_empty()
                || reuse_contract_id.len() > 256
                || reuse_contract_id.contains('\0')
                || !is_sha256(provider_implementation_sha256)
                || !is_sha256(provider_inventory_sha256)
                || roots.is_empty()
            {
                return Err(ProviderPayloadError::Invalid(
                    "toolchain-bound provider authority has invalid policy, ecosystem, contract, implementation, or root population"
                        .into(),
                ));
            }
            if roots
                .windows(2)
                .any(|pair| pair[0].execution_root >= pair[1].execution_root)
            {
                return Err(ProviderPayloadError::Invalid(
                    "toolchain-bound execution roots must be sorted and unique".into(),
                ));
            }
            let mut covered_units = BTreeMap::<ProjectUnitId, String>::new();
            let mut reconstruction_kind = None;
            for root in roots {
                validate_execution_prefix(&root.execution_root)?;
                if root.project_unit_ids.is_empty()
                    || root
                        .project_unit_ids
                        .windows(2)
                        .any(|pair| pair[0] >= pair[1])
                    || !is_sha256(&root.toolchain_fingerprint_sha256)
                    || !is_sha256(&root.provider_configuration_sha256)
                {
                    return Err(ProviderPayloadError::Invalid(
                        "toolchain-bound root authority has invalid unit or fingerprint evidence"
                            .into(),
                    ));
                }
                let current_kind = match &root.generation_reconstruction {
                    ProviderGenerationReconstruction::DeterministicInvocation => 0_u8,
                    ProviderGenerationReconstruction::ObservedWorkspace {
                        runtime_configuration_sha256,
                        workspace_resolution_sha256,
                        semantic_inputs,
                    } => {
                        if !is_sha256(runtime_configuration_sha256)
                            || !is_sha256(workspace_resolution_sha256)
                        {
                            return Err(ProviderPayloadError::Invalid(
                                "observed-workspace reconstruction has invalid identity evidence"
                                    .into(),
                            ));
                        }
                        validate_provider_semantic_inputs(
                            semantic_inputs,
                            &ProviderFrameLimits::default(),
                        )
                        .map_err(|error| ProviderPayloadError::Invalid(error.to_string()))?;
                        1
                    }
                };
                if reconstruction_kind
                    .replace(current_kind)
                    .is_some_and(|previous| previous != current_kind)
                {
                    return Err(ProviderPayloadError::Invalid(
                        "toolchain-bound execution roots must use one reconstruction contract"
                            .into(),
                    ));
                }
                for unit in &root.project_unit_ids {
                    if covered_units
                        .insert(unit.clone(), root.execution_root.clone())
                        .is_some()
                    {
                        return Err(ProviderPayloadError::Invalid(
                            "toolchain-bound project units must belong to exactly one execution root"
                                .into(),
                        ));
                    }
                }
            }
            let CapabilityScope::ProjectUnits {
                project_unit_ids, ..
            } = &receipt.scope
            else {
                return Err(ProviderPayloadError::Invalid(
                    "toolchain-bound one-shot authority requires a project-units receipt scope"
                        .into(),
                ));
            };
            if covered_units.keys().cloned().collect::<Vec<_>>() != *project_unit_ids {
                return Err(ProviderPayloadError::Invalid(
                    "toolchain-bound execution roots do not exactly cover the receipt project units"
                        .into(),
                ));
            }
            Ok(())
        }
    }
}

fn validate_reconstruction_semantic_inputs(
    authority: &ProviderExecutionAuthority,
    payload_inputs: &ProviderSemanticInputs,
) -> Result<(), ProviderPayloadError> {
    let ProviderExecutionAuthority::ToolchainBound { roots, .. } = authority else {
        return Ok(());
    };
    if roots.iter().all(|root| {
        matches!(
            &root.generation_reconstruction,
            ProviderGenerationReconstruction::DeterministicInvocation
        )
    }) {
        return Ok(());
    }

    let mut paths = BTreeMap::new();
    let mut environment = BTreeMap::new();
    let mut issues = BTreeSet::new();
    for root in roots {
        let ProviderGenerationReconstruction::ObservedWorkspace {
            semantic_inputs, ..
        } = &root.generation_reconstruction
        else {
            return Err(ProviderPayloadError::Invalid(
                "mixed reconstruction contracts cannot compose semantic inputs".into(),
            ));
        };
        for input in &semantic_inputs.paths {
            if paths
                .insert(input.path.clone(), input.clone())
                .is_some_and(|previous| previous != *input)
            {
                return Err(ProviderPayloadError::Invalid(format!(
                    "reconstruction path {} has conflicting identities",
                    input.path
                )));
            }
        }
        for input in &semantic_inputs.environment {
            if environment
                .insert(input.name.clone(), input.clone())
                .is_some_and(|previous| previous != *input)
            {
                return Err(ProviderPayloadError::Invalid(format!(
                    "reconstruction environment {} has conflicting identities",
                    input.name
                )));
            }
        }
        issues.extend(semantic_inputs.issues.iter().cloned());
    }
    let mut combined = ProviderSemanticInputs::empty();
    combined.paths = paths.into_values().collect();
    combined.environment = environment.into_values().collect();
    if !issues.is_empty() {
        combined.coverage = h00ligan_provider_protocol::ProviderSemanticInputCoverage::Unverifiable;
        combined.issues = issues.into_iter().collect();
    }
    if &combined != payload_inputs {
        return Err(ProviderPayloadError::Invalid(
            "root reconstruction inputs do not exactly compose the payload semantic inputs".into(),
        ));
    }
    Ok(())
}

fn validate_provider_configurations(
    configurations: &BTreeMap<String, String>,
    require_nonempty: bool,
) -> Result<(), ProviderPayloadError> {
    if require_nonempty && configurations.is_empty() {
        return Err(ProviderPayloadError::Invalid(
            "process-local authority requires an execution-root configuration population".into(),
        ));
    }
    for (execution_prefix, configuration_sha256) in configurations {
        validate_execution_prefix(execution_prefix)?;
        if !is_sha256(configuration_sha256) {
            return Err(ProviderPayloadError::Invalid(
                "provider configuration authority requires lowercase SHA-256 digests".into(),
            ));
        }
    }
    Ok(())
}

fn validate_execution_prefix(prefix: &str) -> Result<(), ProviderPayloadError> {
    let path = Path::new(prefix);
    if !prefix.is_empty()
        && (path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_))))
    {
        return Err(ProviderPayloadError::Invalid(
            "provider execution root is not canonical and repository-relative".into(),
        ));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn span_contains(outer: &NormalizedSourceSpan, inner: &NormalizedSourceSpan) -> bool {
    outer.start_byte <= inner.start_byte && inner.end_byte <= outer.end_byte
}

fn validate_location<'a>(
    location: &ProviderLocation,
    documents: &'a BTreeMap<&str, &ProviderDocument>,
) -> Result<&'a ProviderDocument, ProviderPayloadError> {
    let Some(document) = documents.get(location.document_path.as_str()).copied() else {
        return Err(ProviderPayloadError::Invalid(format!(
            "location references missing document {}",
            location.document_path
        )));
    };
    let span = &location.span;
    let byte_range_is_ordered = span.start_byte <= span.end_byte;
    let byte_range_is_within_document = span.end_byte <= document.byte_length;
    if !byte_range_is_ordered || !byte_range_is_within_document {
        return Err(ProviderPayloadError::Invalid(format!(
            "location byte range {}..{} exceeds document {} length {}",
            span.start_byte, span.end_byte, location.document_path, document.byte_length
        )));
    }
    if span.start_line > span.end_line
        || (span.start_line == span.end_line
            && span.start_utf8_byte_column > span.end_utf8_byte_column)
    {
        return Err(ProviderPayloadError::Invalid(format!(
            "location line/column range is reversed for {}",
            location.document_path
        )));
    }
    Ok(document)
}

fn validate_receipt_language(
    scope: &CapabilityScope,
    language_id: &LanguageId,
) -> Result<(), ProviderPayloadError> {
    let scoped_language = match scope {
        CapabilityScope::Repository { .. } => return Ok(()),
        CapabilityScope::Language { language_id, .. }
        | CapabilityScope::ProjectUnit { language_id, .. }
        | CapabilityScope::ProjectUnits { language_id, .. } => language_id,
    };
    if scoped_language != language_id {
        return Err(ProviderPayloadError::Invalid(format!(
            "payload language {language_id} is outside receipt language {scoped_language}"
        )));
    }
    Ok(())
}

fn validate_label(label: &str, value: &str) -> Result<(), ProviderPayloadError> {
    if value.trim().is_empty() || value.len() > 16 * 1024 || value.chars().any(char::is_control) {
        return Err(ProviderPayloadError::Invalid(format!(
            "{label} is empty, too long, or contains control characters"
        )));
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<(), ProviderPayloadError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ProviderPayloadError::Invalid(format!(
            "{label} is not a lowercase SHA-256"
        )));
    }
    Ok(())
}

fn safe_relative_path(path: &str) -> bool {
    let path = Path::new(path);
    let canonical_label = path.components().collect::<PathBuf>();
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && !path.as_os_str().to_string_lossy().contains('\\')
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && canonical_label.as_os_str().to_string_lossy() == path.as_os_str().to_string_lossy()
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Debug, Error)]
pub enum ProviderPayloadError {
    #[error("invalid provider payload: {0}")]
    Invalid(String),
    #[error("serialize provider payload: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_intel_domain::{CapabilityReceipt, ConfigurationId, ProjectUnitId, ProviderId};

    fn receipt(provider_id: &str) -> CapabilityReceipt {
        CapabilityReceipt::complete(
            "calls",
            provider_id,
            "1.0.0",
            CapabilityScope::ProjectUnit {
                language_id: LanguageId::new("rust"),
                project_unit_id: ProjectUnitId::new("workspace"),
                configuration_id: ConfigurationId::new("default"),
            },
            "a".repeat(64),
        )
    }

    fn location(start_byte: u64, end_byte: u64) -> ProviderLocation {
        ProviderLocation {
            document_path: "src/lib.rs".into(),
            span: NormalizedSourceSpan {
                start_byte,
                end_byte,
                start_line: 0,
                start_utf8_byte_column: start_byte as u32,
                end_line: 0,
                end_utf8_byte_column: end_byte as u32,
            },
        }
    }

    fn payload(provider_id: &str) -> ProviderPayload {
        ProviderPayload::Calls(CallsProviderPayload {
            schema_version: CALLS_PROVIDER_PAYLOAD_SCHEMA.into(),
            population: CallsPopulation::ProviderResolvedExplicitSourceInvocations,
            receipt: receipt(provider_id),
            semantic_inputs: ProviderSemanticInputs::empty(),
            execution_authority: ProviderExecutionAuthority::InvocationBound {
                provider_configurations_sha256: BTreeMap::new(),
            },
            canonical_snapshot_sha256: None,
            documents: vec![ProviderDocument {
                document_path: "src/lib.rs".into(),
                language_id: LanguageId::new("rust"),
                content_sha256: "b".repeat(64),
                cross_document_surface_sha256: "c".repeat(64),
                byte_length: 64,
            }],
            symbols: vec![
                ProviderSymbol {
                    provider_symbol_id: "callee".into(),
                    name: "callee".into(),
                    provider_kind: "function".into(),
                    language_id: LanguageId::new("rust"),
                    role: ProviderSymbolRole::SourceInvocationTarget,
                    definition: Some(location(40, 46)),
                    structural_extent: Some(location(32, 64)),
                    call_owner_extent: Some(location(32, 64)),
                },
                ProviderSymbol {
                    provider_symbol_id: "caller".into(),
                    name: "caller".into(),
                    provider_kind: "function".into(),
                    language_id: LanguageId::new("rust"),
                    role: ProviderSymbolRole::SourceInvocationTarget,
                    definition: Some(location(0, 6)),
                    structural_extent: Some(location(0, 32)),
                    call_owner_extent: Some(location(0, 32)),
                },
            ],
            calls: vec![ProviderCall {
                caller_symbol_id: "caller".into(),
                callee_symbol_id: "callee".into(),
                call_site: location(8, 14),
            }],
            callable_bindings: Vec::new(),
            coverage_exclusions: Vec::new(),
        })
    }

    #[test]
    fn canonical_payload_round_trip_is_order_independent() {
        let mut reversed = payload("provider-a");
        let ProviderPayload::Calls(document) = &mut reversed else {
            unreachable!("Calls fixture")
        };
        document.symbols.reverse();

        let canonical = canonical_provider_payload_bytes(&reversed).expect("canonical payload");
        let parsed =
            parse_canonical_provider_payload_bytes(&canonical).expect("parse canonical payload");
        assert_eq!(
            parsed.payload(),
            &normalize_provider_payload(&reversed).unwrap()
        );
        let expected_descriptor = provider_payload_descriptor(&payload("provider-a")).unwrap();
        assert_eq!(parsed.descriptor(), &expected_descriptor);

        let noncanonical = serde_json::to_vec(&reversed).expect("serialize input order");
        assert_ne!(noncanonical, canonical);
        assert!(matches!(
            parse_canonical_provider_payload_bytes(&noncanonical),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("not canonical")
        ));
    }

    #[test]
    fn normalized_payload_authority_mutation_validates_before_changing_state() {
        let mut normalized =
            normalize_provider_payload_typed(&payload("provider-a")).expect("normalized fixture");
        let unchanged = normalized.clone();

        let authority_error = normalized
            .bind_semantic_authority(
                ProviderSemanticInputs::empty(),
                ProviderExecutionAuthority::InvocationBound {
                    provider_configurations_sha256: BTreeMap::from([(
                        String::new(),
                        "not-a-sha256".into(),
                    )]),
                },
            )
            .expect_err("invalid execution authority must fail closed");
        assert!(authority_error.to_string().contains("configuration"));
        assert_eq!(normalized, unchanged, "failed mutation must be atomic");
    }

    #[test]
    fn canonical_seal_of_normalized_payload_does_not_normalize_again() {
        reset_provider_payload_normalizations();
        let normalized =
            normalize_provider_payload_typed(&payload("provider-a")).expect("normalized fixture");
        assert_eq!(provider_payload_normalizations(), 1, "positive control");

        let (canonical, timings) =
            canonicalize_normalized_provider_payload_profiled(normalized.clone())
                .expect("canonical seal");
        let shared = canonical.normalized_clone();

        assert_eq!(provider_payload_normalizations(), 1);
        assert_eq!(timings.normalization, Duration::ZERO);
        assert_eq!(canonical.payload(), normalized.payload());
        assert!(
            shared.shares_allocation_with(&normalized),
            "the canonical seal and retained normalized evidence must share one immutable payload allocation"
        );
        assert_eq!(
            canonical.bytes(),
            canonical_provider_payload_bytes(normalized.payload())
                .expect("independent canonical byte control")
        );
    }

    #[test]
    fn provider_native_symbol_ids_are_isolated_by_receipt_and_payload_identity() {
        let first = provider_payload_descriptor(&payload("provider-a")).unwrap();
        let second = provider_payload_descriptor(&payload("provider-b")).unwrap();

        assert_ne!(first.receipt_id, second.receipt_id);
        assert_ne!(first.payload_id, second.payload_id);
        assert_ne!(first.payload_sha256, second.payload_sha256);
        assert_eq!(first.provider_id, ProviderId::new("provider-a"));
        assert_eq!(second.provider_id, ProviderId::new("provider-b"));
    }

    #[test]
    fn unsafe_paths_ranges_and_missing_symbols_fail_closed() {
        let mut invalid_surface = payload("provider-a");
        let ProviderPayload::Calls(document) = &mut invalid_surface else {
            unreachable!("Calls fixture")
        };
        document.documents[0].cross_document_surface_sha256 = "not-a-sha256".into();
        assert!(matches!(
            normalize_provider_payload(&invalid_surface),
            Err(ProviderPayloadError::Invalid(reason))
                if reason.contains("cross-document surface fingerprint")
        ));

        let mut unsafe_path = payload("provider-a");
        let ProviderPayload::Calls(document) = &mut unsafe_path else {
            unreachable!("Calls fixture")
        };
        document.documents[0].document_path = "src//lib.rs".into();
        assert!(matches!(
            normalize_provider_payload(&unsafe_path),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("repository-relative")
        ));

        let mut oversized_range = payload("provider-a");
        let ProviderPayload::Calls(document) = &mut oversized_range else {
            unreachable!("Calls fixture")
        };
        document.symbols[0].definition = Some(location(32, 65));
        assert!(matches!(
            normalize_provider_payload(&oversized_range),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("exceeds document")
        ));

        let mut missing_symbol = payload("provider-a");
        let ProviderPayload::Calls(document) = &mut missing_symbol else {
            unreachable!("Calls fixture")
        };
        document.calls[0].callee_symbol_id = "absent".into();
        assert!(matches!(
            normalize_provider_payload(&missing_symbol),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("missing callee")
        ));
    }

    #[test]
    fn conflicting_or_incomplete_payload_evidence_fails_closed() {
        let mut duplicate_symbol = payload("provider-a");
        let ProviderPayload::Calls(document) = &mut duplicate_symbol else {
            unreachable!("Calls fixture")
        };
        document.symbols.push(document.symbols[0].clone());
        assert!(matches!(
            normalize_provider_payload(&duplicate_symbol),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("symbol IDs must be unique")
        ));

        let mut missing_site = serde_json::to_value(payload("provider-a")).unwrap();
        missing_site["payload"]["calls"][0]
            .as_object_mut()
            .unwrap()
            .remove("call_site");
        assert!(serde_json::from_value::<ProviderPayload>(missing_site).is_err());

        let mut incomplete_receipt = payload("provider-a");
        let ProviderPayload::Calls(document) = &mut incomplete_receipt else {
            unreachable!("Calls fixture")
        };
        document.receipt.status = crate::code_intel_domain::CapabilityStatus::Partial;
        document.receipt.reason_code = Some("partial".into());
        document.receipt.reason = Some("partial evidence".into());
        assert!(matches!(
            normalize_provider_payload(&incomplete_receipt),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("status must be complete")
        ));
    }

    #[test]
    fn complete_calls_payload_has_no_weaker_confidence_state() {
        let mut legacy_weaker_evidence = serde_json::to_value(payload("provider-a")).unwrap();
        legacy_weaker_evidence["payload"]["calls"][0]["confidence"] =
            serde_json::Value::String("provider_reported".into());

        let error = serde_json::from_value::<ProviderPayload>(legacy_weaker_evidence)
            .expect_err("exact Calls schema must reject a weaker confidence state");
        assert!(error.to_string().contains("unknown field `confidence`"));
    }

    #[test]
    fn complete_calls_payload_rejects_call_site_outside_claimed_caller() {
        let mut wrong_owner = payload("provider-a");
        let ProviderPayload::Calls(document) = &mut wrong_owner else {
            unreachable!("Calls fixture")
        };
        document.calls[0].call_site = location(48, 54);

        assert!(matches!(
            normalize_provider_payload(&wrong_owner),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("outside caller callable extent")
        ));

        let mut missing_extent = payload("provider-a");
        let ProviderPayload::Calls(document) = &mut missing_extent else {
            unreachable!("Calls fixture")
        };
        document
            .symbols
            .iter_mut()
            .find(|symbol| symbol.provider_symbol_id == "caller")
            .unwrap()
            .call_owner_extent = None;
        assert!(matches!(
            normalize_provider_payload(&missing_extent),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("has no call-owner extent")
        ));
    }

    /// RIGHT-REASON REGRESSION for B06: removing the extent from a declared
    /// source callable must not silently reclassify it as a dynamic or external
    /// target. The independent role discriminant makes that mutation invalid.
    #[test]
    fn local_call_target_without_structural_extent_is_not_reclassified_as_external() {
        let mut payload = payload("provider-a");
        let ProviderPayload::Calls(document) = &mut payload else {
            unreachable!("Calls fixture")
        };
        document
            .symbols
            .iter_mut()
            .find(|symbol| symbol.provider_symbol_id == "callee")
            .expect("local callee control")
            .structural_extent = None;

        assert!(matches!(
            normalize_provider_payload(&payload),
            Err(ProviderPayloadError::Invalid(reason))
                if reason.contains("source invocation target callee lacks a local definition or structural extent")
        ));
    }

    #[test]
    fn callable_bindings_require_exact_owned_callable_endpoints() {
        let binding = ProviderCallableBinding {
            binding_symbol_id: "caller".into(),
            target_symbol_id: "callee".into(),
            binding_site: location(8, 14),
        };
        let mut valid = payload("provider-a");
        let ProviderPayload::Calls(document) = &mut valid else {
            unreachable!("Calls fixture")
        };
        document.callable_bindings.push(binding);
        normalize_provider_payload(&valid).expect("control: exact callable binding is valid");

        let mut missing_binding = valid.clone();
        let ProviderPayload::Calls(document) = &mut missing_binding else {
            unreachable!("Calls fixture")
        };
        document.callable_bindings[0].binding_symbol_id = "absent".into();
        assert!(matches!(
            normalize_provider_payload(&missing_binding),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("missing binding symbol")
        ));

        let mut missing_target = valid.clone();
        let ProviderPayload::Calls(document) = &mut missing_target else {
            unreachable!("Calls fixture")
        };
        document.callable_bindings[0].target_symbol_id = "absent".into();
        assert!(matches!(
            normalize_provider_payload(&missing_target),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("missing target symbol")
        ));

        let mut self_binding = valid.clone();
        let ProviderPayload::Calls(document) = &mut self_binding else {
            unreachable!("Calls fixture")
        };
        document.callable_bindings[0].target_symbol_id = "caller".into();
        assert!(matches!(
            normalize_provider_payload(&self_binding),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("cannot target itself")
        ));

        let mut outside_extent = valid.clone();
        let ProviderPayload::Calls(document) = &mut outside_extent else {
            unreachable!("Calls fixture")
        };
        document.callable_bindings[0].binding_site = location(40, 46);
        assert!(matches!(
            normalize_provider_payload(&outside_extent),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("outside its binding extent")
        ));

        let mut missing_target_extent = valid;
        let ProviderPayload::Calls(document) = &mut missing_target_extent else {
            unreachable!("Calls fixture")
        };
        document
            .symbols
            .iter_mut()
            .find(|symbol| symbol.provider_symbol_id == "callee")
            .unwrap()
            .structural_extent = None;
        assert!(matches!(
            normalize_provider_payload(&missing_target_extent),
            Err(ProviderPayloadError::Invalid(reason)) if reason.contains("source invocation target callee lacks a local definition or structural extent")
        ));
    }
}
