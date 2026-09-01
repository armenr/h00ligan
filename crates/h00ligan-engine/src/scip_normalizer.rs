//! Normalize one provider-isolated SCIP artifact into canonical Calls evidence.
//!
//! SCIP resolves symbol identity, but the protocol has no call role. A plain
//! reference to a function can be an invocation, a function value, or another
//! use. This adapter therefore emits a call only when two independent facts
//! agree: the provider resolved the occurrence to a local callable symbol and
//! source syntax independently proves an explicit invocation. Registered
//! language grammars identify ordinary calls; inside an opaque Rust macro
//! token tree, the exact callee token must be followed only by trivia and `(`.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use h00ligan_provider_protocol::{
    H00_GO_LANGUAGE, H00_GO_PROVIDER_ID, H00_PYREFLY_LANGUAGE, H00_PYREFLY_PROVIDER_ID,
    H00_RUST_ANALYZER_LANGUAGE, H00_RUST_ANALYZER_PROVIDER_ID, H00_TYPESCRIPT_LANGUAGE,
    H00_TYPESCRIPT_PROVIDER_ID,
};
use protobuf::{Enum as _, EnumOrUnknown, Message as _, MessageField};
use scip::types::{
    Document, Index, Metadata, PositionEncoding, SymbolRole, TextEncoding, ToolInfo, descriptor,
    symbol_information,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tree_sitter::Node;

use crate::code_intel_domain::{
    CALLS_CONFIGURATION_ID, CallsPopulation, CapabilityReceipt, CapabilityScope, CapabilityStatus,
    ConfigurationId, LanguageId, ProjectInventory,
};
#[cfg(test)]
use crate::code_intel_inventory::project_inventory_fingerprint;
use crate::code_intel_inventory::{
    semantic_provider_inventory_fingerprint, semantic_provider_unit_execution_roots,
};
use crate::code_intel_payload::{
    CALLS_PROVIDER_PAYLOAD_SCHEMA, CallsProviderPayload, NormalizedProviderPayload,
    NormalizedSourceSpan, ProviderCall, ProviderCallableBinding, ProviderCoverageExclusion,
    ProviderDocument, ProviderExecutionAuthority, ProviderLocation, ProviderPayload,
    ProviderRootInvocation, ProviderSymbol, ProviderSymbolRole, normalize_provider_payload_typed,
};
use crate::language::NamedCallForm;
use crate::scip_paths::{execution_prefix, repository_document_path};

const NORMALIZER_FINGERPRINT_SCHEMA: &[u8] = b"h00/scip-calls-normalizer/v18\0";
const CANONICAL_SCIP_SNAPSHOT_SCHEMA: &[u8] = b"h00/canonical-scip-snapshot/v5\0";
const CANONICAL_SCIP_INPUT_SCHEMA: &[u8] = b"h00/canonical-scip-input/v1\0";
const UNCONFIGURED_SCIP_INPUT: &[u8] = b"h00/scip-provider-configuration/unavailable/v1\0";
const SCIP_GO_UNSPECIFIED_POSITION_ENCODING_VERSION: &str = "0.2.7";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedSourceEvidence {
    pub relative_path: String,
    pub language: String,
    pub blake3_hash: String,
    /// Exact structural-extraction evidence. `None` means the source was
    /// discovered but its semantic surface was not authoritatively extracted,
    /// so Complete provider authority is impossible.
    pub cross_document_surface_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScipProviderSpec {
    pub language: &'static str,
    pub ecosystem: &'static str,
    pub provider_id: &'static str,
    pub tool_name: &'static str,
}

impl ScipProviderSpec {
    pub const fn rust_analyzer() -> Self {
        Self {
            language: "rust",
            ecosystem: "cargo",
            provider_id: "rust-analyzer-scip",
            tool_name: "rust-analyzer",
        }
    }

    pub const fn scip_go() -> Self {
        Self {
            language: "go",
            ecosystem: "go",
            provider_id: "scip-go",
            tool_name: "scip-go",
        }
    }

    /// The persistent h00ligan-owned rust-analyzer process is a distinct provider
    /// lineage from the stock one-shot `rust-analyzer scip` executable. Their
    /// documents share a format, but incremental output may extend only a
    /// baseline certified by this exact provider.
    pub const fn rust_analyzer_sidecar() -> Self {
        Self {
            language: H00_RUST_ANALYZER_LANGUAGE,
            ecosystem: "cargo",
            provider_id: H00_RUST_ANALYZER_PROVIDER_ID,
            tool_name: "rust-analyzer",
        }
    }

    /// The persistent h00ligan-owned gopls/scip-go composition has its own exact
    /// lineage while emitting ordinary canonical Go SCIP documents.
    pub const fn gopls_sidecar() -> Self {
        Self {
            language: H00_GO_LANGUAGE,
            ecosystem: "go",
            provider_id: H00_GO_PROVIDER_ID,
            tool_name: H00_GO_PROVIDER_ID,
        }
    }

    /// The persistent h00ligan-owned Pyrefly process emits canonical Python SCIP
    /// documents under its own exact provider lineage.
    pub const fn pyrefly_sidecar() -> Self {
        Self {
            language: H00_PYREFLY_LANGUAGE,
            ecosystem: "python",
            provider_id: H00_PYREFLY_PROVIDER_ID,
            tool_name: H00_PYREFLY_PROVIDER_ID,
        }
    }

    /// The persistent h00ligan-owned TypeScript native compiler emits canonical
    /// TypeScript SCIP documents under its own exact provider lineage.
    pub const fn typescript_native_sidecar() -> Self {
        Self {
            language: H00_TYPESCRIPT_LANGUAGE,
            ecosystem: "node",
            provider_id: H00_TYPESCRIPT_PROVIDER_ID,
            tool_name: H00_TYPESCRIPT_PROVIDER_ID,
        }
    }

    /// Resolve one h00ligan-owned persistent provider lineage from the exact
    /// protocol identity carried across process and cache boundaries.
    /// Keeping this population beside the canonical specs prevents provider
    /// admission and cross-process cache support from drifting by language.
    pub(crate) fn persistent_from_lineage(provider_id: &str, language: &str) -> Option<Self> {
        [
            Self::rust_analyzer_sidecar(),
            Self::gopls_sidecar(),
            Self::pyrefly_sidecar(),
            Self::typescript_native_sidecar(),
        ]
        .into_iter()
        .find(|spec| spec.provider_id == provider_id && spec.language == language)
    }

    /// Resolve every provider lineage whose exact canonical snapshot may be
    /// retained as disposable cross-process acceleration. The stock Go
    /// provider has a separate deterministic reuse contract; persistent
    /// providers share the registry above.
    pub(crate) fn cacheable_from_lineage(provider_id: &str, language: &str) -> Option<Self> {
        let stock_go = Self::scip_go();
        (stock_go.provider_id == provider_id && stock_go.language == language)
            .then_some(stock_go)
            .or_else(|| Self::persistent_from_lineage(provider_id, language))
    }

    fn scope(self) -> CapabilityScope {
        CapabilityScope::Language {
            language_id: LanguageId::new(self.language),
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScipArtifactEvidence {
    pub language_id: LanguageId,
    pub receipt: CapabilityReceipt,
    pub payload: Option<NormalizedProviderPayload>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScipArtifactInput {
    pub artifact_path: PathBuf,
    pub execution_root: PathBuf,
    pub executed_provider_version: String,
    /// Exact product-resolved provider/toolchain configuration used for this
    /// execution root. It is incorporated into the canonical snapshot and
    /// persisted payload so later reuse cannot trust ambient version text.
    pub provider_configuration_sha256: String,
}

/// One admitted semantic-provider result shared by both canonical Calls
/// normalization and residual graph projection.
pub struct ScipArtifactSetNormalization {
    pub evidence: ScipArtifactEvidence,
    /// Independently typed capabilities returned by the same admitted
    /// provider terminal. These are sealed and published beside, but never
    /// reinterpreted as, the primary canonical Calls evidence.
    pub supplemental_evidence: Vec<ScipArtifactEvidence>,
    pub canonical_snapshot: Option<CanonicalScipSnapshot>,
    /// Disposable syntax acceleration derived from exact source bytes.
    /// Publication authority never depends on this cache being present.
    pub(crate) source_syntax_cache: Option<CanonicalSourceSyntaxCache>,
    pub(crate) timings: ScipNormalizationTimings,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ScipNormalizationTimings {
    /// Direct wall clock for the complete normalizer. This is retained only
    /// to partition enclosing work; it is not exported beside its components.
    pub total: Duration,
    pub setup: Duration,
    pub source_validation: Duration,
    pub coverage_exclusion_setup: Duration,
    pub occurrence_indexing: Duration,
    pub definition_collection: Duration,
    pub definition_canonicalization: Duration,
    pub binding_and_lookup_indexing: Duration,
    pub call_resolution: Duration,
    pub coverage_validation: Duration,
    pub payload_finalization: Duration,
    pub source_documents: u64,
    pub syntax_cache_hits: u64,
    pub provider_documents: u64,
    pub provider_document_cache_hits: u64,
    pub definition_document_cache_hits: u64,
    pub definition_groups: u64,
    pub definition_group_reuse_hits: u64,
    pub call_documents: u64,
    pub call_document_reuse_hits: u64,
}

/// One canonical provider snapshot paired with the exact final evidence that
/// was admitted into the same immutable generation.
///
/// This is process-local acceleration, never publication authority. A later
/// pipeline run must independently revalidate current source, project-input,
/// provider, and toolchain identity before it may reuse the pair.
#[derive(Clone)]
pub struct CanonicalSemanticBasis {
    pub snapshot: CanonicalScipSnapshot,
    pub evidence: ScipArtifactEvidence,
    pub supplemental_evidence: Vec<ScipArtifactEvidence>,
    pub(crate) source_syntax_cache: Option<CanonicalSourceSyntaxCache>,
}

/// Process-local, content-addressed source syntax acceleration.
///
/// Every normalization still reads and hashes the current source population
/// and reruns repository-wide symbol resolution. Only the deterministic
/// document-local tree-sitter census and line table may be reused.
#[derive(Clone)]
pub struct CanonicalSourceSyntaxCache {
    language: String,
    documents: Arc<BTreeMap<String, CachedSourceSyntaxDocument>>,
    provider_documents: Arc<BTreeMap<String, CachedProviderNormalizationDocument>>,
    canonical_definitions: Option<CachedCanonicalDefinitionGroups>,
}

#[derive(Clone)]
struct CachedSourceSyntaxDocument {
    blake3_hash: String,
    content_sha256: String,
    byte_length: u64,
    line_ranges: Arc<[(usize, usize)]>,
    syntax: Arc<SourceSyntaxEvidence>,
}

/// One exact repository-wide provider document population.
///
/// Full certification and affected-document refresh both normalize through
/// this same snapshot so the incremental lane cannot invent a weaker
/// resolution algorithm.
#[derive(Clone)]
pub struct CanonicalScipSnapshot {
    root: PathBuf,
    provider: CanonicalScipProviderCoordinate,
    scope: CapabilityScope,
    execution_root_prefixes: BTreeSet<String>,
    /// Canonical SCIP fields that are invariant across document overlays. Its
    /// `documents` population is always empty; documents are retained as
    /// independently shared immutable shards below.
    index_envelope: Arc<Index>,
    documents_by_path: Arc<BTreeMap<String, Arc<Document>>>,
    document_manifest_sha256: String,
    document_sha256_by_path: BTreeMap<String, String>,
}

/// Exact provider-side coordinate owned by one canonical document snapshot.
/// Keeping lineage and per-root invocation identities together prevents
/// affected refresh, cache rehydration, and full composition from accepting
/// subtly different subsets of the same provider authority.
#[derive(Clone)]
struct CanonicalScipProviderCoordinate {
    spec: ScipProviderSpec,
    executed_version: String,
    implementation_sha256: Option<String>,
    configurations_sha256: BTreeMap<String, String>,
}

impl CanonicalScipProviderCoordinate {
    fn new(
        spec: ScipProviderSpec,
        executed_version: impl Into<String>,
        implementation_sha256: Option<String>,
        configurations_sha256: BTreeMap<String, String>,
    ) -> Result<Self, CanonicalScipSnapshotError> {
        let executed_version = executed_version.into().trim().to_owned();
        if executed_version.is_empty() {
            return Err(CanonicalScipSnapshotError(
                "canonical snapshot provider version is empty".into(),
            ));
        }
        if implementation_sha256.as_ref().is_some_and(|digest| {
            digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err(CanonicalScipSnapshotError(
                "canonical snapshot provider implementation identity is not lowercase SHA-256"
                    .into(),
            ));
        }
        Ok(Self {
            spec,
            executed_version,
            implementation_sha256,
            configurations_sha256,
        })
    }

    fn has_same_lineage(&self, other: &Self) -> bool {
        self.spec == other.spec
            && self.executed_version == other.executed_version
            && self.implementation_sha256 == other.implementation_sha256
    }
}

/// One exact outcome for an affected canonical provider document. Providers
/// may omit a source that has no SCIP occurrences, so omission is explicit
/// rather than inferred from a missing response.
#[derive(Clone)]
pub enum CanonicalScipDocumentUpdate {
    Present {
        document_path: String,
        document: Document,
    },
    Omitted {
        document_path: String,
    },
}

#[derive(Debug, Error)]
#[error("invalid canonical SCIP snapshot: {0}")]
pub struct CanonicalScipSnapshotError(String);

impl CanonicalScipSnapshot {
    fn from_composed_index(
        root: PathBuf,
        provider: CanonicalScipProviderCoordinate,
        scope: CapabilityScope,
        execution_root_prefixes: BTreeSet<String>,
        mut index: Index,
    ) -> Result<Self, CanonicalScipSnapshotError> {
        let metadata = index.metadata.as_ref().ok_or_else(|| {
            CanonicalScipSnapshotError("canonical SCIP snapshot has no metadata".into())
        })?;
        let tool = metadata.tool_info.as_ref().ok_or_else(|| {
            CanonicalScipSnapshotError("canonical SCIP snapshot has no tool identity".into())
        })?;
        if tool.name != provider.spec.tool_name || tool.version.trim() != provider.executed_version
        {
            return Err(CanonicalScipSnapshotError(format!(
                "canonical SCIP tool identity {:?} {:?} differs from admitted {} {:?}",
                tool.name, tool.version, provider.spec.tool_name, provider.executed_version
            )));
        }
        validate_provider_configuration_population(
            &execution_root_prefixes,
            &provider.configurations_sha256,
        )?;
        let (document_manifest_sha256, document_sha256_by_path) =
            canonicalize_snapshot_documents(provider.spec, &mut index.documents)?;
        let documents_by_path = std::mem::take(&mut index.documents)
            .into_iter()
            .map(|document| (document.relative_path.clone(), Arc::new(document)))
            .collect::<BTreeMap<_, _>>();
        if documents_by_path.keys().ne(document_sha256_by_path.keys()) {
            return Err(CanonicalScipSnapshotError(
                "canonical document and identity populations diverged".into(),
            ));
        }
        Ok(Self {
            root,
            provider,
            scope,
            execution_root_prefixes,
            index_envelope: Arc::new(index),
            documents_by_path: Arc::new(documents_by_path),
            document_manifest_sha256,
            document_sha256_by_path,
        })
    }

    fn with_shared_documents(
        &self,
        provider: CanonicalScipProviderCoordinate,
        documents_by_path: BTreeMap<String, Arc<Document>>,
        document_sha256_by_path: BTreeMap<String, String>,
    ) -> Result<Self, CanonicalScipSnapshotError> {
        if documents_by_path.keys().ne(document_sha256_by_path.keys()) {
            return Err(CanonicalScipSnapshotError(
                "canonical document and identity populations diverged".into(),
            ));
        }
        validate_provider_configuration_population(
            &self.execution_root_prefixes,
            &provider.configurations_sha256,
        )?;
        let document_manifest_sha256 = canonical_document_manifest_sha256(&document_sha256_by_path);
        Ok(Self {
            root: self.root.clone(),
            provider,
            scope: self.scope.clone(),
            execution_root_prefixes: self.execution_root_prefixes.clone(),
            index_envelope: Arc::clone(&self.index_envelope),
            documents_by_path: Arc::new(documents_by_path),
            document_manifest_sha256,
            document_sha256_by_path,
        })
    }

    #[cfg(test)]
    pub(crate) fn document_manifest_sha256(&self) -> &str {
        &self.document_manifest_sha256
    }

    pub(crate) fn identity_sha256(&self) -> String {
        sha256_hex(&self.fingerprint_material())
    }

    pub(crate) fn encoded_index(&self) -> Result<Vec<u8>, CanonicalScipSnapshotError> {
        let mut index = self.index_envelope.as_ref().clone();
        index.documents = self
            .documents_by_path
            .values()
            .map(|document| document.as_ref().clone())
            .collect();
        index.write_to_bytes().map_err(|error| {
            CanonicalScipSnapshotError(format!("cannot serialize canonical SCIP snapshot: {error}"))
        })
    }

    pub(crate) fn documents(&self) -> impl Iterator<Item = &Document> {
        self.documents_by_path
            .values()
            .map(|document| document.as_ref())
    }

    #[cfg(test)]
    fn document_storage_address(&self, document_path: &str) -> Option<*const Document> {
        self.documents_by_path.get(document_path).map(Arc::as_ptr)
    }

    #[cfg(test)]
    fn document_count(&self) -> usize {
        self.documents_by_path.len()
    }

    #[cfg(test)]
    fn has_external_symbols(&self) -> bool {
        !self.index_envelope.external_symbols.is_empty()
    }

    pub(crate) const fn provider_configurations_sha256(&self) -> &BTreeMap<String, String> {
        &self.provider.configurations_sha256
    }

    pub(crate) const fn provider_id(&self) -> &'static str {
        self.provider.spec.provider_id
    }

    pub(crate) fn executed_provider_version(&self) -> &str {
        &self.provider.executed_version
    }

    pub(crate) fn provider_implementation_sha256(&self) -> Option<&str> {
        self.provider.implementation_sha256.as_deref()
    }

    pub(crate) fn provider_configuration_sha256_for_execution_root(
        &self,
        execution_root: &Path,
    ) -> Result<Option<&str>, CanonicalScipSnapshotError> {
        let prefix = execution_prefix(&self.root, execution_root)
            .map_err(|error| CanonicalScipSnapshotError(error.to_string()))?
            .to_string_lossy()
            .replace('\\', "/");
        Ok(self
            .provider
            .configurations_sha256
            .get(&prefix)
            .map(String::as_str))
    }

    /// Replace the complete provider-document slice owned by one execution
    /// root while retaining every sibling root byte-for-byte.
    ///
    /// The replacement artifact is still validated against the canonical
    /// provider/version/configuration/root population. Documents are assigned
    /// to the deepest configured execution-root prefix so an outer workspace
    /// can never overwrite a separately scheduled nested root. The resulting
    /// repository-wide snapshot must still pass ordinary global normalization
    /// before it can carry capability authority.
    pub(crate) fn replace_execution_root_artifact(
        &self,
        artifact: &ScipArtifactInput,
    ) -> Result<Self, CanonicalScipSnapshotError> {
        let execution_root = fs::canonicalize(&artifact.execution_root).map_err(|error| {
            CanonicalScipSnapshotError(format!(
                "cannot resolve replacement execution root: {error}"
            ))
        })?;
        let prefix = execution_prefix(&self.root, &execution_root)
            .map_err(|error| CanonicalScipSnapshotError(error.to_string()))?;
        let prefix_text = prefix.to_string_lossy().replace('\\', "/");
        if !self.execution_root_prefixes.contains(&prefix_text) {
            return Err(CanonicalScipSnapshotError(format!(
                "replacement execution root {prefix_text:?} is outside the canonical population"
            )));
        }
        if artifact.executed_provider_version != self.provider.executed_version {
            return Err(CanonicalScipSnapshotError(
                "replacement provider version differs from the canonical snapshot".into(),
            ));
        }
        if self.provider.configurations_sha256.get(&prefix_text)
            != Some(&artifact.provider_configuration_sha256)
        {
            return Err(CanonicalScipSnapshotError(
                "replacement provider configuration differs from the canonical execution root"
                    .into(),
            ));
        }

        let bytes = fs::read(&artifact.artifact_path).map_err(|error| {
            CanonicalScipSnapshotError(format!("cannot read replacement SCIP artifact: {error}"))
        })?;
        let replacement = Index::parse_from_bytes(&bytes).map_err(|error| {
            CanonicalScipSnapshotError(format!("cannot decode replacement SCIP artifact: {error}"))
        })?;
        let metadata = replacement.metadata.as_ref().ok_or_else(|| {
            CanonicalScipSnapshotError("replacement SCIP artifact has no metadata".into())
        })?;
        let tool = metadata.tool_info.as_ref().ok_or_else(|| {
            CanonicalScipSnapshotError("replacement SCIP artifact has no tool identity".into())
        })?;
        if tool.name != self.provider.spec.tool_name
            || tool.version.trim() != self.provider.executed_version
        {
            return Err(CanonicalScipSnapshotError(
                "replacement SCIP artifact has the wrong provider identity".into(),
            ));
        }
        if metadata.text_document_encoding.enum_value() != Ok(TextEncoding::UTF8) {
            return Err(CanonicalScipSnapshotError(
                "replacement SCIP artifact does not use UTF-8 source positions".into(),
            ));
        }
        let artifact_root = file_uri_path(&metadata.project_root)
            .map_err(|error| CanonicalScipSnapshotError(error.detail))
            .and_then(|path| {
                fs::canonicalize(path).map_err(|error| {
                    CanonicalScipSnapshotError(format!(
                        "cannot resolve replacement SCIP project root: {error}"
                    ))
                })
            })?;
        if artifact_root != execution_root {
            return Err(CanonicalScipSnapshotError(
                "replacement SCIP project root differs from its admitted execution root".into(),
            ));
        }

        let owner_for_document = |document_path: &str| {
            self.execution_root_prefixes
                .iter()
                .filter(|candidate| {
                    candidate.is_empty()
                        || Path::new(document_path).starts_with(Path::new(candidate.as_str()))
                })
                .max_by(|left, right| {
                    Path::new(left.as_str())
                        .components()
                        .count()
                        .cmp(&Path::new(right.as_str()).components().count())
                        .then_with(|| left.cmp(right))
                })
        };
        let mut replacement_documents = BTreeMap::new();
        for mut document in replacement.documents {
            let Ok(repository_path) =
                repository_document_path(Path::new(&prefix_text), &document.relative_path)
            else {
                continue;
            };
            if owner_for_document(&repository_path).map(String::as_str)
                != Some(prefix_text.as_str())
            {
                continue;
            }
            document.relative_path = repository_path.clone();
            canonicalize_scip_document(&mut document)?;
            let document_sha256 = canonical_document_sha256(&document)?;
            if replacement_documents
                .insert(
                    repository_path.clone(),
                    (Arc::new(document), document_sha256),
                )
                .is_some()
            {
                return Err(CanonicalScipSnapshotError(format!(
                    "replacement SCIP artifact contains duplicate document {repository_path:?}"
                )));
            }
        }

        let mut documents_by_path = self
            .documents_by_path
            .iter()
            .filter(|(document_path, _)| {
                owner_for_document(document_path).map(String::as_str) != Some(prefix_text.as_str())
            })
            .map(|(document_path, document)| (document_path.clone(), Arc::clone(document)))
            .collect::<BTreeMap<_, _>>();
        let mut document_sha256_by_path = self
            .document_sha256_by_path
            .iter()
            .filter(|(document_path, _)| {
                owner_for_document(document_path).map(String::as_str) != Some(prefix_text.as_str())
            })
            .map(|(document_path, digest)| (document_path.clone(), digest.clone()))
            .collect::<BTreeMap<_, _>>();
        for (path, (document, document_sha256)) in replacement_documents {
            if documents_by_path.insert(path.clone(), document).is_some()
                || document_sha256_by_path
                    .insert(path.clone(), document_sha256)
                    .is_some()
            {
                return Err(CanonicalScipSnapshotError(format!(
                    "replacement execution root conflicts with retained document {path:?}"
                )));
            }
        }
        self.with_shared_documents(
            self.provider.clone(),
            documents_by_path,
            document_sha256_by_path,
        )
    }

    /// Replace one or more complete persistent-provider execution-root
    /// partitions while retaining every unaffected sibling partition.
    ///
    /// Both snapshots have already crossed the provider protocol and
    /// canonical document boundary. The replacement may update root-local
    /// toolchain/configuration identity, but it cannot change provider
    /// lineage, repository ownership, or execution-root population. The
    /// recomposed snapshot still has to pass ordinary repository-wide
    /// normalization before it can carry capability authority.
    pub(crate) fn replace_execution_root_partitions(
        &self,
        replacement: &Self,
    ) -> Result<Self, CanonicalScipSnapshotError> {
        if self.root != replacement.root || !self.provider.has_same_lineage(&replacement.provider) {
            return Err(CanonicalScipSnapshotError(
                "replacement snapshot belongs to a different provider lineage".into(),
            ));
        }
        if replacement.execution_root_prefixes.is_empty()
            || !replacement
                .execution_root_prefixes
                .is_subset(&self.execution_root_prefixes)
        {
            return Err(CanonicalScipSnapshotError(
                "replacement snapshot execution roots are outside the canonical population".into(),
            ));
        }
        let owner_for_document = |document_path: &str| {
            self.execution_root_prefixes
                .iter()
                .filter(|candidate| {
                    candidate.is_empty()
                        || Path::new(document_path).starts_with(Path::new(candidate.as_str()))
                })
                .max_by(|left, right| {
                    Path::new(left.as_str())
                        .components()
                        .count()
                        .cmp(&Path::new(right.as_str()).components().count())
                        .then_with(|| left.cmp(right))
                })
        };
        let mut replacement_documents = BTreeMap::new();
        for (document_path, document) in replacement.documents_by_path.iter() {
            let owner = owner_for_document(&document.relative_path).ok_or_else(|| {
                CanonicalScipSnapshotError(format!(
                    "replacement document {:?} has no canonical execution-root owner",
                    document.relative_path
                ))
            })?;
            if !replacement.execution_root_prefixes.contains(owner) {
                return Err(CanonicalScipSnapshotError(format!(
                    "replacement document {:?} belongs to retained execution root {owner:?}",
                    document.relative_path
                )));
            }
            if replacement_documents
                .insert(document_path.clone(), Arc::clone(document))
                .is_some()
            {
                return Err(CanonicalScipSnapshotError(format!(
                    "replacement snapshot contains duplicate document {:?}",
                    document.relative_path
                )));
            }
        }

        let mut documents_by_path = self
            .documents_by_path
            .iter()
            .filter(|(document_path, _)| {
                owner_for_document(document_path)
                    .is_none_or(|owner| !replacement.execution_root_prefixes.contains(owner))
            })
            .map(|(document_path, document)| (document_path.clone(), Arc::clone(document)))
            .collect::<BTreeMap<_, _>>();
        let mut document_sha256_by_path = self
            .document_sha256_by_path
            .iter()
            .filter(|(document_path, _)| {
                owner_for_document(document_path)
                    .is_none_or(|owner| !replacement.execution_root_prefixes.contains(owner))
            })
            .map(|(document_path, digest)| (document_path.clone(), digest.clone()))
            .collect::<BTreeMap<_, _>>();
        for (path, document) in replacement_documents {
            let replacement_digest = replacement
                .document_sha256_by_path
                .get(&path)
                .expect("replacement document has canonical identity")
                .clone();
            if documents_by_path.insert(path.clone(), document).is_some()
                || document_sha256_by_path
                    .insert(path.clone(), replacement_digest)
                    .is_some()
            {
                return Err(CanonicalScipSnapshotError(format!(
                    "replacement execution root conflicts with retained document {path:?}"
                )));
            }
        }
        let mut provider = self.provider.clone();
        for prefix in &replacement.execution_root_prefixes {
            let configuration = replacement
                .provider
                .configurations_sha256
                .get(prefix)
                .ok_or_else(|| {
                    CanonicalScipSnapshotError(format!(
                        "replacement execution root {prefix:?} has no provider configuration"
                    ))
                })?;
            provider
                .configurations_sha256
                .insert(prefix.clone(), configuration.clone());
        }
        self.with_shared_documents(provider, documents_by_path, document_sha256_by_path)
    }

    #[cfg(test)]
    pub fn document_bytes(&self, document_path: &str) -> Option<Vec<u8>> {
        self.documents_by_path
            .get(document_path)
            .and_then(|document| document.write_to_bytes().ok())
    }

    fn fingerprint_material(&self) -> Vec<u8> {
        let mut material = CANONICAL_SCIP_SNAPSHOT_SCHEMA.to_vec();
        append_fingerprint_field(&mut material, self.provider.spec.provider_id.as_bytes());
        append_fingerprint_field(&mut material, self.provider.executed_version.as_bytes());
        append_fingerprint_field(
            &mut material,
            self.provider
                .implementation_sha256
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        );
        append_fingerprint_field(
            &mut material,
            &(self.provider.configurations_sha256.len() as u64).to_be_bytes(),
        );
        for (prefix, configuration) in &self.provider.configurations_sha256 {
            append_fingerprint_field(&mut material, prefix.as_bytes());
            append_fingerprint_field(&mut material, configuration.as_bytes());
        }
        append_fingerprint_field(&mut material, self.document_manifest_sha256.as_bytes());
        for prefix in &self.execution_root_prefixes {
            append_fingerprint_field(&mut material, prefix.as_bytes());
        }
        material
    }

    /// Exact provider invocation/configuration identity, deliberately excluding
    /// the provider output document snapshot. The latter is independently
    /// sealed by [`Self::identity_sha256`] and by immutable generation digests.
    fn input_configuration_material(&self) -> Vec<u8> {
        let mut material = CANONICAL_SCIP_INPUT_SCHEMA.to_vec();
        append_fingerprint_field(&mut material, self.provider.spec.provider_id.as_bytes());
        append_fingerprint_field(&mut material, self.provider.executed_version.as_bytes());
        append_fingerprint_field(
            &mut material,
            self.provider
                .implementation_sha256
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        );
        append_fingerprint_field(
            &mut material,
            &(self.provider.configurations_sha256.len() as u64).to_be_bytes(),
        );
        for (prefix, configuration) in &self.provider.configurations_sha256 {
            append_fingerprint_field(&mut material, prefix.as_bytes());
            append_fingerprint_field(&mut material, configuration.as_bytes());
        }
        for prefix in &self.execution_root_prefixes {
            append_fingerprint_field(&mut material, prefix.as_bytes());
        }
        material
    }

    /// Overlay one exactly accounted affected set. Every requested path must
    /// have one response, and no response may escape the requested population.
    pub fn overlay_affected_documents(
        &self,
        affected_documents: &BTreeSet<String>,
        updates: Vec<CanonicalScipDocumentUpdate>,
    ) -> Result<Self, CanonicalScipSnapshotError> {
        if affected_documents.is_empty() {
            return Err(CanonicalScipSnapshotError(
                "affected document population is empty".into(),
            ));
        }
        let mut updates_by_path = BTreeMap::new();
        for update in updates {
            let path = match &update {
                CanonicalScipDocumentUpdate::Present { document_path, .. }
                | CanonicalScipDocumentUpdate::Omitted { document_path } => document_path.clone(),
            };
            validate_repository_document_path(&path)?;
            if updates_by_path.insert(path.clone(), update).is_some() {
                return Err(CanonicalScipSnapshotError(format!(
                    "duplicate affected document outcome: {path}"
                )));
            }
        }
        if updates_by_path.keys().collect::<BTreeSet<_>>()
            != affected_documents.iter().collect::<BTreeSet<_>>()
        {
            return Err(CanonicalScipSnapshotError(
                "affected document outcomes do not exactly match the requested population".into(),
            ));
        }

        let mut documents_by_path = self
            .documents_by_path
            .iter()
            .map(|(document_path, document)| (document_path.clone(), Arc::clone(document)))
            .collect::<BTreeMap<_, _>>();
        let mut document_sha256_by_path = self.document_sha256_by_path.clone();
        for (path, update) in updates_by_path {
            match update {
                CanonicalScipDocumentUpdate::Present {
                    document_path,
                    mut document,
                } => {
                    if document.relative_path != document_path {
                        return Err(CanonicalScipSnapshotError(format!(
                            "affected document path {document_path} differs from its SCIP path {:?}",
                            document.relative_path
                        )));
                    }
                    if document.language != self.provider.spec.language {
                        return Err(CanonicalScipSnapshotError(format!(
                            "affected document {document_path} reports language {:?}, expected {:?}",
                            document.language, self.provider.spec.language
                        )));
                    }
                    canonicalize_scip_document(&mut document)?;
                    let document_sha256 = canonical_document_sha256(&document)?;
                    documents_by_path.insert(path, Arc::new(document));
                    document_sha256_by_path.insert(document_path, document_sha256);
                }
                CanonicalScipDocumentUpdate::Omitted { .. } => {
                    documents_by_path.remove(&path);
                    document_sha256_by_path.remove(&path);
                }
            }
        }
        self.with_shared_documents(
            self.provider.clone(),
            documents_by_path,
            document_sha256_by_path,
        )
    }
}

/// Reconstruct one disposable canonical provider snapshot from bytes whose
/// semantic identity is sealed by an immutable normalized Calls payload.
///
/// Cache metadata and external-symbol populations are deliberately ignored.
/// The canonical index is rebuilt from document bytes plus payload-owned
/// provider/root/configuration evidence, then its complete snapshot identity
/// must match the publication before the result can become a reuse candidate.
pub fn rehydrate_canonical_snapshot(
    root: &Path,
    spec: ScipProviderSpec,
    payload: &CallsProviderPayload,
    provider_configurations_sha256: BTreeMap<String, String>,
    encoded_index: &[u8],
) -> Result<CanonicalScipSnapshot, CanonicalScipSnapshotError> {
    if payload.receipt.status != CapabilityStatus::Complete
        || payload.receipt.provider_id.0 != spec.provider_id
        || payload
            .receipt
            .scope
            .language_id()
            .map(|language| language.0.as_str())
            != Some(spec.language)
    {
        return Err(CanonicalScipSnapshotError(
            "cached snapshot payload does not match complete provider authority".into(),
        ));
    }
    let expected_identity = payload
        .canonical_snapshot_sha256
        .as_deref()
        .ok_or_else(|| {
            CanonicalScipSnapshotError("payload has no canonical snapshot identity".into())
        })?;
    let provider_version = payload
        .receipt
        .provider_version
        .as_deref()
        .filter(|version| !version.trim().is_empty())
        .ok_or_else(|| CanonicalScipSnapshotError("payload has no provider version".into()))?;
    let ProviderExecutionAuthority::ToolchainBound {
        ecosystem_id,
        roots,
        provider_implementation_sha256,
        ..
    } = &payload.execution_authority
    else {
        return Err(CanonicalScipSnapshotError(
            "cached snapshot payload is not toolchain-bound".into(),
        ));
    };
    if ecosystem_id.0 != spec.ecosystem || roots.is_empty() {
        return Err(CanonicalScipSnapshotError(
            "cached snapshot payload has the wrong ecosystem or no execution roots".into(),
        ));
    }

    let canonical_root = fs::canonicalize(root).map_err(|error| {
        CanonicalScipSnapshotError(format!("cannot resolve repository root: {error}"))
    })?;
    let mut execution_root_prefixes = BTreeSet::new();
    for authority in roots {
        let prefix = Path::new(&authority.execution_root);
        let execution_root = canonical_root.join(prefix);
        let canonical_prefix = execution_prefix(&canonical_root, &execution_root)
            .map_err(|error| CanonicalScipSnapshotError(error.to_string()))?
            .to_string_lossy()
            .replace('\\', "/");
        if canonical_prefix != authority.execution_root
            || !execution_root_prefixes.insert(canonical_prefix.clone())
        {
            return Err(CanonicalScipSnapshotError(
                "cached snapshot execution-root population is not canonical and unique".into(),
            ));
        }
    }
    if provider_configurations_sha256
        .keys()
        .collect::<BTreeSet<_>>()
        != execution_root_prefixes.iter().collect::<BTreeSet<_>>()
    {
        return Err(CanonicalScipSnapshotError(
            "cached snapshot configuration population differs from execution authority roots"
                .into(),
        ));
    }

    let cached = Index::parse_from_bytes(encoded_index).map_err(|error| {
        CanonicalScipSnapshotError(format!("cannot decode cached SCIP snapshot: {error}"))
    })?;
    let mut tool = ToolInfo::new();
    tool.name = spec.tool_name.into();
    tool.version = provider_version.into();
    let mut metadata = Metadata::new();
    metadata.tool_info = MessageField::some(tool);
    metadata.project_root = local_file_uri(&canonical_root).ok_or_else(|| {
        CanonicalScipSnapshotError(
            "repository root is not representable as a UTF-8 file URI".into(),
        )
    })?;
    metadata.text_document_encoding = EnumOrUnknown::new(TextEncoding::UTF8);
    let mut index = Index::new();
    index.metadata = MessageField::some(metadata);
    index.documents = cached.documents;

    let snapshot = CanonicalScipSnapshot::from_composed_index(
        canonical_root,
        CanonicalScipProviderCoordinate::new(
            spec,
            provider_version,
            Some(provider_implementation_sha256.clone()),
            provider_configurations_sha256,
        )?,
        payload.receipt.scope.clone(),
        execution_root_prefixes,
        index,
    )?;
    let actual_identity = snapshot.identity_sha256();
    if actual_identity != expected_identity {
        return Err(CanonicalScipSnapshotError(format!(
            "cached SCIP snapshot identity differs from immutable payload: expected {expected_identity}, observed {actual_identity}"
        )));
    }
    Ok(snapshot)
}

/// Build one repository-wide canonical baseline from every independently
/// admitted persistent-provider execution root.
///
/// Provider documents already use repository-relative paths. Execution roots
/// are therefore lineage and scope evidence only; composing them here avoids
/// falsely promoting one successful workspace to repository-wide authority.
#[cfg(test)]
pub fn canonical_scip_snapshot_from_provider_document_sets(
    root: &Path,
    spec: ScipProviderSpec,
    executed_provider_version: &str,
    provider_configurations_by_execution_root: &BTreeMap<PathBuf, String>,
    documents: Vec<Document>,
    inventory: &ProjectInventory,
) -> Result<CanonicalScipSnapshot, CanonicalScipSnapshotError> {
    canonical_scip_snapshot_from_provider_document_sets_with_identity(
        root,
        spec,
        executed_provider_version,
        None,
        provider_configurations_by_execution_root,
        documents,
        inventory,
    )
}

pub fn canonical_scip_snapshot_from_provider_document_sets_with_identity(
    root: &Path,
    spec: ScipProviderSpec,
    executed_provider_version: &str,
    provider_implementation_sha256: Option<&str>,
    provider_configurations_by_execution_root: &BTreeMap<PathBuf, String>,
    documents: Vec<Document>,
    inventory: &ProjectInventory,
) -> Result<CanonicalScipSnapshot, CanonicalScipSnapshotError> {
    let executed_provider_version = executed_provider_version.trim();
    if executed_provider_version.is_empty() {
        return Err(CanonicalScipSnapshotError(
            "provider version is empty".into(),
        ));
    }
    if provider_configurations_by_execution_root.is_empty() {
        return Err(CanonicalScipSnapshotError(
            "provider execution-root population is empty".into(),
        ));
    }
    let root = fs::canonicalize(root).map_err(|error| {
        CanonicalScipSnapshotError(format!("cannot resolve repository root: {error}"))
    })?;
    let mut successful_roots = BTreeSet::new();
    let mut provider_configurations_sha256 = BTreeMap::new();
    for (execution_root, configuration_sha256) in provider_configurations_by_execution_root {
        let prefix = execution_prefix(&root, execution_root)
            .map_err(|error| CanonicalScipSnapshotError(error.to_string()))?;
        let prefix_text = prefix.to_string_lossy().replace('\\', "/");
        if !successful_roots.insert(prefix)
            || provider_configurations_sha256
                .insert(prefix_text, configuration_sha256.clone())
                .is_some()
        {
            return Err(CanonicalScipSnapshotError(
                "provider execution-root population contains canonical duplicates".into(),
            ));
        }
    }
    let scope = provider_scope_for_execution_roots(spec, &successful_roots, inventory);
    let execution_root_prefixes = provider_configurations_sha256
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut tool = ToolInfo::new();
    tool.name = spec.tool_name.into();
    tool.version = executed_provider_version.into();
    let mut metadata = Metadata::new();
    metadata.tool_info = MessageField::some(tool);
    metadata.project_root = local_file_uri(&root).ok_or_else(|| {
        CanonicalScipSnapshotError(
            "repository root is not representable as a UTF-8 file URI".into(),
        )
    })?;
    metadata.text_document_encoding = EnumOrUnknown::new(TextEncoding::UTF8);
    let mut index = Index::new();
    index.metadata = MessageField::some(metadata);
    index.documents = documents;

    CanonicalScipSnapshot::from_composed_index(
        root,
        CanonicalScipProviderCoordinate::new(
            spec,
            executed_provider_version,
            provider_implementation_sha256.map(str::to_owned),
            provider_configurations_sha256,
        )?,
        scope,
        execution_root_prefixes,
        index,
    )
}

fn validate_provider_configuration_population(
    execution_root_prefixes: &BTreeSet<String>,
    provider_configurations_sha256: &BTreeMap<String, String>,
) -> Result<(), CanonicalScipSnapshotError> {
    if provider_configurations_sha256.is_empty() {
        return Ok(());
    }
    if provider_configurations_sha256
        .keys()
        .collect::<BTreeSet<_>>()
        != execution_root_prefixes.iter().collect::<BTreeSet<_>>()
    {
        return Err(CanonicalScipSnapshotError(
            "provider configuration population differs from execution-root population".into(),
        ));
    }
    if provider_configurations_sha256
        .values()
        .any(|configuration| {
            configuration.len() != 64
                || !configuration
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(CanonicalScipSnapshotError(
            "provider configuration identity is not lowercase SHA-256".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IncompleteKind {
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizationFailure {
    kind: IncompleteKind,
    code: &'static str,
    detail: String,
}

impl NormalizationFailure {
    fn partial(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind: IncompleteKind::Partial,
            code,
            detail: detail.into(),
        }
    }

    fn unavailable(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            kind: IncompleteKind::Unavailable,
            code,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DefinitionRecord {
    provider_symbol_id: String,
    name: String,
    kind: String,
    provider_kind: symbol_information::Kind,
    document_path: String,
    definition: ProviderLocation,
    /// Source-backed extent used to expose this symbol as a callable identity.
    /// A package-level function value may have an identity extent without
    /// owning initializer calls inside that extent.
    enclosing_span: Option<NormalizedSourceSpan>,
    /// Exact structural extent for an invocation target that does not own a
    /// callable body, such as a Python class object.
    invocation_target_span: Option<NormalizedSourceSpan>,
    /// Exact syntax body that may authoritatively own call sites.
    call_owner_span: Option<NormalizedSourceSpan>,
    value_binding_span: Option<NormalizedSourceSpan>,
    binding_scope: (u64, u64),
    callable: bool,
    rust_declared_owner: Option<RustProviderOwner>,
}

impl DefinitionRecord {
    const fn source_invocation_target(&self) -> bool {
        self.enclosing_span.is_some() || self.invocation_target_span.is_some()
    }

    fn structural_span(&self) -> Option<&NormalizedSourceSpan> {
        self.enclosing_span
            .as_ref()
            .or(self.invocation_target_span.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceCallCallee {
    name: String,
    form: NamedCallForm,
    receiver_identity_range: Option<(usize, usize)>,
    /// The source grammar proves that this is a bound-receiver call to a
    /// method declared directly on the same source owner. This is deliberately
    /// narrower than a terminal-name collision: dynamic/external selectors do
    /// not become repository-local merely because another class has the same
    /// method name.
    source_local_method_target: bool,
}

type SourceCallCallees = BTreeMap<(usize, usize), SourceCallCallee>;
type SourceCallableNames = BTreeSet<String>;
type SourceBindingScopes = BTreeMap<(usize, usize), (u64, u64)>;
type SourceCallableExtents = BTreeMap<(usize, usize), (usize, usize)>;
type SourceInvocationTargetExtents = BTreeMap<(usize, usize), (usize, usize)>;
type SourceValueBindingExtents = BTreeMap<(usize, usize), (usize, usize)>;
type SourceCallableBindingTargets = BTreeMap<(usize, usize), (usize, usize)>;
type SourceDirectClosureBindings = BTreeSet<(usize, usize)>;
type SourceCallOwnerExtents = BTreeSet<(usize, usize)>;
type SourceDeclaredTypeNames = BTreeMap<(usize, usize), (usize, usize)>;
type SourceParameterBindings = BTreeMap<String, Vec<SourceParameterBinding>>;
type SourceConditionalRanges = BTreeSet<(u64, u64)>;
type SourceGeneratedRanges = BTreeSet<(u64, u64)>;
type CanonicalDefinitionGroups = (
    BTreeMap<String, DefinitionRecord>,
    BTreeMap<String, Vec<String>>,
);
type SharedCanonicalDefinitions = BTreeMap<Arc<str>, Arc<DefinitionRecord>>;
type SharedDefinitionAliases = BTreeMap<Arc<str>, Arc<[Arc<str>]>>;
type SharedDefinitionRecordsByBaseId = BTreeMap<Arc<str>, Arc<[Arc<DefinitionRecord>]>>;

#[derive(Debug)]
struct SourceRangeGroup {
    start: u64,
    ends: Vec<u64>,
}

/// Immutable containment index for syntax-tree ranges.
///
/// Tree-sitter node extents are laminar (nested or disjoint), which permits a
/// rightmost-start/max-end lookup in logarithmic time. The original linear
/// selection remains as an exact fallback if an upstream parser ever violates
/// that invariant, so the index changes cost rather than semantics.
#[derive(Debug)]
struct SourceRangeIndex {
    ranges: BTreeSet<(u64, u64)>,
    groups: Vec<SourceRangeGroup>,
    segment_base: usize,
    max_end_tree: Vec<u64>,
    laminar: bool,
}

impl SourceRangeIndex {
    fn new(ranges: BTreeSet<(u64, u64)>) -> Self {
        let laminar = source_ranges_are_laminar(&ranges);
        let mut by_start = BTreeMap::<u64, Vec<u64>>::new();
        for &(start, end) in &ranges {
            if start <= end {
                by_start.entry(start).or_default().push(end);
            }
        }
        let groups = by_start
            .into_iter()
            .map(|(start, mut ends)| {
                ends.sort_unstable();
                ends.dedup();
                SourceRangeGroup { start, ends }
            })
            .collect::<Vec<_>>();
        let segment_base = groups.len().max(1).next_power_of_two();
        let mut max_end_tree = vec![0; segment_base * 2];
        for (index, group) in groups.iter().enumerate() {
            max_end_tree[segment_base + index] = group.ends.last().copied().unwrap_or_default();
        }
        for node in (1..segment_base).rev() {
            max_end_tree[node] = max_end_tree[node * 2].max(max_end_tree[node * 2 + 1]);
        }
        Self {
            ranges,
            groups,
            segment_base,
            max_end_tree,
            laminar,
        }
    }

    fn from_usize(ranges: BTreeSet<(usize, usize)>) -> Self {
        Self::new(
            ranges
                .into_iter()
                .map(|(start, end)| (start as u64, end as u64))
                .collect(),
        )
    }

    fn tightest_containing(&self, start_byte: u64, end_byte: u64) -> Option<(u64, u64)> {
        if !self.laminar {
            return self
                .ranges
                .iter()
                .copied()
                .filter(|(start, end)| {
                    #[cfg(test)]
                    SOURCE_RANGE_PROBE_COUNT.with(|count| count.set(count.get() + 1));
                    *start <= start_byte && end_byte <= *end
                })
                .min_by_key(|(start, end)| end.saturating_sub(*start));
        }

        let upper = self.groups.partition_point(|group| {
            #[cfg(test)]
            SOURCE_RANGE_PROBE_COUNT.with(|count| count.set(count.get() + 1));
            group.start <= start_byte
        });
        let group_index =
            self.find_rightmost_containing(1, 0, self.segment_base, upper, end_byte)?;
        let group = self.groups.get(group_index)?;
        let candidate_index = group.ends.partition_point(|end| {
            #[cfg(test)]
            SOURCE_RANGE_PROBE_COUNT.with(|count| count.set(count.get() + 1));
            *end < end_byte
        });
        group
            .ends
            .get(candidate_index)
            .copied()
            .map(|end| (group.start, end))
    }

    fn find_rightmost_containing(
        &self,
        tree_node: usize,
        start: usize,
        end: usize,
        upper: usize,
        required_end: u64,
    ) -> Option<usize> {
        #[cfg(test)]
        SOURCE_RANGE_PROBE_COUNT.with(|count| count.set(count.get() + 1));
        if start >= upper || self.max_end_tree.get(tree_node).copied()? < required_end {
            return None;
        }
        if end - start == 1 {
            return (start < self.groups.len()).then_some(start);
        }
        let middle = start + (end - start) / 2;
        self.find_rightmost_containing(tree_node * 2 + 1, middle, end, upper, required_end)
            .or_else(|| {
                self.find_rightmost_containing(tree_node * 2, start, middle, upper, required_end)
            })
    }
}

impl std::ops::Deref for SourceRangeIndex {
    type Target = BTreeSet<(u64, u64)>;

    fn deref(&self) -> &Self::Target {
        &self.ranges
    }
}

fn source_ranges_are_laminar(ranges: &BTreeSet<(u64, u64)>) -> bool {
    let mut ordered = ranges.iter().copied().collect::<Vec<_>>();
    ordered.sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| right.1.cmp(&left.1)));
    let mut active_ends = Vec::<u64>::new();
    for (start, end) in ordered {
        while active_ends
            .last()
            .is_some_and(|active_end| *active_end <= start)
        {
            active_ends.pop();
        }
        if active_ends
            .last()
            .is_some_and(|active_end| end > *active_end)
        {
            return false;
        }
        active_ends.push(end);
    }
    true
}

/// Per-document exact owner lookup for canonical provider call records.
///
/// Callable body extents come from the syntax census and are therefore
/// laminar. Resolve the tightest containing extent through the same indexed
/// containment primitive used by the rest of the census, then inspect only the
/// definitions attached to that exact extent. If an upstream parser ever
/// supplies crossing extents, preserve the old exhaustive fail-closed
/// semantics instead of guessing.
#[derive(Debug)]
struct DefinitionCallOwnerIndex {
    ranges: SourceRangeIndex,
    provider_ids_by_range: BTreeMap<(u64, u64), Vec<String>>,
}

impl DefinitionCallOwnerIndex {
    fn new<'a>(definitions: impl IntoIterator<Item = &'a DefinitionRecord>) -> Self {
        let mut provider_ids_by_range = BTreeMap::<(u64, u64), Vec<String>>::new();
        for definition in definitions {
            if !definition.callable {
                continue;
            }
            let Some(span) = definition.call_owner_span.as_ref() else {
                continue;
            };
            provider_ids_by_range
                .entry((span.start_byte, span.end_byte))
                .or_default()
                .push(definition.provider_symbol_id.clone());
        }
        for provider_ids in provider_ids_by_range.values_mut() {
            provider_ids.sort();
            provider_ids.dedup();
        }
        let ranges = SourceRangeIndex::new(provider_ids_by_range.keys().copied().collect());
        Self {
            ranges,
            provider_ids_by_range,
        }
    }

    fn resolve<'a>(
        &self,
        definitions: &'a SharedCanonicalDefinitions,
        call_span: &NormalizedSourceSpan,
    ) -> Result<Option<&'a DefinitionRecord>, ()> {
        if !self.ranges.laminar {
            return enclosing_callable_linear(
                self.provider_ids_by_range
                    .values()
                    .flatten()
                    .filter_map(|provider_id| definitions.get(provider_id.as_str()))
                    .map(Arc::as_ref),
                call_span,
            );
        }

        let Some(owner_range) = self
            .ranges
            .tightest_containing(call_span.start_byte, call_span.end_byte)
        else {
            return Ok(None);
        };
        let Some(provider_ids) = self.provider_ids_by_range.get(&owner_range) else {
            return Ok(None);
        };
        let mut owner = None;
        for provider_id in provider_ids {
            #[cfg(test)]
            CALL_OWNER_CANDIDATE_PROBE_COUNT.with(|count| count.set(count.get() + 1));
            let Some(definition) = definitions.get(provider_id.as_str()).map(Arc::as_ref) else {
                continue;
            };
            match owner {
                None => owner = Some(definition),
                Some(existing) if existing.provider_symbol_id != definition.provider_symbol_id => {
                    return Err(());
                }
                Some(_) => {}
            }
        }
        Ok(owner)
    }

    fn resolve_published<'a>(
        &self,
        definitions: &'a SharedCanonicalDefinitions,
        call_span: &NormalizedSourceSpan,
    ) -> Result<Option<&'a DefinitionRecord>, ()> {
        enclosing_callable_linear(
            self.provider_ids_by_range
                .values()
                .flatten()
                .filter_map(|provider_id| definitions.get(provider_id.as_str()))
                .map(Arc::as_ref)
                .filter(|definition| definition.structural_span().is_some()),
            call_span,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceParameterBinding {
    definition_range: (usize, usize),
    scope: (u64, u64),
}

#[derive(Debug)]
struct SourceSyntaxEvidence {
    call_callees: SourceCallCallees,
    local_callable_names: SourceCallableNames,
    local_invocation_target_names: SourceCallableNames,
    go_package_name: Option<String>,
    go_package_function_names: SourceCallableNames,
    binding_scopes: SourceBindingScopes,
    callable_extents: SourceCallableExtents,
    non_structural_callable_definitions: BTreeSet<(usize, usize)>,
    invocation_target_extents: SourceInvocationTargetExtents,
    value_binding_extents: SourceValueBindingExtents,
    callable_binding_targets: SourceCallableBindingTargets,
    direct_closure_bindings: SourceDirectClosureBindings,
    call_owner_extents: SourceRangeIndex,
    anonymous_callable_extents: SourceRangeIndex,
    declared_type_names: SourceDeclaredTypeNames,
    parameter_bindings: SourceParameterBindings,
    conditional_ranges: SourceRangeIndex,
    generated_ranges: SourceRangeIndex,
}

#[derive(Debug, Default)]
struct SourceDefinitionContexts {
    local_callable_names: SourceCallableNames,
    local_invocation_target_names: SourceCallableNames,
    go_package_function_names: SourceCallableNames,
    binding_scopes: SourceBindingScopes,
    callable_extents: SourceCallableExtents,
    non_structural_callable_definitions: BTreeSet<(usize, usize)>,
    invocation_target_extents: SourceInvocationTargetExtents,
    value_binding_extents: SourceValueBindingExtents,
    direct_closure_bindings: SourceDirectClosureBindings,
    call_owner_extents: SourceCallOwnerExtents,
    anonymous_callable_extents: SourceCallOwnerExtents,
    declared_type_names: SourceDeclaredTypeNames,
}

struct SourceSyntaxCensus<'source> {
    source: &'source str,
    language: &'source str,
    extractor: &'static dyn crate::language::LanguageExtractor,
    call_callees: SourceCallCallees,
    definition_contexts: SourceDefinitionContexts,
    callable_binding_targets: SourceCallableBindingTargets,
    parameter_bindings: SourceParameterBindings,
    conditional_ranges: SourceConditionalRanges,
    generated_ranges: SourceGeneratedRanges,
}

impl<'source> SourceSyntaxCensus<'source> {
    fn new(
        source: &'source str,
        language: &'source str,
        extractor: &'static dyn crate::language::LanguageExtractor,
    ) -> Self {
        Self {
            source,
            language,
            extractor,
            call_callees: BTreeMap::new(),
            definition_contexts: SourceDefinitionContexts::default(),
            callable_binding_targets: BTreeMap::new(),
            parameter_bindings: BTreeMap::new(),
            conditional_ranges: BTreeSet::new(),
            generated_ranges: BTreeSet::new(),
        }
    }

    fn visit(&mut self, node: Node<'_>, root: Node<'_>) {
        collect_call_callee_at_node(node, self.source, self.extractor, &mut self.call_callees);
        collect_definition_context_at_node(
            node,
            root,
            self.source,
            self.language,
            self.extractor,
            &mut self.definition_contexts,
        );
        collect_go_callable_binding_targets_at_node(
            node,
            self.language,
            &mut self.callable_binding_targets,
        );
        collect_parameter_bindings_at_node(
            node,
            root,
            self.source,
            self.language,
            &mut self.parameter_bindings,
        );
        collect_conditional_range_at_node(
            node,
            self.source,
            self.language,
            &mut self.conditional_ranges,
        );
        collect_generated_range_at_node(node, self.language, &mut self.generated_ranges);

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            self.visit(child, root);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RustProviderOwner {
    scheme: String,
    package_manager: String,
    package_name: String,
    package_version: String,
    descriptors: Vec<(String, i32)>,
}

type ProviderSymbolsByRange = BTreeMap<String, Arc<BTreeMap<(usize, usize), BTreeSet<String>>>>;
type ProviderReferenceSymbolsByRange = BTreeMap<String, Arc<BTreeMap<(usize, usize), Vec<String>>>>;
type RustMethodWitnesses = BTreeMap<(RustProviderOwner, String), BTreeSet<String>>;

#[derive(Debug, Clone)]
struct NormalizedProviderOccurrence {
    symbol: String,
    symbol_roles: i32,
    provider_symbol_id: String,
    span: NormalizedSourceSpan,
    range: (usize, usize),
}

/// Exact document-local provider work retained only as process-local
/// acceleration. Reuse requires both the canonical provider-document digest
/// and the independently validated live source digest to match.
#[derive(Clone)]
struct CachedProviderNormalizationDocument {
    source_content_sha256: String,
    provider_document_sha256: Option<String>,
    occurrences: Arc<[NormalizedProviderOccurrence]>,
    symbols_by_range: Arc<BTreeMap<(usize, usize), BTreeSet<String>>>,
    reference_symbols_by_range: Arc<BTreeMap<(usize, usize), Vec<String>>>,
    invoked_symbol_ids: Arc<BTreeSet<String>>,
    definition_records: Option<Arc<[DefinitionRecord]>>,
    rust_method_witnesses: Option<Arc<RustMethodWitnesses>>,
}

#[cfg(test)]
impl CachedProviderNormalizationDocument {
    fn shares_immutable_acceleration_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.occurrences, &other.occurrences)
            && Arc::ptr_eq(&self.symbols_by_range, &other.symbols_by_range)
            && Arc::ptr_eq(
                &self.reference_symbols_by_range,
                &other.reference_symbols_by_range,
            )
            && Arc::ptr_eq(&self.invoked_symbol_ids, &other.invoked_symbol_ids)
    }
}

#[derive(Clone)]
struct CachedCanonicalDefinitionGroups {
    definitions: Arc<SharedCanonicalDefinitions>,
    aliases: Arc<SharedDefinitionAliases>,
    /// Exact pre-canonical records grouped by their provider base identity.
    /// Incremental normalization uses this inverse index to rebuild only
    /// groups touched by changed documents without walking every unchanged
    /// provider document. Values retain every duplicate record because
    /// canonicalization may deliberately collapse non-invocation definitions.
    records_by_base_id: Arc<SharedDefinitionRecordsByBaseId>,
}

fn has_provider_definition_occurrence(
    occurrences: &[NormalizedProviderOccurrence],
    provider_symbol_id: &str,
) -> bool {
    occurrences.iter().any(|occurrence| {
        occurrence.symbol_roles & SymbolRole::Definition.value() != 0
            && occurrence.provider_symbol_id == provider_symbol_id
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MethodOmission {
    CoveredOutsideSourcePopulation,
    MissingSourceCall,
    Unresolved,
}

struct MethodOmissionEvidence<'a> {
    document_path: &'a str,
    call_range: (usize, usize),
    provider_symbols_by_range: &'a ProviderSymbolsByRange,
    definitions: &'a SharedCanonicalDefinitions,
    definition_aliases: &'a SharedDefinitionAliases,
    rust_method_witnesses: &'a RustMethodWitnesses,
}

impl SourceSyntaxEvidence {
    fn enclosing_conditional_range(&self, start_byte: u64, end_byte: u64) -> Option<(u64, u64)> {
        smallest_containing_range(&self.conditional_ranges, start_byte, end_byte)
    }

    fn enclosing_generated_range(&self, start_byte: u64, end_byte: u64) -> Option<(u64, u64)> {
        smallest_containing_range(&self.generated_ranges, start_byte, end_byte)
    }

    fn range_has_callable_owner(&self, start_byte: u64, end_byte: u64) -> bool {
        self.call_owner_extents
            .tightest_containing(start_byte, end_byte)
            .is_some()
    }

    fn exact_call_owner_extent(&self, start_byte: u64, end_byte: u64) -> bool {
        self.call_owner_extents
            .ranges
            .contains(&(start_byte, end_byte))
    }

    fn execution_root_context(
        &self,
        start_byte: u64,
        end_byte: u64,
    ) -> crate::code_intel_domain::ExecutionRootContext {
        if self
            .anonymous_callable_extents
            .tightest_containing(start_byte, end_byte)
            .is_some()
        {
            crate::code_intel_domain::ExecutionRootContext::AnonymousCallable
        } else {
            crate::code_intel_domain::ExecutionRootContext::ModuleInitialization
        }
    }
}

fn smallest_containing_range(
    ranges: &SourceRangeIndex,
    start_byte: u64,
    end_byte: u64,
) -> Option<(u64, u64)> {
    ranges.tightest_containing(start_byte, end_byte)
}

#[derive(Debug)]
struct SourceDocument {
    /// Repository source validated as UTF-8 exactly once at document admission.
    text: String,
    line_ranges: Arc<[(usize, usize)]>,
    descriptor: ProviderDocument,
    syntax: Arc<SourceSyntaxEvidence>,
}

fn is_go_test_document(document_path: &str) -> bool {
    document_path.ends_with("_test.go")
}

fn go_package_scope(document_path: &str, source: &SourceDocument) -> Option<(String, String)> {
    let package = source.syntax.go_package_name.as_ref()?;
    let directory = Path::new(document_path)
        .parent()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    Some((directory, package.clone()))
}

#[derive(Clone, Copy)]
struct ArtifactNormalizationContext<'a> {
    root: &'a Path,
    execution_root: &'a Path,
    artifact_path: Option<&'a Path>,
    artifact_index: Option<&'a Index>,
    canonical_snapshot: Option<&'a CanonicalScipSnapshot>,
    spec: ScipProviderSpec,
    executed_provider_version: Option<&'a str>,
    input_configuration_material: Option<&'a [u8]>,
    provider_configurations_sha256: Option<&'a BTreeMap<String, String>>,
    provider_documents_sha256: Option<&'a BTreeMap<String, String>>,
    inventory: &'a ProjectInventory,
}

#[derive(Clone, Copy)]
struct AffectedCallsReuse<'a> {
    affected_documents: &'a BTreeSet<String>,
    prior_payload: &'a CallsProviderPayload,
}

impl ArtifactNormalizationContext<'_> {
    #[cfg(test)]
    fn normalize_with_source_syntax_cache(
        self,
        scope: CapabilityScope,
        indexed_sources: &[IndexedSourceEvidence],
        prior_source_syntax_cache: Option<&CanonicalSourceSyntaxCache>,
    ) -> (
        ScipArtifactEvidence,
        Option<CanonicalSourceSyntaxCache>,
        ScipNormalizationTimings,
    ) {
        self.normalize_with_acceleration(scope, indexed_sources, prior_source_syntax_cache, None)
    }

    fn normalize_with_acceleration(
        mut self,
        scope: CapabilityScope,
        indexed_sources: &[IndexedSourceEvidence],
        prior_source_syntax_cache: Option<&CanonicalSourceSyntaxCache>,
        affected_calls_reuse: Option<AffectedCallsReuse<'_>>,
    ) -> (
        ScipArtifactEvidence,
        Option<CanonicalSourceSyntaxCache>,
        ScipNormalizationTimings,
    ) {
        self.executed_provider_version = self
            .executed_provider_version
            .map(str::trim)
            .filter(|version| !version.is_empty());
        match normalize_complete(
            self,
            &scope,
            indexed_sources,
            prior_source_syntax_cache,
            affected_calls_reuse,
        ) {
            Ok((payload, source_syntax_cache, timings)) => {
                let receipt = payload.payload().receipt().clone();
                (
                    ScipArtifactEvidence {
                        language_id: LanguageId::new(self.spec.language),
                        receipt,
                        payload: Some(payload),
                    },
                    Some(source_syntax_cache),
                    timings,
                )
            }
            Err(failure) => {
                let receipt = match failure.kind {
                    IncompleteKind::Partial => CapabilityReceipt::partial(
                        "calls",
                        self.spec.provider_id,
                        self.executed_provider_version.map(str::to_owned),
                        scope.clone(),
                        None,
                        failure.code,
                        failure.detail,
                    ),
                    IncompleteKind::Unavailable => CapabilityReceipt::unavailable(
                        "calls",
                        self.spec.provider_id,
                        self.executed_provider_version.map(str::to_owned),
                        scope.clone(),
                        None,
                        failure.code,
                        failure.detail,
                    ),
                };
                (
                    ScipArtifactEvidence {
                        language_id: LanguageId::new(self.spec.language),
                        receipt,
                        payload: None,
                    },
                    None,
                    ScipNormalizationTimings::default(),
                )
            }
        }
    }
}

/// Normalize an artifact without leaking failure into a false complete receipt.
/// Every failure returns a typed non-complete receipt and no payload.
#[cfg(test)]
pub fn normalize_scip_artifact(
    root: &Path,
    artifact_path: &Path,
    spec: ScipProviderSpec,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
) -> ScipArtifactEvidence {
    ArtifactNormalizationContext {
        root,
        execution_root: root,
        artifact_path: Some(artifact_path),
        artifact_index: None,
        canonical_snapshot: None,
        spec,
        executed_provider_version: None,
        input_configuration_material: None,
        provider_configurations_sha256: None,
        provider_documents_sha256: None,
        inventory,
    }
    .normalize_with_source_syntax_cache(spec.scope(), indexed_sources, None)
    .0
}

/// Compose every invocation from one semantic provider into a single
/// repository-scoped normalization pass. This is necessary for calls whose
/// reference appears in one execution root and whose definition appears in
/// another: per-artifact normalization would discard that relationship before
/// payloads could be combined. Composition remains in memory: serializing a
/// temporary aggregate only to read and decode it again adds no authority.
pub fn normalize_scip_artifact_set_for_inventory_coverage(
    root: &Path,
    spec: ScipProviderSpec,
    artifacts: &[ScipArtifactInput],
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
) -> ScipArtifactSetNormalization {
    let scope = spec.scope();
    let Some(first) = artifacts.first() else {
        return unavailable_artifact_set(
            spec,
            None,
            scope,
            "provider_failed_or_unavailable",
            "the requested semantic provider produced no artifacts",
        );
    };
    let executed_version = first.executed_provider_version.trim();
    if executed_version.is_empty()
        || artifacts
            .iter()
            .any(|artifact| artifact.executed_provider_version.trim() != executed_version)
    {
        return unavailable_artifact_set(
            spec,
            None,
            scope,
            "provider_identity_mismatch",
            "provider invocations did not share one non-empty executable version",
        );
    }

    let canonical_root = match fs::canonicalize(root) {
        Ok(root) => root,
        Err(error) => {
            return unavailable_artifact_set(
                spec,
                Some(executed_version),
                scope,
                "repository_root_unreadable",
                format!("cannot resolve repository root: {error}"),
            );
        }
    };
    let mut prepared = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let prefix = match execution_prefix(&canonical_root, &artifact.execution_root) {
            Ok(prefix) => prefix,
            Err(error) => {
                return unavailable_artifact_set(
                    spec,
                    Some(executed_version),
                    scope,
                    "provider_root_mismatch",
                    error.to_string(),
                );
            }
        };
        let bytes = match fs::read(&artifact.artifact_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                return unavailable_artifact_set(
                    spec,
                    Some(executed_version),
                    scope,
                    "provider_artifact_unreadable",
                    format!("cannot read SCIP artifact: {error}"),
                );
            }
        };
        let index = match Index::parse_from_bytes(&bytes) {
            Ok(index) => index,
            Err(error) => {
                return unavailable_artifact_set(
                    spec,
                    Some(executed_version),
                    scope,
                    "provider_artifact_invalid",
                    format!("cannot decode SCIP artifact: {error}"),
                );
            }
        };
        let Some(metadata) = index.metadata.as_ref() else {
            return unavailable_artifact_set(
                spec,
                Some(executed_version),
                scope,
                "provider_metadata_missing",
                "SCIP artifact has no metadata",
            );
        };
        let Some(tool) = metadata.tool_info.as_ref() else {
            return unavailable_artifact_set(
                spec,
                Some(executed_version),
                scope,
                "provider_identity_missing",
                "SCIP metadata has no tool identity",
            );
        };
        if tool.name != spec.tool_name || tool.version.trim() != executed_version {
            return unavailable_artifact_set(
                spec,
                Some(executed_version),
                scope,
                "provider_identity_mismatch",
                format!(
                    "expected {} tool version {:?}, found name {:?} version {:?}",
                    spec.tool_name, executed_version, tool.name, tool.version
                ),
            );
        }
        if metadata.text_document_encoding.enum_value() != Ok(TextEncoding::UTF8) {
            return unavailable_artifact_set(
                spec,
                Some(executed_version),
                scope,
                "unsupported_source_encoding",
                "every composed SCIP artifact must use UTF-8 source positions",
            );
        }
        let artifact_root = match file_uri_path(&metadata.project_root).and_then(|path| {
            fs::canonicalize(path).map_err(|error| {
                NormalizationFailure::unavailable(
                    "provider_root_unreadable",
                    format!("cannot resolve SCIP project root: {error}"),
                )
            })
        }) {
            Ok(root) => root,
            Err(failure) => {
                return unavailable_artifact_set(
                    spec,
                    Some(executed_version),
                    scope,
                    failure.code,
                    failure.detail,
                );
            }
        };
        let expected_root = match fs::canonicalize(&artifact.execution_root) {
            Ok(root) => root,
            Err(error) => {
                return unavailable_artifact_set(
                    spec,
                    Some(executed_version),
                    scope,
                    "provider_root_unreadable",
                    format!("cannot resolve SCIP execution root: {error}"),
                );
            }
        };
        if artifact_root != expected_root {
            return unavailable_artifact_set(
                spec,
                Some(executed_version),
                scope,
                "provider_root_mismatch",
                "SCIP project root differs from the admitted provider execution root",
            );
        }
        if artifact.provider_configuration_sha256.len() != 64
            || !artifact
                .provider_configuration_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return unavailable_artifact_set(
                spec,
                Some(executed_version),
                scope,
                "provider_configuration_invalid",
                "provider execution did not carry a lowercase SHA-256 configuration identity",
            );
        }
        prepared.push((
            prefix,
            artifact.provider_configuration_sha256.clone(),
            bytes,
            index,
        ));
    }
    prepared.sort_by(|left, right| left.0.cmp(&right.0));
    if prepared.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return unavailable_artifact_set(
            spec,
            Some(executed_version),
            scope,
            "provider_artifact_ambiguous",
            "multiple provider artifacts claimed the same execution root",
        );
    }

    let successful_roots = prepared
        .iter()
        .map(|(prefix, _, _, _)| prefix.clone())
        .collect::<BTreeSet<_>>();
    let scope = provider_scope_for_execution_roots(spec, &successful_roots, inventory);
    let scoped_sources = indexed_sources_for_scope(spec, &scope, indexed_sources, inventory);

    // Compose only fields this boundary has independently validated and uses.
    // Cloning artifact zero would silently privilege unrelated protobuf fields
    // (for example `external_symbols`) from whichever execution root sorted
    // first.
    let execution_root_prefixes = prepared
        .iter()
        .map(|(prefix, _, _, _)| prefix.to_string_lossy().replace('\\', "/"))
        .collect::<BTreeSet<_>>();
    let provider_configurations_sha256 = prepared
        .iter()
        .map(|(prefix, configuration, _, _)| {
            (
                prefix.to_string_lossy().replace('\\', "/"),
                configuration.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut combined = Index::new();
    combined.metadata = prepared[0].3.metadata.clone();
    for (prefix, _, _, index) in &prepared {
        let prefix = prefix.to_string_lossy().replace('\\', "/");
        for document in &index.documents {
            let mut document = document.clone();
            let Ok(repository_path) =
                repository_document_path(Path::new(&prefix), &document.relative_path)
            else {
                // The indexed structural population is the repository authority.
                // Providers may additionally emit dependency, sysroot, or build-cache
                // documents whose paths traverse out of their execution root (real
                // scip-go does this for GOCACHE export data). Such a document cannot
                // satisfy an admitted repository path, so exclude it before composing
                // artifacts. The later exact population check still fails closed if an
                // admitted source is absent or represented only by an unsafe path.
                continue;
            };
            document.relative_path = repository_path;
            combined.documents.push(document);
        }
    }
    let Some(metadata) = combined.metadata.as_mut() else {
        unreachable!("every prepared artifact has metadata");
    };
    let Some(root_uri) = local_file_uri(&canonical_root) else {
        return unavailable_artifact_set(
            spec,
            Some(executed_version),
            scope,
            "provider_root_uri_invalid",
            "repository root is not representable as a UTF-8 file URI",
        );
    };
    metadata.project_root = root_uri;
    let snapshot = match CanonicalScipProviderCoordinate::new(
        spec,
        executed_version,
        None,
        provider_configurations_sha256,
    )
    .and_then(|provider| {
        CanonicalScipSnapshot::from_composed_index(
            canonical_root,
            provider,
            scope,
            execution_root_prefixes,
            combined,
        )
    }) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return unavailable_artifact_set(
                spec,
                Some(executed_version),
                spec.scope(),
                "canonical_snapshot_invalid",
                error.to_string(),
            );
        }
    };
    normalize_canonical_snapshot_with_sources(snapshot, &scoped_sources, inventory, None, None)
}

/// Normalize an overlaid canonical snapshot through the exact same global
/// resolution and coverage machinery used by full provider certification.
pub fn normalize_canonical_scip_snapshot_for_inventory_coverage(
    root: &Path,
    snapshot: CanonicalScipSnapshot,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
) -> ScipArtifactSetNormalization {
    normalize_canonical_scip_snapshot_with_source_syntax_cache(
        root,
        snapshot,
        indexed_sources,
        inventory,
        None,
    )
}

pub fn normalize_canonical_scip_snapshot_with_source_syntax_cache(
    root: &Path,
    snapshot: CanonicalScipSnapshot,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
    prior_source_syntax_cache: Option<&CanonicalSourceSyntaxCache>,
) -> ScipArtifactSetNormalization {
    normalize_canonical_scip_snapshot_with_acceleration(
        root,
        snapshot,
        indexed_sources,
        inventory,
        prior_source_syntax_cache,
        None,
    )
}

pub fn normalize_canonical_scip_snapshot_with_affected_calls_reuse(
    root: &Path,
    snapshot: CanonicalScipSnapshot,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
    prior_source_syntax_cache: Option<&CanonicalSourceSyntaxCache>,
    affected_documents: &BTreeSet<String>,
    prior_payload: &CallsProviderPayload,
) -> ScipArtifactSetNormalization {
    normalize_canonical_scip_snapshot_with_acceleration(
        root,
        snapshot,
        indexed_sources,
        inventory,
        prior_source_syntax_cache,
        Some(AffectedCallsReuse {
            affected_documents,
            prior_payload,
        }),
    )
}

fn normalize_canonical_scip_snapshot_with_acceleration(
    root: &Path,
    snapshot: CanonicalScipSnapshot,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
    prior_source_syntax_cache: Option<&CanonicalSourceSyntaxCache>,
    affected_calls_reuse: Option<AffectedCallsReuse<'_>>,
) -> ScipArtifactSetNormalization {
    let canonical_root = match fs::canonicalize(root) {
        Ok(root) => root,
        Err(error) => {
            return unavailable_artifact_set(
                snapshot.provider.spec,
                Some(&snapshot.provider.executed_version),
                snapshot.scope.clone(),
                "repository_root_unreadable",
                format!("cannot resolve repository root: {error}"),
            );
        }
    };
    if canonical_root != snapshot.root {
        return unavailable_artifact_set(
            snapshot.provider.spec,
            Some(&snapshot.provider.executed_version),
            snapshot.scope.clone(),
            "provider_root_mismatch",
            "canonical SCIP snapshot belongs to a different repository root",
        );
    }
    let scoped_sources = indexed_sources_for_scope(
        snapshot.provider.spec,
        &snapshot.scope,
        indexed_sources,
        inventory,
    );
    normalize_canonical_snapshot_with_sources(
        snapshot,
        &scoped_sources,
        inventory,
        prior_source_syntax_cache,
        affected_calls_reuse,
    )
}

fn normalize_canonical_snapshot_with_sources(
    snapshot: CanonicalScipSnapshot,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
    prior_source_syntax_cache: Option<&CanonicalSourceSyntaxCache>,
    affected_calls_reuse: Option<AffectedCallsReuse<'_>>,
) -> ScipArtifactSetNormalization {
    #[cfg(test)]
    CANONICAL_NORMALIZATION_COUNT.with(|count| count.set(count.get() + 1));

    let input_configuration_material = snapshot.input_configuration_material();
    let (mut evidence, source_syntax_cache, timings) = ArtifactNormalizationContext {
        root: &snapshot.root,
        execution_root: &snapshot.root,
        artifact_path: None,
        artifact_index: None,
        canonical_snapshot: Some(&snapshot),
        spec: snapshot.provider.spec,
        executed_provider_version: Some(&snapshot.provider.executed_version),
        input_configuration_material: Some(&input_configuration_material),
        provider_configurations_sha256: Some(&snapshot.provider.configurations_sha256),
        provider_documents_sha256: Some(&snapshot.document_sha256_by_path),
        inventory,
    }
    .normalize_with_acceleration(
        snapshot.scope.clone(),
        indexed_sources,
        prior_source_syntax_cache,
        affected_calls_reuse,
    );
    let canonical_snapshot = if evidence.receipt.status == CapabilityStatus::Complete {
        match evidence.payload.as_mut() {
            Some(payload) => {
                if let Err(error) = payload.bind_canonical_snapshot(&snapshot) {
                    let mut failed = unavailable_artifact_set(
                        snapshot.provider.spec,
                        Some(&snapshot.provider.executed_version),
                        snapshot.scope.clone(),
                        "canonical_snapshot_identity_invalid",
                        error.to_string(),
                    );
                    failed.timings = timings;
                    return failed;
                }
                Some(snapshot)
            }
            None => None,
        }
    } else {
        None
    };
    ScipArtifactSetNormalization {
        evidence,
        supplemental_evidence: Vec::new(),
        canonical_snapshot,
        source_syntax_cache,
        timings,
    }
}

fn indexed_sources_for_scope(
    spec: ScipProviderSpec,
    scope: &CapabilityScope,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
) -> Vec<IndexedSourceEvidence> {
    let CapabilityScope::ProjectUnits {
        project_unit_ids, ..
    } = scope
    else {
        return indexed_sources.to_vec();
    };
    let covered_units = project_unit_ids.iter().collect::<BTreeSet<_>>();
    let covered_paths = inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.language_id.0 == spec.language
                && inventory.is_semantic_source_owner(membership)
                && covered_units.contains(&membership.project_unit_id)
        })
        .map(|membership| membership.document_path.as_str())
        .collect::<BTreeSet<_>>();
    indexed_sources
        .iter()
        .filter(|source| covered_paths.contains(source.relative_path.as_str()))
        .cloned()
        .collect()
}

fn provider_scope_for_execution_roots(
    spec: ScipProviderSpec,
    successful_roots: &BTreeSet<PathBuf>,
    inventory: &ProjectInventory,
) -> CapabilityScope {
    let covered_units =
        semantic_provider_unit_execution_roots(inventory, spec.language, spec.ecosystem)
            .into_iter()
            .filter(|(_, execution_root)| successful_roots.contains(execution_root))
            .map(|(project_unit_id, _)| project_unit_id)
            .collect::<Vec<_>>();
    if covered_units.is_empty() {
        // Test fixtures and explicit normalization callers can intentionally
        // operate over loose sources. Production provider scheduling never
        // creates an artifact for a source population without an eligible
        // package/module root.
        spec.scope()
    } else {
        CapabilityScope::ProjectUnits {
            language_id: LanguageId::new(spec.language),
            project_unit_ids: covered_units,
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        }
    }
}

fn unavailable_artifact_set(
    spec: ScipProviderSpec,
    provider_version: Option<&str>,
    scope: CapabilityScope,
    code: impl Into<String>,
    detail: impl Into<String>,
) -> ScipArtifactSetNormalization {
    ScipArtifactSetNormalization {
        canonical_snapshot: None,
        supplemental_evidence: Vec::new(),
        source_syntax_cache: None,
        timings: ScipNormalizationTimings::default(),
        evidence: ScipArtifactEvidence {
            language_id: LanguageId::new(spec.language),
            receipt: CapabilityReceipt::unavailable(
                "calls",
                spec.provider_id,
                provider_version.map(str::to_owned),
                scope,
                None,
                code,
                detail,
            ),
            payload: None,
        },
    }
}

fn canonicalize_snapshot_documents(
    spec: ScipProviderSpec,
    documents: &mut [Document],
) -> Result<(String, BTreeMap<String, String>), CanonicalScipSnapshotError> {
    documents.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let mut previous_path = None::<String>;
    let mut document_sha256_by_path = BTreeMap::new();
    for document in documents {
        validate_repository_document_path(&document.relative_path)?;
        if previous_path.as_deref() == Some(document.relative_path.as_str()) {
            return Err(CanonicalScipSnapshotError(format!(
                "duplicate canonical document path: {}",
                document.relative_path
            )));
        }
        if document.language != spec.language {
            return Err(CanonicalScipSnapshotError(format!(
                "canonical document {} reports language {:?}, expected {:?}",
                document.relative_path, document.language, spec.language
            )));
        }
        canonicalize_scip_document(document)?;
        previous_path = Some(document.relative_path.clone());
        document_sha256_by_path.insert(
            document.relative_path.clone(),
            canonical_document_sha256(document)?,
        );
    }
    let manifest = canonical_document_manifest_sha256(&document_sha256_by_path);
    Ok((manifest, document_sha256_by_path))
}

fn canonical_document_sha256(document: &Document) -> Result<String, CanonicalScipSnapshotError> {
    let bytes = document.write_to_bytes().map_err(|error| {
        CanonicalScipSnapshotError(format!(
            "cannot serialize canonical document {}: {error}",
            document.relative_path
        ))
    })?;
    Ok(sha256_hex(&bytes))
}

fn canonical_document_manifest_sha256(
    document_sha256_by_path: &BTreeMap<String, String>,
) -> String {
    let mut fingerprint = CANONICAL_SCIP_SNAPSHOT_SCHEMA.to_vec();
    for (document_path, document_sha256) in document_sha256_by_path {
        append_fingerprint_field(&mut fingerprint, document_path.as_bytes());
        append_fingerprint_field(&mut fingerprint, document_sha256.as_bytes());
    }
    sha256_hex(&fingerprint)
}

/// Canonicalize SCIP fields whose protocol meaning is a population rather
/// than an emission-order log. Several indexers construct these vectors from
/// hash maps, so retaining producer order makes equivalent indexes acquire
/// different generation identities and breaks exact incremental/full parity.
fn canonicalize_scip_document(document: &mut Document) -> Result<(), CanonicalScipSnapshotError> {
    #[cfg(test)]
    CANONICAL_DOCUMENT_CANONICALIZATION_COUNT.with(|count| count.set(count.get() + 1));
    for symbol in &mut document.symbols {
        if let Some(signature) = symbol.signature_documentation.as_mut() {
            canonicalize_scip_document(signature)?;
        }
        sort_serialized_population(&mut symbol.relationships, "symbol relationships")?;
    }
    sort_serialized_population(&mut document.symbols, "document symbols")?;
    sort_serialized_population(&mut document.occurrences, "document occurrences")?;
    Ok(())
}

fn sort_serialized_population<M: protobuf::Message>(
    population: &mut Vec<M>,
    label: &str,
) -> Result<(), CanonicalScipSnapshotError> {
    let mut keyed = Vec::with_capacity(population.len());
    for message in std::mem::take(population) {
        let bytes = message.write_to_bytes().map_err(|error| {
            CanonicalScipSnapshotError(format!("cannot canonicalize {label}: {error}"))
        })?;
        keyed.push((bytes, message));
    }
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    *population = keyed.into_iter().map(|(_, message)| message).collect();
    Ok(())
}

fn validate_repository_document_path(path: &str) -> Result<(), CanonicalScipSnapshotError> {
    match repository_document_path(Path::new(""), path) {
        Ok(canonical) if canonical == path => Ok(()),
        Ok(canonical) => Err(CanonicalScipSnapshotError(format!(
            "document path is not canonical: {path:?} becomes {canonical:?}"
        ))),
        Err(error) => Err(CanonicalScipSnapshotError(error.to_string())),
    }
}

fn append_fingerprint_field(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(&(field.len() as u64).to_be_bytes());
    output.extend_from_slice(field);
}

fn local_file_uri(path: &Path) -> Option<String> {
    let path = path.to_str()?;
    let mut uri = String::from("file://");
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'_' | b'.' | b'~') {
            uri.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(uri, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    Some(uri)
}

fn materialize_source_population(
    root: &Path,
    language: &str,
    expected_sources: &BTreeMap<&str, &IndexedSourceEvidence>,
    documents_by_path: Option<&BTreeMap<String, &Document>>,
    inventory: &ProjectInventory,
    prior_source_syntax_cache: Option<&CanonicalSourceSyntaxCache>,
) -> Result<
    (
        BTreeMap<String, SourceDocument>,
        CanonicalSourceSyntaxCache,
        u64,
    ),
    NormalizationFailure,
> {
    let expected_source_entries = expected_sources
        .iter()
        .map(|(&relative_path, &indexed)| (relative_path, indexed))
        .collect::<Vec<_>>();
    let materialized_source_documents = ordered_parallel_try_map(
        &expected_source_entries,
        |entry| {
            let (relative_path, indexed) = *entry;
            let document = documents_by_path
                .and_then(|documents| documents.get(relative_path))
                .copied();
            let source_path = root.join(relative_path);
            let canonical_source = fs::canonicalize(&source_path).map_err(|error| {
                NormalizationFailure::unavailable(
                    "indexed_source_unreadable",
                    format!("cannot resolve indexed source {relative_path}: {error}"),
                )
            })?;
            if !canonical_source.starts_with(root) {
                return Err(NormalizationFailure::unavailable(
                    "indexed_source_escapes_root",
                    format!("indexed source {relative_path} resolves outside the repository"),
                ));
            }
            let bytes = fs::read(&canonical_source).map_err(|error| {
                NormalizationFailure::unavailable(
                    "indexed_source_unreadable",
                    format!("cannot read indexed source {relative_path}: {error}"),
                )
            })?;
            let source = String::from_utf8(bytes).map_err(|error| {
                NormalizationFailure::unavailable(
                    "indexed_source_not_utf8",
                    format!("indexed source {relative_path} is not UTF-8: {error}"),
                )
            })?;
            let source_bytes = source.as_bytes();
            let current_blake3 = blake3::hash(source_bytes).to_hex().to_string();
            if current_blake3 != indexed.blake3_hash {
                return Err(NormalizationFailure::unavailable(
                    "indexed_source_changed",
                    format!("indexed source {relative_path} changed during provider execution"),
                ));
            }
            if document.is_some_and(|document| {
                !document.text.is_empty() && document.text.as_bytes() != source_bytes
            }) {
                return Err(NormalizationFailure::unavailable(
                    "provider_document_text_mismatch",
                    format!("embedded SCIP text differs from indexed source {relative_path}"),
                ));
            }
            if !inventory
                .project_topology
                .memberships
                .iter()
                .any(|membership| {
                    membership.document_path == *relative_path
                        && membership.language_id == LanguageId::new(language)
                        && inventory.is_semantic_source_owner(membership)
                })
            {
                return Err(NormalizationFailure::partial(
                    "source_owner_unproven",
                    format!(
                        "indexed source {relative_path} has no semantic SourceOwner membership"
                    ),
                ));
            }

            let content_sha256 = sha256_hex(source_bytes);
            let byte_length = source.len() as u64;
            let cross_document_surface_sha256 = indexed
                .cross_document_surface_sha256
                .clone()
                .ok_or_else(|| {
                    NormalizationFailure::partial(
                        "semantic_surface_unavailable",
                        format!(
                            "indexed source {relative_path} has no authoritative cross-document surface"
                        ),
                    )
                })?;
            let cached = prior_source_syntax_cache
                .filter(|cache| cache.language == language)
                .and_then(|cache| cache.documents.get(relative_path))
                .filter(|cached| {
                    cached.blake3_hash == indexed.blake3_hash
                        && cached.content_sha256 == content_sha256
                        && cached.byte_length == byte_length
                });
            let (line_ranges, syntax, syntax_cache_hit) = match cached {
                Some(cached) => (
                    Arc::clone(&cached.line_ranges),
                    Arc::clone(&cached.syntax),
                    true,
                ),
                None => (
                    Arc::from(line_ranges(source_bytes)),
                    Arc::new(source_call_evidence(&source, relative_path, language)?),
                    false,
                ),
            };
            Ok((
                relative_path.to_owned(),
                SourceDocument {
                    text: source,
                    line_ranges,
                    descriptor: ProviderDocument {
                        document_path: relative_path.to_owned(),
                        language_id: LanguageId::new(language),
                        content_sha256,
                        cross_document_surface_sha256,
                        byte_length,
                    },
                    syntax,
                },
                syntax_cache_hit,
            ))
        },
    )?;
    let syntax_cache_hits = materialized_source_documents
        .iter()
        .filter(|(_, _, cache_hit)| *cache_hit)
        .count() as u64;
    let source_documents = materialized_source_documents
        .into_iter()
        .map(|(relative_path, document, _)| (relative_path, document))
        .collect::<BTreeMap<_, _>>();
    let source_syntax_cache = CanonicalSourceSyntaxCache {
        language: language.to_owned(),
        documents: Arc::new(
            source_documents
                .iter()
                .map(|(relative_path, document)| {
                    let indexed = expected_sources
                        .get(relative_path.as_str())
                        .expect("every materialized source came from the expected population");
                    (
                        relative_path.clone(),
                        CachedSourceSyntaxDocument {
                            blake3_hash: indexed.blake3_hash.clone(),
                            content_sha256: document.descriptor.content_sha256.clone(),
                            byte_length: document.descriptor.byte_length,
                            line_ranges: Arc::clone(&document.line_ranges),
                            syntax: Arc::clone(&document.syntax),
                        },
                    )
                })
                .collect(),
        ),
        provider_documents: Arc::new(BTreeMap::new()),
        canonical_definitions: None,
    };
    Ok((source_documents, source_syntax_cache, syntax_cache_hits))
}

/// Prime process-local syntax acceleration after an exact immutable semantic
/// basis has been independently re-authorized. The cache is rebuilt from
/// current source bytes rather than trusted from generated cache storage, so
/// it can change cost but never publication authority.
pub fn build_canonical_source_syntax_cache(
    root: &Path,
    language: &str,
    indexed_sources: &[IndexedSourceEvidence],
    inventory: &ProjectInventory,
) -> Result<CanonicalSourceSyntaxCache, String> {
    let root =
        fs::canonicalize(root).map_err(|error| format!("repository_root_unreadable: {error}"))?;
    let expected_sources = indexed_sources
        .iter()
        .filter(|source| {
            source.language == language
                && !inventory.is_structural_only_source_document(
                    &source.relative_path,
                    &LanguageId::new(language),
                )
        })
        .map(|source| (source.relative_path.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    if expected_sources.is_empty() {
        return Err(format!(
            "indexed_source_population_empty: no indexed {language} source population exists"
        ));
    }
    materialize_source_population(&root, language, &expected_sources, None, inventory, None)
        .map(|(_, cache, _)| cache)
        .map_err(|error| format!("{}: {}", error.code, error.detail))
}

fn normalize_complete(
    context: ArtifactNormalizationContext<'_>,
    scope: &CapabilityScope,
    indexed_sources: &[IndexedSourceEvidence],
    prior_source_syntax_cache: Option<&CanonicalSourceSyntaxCache>,
    affected_calls_reuse: Option<AffectedCallsReuse<'_>>,
) -> Result<
    (
        NormalizedProviderPayload,
        CanonicalSourceSyntaxCache,
        ScipNormalizationTimings,
    ),
    NormalizationFailure,
> {
    let normalization_started = Instant::now();
    let ArtifactNormalizationContext {
        root,
        execution_root,
        artifact_path,
        artifact_index,
        canonical_snapshot,
        spec,
        executed_provider_version,
        input_configuration_material,
        provider_configurations_sha256,
        provider_documents_sha256,
        inventory,
    } = context;
    let root = fs::canonicalize(root).map_err(|error| {
        NormalizationFailure::unavailable(
            "repository_root_unreadable",
            format!("cannot resolve repository root: {error}"),
        )
    })?;
    let execution_root = fs::canonicalize(execution_root).map_err(|error| {
        NormalizationFailure::unavailable(
            "provider_root_unreadable",
            format!("cannot resolve SCIP execution root: {error}"),
        )
    })?;
    let execution_prefix = execution_prefix(&root, &execution_root).map_err(|error| {
        NormalizationFailure::unavailable("provider_root_mismatch", error.to_string())
    })?;
    let artifact_bytes = artifact_path
        .map(|artifact_path| {
            fs::read(artifact_path).map_err(|error| {
                NormalizationFailure::unavailable(
                    "provider_artifact_unreadable",
                    format!("cannot read SCIP artifact: {error}"),
                )
            })
        })
        .transpose()?
        .unwrap_or_default();
    let decoded_index = if artifact_index.is_none() && canonical_snapshot.is_none() {
        Some(Index::parse_from_bytes(&artifact_bytes).map_err(|error| {
            NormalizationFailure::unavailable(
                "provider_artifact_invalid",
                format!("cannot decode SCIP artifact: {error}"),
            )
        })?)
    } else {
        None
    };
    let index = artifact_index.or(decoded_index.as_ref());
    let metadata = canonical_snapshot
        .and_then(|snapshot| snapshot.index_envelope.metadata.as_ref())
        .or_else(|| index.and_then(|index| index.metadata.as_ref()))
        .ok_or_else(|| {
            NormalizationFailure::unavailable(
                "provider_metadata_missing",
                "SCIP artifact has no metadata",
            )
        })?;
    let tool = metadata.tool_info.as_ref().ok_or_else(|| {
        NormalizationFailure::unavailable(
            "provider_identity_missing",
            "SCIP metadata has no tool identity",
        )
    })?;
    if tool.name != spec.tool_name
        || tool.version.trim().is_empty()
        || executed_provider_version.is_some_and(|version| tool.version.trim() != version.trim())
    {
        return Err(NormalizationFailure::unavailable(
            "provider_identity_mismatch",
            format!(
                "expected {} tool version {:?}, found name {:?} version {:?}",
                spec.tool_name, executed_provider_version, tool.name, tool.version
            ),
        ));
    }
    let admitted_provider_version = executed_provider_version.unwrap_or(&tool.version).trim();
    let artifact_root = file_uri_path(&metadata.project_root)?;
    let artifact_root = fs::canonicalize(&artifact_root).map_err(|error| {
        NormalizationFailure::unavailable(
            "provider_root_unreadable",
            format!("cannot resolve SCIP project root: {error}"),
        )
    })?;
    if artifact_root != execution_root {
        return Err(NormalizationFailure::unavailable(
            "provider_root_mismatch",
            "SCIP project root differs from the admitted provider execution root",
        ));
    }
    match metadata.text_document_encoding.enum_value() {
        Ok(TextEncoding::UTF8) => {}
        Ok(other) => {
            return Err(NormalizationFailure::unavailable(
                "unsupported_source_encoding",
                format!("SCIP source text encoding {other:?} is not UTF-8"),
            ));
        }
        Err(value) => {
            return Err(NormalizationFailure::unavailable(
                "unknown_source_encoding",
                format!("SCIP source text encoding value {value} is unknown"),
            ));
        }
    }

    let expected_sources = indexed_sources
        .iter()
        .filter(|source| {
            source.language == spec.language
                && !inventory.is_structural_only_source_document(
                    &source.relative_path,
                    &LanguageId::new(spec.language),
                )
        })
        .map(|source| (source.relative_path.as_str(), source))
        .collect::<BTreeMap<_, _>>();
    if expected_sources.is_empty() {
        return Err(NormalizationFailure::unavailable(
            "indexed_source_population_empty",
            format!("no indexed {} source population exists", spec.language),
        ));
    }

    let mut seen_document_paths = BTreeSet::<String>::new();
    let mut documents_by_path = BTreeMap::<String, &Document>::new();
    let mut provider_documents: Box<dyn Iterator<Item = &Document> + '_> =
        if let Some(snapshot) = canonical_snapshot {
            Box::new(
                snapshot
                    .documents_by_path
                    .values()
                    .map(|document| document.as_ref()),
            )
        } else if let Some(index) = index {
            Box::new(index.documents.iter())
        } else {
            return Err(NormalizationFailure::unavailable(
                "provider_artifact_unreadable",
                "normalization received neither provider bytes nor a canonical snapshot",
            ));
        };
    for document in &mut provider_documents {
        let repository_path = repository_document_path(&execution_prefix, &document.relative_path)
            .map_err(|error| {
                NormalizationFailure::unavailable(
                    "provider_document_path_unsafe",
                    error.to_string(),
                )
            })?;
        if document.language != spec.language {
            return Err(NormalizationFailure::partial(
                "provider_document_language_mismatch",
                format!(
                    "document {repository_path} reports language {:?}, expected {:?}",
                    document.language, spec.language
                ),
            ));
        }
        if !seen_document_paths.insert(repository_path.clone()) {
            return Err(NormalizationFailure::unavailable(
                "provider_document_duplicate",
                format!("duplicate SCIP document {repository_path}"),
            ));
        }
        if !expected_sources.contains_key(repository_path.as_str()) {
            // The structural source population is the repository authority.
            // Providers commonly emit dependency, sysroot, generated, or
            // otherwise ignored documents in addition to that population.
            // Those documents may neither widen authority nor downgrade
            // complete coverage of every admitted project source. Exclude the
            // whole document before symbol/call normalization; equality below
            // still fails closed when any admitted source is missing.
            continue;
        }
        if documents_by_path
            .insert(repository_path.clone(), document)
            .is_some()
        {
            return Err(NormalizationFailure::unavailable(
                "provider_document_duplicate",
                format!("duplicate SCIP document {repository_path}"),
            ));
        }
    }
    let actual_paths = documents_by_path
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_paths = expected_sources.keys().copied().collect::<BTreeSet<_>>();
    let missing_document_paths = expected_paths
        .difference(&actual_paths)
        .copied()
        .collect::<Vec<_>>();

    let setup_duration = normalization_started.elapsed();
    let source_validation_started = Instant::now();
    let (source_documents, mut source_syntax_cache, syntax_cache_hits) =
        materialize_source_population(
            &root,
            spec.language,
            &expected_sources,
            Some(&documents_by_path),
            inventory,
            prior_source_syntax_cache,
        )?;
    let source_document_count = source_documents.len() as u64;
    let source_validation_duration = source_validation_started.elapsed();
    let mut reused_evidence_documents = BTreeSet::new();
    let mut reused_call_documents = BTreeSet::new();
    if let Some(reuse) = affected_calls_reuse {
        if reuse.affected_documents.is_empty()
            || reuse.prior_payload.receipt.status != CapabilityStatus::Complete
            || reuse.prior_payload.receipt.provider_id.0 != spec.provider_id
            || reuse.prior_payload.receipt.provider_version.as_deref()
                != Some(executed_provider_version.unwrap_or(&tool.version))
            || reuse.prior_payload.receipt.scope != *scope
        {
            return Err(NormalizationFailure::unavailable(
                "affected_calls_reuse_invalid",
                "prior Calls evidence does not match the affected normalization authority",
            ));
        }
        if reuse
            .affected_documents
            .iter()
            .any(|path| !expected_sources.contains_key(path.as_str()))
        {
            return Err(NormalizationFailure::unavailable(
                "affected_calls_population_invalid",
                "affected Calls reuse names a document outside the indexed source population",
            ));
        }
        let prior_documents = reuse
            .prior_payload
            .documents
            .iter()
            .map(|document| (document.document_path.as_str(), document))
            .collect::<BTreeMap<_, _>>();
        for (document_path, source) in &source_documents {
            if reuse.affected_documents.contains(document_path) {
                let Some(prior) = prior_documents.get(document_path.as_str()).copied() else {
                    return Err(NormalizationFailure::unavailable(
                        "affected_calls_population_invalid",
                        format!(
                            "affected document {document_path} has no prior Calls source authority"
                        ),
                    ));
                };
                if prior.cross_document_surface_sha256
                    != source.descriptor.cross_document_surface_sha256
                {
                    return Err(NormalizationFailure::unavailable(
                        "affected_calls_surface_mismatch",
                        format!(
                            "affected document {document_path} changed its cross-document semantic surface"
                        ),
                    ));
                }
                continue;
            }
            if prior_documents.get(document_path.as_str()).copied() != Some(&source.descriptor) {
                return Err(NormalizationFailure::unavailable(
                    "affected_calls_source_mismatch",
                    format!(
                        "unchanged document {document_path} differs from prior Calls source authority"
                    ),
                ));
            }
            reused_evidence_documents.insert(document_path.clone());
            if actual_paths.contains(document_path.as_str()) {
                reused_call_documents.insert(document_path.clone());
            }
        }
    }
    let coverage_exclusion_setup_started = Instant::now();

    let mut coverage_exclusions = BTreeSet::new();
    for document_path in missing_document_paths {
        let source = source_documents
            .get(document_path)
            .expect("every indexed source was materialized");
        if source.text.is_empty() {
            continue;
        }
        coverage_exclusions.insert(ProviderCoverageExclusion {
            location: ProviderLocation {
                document_path: document_path.to_owned(),
                span: normalized_source_byte_span(source, document_path, 0, source.text.len())?,
            },
            reason_code: "provider_document_omitted".into(),
        });
    }
    let coverage_exclusion_setup_duration = coverage_exclusion_setup_started.elapsed();
    let occurrence_indexing_started = Instant::now();
    let mut provider_invoked_symbol_ids = BTreeSet::new();
    let mut provider_symbols_by_range = ProviderSymbolsByRange::new();
    let mut provider_reference_symbols_by_range = ProviderReferenceSymbolsByRange::new();
    let mut provider_occurrences_by_document =
        BTreeMap::<String, Arc<[NormalizedProviderOccurrence]>>::new();
    let mut provider_document_cache_hits = 0_u64;
    let mut next_provider_document_cache = BTreeMap::new();
    for (document_path, document) in &documents_by_path {
        let source = source_documents
            .get(document_path)
            .expect("validated source document");
        let provider_document_sha256 = provider_documents_sha256
            .and_then(|documents| documents.get(document_path))
            .cloned();
        let cached = provider_document_sha256
            .as_ref()
            .and_then(|expected_digest| {
                prior_source_syntax_cache
                    .filter(|cache| cache.language == spec.language)
                    .and_then(|cache| cache.provider_documents.get(document_path))
                    .filter(|cached| {
                        cached.source_content_sha256 == source.descriptor.content_sha256
                            && cached.provider_document_sha256.as_ref() == Some(expected_digest)
                    })
                    .cloned()
            });
        let normalized = match cached {
            Some(cached) => {
                provider_document_cache_hits += 1;
                cached
            }
            None => {
                let mut normalized_occurrences = Vec::with_capacity(document.occurrences.len());
                let mut symbols_by_range = BTreeMap::new();
                let mut reference_symbols_by_range = BTreeMap::new();
                let mut invoked_symbol_ids = BTreeSet::new();
                for occurrence in &document.occurrences {
                    if occurrence.symbol.is_empty() {
                        continue;
                    }
                    let span = normalized_provider_span(
                        spec,
                        admitted_provider_version,
                        document,
                        source,
                        &occurrence.range,
                    )?;
                    let range = (span.start_byte as usize, span.end_byte as usize);
                    let is_definition =
                        occurrence.symbol_roles & SymbolRole::Definition.value() != 0;
                    let is_call = source.syntax.call_callees.contains_key(&range);
                    let is_callable_binding_target = spec.language == "go"
                        && source.syntax.callable_binding_targets.contains_key(&range);
                    if spec.language == "go"
                        && !is_definition
                        && !is_call
                        && !is_callable_binding_target
                    {
                        continue;
                    }
                    let provider_symbol_id = qualified_symbol_id(document_path, &occurrence.symbol);
                    if spec.language == "rust" {
                        #[cfg(test)]
                        PROVIDER_SYMBOL_RANGE_INSERT_COUNT.with(|count| count.set(count.get() + 1));
                        symbols_by_range
                            .entry(range)
                            .or_insert_with(BTreeSet::new)
                            .insert(provider_symbol_id.clone());
                    }
                    if spec.language == "go" && !is_definition {
                        if is_callable_binding_target {
                            #[cfg(test)]
                            PROVIDER_REFERENCE_RANGE_INSERT_COUNT
                                .with(|count| count.set(count.get() + 1));
                            reference_symbols_by_range
                                .entry(range)
                                .or_insert_with(Vec::new)
                                .push(provider_symbol_id.clone());
                        }
                        if is_call {
                            invoked_symbol_ids.insert(provider_symbol_id.clone());
                        }
                    }
                    normalized_occurrences.push(NormalizedProviderOccurrence {
                        symbol: occurrence.symbol.clone(),
                        symbol_roles: occurrence.symbol_roles,
                        provider_symbol_id,
                        span,
                        range,
                    });
                    #[cfg(test)]
                    NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT
                        .with(|count| count.set(count.get() + 1));
                }
                CachedProviderNormalizationDocument {
                    source_content_sha256: source.descriptor.content_sha256.clone(),
                    provider_document_sha256,
                    occurrences: Arc::from(normalized_occurrences),
                    symbols_by_range: Arc::new(symbols_by_range),
                    reference_symbols_by_range: Arc::new(reference_symbols_by_range),
                    invoked_symbol_ids: Arc::new(invoked_symbol_ids),
                    definition_records: None,
                    rust_method_witnesses: None,
                }
            }
        };
        provider_invoked_symbol_ids.extend(normalized.invoked_symbol_ids.iter().cloned());
        if !normalized.symbols_by_range.is_empty() {
            provider_symbols_by_range
                .insert(document_path.clone(), normalized.symbols_by_range.clone());
        }
        if !normalized.reference_symbols_by_range.is_empty() {
            provider_reference_symbols_by_range.insert(
                document_path.clone(),
                normalized.reference_symbols_by_range.clone(),
            );
        }
        provider_occurrences_by_document
            .insert(document_path.clone(), Arc::clone(&normalized.occurrences));
        next_provider_document_cache.insert(document_path.clone(), normalized);
    }
    let occurrence_indexing_duration = occurrence_indexing_started.elapsed();
    let prior_canonical_definitions = affected_calls_reuse
        .and(prior_source_syntax_cache)
        .filter(|cache| cache.language == spec.language)
        .and_then(|cache| cache.canonical_definitions.clone());
    let incremental_definition_reuse = prior_canonical_definitions.is_some();
    let definition_collection_started = Instant::now();
    let mut definition_records = Vec::<DefinitionRecord>::new();
    let mut rust_method_witnesses = RustMethodWitnesses::new();
    let mut definition_document_cache_hits = 0_u64;
    for (document_path, document) in &documents_by_path {
        let cached = next_provider_document_cache
            .get(document_path)
            .and_then(|cached| {
                Some((
                    Arc::clone(cached.definition_records.as_ref()?),
                    Arc::clone(cached.rust_method_witnesses.as_ref()?),
                ))
            });
        if let Some((cached_definitions, cached_witnesses)) = cached {
            definition_document_cache_hits += 1;
            if !incremental_definition_reuse {
                definition_records.extend(cached_definitions.iter().cloned());
            }
            for (owner, symbols) in cached_witnesses.iter() {
                rust_method_witnesses
                    .entry(owner.clone())
                    .or_default()
                    .extend(symbols.iter().cloned());
            }
            continue;
        }
        let mut document_definition_records = Vec::new();
        let mut document_rust_method_witnesses = RustMethodWitnesses::new();
        let source = source_documents
            .get(document_path)
            .expect("validated source document");
        let symbol_information = document
            .symbols
            .iter()
            .map(|information| (information.symbol.as_str(), information))
            .collect::<BTreeMap<_, _>>();
        if spec.language == "rust" {
            for information in &document.symbols {
                let Ok(kind) = information.kind.enum_value() else {
                    continue;
                };
                if !callable_kind(kind) || information.display_name.trim().is_empty() {
                    continue;
                }
                let Some(owner) = rust_method_owner(&information.symbol) else {
                    continue;
                };
                document_rust_method_witnesses
                    .entry((
                        owner,
                        comparable_callee_name(&information.display_name).to_owned(),
                    ))
                    .or_default()
                    .insert(qualified_symbol_id(document_path, &information.symbol));
            }
        }
        let occurrences = provider_occurrences_by_document
            .get(document_path)
            .expect("normalized provider occurrences");
        for occurrence in occurrences.iter() {
            if occurrence.symbol_roles & SymbolRole::Definition.value() == 0
                || occurrence.symbol_roles & SymbolRole::ForwardDefinition.value() != 0
            {
                continue;
            }
            let provider_symbol_id = occurrence.provider_symbol_id.clone();
            let definition_span = occurrence.span.clone();
            let definition_range = occurrence.range;
            let Some(information) = symbol_information.get(occurrence.symbol.as_str()).copied()
            else {
                if source
                    .syntax
                    .callable_extents
                    .contains_key(&definition_range)
                    || source
                        .syntax
                        .invocation_target_extents
                        .contains_key(&definition_range)
                {
                    return Err(NormalizationFailure::partial(
                        "provider_invocation_target_information_missing",
                        format!(
                            "provider invocation-target definition {} at {document_path}:{}-{} has no matching SymbolInformation",
                            occurrence.symbol, definition_span.start_byte, definition_span.end_byte,
                        ),
                    ));
                }
                continue;
            };
            let kind = information.kind.enum_value().map_err(|value| {
                NormalizationFailure::unavailable(
                    "provider_symbol_kind_unknown",
                    format!("symbol {} has unknown kind {value}", occurrence.symbol),
                )
            })?;
            let name = if information.display_name.trim().is_empty() {
                source_slice(source.text.as_bytes(), &definition_span)?.to_owned()
            } else {
                information.display_name.clone()
            };
            let value_binding_span = source
                .syntax
                .value_binding_extents
                .get(&definition_range)
                .copied()
                .map(|(start, end)| normalized_source_byte_span(source, document_path, start, end))
                .transpose()?;
            let repository_scope = (0, source.text.len() as u64);
            let binding_scope = source
                .syntax
                .binding_scopes
                .get(&definition_range)
                .copied()
                .unwrap_or(repository_scope);
            let rust_declared_owner = (spec.language == "rust")
                .then(|| source.syntax.declared_type_names.get(&definition_range))
                .flatten()
                .and_then(|type_range| {
                    unique_provider_symbol_at_range(
                        &provider_symbols_by_range,
                        document_path,
                        *type_range,
                    )
                })
                .and_then(rust_type_owner);
            let syntax_call_owner_extent = source
                .syntax
                .callable_extents
                .get(&definition_range)
                .copied();
            let syntax_callable_extent = syntax_call_owner_extent.or_else(|| {
                // An invoked package-level variable is a stable structural
                // binding (the Go extractor publishes its exact var spec as
                // a `static`). A function-local variable or parameter is
                // only a dynamic call target: it does not own a callable
                // body and must not masquerade as a structural definition.
                (spec.language == "go"
                    && kind == symbol_information::Kind::Variable
                    && provider_invoked_symbol_ids.contains(&provider_symbol_id)
                    && binding_scope == repository_scope)
                    .then(|| {
                        source
                            .syntax
                            .value_binding_extents
                            .get(&definition_range)
                            .copied()
                    })
                    .flatten()
            });
            let syntax_invocation_target_extent = source
                .syntax
                .invocation_target_extents
                .get(&definition_range)
                .copied();
            let callable = callable_kind(kind)
                || (call_target_kind(spec, kind) && syntax_callable_extent.is_some());
            let syntax_callable_extent = syntax_callable_extent
                .map(|(start, end)| normalized_source_byte_span(source, document_path, start, end))
                .transpose()?;
            let invocation_target_span = syntax_invocation_target_extent
                .map(|(start, end)| normalized_source_byte_span(source, document_path, start, end))
                .transpose()?;
            let call_owner_span = syntax_callable_extent
                .as_ref()
                .filter(|span| {
                    source
                        .syntax
                        .exact_call_owner_extent(span.start_byte, span.end_byte)
                })
                .cloned();
            if callable && syntax_callable_extent.is_none() {
                if source
                    .syntax
                    .enclosing_generated_range(definition_span.start_byte, definition_span.end_byte)
                    .is_some()
                {
                    // rust-analyzer exposes macro-expanded callables at their
                    // invocation-token spans. They have no literal callable
                    // syntax or structural node in the indexed document, so
                    // they cannot establish source ownership or be queried as
                    // source-backed definitions. They are outside the named
                    // explicit-source-invocation population, not a hole within
                    // it, so they must not qualify unrelated query results.
                    continue;
                }
                return Err(NormalizationFailure::partial(
                    "provider_definition_span_mismatch",
                    format!(
                        "provider callable definition {} at {document_path}:{}-{} does not match an exact syntax callable-name span",
                        occurrence.symbol, definition_span.start_byte, definition_span.end_byte,
                    ),
                ));
            }
            // Provider enclosing ranges are descriptive metadata, not lexical
            // ownership authority. Only the exact syntax callable matched by
            // the provider definition may own call sites. A language adapter
            // may additionally prove that the callable is nested runtime
            // state rather than a stable structural target. Keep its exact
            // owner span for coverage accounting without publishing a graph
            // identity that structural extraction deliberately does not own.
            let structurally_published_callable = !source
                .syntax
                .non_structural_callable_definitions
                .contains(&definition_range);
            let enclosing_span = structurally_published_callable
                .then_some(syntax_callable_extent)
                .flatten();
            let record = DefinitionRecord {
                provider_symbol_id,
                name,
                kind: kind_name(kind),
                provider_kind: kind,
                document_path: document_path.clone(),
                definition: ProviderLocation {
                    document_path: document_path.clone(),
                    span: definition_span,
                },
                enclosing_span,
                invocation_target_span,
                call_owner_span,
                value_binding_span,
                binding_scope,
                callable,
                rust_declared_owner,
            };
            document_definition_records.push(record);
            #[cfg(test)]
            PROVIDER_DEFINITION_RECORD_RETAIN_COUNT.with(|count| count.set(count.get() + 1));
        }
        let document_definition_records: Arc<[DefinitionRecord]> =
            Arc::from(document_definition_records);
        let document_rust_method_witnesses = Arc::new(document_rust_method_witnesses);
        if !incremental_definition_reuse {
            definition_records.extend(document_definition_records.iter().cloned());
        }
        for (owner, symbols) in document_rust_method_witnesses.iter() {
            rust_method_witnesses
                .entry(owner.clone())
                .or_default()
                .extend(symbols.iter().cloned());
        }
        let cached = next_provider_document_cache
            .get_mut(document_path)
            .expect("every provider document has exact occurrence acceleration");
        cached.definition_records = Some(document_definition_records);
        cached.rust_method_witnesses = Some(document_rust_method_witnesses);
    }
    let definition_collection_duration = definition_collection_started.elapsed();
    let definition_canonicalization_started = Instant::now();
    let (
        mut definitions,
        definition_aliases,
        definition_records_by_base_id,
        definition_group_reuse_hits,
    ) = if let (Some(reuse), Some(prior_canonical)) =
        (affected_calls_reuse, prior_canonical_definitions)
    {
        let mut affected_base_ids = BTreeSet::new();
        for document_path in reuse.affected_documents {
            if let Some(records) = prior_source_syntax_cache
                .and_then(|cache| cache.provider_documents.get(document_path))
                .and_then(|cached| cached.definition_records.as_ref())
            {
                affected_base_ids.extend(
                    records
                        .iter()
                        .map(|record| record.provider_symbol_id.clone()),
                );
            }
            if let Some(records) = next_provider_document_cache
                .get(document_path)
                .and_then(|cached| cached.definition_records.as_ref())
            {
                affected_base_ids.extend(
                    records
                        .iter()
                        .map(|record| record.provider_symbol_id.clone()),
                );
            }
        }

        let mut definitions = Arc::clone(&prior_canonical.definitions);
        let mut aliases = Arc::clone(&prior_canonical.aliases);
        let reused_groups = aliases.len().saturating_sub(
            affected_base_ids
                .iter()
                .filter(|base_id| aliases.contains_key(base_id.as_str()))
                .count(),
        );
        let mut current_affected_records = BTreeMap::<String, Vec<DefinitionRecord>>::new();
        for document_path in reuse.affected_documents {
            if let Some(records) = next_provider_document_cache
                .get(document_path)
                .and_then(|cached| cached.definition_records.as_ref())
            {
                for record in records.iter() {
                    #[cfg(test)]
                    DEFINITION_RECORD_GROUP_SCAN_COUNT.with(|count| count.set(count.get() + 1));
                    current_affected_records
                        .entry(record.provider_symbol_id.clone())
                        .or_default()
                        .push(record.clone());
                }
            }
        }
        let definition_records_by_base_id = refresh_definition_records_by_base_id(
            &prior_canonical.records_by_base_id,
            reuse.affected_documents,
            &affected_base_ids,
            current_affected_records,
        );
        let replacement_records = affected_base_ids
            .iter()
            .filter_map(|base_id| definition_records_by_base_id.get(base_id.as_str()))
            .flat_map(|records| records.iter().map(|record| record.as_ref().clone()))
            .collect();
        let (replacement_definitions, replacement_aliases) =
            canonicalize_definition_records(replacement_records)?;
        {
            let definitions = Arc::make_mut(&mut definitions);
            let aliases = Arc::make_mut(&mut aliases);
            for base_id in &affected_base_ids {
                if let Some(canonical_ids) = aliases.remove(base_id.as_str()) {
                    for canonical_id in canonical_ids.iter() {
                        definitions.remove(canonical_id.as_ref());
                    }
                }
            }
            for (canonical_id, definition) in replacement_definitions {
                if definitions
                    .insert(Arc::from(canonical_id.clone()), Arc::new(definition))
                    .is_some()
                {
                    return Err(NormalizationFailure::unavailable(
                        "incremental_definition_identity_collision",
                        format!(
                            "affected definition canonical identity {canonical_id} collides with an unchanged group"
                        ),
                    ));
                }
            }
            aliases.extend(shared_definition_aliases(replacement_aliases));
        }
        (
            definitions,
            aliases,
            definition_records_by_base_id,
            reused_groups as u64,
        )
    } else {
        let records_by_base_id = definition_records_by_base_id(&definition_records);
        let (definitions, aliases) = canonicalize_definition_records(definition_records)?;
        (
            Arc::new(shared_canonical_definitions(definitions)),
            Arc::new(shared_definition_aliases(aliases)),
            Arc::new(records_by_base_id),
            0,
        )
    };
    let definition_group_count = definition_aliases.len() as u64;
    source_syntax_cache.canonical_definitions = Some(CachedCanonicalDefinitionGroups {
        definitions: Arc::clone(&definitions),
        aliases: Arc::clone(&definition_aliases),
        records_by_base_id: definition_records_by_base_id,
    });
    source_syntax_cache.provider_documents = Arc::new(next_provider_document_cache);
    let definition_canonicalization_duration = definition_canonicalization_started.elapsed();
    let binding_and_lookup_indexing_started = Instant::now();
    let mut variable_definitions_by_range =
        BTreeMap::<String, BTreeMap<(u64, u64), Vec<String>>>::new();
    for (provider_symbol_id, definition) in definitions.iter() {
        if definition.provider_kind != symbol_information::Kind::Variable {
            continue;
        }
        variable_definitions_by_range
            .entry(definition.document_path.clone())
            .or_default()
            .entry((
                definition.definition.span.start_byte,
                definition.definition.span.end_byte,
            ))
            .or_default()
            .push(provider_symbol_id.to_string());
    }
    let mut raw_callable_bindings = BTreeSet::<(String, String, ProviderLocation)>::new();
    let mut unresolved_callable_binding_sites = Vec::<(String, ProviderLocation)>::new();
    for document_path in documents_by_path.keys() {
        let source = source_documents
            .get(document_path)
            .expect("validated source document");
        for (target_range, binding_definition_range) in &source.syntax.callable_binding_targets {
            let binding_candidates = variable_definitions_by_range
                .get(document_path)
                .and_then(|ranges| {
                    ranges.get(&(
                        binding_definition_range.0 as u64,
                        binding_definition_range.1 as u64,
                    ))
                })
                .map(Vec::as_slice)
                .unwrap_or_default();
            let binding_id = match binding_candidates {
                [] => continue,
                [binding_id] => binding_id.clone(),
                _ => {
                    return Err(NormalizationFailure::unavailable(
                        "callable_binding_definition_ambiguous",
                        format!(
                            "Go callable binding at {document_path}:{binding_definition_range:?} maps to multiple provider definitions"
                        ),
                    ));
                }
            };
            let target_location = ProviderLocation {
                document_path: document_path.clone(),
                span: normalized_source_byte_span(
                    source,
                    document_path,
                    target_range.0,
                    target_range.1,
                )?,
            };
            let matching_symbols = provider_reference_symbols_by_range
                .get(document_path)
                .and_then(|ranges| ranges.get(target_range));
            let target_base_id = match matching_symbols {
                None => {
                    unresolved_callable_binding_sites.push((binding_id, target_location));
                    continue;
                }
                Some(symbols) if symbols.len() == 1 => symbols
                    .first()
                    .expect("one provider symbol at binding target")
                    .clone(),
                Some(_) => {
                    return Err(NormalizationFailure::partial(
                        "provider_callable_binding_occurrence_ambiguous",
                        format!(
                            "multiple provider occurrences cover Go callable binding syntax at {document_path}:{target_range:?}"
                        ),
                    ));
                }
            };
            let Some(candidate_ids) = definition_aliases.get(target_base_id.as_str()) else {
                // A provider-resolved external callable has no repository-local
                // liveness target. The binding itself remains callable.
                continue;
            };
            let target = resolve_callee_definition(
                &target_base_id,
                candidate_ids,
                &definitions,
                document_path,
                &target_location.span,
            )?;
            raw_callable_bindings.insert((
                binding_id,
                target.provider_symbol_id.clone(),
                target_location,
            ));
        }
    }

    // Callable values can be chained (`var b = a; var a = target; b()`).
    // Propagate provider-proven callability through exact local binding edges
    // to a fixed point; never use names or assignment order as authority.
    loop {
        let mut promoted = Vec::new();
        for (binding_id, target_id, _) in &raw_callable_bindings {
            let Some(binding) = definitions.get(binding_id.as_str()) else {
                continue;
            };
            let Some(target) = definitions.get(target_id.as_str()) else {
                continue;
            };
            if binding.callable
                && !target.callable
                && call_target_kind(spec, target.provider_kind)
                && target.value_binding_span.is_some()
            {
                promoted.push(target_id.clone());
            }
        }
        if promoted.is_empty() {
            break;
        }
        promoted.sort();
        promoted.dedup();
        let definitions = Arc::make_mut(&mut definitions);
        for target_id in promoted {
            let target = definitions
                .get_mut(target_id.as_str())
                .expect("binding propagation target remains defined");
            let target = Arc::make_mut(target);
            target.callable = true;
            target.enclosing_span = target.value_binding_span.clone();
        }
    }

    let mut callable_bindings = Vec::new();
    for (binding_id, target_id, binding_site) in raw_callable_bindings {
        let binding = definitions
            .get(binding_id.as_str())
            .expect("callable binding source remains defined");
        if !binding.callable {
            continue;
        }
        let target = definitions
            .get(target_id.as_str())
            .expect("callable binding target remains defined");
        if !target.callable {
            return Err(NormalizationFailure::partial(
                "callable_binding_target_not_callable",
                format!(
                    "provider-resolved callable binding {} targets non-callable local symbol {}",
                    binding.provider_symbol_id, target.provider_symbol_id
                ),
            ));
        }
        callable_bindings.push(ProviderCallableBinding {
            binding_symbol_id: binding.provider_symbol_id.clone(),
            target_symbol_id: target.provider_symbol_id.clone(),
            binding_site,
        });
    }
    for (binding_id, location) in unresolved_callable_binding_sites {
        if definitions
            .get(binding_id.as_str())
            .is_some_and(|binding| binding.callable)
        {
            coverage_exclusions.insert(ProviderCoverageExclusion {
                location,
                reason_code: "callable_binding_unresolved".into(),
            });
        }
    }
    let mut definitions_by_document: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (provider_symbol_id, definition) in definitions.iter() {
        definitions_by_document
            .entry(definition.document_path.clone())
            .or_default()
            .push(provider_symbol_id.to_string());
    }
    let definition_owner_indexes = definitions_by_document
        .iter()
        .map(|(document_path, provider_ids)| {
            (
                document_path.clone(),
                DefinitionCallOwnerIndex::new(
                    provider_ids
                        .iter()
                        .filter_map(|provider_id| definitions.get(provider_id.as_str()))
                        .map(Arc::as_ref),
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let provider_invocation_target_definition_ranges = definitions
        .values()
        .filter(|definition| definition.source_invocation_target())
        .fold(
            BTreeMap::<String, BTreeSet<(usize, usize)>>::new(),
            |mut ranges, definition| {
                ranges
                    .entry(definition.document_path.clone())
                    .or_default()
                    .insert((
                        definition.definition.span.start_byte as usize,
                        definition.definition.span.end_byte as usize,
                    ));
                ranges
            },
        );
    for (document_path, source) in &source_documents {
        if !actual_paths.contains(document_path.as_str()) {
            continue;
        }
        let covered = provider_invocation_target_definition_ranges
            .get(document_path)
            .cloned()
            .unwrap_or_default();
        for definition_range in source
            .syntax
            .callable_extents
            .keys()
            .chain(source.syntax.invocation_target_extents.keys())
        {
            if covered.contains(definition_range) {
                continue;
            }
            if let Some((start, end)) = source
                .syntax
                .enclosing_conditional_range(definition_range.0 as u64, definition_range.1 as u64)
            {
                coverage_exclusions.insert(provider_coverage_exclusion(
                    source,
                    document_path,
                    start,
                    end,
                    "conditional_compilation",
                )?);
            }
        }
    }

    let mut local_callable_names_by_document = source_documents
        .iter()
        .filter(|(document_path, _)| actual_paths.contains(document_path.as_str()))
        .map(|(document_path, source)| {
            let mut names = source.syntax.local_callable_names.clone();
            names.extend(source.syntax.local_invocation_target_names.iter().cloned());
            (document_path.clone(), names)
        })
        .collect::<BTreeMap<_, _>>();
    let mut repository_callable_names = source_documents
        .iter()
        .filter(|(document_path, _)| actual_paths.contains(document_path.as_str()))
        .flat_map(|(_, source)| {
            source
                .syntax
                .local_callable_names
                .iter()
                .chain(source.syntax.local_invocation_target_names.iter())
                .cloned()
        })
        .collect::<BTreeSet<_>>();
    for definition in definitions
        .values()
        .filter(|definition| definition.source_invocation_target())
    {
        repository_callable_names.insert(comparable_callee_name(&definition.name).to_owned());
        local_callable_names_by_document
            .entry(definition.document_path.clone())
            .or_default()
            .insert(comparable_callee_name(&definition.name).to_owned());
    }
    let mut go_package_function_names = BTreeMap::<(String, String), SourceCallableNames>::new();
    let mut go_production_package_function_names =
        BTreeMap::<(String, String), SourceCallableNames>::new();
    for (document_path, source) in &source_documents {
        if !actual_paths.contains(document_path.as_str()) {
            continue;
        }
        let Some(scope) = go_package_scope(document_path, source) else {
            continue;
        };
        go_package_function_names
            .entry(scope.clone())
            .or_default()
            .extend(source.syntax.go_package_function_names.iter().cloned());
        if !is_go_test_document(document_path) {
            go_production_package_function_names
                .entry(scope)
                .or_default()
                .extend(source.syntax.go_package_function_names.iter().cloned());
        }
    }

    // A complete Calls payload addresses the provider's complete callable
    // definition population, not merely symbols that happen to participate in
    // at least one call edge. Zero-caller leaves must still have an exact
    // provider identity so a query can return an authoritative empty result.
    let binding_and_lookup_indexing_duration = binding_and_lookup_indexing_started.elapsed();
    let call_resolution_started = Instant::now();
    let mut symbols = definitions
        .values()
        .filter(|definition| definition.source_invocation_target())
        .map(|definition| {
            (
                definition.provider_symbol_id.clone(),
                provider_symbol(definition, spec.language),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if let Some(reuse) = affected_calls_reuse {
        let prior_symbols = reuse
            .prior_payload
            .symbols
            .iter()
            .map(|symbol| (symbol.provider_symbol_id.as_str(), symbol))
            .collect::<BTreeMap<_, _>>();
        reused_call_documents.retain(|document_path| {
            let calls_are_reusable = reuse
                .prior_payload
                .calls
                .iter()
                .filter(|call| call.call_site.document_path == *document_path)
                .all(|call| {
                    [&call.caller_symbol_id, &call.callee_symbol_id]
                        .into_iter()
                        .all(|symbol_id| {
                            let Some(prior_symbol) = prior_symbols.get(symbol_id.as_str()).copied()
                            else {
                                return false;
                            };
                            symbols.get(symbol_id).map_or_else(
                                || {
                                    prior_symbol.definition.is_some()
                                        && prior_symbol
                                            .definition
                                            .iter()
                                            .chain(prior_symbol.structural_extent.iter())
                                            .chain(prior_symbol.call_owner_extent.iter())
                                            .all(|location| {
                                                reused_evidence_documents
                                                    .contains(&location.document_path)
                                            })
                                },
                                |current_symbol| current_symbol == prior_symbol,
                            )
                        })
                });
            let roots_are_reusable = reuse
                .prior_payload
                .root_invocations
                .iter()
                .filter(|invocation| invocation.call_site.document_path == *document_path)
                .all(|invocation| {
                    let Some(prior_symbol) = prior_symbols
                        .get(invocation.callee_symbol_id.as_str())
                        .copied()
                    else {
                        return false;
                    };
                    symbols
                        .get(&invocation.callee_symbol_id)
                        .is_some_and(|current_symbol| current_symbol == prior_symbol)
                });
            calls_are_reusable && roots_are_reusable
        });
        coverage_exclusions.extend(
            reuse
                .prior_payload
                .coverage_exclusions
                .iter()
                .filter(|exclusion| {
                    reused_call_documents.contains(&exclusion.location.document_path)
                })
                .cloned(),
        );
    }
    let mut calls = affected_calls_reuse.map_or_else(Vec::new, |reuse| {
        reuse
            .prior_payload
            .calls
            .iter()
            .filter(|call| reused_call_documents.contains(&call.call_site.document_path))
            .cloned()
            .collect()
    });
    let mut root_invocations = affected_calls_reuse.map_or_else(Vec::new, |reuse| {
        reuse
            .prior_payload
            .root_invocations
            .iter()
            .filter(|invocation| {
                reused_call_documents.contains(&invocation.call_site.document_path)
            })
            .cloned()
            .collect()
    });
    if let Some(reuse) = affected_calls_reuse {
        let retained_symbol_ids = calls
            .iter()
            .flat_map(|call| [&call.caller_symbol_id, &call.callee_symbol_id])
            .chain(
                root_invocations
                    .iter()
                    .map(|invocation| &invocation.callee_symbol_id),
            )
            .collect::<BTreeSet<_>>();
        for symbol in &reuse.prior_payload.symbols {
            if retained_symbol_ids.contains(&symbol.provider_symbol_id) {
                symbols
                    .entry(symbol.provider_symbol_id.clone())
                    .or_insert_with(|| symbol.clone());
            }
        }
    }
    let mut covered_call_callee_ranges: BTreeMap<String, BTreeSet<(usize, usize)>> =
        BTreeMap::new();
    for (document_path, occurrences) in &provider_occurrences_by_document {
        if reused_call_documents.contains(document_path) {
            continue;
        }
        #[cfg(test)]
        CALL_DOCUMENT_RESOLUTION_COUNT.with(|count| count.set(count.get() + 1));
        let source = source_documents
            .get(document_path)
            .expect("validated source document");
        for occurrence in occurrences.iter() {
            if occurrence.symbol_roles & SymbolRole::Definition.value() != 0 {
                continue;
            }
            let call_span = occurrence.span.clone();
            if call_span.start_byte == call_span.end_byte {
                // A zero-width reference cannot identify source invocation
                // syntax. Ignore the malformed artifact locally instead of
                // allowing it to invalidate the language-wide payload.
                continue;
            }
            let byte_range = occurrence.range;
            let syntax_callee = if let Some(callee) = source.syntax.call_callees.get(&byte_range) {
                Cow::Borrowed(callee.name.as_str())
            } else if let Some((_, generated_end)) = source
                .syntax
                .enclosing_generated_range(call_span.start_byte, call_span.end_byte)
                && rust_macro_occurrence_has_explicit_arguments(
                    source.text.as_bytes(),
                    call_span.end_byte,
                    generated_end,
                )
            {
                Cow::Owned(source_slice(source.text.as_bytes(), &call_span)?.to_owned())
            } else {
                // A provider-resolved token without independently proven call
                // syntax (for example `wrapper!(target)`) is outside the named
                // invocation population. It is neither a call nor an authority
                // exclusion.
                continue;
            };
            if !covered_call_callee_ranges
                .entry(document_path.clone())
                .or_default()
                .insert(byte_range)
            {
                return Err(NormalizationFailure::partial(
                    "provider_call_occurrence_duplicate",
                    format!(
                        "multiple provider occurrences cover call syntax at {}:{byte_range:?}",
                        document_path
                    ),
                ));
            }
            let callee_id = occurrence.provider_symbol_id.clone();
            let callee = if let Some(candidate_ids) = definition_aliases.get(callee_id.as_str()) {
                Cow::Borrowed(resolve_callee_definition(
                    &callee_id,
                    candidate_ids,
                    &definitions,
                    document_path,
                    &call_span,
                )?)
            } else if occurrence.symbol.starts_with("local ") {
                let Some(binding) =
                    resolve_parameter_binding(source, syntax_callee.as_ref(), &call_span)?
                else {
                    return Err(NormalizationFailure::partial(
                        "local_call_target_unresolved",
                        format!(
                            "call at {document_path}:{}-{} ({syntax_callee:?}) resolves to provider-local symbol {} without an admitted definition or unique lexical parameter binding (provider definition occurrence: {})",
                            call_span.start_byte,
                            call_span.end_byte,
                            occurrence.symbol,
                            has_provider_definition_occurrence(occurrences, &callee_id),
                        ),
                    ));
                };
                Cow::Owned(parameter_definition_record(
                    source,
                    document_path,
                    callee_id,
                    syntax_callee.as_ref(),
                    binding,
                )?)
            } else {
                // External and otherwise out-of-population callees are outside
                // this repository-local Calls payload.
                continue;
            };
            if !call_target_kind(spec, callee.provider_kind) {
                if spec.language == "go" && go_conversion_target_kind(callee.provider_kind) {
                    // Go's call-expression grammar also represents explicit
                    // type conversions (`T(value)`). Provider resolution to a
                    // local type is positive evidence that this syntax is not
                    // a function invocation. It covers the syntax population
                    // above but must not emit a Calls edge.
                    continue;
                }
                return Err(NormalizationFailure::partial(
                    "call_target_not_callable",
                    format!(
                        "call at {document_path}:{}-{} resolves to non-callable local symbol {} \
                         defined as {} {:?} at {}:{}-{}",
                        call_span.start_byte,
                        call_span.end_byte,
                        occurrence.symbol,
                        callee.kind,
                        callee.name,
                        callee.document_path,
                        callee.definition.span.start_byte,
                        callee.definition.span.end_byte,
                    ),
                ));
            }
            if rust_constructor_target_kind(spec, callee.provider_kind) {
                // Rust tuple structs and payload-carrying enum variants use
                // call-expression syntax, but they do not own callable source
                // bodies in h00ligan's structural graph. Provider resolution to a
                // Struct or EnumMember is positive evidence that the callee is
                // construction syntax, not unknown function-value dispatch.
                // The syntax range was accounted for above; omit it from the
                // callable invocation payload instead of globally qualifying
                // unrelated negative Calls results.
                continue;
            }
            if spec.language == "rust"
                && callee.provider_kind == symbol_information::Kind::Variable
                && callee.document_path == *document_path
                && source.syntax.direct_closure_bindings.contains(&(
                    callee.definition.span.start_byte as usize,
                    callee.definition.span.end_byte as usize,
                ))
            {
                // A direct, uncoerced Rust closure literal has a unique inferred
                // type. `let mut name = |...| ...` permits an `FnMut` call to
                // change captured state; it does not make the closure body a
                // replaceable function target. Provider resolution back to the
                // exact binding therefore proves this invocation's body identity.
                // Calls inside the closure remain attributed to their enclosing
                // named callable; the self-invocation has no separately queryable
                // structural node.
                continue;
            }
            if callee.structural_span().is_none() && callee.call_owner_span.is_none() {
                // The provider proved an invocation of a local callable value,
                // but no source-backed structural callable owns that value.
                // Preserve the positive call-site evidence while qualifying
                // negative liveness: a runtime assignment may still target a
                // repository function that static provider evidence cannot
                // resolve here.
                coverage_exclusions.insert(ProviderCoverageExclusion {
                    location: ProviderLocation {
                        document_path: document_path.clone(),
                        span: call_span.clone(),
                    },
                    reason_code: "dynamic_callable_target_unresolved".into(),
                });
            }
            let owner_index = definition_owner_indexes.get(document_path);
            let provider_caller = owner_index
                .map_or(Ok(None), |index| index.resolve(&definitions, &call_span))
                .map_err(|()| {
                    NormalizationFailure::partial(
                        "call_owner_ambiguous",
                        format!(
                            "call at {document_path}:{}-{} to {} has multiple equally tight callable owners",
                            call_span.start_byte, call_span.end_byte, occurrence.symbol
                        ),
                    )
                })?;
            let provider_caller = if provider_caller
                .is_some_and(|caller| caller.structural_span().is_none())
            {
                // Nested callable values have exact lexical bodies but are not
                // stable structural query targets. Attribute their explicit
                // source invocations to the tightest published enclosing
                // callable, matching the graph's deliberate granularity.
                // This is the same conservative lexical over-approximation
                // used for branches: it may retain a target, never erase one.
                owner_index
                    .map_or(Ok(None), |index| {
                        index.resolve_published(&definitions, &call_span)
                    })
                    .map_err(|()| {
                        NormalizationFailure::partial(
                            "call_owner_ambiguous",
                            format!(
                                "call at {document_path}:{}-{} to {} has multiple equally tight published callable owners",
                                call_span.start_byte, call_span.end_byte, occurrence.symbol
                            ),
                        )
                    })?
            } else {
                provider_caller
            };
            let caller = if let Some(caller) = provider_caller {
                Cow::Borrowed(caller)
            } else {
                if let Some((start, end)) = source
                    .syntax
                    .enclosing_conditional_range(call_span.start_byte, call_span.end_byte)
                {
                    coverage_exclusions.insert(provider_coverage_exclusion(
                        source,
                        document_path,
                        start,
                        end,
                        "conditional_compilation",
                    )?);
                    continue;
                }
                if !source
                    .syntax
                    .range_has_callable_owner(call_span.start_byte, call_span.end_byte)
                {
                    if callee.structural_span().is_some() {
                        symbols
                            .entry(callee.provider_symbol_id.clone())
                            .or_insert_with(|| provider_symbol(callee.as_ref(), spec.language));
                        root_invocations.push(ProviderRootInvocation {
                            callee_symbol_id: callee.provider_symbol_id.clone(),
                            context: source
                                .syntax
                                .execution_root_context(call_span.start_byte, call_span.end_byte),
                            call_site: ProviderLocation {
                                document_path: document_path.clone(),
                                span: call_span,
                            },
                        });
                    }
                    // A non-structural callee already received an exact dynamic
                    // target exclusion above. Do not add a second, misleading
                    // execution-root diagnosis for the same call site.
                    continue;
                }
                let Some(caller) =
                    structural_call_owner(source, document_path, spec.language, &call_span)?
                else {
                    return Err(NormalizationFailure::partial(
                        "call_owner_unproven",
                        format!(
                            "call at {document_path}:{}-{} to {} has no uniquely enclosing callable definition",
                            call_span.start_byte, call_span.end_byte, occurrence.symbol
                        ),
                    ));
                };
                Cow::Owned(caller)
            };

            if caller.structural_span().is_none() {
                // A nested callable value can be the exact compiler-proven
                // lexical owner of this call while remaining intentionally
                // absent from the structural graph. Do not manufacture a
                // graph caller for runtime-local state. Preserve the scoped
                // uncertainty at the exact call site instead.
                coverage_exclusions.insert(ProviderCoverageExclusion {
                    location: ProviderLocation {
                        document_path: document_path.clone(),
                        span: call_span,
                    },
                    reason_code: "local_callable_caller_unpublished".into(),
                });
                continue;
            }

            symbols
                .entry(caller.provider_symbol_id.clone())
                .or_insert_with(|| provider_symbol(caller.as_ref(), spec.language));
            symbols
                .entry(callee.provider_symbol_id.clone())
                .or_insert_with(|| provider_symbol(callee.as_ref(), spec.language));
            calls.push(ProviderCall {
                caller_symbol_id: caller.provider_symbol_id.clone(),
                callee_symbol_id: callee.provider_symbol_id.clone(),
                call_site: ProviderLocation {
                    document_path: document_path.clone(),
                    span: call_span,
                },
            });
        }
    }
    let call_resolution_duration = call_resolution_started.elapsed();
    let coverage_validation_started = Instant::now();

    for (document_path, source) in &source_documents {
        if !actual_paths.contains(document_path.as_str()) {
            continue;
        }
        if reused_call_documents.contains(document_path) {
            continue;
        }
        let covered = covered_call_callee_ranges
            .get(document_path)
            .cloned()
            .unwrap_or_default();
        let mut missing = Vec::new();
        for (range, callee) in &source.syntax.call_callees {
            if covered.contains(range)
                || (spec.language == "go" && callee.form != NamedCallForm::Direct)
            {
                continue;
            }
            let callee_name = comparable_callee_name(&callee.name);
            let has_lexical_parameter = source_parameter_binding_covers_call(
                source,
                callee_name,
                (range.0 as u64, range.1 as u64),
            );
            let has_local_candidate = if spec.language == "go" {
                go_package_scope(document_path, source)
                    .and_then(|scope| {
                        if is_go_test_document(document_path) {
                            go_package_function_names.get(&scope)
                        } else {
                            go_production_package_function_names.get(&scope)
                        }
                    })
                    .is_some_and(|names| names.contains(callee_name))
            } else {
                local_callable_names_by_document
                    .get(document_path)
                    .is_some_and(|names| names.contains(callee_name))
                    || repository_callable_names.contains(callee_name)
            };
            if !has_lexical_parameter && !has_local_candidate {
                continue;
            }
            if let Some((start, end)) = source
                .syntax
                .enclosing_conditional_range(range.0 as u64, range.1 as u64)
            {
                coverage_exclusions.insert(provider_coverage_exclusion(
                    source,
                    document_path,
                    start,
                    end,
                    "conditional_compilation",
                )?);
            } else if callee.form == NamedCallForm::Method {
                let omission_evidence = MethodOmissionEvidence {
                    document_path,
                    call_range: *range,
                    provider_symbols_by_range: &provider_symbols_by_range,
                    definitions: &definitions,
                    definition_aliases: &definition_aliases,
                    rust_method_witnesses: &rust_method_witnesses,
                };
                match classify_method_omission(spec, callee, &omission_evidence) {
                    MethodOmission::CoveredOutsideSourcePopulation => {}
                    MethodOmission::MissingSourceCall => missing.push(*range),
                    MethodOmission::Unresolved => {
                        coverage_exclusions.insert(provider_coverage_exclusion(
                            source,
                            document_path,
                            range.0 as u64,
                            range.1 as u64,
                            "provider_method_call_unresolved",
                        )?);
                    }
                }
            } else {
                missing.push(*range);
            }
        }
        if !missing.is_empty() {
            return Err(NormalizationFailure::partial(
                "provider_call_occurrence_incomplete",
                format!(
                    "provider occurrence coverage is missing call syntax in {document_path} at {missing:?}"
                ),
            ));
        }
    }
    let coverage_validation_duration = coverage_validation_started.elapsed();
    let payload_finalization_started = Instant::now();

    let receipt_provider_version = admitted_provider_version;
    let input_fingerprint = calls_input_fingerprint(
        spec,
        receipt_provider_version,
        input_configuration_material.unwrap_or(UNCONFIGURED_SCIP_INPUT),
        source_documents
            .values()
            .map(|document| &document.descriptor),
        inventory,
    )?;
    let receipt = CapabilityReceipt::complete(
        "calls",
        spec.provider_id,
        receipt_provider_version,
        scope.clone(),
        input_fingerprint,
    );
    let payload = ProviderPayload::Calls(CallsProviderPayload {
        schema_version: CALLS_PROVIDER_PAYLOAD_SCHEMA.into(),
        population: CallsPopulation::ProviderResolvedExplicitSourceInvocations,
        receipt,
        semantic_inputs: h00ligan_provider_protocol::ProviderSemanticInputs::empty(),
        execution_authority: ProviderExecutionAuthority::InvocationBound {
            provider_configurations_sha256: provider_configurations_sha256
                .cloned()
                .unwrap_or_default(),
        },
        canonical_snapshot_sha256: None,
        documents: source_documents
            .into_values()
            .map(|document| document.descriptor)
            .collect(),
        symbols: symbols.into_values().collect(),
        calls,
        root_invocations,
        callable_bindings,
        coverage_exclusions: coverage_exclusions.into_iter().collect(),
    });
    let payload = normalize_provider_payload_typed(&payload).map_err(|error| {
        NormalizationFailure::unavailable(
            "normalized_payload_invalid",
            format!("normalized Calls payload is invalid: {error}"),
        )
    })?;
    let payload_finalization_duration = payload_finalization_started.elapsed();
    let total_duration = normalization_started.elapsed();
    Ok((
        payload,
        source_syntax_cache,
        ScipNormalizationTimings {
            total: total_duration,
            setup: setup_duration,
            source_validation: source_validation_duration,
            coverage_exclusion_setup: coverage_exclusion_setup_duration,
            occurrence_indexing: occurrence_indexing_duration,
            definition_collection: definition_collection_duration,
            definition_canonicalization: definition_canonicalization_duration,
            binding_and_lookup_indexing: binding_and_lookup_indexing_duration,
            call_resolution: call_resolution_duration,
            coverage_validation: coverage_validation_duration,
            payload_finalization: payload_finalization_duration,
            source_documents: source_document_count,
            syntax_cache_hits,
            provider_documents: documents_by_path.len() as u64,
            provider_document_cache_hits,
            definition_document_cache_hits,
            definition_groups: definition_group_count,
            definition_group_reuse_hits,
            call_documents: provider_occurrences_by_document.len() as u64,
            call_document_reuse_hits: reused_call_documents.len() as u64,
        },
    ))
}

/// Apply independent work concurrently while retaining deterministic input
/// ordering and first-error selection. Rayon preserves the indexed input order
/// when collecting into a `Vec`; resolving that result sequentially makes an
/// earlier source's failure authoritative even if a later worker finishes first.
fn ordered_parallel_try_map<T, U, E, F>(items: &[T], operation: F) -> Result<Vec<U>, E>
where
    T: Sync,
    U: Send,
    E: Send,
    F: Fn(&T) -> Result<U, E> + Sync + Send,
{
    use rayon::prelude::*;

    items
        .par_iter()
        .map(operation)
        .collect::<Vec<_>>()
        .into_iter()
        .collect()
}

fn provider_coverage_exclusion(
    source: &SourceDocument,
    document_path: &str,
    start: u64,
    end: u64,
    reason_code: &str,
) -> Result<ProviderCoverageExclusion, NormalizationFailure> {
    Ok(ProviderCoverageExclusion {
        location: ProviderLocation {
            document_path: document_path.to_owned(),
            span: normalized_source_byte_span(source, document_path, start as usize, end as usize)?,
        },
        reason_code: reason_code.into(),
    })
}

/// Reconstruct only a missing caller identity from exact source syntax. The
/// compiler provider remains authoritative for the call occurrence and callee;
/// this witness supplies the one co-published structural callable whose extent
/// uniquely contains that occurrence.
fn structural_call_owner(
    source: &SourceDocument,
    document_path: &str,
    language: &str,
    call_span: &NormalizedSourceSpan,
) -> Result<Option<DefinitionRecord>, NormalizationFailure> {
    let Some((owner_start, owner_end)) = source
        .syntax
        .call_owner_extents
        .tightest_containing(call_span.start_byte, call_span.end_byte)
    else {
        return Ok(None);
    };
    let owner_start_usize = usize::try_from(owner_start).map_err(|_| {
        NormalizationFailure::unavailable(
            "call_owner_span_invalid",
            format!("call owner start in {document_path} exceeds this platform"),
        )
    })?;
    let owner_end_usize = usize::try_from(owner_end).map_err(|_| {
        NormalizationFailure::unavailable(
            "call_owner_span_invalid",
            format!("call owner end in {document_path} exceeds this platform"),
        )
    })?;
    let mut definition_ranges = source
        .syntax
        .callable_extents
        .iter()
        .filter_map(|(definition, extent)| {
            (*extent == (owner_start_usize, owner_end_usize)).then_some(*definition)
        })
        .collect::<Vec<_>>();
    definition_ranges.sort_unstable();
    definition_ranges.dedup();
    let [definition_range] = definition_ranges.as_slice() else {
        return Ok(None);
    };
    let name = source
        .text
        .get(definition_range.0..definition_range.1)
        .filter(|name| !name.is_empty() && *name != "_")
        .ok_or_else(|| {
            NormalizationFailure::unavailable(
                "call_owner_name_invalid",
                format!("call owner name in {document_path} is not exact UTF-8 source"),
            )
        })?
        .to_owned();
    let definition_span = normalized_source_byte_span(
        source,
        document_path,
        definition_range.0,
        definition_range.1,
    )?;
    let owner_span =
        normalized_source_byte_span(source, document_path, owner_start_usize, owner_end_usize)?;
    let identity_material = format!(
        "h00/structural-call-owner/v1\0{language}\0{document_path}\0{}\0{}",
        definition_range.0, definition_range.1
    );
    Ok(Some(DefinitionRecord {
        provider_symbol_id: format!(
            "h00-structural-call-owner:{}",
            blake3::hash(identity_material.as_bytes()).to_hex()
        ),
        name,
        kind: "function".into(),
        provider_kind: symbol_information::Kind::Function,
        document_path: document_path.into(),
        definition: ProviderLocation {
            document_path: document_path.into(),
            span: definition_span,
        },
        enclosing_span: Some(owner_span.clone()),
        invocation_target_span: None,
        call_owner_span: Some(owner_span),
        value_binding_span: None,
        binding_scope: source
            .syntax
            .binding_scopes
            .get(definition_range)
            .copied()
            .unwrap_or((owner_start, owner_end)),
        callable: true,
        rust_declared_owner: None,
    }))
}

fn unique_provider_symbol_at_range<'a>(
    symbols: &'a ProviderSymbolsByRange,
    document_path: &str,
    range: (usize, usize),
) -> Option<&'a str> {
    let candidates = symbols.get(document_path)?.get(&range)?;
    (candidates.len() == 1)
        .then(|| candidates.first().map(String::as_str))
        .flatten()
}

fn classify_method_omission(
    spec: ScipProviderSpec,
    callee: &SourceCallCallee,
    evidence: &MethodOmissionEvidence<'_>,
) -> MethodOmission {
    match spec.language {
        "rust" => classify_rust_method_omission(callee, evidence),
        "python" if callee.source_local_method_target => MethodOmission::MissingSourceCall,
        "python" => MethodOmission::Unresolved,
        "typescript" => MethodOmission::Unresolved,
        // Other registered providers retain their existing fail-closed
        // behavior until their receiver population has an equivalent exact
        // witness. Go selectors are excluded before this classifier because
        // scip-go's admitted occurrence population is direct calls only.
        _ => MethodOmission::MissingSourceCall,
    }
}

fn classify_rust_method_omission(
    callee: &SourceCallCallee,
    evidence: &MethodOmissionEvidence<'_>,
) -> MethodOmission {
    let Some(receiver_range) = callee.receiver_identity_range else {
        return MethodOmission::Unresolved;
    };
    let Some(receiver_symbol) = unique_provider_symbol_at_range(
        evidence.provider_symbols_by_range,
        evidence.document_path,
        receiver_range,
    ) else {
        return MethodOmission::Unresolved;
    };
    let Some(receiver_definition) = unique_reference_definition(
        receiver_symbol,
        evidence.document_path,
        evidence.call_range,
        evidence.definitions,
        evidence.definition_aliases,
    ) else {
        return MethodOmission::Unresolved;
    };
    let Some(owner) = receiver_definition.rust_declared_owner.as_ref() else {
        return MethodOmission::Unresolved;
    };
    let key = (
        owner.clone(),
        comparable_callee_name(&callee.name).to_owned(),
    );
    let Some(witnesses) = evidence.rust_method_witnesses.get(&key) else {
        return MethodOmission::Unresolved;
    };
    if witnesses.iter().any(|witness| {
        evidence
            .definition_aliases
            .get(witness.as_str())
            .into_iter()
            .flat_map(|canonical_ids| canonical_ids.iter())
            .any(|candidate| {
                evidence
                    .definitions
                    .get(candidate.as_ref())
                    .is_some_and(|definition| definition.callable)
            })
    }) {
        MethodOmission::MissingSourceCall
    } else {
        // The provider knows a method with this exact nominal owner and name,
        // but that method has no repository source-backed callable definition.
        // Covering the syntax without emitting a local Calls edge is therefore
        // exact for h00ligan's explicit-source-invocation population.
        MethodOmission::CoveredOutsideSourcePopulation
    }
}

fn unique_reference_definition<'a>(
    provider_symbol_id: &str,
    document_path: &str,
    call_range: (usize, usize),
    definitions: &'a SharedCanonicalDefinitions,
    definition_aliases: &SharedDefinitionAliases,
) -> Option<&'a DefinitionRecord> {
    let candidates = definition_aliases.get(provider_symbol_id)?;
    let mut matching = candidates.iter().filter_map(|candidate| {
        let definition = definitions.get(candidate.as_ref()).map(Arc::as_ref)?;
        (definition.document_path != document_path
            || (definition.binding_scope.0 <= call_range.0 as u64
                && call_range.1 as u64 <= definition.binding_scope.1))
            .then_some(definition)
    });
    let resolved = matching.next()?;
    matching.next().is_none().then_some(resolved)
}

fn rust_type_owner(symbol: &str) -> Option<RustProviderOwner> {
    let parsed = scip::symbol::parse_symbol(symbol).ok()?;
    let type_index = parsed
        .descriptors
        .iter()
        .rposition(|item| item.suffix.enum_value().ok() == Some(descriptor::Suffix::Type))?;
    rust_owner_from_parts(
        &parsed,
        parsed.descriptors[..=type_index]
            .iter()
            .map(|item| (item.name.clone(), item.suffix.value())),
    )
}

fn rust_method_owner(symbol: &str) -> Option<RustProviderOwner> {
    let parsed = scip::symbol::parse_symbol(symbol).ok()?;
    let method_index = parsed
        .descriptors
        .iter()
        .rposition(|item| item.suffix.enum_value().ok() == Some(descriptor::Suffix::Method))?;
    let owner_descriptors = &parsed.descriptors[..method_index];
    if let Some(impl_index) = owner_descriptors.iter().rposition(|item| {
        item.name == "impl" && item.suffix.enum_value().ok() == Some(descriptor::Suffix::Type)
    }) {
        let self_type = owner_descriptors.get(impl_index + 1)?;
        if self_type.suffix.enum_value().ok() != Some(descriptor::Suffix::TypeParameter) {
            return None;
        }
        let self_name = rust_impl_self_type_name(&self_type.name)?;
        return rust_owner_from_parts(
            &parsed,
            owner_descriptors[..impl_index]
                .iter()
                .map(|item| (item.name.clone(), item.suffix.value()))
                .chain(std::iter::once((
                    self_name,
                    descriptor::Suffix::Type.value(),
                ))),
        );
    }
    let type_index = owner_descriptors
        .iter()
        .rposition(|item| item.suffix.enum_value().ok() == Some(descriptor::Suffix::Type))?;
    rust_owner_from_parts(
        &parsed,
        owner_descriptors[..=type_index]
            .iter()
            .map(|item| (item.name.clone(), item.suffix.value())),
    )
}

fn rust_owner_from_parts(
    symbol: &scip::types::Symbol,
    descriptors: impl IntoIterator<Item = (String, i32)>,
) -> Option<RustProviderOwner> {
    let package = symbol.package.as_ref()?;
    Some(RustProviderOwner {
        scheme: symbol.scheme.clone(),
        package_manager: package.manager.clone(),
        package_name: package.name.clone(),
        package_version: package.version.clone(),
        descriptors: descriptors.into_iter().collect(),
    })
}

fn rust_impl_self_type_name(raw: &str) -> Option<String> {
    let raw = raw.trim_matches('`').trim();
    let base = raw.split('<').next()?.trim();
    let terminal = base.rsplit("::").next()?.trim();
    (!terminal.is_empty()).then(|| comparable_callee_name(terminal).to_owned())
}

fn definition_records_by_base_id(records: &[DefinitionRecord]) -> SharedDefinitionRecordsByBaseId {
    let mut grouped = BTreeMap::<String, Vec<Arc<DefinitionRecord>>>::new();
    for record in records {
        grouped
            .entry(record.provider_symbol_id.clone())
            .or_default()
            .push(Arc::new(record.clone()));
    }
    grouped
        .into_iter()
        .map(|(base_id, records)| (Arc::from(base_id), Arc::from(records)))
        .collect()
}

fn shared_canonical_definitions(
    definitions: BTreeMap<String, DefinitionRecord>,
) -> SharedCanonicalDefinitions {
    definitions
        .into_iter()
        .map(|(canonical_id, definition)| (Arc::from(canonical_id), Arc::new(definition)))
        .collect()
}

fn shared_definition_aliases(aliases: BTreeMap<String, Vec<String>>) -> SharedDefinitionAliases {
    aliases
        .into_iter()
        .map(|(base_id, canonical_ids)| {
            (
                Arc::from(base_id),
                Arc::from(
                    canonical_ids
                        .into_iter()
                        .map(Arc::<str>::from)
                        .collect::<Vec<_>>(),
                ),
            )
        })
        .collect()
}

fn refresh_definition_records_by_base_id(
    prior: &Arc<SharedDefinitionRecordsByBaseId>,
    affected_documents: &BTreeSet<String>,
    affected_base_ids: &BTreeSet<String>,
    mut current_affected_records: BTreeMap<String, Vec<DefinitionRecord>>,
) -> Arc<SharedDefinitionRecordsByBaseId> {
    let mut refreshed = Arc::clone(prior);
    let records_by_base_id = Arc::make_mut(&mut refreshed);
    for base_id in affected_base_ids {
        let mut replacement_records = records_by_base_id
            .get(base_id.as_str())
            .into_iter()
            .flat_map(|records| records.iter())
            .filter(|record| !affected_documents.contains(&record.document_path))
            .cloned()
            .collect::<Vec<_>>();
        replacement_records.extend(
            current_affected_records
                .remove(base_id)
                .unwrap_or_default()
                .into_iter()
                .map(Arc::new),
        );
        if replacement_records.is_empty() {
            records_by_base_id.remove(base_id.as_str());
        } else {
            records_by_base_id.insert(Arc::from(base_id.clone()), Arc::from(replacement_records));
        }
    }
    debug_assert!(
        current_affected_records.is_empty(),
        "every current affected definition must contribute its base identity"
    );
    refreshed
}

fn canonicalize_definition_records(
    mut records: Vec<DefinitionRecord>,
) -> Result<CanonicalDefinitionGroups, NormalizationFailure> {
    records.sort_by(|left, right| {
        left.provider_symbol_id
            .cmp(&right.provider_symbol_id)
            .then_with(|| left.document_path.cmp(&right.document_path))
            .then_with(|| {
                left.definition
                    .span
                    .start_byte
                    .cmp(&right.definition.span.start_byte)
            })
            .then_with(|| {
                left.definition
                    .span
                    .end_byte
                    .cmp(&right.definition.span.end_byte)
            })
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.name.cmp(&right.name))
    });
    let mut definitions = BTreeMap::new();
    let mut aliases = BTreeMap::new();
    let mut records = records.into_iter().peekable();
    while let Some(first) = records.next() {
        #[cfg(test)]
        DEFINITION_GROUP_CANONICALIZATION_COUNT.with(|count| count.set(count.get() + 1));
        let base_id = first.provider_symbol_id.clone();
        let mut group = vec![first];
        while records
            .peek()
            .is_some_and(|record| record.provider_symbol_id == base_id)
        {
            group.push(records.next().expect("peeked definition record"));
        }
        group.dedup();
        if group.len() == 1 {
            let mut record = group.pop().expect("one definition record");
            record.provider_symbol_id = base_id.clone();
            definitions.insert(base_id.clone(), record);
            aliases.insert(base_id.clone(), vec![base_id]);
            continue;
        }
        if group
            .iter()
            .all(|record| !record.source_invocation_target())
        {
            let mut record = group.remove(0);
            record.provider_symbol_id = base_id.clone();
            definitions.insert(base_id.clone(), record);
            aliases.insert(base_id.clone(), vec![base_id]);
            continue;
        }
        if group
            .iter()
            .any(|record| !record.source_invocation_target())
            || group.iter().enumerate().any(|(index, left)| {
                group.iter().skip(index + 1).any(|right| {
                    left.document_path == right.document_path
                        && scopes_overlap(left.binding_scope, right.binding_scope)
                })
            })
        {
            let locations = group
                .iter()
                .map(|record| {
                    format!(
                        "{}:{}-{}",
                        record.document_path,
                        record.definition.span.start_byte,
                        record.definition.span.end_byte
                    )
                })
                .collect::<Vec<_>>();
            return Err(NormalizationFailure::unavailable(
                "provider_definition_duplicate",
                format!(
                    "multiple unresolved definitions claim provider symbol {base_id}: {locations:?}"
                ),
            ));
        }

        let mut canonical_ids = Vec::with_capacity(group.len());
        for mut record in group {
            let canonical_id = format!(
                "{base_id}@{}:{}-{}",
                record.document_path,
                record.definition.span.start_byte,
                record.definition.span.end_byte
            );
            record.provider_symbol_id = canonical_id.clone();
            definitions.insert(canonical_id.clone(), record);
            canonical_ids.push(canonical_id);
        }
        aliases.insert(base_id, canonical_ids);
    }
    Ok((definitions, aliases))
}

const fn scopes_overlap(left: (u64, u64), right: (u64, u64)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

fn source_parameter_binding_covers_call(
    source: &SourceDocument,
    callee_name: &str,
    call_range: (u64, u64),
) -> bool {
    source
        .syntax
        .parameter_bindings
        .get(callee_name)
        .into_iter()
        .flatten()
        .any(|binding| binding.scope.0 <= call_range.0 && call_range.1 <= binding.scope.1)
}

fn resolve_parameter_binding(
    source: &SourceDocument,
    callee_name: &str,
    call_span: &NormalizedSourceSpan,
) -> Result<Option<SourceParameterBinding>, NormalizationFailure> {
    let candidates = source
        .syntax
        .parameter_bindings
        .get(comparable_callee_name(callee_name))
        .into_iter()
        .flatten()
        .copied()
        .filter(|binding| {
            binding.scope.0 <= call_span.start_byte && call_span.end_byte <= binding.scope.1
        })
        .collect::<Vec<_>>();
    let Some(minimum_scope_length) = candidates
        .iter()
        .map(|binding| binding.scope.1 - binding.scope.0)
        .min()
    else {
        return Ok(None);
    };
    let nearest = candidates
        .into_iter()
        .filter(|binding| binding.scope.1 - binding.scope.0 == minimum_scope_length)
        .collect::<Vec<_>>();
    match nearest.as_slice() {
        [binding] => Ok(Some(*binding)),
        _ => Err(NormalizationFailure::partial(
            "local_call_target_ambiguous",
            format!(
                "call at {}-{} to {callee_name:?} has multiple equally-near lexical parameter bindings",
                call_span.start_byte, call_span.end_byte
            ),
        )),
    }
}

fn parameter_definition_record(
    source: &SourceDocument,
    document_path: &str,
    provider_symbol_id: String,
    name: &str,
    binding: SourceParameterBinding,
) -> Result<DefinitionRecord, NormalizationFailure> {
    let definition_span = normalized_source_byte_span(
        source,
        document_path,
        binding.definition_range.0,
        binding.definition_range.1,
    )?;
    Ok(DefinitionRecord {
        provider_symbol_id,
        name: comparable_callee_name(name).to_owned(),
        kind: kind_name(symbol_information::Kind::Parameter),
        provider_kind: symbol_information::Kind::Parameter,
        document_path: document_path.to_owned(),
        definition: ProviderLocation {
            document_path: document_path.to_owned(),
            span: definition_span,
        },
        enclosing_span: None,
        invocation_target_span: None,
        call_owner_span: None,
        value_binding_span: None,
        binding_scope: binding.scope,
        callable: false,
        rust_declared_owner: None,
    })
}

fn resolve_callee_definition<'a>(
    base_id: &str,
    candidate_ids: &[Arc<str>],
    definitions: &'a SharedCanonicalDefinitions,
    document_path: &str,
    call_span: &NormalizedSourceSpan,
) -> Result<&'a DefinitionRecord, NormalizationFailure> {
    if candidate_ids.len() == 1 {
        return Ok(definitions
            .get(candidate_ids[0].as_ref())
            .map(Arc::as_ref)
            .expect("definition alias references a canonical definition"));
    }
    let candidates = candidate_ids
        .iter()
        .filter_map(|candidate_id| definitions.get(candidate_id.as_ref()).map(Arc::as_ref))
        .filter(|candidate| {
            candidate.document_path == document_path
                && candidate.binding_scope.0 <= call_span.start_byte
                && call_span.end_byte <= candidate.binding_scope.1
        })
        .collect::<Vec<_>>();
    if let [candidate] = candidates.as_slice() {
        return Ok(*candidate);
    }
    Err(NormalizationFailure::unavailable(
        "provider_reference_ambiguous",
        format!(
            "call occurrence cannot select one lexical definition for provider symbol {base_id}"
        ),
    ))
}

fn file_uri_path(uri: &str) -> Result<PathBuf, NormalizationFailure> {
    let encoded = uri.strip_prefix("file://").ok_or_else(|| {
        NormalizationFailure::unavailable(
            "provider_root_uri_invalid",
            "SCIP project root is not a file URI",
        )
    })?;
    if !encoded.starts_with('/') || encoded.contains(['?', '#']) {
        return Err(NormalizationFailure::unavailable(
            "provider_root_uri_invalid",
            "SCIP project root file URI is not an absolute local path",
        ));
    }
    let bytes = percent_decode(encoded.as_bytes())?;
    let decoded = String::from_utf8(bytes).map_err(|error| {
        NormalizationFailure::unavailable(
            "provider_root_uri_invalid",
            format!("SCIP project root is not UTF-8: {error}"),
        )
    })?;
    Ok(PathBuf::from(decoded))
}

fn percent_decode(encoded: &[u8]) -> Result<Vec<u8>, NormalizationFailure> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] != b'%' {
            decoded.push(encoded[index]);
            index += 1;
            continue;
        }
        if index + 2 >= encoded.len() {
            return Err(NormalizationFailure::unavailable(
                "provider_root_uri_invalid",
                "SCIP project root contains a truncated percent escape",
            ));
        }
        let high = hex_nibble(encoded[index + 1]);
        let low = hex_nibble(encoded[index + 2]);
        let Some((high, low)) = high.zip(low) else {
            return Err(NormalizationFailure::unavailable(
                "provider_root_uri_invalid",
                "SCIP project root contains an invalid percent escape",
            ));
        };
        let byte = (high << 4) | low;
        if byte == 0 {
            return Err(NormalizationFailure::unavailable(
                "provider_root_uri_invalid",
                "SCIP project root contains an encoded NUL",
            ));
        }
        decoded.push(byte);
        index += 3;
    }
    Ok(decoded)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn source_call_evidence(
    source: &str,
    relative_path: &str,
    language: &str,
) -> Result<SourceSyntaxEvidence, NormalizationFailure> {
    let extension = Path::new(relative_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .ok_or_else(|| {
            NormalizationFailure::unavailable(
                "language_syntax_unavailable",
                format!("indexed source {relative_path} has no extension"),
            )
        })?;
    let extractor = crate::language::extractor_for_extension(extension).ok_or_else(|| {
        NormalizationFailure::unavailable(
            "language_syntax_unavailable",
            format!("no registered syntax adapter for {relative_path}"),
        )
    })?;
    if extractor.language() != language {
        return Err(NormalizationFailure::unavailable(
            "language_syntax_mismatch",
            format!(
                "registered syntax for {relative_path} is {}, expected {language}",
                extractor.language()
            ),
        ));
    }
    let tree = extractor
        .parse_admitted_tree(source, relative_path)
        .map_err(|error| match error {
            crate::structural_ir::ExtractorError::IncompleteSyntax { .. } => {
                NormalizationFailure::partial(
                    "language_parse_incomplete",
                    format!("indexed source {relative_path} contains syntax errors: {error}"),
                )
            }
            crate::structural_ir::ExtractorError::LanguageError(_) => {
                NormalizationFailure::unavailable(
                    "language_syntax_unavailable",
                    format!("cannot load syntax for {relative_path}: {error}"),
                )
            }
            _ => NormalizationFailure::unavailable(
                "language_parse_failed",
                format!("cannot parse indexed source {relative_path}: {error}"),
            ),
        })?;
    let go_package_name = if language == "go" {
        Some(go_package_name(tree.root_node(), source).ok_or_else(|| {
            NormalizationFailure::unavailable(
                "go_package_unavailable",
                format!("indexed Go source {relative_path} has no package clause"),
            )
        })?)
    } else {
        None
    };
    let mut census = SourceSyntaxCensus::new(source, language, extractor);
    census.visit(tree.root_node(), tree.root_node());
    let SourceSyntaxCensus {
        call_callees,
        definition_contexts,
        callable_binding_targets,
        parameter_bindings,
        conditional_ranges,
        generated_ranges,
        ..
    } = census;
    Ok(SourceSyntaxEvidence {
        call_callees,
        local_callable_names: definition_contexts.local_callable_names,
        local_invocation_target_names: definition_contexts.local_invocation_target_names,
        go_package_name,
        go_package_function_names: definition_contexts.go_package_function_names,
        binding_scopes: definition_contexts.binding_scopes,
        callable_extents: definition_contexts.callable_extents,
        non_structural_callable_definitions: definition_contexts
            .non_structural_callable_definitions,
        invocation_target_extents: definition_contexts.invocation_target_extents,
        value_binding_extents: definition_contexts.value_binding_extents,
        callable_binding_targets,
        direct_closure_bindings: definition_contexts.direct_closure_bindings,
        call_owner_extents: SourceRangeIndex::from_usize(definition_contexts.call_owner_extents),
        anonymous_callable_extents: SourceRangeIndex::from_usize(
            definition_contexts.anonymous_callable_extents,
        ),
        declared_type_names: definition_contexts.declared_type_names,
        parameter_bindings,
        conditional_ranges: SourceRangeIndex::new(conditional_ranges),
        generated_ranges: SourceRangeIndex::new(generated_ranges),
    })
}

fn collect_go_callable_binding_targets_at_node(
    node: Node<'_>,
    language: &str,
    targets: &mut SourceCallableBindingTargets,
) {
    if language == "go"
        && node.kind() == "var_spec"
        && !has_ancestor_kind(node, "block")
        && let Some(values) = node.child_by_field_name("value")
    {
        let mut name_cursor = node.walk();
        for (index, name) in node
            .children_by_field_name("name", &mut name_cursor)
            .enumerate()
        {
            let Some(index) = u32::try_from(index).ok() else {
                continue;
            };
            let Some(value) = values.named_child(index) else {
                continue;
            };
            let Some(target) = go_callable_value_target(value) else {
                continue;
            };
            targets.insert(
                (target.start_byte(), target.end_byte()),
                (name.start_byte(), name.end_byte()),
            );
        }
    }
}

fn has_ancestor_kind(node: Node<'_>, kind: &str) -> bool {
    let mut ancestor = node.parent();
    while let Some(candidate) = ancestor {
        if candidate.kind() == kind {
            return true;
        }
        ancestor = candidate.parent();
    }
    false
}

fn go_package_name(root: Node<'_>, source: &str) -> Option<String> {
    let mut cursor = root.walk();
    let package_clause = root
        .named_children(&mut cursor)
        .find(|child| child.kind() == "package_clause")?;
    let package = package_clause.named_child(0)?;
    (package.kind() == "package_identifier")
        .then(|| source.get(package.start_byte()..package.end_byte()))
        .flatten()
        .map(ToOwned::to_owned)
}

fn collect_call_callee_at_node(
    node: Node<'_>,
    source: &str,
    extractor: &dyn crate::language::LanguageExtractor,
    callees: &mut SourceCallCallees,
) {
    if let Some(call) = extractor.named_call_syntax(node) {
        let range = (call.callee.start_byte(), call.callee.end_byte());
        if let Some(name) = source.get(range.0..range.1) {
            let receiver_identity_range = call
                .receiver_identity
                .map(|receiver| (receiver.start_byte(), receiver.end_byte()));
            let source_local_method_target = extractor.language() == "python"
                && call.form == NamedCallForm::Method
                && call.receiver_identity.is_some_and(|receiver| {
                    python_bound_receiver_declares_method(node, receiver, call.callee, source)
                });
            callees.insert(
                range,
                SourceCallCallee {
                    name: name.to_owned(),
                    form: call.form,
                    receiver_identity_range,
                    source_local_method_target,
                },
            );
        }
    }
}

/// Return a narrow source witness that a Python selector is aimed at a method
/// declared directly on the same class as its bound receiver. This does not
/// claim complete Python runtime dispatch; it only identifies syntax Pyrefly's
/// repository-reference contract is expected to cover. Arbitrary objects,
/// chained attributes, inherited members, aliases, and shadowed receivers stay
/// unresolved and become scoped coverage exclusions rather than global loss.
fn python_bound_receiver_declares_method(
    call: Node<'_>,
    receiver: Node<'_>,
    callee: Node<'_>,
    source: &str,
) -> bool {
    if receiver.kind() != "identifier" || callee.kind() != "identifier" {
        return false;
    }
    let Some(receiver_name) = source.get(receiver.start_byte()..receiver.end_byte()) else {
        return false;
    };
    let Some(method_name) = source.get(callee.start_byte()..callee.end_byte()) else {
        return false;
    };

    let mut ancestor = call.parent();
    while let Some(candidate) = ancestor {
        if candidate.kind() == "function_definition"
            && python_function_bound_receiver(candidate, source) == Some(receiver_name)
            && let Some(class) = python_direct_class_owner(candidate)
        {
            return python_class_declares_method(class, method_name, source);
        }
        ancestor = candidate.parent();
    }
    false
}

fn python_function_bound_receiver<'source>(
    function: Node<'_>,
    source: &'source str,
) -> Option<&'source str> {
    if python_function_has_staticmethod_decorator(function, source) {
        return None;
    }
    let parameters = function.child_by_field_name("parameters")?;
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .find_map(python_parameter_binding_identifier)
        .and_then(|identifier| source.get(identifier.start_byte()..identifier.end_byte()))
}

fn python_parameter_binding_identifier(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "identifier" {
        return Some(node);
    }
    if let Some(name) = node.child_by_field_name("name") {
        return python_parameter_binding_identifier(name);
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .next()
        .and_then(python_parameter_binding_identifier)
}

fn python_function_has_staticmethod_decorator(function: Node<'_>, source: &str) -> bool {
    let Some(decorated) = function
        .parent()
        .filter(|parent| parent.kind() == "decorated_definition")
    else {
        return false;
    };
    let mut cursor = decorated.walk();
    decorated
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "decorator")
        .filter_map(|decorator| source.get(decorator.start_byte()..decorator.end_byte()))
        .map(|decorator| {
            decorator
                .chars()
                .filter(|character| !character.is_whitespace())
        })
        .map(Iterator::collect::<String>)
        .any(|decorator| decorator == "@staticmethod" || decorator.ends_with(".staticmethod"))
}

fn python_direct_class_owner(function: Node<'_>) -> Option<Node<'_>> {
    let declaration = function
        .parent()
        .filter(|parent| parent.kind() == "decorated_definition")
        .unwrap_or(function);
    let body = declaration
        .parent()
        .filter(|parent| parent.kind() == "block")?;
    body.parent()
        .filter(|parent| parent.kind() == "class_definition")
}

fn python_class_declares_method(class: Node<'_>, method_name: &str, source: &str) -> bool {
    let Some(body) = class.child_by_field_name("body") else {
        return false;
    };
    let mut cursor = body.walk();
    body.named_children(&mut cursor).any(|declaration| {
        let function = if declaration.kind() == "function_definition" {
            Some(declaration)
        } else if declaration.kind() == "decorated_definition" {
            declaration
                .child_by_field_name("definition")
                .filter(|definition| definition.kind() == "function_definition")
        } else {
            None
        };
        function
            .and_then(|function| function.child_by_field_name("name"))
            .and_then(|name| source.get(name.start_byte()..name.end_byte()))
            == Some(method_name)
    })
}

/// Tree-sitter deliberately treats a Rust macro's token tree as opaque, so it
/// cannot corroborate calls within that region. Admit only the narrow lexical
/// shape whose meaning is visible without expanding the macro: the exact
/// provider-resolved callee token is followed solely by Rust trivia and then
/// an argument-list opener. Bare callable tokens remain outside the named
/// Calls population.
fn rust_macro_occurrence_has_explicit_arguments(
    source: &[u8],
    occurrence_end: u64,
    generated_end: u64,
) -> bool {
    let Ok(cursor) = usize::try_from(occurrence_end) else {
        return false;
    };
    let Ok(limit) = usize::try_from(generated_end) else {
        return false;
    };
    if cursor > limit || limit > source.len() {
        return false;
    }
    skip_rust_trivia(source, cursor, limit)
        .filter(|cursor| *cursor < limit)
        .and_then(|cursor| source.get(cursor))
        .is_some_and(|byte| *byte == b'(')
}

fn skip_rust_trivia(source: &[u8], mut cursor: usize, limit: usize) -> Option<usize> {
    loop {
        let before = cursor;
        while cursor < limit {
            let remaining = std::str::from_utf8(source.get(cursor..limit)?).ok()?;
            let character = remaining.chars().next()?;
            if !character.is_whitespace() {
                break;
            }
            cursor += character.len_utf8();
        }
        let bounded = source.get(cursor..limit)?;
        if bounded.starts_with(b"//") {
            cursor += 2;
            while cursor < limit && source[cursor] != b'\n' {
                cursor += 1;
            }
            continue;
        }
        if bounded.starts_with(b"/*") {
            cursor += 2;
            let mut depth = 1_usize;
            while cursor < limit && depth > 0 {
                let bounded = source.get(cursor..limit)?;
                if bounded.starts_with(b"/*") {
                    depth += 1;
                    cursor += 2;
                } else if bounded.starts_with(b"*/") {
                    depth -= 1;
                    cursor += 2;
                } else {
                    cursor += 1;
                }
            }
            if depth != 0 {
                return None;
            }
            continue;
        }
        if cursor == before {
            return Some(cursor);
        }
    }
}

fn collect_definition_context_at_node(
    node: Node<'_>,
    root: Node<'_>,
    source: &str,
    language: &str,
    extractor: &dyn crate::language::LanguageExtractor,
    contexts: &mut SourceDefinitionContexts,
) {
    if extractor
        .anonymous_callable_declaration_kinds()
        .contains(&node.kind())
    {
        contexts
            .anonymous_callable_extents
            .insert((node.start_byte(), node.end_byte()));
    }
    let named_callable = extractor.named_callable_syntax(node);
    let definition_range = (node.start_byte(), node.end_byte());
    let invocation_target_extent = python_class_invocation_target_extent(node, language);
    if matches!(node.kind(), "identifier" | "field_identifier")
        || named_callable.is_some()
        || invocation_target_extent.is_some()
    {
        let mut binding = None;
        let go_function_literal_owner = (language == "go"
            && node.kind() == "identifier"
            && node.parent().is_some_and(|parent| {
                crate::language::go::var_name_binds_function_literal(parent, node)
            }))
        .then(|| node.parent().expect("validated Go var_spec parent"));
        let mut go_package_function =
            go_function_literal_owner.is_some_and(|owner| !has_ancestor_kind(owner, "block"));
        let mut callable_extent = if let Some(owner) = go_function_literal_owner {
            let extent = (owner.start_byte(), owner.end_byte());
            contexts.call_owner_extents.insert(extent);
            Some(extent)
        } else {
            None
        };
        if callable_extent.is_none()
            && let Some(callable) = named_callable
        {
            callable_extent = Some(callable.extent);
            go_package_function |= language == "go" && callable.is_package_function;
            if !callable.structural_target {
                contexts
                    .non_structural_callable_definitions
                    .insert(definition_range);
            }
            if callable.has_body {
                contexts.call_owner_extents.insert(callable.extent);
            }
        }
        let mut ancestor = node.parent();
        while let Some(candidate) = ancestor {
            if binding.is_none() && candidate.kind() == "block" {
                binding = Some((candidate.start_byte() as u64, candidate.end_byte() as u64));
            }
            if binding.is_some() && callable_extent.is_some() {
                break;
            }
            ancestor = candidate.parent();
        }
        if let Some(extent) = invocation_target_extent {
            contexts
                .invocation_target_extents
                .insert(definition_range, extent);
            if let Some(name) = source.get(definition_range.0..definition_range.1)
                && !name.is_empty()
            {
                contexts
                    .local_invocation_target_names
                    .insert(comparable_callee_name(name).to_owned());
            }
        }
        if language == "rust"
            && let Some(type_name) = rust_declared_type_name(node)
        {
            contexts.declared_type_names.insert(
                definition_range,
                (type_name.start_byte(), type_name.end_byte()),
            );
        }
        if language == "rust" && rust_identifier_binds_direct_closure(node) {
            contexts.direct_closure_bindings.insert(definition_range);
        }
        if language == "go"
            && node.kind() == "identifier"
            && node.parent().is_some_and(|parent| {
                parent.kind() == "var_spec"
                    && parent
                        .children_by_field_name("name", &mut parent.walk())
                        .any(|name| {
                            name.start_byte() == node.start_byte()
                                && name.end_byte() == node.end_byte()
                        })
            })
        {
            let owner = node.parent().expect("validated Go var_spec parent");
            contexts
                .value_binding_extents
                .insert(definition_range, (owner.start_byte(), owner.end_byte()));
        }
        contexts.binding_scopes.insert(
            definition_range,
            binding.unwrap_or_else(|| (root.start_byte() as u64, root.end_byte() as u64)),
        );
        if let Some(callable_extent) = callable_extent {
            contexts
                .callable_extents
                .insert(definition_range, callable_extent);
            if let Some(name) = source.get(definition_range.0..definition_range.1)
                && !name.is_empty()
                && name != "_"
                && (language != "go" || !has_ancestor_kind(node, "block"))
            {
                let name = comparable_callee_name(name).to_owned();
                contexts.local_callable_names.insert(name.clone());
                if go_package_function {
                    contexts.go_package_function_names.insert(name);
                }
            }
        }
    }
}

fn python_class_invocation_target_extent(node: Node<'_>, language: &str) -> Option<(usize, usize)> {
    if language != "python" || node.kind() != "identifier" {
        return None;
    }
    let class = node
        .parent()
        .filter(|parent| parent.kind() == "class_definition")?;
    let name = class.child_by_field_name("name")?;
    (name.start_byte() == node.start_byte() && name.end_byte() == node.end_byte())
        .then_some((class.start_byte(), class.end_byte()))
}

fn rust_declared_type_name(identifier: Node<'_>) -> Option<Node<'_>> {
    let parent = identifier.parent()?;
    let is_named_field = parent.kind() == "field_declaration"
        && parent.child_by_field_name("name").is_some_and(|name| {
            name.start_byte() == identifier.start_byte() && name.end_byte() == identifier.end_byte()
        });
    let is_direct_binding = matches!(parent.kind(), "parameter" | "let_declaration")
        && parent
            .child_by_field_name("pattern")
            .is_some_and(|pattern| {
                pattern.start_byte() == identifier.start_byte()
                    && pattern.end_byte() == identifier.end_byte()
            });
    if !is_named_field && !is_direct_binding {
        return None;
    }
    rust_outer_nominal_type_name(parent.child_by_field_name("type")?)
}

fn rust_outer_nominal_type_name(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "type_identifier" | "primitive_type" => Some(node),
        "scoped_type_identifier" => node.child_by_field_name("name"),
        "generic_type" => node
            .child_by_field_name("type")
            .and_then(rust_outer_nominal_type_name),
        "reference_type" | "pointer_type" | "parenthesized_type" => {
            node.named_child(0).and_then(rust_outer_nominal_type_name)
        }
        _ => None,
    }
}

fn rust_identifier_binds_direct_closure(identifier: Node<'_>) -> bool {
    if identifier.kind() != "identifier" {
        return false;
    }
    let Some(parent) = identifier.parent() else {
        return false;
    };
    let declaration = if parent.kind() == "let_declaration" {
        parent
    } else if parent.kind() == "mutable_pattern" {
        let Some(declaration) = parent.parent() else {
            return false;
        };
        if declaration.kind() != "let_declaration" {
            return false;
        }
        declaration
    } else {
        return false;
    };
    let Some(pattern) = declaration.child_by_field_name("pattern") else {
        return false;
    };
    let direct_identifier = if pattern.kind() == "identifier" {
        pattern.start_byte() == identifier.start_byte()
            && pattern.end_byte() == identifier.end_byte()
    } else if pattern.kind() == "mutable_pattern" && parent.kind() == "mutable_pattern" {
        let mut cursor = pattern.walk();
        let identifiers = pattern
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "identifier")
            .collect::<Vec<_>>();
        identifiers.len() == 1
            && identifiers[0].start_byte() == identifier.start_byte()
            && identifiers[0].end_byte() == identifier.end_byte()
    } else {
        false
    };
    direct_identifier
        && declaration.child_by_field_name("type").is_none()
        && declaration
            .child_by_field_name("value")
            .is_some_and(|value| value.kind() == "closure_expression")
}

fn collect_parameter_bindings_at_node(
    node: Node<'_>,
    root: Node<'_>,
    source: &str,
    language: &str,
    bindings: &mut SourceParameterBindings,
) {
    match (language, node.kind()) {
        ("rust", "parameter") => {
            if let Some(pattern) = node.child_by_field_name("pattern")
                && pattern.kind() == "identifier"
            {
                record_parameter_binding(pattern, node, root, source, bindings);
            }
        }
        ("go", "parameter_declaration" | "variadic_parameter_declaration") => {
            let type_range = node
                .child_by_field_name("type")
                .map(|r#type| (r#type.start_byte(), r#type.end_byte()));
            let mut cursor = node.walk();
            for identifier in node
                .named_children(&mut cursor)
                .filter(|child| child.kind() == "identifier")
                .filter(|child| {
                    type_range.is_none_or(|(start, end)| {
                        child.start_byte() < start || end < child.end_byte()
                    })
                })
            {
                record_parameter_binding(identifier, node, root, source, bindings);
            }
        }
        _ => {}
    }
}

fn record_parameter_binding(
    identifier: Node<'_>,
    parameter: Node<'_>,
    root: Node<'_>,
    source: &str,
    bindings: &mut SourceParameterBindings,
) {
    let definition_range = (identifier.start_byte(), identifier.end_byte());
    let Some(name) = source.get(definition_range.0..definition_range.1) else {
        return;
    };
    let scope = enclosing_body_scope(parameter, root);
    let binding = SourceParameterBinding {
        definition_range,
        scope,
    };
    let entries = bindings
        .entry(comparable_callee_name(name).to_owned())
        .or_default();
    if !entries.contains(&binding) {
        entries.push(binding);
    }
}

fn enclosing_body_scope(node: Node<'_>, root: Node<'_>) -> (u64, u64) {
    let mut ancestor = node.parent();
    while let Some(candidate) = ancestor {
        if let Some(body) = candidate.child_by_field_name("body") {
            return (body.start_byte() as u64, body.end_byte() as u64);
        }
        ancestor = candidate.parent();
    }
    (root.start_byte() as u64, root.end_byte() as u64)
}

fn collect_conditional_range_at_node(
    node: Node<'_>,
    source: &str,
    language: &str,
    ranges: &mut SourceConditionalRanges,
) {
    if language == "rust"
        && node.kind() != "attribute_item"
        && rust_node_has_cfg_attribute(node, source)
    {
        ranges.insert((node.start_byte() as u64, node.end_byte() as u64));
    }
}

fn collect_generated_range_at_node(
    node: Node<'_>,
    language: &str,
    ranges: &mut SourceGeneratedRanges,
) {
    if language == "rust" && node.kind() == "macro_invocation" {
        ranges.insert((node.start_byte() as u64, node.end_byte() as u64));
    }
}

fn rust_node_has_cfg_attribute(node: Node<'_>, source: &str) -> bool {
    let mut sibling = node.prev_named_sibling();
    while let Some(attribute) = sibling {
        if attribute.kind() != "attribute_item" {
            break;
        }
        if source
            .get(attribute.start_byte()..attribute.end_byte())
            .is_some_and(is_cfg_controlling_attribute)
        {
            return true;
        }
        sibling = attribute.prev_named_sibling();
    }
    false
}

fn is_cfg_controlling_attribute(attribute: &str) -> bool {
    let compact = attribute
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    compact.starts_with("#[cfg(")
        || (compact.starts_with("#[cfg_attr(") && compact.contains(",cfg("))
}

fn comparable_callee_name(name: &str) -> &str {
    name.strip_prefix("r#").unwrap_or(name)
}

fn go_callable_value_target(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" | "field_identifier" => Some(node),
        "selector_expression" => node.child_by_field_name("field"),
        "parenthesized_expression" => node.named_child(0).and_then(go_callable_value_target),
        _ => None,
    }
}

#[cfg(test)]
fn normalized_span(
    document: &Document,
    source: &[u8],
    range: &[i32],
) -> Result<NormalizedSourceSpan, NormalizationFailure> {
    let encoding = required_position_encoding(document)?;
    normalized_span_with_encoding(document, source, range, encoding)
}

/// Resolve the position contract of a provider whose exact identity was
/// already validated from the artifact metadata.
///
/// `scip-go` 0.2.7 (the current upstream release) emits Go `token.Position`
/// columns but leaves the SCIP field unset. Go defines those columns as byte
/// counts, and SCIP prescribes UTF-8 byte offsets for Go producers. Admit that
/// one exact provider contract; every other omitted or unknown encoding remains
/// invalid so an ambiguous artifact cannot gain Calls authority.
fn normalized_provider_span(
    spec: ScipProviderSpec,
    provider_version: &str,
    document: &Document,
    source: &SourceDocument,
    range: &[i32],
) -> Result<NormalizedSourceSpan, NormalizationFailure> {
    #[cfg(test)]
    PROVIDER_SPAN_NORMALIZATION_COUNT.with(|count| count.set(count.get() + 1));

    let encoding = match declared_position_encoding(document)? {
        PositionEncoding::UnspecifiedPositionEncoding
            if spec == ScipProviderSpec::scip_go()
                && provider_version == SCIP_GO_UNSPECIFIED_POSITION_ENCODING_VERSION =>
        {
            PositionEncoding::UTF8CodeUnitOffsetFromLineStart
        }
        PositionEncoding::UnspecifiedPositionEncoding => {
            return Err(unspecified_position_encoding(document));
        }
        encoding => encoding,
    };
    normalized_span_with_encoding_and_lines(
        document,
        source.text.as_bytes(),
        &source.line_ranges,
        range,
        encoding,
    )
}

fn declared_position_encoding(
    document: &Document,
) -> Result<PositionEncoding, NormalizationFailure> {
    document.position_encoding.enum_value().map_err(|value| {
        NormalizationFailure::unavailable(
            "provider_position_encoding_unknown",
            format!(
                "document {} has unknown position encoding {value}",
                document.relative_path
            ),
        )
    })
}

#[cfg(test)]
fn required_position_encoding(
    document: &Document,
) -> Result<PositionEncoding, NormalizationFailure> {
    match declared_position_encoding(document)? {
        PositionEncoding::UnspecifiedPositionEncoding => {
            Err(unspecified_position_encoding(document))
        }
        encoding => Ok(encoding),
    }
}

fn unspecified_position_encoding(document: &Document) -> NormalizationFailure {
    NormalizationFailure::unavailable(
        "provider_position_encoding_unspecified",
        format!(
            "document {} does not specify its position encoding",
            document.relative_path
        ),
    )
}

#[cfg(test)]
fn normalized_span_with_encoding(
    document: &Document,
    source: &[u8],
    range: &[i32],
    encoding: PositionEncoding,
) -> Result<NormalizedSourceSpan, NormalizationFailure> {
    let lines = line_ranges(source);
    normalized_span_with_encoding_and_lines(document, source, &lines, range, encoding)
}

fn normalized_span_with_encoding_and_lines(
    document: &Document,
    source: &[u8],
    lines: &[(usize, usize)],
    range: &[i32],
    encoding: PositionEncoding,
) -> Result<NormalizedSourceSpan, NormalizationFailure> {
    let (start_line, start_column, end_line, end_column) = match range {
        [line, start, end] => (*line, *start, *line, *end),
        [start_line, start, end_line, end] => (*start_line, *start, *end_line, *end),
        _ => {
            return Err(NormalizationFailure::unavailable(
                "provider_range_invalid",
                format!(
                    "document {} contains a SCIP range with {} elements",
                    document.relative_path,
                    range.len()
                ),
            ));
        }
    };
    let values = [start_line, start_column, end_line, end_column];
    if values.iter().any(|value| *value < 0) {
        return Err(NormalizationFailure::unavailable(
            "provider_range_invalid",
            format!(
                "document {} contains a negative SCIP range",
                document.relative_path
            ),
        ));
    }
    debug_assert_ne!(encoding, PositionEncoding::UnspecifiedPositionEncoding);
    let (start_byte, start_utf8_column) = position_to_byte(
        source,
        lines,
        start_line as usize,
        start_column as usize,
        encoding,
        &document.relative_path,
    )?;
    let (end_byte, end_utf8_column) = position_to_byte(
        source,
        lines,
        end_line as usize,
        end_column as usize,
        encoding,
        &document.relative_path,
    )?;
    if start_byte > end_byte {
        return Err(NormalizationFailure::unavailable(
            "provider_range_reversed",
            format!(
                "document {} contains a reversed SCIP range",
                document.relative_path
            ),
        ));
    }
    Ok(NormalizedSourceSpan {
        start_byte: start_byte as u64,
        end_byte: end_byte as u64,
        start_line: start_line as u32,
        start_utf8_byte_column: start_utf8_column as u32,
        end_line: end_line as u32,
        end_utf8_byte_column: end_utf8_column as u32,
    })
}

fn normalized_source_byte_span(
    source: &SourceDocument,
    document_path: &str,
    start_byte: usize,
    end_byte: usize,
) -> Result<NormalizedSourceSpan, NormalizationFailure> {
    let source_text = source.text.as_str();
    if start_byte > end_byte
        || end_byte > source.text.len()
        || !source_text.is_char_boundary(start_byte)
        || !source_text.is_char_boundary(end_byte)
    {
        return Err(NormalizationFailure::unavailable(
            "language_syntax_range_invalid",
            format!("syntax range {start_byte}-{end_byte} is invalid for document {document_path}"),
        ));
    }
    let (start_line, start_column) = source_byte_position(&source.line_ranges, start_byte)
        .ok_or_else(|| {
            NormalizationFailure::unavailable(
                "language_syntax_range_invalid",
                format!("syntax range start {start_byte} is outside document {document_path}"),
            )
        })?;
    let (end_line, end_column) =
        source_byte_position(&source.line_ranges, end_byte).ok_or_else(|| {
            NormalizationFailure::unavailable(
                "language_syntax_range_invalid",
                format!("syntax range end {end_byte} is outside document {document_path}"),
            )
        })?;
    Ok(NormalizedSourceSpan {
        start_byte: start_byte as u64,
        end_byte: end_byte as u64,
        start_line: start_line as u32,
        start_utf8_byte_column: start_column as u32,
        end_line: end_line as u32,
        end_utf8_byte_column: end_column as u32,
    })
}

fn source_byte_position(lines: &[(usize, usize)], byte: usize) -> Option<(usize, usize)> {
    let insertion = lines.partition_point(|(start, _)| {
        #[cfg(test)]
        SOURCE_POSITION_PROBE_COUNT.with(|count| count.set(count.get() + 1));
        *start <= byte
    });
    let line = insertion.checked_sub(1)?;
    let (start, end) = *lines.get(line)?;
    (byte <= end).then_some((line, byte - start))
}

fn line_ranges(source: &[u8]) -> Vec<(usize, usize)> {
    #[cfg(test)]
    LINE_RANGE_SCAN_COUNT.with(|count| count.set(count.get() + 1));

    let mut ranges = Vec::new();
    let mut start = 0;
    for (index, byte) in source.iter().copied().enumerate() {
        if byte == b'\n' {
            ranges.push((start, index));
            start = index + 1;
        }
    }
    ranges.push((start, source.len()));
    ranges
}

#[cfg(test)]
std::thread_local! {
    static CANONICAL_NORMALIZATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CANONICAL_DOCUMENT_CANONICALIZATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CALL_OWNER_CANDIDATE_PROBE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static LINE_RANGE_SCAN_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PROVIDER_SPAN_NORMALIZATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PROVIDER_SYMBOL_RANGE_INSERT_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PROVIDER_REFERENCE_RANGE_INSERT_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PROVIDER_DEFINITION_RECORD_RETAIN_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DEFINITION_RECORD_GROUP_SCAN_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static DEFINITION_GROUP_CANONICALIZATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CALL_DOCUMENT_RESOLUTION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static QUALIFIED_SYMBOL_ID_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static EAGER_PROVIDER_DEFINITION_INDEX_INSERT_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static EAGER_DEFINITION_GROUP_TREE_INSERT_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SPAN_UTF8_REVALIDATION_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SOURCE_POSITION_PROBE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SOURCE_RANGE_PROBE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub fn reset_canonical_normalization_count() {
    CANONICAL_NORMALIZATION_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub fn canonical_normalization_count() -> usize {
    CANONICAL_NORMALIZATION_COUNT.with(std::cell::Cell::get)
}

#[cfg(test)]
fn reset_canonical_document_canonicalization_count() {
    CANONICAL_DOCUMENT_CANONICALIZATION_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
fn canonical_document_canonicalization_count() -> usize {
    CANONICAL_DOCUMENT_CANONICALIZATION_COUNT.with(std::cell::Cell::get)
}

fn position_to_byte(
    source: &[u8],
    lines: &[(usize, usize)],
    line: usize,
    column: usize,
    encoding: PositionEncoding,
    document_path: &str,
) -> Result<(usize, usize), NormalizationFailure> {
    let (line_start, line_end) = lines.get(line).copied().ok_or_else(|| {
        NormalizationFailure::unavailable(
            "provider_range_out_of_bounds",
            format!("document {document_path} has no line {line}"),
        )
    })?;
    let line_bytes = &source[line_start..line_end];
    let line_text = std::str::from_utf8(line_bytes).map_err(|error| {
        NormalizationFailure::unavailable(
            "indexed_source_not_utf8",
            format!("document {document_path} is not UTF-8: {error}"),
        )
    })?;
    let byte_column = match encoding {
        PositionEncoding::UTF8CodeUnitOffsetFromLineStart => {
            if column > line_bytes.len() || !line_text.is_char_boundary(column) {
                return Err(NormalizationFailure::unavailable(
                    "provider_range_out_of_bounds",
                    format!(
                        "document {document_path} UTF-8 column {column} is not a character boundary"
                    ),
                ));
            }
            column
        }
        PositionEncoding::UTF16CodeUnitOffsetFromLineStart => code_units_to_byte(
            line_text,
            column,
            char::len_utf16,
        )
        .ok_or_else(|| {
            NormalizationFailure::unavailable(
                "provider_range_out_of_bounds",
                format!(
                    "document {document_path} UTF-16 column {column} is not a character boundary"
                ),
            )
        })?,
        PositionEncoding::UTF32CodeUnitOffsetFromLineStart => code_units_to_byte(
            line_text,
            column,
            |_| 1,
        )
        .ok_or_else(|| {
            NormalizationFailure::unavailable(
                "provider_range_out_of_bounds",
                format!(
                    "document {document_path} UTF-32 column {column} is not a character boundary"
                ),
            )
        })?,
        PositionEncoding::UnspecifiedPositionEncoding => unreachable!("rejected above"),
    };
    Ok((line_start + byte_column, byte_column))
}

fn code_units_to_byte(
    text: &str,
    target_units: usize,
    units: impl Fn(char) -> usize,
) -> Option<usize> {
    if target_units == 0 {
        return Some(0);
    }
    let mut consumed = 0;
    for (byte_index, character) in text.char_indices() {
        if consumed == target_units {
            return Some(byte_index);
        }
        consumed += units(character);
        if consumed > target_units {
            return None;
        }
    }
    (consumed == target_units).then_some(text.len())
}

fn qualified_symbol_id(document_path: &str, symbol: &str) -> String {
    #[cfg(test)]
    QUALIFIED_SYMBOL_ID_COUNT.with(|count| count.set(count.get() + 1));

    if symbol.starts_with("local ") {
        format!("h00-local:{document_path}:{symbol}")
    } else {
        symbol.to_owned()
    }
}

const fn callable_kind(kind: symbol_information::Kind) -> bool {
    matches!(
        kind,
        symbol_information::Kind::AbstractMethod
            | symbol_information::Kind::Accessor
            | symbol_information::Kind::Constructor
            | symbol_information::Kind::Function
            | symbol_information::Kind::Getter
            | symbol_information::Kind::Method
            | symbol_information::Kind::MethodAlias
            | symbol_information::Kind::MethodSpecification
            | symbol_information::Kind::Operator
            | symbol_information::Kind::ProtocolMethod
            | symbol_information::Kind::PureVirtualMethod
            | symbol_information::Kind::Setter
            | symbol_information::Kind::SingletonMethod
            | symbol_information::Kind::StaticMethod
            | symbol_information::Kind::TraitMethod
            | symbol_information::Kind::TypeClassMethod
    )
}

fn call_target_kind(spec: ScipProviderSpec, kind: symbol_information::Kind) -> bool {
    if callable_kind(kind) {
        return true;
    }
    match spec.language {
        "rust" => matches!(
            kind,
            symbol_information::Kind::Parameter
                | symbol_information::Kind::Variable
                | symbol_information::Kind::Constant
                | symbol_information::Kind::StaticVariable
                | symbol_information::Kind::Field
                | symbol_information::Kind::Struct
                | symbol_information::Kind::EnumMember
                | symbol_information::Kind::Constructor
        ),
        "go" => matches!(
            kind,
            symbol_information::Kind::Parameter
                | symbol_information::Kind::Variable
                | symbol_information::Kind::Field
        ),
        "python" => kind == symbol_information::Kind::Class,
        "typescript" => matches!(
            kind,
            symbol_information::Kind::Parameter
                | symbol_information::Kind::Variable
                | symbol_information::Kind::Constant
                | symbol_information::Kind::StaticVariable
                | symbol_information::Kind::Field
                | symbol_information::Kind::Property
        ),
        _ => false,
    }
}

fn rust_constructor_target_kind(spec: ScipProviderSpec, kind: symbol_information::Kind) -> bool {
    spec.language == "rust"
        && matches!(
            kind,
            symbol_information::Kind::Struct | symbol_information::Kind::EnumMember
        )
}

const fn go_conversion_target_kind(kind: symbol_information::Kind) -> bool {
    matches!(
        kind,
        symbol_information::Kind::Array
            | symbol_information::Kind::Class
            | symbol_information::Kind::Enum
            | symbol_information::Kind::Interface
            | symbol_information::Kind::Struct
            | symbol_information::Kind::Type
            | symbol_information::Kind::TypeAlias
            | symbol_information::Kind::TypeParameter
            | symbol_information::Kind::Union
    )
}

fn kind_name(kind: symbol_information::Kind) -> String {
    format!("{kind:?}").to_ascii_lowercase()
}

fn enclosing_callable_linear<'a>(
    definitions: impl Iterator<Item = &'a DefinitionRecord>,
    call_span: &NormalizedSourceSpan,
) -> Result<Option<&'a DefinitionRecord>, ()> {
    let mut selected = None::<(u64, &'a DefinitionRecord)>;
    let mut ambiguous = false;
    for definition in definitions.filter(|definition| definition.callable) {
        #[cfg(test)]
        CALL_OWNER_CANDIDATE_PROBE_COUNT.with(|count| count.set(count.get() + 1));
        let Some(enclosing) = definition.call_owner_span.as_ref() else {
            continue;
        };
        if enclosing.start_byte > call_span.start_byte || call_span.end_byte > enclosing.end_byte {
            continue;
        }
        let length = enclosing.end_byte - enclosing.start_byte;
        match selected {
            None => selected = Some((length, definition)),
            Some((selected_length, _)) if length < selected_length => {
                selected = Some((length, definition));
                ambiguous = false;
            }
            Some((selected_length, selected_definition)) if length == selected_length => {
                ambiguous |=
                    definition.provider_symbol_id != selected_definition.provider_symbol_id;
            }
            Some(_) => {}
        }
    }
    if ambiguous {
        Err(())
    } else {
        Ok(selected.map(|(_, definition)| definition))
    }
}

fn provider_symbol(definition: &DefinitionRecord, language: &str) -> ProviderSymbol {
    debug_assert_eq!(
        definition.document_path,
        definition.definition.document_path
    );
    ProviderSymbol {
        provider_symbol_id: definition.provider_symbol_id.clone(),
        name: definition.name.clone(),
        provider_kind: definition.kind.clone(),
        language_id: LanguageId::new(language),
        role: if definition.structural_span().is_some() {
            ProviderSymbolRole::SourceInvocationTarget
        } else {
            ProviderSymbolRole::LocalInvocationTarget
        },
        definition: Some(definition.definition.clone()),
        structural_extent: definition
            .structural_span()
            .cloned()
            .map(|span| ProviderLocation {
                document_path: definition.document_path.clone(),
                span,
            }),
        call_owner_extent: definition
            .call_owner_span
            .clone()
            .map(|span| ProviderLocation {
                document_path: definition.document_path.clone(),
                span,
            }),
    }
}

fn source_slice<'a>(
    source: &'a [u8],
    span: &NormalizedSourceSpan,
) -> Result<&'a str, NormalizationFailure> {
    let start = usize::try_from(span.start_byte).map_err(|_| {
        NormalizationFailure::unavailable("provider_range_out_of_bounds", "range start overflow")
    })?;
    let end = usize::try_from(span.end_byte).map_err(|_| {
        NormalizationFailure::unavailable("provider_range_out_of_bounds", "range end overflow")
    })?;
    std::str::from_utf8(source.get(start..end).ok_or_else(|| {
        NormalizationFailure::unavailable(
            "provider_range_out_of_bounds",
            "definition range exceeds source bytes",
        )
    })?)
    .map_err(|error| {
        NormalizationFailure::unavailable(
            "provider_range_out_of_bounds",
            format!("definition range is not UTF-8: {error}"),
        )
    })
}

fn calls_input_fingerprint<'a>(
    spec: ScipProviderSpec,
    provider_version: &str,
    provider_configuration_material: &[u8],
    documents: impl Iterator<Item = &'a ProviderDocument>,
    inventory: &ProjectInventory,
) -> Result<String, NormalizationFailure> {
    let inventory_fingerprint =
        semantic_provider_inventory_fingerprint(inventory, spec.language, spec.ecosystem).map_err(
            |error| {
                NormalizationFailure::unavailable(
                    "project_inventory_invalid",
                    format!("cannot fingerprint provider-scoped project inventory: {error}"),
                )
            },
        )?;
    let mut documents = documents.collect::<Vec<_>>();
    documents.sort();
    let mut hasher = Sha256::new();
    hasher.update(NORMALIZER_FINGERPRINT_SCHEMA);
    hash_field(&mut hasher, spec.provider_id);
    hash_field(&mut hasher, provider_version);
    hash_field(&mut hasher, spec.language);
    hash_field(&mut hasher, CALLS_CONFIGURATION_ID);
    hash_field(&mut hasher, &sha256_hex(provider_configuration_material));
    hash_field(&mut hasher, &inventory_fingerprint);
    for document in documents {
        hash_field(&mut hasher, &document.document_path);
        hash_field(&mut hasher, &document.content_sha256);
        hash_field(&mut hasher, &document.cross_document_surface_sha256);
        hash_field(&mut hasher, &document.byte_length.to_string());
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use protobuf::EnumOrUnknown;
    use scip::types::{Metadata, Occurrence, SymbolInformation, ToolInfo};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tempfile::TempDir;

    use crate::code_intel_domain::{
        CapabilityStatus, DocumentMembership, DocumentMembershipKind, EcosystemId, ProjectInput,
        ProjectInputRole, ProjectInventoryCoverage, ProjectUnit, ProjectUnitId, ProjectUnitKind,
    };
    use crate::code_intel_inventory::{InventorySource, build_project_inventory};

    const RUST_SOURCE: &str = "fn target() {}\nfn caller() { target(); }\n";
    const GO_SOURCE: &str = "package fixture\nfunc target() {}\nfunc caller() { target() }\n";
    const PYTHON_SOURCE: &str = "def target(): return 1\ndef caller(): return target()\n";

    #[test]
    fn anonymous_callable_context_census_is_language_registered_and_polyglot() {
        for (language, path, source) in [
            (
                "rust",
                "src/lib.rs",
                "fn target() {}\nfn owner() { let callback = || target(); drop(callback); }\n",
            ),
            (
                "go",
                "main.go",
                "package fixture\nfunc target() {}\nfunc owner() { callback := func() { target() }; _ = callback }\n",
            ),
            (
                "python",
                "app.py",
                "def target(): return 1\ncallback = lambda: target()\n",
            ),
            (
                "typescript",
                "src/app.ts",
                "function target() {}\nconst callback = () => target();\n",
            ),
        ] {
            let syntax = source_call_evidence(source, path, language)
                .unwrap_or_else(|error| panic!("{language} syntax census: {error:?}"));
            let start = source.rfind("target()").expect("anonymous call marker") as u64;
            assert_eq!(
                syntax.execution_root_context(start, start + 6),
                crate::code_intel_domain::ExecutionRootContext::AnonymousCallable,
                "{language} must classify its registered anonymous callable syntax"
            );
        }

        let module_source = "def target(): return 1\ntarget()\n";
        let module_syntax = source_call_evidence(module_source, "app.py", "python")
            .expect("module-scope positive control");
        let module_start = module_source.rfind("target()").expect("module call") as u64;
        assert_eq!(
            module_syntax.execution_root_context(module_start, module_start + 6),
            crate::code_intel_domain::ExecutionRootContext::ModuleInitialization,
            "ordinary module scope must remain distinct"
        );
    }

    #[test]
    fn affected_definition_group_refresh_preserves_shared_unchanged_records() {
        let record = |base_id: &str, document_path: &str, start_byte: u64| {
            let span = NormalizedSourceSpan {
                start_byte,
                end_byte: start_byte + 6,
                start_line: 0,
                start_utf8_byte_column: start_byte as u32,
                end_line: 0,
                end_utf8_byte_column: start_byte as u32 + 6,
            };
            DefinitionRecord {
                provider_symbol_id: base_id.into(),
                name: "target".into(),
                kind: "function".into(),
                provider_kind: symbol_information::Kind::Function,
                document_path: document_path.into(),
                definition: ProviderLocation {
                    document_path: document_path.into(),
                    span: span.clone(),
                },
                enclosing_span: Some(span.clone()),
                invocation_target_span: None,
                call_owner_span: Some(span),
                value_binding_span: None,
                binding_scope: (0, 128),
                callable: true,
                rust_declared_owner: None,
            }
        };
        let changed_before = record("shared", "src/changed.rs", 4);
        let changed_after = record("shared", "src/changed.rs", 12);
        let unchanged = record("shared", "src/stable.rs", 20);
        let unrelated: Arc<[Arc<DefinitionRecord>]> =
            Arc::from(vec![Arc::new(record("unrelated", "src/stable.rs", 40))]);
        let prior: Arc<SharedDefinitionRecordsByBaseId> = Arc::new(BTreeMap::from([
            (
                Arc::from("shared"),
                Arc::from(vec![
                    Arc::new(changed_before.clone()),
                    Arc::new(unchanged.clone()),
                ]),
            ),
            (Arc::from("unrelated"), Arc::clone(&unrelated)),
        ]));

        let refreshed = refresh_definition_records_by_base_id(
            &prior,
            &BTreeSet::from(["src/changed.rs".into()]),
            &BTreeSet::from(["shared".into()]),
            BTreeMap::from([("shared".into(), vec![changed_after.clone()])]),
        );
        let shared = refreshed.get("shared").expect("shared group retained");
        assert_eq!(shared.len(), 2, "positive shared-group population control");
        assert!(shared.iter().any(|record| record.as_ref() == &unchanged));
        assert!(
            shared
                .iter()
                .any(|record| record.as_ref() == &changed_after)
        );
        assert!(
            !shared
                .iter()
                .any(|record| record.as_ref() == &changed_before)
        );
        assert!(
            Arc::ptr_eq(
                refreshed
                    .get("unrelated")
                    .expect("unaffected group retained"),
                &unrelated
            ),
            "an unrelated group must remain physically shared"
        );
    }

    #[test]
    fn independent_source_materialization_overlaps_without_reordering_results() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .expect("bounded test pool");
        let inputs = (0..24).collect::<Vec<_>>();
        let active = AtomicUsize::new(0);
        let maximum_active = AtomicUsize::new(0);

        let output = pool
            .install(|| {
                ordered_parallel_try_map(&inputs, |input| {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum_active.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(10));
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, ()>(*input)
                })
            })
            .expect("independent work succeeds");

        assert_eq!(
            output, inputs,
            "parallel completion must not reorder inputs"
        );
        assert!(
            maximum_active.load(Ordering::SeqCst) > 1,
            "independent source documents must be materialized concurrently"
        );

        let first_error = pool.install(|| {
            ordered_parallel_try_map(&inputs, |input| match *input {
                1 => {
                    std::thread::sleep(Duration::from_millis(20));
                    Err(1)
                }
                2 => Err(2),
                value => Ok(value),
            })
        });
        assert_eq!(
            first_error,
            Err(1),
            "parallel completion order must not choose a later input's error"
        );
    }

    #[test]
    fn one_pass_syntax_census_matches_structural_callable_names() {
        let cases: [(&str, &str, &str, &[&str]); 4] = [
            (
                "rust",
                "src/lib.rs",
                concat!(
                    "struct Thing;\n",
                    "trait Contract { fn required(); fn provided() {} }\n",
                    "impl Thing { fn method(&self) {} }\n",
                    "fn outer() { fn nested() {} nested(); }\n",
                ),
                &["nested"],
            ),
            (
                "go",
                "main.go",
                concat!(
                    "package main\n",
                    "type Thing struct{}\n",
                    "func top() {}\n",
                    "func (Thing) method() {}\n",
                    "var callback = func() {}\n",
                    "type Contract interface { Required() }\n",
                    "func outer() { local := func() {}; local() }\n",
                ),
                &["local"],
            ),
            (
                "python",
                "src/main.py",
                concat!(
                    "@trace\ndef top():\n    return 1\n",
                    "class Thing:\n    def method(self):\n        return top()\n",
                    "def outer():\n    def nested():\n        return top()\n    return nested()\n",
                ),
                &["nested", "top", "top"],
            ),
            (
                "typescript",
                "src/main.ts",
                concat!(
                    "export function top(): number { return 1; }\n",
                    "export class Thing { method(): number { return top(); } }\n",
                    "export function outer(): number { function nested() { return top(); } return nested(); }\n",
                ),
                &["nested", "top", "top"],
            ),
        ];

        for (language, path, source, expected_calls) in cases {
            let syntax = source_call_evidence(source, path, language).expect("syntax census");
            let mut actual_calls = syntax
                .call_callees
                .values()
                .map(|callee| callee.name.as_str())
                .collect::<Vec<_>>();
            actual_calls.sort_unstable();
            assert_eq!(
                actual_calls, expected_calls,
                "{language} adapter must expose the exact named-call population"
            );
            let extracted = crate::extractor::extract_source(source, path)
                .expect("independent structural extraction control");
            let structural_callables = extracted
                .symbols
                .iter()
                .filter(|symbol| {
                    symbol
                        .kind
                        .has_role(crate::structural_ir::SymbolRole::Callable)
                })
                .map(|symbol| comparable_callee_name(&symbol.name).to_owned())
                .collect::<BTreeSet<_>>();
            assert_eq!(
                syntax.local_callable_names, structural_callables,
                "{language} census must preserve the structural callable-name population without a second production parse"
            );
            let syntax_callable_extents = syntax
                .callable_extents
                .iter()
                .filter_map(|(name_range, extent)| {
                    source
                        .get(name_range.0..name_range.1)
                        .map(|name| (comparable_callee_name(name).to_owned(), *extent))
                })
                .collect::<BTreeMap<_, _>>();
            let structural_callable_extents = extracted
                .symbols
                .iter()
                .filter(|symbol| {
                    symbol
                        .kind
                        .has_role(crate::structural_ir::SymbolRole::Callable)
                })
                .map(|symbol| (comparable_callee_name(&symbol.name).to_owned(), symbol.span))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(
                syntax_callable_extents, structural_callable_extents,
                "{language} provider joins and structural publication must share exact callable extents"
            );

            if language == "go" {
                let structural_package_callables = extracted
                    .symbols
                    .iter()
                    .filter(|symbol| {
                        symbol
                            .kind
                            .has_role(crate::structural_ir::SymbolRole::Callable)
                            && symbol.has_body
                            && symbol.parent.is_none()
                    })
                    .map(|symbol| comparable_callee_name(&symbol.name).to_owned())
                    .collect::<BTreeSet<_>>();
                assert_eq!(
                    syntax.go_package_function_names, structural_package_callables,
                    "Go package-call authority must include package callable values while excluding methods, interface signatures, and block-local closures"
                );
            }
        }
    }

    #[test]
    fn typed_typescript_template_uses_the_adapter_admission_in_semantic_census() {
        let source = concat!(
            "declare const sql: <T>(parts: TemplateStringsArray) => T;\n",
            "export async function load() {\n",
            "  const { rows } = await sql<{ exists: boolean }>`select true as exists`;\n",
            "  notify();\n",
            "  return rows;\n",
            "}\n",
        );
        let evidence = source_call_evidence(source, "src/database.ts", "typescript")
            .expect("semantic census must share TypeScript syntax admission");
        assert!(
            evidence
                .call_callees
                .values()
                .any(|callee| callee.name == "notify"),
            "positive semantic-census population control"
        );

        let mixed_invalid = format!("{source}\nexport class Broken {{ method(\n");
        let error = source_call_evidence(&mixed_invalid, "src/broken.ts", "typescript")
            .expect_err("the known grammar gap must not launder a real syntax error");
        assert_eq!(error.code, "language_parse_incomplete");
    }

    #[test]
    fn rust_edition_2024_let_chains_do_not_invalidate_call_evidence() {
        let source = concat!(
            "fn target() {}\n",
            "fn caller(value: Option<u8>, enabled: bool) {\n",
            "    if enabled && let Some(_value) = value { target(); }\n",
            "}\n",
        );
        let evidence = source_call_evidence(source, "src/lib.rs", "rust")
            .expect("valid Rust 2024 let-chain source");
        assert!(evidence.local_callable_names.contains("target"));
        assert!(
            evidence
                .call_callees
                .values()
                .any(|callee| callee.name == "target"),
            "positive control: the call inside the let-chain must remain discoverable"
        );
    }

    struct Fixture {
        _workspace: TempDir,
        root: PathBuf,
        artifact: PathBuf,
        spec: ScipProviderSpec,
        indexed_sources: Vec<IndexedSourceEvidence>,
        inventory: ProjectInventory,
        index: Index,
    }

    impl Fixture {
        fn normalize(&self) -> ScipArtifactEvidence {
            fs::write(
                &self.artifact,
                self.index.write_to_bytes().expect("serialize SCIP fixture"),
            )
            .expect("write SCIP fixture");
            normalize_scip_artifact(
                &self.root,
                &self.artifact,
                self.spec,
                &self.indexed_sources,
                &self.inventory,
            )
        }
    }

    #[test]
    fn complete_provider_authority_requires_structural_surface_evidence() {
        let mut fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                RUST_SOURCE,
                0,
                1,
                "rust fixture target().",
                "rust fixture caller().",
            )],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        fixture.indexed_sources[0].cross_document_surface_sha256 = None;

        let evidence = fixture.normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Partial);
        assert_eq!(
            evidence.receipt.reason_code.as_deref(),
            Some("semantic_surface_unavailable")
        );
        assert!(evidence.payload.is_none());
    }

    #[test]
    fn provider_normalization_builds_one_line_index_per_source_document() {
        let fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                RUST_SOURCE,
                0,
                1,
                "rust fixture target().",
                "rust fixture caller().",
            )],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        LINE_RANGE_SCAN_COUNT.with(|count| count.set(0));

        let evidence = fixture.normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let scans = LINE_RANGE_SCAN_COUNT.with(std::cell::Cell::get);
        assert_eq!(
            scans, 1,
            "line boundaries are document state and must not be rebuilt for every provider occurrence"
        );
    }

    /// RIGHT-REASON REGRESSION: the TypeScript compiler describes a `const`
    /// binding by its declaration kind even when its initializer owns an arrow
    /// function body. The language adapter must supply that exact callable
    /// extent before the resolved invocation can become a Calls edge.
    #[test]
    fn typescript_callable_value_joins_compiler_kind_to_structural_body() {
        const SOURCE: &str = "const tokenColor = (name: string) => name;\nfunction caller() { return tokenColor(\"x\"); }\n";
        const TOKEN: &str = "typescript npm fixture 0.1.0 src/index.ts/tokenColor.";
        const CALLER: &str = "typescript npm fixture 0.1.0 src/index.ts/caller().";
        let mut lines = SOURCE.lines();
        let binding_line = lines.next().expect("binding line");
        let caller_line = lines.next().expect("caller line");
        let binding_column = binding_line.find("tokenColor").expect("binding name") as i32;
        let caller_column = caller_line.find("caller").expect("caller name") as i32;
        let call_column = caller_line.rfind("tokenColor").expect("call target") as i32;

        let mut binding_definition = Occurrence::new();
        binding_definition.symbol = TOKEN.into();
        binding_definition.symbol_roles = SymbolRole::Definition.value();
        binding_definition.range = vec![0, binding_column, binding_column + 10];

        let mut caller_definition = Occurrence::new();
        caller_definition.symbol = CALLER.into();
        caller_definition.symbol_roles = SymbolRole::Definition.value();
        caller_definition.range = vec![1, caller_column, caller_column + 6];

        let mut call = Occurrence::new();
        call.symbol = TOKEN.into();
        call.range = vec![1, call_column, call_column + 10];

        let mut binding_information = SymbolInformation::new();
        binding_information.symbol = TOKEN.into();
        binding_information.display_name = "tokenColor".into();
        binding_information.kind = EnumOrUnknown::new(symbol_information::Kind::Constant);

        let mut caller_information = SymbolInformation::new();
        caller_information.symbol = CALLER.into();
        caller_information.display_name = "caller".into();
        caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

        let mut document = Document::new();
        document.language = "typescript".into();
        document.relative_path = "src/index.ts".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![binding_definition, caller_definition, call];
        document.symbols = vec![binding_information, caller_information];

        let evidence = fixture(
            ScipProviderSpec::typescript_native_sidecar(),
            vec![document],
            &[("src/index.ts", SOURCE)],
        )
        .normalize();
        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "resolved callable value was not admitted: {:?}",
            evidence.receipt
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete TypeScript Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        let callee = payload
            .symbols
            .iter()
            .find(|symbol| symbol.name == "tokenColor")
            .expect("callable-value target symbol");
        assert_eq!(callee.provider_kind, "constant");
        assert_eq!(callee.role, ProviderSymbolRole::SourceInvocationTarget);
        assert!(
            callee.structural_extent.is_some(),
            "a package-level arrow binding is a stable structural query target"
        );
    }

    #[test]
    fn typescript_named_targets_from_module_and_anonymous_test_roots_remain_positive_calls() {
        const SOURCE: &str = concat!(
            "function target() { return 1; }\n",
            "target();\n",
            "test(\"works\", () => target());\n",
        );
        const TARGET: &str = "typescript npm fixture 0.1.0 src/index.spec.ts/target().";
        let definition_line = SOURCE.lines().next().expect("definition line");
        let definition_column = definition_line.find("target").expect("target definition") as i32;

        let mut definition = Occurrence::new();
        definition.symbol = TARGET.into();
        definition.symbol_roles = SymbolRole::Definition.value();
        definition.range = vec![0, definition_column, definition_column + 6];

        let mut module_call = Occurrence::new();
        module_call.symbol = TARGET.into();
        module_call.range = vec![1, 0, 6];

        let callback_line = SOURCE.lines().nth(2).expect("callback line");
        let callback_column = callback_line.rfind("target").expect("callback call") as i32;
        let mut callback_call = Occurrence::new();
        callback_call.symbol = TARGET.into();
        callback_call.range = vec![2, callback_column, callback_column + 6];

        let mut information = SymbolInformation::new();
        information.symbol = TARGET.into();
        information.display_name = "target".into();
        information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

        let mut document = Document::new();
        document.language = "typescript".into();
        document.relative_path = "src/index.spec.ts".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![definition, module_call, callback_call];
        document.symbols = vec![information];

        let evidence = fixture(
            ScipProviderSpec::typescript_native_sidecar(),
            vec![document],
            &[("src/index.spec.ts", SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete TypeScript Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.calls.is_empty());
        assert_eq!(payload.root_invocations.len(), 2);
        assert!(payload.root_invocations.iter().all(|invocation| {
            invocation.callee_symbol_id == TARGET
                && invocation.call_site.document_path == "src/index.spec.ts"
        }));
        let module = payload
            .root_invocations
            .iter()
            .find(|invocation| invocation.call_site.span.start_line == 1)
            .expect("module initialization invocation");
        let callback = payload
            .root_invocations
            .iter()
            .find(|invocation| invocation.call_site.span.start_line == 2)
            .expect("anonymous callback invocation");
        assert_eq!(
            module.context,
            crate::code_intel_domain::ExecutionRootContext::ModuleInitialization
        );
        assert_eq!(
            callback.context,
            crate::code_intel_domain::ExecutionRootContext::AnonymousCallable,
            "a deferred anonymous callback must not inherit module-initialization authority"
        );
        assert!(payload.coverage_exclusions.is_empty());
    }

    /// RIGHT-REASON REGRESSION from ERA dogfood: a nested TypeScript arrow
    /// binding owns compiler call evidence but structural extraction does not
    /// publish runtime-local values as stable graph/query identities. Those
    /// are separate contracts: keep exact scoped coverage evidence without
    /// forcing a fabricated structural node into publication.
    #[test]
    fn typescript_nested_callable_preserves_calls_without_becoming_a_structural_target() {
        const SOURCE: &str = concat!(
            "function target() { return 1; }\n",
            "function caller() {\n",
            "  const local = () => target();\n",
            "  return local();\n",
            "}\n",
        );
        const TARGET: &str = "typescript npm fixture 0.1.0 src/index.ts/target().";
        const CALLER: &str = "typescript npm fixture 0.1.0 src/index.ts/caller().";
        const LOCAL: &str = "local 0";
        const QUALIFIED_LOCAL: &str = "h00-local:src/index.ts:local 0";

        let mut definitions = Vec::new();
        let mut information = Vec::new();
        for (line_index, name, symbol, kind) in [
            (0, "target", TARGET, symbol_information::Kind::Function),
            (1, "caller", CALLER, symbol_information::Kind::Function),
            (2, "local", LOCAL, symbol_information::Kind::Constant),
        ] {
            let line = SOURCE.lines().nth(line_index).expect("definition line");
            let column = line.find(name).expect("definition name") as i32;
            let mut definition = Occurrence::new();
            definition.symbol = symbol.into();
            definition.symbol_roles = SymbolRole::Definition.value();
            definition.range = vec![
                line_index as i32,
                column,
                column + i32::try_from(name.len()).expect("definition name length"),
            ];
            definitions.push(definition);

            let mut symbol_information = SymbolInformation::new();
            symbol_information.symbol = symbol.into();
            symbol_information.display_name = name.into();
            symbol_information.kind = EnumOrUnknown::new(kind);
            information.push(symbol_information);
        }

        let nested_line = SOURCE.lines().nth(2).expect("nested arrow line");
        let target_call_column = nested_line.rfind("target").expect("nested target call") as i32;
        let mut target_call = Occurrence::new();
        target_call.symbol = TARGET.into();
        target_call.range = vec![2, target_call_column, target_call_column + 6];

        let outer_line = SOURCE.lines().nth(3).expect("outer call line");
        let local_call_column = outer_line.rfind("local").expect("local call") as i32;
        let mut local_call = Occurrence::new();
        local_call.symbol = LOCAL.into();
        local_call.range = vec![3, local_call_column, local_call_column + 5];

        let mut document = Document::new();
        document.language = "typescript".into();
        document.relative_path = "src/index.ts".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = definitions;
        document.occurrences.extend([target_call, local_call]);
        document.symbols = information;

        let fixture = fixture(
            ScipProviderSpec::typescript_native_sidecar(),
            vec![document],
            &[("src/index.ts", SOURCE)],
        );
        let evidence = fixture.normalize();
        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "runtime-local callable evidence must be scoped rather than poisoning the project: {:?}",
            evidence.receipt
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete TypeScript Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };

        let local = payload
            .symbols
            .iter()
            .find(|symbol| symbol.provider_symbol_id == QUALIFIED_LOCAL)
            .expect("provider-observed nested callable");
        assert_eq!(local.role, ProviderSymbolRole::LocalInvocationTarget);
        assert!(local.structural_extent.is_none());
        assert!(
            local.call_owner_extent.is_some(),
            "the exact nested arrow still owns its compiler-observed body calls"
        );
        assert_eq!(
            payload.calls.len(),
            2,
            "the local invocation and its body call must both remain positive provider evidence"
        );
        assert!(
            payload
                .calls
                .iter()
                .any(|call| { call.caller_symbol_id == CALLER && call.callee_symbol_id == TARGET })
        );
        assert!(payload.calls.iter().any(|call| {
            call.caller_symbol_id == CALLER && call.callee_symbol_id == QUALIFIED_LOCAL
        }));
        assert!(
            payload.coverage_exclusions.is_empty(),
            "an exact local body and exact published lexical owner need no uncertainty escape hatch"
        );

        let extracted =
            crate::extractor::extract_file(&fixture.root.join("src/index.ts"), &fixture.root)
                .expect("independently extract the TypeScript structural graph");
        let mut graph = crate::graph::KnowledgeGraph::new();
        crate::edge_builder::build_graph(&[extracted], &mut graph)
            .expect("build the TypeScript structural graph");
        assert!(
            graph.node_by_name("local").is_none(),
            "positive control: structural extraction deliberately omits nested runtime values"
        );
        let caller_id = graph
            .node_by_name("caller")
            .expect("structural caller")
            .memory_id;
        let target_id = graph
            .node_by_name("target")
            .expect("structural target")
            .memory_id;
        let stats =
            crate::code_intel_calls::project_calls_payload_structural_join(&mut graph, &payload)
                .expect("runtime-local evidence must not break publication join");
        assert_eq!(stats.novel_edges, 1);
        assert!(
            graph
                .find_edge_by_kind_mut(caller_id, target_id, crate::graph::EdgeKind::Calls)
                .is_some(),
            "the nested body's exact call must project through its nearest stable lexical owner"
        );
    }

    #[test]
    fn rust_normalization_builds_only_receiver_owner_occurrence_index() {
        let fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                RUST_SOURCE,
                0,
                1,
                "rust fixture target().",
                "rust fixture caller().",
            )],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        PROVIDER_SYMBOL_RANGE_INSERT_COUNT.with(|count| count.set(0));
        PROVIDER_REFERENCE_RANGE_INSERT_COUNT.with(|count| count.set(0));

        let evidence = fixture.normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        assert!(
            PROVIDER_SYMBOL_RANGE_INSERT_COUNT.with(std::cell::Cell::get) > 0,
            "positive control: Rust receiver/type-owner authority populated its occurrence index"
        );
        assert_eq!(
            PROVIDER_REFERENCE_RANGE_INSERT_COUNT.with(std::cell::Cell::get),
            0,
            "Rust normalization must not populate Go callable-binding reference ranges"
        );
    }

    #[test]
    fn source_byte_position_is_logarithmic_and_preserves_line_boundaries() {
        let source = "x\n".repeat(4_096);
        let lines = line_ranges(source.as_bytes());
        let samples = [
            0,
            lines[2_048].0,
            lines[2_048].1,
            source.len().saturating_sub(1),
            source.len(),
        ];

        for byte in samples {
            let expected = lines
                .iter()
                .copied()
                .enumerate()
                .find_map(|(line, (start, end))| {
                    (start <= byte && byte <= end).then_some((line, byte - start))
                });
            SOURCE_POSITION_PROBE_COUNT.with(|count| count.set(0));
            let actual = source_byte_position(&lines, byte);
            let probes = SOURCE_POSITION_PROBE_COUNT.with(std::cell::Cell::get);

            assert_eq!(actual, expected, "byte {byte} boundary semantics");
            assert!(
                probes <= 16,
                "line lookup must be logarithmic: byte {byte} used {probes} probes across {} lines",
                lines.len()
            );
        }
    }

    #[test]
    fn smallest_containing_syntax_range_is_logarithmic() {
        let ranges = (0..4_096_u64)
            .map(|start| (start, 8_192 - start))
            .collect::<BTreeSet<_>>();
        let index = SourceRangeIndex::new(ranges);
        SOURCE_RANGE_PROBE_COUNT.with(|count| count.set(0));

        let enclosing = smallest_containing_range(&index, 4_095, 4_096);
        let probes = SOURCE_RANGE_PROBE_COUNT.with(std::cell::Cell::get);

        assert_eq!(enclosing, Some((4_095, 4_097)));
        assert!(
            probes <= 64,
            "syntax ownership lookup must be logarithmic: {probes} probes across {} ranges",
            index.len()
        );
    }

    #[test]
    fn call_owner_lookup_is_not_linear_in_document_definitions() {
        const DEFINITION_COUNT: usize = 128;
        let mut source = String::new();
        let mut occurrences = Vec::new();
        let mut symbols = Vec::new();

        for index in 0..DEFINITION_COUNT {
            let name = format!("f{index:03}");
            let symbol = format!("rust fixture 0.1.0 lib/{name}().");
            let line = format!("fn {name}() {{}}\n");
            let name_column = line.find(&name).expect("definition name");
            let mut definition = Occurrence::new();
            definition.symbol = symbol.clone();
            definition.symbol_roles = SymbolRole::Definition.value();
            definition.range = vec![
                index as i32,
                name_column as i32,
                (name_column + name.len()) as i32,
            ];
            definition.enclosing_range =
                vec![index as i32, 0, index as i32, line.trim_end().len() as i32];
            occurrences.push(definition);

            let mut information = SymbolInformation::new();
            information.symbol = symbol;
            information.display_name = name;
            information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);
            symbols.push(information);
            source.push_str(&line);
        }

        let caller_line_index = DEFINITION_COUNT;
        let caller_line = "fn caller() { f000(); }\n";
        let caller_column = caller_line.find("caller").expect("caller definition");
        let call_column = caller_line.find("f000").expect("target call");
        let caller_symbol = "rust fixture 0.1.0 lib/caller().";
        let mut caller_definition = Occurrence::new();
        caller_definition.symbol = caller_symbol.into();
        caller_definition.symbol_roles = SymbolRole::Definition.value();
        caller_definition.range = vec![
            caller_line_index as i32,
            caller_column as i32,
            (caller_column + "caller".len()) as i32,
        ];
        caller_definition.enclosing_range = vec![
            caller_line_index as i32,
            0,
            caller_line_index as i32,
            caller_line.trim_end().len() as i32,
        ];
        occurrences.push(caller_definition);

        let mut target_call = Occurrence::new();
        target_call.symbol = "rust fixture 0.1.0 lib/f000().".into();
        target_call.range = vec![
            caller_line_index as i32,
            call_column as i32,
            (call_column + "f000".len()) as i32,
        ];
        occurrences.push(target_call);

        let mut caller_information = SymbolInformation::new();
        caller_information.symbol = caller_symbol.into();
        caller_information.display_name = "caller".into();
        caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);
        symbols.push(caller_information);
        source.push_str(caller_line);

        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = "src/lib.rs".into();
        document.text = source.clone();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = occurrences;
        document.symbols = symbols;

        CALL_OWNER_CANDIDATE_PROBE_COUNT.with(|count| count.set(0));
        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", source.as_str())],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let probes = CALL_OWNER_CANDIDATE_PROBE_COUNT.with(std::cell::Cell::get);
        assert!(
            probes <= 16,
            "call-owner lookup must not scan all {DEFINITION_COUNT} document definitions: {probes} candidate probes"
        );
    }

    #[test]
    fn normalized_source_spans_do_not_revalidate_the_whole_document() {
        SPAN_UTF8_REVALIDATION_COUNT.with(|count| count.set(0));
        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                RUST_SOURCE,
                0,
                1,
                "rust fixture target().",
                "rust fixture caller().",
            )],
            &[("src/lib.rs", RUST_SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        assert_eq!(
            SPAN_UTF8_REVALIDATION_COUNT.with(std::cell::Cell::get),
            0,
            "UTF-8 is a document invariant and must not be revalidated for every constructed span"
        );
    }

    fn fixture(
        spec: ScipProviderSpec,
        documents: Vec<Document>,
        sources: &[(&str, &str)],
    ) -> Fixture {
        let workspace = TempDir::new().expect("scratch workspace");
        let root = workspace.path().join("repo");
        fs::create_dir_all(&root).expect("scratch root");
        match spec.language {
            "rust" => fs::write(
                root.join("Cargo.toml"),
                "[package]\nname = \"normalizer-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .expect("Rust fixture manifest"),
            "go" => fs::write(
                root.join("go.mod"),
                "module example.invalid/normalizer-fixture\n\ngo 1.27.0\n",
            )
            .expect("Go fixture manifest"),
            "python" => fs::write(
                root.join("pyproject.toml"),
                "[project]\nname = \"normalizer-fixture\"\nversion = \"0.1.0\"\n",
            )
            .expect("Python fixture manifest"),
            "typescript" => fs::write(
                root.join("package.json"),
                "{\"name\":\"normalizer-fixture\",\"version\":\"0.1.0\",\"type\":\"module\"}\n",
            )
            .expect("TypeScript fixture manifest"),
            language => panic!("fixture has no executable project model for {language}"),
        }
        for (relative_path, source) in sources {
            let path = root.join(relative_path);
            fs::create_dir_all(path.parent().expect("source parent")).expect("source directory");
            fs::write(path, source).expect("source fixture");
        }
        let indexed_sources = sources
            .iter()
            .map(|(relative_path, source)| IndexedSourceEvidence {
                relative_path: (*relative_path).into(),
                language: spec.language.into(),
                blake3_hash: blake3::hash(source.as_bytes()).to_hex().to_string(),
                cross_document_surface_sha256: Some(sha256_hex(source.as_bytes())),
            })
            .collect::<Vec<_>>();
        // Normalizer tests exercise an already-admitted provider population;
        // project discovery has its own boundary tests. Use one explicit
        // executable unit so arbitrary synthetic filenames do not accidentally
        // become structural-only merely because Cargo/Go would not discover
        // them from a real manifest.
        let project_unit_id = ProjectUnitId::new(format!(
            "fixture:{}:{}:project",
            spec.language, spec.ecosystem
        ));
        let inventory = ProjectInventory {
            coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
            project_topology: crate::code_intel_domain::ProjectTopology {
                units: vec![ProjectUnit {
                    project_unit_id: project_unit_id.clone(),
                    language_id: LanguageId::new(spec.language),
                    ecosystem_id: EcosystemId::new(spec.ecosystem),
                    kind: match spec.language {
                        "go" => ProjectUnitKind::Module,
                        "rust" | "python" | "typescript" => ProjectUnitKind::Package,
                        language => panic!("fixture has no unit kind for {language}"),
                    },
                    root_path: String::new(),
                    manifest_path: Some(match spec.language {
                        "go" => "go.mod".into(),
                        "rust" => "Cargo.toml".into(),
                        "python" => "pyproject.toml".into(),
                        "typescript" => "package.json".into(),
                        language => panic!("fixture has no manifest path for {language}"),
                    }),
                    compilation_root_paths: Vec::new(),
                }],
                memberships: sources
                    .iter()
                    .map(|(relative_path, _)| DocumentMembership {
                        document_path: (*relative_path).into(),
                        language_id: LanguageId::new(spec.language),
                        project_unit_id: project_unit_id.clone(),
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

        let mut tool = ToolInfo::new();
        tool.name = spec.tool_name.into();
        tool.version = "fixture-provider-1.0.0".into();
        let mut metadata = Metadata::new();
        metadata.tool_info = protobuf::MessageField::some(tool);
        metadata.project_root = format!("file://{}", root.display());
        metadata.text_document_encoding = EnumOrUnknown::new(TextEncoding::UTF8);
        let mut index = Index::new();
        index.metadata = protobuf::MessageField::some(metadata);
        index.documents = documents;

        let artifact = workspace.path().join("fixture.scip");
        Fixture {
            _workspace: workspace,
            root,
            artifact,
            spec,
            indexed_sources,
            inventory,
            index,
        }
    }

    #[test]
    fn composed_artifact_without_temp_workspace_child() {
        if std::env::var_os("H00_COMPOSED_ARTIFACT_NO_TEMP_CHILD").is_none() {
            return;
        }
        let root = PathBuf::from(
            std::env::var_os("H00_COMPOSED_ARTIFACT_ROOT").expect("child repository root"),
        );
        let artifact = PathBuf::from(
            std::env::var_os("H00_COMPOSED_ARTIFACT_INPUT").expect("child SCIP artifact"),
        );
        let source = fs::read(root.join("src/lib.rs")).expect("child source fixture");
        let indexed_sources = vec![IndexedSourceEvidence {
            relative_path: "src/lib.rs".into(),
            language: "rust".into(),
            blake3_hash: blake3::hash(&source).to_hex().to_string(),
            cross_document_surface_sha256: Some(sha256_hex(&source)),
        }];
        let inventory =
            build_project_inventory(&root, &[InventorySource::new("src/lib.rs", "rust")]);
        let normalization = normalize_scip_artifact_set_for_inventory_coverage(
            &root,
            ScipProviderSpec::rust_analyzer(),
            &[ScipArtifactInput {
                artifact_path: artifact,
                execution_root: root.clone(),
                executed_provider_version: "fixture-provider-1.0.0".into(),
                provider_configuration_sha256: "a".repeat(64),
            }],
            &indexed_sources,
            &inventory,
        );
        let evidence = normalization.evidence;
        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "in-memory composition must remain usable when process TMPDIR is unusable: {:?}",
            evidence.receipt
        );
    }

    #[test]
    fn composed_artifact_requires_no_process_temp_workspace() {
        let fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                RUST_SOURCE,
                0,
                1,
                "rust fixture target().",
                "rust fixture caller().",
            )],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        fs::write(
            &fixture.artifact,
            fixture
                .index
                .write_to_bytes()
                .expect("serialize composed SCIP fixture"),
        )
        .expect("write composed SCIP fixture");
        let poisoned_tmp = fixture._workspace.path().join("not-a-temp-directory");
        fs::write(&poisoned_tmp, b"ordinary file").expect("poisoned TMPDIR fixture");

        let output = std::process::Command::new(
            std::env::current_exe().expect("current unit-test executable"),
        )
        .args([
            "--exact",
            "scip_normalizer::tests::composed_artifact_without_temp_workspace_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("H00_COMPOSED_ARTIFACT_NO_TEMP_CHILD", "1")
        .env("H00_COMPOSED_ARTIFACT_ROOT", &fixture.root)
        .env("H00_COMPOSED_ARTIFACT_INPUT", &fixture.artifact)
        .env("TMPDIR", &poisoned_tmp)
        .output()
        .expect("run isolated composed-artifact scratch child");
        assert!(
            output.status.success(),
            "in-memory composition must ignore unusable process TMPDIR; \
             stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert_eq!(
            fs::read(&poisoned_tmp).expect("poisoned TMPDIR remains readable"),
            b"ordinary file",
            "normalization must not replace or mutate the process temporary path"
        );
    }

    /// FALSIFIER: the executable version observed by the product and the tool
    /// version stamped into the admitted artifact are one provider coordinate.
    /// Name-only admission would attribute one executable's output to another
    /// version in the capability receipt and canonical snapshot.
    #[test]
    fn artifact_metadata_version_must_match_executed_provider_version() {
        let fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                RUST_SOURCE,
                0,
                1,
                "rust fixture target().",
                "rust fixture caller().",
            )],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        fs::write(
            &fixture.artifact,
            fixture
                .index
                .write_to_bytes()
                .expect("serialize version-bound artifact"),
        )
        .expect("write version-bound artifact");
        let normalize = |executed_provider_version: &str| {
            normalize_scip_artifact_set_for_inventory_coverage(
                &fixture.root,
                fixture.spec,
                &[ScipArtifactInput {
                    artifact_path: fixture.artifact.clone(),
                    execution_root: fixture.root.clone(),
                    executed_provider_version: executed_provider_version.into(),
                    provider_configuration_sha256: "a".repeat(64),
                }],
                &fixture.indexed_sources,
                &fixture.inventory,
            )
        };

        let matched = normalize("fixture-provider-1.0.0");
        assert_eq!(
            matched.evidence.receipt.status,
            CapabilityStatus::Complete,
            "positive control: the exact artifact/executable version pair is admissible"
        );
        let mismatched = normalize("fixture-provider-2.0.0");
        assert_failure(
            &mismatched.evidence,
            CapabilityStatus::Unavailable,
            "provider_identity_mismatch",
        );
        assert!(
            mismatched.canonical_snapshot.is_none(),
            "a mismatched provider artifact cannot become affected-export lineage"
        );
    }

    #[test]
    fn execution_root_replacement_retains_siblings_and_rejects_wrong_authority() {
        const ALPHA_BEFORE: &str = "package alpha\nfunc Alpha() int { return 1 }\n";
        const ALPHA_AFTER: &str = "package alpha\nfunc Alpha() int { return 2 }\n";
        const BETA: &str = "package beta\nfunc Beta() int { return 1 }\n";

        let workspace = TempDir::new().expect("root replacement workspace");
        let root = workspace.path().join("repo");
        let alpha_root = root.join("alpha");
        let beta_root = root.join("beta");
        fs::create_dir_all(&alpha_root).expect("alpha root");
        fs::create_dir_all(&beta_root).expect("beta root");

        let metadata = |project_root: &Path| {
            let mut tool = ToolInfo::new();
            tool.name = "scip-go".into();
            tool.version = "fixture-provider-1.0.0".into();
            let mut metadata = Metadata::new();
            metadata.tool_info = protobuf::MessageField::some(tool);
            metadata.project_root = format!("file://{}", project_root.display());
            metadata.text_document_encoding = EnumOrUnknown::new(TextEncoding::UTF8);
            metadata
        };
        let mut baseline = Index::new();
        baseline.metadata = protobuf::MessageField::some(metadata(&root));
        baseline.documents = vec![
            go_document_with_function_definitions(
                "alpha/module.go",
                ALPHA_BEFORE,
                &[("Alpha", "go fixture alpha/Alpha().")],
            ),
            go_document_with_function_definitions(
                "beta/module.go",
                BETA,
                &[("Beta", "go fixture beta/Beta().")],
            ),
        ];
        let snapshot = CanonicalScipSnapshot::from_composed_index(
            fs::canonicalize(&root).expect("canonical repository root"),
            CanonicalScipProviderCoordinate::new(
                ScipProviderSpec::scip_go(),
                "fixture-provider-1.0.0",
                None,
                BTreeMap::from([
                    ("alpha".into(), "a".repeat(64)),
                    ("beta".into(), "b".repeat(64)),
                ]),
            )
            .expect("canonical provider coordinate"),
            CapabilityScope::Language {
                language_id: LanguageId::new("go"),
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            },
            BTreeSet::from(["alpha".into(), "beta".into()]),
            baseline,
        )
        .expect("canonical multi-root baseline");
        let beta_before = snapshot
            .document_bytes("beta/module.go")
            .expect("baseline beta document");

        let mut replacement = Index::new();
        replacement.metadata = protobuf::MessageField::some(metadata(&alpha_root));
        replacement.documents = vec![go_document_with_function_definitions(
            "module.go",
            ALPHA_AFTER,
            &[("Alpha", "go fixture alpha/Alpha().")],
        )];
        let artifact_path = workspace.path().join("alpha.scip");
        fs::write(
            &artifact_path,
            replacement
                .write_to_bytes()
                .expect("serialize alpha replacement"),
        )
        .expect("write alpha replacement");
        let input = ScipArtifactInput {
            artifact_path,
            execution_root: alpha_root.clone(),
            executed_provider_version: "fixture-provider-1.0.0".into(),
            provider_configuration_sha256: "a".repeat(64),
        };
        let replaced = snapshot
            .replace_execution_root_artifact(&input)
            .expect("replace alpha root");
        assert_ne!(
            replaced.document_bytes("alpha/module.go"),
            snapshot.document_bytes("alpha/module.go"),
            "changed root must replace its canonical provider document"
        );
        assert_eq!(
            replaced.document_bytes("beta/module.go"),
            Some(beta_before),
            "unchanged sibling root must remain byte-identical"
        );

        let mut canonical_replacement_index = Index::new();
        canonical_replacement_index.metadata = protobuf::MessageField::some(metadata(&root));
        canonical_replacement_index.documents = vec![go_document_with_function_definitions(
            "alpha/module.go",
            ALPHA_AFTER,
            &[("Alpha", "go fixture alpha/Alpha().")],
        )];
        let canonical_replacement = CanonicalScipSnapshot::from_composed_index(
            fs::canonicalize(&root).expect("canonical repository root"),
            CanonicalScipProviderCoordinate::new(
                ScipProviderSpec::scip_go(),
                "fixture-provider-1.0.0",
                None,
                BTreeMap::from([("alpha".into(), "c".repeat(64))]),
            )
            .expect("replacement provider coordinate"),
            CapabilityScope::Language {
                language_id: LanguageId::new("go"),
                configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
            },
            BTreeSet::from(["alpha".into()]),
            canonical_replacement_index,
        )
        .expect("canonical alpha replacement");
        let partition_replaced = snapshot
            .replace_execution_root_partitions(&canonical_replacement)
            .expect("replace canonical alpha partition");
        assert_ne!(
            partition_replaced.document_bytes("alpha/module.go"),
            snapshot.document_bytes("alpha/module.go"),
            "changed canonical root must replace its provider document"
        );
        assert_eq!(
            partition_replaced.document_bytes("beta/module.go"),
            snapshot.document_bytes("beta/module.go"),
            "canonical root replacement must retain sibling bytes"
        );
        assert_eq!(
            partition_replaced
                .provider_configuration_sha256_for_execution_root(&alpha_root)
                .expect("alpha configuration lookup"),
            Some("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            "root-local recertification may update only that root's configuration identity"
        );

        let mut wrong_configuration = input;
        wrong_configuration.provider_configuration_sha256 = "c".repeat(64);
        let error = match snapshot.replace_execution_root_artifact(&wrong_configuration) {
            Ok(_) => panic!("wrong root configuration must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("configuration differs"),
            "unexpected root-configuration error: {error}"
        );
    }

    #[test]
    fn successful_project_unit_with_omitted_build_variant_stays_qualified() {
        const A_SOURCE: &str = "package alpha\nfunc Alpha() {}\n";
        const A_OMITTED_SOURCE: &str = concat!(
            "//go:build darwin\n",
            "package alpha\n",
            "func DarwinOnly() {}\n",
        );
        const B_SOURCE: &str = "package beta\nfunc Beta() {}\n";

        let workspace = TempDir::new().expect("scratch workspace");
        let root = workspace.path().join("repo");
        let alpha_root = root.join("alpha");
        let beta_root = root.join("beta");
        for (module_root, module_path) in [
            (&alpha_root, "example.invalid/alpha"),
            (&beta_root, "example.invalid/beta"),
        ] {
            fs::create_dir_all(module_root).expect("module root");
            fs::write(
                module_root.join("go.mod"),
                format!("module {module_path}\n\ngo 1.26\n"),
            )
            .expect("Go manifest");
        }
        fs::write(alpha_root.join("alpha.go"), A_SOURCE).expect("alpha source");
        fs::write(alpha_root.join("alpha_darwin.go"), A_OMITTED_SOURCE)
            .expect("qualified alpha source");
        fs::write(beta_root.join("beta.go"), B_SOURCE).expect("beta source");

        let sources = [
            ("alpha/alpha.go", A_SOURCE),
            ("alpha/alpha_darwin.go", A_OMITTED_SOURCE),
            ("beta/beta.go", B_SOURCE),
        ];
        let indexed_sources = sources
            .iter()
            .map(|(relative_path, source)| IndexedSourceEvidence {
                relative_path: (*relative_path).into(),
                language: "go".into(),
                blake3_hash: blake3::hash(source.as_bytes()).to_hex().to_string(),
                cross_document_surface_sha256: Some(sha256_hex(source.as_bytes())),
            })
            .collect::<Vec<_>>();
        let inventory = build_project_inventory(
            &root,
            &sources
                .iter()
                .map(|(relative_path, _)| InventorySource::new(*relative_path, "go"))
                .collect::<Vec<_>>(),
        );

        let write_artifact = |artifact_path: &Path, execution_root: &Path, document: Document| {
            let mut tool = ToolInfo::new();
            tool.name = "scip-go".into();
            tool.version = "fixture-provider-1.0.0".into();
            let mut metadata = Metadata::new();
            metadata.tool_info = protobuf::MessageField::some(tool);
            metadata.project_root = format!("file://{}", execution_root.display());
            metadata.text_document_encoding = EnumOrUnknown::new(TextEncoding::UTF8);
            let mut index = Index::new();
            index.metadata = protobuf::MessageField::some(metadata);
            index.documents = vec![document];
            let mut external = SymbolInformation::new();
            external.symbol = "external fixture residue.".into();
            external.display_name = "fixture_residue".into();
            index.external_symbols.push(external);
            fs::write(
                artifact_path,
                index.write_to_bytes().expect("serialize SCIP fixture"),
            )
            .expect("write SCIP fixture");
        };
        let alpha_artifact = workspace.path().join("alpha.scip");
        write_artifact(
            &alpha_artifact,
            &alpha_root,
            go_document_with_function_definitions(
                "alpha.go",
                A_SOURCE,
                &[("Alpha", "go fixture alpha/Alpha().")],
            ),
        );
        let beta_artifact = workspace.path().join("beta.scip");
        write_artifact(
            &beta_artifact,
            &beta_root,
            go_document_with_function_definitions(
                "beta.go",
                B_SOURCE,
                &[("Beta", "go fixture beta/Beta().")],
            ),
        );
        let normalization = normalize_scip_artifact_set_for_inventory_coverage(
            &root,
            ScipProviderSpec::scip_go(),
            &[
                ScipArtifactInput {
                    artifact_path: alpha_artifact,
                    execution_root: alpha_root,
                    executed_provider_version: "fixture-provider-1.0.0".into(),
                    provider_configuration_sha256: "a".repeat(64),
                },
                ScipArtifactInput {
                    artifact_path: beta_artifact,
                    execution_root: beta_root,
                    executed_provider_version: "fixture-provider-1.0.0".into(),
                    provider_configuration_sha256: "b".repeat(64),
                },
            ],
            &indexed_sources,
            &inventory,
        );
        let canonical_snapshot = normalization
            .canonical_snapshot
            .as_ref()
            .expect("complete artifact set retains canonical snapshot");
        let canonical_snapshot_identity = canonical_snapshot.identity_sha256();
        assert!(
            !canonical_snapshot.has_external_symbols(),
            "composed residual state must not privilege unrelated protobuf residue from the first execution root"
        );
        let evidence = normalization.evidence;

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let CapabilityScope::ProjectUnits {
            project_unit_ids, ..
        } = &evidence.receipt.scope
        else {
            panic!("successful module roots require exact project-unit authority");
        };
        assert_eq!(
            project_unit_ids.len(),
            2,
            "an omitted build variant must not drop its successfully indexed module"
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("qualified Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(
            payload.canonical_snapshot_sha256.as_deref(),
            Some(canonical_snapshot_identity.as_str()),
            "immutable Calls evidence must seal the exact canonical snapshot used for projection"
        );
        assert!(payload.coverage_exclusions.iter().any(|exclusion| {
            exclusion.location.document_path == "alpha/alpha_darwin.go"
                && exclusion.reason_code == "provider_document_omitted"
        }));
        assert!(
            payload
                .documents
                .iter()
                .any(|document| document.document_path == "alpha/alpha_darwin.go"),
            "the omitted source remains explicitly accounted for"
        );
    }

    fn document_with_call(
        language: &str,
        relative_path: &str,
        source: &str,
        target_line_index: usize,
        caller_line_index: usize,
        target_symbol: &str,
        caller_symbol: &str,
    ) -> Document {
        let target_line = source.lines().nth(target_line_index).expect("target line");
        let caller_line = source.lines().nth(caller_line_index).expect("caller line");
        let target_definition_column = target_line.find("target").expect("target definition");
        let caller_definition_column = caller_line.find("caller").expect("caller definition");
        let call_column = caller_line.rfind("target").expect("target call");

        let mut target_definition = Occurrence::new();
        target_definition.symbol = target_symbol.into();
        target_definition.symbol_roles = SymbolRole::Definition.value();
        target_definition.range = vec![
            target_line_index as i32,
            target_definition_column as i32,
            (target_definition_column + 6) as i32,
        ];
        target_definition.enclosing_range = vec![
            target_line_index as i32,
            0,
            target_line_index as i32,
            target_line.len() as i32,
        ];

        let mut caller_definition = Occurrence::new();
        caller_definition.symbol = caller_symbol.into();
        caller_definition.symbol_roles = SymbolRole::Definition.value();
        caller_definition.range = vec![
            caller_line_index as i32,
            caller_definition_column as i32,
            (caller_definition_column + 6) as i32,
        ];
        caller_definition.enclosing_range = vec![
            caller_line_index as i32,
            0,
            caller_line_index as i32,
            caller_line.len() as i32,
        ];

        let mut call = Occurrence::new();
        call.symbol = target_symbol.into();
        call.range = vec![
            caller_line_index as i32,
            call_column as i32,
            (call_column + 6) as i32,
        ];

        let mut target_information = SymbolInformation::new();
        target_information.symbol = target_symbol.into();
        target_information.display_name = "target".into();
        target_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);
        let mut caller_information = SymbolInformation::new();
        caller_information.symbol = caller_symbol.into();
        caller_information.display_name = "caller".into();
        caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

        let mut document = Document::new();
        document.language = language.into();
        document.relative_path = relative_path.into();
        document.text = source.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![target_definition, caller_definition, call];
        document.symbols = vec![target_information, caller_information];
        document
    }

    fn python_document_with_definitions(
        relative_path: &str,
        source: &str,
        definitions: &[(usize, &str, &str, symbol_information::Kind)],
    ) -> Document {
        let mut occurrences = Vec::with_capacity(definitions.len());
        let mut symbols = Vec::with_capacity(definitions.len());
        for (line_index, name, symbol, kind) in definitions {
            let line = source.lines().nth(*line_index).expect("definition line");
            let column = line.find(name).expect("definition name") as i32;
            let mut occurrence = Occurrence::new();
            occurrence.symbol = (*symbol).into();
            occurrence.symbol_roles = SymbolRole::Definition.value();
            occurrence.range = vec![
                *line_index as i32,
                column,
                column + i32::try_from(name.len()).expect("definition name length"),
            ];
            occurrences.push(occurrence);

            let mut information = SymbolInformation::new();
            information.symbol = (*symbol).into();
            information.display_name = (*name).into();
            information.kind = EnumOrUnknown::new(*kind);
            symbols.push(information);
        }

        let mut document = Document::new();
        document.language = "python".into();
        document.relative_path = relative_path.into();
        document.text = source.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = occurrences;
        document.symbols = symbols;
        document
    }

    fn go_document_with_function_definitions(
        relative_path: &str,
        source: &str,
        definitions: &[(&str, &str)],
    ) -> Document {
        let mut occurrences = Vec::new();
        let mut symbols = Vec::new();
        for (name, symbol) in definitions {
            let (line_index, line) = source
                .lines()
                .enumerate()
                .find(|(_, line)| line.contains(&format!("func {name}")))
                .unwrap_or_else(|| panic!("function {name:?} in fixture source"));
            let column = line.find(name).expect("function name column") as i32;

            let mut definition = Occurrence::new();
            definition.symbol = (*symbol).into();
            definition.symbol_roles = SymbolRole::Definition.value();
            definition.range = vec![line_index as i32, column, column + name.len() as i32];
            definition.enclosing_range =
                vec![line_index as i32, 0, line_index as i32, line.len() as i32];
            occurrences.push(definition);

            let mut information = SymbolInformation::new();
            information.symbol = (*symbol).into();
            information.display_name = (*name).into();
            information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);
            symbols.push(information);
        }

        let mut document = Document::new();
        document.language = "go".into();
        document.relative_path = relative_path.into();
        document.text = source.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = occurrences;
        document.symbols = symbols;
        document
    }

    fn assert_failure(
        evidence: &ScipArtifactEvidence,
        status: CapabilityStatus,
        reason_code: &str,
    ) {
        assert_eq!(evidence.receipt.status, status);
        assert_eq!(evidence.receipt.reason_code.as_deref(), Some(reason_code));
        assert!(
            evidence.payload.is_none(),
            "non-complete evidence must never carry a payload"
        );
    }

    fn byte_column_as_units(source: &str, byte_column: usize, encoding: PositionEncoding) -> i32 {
        let prefix = &source[..byte_column];
        match encoding {
            PositionEncoding::UTF8CodeUnitOffsetFromLineStart => byte_column as i32,
            PositionEncoding::UTF16CodeUnitOffsetFromLineStart => {
                prefix.encode_utf16().count() as i32
            }
            PositionEncoding::UTF32CodeUnitOffsetFromLineStart => prefix.chars().count() as i32,
            PositionEncoding::UnspecifiedPositionEncoding => unreachable!("test encoding"),
        }
    }

    #[test]
    fn utf8_utf16_and_utf32_positions_normalize_to_the_same_utf8_span() {
        let source = "let café = \"🙂\"; target();\n";
        let start = source.find("target").expect("target byte column");
        let end = start + "target".len();
        let expected = NormalizedSourceSpan {
            start_byte: start as u64,
            end_byte: end as u64,
            start_line: 0,
            start_utf8_byte_column: start as u32,
            end_line: 0,
            end_utf8_byte_column: end as u32,
        };

        for encoding in [
            PositionEncoding::UTF8CodeUnitOffsetFromLineStart,
            PositionEncoding::UTF16CodeUnitOffsetFromLineStart,
            PositionEncoding::UTF32CodeUnitOffsetFromLineStart,
        ] {
            let mut document = Document::new();
            document.relative_path = "src/lib.rs".into();
            document.position_encoding = EnumOrUnknown::new(encoding);
            let range = vec![
                0,
                byte_column_as_units(source, start, encoding),
                byte_column_as_units(source, end, encoding),
            ];
            assert_eq!(
                normalized_span(&document, source.as_bytes(), &range).expect("valid encoded span"),
                expected
            );
        }
    }

    #[test]
    fn invalid_unknown_and_split_code_unit_positions_fail_closed() {
        let source = "🙂target\n";
        let mut document = Document::new();
        document.relative_path = "src/lib.rs".into();

        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        let utf8_split = normalized_span(&document, source.as_bytes(), &[0, 1, 4])
            .expect_err("UTF-8 split must fail");
        assert_eq!(utf8_split.code, "provider_range_out_of_bounds");

        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF16CodeUnitOffsetFromLineStart);
        let utf16_split = normalized_span(&document, source.as_bytes(), &[0, 1, 2])
            .expect_err("UTF-16 surrogate split must fail");
        assert_eq!(utf16_split.code, "provider_range_out_of_bounds");

        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UnspecifiedPositionEncoding);
        let unspecified = normalized_span(&document, source.as_bytes(), &[0, 0, 2])
            .expect_err("unspecified positions must fail");
        assert_eq!(unspecified.code, "provider_position_encoding_unspecified");

        document.position_encoding = EnumOrUnknown::from_i32(99);
        let unknown = normalized_span(&document, source.as_bytes(), &[0, 0, 2])
            .expect_err("unknown positions must fail");
        assert_eq!(unknown.code, "provider_position_encoding_unknown");

        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        assert_eq!(
            normalized_span(&document, source.as_bytes(), &[9, 0, 1])
                .expect_err("missing line must fail")
                .code,
            "provider_range_out_of_bounds"
        );
        assert_eq!(
            normalized_span(&document, source.as_bytes(), &[0, 5, 4])
                .expect_err("reversed range must fail")
                .code,
            "provider_range_reversed"
        );
        assert_eq!(
            normalized_span(&document, source.as_bytes(), &[0, 0])
                .expect_err("malformed range must fail")
                .code,
            "provider_range_invalid"
        );
    }

    #[test]
    fn zero_call_callable_definition_remains_provider_addressable() {
        const SOURCE: &str = "pub fn orphan_accessor() -> u32 { 42 }\n";
        const SYMBOL: &str = "rust fixture 0.1.0 lib/orphan_accessor().";
        let definition_column = SOURCE.find("orphan_accessor").expect("definition column");

        let mut definition = Occurrence::new();
        definition.symbol = SYMBOL.into();
        definition.symbol_roles = SymbolRole::Definition.value();
        definition.range = vec![
            0,
            definition_column as i32,
            (definition_column + "orphan_accessor".len()) as i32,
        ];
        definition.enclosing_range = vec![0, 0, SOURCE.trim_end().len() as i32];

        let mut information = SymbolInformation::new();
        information.symbol = SYMBOL.into();
        information.display_name = "orphan_accessor".into();
        information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = "src/lib.rs".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![definition];
        document.symbols = vec![information];

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(
            payload.calls.is_empty(),
            "positive control: no call was indexed"
        );
        assert_eq!(payload.symbols.len(), 1);
        assert_eq!(payload.symbols[0].provider_symbol_id, SYMBOL);
        assert_eq!(payload.symbols[0].name, "orphan_accessor");
    }

    #[test]
    fn registered_language_calls_emit_provider_isolated_complete_evidence() {
        let cases = [
            (
                ScipProviderSpec::rust_analyzer(),
                "src/lib.rs",
                RUST_SOURCE,
                0,
                1,
                "rust fixture 0.1.0 lib/target().",
                "rust fixture 0.1.0 lib/caller().",
            ),
            (
                ScipProviderSpec::scip_go(),
                "main.go",
                GO_SOURCE,
                1,
                2,
                "go fixture target().",
                "go fixture caller().",
            ),
            (
                ScipProviderSpec::pyrefly_sidecar(),
                "src/fixture.py",
                PYTHON_SOURCE,
                0,
                1,
                "pyrefly python fixture . target().",
                "pyrefly python fixture . caller().",
            ),
        ];

        for (spec, path, source, target_line, caller_line, target_symbol, caller_symbol) in cases {
            let document = document_with_call(
                spec.language,
                path,
                source,
                target_line,
                caller_line,
                target_symbol,
                caller_symbol,
            );
            let fixture = fixture(spec, vec![document], &[(path, source)]);
            let evidence = fixture.normalize();
            assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
            assert_eq!(
                evidence.receipt.provider_id.0, spec.provider_id,
                "provider identity must remain language-specific"
            );
            assert_eq!(
                evidence.receipt.provider_version.as_deref(),
                Some("fixture-provider-1.0.0")
            );
            let ProviderPayload::Calls(payload) =
                evidence.payload.expect("complete payload").into_payload()
            else {
                unreachable!("Calls fixture")
            };
            assert_eq!(payload.calls.len(), 1);
            assert_eq!(payload.calls[0].caller_symbol_id, caller_symbol);
            assert_eq!(payload.calls[0].callee_symbol_id, target_symbol);
            assert_eq!(payload.documents.len(), 1);
        }
    }

    /// RIGHT-REASON REGRESSION from installed-product dogfood: Python class
    /// objects are valid invocation targets even though the class definition
    /// is not itself a callable body. Conflating those two roles downgraded an
    /// otherwise exact Pyrefly payload whenever ordinary code constructed a
    /// local exception or class.
    #[test]
    fn python_class_construction_is_a_source_invocation_target() {
        const SOURCE: &str = "class Widget:\n    pass\n\ndef caller():\n    return Widget()\n";
        const CLASS: &str = "pyrefly python fixture . Widget#";
        const CALLER: &str = "pyrefly python fixture . caller().";

        let mut class_definition = Occurrence::new();
        class_definition.symbol = CLASS.into();
        class_definition.symbol_roles = SymbolRole::Definition.value();
        class_definition.range = vec![0, 6, 12];

        let mut caller_definition = Occurrence::new();
        caller_definition.symbol = CALLER.into();
        caller_definition.symbol_roles = SymbolRole::Definition.value();
        caller_definition.range = vec![3, 4, 10];

        let mut class_call = Occurrence::new();
        class_call.symbol = CLASS.into();
        class_call.range = vec![4, 11, 17];

        let mut class_information = SymbolInformation::new();
        class_information.symbol = CLASS.into();
        class_information.display_name = "Widget".into();
        class_information.kind = EnumOrUnknown::new(symbol_information::Kind::Class);
        let mut caller_information = SymbolInformation::new();
        caller_information.symbol = CALLER.into();
        caller_information.display_name = "caller".into();
        caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

        let mut document = Document::new();
        document.language = "python".into();
        document.relative_path = "src/fixture.py".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![class_definition, caller_definition, class_call];
        document.symbols = vec![class_information, caller_information];

        let fixture = fixture(
            ScipProviderSpec::pyrefly_sidecar(),
            vec![document],
            &[("src/fixture.py", SOURCE)],
        );
        let evidence = fixture.normalize();

        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "a provider-resolved Python class construction is exact Calls evidence: {:?}",
            evidence.receipt
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Python class-construction payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        assert_eq!(payload.calls[0].caller_symbol_id, CALLER);
        assert_eq!(payload.calls[0].callee_symbol_id, CLASS);
        let class = payload
            .symbols
            .iter()
            .find(|symbol| symbol.provider_symbol_id == CLASS)
            .expect("class invocation target remains provider-addressable");
        assert!(class.definition.is_some());
        assert_eq!(class.role, ProviderSymbolRole::SourceInvocationTarget);
        assert!(class.structural_extent.is_some());
        assert!(class.call_owner_extent.is_none());

        let extracted =
            crate::extractor::extract_file(&fixture.root.join("src/fixture.py"), &fixture.root)
                .expect("independently extract the Python structural graph");
        let mut graph = crate::graph::KnowledgeGraph::new();
        crate::edge_builder::build_graph(&[extracted], &mut graph)
            .expect("build the Python structural graph");
        let caller = graph
            .node_by_name("caller")
            .expect("structural caller")
            .memory_id;
        let class = graph
            .node_by_name("Widget")
            .expect("structural class invocation target")
            .memory_id;
        assert!(
            graph
                .find_edge_by_kind_mut(caller, class, crate::graph::EdgeKind::Calls)
                .is_none(),
            "positive control: structural extraction alone must not fabricate Calls"
        );

        let stats =
            crate::code_intel_calls::project_calls_payload_structural_join(&mut graph, &payload)
                .expect("join the provider-resolved class construction to structural identity");
        assert_eq!(stats.novel_edges, 1);
        let edge = graph
            .find_edge_by_kind_mut(caller, class, crate::graph::EdgeKind::Calls)
            .expect("projected Python class-construction edge");
        assert_eq!(edge.source, crate::graph::EdgeSource::Scip);
        assert_eq!(edge.scope, crate::graph::EdgeScope::Production);
    }

    /// RIGHT-REASON REGRESSION from real h00ligan dogfood: Pyrefly exports
    /// only references resolved to repository declarations. An external
    /// selector such as `dict.get` is therefore legitimately absent from its
    /// SCIP document. A repository method with the same terminal name must
    /// not turn that exact, bounded omission into language-wide payload loss.
    #[test]
    fn python_external_selector_name_collision_is_a_scoped_exclusion() {
        const SOURCE: &str = concat!(
            "class Local:\n",
            "    def get(self):\n",
            "        return 1\n",
            "\n",
            "def caller(body: dict):\n",
            "    return body.get(\"value\")\n",
        );
        const CLASS: &str = "pyrefly python fixture . Local#";
        const GET: &str = "pyrefly python fixture . Local#get().";
        const CALLER: &str = "pyrefly python fixture . caller().";

        let document = python_document_with_definitions(
            "src/fixture.py",
            SOURCE,
            &[
                (0, "Local", CLASS, symbol_information::Kind::Class),
                (1, "get", GET, symbol_information::Kind::Method),
                (4, "caller", CALLER, symbol_information::Kind::Function),
            ],
        );

        let evidence = fixture(
            ScipProviderSpec::pyrefly_sidecar(),
            vec![document],
            &[("src/fixture.py", SOURCE)],
        )
        .normalize();

        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "one exact external selector omission must not discard unrelated repository Calls: {evidence:#?}",
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("qualified Python Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.calls.is_empty());
        assert_eq!(payload.coverage_exclusions.len(), 1);
        assert_eq!(
            payload.coverage_exclusions[0].reason_code,
            "provider_method_call_unresolved"
        );
        let call_start = SOURCE.rfind("get").expect("external selector") as u64;
        assert_eq!(
            payload.coverage_exclusions[0].location.span.start_byte,
            call_start
        );
        assert_eq!(
            payload.coverage_exclusions[0].location.span.end_byte,
            call_start + "get".len() as u64
        );
    }

    /// RIGHT-REASON REGRESSION from ERA dogfood: the native TypeScript
    /// provider omits an optional external selector when the compiler has no
    /// repository symbol for it. A local callable with the same terminal name
    /// must not turn that receiver-unresolved syntax into a missing local call.
    /// The direct-call control proves that real local omissions still fail.
    #[test]
    fn typescript_unresolved_selector_name_collision_is_scoped_but_direct_call_is_not() {
        const STATUS: &str = "typescript npm fixture 0.1.0 src/fixture.mjs/status().";
        const CALLER: &str = "typescript npm fixture 0.1.0 src/fixture.mjs/caller().";
        fn definitions_only_document(source: &str) -> Document {
            let mut lines = source.lines();
            let status_line = lines.next().expect("status line");
            let caller_line = lines.next().expect("caller line");
            let status_column = status_line.find("status").expect("status definition") as i32;
            let caller_column = caller_line.find("caller").expect("caller definition") as i32;

            let mut status_definition = Occurrence::new();
            status_definition.symbol = STATUS.into();
            status_definition.symbol_roles = SymbolRole::Definition.value();
            status_definition.range = vec![0, status_column, status_column + 6];

            let mut caller_definition = Occurrence::new();
            caller_definition.symbol = CALLER.into();
            caller_definition.symbol_roles = SymbolRole::Definition.value();
            caller_definition.range = vec![1, caller_column, caller_column + 6];

            let mut status_information = SymbolInformation::new();
            status_information.symbol = STATUS.into();
            status_information.display_name = "status".into();
            status_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

            let mut caller_information = SymbolInformation::new();
            caller_information.symbol = CALLER.into();
            caller_information.display_name = "caller".into();
            caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

            let mut document = Document::new();
            document.language = "typescript".into();
            document.relative_path = "src/fixture.mjs".into();
            document.text = source.into();
            document.position_encoding =
                EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
            document.occurrences = vec![status_definition, caller_definition];
            document.symbols = vec![status_information, caller_information];
            document
        }

        const SELECTOR_SOURCE: &str = concat!(
            "function status() { return 200; }\n",
            "function caller(response) { return response?.status(); }\n",
        );
        let selector = fixture(
            ScipProviderSpec::typescript_native_sidecar(),
            vec![definitions_only_document(SELECTOR_SOURCE)],
            &[("src/fixture.mjs", SELECTOR_SOURCE)],
        )
        .normalize();
        assert_eq!(selector.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = selector
            .payload
            .expect("qualified TypeScript Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.calls.is_empty());
        assert_eq!(payload.coverage_exclusions.len(), 1);
        assert_eq!(
            payload.coverage_exclusions[0].reason_code,
            "provider_method_call_unresolved"
        );
        let selector_start = SELECTOR_SOURCE.rfind("status").expect("optional selector") as u64;
        assert_eq!(
            payload.coverage_exclusions[0].location.span.start_byte,
            selector_start
        );

        const DIRECT_SOURCE: &str = concat!(
            "function status() { return 200; }\n",
            "function caller() { return status(); }\n",
        );
        let direct = fixture(
            ScipProviderSpec::typescript_native_sidecar(),
            vec![definitions_only_document(DIRECT_SOURCE)],
            &[("src/fixture.mjs", DIRECT_SOURCE)],
        )
        .normalize();
        assert_failure(
            &direct,
            CapabilityStatus::Partial,
            "provider_call_occurrence_incomplete",
        );
    }

    #[test]
    fn python_bound_receiver_method_witness_is_narrow_and_non_vacuous() {
        const SOURCE: &str = concat!(
            "class Local:\n",
            "    def get(self):\n",
            "        return 1\n",
            "\n",
            "    def caller(self, body):\n",
            "        self.get()\n",
            "        body.get(\"value\")\n",
            "        self.session.get(\"value\")\n",
            "\n",
            "    @staticmethod\n",
            "    def static(self):\n",
            "        self.get()\n",
        );
        let syntax =
            source_call_evidence(SOURCE, "src/fixture.py", "python").expect("Python call census");
        let callee = |selector_start: usize, receiver_prefix: &str| {
            let start = selector_start + receiver_prefix.len();
            syntax
                .call_callees
                .get(&(start, start + "get".len()))
                .expect("censused selector")
        };

        let bound = SOURCE.find("self.get()").expect("bound receiver call");
        assert!(
            callee(bound, "self.").source_local_method_target,
            "positive control: a bound receiver targeting its source class method must fire"
        );
        let arbitrary = SOURCE.find("body.get").expect("arbitrary receiver call");
        assert!(!callee(arbitrary, "body.").source_local_method_target);
        let chained = SOURCE
            .find("self.session.get")
            .expect("chained receiver call");
        assert!(!callee(chained, "self.session.").source_local_method_target);
        let static_receiver = SOURCE.rfind("self.get()").expect("static receiver call");
        assert!(!callee(static_receiver, "self.").source_local_method_target);
    }

    #[test]
    fn python_bound_receiver_missing_local_method_occurrence_remains_partial() {
        const SOURCE: &str = concat!(
            "class Local:\n",
            "    def get(self):\n",
            "        return 1\n",
            "\n",
            "    def caller(self):\n",
            "        return self.get()\n",
        );
        const CLASS: &str = "pyrefly python fixture . Local#";
        const GET: &str = "pyrefly python fixture . Local#get().";
        const CALLER: &str = "pyrefly python fixture . Local#caller().";
        let definitions = [
            (0, "Local", CLASS, symbol_information::Kind::Class),
            (1, "get", GET, symbol_information::Kind::Method),
            (4, "caller", CALLER, symbol_information::Kind::Method),
        ];
        let document = python_document_with_definitions("src/fixture.py", SOURCE, &definitions);
        let omitted = fixture(
            ScipProviderSpec::pyrefly_sidecar(),
            vec![document],
            &[("src/fixture.py", SOURCE)],
        )
        .normalize();
        assert_failure(
            &omitted,
            CapabilityStatus::Partial,
            "provider_call_occurrence_incomplete",
        );

        let mut covered_document =
            python_document_with_definitions("src/fixture.py", SOURCE, &definitions);
        let call_line = SOURCE.lines().nth(5).expect("call line");
        let call_column = call_line.rfind("get").expect("covered call") as i32;
        let mut call = Occurrence::new();
        call.symbol = GET.into();
        call.range = vec![5, call_column, call_column + "get".len() as i32];
        covered_document.occurrences.push(call);
        let covered = fixture(
            ScipProviderSpec::pyrefly_sidecar(),
            vec![covered_document],
            &[("src/fixture.py", SOURCE)],
        )
        .normalize();
        assert_eq!(covered.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = covered
            .payload
            .expect("provider-covered local method payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        assert_eq!(payload.calls[0].caller_symbol_id, CALLER);
        assert_eq!(payload.calls[0].callee_symbol_id, GET);
        assert!(payload.coverage_exclusions.is_empty());
    }

    /// RIGHT-REASON REGRESSION from AEGIS: Pyrefly can resolve a call target
    /// while omitting the enclosing ordinary function's definition occurrence.
    /// Exact tree-sitter name/extent evidence still identifies one co-published
    /// structural caller; losing that positive call edge would make reachability
    /// classification incomplete for an analyzer-export detail.
    #[test]
    fn syntax_callable_owner_supplies_missing_provider_caller_definition() {
        const SOURCE: &str = "def target(): return 1\ndef caller(): return target()\n";
        const TARGET: &str = "pyrefly python fixture . target().";
        let mut document = python_document_with_definitions(
            "src/fixture.py",
            SOURCE,
            &[(0, "target", TARGET, symbol_information::Kind::Function)],
        );
        let call_line = SOURCE.lines().nth(1).expect("caller line");
        let call_column = call_line.rfind("target").expect("target call") as i32;
        let mut call = Occurrence::new();
        call.symbol = TARGET.into();
        call.range = vec![1, call_column, call_column + "target".len() as i32];
        document.occurrences.push(call);

        let evidence = fixture(
            ScipProviderSpec::pyrefly_sidecar(),
            vec![document],
            &[("src/fixture.py", SOURCE)],
        )
        .normalize();
        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "exact structural caller ownership must complete a provider-resolved call: {evidence:#?}"
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        assert_eq!(payload.calls[0].callee_symbol_id, TARGET);
        let caller = payload
            .symbols
            .iter()
            .find(|symbol| symbol.provider_symbol_id == payload.calls[0].caller_symbol_id)
            .expect("structurally witnessed caller symbol");
        assert_eq!(caller.name, "caller");
        assert_eq!(
            caller
                .structural_extent
                .as_ref()
                .expect("caller structural extent")
                .span
                .start_line,
            1
        );
    }

    #[test]
    fn syntax_callable_extent_owns_calls_when_provider_enclosing_range_is_too_narrow() {
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";
        let mut document =
            document_with_call("rust", "src/lib.rs", RUST_SOURCE, 0, 1, TARGET, CALLER);
        let caller_definition = document
            .occurrences
            .iter_mut()
            .find(|occurrence| {
                occurrence.symbol == CALLER
                    && occurrence.symbol_roles & SymbolRole::Definition.value() != 0
            })
            .expect("caller definition");
        caller_definition.enclosing_range = caller_definition.range.clone();

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", RUST_SOURCE)],
        )
        .normalize();

        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "tree-sitter source structure, not an undersized provider enclosing range, must own the call: {:?}",
            evidence.receipt
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        assert_eq!(payload.calls[0].caller_symbol_id, CALLER);
        assert_eq!(payload.calls[0].callee_symbol_id, TARGET);
    }

    #[test]
    fn provider_enclosing_range_cannot_replace_syntax_proof_of_caller_ownership() {
        const SOURCE: &str = concat!(
            "fn target() {}\n",
            "trait Owner { fn owner(); }\n",
            "fn caller() { target(); }\n",
        );
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        const OWNER: &str = "rust fixture 0.1.0 lib/Owner#owner().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";

        let mut target_definition = Occurrence::new();
        target_definition.symbol = TARGET.into();
        target_definition.symbol_roles = SymbolRole::Definition.value();
        target_definition.range = vec![0, 3, 9];
        target_definition.enclosing_range = vec![0, 0, 0, 14];

        let mut malformed_owner = Occurrence::new();
        malformed_owner.symbol = OWNER.into();
        malformed_owner.symbol_roles = SymbolRole::Definition.value();
        malformed_owner.range = vec![1, 0, 2];
        malformed_owner.enclosing_range = vec![0, 0, 2, 25];

        let call_column = SOURCE
            .lines()
            .nth(2)
            .expect("caller line")
            .rfind("target")
            .expect("target call") as i32;
        let mut call = Occurrence::new();
        call.symbol = TARGET.into();
        call.range = vec![2, call_column, call_column + 6];

        let information = |symbol: &str, name: &str, kind| {
            let mut information = SymbolInformation::new();
            information.symbol = symbol.into();
            information.display_name = name.into();
            information.kind = EnumOrUnknown::new(kind);
            information
        };

        let mut malformed = Document::new();
        malformed.language = "rust".into();
        malformed.relative_path = "src/lib.rs".into();
        malformed.text = SOURCE.into();
        malformed.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        malformed.occurrences = vec![target_definition, malformed_owner, call];
        malformed.symbols = vec![
            information(TARGET, "target", symbol_information::Kind::Function),
            information(OWNER, "owner", symbol_information::Kind::Method),
        ];

        assert_failure(
            &fixture(
                ScipProviderSpec::rust_analyzer(),
                vec![malformed],
                &[("src/lib.rs", SOURCE)],
            )
            .normalize(),
            CapabilityStatus::Partial,
            "provider_definition_span_mismatch",
        );

        let positive = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                SOURCE,
                0,
                2,
                TARGET,
                CALLER,
            )],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(positive.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = positive
            .payload
            .expect("positive Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        assert_eq!(payload.calls[0].caller_symbol_id, CALLER);
    }

    #[test]
    fn provider_macro_expansion_definition_cannot_claim_source_ownership() {
        const SOURCE: &str = concat!(
            "macro_rules! make_test { ($name:ident) => { fn $name() {} }; }\n",
            "make_test!(generated_roundtrip);\n",
        );
        const GENERATED: &str = "rust fixture 0.1.0 lib/generated_roundtrip().";
        let generated_start = SOURCE.find("generated_roundtrip").expect("macro argument") as i32;

        let syntax =
            source_call_evidence(SOURCE, "src/lib.rs", "rust").expect("valid macro fixture syntax");
        assert!(
            syntax
                .enclosing_generated_range(
                    generated_start as u64,
                    (generated_start as usize + "generated_roundtrip".len()) as u64,
                )
                .is_some(),
            "positive control: the provider definition token must lie inside a macro invocation"
        );

        let mut definition = Occurrence::new();
        definition.symbol = GENERATED.into();
        definition.symbol_roles = SymbolRole::Definition.value();
        definition.range = vec![
            1,
            "make_test!(".len() as i32,
            ("make_test!(".len() + "generated_roundtrip".len()) as i32,
        ];
        definition.enclosing_range = vec![0, 0, 1, 32];

        let mut information = SymbolInformation::new();
        information.symbol = GENERATED.into();
        information.display_name = "generated_roundtrip".into();
        information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = "src/lib.rs".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![definition];
        document.symbols = vec![information];

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.symbols.is_empty());
        assert!(payload.calls.is_empty());
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(|exclusion| exclusion.reason_code != "macro_expansion"),
            "generated definitions are outside the explicit source-invocation population, not a global coverage hole: {:?}",
            payload.coverage_exclusions
        );
    }

    #[test]
    fn provider_inactive_cfg_callable_is_outside_the_named_caller_population() {
        const SOURCE: &str = concat!(
            "fn target() {}\n",
            "#[cfg(not(feature = \"code-intel\"))]\n",
            "fn caller() { target(); }\n",
        );
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";
        let syntax = source_call_evidence(SOURCE, "src/lib.rs", "rust")
            .expect("valid conditional Rust source");
        let call_start = SOURCE.rfind("target").expect("target call") as u64;
        assert!(
            syntax
                .conditional_ranges
                .iter()
                .any(|(start, end)| *start <= call_start && call_start < *end),
            "positive control: the cfg-decorated caller must be identified"
        );

        let mut document = document_with_call("rust", "src/lib.rs", SOURCE, 0, 2, TARGET, CALLER);
        document.occurrences.retain(|occurrence| {
            occurrence.symbol != CALLER
                || occurrence.symbol_roles & SymbolRole::Definition.value() == 0
        });
        document
            .symbols
            .retain(|information| information.symbol != CALLER);

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "a reference emitted from a cfg-inactive function without a provider caller definition is outside the named-caller population: {:?}",
            evidence.receipt
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.calls.is_empty());
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .any(|exclusion| exclusion.reason_code == "conditional_compilation")
        );
    }

    #[test]
    fn cfg_attr_that_applies_cfg_marks_the_callable_as_conditional() {
        const SOURCE: &str = concat!(
            "fn target() {}\n",
            "#[cfg_attr(feature = \"outer\", cfg(feature = \"inner\"))]\n",
            "fn caller() { target(); }\n",
        );
        let syntax = source_call_evidence(SOURCE, "src/lib.rs", "rust")
            .expect("valid cfg_attr-decorated Rust source");
        let call_start = SOURCE.rfind("target").expect("target call") as u64;
        assert!(
            syntax
                .conditional_ranges
                .iter()
                .any(|(start, end)| *start <= call_start && call_start < *end),
            "cfg_attr can apply cfg and omit the entire callable from provider evidence"
        );

        const NON_CONDITIONAL: &str = concat!(
            "fn target() {}\n",
            "#[cfg_attr(feature = \"outer\", inline)]\n",
            "fn caller() { target(); }\n",
        );
        let syntax = source_call_evidence(NON_CONDITIONAL, "src/lib.rs", "rust")
            .expect("valid non-cfg cfg_attr source");
        let call_start = NON_CONDITIONAL.rfind("target").expect("target call") as u64;
        assert!(
            syntax
                .conditional_ranges
                .iter()
                .all(|(start, end)| !(start <= &call_start && call_start < *end)),
            "an unrelated cfg_attr must not manufacture a conditional-coverage exclusion"
        );
    }

    #[test]
    fn provider_covered_cfg_callable_does_not_create_a_coverage_exclusion() {
        const SOURCE: &str = concat!(
            "fn target() {}\n",
            "#[cfg(feature = \"indexed\")]\n",
            "fn caller() { target(); }\n",
        );
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";
        let syntax = source_call_evidence(SOURCE, "src/lib.rs", "rust")
            .expect("valid conditional Rust source");
        assert!(
            !syntax.conditional_ranges.is_empty(),
            "positive control: the cfg-decorated callable must be identified"
        );

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                SOURCE,
                0,
                2,
                TARGET,
                CALLER,
            )],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(
            payload.calls.len(),
            1,
            "provider-covered call remains queryable"
        );
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(|exclusion| exclusion.reason_code != "conditional_compilation"),
            "cfg syntax alone is not evidence of omitted semantic coverage: {:?}",
            payload.coverage_exclusions
        );
    }

    #[test]
    fn harmless_macro_does_not_create_a_coverage_exclusion() {
        const SOURCE: &str = concat!(
            "fn target() {}\n",
            "fn caller() { assert!(true); target(); }\n",
        );
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";
        let syntax = source_call_evidence(SOURCE, "src/lib.rs", "rust")
            .expect("valid macro-containing Rust source");
        assert!(
            !syntax.generated_ranges.is_empty(),
            "positive control: the macro invocation must be identified"
        );

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                SOURCE,
                0,
                1,
                TARGET,
                CALLER,
            )],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(
            payload.calls.len(),
            1,
            "provider-covered call remains queryable"
        );
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(|exclusion| exclusion.reason_code != "macro_expansion"),
            "an unrelated macro is not evidence of omitted Calls coverage: {:?}",
            payload.coverage_exclusions
        );
    }

    #[test]
    fn non_callable_provider_reference_inside_macro_does_not_qualify_calls() {
        const SOURCE: &str = concat!(
            "fn target() {}\n",
            "fn caller() { let x = 1; println!(\"{x}\"); target(); }\n",
        );
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";
        const VARIABLE: &str = "rust fixture 0.1.0 lib/x.";
        let line = SOURCE.lines().nth(1).expect("caller line");
        let definition_column = line.find("x =").expect("variable definition") as i32;
        let reference_column = (line.find("{x}").expect("macro reference") + 1) as i32;

        let mut variable_definition = Occurrence::new();
        variable_definition.symbol = VARIABLE.into();
        variable_definition.symbol_roles = SymbolRole::Definition.value();
        variable_definition.range = vec![1, definition_column, definition_column + 1];
        let mut variable_reference = Occurrence::new();
        variable_reference.symbol = VARIABLE.into();
        variable_reference.range = vec![1, reference_column, reference_column + 1];
        let mut variable_information = SymbolInformation::new();
        variable_information.symbol = VARIABLE.into();
        variable_information.display_name = "x".into();
        variable_information.kind = EnumOrUnknown::new(symbol_information::Kind::Variable);

        let mut document = document_with_call("rust", "src/lib.rs", SOURCE, 0, 1, TARGET, CALLER);
        document.occurrences.push(variable_definition);
        document.occurrences.push(variable_reference);
        document.symbols.push(variable_information);

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(|exclusion| exclusion.reason_code != "macro_expansion"),
            "a non-callable value reference inside a macro is not omitted caller evidence: {:?}",
            payload.coverage_exclusions
        );
    }

    #[test]
    fn provider_resolved_explicit_invocation_inside_macro_is_a_call() {
        const SOURCE: &str = concat!(
            "fn target() {}\n",
            "fn caller() { wrapper!(target /* outer /* nested */ trivia */ ()); }\n",
        );
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                SOURCE,
                0,
                1,
                TARGET,
                CALLER,
            )],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(
            payload.calls.len(),
            1,
            "provider-resolved explicit invocation syntax remains a call inside a macro token tree"
        );
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(|exclusion| exclusion.reason_code != "macro_expansion"),
            "an admitted explicit source invocation must not poison authority for its whole macro: {:?}",
            payload.coverage_exclusions
        );
    }

    #[test]
    fn macro_invocation_admission_never_reads_past_the_invocation_range() {
        const SOURCE: &str = "wrapper!(target)(argument)";
        let macro_end = SOURCE.find(")(").expect("macro boundary") + 1;

        assert!(
            !rust_macro_occurrence_has_explicit_arguments(
                SOURCE.as_bytes(),
                macro_end as u64,
                macro_end as u64,
            ),
            "a provider occurrence ending at the macro boundary must not borrow the following argument list"
        );
    }

    #[test]
    fn zero_width_provider_occurrence_inside_macro_is_skipped() {
        const SOURCE: &str = concat!("fn target() {}\n", "fn caller() { wrapper!(target()); }\n",);
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";
        let caller_line = SOURCE.lines().nth(1).expect("caller line");
        let before_arguments = caller_line.rfind("target").expect("macro target") + 6;
        let mut document = document_with_call("rust", "src/lib.rs", SOURCE, 0, 1, TARGET, CALLER);
        document
            .occurrences
            .last_mut()
            .expect("provider reference")
            .range = vec![1, before_arguments as i32, before_arguments as i32];

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "a malformed zero-width provider artifact is outside the invocation population, not a language-wide outage: {:?}",
            evidence.receipt
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.calls.is_empty());
    }

    #[test]
    fn bare_callable_macro_argument_is_neither_a_call_nor_an_authority_exclusion() {
        const SOURCE: &str = concat!("fn target() {}\n", "fn caller() { wrapper!(target); }\n",);
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                SOURCE,
                0,
                1,
                TARGET,
                CALLER,
            )],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(
            payload.calls.is_empty(),
            "a callable token passed to a macro is not an explicit invocation"
        );
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(|exclusion| exclusion.reason_code != "macro_expansion"),
            "syntax outside the named invocation population must not qualify global authority: {:?}",
            payload.coverage_exclusions
        );
    }

    #[test]
    fn common_macro_invocations_do_not_create_blanket_coverage_exclusions() {
        const SOURCE: &str = concat!(
            "fn target() -> bool { true }\n",
            "fn caller() { assert!(target()); let _ = format!(\"{}\", target()); }\n",
        );
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";
        let line = SOURCE.lines().nth(1).expect("caller line");
        let first_call = line.find("target").expect("assert target") as i32;
        let mut document = document_with_call("rust", "src/lib.rs", SOURCE, 0, 1, TARGET, CALLER);
        let mut occurrence = Occurrence::new();
        occurrence.symbol = TARGET.into();
        occurrence.range = vec![1, first_call, first_call + 6];
        document.occurrences.push(occurrence);

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(
            payload.calls.len(),
            2,
            "both provider-resolved explicit invocations are in the named population"
        );
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(|exclusion| exclusion.reason_code != "macro_expansion"),
            "ordinary macros must not make every repository query qualified: {:?}",
            payload.coverage_exclusions
        );
    }

    #[test]
    fn rust_macro_token_tree_is_not_source_call_syntax() {
        const SOURCE: &str = concat!("fn target() {}\n", "fn caller() { wrapper!(target()); }\n",);
        let syntax = source_call_evidence(SOURCE, "src/lib.rs", "rust")
            .expect("valid macro-containing Rust source");
        let target_start = SOURCE.rfind("target").expect("macro target") as u64;
        assert!(
            syntax
                .enclosing_generated_range(target_start, target_start + 6)
                .is_some(),
            "positive control: the token must be inside generated syntax"
        );
        assert!(
            syntax
                .call_callees
                .keys()
                .all(|(start, end)| !(*start as u64 <= target_start && target_start < *end as u64)),
            "Rust macro token trees are provider-reference evidence, not literal source call expressions"
        );
    }

    #[test]
    fn invocation_target_definition_without_symbol_information_is_not_complete_authority() {
        const SOURCE: &str = "fn target() {}\n";
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        let mut definition = Occurrence::new();
        definition.symbol = TARGET.into();
        definition.symbol_roles = SymbolRole::Definition.value();
        definition.range = vec![0, 3, 9];

        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = "src/lib.rs".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![definition];

        assert_failure(
            &fixture(
                ScipProviderSpec::rust_analyzer(),
                vec![document],
                &[("src/lib.rs", SOURCE)],
            )
            .normalize(),
            CapabilityStatus::Partial,
            "provider_invocation_target_information_missing",
        );
    }

    #[test]
    fn module_initializer_call_is_positive_root_invocation_evidence() {
        const SOURCE: &str = concat!(
            "const fn target() -> usize { 1 }\n",
            "const VALUE: usize = target();\n",
        );
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";

        let target_column = SOURCE.lines().next().unwrap().find("target").unwrap() as i32;
        let call_column = SOURCE.lines().nth(1).unwrap().find("target").unwrap() as i32;

        let mut definition = Occurrence::new();
        definition.symbol = TARGET.into();
        definition.symbol_roles = SymbolRole::Definition.value();
        definition.range = vec![0, target_column, target_column + 6];
        definition.enclosing_range = vec![0, 0, SOURCE.lines().next().unwrap().len() as i32];

        let mut call = Occurrence::new();
        call.symbol = TARGET.into();
        call.range = vec![1, call_column, call_column + 6];

        let mut information = SymbolInformation::new();
        information.symbol = TARGET.into();
        information.display_name = "target".into();
        information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = "src/lib.rs".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![definition, call];
        document.symbols = vec![information];

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "a source-level initializer is a known caller-shape exclusion, not evidence that the provider failed the entire language: {:?}",
            evidence.receipt
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.calls.is_empty());
        assert_eq!(payload.root_invocations.len(), 1);
        assert_eq!(payload.root_invocations[0].callee_symbol_id, TARGET);
        assert_eq!(payload.root_invocations[0].call_site.span.start_line, 1);
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(|exclusion| exclusion.reason_code != "module_initialization"),
            "a resolved source-root invocation is positive evidence, not an authority gap"
        );
    }

    #[test]
    fn provider_omission_inside_cfg_statement_is_not_a_coverage_gap() {
        const SOURCE: &str = concat!(
            "fn target() {}\n",
            "fn caller() { #[cfg(not(feature = \"code-intel\"))] target(); }\n",
        );
        const TARGET: &str = "rust fixture 0.1.0 lib/target().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";
        let syntax = source_call_evidence(SOURCE, "src/lib.rs", "rust")
            .expect("valid statement-level cfg source");
        let call_start = SOURCE.rfind("target").expect("target call") as u64;
        assert!(
            syntax
                .conditional_ranges
                .iter()
                .any(|(start, end)| *start <= call_start && call_start < *end),
            "positive control: the cfg-decorated statement must be identified: {:?}",
            syntax.conditional_ranges
        );

        let mut document = document_with_call("rust", "src/lib.rs", SOURCE, 0, 1, TARGET, CALLER);
        document
            .occurrences
            .retain(|occurrence| occurrence.symbol_roles & SymbolRole::Definition.value() != 0);
        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "an omitted call inside a cfg-inactive statement must not downgrade provider coverage: {:?}",
            evidence.receipt
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.calls.is_empty());
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .any(|exclusion| exclusion.reason_code == "conditional_compilation")
        );
    }

    #[test]
    fn same_name_definition_in_another_document_makes_omitted_coverage_ambiguous() {
        const FIRST_SOURCE: &str = "fn target() {}\n";
        const SECOND_SOURCE: &str = "fn caller() { target(); }\n";
        const TARGET: &str = "rust fixture 0.1.0 first/target().";
        const CALLER: &str = "rust fixture 0.1.0 second/caller().";

        let mut target_definition = Occurrence::new();
        target_definition.symbol = TARGET.into();
        target_definition.symbol_roles = SymbolRole::Definition.value();
        target_definition.range = vec![0, 3, 9];
        let mut target_information = SymbolInformation::new();
        target_information.symbol = TARGET.into();
        target_information.display_name = "target".into();
        target_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);
        let mut first = Document::new();
        first.language = "rust".into();
        first.relative_path = "src/first.rs".into();
        first.text = FIRST_SOURCE.into();
        first.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        first.occurrences = vec![target_definition];
        first.symbols = vec![target_information];

        let mut caller_definition = Occurrence::new();
        caller_definition.symbol = CALLER.into();
        caller_definition.symbol_roles = SymbolRole::Definition.value();
        caller_definition.range = vec![0, 3, 9];
        let mut caller_information = SymbolInformation::new();
        caller_information.symbol = CALLER.into();
        caller_information.display_name = "caller".into();
        caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);
        let mut second = Document::new();
        second.language = "rust".into();
        second.relative_path = "src/second.rs".into();
        second.text = SECOND_SOURCE.into();
        second.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        second.occurrences = vec![caller_definition];
        second.symbols = vec![caller_information];

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![first, second],
            &[
                ("src/first.rs", FIRST_SOURCE),
                ("src/second.rs", SECOND_SOURCE),
            ],
        )
        .normalize();
        assert_failure(
            &evidence,
            CapabilityStatus::Partial,
            "provider_call_occurrence_incomplete",
        );
    }

    #[test]
    fn unrelated_variable_name_does_not_create_repository_wide_call_authority() {
        const CALLER_SOURCE: &str = "fn caller(mutex: &std::sync::Mutex<()>) { mutex.lock(); }\n";
        const OTHER_SOURCE: &str = "fn witness() { let lock = 1; let _ = lock; }\n";

        let function_document = |path: &str, source: &str, name: &str, symbol: &str| {
            let definition_column = source.find(name).expect("function name") as i32;
            let mut definition = Occurrence::new();
            definition.symbol = symbol.into();
            definition.symbol_roles = SymbolRole::Definition.value();
            definition.range = vec![0, definition_column, definition_column + name.len() as i32];
            definition.enclosing_range = vec![0, 0, source.trim_end().len() as i32];

            let mut information = SymbolInformation::new();
            information.symbol = symbol.into();
            information.display_name = name.into();
            information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

            let mut document = Document::new();
            document.language = "rust".into();
            document.relative_path = path.into();
            document.text = source.into();
            document.position_encoding =
                EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
            document.occurrences = vec![definition];
            document.symbols = vec![information];
            document
        };

        let caller = function_document(
            "src/caller.rs",
            CALLER_SOURCE,
            "caller",
            "rust fixture caller().",
        );
        let mut other = function_document(
            "src/other.rs",
            OTHER_SOURCE,
            "witness",
            "rust fixture witness().",
        );
        let variable_column = OTHER_SOURCE.find("lock").expect("variable name") as i32;
        let mut variable_definition = Occurrence::new();
        variable_definition.symbol = "local 0".into();
        variable_definition.symbol_roles = SymbolRole::Definition.value();
        variable_definition.range = vec![0, variable_column, variable_column + "lock".len() as i32];
        let mut variable_information = SymbolInformation::new();
        variable_information.symbol = "local 0".into();
        variable_information.display_name = "lock".into();
        variable_information.kind = EnumOrUnknown::new(symbol_information::Kind::Variable);
        other.occurrences.push(variable_definition);
        other.symbols.push(variable_information);

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![caller, other],
            &[
                ("src/caller.rs", CALLER_SOURCE),
                ("src/other.rs", OTHER_SOURCE),
            ],
        )
        .normalize();

        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "an ordinary variable in another document cannot make an omitted external method call repository-local: {:?}",
            evidence.receipt,
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.calls.is_empty());
    }

    #[test]
    fn ambiguous_omitted_method_is_a_scoped_exclusion_not_payload_loss() {
        const LOCAL_SOURCE: &str = concat!(
            "struct Local;\n",
            "impl Local {\n",
            "    fn clone(&self) -> Self { Local }\n",
            "}\n",
        );
        const CALLER_SOURCE: &str = "fn caller(value: &std::sync::Arc<u8>) { value.clone(); }\n";

        let mut local_definition = Occurrence::new();
        local_definition.symbol = "rust-analyzer cargo fixture 0.1.0 lib/Local#clone().".into();
        local_definition.symbol_roles = SymbolRole::Definition.value();
        let local_line = LOCAL_SOURCE.lines().nth(2).expect("local method line");
        let local_column = local_line.find("clone").expect("local method name") as i32;
        local_definition.range = vec![2, local_column, local_column + "clone".len() as i32];
        let mut local_information = SymbolInformation::new();
        local_information.symbol = local_definition.symbol.clone();
        local_information.display_name = "clone".into();
        local_information.kind = EnumOrUnknown::new(symbol_information::Kind::Method);
        let mut local_document = Document::new();
        local_document.language = "rust".into();
        local_document.relative_path = "src/local.rs".into();
        local_document.text = LOCAL_SOURCE.into();
        local_document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        local_document.occurrences = vec![local_definition];
        local_document.symbols = vec![local_information];

        let mut caller_definition = Occurrence::new();
        caller_definition.symbol = "rust fixture caller().".into();
        caller_definition.symbol_roles = SymbolRole::Definition.value();
        let caller_column = CALLER_SOURCE.find("caller").expect("caller name") as i32;
        caller_definition.range = vec![0, caller_column, caller_column + "caller".len() as i32];
        caller_definition.enclosing_range = vec![0, 0, CALLER_SOURCE.trim_end().len() as i32];
        let mut caller_information = SymbolInformation::new();
        caller_information.symbol = caller_definition.symbol.clone();
        caller_information.display_name = "caller".into();
        caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);
        let mut caller_document = Document::new();
        caller_document.language = "rust".into();
        caller_document.relative_path = "src/caller.rs".into();
        caller_document.text = CALLER_SOURCE.into();
        caller_document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        caller_document.occurrences = vec![caller_definition];
        caller_document.symbols = vec![caller_information];

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![local_document, caller_document],
            &[
                ("src/local.rs", LOCAL_SOURCE),
                ("src/caller.rs", CALLER_SOURCE),
            ],
        )
        .normalize();

        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "one ambiguous method omission must not discard all provider-resolved Calls evidence: {:?}",
            evidence.receipt,
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("qualified Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.calls.is_empty());
        assert_eq!(payload.coverage_exclusions.len(), 1);
        assert_eq!(
            payload.coverage_exclusions[0].reason_code,
            "provider_method_call_unresolved"
        );
        assert_eq!(
            payload.coverage_exclusions[0].location.document_path,
            "src/caller.rs"
        );
        let call_start = CALLER_SOURCE.rfind("clone").expect("omitted method") as u64;
        assert_eq!(
            payload.coverage_exclusions[0].location.span.start_byte,
            call_start
        );
        assert_eq!(
            payload.coverage_exclusions[0].location.span.end_byte,
            call_start + "clone".len() as u64
        );
    }

    #[test]
    fn provider_resolved_receiver_owner_closes_unrelated_method_name_collision() {
        const LOCAL_SOURCE: &str = concat!(
            "struct Local;\n",
            "impl Local {\n",
            "    fn clone(&self) -> Self { Local }\n",
            "}\n",
        );
        const CALLER_SOURCE: &str = "fn caller(value: &std::sync::Arc<u8>) { value.clone(); }\n";

        let mut local_definition = Occurrence::new();
        local_definition.symbol = "rust-analyzer cargo fixture 0.1.0 lib/Local#clone().".into();
        local_definition.symbol_roles = SymbolRole::Definition.value();
        let local_line = LOCAL_SOURCE.lines().nth(2).expect("local method line");
        let local_column = local_line.find("clone").expect("local method name") as i32;
        local_definition.range = vec![2, local_column, local_column + "clone".len() as i32];
        let mut local_information = SymbolInformation::new();
        local_information.symbol = local_definition.symbol.clone();
        local_information.display_name = "clone".into();
        local_information.kind = EnumOrUnknown::new(symbol_information::Kind::Method);
        let mut local_document = Document::new();
        local_document.language = "rust".into();
        local_document.relative_path = "src/local.rs".into();
        local_document.text = LOCAL_SOURCE.into();
        local_document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        local_document.occurrences = vec![local_definition];
        local_document.symbols = vec![local_information];

        let mut caller_definition = Occurrence::new();
        caller_definition.symbol = "rust fixture caller().".into();
        caller_definition.symbol_roles = SymbolRole::Definition.value();
        let caller_column = CALLER_SOURCE.find("caller").expect("caller name") as i32;
        caller_definition.range = vec![0, caller_column, caller_column + "caller".len() as i32];
        caller_definition.enclosing_range = vec![0, 0, CALLER_SOURCE.trim_end().len() as i32];
        let mut caller_information = SymbolInformation::new();
        caller_information.symbol = caller_definition.symbol.clone();
        caller_information.display_name = "caller".into();
        caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

        let parameter_column = CALLER_SOURCE.find("value").expect("parameter name") as i32;
        let mut parameter_definition = Occurrence::new();
        parameter_definition.symbol = "local 0".into();
        parameter_definition.symbol_roles = SymbolRole::Definition.value();
        parameter_definition.range =
            vec![0, parameter_column, parameter_column + "value".len() as i32];
        let mut parameter_reference = Occurrence::new();
        parameter_reference.symbol = parameter_definition.symbol.clone();
        let receiver_column = CALLER_SOURCE.rfind("value").expect("receiver name") as i32;
        parameter_reference.range =
            vec![0, receiver_column, receiver_column + "value".len() as i32];
        let mut parameter_information = SymbolInformation::new();
        parameter_information.symbol = parameter_definition.symbol.clone();
        parameter_information.display_name = "value".into();
        parameter_information.kind = EnumOrUnknown::new(symbol_information::Kind::Parameter);

        let mut external_clone_information = SymbolInformation::new();
        external_clone_information.symbol = concat!(
            "rust-analyzer cargo alloc https://github.com/rust-lang/rust/library/alloc ",
            "sync/impl#[`Arc<T, A>`][Clone]clone().",
        )
        .into();
        external_clone_information.display_name = "clone".into();
        external_clone_information.kind = EnumOrUnknown::new(symbol_information::Kind::Method);

        let type_column = CALLER_SOURCE.find("Arc").expect("receiver type") as i32;
        let mut type_reference = Occurrence::new();
        type_reference.symbol =
            "rust-analyzer cargo alloc https://github.com/rust-lang/rust/library/alloc sync/Arc#"
                .into();
        type_reference.range = vec![0, type_column, type_column + "Arc".len() as i32];

        let mut caller_document = Document::new();
        caller_document.language = "rust".into();
        caller_document.relative_path = "src/caller.rs".into();
        caller_document.text = CALLER_SOURCE.into();
        caller_document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        caller_document.occurrences = vec![
            caller_definition,
            parameter_definition,
            parameter_reference,
            type_reference,
        ];
        caller_document.symbols = vec![
            caller_information,
            parameter_information,
            external_clone_information,
        ];

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![local_document, caller_document],
            &[
                ("src/local.rs", LOCAL_SOURCE),
                ("src/caller.rs", CALLER_SOURCE),
            ],
        )
        .normalize();

        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "provider-resolved receiver ownership must prove that Arc::clone cannot target Local::clone: {:?}",
            evidence.receipt,
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.calls.is_empty());
        assert!(
            payload.coverage_exclusions.is_empty(),
            "a proven external receiver is not an excluded local Calls region: {:?}",
            payload.coverage_exclusions,
        );
    }

    #[test]
    fn provider_resolved_source_owner_keeps_missing_method_occurrence_partial() {
        const SOURCE: &str = concat!(
            "struct Local;\n",
            "impl Local {\n",
            "    fn clone(&self) -> Self { Local }\n",
            "}\n",
            "fn caller(value: &Local) { value.clone(); }\n",
        );

        let syntax =
            source_call_evidence(SOURCE, "src/lib.rs", "rust").expect("source syntax evidence");
        let parameter_start = SOURCE.find("value").expect("parameter byte range");
        let type_start = SOURCE.find("&Local").expect("type byte range") + 1;
        assert_eq!(
            syntax
                .declared_type_names
                .get(&(parameter_start, parameter_start + "value".len())),
            Some(&(type_start, type_start + "Local".len())),
            "the existing syntax census must bind the parameter to its nominal type"
        );
        assert_eq!(
            rust_type_owner("rust-analyzer cargo fixture 0.1.0 lib/Local#")
                .expect("provider type owner"),
            rust_method_owner("rust-analyzer cargo fixture 0.1.0 lib/Local#clone().",)
                .expect("provider method owner"),
            "provider type and method symbols must identify the same nominal owner"
        );

        let mut clone_definition = Occurrence::new();
        clone_definition.symbol = "rust-analyzer cargo fixture 0.1.0 lib/Local#clone().".into();
        clone_definition.symbol_roles = SymbolRole::Definition.value();
        let clone_line = SOURCE.lines().nth(2).expect("local method line");
        let clone_column = clone_line.find("clone").expect("local method name") as i32;
        clone_definition.range = vec![2, clone_column, clone_column + "clone".len() as i32];
        let mut clone_information = SymbolInformation::new();
        clone_information.symbol = clone_definition.symbol.clone();
        clone_information.display_name = "clone".into();
        clone_information.kind = EnumOrUnknown::new(symbol_information::Kind::Method);

        let caller_line = SOURCE.lines().nth(4).expect("caller line");
        let mut caller_definition = Occurrence::new();
        caller_definition.symbol = "rust fixture caller().".into();
        caller_definition.symbol_roles = SymbolRole::Definition.value();
        let caller_column = caller_line.find("caller").expect("caller name") as i32;
        caller_definition.range = vec![4, caller_column, caller_column + "caller".len() as i32];
        caller_definition.enclosing_range =
            vec![4, 0, 4, caller_line.len().try_into().expect("line length")];
        let mut caller_information = SymbolInformation::new();
        caller_information.symbol = caller_definition.symbol.clone();
        caller_information.display_name = "caller".into();
        caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

        let parameter_column = caller_line.find("value").expect("parameter name") as i32;
        let mut parameter_definition = Occurrence::new();
        parameter_definition.symbol = "local 0".into();
        parameter_definition.symbol_roles = SymbolRole::Definition.value();
        parameter_definition.range =
            vec![4, parameter_column, parameter_column + "value".len() as i32];
        let mut parameter_reference = Occurrence::new();
        parameter_reference.symbol = parameter_definition.symbol.clone();
        let receiver_column = caller_line.rfind("value").expect("receiver name") as i32;
        parameter_reference.range =
            vec![4, receiver_column, receiver_column + "value".len() as i32];
        let mut parameter_information = SymbolInformation::new();
        parameter_information.symbol = parameter_definition.symbol.clone();
        parameter_information.display_name = "value".into();
        parameter_information.kind = EnumOrUnknown::new(symbol_information::Kind::Parameter);

        let type_column = caller_line.find("Local").expect("receiver type") as i32;
        let mut type_reference = Occurrence::new();
        type_reference.symbol = "rust-analyzer cargo fixture 0.1.0 lib/Local#".into();
        type_reference.range = vec![4, type_column, type_column + "Local".len() as i32];

        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = "src/lib.rs".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![
            clone_definition,
            caller_definition,
            parameter_definition,
            parameter_reference,
            type_reference,
        ];
        document.symbols = vec![clone_information, caller_information, parameter_information];

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();

        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Partial,
            "a provider-resolved source-local method witness must not be treated as out-of-population coverage: {evidence:#?}",
        );
        assert_eq!(
            evidence.receipt.reason_code.as_deref(),
            Some("provider_call_occurrence_incomplete")
        );
        assert!(evidence.payload.is_none());
    }

    #[test]
    fn omitted_cross_document_local_call_occurrence_is_partial() {
        const LIB_SOURCE: &str = "pub mod helper;\npub mod caller;\n";
        const HELPER_SOURCE: &str = "pub fn helper() {}\n";
        const CALLER_SOURCE: &str = "pub fn caller() { crate::helper::helper(); }\n";
        const HELPER: &str = "rust fixture 0.1.0 lib/helper().";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";

        let function_document =
            |path: &str, source: &str, symbol: &str, name: &str, call: Option<(&str, i32)>| {
                let definition_column = source.find(name).expect("definition name") as i32;
                let mut definition = Occurrence::new();
                definition.symbol = symbol.into();
                definition.symbol_roles = SymbolRole::Definition.value();
                definition.range =
                    vec![0, definition_column, definition_column + name.len() as i32];
                definition.enclosing_range = vec![0, 0, source.trim_end().len() as i32];

                let mut occurrences = vec![definition];
                if let Some((callee_symbol, call_column)) = call {
                    let mut call = Occurrence::new();
                    call.symbol = callee_symbol.into();
                    call.range = vec![0, call_column, call_column + "helper".len() as i32];
                    occurrences.push(call);
                }

                let mut information = SymbolInformation::new();
                information.symbol = symbol.into();
                information.display_name = name.into();
                information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

                let mut document = Document::new();
                document.language = "rust".into();
                document.relative_path = path.into();
                document.text = source.into();
                document.position_encoding =
                    EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
                document.occurrences = occurrences;
                document.symbols = vec![information];
                document
            };
        let empty_lib_document = || {
            let mut document = Document::new();
            document.language = "rust".into();
            document.relative_path = "src/lib.rs".into();
            document.text = LIB_SOURCE.into();
            document.position_encoding =
                EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
            document
        };
        let sources = [
            ("src/lib.rs", LIB_SOURCE),
            ("src/helper.rs", HELPER_SOURCE),
            ("src/caller.rs", CALLER_SOURCE),
        ];
        let helper_document =
            || function_document("src/helper.rs", HELPER_SOURCE, HELPER, "helper", None);
        let call_column = CALLER_SOURCE.rfind("helper").expect("helper call") as i32;

        let omitted = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![
                empty_lib_document(),
                helper_document(),
                function_document("src/caller.rs", CALLER_SOURCE, CALLER, "caller", None),
            ],
            &sources,
        )
        .normalize();
        assert_failure(
            &omitted,
            CapabilityStatus::Partial,
            "provider_call_occurrence_incomplete",
        );

        let complete = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![
                empty_lib_document(),
                helper_document(),
                function_document(
                    "src/caller.rs",
                    CALLER_SOURCE,
                    CALLER,
                    "caller",
                    Some((HELPER, call_column)),
                ),
            ],
            &sources,
        )
        .normalize();
        assert_eq!(complete.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = complete
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        assert_eq!(payload.calls[0].caller_symbol_id, CALLER);
        assert_eq!(payload.calls[0].callee_symbol_id, HELPER);
    }

    #[test]
    fn duplicate_non_callable_provider_definitions_do_not_poison_calls_authority() {
        let mut document = document_with_call(
            "rust",
            "src/lib.rs",
            RUST_SOURCE,
            0,
            1,
            "rust fixture 0.1.0 lib/target().",
            "rust fixture 0.1.0 lib/caller().",
        );
        let package_symbol = "rust-analyzer cargo fixture 0.0.0 crate/";
        let mut package_information = SymbolInformation::new();
        package_information.symbol = package_symbol.into();
        package_information.display_name = "crate".into();
        package_information.kind = EnumOrUnknown::new(symbol_information::Kind::Module);
        document.symbols.push(package_information);

        for line in [0, 1] {
            let mut package_definition = Occurrence::new();
            package_definition.symbol = package_symbol.into();
            package_definition.symbol_roles = SymbolRole::Definition.value();
            package_definition.range = vec![line, 0, 2];
            document.occurrences.push(package_definition);
        }

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", RUST_SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
    }

    #[test]
    fn byte_identical_callable_definition_occurrences_are_deduplicated() {
        let mut document = document_with_call(
            "rust",
            "src/lib.rs",
            RUST_SOURCE,
            0,
            1,
            "rust fixture 0.1.0 lib/target().",
            "rust fixture 0.1.0 lib/caller().",
        );
        let duplicate = document
            .occurrences
            .iter()
            .find(|occurrence| occurrence.symbol_roles & SymbolRole::Definition.value() != 0)
            .expect("callable definition")
            .clone();
        document.occurrences.push(duplicate);

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", RUST_SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
    }

    #[test]
    fn distinct_callable_symbols_with_one_extent_fail_closed_as_ambiguous_owners() {
        const OTHER_CALLER: &str = "rust fixture 0.1.0 lib/other_caller().";
        let mut document = document_with_call(
            "rust",
            "src/lib.rs",
            RUST_SOURCE,
            0,
            1,
            "rust fixture 0.1.0 lib/target().",
            "rust fixture 0.1.0 lib/caller().",
        );
        let mut competing_owner = document
            .occurrences
            .iter()
            .find(|occurrence| {
                occurrence.symbol == "rust fixture 0.1.0 lib/caller()."
                    && occurrence.symbol_roles & SymbolRole::Definition.value() != 0
            })
            .expect("caller definition")
            .clone();
        competing_owner.symbol = OTHER_CALLER.into();
        document.occurrences.push(competing_owner);

        let mut competing_information = SymbolInformation::new();
        competing_information.symbol = OTHER_CALLER.into();
        competing_information.display_name = "other_caller".into();
        competing_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);
        document.symbols.push(competing_information);

        assert_failure(
            &fixture(
                ScipProviderSpec::rust_analyzer(),
                vec![document],
                &[("src/lib.rs", RUST_SOURCE)],
            )
            .normalize(),
            CapabilityStatus::Partial,
            "call_owner_ambiguous",
        );
    }

    #[test]
    fn overlapping_callable_definitions_with_one_provider_id_still_fail_closed() {
        let mut document = document_with_call(
            "rust",
            "src/lib.rs",
            RUST_SOURCE,
            0,
            1,
            "rust fixture 0.1.0 lib/target().",
            "rust fixture 0.1.0 lib/caller().",
        );
        let mut duplicate = document
            .occurrences
            .iter()
            .find(|occurrence| occurrence.symbol_roles & SymbolRole::Definition.value() != 0)
            .expect("target definition")
            .clone();
        duplicate.range = document
            .occurrences
            .iter()
            .filter(|occurrence| occurrence.symbol_roles & SymbolRole::Definition.value() != 0)
            .nth(1)
            .expect("caller definition")
            .range
            .clone();
        document.occurrences.push(duplicate);

        assert_failure(
            &fixture(
                ScipProviderSpec::rust_analyzer(),
                vec![document],
                &[("src/lib.rs", RUST_SOURCE)],
            )
            .normalize(),
            CapabilityStatus::Unavailable,
            "provider_definition_duplicate",
        );
    }

    #[test]
    fn repeated_nested_function_symbols_are_resolved_by_disjoint_lexical_scope() {
        const SOURCE: &str = concat!(
            "fn outer_a() {\n",
            "    fn fallible() {}\n",
            "    fallible();\n",
            "}\n",
            "fn outer_b() {\n",
            "    fn fallible() {}\n",
            "    fallible();\n",
            "}\n",
        );
        const FALLIBLE: &str = "rust fixture 0.1.0 tests/fallible().";
        const OUTER_A: &str = "rust fixture 0.1.0 lib/outer_a().";
        const OUTER_B: &str = "rust fixture 0.1.0 lib/outer_b().";

        let definition = |symbol: &str, line: i32, start: i32, end: i32, enclosing: Vec<i32>| {
            let mut occurrence = Occurrence::new();
            occurrence.symbol = symbol.into();
            occurrence.symbol_roles = SymbolRole::Definition.value();
            occurrence.range = vec![line, start, end];
            occurrence.enclosing_range = enclosing;
            occurrence
        };
        let call = |line: i32| {
            let mut occurrence = Occurrence::new();
            occurrence.symbol = FALLIBLE.into();
            occurrence.range = vec![line, 4, 12];
            occurrence
        };
        let information = |symbol: &str, name: &str| {
            let mut information = SymbolInformation::new();
            information.symbol = symbol.into();
            information.display_name = name.into();
            information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);
            information
        };

        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = "src/lib.rs".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![
            definition(OUTER_A, 0, 3, 10, vec![0, 0, 3, 1]),
            definition(FALLIBLE, 1, 7, 15, vec![1, 4, 1, 20]),
            call(2),
            definition(OUTER_B, 4, 3, 10, vec![4, 0, 7, 1]),
            definition(FALLIBLE, 5, 7, 15, vec![5, 4, 5, 20]),
            call(6),
        ];
        document.symbols = vec![
            information(OUTER_A, "outer_a"),
            information(OUTER_B, "outer_b"),
            information(FALLIBLE, "fallible"),
        ];

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 2);
        assert_eq!(
            payload
                .calls
                .iter()
                .map(|call| call.callee_symbol_id.as_str())
                .collect::<BTreeSet<_>>()
                .len(),
            2,
            "the collapsed provider ID must become two stable lexical identities"
        );
    }

    #[test]
    fn provider_resolved_callable_parameter_is_a_target_but_package_is_not() {
        const SOURCE: &str = "fn caller(embed_many: impl Fn()) { embed_many(); }\n";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";
        const PARAMETER: &str = "local 0";
        let caller_start = SOURCE.find("caller").expect("caller definition") as i32;
        let parameter_start = SOURCE.find("embed_many").expect("parameter definition") as i32;
        let call_start = SOURCE.rfind("embed_many").expect("parameter call") as i32;

        let mut caller_definition = Occurrence::new();
        caller_definition.symbol = CALLER.into();
        caller_definition.symbol_roles = SymbolRole::Definition.value();
        caller_definition.range = vec![0, caller_start, caller_start + 6];
        caller_definition.enclosing_range = vec![0, 0, SOURCE.trim_end().len() as i32];

        let mut parameter_definition = Occurrence::new();
        parameter_definition.symbol = PARAMETER.into();
        parameter_definition.symbol_roles = SymbolRole::Definition.value();
        parameter_definition.range = vec![0, parameter_start, parameter_start + 10];

        let mut call = Occurrence::new();
        call.symbol = PARAMETER.into();
        call.range = vec![0, call_start, call_start + 10];

        let mut caller_information = SymbolInformation::new();
        caller_information.symbol = CALLER.into();
        caller_information.display_name = "caller".into();
        caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);
        let mut parameter_information = SymbolInformation::new();
        parameter_information.symbol = PARAMETER.into();
        parameter_information.display_name = "embed_many".into();
        parameter_information.kind = EnumOrUnknown::new(symbol_information::Kind::Parameter);

        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = "src/lib.rs".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![caller_definition, parameter_definition, call];
        document.symbols = vec![caller_information, parameter_information];

        let complete = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document.clone()],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();
        assert_eq!(complete.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = complete
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        assert!(payload.coverage_exclusions.iter().any(|exclusion| {
            exclusion.reason_code == "dynamic_callable_target_unresolved"
                && exclusion.location.span.start_byte == call_start as u64
        }));
        assert_eq!(
            payload
                .symbols
                .iter()
                .find(|symbol| symbol.name == "embed_many")
                .expect("callable parameter symbol")
                .provider_kind,
            "parameter"
        );

        document
            .symbols
            .iter_mut()
            .find(|symbol| symbol.symbol == PARAMETER)
            .expect("parameter information")
            .kind = EnumOrUnknown::new(symbol_information::Kind::Package);
        assert_failure(
            &fixture(
                ScipProviderSpec::rust_analyzer(),
                vec![document],
                &[("src/lib.rs", SOURCE)],
            )
            .normalize(),
            CapabilityStatus::Partial,
            "call_target_not_callable",
        );
    }

    #[test]
    fn provider_local_parameter_without_definition_is_corroborated_by_syntax() {
        const SOURCE: &str = "fn caller<F>(f: F) where F: FnOnce() { f(); }\n";
        const CALLER: &str = "rust fixture 0.1.0 lib/caller().";
        const PARAMETER: &str = "local 5";
        let caller_start = SOURCE.find("caller").expect("caller definition") as i32;
        let call_start = SOURCE.rfind("f()").expect("parameter call") as i32;

        let mut caller_definition = Occurrence::new();
        caller_definition.symbol = CALLER.into();
        caller_definition.symbol_roles = SymbolRole::Definition.value();
        caller_definition.range = vec![0, caller_start, caller_start + 6];

        let mut call = Occurrence::new();
        call.symbol = PARAMETER.into();
        call.range = vec![0, call_start, call_start + 1];

        let mut caller_information = SymbolInformation::new();
        caller_information.symbol = CALLER.into();
        caller_information.display_name = "caller".into();
        caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = "src/lib.rs".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![caller_definition, call];
        document.symbols = vec![caller_information];

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();

        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "provider-local invocation plus a unique lexical parameter binding must be sufficient: {:?}",
            evidence.receipt
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        let parameter = payload
            .symbols
            .iter()
            .find(|symbol| symbol.provider_symbol_id == "h00-local:src/lib.rs:local 5")
            .expect("syntax-corroborated parameter symbol");
        assert_eq!(parameter.name, "f");
        assert_eq!(parameter.provider_kind, "parameter");
        assert!(parameter.definition.is_some());
        assert!(parameter.structural_extent.is_none());
        assert!(parameter.call_owner_extent.is_none());
    }

    #[test]
    fn rust_tuple_constructor_is_outside_callable_invocation_authority() {
        const SOURCE: &str = "struct target();\nfn caller() { let _ = target(); }\n";
        const TARGET: &str = "rust fixture 0.1.0 target#";
        const CALLER: &str = "rust fixture 0.1.0 caller().";
        let mut document = document_with_call("rust", "src/lib.rs", SOURCE, 0, 1, TARGET, CALLER);
        document
            .symbols
            .iter_mut()
            .find(|symbol| symbol.symbol == TARGET)
            .expect("tuple-struct symbol information")
            .kind = EnumOrUnknown::new(symbol_information::Kind::Struct);

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(
            payload.calls.is_empty(),
            "construction syntax is not a source-backed callable invocation: {:?}",
            payload.calls
        );
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(
                    |exclusion| exclusion.reason_code != "constructor_target_unmodeled"
                        && exclusion.reason_code != "dynamic_callable_target_unresolved"
                ),
            "a provider-resolved construction is accounted syntax, not an unknown callable target: {:?}",
            payload.coverage_exclusions
        );
    }

    fn rust_closure_document(source: &str) -> Document {
        const TARGET: &str = "rust fixture 0.1.0 target().";
        const CALLER: &str = "rust fixture 0.1.0 caller().";
        const RUN: &str = "local 0";
        let lines = source.lines().collect::<Vec<_>>();
        let occurrence = |symbol: &str, line: usize, name: &str, definition: bool| {
            let start = lines[line].find(name).expect("fixture token") as i32;
            let mut value = Occurrence::new();
            value.symbol = symbol.into();
            value.range = vec![line as i32, start, start + name.len() as i32];
            if definition {
                value.symbol_roles = SymbolRole::Definition.value();
            }
            value
        };
        let information = |symbol: &str, name: &str, kind| {
            let mut value = SymbolInformation::new();
            value.symbol = symbol.into();
            value.display_name = name.into();
            value.kind = EnumOrUnknown::new(kind);
            value
        };

        let mut document = Document::new();
        document.language = "rust".into();
        document.relative_path = "src/lib.rs".into();
        document.text = source.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![
            occurrence(TARGET, 0, "target", true),
            occurrence(CALLER, 1, "caller", true),
            occurrence(RUN, 2, "run", true),
            occurrence(TARGET, 2, "target", false),
            occurrence(RUN, 3, "run", false),
        ];
        document.symbols = vec![
            information(TARGET, "target", symbol_information::Kind::Function),
            information(CALLER, "caller", symbol_information::Kind::Function),
            information(RUN, "run", symbol_information::Kind::Variable),
        ];
        document
    }

    #[test]
    fn rust_immutable_closure_invocation_is_not_unknown_dispatch() {
        const SOURCE: &str =
            "fn target() {}\nfn caller() {\n    let run = || target();\n    run();\n}\n";
        const TARGET: &str = "rust fixture 0.1.0 target().";

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![rust_closure_document(SOURCE)],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(
            payload
                .calls
                .iter()
                .map(|call| call.callee_symbol_id.as_str())
                .collect::<Vec<_>>(),
            vec![TARGET],
            "the named call inside the closure remains, while invoking the closure binding itself is outside the named-call population"
        );
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(|exclusion| { exclusion.reason_code != "dynamic_callable_target_unresolved" })
        );
    }

    #[test]
    fn rust_fn_mut_closure_invocation_is_not_unknown_dispatch() {
        const SOURCE: &str =
            "fn target() {}\nfn caller() {\n    let mut run = || target();\n    run();\n}\n";
        const TARGET: &str = "rust fixture 0.1.0 target().";
        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![rust_closure_document(SOURCE)],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(
            payload
                .calls
                .iter()
                .map(|call| call.callee_symbol_id.as_str())
                .collect::<Vec<_>>(),
            vec![TARGET],
            "FnMut changes captured state, not the direct closure literal's callable identity"
        );
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(|exclusion| exclusion.reason_code != "dynamic_callable_target_unresolved")
        );
    }

    #[test]
    fn rust_coercible_function_pointer_binding_remains_dynamic() {
        const SOURCE: &str =
            "fn target() {}\nfn caller() {\n    let mut run: fn() = || target();\n    run();\n}\n";
        const RUN: &str = "local 0";
        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![rust_closure_document(SOURCE)],
            &[("src/lib.rs", SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(
            payload
                .calls
                .iter()
                .any(|call| call.callee_symbol_id.ends_with(RUN)),
            "an explicitly coercible function-pointer binding can be replaced with another target"
        );
        assert!(payload.coverage_exclusions.iter().any(|exclusion| {
            exclusion.reason_code == "dynamic_callable_target_unresolved"
                && exclusion.location.span.start_line == 3
        }));
    }

    #[test]
    fn static_method_kind_is_a_callable_definition() {
        let target = "rust fixture 0.1.0 config/impl#[Config][Default]default().";
        let caller = "rust fixture 0.1.0 lib/caller().";
        let mut document =
            document_with_call("rust", "src/lib.rs", RUST_SOURCE, 0, 1, target, caller);
        document
            .symbols
            .iter_mut()
            .find(|symbol| symbol.symbol == target)
            .expect("target symbol information")
            .kind = EnumOrUnknown::new(symbol_information::Kind::StaticMethod);

        let evidence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", RUST_SOURCE)],
        )
        .normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        assert_eq!(payload.calls[0].callee_symbol_id, target);
    }

    #[test]
    fn scip_go_unspecified_positions_use_the_providers_utf8_byte_contract() {
        let source = concat!(
            "package main\n",
            "func target() {}\n",
            "func caller() { _ = \"🙂\"; target() }\n",
        );
        let document = || {
            let mut document = document_with_call(
                "go",
                "main.go",
                source,
                1,
                2,
                "go fixture target().",
                "go fixture caller().",
            );
            document.position_encoding =
                EnumOrUnknown::new(PositionEncoding::UnspecifiedPositionEncoding);
            document
        };
        let mut admitted = fixture(
            ScipProviderSpec::scip_go(),
            vec![document()],
            &[("main.go", source)],
        );
        admitted
            .index
            .metadata
            .as_mut()
            .expect("SCIP metadata")
            .tool_info
            .as_mut()
            .expect("SCIP tool identity")
            .version = SCIP_GO_UNSPECIFIED_POSITION_ENCODING_VERSION.into();
        let evidence = admitted.normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Go Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        assert_eq!(payload.calls[0].caller_symbol_id, "go fixture caller().");
        assert_eq!(payload.calls[0].callee_symbol_id, "go fixture target().");
        assert_eq!(
            &source.as_bytes()[payload.calls[0].call_site.span.start_byte as usize
                ..payload.calls[0].call_site.span.end_byte as usize],
            b"target",
            "provider byte columns after a multibyte character must resolve exactly"
        );

        let mut unknown_version = fixture(
            ScipProviderSpec::scip_go(),
            vec![document()],
            &[("main.go", source)],
        );
        unknown_version
            .index
            .metadata
            .as_mut()
            .expect("SCIP metadata")
            .tool_info
            .as_mut()
            .expect("SCIP tool identity")
            .version = "0.2.8".into();
        assert_failure(
            &unknown_version.normalize(),
            CapabilityStatus::Unavailable,
            "provider_position_encoding_unspecified",
        );
    }

    #[test]
    fn go_interface_method_definition_uses_its_exact_method_element_extent() {
        const SOURCE: &str = concat!(
            "package main\n",
            "var netListen = func() interface { Close() error } { return nil }\n",
        );
        const SYMBOL: &str = "local 96";
        let line = SOURCE.lines().nth(1).expect("Go declaration line");
        let start = line.find("Close").expect("interface method name") as i32;

        let mut definition = Occurrence::new();
        definition.symbol = SYMBOL.into();
        definition.symbol_roles = SymbolRole::Definition.value();
        definition.range = vec![1, start, start + "Close".len() as i32];

        let mut information = SymbolInformation::new();
        information.symbol = SYMBOL.into();
        information.display_name = "Close".into();
        information.kind = EnumOrUnknown::new(symbol_information::Kind::Method);

        let mut document = Document::new();
        document.language = "go".into();
        document.relative_path = "main.go".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![definition];
        document.symbols = vec![information];

        let evidence = fixture(
            ScipProviderSpec::scip_go(),
            vec![document],
            &[("main.go", SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        let method = payload
            .symbols
            .iter()
            .find(|symbol| symbol.name == "Close")
            .expect("interface method provider symbol");
        let extent = method
            .structural_extent
            .as_ref()
            .expect("method structural extent");
        assert_eq!(
            &SOURCE.as_bytes()[extent.span.start_byte as usize..extent.span.end_byte as usize],
            b"Close() error",
        );
    }

    #[test]
    fn call_syntax_ranges_remain_utf8_byte_offsets_after_multibyte_text() {
        let cases = [
            (
                "rust",
                "src/lib.rs",
                "const MASCOT: &str = \"🦉\";\nfn caller() { MASCOT.len(); target(); }\n",
                ["len", "target"],
            ),
            (
                "go",
                "main.go",
                "package main\nconst mascot = \"🦉\"\nfunc caller() { len(mascot); target() }\n",
                ["len", "target"],
            ),
        ];

        for (language, path, source, callees) in cases {
            let evidence = source_call_evidence(source, path, language).expect("valid syntax");
            for callee in callees {
                let start = source.find(callee).expect("callee in source");
                assert!(
                    evidence
                        .call_callees
                        .contains_key(&(start, start + callee.len())),
                    "{language} call range for {callee:?} must use source-byte offsets: {:?}",
                    evidence.call_callees
                );
            }
        }
    }

    #[test]
    fn omitted_external_calls_do_not_downgrade_complete_local_call_coverage() {
        let cases = [
            (
                ScipProviderSpec::rust_analyzer(),
                "src/lib.rs",
                "fn target() {}\nfn caller() { Vec::<u8>::new(); target(); }\n",
                0,
                1,
                "rust fixture target().",
                "rust fixture caller().",
            ),
            (
                ScipProviderSpec::scip_go(),
                "main.go",
                "package main\nfunc target() {}\nfunc caller() { _ = len(\"x\"); target() }\n",
                1,
                2,
                "go fixture target().",
                "go fixture caller().",
            ),
        ];

        for (spec, path, source, target_line, caller_line, target_symbol, caller_symbol) in cases {
            let document = document_with_call(
                spec.language,
                path,
                source,
                target_line,
                caller_line,
                target_symbol,
                caller_symbol,
            );
            let evidence = fixture(spec, vec![document], &[(path, source)]).normalize();
            assert_eq!(
                evidence.receipt.status,
                CapabilityStatus::Complete,
                "dependency and language-builtin calls are outside repository-local Calls authority: {:?}",
                evidence.receipt
            );
            let ProviderPayload::Calls(payload) =
                evidence.payload.expect("complete payload").into_payload()
            else {
                unreachable!("Calls fixture")
            };
            assert_eq!(payload.calls.len(), 1);
        }
    }

    #[test]
    fn omitted_go_selector_does_not_inherit_local_authority_from_its_bare_name() {
        const SOURCE: &str = concat!(
            "package main\n",
            "type External interface { Close() error }\n",
            "func caller(external External) { _ = external.Close() }\n",
        );
        const METHOD: &str = "go fixture External#Close().";
        const CALLER: &str = "go fixture caller().";

        let method_line = SOURCE.lines().nth(1).expect("interface line");
        let method_column = method_line.find("Close").expect("method name") as i32;
        let mut method_definition = Occurrence::new();
        method_definition.symbol = METHOD.into();
        method_definition.symbol_roles = SymbolRole::Definition.value();
        method_definition.range = vec![1, method_column, method_column + "Close".len() as i32];

        let caller_line = SOURCE.lines().nth(2).expect("caller line");
        let caller_column = caller_line.find("caller").expect("caller name") as i32;
        let mut caller_definition = Occurrence::new();
        caller_definition.symbol = CALLER.into();
        caller_definition.symbol_roles = SymbolRole::Definition.value();
        caller_definition.range = vec![2, caller_column, caller_column + "caller".len() as i32];
        caller_definition.enclosing_range = vec![2, 0, 2, caller_line.len() as i32];

        let mut method_information = SymbolInformation::new();
        method_information.symbol = METHOD.into();
        method_information.display_name = "Close".into();
        method_information.kind = EnumOrUnknown::new(symbol_information::Kind::Method);
        let mut caller_information = SymbolInformation::new();
        caller_information.symbol = CALLER.into();
        caller_information.display_name = "caller".into();
        caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);

        let mut document = Document::new();
        document.language = "go".into();
        document.relative_path = "main.go".into();
        document.text = SOURCE.into();
        document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        document.occurrences = vec![method_definition, caller_definition];
        document.symbols = vec![method_information, caller_information];

        let evidence = fixture(
            ScipProviderSpec::scip_go(),
            vec![document],
            &[("main.go", SOURCE)],
        )
        .normalize();

        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "an omitted selector has no repository-local identity merely because a local method has the same terminal name: {:?}",
            evidence.receipt,
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(payload.calls.is_empty());
    }

    #[test]
    fn omitted_go_direct_call_does_not_inherit_authority_from_another_package() {
        const CALLER_SOURCE: &str = concat!(
            "package alpha\n",
            "import . \"example.com/dependency\"\n",
            "func caller() { Target() }\n",
        );
        const OTHER_SOURCE: &str = "package beta\nfunc Target() {}\n";
        let caller = go_document_with_function_definitions(
            "alpha/caller.go",
            CALLER_SOURCE,
            &[("caller", "go fixture alpha/caller().")],
        );
        let other = go_document_with_function_definitions(
            "beta/target.go",
            OTHER_SOURCE,
            &[("Target", "go fixture beta/Target().")],
        );

        let evidence = fixture(
            ScipProviderSpec::scip_go(),
            vec![caller, other],
            &[
                ("alpha/caller.go", CALLER_SOURCE),
                ("beta/target.go", OTHER_SOURCE),
            ],
        )
        .normalize();

        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "a direct call cannot bind to a same-named declaration in a different Go package: {:?}",
            evidence.receipt,
        );
    }

    #[test]
    fn omitted_go_direct_call_does_not_inherit_authority_from_test_only_code() {
        const CALLER_SOURCE: &str = concat!(
            "package alpha\n",
            "import . \"example.com/dependency\"\n",
            "func caller() { Target() }\n",
        );
        const TEST_SOURCE: &str = "package alpha\nfunc Target() {}\n";
        let caller = go_document_with_function_definitions(
            "alpha/caller.go",
            CALLER_SOURCE,
            &[("caller", "go fixture alpha/caller().")],
        );
        let test_only = go_document_with_function_definitions(
            "alpha/target_test.go",
            TEST_SOURCE,
            &[("Target", "go fixture alpha/Target().")],
        );

        let evidence = fixture(
            ScipProviderSpec::scip_go(),
            vec![caller, test_only],
            &[
                ("alpha/caller.go", CALLER_SOURCE),
                ("alpha/target_test.go", TEST_SOURCE),
            ],
        )
        .normalize();

        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "production authority cannot be borrowed from a same-package _test.go declaration: {:?}",
            evidence.receipt,
        );
    }

    #[test]
    fn omitted_same_package_go_direct_call_remains_partial() {
        const CALLER_SOURCE: &str = "package alpha\nfunc caller() { target() }\n";
        const TARGET_SOURCE: &str = "package alpha\nfunc target() {}\n";
        let caller = go_document_with_function_definitions(
            "alpha/caller.go",
            CALLER_SOURCE,
            &[("caller", "go fixture alpha/caller().")],
        );
        let target = go_document_with_function_definitions(
            "alpha/target.go",
            TARGET_SOURCE,
            &[("target", "go fixture alpha/target().")],
        );
        let fixture = fixture(
            ScipProviderSpec::scip_go(),
            vec![caller, target],
            &[
                ("alpha/caller.go", CALLER_SOURCE),
                ("alpha/target.go", TARGET_SOURCE),
            ],
        );

        assert_failure(
            &fixture.normalize(),
            CapabilityStatus::Partial,
            "provider_call_occurrence_incomplete",
        );
    }

    #[test]
    fn go_function_valued_package_variable_owns_its_body_calls() {
        const SOURCE: &str = concat!(
            "package main\n",
            "var seam = func() int { return target() }\n",
            "func target() int { return 1 }\n",
        );
        const SEAM: &str = "go fixture seam.";
        const TARGET: &str = "go fixture target().";
        let mut document =
            go_document_with_function_definitions("main.go", SOURCE, &[("target", TARGET)]);

        let seam_line = SOURCE.lines().nth(1).expect("seam line");
        let seam_column = seam_line.find("seam").expect("seam definition") as i32;
        let mut seam_definition = Occurrence::new();
        seam_definition.symbol = SEAM.into();
        seam_definition.symbol_roles = SymbolRole::Definition.value();
        seam_definition.range = vec![1, seam_column, seam_column + "seam".len() as i32];
        seam_definition.enclosing_range = vec![1, 0, 1, seam_line.len() as i32];

        let call_column = seam_line.rfind("target").expect("target call") as i32;
        let mut call = Occurrence::new();
        call.symbol = TARGET.into();
        call.range = vec![1, call_column, call_column + "target".len() as i32];

        let mut seam_information = SymbolInformation::new();
        seam_information.symbol = SEAM.into();
        seam_information.display_name = "seam".into();
        seam_information.kind = EnumOrUnknown::new(symbol_information::Kind::Variable);
        document.occurrences.extend([seam_definition, call]);
        document.symbols.push(seam_information);

        let evidence = fixture(
            ScipProviderSpec::scip_go(),
            vec![document],
            &[("main.go", SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.calls.len(), 1);
        assert_eq!(payload.calls[0].caller_symbol_id, SEAM);
        assert_eq!(payload.calls[0].callee_symbol_id, TARGET);
        assert!(payload.coverage_exclusions.is_empty());
    }

    #[test]
    fn invoked_go_function_alias_has_a_structural_extent() {
        const SOURCE: &str = concat!(
            "package main\n",
            "var seam = target\n",
            "func target() {}\n",
            "func caller() { seam() }\n",
        );
        const SEAM: &str = "go fixture seam.";
        const TARGET: &str = "go fixture target().";
        const CALLER: &str = "go fixture caller().";
        let mut document = go_document_with_function_definitions(
            "main.go",
            SOURCE,
            &[("target", TARGET), ("caller", CALLER)],
        );

        let seam_line = SOURCE.lines().nth(1).expect("seam line");
        let seam_column = seam_line.find("seam").expect("seam definition") as i32;
        let mut seam_definition = Occurrence::new();
        seam_definition.symbol = SEAM.into();
        seam_definition.symbol_roles = SymbolRole::Definition.value();
        seam_definition.range = vec![1, seam_column, seam_column + "seam".len() as i32];
        seam_definition.enclosing_range = vec![1, 0, 1, seam_line.len() as i32];

        let target_column = seam_line.rfind("target").expect("target binding") as i32;
        let mut target_binding = Occurrence::new();
        target_binding.symbol = TARGET.into();
        target_binding.range = vec![1, target_column, target_column + "target".len() as i32];

        let caller_line = SOURCE.lines().nth(3).expect("caller line");
        let call_column = caller_line.rfind("seam").expect("seam call") as i32;
        let mut seam_call = Occurrence::new();
        seam_call.symbol = SEAM.into();
        seam_call.range = vec![3, call_column, call_column + "seam".len() as i32];

        let mut seam_information = SymbolInformation::new();
        seam_information.symbol = SEAM.into();
        seam_information.display_name = "seam".into();
        seam_information.kind = EnumOrUnknown::new(symbol_information::Kind::Variable);
        document
            .occurrences
            .extend([seam_definition, target_binding, seam_call]);
        document.symbols.push(seam_information);

        let evidence = fixture(
            ScipProviderSpec::scip_go(),
            vec![document],
            &[("main.go", SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        let seam = payload
            .symbols
            .iter()
            .find(|symbol| symbol.provider_symbol_id == SEAM)
            .expect("invoked package variable must remain addressable");
        let extent = seam
            .structural_extent
            .as_ref()
            .expect("an invoked package variable is provider-proven callable");
        assert_eq!(
            (extent.span.start_line, extent.span.end_line),
            (1, 1),
            "the exact var spec is the callable identity extent",
        );
        assert!(
            payload
                .calls
                .iter()
                .any(|call| { call.caller_symbol_id == CALLER && call.callee_symbol_id == SEAM }),
            "the source invocation must target the callable binding symbol",
        );
        assert_eq!(payload.callable_bindings.len(), 1);
        assert_eq!(payload.callable_bindings[0].binding_symbol_id, SEAM);
        assert_eq!(payload.callable_bindings[0].target_symbol_id, TARGET);
        assert_eq!(payload.callable_bindings[0].binding_site.span.start_line, 1);
        assert!(
            payload.coverage_exclusions.is_empty(),
            "a package-level callable binding has an exact structural identity",
        );
    }

    #[test]
    fn invoked_go_composed_initializer_is_not_a_call_from_the_bound_value() {
        const SOURCE: &str = concat!(
            "package main\n",
            "func wrap(fn func()) func() { return fn }\n",
            "func target() {}\n",
            "var handler = wrap(target)\n",
            "func caller() { handler() }\n",
        );
        const WRAP: &str = "go fixture wrap().";
        const TARGET: &str = "go fixture target().";
        const HANDLER: &str = "go fixture handler.";
        const CALLER: &str = "go fixture caller().";
        let mut document = go_document_with_function_definitions(
            "main.go",
            SOURCE,
            &[("wrap", WRAP), ("target", TARGET), ("caller", CALLER)],
        );

        let initializer_line = SOURCE.lines().nth(3).expect("initializer line");
        let handler_column = initializer_line
            .find("handler")
            .expect("handler definition") as i32;
        let wrap_column = initializer_line.find("wrap").expect("wrap invocation") as i32;
        let target_column = initializer_line.find("target").expect("target value") as i32;
        let caller_line = SOURCE.lines().nth(4).expect("caller line");
        let handler_call_column = caller_line.find("handler").expect("handler invocation") as i32;

        let mut handler_definition = Occurrence::new();
        handler_definition.symbol = HANDLER.into();
        handler_definition.symbol_roles = SymbolRole::Definition.value();
        handler_definition.range = vec![3, handler_column, handler_column + 7];
        let mut wrap_call = Occurrence::new();
        wrap_call.symbol = WRAP.into();
        wrap_call.range = vec![3, wrap_column, wrap_column + 4];
        let mut target_value = Occurrence::new();
        target_value.symbol = TARGET.into();
        target_value.range = vec![3, target_column, target_column + 6];
        let mut handler_call = Occurrence::new();
        handler_call.symbol = HANDLER.into();
        handler_call.range = vec![4, handler_call_column, handler_call_column + 7];
        document
            .occurrences
            .extend([handler_definition, wrap_call, target_value, handler_call]);

        let mut handler_information = SymbolInformation::new();
        handler_information.symbol = HANDLER.into();
        handler_information.display_name = "handler".into();
        handler_information.kind = EnumOrUnknown::new(symbol_information::Kind::Variable);
        document.symbols.push(handler_information);

        let evidence = fixture(
            ScipProviderSpec::scip_go(),
            vec![document],
            &[("main.go", SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(
            payload.calls.iter().any(|call| {
                call.caller_symbol_id == CALLER && call.callee_symbol_id == HANDLER
            })
        );
        assert!(
            payload.calls.iter().all(|call| {
                !(call.caller_symbol_id == HANDLER && call.callee_symbol_id == WRAP)
            }),
            "package initialization executes wrap; invoking handler later does not"
        );
        assert!(payload.root_invocations.iter().any(|invocation| {
            invocation.callee_symbol_id == WRAP && invocation.call_site.span.start_line == 3
        }));
        assert!(
            payload
                .coverage_exclusions
                .iter()
                .all(|exclusion| exclusion.reason_code != "module_initialization")
        );
    }

    #[test]
    fn go_callable_bindings_do_not_rescan_every_provider_occurrence() {
        const BINDING_COUNT: usize = 16;
        const TARGET: &str = "go fixture target().";
        const CALLER: &str = "go fixture caller().";

        let mut source = String::from("package main\nfunc target() {}\n");
        for index in 0..BINDING_COUNT {
            source.push_str(&format!("var seam{index} = target\n"));
        }
        source.push_str("func caller() { ");
        for index in 0..BINDING_COUNT {
            source.push_str(&format!("seam{index}(); "));
        }
        source.push_str("}\n");
        source.push_str("var plain int\n");

        let mut document = go_document_with_function_definitions(
            "main.go",
            &source,
            &[("target", TARGET), ("caller", CALLER)],
        );
        let caller_line_index = BINDING_COUNT + 2;
        let caller_line = source.lines().nth(caller_line_index).expect("caller line");
        for index in 0..BINDING_COUNT {
            let binding_line_index = index + 2;
            let binding_line = source
                .lines()
                .nth(binding_line_index)
                .expect("binding line");
            let binding_name = format!("seam{index}");
            let binding_symbol = format!("go fixture {binding_name}.");
            let definition_column = binding_line
                .find(&binding_name)
                .expect("binding definition");
            let target_column = binding_line.rfind("target").expect("binding target");
            let call_column = caller_line.find(&binding_name).expect("binding invocation");

            let mut definition = Occurrence::new();
            definition.symbol = binding_symbol.clone();
            definition.symbol_roles = SymbolRole::Definition.value();
            definition.range = vec![
                binding_line_index as i32,
                definition_column as i32,
                (definition_column + binding_name.len()) as i32,
            ];
            let mut target_reference = Occurrence::new();
            target_reference.symbol = TARGET.into();
            target_reference.range = vec![
                binding_line_index as i32,
                target_column as i32,
                (target_column + "target".len()) as i32,
            ];
            let mut invocation = Occurrence::new();
            invocation.symbol = binding_symbol.clone();
            invocation.range = vec![
                caller_line_index as i32,
                call_column as i32,
                (call_column + binding_name.len()) as i32,
            ];
            let mut information = SymbolInformation::new();
            information.symbol = binding_symbol;
            information.display_name = binding_name;
            information.kind = EnumOrUnknown::new(symbol_information::Kind::Variable);

            document
                .occurrences
                .extend([definition, target_reference, invocation]);
            document.symbols.push(information);
        }
        let plain_line_index = BINDING_COUNT + 3;
        let plain_line = source.lines().nth(plain_line_index).expect("plain line");
        let plain_column = plain_line.find("int").expect("plain type reference");
        let mut plain_reference = Occurrence::new();
        plain_reference.symbol = "go stdlib int#".into();
        plain_reference.range = vec![
            plain_line_index as i32,
            plain_column as i32,
            (plain_column + "int".len()) as i32,
        ];
        document.occurrences.push(plain_reference);
        let occurrence_count = document.occurrences.len();
        let fixture = fixture(
            ScipProviderSpec::scip_go(),
            vec![document],
            &[("main.go", &source)],
        );
        PROVIDER_SPAN_NORMALIZATION_COUNT.with(|count| count.set(0));
        PROVIDER_SYMBOL_RANGE_INSERT_COUNT.with(|count| count.set(0));
        PROVIDER_REFERENCE_RANGE_INSERT_COUNT.with(|count| count.set(0));
        NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT.with(|count| count.set(0));
        QUALIFIED_SYMBOL_ID_COUNT.with(|count| count.set(0));
        EAGER_PROVIDER_DEFINITION_INDEX_INSERT_COUNT.with(|count| count.set(0));
        EAGER_DEFINITION_GROUP_TREE_INSERT_COUNT.with(|count| count.set(0));

        let evidence = fixture.normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.callable_bindings.len(), BINDING_COUNT);
        let normalizations = PROVIDER_SPAN_NORMALIZATION_COUNT.with(std::cell::Cell::get);
        assert_eq!(
            normalizations, occurrence_count,
            "each provider occurrence span must be normalized exactly once and shared by definition, binding, and call resolution"
        );
        assert_eq!(
            PROVIDER_SYMBOL_RANGE_INSERT_COUNT.with(std::cell::Cell::get),
            0,
            "Go normalization must not populate Rust receiver/type-owner range authority"
        );
        assert_eq!(
            PROVIDER_REFERENCE_RANGE_INSERT_COUNT.with(std::cell::Cell::get),
            BINDING_COUNT,
            "Go reference authority must index exactly the provider occurrences at callable-binding target ranges"
        );
        assert_eq!(
            NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT.with(std::cell::Cell::get),
            occurrence_count - 1,
            "an independently validated non-call/non-binding Go reference must not enter global definition/call resolution"
        );
        assert_eq!(
            QUALIFIED_SYMBOL_ID_COUNT.with(std::cell::Cell::get),
            occurrence_count - 1,
            "qualified provider identities must be constructed once per retained occurrence, not rebuilt for document-local SymbolInformation joins"
        );
        assert!(
            !payload.symbols.is_empty(),
            "positive control: this fixture must contain admitted provider definitions"
        );
        assert_eq!(
            EAGER_PROVIDER_DEFINITION_INDEX_INSERT_COUNT.with(std::cell::Cell::get),
            0,
            "definition-presence diagnostics must not eagerly index the complete provider definition population"
        );
        assert_eq!(
            EAGER_DEFINITION_GROUP_TREE_INSERT_COUNT.with(std::cell::Cell::get),
            0,
            "definition records must be deterministically sorted and grouped once rather than inserted through an intermediate ordered tree"
        );
    }

    #[test]
    fn provider_definition_presence_diagnostic_is_lazy_and_exact() {
        let occurrences = [NormalizedProviderOccurrence {
            symbol: "local 0".into(),
            symbol_roles: SymbolRole::Definition.value(),
            provider_symbol_id: "h00-local:src/lib.rs:local 0".into(),
            span: NormalizedSourceSpan {
                start_byte: 0,
                end_byte: 1,
                start_line: 0,
                start_utf8_byte_column: 0,
                end_line: 0,
                end_utf8_byte_column: 1,
            },
            range: (0, 1),
        }];

        assert!(has_provider_definition_occurrence(
            &occurrences,
            "h00-local:src/lib.rs:local 0"
        ));
        assert!(!has_provider_definition_occurrence(
            &occurrences,
            "h00-local:src/lib.rs:local 1"
        ));
    }

    #[test]
    fn invoked_local_go_function_value_is_dynamic_not_a_structural_callable() {
        const SOURCE: &str = concat!(
            "package main\n",
            "func caller() {\n",
            "\tvar cancel func()\n",
            "\tcancel()\n",
            "}\n",
        );
        const CALLER: &str = "go fixture caller().";
        const LOCAL: &str = "local 1";
        const QUALIFIED_LOCAL: &str = "h00-local:main.go:local 1";
        let mut document =
            go_document_with_function_definitions("main.go", SOURCE, &[("caller", CALLER)]);

        let definition_line = SOURCE.lines().nth(2).expect("local definition line");
        let definition_column = definition_line.find("cancel").expect("local definition") as i32;
        let mut local_definition = Occurrence::new();
        local_definition.symbol = LOCAL.into();
        local_definition.symbol_roles = SymbolRole::Definition.value();
        local_definition.range = vec![
            2,
            definition_column,
            definition_column + "cancel".len() as i32,
        ];

        let call_line = SOURCE.lines().nth(3).expect("local call line");
        let call_column = call_line.find("cancel").expect("local call") as i32;
        let mut local_call = Occurrence::new();
        local_call.symbol = LOCAL.into();
        local_call.range = vec![3, call_column, call_column + "cancel".len() as i32];

        let mut local_information = SymbolInformation::new();
        local_information.symbol = LOCAL.into();
        local_information.display_name = "cancel".into();
        local_information.kind = EnumOrUnknown::new(symbol_information::Kind::Variable);
        document.occurrences.extend([local_definition, local_call]);
        document.symbols.push(local_information);

        let evidence = fixture(
            ScipProviderSpec::scip_go(),
            vec![document],
            &[("main.go", SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        let local = payload
            .symbols
            .iter()
            .find(|symbol| symbol.provider_symbol_id == QUALIFIED_LOCAL)
            .expect("provider-observed local function value");
        assert!(
            local.structural_extent.is_none(),
            "a local variable declaration must not masquerade as a structural callable body",
        );
        assert!(payload.calls.iter().any(|call| {
            call.caller_symbol_id == CALLER && call.callee_symbol_id == QUALIFIED_LOCAL
        }));
        assert!(payload.coverage_exclusions.iter().any(|exclusion| {
            exclusion.reason_code == "dynamic_callable_target_unresolved"
                && exclusion.location.span.start_line == 3
        }));
    }

    #[test]
    fn go_named_type_conversion_is_not_a_function_call() {
        const SOURCE: &str = concat!(
            "package main\n",
            "type target string\n",
            "func caller() { _ = target(\"fixture\") }\n",
        );
        const TARGET: &str = "go fixture target#";
        const CALLER: &str = "go fixture caller().";
        let mut document = document_with_call("go", "main.go", SOURCE, 1, 2, TARGET, CALLER);
        document
            .symbols
            .iter_mut()
            .find(|symbol| symbol.symbol == TARGET)
            .expect("type symbol information")
            .kind = EnumOrUnknown::new(symbol_information::Kind::Type);

        let evidence = fixture(
            ScipProviderSpec::scip_go(),
            vec![document],
            &[("main.go", SOURCE)],
        )
        .normalize();

        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert!(
            payload.calls.is_empty(),
            "a provider-resolved Go type conversion must not become a Calls edge",
        );
    }

    #[test]
    fn omitted_local_call_occurrence_remains_partial() {
        let mut document = document_with_call(
            "rust",
            "src/lib.rs",
            RUST_SOURCE,
            0,
            1,
            "rust fixture target().",
            "rust fixture caller().",
        );
        document
            .occurrences
            .retain(|occurrence| occurrence.symbol_roles != 0);
        let fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        assert_failure(
            &fixture.normalize(),
            CapabilityStatus::Partial,
            "provider_call_occurrence_incomplete",
        );
    }

    #[test]
    fn provider_identity_root_path_text_and_source_drift_fail_closed() {
        let new_rust_fixture = || {
            fixture(
                ScipProviderSpec::rust_analyzer(),
                vec![document_with_call(
                    "rust",
                    "src/lib.rs",
                    RUST_SOURCE,
                    0,
                    1,
                    "rust fixture target().",
                    "rust fixture caller().",
                )],
                &[("src/lib.rs", RUST_SOURCE)],
            )
        };

        let mut wrong_tool = new_rust_fixture();
        wrong_tool
            .index
            .metadata
            .as_mut()
            .expect("metadata")
            .tool_info
            .as_mut()
            .expect("tool")
            .name = "scip-go".into();
        assert_failure(
            &wrong_tool.normalize(),
            CapabilityStatus::Unavailable,
            "provider_identity_mismatch",
        );

        let mut wrong_root = new_rust_fixture();
        let other_root = wrong_root
            .root
            .parent()
            .expect("workspace")
            .join("other-repo");
        fs::create_dir_all(&other_root).expect("other root");
        wrong_root
            .index
            .metadata
            .as_mut()
            .expect("metadata")
            .project_root = format!("file://{}", other_root.display());
        assert_failure(
            &wrong_root.normalize(),
            CapabilityStatus::Unavailable,
            "provider_root_mismatch",
        );

        let mut unsafe_path = new_rust_fixture();
        unsafe_path.index.documents[0].relative_path = "../src/lib.rs".into();
        assert_failure(
            &unsafe_path.normalize(),
            CapabilityStatus::Unavailable,
            "provider_document_path_unsafe",
        );

        let mut wrong_text = new_rust_fixture();
        wrong_text.index.documents[0]
            .text
            .push_str("// provider drift\n");
        assert_failure(
            &wrong_text.normalize(),
            CapabilityStatus::Unavailable,
            "provider_document_text_mismatch",
        );

        let changed_source = new_rust_fixture();
        fs::write(
            changed_source.root.join("src/lib.rs"),
            "fn target() {}\nfn caller() {}\n",
        )
        .expect("change indexed source");
        assert_failure(
            &changed_source.normalize(),
            CapabilityStatus::Unavailable,
            "indexed_source_changed",
        );
    }

    #[test]
    fn omitted_provider_documents_are_qualified_while_corruption_fails_closed() {
        let first = document_with_call(
            "rust",
            "src/lib.rs",
            RUST_SOURCE,
            0,
            1,
            "rust fixture target().",
            "rust fixture caller().",
        );
        let second_source = "fn target() {}\nfn caller() { target(); }\n";
        let second = document_with_call(
            "rust",
            "src/second.rs",
            second_source,
            0,
            1,
            "rust fixture second/target().",
            "rust fixture second/caller().",
        );
        let mut incomplete = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![first.clone(), second],
            &[
                ("src/lib.rs", RUST_SOURCE),
                ("src/second.rs", second_source),
            ],
        );
        incomplete.index.documents.pop();
        let omitted = incomplete.normalize();
        assert_eq!(
            omitted.receipt.status,
            CapabilityStatus::Complete,
            "omitted provider document should qualify, not discard, covered evidence: {:?}",
            omitted.receipt
        );
        let ProviderPayload::Calls(omitted) = omitted
            .payload
            .expect("qualified complete Calls payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(
            omitted
                .documents
                .iter()
                .map(|document| document.document_path.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["src/lib.rs", "src/second.rs"]),
            "the payload must still account for the complete indexed source population"
        );
        let exclusion = omitted
            .coverage_exclusions
            .iter()
            .find(|exclusion| exclusion.location.document_path == "src/second.rs")
            .expect("whole omitted provider document must remain explicit");
        assert_eq!(exclusion.reason_code, "provider_document_omitted");
        assert_eq!(exclusion.location.span.start_byte, 0);
        assert_eq!(
            exclusion.location.span.end_byte,
            second_source.len() as u64,
            "the qualification must cover the entire omitted source file"
        );

        let mut duplicate = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![first.clone()],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        duplicate.index.documents.push(first.clone());
        assert_failure(
            &duplicate.normalize(),
            CapabilityStatus::Unavailable,
            "provider_document_duplicate",
        );

        let mut no_owner = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![first.clone()],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        for membership in &mut no_owner.inventory.project_topology.memberships {
            membership.kind = DocumentMembershipKind::PathContext;
        }
        assert_failure(
            &no_owner.normalize(),
            CapabilityStatus::Partial,
            "source_owner_unproven",
        );

        let mut unspecified_encoding = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![first.clone()],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        unspecified_encoding.index.documents[0].position_encoding =
            EnumOrUnknown::new(PositionEncoding::UnspecifiedPositionEncoding);
        assert_failure(
            &unspecified_encoding.normalize(),
            CapabilityStatus::Unavailable,
            "provider_position_encoding_unspecified",
        );

        let mut duplicate_occurrence = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![first],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        let call = duplicate_occurrence.index.documents[0]
            .occurrences
            .iter()
            .find(|occurrence| occurrence.symbol_roles == 0)
            .expect("call occurrence")
            .clone();
        duplicate_occurrence.index.documents[0]
            .occurrences
            .push(call);
        assert_failure(
            &duplicate_occurrence.normalize(),
            CapabilityStatus::Partial,
            "provider_call_occurrence_duplicate",
        );
    }

    #[test]
    fn provider_dependency_documents_do_not_widen_or_downgrade_project_authority() {
        let project = document_with_call(
            "rust",
            "src/lib.rs",
            RUST_SOURCE,
            0,
            1,
            "rust fixture target().",
            "rust fixture caller().",
        );
        let toolchain_path = concat!(
            ".devbox/virtenv/rustup/toolchains/test-toolchain/",
            "lib/rustlib/src/rust/library/test/src/lib.rs"
        );
        let toolchain = document_with_call(
            "rust",
            toolchain_path,
            RUST_SOURCE,
            0,
            1,
            "rust stdlib target().",
            "rust stdlib caller().",
        );
        let fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![project, toolchain],
            &[("src/lib.rs", RUST_SOURCE)],
        );

        let evidence = fixture.normalize();
        assert_eq!(
            evidence.receipt.status,
            CapabilityStatus::Complete,
            "provider dependency and toolchain documents are outside the indexed project population: {:?}",
            evidence.receipt
        );
        let ProviderPayload::Calls(payload) = evidence
            .payload
            .expect("complete project payload")
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(
            payload
                .documents
                .iter()
                .map(|document| document.document_path.as_str())
                .collect::<Vec<_>>(),
            vec!["src/lib.rs"]
        );
        assert_eq!(
            payload.calls.len(),
            1,
            "project call is the positive control"
        );
        assert!(payload.symbols.iter().all(|symbol| {
            symbol
                .definition
                .as_ref()
                .is_none_or(|definition| definition.document_path == "src/lib.rs")
        }));
    }

    #[test]
    fn provider_local_symbols_are_scoped_to_their_document() {
        let first = document_with_call(
            "rust",
            "src/first.rs",
            RUST_SOURCE,
            0,
            1,
            "local 0",
            "local 1",
        );
        let second = document_with_call(
            "rust",
            "src/second.rs",
            RUST_SOURCE,
            0,
            1,
            "local 0",
            "local 1",
        );
        let fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![first, second],
            &[
                ("src/first.rs", RUST_SOURCE),
                ("src/second.rs", RUST_SOURCE),
            ],
        );
        let evidence = fixture.normalize();
        assert_eq!(evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(payload) =
            evidence.payload.expect("complete payload").into_payload()
        else {
            unreachable!("Calls fixture")
        };
        assert_eq!(payload.documents.len(), 2);
        assert_eq!(payload.symbols.len(), 4);
        assert_eq!(payload.calls.len(), 2);
        assert!(
            payload
                .symbols
                .iter()
                .any(|symbol| { symbol.provider_symbol_id == "h00-local:src/first.rs:local 0" })
        );
        assert!(
            payload
                .symbols
                .iter()
                .any(|symbol| { symbol.provider_symbol_id == "h00-local:src/second.rs:local 0" })
        );
    }

    #[test]
    fn unresolved_local_call_target_fails_closed() {
        let mut document = document_with_call(
            "rust",
            "src/lib.rs",
            RUST_SOURCE,
            0,
            1,
            "local 0",
            "local 1",
        );
        document.occurrences.remove(0);
        document.symbols.remove(0);
        let fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        let evidence = fixture.normalize();
        assert_failure(
            &evidence,
            CapabilityStatus::Partial,
            "local_call_target_unresolved",
        );
        let reason = evidence.receipt.reason.expect("bounded failure reason");
        assert!(
            reason.contains("src/lib.rs:"),
            "missing call path: {reason}"
        );
        assert!(
            reason.contains("\"target\""),
            "missing syntax callee: {reason}"
        );
        assert!(reason.contains("local 0"), "missing provider ID: {reason}");
        assert!(
            reason.contains("provider definition occurrence: false"),
            "missing provider-population evidence: {reason}"
        );
    }

    #[test]
    fn canonical_snapshot_overlay_replaces_only_the_exact_affected_population() {
        let fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![
                document_with_call(
                    "rust",
                    "src/first.rs",
                    RUST_SOURCE,
                    0,
                    1,
                    "local 0",
                    "local 1",
                ),
                document_with_call(
                    "rust",
                    "src/second.rs",
                    RUST_SOURCE,
                    0,
                    1,
                    "local 0",
                    "local 1",
                ),
            ],
            &[
                ("src/first.rs", RUST_SOURCE),
                ("src/second.rs", RUST_SOURCE),
            ],
        );
        fs::write(
            &fixture.artifact,
            fixture
                .index
                .write_to_bytes()
                .expect("serialize snapshot fixture"),
        )
        .expect("write snapshot fixture");
        let normalization = normalize_scip_artifact_set_for_inventory_coverage(
            &fixture.root,
            fixture.spec,
            &[ScipArtifactInput {
                artifact_path: fixture.artifact.clone(),
                execution_root: fixture.root.clone(),
                executed_provider_version: "fixture-provider-1.0.0".into(),
                provider_configuration_sha256: "a".repeat(64),
            }],
            &fixture.indexed_sources,
            &fixture.inventory,
        );
        let snapshot = normalization
            .canonical_snapshot
            .expect("complete normalization retains its canonical snapshot");
        let unchanged_before = snapshot
            .document_bytes("src/second.rs")
            .expect("unchanged document bytes");
        let mut replacement = fixture.index.documents[0].clone();
        replacement
            .text
            .push_str("// body-local provider refresh\n");

        reset_canonical_document_canonicalization_count();
        let overlaid = snapshot
            .overlay_affected_documents(
                &BTreeSet::from(["src/first.rs".into()]),
                vec![CanonicalScipDocumentUpdate::Present {
                    document_path: "src/first.rs".into(),
                    document: replacement,
                }],
            )
            .expect("exact affected-document overlay");
        assert_eq!(
            canonical_document_canonicalization_count(),
            1,
            "an affected overlay must canonicalize only the changed provider document"
        );
        assert_eq!(
            overlaid
                .document_bytes("src/second.rs")
                .expect("preserved unaffected document"),
            unchanged_before,
            "unaffected canonical provider evidence must remain byte-identical"
        );
        assert_ne!(
            overlaid.document_manifest_sha256(),
            snapshot.document_manifest_sha256(),
            "the exact canonical manifest must bind the changed provider document"
        );
        assert_ne!(
            overlaid.identity_sha256(),
            snapshot.identity_sha256(),
            "the full snapshot lineage must bind the changed provider document"
        );

        assert!(
            snapshot
                .overlay_affected_documents(
                    &BTreeSet::from(["src/first.rs".into(), "src/second.rs".into()]),
                    vec![CanonicalScipDocumentUpdate::Omitted {
                        document_path: "src/first.rs".into(),
                    }],
                )
                .is_err(),
            "missing an affected-document outcome must fail closed"
        );
    }

    /// FALSIFIER: SCIP document `symbols` and `occurrences` are semantic
    /// populations, not producer-order logs. scip-go 0.2.7 builds its symbol
    /// census from a Go map, so two equivalent full indexes can serialize
    /// these populations in different orders. Canonical snapshot identity and
    /// affected-document parity must not depend on that incidental order.
    #[test]
    fn canonical_snapshot_identity_ignores_document_population_order() {
        let fixture = fixture(
            ScipProviderSpec::scip_go(),
            vec![document_with_call(
                "go",
                "src/lib.go",
                GO_SOURCE,
                1,
                2,
                "scip-go gomod fixture target().",
                "scip-go gomod fixture caller().",
            )],
            &[("src/lib.go", GO_SOURCE)],
        );
        fs::write(
            &fixture.artifact,
            fixture
                .index
                .write_to_bytes()
                .expect("serialize canonical-order fixture"),
        )
        .expect("write canonical-order fixture");
        let normalization = normalize_scip_artifact_set_for_inventory_coverage(
            &fixture.root,
            fixture.spec,
            &[ScipArtifactInput {
                artifact_path: fixture.artifact.clone(),
                execution_root: fixture.root.clone(),
                executed_provider_version: "fixture-provider-1.0.0".into(),
                provider_configuration_sha256: "a".repeat(64),
            }],
            &fixture.indexed_sources,
            &fixture.inventory,
        );
        let baseline = normalization
            .canonical_snapshot
            .expect("complete normalization retains its canonical snapshot");
        let mut reordered_document = fixture.index.documents[0].clone();
        let original_bytes = reordered_document
            .write_to_bytes()
            .expect("serialize original provider document");
        reordered_document.occurrences.reverse();
        reordered_document.symbols.reverse();
        let reordered_bytes = reordered_document
            .write_to_bytes()
            .expect("serialize reordered provider document");
        assert_ne!(
            reordered_bytes, original_bytes,
            "positive control: the producer-order mutation must change raw protobuf bytes"
        );

        let reordered = baseline
            .overlay_affected_documents(
                &BTreeSet::from(["src/lib.go".into()]),
                vec![CanonicalScipDocumentUpdate::Present {
                    document_path: "src/lib.go".into(),
                    document: reordered_document,
                }],
            )
            .expect("semantically equivalent affected-document overlay");
        assert_eq!(
            reordered.document_manifest_sha256(),
            baseline.document_manifest_sha256(),
            "canonical manifest identity must ignore incidental population order"
        );
        assert_eq!(
            reordered.identity_sha256(),
            baseline.identity_sha256(),
            "canonical snapshot lineage must ignore incidental population order"
        );
        assert_eq!(
            reordered.document_bytes("src/lib.go"),
            baseline.document_bytes("src/lib.go"),
            "canonical persisted document bytes must converge"
        );
    }

    /// FALSIFIER: `CapabilityReceipt::input_fingerprint` is documented as
    /// exact provider input/configuration identity. Canonical provider output
    /// has its own sealed snapshot lineage and must not be mixed into that
    /// input coordinate. Otherwise a provider-output metadata change falsely
    /// reports input drift even when repository bytes,
    /// inventory, execution roots, provider version, and configuration are
    /// identical.
    #[test]
    fn calls_input_fingerprint_excludes_provider_output_only_drift() {
        let fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                RUST_SOURCE,
                0,
                1,
                "rust fixture target().",
                "rust fixture caller().",
            )],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        fs::write(
            &fixture.artifact,
            fixture
                .index
                .write_to_bytes()
                .expect("serialize baseline snapshot fixture"),
        )
        .expect("write baseline snapshot fixture");
        let baseline = normalize_scip_artifact_set_for_inventory_coverage(
            &fixture.root,
            fixture.spec,
            &[ScipArtifactInput {
                artifact_path: fixture.artifact.clone(),
                execution_root: fixture.root.clone(),
                executed_provider_version: "fixture-provider-1.0.0".into(),
                provider_configuration_sha256: "a".repeat(64),
            }],
            &fixture.indexed_sources,
            &fixture.inventory,
        );
        assert_eq!(baseline.evidence.receipt.status, CapabilityStatus::Complete);
        let baseline_input = baseline
            .evidence
            .receipt
            .input_fingerprint
            .clone()
            .expect("complete receipt input fingerprint");
        let baseline_snapshot = baseline
            .canonical_snapshot
            .expect("complete normalization retains its canonical snapshot");
        let baseline_snapshot_identity = baseline_snapshot.identity_sha256();

        let mut provider_output_only = fixture.index.documents[0].clone();
        provider_output_only
            .symbols
            .first_mut()
            .expect("provider symbol positive control")
            .documentation
            .push("provider-output-only documentation drift".into());
        let changed_snapshot = baseline_snapshot
            .overlay_affected_documents(
                &BTreeSet::from(["src/lib.rs".into()]),
                vec![CanonicalScipDocumentUpdate::Present {
                    document_path: "src/lib.rs".into(),
                    document: provider_output_only,
                }],
            )
            .expect("overlay provider-output-only drift");
        assert_ne!(
            baseline_snapshot_identity,
            changed_snapshot.identity_sha256(),
            "positive control: sealed provider-output lineage must detect the drift"
        );

        let changed = normalize_canonical_scip_snapshot_for_inventory_coverage(
            &fixture.root,
            changed_snapshot,
            &fixture.indexed_sources,
            &fixture.inventory,
        );
        assert_eq!(changed.evidence.receipt.status, CapabilityStatus::Complete);
        assert_eq!(
            changed.evidence.receipt.input_fingerprint.as_deref(),
            Some(baseline_input.as_str()),
            "provider-output-only drift must not masquerade as provider input drift"
        );
    }

    /// FALSIFIER: one provider's input authority is bounded to the project
    /// units, inputs, and documents it actually governs. A Go-only manifest
    /// change in a mixed repository must not claim that identical Rust
    /// provider inputs drifted merely because the repository-wide inventory
    /// changed.
    #[test]
    fn calls_input_fingerprint_excludes_unrelated_language_inventory_drift() {
        let fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![document_with_call(
                "rust",
                "src/lib.rs",
                RUST_SOURCE,
                0,
                1,
                "rust fixture target().",
                "rust fixture caller().",
            )],
            &[("src/lib.rs", RUST_SOURCE)],
        );
        fs::write(
            &fixture.artifact,
            fixture
                .index
                .write_to_bytes()
                .expect("serialize mixed-inventory baseline"),
        )
        .expect("write mixed-inventory baseline");
        let normalize = |inventory: &ProjectInventory| {
            normalize_scip_artifact_set_for_inventory_coverage(
                &fixture.root,
                fixture.spec,
                &[ScipArtifactInput {
                    artifact_path: fixture.artifact.clone(),
                    execution_root: fixture.root.clone(),
                    executed_provider_version: "fixture-provider-1.0.0".into(),
                    provider_configuration_sha256: "a".repeat(64),
                }],
                &fixture.indexed_sources,
                inventory,
            )
        };
        let baseline = normalize(&fixture.inventory);
        assert_eq!(baseline.evidence.receipt.status, CapabilityStatus::Complete);

        let mut go_only_drift = fixture.inventory.clone();
        go_only_drift.project_topology.units.push(ProjectUnit {
            project_unit_id: ProjectUnitId::new("fixture:go:go:module"),
            language_id: LanguageId::new("go"),
            ecosystem_id: EcosystemId::new("go"),
            kind: ProjectUnitKind::Module,
            root_path: "go-module".into(),
            manifest_path: Some("go-module/go.mod".into()),
            compilation_root_paths: Vec::new(),
        });
        go_only_drift.inputs.push(ProjectInput {
            path: "go-module/go.mod".into(),
            language_id: LanguageId::new("go"),
            ecosystem_id: EcosystemId::new("go"),
            role: ProjectInputRole::Manifest,
            content_sha256: "b".repeat(64),
        });
        assert_ne!(
            project_inventory_fingerprint(&fixture.inventory).expect("baseline inventory"),
            project_inventory_fingerprint(&go_only_drift).expect("changed global inventory"),
            "positive control: the repository-wide inventory must observe Go drift"
        );

        let changed = normalize(&go_only_drift);
        assert_eq!(changed.evidence.receipt.status, CapabilityStatus::Complete);
        assert_eq!(
            changed.evidence.receipt.input_fingerprint, baseline.evidence.receipt.input_fingerprint,
            "unrelated Go inventory must not perturb Rust provider input authority"
        );
    }

    #[test]
    fn overlaid_snapshot_normalization_equals_fresh_full_normalization() {
        const BEFORE: &str = "fn target() {}\nfn caller() { target(); }\n";
        const AFTER: &str =
            "fn target() {}\n// length-changing body-local edit\nfn caller() { target(); }\n";
        const UNCHANGED: &str = "fn caller() { target(); }\n";
        let mut unchanged_caller = Occurrence::new();
        unchanged_caller.symbol = "rust fixture stable_caller().".into();
        unchanged_caller.symbol_roles = SymbolRole::Definition.value();
        unchanged_caller.range = vec![0, 3, 9];
        unchanged_caller.enclosing_range = vec![0, 0, 0, 25];
        let mut unchanged_call = Occurrence::new();
        unchanged_call.symbol = "rust fixture target().".into();
        unchanged_call.range = vec![0, 14, 20];
        let mut unchanged_caller_information = SymbolInformation::new();
        unchanged_caller_information.symbol = "rust fixture stable_caller().".into();
        unchanged_caller_information.display_name = "caller".into();
        unchanged_caller_information.kind = EnumOrUnknown::new(symbol_information::Kind::Function);
        let mut unchanged_document = Document::new();
        unchanged_document.language = "rust".into();
        unchanged_document.relative_path = "src/stable.rs".into();
        unchanged_document.text = UNCHANGED.into();
        unchanged_document.position_encoding =
            EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        unchanged_document.occurrences = vec![unchanged_caller, unchanged_call];
        unchanged_document.symbols = vec![unchanged_caller_information];
        let unchanged_definition_count = unchanged_document
            .occurrences
            .iter()
            .filter(|occurrence| occurrence.symbol_roles & SymbolRole::Definition.value() != 0)
            .count();
        let mut fixture = fixture(
            ScipProviderSpec::rust_analyzer(),
            vec![
                document_with_call(
                    "rust",
                    "src/lib.rs",
                    BEFORE,
                    0,
                    1,
                    "rust fixture target().",
                    "rust fixture caller().",
                ),
                unchanged_document.clone(),
            ],
            &[("src/lib.rs", BEFORE), ("src/stable.rs", UNCHANGED)],
        );
        fs::write(
            &fixture.artifact,
            fixture
                .index
                .write_to_bytes()
                .expect("serialize baseline snapshot fixture"),
        )
        .expect("write baseline snapshot fixture");
        let baseline = normalize_scip_artifact_set_for_inventory_coverage(
            &fixture.root,
            fixture.spec,
            &[ScipArtifactInput {
                artifact_path: fixture.artifact.clone(),
                execution_root: fixture.root.clone(),
                executed_provider_version: "fixture-provider-1.0.0".into(),
                provider_configuration_sha256: "a".repeat(64),
            }],
            &fixture.indexed_sources,
            &fixture.inventory,
        );
        assert_eq!(baseline.evidence.receipt.status, CapabilityStatus::Complete);
        let ProviderPayload::Calls(prior_payload) = baseline
            .evidence
            .payload
            .as_ref()
            .expect("complete baseline Calls payload")
            .clone()
            .into_payload()
        else {
            unreachable!("Calls fixture")
        };
        let baseline_source_syntax_cache = baseline
            .source_syntax_cache
            .expect("complete normalization retains document-local syntax acceleration");
        let baseline_snapshot = baseline
            .canonical_snapshot
            .expect("complete baseline snapshot");

        fs::write(fixture.root.join("src/lib.rs"), AFTER).expect("write changed source");
        fixture.indexed_sources[0].blake3_hash =
            blake3::hash(AFTER.as_bytes()).to_hex().to_string();
        // The edit moves only the caller body. The independently extracted
        // cross-document surface therefore remains the exact prior surface.
        let changed_document = document_with_call(
            "rust",
            "src/lib.rs",
            AFTER,
            0,
            2,
            "rust fixture target().",
            "rust fixture caller().",
        );
        let changed_definition_count = changed_document
            .occurrences
            .iter()
            .filter(|occurrence| occurrence.symbol_roles & SymbolRole::Definition.value() != 0)
            .count();
        assert_eq!(
            baseline_snapshot.document_count(),
            2,
            "positive control: the canonical parent contains one changed and one retained document"
        );
        let baseline_changed_storage = baseline_snapshot
            .document_storage_address("src/lib.rs")
            .expect("baseline changed document storage");
        let baseline_unchanged_storage = baseline_snapshot
            .document_storage_address("src/stable.rs")
            .expect("baseline unchanged document storage");
        let overlaid_snapshot = baseline_snapshot
            .overlay_affected_documents(
                &BTreeSet::from(["src/lib.rs".into()]),
                vec![CanonicalScipDocumentUpdate::Present {
                    document_path: "src/lib.rs".into(),
                    document: changed_document.clone(),
                }],
            )
            .expect("overlay exact changed provider document");
        assert_eq!(
            overlaid_snapshot.document_storage_address("src/stable.rs"),
            Some(baseline_unchanged_storage),
            "a one-document overlay must share immutable retained documents instead of deep-cloning the canonical snapshot"
        );
        assert_ne!(
            overlaid_snapshot.document_storage_address("src/lib.rs"),
            Some(baseline_changed_storage),
            "positive control: the affected canonical document must own new immutable storage"
        );
        NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT.with(|count| count.set(0));
        PROVIDER_DEFINITION_RECORD_RETAIN_COUNT.with(|count| count.set(0));
        DEFINITION_RECORD_GROUP_SCAN_COUNT.with(|count| count.set(0));
        DEFINITION_GROUP_CANONICALIZATION_COUNT.with(|count| count.set(0));
        CALL_DOCUMENT_RESOLUTION_COUNT.with(|count| count.set(0));
        let uncached = normalize_canonical_scip_snapshot_for_inventory_coverage(
            &fixture.root,
            overlaid_snapshot.clone(),
            &fixture.indexed_sources,
            &fixture.inventory,
        );
        let uncached_occurrences =
            NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT.with(std::cell::Cell::get);
        let uncached_definitions =
            PROVIDER_DEFINITION_RECORD_RETAIN_COUNT.with(std::cell::Cell::get);
        let uncached_call_documents = CALL_DOCUMENT_RESOLUTION_COUNT.with(std::cell::Cell::get);
        let uncached_definition_groups =
            DEFINITION_GROUP_CANONICALIZATION_COUNT.with(std::cell::Cell::get);
        assert_eq!(uncached.timings.provider_documents, 2);
        assert_eq!(uncached.timings.provider_document_cache_hits, 0);
        assert_eq!(
            uncached.timings.source_documents - uncached.timings.syntax_cache_hits,
            2,
            "positive control: ordinary global normalization reparses both source documents"
        );
        assert!(
            uncached_occurrences > changed_document.occurrences.len(),
            "positive control: the global pass must normalize the populated unchanged document"
        );
        assert!(
            uncached_definitions > changed_definition_count,
            "positive control: the global pass must collect definitions from the populated unchanged document"
        );
        assert_eq!(
            uncached_call_documents, 2,
            "positive control: the global pass must resolve calls in both provider documents"
        );
        assert_eq!(
            uncached_definition_groups, 3,
            "positive control: the global pass must canonicalize every provider definition group"
        );

        NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT.with(|count| count.set(0));
        PROVIDER_DEFINITION_RECORD_RETAIN_COUNT.with(|count| count.set(0));
        DEFINITION_GROUP_CANONICALIZATION_COUNT.with(|count| count.set(0));
        CALL_DOCUMENT_RESOLUTION_COUNT.with(|count| count.set(0));
        let affected_documents = BTreeSet::from(["src/lib.rs".into()]);
        let incremental = normalize_canonical_scip_snapshot_with_affected_calls_reuse(
            &fixture.root,
            overlaid_snapshot.clone(),
            &fixture.indexed_sources,
            &fixture.inventory,
            Some(&baseline_source_syntax_cache),
            &affected_documents,
            &prior_payload,
        );
        assert_eq!(incremental.timings.provider_documents, 2);
        assert_eq!(incremental.timings.provider_document_cache_hits, 1);
        assert_eq!(incremental.timings.definition_document_cache_hits, 1);
        assert_eq!(incremental.timings.definition_groups, 3);
        assert_eq!(incremental.timings.definition_group_reuse_hits, 1);
        assert_eq!(incremental.timings.call_documents, 2);
        assert_eq!(incremental.timings.call_document_reuse_hits, 1);
        assert_eq!(
            incremental.timings.source_documents - incremental.timings.syntax_cache_hits,
            1,
            "only the source whose exact content identity changed may be reparsed"
        );
        assert_eq!(
            NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT.with(std::cell::Cell::get),
            changed_document.occurrences.len(),
            "a one-document refresh must not renormalize provider occurrences from an exact unchanged document"
        );
        assert_eq!(
            PROVIDER_DEFINITION_RECORD_RETAIN_COUNT.with(std::cell::Cell::get),
            changed_definition_count,
            "a one-document refresh must not recollect definitions from an exact unchanged document"
        );
        assert_eq!(
            DEFINITION_RECORD_GROUP_SCAN_COUNT.with(std::cell::Cell::get),
            changed_definition_count,
            "a one-document refresh must not rescan definition records owned only by unchanged documents"
        );
        assert_eq!(
            CALL_DOCUMENT_RESOLUTION_COUNT.with(std::cell::Cell::get),
            1,
            "a one-document refresh must not re-resolve Calls owned by an unchanged document"
        );
        assert_eq!(
            DEFINITION_GROUP_CANONICALIZATION_COUNT.with(std::cell::Cell::get),
            2,
            "a one-document refresh must canonicalize only base identities touched by that document"
        );
        assert_eq!(
            incremental.evidence.receipt.status,
            CapabilityStatus::Complete,
            "overlaid complete snapshot must retain global normalization authority: {:?}",
            incremental.evidence.receipt
        );
        assert_eq!(
            incremental.evidence, uncached.evidence,
            "syntax acceleration must not change global semantic authority"
        );
        let incremental_source_syntax_cache = incremental
            .source_syntax_cache
            .as_ref()
            .expect("incremental normalization retains document acceleration");
        let baseline_unchanged = baseline_source_syntax_cache
            .provider_documents
            .get("src/stable.rs")
            .expect("baseline unchanged provider document");
        let incremental_unchanged = incremental_source_syntax_cache
            .provider_documents
            .get("src/stable.rs")
            .expect("incremental unchanged provider document");
        assert!(
            incremental_unchanged.shares_immutable_acceleration_with(baseline_unchanged),
            "a cache hit must share immutable provider-document acceleration instead of deep-cloning the unchanged population"
        );
        let unchanged_base_id = "rust fixture stable_caller().";
        let baseline_canonical = baseline_source_syntax_cache
            .canonical_definitions
            .as_ref()
            .expect("baseline canonical definition acceleration");
        let incremental_canonical = incremental_source_syntax_cache
            .canonical_definitions
            .as_ref()
            .expect("incremental canonical definition acceleration");
        let baseline_aliases = baseline_canonical
            .aliases
            .get(unchanged_base_id)
            .expect("baseline unchanged definition aliases");
        let incremental_aliases = incremental_canonical
            .aliases
            .get(unchanged_base_id)
            .expect("incremental unchanged definition aliases");
        assert!(
            Arc::ptr_eq(baseline_aliases, incremental_aliases),
            "an unchanged canonical alias group must remain physically shared"
        );
        for canonical_id in baseline_aliases.iter() {
            assert!(
                Arc::ptr_eq(
                    baseline_canonical
                        .definitions
                        .get(canonical_id.as_ref())
                        .expect("baseline unchanged canonical definition"),
                    incremental_canonical
                        .definitions
                        .get(canonical_id.as_ref())
                        .expect("incremental unchanged canonical definition")
                ),
                "an unchanged canonical definition record must remain physically shared"
            );
        }

        let mut stale_prior_payload = prior_payload.clone();
        stale_prior_payload
            .documents
            .iter_mut()
            .find(|document| document.document_path == "src/stable.rs")
            .expect("unchanged prior document positive control")
            .content_sha256 = "0".repeat(64);
        let refused = normalize_canonical_scip_snapshot_with_affected_calls_reuse(
            &fixture.root,
            overlaid_snapshot.clone(),
            &fixture.indexed_sources,
            &fixture.inventory,
            Some(&baseline_source_syntax_cache),
            &affected_documents,
            &stale_prior_payload,
        );
        assert_eq!(
            refused.evidence.receipt.status,
            CapabilityStatus::Unavailable
        );
        assert_eq!(
            refused.evidence.receipt.reason_code.as_deref(),
            Some("affected_calls_source_mismatch")
        );
        assert!(
            refused.evidence.payload.is_none() && refused.canonical_snapshot.is_none(),
            "mismatched prior source authority must never produce a reusable payload or snapshot"
        );

        let mut changed_surface_sources = fixture.indexed_sources.clone();
        changed_surface_sources[0].cross_document_surface_sha256 = Some("f".repeat(64));
        assert_ne!(
            changed_surface_sources[0].cross_document_surface_sha256,
            fixture.indexed_sources[0].cross_document_surface_sha256,
            "positive control: the affected source surface identity must differ"
        );
        let refused = normalize_canonical_scip_snapshot_with_affected_calls_reuse(
            &fixture.root,
            overlaid_snapshot.clone(),
            &changed_surface_sources,
            &fixture.inventory,
            Some(&baseline_source_syntax_cache),
            &affected_documents,
            &prior_payload,
        );
        assert_eq!(
            refused.evidence.receipt.status,
            CapabilityStatus::Unavailable
        );
        assert_eq!(
            refused.evidence.receipt.reason_code.as_deref(),
            Some("affected_calls_surface_mismatch")
        );

        const SHIFTED: &str = "// body-local prefix\nfn target() {}\nfn caller() { target(); }\n";
        fs::write(fixture.root.join("src/lib.rs"), SHIFTED).expect("write shifted source");
        let mut shifted_sources = fixture.indexed_sources.clone();
        shifted_sources[0].blake3_hash = blake3::hash(SHIFTED.as_bytes()).to_hex().to_string();
        let shifted_document = document_with_call(
            "rust",
            "src/lib.rs",
            SHIFTED,
            1,
            2,
            "rust fixture target().",
            "rust fixture caller().",
        );
        let shifted_snapshot = baseline_snapshot
            .overlay_affected_documents(
                &affected_documents,
                vec![CanonicalScipDocumentUpdate::Present {
                    document_path: "src/lib.rs".into(),
                    document: shifted_document,
                }],
            )
            .expect("overlay a body-only edit that moves a referenced definition");
        CALL_DOCUMENT_RESOLUTION_COUNT.with(|count| count.set(0));
        let shifted_incremental = normalize_canonical_scip_snapshot_with_affected_calls_reuse(
            &fixture.root,
            shifted_snapshot.clone(),
            &shifted_sources,
            &fixture.inventory,
            Some(&baseline_source_syntax_cache),
            &affected_documents,
            &prior_payload,
        );
        assert_eq!(
            shifted_incremental.evidence.receipt.status,
            CapabilityStatus::Complete
        );
        assert_eq!(
            shifted_incremental.timings.call_document_reuse_hits, 0,
            "an unchanged caller must be re-resolved when its affected target's canonical symbol moved"
        );
        assert_eq!(
            CALL_DOCUMENT_RESOLUTION_COUNT.with(std::cell::Cell::get),
            2,
            "both the affected document and its unchanged dependent caller must be re-resolved"
        );
        let shifted_full = normalize_canonical_scip_snapshot_for_inventory_coverage(
            &fixture.root,
            shifted_snapshot,
            &shifted_sources,
            &fixture.inventory,
        );
        assert_eq!(
            shifted_incremental.evidence, shifted_full.evidence,
            "dependent-call re-resolution must remain byte-equivalent to a fresh full normalization"
        );
        fs::write(fixture.root.join("src/lib.rs"), AFTER).expect("restore changed source");

        let mut altered_unchanged_document = unchanged_document.clone();
        altered_unchanged_document.text.clear();
        let provider_changed_snapshot = overlaid_snapshot
            .overlay_affected_documents(
                &BTreeSet::from(["src/stable.rs".into()]),
                vec![CanonicalScipDocumentUpdate::Present {
                    document_path: "src/stable.rs".into(),
                    document: altered_unchanged_document,
                }],
            )
            .expect("alter one canonical provider document without changing live source");
        let incremental_cache = incremental
            .source_syntax_cache
            .as_ref()
            .expect("incremental normalization retains exact document acceleration");
        NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT.with(|count| count.set(0));
        PROVIDER_DEFINITION_RECORD_RETAIN_COUNT.with(|count| count.set(0));
        let provider_changed = normalize_canonical_scip_snapshot_with_source_syntax_cache(
            &fixture.root,
            provider_changed_snapshot,
            &fixture.indexed_sources,
            &fixture.inventory,
            Some(incremental_cache),
        );
        assert_eq!(provider_changed.timings.provider_document_cache_hits, 1);
        assert_eq!(provider_changed.timings.definition_document_cache_hits, 1);
        assert_eq!(
            NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT.with(std::cell::Cell::get),
            unchanged_document.occurrences.len(),
            "altered provider bytes must invalidate that document even when live source bytes are unchanged"
        );
        assert_eq!(
            PROVIDER_DEFINITION_RECORD_RETAIN_COUNT.with(std::cell::Cell::get),
            unchanged_definition_count,
            "altered provider bytes must invalidate cached definitions for that document"
        );
        let mut provider_changed_evidence = provider_changed.evidence;
        let mut incremental_evidence = incremental.evidence.clone();
        for evidence in [&mut provider_changed_evidence, &mut incremental_evidence] {
            if let Some(normalized) = evidence.payload.take() {
                let ProviderPayload::Calls(mut payload) = normalized.into_payload() else {
                    unreachable!("Calls fixture")
                };
                payload.canonical_snapshot_sha256 = None;
                evidence.payload = Some(
                    normalize_provider_payload_typed(&ProviderPayload::Calls(payload))
                        .expect("fixture payload remains normalized after identity elision"),
                );
            }
        }
        assert_eq!(
            provider_changed_evidence, incremental_evidence,
            "provider text omission is semantically inert apart from canonical snapshot identity, but must still cross the exact cache key"
        );

        let mut textless_changed_document = changed_document.clone();
        textless_changed_document.text.clear();
        let textless_snapshot = overlaid_snapshot
            .overlay_affected_documents(
                &BTreeSet::from(["src/lib.rs".into()]),
                vec![CanonicalScipDocumentUpdate::Present {
                    document_path: "src/lib.rs".into(),
                    document: textless_changed_document,
                }],
            )
            .expect("provider snapshot whose positions do not embed source text");
        let textless_baseline = normalize_canonical_scip_snapshot_with_source_syntax_cache(
            &fixture.root,
            textless_snapshot.clone(),
            &fixture.indexed_sources,
            &fixture.inventory,
            Some(incremental_cache),
        );
        assert_eq!(
            textless_baseline.evidence.receipt.status,
            CapabilityStatus::Complete
        );
        let textless_cache = textless_baseline
            .source_syntax_cache
            .as_ref()
            .expect("textless provider baseline retains exact acceleration");
        let source_only_after = format!("{AFTER}// cache-key source drift\n");
        fs::write(fixture.root.join("src/lib.rs"), &source_only_after)
            .expect("write source-only cache-key drift");
        fixture.indexed_sources[0].blake3_hash = blake3::hash(source_only_after.as_bytes())
            .to_hex()
            .to_string();
        NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT.with(|count| count.set(0));
        PROVIDER_DEFINITION_RECORD_RETAIN_COUNT.with(|count| count.set(0));
        let source_changed = normalize_canonical_scip_snapshot_with_source_syntax_cache(
            &fixture.root,
            textless_snapshot,
            &fixture.indexed_sources,
            &fixture.inventory,
            Some(textless_cache),
        );
        assert_eq!(
            source_changed.evidence.receipt.status,
            CapabilityStatus::Complete
        );
        assert_eq!(source_changed.timings.provider_document_cache_hits, 1);
        assert_eq!(source_changed.timings.definition_document_cache_hits, 1);
        assert_eq!(
            NORMALIZED_PROVIDER_OCCURRENCE_RETAIN_COUNT.with(std::cell::Cell::get),
            changed_document.occurrences.len(),
            "changed live source bytes must invalidate that document even when canonical provider bytes are unchanged"
        );
        assert_eq!(
            PROVIDER_DEFINITION_RECORD_RETAIN_COUNT.with(std::cell::Cell::get),
            changed_definition_count,
            "changed live source bytes must invalidate cached definitions for that document"
        );

        fs::write(fixture.root.join("src/lib.rs"), AFTER).expect("restore changed source");
        fixture.indexed_sources[0].blake3_hash =
            blake3::hash(AFTER.as_bytes()).to_hex().to_string();

        fixture.index.documents = vec![changed_document, unchanged_document];
        let fresh_artifact = fixture._workspace.path().join("fresh.scip");
        fs::write(
            &fresh_artifact,
            fixture
                .index
                .write_to_bytes()
                .expect("serialize fresh full snapshot"),
        )
        .expect("write fresh full snapshot");
        let fresh = normalize_scip_artifact_set_for_inventory_coverage(
            &fixture.root,
            fixture.spec,
            &[ScipArtifactInput {
                artifact_path: fresh_artifact,
                execution_root: fixture.root.clone(),
                executed_provider_version: "fixture-provider-1.0.0".into(),
                provider_configuration_sha256: "a".repeat(64),
            }],
            &fixture.indexed_sources,
            &fixture.inventory,
        );
        assert_eq!(fresh.evidence.receipt.status, CapabilityStatus::Complete);
        assert_eq!(
            incremental.evidence, fresh.evidence,
            "the same canonical document population must produce byte-equivalent authority regardless of full versus affected refresh"
        );
    }
}
