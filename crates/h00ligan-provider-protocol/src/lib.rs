//! Bounded, identity-bearing protocol for h00ligan semantic providers.
//!
//! Provider processes are accelerators, not authorities. Every response is
//! admitted only against the request, session, provider build, repository,
//! configuration, source population, and source epoch that the h00ligan runtime already owns.
//! The wire frame keeps typed JSON metadata separate from raw source/SCIP
//! attachments so binary evidence is never base64-expanded.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const SEMANTIC_PROVIDER_PROTOCOL: &str = "h00/semantic-provider/v15";
pub const H00_RUST_ANALYZER_PROVIDER_ID: &str = "h00-rust-analyzer-scip";
pub const H00_RUST_ANALYZER_LANGUAGE: &str = "rust";
pub const H00_RUST_ANALYZER_UPSTREAM_VERSION: &str = "1.97.1";
pub const H00_RUST_ANALYZER_UPSTREAM_COMMIT: &str = "8bab26f4f68e0e26f0bb7960be334d5b520ea452";
pub const H00_RUST_ANALYZER_IMPLEMENTATION_V6: &str = "rust-analyzer-1.97.1/cargo-profile=explicit/cargo-lockfile=private-redirect/workspace-resolution=bound/build-scripts=required/proc-macros=required/runtime-executables=exact/durable-semantic-inputs=v2/v6";
pub const H00_GO_PROVIDER_ID: &str = "h00-gopls-scip";
pub const H00_GO_LANGUAGE: &str = "go";
pub const H00_GOPLS_UPSTREAM_VERSION: &str = "v0.23.0";
pub const H00_GOPLS_UPSTREAM_COMMIT: &str = "014f87ff5c01915bc90f4f11a6bb8aea3e0edbd7";
pub const H00_SCIP_GO_UPSTREAM_VERSION: &str = "v0.2.7";
pub const H00_SCIP_GO_UPSTREAM_COMMIT: &str = "2e9ff3c2603a85daabe125c9f20075ec52df0731";
pub const H00_GO_IMPLEMENTATION_V4: &str = "gopls-v0.23.0+scip-go-v0.2.7/project-input-reconfigure=discard-on-failure/snapshot-inputs=exact/callable-liveness=go-rta-v1/h00ligan-v4";
pub const H00_PYREFLY_PROVIDER_ID: &str = "h00-pyrefly-scip";
pub const H00_PYREFLY_LANGUAGE: &str = "python";
pub const H00_PYREFLY_UPSTREAM_VERSION: &str = "1.2.0";
pub const H00_PYREFLY_UPSTREAM_COMMIT: &str = "1933169ad8ee9e4d4114112eb56ef0811fb0a094";
pub const H00_PYREFLY_IMPLEMENTATION_V1: &str = "pyrefly-1.2.0/h00-semantic-provider-v1";
pub const H00_TYPESCRIPT_PROVIDER_ID: &str = "h00-typescript-native-scip";
pub const H00_TYPESCRIPT_LANGUAGE: &str = "typescript";
pub const H00_TYPESCRIPT_UPSTREAM_VERSION: &str = "7.0.2";
pub const H00_TYPESCRIPT_UPSTREAM_COMMIT: &str = "2bd066d87f5bafd315be9f40889d0a60b9e58e0b";
pub const H00_SCIP_BINDINGS_UPSTREAM_VERSION: &str = "v0.9.0";
pub const H00_SCIP_BINDINGS_UPSTREAM_COMMIT: &str = "e8ee0ae6038f8298e2195812eea9d7b1196748ae";
pub const H00_TYPESCRIPT_IMPLEMENTATION_V2: &str =
    "typescript-native-7.0.2+scip-v0.9.0/independent-semantic-input-bound/h00-semantic-provider-v2";
pub const GO_PROVIDER_SEMANTIC_ENVIRONMENT: &[&str] = &[
    "CGO_ENABLED",
    "GOCACHE",
    "GO111MODULE",
    "GOARCH",
    "GOENV",
    "GOEXPERIMENT",
    "GOFLAGS",
    "GOMODCACHE",
    "GOOS",
    "GOPRIVATE",
    "GOPROXY",
    "GOROOT",
    "GOSUMDB",
    "GOTOOLCHAIN",
    "GOWORK",
];
/// Exact PID of the process that owns one disposable semantic provider.
///
/// The spawner sets this after clearing the child environment. Providers must
/// reject startup if they have already been reparented, then keep watching this
/// exact identity for the remainder of their process lifetime. This is volatile
/// lifecycle metadata and must never enter semantic runtime fingerprints.
pub const PROVIDER_PARENT_PID_ENV: &str = "H00_PROVIDER_PARENT_PID";
pub const RESOLVED_TOOLCHAIN_SHA256_ENV: &str = "H00_RESOLVED_TOOLCHAIN_SHA256";
pub const RESOLVED_RUSTC_SHA256_ENV: &str = "H00_RESOLVED_RUSTC_SHA256";
pub const RESOLVED_CARGO_SHA256_ENV: &str = "H00_RESOLVED_CARGO_SHA256";
pub const RESOLVED_GO_SHA256_ENV: &str = "H00_RESOLVED_GO_SHA256";
pub const SEMANTIC_PROVIDER_CACHE_DIR_ENV: &str = "H00_SEMANTIC_PROVIDER_CACHE_DIR";
pub const RUST_SEMANTIC_PROFILE_ENV: &str = "H00_RUST_SEMANTIC_PROFILE";
pub const RUST_SEMANTIC_PROFILE_SCHEMA: &str = "h00/rust-semantic-profile/v1";
pub const SEMANTIC_PROVIDER_FRAME_MAGIC: &[u8; 8] = b"H00SP15\0";
pub const CALLABLE_LIVENESS_ANALYSIS_ID: &str = "callable_liveness";
pub const CALLABLE_LIVENESS_ANALYSIS_SCHEMA_V1: &str = "h00/semantic-provider/callable-liveness/v1";
pub const GO_CALLABLE_LIVENESS_CONFIGURATION_V1: &str =
    "go-rta-v1/production=main+public-api/tests=go-test-roots";
pub const PROVIDER_FRAME_HEADER_BYTES: usize = 20;
const SOURCE_POPULATION_SCHEMA: &[u8] = b"h00/semantic-provider/source-population/v1\0";
const PROVIDER_RUNTIME_CONFIGURATION_SCHEMA: &[u8] =
    b"h00/semantic-provider/runtime-configuration/v1\0";
const RESOLVED_AUTHORITY_CONFIGURATION_SCHEMA: &[u8] =
    b"h00/semantic-provider/resolved-authority-configuration/v2\0";
const PROVIDER_SEMANTIC_INPUTS_SCHEMA: &str = "h00/semantic-provider/semantic-inputs/v4";
const PROVIDER_SEMANTIC_INPUTS_DIGEST_SCHEMA: &[u8] =
    b"h00/semantic-provider/semantic-inputs-digest/v4\0";
const PROVIDER_IDENTITY_DIGEST_SCHEMA: &[u8] =
    b"h00/semantic-provider/provider-identity-digest/v2\0";
const PROVIDER_SEMANTIC_PATH_SCHEMA: &[u8] = b"h00/semantic-provider/semantic-path/v3\0";
const MAX_PROVIDER_SEMANTIC_INPUT_ENTRIES: u64 = 2_000_000;
const MAX_PROVIDER_SEMANTIC_INPUT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_RUST_SEMANTIC_PROFILE_BYTES: usize = 16 * 1024;
const MAX_PROVIDER_RUNTIME_COMPONENTS: usize = 64;
const MAX_PROVIDER_RUNTIME_COMPONENT_NAME_BYTES: usize = 64;

/// Cargo feature population analyzed by one Rust semantic-provider session.
///
/// This is an authority coordinate, not a convenience flag. `WorkspaceDefault`
/// describes the ordinary host build selected by Cargo manifests. `All` and
/// `Selected` are deliberate alternate configurations and must never be
/// silently substituted for that default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RustCargoFeatures {
    WorkspaceDefault,
    All,
    Selected {
        features: Vec<String>,
        no_default_features: bool,
    },
}

/// Exact Rust program configuration requested by the h00ligan product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RustSemanticProfile {
    pub schema_version: String,
    pub cargo_features: RustCargoFeatures,
    /// Optional explicit Rust target triple. `None` means the resolved
    /// toolchain's host target; target-specification file paths are not yet
    /// admitted because their bytes would need separate authority.
    pub target: Option<String>,
}

impl RustSemanticProfile {
    #[must_use]
    pub fn workspace_default() -> Self {
        Self {
            schema_version: RUST_SEMANTIC_PROFILE_SCHEMA.into(),
            cargo_features: RustCargoFeatures::WorkspaceDefault,
            target: None,
        }
    }

    #[must_use]
    pub fn all_features() -> Self {
        Self {
            schema_version: RUST_SEMANTIC_PROFILE_SCHEMA.into(),
            cargo_features: RustCargoFeatures::All,
            target: None,
        }
    }

    pub fn selected_features(
        features: impl IntoIterator<Item = String>,
        no_default_features: bool,
    ) -> Result<Self, SemanticProviderProtocolError> {
        let mut features = features.into_iter().collect::<Vec<_>>();
        features.sort();
        features.dedup();
        let profile = Self {
            schema_version: RUST_SEMANTIC_PROFILE_SCHEMA.into(),
            cargo_features: RustCargoFeatures::Selected {
                features,
                no_default_features,
            },
            target: None,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn with_target(
        mut self,
        target: impl Into<String>,
    ) -> Result<Self, SemanticProviderProtocolError> {
        self.target = Some(target.into());
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), SemanticProviderProtocolError> {
        if self.schema_version != RUST_SEMANTIC_PROFILE_SCHEMA {
            return Err(SemanticProviderProtocolError::InvalidRustSemanticProfile(
                "schema mismatch".into(),
            ));
        }
        if let RustCargoFeatures::Selected { features, .. } = &self.cargo_features
            && (features.is_empty()
                || !features.windows(2).all(|pair| pair[0] < pair[1])
                || features.iter().any(|feature| {
                    feature.is_empty()
                        || feature.len() > 256
                        || feature.chars().any(char::is_whitespace)
                        || feature.chars().any(char::is_control)
                }))
        {
            return Err(SemanticProviderProtocolError::InvalidRustSemanticProfile(
                "selected Cargo features must be a nonempty sorted unique bounded population"
                    .into(),
            ));
        }
        if self.target.as_deref().is_some_and(|target| {
            target.is_empty()
                || target.len() > 256
                || !target
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        }) {
            return Err(SemanticProviderProtocolError::InvalidRustSemanticProfile(
                "target must be a bounded Rust target triple, not a path".into(),
            ));
        }
        Ok(())
    }

    pub fn to_environment_value(&self) -> Result<String, SemanticProviderProtocolError> {
        self.validate()?;
        let encoded = serde_json::to_string(self).map_err(|error| {
            SemanticProviderProtocolError::InvalidRustSemanticProfile(error.to_string())
        })?;
        if encoded.len() > MAX_RUST_SEMANTIC_PROFILE_BYTES {
            return Err(SemanticProviderProtocolError::InvalidRustSemanticProfile(
                "encoded profile exceeds its byte bound".into(),
            ));
        }
        Ok(encoded)
    }

    pub fn from_environment_value(value: &str) -> Result<Self, SemanticProviderProtocolError> {
        if value.is_empty() || value.len() > MAX_RUST_SEMANTIC_PROFILE_BYTES {
            return Err(SemanticProviderProtocolError::InvalidRustSemanticProfile(
                "encoded profile is empty or oversized".into(),
            ));
        }
        let profile: Self = serde_json::from_str(value).map_err(|error| {
            SemanticProviderProtocolError::InvalidRustSemanticProfile(error.to_string())
        })?;
        profile.validate()?;
        Ok(profile)
    }
}

impl Default for RustSemanticProfile {
    fn default() -> Self {
        Self::workspace_default()
    }
}

/// Hard bounds negotiated by both ends before any provider work is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderFrameLimits {
    pub max_frame_bytes: usize,
    pub max_metadata_bytes: usize,
    pub max_attachments: usize,
    pub max_attachment_bytes: usize,
    pub max_total_attachment_bytes: usize,
    pub max_document_paths: usize,
    pub max_semantic_input_paths: usize,
    pub max_outstanding_requests: usize,
}

impl Default for ProviderFrameLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 128 * 1024 * 1024,
            max_metadata_bytes: 4 * 1024 * 1024,
            max_attachments: 4096,
            max_attachment_bytes: 64 * 1024 * 1024,
            max_total_attachment_bytes: 120 * 1024 * 1024,
            max_document_paths: 4096,
            max_semantic_input_paths: 8192,
            max_outstanding_requests: 64,
        }
    }
}

/// One typed metadata document plus zero or more opaque binary attachments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderFrame<T> {
    pub metadata: T,
    pub attachments: Vec<Vec<u8>>,
}

/// Exact executable and patched-upstream identity of one provider process.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSourceComponent {
    pub version: String,
    pub revision: String,
}

/// Exact executable and complete source-component identity of one provider
/// process.
///
/// A provider may compose multiple pinned upstreams; every one is an explicit
/// durable coordinate rather than being hidden inside a patch hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderIdentity {
    pub protocol: String,
    pub provider_id: String,
    pub language: String,
    pub implementation_version: String,
    pub source_components: BTreeMap<String, ProviderSourceComponent>,
    pub patch_sha256: String,
    pub executable_sha256: String,
}

#[must_use]
pub fn rust_analyzer_source_components() -> BTreeMap<String, ProviderSourceComponent> {
    BTreeMap::from([(
        "rust_analyzer".into(),
        ProviderSourceComponent {
            version: H00_RUST_ANALYZER_UPSTREAM_VERSION.into(),
            revision: H00_RUST_ANALYZER_UPSTREAM_COMMIT.into(),
        },
    )])
}

#[must_use]
pub fn go_provider_source_components() -> BTreeMap<String, ProviderSourceComponent> {
    BTreeMap::from([
        (
            "gopls".into(),
            ProviderSourceComponent {
                version: H00_GOPLS_UPSTREAM_VERSION.into(),
                revision: H00_GOPLS_UPSTREAM_COMMIT.into(),
            },
        ),
        (
            "scip_go".into(),
            ProviderSourceComponent {
                version: H00_SCIP_GO_UPSTREAM_VERSION.into(),
                revision: H00_SCIP_GO_UPSTREAM_COMMIT.into(),
            },
        ),
    ])
}

#[must_use]
pub fn pyrefly_source_components() -> BTreeMap<String, ProviderSourceComponent> {
    BTreeMap::from([(
        "pyrefly".into(),
        ProviderSourceComponent {
            version: H00_PYREFLY_UPSTREAM_VERSION.into(),
            revision: H00_PYREFLY_UPSTREAM_COMMIT.into(),
        },
    )])
}

#[must_use]
pub fn typescript_source_components() -> BTreeMap<String, ProviderSourceComponent> {
    BTreeMap::from([
        (
            "scip_bindings".into(),
            ProviderSourceComponent {
                version: H00_SCIP_BINDINGS_UPSTREAM_VERSION.into(),
                revision: H00_SCIP_BINDINGS_UPSTREAM_COMMIT.into(),
            },
        ),
        (
            "typescript_native".into(),
            ProviderSourceComponent {
                version: H00_TYPESCRIPT_UPSTREAM_VERSION.into(),
                revision: H00_TYPESCRIPT_UPSTREAM_COMMIT.into(),
            },
        ),
    ])
}

/// Canonical durable identity of one exact provider implementation.
///
/// Unlike the user-facing provider version, this binds the wire protocol,
/// patched upstream source, and executable bytes. Persisted semantic evidence
/// may use it as one coordinate of a separately validated reuse contract.
pub fn provider_identity_sha256(
    identity: &ProviderIdentity,
) -> Result<String, SemanticProviderProtocolError> {
    validate_provider_identity(identity)?;
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, PROVIDER_IDENTITY_DIGEST_SCHEMA);
    let source_component_count = (identity.source_components.len() as u64).to_be_bytes();
    for field in [
        identity.protocol.as_bytes(),
        identity.provider_id.as_bytes(),
        identity.language.as_bytes(),
        identity.implementation_version.as_bytes(),
        source_component_count.as_slice(),
    ] {
        hash_field(&mut hasher, field);
    }
    for (name, component) in &identity.source_components {
        for field in [
            name.as_bytes(),
            component.version.as_bytes(),
            component.revision.as_bytes(),
        ] {
            hash_field(&mut hasher, field);
        }
    }
    for field in [
        identity.patch_sha256.as_bytes(),
        identity.executable_sha256.as_bytes(),
    ] {
        hash_field(&mut hasher, field);
    }
    Ok(hex_digest(&hasher.finalize()))
}

/// Exact runtime toolchain observed by a trusted provider executable before it
/// loads a workspace.
///
/// Authority binds this digest in addition to the provider build. The bounded
/// canonical component map lets every language name its real runtime inputs
/// without fabricating another provider's compiler or package-manager fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRuntimeConfiguration {
    pub configuration_sha256: String,
    /// Product-resolved system or managed toolchain identity supplied before
    /// provider launch and independently echoed by the provider runtime.
    pub resolved_toolchain_sha256: String,
    pub component_sha256s: BTreeMap<String, String>,
    pub environment_sha256: String,
    pub workspace_configuration_sha256: String,
}

/// Complete authority coordinates for one provider source epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAuthority {
    pub session_id: String,
    pub root_sha256: String,
    pub root_topology_sha256: String,
    pub configuration_sha256: String,
    /// Exact workspace/dependency graph observed while opening the provider.
    /// `None` is legal only on the client's initial `OpenSession` request;
    /// every admitted provider terminal carries `Some` and is bound to it.
    pub workspace_resolution_sha256: Option<String>,
    /// Exact bounded repository-local paths and environment values whose
    /// bytes influenced the provider program outside the indexed source
    /// population. `None` is legal only on the initial `OpenSession` request.
    pub semantic_inputs_sha256: Option<String>,
    pub population_sha256: String,
    pub source_epoch: u64,
}

/// Persistable state of one repository-local provider input.
///
/// Observation follows repository-contained symlinks while binding their
/// canonical target. Escaping links and special files remain fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSemanticPathKind {
    Missing,
    File,
    /// Exact recursive bytes below a declared directory.
    Directory,
    /// Exact immediate entry names and entry kinds observed during compiler
    /// resolution. Descendant bytes are owned by separately observed paths.
    DirectoryListing,
}

/// Stable authority root for a semantic input path.
///
/// Linked Git worktrees keep their per-worktree and shared control files
/// outside the checked-out source directory. Persisting those absolute paths
/// would bind one machine layout and leak it into the generation. These typed
/// roots instead re-resolve the current checkout's own `.git`/`commondir`
/// control plane on every freshness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSemanticPathRoot {
    Repository,
    GitWorktree,
    GitCommon,
}

impl ProviderSemanticPathRoot {
    const fn digest_label(self) -> &'static [u8] {
        match self {
            Self::Repository => b"repository",
            Self::GitWorktree => b"git_worktree",
            Self::GitCommon => b"git_common",
        }
    }
}

/// Canonical, machine-independent coordinate supplied by a provider before
/// it observes an exact semantic input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProviderSemanticPathCoordinate {
    pub root: ProviderSemanticPathRoot,
    pub path: String,
}

impl ProviderSemanticPathCoordinate {
    #[must_use]
    pub fn repository(path: impl Into<String>) -> Self {
        Self {
            root: ProviderSemanticPathRoot::Repository,
            path: path.into(),
        }
    }
}

/// Transient local resolution of one persisted semantic coordinate. Absolute
/// paths never enter the serialized manifest or its user-facing diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSemanticPathLocation {
    pub authority_root: PathBuf,
    pub absolute_path: PathBuf,
}

/// Exact authority-relative non-source input observed by a semantic provider.
/// The identity digest covers the complete bounded file/directory population,
/// not timestamps or a machine-local absolute path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSemanticPathInput {
    pub root: ProviderSemanticPathRoot,
    pub path: String,
    pub kind: ProviderSemanticPathKind,
    pub identity_sha256: String,
    pub entry_count: u64,
    pub byte_length: u64,
}

/// A Cargo-declared environment input without persisting its possibly secret
/// value. `None` means the variable was absent; an empty value has a SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSemanticEnvironmentInput {
    pub name: String,
    pub value_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSemanticInputCoverage {
    Complete,
    Unverifiable,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSemanticInputIssue {
    pub code: String,
    pub path: String,
    pub detail: String,
}

/// Bounded, canonical semantic inputs that can be re-observed by a fresh CLI,
/// MCP, or WATCH process without launching the provider again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSemanticInputs {
    pub schema_version: String,
    pub coverage: ProviderSemanticInputCoverage,
    pub paths: Vec<ProviderSemanticPathInput>,
    pub environment: Vec<ProviderSemanticEnvironmentInput>,
    pub issues: Vec<ProviderSemanticInputIssue>,
}

impl ProviderSemanticInputs {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            schema_version: PROVIDER_SEMANTIC_INPUTS_SCHEMA.into(),
            coverage: ProviderSemanticInputCoverage::Complete,
            paths: Vec::new(),
            environment: Vec::new(),
            issues: Vec::new(),
        }
    }
}

/// One exact source document admitted into a provider session.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSourceIdentity {
    pub document_path: String,
    pub language: String,
    /// Opaque identity owned by h00ligan's structural source authority.
    pub content_identity: String,
    /// Transport-level digest independently recomputed from provider bytes.
    pub content_sha256: String,
}

/// Machine-observed state of an authority-relevant provider subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderComponentHealth {
    Healthy,
    NotApplicable,
    Disabled,
    Failed,
    Unknown,
}

impl ProviderComponentHealth {
    const fn admits_complete(self) -> bool {
        matches!(self, Self::Healthy | Self::NotApplicable)
    }
}

/// Provider health that must be Complete before affected output is trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderHealthEvidence {
    /// Provider-defined, language-neutral subsystem population. Component
    /// labels obey the same bounded canonical grammar as runtime components.
    pub components: BTreeMap<String, ProviderComponentHealth>,
    pub diagnostics_complete: bool,
    pub degradation_reasons: Vec<String>,
}

impl ProviderHealthEvidence {
    #[must_use]
    pub fn admits_complete(&self) -> bool {
        !self.components.is_empty()
            && self.components.len() <= MAX_PROVIDER_RUNTIME_COMPONENTS
            && self.components.iter().all(|(name, health)| {
                validate_runtime_component_name(name).is_ok() && health.admits_complete()
            })
            && self.diagnostics_complete
            && self.degradation_reasons.is_empty()
    }
}

/// Terminal operation associated with one one-use request claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOperation {
    Hello,
    OpenSession,
    ReconfigureSession,
    ApplyEpoch,
    RefreshAffected,
    CertifyFull,
    CloseSession,
}

/// Exact source mutation carried by an `ApplyEpoch` or `RefreshAffected` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderSourceChange {
    Replace {
        document_path: String,
        language: String,
        previous_content_identity: String,
        previous_content_sha256: String,
        content_identity: String,
        content_sha256: String,
        attachment_index: u32,
    },
}

/// One opaque, typed semantic analysis requested alongside canonical provider
/// documents.
///
/// The transport owns exact identity, bounds, and attachment admission; the
/// consuming engine owns the analysis schema's semantics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAnalysisRequest {
    pub analysis_id: String,
    pub schema_version: String,
    pub configuration_id: String,
}

/// Request metadata. Source bytes are referenced through frame attachments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderRequestBody {
    Hello,
    OpenSession {
        repository_root: String,
        execution_root: String,
        execution_prefix: String,
        authority: ProviderAuthority,
        sources: Vec<ProviderSourceIdentity>,
        /// Exact client-owned project-input/environment expectation. Rust's
        /// provider currently observes a richer Cargo-owned population and
        /// therefore receives `None`; Go requires `Some`.
        expected_semantic_inputs: Option<ProviderSemanticInputs>,
    },
    /// Re-observe project inputs and workspace resolution in an already
    /// admitted provider session. The client owns every next coordinate except
    /// the two provider-observed digests, exactly as for `OpenSession`.
    ReconfigureSession {
        previous_authority: ProviderAuthority,
        next_authority: ProviderAuthority,
        expected_semantic_inputs: ProviderSemanticInputs,
    },
    ApplyEpoch {
        previous_authority: ProviderAuthority,
        next_authority: ProviderAuthority,
        changes: Vec<ProviderSourceChange>,
    },
    /// Apply one exact source epoch and export its affected canonical
    /// documents under one provider-owned, terminally witnessed transaction.
    RefreshAffected {
        previous_authority: ProviderAuthority,
        next_authority: ProviderAuthority,
        changes: Vec<ProviderSourceChange>,
        /// Exact canonical snapshot that the client will overlay.
        parent_snapshot_sha256: String,
        documents: Vec<String>,
        analyses: Vec<ProviderAnalysisRequest>,
    },
    CertifyFull {
        authority: ProviderAuthority,
        analyses: Vec<ProviderAnalysisRequest>,
    },
    CloseSession,
}

/// Every request names its owning session and exact expected provider build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRequest {
    pub request_id: u64,
    pub session_id: String,
    pub expected_provider: ProviderIdentity,
    pub body: ProviderRequestBody,
}

/// Explicit result for one requested canonical provider document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderDocumentOutcome {
    Present {
        document_path: String,
        language: String,
        content_identity: String,
        canonical_document_sha256: String,
        attachment_index: u32,
    },
    Omitted {
        document_path: String,
        language: String,
        content_identity: String,
    },
}

/// Exact attachment claim for one requested semantic analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAnalysisOutcome {
    pub analysis_id: String,
    pub schema_version: String,
    pub configuration_id: String,
    pub language: String,
    pub canonical_analysis_sha256: String,
    pub attachment_index: u32,
}

impl ProviderDocumentOutcome {
    fn document_path(&self) -> &str {
        match self {
            Self::Present { document_path, .. } | Self::Omitted { document_path, .. } => {
                document_path
            }
        }
    }
}

/// Response metadata. Errors are terminal responses and retain request IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderResponseBody {
    Hello {
        limits: ProviderFrameLimits,
        runtime_configuration: ProviderRuntimeConfiguration,
    },
    SessionOpened {
        authority: ProviderAuthority,
        health: ProviderHealthEvidence,
        semantic_inputs: ProviderSemanticInputs,
    },
    SessionReconfigured {
        authority: ProviderAuthority,
        health: ProviderHealthEvidence,
        semantic_inputs: ProviderSemanticInputs,
    },
    EpochApplied {
        authority: ProviderAuthority,
        health: ProviderHealthEvidence,
    },
    /// Affected-document evidence returned by the same request that applied
    /// the source epoch. The runtime observation is taken after provider work
    /// and is part of terminal admission, so the client need not issue a
    /// second identity-only probe.
    AffectedRefreshed {
        authority: ProviderAuthority,
        parent_snapshot_sha256: String,
        health: ProviderHealthEvidence,
        runtime_configuration: ProviderRuntimeConfiguration,
        outcomes: Vec<ProviderDocumentOutcome>,
        analyses: Vec<ProviderAnalysisOutcome>,
    },
    FullCertification {
        authority: ProviderAuthority,
        health: ProviderHealthEvidence,
        outcomes: Vec<ProviderDocumentOutcome>,
        analyses: Vec<ProviderAnalysisOutcome>,
    },
    SessionClosed,
    Error {
        code: String,
        message: String,
        retryable: bool,
    },
}

/// Every response—including errors—echoes exact request/session/provider IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderResponse {
    pub request_id: u64,
    pub session_id: String,
    pub provider: ProviderIdentity,
    pub body: ProviderResponseBody,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedProviderDocument {
    pub language: String,
    pub content_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedAffectedRefresh {
    pub request_id: u64,
    pub provider: ProviderIdentity,
    pub authority: ProviderAuthority,
    pub parent_snapshot_sha256: String,
    pub documents: BTreeMap<String, ExpectedProviderDocument>,
    pub analyses: BTreeMap<String, ExpectedProviderAnalysis>,
    /// Exact post-work runtime witness required from the atomic terminal.
    pub terminal_runtime_configuration: ProviderRuntimeConfiguration,
}

/// Exact authority and source population required from one full provider
/// certification.
///
/// Full certification and affected refresh use the same document admission
/// rules; only affected refresh additionally names its canonical parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedFullCertification {
    pub request_id: u64,
    pub provider: ProviderIdentity,
    pub authority: ProviderAuthority,
    pub documents: BTreeMap<String, ExpectedProviderDocument>,
    pub analyses: BTreeMap<String, ExpectedProviderAnalysis>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedProviderAnalysis {
    pub schema_version: String,
    pub configuration_id: String,
    pub language: String,
}

/// Canonical bytes admitted after every identity, health, and coverage check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmittedProviderDocument {
    Present {
        document_path: String,
        canonical_document: Vec<u8>,
    },
    Omitted {
        document_path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedProviderAnalysis {
    pub analysis_id: String,
    pub schema_version: String,
    pub configuration_id: String,
    pub language: String,
    pub canonical_analysis: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedProviderExport {
    pub documents: Vec<AdmittedProviderDocument>,
    pub analyses: Vec<AdmittedProviderAnalysis>,
}

/// A bounded per-session request ledger. A terminal claim succeeds once.
#[derive(Debug)]
pub struct ProviderRequestClaims {
    session_id: String,
    max_outstanding: usize,
    next_request_id: u64,
    outstanding: BTreeMap<u64, ProviderOperation>,
}

impl ProviderRequestClaims {
    pub fn new(
        session_id: impl Into<String>,
        max_outstanding: usize,
    ) -> Result<Self, SemanticProviderProtocolError> {
        let session_id = session_id.into();
        validate_text("session ID", &session_id, 128)?;
        if max_outstanding == 0 {
            return Err(SemanticProviderProtocolError::InvalidLimits(
                "max outstanding requests is zero".into(),
            ));
        }
        Ok(Self {
            session_id,
            max_outstanding,
            next_request_id: 1,
            outstanding: BTreeMap::new(),
        })
    }

    pub fn issue(
        &mut self,
        operation: ProviderOperation,
    ) -> Result<u64, SemanticProviderProtocolError> {
        if self.outstanding.len() >= self.max_outstanding {
            return Err(SemanticProviderProtocolError::TooManyOutstandingRequests {
                limit: self.max_outstanding,
            });
        }
        let request_id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(SemanticProviderProtocolError::RequestIdExhausted)?;
        self.outstanding.insert(request_id, operation);
        Ok(request_id)
    }

    pub fn claim(
        &mut self,
        session_id: &str,
        request_id: u64,
        operation: ProviderOperation,
    ) -> Result<(), SemanticProviderProtocolError> {
        if session_id != self.session_id {
            return Err(SemanticProviderProtocolError::ForeignSession);
        }
        let Some(pending) = self.outstanding.get(&request_id) else {
            return Err(SemanticProviderProtocolError::UnknownOrReplayedRequest { request_id });
        };
        if *pending != operation {
            return Err(SemanticProviderProtocolError::UnexpectedOperation);
        }
        self.outstanding.remove(&request_id);
        Ok(())
    }

    #[must_use]
    pub fn outstanding_ids(&self) -> BTreeSet<u64> {
        self.outstanding.keys().copied().collect()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SemanticProviderProtocolError {
    #[error("invalid provider protocol limits: {0}")]
    InvalidLimits(String),
    #[error("provider frame exceeds {limit} bytes")]
    FrameTooLarge { limit: usize },
    #[error("provider frame is shorter than its fixed header")]
    FrameTooShort,
    #[error("provider frame magic or protocol version is invalid")]
    InvalidFrameMagic,
    #[error("provider frame length does not match its declared length")]
    FrameLengthMismatch,
    #[error("provider metadata exceeds {limit} bytes")]
    MetadataTooLarge { limit: usize },
    #[error("provider frame exceeds the attachment count limit {limit}")]
    TooManyAttachments { limit: usize },
    #[error("provider attachment exceeds {limit} bytes")]
    AttachmentTooLarge { limit: usize },
    #[error("provider attachments exceed {limit} total bytes")]
    AttachmentsTooLarge { limit: usize },
    #[error("provider frame arithmetic overflow")]
    ArithmeticOverflow,
    #[error("provider metadata serialization failed: {0}")]
    MetadataSerialization(String),
    #[error("provider metadata decoding failed: {0}")]
    MetadataDecoding(String),
    #[error("provider transport I/O failed: {0}")]
    Io(String),
    #[error("provider identity is invalid: {0}")]
    InvalidProviderIdentity(String),
    #[error("provider runtime configuration is invalid: {0}")]
    InvalidRuntimeConfiguration(String),
    #[error("Rust semantic profile is invalid: {0}")]
    InvalidRustSemanticProfile(String),
    #[error("provider authority is invalid: {0}")]
    InvalidAuthority(String),
    #[error("response belongs to a different request")]
    RequestMismatch,
    #[error("response belongs to a foreign session")]
    ForeignSession,
    #[error("response provider identity differs from the requested executable")]
    ProviderIdentityMismatch,
    #[error("response authority differs from the requested source epoch")]
    AuthorityMismatch,
    #[error("response belongs to a different canonical parent snapshot")]
    ParentSnapshotMismatch,
    #[error("provider health cannot support Complete authority")]
    ProviderUnhealthy,
    #[error("provider returned an unexpected terminal operation")]
    UnexpectedOperation,
    #[error("provider request ID must be nonzero")]
    InvalidRequestId,
    #[error("provider request contains an invalid canonical root")]
    InvalidCanonicalRoot,
    #[error("provider source population is empty, oversized, duplicate, or malformed")]
    InvalidSourcePopulation,
    #[error("provider source population digest does not match its authority")]
    SourcePopulationDigestMismatch,
    #[error("provider semantic inputs are invalid: {0}")]
    InvalidSemanticInputs(String),
    #[error("provider source epoch transition is not exact and monotonic")]
    InvalidEpochTransition,
    #[error("provider request attachment population is invalid")]
    InvalidRequestAttachments,
    #[error("provider replacement bytes do not match their declared digest")]
    SourceDigestMismatch,
    #[error("provider returned invalid document path `{0}`")]
    InvalidDocumentPath(String),
    #[error("provider returned duplicate document outcome `{0}`")]
    DuplicateDocumentOutcome(String),
    #[error("provider returned duplicate semantic analysis outcome `{0}`")]
    DuplicateAnalysisOutcome(String),
    #[error("provider semantic analysis outcomes do not exactly cover the requested population")]
    AnalysisCoverageMismatch,
    #[error("provider semantic analysis metadata differs from the requested analysis `{0}`")]
    AnalysisIdentityMismatch(String),
    #[error("provider document outcomes do not exactly cover the requested population")]
    CoverageMismatch,
    #[error("provider document metadata differs from exact source authority for `{0}`")]
    DocumentIdentityMismatch(String),
    #[error("provider attachment index {index} is outside the frame population")]
    AttachmentIndexOutOfRange { index: usize },
    #[error("provider attachment index {index} was claimed more than once")]
    AttachmentReused { index: usize },
    #[error("provider frame contains an unclaimed attachment")]
    UnclaimedAttachment,
    #[error("canonical provider document is empty")]
    EmptyDocument,
    #[error("canonical provider document digest is invalid")]
    DocumentDigestMismatch,
    #[error("canonical provider semantic analysis is empty")]
    EmptyAnalysis,
    #[error("canonical provider semantic analysis digest is invalid")]
    AnalysisDigestMismatch,
    #[error("too many outstanding provider requests (limit {limit})")]
    TooManyOutstandingRequests { limit: usize },
    #[error("provider request ID space is exhausted")]
    RequestIdExhausted,
    #[error("provider response request {request_id} is unknown or already claimed")]
    UnknownOrReplayedRequest { request_id: u64 },
}

/// Encode one bounded frame. The four-byte lengths are network byte order.
pub fn encode_provider_frame<T: Serialize>(
    frame: &ProviderFrame<T>,
    limits: &ProviderFrameLimits,
) -> Result<Vec<u8>, SemanticProviderProtocolError> {
    validate_limits(limits)?;
    let metadata = serde_json::to_vec(&frame.metadata)
        .map_err(|error| SemanticProviderProtocolError::MetadataSerialization(error.to_string()))?;
    if metadata.len() > limits.max_metadata_bytes {
        return Err(SemanticProviderProtocolError::MetadataTooLarge {
            limit: limits.max_metadata_bytes,
        });
    }
    if frame.attachments.len() > limits.max_attachments {
        return Err(SemanticProviderProtocolError::TooManyAttachments {
            limit: limits.max_attachments,
        });
    }
    let mut attachment_bytes = 0usize;
    let mut payload_bytes = metadata.len();
    for attachment in &frame.attachments {
        if attachment.len() > limits.max_attachment_bytes {
            return Err(SemanticProviderProtocolError::AttachmentTooLarge {
                limit: limits.max_attachment_bytes,
            });
        }
        attachment_bytes = attachment_bytes
            .checked_add(attachment.len())
            .ok_or(SemanticProviderProtocolError::ArithmeticOverflow)?;
        payload_bytes = payload_bytes
            .checked_add(4)
            .and_then(|total| total.checked_add(attachment.len()))
            .ok_or(SemanticProviderProtocolError::ArithmeticOverflow)?;
    }
    if attachment_bytes > limits.max_total_attachment_bytes {
        return Err(SemanticProviderProtocolError::AttachmentsTooLarge {
            limit: limits.max_total_attachment_bytes,
        });
    }
    let total_bytes = PROVIDER_FRAME_HEADER_BYTES
        .checked_add(payload_bytes)
        .ok_or(SemanticProviderProtocolError::ArithmeticOverflow)?;
    if total_bytes > limits.max_frame_bytes || payload_bytes > u32::MAX as usize {
        return Err(SemanticProviderProtocolError::FrameTooLarge {
            limit: limits.max_frame_bytes,
        });
    }
    let metadata_len = u32::try_from(metadata.len())
        .map_err(|_| SemanticProviderProtocolError::ArithmeticOverflow)?;
    let attachment_count = u32::try_from(frame.attachments.len())
        .map_err(|_| SemanticProviderProtocolError::ArithmeticOverflow)?;

    let mut output = Vec::with_capacity(total_bytes);
    output.extend_from_slice(SEMANTIC_PROVIDER_FRAME_MAGIC);
    output.extend_from_slice(&(payload_bytes as u32).to_be_bytes());
    output.extend_from_slice(&metadata_len.to_be_bytes());
    output.extend_from_slice(&attachment_count.to_be_bytes());
    output.extend_from_slice(&metadata);
    for attachment in &frame.attachments {
        output.extend_from_slice(&(attachment.len() as u32).to_be_bytes());
        output.extend_from_slice(attachment);
    }
    Ok(output)
}

/// Decode one complete frame only after all declared lengths pass their caps.
pub fn decode_provider_frame<T: DeserializeOwned>(
    bytes: &[u8],
    limits: &ProviderFrameLimits,
) -> Result<ProviderFrame<T>, SemanticProviderProtocolError> {
    validate_limits(limits)?;
    if bytes.len() > limits.max_frame_bytes {
        return Err(SemanticProviderProtocolError::FrameTooLarge {
            limit: limits.max_frame_bytes,
        });
    }
    if bytes.len() < PROVIDER_FRAME_HEADER_BYTES {
        return Err(SemanticProviderProtocolError::FrameTooShort);
    }
    if &bytes[..SEMANTIC_PROVIDER_FRAME_MAGIC.len()] != SEMANTIC_PROVIDER_FRAME_MAGIC {
        return Err(SemanticProviderProtocolError::InvalidFrameMagic);
    }
    let metadata_len = read_u32(bytes, 12)? as usize;
    let attachment_count = read_u32(bytes, 16)? as usize;
    let expected_len =
        provider_frame_total_len_from_header(&bytes[..PROVIDER_FRAME_HEADER_BYTES], limits)?;
    if expected_len != bytes.len() {
        return Err(SemanticProviderProtocolError::FrameLengthMismatch);
    }
    if metadata_len > limits.max_metadata_bytes {
        return Err(SemanticProviderProtocolError::MetadataTooLarge {
            limit: limits.max_metadata_bytes,
        });
    }
    if attachment_count > limits.max_attachments {
        return Err(SemanticProviderProtocolError::TooManyAttachments {
            limit: limits.max_attachments,
        });
    }
    let metadata_end = PROVIDER_FRAME_HEADER_BYTES
        .checked_add(metadata_len)
        .ok_or(SemanticProviderProtocolError::ArithmeticOverflow)?;
    let metadata_bytes = bytes
        .get(PROVIDER_FRAME_HEADER_BYTES..metadata_end)
        .ok_or(SemanticProviderProtocolError::FrameLengthMismatch)?;
    let metadata = serde_json::from_slice(metadata_bytes)
        .map_err(|error| SemanticProviderProtocolError::MetadataDecoding(error.to_string()))?;

    let mut cursor = metadata_end;
    let mut total_attachment_bytes = 0usize;
    let mut attachments = Vec::with_capacity(attachment_count);
    for _ in 0..attachment_count {
        let attachment_len = read_u32(bytes, cursor)? as usize;
        cursor = cursor
            .checked_add(4)
            .ok_or(SemanticProviderProtocolError::ArithmeticOverflow)?;
        if attachment_len > limits.max_attachment_bytes {
            return Err(SemanticProviderProtocolError::AttachmentTooLarge {
                limit: limits.max_attachment_bytes,
            });
        }
        total_attachment_bytes = total_attachment_bytes
            .checked_add(attachment_len)
            .ok_or(SemanticProviderProtocolError::ArithmeticOverflow)?;
        if total_attachment_bytes > limits.max_total_attachment_bytes {
            return Err(SemanticProviderProtocolError::AttachmentsTooLarge {
                limit: limits.max_total_attachment_bytes,
            });
        }
        let end = cursor
            .checked_add(attachment_len)
            .ok_or(SemanticProviderProtocolError::ArithmeticOverflow)?;
        let attachment = bytes
            .get(cursor..end)
            .ok_or(SemanticProviderProtocolError::FrameLengthMismatch)?;
        attachments.push(attachment.to_vec());
        cursor = end;
    }
    if cursor != bytes.len() {
        return Err(SemanticProviderProtocolError::FrameLengthMismatch);
    }
    Ok(ProviderFrame {
        metadata,
        attachments,
    })
}

/// Write one complete frame to a stream and flush its terminal bytes.
pub fn write_provider_frame<W: Write, T: Serialize>(
    writer: &mut W,
    frame: &ProviderFrame<T>,
    limits: &ProviderFrameLimits,
) -> Result<(), SemanticProviderProtocolError> {
    let encoded = encode_provider_frame(frame, limits)?;
    writer
        .write_all(&encoded)
        .and_then(|()| writer.flush())
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))
}

/// Read one frame from a stream without allocating from an untrusted length.
pub fn read_provider_frame<R: Read, T: DeserializeOwned>(
    reader: &mut R,
    limits: &ProviderFrameLimits,
) -> Result<ProviderFrame<T>, SemanticProviderProtocolError> {
    validate_limits(limits)?;
    let mut header = [0_u8; PROVIDER_FRAME_HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
    let total_len = provider_frame_total_len_from_header(&header, limits)?;
    let mut encoded = Vec::with_capacity(total_len);
    encoded.extend_from_slice(&header);
    encoded.resize(total_len, 0);
    reader
        .read_exact(&mut encoded[PROVIDER_FRAME_HEADER_BYTES..])
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
    decode_provider_frame(&encoded, limits)
}

/// Validate an untrusted fixed frame header and return its bounded total
/// length before any caller allocates the payload. Async transports use this
/// same parser as the blocking stream adapter.
pub fn provider_frame_total_len_from_header(
    header: &[u8],
    limits: &ProviderFrameLimits,
) -> Result<usize, SemanticProviderProtocolError> {
    validate_limits(limits)?;
    if header.len() != PROVIDER_FRAME_HEADER_BYTES {
        return Err(SemanticProviderProtocolError::FrameTooShort);
    }
    if &header[..SEMANTIC_PROVIDER_FRAME_MAGIC.len()] != SEMANTIC_PROVIDER_FRAME_MAGIC {
        return Err(SemanticProviderProtocolError::InvalidFrameMagic);
    }
    let payload_len = read_u32(header, 8)? as usize;
    let metadata_len = read_u32(header, 12)? as usize;
    let attachment_count = read_u32(header, 16)? as usize;
    let total_len = PROVIDER_FRAME_HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(SemanticProviderProtocolError::ArithmeticOverflow)?;
    if total_len > limits.max_frame_bytes {
        return Err(SemanticProviderProtocolError::FrameTooLarge {
            limit: limits.max_frame_bytes,
        });
    }
    if metadata_len > limits.max_metadata_bytes {
        return Err(SemanticProviderProtocolError::MetadataTooLarge {
            limit: limits.max_metadata_bytes,
        });
    }
    if attachment_count > limits.max_attachments {
        return Err(SemanticProviderProtocolError::TooManyAttachments {
            limit: limits.max_attachments,
        });
    }
    Ok(total_len)
}

/// Validate request-local bounds before provider state can mutate.
///
/// Session-state comparisons remain the server's responsibility because they
/// require the previously admitted population.
pub fn validate_provider_request(
    frame: &ProviderFrame<ProviderRequest>,
    limits: &ProviderFrameLimits,
) -> Result<(), SemanticProviderProtocolError> {
    validate_limits(limits)?;
    let request = &frame.metadata;
    if request.request_id == 0 {
        return Err(SemanticProviderProtocolError::InvalidRequestId);
    }
    validate_text("session ID", &request.session_id, 128)?;
    validate_provider_identity(&request.expected_provider)?;

    let mut claimed_attachments = BTreeSet::new();
    match &request.body {
        ProviderRequestBody::Hello | ProviderRequestBody::CloseSession => {}
        ProviderRequestBody::OpenSession {
            repository_root,
            execution_root,
            execution_prefix,
            authority,
            sources,
            expected_semantic_inputs,
        } => {
            if [repository_root, execution_root].iter().any(|root| {
                root.is_empty() || root.len() > 4096 || root.chars().any(char::is_control)
            }) || (!execution_prefix.is_empty()
                && validate_document_path(execution_prefix).is_err())
            {
                return Err(SemanticProviderProtocolError::InvalidCanonicalRoot);
            }
            validate_authority(authority)?;
            if authority.workspace_resolution_sha256.is_some()
                || authority.semantic_inputs_sha256.is_some()
            {
                return Err(SemanticProviderProtocolError::InvalidAuthority(
                    "open-session authority must not predeclare provider-observed workspace resolution or semantic inputs"
                        .into(),
                ));
            }
            if authority.session_id != request.session_id {
                return Err(SemanticProviderProtocolError::ForeignSession);
            }
            let digest = source_population_sha256(sources, limits)?;
            if digest != authority.population_sha256 {
                return Err(SemanticProviderProtocolError::SourcePopulationDigestMismatch);
            }
            if let Some(expected) = expected_semantic_inputs {
                validate_provider_semantic_inputs(expected, limits)?;
                if expected.coverage != ProviderSemanticInputCoverage::Complete {
                    return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                        "expected semantic-input population must be complete".into(),
                    ));
                }
            }
        }
        ProviderRequestBody::ReconfigureSession {
            previous_authority,
            next_authority,
            expected_semantic_inputs,
        } => {
            validate_authority(previous_authority)?;
            validate_authority(next_authority)?;
            validate_provider_semantic_inputs(expected_semantic_inputs, limits)?;
            resolved_authority_configuration_sha256(previous_authority)?;
            if previous_authority.session_id != request.session_id
                || next_authority.session_id != request.session_id
            {
                return Err(SemanticProviderProtocolError::ForeignSession);
            }
            if previous_authority.workspace_resolution_sha256.is_none()
                || previous_authority.semantic_inputs_sha256.is_none()
                || next_authority.workspace_resolution_sha256.is_some()
                || next_authority.semantic_inputs_sha256.is_some()
                || previous_authority.source_epoch.checked_add(1)
                    != Some(next_authority.source_epoch)
                || previous_authority.root_sha256 != next_authority.root_sha256
                || previous_authority.root_topology_sha256 == next_authority.root_topology_sha256
                || previous_authority.configuration_sha256 != next_authority.configuration_sha256
                || previous_authority.population_sha256 != next_authority.population_sha256
                || expected_semantic_inputs.coverage != ProviderSemanticInputCoverage::Complete
            {
                return Err(SemanticProviderProtocolError::InvalidEpochTransition);
            }
        }
        ProviderRequestBody::ApplyEpoch {
            previous_authority,
            next_authority,
            changes,
        } => {
            validate_epoch_transition(
                &request.session_id,
                previous_authority,
                next_authority,
                changes,
                &frame.attachments,
                &mut claimed_attachments,
                limits,
            )?;
        }
        ProviderRequestBody::RefreshAffected {
            previous_authority,
            next_authority,
            changes,
            parent_snapshot_sha256,
            documents,
            analyses,
        } => {
            validate_epoch_transition(
                &request.session_id,
                previous_authority,
                next_authority,
                changes,
                &frame.attachments,
                &mut claimed_attachments,
                limits,
            )?;
            validate_affected_selection(
                &request.session_id,
                next_authority,
                parent_snapshot_sha256,
                documents,
                limits,
            )?;
            validate_analysis_requests(analyses)?;
        }
        ProviderRequestBody::CertifyFull {
            authority,
            analyses,
        } => {
            validate_authority(authority)?;
            resolved_authority_configuration_sha256(authority)?;
            if authority.session_id != request.session_id {
                return Err(SemanticProviderProtocolError::ForeignSession);
            }
            validate_analysis_requests(analyses)?;
        }
    }
    if claimed_attachments.len() != frame.attachments.len() {
        return Err(SemanticProviderProtocolError::InvalidRequestAttachments);
    }
    Ok(())
}

fn validate_analysis_requests(
    analyses: &[ProviderAnalysisRequest],
) -> Result<(), SemanticProviderProtocolError> {
    let mut ids = BTreeSet::new();
    for analysis in analyses {
        validate_text("analysis ID", &analysis.analysis_id, 128)?;
        validate_text("analysis schema", &analysis.schema_version, 256)?;
        validate_text("analysis configuration", &analysis.configuration_id, 512)?;
        if !ids.insert(analysis.analysis_id.as_str()) {
            return Err(SemanticProviderProtocolError::DuplicateAnalysisOutcome(
                analysis.analysis_id.clone(),
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_epoch_transition(
    request_session_id: &str,
    previous_authority: &ProviderAuthority,
    next_authority: &ProviderAuthority,
    changes: &[ProviderSourceChange],
    attachments: &[Vec<u8>],
    claimed_attachments: &mut BTreeSet<usize>,
    limits: &ProviderFrameLimits,
) -> Result<(), SemanticProviderProtocolError> {
    validate_authority(previous_authority)?;
    validate_authority(next_authority)?;
    resolved_authority_configuration_sha256(previous_authority)?;
    resolved_authority_configuration_sha256(next_authority)?;
    if previous_authority.session_id != request_session_id
        || next_authority.session_id != request_session_id
    {
        return Err(SemanticProviderProtocolError::ForeignSession);
    }
    if previous_authority.source_epoch.checked_add(1) != Some(next_authority.source_epoch)
        || previous_authority.root_sha256 != next_authority.root_sha256
        || previous_authority.root_topology_sha256 != next_authority.root_topology_sha256
        || previous_authority.configuration_sha256 != next_authority.configuration_sha256
        || previous_authority.workspace_resolution_sha256
            != next_authority.workspace_resolution_sha256
        || previous_authority.semantic_inputs_sha256 != next_authority.semantic_inputs_sha256
        || previous_authority.population_sha256 == next_authority.population_sha256
        || changes.is_empty()
        || changes.len() > limits.max_document_paths
    {
        return Err(SemanticProviderProtocolError::InvalidEpochTransition);
    }
    let mut paths = BTreeSet::new();
    for change in changes {
        let ProviderSourceChange::Replace {
            document_path,
            language,
            previous_content_identity,
            previous_content_sha256,
            content_identity,
            content_sha256,
            attachment_index,
        } = change;
        validate_document_path(document_path)?;
        validate_text("source language", language, 64)?;
        validate_text("previous content identity", previous_content_identity, 256)?;
        validate_text("content identity", content_identity, 256)?;
        if !is_sha256(previous_content_sha256)
            || !is_sha256(content_sha256)
            || previous_content_identity == content_identity
            || previous_content_sha256 == content_sha256
            || !paths.insert(document_path)
        {
            return Err(SemanticProviderProtocolError::InvalidEpochTransition);
        }
        let index = *attachment_index as usize;
        let bytes = attachments
            .get(index)
            .ok_or(SemanticProviderProtocolError::InvalidRequestAttachments)?;
        if !claimed_attachments.insert(index) {
            return Err(SemanticProviderProtocolError::InvalidRequestAttachments);
        }
        if sha256_hex(bytes) != *content_sha256 {
            return Err(SemanticProviderProtocolError::SourceDigestMismatch);
        }
    }
    Ok(())
}

fn validate_affected_selection(
    request_session_id: &str,
    authority: &ProviderAuthority,
    parent_snapshot_sha256: &str,
    documents: &[String],
    limits: &ProviderFrameLimits,
) -> Result<(), SemanticProviderProtocolError> {
    validate_authority(authority)?;
    resolved_authority_configuration_sha256(authority)?;
    if authority.session_id != request_session_id {
        return Err(SemanticProviderProtocolError::ForeignSession);
    }
    if !is_sha256(parent_snapshot_sha256) {
        return Err(SemanticProviderProtocolError::ParentSnapshotMismatch);
    }
    let mut paths = BTreeSet::new();
    if documents.is_empty()
        || documents.len() > limits.max_document_paths
        || documents
            .iter()
            .any(|path| validate_document_path(path).is_err() || !paths.insert(path.as_str()))
    {
        return Err(SemanticProviderProtocolError::CoverageMismatch);
    }
    Ok(())
}

/// Deterministic digest of an exact source population, shared by the client
/// and provider so neither side can silently add, omit, or duplicate a path.
pub fn source_population_sha256(
    sources: &[ProviderSourceIdentity],
    limits: &ProviderFrameLimits,
) -> Result<String, SemanticProviderProtocolError> {
    validate_limits(limits)?;
    if sources.is_empty() || sources.len() > limits.max_document_paths {
        return Err(SemanticProviderProtocolError::InvalidSourcePopulation);
    }
    let mut ordered = BTreeMap::new();
    for source in sources {
        validate_document_path(&source.document_path)?;
        validate_text("source language", &source.language, 64)?;
        validate_text("content identity", &source.content_identity, 256)?;
        if !is_sha256(&source.content_sha256)
            || ordered
                .insert(source.document_path.as_str(), source)
                .is_some()
        {
            return Err(SemanticProviderProtocolError::InvalidSourcePopulation);
        }
    }
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, SOURCE_POPULATION_SCHEMA);
    for source in ordered.into_values() {
        hash_field(&mut hasher, source.document_path.as_bytes());
        hash_field(&mut hasher, source.language.as_bytes());
        hash_field(&mut hasher, source.content_identity.as_bytes());
        hash_field(&mut hasher, source.content_sha256.as_bytes());
    }
    Ok(hex_digest(&hasher.finalize()))
}

const MAX_GIT_CONTROL_POINTER_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitControlRoots {
    worktree: PathBuf,
    common: PathBuf,
    linked: bool,
}

fn read_git_control_pointer(
    path: &Path,
    label: &str,
) -> Result<String, SemanticProviderProtocolError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| SemanticProviderProtocolError::Io(format!("{label}: {error}")))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_GIT_CONTROL_POINTER_BYTES
    {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!("{label} is not a bounded regular file"),
        ));
    }
    let value = std::fs::read_to_string(path)
        .map_err(|error| SemanticProviderProtocolError::Io(format!("{label}: {error}")))?;
    let value = value.trim();
    if value.is_empty() || value.contains('\0') || value.lines().count() != 1 {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!("{label} is not one bounded path"),
        ));
    }
    Ok(value.to_owned())
}

fn canonical_git_directory(
    path: &Path,
    label: &str,
) -> Result<PathBuf, SemanticProviderProtocolError> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| SemanticProviderProtocolError::Io(format!("{label}: {error}")))?;
    let metadata = std::fs::symlink_metadata(&canonical)
        .map_err(|error| SemanticProviderProtocolError::Io(format!("{label}: {error}")))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!("{label} is not a plain directory"),
        ));
    }
    Ok(canonical)
}

fn canonical_git_file(path: &Path, label: &str) -> Result<PathBuf, SemanticProviderProtocolError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| SemanticProviderProtocolError::Io(format!("{label}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!("{label} is not a plain file"),
        ));
    }
    std::fs::canonicalize(path)
        .map_err(|error| SemanticProviderProtocolError::Io(format!("{label}: {error}")))
}

fn resolve_git_control_roots(
    repository_root: &Path,
) -> Result<GitControlRoots, SemanticProviderProtocolError> {
    let marker = repository_root.join(".git");
    let metadata = std::fs::symlink_metadata(&marker)
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
    if metadata.file_type().is_symlink() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "Git control marker is a symlink".into(),
        ));
    }
    if metadata.file_type().is_dir() {
        let root = canonical_git_directory(&marker, "Git control directory")?;
        return Ok(GitControlRoots {
            worktree: root.clone(),
            common: root,
            linked: false,
        });
    }
    if !metadata.file_type().is_file() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "Git control marker is neither a directory nor a file".into(),
        ));
    }

    let marker_value = read_git_control_pointer(&marker, "linked-worktree .git marker")?;
    let git_dir = marker_value
        .strip_prefix("gitdir:")
        .map(str::trim)
        .ok_or_else(|| {
            SemanticProviderProtocolError::InvalidSemanticInputs(
                "linked-worktree .git marker lacks gitdir".into(),
            )
        })?;
    if git_dir.is_empty() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "linked-worktree .git marker has an empty gitdir".into(),
        ));
    }
    let git_dir = PathBuf::from(git_dir);
    let git_dir = if git_dir.is_absolute() {
        git_dir
    } else {
        repository_root.join(git_dir)
    };
    let worktree = canonical_git_directory(&git_dir, "linked-worktree gitdir")?;
    let head = std::fs::symlink_metadata(worktree.join("HEAD"))
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
    if !head.file_type().is_file() || head.file_type().is_symlink() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "linked-worktree gitdir has no plain HEAD file".into(),
        ));
    }

    let reciprocal_marker = worktree.join("gitdir");
    let reciprocal_value =
        read_git_control_pointer(&reciprocal_marker, "linked-worktree gitdir backpointer")?;
    let reciprocal_value = PathBuf::from(reciprocal_value);
    let reciprocal_path = if reciprocal_value.is_absolute() {
        reciprocal_value
    } else {
        worktree.join(reciprocal_value)
    };
    let expected_marker = canonical_git_file(&marker, "linked-worktree .git marker")?;
    let observed_marker = canonical_git_file(&reciprocal_path, "linked-worktree gitdir target")?;
    if observed_marker != expected_marker {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "linked-worktree gitdir does not point back to the repository .git marker".into(),
        ));
    }

    let commondir_marker = worktree.join("commondir");
    match std::fs::symlink_metadata(&commondir_marker) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                "linked-worktree gitdir has no commondir pointer".into(),
            ));
        }
        Err(error) => return Err(SemanticProviderProtocolError::Io(error.to_string())),
    }
    let value = read_git_control_pointer(&commondir_marker, "Git commondir pointer")?;
    let value = PathBuf::from(value);
    let candidate = if value.is_absolute() {
        value
    } else {
        worktree.join(value)
    };
    let common = canonical_git_directory(&candidate, "Git common directory")?;
    if common == worktree {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "linked-worktree gitdir does not identify a distinct common Git directory".into(),
        ));
    }
    let worktrees = common.join("worktrees");
    let relative = worktree.strip_prefix(&worktrees).map_err(|_| {
        SemanticProviderProtocolError::InvalidSemanticInputs(
            "linked-worktree gitdir is not owned by its common Git directory".into(),
        )
    })?;
    let mut components = relative.components();
    if components.next().is_none() || components.next().is_some() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "linked-worktree gitdir has an invalid common-directory coordinate".into(),
        ));
    }
    Ok(GitControlRoots {
        worktree,
        common,
        linked: true,
    })
}

fn normalize_absolute_semantic_input(
    path: &Path,
) -> Result<PathBuf, SemanticProviderProtocolError> {
    if !path.is_absolute() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!("semantic input is not absolute: {}", path.display()),
        ));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                        format!("semantic input escapes filesystem root: {}", path.display()),
                    ));
                }
            }
            std::path::Component::Normal(component) => normalized.push(component),
        }
    }
    Ok(normalized)
}

fn coordinate_below(
    root: ProviderSemanticPathRoot,
    authority_root: &Path,
    path: &Path,
) -> Result<Option<ProviderSemanticPathCoordinate>, SemanticProviderProtocolError> {
    let Ok(relative) = path.strip_prefix(authority_root) else {
        return Ok(None);
    };
    let label = semantic_repository_relative_label(Path::new(""), relative)?;
    if label.is_empty() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input cannot claim an entire authority root".into(),
        ));
    }
    Ok(Some(ProviderSemanticPathCoordinate { root, path: label }))
}

/// Convert an absolute compiler-observed input into a machine-independent
/// coordinate. Only the selected repository and its mechanically proven Git
/// worktree/common directories are admissible.
pub fn classify_provider_semantic_input_path(
    repository_root: &Path,
    path: &Path,
) -> Result<ProviderSemanticPathCoordinate, SemanticProviderProtocolError> {
    let path = normalize_absolute_semantic_input(path)?;
    let repository_root = normalize_absolute_semantic_input(repository_root)?;
    if let Some(coordinate) = coordinate_below(
        ProviderSemanticPathRoot::Repository,
        &repository_root,
        &path,
    )? {
        return Ok(coordinate);
    }
    let roots = resolve_git_control_roots(&repository_root)?;
    if !roots.linked {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!(
                "semantic input escapes repository authority: {}",
                path.display()
            ),
        ));
    }
    if let Some(coordinate) = coordinate_below(
        ProviderSemanticPathRoot::GitWorktree,
        &roots.worktree,
        &path,
    )? {
        return Ok(coordinate);
    }
    if let Some(coordinate) =
        coordinate_below(ProviderSemanticPathRoot::GitCommon, &roots.common, &path)?
    {
        return Ok(coordinate);
    }
    Err(SemanticProviderProtocolError::InvalidSemanticInputs(
        format!(
            "semantic input escapes repository and Git authority: {}",
            path.display()
        ),
    ))
}

fn validate_semantic_coordinate(
    coordinate: &ProviderSemanticPathCoordinate,
) -> Result<(), SemanticProviderProtocolError> {
    match coordinate.root {
        ProviderSemanticPathRoot::Repository => validate_semantic_input_path(&coordinate.path),
        ProviderSemanticPathRoot::GitWorktree | ProviderSemanticPathRoot::GitCommon => {
            validate_document_path(&coordinate.path)
        }
    }
}

/// Resolve one persisted coordinate to the current checkout without accepting
/// a serialized absolute path.
pub fn resolve_provider_semantic_path_location(
    repository_root: &Path,
    root: ProviderSemanticPathRoot,
    relative_path: &str,
) -> Result<ProviderSemanticPathLocation, SemanticProviderProtocolError> {
    let coordinate = ProviderSemanticPathCoordinate {
        root,
        path: relative_path.to_owned(),
    };
    validate_semantic_coordinate(&coordinate)?;
    let authority_root = match root {
        ProviderSemanticPathRoot::Repository => repository_root.to_path_buf(),
        ProviderSemanticPathRoot::GitWorktree | ProviderSemanticPathRoot::GitCommon => {
            let roots = resolve_git_control_roots(repository_root)?;
            if !roots.linked {
                return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                    "external Git semantic root requires a linked worktree".into(),
                ));
            }
            match root {
                ProviderSemanticPathRoot::GitWorktree => roots.worktree,
                ProviderSemanticPathRoot::GitCommon => roots.common,
                ProviderSemanticPathRoot::Repository => unreachable!(),
            }
        }
    };
    let absolute_path = authority_root.join(relative_path);
    Ok(ProviderSemanticPathLocation {
        authority_root,
        absolute_path,
    })
}

fn semantic_coordinates_with_addressing_inputs(
    repository_root: &Path,
    coordinates: &BTreeSet<ProviderSemanticPathCoordinate>,
) -> Result<BTreeSet<ProviderSemanticPathCoordinate>, SemanticProviderProtocolError> {
    let mut expanded = coordinates.clone();
    for coordinate in coordinates {
        validate_semantic_coordinate(coordinate)?;
    }
    if coordinates
        .iter()
        .all(|coordinate| coordinate.root == ProviderSemanticPathRoot::Repository)
    {
        return Ok(expanded);
    }
    let roots = resolve_git_control_roots(repository_root)?;
    if !roots.linked {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "external Git semantic inputs require a linked worktree".into(),
        ));
    }
    expanded.insert(ProviderSemanticPathCoordinate::repository(".git"));
    expanded.insert(ProviderSemanticPathCoordinate {
        root: ProviderSemanticPathRoot::GitWorktree,
        path: "gitdir".into(),
    });
    debug_assert_ne!(roots.common, roots.worktree);
    expanded.insert(ProviderSemanticPathCoordinate {
        root: ProviderSemanticPathRoot::GitWorktree,
        path: "commondir".into(),
    });
    Ok(expanded)
}

/// Capture exact bounded repository-local semantic inputs.
///
/// All supplied paths are canonical repository-relative labels; no machine
/// path enters the result persisted for later freshness checks.
pub fn capture_provider_semantic_inputs(
    repository_root: &Path,
    paths: &BTreeSet<String>,
    environment_names: &BTreeSet<String>,
    limits: &ProviderFrameLimits,
) -> Result<ProviderSemanticInputs, SemanticProviderProtocolError> {
    let coordinates = paths
        .iter()
        .cloned()
        .map(ProviderSemanticPathCoordinate::repository)
        .collect();
    capture_provider_semantic_inputs_at_coordinates(
        repository_root,
        &coordinates,
        environment_names,
        limits,
    )
}

/// Capture exact semantic inputs from repository or mechanically resolved Git
/// control roots. Any path outside those three authorities is rejected before
/// bytes are read.
///
/// Linked-worktree addressing files are included automatically so changing
/// `.git` or `commondir` also invalidates the generation.
pub fn capture_provider_semantic_inputs_at_coordinates(
    repository_root: &Path,
    coordinates: &BTreeSet<ProviderSemanticPathCoordinate>,
    environment_names: &BTreeSet<String>,
    limits: &ProviderFrameLimits,
) -> Result<ProviderSemanticInputs, SemanticProviderProtocolError> {
    validate_limits(limits)?;
    let coordinates = semantic_coordinates_with_addressing_inputs(repository_root, coordinates)?;
    if coordinates.len() > limits.max_semantic_input_paths
        || environment_names.len() > limits.max_semantic_input_paths
    {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input population exceeds negotiated path bounds".into(),
        ));
    }
    let root_metadata = std::fs::symlink_metadata(repository_root)
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
    if !root_metadata.file_type().is_dir() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input repository root is not a directory".into(),
        ));
    }
    let mut budget = SemanticInputBudget::default();
    let mut observed_paths = Vec::with_capacity(coordinates.len());
    for coordinate in &coordinates {
        observed_paths.push(observe_provider_semantic_coordinate_with_budget(
            repository_root,
            coordinate,
            &mut budget,
        )?);
    }
    let mut environment = Vec::with_capacity(environment_names.len());
    for name in environment_names {
        validate_environment_name(name)?;
        environment.push(observe_provider_semantic_environment(name));
    }
    let inputs = ProviderSemanticInputs {
        schema_version: PROVIDER_SEMANTIC_INPUTS_SCHEMA.into(),
        coverage: ProviderSemanticInputCoverage::Complete,
        paths: observed_paths,
        environment,
        issues: Vec::new(),
    };
    validate_provider_semantic_inputs(&inputs, limits)?;
    Ok(inputs)
}

/// Capture exact repository paths while binding environment coordinates to
/// the explicit post-`env_clear` provider environment rather than this
/// process's ambient variables.
pub fn capture_provider_semantic_inputs_in_environment(
    repository_root: &Path,
    paths: &BTreeSet<String>,
    environment_names: &BTreeSet<String>,
    environment: &BTreeMap<OsString, OsString>,
    limits: &ProviderFrameLimits,
) -> Result<ProviderSemanticInputs, SemanticProviderProtocolError> {
    let mut inputs =
        capture_provider_semantic_inputs(repository_root, paths, &BTreeSet::new(), limits)?;
    inputs.environment = environment_names
        .iter()
        .map(|name| ProviderSemanticEnvironmentInput {
            name: name.clone(),
            value_sha256: environment
                .get(OsStr::new(name))
                .map(|value| sha256_hex(value.as_encoded_bytes())),
        })
        .collect();
    validate_provider_semantic_inputs(&inputs, limits)?;
    Ok(inputs)
}

/// Re-observe a persisted semantic-input manifest under the current process.
/// `Ok(false)` is ordinary drift; an error means freshness could not be
/// established and callers must not report Fresh.
pub fn provider_semantic_inputs_are_current(
    repository_root: &Path,
    expected: &ProviderSemanticInputs,
    limits: &ProviderFrameLimits,
) -> Result<bool, SemanticProviderProtocolError> {
    validate_provider_semantic_inputs(expected, limits)?;
    if expected.coverage != ProviderSemanticInputCoverage::Complete {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input population was not completely reproducible".into(),
        ));
    }
    let mut observed = recapture_provider_semantic_paths(repository_root, expected, limits)?;
    observed.environment = expected
        .environment
        .iter()
        .map(|input| observe_provider_semantic_environment(&input.name))
        .collect();
    validate_provider_semantic_inputs(&observed, limits)?;
    Ok(observed == *expected)
}

/// Re-observe only the repository-local path portion of a persisted semantic
/// input manifest.
///
/// Query processes use this to decide whether an immutable generation still
/// describes the current repository. The query process's ambient environment
/// is deliberately excluded: provider children run with a cleared, explicit
/// environment, and a reader's unrelated launch environment is not repository
/// freshness authority.
pub fn provider_semantic_paths_are_current(
    repository_root: &Path,
    expected: &ProviderSemanticInputs,
    limits: &ProviderFrameLimits,
) -> Result<bool, SemanticProviderProtocolError> {
    validate_provider_semantic_inputs(expected, limits)?;
    if expected.coverage != ProviderSemanticInputCoverage::Complete {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input population was not completely reproducible".into(),
        ));
    }
    let observed = recapture_provider_semantic_paths(repository_root, expected, limits)?;
    Ok(observed.paths == expected.paths)
}

/// Re-observe a persisted semantic-input manifest under the exact environment
/// selected for a provider child.
///
/// Callers must pass the final post-`env_clear` environment, including any
/// product-injected provider coordinates. This keeps generation reuse bound to
/// the environment the provider will actually see instead of the unrelated
/// ambient environment of the CLI, MCP server, or watcher.
pub fn provider_semantic_inputs_are_current_in_environment(
    repository_root: &Path,
    expected: &ProviderSemanticInputs,
    environment: &BTreeMap<OsString, OsString>,
    limits: &ProviderFrameLimits,
) -> Result<bool, SemanticProviderProtocolError> {
    validate_provider_semantic_inputs(expected, limits)?;
    if expected.coverage != ProviderSemanticInputCoverage::Complete {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input population was not completely reproducible".into(),
        ));
    }
    let mut observed = recapture_provider_semantic_paths(repository_root, expected, limits)?;
    observed.environment = expected
        .environment
        .iter()
        .map(|input| ProviderSemanticEnvironmentInput {
            name: input.name.clone(),
            value_sha256: environment
                .get(OsStr::new(&input.name))
                .map(|value| sha256_hex(value.as_encoded_bytes())),
        })
        .collect();
    validate_provider_semantic_inputs(&observed, limits)?;
    Ok(observed == *expected)
}

fn recapture_provider_semantic_paths(
    repository_root: &Path,
    expected: &ProviderSemanticInputs,
    limits: &ProviderFrameLimits,
) -> Result<ProviderSemanticInputs, SemanticProviderProtocolError> {
    if expected.paths.len() > limits.max_semantic_input_paths {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input population exceeds negotiated path bounds".into(),
        ));
    }
    let root_metadata = std::fs::symlink_metadata(repository_root)
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
    if !root_metadata.file_type().is_dir() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input repository root is not a directory".into(),
        ));
    }
    let mut budget = SemanticInputBudget::default();
    let mut paths = Vec::with_capacity(expected.paths.len());
    for input in &expected.paths {
        paths.push(observe_provider_semantic_coordinate_for_kind_with_budget(
            repository_root,
            &ProviderSemanticPathCoordinate {
                root: input.root,
                path: input.path.clone(),
            },
            input.kind,
            &mut budget,
        )?);
    }
    Ok(ProviderSemanticInputs {
        schema_version: PROVIDER_SEMANTIC_INPUTS_SCHEMA.into(),
        coverage: ProviderSemanticInputCoverage::Complete,
        paths,
        environment: Vec::new(),
        issues: Vec::new(),
    })
}

/// Validate and hash the canonical manifest published in `SessionOpened` and
/// persisted with its provider payload.
pub fn provider_semantic_inputs_sha256(
    inputs: &ProviderSemanticInputs,
    limits: &ProviderFrameLimits,
) -> Result<String, SemanticProviderProtocolError> {
    validate_provider_semantic_inputs(inputs, limits)?;
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, PROVIDER_SEMANTIC_INPUTS_DIGEST_SCHEMA);
    hash_field(
        &mut hasher,
        match inputs.coverage {
            ProviderSemanticInputCoverage::Complete => b"complete",
            ProviderSemanticInputCoverage::Unverifiable => b"unverifiable",
        },
    );
    for input in &inputs.paths {
        hash_field(&mut hasher, input.root.digest_label());
        hash_field(&mut hasher, input.path.as_bytes());
        hash_field(
            &mut hasher,
            match input.kind {
                ProviderSemanticPathKind::Missing => b"missing",
                ProviderSemanticPathKind::File => b"file",
                ProviderSemanticPathKind::Directory => b"directory",
                ProviderSemanticPathKind::DirectoryListing => b"directory_listing",
            },
        );
        hash_field(&mut hasher, input.identity_sha256.as_bytes());
        hash_field(&mut hasher, &input.entry_count.to_be_bytes());
        hash_field(&mut hasher, &input.byte_length.to_be_bytes());
    }
    for input in &inputs.environment {
        hash_field(&mut hasher, input.name.as_bytes());
        match &input.value_sha256 {
            Some(value) => {
                hash_field(&mut hasher, b"present");
                hash_field(&mut hasher, value.as_bytes());
            }
            None => hash_field(&mut hasher, b"missing"),
        }
    }
    for issue in &inputs.issues {
        hash_field(&mut hasher, issue.code.as_bytes());
        hash_field(&mut hasher, issue.path.as_bytes());
        hash_field(&mut hasher, issue.detail.as_bytes());
    }
    Ok(hex_digest(&hasher.finalize()))
}

pub fn validate_provider_semantic_inputs(
    inputs: &ProviderSemanticInputs,
    limits: &ProviderFrameLimits,
) -> Result<(), SemanticProviderProtocolError> {
    validate_limits(limits)?;
    if inputs.schema_version != PROVIDER_SEMANTIC_INPUTS_SCHEMA {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input schema mismatch".into(),
        ));
    }
    if inputs.paths.len() > limits.max_semantic_input_paths
        || inputs.environment.len() > limits.max_semantic_input_paths
        || inputs.issues.len() > limits.max_semantic_input_paths
    {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input population exceeds negotiated path bounds".into(),
        ));
    }
    let mut previous_path = None;
    for input in &inputs.paths {
        match input.root {
            ProviderSemanticPathRoot::Repository => validate_semantic_input_path(&input.path)?,
            ProviderSemanticPathRoot::GitWorktree | ProviderSemanticPathRoot::GitCommon => {
                validate_document_path(&input.path)?;
                if !matches!(
                    input.kind,
                    ProviderSemanticPathKind::Missing | ProviderSemanticPathKind::File
                ) {
                    return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                        format!("Git semantic input {} is not a file", input.path),
                    ));
                }
            }
        }
        let coordinate = (input.root, input.path.as_str());
        if previous_path.is_some_and(|previous| previous >= coordinate)
            || !is_sha256(&input.identity_sha256)
            || (input.kind == ProviderSemanticPathKind::Missing
                && (input.entry_count != 0 || input.byte_length != 0))
            || (input.kind != ProviderSemanticPathKind::Missing && input.entry_count == 0)
            || input.entry_count > MAX_PROVIDER_SEMANTIC_INPUT_ENTRIES
            || input.byte_length > MAX_PROVIDER_SEMANTIC_INPUT_BYTES
        {
            return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                format!("invalid semantic path input {}", input.path),
            ));
        }
        previous_path = Some(coordinate);
    }
    let mut previous_name = None;
    for input in &inputs.environment {
        validate_environment_name(&input.name)?;
        if previous_name.is_some_and(|previous| previous >= input.name.as_str())
            || input
                .value_sha256
                .as_ref()
                .is_some_and(|value| !is_sha256(value))
        {
            return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                format!("invalid semantic environment input {}", input.name),
            ));
        }
        previous_name = Some(input.name.as_str());
    }
    if (inputs.coverage == ProviderSemanticInputCoverage::Complete && !inputs.issues.is_empty())
        || (inputs.coverage == ProviderSemanticInputCoverage::Unverifiable
            && inputs.issues.is_empty())
    {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input coverage and issue population disagree".into(),
        ));
    }
    let mut previous_issue = None;
    for issue in &inputs.issues {
        validate_text("semantic input issue code", &issue.code, 128)?;
        validate_document_path(&issue.path)?;
        validate_text("semantic input issue detail", &issue.detail, 1024)?;
        if previous_issue.is_some_and(|previous| previous >= issue) {
            return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                "semantic input issues are duplicate or not canonical".into(),
            ));
        }
        previous_issue = Some(issue);
    }
    Ok(())
}

#[derive(Default)]
struct SemanticInputBudget {
    entries: u64,
    bytes: u64,
}

impl SemanticInputBudget {
    fn observe_entry(&mut self) -> Result<(), SemanticProviderProtocolError> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > MAX_PROVIDER_SEMANTIC_INPUT_ENTRIES {
            return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                "semantic input entry population exceeds its bound".into(),
            ));
        }
        Ok(())
    }

    fn observe_bytes(&mut self, bytes: usize) -> Result<(), SemanticProviderProtocolError> {
        self.bytes = self
            .bytes
            .checked_add(bytes as u64)
            .ok_or(SemanticProviderProtocolError::ArithmeticOverflow)?;
        if self.bytes > MAX_PROVIDER_SEMANTIC_INPUT_BYTES {
            return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                "semantic input byte population exceeds its bound".into(),
            ));
        }
        Ok(())
    }
}

fn observe_provider_semantic_coordinate_with_budget(
    repository_root: &Path,
    coordinate: &ProviderSemanticPathCoordinate,
    budget: &mut SemanticInputBudget,
) -> Result<ProviderSemanticPathInput, SemanticProviderProtocolError> {
    validate_semantic_coordinate(coordinate)?;
    let location = resolve_provider_semantic_path_location(
        repository_root,
        coordinate.root,
        &coordinate.path,
    )?;
    let before_entries = budget.entries;
    let before_bytes = budget.bytes;
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, PROVIDER_SEMANTIC_PATH_SCHEMA);
    hash_field(&mut hasher, coordinate.root.digest_label());
    let kind = hash_provider_semantic_path(
        &mut hasher,
        &location.authority_root,
        &location.absolute_path,
        &location.absolute_path,
        budget,
        &mut BTreeSet::new(),
    )?;
    if coordinate.root != ProviderSemanticPathRoot::Repository
        && !matches!(
            kind,
            ProviderSemanticPathKind::Missing | ProviderSemanticPathKind::File
        )
    {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!("Git semantic input {} is not a file", coordinate.path),
        ));
    }
    Ok(ProviderSemanticPathInput {
        root: coordinate.root,
        path: coordinate.path.clone(),
        kind,
        identity_sha256: hex_digest(&hasher.finalize()),
        entry_count: budget.entries.saturating_sub(before_entries),
        byte_length: budget.bytes.saturating_sub(before_bytes),
    })
}

/// Capture the immediate directory membership observed by a compiler.
///
/// Unlike a declared recursive directory input, this does not hash descendant
/// bytes that the compiler never read.
pub fn capture_provider_semantic_directory_listing(
    repository_root: &Path,
    relative_path: &str,
    limits: &ProviderFrameLimits,
) -> Result<ProviderSemanticPathInput, SemanticProviderProtocolError> {
    validate_limits(limits)?;
    let mut budget = SemanticInputBudget::default();
    let input = observe_provider_semantic_path_for_kind_with_budget(
        repository_root,
        relative_path,
        ProviderSemanticPathKind::DirectoryListing,
        &mut budget,
    )?;
    let manifest = ProviderSemanticInputs {
        schema_version: PROVIDER_SEMANTIC_INPUTS_SCHEMA.into(),
        coverage: ProviderSemanticInputCoverage::Complete,
        paths: vec![input.clone()],
        environment: Vec::new(),
        issues: Vec::new(),
    };
    validate_provider_semantic_inputs(&manifest, limits)?;
    Ok(input)
}

fn observe_provider_semantic_path_for_kind_with_budget(
    repository_root: &Path,
    relative_path: &str,
    expected_kind: ProviderSemanticPathKind,
    budget: &mut SemanticInputBudget,
) -> Result<ProviderSemanticPathInput, SemanticProviderProtocolError> {
    observe_provider_semantic_coordinate_for_kind_with_budget(
        repository_root,
        &ProviderSemanticPathCoordinate::repository(relative_path),
        expected_kind,
        budget,
    )
}

fn observe_provider_semantic_coordinate_for_kind_with_budget(
    repository_root: &Path,
    coordinate: &ProviderSemanticPathCoordinate,
    expected_kind: ProviderSemanticPathKind,
    budget: &mut SemanticInputBudget,
) -> Result<ProviderSemanticPathInput, SemanticProviderProtocolError> {
    validate_semantic_coordinate(coordinate)?;
    if coordinate.root != ProviderSemanticPathRoot::Repository
        || expected_kind != ProviderSemanticPathKind::DirectoryListing
    {
        return observe_provider_semantic_coordinate_with_budget(
            repository_root,
            coordinate,
            budget,
        );
    }
    let location = resolve_provider_semantic_path_location(
        repository_root,
        coordinate.root,
        &coordinate.path,
    )?;
    let absolute = location.absolute_path;
    if expected_kind != ProviderSemanticPathKind::DirectoryListing
        || !std::fs::metadata(&absolute).is_ok_and(|metadata| metadata.is_dir())
    {
        return observe_provider_semantic_coordinate_with_budget(
            repository_root,
            coordinate,
            budget,
        );
    }
    let before_entries = budget.entries;
    let before_bytes = budget.bytes;
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, PROVIDER_SEMANTIC_PATH_SCHEMA);
    hash_field(&mut hasher, coordinate.root.digest_label());
    hash_provider_semantic_directory_listing(
        &mut hasher,
        &location.authority_root,
        &absolute,
        &absolute,
        budget,
    )?;
    Ok(ProviderSemanticPathInput {
        root: coordinate.root,
        path: coordinate.path.clone(),
        kind: ProviderSemanticPathKind::DirectoryListing,
        identity_sha256: hex_digest(&hasher.finalize()),
        entry_count: budget.entries.saturating_sub(before_entries),
        byte_length: budget.bytes.saturating_sub(before_bytes),
    })
}

fn hash_provider_semantic_path(
    hasher: &mut Sha256,
    repository_root: &Path,
    logical_root: &Path,
    path: &Path,
    budget: &mut SemanticInputBudget,
    active_directories: &mut BTreeSet<PathBuf>,
) -> Result<ProviderSemanticPathKind, SemanticProviderProtocolError> {
    let relative = path.strip_prefix(logical_root).map_err(|_| {
        SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input traversal escaped its logical root".into(),
        )
    })?;
    let relative = relative.to_str().ok_or_else(|| {
        SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input path is not UTF-8".into(),
        )
    })?;
    hash_field(&mut *hasher, relative.as_bytes());
    let resolution = resolve_provider_semantic_path(repository_root, path)?;
    hash_field(&mut *hasher, resolution.canonical_delta.as_bytes());
    if !resolution.exists {
        hash_field(&mut *hasher, b"missing");
        if resolve_provider_semantic_path(repository_root, path)? != resolution {
            return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                format!("semantic input changed while hashing: {}", path.display()),
            ));
        }
        return Ok(ProviderSemanticPathKind::Missing);
    }
    let before = std::fs::metadata(path)
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
    let before_stamp = semantic_metadata_stamp(&before)?;
    budget.observe_entry()?;
    let file_type = before.file_type();
    let kind = if file_type.is_file() {
        hash_field(&mut *hasher, b"file");
        let mut file = File::open(path)
            .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
        let mut file_hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
            if read == 0 {
                break;
            }
            budget.observe_bytes(read)?;
            file_hasher.update(&buffer[..read]);
        }
        hash_field(&mut *hasher, &file_hasher.finalize());
        ProviderSemanticPathKind::File
    } else if file_type.is_dir() {
        if !active_directories.insert(resolution.canonical_path.clone()) {
            return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                format!(
                    "semantic input contains a directory cycle: {}",
                    path.display()
                ),
            ));
        }
        hash_field(&mut *hasher, b"directory");
        let entries = sorted_semantic_directory_entries(path)?;
        hash_field(&mut *hasher, &(entries.len() as u64).to_be_bytes());
        for entry in &entries {
            hash_provider_semantic_path(
                hasher,
                repository_root,
                logical_root,
                entry,
                budget,
                active_directories,
            )?;
        }
        active_directories.remove(&resolution.canonical_path);
        if sorted_semantic_directory_entries(path)? != entries {
            return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                format!(
                    "semantic input directory changed while hashing: {}",
                    path.display()
                ),
            ));
        }
        ProviderSemanticPathKind::Directory
    } else {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!(
                "semantic input has unsupported file type: {}",
                path.display()
            ),
        ));
    };
    let after = std::fs::metadata(path)
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
    if semantic_metadata_stamp(&after)? != before_stamp
        || resolve_provider_semantic_path(repository_root, path)? != resolution
    {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!("semantic input changed while hashing: {}", path.display()),
        ));
    }
    Ok(kind)
}

fn hash_provider_semantic_directory_listing(
    hasher: &mut Sha256,
    repository_root: &Path,
    logical_root: &Path,
    path: &Path,
    budget: &mut SemanticInputBudget,
) -> Result<(), SemanticProviderProtocolError> {
    let relative = path.strip_prefix(logical_root).map_err(|_| {
        SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input traversal escaped its logical root".into(),
        )
    })?;
    let relative = relative.to_str().ok_or_else(|| {
        SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input path is not UTF-8".into(),
        )
    })?;
    hash_field(&mut *hasher, relative.as_bytes());
    let resolution = resolve_provider_semantic_path(repository_root, path)?;
    if !resolution.exists {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!("semantic directory listing is missing: {}", path.display()),
        ));
    }
    hash_field(&mut *hasher, resolution.canonical_delta.as_bytes());
    let before = std::fs::metadata(path)
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
    if !before.file_type().is_dir() {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!(
                "semantic directory listing is not a directory: {}",
                path.display()
            ),
        ));
    }
    let before_stamp = semantic_metadata_stamp(&before)?;
    budget.observe_entry()?;
    hash_field(&mut *hasher, b"directory_listing");
    let entries = semantic_directory_listing_entries(repository_root, path)?;
    hash_field(&mut *hasher, &(entries.len() as u64).to_be_bytes());
    for entry in &entries {
        budget.observe_entry()?;
        budget.observe_bytes(entry.name.len().saturating_add(entry.canonical_delta.len()))?;
        hash_field(&mut *hasher, entry.name.as_bytes());
        hash_field(
            &mut *hasher,
            match entry.kind {
                SemanticDirectoryEntryKind::File => b"file",
                SemanticDirectoryEntryKind::Directory => b"directory",
            },
        );
        hash_field(&mut *hasher, entry.canonical_delta.as_bytes());
    }
    if semantic_directory_listing_entries(repository_root, path)? != entries {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!(
                "semantic directory listing changed while hashing: {}",
                path.display()
            ),
        ));
    }
    let after = std::fs::metadata(path)
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
    if semantic_metadata_stamp(&after)? != before_stamp
        || resolve_provider_semantic_path(repository_root, path)? != resolution
    {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            format!(
                "semantic directory changed while hashing its listing: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SemanticDirectoryEntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SemanticDirectoryEntry {
    name: String,
    kind: SemanticDirectoryEntryKind,
    canonical_delta: String,
}

fn semantic_directory_listing_entries(
    repository_root: &Path,
    path: &Path,
) -> Result<Vec<SemanticDirectoryEntry>, SemanticProviderProtocolError> {
    let mut entries = std::fs::read_dir(path)
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?
        .map(|entry| {
            let entry =
                entry.map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
            let name = entry.file_name().into_string().map_err(|_| {
                SemanticProviderProtocolError::InvalidSemanticInputs(
                    "semantic directory listing contains a non-UTF-8 name".into(),
                )
            })?;
            let resolution = resolve_provider_semantic_path(repository_root, &entry.path())?;
            if !resolution.exists {
                return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                    format!(
                        "semantic directory entry is missing: {}",
                        entry.path().display()
                    ),
                ));
            }
            let file_type = std::fs::metadata(entry.path())
                .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?
                .file_type();
            let kind = if file_type.is_file() {
                SemanticDirectoryEntryKind::File
            } else if file_type.is_dir() {
                SemanticDirectoryEntryKind::Directory
            } else {
                return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                    format!(
                        "semantic directory listing contains an unsupported entry: {}",
                        entry.path().display()
                    ),
                ));
            };
            Ok(SemanticDirectoryEntry {
                name,
                kind,
                canonical_delta: resolution.canonical_delta,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    Ok(entries)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderSemanticPathResolution {
    exists: bool,
    canonical_path: PathBuf,
    canonical_delta: String,
}

/// Resolve an existing semantic path—or the nearest existing ancestor of a
/// missing candidate—without allowing a symlink to import machine-external
/// state. The empty delta is reserved for a path whose canonical repository
/// coordinate is unchanged; linked paths bind an explicit `target:` label.
fn resolve_provider_semantic_path(
    repository_root: &Path,
    path: &Path,
) -> Result<ProviderSemanticPathResolution, SemanticProviderProtocolError> {
    let logical_relative = semantic_repository_relative_label(repository_root, path)?;
    let canonical_root = std::fs::canonicalize(repository_root)
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?;
    let mut candidate = path.to_path_buf();
    let mut missing_suffix = Vec::<OsString>::new();
    let (mut canonical_path, exists) = loop {
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => {
                let resolved = std::fs::canonicalize(&candidate).map_err(|error| {
                    SemanticProviderProtocolError::InvalidSemanticInputs(format!(
                        "semantic input contains an unresolved symlink: {}: {error}",
                        candidate.display()
                    ))
                })?;
                break (resolved, missing_suffix.is_empty());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if candidate == repository_root {
                    return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                        "semantic input repository root disappeared during observation".into(),
                    ));
                }
                let name = candidate.file_name().ok_or_else(|| {
                    SemanticProviderProtocolError::InvalidSemanticInputs(
                        "semantic input has no repository-local ancestor".into(),
                    )
                })?;
                missing_suffix.push(name.to_os_string());
                candidate = candidate
                    .parent()
                    .ok_or_else(|| {
                        SemanticProviderProtocolError::InvalidSemanticInputs(
                            "semantic input escaped its repository root".into(),
                        )
                    })?
                    .to_path_buf();
                if candidate != repository_root && !candidate.starts_with(repository_root) {
                    return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                        "semantic input escaped its repository root".into(),
                    ));
                }
            }
            Err(error) => return Err(SemanticProviderProtocolError::Io(error.to_string())),
        }
    };
    for component in missing_suffix.iter().rev() {
        canonical_path.push(component);
    }
    let canonical_relative = semantic_repository_relative_label(&canonical_root, &canonical_path)
        .map_err(|_| {
        SemanticProviderProtocolError::InvalidSemanticInputs(format!(
            "semantic input symlink escapes repository authority: {}",
            path.display()
        ))
    })?;
    let canonical_delta = if canonical_relative == logical_relative {
        String::new()
    } else {
        format!("target:{canonical_relative}")
    };
    Ok(ProviderSemanticPathResolution {
        exists,
        canonical_path,
        canonical_delta,
    })
}

fn semantic_repository_relative_label(
    repository_root: &Path,
    path: &Path,
) -> Result<String, SemanticProviderProtocolError> {
    let relative = path.strip_prefix(repository_root).map_err(|_| {
        SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input path escapes repository authority".into(),
        )
    })?;
    let mut parts = Vec::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(value) => parts.push(value.to_str().ok_or_else(|| {
                SemanticProviderProtocolError::InvalidSemanticInputs(
                    "semantic input path is not UTF-8".into(),
                )
            })?),
            std::path::Component::CurDir => {}
            _ => {
                return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
                    "semantic input path is not a canonical repository label".into(),
                ));
            }
        }
    }
    Ok(parts.join("/"))
}

fn sorted_semantic_directory_entries(
    path: &Path,
) -> Result<Vec<PathBuf>, SemanticProviderProtocolError> {
    let mut entries = std::fs::read_dir(path)
        .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))?
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|error| SemanticProviderProtocolError::Io(error.to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if entries
        .iter()
        .any(|entry| entry.file_name().and_then(|name| name.to_str()).is_none())
    {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic input directory contains a non-UTF-8 name".into(),
        ));
    }
    entries.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(entries)
}

fn semantic_metadata_stamp(
    metadata: &std::fs::Metadata,
) -> Result<(bool, bool, u64, Option<std::time::SystemTime>), SemanticProviderProtocolError> {
    Ok((
        metadata.file_type().is_file(),
        metadata.file_type().is_dir(),
        metadata.len(),
        metadata.modified().ok(),
    ))
}

fn validate_environment_name(name: &str) -> Result<(), SemanticProviderProtocolError> {
    if name.is_empty()
        || name.len() > 1024
        || name.contains('=')
        || name.chars().any(char::is_control)
    {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic environment name is empty, oversized, or malformed".into(),
        ));
    }
    Ok(())
}

fn observe_provider_semantic_environment(name: &str) -> ProviderSemanticEnvironmentInput {
    ProviderSemanticEnvironmentInput {
        name: name.into(),
        value_sha256: std::env::var_os(name).map(|value| sha256_hex(value.as_encoded_bytes())),
    }
}

/// Bind runtime/toolchain configuration to the exact Cargo workspace model.
///
/// The resulting coordinate is stored in canonical semantic snapshots and
/// immutable capability receipts.
pub fn resolved_authority_configuration_sha256(
    authority: &ProviderAuthority,
) -> Result<String, SemanticProviderProtocolError> {
    validate_authority(authority)?;
    let resolution = authority
        .workspace_resolution_sha256
        .as_deref()
        .ok_or_else(|| {
            SemanticProviderProtocolError::InvalidAuthority(
                "workspace resolution is not yet established".into(),
            )
        })?;
    let semantic_inputs = authority.semantic_inputs_sha256.as_deref().ok_or_else(|| {
        SemanticProviderProtocolError::InvalidAuthority(
            "semantic inputs are not yet established".into(),
        )
    })?;
    resolved_workspace_configuration_sha256(
        &authority.configuration_sha256,
        resolution,
        semantic_inputs,
    )
}

/// Reconstruct the provider-observed workspace coordinate from its exact
/// runtime, dependency-resolution, and semantic-input identities.
///
/// This is the descriptor form of [`resolved_authority_configuration_sha256`]:
/// it deliberately excludes ephemeral session/source-epoch fields so a fresh
/// process can verify a closed immutable generation without loading the
/// workspace again.
pub fn resolved_workspace_configuration_sha256(
    runtime_configuration_sha256: &str,
    workspace_resolution_sha256: &str,
    semantic_inputs_sha256: &str,
) -> Result<String, SemanticProviderProtocolError> {
    if !is_sha256(runtime_configuration_sha256)
        || !is_sha256(workspace_resolution_sha256)
        || !is_sha256(semantic_inputs_sha256)
    {
        return Err(SemanticProviderProtocolError::InvalidAuthority(
            "resolved workspace coordinate contains a non-SHA-256 digest".into(),
        ));
    }
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, RESOLVED_AUTHORITY_CONFIGURATION_SCHEMA);
    hash_field(&mut hasher, runtime_configuration_sha256.as_bytes());
    hash_field(&mut hasher, workspace_resolution_sha256.as_bytes());
    hash_field(&mut hasher, semantic_inputs_sha256.as_bytes());
    Ok(hex_digest(&hasher.finalize()))
}

/// Construct a language-neutral semantic runtime identity from exact component
/// reports observed inside the provider's cleared, explicitly populated
/// environment.
pub fn provider_runtime_configuration(
    resolved_toolchain_sha256: &str,
    component_reports: &[(&str, &[u8])],
    environment_report: &[u8],
    workspace_configuration_report: &[u8],
) -> Result<ProviderRuntimeConfiguration, SemanticProviderProtocolError> {
    let mut component_sha256s = BTreeMap::new();
    for (name, report) in component_reports {
        validate_runtime_component_name(name)?;
        if component_sha256s
            .insert((*name).to_owned(), sha256_hex(report))
            .is_some()
        {
            return Err(SemanticProviderProtocolError::InvalidRuntimeConfiguration(
                format!("runtime component `{name}` is duplicated"),
            ));
        }
    }
    let environment_sha256 = sha256_hex(environment_report);
    let workspace_configuration_sha256 = sha256_hex(workspace_configuration_report);
    let configuration_sha256 = runtime_configuration_digest(
        resolved_toolchain_sha256,
        &component_sha256s,
        &environment_sha256,
        &workspace_configuration_sha256,
    );
    let configuration = ProviderRuntimeConfiguration {
        configuration_sha256,
        resolved_toolchain_sha256: resolved_toolchain_sha256.into(),
        component_sha256s,
        environment_sha256,
        workspace_configuration_sha256,
    };
    validate_runtime_configuration(&configuration)?;
    Ok(configuration)
}

/// Construct the exact Rust semantic runtime identity from command outputs
/// observed inside the provider's cleared, explicitly populated environment.
pub fn rust_analyzer_runtime_configuration(
    resolved_toolchain_sha256: &str,
    rustc_verbose_version: &[u8],
    cargo_version: &[u8],
    sysroot_path: &[u8],
    environment_report: &[u8],
    workspace_configuration_report: &[u8],
) -> Result<ProviderRuntimeConfiguration, SemanticProviderProtocolError> {
    provider_runtime_configuration(
        resolved_toolchain_sha256,
        &[
            ("cargo_version", cargo_version),
            ("rustc_sysroot_path", sysroot_path),
            ("rustc_verbose_version", rustc_verbose_version),
        ],
        environment_report,
        workspace_configuration_report,
    )
}

/// Reject a self-inconsistent runtime report before its digest can enter an
/// authority coordinate.
pub fn validate_runtime_configuration(
    configuration: &ProviderRuntimeConfiguration,
) -> Result<(), SemanticProviderProtocolError> {
    if configuration.component_sha256s.is_empty()
        || configuration.component_sha256s.len() > MAX_PROVIDER_RUNTIME_COMPONENTS
    {
        return Err(SemanticProviderProtocolError::InvalidRuntimeConfiguration(
            format!("runtime component count must be in 1..={MAX_PROVIDER_RUNTIME_COMPONENTS}"),
        ));
    }
    for digest in [
        &configuration.configuration_sha256,
        &configuration.resolved_toolchain_sha256,
        &configuration.environment_sha256,
        &configuration.workspace_configuration_sha256,
    ] {
        if !is_sha256(digest) {
            return Err(SemanticProviderProtocolError::InvalidRuntimeConfiguration(
                "runtime identity contains a non-SHA-256 digest".into(),
            ));
        }
    }
    for (name, digest) in &configuration.component_sha256s {
        validate_runtime_component_name(name)?;
        if !is_sha256(digest) {
            return Err(SemanticProviderProtocolError::InvalidRuntimeConfiguration(
                format!("runtime component `{name}` contains a non-SHA-256 digest"),
            ));
        }
    }
    let expected = runtime_configuration_digest(
        &configuration.resolved_toolchain_sha256,
        &configuration.component_sha256s,
        &configuration.environment_sha256,
        &configuration.workspace_configuration_sha256,
    );
    if configuration.configuration_sha256 != expected {
        return Err(SemanticProviderProtocolError::InvalidRuntimeConfiguration(
            "runtime configuration digest does not match its component identities".into(),
        ));
    }
    Ok(())
}

fn runtime_configuration_digest(
    resolved_toolchain_sha256: &str,
    component_sha256s: &BTreeMap<String, String>,
    environment_sha256: &str,
    workspace_configuration_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, PROVIDER_RUNTIME_CONFIGURATION_SCHEMA);
    hash_field(&mut hasher, resolved_toolchain_sha256.as_bytes());
    hash_field(&mut hasher, &(component_sha256s.len() as u64).to_be_bytes());
    for (name, digest) in component_sha256s {
        hash_field(&mut hasher, name.as_bytes());
        hash_field(&mut hasher, digest.as_bytes());
    }
    hash_field(&mut hasher, environment_sha256.as_bytes());
    hash_field(&mut hasher, workspace_configuration_sha256.as_bytes());
    hex_digest(&hasher.finalize())
}

fn validate_runtime_component_name(name: &str) -> Result<(), SemanticProviderProtocolError> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_PROVIDER_RUNTIME_COMPONENT_NAME_BYTES
        || !bytes[0].is_ascii_lowercase()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(SemanticProviderProtocolError::InvalidRuntimeConfiguration(
            format!(
                "runtime component name must be 1..={MAX_PROVIDER_RUNTIME_COMPONENT_NAME_BYTES} lowercase ASCII letters, digits, or underscores and start with a letter"
            ),
        ));
    }
    Ok(())
}

/// Admit one atomic affected-refresh terminal only when it exactly covers the
/// requested population, matches the post-work runtime witness, and all
/// attached bytes match their declared digest.
pub fn validate_affected_refresh(
    frame: ProviderFrame<ProviderResponse>,
    expected: &ExpectedAffectedRefresh,
    limits: &ProviderFrameLimits,
) -> Result<AdmittedProviderExport, SemanticProviderProtocolError> {
    validate_expected_export(
        &expected.provider,
        &expected.authority,
        &expected.documents,
        &expected.analyses,
        limits,
    )?;
    if !is_sha256(&expected.parent_snapshot_sha256) {
        return Err(SemanticProviderProtocolError::ParentSnapshotMismatch);
    }
    let ProviderFrame {
        metadata: response,
        attachments,
    } = frame;
    validate_response_identity(
        &response,
        expected.request_id,
        &expected.provider,
        &expected.authority,
    )?;
    let ProviderResponseBody::AffectedRefreshed {
        authority,
        parent_snapshot_sha256,
        health,
        runtime_configuration,
        outcomes,
        analyses,
    } = response.body
    else {
        return Err(SemanticProviderProtocolError::UnexpectedOperation);
    };
    validate_runtime_configuration(&runtime_configuration)?;
    if runtime_configuration != expected.terminal_runtime_configuration {
        return Err(SemanticProviderProtocolError::InvalidRuntimeConfiguration(
            "affected-refresh terminal runtime differs from the admitted process".into(),
        ));
    }
    if parent_snapshot_sha256 != expected.parent_snapshot_sha256 {
        return Err(SemanticProviderProtocolError::ParentSnapshotMismatch);
    }
    admit_export_outcomes(
        ProviderExportTerminal {
            authority,
            health,
            outcomes,
            analysis_outcomes: analyses,
            attachments,
        },
        ExpectedProviderExport {
            authority: &expected.authority,
            documents: &expected.documents,
            analyses: &expected.analyses,
            limits,
        },
    )
}

/// Admit one full-certification terminal under the same exact identity,
/// health, coverage, and attachment rules as an affected refresh.
pub fn validate_full_certification(
    frame: ProviderFrame<ProviderResponse>,
    expected: &ExpectedFullCertification,
    limits: &ProviderFrameLimits,
) -> Result<AdmittedProviderExport, SemanticProviderProtocolError> {
    validate_expected_export(
        &expected.provider,
        &expected.authority,
        &expected.documents,
        &expected.analyses,
        limits,
    )?;
    let ProviderFrame {
        metadata: response,
        attachments,
    } = frame;
    validate_response_identity(
        &response,
        expected.request_id,
        &expected.provider,
        &expected.authority,
    )?;
    let ProviderResponseBody::FullCertification {
        authority,
        health,
        outcomes,
        analyses,
    } = response.body
    else {
        return Err(SemanticProviderProtocolError::UnexpectedOperation);
    };
    admit_export_outcomes(
        ProviderExportTerminal {
            authority,
            health,
            outcomes,
            analysis_outcomes: analyses,
            attachments,
        },
        ExpectedProviderExport {
            authority: &expected.authority,
            documents: &expected.documents,
            analyses: &expected.analyses,
            limits,
        },
    )
}

fn validate_expected_export(
    provider: &ProviderIdentity,
    authority: &ProviderAuthority,
    documents: &BTreeMap<String, ExpectedProviderDocument>,
    analyses: &BTreeMap<String, ExpectedProviderAnalysis>,
    limits: &ProviderFrameLimits,
) -> Result<(), SemanticProviderProtocolError> {
    validate_limits(limits)?;
    validate_provider_identity(provider)?;
    validate_authority(authority)?;
    resolved_authority_configuration_sha256(authority)?;
    if documents.is_empty() || documents.len() > limits.max_document_paths {
        return Err(SemanticProviderProtocolError::CoverageMismatch);
    }
    for (path, document) in documents {
        validate_document_path(path)?;
        validate_text("document language", &document.language, 64)?;
        validate_text("content identity", &document.content_identity, 256)?;
    }
    let requested = analyses
        .iter()
        .map(|(analysis_id, expected)| ProviderAnalysisRequest {
            analysis_id: analysis_id.clone(),
            schema_version: expected.schema_version.clone(),
            configuration_id: expected.configuration_id.clone(),
        })
        .collect::<Vec<_>>();
    validate_analysis_requests(&requested)?;
    for expected in analyses.values() {
        validate_text("analysis language", &expected.language, 64)?;
    }
    Ok(())
}

fn validate_response_identity(
    response: &ProviderResponse,
    request_id: u64,
    provider: &ProviderIdentity,
    authority: &ProviderAuthority,
) -> Result<(), SemanticProviderProtocolError> {
    if response.request_id != request_id {
        return Err(SemanticProviderProtocolError::RequestMismatch);
    }
    if response.session_id != authority.session_id {
        return Err(SemanticProviderProtocolError::ForeignSession);
    }
    validate_provider_identity(&response.provider)?;
    if response.provider != *provider {
        return Err(SemanticProviderProtocolError::ProviderIdentityMismatch);
    }
    Ok(())
}

struct ProviderExportTerminal {
    authority: ProviderAuthority,
    health: ProviderHealthEvidence,
    outcomes: Vec<ProviderDocumentOutcome>,
    analysis_outcomes: Vec<ProviderAnalysisOutcome>,
    attachments: Vec<Vec<u8>>,
}

struct ExpectedProviderExport<'a> {
    authority: &'a ProviderAuthority,
    documents: &'a BTreeMap<String, ExpectedProviderDocument>,
    analyses: &'a BTreeMap<String, ExpectedProviderAnalysis>,
    limits: &'a ProviderFrameLimits,
}

fn admit_export_outcomes(
    terminal: ProviderExportTerminal,
    expected: ExpectedProviderExport<'_>,
) -> Result<AdmittedProviderExport, SemanticProviderProtocolError> {
    let ProviderExportTerminal {
        authority,
        health,
        outcomes,
        analysis_outcomes,
        attachments,
    } = terminal;
    if outcomes.len() > expected.limits.max_document_paths {
        return Err(SemanticProviderProtocolError::CoverageMismatch);
    }
    validate_authority(&authority)?;
    if authority != *expected.authority {
        return Err(SemanticProviderProtocolError::AuthorityMismatch);
    }
    if !health.admits_complete() {
        return Err(SemanticProviderProtocolError::ProviderUnhealthy);
    }

    let mut outcomes_by_path = BTreeMap::new();
    for outcome in outcomes {
        let path = outcome.document_path().to_owned();
        validate_document_path(&path)?;
        if outcomes_by_path.insert(path.clone(), outcome).is_some() {
            return Err(SemanticProviderProtocolError::DuplicateDocumentOutcome(
                path,
            ));
        }
    }
    if outcomes_by_path.keys().collect::<BTreeSet<_>>()
        != expected.documents.keys().collect::<BTreeSet<_>>()
    {
        return Err(SemanticProviderProtocolError::CoverageMismatch);
    }

    let mut analysis_outcomes_by_id = BTreeMap::new();
    for outcome in analysis_outcomes {
        validate_text("analysis ID", &outcome.analysis_id, 128)?;
        let analysis_id = outcome.analysis_id.clone();
        if analysis_outcomes_by_id
            .insert(analysis_id.clone(), outcome)
            .is_some()
        {
            return Err(SemanticProviderProtocolError::DuplicateAnalysisOutcome(
                analysis_id,
            ));
        }
    }
    if analysis_outcomes_by_id.keys().collect::<BTreeSet<_>>()
        != expected.analyses.keys().collect::<BTreeSet<_>>()
    {
        return Err(SemanticProviderProtocolError::AnalysisCoverageMismatch);
    }

    let mut attachments = attachments.into_iter().map(Some).collect::<Vec<_>>();
    let mut admitted_documents = Vec::with_capacity(expected.documents.len());
    for (path, expected_document) in expected.documents {
        let outcome = outcomes_by_path
            .remove(path)
            .ok_or(SemanticProviderProtocolError::CoverageMismatch)?;
        match outcome {
            ProviderDocumentOutcome::Present {
                document_path,
                language,
                content_identity,
                canonical_document_sha256,
                attachment_index,
            } => {
                if language != expected_document.language
                    || content_identity != expected_document.content_identity
                {
                    return Err(SemanticProviderProtocolError::DocumentIdentityMismatch(
                        document_path,
                    ));
                }
                let index = attachment_index as usize;
                let slot = attachments
                    .get_mut(index)
                    .ok_or(SemanticProviderProtocolError::AttachmentIndexOutOfRange { index })?;
                let bytes = slot
                    .take()
                    .ok_or(SemanticProviderProtocolError::AttachmentReused { index })?;
                if bytes.is_empty() {
                    return Err(SemanticProviderProtocolError::EmptyDocument);
                }
                if !is_sha256(&canonical_document_sha256)
                    || sha256_hex(&bytes) != canonical_document_sha256
                {
                    return Err(SemanticProviderProtocolError::DocumentDigestMismatch);
                }
                admitted_documents.push(AdmittedProviderDocument::Present {
                    document_path,
                    canonical_document: bytes,
                });
            }
            ProviderDocumentOutcome::Omitted {
                document_path,
                language,
                content_identity,
            } => {
                if language != expected_document.language
                    || content_identity != expected_document.content_identity
                {
                    return Err(SemanticProviderProtocolError::DocumentIdentityMismatch(
                        document_path,
                    ));
                }
                admitted_documents.push(AdmittedProviderDocument::Omitted { document_path });
            }
        }
    }
    let mut admitted_analyses = Vec::with_capacity(expected.analyses.len());
    for (analysis_id, expected_analysis) in expected.analyses {
        let outcome = analysis_outcomes_by_id
            .remove(analysis_id)
            .ok_or(SemanticProviderProtocolError::AnalysisCoverageMismatch)?;
        if outcome.schema_version != expected_analysis.schema_version
            || outcome.configuration_id != expected_analysis.configuration_id
            || outcome.language != expected_analysis.language
        {
            return Err(SemanticProviderProtocolError::AnalysisIdentityMismatch(
                analysis_id.clone(),
            ));
        }
        let index = outcome.attachment_index as usize;
        let slot = attachments
            .get_mut(index)
            .ok_or(SemanticProviderProtocolError::AttachmentIndexOutOfRange { index })?;
        let bytes = slot
            .take()
            .ok_or(SemanticProviderProtocolError::AttachmentReused { index })?;
        if bytes.is_empty() {
            return Err(SemanticProviderProtocolError::EmptyAnalysis);
        }
        if !is_sha256(&outcome.canonical_analysis_sha256)
            || sha256_hex(&bytes) != outcome.canonical_analysis_sha256
        {
            return Err(SemanticProviderProtocolError::AnalysisDigestMismatch);
        }
        admitted_analyses.push(AdmittedProviderAnalysis {
            analysis_id: outcome.analysis_id,
            schema_version: outcome.schema_version,
            configuration_id: outcome.configuration_id,
            language: outcome.language,
            canonical_analysis: bytes,
        });
    }
    if attachments.iter().any(Option::is_some) {
        return Err(SemanticProviderProtocolError::UnclaimedAttachment);
    }
    Ok(AdmittedProviderExport {
        documents: admitted_documents,
        analyses: admitted_analyses,
    })
}

fn validate_limits(limits: &ProviderFrameLimits) -> Result<(), SemanticProviderProtocolError> {
    if limits.max_frame_bytes < PROVIDER_FRAME_HEADER_BYTES
        || limits.max_metadata_bytes == 0
        || limits.max_metadata_bytes > limits.max_frame_bytes
        || limits.max_attachments == 0
        || limits.max_attachment_bytes == 0
        || limits.max_total_attachment_bytes == 0
        || limits.max_total_attachment_bytes > limits.max_frame_bytes
        || limits.max_document_paths == 0
        || limits.max_semantic_input_paths == 0
        || limits.max_outstanding_requests == 0
    {
        return Err(SemanticProviderProtocolError::InvalidLimits(
            "frame, metadata, attachment, document, or request bounds are inconsistent".into(),
        ));
    }
    Ok(())
}

pub fn validate_provider_identity(
    identity: &ProviderIdentity,
) -> Result<(), SemanticProviderProtocolError> {
    if identity.protocol != SEMANTIC_PROVIDER_PROTOCOL {
        return Err(SemanticProviderProtocolError::InvalidProviderIdentity(
            "protocol mismatch".into(),
        ));
    }
    for (label, value, max) in [
        ("provider ID", identity.provider_id.as_str(), 128),
        ("language", identity.language.as_str(), 64),
        (
            "implementation version",
            identity.implementation_version.as_str(),
            256,
        ),
    ] {
        validate_text(label, value, max).map_err(|error| {
            SemanticProviderProtocolError::InvalidProviderIdentity(error.to_string())
        })?;
    }
    if identity.source_components.is_empty()
        || identity.source_components.len() > MAX_PROVIDER_RUNTIME_COMPONENTS
        || !is_sha256(&identity.patch_sha256)
        || !is_sha256(&identity.executable_sha256)
    {
        return Err(SemanticProviderProtocolError::InvalidProviderIdentity(
            "source-component count or SHA-256 identity is malformed".into(),
        ));
    }
    for (name, component) in &identity.source_components {
        validate_runtime_component_name(name).map_err(|error| {
            SemanticProviderProtocolError::InvalidProviderIdentity(error.to_string())
        })?;
        validate_text("source component version", &component.version, 128).map_err(|error| {
            SemanticProviderProtocolError::InvalidProviderIdentity(error.to_string())
        })?;
        if !component
            .revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
            || !(7..=128).contains(&component.revision.len())
        {
            return Err(SemanticProviderProtocolError::InvalidProviderIdentity(
                format!("source component `{name}` revision is malformed"),
            ));
        }
    }
    Ok(())
}

fn validate_authority(authority: &ProviderAuthority) -> Result<(), SemanticProviderProtocolError> {
    validate_text("session ID", &authority.session_id, 128)
        .map_err(|error| SemanticProviderProtocolError::InvalidAuthority(error.to_string()))?;
    for digest in [
        &authority.root_sha256,
        &authority.root_topology_sha256,
        &authority.configuration_sha256,
        &authority.population_sha256,
    ] {
        if !is_sha256(digest) {
            return Err(SemanticProviderProtocolError::InvalidAuthority(
                "authority digest is not lowercase SHA-256".into(),
            ));
        }
    }
    if authority
        .workspace_resolution_sha256
        .as_ref()
        .is_some_and(|digest| !is_sha256(digest))
    {
        return Err(SemanticProviderProtocolError::InvalidAuthority(
            "workspace resolution is not lowercase SHA-256".into(),
        ));
    }
    if authority
        .semantic_inputs_sha256
        .as_ref()
        .is_some_and(|digest| !is_sha256(digest))
        || authority.workspace_resolution_sha256.is_some()
            != authority.semantic_inputs_sha256.is_some()
    {
        return Err(SemanticProviderProtocolError::InvalidAuthority(
            "semantic inputs are malformed or not paired with workspace resolution".into(),
        ));
    }
    Ok(())
}

fn validate_text(
    label: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), SemanticProviderProtocolError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(SemanticProviderProtocolError::InvalidAuthority(format!(
            "{label} is empty, oversized, or contains control characters"
        )));
    }
    Ok(())
}

fn validate_document_path(path: &str) -> Result<(), SemanticProviderProtocolError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        Err(SemanticProviderProtocolError::InvalidDocumentPath(
            path.into(),
        ))
    } else {
        Ok(())
    }
}

fn validate_semantic_input_path(path: &str) -> Result<(), SemanticProviderProtocolError> {
    if path == "." {
        Ok(())
    } else {
        validate_document_path(path)
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

/// Reconstruct the canonical semantic-path identity for one regular file from
/// an independently observed raw content digest.
///
/// Inventory owners use this to prove that a captured provider manifest
/// describes the exact bytes already admitted into project topology, without
/// racing a second filesystem read.
pub fn provider_semantic_file_identity_sha256(
    content_sha256: &str,
) -> Result<String, SemanticProviderProtocolError> {
    if !is_sha256(content_sha256) {
        return Err(SemanticProviderProtocolError::InvalidSemanticInputs(
            "semantic file content digest is not canonical SHA-256".into(),
        ));
    }
    let mut content_digest = [0_u8; 32];
    for (index, pair) in content_sha256.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| {
            SemanticProviderProtocolError::InvalidSemanticInputs(
                "semantic file content digest is not canonical SHA-256".into(),
            )
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| {
            SemanticProviderProtocolError::InvalidSemanticInputs(
                "semantic file content digest is not canonical SHA-256".into(),
            )
        })?;
        content_digest[index] = (high << 4) | low;
    }
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, PROVIDER_SEMANTIC_PATH_SCHEMA);
    hash_field(
        &mut hasher,
        ProviderSemanticPathRoot::Repository.digest_label(),
    );
    hash_field(&mut hasher, b"");
    hash_field(&mut hasher, b"");
    hash_field(&mut hasher, b"file");
    hash_field(&mut hasher, &content_digest);
    Ok(hex_digest(&hasher.finalize()))
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn hex_digest(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, SemanticProviderProtocolError> {
    let field = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(SemanticProviderProtocolError::FrameLengthMismatch)?;
    let field: [u8; 4] = field
        .try_into()
        .map_err(|_| SemanticProviderProtocolError::FrameLengthMismatch)?;
    Ok(u32::from_be_bytes(field))
}
