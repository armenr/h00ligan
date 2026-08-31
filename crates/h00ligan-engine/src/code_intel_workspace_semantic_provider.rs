//! Persistent self-contained workspace semantic-provider product boundary.
//!
//! Python and TypeScript own their pinned identities and shared whole-provider
//! policy here. The language-neutral coordinator owns only common
//! process/session transaction state.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use h00ligan_provider_protocol::{
    H00_PYREFLY_IMPLEMENTATION_V1, H00_PYREFLY_LANGUAGE, H00_PYREFLY_PROVIDER_ID,
    H00_TYPESCRIPT_IMPLEMENTATION_V1, H00_TYPESCRIPT_LANGUAGE, H00_TYPESCRIPT_PROVIDER_ID,
    ProviderFrameLimits, ProviderIdentity, ProviderSemanticInputs, ProviderSourceComponent,
    SEMANTIC_PROVIDER_CACHE_DIR_ENV, pyrefly_source_components, sha256_hex,
    typescript_source_components, validate_provider_identity,
};

use crate::code_intel_domain::ProjectInventory;
use crate::code_intel_semantic_provider_coordinator::{
    PersistentSemanticProviderConfig, PersistentSemanticProviderCoordinator,
    SemanticProviderInvalidationScope, SemanticProviderLifecyclePolicy, SemanticProviderPolicy,
    SourceChangedFullCertificationMode, append_authority_field,
};
pub use crate::code_intel_semantic_provider_coordinator::{
    SemanticProviderConfigError, SemanticProviderError,
};
use crate::code_intel_semantic_provider_process::SemanticProviderProcessConfig;
use crate::code_intel_toolchain::{ResolvedToolchain, ToolchainResolver};

const WORKSPACE_PROVIDER_OPEN_SESSION_REUSE_CONTRACT_ID: &str =
    "h00/workspace-provider/open-session-reuse/v1";
const WORKSPACE_PROVIDER_INVOCATION_SCHEMA: &[u8] = b"h00/workspace-provider/invocation/v1\0";
const WORKSPACE_PROVIDER_CONFIGURATION_SCHEMA: &[u8] = b"h00/workspace-provider/configuration/v1\0";
const WORKSPACE_PROVIDER_CACHE_NAMESPACE_SCHEMA: &[u8] =
    b"h00/workspace-provider/cache-namespace/v1\0";

type ProviderSourceComponentsFactory = fn() -> BTreeMap<String, ProviderSourceComponent>;

/// Static identity and inventory policy for a self-contained workspace
/// analyzer. The persistent coordinator consumes this descriptor without
/// learning which language it represents.
#[derive(Debug, Clone, Copy)]
pub(crate) struct WorkspaceSemanticProviderDescriptor {
    pub(crate) language: &'static str,
    ecosystem: &'static str,
    provider_id: &'static str,
    implementation_version: &'static str,
    source_components: ProviderSourceComponentsFactory,
    operation_label: &'static str,
}

pub(crate) const PYREFLY_WORKSPACE_PROVIDER: WorkspaceSemanticProviderDescriptor =
    WorkspaceSemanticProviderDescriptor {
        language: H00_PYREFLY_LANGUAGE,
        ecosystem: "python",
        provider_id: H00_PYREFLY_PROVIDER_ID,
        implementation_version: H00_PYREFLY_IMPLEMENTATION_V1,
        source_components: pyrefly_source_components,
        operation_label: "persistent Pyrefly",
    };

pub(crate) const TYPESCRIPT_WORKSPACE_PROVIDER: WorkspaceSemanticProviderDescriptor =
    WorkspaceSemanticProviderDescriptor {
        language: H00_TYPESCRIPT_LANGUAGE,
        ecosystem: "node",
        provider_id: H00_TYPESCRIPT_PROVIDER_ID,
        implementation_version: H00_TYPESCRIPT_IMPLEMENTATION_V1,
        source_components: typescript_source_components,
        operation_label: "persistent TypeScript native",
    };

#[derive(Debug, Clone, Copy)]
pub struct WorkspaceSemanticProviderPolicy {
    pub(crate) descriptor: WorkspaceSemanticProviderDescriptor,
}

impl WorkspaceSemanticProviderPolicy {
    fn cache_workspace_directory(
        &self,
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
    ) -> Option<PathBuf> {
        let mut namespace = Vec::new();
        append_authority_field(&mut namespace, WORKSPACE_PROVIDER_CACHE_NAMESPACE_SCHEMA);
        append_authority_field(&mut namespace, self.descriptor.language.as_bytes());
        append_authority_field(
            &mut namespace,
            config.expected_identity().executable_sha256.as_bytes(),
        );
        append_authority_field(
            &mut namespace,
            toolchain
                .execution_root
                .to_str()
                .expect("validated UTF-8 execution root")
                .as_bytes(),
        );
        Some(
            config
                .cache_root()?
                .join(self.descriptor.language)
                .join(toolchain.fingerprint_sha256())
                .join("workspaces")
                .join(sha256_hex(&namespace)),
        )
    }
}

impl SemanticProviderPolicy for WorkspaceSemanticProviderPolicy {
    fn language(&self) -> &'static str {
        self.descriptor.language
    }

    fn ecosystem(&self) -> &'static str {
        self.descriptor.ecosystem
    }

    fn operation_label(&self) -> &'static str {
        self.descriptor.operation_label
    }

    fn reuse_contract_id(&self) -> &'static str {
        WORKSPACE_PROVIDER_OPEN_SESSION_REUSE_CONTRACT_ID
    }

    fn invocation_schema(&self) -> &'static [u8] {
        WORKSPACE_PROVIDER_INVOCATION_SCHEMA
    }

    fn configuration_schema(&self) -> &'static [u8] {
        WORKSPACE_PROVIDER_CONFIGURATION_SCHEMA
    }

    fn required_components(&self) -> &'static [&'static str] {
        &[]
    }

    fn configure_process(
        &self,
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
        process: &mut SemanticProviderProcessConfig,
    ) {
        if let Some(cache_directory) = self.cache_workspace_directory(config, toolchain) {
            process.environment.insert(
                SEMANTIC_PROVIDER_CACHE_DIR_ENV.into(),
                cache_directory.into_os_string(),
            );
        }
    }

    fn active_cache_directories(
        &self,
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
    ) -> Vec<PathBuf> {
        self.cache_workspace_directory(config, toolchain)
            .into_iter()
            .collect()
    }

    fn execution_root_inventory_fingerprints(
        &self,
        _repository_root: &Path,
        execution_roots: &[PathBuf],
        _inventory: &ProjectInventory,
        whole_inventory_sha256: &str,
    ) -> Result<BTreeMap<PathBuf, String>, SemanticProviderError> {
        Ok(execution_roots
            .iter()
            .cloned()
            .map(|root| (root, whole_inventory_sha256.to_owned()))
            .collect())
    }

    fn execution_root_semantic_input_paths(
        &self,
        _repository_root: &Path,
        execution_roots: &[PathBuf],
        _inventory: &ProjectInventory,
    ) -> Result<BTreeMap<PathBuf, BTreeSet<String>>, SemanticProviderError> {
        Ok(execution_roots
            .iter()
            .cloned()
            .map(|root| (root, BTreeSet::new()))
            .collect())
    }

    fn reload_sensitive_documents(
        &self,
        _repository_root: &Path,
        _inventory: &ProjectInventory,
    ) -> Result<BTreeSet<String>, SemanticProviderError> {
        Ok(BTreeSet::new())
    }

    fn lifecycle_policy(&self) -> SemanticProviderLifecyclePolicy {
        SemanticProviderLifecyclePolicy::new(
            SourceChangedFullCertificationMode::ApplyToRetainedSessions,
            SemanticProviderInvalidationScope::WholeProvider,
        )
    }

    fn closed_generation_inputs_are_reconstructable(
        &self,
        _repository_root: &Path,
        _inventory: &ProjectInventory,
        _execution_roots: &[PathBuf],
    ) -> bool {
        false
    }

    fn capture_expected_semantic_inputs(
        &self,
        _repository_root: &Path,
        semantic_input_paths: &BTreeSet<String>,
        _provider_environment: &BTreeMap<OsString, OsString>,
        _limits: &ProviderFrameLimits,
        _inventory: &ProjectInventory,
    ) -> Result<Option<ProviderSemanticInputs>, SemanticProviderError> {
        if !semantic_input_paths.is_empty() {
            return Err(SemanticProviderError::InvalidTransition(
                "workspace-provider-client-semantic-input-population",
            ));
        }
        Ok(None)
    }

    fn append_invocation_coordinates(
        &self,
        _material: &mut Vec<u8>,
    ) -> Result<(), SemanticProviderError> {
        Ok(())
    }
}

/// Product-facing configuration for self-contained workspace analyzers.
///
/// Python and TypeScript share this adapter because their lifecycle and
/// authority contract are identical: product-owned analyzer bytes, a managed
/// environment with no required ambient compiler, provider-observed semantic
/// inputs, and conservative whole-inventory session invalidation.
#[derive(Debug, Clone)]
pub struct WorkspaceSemanticProviderConfig {
    binary: PathBuf,
    expected_identity: ProviderIdentity,
    arguments: Vec<OsString>,
    toolchain_resolver: Arc<dyn ToolchainResolver>,
    request_timeout: Duration,
    max_stderr_bytes: usize,
    cache_root: Option<PathBuf>,
    descriptor: WorkspaceSemanticProviderDescriptor,
}

impl WorkspaceSemanticProviderConfig {
    pub fn pyrefly(
        binary: impl Into<PathBuf>,
        expected_identity: ProviderIdentity,
        toolchain_resolver: Arc<dyn ToolchainResolver>,
    ) -> Result<Self, SemanticProviderConfigError> {
        Self::new(
            binary,
            expected_identity,
            toolchain_resolver,
            PYREFLY_WORKSPACE_PROVIDER,
        )
    }

    pub fn typescript_native(
        binary: impl Into<PathBuf>,
        expected_identity: ProviderIdentity,
        toolchain_resolver: Arc<dyn ToolchainResolver>,
    ) -> Result<Self, SemanticProviderConfigError> {
        Self::new(
            binary,
            expected_identity,
            toolchain_resolver,
            TYPESCRIPT_WORKSPACE_PROVIDER,
        )
    }

    fn new(
        binary: impl Into<PathBuf>,
        expected_identity: ProviderIdentity,
        toolchain_resolver: Arc<dyn ToolchainResolver>,
        descriptor: WorkspaceSemanticProviderDescriptor,
    ) -> Result<Self, SemanticProviderConfigError> {
        validate_provider_identity(&expected_identity)
            .map_err(|error| SemanticProviderConfigError::Identity(error.to_string()))?;
        if expected_identity.provider_id != descriptor.provider_id
            || expected_identity.language != descriptor.language
            || expected_identity.implementation_version != descriptor.implementation_version
            || expected_identity.source_components != (descriptor.source_components)()
        {
            return Err(SemanticProviderConfigError::Identity(format!(
                "identity is not the pinned h00ligan {} provider",
                descriptor.language
            )));
        }
        let defaults =
            SemanticProviderProcessConfig::new("", expected_identity.clone(), "0".repeat(64), "");
        Ok(Self {
            binary: binary.into(),
            expected_identity,
            arguments: Vec::new(),
            toolchain_resolver,
            request_timeout: defaults.request_timeout,
            max_stderr_bytes: defaults.max_stderr_bytes,
            cache_root: None,
            descriptor,
        })
    }

    pub const fn arguments_mut(&mut self) -> &mut Vec<OsString> {
        &mut self.arguments
    }

    pub const fn set_request_timeout(&mut self, timeout: Duration) {
        self.request_timeout = timeout;
    }

    pub const fn set_max_stderr_bytes(&mut self, max_stderr_bytes: usize) {
        self.max_stderr_bytes = max_stderr_bytes;
    }

    pub fn bind_cache_root(&mut self, cache_root: &Path) {
        self.cache_root = Some(cache_root.to_path_buf());
    }

    pub const fn language(&self) -> &'static str {
        self.descriptor.language
    }

    pub(crate) fn into_runtime_config(
        self,
    ) -> PersistentSemanticProviderConfig<WorkspaceSemanticProviderPolicy> {
        PersistentSemanticProviderConfig::from_adapter(
            self.binary,
            self.expected_identity,
            self.arguments,
            self.toolchain_resolver,
            self.request_timeout,
            self.max_stderr_bytes,
            self.cache_root,
            WorkspaceSemanticProviderPolicy {
                descriptor: self.descriptor,
            },
        )
    }
}

pub(crate) type WorkspaceSemanticProviderCoordinator =
    PersistentSemanticProviderCoordinator<WorkspaceSemanticProviderPolicy>;

impl PersistentSemanticProviderCoordinator<WorkspaceSemanticProviderPolicy> {
    #[must_use]
    pub fn new(config: WorkspaceSemanticProviderConfig) -> Self {
        Self::from_config(config.into_runtime_config())
    }
}
