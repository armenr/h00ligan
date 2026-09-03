//! Persistent Go semantic-provider product boundary.
//!
//! Go owns its compiler-specific identity, toolchain, cache, inventory,
//! semantic-input, and root-local invalidation policy here. The neutral
//! coordinator owns the shared process/session transaction lifecycle.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use h00ligan_provider_protocol::{
    CALLABLE_LIVENESS_ANALYSIS_ID, CALLABLE_LIVENESS_ANALYSIS_SCHEMA_V1,
    GO_CALLABLE_LIVENESS_CONFIGURATION_V1, GO_PROVIDER_SEMANTIC_ENVIRONMENT,
    H00_GO_IMPLEMENTATION_V4, H00_GO_LANGUAGE, H00_GO_PROVIDER_ID, ProviderAnalysisRequest,
    ProviderFrameLimits, ProviderIdentity, ProviderSemanticInputCoverage, ProviderSemanticInputs,
    ProviderSemanticPathKind, ProviderSemanticPathRoot, RESOLVED_GO_SHA256_ENV,
    capture_provider_semantic_inputs_in_environment, go_provider_source_components,
    provider_semantic_file_identity_sha256, sha256_hex, validate_provider_identity,
};

use crate::code_intel_domain::ProjectInventory;
use crate::code_intel_inventory::{
    go_execution_root_inventory_fingerprints, go_provider_semantic_input_paths,
};
use crate::code_intel_semantic_provider_coordinator::{
    PersistentSemanticProviderConfig, PersistentSemanticProviderCoordinator,
    SemanticProviderInvalidationScope, SemanticProviderLifecyclePolicy, SemanticProviderPolicy,
    SourceChangedFullCertificationMode, append_authority_field, execution_prefix,
};
pub use crate::code_intel_semantic_provider_coordinator::{
    SemanticProviderConfigError, SemanticProviderError,
};
use crate::code_intel_semantic_provider_process::SemanticProviderProcessConfig;
use crate::code_intel_toolchain::{ResolvedToolchain, ToolchainResolver};

pub const GO_OPEN_SESSION_REUSE_CONTRACT_ID: &str = "h00/go/open-session-reuse/v1";
const GO_PROVIDER_INVOCATION_SCHEMA: &[u8] = b"h00/go-provider/invocation/v1\0";
const GO_PROVIDER_CONFIGURATION_SCHEMA: &[u8] = b"h00/go-provider/configuration/v1\0";
const GO_PROVIDER_CACHE_NAMESPACE_SCHEMA: &[u8] = b"h00/go-provider/cache-namespace/v2\0";

fn validate_go_semantic_inputs_against_inventory(
    semantic_inputs: &ProviderSemanticInputs,
    inventory: &ProjectInventory,
) -> Result<(), SemanticProviderError> {
    if semantic_inputs.coverage != ProviderSemanticInputCoverage::Complete
        || !semantic_inputs.issues.is_empty()
    {
        return Err(SemanticProviderError::InvalidTransition(
            "go-semantic-input-coverage",
        ));
    }
    let inventory_inputs = inventory
        .inputs
        .iter()
        .filter(|input| input.language_id.0 == "go" && input.ecosystem_id.0 == "go")
        .map(|input| (input.path.as_str(), input))
        .collect::<BTreeMap<_, _>>();
    for semantic_input in &semantic_inputs.paths {
        if semantic_input.root != ProviderSemanticPathRoot::Repository {
            return Err(SemanticProviderError::Inventory(format!(
                "Go semantic input {:?}:{} is not repository-owned",
                semantic_input.root, semantic_input.path
            )));
        }
        match inventory_inputs.get(semantic_input.path.as_str()) {
            Some(inventory_input) => {
                let expected_identity =
                    provider_semantic_file_identity_sha256(&inventory_input.content_sha256)?;
                if semantic_input.kind != ProviderSemanticPathKind::File
                    || semantic_input.entry_count != 1
                    || semantic_input.identity_sha256 != expected_identity
                {
                    return Err(SemanticProviderError::Inventory(format!(
                        "Go semantic input {} differs from the admitted project inventory",
                        semantic_input.path
                    )));
                }
            }
            None if semantic_input.kind == ProviderSemanticPathKind::Missing => {}
            None => {
                return Err(SemanticProviderError::Inventory(format!(
                    "Go semantic input {} appeared outside the admitted project inventory",
                    semantic_input.path
                )));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub struct GoSemanticProviderPolicy;

impl GoSemanticProviderPolicy {
    fn cache_toolchain_directory(
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
    ) -> Option<PathBuf> {
        Some(
            config
                .cache_root()?
                .join("go")
                .join(toolchain.fingerprint_sha256()),
        )
    }

    fn cache_workspace_directory(
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
    ) -> Option<PathBuf> {
        let mut namespace = Vec::new();
        append_authority_field(&mut namespace, GO_PROVIDER_CACHE_NAMESPACE_SCHEMA);
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
            Self::cache_toolchain_directory(config, toolchain)?
                .join("workspaces")
                .join(sha256_hex(&namespace)),
        )
    }

    fn build_cache_directory(
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
    ) -> Option<PathBuf> {
        Self::cache_toolchain_directory(config, toolchain)
            .map(|directory| directory.join("go-build"))
    }
}

impl SemanticProviderPolicy for GoSemanticProviderPolicy {
    fn language(&self) -> &'static str {
        H00_GO_LANGUAGE
    }

    fn ecosystem(&self) -> &'static str {
        "go"
    }

    fn operation_label(&self) -> &'static str {
        "persistent gopls"
    }

    fn reuse_contract_id(&self) -> &'static str {
        GO_OPEN_SESSION_REUSE_CONTRACT_ID
    }

    fn invocation_schema(&self) -> &'static [u8] {
        GO_PROVIDER_INVOCATION_SCHEMA
    }

    fn configuration_schema(&self) -> &'static [u8] {
        GO_PROVIDER_CONFIGURATION_SCHEMA
    }

    fn required_components(&self) -> &'static [&'static str] {
        &["go"]
    }

    fn requested_analyses(&self) -> Vec<ProviderAnalysisRequest> {
        vec![ProviderAnalysisRequest {
            analysis_id: CALLABLE_LIVENESS_ANALYSIS_ID.into(),
            schema_version: CALLABLE_LIVENESS_ANALYSIS_SCHEMA_V1.into(),
            configuration_id: GO_CALLABLE_LIVENESS_CONFIGURATION_V1.into(),
        }]
    }

    fn configure_process(
        &self,
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
        process: &mut SemanticProviderProcessConfig,
    ) {
        let component = toolchain
            .components
            .get("go")
            .expect("validated Go toolchain contains go");
        process.environment.insert(
            RESOLVED_GO_SHA256_ENV.into(),
            component.executable_sha256.clone().into(),
        );
        if let Some(cache_directory) = Self::cache_workspace_directory(config, toolchain) {
            process.environment.insert(
                "GOPLSCACHE".into(),
                cache_directory.join("gopls").into_os_string(),
            );
        }
        if let Some(build_cache) = Self::build_cache_directory(config, toolchain) {
            process
                .environment
                .insert("GOCACHE".into(), build_cache.into_os_string());
        }
    }

    fn active_cache_directories(
        &self,
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
    ) -> Vec<PathBuf> {
        [
            Self::cache_workspace_directory(config, toolchain),
            Self::build_cache_directory(config, toolchain),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    fn execution_root_inventory_fingerprints(
        &self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        inventory: &ProjectInventory,
        _whole_inventory_sha256: &str,
    ) -> Result<BTreeMap<PathBuf, String>, SemanticProviderError> {
        let roots_by_label = execution_roots
            .iter()
            .map(|root| Ok((execution_prefix(repository_root, root)?, root.clone())))
            .collect::<Result<BTreeMap<_, _>, SemanticProviderError>>()?;
        let expected_roots = roots_by_label.keys().cloned().collect::<BTreeSet<_>>();
        let fingerprints = go_execution_root_inventory_fingerprints(inventory, &expected_roots)
            .ok_or(SemanticProviderError::InvalidTransition(
                "go-execution-root-topology-unpartitionable",
            ))?;
        if fingerprints.len() != execution_roots.len() {
            return Err(SemanticProviderError::InvalidTransition(
                "go-execution-root-topology-population-mismatch",
            ));
        }
        fingerprints
            .into_iter()
            .map(|(label, fingerprint)| {
                roots_by_label
                    .get(&label)
                    .cloned()
                    .map(|root| (root, fingerprint))
                    .ok_or(SemanticProviderError::InvalidTransition(
                        "go-execution-root-topology-owner-missing",
                    ))
            })
            .collect()
    }

    fn execution_root_semantic_input_paths(
        &self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        inventory: &ProjectInventory,
    ) -> Result<BTreeMap<PathBuf, BTreeSet<String>>, SemanticProviderError> {
        let roots_by_label = execution_roots
            .iter()
            .map(|root| Ok((execution_prefix(repository_root, root)?, root.clone())))
            .collect::<Result<BTreeMap<_, _>, SemanticProviderError>>()?;
        let expected_roots = roots_by_label.keys().cloned().collect::<BTreeSet<_>>();
        let paths = go_provider_semantic_input_paths(inventory, &expected_roots).ok_or(
            SemanticProviderError::InvalidTransition(
                "go-semantic-input-population-unpartitionable",
            ),
        )?;
        if paths.len() != execution_roots.len() {
            return Err(SemanticProviderError::InvalidTransition(
                "go-semantic-input-root-population-mismatch",
            ));
        }
        paths
            .into_iter()
            .map(|(label, paths)| {
                roots_by_label
                    .get(&label)
                    .cloned()
                    .map(|root| (root, paths))
                    .ok_or(SemanticProviderError::InvalidTransition(
                        "go-semantic-input-owner-missing",
                    ))
            })
            .collect()
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
            SourceChangedFullCertificationMode::ReplaceSessions,
            SemanticProviderInvalidationScope::ExecutionRootLocal,
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
        repository_root: &Path,
        semantic_input_paths: &BTreeSet<String>,
        provider_environment: &BTreeMap<OsString, OsString>,
        limits: &ProviderFrameLimits,
        inventory: &ProjectInventory,
    ) -> Result<Option<ProviderSemanticInputs>, SemanticProviderError> {
        let environment_names = GO_PROVIDER_SEMANTIC_ENVIRONMENT
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<BTreeSet<_>>();
        let expected = capture_provider_semantic_inputs_in_environment(
            repository_root,
            semantic_input_paths,
            &environment_names,
            provider_environment,
            limits,
        )?;
        validate_go_semantic_inputs_against_inventory(&expected, inventory)?;
        Ok(Some(expected))
    }

    fn append_invocation_coordinates(
        &self,
        _material: &mut Vec<u8>,
    ) -> Result<(), SemanticProviderError> {
        Ok(())
    }
}

/// Exact executable identity and launch policy for Go.
#[derive(Debug, Clone)]
pub struct GoSemanticProviderConfig {
    binary: PathBuf,
    expected_identity: ProviderIdentity,
    arguments: Vec<OsString>,
    toolchain_resolver: Arc<dyn ToolchainResolver>,
    request_timeout: Duration,
    max_stderr_bytes: usize,
    cache_root: Option<PathBuf>,
}

impl GoSemanticProviderConfig {
    pub fn new(
        binary: impl Into<PathBuf>,
        expected_identity: ProviderIdentity,
        toolchain_resolver: Arc<dyn ToolchainResolver>,
    ) -> Result<Self, SemanticProviderConfigError> {
        validate_provider_identity(&expected_identity)
            .map_err(|error| SemanticProviderConfigError::Identity(error.to_string()))?;
        if expected_identity.provider_id != H00_GO_PROVIDER_ID
            || expected_identity.language != H00_GO_LANGUAGE
            || expected_identity.implementation_version != H00_GO_IMPLEMENTATION_V4
            || expected_identity.source_components != go_provider_source_components()
        {
            return Err(SemanticProviderConfigError::Identity(
                "identity is not the pinned h00ligan gopls/scip-go provider".into(),
            ));
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
        H00_GO_LANGUAGE
    }

    pub(crate) fn into_runtime_config(
        self,
    ) -> PersistentSemanticProviderConfig<GoSemanticProviderPolicy> {
        PersistentSemanticProviderConfig::from_adapter(
            self.binary,
            self.expected_identity,
            self.arguments,
            self.toolchain_resolver,
            self.request_timeout,
            self.max_stderr_bytes,
            self.cache_root,
            GoSemanticProviderPolicy,
        )
    }
}

pub(crate) type GoSemanticProviderCoordinator =
    PersistentSemanticProviderCoordinator<GoSemanticProviderPolicy>;

impl PersistentSemanticProviderCoordinator<GoSemanticProviderPolicy> {
    #[must_use]
    pub fn new(config: GoSemanticProviderConfig) -> Self {
        Self::from_config(config.into_runtime_config())
    }
}
