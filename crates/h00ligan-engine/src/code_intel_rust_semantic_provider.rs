//! Persistent Rust semantic-provider product boundary.
//!
//! Rust owns its compiler-specific identity, toolchain, cache, inventory, and
//! invalidation policy here. The language-neutral coordinator owns only
//! process/session reuse, refresh transactions, cancellation, and publication
//! admission.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use h00ligan_provider_protocol::{
    H00_RUST_ANALYZER_IMPLEMENTATION_V5, H00_RUST_ANALYZER_LANGUAGE, H00_RUST_ANALYZER_PROVIDER_ID,
    ProviderFrameLimits, ProviderIdentity, ProviderSemanticInputs, RESOLVED_CARGO_SHA256_ENV,
    RESOLVED_RUSTC_SHA256_ENV, RUST_SEMANTIC_PROFILE_ENV, RustSemanticProfile,
    rust_analyzer_source_components, sha256_hex, validate_provider_identity,
};

use crate::code_intel_cargo::{CargoTargetKind, cargo_package_layout};
use crate::code_intel_domain::{
    DocumentMembershipKind, ProjectInputRole, ProjectInventory, ProjectUnitKind,
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

pub(crate) const RUST_OPEN_SESSION_REUSE_CONTRACT_ID: &str =
    "h00/rust/closed-generation-reconstruction/v2";
const RUST_PROVIDER_INVOCATION_SCHEMA: &[u8] = b"h00/rust-provider/invocation/v1\0";
const RUST_PROVIDER_CONFIGURATION_SCHEMA: &[u8] = b"h00/rust-provider/configuration/v1\0";
const RUST_PROVIDER_CACHE_NAMESPACE_SCHEMA: &[u8] =
    b"h00/rust-provider/compilation-cache-namespace/v1\0";

/// A persisted Cargo workspace resolution is deterministic across processes
/// only when every execution root has an exact dependency lock in the live
/// project inventory. Lockless roots retain the full OpenSession fallback.
pub(crate) fn rust_execution_roots_are_lock_closed(
    repository_root: &Path,
    inventory: &ProjectInventory,
    execution_roots: &[PathBuf],
) -> bool {
    execution_roots.iter().all(|execution_root| {
        let Ok(prefix) = execution_prefix(repository_root, execution_root) else {
            return false;
        };
        let lock_path = if prefix.is_empty() {
            "Cargo.lock".to_owned()
        } else {
            format!("{prefix}/Cargo.lock")
        };
        inventory.inputs.iter().any(|input| {
            input.path == lock_path
                && input.language_id.0 == H00_RUST_ANALYZER_LANGUAGE
                && input.ecosystem_id.0 == "cargo"
                && input.role == ProjectInputRole::DependencyLock
        })
    })
}

/// Cargo build scripts and proc-macro packages contribute semantics outside
/// the ordinary source overlay. Their implementation bytes are therefore
/// provider-session coordinates: changing them requires Cargo reload, build
/// script execution, and proc-macro recompilation before Complete can survive.
pub(crate) fn rust_provider_reload_sensitive_documents(
    repository_root: &Path,
    inventory: &ProjectInventory,
) -> Result<BTreeSet<String>, SemanticProviderError> {
    let mut sensitive = BTreeSet::new();
    for unit in inventory.project_topology.units.iter().filter(|unit| {
        unit.language_id.0 == H00_RUST_ANALYZER_LANGUAGE
            && unit.ecosystem_id.0 == "cargo"
            && unit.kind == ProjectUnitKind::Package
    }) {
        let manifest_path = unit.manifest_path.as_deref().ok_or_else(|| {
            SemanticProviderError::Inventory(format!(
                "Cargo package {} has no manifest path",
                unit.project_unit_id.0
            ))
        })?;
        let manifest_bytes = fs::read(repository_root.join(manifest_path)).map_err(|error| {
            SemanticProviderError::Inventory(format!(
                "read Cargo manifest {manifest_path}: {error}"
            ))
        })?;
        let manifest = toml::from_slice::<toml::Value>(&manifest_bytes).map_err(|error| {
            SemanticProviderError::Inventory(format!(
                "parse Cargo manifest {manifest_path}: {error}"
            ))
        })?;
        let package_root = repository_root.join(&unit.root_path);
        for target in cargo_package_layout(&package_root, &manifest)
            .targets()
            .iter()
            .filter(|target| target.kind == CargoTargetKind::BuildScript)
        {
            let relative = target
                .source_path
                .strip_prefix(repository_root)
                .map_err(|_| {
                    SemanticProviderError::Inventory(format!(
                        "Cargo build script escapes repository root: {}",
                        target.source_path.display()
                    ))
                })?;
            sensitive.insert(relative.to_string_lossy().replace('\\', "/"));
        }
        let proc_macro = manifest
            .get("lib")
            .and_then(|lib| lib.get("proc-macro"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if proc_macro {
            sensitive.extend(
                inventory
                    .project_topology
                    .memberships
                    .iter()
                    .filter(|membership| {
                        membership.project_unit_id == unit.project_unit_id
                            && membership.kind == DocumentMembershipKind::SourceOwner
                    })
                    .map(|membership| membership.document_path.clone()),
            );
        }
    }
    Ok(sensitive)
}

#[derive(Debug, Clone)]
pub struct RustSemanticProviderPolicy {
    pub(crate) semantic_profile: RustSemanticProfile,
}

impl RustSemanticProviderPolicy {
    fn compilation_cache_target_directory(
        &self,
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
    ) -> Option<PathBuf> {
        let cache_root = config.cache_root()?;
        let mut namespace = Vec::new();
        append_authority_field(&mut namespace, RUST_PROVIDER_CACHE_NAMESPACE_SCHEMA);
        append_authority_field(
            &mut namespace,
            self.semantic_profile
                .to_environment_value()
                .expect("validated Rust semantic profile")
                .as_bytes(),
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
            cache_root
                .join("rust")
                .join(toolchain.fingerprint_sha256())
                .join("workspaces")
                .join(sha256_hex(&namespace))
                .join("target"),
        )
    }
}

impl SemanticProviderPolicy for RustSemanticProviderPolicy {
    fn language(&self) -> &'static str {
        H00_RUST_ANALYZER_LANGUAGE
    }

    fn ecosystem(&self) -> &'static str {
        "cargo"
    }

    fn operation_label(&self) -> &'static str {
        "persistent rust-analyzer"
    }

    fn reuse_contract_id(&self) -> &'static str {
        RUST_OPEN_SESSION_REUSE_CONTRACT_ID
    }

    fn invocation_schema(&self) -> &'static [u8] {
        RUST_PROVIDER_INVOCATION_SCHEMA
    }

    fn configuration_schema(&self) -> &'static [u8] {
        RUST_PROVIDER_CONFIGURATION_SCHEMA
    }

    fn required_components(&self) -> &'static [&'static str] {
        &["rustc", "cargo"]
    }

    fn configure_process(
        &self,
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
        process: &mut SemanticProviderProcessConfig,
    ) {
        for (role, environment_name) in [
            ("rustc", RESOLVED_RUSTC_SHA256_ENV),
            ("cargo", RESOLVED_CARGO_SHA256_ENV),
        ] {
            let component = toolchain
                .components
                .get(role)
                .expect("validated Rust toolchain contains rustc and cargo");
            process.environment.insert(
                environment_name.into(),
                component.executable_sha256.clone().into(),
            );
        }
        process.environment.insert(
            RUST_SEMANTIC_PROFILE_ENV.into(),
            self.semantic_profile
                .to_environment_value()
                .expect("validated Rust semantic profile")
                .into(),
        );
        if let Some(target) = self.compilation_cache_target_directory(config, toolchain) {
            process
                .environment
                .insert("CARGO_TARGET_DIR".into(), target.into_os_string());
        }
    }

    fn active_cache_directories(
        &self,
        config: &PersistentSemanticProviderConfig<Self>,
        toolchain: &ResolvedToolchain,
    ) -> Vec<PathBuf> {
        self.compilation_cache_target_directory(config, toolchain)
            .and_then(|target| target.parent().map(Path::to_path_buf))
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
        repository_root: &Path,
        inventory: &ProjectInventory,
    ) -> Result<BTreeSet<String>, SemanticProviderError> {
        rust_provider_reload_sensitive_documents(repository_root, inventory)
    }

    fn lifecycle_policy(&self) -> SemanticProviderLifecyclePolicy {
        SemanticProviderLifecyclePolicy::new(
            SourceChangedFullCertificationMode::ApplyToRetainedSessions,
            SemanticProviderInvalidationScope::WholeProvider,
        )
    }

    fn closed_generation_inputs_are_reconstructable(
        &self,
        repository_root: &Path,
        inventory: &ProjectInventory,
        execution_roots: &[PathBuf],
    ) -> bool {
        rust_execution_roots_are_lock_closed(repository_root, inventory, execution_roots)
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
                "rust-client-semantic-input-population",
            ));
        }
        Ok(None)
    }

    fn append_invocation_coordinates(
        &self,
        material: &mut Vec<u8>,
    ) -> Result<(), SemanticProviderError> {
        append_authority_field(
            material,
            self.semantic_profile.to_environment_value()?.as_bytes(),
        );
        Ok(())
    }
}

/// Exact executable identity and launch policy for Rust.
#[derive(Debug, Clone)]
pub struct RustSemanticProviderConfig {
    pub binary: PathBuf,
    pub expected_identity: ProviderIdentity,
    pub arguments: Vec<OsString>,
    pub toolchain_resolver: Arc<dyn ToolchainResolver>,
    semantic_profile: RustSemanticProfile,
    pub request_timeout: Duration,
    pub max_stderr_bytes: usize,
    cache_root: Option<PathBuf>,
}

impl RustSemanticProviderConfig {
    pub fn new(
        binary: impl Into<PathBuf>,
        expected_identity: ProviderIdentity,
        toolchain_resolver: Arc<dyn ToolchainResolver>,
    ) -> Result<Self, SemanticProviderConfigError> {
        validate_provider_identity(&expected_identity)
            .map_err(|error| SemanticProviderConfigError::Identity(error.to_string()))?;
        if expected_identity.provider_id != H00_RUST_ANALYZER_PROVIDER_ID
            || expected_identity.language != H00_RUST_ANALYZER_LANGUAGE
            || expected_identity.implementation_version != H00_RUST_ANALYZER_IMPLEMENTATION_V5
            || expected_identity.source_components != rust_analyzer_source_components()
        {
            return Err(SemanticProviderConfigError::Identity(
                "identity is not the pinned h00ligan rust-analyzer provider".into(),
            ));
        }
        let defaults =
            SemanticProviderProcessConfig::new("", expected_identity.clone(), "0".repeat(64), "");
        Ok(Self {
            binary: binary.into(),
            expected_identity,
            arguments: Vec::new(),
            toolchain_resolver,
            semantic_profile: RustSemanticProfile::workspace_default(),
            request_timeout: defaults.request_timeout,
            max_stderr_bytes: defaults.max_stderr_bytes,
            cache_root: None,
        })
    }

    pub fn bind_cache_root(&mut self, cache_root: &Path) {
        self.cache_root = Some(cache_root.to_path_buf());
    }

    pub fn set_semantic_profile(
        &mut self,
        profile: RustSemanticProfile,
    ) -> Result<(), SemanticProviderConfigError> {
        profile
            .validate()
            .map_err(|error| SemanticProviderConfigError::Policy(error.to_string()))?;
        self.semantic_profile = profile;
        Ok(())
    }

    #[must_use]
    pub const fn semantic_profile(&self) -> &RustSemanticProfile {
        &self.semantic_profile
    }

    pub const fn language(&self) -> &'static str {
        H00_RUST_ANALYZER_LANGUAGE
    }

    pub(crate) fn into_runtime_config(
        self,
    ) -> PersistentSemanticProviderConfig<RustSemanticProviderPolicy> {
        PersistentSemanticProviderConfig::from_adapter(
            self.binary,
            self.expected_identity,
            self.arguments,
            self.toolchain_resolver,
            self.request_timeout,
            self.max_stderr_bytes,
            self.cache_root,
            RustSemanticProviderPolicy {
                semantic_profile: self.semantic_profile,
            },
        )
    }
}

pub(crate) type RustSemanticProviderCoordinator =
    PersistentSemanticProviderCoordinator<RustSemanticProviderPolicy>;

impl PersistentSemanticProviderCoordinator<RustSemanticProviderPolicy> {
    #[must_use]
    pub fn new(config: RustSemanticProviderConfig) -> Self {
        Self::from_config(config.into_runtime_config())
    }
}
