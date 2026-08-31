//! Product-resolved semantic toolchains.
//!
//! The engine owns the authority shape while product adapters own discovery.
//! Providers therefore receive an explicit, fingerprinted environment instead
//! of consulting ambient process state, and future language integrations can
//! share one lifecycle contract without sharing language-specific resolution.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use futures::future::join_all;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::code_intel_cancellation::IndexCancellation;
use crate::code_intel_domain::{EcosystemId, ProjectInventory, ProjectUnitId};
use crate::code_intel_inventory::{
    semantic_provider_inventory_fingerprint, semantic_provider_unit_execution_roots,
};
use crate::code_intel_payload::{
    ProviderExecutionAuthority, ProviderExecutionRootAuthority, ProviderGenerationReconstruction,
};
use crate::scip_paths::execution_prefix;

const RESOLVED_TOOLCHAIN_SCHEMA: &[u8] = b"h00/resolved-semantic-toolchain/v1\0";
const TOOLCHAIN_PROVIDER_CONFIGURATION_SCHEMA: &[u8] = b"h00/toolchain-provider-configuration/v1\0";
const MAX_VERSION_BYTES: usize = 16 * 1024;
const MAX_ENVIRONMENT_VALUE_BYTES: usize = 1024 * 1024;

pub(crate) const SCIP_GO_REUSE_CONTRACT_ID: &str = "h00/scip-go/toolchain-bound/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolchainOrigin {
    /// Executables and environment observed from the user's captured system.
    System,
    /// Product-managed semantic environment. The analyzer executable is bound
    /// independently by provider identity, so a self-contained provider may
    /// legitimately require no additional executable components.
    Managed,
}

impl ToolchainOrigin {
    const fn label(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Managed => "managed",
        }
    }
}

/// One executable participating in a semantic toolchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedToolchainComponent {
    pub role: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub version: String,
}

impl ResolvedToolchainComponent {
    pub fn new(
        role: impl Into<String>,
        executable: impl Into<PathBuf>,
        executable_sha256: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, ToolchainResolutionError> {
        let component = Self {
            role: role.into(),
            executable: executable.into(),
            executable_sha256: executable_sha256.into(),
            version: version.into(),
        };
        component.validate()?;
        Ok(component)
    }

    fn validate(&self) -> Result<(), ToolchainResolutionError> {
        if self.role.is_empty()
            || !self.role.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
        {
            return Err(ToolchainResolutionError::Invalid(
                "toolchain component role is not a stable lowercase identifier".into(),
            ));
        }
        if !self.executable.is_absolute() || self.executable.to_str().is_none() {
            return Err(ToolchainResolutionError::Invalid(format!(
                "toolchain component {} has no absolute UTF-8 executable path",
                self.role
            )));
        }
        if !is_sha256(&self.executable_sha256) {
            return Err(ToolchainResolutionError::Invalid(format!(
                "toolchain component {} has no exact executable SHA-256",
                self.role
            )));
        }
        let version = self.version.trim();
        if version.is_empty() || version.len() > MAX_VERSION_BYTES || version.contains('\0') {
            return Err(ToolchainResolutionError::Invalid(format!(
                "toolchain component {} has an invalid bounded version report",
                self.role
            )));
        }
        Ok(())
    }
}

/// Exact product-side resolution for one language and execution root.
///
/// `fingerprint_sha256` deliberately excludes `execution_root`: repository and
/// root topology are separate authority coordinates. Two roots using identical
/// tools may therefore share a toolchain identity, while different per-root
/// toolchains remain independently representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedToolchain {
    pub language: String,
    pub execution_root: PathBuf,
    pub origin: ToolchainOrigin,
    pub components: BTreeMap<String, ResolvedToolchainComponent>,
    pub sysroot: Option<PathBuf>,
    pub environment: BTreeMap<String, String>,
    fingerprint_sha256: String,
}

impl ResolvedToolchain {
    pub fn new(
        language: impl Into<String>,
        execution_root: impl Into<PathBuf>,
        origin: ToolchainOrigin,
        components: impl IntoIterator<Item = ResolvedToolchainComponent>,
        sysroot: Option<PathBuf>,
        environment: BTreeMap<String, String>,
    ) -> Result<Self, ToolchainResolutionError> {
        let language = language.into();
        let execution_root = execution_root.into();
        if language.is_empty()
            || !language
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-' || byte == b'_')
        {
            return Err(ToolchainResolutionError::Invalid(
                "toolchain language is not a stable lowercase identifier".into(),
            ));
        }
        if !execution_root.is_absolute() || execution_root.to_str().is_none() {
            return Err(ToolchainResolutionError::Invalid(
                "toolchain execution root is not an absolute UTF-8 path".into(),
            ));
        }
        if sysroot
            .as_ref()
            .is_some_and(|path| !path.is_absolute() || path.to_str().is_none())
        {
            return Err(ToolchainResolutionError::Invalid(
                "toolchain sysroot is not an absolute UTF-8 path".into(),
            ));
        }
        let mut components_by_role = BTreeMap::new();
        for component in components {
            component.validate()?;
            let role = component.role.clone();
            if components_by_role.insert(role.clone(), component).is_some() {
                return Err(ToolchainResolutionError::Invalid(format!(
                    "toolchain component role is duplicated: {role}"
                )));
            }
        }
        if components_by_role.is_empty() && origin == ToolchainOrigin::System {
            return Err(ToolchainResolutionError::Invalid(
                "system-resolved toolchain has no executable components".into(),
            ));
        }
        for (name, value) in &environment {
            if name.is_empty()
                || name.contains(['=', '\0'])
                || value.contains('\0')
                || value.len() > MAX_ENVIRONMENT_VALUE_BYTES
            {
                return Err(ToolchainResolutionError::Invalid(format!(
                    "resolved toolchain environment entry is invalid: {name:?}"
                )));
            }
        }
        let fingerprint_sha256 = fingerprint(
            &language,
            origin,
            &components_by_role,
            sysroot.as_deref(),
            &environment,
        );
        Ok(Self {
            language,
            execution_root,
            origin,
            components: components_by_role,
            sysroot,
            environment,
            fingerprint_sha256,
        })
    }

    #[must_use]
    pub fn fingerprint_sha256(&self) -> &str {
        &self.fingerprint_sha256
    }

    #[must_use]
    pub fn process_environment(&self) -> BTreeMap<OsString, OsString> {
        self.environment
            .iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value)))
            .collect()
    }

    /// Rebind one exact toolchain identity to another canonical execution
    /// root. Root topology is an independent authority coordinate and is
    /// deliberately excluded from `fingerprint_sha256`.
    pub fn rebind_execution_root(
        &self,
        execution_root: impl Into<PathBuf>,
    ) -> Result<Self, ToolchainResolutionError> {
        Self::new(
            self.language.clone(),
            execution_root,
            self.origin,
            self.components.values().cloned(),
            self.sysroot.clone(),
            self.environment.clone(),
        )
    }
}

/// Product-owned discovery boundary. Implementations may resolve a system
/// toolchain today or a verified managed toolchain later; the engine consumes
/// only the exact result.
pub trait ToolchainResolver: std::fmt::Debug + Send + Sync + 'static {
    /// Stable identity of the resolver policy, not of one observed toolchain.
    /// A persisted one-shot authority may be reconstructed only by the exact
    /// policy that defined its executable and environment population.
    fn policy_id(&self, language: &str) -> Result<&'static str, ToolchainResolutionError>;

    fn resolve<'a>(
        &'a self,
        language: &'a str,
        execution_root: &'a Path,
        cancellation: &'a IndexCancellation,
    ) -> Pin<
        Box<dyn Future<Output = Result<ResolvedToolchain, ToolchainResolutionError>> + Send + 'a>,
    >;

    /// Resolve a complete execution-root population. Product adapters may
    /// share root-independent discovery work while returning one exact result
    /// per input root; the default preserves independent per-root resolution.
    fn resolve_population<'a>(
        &'a self,
        language: &'a str,
        execution_roots: &'a [PathBuf],
        cancellation: &'a IndexCancellation,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Vec<ResolvedToolchain>, ToolchainResolutionError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            join_all(
                execution_roots
                    .iter()
                    .map(|execution_root| self.resolve(language, execution_root, cancellation)),
            )
            .await
            .into_iter()
            .collect()
        })
    }
}

pub(crate) struct ToolchainBoundAuthorityInput<'a> {
    pub repository_root: &'a Path,
    pub inventory: &'a ProjectInventory,
    pub language: &'a str,
    pub ecosystem: &'a str,
    pub resolver_policy_id: &'a str,
    pub reuse_contract_id: &'a str,
    pub provider_implementation_sha256: &'a str,
    pub provider_configurations_sha256: &'a BTreeMap<String, String>,
    /// `None` denotes a deterministic one-shot provider. Session providers
    /// supply one exact reconstruction descriptor per execution-root prefix.
    pub reconstruction_descriptors: Option<&'a BTreeMap<String, ProviderGenerationReconstruction>>,
    pub toolchains: &'a BTreeMap<PathBuf, ResolvedToolchain>,
}

/// Bind exact resolved toolchains to the project units governed by each
/// provider execution root. This is provider-neutral persisted authority: the
/// normalizer owns payload shape, while the product resolver owns executable
/// discovery and re-observation.
pub(crate) fn toolchain_bound_execution_authority(
    input: ToolchainBoundAuthorityInput<'_>,
) -> Result<ProviderExecutionAuthority, ToolchainResolutionError> {
    let ToolchainBoundAuthorityInput {
        repository_root,
        inventory,
        language,
        ecosystem,
        resolver_policy_id,
        reuse_contract_id,
        provider_implementation_sha256,
        provider_configurations_sha256,
        reconstruction_descriptors,
        toolchains,
    } = input;
    if resolver_policy_id.is_empty()
        || resolver_policy_id.contains('\0')
        || reuse_contract_id.is_empty()
        || reuse_contract_id.contains('\0')
        || !is_sha256(provider_implementation_sha256)
    {
        return Err(ToolchainResolutionError::Invalid(
            "toolchain resolver policy, reuse contract, or provider identity is invalid".into(),
        ));
    }
    let unit_roots = semantic_provider_unit_execution_roots(inventory, language, ecosystem);
    let mut units_by_root = BTreeMap::<PathBuf, Vec<ProjectUnitId>>::new();
    for (project_unit_id, relative_root) in unit_roots {
        units_by_root
            .entry(repository_root.join(relative_root))
            .or_default()
            .push(project_unit_id);
    }
    if units_by_root.is_empty() || units_by_root.len() != toolchains.len() {
        return Err(ToolchainResolutionError::Invalid(
            "resolved toolchains do not exactly cover semantic execution roots".into(),
        ));
    }

    let mut roots = Vec::with_capacity(units_by_root.len());
    for (execution_root, mut project_unit_ids) in units_by_root {
        let canonical_root = std::fs::canonicalize(&execution_root).map_err(|error| {
            ToolchainResolutionError::Resolution {
                language: language.into(),
                root: execution_root.clone(),
                detail: format!("canonicalize execution root: {error}"),
            }
        })?;
        let Some(toolchain) = toolchains.get(&canonical_root) else {
            return Err(ToolchainResolutionError::Invalid(format!(
                "resolved toolchain is missing for {}",
                canonical_root.display()
            )));
        };
        if toolchain.language != language || toolchain.execution_root != canonical_root {
            return Err(ToolchainResolutionError::Invalid(
                "resolved toolchain language or execution root differs from requested authority"
                    .into(),
            ));
        }
        project_unit_ids.sort();
        project_unit_ids.dedup();
        let prefix = execution_prefix(repository_root, &canonical_root)
            .map_err(|error| ToolchainResolutionError::Invalid(error.to_string()))?;
        let prefix = prefix.to_string_lossy().replace('\\', "/");
        let provider_configuration_sha256 = provider_configurations_sha256
            .get(&prefix)
            .filter(|digest| is_sha256(digest))
            .ok_or_else(|| {
                ToolchainResolutionError::Invalid(format!(
                    "provider configuration is missing or invalid for {prefix:?}"
                ))
            })?;
        let generation_reconstruction = match reconstruction_descriptors {
            Some(descriptors) => descriptors.get(&prefix).cloned().ok_or_else(|| {
                ToolchainResolutionError::Invalid(format!(
                    "provider reconstruction descriptor is missing for {prefix:?}"
                ))
            })?,
            None => ProviderGenerationReconstruction::DeterministicInvocation,
        };
        roots.push(ProviderExecutionRootAuthority {
            execution_root: prefix,
            project_unit_ids,
            toolchain_fingerprint_sha256: toolchain.fingerprint_sha256().into(),
            provider_configuration_sha256: provider_configuration_sha256.clone(),
            generation_reconstruction,
        });
    }
    roots.sort_by(|left, right| left.execution_root.cmp(&right.execution_root));
    if roots.len() != provider_configurations_sha256.len()
        || reconstruction_descriptors.is_some_and(|descriptors| descriptors.len() != roots.len())
    {
        return Err(ToolchainResolutionError::Invalid(
            "provider configurations or reconstruction descriptors do not exactly cover execution roots"
                .into(),
        ));
    }
    let provider_inventory_sha256 =
        semantic_provider_inventory_fingerprint(inventory, language, ecosystem)
            .map_err(|error| ToolchainResolutionError::Invalid(error.to_string()))?;
    Ok(ProviderExecutionAuthority::ToolchainBound {
        resolver_policy_id: resolver_policy_id.into(),
        ecosystem_id: EcosystemId::new(ecosystem),
        reuse_contract_id: reuse_contract_id.into(),
        provider_implementation_sha256: provider_implementation_sha256.into(),
        provider_inventory_sha256,
        roots,
    })
}

/// Require one exact provider executable across a composed toolchain
/// population and return its byte identity.
pub(crate) fn toolchain_provider_implementation_sha256(
    toolchains: &BTreeMap<PathBuf, ResolvedToolchain>,
    component_role: &str,
) -> Result<String, ToolchainResolutionError> {
    let mut identity = None;
    for toolchain in toolchains.values() {
        let component = toolchain.components.get(component_role).ok_or_else(|| {
            ToolchainResolutionError::Invalid(format!(
                "toolchain has no {component_role} provider component"
            ))
        })?;
        if identity
            .as_ref()
            .is_some_and(|current| current != &component.executable_sha256)
        {
            return Err(ToolchainResolutionError::Invalid(format!(
                "toolchain roots resolve different {component_role} provider executables"
            )));
        }
        identity.get_or_insert_with(|| component.executable_sha256.clone());
    }
    identity.ok_or_else(|| {
        ToolchainResolutionError::Invalid("toolchain provider population is empty".into())
    })
}

/// Bind the exact provider invocation contract to each resolved toolchain.
/// The contract ID must be bumped whenever product-owned arguments or
/// environment semantics change.
pub(crate) fn toolchain_provider_configuration_population(
    repository_root: &Path,
    reuse_contract_id: &str,
    toolchains: &BTreeMap<PathBuf, ResolvedToolchain>,
) -> Result<BTreeMap<String, String>, ToolchainResolutionError> {
    if reuse_contract_id.is_empty() || reuse_contract_id.contains('\0') {
        return Err(ToolchainResolutionError::Invalid(
            "toolchain provider reuse contract is invalid".into(),
        ));
    }
    let mut configurations = BTreeMap::new();
    for (execution_root, toolchain) in toolchains {
        let prefix = execution_prefix(repository_root, execution_root)
            .map_err(|error| ToolchainResolutionError::Invalid(error.to_string()))?
            .to_string_lossy()
            .replace('\\', "/");
        let digest = toolchain_provider_configuration_sha256(
            reuse_contract_id,
            toolchain.fingerprint_sha256(),
        );
        if configurations.insert(prefix, digest).is_some() {
            return Err(ToolchainResolutionError::Invalid(
                "toolchain provider configuration roots are not unique".into(),
            ));
        }
    }
    Ok(configurations)
}

pub(crate) fn toolchain_provider_configuration_sha256(
    reuse_contract_id: &str,
    toolchain_fingerprint_sha256: &str,
) -> String {
    assert!(
        !reuse_contract_id.is_empty()
            && !reuse_contract_id.contains('\0')
            && is_sha256(toolchain_fingerprint_sha256),
        "toolchain provider configuration requires validated coordinates"
    );
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, TOOLCHAIN_PROVIDER_CONFIGURATION_SCHEMA);
    hash_field(&mut hasher, reuse_contract_id.as_bytes());
    hash_field(&mut hasher, toolchain_fingerprint_sha256.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Resolve one language's complete execution-root population concurrently and
/// reject missing, duplicated, or retargeted results as a unit.
pub(crate) async fn resolve_toolchain_population(
    resolver: Option<&Arc<dyn ToolchainResolver>>,
    language: &str,
    execution_roots: &[PathBuf],
    cancellation: &IndexCancellation,
) -> Result<BTreeMap<PathBuf, ResolvedToolchain>, ToolchainResolutionError> {
    let Some(resolver) = resolver else {
        return Err(ToolchainResolutionError::Resolution {
            language: language.into(),
            root: execution_roots.first().cloned().unwrap_or_default(),
            detail: "product runtime did not supply a semantic toolchain resolver".into(),
        });
    };
    let resolutions = resolver
        .resolve_population(language, execution_roots, cancellation)
        .await?;
    if resolutions.len() != execution_roots.len() {
        return Err(ToolchainResolutionError::Invalid(
            "resolver returned a different toolchain population cardinality".into(),
        ));
    }
    let mut resolved = BTreeMap::new();
    for (requested_root, toolchain) in execution_roots.iter().zip(resolutions) {
        let canonical_requested = std::fs::canonicalize(requested_root).map_err(|error| {
            ToolchainResolutionError::Resolution {
                language: language.into(),
                root: requested_root.clone(),
                detail: format!("canonicalize requested execution root: {error}"),
            }
        })?;
        if toolchain.language != language || toolchain.execution_root != canonical_requested {
            return Err(ToolchainResolutionError::Invalid(
                "resolver returned a toolchain for a different language or execution root".into(),
            ));
        }
        if resolved.insert(canonical_requested, toolchain).is_some() {
            return Err(ToolchainResolutionError::Invalid(
                "provider execution roots are not canonically unique".into(),
            ));
        }
    }
    Ok(resolved)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ToolchainResolutionError {
    #[error("semantic toolchain resolution was cancelled")]
    Cancelled,
    #[error("semantic toolchain language is unsupported: {0}")]
    UnsupportedLanguage(String),
    #[error("semantic toolchain resolution is invalid: {0}")]
    Invalid(String),
    #[error("semantic toolchain resolution failed for {language} at {root}: {detail}")]
    Resolution {
        language: String,
        root: PathBuf,
        detail: String,
    },
}

/// Deterministic resolver shared by engine unit tests. Production discovery
/// belongs to the embedding product, so engine tests inject an exact result
/// instead of consulting whichever toolchain happens to run the test suite.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub(crate) struct TestToolchainResolver {
    environment: BTreeMap<String, String>,
    components: Option<Vec<ResolvedToolchainComponent>>,
}

#[cfg(test)]
impl TestToolchainResolver {
    pub(crate) fn new(environment: BTreeMap<String, String>) -> Self {
        Self {
            environment,
            components: None,
        }
    }

    pub(crate) fn from_current_process(names: &[&str]) -> Self {
        let environment = names
            .iter()
            .filter_map(|name| {
                std::env::var_os(name)
                    .and_then(|value| value.into_string().ok())
                    .map(|value| ((*name).to_owned(), value))
            })
            .collect();
        Self::new(environment)
    }

    #[must_use]
    pub(crate) fn with_environment(mut self, name: &str, value: &str) -> Self {
        self.environment.insert(name.into(), value.into());
        self
    }

    /// Bind the real installed Rust programs for tests that launch the real
    /// provider. Ordinary engine tests retain deterministic fake components;
    /// installed-boundary tests must model the production resolver's exact
    /// executable paths, byte identities, and environment bindings.
    pub(crate) fn with_installed_rust_programs(mut self) -> Self {
        let components = [("cargo", "CARGO"), ("rustc", "RUSTC")]
            .into_iter()
            .map(|(role, environment_name)| {
                let executable = test_runtime_program(environment_name, role);
                let bytes = std::fs::read(&executable).unwrap_or_else(|error| {
                    panic!("read installed {role} test executable: {error}")
                });
                let digest = Sha256::digest(&bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let output = std::process::Command::new(&executable)
                    .arg("--version")
                    .output()
                    .unwrap_or_else(|error| panic!("run installed {role} --version: {error}"));
                assert!(
                    output.status.success(),
                    "installed {role} --version failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let version = String::from_utf8(output.stdout).unwrap_or_else(|error| {
                    panic!("installed {role} version is not UTF-8: {error}")
                });
                self.environment.insert(
                    environment_name.into(),
                    executable
                        .to_str()
                        .unwrap_or_else(|| panic!("installed {role} path is not UTF-8"))
                        .into(),
                );
                ResolvedToolchainComponent::new(role, executable, digest, version)
                    .unwrap_or_else(|error| panic!("installed {role} component: {error}"))
            })
            .collect();
        self.components = Some(components);
        self
    }
}

#[cfg(test)]
fn test_runtime_program(environment_name: &str, default: &str) -> PathBuf {
    let requested = std::env::var_os(environment_name).unwrap_or_else(|| default.into());
    let requested = Path::new(&requested);
    if requested.components().count() > 1 {
        return if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            std::env::current_dir()
                .expect("current test directory")
                .join(requested)
        };
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join(requested))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{default} in installed test PATH"))
}

#[cfg(test)]
impl ToolchainResolver for TestToolchainResolver {
    fn policy_id(&self, language: &str) -> Result<&'static str, ToolchainResolutionError> {
        if language == "rust" {
            Ok("h00/test-semantic-toolchain/v1")
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
    ) -> Pin<
        Box<dyn Future<Output = Result<ResolvedToolchain, ToolchainResolutionError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(ToolchainResolutionError::Cancelled);
            }
            if language != "rust" {
                return Err(ToolchainResolutionError::UnsupportedLanguage(
                    language.into(),
                ));
            }
            let executable =
                std::env::current_exe().map_err(|error| ToolchainResolutionError::Resolution {
                    language: language.into(),
                    root: execution_root.to_path_buf(),
                    detail: format!("resolve current test executable: {error}"),
                })?;
            let components = self.components.clone().unwrap_or_else(|| {
                vec![
                    ResolvedToolchainComponent::new(
                        "cargo",
                        &executable,
                        "a".repeat(64),
                        "cargo test fixture",
                    )
                    .expect("deterministic test cargo component"),
                    ResolvedToolchainComponent::new(
                        "rustc",
                        executable,
                        "b".repeat(64),
                        "rustc test fixture",
                    )
                    .expect("deterministic test rustc component"),
                ]
            });
            ResolvedToolchain::new(
                language,
                execution_root,
                ToolchainOrigin::System,
                components,
                None,
                self.environment.clone(),
            )
        })
    }
}

fn fingerprint(
    language: &str,
    origin: ToolchainOrigin,
    components: &BTreeMap<String, ResolvedToolchainComponent>,
    sysroot: Option<&Path>,
    environment: &BTreeMap<String, String>,
) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, RESOLVED_TOOLCHAIN_SCHEMA);
    hash_field(&mut hasher, language.as_bytes());
    hash_field(&mut hasher, origin.label().as_bytes());
    for (role, component) in components {
        hash_field(&mut hasher, role.as_bytes());
        hash_field(
            &mut hasher,
            component
                .executable
                .to_str()
                .expect("validated UTF-8 executable")
                .as_bytes(),
        );
        hash_field(&mut hasher, component.executable_sha256.as_bytes());
        hash_field(&mut hasher, component.version.trim().as_bytes());
    }
    hash_field(
        &mut hasher,
        sysroot
            .and_then(Path::to_str)
            .unwrap_or("no-semantic-toolchain-sysroot")
            .as_bytes(),
    );
    for (name, value) in environment {
        hash_field(&mut hasher, name.as_bytes());
        hash_field(&mut hasher, value.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct EmptyPopulationResolver;

    impl ToolchainResolver for EmptyPopulationResolver {
        fn policy_id(&self, _language: &str) -> Result<&'static str, ToolchainResolutionError> {
            Ok("h00/test-empty-population/v1")
        }

        fn resolve<'a>(
            &'a self,
            _language: &'a str,
            _execution_root: &'a Path,
            _cancellation: &'a IndexCancellation,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<ResolvedToolchain, ToolchainResolutionError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async {
                Err(ToolchainResolutionError::Invalid(
                    "single-root resolution must not be reached".into(),
                ))
            })
        }

        fn resolve_population<'a>(
            &'a self,
            _language: &'a str,
            _execution_roots: &'a [PathBuf],
            _cancellation: &'a IndexCancellation,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<Vec<ResolvedToolchain>, ToolchainResolutionError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    fn component(
        role: &str,
        path: &str,
        digest: char,
        version: &str,
    ) -> ResolvedToolchainComponent {
        ResolvedToolchainComponent::new(
            role,
            PathBuf::from(path),
            std::iter::repeat_n(digest, 64).collect::<String>(),
            version,
        )
        .expect("valid component")
    }

    fn resolved(cargo_digest: char, environment: BTreeMap<String, String>) -> ResolvedToolchain {
        ResolvedToolchain::new(
            "rust",
            "/repo/member",
            ToolchainOrigin::System,
            [
                component("cargo", "/tools/bin/cargo", cargo_digest, "cargo 1.97.1"),
                component("rustc", "/tools/bin/rustc", 'b', "rustc 1.97.1"),
            ],
            Some(PathBuf::from("/tools")),
            environment,
        )
        .expect("resolved toolchain")
    }

    #[test]
    fn fingerprint_binds_executables_versions_sysroot_environment_and_origin_not_root() {
        let baseline = resolved('a', BTreeMap::from([("PATH".into(), "/tools/bin".into())]));
        let same_at_another_root = ResolvedToolchain::new(
            "rust",
            "/repo/other-member",
            ToolchainOrigin::System,
            baseline.components.values().cloned(),
            baseline.sysroot.clone(),
            baseline.environment.clone(),
        )
        .expect("same toolchain at another root");
        assert_eq!(
            baseline.fingerprint_sha256(),
            same_at_another_root.fingerprint_sha256(),
            "repository topology, not the toolchain fingerprint, owns root identity"
        );

        let changed_binary = resolved('c', BTreeMap::from([("PATH".into(), "/tools/bin".into())]));
        let changed_environment =
            resolved('a', BTreeMap::from([("PATH".into(), "/other/bin".into())]));
        assert_ne!(
            baseline.fingerprint_sha256(),
            changed_binary.fingerprint_sha256()
        );
        assert_ne!(
            baseline.fingerprint_sha256(),
            changed_environment.fingerprint_sha256()
        );
    }

    #[tokio::test]
    async fn population_cardinality_mismatch_is_rejected_before_authority() {
        let temporary = tempfile::TempDir::new().expect("toolchain population scratch");
        let root = temporary.path().join("repo");
        std::fs::create_dir_all(&root).expect("execution root");
        let resolver: Arc<dyn ToolchainResolver> = Arc::new(EmptyPopulationResolver);
        let error =
            resolve_toolchain_population(Some(&resolver), "go", &[root], &IndexCancellation::new())
                .await
                .expect_err("an incomplete population cannot grant authority");
        assert!(
            matches!(error, ToolchainResolutionError::Invalid(detail) if detail.contains("cardinality"))
        );
    }

    #[test]
    fn invalid_or_duplicate_components_never_form_authority() {
        let exact = component("rustc", "/tools/bin/rustc", 'a', "rustc 1.97.1");
        assert!(
            ResolvedToolchain::new(
                "rust",
                "/repo",
                ToolchainOrigin::System,
                [exact.clone(), exact],
                None,
                BTreeMap::new(),
            )
            .is_err()
        );
        assert!(ResolvedToolchainComponent::new("Rust C", "relative/rustc", "bad", "").is_err());
    }

    /// FALSIFIER: a provider that embeds its own analyzer has no external
    /// compiler/runtime executable to discover. Its independently bound
    /// provider identity plus this managed environment are sufficient
    /// authority; ambient/system discovery must still prove a component.
    #[test]
    fn managed_self_contained_environment_needs_no_external_component() {
        let managed = ResolvedToolchain::new(
            "typescript",
            "/repo",
            ToolchainOrigin::Managed,
            [],
            None,
            BTreeMap::from([("TMPDIR".into(), "/tmp".into())]),
        )
        .expect("self-contained managed semantic environment");
        assert!(managed.components.is_empty(), "positive empty population");
        assert!(
            ResolvedToolchain::new(
                "typescript",
                "/repo",
                ToolchainOrigin::System,
                [],
                None,
                BTreeMap::new(),
            )
            .is_err(),
            "ambient authority still requires at least one executable witness"
        );
    }
}
