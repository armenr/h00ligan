//! Product-owned runtime assembly for h00ligan adapters.
//!
//! The engine owns provider/process semantics, while the shipped executable
//! owns how those capabilities are assembled. Keeping that choice here stops
//! h00ligan-engine from discovering adjacent installation files or depending on a
//! particular packaging layout.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use h00ligan_engine::code_intel_semantic_provider_registry::{
    SemanticProviderConfig, SemanticProviderRegistryError,
};
use h00ligan_engine::code_intel_supervisor::IndexSupervisor;
use h00ligan_engine::code_intel_toolchain::{ToolchainResolutionError, ToolchainResolver};
use h00ligan_engine::project_binding::{PROVIDER_CACHE_DIRECTORY, ProjectBinding};
use h00ligan_provider_protocol::ProviderIdentity;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

pub const INTERNAL_RUST_PROVIDER_ARGUMENT: &str = "__h00-internal-rust-provider";

#[derive(Debug, Error)]
pub enum LiganRuntimeError {
    #[error("cannot resolve the current h00ligan executable: {0}")]
    CurrentExecutable(String),
    #[error("semantic-provider configuration is invalid: {0}")]
    ProviderConfig(String),
    #[error(transparent)]
    Toolchain(#[from] ToolchainResolutionError),
    #[error(transparent)]
    ProviderRegistry(#[from] SemanticProviderRegistryError),
    #[error("embedded semantic provider is invalid: {0}")]
    EmbeddedProvider(String),
    #[error("semantic-provider product for language '{0}' is configured more than once")]
    DuplicateProductProvider(String),
}

#[derive(Clone)]
struct EmbeddedProvider {
    bytes: Arc<[u8]>,
    identity: ProviderIdentity,
    executable_name: &'static str,
    config_factory: SemanticProviderConfigFactory,
}

#[derive(Clone)]
enum SemanticProviderProduct {
    Configured(SemanticProviderConfig),
    Embedded(EmbeddedProvider),
}

pub type SemanticProviderConfigFactory = fn(
    PathBuf,
    ProviderIdentity,
    Arc<dyn ToolchainResolver>,
) -> Result<SemanticProviderConfig, String>;

pub(crate) enum SemanticProviderExecutableSpec {
    SameExecutable {
        argument: &'static str,
    },
    Embedded {
        bytes: &'static [u8],
        executable_name: &'static str,
    },
}

pub(crate) struct SemanticProviderProductSpec {
    pub(crate) identity: ProviderIdentity,
    pub(crate) executable: SemanticProviderExecutableSpec,
    pub(crate) config_factory: SemanticProviderConfigFactory,
}

/// Immutable product capabilities injected into every CLI/MCP/WATCH adapter.
#[derive(Clone)]
pub struct LiganRuntime {
    semantic_provider_products: Vec<SemanticProviderProduct>,
    toolchain_resolver: Option<Arc<dyn ToolchainResolver>>,
}

impl LiganRuntime {
    /// Assemble the ordinary CLI/MCP/WATCH runtime with exact installed
    /// one-shot provider discovery.
    pub fn with_system_toolchains() -> Result<Self, LiganRuntimeError> {
        Ok(Self {
            semantic_provider_products: Vec::new(),
            toolchain_resolver: Some(Arc::new(
                crate::toolchain::SystemToolchainResolver::capture()?,
            )),
        })
    }

    /// Assemble one product-owned persistent-provider collection. An embedded
    /// helper is materialized privately and content-verified; a same-executable
    /// provider receives only the exact hidden dispatch argument.
    pub(crate) fn with_semantic_provider_products(
        products: Vec<SemanticProviderProductSpec>,
    ) -> Result<Self, LiganRuntimeError> {
        let executable = std::env::current_exe()
            .map_err(|error| LiganRuntimeError::CurrentExecutable(error.to_string()))?;
        let toolchain_resolver: Arc<dyn ToolchainResolver> =
            Arc::new(crate::toolchain::SystemToolchainResolver::capture_for_provider_products()?);
        let mut languages = BTreeSet::new();
        let mut semantic_provider_products = Vec::with_capacity(products.len());
        for product in products {
            let language = product.identity.language.clone();
            if !languages.insert(language.clone()) {
                return Err(LiganRuntimeError::DuplicateProductProvider(language));
            }
            match product.executable {
                SemanticProviderExecutableSpec::SameExecutable { argument } => {
                    let mut provider = (product.config_factory)(
                        executable.clone(),
                        product.identity,
                        Arc::clone(&toolchain_resolver),
                    )
                    .map_err(LiganRuntimeError::ProviderConfig)?;
                    provider.set_arguments(vec![OsString::from(argument)]);
                    semantic_provider_products.push(SemanticProviderProduct::Configured(provider));
                }
                SemanticProviderExecutableSpec::Embedded {
                    bytes,
                    executable_name,
                } => {
                    semantic_provider_products.push(SemanticProviderProduct::Embedded(
                        EmbeddedProvider {
                            bytes: Arc::from(bytes),
                            identity: product.identity,
                            executable_name,
                            config_factory: product.config_factory,
                        },
                    ));
                }
            }
        }
        Ok(Self {
            semantic_provider_products,
            toolchain_resolver: Some(toolchain_resolver),
        })
    }

    /// Build one supervisor from this product's explicit provider policy.
    pub fn supervisor(
        &self,
        binding: &ProjectBinding,
    ) -> Result<Arc<IndexSupervisor>, LiganRuntimeError> {
        let mut providers = Vec::with_capacity(self.semantic_provider_products.len());
        for product in &self.semantic_provider_products {
            match product {
                SemanticProviderProduct::Configured(config) => providers.push(config.clone()),
                SemanticProviderProduct::Embedded(embedded) => {
                    let binary = materialize_embedded_provider(binding, embedded)?;
                    let resolver = self.toolchain_resolver.as_ref().ok_or_else(|| {
                        LiganRuntimeError::EmbeddedProvider(
                            "embedded provider has no product toolchain resolver".into(),
                        )
                    })?;
                    providers.push(
                        (embedded.config_factory)(
                            binary,
                            embedded.identity.clone(),
                            Arc::clone(resolver),
                        )
                        .map_err(LiganRuntimeError::ProviderConfig)?,
                    );
                }
            }
        }
        let cache_root = binding.graph_dir().join(PROVIDER_CACHE_DIRECTORY);
        for provider in &mut providers {
            provider.bind_cache_root(&cache_root);
        }

        let supervisor = if providers.is_empty() {
            self.toolchain_resolver.as_ref().map_or_else(
                || IndexSupervisor::new(binding.clone()),
                |resolver| {
                    IndexSupervisor::with_toolchain_resolver(binding.clone(), Arc::clone(resolver))
                },
            )
        } else {
            IndexSupervisor::with_semantic_providers(
                binding.clone(),
                providers,
                self.toolchain_resolver.clone(),
            )?
        };
        Ok(Arc::new(supervisor))
    }
}

impl Default for LiganRuntime {
    fn default() -> Self {
        Self::with_system_toolchains().unwrap_or(Self {
            semantic_provider_products: Vec::new(),
            toolchain_resolver: None,
        })
    }
}

fn materialize_embedded_provider(
    binding: &ProjectBinding,
    embedded: &EmbeddedProvider,
) -> Result<PathBuf, LiganRuntimeError> {
    validate_provider_executable_name(embedded.executable_name)?;
    let digest = sha256_bytes(&embedded.bytes);
    if digest != embedded.identity.executable_sha256 {
        return Err(LiganRuntimeError::EmbeddedProvider(
            "embedded provider bytes changed after runtime construction".into(),
        ));
    }
    fs::create_dir_all(binding.graph_dir()).map_err(|error| {
        LiganRuntimeError::EmbeddedProvider(format!(
            "create selected graph directory {}: {error}",
            binding.graph_dir().display()
        ))
    })?;
    require_real_directory(binding.graph_dir())?;
    let provider_cache = binding.graph_dir().join(PROVIDER_CACHE_DIRECTORY);
    create_owned_real_directory(&provider_cache)?;
    let executable_cache = provider_cache.join("executables");
    create_owned_real_directory(&executable_cache)?;
    let cache_root = executable_cache.join(&digest);
    create_owned_real_directory(&cache_root)?;

    let binary = cache_root.join(embedded.executable_name);
    if binary.exists() {
        validate_materialized_binary(&binary, &digest)?;
        return Ok(binary);
    }

    let mut temporary = None;
    for attempt in 0..64u32 {
        let candidate = cache_root.join(format!(
            ".{}.{}.{}.tmp",
            embedded.executable_name,
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temporary = Some((candidate, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(LiganRuntimeError::EmbeddedProvider(format!(
                    "create private provider candidate: {error}"
                )));
            }
        }
    }
    let (temporary_path, mut temporary_file) = temporary.ok_or_else(|| {
        LiganRuntimeError::EmbeddedProvider(
            "cannot allocate a private provider candidate after 64 attempts".into(),
        )
    })?;
    let write_result = (|| -> Result<(), LiganRuntimeError> {
        temporary_file.write_all(&embedded.bytes).map_err(|error| {
            LiganRuntimeError::EmbeddedProvider(format!("write embedded provider: {error}"))
        })?;
        temporary_file.sync_all().map_err(|error| {
            LiganRuntimeError::EmbeddedProvider(format!("sync embedded provider: {error}"))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            temporary_file
                .set_permissions(fs::Permissions::from_mode(0o700))
                .map_err(|error| {
                    LiganRuntimeError::EmbeddedProvider(format!(
                        "set private provider permissions: {error}"
                    ))
                })?;
        }
        drop(temporary_file);
        match fs::hard_link(&temporary_path, &binary) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(error) => Err(LiganRuntimeError::EmbeddedProvider(format!(
                "publish private provider without overwrite: {error}"
            ))),
        }
    })();
    let _ = fs::remove_file(&temporary_path);
    write_result?;
    validate_materialized_binary(&binary, &digest)?;
    Ok(binary)
}

fn validate_provider_executable_name(name: &str) -> Result<(), LiganRuntimeError> {
    if name.is_empty()
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(LiganRuntimeError::EmbeddedProvider(format!(
            "provider executable name is not one safe portable path component: {name:?}"
        )));
    }
    Ok(())
}

fn require_real_directory(path: &std::path::Path) -> Result<(), LiganRuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LiganRuntimeError::EmbeddedProvider(format!(
            "inspect private provider directory {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(LiganRuntimeError::EmbeddedProvider(format!(
            "private provider directory is not a real directory: {}",
            path.display()
        )));
    }
    Ok(())
}

fn create_owned_real_directory(path: &std::path::Path) -> Result<(), LiganRuntimeError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => {
            return Err(LiganRuntimeError::EmbeddedProvider(format!(
                "create private provider cache component {}: {error}",
                path.display()
            )));
        }
    }
    require_real_directory(path)
}

fn validate_materialized_binary(
    path: &std::path::Path,
    expected_sha256: &str,
) -> Result<(), LiganRuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        LiganRuntimeError::EmbeddedProvider(format!(
            "inspect materialized provider {}: {error}",
            path.display()
        ))
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(LiganRuntimeError::EmbeddedProvider(format!(
            "materialized provider is not a real regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o100 == 0 {
            return Err(LiganRuntimeError::EmbeddedProvider(format!(
                "materialized provider is not owner-executable: {}",
                path.display()
            )));
        }
    }
    let bytes = fs::read(path).map_err(|error| {
        LiganRuntimeError::EmbeddedProvider(format!(
            "read materialized provider {}: {error}",
            path.display()
        ))
    })?;
    let observed = sha256_bytes(&bytes);
    if observed != expected_sha256 {
        return Err(LiganRuntimeError::EmbeddedProvider(format!(
            "materialized provider SHA-256 mismatch: expected {expected_sha256}, observed {observed}"
        )));
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::sync::{Arc, Barrier};

    use h00ligan_provider_protocol::{
        H00_GO_PROVIDER_ID, SEMANTIC_PROVIDER_PROTOCOL, go_provider_source_components,
    };
    use tempfile::TempDir;

    use super::*;

    fn fixture_config_factory(
        _binary: PathBuf,
        _identity: ProviderIdentity,
        _resolver: Arc<dyn ToolchainResolver>,
    ) -> Result<SemanticProviderConfig, String> {
        panic!("materialization fixture must not construct an adapter")
    }

    fn fixture() -> EmbeddedProvider {
        let bytes = Arc::<[u8]>::from(b"fixture embedded Go provider\n".as_slice());
        EmbeddedProvider {
            identity: ProviderIdentity {
                protocol: SEMANTIC_PROVIDER_PROTOCOL.into(),
                provider_id: H00_GO_PROVIDER_ID.into(),
                language: "go".into(),
                implementation_version: "fixture-v1".into(),
                source_components: go_provider_source_components(),
                patch_sha256: sha256_bytes(b"fixture patch"),
                executable_sha256: sha256_bytes(&bytes),
            },
            bytes,
            executable_name: "h00-go-semantic-provider",
            config_factory: fixture_config_factory,
        }
    }

    fn binding(temporary: &TempDir) -> ProjectBinding {
        let root = temporary.path().join("repo");
        std::fs::create_dir_all(&root).expect("fixture repository");
        ProjectBinding::explicit(&root, &temporary.path().join("data"))
            .expect("explicit fixture binding")
    }

    fn binary_path(binding: &ProjectBinding, embedded: &EmbeddedProvider) -> PathBuf {
        binding
            .graph_dir()
            .join(PROVIDER_CACHE_DIRECTORY)
            .join("executables")
            .join(&embedded.identity.executable_sha256)
            .join(embedded.executable_name)
    }

    #[test]
    fn embedded_provider_materializes_exact_private_bytes() {
        let temporary = TempDir::new().expect("temporary workspace");
        let binding = binding(&temporary);
        let embedded = fixture();

        let binary = materialize_embedded_provider(&binding, &embedded)
            .expect("materialize embedded provider");

        assert_eq!(binary, binary_path(&binding, &embedded));
        assert_eq!(std::fs::read(&binary).unwrap(), embedded.bytes.as_ref());
        let metadata = std::fs::symlink_metadata(&binary).unwrap();
        assert!(metadata.file_type().is_file());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn embedded_provider_rejects_nonportable_or_escaping_executable_names() {
        for name in ["", ".", "..", "../escape", "nested/provider", "has space"] {
            let temporary = TempDir::new().expect("temporary workspace");
            let binding = binding(&temporary);
            let mut embedded = fixture();
            embedded.executable_name = name;

            let error = materialize_embedded_provider(&binding, &embedded)
                .expect_err("unsafe executable component must fail before cache creation");

            assert!(
                error.to_string().contains("safe portable"),
                "{name:?}: {error}"
            );
            assert!(
                !binding.graph_dir().exists(),
                "invalid name must be rejected before any managed path exists"
            );
        }
    }

    #[test]
    fn embedded_provider_refuses_tampered_existing_bytes_without_overwrite() {
        let temporary = TempDir::new().expect("temporary workspace");
        let binding = binding(&temporary);
        let embedded = fixture();
        let binary = binary_path(&binding, &embedded);
        std::fs::create_dir_all(binary.parent().unwrap()).unwrap();
        std::fs::write(&binary, b"tampered and user-owned\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let before = std::fs::read(&binary).unwrap();

        let error = materialize_embedded_provider(&binding, &embedded)
            .expect_err("tampered content address must fail closed");

        assert!(error.to_string().contains("SHA-256 mismatch"), "{error}");
        assert_eq!(std::fs::read(&binary).unwrap(), before);
    }

    #[test]
    fn embedded_provider_refuses_symlinked_owned_cache_component() {
        let temporary = TempDir::new().expect("temporary workspace");
        let binding = binding(&temporary);
        let embedded = fixture();
        let external = temporary.path().join("external-sentinel");
        std::fs::create_dir_all(&external).unwrap();
        std::fs::write(external.join("sentinel"), b"unchanged\n").unwrap();
        std::fs::create_dir_all(binding.graph_dir()).unwrap();
        symlink(
            &external,
            binding.graph_dir().join(PROVIDER_CACHE_DIRECTORY),
        )
        .unwrap();

        let error = materialize_embedded_provider(&binding, &embedded)
            .expect_err("owned cache symlink must fail closed");

        assert!(
            error.to_string().contains("not a real directory"),
            "{error}"
        );
        assert_eq!(
            std::fs::read(external.join("sentinel")).unwrap(),
            b"unchanged\n"
        );
        assert!(
            !external.join("executables").exists(),
            "refusal must occur before creating anything through the symlink"
        );
    }

    #[test]
    fn concurrent_embedded_provider_materialization_converges_without_residue() {
        let temporary = TempDir::new().expect("temporary workspace");
        let binding = binding(&temporary);
        let embedded = fixture();
        let barrier = Arc::new(Barrier::new(16));
        let paths = std::thread::scope(|scope| {
            let handles: [_; 16] = std::array::from_fn(|_| {
                let barrier = Arc::clone(&barrier);
                let binding = binding.clone();
                let embedded = embedded.clone();
                scope.spawn(move || {
                    barrier.wait();
                    materialize_embedded_provider(&binding, &embedded)
                })
            });
            handles
                .into_iter()
                .map(|handle| handle.join().expect("materializer thread"))
                .collect::<Result<Vec<_>, _>>()
        })
        .expect("every concurrent materializer must converge");

        assert!(paths.windows(2).all(|pair| pair[0] == pair[1]));
        assert_eq!(std::fs::read(&paths[0]).unwrap(), embedded.bytes.as_ref());
        let entries = std::fs::read_dir(paths[0].parent().unwrap())
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            entries.len(),
            1,
            "all private candidates must be removed after publication"
        );
    }
}
