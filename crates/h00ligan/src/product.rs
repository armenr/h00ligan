//! One executable-policy boundary shared by development and portable builds.
//!
//! Packaging adapters supply capabilities; this module owns private dispatch,
//! runtime construction, and entry into the CLI/MCP/WATCH surface. The
//! portable wrapper therefore cannot silently grow a second product policy.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;
use std::sync::Arc;

use h00ligan_engine::code_intel_go_semantic_provider::GoSemanticProviderConfig;
use h00ligan_engine::code_intel_rust_semantic_provider::RustSemanticProviderConfig;
use h00ligan_engine::code_intel_semantic_provider_registry::SemanticProviderConfig;
use h00ligan_engine::code_intel_toolchain::ToolchainResolver;
use h00ligan_engine::code_intel_workspace_semantic_provider::WorkspaceSemanticProviderConfig;
use h00ligan_provider_protocol::ProviderIdentity;

use crate::runtime::{
    LiganRuntime, SemanticProviderConfigFactory, SemanticProviderExecutableSpec,
    SemanticProviderProductSpec,
};

/// Provider hooks linked into the h00ligan executable itself.
#[derive(Clone, Copy, Debug)]
pub struct SameExecutableProvider {
    argument: &'static str,
    identity: fn() -> Result<ProviderIdentity, String>,
    run_stdio: fn() -> Result<(), String>,
    config_factory: SemanticProviderConfigFactory,
}

impl SameExecutableProvider {
    #[must_use]
    pub const fn new(
        argument: &'static str,
        identity: fn() -> Result<ProviderIdentity, String>,
        run_stdio: fn() -> Result<(), String>,
        config_factory: SemanticProviderConfigFactory,
    ) -> Self {
        Self {
            argument,
            identity,
            run_stdio,
            config_factory,
        }
    }
}

/// Provider executable bytes linked into the portable h00ligan artifact.
#[derive(Clone, Copy, Debug)]
pub struct EmbeddedExecutableProvider {
    bytes: &'static [u8],
    executable_name: &'static str,
    identity: fn() -> ProviderIdentity,
    config_factory: SemanticProviderConfigFactory,
}

impl EmbeddedExecutableProvider {
    #[must_use]
    pub const fn new(
        bytes: &'static [u8],
        executable_name: &'static str,
        identity: fn() -> ProviderIdentity,
        config_factory: SemanticProviderConfigFactory,
    ) -> Self {
        Self {
            bytes,
            executable_name,
            identity,
            config_factory,
        }
    }
}

/// One provider capability linked or embedded by a packaging lane.
#[derive(Clone, Copy, Debug)]
pub enum ProductProvider {
    SameExecutable(SameExecutableProvider),
    EmbeddedExecutable(EmbeddedExecutableProvider),
}

impl From<SameExecutableProvider> for ProductProvider {
    fn from(provider: SameExecutableProvider) -> Self {
        Self::SameExecutable(provider)
    }
}

impl From<EmbeddedExecutableProvider> for ProductProvider {
    fn from(provider: EmbeddedExecutableProvider) -> Self {
        Self::EmbeddedExecutable(provider)
    }
}

/// Typed Rust adapter factory supplied to a generic executable launch spec.
pub fn rust_provider_config(
    binary: PathBuf,
    identity: ProviderIdentity,
    resolver: Arc<dyn ToolchainResolver>,
) -> Result<SemanticProviderConfig, String> {
    RustSemanticProviderConfig::new(binary, identity, resolver)
        .map(Into::into)
        .map_err(|error| error.to_string())
}

/// Typed Go adapter factory supplied to a generic executable launch spec.
pub fn go_provider_config(
    binary: PathBuf,
    identity: ProviderIdentity,
    resolver: Arc<dyn ToolchainResolver>,
) -> Result<SemanticProviderConfig, String> {
    GoSemanticProviderConfig::new(binary, identity, resolver)
        .map(Into::into)
        .map_err(|error| error.to_string())
}

/// Typed Pyrefly adapter factory supplied to a generic executable launch spec.
pub fn pyrefly_provider_config(
    binary: PathBuf,
    identity: ProviderIdentity,
    resolver: Arc<dyn ToolchainResolver>,
) -> Result<SemanticProviderConfig, String> {
    WorkspaceSemanticProviderConfig::pyrefly(binary, identity, resolver)
        .map(Into::into)
        .map_err(|error| error.to_string())
}

/// Typed TypeScript-native adapter factory supplied to a generic executable
/// launch spec.
pub fn typescript_provider_config(
    binary: PathBuf,
    identity: ProviderIdentity,
    resolver: Arc<dyn ToolchainResolver>,
) -> Result<SemanticProviderConfig, String> {
    WorkspaceSemanticProviderConfig::typescript_native(binary, identity, resolver)
        .map(Into::into)
        .map_err(|error| error.to_string())
}

#[derive(Clone)]
enum ProductCapabilities {
    SystemToolchains,
    Embedded(Vec<ProductProvider>),
}

/// Immutable executable capabilities supplied by one packaging lane.
#[derive(Clone)]
pub struct Product {
    capabilities: ProductCapabilities,
}

impl Product {
    /// Ordinary workspace/development product. Semantic toolchains are
    /// resolved explicitly from the captured process environment.
    #[must_use]
    pub const fn system_toolchains() -> Self {
        Self {
            capabilities: ProductCapabilities::SystemToolchains,
        }
    }

    /// Portable one-file product with a typed provider-capability collection.
    /// Every member still enters the same runtime and adapter path.
    #[must_use]
    pub const fn embedded_semantic_providers(providers: Vec<ProductProvider>) -> Self {
        Self {
            capabilities: ProductCapabilities::Embedded(providers),
        }
    }

    fn runtime(self) -> Result<LiganRuntime, String> {
        match self.capabilities {
            ProductCapabilities::SystemToolchains => {
                LiganRuntime::with_system_toolchains().map_err(|error| error.to_string())
            }
            ProductCapabilities::Embedded(providers) => {
                let mut products = Vec::with_capacity(providers.len());
                for provider in providers {
                    match provider {
                        ProductProvider::SameExecutable(provider) => {
                            products.push(SemanticProviderProductSpec {
                                identity: (provider.identity)()?,
                                executable: SemanticProviderExecutableSpec::SameExecutable {
                                    argument: provider.argument,
                                },
                                config_factory: provider.config_factory,
                            });
                        }
                        ProductProvider::EmbeddedExecutable(provider) => {
                            products.push(SemanticProviderProductSpec {
                                identity: (provider.identity)(),
                                executable: SemanticProviderExecutableSpec::Embedded {
                                    bytes: provider.bytes,
                                    executable_name: provider.executable_name,
                                },
                                config_factory: provider.config_factory,
                            });
                        }
                    }
                }
                LiganRuntime::with_semantic_provider_products(products)
                    .map_err(|error| error.to_string())
            }
        }
    }

    fn same_executable_provider(
        &self,
        argument: &OsStr,
    ) -> Result<Option<SameExecutableProvider>, String> {
        let ProductCapabilities::Embedded(providers) = &self.capabilities else {
            return Ok(None);
        };
        let mut matching = providers.iter().filter_map(|provider| match provider {
            ProductProvider::SameExecutable(provider)
                if OsStr::new(provider.argument) == argument =>
            {
                Some(*provider)
            }
            ProductProvider::SameExecutable(_) | ProductProvider::EmbeddedExecutable(_) => None,
        });
        let first = matching.next();
        if matching.next().is_some() {
            return Err(format!(
                "internal semantic-provider argument is configured more than once: {argument:?}"
            ));
        }
        Ok(first)
    }
}

/// Enter h00ligan through one product-policy path.
///
/// Only a product that actually linked a provider can claim that provider's
/// exact private argument. Every ordinary invocation proceeds through the
/// same runtime factory and CLI/MCP/WATCH adapters.
pub fn run(product: Product) {
    if let Some(argument) = exact_internal_provider_argument(std::env::args_os()) {
        match product.same_executable_provider(&argument) {
            Ok(Some(provider)) => {
                let status = match (provider.run_stdio)() {
                    Ok(()) => 0,
                    Err(error) => {
                        eprintln!("Internal semantic provider failed: {error}");
                        1
                    }
                };
                std::process::exit(status);
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("h00ligan product configuration failed: {error}");
                std::process::exit(1);
            }
        }
    }

    crate::cli::run_with_runtime_factory(move || product.runtime());
}

fn exact_internal_provider_argument(
    mut arguments: impl Iterator<Item = OsString>,
) -> Option<OsString> {
    let _executable = arguments.next();
    let argument = arguments.next()?;
    arguments.next().is_none().then_some(argument)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use h00ligan_engine::code_intel_semantic_provider_registry::SemanticProviderConfig;
    use h00ligan_engine::code_intel_toolchain::ToolchainResolver;

    use crate::runtime::INTERNAL_RUST_PROVIDER_ARGUMENT;

    use super::*;

    fn arguments<'a>(values: &'a [&'a str]) -> impl Iterator<Item = OsString> + 'a {
        values.iter().map(OsString::from)
    }

    fn config_factory(
        _binary: PathBuf,
        _identity: ProviderIdentity,
        _resolver: Arc<dyn ToolchainResolver>,
    ) -> Result<SemanticProviderConfig, String> {
        panic!("dispatch-only fixture must not construct a provider config")
    }

    fn linked_fixture() -> SameExecutableProvider {
        fn identity() -> Result<ProviderIdentity, String> {
            panic!("dispatch-only fixture must not resolve provider identity")
        }
        fn run_stdio() -> Result<(), String> {
            panic!("dispatch-only fixture must not run a provider")
        }
        SameExecutableProvider::new(
            INTERNAL_RUST_PROVIDER_ARGUMENT,
            identity,
            run_stdio,
            config_factory,
        )
    }

    #[test]
    fn hidden_provider_dispatch_requires_the_exact_private_argument_population() {
        let product = Product::embedded_semantic_providers(vec![linked_fixture().into()]);
        let exact = exact_internal_provider_argument(arguments(&[
            "h00ligan",
            INTERNAL_RUST_PROVIDER_ARGUMENT,
        ]))
        .expect("one exact argument");
        assert!(
            product
                .same_executable_provider(&exact)
                .expect("unambiguous provider")
                .is_some()
        );

        assert!(exact_internal_provider_argument(arguments(&["h00ligan"])).is_none());
        assert!(
            exact_internal_provider_argument(arguments(&[
                "h00ligan",
                INTERNAL_RUST_PROVIDER_ARGUMENT,
                "extra",
            ]))
            .is_none()
        );
        let ordinary = exact_internal_provider_argument(arguments(&["h00ligan", "index"]))
            .expect("ordinary single command");
        assert!(
            product
                .same_executable_provider(&ordinary)
                .expect("ordinary argument lookup")
                .is_none(),
            "an ordinary one-argument CLI command grants no private provider authority"
        );
    }

    #[test]
    fn system_product_has_no_private_provider_authority() {
        assert!(
            Product::system_toolchains()
                .same_executable_provider(OsStr::new(INTERNAL_RUST_PROVIDER_ARGUMENT))
                .expect("valid system product")
                .is_none()
        );
    }

    #[test]
    fn duplicate_private_provider_authority_is_rejected_before_dispatch() {
        let provider = linked_fixture();
        let product = Product::embedded_semantic_providers(vec![provider.into(), provider.into()]);
        assert!(
            product
                .same_executable_provider(OsStr::new(INTERNAL_RUST_PROVIDER_ARGUMENT))
                .expect_err("duplicate private argument must be ambiguous")
                .contains("more than once")
        );
    }
}
