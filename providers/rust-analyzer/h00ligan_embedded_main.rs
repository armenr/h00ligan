//! Single-file product capability adapter.
//!
//! The release builder compiles this tiny adapter with the h00ligan library and
//! exact patched provider. Dispatch and runtime policy remain in h00ligan's
//! checked-in product runner; this file supplies only linked capabilities.

const EMBEDDED_GO_PROVIDER: &[u8] = include_bytes!(env!("H00_GO_PROVIDER_BINARY"));
const EMBEDDED_PYTHON_PROVIDER: &[u8] = include_bytes!(env!("H00_PYREFLY_PROVIDER_BINARY"));
const EMBEDDED_TYPESCRIPT_PROVIDER: &[u8] =
    include_bytes!(env!("H00_TYPESCRIPT_PROVIDER_BINARY"));

fn go_provider_identity() -> h00ligan_provider_protocol::ProviderIdentity {
    h00ligan_provider_protocol::ProviderIdentity {
        protocol: h00ligan_provider_protocol::SEMANTIC_PROVIDER_PROTOCOL.into(),
        provider_id: h00ligan_provider_protocol::H00_GO_PROVIDER_ID.into(),
        language: h00ligan_provider_protocol::H00_GO_LANGUAGE.into(),
        implementation_version: h00ligan_provider_protocol::H00_GO_IMPLEMENTATION_V4.into(),
        source_components: h00ligan_provider_protocol::go_provider_source_components(),
        patch_sha256: env!("H00_GO_PROVIDER_PATCH_SHA256").into(),
        executable_sha256: env!("H00_GO_PROVIDER_BINARY_SHA256").into(),
    }
}

fn typescript_provider_identity() -> h00ligan_provider_protocol::ProviderIdentity {
    h00ligan_provider_protocol::ProviderIdentity {
        protocol: h00ligan_provider_protocol::SEMANTIC_PROVIDER_PROTOCOL.into(),
        provider_id: h00ligan_provider_protocol::H00_TYPESCRIPT_PROVIDER_ID.into(),
        language: h00ligan_provider_protocol::H00_TYPESCRIPT_LANGUAGE.into(),
        implementation_version:
            h00ligan_provider_protocol::H00_TYPESCRIPT_IMPLEMENTATION_V1.into(),
        source_components: h00ligan_provider_protocol::typescript_source_components(),
        patch_sha256: env!("H00_TYPESCRIPT_PROVIDER_PATCH_SHA256").into(),
        executable_sha256: env!("H00_TYPESCRIPT_PROVIDER_BINARY_SHA256").into(),
    }
}

fn rust_provider_identity(
) -> Result<h00ligan_provider_protocol::ProviderIdentity, String> {
    h00ligan_ra_provider::executable_identity().map_err(|error| error.to_string())
}

fn run_rust_provider() -> Result<(), String> {
    h00ligan_ra_provider::run_stdio().map_err(|error| format!("{error:#}"))
}

fn python_provider_identity() -> h00ligan_provider_protocol::ProviderIdentity {
    h00ligan_provider_protocol::ProviderIdentity {
        protocol: h00ligan_provider_protocol::SEMANTIC_PROVIDER_PROTOCOL.into(),
        provider_id: h00ligan_provider_protocol::H00_PYREFLY_PROVIDER_ID.into(),
        language: h00ligan_provider_protocol::H00_PYREFLY_LANGUAGE.into(),
        implementation_version:
            h00ligan_provider_protocol::H00_PYREFLY_IMPLEMENTATION_V1.into(),
        source_components: h00ligan_provider_protocol::pyrefly_source_components(),
        patch_sha256: env!("H00_PYREFLY_PATCH_SHA256").into(),
        executable_sha256: env!("H00_PYREFLY_PROVIDER_BINARY_SHA256").into(),
    }
}

fn main() {
    h00ligan::product::run(
        h00ligan::product::Product::embedded_semantic_providers(vec![
            h00ligan::product::SameExecutableProvider::new(
                h00ligan::runtime::INTERNAL_RUST_PROVIDER_ARGUMENT,
                rust_provider_identity,
                run_rust_provider,
                h00ligan::product::rust_provider_config,
            )
            .into(),
            h00ligan::product::EmbeddedExecutableProvider::new(
                EMBEDDED_PYTHON_PROVIDER,
                "h00-pyrefly-semantic-provider",
                python_provider_identity,
                h00ligan::product::pyrefly_provider_config,
            )
            .into(),
            h00ligan::product::EmbeddedExecutableProvider::new(
                EMBEDDED_GO_PROVIDER,
                "h00-go-semantic-provider",
                go_provider_identity,
                h00ligan::product::go_provider_config,
            )
            .into(),
            h00ligan::product::EmbeddedExecutableProvider::new(
                EMBEDDED_TYPESCRIPT_PROVIDER,
                "h00-typescript-semantic-provider",
                typescript_provider_identity,
                h00ligan::product::typescript_provider_config,
            )
            .into(),
        ]),
    );
}
