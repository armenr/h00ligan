//! Product-shape contract for semantic-provider assembly.
//!
//! The ordinary executable and portable artifact may supply different
//! capabilities, but they must enter one checked-in product runner. Likewise,
//! adding a language adapter must extend a provider collection rather than add
//! another Rust/Go-shaped constructor argument or runtime field.

use std::collections::BTreeSet;

const REGISTRY: &str =
    include_str!("../../h00ligan-engine/src/code_intel_semantic_provider_registry.rs");
const COORDINATOR: &str =
    include_str!("../../h00ligan-engine/src/code_intel_semantic_provider_coordinator.rs");
const RUST_ADAPTER: &str =
    include_str!("../../h00ligan-engine/src/code_intel_rust_semantic_provider.rs");
const GO_ADAPTER: &str =
    include_str!("../../h00ligan-engine/src/code_intel_go_semantic_provider.rs");
const WORKSPACE_ADAPTER: &str =
    include_str!("../../h00ligan-engine/src/code_intel_workspace_semantic_provider.rs");
const PROVIDER_PROTOCOL: &str = include_str!("../../h00ligan-provider-protocol/src/lib.rs");
const PROVIDER_PROCESS: &str =
    include_str!("../../h00ligan-engine/src/code_intel_semantic_provider_process.rs");
const RUST_PROVIDER: &str =
    include_str!("../../../providers/rust-analyzer/h00ligan_ra_provider.rs");
const GO_PROVIDER: &str = include_str!("../../../providers/go/gopls/h00_semantic_provider.go");
const PYTHON_PROVIDER: &str =
    include_str!("../../../providers/python/pyrefly/h00_pyrefly_semantic_provider.rs");
const TYPESCRIPT_PROVIDER: &str =
    include_str!("../../../providers/typescript/h00_semantic_provider.go");
const SUPERVISOR: &str = include_str!("../../h00ligan-engine/src/code_intel_supervisor.rs");
const RUNTIME: &str = include_str!("../src/runtime.rs");
const PRODUCT: &str = include_str!("../src/product.rs");
const TOOLCHAIN: &str = include_str!("../src/toolchain.rs");
const ORDINARY_MAIN: &str = include_str!("../src/bin/h00ligan.rs");
const PORTABLE_MAIN: &str =
    include_str!("../../../providers/rust-analyzer/h00ligan_embedded_main.rs");
const PORTABLE_BUILDER: &str = include_str!("../../../scripts/build-h00ligan-portable.sh");
const GO_PROVIDER_BUILDER: &str =
    include_str!("../../../scripts/build-h00-go-semantic-provider.sh");
const TYPESCRIPT_PROVIDER_BUILDER: &str =
    include_str!("../../../scripts/build-h00-typescript-semantic-provider.sh");
const PYTHON_PROVIDER_BUILDER: &str =
    include_str!("../../../scripts/build-h00-pyrefly-semantic-provider.sh");
const OFFICIAL_GO_SDK_RESOLVER: &str =
    include_str!("../../../scripts/resolve-h00-official-go-sdk.sh");
const WATCH_LIFECYCLE: &str = include_str!("watch_lifecycle.rs");

#[test]
fn provider_configuration_is_collection_shaped_across_engine_and_product() {
    let population = [REGISTRY, SUPERVISOR, RUNTIME];
    assert_eq!(
        population
            .iter()
            .filter(|source| source.contains("SemanticProvider"))
            .count(),
        population.len(),
        "positive control: all measured assembly layers must contain semantic-provider code"
    );

    assert!(
        REGISTRY.contains("pub struct SemanticProviderConfig"),
        "the engine must expose one typed provider-configuration collection element"
    );
    assert!(
        SUPERVISOR.contains("providers: Vec<SemanticProviderConfig>"),
        "the supervisor constructor must receive a provider collection"
    );
    assert!(
        !SUPERVISOR.contains("rust: Option<RustSemanticProviderConfig>")
            && !SUPERVISOR.contains("go: Option<GoSemanticProviderConfig>"),
        "adding a language must not extend a Rust/Go constructor tuple"
    );
    assert!(
        RUNTIME.contains("semantic_provider_products: Vec<SemanticProviderProduct>"),
        "h00ligan runtime policy must retain one product-provider collection"
    );
    assert!(
        !RUNTIME.contains("rust_semantic_provider: Option<RustSemanticProviderConfig>")
            && !RUNTIME.contains("embedded_go_provider: Option<EmbeddedGoProvider>"),
        "adding a language must not add another product runtime field"
    );
}

/// FALSIFIER: a collection is not genuinely extensible when each element is a
/// closed Rust/Go enum and every assembly layer still matches on the language.
/// Adding a provider may select a reusable launch strategy and adapter factory,
/// but must not add a language variant to registry, runtime, or product policy.
#[test]
fn provider_configuration_and_packaging_are_open_to_a_third_language() {
    let population = [REGISTRY, RUNTIME, PRODUCT];
    assert_eq!(
        population
            .iter()
            .filter(|source| source.contains("SemanticProvider"))
            .count(),
        population.len(),
        "positive control: every measured production assembly layer is populated"
    );

    assert!(
        !REGISTRY.contains("pub enum SemanticProviderConfig")
            && !REGISTRY.contains("SemanticProviderConfig::Rust")
            && !REGISTRY.contains("SemanticProviderConfig::Go"),
        "engine configuration must erase adapter construction without a closed language match"
    );
    assert!(
        !RUNTIME.contains("RustSameExecutable") && !RUNTIME.contains("GoEmbedded"),
        "runtime products must select launch strategies rather than language variants"
    );
    assert!(
        !PRODUCT.contains("ProductProvider::Rust") && !PRODUCT.contains("ProductProvider::Go"),
        "one-file product assembly must dispatch generic provider capabilities, not Rust/Go arms"
    );
}

/// FALSIFIER: a provider collection is still closed when the shared lifecycle
/// owns a Rust/Go discriminator or when one language coordinator wraps the
/// other. Language-specific cache, toolchain, topology, and semantic-input
/// behavior belongs to a typed policy; session/reuse/refresh/publication state
/// belongs to one language-neutral coordinator.
#[test]
fn persistent_provider_lifecycle_is_language_neutral() {
    let adapters = [RUST_ADAPTER, GO_ADAPTER, WORKSPACE_ADAPTER];
    assert!(
        adapters
            .iter()
            .all(|source| source.contains("impl SemanticProviderPolicy for")),
        "positive control: every measured adapter must own a concrete language policy"
    );
    assert!(
        COORDINATOR.contains("trait SemanticProviderPolicy")
            && COORDINATOR.contains("struct PersistentSemanticProviderCoordinator<"),
        "the shared lifecycle must be parameterized by an adapter-owned policy"
    );
    assert!(
        !COORDINATOR.contains("SemanticProviderFlavor")
            && !COORDINATOR.contains("inner: RustSemanticProviderCoordinator"),
        "the shared lifecycle must not branch on Rust/Go or make Go a wrapper around Rust"
    );
    for adapter_owned_declaration in [
        "impl SemanticProviderPolicy for RustSemanticProviderPolicy",
        "impl SemanticProviderPolicy for GoSemanticProviderPolicy",
        "impl SemanticProviderPolicy for WorkspaceSemanticProviderPolicy",
        "pub struct RustSemanticProviderConfig",
        "pub struct GoSemanticProviderConfig",
        "pub struct WorkspaceSemanticProviderConfig",
        "fn rust_execution_roots_are_lock_closed",
        "fn rust_provider_reload_sensitive_documents",
        "fn validate_go_semantic_inputs_against_inventory",
    ] {
        assert!(
            !COORDINATOR.contains(adapter_owned_declaration),
            "the neutral coordinator must not retain adapter-owned declaration {adapter_owned_declaration}"
        );
    }
    assert!(
        RUST_ADAPTER.contains("fn rust_execution_roots_are_lock_closed")
            && RUST_ADAPTER.contains("fn rust_provider_reload_sensitive_documents")
            && GO_ADAPTER.contains("fn validate_go_semantic_inputs_against_inventory"),
        "compiler-specific inventory and semantic-input policy must live with its adapter"
    );
}

/// FALSIFIER: parameterizing a coordinator is not sufficient when the owner
/// is still a Rust-named module and its invalidation/session decisions remain
/// a loose collection of independently queried methods. The lifecycle owner
/// must have a neutral module boundary and consume one typed policy value;
/// stable language modules remain the product-facing adapters.
#[test]
fn persistent_provider_lifecycle_has_a_neutral_owner_and_typed_policy() {
    let population = [RUST_ADAPTER, COORDINATOR];

    assert!(
        population
            .iter()
            .any(|source| source.contains("struct PersistentSemanticProviderCoordinator<")),
        "positive control: the measured source population must contain the coordinator"
    );
    assert!(
        !RUST_ADAPTER.contains("pub struct PersistentSemanticProviderCoordinator<"),
        "the language-neutral lifecycle owner must not remain in the Rust adapter module"
    );
    assert!(
        COORDINATOR.contains("struct PersistentSemanticProviderCoordinator<")
            && COORDINATOR.contains("struct SemanticProviderLifecyclePolicy")
            && COORDINATOR.contains("fn lifecycle_policy(&self)"),
        "the neutral coordinator must consume one typed adapter-supplied lifecycle policy"
    );
    assert!(
        RUST_ADAPTER.contains("pub struct RustSemanticProviderConfig")
            && GO_ADAPTER.contains("pub struct GoSemanticProviderConfig")
            && WORKSPACE_ADAPTER.contains("WorkspaceSemanticProviderConfig"),
        "positive control: stable language-facing adapters must own their typed configurations"
    );
}

/// FALSIFIER: separating adapters does not cure lifecycle pile-on if exact
/// basis selection and root-candidate admission remain hand-copied across
/// callers. Selection has one structural validator, while replacement and
/// reconfiguration retain distinct session transactions that converge on one
/// authority-admission owner.
#[test]
fn persistent_provider_lifecycle_has_single_admission_owners() {
    assert_eq!(
        COORDINATOR
            .matches("fn exact_canonical_basis_candidate")
            .count(),
        1,
        "exact immutable-basis structure must have one validator"
    );
    assert_eq!(
        COORDINATOR.matches("prior_bases.iter().filter").count(),
        1,
        "callers must not reproduce exact-basis selection"
    );
    assert_eq!(
        COORDINATOR
            .matches(".admit_execution_root_recertification(")
            .count(),
        2,
        "replacement and reconfiguration must converge on one root-candidate admission owner"
    );
    assert_eq!(
        COORDINATOR
            .matches("fn admit_execution_root_recertification")
            .count(),
        1,
        "root-scoped authority admission must not be duplicated"
    );
}

/// FALSIFIER: once affected refresh applies the epoch, exports the selected
/// documents, and witnesses terminal runtime state in one transaction, the
/// old standalone export request/terminal is not compatibility—it is a second
/// lifecycle contract with no production caller. Every shipped adapter must
/// retain the atomic operation and reject the split operation by construction.
#[test]
fn atomic_affected_refresh_is_the_only_shipped_affected_operation() {
    let population = [
        PROVIDER_PROTOCOL,
        PROVIDER_PROCESS,
        RUST_PROVIDER,
        GO_PROVIDER,
        PYTHON_PROVIDER,
        TYPESCRIPT_PROVIDER,
    ];
    assert_eq!(
        population
            .iter()
            .filter(|source| {
                source.contains("RefreshAffected") || source.contains("refresh_affected")
            })
            .count(),
        population.len(),
        "positive control: every measured protocol/adapter layer must implement atomic refresh"
    );
    for source in population {
        assert!(
            !source.contains("ExportAffected")
                && !source.contains("export_affected")
                && !source.contains("ProviderResponseBody::AffectedDocuments")
                && !source.contains("\"affected_documents\""),
            "the shipped protocol/adapter population must not retain the split affected export"
        );
    }
}

/// FALSIFIER: Python and TypeScript intentionally share the same retained,
/// whole-provider lifecycle policy. Keeping two hand-copied installed WATCH
/// programs lets their common authority/parity/restore contract drift. Their
/// fixtures remain typed rows, but the lifecycle oracle must have one owner.
#[test]
fn workspace_provider_watch_lifecycles_use_one_explicit_conformance_matrix() {
    for test_name in [
        "installed_python_watch_source_and_configuration_lifecycle_matches_full_baselines",
        "installed_typescript_watch_source_and_configuration_lifecycle_matches_full_baselines",
    ] {
        assert!(
            WATCH_LIFECYCLE.contains(test_name),
            "positive control: installed workspace-provider row {test_name} must be populated"
        );
    }
    assert!(
        WATCH_LIFECYCLE.contains("enum WorkspaceProviderWatchConformanceCase")
            && WATCH_LIFECYCLE.contains("const WORKSPACE_PROVIDER_WATCH_CONFORMANCE_MATRIX")
            && WATCH_LIFECYCLE.contains("fn run_workspace_provider_watch_conformance("),
        "the two workspace-provider fixtures must be rows in one installed lifecycle oracle"
    );
}

/// FALSIFIER: an engine adapter that product assembly cannot construct is not
/// wired. Python and TypeScript must enter the same generic adapter family,
/// while retaining distinct typed factories for their pinned identities.
#[test]
fn workspace_provider_family_is_reachable_from_product_assembly() {
    assert!(
        WORKSPACE_ADAPTER.contains("pub struct WorkspaceSemanticProviderConfig")
            && REGISTRY
                .contains("impl SemanticProviderAdapterConfig for WorkspaceSemanticProviderConfig"),
        "positive control: the measured engine adapter family must be populated and registered"
    );
    assert!(
        PRODUCT.contains("pub fn pyrefly_provider_config(")
            && PRODUCT.contains("WorkspaceSemanticProviderConfig::pyrefly(")
            && PRODUCT.contains("pub fn typescript_provider_config(")
            && PRODUCT.contains("WorkspaceSemanticProviderConfig::typescript_native("),
        "the product must expose one typed factory per pinned workspace analyzer"
    );
    assert!(
        !PRODUCT.contains("PythonSemanticProviderCoordinator")
            && !PRODUCT.contains("TypeScriptSemanticProviderCoordinator"),
        "product reachability must not clone language-specific lifecycle owners"
    );
}

/// FALSIFIER: provider assembly is not open while toolchain discovery remains
/// a Rust/Go switch, and one language's packaging choice must not change the
/// authority policy identity recorded for every other language.
#[test]
fn semantic_toolchain_resolution_is_language_policy_driven() {
    assert!(
        TOOLCHAIN.contains("resolve_rust") && TOOLCHAIN.contains("resolve_go"),
        "positive control: the measured resolver must contain both current language populations"
    );
    assert!(
        TOOLCHAIN.contains("trait SystemToolchainPolicy")
            && TOOLCHAIN.contains("policies: BTreeMap<"),
        "system discovery must dispatch through an open language-policy collection"
    );
    assert!(
        TOOLCHAIN.contains("fn policy_id(") && TOOLCHAIN.contains("language: &str"),
        "authority policy identity must be selected for the requested language"
    );
    assert!(
        !TOOLCHAIN.contains("embedded_go_provider")
            && !TOOLCHAIN.contains("match language")
            && !TOOLCHAIN.contains("matches!(language.as_str(), \"rust\" | \"go\")"),
        "the shared resolver must not encode a Go mode bit or a closed Rust/Go language switch"
    );
}

#[test]
fn ordinary_and_portable_executables_enter_one_checked_in_product_runner() {
    let entrypoints = [ORDINARY_MAIN, PORTABLE_MAIN];
    assert_eq!(
        entrypoints
            .iter()
            .filter(|source| source.contains("fn main()"))
            .count(),
        entrypoints.len(),
        "positive control: both measured executable entrypoints must be populated"
    );
    assert!(
        entrypoints
            .iter()
            .all(|source| source.contains("h00ligan::product::run(")),
        "ordinary and portable executables must delegate product policy to the same checked-in runner"
    );
    assert!(
        !PORTABLE_MAIN.contains("run_with_runtime_factory")
            && !PORTABLE_MAIN.contains("std::process::exit"),
        "the portable adapter must supply provider hooks, not duplicate runtime or dispatch policy"
    );
    for capability in [
        "EMBEDDED_TYPESCRIPT_PROVIDER",
        "H00_TYPESCRIPT_PROVIDER_ID",
        "typescript_source_components()",
        "h00ligan::product::typescript_provider_config",
    ] {
        assert!(
            PORTABLE_MAIN.contains(capability),
            "the one-file product does not wire its TypeScript capability: {capability}"
        );
    }
}

/// FALSIFIER: adding bytes to the adapter alone is not a shipped capability.
/// The portable builder must build, validate, snapshot, identity-bind, and
/// export the exact TypeScript provider artifact used by `include_bytes!`.
#[test]
fn portable_builder_binds_the_embedded_typescript_provider_end_to_end() {
    assert!(
        PORTABLE_BUILDER.contains("H00_GO_PROVIDER_BINARY"),
        "positive control: the measured builder contains the existing embedded Go provider lane"
    );
    for binding in [
        "build-h00-typescript-semantic-provider.sh",
        "H00_TYPESCRIPT_PROVIDER_BINARY",
        "H00_TYPESCRIPT_PROVIDER_BINARY_SHA256",
        "H00_TYPESCRIPT_PROVIDER_PATCH_SHA256",
        "typescript_provider_receipt_sha256",
        "resolve-h00-official-go-sdk.sh",
        "go_provider_go_sdk_resolver_sha256",
        "typescript_provider_go_sdk_resolver_sha256",
    ] {
        assert!(
            PORTABLE_BUILDER.contains(binding),
            "portable product omits TypeScript artifact authority: {binding}"
        );
    }
}

/// RIGHT-REASON REGRESSION: a Pyrefly adapter does not become a shipped
/// capability merely because its source exists. The portable builder must
/// build and re-verify an independently locked provider, bind its exact bytes
/// and source coordinates into the artifact receipt, and embed those bytes in
/// the single distributed product.
#[test]
fn portable_builder_binds_the_embedded_python_provider_end_to_end() {
    assert!(
        PYTHON_PROVIDER_BUILDER.contains("H00_PYREFLY_SOURCE_ROOT")
            && PYTHON_PROVIDER_BUILDER.contains("H00_PYREFLY_ARCHIVE_SHA256"),
        "positive control: the measured Pyrefly builder exposes prepared-source authority"
    );
    for binding in [
        "build-h00-pyrefly-semantic-provider.sh",
        "H00_PYREFLY_SOURCE_ROOT",
        "H00_PYREFLY_SOURCE_KEY",
        "H00_PYREFLY_PATCH_SHA256",
        "H00_PYREFLY_BUILDER_SHA256",
        "H00_PYREFLY_ARCHIVE_SHA256",
        "H00_PYREFLY_SOURCE_TREE_SHA256",
        "H00_PYREFLY_CACHE_PUBLISHER_SHA256",
        "H00_PYREFLY_PROVIDER_BINARY",
        "H00_PYREFLY_PROVIDER_BINARY_SHA256",
        "H00_PYREFLY_PROVIDER_RECEIPT",
        "verify_python_provider_source",
        "python_provider_binary_sha256",
        "python_provider_source_key",
        "python_provider_source_tree_sha256",
        "python_provider_patch_sha256",
        "python_provider_builder_sha256",
        "python_provider_archive_sha256",
        "python_provider_cache_publisher_sha256",
        "python_provider_receipt_sha256",
    ] {
        assert!(
            PORTABLE_BUILDER.contains(binding),
            "portable product omits linked Python provider authority: {binding}"
        );
    }
    for capability in [
        "EMBEDDED_PYTHON_PROVIDER",
        "H00_PYREFLY_PROVIDER_ID",
        "pyrefly_source_components()",
        "H00_PYREFLY_PROVIDER_BINARY_SHA256",
        "h00ligan::product::pyrefly_provider_config",
    ] {
        assert!(
            PORTABLE_MAIN.contains(capability),
            "the one-file product does not wire its Python capability: {capability}"
        );
    }
}

fn printed_machine_output_keys(section: &str, prefix: &str) -> BTreeSet<String> {
    section
        .lines()
        .filter_map(|line| {
            let key = line
                .trim()
                .strip_prefix("printf '")?
                .split_once("=%s\\n'")?
                .0;
            key.starts_with(prefix).then(|| key.to_owned())
        })
        .collect()
}

/// SOURCE CONTRACT: prepare-only output and final artifact output are both
/// consumed as machine authority. Losing a Pyrefly identity field from either
/// branch must fail even when the other branch still contains that spelling.
#[test]
fn portable_builder_machine_outputs_bind_identical_pyrefly_authority() {
    let prepare = PORTABLE_BUILDER
        .split_once("if ((prepare_only)); then")
        .expect("positive control: prepare-only branch")
        .1
        .split_once("    exit 0\nfi")
        .expect("bounded prepare-only branch")
        .0;
    let final_output = PORTABLE_BUILDER
        .rsplit_once("if ((machine_output)); then")
        .expect("positive control: terminal machine-output branch")
        .1;
    let expected = [
        "H00_PYREFLY_ARCHIVE_SHA256",
        "H00_PYREFLY_BUILDER_SHA256",
        "H00_PYREFLY_CACHE_PUBLISHER_SHA256",
        "H00_PYREFLY_PATCH_SHA256",
        "H00_PYREFLY_PROVIDER_BINARY",
        "H00_PYREFLY_PROVIDER_BINARY_SHA256",
        "H00_PYREFLY_PROVIDER_RECEIPT",
        "H00_PYREFLY_SOURCE_KEY",
        "H00_PYREFLY_SOURCE_ROOT",
        "H00_PYREFLY_SOURCE_TREE_SHA256",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();

    assert_eq!(
        printed_machine_output_keys(prepare, "H00_PYREFLY_"),
        expected,
        "prepare-only machine output must expose the complete Pyrefly authority set"
    );
    assert_eq!(
        printed_machine_output_keys(final_output, "H00_PYREFLY_"),
        expected,
        "final machine output must expose the same complete Pyrefly authority set"
    );
}

/// RIGHT-REASON REGRESSION: distribution-patched Go SDKs may embed host-store
/// paths in otherwise static provider bytes. Both native provider builders
/// must resolve one checksummed official SDK through the same owner, while the
/// resolver must bind the archive, extracted tree, executable, and receipt.
#[test]
fn native_go_builders_share_one_official_sdk_authority() {
    assert!(
        GO_PROVIDER_BUILDER.contains("go_sdk_resolver_live")
            && TYPESCRIPT_PROVIDER_BUILDER.contains("go_sdk_resolver_live"),
        "both native provider builders must enter the shared SDK owner"
    );
    for authority in [
        "H00_GO_SDK_ARCHIVE_SHA256",
        "H00_GO_SDK_TREE_SHA256",
        "H00_GO_SDK_BINARY_SHA256",
        "H00_GO_SDK_RECEIPT_SHA256",
        "H00_GO_SDK_RESOLVER_SHA256",
    ] {
        assert!(
            OFFICIAL_GO_SDK_RESOLVER.contains(authority),
            "official Go SDK resolver omits authority coordinate: {authority}"
        );
    }
    assert!(
        TYPESCRIPT_PROVIDER_BUILDER.contains("-tags \"$go_build_tags\"")
            && TYPESCRIPT_PROVIDER_BUILDER.contains("timetzdata")
            && TYPESCRIPT_PROVIDER_BUILDER.contains("/nix/store/positive-control"),
        "the TypeScript artifact must embed timezone data and non-vacuously reject host-store paths"
    );
}
