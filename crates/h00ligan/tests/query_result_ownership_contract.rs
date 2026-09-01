//! Source-shape controls for query result and snapshot lifecycle ownership.
//!
//! Product tests prove the runtime contracts. These controls prevent adapters
//! or individual query modules from quietly recreating policy owners that can
//! drift while preserving the same happy-path output.

const DOMAIN: &str = include_str!("../../h00ligan-engine/src/code_intel_domain.rs");
const SNAPSHOT: &str = include_str!("../../h00ligan-interface/src/code_intel_context.rs");
const MCP_QUERY_ADAPTER: &str =
    include_str!("../../h00ligan-interface/src/tools/composite_intel_query.rs");
const CLI_QUERY_ADAPTER: &str = include_str!("../src/composite_cmd_query.rs");
const CLI_SURFACE: &str = include_str!("../src/cli.rs");
const DIRECT_QUERY_ADAPTER: &str = include_str!("../src/ligan_cmd.rs");

const GENERATION_RESULT_OWNERS: [(&str, &str); 11] = [
    (
        "calls",
        include_str!("../../h00ligan-engine/src/code_intel_calls.rs"),
    ),
    (
        "tests",
        include_str!("../../h00ligan-engine/src/code_intel_tests.rs"),
    ),
    (
        "find",
        include_str!("../../h00ligan-engine/src/code_intel_find.rs"),
    ),
    (
        "inspect",
        include_str!("../../h00ligan-engine/src/code_intel_inspect.rs"),
    ),
    (
        "dead",
        include_str!("../../h00ligan-engine/src/code_intel_dead.rs"),
    ),
    (
        "audit",
        include_str!("../../h00ligan-engine/src/code_intel_audit.rs"),
    ),
    (
        "assess",
        include_str!("../../h00ligan-engine/src/code_intel_assess.rs"),
    ),
    (
        "read",
        include_str!("../../h00ligan-engine/src/code_intel_read.rs"),
    ),
    (
        "type",
        include_str!("../../h00ligan-engine/src/code_intel_type.rs"),
    ),
    (
        "overview",
        include_str!("../../h00ligan-engine/src/code_intel_overview.rs"),
    ),
    (
        "dependencies",
        include_str!("../../h00ligan-engine/src/code_intel_dependencies.rs"),
    ),
];

const LIVE_HYBRID_RESULT_OWNERS: [(&str, &str); 2] = [
    (
        "diff",
        include_str!("../../h00ligan-engine/src/code_intel_diff.rs"),
    ),
    (
        "source_search",
        include_str!("../../h00ligan-engine/src/code_intel_source_search.rs"),
    ),
];

#[test]
fn query_modules_register_with_and_reference_the_shared_result_envelope() {
    let registered_owner_count = SNAPSHOT.matches("generation_bound_result!(").count()
        + SNAPSHOT
            .matches("impl GenerationBoundResult for h00ligan_engine::")
            .count();
    assert_eq!(
        GENERATION_RESULT_OWNERS.len(),
        registered_owner_count,
        "the result-envelope population must match the snapshot's actual generation-bound owners"
    );

    assert_eq!(
        DOMAIN
            .matches("pub const MAX_CODE_INTEL_RESULT_CHARS")
            .count(),
        1,
        "positive control: final product envelope owner"
    );
    assert_eq!(
        DOMAIN
            .matches("pub const MAX_GENERATION_ENGINE_RESULT_CHARS")
            .count(),
        1,
        "positive control: generation result budget owner"
    );
    assert_eq!(
        DOMAIN.matches("pub fn result_too_large(").count(),
        1,
        "positive control: typed overflow constructor owner"
    );

    for (operation, source) in GENERATION_RESULT_OWNERS {
        assert!(
            SNAPSHOT.contains(&format!("\"{operation}\"")),
            "{operation} must be registered as a generation-bound snapshot result"
        );
        assert!(
            source.contains("MAX_GENERATION_ENGINE_RESULT_CHARS"),
            "{operation} must consume the shared generation budget"
        );
        assert!(
            source.contains("DomainError::result_too_large"),
            "{operation} must use the shared typed overflow contract"
        );
    }

    for (operation, source) in LIVE_HYBRID_RESULT_OWNERS {
        assert!(
            source.contains("MAX_CODE_INTEL_RESULT_CHARS"),
            "{operation} must consume the final product envelope"
        );
        assert!(
            source.contains("DomainError::result_too_large"),
            "{operation} must use the shared typed overflow contract"
        );
    }

    // This is deliberately a positive source-ownership census, not a parser
    // pretending to prove that no differently named local numeric limit can
    // exist. Per-query overflow tests and the immutable snapshot's final
    // envelope are the executable enforcement boundary.
}

#[test]
fn direct_cli_adapter_contains_only_reachable_shipped_entrypoints() {
    for entrypoint in ["run_type", "run_read_symbol", "run_call_sites"] {
        assert_eq!(
            DIRECT_QUERY_ADAPTER
                .matches(&format!("pub async fn {entrypoint}("))
                .count(),
            1,
            "known-positive: live direct query {entrypoint} must have one adapter owner"
        );
        assert!(
            CLI_SURFACE.contains(&format!("ligan_cmd::{entrypoint}")),
            "known-positive: live direct query {entrypoint} must remain wired"
        );
    }

    for retired in [
        "run_symbol(",
        "run_symbols_overview(",
        "run_symbols_file(",
        "run_symbols_dir(",
        "run_impact(",
        "SymbolSubcommand",
        "SymbolsArgs",
        "ImpactArgs",
    ] {
        assert!(
            !DIRECT_QUERY_ADAPTER.contains(retired) && !CLI_SURFACE.contains(retired),
            "unreleased superseded CLI residue must stay deleted: {retired}"
        );
    }
}

#[test]
fn diff_blocking_lifecycle_is_owned_by_the_immutable_snapshot() {
    assert_eq!(
        SNAPSHOT.matches("pub async fn query_diff(").count(),
        1,
        "positive control: one snapshot-owned Diff entrypoint"
    );
    assert_eq!(
        SNAPSHOT
            .matches("code_intel_diff::query_live_diff(")
            .count(),
        1,
        "only the snapshot owner may enter the blocking engine use case"
    );
    for (adapter, source) in [("CLI", CLI_QUERY_ADAPTER), ("MCP", MCP_QUERY_ADAPTER)] {
        assert!(
            source.contains(".query_diff("),
            "{adapter} must delegate to the snapshot owner"
        );
        assert!(
            !source.contains("query_live_diff"),
            "{adapter} must not reconstruct Diff authority or task lifecycle"
        );
    }
}

#[test]
fn source_search_blocking_lifecycle_is_owned_by_the_immutable_snapshot() {
    assert_eq!(
        SNAPSHOT
            .matches("pub async fn query_source_search(")
            .count(),
        1,
        "positive control: one snapshot-owned source-search entrypoint"
    );
    assert_eq!(
        SNAPSHOT.matches("search_registered_source(").count(),
        1,
        "only the snapshot owner may enter the blocking source-search use case"
    );
    for (adapter, source) in [("CLI", CLI_QUERY_ADAPTER), ("MCP", MCP_QUERY_ADAPTER)] {
        assert!(
            source.contains(".query_source_search("),
            "{adapter} must delegate to the snapshot owner"
        );
        for forbidden in ["search_registered_source", "bind_source_search_result"] {
            assert!(
                !source.contains(forbidden),
                "{adapter} must not reconstruct source-search authority or task lifecycle with {forbidden}"
            );
        }
    }
}
