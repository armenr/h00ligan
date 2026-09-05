//! Real-boundary contract for SCIP evidence entering an immutable generation.
//!
//! The parent builds and validates a SCIP protobuf, then runs this same test in
//! an isolated child process whose PATH contains a scratch provider executable.
//! That keeps environment mutation out of the test process while exercising the
//! production provider probe, generation, pipeline, publisher, and resolver.

#![cfg(all(feature = "code-intel", unix))]

use std::collections::BTreeMap;
use std::fs;
use std::future::Future;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;

use h00ligan_engine::code_intel_cancellation::IndexCancellation;
use h00ligan_engine::code_intel_domain::{CapabilityStatus, LanguageId};
use h00ligan_engine::code_intel_payload::ProviderPayload;
use h00ligan_engine::code_intel_publication::{
    IndexGenerationPublicationError, publish_fresh_index_generation, resolve_generation,
};
use h00ligan_engine::code_intel_toolchain::{
    ResolvedToolchain, ResolvedToolchainComponent, ToolchainOrigin, ToolchainResolutionError,
    ToolchainResolver,
};
use h00ligan_engine::graph::EdgeKind;
use h00ligan_engine::graph_store::GraphStore;
use h00ligan_engine::index_pipeline::{
    IndexConfig, IndexPipelineError, IndexProgressPhase, ScipMode,
};
use protobuf::{Enum as _, Message as _};
use redb::ReadOnlyDatabase;
use scip::types::{
    Document, Index, Metadata, Occurrence, PositionEncoding, SymbolInformation, SymbolRole,
    TextEncoding, ToolInfo, symbol_information,
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const CHILD_MODE: &str = "H00_TEST_SCIP_PUBLICATION_CHILD";
const CHILD_ROOT: &str = "H00_TEST_SCIP_PUBLICATION_ROOT";
const CHILD_GRAPH: &str = "H00_TEST_SCIP_PUBLICATION_GRAPH";
const PROVIDER_ARTIFACT: &str = "H00_TEST_SCIP_PROVIDER_ARTIFACT";
const RUST_PROVIDER_CACHE_LOG: &str = "H00_TEST_SCIP_RUST_PROVIDER_CACHE_LOG";
const GO_PROVIDER_ARTIFACT: &str = "H00_TEST_SCIP_GO_PROVIDER_ARTIFACT";
const GO_PROVIDER_CACHE_LOG: &str = "H00_TEST_SCIP_GO_PROVIDER_CACHE_LOG";
const GO_TOOLCHAIN_BIN: &str = "H00_TEST_SCIP_GO_TOOLCHAIN_BIN";
const PROVIDER_EXECUTED: &str = "H00_TEST_SCIP_PROVIDER_EXECUTED";
const ROOT_ARTIFACT_SHAPE: &str = "H00_TEST_SCIP_ROOT_ARTIFACT_SHAPE";
const ROOT_ARTIFACT_SENTINEL: &str = "H00_TEST_SCIP_ROOT_ARTIFACT_SENTINEL";
const EXECUTED_PROVIDER_VERSION: &str = "fixture-probe";
const PROVIDER_VERSION: &str = EXECUTED_PROVIDER_VERSION;
const MISMATCHED_PROVIDER_VERSION: &str = "fixture-artifact-other";
const CALLER_SYMBOL: &str = "rust-analyzer cargo fixture_pkg 0.1.0 lib/caller().";
const TARGET_SYMBOL: &str = "rust-analyzer cargo fixture_pkg 0.1.0 lib/target().";
const EXECUTED_GO_PROVIDER_VERSION: &str = "fixture-probe";
const GO_PROVIDER_VERSION: &str = EXECUTED_GO_PROVIDER_VERSION;
const GO_CALLER_SYMBOL: &str = "scip-go gomod example.com/fixture v0.0.0 main/caller().";
const GO_TARGET_SYMBOL: &str = "scip-go gomod example.com/fixture v0.0.0 main/target().";
const SOURCE: &str = concat!(
    "pub fn target() {}\n",
    "pub fn caller() { let café = \"🙂\"; let alias = target; let _ = alias; target(); }\n",
);
const GO_SOURCE: &str = concat!(
    "package main\n",
    "func target() {}\n",
    "func caller() { target() }\n",
);
const RUST_PROVIDER_SCRIPT: &str = "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'rust-analyzer fixture-probe'\n  exit 0\nfi\nif [ \"$1\" = \"scip\" ]; then\n  if [ -n \"$H00_TEST_SCIP_PROVIDER_EXECUTED\" ]; then\n    printf '%s\\n' 'provider-executed' > \"$H00_TEST_SCIP_PROVIDER_EXECUTED\"\n  fi\n  shift\n  output=''\n  config=''\n  while [ \"$#\" -gt 0 ]; do\n    if [ \"$1\" = \"--output\" ]; then\n      shift\n      output=$1\n    elif [ \"$1\" = \"--config-path\" ]; then\n      shift\n      config=$1\n    fi\n    shift\n  done\n  [ -n \"$output\" ] || exit 65\n  [ -n \"$config\" ] || exit 66\n  grep -q -- '--locked' \"$config\" || exit 67\n  case \"$output\" in \"$PWD\"/*) exit 68 ;; esac\n  case \"$CARGO_TARGET_DIR\" in \"$PWD\"/*|'') exit 69 ;; esac\n  if [ -n \"$H00_TEST_SCIP_RUST_PROVIDER_CACHE_LOG\" ]; then\n    printf '%s\\n' \"$CARGO_TARGET_DIR\" >> \"$H00_TEST_SCIP_RUST_PROVIDER_CACHE_LOG\"\n  fi\n  if [ \"$H00_TEST_SCIP_ROOT_ARTIFACT_SHAPE\" = \"provider-symlink\" ]; then\n    ln -s \"$H00_TEST_SCIP_ROOT_ARTIFACT_SENTINEL\" \"$output\"\n    exit 0\n  fi\n  cp \"$H00_TEST_SCIP_PROVIDER_ARTIFACT\" \"$output\"\n  exit 0\nfi\nexit 64\n";
const GO_PROVIDER_SCRIPT: &str = "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then\n  printf '%s\\n' 'scip-go fixture-probe'\n  exit 0\nfi\nif [ \"$1\" = \"index\" ]; then\n  shift\n  output=''\n  while [ \"$#\" -gt 0 ]; do\n    if [ \"$1\" = \"-o\" ]; then\n      shift\n      output=$1\n    fi\n    shift\n  done\n  [ -n \"$output\" ] || exit 65\n  [ \"$GOFLAGS\" = '-mod=readonly' ] || exit 66\n  case \"$output\" in \"$PWD\"/*) exit 67 ;; esac\n  case \"$GOCACHE\" in \"$PWD\"/*|'') exit 68 ;; esac\n  case \"$GOMODCACHE\" in \"$PWD\"/*|'') exit 69 ;; esac\n  if [ -n \"$H00_TEST_SCIP_GO_PROVIDER_CACHE_LOG\" ]; then\n    printf '%s\\t%s\\n' \"$GOCACHE\" \"$GOMODCACHE\" >> \"$H00_TEST_SCIP_GO_PROVIDER_CACHE_LOG\"\n  fi\n  cp \"$H00_TEST_SCIP_GO_PROVIDER_ARTIFACT\" \"$output\"\n  exit 0\nfi\nexit 64\n";
const GO_TOOLCHAIN_SCRIPT: &str = "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then\n  printf '%s\\n' 'go version go1.27.0 fixture'\n  exit 0\nfi\nexit 64\n";

#[derive(Debug)]
struct FixtureGoToolchainResolver {
    bin: PathBuf,
    environment: BTreeMap<String, String>,
}

impl FixtureGoToolchainResolver {
    fn from_child_environment() -> Self {
        let bin = PathBuf::from(
            std::env::var_os(GO_TOOLCHAIN_BIN).expect("explicit fixture Go toolchain directory"),
        );
        let mut environment: BTreeMap<String, String> =
            ["PATH", GO_PROVIDER_ARTIFACT, GO_PROVIDER_CACHE_LOG]
                .into_iter()
                .filter_map(|name| std::env::var(name).ok().map(|value| (name.into(), value)))
                .collect();
        // Like the product resolver, this fixture owns its complete launch
        // environment; the provider adapter must not invent build flags.
        environment.insert("GOFLAGS".into(), "-mod=readonly".into());
        Self { bin, environment }
    }
}

impl ToolchainResolver for FixtureGoToolchainResolver {
    fn policy_id(&self, language: &str) -> Result<&'static str, ToolchainResolutionError> {
        if language == "go" {
            Ok("h00/test-explicit-go-toolchain/v1")
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
            if language != "go" {
                return Err(ToolchainResolutionError::UnsupportedLanguage(
                    language.into(),
                ));
            }
            let canonical_root = fs::canonicalize(execution_root).map_err(|error| {
                ToolchainResolutionError::Resolution {
                    language: language.into(),
                    root: execution_root.into(),
                    detail: format!("canonicalize fixture execution root: {error}"),
                }
            })?;
            let component = |role: &str, name: &str, version: &str| {
                let executable = self.bin.join(name);
                let bytes = fs::read(&executable).map_err(|error| {
                    ToolchainResolutionError::Resolution {
                        language: language.into(),
                        root: canonical_root.clone(),
                        detail: format!("read fixture {role} executable: {error}"),
                    }
                })?;
                let digest = Sha256::digest(bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                ResolvedToolchainComponent::new(role, executable, digest, version)
            };
            ResolvedToolchain::new(
                language,
                canonical_root.clone(),
                ToolchainOrigin::System,
                [
                    component("go", "go", "go version go1.27.0 fixture")?,
                    component("scip-go", "scip-go", EXECUTED_GO_PROVIDER_VERSION)?,
                ],
                None,
                self.environment.clone(),
            )
        })
    }
}

fn fixture_index(root: &Path, include_call_occurrence: bool) -> Index {
    let mut tool = ToolInfo::new();
    tool.name = "rust-analyzer".into();
    tool.version = PROVIDER_VERSION.into();
    tool.arguments = vec!["scip".into(), ".".into(), "--features=all".into()];

    let mut metadata = Metadata::new();
    metadata.tool_info = protobuf::MessageField::some(tool);
    metadata.project_root = format!("file://{}", root.display());
    metadata.text_document_encoding = protobuf::EnumOrUnknown::new(TextEncoding::UTF8);

    let mut document = Document::new();
    document.language = "rust".into();
    document.relative_path = "src/lib.rs".into();
    document.text = SOURCE.into();
    document.position_encoding =
        protobuf::EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);

    let target_line = SOURCE.lines().next().expect("target source line");
    let caller_line = SOURCE.lines().nth(1).expect("caller source line");
    let target_name_start = target_line.find("target").expect("target definition") as i32;
    let caller_name_start = caller_line.find("caller").expect("caller definition") as i32;
    let target_value_start = caller_line
        .find("target;")
        .expect("target function-value reference") as i32;
    let target_call_start = caller_line.rfind("target").expect("target call") as i32;

    let mut target_definition = Occurrence::new();
    target_definition.symbol = TARGET_SYMBOL.into();
    target_definition.symbol_roles = SymbolRole::Definition.value();
    target_definition.range = vec![0, target_name_start, target_name_start + 6];
    target_definition.enclosing_range = vec![0, 0, 0, target_line.len() as i32];

    let mut caller_definition = Occurrence::new();
    caller_definition.symbol = CALLER_SYMBOL.into();
    caller_definition.symbol_roles = SymbolRole::Definition.value();
    caller_definition.range = vec![1, caller_name_start, caller_name_start + 6];
    caller_definition.enclosing_range = vec![1, 0, 1, caller_line.len() as i32];

    let mut target_reference = Occurrence::new();
    target_reference.symbol = TARGET_SYMBOL.into();
    target_reference.range = vec![1, target_call_start, target_call_start + 6];

    let mut target_value_reference = Occurrence::new();
    target_value_reference.symbol = TARGET_SYMBOL.into();
    target_value_reference.range = vec![1, target_value_start, target_value_start + 6];

    let mut target_information = SymbolInformation::new();
    target_information.symbol = TARGET_SYMBOL.into();
    target_information.display_name = "target".into();
    target_information.kind = protobuf::EnumOrUnknown::new(symbol_information::Kind::Function);

    let mut caller_information = SymbolInformation::new();
    caller_information.symbol = CALLER_SYMBOL.into();
    caller_information.display_name = "caller".into();
    caller_information.kind = protobuf::EnumOrUnknown::new(symbol_information::Kind::Function);

    document.occurrences = vec![target_definition, caller_definition, target_value_reference];
    if include_call_occurrence {
        document.occurrences.push(target_reference);
    }
    document.symbols = vec![target_information, caller_information];

    let mut index = Index::new();
    index.metadata = protobuf::MessageField::some(metadata);
    index.documents = vec![document];
    index
}

fn go_fixture_index(root: &Path) -> Index {
    let mut tool = ToolInfo::new();
    tool.name = "scip-go".into();
    tool.version = GO_PROVIDER_VERSION.into();
    tool.arguments = vec!["index".into(), "./...".into()];

    let mut metadata = Metadata::new();
    metadata.tool_info = protobuf::MessageField::some(tool);
    metadata.project_root = format!("file://{}", root.display());
    metadata.text_document_encoding = protobuf::EnumOrUnknown::new(TextEncoding::UTF8);

    let mut document = Document::new();
    document.language = "go".into();
    document.relative_path = "main.go".into();
    document.text = GO_SOURCE.into();
    document.position_encoding =
        protobuf::EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);

    let target_line = GO_SOURCE.lines().nth(1).expect("Go target line");
    let caller_line = GO_SOURCE.lines().nth(2).expect("Go caller line");
    let target_definition_start = target_line.find("target").expect("Go target definition") as i32;
    let caller_definition_start = caller_line.find("caller").expect("Go caller definition") as i32;
    let target_call_start = caller_line.rfind("target").expect("Go target call") as i32;

    let mut target_definition = Occurrence::new();
    target_definition.symbol = GO_TARGET_SYMBOL.into();
    target_definition.symbol_roles = SymbolRole::Definition.value();
    target_definition.range = vec![1, target_definition_start, target_definition_start + 6];
    target_definition.enclosing_range = vec![1, 0, 1, target_line.len() as i32];

    let mut caller_definition = Occurrence::new();
    caller_definition.symbol = GO_CALLER_SYMBOL.into();
    caller_definition.symbol_roles = SymbolRole::Definition.value();
    caller_definition.range = vec![2, caller_definition_start, caller_definition_start + 6];
    caller_definition.enclosing_range = vec![2, 0, 2, caller_line.len() as i32];

    let mut target_call = Occurrence::new();
    target_call.symbol = GO_TARGET_SYMBOL.into();
    target_call.range = vec![2, target_call_start, target_call_start + 6];

    let mut target_information = SymbolInformation::new();
    target_information.symbol = GO_TARGET_SYMBOL.into();
    target_information.display_name = "target".into();
    target_information.kind = protobuf::EnumOrUnknown::new(symbol_information::Kind::Function);

    let mut caller_information = SymbolInformation::new();
    caller_information.symbol = GO_CALLER_SYMBOL.into();
    caller_information.display_name = "caller".into();
    caller_information.kind = protobuf::EnumOrUnknown::new(symbol_information::Kind::Function);

    document.occurrences = vec![target_definition, caller_definition, target_call];
    document.symbols = vec![target_information, caller_information];

    let mut index = Index::new();
    index.metadata = protobuf::MessageField::some(metadata);
    index.documents = vec![document];
    index
}

fn assert_non_vacuous_fixture(
    bytes: &[u8],
    root: &Path,
    expected_references: usize,
    expected_provider_version: &str,
) {
    let parsed = Index::parse_from_bytes(bytes).expect("fixture must be valid SCIP protobuf");
    let metadata = parsed.metadata.as_ref().expect("fixture metadata");
    let tool = metadata.tool_info.as_ref().expect("fixture tool identity");
    assert_eq!(tool.name, "rust-analyzer");
    assert_eq!(tool.version, expected_provider_version);
    assert_eq!(metadata.project_root, format!("file://{}", root.display()));
    assert_eq!(
        metadata
            .text_document_encoding
            .enum_value()
            .expect("known text encoding"),
        TextEncoding::UTF8
    );

    assert_eq!(parsed.documents.len(), 1);
    let document = &parsed.documents[0];
    assert_eq!(document.language, "rust");
    assert_eq!(document.relative_path, "src/lib.rs");
    assert_eq!(document.text, SOURCE);
    assert!(document.text.contains("café"));
    assert!(document.text.contains('🙂'));
    assert_eq!(
        document
            .position_encoding
            .enum_value()
            .expect("known encoding"),
        PositionEncoding::UTF8CodeUnitOffsetFromLineStart
    );
    assert!(document.occurrences.iter().any(|occurrence| {
        occurrence.symbol == CALLER_SYMBOL
            && occurrence.symbol_roles & SymbolRole::Definition.value() != 0
    }));
    assert_eq!(
        document
            .occurrences
            .iter()
            .filter(|occurrence| {
                occurrence.symbol == TARGET_SYMBOL && occurrence.symbol_roles == 0
            })
            .count(),
        expected_references,
        "the fixture must contain its exact intended target-reference population"
    );
}

async fn published_calls_edge_count(database_path: &Path) -> usize {
    let database = Arc::new(
        ReadOnlyDatabase::open(database_path).expect("open published generation read-only"),
    );
    let graph_store = GraphStore::new_read_only(database);
    graph_store
        .load_snapshot()
        .await
        .expect("load published graph")
        .expect("published graph snapshot")
        .all_edges()
        .into_iter()
        .filter(|(_, _, edge)| edge.kind == EdgeKind::Calls)
        .count()
}

async fn run_child_contract(root: PathBuf, graph: PathBuf) {
    let config = IndexConfig {
        root: root.clone(),
        full: true,
        scip: ScipMode::Refresh,
        languages: vec!["rust".into()],
        provider_data_root: Some(graph.clone()),
        ..IndexConfig::default()
    };
    let published = publish_fresh_index_generation(&graph, &config, Some("fixture-source".into()))
        .await
        .expect("the scratch provider run must publish a generation");
    assert!(
        published.telemetry.edges_added > 0,
        "the generated SCIP artifact must reach the production graph merge"
    );
    let semantic_phase_labels = published
        .telemetry
        .phase_timings
        .iter()
        .filter(|timing| timing.phase == IndexProgressPhase::SemanticProvider)
        .map(|timing| timing.label.as_str())
        .collect::<Vec<_>>();
    for expected in [
        "semantic provider cache preparation",
        "semantic provider cache maintenance",
        "rust artifact composition and authority binding",
        "rust normalized Calls projection",
        "rust residual SCIP projection",
        "semantic provider workspace cleanup",
        "semantic orchestration",
    ] {
        assert!(
            semantic_phase_labels.contains(&expected),
            "the terminal receipt must expose semantic subphase {expected:?}: {semantic_phase_labels:?}"
        );
    }
    assert!(
        !semantic_phase_labels.contains(&"semantic normalization"),
        "the old umbrella label hid metadata, normalization, Calls projection, and residual projection behind one duration"
    );
    // RIGHT-REASON TELEMETRY REGRESSION: this is a flat machine-readable
    // timing population. Inclusive parents beside their own children make a
    // consumer double-count work and can point optimization at the wrong
    // phase. The real provider positive controls above prove this assertion is
    // observing a populated production path rather than an empty receipt.
    for ambiguous_parent in [
        "rust evidence composition and normalization",
        "rust global semantic resolution",
        "rust definition indexing",
    ] {
        assert!(
            !semantic_phase_labels.contains(&ambiguous_parent),
            "flat semantic timings must not export inclusive parent {ambiguous_parent:?}: {semantic_phase_labels:?}"
        );
    }
    for component in [
        "rust artifact composition and authority binding",
        "rust coverage exclusion setup",
    ] {
        assert!(
            semantic_phase_labels.contains(&component),
            "the additive semantic timing population must expose component {component:?}: {semantic_phase_labels:?}"
        );
    }
    for (prefix, suffix) in [
        ("rust definition collection (", " document cache hits)"),
        ("rust definition canonicalization (", " group reuse hits)"),
    ] {
        let matches = semantic_phase_labels
            .iter()
            .filter_map(|label| {
                label
                    .strip_prefix(prefix)
                    .and_then(|value| value.strip_suffix(suffix))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "the additive semantic timing population must expose exactly one counted component {prefix:?}: {semantic_phase_labels:?}"
        );
        let (hits, total) = matches[0]
            .split_once('/')
            .unwrap_or_else(|| panic!("timing work count must be hits/total: {}", matches[0]));
        let hits = hits.parse::<u64>().expect("timing cache-hit count");
        let total = total.parse::<u64>().expect("timing total count");
        assert!(
            total > 0 && hits <= total,
            "timing work count must be populated and coherent: {hits}/{total}"
        );
    }

    let resolved = resolve_generation(&graph, &root).expect("published generation must resolve");
    assert!(
        published_calls_edge_count(&resolved.database_path).await > 0,
        "the positive control requires normalized invocation evidence to reach the published Calls graph"
    );
    let calls_receipt = resolved
        .manifest
        .receipts
        .iter()
        .find(|receipt| {
            receipt.capability_id == "calls"
                && receipt.scope.language_id() == Some(&LanguageId::new("rust"))
        })
        .expect("Rust Calls receipt");
    if calls_receipt.status != CapabilityStatus::Complete {
        assert_eq!(
            calls_receipt.status,
            CapabilityStatus::Partial,
            "a parsed artifact must reach the legacy partial path, not provider-unavailable"
        );
        assert_eq!(
            calls_receipt.reason_code.as_deref(),
            Some("scoped_completeness_unproven"),
            "the red must fire after successful artifact ingestion"
        );
    }
    assert_eq!(
        calls_receipt.status,
        CapabilityStatus::Complete,
        "a validated, complete Rust SCIP artifact must not collapse to aggregate partial evidence"
    );
    assert_eq!(
        calls_receipt.provider_version.as_deref(),
        Some(EXECUTED_PROVIDER_VERSION),
        "the receipt must identify the executable that actually produced the artifact"
    );
    assert_eq!(
        resolved.provider_payloads.len(),
        1,
        "one complete Calls receipt requires exactly one same-generation provider payload"
    );
    let ProviderPayload::Calls(payload) = resolved.provider_payloads[0].payload() else {
        panic!("Rust Calls fixture published a non-Calls payload")
    };
    assert_eq!(payload.receipt, *calls_receipt);
    assert_eq!(payload.documents.len(), 1);
    assert_eq!(payload.documents[0].document_path, "src/lib.rs");
    let caller = payload
        .symbols
        .iter()
        .find(|symbol| symbol.provider_symbol_id == CALLER_SYMBOL && symbol.name == "caller")
        .expect("caller symbol");
    assert!(
        payload.symbols.iter().any(|symbol| {
            symbol.provider_symbol_id == TARGET_SYMBOL && symbol.name == "target"
        })
    );
    assert_eq!(
        payload.calls.len(),
        1,
        "a function-value reference to the same callable must not become a call"
    );
    let call = &payload.calls[0];
    assert_eq!(call.caller_symbol_id, CALLER_SYMBOL);
    assert_eq!(call.callee_symbol_id, TARGET_SYMBOL);
    let call_site = &call.call_site;
    let caller_line = SOURCE.lines().nth(1).expect("caller source line");
    let call_column = caller_line.rfind("target").expect("target call") as u64;
    let call_start = SOURCE.find(caller_line).expect("caller line offset") as u64 + call_column;
    assert_eq!(call_site.span.start_byte, call_start);
    assert_eq!(call_site.span.end_byte, call_start + 6);
    assert_eq!(call_site.span.start_utf8_byte_column, call_column as u32);
    assert_eq!(call_site.span.end_utf8_byte_column, call_column as u32 + 6);
    let caller_extent = caller
        .call_owner_extent
        .as_ref()
        .expect("persisted caller ownership extent");
    assert_eq!(caller_extent.document_path, call_site.document_path);
    assert!(caller_extent.span.start_byte <= call_site.span.start_byte);
    assert!(call_site.span.end_byte <= caller_extent.span.end_byte);
}

async fn run_incomplete_semantic_child_contract(
    root: PathBuf,
    graph: PathBuf,
    expected_reason_code: &str,
) {
    let structural_config = IndexConfig {
        root: root.clone(),
        full: true,
        scip: ScipMode::Disabled,
        languages: vec!["rust".into()],
        ..IndexConfig::default()
    };
    let baseline = publish_fresh_index_generation(
        &graph,
        &structural_config,
        Some("structural-baseline".into()),
    )
    .await
    .expect("the positive control must publish a structural generation");

    let semantic_config = IndexConfig {
        root: root.clone(),
        full: true,
        scip: ScipMode::Refresh,
        languages: vec!["rust".into()],
        ..IndexConfig::default()
    };
    let best_effort = publish_fresh_index_generation(
        &graph,
        &semantic_config,
        Some("best-effort-incomplete-semantic-candidate".into()),
    )
    .await
    .expect("best-effort semantic refresh must publish honest partial authority");

    let resolved = resolve_generation(&graph, &root).expect("best-effort generation must resolve");
    assert_eq!(resolved.head, best_effort.publication.head);
    assert_ne!(
        resolved.manifest.generation_id, baseline.publication.manifest.generation_id,
        "honest partial provider evidence must replace the structural-only baseline"
    );
    assert_eq!(
        published_calls_edge_count(&resolved.database_path).await,
        0,
        "an omitted call occurrence must never be invented as Calls evidence"
    );
    let calls_receipt = resolved
        .manifest
        .receipts
        .iter()
        .find(|receipt| {
            receipt.capability_id == "calls"
                && receipt.scope.language_id() == Some(&LanguageId::new("rust"))
        })
        .expect("Rust Calls receipt");
    assert_eq!(calls_receipt.status, CapabilityStatus::Partial);
    assert_eq!(
        calls_receipt.reason_code.as_deref(),
        Some(expected_reason_code)
    );
    assert!(
        resolved.provider_payloads.is_empty(),
        "partial authority must never publish a complete Calls payload"
    );

    let strict_config = IndexConfig {
        require_complete_calls: true,
        ..semantic_config
    };
    let error = publish_fresh_index_generation(
        &graph,
        &strict_config,
        Some("strict-incomplete-semantic-candidate".into()),
    )
    .await
    .expect_err("strict semantic refresh must reject incomplete provider authority");
    assert!(
        matches!(
            &error,
            IndexGenerationPublicationError::Pipeline(
                IndexPipelineError::SemanticProvidersUnsatisfied { evidence }
            ) if evidence.contains(expected_reason_code)
        ),
        "the rejection must preserve the provider's bounded incompleteness evidence: {error:?}"
    );

    let after_strict =
        resolve_generation(&graph, &root).expect("last-good generation must resolve");
    assert_eq!(
        after_strict.head, best_effort.publication.head,
        "a rejected strict candidate must not advance either publication head"
    );
    assert_eq!(
        after_strict.manifest.generation_id,
        best_effort.publication.manifest.generation_id
    );
    assert_eq!(
        published_calls_edge_count(&after_strict.database_path).await,
        0,
        "a rejected strict candidate must not contaminate the last-good partial graph"
    );
    let retained_calls_receipt = after_strict
        .manifest
        .receipts
        .iter()
        .find(|receipt| {
            receipt.capability_id == "calls"
                && receipt.scope.language_id() == Some(&LanguageId::new("rust"))
        })
        .expect("Rust Calls receipt");
    assert_eq!(retained_calls_receipt.status, CapabilityStatus::Partial);
    assert_eq!(
        retained_calls_receipt.reason_code.as_deref(),
        Some(expected_reason_code),
        "the retained receipt must come from the best-effort generation, not the rejected candidate"
    );
    assert!(
        after_strict.provider_payloads.is_empty(),
        "non-complete authority must never publish a Calls payload"
    );
}

async fn run_provider_version_mismatch_child_contract(root: PathBuf, graph: PathBuf) {
    let semantic_config = IndexConfig {
        root: root.clone(),
        full: true,
        scip: ScipMode::Refresh,
        languages: vec!["rust".into()],
        ..IndexConfig::default()
    };
    let best_effort = publish_fresh_index_generation(
        &graph,
        &semantic_config,
        Some("provider-version-mismatch".into()),
    )
    .await
    .expect("provider-version mismatch must preserve structural publication");

    let resolved = resolve_generation(&graph, &root).expect("best-effort generation must resolve");
    assert_eq!(resolved.head, best_effort.publication.head);
    assert_eq!(
        published_calls_edge_count(&resolved.database_path).await,
        0,
        "a foreign provider-version artifact must contribute no Calls edge"
    );
    let calls_receipt = resolved
        .manifest
        .receipts
        .iter()
        .find(|receipt| {
            receipt.capability_id == "calls"
                && receipt.scope.language_id() == Some(&LanguageId::new("rust"))
        })
        .expect("Rust Calls receipt");
    assert_eq!(calls_receipt.status, CapabilityStatus::Unavailable);
    assert_eq!(
        calls_receipt.reason_code.as_deref(),
        Some("provider_identity_mismatch")
    );
    assert_eq!(
        calls_receipt.provider_version.as_deref(),
        Some(EXECUTED_PROVIDER_VERSION),
        "the refusal must identify the executable actually invoked"
    );
    assert!(
        resolved.provider_payloads.is_empty(),
        "a provider-version mismatch must publish no semantic payload"
    );

    let strict_config = IndexConfig {
        require_complete_calls: true,
        ..semantic_config
    };
    let error = publish_fresh_index_generation(
        &graph,
        &strict_config,
        Some("strict-provider-version-mismatch".into()),
    )
    .await
    .expect_err("strict semantic refresh must reject foreign provider-version evidence");
    assert!(
        matches!(
            &error,
            IndexGenerationPublicationError::Pipeline(
                IndexPipelineError::SemanticProvidersUnsatisfied { evidence }
            ) if evidence.contains("provider_identity_mismatch")
        ),
        "strict refusal must preserve the exact provider-identity cause: {error:?}"
    );
    let retained = resolve_generation(&graph, &root).expect("last-good generation must resolve");
    assert_eq!(
        retained.head, best_effort.publication.head,
        "strict rejection must not advance the published generation"
    );
}

async fn run_go_child_contract(root: PathBuf, graph: PathBuf) {
    let config = IndexConfig {
        root: root.clone(),
        full: true,
        scip: ScipMode::Refresh,
        languages: vec!["go".into()],
        toolchain_resolver: Some(Arc::new(
            FixtureGoToolchainResolver::from_child_environment(),
        )),
        ..IndexConfig::default()
    };
    let published = publish_fresh_index_generation(&graph, &config, Some("fixture-source".into()))
        .await
        .expect("the scratch scip-go run must publish a generation");
    assert!(
        published.telemetry.edges_added > 0,
        "the generated Go SCIP artifact must reach the production graph merge; receipts={:?}",
        published.publication.manifest.receipts,
    );

    let resolved = resolve_generation(&graph, &root).expect("published Go generation must resolve");
    let calls_receipt = resolved
        .manifest
        .receipts
        .iter()
        .find(|receipt| {
            receipt.capability_id == "calls"
                && receipt.scope.language_id() == Some(&LanguageId::new("go"))
        })
        .expect("Go Calls receipt");
    assert_eq!(calls_receipt.status, CapabilityStatus::Complete);
    assert_eq!(calls_receipt.provider_id.0, "scip-go");
    assert_eq!(
        calls_receipt.provider_version.as_deref(),
        Some(EXECUTED_GO_PROVIDER_VERSION)
    );
    assert_eq!(resolved.provider_payloads.len(), 1);
    let ProviderPayload::Calls(payload) = resolved.provider_payloads[0].payload() else {
        panic!("Go Calls fixture published a non-Calls payload")
    };
    assert_eq!(payload.receipt, *calls_receipt);
    assert_eq!(payload.documents.len(), 1);
    assert_eq!(payload.documents[0].document_path, "main.go");
    assert_eq!(payload.calls.len(), 1);
    assert_eq!(payload.calls[0].caller_symbol_id, GO_CALLER_SYMBOL);
    assert_eq!(payload.calls[0].callee_symbol_id, GO_TARGET_SYMBOL);
}

async fn run_go_cache_reuse_child_contract(root: PathBuf, graph: PathBuf) {
    let config = IndexConfig {
        root,
        full: true,
        scip: ScipMode::Refresh,
        languages: vec!["go".into()],
        provider_data_root: Some(graph.clone()),
        toolchain_resolver: Some(Arc::new(
            FixtureGoToolchainResolver::from_child_environment(),
        )),
        ..IndexConfig::default()
    };

    for source_revision in ["fixture-source-1", "fixture-source-2"] {
        publish_fresh_index_generation(&graph, &config, Some(source_revision.into()))
            .await
            .expect("each scratch scip-go run must publish a generation");
    }
}

async fn run_rust_cache_reuse_child_contract(root: PathBuf, graph: PathBuf) {
    let config = IndexConfig {
        root,
        full: true,
        scip: ScipMode::Refresh,
        languages: vec!["rust".into()],
        provider_data_root: Some(graph.clone()),
        ..IndexConfig::default()
    };

    for source_revision in ["fixture-source-1", "fixture-source-2"] {
        publish_fresh_index_generation(&graph, &config, Some(source_revision.into()))
            .await
            .expect("each scratch rust-analyzer run must publish a generation");
    }
}

async fn run_mixed_child_contract(root: PathBuf, graph: PathBuf) {
    let config = IndexConfig {
        root: root.clone(),
        full: true,
        scip: ScipMode::Refresh,
        languages: vec!["rust".into(), "go".into()],
        toolchain_resolver: Some(Arc::new(
            FixtureGoToolchainResolver::from_child_environment(),
        )),
        ..IndexConfig::default()
    };
    publish_fresh_index_generation(&graph, &config, Some("fixture-source".into()))
        .await
        .expect("both scratch providers must publish one generation");

    let resolved =
        resolve_generation(&graph, &root).expect("published mixed generation must resolve");
    let complete_calls = resolved
        .manifest
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.capability_id == "calls" && receipt.status == CapabilityStatus::Complete
        })
        .collect::<Vec<_>>();
    assert_eq!(complete_calls.len(), 2);
    assert!(complete_calls.iter().any(|receipt| {
        receipt.provider_id.0 == "rust-analyzer-scip"
            && receipt.provider_version.as_deref() == Some(EXECUTED_PROVIDER_VERSION)
    }));
    assert!(complete_calls.iter().any(|receipt| {
        receipt.provider_id.0 == "scip-go"
            && receipt.provider_version.as_deref() == Some(EXECUTED_GO_PROVIDER_VERSION)
    }));

    assert_eq!(resolved.provider_payloads.len(), 2);
    let payload_documents = resolved
        .provider_payloads
        .iter()
        .flat_map(|payload| payload.payload().documents())
        .map(|document| document.document_path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        payload_documents,
        std::collections::BTreeSet::from(["main.go", "src/lib.rs"])
    );
    assert_no_provider_residue(&root);
}

fn assert_no_provider_residue(root: &Path) {
    for relative in [
        "index.scip",
        "index.go.scip",
        "target",
        "Cargo.lock",
        "go.sum",
    ] {
        assert!(
            !root.join(relative).exists(),
            "provider execution must not leave {relative} in the indexed project"
        );
    }
}

fn run_isolated_parent(
    test_name: &str,
    include_call_occurrence: bool,
    target_display_name: Option<&str>,
    assert_cache_reuse: bool,
    artifact_provider_version: Option<&str>,
) {
    let workspace = TempDir::new().expect("scratch workspace");
    let root = workspace.path().join("repo");
    let graph = workspace.path().join("data");
    let provider_bin = workspace.path().join("bin");
    fs::create_dir_all(root.join("src")).expect("scratch source directory");
    fs::create_dir_all(&graph).expect("scratch publication directory");
    fs::create_dir_all(&provider_bin).expect("scratch provider bin directory");
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("scratch Cargo manifest");
    fs::write(root.join("src/lib.rs"), SOURCE).expect("scratch Unicode source");

    let artifact = workspace.path().join("fixture.scip");
    let cache_log = workspace.path().join("rust-provider-cache.log");
    let mut fixture = fixture_index(&root, include_call_occurrence);
    let artifact_provider_version = artifact_provider_version.unwrap_or(PROVIDER_VERSION);
    fixture
        .metadata
        .as_mut()
        .expect("fixture metadata")
        .tool_info
        .as_mut()
        .expect("fixture tool identity")
        .version = artifact_provider_version.into();
    if let Some(display_name) = target_display_name {
        fixture.documents[0]
            .symbols
            .iter_mut()
            .find(|symbol| symbol.symbol == TARGET_SYMBOL)
            .expect("target symbol information")
            .display_name = display_name.into();
    }
    let artifact_bytes = fixture
        .write_to_bytes()
        .expect("serialize fixture SCIP index");
    assert_non_vacuous_fixture(
        &artifact_bytes,
        &root,
        if include_call_occurrence { 2 } else { 1 },
        artifact_provider_version,
    );
    fs::write(&artifact, artifact_bytes).expect("scratch provider artifact");

    let provider = provider_bin.join("rust-analyzer");
    fs::write(&provider, RUST_PROVIDER_SCRIPT).expect("scratch provider executable");
    let mut permissions = fs::metadata(&provider)
        .expect("provider metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).expect("provider executable mode");

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut child_paths = vec![provider_bin];
    child_paths.extend(std::env::split_paths(&original_path));
    let child_path = std::env::join_paths(child_paths).expect("child PATH");
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(CHILD_MODE, "1")
        .env(CHILD_ROOT, &root)
        .env(CHILD_GRAPH, &graph)
        .env(PROVIDER_ARTIFACT, &artifact)
        .env(RUST_PROVIDER_CACHE_LOG, &cache_log)
        .env("PATH", child_path)
        .output()
        .expect("run isolated production-boundary child");

    assert!(
        output.status.success(),
        "isolated SCIP publication child failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_no_provider_residue(&root);

    if assert_cache_reuse {
        let observed = fs::read_to_string(&cache_log)
            .expect("the fake provider must record its target directories")
            .lines()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        assert_eq!(
            observed.len(),
            2,
            "non-vacuity: two publications must execute rust-analyzer twice"
        );
        assert_eq!(
            observed[0], observed[1],
            "successive publications must reuse the same warm Cargo target directory"
        );
        assert_eq!(
            observed[0],
            graph.join("provider-cache-v1/rust/cargo-target")
        );
        assert!(observed[0].is_dir(), "the warm Cargo cache must survive");
    }
}

fn run_isolated_go_parent(
    test_name: &str,
    include_external_cache_document: bool,
    assert_cache_reuse: bool,
) {
    let workspace = TempDir::new().expect("scratch workspace");
    let root = workspace.path().join("repo");
    let graph = workspace.path().join("data");
    let provider_bin = workspace.path().join("bin");
    fs::create_dir_all(&root).expect("scratch Go root");
    fs::create_dir_all(&graph).expect("scratch publication directory");
    fs::create_dir_all(&provider_bin).expect("scratch provider bin directory");
    fs::write(
        root.join("go.mod"),
        "module example.com/fixture\n\ngo 1.25\n",
    )
    .expect("scratch Go manifest");
    fs::write(root.join("main.go"), GO_SOURCE).expect("scratch Go source");

    let artifact = workspace.path().join("fixture-go.scip");
    let cache_log = workspace.path().join("go-provider-cache.log");
    let mut fixture = go_fixture_index(&root);
    if include_external_cache_document {
        let mut cache_document = Document::new();
        cache_document.language = "go".into();
        cache_document.relative_path = concat!(
            "../../../../../tmp/provider-work/artifacts/go-0-work/",
            "go-build-cache/df/generated-export-data-d",
        )
        .into();
        cache_document.text = "provider-owned build cache\n".into();
        cache_document.position_encoding =
            protobuf::EnumOrUnknown::new(PositionEncoding::UTF8CodeUnitOffsetFromLineStart);
        fixture.documents.push(cache_document);
    }
    let artifact_bytes = fixture.write_to_bytes().expect("serialize Go SCIP fixture");
    let parsed = Index::parse_from_bytes(&artifact_bytes).expect("valid Go SCIP fixture");
    assert_eq!(
        parsed.documents.len(),
        if include_external_cache_document {
            2
        } else {
            1
        },
        "the cache-document control must change the provider document population",
    );
    assert_eq!(parsed.documents[0].language, "go");
    assert!(parsed.documents[0]
        .occurrences
        .iter()
        .any(|occurrence| occurrence.symbol == GO_TARGET_SYMBOL && occurrence.symbol_roles == 0));
    if include_external_cache_document {
        assert!(
            parsed.documents[1].relative_path.starts_with("../"),
            "positive control: the fixture must reproduce scip-go's external build-cache path",
        );
    }
    fs::write(&artifact, artifact_bytes).expect("scratch Go provider artifact");

    for (name, script) in [("go", GO_TOOLCHAIN_SCRIPT), ("scip-go", GO_PROVIDER_SCRIPT)] {
        let executable = provider_bin.join(name);
        fs::write(&executable, script).expect("scratch Go toolchain executable");
        let mut permissions = fs::metadata(&executable)
            .expect("toolchain metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&executable, permissions).expect("toolchain executable mode");
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut child_paths = vec![provider_bin.clone()];
    child_paths.extend(std::env::split_paths(&original_path));
    let child_path = std::env::join_paths(child_paths).expect("child PATH");
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(CHILD_MODE, "1")
        .env(CHILD_ROOT, &root)
        .env(CHILD_GRAPH, &graph)
        .env(GO_PROVIDER_ARTIFACT, &artifact)
        .env(GO_PROVIDER_CACHE_LOG, &cache_log)
        .env(GO_TOOLCHAIN_BIN, &provider_bin)
        .env("PATH", child_path)
        .output()
        .expect("run isolated Go production-boundary child");

    assert!(
        output.status.success(),
        "isolated Go SCIP publication child failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_no_provider_residue(&root);

    if assert_cache_reuse {
        let observed = fs::read_to_string(&cache_log)
            .expect("the fake provider must record its cache paths")
            .lines()
            .map(|line| {
                let (build, modules) = line
                    .split_once('\t')
                    .expect("cache evidence has build and module paths");
                (PathBuf::from(build), PathBuf::from(modules))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            observed.len(),
            2,
            "non-vacuity: two publications must execute the Go provider twice"
        );
        assert_eq!(
            observed[0], observed[1],
            "successive publications must reuse the same warm Go caches"
        );
        let expected_cache_root = graph.join("provider-cache-v1/go");
        assert_eq!(observed[0].0, expected_cache_root.join("build"));
        assert_eq!(observed[0].1, expected_cache_root.join("modules"));
        assert!(observed[0].0.is_dir(), "the warm build cache must survive");
        assert!(observed[0].1.is_dir(), "the warm module cache must survive");
        assert!(
            fs::read_dir(&graph)
                .expect("graph directory remains readable")
                .all(|entry| !entry
                    .expect("graph directory entry")
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".h00-provider-")),
            "disposable provider workspaces must still be reclaimed"
        );
    }
}

fn run_isolated_mixed_parent(test_name: &str) {
    let workspace = TempDir::new().expect("scratch workspace");
    let root = workspace.path().join("repo");
    let graph = workspace.path().join("data");
    let provider_bin = workspace.path().join("bin");
    fs::create_dir_all(root.join("src")).expect("scratch Rust source directory");
    fs::create_dir_all(&graph).expect("scratch publication directory");
    fs::create_dir_all(&provider_bin).expect("scratch provider bin directory");
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("scratch Cargo manifest");
    fs::write(root.join("src/lib.rs"), SOURCE).expect("scratch Rust source");
    fs::write(
        root.join("go.mod"),
        "module example.com/fixture\n\ngo 1.25\n",
    )
    .expect("scratch Go manifest");
    fs::write(root.join("main.go"), GO_SOURCE).expect("scratch Go source");

    let rust_artifact = workspace.path().join("fixture-rust.scip");
    fs::write(
        &rust_artifact,
        fixture_index(&root, true)
            .write_to_bytes()
            .expect("serialize Rust SCIP fixture"),
    )
    .expect("scratch Rust provider artifact");
    let go_artifact = workspace.path().join("fixture-go.scip");
    fs::write(
        &go_artifact,
        go_fixture_index(&root)
            .write_to_bytes()
            .expect("serialize Go SCIP fixture"),
    )
    .expect("scratch Go provider artifact");

    for (name, script) in [
        ("go", GO_TOOLCHAIN_SCRIPT),
        ("rust-analyzer", RUST_PROVIDER_SCRIPT),
        ("scip-go", GO_PROVIDER_SCRIPT),
    ] {
        let provider = provider_bin.join(name);
        fs::write(&provider, script).expect("scratch provider executable");
        let mut permissions = fs::metadata(&provider)
            .expect("provider metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&provider, permissions).expect("provider executable mode");
    }

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut child_paths = vec![provider_bin.clone()];
    child_paths.extend(std::env::split_paths(&original_path));
    let child_path = std::env::join_paths(child_paths).expect("child PATH");
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(CHILD_MODE, "1")
        .env(CHILD_ROOT, &root)
        .env(CHILD_GRAPH, &graph)
        .env(PROVIDER_ARTIFACT, &rust_artifact)
        .env(GO_PROVIDER_ARTIFACT, &go_artifact)
        .env(GO_TOOLCHAIN_BIN, &provider_bin)
        .env("PATH", child_path)
        .output()
        .expect("run isolated mixed production-boundary child");

    assert!(
        output.status.success(),
        "isolated mixed SCIP publication child failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert_no_provider_residue(&root);
}

#[derive(Debug, Eq, PartialEq)]
enum RootArtifactState {
    Absent,
    Regular(Vec<u8>),
    Symlink(PathBuf),
}

fn root_artifact_state(path: &Path) -> RootArtifactState {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return RootArtifactState::Absent;
    };
    if metadata.file_type().is_symlink() {
        RootArtifactState::Symlink(fs::read_link(path).expect("root artifact symlink target"))
    } else {
        RootArtifactState::Regular(fs::read(path).expect("root artifact bytes"))
    }
}

async fn run_root_artifact_policy_child(root: PathBuf, graph: PathBuf) {
    let shape = std::env::var(ROOT_ARTIFACT_SHAPE).expect("root artifact shape");
    let sentinel =
        PathBuf::from(std::env::var_os(ROOT_ARTIFACT_SENTINEL).expect("root artifact sentinel"));
    let provider_executed =
        PathBuf::from(std::env::var_os(PROVIDER_EXECUTED).expect("provider execution marker"));
    let root_artifact = root.join("index.scip");
    let root_artifact_before = root_artifact_state(&root_artifact);
    let sentinel_before = fs::read(&sentinel).ok();
    let config = IndexConfig {
        root: root.clone(),
        full: true,
        scip: ScipMode::Refresh,
        provider_data_root: Some(graph.clone()),
        languages: vec!["rust".into()],
        ..IndexConfig::default()
    };

    if shape == "provider-symlink" {
        let error = publish_fresh_index_generation(&graph, &config, Some("fixture-source".into()))
            .await
            .expect_err("a provider-created ephemeral SCIP symlink must fail publication");
        assert!(
            error.to_string().contains("symlinked generated"),
            "post-provider refusal must retain the typed artifact cause: {error}"
        );
        assert!(
            provider_executed.is_file(),
            "the postcondition control must prove the provider executed"
        );
        assert_eq!(
            root_artifact_state(&root_artifact),
            root_artifact_before,
            "a rejected ephemeral provider output must not touch the project root"
        );
        for head in ["head-0.json", "head-1.json"] {
            assert!(
                !graph
                    .join(h00ligan_engine::code_intel_publication::PUBLICATION_DIRECTORY)
                    .join(head)
                    .exists(),
                "a refused provider output must not publish a head"
            );
        }
        return;
    }

    publish_fresh_index_generation(&graph, &config, Some("fixture-source".into()))
        .await
        .expect("pre-existing root artifacts are outside the provider workspace");
    assert!(
        provider_executed.is_file(),
        "the provider must execute despite an unrelated root artifact"
    );
    assert_eq!(
        root_artifact_state(&root_artifact),
        root_artifact_before,
        "provider execution must preserve every pre-existing root artifact shape and byte"
    );
    assert_eq!(
        fs::read(&sentinel).ok(),
        sentinel_before,
        "provider execution must not create or modify a symlink target"
    );
    assert!(
        graph
            .join(h00ligan_engine::code_intel_publication::PUBLICATION_DIRECTORY)
            .is_dir(),
        "the positive control must publish an immutable generation"
    );
    assert!(!root.join("target").exists());
    assert!(!root.join("Cargo.lock").exists());
}

fn run_isolated_root_artifact_parent(test_name: &str, shape: &str) {
    let workspace = TempDir::new().expect("scratch workspace");
    let root = workspace.path().join("repo");
    let graph = workspace.path().join("data");
    let provider_bin = workspace.path().join("bin");
    fs::create_dir_all(root.join("src")).expect("scratch source directory");
    fs::create_dir_all(&graph).expect("scratch publication directory");
    fs::create_dir_all(&provider_bin).expect("scratch provider bin directory");
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("scratch Cargo manifest");
    fs::write(root.join("src/lib.rs"), SOURCE).expect("scratch source");

    let artifact = workspace.path().join("fixture.scip");
    fs::write(
        &artifact,
        fixture_index(&root, true)
            .write_to_bytes()
            .expect("serialize fixture SCIP index"),
    )
    .expect("scratch provider artifact");

    let provider = provider_bin.join("rust-analyzer");
    fs::write(&provider, RUST_PROVIDER_SCRIPT).expect("scratch provider executable");
    let mut permissions = fs::metadata(&provider)
        .expect("provider metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&provider, permissions).expect("provider executable mode");

    let sentinel = workspace.path().join("outside-index.scip");
    match shape {
        "existing-symlink" => {
            fs::write(&sentinel, b"outside sentinel\n").expect("existing symlink target");
            symlink(&sentinel, root.join("index.scip")).expect("existing-target root symlink");
        }
        "dangling-symlink" => {
            symlink(&sentinel, root.join("index.scip")).expect("dangling root symlink");
        }
        "regular" => {
            fs::write(root.join("index.scip"), b"stale regular artifact\n")
                .expect("pre-existing regular artifact");
        }
        "provider-symlink" => {
            fs::write(
                &sentinel,
                fs::read(&artifact).expect("provider fixture bytes for symlink target"),
            )
            .expect("provider symlink target");
        }
        other => panic!("unknown root artifact shape: {other}"),
    }
    let provider_executed = workspace.path().join("provider-executed.txt");

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut child_paths = vec![provider_bin];
    child_paths.extend(std::env::split_paths(&original_path));
    let child_path = std::env::join_paths(child_paths).expect("child PATH");
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env(CHILD_MODE, "1")
        .env(CHILD_ROOT, &root)
        .env(CHILD_GRAPH, &graph)
        .env(PROVIDER_ARTIFACT, &artifact)
        .env(PROVIDER_EXECUTED, &provider_executed)
        .env(ROOT_ARTIFACT_SHAPE, shape)
        .env(ROOT_ARTIFACT_SENTINEL, &sentinel)
        .env("PATH", child_path)
        .output()
        .expect("run isolated root-artifact policy child");

    assert!(
        output.status.success(),
        "isolated root-artifact policy child failed for {shape}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
async fn successful_scip_generation_publishes_complete_calls_payload() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_child_contract(root, graph).await;
        return;
    }

    run_isolated_parent(
        "successful_scip_generation_publishes_complete_calls_payload",
        true,
        None,
        false,
        None,
    );
}

/// RIGHT-REASON PRODUCT REGRESSION: a wire-valid SCIP artifact cannot borrow
/// authority from a different provider version merely because its tool name,
/// source population, and protobuf shape are otherwise valid.
#[tokio::test]
async fn artifact_provider_version_mismatch_never_grants_calls_authority() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_provider_version_mismatch_child_contract(root, graph).await;
        return;
    }

    run_isolated_parent(
        "artifact_provider_version_mismatch_never_grants_calls_authority",
        true,
        None,
        false,
        Some(MISMATCHED_PROVIDER_VERSION),
    );
}

#[tokio::test]
async fn successive_rust_publications_reuse_surviving_private_provider_cache() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_rust_cache_reuse_child_contract(root, graph).await;
        return;
    }

    run_isolated_parent(
        "successive_rust_publications_reuse_surviving_private_provider_cache",
        true,
        None,
        true,
        None,
    );
}

#[tokio::test]
async fn missing_provider_occurrence_is_partial_by_default_but_strict_mode_fails_closed() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_incomplete_semantic_child_contract(root, graph, "provider_call_occurrence_incomplete")
            .await;
        return;
    }

    run_isolated_parent(
        "missing_provider_occurrence_is_partial_by_default_but_strict_mode_fails_closed",
        false,
        None,
        false,
        None,
    );
}

#[tokio::test]
async fn structurally_unjoinable_provider_payload_is_partial_and_strict_mode_fails_closed() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_incomplete_semantic_child_contract(root, graph, "provider_structural_join_incomplete")
            .await;
        return;
    }

    run_isolated_parent(
        "structurally_unjoinable_provider_payload_is_partial_and_strict_mode_fails_closed",
        true,
        Some("provider_name_that_cannot_join_target"),
        false,
        None,
    );
}

#[tokio::test]
async fn successful_go_scip_generation_uses_the_go_artifact_slot_and_provider() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_go_child_contract(root, graph).await;
        return;
    }

    run_isolated_go_parent(
        "successful_go_scip_generation_uses_the_go_artifact_slot_and_provider",
        false,
        false,
    );
}

#[tokio::test]
async fn successful_go_scip_generation_ignores_external_build_cache_documents() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_go_child_contract(root, graph).await;
        return;
    }

    run_isolated_go_parent(
        "successful_go_scip_generation_ignores_external_build_cache_documents",
        true,
        false,
    );
}

#[tokio::test]
async fn successive_go_publications_reuse_surviving_private_provider_caches() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_go_cache_reuse_child_contract(root, graph).await;
        return;
    }

    run_isolated_go_parent(
        "successive_go_publications_reuse_surviving_private_provider_caches",
        false,
        true,
    );
}

#[tokio::test]
async fn mixed_rust_go_generation_keeps_provider_artifacts_and_payloads_isolated() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_mixed_child_contract(root, graph).await;
        return;
    }

    run_isolated_mixed_parent(
        "mixed_rust_go_generation_keeps_provider_artifacts_and_payloads_isolated",
    );
}

#[tokio::test]
async fn refresh_preserves_existing_and_dangling_root_scip_symlinks() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_root_artifact_policy_child(root, graph).await;
        return;
    }

    for shape in ["existing-symlink", "dangling-symlink"] {
        run_isolated_root_artifact_parent(
            "refresh_preserves_existing_and_dangling_root_scip_symlinks",
            shape,
        );
    }
}

#[tokio::test]
async fn refresh_preserves_a_regular_root_scip_artifact_and_publishes() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_root_artifact_policy_child(root, graph).await;
        return;
    }

    run_isolated_root_artifact_parent(
        "refresh_preserves_a_regular_root_scip_artifact_and_publishes",
        "regular",
    );
}

#[tokio::test]
async fn provider_created_ephemeral_scip_symlink_is_refused_without_publishing_a_head() {
    if std::env::var_os(CHILD_MODE).is_some() {
        let root = PathBuf::from(std::env::var_os(CHILD_ROOT).expect("child root"));
        let graph = PathBuf::from(std::env::var_os(CHILD_GRAPH).expect("child graph"));
        run_root_artifact_policy_child(root, graph).await;
        return;
    }

    run_isolated_root_artifact_parent(
        "provider_created_ephemeral_scip_symlink_is_refused_without_publishing_a_head",
        "provider-symlink",
    );
}
