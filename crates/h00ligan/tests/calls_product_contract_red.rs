//! Real-boundary falsifiers for the first corrected h00ligan domain slice.
//!
//! These tests intentionally describe the product contract we are moving to,
//! not the current duplicated CLI/MCP implementation. Each negative assertion
//! is paired with a positive control that proves the same fixture and boundary
//! can return real data.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use h00ligan_engine::code_intel_domain::{
    CALLS_CONFIGURATION_ID, CallsPopulation, CapabilityReceipt, CapabilityScope, CapabilityStatus,
    ConfigurationId, DocumentMembership, DocumentMembershipKind, EcosystemId, LanguageId,
    ProjectInventory, ProjectInventoryCoverage, ProjectUnit, ProjectUnitId, ProjectUnitKind,
    STRUCTURAL_GRAPH_CONFIGURATION_ID,
};
use h00ligan_engine::code_intel_inventory::{InventorySource, build_project_inventory};
use h00ligan_engine::code_intel_payload::{
    CALLS_PROVIDER_PAYLOAD_SCHEMA, CallsProviderPayload, NormalizedSourceSpan, ProviderCall,
    ProviderCoverageExclusion, ProviderDocument, ProviderLocation, ProviderPayload, ProviderSymbol,
    ProviderSymbolRole,
};
use h00ligan_engine::code_intel_publication::{
    GenerationDraft, SemanticPublisher, resolve_generation,
};
use h00ligan_engine::edge_builder::build_graph;
use h00ligan_engine::entry_points::EntryPointKind;
use h00ligan_engine::extractor::extract_file;
use h00ligan_engine::graph::{EdgeKind, GraphEdge, GraphNode, KnowledgeGraph};
use h00ligan_engine::graph_query::collect_type_children;
use h00ligan_engine::graph_store::{GraphGenerationMetadata, GraphStore};
use h00ligan_engine::index_state::IndexState;
use h00ligan_engine::project_binding::{ProjectBinding, ProjectBindingOptions};
use h00ligan_engine::reachability::{
    ClassifiedNode, PersistedEntryPoint, REACHABILITY_EVIDENCE_SCHEMA, ReachabilityClass,
    ReachabilityEvidence, ReachabilityReport, ReachabilitySummary,
};
use h00ligan_engine::structural_ir::{SymbolRole, symbol_kind_has_role};
use h00ligan_provider_protocol::{
    ProviderFrameLimits, ProviderSemanticEnvironmentInput, ProviderSemanticInputs,
    capture_provider_semantic_inputs,
};
use redb::{ReadableDatabase as _, TableDefinition};
use serde_json::{Value, json};
use tempfile::TempDir;

fn h00ligan() -> Command {
    Command::new(env!("CARGO_BIN_EXE_h00ligan"))
}

#[cfg(unix)]
fn canonical_fixture_path(path: &Path) -> PathBuf {
    std::fs::canonicalize(path)
        .unwrap_or_else(|error| panic!("canonicalize fixture path {}: {error}", path.display()))
}

fn create_source_root(temporary: &TempDir, name: &str, source: &str) -> PathBuf {
    let root = temporary.path().join(name);
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(root.join("src/lib.rs"), source).expect("source fixture");
    root
}

fn file_population(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, current: &Path, population: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = std::fs::read_dir(current)
            .unwrap_or_else(|error| panic!("read {}: {error}", current.display()))
            .map(|entry| entry.expect("directory entry"))
            .collect::<Vec<_>>();
        entries.sort_by_key(std::fs::DirEntry::path);
        for entry in entries {
            let path = entry.path();
            let file_type = entry
                .file_type()
                .unwrap_or_else(|error| panic!("classify {}: {error}", path.display()));
            if file_type.is_dir() {
                collect(root, &path, population);
            } else if file_type.is_file() {
                population.insert(
                    path.strip_prefix(root)
                        .expect("population-relative path")
                        .to_path_buf(),
                    std::fs::read(&path)
                        .unwrap_or_else(|error| panic!("read {}: {error}", path.display())),
                );
            } else if file_type.is_symlink() {
                population.insert(
                    path.strip_prefix(root)
                        .expect("population-relative path")
                        .to_path_buf(),
                    std::fs::read_link(&path)
                        .unwrap_or_else(|error| panic!("read link {}: {error}", path.display()))
                        .as_os_str()
                        .as_encoded_bytes()
                        .to_vec(),
                );
            }
        }
    }

    let mut population = BTreeMap::new();
    collect(root, root, &mut population);
    population
}

#[cfg(unix)]
const SHIPPED_INDEX_SOURCE: &str = "pub fn target() {}\npub fn caller() { target(); }\n";
#[cfg(unix)]
const SHIPPED_TESTS_INDEX_SOURCE: &str = "pub fn target() {}\n#[test]\nfn caller() { target(); }\n";
#[cfg(unix)]
const SHIPPED_INDEX_PROVIDER_VERSION: &str = SHIPPED_EXECUTABLE_PROVIDER_VERSION;
const SHIPPED_EXECUTABLE_PROVIDER_VERSION: &str = "fixture-executable-2026.08.16";
#[cfg(unix)]
const SHIPPED_INDEX_TARGET_SYMBOL: &str = "rust-analyzer cargo fixture_pkg 0.1.0 lib/target().";
#[cfg(unix)]
const SHIPPED_INDEX_CALLER_SYMBOL: &str = "rust-analyzer cargo fixture_pkg 0.1.0 lib/caller().";
#[cfg(unix)]
const SHIPPED_GO_BINDING_SOURCE: &str = concat!(
    "package worker\n",
    "var seam = target\n",
    "func target() {}\n",
    "func caller() { seam() }\n",
    "func outer() { caller() }\n",
);
#[cfg(unix)]
const SHIPPED_GO_BINDING_TEST_SOURCE: &str = concat!(
    "package worker\n",
    "import \"testing\"\n",
    "func TestOuter(_ *testing.T) { outer() }\n",
);
#[cfg(unix)]
const SHIPPED_GO_TAGGED_SOURCE: &str = concat!(
    "//go:build smoke\n",
    "\n",
    "package worker\n",
    "func smokeCaller() { target() }\n",
);
#[cfg(unix)]
const SHIPPED_GO_SEAM_SYMBOL: &str = "scip-go gomod example.test/worker . seam.";
#[cfg(unix)]
const SHIPPED_GO_TARGET_SYMBOL: &str = "scip-go gomod example.test/worker . target().";
#[cfg(unix)]
const SHIPPED_GO_CALLER_SYMBOL: &str = "scip-go gomod example.test/worker . caller().";
#[cfg(unix)]
const SHIPPED_GO_OUTER_SYMBOL: &str = "scip-go gomod example.test/worker . outer().";
#[cfg(unix)]
const SHIPPED_GO_TEST_SYMBOL: &str = "scip-go gomod example.test/worker . TestOuter().";

#[cfg(unix)]
fn protobuf_varint(output: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        output.push(if value == 0 { byte } else { byte | 0x80 });
        if value == 0 {
            return;
        }
    }
}

#[cfg(unix)]
fn protobuf_key(output: &mut Vec<u8>, field: u32, wire_type: u8) {
    protobuf_varint(output, u64::from((field << 3) | u32::from(wire_type)));
}

#[cfg(unix)]
fn protobuf_bytes(output: &mut Vec<u8>, field: u32, value: &[u8]) {
    protobuf_key(output, field, 2);
    protobuf_varint(output, value.len() as u64);
    output.extend_from_slice(value);
}

#[cfg(unix)]
fn protobuf_string(output: &mut Vec<u8>, field: u32, value: &str) {
    protobuf_bytes(output, field, value.as_bytes());
}

#[cfg(unix)]
fn protobuf_int(output: &mut Vec<u8>, field: u32, value: u64) {
    protobuf_key(output, field, 0);
    protobuf_varint(output, value);
}

#[cfg(unix)]
fn protobuf_packed_ints(output: &mut Vec<u8>, field: u32, values: &[u64]) {
    let mut packed = Vec::new();
    for value in values {
        protobuf_varint(&mut packed, *value);
    }
    protobuf_bytes(output, field, &packed);
}

#[cfg(unix)]
fn scip_occurrence(range: &[u64], symbol: &str, definition: bool, extent: &[u64]) -> Vec<u8> {
    let mut occurrence = Vec::new();
    protobuf_packed_ints(&mut occurrence, 1, range);
    protobuf_string(&mut occurrence, 2, symbol);
    if definition {
        protobuf_int(&mut occurrence, 3, 1);
    }
    if !extent.is_empty() {
        protobuf_packed_ints(&mut occurrence, 7, extent);
    }
    occurrence
}

#[cfg(unix)]
fn scip_symbol(symbol: &str, display_name: &str) -> Vec<u8> {
    scip_symbol_with_kind(symbol, display_name, 17)
}

#[cfg(unix)]
fn scip_symbol_with_kind(symbol: &str, display_name: &str, kind: u64) -> Vec<u8> {
    let mut information = Vec::new();
    protobuf_string(&mut information, 1, symbol);
    protobuf_int(&mut information, 5, kind);
    protobuf_string(&mut information, 6, display_name);
    information
}

/// Serialize the minimum valid SCIP protobuf needed by the shipped-index
/// boundary test without adding a second test-only protobuf dependency.
///
/// The fixture still crosses the production decoder and normalizer. Exact
/// provider execution, root identity, document population, definitions, and
/// the sole call occurrence are asserted again through the published result.
#[cfg(unix)]
fn shipped_index_scip_fixture(root: &Path) -> Vec<u8> {
    shipped_index_scip_fixture_with_kinds(root, 17, 17)
}

#[cfg(unix)]
fn shipped_index_scip_fixture_with_kinds(
    root: &Path,
    target_kind: u64,
    caller_kind: u64,
) -> Vec<u8> {
    shipped_index_scip_fixture_for_source_with_kinds(
        root,
        SHIPPED_INDEX_SOURCE,
        target_kind,
        caller_kind,
    )
}

#[cfg(unix)]
fn shipped_index_scip_fixture_for_source_with_kinds(
    root: &Path,
    source: &str,
    target_kind: u64,
    caller_kind: u64,
) -> Vec<u8> {
    let mut tool = Vec::new();
    protobuf_string(&mut tool, 1, "rust-analyzer");
    protobuf_string(&mut tool, 2, SHIPPED_INDEX_PROVIDER_VERSION);
    protobuf_string(&mut tool, 3, "scip");
    protobuf_string(&mut tool, 3, ".");

    let mut metadata = Vec::new();
    protobuf_bytes(&mut metadata, 2, &tool);
    protobuf_string(&mut metadata, 3, &format!("file://{}", root.display()));
    protobuf_int(&mut metadata, 4, 1); // scip.TextEncoding.UTF8

    let (target_line_number, target_line) = source
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains("fn target"))
        .expect("target source line");
    let (caller_line_number, caller_line) = source
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains("fn caller"))
        .expect("caller source line");
    let target_definition = target_line.find("target").expect("target definition") as u64;
    let caller_definition = caller_line.find("caller").expect("caller definition") as u64;
    let target_call = caller_line.rfind("target").expect("target call") as u64;

    let occurrences = [
        scip_occurrence(
            &[
                target_line_number as u64,
                target_definition,
                target_definition + 6,
            ],
            SHIPPED_INDEX_TARGET_SYMBOL,
            true,
            &[
                target_line_number as u64,
                0,
                target_line_number as u64,
                target_line.len() as u64,
            ],
        ),
        scip_occurrence(
            &[
                caller_line_number as u64,
                caller_definition,
                caller_definition + 6,
            ],
            SHIPPED_INDEX_CALLER_SYMBOL,
            true,
            &[
                caller_line_number as u64,
                0,
                caller_line_number as u64,
                caller_line.len() as u64,
            ],
        ),
        scip_occurrence(
            &[caller_line_number as u64, target_call, target_call + 6],
            SHIPPED_INDEX_TARGET_SYMBOL,
            false,
            &[],
        ),
    ];

    let mut document = Vec::new();
    protobuf_string(&mut document, 4, "rust");
    protobuf_string(&mut document, 1, "src/lib.rs");
    for occurrence in occurrences {
        protobuf_bytes(&mut document, 2, &occurrence);
    }
    protobuf_bytes(
        &mut document,
        3,
        &scip_symbol_with_kind(SHIPPED_INDEX_TARGET_SYMBOL, "target", target_kind),
    );
    protobuf_bytes(
        &mut document,
        3,
        &scip_symbol_with_kind(SHIPPED_INDEX_CALLER_SYMBOL, "caller", caller_kind),
    );
    protobuf_string(&mut document, 5, source);
    protobuf_int(&mut document, 6, 1); // UTF8CodeUnitOffsetFromLineStart

    let mut index = Vec::new();
    protobuf_bytes(&mut index, 1, &metadata);
    protobuf_bytes(&mut index, 2, &document);
    index
}

/// Minimal scip-go-compatible artifact with one exact invocation chain ending
/// in a package-level callable-value assignment. This crosses the production
/// decoder, Go syntax corroborator, normalizer, publisher, and query adapters.
#[cfg(unix)]
fn shipped_go_callable_binding_scip_fixture(root: &Path) -> Vec<u8> {
    let source = SHIPPED_GO_BINDING_SOURCE;
    let lines = source.lines().collect::<Vec<_>>();
    let span = |line: usize, name: &str, last: bool| {
        let column = if last {
            lines[line].rfind(name)
        } else {
            lines[line].find(name)
        }
        .unwrap_or_else(|| panic!("missing {name} on fixture line {line}"))
            as u64;
        vec![line as u64, column, column + name.len() as u64]
    };
    let extent = |line: usize| vec![line as u64, 0, line as u64, lines[line].len() as u64];

    let mut tool = Vec::new();
    protobuf_string(&mut tool, 1, "scip-go");
    protobuf_string(&mut tool, 2, "0.2.7");
    protobuf_string(&mut tool, 3, "index");

    let mut metadata = Vec::new();
    protobuf_bytes(&mut metadata, 2, &tool);
    protobuf_string(&mut metadata, 3, &format!("file://{}", root.display()));
    protobuf_int(&mut metadata, 4, 1); // scip.TextEncoding.UTF8

    let occurrences = [
        scip_occurrence(
            &span(1, "seam", false),
            SHIPPED_GO_SEAM_SYMBOL,
            true,
            &extent(1),
        ),
        scip_occurrence(
            &span(1, "target", true),
            SHIPPED_GO_TARGET_SYMBOL,
            false,
            &[],
        ),
        scip_occurrence(
            &span(2, "target", false),
            SHIPPED_GO_TARGET_SYMBOL,
            true,
            &extent(2),
        ),
        scip_occurrence(
            &span(3, "caller", false),
            SHIPPED_GO_CALLER_SYMBOL,
            true,
            &extent(3),
        ),
        scip_occurrence(&span(3, "seam", true), SHIPPED_GO_SEAM_SYMBOL, false, &[]),
        scip_occurrence(
            &span(4, "outer", false),
            SHIPPED_GO_OUTER_SYMBOL,
            true,
            &extent(4),
        ),
        scip_occurrence(
            &span(4, "caller", true),
            SHIPPED_GO_CALLER_SYMBOL,
            false,
            &[],
        ),
    ];

    let mut document = Vec::new();
    protobuf_string(&mut document, 4, "go");
    protobuf_string(&mut document, 1, "worker.go");
    for occurrence in occurrences {
        protobuf_bytes(&mut document, 2, &occurrence);
    }
    for (symbol, display_name, kind) in [
        (SHIPPED_GO_SEAM_SYMBOL, "seam", 61),
        (SHIPPED_GO_TARGET_SYMBOL, "target", 17),
        (SHIPPED_GO_CALLER_SYMBOL, "caller", 17),
        (SHIPPED_GO_OUTER_SYMBOL, "outer", 17),
    ] {
        protobuf_bytes(
            &mut document,
            3,
            &scip_symbol_with_kind(symbol, display_name, kind),
        );
    }
    protobuf_string(&mut document, 5, source);
    // scip-go 0.2.7 declares UTF-8 at artifact level but leaves this
    // document field unset. The production normalizer has one exact,
    // provider-identity-gated byte-column contract for that upstream shape.

    let test_source = SHIPPED_GO_BINDING_TEST_SOURCE;
    let test_lines = test_source.lines().collect::<Vec<_>>();
    let test_span = |line: usize, name: &str, last: bool| {
        let column = if last {
            test_lines[line].rfind(name)
        } else {
            test_lines[line].find(name)
        }
        .unwrap_or_else(|| panic!("missing {name} on fixture test line {line}"))
            as u64;
        vec![line as u64, column, column + name.len() as u64]
    };
    let mut test_document = Vec::new();
    protobuf_string(&mut test_document, 4, "go");
    protobuf_string(&mut test_document, 1, "worker_test.go");
    protobuf_bytes(
        &mut test_document,
        2,
        &scip_occurrence(
            &test_span(2, "TestOuter", false),
            SHIPPED_GO_TEST_SYMBOL,
            true,
            &[2, 0, 2, test_lines[2].len() as u64],
        ),
    );
    protobuf_bytes(
        &mut test_document,
        2,
        &scip_occurrence(
            &test_span(2, "outer", true),
            SHIPPED_GO_OUTER_SYMBOL,
            false,
            &[],
        ),
    );
    protobuf_bytes(
        &mut test_document,
        3,
        &scip_symbol_with_kind(SHIPPED_GO_TEST_SYMBOL, "TestOuter", 17),
    );
    protobuf_string(&mut test_document, 5, test_source);

    let mut index = Vec::new();
    protobuf_bytes(&mut index, 1, &metadata);
    protobuf_bytes(&mut index, 2, &document);
    protobuf_bytes(&mut index, 2, &test_document);
    index
}

#[cfg(unix)]
fn definition_only_scip_fixture(
    project_root: &Path,
    document_path: &str,
    source: &str,
    package: &str,
    function: &str,
    called_symbol: Option<(&str, &str)>,
) -> Vec<u8> {
    let mut tool = Vec::new();
    protobuf_string(&mut tool, 1, "rust-analyzer");
    protobuf_string(&mut tool, 2, SHIPPED_INDEX_PROVIDER_VERSION);
    protobuf_string(&mut tool, 3, "scip");
    protobuf_string(&mut tool, 3, ".");

    let mut metadata = Vec::new();
    protobuf_bytes(&mut metadata, 2, &tool);
    protobuf_string(
        &mut metadata,
        3,
        &format!("file://{}", project_root.display()),
    );
    protobuf_int(&mut metadata, 4, 1); // scip.TextEncoding.UTF8

    let (definition_line, definition_source_line) = source
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains(&format!("fn {function}")))
        .unwrap_or_else(|| panic!("fixture source must define {function}"));
    let definition = definition_source_line
        .find(function)
        .expect("fixture function definition") as u64;
    let symbol = format!("rust-analyzer cargo {package} 0.1.0 lib/{function}().");
    let mut occurrences = vec![scip_occurrence(
        &[
            definition_line as u64,
            definition,
            definition + function.len() as u64,
        ],
        &symbol,
        true,
        &[
            definition_line as u64,
            0,
            definition_line as u64,
            definition_source_line.len() as u64,
        ],
    )];
    if let Some((called_name, called_symbol)) = called_symbol {
        let (call_line, call_source_line) = source
            .lines()
            .enumerate()
            .find(|(_, line)| line.contains(&format!("{called_name}()")))
            .unwrap_or_else(|| panic!("fixture source must call {called_name}"));
        let call = call_source_line
            .rfind(called_name)
            .expect("fixture call range") as u64;
        occurrences.push(scip_occurrence(
            &[call_line as u64, call, call + called_name.len() as u64],
            called_symbol,
            false,
            &[],
        ));
    }

    let mut document = Vec::new();
    protobuf_string(&mut document, 4, "rust");
    protobuf_string(&mut document, 1, document_path);
    for occurrence in occurrences {
        protobuf_bytes(&mut document, 2, &occurrence);
    }
    protobuf_bytes(&mut document, 3, &scip_symbol(&symbol, function));
    protobuf_string(&mut document, 5, source);
    protobuf_int(&mut document, 6, 1); // UTF8CodeUnitOffsetFromLineStart

    let mut index = Vec::new();
    protobuf_bytes(&mut index, 1, &metadata);
    protobuf_bytes(&mut index, 2, &document);
    index
}

#[cfg(unix)]
fn install_fixture_rust_analyzer(
    workspace: &Path,
    root: &Path,
) -> (PathBuf, PathBuf, std::ffi::OsString) {
    install_fixture_rust_analyzer_for_source(workspace, root, SHIPPED_INDEX_SOURCE)
}

#[cfg(unix)]
fn install_fixture_rust_analyzer_for_source(
    workspace: &Path,
    root: &Path,
    source: &str,
) -> (PathBuf, PathBuf, std::ffi::OsString) {
    let provider_bin = workspace.join("bin");
    let provider_artifact = workspace.join("fixture.scip");
    let provider_executed = workspace.join("provider-executed");
    std::fs::create_dir_all(&provider_bin).expect("fixture provider bin");
    std::fs::write(
        &provider_artifact,
        shipped_index_scip_fixture_for_source_with_kinds(root, source, 17, 17),
    )
    .expect("fixture SCIP artifact");

    let provider = provider_bin.join("rust-analyzer");
    std::fs::write(
        &provider,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then printf '%s\\n' 'rust-analyzer fixture-executable-2026.08.16'; exit 0; fi\n\
         if [ \"$1\" = \"scip\" ]; then\n\
           printf '%s\\n' 'executed' > \"$H00_TEST_PROVIDER_EXECUTED\"\n\
           shift\n\
           output=''\n\
           while [ \"$#\" -gt 0 ]; do\n\
             if [ \"$1\" = \"--output\" ]; then shift; output=$1; fi\n\
             shift\n\
           done\n\
           [ -n \"$output\" ] || exit 65\n\
           case \"$output\" in \"$PWD\"/*) exit 66 ;; esac\n\
           case \"$CARGO_TARGET_DIR\" in \"$PWD\"/*|'') exit 67 ;; esac\n\
           cp \"$H00_TEST_PROVIDER_ARTIFACT\" \"$output\"\n\
           exit 0\n\
         fi\n\
         exit 64\n",
    )
    .expect("fixture provider executable");
    let mut permissions = std::fs::metadata(&provider)
        .expect("fixture provider metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&provider, permissions).expect("fixture provider mode");

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![provider_bin];
    paths.extend(std::env::split_paths(&original_path));
    let path = std::env::join_paths(paths).expect("fixture provider PATH");
    (provider_artifact, provider_executed, path)
}

#[cfg(unix)]
fn install_fixture_scip_go_callable_binding(
    workspace: &Path,
    root: &Path,
) -> (PathBuf, PathBuf, std::ffi::OsString) {
    let provider_bin = workspace.join("go-bin");
    let go_root = provider_bin.join("go-root");
    let provider_artifact = workspace.join("go-binding.scip");
    let provider_executed = workspace.join("go-provider-executed");
    std::fs::create_dir_all(go_root.join("bin")).expect("fixture Go toolchain root");
    std::fs::write(
        &provider_artifact,
        shipped_go_callable_binding_scip_fixture(root),
    )
    .expect("fixture Go SCIP artifact");

    let provider = provider_bin.join("scip-go");
    let provider_script = format!(
        "#!/bin/sh\n\
         artifact='{}'\n\
         executed='{}'\n\
         if [ \"$1\" = \"--version\" ]; then printf '%s\\n' 'scip-go 0.2.7'; exit 0; fi\n\
         if [ \"$1\" = \"index\" ]; then\n\
           printf '%s\\n' \"$PWD\" > \"$executed\"\n\
           shift\n\
           output=''\n\
           while [ \"$#\" -gt 0 ]; do\n\
             if [ \"$1\" = \"-o\" ]; then shift; output=$1; fi\n\
             shift\n\
           done\n\
           [ -n \"$output\" ] || exit 65\n\
           case \"$output\" in \"$PWD\"/*) exit 66 ;; esac\n\
           cp \"$artifact\" \"$output\"\n\
           exit 0\n\
         fi\n\
         exit 64\n",
        provider_artifact.display(),
        provider_executed.display(),
    );
    std::fs::write(&provider, provider_script).expect("fixture scip-go executable");
    let mut permissions = std::fs::metadata(&provider)
        .expect("fixture scip-go metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&provider, permissions).expect("fixture scip-go mode");

    let go = provider_bin.join("go");
    std::fs::write(
        &go,
        format!(
            "#!/bin/sh\n\
             if [ \"$1\" = \"version\" ]; then printf '%s\\n' 'go version go1.26.0 linux/amd64'; exit 0; fi\n\
             if [ \"$1\" = \"env\" ] && [ \"$2\" = \"GOROOT\" ]; then printf '%s\\n' '{}'; exit 0; fi\n\
             exit 64\n",
            go_root.display(),
        ),
    )
    .expect("fixture go executable");
    let mut permissions = std::fs::metadata(&go)
        .expect("fixture go metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&go, permissions).expect("fixture go mode");
    let effective_go = go_root.join("bin/go");
    std::fs::write(
        &effective_go,
        "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then printf '%s\\n' 'go version go1.26.0 linux/amd64'; exit 0; fi\nexit 64\n",
    )
    .expect("fixture effective go executable");
    let mut permissions = std::fs::metadata(&effective_go)
        .expect("fixture effective go metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&effective_go, permissions).expect("fixture effective go mode");

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![provider_bin];
    paths.extend(std::env::split_paths(&original_path));
    let path = std::env::join_paths(paths).expect("fixture scip-go PATH");
    (provider_artifact, provider_executed, path)
}

#[cfg(unix)]
struct MultiRootFixtureProvider {
    root_artifact: PathBuf,
    detached_artifact: PathBuf,
    execution_log: PathBuf,
    path: std::ffi::OsString,
}

#[cfg(unix)]
fn install_multiroot_fixture_rust_analyzer(
    workspace: &Path,
    root: &Path,
    detached: &Path,
    detached_source: &str,
) -> MultiRootFixtureProvider {
    let provider_bin = workspace.join("multiroot-bin");
    let root_artifact = workspace.join("root.scip");
    let detached_artifact = workspace.join("detached.scip");
    let execution_log = workspace.join("provider-executions");
    std::fs::create_dir_all(&provider_bin).expect("fixture provider bin");
    std::fs::write(&root_artifact, shipped_index_scip_fixture(root)).expect("root SCIP artifact");
    std::fs::write(
        &detached_artifact,
        definition_only_scip_fixture(
            detached,
            "src/lib.rs",
            detached_source,
            "detached_fixture",
            "detached_only",
            Some(("target", SHIPPED_INDEX_TARGET_SYMBOL)),
        ),
    )
    .expect("detached SCIP artifact");

    let provider = provider_bin.join("rust-analyzer");
    std::fs::write(
        &provider,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then printf '%s\\n' 'rust-analyzer fixture-executable-2026.08.16'; exit 0; fi\n\
         if [ \"$1\" = \"scip\" ]; then\n\
           printf '%s\\n' \"$PWD\" >> \"$H00_TEST_PROVIDER_EXECUTION_LOG\"\n\
           shift\n\
           output=''\n\
           while [ \"$#\" -gt 0 ]; do\n\
             if [ \"$1\" = \"--output\" ]; then shift; output=$1; fi\n\
             shift\n\
           done\n\
           [ -n \"$output\" ] || exit 65\n\
           case \"$output\" in \"$PWD\"/*) exit 66 ;; esac\n\
           case \"$CARGO_TARGET_DIR\" in \"$PWD\"/*|'') exit 67 ;; esac\n\
           if [ \"$PWD\" = \"$H00_TEST_PROVIDER_ROOT\" ]; then\n\
             cp \"$H00_TEST_PROVIDER_ROOT_ARTIFACT\" \"$output\"\n\
           elif [ \"$PWD\" = \"$H00_TEST_PROVIDER_DETACHED\" ]; then\n\
             cp \"$H00_TEST_PROVIDER_DETACHED_ARTIFACT\" \"$output\"\n\
           else\n\
             exit 68\n\
           fi\n\
           exit 0\n\
         fi\n\
         exit 64\n",
    )
    .expect("fixture provider executable");
    let mut permissions = std::fs::metadata(&provider)
        .expect("fixture provider metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&provider, permissions).expect("fixture provider mode");

    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![provider_bin];
    paths.extend(std::env::split_paths(&original_path));
    let path = std::env::join_paths(paths).expect("fixture provider PATH");
    MultiRootFixtureProvider {
        root_artifact,
        detached_artifact,
        execution_log,
        path,
    }
}

fn node(name: &str, file: &str, line: usize) -> GraphNode {
    GraphNode {
        memory_id: uuid::Uuid::new_v4(),
        symbol_name: name.into(),
        kind: "function".into(),
        file_path: file.into(),
        content_hash: format!("hash-{name}"),
        signature: format!("fn {name}()"),
        reachability_class: ReachabilityClass::Wired,
        line_start: Some(line),
        line_end: Some(line),
        has_body: Some(true),
        visibility: "pub".into(),
        is_test_only: Some(false),
        is_test_root: false,
        has_platform_cfg: false,
        rustc_flagged_dead: false,
        entry_retain: Default::default(),
        has_uncaptured_items: false,
        oracle_receipt: None,
    }
}

fn fixture_reachability_evidence(
    graph: &KnowledgeGraph,
    mut entry_points: Vec<PersistedEntryPoint>,
) -> ReachabilityEvidence {
    entry_points.sort();
    entry_points.dedup();

    let mut classified = graph
        .all_nodes()
        .into_iter()
        .map(|node| ClassifiedNode {
            memory_id: node.memory_id,
            symbol_name: node.symbol_name.clone(),
            file_path: node.file_path.clone(),
            kind: node.kind.clone(),
            classification: node.reachability_class,
            has_retain_attr: node.entry_retain.has_retain_attr(),
            has_uncaptured_items: node.has_uncaptured_items,
        })
        .collect::<Vec<_>>();
    classified.sort_by_key(|node| node.memory_id);

    let mut summary = ReachabilitySummary {
        total: classified.len(),
        wired: 0,
        public_api: 0,
        structural: 0,
        test_only: 0,
        dead: 0,
        orphan_files: 0,
        suspected: 0,
        excluded: 0,
    };
    for node in &classified {
        match node.classification {
            ReachabilityClass::Wired => summary.wired += 1,
            ReachabilityClass::PublicApi => summary.public_api += 1,
            ReachabilityClass::Structural => summary.structural += 1,
            ReachabilityClass::TestOnly => summary.test_only += 1,
            ReachabilityClass::Dead => summary.dead += 1,
            ReachabilityClass::Suspected => summary.suspected += 1,
            ReachabilityClass::Excluded => summary.excluded += 1,
            ReachabilityClass::Orphan | ReachabilityClass::Unclassified => {}
        }
    }

    let materialized = entry_points
        .iter()
        .map(PersistedEntryPoint::as_entry_point)
        .collect::<Vec<_>>();
    let mut trace_root_ids =
        h00ligan_engine::graph_query::resolve_production_root_ids(graph, &materialized);
    trace_root_ids.sort_unstable();
    trace_root_ids.dedup();

    let evidence = ReachabilityEvidence {
        schema: REACHABILITY_EVIDENCE_SCHEMA.into(),
        report: ReachabilityReport {
            classified,
            summary,
            entry_points_used: entry_points
                .iter()
                .map(|entry_point| {
                    format!(
                        "{} [{}] ({})",
                        entry_point.name, entry_point.kind, entry_point.crate_name
                    )
                })
                .collect(),
            orphan_files: Vec::new(),
            test_chains: BTreeMap::new(),
        },
        classified_documents: graph
            .all_nodes()
            .into_iter()
            .filter(|node| h00ligan_engine::graph_stats::node_language(node).is_some())
            .map(|node| node.file_path.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        entry_points,
        trace_root_ids,
    };
    evidence
        .validate(graph)
        .expect("fixture reachability evidence");
    evidence
}

#[derive(Debug)]
struct SeededCallsGeneration {
    generation_id: String,
    repository_id: String,
    database_path: PathBuf,
    project_unit_ids: Vec<String>,
    call_spans: Vec<NormalizedSourceSpan>,
}

fn source_span(source: &str, start_byte: usize, end_byte: usize) -> NormalizedSourceSpan {
    assert!(start_byte < end_byte);
    assert!(end_byte <= source.len());
    assert!(source.is_char_boundary(start_byte));
    assert!(source.is_char_boundary(end_byte));

    let position = |offset: usize| {
        let prefix = &source[..offset];
        let line = prefix.bytes().filter(|byte| *byte == b'\n').count();
        let line_start = prefix.rfind('\n').map_or(0, |newline| newline + 1);
        (line as u32, (offset - line_start) as u32)
    };
    let (start_line, start_utf8_byte_column) = position(start_byte);
    let (end_line, end_utf8_byte_column) = position(end_byte);
    NormalizedSourceSpan {
        start_byte: start_byte as u64,
        end_byte: end_byte as u64,
        start_line,
        start_utf8_byte_column,
        end_line,
        end_utf8_byte_column,
    }
}

fn function_extent(source: &str, name: &str) -> (NormalizedSourceSpan, NormalizedSourceSpan) {
    let declaration = format!("fn {name}(");
    let declaration_start = source
        .find(&declaration)
        .unwrap_or_else(|| panic!("missing function declaration {declaration}"));
    let name_start = declaration_start + "fn ".len();
    let line_start = source[..declaration_start]
        .rfind('\n')
        .map_or(0, |newline| newline + 1);
    let line_end = source[declaration_start..]
        .find('\n')
        .map_or(source.len(), |relative| declaration_start + relative);
    (
        source_span(source, name_start, name_start + name.len()),
        source_span(source, line_start, line_end),
    )
}

const fn graph_source_span(span: &NormalizedSourceSpan) -> h00ligan_engine::graph::SourceSpan {
    h00ligan_engine::graph::SourceSpan {
        start_byte: span.start_byte as usize,
        end_byte: span.end_byte as usize,
    }
}

async fn seed_calls_bundle(
    root: &Path,
    data_dir: &Path,
    caller_names: &[&str],
) -> SeededCallsGeneration {
    let edges = caller_names
        .iter()
        .map(|caller| CallsFixtureEdge {
            caller,
            callee: "target",
            is_test_only: false,
            is_test_root: false,
        })
        .collect::<Vec<_>>();
    seed_calls_topology_bundle(root, data_dir, &edges, false).await
}

async fn seed_test_calls_bundle(
    root: &Path,
    data_dir: &Path,
    caller_names: &[&str],
) -> SeededCallsGeneration {
    let edges = caller_names
        .iter()
        .map(|caller| CallsFixtureEdge {
            caller,
            callee: "target",
            is_test_only: true,
            is_test_root: true,
        })
        .collect::<Vec<_>>();
    seed_calls_topology_bundle(root, data_dir, &edges, true).await
}

#[derive(Clone, Copy)]
struct CallsFixtureEdge<'a> {
    caller: &'a str,
    callee: &'a str,
    is_test_only: bool,
    is_test_root: bool,
}

struct CallsFixtureOptions<'a> {
    edges: &'a [CallsFixtureEdge<'a>],
    structural_authority: bool,
    materialize_graph_edges: bool,
    symbol_documents: &'a BTreeMap<String, String>,
    reachability_overrides: &'a BTreeMap<String, ReachabilityClass>,
    visibility_overrides: &'a BTreeMap<String, String>,
    provider_omissions: &'a BTreeSet<String>,
    provider_exclusions: &'a BTreeMap<String, String>,
    semantic_inputs: ProviderSemanticInputs,
    project_inventory: Option<ProjectInventory>,
}

async fn seed_calls_topology_bundle(
    root: &Path,
    data_dir: &Path,
    edges: &[CallsFixtureEdge<'_>],
    structural_authority: bool,
) -> SeededCallsGeneration {
    seed_calls_topology_bundle_with_documents(
        root,
        data_dir,
        edges,
        structural_authority,
        &BTreeMap::new(),
    )
    .await
}

async fn seed_audit_scope_bundle(
    root: &Path,
    data_dir: &Path,
    edges: &[CallsFixtureEdge<'_>],
) -> SeededCallsGeneration {
    let symbol_documents = BTreeMap::new();
    let reachability_overrides = BTreeMap::new();
    let visibility_overrides = BTreeMap::new();
    let provider_omissions = BTreeSet::new();
    let provider_exclusions = BTreeMap::new();
    seed_calls_topology_bundle_with_documents_and_node_overrides_and_provider_omissions(
        root,
        data_dir,
        CallsFixtureOptions {
            edges,
            structural_authority: true,
            materialize_graph_edges: true,
            symbol_documents: &symbol_documents,
            reachability_overrides: &reachability_overrides,
            visibility_overrides: &visibility_overrides,
            provider_omissions: &provider_omissions,
            provider_exclusions: &provider_exclusions,
            semantic_inputs: ProviderSemanticInputs::empty(),
            project_inventory: None,
        },
    )
    .await
}

async fn seed_calls_topology_bundle_with_documents(
    root: &Path,
    data_dir: &Path,
    edges: &[CallsFixtureEdge<'_>],
    structural_authority: bool,
    symbol_documents: &BTreeMap<String, String>,
) -> SeededCallsGeneration {
    seed_calls_topology_bundle_with_documents_and_reachability(
        root,
        data_dir,
        edges,
        structural_authority,
        symbol_documents,
        &BTreeMap::new(),
    )
    .await
}

async fn seed_calls_topology_bundle_with_documents_and_reachability(
    root: &Path,
    data_dir: &Path,
    edges: &[CallsFixtureEdge<'_>],
    structural_authority: bool,
    symbol_documents: &BTreeMap<String, String>,
    reachability_overrides: &BTreeMap<String, ReachabilityClass>,
) -> SeededCallsGeneration {
    seed_calls_topology_bundle_with_documents_and_node_overrides(
        root,
        data_dir,
        edges,
        structural_authority,
        symbol_documents,
        reachability_overrides,
        &BTreeMap::new(),
    )
    .await
}

async fn seed_calls_topology_bundle_with_documents_and_node_overrides(
    root: &Path,
    data_dir: &Path,
    edges: &[CallsFixtureEdge<'_>],
    structural_authority: bool,
    symbol_documents: &BTreeMap<String, String>,
    reachability_overrides: &BTreeMap<String, ReachabilityClass>,
    visibility_overrides: &BTreeMap<String, String>,
) -> SeededCallsGeneration {
    let provider_omissions = BTreeSet::new();
    let provider_exclusions = BTreeMap::new();
    seed_calls_topology_bundle_with_documents_and_node_overrides_and_provider_omissions(
        root,
        data_dir,
        CallsFixtureOptions {
            edges,
            structural_authority,
            materialize_graph_edges: false,
            symbol_documents,
            reachability_overrides,
            visibility_overrides,
            provider_omissions: &provider_omissions,
            provider_exclusions: &provider_exclusions,
            semantic_inputs: ProviderSemanticInputs::empty(),
            project_inventory: None,
        },
    )
    .await
}

async fn seed_calls_topology_bundle_with_documents_and_node_overrides_and_provider_omissions(
    root: &Path,
    data_dir: &Path,
    options: CallsFixtureOptions<'_>,
) -> SeededCallsGeneration {
    let CallsFixtureOptions {
        edges,
        structural_authority,
        materialize_graph_edges,
        symbol_documents,
        reachability_overrides,
        visibility_overrides,
        provider_omissions,
        provider_exclusions,
        semantic_inputs,
        project_inventory,
    } = options;
    std::fs::create_dir_all(data_dir).expect("graph directory");
    let binding = ProjectBinding::resolve(
        ProjectBindingOptions::new(root)
            .explicit_root(root)
            .global_graph_dir(data_dir),
    )
    .expect("project binding");

    let mut document_paths = BTreeMap::from([("src/lib.rs".to_owned(), ())]);
    for document_path in symbol_documents.values() {
        document_paths.insert(document_path.clone(), ());
    }
    let sources = document_paths
        .into_keys()
        .map(|document_path| {
            let source = std::fs::read_to_string(root.join(&document_path))
                .unwrap_or_else(|error| panic!("read fixture {document_path}: {error}"));
            (document_path, source)
        })
        .collect::<BTreeMap<_, _>>();
    let symbol_document = |symbol_name: &str| {
        symbol_documents
            .get(symbol_name)
            .map_or("src/lib.rs", String::as_str)
    };
    let mut graph = KnowledgeGraph::new();
    let mut graph_ids = BTreeMap::new();
    let mut classifications = BTreeMap::new();
    for edge in edges {
        assert!(
            !provider_omissions.contains(edge.caller) && !provider_omissions.contains(edge.callee),
            "an intentionally unjoined structural callable cannot participate in provider calls"
        );
        classifications.entry(edge.caller).or_insert((false, false));
        classifications.entry(edge.callee).or_insert((false, false));
    }
    for symbol_name in provider_omissions {
        classifications
            .entry(symbol_name.as_str())
            .or_insert((false, false));
    }
    let mut classified_callers = std::collections::BTreeSet::new();
    for edge in edges {
        if classified_callers.insert(edge.caller) {
            classifications.insert(edge.caller, (edge.is_test_only, edge.is_test_root));
        } else {
            assert_eq!(
                classifications[edge.caller],
                (edge.is_test_only, edge.is_test_root),
                "fixture caller classification must be stable"
            );
        }
    }
    for (symbol_name, (is_test_only, is_test_root)) in &classifications {
        let document_path = symbol_document(symbol_name);
        let source = &sources[document_path];
        let (definition, extent) = function_extent(source, symbol_name);
        let mut symbol = node(symbol_name, document_path, definition.start_line as usize);
        if let Some(reachability) = reachability_overrides.get(*symbol_name) {
            symbol.reachability_class = *reachability;
        }
        if let Some(visibility) = visibility_overrides.get(*symbol_name) {
            symbol.visibility.clone_from(visibility);
        }
        symbol.content_hash = h00ligan_engine::extractor::extract_source(source, document_path)
            .expect("extract fixture source authority")
            .symbols
            .into_iter()
            .find(|extracted| extracted.name == *symbol_name)
            .unwrap_or_else(|| panic!("missing extracted fixture symbol {symbol_name}"))
            .content_hash;
        symbol.is_test_only = Some(*is_test_only);
        symbol.is_test_root = *is_test_root;
        let symbol_id = symbol.memory_id;
        graph.add_node(symbol).expect("fixture graph node");
        graph_ids.insert(*symbol_name, symbol_id);
        graph
            .set_source_span(symbol_id, graph_source_span(&extent))
            .expect("fixture graph source span");
    }
    if materialize_graph_edges {
        for edge in edges {
            graph
                .add_edge(
                    graph_ids[edge.caller],
                    graph_ids[edge.callee],
                    GraphEdge {
                        kind: EdgeKind::Calls,
                        source: h00ligan_engine::graph::EdgeSource::Scip,
                        scope: if edge.is_test_only {
                            h00ligan_engine::graph::EdgeScope::Test
                        } else {
                            h00ligan_engine::graph::EdgeScope::Production
                        },
                        ..GraphEdge::default()
                    },
                )
                .expect("fixture materialized Calls edge");
        }
    }

    let workspace_unit_id = ProjectUnitId::new("rust:test:workspace");
    let nested_unit_id = ProjectUnitId::new("rust:test:nested");
    let project_inventory = project_inventory.unwrap_or_else(|| ProjectInventory {
        coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
        project_topology: h00ligan_engine::code_intel_domain::ProjectTopology {
            units: vec![
                ProjectUnit {
                    project_unit_id: workspace_unit_id.clone(),
                    language_id: LanguageId::new("rust"),
                    ecosystem_id: EcosystemId::new("cargo"),
                    kind: ProjectUnitKind::Workspace,
                    root_path: String::new(),
                    manifest_path: None,
                    compilation_root_paths: Vec::new(),
                },
                ProjectUnit {
                    project_unit_id: nested_unit_id.clone(),
                    language_id: LanguageId::new("rust"),
                    ecosystem_id: EcosystemId::new("cargo"),
                    kind: ProjectUnitKind::Package,
                    root_path: "src".into(),
                    manifest_path: None,
                    compilation_root_paths: Vec::new(),
                },
            ],
            memberships: sources
                .keys()
                .flat_map(|document_path| {
                    let mut memberships = vec![DocumentMembership {
                        document_path: document_path.clone(),
                        language_id: LanguageId::new("rust"),
                        project_unit_id: workspace_unit_id.clone(),
                        kind: DocumentMembershipKind::SourceOwner,
                    }];
                    if document_path.starts_with("src/") {
                        memberships.push(DocumentMembership {
                            document_path: document_path.clone(),
                            language_id: LanguageId::new("rust"),
                            project_unit_id: nested_unit_id.clone(),
                            kind: DocumentMembershipKind::PathContext,
                        });
                    }
                    memberships
                })
                .collect(),
            relationships: Vec::new(),
            exact_workspace_member_sets: Vec::new(),
            dependency_graphs: Vec::new(),
        },
        analysis_context_graphs: Vec::new(),
        inputs: Vec::new(),
        issues: Vec::new(),
    });
    let receipt = CapabilityReceipt::complete(
        "calls",
        "fixture-scip",
        "1.0.0",
        CapabilityScope::Repository {
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        },
        "a".repeat(64),
    );
    let mut receipts = vec![receipt.clone()];
    if structural_authority {
        receipts.push(CapabilityReceipt::complete(
            "structural_graph",
            "fixture-structural",
            "1.0.0",
            CapabilityScope::Language {
                language_id: LanguageId::new("rust"),
                configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
            },
            "c".repeat(64),
        ));
    }

    let location = |document_path: &str, span| ProviderLocation {
        document_path: document_path.into(),
        span,
    };
    let mut provider_ids = BTreeMap::new();
    let mut symbols = Vec::new();
    for symbol_name in classifications.keys() {
        if provider_omissions.contains(*symbol_name) {
            continue;
        }
        let document_path = symbol_document(symbol_name);
        let source = &sources[document_path];
        let (definition, extent) = function_extent(source, symbol_name);
        let provider_symbol_id = format!("rust fixture symbol {symbol_name}");
        provider_ids.insert(*symbol_name, provider_symbol_id.clone());
        symbols.push(ProviderSymbol {
            provider_symbol_id,
            name: (*symbol_name).into(),
            provider_kind: "function".into(),
            language_id: LanguageId::new("rust"),
            role: ProviderSymbolRole::SourceInvocationTarget,
            definition: Some(location(document_path, definition)),
            structural_extent: Some(location(document_path, extent.clone())),
            call_owner_extent: Some(location(document_path, extent)),
        });
    }
    let mut calls = Vec::new();
    let mut call_spans = Vec::new();
    for edge in edges {
        let caller_document = symbol_document(edge.caller);
        let source = &sources[caller_document];
        let (_, extent) = function_extent(source, edge.caller);
        let extent_start = extent.start_byte as usize;
        let extent_end = extent.end_byte as usize;
        let invocation = format!("{}()", edge.callee);
        let relative_call = source[extent_start..extent_end]
            .find(&invocation)
            .unwrap_or_else(|| panic!("missing {} call in {}", edge.callee, edge.caller));
        let call_start = extent_start + relative_call;
        let call_span = source_span(source, call_start, call_start + edge.callee.len());
        calls.push(ProviderCall {
            caller_symbol_id: provider_ids[edge.caller].clone(),
            callee_symbol_id: provider_ids[edge.callee].clone(),
            call_site: location(caller_document, call_span.clone()),
        });
        call_spans.push(call_span);
    }
    let coverage_exclusions = provider_exclusions
        .iter()
        .map(|(symbol_name, reason_code)| {
            let document_path = symbol_document(symbol_name);
            let source = &sources[document_path];
            let (_, extent) = function_extent(source, symbol_name);
            ProviderCoverageExclusion {
                location: location(document_path, extent),
                reason_code: reason_code.clone(),
            }
        })
        .collect();
    let payload = ProviderPayload::Calls(CallsProviderPayload {
        schema_version: CALLS_PROVIDER_PAYLOAD_SCHEMA.into(),
        population: CallsPopulation::ProviderResolvedExplicitSourceInvocations,
        receipt: receipt.clone(),
        semantic_inputs,
        execution_authority:
            h00ligan_engine::code_intel_payload::ProviderExecutionAuthority::InvocationBound {
                provider_configurations_sha256: BTreeMap::new(),
            },
        canonical_snapshot_sha256: None,
        documents: sources
            .iter()
            .map(|(document_path, source)| ProviderDocument {
                document_path: document_path.clone(),
                language_id: LanguageId::new("rust"),
                content_sha256: "b".repeat(64),
                cross_document_surface_sha256: "c".repeat(64),
                byte_length: source.len() as u64,
            })
            .collect(),
        symbols,
        calls,
        callable_bindings: Vec::new(),
        coverage_exclusions,
    });

    let reachability_evidence = fixture_reachability_evidence(
        &graph,
        vec![PersistedEntryPoint {
            name: "fixture".into(),
            kind: EntryPointKind::LibRoot,
            file_path: "src/lib.rs".into(),
            crate_name: "fixture".into(),
        }],
    );

    let mut publisher =
        SemanticPublisher::acquire(binding.graph_dir(), root).expect("semantic publisher");
    let workspace = publisher.begin_generation().expect("generation workspace");
    let store = GraphStore::new(workspace.database());
    store
        .save_snapshot_with_reachability_evidence(&graph, &reachability_evidence)
        .await
        .expect("graph snapshot with reachability evidence");
    store.set_origin(root).await.expect("graph origin");
    store
        .set_generation_metadata(GraphGenerationMetadata::now(false))
        .await
        .expect("complete generation metadata");
    drop(store);
    let index_state = h00ligan_engine::index_state::IndexState::new(workspace.database())
        .expect("fixture indexed-source state");
    for (document_path, source) in &sources {
        let extracted = h00ligan_engine::extractor::extract_source(source, document_path)
            .expect("extract fixture indexed-source record");
        index_state
            .set_file(
                document_path,
                &h00ligan_engine::index_state::FileRecord {
                    blake3_hash: extracted.file_hash,
                    last_indexed: 1,
                    symbol_count: u32::try_from(extracted.symbols.len())
                        .expect("fixture symbol population fits u32"),
                    language: "rust".into(),
                },
            )
            .expect("fixture indexed-source record");
    }
    drop(index_state);

    let published = publisher
        .finish_generation(
            workspace,
            GenerationDraft {
                source_revision: Some("fixture-revision".into()),
                project_inventory: project_inventory.clone(),
                receipts,
                provider_payloads: vec![payload],
            },
        )
        .expect("publish immutable Calls generation");
    let resolved =
        resolve_generation(binding.graph_dir(), root).expect("resolve immutable Calls generation");
    assert_eq!(resolved.manifest, published.manifest);
    assert_eq!(resolved.project_inventory, published.project_inventory);
    assert_eq!(resolved.provider_payloads, published.provider_payloads);
    assert_eq!(resolved.database_path, published.database_path);

    SeededCallsGeneration {
        generation_id: published.manifest.generation_id.0,
        repository_id: published.manifest.repository_id.0,
        database_path: published.database_path,
        project_unit_ids: resolved
            .project_inventory
            .project_topology
            .memberships
            .iter()
            .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
            .map(|membership| membership.project_unit_id.0.clone())
            .collect(),
        call_spans,
    }
}

async fn publish_graph_with_unavailable_reachability(
    root: &Path,
    data_dir: &Path,
    invalid_document: bool,
) {
    std::fs::create_dir_all(data_dir).expect("graph directory");
    let mut graph = KnowledgeGraph::new();
    let mut published_type = node("PublishedType", "src/lib.rs", 0);
    published_type.kind = "struct".into();
    published_type.signature = "pub struct PublishedType;".into();
    published_type.has_body = Some(true);
    graph
        .add_node(published_type)
        .expect("published graph node");

    let mut publisher = SemanticPublisher::acquire(data_dir, root).expect("semantic publisher");
    let workspace = publisher.begin_generation().expect("generation workspace");
    let database = workspace.database();
    let store = GraphStore::new(Arc::clone(&database));
    store
        .save_snapshot(&graph)
        .await
        .expect("graph-only snapshot");
    store.set_origin(root).await.expect("graph origin");
    store
        .set_generation_metadata(GraphGenerationMetadata::now(false))
        .await
        .expect("complete generation metadata");
    if invalid_document {
        let transaction = database.begin_write().expect("evidence transaction");
        {
            let definition: redb::TableDefinition<&str, &[u8]> =
                redb::TableDefinition::new("graph_reachability_evidence");
            let mut table = transaction
                .open_table(definition)
                .expect("reachability evidence table");
            table
                .insert("latest", b"{not-json".as_slice())
                .expect("invalid evidence bytes");
        }
        transaction.commit().expect("commit invalid evidence");
    }
    drop(store);
    drop(database);

    publisher
        .finish_generation(
            workspace,
            GenerationDraft {
                source_revision: Some("reachability-negative-fixture".into()),
                project_inventory: ProjectInventory {
                    coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
                    project_topology: h00ligan_engine::code_intel_domain::ProjectTopology {
                        units: Vec::new(),
                        memberships: Vec::new(),
                        relationships: Vec::new(),
                        exact_workspace_member_sets: Vec::new(),
                        dependency_graphs: Vec::new(),
                    },
                    analysis_context_graphs: Vec::new(),
                    inputs: Vec::new(),
                    issues: Vec::new(),
                },
                receipts: vec![CapabilityReceipt::complete(
                    "structural_graph",
                    "h00-structural",
                    h00ligan_engine::BUILD_IDENTITY,
                    CapabilityScope::Language {
                        language_id: LanguageId::new("rust"),
                        configuration_id: ConfigurationId::new("structural-v2"),
                    },
                    "0".repeat(64),
                )],
                provider_payloads: Vec::new(),
            },
        )
        .expect("publish graph with unavailable reachability evidence");
}

async fn publish_metadata_authority_fixture(root: &Path, data_dir: &Path) {
    std::fs::create_dir_all(data_dir).expect("graph directory");
    let source = std::fs::read_to_string(root.join("src/lib.rs")).expect("fixture source");
    let (definition, extent) = function_extent(&source, "published_symbol");
    let mut graph = KnowledgeGraph::new();
    let published_symbol = node(
        "published_symbol",
        "src/lib.rs",
        definition.start_line as usize,
    );
    let published_symbol_id = published_symbol.memory_id;
    graph
        .add_node(published_symbol)
        .expect("published graph node");
    graph
        .set_source_span(published_symbol_id, graph_source_span(&extent))
        .expect("published graph callable extent");
    let rust_unit_id = ProjectUnitId::new("rust:metadata:workspace");
    let project_inventory = ProjectInventory {
        coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
        project_topology: h00ligan_engine::code_intel_domain::ProjectTopology {
            units: vec![ProjectUnit {
                project_unit_id: rust_unit_id.clone(),
                language_id: LanguageId::new("rust"),
                ecosystem_id: EcosystemId::new("cargo"),
                kind: ProjectUnitKind::Workspace,
                root_path: String::new(),
                manifest_path: None,
                compilation_root_paths: Vec::new(),
            }],
            memberships: vec![DocumentMembership {
                document_path: "src/lib.rs".into(),
                language_id: LanguageId::new("rust"),
                project_unit_id: rust_unit_id,
                kind: DocumentMembershipKind::SourceOwner,
            }],
            relationships: Vec::new(),
            exact_workspace_member_sets: Vec::new(),
            dependency_graphs: Vec::new(),
        },
        analysis_context_graphs: Vec::new(),
        inputs: Vec::new(),
        issues: Vec::new(),
    };
    let calls_receipt = CapabilityReceipt::complete(
        "calls",
        "fixture-scip",
        "1.0.0",
        CapabilityScope::Language {
            language_id: LanguageId::new("rust"),
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        },
        "c".repeat(64),
    );
    let location = |span| ProviderLocation {
        document_path: "src/lib.rs".into(),
        span,
    };
    let calls_payload = ProviderPayload::Calls(CallsProviderPayload {
        schema_version: CALLS_PROVIDER_PAYLOAD_SCHEMA.into(),
        population: CallsPopulation::ProviderResolvedExplicitSourceInvocations,
        receipt: calls_receipt.clone(),
        semantic_inputs: h00ligan_provider_protocol::ProviderSemanticInputs::empty(),
        execution_authority:
            h00ligan_engine::code_intel_payload::ProviderExecutionAuthority::InvocationBound {
                provider_configurations_sha256: BTreeMap::new(),
            },
        canonical_snapshot_sha256: None,
        documents: vec![ProviderDocument {
            document_path: "src/lib.rs".into(),
            language_id: LanguageId::new("rust"),
            content_sha256: "d".repeat(64),
            cross_document_surface_sha256: "e".repeat(64),
            byte_length: source.len() as u64,
        }],
        symbols: vec![ProviderSymbol {
            provider_symbol_id: "rust fixture published_symbol".into(),
            name: "published_symbol".into(),
            provider_kind: "function".into(),
            language_id: LanguageId::new("rust"),
            role: ProviderSymbolRole::SourceInvocationTarget,
            definition: Some(location(definition)),
            structural_extent: Some(location(extent.clone())),
            call_owner_extent: Some(location(extent)),
        }],
        calls: Vec::new(),
        callable_bindings: Vec::new(),
        coverage_exclusions: Vec::new(),
    });

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as i64;
    let mut publisher = SemanticPublisher::acquire(data_dir, root).expect("semantic publisher");
    let workspace = publisher.begin_generation().expect("generation workspace");
    let database = workspace.database();
    let store = GraphStore::new(Arc::clone(&database));
    let reachability_evidence = fixture_reachability_evidence(
        &graph,
        vec![PersistedEntryPoint {
            name: "metadata_authority_fixture".into(),
            kind: EntryPointKind::LibRoot,
            file_path: "src/lib.rs".into(),
            crate_name: "metadata_authority_fixture".into(),
        }],
    );
    store
        .save_snapshot_with_reachability_evidence(&graph, &reachability_evidence)
        .await
        .expect("graph snapshot with reachability evidence");
    store.set_origin(root).await.expect("graph origin");
    store
        .set_generation_metadata(GraphGenerationMetadata::now(false))
        .await
        .expect("complete immutable metadata");
    let index_state = h00ligan_engine::index_state::IndexState::new(Arc::clone(&database))
        .expect("immutable index state");
    index_state
        .set_metadata(&h00ligan_engine::index_state::IndexMetadata {
            repo_root: root.to_string_lossy().into_owned(),
            last_full_scan: Some(now_ms),
            last_update: Some(now_ms),
            git_head: None,
            total_files: 1,
            total_symbols: 1,
            total_edges: 0,
        })
        .expect("immutable index metadata");
    drop(index_state);
    drop(store);
    drop(database);

    publisher
        .finish_generation(
            workspace,
            GenerationDraft {
                source_revision: Some("metadata-authority-fixture".into()),
                project_inventory,
                receipts: vec![calls_receipt],
                provider_payloads: vec![calls_payload],
            },
        )
        .expect("publish metadata authority fixture");

    // Populate the obsolete root bundle with the exact opposite metadata. This
    // is a non-vacuity control: the pre-repair composite readers opened these
    // files after loading the immutable graph and therefore spliced two
    // authorities into one answer.
    let legacy_database = Arc::new(
        redb::Database::create(data_dir.join("graph.redb")).expect("legacy graph database"),
    );
    let legacy_store = GraphStore::new(Arc::clone(&legacy_database));
    legacy_store
        .save_snapshot(&graph)
        .await
        .expect("legacy graph snapshot");
    legacy_store
        .set_origin(root)
        .await
        .expect("legacy graph origin");
    legacy_store
        .set_generation_metadata(GraphGenerationMetadata::now(true))
        .await
        .expect("conflicting obsolete metadata");
    drop(legacy_store);
    let transaction = legacy_database
        .begin_write()
        .expect("legacy poison transaction");
    {
        let mut metadata = transaction
            .open_table(TableDefinition::<&str, u64>::new("graph_meta"))
            .expect("legacy poison metadata table");
        metadata
            .insert("scip_ran_ok", 0)
            .expect("obsolete aggregate poison value");
    }
    transaction.commit().expect("commit obsolete poison value");
    drop(legacy_database);

    let legacy_index_database = Arc::new(
        redb::Database::create(data_dir.join("index.redb"))
            .expect("conflicting legacy index database"),
    );
    let legacy_index = h00ligan_engine::index_state::IndexState::new(legacy_index_database)
        .expect("conflicting legacy index state");
    legacy_index
        .set_metadata(&h00ligan_engine::index_state::IndexMetadata {
            repo_root: root.to_string_lossy().into_owned(),
            last_full_scan: Some(1),
            last_update: Some(1),
            git_head: None,
            total_files: 99,
            total_symbols: 99,
            total_edges: 99,
        })
        .expect("conflicting legacy index metadata");
}

async fn publish_mixed_calls_authority_fixture(root: &Path, data_dir: &Path) {
    publish_mixed_calls_authority_fixture_with_configuration(
        root,
        data_dir,
        CALLS_CONFIGURATION_ID,
    )
    .await;
}

async fn publish_mixed_calls_authority_fixture_with_configuration(
    root: &Path,
    data_dir: &Path,
    calls_configuration_id: &str,
) {
    std::fs::create_dir_all(data_dir).expect("graph directory");
    let rust_source = std::fs::read_to_string(root.join("src/lib.rs")).expect("Rust source");
    let rust_extracted = extract_file(&root.join("src/lib.rs"), root).expect("extract Rust source");
    let go_extracted = extract_file(&root.join("main.go"), root).expect("extract Go source");

    let mut rust_dead = node("rust_dead", "src/lib.rs", 0);
    rust_dead.reachability_class = ReachabilityClass::Dead;
    rust_dead.visibility = "private".into();
    let (_, rust_extent) = function_extent(&rust_source, "rust_dead");
    let rust_dead_id = rust_dead.memory_id;
    let mut go_dead = node("go_dead", "main.go", 1);
    go_dead.reachability_class = ReachabilityClass::Dead;
    let mut graph = KnowledgeGraph::new();
    graph.add_node(rust_dead).expect("Rust graph node");
    graph
        .set_source_span(rust_dead_id, graph_source_span(&rust_extent))
        .expect("Rust graph callable extent");
    graph.add_node(go_dead).expect("Go graph node");

    let project_inventory = h00ligan_engine::code_intel_inventory::build_project_inventory(
        root,
        &[
            h00ligan_engine::code_intel_inventory::InventorySource::new("src/lib.rs", "rust"),
            h00ligan_engine::code_intel_inventory::InventorySource::new("main.go", "go"),
        ],
    );
    let rust_receipt = CapabilityReceipt::complete(
        "calls",
        "fixture-rust-provider",
        "1.0.0",
        CapabilityScope::Language {
            language_id: LanguageId::new("rust"),
            configuration_id: ConfigurationId::new(calls_configuration_id),
        },
        "e".repeat(64),
    );
    let go_receipt = CapabilityReceipt::unavailable(
        "calls",
        "fixture-go-provider",
        None,
        CapabilityScope::Language {
            language_id: LanguageId::new("go"),
            configuration_id: ConfigurationId::new(calls_configuration_id),
        },
        None,
        "provider_not_installed",
        "the Go Calls provider was not available for this generation",
    );
    let (definition, extent) = function_extent(&rust_source, "rust_dead");
    let location = |span| ProviderLocation {
        document_path: "src/lib.rs".into(),
        span,
    };
    let rust_payload = ProviderPayload::Calls(CallsProviderPayload {
        schema_version: CALLS_PROVIDER_PAYLOAD_SCHEMA.into(),
        population: CallsPopulation::ProviderResolvedExplicitSourceInvocations,
        receipt: rust_receipt.clone(),
        semantic_inputs: h00ligan_provider_protocol::ProviderSemanticInputs::empty(),
        execution_authority:
            h00ligan_engine::code_intel_payload::ProviderExecutionAuthority::InvocationBound {
                provider_configurations_sha256: BTreeMap::new(),
            },
        canonical_snapshot_sha256: None,
        documents: vec![ProviderDocument {
            document_path: "src/lib.rs".into(),
            language_id: LanguageId::new("rust"),
            content_sha256: "f".repeat(64),
            cross_document_surface_sha256: "e".repeat(64),
            byte_length: rust_source.len() as u64,
        }],
        symbols: vec![ProviderSymbol {
            provider_symbol_id: "rust fixture rust_dead".into(),
            name: "rust_dead".into(),
            provider_kind: "function".into(),
            language_id: LanguageId::new("rust"),
            role: ProviderSymbolRole::SourceInvocationTarget,
            definition: Some(location(definition)),
            structural_extent: Some(location(extent.clone())),
            call_owner_extent: Some(location(extent)),
        }],
        calls: Vec::new(),
        callable_bindings: Vec::new(),
        coverage_exclusions: Vec::new(),
    });

    let mut publisher = SemanticPublisher::acquire(data_dir, root).expect("semantic publisher");
    let workspace = publisher.begin_generation().expect("generation workspace");
    let database = workspace.database();
    let store = GraphStore::new(Arc::clone(&database));
    let reachability_evidence = fixture_reachability_evidence(
        &graph,
        vec![
            PersistedEntryPoint {
                name: "mixed_fixture".into(),
                kind: EntryPointKind::LibRoot,
                file_path: "src/lib.rs".into(),
                crate_name: "mixed_fixture".into(),
            },
            PersistedEntryPoint {
                name: "mixed".into(),
                kind: EntryPointKind::LibRoot,
                file_path: String::new(),
                crate_name: "example.test/mixed".into(),
            },
        ],
    );
    store
        .save_snapshot_with_reachability_evidence(&graph, &reachability_evidence)
        .await
        .expect("graph snapshot with reachability evidence");
    store.set_origin(root).await.expect("graph origin");
    store
        .set_generation_metadata(GraphGenerationMetadata::now(false))
        .await
        .expect("complete generation metadata");
    drop(store);
    let index_state = h00ligan_engine::index_state::IndexState::new(Arc::clone(&database))
        .expect("generation index state");
    for (path, output, language) in [
        ("src/lib.rs", &rust_extracted, "rust"),
        ("main.go", &go_extracted, "go"),
    ] {
        index_state
            .set_file(
                path,
                &h00ligan_engine::index_state::FileRecord {
                    blake3_hash: output.file_hash.clone(),
                    last_indexed: 1,
                    symbol_count: u32::try_from(output.symbols.len())
                        .expect("fixture symbol population fits u32"),
                    language: language.into(),
                },
            )
            .expect("generation source record");
    }
    drop(index_state);
    drop(database);

    let rust_structural = CapabilityReceipt::complete(
        "structural_graph",
        "h00-structural",
        "test",
        CapabilityScope::Language {
            language_id: LanguageId::new("rust"),
            configuration_id: ConfigurationId::new("structural-v2"),
        },
        rust_extracted.file_hash,
    );
    let go_structural = CapabilityReceipt::complete(
        "structural_graph",
        "h00-structural",
        "test",
        CapabilityScope::Language {
            language_id: LanguageId::new("go"),
            configuration_id: ConfigurationId::new("structural-v2"),
        },
        go_extracted.file_hash,
    );

    publisher
        .finish_generation(
            workspace,
            GenerationDraft {
                source_revision: Some("mixed-calls-authority-fixture".into()),
                project_inventory,
                receipts: vec![rust_receipt, go_receipt, rust_structural, go_structural],
                provider_payloads: vec![rust_payload],
            },
        )
        .expect("publish mixed Calls authority fixture");
}

async fn publish_typescript_health_failure_without_callable_declaration(
    root: &Path,
    data_dir: &Path,
) {
    std::fs::create_dir_all(data_dir).expect("graph directory");
    let source_path = root.join("src/usage.ts");
    let extracted = extract_file(&source_path, root).expect("extract TypeScript source");
    let file_hash = extracted.file_hash.clone();
    let symbol_count = extracted.symbols.len();
    let mut graph = KnowledgeGraph::new();
    build_graph(&[extracted], &mut graph).expect("build TypeScript structural graph");
    assert!(
        graph.node_by_name("result").is_some(),
        "positive control: the module-level call result is structurally represented"
    );
    assert!(
        graph
            .all_nodes()
            .iter()
            .all(|node| !symbol_kind_has_role(&node.kind, SymbolRole::Callable)),
        "positive control: this fixture reaches applicability through semantic ownership, not a declaration"
    );

    let project_inventory =
        build_project_inventory(root, &[InventorySource::new("src/usage.ts", "typescript")]);
    assert!(
        project_inventory
            .project_topology
            .memberships
            .iter()
            .any(|membership| {
                membership.language_id == LanguageId::new("typescript")
                    && project_inventory.is_semantic_source_owner(membership)
            }),
        "positive control: package.json/tsconfig project discovery owns the source semantically"
    );

    let structural_receipt = CapabilityReceipt::complete(
        "structural_graph",
        "h00-structural",
        "test",
        CapabilityScope::Language {
            language_id: LanguageId::new("typescript"),
            configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
        },
        file_hash.clone(),
    );
    let calls_receipt = CapabilityReceipt::unavailable(
        "calls",
        "typescript-language-service",
        None,
        CapabilityScope::Language {
            language_id: LanguageId::new("typescript"),
            configuration_id: ConfigurationId::new(CALLS_CONFIGURATION_ID),
        },
        None,
        "provider_failed_or_unavailable",
        "the persistent h00ligan typescript provider failed its authority or health contract; weaker one-shot authority was refused",
    );

    let mut publisher = SemanticPublisher::acquire(data_dir, root).expect("semantic publisher");
    let workspace = publisher.begin_generation().expect("generation workspace");
    let database = workspace.database();
    let store = GraphStore::new(Arc::clone(&database));
    store
        .save_snapshot(&graph)
        .await
        .expect("TypeScript graph snapshot");
    store.set_origin(root).await.expect("graph origin");
    store
        .set_generation_metadata(GraphGenerationMetadata::now(false))
        .await
        .expect("complete generation metadata");
    drop(store);
    let index_state = IndexState::new(Arc::clone(&database)).expect("generation index state");
    index_state
        .set_file(
            "src/usage.ts",
            &h00ligan_engine::index_state::FileRecord {
                blake3_hash: file_hash,
                last_indexed: 1,
                symbol_count: u32::try_from(symbol_count)
                    .expect("fixture symbol population fits u32"),
                language: "typescript".into(),
            },
        )
        .expect("generation source record");
    drop(index_state);
    drop(database);

    publisher
        .finish_generation(
            workspace,
            GenerationDraft {
                source_revision: Some("typescript-health-failure-fixture".into()),
                project_inventory,
                receipts: vec![structural_receipt, calls_receipt],
                provider_payloads: Vec::new(),
            },
        )
        .expect("publish TypeScript health-failure generation");
}

fn run_calls(root: &Path, data_dir: &Path, extra: &[&str]) -> Output {
    run_calls_for(root, data_dir, "target", extra)
}

fn run_calls_for(root: &Path, data_dir: &Path, symbol: &str, extra: &[&str]) -> Output {
    h00ligan()
        .arg("--root")
        .arg(root)
        .arg("--data-dir")
        .arg(data_dir)
        .args(["calls", symbol, "--format", "json"])
        .args(extra)
        .output()
        .expect("run h00ligan calls")
}

fn run_symbol_verb(
    root: &Path,
    data_dir: &Path,
    verb: &str,
    symbol: &str,
    extra: &[&str],
) -> Output {
    h00ligan()
        .arg("--root")
        .arg(root)
        .arg("--data-dir")
        .arg(data_dir)
        .args([verb, symbol, "--format", "json"])
        .args(extra)
        .output()
        .unwrap_or_else(|error| panic!("run h00ligan {verb}: {error}"))
}

fn find_exact_selector(root: &Path, data_dir: &Path, name: &str) -> String {
    let found = h00ligan()
        .arg("--root")
        .arg(root)
        .arg("--data-dir")
        .arg(data_dir)
        .args([
            "find",
            name,
            "--name",
            "--definitions-only",
            "--format",
            "json",
        ])
        .output()
        .unwrap_or_else(|error| panic!("find exact selector for {name}: {error}"));
    assert!(
        found.status.success(),
        "Find selector control failed for {name}: stdout={} stderr={}",
        String::from_utf8_lossy(&found.stdout),
        String::from_utf8_lossy(&found.stderr),
    );
    let found = stdout_json(&found);
    let matches = found["items"]
        .as_array()
        .expect("Find items")
        .iter()
        .filter(|item| item["name"] == name)
        .collect::<Vec<_>>();
    assert_eq!(matches.len(), 1, "Find must resolve one {name}: {found}");
    matches[0]["symbol_id"]
        .as_str()
        .expect("Find symbol_id")
        .to_owned()
}

fn result_selector<'a>(verb: &str, result: &'a Value) -> &'a str {
    let value = match verb {
        "type" => &result["resolved_type"]["symbol_id"],
        "read" | "calls" | "inspect" | "tests" => &result["resolved_symbol"]["symbol_id"],
        "assess" => &result["resolved_symbol"]["structural"]["symbol_id"],
        "dead" => &result["items"][0]["symbol"]["symbol_id"],
        other => panic!("unknown selector-bearing verb {other}"),
    };
    value
        .as_str()
        .unwrap_or_else(|| panic!("{verb} result must expose its exact selector: {result}"))
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout must be one JSON value ({error}); status={:?}; stdout={}; stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

fn without_ephemeral_cursor_lease(mut value: Value) -> Value {
    fn remove_leases(value: &mut Value) {
        match value {
            Value::Object(object) => {
                if let Some(page) = object.get_mut("page").and_then(Value::as_object_mut) {
                    page.remove("next_cursor");
                    page.remove("expires_at_unix_seconds");
                }
                for child in object.values_mut() {
                    remove_leases(child);
                }
            }
            Value::Array(array) => {
                for child in array {
                    remove_leases(child);
                }
            }
            _ => {}
        }
    }
    remove_leases(&mut value);
    value
}

fn without_live_input_observation(mut value: Value) -> Value {
    if let Some(repository) = value.get_mut("repository").and_then(Value::as_object_mut) {
        repository.remove("live_inputs");
    }
    if let Some(warnings) = value.get_mut("warnings").and_then(Value::as_array_mut) {
        warnings.retain(|warning| {
            !warning
                .as_str()
                .is_some_and(|warning| warning.contains("not the current worktree"))
        });
    }
    if value["warnings"].as_array().is_some_and(Vec::is_empty) {
        value
            .as_object_mut()
            .expect("query result object")
            .remove("warnings");
    }
    value
}

fn result_count(value: &Value) -> Option<usize> {
    value
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::len)
        .or_else(|| {
            value
                .get("total_call_sites")
                .and_then(Value::as_u64)
                .map(|count| count as usize)
        })
}

fn calls_language<'a>(value: &'a Value, language_id: &str) -> &'a Value {
    value["capabilities"]["calls"]["languages"]
        .as_array()
        .and_then(|languages| {
            languages
                .iter()
                .find(|language| language["language_id"] == language_id)
        })
        .unwrap_or_else(|| panic!("missing Calls authority for {language_id}: {value}"))
}

fn dead_calls_language<'a>(value: &'a Value, language_id: &str) -> &'a Value {
    value["authority"]["calls"]["languages"]
        .as_array()
        .and_then(|languages| {
            languages
                .iter()
                .find(|language| language["language_id"] == language_id)
        })
        .unwrap_or_else(|| panic!("missing Dead Calls authority for {language_id}: {value}"))
}

fn dead_language<'a>(value: &'a Value, language_id: &str) -> &'a Value {
    value["authority"]["languages"]
        .as_array()
        .and_then(|languages| {
            languages
                .iter()
                .find(|language| language["language_id"] == language_id)
        })
        .unwrap_or_else(|| panic!("missing Dead language authority for {language_id}: {value}"))
}

fn dead_item<'a>(value: &'a Value, symbol_name: &str) -> &'a Value {
    value["items"]
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|item| item["symbol"]["name"] == symbol_name)
        })
        .unwrap_or_else(|| panic!("missing Dead item for {symbol_name}: {value}"))
}

fn spawn_mcp(root: &Path, data_dir: &Path) -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let mut command = h00ligan();
    command
        .arg("--root")
        .arg(root)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("mcp-serve");
    spawn_mcp_command(command)
}

fn spawn_mcp_command(mut command: Command) -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn h00ligan MCP");
    let stdin = child.stdin.take().expect("MCP stdin");
    let stdout = BufReader::new(child.stdout.take().expect("MCP stdout"));
    (child, stdin, stdout)
}

#[cfg(unix)]
fn spawn_mcp_with_fixture_provider(
    root: &Path,
    data_dir: &Path,
    path: &std::ffi::OsStr,
    provider_artifact: &Path,
    provider_executed: &Path,
) -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let mut command = h00ligan();
    command
        .arg("--root")
        .arg(root)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("mcp-serve")
        .env("PATH", path)
        .env("H00_TEST_PROVIDER_ARTIFACT", provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", provider_executed);
    spawn_mcp_command(command)
}

fn call_mcp(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    id: u64,
    name: &str,
    arguments: Value,
) -> Value {
    writeln!(
        stdin,
        "{}",
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        })
    )
    .expect("write MCP request");
    stdin.flush().expect("flush MCP request");

    let mut line = String::new();
    stdout.read_line(&mut line).expect("read MCP response");
    assert!(!line.is_empty(), "MCP closed before response {id}");
    serde_json::from_str(&line).expect("JSON-RPC response")
}

fn mcp_text_payload(response: &Value) -> Value {
    let text = response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("missing MCP text fallback: {response}"));
    serde_json::from_str(text)
        .unwrap_or_else(|error| panic!("MCP text fallback must contain JSON ({error}): {response}"))
}

fn call_mcp_reindex_terminal(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    id: u64,
    arguments: Value,
) -> Value {
    let started_response = call_mcp(stdin, stdout, id, "reindex", arguments);
    assert_ne!(
        started_response["result"]["isError"], true,
        "reindex must return an operation receipt: {started_response}"
    );
    let started = mcp_text_payload(&started_response);
    assert_eq!(started["terminal"], false, "{started}");
    let operation_id = started["operation_id"]
        .as_str()
        .expect("reindex operation ID")
        .to_owned();
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut poll = 0_u64;
    loop {
        // Lifecycle polls use a disjoint ID range so existing assertions can
        // keep their stable human-sized request IDs.
        let status_id = 1_000_000_000_u64 + id.saturating_mul(100_000) + poll;
        poll = poll.saturating_add(1);
        let response = call_mcp(
            stdin,
            stdout,
            status_id,
            "reindex_status",
            json!({"operation_id": operation_id}),
        );
        assert_ne!(response["result"]["isError"], true, "{response}");
        let terminal = mcp_text_payload(&response);
        if terminal["terminal"] == true {
            return terminal;
        }
        assert!(
            Instant::now() < deadline,
            "reindex did not become terminal: {terminal}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn stop_mcp(child: Child, stdin: ChildStdin) -> Output {
    drop(stdin);
    child.wait_with_output().expect("join MCP child")
}

#[test]
fn shipped_find_pages_one_forced_mode_through_cli_and_mcp() {
    let temporary = TempDir::new().expect("temporary directory");
    let mut source = String::new();
    for index in 0..12 {
        source.push_str(&format!("pub fn needle_{index:02}() {{}}\n"));
    }
    let root = create_source_root(&temporary, "find-contract-repo", &source);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"find_contract\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish Find fixture");
    assert!(
        indexed.status.success(),
        "positive control: shipped indexing must publish all Find candidates: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let cli_first = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "find", "needle_*", "--name", "--limit", "5", "--format", "json",
        ])
        .output()
        .expect("query first CLI Find page");
    assert!(
        cli_first.status.success(),
        "positive control: the existing CLI forced-name mode must find the fixture: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_first.stdout),
        String::from_utf8_lossy(&cli_first.stderr),
    );
    let cli_first = stdout_json(&cli_first);
    assert_eq!(cli_first["items"].as_array().map(Vec::len), Some(5));
    assert_eq!(cli_first["page"]["has_more"], true);

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_first = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "find",
        json!({
            "query": "needle_*",
            "mode": "name",
            "limit": 5,
        }),
    );
    assert!(
        mcp_first.get("error").is_none(),
        "MCP must expose the same explicit mode as CLI instead of rejecting it: {mcp_first}"
    );
    let mcp_first = mcp_first["result"]["structuredContent"].clone();

    assert_eq!(
        without_ephemeral_cursor_lease(cli_first.clone()),
        without_ephemeral_cursor_lease(mcp_first),
        "the two shipped adapters must serialize one shared Find result"
    );
    assert_eq!(cli_first["schema_version"], "h00/code-intel/find/v1");
    assert_eq!(cli_first["query"]["mode"], "name");
    assert_eq!(cli_first["authority"]["status"], "complete");
    assert_eq!(cli_first["page"]["returned"], 5);
    assert_eq!(cli_first["page"]["total_items"], 12);
    assert_eq!(cli_first["page"]["has_more"], true);
    let cursor = cli_first["page"]["next_cursor"]
        .as_str()
        .expect("first Find page cursor");

    let cli_second = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "find", "needle_*", "--name", "--limit", "5", "--cursor", cursor, "--format", "json",
        ])
        .output()
        .expect("query second CLI Find page");
    assert!(
        cli_second.status.success(),
        "CLI Find continuation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_second.stdout),
        String::from_utf8_lossy(&cli_second.stderr),
    );
    let cli_second = stdout_json(&cli_second);
    let mcp_second = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "find",
        json!({
            "query": "needle_*",
            "mode": "name",
            "limit": 5,
            "cursor": cursor,
        }),
    );
    let mcp_second = mcp_second["result"]["structuredContent"].clone();
    assert_eq!(
        without_ephemeral_cursor_lease(cli_second.clone()),
        without_ephemeral_cursor_lease(mcp_second),
        "cursor lease wall-clock seconds are transport-local; page semantics must be identical"
    );
    assert_eq!(cli_second["page"]["offset"], 5);
    assert_eq!(cli_second["page"]["returned"], 5);

    let first_ids = cli_first["items"]
        .as_array()
        .expect("first Find items")
        .iter()
        .map(|item| item["symbol_id"].as_str().expect("Find symbol id"))
        .collect::<std::collections::BTreeSet<_>>();
    let second_ids = cli_second["items"]
        .as_array()
        .expect("second Find items")
        .iter()
        .map(|item| item["symbol_id"].as_str().expect("Find symbol id"))
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        first_ids.is_disjoint(&second_ids),
        "continuation pages must not repeat structural identities"
    );

    let cli_path = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["find", "src", "--path", "--format", "json"])
        .output()
        .expect("query forced CLI path mode");
    assert!(
        cli_path.status.success(),
        "forced path mode must preserve name-shaped directory queries: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_path.stdout),
        String::from_utf8_lossy(&cli_path.stderr),
    );
    let cli_path = stdout_json(&cli_path);
    let mcp_path = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "find",
        json!({"query": "src", "mode": "path"}),
    );
    assert_eq!(mcp_path["result"]["structuredContent"], cli_path);
    assert_eq!(cli_path["query"]["mode"], "path");
    assert_eq!(cli_path["page"]["total_items"], 12);

    let cli_escape = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["find", "../outside.rs", "--path", "--format", "json"])
        .output()
        .expect("reject escaping CLI Find path");
    assert!(!cli_escape.status.success());
    let cli_escape = stdout_json(&cli_escape);
    assert_eq!(cli_escape["error"]["code"], "source_path_invalid");
    let mcp_escape = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "find",
        json!({"query": "../outside.rs", "mode": "path"}),
    );
    assert_eq!(mcp_escape["result"]["isError"], true);
    assert_eq!(mcp_escape["result"]["structuredContent"], cli_escape);

    let crossed_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "find",
            "needle_0*",
            "--name",
            "--limit",
            "5",
            "--cursor",
            cursor,
            "--format",
            "json",
        ])
        .output()
        .expect("reject crossed CLI Find cursor");
    assert!(!crossed_cli.status.success());
    let crossed_cli = stdout_json(&crossed_cli);
    assert_eq!(crossed_cli["error"]["code"], "invalid_cursor");
    let crossed_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        5,
        "find",
        json!({
            "query": "needle_0*",
            "mode": "name",
            "limit": 5,
            "cursor": cursor,
        }),
    );
    assert_eq!(crossed_mcp["result"]["isError"], true);
    assert_eq!(crossed_mcp["result"]["structuredContent"], crossed_cli);

    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let conflicting_modes = h00ligan()
        .args(["find", "needle", "--name", "--path"])
        .output()
        .expect("reject conflicting CLI Find modes");
    assert!(
        !conflicting_modes.status.success()
            && String::from_utf8_lossy(&conflicting_modes.stderr).contains("cannot be used with"),
        "CLI must reject mode ambiguity rather than silently preferring one flag: stdout={} stderr={}",
        String::from_utf8_lossy(&conflicting_modes.stdout),
        String::from_utf8_lossy(&conflicting_modes.stderr),
    );
}

#[tokio::test]
async fn shipped_tests_pages_one_shared_result_through_cli_and_mcp() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "tests-contract-repo",
        "pub fn test_alpha() { target(); }\npub fn test_beta() { target(); }\npub fn target() {}\n",
    );
    let data_dir = temporary.path().join("bundle");
    let seeded = seed_test_calls_bundle(&root, &data_dir, &["test_alpha", "test_beta"]).await;
    let resolved = resolve_generation(&data_dir, &root).expect("resolve Tests generation");
    let provider_call_count = resolved
        .provider_payloads
        .iter()
        .map(|payload| match payload.payload() {
            ProviderPayload::Calls(calls) => calls.calls.len(),
            ProviderPayload::CallableLiveness(_) => 0,
        })
        .sum::<usize>();
    assert_eq!(
        provider_call_count, 2,
        "positive control: the immutable provider population must contain two Calls"
    );
    let database = Arc::new(
        redb::ReadOnlyDatabase::open(&seeded.database_path).expect("open Tests generation"),
    );
    let graph = GraphStore::new_read_only(database)
        .load_snapshot_checked(&root)
        .await
        .expect("load Tests generation")
        .expect("Tests graph snapshot");
    let target = graph
        .all_nodes()
        .into_iter()
        .find(|node| node.symbol_name == "target")
        .expect("Tests target node");
    assert_eq!(
        graph
            .all_nodes()
            .into_iter()
            .filter(|node| node.is_test_only == Some(true))
            .count(),
        2,
        "positive control: the structural graph must classify two test functions; nodes={:?}",
        graph
            .all_nodes()
            .into_iter()
            .map(|node| (&node.symbol_name, &node.file_path, node.is_test_only))
            .collect::<Vec<_>>()
    );
    assert_eq!(target.is_test_only, Some(false));
    drop(graph);

    let cli_first = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["tests", "target", "--limit", "1", "--format", "json"])
        .output()
        .expect("query first CLI Tests page");
    assert!(
        cli_first.status.success(),
        "positive control: complete Calls authority must expose both test callers: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_first.stdout),
        String::from_utf8_lossy(&cli_first.stderr),
    );
    let cli_first = stdout_json(&cli_first);
    assert_eq!(
        cli_first["page"]["total_items"], 2,
        "positive control: {cli_first}"
    );
    assert_eq!(cli_first["items"].as_array().map(Vec::len), Some(1));

    let human_first = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["tests", "target", "--limit", "1"])
        .output()
        .expect("query first human Tests page");
    assert!(human_first.status.success());
    let human_first = String::from_utf8(human_first.stdout).expect("UTF-8 human Tests output");
    assert!(
        human_first.contains("Showing 1 of 2 test roots on this page."),
        "human pagination must report the effective page without mislabelling a product maximum: {human_first}"
    );
    assert!(
        !human_first.contains("maximum page size"),
        "an adaptive serialized-result bound is not the configured maximum page size: {human_first}"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_first = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "tests",
        json!({"symbol": "target", "limit": 1}),
    );
    assert!(
        mcp_first.get("error").is_none(),
        "MCP Tests positive control must execute: {mcp_first}"
    );
    let mcp_first = mcp_first["result"]["structuredContent"].clone();

    for (surface, result) in [("CLI", &cli_first), ("MCP", &mcp_first)] {
        assert!(
            result["page"]["next_cursor"].is_string()
                && result["page"]["expires_at_unix_seconds"].is_u64(),
            "{surface} must retain a complete time-bound Tests cursor lease: {result}"
        );
    }
    assert_eq!(
        without_ephemeral_cursor_lease(cli_first.clone()),
        without_ephemeral_cursor_lease(mcp_first),
        "CLI and MCP must serialize one shared stable Tests result; independently minted cursor leases may differ"
    );
    assert_eq!(cli_first["schema_version"], "h00/code-intel/tests/v2");
    assert_eq!(cli_first["generation_id"], seeded.generation_id);
    assert_eq!(
        cli_first["repository"]["repository_id"],
        seeded.repository_id
    );
    assert_eq!(cli_first["authority"]["status"], "complete");
    assert_eq!(cli_first["page"]["returned"], 1);
    assert_eq!(cli_first["page"]["total_items"], 2);
    assert_eq!(cli_first["page"]["has_more"], true);
    let cursor = cli_first["page"]["next_cursor"]
        .as_str()
        .expect("first Tests page cursor");

    let cli_second = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "tests", "target", "--limit", "1", "--cursor", cursor, "--format", "json",
        ])
        .output()
        .expect("query second CLI Tests page");
    assert!(
        cli_second.status.success(),
        "CLI Tests continuation failed: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_second.stdout),
        String::from_utf8_lossy(&cli_second.stderr),
    );
    let cli_second = stdout_json(&cli_second);
    let mcp_second = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "tests",
        json!({"symbol": "target", "limit": 1, "cursor": cursor}),
    );
    assert_eq!(mcp_second["result"]["structuredContent"], cli_second);
    assert_eq!(cli_second["page"]["offset"], 1);
    assert_eq!(cli_second["page"]["returned"], 1);
    assert_eq!(cli_second["page"]["has_more"], false);
    assert_ne!(
        cli_first["items"][0]["test"]["symbol_id"], cli_second["items"][0]["test"]["symbol_id"],
        "Tests continuation pages must not repeat identities"
    );

    let crossed_cursor_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "tests",
            "test_alpha",
            "--limit",
            "1",
            "--cursor",
            cursor,
            "--format",
            "json",
        ])
        .output()
        .expect("reject Tests cursor for another resolved target");
    assert!(!crossed_cursor_cli.status.success());
    let crossed_cursor_cli = stdout_json(&crossed_cursor_cli);
    assert_eq!(crossed_cursor_cli["error"]["code"], "invalid_cursor");
    let crossed_cursor_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "tests",
        json!({"symbol": "test_alpha", "limit": 1, "cursor": cursor}),
    );
    assert_eq!(crossed_cursor_mcp["result"]["isError"], true);
    assert_eq!(
        crossed_cursor_mcp["result"]["structuredContent"],
        crossed_cursor_cli
    );

    let wrong_file_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "tests",
            "target",
            "--file",
            "src/missing.rs",
            "--format",
            "json",
        ])
        .output()
        .expect("reject wrong CLI Tests file selector");
    assert!(!wrong_file_cli.status.success());
    let wrong_file_cli = stdout_json(&wrong_file_cli);
    assert_eq!(wrong_file_cli["error"]["code"], "source_path_invalid");
    let wrong_file_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "tests",
        json!({"symbol": "target", "file": "src/missing.rs"}),
    );
    assert_eq!(wrong_file_mcp["result"]["isError"], true);
    assert_eq!(
        wrong_file_mcp["result"]["structuredContent"],
        wrong_file_cli
    );

    let stopped = stop_mcp(child, stdin);
    assert!(
        stopped.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
}

#[tokio::test]
async fn shipped_tests_traverses_test_helpers_but_reports_only_runnable_roots() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "tests-transitive-repo",
        "pub fn outer_test() { test_entry(); }\npub fn test_entry() { helper(); }\npub fn helper() { target(); }\npub fn target() {}\n",
    );
    let data_dir = temporary.path().join("bundle");
    let edges = [
        CallsFixtureEdge {
            caller: "outer_test",
            callee: "test_entry",
            is_test_only: true,
            is_test_root: true,
        },
        CallsFixtureEdge {
            caller: "test_entry",
            callee: "helper",
            is_test_only: true,
            is_test_root: true,
        },
        CallsFixtureEdge {
            caller: "helper",
            callee: "target",
            is_test_only: true,
            is_test_root: false,
        },
    ];
    seed_calls_topology_bundle(&root, &data_dir, &edges, true).await;

    let output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["tests", "target", "--format", "json"])
        .output()
        .expect("query transitive Tests path");
    assert!(
        output.status.success(),
        "provider-backed transitive Tests query failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let result = stdout_json(&output);
    assert_eq!(result["authority"]["status"], "complete");
    assert_eq!(result["page"]["total_items"], 2);
    let items = result["items"].as_array().expect("Tests items");
    let test_entry = items
        .iter()
        .find(|item| item["test"]["name"] == "test_entry")
        .expect("direct runnable test root");
    let outer_test = items
        .iter()
        .find(|item| item["test"]["name"] == "outer_test")
        .expect("outer runnable test root");
    assert_eq!(test_entry["chain"].as_array().map(Vec::len), Some(2));
    assert_eq!(test_entry["chain"][0]["relation"], "exact_invocation");
    assert_eq!(
        test_entry["chain"][0]["evidence"]["caller"]["name"],
        "test_entry"
    );
    assert_eq!(
        test_entry["chain"][0]["evidence"]["callee"]["name"],
        "helper"
    );
    assert_eq!(test_entry["chain"][1]["relation"], "exact_invocation");
    assert_eq!(
        test_entry["chain"][1]["evidence"]["caller"]["name"],
        "helper"
    );
    assert_eq!(
        test_entry["chain"][1]["evidence"]["callee"]["name"],
        "target"
    );
    assert_eq!(outer_test["chain"].as_array().map(Vec::len), Some(3));
    assert!(outer_test["chain"].as_array().is_some_and(|chain| {
        chain
            .iter()
            .all(|step| step["relation"] == "exact_invocation")
    }));
    assert_eq!(
        outer_test["chain"][0]["evidence"]["caller"]["name"],
        "outer_test"
    );
    assert_eq!(
        outer_test["chain"][0]["evidence"]["callee"]["name"],
        "test_entry"
    );
    assert!(
        items.iter().all(|item| item["test"]["name"] != "helper"),
        "a test-only helper is not itself a runnable test root: {result}"
    );
}

#[tokio::test]
async fn shipped_tests_projects_every_chain_document_into_the_unit_graph() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "tests-cross-file-repo", "pub fn target() {}\n");
    std::fs::write(
        root.join("src/helpers.rs"),
        "pub fn helper() { target(); }\n",
    )
    .expect("helper source fixture");
    std::fs::create_dir_all(root.join("tests")).expect("test source directory");
    std::fs::write(
        root.join("tests/integration.rs"),
        "pub fn test_entry() { helper(); }\n",
    )
    .expect("test-root source fixture");
    let data_dir = temporary.path().join("bundle");
    let edges = [
        CallsFixtureEdge {
            caller: "test_entry",
            callee: "helper",
            is_test_only: true,
            is_test_root: true,
        },
        CallsFixtureEdge {
            caller: "helper",
            callee: "target",
            is_test_only: true,
            is_test_root: false,
        },
    ];
    let symbol_documents = BTreeMap::from([
        ("helper".to_owned(), "src/helpers.rs".to_owned()),
        ("test_entry".to_owned(), "tests/integration.rs".to_owned()),
    ]);
    seed_calls_topology_bundle_with_documents(&root, &data_dir, &edges, true, &symbol_documents)
        .await;

    let output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["tests", "target", "--format", "json"])
        .output()
        .expect("query cross-file Tests path");
    assert!(
        output.status.success(),
        "cross-file Tests query failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let result = stdout_json(&output);
    assert_eq!(
        result["items"][0]["chain"].as_array().map(Vec::len),
        Some(2)
    );
    let projected_documents = result["unit_graph"]["memberships"]
        .as_array()
        .expect("unit graph memberships")
        .iter()
        .filter_map(|membership| membership["document_path"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        projected_documents,
        std::collections::BTreeSet::from(["src/helpers.rs", "src/lib.rs", "tests/integration.rs",]),
        "the unit graph must cover every document named by the returned test chain: {result}"
    );
}

#[tokio::test]
async fn shipped_tests_qualifies_results_when_a_provider_call_path_exceeds_its_depth_bound() {
    let temporary = TempDir::new().expect("temporary directory");
    let helper_names = (0..=10)
        .map(|index| format!("helper_{index}"))
        .collect::<Vec<_>>();
    let mut source =
        String::from("pub fn near_test() { target(); }\npub fn far_test() { helper_10(); }\n");
    for (index, helper) in helper_names.iter().enumerate() {
        let callee = if index == 0 {
            "target"
        } else {
            helper_names[index - 1].as_str()
        };
        source.push_str(&format!("pub fn {helper}() {{ {callee}(); }}\n"));
    }
    source.push_str("pub fn target() {}\n");
    let root = create_source_root(&temporary, "tests-depth-repo", &source);
    let data_dir = temporary.path().join("bundle");
    let mut edges = vec![CallsFixtureEdge {
        caller: "near_test",
        callee: "target",
        is_test_only: true,
        is_test_root: true,
    }];
    for (index, helper) in helper_names.iter().enumerate() {
        edges.push(CallsFixtureEdge {
            caller: helper,
            callee: if index == 0 {
                "target"
            } else {
                helper_names[index - 1].as_str()
            },
            is_test_only: true,
            is_test_root: false,
        });
    }
    edges.push(CallsFixtureEdge {
        caller: "far_test",
        callee: helper_names.last().expect("far helper"),
        is_test_only: true,
        is_test_root: true,
    });
    seed_calls_topology_bundle(&root, &data_dir, &edges, true).await;

    let output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["tests", "target", "--format", "json"])
        .output()
        .expect("query depth-bounded Tests path");
    assert!(
        output.status.success(),
        "depth-bounded Tests query failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let result = stdout_json(&output);
    assert_eq!(
        result["page"]["total_items"], 1,
        "the nearby positive control must still fire: {result}"
    );
    assert_eq!(result["items"][0]["test"]["name"], "near_test");
    assert_eq!(result["authority"]["status"], "qualified");
    assert_eq!(result["authority"]["traversal_complete"], false);
    assert!(
        result["authority"]["depth_cutoff_nodes"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "the far test must create an explicit depth frontier: {result}"
    );
    assert!(
        result["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("maximum provider execution-path depth")))),
        "the qualified result must explain its depth boundary: {result}"
    );
}

#[tokio::test]
async fn shipped_tests_does_not_claim_a_complete_zero_without_structural_test_root_authority() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "tests-authority-repo",
        "pub fn caller() { target(); }\npub fn target() {}\n",
    );
    let data_dir = temporary.path().join("bundle");
    seed_calls_bundle(&root, &data_dir, &["caller"]).await;

    let calls = run_calls(&root, &data_dir, &[]);
    assert!(
        calls.status.success() && result_count(&stdout_json(&calls)) == Some(1),
        "positive control: complete Calls evidence must still fire"
    );
    let output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["tests", "target", "--format", "json"])
        .output()
        .expect("query Tests without structural receipt");
    assert!(output.status.success());
    let result = stdout_json(&output);
    assert_eq!(result["page"]["total_items"], 0);
    assert_eq!(result["authority"]["calls"]["status"], "complete");
    assert_eq!(result["authority"]["status"], "qualified");
    assert_eq!(result["authority"]["population_complete"], false);
    assert!(
        result["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("structural authority")))),
        "a zero without test-root classification authority must explain why it is not complete: {result}"
    );
}

#[tokio::test]
async fn shipped_cli_and_mcp_type_share_exact_field_cardinality() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        "pub struct Value;\npub struct Counter { pub value: Value }\n",
    );
    let data_dir = temporary.path().join("bundle");
    std::fs::create_dir_all(&data_dir).expect("publication directory");

    let output = extract_file(&root.join("src/lib.rs"), &root).expect("extract source fixture");
    assert!(
        output.symbols.iter().any(|symbol| symbol.name == "Counter"),
        "positive control: the production extractor must find Counter"
    );
    let mut graph = KnowledgeGraph::new();
    build_graph(&[output], &mut graph).expect("build indexed graph");
    let counter = graph
        .all_nodes()
        .into_iter()
        .find(|node| node.symbol_name == "Counter")
        .expect("Counter graph node");
    let structural_children = collect_type_children(&graph, &counter.memory_id);
    assert_eq!(
        structural_children.fields.len(),
        1,
        "positive control: Counter has exactly one structural field"
    );
    assert_eq!(
        structural_children.field_type_refs.len(),
        1,
        "positive control: Counter's field has one separate type reference"
    );

    let binding = ProjectBinding::resolve(
        ProjectBindingOptions::new(&root)
            .explicit_root(&root)
            .global_graph_dir(&data_dir),
    )
    .expect("project binding");
    let mut publisher =
        SemanticPublisher::acquire(binding.graph_dir(), binding.root()).expect("publisher");
    let workspace = publisher.begin_generation().expect("generation workspace");
    let store = GraphStore::new(workspace.database());
    store.save_snapshot(&graph).await.expect("graph snapshot");
    store.set_origin(&root).await.expect("graph origin");
    store
        .set_generation_metadata(GraphGenerationMetadata::now(false))
        .await
        .expect("complete generation metadata");
    drop(store);
    publisher
        .finish_generation(
            workspace,
            GenerationDraft {
                source_revision: Some("type-cardinality-fixture".into()),
                project_inventory: ProjectInventory {
                    coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
                    project_topology: h00ligan_engine::code_intel_domain::ProjectTopology {
                        units: Vec::new(),
                        memberships: Vec::new(),
                        relationships: Vec::new(),
                        exact_workspace_member_sets: Vec::new(),
                        dependency_graphs: Vec::new(),
                    },
                    analysis_context_graphs: Vec::new(),
                    inputs: Vec::new(),
                    issues: Vec::new(),
                },
                receipts: vec![CapabilityReceipt::complete(
                    "structural_graph",
                    "h00-structural",
                    h00ligan_engine::BUILD_IDENTITY,
                    CapabilityScope::Language {
                        language_id: LanguageId::new("rust"),
                        configuration_id: ConfigurationId::new("structural-v2"),
                    },
                    "0".repeat(64),
                )],
                provider_payloads: Vec::new(),
            },
        )
        .expect("publish type-cardinality fixture");
    drop(publisher);

    let cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "type",
            "Counter",
            "--file",
            "src/lib.rs",
            "--format",
            "json",
        ])
        .output()
        .expect("run shipped CLI type query");
    assert!(
        cli.status.success(),
        "CLI type query failed: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_payload: Value = serde_json::from_slice(&cli.stdout).expect("CLI type JSON");

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_response = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "type",
        json!({"symbol": "Counter", "file": "src/lib.rs"}),
    );
    let mcp_payload = mcp_response["result"]["structuredContent"].clone();
    let mcp_text = mcp_text_payload(&mcp_response);
    let mcp_output = stop_mcp(child, stdin);
    assert!(
        mcp_output.status.success(),
        "MCP type query failed: {}",
        String::from_utf8_lossy(&mcp_output.stderr)
    );
    assert_eq!(
        cli_payload, mcp_payload,
        "CLI JSON and MCP structuredContent must be the same engine-owned Type result"
    );
    assert_eq!(
        mcp_text, mcp_payload,
        "MCP text fallback must serialize that same Type result"
    );
    assert_eq!(cli_payload["schema_version"], "h00/code-intel/type/v1");
    assert_eq!(cli_payload["capability"], "structural_graph");
    assert_eq!(cli_payload["resolved_type"]["name"], "Counter");
    assert_eq!(cli_payload["totals"]["fields"], 1);
    assert_eq!(cli_payload["totals"]["field_type_references"], 1);
    assert_eq!(cli_payload["page"]["total_items"], 2);
    let roles = cli_payload["items"]
        .as_array()
        .expect("typed Type member population")
        .iter()
        .map(|item| item["role"].as_str().expect("typed member role"))
        .collect::<Vec<_>>();
    assert_eq!(
        roles,
        ["field", "field_type_reference"],
        "positive control: the shared result carries both independently measured structural roles"
    );
}

#[tokio::test]
async fn shipped_assess_derives_transitive_impact_from_the_immutable_provider_call_graph() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "assess-provider-repo",
        "pub fn outer() { inner(); }\npub fn inner() { target(); }\npub fn target() {}\n",
    );
    let data_dir = temporary.path().join("bundle");
    let edges = [
        CallsFixtureEdge {
            caller: "outer",
            callee: "inner",
            is_test_only: false,
            is_test_root: false,
        },
        CallsFixtureEdge {
            caller: "inner",
            callee: "target",
            is_test_only: false,
            is_test_root: false,
        },
    ];
    let seeded = seed_calls_topology_bundle(&root, &data_dir, &edges, true).await;

    let target_calls = stdout_json(&run_calls(&root, &data_dir, &[]));
    let inner_calls = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["calls", "inner", "--format", "json"])
        .output()
        .expect("query provider caller positive control");
    assert!(inner_calls.status.success());
    let inner_calls = stdout_json(&inner_calls);
    assert_eq!(result_count(&target_calls), Some(1));
    assert_eq!(target_calls["items"][0]["caller"]["name"], "inner");
    assert_eq!(result_count(&inner_calls), Some(1));
    assert_eq!(inner_calls["items"][0]["caller"]["name"], "outer");

    let database = Arc::new(
        redb::ReadOnlyDatabase::open(&seeded.database_path).expect("open Assess generation"),
    );
    let graph = GraphStore::new_read_only(database)
        .load_snapshot_checked(&root)
        .await
        .expect("load Assess generation")
        .expect("Assess graph snapshot");
    assert_eq!(
        graph.all_edges().len(),
        0,
        "negative control: the legacy structural relationship population must be empty"
    );
    drop(graph);

    let cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["assess", "target", "--filter", "all", "--format", "json"])
        .output()
        .expect("query shipped CLI Assess");
    assert!(
        cli.status.success(),
        "provider-backed Assess must execute: stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr),
    );
    let cli = stdout_json(&cli);
    assert_eq!(cli["schema_version"], "h00/code-intel/assess/v2");
    assert_eq!(
        cli["blast_radius"]["observed_affected_symbols"], 2,
        "Assess must not return a confident empty blast radius while the immutable provider proves a two-hop chain: {cli}"
    );
    assert_eq!(cli["callers"]["observed_direct_callers"], 1);
    assert_eq!(cli["blast_radius"]["items"][0]["symbol"]["name"], "inner");
    assert_eq!(cli["blast_radius"]["items"][1]["symbol"]["name"], "outer");
    assert_eq!(
        cli["blast_radius"]["items"][0]["execution_path"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    assert_eq!(
        cli["blast_radius"]["items"][1]["execution_path"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(cli["risk"]["observed_transitive_execution_dependents"], 2);
    assert_eq!(cli["risk"]["observed_qualified_binding_dependents"], 0);
    assert_eq!(cli["risk"]["observed_direct_callers"], 1);
    assert_eq!(cli["risk"]["observed_runnable_test_roots"], 0);
    assert!(
        cli["risk"].get("level").is_none(),
        "Assess must report objective evidence instead of a synthetic HIGH/MEDIUM/LOW tier: {cli}"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "assess",
        json!({
            "symbol": "target",
            "filter": "all"
        }),
    );
    assert!(
        mcp.get("error").is_none() && mcp["result"]["isError"] != true,
        "MCP Assess must execute the same shared use case: {mcp}"
    );
    assert_eq!(mcp["result"]["structuredContent"], cli);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[tokio::test]
async fn shipped_inspect_uses_provider_calls_instead_of_legacy_relationship_edges() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "inspect-provider-repo",
        "pub fn caller() { target(); }\npub fn target() {}\n",
    );
    let data_dir = temporary.path().join("bundle");
    let seeded = seed_calls_topology_bundle(
        &root,
        &data_dir,
        &[CallsFixtureEdge {
            caller: "caller",
            callee: "target",
            is_test_only: false,
            is_test_root: false,
        }],
        true,
    )
    .await;

    let calls = stdout_json(&run_calls(&root, &data_dir, &[]));
    assert_eq!(result_count(&calls), Some(1));
    assert_eq!(calls["items"][0]["caller"]["name"], "caller");

    let database = Arc::new(
        redb::ReadOnlyDatabase::open(&seeded.database_path).expect("open Inspect generation"),
    );
    let graph = GraphStore::new_read_only(database)
        .load_snapshot_checked(&root)
        .await
        .expect("load Inspect generation")
        .expect("Inspect graph snapshot");
    assert_eq!(
        graph.all_edges().len(),
        0,
        "negative control: Inspect must not be able to recover the caller from legacy graph edges"
    );
    drop(graph);

    let inspect = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "inspect",
            "target",
            "--sections",
            "callers",
            "--format",
            "json",
        ])
        .output()
        .expect("query shipped CLI Inspect");
    assert!(
        inspect.status.success(),
        "Inspect must execute over the published generation: stdout={} stderr={}",
        String::from_utf8_lossy(&inspect.stdout),
        String::from_utf8_lossy(&inspect.stderr),
    );
    let inspect = stdout_json(&inspect);
    assert_eq!(inspect["schema_version"], "h00/code-intel/inspect/v2");
    assert_eq!(
        inspect["callers"]["result"]["total_callers"], 1,
        "Inspect must compose the canonical provider Calls result instead of returning a confident legacy-graph zero: {inspect}"
    );
    assert_eq!(
        inspect["callers"]["result"]["items"][0]["caller"]["name"],
        "caller"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "inspect",
        json!({"symbol": "target", "sections": ["callers"]}),
    );
    assert!(
        mcp.get("error").is_none() && mcp["result"]["isError"] != true,
        "MCP Inspect must execute the same shared use case: {mcp}"
    );
    assert_eq!(mcp["result"]["structuredContent"], inspect);
    assert_eq!(mcp_text_payload(&mcp), inspect);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[tokio::test]
async fn shipped_inspect_composes_one_complete_function_dossier_across_cli_and_mcp() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "inspect-dossier-repo",
        "pub fn caller() { target(); }\n#[test]\nfn target_test() { target(); }\npub fn target() {}\n",
    );
    let data_dir = temporary.path().join("bundle");
    seed_calls_topology_bundle(
        &root,
        &data_dir,
        &[
            CallsFixtureEdge {
                caller: "caller",
                callee: "target",
                is_test_only: false,
                is_test_root: false,
            },
            CallsFixtureEdge {
                caller: "target_test",
                callee: "target",
                is_test_only: true,
                is_test_root: true,
            },
        ],
        true,
    )
    .await;

    let cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["inspect", "target", "--format", "json"])
        .output()
        .expect("query complete CLI Inspect dossier");
    assert!(
        cli.status.success(),
        "Inspect dossier must execute: stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr),
    );
    let cli = stdout_json(&cli);
    assert_eq!(cli["schema_version"], "h00/code-intel/inspect/v2");
    assert_eq!(cli["authority"]["status"], "complete");
    assert_eq!(cli["authority"]["requested_facets_complete"], true);
    assert_eq!(cli["source"]["status"], "available");
    assert!(
        cli["source"]["result"]["source"]
            .as_str()
            .is_some_and(|source| source.contains("pub fn target()"))
    );
    assert_eq!(cli["structure"]["status"], "not_applicable");
    assert_eq!(cli["callers"]["status"], "available");
    assert_eq!(cli["callers"]["result"]["total_callers"], 2);
    assert_eq!(cli["field_usage"]["status"], "not_applicable");
    assert_eq!(cli["tests"]["status"], "available");
    assert_eq!(cli["tests"]["result"]["page"]["total_items"], 1);
    assert_eq!(
        cli["tests"]["result"]["items"][0]["test"]["name"],
        "target_test"
    );
    assert_eq!(cli["warnings"]["status"], "available");
    assert!(
        serde_json::to_string(&cli)
            .expect("serialize Inspect dossier")
            .chars()
            .count()
            <= h00ligan_engine::code_intel_inspect::MAX_INSPECT_RESULT_CHARS
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "inspect",
        json!({"symbol": "target"}),
    );
    assert_eq!(mcp["result"]["structuredContent"], cli);
    assert_eq!(mcp_text_payload(&mcp), cli);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[tokio::test]
async fn shipped_inspect_adapts_preview_population_to_the_serialized_product_bound() {
    let temporary = TempDir::new().expect("temporary directory");
    let caller_names = (0..24)
        .map(|index| format!("caller_{index:02}_{}", "x".repeat(800)))
        .collect::<Vec<_>>();
    let mut source = String::new();
    for caller in &caller_names {
        source.push_str(&format!("pub fn {caller}() {{ target(); }}\n"));
    }
    source.push_str("pub fn target() {}\n");
    let root = create_source_root(&temporary, "inspect-bound-repo", &source);
    let data_dir = temporary.path().join("bundle");
    let edges = caller_names
        .iter()
        .map(|caller| CallsFixtureEdge {
            caller,
            callee: "target",
            is_test_only: false,
            is_test_root: false,
        })
        .collect::<Vec<_>>();
    seed_calls_topology_bundle(&root, &data_dir, &edges, true).await;

    let cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "inspect",
            "target",
            "--sections",
            "callers",
            "--format",
            "json",
        ])
        .output()
        .expect("query bounded CLI Inspect dossier");
    assert!(
        cli.status.success(),
        "bounded Inspect dossier must execute: stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr),
    );
    let cli = stdout_json(&cli);
    let serialized_chars = serde_json::to_string(&cli)
        .expect("serialize bounded Inspect result")
        .chars()
        .count();
    assert!(
        serialized_chars <= h00ligan_engine::code_intel_inspect::MAX_INSPECT_RESULT_CHARS,
        "Inspect serialized {serialized_chars} characters: {cli}"
    );
    assert_eq!(cli["callers"]["result"]["total_callers"], 24);
    assert!(
        cli["query"]["preview_item_limit"]
            .as_u64()
            .is_some_and(|limit| limit < 20),
        "positive control: the fixture must force adaptive preview reduction: {cli}"
    );
    assert_eq!(cli["callers"]["result"]["page"]["has_more"], true);
    assert!(
        cli["notices"]
            .as_array()
            .is_some_and(|notices| notices.iter().any(|notice| {
                notice
                    .as_str()
                    .is_some_and(|notice| notice.contains("serialized-result bounds reduced"))
            })),
        "Inspect must disclose adaptive result contraction: {cli}"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "inspect",
        json!({"symbol": "target", "sections": ["callers"]}),
    );
    let mcp_result = mcp["result"]["structuredContent"].clone();
    assert_eq!(
        without_ephemeral_cursor_lease(mcp_result.clone()),
        without_ephemeral_cursor_lease(cli.clone()),
        "CLI and MCP Inspect dossiers may issue distinct time-bound cursor leases, but every semantic field must match"
    );
    for (surface, result) in [("CLI", &cli), ("MCP", &mcp_result)] {
        assert!(
            result["callers"]["result"]["page"]["next_cursor"].is_string()
                && result["callers"]["result"]["page"]["expires_at_unix_seconds"].is_u64(),
            "{surface} Inspect must retain the nested time-bound cursor lease: {result}"
        );
    }
    assert_eq!(mcp_text_payload(&mcp), mcp_result);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[tokio::test]
async fn shipped_dead_reconciles_provider_calls_before_reporting_a_symbol_dead() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "dead-provider-repo",
        "pub fn caller() { target(); }\nfn target() {}\n",
    );
    let data_dir = temporary.path().join("bundle");
    let reachability = BTreeMap::from([("target".to_owned(), ReachabilityClass::Dead)]);
    let visibility = BTreeMap::from([("target".to_owned(), "private".to_owned())]);
    let seeded = seed_calls_topology_bundle_with_documents_and_node_overrides(
        &root,
        &data_dir,
        &[CallsFixtureEdge {
            caller: "caller",
            callee: "target",
            is_test_only: false,
            is_test_root: false,
        }],
        true,
        &BTreeMap::new(),
        &reachability,
        &visibility,
    )
    .await;

    let calls = stdout_json(&run_calls(&root, &data_dir, &[]));
    assert_eq!(result_count(&calls), Some(1));
    assert_eq!(calls["items"][0]["caller"]["name"], "caller");

    let database = Arc::new(
        redb::ReadOnlyDatabase::open(&seeded.database_path).expect("open Dead generation"),
    );
    let graph = GraphStore::new_read_only(database)
        .load_snapshot_checked(&root)
        .await
        .expect("load Dead generation")
        .expect("Dead graph snapshot");
    assert_eq!(graph.all_edges().len(), 0);
    assert_eq!(
        graph
            .node_by_name("target")
            .map(|node| node.reachability_class),
        Some(ReachabilityClass::Dead),
        "negative control: the persisted legacy verdict must contradict the provider call"
    );
    drop(graph);

    let cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["dead", "target", "--format", "json"])
        .output()
        .expect("query shipped CLI Dead");
    assert!(
        cli.status.success(),
        "Dead must execute over the published generation: stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr),
    );
    let cli = stdout_json(&cli);
    assert_eq!(
        cli["items"][0]["reachable_from_retained_root"], true,
        "an exact provider caller must defeat the stale legacy Dead label: {cli}"
    );
    assert_eq!(
        cli["items"][0]["verdict"], "live_production",
        "the provider-backed promotion must name its liveness tier: {cli}"
    );
    assert_eq!(
        cli["items"][0]["recommendation"], "keep",
        "a live target must carry no deletion-shaped recommendation: {cli}"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "dead_code",
        json!({"symbol": "target"}),
    );
    assert_eq!(mcp["result"]["structuredContent"], cli);
    assert_eq!(mcp_text_payload(&mcp), cli);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[tokio::test]
async fn shipped_dead_does_not_treat_an_unrooted_caller_cycle_as_liveness() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "dead-cycle-repo",
        "fn caller() { target(); }\nfn target() { caller(); }\n",
    );
    let data_dir = temporary.path().join("bundle");
    let reachability = BTreeMap::from([
        ("caller".to_owned(), ReachabilityClass::Dead),
        ("target".to_owned(), ReachabilityClass::Dead),
    ]);
    let visibility = BTreeMap::from([
        ("caller".to_owned(), "private".to_owned()),
        ("target".to_owned(), "private".to_owned()),
    ]);
    seed_calls_topology_bundle_with_documents_and_node_overrides(
        &root,
        &data_dir,
        &[
            CallsFixtureEdge {
                caller: "caller",
                callee: "target",
                is_test_only: false,
                is_test_root: false,
            },
            CallsFixtureEdge {
                caller: "target",
                callee: "caller",
                is_test_only: false,
                is_test_root: false,
            },
        ],
        true,
        &BTreeMap::new(),
        &reachability,
        &visibility,
    )
    .await;

    let calls = stdout_json(&run_calls(&root, &data_dir, &["--filter", "all"]));
    assert_eq!(result_count(&calls), Some(1));
    assert_eq!(calls["items"][0]["caller"]["name"], "caller");

    let cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["dead", "target", "--format", "json"])
        .output()
        .expect("query shipped CLI Dead cycle control");
    assert!(
        cli.status.success(),
        "Dead cycle control must execute: stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr),
    );
    let cli = stdout_json(&cli);
    assert_eq!(cli["items"][0]["verdict"], "unreached_callable");
    assert_eq!(cli["items"][0]["reachable_from_retained_root"], false);
    assert_eq!(cli["items"][0]["recommendation"], "review");

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "dead_code",
        json!({"symbol": "target"}),
    );
    assert_eq!(mcp["result"]["structuredContent"], cli);
    assert_eq!(mcp_text_payload(&mcp), cli);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

/// FALSIFIER: selected-symbol Dead authority is bounded by the target unit's
/// possible-caller closure, not by unrelated packages that merely share one
/// repository-wide provider payload. The adjacent partial-topology control
/// proves the same negative claim is withheld when that closure is uncertain.
#[tokio::test]
async fn shipped_dead_scopes_negative_authority_to_the_possible_caller_units() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "dead-unit-authority-repo",
        "fn target() { target(); }\n",
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"target-package\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("target package manifest");
    std::fs::create_dir_all(root.join("providers/src"))
        .expect("independent package source directory");
    std::fs::write(
        root.join("providers/Cargo.toml"),
        "[package]\nname = \"independent-package\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("independent package manifest");
    std::fs::write(
        root.join("providers/src/lib.rs"),
        "fn unrelated_dynamic_region() {}\n",
    )
    .expect("independent package source");

    let inventory = build_project_inventory(
        &root,
        &[
            InventorySource::new("src/lib.rs", "rust"),
            InventorySource::new("providers/src/lib.rs", "rust"),
        ],
    );
    assert_eq!(
        inventory.coverage,
        ProjectInventoryCoverage::IndexedSourcePopulationComplete,
        "positive control: both real Cargo packages must be classified"
    );
    let dependency_graph = inventory
        .project_topology
        .dependency_graphs
        .iter()
        .find(|graph| graph.language_id == LanguageId::new("rust"))
        .expect("Rust dependency graph");
    assert_eq!(
        dependency_graph.coverage,
        h00ligan_engine::code_intel_domain::ProjectUnitDependencyGraphCoverage::Complete
    );
    assert_eq!(dependency_graph.project_unit_ids.len(), 2);
    assert!(
        dependency_graph.dependencies.is_empty(),
        "positive control: neither package can call into the other by declared local dependency"
    );
    let owner_for = |document_path: &str| {
        inventory
            .project_topology
            .memberships
            .iter()
            .find(|membership| {
                membership.document_path == document_path
                    && membership.kind == DocumentMembershipKind::SourceOwner
            })
            .expect("source-owner membership")
            .project_unit_id
            .clone()
    };
    let target_owner = owner_for("src/lib.rs");
    let independent_owner = owner_for("providers/src/lib.rs");

    let symbol_documents = BTreeMap::from([(
        "unrelated_dynamic_region".to_owned(),
        "providers/src/lib.rs".to_owned(),
    )]);
    let reachability = BTreeMap::from([
        ("target".to_owned(), ReachabilityClass::Excluded),
        (
            "unrelated_dynamic_region".to_owned(),
            ReachabilityClass::Excluded,
        ),
    ]);
    let visibility = BTreeMap::from([
        ("target".to_owned(), "private".to_owned()),
        ("unrelated_dynamic_region".to_owned(), "private".to_owned()),
    ]);
    let provider_omissions = BTreeSet::from(["unrelated_dynamic_region".to_owned()]);
    let provider_exclusions = BTreeMap::from([(
        "unrelated_dynamic_region".to_owned(),
        "dynamic_callable_region".to_owned(),
    )]);
    let edges = [CallsFixtureEdge {
        caller: "target",
        callee: "target",
        is_test_only: false,
        is_test_root: false,
    }];
    let complete_data_dir = temporary.path().join("complete-bundle");
    seed_calls_topology_bundle_with_documents_and_node_overrides_and_provider_omissions(
        &root,
        &complete_data_dir,
        CallsFixtureOptions {
            edges: &edges,
            structural_authority: true,
            materialize_graph_edges: false,
            symbol_documents: &symbol_documents,
            reachability_overrides: &reachability,
            visibility_overrides: &visibility,
            provider_omissions: &provider_omissions,
            provider_exclusions: &provider_exclusions,
            semantic_inputs: ProviderSemanticInputs::empty(),
            project_inventory: Some(inventory.clone()),
        },
    )
    .await;

    let run_dead = |data_dir: &Path| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(data_dir)
            .args(["dead", "target", "--format", "json"])
            .output()
            .expect("query shipped CLI Dead")
    };
    let complete = run_dead(&complete_data_dir);
    assert!(
        complete.status.success(),
        "unit-scoped Dead must execute: stdout={} stderr={}",
        String::from_utf8_lossy(&complete.stdout),
        String::from_utf8_lossy(&complete.stderr),
    );
    let complete = stdout_json(&complete);
    assert_eq!(complete["items"][0]["verdict"], "unreached_callable");
    assert_eq!(complete["items"][0]["reachable_from_retained_root"], false);
    assert_eq!(complete["items"][0]["evidence"]["status"], "complete");
    assert_eq!(complete["authority"]["status"], "complete");
    assert_eq!(complete["authority"]["calls"]["status"], "complete");
    assert_eq!(dead_language(&complete, "rust")["status"], "complete");

    let complete_audit = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&complete_data_dir)
        .args(["audit", "--min-dead-ratio-percent", "1", "--format", "json"])
        .output()
        .expect("query shipped CLI Audit");
    assert!(complete_audit.status.success());
    let complete_audit = stdout_json(&complete_audit);
    assert_eq!(complete_audit["dead_code"]["status"], "partial");
    assert!(complete_audit["dead_code"]["total"].is_null());
    assert_eq!(
        complete_audit["dead_code"]["authoritative_project_units"],
        1
    );
    assert_eq!(complete_audit["dead_code"]["withheld_project_units"], 1);
    assert!(
        complete_audit["dead_code"]["top_files"]
            .as_array()
            .is_some_and(|files| { files.len() == 1 && files[0]["document_path"] == "src/lib.rs" }),
        "Audit must rank only the admitted unit's dead symbols: {complete_audit}"
    );
    assert!(
        complete_audit["dead_code"]["high_ratio_project_units"]
            .as_array()
            .is_some_and(|units| {
                units.len() == 1 && units[0]["project_unit_id"] == target_owner.0
            }),
        "Audit must retain the target package's exact unit-local health: {complete_audit}"
    );

    let complete_overview = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&complete_data_dir)
        .args(["overview", "--format", "json"])
        .output()
        .expect("query shipped CLI Overview");
    assert!(complete_overview.status.success());
    let complete_overview = stdout_json(&complete_overview);
    assert_eq!(complete_overview["health_status"], "partial");
    let overview_units = complete_overview["project_units"]
        .as_array()
        .expect("Overview project-unit population");
    let target_overview = overview_units
        .iter()
        .find(|unit| unit["project_unit_id"] == target_owner.0)
        .expect("target package Overview row");
    let independent_overview = overview_units
        .iter()
        .find(|unit| unit["project_unit_id"] == independent_owner.0)
        .expect("independent package Overview row");
    assert_eq!(target_overview["health"]["dead"], 1);
    assert!(independent_overview["health"].is_null());

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &complete_data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "dead_code",
        json!({"symbol": "target"}),
    );
    assert_eq!(mcp["result"]["structuredContent"], complete);
    assert_eq!(mcp_text_payload(&mcp), complete);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());

    // Non-vacuity for the batched Audit/Overview fast path: one complete
    // language projection contains both packages, but the persisted complete
    // dependency graph says the independent package cannot call the target.
    // The reusable projection must reapply that exact closure guard rather
    // than leaking a foreign caller into an authoritative unit result.
    let contradictory_data_dir = temporary.path().join("contradictory-bundle");
    std::fs::write(
        root.join("providers/src/lib.rs"),
        "fn unrelated_dynamic_region() { target(); }\n",
    )
    .expect("contradictory independent-package source");
    let contradictory_edges = [CallsFixtureEdge {
        caller: "unrelated_dynamic_region",
        callee: "target",
        is_test_only: false,
        is_test_root: false,
    }];
    let no_omissions = BTreeSet::new();
    let no_exclusions = BTreeMap::new();
    seed_calls_topology_bundle_with_documents_and_node_overrides_and_provider_omissions(
        &root,
        &contradictory_data_dir,
        CallsFixtureOptions {
            edges: &contradictory_edges,
            structural_authority: true,
            materialize_graph_edges: false,
            symbol_documents: &symbol_documents,
            reachability_overrides: &reachability,
            visibility_overrides: &visibility,
            provider_omissions: &no_omissions,
            provider_exclusions: &no_exclusions,
            semantic_inputs: ProviderSemanticInputs::empty(),
            project_inventory: Some(inventory.clone()),
        },
    )
    .await;
    for operation in ["audit", "overview"] {
        let output = h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&contradictory_data_dir)
            .args([operation, "--format", "json"])
            .output()
            .expect("query contradictory batched liveness population");
        assert!(
            !output.status.success(),
            "{operation} must reject a foreign caller that contradicts the persisted dependency closure"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("contradicts the persisted possible-caller dependency population"),
            "{operation} must fail for the intended closure contradiction: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    let mut partial_inventory = inventory;
    let dependency_graph = partial_inventory
        .project_topology
        .dependency_graphs
        .first_mut()
        .expect("Cargo dependency graph");
    dependency_graph.coverage =
        h00ligan_engine::code_intel_domain::ProjectUnitDependencyGraphCoverage::Partial;
    dependency_graph.gaps.push(
        h00ligan_engine::code_intel_domain::ProjectUnitDependencyGap {
            reason_code: "falsifier_topology_unknown".into(),
            project_unit_id: None,
            path: "Cargo.toml".into(),
            detail: "positive fail-closed control".into(),
        },
    );
    let partial_data_dir = temporary.path().join("partial-bundle");
    seed_calls_topology_bundle_with_documents_and_node_overrides_and_provider_omissions(
        &root,
        &partial_data_dir,
        CallsFixtureOptions {
            edges: &edges,
            structural_authority: true,
            materialize_graph_edges: false,
            symbol_documents: &symbol_documents,
            reachability_overrides: &reachability,
            visibility_overrides: &visibility,
            provider_omissions: &provider_omissions,
            provider_exclusions: &provider_exclusions,
            semantic_inputs: ProviderSemanticInputs::empty(),
            project_inventory: Some(partial_inventory),
        },
    )
    .await;
    let partial = run_dead(&partial_data_dir);
    assert!(partial.status.success());
    let partial = stdout_json(&partial);
    assert_eq!(partial["items"][0]["verdict"], "unknown");
    assert!(
        partial["items"][0]["reachable_from_retained_root"].is_null(),
        "partial dependency evidence cannot authorize a negative liveness claim"
    );
    assert_eq!(partial["items"][0]["evidence"]["status"], "qualified");
    assert_eq!(partial["authority"]["status"], "qualified");
    assert_eq!(partial["authority"]["calls"]["status"], "qualified");
    assert_eq!(dead_language(&partial, "rust")["status"], "qualified");

    let partial_audit = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&partial_data_dir)
        .args(["audit", "--min-dead-ratio-percent", "1", "--format", "json"])
        .output()
        .expect("query partial-topology Audit");
    assert!(partial_audit.status.success());
    let partial_audit = stdout_json(&partial_audit);
    assert_eq!(partial_audit["dead_code"]["status"], "unavailable");
    assert_eq!(partial_audit["dead_code"]["authoritative_project_units"], 0);
    assert_eq!(partial_audit["dead_code"]["withheld_project_units"], 2);

    let partial_overview = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&partial_data_dir)
        .args(["overview", "--format", "json"])
        .output()
        .expect("query partial-topology Overview");
    assert!(partial_overview.status.success());
    let partial_overview = stdout_json(&partial_overview);
    assert_eq!(partial_overview["health_status"], "partial");
    assert!(
        partial_overview["project_units"]
            .as_array()
            .is_some_and(|units| units.iter().all(|unit| unit["health"].is_null())),
        "partial dependency topology must withhold every unit health slice"
    );
}

#[tokio::test]
async fn shipped_dead_does_not_nominate_a_structurally_retained_test_callable() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "dead-test-retention-repo", "");
    std::fs::create_dir_all(root.join("tests")).expect("test fixture directory");
    std::fs::write(
        root.join("tests/helpers.rs"),
        "fn dynamic_handler() { dynamic_handler(); }\n",
    )
    .expect("test helper source");
    let data_dir = temporary.path().join("bundle");
    let symbol_documents =
        BTreeMap::from([("dynamic_handler".to_owned(), "tests/helpers.rs".to_owned())]);
    let reachability =
        BTreeMap::from([("dynamic_handler".to_owned(), ReachabilityClass::TestOnly)]);
    let visibility = BTreeMap::from([("dynamic_handler".to_owned(), "private".to_owned())]);
    seed_calls_topology_bundle_with_documents_and_node_overrides(
        &root,
        &data_dir,
        &[CallsFixtureEdge {
            caller: "dynamic_handler",
            callee: "dynamic_handler",
            is_test_only: true,
            is_test_root: false,
        }],
        true,
        &symbol_documents,
        &reachability,
        &visibility,
    )
    .await;

    let single = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["dead", "dynamic_handler", "--format", "json"])
        .output()
        .expect("query retained test callable");
    assert!(
        single.status.success(),
        "Dead query must execute: stdout={} stderr={}",
        String::from_utf8_lossy(&single.stdout),
        String::from_utf8_lossy(&single.stderr),
    );
    let single = stdout_json(&single);
    let item = &single["items"][0];
    assert_eq!(item["callable"], true);
    assert_eq!(item["persisted_reachability"], "TestOnly");
    assert_eq!(item["verdict"], "retained_structural");
    assert!(item["reachable_from_retained_root"].is_null());
    assert_eq!(item["recommendation"], "keep");
    assert_eq!(item["evidence"]["status"], "qualified");
    assert_eq!(
        item["evidence"]["reason_code"],
        "test_callable_retained_by_structural_reachability"
    );

    let full = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["dead", "--format", "json"])
        .output()
        .expect("query full Dead candidate population");
    assert!(full.status.success());
    let full = stdout_json(&full);
    assert_eq!(full["summary"]["candidate_items"], 0);
    assert_eq!(full["page"]["total_items"], 0);
}

#[tokio::test]
async fn shipped_dead_surfaces_an_unjoined_callable_even_when_its_old_label_says_live() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "dead-unjoined-repo",
        "pub fn root() { live_target(); }\nfn live_target() {}\nfn omitted_callable() {}\n",
    );
    let data_dir = temporary.path().join("bundle");
    let reachability = BTreeMap::from([
        ("live_target".to_owned(), ReachabilityClass::Dead),
        ("omitted_callable".to_owned(), ReachabilityClass::Wired),
    ]);
    let visibility = BTreeMap::from([
        ("root".to_owned(), "pub".to_owned()),
        ("live_target".to_owned(), "private".to_owned()),
        ("omitted_callable".to_owned(), "private".to_owned()),
    ]);
    let provider_omissions = BTreeSet::from(["omitted_callable".to_owned()]);
    let provider_exclusions = BTreeMap::new();
    seed_calls_topology_bundle_with_documents_and_node_overrides_and_provider_omissions(
        &root,
        &data_dir,
        CallsFixtureOptions {
            edges: &[CallsFixtureEdge {
                caller: "root",
                callee: "live_target",
                is_test_only: false,
                is_test_root: false,
            }],
            structural_authority: true,
            materialize_graph_edges: false,
            symbol_documents: &BTreeMap::new(),
            reachability_overrides: &reachability,
            visibility_overrides: &visibility,
            provider_omissions: &provider_omissions,
            provider_exclusions: &provider_exclusions,
            semantic_inputs: ProviderSemanticInputs::empty(),
            project_inventory: None,
        },
    )
    .await;

    let calls = stdout_json(&run_calls_for(
        &root,
        &data_dir,
        "live_target",
        &["--filter", "all"],
    ));
    assert_eq!(result_count(&calls), Some(1));
    assert_eq!(calls["items"][0]["caller"]["name"], "root");

    let run_dead = |extra: &[&str]| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("dead")
            .args(extra)
            .args(["--format", "json"])
            .output()
            .expect("query shipped CLI Dead")
    };
    let full = run_dead(&[]);
    assert!(
        full.status.success(),
        "Dead must surface the authority gap: stdout={} stderr={}",
        String::from_utf8_lossy(&full.stdout),
        String::from_utf8_lossy(&full.stderr),
    );
    let full = stdout_json(&full);
    assert_eq!(full["authority"]["calls"]["status"], "complete");
    assert_eq!(dead_language(&full, "rust")["status"], "qualified");
    assert_eq!(dead_language(&full, "rust")["unjoined_source_callables"], 1);
    assert_eq!(full["authority"]["callable_population_complete"], false);
    assert_eq!(full["authority"]["item_evidence_complete"], false);
    assert_eq!(full["authority"]["population_complete"], false);
    assert_eq!(full["summary"]["observed_items"], 1);
    assert_eq!(full["summary"]["candidate_items"], 1);
    let omitted = dead_item(&full, "omitted_callable");
    assert_eq!(omitted["persisted_reachability"], "Wired");
    assert_eq!(omitted["verdict"], "unknown");
    assert!(omitted["reachable_from_retained_root"].is_null());
    assert_eq!(omitted["recommendation"], "withheld");
    assert_eq!(
        omitted["evidence"]["reason_code"],
        "callable_outside_provider_population"
    );

    let live = run_dead(&["live_target"]);
    assert!(live.status.success());
    let live = stdout_json(&live);
    assert_eq!(live["items"][0]["verdict"], "live_production");
    assert_eq!(live["items"][0]["reachable_from_retained_root"], true);

    let omitted_calls = run_calls_for(&root, &data_dir, "omitted_callable", &[]);
    assert!(
        !omitted_calls.status.success(),
        "a callable outside the provider population must refuse rather than inventing zero callers"
    );
    let omitted_calls = stdout_json(&omitted_calls);
    assert_eq!(
        omitted_calls["error"]["code"],
        "symbol_outside_provider_population"
    );
    assert_eq!(
        omitted_calls["error"]["evidence"][0]["reason_code"],
        "callable_outside_provider_population"
    );
    assert!(
        !omitted_calls["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("generation is invalid")
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_full = call_mcp(&mut stdin, &mut stdout, 1, "dead_code", json!({}));
    let mcp_live = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "dead_code",
        json!({"symbol": "live_target"}),
    );
    assert_eq!(mcp_full["result"]["structuredContent"], full);
    assert_eq!(mcp_live["result"]["structuredContent"], live);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[tokio::test]
async fn shipped_dead_preserves_positive_paths_but_withholds_excluded_negative_claims() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "dead-qualified-repo",
        "pub fn root() { reached_target(); }\nfn reached_target() {}\nfn excluded_unreached() { excluded_unreached(); }\n",
    );
    let data_dir = temporary.path().join("bundle");
    let reachability = BTreeMap::from([
        ("reached_target".to_owned(), ReachabilityClass::Dead),
        ("excluded_unreached".to_owned(), ReachabilityClass::Dead),
    ]);
    let visibility = BTreeMap::from([
        ("root".to_owned(), "pub".to_owned()),
        ("reached_target".to_owned(), "private".to_owned()),
        ("excluded_unreached".to_owned(), "private".to_owned()),
    ]);
    let provider_omissions = BTreeSet::from(["excluded_unreached".to_owned()]);
    let provider_exclusions = BTreeMap::from([(
        "excluded_unreached".to_owned(),
        "conditional_compilation".to_owned(),
    )]);
    seed_calls_topology_bundle_with_documents_and_node_overrides_and_provider_omissions(
        &root,
        &data_dir,
        CallsFixtureOptions {
            edges: &[CallsFixtureEdge {
                caller: "root",
                callee: "reached_target",
                is_test_only: false,
                is_test_root: false,
            }],
            structural_authority: true,
            materialize_graph_edges: false,
            symbol_documents: &BTreeMap::new(),
            reachability_overrides: &reachability,
            visibility_overrides: &visibility,
            provider_omissions: &provider_omissions,
            provider_exclusions: &provider_exclusions,
            semantic_inputs: ProviderSemanticInputs::empty(),
            project_inventory: None,
        },
    )
    .await;

    let calls = stdout_json(&run_calls_for(
        &root,
        &data_dir,
        "reached_target",
        &["--filter", "all"],
    ));
    assert_eq!(result_count(&calls), Some(1));
    assert_eq!(calls["items"][0]["caller"]["name"], "root");
    assert_eq!(calls["authority"]["status"], "qualified");

    let run_dead = |extra: &[&str]| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("dead")
            .args(extra)
            .args(["--format", "json"])
            .output()
            .expect("query shipped CLI Dead")
    };
    let live = run_dead(&["reached_target"]);
    assert!(live.status.success());
    let live = stdout_json(&live);
    assert_eq!(live["items"][0]["verdict"], "live_production");
    assert_eq!(live["items"][0]["reachable_from_retained_root"], true);
    assert_eq!(live["items"][0]["evidence"]["status"], "complete");
    assert_eq!(dead_language(&live, "rust")["status"], "qualified");
    assert_eq!(dead_language(&live, "rust")["unjoined_source_callables"], 0);

    let full = run_dead(&[]);
    assert!(full.status.success());
    let full = stdout_json(&full);
    assert_eq!(full["summary"]["observed_items"], 1);
    assert_eq!(full["summary"]["candidate_items"], 1);
    let excluded = dead_item(&full, "excluded_unreached");
    assert_eq!(excluded["verdict"], "unknown");
    assert!(excluded["reachable_from_retained_root"].is_null());
    assert_eq!(excluded["recommendation"], "withheld");
    assert_eq!(excluded["evidence"]["status"], "qualified");
    assert_eq!(
        excluded["evidence"]["reason_code"],
        "provider_coverage_exclusions"
    );
    assert_eq!(full["authority"]["callable_population_complete"], false);
    assert_eq!(full["authority"]["item_evidence_complete"], false);
    assert_eq!(full["authority"]["population_complete"], false);

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_live = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "dead_code",
        json!({"symbol": "reached_target"}),
    );
    let mcp_full = call_mcp(&mut stdin, &mut stdout, 2, "dead_code", json!({}));
    assert_eq!(mcp_live["result"]["structuredContent"], live);
    assert_eq!(mcp_full["result"]["structuredContent"], full);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[tokio::test]
async fn shipped_dead_reconciles_transitive_provider_paths_from_structural_roots() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "dead-transitive-repo",
        "pub fn root() { middle(); }\nfn middle() { target(); }\nfn target() {}\n",
    );
    let data_dir = temporary.path().join("bundle");
    let reachability = BTreeMap::from([
        ("middle".to_owned(), ReachabilityClass::Dead),
        ("target".to_owned(), ReachabilityClass::Dead),
    ]);
    let visibility = BTreeMap::from([
        ("root".to_owned(), "pub".to_owned()),
        ("middle".to_owned(), "private".to_owned()),
        ("target".to_owned(), "private".to_owned()),
    ]);
    seed_calls_topology_bundle_with_documents_and_node_overrides(
        &root,
        &data_dir,
        &[
            CallsFixtureEdge {
                caller: "root",
                callee: "middle",
                is_test_only: false,
                is_test_root: false,
            },
            CallsFixtureEdge {
                caller: "middle",
                callee: "target",
                is_test_only: false,
                is_test_root: false,
            },
        ],
        true,
        &BTreeMap::new(),
        &reachability,
        &visibility,
    )
    .await;

    let run_dead = |extra: &[&str]| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("dead")
            .args(extra)
            .args(["--format", "json"])
            .output()
            .expect("query shipped CLI Dead")
    };
    let target = run_dead(&["target"]);
    assert!(target.status.success());
    let target = stdout_json(&target);
    assert_eq!(target["items"][0]["persisted_reachability"], "Dead");
    assert_eq!(target["items"][0]["verdict"], "live_production");
    assert_eq!(target["items"][0]["reachable_from_retained_root"], true);
    assert_eq!(target["items"][0]["recommendation"], "keep");
    assert_eq!(target["summary"]["observed_items"], 1);
    assert_eq!(target["summary"]["candidate_items"], 0);

    let full = run_dead(&[]);
    assert!(full.status.success());
    let full = stdout_json(&full);
    assert_eq!(full["authority"]["status"], "complete");
    assert_eq!(full["authority"]["callable_population_complete"], true);
    assert_eq!(full["authority"]["item_evidence_complete"], true);
    assert_eq!(full["authority"]["population_complete"], true);
    assert_eq!(full["summary"]["observed_items"], 0);
    assert_eq!(full["summary"]["candidate_items"], 0);
    assert_eq!(full["page"]["total_items"], 0);

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_target = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "dead_code",
        json!({"symbol": "target"}),
    );
    let mcp_full = call_mcp(&mut stdin, &mut stdout, 2, "dead_code", json!({}));
    assert_eq!(mcp_target["result"]["structuredContent"], target);
    assert_eq!(mcp_full["result"]["structuredContent"], full);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[test]
fn shipped_dead_keeps_noncallable_candidates_qualified_and_non_destructive() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "dead-structural-repo",
        concat!(
            "struct Dormant { value: usize }\n\n",
            "struct Config;\n",
            "impl Default for Config { fn default() -> Self { Self } }\n\n",
            "pub fn live() -> usize { 42 }\n",
        ),
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"dead_structural_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("publish structural-only fixture");
    assert!(
        indexed.status.success(),
        "structural indexing must succeed without a Calls provider: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let type_query = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["type", "Dormant", "--format", "json"])
        .output()
        .expect("query structural positive control");
    assert!(type_query.status.success());
    assert_eq!(stdout_json(&type_query)["resolved_type"]["name"], "Dormant");

    let dead = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["dead", "Dormant", "--format", "json"])
        .output()
        .expect("query structural Dead candidate");
    assert!(
        dead.status.success(),
        "structural Dead query must remain useful: stdout={} stderr={}",
        String::from_utf8_lossy(&dead.stdout),
        String::from_utf8_lossy(&dead.stderr),
    );
    let dead = stdout_json(&dead);
    assert_eq!(dead["items"][0]["callable"], false);
    assert_eq!(dead["items"][0]["verdict"], "structural_candidate");
    assert!(dead["items"][0]["reachable_from_retained_root"].is_null());
    assert_eq!(dead["items"][0]["recommendation"], "review");
    assert_eq!(dead["items"][0]["evidence"]["status"], "qualified");
    assert_eq!(
        dead["items"][0]["evidence"]["reason_code"],
        "structural_candidate_not_provider_reconciled"
    );
    assert_eq!(dead["summary"]["observed_items"], 1);
    assert_eq!(dead["summary"]["candidate_items"], 1);
    assert_eq!(dead["authority"]["structural_candidates_qualified"], true);
    assert_eq!(dead["authority"]["item_evidence_complete"], false);
    assert_eq!(dead["authority"]["population_complete"], false);

    let full_output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["dead", "--limit", "100", "--format", "json"])
        .output()
        .expect("query full structural Dead candidate population");
    assert!(full_output.status.success());
    let full = stdout_json(&full_output);
    let full_items = full["items"].as_array().expect("full Dead items");
    assert!(
        full_items
            .iter()
            .any(|item| item["symbol"]["name"] == "Dormant"),
        "known-positive local candidate must remain in the full report: {full}"
    );
    assert!(
        full_items
            .iter()
            .all(|item| item["symbol"]["source_backed"] == true),
        "synthetic external anchors are graph navigation aids, not user-owned dead code candidates: {full}"
    );

    let external_output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["dead", "Default", "--format", "json"])
        .output()
        .expect("inspect an exact external graph anchor");
    assert!(external_output.status.success());
    let external = stdout_json(&external_output);
    assert_eq!(external["items"][0]["symbol"]["source_backed"], false);
    assert_eq!(external["summary"]["observed_items"], 1);
    assert_eq!(
        external["summary"]["candidate_items"], 0,
        "explicit graph-anchor inspection remains available without calling it user-owned dead code"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "dead_code",
        json!({"symbol": "Dormant"}),
    );
    let mcp_full = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "dead_code",
        json!({"limit": 100}),
    );
    let mcp_external = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "dead_code",
        json!({"symbol": "Default"}),
    );
    assert_eq!(mcp["result"]["structuredContent"], dead);
    assert_eq!(mcp_text_payload(&mcp), dead);
    assert_eq!(mcp_full["result"]["structuredContent"], full);
    assert_eq!(mcp_text_payload(&mcp_full), full);
    assert_eq!(mcp_external["result"]["structuredContent"], external);
    assert_eq!(mcp_text_payload(&mcp_external), external);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[test]
fn shipped_dead_full_report_excludes_import_syntax_without_deadness_authority() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("dead-import-repo");
    std::fs::create_dir_all(&root).expect("source directory");
    std::fs::write(
        root.join("go.mod"),
        "module example.com/deadimport\n\ngo 1.25\n",
    )
    .expect("Go manifest");
    std::fs::write(
        root.join("main.go"),
        concat!(
            "package deadimport\n\n",
            "import \"fmt\"\n\n",
            "type Dormant struct { Value int }\n\n",
            "func Live() string { return fmt.Sprint(\"live\") }\n",
        ),
    )
    .expect("Go source fixture");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish structural Go fixture");
    assert!(
        indexed.status.success(),
        "positive control: structural indexing must publish the fixture: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let imported = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["find", "fmt", "--name", "--format", "json"])
        .output()
        .expect("query populated import control");
    assert!(imported.status.success());
    let imported = stdout_json(&imported);
    assert!(
        imported["items"].as_array().is_some_and(|items| {
            items
                .iter()
                .any(|item| item["name"] == "fmt" && item["kind"] == "import")
        }),
        "positive control: the indexed generation must contain the source-backed import: {imported}"
    );

    let dead = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["dead", "--limit", "100", "--format", "json"])
        .output()
        .expect("query full Dead report");
    assert!(dead.status.success());
    let dead = stdout_json(&dead);
    let items = dead["items"].as_array().expect("Dead items");
    assert!(
        items.iter().any(|item| item["symbol"]["name"] == "Dormant"),
        "positive control: a source-backed structural definition remains reviewable: {dead}"
    );
    assert!(
        items.iter().all(|item| {
            !matches!(
                item["symbol"]["kind"].as_str(),
                Some("use" | "import" | "export")
            )
        }),
        "full Dead candidates must not include import syntax for which structural reachability has no deadness authority: {dead}"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "dead_code",
        json!({"limit": 100}),
    );
    assert_eq!(mcp["result"]["structuredContent"], dead);
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[tokio::test]
async fn shipped_dead_pages_the_full_population_and_bounds_cli_and_mcp_results() {
    let temporary = TempDir::new().expect("temporary directory");
    let caller_names = (0..48)
        .map(|index| format!("candidate_{index:03}_{}", "x".repeat(250)))
        .collect::<Vec<_>>();
    let mut source = String::new();
    for caller in &caller_names {
        source.push_str(&format!("fn {caller}() {{ target(); }}\n"));
    }
    source.push_str("fn target() {}\n");
    let root = create_source_root(&temporary, "dead-page-repo", &source);
    let data_dir = temporary.path().join("bundle");
    let edges = caller_names
        .iter()
        .map(|caller| CallsFixtureEdge {
            caller,
            callee: "target",
            is_test_only: false,
            is_test_root: false,
        })
        .collect::<Vec<_>>();
    let mut visibility = caller_names
        .iter()
        .map(|caller| (caller.clone(), "private".to_owned()))
        .collect::<BTreeMap<_, _>>();
    visibility.insert("target".into(), "private".into());
    seed_calls_topology_bundle_with_documents_and_node_overrides(
        &root,
        &data_dir,
        &edges,
        true,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &visibility,
    )
    .await;

    let run_page = |limit: &str, cursor: Option<&str>| {
        let mut command = h00ligan();
        command
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["dead", "--limit", limit, "--format", "json"]);
        if let Some(cursor) = cursor {
            command.args(["--cursor", cursor]);
        }
        command.output().expect("query paged CLI Dead")
    };
    let first = run_page("17", None);
    assert!(first.status.success());
    let first = stdout_json(&first);
    assert_eq!(first["authority"]["status"], "complete");
    assert_eq!(first["summary"]["observed_items"], 49);
    assert_eq!(first["summary"]["candidate_items"], 49);
    assert_eq!(first["page"]["offset"], 0);
    assert_eq!(first["page"]["limit"], 17);
    assert_eq!(first["page"]["returned"], 17);
    assert_eq!(first["page"]["total_items"], 49);
    assert_eq!(first["page"]["has_more"], true);
    let first_cursor = first["page"]["next_cursor"]
        .as_str()
        .expect("first-page cursor")
        .to_owned();

    let second = run_page("17", Some(&first_cursor));
    assert!(second.status.success());
    let second = stdout_json(&second);
    assert_eq!(second["page"]["offset"], 17);
    assert_eq!(second["page"]["returned"], 17);
    assert_eq!(second["page"]["total_items"], 49);
    let names = |value: &Value| {
        value["items"]
            .as_array()
            .expect("Dead items")
            .iter()
            .map(|item| {
                item["symbol"]["name"]
                    .as_str()
                    .expect("Dead symbol name")
                    .to_owned()
            })
            .collect::<BTreeSet<_>>()
    };
    assert!(
        names(&first).is_disjoint(&names(&second)),
        "cursor continuation must not replay the first page"
    );

    let bounded = run_page("100", None);
    assert!(bounded.status.success());
    let bounded = stdout_json(&bounded);
    let bounded_chars = serde_json::to_string(&bounded)
        .expect("serialize bounded Dead result")
        .chars()
        .count();
    assert!(
        bounded_chars <= h00ligan_engine::code_intel_dead::MAX_DEAD_RESULT_CHARS,
        "Dead result must apply its product bound before transport: {bounded_chars}"
    );
    assert_eq!(bounded["page"]["total_items"], 49);
    assert!(
        bounded["page"]["returned"]
            .as_u64()
            .is_some_and(|returned| returned > 0 && returned < 49),
        "the long-name fixture must force adaptive page reduction: {bounded}"
    );
    assert!(
        bounded["page"]["limit"]
            .as_u64()
            .is_some_and(|limit| limit < 100)
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_first = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "dead_code",
        json!({"limit": 17}),
    );
    let mcp_second = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "dead_code",
        json!({"limit": 17, "cursor": first_cursor}),
    );
    let mcp_bounded = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "dead_code",
        json!({"limit": 100}),
    );
    assert_eq!(
        without_ephemeral_cursor_lease(mcp_first["result"]["structuredContent"].clone()),
        without_ephemeral_cursor_lease(first)
    );
    assert_eq!(
        without_ephemeral_cursor_lease(mcp_second["result"]["structuredContent"].clone()),
        without_ephemeral_cursor_lease(second)
    );
    assert_eq!(
        without_ephemeral_cursor_lease(mcp_bounded["result"]["structuredContent"].clone()),
        without_ephemeral_cursor_lease(bounded)
    );
    assert_eq!(
        mcp_text_payload(&mcp_bounded),
        mcp_bounded["result"]["structuredContent"]
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[tokio::test]
async fn shipped_dead_production_filter_uses_structural_test_facts_not_old_labels() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "dead-production-filter-repo",
        "fn production_candidate() { production_candidate(); }\n",
    );
    std::fs::create_dir_all(root.join("tests")).expect("test fixture directory");
    std::fs::write(
        root.join("tests/helpers.rs"),
        "fn test_candidate() { test_candidate(); }\n",
    )
    .expect("test fixture source");
    let data_dir = temporary.path().join("bundle");
    let symbol_documents =
        BTreeMap::from([("test_candidate".to_owned(), "tests/helpers.rs".to_owned())]);
    let reachability = BTreeMap::from([
        (
            "production_candidate".to_owned(),
            ReachabilityClass::TestOnly,
        ),
        ("test_candidate".to_owned(), ReachabilityClass::Dead),
    ]);
    let visibility = BTreeMap::from([
        ("production_candidate".to_owned(), "private".to_owned()),
        ("test_candidate".to_owned(), "private".to_owned()),
    ]);
    seed_calls_topology_bundle_with_documents_and_node_overrides(
        &root,
        &data_dir,
        &[
            CallsFixtureEdge {
                caller: "production_candidate",
                callee: "production_candidate",
                is_test_only: false,
                is_test_root: false,
            },
            CallsFixtureEdge {
                caller: "test_candidate",
                callee: "test_candidate",
                is_test_only: false,
                is_test_root: false,
            },
        ],
        true,
        &symbol_documents,
        &reachability,
        &visibility,
    )
    .await;

    let run = |production_only: bool| {
        let mut command = h00ligan();
        command
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("dead");
        if production_only {
            command.arg("--production-only");
        }
        command
            .args(["--format", "json"])
            .output()
            .expect("query production-filtered Dead")
    };
    let all = run(false);
    assert!(all.status.success());
    let all = stdout_json(&all);
    assert_eq!(all["page"]["total_items"], 2);
    assert!(dead_item(&all, "production_candidate").is_object());
    assert!(dead_item(&all, "test_candidate").is_object());

    let production = run(true);
    assert!(production.status.success());
    let production = stdout_json(&production);
    assert_eq!(production["query"]["production_only"], true);
    assert_eq!(production["page"]["total_items"], 1);
    assert_eq!(
        production["items"][0]["symbol"]["name"],
        "production_candidate"
    );
    assert_eq!(
        production["items"][0]["persisted_reachability"], "TestOnly",
        "a stale derived label must not override concrete source/test facts"
    );

    let invalid_single = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "dead",
            "production_candidate",
            "--production-only",
            "--format",
            "json",
        ])
        .output()
        .expect("reject a no-op single-symbol production filter");
    assert!(!invalid_single.status.success());
    let invalid_single = stdout_json(&invalid_single);
    assert_eq!(invalid_single["error"]["code"], "invalid_request");
    assert!(
        invalid_single["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("production_only"))
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "dead_code",
        json!({"production_only": true}),
    );
    let mcp_invalid_single = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "dead_code",
        json!({"symbol": "production_candidate", "production_only": true}),
    );
    assert_eq!(mcp["result"]["structuredContent"], production);
    assert_eq!(mcp_invalid_single["result"]["isError"], true);
    assert_eq!(
        mcp_invalid_single["result"]["structuredContent"],
        invalid_single
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[test]
fn shipped_inspect_keeps_structural_facets_useful_without_inventing_field_usage_authority() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "inspect-struct-repo",
        "pub struct Settings {\n    pub timeout: u64,\n}\n\npub fn read_timeout(settings: &Settings) -> u64 { settings.timeout }\n",
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"inspect_struct_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish structural Inspect fixture");
    assert!(
        indexed.status.success(),
        "structural fixture must publish: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["inspect", "Settings", "--format", "json"])
        .output()
        .expect("query structural CLI Inspect dossier");
    assert!(
        cli.status.success(),
        "structural Inspect must remain useful without Calls: stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr),
    );
    let cli = stdout_json(&cli);
    assert_eq!(cli["source"]["status"], "available");
    assert_eq!(cli["structure"]["status"], "available");
    assert_eq!(cli["structure"]["result"]["totals"]["fields"], 1);
    assert_eq!(cli["callers"]["status"], "not_applicable");
    assert_eq!(cli["tests"]["status"], "not_applicable");
    assert_eq!(cli["field_usage"]["status"], "qualified");
    assert_eq!(
        cli["field_usage"]["result"]["authority"]["population_complete"],
        false
    );
    assert_eq!(
        cli["field_usage"]["result"]["authority"]["false_positives_possible"],
        true
    );
    assert_eq!(
        cli["field_usage"]["result"]["authority"]["false_negatives_possible"],
        true
    );
    assert!(
        cli["field_usage"]["result"]["warnings"][0]
            .as_str()
            .is_some_and(|warning| warning.contains("not an exact reference census")),
        "empty heuristic observations must not masquerade as unused-field proof: {cli}"
    );
    assert_eq!(cli["warnings"]["status"], "qualified");
    assert!(cli["warnings"]["result"].get("reachability").is_none());
    assert!(cli["warnings"]["result"].get("action_tier").is_none());
    assert!(
        cli["warnings"]["result"]["signals"]
            .as_array()
            .is_some_and(|signals| signals
                .iter()
                .any(|signal| signal["code"] == "reachability_not_authorized")),
        "non-callable targets must not inherit an unsupported action tier: {cli}"
    );
    assert_eq!(cli["authority"]["status"], "qualified");
    assert_eq!(cli["authority"]["requested_facets_complete"], false);

    let callable_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "inspect",
            "read_timeout",
            "--sections",
            "source,callers,tests,warnings",
            "--format",
            "json",
        ])
        .output()
        .expect("query callable Inspect without Calls authority");
    assert!(
        callable_cli.status.success(),
        "one unavailable capability must not erase useful Inspect facets: stdout={} stderr={}",
        String::from_utf8_lossy(&callable_cli.stdout),
        String::from_utf8_lossy(&callable_cli.stderr),
    );
    let callable_cli = stdout_json(&callable_cli);
    assert_eq!(callable_cli["source"]["status"], "available");
    assert_eq!(callable_cli["callers"]["status"], "unavailable");
    assert_eq!(
        callable_cli["callers"]["issue"]["code"],
        "capability_unavailable"
    );
    assert_eq!(callable_cli["tests"]["status"], "unavailable");
    assert_eq!(
        callable_cli["tests"]["issue"]["code"],
        "capability_unavailable"
    );
    assert_eq!(callable_cli["warnings"]["status"], "qualified");
    assert_eq!(
        callable_cli["warnings"]["result"]["reachability"],
        json!(null)
    );
    assert_eq!(
        callable_cli["warnings"]["result"]["action_tier"],
        json!(null)
    );
    assert!(
        callable_cli["warnings"]["result"]["signals"]
            .as_array()
            .is_some_and(|signals| signals
                .iter()
                .any(|signal| { signal["code"] == "reachability_evidence_unavailable" })),
        "Inspect must explain why it withheld reachability judgment: {callable_cli}"
    );
    assert_eq!(callable_cli["authority"]["status"], "qualified");
    assert_eq!(
        callable_cli["authority"]["requested_facets_complete"],
        false
    );

    for (label, sections) in [
        ("unknown section", "source,everything"),
        ("duplicate section", "source,source"),
    ] {
        let invalid = h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args([
                "inspect",
                "Settings",
                "--sections",
                sections,
                "--format",
                "json",
            ])
            .output()
            .unwrap_or_else(|error| panic!("run {label} Inspect control: {error}"));
        assert!(!invalid.status.success(), "{label} must be rejected");
        let invalid = stdout_json(&invalid);
        assert_eq!(invalid["error"]["code"], "invalid_request");
        assert!(
            invalid["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("sections")),
            "{label} must identify the invalid field: {invalid}"
        );
    }

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "inspect",
        json!({"symbol": "Settings"}),
    );
    let unknown_section = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "inspect",
        json!({"symbol": "Settings", "sections": ["source", "everything"]}),
    );
    let duplicate_section = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "inspect",
        json!({"symbol": "Settings", "sections": ["source", "source"]}),
    );
    let extra_property = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "inspect",
        json!({"symbol": "Settings", "detail": "full"}),
    );
    let callable_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        5,
        "inspect",
        json!({
            "symbol": "read_timeout",
            "sections": ["source", "callers", "tests", "warnings"]
        }),
    );
    assert_eq!(mcp["result"]["structuredContent"], cli);
    assert_eq!(mcp_text_payload(&mcp), cli);
    assert_eq!(callable_mcp["result"]["structuredContent"], callable_cli);
    assert_eq!(mcp_text_payload(&callable_mcp), callable_cli);
    for (label, response) in [
        ("unknown section", unknown_section),
        ("duplicate section", duplicate_section),
        ("unadvertised property", extra_property),
    ] {
        assert_eq!(
            response["error"]["code"], -32602,
            "MCP must reject {label} against the advertised Inspect schema before dispatch: {response}"
        );
    }
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[tokio::test]
async fn shipped_assess_pages_one_bound_provider_impact_population_and_exposes_depth_cutoffs() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "assess-page-repo",
        "pub fn outer() { inner(); }\npub fn inner() { target(); }\npub fn target() {}\n",
    );
    let data_dir = temporary.path().join("bundle");
    let edges = [
        CallsFixtureEdge {
            caller: "outer",
            callee: "inner",
            is_test_only: false,
            is_test_root: false,
        },
        CallsFixtureEdge {
            caller: "inner",
            callee: "target",
            is_test_only: false,
            is_test_root: false,
        },
    ];
    seed_calls_topology_bundle(&root, &data_dir, &edges, true).await;

    let first = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "assess",
            "target",
            "--sections",
            "blast_radius,risk",
            "--filter",
            "all",
            "--limit",
            "1",
            "--format",
            "json",
        ])
        .output()
        .expect("query first Assess page");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first = stdout_json(&first);
    assert_eq!(first["blast_radius"]["page"]["returned"], 1);
    assert_eq!(first["blast_radius"]["page"]["total_items"], 2);
    assert_eq!(first["blast_radius"]["items"][0]["symbol"]["name"], "inner");
    let cursor = first["blast_radius"]["page"]["next_cursor"]
        .as_str()
        .expect("first Assess continuation");

    let second = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "assess",
            "target",
            "--sections",
            "blast_radius,risk",
            "--filter",
            "all",
            "--limit",
            "1",
            "--cursor",
            cursor,
            "--format",
            "json",
        ])
        .output()
        .expect("query second Assess page");
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second = stdout_json(&second);
    assert_eq!(
        second["blast_radius"]["items"][0]["symbol"]["name"],
        "outer"
    );
    assert_eq!(second["blast_radius"]["page"]["has_more"], false);

    let rebound = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "assess",
            "target",
            "--sections",
            "blast_radius,risk",
            "--filter",
            "all",
            "--depth",
            "1",
            "--limit",
            "1",
            "--cursor",
            cursor,
            "--format",
            "json",
        ])
        .output()
        .expect("reject Assess cursor rebound to another depth");
    assert!(!rebound.status.success());
    assert_eq!(stdout_json(&rebound)["error"]["code"], "invalid_cursor");

    let bounded = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "assess",
            "target",
            "--sections",
            "blast_radius,risk",
            "--filter",
            "all",
            "--depth",
            "1",
            "--format",
            "json",
        ])
        .output()
        .expect("query depth-bounded Assess");
    assert!(bounded.status.success());
    let bounded = stdout_json(&bounded);
    assert_eq!(bounded["blast_radius"]["observed_affected_symbols"], 1);
    assert_eq!(bounded["blast_radius"]["execution_depth_cutoff_nodes"], 1);
    assert_eq!(bounded["blast_radius"]["population_complete"], false);
    assert_eq!(bounded["risk"]["depth_boundary_reached"], true);
    assert_eq!(bounded["risk"]["population_complete"], false);

    for (label, arguments, expected_field) in [
        (
            "depth above the product bound",
            vec!["assess", "target", "--depth", "11", "--format", "json"],
            "depth",
        ),
        (
            "unknown reachability filter",
            vec!["assess", "target", "--filter", "maybe", "--format", "json"],
            "filter",
        ),
        (
            "unknown result section",
            vec![
                "assess",
                "target",
                "--sections",
                "blast_radius,everything",
                "--format",
                "json",
            ],
            "sections",
        ),
    ] {
        let invalid = h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("run invalid Assess control '{label}': {error}"));
        assert!(
            !invalid.status.success(),
            "{label} must fail before executing Assess"
        );
        let invalid = stdout_json(&invalid);
        assert_eq!(
            invalid["error"]["code"], "invalid_request",
            "{label} must use the shared typed product error: {invalid}"
        );
        assert!(
            invalid["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(expected_field)),
            "{label} must identify the invalid field: {invalid}"
        );
    }

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let invalid_depth = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "assess",
        json!({"symbol": "target", "depth": 11}),
    );
    let invalid_filter = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "assess",
        json!({"symbol": "target", "filter": "maybe"}),
    );
    let invalid_section = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "assess",
        json!({"symbol": "target", "sections": ["blast_radius", "everything"]}),
    );
    let valid_after_refusals = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "assess",
        json!({
            "symbol": "target",
            "sections": ["blast_radius", "risk"],
            "filter": "all",
            "depth": 1
        }),
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
    for (label, response) in [
        ("invalid depth", invalid_depth),
        ("invalid filter", invalid_filter),
        ("invalid section", invalid_section),
    ] {
        assert_eq!(
            response["error"]["code"], -32602,
            "MCP must reject {label} against the advertised Assess schema before dispatch: {response}"
        );
    }
    assert_eq!(
        valid_after_refusals["result"]["structuredContent"], bounded,
        "positive control: refused MCP inputs must not poison the session or bypass the shared use case"
    );
}

#[test]
fn structural_index_status_uses_generation_receipts_without_inventing_provider_installation() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        "pub fn target() {}\npub fn caller() { target(); }\n",
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("run structural-only shipped index");
    assert!(
        indexed.status.success(),
        "positive control: structural indexing must publish; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let generation = resolve_generation(&data_dir, &root)
        .expect("structural indexing must publish a resolvable generation");
    let receipt = generation
        .manifest
        .receipts
        .iter()
        .find(|receipt| receipt.capability_id == "calls")
        .expect("published Calls receipt");
    assert_eq!(receipt.status, CapabilityStatus::Unavailable);
    assert_eq!(
        receipt.reason_code.as_deref(),
        Some("provider_not_requested"),
        "positive control: the immutable generation must explain why Calls is unavailable"
    );
    let generation_database = redb::ReadOnlyDatabase::open(&generation.database_path)
        .expect("open published generation database");
    let read = generation_database
        .begin_read()
        .expect("begin generation metadata read");
    let metadata = read
        .open_table(TableDefinition::<&str, u64>::new("graph_meta"))
        .expect("open graph metadata");
    assert!(
        metadata
            .get("schema_version")
            .expect("read graph schema version")
            .is_some(),
        "positive control: the current graph metadata table must be readable"
    );
    assert!(
        metadata
            .get("scip_ran_ok")
            .expect("read retired aggregate provider key")
            .is_none(),
        "a current immutable generation must not persist the retired aggregate SCIP authority"
    );
    drop(metadata);
    drop(read);
    drop(generation_database);

    let status = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["status", "--format", "json"])
        .output()
        .expect("run shipped status");
    assert!(
        status.status.success(),
        "status must inspect the structural generation; stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
    );
    let status = stdout_json(&status);
    let rust = calls_language(&status, "rust");
    assert_eq!(rust["status"], "unavailable");
    assert!(
        rust["gaps"]
            .as_array()
            .is_some_and(|gaps| gaps.iter().any(|gap| {
                gap["reason_code"] == "provider_not_requested"
                    && gap["reason"].as_str().is_some_and(|reason| {
                        reason.contains("not requested") || reason.contains("without --scip")
                    })
            })),
        "status must preserve the generation's exact Calls explanation: {status}"
    );
    assert!(
        status["classified_by"].is_object(),
        "positive control: status must expose loaded classification provenance: {status}"
    );
    assert!(
        status["classified_by"].get("index_config").is_none(),
        "classification provenance must not duplicate capability authority: {status}"
    );
    assert!(
        status["classification_currency"]["failures"]
            .as_array()
            .is_some_and(|failures| failures.iter().all(|failure| {
                !failure
                    .as_str()
                    .is_some_and(|failure| failure.contains("INDEX-CONFIG"))
            })),
        "the removed INDEX-CONFIG axis must not reappear through status: {status}"
    );
    assert!(
        status.get("coverage").is_none(),
        "status must not expose a competing graph-shape coverage authority: {status}"
    );
    assert_eq!(status["availability"], "available");
    assert_eq!(status["freshness"], "fresh");
    let recommendation = status["recommendation"]
        .as_str()
        .unwrap_or_else(|| panic!("missing status recommendation: {status}"));
    assert!(
        recommendation.contains("--scip"),
        "the remedy must explain how to request Calls providers: {recommendation}"
    );
    assert!(
        !recommendation.contains("install rust-analyzer"),
        "a deliberately unrequested provider is not evidence that rust-analyzer is absent: \
         {recommendation}"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_status = call_mcp(&mut stdin, &mut stdout, 1, "status", json!({}));
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP status process must exit cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_ne!(
        mcp_status["result"]["isError"], true,
        "MCP status must inspect the same immutable generation: {mcp_status}"
    );
    let structured = &mcp_status["result"]["structuredContent"];
    assert_eq!(
        mcp_text_payload(&mcp_status),
        structured.clone(),
        "MCP text content and native structuredContent must share one status DTO"
    );
    assert_eq!(
        structured["recommendation"], recommendation,
        "CLI JSON and MCP must share the receipt-aware recommendation"
    );
    assert_eq!(
        calls_language(structured, "rust")["gaps"][0]["reason_code"],
        "provider_not_requested"
    );
    assert_eq!(
        structured["classified_by"], status["classified_by"],
        "CLI JSON and MCP must expose the same persisted classification stamp"
    );
    assert_eq!(
        structured["classification_currency"], status["classification_currency"],
        "CLI JSON and MCP must expose the same classification-currency verdict"
    );
    assert!(structured["classified_by"].is_object());
    assert!(structured["classified_by"].get("index_config").is_none());
}

#[cfg(unix)]
#[test]
fn shipped_index_publishes_the_exact_calls_authority_it_generated() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SHIPPED_INDEX_SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);
    let mut provider_bytes =
        std::fs::read(&provider_artifact).expect("fixture provider artifact bytes");
    let mut toolchain_document = Vec::new();
    protobuf_string(&mut toolchain_document, 4, "rust");
    protobuf_string(
        &mut toolchain_document,
        1,
        ".devbox/virtenv/rustup/toolchains/test-toolchain/lib/rustlib/src/rust/library/test/src/lib.rs",
    );
    protobuf_string(
        &mut toolchain_document,
        5,
        "pub fn provider_toolchain_helper() {}\n",
    );
    protobuf_int(&mut toolchain_document, 6, 1);
    protobuf_bytes(&mut provider_bytes, 2, &toolchain_document);
    std::fs::write(&provider_artifact, provider_bytes)
        .expect("provider artifact with an out-of-population toolchain document");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--require-complete-calls"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("run shipped h00ligan index");
    assert!(
        indexed.status.success(),
        "the ordinary shipped index command must complete; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    assert!(
        provider_executed.is_file(),
        "the positive control must prove the provider executable ran"
    );
    for relative in ["index.scip", "index.go.scip", "target", "Cargo.lock"] {
        assert!(
            !root.join(relative).exists(),
            "provider execution must not leave {relative} in the indexed project"
        );
    }

    let publication_directory =
        data_dir.join(h00ligan_engine::code_intel_publication::PUBLICATION_DIRECTORY);
    assert!(
        publication_directory.is_dir(),
        "ordinary indexing generated real provider evidence but did not publish immutable authority; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    let resolved = resolve_generation(&data_dir, &root)
        .expect("ordinary indexing must publish a resolvable immutable generation");
    let calls_receipt = resolved
        .manifest
        .receipts
        .iter()
        .find(|receipt| receipt.capability_id == "calls")
        .expect("published Calls receipt");
    assert_eq!(calls_receipt.status, CapabilityStatus::Complete);
    assert_eq!(
        calls_receipt.provider_version.as_deref(),
        Some(SHIPPED_EXECUTABLE_PROVIDER_VERSION)
    );

    let calls = run_calls(&root, &data_dir, &[]);
    assert!(
        calls.status.success(),
        "the shipped Calls query must consume the authority produced by shipped indexing; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&calls.stdout),
        String::from_utf8_lossy(&calls.stderr),
    );
    let calls = stdout_json(&calls);
    assert_eq!(result_count(&calls), Some(1));
    assert_eq!(calls["items"][0]["caller"]["name"], "caller");
    assert_eq!(calls["items"][0]["call_span"]["start_line"], 1);
    assert_eq!(calls["items"][0]["call_span"]["start_column"], 18);

    let first_generation = resolved.manifest.generation_id.clone();
    let without_provider = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("attempt current no-provider generation");
    assert!(
        without_provider.status.success(),
        "a provider-free run must reuse, not replace, current complete Calls authority; stdout={} stderr={}",
        String::from_utf8_lossy(&without_provider.stdout),
        String::from_utf8_lossy(&without_provider.stderr),
    );
    assert!(
        String::from_utf8_lossy(&without_provider.stderr)
            .contains("Index current (reused immutable generation)"),
        "the command must disclose that no replacement publication occurred: {}",
        String::from_utf8_lossy(&without_provider.stderr)
    );
    let preserved = resolve_generation(&data_dir, &root)
        .expect("the complete generation must remain current after reuse");
    assert_eq!(preserved.manifest.generation_id, first_generation);
    let preserved_calls = run_calls(&root, &data_dir, &[]);
    assert!(
        preserved_calls.status.success(),
        "reuse must leave the prior complete authority queryable"
    );
    assert_eq!(result_count(&stdout_json(&preserved_calls)), Some(1));

    let permissive_reuse = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--allow-capability-downgrade"])
        .output()
        .expect("permit a downgrade without forcing a rebuild");
    assert!(
        permissive_reuse.status.success(),
        "downgrade permission must not reject exact-current reuse; stdout={} stderr={}",
        String::from_utf8_lossy(&permissive_reuse.stdout),
        String::from_utf8_lossy(&permissive_reuse.stderr),
    );
    assert!(
        String::from_utf8_lossy(&permissive_reuse.stderr)
            .contains("Index current (reused immutable generation)"),
        "permission alone must not manufacture a replacement generation: {}",
        String::from_utf8_lossy(&permissive_reuse.stderr)
    );
    assert_eq!(
        resolve_generation(&data_dir, &root)
            .expect("generation after permissive reuse")
            .manifest
            .generation_id,
        first_generation
    );

    let without_provider = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--force", "--allow-capability-downgrade"])
        .output()
        .expect("force and authorize a current no-provider generation");
    assert!(
        without_provider.status.success(),
        "forced capability downgrade must publish honest current authority; stdout={} stderr={}",
        String::from_utf8_lossy(&without_provider.stdout),
        String::from_utf8_lossy(&without_provider.stderr),
    );
    let unavailable = resolve_generation(&data_dir, &root)
        .expect("explicitly authorized no-provider generation must remain resolvable");
    assert_ne!(unavailable.manifest.generation_id, first_generation);
    assert_eq!(
        unavailable.manifest.parent_generation_id.as_ref(),
        Some(&first_generation)
    );
    let unavailable_receipt = unavailable
        .manifest
        .receipts
        .iter()
        .find(|receipt| receipt.capability_id == "calls")
        .expect("current unavailable Calls receipt");
    assert_eq!(unavailable_receipt.status, CapabilityStatus::Unavailable);
    assert_eq!(
        unavailable_receipt.reason_code.as_deref(),
        Some("provider_not_requested")
    );
    let unavailable_calls = run_calls(&root, &data_dir, &[]);
    assert!(
        !unavailable_calls.status.success(),
        "current unavailable authority must replace stale complete Calls evidence"
    );
    let unavailable_error = stdout_json(&unavailable_calls);
    assert_eq!(unavailable_error["error"]["code"], "capability_unavailable");
    assert_eq!(
        unavailable_error["error"]["evidence"][0]["reason_code"],
        "provider_not_requested"
    );

    let refreshed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("repeat shipped h00ligan index");
    assert!(
        refreshed.status.success(),
        "repeat publication through an existing directory must succeed; stdout={} stderr={}",
        String::from_utf8_lossy(&refreshed.stdout),
        String::from_utf8_lossy(&refreshed.stderr),
    );
    let refreshed_generation = resolve_generation(&data_dir, &root)
        .expect("repeat publication must publish a resolvable generation");
    assert_eq!(
        refreshed_generation.manifest.parent_generation_id.as_ref(),
        Some(&unavailable.manifest.generation_id)
    );
    assert!(
        refreshed_generation
            .manifest
            .receipts
            .iter()
            .any(|receipt| {
                receipt.capability_id == "calls" && receipt.status == CapabilityStatus::Complete
            })
    );
    let refreshed_calls = run_calls(&root, &data_dir, &[]);
    assert!(refreshed_calls.status.success());
    assert_eq!(result_count(&stdout_json(&refreshed_calls)), Some(1));

    for obsolete in [
        "graph.redb",
        "index.redb",
        "graph-write.lock",
        "reindex.incomplete",
    ] {
        assert!(
            !data_dir.join(obsolete).exists(),
            "the immutable production writer must not dual-write obsolete {obsolete}"
        );
    }
    assert!(
        !root.join("Cargo.lock").exists() && !root.join("target").exists(),
        "metadata resolution must remain confined outside the indexed project"
    );
}

#[cfg(unix)]
#[test]
fn semantic_restart_recertifies_without_live_provider_authority() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "semantic-restart-repo", SHIPPED_INDEX_SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"semantic_restart\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);

    let run = || {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["index", "--scip", "--format", "json"])
            .env("PATH", &path)
            .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
            .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
            .output()
            .expect("run shipped semantic index")
    };

    let first = run();
    assert!(
        first.status.success() && provider_executed.is_file(),
        "positive control must execute the provider; stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("first JSON output");
    assert_eq!(calls_language(&first_json, "rust")["status"], "complete");

    std::fs::remove_file(&provider_executed).expect("reset provider execution marker");
    let second = run();
    assert!(
        second.status.success(),
        "semantic recertification must succeed; stdout={} stderr={}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr),
    );
    let second_json: Value = serde_json::from_slice(&second.stdout).expect("second JSON output");
    assert_eq!(
        second_json["reused_generation"], false,
        "a fresh process has no live provider/toolchain authority for exact semantic reuse: {second_json}"
    );
    assert!(
        provider_executed.is_file(),
        "the semantic provider must run again before Complete authority is retained"
    );
    assert_ne!(second_json["generation_id"], first_json["generation_id"]);
}

#[cfg(unix)]
#[test]
fn semantic_requests_recertify_without_live_provider_authority() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SHIPPED_INDEX_SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);

    let run = |extra: &[&str]| {
        let mut command = h00ligan();
        command
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["index", "--scip", "--format", "json"])
            .args(extra)
            .env("PATH", &path)
            .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
            .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed);
        command.output().expect("run shipped h00ligan index")
    };

    let first = run(&[]);
    assert!(
        first.status.success() && provider_executed.is_file(),
        "the cold positive control must execute the provider; stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("cold JSON output");
    assert_eq!(
        calls_language(&first_json, "rust")["status"],
        "complete",
        "provider dependency documents must not widen or downgrade project authority: {first_json}"
    );
    let first_generation = first_json["generation_id"]
        .as_str()
        .expect("cold generation ID")
        .to_owned();

    std::fs::remove_file(&provider_executed).expect("reset provider execution marker");
    let unchanged = run(&[]);
    assert!(
        unchanged.status.success(),
        "an unchanged request must succeed; stdout={} stderr={}",
        String::from_utf8_lossy(&unchanged.stdout),
        String::from_utf8_lossy(&unchanged.stderr),
    );
    let unchanged_json: Value =
        serde_json::from_slice(&unchanged.stdout).expect("unchanged JSON output");
    assert_eq!(
        unchanged_json["reused_generation"], false,
        "{unchanged_json}"
    );
    assert_ne!(unchanged_json["generation_id"], first_generation);
    assert_eq!(unchanged_json["files_changed"], 0);
    assert!(
        provider_executed.exists(),
        "a fresh process must reexecute the semantic provider before retaining Complete authority"
    );

    std::fs::remove_file(&provider_executed).expect("reset provider marker before force");
    let forced = run(&["--force"]);
    assert!(
        forced.status.success() && provider_executed.is_file(),
        "explicit force must bypass reuse; stdout={} stderr={}",
        String::from_utf8_lossy(&forced.stdout),
        String::from_utf8_lossy(&forced.stderr),
    );
    let forced_json: Value = serde_json::from_slice(&forced.stdout).expect("forced JSON output");
    assert_eq!(forced_json["reused_generation"], false, "{forced_json}");
    assert_ne!(forced_json["generation_id"], first_generation);

    std::fs::remove_file(&provider_executed).expect("reset provider marker after force");
    let changed_source = "pub fn target() {}\npub fn caller() { target(); }\npub fn added() {}\n";
    std::fs::write(root.join("src/lib.rs"), changed_source).expect("change source bytes");
    std::fs::write(
        &provider_artifact,
        shipped_index_scip_fixture_for_source_with_kinds(&root, changed_source, 17, 17),
    )
    .expect("refresh fixture provider artifact");
    let changed = run(&[]);
    assert!(
        changed.status.success() && provider_executed.is_file(),
        "changed source must rebuild through the provider; stdout={} stderr={}",
        String::from_utf8_lossy(&changed.stdout),
        String::from_utf8_lossy(&changed.stderr),
    );
    let changed_json: Value = serde_json::from_slice(&changed.stdout).expect("changed JSON output");
    assert_eq!(changed_json["reused_generation"], false, "{changed_json}");
    assert_ne!(changed_json["generation_id"], forced_json["generation_id"]);

    std::fs::remove_file(&provider_executed).expect("reset provider marker before MCP refresh");
    let mut command = h00ligan();
    command
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("mcp-serve")
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed);
    let (child, mut stdin, mut stdout) = spawn_mcp_command(command);
    let mcp_recertified =
        call_mcp_reindex_terminal(&mut stdin, &mut stdout, 1, json!({"scip": true}));
    assert_eq!(mcp_recertified["state"], "succeeded", "{mcp_recertified}");
    let mcp_reused_payload = &mcp_recertified["result"];
    assert_eq!(
        mcp_reused_payload["reused_generation"], false,
        "{mcp_reused_payload}"
    );
    assert_ne!(
        mcp_reused_payload["generation"]["id"],
        changed_json["generation_id"]
    );
    assert!(
        provider_executed.exists(),
        "a development MCP process without the embedded persistent coordinator must recertify honestly"
    );

    std::fs::remove_file(&provider_executed).expect("reset provider marker before MCP force");
    let mcp_forced = call_mcp_reindex_terminal(
        &mut stdin,
        &mut stdout,
        2,
        json!({"scip": true, "force": true}),
    );
    assert_eq!(mcp_forced["state"], "succeeded", "{mcp_forced}");
    let mcp_forced_payload = &mcp_forced["result"];
    assert_eq!(
        mcp_forced_payload["reused_generation"], false,
        "{mcp_forced_payload}"
    );
    assert!(
        provider_executed.is_file(),
        "MCP force must bypass shared reuse and execute the provider"
    );
    let output = stop_mcp(child, stdin);
    assert!(output.status.success());

    std::fs::remove_file(&provider_executed).expect("reset provider marker after MCP force");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[features]\ndefault = []\n",
    )
    .expect("change provider project input");
    let project_input_changed = run(&[]);
    assert!(
        project_input_changed.status.success() && provider_executed.is_file(),
        "changed project configuration must invalidate reuse and reexecute providers"
    );
    let project_input_changed =
        serde_json::from_slice::<Value>(&project_input_changed.stdout).expect("project-input JSON");
    assert_eq!(
        project_input_changed["reused_generation"], false,
        "{project_input_changed}"
    );
}

#[cfg(unix)]
#[test]
fn shipped_index_publishes_runnable_test_roots_for_the_shared_tests_contract() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "tests-index-repo", SHIPPED_TESTS_INDEX_SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) = install_fixture_rust_analyzer_for_source(
        temporary.path(),
        &root,
        SHIPPED_TESTS_INDEX_SOURCE,
    );

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("run shipped semantic index for Tests");
    assert!(
        indexed.status.success(),
        "the shipped index must publish structural test-root and Calls authority together; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    assert!(
        provider_executed.is_file(),
        "positive control: the semantic provider executable must run"
    );
    let generation = resolve_generation(&data_dir, &root)
        .expect("Tests index must publish a resolvable immutable generation");
    for capability in ["structural_graph", "calls"] {
        assert!(
            generation.manifest.receipts.iter().any(|receipt| {
                receipt.capability_id == capability && receipt.status == CapabilityStatus::Complete
            }),
            "the same generation must carry complete {capability} authority"
        );
    }

    let cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["tests", "target", "--format", "json"])
        .output()
        .expect("query shipped CLI Tests after indexing");
    assert!(
        cli.status.success(),
        "the CLI must consume the test-root classification it just indexed; stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr),
    );
    let cli = stdout_json(&cli);
    assert_eq!(cli["authority"]["status"], "complete");
    assert_eq!(cli["page"]["total_items"], 1);
    assert_eq!(cli["items"][0]["test"]["name"], "caller");
    assert_eq!(cli["items"][0]["chain"].as_array().map(Vec::len), Some(1));

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "tests",
        json!({"symbol": "target"}),
    );
    assert!(
        mcp.get("error").is_none() && mcp["result"]["isError"] != true,
        "MCP Tests must consume the same indexed generation: {mcp}"
    );
    assert_eq!(mcp["result"]["structuredContent"], cli);
    assert_eq!(mcp_text_payload(&mcp), cli);
    let stopped = stop_mcp(child, stdin);
    assert!(
        stopped.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
}

#[cfg(unix)]
#[test]
fn shipped_calls_joins_provider_callable_vocabulary_to_structural_function_identity() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SHIPPED_INDEX_SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);
    std::fs::write(
        &provider_artifact,
        // scip.SymbolInformation.Kind.StaticMethod. The raw provider
        // vocabulary is provenance; exact source extent plus the co-published
        // structural node establish the product-level callable identity.
        shipped_index_scip_fixture_with_kinds(&root, 80, 80),
    )
    .expect("static-method SCIP fixture");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("index alternate provider callable vocabulary");
    assert!(
        indexed.status.success() && provider_executed.is_file(),
        "positive control: the shipped provider path must publish the admitted SCIP kind; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let calls = run_calls(&root, &data_dir, &[]);
    assert!(
        calls.status.success(),
        "an admitted provider callable kind must not invalidate an exact structural join; stdout={} stderr={}",
        String::from_utf8_lossy(&calls.stdout),
        String::from_utf8_lossy(&calls.stderr),
    );
    let calls = stdout_json(&calls);
    assert_eq!(result_count(&calls), Some(1));
    assert_eq!(calls["resolved_symbol"]["kind"], "function");
    assert_eq!(calls["items"][0]["caller"]["kind"], "function");
}

#[cfg(unix)]
#[test]
fn shipped_cli_and_mcp_admit_explicit_macro_invocations_without_global_qualification() {
    const SOURCE: &str = concat!(
        "pub fn target() {}\n",
        "pub fn caller() { assert!({ target /* provider/source join */ (); true }); }\n",
    );
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);
    std::fs::write(
        &provider_artifact,
        shipped_index_scip_fixture_for_source_with_kinds(&root, SOURCE, 17, 17),
    )
    .expect("macro-call SCIP fixture");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("index explicit macro invocation");
    assert!(
        indexed.status.success() && provider_executed.is_file(),
        "positive control: the shipped provider path must publish the macro fixture; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let cli = run_calls(&root, &data_dir, &[]);
    assert!(
        cli.status.success(),
        "shipped CLI must admit the explicit invocation; stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr),
    );
    let cli = stdout_json(&cli);
    assert_eq!(result_count(&cli), Some(1));
    assert_eq!(cli["schema_version"], "h00/code-intel/calls/v9");
    assert_eq!(cli["authority"]["status"], "complete");
    assert_eq!(
        cli["authority"]["population"],
        "provider_resolved_explicit_source_invocations"
    );
    assert_eq!(cli["authority"]["coverage_exclusions"], json!([]));

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let response = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "calls",
        json!({"symbol": "target"}),
    );
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must exit cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(response["result"]["structuredContent"], cli);
    assert_eq!(mcp_text_payload(&response), cli);
}

#[cfg(unix)]
#[test]
fn shipped_go_calls_distinguishes_missing_module_root_from_provider_failure() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(&root).expect("Go source root");
    std::fs::write(
        root.join("main.go"),
        "package main\n\nfunc target() {}\nfunc main() { target() }\n",
    )
    .expect("Go source fixture");
    let provider_bin = temporary.path().join("go-provider-bin");
    let provider_executed = temporary.path().join("go-provider-executed");
    let go_root = provider_bin.join("go-root");
    std::fs::create_dir_all(&provider_bin).expect("fixture provider bin");
    std::fs::create_dir_all(go_root.join("bin")).expect("fixture Go root");
    let provider = provider_bin.join("scip-go");
    std::fs::write(
        &provider,
        format!(
            "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then printf '%s\\n' 'scip-go fixture-2026.08.17'; exit 0; fi\n\
         if [ \"$1\" = \"index\" ]; then printf '%s\\n' \"$PWD\" > '{}'; exit 42; fi\n\
         exit 64\n",
            provider_executed.display(),
        ),
    )
    .expect("fixture scip-go executable");
    let mut permissions = std::fs::metadata(&provider)
        .expect("fixture provider metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&provider, permissions).expect("fixture provider mode");
    let go = provider_bin.join("go");
    std::fs::write(
        &go,
        format!(
            "#!/bin/sh\n\
             if [ \"$1\" = \"version\" ]; then printf '%s\\n' 'go version go1.26.0 linux/amd64'; exit 0; fi\n\
             if [ \"$1\" = \"env\" ] && [ \"$2\" = \"GOROOT\" ]; then printf '%s\\n' '{}'; exit 0; fi\n\
             exit 64\n",
            go_root.display(),
        ),
    )
    .expect("fixture go executable");
    let mut permissions = std::fs::metadata(&go)
        .expect("fixture go metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&go, permissions).expect("fixture go mode");
    let effective_go = go_root.join("bin/go");
    std::fs::write(
        &effective_go,
        "#!/bin/sh\nif [ \"$1\" = \"version\" ]; then printf '%s\\n' 'go version go1.26.0 linux/amd64'; exit 0; fi\nexit 64\n",
    )
    .expect("fixture effective go executable");
    let mut permissions = std::fs::metadata(&effective_go)
        .expect("fixture effective go metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&effective_go, permissions).expect("fixture effective go mode");
    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![provider_bin];
    paths.extend(std::env::split_paths(&original_path));
    let path = std::env::join_paths(paths).expect("fixture provider PATH");

    let run = |data_dir: &Path| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(data_dir)
            .args(["index", "--scip", "--format", "json"])
            .env("PATH", &path)
            .env("H00_TEST_GO_PROVIDER_EXECUTED", &provider_executed)
            .output()
            .expect("run shipped Go index")
    };

    let without_module_data = temporary.path().join("without-module");
    let without_module = run(&without_module_data);
    assert!(
        without_module.status.success(),
        "loose Go sources must still publish structural evidence: stdout={} stderr={}",
        String::from_utf8_lossy(&without_module.stdout),
        String::from_utf8_lossy(&without_module.stderr),
    );
    assert!(
        !provider_executed.exists(),
        "without go.mod there is no authorized provider execution root"
    );
    let without_module_json = stdout_json(&without_module);
    let without_module_reused = run(&without_module_data);
    assert!(without_module_reused.status.success());
    let without_module_reused = stdout_json(&without_module_reused);
    assert_eq!(
        without_module_reused["reused_generation"], true,
        "a stable loose-source population has no semantic execution root to recertify"
    );
    assert!(
        !provider_executed.exists(),
        "the stable missing Go execution root must not become a provider invocation during exact reuse"
    );
    let without_module_status = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&without_module_data)
        .args(["status", "--format", "json"])
        .output()
        .expect("query loose-source status");
    assert!(without_module_status.status.success());
    let without_module_status = stdout_json(&without_module_status);
    assert_eq!(
        without_module_status["capabilities"]["calls"]["status"],
        "not_applicable",
        "structural-only loose Go must not fabricate a semantic execution scope: first_capabilities={} reused_capabilities={} status_capabilities={}",
        without_module_json["capabilities"],
        without_module_reused["capabilities"],
        without_module_status["capabilities"],
    );
    assert_eq!(
        without_module_status["action_needed"], false,
        "a stable missing execution root cannot be repaired by repeating the satisfied best-effort request"
    );
    assert!(
        without_module_status["recommendation"]
            .as_str()
            .is_some_and(
                |recommendation| recommendation.contains("measured capabilities are ready")
            ),
        "status should describe the complete applicable scope without prescribing inert Go setup: {without_module_status}"
    );
    let run_query = |data_dir: &Path, args: &[&str]| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(data_dir)
            .args(args)
            .output()
            .expect("query shipped loose-source generation")
    };
    let without_module_overview =
        run_query(&without_module_data, &["overview", "--format", "json"]);
    assert!(
        without_module_overview.status.success(),
        "loose-source Overview failed: stdout={} stderr={}",
        String::from_utf8_lossy(&without_module_overview.stdout),
        String::from_utf8_lossy(&without_module_overview.stderr),
    );
    let without_module_overview = stdout_json(&without_module_overview);
    assert_eq!(
        without_module_overview["health_action_needed"], false,
        "structural-only overview must not prescribe an impossible semantic repair: {without_module_overview}"
    );
    assert!(
        without_module_overview.get("health_guidance").is_none(),
        "complete applicable scope needs no remediation guidance: {without_module_overview}"
    );
    assert!(
        without_module_overview
            .get("health_action_required")
            .is_none()
    );

    let without_module_audit = run_query(&without_module_data, &["audit", "--format", "json"]);
    assert!(
        without_module_audit.status.success(),
        "loose-source Audit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&without_module_audit.stdout),
        String::from_utf8_lossy(&without_module_audit.stderr),
    );
    let without_module_audit = stdout_json(&without_module_audit);
    assert_eq!(without_module_audit["dead_code"]["action_needed"], false);
    assert!(
        without_module_audit["dead_code"].get("guidance").is_none(),
        "complete applicable scope needs no audit remediation guidance: {without_module_audit}"
    );
    assert!(
        without_module_audit["dead_code"]
            .get("action_required")
            .is_none()
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &without_module_data);
    let overview_response = call_mcp(&mut stdin, &mut stdout, 41, "overview", json!({}));
    let audit_response = call_mcp(&mut stdin, &mut stdout, 42, "audit", json!({}));
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP loose-source guidance failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        overview_response["result"]["structuredContent"], without_module_overview,
        "CLI and MCP Overview must share the non-actionable capability decision"
    );
    assert_eq!(
        audit_response["result"]["structuredContent"], without_module_audit,
        "CLI and MCP Audit must share the non-actionable capability decision"
    );

    std::fs::write(
        root.join("go.mod"),
        "module example.test/fixture\n\ngo 1.26\n",
    )
    .expect("Go module positive control");
    let with_module = run(&temporary.path().join("with-module"));
    assert!(
        with_module.status.success(),
        "provider failure remains a soft semantic degradation: stdout={} stderr={}",
        String::from_utf8_lossy(&with_module.stdout),
        String::from_utf8_lossy(&with_module.stderr),
    );
    assert_eq!(
        std::fs::read_to_string(&provider_executed)
            .expect("go.mod positive control must execute provider")
            .trim(),
        canonical_fixture_path(&root).display().to_string(),
        "the provider must execute at the discovered Go module root"
    );
    let with_module_json = stdout_json(&with_module);
    let with_module_status = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(temporary.path().join("with-module"))
        .args(["status", "--format", "json"])
        .output()
        .expect("query failed-provider status");
    assert!(with_module_status.status.success());
    assert_eq!(
        stdout_json(&with_module_status)["action_needed"],
        true,
        "positive control: an actual provider failure remains actionable"
    );
    let with_module_overview = run_query(
        &temporary.path().join("with-module"),
        &["overview", "--format", "json"],
    );
    assert!(with_module_overview.status.success());
    assert_eq!(
        stdout_json(&with_module_overview)["health_action_needed"],
        true,
        "positive control: Overview must still prescribe action for a real provider failure"
    );
    let with_module_audit = run_query(
        &temporary.path().join("with-module"),
        &["audit", "--format", "json"],
    );
    assert!(with_module_audit.status.success());
    assert_eq!(
        stdout_json(&with_module_audit)["dead_code"]["action_needed"],
        true,
        "positive control: Audit must still prescribe action for a real provider failure"
    );
    std::fs::remove_file(&provider_executed).expect("reset failed-provider marker");
    let with_module_retry = run(&temporary.path().join("with-module"));
    assert!(
        with_module_retry.status.success() && provider_executed.is_file(),
        "transient provider failure evidence must be retried on the next semantic request"
    );
    let with_module_retry = stdout_json(&with_module_retry);
    assert_eq!(
        with_module_retry["reused_generation"], false,
        "provider execution failure is not stable reusable evidence"
    );
    assert_ne!(
        with_module_retry["generation_id"],
        with_module_json["generation_id"]
    );

    assert!(
        without_module_json["capabilities"]["calls"]["languages"]
            .as_array()
            .is_some_and(|languages| languages
                .iter()
                .all(|language| language["language_id"] != "go")),
        "loose Go sources must not fabricate semantic Calls scope: {without_module_json}"
    );
    assert!(
        without_module_overview["project_units"]
            .as_array()
            .is_some_and(|units| units
                .iter()
                .any(|unit| { unit["language_id"] == "go" && unit["kind"] == "loose_sources" })),
        "positive control: the same Go source must remain visible as structural project inventory: {without_module_overview}"
    );

    assert_eq!(
        calls_language(&with_module_json, "go")["gaps"][0]["reason_code"],
        "provider_failed_or_unavailable",
        "positive control: a discovered root followed by an actual provider failure is a distinct state"
    );
}

#[cfg(unix)]
#[test]
fn installed_one_file_go_reuses_only_the_exact_resolved_toolchain() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("bundle");
    std::fs::create_dir_all(&root).expect("Go source root");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/worker\n\ngo 1.26\n",
    )
    .expect("Go module");
    std::fs::write(root.join("worker.go"), SHIPPED_GO_BINDING_SOURCE).expect("Go source fixture");
    std::fs::write(root.join("worker_test.go"), SHIPPED_GO_BINDING_TEST_SOURCE)
        .expect("Go test fixture");
    let project_before = file_population(&root);
    let (provider_artifact, provider_executed, path) =
        install_fixture_scip_go_callable_binding(temporary.path(), &root);
    let provider = temporary.path().join("go-bin/scip-go");

    let run = || {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["index", "--scip", "--format", "json"])
            .env("PATH", &path)
            .env("H00_TEST_GO_PROVIDER_ARTIFACT", &provider_artifact)
            .env("H00_TEST_GO_PROVIDER_EXECUTED", &provider_executed)
            .output()
            .expect("run shipped Go semantic index")
    };

    let first = run();
    assert!(
        first.status.success() && provider_executed.is_file(),
        "cold positive control must execute scip-go: stdout={} stderr={}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );
    let first = stdout_json(&first);
    assert_eq!(first["reused_generation"], false, "{first}");
    assert_eq!(calls_language(&first, "go")["status"], "complete");

    std::fs::remove_file(&provider_executed).expect("reset provider execution marker");
    let unchanged = run();
    assert!(
        unchanged.status.success(),
        "unchanged exact-toolchain reuse must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&unchanged.stdout),
        String::from_utf8_lossy(&unchanged.stderr),
    );
    let unchanged = stdout_json(&unchanged);
    assert_eq!(
        unchanged["reused_generation"], true,
        "an unchanged Go source/project/toolchain population must reuse exact authority: {unchanged}",
    );
    assert_eq!(unchanged["generation_id"], first["generation_id"]);
    assert!(
        !provider_executed.exists(),
        "exact cross-process reuse must not execute scip-go"
    );

    let mut provider_file = std::fs::OpenOptions::new()
        .append(true)
        .open(&provider)
        .expect("open same-path provider for drift");
    provider_file
        .write_all(b"\n# same version report, different executable identity\n")
        .expect("mutate same-path provider bytes");
    drop(provider_file);
    let drifted = run();
    assert!(
        drifted.status.success(),
        "same-path toolchain drift must recertify successfully: stdout={} stderr={}",
        String::from_utf8_lossy(&drifted.stdout),
        String::from_utf8_lossy(&drifted.stderr),
    );
    let drifted = stdout_json(&drifted);
    assert_eq!(
        drifted["reused_generation"], false,
        "same version text cannot authorize reuse after executable bytes change: {drifted}",
    );
    assert_ne!(drifted["generation_id"], first["generation_id"]);
    assert!(
        provider_executed.is_file(),
        "toolchain drift must execute and recertify the provider"
    );
    assert_eq!(
        file_population(&root),
        project_before,
        "reuse and recertification must leave the project tree untouched",
    );
}

#[cfg(unix)]
#[test]
fn installed_go_discards_a_provider_result_when_toolchain_bytes_drift_mid_run() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("bundle");
    std::fs::create_dir_all(&root).expect("Go source root");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/worker\n\ngo 1.26\n",
    )
    .expect("Go module");
    std::fs::write(root.join("worker.go"), SHIPPED_GO_BINDING_SOURCE).expect("Go source fixture");
    std::fs::write(root.join("worker_test.go"), SHIPPED_GO_BINDING_TEST_SOURCE)
        .expect("Go test fixture");
    let project_before = file_population(&root);
    let (provider_artifact, provider_executed, path) =
        install_fixture_scip_go_callable_binding(temporary.path(), &root);
    let provider = temporary.path().join("go-bin/scip-go");
    std::fs::write(
        &provider,
        format!(
            "#!/bin/sh\n\
             artifact='{}'\n\
             executed='{}'\n\
             if [ \"$1\" = \"--version\" ]; then printf '%s\\n' 'scip-go 0.2.7'; exit 0; fi\n\
             if [ \"$1\" = \"index\" ]; then\n\
               printf '%s\\n' \"$PWD\" > \"$executed\"\n\
               shift\n\
               output=''\n\
               while [ \"$#\" -gt 0 ]; do\n\
                 if [ \"$1\" = \"-o\" ]; then shift; output=$1; fi\n\
                 shift\n\
               done\n\
               cp \"$artifact\" \"$output\"\n\
               printf '%s\\n' '# changed after artifact generation' >> \"$0\"\n\
               exit 0\n\
             fi\n\
             exit 64\n",
            provider_artifact.display(),
            provider_executed.display(),
        ),
    )
    .expect("drifting scip-go executable");
    let mut permissions = std::fs::metadata(&provider)
        .expect("provider metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&provider, permissions).expect("provider mode");

    let output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .env("PATH", &path)
        .output()
        .expect("run shipped Go semantic index");
    assert!(provider_executed.is_file(), "positive execution control");
    assert!(
        !output.status.success(),
        "a mid-run toolchain epoch must not satisfy strict Calls publication: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("toolchain changed")
            || String::from_utf8_lossy(&output.stderr).contains("complete Calls authority"),
        "failure must disclose the authority loss: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    assert_eq!(
        file_population(&root),
        project_before,
        "discarded provider evidence must not mutate project inputs",
    );
    assert!(
        !data_dir.join("publication-v4/head-0.json").exists()
            && !data_dir.join("publication-v4/head-1.json").exists(),
        "strict failure must not publish a candidate generation",
    );
}

#[cfg(unix)]
#[test]
fn shipped_go_callable_bindings_are_qualified_execution_paths_across_cli_and_mcp() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("bundle");
    std::fs::create_dir_all(&root).expect("Go source root");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/worker\n\ngo 1.26\n",
    )
    .expect("Go module");
    std::fs::write(root.join("worker.go"), SHIPPED_GO_BINDING_SOURCE)
        .expect("Go callable-binding source");
    std::fs::write(root.join("worker_test.go"), SHIPPED_GO_BINDING_TEST_SOURCE)
        .expect("Go callable-binding test source");
    let project_before = file_population(&root);
    let (provider_artifact, provider_executed, path) =
        install_fixture_scip_go_callable_binding(temporary.path(), &root);

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--format", "json"])
        .env("PATH", &path)
        .env("H00_TEST_GO_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_GO_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("index Go callable-binding fixture");
    assert!(
        indexed.status.success(),
        "shipped index must publish the fixture provider evidence: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    assert_eq!(
        std::fs::read_to_string(&provider_executed)
            .expect("fixture provider must execute")
            .trim(),
        canonical_fixture_path(&root).display().to_string(),
        "the provider must execute at the discovered Go module root",
    );
    assert_eq!(
        file_population(&root),
        project_before,
        "semantic indexing must not write provider or build artifacts into the project root",
    );

    let calls = run_calls_for(&root, &data_dir, "target", &["--filter", "all"]);
    assert!(
        calls.status.success(),
        "Calls query failed: stdout={} stderr={}",
        String::from_utf8_lossy(&calls.stdout),
        String::from_utf8_lossy(&calls.stderr),
    );
    let calls = stdout_json(&calls);
    assert_eq!(calls["schema_version"], "h00/code-intel/calls/v9");
    assert_eq!(calls["authority"]["status"], "complete");
    assert_eq!(calls["total_callers"], 0);
    assert_eq!(calls["items"].as_array().map(Vec::len), Some(0));
    assert_eq!(calls["callable_value_bindings"], 1);
    assert!(calls["warnings"].as_array().is_some_and(|warnings| {
        warnings.iter().any(|warning| {
            warning
                .as_str()
                .is_some_and(|warning| warning.contains("not direct invocation records"))
        })
    }));

    let seam_calls = run_calls_for(&root, &data_dir, "seam", &["--filter", "all"]);
    assert!(seam_calls.status.success());
    let seam_calls = stdout_json(&seam_calls);
    assert_eq!(seam_calls["total_callers"], 1);
    assert_eq!(seam_calls["items"][0]["caller"]["name"], "caller");
    assert_eq!(seam_calls["callable_value_bindings"], 0);

    let run_assess = |cursor: Option<&str>| {
        let mut command = h00ligan();
        command
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["assess", "target", "--filter", "all", "--depth", "4"]);
        if let Some(cursor) = cursor {
            command.args(["--cursor", cursor]);
        }
        command
            .args(["--format", "json"])
            .output()
            .expect("query Go callable-binding impact")
    };
    let assess = run_assess(None);
    assert!(
        assess.status.success(),
        "Assess query failed: stdout={} stderr={}",
        String::from_utf8_lossy(&assess.stdout),
        String::from_utf8_lossy(&assess.stderr),
    );
    let assess = stdout_json(&assess);
    assert_eq!(assess["schema_version"], "h00/code-intel/assess/v2");
    assert_eq!(assess["authority"]["status"], "qualified");
    assert_eq!(assess["authority"]["population_complete"], true);
    assert_eq!(assess["callers"]["observed_direct_callers"], 0);
    assert_eq!(assess["blast_radius"]["observed_affected_symbols"], 4);
    assert_eq!(
        assess["blast_radius"]["observed_execution_affected_symbols"],
        4
    );
    assert_eq!(
        assess["blast_radius"]["observed_exact_only_affected_symbols"],
        0
    );
    assert_eq!(
        assess["blast_radius"]["observed_qualified_binding_affected_symbols"],
        4
    );
    assert_eq!(assess["risk"]["observed_qualified_binding_dependents"], 4);
    let mut cli_assess_pages = vec![assess.clone()];
    let mut items = assess["blast_radius"]["items"]
        .as_array()
        .expect("typed Assess items")
        .clone();
    let mut next_cursor = assess["blast_radius"]["page"]["next_cursor"]
        .as_str()
        .map(str::to_owned);
    while let Some(cursor) = next_cursor {
        let continuation = run_assess(Some(&cursor));
        assert!(
            continuation.status.success(),
            "Assess continuation failed: stdout={} stderr={}",
            String::from_utf8_lossy(&continuation.stdout),
            String::from_utf8_lossy(&continuation.stderr),
        );
        let continuation = stdout_json(&continuation);
        cli_assess_pages.push(continuation.clone());
        items.extend(
            continuation["blast_radius"]["items"]
                .as_array()
                .expect("typed Assess continuation items")
                .iter()
                .cloned(),
        );
        next_cursor = continuation["blast_radius"]["page"]["next_cursor"]
            .as_str()
            .map(str::to_owned);
    }
    assert_eq!(items.len(), 4, "all observed Assess items must be pageable");
    assert_eq!(
        items
            .iter()
            .map(|item| item["symbol"]["name"].as_str().expect("symbol name"))
            .collect::<Vec<_>>(),
        ["seam", "caller", "outer", "TestOuter"],
        "the shipped Assess graph must retain the complete provider-backed Go execution chain: {assess:#}",
    );
    assert_eq!(
        items
            .iter()
            .map(|item| {
                item["execution_path"]
                    .as_array()
                    .expect("execution path")
                    .iter()
                    .map(|step| step["relation"].as_str().expect("path relation"))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
        [
            vec!["callable_value_binding"],
            vec!["exact_invocation", "callable_value_binding"],
            vec![
                "exact_invocation",
                "exact_invocation",
                "callable_value_binding",
            ],
            vec![
                "exact_invocation",
                "exact_invocation",
                "exact_invocation",
                "callable_value_binding",
            ],
        ],
        "machine output must preserve exact invocation and qualified binding as distinct relations",
    );

    let inspect = run_symbol_verb(&root, &data_dir, "inspect", "target", &[]);
    assert!(inspect.status.success());
    let inspect = stdout_json(&inspect);
    assert_eq!(inspect["schema_version"], "h00/code-intel/inspect/v2");
    assert_eq!(inspect["authority"]["status"], "qualified");
    assert_eq!(inspect["callers"]["result"]["total_callers"], 0);
    assert_eq!(inspect["callers"]["result"]["callable_value_bindings"], 1);
    assert!(
        inspect["warnings"]["result"]["signals"]
            .as_array()
            .is_some_and(|signals| signals
                .iter()
                .any(|signal| { signal["code"] == "qualified_callable_value_binding" }))
    );

    let tests = run_symbol_verb(&root, &data_dir, "tests", "target", &[]);
    assert!(tests.status.success());
    let tests = stdout_json(&tests);
    assert_eq!(tests["schema_version"], "h00/code-intel/tests/v2");
    assert_eq!(tests["authority"]["status"], "qualified");
    assert_eq!(tests["authority"]["population_complete"], true);
    assert_eq!(tests["authority"]["qualified_path_count"], 1);
    assert_eq!(tests["page"]["total_items"], 1);
    assert_eq!(tests["items"][0]["test"]["name"], "TestOuter");
    assert_eq!(
        tests["items"][0]["chain"]
            .as_array()
            .expect("qualified test path")
            .iter()
            .map(|step| step["relation"].as_str().expect("test path relation"))
            .collect::<Vec<_>>(),
        [
            "exact_invocation",
            "exact_invocation",
            "exact_invocation",
            "callable_value_binding",
        ],
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_calls = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "calls",
        json!({"symbol": "target", "filter": "all"}),
    );
    let mcp_assess = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "assess",
        json!({"symbol": "target", "filter": "all", "depth": 4}),
    );
    let mcp_inspect = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "inspect",
        json!({"symbol": "target"}),
    );
    let mcp_tests = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "tests",
        json!({"symbol": "target"}),
    );
    assert_eq!(mcp_calls["result"]["structuredContent"], calls);
    let mcp_assess_first = mcp_assess["result"]["structuredContent"].clone();
    assert_eq!(
        without_ephemeral_cursor_lease(mcp_assess_first.clone()),
        without_ephemeral_cursor_lease(assess.clone()),
        "CLI and MCP must agree apart from independently issued cursor leases",
    );
    let mut mcp_assess_pages = vec![mcp_assess_first.clone()];
    let mut mcp_items = mcp_assess_first["blast_radius"]["items"]
        .as_array()
        .expect("typed MCP Assess items")
        .clone();
    let mut mcp_next_cursor = mcp_assess_first["blast_radius"]["page"]["next_cursor"]
        .as_str()
        .map(str::to_owned);
    let mut mcp_request_id = 5;
    while let Some(cursor) = mcp_next_cursor {
        let response = call_mcp(
            &mut stdin,
            &mut stdout,
            mcp_request_id,
            "assess",
            json!({
                "symbol": "target",
                "filter": "all",
                "depth": 4,
                "cursor": cursor,
            }),
        );
        mcp_request_id += 1;
        assert_ne!(response["result"]["isError"], true, "{response:#}");
        let page = response["result"]["structuredContent"].clone();
        mcp_items.extend(
            page["blast_radius"]["items"]
                .as_array()
                .expect("typed MCP Assess continuation items")
                .iter()
                .cloned(),
        );
        mcp_next_cursor = page["blast_radius"]["page"]["next_cursor"]
            .as_str()
            .map(str::to_owned);
        mcp_assess_pages.push(page);
    }
    assert_eq!(
        mcp_items, items,
        "CLI and MCP must reconstruct the same complete ordered qualified execution graph",
    );
    assert_eq!(
        mcp_assess_pages.len(),
        cli_assess_pages.len(),
        "CLI and MCP must expose the same page boundaries",
    );
    for (mcp_page, cli_page) in mcp_assess_pages.into_iter().zip(cli_assess_pages) {
        assert_eq!(
            without_ephemeral_cursor_lease(mcp_page),
            without_ephemeral_cursor_lease(cli_page),
            "each CLI/MCP continuation page must agree apart from its lease",
        );
    }
    assert_eq!(mcp_inspect["result"]["structuredContent"], inspect);
    assert_eq!(mcp_tests["result"]["structuredContent"], tests);
    assert_eq!(
        without_ephemeral_cursor_lease(mcp_text_payload(&mcp_assess)),
        without_ephemeral_cursor_lease(assess),
        "MCP text and structured payloads must agree apart from cursor lease identity",
    );
    let stopped = stop_mcp(child, stdin);
    assert!(
        stopped.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
}

#[cfg(unix)]
#[test]
fn omitted_go_configuration_documents_are_qualified_across_cli_and_mcp() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    let data_dir = temporary.path().join("bundle");
    std::fs::create_dir_all(&root).expect("Go source root");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/worker\n\ngo 1.26\n",
    )
    .expect("Go module");
    std::fs::write(root.join("worker.go"), SHIPPED_GO_BINDING_SOURCE).expect("default Go source");
    std::fs::write(root.join("worker_test.go"), SHIPPED_GO_BINDING_TEST_SOURCE)
        .expect("Go test source");
    std::fs::write(root.join("smoke.go"), SHIPPED_GO_TAGGED_SOURCE).expect("tagged Go source");
    let project_before = file_population(&root);
    let (provider_artifact, provider_executed, path) =
        install_fixture_scip_go_callable_binding(temporary.path(), &root);

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--format", "json"])
        .env("PATH", &path)
        .env("H00_TEST_GO_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_GO_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("index configuration-qualified Go fixture");
    assert!(
        indexed.status.success(),
        "best-effort indexing must retain covered provider evidence; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    assert_eq!(file_population(&root), project_before);
    let indexed = stdout_json(&indexed);
    assert_eq!(indexed["capabilities"]["calls"]["status"], "qualified");
    assert_eq!(
        indexed["capabilities"]["calls"]["languages"][0]["qualifications"][0]["reason_code"],
        "provider_document_omitted"
    );
    let generation = resolve_generation(&data_dir, &root).expect("qualified generation");
    let ProviderPayload::Calls(payload) = generation
        .provider_payloads
        .first()
        .expect("qualified Calls payload")
        .payload()
    else {
        unreachable!("qualified Calls fixture")
    };
    assert!(payload.coverage_exclusions.iter().any(|exclusion| {
        exclusion.reason_code == "provider_document_omitted"
            && exclusion.location.document_path == "smoke.go"
            && exclusion.location.span.start_byte == 0
            && exclusion.location.span.end_byte == SHIPPED_GO_TAGGED_SOURCE.len() as u64
    }));

    let status = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["status", "--format", "json"])
        .output()
        .expect("query qualified Go status");
    assert!(status.status.success());
    let status = stdout_json(&status);
    assert_eq!(status["capabilities"]["calls"]["status"], "qualified");
    assert_eq!(status["action_needed"], false);
    assert!(
        status["recommendation"]
            .as_str()
            .is_some_and(|recommendation| recommendation.contains("explicitly excluded"))
    );

    let calls = run_calls_for(&root, &data_dir, "target", &["--filter", "all"]);
    assert!(calls.status.success());
    let calls = stdout_json(&calls);
    assert_eq!(calls["authority"]["status"], "qualified");
    assert_eq!(
        calls["authority"]["coverage_exclusions"][0]["reason_code"],
        "provider_document_omitted"
    );

    let excluded = run_calls_for(&root, &data_dir, "smokeCaller", &["--file", "smoke.go"]);
    assert!(!excluded.status.success());
    let excluded = stdout_json(&excluded);
    assert_eq!(
        excluded["error"]["code"],
        "symbol_outside_provider_coverage"
    );
    assert_eq!(
        excluded["error"]["evidence"][0]["reason_code"],
        "provider_document_omitted"
    );

    let strict = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--require-complete-calls"])
        .env("PATH", &path)
        .env("H00_TEST_GO_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_GO_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("run strict configuration-qualified refresh");
    assert!(!strict.status.success());
    assert!(String::from_utf8_lossy(&strict.stderr).contains("provider_document_omitted"));
    assert_eq!(
        resolve_generation(&data_dir, &root)
            .expect("strict refusal preserves head")
            .manifest
            .generation_id,
        generation.manifest.generation_id
    );

    let mut command = h00ligan();
    command
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("mcp-serve")
        .env("PATH", &path)
        .env("H00_TEST_GO_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_GO_PROVIDER_EXECUTED", &provider_executed);
    let (child, mut stdin, mut stdout) = spawn_mcp_command(command);
    let mcp_status = call_mcp(&mut stdin, &mut stdout, 1, "status", json!({}));
    let mcp_calls = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "calls",
        json!({"symbol": "target", "filter": "all"}),
    );
    let mcp_strict = call_mcp_reindex_terminal(
        &mut stdin,
        &mut stdout,
        3,
        json!({"scip": true, "require_complete_calls": true}),
    );
    let mcp_calls_after_refusal = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "calls",
        json!({"symbol": "target", "filter": "all"}),
    );
    assert_eq!(mcp_status["result"]["structuredContent"], status);
    assert_eq!(mcp_calls["result"]["structuredContent"], calls);
    assert_eq!(mcp_strict["state"], "failed");
    assert!(
        mcp_strict["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("provider_document_omitted"))
    );
    assert_eq!(
        mcp_calls_after_refusal["result"]["structuredContent"],
        calls
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
}

#[cfg(unix)]
#[test]
fn semantic_refresh_is_best_effort_unless_complete_calls_are_required() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(&root).expect("Go source root");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/failed-provider\n\ngo 1.25\n",
    )
    .expect("Go module");
    std::fs::write(
        root.join("main.go"),
        "package main\n\nfunc target() {}\nfunc main() { target() }\n",
    )
    .expect("Go source fixture");

    let provider_bin = temporary.path().join("provider-bin");
    std::fs::create_dir_all(&provider_bin).expect("fixture provider bin");
    let provider = provider_bin.join("scip-go");
    std::fs::write(
        &provider,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then printf '%s\\n' 'scip-go fixture-failure'; exit 0; fi\n\
         if [ \"$1\" = \"index\" ]; then exit 42; fi\n\
         exit 64\n",
    )
    .expect("fixture scip-go executable");
    let mut permissions = std::fs::metadata(&provider)
        .expect("fixture provider metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&provider, permissions).expect("fixture provider mode");
    let original_path = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![provider_bin];
    paths.extend(std::env::split_paths(&original_path));
    let path = std::env::join_paths(paths).expect("fixture provider PATH");
    let data_dir = temporary.path().join("bundle");

    let best_effort = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--format", "json"])
        .env("PATH", &path)
        .output()
        .expect("run best-effort semantic refresh");
    assert!(
        best_effort.status.success(),
        "best-effort semantic enrichment must publish honest structural and unavailable provider evidence; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&best_effort.stdout),
        String::from_utf8_lossy(&best_effort.stderr),
    );
    let best_effort_json = stdout_json(&best_effort);
    assert_eq!(
        calls_language(&best_effort_json, "go")["status"],
        "unavailable"
    );
    assert_eq!(
        calls_language(&best_effort_json, "go")["gaps"][0]["reason_code"],
        "provider_failed_or_unavailable"
    );
    assert!(
        best_effort_json["phase_timings"]
            .as_array()
            .is_some_and(|timings| timings.iter().any(|timing| timing["phase"] == "publish")),
        "machine output must retain the coarse phase population: {best_effort_json}"
    );
    let best_effort_generation =
        resolve_generation(&data_dir, &root).expect("best-effort generation must be published");

    let refused = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .env("PATH", &path)
        .output()
        .expect("run strict semantic refresh");
    assert!(
        !refused.status.success(),
        "an explicit complete-Calls requirement must refuse unavailable provider evidence; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr),
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains("complete Calls authority")
            && stderr.contains("provider_failed_or_unavailable"),
        "the strict failure must identify the required capability and provider evidence: {stderr}"
    );
    let after_cli_refusal =
        resolve_generation(&data_dir, &root).expect("strict refusal preserves best-effort head");
    assert_eq!(
        after_cli_refusal.manifest.generation_id, best_effort_generation.manifest.generation_id,
        "a strict semantic candidate must validate before advancing publication authority"
    );

    let mut command = h00ligan();
    command
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("mcp-serve")
        .env("PATH", &path);
    let (child, mut stdin, mut stdout) = spawn_mcp_command(command);
    let best_effort_response =
        call_mcp_reindex_terminal(&mut stdin, &mut stdout, 1, json!({"scip": true}));
    assert_eq!(
        best_effort_response["state"], "succeeded",
        "MCP must expose the same best-effort semantic publication as CLI: {best_effort_response}"
    );
    let best_effort_payload = &best_effort_response["result"];
    assert_eq!(
        best_effort_payload["reused_generation"], false,
        "provider execution failure is transient and must be retried: {best_effort_payload}"
    );
    let mcp_generation =
        resolve_generation(&data_dir, &root).expect("MCP best-effort generation must publish");
    assert_ne!(
        mcp_generation.manifest.generation_id, best_effort_generation.manifest.generation_id,
        "a successful retry of transient provider failure must advance the head"
    );

    let strict_response = call_mcp_reindex_terminal(
        &mut stdin,
        &mut stdout,
        2,
        json!({"scip": true, "require_complete_calls": true}),
    );
    assert_eq!(
        strict_response["state"], "failed",
        "MCP must apply the same explicit strict requirement as CLI: {strict_response}"
    );
    assert!(
        strict_response["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("complete Calls authority")),
        "MCP error must retain the shared strict capability failure: {strict_response}"
    );
    let after_mcp = resolve_generation(&data_dir, &root)
        .expect("strict MCP candidate preserves best-effort generation");
    assert_eq!(
        after_mcp.manifest.generation_id, mcp_generation.manifest.generation_id,
        "strict MCP semantic refresh must not advance the publication head"
    );
    let invalid = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "reindex",
        json!({"require_complete_calls": true}),
    );
    assert_eq!(invalid["error"]["code"], -32602, "{invalid}");
    assert!(
        invalid["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("requires 'scip' to be true")),
        "MCP must reject a vacuous strict request: {invalid}"
    );
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must exit cleanly after domain failure: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn human_index_reports_the_active_provider_before_it_finishes() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SHIPPED_INDEX_SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"progress_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);
    let provider_release = temporary.path().join("provider-release");
    let provider = temporary.path().join("bin/rust-analyzer");
    std::fs::write(
        &provider,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--version\" ]; then printf '%s\\n' 'rust-analyzer fixture-executable-2026.08.16'; exit 0; fi\n\
         if [ \"$1\" = \"scip\" ]; then\n\
           printf '%s\\n' 'executed' > \"$H00_TEST_PROVIDER_EXECUTED\"\n\
           shift\n\
           output=''\n\
           while [ \"$#\" -gt 0 ]; do\n\
             if [ \"$1\" = \"--output\" ]; then shift; output=$1; fi\n\
             shift\n\
           done\n\
           while [ ! -f \"$H00_TEST_PROVIDER_RELEASE\" ]; do sleep 0.05; done\n\
           cp \"$H00_TEST_PROVIDER_ARTIFACT\" \"$output\"\n\
           exit 0\n\
         fi\n\
         exit 64\n",
    )
    .expect("blocking fixture provider");
    let mut permissions = std::fs::metadata(&provider)
        .expect("fixture provider metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&provider, permissions).expect("fixture provider mode");

    let mut child = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--require-complete-calls"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .env("H00_TEST_PROVIDER_RELEASE", &provider_release)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn progress-boundary index");
    let stderr = child.stderr.take().expect("child stderr");
    let (line_sender, line_receiver) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let _ =
                line_sender.send(line.unwrap_or_else(|error| format!("<stderr error: {error}>")));
        }
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut lines = Vec::new();
    let mut saw_provider_start = false;
    while std::time::Instant::now() < deadline {
        if let Ok(line) = line_receiver.recv_timeout(std::time::Duration::from_millis(100)) {
            saw_provider_start |= line.contains("rust-analyzer SCIP started");
            lines.push(line);
            if saw_provider_start {
                break;
            }
        }
    }

    let mut provider_entered = provider_executed.is_file();
    let marker_deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while saw_provider_start && !provider_entered && std::time::Instant::now() < marker_deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
        provider_entered = provider_executed.is_file();
    }
    let still_running = child.try_wait().expect("inspect child").is_none();

    if !(saw_provider_start && provider_entered && still_running) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        panic!(
            "progress must identify the active provider before it finishes; \
             saw_start={saw_provider_start} provider_entered={provider_entered} \
             still_running={still_running} stderr={lines:?}"
        );
    }

    std::fs::write(&provider_release, b"continue\n").expect("release fixture provider");
    let status = child.wait().expect("wait for completed index");
    reader.join().expect("join stderr reader");
    assert!(
        status.success(),
        "released provider-backed index must complete"
    );
    assert!(resolve_generation(&data_dir, &root).is_ok());
}

#[cfg(unix)]
#[test]
fn shipped_status_detects_content_drift_even_when_source_mtime_is_restored() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SHIPPED_INDEX_SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("index freshness fixture");
    assert!(
        indexed.status.success() && provider_executed.is_file(),
        "positive control: shipped indexing and its semantic provider must complete; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let run_status = || {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["status", "--format", "json"])
            .output()
            .expect("run shipped status")
    };
    let initial = run_status();
    assert!(initial.status.success());
    assert_eq!(stdout_json(&initial)["freshness"], "fresh");

    let source_path = root.join("src/lib.rs");
    let original_metadata = std::fs::metadata(&source_path).expect("original source metadata");
    let original_modified = original_metadata.modified().expect("original source mtime");
    let original_accessed = original_metadata.accessed().expect("original source atime");
    let changed_source = "pub fn target() {}\npub fn caller() { target(); target(); }\n";
    assert_ne!(changed_source.as_bytes(), SHIPPED_INDEX_SOURCE.as_bytes());
    std::fs::write(&source_path, changed_source).expect("change indexed source bytes");
    let source = std::fs::OpenOptions::new()
        .write(true)
        .open(&source_path)
        .expect("open changed source for timestamp restoration");
    source
        .set_times(
            std::fs::FileTimes::new()
                .set_accessed(original_accessed)
                .set_modified(original_modified),
        )
        .expect("restore original source timestamps");
    assert_eq!(
        std::fs::metadata(&source_path)
            .expect("restored source metadata")
            .modified()
            .expect("restored source mtime"),
        original_modified,
        "falsifier requires byte drift with the original mtime restored"
    );

    let cli = run_status();
    assert!(cli.status.success());
    let cli = stdout_json(&cli);
    assert_eq!(
        cli["freshness"], "stale",
        "status must compare source content, not only mtimes: {cli}"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(&mut stdin, &mut stdout, 1, "status", json!({}));
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        mcp["result"]["structuredContent"]["freshness"], "stale",
        "MCP and CLI must share content-derived freshness: {mcp}"
    );
}

#[cfg(unix)]
#[test]
fn generation_bound_queries_disclose_stale_live_inputs_on_cli_and_mcp() {
    fn assert_stale_generation_result(label: &str, result: &Value) {
        assert_eq!(
            result["repository"]["live_inputs"]["freshness"], "stale",
            "{label} must expose the live-input relation to its immutable generation: {result}"
        );
        let qualifications = result["warnings"]
            .as_array()
            .or_else(|| result["notices"].as_array());
        assert!(
            qualifications.is_some_and(|qualifications| {
                qualifications.iter().any(|warning| {
                    warning
                        .as_str()
                        .is_some_and(|warning| warning.contains("not the current worktree"))
                })
            }),
            "{label} must carry a machine-visible stale-generation qualification: {result}"
        );
    }

    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SHIPPED_INDEX_SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("index stale-query fixture");
    assert!(
        indexed.status.success() && provider_executed.is_file(),
        "positive control: indexing and its provider must complete; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn target() {}\npub fn caller() { target(); target(); }\n",
    )
    .expect("make the live worktree differ from the immutable generation");

    let status = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["status", "--format", "json"])
        .output()
        .expect("run status positive control");
    assert!(status.status.success());
    assert_eq!(
        stdout_json(&status)["freshness"],
        "stale",
        "the same live-input sensor must fire before query qualification"
    );

    let find = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "find",
            "target",
            "--name",
            "--definitions-only",
            "--format",
            "json",
        ])
        .output()
        .expect("run generation-bound Find");
    assert!(find.status.success());
    let find = stdout_json(&find);
    assert_eq!(find["authority"]["status"], "complete");
    assert_stale_generation_result("Find", &find);
    assert_eq!(
        find["repository"]["live_inputs"]["consistency"],
        "per_file_non_atomic"
    );

    let assess = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["assess", "target", "--filter", "all", "--format", "json"])
        .output()
        .expect("run generation-bound Assess");
    assert!(
        assess.status.success(),
        "the immutable generation remains queryable: {}",
        String::from_utf8_lossy(&assess.stderr)
    );
    let assess = stdout_json(&assess);
    assert_eq!(assess["authority"]["status"], "complete");
    assert_stale_generation_result("Assess", &assess);

    let symbol_cases: [(&str, &str, &[&str]); 4] = [
        ("calls", "target", &["--filter", "all"]),
        ("tests", "target", &[]),
        ("dead", "target", &[]),
        ("inspect", "target", &["--sections", "structure"]),
    ];
    let mut cli_symbol_results = BTreeMap::new();
    for (verb, symbol, extra) in symbol_cases {
        let output = run_symbol_verb(&root, &data_dir, verb, symbol, extra);
        assert!(
            output.status.success(),
            "the immutable generation must remain queryable through {verb}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let result = stdout_json(&output);
        assert_stale_generation_result(verb, &result);
        cli_symbol_results.insert(verb, result);
    }

    let mut cli_projection_results = BTreeMap::new();
    for (verb, args) in [
        ("overview", vec!["overview", "--format", "json"]),
        ("deps", vec!["deps", "src/lib.rs", "--format", "json"]),
    ] {
        let output = h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("run h00ligan {verb}: {error}"));
        assert!(
            output.status.success(),
            "the immutable generation must remain queryable through {verb}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let result = stdout_json(&output);
        assert_stale_generation_result(verb, &result);
        cli_projection_results.insert(verb, result);
    }

    let audit = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["audit", "--format", "json"])
        .output()
        .expect("run generation-bound Audit");
    assert!(audit.status.success());
    let audit = stdout_json(&audit);
    assert_eq!(
        audit["repository"]["live_inputs"]["freshness"], "stale",
        "{audit}"
    );
    assert!(audit["warnings"].as_array().is_some_and(|items| {
        items.iter().any(|item| {
            item.as_str()
                .is_some_and(|item| item.contains("not the current worktree"))
        })
    }));

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_find = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "find",
        json!({"query": "target", "mode": "name", "definitions_only": true}),
    );
    let mcp_assess = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "assess",
        json!({"symbol": "target", "filter": "all"}),
    );
    let mcp_calls = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "calls",
        json!({"symbol": "target", "filter": "all"}),
    );
    let mcp_tests = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "tests",
        json!({"symbol": "target"}),
    );
    let mcp_dead = call_mcp(
        &mut stdin,
        &mut stdout,
        5,
        "dead_code",
        json!({"symbol": "target"}),
    );
    let mcp_inspect = call_mcp(
        &mut stdin,
        &mut stdout,
        6,
        "inspect",
        json!({"symbol": "target", "sections": ["structure"]}),
    );
    let mcp_overview = call_mcp(&mut stdin, &mut stdout, 7, "overview", json!({}));
    let mcp_deps = call_mcp(
        &mut stdin,
        &mut stdout,
        8,
        "deps",
        json!({"path": "src/lib.rs"}),
    );
    let mcp_audit = call_mcp(&mut stdin, &mut stdout, 9, "audit", json!({}));
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        mcp_find["result"]["structuredContent"], find,
        "CLI JSON and MCP must expose the exact same observed Find contract"
    );
    assert_eq!(
        without_ephemeral_cursor_lease(mcp_assess["result"]["structuredContent"].clone()),
        without_ephemeral_cursor_lease(assess),
        "CLI JSON and MCP must expose the same observed Assess contract apart from opaque cursor leases"
    );
    for (verb, response) in [
        ("calls", mcp_calls),
        ("tests", mcp_tests),
        ("dead", mcp_dead),
        ("inspect", mcp_inspect),
    ] {
        assert_eq!(
            without_ephemeral_cursor_lease(response["result"]["structuredContent"].clone()),
            without_ephemeral_cursor_lease(cli_symbol_results[verb].clone()),
            "CLI JSON and MCP must expose the same observed {verb} contract apart from opaque cursor leases"
        );
    }
    for (verb, response) in [("overview", mcp_overview), ("deps", mcp_deps)] {
        assert_eq!(
            without_ephemeral_cursor_lease(response["result"]["structuredContent"].clone()),
            without_ephemeral_cursor_lease(cli_projection_results[verb].clone()),
            "CLI JSON and MCP must expose the same observed {verb} contract apart from opaque cursor leases"
        );
    }
    assert_eq!(
        mcp_audit["result"]["structuredContent"], audit,
        "CLI JSON and MCP must expose the same observed Audit projection"
    );

    // Type and a successful source-materializing Read need a different stale
    // shape: mutate an unrelated indexed file so the selected type's exact
    // source bytes remain valid while repository-wide freshness is stale.
    let structural_root = create_source_root(
        &temporary,
        "structural-repo",
        "pub struct Widget { pub field: u32 }\n",
    );
    std::fs::write(
        structural_root.join("Cargo.toml"),
        "[package]\nname = \"structural_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("structural fixture Cargo manifest");
    std::fs::write(
        structural_root.join("src/other.rs"),
        "pub fn helper() -> u32 { 1 }\n",
    )
    .expect("second indexed source");
    let structural_data = temporary.path().join("structural-bundle");
    let structural_index = h00ligan()
        .arg("--root")
        .arg(&structural_root)
        .arg("--data-dir")
        .arg(&structural_data)
        .arg("index")
        .output()
        .expect("index structural stale-query fixture");
    assert!(
        structural_index.status.success(),
        "structural index control must complete: stdout={} stderr={}",
        String::from_utf8_lossy(&structural_index.stdout),
        String::from_utf8_lossy(&structural_index.stderr),
    );
    std::fs::write(
        structural_root.join("src/other.rs"),
        "pub fn helper() -> u32 { 2 }\n",
    )
    .expect("make an unrelated indexed source stale");

    let structural_status = h00ligan()
        .arg("--root")
        .arg(&structural_root)
        .arg("--data-dir")
        .arg(&structural_data)
        .args(["status", "--format", "json"])
        .output()
        .expect("run structural status control");
    assert_eq!(stdout_json(&structural_status)["freshness"], "stale");

    let cli_type = run_symbol_verb(&structural_root, &structural_data, "type", "Widget", &[]);
    let cli_read = run_symbol_verb(&structural_root, &structural_data, "read", "Widget", &[]);
    assert!(cli_type.status.success() && cli_read.status.success());
    let cli_type = stdout_json(&cli_type);
    let cli_read = stdout_json(&cli_read);
    assert_stale_generation_result("type", &cli_type);
    assert_stale_generation_result("read", &cli_read);
    assert!(
        cli_read["source"]
            .as_str()
            .is_some_and(|source| source.contains("pub struct Widget")),
        "Read positive control must still materialize exact unchanged target bytes: {cli_read}"
    );

    let (structural_child, mut structural_stdin, mut structural_stdout) =
        spawn_mcp(&structural_root, &structural_data);
    let mcp_type = call_mcp(
        &mut structural_stdin,
        &mut structural_stdout,
        1,
        "type",
        json!({"symbol": "Widget"}),
    );
    let mcp_read = call_mcp(
        &mut structural_stdin,
        &mut structural_stdout,
        2,
        "read",
        json!({"symbol": "Widget"}),
    );
    let structural_output = stop_mcp(structural_child, structural_stdin);
    assert!(structural_output.status.success());
    assert_eq!(
        without_ephemeral_cursor_lease(mcp_type["result"]["structuredContent"].clone()),
        without_ephemeral_cursor_lease(cli_type),
    );
    assert_eq!(
        without_ephemeral_cursor_lease(mcp_read["result"]["structuredContent"].clone()),
        without_ephemeral_cursor_lease(cli_read),
    );
}

#[cfg(unix)]
#[test]
fn shipped_status_detects_project_input_drift_with_restored_mtime() {
    const ORIGINAL_MANIFEST: &str =
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n";
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SHIPPED_INDEX_SOURCE);
    let manifest_path = root.join("Cargo.toml");
    std::fs::write(&manifest_path, ORIGINAL_MANIFEST).expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("index project-input fixture");
    assert!(
        indexed.status.success() && provider_executed.is_file(),
        "positive control: shipped indexing and its semantic provider must complete; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let run_status = || {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["status", "--format", "json"])
            .output()
            .expect("run shipped status")
    };
    let initial = run_status();
    assert!(initial.status.success());
    assert_eq!(stdout_json(&initial)["freshness"], "fresh");

    let original_metadata = std::fs::metadata(&manifest_path).expect("manifest metadata");
    let original_modified = original_metadata.modified().expect("manifest mtime");
    let original_accessed = original_metadata.accessed().expect("manifest atime");
    std::fs::write(
        &manifest_path,
        "[package]\nname = \"different_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("change project manifest bytes");
    let manifest = std::fs::OpenOptions::new()
        .write(true)
        .open(&manifest_path)
        .expect("open changed manifest for timestamp restoration");
    manifest
        .set_times(
            std::fs::FileTimes::new()
                .set_accessed(original_accessed)
                .set_modified(original_modified),
        )
        .expect("restore project manifest timestamps");
    assert_eq!(
        std::fs::metadata(&manifest_path)
            .expect("restored manifest metadata")
            .modified()
            .expect("restored manifest mtime"),
        original_modified,
        "falsifier requires project-input drift with the original mtime restored"
    );

    let status = run_status();
    assert!(status.status.success());
    let status = stdout_json(&status);
    assert_eq!(
        status["freshness"], "stale",
        "project manifests are semantic inputs and must participate in freshness: {status}"
    );
}

#[tokio::test]
async fn shipped_status_separates_repository_freshness_from_query_process_environment() {
    const PROVIDER_ONLY_ENVIRONMENT: &str = "H00_TEST_PROVIDER_ONLY_SEMANTIC_INPUT";

    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        "pub fn root() { target(); }\nfn target() {}\n",
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"freshness-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let provider_input_path = root.join("provider-input.txt");
    std::fs::write(&provider_input_path, "first\n").expect("provider path input");
    let data_dir = temporary.path().join("bundle");

    let mut semantic_inputs = capture_provider_semantic_inputs(
        &root,
        &BTreeSet::from(["provider-input.txt".to_owned()]),
        &BTreeSet::new(),
        &ProviderFrameLimits::default(),
    )
    .expect("capture provider-declared repository input");
    semantic_inputs
        .environment
        .push(ProviderSemanticEnvironmentInput {
            name: PROVIDER_ONLY_ENVIRONMENT.into(),
            value_sha256: Some("a".repeat(64)),
        });

    let symbol_documents = BTreeMap::new();
    let reachability_overrides = BTreeMap::new();
    let visibility_overrides = BTreeMap::new();
    let provider_omissions = BTreeSet::new();
    let provider_exclusions = BTreeMap::new();
    let project_inventory =
        build_project_inventory(&root, &[InventorySource::new("src/lib.rs", "rust")]);
    assert!(
        project_inventory.issues.is_empty() && !project_inventory.project_topology.units.is_empty(),
        "positive control: live project discovery must produce a complete nonempty inventory"
    );
    seed_calls_topology_bundle_with_documents_and_node_overrides_and_provider_omissions(
        &root,
        &data_dir,
        CallsFixtureOptions {
            edges: &[CallsFixtureEdge {
                caller: "root",
                callee: "target",
                is_test_only: false,
                is_test_root: false,
            }],
            structural_authority: true,
            materialize_graph_edges: false,
            symbol_documents: &symbol_documents,
            reachability_overrides: &reachability_overrides,
            visibility_overrides: &visibility_overrides,
            provider_omissions: &provider_omissions,
            provider_exclusions: &provider_exclusions,
            semantic_inputs,
            project_inventory: Some(project_inventory),
        },
    )
    .await;

    let status = || {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["status", "--format", "json"])
            .env_remove(PROVIDER_ONLY_ENVIRONMENT)
            .output()
            .expect("query shipped status")
    };
    let initial = status();
    assert!(initial.status.success());
    let initial = stdout_json(&initial);
    assert_eq!(
        initial["freshness"], "fresh",
        "query-process environment is not repository freshness authority: {initial}"
    );

    std::fs::write(&provider_input_path, "second\n").expect("change provider path input");
    let changed = status();
    assert!(changed.status.success());
    let changed = stdout_json(&changed);
    assert_eq!(
        changed["freshness"], "stale",
        "positive control: provider-declared repository bytes remain freshness authority: {changed}"
    );
}

#[cfg(unix)]
#[test]
fn shipped_calls_returns_an_authoritative_empty_result_for_a_zero_caller_callable() {
    const SOURCE: &str = "pub fn target() -> u32 { 42 }\n";
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);
    std::fs::write(
        &provider_artifact,
        definition_only_scip_fixture(&root, "src/lib.rs", SOURCE, "fixture_pkg", "target", None),
    )
    .expect("zero-call SCIP fixture");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("index zero-call fixture");
    assert!(
        indexed.status.success(),
        "positive control: shipped indexing must publish complete provider evidence; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    assert!(
        provider_executed.is_file(),
        "the provider executable must run"
    );

    let calls = run_calls(&root, &data_dir, &[]);
    assert!(
        calls.status.success(),
        "a provider-confirmed callable with zero callers must be an authoritative empty result; stdout={} stderr={}",
        String::from_utf8_lossy(&calls.stdout),
        String::from_utf8_lossy(&calls.stderr),
    );
    let calls = stdout_json(&calls);
    assert_eq!(result_count(&calls), Some(0));
    assert_eq!(calls["resolved_symbol"]["name"], "target");
}

#[cfg(unix)]
#[test]
fn shipped_calls_rejects_a_non_callable_target_without_blaming_the_generation() {
    const SOURCE: &str = "pub struct Widget;\npub fn target() -> u32 { 42 }\n";
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);
    std::fs::write(
        &provider_artifact,
        definition_only_scip_fixture(&root, "src/lib.rs", SOURCE, "fixture_pkg", "target", None),
    )
    .expect("definition-only SCIP fixture");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("index non-callable fixture");
    assert!(
        indexed.status.success(),
        "positive control: shipped indexing must publish complete provider evidence; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let calls = run_calls_for(&root, &data_dir, "Widget", &["--file", "src/lib.rs"]);
    assert!(
        !calls.status.success(),
        "a non-callable target must not produce a Calls result"
    );
    let error = stdout_json(&calls);
    assert_eq!(error["error"]["code"], "symbol_not_callable");
    assert!(
        !error["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("generation"),
        "invalid user target shape must not be blamed on immutable publication integrity: {error}"
    );
}

#[cfg(unix)]
#[test]
fn shipped_calls_reports_a_cfg_excluded_target_without_blaming_the_generation() {
    const SOURCE: &str = concat!(
        "#[cfg(not(feature = \"indexed\"))]\n",
        "pub fn hidden() {}\n",
        "pub fn target() -> u32 { 42 }\n",
    );
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);
    std::fs::write(
        &provider_artifact,
        definition_only_scip_fixture(&root, "src/lib.rs", SOURCE, "fixture_pkg", "target", None),
    )
    .expect("cfg-exclusion SCIP fixture");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("index cfg-exclusion fixture");
    assert!(
        indexed.status.success(),
        "positive control: shipped indexing must publish complete scoped evidence; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    let positive = run_calls(&root, &data_dir, &[]);
    assert!(
        positive.status.success(),
        "non-excluded zero-caller control must remain queryable: stdout={} stderr={}",
        String::from_utf8_lossy(&positive.stdout),
        String::from_utf8_lossy(&positive.stderr),
    );

    let excluded = run_calls_for(&root, &data_dir, "hidden", &["--file", "src/lib.rs"]);
    assert!(!excluded.status.success());
    let error = stdout_json(&excluded);
    assert_eq!(error["error"]["code"], "symbol_outside_provider_coverage");
    assert_eq!(
        error["error"]["evidence"][0]["reason_code"],
        "conditional_compilation"
    );
    assert!(
        !error["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("generation is invalid")
    );
}

#[cfg(unix)]
#[test]
fn shipped_calls_qualifies_zero_when_cfg_excludes_a_potential_caller() {
    const SOURCE: &str = concat!(
        "pub fn target() -> u32 { 42 }\n",
        "#[cfg(not(feature = \"indexed\"))]\n",
        "pub fn hidden_caller() { let _ = target(); }\n",
    );
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);
    std::fs::write(
        &provider_artifact,
        definition_only_scip_fixture(&root, "src/lib.rs", SOURCE, "fixture_pkg", "target", None),
    )
    .expect("cfg-caller SCIP fixture");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("index cfg-caller fixture");
    assert!(
        indexed.status.success() && provider_executed.is_file(),
        "positive control: shipped indexing and provider execution must complete; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    let generation = resolve_generation(&data_dir, &root).expect("published generation");
    assert!(
        generation.provider_payloads.iter().any(|payload| {
            matches!(payload.payload(), ProviderPayload::Calls(calls) if
            calls.coverage_exclusions.iter().any(|exclusion| {
                exclusion.reason_code == "conditional_compilation"
                    && exclusion.location.document_path == "src/lib.rs"
            }))
        }),
        "non-vacuity: the published payload must carry the omitted caller region"
    );

    let strict = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "index",
            "--scip",
            "--require-complete-calls",
            "--format",
            "json",
        ])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("run strict cfg-caller refresh");
    assert!(
        !strict.status.success(),
        "strict Calls publication must reject provider-excluded source regions; stdout={} stderr={}",
        String::from_utf8_lossy(&strict.stdout),
        String::from_utf8_lossy(&strict.stderr),
    );
    assert!(
        String::from_utf8_lossy(&strict.stderr).contains("conditional_compilation"),
        "strict refusal must name the exact authority qualification: {}",
        String::from_utf8_lossy(&strict.stderr),
    );
    let after_strict = resolve_generation(&data_dir, &root)
        .expect("strict refusal must preserve the qualified generation");
    assert_eq!(
        after_strict.manifest.generation_id, generation.manifest.generation_id,
        "strict refusal must not advance publication authority"
    );

    let status = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["status", "--format", "json"])
        .output()
        .expect("report qualified cfg-caller status");
    assert!(status.status.success());
    let status = stdout_json(&status);
    assert_eq!(status["capabilities"]["calls"]["status"], "qualified");
    assert_eq!(
        status["capabilities"]["calls"]["languages"][0]["status"],
        "qualified"
    );
    assert_eq!(
        status["capabilities"]["calls"]["languages"][0]["qualifications"][0]["reason_code"],
        "conditional_compilation"
    );

    let calls = run_calls(&root, &data_dir, &[]);
    assert!(
        calls.status.success(),
        "an exact covered-population result remains usable; stdout={} stderr={}",
        String::from_utf8_lossy(&calls.stdout),
        String::from_utf8_lossy(&calls.stderr),
    );
    let calls = stdout_json(&calls);
    assert_eq!(result_count(&calls), Some(0));
    assert_eq!(
        calls["authority"]["status"], "qualified",
        "zero callers cannot be unqualified complete authority while a potential caller region is explicitly excluded: {calls}"
    );
    assert_eq!(
        calls["authority"]["coverage_exclusions"][0]["reason_code"],
        "conditional_compilation"
    );
    assert!(calls["warnings"].as_array().is_some_and(|warnings| {
        warnings.iter().any(|warning| {
            warning
                .as_str()
                .is_some_and(|warning| warning.contains("excluded source region"))
        })
    }));
}

#[tokio::test]
async fn immutable_index_is_the_shared_snapshot_for_cli_readers() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        "pub struct Counter { pub value: usize }\n\
         impl Counter { pub fn increment(&mut self) { self.value += 1; } }\n\
         pub fn consume(counter: &mut Counter) { counter.increment(); }\n",
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"shared_snapshot_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("run shipped h00ligan index");
    assert!(
        indexed.status.success(),
        "positive control: normal index must publish; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let resolved = resolve_generation(&data_dir, &root)
        .expect("normal index must publish a resolvable generation");
    let open_path = resolved.database_path.clone();
    let database = tokio::task::spawn_blocking(move || redb::ReadOnlyDatabase::open(open_path))
        .await
        .expect("join generation open")
        .expect("open generation database");
    let opened = h00ligan_engine::code_intel_publication::validate_open_generation_authority(
        Arc::new(database),
        &resolved,
        &root,
    )
    .expect("generation authority");
    let indexed_graph = opened.graph;
    let indexed_nodes = indexed_graph.node_count();
    assert!(
        indexed_graph
            .all_nodes()
            .iter()
            .any(|node| node.symbol_name == "Counter" && node.kind == "struct"),
        "positive control: the immutable graph must contain Counter"
    );

    std::fs::write(root.join("src/lib.rs"), "pub fn live_only() {}\n")
        .expect("replace source after publication");

    let mut live_graph = KnowledgeGraph::new();
    h00ligan_engine::edge_builder::full_scan(&root, &mut live_graph)
        .expect("positive control: independent live source scan must run");
    assert_ne!(
        live_graph.node_count(),
        indexed_nodes,
        "positive control: changed live source must differ from the indexed generation"
    );
    assert!(
        live_graph
            .all_nodes()
            .iter()
            .any(|node| node.symbol_name == "live_only"),
        "positive control: independent live scan must observe the replacement source"
    );

    let status = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["status", "--format", "json"])
        .output()
        .expect("run status");
    let status_json = serde_json::from_slice::<Value>(&status.stdout).unwrap_or(Value::Null);

    let type_result = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["type", "Counter", "--format", "json"])
        .output()
        .expect("run indexed type query");
    let type_json = serde_json::from_slice::<Value>(&type_result.stdout).unwrap_or(Value::Null);

    let overview = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["overview", "--format", "json"])
        .output()
        .expect("run indexed overview");
    let overview_json = serde_json::from_slice::<Value>(&overview.stdout).unwrap_or(Value::Null);

    let status_uses_generation = status.status.success()
        && status_json["graph_exists"] == true
        && status_json["availability"] == "available"
        && status_json["stats"]["node_count"].as_u64() == Some(indexed_nodes as u64);
    let type_uses_generation = type_result.status.success()
        && type_json["resolved_type"]["name"] == "Counter"
        && !String::from_utf8_lossy(&type_result.stderr).contains("Built graph from source");
    let overview_uses_generation = overview.status.success()
        && overview_json["total_nodes"].as_u64() == Some(indexed_nodes as u64)
        && !String::from_utf8_lossy(&overview.stderr).contains("Built graph from source");
    assert!(
        status_uses_generation && type_uses_generation && overview_uses_generation,
        "every default reader must consume the indexed generation, not the changed live source; \
         status_ok={status_uses_generation} status={} status_stderr={} \
         type_ok={type_uses_generation} type={} type_stderr={} \
         overview_ok={overview_uses_generation} overview={} overview_stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
        String::from_utf8_lossy(&type_result.stdout),
        String::from_utf8_lossy(&type_result.stderr),
        String::from_utf8_lossy(&overview.stdout),
        String::from_utf8_lossy(&overview.stderr),
    );

    for obsolete in [
        "graph.redb",
        "index.redb",
        "graph-write.lock",
        "reindex.incomplete",
    ] {
        assert!(
            !data_dir.join(obsolete).exists(),
            "CLI reads must not create obsolete {obsolete}"
        );
    }
}

#[cfg(unix)]
#[test]
fn every_rust_execution_root_is_rebased_into_one_repository_authority() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SHIPPED_INDEX_SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("root Cargo manifest");
    let detached = root.join("detached");
    std::fs::create_dir_all(detached.join("src")).expect("detached source directory");
    std::fs::write(
        detached.join("Cargo.toml"),
        concat!(
            "[workspace]\n",
            "\n",
            "[package]\n",
            "name = \"detached_fixture\"\n",
            "version = \"0.1.0\"\n",
            "edition = \"2024\"\n",
            "\n",
            "[dependencies]\n",
            "fixture_pkg = { path = \"..\" }\n",
        ),
    )
    .expect("detached Cargo manifest");
    let detached_source = "use fixture_pkg::target;\npub fn detached_only() { target(); }\n";
    std::fs::write(detached.join("src/lib.rs"), detached_source).expect("detached source fixture");
    let canonical_root = canonical_fixture_path(&root);
    let canonical_detached = canonical_fixture_path(&detached);

    let data_dir = temporary.path().join("bundle");
    let provider = install_multiroot_fixture_rust_analyzer(
        temporary.path(),
        &canonical_root,
        &canonical_detached,
        detached_source,
    );
    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip", "--format", "json"])
        .env("PATH", &provider.path)
        .env("H00_TEST_PROVIDER_ROOT", &canonical_root)
        .env("H00_TEST_PROVIDER_DETACHED", &canonical_detached)
        .env("H00_TEST_PROVIDER_ROOT_ARTIFACT", &provider.root_artifact)
        .env(
            "H00_TEST_PROVIDER_DETACHED_ARTIFACT",
            &provider.detached_artifact,
        )
        .env("H00_TEST_PROVIDER_EXECUTION_LOG", &provider.execution_log)
        .output()
        .expect("index nested-Cargo fixture");
    assert!(
        indexed.status.success(),
        "index must publish honest partial authority; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    let execution_roots = std::fs::read_to_string(&provider.execution_log)
        .expect("provider execution log")
        .lines()
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    assert_eq!(
        execution_roots.len(),
        2,
        "one provider invocation is required for each independent Cargo execution root: {execution_roots:?}"
    );
    assert_eq!(
        execution_roots
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        [canonical_root, canonical_detached].into_iter().collect(),
        "the root workspace and detached workspace must each be indexed exactly once"
    );
    let index_payload = stdout_json(&indexed);
    assert_eq!(index_payload["capabilities"]["calls"]["status"], "complete");

    let root_calls = run_calls(&root, &data_dir, &[]);
    assert!(
        root_calls.status.success(),
        "the combined execution-root receipts must authorize the repository-wide caller population; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&root_calls.stdout),
        String::from_utf8_lossy(&root_calls.stderr),
    );
    let root_calls = stdout_json(&root_calls);
    assert_eq!(
        root_calls["page"]["total_items"], 2,
        "root target must retain both its root caller and detached-workspace caller: {root_calls}"
    );
    assert!(
        root_calls["items"]
            .as_array()
            .expect("Calls items")
            .iter()
            .any(|item| item["caller"]["name"] == "detached_only"),
        "the cross-artifact caller must survive provider-set composition: {root_calls}"
    );

    let detached_calls = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "calls",
            "detached_only",
            "--file",
            "detached/src/lib.rs",
            "--filter",
            "all",
            "--format",
            "json",
        ])
        .output()
        .expect("query detached unit");
    assert!(
        detached_calls.status.success(),
        "the detached artifact must be rebased to detached/src/lib.rs and retain its own symbol; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&detached_calls.stdout),
        String::from_utf8_lossy(&detached_calls.stderr),
    );
    assert_eq!(stdout_json(&detached_calls)["page"]["total_items"], 0);

    let generation =
        resolve_generation(&data_dir, &root).expect("resolve multi-root semantic generation");
    let expected_owner_ids = generation
        .project_inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| {
            membership.kind == DocumentMembershipKind::SourceOwner
                && membership.language_id == LanguageId::new("rust")
        })
        .map(|membership| membership.project_unit_id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let complete_scope_ids = generation
        .manifest
        .receipts
        .iter()
        .filter(|receipt| {
            receipt.capability_id == "calls" && receipt.status == CapabilityStatus::Complete
        })
        .flat_map(|receipt| match &receipt.scope {
            CapabilityScope::ProjectUnits {
                project_unit_ids, ..
            } => project_unit_ids.clone(),
            CapabilityScope::Language { language_id, .. }
                if language_id == &LanguageId::new("rust") =>
            {
                expected_owner_ids.iter().cloned().collect()
            }
            other => panic!("multi-root evidence has unexpected scope: {other:?}"),
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        complete_scope_ids, expected_owner_ids,
        "complete receipts must cover every possible Rust caller-owning unit exactly"
    );
    let provider_documents = generation
        .provider_payloads
        .iter()
        .flat_map(|payload| payload.payload().documents().iter())
        .map(|document| document.document_path.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(
        provider_documents.contains("detached/src/lib.rs"),
        "nested provider paths must be canonicalized into repository-relative vocabulary: {provider_documents:?}"
    );
}

#[tokio::test]
async fn shipped_cli_and_mcp_refuse_source_bytes_changed_after_publication() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        concat!(
            "pub struct Counter { pub value: usize }\n",
            "pub fn choose(value: Option<usize>) -> usize {\n",
            "    match value {\n",
            "        Some(value) => value,\n",
            "        None => 0,\n",
            "    }\n",
            "}\n",
        ),
    );
    let data_dir = temporary.path().join("bundle");
    std::fs::create_dir_all(&data_dir).expect("publication directory");
    let output = extract_file(&root.join("src/lib.rs"), &root).expect("extract source fixture");
    assert!(
        output.symbols.iter().any(|symbol| symbol.name == "Counter")
            && output.symbols.iter().any(|symbol| symbol.name == "choose"),
        "positive control: the production extractor must find both queried symbols"
    );
    let indexed_file_hash = output.file_hash.clone();
    let indexed_symbol_count = u32::try_from(output.symbols.len()).expect("fixture symbol count");
    let mut graph = KnowledgeGraph::new();
    build_graph(&[output], &mut graph).expect("build indexed graph");
    let node_ids = graph
        .all_nodes()
        .into_iter()
        .map(|node| node.memory_id)
        .collect::<Vec<_>>();
    for node_id in node_ids {
        graph
            .node_mut(&node_id)
            .expect("indexed node")
            .reachability_class = ReachabilityClass::Structural;
    }

    let binding = ProjectBinding::resolve(
        ProjectBindingOptions::new(&root)
            .explicit_root(&root)
            .global_graph_dir(&data_dir),
    )
    .expect("project binding");
    let mut publisher =
        SemanticPublisher::acquire(binding.graph_dir(), binding.root()).expect("publisher");
    let workspace = publisher.begin_generation().expect("generation workspace");
    let database = workspace.database();
    let store = GraphStore::new(Arc::clone(&database));
    store.save_snapshot(&graph).await.expect("graph snapshot");
    store.set_origin(&root).await.expect("graph origin");
    store
        .set_generation_metadata(GraphGenerationMetadata::now(false))
        .await
        .expect("complete generation metadata");
    drop(store);
    let index_state = h00ligan_engine::index_state::IndexState::new(Arc::clone(&database))
        .expect("generation index state");
    index_state
        .set_file(
            "src/lib.rs",
            &h00ligan_engine::index_state::FileRecord {
                blake3_hash: indexed_file_hash.clone(),
                last_indexed: 1,
                symbol_count: indexed_symbol_count,
                language: "rust".into(),
            },
        )
        .expect("generation source record");
    drop(index_state);
    drop(database);
    let project_unit_id = ProjectUnitId::new("rust-loose-source-fixture");
    publisher
        .finish_generation(
            workspace,
            GenerationDraft {
                source_revision: Some("source-authority-fixture".into()),
                project_inventory: ProjectInventory {
                    coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
                    project_topology: h00ligan_engine::code_intel_domain::ProjectTopology {
                        units: vec![ProjectUnit {
                            project_unit_id: project_unit_id.clone(),
                            language_id: LanguageId::new("rust"),
                            ecosystem_id: EcosystemId::new("rust"),
                            kind: ProjectUnitKind::LooseSources,
                            root_path: String::new(),
                            manifest_path: None,
                            compilation_root_paths: Vec::new(),
                        }],
                        memberships: vec![DocumentMembership {
                            document_path: "src/lib.rs".into(),
                            language_id: LanguageId::new("rust"),
                            project_unit_id,
                            kind: DocumentMembershipKind::SourceOwner,
                        }],
                        relationships: Vec::new(),
                        exact_workspace_member_sets: Vec::new(),
                        dependency_graphs: Vec::new(),
                    },
                    analysis_context_graphs: Vec::new(),
                    inputs: Vec::new(),
                    issues: Vec::new(),
                },
                receipts: vec![CapabilityReceipt::complete(
                    "structural_graph",
                    "h00-structural",
                    h00ligan_engine::BUILD_IDENTITY,
                    CapabilityScope::Language {
                        language_id: LanguageId::new("rust"),
                        configuration_id: ConfigurationId::new("structural-v2"),
                    },
                    indexed_file_hash,
                )],
                provider_payloads: Vec::new(),
            },
        )
        .expect("publish source authority fixture");
    drop(publisher);

    let run = |args: &[&str]| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(args)
            .output()
            .expect("run shipped source query")
    };
    for (name, args) in [
        ("read", &["read", "Counter", "--format", "json"][..]),
        (
            "inspect",
            &[
                "inspect",
                "Counter",
                "--sections",
                "source",
                "--format",
                "json",
            ][..],
        ),
    ] {
        let before = run(args);
        assert!(
            before.status.success(),
            "positive control: shipped CLI {name} must materialize the indexed bytes before drift; stdout={} stderr={}",
            String::from_utf8_lossy(&before.stdout),
            String::from_utf8_lossy(&before.stderr),
        );
    }

    let cli_type = stdout_json(&run(&["type", "Counter", "--format", "json"]));
    let cli_read = stdout_json(&run(&["read", "Counter", "--format", "json"]));
    let cli_find = stdout_json(&run(&["find", "Counter", "--format", "json"]));
    let cli_grep = stdout_json(&run(&["grep-context", "Counter", "--format", "json"]));
    assert!(
        cli_type.get("reachability").is_none()
            && cli_type.get("caller_count").is_none()
            && cli_type.get("dead_count").is_none(),
        "structural CLI type must not claim semantic liveness: {cli_type}"
    );
    assert!(
        cli_read.get("reachability").is_none(),
        "structural CLI read must not claim semantic liveness: {cli_read}"
    );
    assert!(
        cli_find.get("capabilities").is_none()
            && cli_find["items"][0].get("reachability").is_none()
            && cli_find["authority"].get("structural_graph").is_some(),
        "structural CLI find must not couple search to Calls authority: {cli_find}"
    );
    assert!(
        cli_grep["results"].as_array().is_some_and(|results| results
            .iter()
            .all(|result| result.get("reachability").is_none())),
        "structural CLI grep-context must not claim semantic liveness: {cli_grep}"
    );
    let type_help = run(&["type", "--help"]);
    assert!(type_help.status.success());
    assert!(
        !String::from_utf8_lossy(&type_help.stdout).contains("--include-dead"),
        "a structural type query must not expose an obsolete liveness filter"
    );
    for args in [
        &["path", "Counter", "Counter::value"][..],
        &["graph", "path", "Counter", "Counter::value"][..],
    ] {
        let obsolete_path = run(args);
        assert!(
            !obsolete_path.status.success()
                && String::from_utf8_lossy(&obsolete_path.stderr).contains("unrecognized"),
            "a containment BFS must not ship as a call-path query; stdout={} stderr={}",
            String::from_utf8_lossy(&obsolete_path.stdout),
            String::from_utf8_lossy(&obsolete_path.stderr),
        );
    }

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_type = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "type",
        json!({"symbol": "Counter"}),
    );
    let mcp_read = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "read",
        json!({"symbol": "Counter"}),
    );
    let mcp_find = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "find",
        json!({"query": "Counter"}),
    );
    let mcp_grep = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "grep_context",
        json!({"pattern": "Counter"}),
    );
    let mcp_obsolete_type_option = call_mcp(
        &mut stdin,
        &mut stdout,
        5,
        "type",
        json!({"symbol": "Counter", "include_dead": true}),
    );
    let mcp_obsolete_path = call_mcp(
        &mut stdin,
        &mut stdout,
        6,
        "path",
        json!({"from": "Counter", "to": "Counter::value"}),
    );
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mcp_type = &mcp_type["result"]["structuredContent"];
    let mcp_read = &mcp_read["result"]["structuredContent"];
    let mcp_find = &mcp_find["result"]["structuredContent"];
    let mcp_grep = &mcp_grep["result"]["structuredContent"];
    assert!(
        mcp_type.get("reachability").is_none()
            && mcp_type.get("caller_count_total").is_none()
            && mcp_type.get("caller_count_wired").is_none()
            && mcp_type.get("dead_count").is_none(),
        "structural MCP type must not claim semantic liveness: {mcp_type}"
    );
    assert!(mcp_read.get("reachability").is_none(), "{mcp_read}");
    assert!(
        mcp_find.get("capabilities").is_none()
            && mcp_find["items"][0].get("reachability").is_none()
            && mcp_find["authority"].get("structural_graph").is_some(),
        "{mcp_find}"
    );
    assert!(
        mcp_grep["results"].as_array().is_some_and(|results| results
            .iter()
            .all(|result| result.get("reachability").is_none())),
        "{mcp_grep}"
    );
    assert_eq!(mcp_obsolete_type_option["error"]["code"], -32602);
    assert_eq!(mcp_obsolete_path["error"]["code"], -32602);

    let indexed_source = std::fs::read_to_string(root.join("src/lib.rs")).expect("indexed source");
    let surrounding_drift = format!(
        "{indexed_source}// unrelated live comment added outside every indexed definition\n"
    );
    std::fs::write(root.join("src/lib.rs"), &surrounding_drift)
        .expect("change only surrounding source bytes");
    let qualified_cli = run(&[
        "read",
        "Counter",
        "--file",
        "src/lib.rs",
        "--format",
        "json",
    ]);
    assert!(
        qualified_cli.status.success(),
        "an unchanged exact definition must remain readable when only surrounding file bytes drift: stdout={} stderr={}",
        String::from_utf8_lossy(&qualified_cli.stdout),
        String::from_utf8_lossy(&qualified_cli.stderr),
    );
    let qualified_cli = stdout_json(&qualified_cli);
    assert_eq!(qualified_cli["authority"]["status"], "qualified");
    assert_eq!(
        qualified_cli["authority"]["whole_file_matches_generation"],
        false
    );
    assert_eq!(
        qualified_cli["source"],
        "pub struct Counter { pub value: usize }"
    );
    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let qualified_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "read",
        json!({"symbol": "Counter", "file": "src/lib.rs"}),
    );
    let output = stop_mcp(child, stdin);
    assert!(output.status.success());
    assert_eq!(
        qualified_mcp["result"]["structuredContent"], qualified_cli,
        "CLI and MCP must share the same qualified surrounding-drift result"
    );

    let changed = concat!(
        "pub fn live_only() {}\n",
        "pub fn changed(value: Option<usize>) -> usize {\n",
        "    match value {\n",
        "        Some(value) => value + 1,\n",
        "        None => 7,\n",
        "    }\n",
        "}\n",
        "// padding keeps every old byte span in bounds while all symbol bytes differ\n",
    );
    std::fs::write(root.join("src/lib.rs"), changed).expect("mutate source after publication");

    for (name, args) in [
        ("read", &["read", "Counter", "--format", "json"][..]),
        (
            "inspect",
            &[
                "inspect",
                "Counter",
                "--sections",
                "source",
                "--format",
                "json",
            ][..],
        ),
    ] {
        let stale = run(args);
        assert!(
            !stale.status.success()
                && String::from_utf8_lossy(&stale.stderr).contains("source_changed_since_indexing"),
            "shipped CLI {name} must refuse changed bytes with the shared typed reason; stdout={} stderr={}",
            String::from_utf8_lossy(&stale.stdout),
            String::from_utf8_lossy(&stale.stderr),
        );
    }

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let responses = [
        call_mcp(
            &mut stdin,
            &mut stdout,
            1,
            "read",
            json!({"symbol": "Counter"}),
        ),
        call_mcp(
            &mut stdin,
            &mut stdout,
            2,
            "inspect",
            json!({"symbol": "Counter", "sections": ["source"]}),
        ),
    ];
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for response in responses {
        assert_eq!(response["result"]["isError"], true, "{response}");
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "source_changed_since_indexing",
            "{response}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(root.join("src/lib.rs")).expect("changed source"),
        changed,
        "read-only source queries must not repair or rewrite drift"
    );

    std::fs::remove_file(root.join("src/lib.rs")).expect("remove temporary source fixture");
    let missing_cli = run(&["read", "Counter", "--format", "json"]);
    assert!(!missing_cli.status.success());
    let missing_cli = stdout_json(&missing_cli);
    assert_eq!(missing_cli["error"]["code"], "source_read_failed");
    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let missing_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "read",
        json!({"symbol": "Counter"}),
    );
    let output = stop_mcp(child, stdin);
    assert!(output.status.success());
    assert_eq!(missing_mcp["result"]["isError"], true);
    assert_eq!(
        missing_mcp["result"]["structuredContent"], missing_cli,
        "CLI and MCP must share the same typed missing-source refusal"
    );
}

#[test]
fn shipped_read_pages_large_source_through_one_cli_mcp_contract() {
    let temporary = TempDir::new().expect("temporary directory");
    let mut source = String::from("pub fn enormous_symbol() -> usize {\n");
    for index in 0..2_000 {
        source.push_str(&format!(
            "    let value_{index} = {index}; // deliberately retained source page evidence\n"
        ));
    }
    source.push_str("    value_1999\n}\n");
    source.push_str("pub fn another_symbol() -> usize { 7 }\n");
    assert!(
        source.chars().count() > 30_000,
        "positive control: the indexed symbol must exceed the MCP transport ceiling"
    );
    let root = create_source_root(&temporary, "repo", &source);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"read-page-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish large-source generation");
    assert!(
        indexed.status.success(),
        "positive control: large source must index: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let first_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["read", "enormous_symbol", "--format", "json"])
        .output()
        .expect("read first CLI page");
    assert!(
        first_cli.status.success(),
        "bounded CLI read must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&first_cli.stdout),
        String::from_utf8_lossy(&first_cli.stderr),
    );
    let first_cli = stdout_json(&first_cli);

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let first_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "read",
        json!({"symbol": "enormous_symbol"}),
    );
    let first_mcp_result = first_mcp["result"]["structuredContent"].clone();
    assert_eq!(
        without_ephemeral_cursor_lease(first_mcp_result.clone()),
        without_ephemeral_cursor_lease(first_cli.clone()),
        "Read must be bounded inside the shared product contract before MCP transport applies its generic ceiling: {first_mcp}"
    );
    assert!(
        first_mcp_result["page"]["next_cursor"].is_string()
            && first_mcp_result["page"]["expires_at_unix_seconds"].is_u64(),
        "MCP must retain the same time-bound cursor lease contract: {first_mcp_result}"
    );
    assert_eq!(first_cli["schema_version"], "h00/code-intel/read/v1");
    assert_eq!(first_cli["page"]["offset"], 0);
    assert_eq!(first_cli["page"]["has_more"], true);
    assert!(first_cli["page"]["next_cursor"].is_string());
    assert!(
        serde_json::to_string(&first_cli)
            .expect("serialize first Read result")
            .chars()
            .count()
            <= 28_000,
        "the product result must fit below the generic MCP transport ceiling"
    );
    assert_eq!(
        first_cli["source"]
            .as_str()
            .expect("first source page")
            .chars()
            .count() as u64,
        first_cli["page"]["returned"].as_u64().unwrap()
    );

    let cursor = first_cli["page"]["next_cursor"]
        .as_str()
        .expect("first continuation cursor");
    let wrong_file_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "read",
            "enormous_symbol",
            "--file",
            "src/lib.rs",
            "--format",
            "json",
            "--cursor",
            cursor,
        ])
        .output()
        .expect("reject Read cursor under a different file-selection request");
    assert!(!wrong_file_cli.status.success());
    let wrong_file_cli = stdout_json(&wrong_file_cli);
    assert_eq!(wrong_file_cli["error"]["code"], "invalid_cursor");
    let wrong_file_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "read",
        json!({
            "symbol": "enormous_symbol",
            "file": "src/lib.rs",
            "cursor": cursor,
        }),
    );
    assert_eq!(wrong_file_mcp["result"]["isError"], true);
    assert_eq!(
        wrong_file_mcp["result"]["structuredContent"], wrong_file_cli,
        "file selection is part of the shared cursor identity"
    );

    let wrong_symbol_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "read",
            "another_symbol",
            "--format",
            "json",
            "--cursor",
            cursor,
        ])
        .output()
        .expect("reject Read cursor under a different symbol request");
    assert!(!wrong_symbol_cli.status.success());
    let wrong_symbol_cli = stdout_json(&wrong_symbol_cli);
    assert_eq!(wrong_symbol_cli["error"]["code"], "invalid_cursor");
    let wrong_symbol_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "read",
        json!({"symbol": "another_symbol", "cursor": cursor}),
    );
    assert_eq!(wrong_symbol_mcp["result"]["isError"], true);
    assert_eq!(
        wrong_symbol_mcp["result"]["structuredContent"], wrong_symbol_cli,
        "symbol selection is part of the shared cursor identity"
    );

    let second_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "read",
            "enormous_symbol",
            "--format",
            "json",
            "--cursor",
            cursor,
        ])
        .output()
        .expect("read second CLI page");
    assert!(
        second_cli.status.success(),
        "Read continuation must remain usable: stdout={} stderr={}",
        String::from_utf8_lossy(&second_cli.stdout),
        String::from_utf8_lossy(&second_cli.stderr),
    );
    let second_cli = stdout_json(&second_cli);
    let second_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "read",
        json!({"symbol": "enormous_symbol", "cursor": cursor}),
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
    assert_eq!(
        without_ephemeral_cursor_lease(second_mcp["result"]["structuredContent"].clone()),
        without_ephemeral_cursor_lease(second_cli.clone()),
        "CLI and MCP continuations must execute the same Read use case: {second_mcp}"
    );
    assert_eq!(
        second_cli["page"]["offset"], first_cli["page"]["returned"],
        "the cursor must continue the exact source-character population"
    );

    std::fs::write(
        root.join("src/lib.rs"),
        format!("{source}// force a new immutable generation without changing the target\n"),
    )
    .expect("advance source generation");
    let reindexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish replacement generation");
    assert!(
        reindexed.status.success(),
        "positive control: replacement generation must publish: stdout={} stderr={}",
        String::from_utf8_lossy(&reindexed.stdout),
        String::from_utf8_lossy(&reindexed.stderr),
    );
    let stale_generation_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "read",
            "enormous_symbol",
            "--format",
            "json",
            "--cursor",
            cursor,
        ])
        .output()
        .expect("reject cursor from replaced generation");
    assert!(!stale_generation_cli.status.success());
    let stale_generation_cli = stdout_json(&stale_generation_cli);
    assert_eq!(
        stale_generation_cli["error"]["code"],
        "cursor_generation_changed"
    );
    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let stale_generation_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "read",
        json!({"symbol": "enormous_symbol", "cursor": cursor}),
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
    assert_eq!(stale_generation_mcp["result"]["isError"], true);
    assert_eq!(
        stale_generation_mcp["result"]["structuredContent"], stale_generation_cli,
        "CLI and MCP must share generation-bound cursor refusal"
    );
}

#[test]
fn shipped_read_applies_its_serialized_bound_before_mcp_transport() {
    let temporary = TempDir::new().expect("temporary directory");
    let mut source = String::from("pub fn escape_heavy_symbol() -> usize {\n");
    let escaped = "\\".repeat(40);
    for index in 0..600 {
        source.push_str(&format!("    let value_{index} = r#\"{escaped}\"#;\n"));
    }
    source.push_str("    42\n}\n");
    assert!(source.chars().count() > 20_000);
    let root = create_source_root(&temporary, "repo", &source);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"read-escape-bound-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    let data_dir = temporary.path().join("bundle");
    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish escape-heavy source");
    assert!(indexed.status.success());

    let too_large_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "read",
            "escape_heavy_symbol",
            "--limit",
            "20000",
            "--format",
            "json",
        ])
        .output()
        .expect("run product-bound Read");
    assert!(!too_large_cli.status.success());
    let too_large_cli = stdout_json(&too_large_cli);
    assert_eq!(too_large_cli["error"]["code"], "invalid_request");
    assert!(
        too_large_cli["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("product bound")),
        "the shared product contract must explain the bound: {too_large_cli}"
    );

    let usable_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "read",
            "escape_heavy_symbol",
            "--limit",
            "4000",
            "--format",
            "json",
        ])
        .output()
        .expect("run smaller Read page");
    assert!(
        usable_cli.status.success(),
        "positive control: a smaller page must remain usable: stdout={} stderr={}",
        String::from_utf8_lossy(&usable_cli.stdout),
        String::from_utf8_lossy(&usable_cli.stderr),
    );
    let usable_cli = stdout_json(&usable_cli);

    let zero_limit_cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "read",
            "escape_heavy_symbol",
            "--limit",
            "0",
            "--format",
            "json",
        ])
        .output()
        .expect("reject zero Read page");
    assert!(!zero_limit_cli.status.success());
    let zero_limit_cli = stdout_json(&zero_limit_cli);
    assert_eq!(zero_limit_cli["error"]["code"], "invalid_request");

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let too_large_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "read",
        json!({"symbol": "escape_heavy_symbol", "limit": 20000}),
    );
    let usable_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "read",
        json!({"symbol": "escape_heavy_symbol", "limit": 4000}),
    );
    let zero_limit_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "read",
        json!({"symbol": "escape_heavy_symbol", "limit": 0}),
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
    assert_eq!(too_large_mcp["result"]["isError"], true);
    assert_eq!(
        too_large_mcp["result"]["structuredContent"], too_large_cli,
        "MCP must expose the shared typed product bound, not its generic transport fallback"
    );
    assert_eq!(
        without_ephemeral_cursor_lease(usable_mcp["result"]["structuredContent"].clone()),
        without_ephemeral_cursor_lease(usable_cli),
        "CLI and MCP must agree on the bounded Read page apart from independently issued cursor leases"
    );
    assert_eq!(
        zero_limit_mcp["error"]["code"], -32602,
        "MCP transport must reject input outside the advertised schema before invoking the shared use case: {zero_limit_mcp}"
    );
    assert!(
        zero_limit_cli["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("between 1 and")),
        "CLI must expose the equivalent product validation as a typed JSON envelope: {zero_limit_cli}"
    );
}

#[test]
fn shipped_read_refuses_an_outside_file_selector_before_symbol_resolution() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        "pub fn uniquely_named_target() -> usize { 42 }\n",
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"read-selector-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    let outside = temporary.path().join("outside.rs");
    std::fs::write(&outside, "pub fn decoy() {}\n").expect("outside-path control");
    let data_dir = temporary.path().join("bundle");
    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish selector fixture");
    assert!(indexed.status.success());

    let valid = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "read",
            "uniquely_named_target",
            "--file",
            "src/lib.rs",
            "--format",
            "json",
        ])
        .output()
        .expect("run valid exact-file Read");
    assert!(
        valid.status.success(),
        "positive control: exact in-repository selector must work: {}",
        String::from_utf8_lossy(&valid.stderr)
    );

    let refused = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("read")
        .arg("uniquely_named_target")
        .arg("--file")
        .arg(&outside)
        .args(["--format", "json"])
        .output()
        .expect("run outside-selector Read");
    assert!(
        !refused.status.success(),
        "an explicit outside selector must not be ignored merely because the symbol is globally unique: stdout={} stderr={}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr),
    );
    let cli_error = stdout_json(&refused);
    assert_eq!(cli_error["error"]["code"], "source_path_invalid");

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "read",
        json!({
            "symbol": "uniquely_named_target",
            "file": outside.to_string_lossy(),
        }),
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
    assert_eq!(mcp["result"]["isError"], true, "{mcp}");
    assert_eq!(
        mcp["result"]["structuredContent"], cli_error,
        "CLI and MCP must share the exact selector-refusal envelope: {mcp}"
    );
}

#[tokio::test]
async fn shipped_read_preserves_every_occurrence_and_rejects_ambiguous_selectors() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        concat!(
            "pub struct Widget;\n",
            "impl Widget { pub fn first() -> usize { 1 } }\n",
            "impl Widget { pub fn second() -> usize { 2 } }\n",
            "pub fn unique_target() -> usize { 42 }\n",
        ),
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"read-collision-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    let data_dir = temporary.path().join("bundle");
    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish repeated-occurrence generation");
    assert!(
        indexed.status.success(),
        "positive control: repeated source occurrences must publish successfully: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let resolved = resolve_generation(&data_dir, &root).expect("resolve published generation");
    let database = Arc::new(
        redb::ReadOnlyDatabase::open(&resolved.database_path).expect("open generation database"),
    );
    let indexed_files =
        h00ligan_engine::index_state::IndexState::new_read_only(Arc::clone(&database));
    let file_record = indexed_files
        .all_files()
        .expect("indexed source records")
        .into_iter()
        .find(|(path, _)| path == "src/lib.rs")
        .map(|(_, record)| record)
        .expect("src/lib.rs record");
    let graph = GraphStore::new_read_only(database)
        .load_snapshot_checked(&root)
        .await
        .expect("load generation graph")
        .expect("generation graph snapshot");
    let represented = graph.nodes_for_file("src/lib.rs").len();
    assert_eq!(
        usize::try_from(file_record.symbol_count).expect("symbol count fits usize"),
        represented,
        "every extracted source occurrence must survive graph publication"
    );
    assert_eq!(
        graph
            .nodes_for_file("src/lib.rs")
            .iter()
            .filter(|node| node.symbol_name == "impl Widget")
            .count(),
        2,
        "positive control: both valid inherent impl occurrences must be represented"
    );
    assert!(
        graph
            .nodes_for_file("src/lib.rs")
            .iter()
            .any(|node| node.symbol_name == "unique_target"),
        "positive control: the selected unique symbol must still be represented exactly"
    );

    let cli = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "read",
            "unique_target",
            "--file",
            "src/lib.rs",
            "--format",
            "json",
        ])
        .output()
        .expect("read unique target from repeated-occurrence file");
    assert!(
        cli.status.success(),
        "a file containing repeated source occurrences must retain an exact unique Read target: stdout={} stderr={}",
        String::from_utf8_lossy(&cli.stdout),
        String::from_utf8_lossy(&cli.stderr),
    );
    let cli = stdout_json(&cli);
    assert_eq!(cli["resolved_symbol"]["name"], "unique_target");
    assert_eq!(cli["source"], "pub fn unique_target() -> usize { 42 }");
    assert_eq!(cli["authority"]["status"], "complete");
    assert_eq!(cli["authority"]["selected_file_population_complete"], true);
    assert_eq!(cli["authority"]["selected_symbol_identity_complete"], true);

    let found = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "find",
            "impl Widget",
            "--name",
            "--definitions-only",
            "--format",
            "json",
        ])
        .output()
        .expect("find exact repeated-occurrence selectors");
    assert!(
        found.status.success(),
        "Find must expose both repeated occurrences: stdout={} stderr={}",
        String::from_utf8_lossy(&found.stdout),
        String::from_utf8_lossy(&found.stderr),
    );
    let found = stdout_json(&found);
    let selectors = found["items"]
        .as_array()
        .expect("Find items")
        .iter()
        .map(|item| {
            item["symbol_id"]
                .as_str()
                .expect("Find symbol_id")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(selectors.len(), 2, "{found}");
    assert_ne!(selectors[0], selectors[1], "exact selectors must be unique");

    let human_find = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["find", "impl Widget", "--name", "--definitions-only"])
        .output()
        .expect("render human-readable exact selectors");
    assert!(human_find.status.success());
    let human_find = String::from_utf8_lossy(&human_find.stdout);
    for selector in &selectors {
        assert!(
            human_find.contains(&format!("SELECTOR {selector}")),
            "human Find must expose every exact selector needed to resolve a same-file ambiguity: {human_find}"
        );
    }

    let mut exact_cli_sources = BTreeSet::new();
    for selector in &selectors {
        let exact = h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["read", selector, "--format", "json"])
            .output()
            .expect("read one exact occurrence from its Find symbol_id");
        assert!(
            exact.status.success(),
            "a Find symbol_id must resolve one exact occurrence: selector={selector} stdout={} stderr={}",
            String::from_utf8_lossy(&exact.stdout),
            String::from_utf8_lossy(&exact.stderr),
        );
        let exact = stdout_json(&exact);
        assert_eq!(exact["resolved_symbol"]["symbol_id"], selector.as_str());
        exact_cli_sources.insert(
            exact["source"]
                .as_str()
                .expect("exact Read source")
                .to_owned(),
        );
    }
    assert_eq!(
        exact_cli_sources,
        BTreeSet::from([
            "impl Widget { pub fn first() -> usize { 1 } }".to_owned(),
            "impl Widget { pub fn second() -> usize { 2 } }".to_owned(),
        ]),
        "the two exact selectors must address the two distinct source occurrences"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_unique = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "read",
        json!({"symbol": "unique_target", "file": "src/lib.rs"}),
    );
    let mcp_duplicate = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "read",
        json!({"symbol": "impl Widget", "file": "src/lib.rs"}),
    );
    let mcp_exact_first = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "read",
        json!({"symbol": selectors[0]}),
    );
    let mcp_exact_second = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "read",
        json!({"symbol": selectors[1]}),
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
    assert_eq!(
        mcp_unique["result"]["structuredContent"], cli,
        "CLI and MCP must share the same target-specific authority proof"
    );
    assert_eq!(mcp_duplicate["result"]["isError"], true, "{mcp_duplicate}");
    assert_eq!(
        mcp_duplicate["result"]["structuredContent"]["error"]["code"], "ambiguous_symbol",
        "the product must expose the duplicate target instead of selecting one occurrence: {mcp_duplicate}"
    );
    assert_eq!(
        mcp_duplicate["result"]["structuredContent"]["error"]["candidates"],
        json!(["impl Widget (src/lib.rs:2)", "impl Widget (src/lib.rs:3)"]),
        "same-file occurrences must have distinct actionable labels: {mcp_duplicate}"
    );
    let mcp_exact_sources = [&mcp_exact_first, &mcp_exact_second]
        .into_iter()
        .map(|response| {
            assert_ne!(response["result"]["isError"], true, "{response}");
            response["result"]["structuredContent"]["source"]
                .as_str()
                .expect("MCP exact Read source")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(mcp_exact_sources, exact_cli_sources);
}

#[tokio::test]
async fn shipped_exact_symbol_selector_routes_every_symbol_verb_across_cli_and_mcp() {
    let temporary = TempDir::new().expect("temporary directory");
    let semantic_source = concat!(
        "pub fn target() -> usize { 7 }\n",
        "#[test]\n",
        "fn caller() { assert_eq!(target(), 7); }\n",
    );
    let semantic_root = create_source_root(&temporary, "semantic-repo", semantic_source);
    let semantic_data = temporary.path().join("semantic-bundle");
    seed_test_calls_bundle(&semantic_root, &semantic_data, &["caller"]).await;
    let target_selector = find_exact_selector(&semantic_root, &semantic_data, "target");

    let semantic_verbs = ["read", "calls", "assess", "inspect", "dead", "tests"];
    let mut cli_results = BTreeMap::new();
    for verb in semantic_verbs {
        let extra = if matches!(verb, "calls" | "assess") {
            &["--filter", "all"][..]
        } else {
            &[][..]
        };
        let output = run_symbol_verb(
            &semantic_root,
            &semantic_data,
            verb,
            &target_selector,
            extra,
        );
        assert!(
            output.status.success(),
            "exact selector must route shipped CLI {verb}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        let result = stdout_json(&output);
        assert_eq!(
            result_selector(verb, &result),
            target_selector,
            "{verb} must preserve the exact selected identity"
        );
        if verb == "read" {
            assert_eq!(
                result["authority"]["selection_scope"], "exact_symbol_id",
                "Read must truthfully disclose exact-ID selection"
            );
        }
        cli_results.insert(verb, result);
    }

    let (semantic_child, mut semantic_stdin, mut semantic_stdout) =
        spawn_mcp(&semantic_root, &semantic_data);
    for (index, verb) in semantic_verbs.into_iter().enumerate() {
        let tool = if verb == "dead" { "dead_code" } else { verb };
        let mut arguments = json!({"symbol": target_selector});
        if matches!(verb, "calls" | "assess") {
            arguments["filter"] = json!("all");
        }
        let response = call_mcp(
            &mut semantic_stdin,
            &mut semantic_stdout,
            index as u64 + 1,
            tool,
            arguments,
        );
        assert_ne!(response["result"]["isError"], true, "{verb}: {response}");
        assert_eq!(
            response["result"]["structuredContent"], cli_results[verb],
            "CLI and MCP {verb} must share the exact-selector result"
        );
    }
    let semantic_stopped = stop_mcp(semantic_child, semantic_stdin);
    assert!(
        semantic_stopped.status.success(),
        "semantic MCP server must stop cleanly: {}",
        String::from_utf8_lossy(&semantic_stopped.stderr)
    );

    let type_root = create_source_root(
        &temporary,
        "type-repo",
        concat!(
            "pub struct Widget { pub value: usize }\n",
            "impl Widget { pub fn value(&self) -> usize { self.value } }\n",
        ),
    );
    std::fs::write(
        type_root.join("Cargo.toml"),
        "[package]\nname = \"selector_type_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("type fixture manifest");
    let type_data = temporary.path().join("type-bundle");
    let indexed = h00ligan()
        .arg("--root")
        .arg(&type_root)
        .arg("--data-dir")
        .arg(&type_data)
        .arg("index")
        .output()
        .expect("publish structural type fixture");
    assert!(
        indexed.status.success(),
        "structural Type control must publish: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    let type_selector = find_exact_selector(&type_root, &type_data, "Widget");
    let cli_type = run_symbol_verb(&type_root, &type_data, "type", &type_selector, &[]);
    assert!(
        cli_type.status.success(),
        "exact selector must route shipped CLI Type: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_type.stdout),
        String::from_utf8_lossy(&cli_type.stderr),
    );
    let cli_type = stdout_json(&cli_type);
    assert_eq!(result_selector("type", &cli_type), type_selector);

    let (type_child, mut type_stdin, mut type_stdout) = spawn_mcp(&type_root, &type_data);
    let mcp_type = call_mcp(
        &mut type_stdin,
        &mut type_stdout,
        1,
        "type",
        json!({"symbol": type_selector}),
    );
    let type_stopped = stop_mcp(type_child, type_stdin);
    assert!(type_stopped.status.success());
    assert_eq!(mcp_type["result"]["structuredContent"], cli_type);
}

#[test]
fn exact_symbol_selectors_fail_closed_across_generation_repository_shape_and_file() {
    let temporary = TempDir::new().expect("temporary directory");
    let source = "pub fn exact_target() -> usize { 42 }\n";
    let root_a = create_source_root(&temporary, "repo-a", source);
    std::fs::write(
        root_a.join("Cargo.toml"),
        "[package]\nname = \"selector_repo_a\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("repo A manifest");
    let data_a = temporary.path().join("bundle-a");
    let first_index = h00ligan()
        .arg("--root")
        .arg(&root_a)
        .arg("--data-dir")
        .arg(&data_a)
        .arg("index")
        .output()
        .expect("publish first generation");
    assert!(first_index.status.success());
    let first_selector = find_exact_selector(&root_a, &data_a, "exact_target");

    let forced = h00ligan()
        .arg("--root")
        .arg(&root_a)
        .arg("--data-dir")
        .arg(&data_a)
        .args(["index", "--force"])
        .output()
        .expect("force a new immutable generation");
    assert!(
        forced.status.success(),
        "force control must publish: stdout={} stderr={}",
        String::from_utf8_lossy(&forced.stdout),
        String::from_utf8_lossy(&forced.stderr),
    );
    let current_selector = find_exact_selector(&root_a, &data_a, "exact_target");
    assert_ne!(
        first_selector, current_selector,
        "an exact selector must change when immutable generation identity changes"
    );
    let current = run_symbol_verb(&root_a, &data_a, "read", &current_selector, &[]);
    assert!(
        current.status.success(),
        "current selector positive control"
    );

    let stale = run_symbol_verb(&root_a, &data_a, "read", &first_selector, &[]);
    assert!(
        !stale.status.success(),
        "a superseded selector must fail closed"
    );
    assert_eq!(stdout_json(&stale)["error"]["code"], "symbol_not_found");

    let malformed = run_symbol_verb(
        &root_a,
        &data_a,
        "read",
        "sym-v1.not-an-occurrence.not-a-digest",
        &[],
    );
    assert!(
        !malformed.status.success(),
        "reserved-prefix malformed selectors must not fall back to name lookup"
    );
    assert_eq!(stdout_json(&malformed)["error"]["code"], "symbol_not_found");

    let wrong_file = run_symbol_verb(
        &root_a,
        &data_a,
        "read",
        &current_selector,
        &["--file", "src/other.rs"],
    );
    assert!(
        !wrong_file.status.success(),
        "an exact ID plus file is an assertion, never a new lookup"
    );
    assert_eq!(
        stdout_json(&wrong_file)["error"]["code"],
        "symbol_not_found_in_file"
    );

    let root_b = create_source_root(&temporary, "repo-b", source);
    std::fs::write(
        root_b.join("Cargo.toml"),
        "[package]\nname = \"selector_repo_b\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("repo B manifest");
    let data_b = temporary.path().join("bundle-b");
    let index_b = h00ligan()
        .arg("--root")
        .arg(&root_b)
        .arg("--data-dir")
        .arg(&data_b)
        .arg("index")
        .output()
        .expect("publish foreign repository generation");
    assert!(index_b.status.success());
    let foreign = run_symbol_verb(&root_b, &data_b, "read", &current_selector, &[]);
    assert!(
        !foreign.status.success(),
        "an exact selector from another repository must fail closed"
    );
    assert_eq!(stdout_json(&foreign)["error"]["code"], "symbol_not_found");

    let (child, mut stdin, mut stdout) = spawn_mcp(&root_a, &data_a);
    let stale_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "read",
        json!({"symbol": first_selector}),
    );
    let current_mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "read",
        json!({"symbol": current_selector}),
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
    assert_eq!(stale_mcp["result"]["isError"], true, "{stale_mcp}");
    assert_eq!(
        stale_mcp["result"]["structuredContent"]["error"]["code"],
        "symbol_not_found"
    );
    assert_ne!(current_mcp["result"]["isError"], true, "{current_mcp}");
}

#[tokio::test]
async fn shipped_go_repeated_init_occurrences_survive_cli_and_mcp_publication() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(&root).expect("Go fixture root");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/worker\n\ngo 1.26\n",
    )
    .expect("Go fixture module");
    let initial = concat!(
        "package worker\n",
        "func init() { first() }\n",
        "func init() { second() }\n",
        "func first() {}\n",
        "func second() {}\n",
    );
    std::fs::write(root.join("worker.go"), initial).expect("Go fixture source");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish repeated Go init occurrences");
    assert!(
        indexed.status.success(),
        "Go publication failed: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let binding = ProjectBinding::resolve(
        ProjectBindingOptions::new(&root)
            .explicit_root(&root)
            .global_graph_dir(&data_dir),
    )
    .expect("resolve Go fixture binding");
    let generation =
        resolve_generation(binding.graph_dir(), binding.root()).expect("resolve Go generation");
    let database = Arc::new(
        redb::ReadOnlyDatabase::open(&generation.database_path).expect("open Go generation"),
    );
    let record = IndexState::new_read_only(Arc::clone(&database))
        .all_files()
        .expect("Go indexed source records")
        .into_iter()
        .find(|(path, _)| path == "worker.go")
        .map(|(_, record)| record)
        .expect("indexed worker.go");
    let graph = GraphStore::new_read_only(database)
        .load_snapshot_checked(&root)
        .await
        .expect("load Go generation graph")
        .expect("Go generation graph snapshot");
    let represented = graph.nodes_for_file("worker.go");
    assert_eq!(
        usize::try_from(record.symbol_count).expect("Go symbol count fits usize"),
        represented.len(),
        "every extracted Go occurrence must survive publication"
    );
    assert_eq!(
        represented
            .iter()
            .filter(|node| node.kind == "function" && node.symbol_name == "init")
            .count(),
        2,
        "positive control: Go permits and the graph must retain both init functions"
    );
    let structural = generation
        .manifest
        .receipts
        .iter()
        .find(|receipt| receipt.capability_id == "structural_graph")
        .expect("Go structural receipt");
    assert_eq!(
        structural.status,
        CapabilityStatus::Complete,
        "{structural:?}"
    );

    let found = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "find",
            "init",
            "--name",
            "--definitions-only",
            "--format",
            "json",
        ])
        .output()
        .expect("Find repeated Go init functions");
    assert!(
        found.status.success(),
        "Go Find failed: stdout={} stderr={}",
        String::from_utf8_lossy(&found.stdout),
        String::from_utf8_lossy(&found.stderr),
    );
    let found = stdout_json(&found);
    assert_eq!(found["page"]["returned"], 2, "{found}");
    assert_eq!(found["authority"]["status"], "complete", "{found}");

    let changed = concat!(
        "package worker\n",
        "func init() { first() }\n",
        "func init() { first() }\n",
        "func first() {}\n",
        "func second() {}\n",
    );
    std::fs::write(root.join("worker.go"), changed).expect("modify second Go init");
    let diff = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "worker.go", "--format", "json"])
        .output()
        .expect("Diff repeated Go init functions");
    assert!(
        diff.status.success(),
        "Go Diff failed: stdout={} stderr={}",
        String::from_utf8_lossy(&diff.stdout),
        String::from_utf8_lossy(&diff.stderr),
    );
    let diff = stdout_json(&diff);
    assert_eq!(diff["files_compared"], 1, "{diff}");
    assert_eq!(diff["files_excluded"], 0, "{diff}");
    assert_eq!(diff["total_modified"], 1, "{diff}");

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_find = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "find",
        json!({"query": "init", "mode": "name", "definitions_only": true}),
    );
    let mcp_read = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "read",
        json!({"symbol": "init", "file": "worker.go"}),
    );
    let mcp_diff = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "diff",
        json!({"path": "worker.go"}),
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
    assert_eq!(found["repository"]["live_inputs"]["freshness"], "fresh");
    assert_eq!(
        mcp_find["result"]["structuredContent"]["repository"]["live_inputs"]["freshness"], "stale",
        "MCP runs after the deliberate source edit and must report that observation: {mcp_find}"
    );
    assert_eq!(
        without_live_input_observation(mcp_find["result"]["structuredContent"].clone()),
        without_live_input_observation(found),
        "the immutable Find payload must remain identical across the explicit fresh-to-stale transition: {mcp_find}"
    );
    assert_eq!(mcp_diff["result"]["structuredContent"], diff, "{mcp_diff}");
    assert_eq!(mcp_read["result"]["isError"], true, "{mcp_read}");
    assert_eq!(
        mcp_read["result"]["structuredContent"]["error"]["code"], "ambiguous_symbol",
        "{mcp_read}"
    );
    assert_eq!(
        mcp_read["result"]["structuredContent"]["error"]["candidates"],
        json!(["init (worker.go:2)", "init (worker.go:3)"]),
        "Go occurrence diagnostics must distinguish the two valid init functions: {mcp_read}"
    );
}

#[test]
fn grep_context_never_labels_changed_live_bytes_with_a_stale_indexed_symbol() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        concat!(
            "pub fn indexed_owner() {\n",
            "    let indexed_marker = 1;\n",
            "}\n",
        ),
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"grep-context-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish immutable generation");
    assert!(
        indexed.status.success(),
        "positive control: indexing must publish the source fixture; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let run_search = |pattern: &str| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["grep-context", pattern, "--format", "json"])
            .output()
            .expect("run shipped grep-context")
    };
    let indexed_search = stdout_json(&run_search("indexed_marker"));
    assert_eq!(
        indexed_search["results"][0]["containing_symbol"], "indexed_owner",
        "positive control: unchanged source must receive exact indexed context: {indexed_search}"
    );

    std::fs::write(
        root.join("src/lib.rs"),
        concat!(
            "pub fn live_owner() {\n",
            "    let live_marker = 2;\n",
            "}\n",
        ),
    )
    .expect("replace source after publication");

    let live_search_output = run_search("live_marker");
    assert!(
        live_search_output.status.success(),
        "live-worktree search itself remains useful after source drift; stdout={} stderr={}",
        String::from_utf8_lossy(&live_search_output.stdout),
        String::from_utf8_lossy(&live_search_output.stderr),
    );
    let live_search = stdout_json(&live_search_output);
    assert_eq!(live_search["matches_returned"], 1, "{live_search}");
    assert!(
        live_search["results"][0]["containing_symbol"].is_null(),
        "live bytes must never be attributed to a stale generation's symbol merely because its old line span still fits: {live_search}"
    );
    assert_eq!(
        live_search["results"][0]["graph_context_status"], "source_changed_since_generation",
        "the refusal must explain why graph enrichment was withheld: {live_search}"
    );

    let cli_context_output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "grep-context",
            "live_marker",
            "--context-lines",
            "1",
            "--limit",
            "5",
            "--format",
            "json",
        ])
        .output()
        .expect("run context-bearing CLI search");
    assert!(cli_context_output.status.success());
    let cli_context = stdout_json(&cli_context_output);
    assert_eq!(cli_context["records_returned"], 3, "{cli_context}");

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "grep_context",
        json!({"pattern": "live_marker", "context_lines": 1, "limit": 5}),
    );
    let mcp_zero_limit = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "grep_context",
        json!({"pattern": "live_marker", "limit": 0}),
    );
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        mcp["result"]["structuredContent"], cli_context,
        "CLI JSON and MCP structured content must be the same source-search contract"
    );
    assert_eq!(
        mcp_zero_limit["error"]["code"], -32602,
        "MCP schema must reject a false-empty zero limit: {mcp_zero_limit}"
    );

    let cli_zero_limit = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "grep-context",
            "live_marker",
            "--limit",
            "0",
            "--format",
            "json",
        ])
        .output()
        .expect("run rejected zero-limit CLI search");
    assert!(
        !cli_zero_limit.status.success()
            && String::from_utf8_lossy(&cli_zero_limit.stderr)
                .contains("invalid source_search request field 'limit'"),
        "CLI must reject a false-empty zero limit before searching; stdout={} stderr={}",
        String::from_utf8_lossy(&cli_zero_limit.stdout),
        String::from_utf8_lossy(&cli_zero_limit.stderr),
    );

    let large_live_source = (0..20)
        .map(|index| format!("// live_marker_{index} {}\n", "x".repeat(1_800)))
        .collect::<String>();
    std::fs::write(root.join("src/lib.rs"), large_live_source).expect("large live source");
    let cli_oversized = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "grep-context",
            "live_marker",
            "--limit",
            "100",
            "--format",
            "json",
        ])
        .output()
        .expect("run product-bounded CLI search");
    assert!(
        !cli_oversized.status.success()
            && String::from_utf8_lossy(&cli_oversized.stderr)
                .contains("above the 28000-character product bound"),
        "CLI must reject an oversized typed result instead of emitting an untransportable success; stdout={} stderr={}",
        String::from_utf8_lossy(&cli_oversized.stdout),
        String::from_utf8_lossy(&cli_oversized.stderr),
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_oversized = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "grep_context",
        json!({"pattern": "live_marker", "limit": 100}),
    );
    let output = stop_mcp(child, stdin);
    assert!(output.status.success());
    assert_eq!(mcp_oversized["result"]["isError"], true);
    assert_eq!(
        mcp_oversized["result"]["structuredContent"]["error"]["code"], "invalid_request",
        "the domain bound must fire before the generic MCP result cap: {mcp_oversized}"
    );
}

#[test]
fn shipped_diff_never_calls_an_unchanged_explicit_file_changed() {
    let temporary = TempDir::new().expect("temporary directory");
    let original = "pub fn stable_value() -> u32 { 1 }\n";
    let root = create_source_root(&temporary, "repo", original);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"diff-unchanged-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish immutable generation");
    assert!(
        indexed.status.success(),
        "index positive control failed: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let run_diff = || {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["diff", "src/lib.rs", "--format", "json"])
            .output()
            .expect("run shipped file diff")
    };

    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn stable_value() -> u32 { 2 }\n",
    )
    .expect("modify indexed source");
    let changed = stdout_json(&run_diff());
    assert_eq!(
        changed["files_with_symbol_changes"], 1,
        "positive control: a real symbol modification must fire: {changed}"
    );
    assert_eq!(changed["total_modified"], 1, "{changed}");

    for limit in ["0", "101"] {
        let invalid = h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["diff", "src/lib.rs", "--format", "json", "--limit", limit])
            .output()
            .expect("run invalid CLI diff bound");
        assert!(
            !invalid.status.success(),
            "CLI diff limit {limit} must not produce a false-empty or unbounded result: {}",
            String::from_utf8_lossy(&invalid.stdout)
        );
        assert!(
            String::from_utf8_lossy(&invalid.stderr).contains("between 1 and 100"),
            "CLI refusal must identify its exact bound: {}",
            String::from_utf8_lossy(&invalid.stderr)
        );
    }

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    for (id, limit) in [(1, 0), (2, 101)] {
        let invalid = call_mcp(
            &mut stdin,
            &mut stdout,
            id,
            "diff",
            json!({"path": "src/lib.rs", "limit": limit}),
        );
        assert_eq!(
            invalid["error"]["code"], -32602,
            "MCP schema admission must reject diff limit {limit}: {invalid}"
        );
        let expected_boundary = if limit == 0 {
            "minimum 1"
        } else {
            "maximum 100"
        };
        assert!(
            invalid["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(expected_boundary)),
            "MCP refusal must expose its exact {expected_boundary} bound: {invalid}"
        );
    }
    let positive = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "diff",
        json!({"path": "src/lib.rs", "limit": 1}),
    );
    assert_ne!(positive["result"]["isError"], true, "{positive}");
    assert_eq!(
        positive["result"]["structuredContent"]["changes_returned"], 1,
        "the lower edge remains live: {positive}"
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());

    std::fs::write(root.join("src/lib.rs"), original).expect("restore indexed bytes");
    let unchanged = stdout_json(&run_diff());
    assert_eq!(unchanged["total_added"], 0, "{unchanged}");
    assert_eq!(unchanged["total_removed"], 0, "{unchanged}");
    assert_eq!(unchanged["total_modified"], 0, "{unchanged}");
    assert_eq!(unchanged["schema_version"], "h00/code-intel/diff/v1");
    assert_eq!(unchanged["authority"]["status"], "complete", "{unchanged}");
    assert_eq!(unchanged["verdict"], "no_symbol_differences", "{unchanged}");
    assert_eq!(unchanged["files_compared"], 1, "{unchanged}");
    assert_eq!(
        unchanged["files_with_symbol_changes"], 0,
        "a file with no symbol changes must not be called changed: {unchanged}"
    );
    assert_eq!(unchanged["files"], json!([]), "{unchanged}");
}

#[test]
fn shipped_diff_qualifies_a_partial_syntax_recovery_as_unknown() {
    let temporary = TempDir::new().expect("temporary directory");
    let original = "pub fn retained() -> u32 { 1 }\n\npub fn would_look_removed() {}\n";
    let root = create_source_root(&temporary, "repo", original);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"diff-syntax-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    std::fs::write(
        root.join("src/other.rs"),
        "pub fn independently_diffable() -> u32 { 1 }\n",
    )
    .expect("independently representable source");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish immutable generation");
    assert!(
        indexed.status.success(),
        "index positive control failed: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn retained() -> u32 { 2 }\n\npub fn still_valid() {}\n",
    )
    .expect("write valid edit");
    let valid = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "src/lib.rs", "--format", "json"])
        .output()
        .expect("run valid diff positive control");
    assert!(
        valid.status.success(),
        "valid live source must remain diffable: stdout={} stderr={}",
        String::from_utf8_lossy(&valid.stdout),
        String::from_utf8_lossy(&valid.stderr),
    );
    let valid_result = stdout_json(&valid);
    assert_eq!(
        valid_result["verdict"], "symbol_differences_observed",
        "positive control must fire: {valid_result}"
    );

    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn retained() -> u32 {\n    let unfinished =\n",
    )
    .expect("write syntax-incomplete edit");
    let incomplete = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "src/lib.rs", "--format", "json"])
        .output()
        .expect("run syntax-incomplete diff");
    assert!(
        incomplete.status.success(),
        "a recovered partial AST must become a qualified unknown, not an authoritative diff or global failure: stdout={} stderr={}",
        String::from_utf8_lossy(&incomplete.stdout),
        String::from_utf8_lossy(&incomplete.stderr),
    );
    let incomplete_result = stdout_json(&incomplete);
    assert_eq!(incomplete_result["verdict"], "unknown");
    assert_eq!(incomplete_result["files_considered"], 1);
    assert_eq!(incomplete_result["files_compared"], 0);
    assert_eq!(incomplete_result["files_excluded"], 1);
    assert_eq!(
        incomplete_result["authority"]["comparison"]["exclusions"][0]["reason_code"],
        "candidate_syntax_incomplete",
        "the qualified result must identify why no comparison was possible: {incomplete_result}"
    );

    std::fs::write(
        root.join("src/other.rs"),
        "pub fn independently_diffable() -> u32 { 2 }\n",
    )
    .expect("modify independent source");
    let workspace = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "--format", "json"])
        .output()
        .expect("run workspace diff around incomplete source");
    assert!(
        workspace.status.success(),
        "one incomplete candidate must not suppress truthful comparisons elsewhere: stdout={} stderr={}",
        String::from_utf8_lossy(&workspace.stdout),
        String::from_utf8_lossy(&workspace.stderr),
    );
    let workspace_result = stdout_json(&workspace);
    assert_eq!(workspace_result["verdict"], "symbol_differences_observed");
    assert_eq!(workspace_result["files_considered"], 2);
    assert_eq!(workspace_result["files_compared"], 1);
    assert_eq!(workspace_result["files_excluded"], 1);
    assert_eq!(workspace_result["total_modified"], 1);

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_incomplete = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "diff",
        json!({"path": "src/lib.rs"}),
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
    assert_eq!(
        mcp_incomplete["result"]["structuredContent"], incomplete_result,
        "MCP must carry the same qualified syntax-exclusion result: {mcp_incomplete}"
    );
}

#[test]
fn shipped_diff_excludes_a_published_source_that_failed_baseline_extraction() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"diff-extraction-gap-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn represented() -> u32 { 1 }\n",
    )
    .expect("representable source");
    std::fs::write(
        root.join("src/broken.rs"),
        "pub fn unfinished() -> u32 {\n    let value =\n",
    )
    .expect("syntax-incomplete baseline source");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish partial immutable generation");
    assert!(
        indexed.status.success(),
        "an extraction gap must publish explicitly partial authority: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    let generation = resolve_generation(&data_dir, &root).expect("resolve partial generation");
    let structural = generation
        .manifest
        .receipts
        .iter()
        .find(|receipt| receipt.capability_id == "structural_graph")
        .expect("structural receipt");
    assert_eq!(structural.status, CapabilityStatus::Partial);
    assert_eq!(
        structural.reason_code.as_deref(),
        Some("source_extraction_failed")
    );

    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn represented() -> u32 { 2 }\n",
    )
    .expect("modify represented source");
    let workspace = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "--format", "json"])
        .output()
        .expect("run partial workspace diff");
    assert!(
        workspace.status.success(),
        "one unrepresented baseline source must not suppress truthful comparisons: stdout={} stderr={}",
        String::from_utf8_lossy(&workspace.stdout),
        String::from_utf8_lossy(&workspace.stderr),
    );
    let workspace_result = stdout_json(&workspace);
    assert_eq!(workspace_result["verdict"], "symbol_differences_observed");
    assert_eq!(workspace_result["files_considered"], 2);
    assert_eq!(workspace_result["files_compared"], 1);
    assert_eq!(workspace_result["files_excluded"], 1);
    assert_eq!(workspace_result["total_added"], 0, "{workspace_result}");
    assert_eq!(workspace_result["total_modified"], 1, "{workspace_result}");
    assert_eq!(
        workspace_result["authority"]["comparison"]["exclusions"][0]["reason_code"],
        "baseline_source_not_indexed",
        "the extraction gap must be named rather than converted into false additions: {workspace_result}"
    );

    let focused = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "src/broken.rs", "--format", "json"])
        .output()
        .expect("run focused extraction-gap diff");
    assert!(
        focused.status.success(),
        "the known baseline gap should be a structured unknown result: stdout={} stderr={}",
        String::from_utf8_lossy(&focused.stdout),
        String::from_utf8_lossy(&focused.stderr),
    );
    let focused_result = stdout_json(&focused);
    assert_eq!(focused_result["verdict"], "unknown");
    assert_eq!(focused_result["files_considered"], 1);
    assert_eq!(focused_result["files_compared"], 0);
    assert_eq!(focused_result["files_excluded"], 1);
    assert_eq!(focused_result["changes_total"], 0);

    let human = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("diff")
        .output()
        .expect("run human-readable extraction-gap diff");
    assert!(human.status.success());
    assert!(
        String::from_utf8_lossy(&human.stdout).contains("baseline_source_not_indexed: 1"),
        "human output must expose the same exclusion reason instead of pointing only at JSON: {}",
        String::from_utf8_lossy(&human.stdout)
    );
}

#[test]
fn shipped_diff_accepts_an_indexed_path_that_was_deleted_live() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        "pub fn removed_one() {}\n\npub fn removed_two() {}\n",
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"diff-deleted-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    std::fs::write(root.join("src/empty.rs"), "").expect("empty indexed source");
    let data_dir = temporary.path().join("bundle");
    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish immutable generation");
    assert!(
        indexed.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );
    std::fs::remove_file(root.join("src/lib.rs")).expect("delete indexed source");
    std::fs::remove_file(root.join("src/empty.rs")).expect("delete empty indexed source");

    let workspace = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "--format", "json"])
        .output()
        .expect("run workspace deletion positive control");
    assert!(
        workspace.status.success(),
        "workspace diff must observe the deletion: {}",
        String::from_utf8_lossy(&workspace.stderr)
    );
    let workspace_result = stdout_json(&workspace);
    assert_eq!(workspace_result["total_removed"], 2, "{workspace_result}");
    assert_eq!(workspace_result["files_compared"], 2, "{workspace_result}");

    let explicit = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "src/lib.rs", "--format", "json"])
        .output()
        .expect("run explicit deleted-file diff");
    assert!(
        explicit.status.success(),
        "the indexed path is sufficient baseline authority for an explicit deletion: stdout={} stderr={}",
        String::from_utf8_lossy(&explicit.stdout),
        String::from_utf8_lossy(&explicit.stderr),
    );
    let explicit_result = stdout_json(&explicit);
    assert_eq!(explicit_result["query"]["path"], "src/lib.rs");
    assert_eq!(
        explicit_result["files_with_symbol_changes"], 1,
        "{explicit_result}"
    );
    assert_eq!(explicit_result["total_removed"], 2, "{explicit_result}");
    assert_eq!(explicit_result["files"][0]["file_path"], "src/lib.rs");

    let empty = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "src/empty.rs", "--format", "json"])
        .output()
        .expect("run explicit deleted-empty-file diff");
    assert!(
        empty.status.success(),
        "published inventory, not node presence, proves the empty file was a baseline member: stdout={} stderr={}",
        String::from_utf8_lossy(&empty.stdout),
        String::from_utf8_lossy(&empty.stderr),
    );
    let empty_result = stdout_json(&empty);
    assert_eq!(empty_result["query"]["path"], "src/empty.rs");
    assert_eq!(empty_result["files_compared"], 1, "{empty_result}");
    assert_eq!(
        empty_result["files_with_symbol_changes"], 0,
        "{empty_result}"
    );
    assert_eq!(empty_result["changes_total"], 0, "{empty_result}");
    assert_eq!(
        empty_result["verdict"], "no_symbol_differences",
        "{empty_result}"
    );
}

#[test]
fn shipped_diff_applies_its_product_bound_before_mcp_transport() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"diff-result-bound-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    let source = |body: u32| {
        (0..100)
            .map(|index| {
                format!(
                    "pub fn symbol_{index:03}_{}() -> u32 {{ {body} }}\n",
                    "long_name_segment_".repeat(18)
                )
            })
            .collect::<String>()
    };
    std::fs::write(root.join("src/lib.rs"), source(1)).expect("original source");
    let data_dir = temporary.path().join("bundle");
    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish immutable generation");
    assert!(
        indexed.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );
    std::fs::write(root.join("src/lib.rs"), source(2)).expect("modify all symbols");

    let bounded = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "src/lib.rs", "--format", "json", "--limit", "1"])
        .output()
        .expect("run bounded positive control");
    assert!(
        bounded.status.success(),
        "small bounded result must succeed: {}",
        String::from_utf8_lossy(&bounded.stderr)
    );
    let bounded_result = stdout_json(&bounded);
    assert_eq!(bounded_result["changes_total"], 100, "{bounded_result}");
    assert_eq!(bounded_result["changes_returned"], 1, "{bounded_result}");
    assert_eq!(bounded_result["truncated"], true, "{bounded_result}");

    let oversized = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "src/lib.rs", "--format", "json", "--limit", "100"])
        .output()
        .expect("run oversized CLI diff");
    assert!(
        !oversized.status.success(),
        "oversized CLI result must fail"
    );
    assert!(
        String::from_utf8_lossy(&oversized.stderr).contains("28000-character product bound"),
        "CLI must expose the product-domain bound: {}",
        String::from_utf8_lossy(&oversized.stderr)
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_oversized = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "diff",
        json!({"path": "src/lib.rs", "limit": 100}),
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());
    assert_eq!(mcp_oversized["result"]["isError"], true, "{mcp_oversized}");
    assert_eq!(
        mcp_oversized["result"]["structuredContent"]["error"]["code"], "invalid_request",
        "the domain bound must fire before the generic MCP result cap: {mcp_oversized}"
    );
    assert!(
        mcp_oversized["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.contains("28000-character product bound")),
        "MCP refusal must expose the actionable product bound: {mcp_oversized}"
    );
}

#[test]
fn shipped_diff_compares_repeated_source_occurrences_without_collapsing_them() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"diff-duplicate-baseline-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "#[cfg(unix)]\npub fn platform_value() -> u32 { 1 }\n\n\
         #[cfg(windows)]\npub fn platform_value() -> u32 { 2 }\n",
    )
    .expect("duplicate-identity source");
    std::fs::write(
        root.join("src/unique.rs"),
        "pub fn unique_value() -> u32 { 1 }\n",
    )
    .expect("unique source");
    let data_dir = temporary.path().join("bundle");
    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish immutable generation");
    assert!(
        indexed.status.success(),
        "index failed: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );
    let binding = ProjectBinding::resolve(
        ProjectBindingOptions::new(&root)
            .explicit_root(&root)
            .global_graph_dir(&data_dir),
    )
    .expect("resolve published fixture binding");
    let generation = resolve_generation(binding.graph_dir(), binding.root())
        .expect("resolve repeated-occurrence generation");
    let structural = generation
        .manifest
        .receipts
        .iter()
        .find(|receipt| receipt.capability_id == "structural_graph")
        .expect("structural receipt");
    assert_eq!(
        structural.status,
        CapabilityStatus::Complete,
        "a graph that retains every repeated source occurrence has complete structural authority: {structural:?}"
    );
    assert_eq!(structural.reason_code, None, "{structural:?}");

    let repeated_find = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["find", "platform_value", "--format", "json"])
        .output()
        .expect("query Find across repeated source occurrences");
    assert!(
        repeated_find.status.success(),
        "both source occurrences must remain findable: stdout={} stderr={}",
        String::from_utf8_lossy(&repeated_find.stdout),
        String::from_utf8_lossy(&repeated_find.stderr),
    );
    let repeated_find = stdout_json(&repeated_find);
    assert_eq!(repeated_find["page"]["returned"], 2);
    assert_eq!(repeated_find["authority"]["status"], "complete");
    assert_eq!(
        repeated_find["authority"]["structural_graph"]["status"],
        "complete"
    );
    assert_eq!(repeated_find["authority"]["population_complete"], true);

    std::fs::write(
        root.join("src/unique.rs"),
        "pub fn unique_value() -> u32 { 2 }\n",
    )
    .expect("modify unique source");
    let unique = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "src/unique.rs", "--format", "json"])
        .output()
        .expect("run unique diff positive control");
    assert!(
        unique.status.success(),
        "a uniquely identified symbol must remain diffable: {}",
        String::from_utf8_lossy(&unique.stderr)
    );
    assert_eq!(stdout_json(&unique)["total_modified"], 1);

    std::fs::write(
        root.join("src/unique.rs"),
        "#[cfg(unix)]\npub fn unique_value() -> u32 { 2 }\n\n\
         #[cfg(windows)]\npub fn unique_value() -> u32 { 3 }\n",
    )
    .expect("introduce duplicate live identities");
    let repeated_candidate = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "src/unique.rs", "--format", "json"])
        .output()
        .expect("run repeated-candidate diff");
    assert!(
        repeated_candidate.status.success(),
        "a live repeated occurrence population must be compared, not excluded: stdout={} stderr={}",
        String::from_utf8_lossy(&repeated_candidate.stdout),
        String::from_utf8_lossy(&repeated_candidate.stderr),
    );
    let repeated_candidate_result = stdout_json(&repeated_candidate);
    assert_eq!(
        repeated_candidate_result["verdict"],
        "symbol_differences_observed"
    );
    assert_eq!(repeated_candidate_result["files_considered"], 1);
    assert_eq!(repeated_candidate_result["files_compared"], 1);
    assert_eq!(repeated_candidate_result["files_excluded"], 0);
    assert_eq!(repeated_candidate_result["total_modified"], 1);
    assert_eq!(repeated_candidate_result["total_added"], 1);

    let unchanged_repeated = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "src/lib.rs", "--format", "json"])
        .output()
        .expect("run repeated-baseline diff");
    assert!(
        unchanged_repeated.status.success(),
        "an unchanged repeated baseline must compare cleanly: stdout={} stderr={}",
        String::from_utf8_lossy(&unchanged_repeated.stdout),
        String::from_utf8_lossy(&unchanged_repeated.stderr),
    );
    let unchanged_repeated_result = stdout_json(&unchanged_repeated);
    assert_eq!(unchanged_repeated_result["authority"]["status"], "complete");
    assert_eq!(
        unchanged_repeated_result["verdict"],
        "no_symbol_differences"
    );
    assert_eq!(unchanged_repeated_result["files_considered"], 1);
    assert_eq!(unchanged_repeated_result["files_compared"], 1);
    assert_eq!(unchanged_repeated_result["files_excluded"], 0);

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_unchanged = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "diff",
        json!({"path": "src/lib.rs"}),
    );
    assert_eq!(
        mcp_unchanged["result"]["structuredContent"], unchanged_repeated_result,
        "CLI and MCP must expose the same complete repeated-baseline result: {mcp_unchanged}"
    );
    let mcp_repeated_candidate = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "diff",
        json!({"path": "src/unique.rs"}),
    );
    assert_eq!(
        mcp_repeated_candidate["result"]["structuredContent"], repeated_candidate_result,
        "CLI and MCP must share the repeated live-candidate comparison: {mcp_repeated_candidate}"
    );
    let mcp_find = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "find",
        json!({"query": "platform_value"}),
    );
    assert_eq!(
        repeated_find["repository"]["live_inputs"]["freshness"],
        "fresh"
    );
    assert_eq!(
        mcp_find["result"]["structuredContent"]["repository"]["live_inputs"]["freshness"], "stale",
        "MCP runs after the deliberate unrelated source edit: {mcp_find}"
    );
    assert_eq!(
        without_live_input_observation(mcp_find["result"]["structuredContent"].clone()),
        without_live_input_observation(repeated_find),
        "CLI and MCP must share the same immutable repeated-occurrence Find payload across the explicit fresh-to-stale transition: {mcp_find}"
    );
    let stopped = stop_mcp(child, stdin);
    assert!(stopped.status.success());

    std::fs::write(
        root.join("src/unique.rs"),
        "pub fn unique_value() -> u32 { 2 }\n",
    )
    .expect("restore a uniquely representable live candidate");
    let workspace = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["diff", "--format", "json"])
        .output()
        .expect("run qualified repository diff");
    assert!(
        workspace.status.success(),
        "repeated occurrences must not suppress truthful workspace differences: stdout={} stderr={}",
        String::from_utf8_lossy(&workspace.stdout),
        String::from_utf8_lossy(&workspace.stderr),
    );
    let workspace_result = stdout_json(&workspace);
    assert_eq!(workspace_result["verdict"], "symbol_differences_observed");
    assert_eq!(workspace_result["total_modified"], 1);
    assert_eq!(workspace_result["files_considered"], 2);
    assert_eq!(workspace_result["files_compared"], 2);
    assert_eq!(workspace_result["files_excluded"], 0);
    assert_eq!(workspace_result["files"][0]["file_path"], "src/unique.rs");
}

#[tokio::test]
async fn shipped_audit_scopes_page_and_match_across_cli_and_mcp() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "audit-scope-repo",
        "pub fn target() {}\n\
         pub fn target_two() {}\n\
         pub fn production_one() { target(); }\n\
         pub fn production_two() { target_two(); }\n\
         fn test_one() { target(); }\n\
         fn test_two() { target_two(); }\n",
    );
    let data_dir = temporary.path().join("bundle");
    seed_audit_scope_bundle(
        &root,
        &data_dir,
        &[
            CallsFixtureEdge {
                caller: "production_one",
                callee: "target",
                is_test_only: false,
                is_test_root: false,
            },
            CallsFixtureEdge {
                caller: "production_two",
                callee: "target_two",
                is_test_only: false,
                is_test_root: false,
            },
            CallsFixtureEdge {
                caller: "test_one",
                callee: "target",
                is_test_only: true,
                is_test_root: true,
            },
            CallsFixtureEdge {
                caller: "test_two",
                callee: "target_two",
                is_test_only: true,
                is_test_root: true,
            },
        ],
    )
    .await;

    let run_audit = |args: &[&str]| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("audit")
            .args(args)
            .args(["--format", "json"])
            .output()
            .expect("run shipped Audit")
    };

    let production = run_audit(&["--min-fan-in", "1", "--limit", "1"]);
    assert!(
        production.status.success(),
        "production Audit must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&production.stdout),
        String::from_utf8_lossy(&production.stderr),
    );
    let production = stdout_json(&production);
    assert_eq!(production["query"]["scope"], "production");
    assert_eq!(production["dead_code"]["status"], "complete");
    assert_eq!(production["dead_code"]["authoritative_project_units"], 1);
    assert_eq!(production["dead_code"]["withheld_project_units"], 0);
    assert_eq!(production["page"]["total_items"], 2, "{production}");
    assert_eq!(production["page"]["returned"], 1);
    assert_eq!(production["page"]["has_more"], true);
    assert_eq!(production["hotspots"][0]["selected_fan_in"], 1);
    assert_eq!(production["hotspots"][0]["language_id"], "rust");
    assert!(
        production["unit_graph"]["memberships"]
            .as_array()
            .is_some_and(|memberships| !memberships.is_empty()),
        "the paged hotspot must retain its persisted monorepo ownership context: {production}"
    );
    assert_eq!(
        production["hotspots"][0]["fan_in"]["production"]["provider_calls"],
        1
    );
    assert_eq!(
        production["hotspots"][0]["fan_in"]["tests"]["provider_calls"], 1,
        "test Calls remain visible but do not inflate the production ranking"
    );
    assert!(
        serde_json::to_string(&production)
            .expect("serialize Audit page")
            .chars()
            .count()
            <= h00ligan_engine::code_intel_audit::MAX_AUDIT_RESULT_CHARS
    );

    let human = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["audit", "--min-fan-in", "1", "--limit", "1"])
        .output()
        .expect("run human Audit");
    assert!(
        human.status.success(),
        "human Audit must succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&human.stdout),
        String::from_utf8_lossy(&human.stderr),
    );
    let human = String::from_utf8_lossy(&human.stdout);
    for expected in [
        "QUALITY AUDIT",
        "UNREACHED CALLABLES: 0",
        "COUPLING HOTSPOTS — production scope",
        "function, rust, src/lib.rs",
        "provider calls 1, structural call hints 0, field uses 0",
        "scopes: production 1, conditional 0, tests 1",
        "Next cursor:",
    ] {
        assert!(
            human.contains(expected),
            "human Audit must explain the shared machine result using '{expected}': {human}"
        );
    }

    let all = run_audit(&["--scope", "all", "--min-fan-in", "2", "--limit", "1"]);
    assert!(all.status.success());
    let all = stdout_json(&all);
    assert_eq!(all["query"]["scope"], "all");
    assert_eq!(all["hotspots"][0]["selected_fan_in"], 2);

    let cursor = production["page"]["next_cursor"]
        .as_str()
        .expect("production page continuation");
    let continuation = run_audit(&["--min-fan-in", "1", "--limit", "1", "--cursor", cursor]);
    assert!(continuation.status.success());
    let continuation = stdout_json(&continuation);
    assert_eq!(continuation["page"]["offset"], 1);
    assert_ne!(
        continuation["hotspots"][0]["symbol_id"], production["hotspots"][0]["symbol_id"],
        "the continuation must return the second deterministic hotspot"
    );

    let cross_scope = run_audit(&[
        "--scope",
        "all",
        "--min-fan-in",
        "1",
        "--limit",
        "1",
        "--cursor",
        cursor,
    ]);
    assert!(
        !cross_scope.status.success(),
        "a production cursor must fail closed under a different scope"
    );
    let cross_scope = stdout_json(&cross_scope);
    assert_eq!(cross_scope["error"]["code"], "invalid_cursor");

    let invalid = run_audit(&["--min-fan-in", "0"]);
    assert!(
        !invalid.status.success(),
        "an invalid CLI Audit request must fail closed"
    );
    let invalid = stdout_json(&invalid);
    assert_eq!(invalid["error"]["code"], "invalid_request");
    assert_eq!(invalid["error"]["operation"], "audit");
    assert_eq!(invalid["error"]["field"], "min_fan_in");

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_production = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "audit",
        json!({"min_fan_in": 1, "limit": 1}),
    );
    let mcp_all = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "audit",
        json!({"scope": "all", "min_fan_in": 2, "limit": 1}),
    );
    let mcp_cross_scope = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "audit",
        json!({"scope": "all", "min_fan_in": 1, "limit": 1, "cursor": cursor}),
    );
    let mcp_invalid = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "audit",
        json!({"min_fan_in": 0}),
    );
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP Audit process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        without_ephemeral_cursor_lease(mcp_production["result"]["structuredContent"].clone()),
        without_ephemeral_cursor_lease(production),
        "CLI JSON and MCP must expose the same production-scoped Audit DTO"
    );
    assert_eq!(
        without_ephemeral_cursor_lease(mcp_all["result"]["structuredContent"].clone()),
        without_ephemeral_cursor_lease(all),
        "CLI JSON and MCP must expose the same all-scope Audit DTO"
    );
    assert_eq!(mcp_cross_scope["result"]["isError"], true);
    assert_eq!(
        mcp_cross_scope["result"]["structuredContent"], cross_scope,
        "semantic cursor failures must share one typed CLI/MCP domain envelope"
    );
    assert_eq!(
        mcp_invalid["error"]["code"], -32602,
        "MCP schema validation rejects invalid numeric bounds before handler execution"
    );
    assert!(
        mcp_invalid["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("min_fan_in")),
        "the transport refusal must identify the invalid field: {mcp_invalid}"
    );
}

#[tokio::test]
async fn overview_and_audit_do_not_splice_live_topology_or_dry_evidence() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("crates/indexed/src"))
        .expect("indexed package source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/indexed\"]\nresolver = \"3\"\n",
    )
    .expect("workspace manifest");
    std::fs::write(
        root.join("crates/indexed/Cargo.toml"),
        "[package]\nname = \"indexed\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("indexed package manifest");
    std::fs::write(
        root.join("crates/indexed/src/lib.rs"),
        "pub fn published_unit() -> usize { 42 }\n",
    )
    .expect("indexed package source");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish immutable generation");
    assert!(
        indexed.status.success(),
        "positive control: indexing must publish; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    let published = resolve_generation(&data_dir, &root).expect("published generation");
    assert!(
        published
            .project_inventory
            .project_topology
            .units
            .iter()
            .any(|unit| unit.root_path == "crates/indexed"),
        "positive control: the immutable inventory must contain the indexed package"
    );

    std::fs::create_dir_all(root.join("crates/live_only/src"))
        .expect("live-only package source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/indexed\", \"crates/live_only\"]\nresolver = \"3\"\n",
    )
    .expect("mutated workspace manifest");
    std::fs::write(
        root.join("crates/live_only/Cargo.toml"),
        "[package]\nname = \"live_only\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("live-only package manifest");
    std::fs::write(
        root.join("crates/live_only/src/lib.rs"),
        "pub fn clone_one(value: i32) -> i32 {\n\
         let a = value + 1;\n\
         let b = a * 2;\n\
         let c = b - 3;\n\
         let d = c + 4;\n\
         d\n\
         }\n\
         pub fn clone_two(value: i32) -> i32 {\n\
         let a = value + 1;\n\
         let b = a * 2;\n\
         let c = b - 3;\n\
         let d = c + 4;\n\
         d\n\
         }\n",
    )
    .expect("live-only clone source");

    let live_inventory = h00ligan_engine::code_intel_inventory::build_project_inventory(
        &root,
        &[
            h00ligan_engine::code_intel_inventory::InventorySource::new(
                "crates/indexed/src/lib.rs",
                "rust",
            ),
            h00ligan_engine::code_intel_inventory::InventorySource::new(
                "crates/live_only/src/lib.rs",
                "rust",
            ),
        ],
    );
    assert!(
        live_inventory
            .project_topology
            .units
            .iter()
            .any(|unit| unit.root_path == "crates/live_only"),
        "positive control: production inventory discovery must observe the post-publication package"
    );
    let live_dry = h00ligan_engine::dry_detection::detect_clones(&root, 5)
        .expect("positive-control live clone detection");
    assert!(
        live_dry.total_clone_groups > 0,
        "positive control: live clone detection must observe post-publication evidence"
    );

    let run = |command: &str| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args([command, "--format", "json"])
            .output()
            .unwrap_or_else(|error| panic!("run {command}: {error}"))
    };
    let overview = run("overview");
    assert!(
        overview.status.success(),
        "overview must read the immutable generation; stdout={} stderr={}",
        String::from_utf8_lossy(&overview.stdout),
        String::from_utf8_lossy(&overview.stderr),
    );
    let overview_json = stdout_json(&overview);
    let units = overview_json
        .get("project_units")
        .cloned()
        .unwrap_or(Value::Null);
    assert!(
        units.is_array(),
        "overview must expose the persisted polyglot project-unit contract: {overview_json}"
    );
    assert!(
        !units.to_string().contains("live_only"),
        "overview must not splice live-only topology into a pinned generation: {overview_json}"
    );
    assert!(
        overview_json.get("dry").is_none(),
        "overview must not attach live clone evidence to an immutable answer: {overview_json}"
    );

    let audit = run("audit");
    assert!(
        audit.status.success(),
        "audit must read the immutable generation; stdout={} stderr={}",
        String::from_utf8_lossy(&audit.stdout),
        String::from_utf8_lossy(&audit.stderr),
    );
    let audit_json = stdout_json(&audit);
    assert!(
        audit_json.get("dry").is_none(),
        "audit must not attach live clone evidence to an immutable answer: {audit_json}"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_overview = call_mcp(&mut stdin, &mut stdout, 1, "overview", json!({}));
    let mcp_audit = call_mcp(&mut stdin, &mut stdout, 2, "audit", json!({}));
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP immutable-query control must exit cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let structured_overview = mcp_overview["result"]["structuredContent"].clone();
    let structured_audit = mcp_audit["result"]["structuredContent"].clone();
    assert_eq!(
        mcp_text_payload(&mcp_overview),
        structured_overview,
        "MCP overview text fallback and native structuredContent must share one DTO"
    );
    assert_eq!(
        mcp_text_payload(&mcp_audit),
        structured_audit,
        "MCP audit text fallback and native structuredContent must share one DTO"
    );
    assert_eq!(
        overview_json, structured_overview,
        "CLI JSON and MCP overview must expose the same immutable project-unit DTO"
    );
    assert_eq!(
        audit_json, structured_audit,
        "CLI JSON and MCP audit must expose the same immutable DTO"
    );
    assert_eq!(
        resolve_generation(&data_dir, &root)
            .expect("same immutable generation")
            .manifest
            .generation_id,
        published.manifest.generation_id,
        "the query fixture must not publish a replacement generation"
    );
}

#[tokio::test]
async fn unavailable_reachability_evidence_does_not_revoke_structural_type() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", "pub struct PublishedType;\n");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"reachability_evidence_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");

    for (label, invalid_document) in [("missing", false), ("invalid", true)] {
        let data_dir = temporary.path().join(format!("bundle-{label}"));
        publish_graph_with_unavailable_reachability(&root, &data_dir, invalid_document).await;

        let type_result = h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["type", "PublishedType", "--format", "json"])
            .output()
            .expect("run independent structural query");
        assert!(
            type_result.status.success(),
            "{label}: unavailable reachability evidence must not revoke Type; stdout={} stderr={}",
            String::from_utf8_lossy(&type_result.stdout),
            String::from_utf8_lossy(&type_result.stderr),
        );
        assert_eq!(
            stdout_json(&type_result)["resolved_type"]["name"],
            "PublishedType",
            "{label}: positive control must resolve the published structural type"
        );

        let dead = h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["dead", "PublishedType", "--format", "json"])
            .output()
            .expect("run reachability-dependent Dead query");
        assert!(
            !dead.status.success(),
            "{label}: Dead must fail closed without validated generation-local reachability evidence"
        );
        let dead = stdout_json(&dead);
        assert_eq!(dead["error"]["code"], "capability_unavailable");
        assert_eq!(dead["error"]["capability"], "dead");
        assert_eq!(
            dead["error"]["evidence"][0]["reason_code"],
            "reachability_evidence_unavailable"
        );

        let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
        let mcp = call_mcp(
            &mut stdin,
            &mut stdout,
            1,
            "dead_code",
            json!({"symbol": "PublishedType"}),
        );
        assert_eq!(mcp["result"]["isError"], true);
        assert_eq!(mcp["result"]["structuredContent"], dead);
        let stopped = stop_mcp(child, stdin);
        assert!(stopped.status.success());
    }
}

#[tokio::test]
async fn composite_queries_use_metadata_from_the_same_immutable_generation() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        "pub fn published_symbol() -> usize { 42 }\n",
    );
    let data_dir = temporary.path().join("bundle");
    publish_metadata_authority_fixture(&root, &data_dir).await;

    // The conflicting obsolete bundle is real and readable. This proves the
    // test would catch the former second-open behavior rather than passing
    // because the legacy fixture was absent or malformed.
    let legacy_database = redb::ReadOnlyDatabase::open(data_dir.join("graph.redb"))
        .expect("open conflicting legacy graph read-only");
    let read = legacy_database.begin_read().expect("legacy metadata read");
    let metadata = read
        .open_table(TableDefinition::<&str, u64>::new("graph_meta"))
        .expect("legacy metadata table");
    assert_eq!(
        metadata
            .get("scip_ran_ok")
            .expect("obsolete aggregate metadata")
            .map(|value| value.value()),
        Some(0),
        "positive control: the obsolete root artifact really contains the retired key"
    );
    drop(metadata);
    drop(read);
    let legacy_store = GraphStore::new_read_only(Arc::new(legacy_database));
    let legacy_metadata = legacy_store
        .generation_metadata()
        .await
        .expect("obsolete bundle metadata");
    assert!(legacy_metadata.oracle_ran_ok);
    drop(legacy_store);

    let binding = ProjectBinding::resolve(
        ProjectBindingOptions::new(&root)
            .explicit_root(&root)
            .global_graph_dir(&data_dir),
    )
    .expect("project binding");
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(&binding)
        .await
        .expect("load immutable generation");
    assert!(
        snapshot.semantic_generation.is_some(),
        "positive control: the selected authority must be immutable"
    );
    assert!(snapshot.calls_coverage().any_callable_language_complete());
    assert_eq!(snapshot.oracle_ran_ok(), Some(false));
    let immutable_generation_id = snapshot
        .immutable_generation()
        .expect("immutable generation authority")
        .manifest
        .generation_id
        .0
        .clone();

    let run = |args: &[&str]| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(args)
            .output()
            .expect("run shipped composite query")
    };

    let status = run(&["status", "--format", "json"]);
    assert!(
        status.status.success(),
        "status must load the immutable generation: stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
    );
    let status_json = stdout_json(&status);
    assert_eq!(status_json["schema_version"], "h00/code-intel/status/v3");
    assert_eq!(status_json["capabilities"]["calls"]["status"], "complete");
    assert!(
        status_json.get("envelope").is_none(),
        "status must not resurrect retired repository-shape authority"
    );
    assert_eq!(status_json["stats"]["node_count"], 1);

    let dead = run(&["dead", "published_symbol", "--format", "json"]);
    assert!(
        dead.status.success(),
        "dead must load the immutable generation: stdout={} stderr={}",
        String::from_utf8_lossy(&dead.stdout),
        String::from_utf8_lossy(&dead.stderr),
    );
    let dead_json = stdout_json(&dead);
    assert_eq!(dead_json["schema_version"], "h00/code-intel/dead/v1");
    assert_eq!(dead_json["generation_id"], immutable_generation_id);
    assert_eq!(dead_json["authority"]["calls"]["status"], "complete");
    assert_eq!(
        dead_json["authority"]["project_inventory_coverage"],
        "indexed_source_population_complete"
    );
    assert_eq!(dead_json["items"][0]["verdict"], "live_production");
    assert_eq!(dead_json["items"][0]["reachable_from_retained_root"], true);
    assert_eq!(dead_json["items"][0]["recommendation"], "keep");
    assert_eq!(dead_json["items"][0]["evidence"]["status"], "complete");
    for retired_field in ["coverage", "oracle", "freshness", "envelope"] {
        assert!(
            dead_json.get(retired_field).is_none(),
            "Dead must not splice legacy aggregate metadata into its generation-local contract: {dead_json}"
        );
    }

    let overview = run(&["overview", "--format", "json"]);
    assert!(
        overview.status.success(),
        "overview must load the immutable generation: stdout={} stderr={}",
        String::from_utf8_lossy(&overview.stdout),
        String::from_utf8_lossy(&overview.stderr),
    );
    let overview_json = stdout_json(&overview);
    assert_eq!(
        overview_json["schema_version"],
        "h00/code-intel/overview/v3"
    );
    assert_eq!(overview_json["dead_code_count"], 0);
    assert_eq!(overview_json["health_status"], "complete");
    assert!(
        overview_json.get("envelope").is_none(),
        "overview must not resurrect retired repository-shape authority"
    );
    assert_eq!(overview_json["health_action_needed"], false);
    assert!(
        overview_json.get("health_guidance").is_none(),
        "complete immutable SCIP authority must not be downgraded by the root bundle"
    );
}

#[tokio::test]
async fn mixed_language_receipts_partition_cli_and_mcp_dead_code_authority() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", "fn rust_dead() -> usize { 42 }\n");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"mixed_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Rust package manifest");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/mixed\n\ngo 1.25\n",
    )
    .expect("Go module");
    std::fs::write(root.join("main.go"), "package mixed\n\nfunc go_dead() {}\n")
        .expect("Go source");
    let data_dir = temporary.path().join("bundle");
    publish_mixed_calls_authority_fixture(&root, &data_dir).await;

    let run = |args: &[&str]| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(args)
            .output()
            .expect("run shipped mixed-language query")
    };

    let find_help = run(&["find", "--help"]);
    assert!(find_help.status.success());
    let find_help = String::from_utf8_lossy(&find_help.stdout);
    assert!(
        find_help.contains("--kind"),
        "known-positive find option proves the shipped help population is present"
    );
    assert!(
        !find_help.contains("--include-dead"),
        "structural find must not expose a liveness-dependent symbol-hiding mode"
    );

    let status = run(&["status", "--format", "json"]);
    assert!(
        status.status.success(),
        "CLI status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr),
    );
    let status_json = stdout_json(&status);
    assert_eq!(status_json["availability"], "available");
    assert_eq!(
        status_json["freshness"], "fresh",
        "partial Calls coverage must not relabel exact source freshness: {status_json}"
    );
    assert_eq!(status_json["action_needed"], true);
    assert_eq!(status_json["capabilities"]["calls"]["status"], "partial");
    assert!(
        status_json.get("coverage").is_none(),
        "status must report receipt-backed capability coverage, not a competing aggregate tier"
    );
    assert_eq!(calls_language(&status_json, "rust")["status"], "complete");
    let cli_go = calls_language(&status_json, "go");
    assert_eq!(cli_go["status"], "unavailable");
    assert_eq!(cli_go["gaps"][0]["reason_code"], "provider_not_installed");

    let dead = run(&["dead", "--format", "json"]);
    assert!(
        dead.status.success(),
        "CLI dead failed: stdout={} stderr={}",
        String::from_utf8_lossy(&dead.stdout),
        String::from_utf8_lossy(&dead.stderr),
    );
    let dead_json = stdout_json(&dead);
    assert_eq!(dead_json["schema_version"], "h00/code-intel/dead/v1");
    assert_eq!(dead_json["authority"]["status"], "qualified");
    assert_eq!(dead_json["authority"]["calls"]["status"], "partial");
    assert_eq!(dead_language(&dead_json, "rust")["status"], "complete");
    assert_eq!(dead_language(&dead_json, "go")["status"], "unavailable");
    assert_eq!(dead_json["summary"]["observed_items"], 2);
    assert_eq!(dead_json["summary"]["candidate_items"], 2);
    assert_eq!(dead_json["summary"]["unreached_callables"], 1);
    assert_eq!(dead_json["summary"]["unknown_candidates"], 1);
    let rust_dead = dead_item(&dead_json, "rust_dead");
    assert_eq!(rust_dead["verdict"], "unreached_callable");
    assert_eq!(rust_dead["reachable_from_retained_root"], false);
    assert_eq!(rust_dead["recommendation"], "review");
    let go_dead = dead_item(&dead_json, "go_dead");
    assert_eq!(go_dead["verdict"], "unknown");
    assert!(go_dead["reachable_from_retained_root"].is_null());
    assert_eq!(go_dead["recommendation"], "withheld");

    let go_single = run(&["dead", "go_dead", "--format", "json"]);
    assert!(go_single.status.success());
    let go_single_json = stdout_json(&go_single);
    assert_eq!(go_single_json["items"][0]["verdict"], "unknown");
    assert!(go_single_json["items"][0]["reachable_from_retained_root"].is_null());
    assert_eq!(
        dead_calls_language(&go_single_json, "go")["gaps"][0]["reason_code"],
        "provider_not_installed"
    );

    let rust_single = run(&["dead", "rust_dead", "--format", "json"]);
    assert!(rust_single.status.success());
    let rust_single_json = stdout_json(&rust_single);
    assert_eq!(
        rust_single_json["items"][0]["verdict"],
        "unreached_callable"
    );
    assert_eq!(
        rust_single_json["items"][0]["reachable_from_retained_root"],
        false
    );

    let rust_find = run(&["find", "rust_dead", "--format", "json"]);
    assert!(rust_find.status.success());
    let rust_find_json = stdout_json(&rust_find);
    assert_eq!(rust_find_json["page"]["returned"], 1);
    assert_eq!(rust_find_json["page"]["has_more"], false);
    assert!(rust_find_json["items"][0].get("reachability").is_none());
    assert!(rust_find_json.get("capabilities").is_none());

    let go_find = run(&["find", "go_dead", "--format", "json"]);
    assert!(go_find.status.success());
    let go_find_json = stdout_json(&go_find);
    assert_eq!(
        go_find_json["page"]["returned"], 1,
        "structural find must not hide a symbol behind unauthoritative liveness"
    );
    assert!(go_find_json["items"][0].get("reachability").is_none());
    assert!(go_find_json.get("capabilities").is_none());

    let overview = run(&["overview", "--format", "json"]);
    assert!(
        overview.status.success(),
        "CLI overview failed: stdout={} stderr={}",
        String::from_utf8_lossy(&overview.stdout),
        String::from_utf8_lossy(&overview.stderr),
    );
    let overview_json = stdout_json(&overview);
    assert_eq!(overview_json["health_status"], "partial");
    assert!(overview_json["dead_code_count"].is_null());
    let overview_units = overview_json["project_units"]
        .as_array()
        .expect("mixed overview project units");
    let rust_unit = overview_units
        .iter()
        .find(|unit| unit["language_id"] == "rust")
        .expect("Rust project unit");
    let go_unit = overview_units
        .iter()
        .find(|unit| unit["language_id"] == "go")
        .expect("Go project unit");
    assert_eq!(
        rust_unit["health"]["dead"], 1,
        "complete Rust Calls authority must retain the Rust-local health slice"
    );
    assert!(
        go_unit["health"].is_null(),
        "uncovered Go Calls authority must not poison or fabricate the Rust-local slice"
    );

    let audit = run(&["audit", "--min-dead-ratio-percent", "1", "--format", "json"]);
    assert!(
        audit.status.success(),
        "CLI audit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&audit.stdout),
        String::from_utf8_lossy(&audit.stderr),
    );
    let audit_json = stdout_json(&audit);
    assert_eq!(audit_json["dead_code"]["status"], "partial");
    assert!(audit_json["dead_code"]["total"].is_null());
    assert!(
        audit_json["dead_code"]["authoritative_project_units"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );
    assert!(
        audit_json["dead_code"]["withheld_project_units"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );
    let project_unit_authority = audit_json["dead_code"]["project_unit_authority"]
        .as_array()
        .expect("Audit partial health must reconcile project-unit authority by language");
    let rust_authority = project_unit_authority
        .iter()
        .find(|row| row["language_id"] == "rust")
        .expect("Rust dead-code authority row");
    assert_eq!(rust_authority["status"], "complete");
    assert_eq!(rust_authority["authoritative_project_units"], 1);
    assert_eq!(rust_authority["withheld_project_units"], 0);
    let go_authority = project_unit_authority
        .iter()
        .find(|row| row["language_id"] == "go")
        .expect("Go dead-code authority row");
    assert_eq!(go_authority["status"], "unavailable");
    assert_eq!(go_authority["authoritative_project_units"], 0);
    assert_eq!(go_authority["withheld_project_units"], 1);
    assert_eq!(
        project_unit_authority
            .iter()
            .filter_map(|row| row["authoritative_project_units"].as_u64())
            .sum::<u64>(),
        audit_json["dead_code"]["authoritative_project_units"]
            .as_u64()
            .expect("aggregate authoritative project-unit count"),
        "per-language authoritative counts must reconcile exactly"
    );
    assert_eq!(
        project_unit_authority
            .iter()
            .filter_map(|row| row["withheld_project_units"].as_u64())
            .sum::<u64>(),
        audit_json["dead_code"]["withheld_project_units"]
            .as_u64()
            .expect("aggregate withheld project-unit count"),
        "per-language withheld counts must reconcile exactly"
    );
    assert!(
        audit_json["dead_code"]["high_ratio_project_units"]
            .as_array()
            .is_some_and(|units| units.iter().any(|unit| unit["language_id"] == "rust")),
        "complete Rust authority must retain its unit-local dead-code audit: {audit_json}"
    );
    let audit_human = run(&["audit", "--min-dead-ratio-percent", "1"]);
    assert!(audit_human.status.success());
    let audit_human = String::from_utf8_lossy(&audit_human.stdout);
    assert!(
        audit_human.contains("rust: complete — 1 authoritative, 0 withheld"),
        "human Audit must identify the retained Rust population: {audit_human}"
    );
    assert!(
        audit_human.contains("go: unavailable — 0 authoritative, 1 withheld"),
        "human Audit must identify the withheld Go population: {audit_human}"
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp_status = call_mcp(&mut stdin, &mut stdout, 1, "status", json!({}));
    let mcp_dead = call_mcp(&mut stdin, &mut stdout, 2, "dead_code", json!({}));
    let mcp_go = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "dead_code",
        json!({"symbol": "go_dead"}),
    );
    let mcp_rust_find = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "find",
        json!({"query": "rust_dead"}),
    );
    let mcp_go_find = call_mcp(
        &mut stdin,
        &mut stdout,
        5,
        "find",
        json!({"query": "go_dead"}),
    );
    let mcp_obsolete_find_option = call_mcp(
        &mut stdin,
        &mut stdout,
        6,
        "find",
        json!({"query": "go_dead", "include_dead": true}),
    );
    let mcp_overview = call_mcp(&mut stdin, &mut stdout, 7, "overview", json!({}));
    let mcp_audit = call_mcp(
        &mut stdin,
        &mut stdout,
        8,
        "audit",
        json!({"min_dead_ratio_percent": 1}),
    );
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let mcp_status = &mcp_status["result"]["structuredContent"];
    assert_eq!(mcp_status["availability"], "available");
    assert_eq!(mcp_status["freshness"], "fresh");
    assert_eq!(mcp_status["capabilities"]["calls"]["status"], "partial");
    assert!(mcp_status.get("coverage").is_none());
    assert_eq!(
        calls_language(mcp_status, "go")["gaps"][0]["reason_code"],
        "provider_not_installed"
    );
    let mcp_dead = &mcp_dead["result"]["structuredContent"];
    assert_eq!(mcp_dead, &dead_json);
    assert_eq!(
        overview_json, mcp_overview["result"]["structuredContent"],
        "mixed-language Overview authority must be identical across CLI and MCP"
    );
    assert_eq!(
        audit_json, mcp_audit["result"]["structuredContent"],
        "mixed-language Audit authority must be identical across CLI and MCP"
    );
    let mcp_go = &mcp_go["result"]["structuredContent"];
    assert_eq!(mcp_go, &go_single_json);
    let mcp_rust_find = &mcp_rust_find["result"]["structuredContent"];
    assert_eq!(mcp_rust_find["page"]["returned"], 1);
    assert_eq!(mcp_rust_find["page"]["has_more"], false);
    assert!(mcp_rust_find["items"][0].get("reachability").is_none());
    assert!(mcp_rust_find.get("capabilities").is_none());
    let mcp_go_find = &mcp_go_find["result"]["structuredContent"];
    assert_eq!(mcp_go_find["page"]["returned"], 1);
    assert!(mcp_go_find["items"][0].get("reachability").is_none());
    assert!(mcp_go_find.get("capabilities").is_none());
    assert_eq!(mcp_obsolete_find_option["error"]["code"], -32602);
    assert!(
        mcp_obsolete_find_option["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("unadvertised property 'include_dead'"))
    );
}

#[tokio::test]
async fn shipped_cli_and_mcp_require_explicit_publication_recovery() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        "pub fn caller() { target(); }\npub fn target() {}\n",
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"recovery_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    seed_calls_bundle(&root, &data_dir, &["caller"]).await;
    let publication = data_dir.join(h00ligan_engine::code_intel_publication::PUBLICATION_DIRECTORY);
    for slot in 0..2 {
        std::fs::write(
            publication.join(format!("head-{slot}.json")),
            format!("invalid-head-{slot}"),
        )
        .expect("invalid head fixture");
    }
    let before_strict = file_population(&data_dir);

    let strict = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--format", "json"])
        .output()
        .expect("strict shipped index");
    assert!(
        !strict.status.success(),
        "strict indexing must refuse invalid publication controls"
    );
    assert!(
        String::from_utf8_lossy(&strict.stderr).contains("no valid head"),
        "strict refusal must identify the intended control failure: {}",
        String::from_utf8_lossy(&strict.stderr)
    );
    assert_eq!(
        file_population(&data_dir),
        before_strict,
        "strict admission must fail before staging, repair, or rebinding"
    );

    let recovered = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--recover-publication", "--format", "json"])
        .output()
        .expect("explicit shipped recovery");
    assert!(
        recovered.status.success(),
        "explicit CLI recovery failed: stdout={} stderr={}",
        String::from_utf8_lossy(&recovered.stdout),
        String::from_utf8_lossy(&recovered.stderr),
    );
    let recovered_generation =
        resolve_generation(&data_dir, &root).expect("CLI-recovered generation");
    assert_eq!(
        stdout_json(&recovered)["generation_id"],
        recovered_generation.manifest.generation_id.0
    );

    let repository_path = publication.join("repository.json");
    std::fs::remove_file(&repository_path).expect("missing identity fixture");
    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let refused = call_mcp_reindex_terminal(&mut stdin, &mut stdout, 1, json!({}));
    assert_eq!(refused["state"], "failed", "{refused}");
    assert!(
        !repository_path.exists(),
        "ordinary MCP reindex must not fabricate a missing identity"
    );
    let repaired = call_mcp_reindex_terminal(
        &mut stdin,
        &mut stdout,
        2,
        json!({"recover_publication": true}),
    );
    assert_eq!(repaired["state"], "succeeded", "{repaired}");
    assert_eq!(repaired["result"]["publication_recovery_requested"], true);
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP recovery process failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    resolve_generation(&data_dir, &root).expect("MCP-recovered generation");
}

#[cfg(unix)]
#[test]
fn managed_index_refuses_a_tracked_publication_directory_before_mutation() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", "pub fn structural_only() {}\n");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"managed_hygiene_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    let graph = root.join(".h00ligan/code-intel");
    let publication = graph.join(h00ligan_engine::code_intel_publication::PUBLICATION_DIRECTORY);
    std::fs::create_dir_all(&publication).expect("managed publication fixture");
    std::fs::write(graph.join(".gitignore"), "*\n!.gitignore\n").expect("managed ignore fixture");
    std::fs::write(publication.join("sentinel"), b"tracked immutable output\n")
        .expect("tracked publication fixture");
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&root)
            .status()
            .expect("initialize fixture repository")
            .success()
    );
    assert!(
        Command::new("git")
            .args(["-C"])
            .arg(&root)
            .args([
                "add",
                "-f",
                "--",
                ".h00ligan/code-intel/publication-v4/sentinel",
            ])
            .status()
            .expect("force-track managed publication fixture")
            .success()
    );
    let tracked_control = Command::new("git")
        .args(["-C"])
        .arg(&root)
        .args([
            "ls-files",
            "--error-unmatch",
            "--",
            ".h00ligan/code-intel/publication-v4",
        ])
        .output()
        .expect("probe tracked publication population");
    assert!(
        tracked_control.status.success()
            && String::from_utf8_lossy(&tracked_control.stdout).contains("sentinel"),
        "the known-positive Git population probe must find the tracked descendant"
    );

    let before = file_population(&root);
    let refused = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("index")
        .output()
        .expect("run managed h00ligan index");
    let after = file_population(&root);
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success()
            && stderr.contains("tracked generated artifact")
            && stderr.contains("publication-v4"),
        "a tracked immutable publication must be refused by the shared hygiene gate; \
         status={} stdout={} stderr={stderr}",
        refused.status,
        String::from_utf8_lossy(&refused.stdout),
    );
    assert_eq!(
        after, before,
        "managed-artifact refusal must happen before every repository or bundle effect"
    );
}

#[test]
fn shipped_index_surface_does_not_offer_legacy_destructive_adoption() {
    let help = h00ligan()
        .args(["index", "--help"])
        .output()
        .expect("read shipped index help");
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(
        help.contains("--scip"),
        "known-positive option proves the shipped index help population is present"
    );
    assert!(
        !help.contains("--full"),
        "every immutable publication is complete, so the CLI must not advertise a false incremental/full distinction"
    );
    assert!(
        !help.contains("--adopt-foreign-origin"),
        "immutable generations have no destructive foreign-origin adoption mode"
    );

    let rejected = h00ligan()
        .args(["index", "--adopt-foreign-origin"])
        .output()
        .expect("invoke removed legacy option");
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("--adopt-foreign-origin"),
        "the removed option must be rejected by the shipped parser, never accepted as a no-op"
    );
}

#[test]
fn shipped_index_cannot_publish_a_filtered_repository_population() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", "pub fn rust_source() -> usize { 42 }\n");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"complete_population_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("fixture Cargo manifest");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/complete-population\n\ngo 1.25\n",
    )
    .expect("fixture Go module");
    std::fs::write(
        root.join("main.go"),
        "package main\n\nfunc goSource() {}\n\nfunc main() { goSource() }\n",
    )
    .expect("fixture Go source");

    let complete_data = temporary.path().join("complete-bundle");
    let complete = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&complete_data)
        .arg("index")
        .output()
        .expect("index complete mixed-language repository");
    assert!(
        complete.status.success(),
        "positive control: default indexing must publish the complete registered source population; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&complete.stdout),
        String::from_utf8_lossy(&complete.stderr),
    );
    let published =
        resolve_generation(&complete_data, &root).expect("resolve complete mixed generation");
    let indexed_languages = published
        .project_inventory
        .project_topology
        .memberships
        .iter()
        .filter(|membership| membership.kind == DocumentMembershipKind::SourceOwner)
        .map(|membership| membership.language_id.0.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        indexed_languages,
        std::collections::BTreeSet::from(["go", "rust"]),
        "positive control: both registered language populations must enter one generation"
    );

    let help = h00ligan()
        .args(["index", "--help"])
        .output()
        .expect("read shipped index help");
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(
        help.contains("--scip"),
        "known-positive option proves the shipped index help population is present"
    );
    assert!(
        !help.contains("--lang") && !help.contains("--exclude"),
        "a repository generation must not offer filters that turn omitted source into false absence: {help}"
    );

    for (case, arguments) in [
        ("language", vec!["--lang", "rust"]),
        ("exclude", vec!["--exclude", "main.go"]),
    ] {
        let data_dir = temporary.path().join(format!("refused-{case}"));
        let refused = h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .arg("index")
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("run refused {case} filter: {error}"));
        assert!(
            !refused.status.success(),
            "{case} filtering must be rejected before it can publish partial repository authority; \
             stdout={} stderr={}",
            String::from_utf8_lossy(&refused.stdout),
            String::from_utf8_lossy(&refused.stderr),
        );
        assert!(
            !data_dir.exists(),
            "argument rejection must precede every publication effect for {case}"
        );
    }
}

#[test]
fn find_rejects_page_limits_outside_the_shipped_bound() {
    let help = h00ligan()
        .args(["find", "--help"])
        .output()
        .expect("read find help");
    assert!(help.status.success());
    assert!(
        String::from_utf8_lossy(&help.stdout).contains("--limit"),
        "known-positive: the shipped find limit population must be present"
    );

    for limit in ["0", "101"] {
        let rejected = h00ligan()
            .args(["find", "*", "--limit", limit])
            .output()
            .expect("invoke find with invalid limit");
        assert!(
            !rejected.status.success(),
            "find accepted out-of-contract limit {limit}"
        );
        let stderr = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            stderr.contains("between 1 and 100"),
            "find limit {limit} failed for the wrong reason: {stderr}"
        );
        assert!(
            !stderr.contains("indexed generation"),
            "limit validation must happen before publication loading: {stderr}"
        );
    }
}

#[test]
fn deps_exposes_only_the_bounded_summary_contract() {
    let help = h00ligan()
        .args(["deps", "--help"])
        .output()
        .expect("read deps help");
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(
        help.contains("<PATH>"),
        "known-positive: the shipped deps path population must be present: {help}"
    );
    assert!(
        help.contains("--limit") && help.contains("--cursor"),
        "a bounded dependency result must be pageable rather than forcing path subdivision: {help}"
    );
    assert!(
        !help.contains("--detail") && !help.contains("--depth"),
        "deps must not advertise an unbounded legacy dump or an unused traversal control: {help}"
    );

    for retired in [
        ["deps", "src/lib.rs", "--detail"],
        ["deps", "src/lib.rs", "--depth"],
    ] {
        let rejected = h00ligan()
            .args(retired)
            .output()
            .expect("invoke retired deps option");
        assert!(
            !rejected.status.success(),
            "retired deps option was still accepted: {retired:?}"
        );
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains(retired[2]),
            "parser did not identify retired option {}: {}",
            retired[2],
            String::from_utf8_lossy(&rejected.stderr)
        );
    }

    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "deps-limit-repo", "pub fn item() {}\n");
    for limit in ["0", "101"] {
        let data_dir = temporary.path().join(format!("bundle-{limit}"));
        let rejected = h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["deps", "src/lib.rs", "--limit", limit])
            .output()
            .expect("invoke deps with invalid limit");
        assert!(
            !rejected.status.success(),
            "deps accepted out-of-contract limit {limit}"
        );
        let stderr = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            stderr.contains("between 1 and 100") && !stderr.contains("indexed generation"),
            "deps limit {limit} failed after publication loading or for the wrong reason: {stderr}"
        );
        assert!(
            !data_dir.exists(),
            "limit rejection must precede every persisted-bundle read or write"
        );
    }

    let traversal_data_dir = temporary.path().join("traversal-bundle");
    let traversal = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&traversal_data_dir)
        .args(["deps", "../outside.rs"])
        .output()
        .expect("invoke deps with parent traversal");
    assert!(
        !traversal.status.success()
            && String::from_utf8_lossy(&traversal.stderr).contains("forbidden `..` component"),
        "dependency traversal must be rejected for the path reason before loading publication state: stdout={} stderr={}",
        String::from_utf8_lossy(&traversal.stdout),
        String::from_utf8_lossy(&traversal.stderr),
    );
    assert!(
        !traversal_data_dir.exists(),
        "path admission must precede every persisted-bundle read or write"
    );
}

#[test]
fn deps_does_not_count_inverse_trait_navigation_as_a_reverse_dependency() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"deps_contract\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    std::fs::write(
        root.join("src/lib.rs"),
        "pub mod base;\npub mod contract;\npub mod implementation;\npub mod support;\n",
    )
    .expect("crate root");
    std::fs::write(root.join("src/base.rs"), "pub trait Base {}\n").expect("base trait source");
    std::fs::write(
        root.join("src/contract.rs"),
        "use crate::base::Base;\npub trait Service: Base { fn run(&self); }\n",
    )
    .expect("trait source");
    std::fs::write(root.join("src/support.rs"), "pub struct Token;\n").expect("support source");
    std::fs::write(
        root.join("src/implementation.rs"),
        "use crate::contract::Service;\nuse crate::support::Token;\npub struct Worker { pub token: Token }\nimpl Service for Worker { fn run(&self) {} }\n",
    )
    .expect("implementation source");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish dependency fixture");
    assert!(
        indexed.status.success(),
        "positive control: structural indexing must publish the fixture: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["deps", "src/implementation.rs", "--format", "json"])
        .output()
        .expect("query dependency fixture");
    assert!(
        output.status.success(),
        "dependency query failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let result = stdout_json(&output);
    assert_eq!(result["schema_version"], "h00/code-intel/dependencies/v1");
    assert!(
        result["scope"]["symbols"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "positive control: the selected implementation file must own indexed symbols: {result}"
    );
    assert_eq!(result["authority"]["status"], "qualified");
    assert_eq!(
        result["authority"]["structural_graph"]["status"],
        "complete"
    );
    assert_eq!(result["authority"]["calls"]["status"], "unavailable");
    assert_eq!(
        result["authority"]["project_dependencies"]["status"], "unavailable",
        "observed Cargo edges must not fabricate an input-bound completeness receipt"
    );
    assert!(
        result["dependency_evidence_count"]
            .as_u64()
            .is_some_and(|count| count >= 3),
        "positive control: both contract and support dependencies must be populated: {result}"
    );
    assert_eq!(
        result["dependent_evidence_count"], 0,
        "a trait's inverse HasImpl navigation index must not become a claim that the trait file depends on its implementer: {result}"
    );
    let contract = result["files"]
        .as_array()
        .and_then(|files| files.iter().find(|file| file["file"] == "src/contract.rs"))
        .unwrap_or_else(|| {
            panic!("positive control: trait relation must reach contract.rs: {result}")
        });
    let dependency_kinds = contract["dependencies"]
        .as_array()
        .expect("typed dependency evidence population")
        .iter()
        .filter_map(|entry| entry["kind"].as_str())
        .collect::<Vec<_>>();
    assert!(
        dependency_kinds.contains(&"reference") && dependency_kinds.contains(&"implementation"),
        "positive control: the forward source dependency facts must remain visible: {result}"
    );
    assert!(
        contract.get("dependents").is_none() && !result.to_string().contains("has_impl"),
        "navigation-only inverse evidence must be absent from the public contract: {result}"
    );
    assert!(
        result["files"]
            .as_array()
            .is_some_and(|files| files.iter().any(|file| file["file"] == "src/support.rs")),
        "positive control: a second dependency file must make paging non-vacuous: {result}"
    );
    let support = result["files"]
        .as_array()
        .and_then(|files| files.iter().find(|file| file["file"] == "src/support.rs"))
        .unwrap_or_else(|| panic!("support dependency row is absent: {result}"));
    assert!(
        support["dependencies"]
            .as_array()
            .expect("support dependency kinds")
            .iter()
            .filter_map(|entry| entry["kind"].as_str())
            .any(|kind| kind == "type_use"),
        "shipped dependency projection omitted type-use evidence: {result}"
    );

    let contract_dependencies = stdout_json(
        &h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["deps", "src/contract.rs", "--format", "json"])
            .output()
            .expect("query inherited contract dependency"),
    );
    let base = contract_dependencies["files"]
        .as_array()
        .and_then(|files| files.iter().find(|file| file["file"] == "src/base.rs"))
        .unwrap_or_else(|| panic!("base dependency row is absent: {contract_dependencies}"));
    let base_kinds = base["dependencies"]
        .as_array()
        .expect("base dependency kinds")
        .iter()
        .filter_map(|entry| entry["kind"].as_str())
        .collect::<Vec<_>>();
    assert!(
        base_kinds.contains(&"reference") && base_kinds.contains(&"inheritance"),
        "shipped dependency projection must preserve local supertrait evidence: {contract_dependencies}"
    );

    let repository_boundary = stdout_json(
        &h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["deps", ".", "--format", "json"])
            .output()
            .expect("query repository dependency boundary"),
    );
    assert_eq!(repository_boundary["scope"]["path"], ".");
    assert_eq!(repository_boundary["scope"]["kind"], "directory");
    assert_eq!(repository_boundary["page"]["total_items"], 0);
    assert_eq!(repository_boundary["dependency_evidence_count"], 0);
    assert_eq!(repository_boundary["dependent_evidence_count"], 0);

    let first_page = stdout_json(
        &h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args([
                "deps",
                "src/implementation.rs",
                "--format",
                "json",
                "--limit",
                "1",
            ])
            .output()
            .expect("query first dependency page"),
    );
    assert_eq!(first_page["page"]["returned"], 1);
    assert_eq!(first_page["page"]["total_items"], 2);
    assert_eq!(first_page["page"]["has_more"], true);
    let cursor = first_page["page"]["next_cursor"]
        .as_str()
        .expect("first dependency page cursor");
    let second_page = stdout_json(
        &h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args([
                "deps",
                "src/implementation.rs",
                "--format",
                "json",
                "--limit",
                "1",
                "--cursor",
                cursor,
            ])
            .output()
            .expect("query second dependency page"),
    );
    assert_eq!(second_page["page"]["offset"], 1);
    assert_eq!(second_page["page"]["returned"], 1);
    assert_eq!(second_page["page"]["has_more"], false);
    assert_ne!(
        first_page["files"][0]["file"], second_page["files"][0]["file"],
        "continuation must advance through the stable related-file population"
    );
    let first_text_page = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["deps", "src/implementation.rs", "--limit", "1"])
        .output()
        .expect("query human dependency page");
    assert!(first_text_page.status.success());
    let first_text_page = String::from_utf8_lossy(&first_text_page.stdout);
    assert!(
        first_text_page.contains("Next cursor:")
            && first_text_page.contains("pass it back with --cursor"),
        "human output must expose its continuation instead of stranding the operator: {first_text_page}"
    );

    let crossed_scope = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "deps",
            "src/contract.rs",
            "--format",
            "json",
            "--limit",
            "1",
            "--cursor",
            cursor,
        ])
        .output()
        .expect("attempt to reuse cursor across dependency scopes");
    assert!(
        !crossed_scope.status.success()
            && String::from_utf8_lossy(&crossed_scope.stderr)
                .contains("different dependencies request"),
        "a dependency cursor must be bound to the exact normalized scope: stdout={} stderr={}",
        String::from_utf8_lossy(&crossed_scope.stdout),
        String::from_utf8_lossy(&crossed_scope.stderr),
    );

    let missing = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["deps", "src/missing.rs", "--format", "json"])
        .output()
        .expect("query missing dependency scope");
    assert!(
        !missing.status.success()
            && String::from_utf8_lossy(&missing.stderr)
                .contains("not an indexed source file or directory"),
        "a missing scope must be a typed refusal, not an authoritative-looking zero: stdout={} stderr={}",
        String::from_utf8_lossy(&missing.stdout),
        String::from_utf8_lossy(&missing.stderr),
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let response = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "deps",
        json!({"path":"src/implementation.rs"}),
    );
    let missing_response = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "deps",
        json!({"path":"src/missing.rs"}),
    );
    let mcp_output = stop_mcp(child, stdin);
    assert!(
        mcp_output.status.success(),
        "MCP dependency transport failed: {}",
        String::from_utf8_lossy(&mcp_output.stderr)
    );
    assert_eq!(
        result, response["result"]["structuredContent"],
        "CLI JSON and MCP structuredContent must serialize one engine-owned Dependencies result"
    );
    assert_eq!(
        result,
        mcp_text_payload(&response),
        "MCP text fallback must serialize the same Dependencies result"
    );
    assert_eq!(missing_response["result"]["isError"], true);
    assert_eq!(
        missing_response["result"]["structuredContent"]["error"]["code"],
        "source_path_invalid"
    );
}

#[tokio::test]
async fn deps_projects_persisted_cross_file_calls_at_the_shipped_boundary() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("src/caller.rs"),
        "pub fn caller() { target(); }\n",
    )
    .expect("caller source");
    std::fs::write(root.join("src/target.rs"), "pub fn target() {}\n").expect("target source");
    let data_dir = temporary.path().join("bundle");
    std::fs::create_dir_all(&data_dir).expect("bundle directory");

    let mut graph = KnowledgeGraph::new();
    let caller = node("caller", "src/caller.rs", 0);
    let caller_id = caller.memory_id;
    let target = node("target", "src/target.rs", 0);
    let target_id = target.memory_id;
    graph.add_node(caller).expect("caller node");
    graph.add_node(target).expect("target node");
    graph
        .add_edge(
            caller_id,
            target_id,
            GraphEdge {
                kind: EdgeKind::Calls,
                ..Default::default()
            },
        )
        .expect("cross-file Calls edge");

    let project_unit_id = ProjectUnitId::new("rust:test:package");
    let inventory = ProjectInventory {
        coverage: ProjectInventoryCoverage::IndexedSourcePopulationComplete,
        project_topology: h00ligan_engine::code_intel_domain::ProjectTopology {
            units: vec![ProjectUnit {
                project_unit_id: project_unit_id.clone(),
                language_id: LanguageId::new("rust"),
                ecosystem_id: EcosystemId::new("cargo"),
                kind: ProjectUnitKind::Package,
                root_path: String::new(),
                manifest_path: None,
                compilation_root_paths: Vec::new(),
            }],
            memberships: ["src/caller.rs", "src/target.rs"]
                .into_iter()
                .map(|document_path| DocumentMembership {
                    document_path: document_path.into(),
                    language_id: LanguageId::new("rust"),
                    project_unit_id: project_unit_id.clone(),
                    kind: DocumentMembershipKind::SourceOwner,
                })
                .collect(),
            relationships: Vec::new(),
            exact_workspace_member_sets: Vec::new(),
            dependency_graphs: Vec::new(),
        },
        analysis_context_graphs: Vec::new(),
        inputs: Vec::new(),
        issues: Vec::new(),
    };
    let structural_receipt = CapabilityReceipt::complete(
        "structural_graph",
        "fixture-structural",
        "1.0.0",
        CapabilityScope::ProjectUnit {
            language_id: LanguageId::new("rust"),
            project_unit_id,
            configuration_id: ConfigurationId::new(STRUCTURAL_GRAPH_CONFIGURATION_ID),
        },
        "d".repeat(64),
    );

    let mut publisher = SemanticPublisher::acquire(&data_dir, &root).expect("publisher");
    let workspace = publisher.begin_generation().expect("generation workspace");
    let store = GraphStore::new(workspace.database());
    store.save_snapshot(&graph).await.expect("graph snapshot");
    store.set_origin(&root).await.expect("graph origin");
    store
        .set_generation_metadata(GraphGenerationMetadata::now(false))
        .await
        .expect("generation metadata");
    drop(store);
    publisher
        .finish_generation(
            workspace,
            GenerationDraft {
                source_revision: Some("cross-file-call-fixture".into()),
                project_inventory: inventory,
                receipts: vec![structural_receipt],
                provider_payloads: Vec::new(),
            },
        )
        .expect("publish dependency fixture");

    let status = stdout_json(
        &h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["status", "--format", "json"])
            .output()
            .expect("read cross-file graph status"),
    );
    assert_eq!(
        status["stats"]["edge_kinds"]["Calls"], 1,
        "positive control: the published graph must contain one cross-file call: {status}"
    );

    let dependencies = stdout_json(
        &h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["deps", "src/caller.rs", "--format", "json"])
            .output()
            .expect("query cross-file call dependency"),
    );
    assert!(
        dependencies["files"]
            .as_array()
            .and_then(|files| files.iter().find(|file| file["file"] == "src/target.rs"))
            .and_then(|file| file["dependencies"].as_array())
            .is_some_and(|relations| relations
                .iter()
                .any(|relation| { relation["kind"] == "call" && relation["evidence_count"] == 1 })),
        "the shipped dependency projection omitted a persisted cross-file call: {dependencies}"
    );
}

#[test]
fn deps_reports_the_generation_graphs_literal_project_dependency() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("crate_a/src")).expect("crate_a source directory");
    std::fs::create_dir_all(root.join("crate_b/src")).expect("crate_b source directory");
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crate_a\", \"crate_b\"]\nresolver = \"2\"\n",
    )
    .expect("workspace manifest");
    std::fs::write(
        root.join("crate_a/Cargo.toml"),
        "[package]\nname = \"crate_a\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[dependencies]\ncrate_b = { path = \"../crate_b\" }\n",
    )
    .expect("crate_a manifest");
    std::fs::write(root.join("crate_a/src/lib.rs"), "pub fn a_entry() {}\n")
        .expect("crate_a source");
    std::fs::write(
        root.join("crate_b/Cargo.toml"),
        "[package]\nname = \"crate_b\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("crate_b manifest");
    std::fs::write(root.join("crate_b/src/lib.rs"), "pub fn b_api() {}\n").expect("crate_b source");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("index")
        .output()
        .expect("publish workspace dependency fixture");
    assert!(
        indexed.status.success(),
        "workspace dependency fixture must publish: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let status = stdout_json(
        &h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["status", "--format", "json"])
            .output()
            .expect("read workspace graph status"),
    );
    assert!(
        status["stats"]["edge_kinds"]["DependsOn"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "positive control: the published graph must contain the literal project dependency: {status}"
    );

    let dependencies = stdout_json(
        &h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["deps", "crate_a/src/lib.rs", "--format", "json"])
            .output()
            .expect("query workspace dependency"),
    );
    assert_eq!(
        dependencies["authority"]["project_dependencies"]["status"], "unavailable",
        "positive edge evidence is not proof that every manifest dependency was covered"
    );
    let crate_b = dependencies["files"]
        .as_array()
        .and_then(|files| {
            files
                .iter()
                .find(|file| file["file"] == "crate_b/src/lib.rs")
        })
        .unwrap_or_else(|| panic!("crate_b dependency row is absent: {dependencies}"));
    assert!(
        crate_b["dependencies"]
            .as_array()
            .is_some_and(|relations| relations.iter().any(|relation| {
                relation["kind"] == "project_dependency" && relation["evidence_count"] == 1
            })),
        "the literal DependsOn fact must survive as a typed project dependency: {dependencies}"
    );
}

#[test]
fn shipped_cli_does_not_offer_unbound_rust_only_clone_analysis() {
    let help = h00ligan().arg("--help").output().expect("read CLI help");
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(
        help.lines()
            .any(|line| line.trim_start().starts_with("overview")),
        "known-positive: the shipped semantic-reader population must be present"
    );
    assert!(
        !help
            .lines()
            .any(|line| line.trim_start().starts_with("dry")),
        "Rust-only live clone analysis must not masquerade as a generation-bound polyglot command: {help}"
    );

    let rejected = h00ligan()
        .arg("dry")
        .output()
        .expect("invoke retired dry adapter");
    assert!(
        !rejected.status.success(),
        "the retired live Rust-only adapter must be rejected by the shipped parser"
    );
}

#[test]
fn shipped_cli_exposes_manual_and_watched_publication_without_legacy_writer_aliases() {
    let top_level = h00ligan()
        .arg("--help")
        .output()
        .expect("read shipped top-level help");
    assert!(top_level.status.success());
    let top_level = String::from_utf8_lossy(&top_level.stdout);
    assert!(
        top_level
            .lines()
            .any(|line| line.trim_start().starts_with("index ")),
        "known-positive control: top-level help must expose the primary index command"
    );
    assert!(
        top_level
            .lines()
            .any(|line| line.trim_start().starts_with("overview ")),
        "known-positive control: top-level help must expose the independent overview query"
    );
    assert!(
        top_level
            .lines()
            .any(|line| line.trim_start().starts_with("watch ")),
        "the shipped CLI must expose supervised immutable WATCH publication: {top_level}"
    );
    for obsolete in ["scip", "init"] {
        assert!(
            !top_level
                .lines()
                .any(|line| line.trim_start().starts_with(&format!("{obsolete} "))),
            "{obsolete} must not remain a shipped writer-shaped alias while immutable publication owns indexing; help={top_level}"
        );
    }
}

#[test]
fn shipped_h00ligan_omits_duplicate_init_and_rust_only_match_surfaces() {
    let top_level = h00ligan()
        .arg("--help")
        .output()
        .expect("read shipped top-level help");
    assert!(top_level.status.success());
    let help = String::from_utf8_lossy(&top_level.stdout);
    assert!(
        help.lines()
            .any(|line| line.trim_start().starts_with("type ")),
        "known-positive: the standalone structural query population must remain present"
    );
    assert!(
        help.lines()
            .any(|line| line.trim_start().starts_with("index ")),
        "known-positive: the standalone publication population must remain present"
    );
    for removed in ["match", "init"] {
        assert!(
            !help
                .lines()
                .any(|line| line.trim_start().starts_with(&format!("{removed} "))),
            "standalone h00ligan must not ship duplicate or language-specific surface {removed}:\n{help}"
        );
        let rejected = h00ligan()
            .args([removed, "--help"])
            .output()
            .expect("probe removed standalone surface");
        assert!(
            !rejected.status.success(),
            "removed standalone surface {removed} must be rejected by the parser"
        );
    }

    let registry = h00ligan_interface::CodeIntelRegistry::default();
    assert!(registry.handler_names().contains(&"type"));
    assert!(registry.handler_names().contains(&"reindex"));
    assert!(!registry.handler_names().contains(&"match"));
    assert!(!registry.handler_names().contains(&"init"));
    assert!(!registry.handler_names().contains(&"replace_symbol"));
}

#[test]
fn cli_json_and_mcp_status_share_one_typed_result_contract() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", "pub fn status_target() {}\n");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"status_contract\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--format", "json"])
        .output()
        .expect("publish status fixture");
    assert!(
        indexed.status.success(),
        "status fixture must publish: {}",
        String::from_utf8_lossy(&indexed.stderr)
    );

    let cli = stdout_json(
        &h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(&data_dir)
            .args(["status", "--format", "json"])
            .output()
            .expect("run CLI status"),
    );
    assert_eq!(cli["schema_version"], "h00/code-intel/status/v3");
    assert_eq!(cli["publication_state"], "published");
    assert_eq!(cli["graph_loaded"], true);

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let response = call_mcp(&mut stdin, &mut stdout, 1, "status", json!({}));
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP status transport failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        cli, response["result"]["structuredContent"],
        "CLI JSON and MCP structuredContent must serialize one shared Status result"
    );
}

#[test]
fn shipped_assess_qualifies_non_callable_impact_without_reference_authority() {
    const SOURCE: &str = concat!(
        "pub struct Widget;\n",
        "pub fn construct_widget() -> Widget { Widget }\n",
    );
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "assess-non-callable-repo", SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"assess_non_callable\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--format", "json"])
        .output()
        .expect("publish structural-only non-callable fixture");
    assert!(
        indexed.status.success(),
        "structural fixture must publish: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let found = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "find",
            "Widget",
            "--name",
            "--definitions-only",
            "--format",
            "json",
        ])
        .output()
        .expect("run non-vacuous Find control");
    assert!(found.status.success());
    let found = stdout_json(&found);
    assert_eq!(found["page"]["total_items"], 1);
    assert_eq!(found["items"][0]["name"], "Widget");
    assert!(
        SOURCE.matches("Widget").count() >= 3,
        "fixture must contain definition, type-use, and construction references"
    );

    let cli_output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "assess",
            "Widget",
            "--file",
            "src/lib.rs",
            "--filter",
            "all",
            "--format",
            "json",
        ])
        .output()
        .expect("run CLI Assess for non-callable target");
    assert!(
        cli_output.status.success(),
        "Assess must retain useful observed structural evidence: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr),
    );
    let cli = stdout_json(&cli_output);
    assert_eq!(cli["resolved_symbol"]["callable"], false);
    assert_eq!(cli["authority"]["calls"]["status"], "unavailable");
    assert_eq!(
        cli["authority"]["status"], "qualified",
        "non-callable impact cannot be complete without provider-backed reference authority: {cli}"
    );
    assert_eq!(cli["authority"]["population_complete"], false);
    assert_eq!(cli["blast_radius"]["population_complete"], false);
    assert_eq!(cli["risk"]["population_complete"], false);
    assert!(cli["warnings"].as_array().is_some_and(|warnings| {
        warnings.iter().any(|warning| {
            warning.as_str().is_some_and(|warning| {
                warning.contains("non-callable") && warning.contains("reference authority")
            })
        })
    }));

    let human_output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args([
            "assess",
            "Widget",
            "--file",
            "src/lib.rs",
            "--filter",
            "all",
        ])
        .output()
        .expect("run human CLI Assess for non-callable target");
    assert!(human_output.status.success());
    let human = String::from_utf8_lossy(&human_output.stdout);
    assert!(human.contains("authority: Qualified; population complete: false"));
    assert!(human.contains("provider-backed reference authority is unavailable"));

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let mcp = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "assess",
        json!({
            "symbol": "Widget",
            "file": "src/lib.rs",
            "filter": "all"
        }),
    );
    let stopped = stop_mcp(child, stdin);
    assert!(
        stopped.status.success(),
        "MCP transport must stop cleanly: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert_eq!(
        mcp["result"]["structuredContent"], cli,
        "CLI JSON and MCP structuredContent must share the qualified Assess contract"
    );
    assert_eq!(mcp_text_payload(&mcp), cli);
}

#[tokio::test]
async fn status_bounds_missing_provider_evidence_across_cli_and_mcp() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", "fn rust_dead() -> usize { 42 }\n");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"bounded_status\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Rust package manifest");
    std::fs::write(
        root.join("go.mod"),
        "module example.test/bounded_status\n\ngo 1.25\n",
    )
    .expect("Go module");
    std::fs::write(
        root.join("main.go"),
        "package bounded_status\n\nfunc go_dead() {}\n",
    )
    .expect("Go source");
    let data_dir = temporary.path().join("bundle");
    publish_mixed_calls_authority_fixture_with_configuration(&root, &data_dir, "calls-obsolete")
        .await;

    let cli_output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["status", "--format", "json"])
        .output()
        .expect("run CLI status against obsolete provider evidence");
    assert!(
        cli_output.status.success(),
        "status must explain missing current evidence: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr),
    );
    let cli = stdout_json(&cli_output);
    for language_id in ["rust", "go"] {
        let gap = &calls_language(&cli, language_id)["gaps"][0];
        assert_eq!(gap["reason_code"], "provider_evidence_absent");
        assert_eq!(
            gap["reason"],
            "no single complete provider covers all of 1 required project-unit scope"
        );
    }
    let serialized_cli = serde_json::to_string(&cli).expect("serialize CLI status");
    for internal_shape in [
        "ProjectUnit {",
        "LanguageId(",
        "ProjectUnitId(",
        "ConfigurationId(",
    ] {
        assert!(
            !serialized_cli.contains(internal_shape),
            "public Status must not expose internal Rust Debug shape {internal_shape}: {serialized_cli}"
        );
    }

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let response = call_mcp(&mut stdin, &mut stdout, 1, "status", json!({}));
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP status transport failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        cli, response["result"]["structuredContent"],
        "CLI JSON and MCP structuredContent must share the bounded explanation"
    );
    assert_eq!(
        cli,
        mcp_text_payload(&response),
        "MCP text fallback must share the same bounded Status DTO"
    );
}

#[tokio::test]
async fn status_preserves_applicable_typescript_health_failure_across_cli_and_mcp() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = temporary.path().join("repo");
    std::fs::create_dir_all(root.join("src")).expect("source directory");
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"status-health-fixture","version":"1.0.0","type":"module"}"#,
    )
    .expect("package manifest");
    std::fs::write(
        root.join("tsconfig.json"),
        r#"{"compilerOptions":{"target":"ES2022","module":"NodeNext","moduleResolution":"NodeNext","strict":true},"include":["src/**/*.ts"]}"#,
    )
    .expect("TypeScript configuration");
    std::fs::write(
        root.join("src/usage.ts"),
        "import { missing } from './does-not-exist.js';\nexport const result = missing();\n",
    )
    .expect("module-level unresolved call fixture");
    let data_dir = temporary.path().join("bundle");
    publish_typescript_health_failure_without_callable_declaration(&root, &data_dir).await;

    let cli_output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["status", "--format", "json"])
        .output()
        .expect("run CLI status against typed provider-health failure");
    assert!(
        cli_output.status.success(),
        "status remains a successful observation: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr),
    );
    let cli = stdout_json(&cli_output);
    assert_eq!(
        cli["freshness"], "fresh",
        "structural truth remains current"
    );
    assert_eq!(cli["capabilities"]["calls"]["status"], "unavailable");
    let typescript = calls_language(&cli, "typescript");
    assert_eq!(typescript["status"], "unavailable");
    assert_eq!(
        typescript["gaps"][0]["reason_code"],
        "provider_failed_or_unavailable"
    );
    assert_eq!(cli["action_needed"], true);
    assert!(
        cli["recommendation"]
            .as_str()
            .is_some_and(|recommendation| recommendation.contains("Calls coverage is unavailable"))
    );

    let human_output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .arg("status")
        .output()
        .expect("run human status against typed provider-health failure");
    assert!(human_output.status.success());
    let human = String::from_utf8_lossy(&human_output.stdout);
    assert!(human.contains("H00LIGAN STATUS — ATTENTION"));
    assert!(human.contains("Calls: unavailable"));
    assert!(human.contains("typescript: unavailable"));
    assert!(human.contains("failed its authority or health contract"));

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let response = call_mcp(&mut stdin, &mut stdout, 1, "status", json!({}));
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP status transport failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        cli, response["result"]["structuredContent"],
        "CLI JSON and MCP must preserve the same applicable failure"
    );
    assert_eq!(cli, mcp_text_payload(&response));
}

#[test]
fn status_reports_a_malformed_publication_instead_of_calling_it_unindexed() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", "pub fn status_target() {}\n");
    let data_dir = temporary.path().join("bundle");
    let publication = data_dir.join("publication-v4");
    std::fs::create_dir_all(&publication).expect("publication directory");
    std::fs::write(publication.join("head-0.json"), b"not-json").expect("malformed first head");
    std::fs::write(publication.join("head-1.json"), b"also-not-json")
        .expect("malformed second head");

    let cli_output = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["status", "--format", "json"])
        .output()
        .expect("run CLI status against malformed publication");
    assert!(
        cli_output.status.success(),
        "status is a total health query and must report invalid publication state: stdout={} stderr={}",
        String::from_utf8_lossy(&cli_output.stdout),
        String::from_utf8_lossy(&cli_output.stderr)
    );
    let cli = stdout_json(&cli_output);
    assert_eq!(cli["schema_version"], "h00/code-intel/status/v3");
    assert_eq!(cli["publication_state"], "invalid");
    assert_eq!(cli["availability"], "load_failed");
    assert_eq!(cli["graph_loaded"], false);
    assert!(
        cli["recommendation"]
            .as_str()
            .is_some_and(
                |recommendation| recommendation.contains("--recover-publication")
                    && recommendation.contains("recover_publication=true")
            ),
        "invalid publication status must prescribe the explicit CLI and MCP recovery authority: {cli}"
    );
    assert!(
        cli["load_error"]
            .as_str()
            .is_some_and(|error| !error.is_empty())
    );

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let response = call_mcp(&mut stdin, &mut stdout, 1, "status", json!({}));
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain available for status/recovery: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_ne!(response["result"]["isError"], true);
    assert_eq!(
        cli, response["result"]["structuredContent"],
        "both adapters must preserve the same malformed-publication diagnosis"
    );
}

#[tokio::test]
async fn overview_health_is_unknown_without_calls_authority_and_numeric_with_it() {
    let help = h00ligan()
        .args(["overview", "--help"])
        .output()
        .expect("read shipped Overview help");
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(
        help.contains("--format"),
        "known-positive control: Overview help must expose its real output selector"
    );
    assert!(
        !help.contains("--max-depth"),
        "Overview must not advertise an ignored module-depth option"
    );

    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        "pub fn caller() { target(); }\npub fn target() {}\n",
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"overview_authority\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");

    let structural_data = temporary.path().join("structural-bundle");
    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&structural_data)
        .args(["index", "--format", "json"])
        .output()
        .expect("publish structural generation");
    assert!(
        indexed.status.success(),
        "known-positive control: structural indexing must publish a non-empty generation: stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let run_overview = |data_dir: &Path| {
        h00ligan()
            .arg("--root")
            .arg(&root)
            .arg("--data-dir")
            .arg(data_dir)
            .args(["overview", "--format", "json"])
            .output()
            .expect("run CLI overview")
    };
    let structural_output = run_overview(&structural_data);
    assert!(
        structural_output.status.success(),
        "structural overview must remain available: stdout={} stderr={}",
        String::from_utf8_lossy(&structural_output.stdout),
        String::from_utf8_lossy(&structural_output.stderr),
    );
    let structural = stdout_json(&structural_output);
    assert_eq!(structural["schema_version"], "h00/code-intel/overview/v3");
    assert!(structural["generation_id"].is_string());
    assert!(structural["repository"]["repository_id"].is_string());
    assert!(
        structural["total_nodes"]
            .as_u64()
            .is_some_and(|count| count > 0),
        "known-positive control: overview must observe indexed graph nodes: {structural}"
    );
    let units = structural["project_units"]
        .as_array()
        .expect("overview project units");
    assert!(
        !units.is_empty(),
        "known-positive control: overview must observe the indexed project unit: {structural}"
    );
    assert_eq!(
        structural["capabilities"]["calls"]["status"], "unavailable",
        "known-positive control: the fixture intentionally has no Calls receipt"
    );
    assert_eq!(structural["health_status"], "unavailable");

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &structural_data);
    let response = call_mcp(&mut stdin, &mut stdout, 1, "overview", json!({}));
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP overview transport failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        structural, response["result"]["structuredContent"],
        "CLI JSON and MCP must share the same Overview result"
    );
    assert!(
        units.iter().all(|unit| unit["health"].is_null()),
        "per-unit health is a Calls-derived claim and must be unknown without Calls authority: {structural}"
    );
    assert!(
        units.iter().all(|unit| unit["top_types"].is_null()),
        "mixed Calls/FieldOf fan-in must follow the same authority gate: {structural}"
    );
    assert!(
        structural["dead_code_count"].is_null(),
        "the aggregate health claim must also remain unknown without Calls authority"
    );

    let semantic_data = temporary.path().join("semantic-bundle");
    seed_calls_bundle(&root, &semantic_data, &["caller"]).await;
    let semantic_output = run_overview(&semantic_data);
    assert!(
        semantic_output.status.success(),
        "Calls-authoritative overview must remain available: stdout={} stderr={}",
        String::from_utf8_lossy(&semantic_output.stdout),
        String::from_utf8_lossy(&semantic_output.stderr),
    );
    let semantic = stdout_json(&semantic_output);
    assert_eq!(semantic["schema_version"], "h00/code-intel/overview/v3");
    assert_eq!(semantic["capabilities"]["calls"]["status"], "complete");
    assert_eq!(semantic["health_status"], "complete");
    assert!(
        semantic["project_units"]
            .as_array()
            .is_some_and(|project_units| project_units.iter().any(|unit| {
                unit["health"]["wired"]
                    .as_u64()
                    .is_some_and(|count| count > 0)
            })),
        "non-vacuity control: complete Calls authority must expose measured unit health: {semantic}"
    );
}

#[test]
fn shipped_cli_omits_raw_graph_and_source_mutation_surfaces() {
    let help = h00ligan()
        .arg("--help")
        .output()
        .expect("run shipped top-level help");
    assert!(help.status.success());
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(
        help.contains("  calls"),
        "positive control: the admitted Calls operation must remain shipped"
    );
    assert!(
        help.contains("  assess"),
        "positive control: the authority-guarded impact composite must remain shipped"
    );
    assert!(
        !help
            .lines()
            .any(|line| line.trim_start().starts_with("graph ")),
        "raw graph verbs bypass capability admission and duplicate admitted product operations:\n{help}"
    );
    assert!(
        !help
            .lines()
            .any(|line| line.trim_start().starts_with("replace-symbol ")),
        "source mutation must stay out of h00ligan until its non-cooperating race and cancellation contract is closed:\n{help}"
    );

    for removed in [
        ["graph", "--help"].as_slice(),
        ["replace-symbol", "--help"].as_slice(),
    ] {
        let output = h00ligan()
            .args(removed)
            .output()
            .expect("probe removed shipped surface");
        assert!(
            !output.status.success(),
            "removed surface {removed:?} must be rejected by shipped dispatch"
        );
    }
}

#[test]
fn developer_recipes_do_not_invoke_retired_code_intelligence_surfaces() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let justfile = std::fs::read_to_string(workspace.join("Justfile")).expect("read Justfile");

    assert!(
        justfile.lines().any(|line| {
            line == "ci-product: ci-product-preflight ci test-installed perf-smoke"
        }) && justfile.contains("scripts/test-h00ligan-installed-product.sh"),
        "known-positive control: the installed standalone product gate must be present"
    );
    for retired in [
        "--reclassify",
        "h00 graph path",
        "h00 graph warnings",
        "code-path FROM TO:",
        "warnings SYMBOL:",
    ] {
        assert!(
            !justfile.contains(retired),
            "Justfile must not advertise retired code-intelligence surface {retired:?}"
        );
    }
}

#[test]
fn cli_index_publishes_one_immutable_generation_without_legacy_artifacts() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        "pub struct Counter { pub value: usize }\n\
         impl Counter { pub fn increment(&mut self) { self.value += 1; } }\n",
    );
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"init_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    let data_dir = temporary.path().join("bundle");

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--format", "json"])
        .output()
        .expect("run shipped index");
    assert!(
        indexed.status.success(),
        "index must publish one immutable generation; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );

    let resolved = resolve_generation(&data_dir, &root)
        .expect("index must publish a resolvable immutable generation");
    assert_eq!(resolved.head.body.sequence, 1);
    let report = stdout_json(&indexed);
    assert!(
        report["nodes"].as_u64().is_some_and(|count| count > 0),
        "known-positive control: index must report the generation it published; output={report}"
    );
    for obsolete in [
        "graph.redb",
        "index.redb",
        "graph-write.lock",
        "reindex.incomplete",
    ] {
        assert!(
            !data_dir.join(obsolete).exists(),
            "index must not dual-write obsolete {obsolete}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn unindexed_calls_is_typed_unavailable_after_a_real_positive_control() {
    let temporary = TempDir::new().expect("temporary directory");
    let source = "pub fn caller() { target(); }\npub fn target() {}\n";
    let root = create_source_root(&temporary, "repo", source);
    let indexed = temporary.path().join("indexed");
    let unindexed = temporary.path().join("unindexed");
    seed_calls_bundle(&root, &indexed, &["caller"]).await;

    let control = run_calls(&root, &indexed, &[]);
    assert!(
        control.status.success(),
        "positive control must cross the shipped CLI boundary: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert_eq!(result_count(&stdout_json(&control)), Some(1));

    let unavailable = run_calls(&root, &unindexed, &[]);
    assert!(
        !unavailable.status.success(),
        "an unindexed structural scan cannot authoritatively answer calls; stdout={} stderr={}",
        String::from_utf8_lossy(&unavailable.stdout),
        String::from_utf8_lossy(&unavailable.stderr),
    );
    let error = stdout_json(&unavailable);
    assert_eq!(error["error"]["code"], "capability_unavailable");
    assert_eq!(error["error"]["capability"], "calls");
    assert!(error["error"]["scopes"].is_array());
    assert_eq!(
        error["error"]["evidence"][0]["reason_code"],
        "immutable_generation_unavailable"
    );
}

#[tokio::test]
async fn cli_json_and_mcp_structured_content_are_the_same_calls_result() {
    let temporary = TempDir::new().expect("temporary directory");
    let source = "pub fn caller() { target(); }\npub fn target() {}\n";
    let root = create_source_root(&temporary, "repo", source);
    let data_dir = temporary.path().join("bundle");
    let seeded = seed_calls_bundle(&root, &data_dir, &["caller"]).await;

    let cli = run_calls(&root, &data_dir, &[]);
    assert!(
        cli.status.success(),
        "CLI positive control: {}",
        String::from_utf8_lossy(&cli.stderr)
    );
    let cli_result = stdout_json(&cli);
    assert_eq!(result_count(&cli_result), Some(1));

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let response = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "calls",
        json!({"symbol": "target"}),
    );
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP positive control: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let structured = response["result"]["structuredContent"]
        .as_object()
        .unwrap_or_else(|| panic!("calls must return native structuredContent: {response}"));
    let structured = Value::Object(structured.clone());
    assert_eq!(mcp_text_payload(&response), structured);
    assert_eq!(
        cli_result, structured,
        "CLI JSON and MCP must share one DTO"
    );
    assert_eq!(structured["capability"], "calls");
    assert_eq!(structured["authority"]["status"], "complete");
    assert_eq!(structured["generation_id"], seeded.generation_id);
    assert_eq!(
        structured["repository"]["repository_id"],
        seeded.repository_id
    );
    assert!(structured["resolved_symbol"]["language_id"].is_string());
    let project_unit_ids = structured["resolved_symbol"]["project_unit_ids"]
        .as_array()
        .expect("resolved symbol must expose every indexed source owner");
    let mut expected_project_unit_ids = seeded.project_unit_ids;
    expected_project_unit_ids.sort();
    assert_eq!(
        project_unit_ids,
        &expected_project_unit_ids
            .into_iter()
            .map(Value::String)
            .collect::<Vec<_>>(),
        "an inventory-backed product query must preserve every indexed source owner"
    );
    let items = structured["items"]
        .as_array()
        .expect("Calls items must be an array");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0]["call_span"],
        json!({
            "start_byte": seeded.call_spans[0].start_byte,
            "end_byte": seeded.call_spans[0].end_byte,
            "start_line": seeded.call_spans[0].start_line,
            "start_column": seeded.call_spans[0].start_utf8_byte_column,
            "end_line": seeded.call_spans[0].end_line,
            "end_column": seeded.call_spans[0].end_utf8_byte_column,
        }),
        "the product must return the exact persisted provider occurrence"
    );
    assert!(structured["page"].is_object());
}

#[tokio::test]
async fn calls_machine_surface_pages_instead_of_silently_prefixing() {
    let temporary = TempDir::new().expect("temporary directory");
    let source = concat!(
        "pub fn caller_a() { target(); }\n",
        "pub fn caller_b() { target(); }\n",
        "pub fn caller_c() { target(); }\n",
        "pub fn target() {}\n",
    );
    let root = create_source_root(&temporary, "repo", source);
    let data_dir = temporary.path().join("bundle");
    seed_calls_bundle(&root, &data_dir, &["caller_a", "caller_b", "caller_c"]).await;

    let control = run_calls(&root, &data_dir, &[]);
    assert!(control.status.success());
    assert_eq!(result_count(&stdout_json(&control)), Some(3));

    let first = run_calls(&root, &data_dir, &["--limit", "1"]);
    assert!(
        first.status.success(),
        "the machine contract must accept an explicit page size: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first = stdout_json(&first);
    assert_eq!(first["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(first["page"]["has_more"], true);
    let cursor = first["page"]["next_cursor"]
        .as_str()
        .expect("non-terminal page cursor")
        .to_string();

    let second = run_calls(&root, &data_dir, &["--limit", "1", "--cursor", &cursor]);
    assert!(
        second.status.success(),
        "a returned cursor must be consumable: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second = stdout_json(&second);
    assert_eq!(second["items"].as_array().map(Vec::len), Some(1));
    assert_ne!(first["items"][0], second["items"][0]);
    assert_eq!(first["generation_id"], second["generation_id"]);
}

#[tokio::test]
async fn mcp_reindex_requires_explicit_capability_downgrade_authority() {
    let temporary = TempDir::new().expect("temporary directory");
    let source = "pub fn caller() { target(); }\npub fn target() {}\n";
    let root = create_source_root(&temporary, "repo", source);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"mcp_floor_fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let initial = seed_calls_bundle(&root, &data_dir, &["caller"]).await;

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let refused = call_mcp_reindex_terminal(&mut stdin, &mut stdout, 1, json!({}));
    assert_eq!(refused["state"], "failed", "{refused}");
    assert!(
        refused["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("capabilit")),
        "the MCP refusal must explain the preserved authority: {refused}"
    );
    assert_eq!(
        resolve_generation(&data_dir, &root)
            .expect("preserved generation")
            .manifest
            .generation_id
            .0,
        initial.generation_id
    );
    let calls = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "calls",
        json!({"symbol": "target"}),
    );
    assert_ne!(
        calls["result"]["isError"], true,
        "the refused writer must leave prior Calls authority live: {calls}"
    );

    let allowed = call_mcp_reindex_terminal(
        &mut stdin,
        &mut stdout,
        3,
        json!({"allow_capability_downgrade": true}),
    );
    assert_eq!(allowed["state"], "succeeded", "{allowed}");
    assert_eq!(allowed["result"]["capability_downgrade_authorized"], true);
    let downgraded = resolve_generation(&data_dir, &root).expect("downgraded generation");
    assert_ne!(downgraded.manifest.generation_id.0, initial.generation_id);
    assert_eq!(
        downgraded
            .manifest
            .parent_generation_id
            .as_ref()
            .map(|id| &id.0),
        Some(&initial.generation_id)
    );
    let unavailable = call_mcp(
        &mut stdin,
        &mut stdout,
        4,
        "calls",
        json!({"symbol": "target"}),
    );
    assert_eq!(unavailable["result"]["isError"], true, "{unavailable}");

    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP capability-floor process failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn long_lived_mcp_serves_last_good_while_a_candidate_is_incomplete() {
    let temporary = TempDir::new().expect("temporary directory");
    let source = "pub fn caller() { target(); }\npub fn target() {}\n";
    let root = create_source_root(&temporary, "repo", source);
    let data_dir = temporary.path().join("bundle");
    seed_calls_bundle(&root, &data_dir, &["caller"]).await;

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let before = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "calls",
        json!({"symbol": "target"}),
    );
    assert_ne!(
        before["result"]["isError"], true,
        "positive control: {before}"
    );
    let before = mcp_text_payload(&before);
    assert_eq!(result_count(&before), Some(1));
    assert_eq!(
        before["repository"]["live_inputs"]["freshness"], "fresh",
        "positive control: the original generation must match live source"
    );

    let publisher =
        SemanticPublisher::acquire(&data_dir, &root).expect("incomplete candidate publisher");
    let _workspace = publisher
        .begin_generation()
        .expect("private incomplete candidate workspace");
    let during = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "calls",
        json!({"symbol": "target"}),
    );
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_ne!(
        during["result"]["isError"], true,
        "an unpublished candidate must not revoke the last good generation: {during}"
    );
    assert_eq!(mcp_text_payload(&during), before);
}

#[tokio::test]
async fn long_lived_mcp_serves_last_good_when_a_changed_candidate_is_rejected() {
    let temporary = TempDir::new().expect("temporary directory");
    let source = "pub fn caller() { target(); }\npub fn target() {}\n";
    let root = create_source_root(&temporary, "repo", source);
    let data_dir = temporary.path().join("bundle");
    seed_calls_bundle(&root, &data_dir, &["caller"]).await;

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let before = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "calls",
        json!({"symbol": "target"}),
    );
    assert_ne!(
        before["result"]["isError"], true,
        "positive control: {before}"
    );
    let before = mcp_text_payload(&before);
    assert_eq!(result_count(&before), Some(1));
    assert_eq!(
        before["repository"]["live_inputs"]["freshness"], "fresh",
        "positive control: the original generation must match live source"
    );

    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn changed_caller() { target(); }\npub fn target() {}\n",
    )
    .expect("changed source fixture");
    let candidate = seed_calls_bundle(&root, &data_dir, &["changed_caller"]).await;
    let held_database = candidate.database_path.with_extension("redb.held");
    std::fs::rename(&candidate.database_path, &held_database)
        .expect("hold candidate database aside");
    std::fs::write(&candidate.database_path, b"not a redb database")
        .expect("rejected candidate database");
    let after = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "calls",
        json!({"symbol": "target"}),
    );
    std::fs::remove_file(&candidate.database_path).expect("remove rejected candidate database");
    std::fs::rename(&held_database, &candidate.database_path).expect("restore candidate database");
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_ne!(
        after["result"]["isError"], true,
        "a rejected candidate must not revoke the last good generation: {after}"
    );
    let after = mcp_text_payload(&after);
    assert_eq!(
        after["repository"]["live_inputs"]["freshness"], "stale",
        "the retained generation must disclose that the rejected candidate's source bytes remain live"
    );
    assert!(
        after["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("not the current worktree")))),
        "stale last-good evidence must carry an explicit live-source qualification: {after}"
    );
    assert_eq!(
        without_live_input_observation(after),
        without_live_input_observation(before),
        "only live-input currency may change when the immutable last-good generation is retained"
    );
}

#[tokio::test]
async fn long_lived_mcp_serves_last_good_when_candidate_graph_disappears() {
    let temporary = TempDir::new().expect("temporary directory");
    let source = "pub fn caller() { target(); }\npub fn target() {}\n";
    let root = create_source_root(&temporary, "repo", source);
    let data_dir = temporary.path().join("bundle");
    seed_calls_bundle(&root, &data_dir, &["caller"]).await;

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let before = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "calls",
        json!({"symbol": "target"}),
    );
    assert_ne!(
        before["result"]["isError"], true,
        "positive control: {before}"
    );
    let before = mcp_text_payload(&before);
    assert_eq!(
        before["repository"]["live_inputs"]["freshness"], "fresh",
        "positive control: the original generation must match live source"
    );

    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn changed_caller() { target(); }\npub fn target() {}\n",
    )
    .expect("changed source fixture");
    let candidate = seed_calls_bundle(&root, &data_dir, &["changed_caller"]).await;
    let held_database = candidate.database_path.with_extension("redb.held");
    std::fs::rename(&candidate.database_path, &held_database)
        .expect("hold candidate generation database aside");
    let after = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "calls",
        json!({"symbol": "target"}),
    );
    std::fs::rename(&held_database, &candidate.database_path)
        .expect("restore candidate generation database");
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_ne!(
        after["result"]["isError"], true,
        "an absent candidate graph is not a new publication: {after}"
    );
    let after = mcp_text_payload(&after);
    assert_eq!(
        after["repository"]["live_inputs"]["freshness"], "stale",
        "the retained generation must disclose that the absent candidate's source bytes remain live"
    );
    assert!(
        after["warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.iter().any(|warning| warning
                .as_str()
                .is_some_and(|warning| warning.contains("not the current worktree")))),
        "stale last-good evidence must carry an explicit live-source qualification: {after}"
    );
    assert_eq!(
        without_live_input_observation(after),
        without_live_input_observation(before),
        "only live-input currency may change when the immutable last-good generation is retained"
    );
}

#[tokio::test]
async fn query_and_mutation_fail_closed_when_publication_control_is_unsafe() {
    let temporary = TempDir::new().expect("temporary directory");
    let source = "pub fn caller() { target(); }\npub fn target() {}\n";
    let root = create_source_root(&temporary, "repo", source);
    let data_dir = temporary.path().join("bundle");
    seed_calls_bundle(&root, &data_dir, &["caller"]).await;

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let before = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "calls",
        json!({"symbol": "target"}),
    );
    assert_ne!(
        before["result"]["isError"], true,
        "positive control: {before}"
    );
    let before = mcp_text_payload(&before);
    assert_eq!(
        result_count(&before),
        Some(1),
        "positive control must prove that the retained generation was initially queryable: {before}"
    );

    // Replacing the bundle directory with a regular file makes both artifact
    // fingerprinting and marker inspection fail deterministically. Neither a
    // query nor a mutation may proceed when the process cannot validate which
    // published generation is authoritative.
    let held_bundle = temporary.path().join("held-bundle");
    std::fs::rename(&data_dir, &held_bundle).expect("hold bundle aside");
    std::fs::write(&data_dir, b"not a directory").expect("invalid candidate control path");

    let read = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "calls",
        json!({"symbol": "target"}),
    );
    let mutation = call_mcp_reindex_terminal(&mut stdin, &mut stdout, 3, json!({"scip": false}));

    std::fs::remove_file(&data_dir).expect("remove invalid control path");
    std::fs::rename(&held_bundle, &data_dir).expect("restore bundle");
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(
        read["result"]["isError"], true,
        "a retained in-memory generation must not escape after publication authority becomes unsafe: {read}"
    );
    assert!(
        read["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|message| {
                message.contains("refresh publication")
                    && message.contains("unsafe publication artifact")
            }),
        "query refusal must identify the failed publication validation boundary: {read}"
    );
    assert_eq!(mutation["state"], "failed", "{mutation}");
    assert_eq!(mutation["error"]["kind"], "tool_error");
    assert_eq!(mutation["error"]["category"], "preparation");
    assert_eq!(mutation["error"]["code"], "project_path");
    assert!(
        mutation["error"]["message"]
            .as_str()
            .is_some_and(|message| {
                message.contains("refusing non-directory generated artifact")
                    && !message.contains("create explicit graph directory failed")
            }),
        "mutation must fail at typed graph-destination preflight: {mutation}"
    );
    assert_eq!(
        std::fs::read(root.join("src/lib.rs")).expect("source after refused mutation"),
        source.as_bytes()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn long_lived_mcp_reindex_publishes_and_loads_one_immutable_generation() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(&temporary, "repo", SHIPPED_INDEX_SOURCE);
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"fixture_pkg\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .expect("Cargo manifest");
    let data_dir = temporary.path().join("bundle");
    let (provider_artifact, provider_executed, path) =
        install_fixture_rust_analyzer(temporary.path(), &root);

    let indexed = h00ligan()
        .arg("--root")
        .arg(&root)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["index", "--scip"])
        .env("PATH", &path)
        .env("H00_TEST_PROVIDER_ARTIFACT", &provider_artifact)
        .env("H00_TEST_PROVIDER_EXECUTED", &provider_executed)
        .output()
        .expect("run initial shipped index");
    assert!(
        indexed.status.success(),
        "positive control: shipped index must publish complete Calls authority; stdout={} stderr={}",
        String::from_utf8_lossy(&indexed.stdout),
        String::from_utf8_lossy(&indexed.stderr),
    );
    assert!(
        provider_executed.is_file(),
        "positive control: initial provider must execute"
    );
    std::fs::remove_file(&provider_executed).expect("reset provider execution control");
    let initial = resolve_generation(&data_dir, &root).expect("initial immutable generation");

    let (child, mut stdin, mut stdout) = spawn_mcp_with_fixture_provider(
        &root,
        &data_dir,
        &path,
        &provider_artifact,
        &provider_executed,
    );
    let before = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "calls",
        json!({"symbol": "target"}),
    );
    assert_ne!(
        before["result"]["isError"], true,
        "positive control must establish immutable Calls authority: {before}"
    );
    let before_payload = mcp_text_payload(&before);
    assert_eq!(result_count(&before_payload), Some(1));
    assert_eq!(
        before_payload["generation_id"],
        initial.manifest.generation_id.0
    );

    let reindex = call_mcp_reindex_terminal(
        &mut stdin,
        &mut stdout,
        2,
        json!({"scip": true, "require_complete_calls": true, "force": true}),
    );
    let after = call_mcp(
        &mut stdin,
        &mut stdout,
        3,
        "calls",
        json!({"symbol": "target"}),
    );
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        provider_executed.is_file() && reindex["state"] == "succeeded",
        "MCP reindex must reach the provider and publish instead of refusing at the legacy/immutable split; \
         provider_ran={} reindex={reindex}",
        provider_executed.is_file(),
    );
    assert_ne!(
        after["result"]["isError"], true,
        "the same MCP process must load the newly published Calls authority: {after}"
    );
    let after_payload = mcp_text_payload(&after);
    assert_eq!(result_count(&after_payload), Some(1));
    assert_eq!(after_payload["items"][0]["caller"]["name"], "caller");
    assert_ne!(
        after_payload["generation_id"], before_payload["generation_id"],
        "successful reindex must advance the immutable generation"
    );

    let resolved = resolve_generation(&data_dir, &root).expect("reindexed immutable generation");
    assert!(
        resolved.head.body.sequence > initial.head.body.sequence,
        "MCP reindex must advance the publication head"
    );
    assert_eq!(
        after_payload["generation_id"],
        resolved.manifest.generation_id.0
    );
    assert!(resolved.manifest.receipts.iter().any(|receipt| {
        receipt.capability_id == "calls" && receipt.status == CapabilityStatus::Complete
    }));

    for obsolete in [
        "graph.redb",
        "index.redb",
        "graph-write.lock",
        "reindex.incomplete",
    ] {
        assert!(
            !data_dir.join(obsolete).exists(),
            "MCP reindex must not create obsolete {obsolete}"
        );
    }
}

#[tokio::test]
async fn long_lived_mcp_observes_external_publication_on_the_next_request() {
    let temporary = TempDir::new().expect("temporary directory");
    let root = create_source_root(
        &temporary,
        "repo",
        "pub fn before_caller() { target(); }\npub fn target() {}\n",
    );
    let data_dir = temporary.path().join("bundle");
    let sentinel = root.join("provider-root-sentinel");
    std::fs::write(&sentinel, b"unchanged").expect("provider-root sentinel");
    let initial = seed_calls_bundle(&root, &data_dir, &["before_caller"]).await;

    let (child, mut stdin, mut stdout) = spawn_mcp(&root, &data_dir);
    let before = call_mcp(
        &mut stdin,
        &mut stdout,
        1,
        "calls",
        json!({"symbol": "target"}),
    );
    let before = mcp_text_payload(&before);
    assert_eq!(before["generation_id"], initial.generation_id);
    assert_eq!(before["items"][0]["caller"]["name"], "before_caller");

    std::fs::write(
        root.join("src/lib.rs"),
        "pub fn after_caller() { target(); }\npub fn target() {}\n",
    )
    .expect("updated source fixture");
    let external = seed_calls_bundle(&root, &data_dir, &["after_caller"]).await;
    assert_ne!(external.generation_id, initial.generation_id);

    let after = call_mcp(
        &mut stdin,
        &mut stdout,
        2,
        "calls",
        json!({"symbol": "target"}),
    );
    let after = mcp_text_payload(&after);
    let output = stop_mcp(child, stdin);
    assert!(
        output.status.success(),
        "MCP process must remain healthy: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(after["generation_id"], external.generation_id);
    assert_eq!(after["items"][0]["caller"]["name"], "after_caller");
    assert_eq!(std::fs::read(&sentinel).expect("sentinel"), b"unchanged");
    assert!(!root.join("index.scip").exists());
    assert!(!root.join("Cargo.lock").exists());
    assert!(!root.join("target").exists());
}
