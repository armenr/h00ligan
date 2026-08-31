//! Symbol-level diff engine.
//!
//! Compares the current state of source files (via tree-sitter extraction)
//! against the stored knowledge graph snapshot.  Produces a list of added,
//! removed, and modified symbols for each file.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::edge_builder::{qualified_name, source_symbol_ids};
use crate::extractor::extract_source;
use crate::graph::KnowledgeGraph;
use crate::index_state::FileRecord;
use crate::project_binding::{ProjectBinding, ProjectPathError};
use crate::source_discovery::SourceDiscoveryError;
use crate::source_materialization::MAX_MATERIALIZED_SOURCE_FILE_BYTES;
use crate::structural_ir::{ExtractorError, ExtractorOutput};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single entry in a diff report (added or removed symbol).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffEntry {
    /// Fully-qualified or short symbol name.
    pub name: String,
    /// Symbol kind (function, struct, enum, ...).
    pub kind: String,
    /// Source file path (relative to workspace root).
    pub file_path: String,
    /// Line number (1-indexed) where the symbol starts.
    pub line: Option<usize>,
}

/// An entry for a symbol whose content hash changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModifiedEntry {
    /// Symbol name.
    pub name: String,
    /// Symbol kind.
    pub kind: String,
    /// Source file path.
    pub file_path: String,
    /// Line number (1-indexed).
    pub line: Option<usize>,
    /// Content hash stored in the graph (old).
    pub old_hash: String,
    /// Content hash from fresh extraction (new).
    pub new_hash: String,
}

/// Symbol-level diff for a single file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SymbolDiff {
    pub added: Vec<DiffEntry>,
    pub removed: Vec<DiffEntry>,
    pub modified: Vec<ModifiedEntry>,
}

/// Symbol-level diff for a whole file (with path context).
impl SymbolDiff {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileDiff {
    pub file_path: String,
    #[serde(flatten)]
    pub diff: SymbolDiff,
}

/// Raw observation made by the bound live-worktree scanner.
///
/// `files` contains only files with at least one observed symbol difference.
/// This prevents an unchanged file-scoped query from being promoted into a
/// false `files_changed = 1` claim by a transport adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffObservation {
    /// Normalized repository-relative file path, or `.` for repository scope.
    pub scope_path: String,
    /// Number of registered source files in the requested population.
    pub files_considered: usize,
    /// Number of registered source files actually compared or classified as
    /// deleted during this observation.
    pub files_compared: usize,
    /// Bounded, aggregate reasons some considered files could not be compared.
    pub exclusions: Vec<DiffExclusionSummary>,
    pub files: Vec<FileDiff>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffExclusionReason {
    BaselineSymbolIdentityCollision,
    BaselineSourceNotIndexed,
    CandidateSyntaxIncomplete,
}

impl std::fmt::Display for DiffExclusionReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::BaselineSymbolIdentityCollision => "baseline_symbol_identity_collision",
            Self::BaselineSourceNotIndexed => "baseline_source_not_indexed",
            Self::CandidateSyntaxIncomplete => "candidate_syntax_incomplete",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffExclusionSummary {
    pub reason_code: DiffExclusionReason,
    pub files: usize,
}

/// Errors that can occur during diff operations.
#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    #[error("extractor error: {0}")]
    Extractor(#[from] ExtractorError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("project path rejected: {0}")]
    ProjectPath(#[from] ProjectPathError),

    #[error("source discovery failed: {0}")]
    SourceDiscovery(#[from] SourceDiscoveryError),

    #[error("validated diff path escaped the bound project root: {0}")]
    OutsideProjectRoot(PathBuf),

    #[error("project source path is not valid UTF-8: {0}")]
    NonUtf8ProjectPath(PathBuf),

    #[error("persisted graph source path is not project-relative: {0}")]
    InvalidGraphPath(PathBuf),

    #[error("requested diff path is not a normalized project-relative file: {0}")]
    InvalidRequestedPath(PathBuf),

    #[error("requested path is absent from both the live worktree and structural baseline: {0}")]
    UnknownDeletedPath(PathBuf),

    #[error(
        "published source `{path}` collapsed duplicate symbol identities: index recorded {indexed_symbols} symbols but graph retained {graph_nodes} nodes"
    )]
    CollapsedBaselineSymbols {
        path: String,
        indexed_symbols: u32,
        graph_nodes: usize,
    },

    #[error("project source `{path}` is not valid UTF-8: {source}")]
    InvalidUtf8Source {
        path: PathBuf,
        #[source]
        source: std::str::Utf8Error,
    },
}

// ---------------------------------------------------------------------------
// Core diff logic
// ---------------------------------------------------------------------------

fn diff_bound_file(
    graph: &KnowledgeGraph,
    file_path: &str,
    binding: &ProjectBinding,
    indexed_source: Option<&FileRecord>,
) -> Result<SymbolDiff, DiffError> {
    validate_baseline_symbol_population(graph, file_path, indexed_source)?;
    let raw_path = Path::new(file_path);
    let (canonical, bytes) =
        binding.read_existing_file_bounded(raw_path, MAX_MATERIALIZED_SOURCE_FILE_BYTES)?;
    let source = std::str::from_utf8(&bytes).map_err(|source| DiffError::InvalidUtf8Source {
        path: canonical,
        source,
    })?;
    let output = extract_source(source, file_path)?;
    Ok(diff_extracted_file(graph, file_path, &output))
}

fn validate_baseline_symbol_population(
    graph: &KnowledgeGraph,
    file_path: &str,
    indexed_source: Option<&FileRecord>,
) -> Result<(), DiffError> {
    let Some(indexed_source) = indexed_source else {
        return Ok(());
    };
    let graph_nodes = graph.nodes_for_file(file_path).len();
    if graph_nodes != indexed_source.symbol_count as usize {
        return Err(DiffError::CollapsedBaselineSymbols {
            path: file_path.into(),
            indexed_symbols: indexed_source.symbol_count,
            graph_nodes,
        });
    }
    Ok(())
}

fn diff_extracted_file(
    graph: &KnowledgeGraph,
    file_path: &str,
    output: &ExtractorOutput,
) -> SymbolDiff {
    // 1. Stored symbols from the graph, keyed by source occurrence identity.
    // A `(kind, name)` map collapses valid repeated Rust impl blocks and Go
    // init functions; their graph UUIDs retain the occurrence discriminator.
    let stored_nodes = graph.nodes_for_file(file_path);
    let mut stored: HashMap<uuid::Uuid, (&str, &str, &str, Option<usize>)> = HashMap::new();
    for node in &stored_nodes {
        stored.insert(
            node.memory_id,
            (
                &node.symbol_name,
                &node.kind,
                &node.content_hash,
                node.line_start,
            ),
        );
    }

    // 2. Build the exact same occurrence IDs for the live extraction.
    let fresh_ids = source_symbol_ids(file_path, &output.symbols);
    let fresh = fresh_ids
        .into_iter()
        .zip(&output.symbols)
        .collect::<HashMap<_, _>>();

    // 3. Compare.
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    // Symbols in fresh but not in stored => added.
    // Symbols in both but hash differs => modified.
    for (id, sym) in &fresh {
        let kind = sym.kind.to_string();
        let name = qualified_name(sym);
        match stored.get(id) {
            None => {
                added.push(DiffEntry {
                    name,
                    kind,
                    file_path: file_path.to_string(),
                    line: Some(sym.line_range.0 + 1),
                });
            }
            Some((_old_name, _old_kind, old_hash, _line)) => {
                if *old_hash != sym.content_hash {
                    modified.push(ModifiedEntry {
                        name,
                        kind,
                        file_path: file_path.to_string(),
                        line: Some(sym.line_range.0 + 1),
                        old_hash: old_hash.to_string(),
                        new_hash: sym.content_hash.clone(),
                    });
                }
            }
        }
    }

    // Symbols in stored but not in fresh => removed.
    // CI-IND-11: emit the full qualified `name` (the map key) and the stored
    // line (`line_start + 1`), the same shape the deleted-file path in
    // `diff_workspace` produces.
    for (id, (name, kind, _hash, line_start)) in &stored {
        if !fresh.contains_key(id) {
            removed.push(DiffEntry {
                name: (*name).to_string(),
                kind: (*kind).to_string(),
                file_path: file_path.to_string(),
                line: line_start.map(|l| l + 1),
            });
        }
    }

    // Sort for deterministic output.
    added.sort_by(|left, right| {
        (&left.name, &left.kind, left.line).cmp(&(&right.name, &right.kind, right.line))
    });
    removed.sort_by(|left, right| {
        (&left.name, &left.kind, left.line).cmp(&(&right.name, &right.kind, right.line))
    });
    modified.sort_by(|left, right| {
        (
            &left.name,
            &left.kind,
            left.line,
            &left.old_hash,
            &left.new_hash,
        )
            .cmp(&(
                &right.name,
                &right.kind,
                right.line,
                &right.old_hash,
                &right.new_hash,
            ))
    });

    SymbolDiff {
        added,
        removed,
        modified,
    }
}

/// Diff one optional project-relative file, or the whole bound workspace.
///
/// This is the shared CLI/MCP admission boundary. Persisted graph paths are
/// untrusted input: validate every path through `ProjectBinding` before the
/// lower-level diff engine reads source files. A specific path is normalized
/// to the same project-relative form stored in the graph.
pub(crate) fn diff_bound(
    graph: &KnowledgeGraph,
    binding: &ProjectBinding,
    indexed_sources: &BTreeMap<String, FileRecord>,
    baseline_exclusions: &BTreeMap<String, DiffExclusionReason>,
    file_path: Option<&Path>,
) -> Result<DiffObservation, DiffError> {
    if let Some(file_path) = file_path {
        let requested_relative = normalize_requested_path(file_path)?;
        if let Some(reason_code) = baseline_exclusions.get(&requested_relative) {
            return Ok(excluded_observation(requested_relative, *reason_code));
        }
        let selected = binding.root().join(&requested_relative);
        let (relative, diff) = match std::fs::symlink_metadata(&selected) {
            Ok(_) => {
                let canonical = binding.resolve_existing_path(&selected)?;
                let relative = canonical
                    .strip_prefix(binding.root())
                    .map_err(|_| DiffError::OutsideProjectRoot(canonical.clone()))?
                    .to_str()
                    .ok_or_else(|| DiffError::NonUtf8ProjectPath(canonical.clone()))?
                    .to_owned();
                if let Some(reason_code) = baseline_exclusions.get(&relative) {
                    return Ok(excluded_observation(relative, *reason_code));
                }
                let diff =
                    diff_bound_file(graph, &relative, binding, indexed_sources.get(&relative));
                (relative, diff)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let diff = validate_baseline_symbol_population(
                    graph,
                    &requested_relative,
                    indexed_sources.get(&requested_relative),
                )
                .map(|()| removed_symbol_diff(graph, &requested_relative));
                if diff.as_ref().is_ok_and(SymbolDiff::is_empty)
                    && !indexed_sources.contains_key(&requested_relative)
                {
                    return Err(DiffError::UnknownDeletedPath(selected));
                }
                (requested_relative, diff)
            }
            Err(source) => {
                return Err(ProjectPathError::Io {
                    operation: "inspect requested diff path",
                    path: selected,
                    source,
                }
                .into());
            }
        };
        return match diff {
            Ok(diff) => {
                let files = if diff.is_empty() {
                    Vec::new()
                } else {
                    vec![FileDiff {
                        file_path: relative.clone(),
                        diff,
                    }]
                };
                Ok(DiffObservation {
                    scope_path: relative,
                    files_considered: 1,
                    files_compared: 1,
                    exclusions: Vec::new(),
                    files,
                })
            }
            Err(error) => comparison_exclusion_reason(&error)
                .map(|reason_code| excluded_observation(relative, reason_code))
                .ok_or(error),
        };
    }

    diff_workspace_bound(graph, binding, indexed_sources, baseline_exclusions)
}

fn excluded_observation(scope_path: String, reason_code: DiffExclusionReason) -> DiffObservation {
    DiffObservation {
        scope_path,
        files_considered: 1,
        files_compared: 0,
        exclusions: vec![DiffExclusionSummary {
            reason_code,
            files: 1,
        }],
        files: Vec::new(),
    }
}

const fn comparison_exclusion_reason(error: &DiffError) -> Option<DiffExclusionReason> {
    match error {
        DiffError::CollapsedBaselineSymbols { .. } => {
            Some(DiffExclusionReason::BaselineSymbolIdentityCollision)
        }
        DiffError::Extractor(ExtractorError::IncompleteSyntax { .. }) => {
            Some(DiffExclusionReason::CandidateSyntaxIncomplete)
        }
        _ => None,
    }
}

/// Diff every registered source file known to the graph or currently admitted
/// by repository discovery.
///
/// The same registry and ignore-aware walker used by indexing defines the live
/// population. Reads are descriptor-relative through `ProjectBinding`, and a
/// discovery/read/extraction error aborts the operation instead of being
/// misreported as an empty diff.
fn diff_workspace_bound(
    graph: &KnowledgeGraph,
    binding: &ProjectBinding,
    indexed_sources: &BTreeMap<String, FileRecord>,
    baseline_exclusions: &BTreeMap<String, DiffExclusionReason>,
) -> Result<DiffObservation, DiffError> {
    let extensions = crate::language::extensions_for_languages(&[]);
    let discovered =
        crate::source_discovery::discover_source_files(binding.root(), &extensions, &[])?;
    let discovered_files = discovered
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(binding.root())
                .map_err(|_| DiffError::OutsideProjectRoot(path.clone()))?;
            let relative = relative
                .to_str()
                .ok_or_else(|| DiffError::NonUtf8ProjectPath(path.clone()))?;
            Ok(relative.to_owned())
        })
        .collect::<Result<BTreeSet<_>, DiffError>>()?;

    let graph_files = graph
        .all_nodes()
        .into_iter()
        .filter(|node| {
            Path::new(&node.file_path)
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(crate::language::is_registered_extension)
        })
        .map(|node| node.file_path.clone())
        .collect::<BTreeSet<_>>();
    for file_path in &graph_files {
        validate_graph_file_path(file_path)?;
    }
    for file_path in indexed_sources.keys() {
        validate_graph_file_path(file_path)?;
    }
    for file_path in baseline_exclusions.keys() {
        validate_graph_file_path(file_path)?;
    }

    // The immutable project inventory is the baseline source population. The
    // graph-path union is defensive: a damaged generation must not make a
    // persisted node disappear merely because its inventory row is absent.
    let mut baseline_files = indexed_sources.keys().cloned().collect::<BTreeSet<_>>();
    baseline_files.extend(graph_files);
    baseline_files.extend(baseline_exclusions.keys().cloned());

    let files_considered = baseline_files.union(&discovered_files).count();
    let mut files_compared = 0usize;
    let mut exclusion_counts = BTreeMap::<DiffExclusionReason, usize>::new();
    let mut results = Vec::new();

    for file_path in &baseline_files {
        if let Some(reason_code) = baseline_exclusions.get(file_path) {
            *exclusion_counts.entry(*reason_code).or_default() += 1;
            continue;
        }
        if !discovered_files.contains(file_path) {
            match validate_baseline_symbol_population(
                graph,
                file_path,
                indexed_sources.get(file_path),
            ) {
                Ok(()) => {}
                Err(DiffError::CollapsedBaselineSymbols { .. }) => {
                    *exclusion_counts
                        .entry(DiffExclusionReason::BaselineSymbolIdentityCollision)
                        .or_default() += 1;
                    continue;
                }
                Err(error) => return Err(error),
            }
            let diff = removed_symbol_diff(graph, file_path);
            files_compared += 1;
            if !diff.is_empty() {
                results.push(FileDiff {
                    file_path: file_path.clone(),
                    diff,
                });
            }
            continue;
        }

        let diff = match diff_bound_file(graph, file_path, binding, indexed_sources.get(file_path))
        {
            Ok(diff) => diff,
            Err(error) => match comparison_exclusion_reason(&error) {
                Some(reason_code) => {
                    *exclusion_counts.entry(reason_code).or_default() += 1;
                    continue;
                }
                None => return Err(error),
            },
        };
        files_compared += 1;
        if !diff.is_empty() {
            results.push(FileDiff {
                file_path: file_path.clone(),
                diff,
            });
        }
    }

    for file_path in discovered_files.difference(&baseline_files) {
        let diff = match diff_bound_file(graph, file_path, binding, None) {
            Ok(diff) => diff,
            Err(error) => match comparison_exclusion_reason(&error) {
                Some(reason_code) => {
                    *exclusion_counts.entry(reason_code).or_default() += 1;
                    continue;
                }
                None => return Err(error),
            },
        };
        files_compared += 1;
        if !diff.is_empty() {
            results.push(FileDiff {
                file_path: file_path.clone(),
                diff,
            });
        }
    }

    results.sort_by(|left, right| left.file_path.cmp(&right.file_path));
    let exclusions = exclusion_counts
        .into_iter()
        .map(|(reason_code, files)| DiffExclusionSummary { reason_code, files })
        .collect();
    Ok(DiffObservation {
        scope_path: ".".into(),
        files_considered,
        files_compared,
        exclusions,
        files: results,
    })
}

fn normalize_requested_path(path: &Path) -> Result<String, DiffError> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(value) => normalized.push(value),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(DiffError::InvalidRequestedPath(path.to_path_buf()));
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(DiffError::InvalidRequestedPath(path.to_path_buf()));
    }
    normalized
        .to_str()
        .map(str::to_owned)
        .ok_or(DiffError::NonUtf8ProjectPath(normalized))
}

/// Build the one canonical removed-symbol shape used by explicit and
/// repository-wide deletion observations.
fn removed_symbol_diff(graph: &KnowledgeGraph, file_path: &str) -> SymbolDiff {
    // CI-IND-11: use the full qualified `symbol_name` (matching the ordinary
    // file-diff path) and stored 1-indexed line.
    let mut removed = graph
        .nodes_for_file(file_path)
        .into_iter()
        .map(|node| DiffEntry {
            name: node.symbol_name.clone(),
            kind: node.kind.clone(),
            file_path: file_path.to_owned(),
            line: node.line_start.map(|line| line + 1),
        })
        .collect::<Vec<_>>();
    removed.sort_by(|left, right| {
        (&left.name, &left.kind, left.line).cmp(&(&right.name, &right.kind, right.line))
    });
    SymbolDiff {
        added: Vec::new(),
        removed,
        modified: Vec::new(),
    }
}

fn validate_graph_file_path(file_path: &str) -> Result<(), DiffError> {
    let path = Path::new(file_path);
    if path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return Err(DiffError::InvalidGraphPath(path.to_path_buf()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_query::short_name;
    use crate::reachability::ReachabilityClass;

    #[test]
    fn short_name_simple() {
        assert_eq!(short_name("MyStruct::my_method"), "my_method");
        assert_eq!(short_name("standalone_fn"), "standalone_fn");
        assert_eq!(short_name("a::b::c"), "c");
    }

    // ------------------------------------------------------------------
    // CI-IND-13: replace the former tautology tests (symbol_diff_empty_default,
    // diff_entry_fields, modified_entry_fields) — which only constructed a
    // struct literal and echoed its own fields, exercising ZERO diff logic —
    // with round-trip tests that actually drive `diff_file`.
    // ------------------------------------------------------------------

    /// Helper: write `source` to `rel_path` under a fresh tempdir, build a
    /// graph from it, and return (graph, root, rel_path).
    fn build_graph_from_source(
        source: &str,
        rel_path: &str,
    ) -> (KnowledgeGraph, tempfile::TempDir) {
        use crate::edge_builder::build_graph;
        use crate::extractor::extract_file;

        let tmp = tempfile::TempDir::new().expect("create tempdir");
        let abs_path = tmp.path().join(rel_path);
        std::fs::create_dir_all(abs_path.parent().unwrap()).unwrap();
        std::fs::write(&abs_path, source).expect("write source");

        let output = extract_file(&abs_path, tmp.path()).expect("extract_file");
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).expect("build_graph");
        (graph, tmp)
    }

    fn diff_workspace(graph: &KnowledgeGraph, root: &Path) -> Result<Vec<FileDiff>, DiffError> {
        let binding = ProjectBinding::explicit(root, &root.join(".h00ligan/code-intel"))
            .expect("test project binding");
        diff_bound(graph, &binding, &BTreeMap::new(), &BTreeMap::new(), None)
            .map(|observation| observation.files)
    }

    fn diff_one(
        graph: &KnowledgeGraph,
        root: &Path,
        relative: &str,
    ) -> Result<SymbolDiff, DiffError> {
        let binding = ProjectBinding::explicit(root, &root.join(".h00ligan/code-intel"))
            .expect("test project binding");
        diff_bound_file(graph, relative, &binding, None)
    }

    /// Round-trip: diffing an unchanged graph+source yields nothing, and
    /// editing exactly one function body surfaces exactly that symbol in
    /// `modified` with `old_hash != new_hash` (drives the compare logic that
    /// the old `diff_entry_fields`/`modified_entry_fields` tautologies never
    /// touched).
    #[test]
    fn diff_file_round_trip_detects_single_modification() {
        let source = r#"
            pub fn alpha() -> u32 {
                1
            }

            pub fn beta() -> u32 {
                2
            }
        "#;
        let rel_path = "src/lib.rs";
        let (graph, tmp) = build_graph_from_source(source, rel_path);

        // Unchanged: everything empty.
        let diff = diff_one(&graph, tmp.path(), rel_path).expect("bound diff unchanged");
        assert!(diff.added.is_empty(), "unchanged: no added");
        assert!(diff.removed.is_empty(), "unchanged: no removed");
        assert!(diff.modified.is_empty(), "unchanged: no modified");

        // Edit exactly `beta`'s body; re-write source on disk.
        let modified_source = r#"
            pub fn alpha() -> u32 {
                1
            }

            pub fn beta() -> u32 {
                99
            }
        "#;
        std::fs::write(tmp.path().join(rel_path), modified_source).expect("rewrite");

        let diff = diff_one(&graph, tmp.path(), rel_path).expect("bound diff modified");
        assert!(
            diff.added.is_empty(),
            "modify-only: no added, got {:?}",
            diff.added
        );
        assert!(
            diff.removed.is_empty(),
            "modify-only: no removed, got {:?}",
            diff.removed
        );
        assert_eq!(
            diff.modified.len(),
            1,
            "exactly one symbol modified, got {:?}",
            diff.modified.iter().map(|m| &m.name).collect::<Vec<_>>()
        );
        let m = &diff.modified[0];
        assert!(
            m.name.contains("beta"),
            "modified symbol should be beta, got {}",
            m.name
        );
        assert_ne!(m.old_hash, m.new_hash, "modified hashes must differ");
    }

    /// Round-trip: a symbol genuinely added and another genuinely removed are
    /// reported in the precise add/remove sets.
    #[test]
    fn diff_file_round_trip_detects_add_and_remove() {
        let original = r#"
            pub fn keep_me() -> u32 {
                1
            }

            pub fn remove_me() -> u32 {
                2
            }
        "#;
        let rel_path = "src/lib.rs";
        let (graph, tmp) = build_graph_from_source(original, rel_path);

        // Rewrite: drop `remove_me`, add `add_me`.
        let edited = r#"
            pub fn keep_me() -> u32 {
                1
            }

            pub fn add_me() -> u32 {
                3
            }
        "#;
        std::fs::write(tmp.path().join(rel_path), edited).expect("rewrite");

        let diff = diff_one(&graph, tmp.path(), rel_path).expect("bound diff");
        let added: Vec<&str> = diff.added.iter().map(|e| e.name.as_str()).collect();
        let removed: Vec<&str> = diff.removed.iter().map(|e| e.name.as_str()).collect();

        assert!(
            added.iter().any(|n| n.contains("add_me")),
            "add_me should be in added, got {added:?}"
        );
        assert!(
            removed.iter().any(|n| n.contains("remove_me")),
            "remove_me should be in removed, got {removed:?}"
        );
        assert!(
            !removed.iter().any(|n| n.contains("keep_me")),
            "keep_me must not be removed, got {removed:?}"
        );
    }

    #[test]
    fn diff_entries_with_one_name_are_ordered_by_kind() {
        let rel_path = "src/lib.rs";
        let (graph, temporary) = build_graph_from_source("", rel_path);
        std::fs::write(
            temporary.path().join(rel_path),
            "pub struct Shared { pub value: u32 }\n\
             pub enum Shared { One }\n\
             pub trait Shared {}\n\
             pub fn Shared() {}\n\
             pub type Shared = u32;\n\
             pub const Shared: u32 = 1;\n\
             pub static Shared: u32 = 1;\n",
        )
        .expect("write distinct symbol kinds sharing one name");

        let diff = diff_one(&graph, temporary.path(), rel_path).expect("diff candidate");
        let shared_kinds = diff
            .added
            .iter()
            .filter(|entry| entry.name == "Shared")
            .map(|entry| entry.kind.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            shared_kinds,
            vec![
                "const",
                "enum",
                "function",
                "static",
                "struct",
                "trait",
                "type_alias",
            ],
            "equal-name symbols must not inherit randomized HashMap iteration order"
        );
    }

    // ------------------------------------------------------------------
    // CI-IND-01: type-alias kind key must use Display, not Debug.
    // ------------------------------------------------------------------

    /// A file containing a `type` alias diffs clean against its own graph (RED
    /// on HEAD — the fresh side keyed the alias by Debug ("typealias") while
    /// the stored side used Display ("type_alias"), so the alias showed up as
    /// both added and removed on every unchanged file).
    #[test]
    fn diff_file_type_alias_unchanged_is_clean() {
        let source = r#"
            pub type MyResult = Result<u32, String>;

            pub struct Marker {
                pub id: u32,
            }

            pub fn use_alias() -> MyResult {
                Ok(1)
            }
        "#;
        let rel_path = "src/lib.rs";
        let (graph, tmp) = build_graph_from_source(source, rel_path);

        let diff = diff_one(&graph, tmp.path(), rel_path).expect("bound diff");
        let added: Vec<(&str, &str)> = diff
            .added
            .iter()
            .map(|e| (e.kind.as_str(), e.name.as_str()))
            .collect();
        let removed: Vec<(&str, &str)> = diff
            .removed
            .iter()
            .map(|e| (e.kind.as_str(), e.name.as_str()))
            .collect();
        assert!(
            diff.added.is_empty(),
            "type alias produced spurious 'added': {added:?}"
        );
        assert!(
            diff.removed.is_empty(),
            "type alias produced spurious 'removed': {removed:?}"
        );
    }

    // ------------------------------------------------------------------
    // CI-IND-10: diff_workspace must FS-walk for new files.
    // ------------------------------------------------------------------

    /// A new `.rs` file on disk but absent from the graph is discovered by
    /// `diff_workspace` and its symbols reported as `added` (RED on HEAD —
    /// `diff_workspace` only iterated graph files, so a brand-new file was
    /// invisible).
    #[test]
    fn diff_workspace_discovers_new_files() {
        use crate::edge_builder::build_graph;
        use crate::extractor::extract_file;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        // File A: in the graph.
        let a_rel = "crates/x/src/lib.rs";
        let a_abs = tmp.path().join(a_rel);
        std::fs::create_dir_all(a_abs.parent().unwrap()).unwrap();
        std::fs::write(&a_abs, "pub fn known_fn() -> u32 {\n    1\n}\n").expect("write A");
        let output = extract_file(&a_abs, tmp.path()).expect("extract A");
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).expect("build_graph");

        // File B: on disk, NOT in the graph.
        let b_rel = "crates/x/src/newmod.rs";
        let b_abs = tmp.path().join(b_rel);
        std::fs::write(&b_abs, "pub fn brand_new_fn() -> u32 {\n    42\n}\n").expect("write B");

        let results = diff_workspace(&graph, tmp.path()).expect("diff_workspace");
        let b_diff = results
            .iter()
            .find(|fd| fd.file_path == b_rel)
            .unwrap_or_else(|| {
                panic!(
                    "diff_workspace should discover new file {b_rel}; got files: {:?}",
                    results.iter().map(|fd| &fd.file_path).collect::<Vec<_>>()
                )
            });
        assert!(
            !b_diff.diff.added.is_empty(),
            "new file B should report added symbols, got {:?}",
            b_diff.diff.added
        );
        assert!(
            b_diff
                .diff
                .added
                .iter()
                .any(|e| e.name.contains("brand_new_fn")),
            "brand_new_fn should be in B's added set"
        );
    }

    /// Workspace diff follows the language registry, not a Rust-only file
    /// suffix. A changed Go symbol already present in the graph must therefore
    /// be reported through the same operation as a changed Rust symbol.
    #[test]
    fn diff_workspace_reports_changed_go_source() {
        use crate::edge_builder::build_graph;
        use crate::extractor::extract_file;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let rel_path = "cmd/server/main.go";
        let abs_path = tmp.path().join(rel_path);
        std::fs::create_dir_all(abs_path.parent().unwrap()).expect("source directory");
        std::fs::write(
            &abs_path,
            "package main\n\nfunc Answer() int {\n\treturn 42\n}\n",
        )
        .expect("write original Go source");
        let output = extract_file(&abs_path, tmp.path()).expect("extract original Go source");
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).expect("build graph");

        std::fs::write(
            &abs_path,
            "package main\n\nfunc Answer() int {\n\treturn 99\n}\n",
        )
        .expect("modify Go source");

        let results = diff_workspace(&graph, tmp.path()).expect("workspace diff");
        let file = results
            .iter()
            .find(|file| file.file_path == rel_path)
            .unwrap_or_else(|| panic!("changed Go file was absent from diff: {results:?}"));
        assert_eq!(file.diff.modified.len(), 1, "{file:?}");
        assert!(
            file.diff.modified[0].name.contains("Answer"),
            "changed Go symbol must be reported: {file:?}"
        );
    }

    /// A repository is not required to use Cargo's `crates/` layout. New
    /// registered source beneath any in-root directory must be visible.
    #[test]
    fn diff_workspace_discovers_new_source_outside_crates_directory() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let rel_path = "src/new_root_module.rs";
        let abs_path = tmp.path().join(rel_path);
        std::fs::create_dir_all(abs_path.parent().unwrap()).expect("source directory");
        std::fs::write(&abs_path, "pub fn visible_everywhere() {}\n").expect("write new source");

        let results = diff_workspace(&KnowledgeGraph::new(), tmp.path()).expect("workspace diff");
        let file = results
            .iter()
            .find(|file| file.file_path == rel_path)
            .unwrap_or_else(|| panic!("new root source was absent from diff: {results:?}"));
        assert!(
            file.diff
                .added
                .iter()
                .any(|entry| entry.name.contains("visible_everywhere")),
            "new root source symbol must be reported: {file:?}"
        );
    }

    /// Extraction failure is not an empty diff. Returning success here would
    /// give callers false authority that the workspace matches its snapshot.
    #[test]
    fn diff_workspace_propagates_source_extraction_failure() {
        use crate::edge_builder::build_graph;
        use crate::extractor::extract_file;

        let tmp = tempfile::TempDir::new().expect("tempdir");
        let rel_path = "src/lib.rs";
        let abs_path = tmp.path().join(rel_path);
        std::fs::create_dir_all(abs_path.parent().unwrap()).expect("source directory");
        std::fs::write(&abs_path, "pub fn previously_valid() {}\n").expect("write original source");
        let output = extract_file(&abs_path, tmp.path()).expect("extract original source");
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).expect("build graph");

        std::fs::write(&abs_path, [0xff, 0xfe, 0xfd]).expect("write invalid UTF-8 source");
        let error = diff_workspace(&graph, tmp.path())
            .expect_err("invalid source must not be silently reported as unchanged");
        assert!(
            error.to_string().contains("UTF-8"),
            "wrong failure escaped workspace diff: {error}"
        );
    }

    // ------------------------------------------------------------------
    // CI-IND-11: removed-entry shape must be consistent across both paths.
    // ------------------------------------------------------------------

    /// The `removed` DiffEntry shape (qualified name + line policy) is the same
    /// whether the removal comes from `diff_file` (symbol gone from a still-
    /// present file) or from `diff_workspace`'s deleted-file branch (RED on
    /// HEAD — the deleted-file path used `short_name` + `Some(line)` while
    /// `diff_file` used the full name + `None`).
    #[test]
    fn removed_entry_shape_consistent_across_paths() {
        use crate::edge_builder::build_graph;
        use crate::extractor::extract_file;

        // A struct with an impl method `Foo::bar` so the qualified name has `::`.
        let source = r#"
            pub struct Foo;

            impl Foo {
                pub fn bar(&self) -> u32 {
                    1
                }
            }
        "#;
        let rel_path = "crates/x/src/lib.rs";

        // --- Path 1: diff_file with the method genuinely removed ---
        let tmp1 = tempfile::TempDir::new().expect("tempdir1");
        let abs1 = tmp1.path().join(rel_path);
        std::fs::create_dir_all(abs1.parent().unwrap()).unwrap();
        std::fs::write(&abs1, source).expect("write1");
        let out1 = extract_file(&abs1, tmp1.path()).expect("extract1");
        let mut graph1 = KnowledgeGraph::new();
        build_graph(&[out1], &mut graph1).expect("build1");
        // Rewrite the file removing `bar`.
        std::fs::write(&abs1, "pub struct Foo;\n").expect("rewrite1");
        let diff1 = diff_one(&graph1, tmp1.path(), rel_path).expect("bound diff1");
        let bar_removed_diff_file = diff1
            .removed
            .iter()
            .find(|e| e.name.contains("bar"))
            .expect("diff_file should report bar as removed");

        // --- Path 2: diff_workspace deleted-file branch ---
        let tmp2 = tempfile::TempDir::new().expect("tempdir2");
        let abs2 = tmp2.path().join(rel_path);
        std::fs::create_dir_all(abs2.parent().unwrap()).unwrap();
        std::fs::write(&abs2, source).expect("write2");
        let out2 = extract_file(&abs2, tmp2.path()).expect("extract2");
        let mut graph2 = KnowledgeGraph::new();
        build_graph(&[out2], &mut graph2).expect("build2");
        // Delete the file from disk so diff_workspace takes the deleted branch.
        std::fs::remove_file(&abs2).expect("remove2");
        let results2 = diff_workspace(&graph2, tmp2.path()).expect("diff_workspace2");
        let fd2 = results2
            .iter()
            .find(|fd| fd.file_path == rel_path)
            .expect("diff_workspace should report the deleted file");
        let bar_removed_workspace = fd2
            .diff
            .removed
            .iter()
            .find(|e| e.name.contains("bar"))
            .expect("diff_workspace deleted-file should report bar as removed");

        // Both paths must agree on the NAME (full qualified, contains `::`).
        assert_eq!(
            bar_removed_diff_file.name, bar_removed_workspace.name,
            "removed name shape must match across paths"
        );
        assert!(
            bar_removed_workspace.name.contains("::"),
            "deleted-file removed name should be qualified (Foo::bar), got {}",
            bar_removed_workspace.name
        );
        // Both must agree on the LINE policy (both Some after the fix).
        assert_eq!(
            bar_removed_diff_file.line.is_some(),
            bar_removed_workspace.line.is_some(),
            "removed line policy must match across paths (diff_file={:?}, workspace={:?})",
            bar_removed_diff_file.line,
            bar_removed_workspace.line
        );
    }

    // BUG-7: Verify stored key uses full symbol_name, not short_name.
    // Before the fix, stored used short_name ("ContextEnricher") while fresh
    // used full name ("crate::copro::enricher::ContextEnricher"), causing
    // every use import to appear as both added and removed.
    #[test]
    fn diff_stored_key_uses_full_symbol_name() {
        use crate::graph::{GraphNode, KnowledgeGraph};
        use uuid::Uuid;

        let mut graph = KnowledgeGraph::new();
        let node = GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: "crate::copro::enricher::ContextEnricher".into(),
            kind: "use".into(),
            file_path: "src/lib.rs".into(),
            content_hash: "abc123".into(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: Some(1),
            line_end: Some(1),
            has_body: None,
            visibility: String::new(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        };
        graph.add_node(node).unwrap();

        // Build the stored map the same way diff_file does.
        let stored_nodes = graph.nodes_for_file("src/lib.rs");
        let mut stored: HashMap<(String, String), &str> = HashMap::new();
        for node in &stored_nodes {
            stored.insert(
                (node.kind.clone(), node.symbol_name.clone()),
                &node.content_hash,
            );
        }

        // The key should use the full name, not short_name.
        assert!(
            stored.contains_key(&(
                "use".to_string(),
                "crate::copro::enricher::ContextEnricher".to_string()
            )),
            "Stored key should use full symbol_name, not short_name"
        );
        assert!(
            !stored.contains_key(&("use".to_string(), "ContextEnricher".to_string())),
            "Stored key should NOT use short_name (BUG-7)"
        );
    }

    // FIX-2 (2026-04-17): fresh and stored maps must use the same key shape.
    // Before FIX-2 the stored side used qualified names (`Foo::bar`) while
    // the fresh side used bare `sym.name` (`bar`), so every method on an
    // unchanged file appeared as both added (in fresh) and removed (from
    // stored) — generating ~161 false positives in DiffHandler.
    #[test]
    fn diff_file_on_unchanged_source_returns_zero() {
        use crate::edge_builder::build_graph;
        use crate::extractor::extract_file;
        use crate::graph::KnowledgeGraph;
        use tempfile::TempDir;

        // Build a small Rust file with at least one struct + impl method so
        // the fresh/stored key shape difference would be visible.
        let source = r#"
            pub struct Widget {
                pub name: String,
            }

            impl Widget {
                pub fn new(name: String) -> Self {
                    Self { name }
                }

                pub fn greet(&self) -> String {
                    format!("Hello, {}!", self.name)
                }
            }

            pub fn free_function() -> u32 {
                42
            }
        "#;

        let tmp = TempDir::new().expect("create tempdir");
        let rel_path = "src/widget.rs";
        let abs_path = tmp.path().join(rel_path);
        std::fs::create_dir_all(abs_path.parent().unwrap()).unwrap();
        std::fs::write(&abs_path, source).expect("write source");

        // Extract symbols and build a graph from the same file.
        let output = extract_file(&abs_path, tmp.path()).expect("extract_file");
        let mut graph = KnowledgeGraph::new();
        build_graph(&[output], &mut graph).expect("build_graph");

        // Now diff the file against the graph we just built from it.
        let diff = diff_one(&graph, tmp.path(), rel_path).expect("bound diff");

        assert!(
            diff.added.is_empty(),
            "FIX-2 regression: unchanged file produced {} spurious 'added' entries: {:?}",
            diff.added.len(),
            diff.added
                .iter()
                .map(|e| (&e.kind, &e.name))
                .collect::<Vec<_>>(),
        );
        assert!(
            diff.removed.is_empty(),
            "FIX-2 regression: unchanged file produced {} spurious 'removed' entries: {:?}",
            diff.removed.len(),
            diff.removed
                .iter()
                .map(|e| (&e.kind, &e.name))
                .collect::<Vec<_>>(),
        );
        assert!(
            diff.modified.is_empty(),
            "FIX-2 regression: unchanged file produced {} spurious 'modified' entries",
            diff.modified.len(),
        );
    }
}
