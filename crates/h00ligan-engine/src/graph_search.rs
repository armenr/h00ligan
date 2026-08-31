//! Unified search infrastructure for code intelligence queries.
//!
//! Provides the deterministic graph-search kernel below the versioned Find
//! use case. Product request bounds, authority, paging, and serialization live
//! in `code_intel_find`; adapters do not call this module directly.

use crate::graph::KnowledgeGraph;
use crate::graph_query::{MatchTier, find_all_nodes_by_name, is_top_level_kind, short_name};
use crate::structural_ir::{SymbolRole, symbol_kind_has_role};

// ============================================================================
// FindResult
// ============================================================================

/// A unified search result returned by `search_by_name` and `search_by_path`.
#[derive(Debug, Clone)]
pub struct FindResult {
    /// Exact graph identity used by the generation-bound Find projection.
    pub memory_id: uuid::Uuid,
    match_rank: u8,
    pub symbol_name: String,
    pub kind: String,
    pub file_path: String,
    pub line_start: Option<usize>,
    pub signature: String,
    pub visibility: String,
}

// ============================================================================
// Query detection
// ============================================================================

/// Returns `true` if `query` looks like a file path rather than a symbol name.
pub fn is_path_query(query: &str) -> bool {
    query.contains('/') || is_source_file_query(query) || query.starts_with("crates/")
}

/// Whether a path-shaped query names a single SOURCE FILE (vs a directory).
///
/// WU-0024 item 3 (LB-01): keyed off the language REGISTRY — `.rs` AND `.go` —
/// never a hard-coded `.rs`. The old `ends_with(".rs")` gate sent an exact
/// `.go` file path down the directory-prefix branch
/// (`nodes_for_directory("…/x.go/")`), which returned a CONFIDENT-EMPTY
/// result — the lying-zero shape. Shared by `search_by_path`, the CLI `deps`
/// handler, and the MCP `deps` handler (one predicate, three sites — the
/// CLI≡MCP parity rule).
pub fn is_source_file_query(query: &str) -> bool {
    std::path::Path::new(query)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(crate::language::is_registered_extension)
}

// ============================================================================
// Glob matching
// ============================================================================

/// Simple glob matching: supports `*` as wildcard for zero or more characters.
///
/// Handles patterns like `*Handler`, `run_*`, and `*status*`.
/// Matching is case-insensitive.
pub fn glob_match(name: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();

    if parts.len() == 1 {
        // No wildcard, exact match.
        return name == pattern;
    }

    let name_lower = name.to_lowercase();
    let mut pos = 0;

    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let part_lower = part.to_lowercase();
        if let Some(found) = name_lower[pos..].find(&part_lower) {
            if i == 0 && found != 0 {
                // First segment must match at start (no leading `*`).
                return false;
            }
            pos += found + part_lower.len();
        } else {
            return false;
        }
    }

    // If pattern does not end with `*`, the last segment must end at the string end.
    if !pattern.ends_with('*') {
        let last_part = parts.last().unwrap_or(&"");
        if !last_part.is_empty() {
            return name_lower.ends_with(&last_part.to_lowercase());
        }
    }

    true
}

// ============================================================================
// Search by name
// ============================================================================

/// Search symbols by name, with optional glob pattern support.
///
/// If `query` contains `*`, uses glob matching against all nodes.
/// Otherwise, uses `find_all_nodes_by_name` (exact/suffix/substring).
/// Results are filtered by `kind_filter`, then truncated to `limit`.
///
/// Search is deliberately structural: it never hides a matching symbol based
/// on a semantic reachability classification. Callers decide whether that
/// classification is authoritative enough to render as an annotation.
pub fn search_by_name(
    graph: &KnowledgeGraph,
    query: &str,
    kind_filter: Option<&str>,
    definitions_only: bool,
    limit: usize,
) -> Vec<FindResult> {
    let has_glob = query.contains('*');

    let mut results: Vec<FindResult> = if has_glob {
        let nodes = graph.all_nodes();
        nodes
            .iter()
            .filter(|n| glob_match(&n.symbol_name, query))
            .filter(|n| kind_filter.is_none_or(|k| n.kind.eq_ignore_ascii_case(k)))
            .filter(|n| !definitions_only || symbol_kind_has_role(&n.kind, SymbolRole::Definition))
            .map(|n| FindResult {
                memory_id: n.memory_id,
                match_rank: 0,
                symbol_name: n.symbol_name.clone(),
                kind: n.kind.clone(),
                file_path: n.file_path.clone(),
                line_start: n.line_start.map(|l| l + 1),
                signature: if n.signature.is_empty() {
                    format!("{} {}", n.kind, short_name(&n.symbol_name))
                } else {
                    n.signature.clone()
                },
                visibility: extract_visibility(&n.visibility, &n.signature),
            })
            .collect()
    } else {
        let matches = find_all_nodes_by_name(graph, query);
        matches
            .into_iter()
            // Exclude substring matches by default — use glob (*query*) for substring.
            .filter(|m| m.tier != MatchTier::Substring)
            .filter(|m| kind_filter.is_none_or(|k| m.node.kind.eq_ignore_ascii_case(k)))
            .filter(|m| {
                !definitions_only || symbol_kind_has_role(&m.node.kind, SymbolRole::Definition)
            })
            .map(|m| {
                let n = m.node;
                FindResult {
                    memory_id: n.memory_id,
                    match_rank: match m.tier {
                        MatchTier::Exact => 0,
                        MatchTier::Suffix => 1,
                        MatchTier::Substring => 2,
                    },
                    symbol_name: n.symbol_name.clone(),
                    kind: n.kind.clone(),
                    file_path: n.file_path.clone(),
                    line_start: n.line_start.map(|l| l + 1),
                    signature: if n.signature.is_empty() {
                        format!("{} {}", n.kind, short_name(&n.symbol_name))
                    } else {
                        n.signature.clone()
                    },
                    visibility: extract_visibility(&n.visibility, &n.signature),
                }
            })
            .collect()
    };

    results.sort_by(|left, right| {
        left.match_rank.cmp(&right.match_rank).then(
            left.symbol_name
                .cmp(&right.symbol_name)
                .then(left.file_path.cmp(&right.file_path))
                .then(left.line_start.cmp(&right.line_start))
                .then(left.kind.cmp(&right.kind))
                .then(left.memory_id.cmp(&right.memory_id)),
        )
    });
    results.truncate(limit);
    results
}

// ============================================================================
// Search by path
// ============================================================================

/// Search symbols by file path or directory prefix.
///
/// If `query` has a registered source extension, finds symbols in that exact
/// file. Otherwise, treats `query` as a directory prefix and finds symbols in
/// all files under that directory.
pub fn search_by_path(
    graph: &KnowledgeGraph,
    query: &str,
    kind_filter: Option<&str>,
    definitions_only: bool,
    limit: usize,
) -> Vec<FindResult> {
    let is_file = is_source_file_query(query);

    let mut results: Vec<FindResult> = if is_file {
        let nodes = graph.nodes_for_file(query);
        nodes
            .into_iter()
            .filter(|n| is_top_level_kind(&n.kind))
            .filter(|n| kind_filter.is_none_or(|k| n.kind.eq_ignore_ascii_case(k)))
            .filter(|n| !definitions_only || symbol_kind_has_role(&n.kind, SymbolRole::Definition))
            .map(|n| FindResult {
                memory_id: n.memory_id,
                match_rank: 0,
                symbol_name: n.symbol_name.clone(),
                kind: n.kind.clone(),
                file_path: n.file_path.clone(),
                line_start: n.line_start.map(|l| l + 1),
                signature: if n.signature.is_empty() {
                    format!("{} {}", n.kind, short_name(&n.symbol_name))
                } else {
                    n.signature.clone()
                },
                visibility: extract_visibility(&n.visibility, &n.signature),
            })
            .collect()
    } else {
        let prefix = if query.is_empty() {
            String::new()
        } else if query.ends_with('/') {
            query.to_string()
        } else {
            format!("{query}/")
        };
        let file_groups = graph.nodes_for_directory(&prefix);
        file_groups
            .into_iter()
            .flat_map(|(_, nodes)| nodes)
            .filter(|n| is_top_level_kind(&n.kind))
            .filter(|n| kind_filter.is_none_or(|k| n.kind.eq_ignore_ascii_case(k)))
            .filter(|n| !definitions_only || symbol_kind_has_role(&n.kind, SymbolRole::Definition))
            .map(|n| FindResult {
                memory_id: n.memory_id,
                match_rank: 0,
                symbol_name: n.symbol_name.clone(),
                kind: n.kind.clone(),
                file_path: n.file_path.clone(),
                line_start: n.line_start.map(|l| l + 1),
                signature: if n.signature.is_empty() {
                    format!("{} {}", n.kind, short_name(&n.symbol_name))
                } else {
                    n.signature.clone()
                },
                visibility: extract_visibility(&n.visibility, &n.signature),
            })
            .collect()
    };

    results.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then(a.line_start.cmp(&b.line_start))
            .then(a.symbol_name.cmp(&b.symbol_name))
            .then(a.kind.cmp(&b.kind))
            .then(a.memory_id.cmp(&b.memory_id))
    });

    results.truncate(limit);
    results
}

// ============================================================================
// Visibility extraction
// ============================================================================

/// Extract visibility from the node's visibility field or parse from signature.
///
/// The `visibility` field on `GraphNode` may be populated by the extractor
/// (e.g. "Public", "CrateVisible"). If empty, we fall back to parsing the
/// signature prefix for "pub " / "pub(crate) " / "pub(super) ".
fn extract_visibility(node_visibility: &str, signature: &str) -> String {
    // If the node already has a parsed visibility, normalize it.
    if !node_visibility.is_empty() {
        return match node_visibility {
            "Public" => "pub".to_string(),
            "CrateVisible" => "pub(crate)".to_string(),
            "Private" => "private".to_string(),
            other => other.to_lowercase(),
        };
    }

    // Fall back to parsing the signature prefix.
    if signature.starts_with("pub(crate) ") {
        "pub(crate)".to_string()
    } else if signature.starts_with("pub(super) ") {
        "pub(super)".to_string()
    } else if signature.starts_with("pub ") {
        "pub".to_string()
    } else {
        "private".to_string()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_match_star_suffix() {
        assert!(glob_match("RunHandler", "Run*"));
        assert!(!glob_match("MyRunHandler", "Run*"));
    }

    #[test]
    fn glob_match_star_prefix() {
        assert!(glob_match("RunHandler", "*Handler"));
        assert!(glob_match("FooHandler", "*Handler"));
    }

    #[test]
    fn glob_match_star_both() {
        assert!(glob_match("MyRunHandler", "*Run*"));
        assert!(glob_match("RunHandler", "*Run*"));
    }

    #[test]
    fn glob_match_no_wildcard() {
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("nope", "exact"));
    }

    #[test]
    fn glob_match_case_insensitive() {
        assert!(glob_match("fooHandler", "*handler"));
    }

    #[test]
    fn is_path_query_detection() {
        assert!(is_path_query("crates/h00ligan-engine/src/lib.rs"));
        assert!(is_path_query("src/main.rs"));
        assert!(is_path_query("crates/h00ligan-engine"));
        assert!(!is_path_query("find_node_by_name"));
        assert!(!is_path_query("GraphNode"));
    }

    /// WU-0024 item 3 (LB-01): path-shaped detection must be registry-keyed —
    /// a bare `.go` filename is a path query exactly like a bare `.rs` one.
    #[test]
    fn is_path_query_detects_go_files() {
        assert!(is_path_query("internal/sftp/handlers.go"));
        assert!(is_path_query("main.go"));
    }

    fn lb01_node(name: &str, file: &str) -> crate::graph::GraphNode {
        crate::graph::GraphNode {
            memory_id: uuid::Uuid::new_v4(),
            symbol_name: name.to_string(),
            kind: "function".to_string(),
            file_path: file.to_string(),
            content_hash: format!("h-{name}"),
            signature: String::new(),
            reachability_class: crate::reachability::ReachabilityClass::Unclassified,
            line_start: Some(1),
            line_end: Some(10),
            has_body: Some(true),
            visibility: "pub".to_string(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        }
    }

    /// WU-0024 item 3 (LB-01): an EXACT source-file path — `.go` included —
    /// must route to the FILE branch and return its symbols. On HEAD the
    /// `.rs`-only gate sent `…/handlers.go` down the directory-prefix branch
    /// (`nodes_for_directory("…/handlers.go/")`) → a confident-empty result:
    /// the lying-zero shape.
    #[test]
    fn search_by_path_resolves_exact_go_file() {
        let mut graph = crate::graph::KnowledgeGraph::new();
        graph
            .add_node(lb01_node("HandleOpen", "internal/sftp/handlers.go"))
            .expect("add node");
        let results = search_by_path(&graph, "internal/sftp/handlers.go", None, false, 10);
        assert_eq!(
            results.len(),
            1,
            "LB-01: an exact .go file path must return its symbols, not a confident-empty"
        );
    }

    #[test]
    fn structural_search_never_hides_a_dead_symbol() {
        let mut graph = crate::graph::KnowledgeGraph::new();
        let mut node = lb01_node("dead_but_findable", "src/lib.rs");
        node.reachability_class = crate::reachability::ReachabilityClass::Dead;
        graph.add_node(node).expect("add dead node");

        let results = search_by_name(&graph, "dead_but_findable", None, false, 10);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].symbol_name, "dead_but_findable");
    }
}
