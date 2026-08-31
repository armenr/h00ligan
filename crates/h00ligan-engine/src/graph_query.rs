//! Shared graph query helpers for code intelligence tools.
//!
//! This module owns the shared traversal helpers, symbol matchers, edge
//! admission, and graph-derived structural queries used by the CLI and MCP.
//!
//! # Edge admission — ONE surface (WU-0003 / CL-REACH RC1)
//!
//! There is exactly one place that decides whether a given [`EdgeKind`] is
//! followed for a given traversal semantic: [`admits`], a `const fn` over
//! [`EdgeClass`]. It is an *exhaustive* match — adding a 10th `EdgeKind`
//! forces a compile error (no `_ =>` wildcard), so a new edge kind cannot be
//! silently dropped from (or admitted into) a walk.
//!
//! | `EdgeClass` | Admitted kinds | Excluded | Used by |
//! |-------------|----------------|----------|---------|
//! | `Structural` | Calls, Contains, Implements, HasImpl, References, TypeOf, FieldOf, DependsOn, Extends (9) | RelatedTo | structural expansion and inventory queries |
//! | `Dependency` | Calls, Contains, Implements, HasImpl, References, TypeOf, FieldOf (7) | RelatedTo, DependsOn, Extends | impact traversal |
//! | `Call` | Calls, References, TypeOf, FieldOf, Extends (5) | Contains, Implements, HasImpl, DependsOn, RelatedTo | liveness classification and reachability traces |
//!
//! The thin public predicate [`is_dependency_edge`] delegates to [`admits`]; the
//! human-facing "Edge filter: (…)" label is derived from the admit-set via
//! [`admit_set_label`], so the rendered label cannot drift from the filter.
//!
//! `KnowledgeGraph::reachable()` (relevance expansion) and `enrichment::is_enrichment_dep`
//! (fan / centrality) are intentionally NOT folded into `admits` — see the boundary
//! comments at those sites.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io::Write;

use tracing::instrument;
use uuid::Uuid;

use crate::code_intel_domain::LanguageId;
use crate::edge_builder::crate_of;
use crate::entry_points::{EntryPoint, EntryPointKind};
use crate::graph::{EdgeKind, EdgeSource, GraphNode, KnowledgeGraph};
use crate::reachability::{BfsSpec, ReachabilityClass};
use crate::structural_ir::{SymbolRole, symbol_kind_has_role};

// ============================================================================
// Common helpers (deduplicated from CLI + MCP)
// ============================================================================

/// Returns `true` if the given file path looks like a test file.
///
/// WU-0003 / CL-REACH-06: this is the PATH-only fallback used when no persisted
/// `is_test_only` bit is available (SCIP/old nodes). It is ANCHORED — a `tests`
/// path COMPONENT, or a basename starting with `test_` / ending in `_test.rs` /
/// `_tests.rs` — never a raw `.contains("test_")`, so decoys like
/// `src/contest_runner.rs`, `src/latest.rs`, and the fixture-DATA dir
/// `src/test_data/x.rs` do NOT false-match. When a `GraphNode` is in hand,
/// prefer [`node_is_test`] (it reads the persisted AST bit first).
pub fn is_test_file(path: &str) -> bool {
    // A `tests` directory COMPONENT (not a substring) marks a test file.
    if path.split('/').any(|c| c == "tests") {
        return true;
    }
    // Basename-anchored conventions.
    let basename = path.rsplit('/').next().unwrap_or(path);
    basename.starts_with("test_")
        || basename.ends_with("_test.rs")
        || basename.ends_with("_tests.rs")
}

/// Canonical test-ness predicate for a node-in-hand (WU-0003 / CL-REACH-06).
///
/// Reads the PERSISTED `is_test_only` AST bit when present (`Some`), falling back
/// to the anchored [`is_test_file`] path heuristic ONLY for SCIP/old nodes whose
/// bit is `None`. This is the ONE place the classifier-adjacent consumers route
/// their "is this test code?" question through, so a name/path proxy can never
/// disagree with the AST fact.
pub fn node_is_test(_graph: &KnowledgeGraph, node: &GraphNode) -> bool {
    node.is_test_only
        .unwrap_or_else(|| is_test_file(&node.file_path))
}

/// Extract the short (last segment) name from a fully-qualified symbol name.
///
/// e.g. `"MyModule::MyStruct::my_field"` → `"my_field"`.
pub fn short_name(full_name: &str) -> &str {
    full_name.rsplit("::").next().unwrap_or(full_name)
}

/// Returns `true` for top-level symbol kinds that represent independent code
/// entities (as opposed to nested items like fields or parameters).
pub fn is_top_level_kind(kind: &str) -> bool {
    symbol_kind_has_role(kind, SymbolRole::Independent)
}

/// Extract the crate name from a relative file path.
///
/// e.g. `"crates/h00ligan-engine/src/foo.rs"` → `"h00ligan-engine"`.
/// Returns an empty string if the path does not match `crates/<name>/...`.
pub fn crate_from_file(file_path: &str) -> String {
    let parts: Vec<&str> = file_path.split('/').collect();
    if parts.len() >= 2 && parts[0] == "crates" {
        parts[1].to_string()
    } else {
        String::new()
    }
}

/// Compute the Levenshtein edit distance between two strings.
///
/// Uses an O(min(a,b)) space single-row DP approach.
pub fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    // Use a single-row DP approach (O(min(a,b)) space).
    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row = vec![0; b_len + 1];

    for (i, a_char) in a.chars().enumerate() {
        curr_row[0] = i + 1;
        for (j, b_char) in b.chars().enumerate() {
            let cost = if a_char == b_char { 0 } else { 1 };
            curr_row[j + 1] = (prev_row[j + 1] + 1) // deletion
                .min(curr_row[j] + 1) // insertion
                .min(prev_row[j] + cost); // substitution
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b_len]
}

/// Find near-match candidates for a symbol name that wasn't found.
///
/// Returns up to 5 symbol names with Levenshtein distance <= 3, sorted by
/// distance. Used by both CLI and MCP to generate "did you mean?" suggestions.
pub fn symbol_not_found_candidates(graph: &KnowledgeGraph, query: &str) -> Vec<(String, usize)> {
    let query_lower = query.to_lowercase();
    let mut candidates: Vec<(String, usize)> = graph
        .all_nodes()
        .iter()
        .filter_map(|node| {
            let name = &node.symbol_name;
            let dist = levenshtein_distance(&query_lower, &name.to_lowercase());
            if dist <= 3 {
                Some((name.clone(), dist))
            } else {
                None
            }
        })
        .collect();
    candidates.sort_by(|left, right| left.1.cmp(&right.1).then(left.0.cmp(&right.0)));
    candidates.dedup_by(|a, b| a.0 == b.0);
    candidates.truncate(5);
    candidates
}

// ============================================================================
// Symbol matching
// ============================================================================

// `find_node_by_name` (first-match-wins exact > suffix > substring resolver)
// was DELETED in WU-0002 Wave 3 (ADR-0027). Its silent first-match was the
// recurring bug class; all callers migrated to `resolve_unique` (which surfaces
// ambiguity) or `find_all_nodes_by_name` (the tiered candidate set).

/// How a symbol name was matched against a graph node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchTier {
    /// Exact match on `symbol_name`.
    Exact,
    /// symbol_name ends with `::name`.
    Suffix,
    /// symbol_name contains `name` as a substring.
    Substring,
}

/// A graph node with metadata about how it was matched.
#[derive(Debug)]
pub struct SymbolMatch<'a> {
    pub node: &'a GraphNode,
    pub tier: MatchTier,
}

/// Return ALL nodes matching the given name, across all matching tiers.
/// Results are ordered: Exact first, then Suffix, then Substring.
/// Within each tier, results are sorted alphabetically by symbol_name.
///
/// Unlike a first-match resolver, this returns all matches so callers can
/// detect ambiguity (F8) and provide candidates. The resolution entry point is
/// [`resolve_unique`]; this is its tiered candidate source.
#[instrument(level = "debug", skip(graph))]
pub fn find_all_nodes_by_name<'a>(graph: &'a KnowledgeGraph, name: &str) -> Vec<SymbolMatch<'a>> {
    let mut exact: Vec<&GraphNode> = Vec::new();
    let mut suffix: Vec<&GraphNode> = Vec::new();
    let mut substring: Vec<&GraphNode> = Vec::new();

    let suffix_pat = format!("::{name}");

    // Check the name index for an exact match first
    if let Some(n) = graph.node_by_name(name) {
        exact.push(n);
    }

    // Scan all nodes for suffix and substring matches (and additional exact matches
    // that might not be in the name index if names collide)
    let nodes = graph.all_nodes();
    for node in &nodes {
        if node.symbol_name == name {
            // Avoid duplicating the exact match already found via index
            if exact.iter().all(|e| e.memory_id != node.memory_id) {
                exact.push(node);
            }
        } else if node.symbol_name.ends_with(&suffix_pat) {
            suffix.push(node);
        } else if node.symbol_name.contains(name) {
            substring.push(node);
        }
    }

    // Sort within each tier alphabetically
    exact.sort_by(|a, b| a.symbol_name.cmp(&b.symbol_name));
    suffix.sort_by(|a, b| a.symbol_name.cmp(&b.symbol_name));
    substring.sort_by(|a, b| a.symbol_name.cmp(&b.symbol_name));

    let mut results = Vec::with_capacity(exact.len() + suffix.len() + substring.len());
    for node in exact {
        results.push(SymbolMatch {
            node,
            tier: MatchTier::Exact,
        });
    }
    for node in suffix {
        results.push(SymbolMatch {
            node,
            tier: MatchTier::Suffix,
        });
    }
    for node in substring {
        results.push(SymbolMatch {
            node,
            tier: MatchTier::Substring,
        });
    }

    results
}

// ============================================================================
// Typed symbol resolution (ADR-0027 / WU-0002 EP1)
// ============================================================================

/// A unique, addressable identity for a graph node — a newtype over
/// [`GraphNode::memory_id`] (ADR-0027).
///
/// Source-backed `memory_id` values are stable over file path, qualified name,
/// and same-name occurrence ordinal, so valid repeated declarations remain
/// distinct. Wrapping the UUID in a separate type means a caller addresses the
/// unique node it resolved, never a re-resolvable bare name. Round-trips to the
/// node via [`KnowledgeGraph::node`] (O(1)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SymbolId(pub Uuid);

impl SymbolId {
    /// The inner `memory_id` (so a caller can call [`KnowledgeGraph::node`]).
    pub const fn uuid(&self) -> Uuid {
        self.0
    }
}

impl From<Uuid> for SymbolId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

/// A resolution candidate carrying the three fields the F1/F8 diagnostic
/// renderers need without re-querying the graph, plus its [`SymbolId`] so a
/// caller can reach the node directly.
///
/// All fields are read straight off the matched [`GraphNode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// The matched node's unique identity.
    pub id: SymbolId,
    /// Fully-qualified symbol name ([`GraphNode::symbol_name`]).
    pub symbol_name: String,
    /// Source file path ([`GraphNode::file_path`]).
    pub file_path: String,
    /// Symbol kind ([`GraphNode::kind`]).
    pub kind: String,
    /// Zero-based definition line when the node is source-backed.
    pub line_start: Option<usize>,
}

impl Match {
    fn from_node(node: &GraphNode) -> Self {
        Self {
            id: SymbolId(node.memory_id),
            symbol_name: node.symbol_name.clone(),
            file_path: node.file_path.clone(),
            kind: node.kind.clone(),
            line_start: node.line_start,
        }
    }

    /// The canonical structured F8 candidate label (ADR-0027): `symbol (file_path)`.
    ///
    /// The single source of truth for the ambiguous-candidate label, shared by
    /// the CLI (`composite_cmd::ambiguous_symbol_error`) and MCP
    /// (`code_intel::resolve_unique_or_tool_err`) F8 renderers so their labels are
    /// byte-for-byte identical — the CLI ≡ MCP parity contract (P-PARITY-1).
    ///
    /// Deliberately the `symbol (file_path)` pair, NOT the `file_path::symbol`
    /// form (which would trip [`crate::graph_search::is_path_query`]). The
    /// `(file_path)` parenthetical + `symbol_name` are the round-trip key a
    /// caller feeds back as a [`FileContext`] + qualified name to re-resolve to
    /// exactly one node.
    #[must_use]
    pub fn candidate_label(&self) -> String {
        if self.file_path.is_empty() {
            self.symbol_name.clone()
        } else {
            format!("{} ({})", self.symbol_name, self.file_path)
        }
    }

    /// Render ambiguity candidates without producing duplicate labels.
    ///
    /// The ordinary round-trip label remains `symbol (file)`. When multiple
    /// occurrences share that pair, append a one-based line (or, for a
    /// non-source node, its opaque graph identity) so diagnostics expose the
    /// real multiplicity instead of printing indistinguishable candidates.
    #[must_use]
    pub fn candidate_labels(candidates: &[Self]) -> Vec<String> {
        let mut populations = std::collections::BTreeMap::new();
        for candidate in candidates {
            *populations
                .entry((&candidate.symbol_name, &candidate.file_path))
                .or_insert(0usize) += 1;
        }
        candidates
            .iter()
            .map(|candidate| {
                let repeated = populations
                    .get(&(&candidate.symbol_name, &candidate.file_path))
                    .is_some_and(|count| *count > 1);
                if !repeated {
                    return candidate.candidate_label();
                }
                candidate.line_start.map_or_else(
                    || {
                        format!(
                            "{} ({}; {})",
                            candidate.symbol_name,
                            candidate.file_path,
                            candidate.id.uuid()
                        )
                    },
                    |line| {
                        format!(
                            "{} ({}:{})",
                            candidate.symbol_name,
                            candidate.file_path,
                            line + 1
                        )
                    },
                )
            })
            .collect()
    }
}

/// The candidate list of an ambiguous resolution.
///
/// Carried by the `Err` arm of [`Resolution::unique_or_report`] so a caller that
/// wants the unique id is forced to acknowledge — and can render — the ambiguity
/// (ADR-0027).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ambiguity {
    /// Every surviving candidate (≥ 2), in deterministic order.
    pub candidates: Vec<Match>,
}

/// The outcome of [`resolve_unique`] (EP1, ADR-0027).
///
/// `#[must_use]`: a dropped `Resolution` is lint-visible under `-D warnings`.
/// The `Unique` id is extractable **only** via [`Resolution::unique_or_report`],
/// which forces the caller to handle the `Ambiguous` arm — there is deliberately
/// **no** bare accessor that returns a first/any candidate, so silent
/// first-match cannot be expressed at this surface.
#[must_use = "a Resolution must be inspected — dropping it silently discards an Ambiguous candidate list (ADR-0027)"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// Exactly one node resolved.
    Unique(SymbolId),
    /// More than one candidate survived; the caller must disambiguate or report.
    Ambiguous(Vec<Match>),
    /// No node resolved at the Exact or Suffix tier.
    NotFound,
}

impl Resolution {
    /// Extract the unique [`SymbolId`], or report the ambiguity.
    ///
    /// The **only** id-extraction path (ADR-0027). On `Ambiguous` it returns
    /// `Err(Ambiguity)` carrying the full candidate list, so a caller cannot
    /// obtain the id while silently discarding the alternatives. `NotFound` maps
    /// to `Err(Ambiguity { candidates: [] })`.
    pub fn unique_or_report(self) -> Result<SymbolId, Ambiguity> {
        match self {
            Self::Unique(id) => Ok(id),
            Self::Ambiguous(candidates) => Err(Ambiguity { candidates }),
            Self::NotFound => Err(Ambiguity {
                candidates: Vec::new(),
            }),
        }
    }
}

/// An advisory file-path locality hint for [`resolve_unique`] (deliverable 4).
///
/// Wraps a single file path; `resolve_unique` takes `Option<FileContext>` so the
/// locality pre-filter is opt-in (EP4's `resolve_in_file` will take it
/// mandatorily in a later wave).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileContext {
    file_path: String,
}

impl FileContext {
    /// The locality file path.
    pub fn file_path(&self) -> &str {
        &self.file_path
    }
}

impl<S: Into<String>> From<S> for FileContext {
    fn from(path: S) -> Self {
        Self {
            file_path: path.into(),
        }
    }
}

/// EP1 (ADR-0027): resolve `query` to a single node, or surface ambiguity.
///
/// Consumes [`find_all_nodes_by_name`] (NOT `node_by_name`, which reads the
/// single-valued path and is structurally blind to exact collisions). Decision
/// ladder over the **highest non-empty tier among Exact > Suffix** (the
/// Substring tier is excluded from resolution):
///
/// 1. exactly one match → `Unique`;
/// 2. if `locality` is `Some`, a same-file > same-crate pre-filter that singles
///    out exactly one → `Unique` (a locality that singles out zero does NOT
///    manufacture a `Unique`);
/// 3. otherwise > 1 survives → `Ambiguous`;
/// 4. zero matches → `NotFound`.
///
/// There is **no** silent shortest-name / alphabetical tie-break at query time.
///
/// A `::`-qualified retry (e.g. `MemoryStore::store`) resolves via step (1): its
/// qualified name is an Exact-tier match, so it is the lone candidate at the
/// highest non-empty tier. ADR-0027's separate "qualified-suffix carve-out" was
/// struck as subsumed by the Exact tier (empirically inert; WU-0002 Wave 1).
#[instrument(level = "debug", skip(graph))]
pub fn resolve_unique(
    graph: &KnowledgeGraph,
    query: &str,
    locality: Option<FileContext>,
) -> Resolution {
    resolve_unique_matching(graph, query, locality, |_| true)
}

/// Resolve one symbol after applying a verb-owned candidate predicate.
///
/// Exact/suffix tiering, locality, and ambiguity handling remain identical to
/// [`resolve_unique`]; the predicate only removes nodes that cannot satisfy
/// the requesting verb's declared semantic role.
#[instrument(level = "debug", skip(graph, candidate_matches))]
pub fn resolve_unique_matching(
    graph: &KnowledgeGraph,
    query: &str,
    locality: Option<FileContext>,
    candidate_matches: impl Fn(&GraphNode) -> bool,
) -> Resolution {
    // Take the highest non-empty tier among Exact > Suffix. Substring is never
    // a resolution tier (ADR-0027): a substring-only match is NotFound.
    let all = find_all_nodes_by_name(graph, query)
        .into_iter()
        .filter(|candidate| candidate_matches(candidate.node))
        .collect::<Vec<_>>();
    let tier = if all.iter().any(|m| m.tier == MatchTier::Exact) {
        MatchTier::Exact
    } else if all.iter().any(|m| m.tier == MatchTier::Suffix) {
        MatchTier::Suffix
    } else {
        return Resolution::NotFound;
    };
    let candidates: Vec<&GraphNode> = all
        .iter()
        .filter(|m| m.tier == tier)
        .map(|m| m.node)
        .collect();

    // (a) exactly one at the highest tier.
    if let [only] = candidates.as_slice() {
        return Resolution::Unique(SymbolId(only.memory_id));
    }

    // (b) locality pre-filter: same-file, then same-crate. Singles-out-one wins;
    //     singles-out-zero falls through (never manufactures a Unique).
    if let Some(ctx) = &locality
        && let Some(id) = locality_pick(&candidates, ctx.file_path())
    {
        return Resolution::Unique(SymbolId(id));
    }

    // (c) > 1 survives → Ambiguous; (d) 0 → NotFound. A `::`-qualified retry
    //     resolves via step (a) (its qualified name is an Exact-tier singleton);
    //     ADR-0027's separate qualified-suffix carve-out was struck as subsumed
    //     by the Exact tier (empirically inert) — see the resolve_unique doc.
    if candidates.is_empty() {
        Resolution::NotFound
    } else {
        Resolution::Ambiguous(candidates.iter().map(|n| Match::from_node(n)).collect())
    }
}

/// Same-file > same-crate locality pre-filter (the EP1/EP2 canonical ordering,
/// query-side half). Returns `Some(id)` ONLY when a tier singles out exactly one
/// candidate; there is no shortest-name tie-break (that is EP2's build-time
/// policy, not EP1's). Returns `None` (fall through to Ambiguous) otherwise.
fn locality_pick(candidates: &[&GraphNode], source_file: &str) -> Option<Uuid> {
    if source_file.is_empty() {
        return None;
    }
    let same_file: Vec<&GraphNode> = candidates
        .iter()
        .filter(|n| n.file_path == source_file)
        .copied()
        .collect();
    if let [only] = same_file.as_slice() {
        return Some(only.memory_id);
    }
    if !same_file.is_empty() {
        // Multiple same-file matches: ambiguous at query time (no tie-break).
        return None;
    }
    let src_crate = crate_of(source_file);
    let same_crate: Vec<&GraphNode> = candidates
        .iter()
        .filter(|n| crate_of(&n.file_path) == src_crate)
        .copied()
        .collect();
    if let [only] = same_crate.as_slice() {
        return Some(only.memory_id);
    }
    None
}

// ============================================================================
// Typed symbol resolution (ADR-0027 / WU-0002 EP3 — set-valued search)
// ============================================================================

/// EP3 (ADR-0027): the **set-valued** best-effort renderer surface.
///
/// Maps every node returned by [`find_all_nodes_by_name`] to a [`Match`],
/// preserving its tier ordering: Exact > Suffix > Substring, alphabetically
/// within each tier (and **keeping** the Substring tier that EP1/EP2 drop — a
/// renderer wants every plausible candidate, not a single resolution).
///
/// Deliberately exposes **no** `.first()` / `resolve_first()` / `unwrap_or_first()`
/// helper: re-introducing one would let silent first-match re-enter via
/// `search(q).next()` (ADR-0027 EP3 + the lint/review gate). A caller that needs
/// a single verdict uses [`resolve_unique`] (EP1), not `search`.
#[instrument(level = "debug", skip(graph))]
pub fn search(graph: &KnowledgeGraph, query: &str) -> Vec<Match> {
    find_all_nodes_by_name(graph, query)
        .iter()
        .map(|m| Match::from_node(m.node))
        .collect()
}

// ============================================================================
// Typed symbol resolution (ADR-0027 / WU-0002 EP4 — mandatory-locality mutation)
// ============================================================================

/// The outcome of [`resolve_in_file`] (EP4, ADR-0027) — the mutation surface.
///
/// `#[must_use]`: a dropped `FileResolution` is lint-visible under `-D warnings`.
/// Unlike EP1's [`Resolution`], locality is a **mandatory input** and a
/// name-found-but-in-a-different-file is a **hard refuse** ([`Self::WrongFile`]),
/// never a silent cross-file edit. There is no heuristic fallback.
#[must_use = "a FileResolution must be inspected — WrongFile/NotFoundInFile must refuse the mutation (ADR-0027)"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileResolution {
    /// Exactly one node carries the query name in the requested file.
    Unique(SymbolId),
    /// The name exists, but only in other file(s): a hard refuse carrying the
    /// candidate locations so the caller can report where it actually lives. Also
    /// used when MULTIPLE same-file nodes carry the name (never silently pick).
    WrongFile {
        /// The candidate(s) found in other files (or the ambiguous same-file set).
        found_in: Vec<Match>,
    },
    /// The name is absent from the entire graph (Exact and Suffix tiers empty) —
    /// distinct from `WrongFile` (different refuse message).
    NotFoundInFile,
}

/// EP4 (ADR-0027): resolve `query` to a single node **in `file`**, or refuse.
///
/// Locality is a mandatory input (`FileContext` by value), there is **no**
/// heuristic fallback, and a name-found-but-wrong-file is a hard
/// [`FileResolution::WrongFile`] refuse — folding the post-hoc `editor.rs:313`
/// path guard into resolution so a different-file homonym can never be silently
/// edited.
///
/// Algorithm (no fallback): take the highest non-empty tier among Exact > Suffix
/// (the Substring tier is DROPPED — a substring match is never a mutation target);
/// both empty → `NotFoundInFile`. Partition that tier by `file_path == file`:
/// - exactly one same-file → `Unique`;
/// - zero same-file but ≥ 1 other-file → `WrongFile { found_in: those }`;
/// - multiple same-file → `WrongFile` (refuse; never pick — OQ-DUPNODE-safe).
#[instrument(level = "debug", skip(graph))]
pub fn resolve_in_file(graph: &KnowledgeGraph, query: &str, file: FileContext) -> FileResolution {
    resolve_in_file_matching(graph, query, file, |_| true)
}

/// Exact-file resolution with the same verb-owned candidate predicate as
/// [`resolve_unique_matching`].
#[instrument(level = "debug", skip(graph, candidate_matches))]
pub fn resolve_in_file_matching(
    graph: &KnowledgeGraph,
    query: &str,
    file: FileContext,
    candidate_matches: impl Fn(&GraphNode) -> bool,
) -> FileResolution {
    let all = find_all_nodes_by_name(graph, query)
        .into_iter()
        .filter(|candidate| candidate_matches(candidate.node))
        .collect::<Vec<_>>();
    let tier = if all.iter().any(|m| m.tier == MatchTier::Exact) {
        MatchTier::Exact
    } else if all.iter().any(|m| m.tier == MatchTier::Suffix) {
        MatchTier::Suffix
    } else {
        return FileResolution::NotFoundInFile;
    };
    let candidates: Vec<&GraphNode> = all
        .iter()
        .filter(|m| m.tier == tier)
        .map(|m| m.node)
        .collect();

    let same_file: Vec<&GraphNode> = candidates
        .iter()
        .filter(|n| n.file_path == file.file_path())
        .copied()
        .collect();

    match same_file.as_slice() {
        // Exactly one node carries the name in the requested file.
        [only] => FileResolution::Unique(SymbolId(only.memory_id)),
        // No same-file node: the name lives elsewhere — refuse with locations.
        [] => FileResolution::WrongFile {
            found_in: candidates.iter().map(|n| Match::from_node(n)).collect(),
        },
        // Multiple same-file nodes: genuinely ambiguous — refuse, never pick.
        _ => FileResolution::WrongFile {
            found_in: same_file.iter().map(|n| Match::from_node(n)).collect(),
        },
    }
}

// ============================================================================
// Trait bridging
// ============================================================================

/// Find the corresponding trait method node for an impl method node.
///
/// Given a node like `"impl MemoryStore for LanceStore::store"`, this finds
/// the trait method node `"MemoryStore::store"` in the graph.
/// Returns `None` if the node is not an impl method or the trait method is not found.
#[instrument(level = "debug", skip(graph, node), fields(symbol_name = %node.symbol_name))]
pub fn find_trait_method_for_impl<'a>(
    graph: &'a KnowledgeGraph,
    node: &GraphNode,
) -> Option<&'a GraphNode> {
    // Only applies to impl method symbols: "impl Trait for Type::method"
    let name = &node.symbol_name;
    if !name.starts_with("impl ") {
        return None;
    }

    // Find the last "::" — everything after is the method name
    let last_sep = name.rfind("::")?;
    let method_name = &name[last_sep + 2..];

    // Extract the trait name: "impl <Trait> for <Type>::method"
    // First, get the parent part (everything before ::method)
    let parent_part = &name[..last_sep];
    // parent_part looks like "impl Trait for Type"
    let stripped = parent_part.strip_prefix("impl ")?;
    let for_idx = stripped.find(" for ")?;
    let trait_name = stripped[..for_idx].trim();

    if trait_name.is_empty() || method_name.is_empty() {
        return None;
    }

    // Search for the trait method node: "TraitName::method_name"
    let trait_method_name = format!("{trait_name}::{method_name}");
    graph
        .all_nodes()
        .into_iter()
        .find(|n| n.symbol_name == trait_method_name)
}

/// Find all impl method nodes for a given trait method node (reverse bridging).
///
/// Given a node like `"MemoryStore::store"`, this finds all impl method nodes
/// matching the pattern `"impl MemoryStore for *::store"` in the graph.
///
/// This is the reverse of [`find_trait_method_for_impl`]: it bridges from
/// trait methods to their concrete implementations, enabling blast-radius
/// queries to also seed from impl methods that callers may reference.
#[instrument(level = "debug", skip(graph, node), fields(symbol_name = %node.symbol_name))]
pub fn find_impl_methods_for_trait<'a>(
    graph: &'a KnowledgeGraph,
    node: &GraphNode,
) -> Vec<&'a GraphNode> {
    let name = &node.symbol_name;

    // Must contain "::" to be a "Trait::method" pattern
    let sep_idx = match name.find("::") {
        Some(idx) => idx,
        None => return Vec::new(),
    };

    // Don't apply reverse bridging to impl methods themselves
    if name.starts_with("impl ") {
        return Vec::new();
    }

    let trait_name = &name[..sep_idx];
    let method_name = &name[sep_idx + 2..];

    if trait_name.is_empty() || method_name.is_empty() {
        return Vec::new();
    }

    // Look for nodes matching "impl {trait_name} for *::{method_name}"
    let prefix = format!("impl {trait_name} for ");
    let method_suffix = format!("::{method_name}");

    graph
        .all_nodes()
        .into_iter()
        .filter(|n| n.symbol_name.starts_with(&prefix) && n.symbol_name.ends_with(&method_suffix))
        .collect()
}

/// Seed the trait↔impl dispatch bridge from the `Implements`/`HasImpl` EDGES
/// (WU-0003 / CL-REACH RC2 / CL-REACH-05).
///
/// Unlike [`find_trait_method_for_impl`] / [`find_impl_methods_for_trait`]
/// (which parse the `"impl Trait for Type::method"` symbol-name string and so
/// silently miss any node whose name deviates from that shape), this consults
/// the graph edges the builder created from the trait↔impl relationship:
///
/// - `Concrete --Implements--> Trait` (impl block → trait)
/// - `Trait --HasImpl--> Concrete` (trait → impl block)
///
/// Those edges sit on the impl-BLOCK / trait / concrete-type nodes, so from a
/// `root` we (a) reach the bridged nodes directly via outgoing `Implements` /
/// `HasImpl`, and (b) if `root` is a method, hop to its parent impl-block /
/// type via incoming `Contains` first, then bridge from there. Returns the set
/// of bridged node ids to seed the reverse BFS from. Purely additive: callers
/// union these with the root and any name-string bridges.
fn seed_trait_bridge_via_edges(graph: &KnowledgeGraph, root: &GraphNode) -> HashSet<Uuid> {
    let mut seeds: HashSet<Uuid> = HashSet::new();

    // Candidate "anchor" nodes that may carry Implements/HasImpl edges: the
    // root itself plus its structural parent (an impl-block / trait / type the
    // root is `Contains`-nested under), reached via an incoming Contains edge.
    let mut anchors: Vec<Uuid> = vec![root.memory_id];
    for (parent_id, edge) in graph.incoming_neighbors(&root.memory_id) {
        if edge.kind == EdgeKind::Contains {
            anchors.push(parent_id);
        }
    }

    for anchor in anchors {
        for (target_id, edge) in graph.neighbors(&anchor) {
            // impl-block --Implements--> trait ; trait --HasImpl--> concrete
            if matches!(edge.kind, EdgeKind::Implements | EdgeKind::HasImpl) {
                seeds.insert(target_id);
                // Also seed the bridged node's Contains-children (the trait's
                // / concrete type's methods) so method-level callers are
                // reached even when the name-string bridge cannot resolve them.
                for (child_id, child_edge) in graph.neighbors(&target_id) {
                    if child_edge.kind == EdgeKind::Contains {
                        seeds.insert(child_id);
                    }
                }
            }
        }
    }

    seeds.remove(&root.memory_id);
    seeds
}

// ============================================================================
// Edge admission — the ONE surface (WU-0003 / CL-REACH RC1)
// ============================================================================

/// The traversal semantic an edge admission is gated on.
///
/// The `Dependency`-minus-`Contains` walk is represented by `Dependency` plus
/// [`BfsSpec::include_contains`] `= false`, not by another edge class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeClass {
    /// Maximum structural reachability: every edge except `RelatedTo` (9 kinds).
    Structural,
    /// Code + structural dependency edges (7 kinds): also drops `DependsOn` and
    /// `Extends`. Impact and dependency-summary queries use this class.
    Dependency,
    /// Directed call-reachability edge set (5 kinds): `Calls`, `References`,
    /// `TypeOf`, `FieldOf`, `Extends`. Drops `Contains` (containment is not
    /// use — a module owning a symbol does not USE it) and `DependsOn`
    /// (crate-root→dep-crate-root, zero symbol-level reachability), and never
    /// admits `Implements`/`HasImpl` (consumed structurally by the guard
    /// post-passes) or `RelatedTo`. The liveness verdict and its explanatory
    /// trace use this exact class.
    Call,
}

/// The single edge-admission decision (WU-0003 / CL-REACH RC1).
///
/// Returns `true` if an edge of `kind` is followed under the given
/// [`EdgeClass`]. Written as an EXHAUSTIVE match with NO `_ =>` wildcard:
/// adding a 10th [`EdgeKind`] variant forces exactly one edit here and fails
/// to compile until it is classified, so a new edge kind can never be
/// silently admitted or dropped.
pub const fn admits(class: EdgeClass, kind: EdgeKind) -> bool {
    match class {
        // Structural: all 9 except RelatedTo.
        EdgeClass::Structural => match kind {
            EdgeKind::Calls
            | EdgeKind::Contains
            | EdgeKind::Implements
            | EdgeKind::HasImpl
            | EdgeKind::References
            | EdgeKind::TypeOf
            | EdgeKind::FieldOf
            | EdgeKind::DependsOn
            | EdgeKind::Extends => true,
            EdgeKind::RelatedTo => false,
        },
        // Dependency: Structural minus DependsOn + Extends (7 kinds).
        EdgeClass::Dependency => match kind {
            EdgeKind::Calls
            | EdgeKind::Contains
            | EdgeKind::Implements
            | EdgeKind::HasImpl
            | EdgeKind::References
            | EdgeKind::TypeOf
            | EdgeKind::FieldOf => true,
            EdgeKind::DependsOn | EdgeKind::Extends | EdgeKind::RelatedTo => false,
        },
        // Call: directed call-reachability (5 kinds). Calls + construction/use
        // edges (References/TypeOf/FieldOf) + local supertrait (Extends). Drops
        // Contains + DependsOn; never Implements/HasImpl/RelatedTo (WU-0015).
        EdgeClass::Call => match kind {
            EdgeKind::Calls
            | EdgeKind::References
            | EdgeKind::TypeOf
            | EdgeKind::FieldOf
            | EdgeKind::Extends => true,
            EdgeKind::Contains
            | EdgeKind::DependsOn
            | EdgeKind::Implements
            | EdgeKind::HasImpl
            | EdgeKind::RelatedTo => false,
        },
    }
}

/// Derive the human-facing label for an [`EdgeClass`]'s admit-set.
///
/// The "Edge filter:" line rendered by the CLI is produced from this, so it
/// can never drift from what [`admits`] actually follows (WU-0003 / CL-REACH
/// RC1; closes the actively-wrong hand-written label).
pub fn admit_set_label(class: EdgeClass) -> String {
    const ALL_KINDS: &[EdgeKind] = &[
        EdgeKind::Calls,
        EdgeKind::Contains,
        EdgeKind::Implements,
        EdgeKind::HasImpl,
        EdgeKind::References,
        EdgeKind::TypeOf,
        EdgeKind::FieldOf,
        EdgeKind::DependsOn,
        EdgeKind::Extends,
        EdgeKind::RelatedTo,
    ];
    let admitted: Vec<String> = ALL_KINDS
        .iter()
        .filter(|k| admits(class, **k))
        .map(|k| format!("{k:?}"))
        .collect();
    admitted.join(", ")
}

/// Edge kinds for blast radius dependency analysis.
///
/// Thin adapter over [`admits`] (`EdgeClass::Dependency`), retained as a
/// standalone predicate for the call sites that inspect a single edge's kind
/// inline (e.g. depth-1 dependency filters, the cascade-delete has-alive-incoming
/// check). The transitive walks no longer pass it as a `fn(EdgeKind) -> bool` —
/// they route admission through [`BfsSpec::admits_edge`] instead (WU-0003 /
/// CL-REACH RC2). Includes Contains because it connects symbols to their parent
/// containers (e.g. impl block to trait method), required for BFS to escape from
/// structurally nested seeds. Excludes RelatedTo, DependsOn, Extends.
pub const fn is_dependency_edge(kind: EdgeKind) -> bool {
    admits(EdgeClass::Dependency, kind)
}

// ============================================================================
// The ONE traversal core — visitor-pattern BFS (WU-0003 / CL-REACH RC2)
// ============================================================================

/// One traversed node as seen by a [`graph_walk`] visitor.
#[derive(Debug, Clone, Copy)]
pub struct WalkStep {
    /// The `memory_id` of the node just reached (a root/seed at `depth == 0`,
    /// or a node discovered by following an admitted edge at `depth >= 1`).
    pub node_id: Uuid,
    /// Distance in hops from the nearest root/seed (`0` for a root/seed).
    pub depth: usize,
    /// The node we arrived from, or `None` for a root/seed.
    pub from: Option<Uuid>,
    /// The kind of edge traversed to reach this node, or `None` for a root/seed.
    pub via_edge: Option<EdgeKind>,
    /// The confidence of the edge traversed to reach this node (`0.0` for a
    /// root/seed). The exact traversed edge's confidence — never a re-lookup
    /// that could pick a different parallel edge.
    pub confidence: f32,
    /// `true` when reached by following an *incoming* edge (callee → caller /
    /// child → parent); `false` for an outgoing edge. Meaningless (`false`) for
    /// roots/seeds.
    pub incoming: bool,
}

/// What a [`graph_walk`] visitor asks the traversal to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkControl {
    /// Keep going: expand this node's admitted neighbors normally.
    Continue,
    /// Do not expand this node's children, but keep walking the rest of the
    /// frontier (this node is recorded as visited, its neighbors are not
    /// enqueued from here).
    SkipChildren,
    /// Halt the entire walk immediately (early-exit, e.g. target found).
    Stop,
}

/// The ONE BFS traversal driver every reachability/connectivity walk shares.
///
/// WU-0003 / CL-REACH RC2: replaces ~8 hand-rolled traversal loops so they
/// cannot diverge on direction, edge admission, the symmetric `HasImpl`/test-
/// module prune, edge-driven trait bridging, depth handling, or visited-set
/// dedup. Each former walk now supplies only a `visit` CLOSURE that builds its
/// specific result (a set, a path, a dependents list, a bool, chains, …); the
/// incompatible result *types* live in the closures, the *traversal* lives
/// here once.
///
/// The core owns:
/// - **Seeding** the `roots` (deduped) at depth 0, plus — when
///   `spec.trait_bridge` — the edge-driven trait↔impl seeds
///   ([`seed_trait_bridge_via_edges`]) for each root, also at depth 0.
/// - **Direction** (`Out` / `In` / `Both` per [`BfsSpec::direction`]).
/// - **Admission** via [`BfsSpec::admits_edge`] (the RC1 `admits` surface plus
///   the symmetric `HasImpl` / `Contains` prune).
/// - **The test-module prune** (`spec.skip_test_modules`), applied SYMMETRICALLY
///   to neighbors in both directions off the one canonical predicate
///   [`crate::reachability::is_test_module_symbol`].
/// - **Depth** + the optional `max_depth` cutoff (a node at `max_depth` is
///   visited but its children are not expanded — matching the historical
///   `if depth >= max_depth { continue }`).
/// - **Visited-set dedup** (each node visited at most once; the *first* arrival
///   wins, BFS-shortest).
///
/// The visitor is invoked once per node as it is first reached (roots/seeds
/// included). Its [`WalkControl`] return governs expansion: `Continue` expands,
/// `SkipChildren` records-but-does-not-expand, `Stop` halts the whole walk.
pub fn graph_walk(
    graph: &KnowledgeGraph,
    roots: &[Uuid],
    spec: &BfsSpec,
    max_depth: Option<usize>,
    mut visit: impl FnMut(WalkStep) -> WalkControl,
) {
    let mut visited: HashSet<Uuid> = HashSet::new();
    let mut queue: VecDeque<(Uuid, usize)> = VecDeque::new();

    // Seed roots (deduped, only nodes that exist).
    let mut seeds: Vec<Uuid> = Vec::new();
    for &root in roots {
        if graph.node(&root).is_some() && visited.insert(root) {
            seeds.push(root);
        }
    }
    // Edge-driven trait bridging (RC2 / CL-REACH-05): widen the seed set with
    // the trait↔impl nodes reachable from each root via Implements/HasImpl
    // EDGES (never symbol-name string parsing). Purely additive — only ever
    // adds seeds, so the walk can only widen, never narrow.
    if spec.trait_bridge {
        let mut bridge: Vec<Uuid> = Vec::new();
        for &root in &seeds {
            if let Some(node) = graph.node(&root) {
                for s in seed_trait_bridge_via_edges(graph, node) {
                    if visited.insert(s) {
                        bridge.push(s);
                    }
                }
            }
        }
        seeds.extend(bridge);
    }

    // Visit + enqueue the seeds.
    for seed in seeds {
        match visit(WalkStep {
            node_id: seed,
            depth: 0,
            from: None,
            via_edge: None,
            confidence: 0.0,
            incoming: false,
        }) {
            WalkControl::Stop => return,
            WalkControl::SkipChildren => {}
            WalkControl::Continue => queue.push_back((seed, 0)),
        }
    }

    let follow_out = spec.follows_out();
    let follow_in = spec.follows_in();

    while let Some((current, depth)) = queue.pop_front() {
        if max_depth.is_some_and(|m| depth >= m) {
            continue;
        }
        let next_depth = depth + 1;

        // Outgoing edges (caller → callee, parent → child).
        if follow_out {
            for (neighbor_id, edge) in graph.neighbors(&current) {
                if !spec.admits_edge(edge.kind, true) {
                    continue;
                }
                if spec.skip_test_modules
                    && crate::reachability::is_test_module_symbol(graph, &neighbor_id)
                {
                    continue;
                }
                if !visited.insert(neighbor_id) {
                    continue;
                }
                match visit(WalkStep {
                    node_id: neighbor_id,
                    depth: next_depth,
                    from: Some(current),
                    via_edge: Some(edge.kind),
                    confidence: edge.confidence,
                    incoming: false,
                }) {
                    WalkControl::Stop => return,
                    WalkControl::SkipChildren => {}
                    WalkControl::Continue => queue.push_back((neighbor_id, next_depth)),
                }
            }
        }

        // Incoming edges (callee → caller, child → parent).
        if follow_in {
            for (neighbor_id, edge) in graph.incoming_neighbors(&current) {
                if !spec.admits_edge(edge.kind, false) {
                    continue;
                }
                if spec.skip_test_modules
                    && crate::reachability::is_test_module_symbol(graph, &neighbor_id)
                {
                    continue;
                }
                if !visited.insert(neighbor_id) {
                    continue;
                }
                match visit(WalkStep {
                    node_id: neighbor_id,
                    depth: next_depth,
                    from: Some(current),
                    via_edge: Some(edge.kind),
                    confidence: edge.confidence,
                    incoming: true,
                }) {
                    WalkControl::Stop => return,
                    WalkControl::SkipChildren => {}
                    WalkControl::Continue => queue.push_back((neighbor_id, next_depth)),
                }
            }
        }
    }
}

// ============================================================================
// Reachability helpers
// ============================================================================

/// Format a reachability class as a short label.
///
/// WU-0003 / CL-REACH RC5: takes the now-non-`Option` class directly. The
/// former `None => "unknown"` arm becomes the explicit `Unclassified =>
/// "UNCLASSIFIED"` arm — callers passing the bare `node.reachability_class`
/// field compile unchanged.
pub const fn reachability_label(class: ReachabilityClass) -> &'static str {
    match class {
        ReachabilityClass::Wired => "WIRED",
        ReachabilityClass::PublicApi => "PUBLIC_API",
        ReachabilityClass::Structural => "STRUCTURAL",
        ReachabilityClass::TestOnly => "TEST_ONLY",
        ReachabilityClass::Dead => "DEAD",
        ReachabilityClass::Orphan => "ORPHAN",
        ReachabilityClass::Unclassified => "UNCLASSIFIED",
        ReachabilityClass::Suspected => "SUSPECTED",
        ReachabilityClass::Excluded => "EXCLUDED",
    }
}

/// Run inline reachability analysis for a single node.
///
/// Returns the classification for `memory_id`. Used as a fallback when
/// `reachability_class` is `Unclassified` (snapshot was saved before
/// `h00ligan graph reachability` was run).
///
/// OBS-1/SIMILAR (ADR-0029): returns `Result<Option<_>, EntryPointError>`, NOT
/// `Option<_>`. The former `discover_entry_points(root).ok()?` collapsed a
/// discovery ERROR to `None`, which callers folded to `Unclassified` — an error
/// masquerading as a default verdict (the very silent-swallow class this WU
/// closes, one layer in). Now a discovery error PROPAGATES; a genuine
/// "no class found for this node" still returns `Ok(None)`.
#[instrument(level = "debug", skip(graph), fields(memory_id = %memory_id))]
pub fn run_inline_reachability(
    graph: &KnowledgeGraph,
    memory_id: &Uuid,
    root: &std::path::Path,
) -> Result<Option<ReachabilityClass>, crate::entry_points::EntryPointError> {
    let entry_points = crate::entry_points::discover_entry_points(root)?;
    let analyzer = crate::reachability::ReachabilityAnalyzer::new(graph, entry_points);
    let report = analyzer.analyze();
    Ok(report
        .classified
        .iter()
        .find(|c| c.memory_id == *memory_id)
        .map(|c| c.classification))
}

// ============================================================================
// Trace instrumentation (diagnostic only)
// ============================================================================

/// A trace writer for BFS debugging. Wraps a `BufWriter<File>`.
pub struct TraceWriter {
    writer: std::io::BufWriter<std::fs::File>,
}

impl TraceWriter {
    /// Create a new trace writer, creating parent directories as needed.
    pub fn new(path: &std::path::Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::File::create(path)?;
        Ok(Self {
            writer: std::io::BufWriter::new(file),
        })
    }

    /// Write a line to the trace file.
    pub fn writeln(&mut self, msg: &str) {
        let _ = writeln!(self.writer, "{}", msg);
    }

    /// Flush the trace writer.
    pub fn flush(&mut self) {
        let _ = self.writer.flush();
    }
}

/// Resolve production binary and build-script entry points to graph root UUIDs.
///
/// Mirrors `ReachabilityAnalyzer::resolve_production_roots` logic so that
/// the traced reachability BFS can resolve roots independently without
/// modifying the `ReachabilityAnalyzer` API.
#[instrument(level = "debug", skip(graph, entry_points), fields(entry_point_count = entry_points.len()))]
pub fn resolve_production_root_ids(
    graph: &KnowledgeGraph,
    entry_points: &[EntryPoint],
) -> Vec<Uuid> {
    let all_nodes = graph.all_nodes();
    let mut file_to_nodes: HashMap<&str, Vec<Uuid>> = HashMap::new();
    for node in &all_nodes {
        file_to_nodes
            .entry(node.file_path.as_str())
            .or_default()
            .push(node.memory_id);
    }

    let mut roots = Vec::new();

    for ep in entry_points {
        if !matches!(
            ep.kind,
            EntryPointKind::Binary | EntryPointKind::BuildScript
        ) {
            continue;
        }

        let ep_path_str = ep.file_path.to_string_lossy();
        let ep_normalized = ep_path_str.strip_prefix("./").unwrap_or(&ep_path_str);

        // CL-REACH-05 (parity with `ReachabilityAnalyzer::resolve_production_roots`):
        // seed ONLY the entry symbol `main` (matched on the short name so a
        // nested `app::main` resolves), never every top-level function in the
        // file. This MUST stay in lockstep with the classifier's seeding so the
        // explanatory trace seeds from the same roots the verdict used.
        let mut file_matched = false;
        let mut symbol_resolved = false;
        for (&graph_path, node_ids) in &file_to_nodes {
            let gp_normalized = graph_path.strip_prefix("./").unwrap_or(graph_path);
            if ep_normalized.ends_with(gp_normalized) || gp_normalized.ends_with(ep_normalized) {
                file_matched = true;
                for &node_id in node_ids {
                    if let Some(node) = graph.node(&node_id)
                        && symbol_kind_has_role(&node.kind, SymbolRole::Callable)
                        && node
                            .symbol_name
                            .rsplit("::")
                            .next()
                            .unwrap_or(&node.symbol_name)
                            == "main"
                    {
                        roots.push(node_id);
                        symbol_resolved = true;
                    }
                }
            }
        }

        // Narrow fallback: an entry file matched but its `main` symbol did not
        // resolve — seed that file's nodes rather than dropping the entry. Does
        // NOT re-introduce the cross-file all-functions over-seed.
        if file_matched && !symbol_resolved {
            for (&graph_path, node_ids) in &file_to_nodes {
                let gp_normalized = graph_path.strip_prefix("./").unwrap_or(graph_path);
                if ep_normalized.ends_with(gp_normalized) || gp_normalized.ends_with(ep_normalized)
                {
                    roots.extend(node_ids);
                }
            }
        }
    }

    roots
}

/// Trace the exact directed call-reachability walk used by the liveness
/// classifier, stopping when a specific target is found.
///
/// This is explanatory evidence for the persisted verdict, so it deliberately
/// shares the classifier's complete traversal spec rather than maintaining an
/// independent path contract.
#[instrument(level = "debug", skip(graph, roots, trace), fields(target_id = %target_id, root_count = roots.len()))]
pub fn traced_reachability_bfs(
    graph: &KnowledgeGraph,
    roots: &[Uuid],
    target_id: Uuid,
    trace: &mut TraceWriter,
) -> Option<Vec<Uuid>> {
    let node_label = |id: &Uuid| -> String {
        graph
            .node(id)
            .map(|n| format!("'{}' ({}, {})", n.symbol_name, n.file_path, n.kind))
            .unwrap_or_else(|| format!("<?> (uuid={id})"))
    };

    let target_label = node_label(&target_id);
    trace.writeln("REACHABILITY TRACE");
    trace.writeln(&format!(
        "Graph: {} nodes, {} edges",
        graph.node_count(),
        graph.edge_count()
    ));
    trace.writeln(&format!(
        "Edge filter: Call ({})",
        admit_set_label(EdgeClass::Call)
    ));
    trace.writeln(&format!("Target: {target_label} (UUID: {target_id})"));
    trace.writeln(&format!("Roots: {} entry points", roots.len()));
    for root in roots {
        trace.writeln(&format!("  Root: {}", node_label(root)));
    }
    trace.writeln("");

    // Route through the shared traversal core with the exact classifier contract.
    // The interleaved trace is emitted from the visitor: it sees each traversed node
    // with its `from`/`via_edge`/`incoming`, which is exactly what the per-step
    // "TRAVERSED" lines and the reconstructed path need.
    let mut parents: HashMap<Uuid, (Uuid, EdgeKind, &'static str)> = HashMap::new();
    let mut visited_total: usize = 0;
    let mut found_path: Option<Vec<Uuid>> = None;

    graph_walk(graph, roots, &BfsSpec::reachability_trace(), None, |step| {
        visited_total += 1;
        match (step.from, step.via_edge) {
            (Some(from), Some(ek)) => {
                let dir = if step.incoming { "IN" } else { "OUT" };
                parents.insert(step.node_id, (from, ek, dir));
                let arrow = if step.incoming { "IN  <-" } else { "OUT ->" };
                trace.writeln(&format!(
                    "    {arrow} {} ({:?}, conf {:.2}) -> TRAVERSED",
                    node_label(&step.node_id),
                    ek,
                    step.confidence
                ));
                if step.node_id == target_id {
                    let via = if step.incoming {
                        "incoming"
                    } else {
                        "outgoing"
                    };
                    trace.writeln(&format!(
                        "\n  *** TARGET FOUND at depth {} via {via} {ek:?} edge ***",
                        step.depth
                    ));
                    let path = reconstruct_trace_path(&parents, target_id, roots);
                    trace.writeln(&format!(
                        "\n  PATH ({} hops):",
                        path.len().saturating_sub(1)
                    ));
                    for (pi, &pid) in path.iter().enumerate() {
                        let plabel = node_label(&pid);
                        if pi == 0 {
                            trace.writeln(&format!("    [{pi}] {plabel}"));
                        } else if let Some(&(_, ek2, dir2)) = parents.get(&pid) {
                            trace.writeln(&format!("    [{pi}] --[{dir2} {ek2:?}]--> {plabel}"));
                        }
                    }
                    found_path = Some(path);
                    return WalkControl::Stop;
                }
            }
            _ => {
                // A root/seed (depth 0). A root that IS the target proves
                // itself trivially.
                trace.writeln(&format!("  Root: {}", node_label(&step.node_id)));
                if step.node_id == target_id {
                    trace.writeln("TARGET found immediately — it IS a root node.");
                    found_path = Some(vec![step.node_id]);
                    return WalkControl::Stop;
                }
            }
        }
        WalkControl::Continue
    });

    if let Some(path) = found_path {
        trace.flush();
        return Some(path);
    }

    trace.writeln("\nRESULT: Target NOT found after BFS exhaustion.");
    trace.writeln(&format!("  Total visited: {visited_total} nodes"));
    trace.flush();
    None
}

/// Reconstruct a path from target back to a root using parent pointers.
fn reconstruct_trace_path(
    parents: &HashMap<Uuid, (Uuid, EdgeKind, &'static str)>,
    target: Uuid,
    roots: &[Uuid],
) -> Vec<Uuid> {
    let root_set: HashSet<Uuid> = roots.iter().copied().collect();
    let mut path = vec![target];
    let mut current = target;
    // Safety: limit iterations to prevent infinite loops on corrupted parent maps
    for _ in 0..1000 {
        if root_set.contains(&current) {
            break;
        }
        match parents.get(&current) {
            Some(&(parent, _, _)) => {
                path.push(parent);
                current = parent;
            }
            None => break,
        }
    }
    path.reverse();
    path
}

// ============================================================================
// Reverse BFS — unified from 4 previous implementations
// ============================================================================

/// Filter for reachability classes during reverse BFS.
///
/// Controls which nodes appear in the output. The BFS traversal always
/// continues through ALL nodes regardless of filter — a dead node might
/// have wired dependents further up the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachabilityFilter {
    /// Only include nodes reachable from production entry points
    /// (Wired, PublicApi, Structural).
    Wired,
    /// Only include dead/orphan nodes.
    Dead,
    /// Only include test-only nodes.
    TestOnly,
    /// Include all nodes regardless of reachability class.
    All,
}

/// A single entry from reverse BFS traversal.
#[derive(Debug, Clone)]
pub struct ReverseBfsEntry {
    /// The graph node found during traversal.
    pub node: GraphNode,
    /// How deep this node is from the root (1 = direct caller).
    pub depth: usize,
    /// The edge kind connecting this node to its predecessor.
    pub edge_kind: EdgeKind,
    /// Confidence of the edge connecting this node.
    pub confidence: f32,
}

/// Result of a reverse BFS traversal.
#[derive(Debug, Clone)]
pub struct ReverseBfsResult {
    /// All dependent nodes found, with depth and edge metadata.
    pub dependents: Vec<ReverseBfsEntry>,
    /// Count of symbols per file path among dependents.
    pub file_counts: HashMap<String, usize>,
    /// Count of test functions per test file path among dependents.
    pub test_files: HashMap<String, usize>,
    /// Warning when all dependents are in the same file as the root.
    pub isolation_note: Option<String>,
}

/// Unified reverse BFS traversal from a root node through incoming edges.
///
/// Merges features from 4 previous implementations:
/// - **Trait bridging** (from composite_intel.rs): follows impl-to-trait and
///   trait-to-impl dyn dispatch edges to find callers across dispatch boundaries.
/// - **Reachability filter** (from code_intel.rs / change_plan.rs): optional
///   filter on the OUTPUT only — BFS traversal always continues through all nodes.
/// - **None-handling** (from change_plan.rs `map_or` pattern): nodes with
///   `reachability_class = None` are NOT treated as Dead. They pass all filters
///   except Dead (if you explicitly ask for dead, None is not dead).
/// - **Isolation detection** (from code_intel.rs): warns when all dependents
///   reside in the same file as the root symbol.
pub fn reverse_bfs(
    graph: &KnowledgeGraph,
    root: &GraphNode,
    max_depth: usize,
    filter: Option<ReachabilityFilter>,
) -> ReverseBfsResult {
    // Trait dispatch bridging (WU-0003 / CL-REACH RC2 / CL-REACH-05).
    //
    // EDGE-DRIVEN bridging off the `Implements`/`HasImpl` graph edges
    // (`seed_trait_bridge_via_edges`) is owned by the ONE traversal core via
    // `BfsSpec::dependents().trait_bridge` — it works even when the symbol-name
    // string does not match the `"impl Trait for Type::method"` shape the
    // legacy parser expected, closing the parser-fragility under-report.
    //
    // The legacy name-string bridges are kept here as an ADDITIVE fallback (the
    // documented CL-REACH-05 method-granularity fallback): they match the
    // trait↔impl *method* granularity (by method name) the block-level edges
    // alone cannot resolve, so dropping them would *lose* reachability. They are
    // passed as extra roots — together with the root + the edge-driven seeds the
    // core adds, the bridge can only widen, never narrow, the dependent set.
    let mut roots: Vec<Uuid> = vec![root.memory_id];
    if let Some(trait_method) = find_trait_method_for_impl(graph, root) {
        roots.push(trait_method.memory_id);
    }
    for impl_method in find_impl_methods_for_trait(graph, root) {
        roots.push(impl_method.memory_id);
    }

    let mut dependents: Vec<ReverseBfsEntry> = Vec::new();
    let mut file_counts: HashMap<String, usize> = HashMap::new();
    let mut test_files: HashMap<String, usize> = HashMap::new();

    // RC2: route through the ONE traversal core (`dependents` preset = INCOMING
    // `Dependency` admission + edge-driven trait bridge). The seeds (root +
    // name-string + edge-driven bridges) arrive at depth 0 and are excluded
    // from the dependents output exactly as before; discovered nodes (depth >=
    // 1) are filtered on OUTPUT only — traversal always continues so a
    // filtered-out node's own dependents are still reached.
    graph_walk(
        graph,
        &roots,
        &BfsSpec::dependents(),
        Some(max_depth),
        |step| {
            // Seeds (depth 0) are not "dependents".
            if step.depth == 0 {
                return WalkControl::Continue;
            }
            let Some(node) = graph.node(&step.node_id) else {
                return WalkControl::Continue;
            };
            let edge_kind = step.via_edge.unwrap_or(EdgeKind::Calls);

            // Test file detection (always, regardless of filter). WU-0003 /
            // CL-REACH-06: a node is in hand, so read the persisted is_test_only
            // bit via `node_is_test` rather than guessing from the path alone.
            if node_is_test(graph, node) {
                *test_files.entry(node.file_path.clone()).or_insert(0) += 1;
            }

            // Apply reachability filter to output only.
            // WU-0003 RC5: the class is non-`Option`. An `Unclassified` node is
            // NEVER folded into Dead (the false-clean) — it passes every filter
            // EXCEPT `Dead`, exactly preserving the prior honest
            // `None`-passes-all-except-Dead handling.
            if let Some(ref filter_class) = filter
                && *filter_class != ReachabilityFilter::All
            {
                let node_reach = node.reachability_class;
                let passes = if node_reach == ReachabilityClass::Unclassified {
                    !matches!(filter_class, ReachabilityFilter::Dead)
                } else {
                    match filter_class {
                        ReachabilityFilter::Wired => matches!(
                            node_reach,
                            ReachabilityClass::Wired
                                | ReachabilityClass::PublicApi
                                | ReachabilityClass::Structural
                        ),
                        ReachabilityFilter::Dead => matches!(
                            node_reach,
                            ReachabilityClass::Dead | ReachabilityClass::Orphan
                        ),
                        ReachabilityFilter::TestOnly => {
                            matches!(node_reach, ReachabilityClass::TestOnly)
                        }
                        ReachabilityFilter::All => true,
                    }
                };
                if !passes {
                    return WalkControl::Continue;
                }
            }

            *file_counts.entry(node.file_path.clone()).or_insert(0) += 1;
            dependents.push(ReverseBfsEntry {
                node: node.clone(),
                depth: step.depth,
                edge_kind,
                confidence: step.confidence,
            });
            WalkControl::Continue
        },
    );

    // Isolation detection: warn when all dependents are in the same file as root.
    let isolation_note = if !dependents.is_empty()
        && dependents
            .iter()
            .all(|entry| entry.node.file_path == root.file_path)
    {
        let filename = root.file_path.rsplit('/').next().unwrap_or(&root.file_path);
        Some(format!(
            "\u{26a0} All {} dependents are internal to {} \u{2014} no external callers detected.",
            dependents.len(),
            filename,
        ))
    } else {
        None
    };

    ReverseBfsResult {
        dependents,
        file_counts,
        test_files,
        isolation_note,
    }
}

// ============================================================================
// Dead code helpers — unified from composite_intel.rs + composite_cmd.rs
// ============================================================================

/// Recommendation action for a dead symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeadAction {
    /// Private, unreferenced, and flagged by the rustc/clippy dead-code oracle —
    /// the INTENDED `DEAD (confirmed)` tier (ADR-0038 §2). WU-0016 / ADR-0039
    /// demote: advisory only, NOT a delete authority — a human verifies before
    /// removing. RV-003: the "confirmed"/"compiler-corroborated" certainty is NOT
    /// yet earned — Class-B (OQ-ORACLE-LINT-FAMILY-OVERBROAD) still lets an
    /// `unused_*` diagnostic spoof the rustc conjunct; the blessed name lands when
    /// B (with C/J) lands.
    SafeDelete,
    /// Looks unused, but delete authority is withheld — the catch-all withhold
    /// verdict.
    ///
    /// WU-0016 Leg F (OQ-DELETE-REASON-PROVENANCE) corrects a conflation: this
    /// variant is returned for several disjoint causes — a residual
    /// `Suspected`/`Orphan` reachability class, an
    /// uncorroborated (`!rustc_flagged_dead`, the DOMINANT real cause) node, a
    /// `pub` visibility, a cfg-touching crate, a `#[allow(dead_code)]` retain
    /// attr, a LEG-D counterpart that blocks co-deletion, or the gate-layer
    /// oracle downgrade (`!oracle_ran_ok`).
    /// The specific cause is named by
    /// [`classify_withhold_cause`](crate::graph_query::classify_withhold_cause);
    /// this variant is only the verdict, never the reason. It is also the
    /// downgrade target of [`SafeDelete`](Self::SafeDelete) when the oracle is
    /// unavailable or degraded.
    SuspectedDelete,
    /// Some dependents are alive — needs review before deletion.
    NeedsReview,
    /// Only referenced from test code — consider promoting or removing.
    TestOnly,
    /// Reachability could not be computed — the call graph carries no SCIP
    /// coverage, so no recommendation can be trusted (ADR-0034 L4, Decision 2).
    /// Produced ONLY by the verb-level suppression path
    /// ([`dead_single_gated`]); the raw [`classify_dead_action`] never returns
    /// it (L6 decoupling preserved).
    Unknown,
}

impl DeadAction {
    /// Machine-readable label for the action (WU-0016 / ADR-0039 demote:
    /// `SafeDelete` renders the advisory `DEAD` tier, NOT `SAFE_DELETE` — the
    /// delete-authority claim is stripped; the "confirmed" suffix is withheld
    /// until Class-B lands, RV-003).
    pub const fn label(&self) -> &'static str {
        match self {
            Self::SafeDelete => "DEAD",
            Self::SuspectedDelete => "SUSPECTED_DELETE",
            Self::NeedsReview => "NEEDS_REVIEW",
            Self::TestOnly => "TEST_ONLY",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Human-readable description of the action.
    pub const fn description(&self) -> &'static str {
        match self {
            // REVISIT(RV-003 until: OQ-ORACLE-LINT-FAMILY-OVERBROAD): promote this
            // advisory wording + the RV-003 sweep set back to the blessed
            // "DEAD (confirmed)" / "compiler-corroborated" vocabulary once the
            // remaining oracle confounders close. WU-0016 Class-B narrowed the
            // oracle to `dead_code`-only + subject-identity (the `unused_*` spoof
            // is CLOSED), but promotion also needs C (cfg-stripped bodies clippy
            // never compiled) and J (retain-attr / entry-point liveness) resolved
            // — so the "flagged" (not "corroborated") wording stays until B+C+J.
            Self::SafeDelete => {
                "private and unreachable by static analysis — may still be wired via an unseen edge; verify before removing"
            }
            // WU-0016 Leg F (OQ-DELETE-REASON-PROVENANCE): this is now a GENERIC
            // fallback only. `SuspectedDelete` is returned for several disjoint causes
            // (dominantly `!rustc_flagged_dead`), so this const must NOT name any
            // single one. Every render surface uses the cause-carrying
            // `withhold_reason` (from `classify_withhold_cause`), not this string.
            Self::SuspectedDelete => {
                "looks unused — delete authority withheld; verify before removing"
            }
            Self::NeedsReview => "has alive dependents",
            Self::TestOnly => "consider promoting to production or removing test",
            Self::Unknown => {
                "reachability unavailable — call-graph coverage insufficient; recommendation withheld"
            }
        }
    }
}

/// The advisory tiered-output label for a dead-code verdict (WU-0016 / ADR-0039
/// RC-B5).
///
/// The SINGLE injection point for the demoted tiered vocabulary
/// (`DEAD` / `SUSPECTED` / `LIVE_ASSUMED`; the `DEAD` tier is the intended
/// `DEAD (confirmed)` but renders without the suffix until Class-B lands — RV-003)
/// surfaced by the CLI and
/// MCP `dead <symbol>` renderers. A pure projection over the EXISTING carriers
/// (`is_dead` + [`DeadAction`]) that materializes a `&'static str` engine-side —
/// deliberately NOT a new enum threaded through render signatures (that is the
/// ADR-0037 `SafeDeleteVerdict` cross-crate-token trap). Advisory only: the
/// `DEAD` tier is a static-analysis verdict, never a delete authority.
/// Render the TRI-STATE oracle-run status for the `dead` surface (WU-0016 Leg F
/// PART 4).
///
/// Current immutable publications always carry an oracle outcome. `None` is
/// reserved for an unloaded or synthetic snapshot and is never authoritative.
#[must_use]
pub const fn oracle_status_label(oracle_ran_ok: Option<bool>) -> &'static str {
    match oracle_ran_ok {
        Some(true) => "ran-ok",
        Some(false) => "degraded",
        None => "unavailable",
    }
}

pub const fn dead_tier_label(is_dead: bool, action: &DeadAction) -> &'static str {
    if !is_dead {
        return "LIVE_ASSUMED";
    }
    match action {
        // The 4-way SafeDelete conjunction (private + rustc-flagged + cfg-clean +
        // Dead) is the INTENDED confirmed-dead tier — renders plain "DEAD" (no
        // "confirmed") until Class-B lands (RV-003 / OQ-ORACLE-LINT-FAMILY-OVERBROAD).
        DeadAction::SafeDelete => "DEAD",
        DeadAction::SuspectedDelete => "SUSPECTED",
        DeadAction::NeedsReview => "NEEDS_REVIEW",
        DeadAction::TestOnly => "TEST_ONLY",
        DeadAction::Unknown => "UNKNOWN",
    }
}

/// The honest reachability warning for a symbol's `inspect`/`assess` warnings
/// section (WU-0016 / ADR-0039 RC-B3).
///
/// The SINGLE source of the `DEAD`/`ORPHAN`/`TEST_ONLY` warning strings shared
/// by the CLI (`h00ligan inspect`) and MCP (`inspect`) renderers — hoisted from
/// the two verbatim clones so they cannot drift. The `DEAD` message is demoted
/// (WU-0016): it describes the static-analysis finding and directs verification,
/// making NO delete-authority claim. Returns `None` for classes that carry no
/// warning.
pub const fn reachability_warning(class: ReachabilityClass) -> Option<&'static str> {
    match class {
        ReachabilityClass::Dead => Some(
            "DEAD: unreachable by static analysis — may still be wired via an unseen edge; \
             verify before removing",
        ),
        ReachabilityClass::Orphan => Some("ORPHAN: file has no mod declaration"),
        ReachabilityClass::TestOnly => Some("TEST_ONLY: only reachable from test code"),
        _ => None,
    }
}

/// The honest `type`-command dead-field warning (WU-0016 / ADR-0039 RC-B4).
///
/// The SINGLE source of the dead-field warning shared by the CLI
/// (`h00ligan type`) and MCP (`type`) renderers — hoisted from the two verbatim
/// clones. WU-0016 demote: drops the `Consider removing.` delete verb; states
/// the graph finding and directs verification instead.
#[must_use]
pub fn dead_field_warning(field_short_name: &str) -> String {
    format!(
        "DEAD FIELD: {field_short_name} has 0 graph reads (unreferenced in the graph — \
         verify before removing)"
    )
}

/// Produce a human-readable reason a DEAD/ORPHAN node is unreachable.
///
/// WU-0016 / ADR-0039 RC-B6 — promoted from the MCP crate to the engine so the
/// CLI and MCP `dead` renderers share ONE implementation, closing the CLI≡MCP
/// parity gap.
///
/// - `"No incoming edges"` — ORPHAN / nothing points here
/// - `"Only callers are in test modules"` — incoming edges exist but every
///   caller is test-only
/// - `"Contained in dead parent: <name>"` — this node's parent is dead
/// - `"No path from any public entry point"` — reachable from something, but
///   that chain does not terminate at a wired entry point
#[must_use]
pub fn classify_dead_reason(graph: &KnowledgeGraph, node: &GraphNode) -> String {
    let incoming = graph.incoming_neighbors(&node.memory_id);
    if incoming.is_empty() {
        return "No incoming edges".to_string();
    }

    // Find parent via Contains edges (first incoming Contains wins).
    let parent_dead: Option<String> = incoming.iter().find_map(|(src_id, edge)| {
        if edge.kind == EdgeKind::Contains {
            graph.node(src_id).and_then(|parent| {
                if matches!(
                    parent.reachability_class,
                    ReachabilityClass::Dead | ReachabilityClass::Orphan
                ) {
                    Some(short_name(&parent.symbol_name).to_string())
                } else {
                    None
                }
            })
        } else {
            None
        }
    });
    if let Some(parent) = parent_dead {
        return format!("Contained in dead parent: {parent}");
    }

    // Dependency-edge callers.
    let dep_callers: Vec<&GraphNode> = incoming
        .iter()
        .filter(|(_, edge)| is_dependency_edge(edge.kind))
        .filter_map(|(src_id, _)| graph.node(src_id))
        .collect();

    if dep_callers.is_empty() {
        return "No incoming edges".to_string();
    }

    // If every dependency caller is test-only, we're test-only-dead.
    let all_test_only = dep_callers
        .iter()
        .all(|c| matches!(c.reachability_class, ReachabilityClass::TestOnly));
    if all_test_only {
        return "Only callers are in test modules".to_string();
    }

    // Otherwise: callers exist but none are wired.
    "No path from any public entry point".to_string()
}

/// Classify what action to take on a dead symbol.
///
/// Examines the symbol's incoming dependency edges to determine if any
/// alive or test-only dependents exist, and recommends the appropriate
/// cleanup action.
/// Whether a node's visibility makes it delete-eligible: genuinely private to
/// its crate — NOT `pub`, and NOT the empty string. An empty visibility is an
/// old-snapshot / SCIP-only node whose privacy is unknown, so it is treated as
/// NON-deletable (over-conservative — it can never gain delete authority). The
/// delete-eligible set is exactly {`private`, `pub(crate)`, `pub(super)`,
/// `pub(in …)`}; `pub(crate)` qualifies because any cross-crate use of it is
/// privacy-forbidden (WU-0015 Leg-3b / ADR-0036).
pub(crate) fn visibility_is_deletable(visibility: &str) -> bool {
    visibility == "private"
        || visibility == "pub(crate)"
        || visibility == "pub(super)"
        || visibility.starts_with("pub(in ")
}

/// Usage-dependency predicate for [`classify_dead_action`]: an incoming edge
/// whose SOURCE is a *user* of this node — [`is_dependency_edge`] MINUS
/// `Contains`.
///
/// `Contains` is parent→child (an impl block → its method, a module → its item),
/// so an INCOMING `Contains` means "this node is NESTED IN the source", never
/// "the source USES this node". Counting it as a usage-dependent is a category
/// error: a dead item merely nested in an alive parent would read as if it had an
/// alive *user*, mis-labelling it `NeedsReview` (WU-0015 Leg-D / MAJOR fix).
/// Containment breakage — deleting a node still nested in a live parent — is
/// instead owned by the LEG-D trait-contract guard in
/// [`classify_dead_action_inner`], which inspects the `Contains` counterpart's
/// own deletability. [`is_dependency_edge`] itself is UNCHANGED (it stays
/// Contains-inclusive; it is load-bearing for BFS escape from nested seeds).
const fn is_usage_dependency_edge(kind: EdgeKind) -> bool {
    is_dependency_edge(kind) && !matches!(kind, EdgeKind::Contains)
}

/// Classify what cleanup action to take on a dead/orphan symbol.
///
/// Examines the symbol's incoming edges for alive/test-only USERS, then applies
/// the 4-way `SafeDelete` conjunction and the LEG-D trait-contract guard. Thin
/// wrapper over [`classify_dead_action_inner`] seeding an empty `visited` set
/// (the cycle-guard for the LEG-D guard's recursion into edge counterparts).
pub fn classify_dead_action(
    graph: &KnowledgeGraph,
    node: &GraphNode,
    cfg_crates: &HashSet<String>,
) -> DeadAction {
    let mut visited = HashSet::new();
    classify_dead_action_inner(graph, node, cfg_crates, &mut visited)
}

/// Cycle-safe worker for [`classify_dead_action`].
///
/// `visited` is a monotone SEEN-SET (insert-only, NEVER removed) of every node
/// already evaluated in this top-level call, so the LEG-D guard's recursion into
/// `Implements`/`HasImpl`/`Contains` counterparts terminates on a mutual-impl
/// cycle (`trait ↔ impl ↔ struct`). It is deliberately NOT a stack/path —
/// soundness does not require popping (see the base case), and adding a `.remove`
/// would re-open non-termination on cycles. The public entry seeds it empty.
fn classify_dead_action_inner(
    graph: &KnowledgeGraph,
    node: &GraphNode,
    cfg_crates: &HashSet<String>,
    visited: &mut HashSet<Uuid>,
) -> DeadAction {
    // CYCLE base case (LEG-D). A node already in `visited` (a true cycle back-edge
    // OR a fully-evaluated sibling — `visited` is a monotone seen-set, not a stack)
    // is treated as corroborated-deletable. This is sound in BOTH directions:
    //   • a wholly-dead mutual-impl cluster then CO-DELETES — every member passes
    //     its own 4-way, and the back-edge optimism lets the last member close the
    //     ring as SafeDelete; deleting the whole ring together dangles nothing;
    //   • a NON-deletable member never gets hidden by this optimism — it returns a
    //     non-`SafeDelete` verdict from its OWN pre-guard checks (4-way / alive- or
    //     test-dependent) on its FIRST visit, which is what any dependent consumes;
    //     the base case only fires on a SECOND (back-edge) visit, after that true
    //     verdict is already computed and propagating. A member made non-deletable
    //     by an EXTERNAL non-deletable counterpart is caught in its own frame (it
    //     checks all its counterparts directly), so the withhold still propagates.
    if !visited.insert(node.memory_id) {
        return DeadAction::SafeDelete;
    }

    let dependents = graph.incoming_neighbors(&node.memory_id);

    // Check if any dependent is alive (not Dead/Orphan/None). `Contains` is
    // EXCLUDED (`is_usage_dependency_edge`): an incoming `Contains` is this node's
    // CONTAINER, not a USER, so "nested in an alive parent" must not read as "has
    // an alive user" — containment breakage is owned by the LEG-D guard below.
    let has_alive_dependent = dependents.iter().any(|(id, edge)| {
        if !is_usage_dependency_edge(edge.kind) {
            return false;
        }
        graph
            .node(id)
            .map(|n| {
                !matches!(
                    n.reachability_class,
                    ReachabilityClass::Dead
                        | ReachabilityClass::Orphan
                        | ReachabilityClass::Unclassified
                )
            })
            .unwrap_or(false)
    });

    if has_alive_dependent {
        return DeadAction::NeedsReview;
    }

    // Check if any dependent is test-only (`Contains` excluded, same rationale).
    let has_test_dependent = dependents.iter().any(|(id, edge)| {
        if !is_usage_dependency_edge(edge.kind) {
            return false;
        }
        graph
            .node(id)
            .map(|n| matches!(n.reachability_class, ReachabilityClass::TestOnly))
            .unwrap_or(false)
    });

    if has_test_dependent {
        return DeadAction::TestOnly;
    }

    // Belt-and-suspenders (WU-0003 / CL-REACH-04): a dead node whose file lives
    // under a `tests/`, `examples/`, or `benches/` directory is test/dev code —
    // never a SAFE_DELETE production-cleanup candidate even if it has no
    // surviving dependents. Anchored on a path COMPONENT (not a raw substring)
    // so `src/contest_runner.rs` does not false-match.
    if path_under_test_dir(&node.file_path) {
        return DeadAction::TestOnly;
    }

    // WU-0015 / ADR-0036 Leg-3b — the 4-way SafeDelete conjunction. Delete
    // authority (`SafeDelete`) is granted ONLY when ALL FOUR hold:
    //   (1) `reachability_class == Dead` — the private call-unreachable-no-guard
    //       residual promoted by the Leg-3b visibility-gated sweep (a pub or
    //       guard-rescued node never reaches this class);
    //   (2) `rustc_flagged_dead` — the index-time Phase-8e rustc/clippy oracle
    //       flagged THIS exact definition line (span-based, never name-based,
    //       narrowed to `dead_code`-only + subject-identity by WU-0016 Class-B;
    //       an absent oracle leaves this `false`). RV-003 caveat: the `unused_*`
    //       spoof this conjunct once carried is now CLOSED, but the user-facing
    //       "flagged" (not "corroborated") wording STAYS — vocab-promotion is
    //       gated on Class-B TOGETHER WITH the still-open confounders C
    //       (cfg-stripped code: `cfg(doc)` / `docsrs` / `kani` bodies clippy
    //       never compiled, so it cannot see their uses) and J (a `#[used]` /
    //       retain-attr, or an unlisted entry point, keeping a def live despite
    //       the dead_code flag);
    //   (3) the visibility is delete-eligible — private/pub(crate)/… , NOT `pub`
    //       and NOT the empty string (see `visibility_is_deletable`);
    //   (4) the node's crate is cfg-CLEAN — `crate_name_of` resolves to a real
    //       `crates/<name>` crate that carries NO platform-cfg anywhere. A
    //       `None` crate (bare `src/lib.rs`, single-package repo) is NOT eligible:
    //       it has no cfg-clean-crate attribution (V3-6-consistent — external /
    //       non-`crates/` → review, not delete).
    // ANY single conjunct failing → the non-delete `SuspectedDelete`. This is the
    // load-bearing safety gate: the ceiling is `count(SafeDelete) == confined &&
    // corroborated`, never "every Dead node is deletable".
    let is_safe_delete = node.reachability_class == ReachabilityClass::Dead
        && node.rustc_flagged_dead
        && visibility_is_deletable(&node.visibility)
        && crate_name_of(&node.file_path).is_some_and(|c| !cfg_crates.contains(c))
        // WU-0015 Leg J (part b) — a `#[allow(dead_code)]` retain attr is the
        // author's explicit "keep this"; it vetoes SafeDelete (downgrade-only,
        // SafeDelete → SuspectedDelete). Belt-and-suspenders with conjunct 2: an
        // `allow(dead_code)` item is ~never `rustc_flagged_dead` (the attr
        // suppresses the very lint), but keeping the veto explicit also makes a
        // retain node BLOCK its LEG-D counterparts (safe-direction). `#[used]` is
        // NOT read here — it becomes Wired via the part-a entry-point seeding, so
        // a Dead-only classify never sees it.
        && !node.entry_retain.has_retain_attr();
    if !is_safe_delete {
        return DeadAction::SuspectedDelete;
    }

    // WU-0015 LEG-D — the trait-contract guard (OQ-TRAIT-CONTRACT-GUARD). A node
    // that PASSES the 4-way is still withheld from `SafeDelete` when it has an
    // incoming `Implements` / `HasImpl` / `Contains` edge whose COUNTERPART (the
    // edge SOURCE) is NOT itself corroborated-deletable. Deleting the node would
    // dangle an edge-carried reference in a still-alive counterpart — the
    // build-break classes E0405 (impl of a deleted trait), E0412 (a deleted type
    // in a live `impl`/`HasImpl`), E0046/E0438 (a deleted item required by a live
    // impl block). Directions (edge_builder ground truth): `Implements` impl→trait,
    // `HasImpl` trait→struct, `Contains` parent→child, so `incoming_neighbors`
    // yields exactly the trait's impls, the struct's owning trait, and the item's
    // container. Recursion (threading the SAME `visited`) makes the check the FULL
    // gate, not a single level, so a wholly-dead cluster whose impl block is merely
    // UNFLAGGED still withholds the trait+struct (the impl fails its own 4-way).
    // Downgrade-ONLY: this branch runs solely when the verdict is already
    // `SafeDelete`, so it can lower `SafeDelete`→`SuspectedDelete` but never grant
    // — the same safe-direction invariant as conjuncts B+C.
    let counterpart_blocks_delete = dependents.iter().any(|(id, edge)| {
        if !matches!(
            edge.kind,
            EdgeKind::Implements | EdgeKind::HasImpl | EdgeKind::Contains
        ) {
            return false;
        }
        // An absent counterpart node (`None`) cannot carry a dangling reference,
        // so it never blocks (mirrors the `unwrap_or(false)` convention above).
        graph.node(id).is_some_and(|counterpart| {
            classify_dead_action_inner(graph, counterpart, cfg_crates, visited)
                != DeadAction::SafeDelete
        })
    });

    if counterpart_blocks_delete {
        DeadAction::SuspectedDelete
    } else {
        DeadAction::SafeDelete
    }
}

// ============================================================================
// WU-0016 Leg F — cause-carrying withhold reason (OQ-DELETE-REASON-PROVENANCE)
// ============================================================================

/// The oracle-degraded backstop (`!oracle_ran_ok`).
const WITHHOLD_ORACLE_DEGRADED: &str = "looks unused, but the dead-code oracle could not corroborate this run (degraded/absent clippy build) — advisory only; verify before removing";
/// Cause #3 — conjunct 1 failed: not confirmed-dead reachability class.
const WITHHOLD_REACHABILITY: &str = "reachability class is not confirmed-dead (Suspected/Orphan) — a directed-reachability residue; review before removing";
/// Cause #4 — conjunct 2 failed: the oracle did not flag it (the DOMINANT cause,
/// the LIE this leg fixes).
const WITHHOLD_UNCORROBORATED: &str = "the dead-code oracle (rustc/clippy) did not flag this symbol — uncorroborated; verify before removing";
/// Cause #5 — conjunct 3 failed: exported/public visibility.
const WITHHOLD_VISIBILITY: &str =
    "exported/public visibility — an unseen external caller may exist; verify before removing";
/// Cause #6 — conjunct 4 failed: cfg-touching (or non-`crates/`) crate.
const WITHHOLD_CFG: &str = "the crate carries platform-cfg (or has no crates/<name> attribution) — a cfg-gated caller may be invisible to the index; verify before removing";
/// Cause #7 — the retain veto: `#[allow(dead_code)]`.
const WITHHOLD_RETAIN: &str =
    "carries a #[allow(dead_code)] retain attribute — the author marked this keep; do not remove";
/// The generic fallback if the LEG-D counterpart is present but no name resolves
/// (`graph.node` absent — never blocks per the `unwrap_or(false)` convention, so
/// in practice unreached; kept demote-safe).
const WITHHOLD_GENERIC: &str = "looks unused — delete authority withheld; verify before removing";

/// Produce the cause-carrying reason a dead symbol's delete-authority was
/// withheld — or, for a confirmed DEAD node, the corroboration that earned it
/// (WU-0016 Leg F / OQ-DELETE-REASON-PROVENANCE).
///
/// The core of Leg F: it KILLS the overloaded single `SuspectedDelete`
/// description that falsely printed "the repo shape is un-indexable (ADR-0035)"
/// for EVERY withheld symbol, when ~7 disjoint causes route to `SuspectedDelete`
/// (dominantly `!rustc_flagged_dead`). It names the FIRST-failing cause in the
/// disjoint-layer order, so exactly ONE layer owns each withhold. The two
/// The oracle gate-layer downgrade comes first (it acts ONLY on a
/// classify==`SafeDelete` input, so it cannot mask a genuine conjunct break).
/// Otherwise classify itself returned
/// `SuspectedDelete`, and the reason is the FIRST-failing conjunct of the 4-way in
/// code order (reachability, then uncorroborated, then visibility, then cfg), then
/// the retain veto, then the LEG-D counterpart (interpolating the blocking
/// counterpart's name).
///
/// A confirmed DEAD node (classify==`SafeDelete`, oracle ran)
/// returns the corroboration reason naming the [`OracleReceipt`](crate::graph::OracleReceipt).
/// `NeedsReview` / `TestOnly` keep their existing description. DEMOTE-safe
/// throughout (ADR-0038): NO delete-authority verb — "verify/review before
/// removing", never "safe to delete".
///
/// The downgrade layer is checked before conjunct re-derivation because it acts
/// only on a classify==`SafeDelete` input and therefore cannot mask a genuine
/// conjunct break.
#[must_use]
pub fn classify_withhold_cause(
    graph: &KnowledgeGraph,
    node: &GraphNode,
    cfg_crates: &HashSet<String>,
    oracle_ran_ok: bool,
) -> String {
    match classify_dead_action(graph, node, cfg_crates) {
        DeadAction::SafeDelete => {
            if !oracle_ran_ok {
                WITHHOLD_ORACLE_DEGRADED.to_string()
            } else {
                safe_delete_corroboration_reason(node)
            }
        }
        DeadAction::SuspectedDelete => withhold_conjunct_cause(graph, node, cfg_crates),
        // Not withholds — keep the existing action descriptions (the render sites
        // route these through this fn too, replacing `act.description()`).
        DeadAction::NeedsReview => DeadAction::NeedsReview.description().to_string(),
        DeadAction::TestOnly => DeadAction::TestOnly.description().to_string(),
        // `classify_dead_action` never returns `Unknown` (verb-level only).
        DeadAction::Unknown => DeadAction::Unknown.description().to_string(),
    }
}

/// The confirmed-DEAD (SafeDelete) reason surfacing the corroborating
/// [`OracleReceipt`](crate::graph::OracleReceipt) (WU-0016 Leg F; replaces the
/// generic `SafeDelete.description()` at render). Names WHICH diagnostic, at which
/// line, on which subject corroborated the finding. DEMOTE-safe (no "safe to
/// delete").
fn safe_delete_corroboration_reason(node: &GraphNode) -> String {
    node.oracle_receipt.as_ref().map_or_else(
        // No receipt (e.g. a flag set by a test helper without `apply_oracle`, or
        // an old snapshot pre-Leg-F) — the corroboration still holds; name it
        // generically.
        || {
            "corroborated dead: rustc flagged this symbol dead_code; private; cfg-clean crate \
             — verify before removing"
                .to_string()
        },
        |r| {
            let subject = r
                .subject
                .clone()
                .unwrap_or_else(|| short_name(&node.symbol_name).to_string());
            format!(
                "corroborated dead: rustc flagged {} at line {} for '{}'; private; cfg-clean crate \
                 — verify before removing",
                r.code, r.line, subject
            )
        },
    )
}

/// Re-derive the FIRST-failing conjunct/guard for a `SuspectedDelete` verdict
/// (causes #3–#8), in the EXACT code order of
/// [`classify_dead_action_inner`]'s 4-way conjunction so the named cause is the
/// genuine first-failing one (the disjointness guarantee — a fixture that breaks
/// exactly one conjunct binds to exactly that cause).
fn withhold_conjunct_cause(
    graph: &KnowledgeGraph,
    node: &GraphNode,
    cfg_crates: &HashSet<String>,
) -> String {
    if node.reachability_class != ReachabilityClass::Dead {
        return WITHHOLD_REACHABILITY.to_string(); // #3
    }
    if !node.rustc_flagged_dead {
        return WITHHOLD_UNCORROBORATED.to_string(); // #4
    }
    if !visibility_is_deletable(&node.visibility) {
        return WITHHOLD_VISIBILITY.to_string(); // #5
    }
    if crate_name_of(&node.file_path).is_none_or(|c| cfg_crates.contains(c)) {
        return WITHHOLD_CFG.to_string(); // #6
    }
    if node.entry_retain.has_retain_attr() {
        return WITHHOLD_RETAIN.to_string(); // #7
    }
    // #8 — the LEG-D trait-contract guard: name the blocking counterpart. Mirrors
    // the `counterpart_blocks_delete` scan in `classify_dead_action_inner`.
    let incoming = graph.incoming_neighbors(&node.memory_id);
    let blocking = incoming.iter().find_map(|(src_id, edge)| {
        if !matches!(
            edge.kind,
            EdgeKind::Implements | EdgeKind::HasImpl | EdgeKind::Contains
        ) {
            return None;
        }
        graph.node(src_id).and_then(|counterpart| {
            if classify_dead_action(graph, counterpart, cfg_crates) != DeadAction::SafeDelete {
                Some(counterpart.symbol_name.clone())
            } else {
                None
            }
        })
    });
    blocking.map_or_else(
        || WITHHOLD_GENERIC.to_string(),
        |name| {
            format!(
                "a trait/impl/containment counterpart '{name}' is not itself removable — deleting \
                 this would dangle it; review before removing"
            )
        },
    )
}

/// Returns `true` if a path has a `tests`, `examples`, or `benches` directory
/// COMPONENT (WU-0003 / CL-REACH-04). Component-anchored, never a substring
/// match, so `src/contest_runner.rs` / `src/latest.rs` do not false-match.
fn path_under_test_dir(path: &str) -> bool {
    path.split('/')
        .any(|c| c == "tests" || c == "examples" || c == "benches")
}

/// The owning crate name for a `crates/<name>/...` path, else `None`.
///
/// A path not under `crates/<name>/` yields `None` (WU-0015 Leg 2 / ADR-0036).
/// DISTINCT from [`crate::edge_builder::crate_of`] (the build-time tie-break
/// key), which falls back to the first path segment and NEVER returns `None`.
/// The Leg-3 DEAD-authority gate needs the `Option` form so it can SKIP a
/// non-`crates/` node (a bare `src/main.rs`, a doc file) rather than inventing a
/// bogus crate bucket. Placed here so the Leg-3 gate consumes it beside
/// [`classify_dead_action`]; Leg 2 does NOT wire it into any verdict.
pub fn crate_name_of(file_path: &str) -> Option<&str> {
    let rest = file_path.strip_prefix("crates/")?;
    let name = rest.split('/').next().unwrap_or("");
    if name.is_empty() { None } else { Some(name) }
}

/// The set of crate names owning at least one platform-cfg node.
///
/// A node is platform-cfg-touching when `GraphNode::has_platform_cfg` is set
/// (captured at index time by [`crate::extractor::scan_platform_cfg`]) —
/// WU-0015 Leg 2 / ADR-0036.
/// Groups nodes by [`crate_name_of`] and OR-rolls `has_platform_cfg` per crate;
/// a node at a non-`crates/` path (`crate_name_of` → `None`) is skipped, never
/// bucketed. This is the SIGNAL the Leg-3 DEAD-authority gate consults: Leg 2
/// COMPUTES it and Leg 3b has SINCE wired it into `classify_dead_action` as
/// conjunct 4 of the `SafeDelete` gate, withholding delete-authority from
/// cfg-touching crates.
pub fn cfg_touching_crates(graph: &KnowledgeGraph) -> HashSet<String> {
    let mut set = HashSet::new();
    for node in graph.all_nodes() {
        if node.has_platform_cfg
            && let Some(name) = crate_name_of(&node.file_path)
        {
            set.insert(name.to_string());
        }
    }
    set
}

// ============================================================================
// Coverage-gated dead-code reporting (ADR-0034 L4, Decisions 2/3)
// ============================================================================

/// One dead/orphan symbol with its recommended action — the unit a gated full
/// report yields.
///
/// Carries `node_id` so a renderer can re-fetch the node (e.g. the MCP
/// per-symbol `reason` string) without re-traversing the graph.
#[derive(Debug, Clone)]
pub struct DeadEntry {
    /// Graph id of the dead node (for renderer re-lookup).
    pub node_id: Uuid,
    /// Fully-qualified symbol name.
    pub symbol_name: String,
    /// Node kind (`"function"`, `"struct"`, …).
    pub kind: String,
    /// Source file path.
    pub file_path: String,
    /// Reachability class (`Dead` or `Orphan`).
    pub reachability: ReachabilityClass,
    /// Recommended cleanup action ([`classify_dead_action`]).
    pub action: DeadAction,
    /// The cause-carrying reason the action was reached (WU-0016 Leg F /
    /// OQ-DELETE-REASON-PROVENANCE), from [`classify_withhold_cause`]. Computed at
    /// the gated layer where the oracle disposition is in scope, so
    /// BOTH the CLI and MCP full reports can explain each per-symbol withhold
    /// identically (parity by construction). For a corroborated SafeDelete this
    /// carries the corroboration receipt instead of a withhold cause — i.e. it is
    /// the action's reason (withhold cause OR corroboration), not solely a withhold.
    pub withhold_reason: String,
}

/// The four action tallies of a full dead report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeadCounts {
    /// Total dead + orphan symbols.
    pub total_dead: usize,
    /// Count of DEAD-tier symbols (the retained `DeadAction::SafeDelete`
    /// classification). Rendered user-facing under the blessed `dead` tier label,
    /// NEVER `safe_delete` (WU-0016 demote: no surface asserts delete-safety).
    pub safe_delete: usize,
    /// Symbols that look unused but whose delete authority is withheld — the
    /// `DeadAction::SuspectedDelete` catch-all. WU-0016 Leg F corrects the prior
    /// historical "this is normally 0" claim: it is NOT — the dominant
    /// contributor is `!rustc_flagged_dead` (uncorroborated), plus
    /// residual-class / `pub` / cfg-crate / retain-attr / LEG-D-counterpart cases.
    /// The specific per-symbol cause is carried in
    /// [`DeadEntry::withhold_reason`].
    pub suspected_delete: usize,
    /// Symbols that need review before deletion.
    pub needs_review: usize,
    /// Symbols referenced only from test code.
    pub test_only: usize,
}

/// The EMIT payload of [`dead_report_gated`] — all dead/orphan entries, each
/// with its action.
///
/// A renderer derives [`DeadCounts`] + file groupings from it. Sharing this
/// between the CLI and MCP renderers makes the suppress/emit decision
/// parity-by-construction (ADR-0034 L4, S5).
#[derive(Debug, Clone, Default)]
pub struct DeadFullData {
    /// Every dead/orphan symbol with its action.
    pub entries: Vec<DeadEntry>,
}

impl DeadFullData {
    /// Tally the entries by action.
    #[must_use]
    pub fn counts(&self) -> DeadCounts {
        let mut c = DeadCounts {
            total_dead: self.entries.len(),
            ..DeadCounts::default()
        };
        for e in &self.entries {
            match e.action {
                DeadAction::SafeDelete => c.safe_delete += 1,
                DeadAction::SuspectedDelete => c.suspected_delete += 1,
                DeadAction::NeedsReview => c.needs_review += 1,
                DeadAction::TestOnly => c.test_only += 1,
                // Unknown never appears in a Full report (it is only produced by
                // the verb-level suppression path, which short-circuits to the
                // Unknown variant before any entry is built).
                DeadAction::Unknown => {}
            }
        }
        c
    }

    /// Group entries by file, sorted by dead-symbol count descending (the
    /// stable rendering order shared by both surfaces).
    #[must_use]
    pub fn grouped_by_file(&self) -> Vec<(String, Vec<DeadEntry>)> {
        let mut by_file: HashMap<&str, Vec<DeadEntry>> = HashMap::new();
        for e in &self.entries {
            by_file.entry(&e.file_path).or_default().push(e.clone());
        }
        let mut files: Vec<(String, Vec<DeadEntry>)> = by_file
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        files.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
        files
    }

    /// Keep only entries matching `keep` (e.g. the MCP `production_only`
    /// filter) — returns a new [`DeadFullData`] whose `counts()`/grouping
    /// reflect the filtered set. The gate decision is unaffected: this is a
    /// render-side filter applied AFTER the shared suppress/emit verdict.
    #[must_use]
    pub fn retaining(&self, keep: impl Fn(&DeadEntry) -> bool) -> Self {
        Self {
            entries: self.entries.iter().filter(|e| keep(e)).cloned().collect(),
        }
    }
}

/// Gated full dead report (ADR-0034 L4, Decision 2). `Unknown` = verb-level
/// suppression under insufficient coverage (`None`/enabled-`Low`); `Full` = the
/// real report the renderer formats.
#[derive(Debug, Clone)]
pub enum DeadReport {
    /// Coverage insufficient — the WHOLE verb returns UNKNOWN; the Dead set is
    /// never consulted (it would be empty=false-clean or indistinguishably
    /// poisoned). Counts render `null`, arrays empty.
    Unknown,
    /// Coverage sufficient — the real report.
    Full(DeadFullData),
}

/// Gated single-symbol dead report (ADR-0034 L4, Decision 3).
///
/// Under `Unknown` the reachability verdict and action are withheld. (WU-0016 /
/// ADR-0039: the former `cascade_deletable` payload was removed — a second
/// delete-authority output with no consumer under the demote.)
#[derive(Debug, Clone)]
pub enum DeadSingleReport {
    /// Coverage insufficient — reachability/action withheld.
    Unknown,
    /// Coverage sufficient — the real single-symbol verdict.
    Computed {
        /// Whether the symbol is Dead/Orphan.
        is_dead: bool,
        /// Cleanup action — `Some` iff `is_dead`.
        action: Option<DeadAction>,
        /// The cause-carrying reason the action was reached (WU-0016 Leg F /
        /// OQ-DELETE-REASON-PROVENANCE) — from [`classify_withhold_cause`], so the
        /// single-symbol surface EXPLAINS the withhold (naming the specific cause)
        /// instead of printing the overloaded `un-indexable` lie. `Some` iff
        /// `is_dead` (mirrors `action`).
        withhold_reason: Option<String>,
    },
}

/// Whether a [`CoverageTier`](crate::graph_stats::CoverageTier) must SUPPRESS
/// the reachability-derived verdict to verb-level UNKNOWN (ADR-0034 L4).
///
/// `Unavailable` suppresses when no immutable Calls receipt authorizes the
/// query scope.
///
/// The SINGLE source of the suppress policy — shared by the engine dead/single
/// gates AND the CLI/MCP inspect/assess/tests gates (L4-completion) so the
/// policy can never diverge across surfaces (review NIT: was re-implemented
/// inline at several adapter sites).
#[must_use]
pub const fn tier_suppresses(tier: crate::graph_stats::CoverageTier) -> bool {
    matches!(
        tier,
        crate::graph_stats::CoverageTier::Unavailable
            // WU-0023 P3b LEAK-1: a total-extraction-failure store (`total_nodes
            // == 0`) suppresses to UNKNOWN — rendering `dead_code:0`/`fresh` on an
            // empty extraction is a false-CLEAN.
            | crate::graph_stats::CoverageTier::Degenerate
    )
}

/// The SINGLE two-argument suppression chokepoint (DEC-R8a, WU-0023 P3b).
///
/// The ONE place BOTH the coverage tier AND the reachability-classification axis
/// combine into the verb-level UNKNOWN decision. Suppresses (UNKNOWN) when
/// EITHER:
/// - the [`CoverageTier`](crate::graph_stats::CoverageTier) is insufficient
///   (`None`/`Low`/`Degenerate` — via [`tier_suppresses`]); OR
/// - reachability classification did NOT run for this graph
///   (`!reachability_classified`) — a store whose nodes are all `Unclassified`
///   cannot answer dead/reachable, so the reachability-derived verdict is
///   UNKNOWN, never a false-CLEAN `0` (ADR-0025 rev-3 §R8-DEGRADE).
///
/// EVERY reachability-gated surface (the `dead` whole-verb gate + the CLI/MCP
/// `assess`/`inspect`/`tests`/`overview`/`audit` gates) routes through THIS one
/// function so CLI≡MCP parity holds by construction — a per-surface
/// re-implementation is a parity-divergence bug waiting to happen. `Sufficient`
/// coverage on a classified graph is the only non-suppressing state.
#[must_use]
pub const fn suppresses(
    tier: crate::graph_stats::CoverageTier,
    reachability_classified: bool,
) -> bool {
    !reachability_classified || tier_suppresses(tier)
}

/// Whether reachability classification RAN for this graph (DEC-R8a, WU-0023 P3b).
///
/// Derived from in-memory graph state — the parity-by-construction signal BOTH
/// the CLI and MCP surfaces read (each already holds the graph; neither needs a
/// new store-flag or context field). `classify_and_writeback` leaves ZERO
/// `Unclassified` nodes on completion (the RC4 invariant,
/// `reachability.rs` `classify_and_writeback_leaves_zero_unclassified`), so a
/// graph carrying ANY `Unclassified` node is one on which classification did NOT
/// complete → the reachability-derived verbs must render UNKNOWN.
///
/// An EMPTY graph (0 nodes) is vacuously "classified" here (there is nothing to
/// classify); its false-CLEAN is closed on the SEPARATE
/// [`CoverageTier::Degenerate`](crate::graph_stats::CoverageTier::Degenerate)
/// axis (LEAK-1), so this predicate does not need to special-case it.
#[must_use]
pub fn graph_reachability_classified(graph: &KnowledgeGraph) -> bool {
    !graph
        .all_nodes()
        .iter()
        .any(|n| matches!(n.reachability_class, ReachabilityClass::Unclassified))
}

/// Whether a node belongs to a coverage-suppressed LANGUAGE (DEC-R5a, WU-0023
/// P3b) — its verdict renders UNKNOWN, so it is excluded from the (Path-B,
/// reporting) dead set. `suppressed_langs` is
/// [`coverage_suppressed_languages`](crate::graph_stats::coverage_suppressed_languages);
/// empty on a Rust-only store (→ never excludes, RUST NO-REGRESSION).
#[must_use]
fn node_language_suppressed(node: &GraphNode, suppressed_langs: &HashSet<&'static str>) -> bool {
    crate::graph_stats::node_language(node).is_some_and(|l| suppressed_langs.contains(l))
}

/// The registered languages whose nodes touch ≥1 SCIP-derived `Calls` edge
/// (DEC-R5a support). A language present here has precise resolution merged for
/// at least part of its slice; a language ABSENT here (with function nodes)
/// resolved only to the structural tags floor.
fn languages_touching_scip_calls(graph: &KnowledgeGraph) -> HashSet<&'static str> {
    let mut set: HashSet<&'static str> = HashSet::new();
    for (src, tgt, edge) in graph.all_edges() {
        if edge.kind == EdgeKind::Calls
            && matches!(edge.source, EdgeSource::Scip | EdgeSource::Both)
        {
            for id in [src, tgt] {
                if let Some(l) = graph.node(&id).and_then(crate::graph_stats::node_language) {
                    set.insert(l);
                }
            }
        }
    }
    set
}

/// The languages whose dead-code slice lacks generation-authoritative Calls
/// evidence.
///
/// This predicate never infers authority from an edge happening to exist and
/// never gives Rust a privileged implicit success. The caller supplies the exact
/// complete-language population resolved from the immutable generation's
/// capability receipts.
fn coverage_suppressed_languages_from_authority(
    graph: &KnowledgeGraph,
    complete_languages: &BTreeSet<LanguageId>,
) -> HashSet<&'static str> {
    crate::graph_stats::coverage_suppressed_languages(graph, |language| {
        complete_languages.contains(&LanguageId::new(language))
    })
}

/// True for a symbol whose source file lives under a `target/` build directory.
///
/// Cargo build scripts emit generated Rust into `OUT_DIR` (e.g. serde's
/// `target/debug/build/serde-*/out/*.rs` `__private` glue), which the SCIP merge
/// can ingest as graph nodes. Such artifacts are never user-owned source, so the
/// dead / `SAFE_DELETE` surface must never recommend deleting them (WU-0014
/// target-glue defect).
///
/// Matches an ORDERED `target` → `build` → `out` path-component subsequence —
/// catching the OUT_DIR shape under both relative (`target/debug/build/…/out/…`)
/// and absolute (`/abs/…/target/…/build/…/out/…`) roots, including cross-compile
/// / custom-profile variants with extra middle components. Deliberately a LOOSE
/// subsequence rather than strict `target/<profile>/build/<pkg>/out` adjacency:
/// the goal is to match every real OUT_DIR layout, accepting that a contrived
/// USER tree whose components happen to read `target … build … out` in order
/// would also be excluded (far below the prior `any(== "target")` over-match —
/// a genuinely-dead symbol under a dir merely named `target` stays on the dead
/// surface).
///
/// `pub` for cross-crate reuse: also the single source for the
/// [`crate::dead_pipeline::compute_dead_tiers`] broad-set filter (WU-0022 S1 Path A;
/// hoisted from h00ligan's `reachability_tiers`), so the `dead` command and
/// `graph reachability` exclude generated glue identically.
#[must_use]
pub fn is_generated_target_path(file_path: &str) -> bool {
    // Match ONLY the cargo build-script OUT_DIR shape
    // (`…/target/<profile>/build/<pkg>/out/<file>`) — an ORDERED
    // `target` → `build` → `out` component subsequence — NOT any path that
    // merely contains a component named `target`. A genuinely-dead USER symbol
    // under a dir named `target` (e.g. `src/foo/target/bar.rs`) must stay in the
    // dead surface; the prior `any(== "target")` over-matched (review finding).
    let mut comps = std::path::Path::new(file_path)
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(name) => name.to_str(),
            _ => None,
        });
    comps.any(|c| c == "target") && comps.any(|c| c == "build") && comps.any(|c| c == "out")
}

// ============================================================================
// WU-0022 S1 — the unified dead-verdict pipeline (OQ-TRAIT-GUARD-RESIDUAL-adjacent
// consolidation of the code-intel composite-layer fork)
// ============================================================================
//
// WU-0022 S1 collapses the two divergent dead-verdict wrapper stacks — Path B
// (`dead_report_gated`/`dead_single_gated`, the `dead` command + MCP) and Path A
// (`dead_pipeline::compute_dead_tiers`, the `graph reachability` wiring surface) —
// onto ONE decision core (`classify_dead_action`) with EXACTLY ONE application
// site for each gate/downgrade primitive:
//   • [`dead_verb_suppressed`]  — the single dead-pipeline consumer of
//     [`tier_suppresses`] (ADR-0034 L4 whole-verb suppression), used ONLY by
//     Path B. Path A never whole-verb-suppresses (a wiring gate must fire on RAW
//     membership under any coverage — `dead_pipeline` MAJOR-2). The
//     assess/inspect/tests coverage gates are a SEPARATE, coarser use of
//     `tier_suppresses` (PARITY-I) this consolidation leaves untouched.
//   • [`downgraded_action`]     — the single application site for the per-symbol
//     oracle-authority downgrade ([`oracle_stale_downgrade_action`] WU-0016 leg
//     E). BOTH paths route their
//     per-symbol action through here, so the `graph reachability` `dead_confirmed`
//     bucket claims SafeDelete-grade confidence ONLY when the corroboration holds
//     (the D3/D4 REPORTING-vs-GATING split: downgrades touch the reported
//     confidence LABELS; RAW membership stays for the `--fail-on-dead` exit).
// The gate signals both paths (+ both surfaces, CLI≡MCP) resolve are unified in
// [`GateSignals`] via the single [`GateSignals::derive`] loader (D7). See
// ADR-0034 (§Decision-2/§Decision-10 — verb-level suppress + over-suppression is
// itself a lie), ADR-0035 (D2 per-symbol strip + ATTACK-1 fig-leaf rejection),
// ADR-0038 (§2 the compiler-sound coverage-complete DEAD tier), and WU-0016
// legs E (`oracle_stale_downgrade_action`) + F (`classify_withhold_cause`).

/// The three gate signals the dead pipeline consumes, resolved ONCE per surface
/// via [`GateSignals::derive`] (WU-0022 S1, D7).
///
/// Unifies the previously-divergent signal sourcing: the CLI read
/// scip/oracle state from the `data_dir` redb, the MCP threaded it via
/// `ToolContext`, and `graph reachability` applied NO downgrades at all — all
/// three now collapse their raw bits through the SAME loader so the `dead`
/// command (CLI + MCP) and `graph reachability` derive identically (CLI≡MCP
/// parity by construction; PARITY-J).
///
/// `tier` gates ONLY Path B's whole verb ([`dead_verb_suppressed`]); Path A
/// ([`compute_dead_tiers`](crate::dead_pipeline::compute_dead_tiers)) IGNORES it
/// by contract — a wiring gate fires on RAW membership under any coverage
/// (`dead_pipeline` MAJOR-2). `oracle_ran_ok` feeds the per-symbol downgrade
/// ([`downgraded_action`]) on BOTH paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateSignals {
    /// Call-graph coverage tier (ADR-0034 L4). Consumed only by
    /// [`dead_verb_suppressed`] (Path B whole-verb gate).
    pub tier: crate::graph_stats::CoverageTier,
    /// Whether the last index's Phase-8e oracle pass was authoritative
    /// (WU-0016 leg E; missing metadata is non-authoritative). Feeds
    /// [`downgraded_action`] (both paths).
    pub oracle_ran_ok: bool,
    /// Whether reachability classification ran for this graph (DEC-R8a, WU-0023
    /// P3b — [`graph_reachability_classified`]). Consumed ONLY by
    /// [`dead_verb_suppressed`] (Path B whole-verb gate, via [`suppresses`]);
    /// Path A ([`compute_dead_tiers`](crate::dead_pipeline::compute_dead_tiers))
    /// IGNORES it (a wiring gate must fire on RAW membership under any signal —
    /// LEAK-3). [`GateSignals::derive`] defaults it to `true` (the absent/legacy
    /// convention — a store predating this axis reads as classified); the Path-B
    /// surfaces override it with the graph-derived value.
    pub reachability_classified: bool,
}

impl GateSignals {
    /// Derive the collapsed gate signals from a surface's already-loaded raw bits
    /// — the ONE loader the `dead` command (CLI + MCP) and `graph reachability`
    /// all call (WU-0022 S1, D7).
    ///
    /// `cov` is the already-computed [`CallEdgeCoverage`](crate::graph_stats::CallEdgeCoverage)
    /// (surfaces reuse it for their coverage block, so it is passed in rather than
    /// recomputed); `oracle_ran_ok` collapses the snapshot state with absence
    /// failing closed.
    #[must_use]
    pub fn derive(cov: &crate::graph_stats::CallEdgeCoverage, oracle_ran_ok: Option<bool>) -> Self {
        Self {
            tier: crate::graph_stats::coverage_tier(cov),
            oracle_ran_ok: oracle_ran_ok.unwrap_or(false),
            // Path-B surfaces override this graph-classification default with
            // `graph_reachability_classified(graph)`; Path A
            // (`compute_dead_tiers`, via `graph reachability`) leaves it TRUE and
            // never reads it (raw-membership gate — LEAK-3).
            reachability_classified: true,
        }
    }
}

/// The SINGLE dead-pipeline application site for the ADR-0034 L4 whole-verb
/// coverage suppression + the ADR-0035 D3 evidence-of-damage suppression
/// (WU-0022 S1).
///
/// `dead_report_gated` + `dead_single_gated` (Path B) both gate through here, so
/// [`tier_suppresses`] has exactly ONE dead-pipeline call site. Path A
/// ([`compute_dead_tiers`](crate::dead_pipeline::compute_dead_tiers)) deliberately
/// does NOT consult this: a wiring gate must fire on RAW membership under any
/// coverage (`dead_pipeline` MAJOR-2), and suppressing it under low coverage
/// would let genuinely-unwired code silently PASS `--fail-on-dead` — the exact
/// damaging mode ADR-0034 (poisoned-Dead-set) + ADR-0035 (ATTACK-1) forbid.
#[must_use]
pub(crate) const fn dead_verb_suppressed(signals: GateSignals) -> bool {
    // DEC-R8a: the two-arg `suppresses` chokepoint folds the coverage tier AND
    // the reachability-classification axis (an unclassified graph → UNKNOWN).
    suppresses(signals.tier, signals.reachability_classified)
}

/// The SINGLE application site for the per-symbol oracle-authority downgrade
/// (WU-0022 S1) — [`oracle_stale_downgrade_action`] (WU-0016 leg E).
///
/// EVERY dead-pipeline surface routes its per-symbol action through here — the
/// `dead` full/single reports (Path B) AND the `graph reachability` tiers
/// projection (Path A) — so `oracle_stale_downgrade_action` has exactly one
/// call site (this fn), and
/// a would-be-`SafeDelete` symbol claims `dead_confirmed`/SafeDelete-grade
/// confidence ONLY when the corroboration holds. A degraded oracle strips
/// `SafeDelete` → `SuspectedDelete`.
#[must_use]
pub(crate) fn downgraded_action(raw: DeadAction, signals: GateSignals) -> DeadAction {
    oracle_stale_downgrade_action(raw, signals.oracle_ran_ok)
}

/// Compute the FULL dead report under the coverage gate (ADR-0034 L4,
/// Decision 2).
///
/// Under an insufficient tier (`None`/enabled-`Low`) it
/// short-circuits to [`DeadReport::Unknown`] **BEFORE** the Dead set is
/// consulted — it does not classify nodes, does not run
/// [`classify_dead_action`], does not enumerate `Dead|Orphan`. Otherwise it
/// returns the full report unchanged. Suppress-only + monotone: it withholds,
/// never manufactures (a future L6 coverage rise un-suppresses `None →
/// Sufficient`). BOTH the CLI `run_dead_full` and the MCP `execute_dead_full`
/// route through this — the by-construction parity surface (S5).
#[must_use]
pub fn dead_report_gated(
    graph: &KnowledgeGraph,
    tier: crate::graph_stats::CoverageTier,
    oracle_ran_ok: bool,
) -> DeadReport {
    let resolved = languages_touching_scip_calls(graph);
    let mut legacy_complete_languages = resolved
        .into_iter()
        .map(LanguageId::new)
        .collect::<BTreeSet<_>>();
    legacy_complete_languages.insert(LanguageId::new("rust"));
    dead_report_gated_with_calls_authority(graph, tier, oracle_ran_ok, &legacy_complete_languages)
}

/// Compute the full dead report using exact generation-authoritative Calls
/// coverage partitioned by language.
///
/// This is the production entrypoint. `complete_languages` must come from the
/// queried immutable generation's capability receipts and project inventory.
/// A complete language remains reportable in a mixed repository while every
/// incomplete language is withheld instead of being promoted by another
/// provider's success.
#[must_use]
pub fn dead_report_gated_with_calls_authority(
    graph: &KnowledgeGraph,
    tier: crate::graph_stats::CoverageTier,
    oracle_ran_ok: bool,
    complete_languages: &BTreeSet<LanguageId>,
) -> DeadReport {
    // WU-0022 S1: the ADR-0034 L4 coverage suppression via the SINGLE
    // dead-pipeline gate (`dead_verb_suppressed`) short-circuits to verb-level UNKNOWN
    // BEFORE the Dead set is consulted. DEC-R8a (WU-0023 P3b): the
    // reachability-classification axis is DERIVED from the graph here (the
    // parity-by-construction source — both CLI and MCP call this one engine fn),
    // so an unclassified graph short-circuits to UNKNOWN, never a false-CLEAN 0.
    let signals = GateSignals {
        tier,
        oracle_ran_ok,
        reachability_classified: graph_reachability_classified(graph),
    };
    if dead_verb_suppressed(signals) {
        return DeadReport::Unknown;
    }

    // DEC-R5a (WU-0023 P3b): the set of coverage-uncovered LANGUAGES (Go at the
    // tags floor), DERIVED from the graph (SCIP-Calls-edge provenance) so BOTH
    // surfaces get the same set by construction. Empty on a Rust-only store →
    // no exclusion below → byte-identical (RUST NO-REGRESSION).
    let suppressed_langs = coverage_suppressed_languages_from_authority(graph, complete_languages);

    // WU-0015 Leg-3b: compute the cfg-touching-crate set ONCE per report
    // (`cfg_touching_crates` is O(all_nodes)) and thread it into every per-node
    // `classify_dead_action` — NEVER recompute it per node.
    let cfg_crates = cfg_touching_crates(graph);
    let entries: Vec<DeadEntry> = graph
        .all_nodes()
        .into_iter()
        .filter(|n| {
            matches!(
                n.reachability_class,
                // WU-0015 / ADR-0036 v6: surface the `Suspected` recall tier
                // alongside Dead/Orphan so the directed-reachability residue is
                // SHOWN (as a non-delete SUSPECTED hint), not merely computed.
                ReachabilityClass::Dead
                    | ReachabilityClass::Orphan
                    | ReachabilityClass::Suspected
            )
            // WU-0014: build-script `OUT_DIR` glue under `target/` is never
            // user-owned source — exclude it from the SAFE_DELETE surface.
            && !is_generated_target_path(&n.file_path)
            // DEC-R5a (WU-0023 P3b): a node whose LANGUAGE has insufficient
            // call-graph coverage (e.g. Go at the tags floor) renders UNKNOWN —
            // it is EXCLUDED from the authoritative dead set here, never summed
            // into a blended Dead total. On a Rust-only store `suppressed_langs`
            // is empty → no exclusion → byte-identical (RUST NO-REGRESSION).
            && !node_language_suppressed(n, &suppressed_langs)
        })
        .map(|n| DeadEntry {
            node_id: n.memory_id,
            symbol_name: n.symbol_name.clone(),
            kind: n.kind.clone(),
            file_path: n.file_path.clone(),
            reachability: n.reachability_class,
            // WU-0022 S1: the per-symbol delete-authority downgrade via the SINGLE
            // application site (`downgraded_action`) — the
            // OQ-ORACLE-INCREMENTAL-STALE backstop strips SafeDelete →
            // SuspectedDelete while keeping the finding.
            action: downgraded_action(classify_dead_action(graph, n, &cfg_crates), signals),
            // WU-0016 Leg F: the cause-carrying reason, computed HERE where the
            // oracle disposition is in scope (parity by construction —
            // the MCP + CLI full reports both consume this ONE field).
            withhold_reason: classify_withhold_cause(graph, n, &cfg_crates, oracle_ran_ok),
        })
        .collect();

    DeadReport::Full(DeadFullData { entries })
}

/// Apply the OQ-ORACLE-INCREMENTAL-STALE backstop downgrade (part b2).
///
/// When the last reindex's Phase-8e oracle pass was NOT authoritative
/// (`oracle_ran_ok == false` — a degraded/absent clippy build could not
/// re-affirm the per-node `rustc_flagged_dead` bits), a confident
/// [`DeadAction::SafeDelete`] is downgraded to [`DeadAction::SuspectedDelete`]
/// (delete authority stripped); every other action and an authoritative pass
/// (`oracle_ran_ok == true`) are unchanged.
///
/// TARGETED, not blanket: it fires ONLY on a degraded build (rare + genuinely
/// global), NOT on every incremental — so the confirmed tier is preserved on the
/// normal clean-incremental path (the part-c blanket-drift downgrade this
/// SUPERSEDES would have collapsed it every incremental). Pure + `#[must_use]`.
/// WU-0022 S1: applied at exactly one application site
/// ([`downgraded_action`]), which every dead-pipeline surface
/// (Path A + Path B, CLI + MCP) routes through — so the degraded-oracle strip is
/// applied identically everywhere (parity by construction). Kept `pub` for the
/// leg-E unit tests that exercise it directly.
#[must_use]
pub fn oracle_stale_downgrade_action(action: DeadAction, oracle_ran_ok: bool) -> DeadAction {
    if !oracle_ran_ok && action == DeadAction::SafeDelete {
        DeadAction::SuspectedDelete
    } else {
        action
    }
}

/// Compute the SINGLE-symbol dead report under the coverage gate (ADR-0034 L4,
/// Decision 3).
///
/// Under an insufficient tier it returns [`DeadSingleReport::Unknown`]
/// — withholding reachability and the action recommendation — without computing
/// either. Otherwise it returns the real verdict (`classify_dead_action`). BOTH
/// single-symbol paths route through this (S5).
#[must_use]
pub fn dead_single_gated(
    graph: &KnowledgeGraph,
    node: &GraphNode,
    tier: crate::graph_stats::CoverageTier,
    oracle_ran_ok: bool,
) -> DeadSingleReport {
    let resolved = languages_touching_scip_calls(graph);
    let mut legacy_complete_languages = resolved
        .into_iter()
        .map(LanguageId::new)
        .collect::<BTreeSet<_>>();
    legacy_complete_languages.insert(LanguageId::new("rust"));
    dead_single_gated_with_calls_authority(
        graph,
        node,
        tier,
        oracle_ran_ok,
        &legacy_complete_languages,
    )
}

/// Compute one dead-code verdict using exact generation-authoritative Calls
/// coverage partitioned by language.
#[must_use]
pub fn dead_single_gated_with_calls_authority(
    graph: &KnowledgeGraph,
    node: &GraphNode,
    tier: crate::graph_stats::CoverageTier,
    oracle_ran_ok: bool,
    complete_languages: &BTreeSet<LanguageId>,
) -> DeadSingleReport {
    // WU-0022 S1: the whole-verb gate via the SINGLE dead-pipeline consumer.
    // DEC-R8a (WU-0023 P3b): the reachability-classification axis is DERIVED from
    // the graph (parity-by-construction with the full report + the CLI/MCP gates).
    let signals = GateSignals {
        tier,
        oracle_ran_ok,
        reachability_classified: graph_reachability_classified(graph),
    };
    if dead_verb_suppressed(signals) {
        return DeadSingleReport::Unknown;
    }

    // DEC-R5a (WU-0023 P3b): a symbol whose LANGUAGE has insufficient call-graph
    // coverage (e.g. a Go symbol at the tags floor) renders UNKNOWN — its
    // reachability/action are withheld, NEVER a false-DEAD verdict. Derived from
    // the graph (SCIP-Calls-edge provenance); empty on a Rust-only store.
    if node_language_suppressed(
        node,
        &coverage_suppressed_languages_from_authority(graph, complete_languages),
    ) {
        return DeadSingleReport::Unknown;
    }

    // Generated build-script OUT_DIR code (under target/) is never a user
    // deletion target — exclude it from the single-symbol SAFE_DELETE surface
    // too, mirroring the dead_report_gated full-report filter (closes the
    // single-symbol target/-glue leak flagged in review).
    let is_dead = matches!(
        node.reachability_class,
        // WU-0015 / ADR-0036 v6: the `Suspected` recall tier is surfaced here as
        // a non-delete candidate too (its action is `SuspectedDelete`, never
        // `SafeDelete`), so `dead <symbol>` reports the directed-reachability
        // residue instead of hiding it.
        ReachabilityClass::Dead | ReachabilityClass::Orphan | ReachabilityClass::Suspected
    ) && !is_generated_target_path(&node.file_path);
    // WU-0015 Leg-3b: compute the cfg-touching-crate set ONCE (O(all_nodes)) and
    // thread it into the action recommendation. Only computed when the node is a
    // dead/suspected candidate (the recommendation is otherwise `None`).
    let cfg_crates = if is_dead {
        cfg_touching_crates(graph)
    } else {
        HashSet::new()
    };
    let action = if is_dead {
        // WU-0022 S1: the per-symbol downgrade via the SINGLE application site
        // (`downgraded_action`) — the single-symbol twin of the full-report
        // composition (ADR-0035 D2 ∘ OQ-ORACLE-INCREMENTAL-STALE).
        Some(downgraded_action(
            classify_dead_action(graph, node, &cfg_crates),
            signals,
        ))
    } else {
        None
    };

    // WU-0016 Leg F: the cause-carrying reason — computed HERE with oracle state
    // in scope so the single-symbol surface names the specific withhold cause
    // (not the overloaded un-indexable lie). `Some` iff `is_dead`, mirroring
    // `action`; parity by construction with the full-report `DeadEntry` field.
    let withhold_reason = if is_dead {
        Some(classify_withhold_cause(
            graph,
            node,
            &cfg_crates,
            oracle_ran_ok,
        ))
    } else {
        None
    };

    DeadSingleReport::Computed {
        is_dead,
        action,
        withhold_reason,
    }
}

// ============================================================================
// L4 reachability suppression for the composite verbs (ADR-0034, WU-0014)
// ============================================================================
//
// `dead`/`audit`/`overview`/`status` already gate on call-graph coverage. The
// composite reachability verbs — `assess`/`inspect`/`tests` — leaked CONFIDENT
// reachability verdicts (DEAD / 0 callers / RISK: LOW / ACTION TIER) on a
// provider-unavailable repo, where the call graph is unauthorised. These helpers thread
// the same gate into those verbs' JSON: under `Unavailable` coverage the
// reachability-DERIVED fields are replaced with honest `UNKNOWN`, while the
// SYNTACTIC facts (source, signature, structure) are preserved. They are pure
// JSON post-processors shared by BOTH the CLI (`h00ligan`) and MCP (`h00ligan-interface`)
// renderers, so CLI≡MCP parity holds by construction. Suppress-only: they never
// fabricate a verdict.

/// The honest UNKNOWN `callers`/`tests` sub-object both verbs emit under
/// suppression: an unknown count with an empty item list (NEVER `0`, which would
/// read as a confident "no callers").
fn unknown_count_section(count_key: &str) -> serde_json::Value {
    serde_json::json!({
        count_key: serde_json::Value::Null,
        "items": [],
    })
}

/// Attach the shared `coverage` block + remediation note to a suppressed result.
fn attach_coverage_note(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    coverage: serde_json::Value,
) {
    obj.insert("coverage".to_string(), coverage);
    obj.insert(
        "action_required".to_string(),
        serde_json::json!(crate::graph_stats::CALLS_ACTIONABLE_GAP_GUIDANCE),
    );
}

/// Suppress the reachability-derived fields of an `assess` result to UNKNOWN.
///
/// Every `assess` section (blast_radius/callers/tests/risk) is call-graph
/// derived, so all are neutralized; the syntactic identity (`symbol`/`resolved`)
/// is preserved. Only keys already present are rewritten, so the requested-
/// sections contract is honored.
pub fn suppress_assess_json(result: &mut serde_json::Value, coverage: serde_json::Value) {
    let Some(obj) = result.as_object_mut() else {
        return;
    };
    obj.insert("reachability".to_string(), serde_json::json!("UNKNOWN"));
    if obj.contains_key("blast_radius") {
        obj.insert(
            "blast_radius".to_string(),
            serde_json::json!({
                "total_affected": serde_json::Value::Null,
                "affected": [],
                "reachability": "UNKNOWN",
            }),
        );
    }
    if obj.contains_key("callers") {
        obj.insert("callers".to_string(), unknown_count_section("count"));
    }
    if obj.contains_key("tests") {
        obj.insert(
            "tests".to_string(),
            unknown_count_section("test_function_count"),
        );
    }
    if obj.contains_key("risk") {
        obj.insert(
            "risk".to_string(),
            serde_json::json!({
                "level": "UNKNOWN",
                "fan_in": serde_json::Value::Null,
                "max_depth": serde_json::Value::Null,
                "files_affected": serde_json::Value::Null,
                "test_function_count": serde_json::Value::Null,
            }),
        );
    }
    attach_coverage_note(obj, coverage);
}

/// Suppress the reachability-derived fields of an `inspect` result to UNKNOWN.
///
/// Keeps the syntactic sections (source/signature/structure fields+variants) and
/// neutralizes only the call-graph-derived ones: top-level reachability,
/// per-method reachability, callers, field_usage (caller-derived), tests, the
/// action tier, and the reachability/no-callers warnings.
pub fn suppress_inspect_json(result: &mut serde_json::Value, coverage: serde_json::Value) {
    let Some(obj) = result.as_object_mut() else {
        return;
    };
    obj.insert("reachability".to_string(), serde_json::json!("UNKNOWN"));
    // Per-method reachability inside `structure` is also call-graph derived.
    if let Some(methods) = obj
        .get_mut("structure")
        .and_then(|s| s.get_mut("methods"))
        .and_then(serde_json::Value::as_array_mut)
    {
        for m in methods {
            if let Some(mo) = m.as_object_mut()
                && mo.contains_key("reachability")
            {
                mo.insert("reachability".to_string(), serde_json::json!("UNKNOWN"));
            }
        }
    }
    if obj.contains_key("callers") {
        obj.insert("callers".to_string(), unknown_count_section("count"));
    }
    // field_usage is derived from the (unknown) caller set — withhold it.
    if obj.contains_key("field_usage") {
        obj.insert("field_usage".to_string(), serde_json::Value::Null);
    }
    if obj.contains_key("tests") {
        obj.insert("tests".to_string(), unknown_count_section("count"));
    }
    if obj.contains_key("action_tier") {
        obj.insert("action_tier".to_string(), serde_json::json!("UNKNOWN"));
    }
    // Drop the reachability/no-callers warnings; keep syntactic ones (signature,
    // line range).
    if let Some(warnings) = obj
        .get_mut("warnings")
        .and_then(serde_json::Value::as_array_mut)
    {
        warnings.retain(|w| {
            w.as_str().is_none_or(|s| {
                !(s.starts_with("DEAD:")
                    || s.starts_with("ORPHAN:")
                    || s.starts_with("TEST_ONLY:")
                    || s.starts_with("No callers detected"))
            })
        });
        if warnings.is_empty() {
            obj.remove("warnings");
        }
    }
    attach_coverage_note(obj, coverage);
}

/// Suppress the reachability-derived fields of a `tests` result to UNKNOWN.
///
/// The test set is reverse-BFS over the (absent) call graph, so under
/// suppression the count, list, and reachability are withheld rather than
/// rendered as a confident `0` / `NO COVERAGE`.
pub fn suppress_tests_json(result: &mut serde_json::Value, coverage: serde_json::Value) {
    let Some(obj) = result.as_object_mut() else {
        return;
    };
    obj.insert("reachability".to_string(), serde_json::json!("UNKNOWN"));
    obj.insert("test_count".to_string(), serde_json::Value::Null);
    obj.insert("tests".to_string(), serde_json::json!([]));
    obj.insert("truncated".to_string(), serde_json::json!(false));
    obj.remove("truncation_hint");
    attach_coverage_note(obj, coverage);
}

/// Find test functions that transitively call a given symbol via reverse BFS.
///
/// Walks incoming edges from the target, collecting `#[test]` / `#[tokio::test]`
/// functions along the way. Returns each test function with the call chain
/// from the target to that test.
///
/// WU-0003 / CL-REACH RC2 (finish-collapse): routes through the ONE traversal
/// core ([`graph_walk`]) via the `test_callers` preset (INCOMING / `Dependency`
/// admission — the historical `is_dependency_edge` set, NO trait bridge, NO
/// test-module prune), DELETING the hand-rolled BFS loop. The per-node call
/// chain (`path`) is threaded through the visitor via a `from`-keyed map: the
/// root's chain is `[target_name]` and each discovered node's chain is its
/// parent's chain plus its own name. The legacy depth cap was `path.len() < 10`
/// where `path` was the PARENT's chain, i.e. a node was expanded when its
/// parent's chain was shorter than 10. Equivalently, a discovered node's OWN
/// chain length is the parent's plus one, so it is expanded iff its own chain
/// length is `<= 10` — reproduced here exactly.
pub fn find_test_callers<'a>(
    graph: &'a KnowledgeGraph,
    target_id: Uuid,
) -> Vec<(&'a GraphNode, Vec<String>)> {
    let mut results: Vec<(&'a GraphNode, Vec<String>)> = Vec::new();
    // Per-node call chain, keyed by node id. The root's chain is seeded with the
    // target's symbol name; each discovered node's chain is built from its
    // parent's (`step.from`) chain. BFS visits each node once on first (shortest)
    // arrival, and `from` is always an already-visited node, so its chain is
    // present when a child is reached — mirroring the legacy per-queue-entry
    // path threading.
    let mut chains: HashMap<Uuid, Vec<String>> = HashMap::new();

    graph_walk(
        graph,
        &[target_id],
        &BfsSpec::test_callers(),
        None,
        |step| {
            // Root (depth 0): seed its chain and always expand.
            if step.depth == 0 {
                let target_name = graph
                    .node(&step.node_id)
                    .map(|n| n.symbol_name.clone())
                    .unwrap_or_default();
                chains.insert(step.node_id, vec![target_name]);
                return WalkControl::Continue;
            }

            let Some(caller_node) = graph.node(&step.node_id) else {
                // Unknown node: legacy never built a path or enqueued it.
                return WalkControl::SkipChildren;
            };

            // Build this node's chain = parent's chain + this node's name.
            let parent_chain = step
                .from
                .and_then(|f| chains.get(&f))
                .cloned()
                .unwrap_or_default();
            let mut new_path = parent_chain;
            new_path.push(caller_node.symbol_name.clone());

            // WU-0003 / CL-REACH-06: a node is in hand, so consult the persisted
            // is_test_only bit (`node_is_test`) first; the `tests::` qualified-name
            // checks remain an OR-fallback for SCIP/old nodes whose bit is `None`.
            if (node_is_test(graph, caller_node)
                || caller_node.symbol_name.starts_with("tests::")
                || caller_node.symbol_name.contains("::tests::"))
                && symbol_kind_has_role(&caller_node.kind, SymbolRole::Callable)
            {
                results.push((caller_node, new_path.clone()));
            }

            // Legacy enqueued a node iff its PARENT's chain length was `< 10`;
            // equivalently this node's OWN chain length is `<= 10`.
            let own_len = new_path.len();
            chains.insert(step.node_id, new_path);
            if own_len <= 10 {
                WalkControl::Continue
            } else {
                WalkControl::SkipChildren
            }
        },
    );

    results
}

// ============================================================================
// collect_type_children — language-neutral type/container traversal
// ============================================================================

/// Structural children of a type node, classified by role.
///
/// Used by both the standalone `type` handler (`code_intel::TypeDefHandler`)
/// and the `inspect` handler's `structure` section to present a consistent
/// view of what a type contains.
#[derive(Debug, Default, Clone)]
pub struct TypeChildren {
    /// Data-member nodes (for example Rust/Go fields or class properties).
    pub fields: Vec<GraphNode>,
    /// Referenced field types (FieldOf edges — resolved struct/enum types
    /// used inside this struct's fields).
    pub field_type_refs: Vec<GraphNode>,
    /// Callable nodes. These can be direct children or depth-2 children of an
    /// implementation block.
    pub methods: Vec<GraphNode>,
    /// Enum variants (depth-1 Contains, kind `variant` or `enum_variant`).
    pub variants: Vec<GraphNode>,
    /// Impl block nodes related to this type (depth-1 Contains where child
    /// kind is `impl`). Useful for reporting trait implementations.
    pub impl_blocks: Vec<GraphNode>,
}

/// Collects the structural children of any type or container node.
///
/// Direct `Contains` children are classified by language-neutral symbol role.
/// If the root contains implementation blocks, their callable children are
/// flattened into the same method population. Traversal follows graph shape,
/// not a closed list of source-language type spellings.
pub fn collect_type_children(graph: &KnowledgeGraph, root_id: &Uuid) -> TypeChildren {
    let mut out = TypeChildren::default();

    if graph.node(root_id).is_none() {
        return out;
    }

    // Depth-1 traversal: classify Contains/FieldOf children by kind.
    let mut impl_block_ids: Vec<Uuid> = Vec::new();
    for (target_id, edge) in graph.neighbors(root_id) {
        if edge.kind == EdgeKind::FieldOf {
            if let Some(child) = graph.node(&target_id) {
                out.field_type_refs.push(child.clone());
            }
            continue;
        }
        if edge.kind != EdgeKind::Contains {
            continue;
        }
        let Some(child) = graph.node(&target_id) else {
            continue;
        };
        match child.kind.as_str() {
            kind if symbol_kind_has_role(kind, SymbolRole::DataMember) => {
                out.fields.push(child.clone());
            }
            "enum_variant" | "variant" => out.variants.push(child.clone()),
            kind if symbol_kind_has_role(kind, SymbolRole::Callable) => {
                out.methods.push(child.clone());
            }
            "impl" => {
                out.impl_blocks.push(child.clone());
                impl_block_ids.push(target_id);
            }
            _ => { /* skip unknown child kinds (type_param, etc.) */ }
        }
    }

    // Depth-2 traversal: callable children nested in implementation blocks.
    let mut seen_method_ids: HashSet<Uuid> = out.methods.iter().map(|m| m.memory_id).collect();
    for impl_id in &impl_block_ids {
        for (method_id, edge) in graph.neighbors(impl_id) {
            if edge.kind != EdgeKind::Contains {
                continue;
            }
            if !seen_method_ids.insert(method_id) {
                continue;
            }
            let Some(method_node) = graph.node(&method_id) else {
                continue;
            };
            if symbol_kind_has_role(&method_node.kind, SymbolRole::Callable) {
                out.methods.push(method_node.clone());
            }
        }
    }

    out
}

// ============================================================================
// Field-usage heuristic helpers (shared by MCP + CLI inspect handlers)
// ============================================================================

/// Strip `//` line comments and `"..."` string contents from a single
/// source line. Used by field_usage detection to avoid matching field
/// names mentioned in docstrings or error messages.
///
/// Single-line scanner — does NOT handle block comments (`/* ... */`)
/// or raw strings (`r"..."`). For heuristic matching, the false-positive
/// rate these introduce is acceptable given the alternative is a
/// tree-sitter rewrite.
pub fn strip_comments_and_strings(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let bytes = line.as_bytes();
    let mut i = 0;
    let mut in_string = false;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            out.push(' ');
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            break;
        }
        if b == b'"' {
            in_string = true;
            out.push(' ');
            i += 1;
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
}

/// Build the field-usage regex source for a single field.
///
/// Matches four usage patterns (with regex escaping for metacharacters):
///   1. `\.field\b`            — dot-access (`self.field`)
///   2. `\bfield:`             — explicit init (`Foo { field: v }`)
///   3. `[\{,]\s*field\s*[,}]` — shorthand init (first or middle position)
///   4. `let \w+ \{..field..}` — destructuring
pub fn field_usage_regex_pattern(field_name: &str) -> String {
    let escaped = regex::escape(field_name);
    format!(
        r"(\.{0}\b)|(\b{0}:)|([\{{,]\s*{0}\s*[,}}])|(let\s+\w+\s*\{{[^}}]*\b{0}\b)",
        escaped
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphEdge, GraphNode, KnowledgeGraph};
    use std::assert_matches;

    fn make_node(name: &str, kind: &str, file: &str) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.into(),
            kind: kind.into(),
            file_path: file.into(),
            content_hash: "abc123".into(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Unclassified,
            line_start: None,
            line_end: None,
            has_body: None,
            visibility: String::new(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        }
    }

    fn calls_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::Calls,
            confidence: 0.9,
            ..GraphEdge::default()
        }
    }

    #[test]
    fn delete_visibility_is_an_explicit_allowlist() {
        for visibility in ["private", "pub(crate)", "pub(super)", "pub(in crate::x)"] {
            assert!(visibility_is_deletable(visibility), "{visibility}");
        }
        for visibility in ["", "pub", "protected", "package", "unknown"] {
            assert!(!visibility_is_deletable(visibility), "{visibility}");
        }
    }

    fn contains_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::Contains,
            confidence: 1.0,
            ..GraphEdge::default()
        }
    }

    /// FALSIFIER for the nominally generic extractor registry: Python and
    /// TypeScript definitions must not disappear merely because the shared
    /// symbol vocabulary was frozen around Rust and Go spellings. The known
    /// positive and nested negative keep this from passing through a blanket
    /// `true` fallback.
    #[test]
    fn top_level_symbol_roles_cover_polyglot_definition_kinds() {
        assert!(is_top_level_kind("function"), "known-positive control");
        for kind in ["class", "interface", "namespace", "variable", "import"] {
            assert!(
                is_top_level_kind(kind),
                "{kind} must participate in universal definition queries"
            );
        }
        assert!(!is_top_level_kind("field"), "nested-field negative control");
    }

    // The former find_node_by_name first-match-blessing tests (exact/suffix/
    // substring/not-found) were DELETED in WU-0002 Wave 3 (ADR-0027): they are
    // subsumed by the EP1 falsifiers below — f1_bare_name_homonyms_resolve_ambiguous,
    // f5_qualified_resolves_while_bare_is_ambiguous, f6 NotFound — which assert the
    // FIXED ambiguity/NotFound behavior rather than the silent first match.

    // -- find_trait_method_for_impl tests --

    #[test]
    fn trait_method_for_impl_found() {
        let mut graph = KnowledgeGraph::new();
        let impl_node = make_node(
            "impl MemoryStore for LanceStore::store",
            "function",
            "src/lance_store.rs",
        );
        let trait_node = make_node("MemoryStore::store", "function", "src/store.rs");

        graph.add_node(impl_node.clone()).unwrap();
        graph.add_node(trait_node).unwrap();

        let found = find_trait_method_for_impl(&graph, &impl_node).unwrap();
        assert_eq!(found.symbol_name, "MemoryStore::store");
    }

    #[test]
    fn trait_method_for_non_impl_returns_none() {
        let graph = KnowledgeGraph::new();
        let node = make_node("MemoryStore::store", "function", "src/store.rs");
        assert!(find_trait_method_for_impl(&graph, &node).is_none());
    }

    // -- find_impl_methods_for_trait tests --

    #[test]
    fn impl_methods_for_trait_found() {
        let mut graph = KnowledgeGraph::new();
        let trait_node = make_node("MemoryStore::store", "function", "src/store.rs");
        let impl1 = make_node(
            "impl MemoryStore for LanceStore::store",
            "function",
            "src/lance_store.rs",
        );
        let impl2 = make_node(
            "impl MemoryStore for MockStore::store",
            "function",
            "src/mock_store.rs",
        );
        let unrelated = make_node(
            "impl OtherTrait for LanceStore::store",
            "function",
            "src/lance_store.rs",
        );

        graph.add_node(trait_node.clone()).unwrap();
        graph.add_node(impl1).unwrap();
        graph.add_node(impl2).unwrap();
        graph.add_node(unrelated).unwrap();

        let impls = find_impl_methods_for_trait(&graph, &trait_node);
        assert_eq!(impls.len(), 2);
        assert!(
            impls
                .iter()
                .any(|n| n.symbol_name == "impl MemoryStore for LanceStore::store")
        );
        assert!(
            impls
                .iter()
                .any(|n| n.symbol_name == "impl MemoryStore for MockStore::store")
        );
    }

    #[test]
    fn impl_methods_for_impl_returns_empty() {
        let graph = KnowledgeGraph::new();
        let impl_node = make_node(
            "impl MemoryStore for LanceStore::store",
            "function",
            "src/lance_store.rs",
        );
        let impls = find_impl_methods_for_trait(&graph, &impl_node);
        assert!(impls.is_empty());
    }

    #[test]
    fn impl_methods_for_simple_name_returns_empty() {
        let graph = KnowledgeGraph::new();
        let simple_node = make_node("store", "function", "src/lib.rs");
        let impls = find_impl_methods_for_trait(&graph, &simple_node);
        assert!(impls.is_empty());
    }

    // -- edge filter tests --

    #[test]
    fn dependency_edge_filter() {
        assert!(is_dependency_edge(EdgeKind::Calls));
        assert!(is_dependency_edge(EdgeKind::Contains));
        assert!(is_dependency_edge(EdgeKind::Implements));
        assert!(is_dependency_edge(EdgeKind::HasImpl));
        assert!(is_dependency_edge(EdgeKind::References));
        assert!(is_dependency_edge(EdgeKind::TypeOf));
        assert!(is_dependency_edge(EdgeKind::FieldOf));
        assert!(!is_dependency_edge(EdgeKind::RelatedTo));
        assert!(!is_dependency_edge(EdgeKind::DependsOn));
        assert!(!is_dependency_edge(EdgeKind::Extends));
    }

    /// WU-0003 / CL-REACH RC1 — F6: the ONE edge-admission surface `admits`
    /// is an exhaustive truth table over all 10 `EdgeKind` variants × all
    /// `EdgeClass` values. There is NO `_ =>` wildcard in `admits` (verify by
    /// reading the source): adding a 10th `EdgeKind` variant would fail to
    /// compile until classified here.
    #[test]
    fn admits_exhaustive_truth_table() {
        // The complete EdgeKind universe — if a variant is added, this array
        // and `admits` both fail to compile until updated.
        let all = [
            EdgeKind::Calls,
            EdgeKind::Implements,
            EdgeKind::Contains,
            EdgeKind::References,
            EdgeKind::DependsOn,
            EdgeKind::Extends,
            EdgeKind::TypeOf,
            EdgeKind::FieldOf,
            EdgeKind::HasImpl,
            EdgeKind::RelatedTo,
        ];
        assert_eq!(
            all.len(),
            10,
            "EdgeKind variant count changed — update admits + this table"
        );

        // Structural: all 9 except RelatedTo.
        for k in all {
            let expect = !matches!(k, EdgeKind::RelatedTo);
            assert_eq!(
                admits(EdgeClass::Structural, k),
                expect,
                "Structural admit mismatch for {k:?}"
            );
        }

        // Dependency: Structural minus DependsOn + Extends (7 kinds).
        for k in all {
            let expect = !matches!(
                k,
                EdgeKind::DependsOn | EdgeKind::Extends | EdgeKind::RelatedTo
            );
            assert_eq!(
                admits(EdgeClass::Dependency, k),
                expect,
                "Dependency admit mismatch for {k:?}"
            );
        }

        // Call: only symbol-level use edges.
        for k in all {
            let expect = matches!(
                k,
                EdgeKind::Calls
                    | EdgeKind::References
                    | EdgeKind::TypeOf
                    | EdgeKind::FieldOf
                    | EdgeKind::Extends
            );
            assert_eq!(
                admits(EdgeClass::Call, k),
                expect,
                "Call admit mismatch for {k:?}"
            );
        }

        // The public dependency predicate is a thin adapter over `admits`.
        for k in all {
            assert_eq!(is_dependency_edge(k), admits(EdgeClass::Dependency, k));
        }
    }

    /// WU-0003 / CL-REACH RC1 — F5: the human-facing label is *derived* from
    /// the admit-set, so it can never drift from what `admits` follows. (HEAD
    /// rendered a hand-written 4-kind label for a 7-kind filter — the bug this
    /// closes.)
    #[test]
    fn admit_set_label_matches_admit_set() {
        assert_eq!(
            admit_set_label(EdgeClass::Dependency),
            "Calls, Contains, Implements, HasImpl, References, TypeOf, FieldOf"
        );
        assert_eq!(
            admit_set_label(EdgeClass::Structural),
            "Calls, Contains, Implements, HasImpl, References, TypeOf, FieldOf, DependsOn, Extends"
        );
    }

    // -- find_all_nodes_by_name tests --

    #[test]
    fn find_all_nodes_exact() {
        let mut graph = KnowledgeGraph::new();
        let node = make_node("store", "function", "a.rs");
        graph.add_node(node).unwrap();

        let matches = find_all_nodes_by_name(&graph, "store");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].tier, MatchTier::Exact);
        assert_eq!(matches[0].node.symbol_name, "store");
    }

    #[test]
    fn find_all_nodes_multiple_tiers() {
        let mut graph = KnowledgeGraph::new();
        let exact = make_node("store", "function", "a.rs");
        let suffix = make_node("MemoryStore::store", "function", "b.rs");
        let substring = make_node("my_store_helper", "function", "c.rs");

        graph.add_node(exact).unwrap();
        graph.add_node(suffix).unwrap();
        graph.add_node(substring).unwrap();

        let matches = find_all_nodes_by_name(&graph, "store");
        assert_eq!(matches.len(), 3);
        assert_eq!(matches[0].tier, MatchTier::Exact);
        assert_eq!(matches[0].node.symbol_name, "store");
        assert_eq!(matches[1].tier, MatchTier::Suffix);
        assert_eq!(matches[1].node.symbol_name, "MemoryStore::store");
        assert_eq!(matches[2].tier, MatchTier::Substring);
        assert_eq!(matches[2].node.symbol_name, "my_store_helper");
    }

    #[test]
    fn find_all_nodes_ambiguous() {
        let mut graph = KnowledgeGraph::new();
        let a = make_node("FooStore::store", "function", "a.rs");
        let b = make_node("BarStore::store", "function", "b.rs");
        let c = make_node("BazStore::store", "function", "c.rs");

        graph.add_node(a).unwrap();
        graph.add_node(b).unwrap();
        graph.add_node(c).unwrap();

        let matches = find_all_nodes_by_name(&graph, "store");
        // All three are suffix matches, sorted alphabetically
        assert_eq!(matches.len(), 3);
        assert!(matches.iter().all(|m| m.tier == MatchTier::Suffix));
        assert_eq!(matches[0].node.symbol_name, "BarStore::store");
        assert_eq!(matches[1].node.symbol_name, "BazStore::store");
        assert_eq!(matches[2].node.symbol_name, "FooStore::store");
    }

    #[test]
    fn find_all_nodes_empty() {
        let graph = KnowledgeGraph::new();
        let matches = find_all_nodes_by_name(&graph, "nonexistent");
        assert!(matches.is_empty());
    }

    // ======================================================================
    // reverse_bfs tests
    // ======================================================================

    fn make_node_with_reach(
        name: &str,
        kind: &str,
        file: &str,
        reach: ReachabilityClass,
    ) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.into(),
            kind: kind.into(),
            file_path: file.into(),
            content_hash: "abc123".into(),
            signature: String::new(),
            reachability_class: reach,
            line_start: None,
            line_end: None,
            has_body: None,
            visibility: String::new(),
            is_test_only: None,
            is_test_root: false,
            has_platform_cfg: false,
            rustc_flagged_dead: false,
            entry_retain: Default::default(),
            has_uncaptured_items: false,
            oracle_receipt: None,
        }
    }

    fn implements_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::Implements,
            confidence: 1.0,
            ..GraphEdge::default()
        }
    }

    #[test]
    fn reverse_bfs_trait_bridging() {
        // Verify BFS follows impl->trait->callers dispatch path.
        let mut graph = KnowledgeGraph::new();

        // Trait method: "MyTrait::do_thing"
        let trait_method = make_node("MyTrait::do_thing", "function", "trait.rs");
        // Impl method: "impl MyTrait for Foo::do_thing"
        let impl_method = make_node("impl MyTrait for Foo::do_thing", "function", "foo.rs");
        // Caller that calls via trait dispatch (calls the trait method)
        let caller = make_node("caller_fn", "function", "caller.rs");

        let trait_id = trait_method.memory_id;
        let impl_id = impl_method.memory_id;
        let caller_id = caller.memory_id;

        graph.add_node(trait_method).unwrap();
        graph.add_node(impl_method.clone()).unwrap();
        graph.add_node(caller).unwrap();

        // caller -> trait_method (calls via dyn dispatch)
        graph.add_edge(caller_id, trait_id, calls_edge()).unwrap();
        // impl -> trait (Implements edge)
        graph
            .add_edge(impl_id, trait_id, implements_edge())
            .unwrap();

        // BFS from impl method should find the caller through trait bridging
        let result = reverse_bfs(&graph, &impl_method, 3, None);

        let dep_names: Vec<&str> = result
            .dependents
            .iter()
            .map(|e| e.node.symbol_name.as_str())
            .collect();
        assert!(
            dep_names.contains(&"caller_fn"),
            "Trait bridging should find caller_fn via trait method. Got: {dep_names:?}"
        );
    }

    #[test]
    fn reverse_bfs_reachability_filter_wired() {
        // Filter::Wired should exclude dead nodes from results but still traverse through them.
        let mut graph = KnowledgeGraph::new();

        let root = make_node_with_reach("root_fn", "function", "a.rs", ReachabilityClass::Wired);
        let dead_middle =
            make_node_with_reach("dead_fn", "function", "b.rs", ReachabilityClass::Dead);
        let wired_top =
            make_node_with_reach("wired_fn", "function", "c.rs", ReachabilityClass::Wired);

        let root_id = root.memory_id;
        let dead_id = dead_middle.memory_id;
        let wired_id = wired_top.memory_id;

        graph.add_node(root.clone()).unwrap();
        graph.add_node(dead_middle).unwrap();
        graph.add_node(wired_top).unwrap();

        // wired_top -> dead_middle -> root
        graph.add_edge(dead_id, root_id, calls_edge()).unwrap();
        graph.add_edge(wired_id, dead_id, calls_edge()).unwrap();

        let result = reverse_bfs(&graph, &root, 3, Some(ReachabilityFilter::Wired));

        let dep_names: Vec<&str> = result
            .dependents
            .iter()
            .map(|e| e.node.symbol_name.as_str())
            .collect();

        // dead_fn should NOT be in results (filtered out)
        assert!(
            !dep_names.contains(&"dead_fn"),
            "Dead nodes should be excluded by Wired filter. Got: {dep_names:?}"
        );
        // wired_fn SHOULD be in results (traversed THROUGH dead_fn)
        assert!(
            dep_names.contains(&"wired_fn"),
            "Wired nodes past dead nodes should still be found. Got: {dep_names:?}"
        );
    }

    #[test]
    fn reverse_bfs_reachability_filter_all() {
        let mut graph = KnowledgeGraph::new();

        let root = make_node_with_reach("root", "function", "a.rs", ReachabilityClass::Wired);
        let dead = make_node_with_reach("dead", "function", "b.rs", ReachabilityClass::Dead);
        let wired = make_node_with_reach("wired", "function", "c.rs", ReachabilityClass::Wired);

        let root_id = root.memory_id;
        let dead_id = dead.memory_id;
        let wired_id = wired.memory_id;

        graph.add_node(root.clone()).unwrap();
        graph.add_node(dead).unwrap();
        graph.add_node(wired).unwrap();

        graph.add_edge(dead_id, root_id, calls_edge()).unwrap();
        graph.add_edge(wired_id, root_id, calls_edge()).unwrap();

        let result = reverse_bfs(&graph, &root, 3, Some(ReachabilityFilter::All));

        assert_eq!(
            result.dependents.len(),
            2,
            "All filter should include both dead and wired nodes"
        );
    }

    #[test]
    fn reverse_bfs_none_handling_not_treated_as_dead() {
        // Nodes with reachability_class = None should NOT be treated as Dead.
        // The map_or design: None passes all filters EXCEPT Dead
        // (if you explicitly ask for dead, None is not dead).
        let mut graph = KnowledgeGraph::new();

        let root = make_node_with_reach("root", "function", "a.rs", ReachabilityClass::Wired);
        let unclassified = make_node_with_reach(
            "unclassified",
            "function",
            "b.rs",
            ReachabilityClass::Unclassified,
        );

        let root_id = root.memory_id;
        let unc_id = unclassified.memory_id;

        graph.add_node(root.clone()).unwrap();
        graph.add_node(unclassified).unwrap();

        graph.add_edge(unc_id, root_id, calls_edge()).unwrap();

        // With Wired filter: None passes (unclassified passes all except Dead).
        let result_wired = reverse_bfs(&graph, &root, 3, Some(ReachabilityFilter::Wired));
        assert_eq!(
            result_wired.dependents.len(),
            1,
            "Unclassified (None) node should PASS Wired filter (not treated as Dead)"
        );

        // With Dead filter: None does NOT pass (asking for dead, None is not dead).
        let result_dead = reverse_bfs(&graph, &root, 3, Some(ReachabilityFilter::Dead));
        assert!(
            result_dead.dependents.is_empty(),
            "Unclassified (None) node should be excluded by Dead filter"
        );

        // With All filter: None passes through.
        let result_all = reverse_bfs(&graph, &root, 3, Some(ReachabilityFilter::All));
        assert_eq!(
            result_all.dependents.len(),
            1,
            "Unclassified (None) node should be included by All filter"
        );

        // With no filter (None parameter): everything passes.
        let result_none = reverse_bfs(&graph, &root, 3, None);
        assert_eq!(
            result_none.dependents.len(),
            1,
            "Unclassified (None) node should be included with no filter"
        );
    }

    #[test]
    fn reverse_bfs_isolation_detection() {
        // When all dependents are in the same file as root, isolation_note should be set.
        let mut graph = KnowledgeGraph::new();

        let root = make_node("root_fn", "function", "crates/foo/src/bar.rs");
        let same_file1 = make_node("helper1", "function", "crates/foo/src/bar.rs");
        let same_file2 = make_node("helper2", "function", "crates/foo/src/bar.rs");

        let root_id = root.memory_id;
        let sf1_id = same_file1.memory_id;
        let sf2_id = same_file2.memory_id;

        graph.add_node(root.clone()).unwrap();
        graph.add_node(same_file1).unwrap();
        graph.add_node(same_file2).unwrap();

        graph.add_edge(sf1_id, root_id, calls_edge()).unwrap();
        graph.add_edge(sf2_id, root_id, calls_edge()).unwrap();

        let result = reverse_bfs(&graph, &root, 3, None);

        assert!(
            result.isolation_note.is_some(),
            "Should detect isolation when all dependents in same file"
        );
        assert!(
            result.isolation_note.as_ref().unwrap().contains("bar.rs"),
            "Isolation note should mention the file name"
        );
    }

    #[test]
    fn reverse_bfs_no_isolation_when_cross_file() {
        let mut graph = KnowledgeGraph::new();

        let root = make_node("root_fn", "function", "a.rs");
        let other = make_node("caller", "function", "b.rs");

        let root_id = root.memory_id;
        let other_id = other.memory_id;

        graph.add_node(root.clone()).unwrap();
        graph.add_node(other).unwrap();

        graph.add_edge(other_id, root_id, calls_edge()).unwrap();

        let result = reverse_bfs(&graph, &root, 3, None);
        assert!(
            result.isolation_note.is_none(),
            "No isolation note when dependents span multiple files"
        );
    }

    #[test]
    fn reverse_bfs_depth_limit() {
        // BFS at depth 2 should not return nodes at depth 3.
        let mut graph = KnowledgeGraph::new();

        let root = make_node("root", "function", "a.rs");
        let depth1 = make_node("d1", "function", "b.rs");
        let depth2 = make_node("d2", "function", "c.rs");
        let depth3 = make_node("d3", "function", "d.rs");

        let root_id = root.memory_id;
        let d1_id = depth1.memory_id;
        let d2_id = depth2.memory_id;
        let d3_id = depth3.memory_id;

        graph.add_node(root.clone()).unwrap();
        graph.add_node(depth1).unwrap();
        graph.add_node(depth2).unwrap();
        graph.add_node(depth3).unwrap();

        graph.add_edge(d1_id, root_id, calls_edge()).unwrap();
        graph.add_edge(d2_id, d1_id, calls_edge()).unwrap();
        graph.add_edge(d3_id, d2_id, calls_edge()).unwrap();

        let result = reverse_bfs(&graph, &root, 2, None);

        let dep_names: Vec<&str> = result
            .dependents
            .iter()
            .map(|e| e.node.symbol_name.as_str())
            .collect();

        assert!(dep_names.contains(&"d1"), "depth 1 should be included");
        assert!(dep_names.contains(&"d2"), "depth 2 should be included");
        assert!(
            !dep_names.contains(&"d3"),
            "depth 3 should NOT be included with max_depth=2. Got: {dep_names:?}"
        );
    }

    #[test]
    fn reverse_bfs_no_duplicates() {
        // Same node reachable via two different paths should appear only once.
        let mut graph = KnowledgeGraph::new();

        let root = make_node("root", "function", "a.rs");
        let bridge_a = make_node("bridge_a", "function", "b.rs");
        let bridge_b = make_node("bridge_b", "function", "c.rs");
        let common = make_node("common", "function", "d.rs");

        let root_id = root.memory_id;
        let a_id = bridge_a.memory_id;
        let b_id = bridge_b.memory_id;
        let common_id = common.memory_id;

        graph.add_node(root.clone()).unwrap();
        graph.add_node(bridge_a).unwrap();
        graph.add_node(bridge_b).unwrap();
        graph.add_node(common).unwrap();

        // Two paths: common -> bridge_a -> root, common -> bridge_b -> root
        graph.add_edge(a_id, root_id, calls_edge()).unwrap();
        graph.add_edge(b_id, root_id, calls_edge()).unwrap();
        graph.add_edge(common_id, a_id, calls_edge()).unwrap();
        graph.add_edge(common_id, b_id, calls_edge()).unwrap();

        let result = reverse_bfs(&graph, &root, 3, None);

        let common_count = result
            .dependents
            .iter()
            .filter(|e| e.node.symbol_name == "common")
            .count();
        assert_eq!(
            common_count, 1,
            "common should appear exactly once despite two paths"
        );
    }

    // ======================================================================
    // classify_dead_action tests
    // ======================================================================

    #[test]
    fn classify_dead_action_safe_delete() {
        let mut graph = KnowledgeGraph::new();
        // WU-0015 Leg-3b: SafeDelete now requires the full 4-way conjunction —
        // class==Dead, rustc_flagged_dead, delete-eligible visibility, AND a
        // cfg-clean `crates/<name>` crate.
        let mut dead = make_node_with_reach(
            "dead_fn",
            "function",
            "crates/x/src/a.rs",
            ReachabilityClass::Dead,
        );
        dead.visibility = "private".into();
        dead.rustc_flagged_dead = true;
        graph.add_node(dead.clone()).unwrap();

        let cfg_crates = cfg_touching_crates(&graph);
        let action = classify_dead_action(&graph, &dead, &cfg_crates);
        assert_eq!(action, DeadAction::SafeDelete);
    }

    #[test]
    fn classify_dead_action_needs_review_with_alive_dependent() {
        let mut graph = KnowledgeGraph::new();
        let dead = make_node_with_reach("dead_fn", "function", "a.rs", ReachabilityClass::Dead);
        let alive = make_node_with_reach("alive_fn", "function", "b.rs", ReachabilityClass::Wired);

        let dead_id = dead.memory_id;
        let alive_id = alive.memory_id;

        graph.add_node(dead.clone()).unwrap();
        graph.add_node(alive).unwrap();
        graph.add_edge(alive_id, dead_id, calls_edge()).unwrap();

        let action = classify_dead_action(&graph, &dead, &HashSet::new());
        assert_eq!(action, DeadAction::NeedsReview);
    }

    #[test]
    fn classify_dead_action_with_test_only_dependent_returns_needs_review() {
        // TestOnly-classified dependents are considered "alive" by classify_dead_action
        // (they are not Dead/Orphan/None), so they trigger NeedsReview.
        let mut graph = KnowledgeGraph::new();
        let dead = make_node_with_reach("dead_fn", "function", "a.rs", ReachabilityClass::Dead);
        let test = make_node_with_reach(
            "test_fn",
            "function",
            "tests/b.rs",
            ReachabilityClass::TestOnly,
        );

        let dead_id = dead.memory_id;
        let test_id = test.memory_id;

        graph.add_node(dead.clone()).unwrap();
        graph.add_node(test).unwrap();
        graph.add_edge(test_id, dead_id, calls_edge()).unwrap();

        let action = classify_dead_action(&graph, &dead, &HashSet::new());
        assert_eq!(action, DeadAction::NeedsReview);
    }

    // ======================================================================
    // find_test_callers tests
    // ======================================================================

    #[test]
    fn find_test_callers_basic() {
        let mut graph = KnowledgeGraph::new();

        let target = make_node("target_fn", "function", "src/lib.rs");
        let test = make_node("test_target", "function", "tests/test_lib.rs");

        let target_id = target.memory_id;
        let test_id = test.memory_id;

        graph.add_node(target).unwrap();
        graph.add_node(test).unwrap();

        // test -> target
        graph.add_edge(test_id, target_id, calls_edge()).unwrap();

        let results = find_test_callers(&graph, target_id);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.symbol_name, "test_target");
    }

    // WU-0003 finish-collapse behavior-preservation falsifier: a TRANSITIVE
    // test-caller chain through a NON-test production intermediate. The
    // intermediate (`mid_fn`) is not collected (not a test) but MUST be expanded
    // so the test two hops up is reached, and the returned call chain must be the
    // full path from target through the intermediate to the test — exactly the
    // pre-migration `path` threading. Confirms the migrated walk does not stop at
    // non-test intermediates.
    #[test]
    fn find_test_callers_transitive_chain_with_path() {
        let mut graph = KnowledgeGraph::new();

        // test_outer -> mid_fn -> target_fn   (reverse: target <- mid <- test)
        let target = make_node("target_fn", "function", "src/lib.rs");
        let mid = make_node("mid_fn", "function", "src/lib.rs");
        let test = make_node("tests::test_outer", "function", "src/lib.rs");

        let target_id = target.memory_id;
        let mid_id = mid.memory_id;
        let test_id = test.memory_id;

        graph.add_node(target).unwrap();
        graph.add_node(mid).unwrap();
        graph.add_node(test).unwrap();

        graph.add_edge(mid_id, target_id, calls_edge()).unwrap();
        graph.add_edge(test_id, mid_id, calls_edge()).unwrap();

        let results = find_test_callers(&graph, target_id);
        // Only the test function is collected — the non-test intermediate is not.
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0.symbol_name, "tests::test_outer");
        // The chain is target -> mid -> test (built parent-by-parent).
        assert_eq!(
            results[0].1,
            vec![
                "target_fn".to_string(),
                "mid_fn".to_string(),
                "tests::test_outer".to_string(),
            ]
        );
    }

    // ======================================================================
    // DeadAction label/description tests
    // ======================================================================

    #[test]
    fn dead_action_label_and_description() {
        assert_eq!(DeadAction::SafeDelete.label(), "DEAD");
        assert_eq!(DeadAction::NeedsReview.label(), "NEEDS_REVIEW");
        assert_eq!(DeadAction::TestOnly.label(), "TEST_ONLY");
        // ADR-0034 L4 (Decision 2): the verb-level suppression variant.
        assert_eq!(DeadAction::Unknown.label(), "UNKNOWN");
        // Catch-all for a finding whose delete authority is withheld.
        assert_eq!(DeadAction::SuspectedDelete.label(), "SUSPECTED_DELETE");

        // WU-0016 / ADR-0039 demote + RV-003: the SafeDelete description drops the
        // over-strong "no production or test impact" delete-authority claim AND the
        // premature "confirmed"/"compiler-corroborated" certainty (Class-B open).
        assert_eq!(
            DeadAction::SafeDelete.description(),
            "private and unreachable by static analysis — may still be wired via an unseen edge; verify before removing"
        );
        assert_eq!(
            DeadAction::NeedsReview.description(),
            "has alive dependents"
        );
        assert_eq!(
            DeadAction::TestOnly.description(),
            "consider promoting to production or removing test"
        );
        assert_eq!(
            DeadAction::Unknown.description(),
            "reachability unavailable — call-graph coverage insufficient; recommendation withheld"
        );
    }

    /// WU-0016 / ADR-0039 RC-B5 falsifier: `dead_tier_label` materializes the
    /// demoted tiered vocabulary (`DEAD` / `SUSPECTED` / `LIVE_ASSUMED`; `DEAD`
    /// renders without a "confirmed" suffix until Class-B lands — RV-003) as a
    /// pure projection over `is_dead` + [`DeadAction`] — with NO delete verb.
    #[test]
    fn dead_tier_label_projects_tiers() {
        // Not dead → the live-assumed tier regardless of the action carried.
        assert_eq!(
            dead_tier_label(false, &DeadAction::SafeDelete),
            "LIVE_ASSUMED"
        );
        // The 4-way SafeDelete conjunction → the "DEAD" tier (never "SAFE_DELETE"
        // — the delete-authority label is stripped; the "confirmed" suffix is
        // withheld until Class-B lands, RV-003).
        assert_eq!(dead_tier_label(true, &DeadAction::SafeDelete), "DEAD");
        assert_eq!(
            dead_tier_label(true, &DeadAction::SuspectedDelete),
            "SUSPECTED"
        );
        assert_eq!(
            dead_tier_label(true, &DeadAction::NeedsReview),
            "NEEDS_REVIEW"
        );
        assert_eq!(dead_tier_label(true, &DeadAction::TestOnly), "TEST_ONLY");
        assert_eq!(dead_tier_label(true, &DeadAction::Unknown), "UNKNOWN");
        // No tier is a delete verb.
        for action in [
            DeadAction::SafeDelete,
            DeadAction::SuspectedDelete,
            DeadAction::NeedsReview,
            DeadAction::TestOnly,
            DeadAction::Unknown,
        ] {
            let label = dead_tier_label(true, &action);
            assert!(
                !label.to_ascii_lowercase().contains("delete"),
                "tier label {label:?} must not carry a delete verb"
            );
        }
    }

    /// WU-0016 / ADR-0039 RC-B4 falsifier: the shared dead-field warning states
    /// the graph finding and drops the `Consider removing.` delete verb.
    #[test]
    fn dead_field_warning_has_no_delete_verb() {
        let w = dead_field_warning("unused_flag");
        assert!(w.starts_with("DEAD FIELD: unused_flag"));
        assert!(!w.contains("Consider removing"));
        assert!(w.contains("verify before removing"));
    }

    /// WU-0016 / ADR-0039 RC-B3 falsifier: the shared reachability warning
    /// describes the DEAD finding without claiming delete authority.
    #[test]
    fn reachability_warning_dead_is_advisory() {
        let dead = reachability_warning(ReachabilityClass::Dead).unwrap();
        assert!(dead.starts_with("DEAD:"));
        assert!(dead.contains("verify before removing"));
        assert!(reachability_warning(ReachabilityClass::Orphan).is_some());
        assert!(reachability_warning(ReachabilityClass::TestOnly).is_some());
        assert!(reachability_warning(ReachabilityClass::Wired).is_none());
    }

    /// WU-0016 / RV-003 falsifier: the WIRED `SafeDelete` description makes NO
    /// premature "confirmed" / "compiler-corroborated" certainty claim while
    /// Class-B (OQ-ORACLE-LINT-FAMILY-OVERBROAD) is open — the `rustc_flagged_dead`
    /// conjunct is spoofable by `unused_*` until B narrows it. Flips to REQUIRE the
    /// promoted vocabulary when B lands (an RV-003 sweep-set member).
    #[test]
    fn dead_description_makes_no_premature_confirmed_claim() {
        let d = DeadAction::SafeDelete.description();
        let lc = d.to_ascii_lowercase();
        assert!(
            !lc.contains("confirmed"),
            "SafeDelete.description() must not claim \"confirmed\" pre-Class-B (RV-003), got: {d:?}"
        );
        assert!(
            !lc.contains("corroborat"),
            "SafeDelete.description() must not claim compiler-\"corroborated\" pre-Class-B (RV-003), got: {d:?}"
        );
        assert!(d.contains("verify before removing"));
    }

    // ======================================================================
    // reverse_bfs test file detection tests
    // ======================================================================

    #[test]
    fn reverse_bfs_detects_test_files() {
        let mut graph = KnowledgeGraph::new();

        let root = make_node("root_fn", "function", "src/lib.rs");
        let test = make_node("test_fn", "function", "tests/test_lib.rs");
        let prod = make_node("prod_fn", "function", "src/prod.rs");

        let root_id = root.memory_id;
        let test_id = test.memory_id;
        let prod_id = prod.memory_id;

        graph.add_node(root.clone()).unwrap();
        graph.add_node(test).unwrap();
        graph.add_node(prod).unwrap();

        graph.add_edge(test_id, root_id, calls_edge()).unwrap();
        graph.add_edge(prod_id, root_id, calls_edge()).unwrap();

        let result = reverse_bfs(&graph, &root, 3, None);

        assert_eq!(result.test_files.len(), 1, "Should detect 1 test file");
        assert!(
            result.test_files.contains_key("tests/test_lib.rs"),
            "Test file should be in test_files map"
        );
        assert_eq!(
            result.file_counts.len(),
            2,
            "Should count both prod and test files"
        );
    }

    // ====================================================================
    // BUG-1: test output truncation — verify many test callers are returned
    // ====================================================================

    #[test]
    fn find_test_callers_returns_all_results_for_capping_by_handler() {
        // Create a graph with a target called by 60 test functions.
        // find_test_callers returns all of them; the handler layer caps at 50.
        let mut graph = KnowledgeGraph::new();

        let target = make_node("high_fan_in_fn", "function", "src/lib.rs");
        let target_id = target.memory_id;
        graph.add_node(target).unwrap();

        for i in 0..60 {
            let test = make_node(&format!("tests::test_{i}"), "function", "tests/test_lib.rs");
            let test_id = test.memory_id;
            graph.add_node(test).unwrap();
            graph.add_edge(test_id, target_id, calls_edge()).unwrap();
        }

        let results = find_test_callers(&graph, target_id);
        // All 60 should be returned — capping is the handler's job.
        assert_eq!(
            results.len(),
            60,
            "find_test_callers should return all tests (handler caps at 50)"
        );
    }

    // ====================================================================
    // BUG-2: find_test_callers catches inline #[cfg(test)] mod tests
    // ====================================================================

    #[test]
    fn find_test_callers_detects_inline_test_modules() {
        // A function in src/lib.rs with an inline test in the same file
        // (mod tests { fn test_foo() }). is_test_file("src/lib.rs") = false,
        // but find_test_callers should detect it via symbol name pattern.
        let mut graph = KnowledgeGraph::new();

        let target = make_node("hybrid_search", "function", "src/lance_store.rs");
        let inline_test = make_node(
            "tests::test_hybrid_search",
            "function",
            "src/lance_store.rs",
        );
        let target_id = target.memory_id;
        let test_id = inline_test.memory_id;

        graph.add_node(target).unwrap();
        graph.add_node(inline_test).unwrap();
        graph.add_edge(test_id, target_id, calls_edge()).unwrap();

        let results = find_test_callers(&graph, target_id);
        assert!(
            !results.is_empty(),
            "find_test_callers should detect inline test module functions"
        );
        assert_eq!(results[0].0.symbol_name, "tests::test_hybrid_search");
    }

    // ====================================================================
    // BUG-3: reverse_bfs with ReachabilityFilter::Wired excludes dead nodes
    // ====================================================================

    #[test]
    fn reverse_bfs_wired_filter_excludes_dead_by_default() {
        let mut graph = KnowledgeGraph::new();

        let root = make_node_with_reach("root", "function", "a.rs", ReachabilityClass::Wired);
        let wired_dep =
            make_node_with_reach("wired_dep", "function", "b.rs", ReachabilityClass::Wired);
        let dead_dep =
            make_node_with_reach("dead_dep", "function", "c.rs", ReachabilityClass::Dead);

        let root_id = root.memory_id;
        let wired_id = wired_dep.memory_id;
        let dead_id = dead_dep.memory_id;

        graph.add_node(root.clone()).unwrap();
        graph.add_node(wired_dep).unwrap();
        graph.add_node(dead_dep).unwrap();

        graph.add_edge(wired_id, root_id, calls_edge()).unwrap();
        graph.add_edge(dead_id, root_id, calls_edge()).unwrap();

        // Default filter (Wired) should exclude dead node.
        let result = reverse_bfs(&graph, &root, 3, Some(ReachabilityFilter::Wired));
        let names: Vec<&str> = result
            .dependents
            .iter()
            .map(|e| e.node.symbol_name.as_str())
            .collect();
        assert!(
            names.contains(&"wired_dep"),
            "Wired node should be in results"
        );
        assert!(
            !names.contains(&"dead_dep"),
            "Dead node should NOT be in results with Wired filter"
        );

        // All filter should include both.
        let result_all = reverse_bfs(&graph, &root, 3, Some(ReachabilityFilter::All));
        assert_eq!(
            result_all.dependents.len(),
            2,
            "All filter should include wired and dead"
        );
    }

    // ====================================================================
    // BUG-4: isolation_note is populated when all dependents are in same file
    // ====================================================================

    #[test]
    fn reverse_bfs_isolation_note_same_file() {
        let mut graph = KnowledgeGraph::new();

        let root = make_node("root_fn", "function", "src/my_module.rs");
        let dep1 = make_node("dep1_fn", "function", "src/my_module.rs");
        let dep2 = make_node("dep2_fn", "function", "src/my_module.rs");

        let root_id = root.memory_id;
        let dep1_id = dep1.memory_id;
        let dep2_id = dep2.memory_id;

        graph.add_node(root.clone()).unwrap();
        graph.add_node(dep1).unwrap();
        graph.add_node(dep2).unwrap();

        graph.add_edge(dep1_id, root_id, calls_edge()).unwrap();
        graph.add_edge(dep2_id, root_id, calls_edge()).unwrap();

        let result = reverse_bfs(&graph, &root, 3, None);
        assert!(
            result.isolation_note.is_some(),
            "Should produce isolation warning when all dependents are in same file"
        );
        assert!(
            result
                .isolation_note
                .as_ref()
                .unwrap()
                .contains("my_module.rs"),
            "Isolation note should mention the file name"
        );
    }

    // ====================================================================
    // find_all_nodes_by_name detects ambiguous suffix matches
    // ====================================================================

    #[test]
    fn find_all_nodes_by_name_detects_ambiguous_suffix_matches() {
        // Two different symbols with the same suffix: "a::tests" and "b::tests".
        // Querying "tests" should return multiple suffix matches.
        let mut graph = KnowledgeGraph::new();

        let node_a = make_node("a::tests", "module", "src/a.rs");
        let node_b = make_node("b::tests", "module", "src/b.rs");

        graph.add_node(node_a).unwrap();
        graph.add_node(node_b).unwrap();

        let matches = find_all_nodes_by_name(&graph, "tests");
        let best_tier = matches[0].tier;
        let same_tier_count = matches.iter().filter(|m| m.tier == best_tier).count();

        assert!(
            same_tier_count > 1,
            "Should detect ambiguity: multiple symbols match 'tests' at the same tier"
        );
    }

    // -- collect_type_children tests --

    fn field_of_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::FieldOf,
            confidence: 1.0,
            ..GraphEdge::default()
        }
    }

    #[test]
    fn collect_type_children_struct_returns_methods_from_impl_blocks() {
        // Shape: struct MyStruct
        //        impl MyStruct { fn foo() {} fn bar() {} }
        //        impl Debug for MyStruct { fn fmt() {} }
        let mut graph = KnowledgeGraph::new();
        let struct_node = make_node("MyStruct", "struct", "a.rs");
        let field_node = make_node("MyStruct::field1", "field", "a.rs");
        let impl1 = make_node("impl MyStruct", "impl", "a.rs");
        let impl1_foo = make_node("impl MyStruct::foo", "method", "a.rs");
        let impl1_bar = make_node("impl MyStruct::bar", "method", "a.rs");
        let impl2 = make_node("impl Debug for MyStruct", "impl", "a.rs");
        let impl2_fmt = make_node("impl Debug for MyStruct::fmt", "method", "a.rs");

        let struct_id = struct_node.memory_id;
        let field_id = field_node.memory_id;
        let impl1_id = impl1.memory_id;
        let foo_id = impl1_foo.memory_id;
        let bar_id = impl1_bar.memory_id;
        let impl2_id = impl2.memory_id;
        let fmt_id = impl2_fmt.memory_id;

        for n in [
            struct_node,
            field_node,
            impl1,
            impl1_foo,
            impl1_bar,
            impl2,
            impl2_fmt,
        ] {
            graph.add_node(n).unwrap();
        }

        // struct contains field + two impl blocks
        graph
            .add_edge(struct_id, field_id, contains_edge())
            .unwrap();
        graph
            .add_edge(struct_id, impl1_id, contains_edge())
            .unwrap();
        graph
            .add_edge(struct_id, impl2_id, contains_edge())
            .unwrap();
        // impls contain their methods
        graph.add_edge(impl1_id, foo_id, contains_edge()).unwrap();
        graph.add_edge(impl1_id, bar_id, contains_edge()).unwrap();
        graph.add_edge(impl2_id, fmt_id, contains_edge()).unwrap();

        let children = collect_type_children(&graph, &struct_id);

        assert_eq!(children.fields.len(), 1, "struct should have 1 field");
        assert_eq!(
            children.methods.len(),
            3,
            "struct methods should flatten from both impl blocks: got {:?}",
            children
                .methods
                .iter()
                .map(|m| m.symbol_name.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(children.impl_blocks.len(), 2);
        assert!(children.variants.is_empty());
    }

    #[test]
    fn collect_type_children_trait_returns_direct_methods() {
        let mut graph = KnowledgeGraph::new();
        let trait_node = make_node("MyTrait", "trait", "a.rs");
        let method1 = make_node("MyTrait::do_thing", "method", "a.rs");
        let method2 = make_node("MyTrait::helper", "function", "a.rs");

        let trait_id = trait_node.memory_id;
        let m1_id = method1.memory_id;
        let m2_id = method2.memory_id;

        for n in [trait_node, method1, method2] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(trait_id, m1_id, contains_edge()).unwrap();
        graph.add_edge(trait_id, m2_id, contains_edge()).unwrap();

        let children = collect_type_children(&graph, &trait_id);
        assert_eq!(
            children.methods.len(),
            2,
            "trait methods come from direct Contains edges"
        );
        assert!(children.impl_blocks.is_empty());
        assert!(children.variants.is_empty());
        assert!(children.fields.is_empty());
    }

    #[test]
    fn collect_type_children_class_uses_language_neutral_child_roles() {
        let mut graph = KnowledgeGraph::new();
        let class_node = make_node("Service", "class", "service.ts");
        let property = make_node("Service::client", "property", "service.ts");
        let constructor = make_node("Service::constructor", "constructor", "service.ts");

        let class_id = class_node.memory_id;
        let property_id = property.memory_id;
        let constructor_id = constructor.memory_id;

        for node in [class_node, property, constructor] {
            graph.add_node(node).unwrap();
        }
        graph
            .add_edge(class_id, property_id, contains_edge())
            .unwrap();
        graph
            .add_edge(class_id, constructor_id, contains_edge())
            .unwrap();

        let children = collect_type_children(&graph, &class_id);
        assert_eq!(children.fields.len(), 1, "property is a data member");
        assert_eq!(children.methods.len(), 1, "constructor is a callable child");
        assert_eq!(children.methods[0].kind, "constructor");
    }

    #[test]
    fn collect_type_children_enum_returns_variants() {
        let mut graph = KnowledgeGraph::new();
        let enum_node = make_node("Color", "enum", "a.rs");
        let v1 = make_node("Color::Red", "enum_variant", "a.rs");
        let v2 = make_node("Color::Blue", "variant", "a.rs");
        let enum_id = enum_node.memory_id;
        let v1_id = v1.memory_id;
        let v2_id = v2.memory_id;

        for n in [enum_node, v1, v2] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(enum_id, v1_id, contains_edge()).unwrap();
        graph.add_edge(enum_id, v2_id, contains_edge()).unwrap();

        let children = collect_type_children(&graph, &enum_id);
        assert_eq!(
            children.variants.len(),
            2,
            "enum variants should be collected (both 'variant' and 'enum_variant' kinds)"
        );
        assert!(children.fields.is_empty());
        assert!(children.methods.is_empty());
    }

    #[test]
    fn collect_type_children_struct_collects_field_type_refs() {
        // Struct has two Contains fields and a FieldOf edge to a referenced type.
        let mut graph = KnowledgeGraph::new();
        let s = make_node("Holder", "struct", "a.rs");
        let f1 = make_node("Holder::inner", "field", "a.rs");
        let other_ty = make_node("Inner", "struct", "b.rs");
        let s_id = s.memory_id;
        let f1_id = f1.memory_id;
        let other_id = other_ty.memory_id;

        for n in [s, f1, other_ty] {
            graph.add_node(n).unwrap();
        }
        graph.add_edge(s_id, f1_id, contains_edge()).unwrap();
        graph.add_edge(s_id, other_id, field_of_edge()).unwrap();

        let children = collect_type_children(&graph, &s_id);
        assert_eq!(children.fields.len(), 1);
        assert_eq!(children.field_type_refs.len(), 1);
        assert_eq!(children.field_type_refs[0].symbol_name, "Inner");
    }

    #[test]
    fn collect_type_children_missing_root_returns_empty() {
        let graph = KnowledgeGraph::new();
        let children = collect_type_children(&graph, &Uuid::new_v4());
        assert!(children.fields.is_empty());
        assert!(children.methods.is_empty());
        assert!(children.variants.is_empty());
        assert!(children.impl_blocks.is_empty());
        assert!(children.field_type_refs.is_empty());
    }

    // ====================================================================
    // ADR-0027 / WU-0002 EP1 — resolve_unique falsifiers (F1, F4–F7)
    // ====================================================================

    /// Set of file_path values across an Ambiguous candidate list (order-free).
    fn file_set(matches: &[Match]) -> std::collections::HashSet<String> {
        matches.iter().map(|m| m.file_path.clone()).collect()
    }

    /// F1: a bare-name resolve over two same-`symbol_name` homonyms in different
    /// files MUST return `Ambiguous` carrying BOTH candidates — silent
    /// first-match is no longer expressible at the EP1 verdict surface.
    #[test]
    fn f1_bare_name_homonyms_resolve_ambiguous() {
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(make_node("store", "function", "a.rs"))
            .unwrap();
        graph
            .add_node(make_node("store", "function", "b.rs"))
            .unwrap();

        let result = resolve_unique(&graph, "store", None);

        assert!(
            matches!(result, Resolution::Ambiguous(_)),
            "two homonyms must be Ambiguous, not a silent Unique"
        );
        let Resolution::Ambiguous(cands) = result.clone() else {
            unreachable!()
        };
        assert_eq!(cands.len(), 2);
        assert_eq!(
            file_set(&cands),
            ["a.rs".to_string(), "b.rs".to_string()]
                .into_iter()
                .collect()
        );
        assert!(cands.iter().all(|m| m.symbol_name == "store"));
        assert!(!matches!(result, Resolution::Unique(_)));

        // F7 linkage: the ONLY id-extraction path returns Err(Ambiguity) with
        // the full candidate list.
        let err = result.unique_or_report().unwrap_err();
        assert_eq!(err.candidates.len(), 2);
    }

    /// F4: a locality matching exactly one of several homonyms MUST single it out
    /// to `Unique` (decision-ladder step b), not `Ambiguous`.
    #[test]
    fn f4_locality_singles_out_unique() {
        let mut graph = KnowledgeGraph::new();
        let a = make_node("store", "function", "a.rs");
        let id_a = a.memory_id;
        graph.add_node(a).unwrap();
        graph
            .add_node(make_node("store", "function", "b.rs"))
            .unwrap();

        let result = resolve_unique(&graph, "store", Some(FileContext::from("a.rs")));
        assert_eq!(result, Resolution::Unique(SymbolId(id_a)));

        // Control: no locality on the SAME graph stays Ambiguous(2) — proving the
        // Unique came from locality, not an index change.
        let none = resolve_unique(&graph, "store", None);
        assert_matches!(none, Resolution::Ambiguous(c) if c.len() == 2);

        // Edge: a FileContext matching NEITHER homonym must NOT manufacture a
        // Unique — it stays Ambiguous.
        let neither = resolve_unique(&graph, "store", Some(FileContext::from("z.rs")));
        assert_matches!(neither, Resolution::Ambiguous(c) if c.len() == 2);
    }

    /// F5: a `::`-qualified query MUST resolve `Unique` while its bare form is
    /// Ambiguous — the qualified-retry escape hatch (ADR-0027 ladder step c).
    ///
    /// NON-VACUITY NOTE (discovery): with `find_all_nodes_by_name` as the
    /// candidate source, the *mechanism* is the highest-tier narrowing in step
    /// (a), not a distinct carve-out branch — the qualified query lands in the
    /// Exact tier as a singleton (`MemoryStore::store` ≠ `OtherStore::store`),
    /// whereas the bare `store` lands in the Suffix tier with two candidates.
    /// Step (c) is behaviorally subsumed by step (a) under this source (see the
    /// inline note in `resolve_unique`). The load-bearing, controlled-revertable
    /// behavior is exact-tier selection: F1's first-match revert makes the bare
    /// case wrong; the F6 substring-tier revert and this exact/suffix split are
    /// what keep a qualified query from collapsing to the wrong homonym.
    #[test]
    fn f5_qualified_resolves_while_bare_is_ambiguous() {
        let mut graph = KnowledgeGraph::new();
        let target = make_node("MemoryStore::store", "function", "src/store.rs");
        let target_id = target.memory_id;
        graph.add_node(target).unwrap();
        graph
            .add_node(make_node("OtherStore::store", "function", "src/other.rs"))
            .unwrap();

        // Qualified query → exact-tier singleton → Unique.
        let result = resolve_unique(&graph, "MemoryStore::store", None);
        assert_eq!(result, Resolution::Unique(SymbolId(target_id)));

        // Discriminator: the bare name on the SAME graph is Ambiguous(2) — proves
        // the Unique came from the qualified form narrowing the candidate set.
        let bare = resolve_unique(&graph, "store", None);
        assert_matches!(bare, Resolution::Ambiguous(c) if c.len() == 2);

        // Negative guard: a ::-qualified query that is now a TWO-way exact
        // homonym (add a second `MemoryStore::store` in another file) stays
        // Ambiguous — uniqueness, not mere qualification, is what resolves.
        graph
            .add_node(make_node("MemoryStore::store", "function", "src/dup.rs"))
            .unwrap();
        let dup = resolve_unique(&graph, "MemoryStore::store", None);
        assert_matches!(dup, Resolution::Ambiguous(c) if c.len() == 2);

        // Suffix-tier qualified path: query `Inner::leaf` has no exact node but is
        // a `::`-suffix of exactly one symbol → resolves Unique through the
        // Suffix tier (exercises the step-(c) gate on a non-exact query).
        let mut g2 = KnowledgeGraph::new();
        let leaf = make_node("Outer::Inner::leaf", "function", "src/leaf.rs");
        let leaf_id = leaf.memory_id;
        g2.add_node(leaf).unwrap();
        assert_eq!(
            resolve_unique(&g2, "Inner::leaf", None),
            Resolution::Unique(SymbolId(leaf_id))
        );
    }

    /// F6: a query that only SUBSTRING-matches MUST yield `NotFound` — EP1
    /// excludes the Substring tier from resolution; never a silent substring pick.
    #[test]
    fn f6_substring_is_not_resolution() {
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(make_node("my_store_helper", "function", "a.rs"))
            .unwrap();

        assert_eq!(resolve_unique(&graph, "store", None), Resolution::NotFound);

        // Positive control: the node IS substring-reachable for EP3/search.
        let all = find_all_nodes_by_name(&graph, "store");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].tier, MatchTier::Substring);

        // Mixed case: an Exact match present → the substring-only node is NOT a
        // candidate; only the higher non-empty tier (Exact) is taken.
        let exact = make_node("store", "function", "b.rs");
        let exact_id = exact.memory_id;
        graph.add_node(exact).unwrap();
        assert_eq!(
            resolve_unique(&graph, "store", None),
            Resolution::Unique(SymbolId(exact_id))
        );
    }

    /// F7 (behavioral half): `.unique_or_report()` is the ONLY id-extraction
    /// path — `Ambiguous` → `Err(Ambiguity)` with all candidates; `Unique` →
    /// `Ok(SymbolId)` round-tripping to the right node via `graph.node`.
    #[test]
    fn f7_unique_or_report_extraction_discipline() {
        let mut graph = KnowledgeGraph::new();
        let a = make_node("store", "function", "a.rs");
        let id_a = a.memory_id;
        graph.add_node(a).unwrap();
        graph
            .add_node(make_node("store", "function", "b.rs"))
            .unwrap();

        // Ambiguous → Err carrying both candidates.
        let amb = resolve_unique(&graph, "store", None);
        let err = amb.unique_or_report().unwrap_err();
        assert_eq!(err.candidates.len(), 2);

        // Unique (via locality) → Ok, round-trips to the a.rs node.
        let uniq = resolve_unique(&graph, "store", Some(FileContext::from("a.rs")));
        let sid = uniq.unique_or_report().expect("unique resolves to Ok");
        assert_eq!(sid, SymbolId(id_a));
        assert_eq!(graph.node(&sid.uuid()).unwrap().memory_id, id_a);

        // NotFound → Err with empty candidate list (no panic, no id).
        assert!(
            resolve_unique(&graph, "totally_absent", None)
                .unique_or_report()
                .unwrap_err()
                .candidates
                .is_empty()
        );
    }

    /// F3 (resolve_unique linkage): with two homonyms indexed, removing one
    /// leaves the survivor as the UNIQUE resolve_unique answer.
    #[test]
    fn f3_remove_survivor_resolves_unique() {
        let mut graph = KnowledgeGraph::new();
        let a = make_node("store", "function", "a.rs");
        let b = make_node("store", "function", "b.rs");
        let id_a = a.memory_id;
        let id_b = b.memory_id;
        graph.add_node(a).unwrap();
        graph.add_node(b).unwrap();

        // Both present → Ambiguous.
        assert_matches!(
            resolve_unique(&graph, "store", None),
            Resolution::Ambiguous(_)
        );

        graph.remove_node(&id_a);
        assert_eq!(
            resolve_unique(&graph, "store", None),
            Resolution::Unique(SymbolId(id_b))
        );
    }

    // ====================================================================
    // ADR-0027 / WU-0002 EP3 — search() falsifiers (set-valued renderer)
    // ====================================================================

    /// EP3: `search` returns ALL tiers INCLUDING a Substring-only match — the
    /// set-valued renderer KEEPS the Substring tier that EP1/EP2 drop. (No
    /// `.first()`/`resolve_first` helper exists — non-existence is enforced by
    /// the API surface + the ADR-0027 review gate.)
    #[test]
    fn ep3_search_renders_all_tiers_incl_substring() {
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(make_node("store", "function", "a.rs"))
            .unwrap(); // Exact
        graph
            .add_node(make_node("Mod::store", "function", "b.rs"))
            .unwrap(); // Suffix
        graph
            .add_node(make_node("my_store_helper", "function", "c.rs"))
            .unwrap(); // Substring

        let results = search(&graph, "store");
        assert_eq!(results.len(), 3, "all three tiers must be present");
        let names: Vec<&str> = results.iter().map(|m| m.symbol_name.as_str()).collect();
        assert!(
            names.contains(&"my_store_helper"),
            "the substring-only match must be PRESENT (search keeps Substring): {names:?}"
        );
        // Match fields populated from the nodes.
        let exact = results
            .iter()
            .find(|m| m.symbol_name == "store")
            .expect("exact match present");
        assert_eq!(exact.file_path, "a.rs");
        assert_eq!(exact.kind, "function");

        // Discriminator: resolve_unique (EP1) drops the substring tier — proving
        // search != resolve_unique. Here "store" has an Exact match so EP1 is
        // Unique(store); the substring node is invisible to EP1.
        assert_matches!(resolve_unique(&graph, "store", None), Resolution::Unique(_));
    }

    /// EP3: pin the REAL output-order/cap change — Exact > Suffix > Substring,
    /// alphabetical within tier, capped at `take(10)`. Distinct from the old
    /// run_signature exact-first + insertion-order behavior. The new order is
    /// asserted EXPLICITLY (the "do-NOT-claim-ordering-preserved" discipline).
    #[test]
    fn ep3_search_order_and_cap_pinned() {
        let mut graph = KnowledgeGraph::new();
        // 1 Exact "x".
        graph
            .add_node(make_node("x", "function", "exact.rs"))
            .unwrap();
        // 3 Suffix nodes added in NON-alpha order: B::x, A::x, C::x.
        graph
            .add_node(make_node("B::x", "function", "b.rs"))
            .unwrap();
        graph
            .add_node(make_node("A::x", "function", "a.rs"))
            .unwrap();
        graph
            .add_node(make_node("C::x", "function", "c.rs"))
            .unwrap();
        // 9 Substring nodes "xx_9".."xx_1" added in REVERSE-alpha order.
        for i in (1..=9).rev() {
            graph
                .add_node(make_node(
                    &format!("xx_{i}"),
                    "function",
                    &format!("s{i}.rs"),
                ))
                .unwrap();
        }

        // `search` is UNCAPPED and fully ordered: the `take(10)` cap is the
        // renderer's choice, applied at the run_signature call site (graph_cmd.rs)
        // — `search` itself returns ALL candidates in tier+alpha order.
        let results = search(&graph, "x");
        assert_eq!(
            results.len(),
            13,
            "search returns ALL candidates (1 exact + 3 suffix + 9 substring); the cap is caller-side"
        );

        // First element is the Exact tier.
        assert_eq!(results[0].symbol_name, "x", "Exact tier comes first");

        // Suffix tier (indices 1..=3) is alpha-ordered A::x < B::x < C::x, and
        // appears BEFORE any Substring match — NOT insertion order (B,A,C).
        assert_eq!(results[1].symbol_name, "A::x");
        assert_eq!(results[2].symbol_name, "B::x");
        assert_eq!(results[3].symbol_name, "C::x");

        // Substring tier (indices 4..=12) is alpha-ordered xx_1..xx_9 — NOT the
        // reverse-alpha insertion order they were added in.
        let substr_names: Vec<&str> = results[4..]
            .iter()
            .map(|m| m.symbol_name.as_str())
            .collect();
        assert_eq!(
            substr_names,
            vec![
                "xx_1", "xx_2", "xx_3", "xx_4", "xx_5", "xx_6", "xx_7", "xx_8", "xx_9"
            ],
            "Substring tier comes after Suffix, alpha-ordered (not insertion order)"
        );

        // No Substring name appears before a Suffix name (tier order, not
        // insertion order).
        let first_substr = results
            .iter()
            .position(|m| m.symbol_name.starts_with("xx_"));
        let last_suffix = results.iter().rposition(|m| m.symbol_name.ends_with("::x"));
        assert!(
            last_suffix < first_substr,
            "all Suffix matches precede all Substring matches"
        );

        // CAP pin: the run_signature rewire applies `.take(10)` over `search`
        // EXACTLY as graph_cmd.rs does. Pinning the same adapter expression here
        // guards the cap behavior the println!-only run_signature cannot cheaply
        // output-assert (discovery note). New order keeps the Exact head +
        // Suffix-before-Substring, capped to 10 (the first 6 substrings fit).
        let capped: Vec<String> = search(&graph, "x")
            .into_iter()
            .map(|m| m.symbol_name)
            .take(10)
            .collect();
        assert_eq!(
            capped.len(),
            10,
            "take(10) cap matches the run_signature site"
        );
        assert_eq!(capped[0], "x");
        assert_eq!(&capped[1..4], &["A::x", "B::x", "C::x"]);
        assert_eq!(
            &capped[4..],
            &["xx_1", "xx_2", "xx_3", "xx_4", "xx_5", "xx_6"],
            "cap truncates the alpha-ordered substring tail"
        );
    }

    /// WU-0003 / CL-REACH RC5 (F9): `reachability_label` takes the non-`Option`
    /// class directly; the former `None => "unknown"` arm became the explicit
    /// `Unclassified => "UNCLASSIFIED"` arm.
    #[test]
    fn reachability_label_unclassified_is_uppercase_token() {
        assert_eq!(
            reachability_label(ReachabilityClass::Unclassified),
            "UNCLASSIFIED"
        );
        assert_eq!(reachability_label(ReachabilityClass::Wired), "WIRED");
        assert_eq!(reachability_label(ReachabilityClass::Dead), "DEAD");
    }

    /// F4 (ADR-0029 OBS-1/SIMILAR): a discovery ERROR from
    /// `run_inline_reachability` PROPAGATES as `Err`, not a silent `Ok(None)`
    /// that callers would fold to `Unclassified`. RED on HEAD: the fn returned
    /// `Option` and did `.ok()?`, so a discovery Err collapsed to `None`
    /// (indistinguishable from genuine-unclassified — the assert-Err would not
    /// even compile against the old signature).
    #[test]
    fn run_inline_reachability_propagates_discovery_error() {
        // A root with NO Cargo.toml -> discover_entry_points Err(NoSupportedManifest).
        let dir = tempfile::tempdir().expect("tempdir");
        let mut graph = KnowledgeGraph::new();
        let node = make_node("alpha", "function", "src/alpha.rs");
        let id = node.memory_id;
        graph.add_node(node).expect("add node");

        let result = run_inline_reachability(&graph, &id, dir.path());
        assert!(
            matches!(
                result,
                Err(crate::entry_points::EntryPointError::NoSupportedManifest)
            ),
            "a discovery error must propagate, not fold to a silent Unclassified"
        );
    }

    // ========================================================================
    // WU-0014 ITEM 2 — target/-glue exclusion from the SAFE_DELETE surface
    // ========================================================================

    #[test]
    fn is_generated_target_path_matches_out_dir_glue() {
        assert!(is_generated_target_path(
            "target/debug/build/serde-abc/out/lib.rs"
        ));
        assert!(is_generated_target_path(
            "/home/u/proj/target/debug/build/x/out/g.rs"
        ));
        assert!(!is_generated_target_path("src/lib.rs"));
        assert!(!is_generated_target_path(
            "crates/h00ligan-engine/src/graph.rs"
        ));
        // `targets` (plural) is a real source dir name, NOT a build dir.
        assert!(!is_generated_target_path("src/targets/mod.rs"));
        // A USER dir literally named `target` with NO build/out OUT_DIR shape
        // must NOT be excluded (review: prior any(=="target") over-matched ->
        // would silently drop genuinely-dead user code from the dead surface).
        assert!(!is_generated_target_path("src/foo/target/bar.rs"));
        assert!(!is_generated_target_path("target/notes.rs")); // target/ but no build/out
    }

    /// RED on HEAD: a Dead symbol resident under `target/` was listed as
    /// SAFE_DELETE in the full dead report; after the WU-0014 filter it is
    /// excluded, while a genuine `src/` dead symbol is STILL reported (the
    /// over-exclusion negative control).
    #[test]
    fn dead_report_excludes_target_glue_keeps_real_dead() {
        let mut graph = KnowledgeGraph::new();
        graph
            .add_node(make_node_with_reach(
                "real_dead",
                "function",
                "src/util.rs",
                ReachabilityClass::Dead,
            ))
            .unwrap();
        graph
            .add_node(make_node_with_reach(
                "__private::Glue",
                "struct",
                "target/debug/build/serde-1.0/out/lib.rs",
                ReachabilityClass::Dead,
            ))
            .unwrap();

        let DeadReport::Full(data) =
            dead_report_gated(&graph, crate::graph_stats::CoverageTier::Sufficient, true)
        else {
            panic!("Sufficient tier must EMIT a full report");
        };
        let names: Vec<&str> = data
            .entries
            .iter()
            .map(|e| e.symbol_name.as_str())
            .collect();
        assert!(
            names.contains(&"real_dead"),
            "genuine src/ dead symbol must still be reported (no over-exclusion)"
        );
        assert!(
            !names.contains(&"__private::Glue"),
            "target/ build-script glue must NOT be on the SAFE_DELETE surface, got {names:?}"
        );
    }

    /// Review fix: the SINGLE-symbol dead check must apply the same target/-glue
    /// exclusion as the full report (it leaked a SAFE_DELETE on a directly-queried
    /// target/ symbol on HEAD-of-this-branch). A target/-resident Dead node →
    /// `is_dead == false` (withheld); a genuine src/ Dead node → `is_dead == true`
    /// (no over-exclusion).
    #[test]
    fn dead_single_excludes_target_glue_keeps_real_dead() {
        let mut graph = KnowledgeGraph::new();
        let real = make_node_with_reach(
            "real_dead",
            "function",
            "src/util.rs",
            ReachabilityClass::Dead,
        );
        let glue = make_node_with_reach(
            "__private::Glue",
            "struct",
            "target/debug/build/serde-1.0/out/lib.rs",
            ReachabilityClass::Dead,
        );
        graph.add_node(real.clone()).unwrap();
        graph.add_node(glue.clone()).unwrap();

        let tier = crate::graph_stats::CoverageTier::Sufficient;
        let DeadSingleReport::Computed {
            is_dead: glue_dead, ..
        } = dead_single_gated(&graph, &glue, tier, true)
        else {
            panic!("Sufficient tier must compute a single-symbol verdict");
        };
        assert!(
            !glue_dead,
            "a directly-queried target/ build-script symbol must NOT report is_dead/SAFE_DELETE"
        );

        let DeadSingleReport::Computed {
            is_dead: real_dead, ..
        } = dead_single_gated(&graph, &real, tier, true)
        else {
            panic!("Sufficient tier must compute a single-symbol verdict");
        };
        assert!(
            real_dead,
            "a genuine src/ Dead symbol must still report is_dead (no over-exclusion)"
        );
    }

    // ========================================================================
    // WU-0014 ITEM 1 — L4 reachability suppression for assess/inspect/tests
    // ========================================================================

    fn fake_coverage_unavailable() -> serde_json::Value {
        serde_json::json!({
            "tier": "Unavailable",
            "calls_authority_available": false
        })
    }

    #[test]
    fn suppress_assess_neutralizes_confident_risk_and_callers() {
        // An EMIT-shaped assess result that LEAKS confident risk + 0 callers.
        let mut result = serde_json::json!({
            "symbol": "helper_used",
            "resolved": "crate::helper_used",
            "blast_radius": { "total_affected": 0, "affected": [] },
            "callers": { "count": 0, "items": [] },
            "tests": { "test_function_count": 0, "items": [] },
            "risk": { "level": "LOW", "fan_in": 0, "max_depth": 0 },
        });
        // Pre-suppression non-vacuity: the confident leak is present.
        assert_eq!(result["risk"]["level"], "LOW");

        suppress_assess_json(&mut result, fake_coverage_unavailable());

        assert_eq!(result["reachability"], "UNKNOWN");
        assert_eq!(result["risk"]["level"], "UNKNOWN");
        assert!(result["risk"]["fan_in"].is_null());
        assert!(result["callers"]["count"].is_null());
        assert!(result["blast_radius"]["total_affected"].is_null());
        assert_eq!(result["coverage"]["tier"], "Unavailable");
        assert!(result.get("action_required").is_some());
    }

    #[test]
    fn suppress_inspect_keeps_syntax_neutralizes_reachability() {
        let mut result = serde_json::json!({
            "symbol": "helper_used",
            "kind": "function",
            "file_path": "src/util.rs",
            "reachability": "DEAD",
            "signature": "fn helper_used()",
            "source": "fn helper_used() {}",
            "structure": {
                "fields": [{ "name": "x", "signature": "u32" }],
                "methods": [{ "name": "m", "signature": "fn m()", "reachability": "DEAD" }],
            },
            "callers": { "count": 0, "items": [] },
            "field_usage": { "x": [] },
            "tests": { "count": 0, "items": [] },
            "action_tier": "ACTION",
            "warnings": [
                "DEAD: not reachable from any entry point",
                "No signature available — run `reindex`"
            ],
        });
        assert_eq!(result["reachability"], "DEAD");

        suppress_inspect_json(&mut result, fake_coverage_unavailable());

        // Reachability-derived → UNKNOWN/withheld.
        assert_eq!(result["reachability"], "UNKNOWN");
        assert_eq!(result["action_tier"], "UNKNOWN");
        assert!(result["callers"]["count"].is_null());
        assert!(result["field_usage"].is_null());
        assert_eq!(result["structure"]["methods"][0]["reachability"], "UNKNOWN");
        // Syntactic facts preserved.
        assert_eq!(result["source"], "fn helper_used() {}");
        assert_eq!(result["signature"], "fn helper_used()");
        assert_eq!(result["structure"]["fields"][0]["name"], "x");
        // The DEAD warning dropped; the syntactic warning kept.
        let warnings = result["warnings"].as_array().expect("warnings kept");
        assert!(
            warnings
                .iter()
                .all(|w| !w.as_str().unwrap().starts_with("DEAD:"))
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.as_str().unwrap().contains("No signature"))
        );
        assert_eq!(result["coverage"]["tier"], "Unavailable");
    }

    #[test]
    fn suppress_tests_withholds_no_coverage_signal() {
        let mut result = serde_json::json!({
            "symbol": "helper_used",
            "kind": "function",
            "file_path": "src/util.rs",
            "reachability": "DEAD",
            "test_count": 0,
            "tests": [],
            "truncated": false,
        });
        assert_eq!(result["reachability"], "DEAD");
        assert_eq!(result["test_count"], 0);

        suppress_tests_json(&mut result, fake_coverage_unavailable());

        assert_eq!(result["reachability"], "UNKNOWN");
        assert!(
            result["test_count"].is_null(),
            "test_count MUST be null (not a confident 0 / NO COVERAGE)"
        );
        assert_eq!(result["coverage"]["tier"], "Unavailable");
        assert!(result.get("action_required").is_some());
    }

    // -----------------------------------------------------------------------
    // WU-0015 Leg 2 — crate_name_of (the Option-returning helper, ADR-0036).
    // DISTINCT from edge_builder::crate_of (which never returns None); the Leg-3
    // gate needs None to SKIP non-crates paths rather than bucket them.
    // -----------------------------------------------------------------------

    #[test]
    fn crate_name_of_c1_extracts_name() {
        assert_eq!(
            crate_name_of("crates/h00ligan-engine/src/graph.rs"),
            Some("h00ligan-engine")
        );
        assert_eq!(crate_name_of("crates/h00-sdl/src/lib.rs"), Some("h00-sdl"));
    }

    #[test]
    fn crate_name_of_c2_non_crates_path_none() {
        assert_eq!(crate_name_of("src/main.rs"), None);
        assert_eq!(crate_name_of("README.md"), None);
        assert_eq!(crate_name_of(""), None);
        // A bare `crates/` with no name segment must also yield None, never Some("").
        assert_eq!(crate_name_of("crates/"), None);
    }
}
