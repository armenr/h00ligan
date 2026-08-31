//! Composite commands: `assess`, `inspect`, `dead`, `tests`, `overview`, and `audit`.
//!
//! Each command composes multiple engine queries into a single CLI
//! invocation. All graph traversal uses shared engine functions from
//! `h00ligan_engine::graph_query` — no duplicate BFS logic.

use std::collections::BTreeSet;
use std::path::Path;

use clap::Args;
#[cfg(test)]
use uuid::Uuid;

use h00ligan_engine::code_intel_assess::{
    AssessRequest, AssessSection, DEFAULT_ASSESS_DEPTH, DEFAULT_ASSESS_PAGE_SIZE,
    ExactAssessResult, parse_assess_filter, parse_assess_section, validate_assess_request,
};
use h00ligan_engine::code_intel_audit::{
    AuditDeadCode, AuditDeadCodeStatus, AuditRequest, DEFAULT_AUDIT_DEAD_RATIO_PERCENT,
    DEFAULT_AUDIT_FAN_IN_THRESHOLD, DEFAULT_AUDIT_PAGE_SIZE, ExactAuditResult, parse_audit_scope,
    validate_audit_request,
};
use h00ligan_engine::code_intel_tests::{
    DEFAULT_TESTS_PAGE_SIZE, ExactTestsResult, TestsRequest, validate_tests_request,
};
use h00ligan_engine::graph::KnowledgeGraph;
#[cfg(test)]
use h00ligan_engine::graph::{EdgeKind, GraphNode};
#[cfg(test)]
use h00ligan_engine::graph_query::reverse_bfs;
#[cfg(test)]
use h00ligan_engine::graph_query::{
    DeadAction, classify_dead_action, is_test_file, resolve_unique,
};
use h00ligan_engine::graph_query::{
    FileContext, Match, reachability_label, symbol_not_found_candidates,
};
use h00ligan_engine::project_binding::ProjectBinding;
#[cfg(test)]
use h00ligan_engine::reachability::ReachabilityClass;

use crate::error::LiganError;
use crate::graph_cmd::load_indexed_graph_snapshot;
use crate::ligan_cmd::OutputFormat;

// ============================================================================
// Helpers
// ============================================================================

/// Parse output format from string.
fn parse_format(s: &str) -> Result<OutputFormat, LiganError> {
    s.parse::<OutputFormat>().map_err(LiganError::Config)
}

fn print_domain_error(
    format: OutputFormat,
    error: &h00ligan_engine::code_intel_domain::DomainError,
) -> Result<(), LiganError> {
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&error.envelope())
                .map_err(|serialize| LiganError::Config(serialize.to_string()))?
        );
    }
    Ok(())
}

/// Truncate a string to at most `max` chars with trailing "...".
///
/// CI-IND-06: truncation is char-boundary-safe. The previous implementation
/// sliced `&name[..max.saturating_sub(3)]` using a raw byte index guarded only
/// by a *byte*-length check (`name.len() <= max`), so a multibyte char
/// straddling the cut boundary panicked ("byte index N is not a char
/// boundary") — this crashed `h00ligan dead`. Mirrors `graph_cmd::truncate_symbol`.
fn truncate_symbol(name: &str, max: usize) -> String {
    if name.len() <= max {
        name.to_string()
    } else {
        let cut = name.floor_char_boundary(max.saturating_sub(3));
        format!("{}...", &name[..cut])
    }
}

/// Format an error for a symbol not found, including Levenshtein candidates.
///
/// FIX-22: emits the standardized F1 shape used by the agent-side
/// `not_found_error` helper (composite_intel.rs). Downstream test helpers
/// parse the `Did you mean one of: [...]?` phrasing so the CLI + MCP
/// paths report the same suggestion text.
pub(crate) fn symbol_not_found_error(graph: &KnowledgeGraph, symbol: &str) -> LiganError {
    let candidates = symbol_not_found_candidates(graph, symbol);
    if candidates.is_empty() {
        LiganError::Config(format!(
            "symbol '{symbol}' not found in knowledge graph. No similar symbols found."
        ))
    } else {
        let top_names: Vec<&str> = candidates.iter().take(5).map(|(n, _)| n.as_str()).collect();
        let suggestion = if top_names.len() == 1 {
            format!("Did you mean '{}'?", top_names[0])
        } else {
            format!("Did you mean one of: [{}]?", top_names.join(", "))
        };
        let full: Vec<String> = candidates
            .iter()
            .take(10)
            .map(|(name, dist)| format!("{name} (dist={dist})"))
            .collect();
        LiganError::Config(format!(
            "symbol '{symbol}' not found. {suggestion} (candidates: [{}])",
            full.join(", "),
        ))
    }
}

/// Format an F8 (ambiguous-symbol) error enumerating every candidate.
///
/// ADR-0027 / WU-0002 Wave 3: the single CLI-side renderer for the
/// [`Resolution::Ambiguous`] arm. Each candidate is rendered with the
/// canonical structured `{symbol_name} ({file_path})` round-trip label —
/// byte-for-byte identical to the MCP F8 candidate label emitted by
/// `resolve_unique_or_tool_err`, so CLI ≡ MCP parity holds.
/// The label deliberately avoids the `::`-prefixed `file_path::symbol` form
/// (which would trip `is_path_query`); the `(file_path)` pair is the
/// round-trip key a caller feeds back as `FileContext` + `symbol_name`.
///
/// Returns [`LiganError::Config`] — never picks a first/arbitrary candidate.
/// The per-candidate label is [`Match::candidate_label`], the single source of
/// truth shared with the MCP F8 renderer (CLI ≡ MCP parity, P-PARITY-1).
pub(crate) fn ambiguous_symbol_error(symbol: &str, candidates: &[Match]) -> LiganError {
    let rendered: Vec<String> = candidates
        .iter()
        .take(10)
        .map(Match::candidate_label)
        .collect();
    LiganError::Config(format!(
        "symbol '{symbol}' is ambiguous — matches {} nodes: [{}]. \
         Use `h00ligan find {symbol:?} --name --definitions-only --format json` and pass one result's symbol_id as the symbol selector. \
         For cross-file homonyms, --file <path> is also sufficient.",
        candidates.len(),
        rendered.join(", "),
    ))
}

/// Map a caller-supplied `--file` CLI disambiguator to a [`FileContext`] locality
/// hint, mirroring the MCP `file_locality` (code_intel.rs) so an **absolute**
/// `--file` resolves identically on both surfaces (CLI ≡ MCP, P-PARITY-1).
///
/// The knowledge graph stores **repo-root-relative** paths, and the engine's
/// `locality_pick` matches by exact string equality — so an absolute `--file`
/// must first be made root-relative or it silently falls through to F8. An
/// absolute path has the (canonicalized) `root` prefix stripped (falling back to
/// the raw `root`), and a leading `./` is removed. A path that is already
/// repo-relative is returned byte-for-byte (the documented happy path is
/// preserved). An empty / absent path yields `None` (no locality → the normal F8
/// ambiguity path). Purely additive: `None` reproduces the legacy behaviour.
pub(crate) fn cli_file_locality(file: Option<&str>, root: &Path) -> Option<FileContext> {
    file.filter(|s| !s.is_empty()).map(|s| {
        let p = Path::new(s);
        // Prefer the canonicalized root (resolves `.`/symlinks so an absolute
        // `--file` under the workspace strips cleanly); fall back to the raw root.
        let rel = root
            .canonicalize()
            .ok()
            .and_then(|abs_root| p.strip_prefix(&abs_root).ok().map(Path::to_path_buf))
            .or_else(|| p.strip_prefix(root).ok().map(Path::to_path_buf))
            .unwrap_or_else(|| p.to_path_buf());
        let rel = rel.strip_prefix("./").unwrap_or(rel.as_path());
        FileContext::from(rel.to_string_lossy().to_string())
    })
}

// ============================================================================
// 1. assess <symbol> — Change Impact Analysis
// ============================================================================

/// Arguments for `h00ligan assess`.
#[derive(Args, Debug, Clone)]
pub struct AssessArgs {
    /// Symbol name, or an exact symbol_id returned by find.
    pub symbol: String,

    /// Optional repo-relative file path to disambiguate a homonym (same-file >
    /// same-crate). Use the path shown in parentheses for each ambiguous candidate.
    #[arg(long)]
    pub file: Option<String>,

    /// Sections to include (default: all). Comma-separated: blast_radius,callers,tests,risk.
    #[arg(long)]
    pub sections: Option<String>,

    /// Max transitive call and structural impact depth (default: 3, max: 10).
    #[arg(long, default_value_t = DEFAULT_ASSESS_DEPTH)]
    pub depth: usize,

    /// Reachability filter: live (default), dead, test_only, all.
    #[arg(long, default_value = "live")]
    pub filter: String,

    /// Maximum affected symbols in this page (default 50, max 100).
    #[arg(long, default_value_t = DEFAULT_ASSESS_PAGE_SIZE)]
    pub limit: usize,

    /// Continue a blast-radius page from the exact generation and query.
    #[arg(long)]
    pub cursor: Option<String>,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// Run the engine-owned Assess contract and render it for the selected
/// transport. The JSON shape is byte-for-byte the same DTO returned by MCP.
pub async fn run_assess(args: AssessArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let sections = match args.sections.as_deref() {
        None => AssessSection::ALL.into_iter().collect::<BTreeSet<_>>(),
        Some(raw) => match raw
            .split(',')
            .map(parse_assess_section)
            .collect::<Result<BTreeSet<_>, _>>()
        {
            Ok(sections) => sections,
            Err(error) => {
                if format == OutputFormat::Json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&error.envelope())
                            .map_err(|serialize| LiganError::Config(serialize.to_string()))?
                    );
                }
                return Err(error.into());
            }
        },
    };
    let filter = match parse_assess_filter(&args.filter) {
        Ok(filter) => filter,
        Err(error) => {
            if format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&error.envelope())
                        .map_err(|serialize| LiganError::Config(serialize.to_string()))?
                );
            }
            return Err(error.into());
        }
    };
    let request = AssessRequest {
        symbol: args.symbol,
        file: args.file,
        sections,
        max_depth: args.depth,
        filter,
        limit: args.limit,
        cursor: args.cursor,
    };
    if let Err(error) = validate_assess_request(&request) {
        if format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::to_string_pretty(&error.envelope())
                    .map_err(|serialize| LiganError::Config(serialize.to_string()))?
            );
        }
        return Err(error.into());
    }
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let result = match snapshot.query_assess(binding, &request).await {
        Ok(result) => result,
        Err(error) => {
            if format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&error.envelope())
                        .map_err(|serialize| LiganError::Config(serialize.to_string()))?
                );
            }
            return Err(error.into());
        }
    };
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .map_err(|error| LiganError::Config(error.to_string()))?
        );
    } else {
        render_assess(&result);
    }
    Ok(())
}

fn render_assess(result: &ExactAssessResult) {
    println!("ASSESS {}", result.resolved_symbol.structural.name);
    println!(
        "  authority: {:?}; population complete: {}",
        result.authority.status, result.authority.population_complete
    );
    println!("  generation: {}", result.generation_id.0);
    println!();

    if let Some(blast) = &result.blast_radius {
        println!(
            "BLAST RADIUS: {} observed affected symbol{} across {} file{}",
            blast.observed_affected_symbols,
            if blast.observed_affected_symbols == 1 {
                ""
            } else {
                "s"
            },
            blast.observed_affected_files,
            if blast.observed_affected_files == 1 {
                ""
            } else {
                "s"
            },
        );
        println!(
            "  evidence: {} execution-path ({} exact-only, {} qualified-binding), {} structural; page {} returned {}",
            blast.observed_execution_affected_symbols,
            blast.observed_exact_only_affected_symbols,
            blast.observed_qualified_binding_affected_symbols,
            blast.observed_structural_affected_symbols,
            blast.page.offset,
            blast.page.returned,
        );
        for item in &blast.items {
            let mut evidence = Vec::new();
            if let Some(path) = &item.execution_path {
                if path
                    .iter()
                    .any(h00ligan_engine::code_intel_calls::CallablePathStep::is_qualified)
                {
                    evidence.push("qualified-binding");
                } else {
                    evidence.push("exact-call");
                }
            }
            if item.structural_path.is_some() {
                evidence.push("structural");
            }
            println!(
                "  depth {:<2} {:<36} {} [{}; {}]",
                item.minimum_depth,
                truncate_symbol(&item.symbol.name, 36),
                item.symbol.document_path,
                evidence.join("+"),
                reachability_label(item.reachability),
            );
        }
        if let Some(cursor) = &blast.page.next_cursor {
            println!("  next cursor: {cursor}");
        }
        println!();
    }

    if let Some(callers) = &result.callers {
        println!("DIRECT CALLERS: {:?}", callers.applicability);
        if let Some(count) = callers.observed_direct_callers {
            println!(
                "  {count} caller symbol{} at {} exact call site{}",
                if count == 1 { "" } else { "s" },
                callers.observed_call_sites.unwrap_or(0),
                if callers.observed_call_sites == Some(1) {
                    ""
                } else {
                    "s"
                },
            );
        }
        for item in &callers.items {
            println!(
                "  {} ({}) line {}",
                item.caller.name,
                item.caller.document_path,
                item.call_span.start_line + 1,
            );
        }
        println!();
    }

    if let Some(tests) = &result.tests {
        println!("RUNNABLE TEST ROOTS: {:?}", tests.applicability);
        if let Some(count) = tests.observed_runnable_test_roots {
            println!("  {count} observed");
        }
        for item in &tests.items {
            println!("  {} ({})", item.test.name, item.test.document_path);
        }
        println!();
    }

    if let Some(signals) = &result.risk {
        println!("REVIEW SIGNALS (objective, no synthetic risk tier):");
        println!("  affected symbols: {}", signals.observed_affected_symbols);
        println!("  affected files: {}", signals.observed_affected_files);
        if let Some(callers) = signals.observed_direct_callers {
            println!("  direct callers: {callers}");
        }
        if let Some(tests) = signals.observed_runnable_test_roots {
            println!("  runnable test roots: {tests}");
        }
        println!(
            "  maximum observed depth: {}",
            signals.maximum_observed_depth
        );
        println!("  crosses project units: {}", signals.crosses_project_units);
        println!("  population complete: {}", signals.population_complete);
        println!();
    }

    if !result.warnings.is_empty() {
        println!("QUALIFICATIONS:");
        for warning in &result.warnings {
            println!("  - {warning}");
        }
    }
}

// ============================================================================
// 2. inspect <symbol> — bounded multi-facet symbol dossier
// ============================================================================

/// Arguments for `h00ligan inspect`.
#[derive(Args, Debug, Clone)]
pub struct InspectArgs {
    /// Symbol name, or an exact symbol_id returned by find.
    pub symbol: String,

    /// Optional exact repository-relative indexed file used to disambiguate a homonym.
    #[arg(long)]
    pub file: Option<String>,

    /// Sections to include (default: all).
    /// Comma-separated: source,structure,callers,field_usage,tests,warnings.
    #[arg(long)]
    pub sections: Option<String>,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// Execute the same engine-owned Inspect composition used by MCP.
pub async fn run_inspect(args: InspectArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let sections = match args.sections.as_deref() {
        None => h00ligan_engine::code_intel_inspect::InspectSection::ALL
            .into_iter()
            .collect::<BTreeSet<_>>(),
        Some(raw) => {
            match h00ligan_engine::code_intel_inspect::parse_inspect_sections(raw.split(',')) {
                Ok(sections) => sections,
                Err(error) => {
                    if format == OutputFormat::Json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&error.envelope())
                                .map_err(|serialize| LiganError::Config(serialize.to_string()))?
                        );
                    }
                    return Err(error.into());
                }
            }
        }
    };
    let request = h00ligan_engine::code_intel_inspect::InspectRequest {
        symbol: args.symbol,
        file: args.file,
        sections,
    };
    if let Err(error) = h00ligan_engine::code_intel_inspect::validate_inspect_request(&request) {
        if format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::to_string_pretty(&error.envelope())
                    .map_err(|serialize| LiganError::Config(serialize.to_string()))?
            );
        }
        return Err(error.into());
    }

    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let result = match snapshot.query_inspect(binding, &request).await {
        Ok(result) => result,
        Err(error) => {
            if format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&error.envelope())
                        .map_err(|serialize| LiganError::Config(serialize.to_string()))?
                );
            }
            return Err(error.into());
        }
    };
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .map_err(|error| LiganError::Config(error.to_string()))?
        );
    } else {
        render_inspect(&result);
    }
    Ok(())
}

fn render_inspect(result: &h00ligan_engine::code_intel_inspect::ExactInspectResult) {
    use h00ligan_engine::code_intel_inspect::InspectFacet;

    println!(
        "INSPECT {} ({})",
        result.resolved_symbol.name, result.resolved_symbol.kind
    );
    println!("  file: {}", result.resolved_symbol.document_path);
    if !result.resolved_symbol.signature.is_empty() {
        println!("  signature: {}", result.resolved_symbol.signature);
    }
    println!(
        "  authority: {:?}; requested facets complete: {}",
        result.authority.status, result.authority.requested_facets_complete
    );
    println!("  generation: {}", result.generation_id.0);

    if let Some(source) = &result.source {
        println!();
        println!("SOURCE:");
        match source {
            InspectFacet::Available { result } | InspectFacet::Qualified { result } => {
                for line in result.source.lines() {
                    println!("  {line}");
                }
                if result.page.has_more {
                    println!(
                        "  ... {} more character(s); continue with `read --cursor {}`",
                        result
                            .page
                            .total_items
                            .saturating_sub(result.page.offset + result.page.returned),
                        result.page.next_cursor.as_deref().unwrap_or("<missing>")
                    );
                }
            }
            InspectFacet::NotApplicable { issue } | InspectFacet::Unavailable { issue } => {
                println!("  [{}] {}", issue.code, issue.message);
            }
        }
    }

    if let Some(structure) = &result.structure {
        println!();
        println!("STRUCTURE:");
        match structure {
            InspectFacet::Available { result } | InspectFacet::Qualified { result } => {
                println!(
                    "  {} member(s) returned of {}",
                    result.page.returned, result.page.total_items
                );
                for item in &result.items {
                    println!(
                        "  {:?}: {} ({})",
                        item.role, item.symbol.name, item.symbol.document_path
                    );
                }
                if result.page.has_more {
                    println!(
                        "  ... continue with `type --cursor {}`",
                        result.page.next_cursor.as_deref().unwrap_or("<missing>")
                    );
                }
            }
            InspectFacet::NotApplicable { issue } | InspectFacet::Unavailable { issue } => {
                println!("  [{}] {}", issue.code, issue.message);
            }
        }
    }

    if let Some(callers) = &result.callers {
        println!();
        println!("CALLERS:");
        match callers {
            InspectFacet::Available { result } | InspectFacet::Qualified { result } => {
                println!(
                    "  {} exact caller(s); {} callable-value binding(s); {} exact caller occurrence(s) returned",
                    result.total_callers, result.callable_value_bindings, result.page.returned
                );
                for caller in &result.items {
                    println!("  {} ({})", caller.caller.name, caller.caller.document_path);
                }
                if result.page.has_more {
                    println!(
                        "  ... continue with `calls --filter all --cursor {}`",
                        result.page.next_cursor.as_deref().unwrap_or("<missing>")
                    );
                }
            }
            InspectFacet::NotApplicable { issue } | InspectFacet::Unavailable { issue } => {
                println!("  [{}] {}", issue.code, issue.message);
            }
        }
    }

    if let Some(field_usage) = &result.field_usage {
        println!();
        println!("FIELD USAGE:");
        match field_usage {
            InspectFacet::Available { result } | InspectFacet::Qualified { result } => {
                for item in &result.items {
                    if item.dependents.is_empty() {
                        println!("  {}: no observations", item.field.name);
                    } else {
                        let users = item
                            .dependents
                            .iter()
                            .map(|dependent| dependent.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        println!("  {}: {users}", item.field.name);
                    }
                }
                for warning in &result.warnings {
                    println!("  note: {warning}");
                }
            }
            InspectFacet::NotApplicable { issue } | InspectFacet::Unavailable { issue } => {
                println!("  [{}] {}", issue.code, issue.message);
            }
        }
    }

    if let Some(tests) = &result.tests {
        println!();
        println!("TESTS:");
        match tests {
            InspectFacet::Available { result } | InspectFacet::Qualified { result } => {
                println!(
                    "  {} runnable test root(s); {} returned",
                    result.page.total_items, result.page.returned
                );
                for test in &result.items {
                    println!("  {} ({})", test.test.name, test.test.document_path);
                }
                if result.page.has_more {
                    println!(
                        "  ... continue with `tests --cursor {}`",
                        result.page.next_cursor.as_deref().unwrap_or("<missing>")
                    );
                }
            }
            InspectFacet::NotApplicable { issue } | InspectFacet::Unavailable { issue } => {
                println!("  [{}] {}", issue.code, issue.message);
            }
        }
    }

    if let Some(warnings) = &result.warnings {
        println!();
        println!("REVIEW SIGNALS:");
        match warnings {
            InspectFacet::Available { result } | InspectFacet::Qualified { result } => {
                if let Some(reachability) = result.reachability {
                    println!("  reachability: {reachability}");
                }
                if let Some(action_tier) = &result.action_tier {
                    println!("  action tier: {action_tier}");
                }
                if result.signals.is_empty() {
                    println!("  (no review signals)");
                } else {
                    for signal in &result.signals {
                        println!("  [{}] {}", signal.code, signal.message);
                    }
                }
            }
            InspectFacet::NotApplicable { issue } | InspectFacet::Unavailable { issue } => {
                println!("  [{}] {}", issue.code, issue.message);
            }
        }
    }

    for notice in &result.notices {
        println!();
        println!("NOTE: {notice}");
    }
}
// ============================================================================
// 3. dead [symbol] — Dead Code Analysis
// ============================================================================

/// Arguments for `h00ligan dead`.
#[derive(Args, Debug, Clone)]
pub struct DeadArgs {
    /// Symbol name or exact symbol_id returned by find (omit for a full report).
    pub symbol: Option<String>,

    /// Optional repo-relative file path to disambiguate a homonym on the
    /// single-symbol path (same-file > same-crate). Use the path shown in
    /// parentheses for each ambiguous candidate.
    #[arg(long)]
    pub file: Option<String>,

    /// Exclude test-only source populations from the full candidate report.
    #[arg(long)]
    pub production_only: bool,

    /// Maximum candidates in this page (default 50, max 100).
    #[arg(long, default_value_t = h00ligan_engine::code_intel_dead::DEFAULT_DEAD_PAGE_SIZE)]
    pub limit: usize,

    /// Continue a full candidate page from the exact generation and query.
    #[arg(long)]
    pub cursor: Option<String>,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// Run the engine-owned Dead v1 contract. Human output is a renderer over the
/// same bounded DTO that CLI JSON and MCP return.
pub async fn run_dead(args: DeadArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let request = h00ligan_engine::code_intel_dead::DeadRequest {
        symbol: args.symbol,
        file: args.file,
        production_only: args.production_only,
        limit: args.limit,
        cursor: args.cursor,
    };
    if let Err(error) = h00ligan_engine::code_intel_dead::validate_dead_request(&request) {
        if format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::to_string_pretty(&error.envelope())
                    .map_err(|serialize| LiganError::Config(serialize.to_string()))?
            );
        }
        return Err(error.into());
    }
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let result = match snapshot.query_dead(binding, &request).await {
        Ok(result) => result,
        Err(error) => {
            if format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&error.envelope())
                        .map_err(|serialize| LiganError::Config(serialize.to_string()))?
                );
            }
            return Err(error.into());
        }
    };
    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .map_err(|error| LiganError::Config(error.to_string()))?
        );
    } else {
        print!("{}", render_dead_text(&result));
    }
    Ok(())
}

fn render_dead_text(result: &h00ligan_engine::code_intel_dead::ExactDeadResult) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    if let Some(symbol) = result.query.symbol.as_deref() {
        let _ = writeln!(out, "DEAD CODE — {symbol}");
    } else {
        let _ = writeln!(out, "DEAD CODE CANDIDATES");
    }
    if result.query.symbol.is_some() {
        if let Some(item) = result.items.first() {
            let _ = write!(out, "{}", render_dead_item_text(item));
        } else {
            let _ = writeln!(out, "  No matching symbol was evaluated.");
        }
        let _ = writeln!(
            out,
            "  Authority: {} · population {}",
            dead_authority_label(&result.authority.status),
            if result.authority.population_complete {
                "complete"
            } else {
                "incomplete"
            }
        );
    } else {
        let _ = writeln!(
            out,
            "  Authority: {} · population {}",
            dead_authority_label(&result.authority.status),
            if result.authority.population_complete {
                "complete"
            } else {
                "incomplete"
            }
        );
        let _ = writeln!(
            out,
            "  {} candidates: {} unreached callables · {} qualified structural · {} unknown",
            result.summary.candidate_items,
            result.summary.unreached_callables,
            result.summary.qualified_structural_candidates,
            result.summary.unknown_candidates,
        );
        let _ = writeln!(out);
        for (index, item) in result.items.iter().enumerate() {
            let line = item
                .symbol
                .start_line
                .map(|line| format!(":{}", line + 1))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "  {}. {} — {}",
                result.page.offset + index + 1,
                item.symbol.name,
                dead_verdict_label(item.verdict)
            );
            let _ = writeln!(
                out,
                "     {}{line} · {}",
                item.symbol.document_path,
                dead_recommendation_label(item.recommendation)
            );
        }
    }
    if let Some(cursor) = result.page.next_cursor.as_deref() {
        let _ = writeln!(out, "\n  Next cursor: {cursor}");
    }
    if result.query.symbol.is_none() {
        for warning in &result.warnings {
            let _ = writeln!(out, "  Note: {warning}");
        }
    }
    out
}

fn render_dead_item_text(item: &h00ligan_engine::code_intel_dead::DeadItem) -> String {
    use std::fmt::Write as _;

    let line = item
        .symbol
        .start_line
        .map(|line| format!(":{}", line + 1))
        .unwrap_or_default();
    let mut out = String::new();
    let _ = writeln!(out, "  Verdict: {}", dead_verdict_label(item.verdict));
    let _ = writeln!(out, "  File: {}{line}", item.symbol.document_path);
    let _ = writeln!(
        out,
        "  Recommendation: {}",
        dead_recommendation_label(item.recommendation)
    );
    let _ = writeln!(
        out,
        "  Why: {} — {}",
        dead_evidence_status_label(item.evidence.status),
        dead_evidence_reason(item)
    );
    out
}

fn dead_evidence_reason(item: &h00ligan_engine::code_intel_dead::DeadItem) -> &str {
    if item.verdict == h00ligan_engine::code_intel_dead::DeadVerdict::StructuralCandidate {
        "non-callable symbols do not yet have provider-backed liveness evidence"
    } else {
        &item.evidence.reason
    }
}

const fn dead_authority_label(
    status: &h00ligan_engine::code_intel_domain::AuthorityStatus,
) -> &'static str {
    use h00ligan_engine::code_intel_domain::AuthorityStatus;
    match status {
        AuthorityStatus::Complete => "complete",
        AuthorityStatus::Qualified => "qualified",
    }
}

const fn dead_evidence_status_label(
    status: h00ligan_engine::code_intel_dead::DeadEvidenceStatus,
) -> &'static str {
    use h00ligan_engine::code_intel_dead::DeadEvidenceStatus;
    match status {
        DeadEvidenceStatus::Complete => "complete",
        DeadEvidenceStatus::Qualified => "qualified",
        DeadEvidenceStatus::Unavailable => "unavailable",
    }
}

const fn dead_verdict_label(
    verdict: h00ligan_engine::code_intel_dead::DeadVerdict,
) -> &'static str {
    use h00ligan_engine::code_intel_dead::DeadVerdict;
    match verdict {
        DeadVerdict::LiveProduction => "live in production",
        DeadVerdict::LiveTest => "used by tests",
        DeadVerdict::UnreachedCallable => "candidate — no retained root reaches this callable",
        DeadVerdict::StructuralCandidate => {
            "unknown — structural liveness is not provider-verified"
        }
        DeadVerdict::RetainedStructural => "retained structural symbol",
        DeadVerdict::Excluded => "excluded from this analysis",
        DeadVerdict::Unknown => "unknown — evidence is incomplete",
    }
}

const fn dead_recommendation_label(
    recommendation: h00ligan_engine::code_intel_dead::DeadRecommendation,
) -> &'static str {
    use h00ligan_engine::code_intel_dead::DeadRecommendation;
    match recommendation {
        DeadRecommendation::Keep => "keep",
        DeadRecommendation::Review => "review manually; do not remove from this result alone",
        DeadRecommendation::Withheld => "withheld until authority is complete",
    }
}

// ============================================================================
// 4. tests <symbol> — Test Coverage Mapping
// ============================================================================

/// Arguments for `h00ligan tests`.
#[derive(Args, Debug, Clone)]
pub struct TestsArgs {
    /// Symbol name, or an exact symbol_id returned by find.
    pub symbol: String,

    /// Optional repo-relative file path to disambiguate a homonym (same-file >
    /// same-crate). Use the path shown in parentheses for each ambiguous candidate.
    #[arg(long)]
    pub file: Option<String>,

    /// Maximum runnable test entries in this page (default 50, max 100).
    #[arg(long, default_value_t = DEFAULT_TESTS_PAGE_SIZE)]
    pub limit: usize,

    /// Continue a prior page from the exact generation and resolved target.
    #[arg(long)]
    pub cursor: Option<String>,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// Run `tests <symbol>` — find test coverage for a symbol.
pub async fn run_tests(args: TestsArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let request = TestsRequest {
        symbol: args.symbol,
        file: args.file,
        limit: args.limit,
        cursor: args.cursor,
    };
    if let Err(error) = validate_tests_request(&request) {
        if format == OutputFormat::Json {
            println!(
                "{}",
                serde_json::to_string_pretty(&error.envelope())
                    .map_err(|serialize| LiganError::Config(serialize.to_string()))?
            );
        }
        return Err(error.into());
    }
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let result = match snapshot.query_tests(binding, &request).await {
        Ok(result) => result,
        Err(error) => {
            if format == OutputFormat::Json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&error.envelope())
                        .map_err(|serialize| LiganError::Config(serialize.to_string()))?
                );
            }
            return Err(error.into());
        }
    };

    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result)
                .map_err(|error| LiganError::Config(error.to_string()))?
        );
    } else {
        render_tests(&result);
    }

    Ok(())
}

fn render_tests(result: &ExactTestsResult) {
    println!("TESTS REACHING {}", result.resolved_symbol.name);
    println!(
        "  {} runnable test root{}; authority: {:?}",
        result.page.total_items,
        if result.page.total_items == 1 {
            ""
        } else {
            "s"
        },
        result.authority.status,
    );
    println!(
        "  Page: offset {}, returned {}, limit {}",
        result.page.offset, result.page.returned, result.page.limit
    );
    println!();

    if result.items.is_empty() {
        match result.authority.status {
            h00ligan_engine::code_intel_domain::AuthorityStatus::Complete => {
                println!(
                    "  No runnable test root reaches this symbol in the complete provider-backed population."
                );
            }
            h00ligan_engine::code_intel_domain::AuthorityStatus::Qualified => {
                println!(
                    "  No runnable test root was found in the qualified population; exclusions or depth limits may hide additional paths."
                );
            }
        }
    }
    for (index, item) in result.items.iter().enumerate() {
        println!(
            "{}. {} ({})",
            result.page.offset + index + 1,
            item.test.name,
            item.test.document_path
        );
        let chain = item
            .chain
            .iter()
            .map(|step| step.source().name.as_str())
            .chain(item.chain.last().map(|step| step.target().name.as_str()))
            .collect::<Vec<_>>();
        if !chain.is_empty() {
            println!("   chain: {}", chain.join(" -> "));
        }
        if item
            .chain
            .iter()
            .any(h00ligan_engine::code_intel_calls::CallablePathStep::is_qualified)
        {
            println!("   authority: qualified callable-value dispatch path");
        }
    }
    if let Some(cursor) = &result.page.next_cursor {
        println!(
            "\n  Showing {} of {} test roots on this page.",
            result.page.returned, result.page.total_items
        );
        println!("  NEXT CURSOR: {cursor}");
    }
    for warning in &result.warnings {
        eprintln!("WARNING: {warning}");
    }
}

// ============================================================================
// 5. overview — Architecture Overview
// ============================================================================

/// Arguments for `h00ligan overview`.
#[derive(Args, Debug, Clone)]
pub struct OverviewArgs {
    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// Run `overview` from one immutable graph + project-inventory generation.
pub async fn run_overview(args: OverviewArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let (_graph, snapshot) = load_indexed_graph_snapshot(binding).await?;
    let result = snapshot
        .query_overview(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;

    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }

    print!("{}", render_overview_text(&result));

    Ok(())
}

/// Render the human-readable CLI view of the shared Overview result.
///
/// Pure (returns the rendered `String`, no `println!`), so the CLI render is
/// drive-testable end-to-end. On an unclassified graph this renders a prominent
/// UNCLASSIFIED banner and suppresses an authoritative unreached-callable
/// count. A zero on an unclassified graph is a false-clean (the classifier
/// never ran), so presenting it as clean would be dangerously misleading.
fn render_overview_text(
    overview: &h00ligan_engine::code_intel_overview::ExactOverviewResult,
) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "ARCHITECTURE OVERVIEW");
    let _ = writeln!(out, "  Project: {}", overview.repository.root_label);
    let _ = writeln!(
        out,
        "  Graph: {} nodes, {} edges",
        format_human_count(overview.total_nodes),
        format_human_count(overview.total_edges)
    );
    let _ = writeln!(
        out,
        "  Health: {}",
        overview_health_label(overview.health_status)
    );

    // CL-REACH-08: surface the unclassified banner at the top, before any health
    // numbers a reader might mistake for a clean signal.
    if overview.needs_unclassified {
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "⚠ UNCLASSIFIED — run `h00ligan index` first ({} nodes unclassified)",
            overview.unclassified_count
        );
    }

    let label_counts = overview.project_units.iter().fold(
        std::collections::BTreeMap::<&str, usize>::new(),
        |mut counts, unit| {
            *counts.entry(unit.label.as_str()).or_default() += 1;
            counts
        },
    );
    let unit_labels = overview
        .project_units
        .iter()
        .map(|unit| {
            let label = if label_counts.get(unit.label.as_str()).copied().unwrap_or(0) > 1 {
                format!("{} ({})", unit.label, project_unit_kind_label(unit.kind))
            } else {
                unit.label.clone()
            };
            (unit.project_unit_id.clone(), label)
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "PROJECT UNITS ({})",
        format_human_count(overview.project_units.len())
    );
    for info in &overview.project_units {
        let label = unit_labels
            .get(&info.project_unit_id)
            .map_or(info.label.as_str(), String::as_str);
        let root_path = if info.root_path.is_empty() {
            "."
        } else {
            info.root_path.as_str()
        };
        if let Some(health) = &info.health {
            let _ = writeln!(
                out,
                "  {:<32} {:<14} {:<28} wired {}, dead {}, test-only {}",
                label,
                format!(
                    "{} {}",
                    info.language_id,
                    project_unit_kind_label(info.kind)
                ),
                root_path,
                format_human_count(health.wired),
                format_human_count(health.dead),
                format_human_count(health.test_only),
            );
        } else {
            let _ = writeln!(
                out,
                "  {:<32} {:<14} {}",
                label,
                format!(
                    "{} {}",
                    info.language_id,
                    project_unit_kind_label(info.kind)
                ),
                root_path,
            );
        }
    }

    if !overview.project_unit_dependencies.is_empty() {
        let mut dependencies = std::collections::BTreeMap::<String, Vec<String>>::new();
        for dependency in &overview.project_unit_dependencies {
            let from = unit_labels
                .get(&dependency.from_project_unit_id)
                .map_or_else(|| dependency.from_project_unit_id.to_string(), Clone::clone);
            let to = unit_labels
                .get(&dependency.to_project_unit_id)
                .map_or_else(|| dependency.to_project_unit_id.to_string(), Clone::clone);
            dependencies.entry(from).or_default().push(to);
        }
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "DEPENDENCIES ({} relationships)",
            format_human_count(overview.project_unit_dependencies.len())
        );
        for (from, mut targets) in dependencies {
            targets.sort();
            targets.dedup();
            let _ = writeln!(out, "  {from} -> {}", targets.join(", "));
        }
    }

    let has_key_types = overview.project_units.iter().any(|unit| {
        unit.top_types
            .as_ref()
            .is_some_and(|top_types| !top_types.is_empty())
    });
    if has_key_types {
        let _ = writeln!(out);
        let _ = writeln!(out, "KEY TYPES BY FAN-IN");
        for info in &overview.project_units {
            let Some(top_types) = &info.top_types else {
                continue;
            };
            if top_types.is_empty() {
                continue;
            }
            let label = unit_labels
                .get(&info.project_unit_id)
                .map_or(info.label.as_str(), String::as_str);
            let _ = writeln!(out, "  {label}:");
            for key_type in top_types {
                let _ = writeln!(
                    out,
                    "    {:<40} {:>3} incoming edges  ({})",
                    truncate_symbol(&key_type.name, 40),
                    key_type.fan_in,
                    key_type.kind,
                );
            }
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "SOURCE INVENTORY");
    let _ = writeln!(
        out,
        "  Project ownership: {}",
        project_inventory_coverage_label(overview.project_inventory.coverage)
    );
    if !overview.project_inventory.issues.is_empty() {
        let _ = writeln!(
            out,
            "  Classification issues: {}",
            format_human_count(overview.project_inventory.issues.len())
        );
    }
    if overview.project_inventory.unassigned_node_count > 0 {
        let _ = writeln!(
            out,
            "  Unassigned graph nodes: {}",
            format_human_count(overview.project_inventory.unassigned_node_count)
        );
    }

    let _ = writeln!(out);
    if let Some(dead_code_count) = overview.dead_code_count {
        let _ = writeln!(
            out,
            "UNREACHED CALLABLES: {}",
            format_human_count(dead_code_count)
        );
    } else {
        let _ = writeln!(
            out,
            "UNREACHED CALLABLES: unknown — {}",
            overview
                .health_guidance
                .as_deref()
                .unwrap_or("generation health is not authoritative")
        );
    }
    out
}

const fn project_unit_kind_label(
    kind: h00ligan_engine::code_intel_domain::ProjectUnitKind,
) -> &'static str {
    use h00ligan_engine::code_intel_domain::ProjectUnitKind;
    match kind {
        ProjectUnitKind::Workspace => "workspace",
        ProjectUnitKind::Package => "package",
        ProjectUnitKind::Module => "module",
        ProjectUnitKind::LooseSources => "loose sources",
        ProjectUnitKind::AuxiliarySources => "auxiliary sources",
    }
}

const fn project_inventory_coverage_label(
    coverage: h00ligan_engine::code_intel_domain::ProjectInventoryCoverage,
) -> &'static str {
    use h00ligan_engine::code_intel_domain::ProjectInventoryCoverage;
    match coverage {
        ProjectInventoryCoverage::IndexedSourcePopulationComplete => "complete",
        ProjectInventoryCoverage::IndexedSourcePopulationPartial => "partial",
    }
}

const fn overview_health_label(
    status: h00ligan_engine::code_intel_overview::OverviewHealthStatus,
) -> &'static str {
    use h00ligan_engine::code_intel_overview::OverviewHealthStatus;
    match status {
        OverviewHealthStatus::Complete => "complete",
        OverviewHealthStatus::Partial => "partial",
        OverviewHealthStatus::Unavailable => "unavailable (Calls evidence is incomplete)",
        OverviewHealthStatus::NotApplicable => "not applicable",
        OverviewHealthStatus::Unclassified => "unclassified",
        OverviewHealthStatus::Degenerate => "unavailable (generation is degenerate)",
    }
}

fn format_human_count(value: usize) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(character);
    }
    out
}

// ============================================================================
// 6. audit — Full Quality Audit
// ============================================================================

/// Arguments for `h00ligan audit`.
#[derive(Args, Debug, Clone)]
pub struct AuditArgs {
    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Coupling scope: production, conditional, tests, or all.
    #[arg(long, default_value = "production")]
    pub scope: String,

    /// Minimum observed fan-in for a symbol hotspot.
    #[arg(long, default_value_t = DEFAULT_AUDIT_FAN_IN_THRESHOLD)]
    pub min_fan_in: usize,

    /// Minimum per-project-unit dead-symbol ratio, as a percentage.
    #[arg(long, default_value_t = DEFAULT_AUDIT_DEAD_RATIO_PERCENT)]
    pub min_dead_ratio_percent: usize,

    /// Maximum symbol hotspots in this page.
    #[arg(long, default_value_t = DEFAULT_AUDIT_PAGE_SIZE)]
    pub limit: usize,

    /// Continue from a cursor bound to this generation and audit query.
    #[arg(long)]
    pub cursor: Option<String>,
}

/// Run `audit` from one immutable graph + project-inventory generation.
pub async fn run_audit(args: AuditArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let (_graph, snapshot) = load_indexed_graph_snapshot(binding).await?;
    let scope = match parse_audit_scope(&args.scope) {
        Ok(scope) => scope,
        Err(error) => {
            print_domain_error(format, &error)?;
            return Err(error.into());
        }
    };
    let request = AuditRequest {
        scope,
        min_fan_in: args.min_fan_in,
        min_dead_ratio_percent: args.min_dead_ratio_percent,
        limit: args.limit,
        cursor: args.cursor,
    };
    if let Err(error) = validate_audit_request(&request) {
        print_domain_error(format, &error)?;
        return Err(error.into());
    }
    let result = match snapshot.query_audit(binding, &request).await {
        Ok(result) => result,
        Err(error) => {
            print_domain_error(format, &error)?;
            return Err(error.into());
        }
    };

    if format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }

    print!("{}", render_audit_text(&result));
    Ok(())
}

fn render_audit_text(audit: &ExactAuditResult) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(out, "QUALITY AUDIT");
    let _ = writeln!(out, "  Project: {}", audit.repository.root_label);
    if let Some(live_inputs) = &audit.repository.live_inputs {
        let _ = writeln!(out, "  Live inputs: {}", live_inputs.freshness.as_str());
    }
    let _ = writeln!(
        out,
        "  Graph: {} nodes, {} edges",
        format_human_count(audit.graph.total_nodes),
        format_human_count(audit.graph.total_edges)
    );
    let _ = writeln!(
        out,
        "  Authority: Calls {}; structural graph {}",
        capability_coverage_label(audit.authority.calls.status),
        capability_coverage_label(audit.authority.structural_graph.status),
    );

    let _ = writeln!(out);
    match audit.dead_code.status {
        AuditDeadCodeStatus::Complete => {
            let _ = writeln!(
                out,
                "UNREACHED CALLABLES: {}",
                format_human_count(audit.dead_code.total.unwrap_or_default())
            );
            render_audit_dead_observations(&mut out, &audit.dead_code);
        }
        AuditDeadCodeStatus::Partial => {
            let _ = writeln!(
                out,
                "UNREACHED CALLABLES: aggregate unknown — {} authoritative project unit(s), {} withheld",
                audit.dead_code.authoritative_project_units, audit.dead_code.withheld_project_units,
            );
            render_audit_project_unit_authority(&mut out, &audit.dead_code);
            render_audit_dead_observations(&mut out, &audit.dead_code);
            if let Some(guidance) = audit.dead_code.guidance.as_deref() {
                let _ = writeln!(out, "  Qualification: {guidance}");
            }
        }
        AuditDeadCodeStatus::Unavailable => {
            let _ = writeln!(
                out,
                "UNREACHED CALLABLES: unknown — {}",
                audit
                    .dead_code
                    .guidance
                    .as_deref()
                    .unwrap_or("generation health is not authoritative")
            );
            render_audit_project_unit_authority(&mut out, &audit.dead_code);
        }
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "COUPLING HOTSPOTS — {} scope, fan-in >= {} ({} of {})",
        audit.query.scope.as_str(),
        audit.query.min_fan_in,
        audit.page.returned,
        audit.page.total_items,
    );
    if audit.hotspots.is_empty() {
        let _ = writeln!(out, "  None in this page.");
    }
    for hotspot in &audit.hotspots {
        let selected = hotspot.fan_in.selected(audit.query.scope);
        let location = hotspot.start_line.map_or_else(
            || hotspot.document_path.clone(),
            |line| format!("{}:{}", hotspot.document_path, line + 1),
        );
        let _ = writeln!(
            out,
            "  {:>5}  {}  ({}, {}, {})",
            hotspot.selected_fan_in,
            truncate_symbol(&hotspot.name, 64),
            hotspot.kind,
            hotspot.language_id,
            location,
        );
        let _ = writeln!(
            out,
            "         provider calls {}, structural call hints {}, field uses {}",
            selected.provider_calls, selected.structural_call_hints, selected.field_uses
        );
        let _ = writeln!(
            out,
            "         scopes: production {}, conditional {}, tests {}",
            hotspot.fan_in.production.total,
            hotspot.fan_in.conditional.total,
            hotspot.fan_in.tests.total,
        );
    }
    if let Some(cursor) = audit.page.next_cursor.as_deref() {
        let _ = writeln!(out, "  Next cursor: {cursor}");
    }
    for warning in &audit.warnings {
        let _ = writeln!(out, "  Note: {warning}");
    }
    out
}

fn render_audit_project_unit_authority(out: &mut String, dead_code: &AuditDeadCode) {
    use std::fmt::Write as _;

    if dead_code.project_unit_authority.is_empty() {
        return;
    }
    let _ = writeln!(out, "  Project-unit authority by language:");
    for authority in &dead_code.project_unit_authority {
        let _ = writeln!(
            out,
            "    {}: {} — {} authoritative, {} withheld",
            authority.language_id,
            audit_dead_code_status_label(authority.status),
            authority.authoritative_project_units,
            authority.withheld_project_units,
        );
    }
}

const fn audit_dead_code_status_label(status: AuditDeadCodeStatus) -> &'static str {
    match status {
        AuditDeadCodeStatus::Complete => "complete",
        AuditDeadCodeStatus::Partial => "partial",
        AuditDeadCodeStatus::Unavailable => "unavailable",
    }
}

fn render_audit_dead_observations(out: &mut String, dead_code: &AuditDeadCode) {
    use std::fmt::Write as _;

    if !dead_code.top_files.is_empty() {
        let _ = writeln!(out, "  Top files by authoritative unreached callables:");
        for file in &dead_code.top_files {
            let _ = writeln!(
                out,
                "    {:<60} {} unreached",
                file.document_path,
                format_human_count(file.dead_symbols)
            );
        }
    }
    if !dead_code.high_ratio_project_units.is_empty() {
        let _ = writeln!(
            out,
            "  Authoritative project units at or above {}% unreached callables:",
            dead_code.min_ratio_percent
        );
        for unit in &dead_code.high_ratio_project_units {
            let _ = writeln!(
                out,
                "    {:<32} {}/{} callables ({:.2}%, {})",
                unit.label,
                unit.dead_symbols,
                unit.total_symbols,
                unit.ratio_basis_points as f64 / 100.0,
                unit.language_id,
            );
        }
    }
}

const fn capability_coverage_label(
    status: h00ligan_engine::code_intel_domain::CapabilityCoverageStatus,
) -> &'static str {
    use h00ligan_engine::code_intel_domain::CapabilityCoverageStatus;
    match status {
        CapabilityCoverageStatus::NotApplicable => "not applicable",
        CapabilityCoverageStatus::Complete => "complete",
        CapabilityCoverageStatus::Qualified => "qualified",
        CapabilityCoverageStatus::Partial => "partial",
        CapabilityCoverageStatus::Unavailable => "unavailable",
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use h00ligan_engine::graph::GraphEdge;

    /// CI-IND-06 falsifier: `truncate_symbol` must not panic when the byte cut
    /// index (`max.saturating_sub(3)`) lands strictly inside a multibyte UTF-8
    /// char. RED on HEAD — the old `&name[..max.saturating_sub(3)]` raw byte
    /// slice was guarded only by a *byte*-length check (`name.len() <= max`),
    /// so this panicked ("byte index 5 is not a char boundary"), the crash
    /// behind `h00ligan dead`. GREEN after the `floor_char_boundary` fix.
    #[test]
    fn truncate_symbol_multibyte_no_panic() {
        // Greek alpha 'α' is 2 bytes (U+03B1); 10 of them = 20 bytes.
        let name = "α".repeat(10);
        // max = 8 < 20 bytes -> else branch. cut = max - 3 = 5, the *second*
        // byte of the 3rd 'α' (bytes 4,5) -> strictly inside a char boundary.
        let out = truncate_symbol(&name, 8);
        assert!(
            std::str::from_utf8(out.as_bytes()).is_ok(),
            "output must be valid UTF-8"
        );
        assert!(out.ends_with("..."), "should be truncated with ellipsis");
        // floor_char_boundary(5) -> 4, so "αα" + "..." (no panic is the point).
        assert_eq!(out, "αα...");
    }

    /// Build a minimal test graph for composite command tests.
    fn test_graph() -> KnowledgeGraph {
        let mut graph = KnowledgeGraph::new();

        // main() -> run() -> handler() -> helper()
        let main_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        let handler_id = Uuid::new_v4();
        let helper_id = Uuid::new_v4();
        let dead_id = Uuid::new_v4();
        let test_id = Uuid::new_v4();

        graph
            .add_node(GraphNode {
                memory_id: main_id,
                symbol_name: "main".into(),
                kind: "function".into(),
                file_path: "src/main.rs".into(),
                content_hash: "aaa".into(),
                signature: "fn main()".into(),
                reachability_class: ReachabilityClass::Wired,
                line_start: Some(0),
                line_end: Some(10),
                has_body: Some(true),
                visibility: "pub".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        graph
            .add_node(GraphNode {
                memory_id: run_id,
                symbol_name: "run".into(),
                kind: "function".into(),
                file_path: "src/lib.rs".into(),
                content_hash: "bbb".into(),
                signature: "pub fn run()".into(),
                reachability_class: ReachabilityClass::Wired,
                line_start: Some(5),
                line_end: Some(20),
                has_body: Some(true),
                visibility: "pub".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        graph
            .add_node(GraphNode {
                memory_id: handler_id,
                symbol_name: "handler".into(),
                kind: "function".into(),
                file_path: "src/lib.rs".into(),
                content_hash: "ccc".into(),
                signature: "fn handler()".into(),
                reachability_class: ReachabilityClass::Wired,
                line_start: Some(25),
                line_end: Some(40),
                has_body: Some(true),
                visibility: "".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        graph
            .add_node(GraphNode {
                memory_id: helper_id,
                symbol_name: "helper".into(),
                kind: "function".into(),
                file_path: "src/util.rs".into(),
                content_hash: "ddd".into(),
                signature: "fn helper() -> bool".into(),
                reachability_class: ReachabilityClass::Wired,
                line_start: Some(0),
                line_end: Some(5),
                has_body: Some(true),
                visibility: "pub(crate)".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        graph
            .add_node(GraphNode {
                memory_id: dead_id,
                symbol_name: "unused_fn".into(),
                kind: "function".into(),
                file_path: "src/util.rs".into(),
                content_hash: "eee".into(),
                signature: "fn unused_fn()".into(),
                reachability_class: ReachabilityClass::Dead,
                line_start: Some(10),
                line_end: Some(15),
                has_body: Some(true),
                visibility: "".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        graph
            .add_node(GraphNode {
                memory_id: test_id,
                symbol_name: "test_handler".into(),
                kind: "function".into(),
                file_path: "src/tests/handler_test.rs".into(),
                content_hash: "fff".into(),
                signature: "fn test_handler()".into(),
                reachability_class: ReachabilityClass::TestOnly,
                line_start: Some(0),
                line_end: Some(10),
                has_body: Some(true),
                visibility: "".into(),
                is_test_only: None,
                is_test_root: false,
                has_platform_cfg: false,
                rustc_flagged_dead: false,
                entry_retain: Default::default(),
                has_uncaptured_items: false,
                oracle_receipt: None,
            })
            .unwrap();

        // Edges: main --Calls--> run --Calls--> handler --Calls--> helper
        graph
            .add_edge(
                main_id,
                run_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    confidence: 0.9,
                    ..GraphEdge::default()
                },
            )
            .unwrap();
        graph
            .add_edge(
                run_id,
                handler_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    confidence: 0.9,
                    ..GraphEdge::default()
                },
            )
            .unwrap();
        graph
            .add_edge(
                handler_id,
                helper_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    confidence: 0.8,
                    ..GraphEdge::default()
                },
            )
            .unwrap();
        // test --Calls--> handler
        graph
            .add_edge(
                test_id,
                handler_id,
                GraphEdge {
                    kind: EdgeKind::Calls,
                    confidence: 0.7,
                    ..GraphEdge::default()
                },
            )
            .unwrap();

        graph
    }

    /// Build a graph with two free-function homonyms `process` in distinct
    /// files (a.rs / b.rs) — the OQ-READVERB-FILE-DISAMBIGUATOR fixture.
    fn homonym_graph() -> (KnowledgeGraph, Uuid, Uuid) {
        let mut graph = KnowledgeGraph::new();
        let a_id = Uuid::new_v4();
        let b_id = Uuid::new_v4();
        for (id, file) in [(a_id, "a.rs"), (b_id, "b.rs")] {
            graph
                .add_node(GraphNode {
                    memory_id: id,
                    symbol_name: "process".into(),
                    kind: "function".into(),
                    file_path: file.into(),
                    content_hash: file.into(),
                    signature: "pub fn process()".into(),
                    reachability_class: ReachabilityClass::Wired,
                    line_start: Some(0),
                    line_end: Some(3),
                    has_body: Some(true),
                    visibility: "pub".into(),
                    is_test_only: None,
                    is_test_root: false,
                    has_platform_cfg: false,
                    rustc_flagged_dead: false,
                    entry_retain: Default::default(),
                    has_uncaptured_items: false,
                    oracle_receipt: None,
                })
                .unwrap();
        }
        (graph, a_id, b_id)
    }

    /// OQ-READVERB-FILE-DISAMBIGUATOR (CLI falsifier): the shared CLI resolve +
    /// hint path. WITHOUT `--file` a homonym is F8 ambiguous AND the hint now
    /// names `--file` (NOT "use a qualified name"); WITH `--file` it resolves to
    /// the matching file's node — the same engine core the MCP shims use, so
    /// CLI ≡ MCP parity holds by construction. RED on HEAD: every CLI call site
    /// passed `None`, so a free-fn homonym was ALWAYS ambiguous, and the hint
    /// pushed the useless qualified-name advice.
    #[test]
    fn cli_file_disambiguates_free_fn_homonym_and_hint_names_file() {
        let (graph, a_id, b_id) = homonym_graph();

        // WITHOUT --file: ambiguous, and the shared CLI hint names --file.
        let amb = resolve_unique(&graph, "process", None)
            .unique_or_report()
            .expect_err("bare 'process' must be ambiguous");
        assert!(
            !amb.candidates.is_empty(),
            "expected F8 ambiguity (non-empty candidates), not F1 not-found"
        );
        let msg = ambiguous_symbol_error("process", &amb.candidates).to_string();
        assert!(msg.contains("--file"), "hint must name --file: {msg}");
        assert!(
            !msg.to_lowercase().contains("use a qualified name"),
            "hint must drop the misleading qualified-name advice: {msg}"
        );

        // WITH --file: resolves to the matching file's node.
        assert_eq!(
            resolve_unique(&graph, "process", Some(FileContext::from("a.rs")))
                .unique_or_report()
                .unwrap()
                .uuid(),
            a_id,
        );
        assert_eq!(
            resolve_unique(&graph, "process", Some(FileContext::from("b.rs")))
                .unique_or_report()
                .unwrap()
                .uuid(),
            b_id,
        );
    }

    /// MINOR-1 / MINOR-2 falsifier: the prior CLI falsifier passed a hand-built
    /// `FileContext::from(..)` to `resolve_unique`, never the real `--file`
    /// extraction (`cli_file_locality`). This drives the actual extraction the
    /// verb handlers use, on both a repo-relative and an ABSOLUTE `--file`.
    ///
    /// - relative input is preserved byte-for-byte (the documented happy path);
    /// - an absolute input under `root` is relativized so it matches the
    ///   repo-root-relative stored path — the CLI ≡ MCP parity fix.
    ///
    /// RED on HEAD: the CLI mapped `--file` via raw `FileContext::from`, so an
    /// absolute `--file` produced `FileContext("/abs/.../a.rs")`, which
    /// `locality_pick` (exact string match vs stored `a.rs`) NEVER matched →
    /// `resolve_unique` returned `Ambiguous` instead of the a.rs node.
    #[test]
    fn cli_file_locality_relativizes_abs_and_preserves_relative() {
        let (graph, a_id, _b_id) = homonym_graph();

        // Empty / absent → no locality.
        assert_eq!(cli_file_locality(None, Path::new(".")), None);
        assert_eq!(cli_file_locality(Some(""), Path::new(".")), None);

        // Repo-relative is preserved byte-for-byte and resolves to the a.rs node.
        let rel = cli_file_locality(Some("a.rs"), Path::new("."));
        assert_eq!(rel, Some(FileContext::from("a.rs")));
        assert_eq!(
            resolve_unique(&graph, "process", rel)
                .unique_or_report()
                .unwrap()
                .uuid(),
            a_id,
        );

        // A leading `./` is stripped (matches the stored repo-relative path).
        assert_eq!(
            cli_file_locality(Some("./a.rs"), Path::new(".")),
            Some(FileContext::from("a.rs"))
        );

        // An ABSOLUTE --file under a real root is relativized to `a.rs` and then
        // resolves — the bug MINOR-2 fixes (previously fell through to F8).
        let root_dir = tempfile::tempdir().expect("tempdir");
        let canon_root = root_dir.path().canonicalize().expect("canonicalize root");
        let abs_a = canon_root.join("a.rs");
        let abs_locality = cli_file_locality(abs_a.to_str(), &canon_root);
        assert_eq!(abs_locality, Some(FileContext::from("a.rs")));
        assert_eq!(
            resolve_unique(&graph, "process", abs_locality)
                .unique_or_report()
                .unwrap()
                .uuid(),
            a_id,
        );
    }

    #[test]
    fn test_reverse_bfs_finds_dependents() {
        let graph = test_graph();
        // 'helper' is a lone exact match → Unique (the FIXED EP1 behavior).
        let helper_id = resolve_unique(&graph, "helper", None)
            .unique_or_report()
            .unwrap()
            .uuid();
        let helper = graph.node(&helper_id).unwrap();

        let result = reverse_bfs(&graph, helper, 3, None);

        // handler calls helper directly (depth 1)
        assert!(
            result
                .dependents
                .iter()
                .any(|e| e.node.symbol_name == "handler" && e.depth == 1),
            "handler should be at depth 1"
        );
        // run calls handler (depth 2)
        assert!(
            result
                .dependents
                .iter()
                .any(|e| e.node.symbol_name == "run" && e.depth == 2),
            "run should be at depth 2"
        );
        // main calls run (depth 3)
        assert!(
            result
                .dependents
                .iter()
                .any(|e| e.node.symbol_name == "main" && e.depth == 3),
            "main should be at depth 3"
        );
        // test_handler also calls handler (depth 1)
        assert!(
            result
                .dependents
                .iter()
                .any(|e| e.node.symbol_name == "test_handler"),
            "test_handler should be found"
        );
        // File counts should include multiple files
        assert!(result.file_counts.len() >= 2);
        // Test files should include the test file
        assert!(
            result.test_files.contains_key("src/tests/handler_test.rs"),
            "test file should be detected"
        );
    }

    #[test]
    fn test_reverse_bfs_respects_depth() {
        let graph = test_graph();
        // 'helper' is a lone exact match → Unique (the FIXED EP1 behavior).
        let helper_id = resolve_unique(&graph, "helper", None)
            .unique_or_report()
            .unwrap()
            .uuid();
        let helper = graph.node(&helper_id).unwrap();

        let result = reverse_bfs(&graph, helper, 1, None);

        // Only depth 1: handler and test_handler
        assert!(
            result.dependents.iter().all(|e| e.depth <= 1),
            "all affected should be at depth 1 or less"
        );
        assert!(
            !result
                .dependents
                .iter()
                .any(|e| e.node.symbol_name == "run"),
            "run should NOT be found at depth 1"
        );
    }

    #[test]
    fn test_classify_dead_action_safe_delete() {
        let mut graph = test_graph();
        // 'unused_fn' is a lone exact match → Unique (the FIXED EP1 behavior).
        let dead_id = resolve_unique(&graph, "unused_fn", None)
            .unique_or_report()
            .unwrap()
            .uuid();
        // WU-0015 Leg-3b: SafeDelete now requires the full 4-way conjunction —
        // upgrade the lone dead fn to a private, rustc-flagged, cfg-clean-crate node.
        if let Some(n) = graph.node_mut(&dead_id) {
            n.file_path = "crates/x/src/util.rs".into();
            n.visibility = "private".into();
            n.rustc_flagged_dead = true;
        }
        let cfg_crates = h00ligan_engine::graph_query::cfg_touching_crates(&graph);
        let dead = graph.node(&dead_id).unwrap();
        let action = classify_dead_action(&graph, dead, &cfg_crates);
        assert_eq!(action, DeadAction::SafeDelete);
    }

    #[test]
    fn test_is_test_file_patterns() {
        assert!(is_test_file("src/tests/foo.rs"));
        assert!(is_test_file("src/foo_test.rs"));
        assert!(is_test_file("src/test_foo.rs"));
        assert!(is_test_file("src/foo_tests.rs"));
        assert!(!is_test_file("src/foo.rs"));
        assert!(!is_test_file("src/lib.rs"));
    }

    #[test]
    fn test_dead_full_report_finds_dead_symbols() {
        let graph = test_graph();
        let dead_nodes: Vec<&GraphNode> = graph
            .all_nodes()
            .into_iter()
            .filter(|n| {
                matches!(
                    n.reachability_class,
                    ReachabilityClass::Dead | ReachabilityClass::Orphan
                )
            })
            .collect();

        assert_eq!(dead_nodes.len(), 1);
        assert_eq!(dead_nodes[0].symbol_name, "unused_fn");
    }

    #[test]
    fn test_truncate_symbol() {
        assert_eq!(truncate_symbol("short", 10), "short");
        assert_eq!(truncate_symbol("a_very_long_symbol_name", 10), "a_very_...");
    }

    #[test]
    fn test_symbol_not_found_error() {
        let graph = test_graph();
        let err = symbol_not_found_error(&graph, "nonexistent_xyz");
        let msg = err.to_string();
        assert!(
            msg.contains("not found"),
            "error should mention not found: {msg}"
        );
    }

    /// FIX-22 CLI: symbol_not_found_error emits the standardized shape.
    #[test]
    fn symbol_not_found_error_emits_standardized_shape() {
        let graph = test_graph();
        // Use a string close enough to yield candidates (e.g. "helpe" ~ "helper").
        let err = symbol_not_found_error(&graph, "helpe");
        let msg = err.to_string();
        assert!(
            msg.contains("Did you mean '") || msg.contains("Did you mean one of: ["),
            "FIX-22 CLI: standardized suggestion phrasing. Got: {msg}"
        );
        assert!(
            msg.contains("(candidates: ["),
            "FIX-22 CLI: candidates list for CLI users. Got: {msg}"
        );
    }

    #[test]
    fn symbol_not_found_error_empty_graph() {
        let graph = KnowledgeGraph::new();
        let err = symbol_not_found_error(&graph, "anything");
        let msg = err.to_string();
        assert!(msg.contains("No similar symbols found"));
    }

    fn overview_result(
        dead_code_count: Option<usize>,
        health_status: h00ligan_engine::code_intel_overview::OverviewHealthStatus,
        unclassified_count: usize,
    ) -> h00ligan_engine::code_intel_overview::ExactOverviewResult {
        h00ligan_engine::code_intel_overview::ExactOverviewResult {
            schema_version: h00ligan_engine::code_intel_overview::OVERVIEW_SCHEMA_VERSION.into(),
            generation_id: h00ligan_engine::code_intel_domain::GenerationId::new("fixture-generation"),
            repository: h00ligan_engine::code_intel_domain::RepositoryBinding {
                repository_id: h00ligan_engine::code_intel_domain::RepositoryId::new(
                    "fixture-repository",
                ),
                root_label: "fixture".into(),
                live_inputs: None,
            },
            total_nodes: 5,
            total_edges: 2,
            project_units: vec![],
            project_unit_relationships: vec![],
            project_unit_dependencies: vec![],
            project_inventory:
                h00ligan_engine::code_intel_overview::OverviewProjectInventory {
                    coverage: h00ligan_engine::code_intel_domain::ProjectInventoryCoverage::IndexedSourcePopulationComplete,
                    issues: vec![],
                    unassigned_node_count: 5,
            },
            dead_code_count,
            health_status,
            health_action_needed: dead_code_count.is_none(),
            health_guidance: dead_code_count
                .is_none()
                .then(|| "publish authoritative health evidence".into()),
            unclassified_count,
            needs_unclassified: unclassified_count > 0,
            capabilities: h00ligan_engine::code_intel_overview::OverviewCapabilities {
                calls: h00ligan_engine::code_intel_domain::CapabilityCoverage {
                    capability_id: "calls".into(),
                    status: h00ligan_engine::code_intel_domain::CapabilityCoverageStatus::NotApplicable,
                    languages: vec![],
                },
                callable_liveness: h00ligan_engine::code_intel_domain::CapabilityCoverage {
                    capability_id: "callable_liveness".into(),
                    status: h00ligan_engine::code_intel_domain::CapabilityCoverageStatus::NotApplicable,
                    languages: vec![],
                },
            },
            warnings: vec![],
        }
    }

    #[test]
    fn overview_text_and_machine_result_never_present_unclassified_as_clean() {
        let overview = overview_result(
            None,
            h00ligan_engine::code_intel_overview::OverviewHealthStatus::Unclassified,
            1,
        );
        let text = render_overview_text(&overview);
        assert!(text.contains("UNCLASSIFIED"));
        assert!(text.contains("UNREACHED CALLABLES: unknown"));
        assert!(!text.contains("UNREACHED CALLABLES: 0"));

        let machine = serde_json::to_value(&overview).expect("serialize shared Overview result");
        assert_eq!(machine["unclassified_count"], serde_json::json!(1));
        assert_eq!(machine["needs_unclassified"], serde_json::json!(true));
        assert!(machine["dead_code_count"].is_null());
        assert_eq!(machine["health_status"], serde_json::json!("unclassified"));
    }

    #[test]
    fn overview_text_suppresses_or_emits_the_shared_health_value() {
        let unavailable = overview_result(
            None,
            h00ligan_engine::code_intel_overview::OverviewHealthStatus::Unavailable,
            0,
        );
        let unavailable_text = render_overview_text(&unavailable);
        assert!(unavailable_text.contains("UNREACHED CALLABLES: unknown"));
        assert!(!unavailable_text.contains("UNREACHED CALLABLES: 3"));

        let complete = overview_result(
            Some(3),
            h00ligan_engine::code_intel_overview::OverviewHealthStatus::Complete,
            0,
        );
        assert!(render_overview_text(&complete).contains("UNREACHED CALLABLES: 3"));
    }

    #[test]
    fn overview_text_defaults_to_operator_labels_not_internal_graph_ids() {
        use h00ligan_engine::code_intel_domain::{
            EcosystemId, LanguageId, ProjectUnitId, ProjectUnitKind,
        };
        use h00ligan_engine::code_intel_overview::OverviewProjectUnit;
        use h00ligan_engine::graph_overview::ProjectUnitDependency;

        let mut overview = overview_result(
            None,
            h00ligan_engine::code_intel_overview::OverviewHealthStatus::Unavailable,
            0,
        );
        let agent_id =
            ProjectUnitId::new("rust:cargo:package:crates/h00ligan-interface/Cargo.toml");
        let engine_id = ProjectUnitId::new("rust:cargo:package:crates/h00ligan-engine/Cargo.toml");
        let unit =
            |project_unit_id: ProjectUnitId, label: &str, root_path: &str| OverviewProjectUnit {
                project_unit_id,
                label: label.into(),
                language_id: LanguageId::new("rust"),
                ecosystem_id: EcosystemId::new("cargo"),
                kind: ProjectUnitKind::Package,
                root_path: root_path.into(),
                manifest_path: Some(format!("{root_path}/Cargo.toml")),
                health: None,
                top_types: None,
            };
        overview.project_units = vec![
            unit(
                agent_id.clone(),
                "h00ligan-interface",
                "crates/h00ligan-interface",
            ),
            unit(
                engine_id.clone(),
                "h00ligan-engine",
                "crates/h00ligan-engine",
            ),
        ];
        overview.project_unit_dependencies = vec![ProjectUnitDependency {
            from_project_unit_id: agent_id,
            to_project_unit_id: engine_id,
        }];

        let text = render_overview_text(&overview);
        assert!(
            text.contains("h00ligan-interface -> h00ligan-engine"),
            "dependencies should use operator-facing labels: {text}"
        );
        assert!(
            !text.contains("rust:cargo:"),
            "raw project-unit IDs belong in JSON, not the default human view: {text}"
        );
        assert!(
            !text.contains("health=unknown"),
            "one capability summary should replace repeated unknown health rows: {text}"
        );
        assert!(
            !text.contains("KEY TYPES BY FAN-IN"),
            "an unavailable empty section should not render as a blank heading: {text}"
        );
    }

    #[test]
    fn human_dead_item_leads_with_actionable_verdict_not_internal_reason_code() {
        use h00ligan_engine::code_intel_dead::{
            DeadEvidenceBasis, DeadEvidenceStatus, DeadItem, DeadItemEvidence, DeadRecommendation,
            DeadVerdict,
        };
        use h00ligan_engine::code_intel_domain::{ConfigurationId, LanguageId, ProjectUnitId};
        use h00ligan_engine::code_intel_type::StructuralSymbol;

        let item = DeadItem {
            symbol: StructuralSymbol {
                symbol_id: "sym-fixture".into(),
                name: "DeadCodeHandler".into(),
                kind: "struct".into(),
                document_path: "crates/h00ligan-interface/src/tools/composite_intel.rs".into(),
                language_id: LanguageId::new("rust"),
                project_unit_ids: vec![ProjectUnitId::new("fixture-unit")],
                configuration_id: ConfigurationId::new("structural-v2"),
                signature: "pub struct DeadCodeHandler;".into(),
                visibility: "pub".into(),
                start_byte: Some(100),
                end_byte: Some(127),
                start_line: Some(320),
                end_line: Some(320),
                source_backed: true,
            },
            callable: false,
            persisted_reachability: ReachabilityClass::Suspected,
            verdict: DeadVerdict::StructuralCandidate,
            reachable_from_retained_root: None,
            recommendation: DeadRecommendation::Review,
            evidence: DeadItemEvidence {
                status: DeadEvidenceStatus::Qualified,
                basis: DeadEvidenceBasis::PersistedStructuralReachability,
                reason_code: "structural_candidate_not_provider_reconciled".into(),
                reason: "Calls authority does not prove structural liveness".into(),
            },
        };

        let text = render_dead_item_text(&item);
        assert!(text.contains("Verdict: unknown — structural liveness is not provider-verified"));
        assert!(text.contains("File: crates/h00ligan-interface/src/tools/composite_intel.rs:321"));
        assert!(text.contains("Recommendation: review manually; do not remove"));
        assert!(text.contains("Why: qualified"));
        assert!(text.contains("non-callable symbols do not yet have provider-backed liveness"));
        assert!(
            !text.contains("structural_candidate_not_provider_reconciled"),
            "stable machine reason codes belong in JSON, not the default human answer: {text}"
        );
    }
}
