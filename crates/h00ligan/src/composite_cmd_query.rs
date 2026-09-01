//! Composite CLI commands: `status`, `find`, `deps`, `diff`, `grep_context`.
//!
//! Each command composes existing engine functions into a user-friendly
//! interface. No graph logic is duplicated — all heavy lifting delegates
//! to `h00ligan_engine` types.

use clap::Args;
use h00ligan_engine::code_intel_dependencies::{
    DEFAULT_DEPENDENCIES_PAGE_SIZE, DependenciesRequest, DependencyRelationCount,
    ExactDependenciesResult, validate_dependencies_limit, validate_dependencies_path,
};
use h00ligan_engine::code_intel_diff::{
    DEFAULT_DIFF_LIMIT, DiffRequest, ExactDiffResult, validate_diff_request,
};
use h00ligan_engine::code_intel_find::{
    DEFAULT_FIND_PAGE_SIZE, ExactFindResult, FindMode, FindRequest, MAX_FIND_PAGE_SIZE,
    validate_find_request,
};
use h00ligan_engine::code_intel_source_search::{
    DEFAULT_SOURCE_SEARCH_LIMIT, ExactSourceSearchResult, SourceSearchRequest,
    validate_source_search_request,
};
use h00ligan_engine::code_intel_status::{AvailabilityStatus, ExactStatusResult, FreshnessStatus};
#[cfg(test)]
use h00ligan_engine::graph_status::status_verdict;
use h00ligan_engine::project_binding::ProjectBinding;

use crate::error::LiganError;
use crate::graph_cmd::load_indexed_graph_snapshot;
use crate::ligan_cmd::OutputFormat;

// ============================================================================
// status — Graph Health Check
// ============================================================================

/// Arguments for `h00ligan status`.
#[derive(Args, Debug, Clone)]
pub struct StatusArgs {
    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// `h00ligan status` — graph health check.
pub async fn run_status(args: StatusArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .unwrap_or_else(|error| {
            h00ligan_interface::CodeIntelSnapshot::load_failed(error.to_string())
        });
    let result = snapshot.status_result(binding).await;

    match format {
        OutputFormat::Json => {
            crate::output::print_machine_json(&result)?;
        }
        OutputFormat::Text => {
            print!("{}", render_status_text(&result));
        }
    }

    Ok(())
}

fn render_status_text(result: &ExactStatusResult) -> String {
    use std::fmt::Write as _;

    let state = if result.availability != AvailabilityStatus::Available {
        "UNAVAILABLE"
    } else if result.action_needed {
        "ATTENTION"
    } else {
        "READY"
    };
    let mut out = String::new();
    let _ = writeln!(out, "H00LIGAN STATUS — {state}");

    let _ = writeln!(out, "\nPROJECT");
    let _ = writeln!(out, "  Root: {}", result.root.display());
    let _ = writeln!(out, "  Data: {}", result.graph_directory.display());

    let _ = writeln!(out, "\nINDEX");
    let _ = writeln!(
        out,
        "  Publication: {} · graph {}",
        result.publication_state,
        if result.graph_loaded {
            "loaded"
        } else {
            "not loaded"
        }
    );
    let freshness = match result.freshness {
        FreshnessStatus::NotEvaluated => "not evaluated",
        FreshnessStatus::Unknown => "unknown",
        FreshnessStatus::Stale => "stale",
        FreshnessStatus::Fresh => "fresh",
    };
    let _ = write!(out, "  Source freshness: {freshness}");
    if let Some(reason) = result.freshness_reason.as_deref() {
        let _ = write!(out, " — {}", freshness_reason_label(reason));
    }
    let _ = writeln!(out);
    if let Some(indexed_at) = result.indexed_at_unix_seconds {
        let _ = writeln!(out, "  Indexed: {}", format_unix_timestamp(indexed_at));
    }

    let calls = &result.capabilities.calls;
    let _ = writeln!(out, "\nCAPABILITIES");
    let _ = writeln!(out, "  Calls: {}", calls_status_label(calls));
    for language in &calls.languages {
        let _ = write!(
            out,
            "    {}: {}",
            language.language_id,
            capability_status_label(language.status)
        );
        if let Some(provider) = &language.provider_id {
            let _ = write!(out, " via {provider}");
        }
        let _ = writeln!(out);
        for gap in &language.gaps {
            if gap.reason_code != "provider_not_requested" {
                let _ = writeln!(out, "      {}: {}", gap.reason_code, gap.reason);
            }
        }
        for qualification in &language.qualifications {
            let _ = writeln!(
                out,
                "      {}: {}",
                qualification.reason_code, qualification.reason
            );
        }
    }
    let callable_liveness = &result.capabilities.callable_liveness;
    if callable_liveness.status
        != h00ligan_engine::code_intel_domain::CapabilityCoverageStatus::NotApplicable
    {
        let _ = writeln!(
            out,
            "  Callable liveness: {}",
            capability_coverage_status_label(callable_liveness.status)
        );
        for language in &callable_liveness.languages {
            let _ = write!(
                out,
                "    {}: {}",
                language.language_id,
                capability_status_label(language.status)
            );
            if let Some(provider) = &language.provider_id {
                let _ = write!(out, " via {provider}");
            }
            let _ = writeln!(out);
            for gap in &language.gaps {
                let _ = writeln!(out, "      {}: {}", gap.reason_code, gap.reason);
            }
            for qualification in &language.qualifications {
                let _ = writeln!(
                    out,
                    "      {}: {}",
                    qualification.reason_code, qualification.reason
                );
            }
        }
    }

    let _ = writeln!(out, "\nBUILD AND CLASSIFICATION");
    let _ = writeln!(out, "  CLI: {}", crate::build_identity());
    if let Some(provenance) = &result.classified_by {
        let _ = writeln!(
            out,
            "  Reachability build: {} · {} · {}{}",
            provenance.build_identity,
            provenance.prover_config,
            provenance.timestamp,
            if provenance.build_provenance_approximate {
                " · build provenance approximate"
            } else {
                ""
            }
        );
        let _ = writeln!(
            out,
            "  Classifier content: {} · exact",
            provenance.indexer_identity
        );
    } else {
        let _ = writeln!(out, "  Reachability build: not recorded");
        let _ = writeln!(out, "  Classifier content: not recorded");
    }
    match result.classification_currency.current {
        Some(true) => {
            let _ = writeln!(out, "  Classification proof: current");
        }
        Some(false) => {
            let reason = result
                .classification_currency
                .failures
                .first()
                .map_or("recorded inputs no longer match", String::as_str);
            let _ = writeln!(out, "  Classification proof: not current — {reason}");
        }
        None => {
            let reason = result
                .classification_currency
                .not_evaluated_reason
                .unwrap_or("classification provenance is unavailable");
            let _ = writeln!(out, "  Classification proof: not evaluated — {reason}");
        }
    }

    if let Some(error) = &result.load_error {
        let _ = writeln!(out, "\nLOAD ERROR\n  {error}");
    }
    if let Some(stats) = &result.stats {
        let _ = writeln!(out, "\nGRAPH");
        let _ = writeln!(
            out,
            "  {} nodes · {} edges",
            format_count(stats.node_count),
            format_count(stats.edge_count)
        );
        if let Some(reachability) = &result.reachability {
            let _ = writeln!(
                out,
                "  Reachability: {} wired · {} public API · {} structural · {} test-only",
                format_count(reachability.wired),
                format_count(reachability.public_api),
                format_count(reachability.structural),
                format_count(reachability.test_only)
            );
            if let Some(dead) = reachability.dead {
                let _ = writeln!(out, "  Dead: {}", format_count(dead));
            } else {
                let _ = writeln!(
                    out,
                    "  Dead: unknown — {}",
                    result
                        .authoritative_dead_requires
                        .as_deref()
                        .unwrap_or("authoritative classification evidence is unavailable")
                );
            }
            if reachability.unclassified > 0 {
                let _ = writeln!(
                    out,
                    "  Unclassified: {}",
                    format_count(reachability.unclassified)
                );
            }
        }
    }

    if result.index_mode.is_some() {
        let _ = writeln!(
            out,
            "\nNOTE\n  This is an incremental generation; authoritative Dead analysis requires a fresh publication."
        );
    }

    let _ = writeln!(
        out,
        "\n{}",
        if result.action_needed {
            "NEXT"
        } else {
            "READY"
        }
    );
    for sentence in result.recommendation.split(". ") {
        let sentence = sentence.trim().trim_end_matches('.');
        if !sentence.is_empty() {
            let _ = writeln!(out, "  - {sentence}.");
        }
    }
    out
}

fn calls_status_label(
    calls: &h00ligan_engine::code_intel_domain::CapabilityCoverage,
) -> &'static str {
    if !calls.languages.is_empty()
        && calls.languages.iter().all(|language| {
            !language.gaps.is_empty()
                && language
                    .gaps
                    .iter()
                    .all(|gap| gap.reason_code == "provider_not_requested")
        })
    {
        "not indexed"
    } else {
        capability_coverage_status_label(calls.status)
    }
}

const fn capability_coverage_status_label(
    status: h00ligan_engine::code_intel_domain::CapabilityCoverageStatus,
) -> &'static str {
    use h00ligan_engine::code_intel_domain::CapabilityCoverageStatus;
    match status {
        CapabilityCoverageStatus::Complete => "complete",
        CapabilityCoverageStatus::Qualified => "qualified",
        CapabilityCoverageStatus::Partial => "partial",
        CapabilityCoverageStatus::Unavailable => "unavailable",
        CapabilityCoverageStatus::NotApplicable => "not applicable",
    }
}

const fn capability_status_label(
    status: h00ligan_engine::code_intel_domain::CapabilityCoverageStatus,
) -> &'static str {
    use h00ligan_engine::code_intel_domain::CapabilityCoverageStatus;
    match status {
        CapabilityCoverageStatus::Complete => "complete",
        CapabilityCoverageStatus::Qualified => "qualified",
        CapabilityCoverageStatus::Partial => "partial",
        CapabilityCoverageStatus::Unavailable => "unavailable",
        CapabilityCoverageStatus::NotApplicable => "not applicable",
    }
}

fn freshness_reason_label(reason: &str) -> &str {
    match reason {
        "truncated" => "repository exceeds the bounded freshness scan",
        "no_source" => "no source files were found",
        "indexed_source_snapshot_unavailable" => "indexed source evidence is unavailable",
        "source_verification_failed" => "source verification failed",
        "provider_semantic_inputs_unverifiable" => "semantic provider inputs could not be verified",
        other => other,
    }
}

fn format_unix_timestamp(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0))
        .map_or_else(
            || format!("{seconds} (Unix seconds)"),
            |timestamp| timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        )
}

fn format_count(value: usize) -> String {
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
// find <query> — Unified Symbol Search
// ============================================================================

/// Arguments for `h00ligan find`.
#[derive(Args, Debug, Clone)]
pub struct FindArgs {
    /// Search query: symbol name, pattern (e.g., "*Handler"), or file path.
    /// Results include exact selectors accepted by every symbol-oriented verb.
    pub query: String,

    /// Force interpretation as symbol name (skip path detection).
    #[arg(long, conflicts_with = "path")]
    pub name: bool,

    /// Force interpretation as file path (skip name detection).
    #[arg(long, conflicts_with = "name")]
    pub path: bool,

    /// Filter by symbol kind (function, struct, enum, trait, const, module, type_alias, impl, use).
    #[arg(long)]
    pub kind: Option<String>,

    /// Exclude import/use rows so only definitions are returned.
    #[arg(long)]
    pub definitions_only: bool,

    /// Maximum results to return (default 20, max 100).
    #[arg(long, default_value_t = DEFAULT_FIND_PAGE_SIZE)]
    pub limit: usize,

    /// Continue a prior page from the exact generation and Find query.
    #[arg(long)]
    pub cursor: Option<String>,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// `h00ligan find <query>` — unified symbol search.
pub async fn run_find(args: FindArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let mode = if args.name {
        FindMode::Name
    } else if args.path {
        FindMode::Path
    } else {
        FindMode::Auto
    };
    let request = FindRequest {
        query: args.query,
        mode,
        kind: args.kind,
        definitions_only: args.definitions_only,
        limit: args.limit,
        cursor: args.cursor,
    };
    validate_find_request(&request)?;
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let result = snapshot.query_find(binding, &request).await?;

    if format == OutputFormat::Json {
        crate::output::print_machine_json(&result)?;
    } else {
        render_find(&result);
    }

    Ok(())
}

fn render_find(result: &ExactFindResult) {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = write!(
        out,
        "{}",
        find_summary(
            &result.query.value,
            result.query.mode.as_str(),
            &result.authority.status,
            result.page.total_items,
        )
    );
    let _ = writeln!(out);
    if result.items.is_empty() {
        if result.suggestions.is_empty() {
            let _ = writeln!(out, "  No matches found.");
        } else {
            let names = result
                .suggestions
                .iter()
                .map(|suggestion| format!("{} (dist={})", suggestion.name, suggestion.distance))
                .collect::<Vec<_>>();
            let _ = writeln!(
                out,
                "  No matches found. Did you mean: {}?",
                names.join(", ")
            );
        }
    } else {
        let _ = writeln!(
            out,
            "  {:<45} {:<12} {:<12} {:<8} FILE",
            "SYMBOL", "KIND", "VIS", "LINE"
        );
        let _ = writeln!(out, "  {}", "-".repeat(89));
        for item in &result.items {
            let line = item
                .start_line
                .map(|line| (line + 1).to_string())
                .unwrap_or_else(|| "?".into());
            let _ = writeln!(
                out,
                "  {:<45} {:<12} {:<12} {:<8} {}",
                truncate_str(&item.name, 45),
                item.kind,
                item.visibility,
                line,
                item.document_path,
            );
            let _ = writeln!(out, "    SELECTOR {}", item.symbol_id);
        }
    }
    if let Some(cursor) = &result.page.next_cursor {
        let _ = writeln!(
            out,
            "\n  Showing {} of {} matches (maximum page size {MAX_FIND_PAGE_SIZE}).",
            result.page.returned, result.page.total_items
        );
        let _ = writeln!(out, "  Next cursor: {cursor}");
    }
    for warning in &result.warnings {
        let _ = writeln!(out, "Note: {warning}");
    }
    print!("{out}");
}

fn find_summary(
    query: &str,
    mode: &str,
    authority: &h00ligan_engine::code_intel_domain::AuthorityStatus,
    total_items: usize,
) -> String {
    let noun = if total_items == 1 { "match" } else { "matches" };
    format!(
        "FIND \"{query}\"\n  {} {noun} | mode: {mode} | authority: {}\n",
        format_count(total_items),
        authority_status_label(authority)
    )
}

const fn authority_status_label(
    status: &h00ligan_engine::code_intel_domain::AuthorityStatus,
) -> &'static str {
    use h00ligan_engine::code_intel_domain::AuthorityStatus;
    match status {
        AuthorityStatus::Complete => "complete",
        AuthorityStatus::Qualified => "qualified",
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

fn parse_format(s: &str) -> Result<OutputFormat, LiganError> {
    s.parse::<OutputFormat>().map_err(LiganError::Config)
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        // WU-0014 L2 #17: `max.saturating_sub(3)` is an arithmetic BYTE index
        // that panics when it lands inside a multi-byte char. Walk down to the
        // nearest char boundary at or before it before slicing.
        let end = s.floor_char_boundary(max.saturating_sub(3));
        format!("{}...", &s[..end])
    }
}

// ============================================================================
// deps <path> — Dependency Analysis
// ============================================================================

/// Arguments for `h00ligan deps`.
#[derive(Args, Debug, Clone)]
pub struct DepsArgs {
    /// File or directory boundary to analyze (relative to workspace root).
    pub path: String,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Maximum related files in this page (1–100).
    #[arg(long, default_value_t = DEFAULT_DEPENDENCIES_PAGE_SIZE)]
    pub limit: usize,

    /// Continue a prior page from the exact generation and path query.
    #[arg(long)]
    pub cursor: Option<String>,
}

/// `h00ligan deps <path>` — dependency analysis.
pub async fn run_deps(args: DepsArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let limit = validate_dependencies_limit(args.limit)?;
    validate_dependencies_path(binding, &args.path)?;
    let (_graph, snapshot) = load_indexed_graph_snapshot(binding).await?;
    let result = snapshot
        .query_dependencies(
            binding,
            &DependenciesRequest {
                path: args.path,
                limit,
                cursor: args.cursor,
            },
        )
        .await?;

    match format {
        OutputFormat::Json => crate::output::print_machine_json(&result)?,
        OutputFormat::Text => print!("{}", render_dependencies_text(&result)),
    }

    Ok(())
}

fn render_dependencies_text(result: &ExactDependenciesResult) -> String {
    use std::fmt::Write as _;

    fn render_counts(counts: &[DependencyRelationCount]) -> String {
        counts
            .iter()
            .map(|count| format!("{}={}", count.kind, count.evidence_count))
            .collect::<Vec<_>>()
            .join(", ")
    }

    let mut output = String::new();
    let _ = writeln!(output, "DEPENDENCIES \"{}\"", result.scope.path);
    let _ = writeln!(output, "{}", "=".repeat(60));
    let _ = writeln!(output, "  Generation: {}", result.generation_id);
    let _ = writeln!(output, "  Authority:  {}", result.authority.status);
    let _ = writeln!(
        output,
        "  Scope:      {}; {} indexed file(s), {} symbol(s)",
        result.scope.kind, result.scope.indexed_files, result.scope.symbols
    );
    let _ = writeln!(
        output,
        "  Page:       {} returned at offset {} of {} related file(s)",
        result.page.returned, result.page.offset, result.page.total_items
    );
    if let Some(cursor) = &result.page.next_cursor {
        let _ = writeln!(output, "  Next cursor: {cursor}");
        let _ = writeln!(output, "               pass it back with --cursor");
    }

    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "  DEPENDS ON: {} observed evidence edge(s)",
        result.dependency_evidence_count
    );
    let mut dependency_files = 0usize;
    for file in &result.files {
        if file.dependencies.is_empty() {
            continue;
        }
        dependency_files += 1;
        let _ = writeln!(
            output,
            "    {:<52} — {}",
            file.file,
            render_counts(&file.dependencies)
        );
    }
    if dependency_files == 0 {
        let message = if result.dependency_evidence_count == 0 {
            "none observed"
        } else {
            "no dependency rows on this page"
        };
        let _ = writeln!(output, "    ({message})");
    }

    let _ = writeln!(output);
    let _ = writeln!(
        output,
        "  DEPENDED ON BY: {} observed evidence edge(s)",
        result.dependent_evidence_count
    );
    let mut dependent_files = 0usize;
    for file in &result.files {
        if file.dependents.is_empty() {
            continue;
        }
        dependent_files += 1;
        let _ = writeln!(
            output,
            "    {:<52} — {}",
            file.file,
            render_counts(&file.dependents)
        );
    }
    if dependent_files == 0 {
        let message = if result.dependent_evidence_count == 0 {
            "none observed"
        } else {
            "no dependent rows on this page"
        };
        let _ = writeln!(output, "    ({message})");
    }

    for warning in &result.warnings {
        let _ = writeln!(output, "  WARNING: {warning}");
    }
    output
}

// ============================================================================
// diff — Symbol-Level Change Detection
// ============================================================================

/// Arguments for `h00ligan diff`.
#[derive(Args, Debug, Clone)]
pub struct DiffArgs {
    /// File path to diff (relative to root). If omitted, diffs the entire
    /// workspace.
    pub path: Option<String>,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Maximum number of changed symbols to return (1–100).
    #[arg(long, default_value_t = DEFAULT_DIFF_LIMIT)]
    pub limit: usize,
}

/// `h00ligan diff [path]` — compare one immutable generation with live source.
pub async fn run_diff(args: DiffArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let request = DiffRequest {
        path: args.path,
        limit: args.limit,
    };
    validate_diff_request(&request)?;
    let format = parse_format(&args.format)?;
    let (_graph, snapshot) = load_indexed_graph_snapshot(binding).await?;
    let result = snapshot
        .query_diff(binding, &request)
        .await
        .map_err(LiganError::Domain)?;

    match format {
        OutputFormat::Json => crate::output::print_machine_json(&result)?,
        OutputFormat::Text => print!("{}", render_diff_text(&result)),
    }

    Ok(())
}

fn render_diff_text(result: &ExactDiffResult) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    let _ = writeln!(output, "SYMBOL DIFF {}", result.query.path);
    let _ = writeln!(output, "{}", "=".repeat(60));
    let _ = writeln!(output, "  Generation:       {}", result.generation_id);
    let _ = writeln!(output, "  Baseline:         immutable structural graph");
    let _ = writeln!(
        output,
        "  Candidate:        live worktree (per-file, non-atomic)"
    );
    let _ = writeln!(output, "  Authority:        {}", result.authority.status);
    let _ = writeln!(output, "  Verdict:          {}", result.verdict);
    let _ = writeln!(output, "  Files considered: {}", result.files_considered);
    let _ = writeln!(output, "  Files compared:   {}", result.files_compared);
    let _ = writeln!(output, "  Files excluded:   {}", result.files_excluded);
    for exclusion in &result.authority.comparison.exclusions {
        let _ = writeln!(
            output,
            "    - {}: {} file(s)",
            exclusion.reason_code, exclusion.files
        );
    }
    let _ = writeln!(
        output,
        "  Files with symbol changes: {}",
        result.files_with_symbol_changes
    );
    let _ = writeln!(
        output,
        "  Symbol changes:   +{} -{} ~{}",
        result.total_added, result.total_removed, result.total_modified
    );

    if result.files.is_empty() {
        let message = match result.verdict {
            h00ligan_engine::code_intel_diff::DiffVerdict::NoSymbolDifferences => {
                "No symbol-level differences observed."
            }
            h00ligan_engine::code_intel_diff::DiffVerdict::Unknown => {
                "No differences observed, but incomplete authority cannot prove equality."
            }
            h00ligan_engine::code_intel_diff::DiffVerdict::SymbolDifferencesObserved => {
                "Differences were observed but none fit the requested result bound."
            }
        };
        let _ = writeln!(output, "\n{message}");
    }

    for file in &result.files {
        let _ = writeln!(output, "\n  {}", file.file_path);
        for entry in &file.diff.added {
            let line = entry
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default();
            let _ = writeln!(output, "    + {} ({}){}", entry.name, entry.kind, line);
        }
        for entry in &file.diff.removed {
            let line = entry
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default();
            let _ = writeln!(output, "    - {} ({}){}", entry.name, entry.kind, line);
        }
        for entry in &file.diff.modified {
            let line = entry
                .line
                .map(|line| format!(":{line}"))
                .unwrap_or_default();
            let _ = writeln!(output, "    ~ {} ({}){}", entry.name, entry.kind, line);
        }
    }

    if result.truncated {
        let _ = writeln!(
            output,
            "\n... truncated ({}/{} symbol changes returned). Narrow path or raise --limit (maximum 100).",
            result.changes_returned, result.changes_total
        );
    }
    for warning in &result.warnings {
        let _ = writeln!(output, "\nWARNING: {warning}");
    }
    output
}

// ============================================================================
// grep_context <pattern> — Live Source Search with Generation-Bound Context
// ============================================================================

/// Arguments for `h00ligan grep_context`.
#[derive(Args, Debug, Clone)]
pub struct GrepContextArgs {
    /// Regex pattern to search for.
    pub pattern: String,

    /// File path or directory to search in (default: workspace root).
    #[arg(long)]
    pub path: Option<String>,

    /// Number of context lines around each match (0–10).
    #[arg(long, short = 'C', default_value = "0")]
    pub context_lines: usize,

    /// Maximum matches to return (1–100).
    #[arg(long, default_value_t = DEFAULT_SOURCE_SEARCH_LIMIT)]
    pub limit: usize,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// `h00ligan grep_context <pattern>` — live source search with generation-bound context.
pub async fn run_grep_context(
    args: GrepContextArgs,
    binding: &ProjectBinding,
) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let request = SourceSearchRequest {
        pattern: args.pattern,
        path: args.path.unwrap_or_else(|| ".".into()),
        context_lines: args.context_lines,
        limit: args.limit,
    };
    validate_source_search_request(&request)?;
    let (_graph, snapshot) = load_indexed_graph_snapshot(binding).await?;
    let result = snapshot.query_source_search(binding, &request).await?;

    match format {
        OutputFormat::Json => crate::output::print_machine_json(&result)?,
        OutputFormat::Text => print!("{}", render_source_search_text(&result)),
    }

    Ok(())
}

fn render_source_search_text(result: &ExactSourceSearchResult) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    let _ = writeln!(output, "SOURCE SEARCH \"{}\"", result.query.pattern);
    let _ = writeln!(output, "{}", "=".repeat(60));
    let _ = writeln!(output, "  Path:             {}", result.query.path);
    let _ = writeln!(output, "  Source authority: live worktree");
    let _ = writeln!(
        output,
        "  Graph context:    {} ({})",
        result.graph_context.coverage, result.graph_context.generation_id
    );
    let _ = writeln!(
        output,
        "  Matches:          {} returned{}",
        result.matches_returned,
        if result.truncated { " (truncated)" } else { "" }
    );
    let _ = writeln!(output);

    for record in &result.results {
        let symbol = record
            .containing_symbol
            .as_ref()
            .map_or_else(String::new, |symbol| {
                format!(
                    " [{symbol} ({})]",
                    record.symbol_kind.as_deref().unwrap_or("unknown")
                )
            });
        let qualified = if record.containing_symbol.is_none()
            && record.is_match
            && record.graph_context_status
                != h00ligan_engine::code_intel_source_search::SearchGraphContextStatus::ExactGenerationMatch
        {
            format!(" [{}]", record.graph_context_status)
        } else {
            String::new()
        };
        let prefix = if record.is_match { ':' } else { '-' };
        let line_truncated = if record.content_truncated {
            " [line truncated]"
        } else {
            ""
        };
        let _ = writeln!(
            output,
            "  {}{}{}: {}{}{}{}",
            record.file_path,
            prefix,
            record.line_number,
            record.line_text,
            symbol,
            qualified,
            line_truncated
        );
    }
    for warning in &result.warnings {
        let _ = writeln!(output, "  warning: {warning}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use h00ligan_engine::code_intel_domain::CapabilityCoverageStatus;
    use h00ligan_engine::graph_search::{glob_match, is_path_query};
    use h00ligan_engine::graph_stats::StalenessVerdict;

    #[test]
    fn glob_match_star_suffix() {
        assert!(glob_match("BlastRadiusHandler", "*Handler"));
        assert!(glob_match("FindHandler", "*Handler"));
        assert!(!glob_match("BlastRadius", "*Handler"));
    }

    #[test]
    fn glob_match_star_prefix() {
        assert!(glob_match("run_status", "run_*"));
        assert!(glob_match("run_find", "run_*"));
        assert!(!glob_match("status_run", "run_*"));
    }

    #[test]
    fn glob_match_star_both() {
        assert!(glob_match("my_status_check", "*status*"));
        assert!(glob_match("status", "*status*"));
        assert!(!glob_match("my_check", "*status*"));
    }

    #[test]
    fn glob_match_no_wildcard() {
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact_match", "exact"));
    }

    #[test]
    fn glob_match_case_insensitive() {
        assert!(glob_match("BlastRadiusHandler", "*handler"));
        assert!(glob_match("FindHandler", "*HANDLER"));
    }

    #[test]
    fn is_path_query_detection() {
        assert!(is_path_query("crates/h00ligan-engine/src/lib.rs"));
        assert!(is_path_query("src/main.rs"));
        assert!(is_path_query("lib.rs"));
        assert!(!is_path_query("BlastRadiusHandler"));
        assert!(!is_path_query("run_status"));
    }

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_long() {
        let result = truncate_str("very_long_symbol_name_that_exceeds_limit", 20);
        assert!(result.len() <= 20);
        assert!(result.ends_with("..."));
    }

    /// WU-0014 L2 #17 falsifier: truncating a multi-byte string at a `max`
    /// whose `max - 3` byte index lands inside a char must NOT panic. On HEAD,
    /// `&"日本語"[..5]` is mid-char (boundaries at 0/3/6/9) → panic.
    /// floor_char_boundary(5) == 3, so the result is "日...".
    #[test]
    fn truncate_str_multibyte_no_panic() {
        let result = truncate_str("日本語", 8);
        assert!(result.is_char_boundary(result.len()));
        assert!(result.ends_with("..."));
        assert_eq!(result, "日...");
    }

    #[test]
    fn human_find_summary_separates_match_count_from_pagination() {
        use h00ligan_engine::code_intel_domain::AuthorityStatus;

        assert_eq!(
            find_summary("DeadCodeHandler", "name", &AuthorityStatus::Qualified, 1),
            "FIND \"DeadCodeHandler\"\n  1 match | mode: name | authority: qualified\n"
        );
        assert_eq!(
            find_summary("Handler", "name", &AuthorityStatus::Complete, 1_234),
            "FIND \"Handler\"\n  1,234 matches | mode: name | authority: complete\n"
        );
    }

    #[test]
    fn human_status_separates_cli_and_engine_identity_and_withholds_false_dead_total() {
        use std::collections::BTreeMap;
        use std::path::PathBuf;

        use h00ligan_engine::code_intel_domain::{
            CapabilityCoverage, CapabilityEvidenceGap, CapabilityStatus,
            LanguageCapabilityCoverage, LanguageId, ProviderId,
        };
        use h00ligan_engine::code_intel_status::{
            PublicationState, StatusCapabilities, StatusGraphStats, StatusReachability,
        };
        use h00ligan_engine::graph_status::{
            ClassificationCurrencyStatus, ClassificationProvenance,
        };

        let mut result = ExactStatusResult {
            schema_version: h00ligan_engine::code_intel_status::STATUS_SCHEMA_VERSION.into(),
            generation_id: None,
            repository_id: None,
            publication_state: PublicationState::Published,
            graph_exists: true,
            graph_loaded: true,
            root: PathBuf::from("/workspace"),
            graph_directory: PathBuf::from("/workspace/.h00ligan/code-intel"),
            root_source: "explicit".into(),
            graph_source: "cli".into(),
            availability: AvailabilityStatus::Available,
            freshness: FreshnessStatus::Unknown,
            freshness_reason: Some("provider_semantic_inputs_unverifiable".into()),
            freshness_files_checked: Some(12),
            indexed_at_unix_seconds: Some(1_787_035_101),
            action_needed: true,
            recommendation: "Resolve structural coverage gaps.".into(),
            capabilities: StatusCapabilities {
                calls: CapabilityCoverage {
                    capability_id: "calls".into(),
                    status: CapabilityCoverageStatus::Unavailable,
                    languages: vec![LanguageCapabilityCoverage {
                        language_id: LanguageId::new("rust"),
                        status: CapabilityCoverageStatus::Unavailable,
                        provider_id: None,
                        gaps: vec![CapabilityEvidenceGap {
                            provider_id: Some(ProviderId::new("rust-analyzer-scip")),
                            status: CapabilityStatus::Unavailable,
                            reason_code: "provider_not_requested".into(),
                            reason: "semantic provider execution was not requested".into(),
                        }],
                        qualifications: Vec::new(),
                    }],
                },
                callable_liveness: CapabilityCoverage {
                    capability_id: "callable_liveness".into(),
                    status: CapabilityCoverageStatus::NotApplicable,
                    languages: Vec::new(),
                },
            },
            classified_by: Some(ClassificationProvenance {
                build_identity: "0.1.0+fixture+dirty".into(),
                indexer_identity: format!("sha256:{}", "a".repeat(64)),
                prover_config: "code-intel=1".into(),
                timestamp: "2026-08-18T00:00:00Z".into(),
                build_provenance_approximate: true,
            }),
            classification_currency: ClassificationCurrencyStatus {
                current: Some(false),
                not_evaluated_reason: None,
                failures: vec!["dirty build identities cannot certify currency".into()],
            },
            stats: Some(StatusGraphStats {
                node_count: 16_741,
                edge_count: 16_531,
                edge_kinds: BTreeMap::new(),
            }),
            reachability: Some(StatusReachability {
                wired: 5,
                public_api: 1_568,
                structural: 5_689,
                test_only: 4_605,
                dead: None,
                orphan: 0,
                unclassified: 0,
                suspected: 1_790,
                excluded: 41,
            }),
            index_mode: None,
            authoritative_dead_requires: Some("complete Calls authority is unavailable".into()),
            load_error: None,
            origin_mismatch: None,
        };

        let text = render_status_text(&result);
        assert!(text.contains(&format!("CLI: {}", crate::build_identity())));
        assert!(text.contains("Reachability build: 0.1.0+fixture+dirty"));
        assert!(text.contains("Classifier content: sha256:"));
        assert!(!text.contains("Binary:"));
        assert!(text.contains("semantic provider inputs could not be verified"));
        assert!(!text.contains("provider_semantic_inputs_unverifiable"));
        assert!(text.contains("Calls: not indexed"));
        assert!(text.contains("Dead: unknown"));
        assert!(!text.contains("Dead: 3,043"));
        assert!(text.contains("16,741 nodes · 16,531 edges"));
        assert!(!text.contains("Unix seconds"));

        let gap = result.capabilities.calls.languages[0]
            .gaps
            .first_mut()
            .expect("provider gap fixture");
        gap.reason_code = "provider_health_unresolved_imports".into();
        gap.reason = "module resolution excluded unresolved imports".into();
        let typed_failure_text = render_status_text(&result);
        assert!(typed_failure_text.contains("provider_health_unresolved_imports"));
        assert!(typed_failure_text.contains("module resolution excluded unresolved imports"));

        // Positive control for the independent classification axis: a
        // callable population can remain unclassified even when the capability
        // census incorrectly says Calls is not applicable.
        result.capabilities.calls = CapabilityCoverage {
            capability_id: "calls".into(),
            status: CapabilityCoverageStatus::NotApplicable,
            languages: Vec::new(),
        };
        let reachability = result.reachability.as_mut().expect("reachability fixture");
        reachability.dead = None;
        reachability.unclassified = 7;
        result.authoritative_dead_requires =
            Some("reachability is unclassified for 7 graph nodes".into());
        let unclassified_text = render_status_text(&result);
        assert!(unclassified_text.contains("Dead: unknown"));
        assert!(!unclassified_text.contains("Dead: 0"));
        assert!(unclassified_text.contains("Unclassified: 7"));

        result.capabilities.calls = CapabilityCoverage {
            capability_id: "calls".into(),
            status: CapabilityCoverageStatus::Complete,
            languages: vec![LanguageCapabilityCoverage {
                language_id: LanguageId::new("rust"),
                status: CapabilityCoverageStatus::Complete,
                provider_id: Some(ProviderId::new("rust-analyzer-scip")),
                gaps: Vec::new(),
                qualifications: Vec::new(),
            }],
        };
        let classified_gap_text = render_status_text(&result);
        assert!(
            classified_gap_text
                .contains("Dead: unknown — reachability is unclassified for 7 graph nodes")
        );
        assert!(!classified_gap_text.contains("complete Calls authority is unavailable"));
    }

    // =======================================================================
    // F2 (OBS-2) + F3 (OBS-1 status surface) — ADR-0029
    // =======================================================================

    use std::sync::Mutex;

    /// Serializes the cwd/HOME-mutating tests: `EngineConfig::load(None)`
    /// resolves config via `./.h00ligan/config.toml` (cwd-relative) then
    /// `$HOME/.h00ligan/config.toml` — both PROCESS-GLOBAL. Tests that redirect them
    /// must not run concurrently (with each other or the engine's own cwd test).
    static CWD_HOME_GUARD: Mutex<()> = Mutex::new(());

    /// RAII guard that redirects cwd + HOME to a tempdir and restores them on
    /// drop, so `EngineConfig::load(None)` resolves to our fixture config and
    /// nothing else on the box.
    struct CwdHomeRedirect {
        orig_cwd: std::path::PathBuf,
        orig_home: Option<std::ffi::OsString>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl CwdHomeRedirect {
        fn to(dir: &std::path::Path) -> Self {
            let lock = CWD_HOME_GUARD.lock().unwrap_or_else(|e| e.into_inner());
            let orig_cwd = std::env::current_dir().expect("get cwd");
            let orig_home = std::env::var_os("HOME");
            std::env::set_current_dir(dir).expect("set cwd");
            // Point HOME at an empty subdir so a real ~/.h00ligan/config.toml can't
            // shadow the fixture's project-local config (or its absence).
            let fake_home = dir.join("__home__");
            std::fs::create_dir_all(&fake_home).expect("mk fake home");
            unsafe {
                std::env::set_var("HOME", &fake_home);
            }
            Self {
                orig_cwd,
                orig_home,
                _lock: lock,
            }
        }
    }

    impl Drop for CwdHomeRedirect {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.orig_cwd);
            unsafe {
                match &self.orig_home {
                    Some(h) => std::env::set_var("HOME", h),
                    None => std::env::remove_var("HOME"),
                }
            }
        }
    }

    /// Write a `.h00ligan/config.toml` under the given dir.
    fn write_project_config(dir: &std::path::Path, contents: &str) {
        let config_dir = dir.join(".h00ligan");
        std::fs::create_dir_all(&config_dir).expect("mk .h00ligan");
        std::fs::write(config_dir.join("config.toml"), contents).expect("write config");
    }

    /// F2 (OBS-2): a present-but-broken config on the implicit search path
    /// surfaces an error at a WIRED site (`run_status`'s :47 config load) rather
    /// than silently using the default data path. Covers BOTH malformed TOML
    /// and a syntactically valid but unknown standalone field. MUST NOT pass
    /// `--data-dir` (apply_data_dir runs AFTER the swallow and would mask it).
    ///
    /// RED on HEAD: `EngineConfig::load(None).unwrap_or_default()` discarded the
    /// Err -> default config -> run_status returned Ok against the default store.
    #[tokio::test]
    async fn broken_config_surfaces_at_wired_obs2_site() {
        // Case 1: malformed TOML (parse failure).
        {
            let dir = tempfile::tempdir().expect("tempdir");
            write_project_config(dir.path(), "this is = = not valid toml");
            let _redirect = CwdHomeRedirect::to(dir.path());
            let result = h00ligan_engine::config::EngineConfig::load_for_root(dir.path());
            assert!(
                result.is_err(),
                "a malformed config must surface during startup binding, not silently default"
            );
        }
        // Case 2: parses as TOML but belongs to no standalone config surface.
        {
            let dir = tempfile::tempdir().expect("tempdir");
            write_project_config(dir.path(), "[llm]\ntemperature = 3.5\n");
            let _redirect = CwdHomeRedirect::to(dir.path());
            let result = h00ligan_engine::config::EngineConfig::load_for_root(dir.path());
            assert!(
                result.is_err(),
                "an unknown config field must surface during startup binding"
            );
        }
    }

    /// Table name string MUST match graph_store.rs's private `GRAPH_SNAPSHOT`
    /// const (`"graph_snapshot"`). A snapshot written here WITHOUT a
    /// `graph_meta` schema_version stamp trips load_snapshot's version-mismatch
    /// gate (stored_version = None != Some(SCHEMA_VERSION)) -> Ok(None): the
    /// "snapshot present but unloadable" producer, without touching the private
    /// consts.
    fn write_corrupt_graph_redb(path: &std::path::Path) {
        use redb::TableDefinition;
        let snapshot_table: TableDefinition<&str, &[u8]> = TableDefinition::new("graph_snapshot");
        let db = redb::Database::create(path).expect("create graph.redb");
        let txn = db.begin_write().expect("begin write");
        {
            let mut t = txn.open_table(snapshot_table).expect("open table");
            // Present snapshot bytes, no schema_version stamp -> version-mismatch
            // discard -> load_snapshot returns Ok(None).
            t.insert("latest", b"\xde\xad\xbe\xef garbage snapshot".as_slice())
                .expect("insert");
        }
        txn.commit().expect("commit");
        // Drop the handle so the file is closed for the reopen under test.
        drop(db);
    }

    /// F3 (OBS-1, case A): a `graph.redb` PRESENT whose snapshot fails to load
    /// ADR-0033 ROOT-8: a loadable store whose stamped origin differs from the
    /// query root yields the first-class "origin-mismatch" verdict (action
    /// needed, recommend reindex) — REPORTED, never refused. It outranks mere
    /// staleness but ranks below load-failed. RED on HEAD: `origin_mismatch` was
    /// not an input and a foreign-origin store read "fresh".
    #[test]
    fn status_verdict_reports_origin_mismatch_first_class() {
        // origin_mismatch=true on an otherwise-fresh, Sufficient-coverage store.
        let v = status_verdict(
            true,
            false,
            true,
            StalenessVerdict::Fresh,
            CapabilityCoverageStatus::Complete,
        );
        assert_eq!(v.availability_label, "origin-mismatch");
        assert_eq!(v.freshness_label, "not-evaluated");
        assert!(v.action_needed, "an origin mismatch must require action");
        assert!(
            v.recommendation.contains("different workspace"),
            "the recommendation must name the foreign-workspace cause; got: {}",
            v.recommendation
        );
        assert_ne!(
            v.recommendation, "Index is fresh. No action needed.",
            "a foreign-origin store must NOT be reported fresh"
        );

        // Precedence: load_failed outranks origin_mismatch.
        let v = status_verdict(
            true,
            true,
            true,
            StalenessVerdict::Fresh,
            CapabilityCoverageStatus::Complete,
        );
        assert_eq!(v.availability_label, "load-failed");

        // A matching origin (origin_mismatch=false) on a fresh+covered store stays fresh.
        let v = status_verdict(
            true,
            false,
            false,
            StalenessVerdict::Fresh,
            CapabilityCoverageStatus::Complete,
        );
        assert_eq!(v.availability_label, "available");
        assert_eq!(v.freshness_label, "fresh");
        assert!(!v.action_needed);
    }

    /// Root-level legacy graph files are not publication controls. Even a
    /// corrupt one must stay outside semantic status authority.
    #[tokio::test]
    async fn run_status_ignores_corrupt_unpublished_legacy_graph() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("mk data dir");
        let graph_db = data_dir.join("graph.redb");
        write_corrupt_graph_redb(&graph_db);

        let binding = ProjectBinding::explicit(dir.path(), &data_dir).unwrap();
        let snapshot = h00ligan_interface::CodeIntelSnapshot::load(&binding)
            .await
            .expect("legacy bytes are an unpublished state, not semantic input");
        assert!(
            matches!(
                snapshot.load_state,
                h00ligan_interface::GraphLoadState::Unindexed
            ),
            "an unpublished legacy file must not become a failed or loaded generation"
        );
        assert!(snapshot.graph.is_none());
        assert!(snapshot.immutable_generation().is_none());

        // The shipped adapter remains total and reports the unpublished state.
        let args = StatusArgs {
            format: "json".to_string(),
        };
        let result = run_status(args, &binding).await;
        assert!(
            result.is_ok(),
            "run_status must ignore corrupt unpublished legacy bytes"
        );
    }
}
