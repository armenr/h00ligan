//! CLI commands that expose h00ligan code-intelligence tools directly.
//!
//! These are top-level commands (e.g. `h00ligan type`, `h00ligan calls`) that bypass
//! the agent layer and give CLI users direct access to the knowledge graph.

use std::collections::HashMap;

use clap::Args;

use h00ligan_engine::code_intel_domain::{
    AuthorityStatus, CallerFilter, CallsRequest, DEFAULT_CALLS_PAGE_SIZE, DEFAULT_TYPE_PAGE_SIZE,
    TypeRequest,
};
use h00ligan_engine::code_intel_read::{DEFAULT_READ_PAGE_SIZE, ExactReadResult, ReadRequest};
use h00ligan_engine::code_intel_type::{ExactTypeResult, TypeMemberRole};
use h00ligan_engine::graph::{EdgeKind, GraphNode, KnowledgeGraph};
use h00ligan_engine::graph_query::{
    is_dependency_edge, is_top_level_kind, reachability_label, resolve_unique, reverse_bfs,
    short_name,
};
use h00ligan_engine::project_binding::ProjectBinding;
use h00ligan_engine::reachability::ReachabilityClass;

use crate::composite_cmd::{ambiguous_symbol_error, cli_file_locality, symbol_not_found_error};
use crate::error::LiganError;
use crate::graph_cmd::{load_or_scan_graph, truncate_symbol};

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// Output format for all ligan commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            other => Err(format!(
                "unknown format '{other}', expected 'text' or 'json'"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// 1. h00ligan type <symbol>
// ---------------------------------------------------------------------------

/// Show complete type structure (fields, methods, impls, trait implementations).
#[derive(Args, Debug, Clone)]
pub struct TypeArgs {
    /// Type name, or an exact symbol_id returned by find.
    pub symbol: String,

    /// Optional repo-relative file path to disambiguate a homonym (same-file >
    /// same-crate). Use the path shown in parentheses for each ambiguous candidate.
    #[arg(long)]
    pub file: Option<String>,

    /// Output format.
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Maximum structural members in this page (1–100).
    #[arg(long, default_value_t = DEFAULT_TYPE_PAGE_SIZE)]
    pub limit: usize,

    /// Continue a prior page from the exact generation and Type query.
    #[arg(long)]
    pub cursor: Option<String>,
}

/// `h00ligan type <symbol>` — show complete type structure.
pub async fn run_type(args: TypeArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let request = TypeRequest {
        symbol: args.symbol,
        file: args.file,
        limit: args.limit,
        cursor: args.cursor,
    };
    let result = match snapshot.query_type(binding, &request).await {
        Ok(result) => result,
        Err(error) => {
            if format == OutputFormat::Json {
                let envelope = serde_json::to_string_pretty(&error.envelope())
                    .map_err(|serialize| LiganError::Config(serialize.to_string()))?;
                println!("{envelope}");
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
        return Ok(());
    }

    render_type(&result);
    Ok(())
}

fn render_type(result: &ExactTypeResult) {
    println!(
        "TYPE: {} ({})",
        result.resolved_type.name, result.resolved_type.kind
    );
    println!("FILE: {}", result.resolved_type.document_path);
    println!(
        "AUTHORITY: {:?} {} ({})",
        result.authority.status, result.capability, result.authority.provider_id
    );
    println!(
        "PAGE: offset {}, returned {}, total {}",
        result.page.offset, result.page.returned, result.page.total_items
    );

    let mut prior_role = None;
    for item in &result.items {
        if prior_role != Some(item.role) {
            println!("\n{}:", type_role_heading(item.role));
            prior_role = Some(item.role);
        }
        let symbol = &item.symbol;
        let display = if symbol.signature.is_empty() {
            short_name(&symbol.name).to_string()
        } else {
            symbol.signature.clone()
        };
        let line = symbol
            .start_line
            .map(|line| format!(":{}", line + 1))
            .unwrap_or_default();
        println!("  {display} ({}{line})", symbol.document_path);
    }

    if result.items.is_empty() {
        println!("\nNo structural members in this type.");
    }
    if let Some(cursor) = &result.page.next_cursor {
        println!("\nNEXT CURSOR: {cursor}");
    }
    for warning in &result.warnings {
        eprintln!("WARNING: {warning}");
    }
}

const fn type_role_heading(role: TypeMemberRole) -> &'static str {
    match role {
        TypeMemberRole::Field => "FIELDS",
        TypeMemberRole::FieldTypeReference => "FIELD TYPE REFERENCES",
        TypeMemberRole::Variant => "VARIANTS",
        TypeMemberRole::PublicMethod => "PUBLIC METHODS",
        TypeMemberRole::PrivateMethod => "PRIVATE METHODS",
        TypeMemberRole::RequiredMethod => "REQUIRED METHODS",
        TypeMemberRole::ProvidedMethod => "PROVIDED METHODS",
        TypeMemberRole::ImplementationBlock => "IMPLEMENTATION BLOCKS",
        TypeMemberRole::ImplementedTrait => "IMPLEMENTED TRAITS",
        TypeMemberRole::Implementor => "IMPLEMENTORS",
    }
}

// ---------------------------------------------------------------------------
// 2. h00ligan symbol read <name>
// ---------------------------------------------------------------------------

/// Top-level `h00ligan symbol` subcommand group.
#[derive(Args, Debug, Clone)]
pub struct SymbolArgs {
    #[command(subcommand)]
    pub command: SymbolSubcommand,
}

/// Subcommands under `h00ligan symbol`.
#[derive(clap::Subcommand, Debug, Clone)]
pub enum SymbolSubcommand {
    /// Read a function or type body by name via the knowledge graph.
    Read(ReadSymbolArgs),
}

/// Arguments for `h00ligan symbol read`.
#[derive(Args, Debug, Clone)]
pub struct ReadSymbolArgs {
    /// Symbol name, or an exact symbol_id returned by find.
    pub name: String,

    /// Optional exact repo-relative file path. No cross-file fallback is used.
    #[arg(long)]
    pub file: Option<String>,

    /// Maximum Unicode source characters in this page (1–20000).
    #[arg(long, default_value_t = DEFAULT_READ_PAGE_SIZE)]
    pub limit: usize,

    /// Continue a prior page from the exact generation and Read query.
    #[arg(long)]
    pub cursor: Option<String>,

    /// Output format.
    #[arg(long, default_value = "text")]
    pub format: String,
}

/// Dispatch `h00ligan symbol` subcommands.
pub async fn run_symbol(args: SymbolArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    match args.command {
        SymbolSubcommand::Read(read_args) => run_read_symbol(read_args, binding).await,
    }
}

/// `h00ligan symbol read <name>` — read function/type body by name.
pub async fn run_read_symbol(
    args: ReadSymbolArgs,
    binding: &ProjectBinding,
) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let request = ReadRequest {
        symbol: args.name,
        file: args.file,
        limit: args.limit,
        cursor: args.cursor,
    };
    if let Err(error) = h00ligan_engine::code_intel_read::validate_read_request(&request) {
        if format == OutputFormat::Json {
            let envelope = serde_json::to_string_pretty(&error.envelope())
                .map_err(|serialize| LiganError::Config(serialize.to_string()))?;
            println!("{envelope}");
        }
        return Err(error.into());
    }
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let result = match snapshot.query_read(binding, &request).await {
        Ok(result) => result,
        Err(error) => {
            if format == OutputFormat::Json {
                let envelope = serde_json::to_string_pretty(&error.envelope())
                    .map_err(|serialize| LiganError::Config(serialize.to_string()))?;
                println!("{envelope}");
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
        return Ok(());
    }

    render_read(&result);
    Ok(())
}

fn render_read(result: &ExactReadResult) {
    use std::fmt::Write as _;

    let symbol = &result.resolved_symbol;
    let start_line = symbol.definition_span.start_line + 1;
    let end_line = symbol.definition_span.end_line + 1;
    let location = if start_line == end_line {
        format!("{}:{start_line}", symbol.document_path)
    } else {
        format!("{}:{start_line}–{end_line}", symbol.document_path)
    };
    let mut out = String::new();
    let _ = writeln!(out, "READ {}", symbol.name);
    let _ = writeln!(out, "  {} · {location}", symbol.kind);
    let _ = writeln!(
        out,
        "  Authority: {}",
        match result.authority.status {
            AuthorityStatus::Complete => "complete",
            AuthorityStatus::Qualified => "qualified",
        }
    );
    if result.page.offset > 0 || result.page.has_more {
        let _ = writeln!(
            out,
            "  Source page: characters {}..{} of {}",
            result.page.offset,
            result.page.offset + result.page.returned,
            result.page.total_items,
        );
    }
    let _ = writeln!(out);
    for (index, line) in result.source.lines().enumerate() {
        let _ = writeln!(
            out,
            "{:>5} | {}",
            result.source_span.start_line + index + 1,
            line
        );
    }
    if let Some(cursor) = &result.page.next_cursor {
        let _ = writeln!(out, "\nNext cursor: {cursor}");
    }
    for warning in &result.warnings {
        let _ = writeln!(out, "Note: {warning}");
    }
    print!("{out}");
}

// ---------------------------------------------------------------------------
// 3. h00ligan symbols [path]
// ---------------------------------------------------------------------------

/// List top-level symbols in a file or directory.
#[derive(Args, Debug, Clone)]
pub struct SymbolsArgs {
    /// File or directory path (relative to root).
    pub path: String,

    /// Output format.
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Include DEAD symbols in output.
    #[arg(long)]
    pub include_dead: bool,

    /// Directory recursion depth (default: 1, max: 3).
    #[arg(long, default_value = "1")]
    pub depth: usize,
}

/// `h00ligan symbols [path]` — list top-level symbols in file/directory.
pub async fn run_symbols_overview(
    args: SymbolsArgs,
    binding: &ProjectBinding,
) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let graph = load_or_scan_graph(binding).await?;
    let depth = args.depth.min(3);

    // Registry-keyed file detection (WU-0024 review drain, lens1-NB1/lens2-D1:
    // the FOURTH un-migrated `.rs`-only router — a `.go` file path fell to the
    // directory branch and rendered a confident-empty "No symbols found").
    let is_file = h00ligan_engine::graph_search::is_source_file_query(&args.path);

    if is_file {
        run_symbols_file(&graph, &args.path, format, args.include_dead)
    } else {
        run_symbols_dir(&graph, &args.path, depth, format, args.include_dead)
    }
}

fn run_symbols_file(
    graph: &KnowledgeGraph,
    path: &str,
    format: OutputFormat,
    include_dead: bool,
) -> Result<(), LiganError> {
    let mut nodes: Vec<&GraphNode> = graph
        .nodes_for_file(path)
        .into_iter()
        .filter(|n| is_top_level_kind(&n.kind))
        .collect();

    if nodes.is_empty() {
        eprintln!("No symbols found in '{}'. File may not be indexed.", path);
        return Ok(());
    }

    nodes.sort_by_key(|n| n.line_start.unwrap_or(usize::MAX));

    let hidden_dead = if !include_dead {
        let before = nodes.len();
        nodes.retain(|n| {
            !matches!(
                n.reachability_class,
                ReachabilityClass::Dead | ReachabilityClass::Orphan
            )
        });
        before - nodes.len()
    } else {
        0
    };

    if format == OutputFormat::Json {
        let symbols_json: Vec<serde_json::Value> = nodes
            .iter()
            .map(|n| {
                let sig = if n.signature.is_empty() {
                    format!("{} {}", n.kind, short_name(&n.symbol_name))
                } else {
                    n.signature.clone()
                };
                serde_json::json!({
                    "name": n.symbol_name,
                    "kind": n.kind,
                    "reachability": reachability_label(n.reachability_class),
                    "line_start": n.line_start.map(|l| l + 1),
                    "line_end": n.line_end.map(|l| l + 1),
                    "signature": sig,
                })
            })
            .collect();
        let mut result = serde_json::json!({
            "path": path,
            "symbol_count": symbols_json.len(),
            "symbols": symbols_json,
        });
        if hidden_dead > 0 {
            result["hidden_dead"] = serde_json::json!(hidden_dead);
            result["note"] =
                serde_json::json!("DEAD symbols hidden by default. Use --include-dead to show.");
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }

    // Text output.
    if hidden_dead > 0 {
        println!(
            "SYMBOLS in {}  ({} top-level, {} DEAD hidden — use --include-dead to show):",
            path,
            nodes.len(),
            hidden_dead
        );
    } else {
        println!("SYMBOLS in {}  ({} top-level):", path, nodes.len());
    }
    println!();
    println!(
        "  {:<45} {:<12} {:<12} {:<10}",
        "SYMBOL", "KIND", "REACH", "LINES"
    );
    println!("  {}", "-".repeat(80));
    for n in &nodes {
        let lines = match (n.line_start, n.line_end) {
            (Some(s), Some(e)) => format!("{}–{}", s + 1, e + 1),
            _ => "?".to_string(),
        };
        println!(
            "  {:<45} {:<12} {:<12} {:<10}",
            truncate_symbol(&n.symbol_name, 45),
            n.kind,
            reachability_label(n.reachability_class),
            lines,
        );
    }

    Ok(())
}

fn run_symbols_dir(
    graph: &KnowledgeGraph,
    path: &str,
    depth: usize,
    format: OutputFormat,
    include_dead: bool,
) -> Result<(), LiganError> {
    let prefix = if path.ends_with('/') {
        path.to_string()
    } else {
        format!("{path}/")
    };

    let all_files = graph.nodes_for_directory(&prefix);

    if all_files.is_empty() {
        eprintln!("No indexed symbols found under '{}'.", path);
        return Ok(());
    }

    // Filter by depth.
    let mut file_entries: Vec<(&str, Vec<&GraphNode>)> = all_files
        .into_iter()
        .filter(|(file_path, _)| {
            let remainder = &file_path[prefix.len()..];
            let extra_slashes = remainder.matches('/').count();
            extra_slashes < depth
        })
        .map(|(fp, nodes)| {
            let top_level: Vec<&GraphNode> = nodes
                .into_iter()
                .filter(|n| is_top_level_kind(&n.kind))
                .filter(|n| {
                    include_dead
                        || !matches!(
                            n.reachability_class,
                            ReachabilityClass::Dead | ReachabilityClass::Orphan
                        )
                })
                .collect();
            (fp, top_level)
        })
        .filter(|(_, nodes)| !nodes.is_empty())
        .collect();

    file_entries.sort_by_key(|b| std::cmp::Reverse(b.1.len()));

    if format == OutputFormat::Json {
        let files_json: Vec<serde_json::Value> = file_entries
            .iter()
            .map(|(fp, nodes)| {
                let syms: Vec<serde_json::Value> = nodes
                    .iter()
                    .map(|n| {
                        serde_json::json!({
                            "name": n.symbol_name,
                            "kind": n.kind,
                            "reachability": reachability_label(n.reachability_class),
                        })
                    })
                    .collect();
                serde_json::json!({
                    "file": fp,
                    "symbol_count": syms.len(),
                    "symbols": syms,
                })
            })
            .collect();
        let result = serde_json::json!({
            "path": path,
            "file_count": file_entries.len(),
            "files": files_json,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }

    // Text output.
    let total_symbols: usize = file_entries.iter().map(|(_, n)| n.len()).sum();
    println!(
        "SYMBOLS under {}  ({} files, {} top-level symbols):",
        path,
        file_entries.len(),
        total_symbols
    );
    println!();

    for (fp, nodes) in file_entries.iter().take(30) {
        println!("  {} ({} symbols):", fp, nodes.len());
        for n in nodes.iter().take(15) {
            println!(
                "    {:<40} {:<12} {}",
                truncate_symbol(&n.symbol_name, 40),
                n.kind,
                reachability_label(n.reachability_class),
            );
        }
        if nodes.len() > 15 {
            println!("    ... and {} more", nodes.len() - 15);
        }
    }
    if file_entries.len() > 30 {
        println!("  ... and {} more files", file_entries.len() - 30);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 5. h00ligan calls <symbol>
// ---------------------------------------------------------------------------

/// Find semantic callers of a symbol from the published provider evidence.
#[derive(Args, Debug, Clone)]
pub struct CallsArgs {
    /// Symbol name, or an exact symbol_id returned by find.
    pub symbol: String,

    /// Optional repo-relative file path to disambiguate a homonym (same-file >
    /// same-crate). Use the path shown in parentheses for each ambiguous candidate.
    #[arg(long)]
    pub file: Option<String>,

    /// Output format.
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Caller population: live, all, dead, or test_only.
    #[arg(long, default_value = "live")]
    pub filter: CallerFilter,

    /// Maximum call sites in this page (1–100).
    #[arg(long, default_value_t = DEFAULT_CALLS_PAGE_SIZE)]
    pub limit: usize,

    /// Continue a prior page from the exact generation and query that issued it.
    #[arg(long)]
    pub cursor: Option<String>,
}

/// `h00ligan calls <symbol>` — find call sites with source context.
pub async fn run_call_sites(args: CallsArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(error.to_string()))?;
    let request = CallsRequest {
        symbol: args.symbol,
        file: args.file,
        filter: args.filter,
        limit: args.limit,
        cursor: args.cursor,
    };
    let result = match snapshot.query_calls(binding, &request).await {
        Ok(result) => result,
        Err(error) => {
            if format == OutputFormat::Json {
                let envelope = serde_json::to_string_pretty(&error.envelope())
                    .map_err(|serialize| LiganError::Config(serialize.to_string()))?;
                println!("{envelope}");
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
        return Ok(());
    }

    println!("CALLS TO {}", result.resolved_symbol.name);
    println!(
        "  {} caller references across {} callers; authority: {:?} ({})",
        result.page.total_items,
        result.total_callers,
        result.authority.status,
        result.authority.provider_id,
    );
    println!("  Population: {}", result.authority.population);
    if result.callable_value_bindings > 0 {
        println!(
            "  Qualified dispatch evidence: {} callable-value binding{} (not direct calls)",
            result.callable_value_bindings,
            if result.callable_value_bindings == 1 {
                ""
            } else {
                "s"
            }
        );
    }
    println!(
        "  Page: offset {}, returned {}, limit {}",
        result.page.offset, result.page.returned, result.page.limit
    );
    println!();

    if result.items.is_empty() {
        match result.authority.status {
            AuthorityStatus::Complete => {
                println!(
                    "  No caller references in the complete {} population.",
                    result.authority.population
                );
            }
            AuthorityStatus::Qualified => {
                println!(
                    "  No caller references in covered source; excluded regions may contain additional callers."
                );
            }
        }
    }
    for (index, item) in result.items.iter().enumerate() {
        let location = format!(
            "{}:{}",
            item.caller.document_path,
            item.call_span.start_line + 1
        );
        println!(
            "{}. {} ({location})",
            result.page.offset + index + 1,
            item.caller.name,
        );
        for line in item.context.lines() {
            println!("   {line}");
        }
        println!();
    }
    if let Some(cursor) = &result.page.next_cursor {
        println!("NEXT CURSOR: {cursor}");
    }
    for warning in &result.warnings {
        eprintln!("WARNING: {warning}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 6. h00ligan impact <symbol>
// ---------------------------------------------------------------------------

/// Impact analysis: downstream dependents via reverse BFS, affected tests, risk assessment.
#[derive(Args, Debug, Clone)]
pub struct ImpactArgs {
    /// Symbol to analyze downstream impact for.
    pub symbol: String,

    /// Optional repo-relative file path to disambiguate a homonym (same-file >
    /// same-crate). Use the path shown in parentheses for each ambiguous candidate.
    #[arg(long)]
    pub file: Option<String>,

    /// Output format.
    #[arg(long, default_value = "text")]
    pub format: String,

    /// Max reverse-BFS depth for downstream dependents (default: 3, max: 5).
    #[arg(long, default_value = "3")]
    pub depth: usize,

    /// Include DEAD symbols in output.
    #[arg(long)]
    pub include_dead: bool,
}

/// `h00ligan impact <symbol>` — reverse impact analysis (downstream dependents).
pub async fn run_impact(args: ImpactArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    let format = parse_format(&args.format)?;
    let max_depth = args.depth.min(5);
    let graph = load_or_scan_graph(binding).await?;

    // EP1 (ADR-0027): resolve to a unique id; Ambiguous → F8, NotFound → F1
    // with Levenshtein candidates. Only the id is used downstream.
    // OQ-READVERB-FILE-DISAMBIGUATOR: optional --file same-file/same-crate locality.
    let root_id = match resolve_unique(
        &graph,
        &args.symbol,
        cli_file_locality(args.file.as_deref(), binding.root()),
    )
    .unique_or_report()
    {
        Ok(id) => id.uuid(),
        Err(amb) if amb.candidates.is_empty() => {
            return Err(symbol_not_found_error(&graph, &args.symbol));
        }
        Err(amb) => return Err(ambiguous_symbol_error(&args.symbol, &amb.candidates)),
    };

    // Reverse impact: follow INCOMING dependency edges to find dependents.
    // Edges point from user to definition (e.g. Caller --Calls--> Callee),
    // so the incoming side yields the callers — the symbols that would be
    // affected if the target changes.
    //
    // WU-0003 / CL-REACH RC2: routes through the shared `reverse_bfs` core (the
    // `dependents` preset), DELETING the hand-rolled traversal loop. The core
    // adds edge-driven trait↔impl bridging (CL-REACH-05) for free, so impact
    // now crosses dispatch boundaries. `filter = None` returns every dependent;
    // the `--include-dead` Dead/Orphan exclusion is applied below on the OUTPUT,
    // exactly preserving the prior None-is-kept semantics (an `Unclassified`
    // node is never folded into Dead).
    let root_node = graph
        .node(&root_id)
        .ok_or_else(|| {
            LiganError::Config(format!(
                "symbol '{}' resolved but no node found",
                args.symbol
            ))
        })?
        .clone();
    let bfs = reverse_bfs(&graph, &root_node, max_depth, None);
    let test_files = bfs.test_files;

    let mut affected: Vec<(GraphNode, EdgeKind, usize, f32)> = bfs
        .dependents
        .into_iter()
        .filter(|entry| {
            args.include_dead
                || !matches!(
                    entry.node.reachability_class,
                    ReachabilityClass::Dead | ReachabilityClass::Orphan
                )
        })
        .map(|entry| (entry.node, entry.edge_kind, entry.depth, entry.confidence))
        .collect();
    affected.sort_by_key(|(_, _, depth, _)| *depth);

    let mut file_counts: HashMap<String, usize> = HashMap::new();
    for (node, _, _, _) in &affected {
        *file_counts.entry(node.file_path.clone()).or_insert(0) += 1;
    }

    // Risk computation.
    let fan_in = graph
        .incoming_neighbors(&root_id)
        .iter()
        .filter(|(_, e)| is_dependency_edge(e.kind))
        .count();

    let max_affected_depth = affected.iter().map(|(_, _, d, _)| *d).max().unwrap_or(0);

    let risk = if fan_in >= 5 && max_affected_depth >= 2 {
        "HIGH"
    } else if fan_in >= 3 || max_affected_depth >= 2 {
        "MEDIUM"
    } else {
        "LOW"
    };

    let total_test_functions: usize = test_files.values().sum();

    if format == OutputFormat::Json {
        let affected_json: Vec<serde_json::Value> = affected
            .iter()
            .take(30)
            .map(|(node, edge_kind, depth, confidence)| {
                serde_json::json!({
                    "symbol_name": node.symbol_name,
                    "file_path": node.file_path,
                    "kind": node.kind,
                    "edge_kind": format!("{edge_kind:?}"),
                    "depth": depth,
                    "confidence": confidence,
                    "reachability": reachability_label(node.reachability_class),
                })
            })
            .collect();
        let test_files_json: Vec<serde_json::Value> = test_files
            .iter()
            .map(|(path, count)| {
                serde_json::json!({
                    "file": path,
                    "test_function_count": count,
                })
            })
            .collect();
        let result = serde_json::json!({
            "symbol": args.symbol,
            "total_downstream": affected.len(),
            "affected": affected_json,
            "test_files": test_files_json,
            "risk": {
                "level": risk,
                "fan_in": fan_in,
                "max_depth": max_affected_depth,
                "files_affected": file_counts.len(),
                "test_file_count": test_files.len(),
                "test_function_count": total_test_functions,
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&result).unwrap_or_default()
        );
        return Ok(());
    }

    // Text output.
    println!("IMPACT ANALYSIS: {}", args.symbol);
    println!("DIRECTION: reverse (downstream dependents via incoming edges)");
    println!();

    // Group affected by depth.
    println!("DOWNSTREAM DEPENDENTS ({}):", affected.len());
    let mut current_depth = 0;
    for (node, edge_kind, depth, _confidence) in affected.iter().take(30) {
        if *depth != current_depth {
            current_depth = *depth;
            println!("  depth {}:", current_depth);
        }
        let reach = reachability_label(node.reachability_class);
        println!(
            "    {:<35} {:<50} {:?}    [{}]",
            truncate_symbol(&node.symbol_name, 35),
            truncate_symbol(&node.file_path, 50),
            edge_kind,
            reach
        );
    }
    if affected.len() > 30 {
        println!("    ... {} more", affected.len() - 30);
    }

    // Affected test files.
    println!("\nAFFECTED TEST FILES ({}):", test_files.len());
    for (path, count) in &test_files {
        println!("  {}   ({} test functions)", path, count);
    }

    // Risk assessment.
    println!("\nRISK ASSESSMENT:");
    println!("  files_affected: {}", file_counts.len());
    println!("  wired_callers: {}", fan_in);
    println!(
        "  test_coverage: {} test files, {} test functions",
        test_files.len(),
        total_test_functions
    );
    println!("  risk: {}", risk);

    // Suggested test command.
    if !test_files.is_empty() {
        let crate_name = affected
            .first()
            .and_then(|(node, _, _, _)| crate_name_from_path(&node.file_path))
            .or_else(|| {
                test_files
                    .keys()
                    .next()
                    .and_then(|p| crate_name_from_path(p))
            })
            .unwrap_or("h00ligan-engine");

        let test_keywords: Vec<String> = test_files
            .keys()
            .map(|p| {
                p.rsplit('/')
                    .next()
                    .unwrap_or(p)
                    .trim_end_matches(".rs")
                    .trim_end_matches("_test")
                    .to_string()
            })
            .collect();

        println!(
            "\nSUGGESTED TEST COMMAND:\n  cargo test -p {} -- {}",
            crate_name,
            test_keywords.join(" ")
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Shared helpers (private to this module)
// ---------------------------------------------------------------------------

/// Parse output format from string.
fn parse_format(s: &str) -> Result<OutputFormat, LiganError> {
    s.parse::<OutputFormat>().map_err(LiganError::Config)
}

/// Extract crate name from a file path like `crates/h00ligan-interface/src/tools/foo.rs`.
fn crate_name_from_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("crates/")?;
    rest.split('/').next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashSet, VecDeque};

    use h00ligan_engine::code_intel_domain::{ProjectInventory, ProjectInventoryCoverage};
    use h00ligan_engine::code_intel_publication::{GenerationDraft, SemanticPublisher};
    use h00ligan_engine::graph::{GraphEdge, GraphNode, KnowledgeGraph};
    use h00ligan_engine::graph_store::{GraphGenerationMetadata, GraphStore};
    use h00ligan_engine::reachability::ReachabilityClass;
    use uuid::Uuid;

    fn make_node(name: &str, kind: &str, file: &str) -> GraphNode {
        GraphNode {
            memory_id: Uuid::new_v4(),
            symbol_name: name.into(),
            kind: kind.into(),
            file_path: file.into(),
            content_hash: "abc123".into(),
            signature: String::new(),
            reachability_class: ReachabilityClass::Wired,
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

    fn typeof_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::TypeOf,
            confidence: 0.9,
            ..GraphEdge::default()
        }
    }

    fn calls_edge() -> GraphEdge {
        GraphEdge {
            kind: EdgeKind::Calls,
            confidence: 0.9,
            ..GraphEdge::default()
        }
    }

    /// Regression test: a type with many incoming TypeOf edges and zero outgoing
    /// edges must produce downstream dependents when traversing incoming edges.
    ///
    /// Before the fix, `run_impact` followed outgoing edges (`graph.neighbors`),
    /// which returned 0 for types like DecayFunction that have no outgoing
    /// dependency edges. The fix uses `incoming_neighbors` so that "things that
    /// depend on me" are discovered correctly.
    ///
    /// This test exercises the same BFS loop that `run_impact` uses, directly
    /// on a constructed KnowledgeGraph.
    #[test]
    fn impact_typeof_incoming_regression() {
        // Model: DecayFunction is an enum. Three functions reference it via TypeOf.
        // Edge direction: user --TypeOf--> DecayFunction.
        // incoming_neighbors(DecayFunction) should find all three users.
        let mut graph = KnowledgeGraph::new();
        let decay_fn = make_node(
            "DecayFunction",
            "Enum",
            "crates/h00ligan-engine/src/decay.rs",
        );
        let user_a = make_node(
            "apply_decay",
            "Function",
            "crates/h00ligan-engine/src/decay.rs",
        );
        let user_b = make_node(
            "parse_decay",
            "Function",
            "crates/h00ligan-engine/src/config.rs",
        );
        let user_c = make_node(
            "test_decay",
            "Function",
            "crates/h00ligan-engine/tests/decay_test.rs",
        );

        let decay_id = decay_fn.memory_id;
        let a_id = user_a.memory_id;
        let b_id = user_b.memory_id;
        let c_id = user_c.memory_id;

        graph.add_node(decay_fn).expect("add DecayFunction");
        graph.add_node(user_a).expect("add user_a");
        graph.add_node(user_b).expect("add user_b");
        graph.add_node(user_c).expect("add user_c");

        // All three reference DecayFunction via TypeOf (incoming to DecayFunction)
        graph
            .add_edge(a_id, decay_id, typeof_edge())
            .expect("edge a");
        graph
            .add_edge(b_id, decay_id, typeof_edge())
            .expect("edge b");
        graph
            .add_edge(c_id, decay_id, typeof_edge())
            .expect("edge c");

        // Run the same BFS that run_impact uses: incoming_neighbors + is_dependency_edge.
        let max_depth: usize = 3;
        let mut visited: HashSet<Uuid> = HashSet::new();
        let mut queue: VecDeque<(Uuid, usize)> = VecDeque::new();

        visited.insert(decay_id);
        queue.push_back((decay_id, 0));

        let mut affected: Vec<(GraphNode, EdgeKind, usize)> = Vec::new();

        while let Some((current_id, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            for (neighbor_id, edge) in graph.incoming_neighbors(&current_id) {
                if !is_dependency_edge(edge.kind) {
                    continue;
                }
                if visited.contains(&neighbor_id) {
                    continue;
                }
                visited.insert(neighbor_id);
                if let Some(node) = graph.node(&neighbor_id) {
                    queue.push_back((neighbor_id, depth + 1));
                    affected.push((node.clone(), edge.kind, depth + 1));
                }
            }
        }

        assert_eq!(
            affected.len(),
            3,
            "should find 3 dependents via incoming TypeOf edges, got {}",
            affected.len()
        );

        let names: Vec<&str> = affected
            .iter()
            .map(|(n, _, _)| n.symbol_name.as_str())
            .collect();
        assert!(names.contains(&"apply_decay"), "missing apply_decay");
        assert!(names.contains(&"parse_decay"), "missing parse_decay");
        assert!(names.contains(&"test_decay"), "missing test_decay");

        // Verify all edges are TypeOf
        for (_, kind, _) in &affected {
            assert_eq!(*kind, EdgeKind::TypeOf, "expected TypeOf edge");
        }
    }

    /// Regression: verify that outgoing neighbors (the OLD buggy direction)
    /// would return 0 for a type with only incoming TypeOf edges. This confirms
    /// the bug existed and the fix is necessary.
    #[test]
    fn impact_outgoing_returns_zero_for_type() {
        let mut graph = KnowledgeGraph::new();
        let decay_fn = make_node(
            "DecayFunction",
            "Enum",
            "crates/h00ligan-engine/src/decay.rs",
        );
        let user_a = make_node(
            "apply_decay",
            "Function",
            "crates/h00ligan-engine/src/decay.rs",
        );

        let decay_id = decay_fn.memory_id;
        let a_id = user_a.memory_id;

        graph.add_node(decay_fn).expect("add DecayFunction");
        graph.add_node(user_a).expect("add user_a");

        // user_a --TypeOf--> DecayFunction
        graph.add_edge(a_id, decay_id, typeof_edge()).expect("edge");

        // Outgoing neighbors of DecayFunction should be empty (DecayFunction
        // doesn't call/reference anything in this graph).
        let outgoing = graph.neighbors(&decay_id);
        let outgoing_dep: Vec<_> = outgoing
            .iter()
            .filter(|(_, e)| is_dependency_edge(e.kind))
            .collect();
        assert!(
            outgoing_dep.is_empty(),
            "DecayFunction should have 0 outgoing dependency edges, got {}",
            outgoing_dep.len()
        );

        // Incoming neighbors should find user_a.
        let incoming = graph.incoming_neighbors(&decay_id);
        let incoming_dep: Vec<_> = incoming
            .iter()
            .filter(|(_, e)| is_dependency_edge(e.kind))
            .collect();
        assert_eq!(
            incoming_dep.len(),
            1,
            "DecayFunction should have 1 incoming dependency edge, got {}",
            incoming_dep.len()
        );
    }

    /// Regression: multi-depth BFS via incoming edges correctly traverses
    /// chains of dependents (A uses B, B uses C — changing C impacts B and A).
    #[test]
    fn impact_multi_depth_incoming_chain() {
        let mut graph = KnowledgeGraph::new();
        let c_node = make_node("C", "Enum", "crates/h00ligan-engine/src/types.rs");
        let b_node = make_node("B", "Function", "crates/h00ligan-engine/src/mid.rs");
        let a_node = make_node("A", "Function", "crates/h00ligan-engine/src/top.rs");

        let c_id = c_node.memory_id;
        let b_id = b_node.memory_id;
        let a_id = a_node.memory_id;

        graph.add_node(c_node).expect("add C");
        graph.add_node(b_node).expect("add B");
        graph.add_node(a_node).expect("add A");

        // B --TypeOf--> C, A --Calls--> B
        graph
            .add_edge(b_id, c_id, typeof_edge())
            .expect("edge B->C");
        graph.add_edge(a_id, b_id, calls_edge()).expect("edge A->B");

        // Impact of C: incoming at depth 1 finds B, incoming of B at depth 2 finds A.
        let max_depth: usize = 3;
        let mut visited: HashSet<Uuid> = HashSet::new();
        let mut queue: VecDeque<(Uuid, usize)> = VecDeque::new();

        visited.insert(c_id);
        queue.push_back((c_id, 0));

        let mut affected: Vec<(String, usize)> = Vec::new();

        while let Some((current_id, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            for (neighbor_id, edge) in graph.incoming_neighbors(&current_id) {
                if !is_dependency_edge(edge.kind) {
                    continue;
                }
                if visited.contains(&neighbor_id) {
                    continue;
                }
                visited.insert(neighbor_id);
                if let Some(node) = graph.node(&neighbor_id) {
                    queue.push_back((neighbor_id, depth + 1));
                    affected.push((node.symbol_name.clone(), depth + 1));
                }
            }
        }

        assert_eq!(
            affected.len(),
            2,
            "should find B at depth 1 and A at depth 2"
        );

        let b_entry = affected.iter().find(|(name, _)| name == "B");
        let a_entry = affected.iter().find(|(name, _)| name == "A");

        assert!(b_entry.is_some(), "B should be in affected set");
        assert!(a_entry.is_some(), "A should be in affected set");
        assert_eq!(b_entry.unwrap().1, 1, "B should be at depth 1");
        assert_eq!(a_entry.unwrap().1, 2, "A should be at depth 2");
    }

    /// End-to-end test: `run_impact` consumes the graph from one immutable
    /// publication and produces non-zero downstream dependents.
    #[tokio::test]
    async fn run_impact_e2e_finds_typeof_dependents() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let root = tmp.path().join("repo");
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&root).expect("create project root");
        std::fs::create_dir_all(&data_dir).expect("create graph directory");
        let binding = ProjectBinding::explicit(&root, &data_dir).unwrap();

        // Build a graph with TypeOf edges.
        let mut graph = KnowledgeGraph::new();
        let decay_fn = make_node(
            "DecayFunction",
            "Enum",
            "crates/h00ligan-engine/src/decay.rs",
        );
        let user_a = make_node(
            "apply_decay",
            "Function",
            "crates/h00ligan-engine/src/decay.rs",
        );
        let user_b = make_node(
            "parse_decay",
            "Function",
            "crates/h00ligan-engine/src/config.rs",
        );

        let decay_id = decay_fn.memory_id;
        let a_id = user_a.memory_id;
        let b_id = user_b.memory_id;

        graph.add_node(decay_fn).expect("add DecayFunction");
        graph.add_node(user_a).expect("add user_a");
        graph.add_node(user_b).expect("add user_b");

        graph
            .add_edge(a_id, decay_id, typeof_edge())
            .expect("edge a");
        graph
            .add_edge(b_id, decay_id, typeof_edge())
            .expect("edge b");

        let mut publisher =
            SemanticPublisher::acquire(binding.graph_dir(), binding.root()).expect("publisher");
        let workspace = publisher.begin_generation().expect("generation workspace");
        let graph_store = GraphStore::new(workspace.database());
        graph_store
            .save_snapshot(&graph)
            .await
            .expect("save immutable snapshot");
        graph_store
            .set_origin(binding.root())
            .await
            .expect("stamp immutable origin");
        graph_store
            .set_generation_metadata(GraphGenerationMetadata::now(false))
            .await
            .expect("stamp complete generation metadata");
        drop(graph_store);
        publisher
            .finish_generation(
                workspace,
                GenerationDraft {
                    source_revision: Some("impact-test".into()),
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
                    receipts: Vec::new(),
                    provider_payloads: Vec::new(),
                },
            )
            .expect("publish immutable impact fixture");

        // Call run_impact with JSON format. The function prints to stdout,
        // so we verify it completes without error. The assertion on count
        // is handled by the unit tests above; this test verifies the full
        // load-from-redb → BFS → output pipeline.
        let args = ImpactArgs {
            symbol: "DecayFunction".to_string(),
            file: None,
            format: "json".to_string(),
            depth: 3,
            include_dead: false,
        };

        let result = run_impact(args, &binding);
        result
            .await
            .expect("run_impact should succeed with immutable TypeOf dependents");
    }
}
