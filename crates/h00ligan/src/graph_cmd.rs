//! `h00ligan graph` — inspect the code-intelligence knowledge graph.
//!
//! Subcommands:
//! - `h00ligan graph stats` — node count, edge count by type, file count, load time
//! - `h00ligan graph blast-radius <symbol>` — bounded reverse dependency walk
//! - `h00ligan graph signature <symbol>` — one resolved symbol signature
//! - `h00ligan graph reachability` — wiring report: classify symbols as WIRED/PUBLIC_API/TEST_ONLY/DEAD

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use clap::{Args, Subcommand};
use h00ligan_engine::graph::{EdgeKind, GraphNode, KnowledgeGraph};
use h00ligan_engine::graph_query::{
    EdgeClass, GateSignals, Match, TraceWriter, WalkControl, admit_set_label,
    find_impl_methods_for_trait, find_trait_method_for_impl, graph_walk, is_dependency_edge,
    reachability_label, resolve_unique, run_inline_reachability, search, traced_reachability_bfs,
};
use h00ligan_engine::project_binding::ProjectBinding;
use h00ligan_engine::reachability::{BfsSpec, ReachabilityClass};

use crate::composite_cmd::{ambiguous_symbol_error, cli_file_locality, symbol_not_found_error};
use crate::error::LiganError;
use h00ligan_engine::dead_pipeline::{DeadTiers, compute_dead_tiers};

/// Arguments for the `h00ligan graph` subcommand.
#[derive(Args, Debug, Clone)]
pub struct GraphArgs {
    #[command(subcommand)]
    pub subcmd: GraphSubcommand,
}

/// Graph inspection subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum GraphSubcommand {
    /// Show graph statistics: node count, edge count by type, file count.
    Stats {
        /// Output in JSON format.
        #[arg(long)]
        format: Option<String>,
    },
    /// Blast radius: find all symbols that depend on a given symbol (reverse BFS).
    BlastRadius {
        /// Symbol name to analyze.
        symbol: String,

        /// Optional repo-relative file path to disambiguate a homonym (same-file >
        /// same-crate). Use the path shown in parentheses for each ambiguous candidate.
        #[arg(long)]
        file: Option<String>,

        /// Maximum BFS depth (default 3, max 5).
        #[arg(long, default_value = "3")]
        depth: usize,

        /// Write detailed BFS trace to <data-dir>/traces/.
        #[arg(long)]
        trace: bool,

        /// Include DEAD symbols in results (excluded by default).
        #[arg(long)]
        include_dead: bool,
    },
    /// Check whether a symbol is wired to a production entry point.
    IsWired {
        /// Symbol name to check.
        symbol: String,

        /// Optional repo-relative file path to disambiguate a homonym (same-file >
        /// same-crate). Use the path shown in parentheses for each ambiguous candidate.
        #[arg(long)]
        file: Option<String>,
    },
    /// Look up signature and metadata for a symbol.
    Signature {
        /// Symbol name to look up.
        symbol: String,

        /// Include DEAD symbols in results (excluded by default).
        #[arg(long)]
        include_dead: bool,
    },
    /// Wiring report: classify every symbol as WIRED, PUBLIC_API, TEST_ONLY, or DEAD.
    Reachability {
        /// Output format: table (default), json, or summary.
        #[arg(long)]
        format: Option<String>,

        /// Exit with code 2 if any DEAD symbols are found.
        #[arg(long)]
        fail_on_dead: bool,

        /// Exit with code 2 if any orphan files are found.
        #[arg(long)]
        fail_on_orphan: bool,

        /// Print diagnostic information (entry point paths, root counts, edge stats).
        #[arg(long)]
        debug: bool,

        /// Save current metrics as the baseline for future diffing.
        #[arg(long)]
        save_baseline: bool,

        /// Path to baseline file for diff comparison.
        #[arg(long)]
        diff: Option<PathBuf>,

        /// Maximum allowed regression in dead symbol count (used with --diff).
        #[arg(long, default_value = "0")]
        threshold: i64,

        /// Show per-file breakdown in table output.
        #[arg(long)]
        verbose: bool,

        /// Write detailed BFS trace to <data-dir>/traces/.
        #[arg(long)]
        trace: bool,

        /// Symbol name to track in reachability trace (prints path when found).
        #[arg(long)]
        trace_target: Option<String>,

        /// Print only tier counts (Wired/Structural/Test-only/Dead/Orphan).
        #[arg(long)]
        summary: bool,
    },
}

/// Run the graph subcommand.
pub async fn run_graph(args: GraphArgs, binding: &ProjectBinding) -> Result<(), LiganError> {
    // Handle reachability separately because it consumes the generation-local
    // evidence document in addition to the immutable graph.
    if let GraphSubcommand::Reachability {
        format,
        fail_on_dead,
        fail_on_orphan,
        debug,
        save_baseline,
        diff,
        threshold,
        verbose,
        trace,
        trace_target,
        summary,
    } = args.subcmd
    {
        // --summary flag overrides --format to "summary"
        let effective_format = if summary {
            Some("summary".to_string())
        } else {
            format
        };
        return run_reachability(
            binding,
            effective_format.as_deref(),
            fail_on_dead,
            fail_on_orphan,
            debug,
            save_baseline,
            diff,
            threshold,
            verbose,
            trace,
            trace_target,
        )
        .await;
    }

    // Handle the graph-snapshot-only subcommands (blast-radius, is-wired, etc.)
    // These load the graph once and operate purely on the snapshot.
    match &args.subcmd {
        GraphSubcommand::BlastRadius {
            symbol,
            file,
            depth,
            trace,
            include_dead,
        } => {
            let graph = load_or_scan_graph(binding).await?;
            return run_blast_radius(
                &graph,
                symbol,
                file.as_deref(),
                (*depth).min(5),
                *trace,
                *include_dead,
                binding.root(),
                binding.graph_dir(),
            )
            .await;
        }
        GraphSubcommand::IsWired { symbol, file } => {
            let graph = load_or_scan_graph(binding).await?;
            return run_is_wired(&graph, symbol, file.as_deref(), binding.root());
        }
        GraphSubcommand::Signature {
            symbol,
            include_dead,
        } => {
            let graph = load_or_scan_graph(binding).await?;
            return run_signature(&graph, symbol, *include_dead);
        }
        GraphSubcommand::Stats { .. } => {}
        GraphSubcommand::Reachability { .. } => {
            unreachable!("reachability handler returned above")
        }
    }

    let start = Instant::now();
    let graph = load_or_scan_graph(binding).await?;
    let load_time = start.elapsed();

    let GraphSubcommand::Stats { format } = args.subcmd else {
        unreachable!("graph subcommand handler returned above")
    };
    run_stats(&graph, load_time, format.as_deref())
}

/// Load one coherent indexed snapshot and clone its graph for CLI query code.
///
/// Callers that need metadata must retain the returned snapshot rather than
/// reopening legacy root databases or sampling another generation.
pub async fn load_indexed_graph_snapshot(
    binding: &ProjectBinding,
) -> Result<
    (
        h00ligan_engine::graph::KnowledgeGraph,
        h00ligan_interface::CodeIntelSnapshot,
    ),
    LiganError,
> {
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| LiganError::Config(format!("load indexed generation: {error}")))?;
    let graph = snapshot.graph.as_deref().cloned().ok_or_else(|| {
        let reason = match &snapshot.load_state {
            h00ligan_interface::GraphLoadState::Unindexed => {
                "no indexed generation is published".into()
            }
            h00ligan_interface::GraphLoadState::Loaded { .. } => {
                "the indexed generation contains no graph snapshot".into()
            }
            h00ligan_interface::GraphLoadState::LoadFailed { error } => error.clone(),
            h00ligan_interface::GraphLoadState::OriginMismatch { stored, bound } => format!(
                "indexed generation origin {} does not match {}",
                stored.display(),
                bound.display()
            ),
        };
        LiganError::Config(format!(
            "{reason}; run `h00ligan index` to publish one immutable generation"
        ))
    })?;
    Ok((graph, snapshot))
}

/// Graph-only convenience wrapper for query handlers that need no metadata.
pub async fn load_or_scan_graph(
    binding: &ProjectBinding,
) -> Result<h00ligan_engine::graph::KnowledgeGraph, LiganError> {
    Ok(load_indexed_graph_snapshot(binding).await?.0)
}

/// `h00ligan graph stats` — print graph statistics.
fn run_stats(
    graph: &h00ligan_engine::graph::KnowledgeGraph,
    load_time: std::time::Duration,
    format: Option<&str>,
) -> Result<(), LiganError> {
    let nodes = graph.all_nodes();
    let edges = graph.all_edges();

    // Count edges by kind.
    let mut edge_counts: HashMap<String, usize> = HashMap::new();
    for (_, _, edge) in &edges {
        *edge_counts.entry(format!("{:?}", edge.kind)).or_insert(0) += 1;
    }

    // Count edges by source (provenance).
    let mut source_counts: HashMap<String, usize> = HashMap::new();
    let mut total_confidence: f64 = 0.0;
    for (_, _, edge) in &edges {
        *source_counts
            .entry(format!("{:?}", edge.source))
            .or_insert(0) += 1;
        total_confidence += edge.confidence as f64;
    }
    let avg_confidence = if edges.is_empty() {
        0.0
    } else {
        total_confidence / edges.len() as f64
    };

    // Count unique files.
    let file_count = nodes
        .iter()
        .map(|n| n.file_path.as_str())
        .collect::<std::collections::HashSet<_>>()
        .len();

    if format == Some("json") {
        let summary = serde_json::json!({
            "node_count": nodes.len(),
            "edge_count": edges.len(),
            "edges_by_kind": edge_counts,
            "edges_by_source": source_counts,
            "avg_confidence": avg_confidence,
            "file_count": file_count,
            "load_time_ms": load_time.as_millis(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&summary)
                .map_err(|e| LiganError::Config(format!("JSON serialization failed: {e}")))?
        );
    } else {
        eprintln!("Graph statistics:");
        eprintln!("  Nodes:      {}", nodes.len());
        eprintln!("  Edges:      {}", edges.len());
        for (kind, count) in &edge_counts {
            eprintln!("    {kind}: {count}");
        }
        eprintln!("  Edge provenance:");
        for (source, count) in &source_counts {
            eprintln!("    {source}: {count}");
        }
        eprintln!("  Avg confidence: {avg_confidence:.2}");
        eprintln!("  Files:      {file_count}");
        eprintln!("  Load time:  {}ms", load_time.as_millis());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `h00ligan graph reachability` — wiring report
// ---------------------------------------------------------------------------

/// Run reachability analysis and print a wiring report.
///
/// Exit code for the ADR-0046 currency gate's UNKNOWN verdict.
///
/// DISTINCT from `2` (the ordinary "wiring check failed — dead symbols found")
/// and from `1` (a generic error), because "your tree has dead code" and "I
/// cannot certify anything about your tree" are different facts that a CI script
/// must be able to tell apart. Every path that declines to certify leaves
/// through this one constant.
const GATE_UNKNOWN_EXIT_CODE: i32 = 3;

/// The classification-provenance verdict for one reachability run (ADR-0046).
///
/// Carries the persisted stamp (if any) and the evaluation of all three
/// currency axes, so the header line and the `--fail-on-dead` gate read from
/// ONE computation and cannot disagree.
struct Provenance {
    stamp: Option<h00ligan_engine::graph_store::ClassifiedBy>,
    failures: Vec<h00ligan_engine::graph_store::CurrencyFailure>,
}

impl Provenance {
    /// Whether the classification is fully certifiable on all three axes.
    const fn is_current(&self) -> bool {
        self.failures.is_empty()
    }

    /// The one-line header rendering.
    fn header_line(&self) -> String {
        match &self.stamp {
            Some(cb) if self.is_current() => cb.render(),
            Some(cb) => format!("{} — NOT CURRENT: {}", cb.render(), self.failure_summary()),
            None => format!("provenance unknown — {}", self.failure_summary()),
        }
    }

    /// Every failing axis, NAMED. A verdict that says only "UNKNOWN" sends its
    /// reader hunting (ADR-0046 rev-3 A2).
    fn failure_summary(&self) -> String {
        if self.failures.is_empty() {
            return "current".to_string();
        }
        self.failures
            .iter()
            .map(h00ligan_engine::graph_store::CurrencyFailure::describe)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Read the classification stamp and evaluate the THREE currency axes
/// Classification currency: source freshness · exact classifier content ·
/// prover configuration.
///
/// The axis evaluation itself is
/// [`evaluate_classification_currency`](h00ligan_engine::graph_store::evaluate_classification_currency)
/// — the SAME callable falsifier #7 drives, so the test cannot certify a copy
/// of the rule while the shipped gate drifts.
///
/// Freshness reuses the immutable generation's exact indexed-source content
/// check that `status` uses; classification certification cannot be fresher
/// than the source authority it was derived from.
async fn load_provenance(
    snapshot: &h00ligan_interface::CodeIntelSnapshot,
    workspace: &std::path::Path,
) -> Provenance {
    let stamp = snapshot.classified_by().cloned();

    // Axis 1 — immutable indexed bytes vs live selected source bytes.
    let index_stale = match snapshot.source_freshness(workspace).await {
        h00ligan_engine::graph_stats::StalenessVerdict::Fresh => Some(false),
        h00ligan_engine::graph_stats::StalenessVerdict::Stale => Some(true),
        h00ligan_engine::graph_stats::StalenessVerdict::Unknown { .. } => None,
    };

    // The reader's side of the comparison: this binary's identity + prover
    // config, and the index configuration THIS binary would generate. The
    // stamped side was derived at a real generation run, so the two can differ
    // under one binary — which is the whole point of the A1 axis.
    let current = h00ligan_engine::graph_store::ClassifiedBy::now();
    let failures = h00ligan_engine::graph_store::evaluate_classification_currency(
        h00ligan_engine::graph_store::CurrencyInputs {
            stamp: stamp.as_ref(),
            current: &current,
            classification_authority_available: snapshot.require_reachability_evidence().is_ok(),
            index_stale,
        },
    );

    Provenance { stamp, failures }
}

/// Load one validated immutable generation and render its persisted
/// reachability classification without mutating the publication.
#[allow(clippy::too_many_arguments)]
async fn run_reachability(
    binding: &ProjectBinding,
    format: Option<&str>,
    fail_on_dead: bool,
    fail_on_orphan: bool,
    debug: bool,
    save_baseline: bool,
    diff: Option<PathBuf>,
    threshold: i64,
    verbose: bool,
    trace: bool,
    trace_target: Option<String>,
) -> Result<(), LiganError> {
    let start = Instant::now();
    let workspace = binding.root().to_path_buf();
    let effective_data_dir = binding.graph_dir().to_path_buf();
    let snapshot = h00ligan_interface::CodeIntelSnapshot::load(binding)
        .await
        .map_err(|error| {
            LiganError::Config(format!(
                "failed to load code-intelligence generation: {error}"
            ))
        })?;
    snapshot.immutable_generation().ok_or_else(|| {
        LiganError::Config(
            "reachability requires a validated immutable generation; run `h00ligan index`"
                .to_string(),
        )
    })?;
    let graph = snapshot.graph.as_deref().ok_or_else(|| {
        LiganError::Config(
            "validated immutable generation contains no knowledge graph; run `h00ligan index`"
                .to_string(),
        )
    })?;
    if !h00ligan_engine::graph_query::graph_reachability_classified(graph) {
        eprintln!(
            "This generation's classification is INCOMPLETE — it carries unclassified \
             symbols. Run `h00ligan index` to publish a complete generation."
        );
        if fail_on_dead || fail_on_orphan {
            eprintln!(
                "UNKNOWN — cannot certify wiring: {}",
                h00ligan_engine::graph_store::CurrencyFailure::ClassificationAuthorityUnavailable
                    .describe()
            );
            std::process::exit(GATE_UNKNOWN_EXIT_CODE);
        }
        std::process::exit(1);
    }
    let reachability_evidence = match snapshot.require_reachability_evidence() {
        Ok(evidence) => evidence,
        Err(reason) => {
            let message = format!(
                "reachability evidence is unavailable for this immutable generation: {reason}. \
             Run `h00ligan index` to publish a complete generation; live source will not be \
             substituted"
            );
            if fail_on_dead || fail_on_orphan {
                eprintln!("UNKNOWN — cannot certify wiring: {message}");
                std::process::exit(GATE_UNKNOWN_EXIT_CODE);
            }
            return Err(LiganError::Config(message));
        }
    };
    let report = reachability_evidence.report.clone();
    let entry_points_snapshot = reachability_evidence.materialized_entry_points();

    let load_time = start.elapsed();

    // --- Debug output: entry points and graph stats ---
    if debug {
        eprintln!(
            "DEBUG: Persisted entry points ({}):",
            entry_points_snapshot.len()
        );
        for ep in &entry_points_snapshot {
            eprintln!(
                "  [{kind}] {name} ({crate_name}) -> {path}",
                kind = ep.kind,
                name = ep.name,
                crate_name = ep.crate_name,
                path = ep.file_path.display()
            );
        }
        let all_edges = graph.all_edges();
        let mut edge_counts: HashMap<String, usize> = HashMap::new();
        for (_, _, edge) in &all_edges {
            *edge_counts.entry(format!("{:?}", edge.kind)).or_insert(0) += 1;
        }
        eprintln!(
            "DEBUG: Graph loaded: {} nodes, {} edges",
            graph.all_nodes().len(),
            all_edges.len()
        );
        for (kind, count) in &edge_counts {
            eprintln!("  {kind}: {count}");
        }
    }

    let analysis_time = start.elapsed();

    // --- Classification provenance (ADR-0046 D1/D4) ---
    // Read the stamp and evaluate all three currency axes ONCE. The same
    // verdict drives the header provenance line and the --fail-on-dead gate, so
    // what the reader is TOLD and what the gate DECIDES cannot diverge.
    let provenance = load_provenance(&snapshot, &workspace).await;

    // --- Tiered production-unreachable set (LEG A-widen; WU-0022 S1 Path A) ---
    // The SINGLE source driving every wiring surface below: the action_tiers
    // JSON block, the default table's ACTION SUMMARY, the --fail-on-dead exit,
    // --save-baseline/--diff. Computed ONCE over the broad non-live
    // set (class ∈ {Dead, Suspected}, generated OUT_DIR glue excluded), bucketed
    // by the shared engine oracle.
    //
    // The graph it reads is the one pinned in `snapshot`; query execution never
    // reclassifies or republishes it.
    //
    // WU-0022 S1 (D3/D4 REPORTING-vs-GATING split): the tiers now carry the SAME
    // per-symbol downgrade Path B (`dead`) applies — the `dead_confirmed`
    // confidence LABELS are stripped under a degraded/absent oracle
    // (WU-0016 leg E), so this wiring surface never
    // claims SafeDelete-grade confidence the corroboration does not support. The
    // RAW membership (`total()`/`symbol_names()`) that the gates below fire on
    // stays IMMUNE to every signal (MAJOR-2), and coverage tier is IGNORED here
    // (a wiring gate must fire on raw membership under any coverage). The signals
    // are sourced from the same coherent snapshot as the graph.
    let dead_signals = {
        let calls_authority = snapshot.calls_coverage();
        let cov = h00ligan_engine::graph_stats::call_edge_coverage(
            graph,
            calls_authority.any_callable_language_complete(),
        );
        GateSignals::derive(&cov, snapshot.oracle_ran_ok())
    };
    let dead_tiers = compute_dead_tiers(graph, dead_signals);

    // --- Trace: run traced BFS for specific target symbol ---
    if trace {
        if let Some(ref target_name) = trace_target {
            // NON-FATAL trace target (ADR-0027): resolve to a unique id, else
            // warn + skip. Ambiguous and NotFound both skip (never silently pick
            // a first match), but the warning distinguishes them.
            let target_id = match resolve_unique(graph, target_name, None).unique_or_report() {
                Ok(id) => Some(id.uuid()),
                Err(amb) if amb.candidates.is_empty() => {
                    eprintln!(
                        "Warning: --trace-target symbol '{target_name}' not found in knowledge graph"
                    );
                    None
                }
                Err(amb) => {
                    let labels: Vec<String> = amb
                        .candidates
                        .iter()
                        .take(10)
                        .map(Match::candidate_label)
                        .collect();
                    eprintln!(
                        "Warning: --trace-target symbol '{target_name}' is ambiguous — matches {} nodes: [{}]. Skipping trace; use a qualified name.",
                        amb.candidates.len(),
                        labels.join(", "),
                    );
                    None
                }
            };
            if let Some(target_id) = target_id {
                let roots = &reachability_evidence.trace_root_ids;
                let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
                let trace_dir = binding.graph_dir().join("traces");
                tokio::fs::create_dir_all(&trace_dir).await?;
                let trace_path = trace_dir.join(format!("reachability-{target_name}-{ts}.txt"));
                let mut tw = TraceWriter::new(&trace_path)
                    .map_err(|e| LiganError::Config(format!("trace file: {e}")))?;
                tw.writeln(&format!("Production roots resolved: {} UUIDs", roots.len()));
                traced_reachability_bfs(graph, roots, target_id, &mut tw);
                tw.flush();
                eprintln!("Trace written to {}", trace_path.display());
            }
        } else {
            eprintln!("Note: --trace requires --trace-target <symbol> for reachability traces");
        }
    }

    // --- Baseline: save ---
    if save_baseline {
        let baseline = ReachabilityBaseline::from_report(&report, &dead_tiers, &provenance);
        let baseline_path = effective_data_dir.join("wiring-baseline.json");
        let json = serde_json::to_string_pretty(&baseline)
            .map_err(|e| LiganError::Config(format!("baseline serialization failed: {e}")))?;
        let bp = baseline_path.clone();
        tokio::fs::write(&bp, json.as_bytes()).await.map_err(|e| {
            LiganError::Config(format!("failed to write baseline to {}: {e}", bp.display()))
        })?;
        eprintln!("Baseline saved to {}", baseline_path.display());
    }

    // --- Baseline: diff ---
    let mut regression_count: i64 = 0;
    if let Some(ref diff_path) = diff {
        let effective_diff_path = if diff_path.is_dir() {
            diff_path.join("wiring-baseline.json")
        } else {
            diff_path.clone()
        };
        match tokio::fs::read_to_string(&effective_diff_path).await {
            Ok(contents) => match serde_json::from_str::<ReachabilityBaseline>(&contents) {
                Ok(baseline) if baseline.schema_version < WIRING_BASELINE_SCHEMA_VERSION => {
                    // LEG A-widen: a v1 baseline captured the Dead-class-only set.
                    // The current set was widened to DEAD ∪ SUSPECTED, so diffing
                    // against it would report every now-Suspected symbol as a
                    // spurious regression. WARN + recommend re-baseline; skip the
                    // regression diff (regression_count stays 0).
                    eprintln!(
                        "Warning: baseline at {} uses schema v{} (DEAD-only). The wiring set was widened to DEAD∪SUSPECTED (schema v{}); skipping the regression diff to avoid spurious new-dead. Re-run `--save-baseline` to re-baseline.",
                        effective_diff_path.display(),
                        baseline.schema_version,
                        WIRING_BASELINE_SCHEMA_VERSION,
                    );
                }
                Ok(baseline) => {
                    let diff_result = baseline.diff(&report, &dead_tiers, &provenance);
                    regression_count = diff_result.dead_delta;
                    print_reachability_diff(&diff_result);
                }
                Err(e) => {
                    eprintln!(
                        "Warning: failed to parse baseline at {}: {e}",
                        effective_diff_path.display()
                    );
                }
            },
            Err(e) => {
                eprintln!(
                    "Warning: failed to read baseline at {}: {e}",
                    effective_diff_path.display()
                );
            }
        }
    }

    // --- Format output ---
    match format {
        Some("json") => {
            use h00ligan_engine::reachability::ReachabilityClass;

            let ws_str = workspace.to_string_lossy();
            let rel = |path: &str| -> String {
                path.strip_prefix(&*ws_str)
                    .unwrap_or(path)
                    .trim_start_matches('/')
                    .to_string()
            };

            let s = &report.summary;
            let wired_pct = if s.total == 0 {
                0.0
            } else {
                (s.wired as f64 / s.total as f64) * 100.0
            };
            let dead_pct = if s.total == 0 {
                0.0
            } else {
                (s.dead as f64 / s.total as f64) * 100.0
            };

            // --- dead_by_file ---
            // WU-0016 Leg H: the per-file delete-safety tiers come from the ONE
            // shared `compute_file_tiers` (also driving the human path + tests) —
            // the `fully_dead` predicate is no longer inlined/duplicated. Each
            // entry carries the DEMOTE annotation (`mod_linked` + linking file,
            // `capture_complete`) so a consumer understands WHY a file dropped out
            // of `fully_dead_files` — "review candidate, but: mod-linked from
            // <file> / holds uncaptured item(s)".
            let dead_nodes = report.nodes_with_class(ReachabilityClass::Dead);
            let file_tiers = compute_file_tiers(&report, graph);

            let dead_by_file: Vec<serde_json::Value> = file_tiers
                .iter()
                .map(|t| {
                    let pct = if t.total == 0 {
                        0.0
                    } else {
                        (t.dead as f64 / t.total as f64) * 100.0
                    };
                    serde_json::json!({
                        "path": rel(&t.path),
                        "dead_count": t.dead,
                        "total_count": t.total,
                        "dead_pct": (pct * 10.0).round() / 10.0,
                        "fully_dead": t.fully_dead,
                        "mod_linked": t.mod_linked,
                        "mod_linked_from": t.mod_linked_from.as_deref().map(&rel),
                        "capture_complete": t.capture_complete,
                    })
                })
                .collect();

            // --- dead_by_kind ---
            let mut kind_counts: HashMap<&str, usize> = HashMap::new();
            for node in &dead_nodes {
                *kind_counts.entry(node.kind.as_str()).or_default() += 1;
            }
            let dead_by_kind: serde_json::Value = kind_counts
                .iter()
                .map(|(k, v)| (k.to_string(), serde_json::Value::from(*v)))
                .collect::<serde_json::Map<String, serde_json::Value>>()
                .into();

            // --- fully_dead_files ---
            // WU-0015 Leg J + WU-0016 Leg H: `fully_dead` already rolls all four
            // conjuncts (all-dead, no retain attr, not mod-linked, capture
            // complete) via `compute_file_tiers`, so this is a straight filter —
            // no re-derived predicate.
            let fully_dead_files: Vec<serde_json::Value> = file_tiers
                .iter()
                .filter(|t| t.fully_dead)
                // OQ-FULLY-DEAD-JSON-HEDGE: each entry carries the review-candidate
                // advisory so a machine consumer cannot treat the array as a
                // delete list (parity with the human header + per-symbol hedge).
                .map(|t| fully_dead_file_entry(&rel(&t.path), t.dead))
                .collect();

            // --- entry_points (bin only) ---
            let entry_points_json: Vec<serde_json::Value> = entry_points_snapshot
                .iter()
                .filter(|ep| ep.kind == h00ligan_engine::entry_points::EntryPointKind::Binary)
                .map(|ep| {
                    serde_json::json!({
                        "name": ep.name,
                        "kind": format!("{:?}", ep.kind),
                        "crate": ep.crate_name,
                        "path": rel(&ep.file_path.to_string_lossy()),
                    })
                })
                .collect();

            // --- classified with relative paths ---
            let classified_json: Vec<serde_json::Value> = report
                .classified
                .iter()
                .map(|n| {
                    serde_json::json!({
                        "memory_id": n.memory_id.to_string(),
                        "symbol_name": n.symbol_name,
                        "file_path": rel(&n.file_path),
                        "kind": n.kind,
                        "classification": format!("{:?}", n.classification),
                    })
                })
                .collect();

            // ADR-0046 D3 render-honesty, MACHINE surface. The human table got
            // this fix first; the JSON did not, and JSON is the surface that
            // matters MORE — 5 of the 11 Justfile reachability recipes parse it,
            // and a machine consumer cannot notice that a plausible `generated`
            // timestamp describes a classification from last week.
            //
            // `generated` is the persisted classification time. This query
            // never reclassifies or republishes the graph.
            let (generated, generated_kind) = provenance.stamp.as_ref().map_or_else(
                || (String::new(), "unknown"),
                |cb| (cb.timestamp.clone(), "persisted-classification"),
            );
            let envelope = serde_json::json!({
                "generated": generated,
                // What `generated` actually denotes. A consumer that ignores
                // this still gets an honest timestamp; one that reads it can
                // tell a fresh computation from a replayed record.
                "generated_kind": generated_kind,
                "provenance": {
                    "current": provenance.is_current(),
                    "mode": "read-only",
                    "stamp": provenance.stamp.as_ref().map_or(serde_json::Value::Null, |cb| {
                        serde_json::json!({
                            "build_identity": cb.build_identity,
                            "indexer_identity": cb.indexer_identity,
                            "prover_config": cb.prover_config,
                            "timestamp": cb.timestamp,
                            "build_provenance_approximate": cb.approximation().is_some(),
                        })
                    }),
                    "failures": provenance
                        .failures
                        .iter()
                        .map(h00ligan_engine::graph_store::CurrencyFailure::describe)
                        .collect::<Vec<_>>(),
                },
                "analysis_ms": analysis_time.as_millis() as u64,
                "summary": {
                    "total": s.total,
                    "wired": s.wired,
                    "wired_pct": (wired_pct * 10.0).round() / 10.0,
                    "public_api": s.public_api,
                    "structural": s.structural,
                    "test_only": s.test_only,
                    "dead": s.dead,
                    "dead_pct": (dead_pct * 10.0).round() / 10.0,
                    "orphan_files": s.orphan_files,
                },
                "dead_by_file": dead_by_file,
                "dead_by_kind": dead_by_kind,
                "fully_dead_files": fully_dead_files,
                // LEG A-widen: the tiered production-unreachable breakdown
                // (DEAD ∪ SUSPECTED), bucketed by the shared classify_dead_action
                // oracle. Parity-by-construction with the default table's ACTION
                // SUMMARY — both driven by the single `dead_tiers` source. Honest
                // tier names: `dead_confirmed` (the private+rustc-flagged+cfg-clean
                // conjunction), `investigate` (suspected / has-alive-dependent),
                // `test_only`. No "safe"/delete-authority token.
                "action_tiers": dead_tiers.action_tiers_json(),
                "entry_points": entry_points_json,
                "classified": classified_json,
            });

            println!(
                "{}",
                serde_json::to_string_pretty(&envelope)
                    .map_err(|e| LiganError::Config(format!("JSON serialization failed: {e}")))?
            );
        }
        Some("summary") => {
            print_reachability_summary(&report, regression_count, &provenance);
        }
        _ => {
            print_reachability_table(
                &report,
                graph,
                &dead_tiers,
                load_time,
                analysis_time,
                &workspace,
                &provenance,
            );
            if verbose {
                print_reachability_verbose(&report);
            }
        }
    }

    // --- Gate currency precheck (ADR-0046 D3 + rev-3 A2) ---
    // A wiring gate must never return a GREEN PASS over classes it cannot
    // certify. If --fail-on-dead/--fail-on-orphan is asked for and ANY of the
    // three currency axes fails — index stale, stamp absent/mismatched on
    // binary, stamp mismatched on index-config — exit NON-ZERO with a distinct
    // UNKNOWN verdict that NAMES the failing axis.
    //
    // The report is always read-only, and no freshness failure can be cured by
    // this query. A new immutable index generation is the only repair path.
    if (fail_on_dead || fail_on_orphan) && !provenance.is_current() {
        eprintln!(
            "UNKNOWN — cannot certify wiring: {}",
            provenance.failure_summary()
        );
        std::process::exit(GATE_UNKNOWN_EXIT_CODE);
    }

    // --- Exit code logic ---
    // LEG A-widen / MAJOR-2: --fail-on-dead gates on the RAW broad membership
    // (DEAD ∪ SUSPECTED), NOT `summary.dead` — which is 0 whenever the residual
    // is Suspected, silently passing the exact IMPL-not-WIRED code the check
    // exists to catch. `dead_tiers.total()` is never coverage-suppressed.
    let dead_fail = fail_on_dead && dead_tiers.total() > 0;
    let should_fail = dead_fail || (fail_on_orphan && report.summary.orphan_files > 0);
    // Threshold check: if --diff provided and regression exceeds threshold, fail
    let threshold_exceeded = diff.is_some() && regression_count > threshold;
    if should_fail || threshold_exceeded {
        if dead_fail {
            eprintln!(
                "Wiring check failed: {} production-unreachable symbol(s) — {}",
                dead_tiers.total(),
                dead_tiers.fail_summary(),
            );
        }
        if threshold_exceeded {
            eprintln!("Threshold exceeded: {regression_count} regressions > {threshold} allowed");
        }
        std::process::exit(2);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Baseline types (lightweight, serializable — lives in CLI because it's a CLI
// concern, not an engine concept)
// ---------------------------------------------------------------------------

/// Current wiring-baseline schema version. v1 (implicit for old baselines that
/// carry no `schema_version`) captured the DEAD-class-only set; v2 duplicated
/// semantic-provider configuration in classification provenance. v3 captures
/// the broad DEAD ∪ SUSPECTED set while leaving provider authority exclusively
/// in immutable capability receipts. Older baselines are warned and skipped.
const WIRING_BASELINE_SCHEMA_VERSION: u32 = 4;

/// Snapshot of reachability metrics for baseline comparison.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ReachabilityBaseline {
    /// Schema version (see [`WIRING_BASELINE_SCHEMA_VERSION`]).
    schema_version: u32,
    /// Git commit hash when the baseline was captured (empty if unavailable).
    git_commit: String,
    /// ISO-8601 timestamp of baseline capture.
    captured_at: String,
    /// Total symbol count at baseline.
    total: usize,
    /// Production-unreachable count at baseline. Since v2 (LEG A-widen) this is
    /// the broad DEAD ∪ SUSPECTED membership, not the DEAD class alone.
    dead: usize,
    /// Orphan file count at baseline.
    orphan_files: usize,
    /// Names of the production-unreachable symbols at baseline (for diff detail).
    /// Since v2 this is the broad DEAD ∪ SUSPECTED membership.
    dead_symbols: Vec<String>,
    /// Orphan file paths at baseline.
    orphan_file_paths: Vec<String>,

    // --- ADR-0046: classification provenance OF the captured numbers ---
    //
    // The operator's regeneration ruling makes baselines the PROTECTED class:
    // "old data means nothing to us... UNLESS we need to keep it around for
    // comparison/validation/testing, then it matters a lot." A baseline is
    // precisely that — the durable artifact diffed weeks later, long after the
    // store that produced it has been re-indexed a dozen times.
    //
    // Without these fields a `--diff` cannot tell a real regression from a
    // baseline captured by different classifier content or prover config. Git
    // provenance alone cannot answer that question for dirty development builds.
    //
    /// Human build provenance that produced the baseline.
    classified_by_build_identity: String,
    /// Exact classifier-content identity that produced the baseline.
    classified_by_indexer_identity: String,
    /// Prover configuration of that classifier.
    classified_by_prover_config: String,
    /// When those classes were CLASSIFIED — distinct from `captured_at`, which
    /// is when this file was written. In read-only mode they can be days apart,
    /// and the classification time is the one that describes the numbers.
    classified_at: String,
}

/// Result of diffing current report against a saved baseline.
struct BaselineDiff {
    /// Git commit the baseline was captured at.
    baseline_commit: String,
    /// When the baseline was captured.
    baseline_date: String,
    /// Change in dead symbol count (positive = regression).
    dead_delta: i64,
    /// Change in orphan file count.
    orphan_delta: i64,
    /// Symbols that are dead now but were not in the baseline.
    new_dead: Vec<String>,
    /// Symbols that were dead in the baseline but are no longer dead.
    resolved: Vec<String>,
    /// ADR-0046: how the baseline's provenance compares to the current run's.
    ///
    /// A recorded field nobody reads is the dead-field symptom this fix round
    /// exists to remove, so the baseline's stamp is not merely stored — it is
    /// CONSULTED here and surfaced in the diff render. A delta computed across a
    /// provenance boundary is not necessarily a code regression, and the reader
    /// must be told which kind of number they are looking at.
    provenance_note: Option<String>,
}

impl ReachabilityBaseline {
    /// Create a baseline from the current reachability report + the widened
    /// production-unreachable set (DEAD ∪ SUSPECTED; LEG A-widen).
    fn from_report(
        report: &h00ligan_engine::reachability::ReachabilityReport,
        dead_tiers: &DeadTiers,
        provenance: &Provenance,
    ) -> Self {
        let git_commit = std::process::Command::new("git")
            .args(["rev-parse", "--short", "HEAD"])
            .output()
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        Self {
            schema_version: WIRING_BASELINE_SCHEMA_VERSION,
            git_commit,
            captured_at: chrono::Utc::now().to_rfc3339(),
            total: report.summary.total,
            dead: dead_tiers.total(),
            orphan_files: report.summary.orphan_files,
            dead_symbols: dead_tiers.symbol_names(),
            orphan_file_paths: report.orphan_files.clone(),
            // ADR-0046: record WHO classified the numbers above, and under what.
            // An unstamped store yields empty strings — "unknown", stated, never
            // fabricated from the current classifier (which did not classify it).
            classified_by_build_identity: provenance
                .stamp
                .as_ref()
                .map(|cb| cb.build_identity.clone())
                .unwrap_or_default(),
            classified_by_indexer_identity: provenance
                .stamp
                .as_ref()
                .map(|cb| cb.indexer_identity.clone())
                .unwrap_or_default(),
            classified_by_prover_config: provenance
                .stamp
                .as_ref()
                .map(|cb| cb.prover_config.clone())
                .unwrap_or_default(),
            classified_at: provenance
                .stamp
                .as_ref()
                .map(|cb| cb.timestamp.clone())
                .unwrap_or_default(),
        }
    }

    /// Describe how this baseline's classification provenance differs from the
    /// current run's, or `None` when they agree on every recorded axis.
    ///
    /// A baseline with no exact classifier identity is reported as unknown,
    /// never silently treated as comparable.
    fn provenance_delta(&self, provenance: &Provenance) -> Option<String> {
        if self.classified_by_indexer_identity.is_empty() {
            return Some(
                "baseline has no exact classifier-content identity — a delta \
                 across it cannot be attributed to code change alone"
                    .to_string(),
            );
        }
        let Some(now) = provenance.stamp.as_ref() else {
            return Some(format!(
                "baseline was classified by `{}` but the CURRENT store carries no stamp — \
                 the two sides are not comparable",
                self.classified_by_build_identity
            ));
        };
        let mut diffs = Vec::new();
        if self.classified_by_indexer_identity != now.indexer_identity {
            diffs.push(format!(
                "classifier-content `{}` -> `{}`",
                self.classified_by_indexer_identity, now.indexer_identity
            ));
        }
        if self.classified_by_prover_config != now.prover_config {
            diffs.push(format!(
                "prover-config `{}` -> `{}`",
                self.classified_by_prover_config, now.prover_config
            ));
        }
        if diffs.is_empty() {
            None
        } else {
            Some(format!(
                "classification provenance CHANGED since the baseline ({}) — part of any delta \
                 below may be the change in how symbols were classified, not a change in the \
                 code",
                diffs.join("; ")
            ))
        }
    }

    /// Compare the current report + widened production-unreachable set against
    /// this baseline. Only called for a v2+ baseline (a v1 baseline is warned +
    /// skipped upstream to avoid spurious regressions against the widened set).
    fn diff(
        &self,
        report: &h00ligan_engine::reachability::ReachabilityReport,
        dead_tiers: &DeadTiers,
        provenance: &Provenance,
    ) -> BaselineDiff {
        use std::collections::HashSet;

        let current_names = dead_tiers.symbol_names();
        let current_dead: HashSet<&str> = current_names.iter().map(|s| s.as_str()).collect();
        let baseline_dead: HashSet<&str> = self.dead_symbols.iter().map(|s| s.as_str()).collect();

        let new_dead: Vec<String> = current_dead
            .difference(&baseline_dead)
            .map(|s| s.to_string())
            .collect();
        let resolved: Vec<String> = baseline_dead
            .difference(&current_dead)
            .map(|s| s.to_string())
            .collect();

        BaselineDiff {
            provenance_note: self.provenance_delta(provenance),
            baseline_commit: self.git_commit.clone(),
            baseline_date: self.captured_at.clone(),
            dead_delta: dead_tiers.total() as i64 - self.dead as i64,
            orphan_delta: report.summary.orphan_files as i64 - self.orphan_files as i64,
            new_dead,
            resolved,
        }
    }
}

// ---------------------------------------------------------------------------
// File-tier delete-safety (WU-0016 Leg H / OQ-FILE-TIER-CAPTURE-COMPLETENESS)
// ---------------------------------------------------------------------------

/// The load-bearing hedge every `fully_dead_files[]` JSON entry carries
/// (OQ-FULLY-DEAD-JSON-HEDGE).
///
/// The human `FULLY DEAD FILES` header and the per-symbol `dead` verdict
/// (graph_cmd.rs "review candidate (NOT a delete authority)") both hedge that a
/// fully-dead file is a REVIEW candidate, not a delete list — but the JSON
/// `fully_dead_files[]` array carried no such hedge, so an automated consumer
/// treating it as a delete list would break the build on the edge-invisible
/// shapes (macro/derive-emitted or inherent-impl references) the captured-symbol
/// roll-up cannot observe. Per-ENTRY (not just top-level) so an iterating
/// consumer cannot miss it.
const FULLY_DEAD_FILE_ADVISORY: &str = "review candidate — every symbol unreachable by static \
     analysis; verify before removing (the captured-symbol roll-up cannot observe macro/\
     derive-emitted or inherent-impl references)";

/// Build one `fully_dead_files[]` JSON entry, carrying the load-bearing
/// [`FULLY_DEAD_FILE_ADVISORY`] hedge (OQ-FULLY-DEAD-JSON-HEDGE) alongside the
/// `path` + `symbol_count`.
fn fully_dead_file_entry(path: &str, symbol_count: usize) -> serde_json::Value {
    serde_json::json!({
        "path": path,
        "symbol_count": symbol_count,
        "advisory": FULLY_DEAD_FILE_ADVISORY,
    })
}

/// Per-file delete-safety tier ([`compute_file_tiers`]).
///
/// The SINGLE shared computation behind both the `--format json`
/// `dead_by_file[]`/`fully_dead_files[]` block and the default human
/// `DEAD CODE BY FILE`/`FULLY DEAD FILES` sections.
///
/// Extracting this pure fn collapses what were TWO independent inline copies of
/// the `fully_dead` predicate (the JSON assembly and the human path — the
/// twin/DRY hazard WU-0016 Leg J flagged) into one observable surface, so a test
/// reads the REAL verdict instead of re-deriving it (closing
/// OQ-RETAIN-ATTR-RESIDUAL). `path` is the RAW file-path key (the caller applies
/// its own workspace-relative stripping).
#[derive(Debug, Clone)]
pub struct FileTier {
    /// Raw source-file path (the `grouped_by_file` key).
    pub path: String,
    /// Count of `Dead`-class symbols in the file.
    pub dead: usize,
    /// Total classified symbols in the file.
    pub total: usize,
    /// Whether any Dead symbol carries `#[allow(dead_code)]` (the author's
    /// "keep this") — excludes the file from `fully_dead` (WU-0015 Leg J).
    pub has_retain: bool,
    /// Whether a `mod X;` declaration living in a DIFFERENT file targets this
    /// file (an inbound `Contains` edge from a `module` node whose file ≠ this
    /// file). Deleting a mod-linked file breaks the surviving `mod X;` (E0583),
    /// so it is NOT delete-safe even when genuinely all-Dead.
    pub mod_linked: bool,
    /// The file the linking `mod X;` lives in, when `mod_linked` (surfaced in the
    /// JSON so a consumer understands WHY the file was withheld).
    pub mod_linked_from: Option<String>,
    /// Whether the file is capture-complete — no node carries
    /// `has_uncaptured_items` (no item-position construct the extractor whitelist
    /// drops). An incomplete file is NOT delete-safe (deleting it could drop a
    /// generated item, E0425).
    pub capture_complete: bool,
    /// The delete-safety verdict:
    /// `dead == total && !has_retain && !mod_linked && capture_complete`.
    pub fully_dead: bool,
}

/// Compute per-file delete-safety tiers from a reachability report + the graph.
///
/// For each file with at least one `Dead` symbol, this rolls the four
/// `fully_dead` conjuncts:
/// 1. `dead == total` — every classified symbol in the file is Dead.
/// 2. `!has_retain` — no Dead symbol carries `#[allow(dead_code)]` (WU-0015 J).
/// 3. `!mod_linked` — no `mod X;` in a DIFFERENT file targets it (E0583 guard;
///    the `!= path` check is load-bearing so an inline `mod X {}` whose body
///    lives in this file does NOT self-flag it).
/// 4. `capture_complete` — no node holds an uncaptured item-generating construct
///    (E0425 guard; WU-0016 H).
///
/// Files are returned sorted by Dead count descending (matching the prior inline
/// `file_stats` ordering). A demoted file (incomplete or mod-linked) still
/// appears with its WHY carried, never silently withheld.
pub fn compute_file_tiers(
    report: &h00ligan_engine::reachability::ReachabilityReport,
    graph: &KnowledgeGraph,
) -> Vec<FileTier> {
    let by_file = report.grouped_by_file();
    let mut tiers: Vec<FileTier> = Vec::new();
    for (&path, nodes) in &by_file {
        let dead = nodes
            .iter()
            .filter(|n| n.classification == ReachabilityClass::Dead)
            .count();
        if dead == 0 {
            continue;
        }
        let total = nodes.len();
        let has_retain = nodes
            .iter()
            .any(|n| n.classification == ReachabilityClass::Dead && n.has_retain_attr);
        // Capture-complete = NO node in the file carries an uncaptured item.
        let capture_complete = nodes.iter().all(|n| !n.has_uncaptured_items);

        // Mod-linkage: any inbound `Contains` edge from a `module` node whose
        // source file is a DIFFERENT file means a `mod X;` elsewhere targets this
        // file — deleting it would break that declaration (E0583). The `!= path`
        // guard excludes an inline `mod X {}` whose body lives in THIS file.
        let mut mod_linked = false;
        let mut mod_linked_from: Option<String> = None;
        'scan: for n in nodes {
            for (src_id, edge) in graph.incoming_neighbors(&n.memory_id) {
                if edge.kind != EdgeKind::Contains {
                    continue;
                }
                if let Some(src) = graph.node(&src_id)
                    && src.kind == "module"
                    && src.file_path != path
                {
                    mod_linked = true;
                    mod_linked_from = Some(src.file_path.clone());
                    break 'scan;
                }
            }
        }

        let fully_dead = dead == total && !has_retain && !mod_linked && capture_complete;
        tiers.push(FileTier {
            path: path.to_string(),
            dead,
            total,
            has_retain,
            mod_linked,
            mod_linked_from,
            capture_complete,
            fully_dead,
        });
    }
    tiers.sort_by_key(|t| std::cmp::Reverse(t.dead));
    tiers
}

// ---------------------------------------------------------------------------
// Output formatters
// ---------------------------------------------------------------------------

/// Print tier counts, one per line, right-aligned.
///
/// The counts are a read of persisted classes, so even the terse surface states
/// its provenance rather than looking freshly computed.
fn print_reachability_summary(
    report: &h00ligan_engine::reachability::ReachabilityReport,
    _regression_count: i64,
    provenance: &Provenance,
) {
    let s = &report.summary;
    println!("Wired:       {:>6}", s.wired);
    println!("Structural:  {:>6}", s.structural);
    println!("Test-only:   {:>6}", s.test_only);
    println!("Dead:        {:>6}", s.dead);
    println!("Orphan:      {:>6}", s.orphan_files);
    println!(
        "Provenance:  read of persisted classification — {}",
        provenance.header_line()
    );
}

/// Print the reachability report in human-readable grouped table format.
#[allow(clippy::too_many_arguments)]
fn print_reachability_table(
    report: &h00ligan_engine::reachability::ReachabilityReport,
    graph: &KnowledgeGraph,
    dead_tiers: &DeadTiers,
    load_time: std::time::Duration,
    analysis_time: std::time::Duration,
    workspace: &std::path::Path,
    provenance: &Provenance,
) {
    use h00ligan_engine::reachability::ReachabilityClass;

    // Helper: strip workspace prefix for relative paths.
    let ws_str = workspace.to_string_lossy();
    let rel = |path: &str| -> String {
        path.strip_prefix(&*ws_str)
            .unwrap_or(path)
            .trim_start_matches('/')
            .to_string()
    };

    let s = &report.summary;
    let pct = |n: usize| -> f64 {
        if s.total == 0 {
            0.0
        } else {
            (n as f64 / s.total as f64) * 100.0
        }
    };

    eprintln!("WIRING REPORT");
    match provenance.stamp.as_ref() {
        Some(cb) => eprintln!(
            "Classified: {} (report is a read of persisted state)",
            cb.timestamp
        ),
        None => eprintln!("Classified: unknown (report is a read of persisted state)"),
    }
    eprintln!("Provenance: {}", provenance.header_line());
    eprintln!(
        "Analyzed in {}ms (loaded in {}ms)",
        analysis_time.as_millis(),
        load_time.as_millis()
    );
    eprintln!();

    // --- Summary ---
    eprintln!("SUMMARY");
    eprintln!("  WIRED:       {:>5} ({:.1}%)", s.wired, pct(s.wired));
    eprintln!(
        "  PUBLIC_API:  {:>5} ({:.1}%)",
        s.public_api,
        pct(s.public_api)
    );
    eprintln!(
        "  STRUCTURAL:  {:>5} ({:.1}%)",
        s.structural,
        pct(s.structural)
    );
    eprintln!(
        "  TEST_ONLY:   {:>5} ({:.1}%)",
        s.test_only,
        pct(s.test_only)
    );
    eprintln!("  DEAD:        {:>5} ({:.1}%)", s.dead, pct(s.dead));
    eprintln!("  Orphans:     {:>5}", s.orphan_files);
    eprintln!();

    // --- Dead code by file (top 10) ---
    let dead_nodes = report.nodes_with_class(ReachabilityClass::Dead);
    if !dead_nodes.is_empty() {
        // WU-0016 Leg H: the per-file tiers come from the ONE shared
        // `compute_file_tiers` (also driving the JSON path + tests) — the
        // `fully_dead` predicate is no longer inlined/duplicated here. The
        // per-file DEAD/TOTAL counts stay intact; the fully-dead label rolls all
        // four conjuncts (all-dead, no retain attr, not mod-linked, capture
        // complete).
        let file_tiers = compute_file_tiers(report, graph);

        eprintln!("DEAD CODE BY FILE (top 10 by dead symbol count)");
        eprintln!("  {:<52} {:>4}  {:>5}  {:>5}", "FILE", "DEAD", "TOTAL", "%");
        for t in file_tiers.iter().take(10) {
            let dead_pct = if t.total == 0 {
                0.0
            } else {
                (t.dead as f64 / t.total as f64) * 100.0
            };
            eprintln!(
                "  {:<52} {:>4}  {:>5}  {:>4.1}%",
                truncate_symbol(&rel(&t.path), 52),
                t.dead,
                t.total,
                dead_pct
            );
        }
        if file_tiers.len() > 10 {
            eprintln!("  ... and {} more files", file_tiers.len() - 10);
        }
        eprintln!();

        // --- Dead code by kind ---
        let mut kind_counts: HashMap<&str, usize> = HashMap::new();
        for node in &dead_nodes {
            *kind_counts.entry(node.kind.as_str()).or_default() += 1;
        }
        let mut kind_sorted: Vec<(&&str, &usize)> = kind_counts.iter().collect();
        kind_sorted.sort_by(|a, b| b.1.cmp(a.1));

        eprintln!("DEAD CODE BY KIND");
        for (kind, count) in &kind_sorted {
            let kind_pct = (**count as f64 / dead_nodes.len() as f64) * 100.0;
            eprintln!("  {:<16} {:>5} ({:.1}%)", kind, count, kind_pct);
        }
        eprintln!();

        // --- Fully dead files (every symbol unreachable) ---
        // WU-0015 Leg J + WU-0016 Leg H: `fully_dead` already rolls all four
        // conjuncts (all-dead, no retain attr, not mod-linked, capture complete)
        // via `compute_file_tiers`, so this is a straight filter.
        let fully_dead: Vec<_> = file_tiers.iter().filter(|t| t.fully_dead).collect();
        if !fully_dead.is_empty() {
            eprintln!(
                "FULLY DEAD FILES (every symbol unreachable by static analysis — review candidates)"
            );
            for t in &fully_dead {
                eprintln!("  {:<52} {} symbols", rel(&t.path), t.dead);
            }
            eprintln!();
        }
    }

    // --- Action summary (LEG A-widen) ---
    // Driven by the SAME `dead_tiers` source as the --format json `action_tiers`
    // block (parity-by-construction), over the broad production-unreachable set
    // (DEAD ∪ SUSPECTED). Emitted whenever that set is non-empty — NOT gated on
    // the DEAD-class-only sections above (which are empty whenever the residual
    // is Suspected), so the default human output never silently hides
    // production-unreachable code. The former ungated fully-dead-FILE density
    // heuristic (a file-shaped guess at "safe") is dropped: tiering is per-symbol
    // via the shared classify_dead_action oracle.
    if !dead_tiers.is_empty() {
        let dead_confirmed = dead_tiers.dead_confirmed();
        let investigate = dead_tiers.investigate();
        let test_only = dead_tiers.test_only();
        eprintln!();
        eprintln!(
            "ACTION SUMMARY ({} production-unreachable: DEAD ∪ SUSPECTED)",
            dead_tiers.total()
        );
        eprintln!(
            "  Dead-confirmed (private, unreachable, cfg-clean):   {} files, {:>5} symbols",
            dead_confirmed.files, dead_confirmed.symbols
        );
        eprintln!(
            "  Investigate (suspected / has alive dependents):     {} files, {:>5} symbols",
            investigate.files, investigate.symbols
        );
        eprintln!(
            "  Test-only (reachable only from test code):          {} files, {:>5} symbols",
            test_only.files, test_only.symbols
        );
    }

    // --- Orphan files ---
    if !report.orphan_files.is_empty() {
        eprintln!();
        eprintln!("ORPHAN FILES ({}):", report.orphan_files.len());
        for path in &report.orphan_files {
            eprintln!("  {}", rel(path));
        }
    }
}

/// Print per-file breakdown when --verbose is set.
fn print_reachability_verbose(report: &h00ligan_engine::reachability::ReachabilityReport) {
    use h00ligan_engine::reachability::ReachabilityClass;

    // Group classified nodes by file: (wired, dead, test, suspected).
    let mut by_file: HashMap<&str, (usize, usize, usize, usize)> = HashMap::new();
    for node in &report.classified {
        let entry = by_file
            .entry(node.file_path.as_str())
            .or_insert((0, 0, 0, 0));
        match node.classification {
            ReachabilityClass::Wired
            | ReachabilityClass::PublicApi
            | ReachabilityClass::Structural => entry.0 += 1,
            ReachabilityClass::Dead => entry.1 += 1,
            ReachabilityClass::TestOnly => entry.2 += 1,
            // WU-0015: the directed-reachability review tier — surfaced as its
            // own SUSPECTED column, never folded into wired or dead.
            ReachabilityClass::Suspected => entry.3 += 1,
            // orphans are file-level, not symbol-level; an Unclassified node
            // should not appear in a classified report — count neither. ADR-0045:
            // an Excluded (out-of-census) node is folded into none of the columns.
            ReachabilityClass::Orphan
            | ReachabilityClass::Unclassified
            | ReachabilityClass::Excluded => {}
        }
    }

    // Sort by file path for stable output
    let mut files: Vec<_> = by_file.into_iter().collect();
    files.sort_by_key(|(path, _)| *path);

    eprintln!("PER-FILE BREAKDOWN:");
    for (path, (wired, dead, test, suspected)) in &files {
        eprintln!(
            "  {path:<60} {wired:>3} wired | {dead:>3} dead | {test:>3} test | {suspected:>3} suspected",
        );
    }
    eprintln!();
}

/// Print baseline diff output.
fn print_reachability_diff(diff: &BaselineDiff) {
    eprintln!(
        "BASELINE DIFF (vs {} captured {}):",
        if diff.baseline_commit.is_empty() {
            "unknown"
        } else {
            &diff.baseline_commit
        },
        diff.baseline_date
    );

    let dead_label = if diff.dead_delta > 0 {
        format!("+{} REGRESSION", diff.dead_delta)
    } else if diff.dead_delta < 0 {
        format!("{} improved", diff.dead_delta)
    } else {
        "unchanged".to_string()
    };
    eprintln!("  Dead: {} ({dead_label})", diff.dead_delta);

    let orphan_label = if diff.orphan_delta > 0 {
        format!("+{}", diff.orphan_delta)
    } else if diff.orphan_delta < 0 {
        format!("{}", diff.orphan_delta)
    } else {
        "unchanged".to_string()
    };
    eprintln!("  Orphan: {} ({orphan_label})", diff.orphan_delta);

    // ADR-0046: state the provenance boundary BEFORE the symbol lists, so a
    // reader cannot scan the deltas without seeing that they may not be
    // code-attributable.
    if let Some(note) = &diff.provenance_note {
        eprintln!("  ! {note}");
    }

    if !diff.new_dead.is_empty() {
        eprintln!("  New dead: {}", diff.new_dead.join(", "));
    }
    if !diff.resolved.is_empty() {
        eprintln!("  Resolved: {}", diff.resolved.join(", "));
    }
    eprintln!();
}

// ============================================================================
// Graph-based tool commands (blast-radius, is-wired, signature, path, warnings)
// ============================================================================

/// `h00ligan graph blast-radius <symbol>` — find all symbols that depend on a given
/// symbol via reverse BFS (incoming edges).
//
// `too_many_arguments`: the `--file` disambiguator (OQ-READVERB-FILE-DISAMBIGUATOR)
// pushes this to 8 distinct dispatch-time flags. They are independent CLI options
// (each maps 1:1 to a clap `#[arg]`), so bundling them into a struct would only
// move the boilerplate without improving clarity; the justified allow is the
// lighter choice (precedent: the gated-fix runbook blesses it for verb handlers).
#[allow(clippy::too_many_arguments)]
async fn run_blast_radius(
    graph: &KnowledgeGraph,
    symbol: &str,
    file: Option<&str>,
    max_depth: usize,
    trace: bool,
    include_dead: bool,
    workspace_root: &std::path::Path,
    graph_dir: &std::path::Path,
) -> Result<(), LiganError> {
    // EP1 (ADR-0027): resolve to a unique id; Ambiguous → F8, NotFound → F1.
    // OQ-READVERB-FILE-DISAMBIGUATOR: optional --file same-file/same-crate locality.
    let root_id = match resolve_unique(graph, symbol, cli_file_locality(file, workspace_root))
        .unique_or_report()
    {
        Ok(id) => id.uuid(),
        Err(amb) if amb.candidates.is_empty() => {
            return Err(symbol_not_found_error(graph, symbol));
        }
        Err(amb) => return Err(ambiguous_symbol_error(symbol, &amb.candidates)),
    };
    // Borrow the resolved node back for trait-bridging (used downstream).
    let root = graph.node(&root_id).ok_or_else(|| {
        LiganError::Config(format!("symbol '{symbol}' resolved but no node found"))
    })?;

    let trace_path = if trace {
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let safe_sym = symbol.replace("::", "-").replace(' ', "_");
        let trace_dir = graph_dir.join("traces");
        tokio::fs::create_dir_all(&trace_dir).await?;
        Some(trace_dir.join(format!("blast-radius-{safe_sym}-{ts}.txt")))
    } else {
        None
    };

    let mut trace_writer = match trace_path.as_ref() {
        Some(p) => {
            Some(TraceWriter::new(p).map_err(|e| LiganError::Config(format!("trace file: {e}")))?)
        }
        None => None,
    };

    let node_label = |id: &uuid::Uuid| -> String {
        graph
            .node(id)
            .map(|n| format!("'{}' ({}, {})", n.symbol_name, n.file_path, n.kind))
            .unwrap_or_else(|| format!("<?> (uuid={id})"))
    };

    if let Some(tw) = &mut trace_writer {
        tw.writeln("BLAST RADIUS TRACE");
        tw.writeln(&format!("  Root: {}", node_label(&root_id)));
        tw.writeln(&format!(
            "  Graph: {} nodes, {} edges",
            graph.node_count(),
            graph.edge_count()
        ));
        tw.writeln(&format!(
            "  Edge filter: Dependency ({})",
            admit_set_label(EdgeClass::Dependency)
        ));
        tw.writeln(&format!("  Max depth: {max_depth}"));
        tw.writeln("");
    }

    // Reverse dependents walk: follow incoming dependency edges.
    //
    // WU-0003 / CL-REACH RC2: routes through the shared `graph_walk` traversal
    // core (the `dependents` preset = INCOMING / `Dependency` admission +
    // edge-driven trait↔impl bridging), DELETING the hand-rolled BFS loop. The
    // interleaved CLI trace is PRESERVED — it is emitted from the visitor
    // closure, which sees each traversed node with its depth/edge/direction.
    // The name-string trait bridges (method-granularity, the documented
    // CL-REACH-05 fallback) are passed as extra roots so the bridge can only
    // widen the set.
    let mut roots: Vec<uuid::Uuid> = vec![root_id];

    // Trait dispatch bridging: if the root is an impl method (e.g.
    // "impl MemoryStore for LanceStore::store"), also seed from the trait
    // method ("MemoryStore::store") since callers link to the trait.
    if let Some(trait_method) = find_trait_method_for_impl(graph, root) {
        if let Some(tw) = &mut trace_writer {
            tw.writeln(&format!(
                "TRAIT BRIDGING: impl->trait: found {}",
                node_label(&trait_method.memory_id)
            ));
        }
        roots.push(trait_method.memory_id);
    } else if let Some(tw) = &mut trace_writer {
        tw.writeln(
            "TRAIT BRIDGING: impl->trait: none found (not an impl method or trait not in graph)",
        );
    }

    // Reverse trait bridging: if the root is a trait method, also seed from all
    // impl methods since callers may reference concrete implementations.
    let impl_methods = find_impl_methods_for_trait(graph, root);
    if let Some(tw) = &mut trace_writer {
        tw.writeln(&format!(
            "REVERSE TRAIT BRIDGING: trait->impl: {} impl methods found",
            impl_methods.len()
        ));
        for im in &impl_methods {
            tw.writeln(&format!("  impl: {}", node_label(&im.memory_id)));
        }
    }
    for impl_method in impl_methods {
        roots.push(impl_method.memory_id);
    }

    if let Some(tw) = &mut trace_writer {
        tw.writeln("");
    }

    let mut affected: Vec<(GraphNode, EdgeKind, usize, f32)> = Vec::new();
    let mut file_counts: HashMap<String, usize> = HashMap::new();

    graph_walk(
        graph,
        &roots,
        &BfsSpec::dependents(),
        Some(max_depth),
        |step| {
            // Seeds (depth 0: the root + trait bridges) are not "dependents".
            if step.depth == 0 {
                return WalkControl::Continue;
            }
            if let Some(tw) = &mut trace_writer {
                let arrow = if step.incoming { "IN <-" } else { "OUT ->" };
                tw.writeln(&format!(
                    "  [depth {}] {arrow} {} ({:?}, conf {:.2}) -> TRAVERSED",
                    step.depth,
                    node_label(&step.node_id),
                    step.via_edge,
                    step.confidence
                ));
            }
            if let Some(node) = graph.node(&step.node_id) {
                *file_counts.entry(node.file_path.clone()).or_insert(0) += 1;
                affected.push((
                    node.clone(),
                    step.via_edge.unwrap_or(EdgeKind::Calls),
                    step.depth,
                    step.confidence,
                ));
            }
            WalkControl::Continue
        },
    );
    affected.sort_by_key(|(_, _, depth, _)| *depth);

    if let Some(tw) = &mut trace_writer {
        tw.writeln(&format!("\nRESULT: {} dependents found", affected.len()));
        tw.flush();
    }
    if let Some(p) = &trace_path {
        eprintln!("Trace written to {}", p.display());
    }

    // Filter out DEAD symbols from results unless --include-dead is set.
    // BFS traversal still walks through dead nodes (they may have wired dependents),
    // but they are excluded from the displayed result set.
    if !include_dead {
        let before = affected.len();
        affected.retain(|(node, _, _, _)| {
            !matches!(
                node.reachability_class,
                ReachabilityClass::Dead | ReachabilityClass::Orphan
            )
        });
        // Rebuild file_counts from retained set
        file_counts.clear();
        for (node, _, _, _) in &affected {
            *file_counts.entry(node.file_path.clone()).or_insert(0) += 1;
        }
        let filtered = before - affected.len();
        if filtered > 0 {
            eprintln!("Filtered {filtered} dead/orphan symbols (use --include-dead to show all)");
        }
    }

    // Print header
    println!("BLAST RADIUS for '{symbol}' (depth {max_depth}):");
    println!("  Estimated blast radius: {} symbols", affected.len());
    println!();

    if affected.is_empty() {
        println!("  No dependents found.");
        return Ok(());
    }

    // Print affected symbols
    println!(
        "  {:<50} {:<12} {:<10} {:<6} {:<10}",
        "SYMBOL", "FILE", "EDGE", "DEPTH", "REACHABILITY"
    );
    println!("  {}", "-".repeat(90));
    for (node, edge_kind, depth, _confidence) in affected.iter().take(30) {
        let short_file = node.file_path.rsplit('/').next().unwrap_or(&node.file_path);
        println!(
            "  {:<50} {:<12} {:<10} {:<6} {:<10}",
            truncate_symbol(&node.symbol_name, 50),
            truncate_symbol(short_file, 12),
            format!("{edge_kind:?}"),
            depth,
            reachability_label(node.reachability_class),
        );
    }
    if affected.len() > 30 {
        println!("  ... and {} more", affected.len() - 30);
    }

    // File summary
    println!();
    println!("  FILES AFFECTED:");
    let mut files: Vec<_> = file_counts.into_iter().collect();
    files.sort_by_key(|b| std::cmp::Reverse(b.1));
    for (path, count) in files.iter().take(10) {
        println!("    {path}: {count} symbols");
    }
    if files.len() > 10 {
        println!("    ... and {} more files", files.len() - 10);
    }

    Ok(())
}

/// `h00ligan graph is-wired <symbol>` — check whether a symbol is wired to a
/// production entry point.
fn run_is_wired(
    graph: &KnowledgeGraph,
    symbol: &str,
    file: Option<&str>,
    root: &std::path::Path,
) -> Result<(), LiganError> {
    // EP1 (ADR-0027): resolve to a unique id; Ambiguous → F8, NotFound → F1.
    // OQ-READVERB-FILE-DISAMBIGUATOR: optional --file same-file/same-crate locality.
    let node_id =
        match resolve_unique(graph, symbol, cli_file_locality(file, root)).unique_or_report() {
            Ok(id) => id.uuid(),
            Err(amb) if amb.candidates.is_empty() => {
                return Err(symbol_not_found_error(graph, symbol));
            }
            Err(amb) => return Err(ambiguous_symbol_error(symbol, &amb.candidates)),
        };
    let node = graph.node(&node_id).ok_or_else(|| {
        LiganError::Config(format!("symbol '{symbol}' resolved but no node found"))
    })?;

    let caller_count = graph
        .incoming_neighbors(&node.memory_id)
        .iter()
        .filter(|(_, edge)| is_dependency_edge(edge.kind))
        .count();

    // Use cached reachability if available, otherwise run inline analysis.
    // WU-0003 RC5: the field is non-`Option`; an inline `None` (no class found)
    // folds to `Unclassified`, never silently to `Dead`.
    let reachability = if node.reachability_class == ReachabilityClass::Unclassified {
        eprintln!(
            "Note: reachability data not cached -- running inline analysis. Run `h00ligan graph reachability` to persist."
        );
        // OBS-1/SIMILAR (ADR-0029): a discovery ERROR propagates (honest); a
        // genuine "no class found" folds to `Unclassified` (RC5 intent).
        run_inline_reachability(graph, &node.memory_id, root)
            .map_err(|e| {
                LiganError::Config(format!(
                    "could not determine reachability: entry-point discovery failed: {e}"
                ))
            })?
            .unwrap_or(ReachabilityClass::Unclassified)
    } else {
        node.reachability_class
    };
    let action_tier = reachability.action_tier();

    // is-wired is an intentionally-RAW, low-level per-symbol diagnostic: it
    // reports the single node's class + tier verbatim (no aggregation, no
    // wiring-gate widening — that lives in `graph reachability`). Use the shared
    // `.label()` (PRESERVE/REVIEW/UNKNOWN) instead of the `{:?}` Debug repr so the
    // tier renders in the canonical single-source form.
    println!("WIRING CHECK for '{}':", node.symbol_name);
    println!("  File:          {}", node.file_path);
    println!("  Kind:          {}", node.kind);
    println!("  Reachability:  {}", reachability_label(reachability));
    println!("  Action tier:   {}", action_tier.label());
    println!("  Caller count:  {caller_count}");

    // Verdict
    match reachability {
        ReachabilityClass::Wired => {
            println!("  Verdict:       WIRED -- reachable from a production entry point");
        }
        ReachabilityClass::PublicApi => {
            println!("  Verdict:       PUBLIC_API -- reachable as library API surface");
        }
        ReachabilityClass::Structural => {
            println!("  Verdict:       STRUCTURAL -- compile-time dependency of wired code (KEEP)");
        }
        ReachabilityClass::TestOnly => {
            println!("  Verdict:       TEST_ONLY -- only reachable from test code");
        }
        ReachabilityClass::Dead => {
            println!("  Verdict:       DEAD -- not reachable from any entry point");
        }
        ReachabilityClass::Orphan => {
            println!("  Verdict:       ORPHAN -- source file has no mod declaration");
        }
        ReachabilityClass::Unclassified => {
            println!("  Verdict:       UNCLASSIFIED -- reachability analysis not run");
        }
        ReachabilityClass::Suspected => {
            println!(
                "  Verdict:       SUSPECTED -- call-unreachable review candidate (NOT a delete authority)"
            );
        }
        ReachabilityClass::Excluded => {
            println!(
                "  Verdict:       EXCLUDED -- out of the production-reachability census (detached/nested crate or fixture corpus)"
            );
        }
    }

    Ok(())
}

/// `h00ligan graph signature <symbol>` — look up signature/metadata for a symbol.
///
/// Every rendered field comes from the published graph. The command never opens
/// another store or recomputes classification from live source.
fn run_signature(
    graph: &KnowledgeGraph,
    symbol: &str,
    include_dead: bool,
) -> Result<(), LiganError> {
    // EP3 (ADR-0027): signature_check is a set-valued renderer (it supports
    // partial names), so it resolves via `graph_query::search` — the
    // Exact > Suffix > Substring tier order, alphabetical within tier, capped at
    // 10. (Output order/cap differs from the prior hand-rolled exact-first +
    // insertion-order scan: this is the EP3 contract, pinned by a falsifier over
    // `search` itself.)
    let mut matched: Vec<&GraphNode> = search(graph, symbol)
        .iter()
        .filter_map(|m| graph.node(&m.id.uuid()))
        .take(10)
        .collect();

    // Filter out DEAD/Orphan symbols unless --include-dead is set.
    if !include_dead {
        let before = matched.len();
        matched.retain(|n| {
            !matches!(
                n.reachability_class,
                ReachabilityClass::Dead | ReachabilityClass::Orphan
            )
        });
        let filtered = before - matched.len();
        if filtered > 0 {
            eprintln!("Filtered {filtered} dead/orphan matches (use --include-dead to show all)");
        }
    }

    if matched.is_empty() {
        return Err(LiganError::Config(format!(
            "symbol '{symbol}' not found in knowledge graph"
        )));
    }

    println!("SIGNATURE LOOKUP for '{symbol}':");
    println!("  Found {} match(es):", matched.len());
    println!();

    for node in &matched {
        println!("  Symbol:       {}", node.symbol_name);
        println!("  File:         {}", node.file_path);
        println!("  Kind:         {}", node.kind);
        println!(
            "  Reachability: {}",
            reachability_label(node.reachability_class)
        );

        let display_sig = if node.signature.is_empty() {
            "(not available)"
        } else {
            node.signature.as_str()
        };
        println!("  Signature:    {display_sig}");
        if let (Some(start), Some(end)) = (node.line_start, node.line_end) {
            println!(
                "  Lines:        {}-{}",
                start.saturating_add(1),
                end.saturating_add(1)
            );
        }
        let display_visibility = if node.visibility.is_empty() {
            "unknown"
        } else {
            node.visibility.as_str()
        };
        println!("  Visibility:   {display_visibility}");
        println!();
    }

    Ok(())
}

// CI-IND-07 / CI-IND-16: `run_warnings` was dead code (`#[allow(dead_code)]`,
// zero call sites — the `graph warnings` subcommand was folded into `inspect`
// in R032-W3) and also contained an unchecked `&content[..120]` byte-slice
// panic site (CI-IND-16). It has been removed; the panic site is resolved by
// deletion. The char-boundary-safe truncation lives in `truncate_symbol`
// (CI-IND-06), which is the WIRED truncation helper.

/// Truncate a symbol name to fit in a column, adding "..." if needed.
///
/// CI-IND-06: truncation is char-boundary-safe. The previous implementation
/// sliced `&name[..max_len - 3]` / `&name[..max_len]` using raw byte indices
/// guarded only by a *byte*-length check, so a multibyte char straddling the
/// cut boundary panicked ("byte index N is not a char boundary"). Symbol
/// names can contain non-ASCII, and this function is WIRED into several
/// display paths, so the panic was production-reachable.
pub fn truncate_symbol(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else if max_len > 3 {
        let cut = name.floor_char_boundary(max_len - 3);
        format!("{}...", &name[..cut])
    } else {
        let cut = name.floor_char_boundary(max_len);
        name[..cut].to_string()
    }
}
#[cfg(test)]
mod tests {
    use super::{
        FULLY_DEAD_FILE_ADVISORY, fully_dead_file_entry, run_blast_radius, run_is_wired,
        truncate_symbol,
    };
    use h00ligan_engine::graph::{GraphNode, KnowledgeGraph};
    use h00ligan_engine::reachability::ReachabilityClass;

    /// OQ-FULLY-DEAD-JSON-HEDGE falsifier: every `fully_dead_files[]` JSON entry
    /// must carry a non-empty `advisory` (the review-candidate hedge), so a
    /// machine consumer cannot mistake the array for a delete list. RED on HEAD:
    /// the entry was `{ "path", "symbol_count" }` with NO advisory — the JSON was
    /// the one delete-surface missing V1's "verify before removing" hedge that
    /// the human header + per-symbol verdict both carry. GREEN after the per-entry
    /// advisory lands. `path`/`symbol_count` remain intact.
    #[test]
    fn fully_dead_file_entry_carries_nonempty_advisory() {
        let entry = fully_dead_file_entry("crates/x/src/dead.rs", 7);
        let advisory = entry
            .get("advisory")
            .and_then(serde_json::Value::as_str)
            .expect("fully_dead_files entry must carry an `advisory` field");
        assert!(
            !advisory.is_empty(),
            "the advisory hedge must be non-empty (delete-authority guard)"
        );
        assert_eq!(advisory, FULLY_DEAD_FILE_ADVISORY);
        assert!(
            advisory.contains("verify before removing"),
            "advisory must carry the load-bearing verify-before-removing hedge; got: {advisory}"
        );
        // The existing machine-readable fields are preserved.
        assert_eq!(entry["path"], "crates/x/src/dead.rs");
        assert_eq!(entry["symbol_count"], serde_json::json!(7));
    }

    /// CI-IND-06: `truncate_symbol` must not panic when the byte cut index
    /// falls inside a multibyte UTF-8 char, at BOTH branches (RED on HEAD —
    /// both `&name[..max_len - 3]` and `&name[..max_len]` were raw byte slices
    /// guarded only by a byte-length check).
    #[test]
    fn truncate_symbol_multibyte_no_panic_max_len_gt_3() {
        // 'é' is 2 bytes (U+00E9). With max_len = 5, the cut index is
        // max_len - 3 = 2; craft the name so byte 2 is the *middle* of 'é'.
        let name = "aé_bbbbbbbb"; // bytes: a(1) é(2) ... cut at byte 2 = mid-é
        let out = truncate_symbol(name, 5);
        assert!(
            std::str::from_utf8(out.as_bytes()).is_ok(),
            "output must be valid UTF-8"
        );
        assert!(out.ends_with("..."), "should be truncated with ellipsis");
    }

    #[test]
    fn truncate_symbol_multibyte_no_panic_max_len_le_3() {
        // 'é' is 2 bytes; max_len = 1 lands inside 'é' on a raw byte slice.
        let name = "é"; // 2 bytes
        let out = truncate_symbol(name, 1);
        assert!(
            std::str::from_utf8(out.as_bytes()).is_ok(),
            "output must be valid UTF-8"
        );
        // Cut floored to byte 0 -> empty string (no panic is the point).
        assert!(out.chars().count() <= 1);
    }

    #[test]
    fn truncate_symbol_emoji_no_panic() {
        // 4-byte emoji straddling the cut boundary.
        let name = "ab😀cdefghij";
        let out = truncate_symbol(name, 6);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn truncate_symbol_ascii_unchanged_when_short() {
        assert_eq!(truncate_symbol("short", 10), "short");
    }

    /// Build a graph with two free-function homonyms `process` in distinct files
    /// (`a.rs` / `b.rs`), both `Wired` so `run_is_wired` skips the inline
    /// reachability path (no disk access in the unit test).
    fn homonym_graph() -> (KnowledgeGraph, uuid::Uuid, uuid::Uuid) {
        let mut graph = KnowledgeGraph::new();
        let a_id = uuid::Uuid::new_v4();
        let b_id = uuid::Uuid::new_v4();
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

    /// MINOR-1 / MAJOR falsifier (the gap the prior review missed): the prior
    /// falsifiers drove `resolve_unique`/the shims DIRECTLY, never the real
    /// arg→`FileContext` extraction inside a verb handler. This drives the actual
    /// `run_is_wired` / `run_blast_radius` handlers with their `file` argument
    /// SET on a homonym fixture and asserts the handler resolves (no F8).
    ///
    /// RED on the pre-fix wiring: both handlers hardcoded `resolve_unique(.., None)`,
    /// so even with `file=Some(..)` a free-fn homonym was ALWAYS F8 → `Err`. The
    /// `file=Some(rel)` / `file=Some(abs)` arms below assert `Ok` → would FAIL
    /// against the pre-fix code (non-vacuous). The `file=None` arm pins that the
    /// legacy F8 behaviour is preserved.
    #[tokio::test]
    async fn cli_file_arg_disambiguates_homonym_on_is_wired_and_blast_radius() {
        let (graph, _a_id, _b_id) = homonym_graph();
        // A real on-disk root so the absolute-path arm exercises the
        // canonicalize-and-strip relativization (MINOR-2 parity with MCP).
        let root_dir = tempfile::tempdir().expect("tempdir");
        let canon_root = root_dir.path().canonicalize().expect("canonicalize root");
        let abs_a = canon_root.join("a.rs");
        let abs_a_str = abs_a.to_str().expect("utf8 abs path");

        // --- is-wired (sync handler) ---
        // file=None → F8 ambiguity → Err (legacy behaviour preserved).
        assert!(
            run_is_wired(&graph, "process", None, &canon_root).is_err(),
            "bare 'process' (no --file) must stay F8-ambiguous on is-wired"
        );
        // file=Some(relative) → resolves → Ok.
        assert!(
            run_is_wired(&graph, "process", Some("a.rs"), &canon_root).is_ok(),
            "is-wired must resolve the homonym with a repo-relative --file"
        );
        // file=Some(absolute) → relativized → resolves → Ok (MINOR-2 parity).
        assert!(
            run_is_wired(&graph, "process", Some(abs_a_str), &canon_root).is_ok(),
            "is-wired must resolve the homonym with an ABSOLUTE --file (CLI ≡ MCP)"
        );

        // --- blast-radius (async handler) ---
        assert!(
            run_blast_radius(
                &graph,
                "process",
                None,
                3,
                false,
                false,
                &canon_root,
                &canon_root,
            )
            .await
            .is_err(),
            "bare 'process' (no --file) must stay F8-ambiguous on blast-radius"
        );
        assert!(
            run_blast_radius(
                &graph,
                "process",
                Some("b.rs"),
                3,
                false,
                false,
                &canon_root,
                &canon_root,
            )
            .await
            .is_ok(),
            "blast-radius must resolve the homonym with a repo-relative --file"
        );
        assert!(
            run_blast_radius(
                &graph,
                "process",
                Some(abs_a_str),
                3,
                false,
                false,
                &canon_root,
                &canon_root,
            )
            .await
            .is_ok(),
            "blast-radius must resolve the homonym with an ABSOLUTE --file (CLI ≡ MCP)"
        );
    }
}
