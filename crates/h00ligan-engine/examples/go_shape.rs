//! WU-0023 P3a — Go node/edge-shape MEASUREMENT harness.
//!
//! Runs the REAL production extraction path (`extractor::extract_directory` +
//! `edge_builder::build_graph`) IN-MEMORY over a Go repo, then cross-tabulates
//! the top-level (parent=None) identifier population by export-ness × inbound
//! edge count. This is the DEC-R8-PUBAPI model-picking input (ADR-0025 ruling
//! #4): at the tags-only floor `build_graph` emits NO `Calls` edges (Calls is
//! SCIP-only), so top-level Go nodes are ~uniformly 0-inbound — the exported-at-0
//! COUNT is the false-DEAD-risk surface that pub-api-root seeding must cover.
//!
//! This is an `examples/` target BY DESIGN (its output is the artifact, not a
//! production entrypoint) — it is intentionally NOT wired into any `main()`
//! (recorded DEFER-by-design in traceability). Run:
//!
//! ```text
//! cargo run -p h00ligan-engine --no-default-features --features code-intel \
//!   --example go_shape -- <go-repo-path> [index.scip]
//! ```
//!
//! With an optional pre-built `index.scip` (from `scip-go`) as a 2nd arg it also
//! reports the A1 (R7-coverage) MISS-RATE — SCIP package-scope definitions the
//! tags floor does NOT see, as a LOWER bound on real-world divergence (partyline
//! is cgo/build-tag/generated-free = best case for tags coverage).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use h00ligan_engine::edge_builder::build_graph;
use h00ligan_engine::extractor::extract_directory;
use h00ligan_engine::graph::{EdgeKind, KnowledgeGraph};

/// SCIP `SymbolRole::Definition` bit (scip.proto).
const SCIP_ROLE_DEFINITION: i32 = 1;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let repo = args
        .get(1)
        .expect("usage: go_shape <go-repo-path> [index.scip]");
    let repo_path = PathBuf::from(repo);
    let scip_path = args.get(2).map(PathBuf::from);

    let outputs = extract_directory(&repo_path).expect("extract_directory failed");
    let n_files = outputs.len();
    let n_symbols: usize = outputs.iter().map(|o| o.symbols.len()).sum();

    // file_path(relative) -> package name (from the `package X` clause).
    let pkg_of: BTreeMap<String, String> = outputs
        .iter()
        .filter_map(|o| package_of(&repo_path.join(&o.file_path)).map(|p| (o.file_path.clone(), p)))
        .collect();

    let mut graph = KnowledgeGraph::new();
    let stats = build_graph(&outputs, &mut graph).expect("build_graph failed");

    println!("# WU-0023 P3a — Go static node/edge-shape measurement (harness output)\n");
    println!("repo: `{}`", repo_path.display());
    println!(
        "walked: {n_files} files, {n_symbols} extracted symbols; graph: {} nodes, {} edges\n",
        graph.node_count(),
        graph.edge_count()
    );

    // ---- Positive control (MUST-FIX #4): the graph is LIVE, not a dead harness.
    let method_contains_inbound = graph
        .all_nodes()
        .iter()
        .filter(|n| n.symbol_name.contains("::"))
        .filter(|n| {
            graph
                .incoming_neighbors(&n.memory_id)
                .iter()
                .any(|(_, e)| e.kind == EdgeKind::Contains)
        })
        .count();
    println!("## Positive control");
    println!(
        "- `build_graph` edges_added = **{}** (must be > 0)",
        stats.edges_added
    );
    println!(
        "- nested methods (`Type::method`) with an inbound `Contains` edge = **{method_contains_inbound}** (must be > 0)\n"
    );
    assert!(stats.edges_added > 0, "POSITIVE CONTROL FAILED: no edges");
    assert!(
        method_contains_inbound > 0,
        "POSITIVE CONTROL FAILED: no method received an inbound Contains edge — the harness/graph is dead, the uniform-0 column below is meaningless"
    );

    // ---- Primary cross-tab over top-level, non-test identifiers.
    let mut exp_0 = 0usize;
    let mut exp_gt0 = 0usize;
    let mut unexp_0 = 0usize;
    let mut unexp_gt0 = 0usize;
    let mut inbound_kind_hist: BTreeMap<String, usize> = BTreeMap::new();
    let mut kind_hist: BTreeMap<String, usize> = BTreeMap::new();

    // exported-at-0 importability buckets (MUST-FIX #6).
    let mut b_module_public: Vec<String> = Vec::new();
    let mut b_internal: Vec<String> = Vec::new();
    let mut b_main: Vec<String> = Vec::new();

    // test population (reported separately).
    let mut test_exp = 0usize;
    let mut test_unexp = 0usize;

    // tree-sitter top-level (pkg, name) + bare-name sets for A1.
    let mut ts_pkgname: BTreeSet<(String, String)> = BTreeSet::new();
    let mut ts_name: BTreeSet<String> = BTreeSet::new();

    // Optional diagnostic dump (GO_SHAPE_DUMP=1): every top-level `file\tname\tkind\ttest`
    // line, for reconciling against a go/ast oracle. Written to stderr.
    let dump = std::env::var("GO_SHAPE_DUMP").is_ok();

    for n in graph.all_nodes() {
        if n.symbol_name.contains("::") {
            continue; // nested (method) — excluded from the top-level cross-tab
        }
        if dump {
            eprintln!(
                "DUMP\t{}\t{}\t{}\t{}",
                n.file_path,
                n.symbol_name,
                n.kind,
                n.is_test_only == Some(true)
            );
        }
        let exported = n.visibility == "pub";
        if n.is_test_only == Some(true) {
            if exported {
                test_exp += 1;
            } else {
                test_unexp += 1;
            }
            continue;
        }

        *kind_hist.entry(n.kind.clone()).or_default() += 1;
        let pkg = pkg_of.get(&n.file_path).cloned().unwrap_or_default();
        ts_pkgname.insert((pkg.clone(), n.symbol_name.clone()));
        ts_name.insert(n.symbol_name.clone());

        let inbound = graph.incoming_neighbors(&n.memory_id);
        for (_, e) in &inbound {
            *inbound_kind_hist
                .entry(format!("{:?}", e.kind))
                .or_default() += 1;
        }
        let has_inbound = !inbound.is_empty();

        match (exported, has_inbound) {
            (true, false) => {
                exp_0 += 1;
                // Bucket the exported-at-0 (false-DEAD-risk) by importability.
                if pkg == "main" {
                    b_main.push(n.symbol_name.clone());
                } else if is_internal(&n.file_path) {
                    b_internal.push(n.symbol_name.clone());
                } else {
                    b_module_public.push(n.symbol_name.clone());
                }
            }
            (true, true) => exp_gt0 += 1,
            (false, false) => unexp_0 += 1,
            (false, true) => unexp_gt0 += 1,
        }
    }

    let exp_total = exp_0 + exp_gt0;
    let unexp_total = unexp_0 + unexp_gt0;
    println!("## Primary cross-tab — top-level (parent=None), non-test identifiers\n");
    println!("| | inbound == 0 | inbound > 0 | total |");
    println!("|---|---:|---:|---:|");
    println!("| **exported** (`visibility==\"pub\"`) | {exp_0} | {exp_gt0} | {exp_total} |");
    println!("| **unexported** | {unexp_0} | {unexp_gt0} | {unexp_total} |");
    println!(
        "| **total** | {} | {} | {} |\n",
        exp_0 + unexp_0,
        exp_gt0 + unexp_gt0,
        exp_total + unexp_total
    );

    println!("kind histogram (top-level, non-test): {kind_hist:?}");
    println!(
        "inbound-edge kind histogram (top-level, non-test): {}\n",
        if inbound_kind_hist.is_empty() {
            "{} (DEGENERATE: zero inbound edges on any top-level node — the tags floor emits no Calls; Calls is SCIP-only, P3b)".to_string()
        } else {
            format!("{inbound_kind_hist:?}")
        }
    );

    println!("## Exported-at-0 importability buckets (MUST-FIX #6)\n");
    println!(
        "Only **module-public-at-0** is a true public-API false-DEAD surface. `internal/` and `package main` exports are NOT importable, so their 0-inbound carries no external-reachability signal.\n"
    );
    println!(
        "- module-public @ 0-inbound: **{}** {}",
        b_module_public.len(),
        preview(&b_module_public)
    );
    println!(
        "- internal/ @ 0-inbound: **{}** {}",
        b_internal.len(),
        preview(&b_internal)
    );
    println!(
        "- package-main @ 0-inbound: **{}** {}\n",
        b_main.len(),
        preview(&b_main)
    );
    println!(
        "Interpretation: unexported-at-0 ({unexp_0}) is an UPPER BOUND on genuine-dead (the tags floor gives NO liveness signal for top-level Go — 0-inbound is SUSPECTED, not proven, dead). P3a INFORMS but does NOT RESOLVE DEC-R8-PUBAPI (Alt A vs Alt B needs P3b Calls edges).\n"
    );

    println!("## Test-symbol population (reported separately)\n");
    println!("- exported test-file top-level: {test_exp}");
    println!("- unexported test-file top-level: {test_unexp}\n");

    // ---- A1 (R7 coverage) — SCIP miss-rate, if an index.scip was provided.
    match scip_path {
        Some(p) if p.exists() => a1_report(&p, &ts_name, &ts_pkgname),
        Some(p) => println!(
            "## A1 (R7 coverage)\n\nNOT OBTAINED: index.scip `{}` does not exist.\n",
            p.display()
        ),
        None => println!(
            "## A1 (R7 coverage)\n\nNOT OBTAINED: no index.scip argument supplied (run `scip-go` on the copy and pass its path as arg 2).\n"
        ),
    }
}

/// The `package X` clause name of a Go file, or `None`.
fn package_of(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("package ") {
            return rest.split_whitespace().next().map(str::to_string);
        }
    }
    None
}

/// Whether a workspace-relative path has an `internal/` path segment (Go's
/// import-restriction convention: not importable outside the parent).
fn is_internal(file_path: &str) -> bool {
    file_path.split('/').any(|c| c == "internal")
}

/// A short preview of a name list for the report.
fn preview(names: &[String]) -> String {
    if names.is_empty() {
        return String::new();
    }
    let mut sorted = names.to_vec();
    sorted.sort();
    let head: Vec<&str> = sorted.iter().take(12).map(String::as_str).collect();
    let more = if sorted.len() > 12 {
        format!(", … (+{})", sorted.len() - 12)
    } else {
        String::new()
    };
    format!("— e.g. {}{}", head.join(", "), more)
}

/// Parse `index.scip`, classify SCIP package-scope DEFINITION symbols aligned to
/// the tree-sitter top-level (func/type/const/var; methods & members excluded),
/// and report the MISS-RATE against the tree-sitter floor.
fn a1_report(
    scip_path: &Path,
    ts_name: &BTreeSet<String>,
    ts_pkgname: &BTreeSet<(String, String)>,
) {
    use protobuf::Message as _;
    use scip::types::Index;

    println!("## A1 (R7 coverage) — SCIP miss-rate\n");
    let bytes = match std::fs::read(scip_path) {
        Ok(b) => b,
        Err(e) => {
            println!(
                "NOT OBTAINED: could not read {}: {e}\n",
                scip_path.display()
            );
            return;
        }
    };
    let index = match Index::parse_from_bytes(&bytes) {
        Ok(i) => i,
        Err(e) => {
            println!("NOT OBTAINED: SCIP protobuf parse failed: {e}\n",);
            return;
        }
    };

    // SCIP top-level definition sets (non-test documents only, to align with the
    // tree-sitter non-test floor).
    let mut scip_name: BTreeSet<String> = BTreeSet::new();
    let mut scip_pkgname: BTreeSet<(String, String)> = BTreeSet::new();
    let mut scip_by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut n_docs = 0usize;
    for doc in &index.documents {
        if doc.relative_path.ends_with("_test.go") {
            continue;
        }
        n_docs += 1;
        for occ in &doc.occurrences {
            if occ.symbol_roles & SCIP_ROLE_DEFINITION == 0 {
                continue;
            }
            if let Some((kind, pkg, name)) = classify_scip_top_level(&occ.symbol) {
                *scip_by_kind.entry(kind).or_default() += 1;
                scip_name.insert(name.clone());
                scip_pkgname.insert((pkg, name));
            }
        }
    }

    let miss_name: Vec<&String> = scip_name.difference(ts_name).collect();
    let miss_pkgname: Vec<&(String, String)> = scip_pkgname.difference(ts_pkgname).collect();
    let extra_name: Vec<&String> = ts_name.difference(&scip_name).collect();

    let name_rate = if scip_name.is_empty() {
        0.0
    } else {
        miss_name.len() as f64 / scip_name.len() as f64
    };
    let pkgname_rate = if scip_pkgname.is_empty() {
        0.0
    } else {
        miss_pkgname.len() as f64 / scip_pkgname.len() as f64
    };

    println!("- SCIP non-test documents scanned: {n_docs}");
    println!("- SCIP top-level definitions by kind: {scip_by_kind:?}");
    println!(
        "- SCIP top-level def NAME set: {} · tree-sitter top-level NAME set: {}",
        scip_name.len(),
        ts_name.len()
    );
    println!(
        "- **MISS-RATE (bare name)** = SCIP defs the tags floor misses / SCIP defs = {}/{} = **{:.1}%** (LOWER bound; name collisions across packages make this conservative)",
        miss_name.len(),
        scip_name.len(),
        name_rate * 100.0
    );
    println!(
        "- MISS-RATE (pkg,name) = {}/{} = {:.1}% (pkg = last import-path segment ≈ package name; `main` may mismatch the cmd dir)",
        miss_pkgname.len(),
        scip_pkgname.len(),
        pkgname_rate * 100.0
    );
    println!(
        "- names SCIP has that the tags floor misses: {}",
        preview(&miss_name.iter().map(|s| (*s).clone()).collect::<Vec<_>>())
    );
    println!(
        "- names the tags floor has that SCIP omits: {} {}",
        extra_name.len(),
        preview(&extra_name.iter().map(|s| (*s).clone()).collect::<Vec<_>>())
    );
    println!(
        "\nBound direction (MUST-FIX #5): partyline has ZERO cgo/build-tags/generated code = BEST CASE for tags coverage, so this miss-rate is a LOWER bound on real-world divergence; a messier corpus diverges MORE.\n"
    );
}

/// Classify a SCIP symbol string as a package-scope top-level definition aligned
/// to the tree-sitter floor: `(kind, pkg_last_segment, name)`, or `None` for
/// locals, members (methods/fields, `Type#…`), packages, and imports.
fn classify_scip_top_level(sym: &str) -> Option<(&'static str, String, String)> {
    use scip::symbol::{is_local_symbol, parse_symbol};
    use scip::types::descriptor::Suffix;

    if is_local_symbol(sym) {
        return None;
    }
    let parsed = parse_symbol(sym).ok()?;
    let descs = &parsed.descriptors;
    if descs.is_empty() {
        return None;
    }
    let last = descs.last()?;
    let last_suffix = last
        .suffix
        .enum_value()
        .unwrap_or(Suffix::UnspecifiedSuffix);
    // A `Type` (`#`) descriptor anywhere BEFORE the last => this is a member
    // (a method `Type#M().`, a field `Type#f.`) => not top-level.
    let has_type_before_last = descs[..descs.len() - 1]
        .iter()
        .any(|d| matches!(d.suffix.enum_value(), Ok(Suffix::Type)));
    let kind = match last_suffix {
        Suffix::Method if !has_type_before_last => "func",
        Suffix::Type if !has_type_before_last => "type",
        Suffix::Term if !has_type_before_last => "const_or_var",
        _ => return None,
    };
    // Package = last Namespace descriptor before the identifier; its final path
    // segment ≈ the Go package name.
    let pkg = descs[..descs.len() - 1]
        .iter()
        .rev()
        .find(|d| matches!(d.suffix.enum_value(), Ok(Suffix::Namespace)))
        .map(|d| d.name.rsplit('/').next().unwrap_or(&d.name).to_string())
        .unwrap_or_default();
    Some((kind, pkg, last.name.clone()))
}
