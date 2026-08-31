//! WU-0023 P2 — Layer A byte-identity lock for the `LanguageExtractor` refactor.
//!
//! THE INVARIANT: refactoring the hardcoded Rust structural extractor into the
//! `LanguageExtractor` trait + table-driven registry produces a graph that is
//! BYTE-IDENTICAL to the pre-refactor graph on Rust input. This test builds the
//! knowledge graph from a synthetic multi-file Rust fixture through the
//! PRODUCTION path (`extractor::extract_directory` + `edge_builder::build_graph`),
//! normalizes it to a deterministic string (stripping the non-deterministic
//! Hebbian/identity fields), and asserts equality against a golden captured on
//! the pristine (pre-refactor) tree.
//!
//! The golden's non-vacuity is proven separately (WU-0023 P2 build): breaking
//! `node_kind_to_symbol_kind` (`const_item => None`) drops the fixture's const
//! node and drives this test RED before it is restored.
#![cfg(feature = "code-intel")]

use std::collections::HashMap;

use h00ligan_engine::edge_builder::build_graph;
use h00ligan_engine::extractor::extract_directory;
use h00ligan_engine::graph::KnowledgeGraph;

/// Multi-file Rust fixture chosen to exercise every extractor helper + edge kind:
/// pub/private fns, const/static/type-alias/macro, cfg gate, `#[no_mangle]`
/// entry-retain, `#[cfg(test)] mod`, a `#[test]` fn in a production file, an
/// item-position `include!` (uncaptured item), a `use`, plus a second file with a
/// field-typed struct, a tuple struct, an enum with payload/struct/unit variants,
/// a trait with a supertrait + default + required method, an inherent impl, a
/// trait impl (Implements + HasImpl edges), and a serde-annotated field.
const FIXTURE_LIB_RS: &str = r#"//! Fixture crate root.
pub mod types;

use std::collections::HashMap;

/// A public free function.
pub fn public_fn(x: i32) -> i32 {
    x + 1
}

fn private_fn() -> bool {
    true
}

pub const MAX_ITEMS: usize = 10;
static GREETING: &str = "hello";
pub type StringMap = HashMap<String, u32>;

macro_rules! noop {
    () => {};
}

#[cfg(unix)]
pub fn only_on_unix() {}

#[no_mangle]
pub extern "C" fn exported_symbol() {}

#[cfg(test)]
mod tests {
    #[test]
    fn inner_test() {
        assert!(true);
    }
}

#[test]
fn top_level_test() {
    assert_eq!(1, 1);
}

include!("generated.in");
"#;

const FIXTURE_TYPES_RS: &str = r#"use serde::Deserialize;

/// A struct with typed fields.
pub struct Point {
    pub x: f64,
    y: f64,
}

pub struct Wrapper(pub Point);

pub enum Shape {
    Circle(f64),
    Rect { w: f64, h: f64 },
    Empty,
}

pub trait Drawable: std::fmt::Debug {
    fn draw(&self);
    fn area(&self) -> f64 {
        0.0
    }
}

impl Point {
    pub fn new(x: f64, y: f64) -> Self {
        Point { x, y }
    }
}

impl Drawable for Point {
    fn draw(&self) {}
}

#[derive(Deserialize)]
pub struct Config {
    #[serde(with = "helper")]
    pub value: u32,
}
"#;

/// Build the fixture, extract it through the production path, and normalize.
fn build_and_normalize() -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("lib.rs"), FIXTURE_LIB_RS).expect("write lib.rs");
    std::fs::write(dir.path().join("types.rs"), FIXTURE_TYPES_RS).expect("write types.rs");
    // A non-registered extension: THE WALK must exclude it (proves the walk
    // generalization from `ext == "rs"` to `is_registered_extension` keeps the
    // walked set byte-identical with only Rust registered).
    std::fs::write(dir.path().join("notes.txt"), "not rust").expect("write notes.txt");

    let outputs = extract_directory(dir.path()).expect("extract_directory");
    let mut graph = KnowledgeGraph::new();
    build_graph(&outputs, &mut graph).expect("build_graph");
    normalize(&graph)
}

/// Deterministic dump of every AST-derived node + edge fact. Strips the
/// non-deterministic identity/Hebbian fields (`memory_id`, `weight`,
/// `access_count`, `last_accessed_ms`, `created_at_ms`); resolves edge endpoints
/// by (name, file) rather than Uuid; sorts both lists for order-independence.
fn normalize(graph: &KnowledgeGraph) -> String {
    let nodes = graph.all_nodes();
    let by_id: HashMap<_, _> = nodes.iter().map(|n| (n.memory_id, *n)).collect();

    let mut node_lines: Vec<String> = nodes
        .iter()
        .map(|n| {
            format!(
                "NODE\t{name}\t{file}\t{kind}\t{vis}\t{reach:?}\t{ls:?}\t{le:?}\t{body:?}\t{test_only:?}\t{test_root}\t{retain:?}\t{pcfg}\t{uncap}\t{hash}\t{sig}",
                name = n.symbol_name,
                file = n.file_path,
                kind = n.kind,
                vis = n.visibility,
                reach = n.reachability_class,
                ls = n.line_start,
                le = n.line_end,
                body = n.has_body,
                test_only = n.is_test_only,
                test_root = n.is_test_root,
                retain = n.entry_retain,
                pcfg = n.has_platform_cfg,
                uncap = n.has_uncaptured_items,
                hash = n.content_hash,
                sig = n.signature,
            )
        })
        .collect();
    node_lines.sort();

    let mut edge_lines: Vec<String> = graph
        .all_edges()
        .iter()
        .map(|(src, tgt, e)| {
            let (sn, sf) = by_id.get(src).map_or(("?", "?"), |n| {
                (n.symbol_name.as_str(), n.file_path.as_str())
            });
            let (tn, tf) = by_id.get(tgt).map_or(("?", "?"), |n| {
                (n.symbol_name.as_str(), n.file_path.as_str())
            });
            format!(
                "EDGE\t{kind:?}\t{sn}\t{sf}\t{tn}\t{tf}\t{source:?}\t{conf:?}\t{scope:?}",
                kind = e.kind,
                source = e.source,
                conf = e.confidence,
                scope = e.scope,
            )
        })
        .collect();
    edge_lines.sort();

    let mut all = node_lines;
    all.extend(edge_lines);
    all.join("\n")
}

#[test]
fn extractor_graph_is_byte_identical_to_golden() {
    let actual = build_and_normalize();
    let golden = include_str!("fixtures/extractor_byte_identity.golden");

    if actual.trim_end() != golden.trim_end() {
        // Write the current output to a scratch path so a legitimate,
        // reviewed change can be diffed and the golden updated deliberately.
        let out = std::env::temp_dir().join("h00_extractor_byte_identity.actual");
        std::fs::write(&out, &actual).expect("write actual dump");
        panic!(
            "normalized extraction graph differs from golden.\nWrote current output to {} — \
             inspect the diff; if the change is intended, update \
             tests/fixtures/extractor_byte_identity.golden.",
            out.display()
        );
    }
}
