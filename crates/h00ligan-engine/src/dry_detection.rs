//! Structural clone detection via tree-sitter AST fingerprinting.
//!
//! Parses Rust source files, extracts function bodies, normalizes their AST
//! structure (replacing identifiers with positional placeholders, literals with
//! type markers), and hashes the normalized form. Functions with identical
//! fingerprints are structural clones — copy-paste duplicates that differ only
//! in naming.

use std::collections::HashMap;
use std::path::Path;

use ignore::WalkBuilder;
use tree_sitter::Parser;

use crate::language::{LanguageExtractor, rust::RustExtractor};

/// A complete DRY analysis report.
#[derive(Debug, Clone)]
pub struct DryReport {
    /// Groups of structurally identical functions.
    pub clone_groups: Vec<CloneGroup>,
    /// Total number of function bodies analyzed.
    pub total_functions_analyzed: usize,
    /// Number of clone groups found (groups with 2+ members).
    pub total_clone_groups: usize,
    /// Total duplicated lines across all clone groups.
    pub total_duplicated_lines: usize,
}

/// A group of functions that share the same structural fingerprint.
#[derive(Debug, Clone)]
pub struct CloneGroup {
    /// Hex-encoded blake3 hash of the normalized AST structure.
    pub fingerprint: String,
    /// Functions that share this fingerprint.
    pub members: Vec<CloneMember>,
    /// Approximate line count of each member's function body.
    pub structural_lines: usize,
}

/// A single function that is part of a clone group.
#[derive(Debug, Clone)]
pub struct CloneMember {
    /// The function name as it appears in source.
    pub symbol_name: String,
    /// Path to the file containing the function (relative to scan root).
    pub file_path: String,
    /// Start and end line numbers (1-indexed) of the function body.
    pub line_range: (usize, usize),
}

/// Errors that can occur during DRY detection.
#[derive(Debug, thiserror::Error)]
pub enum DryError {
    /// An I/O error occurred reading a file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// tree-sitter language grammar could not be loaded.
    #[error("failed to set tree-sitter language: {0}")]
    LanguageError(String),
}

/// Detect structural clones among Rust functions under `root`.
///
/// Walks all `.rs` files under `root` (respecting `.gitignore`), parses each
/// with tree-sitter, extracts function bodies, computes structural fingerprints,
/// and groups functions with identical fingerprints.
///
/// `min_lines` filters out small functions — only bodies with at least this many
/// lines are considered (default recommendation: 5).
pub fn detect_clones(root: &Path, min_lines: usize) -> Result<DryReport, DryError> {
    let mut parser = Parser::new();
    parser
        // ADR-0024: grammar binding routed through the registry (site 2). DRY
        // normalization stays Rust-specific (fingerprints keyed on Rust node
        // kinds; polyglot DRY is a separate future obligation), so only the
        // grammar — not the `.rs`-scoped walk below — folds through the seam.
        .set_language(&RustExtractor.ts_language_for_path("clone.rs"))
        .map_err(|e| DryError::LanguageError(e.to_string()))?;

    // Collect all function fingerprints across all .rs files.
    let mut fingerprint_map: HashMap<String, Vec<CloneMember>> = HashMap::new();
    let mut total_functions = 0usize;

    let walker = WalkBuilder::new(root)
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .build();

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "skipping unreadable entry during DRY scan");
                continue;
            }
        };
        let path = entry.path();
        if !path.is_file() || path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }

        let source = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "skipping unreadable file");
                continue;
            }
        };

        let tree = match parser.parse(&source, None) {
            Some(t) => t,
            None => {
                tracing::warn!(path = %path.display(), "tree-sitter parse returned None");
                continue;
            }
        };

        let rel_path = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        let src_bytes = source.as_bytes();
        let root_node = tree.root_node();
        let mut cursor = root_node.walk();

        let mut ctx = ExtractCtx {
            src: src_bytes,
            file_path: &rel_path,
            min_lines,
            fingerprint_map: &mut fingerprint_map,
            total_functions: &mut total_functions,
        };

        for child in root_node.children(&mut cursor) {
            extract_functions(&child, &mut ctx);
        }
    }

    // Build clone groups from fingerprints with 2+ members.
    let mut clone_groups: Vec<CloneGroup> = fingerprint_map
        .into_iter()
        .filter(|(_, members)| members.len() >= 2)
        .map(|(fingerprint, members)| {
            let structural_lines = members
                .first()
                .map(|m| {
                    let (start, end) = m.line_range;
                    if end >= start { end - start + 1 } else { 0 }
                })
                .unwrap_or(0);
            CloneGroup {
                fingerprint,
                members,
                structural_lines,
            }
        })
        .collect();

    // Sort by group size (most clones first), then by line count descending.
    clone_groups.sort_by(|a, b| {
        b.members
            .len()
            .cmp(&a.members.len())
            .then_with(|| b.structural_lines.cmp(&a.structural_lines))
    });

    let total_clone_groups = clone_groups.len();
    let total_duplicated_lines: usize = clone_groups
        .iter()
        .map(|g| {
            // Each clone beyond the first is a "duplicate".
            let duplicate_count = g.members.len().saturating_sub(1);
            g.structural_lines * duplicate_count
        })
        .sum();

    Ok(DryReport {
        clone_groups,
        total_functions_analyzed: total_functions,
        total_clone_groups,
        total_duplicated_lines,
    })
}

/// Mutable context threaded through the recursive function extraction walk.
struct ExtractCtx<'a> {
    src: &'a [u8],
    file_path: &'a str,
    min_lines: usize,
    fingerprint_map: &'a mut HashMap<String, Vec<CloneMember>>,
    total_functions: &'a mut usize,
}

/// Recursively extract function items from a tree-sitter node, computing
/// fingerprints for qualifying function bodies.
fn extract_functions(node: &tree_sitter::Node, ctx: &mut ExtractCtx<'_>) {
    let kind = node.kind();

    // Recurse into impl blocks, trait definitions and modules to find nested
    // functions. Impl and trait blocks wrap their methods in a
    // `declaration_list` child, so we must recurse through that as well. Trait
    // default-bodied methods live under `trait_item` → `declaration_list`, so
    // `trait_item` must be in the recurse set or those bodies are never seen.
    if kind == "impl_item"
        || kind == "trait_item"
        || kind == "mod_item"
        || kind == "declaration_list"
    {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            extract_functions(&child, ctx);
        }
        return;
    }

    if kind != "function_item" {
        return;
    }

    // Extract function name.
    let fn_name = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(ctx.src).ok())
        .unwrap_or("<anonymous>")
        .to_string();

    // Find the function body (block node).
    let body_node = match node.child_by_field_name("body") {
        Some(b) => b,
        None => return, // Declaration without body (e.g. trait method signature).
    };

    // Check minimum line count.
    let start_line = body_node.start_position().row + 1; // 1-indexed
    let end_line = body_node.end_position().row + 1;
    let body_lines = if end_line >= start_line {
        end_line - start_line + 1
    } else {
        0
    };

    if body_lines < ctx.min_lines {
        return;
    }

    *ctx.total_functions += 1;

    // Build normalized structural fingerprint from the body AST.
    let fingerprint = compute_fingerprint(&body_node, ctx.src);

    let member = CloneMember {
        symbol_name: fn_name,
        file_path: ctx.file_path.to_string(),
        line_range: (start_line, end_line),
    };

    ctx.fingerprint_map
        .entry(fingerprint)
        .or_default()
        .push(member);
}

/// Compute a structural fingerprint of a tree-sitter node by walking its AST,
/// normalizing identifiers and literals, and hashing the result.
fn compute_fingerprint(node: &tree_sitter::Node, src: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    let mut var_counter = 0u32;
    let mut var_map: HashMap<String, u32> = HashMap::new();
    walk_and_hash(node, src, &mut hasher, &mut var_counter, &mut var_map);
    hasher.finalize().to_hex()[..16].to_string()
}

/// Recursively walk the AST, writing normalized node representations into the
/// hasher. This is the core of structural fingerprinting:
///
/// - Node kinds (e.g. `binary_expression`, `if_expression`) are preserved
///   exactly — they define the structure.
/// - Identifiers are replaced with positional placeholders (`_VAR_0`, `_VAR_1`)
///   so that renaming doesn't change the fingerprint.
/// - Literals are replaced with type markers (`_INT_`, `_STR_`, `_BOOL_`,
///   `_FLOAT_`, `_CHAR_`) so that different constant values don't affect the
///   fingerprint.
/// - Child counts are included to distinguish between nodes with different
///   numbers of arguments/branches.
fn walk_and_hash(
    node: &tree_sitter::Node,
    src: &[u8],
    hasher: &mut blake3::Hasher,
    var_counter: &mut u32,
    var_map: &mut HashMap<String, u32>,
) {
    let kind = node.kind();

    // Write the node kind — this captures the structural skeleton.
    hasher.update(kind.as_bytes());
    hasher.update(b"|");

    // Normalize compound literal nodes: these have children (e.g.
    // `string_literal` → `"`, `string_content`, `"`) but we want to treat
    // the whole subtree as a single normalized token. Do NOT recurse into
    // their children — just emit the type marker and close.
    match kind {
        "string_literal" | "raw_string_literal" => {
            hasher.update(b"_STR_[0]/");
            return;
        }
        "char_literal" => {
            hasher.update(b"_CHAR_[0]/");
            return;
        }
        "boolean_literal" => {
            hasher.update(b"_BOOL_[0]/");
            return;
        }
        _ => {}
    }

    // For leaf nodes, normalize the content.
    if node.child_count() == 0 {
        let text = node.utf8_text(src).unwrap_or("");
        let normalized = match kind {
            // Identifiers: assign positional placeholder.
            "identifier" | "field_identifier" | "type_identifier" => {
                let id = var_map.entry(text.to_string()).or_insert_with(|| {
                    let id = *var_counter;
                    *var_counter += 1;
                    id
                });
                format!("_VAR_{id}_")
            }
            // Numeric literals (leaf nodes).
            "integer_literal" => "_INT_".to_string(),
            "float_literal" => "_FLOAT_".to_string(),
            // Everything else (operators, keywords, punctuation): keep as-is.
            _ => text.to_string(),
        };
        hasher.update(normalized.as_bytes());
    }

    // Write child count to distinguish structural variations.
    hasher.update(b"[");
    hasher.update(node.child_count().to_string().as_bytes());
    hasher.update(b"]");

    // Recurse into children.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_and_hash(&child, src, hasher, var_counter, var_map);
    }

    // End marker for this node's subtree.
    hasher.update(b"/");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Helper: write a .rs file into a temp dir and run detection.
    fn detect_in_source(source: &str, min_lines: usize) -> DryReport {
        let dir = TempDir::new().expect("create temp dir");
        let file_path = dir.path().join("test.rs");
        let mut f = std::fs::File::create(&file_path).expect("create file");
        f.write_all(source.as_bytes()).expect("write source");
        detect_clones(dir.path(), min_lines).expect("detect_clones should succeed")
    }

    #[test]
    fn identical_functions_detected_as_clones() {
        let source = r#"
fn foo(x: i32) -> i32 {
    let a = x + 1;
    let b = a * 2;
    let c = b - 3;
    let d = c + 4;
    let e = d * 5;
    e
}

fn bar(y: i32) -> i32 {
    let a = y + 1;
    let b = a * 2;
    let c = b - 3;
    let d = c + 4;
    let e = d * 5;
    e
}
"#;
        let report = detect_in_source(source, 3);
        assert_eq!(report.total_clone_groups, 1);
        assert_eq!(report.clone_groups[0].members.len(), 2);

        let names: Vec<&str> = report.clone_groups[0]
            .members
            .iter()
            .map(|m| m.symbol_name.as_str())
            .collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"bar"));
    }

    #[test]
    fn different_structures_not_clones() {
        let source = r#"
fn add(x: i32) -> i32 {
    let a = x + 1;
    let b = a * 2;
    let c = b - 3;
    let d = c + 4;
    let e = d * 5;
    e
}

fn subtract(x: i32) -> i32 {
    if x > 0 {
        let a = x - 1;
        let b = a / 2;
        a + b
    } else {
        x
    }
}
"#;
        let report = detect_in_source(source, 3);
        assert_eq!(report.total_clone_groups, 0);
    }

    #[test]
    fn small_functions_filtered_by_min_lines() {
        let source = r#"
fn tiny_a() -> i32 {
    42
}

fn tiny_b() -> i32 {
    42
}
"#;
        // With min_lines=5, these 3-line functions should be excluded.
        let report = detect_in_source(source, 5);
        assert_eq!(report.total_clone_groups, 0);
        assert_eq!(report.total_functions_analyzed, 0);

        // With min_lines=1, they should be found.
        let report = detect_in_source(source, 1);
        assert_eq!(report.total_clone_groups, 1);
    }

    #[test]
    fn literal_normalization_detects_clones() {
        // Same structure, different literal values — should be clones.
        let source = r#"
fn setup_alpha() {
    let name = "alpha";
    let count = 10;
    let flag = true;
    let ratio = 3.14;
    println!("{} {} {} {}", name, count, flag, ratio);
}

fn setup_beta() {
    let name = "beta";
    let count = 20;
    let flag = false;
    let ratio = 2.71;
    println!("{} {} {} {}", name, count, flag, ratio);
}
"#;
        let report = detect_in_source(source, 3);
        assert_eq!(report.total_clone_groups, 1);
    }

    #[test]
    fn multiple_files_cross_file_detection() {
        let dir = TempDir::new().expect("create temp dir");

        let src_a = r#"
fn process_a(x: i32) -> i32 {
    let step1 = x + 1;
    let step2 = step1 * 2;
    let step3 = step2 - 3;
    let step4 = step3 + 4;
    let step5 = step4 * 5;
    step5
}
"#;
        let src_b = r#"
fn process_b(y: i32) -> i32 {
    let step1 = y + 1;
    let step2 = step1 * 2;
    let step3 = step2 - 3;
    let step4 = step3 + 4;
    let step5 = step4 * 5;
    step5
}
"#;
        std::fs::write(dir.path().join("a.rs"), src_a).expect("write a.rs");
        std::fs::write(dir.path().join("b.rs"), src_b).expect("write b.rs");

        let report = detect_clones(dir.path(), 3).expect("detect");
        assert_eq!(report.total_clone_groups, 1);
        let files: Vec<&str> = report.clone_groups[0]
            .members
            .iter()
            .map(|m| m.file_path.as_str())
            .collect();
        assert!(files.contains(&"a.rs"));
        assert!(files.contains(&"b.rs"));
    }

    #[test]
    fn duplicated_lines_calculation() {
        let source = r#"
fn clone_1() {
    let a = 1;
    let b = 2;
    let c = 3;
    let d = 4;
    let e = 5;
}

fn clone_2() {
    let a = 1;
    let b = 2;
    let c = 3;
    let d = 4;
    let e = 5;
}

fn clone_3() {
    let a = 1;
    let b = 2;
    let c = 3;
    let d = 4;
    let e = 5;
}
"#;
        let report = detect_in_source(source, 3);
        assert_eq!(report.total_clone_groups, 1);
        assert_eq!(report.clone_groups[0].members.len(), 3);
        // 3 clones, each ~7 lines body. 2 duplicates * body_lines.
        assert!(report.total_duplicated_lines > 0);
    }

    #[test]
    fn impl_block_functions_detected() {
        let source = r#"
struct Foo;

impl Foo {
    fn method_a(&self) -> i32 {
        let x = 1;
        let y = x + 2;
        let z = y * 3;
        let w = z - 4;
        let v = w + 5;
        v
    }
}

struct Bar;

impl Bar {
    fn method_b(&self) -> i32 {
        let x = 1;
        let y = x + 2;
        let z = y * 3;
        let w = z - 4;
        let v = w + 5;
        v
    }
}
"#;
        let report = detect_in_source(source, 3);
        assert_eq!(report.total_clone_groups, 1);
        let names: Vec<&str> = report.clone_groups[0]
            .members
            .iter()
            .map(|m| m.symbol_name.as_str())
            .collect();
        assert!(names.contains(&"method_a"));
        assert!(names.contains(&"method_b"));
    }

    #[test]
    fn empty_directory_produces_empty_report() {
        let dir = TempDir::new().expect("create temp dir");
        let report = detect_clones(dir.path(), 5).expect("detect");
        assert_eq!(report.total_functions_analyzed, 0);
        assert_eq!(report.total_clone_groups, 0);
        assert!(report.clone_groups.is_empty());
    }

    #[test]
    fn fingerprint_deterministic() {
        // Running detection twice on the same source should yield identical fingerprints.
        let source = r#"
fn deterministic_a(x: i32) -> i32 {
    let a = x + 1;
    let b = a * 2;
    let c = b - 3;
    let d = c + 4;
    let e = d * 5;
    e
}

fn deterministic_b(y: i32) -> i32 {
    let a = y + 1;
    let b = a * 2;
    let c = b - 3;
    let d = c + 4;
    let e = d * 5;
    e
}
"#;
        let report1 = detect_in_source(source, 3);
        let report2 = detect_in_source(source, 3);
        assert_eq!(report1.clone_groups.len(), report2.clone_groups.len());
        assert_eq!(
            report1.clone_groups[0].fingerprint,
            report2.clone_groups[0].fingerprint
        );
    }

    // ------------------------------------------------------------------
    // CI-IND-04: trait default-bodied methods must be analyzed.
    // ------------------------------------------------------------------

    /// A trait default-method body is fingerprinted and counted (RED on HEAD —
    /// `extract_functions` never recursed into `trait_item`, so the method's
    /// `declaration_list` was never reached).
    #[test]
    fn trait_default_method_body_counted() {
        let source = r#"
trait Calculator {
    fn compute(&self) -> i32 {
        let a = 1;
        let b = 2;
        let c = 3;
        let d = 4;
        let e = 5;
        a + b + c + d + e
    }
}
"#;
        let report = detect_in_source(source, 3);
        assert!(
            report.total_functions_analyzed >= 1,
            "trait default method body should be analyzed, got {}",
            report.total_functions_analyzed
        );
    }

    /// Two identical trait default-method bodies form a clone group of size 2,
    /// with members pointing into the traits (RED on HEAD — trait bodies were
    /// never fingerprinted, so no clone group could form).
    #[test]
    fn identical_trait_default_bodies_form_clone_group() {
        let source = r#"
trait Alpha {
    fn run(&self) -> i32 {
        let a = 1;
        let b = 2;
        let c = 3;
        let d = 4;
        let e = 5;
        a + b + c + d + e
    }
}

trait Beta {
    fn run(&self) -> i32 {
        let a = 1;
        let b = 2;
        let c = 3;
        let d = 4;
        let e = 5;
        a + b + c + d + e
    }
}
"#;
        let report = detect_in_source(source, 3);
        assert!(
            report.total_clone_groups >= 1,
            "identical trait default bodies should form >= 1 clone group, got {}",
            report.total_clone_groups
        );
        let biggest = report
            .clone_groups
            .iter()
            .max_by_key(|g| g.members.len())
            .expect("at least one clone group");
        assert!(
            biggest.members.len() >= 2,
            "the trait-default clone group should have >= 2 members, got {}",
            biggest.members.len()
        );
    }
}
