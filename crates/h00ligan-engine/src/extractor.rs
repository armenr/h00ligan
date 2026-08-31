//! Tree-sitter-based Rust source code extractor for code intelligence.
//!
//! Parses `.rs` files into typed [`CodeSymbol`] structs capturing functions,
//! structs, enums, traits, impl blocks, modules, imports, consts, type aliases,
//! statics, and macros. Uses blake3 for content hashing to support invalidation
//! tracking.

use std::path::{Path, PathBuf};

use chrono::Utc;
use tree_sitter::Parser;

use crate::graph::EntryRetainFlags;
use crate::language::{LanguageExtractor, rust::RustExtractor};
use crate::structural_ir::{
    CodeSymbol, ExtractorError, ExtractorOutput, StructuralCaptureGap, StructuralDocumentTarget,
    StructuralRelation, SymbolKind, Visibility,
};

// ---------------------------------------------------------------------------
// Core extraction
// ---------------------------------------------------------------------------

/// Whether a file path denotes a test-only source file.
///
/// A file is test-only when it lives under a `tests/` directory or is itself a
/// `tests.rs` module file. This is a FILE-LEVEL signal: it CANNOT see a
/// `#[cfg(test)]` module or function living inside an otherwise-production `.rs`
/// file — that finer-grained discrimination requires per-symbol cfg(test)
/// detection (see [`has_cfg_test_attribute`]) or, for SCIP edges where no
/// per-occurrence signal exists, persisting `is_test_only` on `GraphNode`
/// (WU-0003 / CL-REACH-06).
///
/// Shared between the extractor's file-level test flag and the SCIP loader's
/// per-document edge-scope derivation (EC-7b, WU-0001) so both use the SAME
/// anchored predicate — deliberately NOT `graph_query::is_test_file`'s
/// unanchored `test_` substring check (CL-REACH-06's target).
pub(crate) fn file_is_test(path: &str) -> bool {
    path.contains("/tests/") || path.ends_with("/tests.rs")
}

/// Whether a single `cfg` KEY atom, at the given `not()` negation parity, denotes
/// code that SCIP's index build could STRIP — and thereby hide a caller from the
/// compiler-accurate graph (WU-0015 Leg 2/3b/C / ADR-0036 v4-1 /
/// OQ-CFG-TOKEN-COMPLETENESS / OQ-CFG-CLEAN-CONJUNCT-UNSOUND).
///
/// SCIP is generated with `--all-features` (`ScipFeatures::All`) on a normal
/// (non-doc, non-sanitizer) build, so exactly TWO keys are resolved to a fixed
/// value there: `feature` (every feature ON) and `test` (test-only symbols are
/// tracked by the separate test-scope machinery, not this delete-authority path).
/// A POSITIVE `feature`/`test` atom is therefore always compiled INTO the SCIP
/// graph — NOT strippable — but a NEGATED one (`not(feature = …)` / `not(test)`)
/// resolves FALSE and is stripped, so it IS strippable. EVERY OTHER key — any
/// `target_*` key (covering `target_os/arch/family/pointer_width/endian/env/vendor`
/// AND the ones the original fixed 9-list omitted: `target_feature/target_abi/
/// target_has_atomic/target_thread_local/…`), the bare `windows`/`unix`/`panic`/
/// `debug_assertions` platform keys, the `doc`/`docsrs`/`kani`/`fuzzing`
/// sanitizer/doc keys, or ANY custom build-script `rustc-cfg` name — is not
/// resolved by SCIP's config and can strip its guarded code in EITHER polarity, so
/// it is presence-detected regardless of `negated` (a `_` fallthrough, never a
/// fixed list).
///
/// Over-detection is SAFE by design — it only DOWNGRADES a node
/// `SafeDelete` → `SuspectedDelete` via the Leg-3b conjunct-4 cfg gate.
/// Under-detection (a genuine strippable cfg missed → a false cfg-CLEAN crate → a
/// latent false-SafeDelete) is the damaging direction this predicate exists to
/// prevent, which is why the default is "strippable".
fn cfg_key_is_strippable(key: &str, negated: bool) -> bool {
    match key {
        // The only keys SCIP resolves to TRUE under its build config: a positive
        // atom is kept (not strippable); a negated one is stripped.
        "feature" | "test" => negated,
        // Any other cfg key is unresolved by SCIP → strippable in either polarity.
        _ => true,
    }
}

/// A byte that can appear inside a Rust identifier (`[A-Za-z0-9_]`).
const fn is_ident_byte(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphanumeric()
}

/// A byte that can START a Rust identifier (`[A-Za-z_]`).
const fn is_ident_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}

/// Index of the `)` that balances the `(` at `open`, or `None` if unbalanced.
fn matching_paren(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut idx = open;
    while idx < bytes.len() {
        match bytes[idx] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
        idx += 1;
    }
    None
}

/// Whether the argument list of a `cfg` surface contains any atom that SCIP could
/// STRIP (see [`cfg_key_is_strippable`]), honoring the `all()`/`any()`/`not()`
/// combinator tree (WU-0015 Leg-3b/C / OQ-CFG-TOKEN-COMPLETENESS /
/// OQ-CFG-CLEAN-CONJUNCT-UNSOUND). `negated` tracks the parity of enclosing
/// `not(...)` wrappers so a `feature`/`test` atom flips from EXCLUDED (positive —
/// SCIP resolves it TRUE) to INCLUDED (negated — SCIP strips the negated arm).
///
/// Implemented as a byte-level recursive descent over the `cfg` predicate grammar
/// rather than a flat identifier walk, because the negation parity — the ONLY
/// thing that distinguishes the deliberately-EXCLUDED positive `feature`/`test`
/// from the strippable `not(feature = …)` / `not(test)` — is only visible in the
/// `not(...)` argument tree:
///   * a STRING literal (`"…"`) is skipped WHOLESALE — in `cfg` syntax a value is
///     always a string literal (`key = "value"`), so no identifier inside a string
///     is ever a key. This is what keeps the positive-feature exclusion honest:
///     `serde` inside `feature = "serde"` is never mistaken for a strippable key.
///   * an identifier followed by `(` is a COMBINATOR — `not` flips `negated`,
///     `all`/`any` (and any other functor, e.g. a `cfg_attr` attribute list) pass
///     it through — and its balanced-paren body is scanned recursively.
///   * any other identifier is a KEY atom, classified by [`cfg_key_is_strippable`].
///
/// Over-detection remains SAFE by design (a false-positive cfg crate merely means
/// Leg 3b downgrades more nodes to Suspected); under-detection is the risk to avoid.
fn args_contain_strippable_cfg(args: &str, negated: bool) -> bool {
    let bytes = args.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // Skip a string literal wholesale (honoring `\"` escapes): it holds a
            // VALUE, never a cfg key.
            b'"' => {
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'\\' => i += 2,
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }
            }
            b if is_ident_start(b) => {
                let start = i;
                let mut j = i + 1;
                while j < bytes.len() && is_ident_byte(bytes[j]) {
                    j += 1;
                }
                let ident = &args[start..j];
                // Look past whitespace for a `(` — a combinator functor — vs a key.
                let mut k = j;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
                if k < bytes.len()
                    && bytes[k] == b'('
                    && let Some(close) = matching_paren(bytes, k)
                {
                    // `k` and `close` index ASCII `(`/`)`, so the slice is on char
                    // boundaries. `not` flips negation; other combinators keep it.
                    let inner_negated = if ident == "not" { !negated } else { negated };
                    if args_contain_strippable_cfg(&args[k + 1..close], inner_negated) {
                        return true;
                    }
                    i = close + 1;
                } else {
                    // A bare key atom (`unix`) or the LHS of `key = "value"`.
                    if cfg_key_is_strippable(ident, negated) {
                        return true;
                    }
                    i = j;
                }
            }
            _ => i += 1,
        }
    }
    false
}

/// Whole-file scan for a `cfg` predicate that SCIP could STRIP (WU-0015 Leg 2/C).
///
/// Returns `true` iff `source` contains a `cfg(...)`, `cfg_attr(...)`, or
/// `cfg!(...)` surface whose (possibly nested `all()/any()/not()`) argument list
/// contains an atom SCIP's `--all-features` build cannot resolve to TRUE (see
/// [`cfg_key_is_strippable`] / [`args_contain_strippable_cfg`]): a platform key, a
/// `doc`/`docsrs`/`kani`/`fuzzing`/custom build cfg, or a NEGATED feature/test.
///
/// The name is historical ("platform") — the signal has broadened to "any
/// SCIP-strippable cfg" (OQ-CFG-CLEAN-CONJUNCT-UNSOUND); the field it feeds
/// ([`ExtractorOutput::has_platform_cfg`]) is bincode-persisted, so a rename would
/// touch the schema + `graph_query` and stays out of this leg's scope.
///
/// This is intentionally a WHOLE-FILE scan rather than the per-item
/// [`has_cfg_test_attribute`] preceding-sibling walk: that walk only inspects
/// `attribute_item` siblings of a definition, so it never sees `cfg!()` in a
/// function BODY, never recognizes `cfg_attr`, and substring-matches rather than
/// token-scanning nested forms — all of which this scanner must catch. Scoping
/// detection to the argument span of a `cfg` surface (not a bare whole-file
/// token search) keeps genuinely cfg-clean crates OUT of the signal set: a file
/// merely naming `unix` in an unrelated identifier or comment does not trip it.
pub fn scan_platform_cfg(source: &str) -> bool {
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if !is_ident_start(b) {
            i += 1;
            continue;
        }
        // Read the identifier at `i`, honoring a left word boundary.
        let start = i;
        let mut j = i + 1;
        while j < bytes.len() && is_ident_byte(bytes[j]) {
            j += 1;
        }
        let at_boundary = start == 0 || !is_ident_byte(bytes[start - 1]);
        let ident = &source[start..j];
        if at_boundary && (ident == "cfg" || ident == "cfg_attr") {
            // Skip whitespace, then an optional `!` (the `cfg!` macro form),
            // then require an opening `(`.
            let mut k = j;
            while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                k += 1;
            }
            if k < bytes.len() && bytes[k] == b'!' {
                k += 1;
                while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                    k += 1;
                }
            }
            if k < bytes.len()
                && bytes[k] == b'('
                && let Some(close) = matching_paren(bytes, k)
            {
                // `k` and `close` index ASCII `(`/`)`, so the slice is on
                // char boundaries.
                if args_contain_strippable_cfg(&source[k + 1..close], false) {
                    return true;
                }
                i = close + 1;
                continue;
            }
        }
        i = j;
    }
    false
}

/// Whether a tree-sitter node kind is one the extractor CAPTURES as a
/// [`CodeSymbol`] — i.e. [`node_kind_to_symbol_kind`] maps it to `Some`.
///
/// Sharing the ONE whitelist (rather than re-listing the kinds) keeps
/// [`rust_capture_gaps`] in lockstep with the capture set: widen the
/// whitelist and the "uncaptured" scan narrows automatically, no second edit.
fn is_captured_item_kind(kind: &str) -> bool {
    node_kind_to_symbol_kind(kind).is_some()
}

/// Whether a tree-sitter node kind occupying an item position is benign NOISE
/// that must NOT count as an "uncaptured item" (WU-0016 Leg H).
///
/// These are the non-item item-position constructs a normal `.rs` file carries
/// in abundance — comments (`//` `/* */` incl. `///`/`//!` doc comments), outer
/// (`#[…]`) and inner (`#![…]`) attributes, stray `;` empty statements, and the
/// `#!`-shebang. Counting any of them would false-withhold nearly every real
/// file. `attribute_item` is included because a decorating `#[…]` is a preceding
/// SIBLING item-position node, not part of the item it decorates.
fn is_noise_item_kind(kind: &str) -> bool {
    matches!(
        kind,
        "line_comment"
            | "block_comment"
            | "attribute_item"
            | "inner_attribute_item"
            | "empty_statement"
            | "shebang"
            // A bare REQUIRED associated type in a trait body (`type Item;`,
            // no `= …`) parses as `associated_type` (not `type_item`). It is a
            // structural member of the already-captured `trait_item`, NOT an
            // independently-emittable item — deleting the file emits no E0425.
            // Excluded so the default-deny scan does not over-withhold dead
            // trait-defining modules. (WU-0016 Leg H reviewer-caught over-withhold.)
            | "associated_type"
    )
}

/// Exact ITEM-POSITION constructs the capture whitelist DROPS.
///
/// WU-0016 Leg H / OQ-FILE-TIER-CAPTURE-COMPLETENESS — the sound
/// capture-completeness precondition for the file-tier `fully_dead` claim.
///
/// POSITION-AWARE + DEFAULT-DENY + WHOLE-FILE. It walks ITEM positions only —
/// the direct children of `source_file`, and recursively the children of every
/// module/impl/trait `declaration_list` body — and NEVER descends into
/// expression positions (a function body `block`). This is load-bearing: a
/// `println!()` in a fn body is ALSO a `macro_invocation` node, and counting it
/// would catastrophically over-withhold almost every file (they nearly all carry
/// expression macros). At each item-position node: if the kind is neither a
/// captured whitelist kind ([`is_captured_item_kind`]) nor benign noise
/// ([`is_noise_item_kind`]) it is an UNCAPTURED ITEM. Default-deny means
/// this catches `macro_invocation` at item position, `foreign_mod_item`,
/// `extern_crate_declaration`, AND any FUTURE/unknown item kind — not a
/// hardcoded three. A captured container (`mod_item`/`impl_item`/`trait_item`)
/// is itself fine, but its body is recursed so a `make_gen!{}` nested inside a
/// `mod {}` is still reported. Every gap retains the exact tree-sitter kind and
/// byte span, in deterministic source order.
fn rust_capture_gaps(root: tree_sitter::Node<'_>) -> Vec<StructuralCaptureGap> {
    fn gap_for_item(node: tree_sitter::Node<'_>) -> StructuralCaptureGap {
        let kind = if node.kind() == "macro_invocation"
            || (node.kind() == "expression_statement"
                && node.named_child_count() == 1
                && node
                    .named_child(0)
                    .is_some_and(|child| child.kind() == "macro_invocation"))
        {
            "unexpanded_rust_item_macro".to_owned()
        } else {
            format!("unrepresented_rust_item:{}", node.kind())
        };
        StructuralCaptureGap::new(kind, (node.start_byte(), node.end_byte()))
    }

    /// Walk the item-position children of `node`, recursing into
    /// module/impl/trait bodies (NEVER into expression/statement blocks).
    fn walk_item_positions(node: tree_sitter::Node<'_>, gaps: &mut Vec<StructuralCaptureGap>) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // Only NAMED nodes are grammar constructs; the anonymous `{`/`}`/`;`
            // punctuation tokens a `declaration_list` body carries are NOT items
            // and must be skipped (else recursing into a mod/impl/trait body would
            // flag its braces as "uncaptured").
            if !child.is_named() {
                continue;
            }
            let kind = child.kind();
            if is_captured_item_kind(kind) {
                // A captured container's body is itself a chain of item
                // positions — recurse so a nested uncaptured item still counts.
                if matches!(kind, "mod_item" | "impl_item" | "trait_item")
                    && let Some(body) = child.child_by_field_name("body")
                {
                    walk_item_positions(body, gaps);
                }
                continue;
            }
            if is_noise_item_kind(kind) {
                continue;
            }
            // Default-deny: an item-position node that is neither captured nor
            // benign noise is an uncaptured item.
            gaps.push(gap_for_item(child));
        }
    }

    let mut gaps = Vec::new();
    walk_item_positions(root, &mut gaps);
    gaps
}

/// Extract Rust symbols from a source string.
///
/// `file_path` is used only for error messages and the output struct -- the
/// source text is provided directly.
pub fn extract_rust_symbols(
    source: &str,
    file_path: &str,
) -> Result<ExtractorOutput, ExtractorError> {
    let mut parser = Parser::new();
    parser
        // ADR-0024: the grammar binding folds through the registry — this is
        // `RustExtractor`'s path-aware grammar seam, the single sanctioned `tree_sitter_rust`
        // structural site (same grammar object → byte-identical parse).
        .set_language(&RustExtractor.ts_language_for_path(file_path))
        .map_err(|e| ExtractorError::LanguageError(e.to_string()))?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| ExtractorError::ParseFailed {
            path: file_path.to_string(),
        })?;

    let root = tree.root_node();
    if root.has_error() {
        return Err(ExtractorError::IncompleteSyntax {
            path: file_path.to_string(),
            detail: String::new(),
        });
    }
    let src = source.as_bytes();
    let mut symbols = Vec::new();

    // Detect if the file itself is test-only (test harness files).
    let file_is_test = file_is_test(file_path);

    // Walk top-level children.
    let mut cursor = root.walk();
    for child in root.children(&mut cursor) {
        extract_node(&child, src, None, Some(&[]), file_is_test, &mut symbols);
    }

    let file_hash = blake3::hash(source.as_bytes()).to_hex().to_string();

    // WU-0015 Leg 2: whole-file platform-cfg token scan (over the FULL source,
    // so it catches `cfg!()` in bodies + `cfg_attr` + non-item cfg that the
    // per-symbol `has_cfg_test_attribute` sibling-walk structurally misses).
    let has_platform_cfg = scan_platform_cfg(source);

    // WU-0016 Leg H: whole-file, position-aware, default-deny scan for
    // item-position constructs the capture whitelist drops (the
    // capture-completeness precondition for the file-tier fully_dead claim).
    let mut capture_gaps = rust_capture_gaps(root);
    capture_gaps.extend(
        symbols
            .iter()
            .filter(|symbol| {
                symbol.relations.iter().any(|relation| {
                    matches!(
                        relation,
                        StructuralRelation::ContainsDocument {
                            target: StructuralDocumentTarget::Unresolved,
                            ..
                        }
                    )
                })
            })
            .map(|symbol| StructuralCaptureGap::new("rust_module_path_unresolved", symbol.span)),
    );
    let cross_document_surface_sha256 =
        crate::code_intel_semantic_refresh::cross_document_surface_sha256(
            &RustExtractor,
            source,
            root,
        );

    Ok(ExtractorOutput {
        file_path: file_path.to_string(),
        file_hash,
        cross_document_surface_sha256,
        symbols,
        extracted_at: Utc::now(),
        has_platform_cfg,
        capture_gaps,
    })
}

/// Extract a file from disk.
///
/// `root` is the workspace root used to compute a relative `file_path` stored
/// in the output. Pass `Path::new("")` when no root is available (the full
/// path will be stored as-is).
pub fn extract_file(path: &Path, root: &Path) -> Result<ExtractorOutput, ExtractorError> {
    let source = std::fs::read_to_string(path)?;
    let rel = path.strip_prefix(root).unwrap_or(path);
    let file_path = rel.to_string_lossy().to_string();
    extract_source(&source, &file_path)
}

/// Extract already-read UTF-8 source using the language registered for
/// `file_path`.
///
/// Filesystem authority belongs to the caller. This entry point lets bound
/// operations read source exactly once through a project capability and then
/// parse those same bytes instead of reopening a path after admission.
pub fn extract_source(source: &str, file_path: &str) -> Result<ExtractorOutput, ExtractorError> {
    // ADR-0024: dispatch to the registered extractor by file extension —
    // `.rs` → `RustExtractor`, `.go` → `GoExtractor` (WU-0023 P3a). The walks
    // filter to registered extensions; the Rust path stays byte-identical to
    // the pre-refactor `extract_rust_symbols`.
    let ext = Path::new(file_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("");
    let extractor = crate::language::extractor_for_extension(ext).ok_or_else(|| {
        ExtractorError::UnsupportedLanguage {
            ext: ext.to_string(),
        }
    })?;
    extractor.extract(source, file_path)
}

/// Extract multiple files, collecting per-file results.
///
/// Unlike [`extract_directory`], this takes explicit paths rather than
/// walking a directory tree. Each path is extracted independently; failures
/// are returned per-file so that a single bad file does not abort the batch.
pub fn extract_files(
    paths: &[PathBuf],
    root: &Path,
) -> Vec<Result<ExtractorOutput, ExtractorError>> {
    paths.iter().map(|p| extract_file(p, root)).collect()
}

/// Recursively extract all files under `dir` whose extension is registered in
/// the [`crate::language`] registry (`.rs` and `.go`).
///
/// `dir` is used both as the walk root and as the prefix to strip, so all
/// resulting `file_path` values are relative to `dir`.
pub fn extract_directory(dir: &Path) -> Result<Vec<ExtractorOutput>, ExtractorError> {
    let mut results = Vec::new();
    collect_rs_files(dir, dir, &mut results)?;
    Ok(results)
}

fn collect_rs_files(
    walk_root: &Path,
    root: &Path,
    results: &mut Vec<ExtractorOutput>,
) -> Result<(), ExtractorError> {
    use ignore::WalkBuilder;

    let walker = WalkBuilder::new(walk_root)
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .build();

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(error = %e, "skipping unreadable entry during extraction walk");
                continue;
            }
        };
        let path = entry.path();
        // ADR-0024: THE WALK is driven by the registry, not a hardcoded `rs`
        // (WU-0023 P3a registered `.go` as the second extension).
        if path.is_file()
            && path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(crate::language::is_registered_extension)
        {
            results.push(extract_file(path, root)?);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Node extraction helpers
// ---------------------------------------------------------------------------

/// Map tree-sitter node kind strings to our [`SymbolKind`].
fn node_kind_to_symbol_kind(kind: &str) -> Option<SymbolKind> {
    match kind {
        "function_item" | "function_signature_item" => Some(SymbolKind::Function),
        "struct_item" | "union_item" => Some(SymbolKind::Struct),
        "enum_item" => Some(SymbolKind::Enum),
        "impl_item" => Some(SymbolKind::Impl),
        "trait_item" => Some(SymbolKind::Trait),
        "const_item" => Some(SymbolKind::Const),
        "static_item" => Some(SymbolKind::Static),
        "mod_item" => Some(SymbolKind::Module),
        "use_declaration" => Some(SymbolKind::Use),
        "type_item" => Some(SymbolKind::TypeAlias),
        "macro_definition" => Some(SymbolKind::Macro),
        _ => None,
    }
}

/// Check whether a tree-sitter node has a `#[cfg(test)]` attribute.
///
/// Looks at preceding siblings for `attribute_item` nodes whose text contains
/// `cfg(test)` or `cfg(any(test`.
fn has_cfg_test_attribute(node: &tree_sitter::Node<'_>, src: &[u8]) -> bool {
    let mut sibling = node.prev_sibling();
    while let Some(sib) = sibling {
        if sib.kind() == "attribute_item" {
            let text = sib.utf8_text(src).unwrap_or("");
            if text.contains("cfg(test)") || text.contains("cfg(any(test") {
                return true;
            }
        } else if sib.kind() != "line_comment" && sib.kind() != "block_comment" {
            // Stop scanning once we pass comments/attributes into real code.
            break;
        }
        sibling = sib.prev_sibling();
    }
    false
}

/// Check whether a tree-sitter node carries a test-runner attribute directly
/// on the item (it is a test ROOT).
///
/// Looks at preceding siblings for `attribute_item` nodes whose attribute path
/// is `test` or ends in `::test` — covering `#[test]`, `#[tokio::test]`,
/// `#[async_std::test]`, `#[rstest]`-style `::test` variants, etc. Deliberately
/// distinct from [`has_cfg_test_attribute`], which matches `cfg(test)` (a
/// MODULE/file test-scope signal) and never the per-item `#[test]` attribute.
///
/// Matches the attribute *path* (not arbitrary substrings) so a `#[cfg(test)]`
/// or a `#[should_panic]` does not falsely register as a test root, and a doc
/// comment mentioning "test" cannot trip it.
fn has_test_attribute_sibling(node: &tree_sitter::Node<'_>, src: &[u8]) -> bool {
    let mut sibling = node.prev_sibling();
    while let Some(sib) = sibling {
        if sib.kind() == "attribute_item" {
            let text = sib.utf8_text(src).unwrap_or("");
            // Strip the `#[ ... ]` wrapper and isolate the attribute path
            // (everything up to the first `(`, `]`, or whitespace).
            let inner = text
                .trim_start_matches("#[")
                .trim_start_matches("#![")
                .trim_start();
            let path: &str = inner
                .split(|c: char| c == '(' || c == ']' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .trim();
            if path == "test" || path.ends_with("::test") {
                return true;
            }
        } else if sib.kind() != "line_comment" && sib.kind() != "block_comment" {
            // Stop scanning once we pass comments/attributes into real code.
            break;
        }
        sibling = sib.prev_sibling();
    }
    false
}

/// Exact path intent attached to one Rust module item.
///
/// A direct `#[path = "..."]` is carried as source data. Conditional path
/// attributes and valid string spellings this bounded parser cannot decode are
/// explicit unresolved facts, never permission to fall back to conventional
/// filenames.
fn module_document_target(node: &tree_sitter::Node<'_>, src: &[u8]) -> StructuralDocumentTarget {
    let mut result = StructuralDocumentTarget::LanguageDefault;
    let mut sibling = node.prev_sibling();
    while let Some(candidate) = sibling {
        if candidate.kind() == "attribute_item" {
            let Some(attribute) = candidate.named_child(0) else {
                return StructuralDocumentTarget::Unresolved;
            };
            let Some(path_node) = attribute.named_child(0) else {
                return StructuralDocumentTarget::Unresolved;
            };
            let path = path_node.utf8_text(src).unwrap_or("");
            if path == "path" {
                let Some(value) = attribute.child_by_field_name("value") else {
                    return StructuralDocumentTarget::Unresolved;
                };
                let Some(path) = simple_rust_path_literal(value.utf8_text(src).unwrap_or(""))
                else {
                    return StructuralDocumentTarget::Unresolved;
                };
                if !matches!(result, StructuralDocumentTarget::LanguageDefault) {
                    return StructuralDocumentTarget::Unresolved;
                }
                result = StructuralDocumentTarget::ExplicitRelativePath(path);
            } else if path == "cfg_attr"
                && attribute
                    .utf8_text(src)
                    .unwrap_or("")
                    .split(|character: char| !(character == '_' || character.is_alphanumeric()))
                    .any(|token| token == "path")
            {
                return StructuralDocumentTarget::Unresolved;
            }
        } else if candidate.kind() != "line_comment" && candidate.kind() != "block_comment" {
            break;
        }
        sibling = candidate.prev_sibling();
    }
    result
}

fn simple_rust_path_literal(literal: &str) -> Option<String> {
    if let Some(content) = literal
        .strip_prefix('"')
        .and_then(|literal| literal.strip_suffix('"'))
    {
        return (!content.contains('\\')).then(|| content.to_owned());
    }
    let quote = literal.find('"')?;
    let prefix = literal.get(..quote)?;
    if !prefix.starts_with('r') || !prefix[1..].bytes().all(|byte| byte == b'#') {
        return None;
    }
    let suffix = format!("\"{}", &prefix[1..]);
    literal
        .get(quote + 1..)?
        .strip_suffix(&suffix)
        .map(str::to_owned)
}

/// Scan an item's preceding `attribute_item` siblings for entry-point / retain
/// attributes (WU-0015 Leg J / OQ-RETAIN-ATTRIBUTE-ENTRYPOINT-BLINDNESS).
///
/// Mirrors [`has_test_attribute_sibling`]'s sibling walk, but accumulates a
/// [`EntryRetainFlags`] bitmask over the retain-relevant attribute PATHs:
/// `#[no_mangle]` → `NO_MANGLE`, `#[export_name = "…"]` → `EXPORT_NAME`,
/// `#[used]` → `USED`, and `#[allow(…)]` → `ALLOW_DEAD_CODE` iff the `allow(…)`
/// arg list carries the `dead_code` token.
///
/// Handles the edition-2024 `#[unsafe(no_mangle)]` idiom by unwrapping a leading
/// `unsafe(` safety wrapper (this workspace is edition 2024): without the unwrap
/// the isolated path would read `unsafe` and the `no_mangle` root would be MISSED
/// → a false `Dead` classification (the damaging direction). `link_name` (an
/// EXTERN import name, not our deletable def) and `cfg_attr(…)`-wrapped
/// attributes are deliberately NOT chased (out of scope for Leg J).
fn scan_entry_retain_attrs(node: &tree_sitter::Node<'_>, src: &[u8]) -> EntryRetainFlags {
    let mut mask: u8 = 0;
    let mut sibling = node.prev_sibling();
    while let Some(sib) = sibling {
        if sib.kind() == "attribute_item" {
            let text = sib.utf8_text(src).unwrap_or("");
            // Strip the `#[ … ]` / `#![ … ]` wrapper.
            let inner = text
                .trim_start_matches("#[")
                .trim_start_matches("#![")
                .trim_start();
            // Unwrap an edition-2024 `unsafe( … )` safety wrapper so
            // `#[unsafe(no_mangle)]` reads its inner path, not `unsafe` (fix #1).
            let inner = inner.strip_prefix("unsafe(").map_or(inner, str::trim_start);
            // Isolate the attribute PATH — everything up to the first delimiter
            // (`(`, `)`, `]`, `=`, or whitespace).
            let path = inner
                .split(|c: char| c == '(' || c == ')' || c == ']' || c == '=' || c.is_whitespace())
                .next()
                .unwrap_or("")
                .trim();
            match path {
                "no_mangle" => mask |= EntryRetainFlags::NO_MANGLE,
                "export_name" => mask |= EntryRetainFlags::EXPORT_NAME,
                "used" => mask |= EntryRetainFlags::USED,
                // Token-scan the `allow( … )` arg list for `dead_code` so BOTH
                // `#[allow(dead_code)]` and `#[allow(unused, dead_code)]` match
                // (fix #3): split on non-identifier bytes and require a WHOLE-token
                // match (so `not_dead_code` does not false-match).
                "allow"
                    if inner
                        .split(|c: char| !(c == '_' || c.is_alphanumeric()))
                        .any(|t| t == "dead_code") =>
                {
                    mask |= EntryRetainFlags::ALLOW_DEAD_CODE;
                }
                _ => {}
            }
        } else if sib.kind() != "line_comment" && sib.kind() != "block_comment" {
            // Stop scanning once we pass comments/attributes into real code.
            break;
        }
        sibling = sib.prev_sibling();
    }
    EntryRetainFlags::from_bits(mask)
}

/// Extract a single node and, for `impl` blocks, recurse into methods.
fn extract_node(
    node: &tree_sitter::Node<'_>,
    src: &[u8],
    parent_name: Option<&str>,
    inline_module_path: Option<&[String]>,
    parent_is_test: bool,
    symbols: &mut Vec<CodeSymbol>,
) {
    let kind_str = node.kind();
    let Some(sym_kind) = node_kind_to_symbol_kind(kind_str) else {
        return;
    };

    // Determine if this node is test-only: either inherited from parent or
    // this node itself carries #[cfg(test)].
    let is_test_only = parent_is_test || has_cfg_test_attribute(node, src);

    // Determine if this node is a test ROOT: it carries a `#[test]`-style
    // runner attribute directly. Independent of `is_test_only` — a `#[test] fn`
    // in a production file is a test root but not test-only.
    let is_test_root = has_test_attribute_sibling(node, src);

    // WU-0015 Leg J: capture entry-point / retain attributes (`#[no_mangle]` /
    // `#[export_name]` / `#[used]` / `#[allow(dead_code)]`) from the preceding
    // attribute siblings, mirroring the test-root sibling scan above.
    let entry_retain = scan_entry_retain_attrs(node, src);

    let name = extract_name(node, src, sym_kind);
    let visibility = extract_visibility(node, src);
    let signature = extract_signature(node, src);
    let doc_comment = extract_doc_comment(node, src);
    let content_hash = {
        let text = node.utf8_text(src).unwrap_or("");
        blake3::hash(text.as_bytes()).to_hex().to_string()
    };

    // EC-3 (WU-0001): field types + field symbols for data types. Struct covers
    // named structs, tuple structs (ordered fields), and unions (union_item now
    // maps to Struct); enums descend into their variants (variant-qualified).
    let (field_types, field_symbols) = match sym_kind {
        SymbolKind::Struct => (
            extract_struct_field_types(node, src),
            extract_struct_fields(node, src, &name, is_test_only),
        ),
        SymbolKind::Enum => extract_enum_data(node, src, &name, is_test_only),
        _ => (Vec::new(), Vec::new()),
    };

    // F2 (WU-0009 / ADR-0030): serde field-attribute helper/module PATHs, carried
    // on the STRUCT symbol so the edge builder emits `struct -> References ->
    // helper` (closing the serde false-DEAD class). Only structs carry these.
    let serde_refs = if sym_kind == SymbolKind::Struct {
        extract_struct_serde_refs(node, src)
    } else {
        Vec::new()
    };

    // Extract supertrait bounds for trait definitions.
    let supertraits = if sym_kind == SymbolKind::Trait {
        extract_supertraits(node, src)
    } else {
        Vec::new()
    };

    // Detect whether this function/method has a body block.
    // In tree-sitter-rust: `function_item` has a body, `function_signature_item`
    // does not. This distinguishes trait default (provided) methods from
    // required (signature-only) methods.
    let has_body = kind_str == "function_item";

    let mut relations = field_types
        .into_iter()
        .map(|target| StructuralRelation::FieldOf { target })
        .chain(
            serde_refs
                .into_iter()
                .map(|target| StructuralRelation::References { target }),
        )
        .chain(
            supertraits
                .into_iter()
                .map(|target| StructuralRelation::Extends { target }),
        )
        .collect::<Vec<_>>();
    if sym_kind == SymbolKind::Use {
        relations.push(StructuralRelation::References {
            target: name.clone(),
        });
    }
    if sym_kind == SymbolKind::Impl {
        relations.extend(extract_impl_relations(node, src));
    }
    if sym_kind == SymbolKind::Module && node.child_by_field_name("body").is_none() {
        relations.push(StructuralRelation::ContainsDocument {
            inline_path: inline_module_path.unwrap_or_default().to_vec(),
            target: inline_module_path.map_or(StructuralDocumentTarget::Unresolved, |_| {
                module_document_target(node, src)
            }),
        });
    }

    symbols.push(CodeSymbol {
        name: name.clone(),
        kind: sym_kind,
        span: (node.start_byte(), node.end_byte()),
        line_range: (node.start_position().row, node.end_position().row),
        signature,
        doc_comment,
        content_hash,
        visibility,
        parent: parent_name.map(String::from),
        is_test_only,
        is_test_root,
        has_body,
        relations,
        entry_retain,
    });

    // EC-3: attach the extracted field symbols (empty for non-data types).
    symbols.extend(field_symbols);

    // Rust permits item declarations anywhere an item statement is legal,
    // including nested blocks and const/static initializer expressions. Walk
    // every non-item descendant uniformly so the structural population stays
    // symmetric with the normalizer's whole-tree callable census. Once an item
    // is found, its own `extract_node` call owns that subtree; this both gives
    // deeper items their immediate item parent and prevents duplicates.
    // EC-1 (WU-0001): thread the QUALIFIED parent path to children so a nested
    // child's `parent` matches its parent node's qualified_name; otherwise the
    // Contains edge is dropped (edge_builder Phase-2 looks the parent up by id).
    let qualified = parent_name.map_or_else(|| name.clone(), |p| format!("{p}::{name}"));
    let child_inline_module_path =
        if sym_kind == SymbolKind::Module && node.child_by_field_name("body").is_some() {
            inline_module_path.and_then(|path| {
                let mut path = path.to_vec();
                match module_document_target(node, src) {
                    StructuralDocumentTarget::LanguageDefault => path.push(name.clone()),
                    StructuralDocumentTarget::ExplicitRelativePath(explicit) => path.push(explicit),
                    StructuralDocumentTarget::Unresolved => return None,
                }
                Some(path)
            })
        } else {
            None
        };
    extract_nested_items(
        node,
        src,
        &qualified,
        child_inline_module_path.as_deref(),
        is_test_only,
        symbols,
    );
}

/// Walk non-item syntax below an extracted item until another item declaration
/// is found. Rust permits local items in function bodies, initializer blocks,
/// and other nested expressions. Once an item is found,
/// [`extract_node`] owns its subtree so methods, modules, and further local
/// functions are not emitted twice.
fn extract_nested_items(
    container: &tree_sitter::Node<'_>,
    src: &[u8],
    function_parent: &str,
    inline_module_path: Option<&[String]>,
    parent_is_test: bool,
    symbols: &mut Vec<CodeSymbol>,
) {
    let mut cursor = container.walk();
    for child in container.children(&mut cursor) {
        if node_kind_to_symbol_kind(child.kind()).is_some() {
            extract_node(
                &child,
                src,
                Some(function_parent),
                inline_module_path,
                parent_is_test,
                symbols,
            );
        } else {
            extract_nested_items(
                &child,
                src,
                function_parent,
                inline_module_path,
                parent_is_test,
                symbols,
            );
        }
    }
}

/// Extract the name of a symbol from its tree-sitter node.
fn extract_name(node: &tree_sitter::Node<'_>, src: &[u8], kind: SymbolKind) -> String {
    match kind {
        SymbolKind::Function
        | SymbolKind::CallableValue
        | SymbolKind::Method
        | SymbolKind::Constructor
        | SymbolKind::Const
        | SymbolKind::Static
        | SymbolKind::Variable
        | SymbolKind::Macro
        | SymbolKind::Struct
        | SymbolKind::Class
        | SymbolKind::Enum
        | SymbolKind::Trait
        | SymbolKind::Interface
        | SymbolKind::TypeAlias
        | SymbolKind::Module
        | SymbolKind::Namespace => node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(src).ok())
            .unwrap_or("<anonymous>")
            .to_string(),
        SymbolKind::Impl => {
            // For impl blocks, extract the type name (possibly with trait).
            // Pattern: `impl Trait for Type` or `impl Type`
            extract_impl_name(node, src)
        }
        SymbolKind::Use | SymbolKind::Import | SymbolKind::Export => {
            // Use declarations: extract the full path.
            node.child_by_field_name("argument")
                .and_then(|n| n.utf8_text(src).ok())
                .unwrap_or_else(|| {
                    // Fallback: extract text between `use ` and `;`
                    node.utf8_text(src)
                        .unwrap_or("use ?")
                        .trim_start_matches("use ")
                        .trim_end_matches(';')
                        .trim()
                })
                .to_string()
        }
        SymbolKind::Field | SymbolKind::Property | SymbolKind::IndexSignature => node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(src).ok())
            .unwrap_or("<anonymous>")
            .to_string(),
        SymbolKind::CallSignature => "<call>".to_string(),
        SymbolKind::ConstructSignature => "new".to_string(),
        SymbolKind::StaticBlock => "<static>".to_string(),
    }
}

/// Extract the name for an `impl` block (e.g. `impl Foo` or `impl Bar for Foo`).
fn extract_impl_name(node: &tree_sitter::Node<'_>, src: &[u8]) -> String {
    // EC-2 (WU-0001): field-driven extraction handles ALL self-type kinds
    // (reference, tuple, array, primitive, pointer, dyn) — never the 'impl ?'
    // sentinel that collapsed distinct non-nominal impls onto one node.
    let type_text = node
        .child_by_field_name("type")
        .and_then(|n| n.utf8_text(src).ok())
        .map(|t| t.trim().to_string());
    let trait_text = node
        .child_by_field_name("trait")
        .and_then(|n| n.utf8_text(src).ok())
        .map(|t| t.trim().to_string());

    match (trait_text, type_text) {
        (Some(tr), Some(ty)) => format!("impl {tr} for {ty}"),
        (None, Some(ty)) => format!("impl {ty}"),
        // No resolvable self-type field — non-panicking fallback.
        _ => "impl ?".to_string(),
    }
}

/// Convert Rust's `impl` syntax into language-neutral relationship facts while
/// the exact AST fields are still available. The graph builder must not need to
/// reverse-parse a display name such as `impl Trait for Type`.
fn extract_impl_relations(node: &tree_sitter::Node<'_>, src: &[u8]) -> Vec<StructuralRelation> {
    let implementation = node
        .child_by_field_name("type")
        .and_then(|child| child.utf8_text(src).ok())
        .and_then(nominal_impl_target);
    let abstraction = node
        .child_by_field_name("trait")
        .and_then(|child| child.utf8_text(src).ok())
        .and_then(nominal_impl_target);

    let mut relations = Vec::new();
    if let Some(target) = implementation.clone() {
        relations.push(StructuralRelation::ContainedBy { target });
    }
    if let Some(abstraction) = abstraction {
        relations.push(StructuralRelation::Implements {
            abstraction,
            implementation,
            // Rust explicitly names the implemented trait, so an unresolved
            // local target may safely become a Rust-owned external anchor.
            synthesize_external: true,
        });
    }
    relations
}

fn nominal_impl_target(text: &str) -> Option<String> {
    let text = text.trim();
    let head = text
        .find('<')
        .map_or(text, |index| text[..index].trim_end());
    (!head.is_empty() && head != "?").then(|| head.to_string())
}

/// Extract visibility from a node (looks for a `visibility_modifier` child).
fn extract_visibility(node: &tree_sitter::Node<'_>, src: &[u8]) -> Visibility {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "visibility_modifier" {
            let text = child.utf8_text(src).unwrap_or("pub");
            return parse_visibility(text);
        }
    }
    Visibility::Private
}

/// Parse a visibility modifier string.
fn parse_visibility(text: &str) -> Visibility {
    let trimmed = text.trim();
    if trimmed == "pub" {
        Visibility::Public
    } else if trimmed == "pub(crate)" {
        Visibility::PubCrate
    } else if trimmed == "pub(super)" {
        Visibility::PubSuper
    } else if trimmed.starts_with("pub(in ") {
        let path = trimmed
            .trim_start_matches("pub(in ")
            .trim_end_matches(')')
            .to_string();
        Visibility::PubIn(path)
    } else {
        // Fallback for any other pub(...) pattern
        Visibility::Public
    }
}

/// Extract the signature of a symbol (text before the body block).
fn extract_signature(node: &tree_sitter::Node<'_>, src: &[u8]) -> String {
    let full_text = node.utf8_text(src).unwrap_or("");

    // EC-6 (WU-0001): only strip the body for brace-BODIED item kinds. For
    // const/static/type/use the first `{` may belong to an initializer
    // (e.g. `const X: Foo = Foo { a: 1 };`), not a body block.
    let brace_bodied = matches!(
        node.kind(),
        "function_item"
            | "struct_item"
            | "enum_item"
            | "impl_item"
            | "trait_item"
            | "mod_item"
            | "union_item"
            // EC-6 fix-2 (audit MEDIUM): macro_definition has a `{}` body too —
            // without this its signature was the whole body, not `macro_rules! name`.
            | "macro_definition"
    );
    if brace_bodied && let Some(brace_pos) = full_text.find('{') {
        let sig = full_text[..brace_pos].trim();
        if !sig.is_empty() {
            return sig.to_string();
        }
    }

    // For short items (use, const without block), take the full text.
    // EC-6: char-boundary-safe truncation — `&full_text[..200]` panics when byte
    // 200 splits a multi-byte codepoint (a library no-panic-rule violation).
    if full_text.len() > 200 {
        let end = full_text
            .char_indices()
            .nth(200)
            .map_or(full_text.len(), |(i, _)| i);
        format!("{}...", &full_text[..end])
    } else {
        full_text.to_string()
    }
}

/// Extract the doc comment preceding a node (consecutive `///` or `//!` lines).
fn extract_doc_comment(node: &tree_sitter::Node<'_>, src: &[u8]) -> Option<String> {
    let mut doc_lines = Vec::new();
    let mut current = node.prev_sibling();

    while let Some(sibling) = current {
        let kind = sibling.kind();
        if kind == "line_comment" {
            let text = sibling.utf8_text(src).unwrap_or("");
            if text.starts_with("///") || text.starts_with("//!") {
                doc_lines.push(text.to_string());
                current = sibling.prev_sibling();
                continue;
            }
        }
        // Also handle attribute-like doc comments and blank lines
        if kind == "attribute_item" {
            // e.g. #[doc = "..."] -- skip over and continue looking for doc comments
            current = sibling.prev_sibling();
            continue;
        }
        break;
    }

    if doc_lines.is_empty() {
        return None;
    }

    // Reverse because we collected bottom-up.
    doc_lines.reverse();

    // Strip the `/// ` prefix for cleaner output.
    let cleaned: Vec<String> = doc_lines
        .iter()
        .map(|line| strip_doc_prefix(line.trim_end()))
        .collect();

    Some(cleaned.join("\n"))
}

/// Strip doc-comment prefixes (`///`, `//!`) from a line.
fn strip_doc_prefix(line: &str) -> String {
    // Try prefixes in order from most specific to least.
    for prefix in &["/// ", "///", "//! ", "//!"] {
        if let Some(stripped) = line.strip_prefix(prefix) {
            return stripped.to_string();
        }
    }
    line.to_string()
}

// ---------------------------------------------------------------------------
// Struct field type extraction (for FieldOf edges)
// ---------------------------------------------------------------------------

/// Extract the resolved type names from a struct's field declarations.
///
/// For each `field_declaration` inside the struct's `field_declaration_list`,
/// extracts the type annotation and unwraps common generic wrappers:
/// `Arc<dyn Trait>` -> `Trait`, `Option<T>` -> `T`, `Vec<T>` -> `T`,
/// `Box<dyn T>` -> `T`, `HashMap<K, V>` -> `K`, `V`.
///
/// Returns a deduplicated list of resolved type names.
fn extract_struct_field_types(node: &tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut types = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "ordered_field_declaration_list" {
            // EC-3 (WU-0001): tuple-struct positional fields — the type is a
            // direct child of the ordered list (no field_declaration wrapper).
            let mut inner = child.walk();
            for fc in child.children(&mut inner) {
                if is_type_node(fc.kind())
                    && let Ok(type_text) = fc.utf8_text(src)
                {
                    types.extend(unwrap_generic_types(type_text.trim()));
                }
            }
        } else if child.kind() == "field_declaration_list" {
            let mut inner_cursor = child.walk();
            for field in child.children(&mut inner_cursor) {
                if field.kind() == "field_declaration" {
                    // The type is typically the last named child of the field_declaration.
                    // Walk children looking for a type node.
                    let mut field_cursor = field.walk();
                    for fc in field.children(&mut field_cursor) {
                        let kind = fc.kind();
                        // Type annotations in tree-sitter Rust appear as various
                        // type nodes: type_identifier, generic_type, reference_type,
                        // scoped_type_identifier, dynamic_type, etc.
                        if is_type_node(kind)
                            && let Ok(type_text) = fc.utf8_text(src)
                        {
                            let resolved = unwrap_generic_types(type_text.trim());
                            types.extend(resolved);
                        }
                    }
                }
            }
        }
    }
    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    types.retain(|t| seen.insert(t.clone()));
    types
}

// ---------------------------------------------------------------------------
// Serde attribute reference extraction (F2, WU-0009 / ADR-0030)
// ---------------------------------------------------------------------------

/// Serde field-attribute meta-item keys that name a helper-FUNCTION or MODULE
/// PATH (the F2 target shapes). Kept as a small named table so a future
/// Go-struct-tag / Python-decorator extractor can add analogous keys without
/// touching the edge-emission path — right-sized per ADR-0030 (serde-specific
/// for the floor, merely *shaped* general; NOT a speculative multi-language
/// registry / `LanguageExtractor` trait, which is explicitly YAGNI here).
///
/// `default`/`with` are the live target shapes in this repo (14 + 7 sites);
/// `deserialize_with`/`serialize_with` (0 sites today) are included because they
/// are the same path-naming serde shape and cost nothing to admit.
const SERDE_REF_KEYS: &[&str] = &["with", "default", "deserialize_with", "serialize_with"];

/// Parse the helper/module PATH strings out of a single serde attribute's text.
///
/// `attr_text` is the raw `#[...]` attribute item text (e.g.
/// `#[serde(default = "default_retries", rename = "r")]`). Returns the PATH
/// string for every [`SERDE_REF_KEYS`] meta-item of the form `key = "PATH"`.
///
/// Deliberately a small string scan, NOT a full meta-item parser: serde
/// attribute values are always string literals here, and the key set is fixed.
/// A bare `#[serde(default)]` (no `= "..."`) names no PATH and yields nothing —
/// the 154+ bare defaults in this repo are correctly NOT F2 sites.
fn parse_serde_ref_paths(attr_text: &str) -> Vec<String> {
    // Only `#[serde(...)]` attributes carry these keys; cheap early-out keeps
    // the per-field scan from inspecting `#[cfg(...)]`, `#[doc = ...]`, etc.
    if !attr_text.contains("serde") {
        return Vec::new();
    }
    let mut paths = Vec::new();
    for key in SERDE_REF_KEYS {
        // Scan every occurrence of `key` so multiple keys (and repeats) are all
        // captured; match `key` followed by `=` and a double-quoted string.
        let mut search_from = 0;
        while let Some(rel) = attr_text[search_from..].find(key) {
            let key_start = search_from + rel;
            let after_key = key_start + key.len();
            search_from = after_key;

            // Guard against matching a key as a substring of a longer ident
            // (e.g. `default` inside `is_default`, or `with` inside `within`).
            // The char before must not be an identifier char.
            if attr_text[..key_start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                continue;
            }
            // Between the key and the `"` only whitespace and a single `=` are
            // allowed (so `serialize_with = "..."` matches but a key appearing
            // outside a `key = "..."` form does not).
            let rest = attr_text[after_key..].trim_start();
            let Some(rest) = rest.strip_prefix('=') else {
                continue;
            };
            let rest = rest.trim_start();
            let Some(rest) = rest.strip_prefix('"') else {
                continue;
            };
            if let Some(end) = rest.find('"') {
                let path = rest[..end].trim();
                if !path.is_empty() {
                    paths.push(path.to_string());
                }
            }
        }
    }
    paths
}

/// Collect every serde-attribute PATH named on a struct's fields.
///
/// Walks the struct's `field_declaration_list` → `field_declaration` children
/// and, for each field, scans its preceding `attribute_item` siblings — the SAME
/// sibling-scan shape as [`has_cfg_test_attribute`] / [`has_test_attribute_sibling`]
/// — extracting any serde helper/module PATH via [`parse_serde_ref_paths`].
///
/// Returns the deduplicated PATH list, carried on the STRUCT [`CodeSymbol`]
/// (`serde_refs`) for the edge builder to resolve into `References` edges.
fn extract_struct_serde_refs(node: &tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let mut refs = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "field_declaration_list" {
            continue;
        }
        let mut inner = child.walk();
        for field in child.children(&mut inner) {
            if field.kind() != "field_declaration" {
                continue;
            }
            // Scan attribute_item siblings that precede this field declaration.
            let mut sibling = field.prev_sibling();
            while let Some(sib) = sibling {
                if sib.kind() == "attribute_item" {
                    let text = sib.utf8_text(src).unwrap_or("");
                    refs.extend(parse_serde_ref_paths(text));
                } else if sib.kind() != "line_comment" && sib.kind() != "block_comment" {
                    // Stop once we pass comments/attributes into the prior field.
                    break;
                }
                sibling = sib.prev_sibling();
            }
        }
    }
    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    refs.retain(|r| seen.insert(r.clone()));
    refs
}

/// Extract struct fields as individual [`CodeSymbol`] entries.
///
/// Walks the struct's `field_declaration_list` → `field_declaration` children,
/// producing one `CodeSymbol` per field with `kind = SymbolKind::Field` and
/// `parent = Some(struct_name)`. The `signature` carries the type text so
/// display code can show `field_name: Type` without redundancy.
fn extract_struct_fields(
    node: &tree_sitter::Node<'_>,
    src: &[u8],
    parent_name: &str,
    is_test_only: bool,
) -> Vec<CodeSymbol> {
    let mut fields = Vec::new();
    let mut cursor = node.walk();

    for child in node.children(&mut cursor) {
        // EC-3 (WU-0001): tuple-struct positional fields ('0','1',...).
        if child.kind() == "ordered_field_declaration_list" {
            let mut inner = child.walk();
            let mut pos = 0usize;
            for fc in child.children(&mut inner) {
                if is_type_node(fc.kind()) {
                    let visibility = if fc
                        .prev_sibling()
                        .is_some_and(|s| s.kind() == "visibility_modifier")
                    {
                        Visibility::Public
                    } else {
                        Visibility::Private
                    };
                    let type_text = fc.utf8_text(src).unwrap_or("").trim().to_string();
                    fields.push(make_field_symbol(
                        pos.to_string(),
                        type_text,
                        parent_name,
                        is_test_only,
                        &fc,
                        src,
                        visibility,
                    ));
                    pos += 1;
                }
            }
            continue;
        }
        if child.kind() != "field_declaration_list" {
            continue;
        }
        let mut inner_cursor = child.walk();
        for field in child.children(&mut inner_cursor) {
            if field.kind() != "field_declaration" {
                continue;
            }

            // Extract field name from the field_identifier child.
            let field_name = match field.child_by_field_name("name") {
                Some(n) => match n.utf8_text(src) {
                    Ok(text) => text.to_string(),
                    Err(_) => continue,
                },
                None => continue,
            };

            // Extract the type text from the type child node.
            let type_text = field
                .child_by_field_name("type")
                .and_then(|n| n.utf8_text(src).ok())
                .unwrap_or("")
                .trim()
                .to_string();

            // Extract visibility from a leading visibility_modifier child.
            let visibility = extract_visibility(&field, src);

            // Content hash from the full field declaration text.
            let field_text = field.utf8_text(src).unwrap_or("");
            let content_hash = blake3::hash(field_text.as_bytes()).to_hex().to_string();

            let relations = unwrap_generic_types(&type_text)
                .into_iter()
                .map(|target| StructuralRelation::TypeOf { target })
                .collect();
            fields.push(CodeSymbol {
                name: field_name,
                kind: SymbolKind::Field,
                span: (field.start_byte(), field.end_byte()),
                line_range: (field.start_position().row, field.end_position().row),
                // Signature carries the type text for display (e.g., "Uuid",
                // "Option<ReachabilityClass>"). The field name is in symbol_name
                // and visibility in the visibility field.
                signature: type_text,
                doc_comment: extract_doc_comment(&field, src),
                content_hash,
                visibility,
                parent: Some(parent_name.to_string()),
                is_test_only,
                // A struct field is never a test root (no `#[test]` attr).
                is_test_root: false,
                has_body: false,
                relations,
                // A synthesized field sub-symbol carries no entry-point/retain
                // attributes of its own (WU-0015 Leg J).
                entry_retain: EntryRetainFlags::default(),
            });
        }
    }

    fields
}

/// EC-3 (WU-0001): shared constructor for a `Field` [`CodeSymbol`] (positional
/// tuple/enum-variant fields). Named struct fields build inline above.
fn make_field_symbol(
    name: String,
    type_text: String,
    parent_name: &str,
    is_test_only: bool,
    node: &tree_sitter::Node<'_>,
    src: &[u8],
    visibility: Visibility,
) -> CodeSymbol {
    let field_text = node.utf8_text(src).unwrap_or("");
    let relations = unwrap_generic_types(&type_text)
        .into_iter()
        .map(|target| StructuralRelation::TypeOf { target })
        .collect();
    CodeSymbol {
        name,
        kind: SymbolKind::Field,
        span: (node.start_byte(), node.end_byte()),
        line_range: (node.start_position().row, node.end_position().row),
        signature: type_text,
        doc_comment: None,
        content_hash: blake3::hash(field_text.as_bytes()).to_hex().to_string(),
        visibility,
        parent: Some(parent_name.to_string()),
        is_test_only,
        // A variant payload field is never a test root (no `#[test]` attr).
        is_test_root: false,
        has_body: false,
        relations,
        // A synthesized field sub-symbol carries no entry-point/retain
        // attributes of its own (WU-0015 Leg J).
        entry_retain: EntryRetainFlags::default(),
    }
}

/// EC-3 (WU-0001): extract an enum's variant payload types + per-variant `Field`
/// symbols. Fields carry a VARIANT-qualified parent (`E::V`) so two payload
/// variants' positional `0` fields are distinct (`E::V::0` vs `E::W::0`) rather
/// than colliding to `E::0` and being DuplicateNode-dropped at graph build.
fn extract_enum_data(
    node: &tree_sitter::Node<'_>,
    src: &[u8],
    enum_name: &str,
    is_test_only: bool,
) -> (Vec<String>, Vec<CodeSymbol>) {
    let mut types = Vec::new();
    let mut fields = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() != "enum_variant_list" {
            continue;
        }
        let mut variant_cursor = child.walk();
        for variant in child.children(&mut variant_cursor) {
            if variant.kind() != "enum_variant" {
                continue;
            }
            let vname = variant
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(src).ok())
                .unwrap_or("");
            let variant_parent = format!("{enum_name}::{vname}");
            let mut body_cursor = variant.walk();
            for body in variant.children(&mut body_cursor) {
                match body.kind() {
                    "ordered_field_declaration_list" => {
                        let mut inner = body.walk();
                        let mut pos = 0usize;
                        for fc in body.children(&mut inner) {
                            if is_type_node(fc.kind()) {
                                let type_text = fc.utf8_text(src).unwrap_or("").trim().to_string();
                                types.extend(unwrap_generic_types(&type_text));
                                fields.push(make_field_symbol(
                                    pos.to_string(),
                                    type_text,
                                    &variant_parent,
                                    is_test_only,
                                    &fc,
                                    src,
                                    Visibility::Public,
                                ));
                                pos += 1;
                            }
                        }
                    }
                    "field_declaration_list" => {
                        let mut inner = body.walk();
                        for field in body.children(&mut inner) {
                            if field.kind() != "field_declaration" {
                                continue;
                            }
                            let fname = match field
                                .child_by_field_name("name")
                                .and_then(|n| n.utf8_text(src).ok())
                            {
                                Some(t) => t.to_string(),
                                None => continue,
                            };
                            let type_text = field
                                .child_by_field_name("type")
                                .and_then(|n| n.utf8_text(src).ok())
                                .unwrap_or("")
                                .trim()
                                .to_string();
                            types.extend(unwrap_generic_types(&type_text));
                            fields.push(make_field_symbol(
                                fname,
                                type_text,
                                &variant_parent,
                                is_test_only,
                                &field,
                                src,
                                extract_visibility(&field, src),
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    (types, fields)
}

/// Extract supertrait names from a trait definition's bounds clause.
///
/// For `trait Foo: Clone + Send + std::fmt::Display`, returns
/// `["Clone", "Send", "Display"]`.
///
/// Uses tree-sitter's `bounds` field on `trait_item` nodes, which contains
/// a `trait_bounds` node with `type_identifier` or `scoped_type_identifier`
/// children. Lifetimes (e.g. `'static`) are skipped.
fn extract_supertraits(node: &tree_sitter::Node<'_>, src: &[u8]) -> Vec<String> {
    let Some(bounds) = node.child_by_field_name("bounds") else {
        return Vec::new();
    };

    let mut supertrait_names = Vec::new();
    let mut cursor = bounds.walk();
    for child in bounds.children(&mut cursor) {
        let kind = child.kind();
        match kind {
            "type_identifier" => {
                // Simple bound like `Clone`, `Send`.
                if let Ok(text) = child.utf8_text(src) {
                    supertrait_names.push(text.to_string());
                }
            }
            "scoped_type_identifier" => {
                // Scoped bound like `std::fmt::Display` — take the last segment.
                if let Some(name_node) = child.child_by_field_name("name")
                    && let Ok(text) = name_node.utf8_text(src)
                {
                    supertrait_names.push(text.to_string());
                }
            }
            "generic_type" => {
                // Generic bound like `Iterator<Item = Foo>` — take the type name.
                if let Some(type_node) = child.child_by_field_name("type")
                    && let Ok(text) = type_node.utf8_text(src)
                {
                    supertrait_names.push(text.to_string());
                }
            }
            // Skip lifetimes, `+` tokens, etc.
            _ => {}
        }
    }

    supertrait_names
}

/// Whether a tree-sitter node kind represents a type annotation.
fn is_type_node(kind: &str) -> bool {
    matches!(
        kind,
        "type_identifier"
            // EC-3 fix-2 (audit HIGH): primitive_type was omitted, so u8/i32/bool/...
            // tuple/enum fields were silently dropped AND misnumbered later positions.
            | "primitive_type"
            | "generic_type"
            | "reference_type"
            | "scoped_type_identifier"
            | "dynamic_type"
            | "tuple_type"
            | "unit_type"
            | "array_type"
            | "slice_type"
            | "bounded_type"
            | "pointer_type"
            | "function_type"
            | "abstract_type"
            | "qualified_type"
            | "never_type"
            | "macro_invocation"
    )
}

/// Unwrap generic wrapper types and extract the inner type names.
///
/// Handles common patterns:
/// - `Arc<dyn Trait>` -> `["Trait"]`
/// - `Option<MyType>` -> `["MyType"]`
/// - `Vec<Item>` -> `["Item"]`
/// - `Box<dyn Handler>` -> `["Handler"]`
/// - `HashMap<String, Value>` -> `["String", "Value"]`
/// - `&str` -> `["str"]`
/// - `&mut T` -> `["T"]`
/// - `MyType` -> `["MyType"]`
///
/// Filters out primitive types (`str`, `String`, `bool`, `u8`..`u128`,
/// `i8`..`i128`, `f32`, `f64`, `usize`, `isize`, `char`).
pub(crate) fn unwrap_generic_types(type_text: &str) -> Vec<String> {
    let mut results = Vec::new();
    unwrap_type_inner(type_text.trim(), &mut results);
    // Filter out primitives and common std types that are not useful graph edges.
    results.retain(|t| !is_primitive_type(t));
    results
}

fn unwrap_type_inner(s: &str, out: &mut Vec<String>) {
    let s = s.trim();
    if s.is_empty() {
        return;
    }

    // Strip reference: &T, &mut T, &'a T
    if let Some(rest) = s.strip_prefix('&') {
        let rest = rest.trim_start();
        // Skip lifetime: &'a T
        let rest = if rest.starts_with('\'') {
            rest.find(char::is_whitespace)
                .map_or(rest, |i| rest[i..].trim_start())
        } else {
            rest
        };
        let rest = rest.strip_prefix("mut ").unwrap_or(rest).trim();
        unwrap_type_inner(rest, out);
        return;
    }

    // Strip dyn prefix: dyn Trait
    if let Some(rest) = s.strip_prefix("dyn ") {
        unwrap_type_inner(rest.trim(), out);
        return;
    }

    // Handle generic types: Name<...>
    if let Some(angle_pos) = s.find('<') {
        let outer = s[..angle_pos].trim();
        let inner = &s[angle_pos + 1..];
        // Find matching closing angle bracket
        let inner = inner.strip_suffix('>').unwrap_or(inner).trim();

        // Known wrapper types whose inner types are more interesting.
        // Check both the full path and the last segment (e.g. "std::sync::Arc" -> "Arc").
        let outer_last = outer.rsplit("::").next().unwrap_or(outer);
        let is_wrapper = matches!(
            outer_last,
            "Arc"
                | "Rc"
                | "Box"
                | "Option"
                | "Vec"
                | "Mutex"
                | "RwLock"
                | "RefCell"
                | "Cell"
                | "Pin"
                | "Cow"
        );

        if is_wrapper {
            // Unwrap further
            unwrap_type_inner(inner, out);
        } else if outer_last == "HashMap" || outer_last == "BTreeMap" {
            // Both key and value types are interesting
            if let Some(comma) = find_top_level_comma(inner) {
                unwrap_type_inner(&inner[..comma], out);
                unwrap_type_inner(&inner[comma + 1..], out);
            } else {
                unwrap_type_inner(inner, out);
            }
        } else {
            // The outer type itself is interesting, plus recurse into inner
            if !outer.is_empty() {
                out.push(outer.to_string());
            }
            unwrap_type_inner(inner, out);
        }
        return;
    }

    // Handle scoped types: path::to::Type -> Type (last segment)
    if s.contains("::") {
        if let Some(last) = s.rsplit("::").next() {
            let last = last.trim();
            if !last.is_empty() && last.chars().next().is_some_and(|c| c.is_uppercase()) {
                out.push(last.to_string());
            }
        }
        return;
    }

    // Simple type name
    if !s.is_empty()
        && s.chars()
            .next()
            .is_some_and(|c| c.is_alphabetic() || c == '_')
    {
        out.push(s.to_string());
    }
}

/// Find the position of the first top-level comma (not inside angle brackets).
fn find_top_level_comma(s: &str) -> Option<usize> {
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            ',' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

/// Check if a type name is a primitive or common std type not worth tracking as an edge.
fn is_primitive_type(name: &str) -> bool {
    matches!(
        name,
        "str"
            | "String"
            | "bool"
            | "u8"
            | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "usize"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "isize"
            | "f32"
            | "f64"
            | "char"
            | "()"
            | "Self"
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn field_targets(symbol: &CodeSymbol) -> Vec<String> {
        symbol
            .relations
            .iter()
            .filter_map(|relation| match relation {
                StructuralRelation::FieldOf { target } => Some(target.clone()),
                _ => None,
            })
            .collect()
    }

    fn extends_targets(symbol: &CodeSymbol) -> Vec<String> {
        symbol
            .relations
            .iter()
            .filter_map(|relation| match relation {
                StructuralRelation::Extends { target } => Some(target.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn rust_extractor_rejects_a_recovered_partial_tree() {
        let error = extract_rust_symbols(
            "pub fn retained() -> u32 {\n    let unfinished =\n",
            "src/lib.rs",
        )
        .expect_err("a syntax-error recovery tree is not authoritative extraction");
        assert!(matches!(error, ExtractorError::IncompleteSyntax { .. }));
    }

    /// FALSIFIER: capture gaps are evidence about exact omitted constructs,
    /// not a file-level boolean. Distinct item-position syntax (including a
    /// nested item) must survive extraction as distinct, ordered kind/span
    /// records so product receipts can identify what authority is missing.
    #[test]
    fn rust_capture_gaps_preserve_exact_kind_span_and_multiplicity() {
        let source = "macro_rules! make_gen { () => {} }\n\
                      make_gen! {}\n\
                      extern crate alloc;\n\
                      mod nested { make_gen! {} }\n";
        let output = extract_rust_symbols(source, "src/lib.rs").expect("extract");
        let observed = output
            .capture_gaps
            .iter()
            .map(|gap| (gap.kind.as_str(), &source[gap.span.0..gap.span.1]))
            .collect::<Vec<_>>();

        assert_eq!(
            observed,
            vec![
                ("unexpanded_rust_item_macro", "make_gen! {}"),
                (
                    "unrepresented_rust_item:extern_crate_declaration",
                    "extern crate alloc;",
                ),
                ("unexpanded_rust_item_macro", "make_gen! {}"),
            ],
            "each omitted item-position construct must retain its grammar kind, exact byte span, and source order"
        );
    }

    /// FALSIFIER: tree-sitter wraps a semicolon-terminated item macro in an
    /// `expression_statement`, but that grammar implementation detail must not
    /// create a second product-level gap kind or obscure the macro authority
    /// that is actually unavailable.
    #[test]
    fn rust_capture_gaps_normalize_statement_wrapped_item_macros() {
        let source = "macro_rules! generate { ($name:ident) => { struct $name; } }\n\
                      generate!(Generated);\n";
        let output = extract_rust_symbols(source, "src/lib.rs").expect("extract");

        assert_eq!(
            output.capture_gaps,
            vec![StructuralCaptureGap::new(
                "unexpanded_rust_item_macro",
                (
                    source.find("generate!(Generated);").expect("macro start"),
                    source.find("generate!(Generated);").expect("macro start")
                        + "generate!(Generated);".len(),
                ),
            )],
            "semicolon wrapping must preserve the exact invocation while naming the missing macro-expansion authority"
        );
    }

    #[test]
    fn rust_capture_gaps_exclude_noise_and_expression_macros() {
        let source = "//! module documentation\n\
                      #![allow(dead_code)]\n\
                      ;\n\
                      trait Store { type Handle; fn open(&self) -> Self::Handle; }\n\
                      fn log() { println!(\"body expression\"); }\n";
        let output = extract_rust_symbols(source, "src/lib.rs").expect("extract");

        assert!(
            output.capture_gaps.is_empty(),
            "benign item-position syntax and expression-position macros are positive over-withhold controls"
        );
    }

    #[test]
    fn extract_simple_function() {
        let source = r#"
/// Adds two numbers.
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        assert_eq!(output.symbols.len(), 1);

        let sym = &output.symbols[0];
        assert_eq!(sym.name, "add");
        assert_eq!(sym.kind, SymbolKind::Function);
        assert_eq!(sym.visibility, Visibility::Public);
        assert!(sym.signature.contains("fn add(a: i32, b: i32) -> i32"));
        assert_eq!(sym.doc_comment.as_deref(), Some("Adds two numbers."));
        assert!(sym.parent.is_none());
    }

    #[test]
    fn extract_local_items_inside_a_function_body() {
        let source = r#"
trait Worker {
    fn handle(&self);
}

#[cfg(test)]
mod tests {
    #[test]
    fn exercise_local_worker() {
        struct LocalWorker;

        impl Worker for LocalWorker {
            fn handle(&self) {}
        }

        LocalWorker.handle();
    }
}
"#;
        let output = extract_rust_symbols(source, "src/lib.rs").unwrap();

        let local_struct = output
            .symbols
            .iter()
            .find(|symbol| symbol.kind == SymbolKind::Struct && symbol.name == "LocalWorker")
            .expect("local struct is part of the structural source population");
        assert_eq!(
            local_struct.parent.as_deref(),
            Some("tests::exercise_local_worker")
        );
        assert!(local_struct.is_test_only);
        assert_eq!(
            &source[local_struct.span.0..local_struct.span.1],
            "struct LocalWorker;"
        );

        let local_impl = output
            .symbols
            .iter()
            .find(|symbol| {
                symbol.kind == SymbolKind::Impl && symbol.name == "impl Worker for LocalWorker"
            })
            .expect("local impl is part of the structural source population");
        assert_eq!(
            local_impl.parent.as_deref(),
            Some("tests::exercise_local_worker")
        );
        assert!(local_impl.is_test_only);

        let local_method = output
            .symbols
            .iter()
            .find(|symbol| {
                symbol.kind == SymbolKind::Function
                    && symbol.name == "handle"
                    && symbol.parent.as_deref()
                        == Some("tests::exercise_local_worker::impl Worker for LocalWorker")
            })
            .expect("local impl method is part of the structural source population");
        assert!(local_method.is_test_only);
        assert_eq!(
            &source[local_method.span.0..local_method.span.1],
            "fn handle(&self) {}"
        );
    }

    #[test]
    fn extract_local_items_inside_nested_function_blocks() {
        let source = r#"
fn outer() {
    if let Some(value) = Some(1_u8) {
        fn field_to_json(value: u8) -> u8 {
            value
        }

        let _ = field_to_json(value);
    }
}
"#;
        let output = extract_rust_symbols(source, "src/lib.rs").unwrap();
        let local = output
            .symbols
            .iter()
            .find(|symbol| symbol.name == "field_to_json")
            .expect("an item in any nested function block is structural source");
        assert_eq!(local.kind, SymbolKind::Function);
        assert_eq!(local.parent.as_deref(), Some("outer"));
        assert_eq!(
            &source[local.span.0..local.span.1],
            "fn field_to_json(value: u8) -> u8 {\n            value\n        }"
        );
    }

    #[test]
    fn extract_local_items_inside_const_and_static_initializers() {
        let source = r#"
const SEED: u32 = {
    fn const_helper() -> u32 {
        1
    }
    const_helper()
};

static VALUE: u32 = {
    fn static_helper() -> u32 {
        2
    }
    static_helper()
};

fn outer() {
    const LOCAL: u32 = {
        fn local_const_helper() -> u32 {
            3
        }
        local_const_helper()
    };
    let _ = LOCAL;
}
"#;
        let output = extract_rust_symbols(source, "src/lib.rs").unwrap();
        let expected = [
            ("const_helper", "SEED"),
            ("static_helper", "VALUE"),
            ("local_const_helper", "outer::LOCAL"),
        ];
        for (name, parent) in expected {
            let matches = output
                .symbols
                .iter()
                .filter(|symbol| symbol.kind == SymbolKind::Function && symbol.name == name)
                .collect::<Vec<_>>();
            assert_eq!(matches.len(), 1, "{name} must be extracted exactly once");
            assert_eq!(matches[0].parent.as_deref(), Some(parent));
        }
    }

    #[test]
    fn extract_struct_with_fields() {
        let source = r#"
/// A point in 2D space.
pub struct Point {
    pub x: f64,
    pub y: f64,
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        // 1 struct + 2 field symbols.
        assert_eq!(output.symbols.len(), 3);

        let sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Struct)
            .expect("Point struct");
        assert_eq!(sym.name, "Point");
        assert_eq!(sym.visibility, Visibility::Public);
        assert!(sym.signature.contains("pub struct Point"));
        assert_eq!(sym.doc_comment.as_deref(), Some("A point in 2D space."));

        // Verify the fields were extracted.
        let field_syms: Vec<&CodeSymbol> = output
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Field)
            .collect();
        assert_eq!(field_syms.len(), 2);
        assert!(
            field_syms
                .iter()
                .any(|f| f.name == "x" && f.signature == "f64")
        );
        assert!(
            field_syms
                .iter()
                .any(|f| f.name == "y" && f.signature == "f64")
        );
    }

    #[test]
    fn extract_trait_with_methods() {
        let source = r#"
/// A trait for greetable things.
pub trait Greetable {
    /// Say hello.
    fn greet(&self) -> String;

    fn farewell(&self) -> String {
        "goodbye".to_string()
    }
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        // Trait itself + 2 methods
        assert!(
            output.symbols.len() >= 3,
            "expected >= 3 symbols, got {}",
            output.symbols.len()
        );

        let trait_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Trait)
            .unwrap();
        assert_eq!(trait_sym.name, "Greetable");
        assert_eq!(trait_sym.visibility, Visibility::Public);

        let methods: Vec<_> = output
            .symbols
            .iter()
            .filter(|s| s.parent.is_some())
            .collect();
        assert_eq!(methods.len(), 2);
        assert!(
            methods
                .iter()
                .all(|m| m.parent.as_deref() == Some("Greetable"))
        );
    }

    #[test]
    fn trait_default_vs_required_methods() {
        let source = r#"
pub trait Component {
    /// Required: implementors must provide this.
    fn handle_key_event(&self, key: u8) -> bool;

    /// Default (provided): has a body, implementors may override.
    fn handle_mouse_event(&self, x: u16, y: u16) -> bool {
        false
    }
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        let methods: Vec<_> = output
            .symbols
            .iter()
            .filter(|s| s.parent.as_deref() == Some("Component"))
            .collect();
        assert_eq!(methods.len(), 2, "expected 2 trait methods");

        let required = methods
            .iter()
            .find(|m| m.name == "handle_key_event")
            .expect("handle_key_event not found");
        assert!(
            !required.has_body,
            "handle_key_event is a required method (signature only) — has_body should be false"
        );

        let provided = methods
            .iter()
            .find(|m| m.name == "handle_mouse_event")
            .expect("handle_mouse_event not found");
        assert!(
            provided.has_body,
            "handle_mouse_event is a provided method (has body) — has_body should be true"
        );
    }

    #[test]
    fn extract_impl_block_with_methods() {
        let source = r#"
pub struct Foo;

impl Foo {
    /// Creates a new Foo.
    pub fn new() -> Self {
        Foo
    }

    fn private_method(&self) {}
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();

        let impl_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Impl)
            .unwrap();
        assert!(
            impl_sym.name.contains("Foo"),
            "impl name should contain Foo, got: {}",
            impl_sym.name
        );

        let new_method = output.symbols.iter().find(|s| s.name == "new").unwrap();
        assert_eq!(new_method.kind, SymbolKind::Function);
        assert_eq!(new_method.visibility, Visibility::Public);
        assert!(new_method.parent.is_some());
        assert!(new_method.parent.as_ref().unwrap().contains("Foo"));
        assert_eq!(
            new_method.doc_comment.as_deref(),
            Some("Creates a new Foo.")
        );

        let priv_method = output
            .symbols
            .iter()
            .find(|s| s.name == "private_method")
            .unwrap();
        assert_eq!(priv_method.visibility, Visibility::Private);
    }

    #[test]
    fn extract_file_on_real_source() {
        let temporary = tempfile::tempdir().expect("extractor fixture");
        let root = temporary.path().join("src");
        std::fs::create_dir_all(&root).expect("source root");
        let clock_path = root.join("clock.rs");
        std::fs::write(
            &clock_path,
            "pub struct Clock;\nimpl Clock { pub fn now(&self) -> u64 { 42 } }\n",
        )
        .expect("source fixture");

        let output = extract_file(&clock_path, &root).expect("extract populated source");
        assert!(!output.symbols.is_empty(), "clock.rs should have symbols");
        assert!(!output.file_hash.is_empty());
        assert_eq!(output.file_path, "clock.rs");
    }

    #[test]
    fn extract_directory_recursive() {
        let temporary = tempfile::tempdir().expect("recursive extractor fixture");
        let source_root = temporary.path().join("src");
        std::fs::create_dir_all(source_root.join("nested")).expect("nested source root");
        std::fs::write(source_root.join("lib.rs"), "mod nested;\n").expect("root source");
        std::fs::write(
            source_root.join("nested/mod.rs"),
            "pub fn nested_value() -> usize { 1 }\n",
        )
        .expect("nested source");

        let outputs = extract_directory(&source_root).expect("extract source tree");
        assert_eq!(outputs.len(), 2, "positive recursive file population");
        for output in outputs {
            assert!(!output.file_hash.is_empty());
            assert!(output.file_path.ends_with(".rs"));
        }
    }

    #[test]
    fn visibility_detection() {
        let source = r#"
pub fn public_fn() {}
pub(crate) fn crate_fn() {}
fn private_fn() {}
pub(super) fn super_fn() {}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        assert_eq!(output.symbols.len(), 4);

        let pub_fn = output
            .symbols
            .iter()
            .find(|s| s.name == "public_fn")
            .unwrap();
        assert_eq!(pub_fn.visibility, Visibility::Public);

        let crate_fn = output
            .symbols
            .iter()
            .find(|s| s.name == "crate_fn")
            .unwrap();
        assert_eq!(crate_fn.visibility, Visibility::PubCrate);

        let priv_fn = output
            .symbols
            .iter()
            .find(|s| s.name == "private_fn")
            .unwrap();
        assert_eq!(priv_fn.visibility, Visibility::Private);

        let super_fn = output
            .symbols
            .iter()
            .find(|s| s.name == "super_fn")
            .unwrap();
        assert_eq!(super_fn.visibility, Visibility::PubSuper);
    }

    #[test]
    fn source_hash_is_deterministic() {
        let source = "pub fn hello() {}";
        let out1 = extract_rust_symbols(source, "a.rs").unwrap();
        let out2 = extract_rust_symbols(source, "b.rs").unwrap();

        // File hash should be the same for identical content.
        assert_eq!(out1.file_hash, out2.file_hash);

        // Symbol content hash should also match.
        assert_eq!(out1.symbols[0].content_hash, out2.symbols[0].content_hash);

        // Different source should produce different hash.
        let out3 = extract_rust_symbols("pub fn world() {}", "c.rs").unwrap();
        assert_ne!(out1.file_hash, out3.file_hash);
    }

    #[test]
    fn extract_enum_const_use_type_alias() {
        let source = r#"
/// Colors.
pub enum Color {
    Red,
    Green,
    Blue,
}

pub const MAX_SIZE: usize = 100;

use std::collections::HashMap;

pub type MyMap = HashMap<String, String>;
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();

        let enum_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Enum)
            .unwrap();
        assert_eq!(enum_sym.name, "Color");
        assert_eq!(enum_sym.doc_comment.as_deref(), Some("Colors."));

        let const_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Const)
            .unwrap();
        assert_eq!(const_sym.name, "MAX_SIZE");

        let use_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Use)
            .unwrap();
        assert!(use_sym.name.contains("HashMap") || use_sym.name.contains("std::collections"));

        let type_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::TypeAlias)
            .unwrap();
        assert_eq!(type_sym.name, "MyMap");
    }

    #[test]
    fn extract_static_and_macro() {
        let source = r#"
pub static GLOBAL: &str = "hello";

macro_rules! my_macro {
    () => {};
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();

        let static_sym = output.symbols.iter().find(|s| s.kind == SymbolKind::Static);
        assert!(static_sym.is_some(), "should extract static item");
        assert_eq!(static_sym.unwrap().name, "GLOBAL");

        let macro_sym = output.symbols.iter().find(|s| s.kind == SymbolKind::Macro);
        assert!(macro_sym.is_some(), "should extract macro_rules");
        assert_eq!(macro_sym.unwrap().name, "my_macro");
    }

    #[test]
    fn extract_trait_impl() {
        let source = r#"
pub struct MyType;

impl std::fmt::Display for MyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MyType")
    }
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();

        let impl_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Impl)
            .unwrap();
        // Should mention both Display and MyType
        assert!(
            impl_sym.name.contains("MyType"),
            "impl name should contain MyType, got: {}",
            impl_sym.name
        );

        let fmt_method = output.symbols.iter().find(|s| s.name == "fmt").unwrap();
        assert!(fmt_method.parent.is_some());
    }

    // ── F1: Trait impl edge-case tests ──────────────────────────────────

    #[test]
    fn test_trait_impl_name_includes_trait() {
        let source = r#"
pub struct MyType;

impl std::fmt::Display for MyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MyType")
    }
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        let impl_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Impl)
            .unwrap();
        // Should produce "impl Display for MyType" or "impl std::fmt::Display for MyType"
        assert!(
            impl_sym.name.contains("Display"),
            "impl name should contain trait name 'Display', got: {}",
            impl_sym.name
        );
        assert!(
            impl_sym.name.contains("MyType"),
            "impl name should contain type name 'MyType', got: {}",
            impl_sym.name
        );
    }

    #[test]
    fn test_generic_impl_block() {
        let source = r#"
pub struct Foo<T>(T);

impl<T: std::fmt::Display> Foo<T> {
    pub fn show(&self) -> String {
        format!("{}", self.0)
    }
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        let impl_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Impl)
            .unwrap();
        // The impl name should reference Foo (possibly with generic params)
        assert!(
            impl_sym.name.contains("Foo"),
            "generic impl name should contain 'Foo', got: {}",
            impl_sym.name
        );

        // The method should be extracted with parent
        let show_method = output.symbols.iter().find(|s| s.name == "show").unwrap();
        assert!(
            show_method.parent.is_some(),
            "method in generic impl should have a parent"
        );
    }

    #[test]
    fn test_impl_scoped_trait() {
        let source = r#"
pub struct MyType;

impl std::fmt::Display for MyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hello")
    }
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        let impl_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Impl)
            .unwrap();
        // Scoped trait path: should contain the full path or at least "Display"
        assert!(
            impl_sym.name.contains("Display"),
            "scoped trait impl should reference 'Display', got: {}",
            impl_sym.name
        );
    }

    #[test]
    fn test_multiple_impl_blocks_same_type() {
        let source = r#"
pub struct Foo;

impl Foo {
    pub fn method_a(&self) {}
}

impl Foo {
    pub fn method_b(&self) {}
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        let impl_count = output
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Impl)
            .count();
        assert_eq!(impl_count, 2, "should extract two impl blocks for Foo");

        let method_a = output
            .symbols
            .iter()
            .find(|s| s.name == "method_a")
            .unwrap();
        let method_b = output
            .symbols
            .iter()
            .find(|s| s.name == "method_b")
            .unwrap();
        assert!(method_a.parent.is_some(), "method_a should have a parent");
        assert!(method_b.parent.is_some(), "method_b should have a parent");
    }

    // ── F2: Use/Import + Module edge-case tests ────────────────────────

    #[test]
    fn test_use_glob_import() {
        let source = r#"
use std::collections::*;
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        let use_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Use)
            .unwrap();
        assert!(
            use_sym.name.contains("std::collections"),
            "glob import name should contain path, got: {}",
            use_sym.name
        );
    }

    #[test]
    fn test_use_multi_import() {
        let source = r#"
use std::{io, fmt};
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        let use_count = output
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Use)
            .count();
        // At minimum, one Use symbol should be extracted for the grouped import
        assert!(
            use_count > 0,
            "multi-use should extract at least one Use symbol"
        );
    }

    #[test]
    fn test_use_aliased_import() {
        let source = r#"
use std::collections::HashMap as Map;
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        let use_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Use)
            .unwrap();
        // Should capture the aliased import path
        assert!(
            use_sym.name.contains("HashMap") || use_sym.name.contains("Map"),
            "aliased import should mention HashMap or Map, got: {}",
            use_sym.name
        );
    }

    #[test]
    fn test_nested_module_extraction() {
        let source = r#"
mod outer {
    mod inner {
        fn f() {}
    }
}
"#;
        let output = extract_rust_symbols(source, "test.rs").unwrap();
        // EC-8a (WU-0001) regression guard: the Module recursion DOES descend
        // declaration_list and extract nested items — it pins the nested-mod
        // symbol existence EC-1's Contains fix depends on. (The prior comment
        // here falsely claimed inner/f are NOT extracted.)
        let outer = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Module && s.name == "outer")
            .expect("outer module extracted");
        assert_eq!(outer.name, "outer");
        assert!(
            output
                .symbols
                .iter()
                .any(|s| s.kind == SymbolKind::Module && s.name == "inner"),
            "EC-8a: nested 'inner' module must be extracted"
        );
        let f = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Function && s.name == "f")
            .expect("EC-8a: nested fn 'f' must be extracted");
        // Suffix-robust to EC-1: parent is 'inner' pre-EC-1, 'outer::inner' post-EC-1.
        assert!(
            f.parent.as_deref().is_some_and(|p| p.ends_with("inner")),
            "EC-8a: nested fn parent must end with 'inner', got {:?}",
            f.parent
        );
    }

    #[test]
    fn ec6_extract_signature_no_panic_on_multibyte_boundary() {
        // EC-6 (WU-0001): a brace-LESS item >200 bytes with a multi-byte codepoint
        // straddling byte 200 must not panic (library no-panic rule). Brace-less so
        // it reaches the truncation (braced items return brace-stripped first).
        let src = format!("const X: &str = \"{}\";", "é".repeat(100));
        // Old code `&full_text[..200]` splits an 'é' here → panic.
        let output = extract_rust_symbols(&src, "test.rs").unwrap();
        assert!(
            output.symbols.iter().any(|s| s.name == "X"),
            "EC-6: the long const must extract without panicking"
        );
    }

    #[test]
    fn ec6_const_initializer_brace_not_stripped() {
        // EC-6 (WU-0001): a braced const initializer must NOT be truncated at the
        // first `{` (it is not a body block; const is not a brace-bodied kind).
        let output = extract_rust_symbols("const X: Foo = Foo { a: 1 };", "test.rs").unwrap();
        let c = output
            .symbols
            .iter()
            .find(|s| s.name == "X")
            .expect("const X");
        assert!(
            c.signature.contains("Foo { a: 1 }"),
            "EC-6: const initializer must keep the brace body, got: {}",
            c.signature
        );
    }

    #[test]
    fn ec3_tuple_struct_field_extracted() {
        // EC-3 (WU-0001): tuple-struct positional fields + typed relations.
        let output = extract_rust_symbols("pub struct Id(Uuid);", "test.rs").unwrap();
        let id = output
            .symbols
            .iter()
            .find(|s| s.name == "Id")
            .expect("Id struct");
        let targets = field_targets(id);
        assert!(
            targets.iter().any(|target| target == "Uuid"),
            "EC-3: tuple-struct field type must be extracted, got {targets:?}"
        );
        assert!(
            output.symbols.iter().any(|s| s.kind == SymbolKind::Field
                && s.parent.as_deref() == Some("Id")
                && s.name == "0"),
            "EC-3: tuple-struct positional Field '0' must be extracted"
        );
    }

    #[test]
    fn ec3_enum_variant_fields_variant_qualified() {
        // EC-3 + correction #3: two payload variants must yield distinct fields with
        // VARIANT-qualified parents (else '0' collides and DuplicateNode-drops one).
        let output = extract_rust_symbols("pub enum E { V(Foo), W(Bar) }", "test.rs").unwrap();
        let e = output
            .symbols
            .iter()
            .find(|s| s.name == "E")
            .expect("enum E");
        let targets = field_targets(e);
        assert!(
            targets.iter().any(|target| target == "Foo")
                && targets.iter().any(|target| target == "Bar"),
            "EC-3: enum payload types Foo+Bar must be typed relations, got {targets:?}"
        );
        let v = output.symbols.iter().any(|s| {
            s.kind == SymbolKind::Field && s.parent.as_deref().is_some_and(|p| p.ends_with("E::V"))
        });
        let w = output.symbols.iter().any(|s| {
            s.kind == SymbolKind::Field && s.parent.as_deref().is_some_and(|p| p.ends_with("E::W"))
        });
        assert!(
            v && w,
            "EC-3: both V and W variant fields must exist with variant-qualified parents"
        );
    }

    #[test]
    fn ec3_union_node_and_field() {
        // EC-3: unions must produce a node (today: zero — no union_item arm) + fields.
        let output = extract_rust_symbols("pub union U { x: u8, y: u16 }", "test.rs").unwrap();
        assert!(
            output.symbols.iter().any(|s| s.name == "U"),
            "EC-3: union U must produce a node"
        );
        assert!(
            output.symbols.iter().any(|s| s.kind == SymbolKind::Field
                && s.parent.as_deref() == Some("U")
                && s.name == "x"),
            "EC-3: union field 'x' must be extracted"
        );
    }

    #[test]
    fn ec2_non_nominal_impls_distinct_no_sentinel() {
        // EC-2 (WU-0001): non-nominal impl self-types (&T, u8, tuple) must NOT
        // collapse to the 'impl ?' sentinel; distinct impls get distinct names.
        let output = extract_rust_symbols(
            "impl Tr for &T {} impl Tr for u8 {} impl Tr for (A, B) {}",
            "test.rs",
        )
        .unwrap();
        let impls: Vec<&str> = output
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Impl)
            .map(|s| s.name.as_str())
            .collect();
        assert!(
            !impls.contains(&"impl ?"),
            "EC-2: no 'impl ?' sentinel, got {:?}",
            impls
        );
        let distinct: std::collections::HashSet<&&str> = impls.iter().collect();
        assert_eq!(
            distinct.len(),
            3,
            "EC-2: three non-nominal impls must have distinct names, got {:?}",
            impls
        );
    }

    #[test]
    fn ec3_primitive_tuple_fields_extracted_and_numbered() {
        // EC-3 fix-2 (audit HIGH): primitive-typed positional fields must be
        // extracted AND keep their true position — a skipped primitive must not
        // misnumber a following field.
        let output = extract_rust_symbols("pub struct Pair(pub u8, pub Foo);", "test.rs").unwrap();
        let sig = |n: &str| {
            output
                .symbols
                .iter()
                .find(|s| {
                    s.kind == SymbolKind::Field
                        && s.name == n
                        && s.parent.as_deref() == Some("Pair")
                })
                .map(|s| s.signature.clone())
        };
        assert_eq!(
            sig("0").as_deref(),
            Some("u8"),
            "EC-3: tuple field '0' must be u8"
        );
        assert_eq!(
            sig("1").as_deref(),
            Some("Foo"),
            "EC-3: tuple field '1' must be Foo (not misnumbered by a skipped primitive)"
        );
    }

    #[test]
    fn ec3_primitive_enum_variant_fields() {
        // EC-3 fix-2: primitive enum-variant payload fields must be extracted.
        let output = extract_rust_symbols("pub enum Op { Add(i32, i32) }", "test.rs").unwrap();
        let n = output
            .symbols
            .iter()
            .filter(|s| {
                s.kind == SymbolKind::Field
                    && s.parent.as_deref().is_some_and(|p| p.ends_with("Op::Add"))
            })
            .count();
        assert_eq!(
            n, 2,
            "EC-3: enum Op::Add(i32,i32) must yield 2 primitive variant fields"
        );
    }

    #[test]
    fn ec6_macro_signature_strips_body() {
        // EC-6 fix-2 (audit MEDIUM): a macro's signature must strip the body,
        // not emit the whole macro_rules! body.
        let output = extract_rust_symbols(
            "macro_rules! my_macro { () => {}; (x:expr) => { x }; }",
            "test.rs",
        )
        .unwrap();
        let m = output
            .symbols
            .iter()
            .find(|s| s.name == "my_macro")
            .expect("macro symbol");
        assert!(
            !m.signature.contains("=>"),
            "EC-6: macro signature must strip the body (no rule arms), got: {}",
            m.signature
        );
    }

    #[test]
    fn test_extract_files_with_small_files() {
        let dir = tempfile::TempDir::new().expect("tmpdir");
        let a = dir.path().join("a.rs");
        let b = dir.path().join("b.rs");
        std::fs::write(&a, "pub fn alpha() {}\n").expect("write a");
        std::fs::write(&b, "pub struct Beta;\n").expect("write b");

        let results = extract_files(&[a, b], dir.path());
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok(), "a.rs should parse");
        assert!(results[1].is_ok(), "b.rs should parse");
        let out_a = results[0].as_ref().expect("a");
        assert_eq!(out_a.symbols.len(), 1);
        assert_eq!(out_a.symbols[0].name, "alpha");
    }

    // ---------------------------------------------------------------
    // unwrap_generic_types tests
    // ---------------------------------------------------------------

    #[test]
    fn unwrap_simple_type() {
        assert_eq!(unwrap_generic_types("MyStruct"), vec!["MyStruct"]);
    }

    #[test]
    fn unwrap_arc_dyn_trait() {
        assert_eq!(unwrap_generic_types("Arc<dyn Embedder>"), vec!["Embedder"]);
    }

    #[test]
    fn unwrap_option() {
        assert_eq!(unwrap_generic_types("Option<GraphNode>"), vec!["GraphNode"]);
    }

    #[test]
    fn unwrap_vec() {
        assert_eq!(unwrap_generic_types("Vec<GraphEdge>"), vec!["GraphEdge"]);
    }

    #[test]
    fn unwrap_box_dyn() {
        assert_eq!(unwrap_generic_types("Box<dyn Handler>"), vec!["Handler"]);
    }

    #[test]
    fn unwrap_hashmap() {
        let mut result = unwrap_generic_types("HashMap<Uuid, NodeEnrichment>");
        result.sort();
        assert_eq!(result, vec!["NodeEnrichment", "Uuid"]);
    }

    #[test]
    fn unwrap_nested_generics() {
        assert_eq!(
            unwrap_generic_types("Arc<RwLock<KnowledgeGraph>>"),
            vec!["KnowledgeGraph"]
        );
    }

    #[test]
    fn unwrap_reference() {
        assert_eq!(unwrap_generic_types("&MyType"), vec!["MyType"]);
    }

    #[test]
    fn unwrap_filters_primitives() {
        assert!(unwrap_generic_types("String").is_empty());
        assert!(unwrap_generic_types("u64").is_empty());
        assert!(unwrap_generic_types("bool").is_empty());
        assert!(unwrap_generic_types("Option<String>").is_empty());
    }

    #[test]
    fn unwrap_scoped_type() {
        assert_eq!(
            unwrap_generic_types("std::sync::Arc<MyType>"),
            vec!["MyType"]
        );
    }

    // ---------------------------------------------------------------
    // extract_struct_field_types integration tests
    // ---------------------------------------------------------------

    #[test]
    fn extract_struct_with_field_types() {
        let src = r#"
pub struct Engine {
    graph: Arc<dyn GraphBackend>,
    config: EngineConfig,
    cache: Option<Cache>,
    name: String,
}
"#;
        let output = extract_rust_symbols(src, "test.rs").expect("parse");
        let struct_sym = output
            .symbols
            .iter()
            .find(|s| s.name == "Engine")
            .expect("Engine struct");
        let mut types = field_targets(struct_sym);
        types.sort();
        // String is filtered out as primitive; Arc is unwrapped to GraphBackend
        assert!(types.contains(&"GraphBackend".to_string()));
        assert!(types.contains(&"EngineConfig".to_string()));
        assert!(types.contains(&"Cache".to_string()));
        assert!(!types.contains(&"String".to_string()));
    }

    #[test]
    fn extract_non_struct_has_empty_field_types() {
        let src = "pub fn foo() {}";
        let output = extract_rust_symbols(src, "test.rs").expect("parse");
        let func_sym = output
            .symbols
            .iter()
            .find(|s| s.name == "foo")
            .expect("foo function");
        assert!(field_targets(func_sym).is_empty());
    }

    #[test]
    fn extract_trait_with_supertraits() {
        let src = "pub trait MyTrait: Clone + Send {\n    fn do_thing(&self);\n}\n";
        let output = extract_rust_symbols(src, "test.rs").expect("parse");
        let trait_sym = output
            .symbols
            .iter()
            .find(|s| s.name == "MyTrait" && s.kind == SymbolKind::Trait)
            .expect("MyTrait trait");
        assert_eq!(extends_targets(trait_sym), vec!["Clone", "Send"]);
    }

    #[test]
    fn extract_trait_no_supertraits() {
        let src = "trait Simple {\n    fn simple(&self);\n}\n";
        let output = extract_rust_symbols(src, "test.rs").expect("parse");
        let trait_sym = output
            .symbols
            .iter()
            .find(|s| s.name == "Simple" && s.kind == SymbolKind::Trait)
            .expect("Simple trait");
        assert!(extends_targets(trait_sym).is_empty());
    }

    #[test]
    fn extract_trait_with_scoped_supertrait() {
        let src = "trait MyDisplay: std::fmt::Display + Clone {\n    fn show(&self);\n}\n";
        let output = extract_rust_symbols(src, "test.rs").expect("parse");
        let trait_sym = output
            .symbols
            .iter()
            .find(|s| s.name == "MyDisplay" && s.kind == SymbolKind::Trait)
            .expect("MyDisplay trait");
        assert_eq!(extends_targets(trait_sym), vec!["Display", "Clone"]);
    }

    #[test]
    fn extract_non_trait_has_empty_supertraits() {
        let src = "pub struct Foo;";
        let output = extract_rust_symbols(src, "test.rs").expect("parse");
        let struct_sym = output
            .symbols
            .iter()
            .find(|s| s.name == "Foo")
            .expect("Foo struct");
        assert!(extends_targets(struct_sym).is_empty());
    }

    // ---- Struct field extraction tests ----

    #[test]
    fn extract_struct_fields_basic() {
        let source = r#"
pub struct Config {
    pub name: String,
    pub max_size: usize,
    data: Vec<u8>,
}
"#;
        let dir = tempfile::TempDir::new().expect("tempdir");
        let src = dir.path().join("fields.rs");
        std::fs::write(&src, source).expect("write");
        let output = extract_file(&src, dir.path()).expect("extract");

        // One struct + 3 fields = 4 symbols
        let struct_sym = output
            .symbols
            .iter()
            .find(|s| s.kind == SymbolKind::Struct && s.name == "Config")
            .expect("Config struct");
        assert_eq!(struct_sym.kind, SymbolKind::Struct);

        let field_syms: Vec<&CodeSymbol> = output
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Field)
            .collect();
        assert_eq!(
            field_syms.len(),
            3,
            "Expected 3 fields, got {}",
            field_syms.len()
        );

        // Verify field names
        let field_names: Vec<&str> = field_syms.iter().map(|f| f.name.as_str()).collect();
        assert!(field_names.contains(&"name"), "missing field 'name'");
        assert!(
            field_names.contains(&"max_size"),
            "missing field 'max_size'"
        );
        assert!(field_names.contains(&"data"), "missing field 'data'");

        // Verify parent is set
        for f in &field_syms {
            assert_eq!(
                f.parent.as_deref(),
                Some("Config"),
                "field {} should have parent Config",
                f.name
            );
        }

        // Verify signatures carry type text
        let name_field = field_syms.iter().find(|f| f.name == "name").unwrap();
        assert_eq!(name_field.signature, "String");

        let max_field = field_syms.iter().find(|f| f.name == "max_size").unwrap();
        assert_eq!(max_field.signature, "usize");

        let data_field = field_syms.iter().find(|f| f.name == "data").unwrap();
        assert_eq!(data_field.signature, "Vec<u8>");
    }

    #[test]
    fn extract_struct_fields_visibility() {
        let source = r#"
pub struct Mixed {
    pub public_field: i32,
    pub(crate) crate_field: bool,
    private_field: String,
}
"#;
        let dir = tempfile::TempDir::new().expect("tempdir");
        let src = dir.path().join("vis.rs");
        std::fs::write(&src, source).expect("write");
        let output = extract_file(&src, dir.path()).expect("extract");

        let field_syms: Vec<&CodeSymbol> = output
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Field)
            .collect();
        assert_eq!(field_syms.len(), 3);

        let pub_field = field_syms
            .iter()
            .find(|f| f.name == "public_field")
            .unwrap();
        assert_eq!(pub_field.visibility, Visibility::Public);

        let crate_field = field_syms.iter().find(|f| f.name == "crate_field").unwrap();
        assert_eq!(crate_field.visibility, Visibility::PubCrate);

        let priv_field = field_syms
            .iter()
            .find(|f| f.name == "private_field")
            .unwrap();
        assert_eq!(priv_field.visibility, Visibility::Private);
    }

    #[test]
    fn extract_struct_fields_complex_types() {
        let source = r#"
pub struct Engine {
    pub store: Arc<dyn MemoryStore>,
    pub config: Option<EngineConfig>,
    pub graph: parking_lot::RwLock<KnowledgeGraph>,
}
"#;
        let dir = tempfile::TempDir::new().expect("tempdir");
        let src = dir.path().join("complex.rs");
        std::fs::write(&src, source).expect("write");
        let output = extract_file(&src, dir.path()).expect("extract");

        let field_syms: Vec<&CodeSymbol> = output
            .symbols
            .iter()
            .filter(|s| s.kind == SymbolKind::Field)
            .collect();
        assert_eq!(field_syms.len(), 3);

        let store_field = field_syms.iter().find(|f| f.name == "store").unwrap();
        assert_eq!(store_field.signature, "Arc<dyn MemoryStore>");

        let config_field = field_syms.iter().find(|f| f.name == "config").unwrap();
        assert_eq!(config_field.signature, "Option<EngineConfig>");

        let graph_field = field_syms.iter().find(|f| f.name == "graph").unwrap();
        assert_eq!(graph_field.signature, "parking_lot::RwLock<KnowledgeGraph>");
    }

    // ------------------------------------------------------------------
    // WU-0003 / CL-REACH RC3 falsifiers — is_test_root capture at index time.
    // Driven end-to-end through the real producer (`extract_rust_symbols`),
    // never a hand-fabricated symbol.
    // ------------------------------------------------------------------

    /// F1 (BEHAVIORAL, red-on-HEAD): a `#[test] fn` in a PRODUCTION `.rs` file
    /// (not under `tests/`, no enclosing `#[cfg(test)] mod`) is captured as a
    /// test ROOT at index time. On HEAD this was invisible:
    /// `has_cfg_test_attribute` matches only `cfg(test)`, never `#[test]`, and
    /// no `is_test_root` field existed — so the test-root-ness was dropped.
    #[test]
    fn extractor_captures_test_root_attr_in_production_file() {
        let src = "\
#[test]
fn my_unit_test() {
    assert_eq!(1 + 1, 2);
}
";
        let out = extract_rust_symbols(src, "crates/app/src/widget.rs").expect("extract");
        let f = out
            .symbols
            .iter()
            .find(|s| s.name == "my_unit_test")
            .expect("found the test fn");
        assert!(
            f.is_test_root,
            "a #[test] fn in a production file must be captured as a test ROOT at index time"
        );
        // It is a test root but NOT test-only (no enclosing cfg(test) module / test file).
        assert!(
            !f.is_test_only,
            "a #[test] fn in a production file is a test ROOT, not test-ONLY"
        );
    }

    /// F2 (POST-SCHEMA): `is_test_root` and `is_test_only` are INDEPENDENT bits.
    /// A `#[test] fn` at file top-level is a root (not test-only); a plain helper
    /// inside `#[cfg(test)] mod tests` is test-only (not a root).
    #[test]
    fn is_test_root_distinct_from_is_test_only() {
        let src = "\
#[cfg(test)]
mod tests {
    fn helper() -> i32 { 7 }
}

#[test]
fn top_level_test() {
    assert_eq!(1, 1);
}
";
        let out = extract_rust_symbols(src, "crates/app/src/lib.rs").expect("extract");

        let helper = out
            .symbols
            .iter()
            .find(|s| s.name == "helper")
            .expect("found helper");
        assert!(
            helper.is_test_only,
            "helper inside cfg(test) mod is test-only"
        );
        assert!(
            !helper.is_test_root,
            "a test helper is NOT a test root (no #[test] attr)"
        );

        let root = out
            .symbols
            .iter()
            .find(|s| s.name == "top_level_test")
            .expect("found top_level_test");
        assert!(root.is_test_root, "#[test] fn is a test root");
        assert!(
            !root.is_test_only,
            "a top-level #[test] fn in a production file is not test-only"
        );
    }

    /// F3 (POST-SCHEMA): the detector matches `#[tokio::test]` (path ends in
    /// `::test`), not only the bare `#[test]`.
    #[test]
    fn tokio_test_attr_is_test_root() {
        let src = "\
#[tokio::test]
async fn async_test() {
    assert!(true);
}
";
        let out = extract_rust_symbols(src, "crates/app/src/lib.rs").expect("extract");
        let f = out
            .symbols
            .iter()
            .find(|s| s.name == "async_test")
            .expect("found async_test");
        assert!(
            f.is_test_root,
            "#[tokio::test] (path ends in ::test) must register as a test root"
        );
    }

    /// Guard: a `#[should_panic]` / `#[cfg(test)]` attribute must NOT falsely
    /// register a non-`#[test]` item as a test root (path-not-substring match).
    #[test]
    fn non_test_attribute_is_not_test_root() {
        let src = "\
#[cfg(test)]
fn cfg_gated_helper() -> i32 { 3 }
";
        let out = extract_rust_symbols(src, "crates/app/src/lib.rs").expect("extract");
        let f = out
            .symbols
            .iter()
            .find(|s| s.name == "cfg_gated_helper")
            .expect("found cfg_gated_helper");
        assert!(
            !f.is_test_root,
            "#[cfg(test)] alone is NOT a #[test] attribute — not a test root"
        );
    }

    // -----------------------------------------------------------------------
    // WU-0015 Leg 2 — scan_platform_cfg falsifier matrix (ADR-0036).
    //
    // The REDs are RED-for-the-right-reason: each targets a cfg shape the
    // per-item `has_cfg_test_attribute` preceding-sibling walk STRUCTURALLY
    // misses (it never inspects a fn body, never recognizes `cfg_attr`, and
    // substring-matches `cfg(test)` rather than token-scanning nested forms).
    // The GREENs are load-bearing: a bare `cfg(test)` and a POSITIVE `feature` cfg
    // must NOT trip the scan (SCIP resolves both), or Leg 3 would over-suppress
    // DEAD-authority. WU-0015 Leg C broadens the scan to ANY SCIP-strippable cfg —
    // doc/docsrs/kani/fuzzing/custom-build cfg + NEGATED feature/test — so those
    // now correctly trip it (see `cfg_scan_legc_*`).
    // -----------------------------------------------------------------------

    #[test]
    fn cfg_scan_r1_cfg_bang_in_body() {
        // `cfg!(...)` inside a fn BODY, no attribute item anywhere — the
        // sibling-walk never looks in bodies, so a naive copy returns false.
        let src = "pub fn probe() { if cfg!(windows) { do_win(); } }";
        assert!(
            scan_platform_cfg(src),
            "cfg!(windows) in a fn body must be detected"
        );
    }

    #[test]
    fn cfg_scan_r2_cfg_attr_unix() {
        // `cfg_attr(...)`, not bare `cfg(...)` — the sibling-walk matches only
        // the literal `cfg(test)` / `cfg(any(test` substrings, missing cfg_attr.
        let src = "#[cfg_attr(unix, path = \"u.rs\")]\nmod platform;";
        assert!(
            scan_platform_cfg(src),
            "cfg_attr(unix, ...) must be recognized as a platform cfg surface"
        );
    }

    #[test]
    fn cfg_scan_r3_nested_all_target_arch() {
        // Nested `all(...)` mixing a platform token with a non-platform token —
        // the scan must reach INTO the nested predicate and key on target_arch.
        let src =
            "#[cfg(all(target_arch = \"x86_64\", feature = \"simd\"))]\npub fn fast_path() {}";
        assert!(
            scan_platform_cfg(src),
            "target_arch inside nested all() must be detected"
        );
    }

    #[test]
    fn cfg_scan_r4_cfg_target_os_item() {
        // The canonical item-attribute platform cfg — the true-positive floor.
        let src = "#[cfg(target_os = \"linux\")]\npub fn only_on_linux() {}";
        assert!(
            scan_platform_cfg(src),
            "the canonical #[cfg(target_os=...)] must be detected"
        );
    }

    #[test]
    fn cfg_scan_r4_all_nine_tokens_covered() {
        // One parametric case per spec'd platform token, each inside a bare
        // `cfg(<token> ...)`, all must be true (the token-coverage floor).
        for token in [
            "target_os",
            "target_arch",
            "target_family",
            "target_pointer_width",
            "target_endian",
            "target_env",
            "target_vendor",
            "windows",
            "unix",
        ] {
            let src = format!("#[cfg({token} = \"x\")]\npub fn g() {{}}");
            assert!(
                scan_platform_cfg(&src),
                "platform token {token:?} inside cfg(...) must be detected"
            );
        }
    }

    #[test]
    fn cfg_scan_leg3b_widened_tokens_covered() {
        // WU-0015 Leg-3b (OQ-CFG-TOKEN-COMPLETENESS): the identifier-walk widens
        // beyond the original fixed 9-list — ANY `target_*` key plus `panic` and
        // `debug_assertions` mark a file platform-cfg-touching. A crate gated ONLY
        // by one of these must NOT be mis-classified cfg-CLEAN (which would make it
        // DEAD-authority-eligible in Leg 3b → a latent false-SafeDelete on a
        // host-unsatisfied symbol).
        for token in [
            "target_feature",
            "target_abi",
            "target_has_atomic",
            "target_thread_local",
            "panic",
            "debug_assertions",
        ] {
            let src = format!("#[cfg({token} = \"x\")]\npub fn g() {{}}");
            assert!(
                scan_platform_cfg(&src),
                "widened platform token {token:?} inside cfg(...) must be detected"
            );
        }
        // Bare-key form (no `= value`) and a nested all() also count.
        assert!(
            scan_platform_cfg("#[cfg(debug_assertions)]\nfn g() {}"),
            "bare debug_assertions must be detected"
        );
        assert!(
            scan_platform_cfg("#[cfg(all(panic = \"abort\", unix))]\nfn g() {}"),
            "panic inside nested all() must be detected"
        );
        // A novel `target_*` key we do not enumerate still matches (over-detection
        // is SAFE by design — under-detection is the damaging direction).
        assert!(
            scan_platform_cfg("#[cfg(target_future_thing)]\nfn g() {}"),
            "any target_* prefix matches (over-detection is safe)"
        );
    }

    #[test]
    fn cfg_scan_g1_cfg_test_only_is_false() {
        // LOAD-BEARING: the platform scan must NOT collapse into cfg(test) — a
        // test-only crate must stay DEAD-authority-eligible in Leg 3.
        let src = "#[cfg(test)]\nmod tests {\n  #[test]\n  fn t() { assert!(true); }\n}";
        assert!(
            !scan_platform_cfg(src),
            "cfg(test) / #[test] must NOT be a platform cfg"
        );
    }

    #[test]
    fn cfg_scan_g2_positive_feature_is_false() {
        // LOAD-BEARING EXCLUSION: a POSITIVE feature cfg is resolved TRUE by SCIP's
        // `--all-features` (ADR-0036 v4-1), so it never hides a symbol → NOT a
        // strippable cfg. The negated mirror is `cfg_scan_legc_negated_feature_*`.
        let src = "#[cfg(feature = \"serde\")]\npub fn with_serde() {}";
        assert!(
            !scan_platform_cfg(src),
            "a positive feature cfg must NOT be flagged (SCIP resolves --all-features)"
        );
    }

    #[test]
    fn cfg_scan_legc_negated_feature_is_true() {
        // WU-0015 Leg C (OQ-CFG-CLEAN-CONJUNCT-UNSOUND): `--all-features` makes
        // `feature = "std"` TRUE, so `not(feature = "std")` resolves FALSE → SCIP
        // STRIPS the negated arm → a caller hidden there is invisible to the graph.
        // The mirror of the positive-feature exclusion: negation flips it back IN.
        let src = "#[cfg(not(feature = \"std\"))]\npub fn no_std_path() {}";
        assert!(
            scan_platform_cfg(src),
            "a NEGATED feature cfg is SCIP-strippable and must be flagged"
        );
    }

    #[test]
    fn cfg_scan_legc_strippable_kinds_are_true() {
        // The SCIP-strippable cfg kinds beyond the platform keys: doc/docsrs/kani/
        // fuzzing sanitizer & doc cfgs, an arbitrary custom build-script rustc-cfg,
        // and `cfg(not(test))` — each hides code from a normal `--all-features`
        // SCIP build, so each must mark the file cfg-touching (WU-0015 Leg C).
        for src in [
            "#[cfg(doc)]\npub fn only_docs() {}",
            "#[cfg(docsrs)]\npub fn on_docsrs() {}",
            "#[cfg(kani)]\npub fn under_kani() {}",
            "#[cfg(fuzzing)]\npub fn under_fuzz() {}",
            "#[cfg(has_custom_thing)]\npub fn custom_build_cfg() {}",
            "#[cfg(not(test))]\npub fn prod_only() {}",
        ] {
            assert!(
                scan_platform_cfg(src),
                "SCIP-strippable cfg must be flagged: {src:?}"
            );
        }
    }

    #[test]
    fn cfg_scan_g3_clean_file_is_false() {
        // The negative baseline: a cfg-clean file → has_platform_cfg=false, so
        // its crate stays DEAD-authority-eligible.
        let src = "pub struct Point { pub x: f64 }\npub fn add(a: i32, b: i32) -> i32 { a + b }";
        assert!(
            !scan_platform_cfg(src),
            "a cfg-clean file must not be flagged platform-cfg"
        );
    }
}
