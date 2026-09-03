//! Language-extraction seam: the [`LanguageExtractor`] trait + a table-driven
//! registry keyed by file extension.
//!
//! The registry ([`REGISTRY`]) is the single source of truth for which source
//! extensions this build can extract. An adapter owns both structural emission
//! and path-sensitive grammar selection (for example TypeScript/JavaScript
//! versus TSX/JSX).
//!
//! No structural extraction site outside this module names a grammar — every
//! `tree_sitter_*` binding is reached through
//! [`LanguageExtractor::ts_language_for_path`].

use std::collections::HashSet;
use std::path::Path;

use crate::structural_ir::{ExtractorError, ExtractorOutput, StructuralDocumentTarget};

mod common;
pub mod go;
pub mod python;
pub mod rust;
pub mod typescript;

/// Exact source-syntax owner for a named callable declaration.
///
/// Semantic normalization asks the same registered language adapter that owns
/// parsing and structural extraction, rather than maintaining a second
/// language-kind switch in the provider boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedCallableSyntax {
    pub extent: (usize, usize),
    pub has_body: bool,
    pub is_package_function: bool,
    /// Whether structural extraction publishes this exact callable as a graph
    /// node. Local callable values may own call sites without becoming stable
    /// source-level deletion/query targets.
    pub structural_target: bool,
}

/// Exact source-syntax target for one explicit invocation.
///
/// Tree-sitter grammars do not share one call-node vocabulary (`call` in
/// Python, `call_expression` in Rust/Go/TypeScript). The registered adapter
/// therefore owns both call admission and the exact callee/receiver spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamedCallSyntax<'tree> {
    pub callee: tree_sitter::Node<'tree>,
    pub form: NamedCallForm,
    pub receiver_identity: Option<tree_sitter::Node<'tree>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedCallForm {
    Direct,
    Method,
    Path,
}

/// A registered structural extractor for one language.
///
/// `Send + Sync` because the index pipeline extracts in parallel: rayon iterates
/// changed files, each calling `extract_file` → a registry lookup on the shared
/// `static` [`REGISTRY`] from multiple threads. Registered extractors are
/// zero-sized unit structs, so this bound is trivially satisfied.
pub trait LanguageExtractor: Send + Sync {
    /// Canonical language name persisted on memory metadata / `FileRecord`
    /// (e.g. `"rust"`). Must match the `IndexConfig.languages` vocabulary.
    fn language(&self) -> &'static str;

    /// Whether the source document belongs to this language's test-only file
    /// population. Structural extraction, execution-root Calls evidence, and
    /// dead-code liveness must share this exact path policy.
    fn source_file_is_test(&self, _file_path: &str) -> bool {
        false
    }

    /// The tree-sitter grammar used for this source path. Returned by value (a
    /// cheap `LanguageFn`-backed handle). The path is load-bearing for language
    /// families with multiple syntaxes, such as TypeScript/JavaScript
    /// (`.ts`/`.js`) and TSX/JSX (`.tsx`/`.jsx`). This is the single sanctioned
    /// grammar-binding seam.
    fn ts_language_for_path(&self, file_path: &str) -> tree_sitter::Language;

    /// Parse and admit one source document according to this adapter's exact
    /// syntax policy. The default is fail-closed; an adapter may override only
    /// for a bounded, independently tested upstream grammar false-positive.
    /// Semantic normalization and structural extraction share this boundary so
    /// they cannot disagree about the same source bytes.
    fn parse_admitted_tree(
        &self,
        source: &str,
        file_path: &str,
    ) -> Result<tree_sitter::Tree, ExtractorError> {
        common::parse_tree(&self.ts_language_for_path(file_path), source, file_path)
    }

    /// Tree-sitter declaration kinds whose `name` field owns a callable body
    /// or callable signature in this language.
    fn named_callable_declaration_kinds(&self) -> &'static [&'static str];

    /// Tree-sitter node kinds whose body is a callable execution context but
    /// has no independently published structural caller identity. Calls in
    /// these ranges remain positive evidence, while product surfaces qualify
    /// their execution as conditional on the anonymous callable running.
    fn anonymous_callable_declaration_kinds(&self) -> &'static [&'static str];

    /// Resolve a grammar-owned call expression to its exact named callee.
    /// Dynamic/computed call targets return `None`; semantic normalization may
    /// not manufacture a named Calls edge without an independently visible
    /// source token.
    fn named_call_syntax<'tree>(
        &self,
        call: tree_sitter::Node<'tree>,
    ) -> Option<NamedCallSyntax<'tree>>;

    /// Return the executable body whose bytes may be elided from this
    /// declaration's cross-document semantic-surface identity.
    ///
    /// The default is fail-closed: a body remains part of the surface until
    /// the language adapter can prove that its declared signature fixes every
    /// fact another document may observe. Keeping this policy beside grammar
    /// ownership prevents the refresh planner from accumulating a second
    /// language-kind switch.
    fn cross_document_surface_elidable_body<'tree>(
        &self,
        _declaration: tree_sitter::Node<'tree>,
        _source: &str,
    ) -> Option<tree_sitter::Node<'tree>> {
        None
    }

    /// Whether a named callable declaration is a package-level function.
    /// This distinction is currently meaningful only to Go Calls coverage.
    fn is_package_function_declaration(&self, _kind: &str) -> bool {
        false
    }

    /// Exact structural extent published for this callable declaration. Most
    /// grammars use the declaration node itself; adapters whose source-level
    /// declaration includes an export/decorator wrapper override this hook.
    fn structural_callable_extent(&self, declaration: tree_sitter::Node<'_>) -> (usize, usize) {
        (declaration.start_byte(), declaration.end_byte())
    }

    /// Resolve one adapter-emitted document-containment fact to portable,
    /// repository-relative candidate paths. The default is deliberately empty:
    /// a shared symbol kind never grants another language's path semantics.
    fn contained_document_candidates(
        &self,
        _declaring_document: &str,
        _symbol_name: &str,
        _inline_path: &[String],
        _target: &StructuralDocumentTarget,
        _is_compilation_root: Option<bool>,
    ) -> Vec<String> {
        Vec::new()
    }

    /// Resolve an exact identifier-like node to the named callable declaration
    /// it owns. The grammar adapter owns the declaration-kind vocabulary;
    /// callers own only the generic exact-name-field invariant.
    fn named_callable_syntax(&self, name: tree_sitter::Node<'_>) -> Option<NamedCallableSyntax> {
        named_declaration_callable_syntax(self, name)
    }

    /// Extract symbols from already-read source text. `source` + `file_path` are
    /// exactly the `extract_rust_symbols` inputs; `file_path` is
    /// workspace-relative (the caller computed it).
    fn extract(&self, source: &str, file_path: &str) -> Result<ExtractorOutput, ExtractorError>;
}

pub(super) fn named_declaration_callable_syntax<E: LanguageExtractor + ?Sized>(
    extractor: &E,
    name: tree_sitter::Node<'_>,
) -> Option<NamedCallableSyntax> {
    let mut ancestor = name.parent();
    while let Some(candidate) = ancestor {
        if extractor
            .named_callable_declaration_kinds()
            .contains(&candidate.kind())
            && candidate
                .child_by_field_name("name")
                .is_some_and(|candidate_name| {
                    candidate_name.start_byte() == name.start_byte()
                        && candidate_name.end_byte() == name.end_byte()
                })
        {
            return Some(NamedCallableSyntax {
                extent: extractor.structural_callable_extent(candidate),
                has_body: candidate.child_by_field_name("body").is_some(),
                is_package_function: extractor.is_package_function_declaration(candidate.kind()),
                structural_target: true,
            });
        }
        ancestor = candidate.parent();
    }
    None
}

/// One registered language: the extensions it claims plus its extractor.
pub struct LanguageEntry {
    /// File extensions (no leading dot) this language owns, e.g. `["rs"]`.
    pub extensions: &'static [&'static str],
    /// The extractor that parses this language's files.
    pub extractor: &'static dyn LanguageExtractor,
}

static RUST_EXTRACTOR: rust::RustExtractor = rust::RustExtractor;
static GO_EXTRACTOR: go::GoExtractor = go::GoExtractor;
static PYTHON_EXTRACTOR: python::PythonExtractor = python::PythonExtractor;
static TYPESCRIPT_EXTRACTOR: typescript::TypeScriptExtractor = typescript::TypeScriptExtractor;

/// THE single source of truth for registered languages (table-driven — adding a
/// language is ONE row here). The `&'static dyn` coercion is const-legal (a unit
/// struct in a `static`, unsized-coerced in the `static` initializer).
static REGISTRY: &[LanguageEntry] = &[
    LanguageEntry {
        extensions: &["rs"],
        extractor: &RUST_EXTRACTOR,
    },
    LanguageEntry {
        extensions: &["go"],
        extractor: &GO_EXTRACTOR,
    },
    LanguageEntry {
        extensions: &["py", "pyi"],
        extractor: &PYTHON_EXTRACTOR,
    },
    LanguageEntry {
        extensions: &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"],
        extractor: &TYPESCRIPT_EXTRACTOR,
    },
];

/// The extractor registered for a file extension (no leading dot), or `None`
/// when the extension has no registered language.
pub fn extractor_for_extension(ext: &str) -> Option<&'static dyn LanguageExtractor> {
    REGISTRY
        .iter()
        .find(|e| e.extensions.contains(&ext))
        .map(|e| e.extractor)
}

/// Route source-file test ownership through the same language adapter that
/// owns parsing and structural facts. Unknown extensions are conservatively
/// not classified as test source.
pub fn source_path_is_test(file_path: &str) -> bool {
    Path::new(file_path)
        .extension()
        .and_then(|extension| extension.to_str())
        .and_then(extractor_for_extension)
        .is_some_and(|extractor| extractor.source_file_is_test(file_path))
}

/// The canonical language name for an extension (the single-source replacement
/// for the inline `rs → rust` maps).
pub fn language_for_extension(ext: &str) -> Option<&'static str> {
    extractor_for_extension(ext).map(|x| x.language())
}

/// Whether an extension has a registered extractor (the extraction-walk predicate).
pub fn is_registered_extension(ext: &str) -> bool {
    extractor_for_extension(ext).is_some()
}

/// The set of registered extensions whose language matches `languages`.
///
/// An empty `languages` filter means "every registered language" (the default).
/// This is the single source that `IndexPipeline::supported_extensions` derives
/// from, replacing the old inline `vec![("rs", "rust")]` (ADR-0024 §F DRY rider).
pub fn extensions_for_languages(languages: &[String]) -> HashSet<String> {
    REGISTRY
        .iter()
        .filter(|e| languages.is_empty() || languages.iter().any(|l| l == e.extractor.language()))
        .flat_map(|e| e.extensions.iter().map(|x| (*x).to_string()))
        .collect()
}

/// Every registered language name, in registry order.
pub fn registered_languages() -> Vec<&'static str> {
    REGISTRY
        .iter()
        .map(|entry| entry.extractor.language())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::source_path_is_test;

    #[test]
    fn test_source_path_policy_is_language_owned_and_non_vacuous() {
        for path in [
            "tests/integration.rs",
            "pkg/service_test.go",
            "tests/test_service.py",
            "apps/web/service.spec.ts",
            "apps/web/service.e2e.ts",
            "apps/web/widget.stories.tsx",
        ] {
            assert!(source_path_is_test(path), "expected test source: {path}");
        }
        for path in [
            "src/contest.rs",
            "pkg/service.go",
            "src/service.py",
            "apps/web/service.ts",
            "apps/web/storybook.ts",
        ] {
            assert!(
                !source_path_is_test(path),
                "production decoy was classified as test source: {path}"
            );
        }
    }
}
