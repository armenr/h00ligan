//! The Rust structural extractor — the first language registered in the
//! [`LanguageExtractor`](super::LanguageExtractor) registry (ADR-0024).
//!
//! [`RustExtractor::extract`] DELEGATES to [`extract_rust_symbols`]: the Rust
//! extraction body (its ~30 helpers + the `ExtractorOutput` types) stays in
//! `extractor.rs` (the minimal-relocation seam), so the literal same code runs
//! and byte-identity holds by construction. Those helpers ARE, semantically,
//! `RustExtractor`'s methods — the Rust language's structural extraction,
//! reachable only through this type via the trait dispatch.

use tree_sitter::Node;

use super::{LanguageExtractor, NamedCallForm, NamedCallSyntax};
use crate::extractor::extract_rust_symbols;
use crate::structural_ir::{ExtractorError, ExtractorOutput, StructuralDocumentTarget};

/// The Rust structural extractor (ADR-0024, first registered language).
///
/// Zero-sized: a unit struct so it lives in a `static` with no runtime init.
pub struct RustExtractor;

impl LanguageExtractor for RustExtractor {
    fn language(&self) -> &'static str {
        "rust"
    }

    fn source_file_is_test(&self, file_path: &str) -> bool {
        crate::extractor::file_is_test(file_path)
    }

    fn ts_language_for_path(&self, _file_path: &str) -> tree_sitter::Language {
        // THE registry grammar binding — the one structural `tree_sitter_rust`
        // site. The extractor parse (site 1) and the DRY-detection parse
        // (site 2) both fold through here.
        tree_sitter_rust::LANGUAGE.into()
    }

    fn named_callable_declaration_kinds(&self) -> &'static [&'static str] {
        &["function_item", "function_signature_item"]
    }

    fn anonymous_callable_declaration_kinds(&self) -> &'static [&'static str] {
        &["closure_expression"]
    }

    fn named_call_syntax<'tree>(&self, call: Node<'tree>) -> Option<NamedCallSyntax<'tree>> {
        if call.kind() != "call_expression" {
            return None;
        }
        rust_call_target(call.child_by_field_name("function")?)
    }

    fn cross_document_surface_elidable_body<'tree>(
        &self,
        declaration: Node<'tree>,
        source: &str,
    ) -> Option<Node<'tree>> {
        if declaration.kind() != "function_item" {
            return None;
        }
        let body = declaration.child_by_field_name("body")?;
        let header = source
            .as_bytes()
            .get(declaration.start_byte()..body.start_byte())?;
        if rust_header_has_body_dependent_surface(header)
            || rust_body_has_cross_document_escape(body, source)
        {
            None
        } else {
            Some(body)
        }
    }

    fn contained_document_candidates(
        &self,
        declaring_document: &str,
        symbol_name: &str,
        inline_path: &[String],
        target: &StructuralDocumentTarget,
        is_compilation_root: Option<bool>,
    ) -> Vec<String> {
        rust_module_document_candidates(
            declaring_document,
            symbol_name,
            inline_path,
            target,
            is_compilation_root,
        )
    }

    fn extract(&self, source: &str, file_path: &str) -> Result<ExtractorOutput, ExtractorError> {
        // Delegate to the unchanged body in `extractor.rs` (minimal-relocation).
        extract_rust_symbols(source, file_path)
    }
}

fn rust_module_document_candidates(
    declaring_document: &str,
    symbol_name: &str,
    inline_path: &[String],
    target: &StructuralDocumentTarget,
    is_compilation_root: Option<bool>,
) -> Vec<String> {
    if matches!(target, StructuralDocumentTarget::Unresolved) {
        return Vec::new();
    }
    let (source_directory, source_file) = declaring_document
        .rsplit_once('/')
        .map_or(("", declaring_document), |(directory, file)| {
            (directory, file)
        });

    // A direct `#[path]` is relative to the source file's directory and does
    // not need crate-root knowledge. Inside an inline module, both explicit
    // and conventional paths inherit the module's effective directory.
    let mut base = source_directory.to_owned();
    if !inline_path.is_empty() || matches!(target, StructuralDocumentTarget::LanguageDefault) {
        let mod_rs = source_file == "mod.rs";
        if !mod_rs {
            match is_compilation_root {
                Some(true) => {}
                Some(false) => {
                    let Some(stem) = source_file.strip_suffix(".rs") else {
                        return Vec::new();
                    };
                    let Some(joined) = portable_join(&base, stem) else {
                        return Vec::new();
                    };
                    base = joined;
                }
                // The low-level graph builder intentionally has no inventory
                // and is retained only for isolated extractor/graph contracts.
                // Preserve its conventional fixture roots without granting
                // production authority: the immutable indexing path always
                // supplies `Some(exact_inventory_fact)` here.
                None if matches!(source_file, "lib.rs" | "main.rs") => {}
                None => return Vec::new(),
            }
        }
        for component in inline_path {
            let Some(joined) = portable_join(&base, component) else {
                return Vec::new();
            };
            base = joined;
        }
    }

    match target {
        StructuralDocumentTarget::LanguageDefault => {
            [format!("{symbol_name}.rs"), format!("{symbol_name}/mod.rs")]
                .into_iter()
                .filter_map(|relative| portable_join(&base, &relative))
                .collect()
        }
        StructuralDocumentTarget::ExplicitRelativePath(relative) => {
            portable_join(&base, relative).into_iter().collect()
        }
        StructuralDocumentTarget::Unresolved => Vec::new(),
    }
}

/// Join source-spelled Rust paths without filesystem access or host-specific
/// separator behavior. Parent components may walk within the repository but
/// never above it; absolute, NUL-bearing, or backslash paths fail closed.
fn portable_join(base: &str, relative: &str) -> Option<String> {
    let windows_absolute = relative
        .as_bytes()
        .get(1)
        .is_some_and(|separator| *separator == b':');
    if relative.is_empty()
        || relative.starts_with('/')
        || relative.contains('\\')
        || relative.contains('\0')
        || windows_absolute
    {
        return None;
    }
    let mut components = base
        .split('/')
        .filter(|component| !component.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for component in relative.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            component => components.push(component.to_owned()),
        }
    }
    (!components.is_empty()).then(|| components.join("/"))
}

fn rust_call_target(function: Node<'_>) -> Option<NamedCallSyntax<'_>> {
    match function.kind() {
        "identifier" => Some(NamedCallSyntax {
            callee: function,
            form: NamedCallForm::Direct,
            receiver_identity: None,
        }),
        "generic_function" | "parenthesized_expression" => {
            rust_call_target(function.named_child(0)?)
        }
        "field_expression" => Some(NamedCallSyntax {
            callee: function.child_by_field_name("field")?,
            form: NamedCallForm::Method,
            receiver_identity: function
                .child_by_field_name("value")
                .and_then(rust_receiver_identity),
        }),
        "scoped_identifier" => Some(NamedCallSyntax {
            callee: function.child_by_field_name("name")?,
            form: NamedCallForm::Path,
            receiver_identity: None,
        }),
        _ => None,
    }
}

fn rust_receiver_identity(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" | "self" | "field_identifier" => Some(node),
        "field_expression" => node.child_by_field_name("field"),
        "parenthesized_expression" | "reference_expression" => {
            node.named_child(0).and_then(rust_receiver_identity)
        }
        _ => None,
    }
}

fn rust_header_has_body_dependent_surface(header: &[u8]) -> bool {
    header
        .split(|byte| !(byte.is_ascii_alphanumeric() || *byte == b'_'))
        .any(|token| matches!(token, b"async" | b"const" | b"impl"))
}

fn rust_body_has_cross_document_escape(node: Node<'_>, source: &str) -> bool {
    if node.kind() == "macro_definition" {
        return true;
    }
    if node.kind() == "attribute_item" {
        let text = source
            .as_bytes()
            .get(node.start_byte()..node.end_byte())
            .unwrap_or_default();
        if [
            b"macro_export".as_slice(),
            b"no_mangle".as_slice(),
            b"export_name".as_slice(),
            b"link_section".as_slice(),
        ]
        .iter()
        .any(|needle| text.windows(needle.len()).any(|window| window == *needle))
        {
            return true;
        }
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| rust_body_has_cross_document_escape(child, source))
}
