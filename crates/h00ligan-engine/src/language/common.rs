//! Shared mechanics for structural language adapters.
//!
//! This module owns parser admission and byte-exact `CodeSymbol` construction;
//! each adapter still owns its syntax, visibility, test, and relationship
//! semantics. Keeping that line explicit prevents a generic query layer from
//! erasing language facts merely to reduce a few lines of code.

use tree_sitter::{Language, Node, Parser, Tree};

use crate::graph::EntryRetainFlags;
use crate::structural_ir::{
    CodeSymbol, ExtractorError, StructuralRelation, SymbolKind, Visibility,
};

pub struct SymbolFacts {
    pub name: String,
    pub kind: SymbolKind,
    /// Absolute byte at which the concise signature ends. When absent, the
    /// symbol's complete source extent is its signature.
    pub signature_end: Option<usize>,
    pub doc_comment: Option<String>,
    pub visibility: Visibility,
    pub parent: Option<String>,
    pub is_test_only: bool,
    pub is_test_root: bool,
    pub has_body: bool,
    pub relations: Vec<StructuralRelation>,
}

pub fn parse_tree(
    language: &Language,
    source: &str,
    file_path: &str,
) -> Result<Tree, ExtractorError> {
    parse_tree_with_recovery_admission(language, source, file_path, |_, _| false)
}

/// Parse a document while allowing one adapter-owned, byte-preserving parser
/// recovery to be admitted as a known grammar false-positive.
///
/// This is deliberately not a general "best effort" switch. The callback must
/// prove that every syntax fault belongs to one exact upstream grammar gap;
/// all other recovery trees still fail closed through the same error path as
/// [`parse_tree`].
pub fn parse_tree_with_recovery_admission(
    language: &Language,
    source: &str,
    file_path: &str,
    admits_recovery: impl FnOnce(&Tree, &str) -> bool,
) -> Result<Tree, ExtractorError> {
    let mut parser = Parser::new();
    parser
        .set_language(language)
        .map_err(|error| ExtractorError::LanguageError(error.to_string()))?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| ExtractorError::ParseFailed {
            path: file_path.to_string(),
        })?;
    if tree.root_node().has_error() && !admits_recovery(&tree, source) {
        let detail = first_syntax_error(tree.root_node()).map_or_else(String::new, |node| {
            let start = node.start_position();
            format!(
                " at {}:{} ({})",
                start.row + 1,
                start.column + 1,
                if node.is_missing() {
                    format!("missing {}", node.kind())
                } else {
                    node.kind().to_string()
                }
            )
        });
        return Err(ExtractorError::IncompleteSyntax {
            path: file_path.to_string(),
            detail,
        });
    }
    Ok(tree)
}

fn first_syntax_error(node: Node<'_>) -> Option<Node<'_>> {
    if node.is_error() || node.is_missing() {
        return Some(node);
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .filter(|child| child.has_error() || child.is_missing())
        .find_map(first_syntax_error)
}

pub fn code_symbol(extent: Node<'_>, source: &str, facts: SymbolFacts) -> CodeSymbol {
    let bytes = source.as_bytes();
    let full_source = bytes
        .get(extent.start_byte()..extent.end_byte())
        .unwrap_or_default();
    let signature_end = facts
        .signature_end
        .unwrap_or_else(|| extent.end_byte())
        .clamp(extent.start_byte(), extent.end_byte());
    let signature = bytes
        .get(extent.start_byte()..signature_end)
        .and_then(|value| std::str::from_utf8(value).ok())
        .unwrap_or_default()
        .trim()
        .to_string();
    CodeSymbol {
        name: facts.name,
        kind: facts.kind,
        span: (extent.start_byte(), extent.end_byte()),
        line_range: (extent.start_position().row, extent.end_position().row),
        signature,
        doc_comment: facts.doc_comment,
        content_hash: blake3::hash(full_source).to_hex().to_string(),
        visibility: facts.visibility,
        parent: facts.parent,
        is_test_only: facts.is_test_only,
        is_test_root: facts.is_test_root,
        has_body: facts.has_body,
        relations: facts.relations,
        entry_retain: EntryRetainFlags::default(),
    }
}

pub fn node_text<'source>(node: Node<'_>, source: &'source str) -> Option<&'source str> {
    std::str::from_utf8(source.as_bytes().get(node.start_byte()..node.end_byte())?).ok()
}

/// Reduce a source type expression to the first conservative named target.
/// This is intentionally not a type parser: adapters call it only for simple
/// structural `TypeOf`/inheritance evidence and skip anything it cannot name.
pub fn simple_type_target(text: &str) -> Option<String> {
    let mut candidate = text.trim();
    candidate = candidate
        .strip_prefix(':')
        .map_or(candidate, str::trim_start);
    candidate = candidate.trim_matches(|character| matches!(character, '\'' | '"'));
    for prefix in ["readonly ", "keyof ", "typeof "] {
        if let Some(rest) = candidate.strip_prefix(prefix) {
            candidate = rest.trim_start();
        }
    }
    let end = candidate
        .char_indices()
        .find_map(|(index, character)| {
            matches!(
                character,
                '<' | '[' | '|' | '&' | ',' | '=' | '(' | ')' | '{' | '}' | ';' | '?' | '!'
            )
            .then_some(index)
        })
        .unwrap_or(candidate.len());
    let candidate = candidate[..end].trim();
    (!candidate.is_empty()
        && candidate
            .chars()
            .all(|character| character.is_alphanumeric() || matches!(character, '_' | '.' | '$')))
    .then(|| candidate.to_string())
}

pub fn unquoted_name(text: &str) -> String {
    text.trim()
        .trim_matches(|character| matches!(character, '\'' | '"' | '`'))
        .to_string()
}
