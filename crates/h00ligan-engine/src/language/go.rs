//! Go structural adapter.
//!
//! The adapter walks the admitted Go AST directly. Package declarations,
//! imports, aliases, defined types, struct fields, functions, methods,
//! variables, constants, and interface methods are classified at their owning
//! syntax nodes; the obsolete upstream tag-query allow-list no longer decides
//! which valid declarations silently disappear. The package clause remains
//! project-inventory metadata rather than a repeated source symbol.

use chrono::Utc;
use tree_sitter::{Node, Parser};

use super::common::{SymbolFacts, code_symbol, node_text, simple_type_target, unquoted_name};
use super::{LanguageExtractor, NamedCallForm, NamedCallSyntax};
use crate::graph::EntryRetainFlags;
use crate::structural_ir::{
    CodeSymbol, ExtractorError, ExtractorOutput, StructuralCaptureGap, StructuralRelation,
    SymbolKind, Visibility,
};

/// The Go structural extractor (ADR-0024 / WU-0023 P3a).
///
/// Zero-sized: a unit struct so it lives in a `static` with no runtime init
/// (mirrors [`super::rust::RustExtractor`]).
pub struct GoExtractor;

impl LanguageExtractor for GoExtractor {
    fn language(&self) -> &'static str {
        "go"
    }

    fn source_file_is_test(&self, file_path: &str) -> bool {
        file_path.ends_with("_test.go")
    }

    fn ts_language_for_path(&self, _file_path: &str) -> tree_sitter::Language {
        // THE single sanctioned `tree_sitter_go` binding site (mirrors
        // `RustExtractor::ts_language`). `LANGUAGE: LanguageFn` -> `Language` via
        // the `tree-sitter-language` shim, identical shape to tree-sitter-rust.
        tree_sitter_go::LANGUAGE.into()
    }

    fn named_callable_declaration_kinds(&self) -> &'static [&'static str] {
        &["function_declaration", "method_declaration", "method_elem"]
    }

    fn anonymous_callable_declaration_kinds(&self) -> &'static [&'static str] {
        &["func_literal"]
    }

    fn named_call_syntax<'tree>(&self, call: Node<'tree>) -> Option<NamedCallSyntax<'tree>> {
        if call.kind() != "call_expression" {
            return None;
        }
        go_call_target(call.child_by_field_name("function")?)
    }

    fn cross_document_surface_elidable_body<'tree>(
        &self,
        declaration: Node<'tree>,
        _source: &str,
    ) -> Option<Node<'tree>> {
        matches!(
            declaration.kind(),
            "function_declaration" | "method_declaration" | "func_literal"
        )
        .then(|| declaration.child_by_field_name("body"))
        .flatten()
    }

    fn is_package_function_declaration(&self, kind: &str) -> bool {
        kind == "function_declaration"
    }

    fn extract(&self, source: &str, file_path: &str) -> Result<ExtractorOutput, ExtractorError> {
        extract_go_symbols(source, file_path)
    }
}

fn go_call_target(function: Node<'_>) -> Option<NamedCallSyntax<'_>> {
    match function.kind() {
        "identifier" => Some(NamedCallSyntax {
            callee: function,
            form: NamedCallForm::Direct,
            receiver_identity: None,
        }),
        "parenthesized_expression" => go_call_target(function.named_child(0)?),
        "selector_expression" => Some(NamedCallSyntax {
            callee: function.child_by_field_name("field")?,
            form: NamedCallForm::Method,
            receiver_identity: function
                .child_by_field_name("operand")
                .and_then(go_receiver_identity),
        }),
        _ => None,
    }
}

fn go_receiver_identity(node: Node<'_>) -> Option<Node<'_>> {
    match node.kind() {
        "identifier" | "field_identifier" => Some(node),
        "selector_expression" => node.child_by_field_name("field"),
        "parenthesized_expression" => node.named_child(0).and_then(go_receiver_identity),
        _ => None,
    }
}

/// Extract Go symbols from one syntax-admitted source file.
fn extract_go_symbols(source: &str, file_path: &str) -> Result<ExtractorOutput, ExtractorError> {
    let language = GoExtractor.ts_language_for_path(file_path);

    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|e| ExtractorError::LanguageError(e.to_string()))?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| ExtractorError::ParseFailed {
            path: file_path.to_string(),
        })?;

    // Go marks a file test-only by the `_test.go` suffix (a file-level fact with
    // no AST attribute); set it here so the downstream node carries it.
    let file_is_test = file_path.ends_with("_test.go");

    let root = tree.root_node();
    if root.has_error() {
        return Err(ExtractorError::IncompleteSyntax {
            path: file_path.to_string(),
            detail: String::new(),
        });
    }
    let src = source.as_bytes();
    let mut symbols = Vec::new();
    let mut cursor = root.walk();
    for declaration in root.named_children(&mut cursor) {
        collect_go_top_level(declaration, source, file_is_test, &mut symbols);
    }
    collect_addressable_anonymous_struct_fields(root, source, file_is_test, &mut symbols);
    collect_interface_methods(root, src, file_is_test, &mut symbols);
    let capture_gaps = go_capture_gaps(root, source, symbols.as_slice());
    let cross_document_surface_sha256 =
        crate::code_intel_semantic_refresh::cross_document_surface_sha256(
            &GoExtractor,
            source,
            root,
        );

    Ok(ExtractorOutput {
        file_path: file_path.to_string(),
        file_hash: blake3::hash(src).to_hex().to_string(),
        cross_document_surface_sha256,
        symbols,
        extracted_at: Utc::now(),
        has_platform_cfg: false,
        capture_gaps,
    })
}

fn collect_go_top_level(
    node: Node<'_>,
    source: &str,
    file_is_test: bool,
    symbols: &mut Vec<CodeSymbol>,
) {
    match node.kind() {
        "function_declaration" => {
            if let Some(symbol) = go_callable_symbol(node, source, file_is_test, false) {
                symbols.push(symbol);
            }
        }
        "method_declaration" => {
            if let Some(symbol) = go_callable_symbol(node, source, file_is_test, true) {
                symbols.push(symbol);
            }
        }
        "type_declaration" => {
            let mut cursor = node.walk();
            for declaration in node.named_children(&mut cursor) {
                if matches!(declaration.kind(), "type_spec" | "type_alias") {
                    collect_go_type(declaration, source, file_is_test, symbols);
                }
            }
        }
        "var_declaration" => {
            collect_go_value_specs(node, source, file_is_test, SymbolKind::Static, symbols)
        }
        "const_declaration" => {
            collect_go_value_specs(node, source, file_is_test, SymbolKind::Const, symbols)
        }
        "import_declaration" => collect_go_imports(node, source, file_is_test, symbols),
        // The package clause is exact project-inventory metadata, not one
        // duplicate graph symbol per file.
        "package_clause" | "comment" => {}
        _ => {}
    }
}

fn go_callable_symbol(
    declaration: Node<'_>,
    source: &str,
    file_is_test: bool,
    is_method: bool,
) -> Option<CodeSymbol> {
    let name_node = declaration.child_by_field_name("name")?;
    let name = node_text(name_node, source)?;
    if name.is_empty() || name == "_" {
        return None;
    }
    let definition = node_text(declaration, source)?;
    Some(CodeSymbol {
        name: name.into(),
        kind: SymbolKind::Function,
        span: (declaration.start_byte(), declaration.end_byte()),
        line_range: (
            declaration.start_position().row,
            declaration.end_position().row,
        ),
        signature: signature_text(declaration, source.as_bytes(), definition),
        doc_comment: doc_comment_of(declaration, source.as_bytes()),
        content_hash: blake3::hash(definition.as_bytes()).to_hex().to_string(),
        visibility: go_visibility(name),
        parent: is_method
            .then(|| receiver_type_name(declaration, source.as_bytes()))
            .flatten(),
        is_test_only: file_is_test,
        is_test_root: !is_method && file_is_test && is_go_test_entry(name),
        has_body: declaration.child_by_field_name("body").is_some(),
        relations: Vec::new(),
        entry_retain: EntryRetainFlags::default(),
    })
}

fn collect_go_type(
    declaration: Node<'_>,
    source: &str,
    file_is_test: bool,
    symbols: &mut Vec<CodeSymbol>,
) {
    let Some(name_node) = declaration.child_by_field_name("name") else {
        return;
    };
    let Some(name) = node_text(name_node, source) else {
        return;
    };
    if name.is_empty() || name == "_" {
        return;
    }
    let Some(definition) = node_text(declaration, source) else {
        return;
    };
    let kind = if declaration.kind() == "type_alias" {
        SymbolKind::TypeAlias
    } else {
        type_kind(declaration)
    };
    let relations = go_type_relations(declaration, source);
    symbols.push(CodeSymbol {
        name: name.into(),
        kind,
        span: (declaration.start_byte(), declaration.end_byte()),
        line_range: (
            declaration.start_position().row,
            declaration.end_position().row,
        ),
        signature: definition.trim().into(),
        doc_comment: doc_comment_of(declaration, source.as_bytes()),
        content_hash: blake3::hash(definition.as_bytes()).to_hex().to_string(),
        visibility: go_visibility(name),
        parent: None,
        is_test_only: file_is_test,
        is_test_root: false,
        has_body: false,
        relations,
        entry_retain: EntryRetainFlags::default(),
    });

    if let Some(underlying) = declaration.child_by_field_name("type")
        && underlying.kind() == "struct_type"
    {
        collect_go_struct_fields(underlying, name, source, file_is_test, symbols);
    }
}

fn go_type_relations(declaration: Node<'_>, source: &str) -> Vec<StructuralRelation> {
    let Some(underlying) = declaration.child_by_field_name("type") else {
        return Vec::new();
    };
    if declaration.kind() == "type_alias" {
        return go_type_target(underlying, source)
            .map(|target| StructuralRelation::TypeOf { target })
            .into_iter()
            .collect();
    }
    if underlying.kind() != "interface_type" {
        return Vec::new();
    }
    let mut relations = Vec::new();
    let mut cursor = underlying.walk();
    for child in underlying
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "type_elem")
    {
        if let Some(target) = node_text(child, source).and_then(simple_type_target) {
            relations.push(StructuralRelation::Extends { target });
        }
    }
    relations
}

fn collect_go_struct_fields(
    structure: Node<'_>,
    owner: &str,
    source: &str,
    file_is_test: bool,
    symbols: &mut Vec<CodeSymbol>,
) {
    let Some(fields) = ({
        let mut cursor = structure.walk();
        structure
            .named_children(&mut cursor)
            .find(|child| child.kind() == "field_declaration_list")
    }) else {
        return;
    };
    let mut cursor = fields.walk();
    for field in fields
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "field_declaration")
    {
        let field_type = field.child_by_field_name("type");
        let relation = field_type
            .and_then(|field_type| go_type_target(field_type, source))
            .map(|target| StructuralRelation::TypeOf { target });
        let mut name_cursor = field.walk();
        let mut names = field
            .children_by_field_name("name", &mut name_cursor)
            .filter_map(|name| node_text(name, source).map(str::to_string))
            .collect::<Vec<_>>();
        if names.is_empty()
            && let Some(name) =
                field_type.and_then(|field_type| go_embedded_field_name(field_type, source))
        {
            names.push(name);
        }
        for name in names.into_iter().filter(|name| name != "_") {
            symbols.push(code_symbol(
                field,
                source,
                SymbolFacts {
                    name: name.clone(),
                    kind: SymbolKind::Field,
                    signature_end: None,
                    doc_comment: doc_comment_of(field, source.as_bytes()),
                    visibility: go_visibility(&name),
                    parent: Some(owner.into()),
                    is_test_only: file_is_test,
                    is_test_root: false,
                    has_body: false,
                    relations: relation.clone().into_iter().collect(),
                },
            ));
        }
    }
}

/// Add fields whose anonymous struct type belongs to an addressable package
/// value, callable signature, or already represented outer field.
///
/// Anonymous structs created inside a function body are intentionally local
/// implementation details and remain outside the structural symbol surface.
/// Signature and package-level shapes, however, are visible to other code and
/// are already part of the adapter's capture census; omitting their fields
/// would make that census permanently partial.
fn collect_addressable_anonymous_struct_fields(
    node: Node<'_>,
    source: &str,
    file_is_test: bool,
    symbols: &mut Vec<CodeSymbol>,
) {
    if node.kind() == "struct_type"
        && !has_block_ancestor(node)
        && !node.parent().is_some_and(|parent| {
            matches!(parent.kind(), "type_spec" | "type_alias")
                && parent
                    .child_by_field_name("type")
                    .is_some_and(|underlying| {
                        underlying.start_byte() == node.start_byte()
                            && underlying.end_byte() == node.end_byte()
                    })
        })
    {
        for owner in anonymous_struct_owner_names(node, source) {
            collect_go_struct_fields(node, &owner, source, file_is_test, symbols);
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_addressable_anonymous_struct_fields(child, source, file_is_test, symbols);
    }
}

fn anonymous_struct_owner_names(node: Node<'_>, source: &str) -> Vec<String> {
    let mut ancestor = node.parent();
    while let Some(candidate) = ancestor {
        match candidate.kind() {
            "field_declaration" if !has_block_ancestor(candidate) => {
                return go_field_names(candidate, source);
            }
            "var_spec" if !has_block_ancestor(candidate) => {
                let mut cursor = candidate.walk();
                return candidate
                    .children_by_field_name("name", &mut cursor)
                    .filter_map(|name| node_text(name, source).map(str::to_owned))
                    .filter(|name| name != "_")
                    .collect();
            }
            "function_declaration" | "method_declaration" => {
                return candidate
                    .child_by_field_name("name")
                    .and_then(|name| node_text(name, source))
                    .filter(|name| !name.is_empty() && *name != "_")
                    .map(|name| vec![name.to_owned()])
                    .unwrap_or_default();
            }
            _ => {}
        }
        ancestor = candidate.parent();
    }
    Vec::new()
}

fn go_embedded_field_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "type_identifier" => node_text(node, source).map(str::to_string),
        "qualified_type" => node
            .child_by_field_name("name")
            .and_then(|name| node_text(name, source))
            .map(str::to_string),
        "generic_type" => node
            .child_by_field_name("type")
            .and_then(|inner| go_embedded_field_name(inner, source)),
        "pointer_type" => node
            .named_child(0)
            .and_then(|inner| go_embedded_field_name(inner, source)),
        _ => None,
    }
}

fn go_type_target(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "pointer_type" => node
            .named_child(0)
            .and_then(|inner| go_type_target(inner, source)),
        "generic_type" => node
            .child_by_field_name("type")
            .and_then(|inner| go_type_target(inner, source)),
        _ => node_text(node, source).and_then(simple_type_target),
    }
}

fn collect_go_value_specs(
    node: Node<'_>,
    source: &str,
    file_is_test: bool,
    default_kind: SymbolKind,
    symbols: &mut Vec<CodeSymbol>,
) {
    if matches!(node.kind(), "var_spec" | "const_spec") {
        let mut cursor = node.walk();
        for name_node in node.children_by_field_name("name", &mut cursor) {
            let Some(name) = node_text(name_node, source) else {
                continue;
            };
            if name.is_empty() || name == "_" {
                continue;
            }
            let function_variable = default_kind == SymbolKind::Static
                && var_name_binds_function_literal(node, name_node);
            symbols.push(code_symbol(
                node,
                source,
                SymbolFacts {
                    name: name.into(),
                    kind: if function_variable {
                        SymbolKind::CallableValue
                    } else {
                        default_kind
                    },
                    signature_end: None,
                    doc_comment: doc_comment_of(node, source.as_bytes()),
                    visibility: go_visibility(name),
                    parent: None,
                    is_test_only: file_is_test,
                    is_test_root: false,
                    has_body: function_variable,
                    relations: Vec::new(),
                },
            ));
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_go_value_specs(child, source, file_is_test, default_kind, symbols);
    }
}

fn collect_go_imports(
    node: Node<'_>,
    source: &str,
    file_is_test: bool,
    symbols: &mut Vec<CodeSymbol>,
) {
    if node.kind() == "import_spec" {
        let Some(path) = node
            .child_by_field_name("path")
            .and_then(|path| node_text(path, source))
            .map(unquoted_name)
        else {
            return;
        };
        let explicit = node
            .child_by_field_name("name")
            .and_then(|name| node_text(name, source));
        let name = match explicit {
            Some(".") => "*".into(),
            Some("_") | None => path.clone(),
            Some(alias) => alias.into(),
        };
        symbols.push(code_symbol(
            node,
            source,
            SymbolFacts {
                name,
                kind: SymbolKind::Import,
                signature_end: None,
                doc_comment: doc_comment_of(node, source.as_bytes()),
                visibility: Visibility::Private,
                parent: None,
                is_test_only: file_is_test,
                is_test_root: false,
                has_body: false,
                relations: vec![StructuralRelation::References { target: path }],
            },
        ));
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_go_imports(child, source, file_is_test, symbols);
    }
}

fn go_visibility(name: &str) -> Visibility {
    if name.chars().next().is_some_and(char::is_uppercase) {
        Visibility::Public
    } else {
        Visibility::Private
    }
}

fn go_capture_gaps(
    root: Node<'_>,
    source: &str,
    symbols: &[CodeSymbol],
) -> Vec<StructuralCaptureGap> {
    fn walk(
        node: Node<'_>,
        source: &str,
        symbols: &[CodeSymbol],
        gaps: &mut Vec<StructuralCaptureGap>,
    ) {
        let symbol_count_at = |extent: Node<'_>| {
            symbols
                .iter()
                .filter(|symbol| symbol.span == (extent.start_byte(), extent.end_byte()))
                .count()
        };
        let gap = |kind: &str, node: Node<'_>, gaps: &mut Vec<StructuralCaptureGap>| {
            gaps.push(StructuralCaptureGap::new(
                kind,
                (node.start_byte(), node.end_byte()),
            ));
        };

        if !has_block_ancestor(node) {
            match node.kind() {
                "function_declaration" | "method_declaration" => {
                    if symbol_count_at(node) == 0 {
                        gap("unrepresented_go_callable", node, gaps);
                    }
                }
                "type_spec" | "type_alias" => {
                    if symbol_count_at(node) == 0 {
                        gap("unrepresented_go_type", node, gaps);
                    }
                }
                "var_spec" | "const_spec" => {
                    let mut cursor = node.walk();
                    let expected = node
                        .children_by_field_name("name", &mut cursor)
                        .filter(|name| node_text(*name, source) != Some("_"))
                        .count();
                    if expected > symbol_count_at(node) {
                        gap("unrepresented_go_value", node, gaps);
                    }
                }
                "import_spec" => {
                    if symbol_count_at(node) == 0 {
                        gap("unrepresented_go_import", node, gaps);
                    }
                }
                "field_declaration" => {
                    let expected = go_field_names(node, source).len();
                    if expected > symbol_count_at(node) {
                        gap("unrepresented_go_field", node, gaps);
                    }
                }
                "method_elem" => {
                    if symbol_count_at(node) == 0 {
                        gap("unrepresented_go_interface_method", node, gaps);
                    }
                }
                "type_elem"
                    if node
                        .parent()
                        .is_some_and(|parent| parent.kind() == "interface_type")
                        && node_text(node, source)
                            .and_then(simple_type_target)
                            .is_none() =>
                {
                    gap("unrepresented_go_interface_type_element", node, gaps);
                }
                _ => {}
            }
        }

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, source, symbols, gaps);
        }
    }

    let mut gaps = Vec::new();
    walk(root, source, symbols, &mut gaps);
    gaps.sort_by(|left, right| left.span.cmp(&right.span).then(left.kind.cmp(&right.kind)));
    gaps.dedup();
    gaps
}

fn go_field_names(field: Node<'_>, source: &str) -> Vec<String> {
    let mut cursor = field.walk();
    let mut names = field
        .children_by_field_name("name", &mut cursor)
        .filter_map(|name| node_text(name, source).map(str::to_string))
        .filter(|name| name != "_")
        .collect::<Vec<_>>();
    if names.is_empty()
        && let Some(name) = field
            .child_by_field_name("type")
            .and_then(|field_type| go_embedded_field_name(field_type, source))
    {
        names.push(name);
    }
    names
}

/// Add Go interface method specifications to the structural callable universe.
///
/// The upstream tags query captures the containing interface type but not its
/// `method_elem` children. scip-go does emit those definitions, including
/// methods of anonymous interfaces used in function signatures. Keeping them
/// structurally visible lets provider definitions join by exact source extent
/// without pretending that a signature-only method owns a function body.
fn collect_interface_methods(
    node: Node<'_>,
    src: &[u8],
    file_is_test: bool,
    symbols: &mut Vec<CodeSymbol>,
) {
    if node.kind() == "method_elem" {
        if let Some(symbol) = interface_method_symbol(node, src, file_is_test) {
            symbols.push(symbol);
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_interface_methods(child, src, file_is_test, symbols);
    }
}

fn interface_method_symbol(method: Node<'_>, src: &[u8], file_is_test: bool) -> Option<CodeSymbol> {
    let name_node = method.child_by_field_name("name")?;
    let name = name_node.utf8_text(src).ok()?;
    if name.is_empty() || name == "_" {
        return None;
    }
    let method_text = method.utf8_text(src).ok()?;
    let visibility = if name.chars().next().is_some_and(char::is_uppercase) {
        Visibility::Public
    } else {
        Visibility::Private
    };
    Some(CodeSymbol {
        name: name.into(),
        kind: SymbolKind::Function,
        span: (method.start_byte(), method.end_byte()),
        line_range: (method.start_position().row, method.end_position().row),
        signature: method_text.trim().into(),
        doc_comment: doc_comment_of(method, src),
        content_hash: blake3::hash(method_text.as_bytes()).to_hex().to_string(),
        visibility,
        parent: nearest_declaration_name(method, src),
        is_test_only: file_is_test,
        is_test_root: false,
        has_body: false,
        relations: Vec::new(),
        entry_retain: EntryRetainFlags::default(),
    })
}

/// Name the nearest represented source declaration that owns an interface
/// method. Named interfaces resolve to their type; anonymous signature
/// interfaces resolve to the surrounding function, method, package variable,
/// or package constant. Block-local declarations are deliberately absent from
/// the structural graph, so a method nested beneath one continues outward to
/// its represented callable owner instead of naming a parent that cannot join.
fn nearest_declaration_name(node: Node<'_>, src: &[u8]) -> Option<String> {
    let mut ancestor = node.parent();
    while let Some(candidate) = ancestor {
        let represented = match candidate.kind() {
            "type_spec" | "type_alias" | "var_spec" | "const_spec" => {
                !has_block_ancestor(candidate)
            }
            "function_declaration" | "method_declaration" => true,
            _ => false,
        };
        if represented
            && let Some(name) = candidate.child_by_field_name("name")
            && let Ok(name) = name.utf8_text(src)
            && !name.is_empty()
            && name != "_"
        {
            return Some(name.into());
        }
        ancestor = candidate.parent();
    }
    None
}

pub(crate) fn var_name_binds_function_literal(var_spec: Node<'_>, name: Node<'_>) -> bool {
    if var_spec.kind() != "var_spec" {
        return false;
    }
    let mut name_cursor = var_spec.walk();
    let Some(name_index) = var_spec
        .children_by_field_name("name", &mut name_cursor)
        .position(|candidate| {
            candidate.start_byte() == name.start_byte() && candidate.end_byte() == name.end_byte()
        })
    else {
        return false;
    };
    let Some(values) = var_spec.child_by_field_name("value") else {
        return false;
    };
    u32::try_from(name_index)
        .ok()
        .and_then(|index| values.named_child(index))
        .is_some_and(|value| value.kind() == "func_literal")
}

/// Map a `type_spec`'s underlying type to a [`SymbolKind`].
///
/// `struct_type` -> `Struct`, `interface_type` -> `Trait` (Go interface ≈ Rust
/// trait. A defined type with any other underlying syntax maps to `Struct` at
/// this structural vocabulary floor; aliases are handled separately.
fn type_kind(type_spec: Node<'_>) -> SymbolKind {
    match type_spec.child_by_field_name("type").map(|n| n.kind()) {
        Some("interface_type") => SymbolKind::Trait,
        _ => SymbolKind::Struct,
    }
}

/// Whether any ancestor of `node` is a `block` — i.e. the node is
/// function/method-local, not package-scope.
fn has_block_ancestor(node: Node<'_>) -> bool {
    let mut cur = node.parent();
    while let Some(p) = cur {
        if p.kind() == "block" {
            return true;
        }
        cur = p.parent();
    }
    false
}

/// The base receiver type name for a `method_declaration`, unwrapping pointer
/// (`*T`) and generic (`T[U]` / `*T[U]`) receivers to the base `type_identifier`.
///
/// Returns the FIRST `type_identifier` in the receiver's `type` field subtree —
/// robust across `T`, `*T`, `T[U]`, `*T[U]` (the base name always precedes the
/// type arguments in pre-order), and correctly ignores the receiver's variable
/// name (an `identifier`, scoped out by searching only the `type` field).
fn receiver_type_name(method: Node<'_>, src: &[u8]) -> Option<String> {
    let receiver = method.child_by_field_name("receiver")?;
    let mut cursor = receiver.walk();
    let param = receiver
        .named_children(&mut cursor)
        .find(|n| n.kind() == "parameter_declaration")?;
    let ty = param.child_by_field_name("type")?;
    let ident = first_type_identifier(ty)?;
    ident.utf8_text(src).ok().map(str::to_string)
}

/// Pre-order search for the first `type_identifier` in `node`'s subtree.
fn first_type_identifier(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "type_identifier" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(found) = first_type_identifier(child) {
            return Some(found);
        }
    }
    None
}

/// Whether `name` is a Go test-ENTRY function name (WU-0023 P3b Bundle-3 rider).
///
/// Implements Go's EXACT `isTest` rule (`cmd/go/internal/load/test.go`): a name
/// is a test entry iff it starts with one of the `{Test, Benchmark, Example,
/// Fuzz}` prefixes AND the rune IMMEDIATELY after the prefix is either absent
/// (the bare prefix, e.g. `Test`) or is NOT a lowercase letter. So `TestFoo`,
/// `Test_foo`, `Test`, `Fuzz1` qualify; `Testing`, `Benchmarker`, `Examples`,
/// `Fuzzy` do NOT (the follow-rune is lowercase → an ordinary exported symbol
/// that merely shares the prefix). Unicode-aware via `char::is_lowercase`,
/// mirroring the first-rune export test above — never a byte-0 ASCII slice.
fn is_go_test_entry(name: &str) -> bool {
    ["Test", "Benchmark", "Example", "Fuzz"]
        .iter()
        .any(|prefix| {
            name.strip_prefix(prefix)
                .is_some_and(|rest| rest.chars().next().is_none_or(|c| !c.is_lowercase()))
        })
}

/// A signature string: the text up to the body block for func/method, else the
/// first line of the node (bounded — a struct/const block body is not a
/// signature).
fn signature_text(def: Node<'_>, src: &[u8], def_text: &str) -> String {
    if let Some(body) = def.child_by_field_name("body") {
        let (start, end) = (def.start_byte(), body.start_byte());
        if end > start
            && let Ok(sig) = std::str::from_utf8(&src[start..end])
        {
            return sig.trim().to_string();
        }
    }
    def_text
        .lines()
        .next()
        .unwrap_or(def_text)
        .trim()
        .to_string()
}

/// Contiguous `comment` siblings immediately preceding `def`, joined — the Go
/// doc-comment convention. `None` when there is no leading comment.
fn doc_comment_of(def: Node<'_>, src: &[u8]) -> Option<String> {
    let mut lines = Vec::new();
    let mut sib = def.prev_sibling();
    while let Some(s) = sib {
        if s.kind() == "comment" {
            if let Ok(t) = s.utf8_text(src) {
                lines.push(t.to_string());
            }
            sib = s.prev_sibling();
        } else {
            break;
        }
    }
    if lines.is_empty() {
        None
    } else {
        lines.reverse();
        Some(lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge_builder::build_graph;
    use crate::extractor::extract_directory;
    use crate::graph::{EdgeKind, KnowledgeGraph};
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::Path;

    const SAMPLE: &str = r#"
package sample

import "fmt"

// Exported doc.
func Alpha() int { return 1 }

func beta() {
	var local = 3
	const localConst = 4
	_ = local
	_ = localConst
}

type Widget struct {
	Name string
}

type gadget struct{}

type Clocker interface {
	Tick() int
}

func (w *Widget) Tick() int { return 0 }

func (w Widget) reset() {}

const MaxN = 10

const (
	alpha = iota
	Beta
	gamma
)

var Registry = fmt.Sprintf("r")

var cache int

var _ = "blank"
"#;

    fn extract(src: &str, path: &str) -> Vec<CodeSymbol> {
        extract_go_symbols(src, path).expect("extract").symbols
    }

    // Falsifier #4 (ABI smoke, non-vacuous): the grammar binds under core 0.26.7
    // and a `.go` source parses to a non-null root with children.
    #[test]
    fn go_grammar_binds_and_parses() {
        let mut parser = Parser::new();
        parser
            .set_language(&GoExtractor.ts_language_for_path("grammar.go"))
            .expect("set_language(go) must be Ok — ABI mismatch otherwise");
        let tree = parser
            .parse("package p\nfunc f() {}\n", None)
            .expect("parse");
        let root = tree.root_node();
        assert!(!root.is_error());
        assert!(root.child_count() > 0, "root must have children");
    }

    #[test]
    fn go_extractor_rejects_a_recovered_partial_tree() {
        let error = extract_go_symbols("package p\nfunc retained( {\n", "pkg/lib.go")
            .expect_err("a syntax-error recovery tree is not authoritative extraction");
        assert!(matches!(error, ExtractorError::IncompleteSyntax { .. }));
    }

    // Non-vacuity for the direct AST census: every registered package surface
    // in this fixture is represented, while an unsupported type-set element
    // produces one exact gap rather than false Complete authority.
    #[test]
    fn go_ast_census_is_non_vacuous() {
        let complete = extract_go_symbols(
            "package p\nimport dep \"example.com/dep\"\ntype Base struct{}\ntype Alias = Base\ntype Record struct { Field Base }\nfunc Live() {}\n",
            "pkg/complete.go",
        )
        .expect("complete package surface");
        assert!(!complete.symbols.is_empty(), "known-positive population");
        assert!(
            complete.capture_gaps.is_empty(),
            "represented surface retained gaps: {:?}",
            complete.capture_gaps
        );

        let partial = extract_go_symbols(
            "package p\ntype Scalar interface { ~int | ~string }\n",
            "pkg/partial.go",
        )
        .expect("valid but only partially represented type set");
        assert!(
            partial
                .capture_gaps
                .iter()
                .any(|gap| { gap.kind == "unrepresented_go_interface_type_element" })
        );
    }

    /// RIGHT-REASON REGRESSION: tree-sitter also names generic type arguments
    /// `type_elem`. Only elements owned by an `interface_type` are Go type-set
    /// declarations; ordinary instantiations cannot downgrade structural
    /// authority.
    #[test]
    fn generic_type_arguments_are_not_interface_type_element_gaps() {
        let output = extract_go_symbols(
            concat!(
                "package p\n",
                "type laneTable[T any] struct{}\n",
                "type writeLane struct{}\n",
                "type session struct { lanes *laneTable[*writeLane] }\n",
            ),
            "generic_field.go",
        )
        .expect("valid generic Go source");
        assert!(
            output.capture_gaps.is_empty(),
            "generic arguments are not interface declarations: {:?}",
            output.capture_gaps
        );
    }

    /// RIGHT-REASON REGRESSION: fields of anonymous structs remain addressable
    /// when the type belongs to a package value or callable signature. They
    /// must enter the structural member population just like fields of a named
    /// struct; only block-local throwaway shapes remain intentionally omitted.
    #[test]
    fn addressable_anonymous_struct_fields_are_structural_members() {
        let source = concat!(
            "package p\n",
            "var keys struct { path string; pem []byte }\n",
            "func cases() []struct { name string; attrs int } { return nil }\n",
            "var sabotages = []struct { variant string; enabled bool }{}\n",
        );
        let output = extract_go_symbols(source, "anonymous_fields.go")
            .expect("valid anonymous-struct source");
        assert!(
            output.capture_gaps.is_empty(),
            "every promised anonymous field must be represented: {:?}",
            output.capture_gaps
        );
        for (name, parent) in [
            ("path", "keys"),
            ("pem", "keys"),
            ("name", "cases"),
            ("attrs", "cases"),
            ("variant", "sabotages"),
            ("enabled", "sabotages"),
        ] {
            assert!(
                output.symbols.iter().any(|symbol| {
                    symbol.name == name
                        && symbol.kind == SymbolKind::Field
                        && symbol.parent.as_deref() == Some(parent)
                }),
                "missing {parent}::{name}: {:?}",
                output.symbols
            );
        }
    }

    // Falsifier #1: >0 symbols with the correct exported/unexported split.
    #[test]
    fn extract_yields_visibility_split() {
        let syms = extract(SAMPLE, "sample.go");
        assert!(!syms.is_empty());
        let alpha = syms.iter().find(|s| s.name == "Alpha").expect("Alpha");
        assert_eq!(alpha.visibility, Visibility::Public);
        assert_eq!(alpha.kind, SymbolKind::Function);
        let beta = syms.iter().find(|s| s.name == "beta").expect("beta");
        assert_eq!(beta.visibility, Visibility::Private);
    }

    // Method -> parent = receiver base type, across pointer/value/generic forms.
    #[test]
    fn method_parent_is_receiver_base_type() {
        let src = "package p\ntype T struct{}\nfunc (t *T) A() {}\nfunc (t T) b() {}\ntype G[U any] struct{}\nfunc (g *G[U]) C() {}\nfunc (g G[U]) d() {}\n";
        let syms = extract(src, "m.go");
        for (name, want_parent) in [("A", "T"), ("b", "T"), ("C", "G"), ("d", "G")] {
            let s = syms
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("method {name}"));
            assert_eq!(s.parent.as_deref(), Some(want_parent), "method {name}");
        }
    }

    #[test]
    fn interface_method_elements_are_structural_callables() {
        let src = concat!(
            "package p\n",
            "type Closer interface { Close() error }\n",
            "var netListen = func() interface { Reset() error } { return nil }\n",
        );
        let syms = extract(src, "interfaces.go");
        for (name, parent) in [("Close", "Closer"), ("Reset", "netListen")] {
            let method = syms
                .iter()
                .find(|symbol| symbol.name == name)
                .unwrap_or_else(|| panic!("interface method {name}"));
            assert_eq!(method.kind, SymbolKind::Function);
            assert_eq!(method.parent.as_deref(), Some(parent));
            assert!(!method.has_body, "interface method {name} has no body");
            assert_eq!(
                &src[method.span.0..method.span.1],
                format!("{name}() error"),
                "the structural extent must be the exact method element",
            );
        }
    }

    /// RIGHT-REASON REGRESSION: scip-go resolves an invocation through a
    /// function-local anonymous interface to that interface's `method_elem`.
    /// The structural graph must retain the same bodyless declaration so the
    /// provider/structural join does not discard otherwise complete Go Calls
    /// authority.
    #[test]
    fn local_anonymous_interface_method_is_a_structural_callable() {
        let src = concat!(
            "package p\n",
            "func canceled(err error) bool {\n",
            "    var value interface { CanceledError() bool }\n",
            "    return value.CanceledError()\n",
            "}\n",
        );
        let syms = extract(src, "local_interface.go");
        let method = syms
            .iter()
            .find(|symbol| symbol.name == "CanceledError")
            .expect("local anonymous-interface method");
        assert_eq!(method.kind, SymbolKind::Function);
        assert_eq!(method.parent.as_deref(), Some("canceled"));
        assert!(
            !method.has_body,
            "an interface contract has no executable body"
        );
        assert_eq!(
            &src[method.span.0..method.span.1],
            "CanceledError() bool",
            "the provider join requires the exact method-element extent",
        );
    }

    #[test]
    fn function_valued_package_variable_is_a_structural_callable() {
        let src = concat!(
            "package p\n",
            "var seam = func() int { return target() }\n",
            "func target() int { return 1 }\n",
        );
        let syms = extract(src, "seam.go");
        let seam = syms
            .iter()
            .find(|symbol| symbol.name == "seam")
            .expect("function-valued package variable");
        assert_eq!(seam.kind, SymbolKind::CallableValue);
        assert!(seam.has_body);
        assert!(seam.parent.is_none());
        assert_eq!(
            &src[seam.span.0..seam.span.1],
            "seam = func() int { return target() }",
        );
    }

    // Function-local values and types remain outside the durable symbol floor;
    // a callable contract declared by a local anonymous interface is retained
    // because provider-backed Calls resolves invocations to that exact extent.
    #[test]
    fn function_local_values_and_types_are_rejected_but_callable_contract_is_retained() {
        let syms = extract(SAMPLE, "sample.go");
        assert!(
            syms.iter()
                .all(|s| s.name != "local" && s.name != "localConst"),
            "function-local var/const must not be captured"
        );

        let local = extract_go_symbols(
            "package p\nfunc outer() {\n type Alias = int\n type Local struct{}\n var callback interface { Hidden() error }\n _ = callback\n}\n",
            "pkg/local.go",
        )
        .expect("valid local declarations");
        for name in ["Alias", "Local", "callback"] {
            assert!(
                local.symbols.iter().all(|symbol| symbol.name != name),
                "function-local `{name}` escaped into the durable symbol graph"
            );
        }
        let hidden = local
            .symbols
            .iter()
            .find(|symbol| symbol.name == "Hidden")
            .expect("local anonymous-interface callable contract");
        assert_eq!(hidden.parent.as_deref(), Some("outer"));
        assert!(!hidden.has_body);
        assert!(
            local.capture_gaps.is_empty(),
            "local non-callables are outside the floor and the callable contract is represented"
        );
    }

    // Grouped/iota const blocks: every name captured; blank `_` skipped.
    #[test]
    fn grouped_const_and_blank_handling() {
        let syms = extract(SAMPLE, "sample.go");
        for n in ["MaxN", "alpha", "Beta", "gamma"] {
            assert!(
                syms.iter()
                    .any(|s| s.name == n && s.kind == SymbolKind::Const),
                "const {n}"
            );
        }
        assert!(
            syms.iter().all(|s| s.name != "_"),
            "blank identifier must be skipped"
        );
        // package_clause is project-unit metadata, not a source symbol.
        assert!(
            syms.iter().all(|s| s.kind != SymbolKind::Module),
            "no package/module symbol"
        );
    }

    // Byte-boundary safety (falsifier #5): non-ASCII in strings/comments does not
    // panic the first-rune visibility path.
    #[test]
    fn non_ascii_source_does_not_panic() {
        let src =
            "package p\n// 日本語 comment 🎉\nvar Msg = \"héllo — 世界 🌍\"\nfunc Ünïcode() {}\n";
        let syms = extract(src, "u.go");
        // The exported ASCII-first var + the U-umlaut-first func are Public.
        assert!(
            syms.iter()
                .any(|s| s.name == "Msg" && s.visibility == Visibility::Public)
        );
        let uni = syms.iter().find(|s| s.name == "Ünïcode").expect("Ünïcode");
        assert_eq!(uni.visibility, Visibility::Public, "Ü is uppercase");
    }

    // Falsifier #2 / WIRING proof: a `.go` path routes through the REGISTRY to
    // GoExtractor. RED before the registry row is added (is_none / no Go symbols).
    #[test]
    fn go_extension_wired_to_go_extractor() {
        assert!(
            crate::language::extractor_for_extension("go").is_some(),
            "the `go` extension must resolve to a registered extractor"
        );
        assert_eq!(crate::language::language_for_extension("go"), Some("go"));
        // extract_file dispatches by extension -> GoExtractor.
        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("wired.go");
        std::fs::write(&f, "package p\nfunc Exported() {}\n").expect("write");
        let out = crate::extractor::extract_file(&f, dir.path()).expect("extract_file(.go)");
        assert!(
            out.symbols.iter().any(|s| s.name == "Exported"),
            "extract_file must route .go to GoExtractor and yield its symbols"
        );
    }

    // Falsifier #3 (non-vacuous golden guard): the checked-in golden mini-package
    // extracts, through the SAME extract_directory + build_graph path, to EXACTLY
    // the hand-verified + go/ast-derived top-level NAME SET and per-kind counts.
    // Break any mapping (visibility, kind, the top-level filter) and this fails.
    #[test]
    fn golden_fixture_set_and_kind_equality() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/go_shape");
        let outputs = extract_directory(&dir).expect("extract_directory(testdata/go_shape)");
        let mut graph = KnowledgeGraph::new();
        let stats = build_graph(&outputs, &mut graph).expect("build_graph");

        // Positive control (MUST-FIX #4): edges exist and a nested method has an
        // inbound Contains edge — the harness's uniform-0 finding is only
        // meaningful once the graph is proven live.
        assert!(stats.edges_added > 0, "build_graph produced no edges");
        let contains_inbound = graph
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
        assert!(
            contains_inbound > 0,
            "no nested method received an inbound Contains edge"
        );

        // Top-level (parent=None), non-test identifier population.
        let mut got: BTreeMap<String, String> = BTreeMap::new();
        let mut test_names: BTreeSet<String> = BTreeSet::new();
        for n in graph.all_nodes() {
            if n.symbol_name.contains("::") || n.kind == "import" {
                continue; // nested (method) — not top-level
            }
            if n.is_test_only == Some(true) {
                test_names.insert(n.symbol_name.clone());
                continue;
            }
            got.insert(n.symbol_name.clone(), n.kind.clone());
        }

        // Hand-verified + go/ast-derived expected set for testdata/go_shape.
        // (name -> extractor SymbolKind Display).
        let expected: &[(&str, &str)] = &[
            ("Alpha", "function"),    // exported func
            ("beta", "function"),     // unexported func
            ("Widget", "struct"),     // exported struct
            ("gadget", "struct"),     // unexported struct
            ("Clocker", "trait"),     // exported interface -> Trait
            ("Meter", "struct"),      // defined type `type Meter float64` -> Struct
            ("Handle", "type_alias"), // alias remains distinct from a defined type
            ("MaxN", "const"),        // exported const
            ("lowConst", "const"),    // unexported const
            ("First", "const"),       // grouped/iota const (exported)
            ("second", "const"),      // grouped/iota const (unexported)
            ("Registry", "static"),   // exported package var (single)
            ("cache", "static"),      // unexported package var (single)
            ("GroupedVar", "static"), // exported grouped var (var_spec_list — AUGMENT pattern 11)
            ("groupedVar", "static"), // unexported grouped var
        ];
        let expected_set: BTreeMap<String, String> = expected
            .iter()
            .map(|(n, k)| ((*n).to_string(), (*k).to_string()))
            .collect();

        assert_eq!(
            got, expected_set,
            "top-level identifier NAME SET / kinds diverged from the go/ast oracle"
        );

        // Test-file symbol lands in the test population, not the primary set.
        assert!(
            test_names.contains("TestAlpha"),
            "TestAlpha should be is_test_only"
        );
        assert!(
            !got.contains_key("TestAlpha"),
            "test symbol must be excluded from the primary set"
        );

        // Exported/unexported split (the DEC-R8-PUBAPI axis).
        let exported = graph
            .all_nodes()
            .iter()
            .filter(|n| {
                !n.symbol_name.contains("::")
                    && n.is_test_only != Some(true)
                    && n.visibility == "pub"
            })
            .count();
        assert_eq!(
            exported, 9,
            "expected 9 exported top-level identifiers in the golden fixture"
        );
    }

    // --- WU-0023 P3b Bundle-3: is_test_root rider ------------------------------

    #[test]
    fn is_go_test_entry_matches_go_exact_rule() {
        // Bare prefix + non-lowercase follow rune → test entry.
        for name in [
            "Test",
            "TestFoo",
            "Test_foo",
            "Benchmark",
            "BenchmarkX",
            "Example",
            "ExampleY",
            "Fuzz",
            "FuzzZ",
            "Fuzz1",
        ] {
            assert!(is_go_test_entry(name), "{name} should be a Go test entry");
        }
        // Lowercase follow rune → an ordinary exported symbol sharing the prefix.
        for name in [
            "Testing",
            "Testable",
            "Benchmarker",
            "Examples",
            "Fuzzy",
            "Testicle",
            "notTest",
            "Helper",
        ] {
            assert!(
                !is_go_test_entry(name),
                "{name} must NOT be a Go test entry"
            );
        }
    }

    /// A `TestXxx` FUNCTION in a `_test.go` file is stamped `is_test_root`; a
    /// method sharing the prefix, and a `TestingHelper`, are NOT — RED on HEAD
    /// where `is_test_root` was hardcoded `false`. NON-VACUOUS: `TestingHelper`
    /// (lowercase follow rune) proves the rule is not a naive prefix match.
    #[test]
    fn extractor_stamps_is_test_root_for_go_test_entries_only() {
        let src = "package p\n\
                   func TestAlpha() {}\n\
                   func TestingHelper() {}\n\
                   func (w Widget) TestMethod() {}\n\
                   type Widget struct{}\n";
        let out = extract_go_symbols(src, "pkg/thing_test.go").unwrap();
        let root = |name: &str| {
            out.symbols
                .iter()
                .find(|s| s.name == name)
                .unwrap()
                .is_test_root
        };
        assert!(root("TestAlpha"), "TestAlpha must be a test root");
        assert!(
            !root("TestingHelper"),
            "TestingHelper must NOT be a test root (lowercase follow rune)"
        );
        assert!(
            !root("TestMethod"),
            "a method (receiver present) is never a Go test entry root"
        );
    }

    #[test]
    fn is_test_root_false_outside_test_file() {
        // Same `TestAlpha` name in a NON-`_test.go` file is not a test entry.
        let out = extract_go_symbols("package p\nfunc TestAlpha() {}\n", "pkg/thing.go").unwrap();
        assert!(
            !out.symbols
                .iter()
                .find(|s| s.name == "TestAlpha")
                .unwrap()
                .is_test_root,
            "a Test-prefixed func outside a _test.go file is NOT a test root"
        );
    }
}
