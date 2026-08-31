//! Python structural adapter.
//!
//! Python is dynamic, but its declared source shape is not opaque. This adapter
//! emits byte-exact classes, functions, methods, properties, imports, type
//! aliases, module/class bindings, and mechanically named instance fields. It
//! does not pretend that these structural facts prove runtime dispatch; that
//! authority belongs to the semantic-provider layer.

use std::path::Path;

use chrono::Utc;
use tree_sitter::Node;

use super::common::{SymbolFacts, code_symbol, node_text, simple_type_target, unquoted_name};
use super::{LanguageExtractor, NamedCallForm, NamedCallSyntax};
use crate::structural_ir::{
    CodeSymbol, ExtractorError, ExtractorOutput, StructuralCaptureGap, StructuralRelation,
    SymbolKind, Visibility,
};

pub struct PythonExtractor;

impl LanguageExtractor for PythonExtractor {
    fn language(&self) -> &'static str {
        "python"
    }

    fn ts_language_for_path(&self, _file_path: &str) -> tree_sitter::Language {
        tree_sitter_python::LANGUAGE.into()
    }

    fn named_callable_declaration_kinds(&self) -> &'static [&'static str] {
        &["function_definition"]
    }

    fn named_call_syntax<'tree>(&self, call: Node<'tree>) -> Option<NamedCallSyntax<'tree>> {
        if call.kind() != "call" {
            return None;
        }
        python_call_target(call.child_by_field_name("function")?)
    }

    fn cross_document_surface_elidable_body<'tree>(
        &self,
        declaration: Node<'tree>,
        _source: &str,
    ) -> Option<Node<'tree>> {
        if declaration.kind() != "function_definition"
            || !python_is_module_function(declaration)
            || declaration.child_by_field_name("return_type").is_none()
            || !python_parameters_are_fully_annotated(declaration)
        {
            return None;
        }
        let body = declaration.child_by_field_name("body")?;
        (!python_body_has_cross_document_escape(body)).then_some(body)
    }

    fn structural_callable_extent(&self, declaration: Node<'_>) -> (usize, usize) {
        let extent = declaration_extent(declaration);
        (extent.start_byte(), extent.end_byte())
    }

    fn extract(&self, source: &str, file_path: &str) -> Result<ExtractorOutput, ExtractorError> {
        extract_python_symbols(source, file_path)
    }
}

fn python_call_target(function: Node<'_>) -> Option<NamedCallSyntax<'_>> {
    match function.kind() {
        "identifier" => Some(NamedCallSyntax {
            callee: function,
            form: NamedCallForm::Direct,
            receiver_identity: None,
        }),
        "parenthesized_expression" => python_call_target(function.named_child(0)?),
        "attribute" => Some(NamedCallSyntax {
            callee: function.child_by_field_name("attribute")?,
            form: NamedCallForm::Method,
            receiver_identity: function.child_by_field_name("object"),
        }),
        _ => None,
    }
}

fn python_is_module_function(declaration: Node<'_>) -> bool {
    let Some(parent) = declaration.parent() else {
        return false;
    };
    if parent.kind() == "module" {
        return true;
    }
    parent.kind() == "decorated_definition"
        && parent
            .parent()
            .is_some_and(|owner| owner.kind() == "module")
}

fn python_parameters_are_fully_annotated(declaration: Node<'_>) -> bool {
    let Some(parameters) = declaration.child_by_field_name("parameters") else {
        return false;
    };
    let mut cursor = parameters.walk();
    parameters
        .named_children(&mut cursor)
        .all(python_parameter_is_annotated)
}

fn python_parameter_is_annotated(parameter: Node<'_>) -> bool {
    match parameter.kind() {
        "typed_parameter" | "typed_default_parameter" => true,
        // A bare `*` is a separator rather than a callable parameter. Named
        // splats are admitted only when their nested parameter is typed.
        "list_splat" | "dictionary_splat" => {
            let mut cursor = parameter.walk();
            let children = parameter.named_children(&mut cursor).collect::<Vec<_>>();
            children.is_empty() || children.iter().copied().any(python_parameter_is_annotated)
        }
        _ => false,
    }
}

fn python_body_has_cross_document_escape(node: Node<'_>) -> bool {
    if matches!(node.kind(), "global_statement" | "nonlocal_statement") {
        return true;
    }
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(python_body_has_cross_document_escape)
}

fn extract_python_symbols(
    source: &str,
    file_path: &str,
) -> Result<ExtractorOutput, ExtractorError> {
    let tree = PythonExtractor.parse_admitted_tree(source, file_path)?;
    let root = tree.root_node();
    let file_is_test = python_test_file(file_path);
    let mut context = WalkContext {
        file_is_test,
        containers: Vec::new(),
        symbols: Vec::new(),
    };
    visit(root, source, &mut context);
    let capture_gaps = python_capture_gaps(root, source, context.symbols.as_slice());
    let cross_document_surface_sha256 =
        crate::code_intel_semantic_refresh::cross_document_surface_sha256(
            &PythonExtractor,
            source,
            root,
        );

    Ok(ExtractorOutput {
        file_path: file_path.to_string(),
        file_hash: blake3::hash(source.as_bytes()).to_hex().to_string(),
        cross_document_surface_sha256,
        symbols: context.symbols,
        extracted_at: Utc::now(),
        has_platform_cfg: false,
        capture_gaps,
    })
}

fn python_capture_gaps(
    root: Node<'_>,
    source: &str,
    symbols: &[CodeSymbol],
) -> Vec<StructuralCaptureGap> {
    fn push_gap(gaps: &mut Vec<StructuralCaptureGap>, kind: &str, node: Node<'_>) {
        gaps.push(StructuralCaptureGap::new(
            kind,
            (node.start_byte(), node.end_byte()),
        ));
    }

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
        match node.kind() {
            "class_definition" | "function_definition" | "type_alias_statement" => {
                if symbol_count_at(declaration_extent(node)) == 0 {
                    push_gap(gaps, "unrepresented_named_declaration", node);
                }
            }
            "import_statement" | "import_from_statement" | "future_import_statement" => {
                if symbol_count_at(node) == 0 {
                    push_gap(gaps, "unrepresented_import_binding", node);
                }
            }
            "assignment" if !has_python_callable_ancestor(node) => {
                let expected = node
                    .child_by_field_name("left")
                    .map(|left| binding_names(left, source).len())
                    .unwrap_or(0);
                if expected > symbol_count_at(node) {
                    push_gap(gaps, "unrepresented_assignment_binding", node);
                }
            }
            // These constructs create module/class bindings in their headers,
            // while function-local control variables remain deliberately
            // outside the structural symbol floor.
            "for_statement" if !has_python_callable_ancestor(node) => {
                let expected = node
                    .child_by_field_name("left")
                    .map(|left| binding_names(left, source).len())
                    .unwrap_or(0);
                if expected > symbol_count_at(node) {
                    push_gap(gaps, "unrepresented_loop_binding", node);
                }
            }
            "with_statement" if !has_python_callable_ancestor(node) => {
                let expected = python_with_target_names(node, source).len();
                if expected > symbol_count_at(node) {
                    push_gap(gaps, "unrepresented_with_binding", node);
                }
            }
            "match_statement" if !has_python_callable_ancestor(node) => {
                push_gap(gaps, "unrepresented_match_binding", node);
            }
            "named_expression" if !has_python_callable_ancestor(node) => {
                push_gap(gaps, "unrepresented_named_expression_binding", node);
            }
            _ => {}
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

fn has_python_callable_ancestor(node: Node<'_>) -> bool {
    let mut ancestor = node.parent();
    while let Some(candidate) = ancestor {
        if matches!(candidate.kind(), "function_definition" | "lambda") {
            return true;
        }
        ancestor = candidate.parent();
    }
    false
}

#[derive(Clone)]
struct Container {
    name: String,
    kind: SymbolKind,
}

struct WalkContext {
    file_is_test: bool,
    containers: Vec<Container>,
    symbols: Vec<CodeSymbol>,
}

impl WalkContext {
    fn parent_name(&self) -> Option<String> {
        self.containers
            .last()
            .map(|container| container.name.clone())
    }

    fn immediate_parent_is_type(&self) -> bool {
        self.containers.last().is_some_and(|container| {
            matches!(container.kind, SymbolKind::Class | SymbolKind::Interface)
        })
    }

    fn nearest_class_name(&self) -> Option<String> {
        self.containers
            .iter()
            .rev()
            .find(|container| matches!(container.kind, SymbolKind::Class | SymbolKind::Interface))
            .map(|container| container.name.clone())
    }
}

fn visit(node: Node<'_>, source: &str, context: &mut WalkContext) {
    match node.kind() {
        // The definition child is the source symbol; visiting decorators as a
        // separate subtree would manufacture identifier definitions.
        "decorated_definition" => {
            if let Some(definition) = node.child_by_field_name("definition") {
                visit(definition, source, context);
            }
        }
        "class_definition" => visit_class(node, source, context),
        "function_definition" => visit_function(node, source, context),
        "import_statement" | "import_from_statement" | "future_import_statement" => {
            emit_imports(node, source, context);
        }
        "type_alias_statement" => emit_type_alias(node, source, context),
        "assignment" => emit_assignment(node, source, context),
        "for_statement" => visit_for_statement(node, source, context),
        "with_statement" => visit_with_statement(node, source, context),
        _ => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                visit(child, source, context);
            }
        }
    }
}

fn durable_binding_kind(context: &WalkContext) -> Option<SymbolKind> {
    if context.immediate_parent_is_type() {
        Some(SymbolKind::Field)
    } else if context.containers.is_empty() {
        Some(SymbolKind::Variable)
    } else {
        None
    }
}

fn visit_for_statement(node: Node<'_>, source: &str, context: &mut WalkContext) {
    if let Some(kind) = durable_binding_kind(context)
        && let Some(left) = node.child_by_field_name("left")
    {
        for name in binding_names(left, source) {
            context.symbols.push(code_symbol(
                node,
                source,
                SymbolFacts {
                    name: name.clone(),
                    kind,
                    signature_end: None,
                    doc_comment: None,
                    visibility: python_visibility(&name),
                    parent: context.parent_name(),
                    is_test_only: context.file_is_test,
                    is_test_root: false,
                    has_body: false,
                    relations: Vec::new(),
                },
            ));
        }
    }
    for field in ["body", "alternative"] {
        if let Some(child) = node.child_by_field_name(field) {
            visit_named_children(child, source, context);
        }
    }
}

fn visit_with_statement(node: Node<'_>, source: &str, context: &mut WalkContext) {
    if let Some(kind) = durable_binding_kind(context) {
        for name in python_with_target_names(node, source) {
            context.symbols.push(code_symbol(
                node,
                source,
                SymbolFacts {
                    name: name.clone(),
                    kind,
                    signature_end: None,
                    doc_comment: None,
                    visibility: python_visibility(&name),
                    parent: context.parent_name(),
                    is_test_only: context.file_is_test,
                    is_test_root: false,
                    has_body: false,
                    relations: Vec::new(),
                },
            ));
        }
    }
    if let Some(body) = node.child_by_field_name("body") {
        visit_named_children(body, source, context);
    }
}

fn python_with_target_names(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(clause) = ({
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .find(|child| child.kind() == "with_clause")
    }) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut cursor = clause.walk();
    for item in clause
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "with_item")
    {
        let Some(value) = item.child_by_field_name("value") else {
            continue;
        };
        if value.kind() != "as_pattern" {
            continue;
        }
        let Some(alias) = value.child_by_field_name("alias") else {
            continue;
        };
        names.extend(binding_names(alias, source));
    }
    names
}

fn visit_class(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(name) = node_text(name_node, source).map(str::to_string) else {
        return;
    };
    let base_names = python_base_names(node, source);
    let kind = if base_names
        .iter()
        .any(|base| base.rsplit('.').next() == Some("Protocol"))
    {
        SymbolKind::Interface
    } else {
        SymbolKind::Class
    };
    let body = node.child_by_field_name("body");
    let extent = declaration_extent(node);
    context.symbols.push(code_symbol(
        extent,
        source,
        SymbolFacts {
            name: name.clone(),
            kind,
            signature_end: body.map(|body| body.start_byte()),
            doc_comment: body.and_then(|body| python_docstring(body, source)),
            visibility: python_visibility(&name),
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: body.is_some_and(|body| body_has_implementation(body, source)),
            relations: base_names
                .into_iter()
                .map(|target| StructuralRelation::Extends { target })
                .collect(),
        },
    ));

    context.containers.push(Container { name, kind });
    if let Some(body) = body {
        visit_named_children(body, source, context);
    }
    context.containers.pop();
}

fn visit_function(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(name) = node_text(name_node, source).map(str::to_string) else {
        return;
    };
    let is_method = context.immediate_parent_is_type();
    let kind = if is_method && name == "__init__" {
        SymbolKind::Constructor
    } else if is_method && python_property_definition(node, source) {
        SymbolKind::Property
    } else if is_method {
        SymbolKind::Method
    } else {
        SymbolKind::Function
    };
    let body = node.child_by_field_name("body");
    let extent = declaration_extent(node);
    let is_test_root = context.file_is_test && name.starts_with("test_");
    context.symbols.push(code_symbol(
        extent,
        source,
        SymbolFacts {
            name: name.clone(),
            kind,
            signature_end: body.map(|body| body.start_byte()),
            doc_comment: body.and_then(|body| python_docstring(body, source)),
            visibility: python_visibility(&name),
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root,
            has_body: body.is_some_and(|body| body_has_implementation(body, source)),
            relations: Vec::new(),
        },
    ));

    context.containers.push(Container { name, kind });
    if let Some(body) = body {
        visit_named_children(body, source, context);
    }
    context.containers.pop();
}

fn emit_assignment(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let type_relation = node
        .child_by_field_name("type")
        .and_then(|annotation| node_text(annotation, source))
        .and_then(simple_type_target)
        .map(|target| StructuralRelation::TypeOf { target });
    let value_is_callable = node
        .child_by_field_name("right")
        .is_some_and(|value| value.kind() == "lambda");

    if let Some((name, class_name)) = python_instance_field(left, source, context) {
        context.symbols.push(code_symbol(
            node,
            source,
            SymbolFacts {
                name: name.clone(),
                kind: SymbolKind::Field,
                signature_end: None,
                doc_comment: None,
                visibility: python_visibility(&name),
                parent: Some(class_name),
                is_test_only: context.file_is_test,
                is_test_root: false,
                has_body: false,
                relations: type_relation.into_iter().collect(),
            },
        ));
        return;
    }

    // Function-local bindings are runtime flow, not stable structural
    // definitions. Class and module bindings are durable source members.
    if context.containers.last().is_some_and(|container| {
        !matches!(container.kind, SymbolKind::Class | SymbolKind::Interface)
    }) {
        return;
    }
    let kind = if value_is_callable {
        SymbolKind::Function
    } else if context.immediate_parent_is_type() {
        SymbolKind::Field
    } else {
        SymbolKind::Variable
    };
    for name in binding_names(left, source) {
        context.symbols.push(code_symbol(
            node,
            source,
            SymbolFacts {
                name: name.clone(),
                kind,
                signature_end: None,
                doc_comment: None,
                visibility: python_visibility(&name),
                parent: context.parent_name(),
                is_test_only: context.file_is_test,
                is_test_root: false,
                has_body: value_is_callable,
                relations: type_relation.clone().into_iter().collect(),
            },
        ));
    }
}

fn emit_type_alias(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(left) = node.child_by_field_name("left") else {
        return;
    };
    let Some(name) = node_text(left, source).and_then(simple_type_target) else {
        return;
    };
    context.symbols.push(code_symbol(
        node,
        source,
        SymbolFacts {
            name: name.clone(),
            kind: SymbolKind::TypeAlias,
            signature_end: None,
            doc_comment: None,
            visibility: python_visibility(&name),
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: false,
            relations: Vec::new(),
        },
    ));
}

fn emit_imports(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let from_import = matches!(
        node.kind(),
        "import_from_statement" | "future_import_statement"
    );
    let mut emitted = 0_usize;
    let mut cursor = node.walk();
    let names = node.children_by_field_name("name", &mut cursor);
    for imported in names {
        let Some((name, target)) = import_binding(imported, source, from_import) else {
            continue;
        };
        context.symbols.push(code_symbol(
            node,
            source,
            SymbolFacts {
                name,
                kind: SymbolKind::Import,
                signature_end: None,
                doc_comment: None,
                visibility: Visibility::Private,
                parent: context.parent_name(),
                is_test_only: context.file_is_test,
                is_test_root: false,
                has_body: false,
                relations: vec![StructuralRelation::References { target }],
            },
        ));
        emitted += 1;
    }
    if emitted == 0
        && from_import
        && node_text(node, source).is_some_and(|text| text.contains("import *"))
        && let Some(target) = node
            .child_by_field_name("module_name")
            .or_else(|| node.child_by_field_name("module"))
            .and_then(|module| node_text(module, source))
            .map(str::to_string)
    {
        context.symbols.push(code_symbol(
            node,
            source,
            SymbolFacts {
                name: "*".to_string(),
                kind: SymbolKind::Import,
                signature_end: None,
                doc_comment: None,
                visibility: Visibility::Private,
                parent: context.parent_name(),
                is_test_only: context.file_is_test,
                is_test_root: false,
                has_body: false,
                relations: vec![StructuralRelation::References { target }],
            },
        ));
    }
}

fn import_binding(imported: Node<'_>, source: &str, from_import: bool) -> Option<(String, String)> {
    if imported.kind() == "aliased_import" {
        let target = imported
            .child_by_field_name("name")
            .and_then(|node| node_text(node, source))?
            .to_string();
        let name = imported
            .child_by_field_name("alias")
            .and_then(|node| node_text(node, source))?
            .to_string();
        return Some((name, target));
    }
    let target = node_text(imported, source)?.to_string();
    let name = if from_import {
        target.rsplit('.').next()?.to_string()
    } else {
        target.split('.').next()?.to_string()
    };
    Some((name, target))
}

fn python_base_names(node: Node<'_>, source: &str) -> Vec<String> {
    let Some(superclasses) = node.child_by_field_name("superclasses") else {
        return Vec::new();
    };
    let mut cursor = superclasses.walk();
    superclasses
        .named_children(&mut cursor)
        .filter(|base| base.kind() != "keyword_argument")
        .filter_map(|base| node_text(base, source))
        .filter_map(simple_type_target)
        .collect()
}

fn python_instance_field(
    left: Node<'_>,
    source: &str,
    context: &WalkContext,
) -> Option<(String, String)> {
    if left.kind() != "attribute" {
        return None;
    }
    let object = left.child_by_field_name("object")?;
    let object = node_text(object, source)?;
    if !matches!(object, "self" | "cls") {
        return None;
    }
    let attribute = left.child_by_field_name("attribute")?;
    let name = node_text(attribute, source)?.to_string();
    Some((name, context.nearest_class_name()?))
}

fn binding_names(node: Node<'_>, source: &str) -> Vec<String> {
    match node.kind() {
        "identifier" => node_text(node, source)
            .map(str::to_string)
            .into_iter()
            .collect(),
        "attribute" => Vec::new(),
        _ => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .flat_map(|child| binding_names(child, source))
                .collect()
        }
    }
}

fn declaration_extent(node: Node<'_>) -> Node<'_> {
    node.parent()
        .filter(|parent| parent.kind() == "decorated_definition")
        .unwrap_or(node)
}

fn python_property_definition(node: Node<'_>, source: &str) -> bool {
    let Some(decorated) = node
        .parent()
        .filter(|parent| parent.kind() == "decorated_definition")
    else {
        return false;
    };
    let mut cursor = decorated.walk();
    decorated
        .named_children(&mut cursor)
        .filter(|child| child.kind() == "decorator")
        .filter_map(|decorator| node_text(decorator, source))
        .map(|decorator| decorator.trim().trim_start_matches('@'))
        .any(|decorator| {
            decorator == "property"
                || decorator.ends_with(".setter")
                || decorator.ends_with(".deleter")
                || decorator.ends_with(".getter")
        })
}

fn python_docstring(body: Node<'_>, source: &str) -> Option<String> {
    let first = body.named_child(0)?;
    if first.kind() != "expression_statement" {
        return None;
    }
    let literal = first.named_child(0)?;
    matches!(literal.kind(), "string" | "concatenated_string")
        .then(|| node_text(literal, source).map(unquoted_name))
        .flatten()
}

fn body_has_implementation(body: Node<'_>, source: &str) -> bool {
    let mut cursor = body.walk();
    body.named_children(&mut cursor).any(|child| {
        let text = node_text(child, source).unwrap_or_default().trim();
        !matches!(text, "pass" | "...")
            && !(child.kind() == "expression_statement"
                && child.named_child(0).is_some_and(|literal| {
                    matches!(literal.kind(), "string" | "concatenated_string")
                }))
    })
}

fn visit_named_children(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        visit(child, source, context);
    }
}

fn python_visibility(name: &str) -> Visibility {
    let magic = name.starts_with("__") && name.ends_with("__") && name.len() > 4;
    if name.starts_with('_') && !magic {
        Visibility::Private
    } else {
        Visibility::Public
    }
}

fn python_test_file(file_path: &str) -> bool {
    let path = Path::new(file_path);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    file_name.starts_with("test_")
        || file_name.ends_with("_test.py")
        || path
            .components()
            .any(|component| component.as_os_str() == "tests")
}
