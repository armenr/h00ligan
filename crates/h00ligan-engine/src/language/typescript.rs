//! TypeScript, JavaScript, TSX, and JSX structural adapter.
//!
//! The adapter selects the embedded TSX grammar by source path, preserves
//! module export and member accessibility separately, and emits declared
//! inheritance/implementation/type facts. JavaScript runtime dispatch remains
//! semantic-provider authority; the structural floor does not guess it.

use std::collections::BTreeSet;
use std::path::Path;

use chrono::Utc;
use tree_sitter::{Node, Tree};

use super::common::{
    SymbolFacts, code_symbol, node_text, parse_tree_with_recovery_admission, simple_type_target,
    unquoted_name,
};
use super::{
    LanguageExtractor, NamedCallForm, NamedCallSyntax, NamedCallableSyntax,
    named_declaration_callable_syntax,
};
use crate::structural_ir::{
    CodeSymbol, ExtractorError, ExtractorOutput, StructuralCaptureGap, StructuralRelation,
    SymbolKind, Visibility,
};

pub struct TypeScriptExtractor;

impl LanguageExtractor for TypeScriptExtractor {
    fn language(&self) -> &'static str {
        "typescript"
    }

    fn source_file_is_test(&self, file_path: &str) -> bool {
        typescript_test_file(file_path)
    }

    fn ts_language_for_path(&self, file_path: &str) -> tree_sitter::Language {
        if matches!(
            Path::new(file_path)
                .extension()
                .and_then(|extension| extension.to_str())
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("tsx" | "jsx")
        ) {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        } else {
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
        }
    }

    fn parse_admitted_tree(&self, source: &str, file_path: &str) -> Result<Tree, ExtractorError> {
        parse_tree_with_recovery_admission(
            &self.ts_language_for_path(file_path),
            source,
            file_path,
            generic_tagged_template_recovery_is_exact,
        )
    }

    fn named_callable_declaration_kinds(&self) -> &'static [&'static str] {
        &[
            "function_declaration",
            "generator_function_declaration",
            "function_signature",
            "method_definition",
            "method_signature",
            "abstract_method_signature",
        ]
    }

    fn anonymous_callable_declaration_kinds(&self) -> &'static [&'static str] {
        &[
            "arrow_function",
            "function_expression",
            "generator_function",
        ]
    }

    fn named_callable_syntax(&self, name: Node<'_>) -> Option<NamedCallableSyntax> {
        if let Some(declarator) = name.parent().filter(|node| {
            node.kind() == "variable_declarator"
                && node
                    .child_by_field_name("name")
                    .is_some_and(|candidate| candidate.byte_range() == name.byte_range())
        }) && declarator
            .child_by_field_name("value")
            .is_some_and(|value| {
                matches!(
                    value.kind(),
                    "arrow_function" | "function_expression" | "generator_function"
                )
            })
        {
            let declaration = declarator.parent().unwrap_or(declarator);
            let extent = declaration_extent(declaration);
            return Some(NamedCallableSyntax {
                extent: (extent.start_byte(), extent.end_byte()),
                has_body: true,
                is_package_function: false,
                structural_target: typescript_callable_binding_is_structural(declarator),
            });
        }
        named_declaration_callable_syntax(self, name)
    }

    fn named_call_syntax<'tree>(&self, call: Node<'tree>) -> Option<NamedCallSyntax<'tree>> {
        if call.kind() != "call_expression" {
            return None;
        }
        typescript_call_target(call.child_by_field_name("function")?)
    }

    fn cross_document_surface_elidable_body<'tree>(
        &self,
        declaration: Node<'tree>,
        _source: &str,
    ) -> Option<Node<'tree>> {
        matches!(
            declaration.kind(),
            "function_declaration" | "generator_function_declaration"
        )
        .then(|| declaration.child_by_field_name("return_type"))
        .flatten()?;
        declaration.child_by_field_name("body")
    }

    fn structural_callable_extent(&self, declaration: Node<'_>) -> (usize, usize) {
        let extent = declaration_extent(declaration);
        (extent.start_byte(), extent.end_byte())
    }

    fn extract(&self, source: &str, file_path: &str) -> Result<ExtractorOutput, ExtractorError> {
        extract_typescript_symbols(source, file_path)
    }
}

fn typescript_callable_binding_is_structural(declarator: Node<'_>) -> bool {
    let mut ancestor = declarator.parent();
    while let Some(node) = ancestor {
        if matches!(
            node.kind(),
            "function_declaration"
                | "generator_function_declaration"
                | "function_expression"
                | "generator_function"
                | "arrow_function"
                | "method_definition"
                | "class_static_block"
        ) {
            return false;
        }
        ancestor = node.parent();
    }
    true
}

fn typescript_call_target(function: Node<'_>) -> Option<NamedCallSyntax<'_>> {
    match function.kind() {
        "identifier" => Some(NamedCallSyntax {
            callee: function,
            form: NamedCallForm::Direct,
            receiver_identity: None,
        }),
        "parenthesized_expression" => typescript_call_target(function.named_child(0)?),
        "member_expression" => Some(NamedCallSyntax {
            callee: function.child_by_field_name("property")?,
            form: NamedCallForm::Method,
            receiver_identity: function.child_by_field_name("object"),
        }),
        _ => None,
    }
}

fn extract_typescript_symbols(
    source: &str,
    file_path: &str,
) -> Result<ExtractorOutput, ExtractorError> {
    let tree = TypeScriptExtractor.parse_admitted_tree(source, file_path)?;
    let root = tree.root_node();
    let file_is_test = typescript_test_file(file_path);
    let commonjs = commonjs_facts(root, source, file_is_test);
    let commonjs_mode = commonjs_extension(file_path) || commonjs.saw_surface;
    let mut context = WalkContext {
        file_is_test,
        commonjs_mode,
        containers: Vec::new(),
        symbols: Vec::new(),
    };
    visit(root, source, &mut context);
    context.symbols.extend(commonjs.symbols.iter().cloned());
    let mut capture_gaps = typescript_capture_gaps(root, source, context.symbols.as_slice());
    capture_gaps.extend(commonjs.capture_gaps);
    capture_gaps.sort_by(|left, right| left.span.cmp(&right.span).then(left.kind.cmp(&right.kind)));
    capture_gaps.dedup();
    let cross_document_surface_sha256 =
        crate::code_intel_semantic_refresh::cross_document_surface_sha256(
            &TypeScriptExtractor,
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

#[derive(Default)]
struct CommonJsFacts {
    saw_surface: bool,
    symbols: Vec<CodeSymbol>,
    capture_gaps: Vec<StructuralCaptureGap>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CommonJsExportTarget {
    Root,
    Named(String),
    Dynamic,
}

fn commonjs_extension(file_path: &str) -> bool {
    matches!(
        Path::new(file_path)
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("cjs" | "cts")
    )
}

fn commonjs_facts(root: Node<'_>, source: &str, file_is_test: bool) -> CommonJsFacts {
    fn walk(node: Node<'_>, source: &str, file_is_test: bool, facts: &mut CommonJsFacts) {
        if node.kind() == "call_expression" {
            collect_commonjs_require(node, source, file_is_test, facts);
        } else if node.kind() == "assignment_expression" {
            collect_commonjs_export(node, source, file_is_test, facts);
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            walk(child, source, file_is_test, facts);
        }
    }

    let mut facts = CommonJsFacts::default();
    walk(root, source, file_is_test, &mut facts);
    facts
        .capture_gaps
        .sort_by(|left, right| left.span.cmp(&right.span).then(left.kind.cmp(&right.kind)));
    facts.capture_gaps.dedup();
    facts
}

fn collect_commonjs_require(
    call: Node<'_>,
    source: &str,
    file_is_test: bool,
    facts: &mut CommonJsFacts,
) {
    if !is_commonjs_require_call(call, source) {
        return;
    }
    facts.saw_surface = true;
    let Some(target) = static_commonjs_require_target(call, source) else {
        facts.capture_gaps.push(StructuralCaptureGap::new(
            "unresolved_commonjs_require",
            (call.start_byte(), call.end_byte()),
        ));
        return;
    };

    let (extent, bindings) = commonjs_require_binding(call, source);
    let names = if bindings.is_empty() {
        vec![target.clone()]
    } else {
        bindings
    };
    for name in names {
        facts.symbols.push(code_symbol(
            extent,
            source,
            SymbolFacts {
                name,
                kind: SymbolKind::Import,
                signature_end: None,
                doc_comment: preceding_doc_comment(extent, source),
                visibility: Visibility::Private,
                parent: None,
                is_test_only: file_is_test,
                is_test_root: false,
                has_body: false,
                relations: vec![StructuralRelation::References {
                    target: target.clone(),
                }],
            },
        ));
    }
}

fn is_commonjs_require_call(call: Node<'_>, source: &str) -> bool {
    call.kind() == "call_expression"
        && call
            .child_by_field_name("function")
            .is_some_and(|function| is_unshadowed_commonjs_identifier(function, "require", source))
}

fn static_commonjs_require_target(call: Node<'_>, source: &str) -> Option<String> {
    is_commonjs_require_call(call, source).then_some(())?;
    let arguments = call.child_by_field_name("arguments")?;
    let mut cursor = arguments.walk();
    let mut named = arguments.named_children(&mut cursor);
    let argument = named.next()?;
    if named.next().is_some() {
        return None;
    }
    static_javascript_string(argument, source)
}

fn commonjs_require_binding<'tree>(call: Node<'tree>, source: &str) -> (Node<'tree>, Vec<String>) {
    let Some(declarator) = call
        .parent()
        .filter(|parent| parent.kind() == "variable_declarator")
        .filter(|declarator| {
            declarator
                .child_by_field_name("value")
                .is_some_and(|value| same_node(value, call))
        })
    else {
        return (call, Vec::new());
    };
    let names = declarator
        .child_by_field_name("name")
        .map(|name| binding_names(name, source))
        .unwrap_or_default();
    let extent = declarator
        .parent()
        .filter(|parent| {
            matches!(
                parent.kind(),
                "lexical_declaration" | "variable_declaration"
            )
        })
        .map(declaration_extent)
        .unwrap_or(declarator);
    (extent, names)
}

fn collect_commonjs_export(
    assignment: Node<'_>,
    source: &str,
    file_is_test: bool,
    facts: &mut CommonJsFacts,
) {
    let Some(left) = assignment.child_by_field_name("left") else {
        return;
    };
    let Some(target) = commonjs_export_target(left, source) else {
        return;
    };
    facts.saw_surface = true;
    let Some(right) = assignment.child_by_field_name("right") else {
        return;
    };
    match target {
        CommonJsExportTarget::Dynamic => facts.capture_gaps.push(StructuralCaptureGap::new(
            "unresolved_commonjs_export",
            (left.start_byte(), left.end_byte()),
        )),
        CommonJsExportTarget::Named(name) => push_commonjs_export(
            facts,
            assignment,
            source,
            file_is_test,
            name,
            direct_identifier(right, source),
        ),
        CommonJsExportTarget::Root => {
            push_commonjs_export(
                facts,
                assignment,
                source,
                file_is_test,
                "module.exports".into(),
                direct_identifier(right, source),
            );
            if right.kind() == "object" {
                collect_commonjs_object_exports(right, assignment, source, file_is_test, facts);
            }
        }
    }
}

fn collect_commonjs_object_exports(
    object: Node<'_>,
    assignment: Node<'_>,
    source: &str,
    file_is_test: bool,
    facts: &mut CommonJsFacts,
) {
    let mut cursor = object.walk();
    for member in object.named_children(&mut cursor) {
        match member.kind() {
            "shorthand_property_identifier" => {
                if let Some(name) = node_text(member, source).map(unquoted_name) {
                    push_commonjs_export(
                        facts,
                        assignment,
                        source,
                        file_is_test,
                        name.clone(),
                        Some(name),
                    );
                }
            }
            "pair" => {
                let name = member
                    .child_by_field_name("key")
                    .and_then(|key| static_property_name(key, source));
                let value = member.child_by_field_name("value");
                if let Some(name) = name {
                    push_commonjs_export(
                        facts,
                        assignment,
                        source,
                        file_is_test,
                        name,
                        value.and_then(|value| direct_identifier(value, source)),
                    );
                } else {
                    facts.capture_gaps.push(StructuralCaptureGap::new(
                        "unresolved_commonjs_export",
                        (member.start_byte(), member.end_byte()),
                    ));
                }
            }
            "method_definition" => {
                if let Some(name) =
                    declared_member_name(member).and_then(|name| static_property_name(name, source))
                {
                    push_commonjs_export(facts, assignment, source, file_is_test, name, None);
                } else {
                    facts.capture_gaps.push(StructuralCaptureGap::new(
                        "unresolved_commonjs_export",
                        (member.start_byte(), member.end_byte()),
                    ));
                }
            }
            "spread_element" => facts.capture_gaps.push(StructuralCaptureGap::new(
                "unresolved_commonjs_export",
                (member.start_byte(), member.end_byte()),
            )),
            _ => {}
        }
    }
}

fn push_commonjs_export(
    facts: &mut CommonJsFacts,
    extent: Node<'_>,
    source: &str,
    file_is_test: bool,
    name: String,
    local_target: Option<String>,
) {
    facts.symbols.push(code_symbol(
        extent,
        source,
        SymbolFacts {
            name,
            kind: SymbolKind::Export,
            signature_end: None,
            doc_comment: preceding_doc_comment(extent, source),
            visibility: Visibility::Public,
            parent: None,
            is_test_only: file_is_test,
            is_test_root: false,
            has_body: false,
            relations: local_target
                .map(|target| StructuralRelation::References { target })
                .into_iter()
                .collect(),
        },
    ));
}

fn commonjs_export_target(left: Node<'_>, source: &str) -> Option<CommonJsExportTarget> {
    if is_module_exports(left, source) {
        return Some(CommonJsExportTarget::Root);
    }
    match left.kind() {
        "member_expression" => {
            let object = left.child_by_field_name("object")?;
            let property = left.child_by_field_name("property")?;
            if is_module_exports(object, source)
                || is_unshadowed_commonjs_identifier(object, "exports", source)
            {
                return static_property_name(property, source)
                    .map(CommonJsExportTarget::Named)
                    .or(Some(CommonJsExportTarget::Dynamic));
            }
        }
        "subscript_expression" => {
            let object = left.child_by_field_name("object")?;
            if is_module_exports(object, source)
                || is_unshadowed_commonjs_identifier(object, "exports", source)
            {
                return left
                    .child_by_field_name("index")
                    .and_then(|index| static_subscript_property_name(index, source))
                    .map(CommonJsExportTarget::Named)
                    .or(Some(CommonJsExportTarget::Dynamic));
            }
        }
        _ => {}
    }
    None
}

fn is_module_exports(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "member_expression" => {
            node.child_by_field_name("object")
                .is_some_and(|object| is_unshadowed_commonjs_identifier(object, "module", source))
                && node
                    .child_by_field_name("property")
                    .is_some_and(|property| node_text(property, source) == Some("exports"))
        }
        "subscript_expression" => {
            node.child_by_field_name("object")
                .is_some_and(|object| is_unshadowed_commonjs_identifier(object, "module", source))
                && node
                    .child_by_field_name("index")
                    .and_then(|index| static_javascript_string(index, source))
                    .as_deref()
                    == Some("exports")
        }
        _ => false,
    }
}

fn static_property_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "property_identifier" | "identifier" | "private_property_identifier" | "number" => {
            node_text(node, source).map(unquoted_name)
        }
        "string" => static_javascript_string(node, source),
        _ => None,
    }
}

fn static_subscript_property_name(node: Node<'_>, source: &str) -> Option<String> {
    match node.kind() {
        "string" => static_javascript_string(node, source),
        "number" => node_text(node, source).map(str::to_string),
        _ => None,
    }
}

fn static_javascript_string(node: Node<'_>, source: &str) -> Option<String> {
    if node.kind() != "string" {
        return None;
    }
    let mut cursor = node.walk();
    if node
        .named_children(&mut cursor)
        .any(|child| child.kind() == "escape_sequence")
    {
        return None;
    }
    node_text(node, source).map(unquoted_name)
}

fn direct_identifier(node: Node<'_>, source: &str) -> Option<String> {
    (node.kind() == "identifier")
        .then(|| node_text(node, source).map(str::to_string))
        .flatten()
}

fn same_node(left: Node<'_>, right: Node<'_>) -> bool {
    left.kind() == right.kind()
        && left.start_byte() == right.start_byte()
        && left.end_byte() == right.end_byte()
}

/// Node exposes `require`, `module`, and `exports` as wrapper bindings, but
/// source declarations with the same spelling own the reference instead. Keep
/// CommonJS recognition at that lexical boundary rather than treating text as
/// identity.
fn is_unshadowed_commonjs_identifier(node: Node<'_>, name: &str, source: &str) -> bool {
    node.kind() == "identifier"
        && node_text(node, source) == Some(name)
        && !commonjs_identifier_has_source_binding(node, name, source)
}

fn commonjs_identifier_has_source_binding(identifier: Node<'_>, name: &str, source: &str) -> bool {
    let mut ancestor = identifier.parent();
    while let Some(scope) = ancestor {
        if commonjs_scope_binds_name(scope, name, source) {
            return true;
        }
        ancestor = scope.parent();
    }
    false
}

fn commonjs_scope_binds_name(scope: Node<'_>, name: &str, source: &str) -> bool {
    match scope.kind() {
        "function_declaration"
        | "generator_function_declaration"
        | "function_expression"
        | "generator_function"
        | "arrow_function"
        | "method_definition" => {
            let own_name_binds = !matches!(scope.kind(), "arrow_function" | "method_definition")
                && scope
                    .child_by_field_name("name")
                    .is_some_and(|binding| binding_node_contains(binding, name, source));
            let parameter_binds = scope
                .child_by_field_name("parameter")
                .or_else(|| scope.child_by_field_name("parameters"))
                .is_some_and(|parameters| binding_node_contains(parameters, name, source));
            own_name_binds
                || parameter_binds
                || scope
                    .child_by_field_name("body")
                    .is_some_and(|body| contains_function_scoped_var(body, name, source))
        }
        "catch_clause" => scope
            .child_by_field_name("parameter")
            .is_some_and(|parameter| binding_node_contains(parameter, name, source)),
        "program" => {
            direct_runtime_binding(scope, name, source)
                || contains_function_scoped_var(scope, name, source)
        }
        "statement_block" => direct_runtime_binding(scope, name, source),
        "class_static_block" => {
            direct_runtime_binding(scope, name, source)
                || contains_function_scoped_var(scope, name, source)
        }
        "for_statement" | "for_in_statement" => direct_runtime_binding(scope, name, source),
        "switch_body" => switch_runtime_binding(scope, name, source),
        _ => false,
    }
}

fn direct_runtime_binding(scope: Node<'_>, name: &str, source: &str) -> bool {
    let mut cursor = scope.walk();
    scope
        .named_children(&mut cursor)
        .any(|child| runtime_declaration_binds(child, name, source))
}

fn switch_runtime_binding(scope: Node<'_>, name: &str, source: &str) -> bool {
    let mut cursor = scope.walk();
    scope.named_children(&mut cursor).any(|clause| {
        let mut clause_cursor = clause.walk();
        clause
            .named_children(&mut clause_cursor)
            .any(|child| runtime_declaration_binds(child, name, source))
    })
}

fn runtime_declaration_binds(node: Node<'_>, name: &str, source: &str) -> bool {
    match node.kind() {
        "lexical_declaration" | "variable_declaration" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .filter(|child| child.kind() == "variable_declarator")
                .filter_map(|declarator| declarator.child_by_field_name("name"))
                .any(|binding| binding_node_contains(binding, name, source))
        }
        "function_declaration"
        | "generator_function_declaration"
        | "class_declaration"
        | "abstract_class_declaration"
        | "enum_declaration"
        | "module"
        | "internal_module" => node
            .child_by_field_name("name")
            .is_some_and(|binding| binding_node_contains(binding, name, source)),
        "import_statement" | "import_alias" => {
            typescript_import_bindings(node, source).contains(name)
        }
        "export_statement" | "ambient_declaration" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .any(|child| runtime_declaration_binds(child, name, source))
        }
        _ => false,
    }
}

fn contains_function_scoped_var(node: Node<'_>, name: &str, source: &str) -> bool {
    fn walk(node: Node<'_>, name: &str, source: &str, is_root: bool) -> bool {
        if !is_root
            && matches!(
                node.kind(),
                "function_declaration"
                    | "generator_function_declaration"
                    | "function_expression"
                    | "generator_function"
                    | "arrow_function"
                    | "method_definition"
                    | "class_static_block"
            )
        {
            return false;
        }
        if node.kind() == "variable_declaration" && runtime_declaration_binds(node, name, source) {
            return true;
        }
        let mut cursor = node.walk();
        node.named_children(&mut cursor)
            .any(|child| walk(child, name, source, false))
    }

    walk(node, name, source, true)
}

fn binding_node_contains(node: Node<'_>, name: &str, source: &str) -> bool {
    match node.kind() {
        "identifier" | "type_identifier" | "shorthand_property_identifier_pattern" => {
            node_text(node, source) == Some(name)
        }
        "required_parameter" | "optional_parameter" => node
            .child_by_field_name("name")
            .or_else(|| node.child_by_field_name("pattern"))
            .is_some_and(|binding| binding_node_contains(binding, name, source)),
        "assignment_pattern" | "object_assignment_pattern" => node
            .child_by_field_name("left")
            .is_some_and(|binding| binding_node_contains(binding, name, source)),
        "pair_pattern" => node
            .child_by_field_name("value")
            .is_some_and(|binding| binding_node_contains(binding, name, source)),
        "array_pattern" | "object_pattern" | "rest_pattern" | "formal_parameters" => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .any(|child| binding_node_contains(child, name, source))
        }
        _ => false,
    }
}

fn typescript_capture_gaps(
    root: Node<'_>,
    source: &str,
    symbols: &[CodeSymbol],
) -> Vec<StructuralCaptureGap> {
    fn push_gap(gaps: &mut Vec<StructuralCaptureGap>, kind: impl Into<String>, node: Node<'_>) {
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
        if has_typescript_static_block_ancestor(node) {
            return;
        }
        let symbol_count_at = |extent: Node<'_>| {
            symbols
                .iter()
                .filter(|symbol| symbol.span == (extent.start_byte(), extent.end_byte()))
                .count()
        };
        match node.kind() {
            "class_declaration"
            | "abstract_class_declaration"
            | "interface_declaration"
            | "type_alias_declaration"
            | "enum_declaration"
            | "function_declaration"
            | "generator_function_declaration"
            | "function_signature"
            | "module"
            | "internal_module" => {
                if symbol_count_at(declaration_extent(node)) == 0 {
                    push_gap(gaps, "unrepresented_named_declaration", node);
                }
            }
            "method_definition" if is_class_member(node) || is_named_module_object_member(node) => {
                if symbol_count_at(node) == 0 {
                    push_gap(gaps, format!("unrepresented_{}", node.kind()), node);
                }
            }
            "method_signature" | "abstract_method_signature" | "property_signature"
                if is_class_member(node) || is_addressable_type_member(node) =>
            {
                if symbol_count_at(node) == 0 {
                    push_gap(gaps, format!("unrepresented_{}", node.kind()), node);
                }
            }
            "public_field_definition" if is_class_member(node) => {
                if symbol_count_at(node) == 0 {
                    push_gap(gaps, "unrepresented_public_field_definition", node);
                }
            }
            "pair" | "shorthand_property_identifier" if is_named_module_object_member(node) => {
                if symbol_count_at(node) == 0 {
                    push_gap(gaps, format!("unrepresented_{}", node.kind()), node);
                }
            }
            "spread_element" if is_named_module_object_member(node) => {
                push_gap(gaps, "unrepresented_object_spread", node);
            }
            "lexical_declaration" | "variable_declaration"
                if !has_typescript_local_scope_ancestor(node) =>
            {
                let expected = {
                    let mut cursor = node.walk();
                    node.named_children(&mut cursor)
                        .filter(|child| child.kind() == "variable_declarator")
                        .filter_map(|declarator| declarator.child_by_field_name("name"))
                        .map(|name| binding_names(name, source).len())
                        .sum::<usize>()
                };
                if expected > symbol_count_at(declaration_extent(node)) {
                    push_gap(gaps, "unrepresented_variable_binding", node);
                }
            }
            "import_statement" | "import_alias" => {
                if symbol_count_at(node) == 0 {
                    push_gap(gaps, "unrepresented_import_binding", node);
                }
            }
            "export_statement" if node.child_by_field_name("declaration").is_none() => {
                if symbol_count_at(node) == 0 {
                    push_gap(gaps, "unrepresented_export_surface", node);
                }
            }
            "call_signature" if is_addressable_type_member(node) => {
                if symbol_count_at(node) == 0 {
                    push_gap(gaps, "unrepresented_call_signature", node);
                }
            }
            "construct_signature" if is_addressable_type_member(node) => {
                if symbol_count_at(node) == 0 {
                    push_gap(gaps, "unrepresented_construct_signature", node);
                }
            }
            "index_signature" if is_addressable_type_member(node) => {
                if symbol_count_at(node) == 0 {
                    push_gap(gaps, "unrepresented_index_signature", node);
                }
            }
            "class_static_block" => {
                if symbol_count_at(node) == 0 {
                    push_gap(gaps, "unrepresented_class_static_block", node);
                }
            }
            "namespace_export" => {}
            _ => {
                if node.parent().is_some_and(|parent| {
                    matches!(parent.kind(), "class_body" | "interface_body")
                        || is_named_type_alias_body(parent)
                }) && !matches!(node.kind(), "comment" | "decorator")
                {
                    push_gap(gaps, format!("unrepresented_{}", node.kind()), node);
                }
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

fn is_class_member(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "class_body")
}

fn is_addressable_type_member(node: Node<'_>) -> bool {
    node.parent()
        .is_some_and(|parent| parent.kind() == "interface_body" || is_named_type_alias_body(parent))
}

fn is_named_type_alias_body(node: Node<'_>) -> bool {
    node.kind() == "object_type"
        && node
            .parent()
            .is_some_and(|parent| parent.kind() == "type_alias_declaration")
}

fn is_named_module_object_member(node: Node<'_>) -> bool {
    let Some(object) = node.parent().filter(|parent| parent.kind() == "object") else {
        return false;
    };
    let Some(declarator) = object
        .parent()
        .filter(|parent| parent.kind() == "variable_declarator")
    else {
        return false;
    };
    let is_value = declarator
        .child_by_field_name("value")
        .is_some_and(|value| {
            value.start_byte() == object.start_byte() && value.end_byte() == object.end_byte()
        });
    let has_stable_owner = declarator
        .child_by_field_name("name")
        .is_some_and(|name| name.kind() == "identifier");
    is_value && has_stable_owner && !has_typescript_local_scope_ancestor(declarator)
}

fn has_typescript_local_scope_ancestor(node: Node<'_>) -> bool {
    let mut ancestor = node.parent();
    while let Some(candidate) = ancestor {
        if matches!(
            candidate.kind(),
            "function_declaration"
                | "generator_function_declaration"
                | "function_expression"
                | "generator_function"
                | "arrow_function"
                | "method_definition"
                | "method_signature"
                | "abstract_method_signature"
                | "class_static_block"
        ) {
            return true;
        }
        ancestor = candidate.parent();
    }
    false
}

fn has_typescript_static_block_ancestor(node: Node<'_>) -> bool {
    let mut ancestor = node.parent();
    while let Some(candidate) = ancestor {
        if candidate.kind() == "class_static_block" {
            return true;
        }
        ancestor = candidate.parent();
    }
    false
}

/// Admit the zero-width recovery produced by tree-sitter-typescript 0.23.2
/// for valid generic tagged templates such as `sql<Row>`...``.
///
/// Upstream issue #341 and PR #342 identify the missing grammar arm. Until a
/// stable release includes it, require every fault in the tree to be exactly
/// the synthetic `!` between an `instantiation_expression` and its template
/// argument. That token occupies no source bytes, so declaration spans and
/// source hashes remain exact. Any real error or any other missing token still
/// fails closed.
fn generic_tagged_template_recovery_is_exact(tree: &Tree, source: &str) -> bool {
    let mut saw_known_recovery = false;
    all_syntax_faults_are_known_generic_templates(tree.root_node(), source, &mut saw_known_recovery)
        && saw_known_recovery
}

fn all_syntax_faults_are_known_generic_templates(
    node: Node<'_>,
    source: &str,
    saw_known_recovery: &mut bool,
) -> bool {
    if node.is_error() {
        return false;
    }
    if node.is_missing() {
        if !is_known_generic_template_missing_token(node, source) {
            return false;
        }
        *saw_known_recovery = true;
        return true;
    }

    let mut cursor = node.walk();
    node.children(&mut cursor).all(|child| {
        all_syntax_faults_are_known_generic_templates(child, source, saw_known_recovery)
    })
}

fn is_known_generic_template_missing_token(missing: Node<'_>, source: &str) -> bool {
    if missing.kind() != "!" || missing.start_byte() != missing.end_byte() {
        return false;
    }
    let Some(non_null) = missing
        .parent()
        .filter(|parent| parent.kind() == "non_null_expression")
    else {
        return false;
    };
    let Some(instantiation) = non_null
        .named_child(0)
        .filter(|child| child.kind() == "instantiation_expression")
    else {
        return false;
    };
    if instantiation
        .child_by_field_name("type_arguments")
        .is_none()
    {
        return false;
    }
    let Some(call) = non_null
        .parent()
        .filter(|parent| parent.kind() == "call_expression")
    else {
        return false;
    };
    let function_is_recovered_non_null =
        call.child_by_field_name("function")
            .is_some_and(|function| {
                function.kind() == non_null.kind()
                    && function.start_byte() == non_null.start_byte()
                    && function.end_byte() == non_null.end_byte()
            });
    let Some(template) = call
        .child_by_field_name("arguments")
        .filter(|arguments| arguments.kind() == "template_string")
    else {
        return false;
    };
    let gap_is_only_whitespace = source
        .get(instantiation.end_byte()..template.start_byte())
        .is_some_and(|gap| gap.chars().all(char::is_whitespace));

    function_is_recovered_non_null
        && missing.start_byte() == template.start_byte()
        && source.as_bytes().get(template.start_byte()) == Some(&b'`')
        && gap_is_only_whitespace
}

#[derive(Clone)]
struct Container {
    name: String,
    kind: SymbolKind,
}

struct WalkContext {
    file_is_test: bool,
    commonjs_mode: bool,
    containers: Vec<Container>,
    symbols: Vec<CodeSymbol>,
}

impl WalkContext {
    fn parent_name(&self) -> Option<String> {
        self.containers
            .last()
            .map(|container| container.name.clone())
    }

    fn immediate_parent_kind(&self) -> Option<SymbolKind> {
        self.containers.last().map(|container| container.kind)
    }

    fn inside_non_durable_value_scope(&self) -> bool {
        self.containers.iter().any(|container| {
            matches!(
                container.kind,
                SymbolKind::Function
                    | SymbolKind::Method
                    | SymbolKind::Constructor
                    | SymbolKind::StaticBlock
            )
        })
    }

    fn inside_static_block(&self) -> bool {
        self.containers
            .iter()
            .any(|container| container.kind == SymbolKind::StaticBlock)
    }

    fn nearest_class_name(&self) -> Option<String> {
        self.containers
            .iter()
            .rev()
            .find(|container| container.kind == SymbolKind::Class)
            .map(|container| container.name.clone())
    }
}

fn visit(node: Node<'_>, source: &str, context: &mut WalkContext) {
    if context.inside_static_block() {
        return;
    }
    match node.kind() {
        "export_statement" => {
            if let Some(declaration) = node.child_by_field_name("declaration") {
                visit(declaration, source, context);
            } else {
                emit_exports(node, source, context);
            }
        }
        "ambient_declaration" => visit_named_children(node, source, context),
        "class_declaration" | "abstract_class_declaration" => visit_class(node, source, context),
        "interface_declaration" => visit_interface(node, source, context),
        "type_alias_declaration" => emit_named_type(node, source, context, SymbolKind::TypeAlias),
        "enum_declaration" => visit_enum(node, source, context),
        "function_declaration" | "generator_function_declaration" | "function_signature" => {
            visit_function(node, source, context)
        }
        "method_definition" | "method_signature" | "abstract_method_signature" => {
            visit_method(node, source, context)
        }
        "public_field_definition" | "property_signature" => emit_member(node, source, context),
        "call_signature" => {
            emit_callable_signature(node, source, context, "<call>", SymbolKind::CallSignature)
        }
        "construct_signature" => {
            emit_callable_signature(node, source, context, "new", SymbolKind::ConstructSignature)
        }
        "index_signature" => emit_index_signature(node, source, context),
        "class_static_block" => emit_static_block(node, source, context),
        "module" | "internal_module" => visit_namespace(node, source, context),
        "lexical_declaration" | "variable_declaration" => {
            emit_variable_declaration(node, source, context)
        }
        "import_statement" | "import_alias" => emit_imports(node, source, context),
        "assignment_expression"
            if context.commonjs_mode
                && node
                    .child_by_field_name("left")
                    .and_then(|left| commonjs_export_target(left, source))
                    .is_some() => {}
        _ => visit_named_children(node, source, context),
    }
}

fn visit_class(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(name) = node_text(name_node, source).map(unquoted_name) else {
        return;
    };
    let body = node.child_by_field_name("body");
    let extent = declaration_extent(node);
    context.symbols.push(code_symbol(
        extent,
        source,
        SymbolFacts {
            name: name.clone(),
            kind: SymbolKind::Class,
            signature_end: body.map(|body| body.start_byte()),
            doc_comment: preceding_doc_comment(extent, source),
            visibility: declaration_visibility(node),
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: body.is_some(),
            relations: class_relations(node, &name, source),
        },
    ));
    context.containers.push(Container {
        name,
        kind: SymbolKind::Class,
    });
    if let Some(body) = body {
        visit_named_children(body, source, context);
    }
    context.containers.pop();
}

fn visit_interface(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(name) = node_text(name_node, source).map(unquoted_name) else {
        return;
    };
    let body = node.child_by_field_name("body");
    let extent = declaration_extent(node);
    context.symbols.push(code_symbol(
        extent,
        source,
        SymbolFacts {
            name: name.clone(),
            kind: SymbolKind::Interface,
            signature_end: body.map(|body| body.start_byte()),
            doc_comment: preceding_doc_comment(extent, source),
            visibility: declaration_visibility(node),
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: false,
            relations: interface_relations(node, source),
        },
    ));
    context.containers.push(Container {
        name,
        kind: SymbolKind::Interface,
    });
    if let Some(body) = body {
        visit_named_children(body, source, context);
    }
    context.containers.pop();
}

fn visit_enum(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(name) = node_text(name_node, source).map(unquoted_name) else {
        return;
    };
    let body = node.child_by_field_name("body");
    let extent = declaration_extent(node);
    let visibility = declaration_visibility(node);
    context.symbols.push(code_symbol(
        extent,
        source,
        SymbolFacts {
            name: name.clone(),
            kind: SymbolKind::Enum,
            signature_end: body.map(|body| body.start_byte()),
            doc_comment: preceding_doc_comment(extent, source),
            visibility: visibility.clone(),
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: false,
            relations: Vec::new(),
        },
    ));
    context.containers.push(Container {
        name,
        kind: SymbolKind::Enum,
    });
    if let Some(body) = body {
        let mut cursor = body.walk();
        for member in body.named_children(&mut cursor) {
            let name_node = if member.kind() == "enum_assignment" {
                member.child_by_field_name("name")
            } else {
                Some(member)
            };
            let Some(member_name) = name_node
                .and_then(|name| node_text(name, source))
                .map(unquoted_name)
            else {
                continue;
            };
            context.symbols.push(code_symbol(
                member,
                source,
                SymbolFacts {
                    name: member_name,
                    kind: SymbolKind::Field,
                    signature_end: None,
                    doc_comment: preceding_doc_comment(member, source),
                    visibility: visibility.clone(),
                    parent: context.parent_name(),
                    is_test_only: context.file_is_test,
                    is_test_root: false,
                    has_body: false,
                    relations: Vec::new(),
                },
            ));
        }
    }
    context.containers.pop();
}

fn visit_function(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(name) = node_text(name_node, source).map(unquoted_name) else {
        return;
    };
    let body = node.child_by_field_name("body");
    let extent = declaration_extent(node);
    context.symbols.push(code_symbol(
        extent,
        source,
        SymbolFacts {
            name: name.clone(),
            kind: SymbolKind::Function,
            signature_end: body.map(|body| body.start_byte()),
            doc_comment: preceding_doc_comment(extent, source),
            visibility: declaration_visibility(node),
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: body.is_some(),
            relations: Vec::new(),
        },
    ));
    context.containers.push(Container {
        name,
        kind: SymbolKind::Function,
    });
    if let Some(body) = body {
        visit_named_children(body, source, context);
    }
    context.containers.pop();
}

fn visit_method(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(name_node) = declared_member_name(node) else {
        return;
    };
    let Some(name) = node_text(name_node, source).map(unquoted_name) else {
        return;
    };
    let body = node.child_by_field_name("body");
    let prefix = source
        .as_bytes()
        .get(node.start_byte()..name_node.start_byte())
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .unwrap_or_default();
    let kind = if name == "constructor" {
        SymbolKind::Constructor
    } else if prefix
        .split(|character: char| !character.is_alphanumeric() && character != '_')
        .any(|token| matches!(token, "get" | "set"))
    {
        SymbolKind::Property
    } else {
        SymbolKind::Method
    };
    context.symbols.push(code_symbol(
        node,
        source,
        SymbolFacts {
            name: name.clone(),
            kind,
            signature_end: body.map(|body| body.start_byte()),
            doc_comment: preceding_doc_comment(node, source),
            visibility: member_visibility(node, name_node, source),
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: body.is_some(),
            relations: Vec::new(),
        },
    ));

    if kind == SymbolKind::Constructor {
        emit_parameter_properties(node, source, context);
    }
    context.containers.push(Container { name, kind });
    if let Some(body) = body {
        visit_named_children(body, source, context);
    }
    context.containers.pop();
}

fn emit_member(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(name_node) = declared_member_name(node) else {
        return;
    };
    let Some(name) = node_text(name_node, source).map(unquoted_name) else {
        return;
    };
    let kind = if matches!(
        context.immediate_parent_kind(),
        Some(SymbolKind::Interface | SymbolKind::TypeAlias)
    ) {
        SymbolKind::Property
    } else {
        SymbolKind::Field
    };
    context.symbols.push(code_symbol(
        node,
        source,
        SymbolFacts {
            name,
            kind,
            signature_end: None,
            doc_comment: preceding_doc_comment(node, source),
            visibility: member_visibility(node, name_node, source),
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: false,
            relations: type_relation(node, source).into_iter().collect(),
        },
    ));
}

fn declared_member_name(node: Node<'_>) -> Option<Node<'_>> {
    node.child_by_field_name("name").or_else(|| {
        let mut cursor = node.walk();
        node.named_children(&mut cursor).find(|child| {
            matches!(
                child.kind(),
                "property_identifier"
                    | "private_property_identifier"
                    | "computed_property_name"
                    | "string"
                    | "number"
            )
        })
    })
}

fn emit_callable_signature(
    node: Node<'_>,
    source: &str,
    context: &mut WalkContext,
    name: &str,
    kind: SymbolKind,
) {
    context.symbols.push(code_symbol(
        node,
        source,
        SymbolFacts {
            name: name.to_string(),
            kind,
            signature_end: None,
            doc_comment: preceding_doc_comment(node, source),
            visibility: Visibility::Public,
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: false,
            relations: Vec::new(),
        },
    ));
}

fn emit_index_signature(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(text) = node_text(node, source) else {
        return;
    };
    let Some(end) = closing_outer_bracket(text) else {
        return;
    };
    context.symbols.push(code_symbol(
        node,
        source,
        SymbolFacts {
            name: text[..=end].trim().to_string(),
            kind: SymbolKind::IndexSignature,
            signature_end: None,
            doc_comment: preceding_doc_comment(node, source),
            visibility: Visibility::Public,
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: false,
            relations: type_relation(node, source).into_iter().collect(),
        },
    ));
}

fn closing_outer_bracket(text: &str) -> Option<usize> {
    let mut depth = 0_usize;
    for (offset, character) in text.char_indices() {
        match character {
            '[' => depth += 1,
            ']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn emit_static_block(node: Node<'_>, source: &str, context: &mut WalkContext) {
    context.symbols.push(code_symbol(
        node,
        source,
        SymbolFacts {
            name: "<static>".to_string(),
            kind: SymbolKind::StaticBlock,
            signature_end: node
                .child_by_field_name("body")
                .map(|body| body.start_byte()),
            doc_comment: preceding_doc_comment(node, source),
            visibility: Visibility::Private,
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: true,
            relations: Vec::new(),
        },
    ));
    if let Some(body) = node.child_by_field_name("body") {
        context.containers.push(Container {
            name: "<static>".to_string(),
            kind: SymbolKind::StaticBlock,
        });
        visit_named_children(body, source, context);
        context.containers.pop();
    }
}

fn emit_parameter_properties(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(parameters) = node.child_by_field_name("parameters") else {
        return;
    };
    let Some(class_name) = context.nearest_class_name() else {
        return;
    };
    let mut cursor = parameters.walk();
    for parameter in parameters.named_children(&mut cursor) {
        if !parameter_has_accessibility(parameter) {
            continue;
        }
        let Some(name_node) = parameter.child_by_field_name("name") else {
            continue;
        };
        let Some(name) = node_text(name_node, source).map(unquoted_name) else {
            continue;
        };
        context.symbols.push(code_symbol(
            parameter,
            source,
            SymbolFacts {
                name,
                kind: SymbolKind::Field,
                signature_end: None,
                doc_comment: None,
                visibility: member_visibility(parameter, name_node, source),
                parent: Some(class_name.clone()),
                is_test_only: context.file_is_test,
                is_test_root: false,
                has_body: false,
                relations: type_relation(parameter, source).into_iter().collect(),
            },
        ));
    }
}

fn emit_named_type(node: Node<'_>, source: &str, context: &mut WalkContext, kind: SymbolKind) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(name) = node_text(name_node, source).map(unquoted_name) else {
        return;
    };
    let extent = declaration_extent(node);
    context.symbols.push(code_symbol(
        extent,
        source,
        SymbolFacts {
            name: name.clone(),
            kind,
            signature_end: None,
            doc_comment: preceding_doc_comment(extent, source),
            visibility: declaration_visibility(node),
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: false,
            relations: Vec::new(),
        },
    ));
    if kind == SymbolKind::TypeAlias
        && let Some(body) = node
            .child_by_field_name("value")
            .filter(|value| value.kind() == "object_type")
    {
        context.containers.push(Container { name, kind });
        visit_named_children(body, source, context);
        context.containers.pop();
    }
}

fn visit_namespace(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(name_node) = node.child_by_field_name("name") else {
        return;
    };
    let Some(name) = node_text(name_node, source).map(unquoted_name) else {
        return;
    };
    let body = node.child_by_field_name("body");
    let extent = declaration_extent(node);
    context.symbols.push(code_symbol(
        extent,
        source,
        SymbolFacts {
            name: name.clone(),
            kind: SymbolKind::Namespace,
            signature_end: body.map(|body| body.start_byte()),
            doc_comment: preceding_doc_comment(extent, source),
            visibility: declaration_visibility(node),
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: body.is_some(),
            relations: Vec::new(),
        },
    ));
    context.containers.push(Container {
        name,
        kind: SymbolKind::Namespace,
    });
    if let Some(body) = body {
        visit_named_children(body, source, context);
    }
    context.containers.pop();
}

fn emit_variable_declaration(node: Node<'_>, source: &str, context: &mut WalkContext) {
    if context.inside_non_durable_value_scope() {
        return;
    }
    let declaration_kind = node
        .child_by_field_name("kind")
        .and_then(|kind| node_text(kind, source))
        .unwrap_or_else(|| {
            node_text(node, source)
                .and_then(|text| text.split_whitespace().next())
                .unwrap_or("")
        });
    let mut cursor = node.walk();
    for declarator in node.named_children(&mut cursor) {
        if declarator.kind() != "variable_declarator" {
            continue;
        }
        let Some(name_node) = declarator.child_by_field_name("name") else {
            continue;
        };
        let value = declarator.child_by_field_name("value");
        if context.commonjs_mode
            && value.is_some_and(|value| static_commonjs_require_target(value, source).is_some())
        {
            continue;
        }
        let value_is_callable = value.is_some_and(|value| {
            matches!(
                value.kind(),
                "arrow_function" | "function_expression" | "generator_function"
            )
        });
        let kind = if value_is_callable {
            SymbolKind::Function
        } else if declaration_kind == "const" {
            SymbolKind::Const
        } else {
            SymbolKind::Variable
        };
        let names = binding_names(name_node, source);
        for name in &names {
            let extent = declaration_extent(node);
            context.symbols.push(code_symbol(
                extent,
                source,
                SymbolFacts {
                    name: name.clone(),
                    kind,
                    signature_end: None,
                    doc_comment: preceding_doc_comment(extent, source),
                    visibility: declaration_visibility(node),
                    parent: context.parent_name(),
                    is_test_only: context.file_is_test,
                    is_test_root: false,
                    has_body: value_is_callable,
                    relations: type_relation(declarator, source).into_iter().collect(),
                },
            ));
        }
        if names.len() == 1
            && name_node.kind() == "identifier"
            && let Some(object) = value.filter(|value| value.kind() == "object")
        {
            context.containers.push(Container {
                name: names[0].clone(),
                kind,
            });
            visit_object_members(object, source, context);
            context.containers.pop();
        }
    }
}

fn visit_object_members(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "method_definition" => visit_method(child, source, context),
            "pair" => emit_object_pair(child, source, context),
            "shorthand_property_identifier" => {
                emit_object_shorthand(child, source, context);
            }
            _ => {}
        }
    }
}

fn emit_object_pair(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(name_node) = node.child_by_field_name("key") else {
        return;
    };
    let Some(name) = node_text(name_node, source).map(unquoted_name) else {
        return;
    };
    let value = node.child_by_field_name("value");
    let value_is_callable = value.is_some_and(|value| {
        matches!(
            value.kind(),
            "arrow_function" | "function_expression" | "generator_function"
        )
    });
    let kind = if value_is_callable {
        SymbolKind::Method
    } else {
        SymbolKind::Property
    };
    let body = value.and_then(|value| value.child_by_field_name("body"));
    context.symbols.push(code_symbol(
        node,
        source,
        SymbolFacts {
            name: name.clone(),
            kind,
            signature_end: body.map(|body| body.start_byte()),
            doc_comment: preceding_doc_comment(node, source),
            visibility: Visibility::Public,
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: body.is_some(),
            relations: Vec::new(),
        },
    ));
    if value_is_callable {
        context.containers.push(Container { name, kind });
        if let Some(body) = body {
            visit_named_children(body, source, context);
        }
        context.containers.pop();
    } else if let Some(object) = value.filter(|value| value.kind() == "object") {
        let qualified_name = context
            .parent_name()
            .map_or_else(|| name.clone(), |parent| format!("{parent}::{name}"));
        context.containers.push(Container {
            name: qualified_name,
            kind: SymbolKind::Property,
        });
        visit_object_members(object, source, context);
        context.containers.pop();
    }
}

fn emit_object_shorthand(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let Some(name) = node_text(node, source).map(unquoted_name) else {
        return;
    };
    context.symbols.push(code_symbol(
        node,
        source,
        SymbolFacts {
            name: name.clone(),
            kind: SymbolKind::Property,
            signature_end: None,
            doc_comment: preceding_doc_comment(node, source),
            visibility: Visibility::Public,
            parent: context.parent_name(),
            is_test_only: context.file_is_test,
            is_test_root: false,
            has_body: false,
            relations: vec![StructuralRelation::References { target: name }],
        },
    ));
}

fn emit_imports(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let target = node
        .child_by_field_name("source")
        .and_then(|source_node| node_text(source_node, source))
        .map(unquoted_name)
        .unwrap_or_else(|| node_text(node, source).unwrap_or("import").to_string());
    let mut bindings = typescript_import_bindings(node, source);
    if bindings.is_empty() && node.kind() == "import_statement" {
        bindings.insert(target.clone());
    }
    for name in bindings.into_iter().chain(
        (node.kind() == "import_alias")
            .then(|| node.named_child(0))
            .flatten()
            .and_then(|name| node_text(name, source))
            .map(unquoted_name),
    ) {
        context.symbols.push(code_symbol(
            node,
            source,
            SymbolFacts {
                name,
                kind: SymbolKind::Import,
                signature_end: None,
                doc_comment: preceding_doc_comment(node, source),
                visibility: Visibility::Private,
                parent: context.parent_name(),
                is_test_only: context.file_is_test,
                is_test_root: false,
                has_body: false,
                relations: vec![StructuralRelation::References {
                    target: target.clone(),
                }],
            },
        ));
    }
}

fn emit_exports(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let module_target = node
        .child_by_field_name("source")
        .and_then(|source_node| node_text(source_node, source))
        .map(unquoted_name);
    let mut bindings = Vec::new();
    collect_export_bindings(node, source, &mut bindings);
    if bindings.is_empty() {
        let statement = node_text(node, source).unwrap_or_default().trim_start();
        let name = if statement.starts_with("export default") {
            "default"
        } else if statement.starts_with("export =") {
            "export="
        } else if statement.starts_with("export *") {
            "*"
        } else {
            "export"
        };
        bindings.push((name.to_string(), None));
    }

    for (name, local_target) in bindings {
        let mut relations = Vec::new();
        if let Some(target) = &module_target {
            relations.push(StructuralRelation::References {
                target: target.clone(),
            });
        }
        if let Some(target) = local_target
            && module_target.as_deref() != Some(target.as_str())
        {
            relations.push(StructuralRelation::References { target });
        }
        context.symbols.push(code_symbol(
            node,
            source,
            SymbolFacts {
                name,
                kind: SymbolKind::Export,
                signature_end: None,
                doc_comment: preceding_doc_comment(node, source),
                visibility: Visibility::Public,
                parent: context.parent_name(),
                is_test_only: context.file_is_test,
                is_test_root: false,
                has_body: false,
                relations,
            },
        ));
    }
}

fn collect_export_bindings(
    node: Node<'_>,
    source: &str,
    bindings: &mut Vec<(String, Option<String>)>,
) {
    if node.kind() == "export_specifier" {
        let local = node
            .child_by_field_name("name")
            .and_then(|name| node_text(name, source))
            .map(unquoted_name);
        let exported = node
            .child_by_field_name("alias")
            .and_then(|alias| node_text(alias, source))
            .map(unquoted_name)
            .or_else(|| local.clone());
        if let Some(exported) = exported {
            bindings.push((exported, local));
        }
        return;
    }
    if node.kind() == "namespace_export" {
        let mut cursor = node.walk();
        let alias = node
            .named_children(&mut cursor)
            .find_map(|child| node_text(child, source).map(unquoted_name));
        bindings.push((alias.unwrap_or_else(|| "*".to_string()), None));
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_export_bindings(child, source, bindings);
    }
}

fn typescript_import_bindings(node: Node<'_>, source: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    collect_import_bindings(node, source, &mut names);
    names
}

fn collect_import_bindings(node: Node<'_>, source: &str, names: &mut BTreeSet<String>) {
    if node.kind() == "import_specifier" {
        let local = node
            .child_by_field_name("alias")
            .or_else(|| node.child_by_field_name("name"));
        if let Some(name) = local.and_then(|name| node_text(name, source)) {
            names.insert(unquoted_name(name));
        }
        return;
    }
    if matches!(node.kind(), "identifier" | "type_identifier")
        && !node
            .parent()
            .is_some_and(|parent| parent.kind() == "import_specifier")
        && let Some(name) = node_text(node, source)
    {
        names.insert(unquoted_name(name));
        return;
    }
    if node.kind() == "string" {
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_import_bindings(child, source, names);
    }
}

fn class_relations(node: Node<'_>, class_name: &str, source: &str) -> Vec<StructuralRelation> {
    let Some(heritage) = named_child_of_kind(node, "class_heritage") else {
        return Vec::new();
    };
    let mut relations = Vec::new();
    let mut cursor = heritage.walk();
    for clause in heritage.named_children(&mut cursor) {
        match clause.kind() {
            "extends_clause" => {
                let mut value_cursor = clause.walk();
                relations.extend(
                    clause
                        .children_by_field_name("value", &mut value_cursor)
                        .filter_map(|value| node_text(value, source))
                        .filter_map(simple_type_target)
                        .map(|target| StructuralRelation::Extends { target }),
                );
            }
            "implements_clause" => {
                let mut type_cursor = clause.walk();
                relations.extend(
                    clause
                        .named_children(&mut type_cursor)
                        .filter_map(|value| node_text(value, source))
                        .filter_map(simple_type_target)
                        .map(|abstraction| StructuralRelation::Implements {
                            abstraction,
                            implementation: Some(class_name.to_string()),
                            synthesize_external: false,
                        }),
                );
            }
            _ => {}
        }
    }
    relations
}

fn interface_relations(node: Node<'_>, source: &str) -> Vec<StructuralRelation> {
    let Some(clause) = named_child_of_kind(node, "extends_type_clause") else {
        return Vec::new();
    };
    let mut cursor = clause.walk();
    clause
        .children_by_field_name("type", &mut cursor)
        .filter_map(|value| node_text(value, source))
        .filter_map(simple_type_target)
        .map(|target| StructuralRelation::Extends { target })
        .collect()
}

fn type_relation(node: Node<'_>, source: &str) -> Option<StructuralRelation> {
    node.child_by_field_name("type")
        .and_then(|annotation| node_text(annotation, source))
        .and_then(simple_type_target)
        .map(|target| StructuralRelation::TypeOf { target })
}

fn parameter_has_accessibility(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "accessibility_modifier")
}

fn declaration_visibility(node: Node<'_>) -> Visibility {
    if node
        .parent()
        .is_some_and(|parent| parent.kind() == "export_statement")
    {
        Visibility::Public
    } else {
        Visibility::Private
    }
}

fn member_visibility(node: Node<'_>, name_node: Node<'_>, source: &str) -> Visibility {
    if name_node.kind() == "private_property_identifier" {
        return Visibility::Private;
    }
    let mut cursor = node.walk();
    let modifier = node
        .named_children(&mut cursor)
        .find(|child| child.kind() == "accessibility_modifier")
        .and_then(|modifier| node_text(modifier, source));
    match modifier {
        Some("private") => Visibility::Private,
        Some("protected") => Visibility::Protected,
        _ => Visibility::Public,
    }
}

fn binding_names(node: Node<'_>, source: &str) -> Vec<String> {
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => node_text(node, source)
            .map(unquoted_name)
            .into_iter()
            .collect(),
        _ => {
            let mut cursor = node.walk();
            node.named_children(&mut cursor)
                .flat_map(|child| binding_names(child, source))
                .collect()
        }
    }
}

fn named_child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.kind() == kind)
}

fn declaration_extent(node: Node<'_>) -> Node<'_> {
    node.parent()
        .filter(|parent| parent.kind() == "export_statement")
        .unwrap_or(node)
}

fn preceding_doc_comment(node: Node<'_>, source: &str) -> Option<String> {
    let comment = node.prev_named_sibling()?;
    if comment.kind() != "comment" || comment.end_position().row + 1 < node.start_position().row {
        return None;
    }
    let text = node_text(comment, source)?.trim();
    text.starts_with("/**").then(|| text.to_string())
}

fn visit_named_children(node: Node<'_>, source: &str, context: &mut WalkContext) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        visit(child, source, context);
    }
}

fn typescript_test_file(file_path: &str) -> bool {
    let path = Path::new(file_path);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    [
        ".test.ts",
        ".test.tsx",
        ".spec.ts",
        ".spec.tsx",
        ".test.js",
        ".test.jsx",
        ".spec.js",
        ".spec.jsx",
        ".test.mjs",
        ".spec.mjs",
        ".test.cjs",
        ".spec.cjs",
        ".e2e.ts",
        ".e2e.tsx",
        ".e2e.js",
        ".e2e.jsx",
        ".e2e.mjs",
        ".e2e.cjs",
        ".stories.ts",
        ".stories.tsx",
        ".stories.js",
        ".stories.jsx",
    ]
    .iter()
    .any(|suffix| file_name.ends_with(suffix))
        || path
            .components()
            .any(|component| component.as_os_str() == "__tests__")
}
