//! Production-path contract for the Python and TypeScript structural adapters.
//!
//! These tests deliberately enter through `extract_source`, the same registry
//! dispatch used by indexing and WATCH. They do not call adapter-private
//! helpers, so a passing result proves extension registration, grammar binding,
//! syntax admission, and structural-IR emission are wired together.

use h00ligan_engine::edge_builder::build_graph;
use h00ligan_engine::extractor::extract_source;
use h00ligan_engine::graph::{EdgeKind, KnowledgeGraph};
use h00ligan_engine::language::{language_for_extension, registered_languages};
use h00ligan_engine::structural_ir::{
    CodeSymbol, ExtractorError, StructuralRelation, SymbolKind, Visibility,
};
use tree_sitter::Parser;

fn symbol<'a>(
    symbols: &'a [CodeSymbol],
    name: &str,
    kind: SymbolKind,
    parent: Option<&str>,
) -> &'a CodeSymbol {
    symbols
        .iter()
        .find(|symbol| {
            symbol.name == name && symbol.kind == kind && symbol.parent.as_deref() == parent
        })
        .unwrap_or_else(|| panic!("missing {kind} `{name}` with parent {parent:?}"))
}

#[test]
fn registry_dispatches_python_typescript_javascript_and_jsx_without_weakening_unknown_files() {
    assert_eq!(
        language_for_extension("rs"),
        Some("rust"),
        "known-positive registry control"
    );
    assert_eq!(
        language_for_extension("go"),
        Some("go"),
        "known-positive registry control"
    );

    for (extension, language, source, expected_name) in [
        ("py", "python", "def answer():\n    return 42\n", "answer"),
        (
            "ts",
            "typescript",
            "export function answer(): number { return 42; }\n",
            "answer",
        ),
        (
            "tsx",
            "typescript",
            "export function Card() { return <section>answer</section>; }\n",
            "Card",
        ),
        (
            "js",
            "typescript",
            "export function answer() { return 42; }\n",
            "answer",
        ),
        (
            "jsx",
            "typescript",
            "export function Card() { return <section>answer</section>; }\n",
            "Card",
        ),
    ] {
        assert_eq!(language_for_extension(extension), Some(language));
        let output = extract_source(source, &format!("src/sample.{extension}"))
            .unwrap_or_else(|error| panic!("production dispatch for .{extension}: {error}"));
        assert_eq!(output.file_path, format!("src/sample.{extension}"));
        assert!(
            output
                .symbols
                .iter()
                .any(|symbol| symbol.name == expected_name),
            ".{extension} dispatch produced no `{expected_name}` symbol"
        );
    }

    for (extension, language) in [
        ("pyi", "python"),
        ("mts", "typescript"),
        ("cts", "typescript"),
        ("mjs", "typescript"),
        ("cjs", "typescript"),
    ] {
        assert_eq!(language_for_extension(extension), Some(language));
    }

    assert_eq!(
        registered_languages(),
        vec!["rust", "go", "python", "typescript"]
    );
    assert!(matches!(
        extract_source("class Example {}", "Example.java"),
        Err(ExtractorError::UnsupportedLanguage { ext }) if ext == "java"
    ));
}

#[test]
fn python_adapter_preserves_callable_type_member_and_inheritance_shape() {
    let source = r#"from typing import Protocol
import os as operating_system

class Base:
    pass

class Client(Protocol):
    def send(self, value: str) -> str: ...

class Service(Base):
    timeout: int = 30

    def __init__(self, client: Client):
        self.client: Client = client

    @property
    def ready(self) -> bool:
        return True

    async def run(self, value: str) -> str:
        return self.client.send(value)

def top(service: Service) -> str:
    def normalize(value: str) -> str:
        return value.strip()
    return normalize("ok")

async def async_top(service: Service) -> str:
    return await service.run("ok")

DEFAULT_LIMIT: int = 10

def _private_helper() -> None:
    pass
"#;
    let output = extract_source(source, "src/service.py").expect("Python structural extraction");
    let symbols = &output.symbols;

    let service = symbol(symbols, "Service", SymbolKind::Class, None);
    assert!(service.relations.contains(&StructuralRelation::Extends {
        target: "Base".into(),
    }));
    symbol(symbols, "Client", SymbolKind::Interface, None);
    symbol(
        symbols,
        "__init__",
        SymbolKind::Constructor,
        Some("Service"),
    );
    symbol(symbols, "run", SymbolKind::Method, Some("Service"));
    symbol(symbols, "ready", SymbolKind::Property, Some("Service"));
    symbol(symbols, "timeout", SymbolKind::Field, Some("Service"));
    let client = symbol(symbols, "client", SymbolKind::Field, Some("Service"));
    assert!(client.relations.contains(&StructuralRelation::TypeOf {
        target: "Client".into(),
    }));
    symbol(symbols, "top", SymbolKind::Function, None);
    symbol(symbols, "normalize", SymbolKind::Function, Some("top"));
    symbol(symbols, "async_top", SymbolKind::Function, None);
    symbol(symbols, "DEFAULT_LIMIT", SymbolKind::Variable, None);
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol.kind == SymbolKind::Import),
        "imports are structural definitions, not discarded parser trivia"
    );
    assert_eq!(
        symbol(symbols, "_private_helper", SymbolKind::Function, None).visibility,
        Visibility::Private
    );
}

#[test]
fn python_test_entry_and_recovery_controls_are_non_vacuous() {
    let output = extract_source(
        "def test_runs():\n    assert True\n\ndef helper():\n    pass\n",
        "tests/test_service.py",
    )
    .expect("valid Python test module");
    let test = symbol(&output.symbols, "test_runs", SymbolKind::Function, None);
    let helper = symbol(&output.symbols, "helper", SymbolKind::Function, None);
    assert!(test.is_test_only);
    assert!(test.is_test_root);
    assert!(helper.is_test_only);
    assert!(
        !helper.is_test_root,
        "the test-root rule must not mark every function"
    );

    let error = extract_source("def broken(:\n    pass\n", "broken.py")
        .expect_err("invalid Python must fail closed");
    assert!(matches!(&error, ExtractorError::IncompleteSyntax { .. }));
    assert!(error.to_string().contains(" at 1:"), "{error}");
}

#[test]
fn typescript_adapter_preserves_declared_types_members_and_relations() {
    let source = r#"import type { Client } from "./client";

export interface BaseContract {
  readonly id: string;
}

export interface Runnable extends BaseContract {
  run(value: string): Promise<string>;
}

export type Result<T> = { value: T };
export enum State { Ready, Busy }

abstract class BaseService {}

export class Service extends BaseService implements Runnable {
  private client: Client;
  readonly id: string = "service";

  constructor(client: Client) {
    this.client = client;
  }

  get ready(): boolean {
    return true;
  }

  async run(value: string): Promise<string> {
    return value;
  }
}

export function top(service: Service): Promise<string> {
  return service.run("ok");
}

export const makeService = (client: Client) => new Service(client);

export namespace Helpers {
  export function identity(value: string): string { return value; }
}
"#;
    let output =
        extract_source(source, "src/service.ts").expect("TypeScript structural extraction");
    let symbols = &output.symbols;

    symbol(symbols, "BaseContract", SymbolKind::Interface, None);
    let runnable = symbol(symbols, "Runnable", SymbolKind::Interface, None);
    assert!(runnable.relations.contains(&StructuralRelation::Extends {
        target: "BaseContract".into(),
    }));
    symbol(symbols, "Result", SymbolKind::TypeAlias, None);
    symbol(symbols, "State", SymbolKind::Enum, None);
    symbol(symbols, "BaseService", SymbolKind::Class, None);
    let service = symbol(symbols, "Service", SymbolKind::Class, None);
    assert!(service.relations.contains(&StructuralRelation::Extends {
        target: "BaseService".into(),
    }));
    assert!(service.relations.iter().any(|relation| matches!(
        relation,
        StructuralRelation::Implements { abstraction, .. } if abstraction == "Runnable"
    )));
    symbol(
        symbols,
        "constructor",
        SymbolKind::Constructor,
        Some("Service"),
    );
    symbol(symbols, "run", SymbolKind::Method, Some("Service"));
    symbol(symbols, "ready", SymbolKind::Property, Some("Service"));
    let client = symbol(symbols, "client", SymbolKind::Field, Some("Service"));
    assert!(client.relations.contains(&StructuralRelation::TypeOf {
        target: "Client".into(),
    }));
    symbol(symbols, "id", SymbolKind::Field, Some("Service"));
    symbol(symbols, "top", SymbolKind::Function, None);
    symbol(symbols, "makeService", SymbolKind::Function, None);
    symbol(symbols, "Helpers", SymbolKind::Namespace, None);
    symbol(symbols, "identity", SymbolKind::Function, Some("Helpers"));
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol.kind == SymbolKind::Import)
    );

    let error = extract_source("export class Broken { method(\n", "broken.ts")
        .expect_err("invalid TypeScript must fail closed");
    assert!(matches!(&error, ExtractorError::IncompleteSyntax { .. }));
    assert!(error.to_string().contains(" at 1:"), "{error}");
}

/// FALSIFIER for valid generic tagged-template expressions used by typed SQL
/// clients. The production adapter must not reject the containing TypeScript
/// document merely because the upstream grammar separates ordinary generic
/// calls from template calls.
#[test]
fn typescript_generic_tagged_template_remains_valid_structural_source() {
    let source = r#"declare const sql: <T>(parts: TemplateStringsArray) => T;

export async function load() {
  const { rows } = await sql<{ exists: boolean }>`select true as exists`;
  return rows;
}
"#;

    for (file_path, grammar) in [
        (
            "src/database.ts",
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT,
        ),
        ("src/database.tsx", tree_sitter_typescript::LANGUAGE_TSX),
    ] {
        let mut parser = Parser::new();
        parser
            .set_language(&grammar.into())
            .expect("TypeScript grammar");
        let upstream_tree = parser.parse(source, None).expect("upstream parse tree");
        assert!(
            upstream_tree.root_node().has_error(),
            "upstream grammar fixed the known gap; remove h00ligan's bounded admission rule"
        );

        let output = extract_source(source, file_path)
            .expect("valid generic tagged template must remain structurally indexable");
        symbol(&output.symbols, "sql", SymbolKind::Const, None);
        let load = symbol(&output.symbols, "load", SymbolKind::Function, None);
        assert!(
            source[load.span.0..load.span.1].contains("sql<{ exists: boolean }>`"),
            "the admitted zero-width recovery must preserve exact host-source spans"
        );
    }

    let mixed_invalid = format!("{source}\nexport class Broken {{ method(\n");
    assert!(matches!(
        extract_source(&mixed_invalid, "src/broken.ts"),
        Err(ExtractorError::IncompleteSyntax { .. })
    ));
}

#[test]
fn tsx_uses_the_jsx_aware_grammar_without_changing_the_language_identity() {
    let source = r#"interface Props { title: string }

export function Card({ title }: Props) {
  return <section aria-label={title}>{title}</section>;
}
"#;
    let output = extract_source(source, "src/Card.tsx").expect("TSX structural extraction");
    assert_eq!(language_for_extension("tsx"), Some("typescript"));
    symbol(&output.symbols, "Props", SymbolKind::Interface, None);
    symbol(&output.symbols, "Card", SymbolKind::Function, None);
}

#[test]
fn adapters_mark_valid_but_unrepresented_declaration_shapes_incomplete() {
    let python_complete = extract_source("VALUE: int = 1\n", "src/complete.py")
        .expect("represented Python declaration");
    assert!(!python_complete.has_uncaptured_items());
    let python_gap = extract_source(
        "match payload:\n    case {\"name\": configured_name}:\n        pass\n",
        "src/settings.py",
    )
    .expect("valid module-level Python match binding");
    assert!(
        python_gap.has_uncaptured_items(),
        "a module-scope match binding must not disappear behind complete structural authority"
    );

    let typescript_complete = extract_source(
        "export interface Named { value: string; run(): void; }\n",
        "src/complete.ts",
    )
    .expect("represented TypeScript declarations");
    assert!(!typescript_complete.has_uncaptured_items());
    let typescript_gap = extract_source(
        "const base = { value: 1 };\nexport const extended = { ...base };\n",
        "src/contracts.ts",
    )
    .expect("valid object spread with unresolved structural expansion");
    assert!(
        typescript_gap.has_uncaptured_items(),
        "object spread requires explicit partial coverage until its expanded surface is represented"
    );
}

/// FALSIFIER for A02/S1: every statically addressable Go package surface must
/// either become a structural fact or make the file's structural authority
/// explicitly partial. The existing function is the non-vacuous positive
/// control; aliases, imports, and struct fields were all silently omitted.
#[test]
fn go_package_surface_is_represented_without_query_allow_list_holes() {
    let source = r#"package model

import dependency "example.com/dependency"
import _ "example.com/register"

type Existing struct{}
type Alias = Existing

type Record struct {
    Exported string
    left, Right int
    *Existing
}

func KnownPositive() {}
"#;
    let output = extract_source(source, "pkg/model.go").expect("valid Go package surface");
    symbol(&output.symbols, "KnownPositive", SymbolKind::Function, None);
    let alias = symbol(&output.symbols, "Alias", SymbolKind::TypeAlias, None);
    assert!(alias.relations.contains(&StructuralRelation::TypeOf {
        target: "Existing".into(),
    }));
    for (name, visibility) in [
        ("Exported", Visibility::Public),
        ("left", Visibility::Private),
        ("Right", Visibility::Public),
        ("Existing", Visibility::Public),
    ] {
        let field = symbol(&output.symbols, name, SymbolKind::Field, Some("Record"));
        assert_eq!(field.visibility, visibility, "field `{name}` visibility");
    }
    let dependency = symbol(&output.symbols, "dependency", SymbolKind::Import, None);
    assert!(
        dependency
            .relations
            .contains(&StructuralRelation::References {
                target: "example.com/dependency".into(),
            })
    );
    let side_effect = symbol(
        &output.symbols,
        "example.com/register",
        SymbolKind::Import,
        None,
    );
    assert!(
        side_effect
            .relations
            .contains(&StructuralRelation::References {
                target: "example.com/register".into(),
            })
    );
    assert!(
        !output.has_uncaptured_items(),
        "fully represented package surface retained gaps: {:?}",
        output.capture_gaps
    );
}

/// FALSIFIER for A06/S1: `with ... as TARGET` performs assignment in the
/// surrounding Python scope. Module and class targets are durable structural
/// bindings; function-local targets remain deliberately below this floor.
#[test]
fn python_with_targets_follow_the_surrounding_binding_scope() {
    let source = r#"def acquire():
    raise NotImplementedError

with acquire() as module_handle, acquire() as (left_handle, right_handle):
    configured = True

class Holder:
    with acquire() as class_handle:
        ready = True

def consume():
    with acquire() as local_handle:
        return local_handle
"#;
    let output = extract_source(source, "src/context.py").expect("valid Python with targets");
    symbol(&output.symbols, "acquire", SymbolKind::Function, None);
    for name in ["module_handle", "left_handle", "right_handle"] {
        symbol(&output.symbols, name, SymbolKind::Variable, None);
    }
    symbol(
        &output.symbols,
        "class_handle",
        SymbolKind::Field,
        Some("Holder"),
    );
    assert!(
        output
            .symbols
            .iter()
            .all(|candidate| candidate.name != "local_handle"),
        "function-local with targets are runtime flow, not durable symbols"
    );
    assert!(
        !output.has_uncaptured_items(),
        "represented with targets retained gaps: {:?}",
        output.capture_gaps
    );
}

/// FALSIFIER for A09/S1: a class static initialization block is a durable
/// executable owner, but every declaration nested inside it is block-local.
#[test]
fn typescript_static_block_does_not_promote_lexical_locals() {
    let source = r#"export class Boot {
  static {
    const transient = 1;
    function helper(): number { return transient; }
    class Inner {}
    initialize();
  }
}
"#;
    let output = extract_source(source, "src/boot.ts").expect("valid static block");
    symbol(&output.symbols, "Boot", SymbolKind::Class, None);
    symbol(
        &output.symbols,
        "<static>",
        SymbolKind::StaticBlock,
        Some("Boot"),
    );
    for local in ["transient", "helper", "Inner"] {
        assert!(
            output
                .symbols
                .iter()
                .all(|candidate| candidate.name != local),
            "static-block local `{local}` escaped into the durable symbol graph"
        );
    }
    assert!(
        !output.has_uncaptured_items(),
        "a represented static owner with intentionally local internals is complete: {:?}",
        output.capture_gaps
    );
}

/// FALSIFIER for A08/S1: `.cjs` is a registered production surface, so static
/// CommonJS dependencies and exports must be structural facts. Dynamic module
/// identities must instead leave exact capture gaps.
#[test]
fn commonjs_static_surfaces_are_facts_and_dynamic_surfaces_are_gaps() {
    let source = r#"function run() {}
const dependency = require("./dependency");
require("./setup");

module.exports = { run };
exports.extra = run;
module.exports.named = run;

const dynamic = require(moduleName);
module.exports[exportName] = run;
"#;
    let output = extract_source(source, "src/plugin.cjs").expect("valid CommonJS module");
    symbol(&output.symbols, "run", SymbolKind::Function, None);
    let dependency = symbol(&output.symbols, "dependency", SymbolKind::Import, None);
    assert!(
        dependency
            .relations
            .contains(&StructuralRelation::References {
                target: "./dependency".into(),
            })
    );
    symbol(&output.symbols, "./setup", SymbolKind::Import, None);
    symbol(&output.symbols, "module.exports", SymbolKind::Export, None);
    for name in ["run", "extra", "named"] {
        let exported = symbol(&output.symbols, name, SymbolKind::Export, None);
        assert!(
            exported
                .relations
                .contains(&StructuralRelation::References {
                    target: "run".into(),
                })
        );
    }
    assert!(
        output
            .capture_gaps
            .iter()
            .any(|gap| gap.kind == "unresolved_commonjs_require"),
        "dynamic require must qualify dependency authority"
    );
    assert!(
        output
            .capture_gaps
            .iter()
            .any(|gap| gap.kind == "unresolved_commonjs_export"),
        "computed CommonJS export must qualify export authority; gaps: {:?}",
        output.capture_gaps
    );
}

#[test]
fn commonjs_wrapper_identifiers_must_be_unshadowed() {
    let source = r#"module.exports = {};

function local(require, module, exports) {
  const dependency = require("./not-a-module-dependency");
  module.exports = dependency;
  exports.fake = dependency;
}
"#;
    let output = extract_source(source, "src/shadowed.cjs").expect("valid shadowed names");
    symbol(&output.symbols, "module.exports", SymbolKind::Export, None);
    assert!(
        output.symbols.iter().all(|candidate| {
            candidate.name != "dependency"
                && candidate.name != "./not-a-module-dependency"
                && candidate.name != "fake"
        }),
        "local bindings named require/module/exports must not manufacture CommonJS surfaces: {:?}",
        output
            .symbols
            .iter()
            .map(|symbol| (&symbol.name, symbol.kind))
            .collect::<Vec<_>>()
    );

    let module_source = r#"const require = localLoader;
const module = customModule;
const exports = customExports;
const dependency = require("./also-not-a-module-dependency");
module.exports = dependency;
exports.fake = dependency;
"#;
    let module_output = extract_source(module_source, "src/module-shadowed.cjs")
        .expect("valid module-level shadowing");
    symbol(
        &module_output.symbols,
        "dependency",
        SymbolKind::Const,
        None,
    );
    assert!(
        module_output
            .symbols
            .iter()
            .all(|candidate| !matches!(candidate.kind, SymbolKind::Import | SymbolKind::Export)),
        "module bindings named require/module/exports must suppress wrapper facts: {:?}",
        module_output
            .symbols
            .iter()
            .map(|symbol| (&symbol.name, symbol.kind))
            .collect::<Vec<_>>()
    );
}

#[test]
fn javascript_require_only_surface_is_not_silently_omitted() {
    let source = r#"const dependency = require("./dependency");
export function load() { return dependency; }
"#;
    let output = extract_source(source, "src/loader.js").expect("valid JavaScript module");
    let dependency = symbol(&output.symbols, "dependency", SymbolKind::Import, None);
    assert!(
        dependency
            .relations
            .contains(&StructuralRelation::References {
                target: "./dependency".into(),
            }),
        "a static require is dependency syntax even without a CommonJS export"
    );
    assert!(
        !output.has_uncaptured_items(),
        "the represented static dependency must not retain a capture gap: {:?}",
        output.capture_gaps
    );
}

#[test]
fn python_module_loop_bindings_and_wildcard_imports_are_structural_facts() {
    let source = r#"from app.models import *

ITEMS = {"first": 1}
for key, value in ITEMS.items():
    configured = value
"#;
    let output = extract_source(source, "scripts/bootstrap.py")
        .expect("valid module bindings and wildcard dependency");
    let wildcard = symbol(&output.symbols, "*", SymbolKind::Import, None);
    assert!(
        wildcard
            .relations
            .contains(&StructuralRelation::References {
                target: "app.models".into(),
            })
    );
    symbol(&output.symbols, "key", SymbolKind::Variable, None);
    symbol(&output.symbols, "value", SymbolKind::Variable, None);
    symbol(&output.symbols, "configured", SymbolKind::Variable, None);
    assert!(
        !output.has_uncaptured_items(),
        "represented module bindings must not retain stale capture gaps: {:?}",
        output.capture_gaps
    );
}

/// FALSIFIER for capture-gap scope: anonymous inline type literals are type
/// expressions, not addressable declarations. Named type aliases and
/// module-owned object literals, however, do own queryable members and must be
/// represented rather than hidden behind language-wide `Complete` authority.
#[test]
fn typescript_capture_authority_follows_addressable_owners() {
    let source = r#"declare const sql: <T>(parts: TemplateStringsArray) => T;

const asserted = unknownValue as { transient: string };
const rows = sql<{ id: string; owner_id: string }>`select id, owner_id from owners`;

export type Result<T> = {
  value: T;
  map<U>(transform: (value: T) => U): Result<U>;
};

export const client = {
  status: "ready",
  run(value: string): string { return value; },
  parse: (value: string): string => value.trim(),
};

declare const Code: { Ok: number };
export const mappings = {
  [Code.Ok]: { status: "ok" },
};
"#;

    let output = extract_source(source, "src/client.ts")
        .expect("valid named and anonymous TypeScript structural shapes");
    symbol(
        &output.symbols,
        "value",
        SymbolKind::Property,
        Some("Result"),
    );
    symbol(&output.symbols, "map", SymbolKind::Method, Some("Result"));
    symbol(
        &output.symbols,
        "status",
        SymbolKind::Property,
        Some("client"),
    );
    symbol(&output.symbols, "run", SymbolKind::Method, Some("client"));
    symbol(&output.symbols, "parse", SymbolKind::Method, Some("client"));
    symbol(
        &output.symbols,
        "[Code.Ok]",
        SymbolKind::Property,
        Some("mappings"),
    );
    symbol(
        &output.symbols,
        "status",
        SymbolKind::Property,
        Some("mappings::[Code.Ok]"),
    );
    assert!(
        !output.has_uncaptured_items(),
        "anonymous inline type expressions must not downgrade otherwise represented named owners: {:?}",
        output.capture_gaps
    );
}

#[test]
fn typescript_represents_non_named_type_members_static_blocks_and_exports() {
    let source = r#"export type CallableFactory<T> = {
  <U>(value: U): U;
  new(value: string): T;
  [key: string]: unknown;
};

export class Boot {
  static { initialize(); }
}

export type { ExternalType } from "./external";
export { externalValue as publicValue } from "./external";
export * from "./all";
"#;
    let output = extract_source(source, "src/contracts.ts")
        .expect("valid callable and module-surface declarations");
    symbol(
        &output.symbols,
        "<call>",
        SymbolKind::CallSignature,
        Some("CallableFactory"),
    );
    symbol(
        &output.symbols,
        "new",
        SymbolKind::ConstructSignature,
        Some("CallableFactory"),
    );
    symbol(
        &output.symbols,
        "[key: string]",
        SymbolKind::IndexSignature,
        Some("CallableFactory"),
    );
    symbol(
        &output.symbols,
        "<static>",
        SymbolKind::StaticBlock,
        Some("Boot"),
    );
    let exported_type = symbol(&output.symbols, "ExternalType", SymbolKind::Export, None);
    assert!(
        exported_type
            .relations
            .contains(&StructuralRelation::References {
                target: "./external".into(),
            })
    );
    symbol(&output.symbols, "publicValue", SymbolKind::Export, None);
    symbol(&output.symbols, "*", SymbolKind::Export, None);
    assert!(
        !output.has_uncaptured_items(),
        "represented type and export surfaces must not retain stale capture gaps: {:?}",
        output.capture_gaps
    );
}

#[test]
fn typescript_overload_signatures_are_distinct_source_occurrences() {
    let source = r#"export class Codec {
  private decode(value: string): string;
  private decode(value: number): string;
  private decode(value: string | number): string { return String(value); }
}
"#;
    let output = extract_source(source, "src/codec.ts").expect("valid method overload set");
    assert_eq!(
        output
            .symbols
            .iter()
            .filter(|candidate| {
                candidate.name == "decode"
                    && candidate.kind == SymbolKind::Method
                    && candidate.parent.as_deref() == Some("Codec")
            })
            .count(),
        3,
        "both overload declarations and the implementation are source occurrences"
    );
    let overload_spans = output
        .symbols
        .iter()
        .filter(|candidate| candidate.name == "decode")
        .map(|candidate| candidate.span)
        .collect::<Vec<_>>();
    assert!(
        !output.has_uncaptured_items(),
        "symbol spans {overload_spans:?}; gaps {:?}",
        output.capture_gaps
    );

    let mut graph = KnowledgeGraph::new();
    build_graph(&[output], &mut graph).expect("build overload occurrence graph");
    assert_eq!(
        graph
            .nodes_for_file("src/codec.ts")
            .into_iter()
            .filter(|node| node.symbol_name == "Codec::decode")
            .count(),
        3,
        "occurrence identities must preserve same-name overload declarations"
    );
}

#[test]
fn typescript_side_effect_import_is_a_dependency_not_a_missing_binding() {
    let output = extract_source("import \"./setup\";\n", "src/bootstrap.ts")
        .expect("valid side-effect import");
    let import = symbol(&output.symbols, "./setup", SymbolKind::Import, None);
    assert!(import.relations.contains(&StructuralRelation::References {
        target: "./setup".into(),
    }));
    assert!(!output.has_uncaptured_items());
}

#[test]
fn typed_python_and_typescript_relations_reach_the_published_graph_shape() {
    let outputs = vec![
        extract_source(
            "class Base:\n    pass\n\nclass Child(Base):\n    def run(self):\n        pass\n",
            "python/models.py",
        )
        .expect("Python relationship source"),
        extract_source(
            "export interface Runnable { run(): void; }\nexport class Worker implements Runnable { run(): void {} }\n",
            "web/worker.ts",
        )
        .expect("TypeScript relationship source"),
    ];
    let mut graph = KnowledgeGraph::new();
    let stats = build_graph(&outputs, &mut graph).expect("four-language graph builder");
    assert!(stats.edges_added > 0, "non-vacuous edge population");

    let node = |file: &str, name: &str| {
        graph
            .all_nodes()
            .into_iter()
            .find(|node| node.file_path == file && node.symbol_name == name)
            .unwrap_or_else(|| panic!("missing graph node {file}:{name}"))
            .memory_id
    };
    let python_base = node("python/models.py", "Base");
    let python_child = node("python/models.py", "Child");
    let python_run = node("python/models.py", "Child::run");
    let runnable = node("web/worker.ts", "Runnable");
    let worker = node("web/worker.ts", "Worker");

    assert!(
        graph
            .neighbors(&python_child)
            .iter()
            .any(|(target, edge)| { *target == python_base && edge.kind == EdgeKind::Extends })
    );
    assert!(
        graph
            .neighbors(&python_child)
            .iter()
            .any(|(target, edge)| { *target == python_run && edge.kind == EdgeKind::Contains })
    );
    assert!(
        graph
            .neighbors(&worker)
            .iter()
            .any(|(target, edge)| { *target == runnable && edge.kind == EdgeKind::Implements })
    );
    assert!(
        graph
            .neighbors(&runnable)
            .iter()
            .any(|(target, edge)| { *target == worker && edge.kind == EdgeKind::HasImpl })
    );
}
