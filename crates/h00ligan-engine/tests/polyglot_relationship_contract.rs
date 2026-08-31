//! Cross-document structural relationships are language/project-owned facts.
//! A repository-global symbol-name collision must never manufacture an edge
//! between unrelated languages merely because their structural kinds align.

use h00ligan_engine::edge_builder::build_graph;
use h00ligan_engine::extractor::extract_file;
use h00ligan_engine::graph::{EdgeKind, KnowledgeGraph};
use tempfile::TempDir;

#[test]
fn rust_impl_resolution_never_binds_an_unrelated_go_type() {
    let temporary = TempDir::new().expect("scratch polyglot repository");
    let root = temporary.path();
    std::fs::create_dir_all(root.join("rust")).expect("Rust source directory");
    std::fs::create_dir_all(root.join("go")).expect("Go source directory");
    std::fs::write(
        root.join("rust/impls.rs"),
        concat!(
            "trait LocalTrait {}\n",
            "struct Local;\n",
            "impl Local { fn local(&self) {} }\n",
            "impl LocalTrait for Local {}\n",
            "impl ForeignTrait for Local {}\n",
            "impl Widget { fn foreign(&self) {} }\n",
        ),
    )
    .expect("Rust structural source");
    std::fs::write(
        root.join("go/widget.go"),
        "package foreign\n\ntype Widget struct{}\ntype ForeignTrait interface{}\n",
    )
    .expect("Go structural source");

    let outputs = [root.join("rust/impls.rs"), root.join("go/widget.go")]
        .iter()
        .map(|path| extract_file(path, root).expect("registered-language extraction"))
        .collect::<Vec<_>>();
    let mut graph = KnowledgeGraph::new();
    build_graph(&outputs, &mut graph).expect("polyglot structural graph");

    let node = |name: &str, file: &str| {
        graph
            .all_nodes()
            .into_iter()
            .find(|node| node.symbol_name == name && node.file_path == file)
            .unwrap_or_else(|| panic!("missing positive node {file}:{name}"))
            .memory_id
    };
    let local = node("Local", "rust/impls.rs");
    let local_impl = node("impl Local", "rust/impls.rs");
    let local_trait = node("LocalTrait", "rust/impls.rs");
    let local_trait_impl = node("impl LocalTrait for Local", "rust/impls.rs");
    let go_widget = node("Widget", "go/widget.go");
    let go_foreign_trait = node("ForeignTrait", "go/widget.go");
    let rust_foreign_trait_impl = node("impl ForeignTrait for Local", "rust/impls.rs");
    let rust_widget_impl = node("impl Widget", "rust/impls.rs");

    assert!(
        graph
            .neighbors(&local)
            .into_iter()
            .any(|(target, edge)| { target == local_impl && edge.kind == EdgeKind::Contains }),
        "positive control: the same-language same-file relationship resolver must fire"
    );
    assert!(
        graph
            .neighbors(&local_trait_impl)
            .into_iter()
            .any(|(target, edge)| { target == local_trait && edge.kind == EdgeKind::Implements }),
        "positive control: same-language trait resolution must fire"
    );
    assert!(
        !graph
            .neighbors(&go_widget)
            .into_iter()
            .any(|(target, edge)| {
                target == rust_widget_impl && edge.kind == EdgeKind::Contains
            }),
        "an unrelated Go type cannot own a Rust impl through a global homonym"
    );
    assert!(
        !graph
            .neighbors(&rust_foreign_trait_impl)
            .into_iter()
            .any(|(target, edge)| {
                target == go_foreign_trait && edge.kind == EdgeKind::Implements
            }),
        "an unrelated Go interface cannot satisfy a Rust impl trait through a global homonym"
    );
}

#[test]
fn rust_reference_resolution_never_binds_an_unrelated_go_symbol() {
    let temporary = TempDir::new().expect("scratch polyglot repository");
    let root = temporary.path();
    std::fs::create_dir_all(root.join("rust")).expect("Rust source directory");
    std::fs::create_dir_all(root.join("go")).expect("Go source directory");
    std::fs::write(
        root.join("rust/imports.rs"),
        concat!("use crate::Helper;\n", "use foreign::OnlyGo;\n",),
    )
    .expect("Rust structural source");
    std::fs::write(root.join("rust/helper.rs"), "pub struct Helper;\n")
        .expect("Rust reference target");
    std::fs::write(
        root.join("go/only_go.go"),
        "package foreign\n\ntype OnlyGo struct{}\n",
    )
    .expect("Go structural source");

    let outputs = [
        root.join("rust/imports.rs"),
        root.join("rust/helper.rs"),
        root.join("go/only_go.go"),
    ]
    .iter()
    .map(|path| extract_file(path, root).expect("registered-language extraction"))
    .collect::<Vec<_>>();
    let mut graph = KnowledgeGraph::new();
    build_graph(&outputs, &mut graph).expect("polyglot structural graph");

    let node = |name: &str, file: &str| {
        graph
            .all_nodes()
            .into_iter()
            .find(|node| node.symbol_name == name && node.file_path == file)
            .unwrap_or_else(|| panic!("missing positive node {file}:{name}"))
            .memory_id
    };
    let local_use = node("crate::Helper", "rust/imports.rs");
    let local_helper = node("Helper", "rust/helper.rs");
    let foreign_use = node("foreign::OnlyGo", "rust/imports.rs");
    let go_only = node("OnlyGo", "go/only_go.go");

    assert!(
        graph
            .neighbors(&local_use)
            .into_iter()
            .any(|(target, edge)| { target == local_helper && edge.kind == EdgeKind::References }),
        "positive control: a same-language local reference must resolve"
    );
    assert!(
        !graph
            .neighbors(&foreign_use)
            .into_iter()
            .any(|(target, edge)| target == go_only && edge.kind == EdgeKind::References),
        "an unrelated Go symbol cannot satisfy a Rust reference through a global homonym"
    );
}
