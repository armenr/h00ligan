//! Exact source bytes authorized by one immutable graph generation.

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::graph::{GraphNode, KnowledgeGraph, SourceSpan};
use crate::project_binding::{ProjectBinding, ProjectPathError};

/// Maximum source-file size admitted by code-intelligence read and edit verbs.
pub const MAX_MATERIALIZED_SOURCE_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// One verified source slice plus the exact file bytes it came from.
#[derive(Debug)]
pub struct MaterializedSource {
    pub path: PathBuf,
    pub file_bytes: Vec<u8>,
    pub span: SourceSpan,
    pub source: String,
}

/// One repository-confined, size-bounded source file read exactly once.
#[derive(Debug)]
pub struct BoundedSourceFile {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

/// Failure to materialize bytes authorized by a graph node.
#[derive(Debug, Error)]
pub enum SourceMaterializationError {
    #[error("[source_read_failed] {0}")]
    ProjectPath(#[from] ProjectPathError),

    #[error("[source_read_failed] source read task failed for '{file_path}' ({symbol}): {message}")]
    ReadTask {
        symbol: String,
        file_path: String,
        message: String,
    },

    #[error(
        "[source_span_unavailable] exact source span for '{symbol}' in '{file_path}' is unavailable; publish a fresh generation"
    )]
    SpanUnavailable { symbol: String, file_path: String },

    #[error(
        "[source_span_invalid] indexed source span {start_byte}..{end_byte} for '{symbol}' in '{file_path}' is outside the current {file_bytes}-byte file"
    )]
    SpanOutsideFile {
        symbol: String,
        file_path: String,
        start_byte: usize,
        end_byte: usize,
        file_bytes: usize,
    },

    #[error(
        "[source_span_invalid] indexed source span for '{symbol}' in '{file_path}' is not valid UTF-8: {source}"
    )]
    SpanNotUtf8 {
        symbol: String,
        file_path: String,
        #[source]
        source: std::str::Utf8Error,
    },

    #[error(
        "[source_changed_since_indexing] source changed since indexing for '{symbol}' in '{file_path}': generation hash {indexed_hash} does not match current hash {current_hash}; publish a fresh generation"
    )]
    SourceChanged {
        symbol: String,
        file_path: String,
        indexed_hash: String,
        current_hash: String,
    },
}

impl SourceMaterializationError {
    /// Stable machine code shared by CLI and MCP adapters.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ProjectPath(_) | Self::ReadTask { .. } => "source_read_failed",
            Self::SpanUnavailable { .. } => "source_span_unavailable",
            Self::SpanOutsideFile { .. } | Self::SpanNotUtf8 { .. } => "source_span_invalid",
            Self::SourceChanged { .. } => "source_changed_since_indexing",
        }
    }

    /// The underlying project-path refusal, when this is a confinement error.
    pub const fn project_path_error(&self) -> Option<&ProjectPathError> {
        match self {
            Self::ProjectPath(error) => Some(error),
            _ => None,
        }
    }
}

fn hash_prefix(hash: &str) -> String {
    hash.chars().take(12).collect()
}

/// Read and verify exactly the source slice published for `node`.
///
/// The open is descriptor-relative to the selected project. A live path is
/// never trusted merely because the old line range still fits.
pub async fn materialize_source(
    binding: &ProjectBinding,
    graph: &KnowledgeGraph,
    node: &GraphNode,
) -> Result<MaterializedSource, SourceMaterializationError> {
    let file = read_source_file(binding, node).await?;
    materialize_source_from_file(graph, node, file)
}

/// Read one graph-authorized source document through the bound repository.
///
/// This deliberately does not select or hash a symbol span. Callers that must
/// validate occurrence identity before choosing a collapsed graph span can do
/// so against these exact bytes, then pass the same read to
/// [`materialize_source_from_file`].
pub async fn read_source_file(
    binding: &ProjectBinding,
    node: &GraphNode,
) -> Result<BoundedSourceFile, SourceMaterializationError> {
    let raw_path = Path::new(&node.file_path).to_path_buf();
    // Confinement is authority, not an incidental consequence of reading. Check
    // it before graph metadata so a hostile graph path cannot be misclassified
    // as merely missing a source span.
    binding.resolve_existing_path(&raw_path)?;
    let owned_binding = binding.clone();
    let symbol = node.symbol_name.clone();
    let file_path = node.file_path.clone();
    let (path, bytes) = tokio::task::spawn_blocking(move || {
        owned_binding.read_existing_file_bounded(&raw_path, MAX_MATERIALIZED_SOURCE_FILE_BYTES)
    })
    .await
    .map_err(|error| SourceMaterializationError::ReadTask {
        symbol: symbol.clone(),
        file_path: file_path.clone(),
        message: error.to_string(),
    })??;

    Ok(BoundedSourceFile { path, bytes })
}

/// Verify and materialize one graph span from a previously confined file read.
pub fn materialize_source_from_file(
    graph: &KnowledgeGraph,
    node: &GraphNode,
    file: BoundedSourceFile,
) -> Result<MaterializedSource, SourceMaterializationError> {
    let span = graph.source_span(&node.memory_id).ok_or_else(|| {
        SourceMaterializationError::SpanUnavailable {
            symbol: node.symbol_name.clone(),
            file_path: node.file_path.clone(),
        }
    })?;

    let slice = file
        .bytes
        .get(span.start_byte..span.end_byte)
        .ok_or_else(|| SourceMaterializationError::SpanOutsideFile {
            symbol: node.symbol_name.clone(),
            file_path: node.file_path.clone(),
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            file_bytes: file.bytes.len(),
        })?;
    let source = std::str::from_utf8(slice)
        .map_err(|source| SourceMaterializationError::SpanNotUtf8 {
            symbol: node.symbol_name.clone(),
            file_path: node.file_path.clone(),
            source,
        })?
        .to_owned();
    let actual_hash = blake3::hash(slice).to_hex().to_string();
    if actual_hash != node.content_hash {
        return Err(SourceMaterializationError::SourceChanged {
            symbol: node.symbol_name.clone(),
            file_path: node.file_path.clone(),
            indexed_hash: hash_prefix(&node.content_hash),
            current_hash: hash_prefix(&actual_hash),
        });
    }

    Ok(MaterializedSource {
        path: file.path,
        file_bytes: file.bytes,
        span,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge_builder::build_graph;
    use crate::extractor::extract_file;

    fn fixture() -> (tempfile::TempDir, ProjectBinding, KnowledgeGraph, GraphNode) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("repo");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(root.join("src/lib.rs"), "pub fn answer() -> u32 { 42 }\n")
            .expect("source fixture");
        let extracted = extract_file(&root.join("src/lib.rs"), &root).expect("extract source");
        let mut graph = KnowledgeGraph::new();
        build_graph(&[extracted], &mut graph).expect("build graph");
        let node = graph
            .all_nodes()
            .into_iter()
            .find(|node| node.symbol_name == "answer")
            .cloned()
            .expect("answer node");
        let binding = ProjectBinding::explicit(&root, &temporary.path().join("bundle"))
            .expect("project binding");
        (temporary, binding, graph, node)
    }

    #[tokio::test]
    async fn exact_published_slice_materializes() {
        let (_temporary, binding, graph, node) = fixture();
        let source = materialize_source(&binding, &graph, &node)
            .await
            .expect("materialized source");
        assert_eq!(source.source, "pub fn answer() -> u32 { 42 }");
        assert_eq!(
            &source.file_bytes[source.span.start_byte..source.span.end_byte],
            source.source.as_bytes()
        );
    }

    /// FALSIFIER for the historical repository-shape downgrade: tree-sitter,
    /// persisted byte spans, UTF-8 slicing, and content hashes all operate on
    /// byte offsets. A Unicode Rust identifier and an over-long source line are
    /// therefore exact materialization controls, not evidence that the indexed
    /// graph is untrustworthy.
    #[tokio::test]
    async fn exact_materialization_must_not_be_downgraded_by_source_shape() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("repo");
        std::fs::create_dir_all(root.join("src")).expect("source directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"shape-falsifier\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .expect("manifest");
        let long_value = "x".repeat(10_128);
        let source = format!(
            "pub fn café() -> usize {{ 1 }}\npub fn very_long() -> &'static str {{ \"{long_value}\" }}\n"
        );
        let source_path = root.join("src/lib.rs");
        std::fs::write(&source_path, &source).expect("source fixture");

        let extracted = extract_file(&source_path, &root).expect("extract exact source");
        let mut graph = KnowledgeGraph::new();
        build_graph(&[extracted], &mut graph).expect("build graph");
        let binding = ProjectBinding::explicit(&root, &temporary.path().join("bundle"))
            .expect("project binding");

        for symbol in ["café", "very_long"] {
            let node = graph
                .all_nodes()
                .into_iter()
                .find(|node| node.symbol_name == symbol)
                .expect("indexed symbol");
            let materialized = materialize_source(&binding, &graph, node)
                .await
                .expect("exact byte-span materialization");
            assert!(materialized.source.contains(symbol));
            assert_eq!(
                &materialized.file_bytes[materialized.span.start_byte..materialized.span.end_byte],
                materialized.source.as_bytes(),
                "tree-sitter and published spans must identify exact UTF-8 bytes"
            );
        }
    }

    #[tokio::test]
    async fn changed_source_is_refused_with_stable_code() {
        let (_temporary, binding, graph, node) = fixture();
        std::fs::write(
            binding.root().join("src/lib.rs"),
            "pub fn answer() -> u32 { 43 }\n",
        )
        .expect("mutate source");
        let error = materialize_source(&binding, &graph, &node)
            .await
            .expect_err("changed source must fail closed");
        assert_eq!(error.code(), "source_changed_since_indexing");
        assert!(matches!(
            error,
            SourceMaterializationError::SourceChanged { .. }
        ));
    }

    #[tokio::test]
    async fn graph_carried_parent_escape_is_refused() {
        let (_temporary, binding, graph, mut node) = fixture();
        node.memory_id = uuid::Uuid::new_v4();
        node.file_path = "../outside.rs".into();
        let error = materialize_source(&binding, &graph, &node)
            .await
            .expect_err("path authority must fire before missing-span classification");
        assert!(matches!(
            error.project_path_error(),
            Some(ProjectPathError::ParentTraversal { .. })
        ));
    }
}
