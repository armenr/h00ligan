//! Language-neutral structural extraction interchange.
//!
//! A language adapter turns one parsed source document into [`ExtractorOutput`]:
//! source-backed symbols plus typed, conservative structural relationships.
//! This module deliberately owns that contract. Rust's parser implementation
//! lives in `extractor`; Go, Python, and TypeScript must not inherit Rust-only
//! fields merely because Rust happened to be implemented first.

use chrono::{DateTime, Utc};
use thiserror::Error;

use crate::graph::EntryRetainFlags;

/// Errors that can occur while structurally extracting one source document.
#[derive(Debug, Error)]
pub enum ExtractorError {
    /// tree-sitter failed to parse the source.
    #[error("tree-sitter parse failed for `{path}`")]
    ParseFailed { path: String },

    /// tree-sitter produced a recovery tree containing syntax errors. Such a
    /// tree is useful to an editor, but is not authoritative enough to publish.
    #[error("source syntax is incomplete for `{path}`{detail}")]
    IncompleteSyntax { path: String, detail: String },

    /// The tree-sitter language grammar could not be loaded.
    #[error("failed to set tree-sitter language: {0}")]
    LanguageError(String),

    /// An I/O error occurred reading a file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The file's extension has no registered language extractor.
    #[error("no registered language extractor for extension `{ext}`")]
    UnsupportedLanguage { ext: String },
}

/// Source-level symbol vocabulary shared by all structural adapters.
///
/// The variants preserve useful source-language distinctions; consumers ask
/// role questions through [`symbol_kind_has_role`] instead of scattering
/// spelling checks such as `kind == "function"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SymbolKind {
    Function,
    /// A named source binding whose value is callable, but which does not
    /// itself declare one executable function/method body. Compiler liveness
    /// may traverse the value without emitting a declaration record for the
    /// binding.
    CallableValue,
    Method,
    Constructor,
    Struct,
    Class,
    Enum,
    Impl,
    Trait,
    Interface,
    Const,
    Static,
    Variable,
    Module,
    Namespace,
    Use,
    Import,
    TypeAlias,
    Macro,
    Field,
    Property,
    CallSignature,
    ConstructSignature,
    IndexSignature,
    StaticBlock,
    Export,
}

impl SymbolKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::CallableValue => "callable_value",
            Self::Method => "method",
            Self::Constructor => "constructor",
            Self::Struct => "struct",
            Self::Class => "class",
            Self::Enum => "enum",
            Self::Impl => "impl",
            Self::Trait => "trait",
            Self::Interface => "interface",
            Self::Const => "const",
            Self::Static => "static",
            Self::Variable => "variable",
            Self::Module => "module",
            Self::Namespace => "namespace",
            Self::Use => "use",
            Self::Import => "import",
            Self::TypeAlias => "type_alias",
            Self::Macro => "macro",
            Self::Field => "field",
            Self::Property => "property",
            Self::CallSignature => "call_signature",
            Self::ConstructSignature => "construct_signature",
            Self::IndexSignature => "index_signature",
            Self::StaticBlock => "static_block",
            Self::Export => "export",
        }
    }

    #[must_use]
    pub fn has_role(self, role: SymbolRole) -> bool {
        symbol_kind_has_role(self.label(), role)
    }
}

impl std::fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Behavioral roles used by language-neutral graph and query consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolRole {
    Callable,
    Independent,
    Definition,
    Type,
    ConcreteType,
    Abstraction,
    DataMember,
    FieldContainer,
    Container,
}

/// Ask a role question of a persisted symbol-kind label.
///
/// Persisted graph nodes intentionally retain human-readable kind strings.
/// Centralizing their interpretation here lets new language adapters preserve
/// distinctions without changing every query consumer in lockstep.
#[must_use]
pub fn symbol_kind_has_role(kind: &str, role: SymbolRole) -> bool {
    match role {
        SymbolRole::Callable => matches!(
            kind,
            "function"
                | "callable_value"
                | "method"
                | "constructor"
                | "call_signature"
                | "construct_signature"
        ),
        SymbolRole::Independent => matches!(
            kind,
            "function"
                | "callable_value"
                | "method"
                | "constructor"
                | "struct"
                | "class"
                | "enum"
                | "union"
                | "impl"
                | "trait"
                | "interface"
                | "const"
                | "static"
                | "variable"
                | "module"
                | "namespace"
                | "use"
                | "import"
                | "type_alias"
                | "macro"
                | "export"
        ),
        SymbolRole::Definition => !matches!(kind, "use" | "import" | "export"),
        SymbolRole::Type => matches!(
            kind,
            "struct" | "class" | "enum" | "union" | "trait" | "interface" | "type_alias"
        ),
        SymbolRole::ConcreteType => matches!(kind, "struct" | "class" | "enum" | "union"),
        SymbolRole::Abstraction => matches!(kind, "trait" | "interface"),
        SymbolRole::DataMember => matches!(kind, "field" | "property" | "index_signature"),
        SymbolRole::FieldContainer => matches!(
            kind,
            "struct" | "class" | "enum" | "union" | "interface" | "type_alias"
        ),
        SymbolRole::Container => matches!(
            kind,
            "struct"
                | "class"
                | "enum"
                | "union"
                | "impl"
                | "trait"
                | "interface"
                | "module"
                | "namespace"
        ),
    }
}

/// Whether one source-backed symbol owns executable callable code rather than
/// merely describing a callable contract or naming a callable value.
///
/// Invocation-target and executable-declaration populations are deliberately
/// distinct: interface/abstract signatures and function-valued bindings can
/// participate in dispatch, while compiler whole-program liveness records the
/// concrete function/method declarations it traverses.
#[must_use]
pub fn symbol_is_executable_callable_declaration(kind: &str, has_body: Option<bool>) -> bool {
    has_body == Some(true)
        && kind != SymbolKind::CallableValue.label()
        && symbol_kind_has_role(kind, SymbolRole::Callable)
}

/// Visibility of a source-backed symbol.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Visibility {
    Public,
    Protected,
    PubCrate,
    PubSuper,
    PubIn(String),
    Private,
}

impl std::fmt::Display for Visibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => f.write_str("pub"),
            Self::Protected => f.write_str("protected"),
            Self::PubCrate => f.write_str("pub(crate)"),
            Self::PubSuper => f.write_str("pub(super)"),
            Self::PubIn(path) => write!(f, "pub(in {path})"),
            Self::Private => f.write_str("private"),
        }
    }
}

/// A conservative relationship asserted by one structural language adapter.
///
/// Targets are source-level names resolved by the graph builder under the
/// indexed project-unit scope. A missing or ambiguous target is skipped rather
/// than guessed. The variants describe semantics, not Rust syntax.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StructuralRelation {
    References {
        target: String,
    },
    FieldOf {
        target: String,
    },
    TypeOf {
        target: String,
    },
    Extends {
        target: String,
    },
    Implements {
        abstraction: String,
        implementation: Option<String>,
        synthesize_external: bool,
    },
    ContainedBy {
        target: String,
    },
    /// This symbol declares that its contents live in another source document.
    /// The language adapter owns path resolution; the shared graph layer may
    /// only admit a resolved document under exact project-inventory scope.
    ContainsDocument {
        /// Inline module/container directory components that participate in
        /// the language's document lookup rule.
        inline_path: Vec<String>,
        target: StructuralDocumentTarget,
    },
}

/// Language-owned path intent for one cross-document structural relation.
///
/// `LanguageDefault` preserves a declared module name without pretending the
/// shared IR knows a language's filename rules. `ExplicitRelativePath` carries
/// an exact source spelling. `Unresolved` is fail-closed evidence that syntax
/// (for example a conditional path attribute) prevented a single safe target.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StructuralDocumentTarget {
    LanguageDefault,
    ExplicitRelativePath(String),
    Unresolved,
}

/// One source-backed symbol emitted by a registered language adapter.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CodeSymbol {
    pub name: String,
    pub kind: SymbolKind,
    /// Byte offsets `(start, end)` in the source document.
    pub span: (usize, usize),
    /// Zero-indexed inclusive line range.
    pub line_range: (usize, usize),
    pub signature: String,
    pub doc_comment: Option<String>,
    pub content_hash: String,
    pub visibility: Visibility,
    /// Exact lexical/container parent when the adapter can identify it.
    pub parent: Option<String>,
    pub is_test_only: bool,
    pub is_test_root: bool,
    pub has_body: bool,
    pub relations: Vec<StructuralRelation>,
    /// Language-owned entry/retention evidence. Rust currently populates this;
    /// adapters without an equivalent exact fact leave it empty.
    pub entry_retain: EntryRetainFlags,
}

/// One exact source construct the structural adapter recognized as definition-
/// or relationship-bearing but could not yet represent in the shared IR.
///
/// Gaps are evidence, not parser failures: the surrounding document remains
/// queryable, while language-scoped structural authority is downgraded until
/// every gap kind is either represented or explicitly removed from the
/// adapter's promised structural vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StructuralCaptureGap {
    pub kind: String,
    pub span: (usize, usize),
}

impl StructuralCaptureGap {
    #[must_use]
    pub fn new(kind: impl Into<String>, span: (usize, usize)) -> Self {
        Self {
            kind: kind.into(),
            span,
        }
    }
}

/// Structural extraction output for one source document.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtractorOutput {
    pub file_path: String,
    pub file_hash: String,
    pub cross_document_surface_sha256: String,
    pub symbols: Vec<CodeSymbol>,
    pub extracted_at: DateTime<Utc>,
    /// Language-owned signal that conditional compilation can hide structure
    /// from the semantic provider used for this generation.
    pub has_platform_cfg: bool,
    /// Exact, language-owned constructs that the adapter observed but cannot
    /// yet represent completely.
    pub capture_gaps: Vec<StructuralCaptureGap>,
}

impl ExtractorOutput {
    #[must_use]
    pub const fn has_uncaptured_items(&self) -> bool {
        !self.capture_gaps.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_vocabulary_has_positive_and_negative_controls() {
        for kind in [
            SymbolKind::Function,
            SymbolKind::CallableValue,
            SymbolKind::Method,
            SymbolKind::Constructor,
        ] {
            assert!(kind.has_role(SymbolRole::Callable));
        }
        assert!(SymbolKind::CallSignature.has_role(SymbolRole::Callable));
        assert!(SymbolKind::ConstructSignature.has_role(SymbolRole::Callable));
        assert!(!SymbolKind::Class.has_role(SymbolRole::Callable));
        assert!(SymbolKind::Class.has_role(SymbolRole::Type));
        assert!(SymbolKind::Class.has_role(SymbolRole::ConcreteType));
        assert!(!SymbolKind::Interface.has_role(SymbolRole::ConcreteType));
        assert!(SymbolKind::Interface.has_role(SymbolRole::Abstraction));
        assert!(SymbolKind::Property.has_role(SymbolRole::DataMember));
        assert!(SymbolKind::IndexSignature.has_role(SymbolRole::DataMember));
        assert!(SymbolKind::Class.has_role(SymbolRole::FieldContainer));
        assert!(SymbolKind::Interface.has_role(SymbolRole::FieldContainer));
        assert!(!SymbolKind::Trait.has_role(SymbolRole::FieldContainer));
        assert!(SymbolKind::Interface.has_role(SymbolRole::Container));
        assert!(!SymbolKind::Import.has_role(SymbolRole::Definition));
        assert!(!SymbolKind::Export.has_role(SymbolRole::Definition));
        assert!(!SymbolKind::Property.has_role(SymbolRole::Independent));
        assert_eq!(Visibility::Protected.to_string(), "protected");
        assert!(symbol_is_executable_callable_declaration(
            SymbolKind::Function.label(),
            Some(true)
        ));
        assert!(!symbol_is_executable_callable_declaration(
            SymbolKind::Function.label(),
            Some(false)
        ));
        assert!(!symbol_is_executable_callable_declaration(
            SymbolKind::CallableValue.label(),
            Some(true)
        ));
    }
}
