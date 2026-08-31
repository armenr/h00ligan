//! One exact, generation-bound symbol selector shared by every query verb.
//!
//! Human callers may continue to pass a symbol name plus an optional file
//! locality. Machine callers can pass the opaque `symbol_id` returned by Find
//! (or any other symbol-bearing result) through the same `symbol` field. The
//! identifier embeds the graph occurrence UUID for O(1) lookup and binds it to
//! the repository and immutable generation, so an ID from another or
//! superseded generation never aliases a current node.

use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::code_intel_domain::{DomainError, GenerationId, RepositoryId};
use crate::code_intel_publication::ResolvedGeneration;
use crate::graph::{GraphNode, KnowledgeGraph};
use crate::graph_query::{
    FileContext, FileResolution, Match, Resolution, resolve_in_file_matching,
    resolve_unique_matching,
};

const EXACT_SYMBOL_ID_PREFIX: &str = "sym-v1.";

/// Whether a caller is intentionally using the opaque exact-selector syntax.
///
/// A malformed value with this reserved prefix is still an exact-selector
/// attempt and must fail closed rather than falling back to fuzzy name lookup.
#[must_use]
pub fn is_exact_symbol_selector(selector: &str) -> bool {
    selector.starts_with(EXACT_SYMBOL_ID_PREFIX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameFileSelection {
    /// Treat a file as a locality hint for homonym resolution.
    Locality,
    /// Require a name match in exactly the selected file.
    ExactFile,
}

/// Create the canonical public identity for one graph occurrence.
#[must_use]
pub fn exact_symbol_id(
    repository_id: &RepositoryId,
    generation_id: &GenerationId,
    memory_id: Uuid,
) -> String {
    let occurrence = memory_id.simple().to_string();
    let mut hasher = Sha256::new();
    hasher.update(b"h00/exact-symbol-selector/v1\0");
    hash_field(&mut hasher, repository_id.0.as_bytes());
    hash_field(&mut hasher, generation_id.0.as_bytes());
    hash_field(&mut hasher, occurrence.as_bytes());
    format!(
        "{EXACT_SYMBOL_ID_PREFIX}{occurrence}.{}",
        hex(&hasher.finalize())
    )
}

/// Resolve an opaque exact selector, returning `None` for an ordinary name.
///
/// `normalized_file`, when supplied, is an additional exact assertion. It
/// never changes which occurrence the ID selects.
fn resolve_exact_symbol_selector<'a>(
    graph: &'a KnowledgeGraph,
    generation: &ResolvedGeneration,
    selector: &str,
    normalized_file: Option<&str>,
) -> Result<Option<&'a GraphNode>, DomainError> {
    if !is_exact_symbol_selector(selector) {
        return Ok(None);
    }
    let Some(memory_id) = decode_symbol_id(selector) else {
        return Err(symbol_not_found(selector));
    };
    let Some(node) = graph.node(&memory_id) else {
        return Err(symbol_not_found(selector));
    };
    let expected = exact_symbol_id(
        &generation.manifest.repository_id,
        &generation.manifest.generation_id,
        memory_id,
    );
    if expected != selector {
        return Err(symbol_not_found(selector));
    }
    if normalized_file.is_some_and(|file| node.file_path != file) {
        return Err(DomainError::SymbolNotFoundInFile {
            symbol: selector.into(),
            file: normalized_file.unwrap_or_default().into(),
            candidates: vec![format!("{} ({})", node.symbol_name, node.file_path)],
        });
    }
    Ok(Some(node))
}

/// Resolve the common public `symbol` selector used by every symbol verb.
///
/// Exact IDs always take precedence and treat `normalized_file` as an exact
/// assertion. Ordinary names retain the verb's declared file semantics.
pub fn resolve_symbol_selector<'a>(
    graph: &'a KnowledgeGraph,
    generation: &ResolvedGeneration,
    selector: &str,
    normalized_file: Option<&str>,
    name_file_selection: NameFileSelection,
) -> Result<&'a GraphNode, DomainError> {
    resolve_symbol_selector_matching(
        graph,
        generation,
        selector,
        normalized_file,
        name_file_selection,
        |_| true,
    )
}

/// Resolve an ordinary name only among nodes eligible for the requesting
/// verb's semantic role. Exact opaque selectors remain exact and are returned
/// unchanged so the verb can report a precise role error for that occurrence.
pub fn resolve_symbol_selector_matching<'a>(
    graph: &'a KnowledgeGraph,
    generation: &ResolvedGeneration,
    selector: &str,
    normalized_file: Option<&str>,
    name_file_selection: NameFileSelection,
    candidate_matches: impl Fn(&GraphNode) -> bool,
) -> Result<&'a GraphNode, DomainError> {
    if let Some(node) = resolve_exact_symbol_selector(graph, generation, selector, normalized_file)?
    {
        return Ok(node);
    }

    let symbol_id = match (normalized_file, name_file_selection) {
        (Some(file), NameFileSelection::ExactFile) => {
            match resolve_in_file_matching(
                graph,
                selector,
                FileContext::from(file.to_owned()),
                candidate_matches,
            ) {
                FileResolution::Unique(symbol_id) => symbol_id,
                FileResolution::NotFoundInFile => {
                    return Err(DomainError::SymbolNotFoundInFile {
                        symbol: selector.into(),
                        file: file.into(),
                        candidates: Vec::new(),
                    });
                }
                FileResolution::WrongFile { found_in } => {
                    let candidates = Match::candidate_labels(&found_in);
                    if found_in.iter().any(|candidate| candidate.file_path == file) {
                        return Err(DomainError::AmbiguousSymbol {
                            symbol: selector.into(),
                            candidates,
                        });
                    }
                    return Err(DomainError::SymbolNotFoundInFile {
                        symbol: selector.into(),
                        file: file.into(),
                        candidates,
                    });
                }
            }
        }
        (file, NameFileSelection::Locality) | (file @ None, NameFileSelection::ExactFile) => {
            let locality = file.map(|path| FileContext::from(path.to_owned()));
            match resolve_unique_matching(graph, selector, locality, candidate_matches) {
                Resolution::Unique(symbol_id) => symbol_id,
                Resolution::NotFound => {
                    return Err(DomainError::SymbolNotFound {
                        symbol: selector.into(),
                    });
                }
                Resolution::Ambiguous(candidates) => {
                    return Err(DomainError::AmbiguousSymbol {
                        symbol: selector.into(),
                        candidates: Match::candidate_labels(&candidates),
                    });
                }
            }
        }
    };
    graph
        .node(&symbol_id.uuid())
        .ok_or_else(|| DomainError::PublishedGenerationInvalid {
            reason: "resolved symbol selector disappeared from the graph".into(),
        })
}

fn decode_symbol_id(selector: &str) -> Option<Uuid> {
    let encoded = selector.strip_prefix(EXACT_SYMBOL_ID_PREFIX)?;
    let (occurrence, digest) = encoded.split_once('.')?;
    if occurrence.len() != 32
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || digest.contains('.')
    {
        return None;
    }
    Uuid::parse_str(occurrence).ok()
}

fn symbol_not_found(selector: &str) -> DomainError {
    DomainError::SymbolNotFound {
        symbol: selector.into(),
    }
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_symbol_id_is_parseable_and_bound_to_repository_and_generation() {
        let occurrence =
            Uuid::parse_str("11223344556677889900aabbccddeeff").expect("fixture occurrence UUID");
        let repository = RepositoryId::new("repo-a");
        let generation = GenerationId::new("generation-a");
        let selector = exact_symbol_id(&repository, &generation, occurrence);
        assert_eq!(decode_symbol_id(&selector), Some(occurrence));
        assert_ne!(
            selector,
            exact_symbol_id(&RepositoryId::new("repo-b"), &generation, occurrence)
        );
        assert_ne!(
            selector,
            exact_symbol_id(&repository, &GenerationId::new("generation-b"), occurrence)
        );
        assert_eq!(decode_symbol_id("ordinary_name"), None);
        assert_eq!(decode_symbol_id("sym-v1.not-an-id.bad"), None);
        assert!(!is_exact_symbol_selector("ordinary_name"));
        assert!(is_exact_symbol_selector("sym-v1.not-an-id.bad"));
    }
}
