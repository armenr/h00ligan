//! Product-shape contract for the persistent semantic-provider owner.
//!
//! Adding Python, TypeScript, or another provider must not require another
//! process-lifecycle slot in the supervisor and publication pipeline. Language
//! adapters may remain distinct, but ownership, cancellation, publication
//! commit, reset, and shutdown flow through one language-keyed registry.

const SUPERVISOR: &str = include_str!("../src/code_intel_supervisor.rs");
const INDEXING: &str = include_str!("../src/code_intel_indexing.rs");
const PUBLICATION: &str = include_str!("../src/code_intel_publication.rs");
const PIPELINE: &str = include_str!("../src/index_pipeline.rs");

#[test]
fn persistent_provider_ownership_is_registry_shaped_not_language_pair_shaped() {
    assert!(
        SUPERVISOR.contains("semantic_providers: Mutex<SemanticProviderRegistry>"),
        "the serialized runner must own one language-keyed provider registry"
    );
    assert!(
        !SUPERVISOR.contains("rust_semantic_provider: Mutex<")
            && !SUPERVISOR.contains("go_semantic_provider: Mutex<"),
        "adding a provider must not require another supervisor field"
    );
    assert!(
        INDEXING.contains("semantic_providers: &mut SemanticProviderRegistry"),
        "reuse admission and fresh publication must share the same registry"
    );
    assert!(
        PUBLICATION.contains("semantic_providers: &'a mut SemanticProviderRegistry"),
        "immutable publication must forward one registry into the candidate pipeline"
    );
    assert!(
        !PUBLICATION.contains("rust_semantic_provider: Option<&'a mut")
            && !PUBLICATION.contains("go_semantic_provider: Option<&'a mut"),
        "adding a provider must not require another publication runtime slot"
    );
    assert!(
        PIPELINE.contains("semantic_providers: &'a mut SemanticProviderRegistry"),
        "one publication candidate must receive the same provider registry"
    );
    assert!(
        !PIPELINE.contains("rust_semantic_provider: Option<&'a mut")
            && !PIPELINE.contains("go_semantic_provider: Option<&'a mut"),
        "adding a provider must not require another pipeline runtime slot"
    );
}
