//! Language-keyed ownership for persistent semantic-provider coordinators.
//!
//! Provider implementations remain language adapters. This module owns their
//! common process/session lifecycle so adding a language does not add another
//! supervisor field, cancellation branch, reset branch, or shutdown branch.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use crate::code_intel_cancellation::IndexCancellation;
use crate::code_intel_domain::ProjectInventory;
use crate::code_intel_go_semantic_provider::{
    GoSemanticProviderConfig, GoSemanticProviderCoordinator,
};
use crate::code_intel_payload::NormalizedProviderPayload;
use crate::code_intel_rust_semantic_provider::{
    RustSemanticProviderConfig, RustSemanticProviderCoordinator,
};
use crate::code_intel_semantic_provider_coordinator::{
    SemanticProviderActivityRecord, SemanticProviderError,
};
use crate::code_intel_workspace_semantic_provider::{
    WorkspaceSemanticProviderConfig, WorkspaceSemanticProviderCoordinator,
};
use crate::scip_normalizer::{
    CanonicalSemanticBasis, IndexedSourceEvidence, ScipArtifactSetNormalization,
};
use async_trait::async_trait;
use futures::future::join_all;

#[async_trait]
pub(crate) trait PersistentSemanticProvider: Send {
    fn language(&self) -> &'static str;

    fn ecosystem(&self) -> &'static str;

    fn provider_id(&self) -> &str;

    fn operation_label(&self) -> &'static str;

    fn set_session_jobs(&mut self, jobs: Option<usize>);

    fn take_last_activity(&mut self) -> Option<SemanticProviderActivityRecord>;

    fn active_cache_directories(&self) -> BTreeSet<PathBuf>;

    async fn authorize_and_hydrate_exact_generation_reuse(
        &mut self,
        repository_root: &Path,
        inventory: &ProjectInventory,
        indexed_sources: &[IndexedSourceEvidence],
        provider_payloads: &[NormalizedProviderPayload],
        prior_bases: &[CanonicalSemanticBasis],
        cancellation: &IndexCancellation,
    ) -> bool;

    async fn reuse_exact_canonical_basis(
        &mut self,
        repository_root: &Path,
        inventory: &ProjectInventory,
        indexed_sources: &[IndexedSourceEvidence],
        prior_bases: &[CanonicalSemanticBasis],
        cancellation: &IndexCancellation,
    ) -> Option<ScipArtifactSetNormalization>;

    async fn refresh(
        &mut self,
        repository_root: &Path,
        execution_roots: &[PathBuf],
        indexed_sources: &[IndexedSourceEvidence],
        inventory: &ProjectInventory,
        cancellation: &IndexCancellation,
    ) -> Result<ScipArtifactSetNormalization, SemanticProviderError>;

    fn mark_publication_committed(&mut self);

    async fn reset(&mut self);
}

macro_rules! impl_persistent_provider {
    ($coordinator:ty) => {
        #[async_trait]
        impl PersistentSemanticProvider for $coordinator {
            fn language(&self) -> &'static str {
                <$coordinator>::language(self)
            }

            fn ecosystem(&self) -> &'static str {
                <$coordinator>::ecosystem(self)
            }

            fn provider_id(&self) -> &str {
                <$coordinator>::provider_id(self)
            }

            fn operation_label(&self) -> &'static str {
                <$coordinator>::operation_label(self)
            }

            fn set_session_jobs(&mut self, jobs: Option<usize>) {
                <$coordinator>::set_session_jobs(self, jobs);
            }

            fn take_last_activity(&mut self) -> Option<SemanticProviderActivityRecord> {
                <$coordinator>::take_last_activity(self)
            }

            fn active_cache_directories(&self) -> BTreeSet<PathBuf> {
                <$coordinator>::active_cache_directories(self)
            }

            async fn authorize_and_hydrate_exact_generation_reuse(
                &mut self,
                repository_root: &Path,
                inventory: &ProjectInventory,
                indexed_sources: &[IndexedSourceEvidence],
                provider_payloads: &[NormalizedProviderPayload],
                prior_bases: &[CanonicalSemanticBasis],
                cancellation: &IndexCancellation,
            ) -> bool {
                <$coordinator>::authorize_and_hydrate_exact_generation_reuse(
                    self,
                    repository_root,
                    inventory,
                    indexed_sources,
                    provider_payloads,
                    prior_bases,
                    cancellation,
                )
                .await
            }

            async fn reuse_exact_canonical_basis(
                &mut self,
                repository_root: &Path,
                inventory: &ProjectInventory,
                indexed_sources: &[IndexedSourceEvidence],
                prior_bases: &[CanonicalSemanticBasis],
                cancellation: &IndexCancellation,
            ) -> Option<ScipArtifactSetNormalization> {
                <$coordinator>::reuse_exact_canonical_basis(
                    self,
                    repository_root,
                    inventory,
                    indexed_sources,
                    prior_bases,
                    cancellation,
                )
                .await
            }

            async fn refresh(
                &mut self,
                repository_root: &Path,
                execution_roots: &[PathBuf],
                indexed_sources: &[IndexedSourceEvidence],
                inventory: &ProjectInventory,
                cancellation: &IndexCancellation,
            ) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
                <$coordinator>::refresh(
                    self,
                    repository_root,
                    execution_roots,
                    indexed_sources,
                    inventory,
                    cancellation,
                )
                .await
            }

            fn mark_publication_committed(&mut self) {
                <$coordinator>::mark_publication_committed(self);
            }

            async fn reset(&mut self) {
                <$coordinator>::reset(self).await;
            }
        }
    };
}

impl_persistent_provider!(RustSemanticProviderCoordinator);
impl_persistent_provider!(GoSemanticProviderCoordinator);
impl_persistent_provider!(WorkspaceSemanticProviderCoordinator);

/// One configured persistent provider supplied by product assembly.
///
/// Adapter construction is type-erased here so adding a language implements
/// one adapter-local factory rather than extending a central enum and match.
/// The concrete config remains typed until this collection boundary.
pub struct SemanticProviderConfig {
    factory: Box<dyn ErasedSemanticProviderConfig>,
}

impl Clone for SemanticProviderConfig {
    fn clone(&self) -> Self {
        Self {
            factory: self.factory.clone_box(),
        }
    }
}

impl fmt::Debug for SemanticProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticProviderConfig")
            .field("language", &self.factory.language())
            .finish_non_exhaustive()
    }
}

impl SemanticProviderConfig {
    pub(crate) fn from_adapter(config: impl SemanticProviderAdapterConfig) -> Self {
        Self {
            factory: Box::new(config),
        }
    }

    #[must_use]
    pub fn language(&self) -> &'static str {
        self.factory.language()
    }

    /// Bind disposable provider caches to the selected repository-local data
    /// directory before the coordinator enters the lifecycle registry.
    pub fn bind_cache_root(&mut self, cache_root: &Path) {
        self.factory.bind_cache_root(cache_root);
    }

    pub fn set_arguments(&mut self, arguments: Vec<OsString>) {
        self.factory.set_arguments(arguments);
    }

    fn into_provider(self) -> Box<dyn PersistentSemanticProvider> {
        self.factory.into_provider()
    }
}

pub(crate) trait SemanticProviderAdapterConfig:
    Clone + fmt::Debug + Send + Sync + 'static
{
    type Provider: PersistentSemanticProvider + 'static;

    fn language(&self) -> &'static str;

    fn bind_cache_root(&mut self, cache_root: &Path);

    fn set_arguments(&mut self, arguments: Vec<OsString>);

    fn into_provider(self) -> Self::Provider;
}

trait ErasedSemanticProviderConfig: fmt::Debug + Send + Sync {
    fn clone_box(&self) -> Box<dyn ErasedSemanticProviderConfig>;

    fn language(&self) -> &'static str;

    fn bind_cache_root(&mut self, cache_root: &Path);

    fn set_arguments(&mut self, arguments: Vec<OsString>);

    fn into_provider(self: Box<Self>) -> Box<dyn PersistentSemanticProvider>;
}

impl<C> ErasedSemanticProviderConfig for C
where
    C: SemanticProviderAdapterConfig,
{
    fn clone_box(&self) -> Box<dyn ErasedSemanticProviderConfig> {
        Box::new(self.clone())
    }

    fn language(&self) -> &'static str {
        SemanticProviderAdapterConfig::language(self)
    }

    fn bind_cache_root(&mut self, cache_root: &Path) {
        SemanticProviderAdapterConfig::bind_cache_root(self, cache_root);
    }

    fn set_arguments(&mut self, arguments: Vec<OsString>) {
        SemanticProviderAdapterConfig::set_arguments(self, arguments);
    }

    fn into_provider(self: Box<Self>) -> Box<dyn PersistentSemanticProvider> {
        Box::new(SemanticProviderAdapterConfig::into_provider(*self))
    }
}

impl SemanticProviderAdapterConfig for RustSemanticProviderConfig {
    type Provider = RustSemanticProviderCoordinator;

    fn language(&self) -> &'static str {
        Self::language(self)
    }

    fn bind_cache_root(&mut self, cache_root: &Path) {
        Self::bind_cache_root(self, cache_root);
    }

    fn set_arguments(&mut self, arguments: Vec<OsString>) {
        self.arguments = arguments;
    }

    fn into_provider(self) -> Self::Provider {
        RustSemanticProviderCoordinator::new(self)
    }
}

impl From<RustSemanticProviderConfig> for SemanticProviderConfig {
    fn from(config: RustSemanticProviderConfig) -> Self {
        Self::from_adapter(config)
    }
}

impl SemanticProviderAdapterConfig for GoSemanticProviderConfig {
    type Provider = GoSemanticProviderCoordinator;

    fn language(&self) -> &'static str {
        Self::language(self)
    }

    fn bind_cache_root(&mut self, cache_root: &Path) {
        Self::bind_cache_root(self, cache_root);
    }

    fn set_arguments(&mut self, arguments: Vec<OsString>) {
        *self.arguments_mut() = arguments;
    }

    fn into_provider(self) -> Self::Provider {
        GoSemanticProviderCoordinator::new(self)
    }
}

impl From<GoSemanticProviderConfig> for SemanticProviderConfig {
    fn from(config: GoSemanticProviderConfig) -> Self {
        Self::from_adapter(config)
    }
}

impl SemanticProviderAdapterConfig for WorkspaceSemanticProviderConfig {
    type Provider = WorkspaceSemanticProviderCoordinator;

    fn language(&self) -> &'static str {
        Self::language(self)
    }

    fn bind_cache_root(&mut self, cache_root: &Path) {
        Self::bind_cache_root(self, cache_root);
    }

    fn set_arguments(&mut self, arguments: Vec<OsString>) {
        *self.arguments_mut() = arguments;
    }

    fn into_provider(self) -> Self::Provider {
        WorkspaceSemanticProviderCoordinator::new(self)
    }
}

impl From<WorkspaceSemanticProviderConfig> for SemanticProviderConfig {
    fn from(config: WorkspaceSemanticProviderConfig) -> Self {
        Self::from_adapter(config)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SemanticProviderRegistryError {
    #[error("semantic-provider language key is empty")]
    EmptyLanguage,
    #[error("semantic-provider language '{0}' is registered more than once")]
    DuplicateLanguage(String),
}

#[derive(Default)]
pub(crate) struct SemanticProviderRegistry {
    providers: BTreeMap<String, Box<dyn PersistentSemanticProvider>>,
}

impl fmt::Debug for SemanticProviderRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticProviderRegistry")
            .field("languages", &self.languages())
            .finish()
    }
}

impl SemanticProviderRegistry {
    pub(crate) fn from_configs(
        providers: Vec<SemanticProviderConfig>,
    ) -> Result<Self, SemanticProviderRegistryError> {
        let mut registry = Self::default();
        for provider in providers {
            registry.register_boxed(provider.into_provider())?;
        }
        Ok(registry)
    }

    #[cfg(test)]
    pub(crate) fn register(
        &mut self,
        provider: impl PersistentSemanticProvider + 'static,
    ) -> Result<(), SemanticProviderRegistryError> {
        self.register_boxed(Box::new(provider))
    }

    fn register_boxed(
        &mut self,
        provider: Box<dyn PersistentSemanticProvider>,
    ) -> Result<(), SemanticProviderRegistryError> {
        let language = provider.language();
        if language.is_empty() {
            return Err(SemanticProviderRegistryError::EmptyLanguage);
        }
        if self.providers.contains_key(language) {
            return Err(SemanticProviderRegistryError::DuplicateLanguage(
                language.to_owned(),
            ));
        }
        self.providers.insert(language.to_owned(), provider);
        Ok(())
    }

    pub(crate) fn languages(&self) -> Vec<&str> {
        self.providers.keys().map(String::as_str).collect()
    }

    pub(crate) fn contains(&self, language: &str) -> bool {
        self.providers.contains_key(language)
    }

    pub(crate) fn contains_provider(&self, language: &str, provider_id: &str) -> bool {
        self.providers
            .get(language)
            .is_some_and(|provider| provider.provider_id() == provider_id)
    }

    pub(crate) fn get_mut(
        &mut self,
        language: &str,
    ) -> Option<&mut (dyn PersistentSemanticProvider + '_)> {
        self.providers
            .get_mut(language)
            .map(|provider| provider.as_mut() as &mut (dyn PersistentSemanticProvider + '_))
    }

    pub(crate) fn set_session_jobs(&mut self, jobs: Option<usize>) {
        for provider in self.providers.values_mut() {
            provider.set_session_jobs(jobs);
        }
    }

    /// Execute one operation against every independently owned language
    /// coordinator and return results in stable language-key order.
    pub(crate) async fn map_providers<'a, T, F>(&'a mut self, mut operation: F) -> Vec<T>
    where
        F: FnMut(
            &'a mut (dyn PersistentSemanticProvider + 'a),
        ) -> Pin<Box<dyn Future<Output = T> + Send + 'a>>,
    {
        let operations = self
            .providers
            .values_mut()
            .map(|provider| operation(provider.as_mut()))
            .collect::<Vec<_>>();
        join_all(operations).await
    }

    pub(crate) fn active_cache_directories(&self) -> BTreeSet<PathBuf> {
        self.providers
            .values()
            .flat_map(|provider| provider.active_cache_directories())
            .collect()
    }

    pub(crate) fn mark_publication_committed(&mut self, language: &str) {
        if let Some(provider) = self.get_mut(language) {
            provider.mark_publication_committed();
        }
    }

    pub(crate) async fn reset_all(&mut self) {
        for provider in self.providers.values_mut() {
            provider.reset().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    #[derive(Debug, Default, PartialEq, Eq)]
    struct FakeLifecycle {
        cache_roots: Vec<PathBuf>,
        session_jobs: Vec<Option<usize>>,
        publication_commits: usize,
        resets: usize,
    }

    #[derive(Debug, Clone)]
    struct FakeProvider {
        language: &'static str,
        lifecycle: Arc<Mutex<FakeLifecycle>>,
    }

    impl SemanticProviderAdapterConfig for FakeProvider {
        type Provider = Self;

        fn language(&self) -> &'static str {
            self.language
        }

        fn bind_cache_root(&mut self, cache_root: &Path) {
            self.lifecycle
                .lock()
                .expect("fake lifecycle lock")
                .cache_roots
                .push(cache_root.to_path_buf());
        }

        fn set_arguments(&mut self, _arguments: Vec<OsString>) {}

        fn into_provider(self) -> Self::Provider {
            self
        }
    }

    #[async_trait]
    impl PersistentSemanticProvider for FakeProvider {
        fn language(&self) -> &'static str {
            self.language
        }

        fn ecosystem(&self) -> &'static str {
            match self.language {
                "go" => "go",
                "rust" => "cargo",
                _ => "test",
            }
        }

        fn provider_id(&self) -> &str {
            "h00-test-provider"
        }

        fn operation_label(&self) -> &'static str {
            "persistent test provider"
        }

        fn set_session_jobs(&mut self, jobs: Option<usize>) {
            self.lifecycle
                .lock()
                .expect("fake lifecycle lock")
                .session_jobs
                .push(jobs);
        }

        fn take_last_activity(&mut self) -> Option<SemanticProviderActivityRecord> {
            None
        }

        fn active_cache_directories(&self) -> BTreeSet<PathBuf> {
            BTreeSet::from([PathBuf::from("cache").join(self.language)])
        }

        async fn authorize_and_hydrate_exact_generation_reuse(
            &mut self,
            _repository_root: &Path,
            _inventory: &ProjectInventory,
            _indexed_sources: &[IndexedSourceEvidence],
            _provider_payloads: &[NormalizedProviderPayload],
            _prior_bases: &[CanonicalSemanticBasis],
            _cancellation: &IndexCancellation,
        ) -> bool {
            false
        }

        async fn reuse_exact_canonical_basis(
            &mut self,
            _repository_root: &Path,
            _inventory: &ProjectInventory,
            _indexed_sources: &[IndexedSourceEvidence],
            _prior_bases: &[CanonicalSemanticBasis],
            _cancellation: &IndexCancellation,
        ) -> Option<ScipArtifactSetNormalization> {
            None
        }

        async fn refresh(
            &mut self,
            _repository_root: &Path,
            _execution_roots: &[PathBuf],
            _indexed_sources: &[IndexedSourceEvidence],
            _inventory: &ProjectInventory,
            _cancellation: &IndexCancellation,
        ) -> Result<ScipArtifactSetNormalization, SemanticProviderError> {
            panic!("registry lifecycle test does not execute a language adapter")
        }

        fn mark_publication_committed(&mut self) {
            self.lifecycle
                .lock()
                .expect("fake lifecycle lock")
                .publication_commits += 1;
        }

        async fn reset(&mut self) {
            self.lifecycle.lock().expect("fake lifecycle lock").resets += 1;
        }
    }

    fn fake_provider(language: &'static str) -> (FakeProvider, Arc<Mutex<FakeLifecycle>>) {
        let lifecycle = Arc::new(Mutex::new(FakeLifecycle::default()));
        (
            FakeProvider {
                language,
                lifecycle: Arc::clone(&lifecycle),
            },
            lifecycle,
        )
    }

    #[tokio::test]
    async fn third_language_flows_through_common_lifecycle_without_new_owner_slot() {
        let (python, lifecycle) = fake_provider("python");
        let mut config = SemanticProviderConfig::from_adapter(python);
        assert_eq!(config.language(), "python");
        config.bind_cache_root(Path::new("provider-cache"));
        let mut registry =
            SemanticProviderRegistry::from_configs(vec![config]).expect("register Python adapter");

        assert_eq!(registry.languages(), vec!["python"]);
        assert!(registry.contains("python"));
        assert!(registry.get_mut("python").is_some());
        assert_eq!(
            registry.active_cache_directories(),
            BTreeSet::from([PathBuf::from("cache/python")])
        );

        registry.set_session_jobs(Some(6));
        registry.mark_publication_committed("python");
        registry.reset_all().await;

        assert_eq!(
            *lifecycle.lock().expect("fake lifecycle after reset"),
            FakeLifecycle {
                cache_roots: vec![PathBuf::from("provider-cache")],
                session_jobs: vec![Some(6)],
                publication_commits: 1,
                resets: 1,
            }
        );
    }

    /// RIGHT-REASON CONCURRENCY REGRESSION: language coordinators own disjoint
    /// child processes, caches, and authority state. Both fake lanes wait at
    /// the same barrier; a serial registry times out on the first lane, while
    /// actual overlap releases both and preserves stable result ordering.
    #[tokio::test]
    async fn independent_language_operations_overlap_without_new_owner_slots() {
        let (go, _) = fake_provider("go");
        let (rust, _) = fake_provider("rust");
        let mut registry = SemanticProviderRegistry::default();
        registry.register(rust).expect("register Rust adapter");
        registry.register(go).expect("register Go adapter");
        let barrier = Arc::new(tokio::sync::Barrier::new(2));

        let results = tokio::time::timeout(
            Duration::from_secs(1),
            registry.map_providers(|provider| {
                let barrier = Arc::clone(&barrier);
                let language = provider.language();
                Box::pin(async move {
                    barrier.wait().await;
                    language
                })
            }),
        )
        .await
        .expect("independent language operations must actually overlap");

        assert_eq!(results, vec!["go", "rust"]);
        assert_eq!(registry.languages(), vec!["go", "rust"]);
    }

    #[test]
    fn invalid_or_duplicate_language_keys_are_rejected_without_replacement() {
        let mut registry = SemanticProviderRegistry::default();
        let (empty, _) = fake_provider("");
        assert_eq!(
            registry.register(empty),
            Err(SemanticProviderRegistryError::EmptyLanguage)
        );

        let (python, _) = fake_provider("python");
        registry.register(python).expect("first Python adapter");
        let (duplicate, _) = fake_provider("python");
        assert_eq!(
            registry.register(duplicate),
            Err(SemanticProviderRegistryError::DuplicateLanguage(
                "python".into()
            ))
        );
        assert_eq!(registry.languages(), vec!["python"]);
    }
}
