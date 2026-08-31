//! Reusable read models bound to one validated immutable generation.
//!
//! The first boundary is deliberately narrow: transports retain one index
//! beside the exact graph/generation snapshot and route target-scoped Calls
//! queries through it. The projection is built once for each target document
//! population and discarded with the owning immutable snapshot.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::code_intel_calls::{
    ExactCallsResult, PublishedCallsGraph, query_published_calls_indexed,
};
use crate::code_intel_domain::{CallsRequest, DomainError, LanguageId};
use crate::code_intel_publication::ResolvedGeneration;
use crate::graph::{GraphNode, KnowledgeGraph};
use crate::project_binding::ProjectBinding;

/// Process-local derived views for one exact graph/generation pair.
///
/// This type is not publication authority. It owns the already validated
/// immutable graph/generation pair so no query caller can substitute one half
/// of a different snapshot. Discard the whole index when publication changes.
pub struct GenerationQueryIndex {
    graph: Arc<KnowledgeGraph>,
    generation: Arc<ResolvedGeneration>,
    calls: Mutex<BTreeMap<CallsProjectionKey, Arc<PublishedCallsGraph>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum CallsProjectionKey {
    TargetDocument {
        language_id: LanguageId,
        document_path: String,
    },
}

impl GenerationQueryIndex {
    #[must_use]
    pub const fn new(graph: Arc<KnowledgeGraph>, generation: Arc<ResolvedGeneration>) -> Self {
        Self {
            graph,
            generation,
            calls: Mutex::new(BTreeMap::new()),
        }
    }

    #[must_use]
    pub const fn graph(&self) -> &Arc<KnowledgeGraph> {
        &self.graph
    }

    #[must_use]
    pub const fn generation(&self) -> &Arc<ResolvedGeneration> {
        &self.generation
    }

    pub fn query_calls(
        &self,
        binding: &ProjectBinding,
        request: &CallsRequest,
    ) -> Result<ExactCallsResult, DomainError> {
        query_published_calls_indexed(self, binding, request)
    }

    pub(crate) fn calls_for_target(
        &self,
        target_language: &LanguageId,
        target: &GraphNode,
    ) -> Result<Arc<PublishedCallsGraph>, DomainError> {
        let key = CallsProjectionKey::TargetDocument {
            language_id: target_language.clone(),
            document_path: target.file_path.clone(),
        };
        let mut calls = self.calls.lock();
        if let Some(projection) = calls.get(&key) {
            return Ok(Arc::clone(projection));
        }
        let projection = Arc::new(PublishedCallsGraph::build_for_target(
            &self.graph,
            &self.generation,
            target_language,
            target,
        )?);
        calls.insert(key, Arc::clone(&projection));
        drop(calls);
        Ok(projection)
    }
}
