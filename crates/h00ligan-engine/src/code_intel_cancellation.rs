//! Cooperative cancellation shared by indexing adapters and blocking providers.
//!
//! The token is deliberately runtime-neutral: blocking provider loops can poll
//! it without depending on a particular async executor, while CLI and MCP
//! adapters may clone it into their own lifecycle state.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Debug, Clone, Default)]
pub struct IndexCancellation {
    cancelled: Arc<AtomicBool>,
}

impl IndexCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}
