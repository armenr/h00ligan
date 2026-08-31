//! Stateless continuation cursors shared by code-intelligence use cases.
//!
//! Cursors bind an offset to one operation, immutable generation, and request
//! identity. The checksum detects corruption; it is deliberately not described
//! as an authorization signature because CLI continuations must work across
//! processes without a hidden machine-local key.

use std::ops::Range;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::code_intel_domain::{DomainError, GenerationId, Page};

const CURSOR_VERSION: u8 = 1;
const CURSOR_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Serialize, Deserialize)]
struct CursorPayload {
    version: u8,
    operation: String,
    generation_id: String,
    request_digest: String,
    offset: usize,
    expires_at_unix_seconds: u64,
    checksum: String,
}

pub struct PageWindow {
    pub range: Range<usize>,
    pub page: Page,
}

/// Stable digest of all request fields except paging controls.
pub fn request_digest(operation: &str, fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"h00-code-intel-request-v1\0");
    hash_field(&mut hasher, operation);
    for field in fields {
        hash_field(&mut hasher, field);
    }
    hex(&hasher.finalize())
}

/// Resolve one page and, when needed, issue a continuation bound to the exact
/// immutable generation and non-paging request identity.
pub fn page_window(
    operation: &str,
    generation_id: &GenerationId,
    request_digest: &str,
    cursor: Option<&str>,
    limit: usize,
    total_items: usize,
) -> Result<PageWindow, DomainError> {
    let now = unix_seconds();
    let offset = match cursor {
        Some(cursor) => {
            decode_cursor(cursor, operation, generation_id, request_digest, now)?.offset
        }
        None => 0,
    };
    if offset > total_items {
        return Err(DomainError::InvalidCursor {
            reason: format!("offset {offset} exceeds result population {total_items}"),
        });
    }

    let end = offset.saturating_add(limit).min(total_items);
    let has_more = end < total_items;
    let expires_at = now.saturating_add(CURSOR_TTL.as_secs());
    let next_cursor = has_more.then(|| {
        encode_cursor(CursorPayload {
            version: CURSOR_VERSION,
            operation: operation.into(),
            generation_id: generation_id.0.clone(),
            request_digest: request_digest.into(),
            offset: end,
            expires_at_unix_seconds: expires_at,
            checksum: String::new(),
        })
    });

    Ok(PageWindow {
        range: offset..end,
        page: Page {
            offset,
            limit,
            returned: end - offset,
            total_items,
            has_more,
            next_cursor,
            expires_at_unix_seconds: has_more.then_some(expires_at),
        },
    })
}

fn encode_cursor(mut payload: CursorPayload) -> String {
    payload.checksum = cursor_checksum(&payload);
    let bytes = serde_json::to_vec(&payload).expect("cursor payload is serializable");
    hex(&bytes)
}

fn decode_cursor(
    encoded: &str,
    operation: &str,
    generation_id: &GenerationId,
    request_digest: &str,
    now: u64,
) -> Result<CursorPayload, DomainError> {
    let bytes = decode_hex(encoded).map_err(|reason| DomainError::InvalidCursor { reason })?;
    let payload: CursorPayload =
        serde_json::from_slice(&bytes).map_err(|error| DomainError::InvalidCursor {
            reason: error.to_string(),
        })?;
    if payload.version != CURSOR_VERSION {
        return Err(DomainError::InvalidCursor {
            reason: format!("unsupported cursor version {}", payload.version),
        });
    }
    if payload.checksum != cursor_checksum(&payload) {
        return Err(DomainError::InvalidCursor {
            reason: "checksum mismatch".into(),
        });
    }
    if payload.operation != operation || payload.request_digest != request_digest {
        return Err(DomainError::InvalidCursor {
            reason: format!("cursor belongs to a different {operation} request"),
        });
    }
    if payload.generation_id != generation_id.0 {
        return Err(DomainError::CursorGenerationChanged {
            cursor_generation: payload.generation_id,
            current_generation: generation_id.0.clone(),
        });
    }
    if payload.expires_at_unix_seconds < now {
        return Err(DomainError::CursorExpired);
    }
    Ok(payload)
}

fn cursor_checksum(payload: &CursorPayload) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"h00-code-intel-cursor-v1\0");
    hasher.update([payload.version]);
    hash_field(&mut hasher, &payload.operation);
    hash_field(&mut hasher, &payload.generation_id);
    hash_field(&mut hasher, &payload.request_digest);
    hasher.update(payload.offset.to_le_bytes());
    hasher.update(payload.expires_at_unix_seconds.to_le_bytes());
    hex(&hasher.finalize())
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>, String> {
    if !encoded.len().is_multiple_of(2) {
        return Err("hex cursor has odd length".into());
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|error| error.to_string())?;
            u8::from_str_radix(text, 16).map_err(|error| error.to_string())
        })
        .collect()
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hash_field(hasher: &mut Sha256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_cannot_cross_operation_boundaries() {
        let generation = GenerationId::new("generation-a");
        let digest = request_digest("calls", &["target", "", "live"]);
        let first =
            page_window("calls", &generation, &digest, None, 1, 2).expect("Calls first page");
        let cursor = first.page.next_cursor.expect("continuation cursor");

        let error = match page_window("type", &generation, &digest, Some(&cursor), 1, 2) {
            Ok(_) => panic!("Calls cursor must not authorize a Type continuation"),
            Err(error) => error,
        };
        assert!(matches!(error, DomainError::InvalidCursor { .. }));
    }

    /// RIGHT-REASON REGRESSION for B02: after structural integrity and request
    /// ownership are established, immutable-generation drift is the primary
    /// diagnosis. Expiry must not hide that the continuation belongs to a
    /// superseded result population.
    #[test]
    fn cursor_identity_precedes_expiry_with_total_error_precedence() {
        let digest = request_digest("calls", &["target"]);
        let cursor = encode_cursor(CursorPayload {
            version: CURSOR_VERSION,
            operation: "calls".into(),
            generation_id: "generation-a".into(),
            request_digest: digest.clone(),
            offset: 1,
            expires_at_unix_seconds: 1,
            checksum: String::new(),
        });

        let generation_error = decode_cursor(
            &cursor,
            "calls",
            &GenerationId::new("generation-b"),
            &digest,
            2,
        )
        .expect_err("superseded generation must outrank expiry");
        assert!(matches!(
            generation_error,
            DomainError::CursorGenerationChanged { .. }
        ));

        let request_error = decode_cursor(
            &cursor,
            "type",
            &GenerationId::new("generation-b"),
            &digest,
            2,
        )
        .expect_err("foreign request identity must outrank generation and expiry");
        assert!(matches!(request_error, DomainError::InvalidCursor { .. }));

        let expiry_error = decode_cursor(
            &cursor,
            "calls",
            &GenerationId::new("generation-a"),
            &digest,
            2,
        )
        .expect_err("an otherwise current cursor still expires");
        assert!(matches!(expiry_error, DomainError::CursorExpired));
    }
}
