//! Delivery result semantics matching legacy EdgePacer's `internal/common/delivery.go`.
//!
//! These types define two distinct concerns:
//! 1. **Source read continuation**: can the tailer keep reading more lines?
//! 2. **Checkpoint advancement**: handled SOLELY by BatchTracker's consecutive-ack rule.
//!
//! These are NOT the same axis. `Buffered` allows continued reading but does NOT
//! imply checkpoint eligibility. Only `Delivered` feeds into the consecutive-ack
//! checkpoint computation.

/// Outcome of a delivery attempt.
///
/// Intentionally does NOT include `SentToDlq` — DLQ behavior is not yet implemented
/// in the Rust rewrite. When DLQ lands, it will be added with its actual guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryResult {
    /// Logs confirmed received by endpoint. This is the ONLY result that feeds
    /// into BatchTracker's consecutive-ack checkpoint computation.
    Delivered,
    /// Persisted to disk buffer. The tailer may continue reading (data is durable
    /// in the buffer), but this does NOT advance the checkpoint — that requires
    /// confirmed delivery through the drain path.
    Buffered,
    /// Delivery failed after exhausting retries. Data remains in the buffer
    /// for manual recovery. The tailer MUST stop reading because the pipeline
    /// is unable to make forward progress.
    Failed,
    /// Buffer full or endpoint unreachable. The tailer MUST stop reading
    /// until backpressure releases.
    Blocked,
}

impl DeliveryResult {
    /// Whether the tailer may continue reading more source data.
    ///
    /// This is about ingest continuation, NOT checkpoint advancement.
    /// Checkpoint advancement is derived solely from BatchTracker.safe_checkpoint().
    pub fn allows_source_read(&self) -> bool {
        matches!(self, Self::Delivered | Self::Buffered)
    }
}

/// Classification of errors for retry decisions.
///
/// Matches Go's `common.ErrorClass` from `delivery.go`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// 5xx, timeouts, network errors — retry with backoff.
    Retryable,
    /// 4xx (except 429) — do not retry, send to DLQ.
    NonRetryable,
    /// 401/403 — trigger token refresh, then retry.
    Auth,
}

/// Classify an HTTP status code into an error class.
pub fn classify_http_status(status: u16) -> ErrorClass {
    match status {
        401 | 403 => ErrorClass::Auth,
        429 => ErrorClass::Retryable, // rate limited — retry with backoff
        400..=499 => ErrorClass::NonRetryable,
        500..=599 => ErrorClass::Retryable,
        _ => ErrorClass::NonRetryable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_read_continuation() {
        assert!(DeliveryResult::Delivered.allows_source_read());
        assert!(DeliveryResult::Buffered.allows_source_read());
        assert!(!DeliveryResult::Failed.allows_source_read());
        assert!(!DeliveryResult::Blocked.allows_source_read());
    }

    #[test]
    fn http_status_classification() {
        assert_eq!(classify_http_status(200), ErrorClass::NonRetryable); // not an error
        assert_eq!(classify_http_status(401), ErrorClass::Auth);
        assert_eq!(classify_http_status(403), ErrorClass::Auth);
        assert_eq!(classify_http_status(404), ErrorClass::NonRetryable);
        assert_eq!(classify_http_status(429), ErrorClass::Retryable);
        assert_eq!(classify_http_status(500), ErrorClass::Retryable);
        assert_eq!(classify_http_status(503), ErrorClass::Retryable);
    }
}
