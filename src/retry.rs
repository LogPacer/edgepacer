//! Exponential backoff retry policy.
//!
//! M2-local policy: simple in-memory retry with exponential backoff.
//! This does NOT replace legacy EdgePacer's full delivery pipeline which includes
//! disk-backed buffering, DLQ, checkpoint-on-ack, and crash-safe resume.
//! Full delivery guarantees land in M4.
//!
//! Mirrors legacy EdgePacer's `internal/backoff/` package for the retry curve only.

use std::time::Duration;

/// Retry policy with exponential backoff and jitter.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// Initial delay before first retry.
    pub initial_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Maximum number of attempts (including initial). 0 = unlimited.
    pub max_attempts: u32,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            max_attempts: 0, // unlimited — never drop customer data
        }
    }
}

impl RetryPolicy {
    /// Compute delay for a given attempt number (1-based).
    /// Returns None if max_attempts exceeded (never if max_attempts == 0).
    pub fn delay_for(&self, attempt: u32) -> Option<Duration> {
        if self.max_attempts > 0 && attempt >= self.max_attempts {
            return None;
        }

        // Exponential: initial * 2^(attempt-1)
        let exp = self.initial_delay.as_millis() as u64 * (1u64 << (attempt - 1).min(16));
        let capped = exp.min(self.max_delay.as_millis() as u64);

        // Add jitter: ±25%
        let jitter_range = capped / 4;
        let jitter = if jitter_range > 0 {
            // Simple deterministic jitter based on attempt (no rand dependency)
            let offset = (attempt as u64 * 7919) % (jitter_range * 2);
            offset as i64 - jitter_range as i64
        } else {
            0
        };

        let delay_ms = (capped as i64 + jitter).max(1) as u64;
        Some(Duration::from_millis(delay_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_unlimited() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, 0); // unlimited — never drop customer data
    }

    #[test]
    fn exponential_growth() {
        let policy = RetryPolicy {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            max_attempts: 5,
        };

        // Attempt 1: ~100ms
        let d1 = policy.delay_for(1).unwrap();
        assert!(d1.as_millis() >= 75 && d1.as_millis() <= 125);

        // Attempt 2: ~200ms
        let d2 = policy.delay_for(2).unwrap();
        assert!(d2.as_millis() >= 150 && d2.as_millis() <= 250);

        // Attempt 3: ~400ms
        let d3 = policy.delay_for(3).unwrap();
        assert!(d3.as_millis() >= 300 && d3.as_millis() <= 500);
    }

    #[test]
    fn respects_max_delay() {
        let policy = RetryPolicy {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            max_attempts: 10,
        };

        // High attempt should be capped
        let d = policy.delay_for(8).unwrap();
        assert!(d.as_secs() <= 6); // 5s + jitter tolerance
    }

    #[test]
    fn none_after_max_attempts() {
        let policy = RetryPolicy {
            max_attempts: 3,
            ..Default::default()
        };

        assert!(policy.delay_for(1).is_some());
        assert!(policy.delay_for(2).is_some());
        assert!(policy.delay_for(3).is_none()); // attempt 3 = max_attempts
    }

    #[test]
    fn unlimited_retries_never_returns_none() {
        let policy = RetryPolicy {
            max_attempts: 0, // unlimited
            ..Default::default()
        };

        // Even at very high attempt counts, should always return Some
        assert!(policy.delay_for(1).is_some());
        assert!(policy.delay_for(100).is_some());
        assert!(policy.delay_for(10_000).is_some());
    }
}
