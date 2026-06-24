//! Token-bucket rate limiter — mirrors Go `internal/ratelimit/limiter.go`.
//!
//! Used to throttle Docker API calls (default 10 req/sec).

use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use tracing::warn;

/// Token-bucket limiter: `rate` events per `interval`, burst == rate.
pub struct RateLimiter {
    rate: u32,
    interval: Duration,
    inner: Mutex<Inner>,
}

struct Inner {
    tokens: f64,
    last: Instant,
    burst: u32,
}

impl RateLimiter {
    /// Create a limiter. Invalid `rate` defaults to 1; zero interval defaults to 1s.
    pub fn new(rate: u32, interval: Duration) -> Self {
        let rate = rate.max(1);
        let interval = if interval.is_zero() {
            Duration::from_secs(1)
        } else {
            interval
        };
        Self {
            rate,
            interval,
            inner: Mutex::new(Inner {
                tokens: rate as f64,
                last: Instant::now(),
                burst: rate,
            }),
        }
    }

    fn refill(inner: &mut Inner, rate: u32, interval: Duration) {
        let now = Instant::now();
        let elapsed = now.duration_since(inner.last);
        inner.last = now;
        let per_token_secs = interval.as_secs_f64() / rate as f64;
        if per_token_secs > 0.0 {
            inner.tokens =
                (inner.tokens + elapsed.as_secs_f64() / per_token_secs).min(inner.burst as f64);
        }
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("rate limiter lock poisoned; recovering token bucket state");
                self.inner.clear_poison();
                poisoned.into_inner()
            }
        }
    }

    /// Non-blocking acquire — returns true if a token was consumed.
    pub fn try_acquire(&self) -> bool {
        let mut inner = self.inner();
        Self::refill(&mut inner, self.rate, self.interval);
        if inner.tokens >= 1.0 {
            inner.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Block until a token is available.
    pub async fn wait(&self) {
        loop {
            if self.try_acquire() {
                return;
            }
            let sleep_for = {
                let mut inner = self.inner();
                Self::refill(&mut inner, self.rate, self.interval);
                let per_token_secs = self.interval.as_secs_f64() / self.rate as f64;
                let deficit = (1.0 - inner.tokens).max(0.0);
                Duration::from_secs_f64(deficit * per_token_secs)
            };
            tokio::time::sleep(sleep_for.max(Duration::from_millis(1))).await;
        }
    }
}

/// Shared Docker API limiter — 10 requests per second (Go default).
pub fn docker_limiter() -> &'static RateLimiter {
    static LIMITER: OnceLock<RateLimiter> = OnceLock::new();
    LIMITER.get_or_init(|| RateLimiter::new(10, Duration::from_secs(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allows_burst_up_to_rate() {
        let limiter = RateLimiter::new(3, Duration::from_secs(1));
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());
    }

    #[tokio::test]
    async fn wait_completes_after_refill() {
        let limiter = RateLimiter::new(1, Duration::from_millis(20));
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire());
        tokio::time::timeout(Duration::from_secs(1), limiter.wait())
            .await
            .expect("wait should not hang");
    }

    #[test]
    fn recovers_from_poisoned_lock() {
        let limiter = RateLimiter::new(1, Duration::from_secs(1));
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = limiter.inner.lock().unwrap();
            panic!("poison rate limiter");
        }));

        assert!(limiter.try_acquire());
    }
}
