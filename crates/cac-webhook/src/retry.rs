//! Minimal retry helpers (replaces git-only `resilient-call` for crates.io).

use std::future::Future;
use std::time::Duration;

/// Simple retry policy: max attempts with exponential backoff + jitter-ish delay.
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base_delay: Duration,
}

impl RetryPolicy {
    pub fn with_max_attempts(max_attempts: u32) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            base_delay: Duration::from_millis(100),
        }
    }
}

/// Error wrapper that can carry a source error or a timeout.
#[derive(Debug)]
pub struct RetryError<E> {
    source: Option<E>,
    timed_out: bool,
}

impl<E> RetryError<E> {
    pub fn into_source(self) -> Option<E> {
        self.source
    }

    pub fn timed_out(&self) -> bool {
        self.timed_out
    }
}

/// Run `fut` with an outer timeout. On timeout returns `RetryError` with no source.
pub async fn with_timeout<T, E, F>(fut: F, timeout: Duration) -> Result<T, RetryError<E>>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(RetryError {
            source: Some(e),
            timed_out: false,
        }),
        Err(_) => Err(RetryError {
            source: None,
            timed_out: true,
        }),
    }
}

/// Retry `make_fut` up to `policy.max_attempts` when `is_retryable` says so.
pub async fn retry<T, E, Fut, Make, Pred>(
    mut make_fut: Make,
    policy: &RetryPolicy,
    is_retryable: Pred,
) -> Result<T, RetryError<E>>
where
    Make: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    Pred: Fn(&E) -> bool,
{
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match make_fut().await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt >= policy.max_attempts || !is_retryable(&e) {
                    return Err(RetryError {
                        source: Some(e),
                        timed_out: false,
                    });
                }
                let delay = policy.base_delay.saturating_mul(1 << (attempt - 1).min(4));
                tokio::time::sleep(delay).await;
            }
        }
    }
}
