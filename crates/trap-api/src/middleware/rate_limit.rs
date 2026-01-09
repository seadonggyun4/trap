// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Rate limiting middleware.

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::Request,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tower::{Layer, Service};

use crate::error::ApiError;

// =============================================================================
// RateLimitConfig
// =============================================================================

/// Configuration for rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled.
    pub enabled: bool,
    /// Global requests per second.
    pub requests_per_second: u32,
    /// Burst size (max tokens in bucket).
    pub burst_size: u32,
    /// Whether to use per-IP limiting.
    pub per_ip: bool,
    /// Per-IP requests per second (if per_ip is enabled).
    pub per_ip_requests_per_second: u32,
    /// Per-IP burst size.
    pub per_ip_burst_size: u32,
    /// Cleanup interval for expired IP entries.
    #[serde(with = "duration_serde")]
    pub cleanup_interval: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 100,
            burst_size: 200,
            per_ip: true,
            per_ip_requests_per_second: 20,
            per_ip_burst_size: 40,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

impl RateLimitConfig {
    /// Creates a disabled rate limiter.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Creates a strict rate limiter for production.
    pub fn strict() -> Self {
        Self {
            enabled: true,
            requests_per_second: 50,
            burst_size: 100,
            per_ip: true,
            per_ip_requests_per_second: 10,
            per_ip_burst_size: 20,
            cleanup_interval: Duration::from_secs(30),
        }
    }

    /// Creates a relaxed rate limiter for development.
    pub fn relaxed() -> Self {
        Self {
            enabled: true,
            requests_per_second: 1000,
            burst_size: 2000,
            per_ip: false,
            per_ip_requests_per_second: 100,
            per_ip_burst_size: 200,
            cleanup_interval: Duration::from_secs(300),
        }
    }
}

// =============================================================================
// Token Bucket
// =============================================================================

/// A simple token bucket rate limiter.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            tokens: max_tokens as f64,
            max_tokens: max_tokens as f64,
            refill_rate: refill_rate as f64,
            last_refill: std::time::Instant::now(),
        }
    }

    fn try_acquire(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    fn time_until_token(&self) -> Duration {
        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let needed = 1.0 - self.tokens;
            Duration::from_secs_f64(needed / self.refill_rate)
        }
    }
}

// =============================================================================
// Rate Limiter State
// =============================================================================

/// Shared state for the rate limiter.
#[derive(Debug)]
pub struct RateLimiterState {
    config: RateLimitConfig,
    global_bucket: std::sync::Mutex<TokenBucket>,
    ip_buckets: DashMap<IpAddr, TokenBucket>,
}

impl RateLimiterState {
    /// Creates a new rate limiter state.
    pub fn new(config: RateLimitConfig) -> Self {
        let global_bucket = TokenBucket::new(config.burst_size, config.requests_per_second);

        Self {
            config,
            global_bucket: std::sync::Mutex::new(global_bucket),
            ip_buckets: DashMap::new(),
        }
    }

    /// Checks if a request is allowed.
    pub fn check(&self, client_ip: Option<IpAddr>) -> RateLimitResult {
        if !self.config.enabled {
            return RateLimitResult::Allowed;
        }

        // Check global limit
        let global_allowed = {
            let mut bucket = self.global_bucket.lock().unwrap();
            bucket.try_acquire()
        };

        if !global_allowed {
            let retry_after = {
                let bucket = self.global_bucket.lock().unwrap();
                bucket.time_until_token().as_secs().max(1)
            };
            return RateLimitResult::Limited {
                retry_after: Some(retry_after),
                reason: "Global rate limit exceeded".to_string(),
            };
        }

        // Check per-IP limit if enabled
        if self.config.per_ip {
            if let Some(ip) = client_ip {
                let ip_allowed = {
                    let mut entry = self.ip_buckets.entry(ip).or_insert_with(|| {
                        TokenBucket::new(
                            self.config.per_ip_burst_size,
                            self.config.per_ip_requests_per_second,
                        )
                    });
                    entry.try_acquire()
                };

                if !ip_allowed {
                    let retry_after = self
                        .ip_buckets
                        .get(&ip)
                        .map(|b| b.time_until_token().as_secs().max(1));

                    return RateLimitResult::Limited {
                        retry_after,
                        reason: format!("Per-IP rate limit exceeded for {}", ip),
                    };
                }
            }
        }

        RateLimitResult::Allowed
    }

    /// Cleans up old IP entries.
    pub fn cleanup(&self) {
        // Remove entries that haven't been used recently
        // In a real implementation, we'd track last access time
        if self.ip_buckets.len() > 10000 {
            // Simple cleanup: remove entries with full buckets
            self.ip_buckets.retain(|_, bucket| {
                bucket.tokens < bucket.max_tokens
            });
        }
    }
}

/// Result of a rate limit check.
#[derive(Debug)]
pub enum RateLimitResult {
    /// Request is allowed.
    Allowed,
    /// Request is rate limited.
    Limited {
        /// Seconds until the client can retry.
        retry_after: Option<u64>,
        /// Reason for limiting.
        reason: String,
    },
}

// =============================================================================
// RateLimitLayer
// =============================================================================

/// Layer for rate limiting.
#[derive(Clone)]
pub struct RateLimitLayer {
    state: Arc<RateLimiterState>,
}

impl RateLimitLayer {
    /// Creates a new rate limit layer.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            state: Arc::new(RateLimiterState::new(config)),
        }
    }

    /// Creates a disabled rate limit layer.
    pub fn disabled() -> Self {
        Self::new(RateLimitConfig::disabled())
    }

    /// Returns the shared state for monitoring.
    pub fn state(&self) -> Arc<RateLimiterState> {
        self.state.clone()
    }
}

impl<S> Layer<S> for RateLimitLayer {
    type Service = RateLimitMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitMiddleware {
            inner,
            state: self.state.clone(),
        }
    }
}

// =============================================================================
// RateLimitMiddleware
// =============================================================================

/// Middleware for rate limiting.
#[derive(Clone)]
pub struct RateLimitMiddleware<S> {
    inner: S,
    state: Arc<RateLimiterState>,
}

impl<S> Service<Request<Body>> for RateLimitMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let state = self.state.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Extract client IP
            let client_ip = req
                .extensions()
                .get::<ConnectInfo<std::net::SocketAddr>>()
                .map(|ci| ci.0.ip());

            // Check rate limit
            match state.check(client_ip) {
                RateLimitResult::Allowed => inner.call(req).await,
                RateLimitResult::Limited { retry_after, reason } => {
                    tracing::debug!(
                        client_ip = ?client_ip,
                        reason = %reason,
                        retry_after = ?retry_after,
                        "Rate limit exceeded"
                    );
                    Ok(ApiError::rate_limit_exceeded(retry_after).into_response())
                }
            }
        })
    }
}

// =============================================================================
// Duration Serde
// =============================================================================

mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_allow() {
        let mut bucket = TokenBucket::new(10, 5);

        // Should allow up to burst_size requests
        for _ in 0..10 {
            assert!(bucket.try_acquire());
        }

        // Should deny after burst is exhausted
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10, 1000);

        // Exhaust tokens
        for _ in 0..10 {
            bucket.try_acquire();
        }
        assert!(!bucket.try_acquire());

        // Wait a bit for refill (simulate with manual refill)
        bucket.last_refill = std::time::Instant::now() - Duration::from_millis(10);
        bucket.refill();

        // Should have some tokens now
        assert!(bucket.tokens > 0.0);
    }

    #[test]
    fn test_rate_limiter_disabled() {
        let config = RateLimitConfig::disabled();
        let state = RateLimiterState::new(config);

        // Should always allow when disabled
        for _ in 0..1000 {
            assert!(matches!(state.check(None), RateLimitResult::Allowed));
        }
    }

    #[test]
    fn test_rate_limiter_global_limit() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 1,
            burst_size: 5,
            per_ip: false,
            ..Default::default()
        };
        let state = RateLimiterState::new(config);

        // Should allow burst_size requests
        for _ in 0..5 {
            assert!(matches!(state.check(None), RateLimitResult::Allowed));
        }

        // Should deny after burst is exhausted
        assert!(matches!(state.check(None), RateLimitResult::Limited { .. }));
    }

    #[test]
    fn test_rate_limiter_per_ip() {
        let config = RateLimitConfig {
            enabled: true,
            requests_per_second: 1000,
            burst_size: 2000,
            per_ip: true,
            per_ip_requests_per_second: 1,
            per_ip_burst_size: 3,
            ..Default::default()
        };
        let state = RateLimiterState::new(config);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Should allow per-IP burst for IP1
        for _ in 0..3 {
            assert!(matches!(state.check(Some(ip1)), RateLimitResult::Allowed));
        }

        // IP1 should be limited
        assert!(matches!(state.check(Some(ip1)), RateLimitResult::Limited { .. }));

        // IP2 should still have its quota
        assert!(matches!(state.check(Some(ip2)), RateLimitResult::Allowed));
    }
}
