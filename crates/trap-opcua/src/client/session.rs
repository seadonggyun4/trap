// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! OPC UA session management.
//!
//! This module provides session lifecycle management for OPC UA connections,
//! including session creation, activation, keepalive, and renewal.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::error::{OpcUaError, OpcUaResult, SessionError};
use crate::types::OpcUaConfig;

// =============================================================================
// SessionState
// =============================================================================

/// State of an OPC UA session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// Session is not created.
    #[default]
    NotCreated,

    /// Session creation is in progress.
    Creating,

    /// Session is created but not activated.
    Created,

    /// Session activation is in progress.
    Activating,

    /// Session is active and ready for use.
    Active,

    /// Session is being renewed.
    Renewing,

    /// Session is being closed.
    Closing,

    /// Session is closed.
    Closed,

    /// Session has failed.
    Failed,
}

impl SessionState {
    /// Returns `true` if the session is active and ready for use.
    #[inline]
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Returns `true` if the session is in a usable state.
    #[inline]
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::Renewing)
    }

    /// Returns `true` if the session is in a transitional state.
    #[inline]
    pub fn is_transitioning(&self) -> bool {
        matches!(
            self,
            Self::Creating | Self::Activating | Self::Renewing | Self::Closing
        )
    }

    /// Returns `true` if the session has failed.
    #[inline]
    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed)
    }

    /// Returns `true` if the session can be reused.
    #[inline]
    pub fn can_reuse(&self) -> bool {
        matches!(self, Self::Active | Self::Created)
    }
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCreated => write!(f, "NotCreated"),
            Self::Creating => write!(f, "Creating"),
            Self::Created => write!(f, "Created"),
            Self::Activating => write!(f, "Activating"),
            Self::Active => write!(f, "Active"),
            Self::Renewing => write!(f, "Renewing"),
            Self::Closing => write!(f, "Closing"),
            Self::Closed => write!(f, "Closed"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

// =============================================================================
// SessionInfo
// =============================================================================

/// Information about an active session.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session ID (server-assigned).
    pub session_id: String,

    /// Authentication token.
    pub auth_token: String,

    /// Session timeout in milliseconds.
    pub timeout_ms: u64,

    /// Server-revised session timeout.
    pub revised_timeout_ms: u64,

    /// Maximum request size.
    pub max_request_size: u32,

    /// Server nonce for security.
    pub server_nonce: Vec<u8>,

    /// Server certificate.
    pub server_certificate: Option<Vec<u8>>,

    /// Session creation time.
    pub created_at: Instant,

    /// Last activity time.
    pub last_activity: Instant,
}

impl SessionInfo {
    /// Creates new session info.
    pub fn new(session_id: impl Into<String>, auth_token: impl Into<String>) -> Self {
        let now = Instant::now();
        Self {
            session_id: session_id.into(),
            auth_token: auth_token.into(),
            timeout_ms: 60000,
            revised_timeout_ms: 60000,
            max_request_size: 0,
            server_nonce: Vec::new(),
            server_certificate: None,
            created_at: now,
            last_activity: now,
        }
    }

    /// Returns the session age.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Returns the time since last activity.
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }

    /// Checks if the session is about to expire.
    pub fn is_expiring_soon(&self, threshold: Duration) -> bool {
        let timeout = Duration::from_millis(self.revised_timeout_ms);
        let remaining = timeout.saturating_sub(self.idle_time());
        remaining < threshold
    }

    /// Updates the last activity time.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }
}

// =============================================================================
// SessionManager
// =============================================================================

/// Manages OPC UA session lifecycle.
///
/// The SessionManager handles:
/// - Session creation and activation
/// - Session renewal before timeout
/// - Automatic reconnection on failure
/// - Keepalive monitoring
///
/// # Thread Safety
///
/// The SessionManager is thread-safe and can be shared across tasks.
pub struct SessionManager {
    /// Session configuration.
    config: OpcUaConfig,

    /// Current session state.
    state: RwLock<SessionState>,

    /// Active session info.
    session_info: RwLock<Option<SessionInfo>>,

    /// Session statistics.
    stats: SessionStats,

    /// State change callback.
    on_state_change: Mutex<Option<Box<dyn Fn(SessionState, SessionState) + Send + Sync>>>,
}

impl SessionManager {
    /// Creates a new session manager.
    pub fn new(config: OpcUaConfig) -> Self {
        Self {
            config,
            state: RwLock::new(SessionState::NotCreated),
            session_info: RwLock::new(None),
            stats: SessionStats::new(),
            on_state_change: Mutex::new(None),
        }
    }

    /// Returns the current session state.
    pub async fn state(&self) -> SessionState {
        *self.state.read().await
    }

    /// Returns the session info if active.
    pub async fn session_info(&self) -> Option<SessionInfo> {
        self.session_info.read().await.clone()
    }

    /// Returns the session statistics.
    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }

    /// Sets a callback for state changes.
    pub async fn set_state_change_callback<F>(&self, callback: F)
    where
        F: Fn(SessionState, SessionState) + Send + Sync + 'static,
    {
        let mut on_change = self.on_state_change.lock().await;
        *on_change = Some(Box::new(callback));
    }

    /// Creates a new session.
    ///
    /// This method creates a session but does not activate it.
    /// Call `activate` to make the session ready for use.
    pub async fn create(&self) -> OpcUaResult<()> {
        let current_state = self.state().await;

        if current_state.is_active() {
            return Ok(()); // Already active
        }

        if current_state == SessionState::Creating {
            return Err(OpcUaError::session(SessionError::creation_failed(
                "Session creation already in progress",
            )));
        }

        self.set_state(SessionState::Creating).await;

        // Simulate session creation (actual implementation would use OPC UA client)
        let session_id = format!("session_{}", chrono::Utc::now().timestamp_millis());
        let auth_token = format!("token_{}", uuid::Uuid::new_v4());

        let mut info = SessionInfo::new(session_id, auth_token);
        info.timeout_ms = self.config.session_timeout.as_millis() as u64;
        info.revised_timeout_ms = info.timeout_ms;

        *self.session_info.write().await = Some(info);
        self.stats.record_creation();
        self.set_state(SessionState::Created).await;

        tracing::info!(
            endpoint = %self.config.endpoint,
            "OPC UA session created"
        );

        Ok(())
    }

    /// Activates the session.
    ///
    /// This method activates a created session, making it ready for use.
    pub async fn activate(&self) -> OpcUaResult<()> {
        let current_state = self.state().await;

        match current_state {
            SessionState::Active => return Ok(()),
            SessionState::Created | SessionState::Renewing => {}
            _ => {
                return Err(OpcUaError::session(SessionError::activation_failed(
                    format!("Invalid state for activation: {}, expected Created or Renewing", current_state),
                )));
            }
        }

        self.set_state(SessionState::Activating).await;

        // Simulate session activation
        if let Some(ref mut info) = *self.session_info.write().await {
            info.touch();
        }

        self.stats.record_activation();
        self.set_state(SessionState::Active).await;

        tracing::info!(
            endpoint = %self.config.endpoint,
            "OPC UA session activated"
        );

        Ok(())
    }

    /// Creates and activates a session in one call.
    pub async fn create_and_activate(&self) -> OpcUaResult<()> {
        self.create().await?;
        self.activate().await
    }

    /// Renews the session before it expires.
    pub async fn renew(&self) -> OpcUaResult<()> {
        let current_state = self.state().await;

        if !current_state.is_usable() {
            return Err(OpcUaError::session(SessionError::NotActivated));
        }

        self.set_state(SessionState::Renewing).await;

        // Simulate session renewal
        if let Some(ref mut info) = *self.session_info.write().await {
            info.touch();
        }

        self.stats.record_renewal();
        self.set_state(SessionState::Active).await;

        tracing::debug!(
            endpoint = %self.config.endpoint,
            "OPC UA session renewed"
        );

        Ok(())
    }

    /// Closes the session.
    pub async fn close(&self) -> OpcUaResult<()> {
        let current_state = self.state().await;

        if matches!(current_state, SessionState::Closed | SessionState::NotCreated) {
            return Ok(());
        }

        self.set_state(SessionState::Closing).await;

        // Clear session info
        *self.session_info.write().await = None;

        self.set_state(SessionState::Closed).await;

        tracing::info!(
            endpoint = %self.config.endpoint,
            "OPC UA session closed"
        );

        Ok(())
    }

    /// Records activity on the session.
    pub async fn touch(&self) {
        if let Some(ref mut info) = *self.session_info.write().await {
            info.touch();
        }
    }

    /// Checks if the session needs renewal.
    pub async fn needs_renewal(&self) -> bool {
        if let Some(ref info) = *self.session_info.read().await {
            // Renew when 75% of timeout has elapsed
            let threshold = Duration::from_millis(info.revised_timeout_ms * 3 / 4);
            info.idle_time() > threshold
        } else {
            false
        }
    }

    /// Ensures the session is active, creating/activating if needed.
    pub async fn ensure_active(&self) -> OpcUaResult<()> {
        let current_state = self.state().await;

        match current_state {
            SessionState::Active => {
                if self.needs_renewal().await {
                    self.renew().await?;
                }
                Ok(())
            }
            SessionState::NotCreated | SessionState::Closed | SessionState::Failed => {
                self.create_and_activate().await
            }
            SessionState::Created => self.activate().await,
            _ => {
                // Wait for transitional state to complete
                tokio::time::sleep(Duration::from_millis(100)).await;
                let new_state = self.state().await;
                if new_state.is_active() {
                    Ok(())
                } else {
                    Err(OpcUaError::session(SessionError::NotActivated))
                }
            }
        }
    }

    /// Sets the session state with notification.
    async fn set_state(&self, new_state: SessionState) {
        let old_state = {
            let mut state = self.state.write().await;
            let old = *state;
            *state = new_state;
            old
        };

        if old_state != new_state {
            tracing::trace!(
                old_state = %old_state,
                new_state = %new_state,
                "Session state changed"
            );

            // Notify callback
            if let Some(ref callback) = *self.on_state_change.lock().await {
                callback(old_state, new_state);
            }
        }
    }
}

impl fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionManager")
            .field("endpoint", &self.config.endpoint)
            .finish()
    }
}

// =============================================================================
// SessionStats
// =============================================================================

/// Statistics for session operations.
#[derive(Debug)]
pub struct SessionStats {
    /// Number of sessions created.
    creations: AtomicU64,

    /// Number of session activations.
    activations: AtomicU64,

    /// Number of session renewals.
    renewals: AtomicU64,

    /// Number of session failures.
    failures: AtomicU64,

    /// Number of reconnections.
    reconnections: AtomicU64,
}

impl SessionStats {
    /// Creates new session statistics.
    pub fn new() -> Self {
        Self {
            creations: AtomicU64::new(0),
            activations: AtomicU64::new(0),
            renewals: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            reconnections: AtomicU64::new(0),
        }
    }

    /// Records a session creation.
    pub fn record_creation(&self) {
        self.creations.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a session activation.
    pub fn record_activation(&self) {
        self.activations.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a session renewal.
    pub fn record_renewal(&self) {
        self.renewals.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a session failure.
    pub fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a reconnection.
    pub fn record_reconnection(&self) {
        self.reconnections.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the number of session creations.
    pub fn creations(&self) -> u64 {
        self.creations.load(Ordering::Relaxed)
    }

    /// Returns the number of session activations.
    pub fn activations(&self) -> u64 {
        self.activations.load(Ordering::Relaxed)
    }

    /// Returns the number of session renewals.
    pub fn renewals(&self) -> u64 {
        self.renewals.load(Ordering::Relaxed)
    }

    /// Returns the number of session failures.
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Returns the number of reconnections.
    pub fn reconnections(&self) -> u64 {
        self.reconnections.load(Ordering::Relaxed)
    }

    /// Resets all statistics.
    pub fn reset(&self) {
        self.creations.store(0, Ordering::Relaxed);
        self.activations.store(0, Ordering::Relaxed);
        self.renewals.store(0, Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
        self.reconnections.store(0, Ordering::Relaxed);
    }
}

impl Default for SessionStats {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state() {
        assert!(SessionState::Active.is_active());
        assert!(SessionState::Active.is_usable());
        assert!(SessionState::Renewing.is_usable());
        assert!(!SessionState::Created.is_active());

        assert!(SessionState::Creating.is_transitioning());
        assert!(SessionState::Activating.is_transitioning());
        assert!(!SessionState::Active.is_transitioning());

        assert!(SessionState::Failed.is_failed());
        assert!(!SessionState::Active.is_failed());
    }

    #[test]
    fn test_session_info() {
        let mut info = SessionInfo::new("session_123", "token_abc");

        assert!(!info.session_id.is_empty());
        assert!(!info.auth_token.is_empty());

        // Test touch updates last_activity
        std::thread::sleep(Duration::from_millis(10));
        let idle_before = info.idle_time();
        info.touch();
        let idle_after = info.idle_time();
        assert!(idle_after < idle_before);
    }

    #[tokio::test]
    async fn test_session_manager() {
        let config = OpcUaConfig::builder()
            .endpoint("opc.tcp://localhost:4840")
            .build()
            .unwrap();

        let manager = SessionManager::new(config);

        assert_eq!(manager.state().await, SessionState::NotCreated);

        manager.create().await.unwrap();
        assert_eq!(manager.state().await, SessionState::Created);

        manager.activate().await.unwrap();
        assert_eq!(manager.state().await, SessionState::Active);

        manager.close().await.unwrap();
        assert_eq!(manager.state().await, SessionState::Closed);
    }

    #[test]
    fn test_session_stats() {
        let stats = SessionStats::new();

        stats.record_creation();
        stats.record_activation();
        stats.record_renewal();
        stats.record_failure();

        assert_eq!(stats.creations(), 1);
        assert_eq!(stats.activations(), 1);
        assert_eq!(stats.renewals(), 1);
        assert_eq!(stats.failures(), 1);

        stats.reset();
        assert_eq!(stats.creations(), 0);
    }
}
