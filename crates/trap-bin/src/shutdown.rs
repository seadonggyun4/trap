// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Graceful shutdown coordination.
//!
//! This module provides utilities for coordinating graceful shutdown across
//! multiple components of the gateway. It handles OS signals (SIGTERM, SIGINT)
//! and allows components to subscribe to shutdown notifications.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::sync::broadcast;
use tracing::{info, warn};

// =============================================================================
// ShutdownCoordinator
// =============================================================================

/// Coordinates graceful shutdown across multiple components.
///
/// The coordinator provides:
/// - A broadcast channel for notifying all components of shutdown
/// - Signal handling for SIGTERM and SIGINT (Unix) or Ctrl+C (Windows)
/// - A future that resolves when shutdown is initiated
///
/// # Example
///
/// ```ignore
/// use trap_bin::shutdown::ShutdownCoordinator;
///
/// let coordinator = ShutdownCoordinator::new();
///
/// // Subscribe to shutdown notifications
/// let mut rx = coordinator.subscribe();
///
/// // In a task, wait for shutdown
/// tokio::spawn(async move {
///     rx.recv().await.ok();
///     println!("Shutdown received!");
/// });
///
/// // Wait for shutdown signal
/// coordinator.wait_for_shutdown().await;
/// ```
#[derive(Clone)]
pub struct ShutdownCoordinator {
    sender: broadcast::Sender<()>,
    shutdown_initiated: Arc<AtomicBool>,
}

impl ShutdownCoordinator {
    /// Creates a new shutdown coordinator.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(1);
        Self {
            sender,
            shutdown_initiated: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Subscribes to shutdown notifications.
    ///
    /// Returns a receiver that will receive a message when shutdown is initiated.
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.sender.subscribe()
    }

    /// Creates a future that resolves when shutdown is signaled.
    ///
    /// This is useful for passing to servers that accept a shutdown future.
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        ShutdownSignal {
            receiver: self.sender.subscribe(),
            shutdown_initiated: self.shutdown_initiated.clone(),
        }
    }

    /// Initiates shutdown.
    ///
    /// This notifies all subscribers that shutdown has been initiated.
    pub fn initiate_shutdown(&self) {
        if self
            .shutdown_initiated
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            info!("Shutdown initiated");
            let _ = self.sender.send(());
        }
    }

    /// Returns true if shutdown has been initiated.
    pub fn is_shutdown_initiated(&self) -> bool {
        self.shutdown_initiated.load(Ordering::SeqCst)
    }

    /// Waits for a shutdown signal (OS signal or manual initiation).
    ///
    /// This method sets up signal handlers and blocks until a shutdown
    /// signal is received.
    pub async fn wait_for_shutdown(&self) {
        let shutdown_initiated = self.shutdown_initiated.clone();
        let sender = self.sender.clone();

        // Already shutdown?
        if shutdown_initiated.load(Ordering::SeqCst) {
            return;
        }

        // Wait for OS signal
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};

            let mut sigterm = signal(SignalKind::terminate())
                .expect("Failed to register SIGTERM handler");
            let mut sigint = signal(SignalKind::interrupt())
                .expect("Failed to register SIGINT handler");
            let mut sigquit = signal(SignalKind::quit())
                .expect("Failed to register SIGQUIT handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT");
                }
                _ = sigquit.recv() => {
                    info!("Received SIGQUIT");
                }
            }
        }

        #[cfg(windows)]
        {
            use tokio::signal::ctrl_c;

            ctrl_c().await.expect("Failed to register Ctrl+C handler");
            info!("Received Ctrl+C");
        }

        // Mark as shutdown and notify subscribers
        if shutdown_initiated
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let _ = sender.send(());
        }
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// ShutdownSignal
// =============================================================================

/// A future that resolves when shutdown is signaled.
///
/// This implements `Future` so it can be used with APIs that expect
/// a shutdown future (like axum's `with_graceful_shutdown`).
pub struct ShutdownSignal {
    receiver: broadcast::Receiver<()>,
    shutdown_initiated: Arc<AtomicBool>,
}

impl ShutdownSignal {
    /// Waits for the shutdown signal.
    pub async fn wait(mut self) {
        // Check if already shutdown
        if self.shutdown_initiated.load(Ordering::SeqCst) {
            return;
        }

        // Wait for the signal
        let _ = self.receiver.recv().await;
    }
}

impl Future for ShutdownSignal {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Check if already shutdown
        if self.shutdown_initiated.load(Ordering::SeqCst) {
            return Poll::Ready(());
        }

        // Use a boxed future for polling
        let this = self.get_mut();
        let mut recv_fut = Box::pin(this.receiver.recv());

        match recv_fut.as_mut().poll(cx) {
            Poll::Ready(_) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
}

// =============================================================================
// ShutdownGuard
// =============================================================================

/// A guard that triggers shutdown when dropped.
///
/// This is useful for ensuring shutdown is initiated if a task panics
/// or returns unexpectedly.
pub struct ShutdownGuard {
    coordinator: ShutdownCoordinator,
    trigger_on_drop: bool,
}

impl ShutdownGuard {
    /// Creates a new shutdown guard.
    pub fn new(coordinator: ShutdownCoordinator) -> Self {
        Self {
            coordinator,
            trigger_on_drop: true,
        }
    }

    /// Disarms the guard so it won't trigger shutdown on drop.
    pub fn disarm(mut self) {
        self.trigger_on_drop = false;
    }
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        if self.trigger_on_drop {
            warn!("ShutdownGuard dropped, initiating shutdown");
            self.coordinator.initiate_shutdown();
        }
    }
}

// =============================================================================
// ShutdownToken
// =============================================================================

/// A token that can be used to check if shutdown has been requested.
///
/// This is a lightweight handle that can be cloned and passed to tasks
/// that need to periodically check for shutdown.
#[derive(Clone)]
pub struct ShutdownToken {
    shutdown_initiated: Arc<AtomicBool>,
}

impl ShutdownToken {
    /// Creates a new shutdown token from a coordinator.
    pub fn from_coordinator(coordinator: &ShutdownCoordinator) -> Self {
        Self {
            shutdown_initiated: coordinator.shutdown_initiated.clone(),
        }
    }

    /// Returns true if shutdown has been requested.
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_initiated.load(Ordering::SeqCst)
    }
}

// =============================================================================
// Utility Functions
// =============================================================================

/// Creates a shutdown coordinator and waits for shutdown signals.
///
/// This is a convenience function for simple applications that just need
/// to wait for Ctrl+C or termination signals.
pub async fn wait_for_shutdown_signals() {
    let coordinator = ShutdownCoordinator::new();
    coordinator.wait_for_shutdown().await;
}

/// Runs a future with graceful shutdown support.
///
/// The provided future will be cancelled when a shutdown signal is received.
pub async fn run_with_shutdown<F, T>(future: F) -> Option<T>
where
    F: Future<Output = T>,
{
    let coordinator = ShutdownCoordinator::new();
    let shutdown_signal = coordinator.shutdown_signal();

    tokio::pin!(future);
    tokio::pin!(shutdown_signal);

    tokio::select! {
        result = &mut future => Some(result),
        _ = &mut shutdown_signal => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_shutdown_coordinator() {
        let coordinator = ShutdownCoordinator::new();
        let mut rx = coordinator.subscribe();

        assert!(!coordinator.is_shutdown_initiated());

        coordinator.initiate_shutdown();

        assert!(coordinator.is_shutdown_initiated());
        assert!(rx.recv().await.is_ok());
    }

    #[tokio::test]
    async fn test_shutdown_signal() {
        let coordinator = ShutdownCoordinator::new();
        let signal = coordinator.shutdown_signal();

        // Initiate shutdown after a short delay
        let coordinator_clone = coordinator.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            coordinator_clone.initiate_shutdown();
        });

        // Wait for shutdown signal
        tokio::time::timeout(Duration::from_secs(1), signal)
            .await
            .expect("Shutdown signal should resolve");
    }

    #[tokio::test]
    async fn test_shutdown_token() {
        let coordinator = ShutdownCoordinator::new();
        let token = ShutdownToken::from_coordinator(&coordinator);

        assert!(!token.is_shutdown_requested());

        coordinator.initiate_shutdown();

        assert!(token.is_shutdown_requested());
    }

    #[tokio::test]
    async fn test_shutdown_guard_triggers_on_drop() {
        let coordinator = ShutdownCoordinator::new();

        {
            let _guard = ShutdownGuard::new(coordinator.clone());
            // Guard is dropped here
        }

        assert!(coordinator.is_shutdown_initiated());
    }

    #[tokio::test]
    async fn test_shutdown_guard_disarm() {
        let coordinator = ShutdownCoordinator::new();

        {
            let guard = ShutdownGuard::new(coordinator.clone());
            guard.disarm();
            // Guard is dropped here but was disarmed
        }

        assert!(!coordinator.is_shutdown_initiated());
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let coordinator = ShutdownCoordinator::new();
        let mut rx1 = coordinator.subscribe();
        let mut rx2 = coordinator.subscribe();

        coordinator.initiate_shutdown();

        assert!(rx1.recv().await.is_ok());
        assert!(rx2.recv().await.is_ok());
    }

    #[tokio::test]
    async fn test_double_shutdown() {
        let coordinator = ShutdownCoordinator::new();

        coordinator.initiate_shutdown();
        coordinator.initiate_shutdown(); // Should be idempotent

        assert!(coordinator.is_shutdown_initiated());
    }
}
