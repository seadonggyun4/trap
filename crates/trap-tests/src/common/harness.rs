// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! # Test Harness
//!
//! High-level test harness for running integration tests with proper setup and teardown.
//!
//! ## Design Principles
//!
//! - Automatic resource management
//! - Consistent test environment setup
//! - Parallel test isolation
//! - Easy cleanup on test completion or failure

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;
use tempfile::TempDir;

use trap_core::{
    bus::{DataBus, CommandBus, CommandReceiver},
    driver::DriverRegistry,
};

// =============================================================================
// Test Harness
// =============================================================================

/// Configuration for the test harness.
#[derive(Debug, Clone)]
pub struct TestHarnessConfig {
    /// Name of the test (used for logging and temp directories).
    pub test_name: String,

    /// Timeout for the entire test.
    pub timeout: Duration,

    /// Data bus capacity.
    pub data_bus_capacity: usize,

    /// Command bus capacity.
    pub command_bus_capacity: usize,

    /// Whether to create a temp directory for the test.
    pub create_temp_dir: bool,

    /// Whether to enable tracing for the test.
    pub enable_tracing: bool,
}

impl Default for TestHarnessConfig {
    fn default() -> Self {
        Self {
            test_name: "unknown_test".to_string(),
            timeout: Duration::from_secs(30),
            data_bus_capacity: 1024,
            command_bus_capacity: 256,
            create_temp_dir: true,
            enable_tracing: false,
        }
    }
}

impl TestHarnessConfig {
    /// Create a new config with a test name.
    pub fn new(test_name: impl Into<String>) -> Self {
        Self {
            test_name: test_name.into(),
            ..Default::default()
        }
    }

    /// Set the timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the data bus capacity.
    pub fn data_bus_capacity(mut self, capacity: usize) -> Self {
        self.data_bus_capacity = capacity;
        self
    }

    /// Set the command bus capacity.
    pub fn command_bus_capacity(mut self, capacity: usize) -> Self {
        self.command_bus_capacity = capacity;
        self
    }

    /// Disable temp directory creation.
    pub fn no_temp_dir(mut self) -> Self {
        self.create_temp_dir = false;
        self
    }

    /// Enable tracing.
    pub fn with_tracing(mut self) -> Self {
        self.enable_tracing = true;
        self
    }
}

/// Resources provided by the test harness.
pub struct TestResources {
    /// Configuration used to create this harness.
    pub config: TestHarnessConfig,

    /// Data bus for the test.
    pub data_bus: Arc<DataBus>,

    /// Command bus for the test.
    pub command_bus: Arc<CommandBus>,

    /// Command receiver (owned, can only be taken once).
    command_receiver: Option<CommandReceiver>,

    /// Driver registry for the test.
    pub driver_registry: Arc<DriverRegistry>,

    /// Temporary directory (if created).
    temp_dir: Option<TempDir>,

    /// Shutdown signal sender.
    shutdown_tx: broadcast::Sender<()>,

    /// Shutdown signal receiver.
    pub shutdown_rx: broadcast::Receiver<()>,
}

impl TestResources {
    /// Get the temp directory path.
    pub fn temp_path(&self) -> Option<PathBuf> {
        self.temp_dir.as_ref().map(|d| d.path().to_path_buf())
    }

    /// Take the command receiver (can only be called once).
    pub fn take_command_receiver(&mut self) -> Option<CommandReceiver> {
        self.command_receiver.take()
    }

    /// Send a shutdown signal.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    /// Create a new shutdown receiver.
    pub fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Create a file path in the temp directory.
    pub fn temp_file(&self, name: &str) -> Option<PathBuf> {
        self.temp_dir.as_ref().map(|d| d.path().join(name))
    }

    /// Create a subdirectory in the temp directory.
    pub fn temp_subdir(&self, name: &str) -> Option<PathBuf> {
        self.temp_dir.as_ref().map(|d| {
            let path = d.path().join(name);
            std::fs::create_dir_all(&path).expect("Failed to create temp subdirectory");
            path
        })
    }
}

/// The main test harness.
pub struct TestHarness {
    config: TestHarnessConfig,
}

impl TestHarness {
    /// Create a new test harness with a config.
    pub fn new(config: TestHarnessConfig) -> Self {
        Self { config }
    }

    /// Create a new test harness with a test name.
    pub fn with_name(test_name: impl Into<String>) -> Self {
        Self::new(TestHarnessConfig::new(test_name))
    }

    /// Set up the test environment.
    pub fn setup(self) -> TestResources {
        // Initialize tracing if requested
        if self.config.enable_tracing {
            let _ = tracing_subscriber::fmt()
                .with_test_writer()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
                )
                .try_init();
        }

        // Create temp directory if requested
        let temp_dir = if self.config.create_temp_dir {
            Some(
                tempfile::Builder::new()
                    .prefix(&format!("trap_test_{}_", self.config.test_name))
                    .tempdir()
                    .expect("Failed to create temp directory"),
            )
        } else {
            None
        };

        // Create message buses
        let data_bus = Arc::new(DataBus::new(self.config.data_bus_capacity));
        let (command_bus, command_receiver) = CommandBus::channel(self.config.command_bus_capacity);
        let command_bus = Arc::new(command_bus);

        // Create driver registry
        let driver_registry = Arc::new(DriverRegistry::new());

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        TestResources {
            config: self.config,
            data_bus,
            command_bus,
            command_receiver: Some(command_receiver),
            driver_registry,
            temp_dir,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Run a test with automatic setup and teardown.
    pub async fn run<F, Fut>(self, test_fn: F)
    where
        F: FnOnce(TestResources) -> Fut,
        Fut: Future<Output = ()>,
    {
        let timeout = self.config.timeout;
        let resources = self.setup();

        // Run the test with a timeout
        let result = tokio::time::timeout(timeout, test_fn(resources)).await;

        match result {
            Ok(()) => {
                // Test completed successfully
            }
            Err(_) => {
                panic!("Test timed out after {:?}", timeout);
            }
        }
    }

    /// Run a test that returns a result.
    pub async fn run_result<F, Fut, T, E>(self, test_fn: F) -> Result<T, E>
    where
        F: FnOnce(TestResources) -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let timeout = self.config.timeout;
        let resources = self.setup();

        // Run the test with a timeout
        let result = tokio::time::timeout(timeout, test_fn(resources)).await;

        match result {
            Ok(inner_result) => inner_result,
            Err(_) => {
                panic!("Test timed out after {:?}", timeout);
            }
        }
    }
}

// =============================================================================
// Test Scenario Runner
// =============================================================================

/// A scenario-based test runner for more complex integration tests.
pub struct ScenarioRunner<S> {
    /// The scenario state.
    state: S,

    /// Steps to execute.
    steps: Vec<Box<dyn ScenarioStep<S>>>,
}

/// A step in a test scenario.
#[async_trait::async_trait]
pub trait ScenarioStep<S>: Send + Sync {
    /// Execute this step.
    async fn execute(&self, state: &mut S) -> Result<(), String>;

    /// Get the step name for logging.
    fn name(&self) -> &str;
}

impl<S: Send + 'static> ScenarioRunner<S> {
    /// Create a new scenario runner with initial state.
    pub fn new(initial_state: S) -> Self {
        Self {
            state: initial_state,
            steps: Vec::new(),
        }
    }

    /// Add a step to the scenario.
    pub fn add_step<Step: ScenarioStep<S> + 'static>(mut self, step: Step) -> Self {
        self.steps.push(Box::new(step));
        self
    }

    /// Add a closure step.
    pub fn then<F, Fut>(self, name: &'static str, step_fn: F) -> Self
    where
        F: Fn(&mut S) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), String>> + Send + 'static,
    {
        self.add_step(ClosureStep { name, step_fn })
    }

    /// Run all steps in the scenario.
    pub async fn run(mut self) -> Result<S, (String, String)> {
        for (i, step) in self.steps.iter().enumerate() {
            tracing::info!("Running step {}: {}", i + 1, step.name());

            if let Err(e) = step.execute(&mut self.state).await {
                return Err((step.name().to_string(), e));
            }
        }

        Ok(self.state)
    }
}

/// A step implemented as a closure.
struct ClosureStep<F> {
    name: &'static str,
    step_fn: F,
}

#[async_trait::async_trait]
impl<S, F, Fut> ScenarioStep<S> for ClosureStep<F>
where
    S: Send + 'static,
    F: Fn(&mut S) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), String>> + Send,
{
    async fn execute(&self, state: &mut S) -> Result<(), String> {
        (self.step_fn)(state).await
    }

    fn name(&self) -> &str {
        self.name
    }
}

// =============================================================================
// Concurrent Test Helper
// =============================================================================

/// Helper for running concurrent tests.
pub struct ConcurrentTestHelper {
    /// Number of concurrent tasks.
    task_count: usize,

    /// Timeout per task.
    task_timeout: Duration,
}

impl ConcurrentTestHelper {
    /// Create a new helper.
    pub fn new(task_count: usize) -> Self {
        Self {
            task_count,
            task_timeout: Duration::from_secs(10),
        }
    }

    /// Set the task timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.task_timeout = timeout;
        self
    }

    /// Run a function concurrently and collect results.
    pub async fn run<F, Fut, T>(&self, task_fn: F) -> Vec<Result<T, String>>
    where
        F: Fn(usize) -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let mut handles = Vec::with_capacity(self.task_count);

        for i in 0..self.task_count {
            let task_fn = task_fn.clone();
            let timeout = self.task_timeout;

            handles.push(tokio::spawn(async move {
                match tokio::time::timeout(timeout, task_fn(i)).await {
                    Ok(result) => Ok(result),
                    Err(_) => Err(format!("Task {} timed out", i)),
                }
            }));
        }

        let mut results = Vec::with_capacity(self.task_count);
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(format!("Task panicked: {}", e))),
            }
        }

        results
    }

    /// Run a function concurrently and assert all succeed.
    pub async fn run_all_succeed<F, Fut, T>(&self, task_fn: F) -> Vec<T>
    where
        F: Fn(usize) -> Fut + Send + Sync + Clone + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let results = self.run(task_fn).await;
        results
            .into_iter()
            .enumerate()
            .map(|(i, r)| r.unwrap_or_else(|e| panic!("Task {} failed: {}", i, e)))
            .collect()
    }
}

// =============================================================================
// Test Assertions Wrapper
// =============================================================================

/// Wraps async assertions with better error messages.
pub async fn assert_async<F, Fut>(
    description: &str,
    timeout: Duration,
    assertion: F,
) -> Result<(), String>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = bool>,
{
    match tokio::time::timeout(timeout, assertion()).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(format!("Assertion failed: {}", description)),
        Err(_) => Err(format!(
            "Assertion timed out after {:?}: {}",
            timeout, description
        )),
    }
}

/// Run a test with automatic cleanup.
#[macro_export]
macro_rules! run_test {
    ($test_name:expr, $test_body:expr) => {{
        use $crate::common::harness::{TestHarness, TestHarnessConfig};

        let harness = TestHarness::new(TestHarnessConfig::new($test_name));
        harness.run($test_body).await
    }};
}
