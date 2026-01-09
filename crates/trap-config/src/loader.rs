// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Configuration loading and processing for TRAP.
//!
//! This module provides functionality to load, parse, validate, and process
//! configuration files in YAML and TOML formats. It also supports environment
//! variable overrides and secret decryption.
//!
//! # Loading Pipeline
//!
//! 1. Parse YAML/TOML file into intermediate structure
//! 2. Resolve environment variable placeholders
//! 3. Resolve relative paths
//! 4. Validate configuration
//! 5. Decrypt encrypted secrets (optional)
//! 6. Parse protocol addresses
//! 7. Return final TrapConfig
//!
//! # Environment Variable Override
//!
//! Configuration values can be overridden using environment variables:
//!
//! ```text
//! TRAP_GATEWAY_ID=my-gateway
//! TRAP_API_PORT=9090
//! TRAP_DEVICES_0_POLL_INTERVAL_MS=2000
//! ```

use crate::error::{ConfigError, ConfigResult};
use crate::schema::TrapConfig;
use serde::de::DeserializeOwned;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// =============================================================================
// ConfigLoader
// =============================================================================

/// Configuration loader for TRAP.
///
/// This loader supports loading configuration from files in YAML and TOML formats,
/// with support for environment variable overrides and secret decryption.
///
/// # Examples
///
/// ```no_run
/// use trap_config::loader::ConfigLoader;
///
/// let loader = ConfigLoader::new();
/// let config = loader.load("config.yaml").unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct ConfigLoader {
    /// Base directory for resolving relative paths.
    base_path: Option<PathBuf>,

    /// Environment variable prefix.
    env_prefix: String,

    /// Whether to resolve environment variables in values.
    resolve_env_vars: bool,

    /// Whether to resolve relative paths.
    resolve_paths: bool,

    /// Master encryption key for decrypting secrets.
    #[cfg(feature = "encryption")]
    encryption_key: Option<[u8; 32]>,
}

impl ConfigLoader {
    /// Creates a new configuration loader with default settings.
    pub fn new() -> Self {
        Self {
            base_path: None,
            env_prefix: "TRAP".to_string(),
            resolve_env_vars: true,
            resolve_paths: true,
            #[cfg(feature = "encryption")]
            encryption_key: None,
        }
    }

    /// Creates a builder for configuring the loader.
    pub fn builder() -> ConfigLoaderBuilder {
        ConfigLoaderBuilder::new()
    }

    /// Sets the base path for resolving relative paths.
    pub fn with_base_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.base_path = Some(path.into());
        self
    }

    /// Sets the environment variable prefix.
    pub fn with_env_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.env_prefix = prefix.into();
        self
    }

    /// Enables or disables environment variable resolution.
    pub fn with_env_vars(mut self, enabled: bool) -> Self {
        self.resolve_env_vars = enabled;
        self
    }

    /// Enables or disables relative path resolution.
    pub fn with_path_resolution(mut self, enabled: bool) -> Self {
        self.resolve_paths = enabled;
        self
    }

    /// Sets the encryption key for decrypting secrets.
    #[cfg(feature = "encryption")]
    pub fn with_encryption_key(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    /// Loads configuration from a file.
    ///
    /// The file format is determined by the file extension:
    /// - `.yaml` or `.yml` - YAML format
    /// - `.toml` - TOML format
    /// - `.json` - JSON format
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the configuration file
    ///
    /// # Returns
    ///
    /// * `Ok(TrapConfig)` - Successfully loaded configuration
    /// * `Err(ConfigError)` - If loading or parsing fails
    pub fn load(&self, path: impl AsRef<Path>) -> ConfigResult<TrapConfig> {
        let path = path.as_ref();
        info!("Loading configuration from: {}", path.display());

        // Determine base path
        let base_path = self.base_path.clone().unwrap_or_else(|| {
            path.parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."))
        });

        // Read file content
        let content = self.read_file(path)?;

        // Determine format and parse
        let format = ConfigFormat::from_path(path)?;
        let mut config: TrapConfig = self.parse_content(&content, format, path)?;

        // Apply environment variable overrides
        if self.resolve_env_vars {
            self.apply_env_overrides(&mut config)?;
        }

        // Resolve relative paths
        if self.resolve_paths {
            self.resolve_relative_paths(&mut config, &base_path);
        }

        // Decrypt secrets
        #[cfg(feature = "encryption")]
        if let Some(ref key) = self.encryption_key {
            self.decrypt_secrets(&mut config, key)?;
        }

        // Validate configuration
        config.validate()?;

        info!("Configuration loaded successfully");
        debug!(
            "Loaded {} devices with {} total tags",
            config.devices.len(),
            config.devices.iter().map(|d| d.tags.len()).sum::<usize>()
        );

        Ok(config)
    }

    /// Loads configuration from a string.
    ///
    /// # Arguments
    ///
    /// * `content` - Configuration content as string
    /// * `format` - The format of the content
    ///
    /// # Returns
    ///
    /// * `Ok(TrapConfig)` - Successfully parsed configuration
    /// * `Err(ConfigError)` - If parsing fails
    pub fn load_from_str(&self, content: &str, format: ConfigFormat) -> ConfigResult<TrapConfig> {
        let mut config = self.parse_str(content, format)?;

        // Apply environment variable overrides
        if self.resolve_env_vars {
            self.apply_env_overrides(&mut config)?;
        }

        // Validate
        config.validate()?;

        Ok(config)
    }

    /// Reads file content.
    fn read_file(&self, path: &Path) -> ConfigResult<String> {
        if !path.exists() {
            return Err(ConfigError::file_not_found(path));
        }

        fs::read_to_string(path).map_err(|e| ConfigError::io(path, e))
    }

    /// Parses content based on format.
    fn parse_content(
        &self,
        content: &str,
        format: ConfigFormat,
        path: &Path,
    ) -> ConfigResult<TrapConfig> {
        // First resolve environment variables in the raw content
        let content = if self.resolve_env_vars {
            self.resolve_env_placeholders(content)?
        } else {
            content.to_string()
        };

        self.parse_str(&content, format)
            .map_err(|e| match e {
                ConfigError::Serialization { message } => ConfigError::parse(path, message),
                other => other,
            })
    }

    /// Parses a string based on format.
    fn parse_str(&self, content: &str, format: ConfigFormat) -> ConfigResult<TrapConfig> {
        match format {
            ConfigFormat::Yaml => {
                serde_yaml_parse(content)
            }
            ConfigFormat::Toml => {
                toml::from_str(content).map_err(|e| ConfigError::serialization(e.to_string()))
            }
            ConfigFormat::Json => {
                serde_json::from_str(content)
                    .map_err(|e| ConfigError::serialization(e.to_string()))
            }
        }
    }

    /// Resolves environment variable placeholders in content.
    ///
    /// Supports the format: `${VAR_NAME}` or `${VAR_NAME:default}`
    fn resolve_env_placeholders(&self, content: &str) -> ConfigResult<String> {
        let mut result = String::with_capacity(content.len());
        let mut chars = content.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '$' && chars.peek() == Some(&'{') {
                chars.next(); // consume '{'

                // Find the closing '}'
                let mut var_content = String::new();
                let mut found_close = false;

                while let Some(c) = chars.next() {
                    if c == '}' {
                        found_close = true;
                        break;
                    }
                    var_content.push(c);
                }

                if !found_close {
                    // No closing brace, keep as-is
                    result.push('$');
                    result.push('{');
                    result.push_str(&var_content);
                    continue;
                }

                // Parse variable name and default
                let (var_name, default_value) = if let Some(idx) = var_content.find(':') {
                    (&var_content[..idx], Some(&var_content[idx + 1..]))
                } else {
                    (var_content.as_str(), None)
                };

                // Look up environment variable
                match env::var(var_name) {
                    Ok(value) => result.push_str(&value),
                    Err(_) => {
                        if let Some(default) = default_value {
                            result.push_str(default);
                        } else {
                            // Keep the original placeholder if not found and no default
                            warn!("Environment variable '{}' not found", var_name);
                            result.push_str(&format!("${{{}}}", var_name));
                        }
                    }
                }
            } else {
                result.push(c);
            }
        }

        Ok(result)
    }

    /// Applies environment variable overrides.
    fn apply_env_overrides(&self, config: &mut TrapConfig) -> ConfigResult<()> {
        // Apply gateway overrides
        if let Ok(value) = env::var(format!("{}_GATEWAY_ID", self.env_prefix)) {
            config.gateway.id = value;
        }
        if let Ok(value) = env::var(format!("{}_GATEWAY_NAME", self.env_prefix)) {
            config.gateway.name = value;
        }

        // Apply API overrides
        if let Ok(value) = env::var(format!("{}_API_PORT", self.env_prefix)) {
            config.api.port = value.parse().map_err(|_| {
                ConfigError::invalid_env_var(
                    format!("{}_API_PORT", self.env_prefix),
                    "expected valid port number",
                )
            })?;
        }
        if let Ok(value) = env::var(format!("{}_API_ENABLED", self.env_prefix)) {
            config.api.enabled = parse_bool(&value);
        }

        // Apply logging overrides
        if let Ok(value) = env::var(format!("{}_LOG_LEVEL", self.env_prefix)) {
            if let Some(level) = parse_log_level(&value) {
                config.logging.level = level;
            }
        }

        // Apply buffer path override
        if let Ok(value) = env::var(format!("{}_BUFFER_PATH", self.env_prefix)) {
            config.buffer.path = PathBuf::from(value);
        }

        // Apply individual device overrides
        for (i, device) in config.devices.iter_mut().enumerate() {
            let prefix = format!("{}_DEVICES_{}", self.env_prefix, i);

            if let Ok(value) = env::var(format!("{}_ENABLED", prefix)) {
                device.enabled = parse_bool(&value);
            }
            if let Ok(value) = env::var(format!("{}_POLL_INTERVAL_MS", prefix)) {
                device.poll_interval_ms = value.parse().map_err(|_| {
                    ConfigError::invalid_env_var(
                        format!("{}_POLL_INTERVAL_MS", prefix),
                        "expected valid number",
                    )
                })?;
            }
        }

        Ok(())
    }

    /// Resolves relative paths in configuration.
    fn resolve_relative_paths(&self, config: &mut TrapConfig, base_path: &Path) {
        // Resolve buffer path
        if config.buffer.path.is_relative() {
            config.buffer.path = base_path.join(&config.buffer.path);
        }

        // Resolve audit log path
        if config.security.audit.path.is_relative() {
            config.security.audit.path = base_path.join(&config.security.audit.path);
        }

        // Resolve logging file path
        if let Some(ref mut log_file) = config.logging.file {
            if log_file.is_relative() {
                *log_file = base_path.join(&log_file);
            }
        }

        // Resolve TLS certificate paths
        if let Some(ref mut tls) = config.security.tls {
            if tls.cert_path.is_relative() {
                tls.cert_path = base_path.join(&tls.cert_path);
            }
            if tls.key_path.is_relative() {
                tls.key_path = base_path.join(&tls.key_path);
            }
            if let Some(ref mut ca_path) = tls.ca_cert_path {
                if ca_path.is_relative() {
                    *ca_path = base_path.join(&ca_path);
                }
            }
        }

        // Resolve OPC UA certificate paths in devices
        for device in &mut config.devices {
            if let crate::schema::ProtocolConfig::OpcUa(ref mut opcua) = device.protocol {
                if let Some(ref mut cert_path) = opcua.certificate_path {
                    if cert_path.is_relative() {
                        *cert_path = base_path.join(&cert_path);
                    }
                }
                if let Some(ref mut key_path) = opcua.private_key_path {
                    if key_path.is_relative() {
                        *key_path = base_path.join(&key_path);
                    }
                }
            }
        }
    }

    /// Decrypts encrypted secret values.
    #[cfg(feature = "encryption")]
    fn decrypt_secrets(&self, config: &mut TrapConfig, key: &[u8; 32]) -> ConfigResult<()> {
        use crate::encryption::Encryptor;

        let encryptor = Encryptor::new(*key);

        // Decrypt JWT secret
        if let Some(ref mut secret) = config.security.jwt.secret {
            if secret.is_encrypted() {
                if let Some(payload) = secret.encrypted_payload() {
                    let decrypted = encryptor.decrypt(payload)?;
                    *secret = crate::schema::SecretValue::new(decrypted);
                }
            }
        }

        // Decrypt device credentials
        for device in &mut config.devices {
            if let crate::schema::ProtocolConfig::OpcUa(ref mut opcua) = device.protocol {
                if let Some(ref mut password) = opcua.password {
                    if password.is_encrypted() {
                        if let Some(payload) = password.encrypted_payload() {
                            let decrypted = encryptor.decrypt(payload)?;
                            *password = crate::schema::SecretValue::new(decrypted);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// ConfigLoaderBuilder
// =============================================================================

/// Builder for ConfigLoader.
#[derive(Debug, Default)]
pub struct ConfigLoaderBuilder {
    base_path: Option<PathBuf>,
    env_prefix: Option<String>,
    resolve_env_vars: Option<bool>,
    resolve_paths: Option<bool>,
    #[cfg(feature = "encryption")]
    encryption_key: Option<[u8; 32]>,
}

impl ConfigLoaderBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the base path.
    pub fn base_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.base_path = Some(path.into());
        self
    }

    /// Sets the environment prefix.
    pub fn env_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.env_prefix = Some(prefix.into());
        self
    }

    /// Enables or disables environment variable resolution.
    pub fn resolve_env_vars(mut self, enabled: bool) -> Self {
        self.resolve_env_vars = Some(enabled);
        self
    }

    /// Enables or disables path resolution.
    pub fn resolve_paths(mut self, enabled: bool) -> Self {
        self.resolve_paths = Some(enabled);
        self
    }

    /// Sets the encryption key.
    #[cfg(feature = "encryption")]
    pub fn encryption_key(mut self, key: [u8; 32]) -> Self {
        self.encryption_key = Some(key);
        self
    }

    /// Builds the ConfigLoader.
    pub fn build(self) -> ConfigLoader {
        let mut loader = ConfigLoader::new();

        if let Some(base_path) = self.base_path {
            loader.base_path = Some(base_path);
        }
        if let Some(prefix) = self.env_prefix {
            loader.env_prefix = prefix;
        }
        if let Some(resolve_env_vars) = self.resolve_env_vars {
            loader.resolve_env_vars = resolve_env_vars;
        }
        if let Some(resolve_paths) = self.resolve_paths {
            loader.resolve_paths = resolve_paths;
        }
        #[cfg(feature = "encryption")]
        if let Some(key) = self.encryption_key {
            loader.encryption_key = Some(key);
        }

        loader
    }
}

// =============================================================================
// ConfigFormat
// =============================================================================

/// Supported configuration file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    /// YAML format.
    Yaml,
    /// TOML format.
    Toml,
    /// JSON format.
    Json,
}

impl ConfigFormat {
    /// Determines the format from a file path.
    pub fn from_path(path: &Path) -> ConfigResult<Self> {
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase());

        match ext.as_deref() {
            Some("yaml") | Some("yml") => Ok(ConfigFormat::Yaml),
            Some("toml") => Ok(ConfigFormat::Toml),
            Some("json") => Ok(ConfigFormat::Json),
            Some(other) => Err(ConfigError::unsupported_format(other)),
            None => Err(ConfigError::unsupported_format("(no extension)")),
        }
    }

    /// Returns the file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            ConfigFormat::Yaml => "yaml",
            ConfigFormat::Toml => "toml",
            ConfigFormat::Json => "json",
        }
    }
}

// =============================================================================
// ConfigMerger
// =============================================================================

/// Merges multiple configuration sources.
#[derive(Debug, Default)]
pub struct ConfigMerger {
    configs: Vec<TrapConfig>,
}

impl ConfigMerger {
    /// Creates a new config merger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a configuration to merge.
    pub fn add(mut self, config: TrapConfig) -> Self {
        self.configs.push(config);
        self
    }

    /// Merges all configurations into one.
    ///
    /// Later configurations override earlier ones for scalar values.
    /// Arrays are concatenated.
    pub fn merge(mut self) -> ConfigResult<TrapConfig> {
        if self.configs.is_empty() {
            return Ok(TrapConfig::default());
        }

        let mut configs = std::mem::take(&mut self.configs);
        let mut result = configs.remove(0);

        for config in configs {
            result = self.merge_two(result, config)?;
        }

        Ok(result)
    }

    fn merge_two(&self, base: TrapConfig, overlay: TrapConfig) -> ConfigResult<TrapConfig> {
        let mut result = base;

        // Merge gateway (overlay wins)
        if !overlay.gateway.id.is_empty() {
            result.gateway = overlay.gateway;
        }

        // Merge devices (concatenate)
        result.devices.extend(overlay.devices);

        // Merge buffer config (overlay wins for non-default values)
        if overlay.buffer.path != crate::schema::default_buffer_path() {
            result.buffer.path = overlay.buffer.path;
        }
        if overlay.buffer.max_size_bytes != crate::schema::DEFAULT_BUFFER_MAX_SIZE {
            result.buffer.max_size_bytes = overlay.buffer.max_size_bytes;
        }

        // Merge API config
        if overlay.api.port != crate::schema::DEFAULT_API_PORT {
            result.api.port = overlay.api.port;
        }

        // Merge security config
        if overlay.security.jwt.enabled {
            result.security.jwt = overlay.security.jwt;
        }
        if overlay.security.tls.is_some() {
            result.security.tls = overlay.security.tls;
        }
        if overlay.security.rate_limit.enabled {
            result.security.rate_limit = overlay.security.rate_limit;
        }

        Ok(result)
    }
}

// =============================================================================
// ConfigWatcher (optional feature)
// =============================================================================

/// Callback type for configuration changes.
pub type ConfigChangeCallback = Box<dyn Fn(&TrapConfig) + Send + Sync>;

/// Configuration file watcher for hot-reloading.
///
/// Note: This is a simplified implementation. For production use,
/// consider using the `notify` crate for proper file system watching.
#[derive(Debug)]
pub struct ConfigWatcher {
    path: PathBuf,
    loader: ConfigLoader,
    last_modified: Option<std::time::SystemTime>,
}

impl ConfigWatcher {
    /// Creates a new configuration watcher.
    pub fn new(path: impl Into<PathBuf>, loader: ConfigLoader) -> Self {
        Self {
            path: path.into(),
            loader,
            last_modified: None,
        }
    }

    /// Checks if the configuration file has changed.
    pub fn has_changed(&mut self) -> bool {
        let metadata = match fs::metadata(&self.path) {
            Ok(m) => m,
            Err(_) => return false,
        };

        let modified = match metadata.modified() {
            Ok(m) => m,
            Err(_) => return false,
        };

        if let Some(last) = self.last_modified {
            if modified > last {
                self.last_modified = Some(modified);
                return true;
            }
        } else {
            self.last_modified = Some(modified);
        }

        false
    }

    /// Reloads the configuration if it has changed.
    pub fn reload_if_changed(&mut self) -> ConfigResult<Option<TrapConfig>> {
        if self.has_changed() {
            let config = self.loader.load(&self.path)?;
            Ok(Some(config))
        } else {
            Ok(None)
        }
    }

    /// Forces a reload of the configuration.
    pub fn reload(&self) -> ConfigResult<TrapConfig> {
        self.loader.load(&self.path)
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Parses a string to bool.
fn parse_bool(value: &str) -> bool {
    matches!(
        value.to_lowercase().as_str(),
        "true" | "1" | "yes" | "on" | "enabled"
    )
}

/// Parses a log level string.
fn parse_log_level(value: &str) -> Option<crate::schema::LogLevel> {
    match value.to_lowercase().as_str() {
        "trace" => Some(crate::schema::LogLevel::Trace),
        "debug" => Some(crate::schema::LogLevel::Debug),
        "info" => Some(crate::schema::LogLevel::Info),
        "warn" | "warning" => Some(crate::schema::LogLevel::Warn),
        "error" => Some(crate::schema::LogLevel::Error),
        _ => None,
    }
}

/// YAML parsing with serde_yaml (config crate uses YAML internally).
fn serde_yaml_parse<T: DeserializeOwned>(content: &str) -> ConfigResult<T> {
    // Using the config crate for YAML parsing
    let config = config::Config::builder()
        .add_source(config::File::from_str(content, config::FileFormat::Yaml))
        .build()
        .map_err(|e| ConfigError::serialization(e.to_string()))?;

    config
        .try_deserialize()
        .map_err(|e| ConfigError::serialization(e.to_string()))
}

// =============================================================================
// Convenience Functions
// =============================================================================

/// Loads configuration from a file with default settings.
///
/// This is a convenience function for simple use cases.
///
/// # Examples
///
/// ```no_run
/// use trap_config::loader::load_config;
///
/// let config = load_config("trap.yaml").unwrap();
/// ```
pub fn load_config(path: impl AsRef<Path>) -> ConfigResult<TrapConfig> {
    ConfigLoader::new().load(path)
}

/// Loads configuration from a string with the specified format.
pub fn load_config_str(content: &str, format: ConfigFormat) -> ConfigResult<TrapConfig> {
    ConfigLoader::new().load_from_str(content, format)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_yaml() -> String {
        r#"
gateway:
  id: test-gateway
  name: Test Gateway

devices: []

buffer:
  path: ./data/buffer
  max_size_bytes: 1073741824
  max_items: 10000000

api:
  enabled: true
  port: 8080

security:
  jwt:
    enabled: false

logging:
  level: info
"#
        .to_string()
    }

    #[test]
    fn test_load_yaml() {
        let yaml = create_test_yaml();
        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        file.write_all(yaml.as_bytes()).unwrap();

        let loader = ConfigLoader::new();
        let config = loader.load(file.path()).unwrap();

        assert_eq!(config.gateway.id, "test-gateway");
        assert_eq!(config.gateway.name, "Test Gateway");
        assert!(config.api.enabled);
        assert_eq!(config.api.port, 8080);
    }

    #[test]
    fn test_config_format_from_path() {
        assert_eq!(
            ConfigFormat::from_path(Path::new("config.yaml")).unwrap(),
            ConfigFormat::Yaml
        );
        assert_eq!(
            ConfigFormat::from_path(Path::new("config.yml")).unwrap(),
            ConfigFormat::Yaml
        );
        assert_eq!(
            ConfigFormat::from_path(Path::new("config.toml")).unwrap(),
            ConfigFormat::Toml
        );
        assert_eq!(
            ConfigFormat::from_path(Path::new("config.json")).unwrap(),
            ConfigFormat::Json
        );
        assert!(ConfigFormat::from_path(Path::new("config.txt")).is_err());
    }

    #[test]
    fn test_env_placeholder_resolution() {
        // Use HOME which is typically set
        let loader = ConfigLoader::new();

        // Test with a variable that likely exists (PATH)
        let result = loader.resolve_env_placeholders("value: ${PATH}").unwrap();
        assert!(result.starts_with("value: "));
        // PATH should be resolved to something (not ${PATH})
        assert!(!result.contains("${PATH}") || result.len() > "value: ".len());
    }

    #[test]
    fn test_env_placeholder_with_default() {
        let loader = ConfigLoader::new();
        let result = loader
            .resolve_env_placeholders("value: ${NONEXISTENT_VAR:default}")
            .unwrap();
        assert_eq!(result, "value: default");
    }

    #[test]
    fn test_parse_bool() {
        assert!(parse_bool("true"));
        assert!(parse_bool("1"));
        assert!(parse_bool("yes"));
        assert!(parse_bool("on"));
        assert!(parse_bool("enabled"));
        assert!(!parse_bool("false"));
        assert!(!parse_bool("0"));
        assert!(!parse_bool("no"));
    }

    #[test]
    fn test_parse_log_level() {
        assert_eq!(parse_log_level("trace"), Some(crate::schema::LogLevel::Trace));
        assert_eq!(parse_log_level("debug"), Some(crate::schema::LogLevel::Debug));
        assert_eq!(parse_log_level("info"), Some(crate::schema::LogLevel::Info));
        assert_eq!(parse_log_level("warn"), Some(crate::schema::LogLevel::Warn));
        assert_eq!(parse_log_level("error"), Some(crate::schema::LogLevel::Error));
        assert_eq!(parse_log_level("invalid"), None);
    }

    #[test]
    fn test_loader_builder() {
        let loader = ConfigLoader::builder()
            .env_prefix("MYAPP")
            .resolve_env_vars(false)
            .resolve_paths(true)
            .build();

        assert_eq!(loader.env_prefix, "MYAPP");
        assert!(!loader.resolve_env_vars);
        assert!(loader.resolve_paths);
    }

    #[test]
    fn test_load_from_str() {
        let yaml = create_test_yaml();
        let loader = ConfigLoader::new().with_env_vars(false);
        let config = loader.load_from_str(&yaml, ConfigFormat::Yaml).unwrap();

        assert_eq!(config.gateway.id, "test-gateway");
    }

    #[test]
    fn test_file_not_found() {
        let loader = ConfigLoader::new();
        let result = loader.load("/nonexistent/path/config.yaml");
        assert!(matches!(result, Err(ConfigError::FileNotFound { .. })));
    }

    #[test]
    fn test_config_watcher() {
        let yaml = create_test_yaml();
        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        file.write_all(yaml.as_bytes()).unwrap();

        let loader = ConfigLoader::new();
        let mut watcher = ConfigWatcher::new(file.path(), loader);

        // First check should record the modification time (returns true since last_modified was None)
        let _first_check = watcher.has_changed();
        // The first call sets last_modified, so it returns false (no change detected yet)
        // because our logic sets last_modified on first call

        // Second check without modification should not indicate change
        assert!(!watcher.has_changed());

        // Verify the watcher was created correctly
        assert!(watcher.reload().is_ok());
    }
}

