// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Certificate manager - main facade for certificate operations.
//!
//! The `CertificateManager` provides a unified interface for:
//! - Generating self-signed certificates
//! - Storing and retrieving certificates
//! - Validating certificates
//! - Managing trust relationships

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;

use super::config::{CertificateConfig, StoreConfig};
use super::error::{CertificateError, CertificateResult, StorageError};
use super::generator::{CertificateGenerator, CertificatePaths, SelfSignedGenerator};
use super::store::{CertificateStore, FileSystemStore, MemoryStore, StoredCertificate, TrustStatus};
use super::validator::{CertificateValidator, ValidationPolicy, ValidationResult, X509Validator};

// =============================================================================
// CertificateManager
// =============================================================================

/// Main facade for certificate operations.
///
/// The `CertificateManager` combines generation, storage, and validation
/// functionality into a single, easy-to-use interface.
///
/// # Example
///
/// ```rust,ignore
/// use trap_opcua::certificate::{CertificateManager, CertificateConfig};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let manager = CertificateManager::new().await?;
///
///     // Generate a self-signed certificate
///     let config = CertificateConfig::builder()
///         .common_name("My OPC UA Client")
///         .application_uri("urn:myapp:client")
///         .validity_days(365)
///         .build()?;
///
///     let paths = manager.generate_self_signed(&config).await?;
///     println!("Certificate saved to: {:?}", paths.certificate_path);
///
///     Ok(())
/// }
/// ```
pub struct CertificateManager {
    /// Certificate store.
    store: Arc<dyn CertificateStore>,
    /// Certificate validator.
    validator: Arc<dyn CertificateValidator>,
    /// Self-signed generator.
    self_signed_generator: Arc<dyn CertificateGenerator>,
    /// CA-signed generator (optional).
    ca_generator: Arc<RwLock<Option<Arc<dyn CertificateGenerator>>>>,
    /// Manager configuration.
    config: ManagerConfig,
}

/// Manager configuration.
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// Store configuration.
    pub store_config: StoreConfig,
    /// Validation policy.
    pub validation_policy: ValidationPolicy,
    /// Auto-generate own certificate if missing.
    pub auto_generate: bool,
    /// Default certificate configuration for auto-generation.
    pub default_cert_config: CertificateConfig,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        Self {
            store_config: StoreConfig::default(),
            validation_policy: ValidationPolicy::opcua(),
            auto_generate: true,
            default_cert_config: CertificateConfig::default(),
        }
    }
}

impl CertificateManager {
    /// Creates a new certificate manager with default configuration.
    pub async fn new() -> CertificateResult<Self> {
        Self::with_config(ManagerConfig::default()).await
    }

    /// Creates a new certificate manager with custom configuration.
    pub async fn with_config(config: ManagerConfig) -> CertificateResult<Self> {
        let store: Arc<dyn CertificateStore> =
            Arc::new(FileSystemStore::with_config(config.store_config.clone()));
        store.initialize().await?;

        let validator: Arc<dyn CertificateValidator> =
            Arc::new(X509Validator::with_policy(store.clone(), config.validation_policy.clone()));

        let self_signed_generator: Arc<dyn CertificateGenerator> =
            Arc::new(SelfSignedGenerator::new());

        Ok(Self {
            store,
            validator,
            self_signed_generator,
            ca_generator: Arc::new(RwLock::new(None)),
            config,
        })
    }

    /// Creates a certificate manager with in-memory store (for testing).
    pub async fn in_memory() -> CertificateResult<Self> {
        let store: Arc<dyn CertificateStore> = Arc::new(MemoryStore::new());
        store.initialize().await?;

        let validator: Arc<dyn CertificateValidator> =
            Arc::new(X509Validator::new(store.clone()));

        let self_signed_generator: Arc<dyn CertificateGenerator> =
            Arc::new(SelfSignedGenerator::new());

        Ok(Self {
            store,
            validator,
            self_signed_generator,
            ca_generator: Arc::new(RwLock::new(None)),
            config: ManagerConfig::default(),
        })
    }

    /// Creates a certificate manager builder.
    pub fn builder() -> CertificateManagerBuilder {
        CertificateManagerBuilder::new()
    }

    // =========================================================================
    // Generation
    // =========================================================================

    /// Generates a self-signed certificate.
    pub async fn generate_self_signed(
        &self,
        config: &CertificateConfig,
    ) -> CertificateResult<CertificatePaths> {
        tracing::info!(
            common_name = %config.subject.common_name,
            application_uri = %config.application_uri,
            validity_days = config.validity_days,
            "Generating self-signed certificate"
        );

        let paths = self
            .self_signed_generator
            .generate_and_save(config)
            .await?;

        // Add to store as trusted (own certificate)
        let cert_bytes = tokio::fs::read(&paths.certificate_path).await.map_err(|e| {
            CertificateError::storage(StorageError::read_failed_with(
                paths.certificate_path.clone(),
                "Failed to read generated certificate",
                e,
            ))
        })?;

        let key_bytes = tokio::fs::read(&paths.private_key_path).await.ok();

        let stored = self
            .store
            .add(
                &cert_bytes,
                key_bytes.as_deref(),
                TrustStatus::Trusted,
            )
            .await?;

        // Set as own certificate
        self.store.set_own_certificate(&stored.thumbprint).await?;

        tracing::info!(
            thumbprint = %paths.thumbprint,
            certificate = %paths.certificate_path.display(),
            private_key = %paths.private_key_path.display(),
            "Generated and stored self-signed certificate"
        );

        Ok(paths)
    }

    /// Generates a self-signed certificate with quick defaults.
    pub async fn generate_quick(
        &self,
        common_name: &str,
        application_uri: &str,
    ) -> CertificateResult<CertificatePaths> {
        let config = CertificateConfig::builder()
            .common_name(common_name)
            .application_uri(application_uri)
            .build()?;

        self.generate_self_signed(&config).await
    }

    /// Ensures an own certificate exists, generating one if necessary.
    pub async fn ensure_own_certificate(&self) -> CertificateResult<StoredCertificate> {
        if let Some(own) = self.store.get_own_certificate().await? {
            // Check if still valid
            if own.is_valid() {
                tracing::debug!(
                    thumbprint = %own.thumbprint,
                    days_remaining = own.days_until_expiration(),
                    "Using existing own certificate"
                );
                return Ok(own);
            } else {
                tracing::warn!(
                    thumbprint = %own.thumbprint,
                    "Own certificate expired, generating new one"
                );
            }
        }

        if !self.config.auto_generate {
            return Err(CertificateError::storage(StorageError::file_not_found(
                "own certificate",
            )));
        }

        // Generate new certificate
        let paths = self
            .generate_self_signed(&self.config.default_cert_config)
            .await?;

        self.store
            .get(&paths.thumbprint)
            .await?
            .ok_or_else(|| CertificateError::storage(StorageError::file_not_found(paths.thumbprint)))
    }

    // =========================================================================
    // Storage
    // =========================================================================

    /// Returns the certificate store.
    pub fn store(&self) -> &Arc<dyn CertificateStore> {
        &self.store
    }

    /// Gets a certificate by thumbprint.
    pub async fn get(&self, thumbprint: &str) -> CertificateResult<Option<StoredCertificate>> {
        self.store.get(thumbprint).await
    }

    /// Gets the own certificate.
    pub async fn get_own_certificate(&self) -> CertificateResult<Option<StoredCertificate>> {
        self.store.get_own_certificate().await
    }

    /// Gets the own certificate bytes.
    pub async fn get_own_certificate_bytes(&self) -> CertificateResult<Option<Vec<u8>>> {
        match self.store.get_own_certificate().await? {
            Some(stored) => Ok(Some(self.store.get_certificate_bytes(&stored.thumbprint).await?)),
            None => Ok(None),
        }
    }

    /// Gets the own private key bytes.
    pub async fn get_own_private_key_bytes(&self) -> CertificateResult<Option<Vec<u8>>> {
        match self.store.get_own_certificate().await? {
            Some(stored) => self.store.get_private_key_bytes(&stored.thumbprint).await,
            None => Ok(None),
        }
    }

    /// Lists all certificates.
    pub async fn list(&self) -> CertificateResult<Vec<StoredCertificate>> {
        self.store.list().await
    }

    /// Lists trusted certificates.
    pub async fn list_trusted(&self) -> CertificateResult<Vec<StoredCertificate>> {
        self.store.list_by_status(TrustStatus::Trusted).await
    }

    /// Lists rejected certificates.
    pub async fn list_rejected(&self) -> CertificateResult<Vec<StoredCertificate>> {
        self.store.list_by_status(TrustStatus::Rejected).await
    }

    /// Lists certificates expiring soon.
    pub async fn list_expiring(&self, days: i64) -> CertificateResult<Vec<StoredCertificate>> {
        self.store.get_expiring(days).await
    }

    /// Adds a certificate to the store.
    pub async fn add_certificate(
        &self,
        cert_der: &[u8],
        trust_status: TrustStatus,
    ) -> CertificateResult<StoredCertificate> {
        self.store.add(cert_der, None, trust_status).await
    }

    /// Adds a certificate from a file.
    pub async fn add_certificate_from_file(
        &self,
        path: impl Into<PathBuf>,
        trust_status: TrustStatus,
    ) -> CertificateResult<StoredCertificate> {
        let path = path.into();
        let cert_der = tokio::fs::read(&path).await.map_err(|e| {
            CertificateError::storage(StorageError::read_failed_with(
                path,
                "Failed to read certificate file",
                e,
            ))
        })?;

        self.store.add(&cert_der, None, trust_status).await
    }

    /// Removes a certificate from the store.
    pub async fn remove(&self, thumbprint: &str) -> CertificateResult<bool> {
        self.store.remove(thumbprint).await
    }

    // =========================================================================
    // Validation
    // =========================================================================

    /// Returns the certificate validator.
    pub fn validator(&self) -> &Arc<dyn CertificateValidator> {
        &self.validator
    }

    /// Validates a certificate.
    pub async fn validate(&self, cert_der: &[u8]) -> CertificateResult<ValidationResult> {
        self.validator.validate(cert_der).await
    }

    /// Validates a certificate with expected application URI.
    pub async fn validate_with_uri(
        &self,
        cert_der: &[u8],
        expected_uri: &str,
    ) -> CertificateResult<ValidationResult> {
        self.validator.validate_with_uri(cert_der, expected_uri).await
    }

    /// Validates a certificate and adds it to the store if valid.
    pub async fn validate_and_store(
        &self,
        cert_der: &[u8],
    ) -> CertificateResult<(ValidationResult, StoredCertificate)> {
        let result = self.validator.validate(cert_der).await?;

        let trust_status = if result.is_valid && result.is_trusted {
            TrustStatus::Trusted
        } else if result.is_valid {
            TrustStatus::Pending
        } else {
            TrustStatus::Rejected
        };

        let stored = self.store.add(cert_der, None, trust_status).await?;

        Ok((result, stored))
    }

    // =========================================================================
    // Trust Management
    // =========================================================================

    /// Trusts a certificate.
    pub async fn trust(&self, thumbprint: &str) -> CertificateResult<()> {
        self.validator.trust(thumbprint).await?;
        if self.store.exists(thumbprint).await? {
            self.store
                .set_trust_status(thumbprint, TrustStatus::Trusted)
                .await?;
        }
        Ok(())
    }

    /// Rejects a certificate.
    pub async fn reject(&self, thumbprint: &str) -> CertificateResult<()> {
        self.validator.reject(thumbprint).await?;
        if self.store.exists(thumbprint).await? {
            self.store
                .set_trust_status(thumbprint, TrustStatus::Rejected)
                .await?;
        }
        Ok(())
    }

    /// Checks if a certificate is trusted.
    pub async fn is_trusted(&self, thumbprint: &str) -> CertificateResult<bool> {
        self.validator.is_trusted(thumbprint).await
    }

    // =========================================================================
    // Maintenance
    // =========================================================================

    /// Cleans up expired certificates.
    pub async fn cleanup_expired(&self) -> CertificateResult<u32> {
        self.store.cleanup_expired().await
    }

    /// Gets manager statistics.
    pub async fn stats(&self) -> CertificateResult<ManagerStats> {
        let all = self.store.list().await?;
        let own = self.store.get_own_certificate().await?;
        let expiring = self.store.get_expiring(30).await?;

        let trusted = all
            .iter()
            .filter(|c| c.trust_status == TrustStatus::Trusted)
            .count();
        let rejected = all
            .iter()
            .filter(|c| c.trust_status == TrustStatus::Rejected)
            .count();
        let pending = all
            .iter()
            .filter(|c| c.trust_status == TrustStatus::Pending)
            .count();
        let expired = all.iter().filter(|c| !c.is_valid()).count();

        Ok(ManagerStats {
            total_certificates: all.len(),
            trusted_count: trusted,
            rejected_count: rejected,
            pending_count: pending,
            expired_count: expired,
            expiring_soon_count: expiring.len(),
            has_own_certificate: own.is_some(),
            own_certificate_valid: own.map(|c| c.is_valid()).unwrap_or(false),
        })
    }
}

impl std::fmt::Debug for CertificateManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateManager")
            .field("store", &self.store.name())
            .field("validator", &self.validator.name())
            .field("config", &self.config)
            .finish()
    }
}

// =============================================================================
// ManagerStats
// =============================================================================

/// Certificate manager statistics.
#[derive(Debug, Clone)]
pub struct ManagerStats {
    /// Total number of certificates in store.
    pub total_certificates: usize,
    /// Number of trusted certificates.
    pub trusted_count: usize,
    /// Number of rejected certificates.
    pub rejected_count: usize,
    /// Number of pending certificates.
    pub pending_count: usize,
    /// Number of expired certificates.
    pub expired_count: usize,
    /// Number of certificates expiring within 30 days.
    pub expiring_soon_count: usize,
    /// Whether an own certificate exists.
    pub has_own_certificate: bool,
    /// Whether the own certificate is valid.
    pub own_certificate_valid: bool,
}

// =============================================================================
// CertificateManagerBuilder
// =============================================================================

/// Builder for `CertificateManager`.
#[derive(Debug, Default)]
pub struct CertificateManagerBuilder {
    store_config: Option<StoreConfig>,
    validation_policy: Option<ValidationPolicy>,
    auto_generate: Option<bool>,
    default_cert_config: Option<CertificateConfig>,
}

impl CertificateManagerBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the store configuration.
    pub fn store_config(mut self, config: StoreConfig) -> Self {
        self.store_config = Some(config);
        self
    }

    /// Sets the base directory for certificate storage.
    pub fn base_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.store_config = Some(StoreConfig::with_base_dir(dir));
        self
    }

    /// Sets the validation policy.
    pub fn validation_policy(mut self, policy: ValidationPolicy) -> Self {
        self.validation_policy = Some(policy);
        self
    }

    /// Uses strict validation policy.
    pub fn strict_validation(mut self) -> Self {
        self.validation_policy = Some(ValidationPolicy::strict());
        self
    }

    /// Uses permissive validation policy.
    pub fn permissive_validation(mut self) -> Self {
        self.validation_policy = Some(ValidationPolicy::permissive());
        self
    }

    /// Sets auto-generation of own certificate.
    pub fn auto_generate(mut self, auto: bool) -> Self {
        self.auto_generate = Some(auto);
        self
    }

    /// Sets the default certificate configuration.
    pub fn default_cert_config(mut self, config: CertificateConfig) -> Self {
        self.default_cert_config = Some(config);
        self
    }

    /// Builds the certificate manager.
    pub async fn build(self) -> CertificateResult<CertificateManager> {
        let config = ManagerConfig {
            store_config: self.store_config.unwrap_or_default(),
            validation_policy: self.validation_policy.unwrap_or_else(ValidationPolicy::opcua),
            auto_generate: self.auto_generate.unwrap_or(true),
            default_cert_config: self.default_cert_config.unwrap_or_default(),
        };

        CertificateManager::with_config(config).await
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_certificate_manager_creation() {
        let manager = CertificateManager::in_memory().await.unwrap();
        assert!(manager.get_own_certificate().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_generate_self_signed() {
        let manager = CertificateManager::in_memory().await.unwrap();

        let config = CertificateConfig::builder()
            .common_name("Test Certificate")
            .application_uri("urn:test:app")
            .overwrite(true)
            .build()
            .unwrap();

        let paths = manager.generate_self_signed(&config).await.unwrap();
        assert!(!paths.thumbprint.is_empty());
    }

    #[tokio::test]
    async fn test_ensure_own_certificate() {
        let manager = CertificateManager::in_memory().await.unwrap();

        // Add a certificate manually and set as own
        let cert_data = vec![0x30, 0x82, 0x01, 0x00, 0x00];
        let stored = manager
            .add_certificate(&cert_data, TrustStatus::Trusted)
            .await
            .unwrap();

        manager.store.set_own_certificate(&stored.thumbprint).await.unwrap();

        // Should return existing
        let cert = manager.ensure_own_certificate().await.unwrap();
        assert_eq!(cert.thumbprint, stored.thumbprint);
        assert!(cert.is_valid());
    }

    #[tokio::test]
    async fn test_trust_management() {
        let manager = CertificateManager::in_memory().await.unwrap();

        // Add a certificate
        let cert_data = vec![0x30, 0x82, 0x01, 0x00, 0x00];
        let stored = manager
            .add_certificate(&cert_data, TrustStatus::Pending)
            .await
            .unwrap();

        // Initially not trusted
        assert!(!manager.is_trusted(&stored.thumbprint).await.unwrap());

        // Trust it
        manager.trust(&stored.thumbprint).await.unwrap();
        assert!(manager.is_trusted(&stored.thumbprint).await.unwrap());

        // Reject it
        manager.reject(&stored.thumbprint).await.unwrap();
        assert!(!manager.is_trusted(&stored.thumbprint).await.unwrap());
    }

    #[tokio::test]
    async fn test_manager_stats() {
        let manager = CertificateManager::in_memory().await.unwrap();

        // Add some certificates
        manager
            .add_certificate(&[0u8; 100], TrustStatus::Trusted)
            .await
            .unwrap();
        manager
            .add_certificate(&[1u8; 100], TrustStatus::Rejected)
            .await
            .unwrap();
        manager
            .add_certificate(&[2u8; 100], TrustStatus::Pending)
            .await
            .unwrap();

        let stats = manager.stats().await.unwrap();
        assert_eq!(stats.total_certificates, 3);
        assert_eq!(stats.trusted_count, 1);
        assert_eq!(stats.rejected_count, 1);
        assert_eq!(stats.pending_count, 1);
    }

    #[tokio::test]
    async fn test_builder() {
        let manager = CertificateManager::builder()
            .permissive_validation()
            .auto_generate(false)
            .build()
            .await
            .unwrap();

        assert!(!manager.config.auto_generate);
    }
}
