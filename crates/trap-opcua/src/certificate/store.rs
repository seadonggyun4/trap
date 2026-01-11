// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Certificate storage traits and implementations.
//!
//! This module provides abstractions for storing and retrieving certificates,
//! supporting different backends (filesystem, database, etc.).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::config::{CertificateFormat, StoreConfig};
use super::error::{
    CertificateError, CertificateResult, ParsingError, StorageError, ValidationError,
};

// =============================================================================
// StoredCertificate
// =============================================================================

/// Metadata about a stored certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCertificate {
    /// Certificate thumbprint (SHA-1).
    pub thumbprint: String,
    /// Certificate thumbprint (SHA-256).
    pub thumbprint_sha256: String,
    /// Subject Distinguished Name.
    pub subject_dn: String,
    /// Issuer Distinguished Name.
    pub issuer_dn: String,
    /// Serial number.
    pub serial_number: String,
    /// Not valid before date.
    pub not_before: DateTime<Utc>,
    /// Not valid after date.
    pub not_after: DateTime<Utc>,
    /// Application URI (from SAN).
    pub application_uri: Option<String>,
    /// Path to certificate file.
    pub certificate_path: PathBuf,
    /// Path to private key file (if available).
    pub private_key_path: Option<PathBuf>,
    /// Certificate format.
    pub format: CertificateFormat,
    /// Whether this is a CA certificate.
    pub is_ca: bool,
    /// Trust status.
    pub trust_status: TrustStatus,
    /// When the certificate was added to the store.
    pub added_at: DateTime<Utc>,
    /// Optional notes/description.
    pub notes: Option<String>,
}

impl StoredCertificate {
    /// Returns `true` if the certificate is currently valid (not expired).
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.not_before && now <= self.not_after
    }

    /// Returns the number of days until expiration.
    pub fn days_until_expiration(&self) -> i64 {
        let now = Utc::now();
        (self.not_after - now).num_days()
    }

    /// Returns `true` if the certificate will expire within the given days.
    pub fn expires_within_days(&self, days: i64) -> bool {
        self.days_until_expiration() <= days
    }

    /// Returns `true` if the certificate is trusted.
    pub fn is_trusted(&self) -> bool {
        matches!(self.trust_status, TrustStatus::Trusted)
    }

    /// Returns `true` if this certificate has a private key.
    pub fn has_private_key(&self) -> bool {
        self.private_key_path.is_some()
    }
}

/// Trust status of a certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum TrustStatus {
    /// Certificate is trusted.
    Trusted,
    /// Certificate is not yet trusted (pending review).
    #[default]
    Pending,
    /// Certificate has been explicitly rejected.
    Rejected,
    /// Trust status is unknown.
    Unknown,
}

impl TrustStatus {
    /// Returns the string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for TrustStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// =============================================================================
// CertificateStore Trait
// =============================================================================

/// Trait for certificate storage operations.
///
/// Implementations can use different backends (filesystem, database, etc.)
/// to store and retrieve certificates.
#[async_trait]
pub trait CertificateStore: Send + Sync {
    /// Returns the store name.
    fn name(&self) -> &str;

    /// Initializes the store (creates directories, etc.).
    async fn initialize(&self) -> CertificateResult<()>;

    /// Adds a certificate to the store.
    async fn add(
        &self,
        cert_der: &[u8],
        private_key_der: Option<&[u8]>,
        trust_status: TrustStatus,
    ) -> CertificateResult<StoredCertificate>;

    /// Gets a certificate by thumbprint.
    async fn get(&self, thumbprint: &str) -> CertificateResult<Option<StoredCertificate>>;

    /// Gets the certificate bytes by thumbprint.
    async fn get_certificate_bytes(&self, thumbprint: &str) -> CertificateResult<Vec<u8>>;

    /// Gets the private key bytes by thumbprint.
    async fn get_private_key_bytes(&self, thumbprint: &str) -> CertificateResult<Option<Vec<u8>>>;

    /// Removes a certificate from the store.
    async fn remove(&self, thumbprint: &str) -> CertificateResult<bool>;

    /// Lists all certificates in the store.
    async fn list(&self) -> CertificateResult<Vec<StoredCertificate>>;

    /// Lists certificates with a specific trust status.
    async fn list_by_status(&self, status: TrustStatus) -> CertificateResult<Vec<StoredCertificate>>;

    /// Updates the trust status of a certificate.
    async fn set_trust_status(
        &self,
        thumbprint: &str,
        status: TrustStatus,
    ) -> CertificateResult<()>;

    /// Checks if a certificate exists.
    async fn exists(&self, thumbprint: &str) -> CertificateResult<bool>;

    /// Gets the own certificate (client/server identity).
    async fn get_own_certificate(&self) -> CertificateResult<Option<StoredCertificate>>;

    /// Sets the own certificate.
    async fn set_own_certificate(&self, thumbprint: &str) -> CertificateResult<()>;

    /// Finds certificates by subject DN.
    async fn find_by_subject(&self, subject: &str) -> CertificateResult<Vec<StoredCertificate>>;

    /// Finds certificates by application URI.
    async fn find_by_application_uri(
        &self,
        uri: &str,
    ) -> CertificateResult<Vec<StoredCertificate>>;

    /// Gets certificates expiring within the given days.
    async fn get_expiring(&self, days: i64) -> CertificateResult<Vec<StoredCertificate>>;

    /// Cleans up expired certificates.
    async fn cleanup_expired(&self) -> CertificateResult<u32>;
}

// =============================================================================
// FileSystemStore
// =============================================================================

/// Filesystem-based certificate store.
///
/// Stores certificates in a directory structure following OPC UA conventions:
/// - `own/` - Own certificates and private keys
/// - `trusted/` - Trusted peer certificates
/// - `rejected/` - Rejected certificates (for review)
/// - `issuers/` - CA certificates
#[derive(Debug)]
pub struct FileSystemStore {
    /// Store configuration.
    config: StoreConfig,
    /// In-memory certificate index.
    index: Arc<RwLock<CertificateIndex>>,
    /// Path to own certificate thumbprint.
    own_thumbprint: Arc<RwLock<Option<String>>>,
}

/// In-memory index of stored certificates.
#[derive(Debug, Default)]
struct CertificateIndex {
    /// Certificates indexed by thumbprint.
    by_thumbprint: HashMap<String, StoredCertificate>,
    /// Thumbprints indexed by subject DN.
    by_subject: HashMap<String, Vec<String>>,
    /// Thumbprints indexed by application URI.
    by_uri: HashMap<String, Vec<String>>,
}

impl FileSystemStore {
    /// Creates a new filesystem store with default configuration.
    pub fn new() -> Self {
        Self::with_config(StoreConfig::default())
    }

    /// Creates a new filesystem store with custom configuration.
    pub fn with_config(config: StoreConfig) -> Self {
        Self {
            config,
            index: Arc::new(RwLock::new(CertificateIndex::default())),
            own_thumbprint: Arc::new(RwLock::new(None)),
        }
    }

    /// Creates a new filesystem store with custom base directory.
    pub fn with_base_dir(base_dir: impl Into<PathBuf>) -> Self {
        Self::with_config(StoreConfig::with_base_dir(base_dir))
    }

    /// Returns the path for a certificate file.
    fn cert_path(&self, thumbprint: &str, trust_status: TrustStatus) -> PathBuf {
        let dir = match trust_status {
            TrustStatus::Trusted => &self.config.trusted_dir,
            TrustStatus::Rejected => &self.config.rejected_dir,
            TrustStatus::Pending => &self.config.rejected_dir,
            TrustStatus::Unknown => &self.config.rejected_dir,
        };
        dir.join(format!("{}.der", thumbprint))
    }

    /// Returns the path for a private key file.
    fn key_path(&self, thumbprint: &str) -> PathBuf {
        self.config.own_dir.join(format!("{}.key", thumbprint))
    }

    /// Returns the path to the index file.
    fn index_path(&self) -> PathBuf {
        self.config.base_dir.join("index.json")
    }

    /// Loads the index from disk.
    async fn load_index(&self) -> CertificateResult<()> {
        let index_path = self.index_path();

        if !index_path.exists() {
            return Ok(());
        }

        let content = tokio::fs::read_to_string(&index_path)
            .await
            .map_err(|e| {
                CertificateError::storage(StorageError::read_failed_with(
                    index_path.clone(),
                    "Failed to read index file",
                    e,
                ))
            })?;

        let stored: Vec<StoredCertificate> =
            serde_json::from_str(&content).map_err(|e| {
                CertificateError::parsing(ParsingError::invalid_pem(format!(
                    "Invalid index file: {}",
                    e
                )))
            })?;

        let mut index = self.index.write().await;
        for cert in stored {
            let thumbprint = cert.thumbprint.clone();
            let subject = cert.subject_dn.clone();
            let uri = cert.application_uri.clone();

            index.by_thumbprint.insert(thumbprint.clone(), cert);

            index
                .by_subject
                .entry(subject)
                .or_default()
                .push(thumbprint.clone());

            if let Some(uri) = uri {
                index
                    .by_uri
                    .entry(uri)
                    .or_default()
                    .push(thumbprint);
            }
        }

        Ok(())
    }

    /// Saves the index to disk.
    async fn save_index(&self) -> CertificateResult<()> {
        let index = self.index.read().await;
        let certs: Vec<&StoredCertificate> = index.by_thumbprint.values().collect();

        let content = serde_json::to_string_pretty(&certs).map_err(|e| {
            CertificateError::storage(StorageError::write_failed(
                self.index_path(),
                format!("Failed to serialize index: {}", e),
            ))
        })?;

        tokio::fs::write(self.index_path(), content)
            .await
            .map_err(|e| {
                CertificateError::storage(StorageError::write_failed_with(
                    self.index_path(),
                    "Failed to write index file",
                    e,
                ))
            })?;

        Ok(())
    }

    /// Parses certificate metadata from DER bytes.
    fn parse_certificate_metadata(
        &self,
        cert_der: &[u8],
        cert_path: PathBuf,
        key_path: Option<PathBuf>,
        trust_status: TrustStatus,
    ) -> CertificateResult<StoredCertificate> {
        // In a real implementation, parse the X.509 certificate
        // For now, create mock metadata

        let thumbprint = hex_encode(&cert_der[..20.min(cert_der.len())]);
        let thumbprint_sha256 = hex_encode(&cert_der[..32.min(cert_der.len())]);

        // Extract subject from mock certificate
        let subject_start = cert_der.iter().position(|&b| b == 0x30).unwrap_or(0) + 1;
        let subject_end = cert_der[subject_start..]
            .iter()
            .position(|&b| b == 0x00)
            .map(|p| subject_start + p)
            .unwrap_or(cert_der.len().min(subject_start + 64));

        let subject_dn = String::from_utf8_lossy(&cert_der[subject_start..subject_end]).to_string();

        // Extract serial number
        let serial_start = subject_end + 1;
        let serial_end = cert_der[serial_start..]
            .iter()
            .position(|&b| b == 0x00)
            .map(|p| serial_start + p)
            .unwrap_or(cert_der.len());

        let serial_number = if serial_end > serial_start {
            String::from_utf8_lossy(&cert_der[serial_start..serial_end]).to_string()
        } else {
            "unknown".to_string()
        };

        Ok(StoredCertificate {
            thumbprint,
            thumbprint_sha256,
            subject_dn: format!("CN={}", subject_dn),
            issuer_dn: format!("CN={}", subject_dn), // Self-signed
            serial_number,
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(365),
            application_uri: None,
            certificate_path: cert_path,
            private_key_path: key_path,
            format: CertificateFormat::Der,
            is_ca: false,
            trust_status,
            added_at: Utc::now(),
            notes: None,
        })
    }
}

impl Default for FileSystemStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CertificateStore for FileSystemStore {
    fn name(&self) -> &str {
        "FileSystemStore"
    }

    async fn initialize(&self) -> CertificateResult<()> {
        // Create directories
        for dir in self.config.all_dirs() {
            tokio::fs::create_dir_all(dir).await.map_err(|e| {
                CertificateError::storage(StorageError::directory_creation_failed(
                    dir.clone(),
                    e.to_string(),
                ))
            })?;
        }

        // Load existing index
        self.load_index().await?;

        tracing::info!(
            base_dir = %self.config.base_dir.display(),
            "Initialized certificate store"
        );

        Ok(())
    }

    async fn add(
        &self,
        cert_der: &[u8],
        private_key_der: Option<&[u8]>,
        trust_status: TrustStatus,
    ) -> CertificateResult<StoredCertificate> {
        // Calculate thumbprint
        let thumbprint = hex_encode(&cert_der[..20.min(cert_der.len())]);

        // Determine paths
        let cert_path = self.cert_path(&thumbprint, trust_status);
        let key_path = if private_key_der.is_some() {
            Some(self.key_path(&thumbprint))
        } else {
            None
        };

        // Save certificate file
        tokio::fs::write(&cert_path, cert_der).await.map_err(|e| {
            CertificateError::storage(StorageError::write_failed_with(
                cert_path.clone(),
                "Failed to write certificate",
                e,
            ))
        })?;

        // Save private key if provided
        if let (Some(key_data), Some(ref key_path)) = (private_key_der, &key_path) {
            tokio::fs::write(key_path, key_data).await.map_err(|e| {
                CertificateError::storage(StorageError::write_failed_with(
                    key_path.clone(),
                    "Failed to write private key",
                    e,
                ))
            })?;

            // Set restrictive permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let permissions = std::fs::Permissions::from_mode(0o600);
                tokio::fs::set_permissions(key_path, permissions).await.ok();
            }
        }

        // Parse and store metadata
        let stored =
            self.parse_certificate_metadata(cert_der, cert_path, key_path, trust_status)?;

        // Update index
        {
            let mut index = self.index.write().await;
            let subject = stored.subject_dn.clone();
            let uri = stored.application_uri.clone();

            index
                .by_thumbprint
                .insert(thumbprint.clone(), stored.clone());

            index
                .by_subject
                .entry(subject)
                .or_default()
                .push(thumbprint.clone());

            if let Some(uri) = uri {
                index.by_uri.entry(uri).or_default().push(thumbprint);
            }
        }

        // Save index
        self.save_index().await?;

        tracing::info!(
            thumbprint = %stored.thumbprint,
            subject = %stored.subject_dn,
            status = %trust_status,
            "Added certificate to store"
        );

        Ok(stored)
    }

    async fn get(&self, thumbprint: &str) -> CertificateResult<Option<StoredCertificate>> {
        let index = self.index.read().await;
        Ok(index.by_thumbprint.get(thumbprint).cloned())
    }

    async fn get_certificate_bytes(&self, thumbprint: &str) -> CertificateResult<Vec<u8>> {
        let stored = self
            .get(thumbprint)
            .await?
            .ok_or_else(|| CertificateError::storage(StorageError::file_not_found(thumbprint)))?;

        tokio::fs::read(&stored.certificate_path)
            .await
            .map_err(|e| {
                CertificateError::storage(StorageError::read_failed_with(
                    stored.certificate_path,
                    "Failed to read certificate",
                    e,
                ))
            })
    }

    async fn get_private_key_bytes(&self, thumbprint: &str) -> CertificateResult<Option<Vec<u8>>> {
        let stored = self
            .get(thumbprint)
            .await?
            .ok_or_else(|| CertificateError::storage(StorageError::file_not_found(thumbprint)))?;

        if let Some(ref key_path) = stored.private_key_path {
            let bytes = tokio::fs::read(key_path).await.map_err(|e| {
                CertificateError::storage(StorageError::read_failed_with(
                    key_path.clone(),
                    "Failed to read private key",
                    e,
                ))
            })?;
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }

    async fn remove(&self, thumbprint: &str) -> CertificateResult<bool> {
        let stored = match self.get(thumbprint).await? {
            Some(s) => s,
            None => return Ok(false),
        };

        // Remove certificate file
        if stored.certificate_path.exists() {
            tokio::fs::remove_file(&stored.certificate_path)
                .await
                .map_err(|e| {
                    CertificateError::storage(StorageError::write_failed_with(
                        stored.certificate_path.clone(),
                        "Failed to remove certificate",
                        e,
                    ))
                })?;
        }

        // Remove private key file
        if let Some(ref key_path) = stored.private_key_path {
            if key_path.exists() {
                tokio::fs::remove_file(key_path).await.map_err(|e| {
                    CertificateError::storage(StorageError::write_failed_with(
                        key_path.clone(),
                        "Failed to remove private key",
                        e,
                    ))
                })?;
            }
        }

        // Update index
        {
            let mut index = self.index.write().await;
            index.by_thumbprint.remove(thumbprint);

            // Remove from subject index
            if let Some(thumbprints) = index.by_subject.get_mut(&stored.subject_dn) {
                thumbprints.retain(|t| t != thumbprint);
            }

            // Remove from URI index
            if let Some(uri) = &stored.application_uri {
                if let Some(thumbprints) = index.by_uri.get_mut(uri) {
                    thumbprints.retain(|t| t != thumbprint);
                }
            }
        }

        self.save_index().await?;

        tracing::info!(
            thumbprint = thumbprint,
            "Removed certificate from store"
        );

        Ok(true)
    }

    async fn list(&self) -> CertificateResult<Vec<StoredCertificate>> {
        let index = self.index.read().await;
        Ok(index.by_thumbprint.values().cloned().collect())
    }

    async fn list_by_status(&self, status: TrustStatus) -> CertificateResult<Vec<StoredCertificate>> {
        let index = self.index.read().await;
        Ok(index
            .by_thumbprint
            .values()
            .filter(|c| c.trust_status == status)
            .cloned()
            .collect())
    }

    async fn set_trust_status(
        &self,
        thumbprint: &str,
        status: TrustStatus,
    ) -> CertificateResult<()> {
        let stored = self
            .get(thumbprint)
            .await?
            .ok_or_else(|| CertificateError::storage(StorageError::file_not_found(thumbprint)))?;

        if stored.trust_status == status {
            return Ok(());
        }

        // Move certificate file to appropriate directory
        let old_path = stored.certificate_path.clone();
        let new_path = self.cert_path(thumbprint, status);

        if old_path != new_path {
            tokio::fs::rename(&old_path, &new_path).await.map_err(|e| {
                CertificateError::storage(StorageError::write_failed_with(
                    new_path.clone(),
                    "Failed to move certificate",
                    e,
                ))
            })?;
        }

        // Update index
        {
            let mut index = self.index.write().await;
            if let Some(cert) = index.by_thumbprint.get_mut(thumbprint) {
                cert.trust_status = status;
                cert.certificate_path = new_path;
            }
        }

        self.save_index().await?;

        tracing::info!(
            thumbprint = thumbprint,
            old_status = %stored.trust_status,
            new_status = %status,
            "Updated certificate trust status"
        );

        Ok(())
    }

    async fn exists(&self, thumbprint: &str) -> CertificateResult<bool> {
        let index = self.index.read().await;
        Ok(index.by_thumbprint.contains_key(thumbprint))
    }

    async fn get_own_certificate(&self) -> CertificateResult<Option<StoredCertificate>> {
        let own = self.own_thumbprint.read().await;
        if let Some(ref thumbprint) = *own {
            self.get(thumbprint).await
        } else {
            Ok(None)
        }
    }

    async fn set_own_certificate(&self, thumbprint: &str) -> CertificateResult<()> {
        // Verify certificate exists
        if !self.exists(thumbprint).await? {
            return Err(CertificateError::validation(ValidationError::not_trusted(
                thumbprint,
            )));
        }

        let mut own = self.own_thumbprint.write().await;
        *own = Some(thumbprint.to_string());

        tracing::info!(
            thumbprint = thumbprint,
            "Set own certificate"
        );

        Ok(())
    }

    async fn find_by_subject(&self, subject: &str) -> CertificateResult<Vec<StoredCertificate>> {
        let index = self.index.read().await;
        let thumbprints = index.by_subject.get(subject).cloned().unwrap_or_default();

        let mut results = Vec::new();
        for thumbprint in thumbprints {
            if let Some(cert) = index.by_thumbprint.get(&thumbprint) {
                results.push(cert.clone());
            }
        }

        Ok(results)
    }

    async fn find_by_application_uri(
        &self,
        uri: &str,
    ) -> CertificateResult<Vec<StoredCertificate>> {
        let index = self.index.read().await;
        let thumbprints = index.by_uri.get(uri).cloned().unwrap_or_default();

        let mut results = Vec::new();
        for thumbprint in thumbprints {
            if let Some(cert) = index.by_thumbprint.get(&thumbprint) {
                results.push(cert.clone());
            }
        }

        Ok(results)
    }

    async fn get_expiring(&self, days: i64) -> CertificateResult<Vec<StoredCertificate>> {
        let index = self.index.read().await;
        Ok(index
            .by_thumbprint
            .values()
            .filter(|c| c.expires_within_days(days))
            .cloned()
            .collect())
    }

    async fn cleanup_expired(&self) -> CertificateResult<u32> {
        let expired: Vec<String> = {
            let index = self.index.read().await;
            index
                .by_thumbprint
                .iter()
                .filter(|(_, c)| !c.is_valid())
                .map(|(t, _)| t.clone())
                .collect()
        };

        let mut removed = 0;
        for thumbprint in expired {
            if self.remove(&thumbprint).await? {
                removed += 1;
            }
        }

        if removed > 0 {
            tracing::info!(count = removed, "Cleaned up expired certificates");
        }

        Ok(removed)
    }
}

// =============================================================================
// MemoryStore (for testing)
// =============================================================================

/// In-memory certificate store for testing.
#[derive(Debug, Default)]
pub struct MemoryStore {
    /// Stored certificates.
    certs: Arc<RwLock<HashMap<String, (StoredCertificate, Vec<u8>, Option<Vec<u8>>)>>>,
    /// Own certificate thumbprint.
    own: Arc<RwLock<Option<String>>>,
}

impl MemoryStore {
    /// Creates a new memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CertificateStore for MemoryStore {
    fn name(&self) -> &str {
        "MemoryStore"
    }

    async fn initialize(&self) -> CertificateResult<()> {
        Ok(())
    }

    async fn add(
        &self,
        cert_der: &[u8],
        private_key_der: Option<&[u8]>,
        trust_status: TrustStatus,
    ) -> CertificateResult<StoredCertificate> {
        let thumbprint = hex_encode(&cert_der[..20.min(cert_der.len())]);

        let stored = StoredCertificate {
            thumbprint: thumbprint.clone(),
            thumbprint_sha256: hex_encode(&cert_der[..32.min(cert_der.len())]),
            subject_dn: "CN=Test".to_string(),
            issuer_dn: "CN=Test".to_string(),
            serial_number: "1".to_string(),
            not_before: Utc::now(),
            not_after: Utc::now() + chrono::Duration::days(365),
            application_uri: None,
            certificate_path: PathBuf::from("memory"),
            private_key_path: private_key_der.map(|_| PathBuf::from("memory")),
            format: CertificateFormat::Der,
            is_ca: false,
            trust_status,
            added_at: Utc::now(),
            notes: None,
        };

        let mut certs = self.certs.write().await;
        certs.insert(
            thumbprint,
            (stored.clone(), cert_der.to_vec(), private_key_der.map(|k| k.to_vec())),
        );

        Ok(stored)
    }

    async fn get(&self, thumbprint: &str) -> CertificateResult<Option<StoredCertificate>> {
        let certs = self.certs.read().await;
        Ok(certs.get(thumbprint).map(|(s, _, _)| s.clone()))
    }

    async fn get_certificate_bytes(&self, thumbprint: &str) -> CertificateResult<Vec<u8>> {
        let certs = self.certs.read().await;
        certs
            .get(thumbprint)
            .map(|(_, c, _)| c.clone())
            .ok_or_else(|| CertificateError::storage(StorageError::file_not_found(thumbprint)))
    }

    async fn get_private_key_bytes(&self, thumbprint: &str) -> CertificateResult<Option<Vec<u8>>> {
        let certs = self.certs.read().await;
        Ok(certs.get(thumbprint).and_then(|(_, _, k)| k.clone()))
    }

    async fn remove(&self, thumbprint: &str) -> CertificateResult<bool> {
        let mut certs = self.certs.write().await;
        Ok(certs.remove(thumbprint).is_some())
    }

    async fn list(&self) -> CertificateResult<Vec<StoredCertificate>> {
        let certs = self.certs.read().await;
        Ok(certs.values().map(|(s, _, _)| s.clone()).collect())
    }

    async fn list_by_status(&self, status: TrustStatus) -> CertificateResult<Vec<StoredCertificate>> {
        let certs = self.certs.read().await;
        Ok(certs
            .values()
            .filter(|(s, _, _)| s.trust_status == status)
            .map(|(s, _, _)| s.clone())
            .collect())
    }

    async fn set_trust_status(
        &self,
        thumbprint: &str,
        status: TrustStatus,
    ) -> CertificateResult<()> {
        let mut certs = self.certs.write().await;
        if let Some((stored, _, _)) = certs.get_mut(thumbprint) {
            stored.trust_status = status;
            Ok(())
        } else {
            Err(CertificateError::storage(StorageError::file_not_found(
                thumbprint,
            )))
        }
    }

    async fn exists(&self, thumbprint: &str) -> CertificateResult<bool> {
        let certs = self.certs.read().await;
        Ok(certs.contains_key(thumbprint))
    }

    async fn get_own_certificate(&self) -> CertificateResult<Option<StoredCertificate>> {
        let own = self.own.read().await;
        if let Some(ref thumbprint) = *own {
            self.get(thumbprint).await
        } else {
            Ok(None)
        }
    }

    async fn set_own_certificate(&self, thumbprint: &str) -> CertificateResult<()> {
        let mut own = self.own.write().await;
        *own = Some(thumbprint.to_string());
        Ok(())
    }

    async fn find_by_subject(&self, subject: &str) -> CertificateResult<Vec<StoredCertificate>> {
        let certs = self.certs.read().await;
        Ok(certs
            .values()
            .filter(|(s, _, _)| s.subject_dn.contains(subject))
            .map(|(s, _, _)| s.clone())
            .collect())
    }

    async fn find_by_application_uri(
        &self,
        uri: &str,
    ) -> CertificateResult<Vec<StoredCertificate>> {
        let certs = self.certs.read().await;
        Ok(certs
            .values()
            .filter(|(s, _, _)| s.application_uri.as_deref() == Some(uri))
            .map(|(s, _, _)| s.clone())
            .collect())
    }

    async fn get_expiring(&self, days: i64) -> CertificateResult<Vec<StoredCertificate>> {
        let certs = self.certs.read().await;
        Ok(certs
            .values()
            .filter(|(s, _, _)| s.expires_within_days(days))
            .map(|(s, _, _)| s.clone())
            .collect())
    }

    async fn cleanup_expired(&self) -> CertificateResult<u32> {
        let expired: Vec<String> = {
            let certs = self.certs.read().await;
            certs
                .iter()
                .filter(|(_, (s, _, _))| !s.is_valid())
                .map(|(t, _)| t.clone())
                .collect()
        };

        let mut removed = 0;
        for thumbprint in expired {
            if self.remove(&thumbprint).await? {
                removed += 1;
            }
        }

        Ok(removed)
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Hex encodes bytes.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_store() {
        let store = MemoryStore::new();
        store.initialize().await.unwrap();

        let cert_data = vec![0u8; 100];
        let key_data = vec![1u8; 50];

        let stored = store
            .add(&cert_data, Some(&key_data), TrustStatus::Trusted)
            .await
            .unwrap();

        assert!(store.exists(&stored.thumbprint).await.unwrap());
        assert!(stored.is_trusted());

        let retrieved = store.get(&stored.thumbprint).await.unwrap().unwrap();
        assert_eq!(retrieved.thumbprint, stored.thumbprint);

        let key = store
            .get_private_key_bytes(&stored.thumbprint)
            .await
            .unwrap();
        assert!(key.is_some());

        store.remove(&stored.thumbprint).await.unwrap();
        assert!(!store.exists(&stored.thumbprint).await.unwrap());
    }

    #[tokio::test]
    async fn test_trust_status() {
        let store = MemoryStore::new();
        let cert_data = vec![0u8; 100];

        let stored = store
            .add(&cert_data, None, TrustStatus::Pending)
            .await
            .unwrap();

        assert_eq!(stored.trust_status, TrustStatus::Pending);

        store
            .set_trust_status(&stored.thumbprint, TrustStatus::Trusted)
            .await
            .unwrap();

        let updated = store.get(&stored.thumbprint).await.unwrap().unwrap();
        assert_eq!(updated.trust_status, TrustStatus::Trusted);
    }

    #[tokio::test]
    async fn test_list_by_status() {
        let store = MemoryStore::new();

        store
            .add(&[0u8; 100], None, TrustStatus::Trusted)
            .await
            .unwrap();
        store
            .add(&[1u8; 100], None, TrustStatus::Rejected)
            .await
            .unwrap();
        store
            .add(&[2u8; 100], None, TrustStatus::Trusted)
            .await
            .unwrap();

        let trusted = store.list_by_status(TrustStatus::Trusted).await.unwrap();
        assert_eq!(trusted.len(), 2);

        let rejected = store.list_by_status(TrustStatus::Rejected).await.unwrap();
        assert_eq!(rejected.len(), 1);
    }

    #[tokio::test]
    async fn test_own_certificate() {
        let store = MemoryStore::new();

        let stored = store
            .add(&[0u8; 100], Some(&[1u8; 50]), TrustStatus::Trusted)
            .await
            .unwrap();

        store.set_own_certificate(&stored.thumbprint).await.unwrap();

        let own = store.get_own_certificate().await.unwrap().unwrap();
        assert_eq!(own.thumbprint, stored.thumbprint);
    }

    #[test]
    fn test_trust_status_display() {
        assert_eq!(TrustStatus::Trusted.as_str(), "trusted");
        assert_eq!(TrustStatus::Rejected.as_str(), "rejected");
        assert_eq!(format!("{}", TrustStatus::Pending), "pending");
    }

    #[test]
    fn test_stored_certificate_validity() {
        let cert = StoredCertificate {
            thumbprint: "ABC".to_string(),
            thumbprint_sha256: "DEF".to_string(),
            subject_dn: "CN=Test".to_string(),
            issuer_dn: "CN=Test".to_string(),
            serial_number: "1".to_string(),
            not_before: Utc::now() - chrono::Duration::days(1),
            not_after: Utc::now() + chrono::Duration::days(60),
            application_uri: None,
            certificate_path: PathBuf::from("test"),
            private_key_path: None,
            format: CertificateFormat::Der,
            is_ca: false,
            trust_status: TrustStatus::Trusted,
            added_at: Utc::now(),
            notes: None,
        };

        assert!(cert.is_valid());
        assert!(cert.expires_within_days(61));
        assert!(!cert.expires_within_days(30));
    }
}
