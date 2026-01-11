// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// Copyright (c) 2025 Sylvex. All rights reserved.

//! Certificate generation and management utilities for OPC UA.
//!
//! This module provides comprehensive certificate management for OPC UA security:
//!
//! - **Generation**: Create self-signed certificates for OPC UA clients/servers
//! - **Storage**: Store certificates in filesystem with proper directory structure
//! - **Validation**: Validate certificates against configurable policies
//! - **Trust Management**: Accept/reject certificates and maintain trust lists
//!
//! # Architecture
//!
//! ```text
//! CertificateManager (Facade)
//!         │
//!         ├─── CertificateGenerator (trait)
//!         │         ├── SelfSignedGenerator
//!         │         └── CaSignedGenerator
//!         │
//!         ├─── CertificateStore (trait)
//!         │         ├── FileSystemStore
//!         │         └── MemoryStore
//!         │
//!         └─── CertificateValidator (trait)
//!                   ├── X509Validator
//!                   └── AcceptAllValidator
//! ```
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use trap_opcua::certificate::{CertificateManager, CertificateConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create certificate manager
//!     let manager = CertificateManager::new().await?;
//!
//!     // Generate self-signed certificate
//!     let config = CertificateConfig::builder()
//!         .common_name("My OPC UA Client")
//!         .organization("My Company")
//!         .application_uri("urn:mycompany:client")
//!         .validity_days(365)
//!         .build()?;
//!
//!     let paths = manager.generate_self_signed(&config).await?;
//!     println!("Certificate: {:?}", paths.certificate_path);
//!     println!("Private Key: {:?}", paths.private_key_path);
//!     println!("Thumbprint: {}", paths.thumbprint);
//!
//!     // Validate a server certificate
//!     let server_cert = std::fs::read("server_cert.der")?;
//!     let result = manager.validate(&server_cert).await?;
//!
//!     if result.is_valid {
//!         println!("Server certificate is valid");
//!         if !result.is_trusted {
//!             // Trust the certificate
//!             manager.trust(&result.thumbprint).await?;
//!         }
//!     } else {
//!         for error in &result.errors {
//!             println!("Validation error: {}", error);
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # OPC UA PKI Structure
//!
//! The `FileSystemStore` organizes certificates following OPC UA conventions:
//!
//! ```text
//! pki/
//! ├── own/          # Own certificates and private keys
//! │   ├── cert.der
//! │   └── cert.key
//! ├── trusted/      # Trusted peer certificates
//! ├── rejected/     # Rejected certificates (for review)
//! └── issuers/      # CA certificates
//! ```
//!
//! # Configuration
//!
//! ## Certificate Configuration
//!
//! ```rust,ignore
//! use trap_opcua::certificate::{
//!     CertificateConfig, KeyAlgorithm, SignatureAlgorithm,
//!     SubjectName, SubjectAltName, KeyUsage,
//! };
//!
//! let config = CertificateConfig::builder()
//!     // Subject name
//!     .subject(SubjectName::new("My Client")
//!         .with_organization("My Company")
//!         .with_country("US"))
//!
//!     // Subject Alternative Names
//!     .add_dns("localhost")
//!     .add_ip("127.0.0.1")
//!     .add_uri("urn:mycompany:client")
//!
//!     // Application URI (required for OPC UA)
//!     .application_uri("urn:mycompany:client")
//!
//!     // Key and signature algorithms
//!     .key_algorithm(KeyAlgorithm::Rsa2048)
//!     .signature_algorithm(SignatureAlgorithm::Sha256WithRsa)
//!
//!     // Validity
//!     .validity_days(365)
//!
//!     // Output paths
//!     .certificate_path("/path/to/cert.der")
//!     .private_key_path("/path/to/key.der")
//!
//!     .build()?;
//! ```
//!
//! ## Validation Policy
//!
//! ```rust,ignore
//! use trap_opcua::certificate::{ValidationPolicy, CertificateManager};
//!
//! // Default OPC UA policy
//! let policy = ValidationPolicy::opcua();
//!
//! // Strict policy (for production)
//! let policy = ValidationPolicy::strict();
//!
//! // Permissive policy (for development/testing)
//! let policy = ValidationPolicy::permissive();
//!
//! let manager = CertificateManager::builder()
//!     .validation_policy(policy)
//!     .build()
//!     .await?;
//! ```
//!
//! # Error Handling
//!
//! Certificate errors are organized by category:
//!
//! ```text
//! CertificateError
//! ├── Generation    - Key/certificate creation failures
//! ├── Storage       - File I/O errors
//! ├── Validation    - Certificate verification failures
//! ├── Parsing       - Format/encoding errors
//! ├── Expiration    - Validity period issues
//! └── Configuration - Invalid settings
//! ```

pub mod config;
pub mod error;
pub mod generator;
pub mod manager;
pub mod store;
pub mod validator;

// Re-export commonly used types
pub use config::{
    CertificateConfig, CertificateConfigBuilder, CertificateFormat, ExtendedKeyUsage,
    KeyAlgorithm, KeyUsage, SignatureAlgorithm, StoreConfig, SubjectAltName, SubjectName,
};

pub use error::{
    CertConfigError, CertificateError, CertificateResult, ExpirationError, GenerationError,
    ParsingError, StorageError, ValidationError,
};

pub use generator::{
    CaSignedGenerator, CertificateGenerator, CertificatePaths, GeneratedCertificate,
    PublicKeyInfo, SelfSignedGenerator,
};

pub use store::{
    CertificateStore, FileSystemStore, MemoryStore, StoredCertificate, TrustStatus,
};

pub use validator::{
    AcceptAllValidator, CertificateValidator, ValidationPolicy, ValidationResult, X509Validator,
};

pub use manager::{CertificateManager, CertificateManagerBuilder, ManagerConfig, ManagerStats};

// =============================================================================
// Convenience Functions
// =============================================================================

/// Creates a new certificate manager with default configuration.
///
/// This is a convenience function equivalent to `CertificateManager::new()`.
///
/// # Example
///
/// ```rust,ignore
/// use trap_opcua::certificate;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let manager = certificate::new_manager().await?;
///     Ok(())
/// }
/// ```
pub async fn new_manager() -> CertificateResult<CertificateManager> {
    CertificateManager::new().await
}

/// Creates an in-memory certificate manager for testing.
///
/// # Example
///
/// ```rust,ignore
/// use trap_opcua::certificate;
///
/// #[tokio::test]
/// async fn test_certificates() {
///     let manager = certificate::test_manager().await.unwrap();
///     // ... test code
/// }
/// ```
pub async fn test_manager() -> CertificateResult<CertificateManager> {
    CertificateManager::in_memory().await
}

/// Generates a quick self-signed certificate.
///
/// This is a convenience function for generating certificates with minimal configuration.
///
/// # Arguments
///
/// * `common_name` - The certificate common name (CN)
/// * `application_uri` - The OPC UA application URI
///
/// # Example
///
/// ```rust,ignore
/// use trap_opcua::certificate;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let paths = certificate::generate_quick(
///         "My OPC UA Client",
///         "urn:mycompany:client"
///     ).await?;
///
///     println!("Generated certificate: {:?}", paths.certificate_path);
///     Ok(())
/// }
/// ```
pub async fn generate_quick(
    common_name: &str,
    application_uri: &str,
) -> CertificateResult<CertificatePaths> {
    let manager = CertificateManager::new().await?;
    manager.generate_quick(common_name, application_uri).await
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_module_exports() {
        // Test that all exports are accessible
        let _config = CertificateConfig::default();
        let _builder = CertificateConfigBuilder::new();
        let _algorithm = KeyAlgorithm::Rsa2048;
        let _format = CertificateFormat::Der;
        let _policy = ValidationPolicy::default();
        let _status = TrustStatus::Trusted;
    }

    #[tokio::test]
    async fn test_convenience_functions() {
        let manager = test_manager().await.unwrap();
        assert!(manager.get_own_certificate().await.unwrap().is_none());
    }

    #[test]
    fn test_error_types() {
        let gen_error = GenerationError::key_generation_failed("RSA", "test");
        let cert_error = CertificateError::generation(gen_error);
        assert!(cert_error.to_string().contains("RSA"));
    }
}
