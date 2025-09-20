// Certificate Storage - Handles persistent storage of SSL certificates

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;
use async_trait::async_trait;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

use crate::error::{WafProxyError, Result as WafResult};

/// SSL/TLS Certificate with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub domain: String,
    pub cert_chain: String,
    pub private_key: String,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub serial_number: Option<String>,
    pub issuer: Option<String>,
}

impl Certificate {
    pub fn new(
        domain: String,
        cert_chain: String,
        private_key: String,
        issued_at: SystemTime,
        expires_at: SystemTime,
    ) -> WafResult<Self> {
        Ok(Self {
            domain,
            cert_chain,
            private_key,
            issued_at,
            expires_at,
            serial_number: None, // Would be parsed from actual certificate
            issuer: None,        // Would be parsed from actual certificate
        })
    }
    
    /// Get certificate as PEM bundle (cert + chain + private key)
    pub fn as_pem_bundle(&self) -> String {
        format!("{}\n{}", self.cert_chain, self.private_key)
    }
    
    /// Get certificate chain only
    pub fn cert_chain_pem(&self) -> &str {
        &self.cert_chain
    }
    
    /// Get private key only
    pub fn private_key_pem(&self) -> &str {
        &self.private_key
    }
    
    /// Check if certificate is valid for domain
    pub fn is_valid_for_domain(&self, domain: &str) -> bool {
        self.domain == domain || 
        (self.domain.starts_with("*.") && domain.ends_with(&self.domain[2..]))
    }
}

/// Trait for certificate storage backends
#[async_trait]
pub trait CertificateStorage: Send + Sync {
    /// Save certificate to storage
    async fn save_certificate(&self, certificate: &Certificate) -> WafResult<()>;
    
    /// Load certificate from storage
    async fn load_certificate(&self, domain: &str) -> WafResult<Option<Certificate>>;
    
    /// Delete certificate from storage
    async fn delete_certificate(&self, domain: &str) -> WafResult<()>;
    
    /// List all stored domains
    async fn list_domains(&self) -> WafResult<Vec<String>>;
    
    /// Check if certificate exists for domain
    async fn certificate_exists(&self, domain: &str) -> WafResult<bool>;
}

/// File-based certificate storage
pub struct FileStorage {
    storage_path: PathBuf,
}

impl FileStorage {
    pub fn new(storage_path: PathBuf) -> Self {
        Self { storage_path }
    }
    
    fn cert_file_path(&self, domain: &str) -> PathBuf {
        self.storage_path.join(format!("{}.json", domain))
    }
    
    async fn ensure_storage_directory(&self) -> WafResult<()> {
        if !self.storage_path.exists() {
            tokio::fs::create_dir_all(&self.storage_path).await
                .map_err(|e| WafProxyError::Internal(
                    format!("Failed to create certificate storage directory: {}", e)
                ))?;
            info!("Created certificate storage directory: {:?}", self.storage_path);
        }
        Ok(())
    }
}

#[async_trait]
impl CertificateStorage for FileStorage {
    async fn save_certificate(&self, certificate: &Certificate) -> WafResult<()> {
        self.ensure_storage_directory().await?;
        
        let cert_file = self.cert_file_path(&certificate.domain);
        let cert_json = serde_json::to_string_pretty(certificate)
            .map_err(|e| WafProxyError::Internal(format!("Failed to serialize certificate: {}", e)))?;
        
        tokio::fs::write(&cert_file, cert_json).await
            .map_err(|e| WafProxyError::Internal(
                format!("Failed to write certificate file {}: {}", cert_file.display(), e)
            ))?;
        
        info!("Saved certificate for domain: {}", certificate.domain);
        Ok(())
    }
    
    async fn load_certificate(&self, domain: &str) -> WafResult<Option<Certificate>> {
        let cert_file = self.cert_file_path(domain);
        
        if !cert_file.exists() {
            return Ok(None);
        }
        
        let cert_json = tokio::fs::read_to_string(&cert_file).await
            .map_err(|e| WafProxyError::Internal(
                format!("Failed to read certificate file {}: {}", cert_file.display(), e)
            ))?;
        
        let certificate: Certificate = serde_json::from_str(&cert_json)
            .map_err(|e| WafProxyError::Internal(
                format!("Failed to deserialize certificate: {}", e)
            ))?;
        
        debug!("Loaded certificate for domain: {}", domain);
        Ok(Some(certificate))
    }
    
    async fn delete_certificate(&self, domain: &str) -> WafResult<()> {
        let cert_file = self.cert_file_path(domain);
        
        if cert_file.exists() {
            tokio::fs::remove_file(&cert_file).await
                .map_err(|e| WafProxyError::Internal(
                    format!("Failed to delete certificate file {}: {}", cert_file.display(), e)
                ))?;
            info!("Deleted certificate for domain: {}", domain);
        }
        
        Ok(())
    }
    
    async fn list_domains(&self) -> WafResult<Vec<String>> {
        if !self.storage_path.exists() {
            return Ok(vec![]);
        }
        
        let mut domains = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.storage_path).await
            .map_err(|e| WafProxyError::Internal(
                format!("Failed to read certificate storage directory: {}", e)
            ))?;
        
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| WafProxyError::Internal(format!("Failed to read directory entry: {}", e)))? {
            
            let path = entry.path();
            if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    domains.push(stem.to_string());
                }
            }
        }
        
        Ok(domains)
    }
    
    async fn certificate_exists(&self, domain: &str) -> WafResult<bool> {
        Ok(self.cert_file_path(domain).exists())
    }
}

/// In-memory certificate storage (for testing or temporary use)
pub struct InMemoryStorage {
    certificates: RwLock<HashMap<String, Certificate>>,
}

impl InMemoryStorage {
    pub fn new() -> Self {
        Self {
            certificates: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl CertificateStorage for InMemoryStorage {
    async fn save_certificate(&self, certificate: &Certificate) -> WafResult<()> {
        let mut certs = self.certificates.write().await;
        certs.insert(certificate.domain.clone(), certificate.clone());
        info!("Saved certificate for domain: {} (in-memory)", certificate.domain);
        Ok(())
    }
    
    async fn load_certificate(&self, domain: &str) -> WafResult<Option<Certificate>> {
        let certs = self.certificates.read().await;
        Ok(certs.get(domain).cloned())
    }
    
    async fn delete_certificate(&self, domain: &str) -> WafResult<()> {
        let mut certs = self.certificates.write().await;
        if certs.remove(domain).is_some() {
            info!("Deleted certificate for domain: {} (in-memory)", domain);
        }
        Ok(())
    }
    
    async fn list_domains(&self) -> WafResult<Vec<String>> {
        let certs = self.certificates.read().await;
        Ok(certs.keys().cloned().collect())
    }
    
    async fn certificate_exists(&self, domain: &str) -> WafResult<bool> {
        let certs = self.certificates.read().await;
        Ok(certs.contains_key(domain))
    }
}

/// Encrypted file storage (for production use)
pub struct EncryptedFileStorage {
    file_storage: FileStorage,
    encryption_key: Vec<u8>,
}

impl EncryptedFileStorage {
    pub fn new(storage_path: PathBuf, encryption_key: Vec<u8>) -> Self {
        Self {
            file_storage: FileStorage::new(storage_path),
            encryption_key,
        }
    }
    
    fn encrypt_data(&self, data: &str) -> WafResult<Vec<u8>> {
        // In a real implementation, this would use a proper encryption library
        // like `aes-gcm` or `chacha20poly1305`
        // For this example, we'll just return the data as bytes (not actually encrypted)
        warn!("Certificate encryption not implemented - using plain text storage");
        Ok(data.as_bytes().to_vec())
    }
    
    fn decrypt_data(&self, encrypted_data: &[u8]) -> WafResult<String> {
        // In a real implementation, this would decrypt the data
        String::from_utf8(encrypted_data.to_vec())
            .map_err(|e| WafProxyError::Internal(format!("Failed to decrypt certificate data: {}", e)))
    }
}

#[async_trait]
impl CertificateStorage for EncryptedFileStorage {
    async fn save_certificate(&self, certificate: &Certificate) -> WafResult<()> {
        let cert_json = serde_json::to_string_pretty(certificate)
            .map_err(|e| WafProxyError::Internal(format!("Failed to serialize certificate: {}", e)))?;
        
        let encrypted_data = self.encrypt_data(&cert_json)?;
        
        // Create a temporary certificate with encrypted data
        // In a real implementation, you'd store the encrypted bytes directly
        let encrypted_cert = Certificate {
            domain: certificate.domain.clone(),
            cert_chain: base64::encode(&encrypted_data),
            private_key: "encrypted".to_string(),
            issued_at: certificate.issued_at,
            expires_at: certificate.expires_at,
            serial_number: certificate.serial_number.clone(),
            issuer: certificate.issuer.clone(),
        };
        
        self.file_storage.save_certificate(&encrypted_cert).await
    }
    
    async fn load_certificate(&self, domain: &str) -> WafResult<Option<Certificate>> {
        if let Some(encrypted_cert) = self.file_storage.load_certificate(domain).await? {
            let encrypted_data = base64::decode(&encrypted_cert.cert_chain)
                .map_err(|e| WafProxyError::Internal(format!("Failed to decode certificate data: {}", e)))?;
            
            let decrypted_json = self.decrypt_data(&encrypted_data)?;
            let certificate: Certificate = serde_json::from_str(&decrypted_json)
                .map_err(|e| WafProxyError::Internal(format!("Failed to deserialize certificate: {}", e)))?;
            
            Ok(Some(certificate))
        } else {
            Ok(None)
        }
    }
    
    async fn delete_certificate(&self, domain: &str) -> WafResult<()> {
        self.file_storage.delete_certificate(domain).await
    }
    
    async fn list_domains(&self) -> WafResult<Vec<String>> {
        self.file_storage.list_domains().await
    }
    
    async fn certificate_exists(&self, domain: &str) -> WafResult<bool> {
        self.file_storage.certificate_exists(domain).await
    }
}

/// Certificate validation utilities
pub struct CertificateValidator;

impl CertificateValidator {
    /// Validate certificate chain
    pub fn validate_chain(_cert_chain: &str) -> WafResult<bool> {
        // In a real implementation, this would:
        // 1. Parse the certificate chain
        // 2. Verify signatures
        // 3. Check certificate validity periods
        // 4. Validate trust chain to root CA
        
        // For now, assume all certificates are valid
        Ok(true)
    }
    
    /// Extract certificate information
    pub fn extract_info(_cert_pem: &str) -> WafResult<HashMap<String, String>> {
        // In a real implementation, this would parse the certificate
        // and extract subject, issuer, validity dates, etc.
        
        let mut info = HashMap::new();
        info.insert("subject".to_string(), "CN=example.com".to_string());
        info.insert("issuer".to_string(), "Let's Encrypt Authority X3".to_string());
        info.insert("serial".to_string(), "123456789".to_string());
        
        Ok(info)
    }
    
    /// Check if certificate matches private key
    pub fn verify_key_pair(_cert_pem: &str, _key_pem: &str) -> WafResult<bool> {
        // In a real implementation, this would verify that the certificate
        // and private key are a matching pair
        Ok(true)
    }
}
