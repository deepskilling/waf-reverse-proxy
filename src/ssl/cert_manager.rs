// Certificate Manager - Handles certificate lifecycle and ACME protocol

use std::sync::Arc;
use std::time::{Duration, SystemTime};
use anyhow::Result;
use tracing::{info, warn, error, debug};
use tokio::sync::RwLock;

use crate::config::SslConfig;
use crate::error::{WafProxyError, Result as WafResult};
use super::{AcmeClient, CertificateStorage, Certificate};

/// Manages SSL/TLS certificates with automatic provisioning and renewal
pub struct CertificateManager {
    config: SslConfig,
    acme_client: Option<Arc<AcmeClient>>,
    storage: Arc<dyn CertificateStorage>,
    statistics: Arc<RwLock<CertificateStatistics>>,
}

#[derive(Debug, Default)]
struct CertificateStatistics {
    certificates_issued: u64,
    certificates_renewed: u64,
    issuance_failures: u64,
    renewal_failures: u64,
    last_issuance: Option<SystemTime>,
    last_renewal: Option<SystemTime>,
}

impl CertificateManager {
    pub async fn new(
        config: SslConfig,
        storage: Arc<dyn CertificateStorage>,
    ) -> WafResult<Self> {
        let acme_client = if config.auto_provision {
            Some(Arc::new(
                AcmeClient::new(
                    config.acme_directory_url.clone(),
                    config.acme_email.clone(),
                ).await?
            ))
        } else {
            None
        };
        
        Ok(Self {
            config,
            acme_client,
            storage,
            statistics: Arc::new(RwLock::new(CertificateStatistics::default())),
        })
    }
    
    /// Request a new certificate for the given domain
    pub async fn request_certificate(&self, domain: &str) -> WafResult<Certificate> {
        info!("Requesting new certificate for domain: {}", domain);
        
        let acme_client = self.acme_client.as_ref()
            .ok_or_else(|| WafProxyError::Internal("ACME client not configured".to_string()))?;
        
        // Create certificate signing request
        let (private_key, csr) = self.generate_csr(domain)?;
        
        // Request certificate through ACME
        match acme_client.request_certificate(domain, &csr).await {
            Ok(cert_chain) => {
                let certificate = Certificate::new(
                    domain.to_string(),
                    cert_chain,
                    private_key,
                    SystemTime::now(),
                    SystemTime::now() + Duration::from_secs(90 * 24 * 3600), // 90 days
                )?;
                
                // Store certificate
                self.storage.save_certificate(&certificate).await?;
                
                // Update statistics
                let mut stats = self.statistics.write().await;
                stats.certificates_issued += 1;
                stats.last_issuance = Some(SystemTime::now());
                drop(stats);
                
                info!("Successfully issued certificate for domain: {}", domain);
                Ok(certificate)
            }
            Err(e) => {
                error!("Failed to request certificate for {}: {}", domain, e);
                
                let mut stats = self.statistics.write().await;
                stats.issuance_failures += 1;
                drop(stats);
                
                Err(WafProxyError::CertificateError {
                    domain: domain.to_string(),
                    error: e.to_string(),
                }.into())
            }
        }
    }
    
    /// Renew an existing certificate
    pub async fn renew_certificate(&self, domain: &str) -> WafResult<Certificate> {
        info!("Renewing certificate for domain: {}", domain);
        
        // Load existing certificate to check if renewal is needed
        let existing_cert = self.storage.load_certificate(domain).await?
            .ok_or_else(|| WafProxyError::Internal(
                format!("No existing certificate found for domain: {}", domain)
            ))?;
        
        if !existing_cert.needs_renewal() {
            debug!("Certificate for {} does not need renewal yet", domain);
            return Ok(existing_cert);
        }
        
        // Request new certificate (same process as initial request)
        match self.request_certificate(domain).await {
            Ok(new_cert) => {
                let mut stats = self.statistics.write().await;
                stats.certificates_renewed += 1;
                stats.last_renewal = Some(SystemTime::now());
                drop(stats);
                
                info!("Successfully renewed certificate for domain: {}", domain);
                Ok(new_cert)
            }
            Err(e) => {
                error!("Failed to renew certificate for {}: {}", domain, e);
                
                let mut stats = self.statistics.write().await;
                stats.renewal_failures += 1;
                drop(stats);
                
                Err(e)
            }
        }
    }
    
    /// Generate Certificate Signing Request (CSR)
    fn generate_csr(&self, domain: &str) -> WafResult<(String, String)> {
        use rcgen::{Certificate as RcgenCert, CertificateParams, DistinguishedName};
        
        let mut params = CertificateParams::new(vec![domain.to_string()]);
        params.distinguished_name = DistinguishedName::new();
        
        let cert = RcgenCert::from_params(params)
            .map_err(|e| WafProxyError::Internal(format!("Failed to generate CSR: {}", e)))?;
        
        let private_key_pem = cert.serialize_private_key_pem();
        let csr_pem = cert.serialize_request_pem()
            .map_err(|e| WafProxyError::Internal(format!("Failed to serialize CSR: {}", e)))?;
        
        Ok((private_key_pem, csr_pem))
    }
    
    /// Validate domain ownership (HTTP-01 challenge handler)
    pub async fn handle_acme_challenge(
        &self,
        domain: &str,
        token: &str,
        key_authorization: &str,
    ) -> WafResult<()> {
        info!("Handling ACME challenge for domain: {}", domain);
        
        // In a real implementation, you would:
        // 1. Store the key authorization in a temporary location
        // 2. Serve it at /.well-known/acme-challenge/{token}
        // 3. The ACME client would validate this
        
        // For this implementation, we'll assume the challenge is handled
        // by the main HTTP server serving the /.well-known path
        
        debug!("ACME challenge: token={}, key_auth={}", token, key_authorization);
        
        // Store challenge response temporarily (this would be picked up by the HTTP server)
        tokio::fs::create_dir_all(".well-known/acme-challenge").await
            .map_err(|e| WafProxyError::Internal(format!("Failed to create challenge directory: {}", e)))?;
        
        tokio::fs::write(
            format!(".well-known/acme-challenge/{}", token),
            key_authorization
        ).await
        .map_err(|e| WafProxyError::Internal(format!("Failed to write challenge file: {}", e)))?;
        
        // Clean up after a delay (challenge files should be temporary)
        let token_cleanup = token.to_string();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(300)).await; // 5 minutes
            let _ = tokio::fs::remove_file(format!(".well-known/acme-challenge/{}", token_cleanup)).await;
        });
        
        Ok(())
    }
    
    /// Get certificate management statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let stats = self.statistics.read().await;
        
        serde_json::json!({
            "certificates_issued": stats.certificates_issued,
            "certificates_renewed": stats.certificates_renewed,
            "issuance_failures": stats.issuance_failures,
            "renewal_failures": stats.renewal_failures,
            "success_rate": if stats.certificates_issued + stats.issuance_failures > 0 {
                stats.certificates_issued as f64 / (stats.certificates_issued + stats.issuance_failures) as f64
            } else {
                0.0
            },
            "renewal_success_rate": if stats.certificates_renewed + stats.renewal_failures > 0 {
                stats.certificates_renewed as f64 / (stats.certificates_renewed + stats.renewal_failures) as f64
            } else {
                0.0
            },
            "last_issuance": stats.last_issuance.map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()),
            "last_renewal": stats.last_renewal.map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()),
        })
    }
    
    /// Load certificate from storage
    pub async fn load_certificate(&self, domain: &str) -> WafResult<Option<Certificate>> {
        self.storage.load_certificate(domain).await
    }
    
    /// List all managed domains
    pub async fn list_domains(&self) -> WafResult<Vec<String>> {
        self.storage.list_domains().await
    }
}

/// Utility functions for certificate validation
impl Certificate {
    /// Check if certificate needs renewal (within 30 days of expiry)
    pub fn needs_renewal(&self) -> bool {
        if let Ok(time_to_expiry) = self.expires_at.duration_since(SystemTime::now()) {
            time_to_expiry < Duration::from_secs(30 * 24 * 3600) // 30 days
        } else {
            true // Already expired
        }
    }
    
    /// Check if certificate is expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }
    
    /// Get days until expiration
    pub fn days_until_expiration(&self) -> i64 {
        if let Ok(duration) = self.expires_at.duration_since(SystemTime::now()) {
            (duration.as_secs() / (24 * 3600)) as i64
        } else {
            -1 // Already expired
        }
    }
}
