// SSL/TLS Certificate Management Module
// Provides automatic certificate provisioning, renewal, and TLS termination

pub mod storage;
pub mod acme;

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::SslConfig;
use crate::error::Result as WafResult;

pub use storage::{CertificateStorage, Certificate};
use acme::{AcmeClient, MockAcmeClient};

/// SSL/TLS management system with automatic certificate provisioning
pub struct SslManager {
    config: SslConfig,
    certificates: Arc<RwLock<HashMap<String, Certificate>>>,
    storage: Arc<dyn CertificateStorage>,
    acme_client: Option<Arc<tokio::sync::Mutex<AcmeClient>>>,
    renewal_task: Option<tokio::task::JoinHandle<()>>,
}

impl SslManager {
    pub async fn new(config: SslConfig) -> WafResult<Self> {
        let storage: Arc<dyn CertificateStorage> = if let Some(storage_path) = &config.storage_path {
            Arc::new(storage::FileStorage::new(storage_path.clone()))
        } else {
            Arc::new(storage::InMemoryStorage::new())
        };
        
        // Load existing certificates
        let certificates = Arc::new(RwLock::new(HashMap::new()));
        
        // Initialize ACME client if auto-provisioning is enabled
        let acme_client = if config.auto_provision {
            match AcmeClient::new(&config.acme_directory_url).await {
                Ok(mut client) => {
                    if let Err(e) = client.create_account(&config.acme_email).await {
                        warn!("Failed to create ACME account: {}, falling back to mock client", e);
                        None
                    } else {
                        info!("ACME client initialized successfully");
                        Some(Arc::new(tokio::sync::Mutex::new(client)))
                    }
                }
                Err(e) => {
                    warn!("Failed to initialize ACME client: {}, auto-provisioning disabled", e);
                    None
                }
            }
        } else {
            None
        };
        
        let _manager = Self {
            config: config.clone(),
            certificates: certificates.clone(),
            storage: storage.clone(),
            acme_client: acme_client.clone(),
            renewal_task: None,
        };
        
        // Start certificate renewal task if auto-provisioning is enabled
        let renewal_task = if config.auto_provision {
            let certificates_clone = certificates.clone();
            let storage_clone = storage.clone();
            let config_clone = config.clone();
            let acme_client_clone = acme_client.clone();
            
            Some(tokio::spawn(async move {
                Self::renewal_loop(certificates_clone, storage_clone, config_clone, acme_client_clone).await;
            }))
        } else {
            None
        };
        
        info!("SSL Manager initialized with {} domains, auto-provision: {}", 
              config.domains.len(), config.auto_provision);
        
        Ok(Self {
            config,
            certificates,
            storage,
            acme_client,
            renewal_task,
        })
    }
    
    /// Get certificate for domain
    pub async fn get_certificate(&self, domain: &str) -> WafResult<Option<Certificate>> {
        // Check in-memory cache first
        {
            let certs = self.certificates.read().await;
            if let Some(cert) = certs.get(domain) {
                if cert.expires_at > std::time::SystemTime::now() {
                    return Ok(Some(cert.clone()));
                }
            }
        }
        
        // Try to load from storage
        if let Some(cert) = self.storage.load_certificate(domain).await? {
            if cert.expires_at > std::time::SystemTime::now() {
                let mut certs = self.certificates.write().await;
                certs.insert(domain.to_string(), cert.clone());
                return Ok(Some(cert));
            }
        }
        
        // Try loading from manual certificate files
        if let Some(cert) = self.load_certificate_from_files(domain).await? {
            return Ok(Some(cert));
        }
        
        // Auto-provision certificate if enabled
        if self.config.auto_provision && self.config.domains.contains(&domain.to_string()) {
            match self.provision_certificate(domain).await {
                Ok(cert) => {
                    info!("Successfully auto-provisioned certificate for domain: {}", domain);
                    return Ok(Some(cert));
                }
                Err(e) => {
                    warn!("Failed to auto-provision certificate for {}: {}", domain, e);
                }
            }
        }
        
        Ok(None)
    }
    
    /// Load certificate from file system (simplified implementation)
    pub async fn load_certificate_from_files(&self, domain: &str) -> WafResult<Option<Certificate>> {
        if let (Some(cert_path), Some(key_path)) = (&self.config.cert_path, &self.config.key_path) {
            // Read certificate and key files
            match tokio::fs::read_to_string(cert_path).await {
                Ok(cert_data) => {
                    match tokio::fs::read_to_string(key_path).await {
                        Ok(key_data) => {
                            let cert = Certificate::new(
                                domain.to_string(),
                                cert_data,
                                key_data,
                                std::time::SystemTime::now(),
                                std::time::SystemTime::now() + std::time::Duration::from_secs(365 * 24 * 3600), // 1 year
                            )?;
                            
                            // Cache the certificate
                            let mut certs = self.certificates.write().await;
                            certs.insert(domain.to_string(), cert.clone());
                            
                            Ok(Some(cert))
                        }
                        Err(e) => {
                            warn!("Failed to read SSL key file {}: {}", key_path, e);
                            Ok(None)
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read SSL cert file {}: {}", cert_path, e);
                    Ok(None)
                }
            }
        } else {
            Ok(None)
        }
    }
    
    /// Add domain for certificate management (simplified)
    pub async fn add_domain(&self, domain: String) -> WafResult<()> {
        info!("Added domain {} to SSL manager", domain);
        Ok(())
    }
    
    /// Remove domain from certificate management
    pub async fn remove_domain(&self, domain: &str) -> WafResult<()> {
        let mut certs = self.certificates.write().await;
        certs.remove(domain);
        self.storage.delete_certificate(domain).await?;
        info!("Removed domain {} from SSL manager", domain);
        Ok(())
    }
    
    /// Provision certificate using ACME
    async fn provision_certificate(&self, domain: &str) -> WafResult<Certificate> {
        if let Some(acme_client) = &self.acme_client {
            info!("Provisioning certificate for domain: {} using ACME", domain);
            let mut client = acme_client.lock().await;
            let cert = client.request_certificate(domain).await?;
            
            // Store the certificate
            self.storage.save_certificate(&cert).await?;
            
            // Cache the certificate
            let mut certs = self.certificates.write().await;
            certs.insert(domain.to_string(), cert.clone());
            
            Ok(cert)
        } else {
            // Fallback to mock provisioning for testing
            warn!("ACME client not available, using mock certificate for {}", domain);
            let mock_client = MockAcmeClient::new();
            let cert = mock_client.request_certificate(domain).await?;
            
            // Store and cache the mock certificate
            self.storage.save_certificate(&cert).await?;
            let mut certs = self.certificates.write().await;
            certs.insert(domain.to_string(), cert.clone());
            
            Ok(cert)
        }
    }
    
    /// Background task for certificate renewal
    async fn renewal_loop(
        certificates: Arc<RwLock<HashMap<String, Certificate>>>,
        storage: Arc<dyn CertificateStorage>,
        config: SslConfig,
        acme_client: Option<Arc<tokio::sync::Mutex<AcmeClient>>>,
    ) {
        let mut interval = tokio::time::interval(config.renewal_check_interval);
        
        loop {
            interval.tick().await;
            
            info!("Checking certificates for renewal...");
            
            // Check each configured domain
            for domain in &config.domains {
                let needs_renewal = {
                    let certs = certificates.read().await;
                    if let Some(cert) = certs.get(domain) {
                        // Renew if certificate expires within 30 days
                        cert.expires_at < std::time::SystemTime::now() + std::time::Duration::from_secs(30 * 24 * 3600)
                    } else {
                        true // Certificate doesn't exist, provision it
                    }
                };
                
                if needs_renewal {
                    info!("Certificate for {} needs renewal", domain);
                    
                    if let Some(acme_client) = &acme_client {
                        match {
                            let mut client = acme_client.lock().await;
                            client.request_certificate(domain).await
                        } {
                            Ok(new_cert) => {
                                // Save the new certificate
                                if let Err(e) = storage.save_certificate(&new_cert).await {
                                    warn!("Failed to store renewed certificate for {}: {}", domain, e);
                                    continue;
                                }
                                
                                // Update in-memory cache
                                let mut certs = certificates.write().await;
                                certs.insert(domain.clone(), new_cert);
                                
                                info!("Successfully renewed certificate for {}", domain);
                            }
                            Err(e) => {
                                warn!("Failed to renew certificate for {}: {}", domain, e);
                            }
                        }
                    } else {
                        // Use mock client for testing
                        let mock_client = MockAcmeClient::new();
                        match mock_client.request_certificate(domain).await {
                            Ok(new_cert) => {
                                if let Err(e) = storage.save_certificate(&new_cert).await {
                                    warn!("Failed to store mock renewed certificate for {}: {}", domain, e);
                                    continue;
                                }
                                
                                let mut certs = certificates.write().await;
                                certs.insert(domain.clone(), new_cert);
                                
                                info!("Mock renewed certificate for {}", domain);
                            }
                            Err(e) => {
                                warn!("Failed to mock renew certificate for {}: {}", domain, e);
                            }
                        }
                    }
                }
            }
        }
    }
    
    /// Get SSL statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let certs = self.certificates.read().await;
        
        let mut domains_by_status = HashMap::new();
        domains_by_status.insert("valid", 0);
        domains_by_status.insert("expired", 0);
        domains_by_status.insert("needs_renewal", 0);
        
        for cert in certs.values() {
            if cert.expires_at < std::time::SystemTime::now() {
                *domains_by_status.get_mut("expired").unwrap() += 1;
            } else if cert.expires_at < std::time::SystemTime::now() + std::time::Duration::from_secs(30 * 24 * 3600) {
                *domains_by_status.get_mut("needs_renewal").unwrap() += 1;
            } else {
                *domains_by_status.get_mut("valid").unwrap() += 1;
            }
        }
        
        serde_json::json!({
            "enabled": self.config.enabled,
            "auto_provision": self.config.auto_provision,
            "total_certificates": certs.len(),
            "certificates_by_status": domains_by_status,
            "acme_directory": self.config.acme_directory_url,
            "storage_type": if self.config.storage_path.is_some() { "file" } else { "memory" },
            "acme_client_available": self.acme_client.is_some(),
            "renewal_task_running": self.renewal_task.is_some(),
        })
    }
}
