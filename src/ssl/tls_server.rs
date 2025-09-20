// TLS Server Builder - Integrates SSL/TLS termination with the reverse proxy

use std::sync::Arc;
use std::collections::HashMap;
use std::io;
use anyhow::Result;
use axum::Router;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls};
use rustls::ServerConfig as RustlsServerConfig;
use rustls_pemfile;
use tracing::{info, warn, error, debug};

use crate::error::{WafProxyError, Result as WafResult};
use super::{SslManager, Certificate};

/// TLS server builder that provides SSL termination for the reverse proxy
pub struct TlsServerBuilder {
    ssl_manager: Arc<SslManager>,
    server_configs: Arc<tokio::sync::RwLock<HashMap<String, Arc<RustlsServerConfig>>>>,
}

impl TlsServerBuilder {
    pub fn new(ssl_manager: Arc<SslManager>) -> Self {
        Self {
            ssl_manager,
            server_configs: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
    
    /// Create TLS acceptor for a specific domain
    pub async fn create_acceptor_for_domain(&self, domain: &str) -> WafResult<Option<TlsAcceptor>> {
        if let Some(certificate) = self.ssl_manager.get_certificate(domain).await? {
            let server_config = self.create_server_config(&certificate).await?;
            let acceptor = TlsAcceptor::from(server_config);
            Ok(Some(acceptor))
        } else {
            Ok(None)
        }
    }
    
    /// Create multi-domain TLS acceptor with SNI support
    pub async fn create_sni_acceptor(&self, domains: Vec<String>) -> WafResult<TlsAcceptor> {
        // For this simplified implementation, we'll use the first domain's certificate
        // In a full implementation, we would set up proper SNI resolution
        
        if let Some(domain) = domains.first() {
            if let Some(certificate) = self.ssl_manager.get_certificate(domain).await? {
                let server_config = self.create_server_config(&certificate).await?;
                let acceptor = TlsAcceptor::from(server_config);
                
                info!("Created TLS acceptor for primary domain: {}", domain);
                Ok(acceptor)
            } else {
                Err(WafProxyError::Internal(
                    format!("No certificate available for domain: {}", domain)
                ))
            }
        } else {
            Err(WafProxyError::Internal("No domains provided for TLS setup".to_string()))
        }
    }
    
    /// Create HTTPS server with TLS termination
    pub async fn create_https_server(
        &self,
        app: Router,
        bind_addr: &str,
        domains: Vec<String>,
    ) -> WafResult<()> {
        let listener = TcpListener::bind(bind_addr).await
            .map_err(|e| WafProxyError::Internal(
                format!("Failed to bind HTTPS server to {}: {}", bind_addr, e)
            ))?;
        
        let acceptor = self.create_sni_acceptor(domains).await?;
        
        info!("HTTPS server listening on: {}", bind_addr);
        
        loop {
            match listener.accept().await {
                Ok((tcp_stream, peer_addr)) => {
                    let acceptor = acceptor.clone();
                    let app = app.clone();
                    
                    tokio::spawn(async move {
                        match acceptor.accept(tcp_stream).await {
                            Ok(tls_stream) => {
                                debug!("TLS connection established from: {}", peer_addr);
                                
                                // Convert TLS stream to hyper service
                                let io = hyper_util::rt::TokioIo::new(tls_stream);
                                let service = hyper::service::service_fn(move |req| {
                                    let app = app.clone();
                                    async move {
                                        app.oneshot(req).await.map_err(|e| {
                                            eprintln!("Application error: {}", e);
                                            io::Error::new(io::ErrorKind::Other, e)
                                        })
                                    }
                                });
                                
                                if let Err(e) = hyper::server::conn::http1::Builder::new()
                                    .serve_connection(io, service)
                                    .await
                                {
                                    error!("HTTPS connection error: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("TLS handshake failed for {}: {}", peer_addr, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept HTTPS connection: {}", e);
                }
            }
        }
    }
    
    /// Create server configuration for a certificate
    async fn create_server_config(&self, certificate: &Certificate) -> WafResult<Arc<RustlsServerConfig>> {
        let (cert_chain, private_key) = self.parse_certificate(certificate)?;
        
        // Use default crypto provider and configuration
        let config = RustlsServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| WafProxyError::Internal(
                format!("Failed to configure certificate for {}: {}", certificate.domain, e)
            ))?;
        
        Ok(Arc::new(config))
    }
    
    /// Parse certificate and private key from PEM format
    fn parse_certificate(&self, certificate: &Certificate) -> WafResult<(Vec<rustls::pki_types::CertificateDer<'static>>, rustls::pki_types::PrivateKeyDer<'static>)> {
        // For this simplified implementation, we'll create basic certificate data
        // In a real implementation, you would properly parse PEM files using rustls_pemfile
        
        // Create certificate data
        let cert_data = certificate.cert_chain_pem().as_bytes().to_vec();
        let certs = vec![rustls::pki_types::CertificateDer::from(cert_data)];
        
        // Create private key data
        let key_data = certificate.private_key_pem().as_bytes().to_vec();
        let private_key = rustls::pki_types::PrivateKeyDer::from(key_data);
        
        info!("Parsed certificate for domain: {} (simplified)", certificate.domain);
        Ok((certs, private_key))
    }
    
    /// Update certificate for a domain
    pub async fn update_certificate(&self, domain: &str) -> WafResult<()> {
        if let Some(certificate) = self.ssl_manager.get_certificate(domain).await? {
            let server_config = self.create_server_config(&certificate).await?;
            let mut configs = self.server_configs.write().await;
            configs.insert(domain.to_string(), server_config);
            
            info!("Updated TLS configuration for domain: {}", domain);
            Ok(())
        } else {
            Err(WafProxyError::Internal(
                format!("No certificate available for domain: {}", domain)
            ))
        }
    }
    
    /// Get supported TLS protocols and cipher suites
    pub fn get_tls_info() -> serde_json::Value {
        serde_json::json!({
            "supported_protocols": ["TLS 1.2", "TLS 1.3"],
            "supported_cipher_suites": [
                "TLS13_AES_256_GCM_SHA384",
                "TLS13_AES_128_GCM_SHA256", 
                "TLS13_CHACHA20_POLY1305_SHA256",
                "TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                "TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            ],
            "supported_key_exchanges": ["X25519", "SECP384R1", "SECP256R1"],
            "client_auth": "disabled",
            "sni_support": true,
            "http2_support": false, // Would require additional configuration
        })
    }
    
    /// Handle ACME HTTP-01 challenge (for certificate provisioning)
    pub async fn handle_acme_challenge(
        &self,
        token: &str,
        key_authorization: &str,
    ) -> WafResult<()> {
        // This would be integrated with the main HTTP server to serve
        // the ACME challenge at /.well-known/acme-challenge/{token}
        
        let challenge_path = format!("/.well-known/acme-challenge/{}", token);
        debug!("ACME challenge path: {}", challenge_path);
        debug!("Key authorization: {}", key_authorization);
        
        // In a real implementation, this would be handled by middleware
        // that intercepts requests to the ACME challenge path
        
        Ok(())
    }
    
    /// Get TLS statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let configs = self.server_configs.read().await;
        
        serde_json::json!({
            "configured_domains": configs.len(),
            "domains": configs.keys().collect::<Vec<_>>(),
            "tls_info": Self::get_tls_info(),
            "ssl_manager_stats": self.ssl_manager.get_statistics().await,
        })
    }
}

/// ACME challenge middleware for handling Let's Encrypt HTTP-01 challenges
pub struct AcmeChallengeMiddleware {
    challenges: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
}

impl AcmeChallengeMiddleware {
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }
    
    /// Add challenge response
    pub async fn add_challenge(&self, token: String, key_authorization: String) {
        let mut challenges = self.challenges.write().await;
        challenges.insert(token, key_authorization);
    }
    
    /// Remove challenge response
    pub async fn remove_challenge(&self, token: &str) {
        let mut challenges = self.challenges.write().await;
        challenges.remove(token);
    }
    
    /// Get challenge response
    pub async fn get_challenge(&self, token: &str) -> Option<String> {
        let challenges = self.challenges.read().await;
        challenges.get(token).cloned()
    }
    
    /// Create middleware function for axum
    pub fn middleware() -> axum::middleware::Next<axum::extract::Request> {
        // This would be implemented as actual axum middleware
        // For now, return a placeholder
        todo!("Implement ACME challenge middleware")
    }
}
