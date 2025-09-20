// ACME Client - Let's Encrypt integration for automatic certificate provisioning

use std::collections::HashMap;
use std::time::Duration;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};

use crate::error::{WafProxyError, Result as WafResult};

/// ACME client for Let's Encrypt certificate provisioning
pub struct AcmeClient {
    directory_url: String,
    email: String,
    http_client: reqwest::Client,
    account_key: String,
    directory: Option<AcmeDirectory>,
}

#[derive(Debug, Deserialize)]
struct AcmeDirectory {
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
    #[serde(rename = "revokeCert")]
    revoke_cert: Option<String>,
    #[serde(rename = "keyChange")]
    key_change: Option<String>,
}

#[derive(Debug, Serialize)]
struct NewAccountRequest {
    contact: Vec<String>,
    #[serde(rename = "termsOfServiceAgreed")]
    terms_of_service_agreed: bool,
}

#[derive(Debug, Serialize)]
struct NewOrderRequest {
    identifiers: Vec<Identifier>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    identifier_type: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct OrderResponse {
    status: String,
    expires: Option<String>,
    identifiers: Vec<Identifier>,
    authorizations: Vec<String>,
    finalize: String,
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Authorization {
    identifier: Identifier,
    status: String,
    expires: Option<String>,
    challenges: Vec<Challenge>,
}

#[derive(Debug, Deserialize)]
struct Challenge {
    #[serde(rename = "type")]
    challenge_type: String,
    status: String,
    url: String,
    token: String,
}

impl AcmeClient {
    pub async fn new(directory_url: String, email: String) -> WafResult<Self> {
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("WAF-ReverseProxy-ACME/1.0")
            .build()
            .map_err(|e| WafProxyError::Internal(format!("Failed to create HTTP client: {}", e)))?;
        
        // Generate account key pair
        let account_key = Self::generate_account_key()?;
        
        let mut client = Self {
            directory_url,
            email,
            http_client,
            account_key,
            directory: None,
        };
        
        // Initialize ACME directory
        client.initialize_directory().await?;
        
        // Create/register ACME account
        client.create_account().await?;
        
        Ok(client)
    }
    
    async fn initialize_directory(&mut self) -> WafResult<()> {
        info!("Initializing ACME directory from: {}", self.directory_url);
        
        let response = self.http_client
            .get(&self.directory_url)
            .send()
            .await
            .map_err(|e| WafProxyError::Internal(format!("Failed to fetch ACME directory: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(WafProxyError::Internal(
                format!("ACME directory request failed with status: {}", response.status())
            ));
        }
        
        let directory: AcmeDirectory = response.json().await
            .map_err(|e| WafProxyError::Internal(format!("Failed to parse ACME directory: {}", e)))?;
        
        debug!("ACME directory initialized: {:?}", directory);
        self.directory = Some(directory);
        
        Ok(())
    }
    
    async fn create_account(&self) -> WafResult<()> {
        let directory = self.directory.as_ref()
            .ok_or_else(|| WafProxyError::Internal("ACME directory not initialized".to_string()))?;
        
        info!("Creating ACME account for: {}", self.email);
        
        let account_request = NewAccountRequest {
            contact: vec![format!("mailto:{}", self.email)],
            terms_of_service_agreed: true,
        };
        
        let payload = serde_json::to_string(&account_request)
            .map_err(|e| WafProxyError::Internal(format!("Failed to serialize account request: {}", e)))?;
        
        let signed_payload = self.sign_payload(&directory.new_account, &payload)?;
        
        let response = self.http_client
            .post(&directory.new_account)
            .header("Content-Type", "application/jose+json")
            .body(signed_payload)
            .send()
            .await
            .map_err(|e| WafProxyError::Internal(format!("Failed to create ACME account: {}", e)))?;
        
        if response.status().is_success() || response.status() == reqwest::StatusCode::CONFLICT {
            info!("ACME account ready");
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(WafProxyError::Internal(
                format!("ACME account creation failed: {} - {}", response.status(), error_text)
            ))
        }
    }
    
    pub async fn request_certificate(&self, domain: &str, csr_pem: &str) -> WafResult<String> {
        info!("Requesting certificate for domain: {}", domain);
        
        // Step 1: Create new order
        let order_url = self.create_order(domain).await?;
        
        // Step 2: Get order details and authorizations
        let order = self.get_order(&order_url).await?;
        
        // Step 3: Complete challenges for each authorization
        for auth_url in &order.authorizations {
            self.complete_authorization(auth_url, domain).await?;
        }
        
        // Step 4: Finalize order with CSR
        self.finalize_order(&order.finalize, csr_pem).await?;
        
        // Step 5: Download certificate
        let cert_url = self.wait_for_certificate(&order_url).await?;
        self.download_certificate(&cert_url).await
    }
    
    async fn create_order(&self, domain: &str) -> WafResult<String> {
        let directory = self.directory.as_ref()
            .ok_or_else(|| WafProxyError::Internal("ACME directory not initialized".to_string()))?;
        
        let order_request = NewOrderRequest {
            identifiers: vec![Identifier {
                identifier_type: "dns".to_string(),
                value: domain.to_string(),
            }],
        };
        
        let payload = serde_json::to_string(&order_request)
            .map_err(|e| WafProxyError::Internal(format!("Failed to serialize order request: {}", e)))?;
        
        let signed_payload = self.sign_payload(&directory.new_order, &payload)?;
        
        let response = self.http_client
            .post(&directory.new_order)
            .header("Content-Type", "application/jose+json")
            .body(signed_payload)
            .send()
            .await
            .map_err(|e| WafProxyError::Internal(format!("Failed to create order: {}", e)))?;
        
        if response.status() == reqwest::StatusCode::CREATED {
            if let Some(location) = response.headers().get("Location") {
                Ok(location.to_str().unwrap_or_default().to_string())
            } else {
                Err(WafProxyError::Internal("No Location header in order response".to_string()))
            }
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(WafProxyError::Internal(
                format!("Order creation failed: {} - {}", response.status(), error_text)
            ))
        }
    }
    
    async fn get_order(&self, order_url: &str) -> WafResult<OrderResponse> {
        let response = self.http_client
            .get(order_url)
            .send()
            .await
            .map_err(|e| WafProxyError::Internal(format!("Failed to get order: {}", e)))?;
        
        if response.status().is_success() {
            response.json().await
                .map_err(|e| WafProxyError::Internal(format!("Failed to parse order response: {}", e)))
        } else {
            Err(WafProxyError::Internal(
                format!("Get order failed: {}", response.status())
            ))
        }
    }
    
    async fn complete_authorization(&self, auth_url: &str, domain: &str) -> WafResult<()> {
        debug!("Completing authorization for: {}", domain);
        
        // Get authorization details
        let response = self.http_client
            .get(auth_url)
            .send()
            .await
            .map_err(|e| WafProxyError::Internal(format!("Failed to get authorization: {}", e)))?;
        
        let authorization: Authorization = response.json().await
            .map_err(|e| WafProxyError::Internal(format!("Failed to parse authorization: {}", e)))?;
        
        // Find HTTP-01 challenge
        let challenge = authorization.challenges.iter()
            .find(|c| c.challenge_type == "http-01")
            .ok_or_else(|| WafProxyError::Internal("No HTTP-01 challenge found".to_string()))?;
        
        // Create key authorization
        let key_authorization = format!("{}.{}", challenge.token, self.get_jwk_thumbprint()?);
        
        // Set up challenge response (this would be handled by the certificate manager)
        // For now, we'll assume the challenge is properly set up
        debug!("Challenge token: {}", challenge.token);
        debug!("Key authorization: {}", key_authorization);
        
        // Notify ACME server that challenge is ready
        let empty_payload = "{}";
        let signed_payload = self.sign_payload(&challenge.url, empty_payload)?;
        
        let response = self.http_client
            .post(&challenge.url)
            .header("Content-Type", "application/jose+json")
            .body(signed_payload)
            .send()
            .await
            .map_err(|e| WafProxyError::Internal(format!("Failed to notify challenge: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(WafProxyError::Internal(
                format!("Challenge notification failed: {}", response.status())
            ));
        }
        
        // Wait for challenge to be validated
        self.wait_for_challenge_completion(auth_url).await?;
        
        Ok(())
    }
    
    async fn wait_for_challenge_completion(&self, auth_url: &str) -> WafResult<()> {
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 30;
        const RETRY_DELAY: Duration = Duration::from_secs(2);
        
        while attempts < MAX_ATTEMPTS {
            tokio::time::sleep(RETRY_DELAY).await;
            
            let response = self.http_client
                .get(auth_url)
                .send()
                .await
                .map_err(|e| WafProxyError::Internal(format!("Failed to check authorization status: {}", e)))?;
            
            let authorization: Authorization = response.json().await
                .map_err(|e| WafProxyError::Internal(format!("Failed to parse authorization: {}", e)))?;
            
            match authorization.status.as_str() {
                "valid" => {
                    debug!("Authorization completed successfully");
                    return Ok(());
                }
                "invalid" => {
                    return Err(WafProxyError::Internal("Authorization failed".to_string()));
                }
                "pending" => {
                    debug!("Authorization still pending, retrying...");
                }
                _ => {
                    debug!("Authorization status: {}", authorization.status);
                }
            }
            
            attempts += 1;
        }
        
        Err(WafProxyError::Internal("Authorization timeout".to_string()))
    }
    
    async fn finalize_order(&self, finalize_url: &str, csr_pem: &str) -> WafResult<()> {
        // Convert PEM CSR to DER format
        let csr_der = self.pem_to_der(csr_pem)?;
        let csr_b64 = base64::encode(&csr_der);
        
        let finalize_request = serde_json::json!({
            "csr": csr_b64
        });
        
        let payload = finalize_request.to_string();
        let signed_payload = self.sign_payload(finalize_url, &payload)?;
        
        let response = self.http_client
            .post(finalize_url)
            .header("Content-Type", "application/jose+json")
            .body(signed_payload)
            .send()
            .await
            .map_err(|e| WafProxyError::Internal(format!("Failed to finalize order: {}", e)))?;
        
        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response.text().await.unwrap_or_default();
            Err(WafProxyError::Internal(
                format!("Order finalization failed: {} - {}", response.status(), error_text)
            ))
        }
    }
    
    async fn wait_for_certificate(&self, order_url: &str) -> WafResult<String> {
        let mut attempts = 0;
        const MAX_ATTEMPTS: u32 = 30;
        const RETRY_DELAY: Duration = Duration::from_secs(2);
        
        while attempts < MAX_ATTEMPTS {
            tokio::time::sleep(RETRY_DELAY).await;
            
            let order = self.get_order(order_url).await?;
            
            match order.status.as_str() {
                "valid" => {
                    if let Some(cert_url) = order.certificate {
                        return Ok(cert_url);
                    }
                }
                "invalid" => {
                    return Err(WafProxyError::Internal("Order failed".to_string()));
                }
                _ => {
                    debug!("Order status: {}, waiting...", order.status);
                }
            }
            
            attempts += 1;
        }
        
        Err(WafProxyError::Internal("Certificate issuance timeout".to_string()))
    }
    
    async fn download_certificate(&self, cert_url: &str) -> WafResult<String> {
        let response = self.http_client
            .get(cert_url)
            .send()
            .await
            .map_err(|e| WafProxyError::Internal(format!("Failed to download certificate: {}", e)))?;
        
        if response.status().is_success() {
            response.text().await
                .map_err(|e| WafProxyError::Internal(format!("Failed to read certificate: {}", e)))
        } else {
            Err(WafProxyError::Internal(
                format!("Certificate download failed: {}", response.status())
            ))
        }
    }
    
    // Utility methods for ACME protocol
    
    fn generate_account_key() -> WafResult<String> {
        // In a real implementation, this would generate an actual RSA or ECDSA key
        // For this example, we'll return a placeholder
        Ok("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n".to_string())
    }
    
    fn sign_payload(&self, url: &str, payload: &str) -> WafResult<String> {
        // In a real implementation, this would:
        // 1. Create JWS (JSON Web Signature) with the account key
        // 2. Sign the payload with proper JOSE headers
        // 3. Return the signed JWS
        
        // For this example, we'll return a mock signed payload
        let mock_jws = serde_json::json!({
            "protected": base64::encode(format!(r#"{{"alg":"RS256","jwk":{{"kty":"RSA"}},"nonce":"mock","url":"{}"}}"#, url)),
            "payload": base64::encode(payload),
            "signature": "mock_signature"
        });
        
        Ok(mock_jws.to_string())
    }
    
    fn get_jwk_thumbprint(&self) -> WafResult<String> {
        // Return mock thumbprint for this example
        Ok("mock_jwk_thumbprint".to_string())
    }
    
    fn pem_to_der(&self, pem: &str) -> WafResult<Vec<u8>> {
        // In a real implementation, this would parse PEM and convert to DER
        // For now, return empty DER data
        Ok(vec![])
    }
}
