#![allow(dead_code)]

use std::sync::Arc;
use std::time::Instant;
use std::collections::HashMap;
use anyhow::Result;
// Removed unused DashMap import
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, warn, info};

use crate::config::{JwtConfig, CircuitBreakerConfig};
use crate::error::{WafProxyError, Result as WafResult};

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: Option<String>,
    pub aud: Option<String>,
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// JWT validator for request authentication
pub struct JwtValidator {
    config: Arc<RwLock<JwtConfig>>,
    encoding_key: Option<EncodingKey>,
    decoding_key: Option<DecodingKey>,
    validation: Validation,
    statistics: Arc<RwLock<JwtStatistics>>,
}

#[derive(Debug, Default)]
struct JwtStatistics {
    total_validations: u64,
    successful_validations: u64,
    failed_validations: u64,
    expired_tokens: u64,
    invalid_signatures: u64,
    missing_claims: u64,
}

impl JwtValidator {
    pub fn new(config: &JwtConfig) -> Result<Self> {
        let algorithm = match config.algorithm.as_str() {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            _ => return Err(anyhow::anyhow!("Unsupported JWT algorithm: {}", config.algorithm)),
        };
        
        let encoding_key = if config.algorithm.starts_with("HS") {
            Some(EncodingKey::from_secret(config.secret.as_bytes()))
        } else {
            None // For RS algorithms, you'd load from a private key file
        };
        
        let decoding_key = if config.algorithm.starts_with("HS") {
            Some(DecodingKey::from_secret(config.secret.as_bytes()))
        } else {
            None // For RS algorithms, you'd load from a public key file
        };
        
        let mut validation = Validation::new(algorithm);
        validation.required_spec_claims.clear();
        
        // Add required claims from config
        for claim in &config.required_claims {
            validation.required_spec_claims.insert(claim.clone());
        }
        
        Ok(Self {
            config: Arc::new(RwLock::new(config.clone())),
            encoding_key,
            decoding_key,
            validation,
            statistics: Arc::new(RwLock::new(JwtStatistics::default())),
        })
    }
    
    /// Validate a JWT token
    pub async fn validate_token(&self, token: &str) -> WafResult<Claims> {
        let config = self.config.read().await;
        
        if !config.enabled {
            return Err(WafProxyError::Auth("JWT validation is disabled".to_string()));
        }
        
        let mut stats = self.statistics.write().await;
        stats.total_validations += 1;
        drop(stats);
        
        let decoding_key = self.decoding_key.as_ref()
            .ok_or_else(|| WafProxyError::Auth("JWT decoding key not configured".to_string()))?;
        
        match decode::<Claims>(token, decoding_key, &self.validation) {
            Ok(token_data) => {
                let claims = token_data.claims;
                
                // Verify required claims
                for required_claim in &config.required_claims {
                    match required_claim.as_str() {
                        "sub" => {
                            if claims.sub.is_empty() {
                                let mut stats = self.statistics.write().await;
                                stats.missing_claims += 1;
                                return Err(WafProxyError::Auth("Missing 'sub' claim".to_string()));
                            }
                        }
                        "exp" => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs() as usize;
                            
                            if claims.exp <= now {
                                let mut stats = self.statistics.write().await;
                                stats.expired_tokens += 1;
                                return Err(WafProxyError::Auth("Token has expired".to_string()));
                            }
                        }
                        custom_claim => {
                            if !claims.custom.contains_key(custom_claim) {
                                let mut stats = self.statistics.write().await;
                                stats.missing_claims += 1;
                                return Err(WafProxyError::Auth(
                                    format!("Missing required claim: {}", custom_claim)
                                ));
                            }
                        }
                    }
                }
                
                let mut stats = self.statistics.write().await;
                stats.successful_validations += 1;
                
                debug!("JWT token validated successfully for subject: {}", claims.sub);
                Ok(claims)
            }
            Err(e) => {
                let mut stats = self.statistics.write().await;
                stats.failed_validations += 1;
                
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                        stats.invalid_signatures += 1;
                        warn!("Invalid JWT signature");
                    }
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        stats.expired_tokens += 1;
                        warn!("Expired JWT token");
                    }
                    _ => {
                        warn!("JWT validation error: {}", e);
                    }
                }
                
                Err(WafProxyError::Auth(format!("JWT validation failed: {}", e)))
            }
        }
    }
    
    /// Generate a new JWT token (for testing or internal use)
    pub async fn generate_token(&self, claims: &Claims) -> WafResult<String> {
        let config = self.config.read().await;
        
        if !config.enabled {
            return Err(WafProxyError::Auth("JWT generation is disabled".to_string()));
        }
        
        let encoding_key = self.encoding_key.as_ref()
            .ok_or_else(|| WafProxyError::Auth("JWT encoding key not configured".to_string()))?;
        
        let header = Header::new(match config.algorithm.as_str() {
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            _ => Algorithm::HS256,
        });
        
        encode(&header, claims, encoding_key)
            .map_err(|e| WafProxyError::Auth(format!("Failed to encode JWT: {}", e)))
    }
    
    /// Get JWT validator statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let stats = self.statistics.read().await;
        let config = self.config.read().await;
        
        serde_json::json!({
            "enabled": config.enabled,
            "algorithm": config.algorithm,
            "statistics": {
                "total_validations": stats.total_validations,
                "successful_validations": stats.successful_validations,
                "failed_validations": stats.failed_validations,
                "success_rate": if stats.total_validations > 0 {
                    stats.successful_validations as f64 / stats.total_validations as f64
                } else {
                    0.0
                },
                "expired_tokens": stats.expired_tokens,
                "invalid_signatures": stats.invalid_signatures,
                "missing_claims": stats.missing_claims,
            },
            "required_claims": config.required_claims,
        })
    }
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Failing fast
    HalfOpen, // Testing if service recovered
}

/// Circuit breaker for upstream services
#[derive(Clone)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitState>>,
    failure_count: Arc<RwLock<u32>>,
    last_failure_time: Arc<RwLock<Option<Instant>>>,
    statistics: Arc<RwLock<CircuitBreakerStatistics>>,
    half_open_requests: Arc<RwLock<u32>>,
}

#[derive(Debug, Default)]
struct CircuitBreakerStatistics {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    rejected_requests: u64,
    state_changes: u64,
    recovery_attempts: u64,
}

impl CircuitBreaker {
    pub fn new(config: &CircuitBreakerConfig) -> Self {
        Self {
            config: config.clone(),
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: Arc::new(RwLock::new(0)),
            last_failure_time: Arc::new(RwLock::new(None)),
            statistics: Arc::new(RwLock::new(CircuitBreakerStatistics::default())),
            half_open_requests: Arc::new(RwLock::new(0)),
        }
    }
    
    /// Check if request should be allowed through the circuit breaker
    pub async fn allow_request(&self) -> WafResult<CircuitBreakerPermit> {
        if !self.config.enabled {
            return Ok(CircuitBreakerPermit::new(self.clone()));
        }
        
        let mut stats = self.statistics.write().await;
        stats.total_requests += 1;
        drop(stats);
        
        let state = *self.state.read().await;
        
        match state {
            CircuitState::Closed => {
                // Normal operation - allow request
                Ok(CircuitBreakerPermit::new(self.clone()))
            }
            CircuitState::Open => {
                // Check if recovery timeout has passed
                let last_failure = *self.last_failure_time.read().await;
                if let Some(last_failure) = last_failure {
                    if last_failure.elapsed() >= self.config.recovery_timeout {
                        // Transition to half-open state
                        *self.state.write().await = CircuitState::HalfOpen;
                        *self.half_open_requests.write().await = 0;
                        
                        let mut stats = self.statistics.write().await;
                        stats.state_changes += 1;
                        stats.recovery_attempts += 1;
                        
                        info!("Circuit breaker transitioning to half-open state");
                        Ok(CircuitBreakerPermit::new(self.clone()))
                    } else {
                        // Still in recovery period - reject request
                        let mut stats = self.statistics.write().await;
                        stats.rejected_requests += 1;
                        
                        warn!("Circuit breaker open - rejecting request");
                        Err(WafProxyError::CircuitBreakerOpen(
                            "Service temporarily unavailable".to_string()
                        ))
                    }
                } else {
                    // No last failure time recorded - allow request
                    Ok(CircuitBreakerPermit::new(self.clone()))
                }
            }
            CircuitState::HalfOpen => {
                // Limited number of test requests allowed
                let mut half_open_requests = self.half_open_requests.write().await;
                
                if *half_open_requests < self.config.half_open_max_calls {
                    *half_open_requests += 1;
                    drop(half_open_requests);
                    
                    debug!("Circuit breaker half-open - allowing test request");
                    Ok(CircuitBreakerPermit::new(self.clone()))
                } else {
                    let mut stats = self.statistics.write().await;
                    stats.rejected_requests += 1;
                    
                    warn!("Circuit breaker half-open - max test requests reached");
                    Err(WafProxyError::CircuitBreakerOpen(
                        "Service testing limit reached".to_string()
                    ))
                }
            }
        }
    }
    
    /// Record a successful request
    pub async fn record_success(&self) {
        let mut stats = self.statistics.write().await;
        stats.successful_requests += 1;
        drop(stats);
        
        let state = *self.state.read().await;
        
        match state {
            CircuitState::Closed => {
                // Reset failure count on success
                *self.failure_count.write().await = 0;
            }
            CircuitState::HalfOpen => {
                // Successful test request - transition back to closed
                *self.state.write().await = CircuitState::Closed;
                *self.failure_count.write().await = 0;
                *self.half_open_requests.write().await = 0;
                
                let mut stats = self.statistics.write().await;
                stats.state_changes += 1;
                
                info!("Circuit breaker recovered - transitioning to closed state");
            }
            CircuitState::Open => {
                // Shouldn't happen, but handle gracefully
                debug!("Received success while circuit breaker is open");
            }
        }
        
        debug!("Circuit breaker recorded successful request");
    }
    
    /// Record a failed request
    pub async fn record_failure(&self) {
        let mut stats = self.statistics.write().await;
        stats.failed_requests += 1;
        drop(stats);
        
        let mut failure_count = self.failure_count.write().await;
        *failure_count += 1;
        let current_failures = *failure_count;
        drop(failure_count);
        
        *self.last_failure_time.write().await = Some(Instant::now());
        
        let state = *self.state.read().await;
        
        match state {
            CircuitState::Closed => {
                if current_failures >= self.config.failure_threshold {
                    // Transition to open state
                    *self.state.write().await = CircuitState::Open;
                    
                    let mut stats = self.statistics.write().await;
                    stats.state_changes += 1;
                    
                    warn!("Circuit breaker opened due to {} failures", current_failures);
                }
            }
            CircuitState::HalfOpen => {
                // Test request failed - back to open state
                *self.state.write().await = CircuitState::Open;
                *self.half_open_requests.write().await = 0;
                
                let mut stats = self.statistics.write().await;
                stats.state_changes += 1;
                
                warn!("Circuit breaker test failed - back to open state");
            }
            CircuitState::Open => {
                // Already open - just update failure time
                debug!("Circuit breaker recorded failure while open");
            }
        }
        
        debug!("Circuit breaker recorded failed request (total: {})", current_failures);
    }
    
    /// Get current circuit breaker state
    pub async fn get_state(&self) -> CircuitState {
        *self.state.read().await
    }
    
    /// Force circuit breaker to a specific state (for testing)
    pub async fn set_state(&self, new_state: CircuitState) {
        let mut state = self.state.write().await;
        *state = new_state;
        
        let mut stats = self.statistics.write().await;
        stats.state_changes += 1;
        
        info!("Circuit breaker state manually set to: {:?}", new_state);
    }
    
    /// Get circuit breaker statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let stats = self.statistics.read().await;
        let state = *self.state.read().await;
        let failure_count = *self.failure_count.read().await;
        let half_open_requests = *self.half_open_requests.read().await;
        let last_failure = *self.last_failure_time.read().await;
        
        serde_json::json!({
            "enabled": self.config.enabled,
            "current_state": format!("{:?}", state),
            "failure_count": failure_count,
            "failure_threshold": self.config.failure_threshold,
            "half_open_requests": half_open_requests,
            "max_half_open_requests": self.config.half_open_max_calls,
            "recovery_timeout_seconds": self.config.recovery_timeout.as_secs(),
            "last_failure_seconds_ago": last_failure.map(|t| t.elapsed().as_secs()),
            "statistics": {
                "total_requests": stats.total_requests,
                "successful_requests": stats.successful_requests,
                "failed_requests": stats.failed_requests,
                "rejected_requests": stats.rejected_requests,
                "success_rate": if stats.total_requests > 0 {
                    stats.successful_requests as f64 / stats.total_requests as f64
                } else {
                    0.0
                },
                "state_changes": stats.state_changes,
                "recovery_attempts": stats.recovery_attempts,
            }
        })
    }
}

/// Permit for circuit breaker requests
pub struct CircuitBreakerPermit {
    circuit_breaker: CircuitBreaker,
}

impl CircuitBreakerPermit {
    fn new(circuit_breaker: CircuitBreaker) -> Self {
        Self { circuit_breaker }
    }
    
    /// Record that the request was successful
    pub async fn success(self) {
        self.circuit_breaker.record_success().await;
    }
    
    /// Record that the request failed
    pub async fn failure(self) {
        self.circuit_breaker.record_failure().await;
    }
}
