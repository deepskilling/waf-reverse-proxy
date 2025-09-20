use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Application-wide error types
#[derive(Error, Debug)]
pub enum WafProxyError {
    #[error("Configuration error: {0}")]
    Config(#[from] anyhow::Error),
    
    #[error("WAF blocked request: {reason}")]
    WafBlocked { reason: String },
    
    #[error("Rate limit exceeded: {limit_type}")]
    RateLimitExceeded { limit_type: String },
    
    #[error("Upstream error: {0}")]
    Upstream(String),
    
    #[error("SSL/TLS error: {0}")]
    Ssl(String),
    
    #[error("Certificate error for domain {domain}: {error}")]
    CertificateError { domain: String, error: String },
    
    #[error("Authentication failed: {0}")]
    Auth(String),
    
    #[error("Authorization failed: {0}")]
    Authorization(String),
    
    #[error("Bad request: {0}")]
    BadRequest(String),
    
    #[error("Internal server error: {0}")]
    Internal(String),
    
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
    
    #[error("Timeout: {0}")]
    Timeout(String),
    
    #[error("Circuit breaker open: {0}")]
    CircuitBreakerOpen(String),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("HTTP error: {0}")]
    Http(#[from] hyper::Error),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

impl WafProxyError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            WafProxyError::WafBlocked { .. } => StatusCode::FORBIDDEN,
            WafProxyError::RateLimitExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
            WafProxyError::Auth(_) => StatusCode::UNAUTHORIZED,
            WafProxyError::Authorization(_) => StatusCode::FORBIDDEN,
            WafProxyError::BadRequest(_) => StatusCode::BAD_REQUEST,
            WafProxyError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            WafProxyError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
            WafProxyError::CircuitBreakerOpen(_) => StatusCode::SERVICE_UNAVAILABLE,
            WafProxyError::Upstream(_) => StatusCode::BAD_GATEWAY,
            WafProxyError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WafProxyError::Ssl(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WafProxyError::CertificateError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
            WafProxyError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WafProxyError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WafProxyError::Redis(_) => StatusCode::INTERNAL_SERVER_ERROR,
            WafProxyError::Json(_) => StatusCode::BAD_REQUEST,
            WafProxyError::Http(_) => StatusCode::BAD_GATEWAY,
            WafProxyError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    
    pub fn error_code(&self) -> &'static str {
        match self {
            WafProxyError::WafBlocked { .. } => "WAF_BLOCKED",
            WafProxyError::RateLimitExceeded { .. } => "RATE_LIMIT_EXCEEDED",
            WafProxyError::Auth(_) => "AUTHENTICATION_FAILED",
            WafProxyError::Authorization(_) => "AUTHORIZATION_FAILED",
            WafProxyError::BadRequest(_) => "BAD_REQUEST",
            WafProxyError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            WafProxyError::Timeout(_) => "TIMEOUT",
            WafProxyError::CircuitBreakerOpen(_) => "CIRCUIT_BREAKER_OPEN",
            WafProxyError::Upstream(_) => "UPSTREAM_ERROR",
            WafProxyError::Config(_) => "CONFIG_ERROR",
            WafProxyError::Ssl(_) => "SSL_ERROR",
            WafProxyError::CertificateError { .. } => "CERTIFICATE_ERROR",
            WafProxyError::Internal(_) => "INTERNAL_ERROR",
            WafProxyError::Database(_) => "DATABASE_ERROR",
            WafProxyError::Redis(_) => "REDIS_ERROR",
            WafProxyError::Json(_) => "JSON_ERROR",
            WafProxyError::Http(_) => "HTTP_ERROR",
            WafProxyError::Io(_) => "IO_ERROR",
        }
    }
}

impl IntoResponse for WafProxyError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_code = self.error_code();
        let message = self.to_string();
        
        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": message,
                "status": status.as_u16()
            }
        }));
        
        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, WafProxyError>;
