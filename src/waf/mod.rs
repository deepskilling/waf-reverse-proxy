pub mod engine;
pub mod rules;
pub mod rate_limiter;
pub mod owasp;
pub mod bot_detection;
pub mod geo_blocking;

// Removed unused Arc import
// Removed unused Result import
use axum::{
    extract::{ConnectInfo, Request},
    http::HeaderMap,
};
use std::net::SocketAddr;
// Removed unused WafConfig import
// Removed unused MetricsCollector import
// Removed unused error imports

pub use engine::WafEngine;
pub use rules::WafAction;
// Removed unused RateLimiter export

/// WAF inspection result
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct WafInspectionResult {
    pub action: WafAction,
    pub reason: String,
    pub rule_name: Option<String>,
    pub confidence: f32,
    pub metadata: serde_json::Value,
}

/// Request context for WAF inspection
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RequestContext {
    pub client_ip: std::net::IpAddr,
    pub user_agent: Option<String>,
    pub method: String,
    pub uri: String,
    pub headers: HeaderMap,
    pub query_string: String,
    pub body: Option<Vec<u8>>,
    pub content_type: Option<String>,
}

impl RequestContext {
    pub fn from_request(
        req: &Request,
        connect_info: &ConnectInfo<SocketAddr>,
    ) -> Self {
        let client_ip = connect_info.0.ip();
        let user_agent = req.headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        
        let method = req.method().to_string();
        let uri = req.uri().to_string();
        let headers = req.headers().clone();
        
        let query_string = req.uri()
            .query()
            .unwrap_or("")
            .to_string();
        
        let content_type = req.headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        
        Self {
            client_ip,
            user_agent,
            method,
            uri,
            headers,
            query_string,
            body: None, // Will be populated separately to avoid cloning large bodies
            content_type,
        }
    }
}
