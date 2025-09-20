#![allow(dead_code)]

pub mod engine;
pub mod load_balancer;
pub mod upstream;
pub mod cache;

// Removed unused Arc import
// Removed unused Result import

// Removed unused config imports
// Removed unused WafEngine import
// Removed unused observability imports
// Removed unused HealthChecker import

pub use engine::ReverseProxy;
// Removed unused load balancer exports
// Removed unused upstream exports
// Removed unused cache export

/// Proxy request context
#[derive(Debug, Clone)]
pub struct ProxyContext {
    pub request_id: String,
    pub client_ip: std::net::IpAddr,
    pub method: String,
    pub uri: String,
    pub headers: axum::http::HeaderMap,
    pub upstream_name: String,
    pub target_server: String,
    pub start_time: std::time::Instant,
}

/// Proxy response information
#[derive(Debug, Clone)]
pub struct ProxyResponse {
    pub status: u16,
    pub headers: axum::http::HeaderMap,
    pub body: bytes::Bytes,
    pub upstream_response_time: std::time::Duration,
    pub total_time: std::time::Duration,
    pub from_cache: bool,
}
