use std::sync::Arc;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use anyhow::Result;
use dashmap::DashMap;
use governor::{Quota, DefaultDirectRateLimiter};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::config::RateLimitingConfig;
use crate::error::Result as WafResult;

/// Token bucket for rate limiting
#[derive(Debug)]
#[allow(dead_code)]
struct TokenBucket {
    limiter: DefaultDirectRateLimiter,
    last_reset: Instant,
}

impl TokenBucket {
    fn new(requests_per_second: Option<u32>, requests_per_minute: Option<u32>, burst: u32) -> Self {
        let quota = if let Some(rps) = requests_per_second {
            Quota::per_second(std::num::NonZeroU32::new(rps).unwrap_or(std::num::NonZeroU32::new(1).unwrap()))
                .allow_burst(std::num::NonZeroU32::new(burst).unwrap_or(std::num::NonZeroU32::new(1).unwrap()))
        } else if let Some(rpm) = requests_per_minute {
            Quota::per_minute(std::num::NonZeroU32::new(rpm).unwrap_or(std::num::NonZeroU32::new(1).unwrap()))
                .allow_burst(std::num::NonZeroU32::new(burst).unwrap_or(std::num::NonZeroU32::new(1).unwrap()))
        } else {
            // Default to 60 requests per minute
            Quota::per_minute(std::num::NonZeroU32::new(60).unwrap())
                .allow_burst(std::num::NonZeroU32::new(burst).unwrap_or(std::num::NonZeroU32::new(1).unwrap()))
        };
        
        Self {
            limiter: DefaultDirectRateLimiter::direct(quota),
            last_reset: Instant::now(),
        }
    }
    
    fn check_rate(&mut self) -> bool {
        match self.limiter.check() {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

/// Rate limiter for various scopes (global, per-IP, per-endpoint)
#[allow(dead_code)]
pub struct RateLimiter {
    config: RateLimitingConfig,
    global_limiter: Arc<RwLock<TokenBucket>>,
    ip_limiters: Arc<DashMap<IpAddr, TokenBucket>>,
    endpoint_limiters: Arc<DashMap<String, TokenBucket>>,
    statistics: Arc<RwLock<RateLimiterStatistics>>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct RateLimiterStatistics {
    global_requests: u64,
    global_blocked: u64,
    ip_requests: u64,
    ip_blocked: u64,
    endpoint_requests: u64,
    endpoint_blocked: u64,
    active_ip_limiters: usize,
    active_endpoint_limiters: usize,
}

impl RateLimiter {
    pub async fn new(config: &RateLimitingConfig) -> Result<Self> {
        let global_limiter = Arc::new(RwLock::new(TokenBucket::new(
            config.global.requests_per_second,
            config.global.requests_per_minute,
            config.global.burst,
        )));
        
        Ok(Self {
            config: config.clone(),
            global_limiter,
            ip_limiters: Arc::new(DashMap::new()),
            endpoint_limiters: Arc::new(DashMap::new()),
            statistics: Arc::new(RwLock::new(RateLimiterStatistics::default())),
        })
    }
    
    /// Check global rate limit
    pub async fn check_global(&self) -> WafResult<bool> {
        let mut limiter = self.global_limiter.write().await;
        let mut stats = self.statistics.write().await;
        
        stats.global_requests += 1;
        
        if limiter.check_rate() {
            debug!("Global rate limit check passed");
            Ok(true)
        } else {
            stats.global_blocked += 1;
            warn!("Global rate limit exceeded");
            Ok(false)
        }
    }
    
    /// Check per-IP rate limit
    pub async fn check_per_ip(&self, ip: &IpAddr) -> WafResult<bool> {
        let mut stats = self.statistics.write().await;
        stats.ip_requests += 1;
        stats.active_ip_limiters = self.ip_limiters.len();
        drop(stats);
        
        // Get or create IP-specific limiter
        let mut limiter = self.ip_limiters
            .entry(*ip)
            .or_insert_with(|| TokenBucket::new(
                self.config.per_ip.requests_per_second,
                self.config.per_ip.requests_per_minute,
                self.config.per_ip.burst,
            ));
        
        if limiter.check_rate() {
            debug!("Per-IP rate limit check passed for {}", ip);
            Ok(true)
        } else {
            let mut stats = self.statistics.write().await;
            stats.ip_blocked += 1;
            warn!("Per-IP rate limit exceeded for {}", ip);
            Ok(false)
        }
    }
    
    /// Check per-endpoint rate limit
    pub async fn check_per_endpoint(&self, endpoint: &str) -> WafResult<bool> {
        let mut stats = self.statistics.write().await;
        stats.endpoint_requests += 1;
        stats.active_endpoint_limiters = self.endpoint_limiters.len();
        drop(stats);
        
        // Get or create endpoint-specific limiter
        let mut limiter = self.endpoint_limiters
            .entry(endpoint.to_string())
            .or_insert_with(|| TokenBucket::new(
                self.config.per_endpoint.requests_per_second,
                self.config.per_endpoint.requests_per_minute,
                self.config.per_endpoint.burst,
            ));
        
        if limiter.check_rate() {
            debug!("Per-endpoint rate limit check passed for {}", endpoint);
            Ok(true)
        } else {
            let mut stats = self.statistics.write().await;
            stats.endpoint_blocked += 1;
            warn!("Per-endpoint rate limit exceeded for {}", endpoint);
            Ok(false)
        }
    }
    
    /// Clean up old limiters (should be called periodically)
    pub async fn cleanup_old_limiters(&self) {
        let cleanup_threshold = Instant::now() - Duration::from_secs(3600); // 1 hour
        
        // Clean up IP limiters
        self.ip_limiters.retain(|_, limiter| {
            limiter.last_reset > cleanup_threshold
        });
        
        // Clean up endpoint limiters
        self.endpoint_limiters.retain(|_, limiter| {
            limiter.last_reset > cleanup_threshold
        });
        
        debug!("Cleaned up old rate limiters. Active IP limiters: {}, Active endpoint limiters: {}", 
               self.ip_limiters.len(), self.endpoint_limiters.len());
    }
    
    /// Update rate limiting configuration
    pub async fn update_config(&self, new_config: &RateLimitingConfig) -> Result<()> {
        // Update global limiter
        let mut global_limiter = self.global_limiter.write().await;
        *global_limiter = TokenBucket::new(
            new_config.global.requests_per_second,
            new_config.global.requests_per_minute,
            new_config.global.burst,
        );
        
        // Clear existing limiters to force recreation with new config
        self.ip_limiters.clear();
        self.endpoint_limiters.clear();
        
        Ok(())
    }
    
    /// Get rate limiter statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let stats = self.statistics.read().await;
        serde_json::json!({
            "global": {
                "requests": stats.global_requests,
                "blocked": stats.global_blocked,
                "block_rate": if stats.global_requests > 0 { 
                    (stats.global_blocked as f64) / (stats.global_requests as f64) 
                } else { 0.0 }
            },
            "per_ip": {
                "requests": stats.ip_requests,
                "blocked": stats.ip_blocked,
                "active_limiters": stats.active_ip_limiters,
                "block_rate": if stats.ip_requests > 0 { 
                    (stats.ip_blocked as f64) / (stats.ip_requests as f64) 
                } else { 0.0 }
            },
            "per_endpoint": {
                "requests": stats.endpoint_requests,
                "blocked": stats.endpoint_blocked,
                "active_limiters": stats.active_endpoint_limiters,
                "block_rate": if stats.endpoint_requests > 0 { 
                    (stats.endpoint_blocked as f64) / (stats.endpoint_requests as f64) 
                } else { 0.0 }
            }
        })
    }
    
    /// Reset all rate limiters (for testing or emergency situations)
    pub async fn reset_all(&self) {
        let mut global_limiter = self.global_limiter.write().await;
        *global_limiter = TokenBucket::new(
            self.config.global.requests_per_second,
            self.config.global.requests_per_minute,
            self.config.global.burst,
        );
        
        self.ip_limiters.clear();
        self.endpoint_limiters.clear();
        
        // Reset statistics
        let mut stats = self.statistics.write().await;
        *stats = RateLimiterStatistics::default();
        
        debug!("All rate limiters reset");
    }
}
