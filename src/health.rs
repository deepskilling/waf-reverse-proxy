#![allow(dead_code)]

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
// Removed unused Result import
use dashmap::DashMap;
use tokio::time::interval;
use reqwest::Client;
use tracing::{info, warn, error, debug};

use crate::config::{ProxyConfig, HealthCheckConfig};
use crate::error::Result as WafResult;

/// Health status of an upstream server
#[derive(Debug, Clone, PartialEq)]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

/// Health check result
#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub server_url: String,
    pub status: HealthStatus,
    pub response_time: Duration,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub timestamp: Instant,
}

/// Server health information
#[derive(Debug, Clone)]
pub struct ServerHealth {
    pub url: String,
    pub status: HealthStatus,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_check: Instant,
    pub last_success: Option<Instant>,
    pub last_failure: Option<Instant>,
    pub total_checks: u64,
    pub total_successes: u64,
    pub total_failures: u64,
    pub average_response_time: Duration,
    pub response_times: Vec<Duration>,
}

impl ServerHealth {
    fn new(url: String) -> Self {
        Self {
            url,
            status: HealthStatus::Unknown,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_check: Instant::now(),
            last_success: None,
            last_failure: None,
            total_checks: 0,
            total_successes: 0,
            total_failures: 0,
            average_response_time: Duration::from_millis(0),
            response_times: Vec::new(),
        }
    }
    
    fn update(&mut self, result: &HealthCheckResult) {
        self.last_check = result.timestamp;
        self.total_checks += 1;
        
        // Keep last 100 response times for average calculation
        self.response_times.push(result.response_time);
        if self.response_times.len() > 100 {
            self.response_times.remove(0);
        }
        
        // Calculate average response time
        let total: Duration = self.response_times.iter().sum();
        self.average_response_time = total / self.response_times.len() as u32;
        
        match result.status {
            HealthStatus::Healthy => {
                self.consecutive_successes += 1;
                self.consecutive_failures = 0;
                self.total_successes += 1;
                self.last_success = Some(result.timestamp);
                self.status = HealthStatus::Healthy;
            }
            HealthStatus::Unhealthy => {
                self.consecutive_failures += 1;
                self.consecutive_successes = 0;
                self.total_failures += 1;
                self.last_failure = Some(result.timestamp);
                self.status = HealthStatus::Unhealthy;
            }
            HealthStatus::Unknown => {
                // Keep existing status for unknown results
            }
        }
    }
    
    fn is_healthy(&self, config: &HealthCheckConfig) -> bool {
        match self.status {
            HealthStatus::Healthy => self.consecutive_failures < config.unhealthy_threshold,
            HealthStatus::Unhealthy => self.consecutive_successes >= config.healthy_threshold,
            HealthStatus::Unknown => false,
        }
    }
}

/// Health checker that monitors upstream server health
pub struct HealthChecker {
    client: Client,
    server_health: Arc<DashMap<String, ServerHealth>>,
    statistics: Arc<tokio::sync::RwLock<HealthStatistics>>,
}

#[derive(Debug, Default)]
struct HealthStatistics {
    total_checks: u64,
    total_healthy: u64,
    total_unhealthy: u64,
    total_errors: u64,
    upstreams_monitored: usize,
    last_check_time: Option<Instant>,
}

impl HealthChecker {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("WAF-ReverseProxy-HealthChecker/1.0")
            .build()
            .expect("Failed to create HTTP client for health checks");
        
        Self {
            client,
            server_health: Arc::new(DashMap::new()),
            statistics: Arc::new(tokio::sync::RwLock::new(HealthStatistics::default())),
        }
    }
    
    /// Start monitoring upstream servers
    pub async fn start_monitoring(&self, proxy_config: &ProxyConfig) {
        info!("Starting health check monitoring");
        
        for (upstream_name, upstream_config) in &proxy_config.upstreams {
            if upstream_config.health_check.enabled {
                info!("Starting health checks for upstream: {}", upstream_name);
                
                for server in &upstream_config.servers {
                    // Initialize server health
                    self.server_health.insert(
                        server.url.clone(),
                        ServerHealth::new(server.url.clone())
                    );
                    
                    // Start periodic health checks
                    let health_checker = self.clone();
                    let server_url = server.url.clone();
                    let health_config = upstream_config.health_check.clone();
                    
                    tokio::spawn(async move {
                        health_checker.monitor_server(&server_url, &health_config).await;
                    });
                }
            }
        }
        
        // Update statistics periodically
        let stats_updater = self.statistics.clone();
        let server_health = self.server_health.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                
                let mut stats = stats_updater.write().await;
                stats.upstreams_monitored = server_health.len();
                stats.last_check_time = Some(Instant::now());
            }
        });
        
        info!("Health check monitoring started for {} servers", self.server_health.len());
    }
    
    async fn monitor_server(&self, server_url: &str, config: &HealthCheckConfig) {
        let mut interval = interval(config.interval);
        
        loop {
            interval.tick().await;
            
            let result = self.check_server_health(server_url, config).await;
            
            // Update server health
            if let Some(mut health) = self.server_health.get_mut(server_url) {
                health.update(&result);
            }
            
            // Update statistics
            let mut stats = self.statistics.write().await;
            stats.total_checks += 1;
            
            match result.status {
                HealthStatus::Healthy => {
                    stats.total_healthy += 1;
                    debug!("Health check passed for {}: {}ms", 
                          server_url, result.response_time.as_millis());
                }
                HealthStatus::Unhealthy => {
                    stats.total_unhealthy += 1;
                    warn!("Health check failed for {}: {}", 
                         server_url, result.error.unwrap_or_default());
                }
                HealthStatus::Unknown => {
                    stats.total_errors += 1;
                    error!("Health check error for {}: {}", 
                          server_url, result.error.unwrap_or_default());
                }
            }
        }
    }
    
    async fn check_server_health(&self, server_url: &str, config: &HealthCheckConfig) -> HealthCheckResult {
        let start_time = Instant::now();
        let health_url = format!("{}{}", server_url.trim_end_matches('/'), &config.path);
        
        match tokio::time::timeout(config.timeout, self.client.get(&health_url).send()).await {
            Ok(Ok(response)) => {
                let response_time = start_time.elapsed();
                let status_code = response.status().as_u16();
                
                if response.status().is_success() {
                    HealthCheckResult {
                        server_url: server_url.to_string(),
                        status: HealthStatus::Healthy,
                        response_time,
                        status_code: Some(status_code),
                        error: None,
                        timestamp: start_time,
                    }
                } else {
                    HealthCheckResult {
                        server_url: server_url.to_string(),
                        status: HealthStatus::Unhealthy,
                        response_time,
                        status_code: Some(status_code),
                        error: Some(format!("HTTP {}", status_code)),
                        timestamp: start_time,
                    }
                }
            }
            Ok(Err(e)) => {
                HealthCheckResult {
                    server_url: server_url.to_string(),
                    status: HealthStatus::Unhealthy,
                    response_time: start_time.elapsed(),
                    status_code: None,
                    error: Some(e.to_string()),
                    timestamp: start_time,
                }
            }
            Err(_) => {
                HealthCheckResult {
                    server_url: server_url.to_string(),
                    status: HealthStatus::Unhealthy,
                    response_time: config.timeout,
                    status_code: None,
                    error: Some("Health check timeout".to_string()),
                    timestamp: start_time,
                }
            }
        }
    }
    
    /// Get health status of a specific server
    pub fn get_server_health(&self, server_url: &str) -> Option<ServerHealth> {
        self.server_health.get(server_url).map(|h| h.clone())
    }
    
    /// Check if a server is healthy
    pub fn is_server_healthy(&self, server_url: &str) -> bool {
        if let Some(health) = self.server_health.get(server_url) {
            match health.status {
                HealthStatus::Healthy => true,
                HealthStatus::Unhealthy | HealthStatus::Unknown => false,
            }
        } else {
            false
        }
    }
    
    /// Get all healthy servers for an upstream
    pub fn get_healthy_servers(&self, server_urls: &[String]) -> Vec<String> {
        server_urls.iter()
            .filter(|url| self.is_server_healthy(url))
            .cloned()
            .collect()
    }
    
    /// Get health status of all servers
    pub fn get_all_server_health(&self) -> HashMap<String, ServerHealth> {
        self.server_health.iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }
    
    /// Force health check for a specific server
    pub async fn force_health_check(&self, server_url: &str, config: &HealthCheckConfig) -> WafResult<HealthCheckResult> {
        let result = self.check_server_health(server_url, config).await;
        
        // Update server health
        if let Some(mut health) = self.server_health.get_mut(server_url) {
            health.update(&result);
        }
        
        Ok(result)
    }
    
    /// Get health statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let stats = self.statistics.read().await;
        let server_health: Vec<_> = self.server_health.iter()
            .map(|entry| {
                let health = entry.value();
                serde_json::json!({
                    "url": health.url,
                    "status": format!("{:?}", health.status),
                    "consecutive_failures": health.consecutive_failures,
                    "consecutive_successes": health.consecutive_successes,
                    "total_checks": health.total_checks,
                    "success_rate": if health.total_checks > 0 {
                        health.total_successes as f64 / health.total_checks as f64
                    } else {
                        0.0
                    },
                    "average_response_time_ms": health.average_response_time.as_millis(),
                    "last_success": health.last_success.map(|t| t.elapsed().as_secs()),
                    "last_failure": health.last_failure.map(|t| t.elapsed().as_secs()),
                })
            })
            .collect();
        
        serde_json::json!({
            "global_statistics": {
                "total_checks": stats.total_checks,
                "total_healthy": stats.total_healthy,
                "total_unhealthy": stats.total_unhealthy,
                "total_errors": stats.total_errors,
                "upstreams_monitored": stats.upstreams_monitored,
                "overall_success_rate": if stats.total_checks > 0 {
                    stats.total_healthy as f64 / stats.total_checks as f64
                } else {
                    0.0
                },
                "last_check_time": stats.last_check_time.map(|t| t.elapsed().as_secs()),
            },
            "server_health": server_health,
            "healthy_servers_count": server_health.iter()
                .filter(|s| s["status"] == "Healthy")
                .count(),
            "unhealthy_servers_count": server_health.iter()
                .filter(|s| s["status"] == "Unhealthy")
                .count(),
        })
    }
    
    /// Reset health status for a server (useful for testing)
    pub fn reset_server_health(&self, server_url: &str) {
        if let Some(mut health) = self.server_health.get_mut(server_url) {
            *health = ServerHealth::new(server_url.to_string());
            info!("Reset health status for server: {}", server_url);
        }
    }
    
    /// Remove monitoring for a server
    pub fn remove_server_monitoring(&self, server_url: &str) {
        self.server_health.remove(server_url);
        info!("Removed health monitoring for server: {}", server_url);
    }
}

impl Clone for HealthChecker {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            server_health: self.server_health.clone(),
            statistics: self.statistics.clone(),
        }
    }
}
