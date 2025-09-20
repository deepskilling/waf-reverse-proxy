#![allow(dead_code)]

use std::sync::Arc;
use std::collections::HashMap;
// Removed unused Result import
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

use crate::config::{ProxyConfig, UpstreamConfig};
use crate::health::HealthChecker;
use crate::error::{WafProxyError, Result as WafResult};
use super::load_balancer::LoadBalancer;

/// Upstream server information
#[derive(Debug, Clone)]
pub struct UpstreamServer {
    pub url: String,
    pub weight: u32,
    pub max_fails: u32,
    pub fail_timeout: std::time::Duration,
    pub current_fails: u32,
    pub last_fail_time: Option<std::time::Instant>,
}

impl UpstreamServer {
    pub fn from_config(server_config: &crate::config::UpstreamServerConfig) -> Self {
        Self {
            url: server_config.url.clone(),
            weight: server_config.weight,
            max_fails: server_config.max_fails,
            fail_timeout: server_config.fail_timeout,
            current_fails: 0,
            last_fail_time: None,
        }
    }
    
    /// Check if server is available (not in fail state)
    pub fn is_available(&self) -> bool {
        if self.current_fails < self.max_fails {
            return true;
        }
        
        if let Some(last_fail) = self.last_fail_time {
            if last_fail.elapsed() > self.fail_timeout {
                return true;
            }
        }
        
        false
    }
    
    /// Record a failure
    pub fn record_failure(&mut self) {
        self.current_fails += 1;
        self.last_fail_time = Some(std::time::Instant::now());
        warn!("Server {} failed, current fails: {}/{}", 
              self.url, self.current_fails, self.max_fails);
    }
    
    /// Record a success (reset failures)
    pub fn record_success(&mut self) {
        if self.current_fails > 0 {
            info!("Server {} recovered, resetting fail count", self.url);
            self.current_fails = 0;
            self.last_fail_time = None;
        }
    }
}

/// Upstream configuration with load balancer
pub struct Upstream {
    pub name: String,
    pub servers: Vec<UpstreamServer>,
    pub load_balancer: LoadBalancer,
    pub health_check_enabled: bool,
}

impl Upstream {
    pub fn from_config(name: String, config: &UpstreamConfig) -> Self {
        let servers: Vec<UpstreamServer> = config.servers
            .iter()
            .map(UpstreamServer::from_config)
            .collect();
        
        let load_balancer = LoadBalancer::new(config.load_balancer.clone());
        
        Self {
            name,
            servers,
            load_balancer,
            health_check_enabled: config.health_check.enabled,
        }
    }
    
    /// Get next available server using load balancing algorithm
    pub async fn get_next_server(&mut self, client_ip: Option<std::net::IpAddr>) -> Option<String> {
        // Filter available servers
        let available_servers: Vec<_> = self.servers.iter()
            .enumerate()
            .filter(|(_, server)| server.is_available())
            .collect();
        
        if available_servers.is_empty() {
            warn!("No available servers in upstream: {}", self.name);
            return None;
        }
        
        // Use load balancer to select server
        let selected_index = self.load_balancer.select_server(
            &available_servers.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            client_ip,
        ).await?;
        
        let server = &available_servers[selected_index].1;
        debug!("Selected server {} for upstream {}", server.url, self.name);
        Some(server.url.clone())
    }
    
    /// Update server statistics
    pub fn record_server_result(&mut self, server_url: &str, success: bool) {
        if let Some(server) = self.servers.iter_mut().find(|s| s.url == server_url) {
            if success {
                server.record_success();
            } else {
                server.record_failure();
            }
        }
    }
    
    /// Get upstream statistics
    pub fn get_statistics(&self) -> serde_json::Value {
        let server_stats: Vec<_> = self.servers.iter().map(|server| {
            serde_json::json!({
                "url": server.url,
                "weight": server.weight,
                "current_fails": server.current_fails,
                "max_fails": server.max_fails,
                "available": server.is_available(),
                "last_fail_time": server.last_fail_time.map(|t| t.elapsed().as_secs()),
            })
        }).collect();
        
        serde_json::json!({
            "name": self.name,
            "servers": server_stats,
            "load_balancer": format!("{:?}", self.load_balancer.get_type()),
            "health_check_enabled": self.health_check_enabled,
            "available_servers": self.servers.iter().filter(|s| s.is_available()).count(),
            "total_servers": self.servers.len(),
        })
    }
}

/// Manages all upstream configurations and server selection
pub struct UpstreamManager {
    upstreams: Arc<RwLock<HashMap<String, Upstream>>>,
    health_checker: Arc<HealthChecker>,
    statistics: Arc<RwLock<UpstreamStatistics>>,
}

#[derive(Debug, Default)]
struct UpstreamStatistics {
    total_requests: u64,
    successful_requests: u64,
    failed_requests: u64,
    upstream_selections: HashMap<String, u64>,
    server_selections: HashMap<String, u64>,
}

impl UpstreamManager {
    pub fn new(config: &ProxyConfig, health_checker: Arc<HealthChecker>) -> Self {
        let mut upstreams = HashMap::new();
        
        for (name, upstream_config) in &config.upstreams {
            let upstream = Upstream::from_config(name.clone(), upstream_config);
            upstreams.insert(name.clone(), upstream);
            info!("Configured upstream '{}' with {} servers", name, upstream_config.servers.len());
        }
        
        Self {
            upstreams: Arc::new(RwLock::new(upstreams)),
            health_checker,
            statistics: Arc::new(RwLock::new(UpstreamStatistics::default())),
        }
    }
    
    /// Get a server from the specified upstream
    pub async fn get_upstream_server(&self, upstream_name: &str) -> WafResult<Option<String>> {
        let mut upstreams = self.upstreams.write().await;
        let mut stats = self.statistics.write().await;
        
        stats.total_requests += 1;
        *stats.upstream_selections.entry(upstream_name.to_string()).or_insert(0) += 1;
        drop(stats);
        
        let upstream = upstreams.get_mut(upstream_name)
            .ok_or_else(|| WafProxyError::BadRequest(
                format!("Unknown upstream: {}", upstream_name)
            ))?;
        
        // If health checking is enabled, filter by health status
        if upstream.health_check_enabled {
            let healthy_servers: Vec<String> = upstream.servers
                .iter()
                .filter_map(|server| {
                    if self.health_checker.is_server_healthy(&server.url) {
                        Some(server.url.clone())
                    } else {
                        None
                    }
                })
                .collect();
            
            if healthy_servers.is_empty() {
                warn!("No healthy servers available for upstream: {}", upstream_name);
                let mut stats = self.statistics.write().await;
                stats.failed_requests += 1;
                return Ok(None);
            }
            
            // Update upstream servers to reflect health status
            for server in &mut upstream.servers {
                if !healthy_servers.contains(&server.url) {
                    server.record_failure();
                } else {
                    server.record_success();
                }
            }
        }
        
        // Get next server using load balancing
        let selected_server = upstream.get_next_server(None).await; // TODO: Pass client IP
        
        if let Some(ref server_url) = selected_server {
            let mut stats = self.statistics.write().await;
            stats.successful_requests += 1;
            *stats.server_selections.entry(server_url.clone()).or_insert(0) += 1;
            debug!("Selected server {} from upstream {}", server_url, upstream_name);
        } else {
            let mut stats = self.statistics.write().await;
            stats.failed_requests += 1;
            warn!("No available servers in upstream: {}", upstream_name);
        }
        
        Ok(selected_server)
    }
    
    /// Record the result of a request to a server
    pub async fn record_server_result(&self, upstream_name: &str, server_url: &str, success: bool) {
        let mut upstreams = self.upstreams.write().await;
        
        if let Some(upstream) = upstreams.get_mut(upstream_name) {
            upstream.record_server_result(server_url, success);
            
            if success {
                debug!("Recorded success for server {} in upstream {}", server_url, upstream_name);
            } else {
                warn!("Recorded failure for server {} in upstream {}", server_url, upstream_name);
            }
        }
    }
    
    /// Add a new upstream configuration
    pub async fn add_upstream(&self, name: String, config: &UpstreamConfig) -> WafResult<()> {
        let mut upstreams = self.upstreams.write().await;
        
        if upstreams.contains_key(&name) {
            return Err(WafProxyError::BadRequest(
                format!("Upstream '{}' already exists", name)
            ));
        }
        
        let upstream = Upstream::from_config(name.clone(), config);
        upstreams.insert(name.clone(), upstream);
        
        info!("Added new upstream '{}' with {} servers", name, config.servers.len());
        Ok(())
    }
    
    /// Remove an upstream configuration
    pub async fn remove_upstream(&self, name: &str) -> WafResult<()> {
        let mut upstreams = self.upstreams.write().await;
        
        if upstreams.remove(name).is_some() {
            info!("Removed upstream '{}'", name);
            Ok(())
        } else {
            Err(WafProxyError::BadRequest(
                format!("Upstream '{}' not found", name)
            ))
        }
    }
    
    /// Update an existing upstream configuration
    pub async fn update_upstream(&self, name: &str, config: &UpstreamConfig) -> WafResult<()> {
        let mut upstreams = self.upstreams.write().await;
        
        if upstreams.contains_key(name) {
            let upstream = Upstream::from_config(name.to_string(), config);
            upstreams.insert(name.to_string(), upstream);
            info!("Updated upstream '{}' with {} servers", name, config.servers.len());
            Ok(())
        } else {
            Err(WafProxyError::BadRequest(
                format!("Upstream '{}' not found", name)
            ))
        }
    }
    
    /// Get statistics for all upstreams
    pub async fn get_statistics(&self) -> serde_json::Value {
        let upstreams = self.upstreams.read().await;
        let stats = self.statistics.read().await;
        
        let upstream_stats: HashMap<String, serde_json::Value> = upstreams
            .iter()
            .map(|(name, upstream)| (name.clone(), upstream.get_statistics()))
            .collect();
        
        serde_json::json!({
            "global_statistics": {
                "total_requests": stats.total_requests,
                "successful_requests": stats.successful_requests,
                "failed_requests": stats.failed_requests,
                "success_rate": if stats.total_requests > 0 {
                    stats.successful_requests as f64 / stats.total_requests as f64
                } else {
                    0.0
                },
                "upstream_selections": stats.upstream_selections,
                "server_selections": stats.server_selections,
            },
            "upstreams": upstream_stats,
            "total_upstreams": upstreams.len(),
        })
    }
    
    /// Get list of all upstream names
    pub async fn get_upstream_names(&self) -> Vec<String> {
        let upstreams = self.upstreams.read().await;
        upstreams.keys().cloned().collect()
    }
    
    /// Check if an upstream exists
    pub async fn has_upstream(&self, name: &str) -> bool {
        let upstreams = self.upstreams.read().await;
        upstreams.contains_key(name)
    }
    
    /// Get specific upstream configuration
    pub async fn get_upstream_config(&self, name: &str) -> Option<serde_json::Value> {
        let upstreams = self.upstreams.read().await;
        upstreams.get(name).map(|upstream| upstream.get_statistics())
    }
}
