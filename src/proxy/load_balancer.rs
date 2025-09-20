use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;

use crate::config::LoadBalancerType as ConfigLoadBalancerType;

/// Load balancer implementation
#[derive(Debug)]
pub struct LoadBalancer {
    algorithm: LoadBalancerAlgorithm,
    connection_counts: Arc<RwLock<HashMap<usize, usize>>>,
}

#[derive(Debug)]
enum LoadBalancerAlgorithm {
    RoundRobin {
        current: AtomicUsize,
    },
    LeastConnections,
    IpHash,
}

// Removed unused LoadBalancerType export

impl LoadBalancer {
    pub fn new(lb_type: ConfigLoadBalancerType) -> Self {
        let algorithm = match lb_type {
            ConfigLoadBalancerType::RoundRobin => LoadBalancerAlgorithm::RoundRobin {
                current: AtomicUsize::new(0),
            },
            ConfigLoadBalancerType::LeastConnections => LoadBalancerAlgorithm::LeastConnections,
            ConfigLoadBalancerType::IpHash => LoadBalancerAlgorithm::IpHash,
        };
        
        Self {
            algorithm,
            connection_counts: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Select a server index from the available servers
    pub async fn select_server(
        &self,
        available_servers: &[usize],
        client_ip: Option<std::net::IpAddr>,
    ) -> Option<usize> {
        if available_servers.is_empty() {
            return None;
        }
        
        match &self.algorithm {
            LoadBalancerAlgorithm::RoundRobin { current } => {
                let index = current.fetch_add(1, Ordering::Relaxed) % available_servers.len();
                let selected = available_servers[index];
                debug!("Round-robin selected server index: {}", selected);
                Some(index)
            }
            
            LoadBalancerAlgorithm::LeastConnections => {
                self.select_least_connections(available_servers).await
            }
            
            LoadBalancerAlgorithm::IpHash => {
                if let Some(ip) = client_ip {
                    let hash = self.hash_ip(ip);
                    let index = hash % available_servers.len();
                    let selected = available_servers[index];
                    debug!("IP hash selected server index: {} for IP: {}", selected, ip);
                    Some(index)
                } else {
                    // Fallback to round-robin if no IP provided
                    debug!("No client IP provided for IP hash, falling back to round-robin");
                    let index = 0; // Simple fallback
                    Some(index)
                }
            }
        }
    }
    
    async fn select_least_connections(&self, available_servers: &[usize]) -> Option<usize> {
        let connection_counts = self.connection_counts.read().await;
        
        let mut min_connections = usize::MAX;
        let mut selected_index = 0;
        
        for (i, &server_index) in available_servers.iter().enumerate() {
            let connections = connection_counts.get(&server_index).unwrap_or(&0);
            if *connections < min_connections {
                min_connections = *connections;
                selected_index = i;
            }
        }
        
        let selected = available_servers[selected_index];
        debug!("Least connections selected server index: {} with {} connections", 
               selected, min_connections);
        Some(selected_index)
    }
    
    fn hash_ip(&self, ip: std::net::IpAddr) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        hasher.finish() as usize
    }
    
    /// Record when a connection is established to a server
    pub async fn record_connection_start(&self, server_index: usize) {
        let mut connection_counts = self.connection_counts.write().await;
        *connection_counts.entry(server_index).or_insert(0) += 1;
        debug!("Connection started to server {}, total connections: {}", 
               server_index, connection_counts[&server_index]);
    }
    
    /// Record when a connection is closed to a server
    pub async fn record_connection_end(&self, server_index: usize) {
        let mut connection_counts = self.connection_counts.write().await;
        if let Some(count) = connection_counts.get_mut(&server_index) {
            if *count > 0 {
                *count -= 1;
                debug!("Connection ended to server {}, remaining connections: {}", 
                       server_index, *count);
            }
        }
    }
    
    /// Get current connection counts for all servers
    pub async fn get_connection_counts(&self) -> HashMap<usize, usize> {
        self.connection_counts.read().await.clone()
    }
    
    /// Reset connection counts (useful for testing or rebalancing)
    pub async fn reset_connection_counts(&self) {
        let mut connection_counts = self.connection_counts.write().await;
        connection_counts.clear();
        debug!("Reset all connection counts");
    }
    
    /// Get load balancer type for reporting
    pub fn get_type(&self) -> &'static str {
        match &self.algorithm {
            LoadBalancerAlgorithm::RoundRobin { .. } => "round_robin",
            LoadBalancerAlgorithm::LeastConnections => "least_connections",
            LoadBalancerAlgorithm::IpHash => "ip_hash",
        }
    }
    
    /// Get load balancer statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let connection_counts = self.connection_counts.read().await;
        
        let total_connections: usize = connection_counts.values().sum();
        let active_servers = connection_counts.len();
        
        let mut server_stats = Vec::new();
        for (server_index, connections) in connection_counts.iter() {
            server_stats.push(serde_json::json!({
                "server_index": server_index,
                "active_connections": connections,
                "connection_percentage": if total_connections > 0 {
                    (*connections as f64 / total_connections as f64) * 100.0
                } else {
                    0.0
                }
            }));
        }
        
        // Sort by server index for consistent output
        server_stats.sort_by(|a, b| {
            a["server_index"].as_u64().unwrap_or(0)
                .cmp(&b["server_index"].as_u64().unwrap_or(0))
        });
        
        serde_json::json!({
            "algorithm": self.get_type(),
            "total_connections": total_connections,
            "active_servers": active_servers,
            "server_connections": server_stats,
            "algorithm_specific": match &self.algorithm {
                LoadBalancerAlgorithm::RoundRobin { current } => serde_json::json!({
                    "current_position": current.load(Ordering::Relaxed),
                }),
                LoadBalancerAlgorithm::LeastConnections => serde_json::json!({
                    "balancing_factor": "connections",
                }),
                LoadBalancerAlgorithm::IpHash => serde_json::json!({
                    "hash_function": "default_hasher",
                    "sticky_sessions": true,
                }),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[tokio::test]
    async fn test_round_robin() {
        let lb = LoadBalancer::new(ConfigLoadBalancerType::RoundRobin);
        let servers = vec![0, 1, 2];
        
        // Test that round-robin cycles through servers
        let mut selections = Vec::new();
        for _ in 0..6 {
            if let Some(index) = lb.select_server(&servers, None).await {
                selections.push(servers[index]);
            }
        }
        
        assert_eq!(selections, vec![0, 1, 2, 0, 1, 2]);
    }
    
    #[tokio::test]
    async fn test_ip_hash_consistency() {
        let lb = LoadBalancer::new(ConfigLoadBalancerType::IpHash);
        let servers = vec![0, 1, 2];
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        
        // Test that the same IP always goes to the same server
        let mut selections = Vec::new();
        for _ in 0..5 {
            if let Some(index) = lb.select_server(&servers, Some(ip)).await {
                selections.push(servers[index]);
            }
        }
        
        // All selections should be the same
        assert!(selections.iter().all(|&x| x == selections[0]));
    }
    
    #[tokio::test]
    async fn test_least_connections() {
        let lb = LoadBalancer::new(ConfigLoadBalancerType::LeastConnections);
        let servers = vec![0, 1, 2];
        
        // Simulate connections to server 0
        lb.record_connection_start(0).await;
        lb.record_connection_start(0).await;
        
        // Simulate connections to server 1
        lb.record_connection_start(1).await;
        
        // Server 2 should be selected (0 connections)
        if let Some(index) = lb.select_server(&servers, None).await {
            assert_eq!(servers[index], 2);
        }
        
        // Add connections to server 2, now server 1 should have least
        lb.record_connection_start(2).await;
        lb.record_connection_start(2).await;
        lb.record_connection_start(2).await;
        
        if let Some(index) = lb.select_server(&servers, None).await {
            assert_eq!(servers[index], 1);
        }
    }
}
