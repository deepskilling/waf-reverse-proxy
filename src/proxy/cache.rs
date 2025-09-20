#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{debug, info};
use serde::{Serialize, Deserialize};

use crate::config::CachingConfig;
use super::ProxyResponse;

/// Cache entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    response: CachedResponse,
    created_at: std::time::SystemTime,
    ttl: Duration,
    access_count: u64,
    last_accessed: std::time::SystemTime,
}

/// Serializable version of ProxyResponse for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    upstream_response_time: Duration,
}

impl From<&ProxyResponse> for CachedResponse {
    fn from(response: &ProxyResponse) -> Self {
        let headers: Vec<(String, String)> = response.headers
            .iter()
            .map(|(name, value)| (
                name.to_string(),
                value.to_str().unwrap_or("").to_string()
            ))
            .collect();
        
        Self {
            status: response.status,
            headers,
            body: response.body.to_vec(),
            upstream_response_time: response.upstream_response_time,
        }
    }
}

impl Into<ProxyResponse> for CachedResponse {
    fn into(self) -> ProxyResponse {
        let mut header_map = axum::http::HeaderMap::new();
        for (name, value) in self.headers {
            if let (Ok(header_name), Ok(header_value)) = (
                name.parse::<axum::http::HeaderName>(),
                value.parse::<axum::http::HeaderValue>()
            ) {
                header_map.insert(header_name, header_value);
            }
        }
        
        ProxyResponse {
            status: self.status,
            headers: header_map,
            body: bytes::Bytes::from(self.body),
            upstream_response_time: self.upstream_response_time,
            total_time: Duration::from_millis(0), // Will be updated by caller
            from_cache: true,
        }
    }
}

impl CacheEntry {
    fn new(response: &ProxyResponse, ttl: Duration) -> Self {
        let now = std::time::SystemTime::now();
        Self {
            response: CachedResponse::from(response),
            created_at: now,
            ttl,
            access_count: 0,
            last_accessed: now,
        }
    }
    
    fn is_expired(&self) -> bool {
        if let Ok(elapsed) = self.created_at.elapsed() {
            elapsed > self.ttl
        } else {
            true // If we can't determine elapsed time, consider it expired
        }
    }
    
    fn access(&mut self) -> ProxyResponse {
        self.access_count += 1;
        self.last_accessed = std::time::SystemTime::now();
        self.response.clone().into()
    }
}

/// Proxy cache implementation with TTL and LRU eviction
pub struct ProxyCache {
    config: CachingConfig,
    cache: Arc<DashMap<String, CacheEntry>>,
    statistics: Arc<RwLock<CacheStatistics>>,
    max_entries: usize,
}

#[derive(Debug, Default)]
struct CacheStatistics {
    total_requests: u64,
    cache_hits: u64,
    cache_misses: u64,
    cache_sets: u64,
    cache_evictions: u64,
    cache_size_bytes: u64,
    expired_entries: u64,
}

impl ProxyCache {
    pub async fn new(config: &CachingConfig) -> Result<Self> {
        let max_entries = Self::parse_max_size(&config.max_size)?;
        
        let cache = Self {
            config: config.clone(),
            cache: Arc::new(DashMap::new()),
            statistics: Arc::new(RwLock::new(CacheStatistics::default())),
            max_entries,
        };
        
        if config.enabled {
            info!("Cache initialized with max entries: {}, default TTL: {:?}", 
                  max_entries, config.default_ttl);
            
            // Start cleanup task
            cache.start_cleanup_task().await;
        }
        
        Ok(cache)
    }
    
    fn parse_max_size(size_str: &str) -> Result<usize> {
        let size_str = size_str.to_uppercase();
        
        if let Some(size) = size_str.strip_suffix("GB") {
            let gb: f64 = size.parse()?;
            Ok((gb * 1024.0 * 1024.0 * 1024.0 / 1024.0) as usize) // Rough estimate of entries
        } else if let Some(size) = size_str.strip_suffix("MB") {
            let mb: f64 = size.parse()?;
            Ok((mb * 1024.0 * 1024.0 / 1024.0) as usize) // Rough estimate of entries
        } else if let Some(size) = size_str.strip_suffix("KB") {
            let kb: f64 = size.parse()?;
            Ok((kb * 1024.0 / 1024.0) as usize) // Rough estimate of entries
        } else {
            // Assume it's a number of entries
            Ok(size_str.parse()?)
        }
    }
    
    async fn start_cleanup_task(&self) {
        let cache = self.cache.clone();
        let statistics = self.statistics.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
            
            loop {
                interval.tick().await;
                
                let mut expired_count = 0;
                let mut removed_size = 0u64;
                
                // Remove expired entries
                cache.retain(|_key, entry| {
                    if entry.is_expired() {
                        expired_count += 1;
                        removed_size += entry.response.body.len() as u64;
                        false
                    } else {
                        true
                    }
                });
                
                if expired_count > 0 {
                    let mut stats = statistics.write().await;
                    stats.expired_entries += expired_count;
                    stats.cache_size_bytes = stats.cache_size_bytes.saturating_sub(removed_size);
                    debug!("Cleaned up {} expired cache entries, freed {} bytes", 
                           expired_count, removed_size);
                }
            }
        });
    }
    
    /// Get cached response if available and not expired
    pub async fn get(&self, key: &str) -> Option<ProxyResponse> {
        if !self.config.enabled {
            return None;
        }
        
        let mut stats = self.statistics.write().await;
        stats.total_requests += 1;
        drop(stats);
        
        if let Some(mut entry) = self.cache.get_mut(key) {
            if !entry.is_expired() {
                let response = entry.access();
                let mut stats = self.statistics.write().await;
                stats.cache_hits += 1;
                drop(stats);
                
                debug!("Cache HIT for key: {}", key);
                Some(response)
            } else {
                // Remove expired entry
                drop(entry);
                self.cache.remove(key);
                let mut stats = self.statistics.write().await;
                stats.cache_misses += 1;
                stats.expired_entries += 1;
                drop(stats);
                
                debug!("Cache MISS (expired) for key: {}", key);
                None
            }
        } else {
            let mut stats = self.statistics.write().await;
            stats.cache_misses += 1;
            drop(stats);
            
            debug!("Cache MISS for key: {}", key);
            None
        }
    }
    
    /// Store response in cache
    pub async fn set(&self, key: String, response: &ProxyResponse) {
        if !self.config.enabled {
            return;
        }
        
        // Determine TTL
        let ttl = self.get_ttl_for_response(response).unwrap_or(self.config.default_ttl);
        
        // Don't cache if TTL is zero
        if ttl.as_secs() == 0 {
            return;
        }
        
        let entry = CacheEntry::new(response, ttl);
        let entry_size = entry.response.body.len() as u64;
        
        // Check if we need to evict entries
        if self.cache.len() >= self.max_entries {
            self.evict_lru_entries(1).await;
        }
        
        self.cache.insert(key.clone(), entry);
        
        let mut stats = self.statistics.write().await;
        stats.cache_sets += 1;
        stats.cache_size_bytes += entry_size;
        drop(stats);
        
        debug!("Cache SET for key: {}, TTL: {:?}, size: {} bytes", key, ttl, entry_size);
    }
    
    fn get_ttl_for_response(&self, response: &ProxyResponse) -> Option<Duration> {
        // Check Cache-Control header first
        if let Some(cache_control) = response.headers.get("cache-control") {
            if let Ok(cache_control_str) = cache_control.to_str() {
                if cache_control_str.contains("no-cache") || cache_control_str.contains("no-store") {
                    return Some(Duration::from_secs(0));
                }
                
                // Look for max-age directive
                for directive in cache_control_str.split(',') {
                    let directive = directive.trim();
                    if directive.starts_with("max-age=") {
                        if let Ok(max_age) = directive[8..].parse::<u64>() {
                            return Some(Duration::from_secs(max_age));
                        }
                    }
                }
            }
        }
        
        // Check Expires header
        if let Some(expires) = response.headers.get("expires") {
            if let Ok(expires_str) = expires.to_str() {
                // Parse expires date and calculate TTL
                // This is a simplified implementation - in production you'd want proper date parsing
                debug!("Found Expires header: {}, using default TTL", expires_str);
            }
        }
        
        None // Use default TTL from config
    }
    
    async fn evict_lru_entries(&self, count: usize) {
        let mut entries_to_remove = Vec::new();
        let mut oldest_accessed = std::time::SystemTime::now();
        
        // Find LRU entries
        for entry in self.cache.iter() {
            let (key, cache_entry) = (entry.key(), entry.value());
            
            if entries_to_remove.len() < count {
                entries_to_remove.push((key.clone(), cache_entry.last_accessed));
                if cache_entry.last_accessed < oldest_accessed {
                    oldest_accessed = cache_entry.last_accessed;
                }
            } else {
                // Replace if this entry is older
                if cache_entry.last_accessed < oldest_accessed {
                    if let Some(newest_idx) = entries_to_remove.iter().position(|(_, accessed)| *accessed == oldest_accessed) {
                        entries_to_remove[newest_idx] = (key.clone(), cache_entry.last_accessed);
                        
                        // Update oldest_accessed
                        oldest_accessed = entries_to_remove.iter()
                            .map(|(_, accessed)| *accessed)
                            .min()
                            .unwrap_or(std::time::SystemTime::now());
                    }
                }
            }
        }
        
        // Remove selected entries
        let mut total_size_freed = 0u64;
        for (key, _) in entries_to_remove {
            if let Some((_, entry)) = self.cache.remove(&key) {
                total_size_freed += entry.response.body.len() as u64;
            }
        }
        
        let mut stats = self.statistics.write().await;
        stats.cache_evictions += count as u64;
        stats.cache_size_bytes = stats.cache_size_bytes.saturating_sub(total_size_freed);
        
        debug!("Evicted {} LRU cache entries, freed {} bytes", count, total_size_freed);
    }
    
    /// Clear all cache entries
    pub async fn clear(&self) {
        self.cache.clear();
        let mut stats = self.statistics.write().await;
        stats.cache_size_bytes = 0;
        info!("Cache cleared");
    }
    
    /// Get cache statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let stats = self.statistics.read().await;
        
        serde_json::json!({
            "enabled": self.config.enabled,
            "statistics": {
                "total_requests": stats.total_requests,
                "cache_hits": stats.cache_hits,
                "cache_misses": stats.cache_misses,
                "hit_rate": if stats.total_requests > 0 {
                    stats.cache_hits as f64 / stats.total_requests as f64
                } else {
                    0.0
                },
                "cache_sets": stats.cache_sets,
                "cache_evictions": stats.cache_evictions,
                "expired_entries": stats.expired_entries,
                "cache_size_bytes": stats.cache_size_bytes,
                "current_entries": self.cache.len(),
                "max_entries": self.max_entries,
                "usage_percentage": (self.cache.len() as f64 / self.max_entries as f64) * 100.0,
            },
            "configuration": {
                "default_ttl_seconds": self.config.default_ttl.as_secs(),
                "max_size": self.config.max_size,
                "rules_count": self.config.rules.len(),
            }
        })
    }
    
    /// Get cache entry information for debugging
    pub async fn get_entry_info(&self, key: &str) -> Option<serde_json::Value> {
        if let Some(entry) = self.cache.get(key) {
            Some(serde_json::json!({
                "key": key,
                "status": entry.response.status,
                "body_size": entry.response.body.len(),
                "created_at": entry.created_at
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                "ttl_seconds": entry.ttl.as_secs(),
                "access_count": entry.access_count,
                "last_accessed": entry.last_accessed
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                "expired": entry.is_expired(),
                "headers_count": entry.response.headers.len(),
            }))
        } else {
            None
        }
    }
    
    /// Remove specific cache entry
    pub async fn remove(&self, key: &str) -> bool {
        if let Some((_, entry)) = self.cache.remove(key) {
            let mut stats = self.statistics.write().await;
            stats.cache_size_bytes = stats.cache_size_bytes.saturating_sub(entry.response.body.len() as u64);
            debug!("Manually removed cache entry: {}", key);
            true
        } else {
            false
        }
    }
}
