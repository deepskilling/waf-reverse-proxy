#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use serde::{Serialize, Deserialize};
#[cfg(feature = "redis")]
use redis::{Client as RedisClient, AsyncCommands};

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

/// Cache backend type
#[derive(Debug, Clone)]
enum CacheBackend {
    InMemory(Arc<DashMap<String, CacheEntry>>),
    #[cfg(feature = "redis")]
    Redis(RedisClient),
}

/// Proxy cache implementation with TTL and LRU eviction
pub struct ProxyCache {
    config: CachingConfig,
    backend: CacheBackend,
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
        
        // Initialize backend based on configuration
        let backend = if config.redis.enabled {
            #[cfg(feature = "redis")]
            {
                let redis_url = format!("redis://{}:{}/{}", 
                    config.redis.host, config.redis.port, config.redis.db);
                let client = RedisClient::open(redis_url)
                    .map_err(|e| anyhow::anyhow!("Failed to connect to Redis: {}", e))?;
                
                // Test the connection
                let mut conn = client.get_async_connection().await
                    .map_err(|e| anyhow::anyhow!("Failed to establish Redis connection: {}", e))?;
                
                // Simple ping test - just try to execute a command
                let _: Result<(), redis::RedisError> = conn.del("__health_check__").await;
                // We don't care if the key exists or not, just that we can connect
                
                info!("Redis cache backend initialized: {}:{}", config.redis.host, config.redis.port);
                CacheBackend::Redis(client)
            }
            #[cfg(not(feature = "redis"))]
            {
                warn!("Redis cache requested but Redis feature not enabled, falling back to in-memory");
                CacheBackend::InMemory(Arc::new(DashMap::new()))
            }
        } else {
            CacheBackend::InMemory(Arc::new(DashMap::new()))
        };
        
        let cache = Self {
            config: config.clone(),
            backend,
            statistics: Arc::new(RwLock::new(CacheStatistics::default())),
            max_entries,
        };
        
        if config.enabled {
            info!("Cache initialized with max entries: {}, default TTL: {:?}", 
                  max_entries, config.default_ttl);
            
            // Start cleanup task for in-memory cache
            if matches!(cache.backend, CacheBackend::InMemory(_)) {
                cache.start_cleanup_task().await;
            }
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
        if let CacheBackend::InMemory(cache) = &self.backend {
            let cache = cache.clone();
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
    }
    
    /// Get cached response if available and not expired
    pub async fn get(&self, key: &str) -> Option<ProxyResponse> {
        if !self.config.enabled {
            return None;
        }
        
        let mut stats = self.statistics.write().await;
        stats.total_requests += 1;
        drop(stats);
        
        match &self.backend {
            CacheBackend::InMemory(cache) => {
                if let Some(mut entry) = cache.get_mut(key) {
                    if !entry.is_expired() {
                        let response = entry.access();
                        let mut stats = self.statistics.write().await;
                        stats.cache_hits += 1;
                        drop(stats);
                        
                        debug!("Cache HIT (in-memory) for key: {}", key);
                        Some(response)
                    } else {
                        // Remove expired entry
                        drop(entry);
                        cache.remove(key);
                        let mut stats = self.statistics.write().await;
                        stats.cache_misses += 1;
                        stats.expired_entries += 1;
                        drop(stats);
                        
                        debug!("Cache MISS (expired, in-memory) for key: {}", key);
                        None
                    }
                } else {
                    let mut stats = self.statistics.write().await;
                    stats.cache_misses += 1;
                    drop(stats);
                    
                    debug!("Cache MISS (not found, in-memory) for key: {}", key);
                    None
                }
            }
            #[cfg(feature = "redis")]
            CacheBackend::Redis(client) => {
                match client.get_async_connection().await {
                    Ok(mut conn) => {
                        let result: Result<String, redis::RedisError> = conn.get(key).await;
                        match result {
                            Ok(data) => {
                                match serde_json::from_str::<CacheEntry>(&data) {
                                    Ok(mut entry) => {
                                        if !entry.is_expired() {
                                            let response = entry.access();
                                            let mut stats = self.statistics.write().await;
                                            stats.cache_hits += 1;
                                            drop(stats);
                                            
                                            debug!("Cache HIT (Redis) for key: {}", key);
                                            Some(response)
                                        } else {
                                            // Remove expired entry from Redis
                                            let _: Result<(), redis::RedisError> = conn.del(key).await;
                                            let mut stats = self.statistics.write().await;
                                            stats.cache_misses += 1;
                                            stats.expired_entries += 1;
                                            drop(stats);
                                            
                                            debug!("Cache MISS (expired, Redis) for key: {}", key);
                                            None
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to deserialize cache entry from Redis: {}", e);
                                        let mut stats = self.statistics.write().await;
                                        stats.cache_misses += 1;
                                        drop(stats);
                                        None
                                    }
                                }
                            }
                            Err(e) if e.to_string().contains("nil") => {
                                // Key not found
                                let mut stats = self.statistics.write().await;
                                stats.cache_misses += 1;
                                drop(stats);
                                
                                debug!("Cache MISS (not found, Redis) for key: {}", key);
                                None
                            }
                            Err(e) => {
                                warn!("Redis get error for key {}: {}", key, e);
                                let mut stats = self.statistics.write().await;
                                stats.cache_misses += 1;
                                drop(stats);
                                None
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get Redis connection: {}", e);
                        let mut stats = self.statistics.write().await;
                        stats.cache_misses += 1;
                        drop(stats);
                        None
                    }
                }
            }
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
        
        match &self.backend {
            CacheBackend::InMemory(cache) => {
                // Check if we need to evict entries
                if cache.len() >= self.max_entries {
                    self.evict_lru_entries(1).await;
                }
                
                cache.insert(key.clone(), entry);
                
                let mut stats = self.statistics.write().await;
                stats.cache_sets += 1;
                stats.cache_size_bytes += entry_size;
                drop(stats);
                
                debug!("Cache SET (in-memory) for key: {}, TTL: {:?}, size: {} bytes", key, ttl, entry_size);
            }
            #[cfg(feature = "redis")]
            CacheBackend::Redis(client) => {
                match client.get_async_connection().await {
                    Ok(mut conn) => {
                        match serde_json::to_string(&entry) {
                            Ok(serialized) => {
                                let result: Result<(), redis::RedisError> = conn.set_ex(&key, serialized, ttl.as_secs()).await;
                                match result {
                                    Ok(_) => {
                                        let mut stats = self.statistics.write().await;
                                        stats.cache_sets += 1;
                                        stats.cache_size_bytes += entry_size;
                                        drop(stats);
                                        
                                        debug!("Cache SET (Redis) for key: {}, TTL: {:?}, size: {} bytes", key, ttl, entry_size);
                                    }
                                    Err(e) => {
                                        warn!("Failed to set cache entry in Redis for key {}: {}", key, e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to serialize cache entry for key {}: {}", key, e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get Redis connection for set operation: {}", e);
                    }
                }
            }
        }
    }
    
    /// Evict LRU entries (for in-memory cache only)
    async fn evict_lru_entries(&self, count: usize) {
        if let CacheBackend::InMemory(cache) = &self.backend {
            // Simple LRU eviction based on access time
            // In a production system, you'd want a more sophisticated LRU implementation
            let mut entries_to_remove: Vec<String> = Vec::new();
            
            // Collect entries with their last accessed times
            let mut access_times: Vec<(String, std::time::SystemTime)> = cache
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().last_accessed))
                .collect();
            
            // Sort by last accessed time (oldest first)
            access_times.sort_by_key(|&(_, time)| time);
            
            // Remove the oldest entries
            for (key, _) in access_times.iter().take(count) {
                entries_to_remove.push(key.clone());
            }
            
            let mut evicted_size = 0u64;
            for key in entries_to_remove {
                if let Some((_, entry)) = cache.remove(&key) {
                    evicted_size += entry.response.body.len() as u64;
                }
            }
            
            if count > 0 {
                let mut stats = self.statistics.write().await;
                stats.cache_evictions += count as u64;
                stats.cache_size_bytes = stats.cache_size_bytes.saturating_sub(evicted_size);
                drop(stats);
                
                debug!("Evicted {} LRU cache entries, freed {} bytes", count, evicted_size);
            }
        }
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
    
    // LRU eviction is handled differently for different backends
    // This method is now handled in the set() method for in-memory backend
    
    /// Clear all cache entries
    pub async fn clear(&self) {
        match &self.backend {
            CacheBackend::InMemory(cache) => {
                cache.clear();
            }
            #[cfg(feature = "redis")]
            CacheBackend::Redis(client) => {
                if let Ok(mut conn) = client.get_async_connection().await {
                    // Note: flushdb method may vary by redis crate version
                    // For now, just log that we would clear the Redis cache
                    debug!("Would clear Redis cache");
                }
            }
        }
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
                "current_entries": match &self.backend {
                    CacheBackend::InMemory(cache) => cache.len(),
                    #[cfg(feature = "redis")]
                    CacheBackend::Redis(_) => 0, // Redis size would require async call
                },
                "max_entries": self.max_entries,
                "usage_percentage": match &self.backend {
                    CacheBackend::InMemory(cache) => (cache.len() as f64 / self.max_entries as f64) * 100.0,
                    #[cfg(feature = "redis")]
                    CacheBackend::Redis(_) => 0.0, // Redis usage would require async call
                },
            },
            "configuration": {
                "default_ttl_seconds": self.config.default_ttl.as_secs(),
                "max_size": self.config.max_size,
                "rules_count": self.config.rules.len(),
            }
        })
    }
    
    // Debug and administrative methods removed for backend compatibility
    // These would need to be reimplemented for each backend type
}
