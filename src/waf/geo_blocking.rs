use std::sync::Arc;
use anyhow::Result;
use tokio::sync::RwLock;
use tracing::{debug, warn, error};
use maxminddb::{MaxMindDBError, Reader};
use serde::Deserialize;

use crate::config::GeoBlockingConfig;
use super::{RequestContext, WafInspectionResult, WafAction};

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct GeoRecord {
    country: Option<Country>,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Country {
    iso_code: Option<String>,
    names: Option<std::collections::HashMap<String, String>>,
}

/// Geo-blocking engine using MaxMind GeoIP database
#[allow(dead_code)]
pub struct GeoBlocker {
    config: Arc<RwLock<GeoBlockingConfig>>,
    reader: Option<Reader<Vec<u8>>>,
    statistics: Arc<RwLock<GeoStatistics>>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct GeoStatistics {
    total_lookups: u64,
    successful_lookups: u64,
    blocked_requests: u64,
    allowed_requests: u64,
    unknown_locations: u64,
    country_stats: std::collections::HashMap<String, u64>,
}

impl GeoBlocker {
    pub async fn new(config: &GeoBlockingConfig) -> Result<Self> {
        let reader = if !config.geodb_path.is_empty() && std::path::Path::new(&config.geodb_path).exists() {
            match Reader::open_readfile(&config.geodb_path) {
                Ok(reader) => {
                    debug!("Loaded GeoIP database from {}", config.geodb_path);
                    Some(reader)
                }
                Err(e) => {
                    error!("Failed to load GeoIP database from {}: {}", config.geodb_path, e);
                    None
                }
            }
        } else {
            warn!("GeoIP database not found at {}, geo-blocking will not function", config.geodb_path);
            None
        };
        
        Ok(Self {
            config: Arc::new(RwLock::new(config.clone())),
            reader,
            statistics: Arc::new(RwLock::new(GeoStatistics::default())),
        })
    }
    
    /// Check if request should be geo-blocked
    pub async fn check(&self, context: &RequestContext) -> Option<WafInspectionResult> {
        let config = self.config.read().await;
        
        if !config.enabled {
            return None;
        }
        
        let reader = match &self.reader {
            Some(reader) => reader,
            None => {
                warn!("GeoIP database not available, cannot perform geo-blocking");
                return None;
            }
        };
        
        let mut stats = self.statistics.write().await;
        stats.total_lookups += 1;
        drop(stats);
        
        // Perform GeoIP lookup
        let country_code = match self.lookup_country(&context.client_ip, reader).await {
            Some(code) => {
                let mut stats = self.statistics.write().await;
                stats.successful_lookups += 1;
                *stats.country_stats.entry(code.clone()).or_insert(0) += 1;
                drop(stats);
                code
            }
            None => {
                let mut stats = self.statistics.write().await;
                stats.unknown_locations += 1;
                drop(stats);
                debug!("Could not determine country for IP {}", context.client_ip);
                return None;
            }
        };
        
        debug!("IP {} is from country: {}", context.client_ip, country_code);
        
        // Check if country is blocked
        let should_block = self.should_block_country(&country_code, &config);
        
        if should_block {
            warn!("Geo-blocking request from {} (country: {})", context.client_ip, country_code);
            let mut stats = self.statistics.write().await;
            stats.blocked_requests += 1;
            
            Some(WafInspectionResult {
                action: WafAction::Block,
                reason: format!("Request blocked due to geo-location: {}", country_code),
                rule_name: Some("geo_blocking".to_string()),
                confidence: 1.0,
                metadata: serde_json::json!({
                    "blocked_country": country_code,
                    "client_ip": context.client_ip.to_string(),
                    "blocking_rule": if config.blocked_countries.contains(&country_code) {
                        "blocked_list"
                    } else {
                        "not_in_allowed_list"
                    }
                }),
            })
        } else {
            debug!("Allowing request from {} (country: {})", context.client_ip, country_code);
            let mut stats = self.statistics.write().await;
            stats.allowed_requests += 1;
            None
        }
    }
    
    async fn lookup_country(&self, ip: &std::net::IpAddr, reader: &Reader<Vec<u8>>) -> Option<String> {
        match reader.lookup::<GeoRecord>(*ip) {
            Ok(record) => {
                if let Some(country) = record.country {
                    if let Some(iso_code) = country.iso_code {
                        return Some(iso_code);
                    }
                }
                None
            }
            Err(MaxMindDBError::AddressNotFoundError(_)) => {
                debug!("IP {} not found in GeoIP database", ip);
                None
            }
            Err(e) => {
                error!("Error looking up IP {} in GeoIP database: {}", ip, e);
                None
            }
        }
    }
    
    fn should_block_country(&self, country_code: &str, config: &GeoBlockingConfig) -> bool {
        // If allowlist is configured and not empty, only allow countries in the list
        if !config.allowed_countries.is_empty() {
            return !config.allowed_countries.contains(&country_code.to_string());
        }
        
        // Otherwise, block countries in the blocklist
        config.blocked_countries.contains(&country_code.to_string())
    }
    
    /// Update geo-blocking configuration
    pub async fn update_config(&self, new_config: &GeoBlockingConfig) -> Result<()> {
        let mut config = self.config.write().await;
        *config = new_config.clone();
        Ok(())
    }
    
    /// Reload GeoIP database
    pub async fn reload_database(&mut self, db_path: &str) -> Result<()> {
        match Reader::open_readfile(db_path) {
            Ok(reader) => {
                self.reader = Some(reader);
                debug!("Reloaded GeoIP database from {}", db_path);
                Ok(())
            }
            Err(e) => {
                error!("Failed to reload GeoIP database from {}: {}", db_path, e);
                Err(e.into())
            }
        }
    }
    
    /// Get geo-blocking statistics
    pub fn get_statistics(&self) -> serde_json::Value {
        // This is a synchronous method to avoid async issues in the caller
        // In a real implementation, you might want to use a different approach
        serde_json::json!({
            "enabled": true,  // We'll assume it's enabled if this object exists
            "database_loaded": self.reader.is_some(),
            "statistics": "unavailable_sync" // Would need async version for full stats
        })
    }
    
    /// Get detailed statistics (async version)
    pub async fn get_detailed_statistics(&self) -> serde_json::Value {
        let stats = self.statistics.read().await;
        let config = self.config.read().await;
        
        serde_json::json!({
            "enabled": config.enabled,
            "database_loaded": self.reader.is_some(),
            "total_lookups": stats.total_lookups,
            "successful_lookups": stats.successful_lookups,
            "blocked_requests": stats.blocked_requests,
            "allowed_requests": stats.allowed_requests,
            "unknown_locations": stats.unknown_locations,
            "success_rate": if stats.total_lookups > 0 {
                stats.successful_lookups as f64 / stats.total_lookups as f64
            } else {
                0.0
            },
            "block_rate": if stats.total_lookups > 0 {
                stats.blocked_requests as f64 / stats.total_lookups as f64
            } else {
                0.0
            },
            "country_distribution": stats.country_stats,
            "configuration": {
                "blocked_countries": config.blocked_countries,
                "allowed_countries": config.allowed_countries,
                "geodb_path": config.geodb_path,
            }
        })
    }
    
    /// Get top countries by request count
    pub async fn get_top_countries(&self, limit: usize) -> Vec<(String, u64)> {
        let stats = self.statistics.read().await;
        let mut country_counts: Vec<(String, u64)> = stats.country_stats.iter()
            .map(|(country, count)| (country.clone(), *count))
            .collect();
        
        country_counts.sort_by(|a, b| b.1.cmp(&a.1));
        country_counts.truncate(limit);
        country_counts
    }
}
