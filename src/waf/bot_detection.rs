use std::sync::Arc;
// Removed unused HashMap import
use std::time::{Duration, Instant};
// Removed unused Result import
use regex::Regex;
use tokio::sync::RwLock;
use dashmap::DashMap;
use tracing::{debug, warn};
use once_cell::sync::Lazy;

use crate::config::BotProtectionConfig;
use super::{RequestContext, WafInspectionResult, WafAction};

/// Known bad bot user agents
#[allow(dead_code)]
static BAD_BOT_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Common scrapers
        Regex::new(r"(?i)(scrapy|beautifulsoup|mechanize|requests|urllib|python)").unwrap(),
        
        // Known malicious bots
        Regex::new(r"(?i)(masscan|nmap|nikto|sqlmap|wpscan|acunetix)").unwrap(),
        
        // Generic bot patterns
        Regex::new(r"(?i)(bot|crawler|spider|scraper|scanner)").unwrap(),
        
        // Headless browsers often used for scraping
        Regex::new(r"(?i)(phantomjs|headlesschrome|slimerjs)").unwrap(),
        
        // Empty or suspicious user agents
        Regex::new(r"^$|^\-$|^null$|^undefined$").unwrap(),
        
        // Common automation tools
        Regex::new(r"(?i)(selenium|puppeteer|playwright|webdriver)").unwrap(),
    ]
});

/// Good bot patterns (search engines, legitimate crawlers)
#[allow(dead_code)]
static GOOD_BOT_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)googlebot").unwrap(),
        Regex::new(r"(?i)bingbot").unwrap(),
        Regex::new(r"(?i)slurp").unwrap(), // Yahoo
        Regex::new(r"(?i)duckduckbot").unwrap(),
        Regex::new(r"(?i)baiduspider").unwrap(),
        Regex::new(r"(?i)yandexbot").unwrap(),
        Regex::new(r"(?i)facebookexternalhit").unwrap(),
        Regex::new(r"(?i)twitterbot").unwrap(),
        Regex::new(r"(?i)linkedinbot").unwrap(),
    ]
});

/// Suspicious patterns in requests that might indicate bot behavior
#[allow(dead_code)]
static SUSPICIOUS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Looking for common vulnerabilities
        Regex::new(r"(?i)/(wp-admin|phpmyadmin|admin|login\.php)").unwrap(),
        Regex::new(r"(?i)/\.(env|git|svn|htaccess)").unwrap(),
        
        // Common attack patterns
        Regex::new(r"(?i)/(shell|webshell|c99|r57|wso)\.php").unwrap(),
        Regex::new(r"(?i)/wp-content/.*\.php").unwrap(),
        
        // Directory enumeration
        Regex::new(r"(?i)/(backup|old|test|dev|staging)/").unwrap(),
    ]
});

/// Bot behavior tracking
#[derive(Debug)]
#[allow(dead_code)]
struct BotBehavior {
    request_count: u64,
    first_seen: Instant,
    last_seen: Instant,
    suspicious_requests: u64,
    user_agents: std::collections::HashSet<String>,
    request_intervals: Vec<Duration>,
    paths_accessed: std::collections::HashSet<String>,
}

impl BotBehavior {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            request_count: 0,
            first_seen: now,
            last_seen: now,
            suspicious_requests: 0,
            user_agents: std::collections::HashSet::new(),
            request_intervals: Vec::new(),
            paths_accessed: std::collections::HashSet::new(),
        }
    }
    
    fn update_request(&mut self, user_agent: Option<&str>, path: &str, is_suspicious: bool) {
        let now = Instant::now();
        
        if self.request_count > 0 {
            let interval = now.duration_since(self.last_seen);
            self.request_intervals.push(interval);
            
            // Keep only recent intervals (last 100 requests)
            if self.request_intervals.len() > 100 {
                self.request_intervals.remove(0);
            }
        }
        
        self.request_count += 1;
        self.last_seen = now;
        
        if let Some(ua) = user_agent {
            self.user_agents.insert(ua.to_string());
        }
        
        self.paths_accessed.insert(path.to_string());
        
        if is_suspicious {
            self.suspicious_requests += 1;
        }
    }
    
    fn calculate_bot_score(&self) -> f32 {
        let mut score = 0.0f32;
        
        // High request rate
        let duration_minutes = self.last_seen.duration_since(self.first_seen).as_secs() as f32 / 60.0;
        if duration_minutes > 0.0 {
            let requests_per_minute = self.request_count as f32 / duration_minutes;
            if requests_per_minute > 60.0 {
                score += 0.3;
            } else if requests_per_minute > 30.0 {
                score += 0.2;
            }
        }
        
        // Consistent request intervals (robotic behavior)
        if self.request_intervals.len() >= 10 {
            let avg_interval = self.request_intervals.iter()
                .map(|d| d.as_millis() as f32)
                .sum::<f32>() / self.request_intervals.len() as f32;
            
            let variance = self.request_intervals.iter()
                .map(|d| {
                    let diff = d.as_millis() as f32 - avg_interval;
                    diff * diff
                })
                .sum::<f32>() / self.request_intervals.len() as f32;
            
            let std_dev = variance.sqrt();
            let coefficient_of_variation = if avg_interval > 0.0 { std_dev / avg_interval } else { 0.0 };
            
            // Low variation indicates robotic behavior
            if coefficient_of_variation < 0.1 {
                score += 0.3;
            } else if coefficient_of_variation < 0.2 {
                score += 0.2;
            }
        }
        
        // Multiple user agents from same IP
        if self.user_agents.len() > 3 {
            score += 0.2;
        }
        
        // High ratio of suspicious requests
        let suspicious_ratio = self.suspicious_requests as f32 / self.request_count as f32;
        if suspicious_ratio > 0.5 {
            score += 0.4;
        } else if suspicious_ratio > 0.2 {
            score += 0.2;
        }
        
        // Accessing many different paths quickly
        if self.paths_accessed.len() > 50 && duration_minutes < 5.0 {
            score += 0.3;
        }
        
        score.min(1.0)
    }
}

/// Bot detection engine
#[allow(dead_code)]
pub struct BotDetector {
    config: Arc<RwLock<BotProtectionConfig>>,
    ip_behaviors: Arc<DashMap<std::net::IpAddr, BotBehavior>>,
    statistics: Arc<RwLock<BotStatistics>>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct BotStatistics {
    total_checks: u64,
    bad_bots_detected: u64,
    good_bots_allowed: u64,
    behavioral_bots_detected: u64,
    suspicious_requests: u64,
}

impl BotDetector {
    pub fn new(config: &BotProtectionConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config.clone())),
            ip_behaviors: Arc::new(DashMap::new()),
            statistics: Arc::new(RwLock::new(BotStatistics::default())),
        }
    }
    
    /// Check if request is from a bot and determine action
    pub async fn check(&self, context: &RequestContext) -> Option<WafInspectionResult> {
        let config = self.config.read().await;
        
        if !config.enabled {
            return None;
        }
        
        let mut stats = self.statistics.write().await;
        stats.total_checks += 1;
        drop(stats);
        
        // 1. Check for known good bots (allow immediately)
        if let Some(user_agent) = &context.user_agent {
            for pattern in GOOD_BOT_PATTERNS.iter() {
                if pattern.is_match(user_agent) {
                    debug!("Good bot detected: {}", user_agent);
                    let mut stats = self.statistics.write().await;
                    stats.good_bots_allowed += 1;
                    return Some(WafInspectionResult {
                        action: WafAction::Allow,
                        reason: "Legitimate search engine bot".to_string(),
                        rule_name: Some("good_bot".to_string()),
                        confidence: 0.9,
                        metadata: serde_json::json!({
                            "bot_type": "good_bot",
                            "user_agent": user_agent,
                        }),
                    });
                }
            }
        }
        
        // 2. Check for known bad bots
        if config.block_known_bots {
            if let Some(result) = self.check_bad_bot_patterns(context).await {
                let mut stats = self.statistics.write().await;
                stats.bad_bots_detected += 1;
                return Some(result);
            }
        }
        
        // 3. Check for suspicious request patterns
        let is_suspicious = self.is_suspicious_request(context).await;
        if is_suspicious {
            let mut stats = self.statistics.write().await;
            stats.suspicious_requests += 1;
        }
        
        // 4. Behavioral analysis
        if config.behavioral_analysis {
            if let Some(result) = self.analyze_behavior(context, is_suspicious).await {
                let mut stats = self.statistics.write().await;
                stats.behavioral_bots_detected += 1;
                return Some(result);
            }
        }
        
        None
    }
    
    async fn check_bad_bot_patterns(&self, context: &RequestContext) -> Option<WafInspectionResult> {
        if let Some(user_agent) = &context.user_agent {
            for pattern in BAD_BOT_PATTERNS.iter() {
                if pattern.is_match(user_agent) {
                    warn!("Bad bot detected: {}", user_agent);
                    return Some(WafInspectionResult {
                        action: WafAction::Block,
                        reason: format!("Known malicious bot detected: {}", user_agent),
                        rule_name: Some("bad_bot".to_string()),
                        confidence: 0.9,
                        metadata: serde_json::json!({
                            "bot_type": "bad_bot",
                            "user_agent": user_agent,
                            "client_ip": context.client_ip.to_string(),
                        }),
                    });
                }
            }
        }
        
        None
    }
    
    async fn is_suspicious_request(&self, context: &RequestContext) -> bool {
        for pattern in SUSPICIOUS_PATTERNS.iter() {
            if pattern.is_match(&context.uri) {
                return true;
            }
        }
        
        // Check for other suspicious indicators
        if context.user_agent.is_none() || 
           context.user_agent.as_ref().map(|ua| ua.is_empty()).unwrap_or(true) {
            return true;
        }
        
        false
    }
    
    async fn analyze_behavior(&self, context: &RequestContext, is_suspicious: bool) -> Option<WafInspectionResult> {
        let config = self.config.read().await;
        
        // Update behavior tracking
        let mut behavior = self.ip_behaviors
            .entry(context.client_ip)
            .or_insert_with(BotBehavior::new);
        
        behavior.update_request(
            context.user_agent.as_deref(),
            &context.uri,
            is_suspicious
        );
        
        let bot_score = behavior.calculate_bot_score();
        
        if bot_score > 0.7 {
            warn!("Behavioral bot detected from {} with score {}", context.client_ip, bot_score);
            
            let action = if config.challenge_suspicious {
                WafAction::Challenge
            } else {
                WafAction::Block
            };
            
            Some(WafInspectionResult {
                action,
                reason: format!("Behavioral analysis indicates bot activity (score: {:.2})", bot_score),
                rule_name: Some("behavioral_bot".to_string()),
                confidence: bot_score,
                metadata: serde_json::json!({
                    "bot_type": "behavioral_bot",
                    "bot_score": bot_score,
                    "client_ip": context.client_ip.to_string(),
                    "request_count": behavior.request_count,
                    "suspicious_requests": behavior.suspicious_requests,
                    "user_agents_count": behavior.user_agents.len(),
                }),
            })
        } else {
            None
        }
    }
    
    /// Clean up old behavior tracking data
    pub async fn cleanup_old_behaviors(&self) {
        let cleanup_threshold = Instant::now() - Duration::from_secs(3600); // 1 hour
        
        self.ip_behaviors.retain(|_, behavior| {
            behavior.last_seen > cleanup_threshold
        });
        
        debug!("Cleaned up old bot behaviors. Active IPs: {}", self.ip_behaviors.len());
    }
    
    /// Get bot detection statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let stats = self.statistics.read().await;
        serde_json::json!({
            "total_checks": stats.total_checks,
            "detections": {
                "bad_bots": stats.bad_bots_detected,
                "good_bots": stats.good_bots_allowed,
                "behavioral_bots": stats.behavioral_bots_detected,
            },
            "suspicious_requests": stats.suspicious_requests,
            "active_ip_tracking": self.ip_behaviors.len(),
            "detection_rate": if stats.total_checks > 0 {
                (stats.bad_bots_detected + stats.behavioral_bots_detected) as f64 / stats.total_checks as f64
            } else {
                0.0
            }
        })
    }
    
    /// Update bot protection configuration
    pub async fn update_config(&self, new_config: &BotProtectionConfig) {
        let mut config = self.config.write().await;
        *config = new_config.clone();
    }
}
