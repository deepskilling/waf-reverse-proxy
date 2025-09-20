use std::sync::Arc;
// Removed unused import
use regex::Regex;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use once_cell::sync::Lazy;

use crate::config::OwaspProtectionConfig;
use super::{RequestContext, WafInspectionResult, WafAction};

/// OWASP Top 10 protection patterns
#[allow(dead_code)]
static SQL_INJECTION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Classic SQL injection patterns
        Regex::new(r"(?i)\b(union\s+(all\s+)?select)\b").unwrap(),
        Regex::new(r"(?i)\b(select\s+.+\s+from)\b").unwrap(),
        Regex::new(r"(?i)\b(insert\s+into)\b").unwrap(),
        Regex::new(r"(?i)\b(delete\s+from)\b").unwrap(),
        Regex::new(r"(?i)\b(update\s+.+\s+set)\b").unwrap(),
        Regex::new(r"(?i)\b(drop\s+(table|database))\b").unwrap(),
        
        // Common injection techniques
        Regex::new(r"(?i)(\'\s*(or|and)\s*\'\w*\'\s*=\s*\'\w*\')").unwrap(),
        Regex::new(r"(?i)(\'\s*(or|and)\s*\d+\s*=\s*\d+)").unwrap(),
        Regex::new(r"(?i)(\-\-|\#|\/\*|\*\/)").unwrap(),
        Regex::new(r"(?i)(exec(\s|\+)+(s|x)p\w+)").unwrap(),
        
        // Time-based and error-based techniques
        Regex::new(r"(?i)\b(waitfor\s+delay)\b").unwrap(),
        Regex::new(r"(?i)\b(benchmark\s*\(|sleep\s*\()").unwrap(),
        Regex::new(r"(?i)\b(extractvalue\s*\(|updatexml\s*\()").unwrap(),
        
        // Hex and char conversion
        Regex::new(r"(?i)(0x[0-9a-f]+|char\s*\(|ascii\s*\()").unwrap(),
    ]
});

#[allow(dead_code)]
static XSS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Script tags
        Regex::new(r"(?i)<script[^>]*>").unwrap(),
        Regex::new(r"(?i)</script>").unwrap(),
        
        // Event handlers
        Regex::new(r"(?i)\bon\w+\s*=").unwrap(),
        
        // JavaScript protocols
        Regex::new(r"(?i)javascript\s*:").unwrap(),
        Regex::new(r"(?i)vbscript\s*:").unwrap(),
        
        // Common XSS payloads
        Regex::new(r"(?i)<img[^>]+src[^>]*=").unwrap(),
        Regex::new(r"(?i)<iframe[^>]*>").unwrap(),
        Regex::new(r"(?i)<object[^>]*>").unwrap(),
        Regex::new(r"(?i)<embed[^>]*>").unwrap(),
        
        // Expression and eval
        Regex::new(r"(?i)(expression\s*\(|eval\s*\()").unwrap(),
        
        // Data URLs
        Regex::new(r"(?i)data\s*:\s*(text|application)").unwrap(),
    ]
});

#[allow(dead_code)]
static RCE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Command execution
        Regex::new(r"(?i)\b(system\s*\(|exec\s*\(|shell_exec\s*\()").unwrap(),
        Regex::new(r"(?i)\b(passthru\s*\(|popen\s*\(|proc_open\s*\()").unwrap(),
        
        // File operations
        Regex::new(r"(?i)\b(file_get_contents\s*\(|readfile\s*\(|fopen\s*\()").unwrap(),
        Regex::new(r"(?i)\b(include\s*\(|require\s*\(|include_once\s*\()").unwrap(),
        
        // Eval functions
        Regex::new(r"(?i)\b(eval\s*\(|assert\s*\(|create_function\s*\()").unwrap(),
        
        // Command chaining
        Regex::new(r"[;&|`\$\(\)]").unwrap(),
        
        // Common shell commands
        Regex::new(r"(?i)\b(cat|ls|dir|pwd|whoami|id|uname)\b").unwrap(),
        Regex::new(r"(?i)\b(wget|curl|nc|netcat|telnet)\b").unwrap(),
    ]
});

#[allow(dead_code)]
static PATH_TRAVERSAL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        // Directory traversal
        Regex::new(r"(\.\./)|(\.\.\\)").unwrap(),
        Regex::new(r"%2e%2e%2f").unwrap(), // URL encoded ../
        Regex::new(r"%2e%2e/").unwrap(),   // Partially encoded ../
        Regex::new(r"\.%2e/").unwrap(),    // Partially encoded ../
        
        // Null byte injection
        Regex::new(r"%00").unwrap(),
        
        // Common sensitive files
        Regex::new(r"(?i)/(etc/passwd|etc/shadow|windows/system32)").unwrap(),
        Regex::new(r"(?i)\.\./(etc/|windows/|usr/|var/|boot/)").unwrap(),
    ]
});

/// OWASP Top 10 protector
#[allow(dead_code)]
pub struct OwaspProtector {
    config: Arc<RwLock<OwaspProtectionConfig>>,
    statistics: Arc<RwLock<OwaspStatistics>>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
struct OwaspStatistics {
    total_checks: u64,
    sql_injection_detected: u64,
    xss_detected: u64,
    rce_detected: u64,
    path_traversal_detected: u64,
    csrf_detected: u64,
}

impl OwaspProtector {
    pub fn new(config: &OwaspProtectionConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config.clone())),
            statistics: Arc::new(RwLock::new(OwaspStatistics::default())),
        }
    }
    
    /// Check request for OWASP Top 10 vulnerabilities
    pub async fn check(&self, context: &RequestContext) -> Option<WafInspectionResult> {
        let config = self.config.read().await;
        let mut stats = self.statistics.write().await;
        
        stats.total_checks += 1;
        drop(stats);
        
        // 1. SQL Injection Detection
        if config.sql_injection.enabled {
            if let Some(result) = self.check_sql_injection(context, &config).await {
                let mut stats = self.statistics.write().await;
                stats.sql_injection_detected += 1;
                return Some(result);
            }
        }
        
        // 2. XSS Detection
        if config.xss_protection.enabled {
            if let Some(result) = self.check_xss(context, &config).await {
                let mut stats = self.statistics.write().await;
                stats.xss_detected += 1;
                return Some(result);
            }
        }
        
        // 3. RCE Detection
        if config.rce_protection.enabled {
            if let Some(result) = self.check_rce(context, &config).await {
                let mut stats = self.statistics.write().await;
                stats.rce_detected += 1;
                return Some(result);
            }
        }
        
        // 4. Path Traversal Detection
        if config.path_traversal.enabled {
            if let Some(result) = self.check_path_traversal(context, &config).await {
                let mut stats = self.statistics.write().await;
                stats.path_traversal_detected += 1;
                return Some(result);
            }
        }
        
        // 5. CSRF Detection
        if config.csrf_protection.enabled {
            if let Some(result) = self.check_csrf(context, &config).await {
                let mut stats = self.statistics.write().await;
                stats.csrf_detected += 1;
                return Some(result);
            }
        }
        
        None
    }
    
    async fn check_sql_injection(&self, context: &RequestContext, config: &OwaspProtectionConfig) -> Option<WafInspectionResult> {
        let mut confidence = 0.0f32;
        let mut matched_patterns = Vec::new();
        
        // Check URI for SQL injection
        for pattern in SQL_INJECTION_PATTERNS.iter() {
            if pattern.is_match(&context.uri) {
                confidence += 0.3;
                matched_patterns.push("uri");
                break;
            }
        }
        
        // Check query string
        for pattern in SQL_INJECTION_PATTERNS.iter() {
            if pattern.is_match(&context.query_string) {
                confidence += 0.4;
                matched_patterns.push("query");
                break;
            }
        }
        
        // Check request body if available
        if let Some(body) = &context.body {
            if let Ok(body_str) = std::str::from_utf8(body) {
                for pattern in SQL_INJECTION_PATTERNS.iter() {
                    if pattern.is_match(body_str) {
                        confidence += 0.5;
                        matched_patterns.push("body");
                        break;
                    }
                }
            }
        }
        
        if confidence >= config.sql_injection.confidence_threshold {
            debug!("SQL injection detected with confidence {}: {:?}", confidence, matched_patterns);
            Some(WafInspectionResult {
                action: WafAction::Block,
                reason: "SQL injection attempt detected".to_string(),
                rule_name: Some("sql_injection".to_string()),
                confidence,
                metadata: serde_json::json!({
                    "attack_type": "sql_injection",
                    "matched_in": matched_patterns,
                    "confidence": confidence,
                }),
            })
        } else {
            None
        }
    }
    
    async fn check_xss(&self, context: &RequestContext, config: &OwaspProtectionConfig) -> Option<WafInspectionResult> {
        let mut confidence = 0.0f32;
        let mut matched_patterns = Vec::new();
        
        // Check URI
        for pattern in XSS_PATTERNS.iter() {
            if pattern.is_match(&context.uri) {
                confidence += 0.3;
                matched_patterns.push("uri");
                break;
            }
        }
        
        // Check query string
        for pattern in XSS_PATTERNS.iter() {
            if pattern.is_match(&context.query_string) {
                confidence += 0.4;
                matched_patterns.push("query");
                break;
            }
        }
        
        // Check request body
        if let Some(body) = &context.body {
            if let Ok(body_str) = std::str::from_utf8(body) {
                for pattern in XSS_PATTERNS.iter() {
                    if pattern.is_match(body_str) {
                        confidence += 0.5;
                        matched_patterns.push("body");
                        break;
                    }
                }
            }
        }
        
        if confidence >= config.xss_protection.confidence_threshold {
            debug!("XSS detected with confidence {}: {:?}", confidence, matched_patterns);
            Some(WafInspectionResult {
                action: WafAction::Block,
                reason: "Cross-site scripting (XSS) attempt detected".to_string(),
                rule_name: Some("xss".to_string()),
                confidence,
                metadata: serde_json::json!({
                    "attack_type": "xss",
                    "matched_in": matched_patterns,
                    "confidence": confidence,
                }),
            })
        } else {
            None
        }
    }
    
    async fn check_rce(&self, context: &RequestContext, config: &OwaspProtectionConfig) -> Option<WafInspectionResult> {
        let mut confidence = 0.0f32;
        let mut matched_patterns = Vec::new();
        
        // Check URI
        for pattern in RCE_PATTERNS.iter() {
            if pattern.is_match(&context.uri) {
                confidence += 0.4;
                matched_patterns.push("uri");
                break;
            }
        }
        
        // Check query string
        for pattern in RCE_PATTERNS.iter() {
            if pattern.is_match(&context.query_string) {
                confidence += 0.5;
                matched_patterns.push("query");
                break;
            }
        }
        
        // Check request body
        if let Some(body) = &context.body {
            if let Ok(body_str) = std::str::from_utf8(body) {
                for pattern in RCE_PATTERNS.iter() {
                    if pattern.is_match(body_str) {
                        confidence += 0.6;
                        matched_patterns.push("body");
                        break;
                    }
                }
            }
        }
        
        if confidence >= config.rce_protection.confidence_threshold {
            warn!("RCE attempt detected with confidence {}: {:?}", confidence, matched_patterns);
            Some(WafInspectionResult {
                action: WafAction::Block,
                reason: "Remote code execution (RCE) attempt detected".to_string(),
                rule_name: Some("rce".to_string()),
                confidence,
                metadata: serde_json::json!({
                    "attack_type": "rce",
                    "matched_in": matched_patterns,
                    "confidence": confidence,
                }),
            })
        } else {
            None
        }
    }
    
    async fn check_path_traversal(&self, context: &RequestContext, config: &OwaspProtectionConfig) -> Option<WafInspectionResult> {
        let mut confidence = 0.0f32;
        let mut matched_patterns = Vec::new();
        
        // Check URI
        for pattern in PATH_TRAVERSAL_PATTERNS.iter() {
            if pattern.is_match(&context.uri) {
                confidence += 0.5;
                matched_patterns.push("uri");
                break;
            }
        }
        
        // Check query string
        for pattern in PATH_TRAVERSAL_PATTERNS.iter() {
            if pattern.is_match(&context.query_string) {
                confidence += 0.4;
                matched_patterns.push("query");
                break;
            }
        }
        
        if confidence >= config.path_traversal.confidence_threshold {
            warn!("Path traversal attempt detected with confidence {}: {:?}", confidence, matched_patterns);
            Some(WafInspectionResult {
                action: WafAction::Block,
                reason: "Path traversal attempt detected".to_string(),
                rule_name: Some("path_traversal".to_string()),
                confidence,
                metadata: serde_json::json!({
                    "attack_type": "path_traversal",
                    "matched_in": matched_patterns,
                    "confidence": confidence,
                }),
            })
        } else {
            None
        }
    }
    
    async fn check_csrf(&self, context: &RequestContext, config: &OwaspProtectionConfig) -> Option<WafInspectionResult> {
        // Simple CSRF check - look for state-changing methods without proper tokens
        if !["POST", "PUT", "DELETE", "PATCH"].contains(&context.method.as_str()) {
            return None;
        }
        
        if !config.csrf_protection.require_token {
            return None;
        }
        
        // Check for CSRF token in headers or body
        let has_csrf_token = context.headers.contains_key("x-csrf-token") ||
                            context.headers.contains_key("x-xsrf-token") ||
                            context.query_string.contains("_token=") ||
                            context.body.as_ref()
                                .and_then(|b| std::str::from_utf8(b).ok())
                                .map(|s| s.contains("_token="))
                                .unwrap_or(false);
        
        if !has_csrf_token {
            warn!("CSRF token missing for state-changing request from {}", context.client_ip);
            Some(WafInspectionResult {
                action: WafAction::Block,
                reason: "CSRF token required for state-changing requests".to_string(),
                rule_name: Some("csrf".to_string()),
                confidence: 0.8,
                metadata: serde_json::json!({
                    "attack_type": "csrf",
                    "method": context.method,
                    "missing_token": true,
                }),
            })
        } else {
            None
        }
    }
    
    /// Update OWASP protection configuration
    pub async fn update_config(&self, new_config: &OwaspProtectionConfig) {
        let mut config = self.config.write().await;
        *config = new_config.clone();
    }
    
    /// Get OWASP protection statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        let stats = self.statistics.read().await;
        serde_json::json!({
            "total_checks": stats.total_checks,
            "detections": {
                "sql_injection": stats.sql_injection_detected,
                "xss": stats.xss_detected,
                "rce": stats.rce_detected,
                "path_traversal": stats.path_traversal_detected,
                "csrf": stats.csrf_detected,
            },
            "detection_rate": if stats.total_checks > 0 {
                ((stats.sql_injection_detected + stats.xss_detected + stats.rce_detected + 
                  stats.path_traversal_detected + stats.csrf_detected) as f64) / (stats.total_checks as f64)
            } else {
                0.0
            }
        })
    }
}
