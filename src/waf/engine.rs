use std::sync::Arc;
use anyhow::Result;
use axum::{
    extract::{ConnectInfo, Request},
};
use std::net::SocketAddr;
use tracing::{info, warn, debug};

use crate::config::WafConfig;
use crate::observability::MetricsCollector;
use crate::error::{WafProxyError, Result as WafResult};
use super::{
    RequestContext, WafInspectionResult, WafAction,
    rules::RuleEngine,
    rate_limiter::RateLimiter,
    owasp::OwaspProtector,
    bot_detection::BotDetector,
    geo_blocking::GeoBlocker,
};

/// Main WAF engine that coordinates all protection mechanisms
#[allow(dead_code)]
pub struct WafEngine {
    config: WafConfig,
    rule_engine: Arc<RuleEngine>,
    rate_limiter: Arc<RateLimiter>,
    owasp_protector: Arc<OwaspProtector>,
    bot_detector: Arc<BotDetector>,
    geo_blocker: Option<Arc<GeoBlocker>>,
    metrics: Arc<MetricsCollector>,
}

impl WafEngine {
    pub async fn new(
        config: &WafConfig,
        metrics: Arc<MetricsCollector>,
    ) -> Result<Self> {
        let rule_engine = Arc::new(RuleEngine::new(&config.custom_rules)?);
        let rate_limiter = Arc::new(RateLimiter::new(&config.rate_limiting).await?);
        let owasp_protector = Arc::new(OwaspProtector::new(&config.owasp_protection));
        let bot_detector = Arc::new(BotDetector::new(&config.bot_protection));
        
        let geo_blocker = if config.geo_blocking.enabled {
            Some(Arc::new(GeoBlocker::new(&config.geo_blocking).await?))
        } else {
            None
        };
        
        Ok(Self {
            config: config.clone(),
            rule_engine,
            rate_limiter,
            owasp_protector,
            bot_detector,
            geo_blocker,
            metrics,
        })
    }
    
    /// Inspect incoming request and determine if it should be allowed
    pub async fn inspect_request(
        &self,
        req: &Request,
        connect_info: &ConnectInfo<SocketAddr>,
        body: Option<&[u8]>,
    ) -> WafResult<WafInspectionResult> {
        if !self.config.enabled {
            return Ok(WafInspectionResult {
                action: WafAction::Allow,
                reason: "WAF disabled".to_string(),
                rule_name: None,
                confidence: 1.0,
                metadata: serde_json::json!({}),
            });
        }
        
        let mut context = RequestContext::from_request(req, connect_info);
        context.body = body.map(|b| b.to_vec());
        
        debug!("WAF inspecting request from {}: {} {}", 
               context.client_ip, context.method, context.uri);
        
        // 1. Rate limiting check (fastest, do first)
        if let Err(e) = self.check_rate_limits(&context).await {
            warn!("Rate limit exceeded for {}: {}", context.client_ip, e);
            self.metrics.increment_counter("waf_rate_limit_blocks", &[
                ("client_ip", context.client_ip.to_string().as_str()),
            ]);
            return Ok(WafInspectionResult {
                action: WafAction::Block,
                reason: e.to_string(),
                rule_name: Some("rate_limit".to_string()),
                confidence: 1.0,
                metadata: serde_json::json!({
                    "client_ip": context.client_ip.to_string(),
                    "type": "rate_limit"
                }),
            });
        }
        
        // 2. Geo-blocking check
        if let Some(geo_blocker) = &self.geo_blocker {
            if let Some(result) = geo_blocker.check(&context).await {
                if result.action == WafAction::Block {
                    warn!("Geo-blocked request from {}: {}", context.client_ip, result.reason);
                    self.metrics.increment_counter("waf_geo_blocks", &[
                        ("client_ip", context.client_ip.to_string().as_str()),
                        ("country", result.metadata.get("country_code").unwrap_or(&serde_json::Value::Null).as_str().unwrap_or("unknown")),
                    ]);
                    return Ok(result);
                }
            }
        }
        
        // 3. Bot detection
        if let Some(result) = self.bot_detector.check(&context).await {
            if result.action == WafAction::Block || result.action == WafAction::Challenge {
                info!("Bot detected from {}: {}", context.client_ip, result.reason);
                self.metrics.increment_counter("waf_bot_blocks", &[
                    ("client_ip", context.client_ip.to_string().as_str()),
                    ("user_agent", context.user_agent.as_deref().unwrap_or("unknown")),
                ]);
                return Ok(result);
            }
        }
        
        // 4. OWASP Top 10 protection
        if let Some(result) = self.owasp_protector.check(&context).await {
            if result.action == WafAction::Block {
                warn!("OWASP attack detected from {}: {}", context.client_ip, result.reason);
                self.metrics.increment_counter("waf_owasp_blocks", &[
                    ("client_ip", context.client_ip.to_string().as_str()),
                    ("attack_type", result.rule_name.as_deref().unwrap_or("unknown")),
                ]);
                return Ok(result);
            }
        }
        
        // 5. Custom rules check
        if let Some(result) = self.rule_engine.evaluate(&context).await? {
            match result.action {
                WafAction::Block => {
                    warn!("Custom rule blocked request from {}: {}", context.client_ip, result.reason);
                    self.metrics.increment_counter("waf_custom_rule_blocks", &[
                        ("client_ip", context.client_ip.to_string().as_str()),
                        ("rule", result.rule_name.as_deref().unwrap_or("unknown")),
                    ]);
                }
                WafAction::Allow | WafAction::Log | WafAction::Challenge => {
                    debug!("Custom rule action for {}: {:?}", context.client_ip, result.action);
                }
            }
            return Ok(result);
        }
        
        // 6. All checks passed
        debug!("Request from {} allowed by WAF", context.client_ip);
        self.metrics.increment_counter("waf_requests_allowed", &[
            ("client_ip", context.client_ip.to_string().as_str()),
        ]);
        
        Ok(WafInspectionResult {
            action: WafAction::Allow,
            reason: "Passed all WAF checks".to_string(),
            rule_name: None,
            confidence: 1.0,
            metadata: serde_json::json!({
                "inspections": ["rate_limit", "geo_blocking", "bot_detection", "owasp", "custom_rules"]
            }),
        })
    }
    
    async fn check_rate_limits(&self, context: &RequestContext) -> WafResult<()> {
        // Check global rate limit
        if !self.rate_limiter.check_global().await? {
            return Err(WafProxyError::RateLimitExceeded {
                limit_type: "global".to_string(),
            });
        }
        
        // Check per-IP rate limit
        if !self.rate_limiter.check_per_ip(&context.client_ip).await? {
            return Err(WafProxyError::RateLimitExceeded {
                limit_type: "per_ip".to_string(),
            });
        }
        
        // Check per-endpoint rate limit
        let endpoint = format!("{}:{}", context.method, context.uri);
        if !self.rate_limiter.check_per_endpoint(&endpoint).await? {
            return Err(WafProxyError::RateLimitExceeded {
                limit_type: "per_endpoint".to_string(),
            });
        }
        
        Ok(())
    }
    
    /// Handle WAF result and return appropriate HTTP response
    pub fn handle_result(&self, result: &WafInspectionResult) -> WafResult<()> {
        match result.action {
            WafAction::Allow => Ok(()),
            WafAction::Block => Err(WafProxyError::WafBlocked {
                reason: result.reason.clone(),
            }),
            WafAction::Challenge => {
                // For now, treat challenge as block
                // In a real implementation, this would return a CAPTCHA page
                Err(WafProxyError::WafBlocked {
                    reason: format!("Challenge required: {}", result.reason),
                })
            }
            WafAction::Log => {
                // Log the event but allow the request
                info!("WAF logged event: {} (confidence: {})", 
                     result.reason, result.confidence);
                Ok(())
            }
        }
    }
    
    /// Update WAF configuration at runtime
    pub async fn update_config(&self, new_config: WafConfig) -> Result<()> {
        // Update rule engine
        self.rule_engine.update_rules(&new_config.custom_rules).await?;
        
        // Update rate limiter
        self.rate_limiter.update_config(&new_config.rate_limiting).await?;
        
        // Update OWASP protector
        self.owasp_protector.update_config(&new_config.owasp_protection).await;
        
        info!("WAF configuration updated successfully");
        Ok(())
    }
    
    /// Get WAF statistics
    pub async fn get_statistics(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.config.enabled,
            "mode": self.config.mode,
            "rate_limiter_stats": self.rate_limiter.get_statistics().await,
            "owasp_stats": self.owasp_protector.get_statistics().await,
            "bot_detector_stats": self.bot_detector.get_statistics().await,
            "geo_blocker_stats": self.geo_blocker.as_ref().map(|g| g.get_statistics()).unwrap_or_default(),
            "rule_engine_stats": self.rule_engine.get_statistics().await,
        })
    }
}
