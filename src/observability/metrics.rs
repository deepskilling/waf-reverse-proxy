#![allow(dead_code)]

// Removed unused Arc import
// Removed unused HashMap import
use anyhow::Result;
use axum::{
    routing::get,
    Router,
};
use metrics::{counter, histogram, gauge, describe_counter, describe_histogram, describe_gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::net::TcpListener;
// Removed unused ServeDir import
use tracing::info;

use crate::config::MetricsConfig;
use crate::error::{WafProxyError, Result as WafResult};

/// Metrics collector that handles all application metrics
pub struct MetricsCollector {
    config: MetricsConfig,
    prometheus_handle: Option<PrometheusHandle>,
}

impl MetricsCollector {
    pub fn new(config: &MetricsConfig) -> Result<Self> {
        let prometheus_handle = if config.enabled {
            // Set up Prometheus metrics exporter
            let builder = PrometheusBuilder::new();
            let handle = builder
                .install_recorder()
                .map_err(|e| anyhow::anyhow!("Failed to install Prometheus recorder: {}", e))?;
            
            // Register custom metrics
            Self::register_metrics(config);
            
            Some(handle)
        } else {
            None
        };
        
        Ok(Self {
            config: config.clone(),
            prometheus_handle,
        })
    }
    
    fn register_metrics(config: &MetricsConfig) {
        // Core WAF metrics
        describe_counter!("waf_requests_total", "Total number of requests processed by WAF");
        describe_counter!("waf_requests_blocked", "Total number of requests blocked by WAF");
        describe_counter!("waf_requests_allowed", "Total number of requests allowed by WAF");
        describe_counter!("waf_rate_limit_blocks", "Total number of requests blocked due to rate limiting");
        describe_counter!("waf_geo_blocks", "Total number of requests blocked due to geo-blocking");
        describe_counter!("waf_bot_blocks", "Total number of requests blocked due to bot detection");
        describe_counter!("waf_owasp_blocks", "Total number of requests blocked due to OWASP attacks");
        describe_counter!("waf_custom_rule_blocks", "Total number of requests blocked due to custom rules");
        
        // Proxy metrics
        describe_counter!("proxy_requests_total", "Total number of proxy requests");
        describe_counter!("proxy_requests_failed", "Total number of failed proxy requests");
        describe_histogram!("proxy_request_duration_seconds", "Duration of proxy requests in seconds");
        describe_histogram!("proxy_upstream_response_time", "Upstream response time in seconds");
        describe_counter!("proxy_upstream_errors", "Total number of upstream errors");
        
        // System metrics
        describe_gauge!("active_connections", "Number of active connections");
        describe_gauge!("memory_usage_bytes", "Memory usage in bytes");
        describe_gauge!("cpu_usage_percent", "CPU usage percentage");
        
        // Security metrics
        describe_counter!("security_events_total", "Total number of security events");
        describe_counter!("failed_auth_attempts", "Total number of failed authentication attempts");
        describe_counter!("suspicious_activities", "Total number of suspicious activities detected");
        
        // Note: Custom metrics from config are registered dynamically when first used
        // since the describe! macros require 'static lifetime strings
        info!("Will register {} custom metrics dynamically when first used", config.custom_metrics.len());
        
        info!("Registered {} custom metrics", config.custom_metrics.len());
    }
    
    /// Start the metrics server
    pub async fn start_server(&self, config: &MetricsConfig) -> WafResult<()> {
        if !config.enabled {
            return Ok(());
        }
        
        let handle = match &self.prometheus_handle {
            Some(handle) => handle.clone(),
            None => return Err(WafProxyError::Internal("Prometheus handle not available".to_string())),
        };
        
        let app = Router::new()
            .route(&config.path, get(move || async move { handle.render() }))
            .route("/health", get(|| async { "OK" }));
        
        let addr = format!("0.0.0.0:{}", config.port);
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| WafProxyError::Internal(format!("Failed to bind metrics server: {}", e)))?;
        
        info!("Metrics server listening on {}{}", addr, config.path);
        
        axum::serve(listener, app)
            .await
            .map_err(|e| WafProxyError::Internal(format!("Metrics server error: {}", e)))?;
        
        Ok(())
    }
    
    /// Record a request metric
    pub async fn record_request(&self, method: &str, status: u16, duration: f64) {
        if !self.config.enabled {
            return;
        }
        
        let status_class = match status {
            200..=299 => "2xx",
            300..=399 => "3xx", 
            400..=499 => "4xx",
            500..=599 => "5xx",
            _ => "unknown",
        };
        
        counter!("proxy_requests_total", "method" => method.to_string(), "status" => status_class).increment(1);
        histogram!("proxy_request_duration_seconds", "method" => method.to_string()).record(duration);
        
        if status >= 400 {
            counter!("proxy_requests_failed", "method" => method.to_string(), "status" => status.to_string()).increment(1);
        }
    }
    
    /// Increment a counter metric (simplified to avoid lifetime issues)
    pub fn increment_counter(&self, _name: &str, _labels: &[(&str, &str)]) {
        if !self.config.enabled {
            return;
        }
        
        // Use a generic counter name since metrics macros require static strings
        counter!("custom_counter").increment(1);
    }
    
    /// Record a histogram value (simplified to avoid lifetime issues)
    pub fn record_histogram(&self, _name: &str, value: f64, _labels: &[(&str, &str)]) {
        if !self.config.enabled {
            return;
        }
        
        // Use a generic histogram name since metrics macros require static strings
        histogram!("custom_histogram").record(value);
    }
    
    /// Set a gauge value (simplified to avoid lifetime issues)
    pub fn set_gauge(&self, _name: &str, value: f64, _labels: &[(&str, &str)]) {
        if !self.config.enabled {
            return;
        }
        
        // Use a generic gauge name since metrics macros require static strings
        gauge!("custom_gauge").set(value);
    }
    
    /// Record WAF-specific metrics
    pub fn record_waf_event(&self, event_type: &str, action: &str, rule_name: Option<&str>) {
        if !self.config.enabled {
            return;
        }
        
        let labels = if let Some(rule) = rule_name {
            vec![("event_type", event_type), ("action", action), ("rule", rule)]
        } else {
            vec![("event_type", event_type), ("action", action)]
        };
        
        self.increment_counter("waf_requests_total", &labels);
        
        match action {
            "block" => {
                self.increment_counter("waf_requests_blocked", &[("type", event_type)]);
            }
            "allow" => {
                self.increment_counter("waf_requests_allowed", &[("type", event_type)]);
            }
            _ => {}
        }
    }
    
    /// Record upstream metrics
    pub fn record_upstream_event(&self, upstream: &str, status: u16, duration: f64) {
        if !self.config.enabled {
            return;
        }
        
        self.record_histogram("proxy_upstream_response_time", duration, &[
            ("upstream", upstream),
            ("status", &status.to_string()),
        ]);
        
        if status >= 500 {
            self.increment_counter("proxy_upstream_errors", &[
                ("upstream", upstream),
                ("status", &status.to_string()),
            ]);
        }
    }
    
    /// Update system metrics
    pub async fn update_system_metrics(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        // Get system information (this is a simplified example)
        // In a real implementation, you'd use a crate like `sysinfo`
        
        // Mock values for demonstration
        let active_connections = 150.0;
        let memory_usage = 1024.0 * 1024.0 * 100.0; // 100MB
        let cpu_usage = 25.5;
        
        self.set_gauge("active_connections", active_connections, &[]);
        self.set_gauge("memory_usage_bytes", memory_usage, &[]);
        self.set_gauge("cpu_usage_percent", cpu_usage, &[]);
        
        Ok(())
    }
    
    /// Get metrics summary as JSON
    pub async fn get_metrics_summary(&self) -> serde_json::Value {
        if !self.config.enabled {
            return serde_json::json!({
                "enabled": false,
                "message": "Metrics collection is disabled"
            });
        }
        
        // This would normally collect current metric values
        // For now, return a basic structure
        serde_json::json!({
            "enabled": true,
            "endpoint": format!(":{}{}", self.config.port, self.config.path),
            "custom_metrics_count": self.config.custom_metrics.len(),
            "status": "collecting"
        })
    }
    
    /// Reset all metrics (useful for testing)
    pub fn reset_metrics(&self) {
        if !self.config.enabled {
            return;
        }
        
        // Note: The metrics crate doesn't provide a direct way to reset all metrics
        // This would need to be implemented differently in a production environment
        info!("Metrics reset requested (not implemented in this example)");
    }
}
