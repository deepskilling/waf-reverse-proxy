pub mod metrics;
pub mod logger;

use std::sync::Arc;
use anyhow::Result;

use crate::config::{MetricsConfig, LoggingConfig};

pub use metrics::MetricsCollector;
pub use logger::Logger;

/// Observability facade that combines metrics and logging
pub struct Observability {
    pub metrics: Arc<MetricsCollector>,
    pub logger: Arc<Logger>,
}

impl Observability {
    pub async fn new(metrics_config: &MetricsConfig, logging_config: &LoggingConfig) -> Result<Self> {
        let metrics = Arc::new(MetricsCollector::new(metrics_config)?);
        let logger = Arc::new(Logger::new(logging_config)?);
        
        Ok(Self {
            metrics,
            logger,
        })
    }
    
    /// Record a request with full observability
    pub async fn record_request(
        &self,
        method: &str,
        uri: &str,
        status: u16,
        duration: std::time::Duration,
        client_ip: &std::net::IpAddr,
        user_agent: Option<&str>,
        waf_action: Option<&str>,
    ) -> Result<()> {
        // Record metrics
        self.metrics.record_request(method, status, duration.as_secs_f64()).await;
        
        // Log the request
        let _ = self.logger.log_request(
            method,
            uri,
            status,
            duration,
            client_ip,
            user_agent,
            waf_action,
        ).await;
        
        Ok(())
    }
    
    /// Record a security event
    pub async fn record_security_event(
        &self,
        event_type: &str,
        severity: &str,
        client_ip: &std::net::IpAddr,
        details: &serde_json::Value,
    ) -> Result<()> {
        // Increment security metrics
        self.metrics.increment_counter("security_events_total", &[
            ("type", event_type),
            ("severity", severity),
        ]);
        
        // Log security event
        let _ = self.logger.log_security_event(event_type, severity, client_ip, details).await;
        
        Ok(())
    }
}
