#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use serde_json::{json, Value};
// Removed unused OpenOptions import
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use chrono::{DateTime, Utc};

use crate::config::LoggingConfig;
use crate::error::{WafProxyError, Result as WafResult};

/// Structured log entry
#[derive(Debug, Clone, serde::Serialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: String,
    pub message: String,
    pub fields: Value,
}

/// Access log entry
#[derive(Debug, Clone, serde::Serialize)]
pub struct AccessLogEntry {
    pub timestamp: DateTime<Utc>,
    pub client_ip: String,
    pub method: String,
    pub uri: String,
    pub status: u16,
    pub duration_ms: u64,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub bytes_sent: Option<u64>,
    pub waf_action: Option<String>,
}

/// Security log entry
#[derive(Debug, Clone, serde::Serialize)]
pub struct SecurityLogEntry {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub severity: String,
    pub client_ip: String,
    pub description: String,
    pub details: Value,
    pub action_taken: Option<String>,
}

/// Logger that handles structured logging for WAF and proxy events
pub struct Logger {
    config: Arc<RwLock<LoggingConfig>>,
    access_log_writer: Option<Arc<RwLock<tokio::fs::File>>>,
    security_log_writer: Option<Arc<RwLock<tokio::fs::File>>>,
    statistics: Arc<RwLock<LoggerStatistics>>,
}

#[derive(Debug, Default)]
struct LoggerStatistics {
    total_log_entries: u64,
    access_log_entries: u64,
    security_log_entries: u64,
    error_log_entries: u64,
    log_write_errors: u64,
}

impl Logger {
    pub fn new(config: &LoggingConfig) -> Result<Self> {
        let access_log_writer = if config.access_log.enabled {
            match Self::create_log_writer(&config.access_log.output) {
                Ok(writer) => Some(Arc::new(RwLock::new(writer))),
                Err(e) => {
                    error!("Failed to create access log writer: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        let security_log_writer = if config.security_log.enabled {
            match Self::create_log_writer(&config.security_log.output) {
                Ok(writer) => Some(Arc::new(RwLock::new(writer))),
                Err(e) => {
                    error!("Failed to create security log writer: {}", e);
                    None
                }
            }
        } else {
            None
        };
        
        Ok(Self {
            config: Arc::new(RwLock::new(config.clone())),
            access_log_writer,
            security_log_writer,
            statistics: Arc::new(RwLock::new(LoggerStatistics::default())),
        })
    }
    
    fn create_log_writer(output_path: &str) -> Result<tokio::fs::File> {
        // For this example, we'll create a simple file writer
        // In production, you might want to use a more sophisticated logging library
        std::fs::create_dir_all(
            std::path::Path::new(output_path).parent().unwrap_or(std::path::Path::new("."))
        )?;
        
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(output_path)?;
        
        Ok(tokio::fs::File::from_std(file))
    }
    
    /// Log a general message
    pub async fn log(&self, level: &str, message: &str, fields: Value) -> WafResult<()> {
        let config = self.config.read().await;
        
        let entry = LogEntry {
            timestamp: Utc::now(),
            level: level.to_string(),
            message: message.to_string(),
            fields,
        };
        
        let mut stats = self.statistics.write().await;
        stats.total_log_entries += 1;
        if level == "error" {
            stats.error_log_entries += 1;
        }
        drop(stats);
        
        match config.output.as_str() {
            "stdout" => {
                if config.format == "json" {
                    println!("{}", serde_json::to_string(&entry).unwrap_or_default());
                } else {
                    println!("[{}] {}: {} - {:?}", 
                            entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                            entry.level.to_uppercase(),
                            entry.message,
                            entry.fields);
                }
            }
            "file" => {
                if let Some(file_path) = &config.file_path {
                    self.write_to_file(file_path, &entry).await?;
                }
            }
            "syslog" => {
                // Syslog implementation would go here
                info!("Syslog output not implemented");
            }
            _ => {
                warn!("Unknown log output: {}", config.output);
            }
        }
        
        Ok(())
    }
    
    /// Log a request (access log)
    pub async fn log_request(
        &self,
        method: &str,
        uri: &str,
        status: u16,
        duration: Duration,
        client_ip: &std::net::IpAddr,
        user_agent: Option<&str>,
        waf_action: Option<&str>,
    ) -> WafResult<()> {
        let config = self.config.read().await;
        
        if !config.access_log.enabled {
            return Ok(());
        }
        
        let entry = AccessLogEntry {
            timestamp: Utc::now(),
            client_ip: client_ip.to_string(),
            method: method.to_string(),
            uri: uri.to_string(),
            status,
            duration_ms: duration.as_millis() as u64,
            user_agent: user_agent.map(|s| s.to_string()),
            referer: None, // Could be extracted from headers
            bytes_sent: None, // Could be tracked from response
            waf_action: waf_action.map(|s| s.to_string()),
        };
        
        let mut stats = self.statistics.write().await;
        stats.access_log_entries += 1;
        drop(stats);
        
        if let Some(writer) = &self.access_log_writer {
            self.write_access_log(writer, &entry).await?;
        }
        
        Ok(())
    }
    
    /// Log a security event
    pub async fn log_security_event(
        &self,
        event_type: &str,
        severity: &str,
        client_ip: &std::net::IpAddr,
        details: &Value,
    ) -> WafResult<()> {
        let config = self.config.read().await;
        
        if !config.security_log.enabled {
            return Ok(());
        }
        
        let description = format!("Security event: {} from {}", event_type, client_ip);
        
        let entry = SecurityLogEntry {
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            client_ip: client_ip.to_string(),
            description,
            details: details.clone(),
            action_taken: None, // Could be provided as parameter
        };
        
        let mut stats = self.statistics.write().await;
        stats.security_log_entries += 1;
        drop(stats);
        
        // Also log to main log with appropriate level
        let log_level = match severity {
            "critical" | "high" => "error",
            "medium" => "warn",
            "low" | "info" => "info",
            _ => "info",
        };
        
        self.log(log_level, &entry.description, json!({
            "event_type": event_type,
            "severity": severity,
            "client_ip": client_ip.to_string(),
            "details": details,
        })).await?;
        
        if let Some(writer) = &self.security_log_writer {
            self.write_security_log(writer, &entry).await?;
        }
        
        Ok(())
    }
    
    async fn write_to_file(&self, file_path: &str, entry: &LogEntry) -> WafResult<()> {
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_path)
            .await
            .map_err(|e| WafProxyError::Io(e))?;
        
        let line = format!("{}\n", serde_json::to_string(entry).unwrap_or_default());
        file.write_all(line.as_bytes()).await
            .map_err(|e| WafProxyError::Io(e))?;
        file.flush().await
            .map_err(|e| WafProxyError::Io(e))?;
        
        Ok(())
    }
    
    async fn write_access_log(
        &self,
        writer: &Arc<RwLock<tokio::fs::File>>,
        entry: &AccessLogEntry,
    ) -> WafResult<()> {
        let mut file = writer.write().await;
        
        let config = self.config.read().await;
        let line = match config.access_log.format.as_str() {
            "combined" => {
                format!(
                    "{} - - [{}] \"{} {} HTTP/1.1\" {} {} \"{}\" \"{}\"\n",
                    entry.client_ip,
                    entry.timestamp.format("%d/%b/%Y:%H:%M:%S %z"),
                    entry.method,
                    entry.uri,
                    entry.status,
                    entry.bytes_sent.unwrap_or(0),
                    entry.referer.as_deref().unwrap_or("-"),
                    entry.user_agent.as_deref().unwrap_or("-")
                )
            }
            "common" => {
                format!(
                    "{} - - [{}] \"{} {} HTTP/1.1\" {} {}\n",
                    entry.client_ip,
                    entry.timestamp.format("%d/%b/%Y:%H:%M:%S %z"),
                    entry.method,
                    entry.uri,
                    entry.status,
                    entry.bytes_sent.unwrap_or(0)
                )
            }
            "json" | _ => {
                format!("{}\n", serde_json::to_string(entry).unwrap_or_default())
            }
        };
        
        file.write_all(line.as_bytes()).await
            .map_err(|e| {
                let mut stats = futures::executor::block_on(self.statistics.write());
                stats.log_write_errors += 1;
                WafProxyError::Io(e)
            })?;
        file.flush().await.map_err(|e| WafProxyError::Io(e))?;
        
        Ok(())
    }
    
    async fn write_security_log(
        &self,
        writer: &Arc<RwLock<tokio::fs::File>>,
        entry: &SecurityLogEntry,
    ) -> WafResult<()> {
        let mut file = writer.write().await;
        
        let line = format!("{}\n", serde_json::to_string(entry).unwrap_or_default());
        file.write_all(line.as_bytes()).await
            .map_err(|e| {
                let mut stats = futures::executor::block_on(self.statistics.write());
                stats.log_write_errors += 1;
                WafProxyError::Io(e)
            })?;
        file.flush().await.map_err(|e| WafProxyError::Io(e))?;
        
        Ok(())
    }
    
    /// Log WAF-specific events
    pub async fn log_waf_event(
        &self,
        action: &str,
        rule_name: Option<&str>,
        client_ip: &std::net::IpAddr,
        details: Value,
    ) -> WafResult<()> {
        let severity = match action {
            "block" => "medium",
            "challenge" => "low",
            "log" => "info",
            _ => "info",
        };
        
        let event_details = json!({
            "action": action,
            "rule_name": rule_name,
            "waf_event": true,
            "details": details,
        });
        
        self.log_security_event("waf_action", severity, client_ip, &event_details).await
    }
    
    /// Update logging configuration
    pub async fn update_config(&self, new_config: &LoggingConfig) -> Result<()> {
        let mut config = self.config.write().await;
        *config = new_config.clone();
        
        info!("Logging configuration updated");
        Ok(())
    }
    
    /// Get logger statistics
    pub async fn get_statistics(&self) -> Value {
        let stats = self.statistics.read().await;
        let config = self.config.read().await;
        
        json!({
            "enabled": true,
            "output": config.output,
            "format": config.format,
            "statistics": {
                "total_log_entries": stats.total_log_entries,
                "access_log_entries": stats.access_log_entries,
                "security_log_entries": stats.security_log_entries,
                "error_log_entries": stats.error_log_entries,
                "log_write_errors": stats.log_write_errors,
            },
            "access_log": {
                "enabled": config.access_log.enabled,
                "format": config.access_log.format,
                "output": config.access_log.output,
            },
            "security_log": {
                "enabled": config.security_log.enabled,
                "output": config.security_log.output,
                "include_request_body": config.security_log.include_request_body,
                "include_response_body": config.security_log.include_response_body,
            }
        })
    }
    
    /// Rotate log files
    pub async fn rotate_logs(&self) -> WafResult<()> {
        let config = self.config.read().await;
        
        // Simple log rotation - in production you'd want something more sophisticated
        if let Some(file_path) = &config.file_path {
            let rotated_path = format!("{}.{}", file_path, Utc::now().format("%Y%m%d_%H%M%S"));
            tokio::fs::rename(file_path, rotated_path).await
                .map_err(|e| WafProxyError::Io(e))?;
        }
        
        info!("Log files rotated");
        Ok(())
    }
}
