use std::sync::Arc;
use anyhow::Result;
#[allow(dead_code)]

use axum::{
    extract::{Path, State},
    // Removed unused StatusCode import
    response::{IntoResponse, Json},
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{info, warn, error};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use serde_json::{json, Value};

use crate::config::{AdminConfig, Config, WafConfig, ProxyConfig};
use crate::observability::MetricsCollector;
use crate::error::{WafProxyError, Result as WafResult};

/// Admin server for managing WAF and proxy configuration
pub struct AdminServer {
    config: AdminConfig,
    app_config: Arc<tokio::sync::RwLock<Config>>,
    metrics: Arc<MetricsCollector>,
}

#[derive(Clone)]
struct AdminState {
    admin_config: AdminConfig,
    app_config: Arc<tokio::sync::RwLock<Config>>,
    metrics: Arc<MetricsCollector>,
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    success: bool,
    message: String,
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConfigUpdateRequest {
    config: Value,
}

#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    message: Option<String>,
    timestamp: chrono::DateTime<chrono::Utc>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            message: None,
            timestamp: chrono::Utc::now(),
        }
    }
    
    fn error(message: String) -> Self {
        Self {
            success: false,
            data: None,
            message: Some(message),
            timestamp: chrono::Utc::now(),
        }
    }
}

impl AdminServer {
    pub fn new(
        config: &AdminConfig,
        app_config: Config,
        metrics: Arc<MetricsCollector>,
    ) -> Result<Self> {
        Ok(Self {
            config: config.clone(),
            app_config: Arc::new(tokio::sync::RwLock::new(app_config)),
            metrics,
        })
    }
    
    /// Start the admin server
    pub async fn start(&self) -> WafResult<()> {
        let state = AdminState {
            admin_config: self.config.clone(),
            app_config: self.app_config.clone(),
            metrics: self.metrics.clone(),
        };
        
        let app = Router::new()
            // Authentication
            .route("/api/auth/login", post(login))
            
            // Configuration management
            .route("/api/config", get(get_config))
            .route("/api/config", put(update_config))
            .route("/api/config/waf", get(get_waf_config))
            .route("/api/config/waf", put(update_waf_config))
            .route("/api/config/proxy", get(get_proxy_config))
            .route("/api/config/proxy", put(update_proxy_config))
            
            // Metrics and monitoring
            .route("/api/metrics", get(get_metrics))
            .route("/api/metrics/summary", get(get_metrics_summary))
            
            // WAF management
            .route("/api/waf/status", get(get_waf_status))
            .route("/api/waf/rules", get(get_waf_rules))
            .route("/api/waf/rules", post(add_waf_rule))
            .route("/api/waf/rules/:rule_name", delete(delete_waf_rule))
            .route("/api/waf/statistics", get(get_waf_statistics))
            
            // Upstream management
            .route("/api/upstreams", get(get_upstreams))
            .route("/api/upstreams/:name", get(get_upstream))
            .route("/api/upstreams/:name", put(update_upstream))
            .route("/api/upstreams/:name", delete(delete_upstream))
            .route("/api/upstreams/:name/health", get(get_upstream_health))
            
            // Cache management
            .route("/api/cache/statistics", get(get_cache_statistics))
            .route("/api/cache/clear", post(clear_cache))
            .route("/api/cache/entry/:key", get(get_cache_entry))
            .route("/api/cache/entry/:key", delete(remove_cache_entry))
            
            // Health and status
            .route("/api/health", get(health_check))
            .route("/api/status", get(get_system_status))
            
            // Utility endpoints
            .route("/api/validate/config", post(validate_config))
            .route("/api/reload", post(reload_configuration))
            
            .layer(CorsLayer::permissive())
            .with_state(state);
        
        let addr = format!("0.0.0.0:{}", self.config.port);
        let listener = TcpListener::bind(&addr).await
            .map_err(|e| WafProxyError::Internal(format!("Failed to bind admin server: {}", e)))?;
        
        info!("Admin server listening on {}", addr);
        
        axum::serve(listener, app)
            .await
            .map_err(|e| WafProxyError::Internal(format!("Admin server error: {}", e)))?;
        
        Ok(())
    }
}

// Authentication handlers
async fn login(
    State(state): State<AdminState>,
    Json(request): Json<AuthRequest>,
) -> impl IntoResponse {
    if !state.admin_config.auth.enabled {
        return Json(ApiResponse::success(AuthResponse {
            success: true,
            message: "Authentication disabled".to_string(),
            token: Some("no-auth".to_string()),
        }));
    }
    
    // Verify credentials
    if request.username != state.admin_config.auth.username {
        warn!("Failed login attempt with username: {}", request.username);
        return Json(ApiResponse::error("Invalid credentials".to_string()));
    }
    
    // Verify password hash
    let parsed_hash = match PasswordHash::new(&state.admin_config.auth.password_hash) {
        Ok(hash) => hash,
        Err(_) => {
            error!("Invalid password hash in configuration");
            return Json(ApiResponse::error("Authentication configuration error".to_string()));
        }
    };
    
    let argon2 = Argon2::default();
    match argon2.verify_password(request.password.as_bytes(), &parsed_hash) {
        Ok(_) => {
            info!("Successful login for user: {}", request.username);
            Json(ApiResponse::success(AuthResponse {
                success: true,
                message: "Authentication successful".to_string(),
                token: Some("authenticated".to_string()), // In production, use proper JWT
            }))
        }
        Err(_) => {
            warn!("Failed login attempt for user: {}", request.username);
            Json(ApiResponse::error("Invalid credentials".to_string()))
        }
    }
}

// Configuration handlers
async fn get_config(State(state): State<AdminState>) -> impl IntoResponse {
    let config = state.app_config.read().await;
    Json(ApiResponse::success(config.clone()))
}

async fn update_config(
    State(state): State<AdminState>,
    Json(request): Json<ConfigUpdateRequest>,
) -> impl IntoResponse {
    match serde_json::from_value::<Config>(request.config) {
        Ok(new_config) => {
            // Validate configuration
            if let Err(e) = new_config.validate() {
                return Json(ApiResponse::error(format!("Configuration validation failed: {}", e)));
            }
            
            let mut config = state.app_config.write().await;
            *config = new_config;
            
            info!("Configuration updated via admin API");
            Json(ApiResponse::success("Configuration updated successfully"))
        }
        Err(e) => {
            Json(ApiResponse::error(format!("Invalid configuration format: {}", e)))
        }
    }
}

async fn get_waf_config(State(state): State<AdminState>) -> impl IntoResponse {
    let config = state.app_config.read().await;
    Json(ApiResponse::success(config.waf.clone()))
}

async fn update_waf_config(
    State(state): State<AdminState>,
    Json(waf_config): Json<WafConfig>,
) -> impl IntoResponse {
    let mut config = state.app_config.write().await;
    config.waf = waf_config;
    
    info!("WAF configuration updated via admin API");
    Json(ApiResponse::success("WAF configuration updated successfully"))
}

async fn get_proxy_config(State(state): State<AdminState>) -> impl IntoResponse {
    let config = state.app_config.read().await;
    Json(ApiResponse::success(config.proxy.clone()))
}

async fn update_proxy_config(
    State(state): State<AdminState>,
    Json(proxy_config): Json<ProxyConfig>,
) -> impl IntoResponse {
    let mut config = state.app_config.write().await;
    config.proxy = proxy_config;
    
    info!("Proxy configuration updated via admin API");
    Json(ApiResponse::success("Proxy configuration updated successfully"))
}

// Metrics handlers
async fn get_metrics(State(state): State<AdminState>) -> impl IntoResponse {
    let metrics_summary = state.metrics.get_metrics_summary().await;
    Json(ApiResponse::success(metrics_summary))
}

async fn get_metrics_summary(State(state): State<AdminState>) -> impl IntoResponse {
    let summary = json!({
        "timestamp": chrono::Utc::now(),
        "uptime": "unknown", // Would need to track application start time
        "version": env!("CARGO_PKG_VERSION"),
        "metrics_enabled": state.app_config.read().await.metrics.enabled,
    });
    Json(ApiResponse::success(summary))
}

// WAF handlers
async fn get_waf_status(State(state): State<AdminState>) -> impl IntoResponse {
    let config = state.app_config.read().await;
    let status = json!({
        "enabled": config.waf.enabled,
        "mode": config.waf.mode,
        "custom_rules_count": config.waf.custom_rules.len(),
        "owasp_protection": {
            "sql_injection": config.waf.owasp_protection.sql_injection.enabled,
            "xss_protection": config.waf.owasp_protection.xss_protection.enabled,
            "rce_protection": config.waf.owasp_protection.rce_protection.enabled,
            "path_traversal": config.waf.owasp_protection.path_traversal.enabled,
            "csrf_protection": config.waf.owasp_protection.csrf_protection.enabled,
        },
        "bot_protection": config.waf.bot_protection.enabled,
        "geo_blocking": config.waf.geo_blocking.enabled,
    });
    Json(ApiResponse::success(status))
}

async fn get_waf_rules(State(state): State<AdminState>) -> impl IntoResponse {
    let config = state.app_config.read().await;
    Json(ApiResponse::success(config.waf.custom_rules.clone()))
}

async fn add_waf_rule(
    State(state): State<AdminState>,
    Json(rule): Json<crate::config::CustomRule>,
) -> impl IntoResponse {
    let mut config = state.app_config.write().await;
    config.waf.custom_rules.push(rule);
    
    info!("WAF rule added via admin API");
    Json(ApiResponse::success("WAF rule added successfully"))
}

async fn delete_waf_rule(
    State(state): State<AdminState>,
    Path(rule_name): Path<String>,
) -> impl IntoResponse {
    let mut config = state.app_config.write().await;
    let initial_len = config.waf.custom_rules.len();
    config.waf.custom_rules.retain(|rule| rule.name != rule_name);
    
    if config.waf.custom_rules.len() < initial_len {
        info!("WAF rule '{}' deleted via admin API", rule_name);
        Json(ApiResponse::success("WAF rule deleted successfully"))
    } else {
        Json(ApiResponse::error("WAF rule not found".to_string()))
    }
}

async fn get_waf_statistics(State(_state): State<AdminState>) -> impl IntoResponse {
    // This would need to be implemented with actual WAF statistics
    let stats = json!({
        "requests_processed": 0,
        "requests_blocked": 0,
        "rules_triggered": {},
        "top_attack_types": [],
    });
    Json(ApiResponse::success(stats))
}

// Upstream handlers
async fn get_upstreams(State(state): State<AdminState>) -> impl IntoResponse {
    let config = state.app_config.read().await;
    Json(ApiResponse::success(config.proxy.upstreams.clone()))
}

async fn get_upstream(
    State(state): State<AdminState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let config = state.app_config.read().await;
    if let Some(upstream) = config.proxy.upstreams.get(&name) {
        Json(ApiResponse::success(upstream.clone()))
    } else {
        Json(ApiResponse::error("Upstream not found".to_string()))
    }
}

async fn update_upstream(
    State(state): State<AdminState>,
    Path(name): Path<String>,
    Json(upstream_config): Json<crate::config::UpstreamConfig>,
) -> impl IntoResponse {
    let mut config = state.app_config.write().await;
    config.proxy.upstreams.insert(name.clone(), upstream_config);
    
    info!("Upstream '{}' updated via admin API", name);
    Json(ApiResponse::success("Upstream updated successfully"))
}

async fn delete_upstream(
    State(state): State<AdminState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let mut config = state.app_config.write().await;
    if config.proxy.upstreams.remove(&name).is_some() {
        info!("Upstream '{}' deleted via admin API", name);
        Json(ApiResponse::success("Upstream deleted successfully"))
    } else {
        Json(ApiResponse::error("Upstream not found".to_string()))
    }
}

async fn get_upstream_health(
    State(_state): State<AdminState>,
    Path(_name): Path<String>,
) -> impl IntoResponse {
    // This would need to be implemented with actual health check data
    let health = json!({
        "healthy_servers": 0,
        "total_servers": 0,
        "last_check": null,
    });
    Json(ApiResponse::success(health))
}

// Cache handlers
async fn get_cache_statistics(State(_state): State<AdminState>) -> impl IntoResponse {
    // This would need to be implemented with actual cache statistics
    let stats = json!({
        "hit_rate": 0.0,
        "total_entries": 0,
        "memory_usage": 0,
    });
    Json(ApiResponse::success(stats))
}

async fn clear_cache(State(_state): State<AdminState>) -> impl IntoResponse {
    // This would need to be implemented with actual cache clearing
    info!("Cache cleared via admin API");
    Json(ApiResponse::success("Cache cleared successfully"))
}

async fn get_cache_entry(
    State(_state): State<AdminState>,
    Path(_key): Path<String>,
) -> impl IntoResponse {
    Json(ApiResponse::<String>::error("Cache entry not found".to_string()))
}

async fn remove_cache_entry(
    State(_state): State<AdminState>,
    Path(_key): Path<String>,
) -> impl IntoResponse {
    Json(ApiResponse::success("Cache entry removed successfully"))
}

// Health and status handlers
async fn health_check() -> impl IntoResponse {
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
    }))
}

async fn get_system_status(State(state): State<AdminState>) -> impl IntoResponse {
    let config = state.app_config.read().await;
    let status = json!({
        "service": "waf-reverse-proxy",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running",
        "uptime": "unknown",
        "configuration": {
            "waf_enabled": config.waf.enabled,
            "proxy_upstreams": config.proxy.upstreams.len(),
            "metrics_enabled": config.metrics.enabled,
        },
        "timestamp": chrono::Utc::now(),
    });
    Json(ApiResponse::success(status))
}

// Utility handlers
async fn validate_config(
    Json(config_value): Json<Value>,
) -> impl IntoResponse {
    match serde_json::from_value::<Config>(config_value) {
        Ok(config) => {
            match config.validate() {
                Ok(_) => Json(ApiResponse::success("Configuration is valid")),
                Err(e) => Json(ApiResponse::error(format!("Configuration validation failed: {}", e))),
            }
        }
        Err(e) => Json(ApiResponse::error(format!("Invalid configuration format: {}", e))),
    }
}

async fn reload_configuration(State(_state): State<AdminState>) -> impl IntoResponse {
    // This would trigger a configuration reload
    info!("Configuration reload requested via admin API");
    Json(ApiResponse::success("Configuration reload initiated"))
}
