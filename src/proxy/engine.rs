#![allow(dead_code)]

use std::sync::Arc;
use std::net::SocketAddr;
use anyhow::Result;
use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{StatusCode, HeaderMap, HeaderName, HeaderValue},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use bytes::Bytes;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    compression::CompressionLayer,
    trace::TraceLayer,
    timeout::TimeoutLayer,
};
use tokio::net::TcpListener;
use tracing::{info, warn, error, debug, instrument};
use uuid::Uuid;
// Removed unused Incoming import
use http_body_util::BodyExt;

use crate::config::{ProxyConfig, ServerConfig};
use crate::waf::WafEngine;
use crate::observability::{MetricsCollector, Logger};
use crate::health::HealthChecker;
use crate::error::{WafProxyError, Result as WafResult};
use super::{
    ProxyContext, ProxyResponse,
    upstream::UpstreamManager,
    cache::ProxyCache,
};

/// Main reverse proxy engine
#[allow(dead_code)]
pub struct ReverseProxy {
    config: Arc<ProxyConfig>,
    waf_engine: Arc<WafEngine>,
    upstream_manager: Arc<UpstreamManager>,
    cache: Arc<ProxyCache>,
    metrics: Arc<MetricsCollector>,
    logger: Arc<Logger>,
    health_checker: Arc<HealthChecker>,
    http_client: reqwest::Client,
}

#[derive(Clone)]
struct AppState {
    proxy: Arc<ReverseProxy>,
}

impl ReverseProxy {
    pub async fn new(
        config: &ProxyConfig,
        waf_engine: Arc<WafEngine>,
        metrics: Arc<MetricsCollector>,
        logger: Arc<Logger>,
        health_checker: Arc<HealthChecker>,
    ) -> Result<Self> {
        let upstream_manager = Arc::new(UpstreamManager::new(config, health_checker.clone()));
        let cache = Arc::new(ProxyCache::new(&config.caching).await?);
        
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .pool_max_idle_per_host(20)
            .user_agent("WAF-ReverseProxy/1.0")
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;
        
        Ok(Self {
            config: Arc::new(config.clone()),
            waf_engine,
            upstream_manager,
            cache,
            metrics,
            logger,
            health_checker,
            http_client,
        })
    }
    
    /// Start the reverse proxy server
    pub async fn start(&self, server_config: &ServerConfig) -> WafResult<()> {
        let app_state = AppState {
            proxy: Arc::new(self.clone()),
        };
        
        // Build the router with middleware
        let app = Router::<AppState>::new()
            .route("/*path", any(simple_handler))
            .fallback(simple_handler)
            .layer(
                ServiceBuilder::new()
                    .layer(TraceLayer::new_for_http())
                    .layer(CorsLayer::permissive())
                    .layer(CompressionLayer::new())
                    .layer(TimeoutLayer::new(std::time::Duration::from_secs(60)))
                    .into_inner(),
            )
            .with_state(app_state);
        
        let addr = format!("{}:{}", server_config.host, server_config.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| WafProxyError::Internal(format!("Failed to bind to {}: {}", addr, e)))?;
        
        info!("Reverse proxy listening on {}", addr);
        
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .map_err(|e| WafProxyError::Internal(format!("Server error: {}", e)))?;
        
        Ok(())
    }
    
    /// Process a single proxy request
    #[instrument(skip(self, req, connect_info), fields(request_id, client_ip, method, uri))]
    pub async fn handle_proxy_request(
        &self,
        req: Request,
        connect_info: ConnectInfo<SocketAddr>,
    ) -> WafResult<Response> {
        let request_id = Uuid::new_v4().to_string();
        let start_time = std::time::Instant::now();
        let client_ip = connect_info.0.ip();
        let method = req.method().to_string();
        let uri = req.uri().to_string();
        
        tracing::Span::current()
            .record("request_id", &request_id)
            .record("client_ip", &client_ip.to_string())
            .record("method", &method)
            .record("uri", &uri);
        
        debug!("Processing request {} from {}: {} {}", request_id, client_ip, method, uri);
        
        // Extract request body for WAF inspection
        let (parts, body) = req.into_parts();
        let body_bytes = match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!("Failed to read request body: {}", e);
                return Ok(StatusCode::BAD_REQUEST.into_response());
            }
        };
        
        // Reconstruct request for WAF inspection
        let req_for_waf = Request::from_parts(parts.clone(), Body::from(body_bytes.clone()));
        
        // WAF inspection
        let waf_result = self.waf_engine.inspect_request(
            &req_for_waf,
            &connect_info,
            if body_bytes.is_empty() { None } else { Some(&body_bytes) },
        ).await?;
        
        // Handle WAF result
        if let Err(waf_error) = self.waf_engine.handle_result(&waf_result) {
            warn!("WAF blocked request {}: {}", request_id, waf_error);
            
            // Log security event
            self.logger.log_waf_event(
                &format!("{:?}", waf_result.action),
                waf_result.rule_name.as_deref(),
                &client_ip,
                waf_result.metadata.clone(),
            ).await?;
            
            // Record metrics
            self.metrics.record_waf_event(
                "blocked",
                &format!("{:?}", waf_result.action),
                waf_result.rule_name.as_deref(),
            );
            
            return Ok(waf_error.into_response());
        }
        
        // Find matching route
        let route = self.find_matching_route(&parts.uri.host().unwrap_or_default(), &parts.uri.path())?;
        let upstream_name = &route.upstream;
        
        // Get upstream server
        let upstream_server = self.upstream_manager
            .get_upstream_server(upstream_name)
            .await?
            .ok_or_else(|| WafProxyError::ServiceUnavailable(
                format!("No healthy servers available for upstream: {}", upstream_name)
            ))?;
        
        let proxy_context = ProxyContext {
            request_id: request_id.clone(),
            client_ip,
            method: method.clone(),
            uri: uri.clone(),
            headers: parts.headers.clone(),
            upstream_name: upstream_name.clone(),
            target_server: upstream_server.clone(),
            start_time,
        };
        
        // Check cache first
        let cache_key = self.generate_cache_key(&proxy_context, &body_bytes);
        if let Some(cached_response) = self.cache.get(&cache_key).await {
            debug!("Serving cached response for request {}", request_id);
            
            self.metrics.increment_counter("proxy_cache_hits", &[
                ("upstream", upstream_name),
            ]);
            
            return Ok(self.build_response_from_cache(cached_response).await);
        }
        
        // Capture user-agent before moving parts
        let user_agent = parts.headers.get("user-agent").and_then(|h| h.to_str().ok()).map(String::from);
        
        // Forward request to upstream
        let proxy_response = self.forward_request(
            &proxy_context,
            parts,
            body_bytes,
        ).await?;
        
        // Cache response if appropriate
        if self.should_cache_response(&proxy_context, &proxy_response) {
            self.cache.set(cache_key, &proxy_response).await;
            self.metrics.increment_counter("proxy_cache_sets", &[
                ("upstream", upstream_name),
            ]);
        }
        
        // Record metrics and logs
        let total_time = start_time.elapsed();
        self.metrics.record_request(&method, proxy_response.status, total_time.as_secs_f64()).await;
        self.metrics.record_upstream_event(upstream_name, proxy_response.status, proxy_response.upstream_response_time.as_secs_f64());
        
        self.logger.log_request(
            &method,
            &uri,
            proxy_response.status,
            total_time,
            &client_ip,
            user_agent.as_deref(),
            Some(&format!("{:?}", waf_result.action)),
        ).await?;
        
        debug!("Completed request {} in {}ms", request_id, total_time.as_millis());
        
        // Build final response
        Ok(self.build_response(proxy_response).await)
    }
    
    fn find_matching_route(&self, host: &str, path: &str) -> WafResult<&crate::config::RouteConfig> {
        for route in &self.config.routes {
            if (route.host.is_empty() || route.host == "*" || route.host == host) &&
               (route.path.is_empty() || route.path == "/" || path.starts_with(&route.path)) {
                return Ok(route);
            }
        }
        
        Err(WafProxyError::BadRequest("No matching route found".to_string()))
    }
    
    async fn forward_request(
        &self,
        context: &ProxyContext,
        parts: axum::http::request::Parts,
        body: Bytes,
    ) -> WafResult<ProxyResponse> {
        let upstream_start = std::time::Instant::now();
        
        // Build target URL
        let target_url = if context.target_server.ends_with('/') {
            format!("{}{}", context.target_server.trim_end_matches('/'), parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"))
        } else {
            format!("{}{}", context.target_server, parts.uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/"))
        };
        
        debug!("Forwarding request {} to {}", context.request_id, target_url);
        
        // Build request - convert Method between different http crate versions
        let method_str = parts.method.as_str();
        let reqwest_method = reqwest::Method::from_bytes(method_str.as_bytes())
            .map_err(|e| WafProxyError::BadRequest(format!("Invalid method: {}", e)))?;
        let mut request_builder = self.http_client
            .request(reqwest_method, &target_url);
        
        // Copy headers (skip hop-by-hop headers) - convert between different http crate versions
        for (name, value) in parts.headers.iter() {
            if !is_hop_by_hop_header(name) {
                let name_str = name.as_str();
                let value_bytes = value.as_bytes();
                request_builder = request_builder.header(name_str, value_bytes);
            }
        }
        
        // Add proxy headers
        request_builder = request_builder
            .header("X-Forwarded-For", context.client_ip.to_string())
            .header("X-Forwarded-Proto", if parts.uri.scheme_str() == Some("https") { "https" } else { "http" })
            .header("X-Real-IP", context.client_ip.to_string())
            .header("X-Request-ID", &context.request_id);
        
        // Add body if present
        if !body.is_empty() {
            request_builder = request_builder.body(body);
        }
        
        // Send request
        let response = request_builder
            .send()
            .await
            .map_err(|e| {
                error!("Upstream request failed for {}: {}", context.request_id, e);
                WafProxyError::Upstream(format!("Request failed: {}", e))
            })?;
        
        let upstream_response_time = upstream_start.elapsed();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        
        // Read response body
        let response_body = response.bytes().await
            .map_err(|e| WafProxyError::Upstream(format!("Failed to read response body: {}", e)))?;
        
        // Convert headers between different http crate versions
        let mut converted_headers = HeaderMap::new();
        for (name, value) in headers.iter() {
            if let Ok(header_name) = HeaderName::from_bytes(name.as_str().as_bytes()) {
                if let Ok(header_value) = HeaderValue::from_bytes(value.as_bytes()) {
                    converted_headers.insert(header_name, header_value);
                }
            }
        }
        
        Ok(ProxyResponse {
            status,
            headers: converted_headers,
            body: response_body,
            upstream_response_time,
            total_time: context.start_time.elapsed(),
            from_cache: false,
        })
    }
    
    fn generate_cache_key(&self, context: &ProxyContext, body: &Bytes) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        context.method.hash(&mut hasher);
        context.uri.hash(&mut hasher);
        
        // Hash relevant headers for cache variance
        for (name, value) in context.headers.iter() {
            if name == "accept-encoding" || name == "accept" {
                name.hash(&mut hasher);
                value.hash(&mut hasher);
            }
        }
        
        if !body.is_empty() {
            body.hash(&mut hasher);
        }
        
        format!("cache:{}:{:x}", context.upstream_name, hasher.finish())
    }
    
    fn should_cache_response(&self, context: &ProxyContext, response: &ProxyResponse) -> bool {
        if !self.config.caching.enabled {
            return false;
        }
        
        // Don't cache error responses
        if response.status >= 400 {
            return false;
        }
        
        // Don't cache non-GET requests by default
        if context.method != "GET" {
            return false;
        }
        
        // Check cache rules
        for rule in &self.config.caching.rules {
            if let Ok(regex) = regex::Regex::new(&rule.pattern) {
                if regex.is_match(&context.uri) {
                    // Check conditions if any
                    if let Some(conditions) = &rule.conditions {
                        for condition in conditions {
                            if let Some(method) = &condition.method {
                                if method != &context.method {
                                    continue;
                                }
                            }
                            if condition.no_auth_header.unwrap_or(false) {
                                if context.headers.contains_key("authorization") {
                                    continue;
                                }
                            }
                        }
                    }
                    return true;
                }
            }
        }
        
        false
    }
    
    async fn build_response_from_cache(&self, cached_response: ProxyResponse) -> Response {
        self.build_response(cached_response).await
    }
    
    async fn build_response(&self, proxy_response: ProxyResponse) -> Response {
        let mut response_builder = Response::builder().status(proxy_response.status);
        
        // Copy response headers (skip hop-by-hop headers)
        for (name, value) in proxy_response.headers.iter() {
            if !is_hop_by_hop_header(name) {
                response_builder = response_builder.header(name, value);
            }
        }
        
        // Add proxy headers
        response_builder = response_builder
            .header("X-Proxy", "WAF-ReverseProxy/1.0")
            .header("X-Cache", if proxy_response.from_cache { "HIT" } else { "MISS" });
        
        response_builder
            .body(axum::body::Body::from(proxy_response.body))
            .unwrap_or_else(|e| {
                error!("Failed to build response: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })
    }
}

impl Clone for ReverseProxy {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            waf_engine: self.waf_engine.clone(),
            upstream_manager: self.upstream_manager.clone(),
            cache: self.cache.clone(),
            metrics: self.metrics.clone(),
            logger: self.logger.clone(),
            health_checker: self.health_checker.clone(),
            http_client: self.http_client.clone(),
        }
    }
}

// Simple test handler
async fn simple_handler(
    State(_state): State<AppState>,
    _req: Request,
) -> impl IntoResponse {
    axum::http::StatusCode::OK
}

// HTTP handler function (currently not used due to trait issues)
async fn handle_request(
    State(state): State<AppState>,
    connect_info: ConnectInfo<SocketAddr>,
    req: Request,
) -> impl IntoResponse {
    match state.proxy.handle_proxy_request(req, connect_info).await {
        Ok(response) => response,
        Err(e) => {
            error!("Proxy request failed: {}", e);
            e.into_response()
        }
    }
}

// Helper function to identify hop-by-hop headers
fn is_hop_by_hop_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_lowercase().as_str(),
        "connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" |
        "te" | "trailers" | "transfer-encoding" | "upgrade"
    )
}
