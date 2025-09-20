use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Main configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub ssl: SslConfig,
    pub waf: WafConfig,
    pub proxy: ProxyConfig,
    pub logging: LoggingConfig,
    pub metrics: MetricsConfig,
    pub redis: RedisConfig,
    pub admin: AdminConfig,
    pub advanced: AdvancedConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub max_connections: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SslConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    pub protocols: Vec<String>,
    pub ciphers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WafConfig {
    pub enabled: bool,
    pub mode: WafMode,
    pub rate_limiting: RateLimitingConfig,
    pub owasp_protection: OwaspProtectionConfig,
    pub bot_protection: BotProtectionConfig,
    pub geo_blocking: GeoBlockingConfig,
    pub custom_rules: Vec<CustomRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WafMode {
    Block,
    Monitor,
    Log,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitingConfig {
    pub global: RateLimit,
    pub per_ip: RateLimit,
    pub per_endpoint: RateLimit,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimit {
    pub requests_per_second: Option<u32>,
    pub requests_per_minute: Option<u32>,
    pub burst: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OwaspProtectionConfig {
    pub sql_injection: ProtectionRule,
    pub xss_protection: ProtectionRule,
    pub csrf_protection: CsrfProtectionRule,
    pub rce_protection: ProtectionRule,
    pub path_traversal: ProtectionRule,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProtectionRule {
    pub enabled: bool,
    pub confidence_threshold: f32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CsrfProtectionRule {
    pub enabled: bool,
    pub confidence_threshold: f32,
    pub require_token: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BotProtectionConfig {
    pub enabled: bool,
    pub challenge_suspicious: bool,
    pub block_known_bots: bool,
    pub user_agent_analysis: bool,
    pub behavioral_analysis: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeoBlockingConfig {
    pub enabled: bool,
    pub blocked_countries: Vec<String>,
    pub allowed_countries: Vec<String>,
    pub geodb_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomRule {
    pub name: String,
    pub pattern: String,
    pub action: String,
    pub conditions: Vec<RuleCondition>,
    pub rate_limit: Option<RateLimit>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleCondition {
    #[serde(rename = "type")]
    pub condition_type: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProxyConfig {
    pub upstreams: HashMap<String, UpstreamConfig>,
    pub routes: Vec<RouteConfig>,
    pub caching: CachingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamConfig {
    pub servers: Vec<UpstreamServerConfig>,
    pub load_balancer: LoadBalancerType,
    pub health_check: HealthCheckConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamServerConfig {
    pub url: String,
    pub weight: u32,
    pub max_fails: u32,
    #[serde(with = "duration_serde")]
    pub fail_timeout: Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerType {
    RoundRobin,
    LeastConnections,
    IpHash,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub path: String,
    #[serde(with = "duration_serde")]
    pub interval: Duration,
    #[serde(with = "duration_serde")]
    pub timeout: Duration,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteConfig {
    pub host: String,
    pub path: String,
    pub upstream: String,
    pub strip_path: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CachingConfig {
    pub enabled: bool,
    #[serde(with = "duration_serde")]
    pub default_ttl: Duration,
    pub max_size: String,
    pub rules: Vec<CacheRule>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheRule {
    pub pattern: String,
    #[serde(with = "duration_serde")]
    pub ttl: Duration,
    pub vary_headers: Option<Vec<String>>,
    pub conditions: Option<Vec<CacheCondition>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CacheCondition {
    pub method: Option<String>,
    pub no_auth_header: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub output: String,
    pub file_path: Option<String>,
    pub access_log: AccessLogConfig,
    pub security_log: SecurityLogConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccessLogConfig {
    pub enabled: bool,
    pub format: String,
    pub output: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityLogConfig {
    pub enabled: bool,
    pub output: String,
    pub include_request_body: bool,
    pub include_response_body: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub port: u16,
    pub path: String,
    pub custom_metrics: Vec<CustomMetric>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomMetric {
    pub name: String,
    #[serde(rename = "type")]
    pub metric_type: String,
    pub help: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub database: u8,
    pub password: String,
    pub pool_size: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminConfig {
    pub enabled: bool,
    pub port: u16,
    pub auth: AdminAuthConfig,
    pub endpoints: Vec<AdminEndpoint>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminAuthConfig {
    pub enabled: bool,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminEndpoint {
    pub path: String,
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdvancedConfig {
    pub circuit_breaker: CircuitBreakerConfig,
    pub jwt: JwtConfig,
    pub ml_anomaly_detection: MlAnomalyConfig,
    pub threat_intelligence: ThreatIntelConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CircuitBreakerConfig {
    pub enabled: bool,
    pub failure_threshold: u32,
    #[serde(with = "duration_serde")]
    pub recovery_timeout: Duration,
    pub half_open_max_calls: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    pub enabled: bool,
    pub secret: String,
    pub algorithm: String,
    pub required_claims: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MlAnomalyConfig {
    pub enabled: bool,
    pub model_path: String,
    pub confidence_threshold: f32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThreatIntelConfig {
    pub enabled: bool,
    pub feeds: Vec<ThreatFeed>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThreatFeed {
    pub url: String,
    pub format: String,
    #[serde(with = "duration_serde")]
    pub update_interval: Duration,
}

impl Config {
    /// Load configuration from file
    pub async fn load(path: &str) -> Result<Self> {
        let content = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read config file: {}", path))?;
        
        let config: Config = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path))?;
        
        config.validate()?;
        Ok(config)
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate server config
        if self.server.port == 0 {
            anyhow::bail!("Server port cannot be zero");
        }
        
        if self.server.workers == 0 {
            anyhow::bail!("Worker count cannot be zero");
        }
        
        // Validate SSL config
        if self.ssl.enabled {
            if self.ssl.cert_path.is_empty() {
                anyhow::bail!("SSL cert_path cannot be empty when SSL is enabled");
            }
            if self.ssl.key_path.is_empty() {
                anyhow::bail!("SSL key_path cannot be empty when SSL is enabled");
            }
        }
        
        // Validate upstream configs
        for (name, upstream) in &self.proxy.upstreams {
            if upstream.servers.is_empty() {
                anyhow::bail!("Upstream '{}' must have at least one server", name);
            }
            
            for server in &upstream.servers {
                if server.url.is_empty() {
                    anyhow::bail!("Server URL cannot be empty in upstream '{}'", name);
                }
                if server.weight == 0 {
                    anyhow::bail!("Server weight cannot be zero in upstream '{}'", name);
                }
            }
        }
        
        // Validate routes
        for route in &self.proxy.routes {
            if !self.proxy.upstreams.contains_key(&route.upstream) {
                anyhow::bail!("Route references unknown upstream: {}", route.upstream);
            }
        }
        
        Ok(())
    }
}

mod duration_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;
    
    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let secs = duration.as_secs();
        serializer.serialize_str(&format!("{}s", secs))
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        parse_duration(&s).map_err(serde::de::Error::custom)
    }
    
    fn parse_duration(s: &str) -> std::result::Result<Duration, Box<dyn std::error::Error + Send + Sync>> {
        if s.ends_with("s") {
            let num: u64 = s.trim_end_matches("s").parse()?;
            Ok(Duration::from_secs(num))
        } else if s.ends_with("m") {
            let num: u64 = s.trim_end_matches("m").parse()?;
            Ok(Duration::from_secs(num * 60))
        } else if s.ends_with("h") {
            let num: u64 = s.trim_end_matches("h").parse()?;
            Ok(Duration::from_secs(num * 3600))
        } else {
            let num: u64 = s.parse()?;
            Ok(Duration::from_secs(num))
        }
    }
}
