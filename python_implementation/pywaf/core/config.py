"""
PyWAF Configuration System

Comprehensive configuration management with validation, type checking,
and runtime updates.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from datetime import timedelta
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings

from .exceptions import ConfigurationError


class LogLevel(str, Enum):
    """Logging levels"""
    TRACE = "trace"
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class LogFormat(str, Enum):
    """Log output formats"""
    JSON = "json"
    TEXT = "text"
    STRUCTURED = "structured"


class WAFMode(str, Enum):
    """WAF operating modes"""
    BLOCK = "block"
    MONITOR = "monitor" 
    LOG = "log"
    OFF = "off"


class LoadBalancerAlgorithm(str, Enum):
    """Load balancing algorithms"""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    IP_HASH = "ip_hash"
    WEIGHTED = "weighted"
    RANDOM = "random"


class CacheBackend(str, Enum):
    """Cache backend types"""
    MEMORY = "memory"
    REDIS = "redis"
    HYBRID = "hybrid"


# Base configuration models

class ServerConfig(BaseModel):
    """Server configuration"""
    host: str = Field(default="0.0.0.0", description="Server bind address")
    port: int = Field(default=8080, ge=1, le=65535, description="Server port")
    workers: int = Field(default=4, ge=1, description="Number of worker processes")
    max_connections: int = Field(default=1000, ge=1, description="Maximum concurrent connections")
    keepalive_timeout: int = Field(default=60, ge=1, description="Keep-alive timeout in seconds")
    
    @field_validator('host')
    @classmethod
    def validate_host(cls, v):
        if not v or v.strip() == "":
            raise ValueError("Host cannot be empty")
        return v


class SSLConfig(BaseModel):
    """SSL/TLS configuration"""
    enabled: bool = Field(default=False, description="Enable SSL/TLS")
    port: int = Field(default=8443, ge=1, le=65535, description="HTTPS port")
    cert_file: Optional[str] = Field(default=None, description="Certificate file path")
    key_file: Optional[str] = Field(default=None, description="Private key file path")
    
    # Let's Encrypt / ACME configuration
    auto_provision: bool = Field(default=False, description="Enable automatic certificate provisioning")
    acme_directory: str = Field(
        default="https://acme-v02.api.letsencrypt.org/directory",
        description="ACME directory URL"
    )
    acme_email: Optional[str] = Field(default=None, description="Email for Let's Encrypt account")
    domains: List[str] = Field(default_factory=list, description="Domains for auto-provisioning")
    
    # SSL settings
    protocols: List[str] = Field(
        default=["TLSv1.2", "TLSv1.3"],
        description="Supported TLS protocols"
    )
    ciphers: Optional[str] = Field(default=None, description="SSL cipher suite")
    
    # Certificate storage and renewal
    cert_dir: str = Field(default="./certs", description="Certificate storage directory")
    renewal_days: int = Field(default=30, ge=1, description="Days before expiry to renew")
    
    @model_validator(mode='after')
    def validate_ssl_config(self):
        if self.enabled:
            if not self.auto_provision:
                if not self.cert_file or not self.key_file:
                    raise ValueError("cert_file and key_file required when SSL enabled and auto_provision disabled")
            else:
                if not self.acme_email:
                    raise ValueError("acme_email required for auto-provisioning")
                if not self.domains:
                    raise ValueError("domains required for auto-provisioning")
        return self


class RateLimitConfig(BaseModel):
    """Rate limiting configuration"""
    requests_per_second: Optional[int] = Field(default=None, ge=1)
    requests_per_minute: Optional[int] = Field(default=None, ge=1) 
    requests_per_hour: Optional[int] = Field(default=None, ge=1)
    burst: int = Field(default=10, ge=1, description="Burst capacity")
    
    @model_validator(mode='after')
    def validate_rate_limits(self):
        if not any([
            self.requests_per_second,
            self.requests_per_minute,
            self.requests_per_hour
        ]):
            raise ValueError("At least one rate limit must be specified")
        return self


class WAFRateLimitConfig(BaseModel):
    """WAF rate limiting configuration"""
    global_limit: Optional[RateLimitConfig] = Field(default=None)
    per_ip: Optional[RateLimitConfig] = Field(default=None)
    per_endpoint: Optional[RateLimitConfig] = Field(default=None)


class OwaspProtectionConfig(BaseModel):
    """OWASP Top 10 protection configuration"""
    enabled: bool = Field(default=True)
    
    # Individual protections
    sql_injection: bool = Field(default=True)
    xss_protection: bool = Field(default=True)
    csrf_protection: bool = Field(default=True)
    rce_protection: bool = Field(default=True)
    path_traversal: bool = Field(default=True)
    
    # Confidence thresholds
    sql_injection_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    xss_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    csrf_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    rce_threshold: float = Field(default=0.9, ge=0.0, le=1.0)
    path_traversal_threshold: float = Field(default=0.9, ge=0.0, le=1.0)


class BotProtectionConfig(BaseModel):
    """Bot detection and protection configuration"""
    enabled: bool = Field(default=True)
    
    # Detection methods
    user_agent_analysis: bool = Field(default=True)
    behavioral_analysis: bool = Field(default=True)
    challenge_response: bool = Field(default=True)
    
    # Bot handling
    block_known_bots: bool = Field(default=True)
    challenge_suspicious: bool = Field(default=True)
    
    # Thresholds
    suspicious_threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    bot_threshold: float = Field(default=0.8, ge=0.0, le=1.0)


class GeoBlockingConfig(BaseModel):
    """Geographic blocking configuration"""
    enabled: bool = Field(default=False)
    
    # Country codes (ISO 3166-1 alpha-2)
    blocked_countries: List[str] = Field(default_factory=list)
    allowed_countries: List[str] = Field(default_factory=list)
    
    # GeoIP database
    geoip_database: str = Field(default="./geoip/GeoLite2-Country.mmdb")
    update_interval: int = Field(default=24*3600, description="Database update interval in seconds")
    
    @field_validator('blocked_countries', 'allowed_countries')
    @classmethod
    def validate_country_codes(cls, v):
        for code in v:
            if not isinstance(code, str) or len(code) != 2:
                raise ValueError(f"Invalid country code: {code}")
        return [code.upper() for code in v]


class CustomRuleCondition(BaseModel):
    """Custom WAF rule condition"""
    type: str = Field(..., description="Condition type")
    field: Optional[str] = Field(default=None, description="Field to match")
    operator: str = Field(default="equals", description="Comparison operator")
    value: Union[str, int, float, List[str]] = Field(..., description="Value to compare")
    case_sensitive: bool = Field(default=True)


class CustomRule(BaseModel):
    """Custom WAF rule"""
    name: str = Field(..., description="Rule name")
    enabled: bool = Field(default=True)
    priority: int = Field(default=100, ge=0, description="Rule priority (lower = higher priority)")
    action: str = Field(..., pattern=r'^(allow|block|monitor|log|challenge)$')
    
    # Rule conditions
    conditions: List[CustomRuleCondition] = Field(..., min_items=1)
    
    # Rule metadata
    description: Optional[str] = Field(default=None)
    tags: List[str] = Field(default_factory=list)


class WAFConfig(BaseModel):
    """WAF configuration"""
    enabled: bool = Field(default=True)
    mode: WAFMode = Field(default=WAFMode.BLOCK)
    
    # Protection modules
    rate_limiting: WAFRateLimitConfig = Field(default_factory=WAFRateLimitConfig)
    owasp_protection: OwaspProtectionConfig = Field(default_factory=OwaspProtectionConfig)
    bot_protection: BotProtectionConfig = Field(default_factory=BotProtectionConfig)
    geo_blocking: GeoBlockingConfig = Field(default_factory=GeoBlockingConfig)
    
    # Custom rules
    custom_rules: List[CustomRule] = Field(default_factory=list)


class UpstreamServer(BaseModel):
    """Upstream server configuration"""
    url: str = Field(..., description="Server URL")
    weight: int = Field(default=100, ge=0, description="Server weight for load balancing")
    backup: bool = Field(default=False, description="Backup server flag")
    
    # Health check settings
    max_fails: int = Field(default=3, ge=0, description="Max failed health checks")
    fail_timeout: int = Field(default=30, ge=1, description="Fail timeout in seconds")


class HealthCheckConfig(BaseModel):
    """Health check configuration"""
    enabled: bool = Field(default=True)
    interval: int = Field(default=30, ge=1, description="Check interval in seconds")
    timeout: int = Field(default=5, ge=1, description="Check timeout in seconds")
    path: str = Field(default="/health", description="Health check path")
    expected_codes: List[int] = Field(default=[200], description="Expected HTTP status codes")
    
    # Advanced health checking
    healthy_threshold: int = Field(default=2, ge=1, description="Consecutive successes to mark healthy")
    unhealthy_threshold: int = Field(default=3, ge=1, description="Consecutive failures to mark unhealthy")


class UpstreamConfig(BaseModel):
    """Upstream configuration"""
    name: str = Field(..., description="Upstream name")
    servers: List[UpstreamServer] = Field(..., min_items=1)
    
    # Load balancing
    algorithm: LoadBalancerAlgorithm = Field(default=LoadBalancerAlgorithm.ROUND_ROBIN)
    
    # Health checking
    health_check: HealthCheckConfig = Field(default_factory=HealthCheckConfig)
    
    # Connection settings
    keepalive: int = Field(default=64, ge=0, description="Keepalive connections")
    connect_timeout: int = Field(default=5, ge=1, description="Connect timeout in seconds")
    read_timeout: int = Field(default=30, ge=1, description="Read timeout in seconds")


class RouteConfig(BaseModel):
    """Route configuration"""
    path: str = Field(..., description="Route path pattern")
    upstream: str = Field(..., description="Upstream name")
    
    # Optional matching criteria
    host: Optional[str] = Field(default=None, description="Host header pattern")
    methods: List[str] = Field(default=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
    
    # Route modifiers
    strip_path: bool = Field(default=False, description="Strip matched path from upstream request")
    add_headers: Dict[str, str] = Field(default_factory=dict, description="Headers to add")
    remove_headers: List[str] = Field(default_factory=list, description="Headers to remove")


class CacheRule(BaseModel):
    """Cache rule configuration"""
    pattern: str = Field(..., description="URL pattern to match")
    ttl: int = Field(default=300, ge=0, description="Cache TTL in seconds")
    vary_headers: List[str] = Field(default_factory=list, description="Headers that vary cache")
    
    # Cache conditions
    methods: List[str] = Field(default=["GET", "HEAD"], description="Cacheable methods")
    status_codes: List[int] = Field(default=[200, 301, 302, 404], description="Cacheable status codes")


class CacheConfig(BaseModel):
    """Cache configuration"""
    enabled: bool = Field(default=True)
    backend: CacheBackend = Field(default=CacheBackend.MEMORY)
    
    # Memory cache settings
    max_size: int = Field(default=1024*1024*100, ge=0, description="Max cache size in bytes")
    max_entries: int = Field(default=10000, ge=0, description="Max cache entries")
    
    # Redis settings
    redis_url: Optional[str] = Field(default=None, description="Redis connection URL")
    redis_prefix: str = Field(default="pywaf:cache:", description="Redis key prefix")
    
    # Cache rules
    default_ttl: int = Field(default=300, ge=0, description="Default TTL in seconds")
    rules: List[CacheRule] = Field(default_factory=list)


class ProxyConfig(BaseModel):
    """Reverse proxy configuration"""
    # Upstreams and routing
    upstreams: List[UpstreamConfig] = Field(default_factory=list)
    routes: List[RouteConfig] = Field(default_factory=list)
    
    # Default upstream for unmatched routes
    default_upstream: Optional[str] = Field(default=None)
    
    # Caching
    cache: CacheConfig = Field(default_factory=CacheConfig)
    
    # Proxy settings
    buffer_size: int = Field(default=4096, ge=1024, description="Buffer size for proxied requests")
    max_body_size: int = Field(default=1024*1024*10, ge=0, description="Max request body size")


class LoggingConfig(BaseModel):
    """Logging configuration"""
    level: LogLevel = Field(default=LogLevel.INFO)
    format: LogFormat = Field(default=LogFormat.JSON)
    
    # Output destinations
    console: bool = Field(default=True, description="Log to console")
    file: Optional[str] = Field(default=None, description="Log file path")
    syslog: bool = Field(default=False, description="Log to syslog")
    
    # Access logging
    access_log: bool = Field(default=True, description="Enable access logging")
    access_log_format: str = Field(
        default='%(client_ip)s - %(method)s %(path)s - %(status_code)s - %(response_time)s ms',
        description="Access log format"
    )
    
    # Security logging
    security_log: bool = Field(default=True, description="Enable security event logging")
    security_log_file: Optional[str] = Field(default=None, description="Security log file")


class MetricsConfig(BaseModel):
    """Metrics configuration"""
    enabled: bool = Field(default=True)
    port: int = Field(default=9090, ge=1, le=65535, description="Metrics server port")
    path: str = Field(default="/metrics", description="Metrics endpoint path")
    
    # Metric collection
    collect_system_metrics: bool = Field(default=True, description="Collect system metrics")
    collect_process_metrics: bool = Field(default=True, description="Collect process metrics")
    
    # Custom metrics
    custom_metrics: Dict[str, Any] = Field(default_factory=dict)


class AdminConfig(BaseModel):
    """Admin API configuration"""
    enabled: bool = Field(default=True)
    host: str = Field(default="127.0.0.1", description="Admin API bind address") 
    port: int = Field(default=8081, ge=1, le=65535, description="Admin API port")
    
    # Authentication
    auth_enabled: bool = Field(default=True, description="Enable authentication")
    username: Optional[str] = Field(default=None, description="Admin username")
    password_hash: Optional[str] = Field(default=None, description="Admin password hash")
    
    # JWT settings
    jwt_secret: Optional[str] = Field(default=None, description="JWT secret key")
    jwt_expiry: int = Field(default=3600, ge=1, description="JWT expiry in seconds")
    
    # API settings
    cors_enabled: bool = Field(default=False, description="Enable CORS")
    cors_origins: List[str] = Field(default_factory=list, description="Allowed CORS origins")
    
    @model_validator(mode='after')
    def validate_admin_config(self):
        if self.enabled and self.auth_enabled:
            if not self.username:
                raise ValueError("Admin username is required when authentication is enabled")
            if not self.password_hash:
                raise ValueError("Admin password_hash is required when authentication is enabled")
            if not self.jwt_secret:
                raise ValueError("JWT secret is required when authentication is enabled")
        return self


class DatabaseConfig(BaseModel):
    """Database configuration"""
    url: str = Field(default="sqlite:///pywaf.db", description="Database URL")
    pool_size: int = Field(default=5, ge=1, description="Connection pool size")
    pool_timeout: int = Field(default=30, ge=1, description="Pool timeout in seconds")
    
    # Migration settings
    auto_migrate: bool = Field(default=True, description="Auto-run migrations on startup")


class Config(BaseSettings):
    """Main PyWAF configuration"""
    
    # Core settings
    server: ServerConfig = Field(default_factory=ServerConfig)
    ssl: SSLConfig = Field(default_factory=SSLConfig)
    waf: WAFConfig = Field(default_factory=WAFConfig)
    proxy: ProxyConfig = Field(default_factory=ProxyConfig)
    
    # Observability
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    metrics: MetricsConfig = Field(default_factory=MetricsConfig)
    
    # Management
    admin: AdminConfig = Field(default_factory=AdminConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    
    # Environment settings
    debug: bool = Field(default=False, description="Debug mode")
    environment: str = Field(default="production", description="Environment name")
    
    class Config:
        env_prefix = "PYWAF_"
        env_file = ".env"
        env_nested_delimiter = "__"
        case_sensitive = False
    
    @classmethod
    def load_from_file(cls, config_file: Union[str, Path]) -> "Config":
        """Load configuration from YAML file"""
        config_path = Path(config_file)
        
        if not config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {config_path}")
        
        try:
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            if not config_data:
                config_data = {}
            
            return cls(**config_data)
            
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML in config file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load config file: {e}")
    
    def save_to_file(self, config_file: Union[str, Path]) -> None:
        """Save configuration to YAML file"""
        config_path = Path(config_file)
        
        # Create directory if it doesn't exist
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(config_path, 'w') as f:
                yaml.dump(
                    self.dict(exclude_none=True),
                    f,
                    default_flow_style=False,
                    indent=2,
                    sort_keys=True
                )
        except Exception as e:
            raise ConfigurationError(f"Failed to save config file: {e}")
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        try:
            # Validate using Pydantic
            self.dict()
        except Exception as e:
            errors.append(str(e))
        
        # Additional custom validation
        
        # Check upstream references in routes
        upstream_names = {upstream.name for upstream in self.proxy.upstreams}
        for route in self.proxy.routes:
            if route.upstream not in upstream_names:
                errors.append(f"Route '{route.path}' references unknown upstream '{route.upstream}'")
        
        # Check default upstream
        if self.proxy.default_upstream and self.proxy.default_upstream not in upstream_names:
            errors.append(f"Default upstream '{self.proxy.default_upstream}' not found")
        
        # Check SSL configuration consistency
        if self.ssl.enabled and self.server.port == self.ssl.port:
            errors.append("SSL port cannot be the same as server port")
        
        # Check admin configuration
        if self.admin.enabled and self.admin.port == self.server.port:
            errors.append("Admin port cannot be the same as server port")
        
        if self.admin.auth_enabled:
            if not self.admin.username or not self.admin.password_hash:
                errors.append("Admin username and password_hash required when auth is enabled")
            if not self.admin.jwt_secret:
                errors.append("JWT secret required when admin auth is enabled")
        
        return errors
    
    def get_summary(self) -> Dict[str, Any]:
        """Get configuration summary"""
        return {
            "environment": self.environment,
            "debug": self.debug,
            "server": {
                "host": self.server.host,
                "port": self.server.port,
                "workers": self.server.workers
            },
            "ssl": {
                "enabled": self.ssl.enabled,
                "auto_provision": self.ssl.auto_provision,
                "domains": len(self.ssl.domains)
            },
            "waf": {
                "enabled": self.waf.enabled,
                "mode": self.waf.mode.value,
                "owasp_protection": self.waf.owasp_protection.enabled,
                "bot_protection": self.waf.bot_protection.enabled,
                "geo_blocking": self.waf.geo_blocking.enabled,
                "custom_rules": len(self.waf.custom_rules)
            },
            "proxy": {
                "upstreams": len(self.proxy.upstreams),
                "routes": len(self.proxy.routes),
                "cache_enabled": self.proxy.cache.enabled
            },
            "admin": {
                "enabled": self.admin.enabled,
                "port": self.admin.port,
                "auth_enabled": self.admin.auth_enabled
            },
            "metrics": {
                "enabled": self.metrics.enabled,
                "port": self.metrics.port
            }
        }
