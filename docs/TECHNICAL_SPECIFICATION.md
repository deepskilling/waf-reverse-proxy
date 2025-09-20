# 🔧 Technical Architecture Specification

**WAF + Reverse Proxy by Deepskilling - Complete Technical Reference**

Detailed technical architecture, API specifications, and implementation details for both Rust and Python versions.

---

## 🏗️ **System Architecture**

### **High-Level Architecture**
```
┌─────────────────────────────────────────────────────────────────────┐
│                          Load Balancer                              │
└─────────────────────────┬───────────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────────┐
│                    WAF + Reverse Proxy                              │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐     │
│  │   WAF Engine    │  │  Reverse Proxy  │  │  SSL/TLS Mgr    │     │
│  │                 │  │                 │  │                 │     │
│  │ • OWASP Top 10  │  │ • Load Balance  │  │ • Cert Mgmt     │     │
│  │ • Bot Detection │  │ • Health Checks │  │ • Auto-Provision│     │
│  │ • Rate Limiting │  │ • Caching       │  │ • TLS Terminate │     │
│  │ • Geo-blocking  │  │ • Request Route │  │ • OCSP Stapling │     │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘     │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Admin & Monitoring                        │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐     │   │
│  │  │ Admin API   │  │  Metrics    │  │  Health Checks  │     │   │
│  │  │             │  │             │  │                 │     │   │
│  │  │ • REST API  │  │ • Prometheus│  │ • Component     │     │   │
│  │  │ • JWT Auth  │  │ • Custom    │  │ • Dependency    │     │   │
│  │  │ • RBAC      │  │ • Export    │  │ • Performance   │     │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘     │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────────┐
│                    Backend Services                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐             │
│  │   API-1     │  │   API-2     │  │   Static Files  │             │
│  └─────────────┘  └─────────────┘  └─────────────────┘             │
└─────────────────────────────────────────────────────────────────────┘
```

### **Request Processing Flow**
```
1. Client Request
   ↓
2. TLS Termination (if HTTPS)
   ↓
3. WAF Analysis
   ├── OWASP Pattern Matching
   ├── Bot Detection Analysis  
   ├── Rate Limiting Check
   ├── Geo-location Verification
   └── Custom Rules Evaluation
   ↓
4. Request Routing Decision
   ├── Host-based Routing
   ├── Path-based Routing
   └── Header-based Routing
   ↓
5. Load Balancing
   ├── Algorithm Selection
   ├── Server Health Check
   └── Connection Pool Management
   ↓
6. Cache Check (if enabled)
   ├── Cache Key Generation
   ├── Cache Lookup
   └── Cache Hit/Miss Logic
   ↓
7. Upstream Request (if cache miss)
   ├── Connection Establishment
   ├── Request Forwarding
   └── Response Reception
   ↓
8. Response Processing
   ├── Header Manipulation
   ├── Security Header Injection
   ├── Cache Storage (if applicable)
   └── Response Forwarding
   ↓
9. Metrics & Logging
   ├── Performance Metrics
   ├── Security Events
   └── Access Logging
```

---

## 🔧 **Component Architecture**

### **🦀 Rust Implementation Architecture**

#### **Core Components**
```rust
// Main application structure
pub struct WafReverseProxy {
    config: Arc<Config>,
    waf_engine: Arc<WafEngine>,
    reverse_proxy: Arc<ReverseProxy>,
    ssl_manager: Arc<SslManager>,
    admin_api: Arc<AdminApi>,
    metrics_collector: Arc<MetricsCollector>,
    health_checker: Arc<HealthChecker>,
}

// WAF Engine
pub struct WafEngine {
    owasp_protector: OwaspProtector,
    bot_detector: BotDetector,
    rate_limiter: RateLimiter,
    geo_blocker: GeoBlocker,
    custom_rules: RuleEngine,
    pattern_cache: Arc<RwLock<PatternCache>>,
}

// Reverse Proxy
pub struct ReverseProxy {
    load_balancer: Arc<LoadBalancer>,
    health_monitor: Arc<HealthMonitor>,
    cache_manager: Arc<CacheManager>,
    connection_pool: Arc<ConnectionPool>,
    request_router: Arc<RequestRouter>,
}
```

#### **Concurrency Model**
```rust
// Tokio async runtime configuration  
#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Spawn async tasks for different components
    let waf_task = tokio::spawn(waf_engine.run());
    let proxy_task = tokio::spawn(reverse_proxy.run());
    let admin_task = tokio::spawn(admin_api.run());
    let metrics_task = tokio::spawn(metrics_collector.run());
    
    // Wait for all tasks to complete
    tokio::try_join!(waf_task, proxy_task, admin_task, metrics_task)?;
    Ok(())
}

// Lock-free data structures for performance
use parking_lot::RwLock;           // Fast reader-writer locks
use crossbeam::channel::unbounded;  // Lock-free channels
use atomic::Atomic;                 // Atomic operations
```

#### **Memory Management**
```rust
// Zero-copy string processing
use bytes::{Bytes, BytesMut};
use http_body_util::Full;

// Memory pools for request processing
pub struct RequestPool {
    pool: Arc<Mutex<Vec<RequestBuffer>>>,
    max_size: usize,
}

// Custom allocators for high-frequency objects
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
```

### **🐍 Python Implementation Architecture**

#### **Core Components**
```python
# Main application structure using FastAPI
class PyWAFApp:
    def __init__(self):
        self.config = Config.load_from_file("config.yaml")
        self.waf_engine = WAFEngine(self.config)
        self.reverse_proxy = ReverseProxy(self.config)
        self.ssl_manager = SSLManager(self.config)
        self.admin_api = create_admin_router(self.config)
        self.metrics = MetricsCollector(self.config)
        self.health_checker = HealthChecker(self.config)

# WAF Engine with async processing
class WAFEngine:
    def __init__(self, config: Config):
        self.owasp_protector = OwaspProtector(config.waf.owasp_protection)
        self.bot_detector = BotDetector(config.waf.bot_protection)
        self.rate_limiter = RateLimiter(config.waf.rate_limiting)
        self.geo_blocker = GeoBlocker(config.waf.geo_blocking)
        self.custom_rules = CustomRuleEngine(config.waf.custom_rules)
        self.pattern_cache = TTLCache(maxsize=10000, ttl=3600)

# Reverse Proxy with httpx backend
class ReverseProxy:
    def __init__(self, config: Config):
        self.load_balancer = LoadBalancer(config.proxy.upstreams)
        self.health_monitor = HealthMonitor(config.proxy.health_checks)
        self.cache_manager = CacheManager(config.proxy.caching)
        self.http_client = httpx.AsyncClient(
            limits=httpx.Limits(max_connections=200),
            timeout=httpx.Timeout(30.0)
        )
```

#### **Async/Await Concurrency**
```python
import asyncio
import aiohttp
from contextlib import asynccontextmanager

# Application lifecycle management
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await waf_engine.initialize()
    await reverse_proxy.start()
    await metrics_collector.start()
    
    yield  # Application runs here
    
    # Shutdown
    await reverse_proxy.stop()
    await metrics_collector.stop()

# Concurrent request processing
async def process_request(request: Request) -> Response:
    # Concurrent WAF analysis and cache lookup
    waf_task = asyncio.create_task(waf_engine.inspect_request(request))
    cache_task = asyncio.create_task(cache_manager.get(request.cache_key))
    
    # Wait for WAF decision
    waf_result = await waf_task
    if waf_result.action == WAFAction.BLOCK:
        return Response(status_code=403, content=waf_result.message)
    
    # Check cache result
    cached_response = await cache_task
    if cached_response:
        return cached_response
    
    # Forward to upstream
    return await reverse_proxy.forward_request(request)
```

---

## 🔒 **Security Architecture**

### **Defense in Depth Strategy**
```
Layer 1: Network Security
├── DDoS Protection (Rate Limiting)
├── IP Reputation Filtering
├── Geo-location Blocking
└── Network ACLs

Layer 2: Application Layer Filtering  
├── OWASP Top 10 Protection
├── Bot Detection & Mitigation
├── Custom Attack Signatures
└── Behavioral Analysis

Layer 3: Content Security
├── Input Validation & Sanitization
├── Output Encoding
├── Content Security Policy
└── Security Headers

Layer 4: Authentication & Authorization
├── JWT Token Validation
├── Role-Based Access Control
├── API Key Management
└── OAuth2/OpenID Connect

Layer 5: Cryptographic Security
├── TLS 1.3 Encryption
├── Perfect Forward Secrecy
├── Certificate Management
└── OCSP Stapling
```

### **Threat Model**
```yaml
# Identified Threats and Mitigations
threats:
  - name: "SQL Injection"
    severity: "CRITICAL"
    mitigations:
      - "Pattern-based detection"
      - "Parameter validation"
      - "Query parameterization detection"
    
  - name: "Cross-Site Scripting (XSS)"
    severity: "HIGH"
    mitigations:
      - "Content Security Policy"
      - "Input sanitization"
      - "Output encoding"
      
  - name: "DDoS Attacks"
    severity: "HIGH"
    mitigations:
      - "Rate limiting (multi-tier)"
      - "Connection limiting"
      - "Resource throttling"
      
  - name: "Bot Attacks"
    severity: "MEDIUM"
    mitigations:
      - "Behavioral analysis"
      - "Challenge-response systems"
      - "User-agent fingerprinting"
```

---

## 📡 **API Specifications**

### **Admin REST API (OpenAPI 3.0)**

#### **Authentication**
```yaml
openapi: 3.0.0
info:
  title: WAF + Reverse Proxy Admin API
  version: 1.0.0
  description: Administrative interface for WAF and Proxy management

components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
      
  schemas:
    AuthRequest:
      type: object
      required: [username, password]
      properties:
        username: {type: string}
        password: {type: string, format: password}
        
    AuthResponse:
      type: object
      properties:
        access_token: {type: string}
        token_type: {type: string, default: "bearer"}
        expires_in: {type: integer}
```

#### **WAF Management Endpoints**
```yaml
paths:
  /admin/waf/stats:
    get:
      summary: Get WAF statistics
      security: [{BearerAuth: []}]
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  requests_processed: {type: integer}
                  requests_blocked: {type: integer}
                  block_rate: {type: number}
                  attack_types:
                    type: object
                    properties:
                      sql_injection: {type: integer}
                      xss: {type: integer}
                      bot_traffic: {type: integer}
                  performance:
                    type: object
                    properties:
                      avg_processing_time_ms: {type: number}
                      
  /admin/waf/rules/{rule_id}:
    put:
      summary: Update WAF rule
      parameters:
        - name: rule_id
          in: path
          required: true
          schema: {type: string}
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                enabled: {type: boolean}
                threshold: {type: number, minimum: 0, maximum: 1}
                action: {type: string, enum: [allow, block, challenge]}
```

#### **Proxy Management Endpoints**
```yaml
  /admin/proxy/upstreams:
    get:
      summary: List all upstream configurations
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  upstreams:
                    type: array
                    items:
                      type: object
                      properties:
                        name: {type: string}
                        algorithm: {type: string}
                        servers:
                          type: array
                          items:
                            type: object
                            properties:
                              host: {type: string}
                              port: {type: integer}
                              status: {type: string, enum: [healthy, unhealthy]}
                              weight: {type: integer}
                              active_connections: {type: integer}
                              
  /admin/proxy/cache/clear:
    delete:
      summary: Clear proxy cache
      parameters:
        - name: pattern
          in: query
          schema: {type: string}
          description: "Cache key pattern to match (supports wildcards)"
      responses:
        200:
          content:
            application/json:
              schema:
                type: object
                properties:
                  entries_cleared: {type: integer}
                  success: {type: boolean}
```

### **WebSocket API for Real-time Monitoring**
```javascript
// WebSocket connection for live monitoring
const ws = new WebSocket('wss://waf.example.com/admin/ws');

// Authentication message
ws.send(JSON.stringify({
    type: 'auth',
    token: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...'
}));

// Subscribe to live events
ws.send(JSON.stringify({
    type: 'subscribe',
    events: ['security_events', 'performance_metrics', 'health_status']
}));

// Event message format
{
    "type": "security_event",
    "timestamp": "2024-01-15T10:30:45.123Z",
    "data": {
        "event_type": "attack_blocked",
        "client_ip": "203.0.113.42",
        "attack_type": "sql_injection",
        "confidence": 0.95,
        "pattern": "' OR 1=1--"
    }
}
```

---

## 🗄️ **Database Schema**

### **Configuration Storage**
```sql
-- Configuration versioning
CREATE TABLE config_versions (
    id SERIAL PRIMARY KEY,
    version VARCHAR(50) NOT NULL,
    config_data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    created_by VARCHAR(100),
    active BOOLEAN DEFAULT FALSE,
    checksum VARCHAR(64)
);

-- WAF rules storage
CREATE TABLE waf_rules (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    pattern TEXT NOT NULL,
    action VARCHAR(20) NOT NULL,
    priority INTEGER DEFAULT 100,
    enabled BOOLEAN DEFAULT TRUE,
    threshold DECIMAL(3,2) DEFAULT 0.8,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Security events logging
CREATE TABLE security_events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    client_ip INET NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    attack_type VARCHAR(50),
    confidence DECIMAL(3,2),
    rule_name VARCHAR(100),
    pattern_matched TEXT,
    action_taken VARCHAR(20),
    request_method VARCHAR(10),
    request_path TEXT,
    request_headers JSONB,
    response_status INTEGER
);

-- Performance metrics
CREATE TABLE performance_metrics (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT NOW(),
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(10,4),
    labels JSONB,
    INDEX (timestamp, metric_name)
);
```

### **Cache Storage Schema (Redis)**
```redis
# Cache key patterns
cache:request:{hash}         # Request cache entries
cache:upstream:{name}        # Upstream response cache
cache:session:{session_id}   # Session data cache
cache:rate_limit:{ip}        # Rate limiting counters
cache:geo:{ip}              # GeoIP lookup cache

# Rate limiting data structures
rate_limit:global           # Global rate limiter (ZSET)
rate_limit:ip:{ip}         # Per-IP counters (HASH)
rate_limit:endpoint:{path} # Per-endpoint counters (HASH)

# Health check data
health:{upstream}:{server} # Server health status
health:last_check:{server} # Last health check timestamp

# Session management
session:{session_id}       # User session data (HASH)
session:tokens:{user_id}   # Active tokens per user (SET)
```

---

## 📊 **Performance Optimization**

### **Rust Optimizations**

#### **Compile-time Optimizations**
```toml
# Cargo.toml - Release profile
[profile.release]
opt-level = 3              # Maximum optimization
lto = true                 # Link-time optimization
codegen-units = 1          # Single codegen unit for better optimization
panic = "abort"            # Smaller binary size
strip = true               # Strip debug symbols

# CPU-specific optimizations
[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "target-cpu=native"]
```

#### **Memory Pool Management**
```rust
// Object pools for high-frequency allocations
use object_pool::Pool;

lazy_static! {
    static ref REQUEST_POOL: Pool<RequestBuffer> = Pool::new(100, || {
        RequestBuffer::with_capacity(8192)
    });
    
    static ref RESPONSE_POOL: Pool<ResponseBuffer> = Pool::new(50, || {
        ResponseBuffer::with_capacity(4096)
    });
}

// Zero-copy string operations
use bytes::BytesMut;
fn process_headers_zero_copy(headers: &[u8]) -> Result<HeaderMap, ParseError> {
    // Parse headers without allocating new strings
    let mut map = HeaderMap::with_capacity(16);
    for line in headers.split(|&b| b == b'\n') {
        // Process line without copying
        if let Some(pos) = line.iter().position(|&b| b == b':') {
            let name = HeaderName::from_bytes(&line[..pos])?;
            let value = HeaderValue::from_bytes(&line[pos+1..])?;
            map.insert(name, value);
        }
    }
    Ok(map)
}
```

#### **Lock-free Data Structures**
```rust
use crossbeam::atomic::AtomicCell;
use parking_lot::{RwLock, Mutex};
use dashmap::DashMap; // Concurrent HashMap

// Lock-free counters for metrics
struct AtomicMetrics {
    requests_total: AtomicU64,
    requests_blocked: AtomicU64,
    response_time_sum: AtomicU64,
    response_time_count: AtomicU64,
}

// Concurrent cache with minimal locking
type ConcurrentCache = DashMap<String, CacheEntry>;
```

### **Python Optimizations**

#### **Asyncio Event Loop Tuning**
```python
import asyncio
import uvloop  # High-performance event loop

# Use uvloop for better performance
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

# Configure event loop
loop = asyncio.new_event_loop()
loop.set_debug(False)  # Disable debug mode in production
loop.slow_callback_duration = 0.1  # Log slow callbacks

# Connection pool optimization
connector = aiohttp.TCPConnector(
    limit=1000,           # Total connection pool size
    limit_per_host=100,   # Per-host connection limit
    ttl_dns_cache=300,    # DNS cache TTL
    use_dns_cache=True,   # Enable DNS caching
    keepalive_timeout=30, # Keep-alive timeout
    enable_cleanup_closed=True  # Clean up closed connections
)
```

#### **Caching Strategies**
```python
from functools import lru_cache
from cachetools import TTLCache, LRUCache
import asyncio

# Multi-level caching
class MultiLevelCache:
    def __init__(self):
        self.l1_cache = LRUCache(maxsize=1000)      # In-memory L1
        self.l2_cache = TTLCache(maxsize=10000, ttl=3600)  # In-memory L2
        self.l3_cache = RedisCache()                # Distributed L3
        
    async def get(self, key: str):
        # Check L1 cache first
        if key in self.l1_cache:
            return self.l1_cache[key]
            
        # Check L2 cache
        if key in self.l2_cache:
            value = self.l2_cache[key]
            self.l1_cache[key] = value  # Promote to L1
            return value
            
        # Check L3 cache
        value = await self.l3_cache.get(key)
        if value:
            self.l2_cache[key] = value  # Store in L2
            self.l1_cache[key] = value  # Store in L1
        return value

# Pattern compilation caching
@lru_cache(maxsize=10000)
def compile_pattern(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)
```

---

## 🔧 **Configuration Schema**

### **Complete Configuration Reference**
```yaml
# Root configuration schema
environment: "production|staging|development"
debug: boolean
log_level: "DEBUG|INFO|WARN|ERROR"

# Server configuration
server:
  host: string              # Bind address
  port: integer            # Port number (1-65535)
  workers: integer         # Number of worker processes
  max_connections: integer # Maximum concurrent connections
  keepalive_timeout: integer # Keep-alive timeout in seconds
  request_timeout: integer # Request timeout in seconds
  max_request_size: string # Maximum request size (e.g., "10MB")
  
# SSL/TLS configuration  
ssl:
  enabled: boolean
  auto_provision: boolean
  
  # Manual certificate configuration
  certificates:
    - domains: [string]     # Domain names
      cert_file: string     # Certificate file path
      key_file: string      # Private key file path
      chain_file: string    # Certificate chain file
      
  # ACME/Let's Encrypt configuration
  acme:
    directory_url: string   # ACME directory URL
    email: string          # Contact email
    domains: [string]      # Domains to provision
    challenge_type: "http-01|dns-01|tls-alpn-01"
    key_type: "rsa2048|rsa4096|ecdsa256|ecdsa384"
    
  # TLS settings
  protocols: [string]      # Enabled TLS versions
  ciphers: [string]        # Allowed cipher suites
  session_cache:
    enabled: boolean
    size: string           # Cache size (e.g., "10MB")
    timeout: integer       # Session timeout
    
  # OCSP stapling
  ocsp_stapling:
    enabled: boolean
    cache_size: string
    timeout: integer

# WAF configuration
waf:
  enabled: boolean
  mode: "monitor|block|challenge"
  
  # OWASP Top 10 protection
  owasp_protection:
    enabled: boolean
    sql_injection_threshold: float    # 0.0-1.0
    xss_threshold: float              # 0.0-1.0
    rce_threshold: float              # 0.0-1.0
    path_traversal_threshold: float   # 0.0-1.0
    csrf_protection:
      enabled: boolean
      token_validation: boolean
      confidence_threshold: float
      
  # Bot protection
  bot_protection:
    enabled: boolean
    detection_threshold: float        # 0.0-1.0
    challenge_threshold: float        # 0.0-1.0
    blocked_user_agents: [string]
    allowed_user_agents: [string]
    behavioral_analysis: boolean
    javascript_challenge: boolean
    
  # Rate limiting
  rate_limiting:
    global_limit:
      requests_per_second: integer
      requests_per_minute: integer
      requests_per_hour: integer
      burst: integer
      algorithm: "token_bucket|sliding_window|fixed_window"
    per_ip_limit:
      requests_per_second: integer
      requests_per_minute: integer
      burst: integer
    per_endpoint_limits:
      - path: string
        requests_per_second: integer
        requests_per_minute: integer
        
  # Geo-blocking
  geo_blocking:
    enabled: boolean
    blocked_countries: [string]       # ISO country codes
    allowed_countries: [string]       # Empty = allow all except blocked
    geoip_database: string           # Path to GeoIP database
    update_interval: integer         # Database update interval
    whitelist_ips: [string]          # IPs to always allow
    
  # Custom rules
  custom_rules:
    - name: string
      enabled: boolean
      priority: integer              # Lower = higher priority
      conditions:
        - type: "path|header|ip|rate_limit"
          operator: "equals|contains|starts_with|ends_with|regex|in_subnet"
          value: string
          name: string               # For header conditions
      action: "allow|block|challenge|log"
      message: string
      
# Reverse proxy configuration
proxy:
  # Upstream servers
  upstreams:
    - name: string
      algorithm: "round_robin|least_connections|ip_hash|weighted_random"
      servers:
        - host: string
          port: integer
          weight: integer            # For weighted algorithms
          max_connections: integer   # Per-server connection limit
          max_fails: integer         # Max failures before marking unhealthy
          fail_timeout: integer      # Timeout after max failures
          
      # Health checks
      health_check:
        enabled: boolean
        type: "http|tcp|custom"
        path: string                 # For HTTP health checks
        method: string               # HTTP method
        interval: integer            # Check interval in seconds
        timeout: integer             # Check timeout
        healthy_threshold: integer   # Successes needed to mark healthy
        unhealthy_threshold: integer # Failures needed to mark unhealthy
        expected_status: [integer]   # Expected HTTP status codes
        expected_body: string        # Expected response body
        headers: {string: string}    # Headers to send
        
  # Request routing
  routes:
    - hosts: [string]                # Host-based routing
      pattern: string                # Path pattern
      upstream: string               # Target upstream name
      timeout: integer               # Request timeout
      retry_attempts: integer        # Number of retries
      cache_ttl: integer            # Cache TTL in seconds
      headers:                      # Headers to add/modify
        add: {string: string}
        set: {string: string}
        remove: [string]
      conditions:                   # Additional routing conditions
        - type: "header|query|method"
          name: string
          operator: string
          value: string
          required: boolean
          
  # Caching
  caching:
    enabled: boolean
    
    # Memory cache
    memory_cache:
      enabled: boolean
      max_size: string              # Maximum cache size
      max_entries: integer          # Maximum number of entries
      eviction_policy: "lru|lfu|ttl"
      compression: boolean
      compression_threshold: integer # Minimum size to compress
      
    # Redis cache
    redis_cache:
      enabled: boolean
      host: string
      port: integer
      db: integer
      password: string
      pool_size: integer
      timeout: integer
      cluster_mode: boolean
      cluster_nodes: [string]
      
    # Cache rules
    cache_rules:
      - path: string
        ttl: integer
        vary_headers: [string]       # Headers to include in cache key
        cache_key_include: [string]  # Additional cache key components
        conditions:
          - header: string
            operator: string
            value: string
            
# Admin API configuration
admin:
  enabled: boolean
  host: string
  port: integer
  
  # Authentication
  auth:
    enabled: boolean
    jwt_secret: string
    jwt_algorithm: string
    token_expiry: integer           # Token expiry in seconds
    refresh_token_expiry: integer   # Refresh token expiry
    max_login_attempts: integer     # Max failed login attempts
    lockout_duration: integer       # Account lockout duration
    
  # CORS settings
  cors:
    enabled: boolean
    allow_origins: [string]
    allow_methods: [string]
    allow_headers: [string]
    expose_headers: [string]
    allow_credentials: boolean
    max_age: integer
    
  # Rate limiting for admin API
  rate_limiting:
    enabled: boolean
    requests_per_minute: integer
    per_ip: boolean
    
# Metrics and monitoring
metrics:
  enabled: boolean
  
  # Prometheus configuration
  prometheus:
    enabled: boolean
    port: integer
    path: string
    registry: "default|custom"
    
  # Custom metrics
  custom_metrics:
    enabled: boolean
    endpoint: string
    format: "prometheus|json|influxdb"
    
  # Health checks
  health_checks:
    enabled: boolean
    endpoint: string
    detailed: boolean               # Include detailed component status
    
# Logging configuration
logging:
  level: "DEBUG|INFO|WARN|ERROR"
  format: "json|text|structured"
  outputs: [string]                # ["stdout", "/var/log/app.log"]
  
  # Security event logging
  security_log:
    enabled: boolean
    file: string
    max_size: string
    rotation: "daily|weekly|size"
    retention_days: integer
    
  # Access logging
  access_log:
    enabled: boolean
    file: string
    format: "combined|common|json|custom"
    custom_format: string
    
  # Performance logging
  performance_log:
    enabled: boolean
    file: string
    slow_request_threshold: integer # Log requests slower than this (ms)

# Database configuration (optional)
database:
  type: "postgresql|mysql|sqlite"
  host: string
  port: integer
  database: string
  username: string
  password: string
  pool_size: integer
  max_connections: integer
  connection_timeout: integer

# External integrations
integrations:
  # Threat intelligence feeds
  threat_intelligence:
    enabled: boolean
    providers:
      - name: string
        url: string
        api_key: string
        update_interval: integer
        
  # SIEM integration
  siem:
    enabled: boolean
    type: "splunk|elk|qradar|custom"
    endpoint: string
    format: "cef|json|syslog"
    
  # Notification services
  notifications:
    email:
      enabled: boolean
      smtp_server: string
      smtp_port: integer
      username: string
      password: string
      from: string
      to: [string]
    slack:
      enabled: boolean
      webhook_url: string
      channel: string
    webhook:
      enabled: boolean
      url: string
      secret: string
      events: [string]
```

This comprehensive technical specification provides complete details for implementing, configuring, and deploying both Rust and Python versions of the WAF + Reverse Proxy system. Each section includes implementation-specific details, performance considerations, and production deployment guidelines.
