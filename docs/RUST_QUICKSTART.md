# 🦀 Rust WAF + Reverse Proxy Quick Start Guide

**Enterprise-grade Web Application Firewall & Reverse Proxy in Rust**

A high-performance, memory-safe implementation featuring OWASP Top 10 protection, advanced reverse proxy capabilities, SSL/TLS management, and comprehensive monitoring.

---

## 📋 Table of Contents

- [🚀 Quick Installation](#-quick-installation)
- [⚡ 5-Minute Setup](#-5-minute-setup)
- [🛡️ WAF Protection Examples](#️-waf-protection-examples)
- [🔄 Reverse Proxy Examples](#-reverse-proxy-examples)
- [🔒 SSL Management Examples](#-ssl-management-examples)
- [📊 Monitoring & Metrics Examples](#-monitoring--metrics-examples)
- [⚙️ Configuration Examples](#️-configuration-examples)
- [🌐 Admin API Usage](#-admin-api-usage)
- [🐳 Docker Deployment](#-docker-deployment)
- [🔧 Advanced Configuration](#-advanced-configuration)

---

## 🚀 Quick Installation

### Prerequisites
```bash
# Rust 1.70+ required
rustc --version

# System dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install build-essential pkg-config libssl-dev redis-server

# System dependencies (macOS)
brew install openssl redis
```

### Install WAF + Reverse Proxy
```bash
# Clone the repository
git clone https://github.com/deepskilling/waf-reverse-proxy.git
cd waf-reverse-proxy

# Build the project
cargo build --release

# Verify installation
./target/release/waf-reverse-proxy --version
```

**Expected Output:**
```
WAF Reverse Proxy v1.0.0 - Built with Rust
By Deepskilling - Enterprise Web Security Solutions
```

---

## ⚡ 5-Minute Setup

### Step 1: Configure and Start
```bash
# Copy default configuration
cp config/config.yaml config.local.yaml

# Start the server
./target/release/waf-reverse-proxy --config config.local.yaml

# Expected output:
# 🚀 Starting WAF + Reverse Proxy...
# 🛡️  WAF Engine initialized - Protection level: HIGH
# 🔄 Reverse Proxy listening on 0.0.0.0:8080
# 📊 Admin API available at http://localhost:8081
# 📈 Metrics endpoint: http://localhost:9090/metrics
```

### Step 2: Verify WAF Protection
```bash
# Test normal request (should pass)
curl -X GET http://localhost:8080/health
# Expected: 200 OK

# Test XSS attack (should be blocked)
curl -X POST http://localhost:8080/api/test \
     -H "Content-Type: application/json" \
     -d '{"comment": "<script>alert(1)</script>"}'
# Expected: 403 Forbidden - XSS attempt blocked
```

### Step 3: Access Management Interfaces
- **Proxy Health**: http://localhost:8080/health
- **Admin API**: http://localhost:8081/api/docs
- **Metrics**: http://localhost:9090/metrics

---

## 🛡️ WAF Protection Examples

### Testing SQL Injection Protection

```bash
# Normal database query (allowed)
curl -X GET "http://localhost:8080/api/users?id=123"
# Response: 200 OK (proxied to upstream)

# SQL injection attempt (blocked)
curl -X GET "http://localhost:8080/api/users?id=1' OR '1'='1"
# Response: 403 Forbidden
# WAF Log: [SECURITY] SQL injection blocked from 127.0.0.1
```

### Testing XSS Protection

```bash
# Normal form submission (allowed)
curl -X POST http://localhost:8080/api/comment \
     -H "Content-Type: application/json" \
     -d '{"comment": "This is a normal comment"}'
# Response: 200 OK (proxied to upstream)

# XSS attack attempt (blocked)
curl -X POST http://localhost:8080/api/comment \
     -H "Content-Type: application/json" \
     -d '{"comment": "<script>document.location='http://evil.com'</script>"}'
# Response: 403 Forbidden
# WAF Log: [SECURITY] XSS attempt blocked - Pattern: <script>
```

### Testing Bot Protection

```bash
# Normal browser request (allowed)
curl -X GET http://localhost:8080/api/data \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
# Response: 200 OK

# Malicious bot request (blocked)
curl -X GET http://localhost:8080/api/data \
     -H "User-Agent: BadBot/1.0 (scraper; +http://badbot.com)"
# Response: 429 Too Many Requests or 403 Forbidden
# WAF Log: [SECURITY] Bot detected and blocked - Confidence: 0.95
```

### Rate Limiting Demonstration

```bash
# Create a simple rate limiting test script
cat > test_rate_limit.sh << 'EOF'
#!/bin/bash
echo "Testing rate limiting (10 requests in 5 seconds)..."
for i in {1..10}; do
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/test)
    echo "Request $i: HTTP $response"
    sleep 0.5
done
EOF

chmod +x test_rate_limit.sh
./test_rate_limit.sh

# Expected output:
# Request 1-8: HTTP 200 (allowed)
# Request 9-10: HTTP 429 (rate limited)
```

---

## 🔄 Reverse Proxy Examples

### Load Balancing Configuration

```yaml
# config.local.yaml - Load balancing setup
proxy:
  upstreams:
    - name: "backend"
      algorithm: "round_robin"  # or "least_connections", "ip_hash"
      servers:
        - host: "app1.internal"
          port: 3000
          weight: 1
        - host: "app2.internal"
          port: 3000
          weight: 2
        - host: "app3.internal"
          port: 3000
          weight: 1
      health_check:
        enabled: true
        path: "/health"
        interval: 30
        timeout: 5
```

### Testing Load Balancing

```bash
# Make multiple requests to see load balancing in action
for i in {1..6}; do
    echo "Request $i:"
    curl -s http://localhost:8080/api/server-info | jq '.server_id'
done

# Expected output (round-robin):
# Request 1: "app1.internal:3000"
# Request 2: "app2.internal:3000"
# Request 3: "app2.internal:3000"  # weight=2, gets more requests
# Request 4: "app3.internal:3000"
# Request 5: "app1.internal:3000"
# Request 6: "app2.internal:3000"
```

### Caching Demonstration

```bash
# First request (cache miss)
time curl -X GET http://localhost:8080/api/heavy-computation
# Response time: ~2.5s (cached for 5 minutes)

# Second request (cache hit)
time curl -X GET http://localhost:8080/api/heavy-computation
# Response time: ~0.05s (served from cache)
# Response headers: X-Cache-Status: HIT

# Check cache statistics
curl http://localhost:8081/api/cache/stats
# {
#   "hits": 1,
#   "misses": 1,
#   "hit_rate": 50.0,
#   "entries": 1,
#   "memory_usage": "2.1MB"
# }
```

---

## 🔒 SSL Management Examples

### Enable SSL/TLS Configuration

```yaml
# config.local.yaml - SSL configuration
ssl:
  enabled: true
  cert_file: "certs/server.crt"
  key_file: "certs/server.key"
  protocols: ["TLSv1.2", "TLSv1.3"]
  ciphers: ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"]
```

### Generate Self-Signed Certificate

```bash
# Create certificates directory
mkdir -p certs

# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
    -days 365 -nodes -subj "/C=US/ST=CA/L=SF/O=Deepskilling/CN=localhost"

# Start with SSL enabled
./target/release/waf-reverse-proxy --config config.local.yaml

# Test HTTPS endpoint
curl -k https://localhost:8443/health
# Response: 200 OK (SSL/TLS encrypted)
```

### Let's Encrypt Auto-Provisioning

```yaml
# config.local.yaml - Let's Encrypt configuration
ssl:
  enabled: true
  auto_provision: true
  acme:
    email: "admin@yourdomain.com"
    domains: ["yourdomain.com", "www.yourdomain.com"]
    directory_url: "https://acme-v02.api.letsencrypt.org/directory"
    challenge_type: "http-01"
  cert_storage: "/app/certs"
```

```bash
# Start with Let's Encrypt (requires domain ownership)
./target/release/waf-reverse-proxy --config config.production.yaml

# Check certificate status
curl http://localhost:8081/api/ssl/certificates
# {
#   "yourdomain.com": {
#     "status": "valid",
#     "expires": "2024-12-20T10:30:00Z",
#     "auto_renew": true
#   }
# }
```

---

## 📊 Monitoring & Metrics Examples

### Prometheus Metrics

```bash
# View available metrics
curl http://localhost:9090/metrics | head -20

# Key metrics to monitor:
# waf_requests_total{action="blocked"} - Total blocked requests
# waf_requests_total{action="allowed"} - Total allowed requests
# proxy_requests_duration_seconds - Request processing time
# proxy_upstream_health_status - Upstream server health
```

### Real-time Monitoring

```bash
# Monitor WAF events in real-time
tail -f /var/log/waf-proxy/security.log | jq '.'

# Example output:
# {
#   "timestamp": "2024-01-15T10:30:45Z",
#   "level": "WARN",
#   "event": "security_block",
#   "client_ip": "203.0.113.42",
#   "attack_type": "sql_injection",
#   "pattern": "' OR 1=1--",
#   "confidence": 0.95
# }
```

### Health Check Monitoring

```bash
# Check overall system health
curl http://localhost:8081/api/health | jq '.'

# {
#   "status": "healthy",
#   "timestamp": "2024-01-15T10:30:45Z",
#   "components": {
#     "waf_engine": {"status": "healthy", "requests_processed": 1542},
#     "reverse_proxy": {"status": "healthy", "upstreams_healthy": 3},
#     "ssl_manager": {"status": "healthy", "certificates_valid": 2},
#     "metrics_collector": {"status": "healthy", "metrics_exported": 45}
#   },
#   "performance": {
#     "memory_usage": "145MB",
#     "cpu_usage": "12%",
#     "request_rate": "150 req/s"
#   }
# }
```

---

## ⚙️ Configuration Examples

### Production Configuration

```yaml
# config.production.yaml
environment: production
debug: false

server:
  host: "0.0.0.0"
  port: 8080
  workers: 8
  max_connections: 10000
  keepalive_timeout: 75

waf:
  enabled: true
  mode: "block"
  
  # OWASP Protection
  owasp_protection:
    sql_injection_threshold: 0.8
    xss_threshold: 0.8
    rce_threshold: 0.9
    path_traversal_threshold: 0.8
    csrf_protection:
      enabled: true
      token_validation: true
  
  # Rate Limiting
  rate_limiting:
    global_limit:
      requests_per_second: 1000
      requests_per_minute: 10000
      burst: 100
    per_ip_limit:
      requests_per_second: 10
      requests_per_minute: 100
      burst: 20
  
  # Bot Protection
  bot_protection:
    enabled: true
    detection_threshold: 0.7
    challenge_threshold: 0.5
    blocked_patterns:
      - ".*[Bb]ot.*"
      - ".*[Ss]craper.*"
      - ".*[Cc]rawler.*"
  
  # Geo-blocking
  geo_blocking:
    enabled: true
    blocked_countries: ["CN", "RU", "KP"]
    allowed_countries: []
    geoip_database: "/app/geoip/GeoLite2-Country.mmdb"

proxy:
  upstreams:
    - name: "backend"
      algorithm: "least_connections"
      health_check:
        enabled: true
        path: "/health"
        interval: 30
        timeout: 5
        healthy_threshold: 2
        unhealthy_threshold: 3
      servers:
        - host: "app1.internal"
          port: 3000
          weight: 1
        - host: "app2.internal"
          port: 3000
          weight: 1
        - host: "app3.internal"
          port: 3000
          weight: 2
  
  # Caching
  caching:
    enabled: true
    backend: "redis"
    redis:
      host: "redis"
      port: 6379
      db: 0
      password: "your-redis-password"
    default_ttl: 300
    max_size: "1GB"

ssl:
  enabled: true
  auto_provision: true
  acme:
    email: "admin@yourdomain.com"
    domains: ["yourdomain.com", "www.yourdomain.com"]
  cert_storage: "/app/certs"

admin:
  enabled: true
  host: "0.0.0.0"
  port: 8081
  auth:
    enabled: true
    jwt_secret: "your-jwt-secret-change-this"
    token_expiry: 3600

metrics:
  enabled: true
  prometheus:
    enabled: true
    port: 9090
    path: "/metrics"
  
logging:
  level: "info"
  format: "json"
  outputs: ["stdout", "/var/log/waf-proxy/app.log"]
  security_log: "/var/log/waf-proxy/security.log"
```

### Custom WAF Rules

```yaml
# Custom rules configuration
waf:
  custom_rules:
    - name: "block_php_files"
      enabled: true
      priority: 50
      pattern: ".*\\.php$"
      action: "block"
      message: "PHP files are not allowed"
      
    - name: "suspicious_headers"
      enabled: true
      priority: 25
      conditions:
        - type: "header"
          name: "X-Forwarded-Proto" 
          contains: "javascript:"
      action: "block"
      message: "Suspicious header detected"
      
    - name: "api_rate_limit"
      enabled: true
      priority: 75
      conditions:
        - type: "path"
          starts_with: "/api/"
        - type: "rate_limit"
          limit: "100/minute"
      action: "challenge"
      message: "API rate limit exceeded"
```

---

## 🌐 Admin API Usage

### Authentication

```bash
# Get authentication token
curl -X POST http://localhost:8081/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "your-admin-password"}'

# Response:
# {
#   "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
#   "token_type": "bearer",
#   "expires_in": 3600
# }

# Use token for subsequent requests
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
```

### WAF Management

```bash
# Get WAF statistics
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8081/api/waf/stats | jq '.'

# {
#   "requests_processed": 15420,
#   "requests_blocked": 342,
#   "block_rate": 2.2,
#   "attack_types": {
#     "sql_injection": 156,
#     "xss": 89,
#     "bot_traffic": 97
#   },
#   "top_blocked_ips": [
#     {"ip": "203.0.113.42", "blocks": 45},
#     {"ip": "198.51.100.23", "blocks": 32}
#   ]
# }

# Enable/disable WAF rules
curl -X PUT -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     http://localhost:8081/api/waf/rules/sql_injection \
     -d '{"enabled": false}'

# Add custom WAF rule
curl -X POST -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     http://localhost:8081/api/waf/rules \
     -d '{
       "name": "block_admin_access",
       "pattern": "^/admin/.*",
       "action": "block",
       "priority": 10,
       "message": "Admin access blocked"
     }'
```

### Proxy Management

```bash
# Get upstream server status
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8081/api/proxy/upstreams | jq '.'

# {
#   "backend": {
#     "algorithm": "least_connections",
#     "servers": [
#       {
#         "host": "app1.internal",
#         "port": 3000,
#         "status": "healthy",
#         "active_connections": 12,
#         "total_requests": 5420
#       },
#       {
#         "host": "app2.internal", 
#         "port": 3000,
#         "status": "healthy",
#         "active_connections": 8,
#         "total_requests": 4892
#       }
#     ]
#   }
# }

# Temporarily disable an upstream server
curl -X PUT -H "Authorization: Bearer $TOKEN" \
     http://localhost:8081/api/proxy/upstreams/backend/servers/app1.internal:3000 \
     -d '{"enabled": false}'
```

---

## 🐳 Docker Deployment

### Quick Docker Setup

```bash
# Build Docker image
docker build -t waf-reverse-proxy:latest .

# Run with default configuration
docker run -d \
  --name waf-proxy \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 9090:9090 \
  waf-reverse-proxy:latest

# Run with custom configuration
docker run -d \
  --name waf-proxy \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 9090:9090 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/certs:/app/certs \
  -e WAF_CONFIG=/app/config/production.yaml \
  waf-reverse-proxy:latest
```

### Docker Compose with Full Monitoring Stack

```yaml
# docker-compose.yml
version: '3.8'

services:
  waf-proxy:
    build: .
    ports:
      - "8080:8080"
      - "8081:8081"
      - "9090:9090"
    volumes:
      - ./config:/app/config
      - ./certs:/app/certs
      - ./logs:/var/log/waf-proxy
    environment:
      - WAF_CONFIG=/app/config/production.yaml
      - RUST_LOG=info
    depends_on:
      - redis
      - prometheus
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9091:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./monitoring/grafana/datasources:/etc/grafana/provisioning/datasources
    restart: unless-stopped

volumes:
  redis-data:
  prometheus-data:
  grafana-data:
```

```bash
# Deploy the full stack
docker-compose up -d

# View logs
docker-compose logs -f waf-proxy

# Scale WAF instances
docker-compose up -d --scale waf-proxy=3

# Access services:
# - WAF Proxy: http://localhost:8080
# - Admin API: http://localhost:8081
# - Grafana: http://localhost:3000 (admin/admin123)
# - Prometheus: http://localhost:9091
```

---

## 🔧 Advanced Configuration

### Performance Tuning

```yaml
# High-performance configuration
server:
  workers: 16  # 2x CPU cores
  max_connections: 50000
  keepalive_timeout: 300
  request_timeout: 60
  
  # Connection pooling
  upstream_pool:
    max_connections_per_upstream: 100
    connection_timeout: 5
    idle_timeout: 300

# Memory optimization
cache:
  memory_limit: "2GB"
  eviction_policy: "lru"
  
# Thread pool tuning
async_runtime:
  worker_threads: 16
  blocking_threads: 32
  thread_stack_size: "2MB"
```

### Load Testing

```bash
# Install Apache Bench for load testing
# Ubuntu/Debian: sudo apt install apache2-utils
# macOS: brew install httpie

# Basic load test
ab -n 10000 -c 100 http://localhost:8080/

# Results interpretation:
# - Requests per second: Should handle 5000+ req/s
# - Mean response time: Should be <20ms
# - Failed requests: Should be 0

# Stress test with WAF enabled
ab -n 5000 -c 50 -T 'application/json' -p attack_payload.json http://localhost:8080/api/test

# Create attack payload for testing
echo '{"comment": "<script>alert(1)</script>"}' > attack_payload.json
```

### Security Hardening

```yaml
# Maximum security configuration
waf:
  mode: "block"  # No learning mode in production
  
  # Strict thresholds
  owasp_protection:
    sql_injection_threshold: 0.6  # More sensitive
    xss_threshold: 0.6
    rce_threshold: 0.7
    
  # Aggressive rate limiting
  rate_limiting:
    global_limit:
      requests_per_second: 500
      burst: 50
    per_ip_limit:
      requests_per_second: 5
      burst: 10
      
  # Comprehensive geo-blocking
  geo_blocking:
    enabled: true
    blocked_countries: ["CN", "RU", "KP", "IR"]
    whitelist_ips: ["203.0.113.0/24"]  # Your office IPs
    
  # Security headers
  security_headers:
    x_frame_options: "DENY"
    x_content_type_options: "nosniff"
    x_xss_protection: "1; mode=block"
    strict_transport_security: "max-age=31536000; includeSubDomains"
    content_security_policy: "default-src 'self'"
```

## 🎯 Next Steps

1. **Production Deployment**: Use the Docker Compose setup with proper SSL certificates
2. **Monitoring Setup**: Configure Prometheus alerts and Grafana dashboards
3. **Security Tuning**: Customize WAF rules for your specific applications
4. **Performance Optimization**: Adjust worker counts and connection limits
5. **Integration**: Connect with your existing SIEM and monitoring systems

## 📚 Additional Resources

- **Full Configuration Reference**: See `config/config.yaml` for all options
- **API Documentation**: Visit `/api/docs` when admin API is running
- **Rust Documentation**: `cargo doc --open` for code documentation
- **Security Best Practices**: Check `docs/SECURITY.md`
- **Troubleshooting Guide**: See `docs/TROUBLESHOOTING.md`

---

**🦀 Ready to deploy enterprise-grade Rust-powered web application protection!**

For support and advanced configuration, refer to the complete documentation or reach out to the Deepskilling team.
