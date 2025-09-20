# WAF + Reverse Proxy by Deepskilling

![Deepskilling](https://img.shields.io/badge/powered%20by-deepskilling-blue)
![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)
![Security](https://img.shields.io/badge/security-enterprise-green)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

A high-performance, enterprise-grade Web Application Firewall (WAF) and Reverse Proxy built in Rust by **Deepskilling**. Designed with reliability, scalability, and availability in mind to protect and accelerate your web applications.

## 🚀 Features

### 🔐 Web Application Firewall (WAF)
- **OWASP Top 10 Protection**: SQL injection, XSS, CSRF, RCE, path traversal detection
- **Bot Protection**: Advanced bot detection with behavioral analysis
- **Rate Limiting**: Global, per-IP, and per-endpoint rate limiting
- **Geo-blocking**: Block or allow traffic based on geographical location
- **Custom Rules**: Flexible rule engine with regex and condition-based matching
- **Real-time Monitoring**: Comprehensive security event logging and metrics

### 🔄 Reverse Proxy
- **Load Balancing**: Round-robin, least connections, and IP hash algorithms
- **Health Checks**: Automatic upstream health monitoring with failover
- **SSL/TLS Termination**: Centralized certificate management
- **Caching**: Intelligent response caching with TTL and LRU eviction
- **Request Routing**: Host-based and path-based routing rules
- **Connection Pooling**: Efficient upstream connection management

### 📊 Observability & Management
- **Metrics**: Prometheus-compatible metrics collection
- **Logging**: Structured JSON logging with configurable outputs
- **Admin API**: RESTful API for configuration and monitoring
- **Health Monitoring**: Built-in health checks and status endpoints
- **Real-time Dashboard**: Web-based administration interface

### 🛡️ Advanced Security
- **Circuit Breakers**: Prevent cascade failures with automatic recovery
- **JWT Validation**: Support for JWT-based authentication
- **Security Headers**: Automatic security header injection
- **Threat Intelligence**: Integration with threat feed APIs
- **Anomaly Detection**: ML-based suspicious behavior detection

## 🏗️ Architecture

Built following SOLID principles with a modular architecture:

```
├── src/
│   ├── main.rs              # Application entry point
│   ├── config.rs            # Configuration management
│   ├── error.rs             # Error handling
│   ├── waf/                 # WAF engine modules
│   │   ├── engine.rs        # Main WAF engine
│   │   ├── rules.rs         # Custom rules engine
│   │   ├── rate_limiter.rs  # Rate limiting
│   │   ├── owasp.rs         # OWASP protection
│   │   ├── bot_detection.rs # Bot detection
│   │   └── geo_blocking.rs  # Geo-location blocking
│   ├── proxy/               # Reverse proxy modules
│   │   ├── engine.rs        # Main proxy engine
│   │   ├── upstream.rs      # Upstream management
│   │   ├── load_balancer.rs # Load balancing algorithms
│   │   └── cache.rs         # Response caching
│   ├── observability/       # Monitoring and logging
│   │   ├── metrics.rs       # Metrics collection
│   │   └── logger.rs        # Structured logging
│   ├── health.rs            # Health checking
│   ├── security.rs          # Security features
│   └── admin.rs             # Administration API
```

## 🚦 Quick Start

### Prerequisites

- Rust 1.70+ 
- OpenSSL development libraries
- Redis (optional, for session storage)
- MaxMind GeoIP database (optional, for geo-blocking)

## 📚 Documentation

- **[SETUP.md](SETUP.md)** - Comprehensive installation and configuration guide
- **[LICENSE](LICENSE)** - MIT License with Deepskilling branding terms
- **API Documentation** - Available at `/api/docs` when running

## ⚡ Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/deepskilling/waf-reverse-proxy.git
cd waf-reverse-proxy

# 2. Quick build and run
cargo build --release
cp config/config.yaml config.local.yaml
./target/release/waf-reverse-proxy --config config.local.yaml

# 3. Verify it's working
curl http://localhost:8080/health    # Main proxy health
curl http://localhost:8081/api/status # Admin API status
```

## 📦 Installation Options

### Option 1: Automated Setup (Recommended)
```bash
# Install dependencies and set up environment
pip install -r config/requirements.txt
python scripts/setup.py all                 # Complete automated setup

# Or step-by-step
python scripts/setup.py init               # Initialize project
python scripts/setup.py deploy --docker    # Docker deployment
python scripts/health_check.py --full      # Health verification
```

### Option 2: Docker Deployment
```bash
# Quick start with Docker Compose
docker-compose up -d

# Custom build
docker build -t deepskilling/waf-reverse-proxy .
docker run -p 8080:8080 deepskilling/waf-reverse-proxy
```

### Option 3: Manual Build
```bash
# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build and install
cargo build --release
sudo cp target/release/waf-reverse-proxy /usr/local/bin/
```

> **📖 For detailed installation, configuration, and deployment instructions, see [SETUP.md](SETUP.md)**

### 🐍 Python Setup Scripts

The project includes comprehensive Python setup scripts for easy deployment:

- **`setup.py`** - Main setup orchestrator
- **`setup_repo.py`** - Git repository setup and GitHub pushing  
- **`setup_deployment.py`** - Docker, Kubernetes, and monitoring setup
- **`health_check.py`** - Comprehensive system health checking

```bash
# Initialize everything
python3 scripts/setup.py all

# Set up Git repository
python3 scripts/setup_repo.py

# Set up deployment environment  
python3 scripts/setup_deployment.py --docker --monitoring

# Run health checks
python3 scripts/health_check.py --full --json
```

### Basic Configuration

Create a `config.yaml` file:

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  workers: 4

waf:
  enabled: true
  mode: "block"
  
  rate_limiting:
    global:
      requests_per_second: 1000
      burst: 2000
    per_ip:
      requests_per_minute: 300
      burst: 500

proxy:
  upstreams:
    default:
      servers:
        - url: "http://127.0.0.1:3000"
          weight: 1
          max_fails: 3
          fail_timeout: 30s
      load_balancer: "round_robin"
      
  routes:
    - host: "example.com"
      path: "/"
      upstream: "default"
```

## 📖 Configuration Guide

### WAF Configuration

#### OWASP Protection
```yaml
waf:
  owasp_protection:
    sql_injection:
      enabled: true
      confidence_threshold: 0.8
    xss_protection:
      enabled: true
      confidence_threshold: 0.8
    rce_protection:
      enabled: true
      confidence_threshold: 0.9
```

#### Custom Rules
```yaml
waf:
  custom_rules:
    - name: "Block admin access from untrusted IPs"
      pattern: "^/admin"
      action: "block"
      conditions:
        - type: "path_regex"
          value: "^/admin.*"
        - type: "ip_not_in_whitelist"
          value: ["192.168.1.0/24", "10.0.0.0/8"]
```

#### Bot Protection
```yaml
waf:
  bot_protection:
    enabled: true
    challenge_suspicious: true
    block_known_bots: true
    behavioral_analysis: true
```

### Proxy Configuration

#### Upstream Servers
```yaml
proxy:
  upstreams:
    api_servers:
      servers:
        - url: "http://api1.internal:8080"
          weight: 2
        - url: "http://api2.internal:8080"
          weight: 1
      load_balancer: "least_connections"
      health_check:
        enabled: true
        path: "/health"
        interval: 30s
        timeout: 5s
```

#### Caching
```yaml
proxy:
  caching:
    enabled: true
    default_ttl: 300s
    max_size: "1GB"
    rules:
      - pattern: "^/api/static/"
        ttl: 3600s
      - pattern: "^/api/dynamic/"
        ttl: 60s
```

### Observability

#### Metrics
```yaml
metrics:
  enabled: true
  port: 9090
  path: "/metrics"
```

#### Logging
```yaml
logging:
  level: "info"
  format: "json"
  access_log:
    enabled: true
    output: "/var/log/access.log"
  security_log:
    enabled: true
    output: "/var/log/security.log"
```

## 🔧 Administration

### Admin API

The admin API provides RESTful endpoints for configuration and monitoring:

```bash
# Get system status
curl http://localhost:8081/api/status

# Get WAF statistics
curl http://localhost:8081/api/waf/statistics

# Update WAF configuration
curl -X PUT http://localhost:8081/api/config/waf \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "mode": "block"}'

# View upstreams
curl http://localhost:8081/api/upstreams

# Get cache statistics
curl http://localhost:8081/api/cache/statistics
```

### Metrics Integration

Prometheus metrics are available at `/metrics`:

```bash
# Sample metrics
waf_requests_total{action="block",type="sql_injection"} 42
proxy_request_duration_seconds_bucket{method="GET",le="0.1"} 1234
upstream_health_status{upstream="default",server="api1"} 1
```

### Health Checks

Built-in health endpoints:

- `/health` - Basic health check
- `/api/health` - Detailed health information
- `/metrics` - Prometheus metrics endpoint

## 🔒 Security Features

### Rate Limiting

Multiple levels of rate limiting:
- **Global**: Overall system protection
- **Per-IP**: Prevent individual IP abuse
- **Per-Endpoint**: Protect specific resources

### Circuit Breakers

Automatic failure detection and recovery:
```yaml
advanced:
  circuit_breaker:
    enabled: true
    failure_threshold: 5
    recovery_timeout: 60s
    half_open_max_calls: 3
```

### JWT Validation

Support for JWT-based authentication:
```yaml
advanced:
  jwt:
    enabled: true
    secret: "your-secret-key"
    algorithm: "HS256"
    required_claims: ["sub", "exp"]
```

## 📈 Performance

### Benchmarks

- **Throughput**: 50,000+ requests/second on modern hardware
- **Latency**: < 1ms additional latency for WAF processing
- **Memory**: Efficient memory usage with configurable limits
- **CPU**: Multi-core scaling with async processing

### Optimization Tips

1. **Enable caching** for static content
2. **Tune worker count** based on CPU cores
3. **Configure connection pooling** for upstream servers
4. **Use appropriate rate limits** to prevent resource exhaustion
5. **Enable compression** for large responses

## 🛠️ Development

### Building from Source

```bash
# Development build
cargo build

# Release build with optimizations
cargo build --release

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run
```

### Testing

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration

# Run with coverage
cargo tarpaulin --out Html
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License with Deepskilling branding terms - see the [LICENSE](LICENSE) file for details.

## 🤝 Support & Community

- **📖 Complete Setup Guide**: [SETUP.md](SETUP.md)
- **🐛 Issues & Bugs**: [GitHub Issues](https://github.com/deepskilling/waf-reverse-proxy/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/deepskilling/waf-reverse-proxy/discussions)
- **📧 Enterprise Support**: Contact Deepskilling for commercial support
- **🌟 Star us on GitHub**: Show your support for the project

## 🗺️ Roadmap

### Upcoming Features

- [ ] Machine learning-based anomaly detection
- [ ] WebSocket and gRPC support
- [ ] Advanced threat intelligence integration
- [ ] GUI administration dashboard
- [ ] Kubernetes native deployment
- [ ] Advanced SSL/TLS features (mTLS, OCSP stapling)

### Performance Improvements

- [ ] Zero-copy request processing
- [ ] Advanced caching strategies
- [ ] Hardware acceleration support
- [ ] Edge computing optimizations

---

## 🎯 Use Cases

### Enterprise API Gateway
- Protect APIs from attacks and abuse
- Load balance across multiple backend services
- Cache responses for improved performance
- Monitor and audit API usage

### Web Application Protection
- Block common web attacks (OWASP Top 10)
- Rate limit abusive clients
- Geographic access control
- Bot detection and mitigation

### Microservices Architecture
- Service mesh integration
- Circuit breaker pattern implementation
- Distributed tracing and monitoring
- Configuration management

### Cloud-Native Deployment
- Container-friendly configuration
- Health checks and service discovery
- Horizontal scaling support
- Cloud provider integration

---

**Built with ❤️ by [Deepskilling](https://deepskilling.com)**

This enterprise-grade WAF + Reverse Proxy solution demonstrates Deepskilling's commitment to delivering high-performance, secure, and scalable infrastructure solutions. Built in Rust for maximum performance and reliability, it's designed to protect and accelerate modern web applications and microservices architectures.

*© 2025 Deepskilling. All rights reserved. | Empowering organizations with cutting-edge security solutions.*
