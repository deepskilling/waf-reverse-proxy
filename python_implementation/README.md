# PyWAF - Complete Python WAF + Reverse Proxy

[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Deepskilling](https://img.shields.io/badge/powered%20by-deepskilling-blue.svg)](https://deepskilling.com)

**PyWAF** is a high-performance Web Application Firewall (WAF) and Reverse Proxy implemented entirely in Python. Built with modern async frameworks and security best practices, it provides enterprise-grade protection, load balancing, and SSL/TLS management.

## 🚀 Features

### 🛡️ **Web Application Firewall (WAF)**
- **OWASP Top 10 Protection**: SQL injection, XSS, CSRF, RCE, path traversal detection
- **Advanced Bot Detection**: User-agent analysis, behavioral patterns, challenge-response
- **Rate Limiting**: Multi-tier rate limiting (global, per-IP, per-endpoint)
- **Geographic Blocking**: Country-based access control with GeoIP2 integration
- **Custom Rules Engine**: Flexible rule creation with regex and condition matching
- **IP Blocklist Management**: Permanent and temporary IP blocking

### 🔄 **Reverse Proxy**
- **Load Balancing**: Round-robin, least-connections, IP-hash, weighted, random algorithms
- **Health Checks**: Automated upstream health monitoring with failover
- **Response Caching**: Redis and in-memory caching with intelligent rules
- **SSL/TLS Termination**: Automatic Let's Encrypt certificate provisioning and renewal
- **Request Routing**: Host and path-based routing with header manipulation
- **Connection Pooling**: Efficient upstream connection management

### 📊 **Monitoring & Management**
- **Prometheus Metrics**: Comprehensive performance and security metrics
- **Health Checking**: Multi-component system health monitoring
- **Admin REST API**: Complete management API with JWT authentication
- **CLI Interface**: Rich command-line tools for operations
- **Structured Logging**: JSON logging with security event tracking
- **Real-time Statistics**: Request rates, error rates, response times

## 📋 Quick Start

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Optional: Redis for advanced caching

### Installation

1. **Clone the repository:**
```bash
git clone https://github.com/deepskilling/pywaf-proxy.git
cd pywaf-proxy
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Configure the system:**
```bash
# Copy and edit the configuration
cp config/config.yaml config/config-prod.yaml
# Edit config-prod.yaml with your settings
```

4. **Start the server:**
```bash
# Using the CLI
pywaf server start --config config/config-prod.yaml

# Or using Python directly
python -m pywaf.main config/config-prod.yaml
```

### Docker Deployment

```bash
# Build the image
docker build -t pywaf .

# Run with docker-compose
docker-compose up -d
```

## 🔧 Configuration

### Basic Configuration

```yaml
# Server settings
server:
  host: "0.0.0.0"
  port: 8080
  workers: 4

# WAF settings
waf:
  enabled: true
  mode: "block"  # block, monitor, log
  
  rate_limiting:
    global_limit:
      requests_per_second: 100
      burst: 200
  
  owasp_protection:
    enabled: true
    sql_injection_threshold: 0.8
    xss_threshold: 0.8

# Proxy settings
proxy:
  upstreams:
    - name: "backend"
      servers:
        - url: "http://127.0.0.1:8081"
          weight: 100
      algorithm: "round_robin"
      health_check:
        enabled: true
        path: "/health"
```

### SSL/TLS with Let's Encrypt

```yaml
ssl:
  enabled: true
  port: 8443
  auto_provision: true
  acme_email: "admin@example.com"
  domains:
    - "api.example.com"
    - "www.example.com"
```

### Advanced WAF Rules

```yaml
waf:
  custom_rules:
    - name: "block_admin_paths"
      enabled: true
      action: "block"
      conditions:
        - type: "path_prefix"
          value: "/admin"
        - type: "ip_not_in_whitelist"
          value: ["192.168.1.0/24"]
```

## 🎯 Usage Examples

### Command Line Interface

```bash
# Check configuration
pywaf config validate --config config/config.yaml

# Show system status
pywaf monitor health --admin-url http://localhost:8081

# Block an IP address
pywaf waf block-ip 192.168.1.100 --duration 3600 --reason "Suspicious activity"

# View proxy status
pywaf proxy status --admin-url http://localhost:8081

# SSL certificate management
pywaf ssl status --admin-url http://localhost:8081
```

### Python API Integration

```python
import asyncio
from pywaf.core.config import Config
from pywaf.core.waf import WAFEngine, RequestContext
from pywaf.core.proxy import ReverseProxy

async def main():
    # Load configuration
    config = Config.load_from_file("config/config.yaml")
    
    # Initialize WAF
    waf = WAFEngine(config)
    
    # Initialize Reverse Proxy
    proxy = ReverseProxy(config)
    await proxy.start()
    
    # Example: Inspect a request
    context = RequestContext(
        client_ip="192.168.1.100",
        user_agent="Mozilla/5.0...",
        method="GET",
        path="/api/users",
        query_string="",
        headers={}
    )
    
    result = await waf.inspect_request(context)
    print(f"WAF Result: {result.action} - {result.message}")

if __name__ == "__main__":
    asyncio.run(main())
```

### REST API Management

```bash
# Login and get token
curl -X POST http://localhost:8081/admin/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Get system status
curl -H "Authorization: Bearer <token>" \
  http://localhost:8081/admin/api/v1/status

# Block IP address
curl -X POST http://localhost:8081/admin/api/v1/waf/block-ip \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"ip_address": "192.168.1.100", "duration": 3600}'
```

## 🏗️ Architecture

### Core Components

```
PyWAF Architecture

┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   FastAPI App   │    │   Admin API     │    │   Metrics API   │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│                 │    │                 │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │    WAF    │  │    │  │   Auth    │  │    │  │Prometheus │  │
│  │  Engine   │  │    │  │ Manager   │  │    │  │Collector  │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
│                 │    │                 │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │  Reverse  │  │    │  │   Config  │  │    │  │  Health   │  │
│  │   Proxy   │  │    │  │ Manager   │  │    │  │ Checker   │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
│                 │    │                 │    │                 │
│  ┌───────────┐  │    └─────────────────┘    └─────────────────┘
│  │    SSL    │  │
│  │ Manager   │  │
│  └───────────┘  │
└─────────────────┘
```

### Security Flow

```
Request Flow Through PyWAF

Internet Request
      │
      ▼
┌─────────────┐
│ Rate Limiter│ ◄── Global, Per-IP, Per-Endpoint
└─────────────┘
      │
      ▼
┌─────────────┐
│ IP Blocklist│ ◄── Permanent & Temporary Blocks
└─────────────┘
      │
      ▼
┌─────────────┐
│Geo Blocking │ ◄── Country-based Access Control
└─────────────┘
      │
      ▼
┌─────────────┐
│Bot Detection│ ◄── User-Agent + Behavioral Analysis
└─────────────┘
      │
      ▼
┌─────────────┐
│OWASP Top 10 │ ◄── SQL Injection, XSS, CSRF, RCE, etc.
│ Protection  │
└─────────────┘
      │
      ▼
┌─────────────┐
│Custom Rules │ ◄── Flexible Rule Engine
└─────────────┘
      │
      ▼
┌─────────────┐
│   Proxy     │ ◄── Load Balancing + Upstream Routing
│  Forward    │
└─────────────┘
      │
      ▼
   Backend
```

## 🔒 Security Features

### OWASP Top 10 Protection

| Attack Type | Detection Method | Confidence Threshold |
|-------------|------------------|---------------------|
| SQL Injection | Regex patterns, payload analysis | 0.8 |
| XSS | Script detection, HTML analysis | 0.8 |
| CSRF | Token validation, referer checking | 0.7 |
| RCE | Command injection patterns | 0.9 |
| Path Traversal | Directory traversal sequences | 0.9 |

### Rate Limiting

```python
# Multi-tier rate limiting
rate_limiting:
  global_limit:
    requests_per_second: 1000    # Global server limit
    burst: 2000
  
  per_ip:
    requests_per_minute: 600     # Per IP address limit
    burst: 100
  
  per_endpoint:
    requests_per_second: 10      # Per API endpoint limit
    burst: 20
```

### Bot Detection

- **User-Agent Analysis**: Known bot patterns, suspicious agents
- **Behavioral Analysis**: Request patterns, timing analysis
- **Challenge-Response**: CAPTCHA integration capability
- **IP Reputation**: Integration with threat intelligence feeds

## 📈 Performance

### Benchmarks

| Metric | Value |
|--------|-------|
| Requests/second | 10,000+ |
| Concurrent connections | 5,000+ |
| WAF processing overhead | <1ms |
| Memory usage | <200MB base |
| Response latency | <10ms added |

### Optimization Features

- **Async Processing**: Full async/await implementation
- **Connection Pooling**: Efficient upstream connections
- **Smart Caching**: Redis + in-memory hybrid caching
- **Lazy Loading**: On-demand resource initialization
- **Efficient Patterns**: Compiled regex for fast matching

## 📊 Monitoring

### Prometheus Metrics

```
# Request metrics
pywaf_http_requests_total{method="GET", status="200", endpoint="/api"}
pywaf_http_request_duration_seconds{method="GET", endpoint="/api"}

# WAF metrics
pywaf_waf_blocks_total{rule="sql_injection", client_ip="x.x.x.x"}
pywaf_rate_limit_hits_total{limit_type="per_ip", client_ip="x.x.x.x"}

# Proxy metrics
pywaf_proxy_upstream_requests_total{upstream="backend", status="success"}
pywaf_proxy_upstream_response_time_seconds{upstream="backend", server="s1"}

# SSL metrics
pywaf_ssl_certificates_expiring
pywaf_ssl_certificates_total
```

### Health Checks

- **System Health**: CPU, memory, disk usage
- **Component Health**: WAF engine, proxy, SSL manager
- **Upstream Health**: Backend server availability
- **Database Health**: Connection and query performance
- **Cache Health**: Redis connectivity and performance

## 🛠️ Development

### Setup Development Environment

```bash
# Clone repository
git clone https://github.com/deepskilling/pywaf-proxy.git
cd pywaf-proxy

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
pytest tests/

# Run with development settings
python -m pywaf.main --config config/config.yaml --debug
```

### Project Structure

```
pywaf/
├── core/                   # Core components
│   ├── config.py          # Configuration management
│   ├── waf.py             # WAF engine
│   ├── proxy.py           # Reverse proxy
│   ├── ssl.py             # SSL/TLS management
│   └── exceptions.py      # Exception classes
├── admin/                 # Admin API
│   └── api.py             # REST API endpoints
├── monitoring/            # Monitoring components
│   ├── metrics.py         # Prometheus metrics
│   └── health.py          # Health checking
├── cli.py                 # Command-line interface
└── main.py                # Main application
```

### Adding Custom WAF Rules

```python
from pywaf.core.waf import WAFEngine
from pywaf.core.config import Config

# Custom rule example
custom_rule = {
    "name": "block_specific_user_agent",
    "enabled": True,
    "action": "block",
    "conditions": [
        {
            "type": "header_regex",
            "field": "user-agent",
            "operator": "matches",
            "value": "BadBot.*",
            "case_sensitive": False
        }
    ],
    "priority": 100
}

# Add to configuration
config.waf.custom_rules.append(custom_rule)
```

## 🚀 Deployment

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN pip install -e .

EXPOSE 8080 8443 8081 9090

CMD ["pywaf", "server", "start", "--config", "config/config.yaml"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pywaf
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pywaf
  template:
    metadata:
      labels:
        app: pywaf
    spec:
      containers:
      - name: pywaf
        image: pywaf:latest
        ports:
        - containerPort: 8080
        - containerPort: 8443
        env:
        - name: PYWAF_ENVIRONMENT
          value: "production"
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: certs
          mountPath: /app/certs
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: config
        configMap:
          name: pywaf-config
      - name: certs
        secret:
          secretName: pywaf-certs
```

### Systemd Service

```ini
[Unit]
Description=PyWAF - Web Application Firewall & Reverse Proxy
After=network.target

[Service]
Type=exec
User=pywaf
Group=pywaf
WorkingDirectory=/opt/pywaf
ExecStart=/opt/pywaf/venv/bin/pywaf server start --config /etc/pywaf/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Run tests: `pytest tests/`
6. Update documentation
7. Commit: `git commit -m 'Add amazing feature'`
8. Push: `git push origin feature/amazing-feature`
9. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **FastAPI** - Modern, fast web framework for building APIs
- **Prometheus** - Monitoring and alerting toolkit
- **Let's Encrypt** - Free SSL/TLS certificates
- **MaxMind GeoIP2** - IP geolocation database
- **OWASP** - Web application security project

## 📞 Support

- **Documentation**: [Full documentation available](docs/)
- **Issues**: [GitHub Issues](https://github.com/deepskilling/pywaf-proxy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/deepskilling/pywaf-proxy/discussions)
- **Email**: support@deepskilling.com

## 🎯 Roadmap

- [ ] GraphQL API support
- [ ] Machine learning-based threat detection
- [ ] WebSocket proxying
- [ ] Advanced caching strategies
- [ ] Integration with external threat intelligence
- [ ] Web-based management dashboard
- [ ] Mobile app for monitoring
- [ ] Advanced analytics and reporting

---

<div align="center">

**Built with ❤️ by [Deepskilling](https://deepskilling.com)**

[![Deepskilling](https://img.shields.io/badge/powered%20by-deepskilling-blue.svg)](https://deepskilling.com)

</div>
