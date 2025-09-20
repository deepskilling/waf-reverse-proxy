# WAF + Reverse Proxy Setup Guide

![Deepskilling](https://img.shields.io/badge/powered%20by-deepskilling-blue)
![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=flat&logo=rust&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white)
![Kubernetes](https://img.shields.io/badge/kubernetes-%23326ce5.svg?style=flat&logo=kubernetes&logoColor=white)

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Installation Methods](#installation-methods)
- [Configuration](#configuration)
- [Deployment Options](#deployment-options)
- [Monitoring Setup](#monitoring-setup)
- [Security Configuration](#security-configuration)
- [Troubleshooting](#troubleshooting)
- [Performance Tuning](#performance-tuning)

## 🔧 Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 2 cores | 4+ cores |
| **RAM** | 2 GB | 8+ GB |
| **Storage** | 1 GB | 10+ GB |
| **OS** | Linux/macOS/Windows | Linux (Ubuntu 20.04+) |

### Software Dependencies

#### Required
- **Rust** 1.70+ (`rustc --version`)
- **Git** 2.30+ (`git --version`)

#### Optional (for specific features)
- **Docker** 20.10+ & **Docker Compose** 2.0+
- **Kubernetes** 1.20+ (for K8s deployment)
- **Python** 3.8+ (for automation scripts)
- **Redis** 6.0+ (for advanced caching)
- **PostgreSQL** 13+ (for persistent storage)

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/deepskilling/waf-reverse-proxy.git
cd waf-reverse-proxy
```

### 2. Quick Build & Run
```bash
# Build the project
cargo build --release

# Copy example configuration
cp config.yaml config.local.yaml

# Run with default settings
./target/release/waf-reverse-proxy --config config.local.yaml
```

### 3. Verify Installation
```bash
# Check WAF status
curl http://localhost:8080/health

# Check admin API
curl http://localhost:8081/api/status

# Check metrics
curl http://localhost:9090/metrics
```

## 📦 Installation Methods

### Method 1: From Source (Recommended)

```bash
# 1. Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 2. Clone and build
git clone https://github.com/deepskilling/waf-reverse-proxy.git
cd waf-reverse-proxy
cargo build --release

# 3. Install system-wide (optional)
sudo cp target/release/waf-reverse-proxy /usr/local/bin/
sudo mkdir -p /etc/waf-proxy
sudo cp config.yaml /etc/waf-proxy/
```

### Method 2: Using Docker

```bash
# Quick start with Docker Compose
docker-compose up -d

# Or build custom image
docker build -t deepskilling/waf-reverse-proxy .
docker run -p 8080:8080 -p 8081:8081 deepskilling/waf-reverse-proxy
```

### Method 3: Automated Setup

```bash
# Install Python dependencies
pip install -r requirements.txt

# Run automated setup
python setup.py all

# For repository setup only
python setup_repo.py
```

## ⚙️ Configuration

### Basic Configuration

Edit `config.yaml` or create `config.local.yaml`:

```yaml
# Server Configuration
server:
  host: "0.0.0.0"
  port: 8080
  workers: 4
  max_connections: 1000

# WAF Configuration
waf:
  enabled: true
  owasp_protection:
    enabled: true
    sql_injection: true
    xss_protection: true
    rce_protection: true
  
  rate_limiting:
    enabled: true
    global_limit: 1000  # requests per second
    per_ip_limit: 100   # requests per second per IP

# Proxy Configuration
proxy:
  upstreams:
    backend:
      servers:
        - url: "http://localhost:3000"
          weight: 1
          max_fails: 3
      load_balancer: "round_robin"
```

### Advanced Configuration

#### SSL/TLS Configuration
```yaml
server:
  tls:
    enabled: true
    cert_path: "/path/to/cert.pem"
    key_path: "/path/to/key.pem"
    protocols: ["TLSv1.2", "TLSv1.3"]
```

#### Logging Configuration
```yaml
logging:
  level: "info"
  access_log: "/var/log/waf-proxy/access.log"
  error_log: "/var/log/waf-proxy/error.log"
  format: "json"
```

#### Caching Configuration
```yaml
caching:
  enabled: true
  type: "redis"
  redis:
    host: "localhost"
    port: 6379
    db: 0
  ttl: 300  # seconds
```

## 🚢 Deployment Options

### Docker Deployment

#### Development
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f waf-proxy

# Scale services
docker-compose up -d --scale waf-proxy=3
```

#### Production
```bash
# Production compose file
docker-compose -f docker-compose.prod.yml up -d

# With custom configuration
docker run -d \
  --name waf-proxy \
  -p 8080:8080 \
  -p 8081:8081 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  deepskilling/waf-reverse-proxy
```

### Kubernetes Deployment

```bash
# Create namespace
kubectl create namespace waf-proxy

# Deploy with Helm (recommended)
helm install waf-proxy ./k8s/helm-chart

# Or apply manifests directly
kubectl apply -f k8s/manifests/
```

### Systemd Service (Linux)

```bash
# Create service file
sudo tee /etc/systemd/system/waf-proxy.service > /dev/null <<EOF
[Unit]
Description=WAF + Reverse Proxy by Deepskilling
After=network.target

[Service]
Type=simple
User=waf-proxy
Group=waf-proxy
ExecStart=/usr/local/bin/waf-reverse-proxy --config /etc/waf-proxy/config.yaml
Restart=always
RestartSec=5
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable waf-proxy
sudo systemctl start waf-proxy
```

## 📊 Monitoring Setup

### Prometheus + Grafana

#### 1. Start Monitoring Stack
```bash
# Using Docker Compose
docker-compose up -d prometheus grafana

# Verify services
curl http://localhost:9090/targets  # Prometheus
curl http://localhost:3000          # Grafana (admin/admin)
```

#### 2. Configure Dashboards

**Grafana Login**: `admin/admin`

Import provided dashboards:
- **WAF Overview**: `grafana/dashboards/waf-overview.json`
- **Proxy Performance**: `grafana/dashboards/proxy-performance.json`
- **Security Dashboard**: `grafana/dashboards/security.json`

#### 3. Set Up Alerts
```yaml
# prometheus/alerts.yml
groups:
  - name: waf-proxy-alerts
    rules:
      - alert: HighErrorRate
        expr: rate(proxy_requests_failed[5m]) > 0.1
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
```

### Health Checks

```bash
# Run comprehensive health check
python health_check.py --full

# Automated monitoring
python health_check.py --monitor --interval 60
```

## 🔒 Security Configuration

### SSL/TLS Setup

#### 1. Generate Self-Signed Certificates (Development)
```bash
# Create certificates directory
mkdir -p ssl

# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes -keyout ssl/key.pem -out ssl/cert.pem -days 365 -subj "/CN=localhost"
```

#### 2. Let's Encrypt (Production)
```bash
# Install certbot
sudo apt-get install certbot

# Get certificate
sudo certbot certonly --standalone -d your-domain.com

# Update config.yaml
server:
  tls:
    enabled: true
    cert_path: "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
    key_path: "/etc/letsencrypt/live/your-domain.com/privkey.pem"
```

### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 8080/tcp  # WAF/Proxy port
sudo ufw allow 8081/tcp  # Admin API
sudo ufw allow 9090/tcp  # Metrics (restrict to monitoring network)

# iptables example
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8081 -s 10.0.0.0/8 -j ACCEPT  # Admin API - internal only
```

### Environment Variables

Create `.env` for sensitive configuration:
```bash
# .env (keep this file secure and never commit to git)
DATABASE_URL=postgresql://user:pass@localhost/wafdb
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=your-super-secret-jwt-key
ADMIN_API_KEY=your-admin-api-key
```

## 🐛 Troubleshooting

### Common Issues

#### 1. Build Failures
```bash
# Update Rust
rustup update

# Clean build
cargo clean && cargo build --release

# Check system dependencies
sudo apt-get install build-essential pkg-config libssl-dev
```

#### 2. Connection Issues
```bash
# Check port availability
sudo netstat -tulpn | grep :8080

# Test connectivity
curl -v http://localhost:8080/health
```

#### 3. Permission Errors
```bash
# Fix file permissions
sudo chown -R $USER:$USER /path/to/waf-proxy
chmod +x target/release/waf-reverse-proxy
```

#### 4. High Memory Usage
```bash
# Monitor memory usage
ps aux | grep waf-reverse-proxy

# Adjust configuration
# config.yaml
server:
  max_connections: 500  # Reduce if high memory usage
  workers: 2           # Adjust based on CPU cores
```

### Debug Mode

```bash
# Enable debug logging
export RUST_LOG=debug

# Run with verbose output
./target/release/waf-reverse-proxy --config config.yaml --verbose
```

### Log Analysis

```bash
# Follow access logs
tail -f /var/log/waf-proxy/access.log

# Search for errors
grep -i error /var/log/waf-proxy/error.log

# Analyze blocked requests
grep -i "blocked" /var/log/waf-proxy/access.log | head -20
```

## ⚡ Performance Tuning

### System Optimization

#### 1. Kernel Parameters
```bash
# /etc/sysctl.conf
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
fs.file-max = 100000

# Apply changes
sudo sysctl -p
```

#### 2. User Limits
```bash
# /etc/security/limits.conf
* soft nofile 65535
* hard nofile 65535
* soft nproc 65535
* hard nproc 65535
```

### Application Tuning

#### 1. Worker Configuration
```yaml
# config.yaml
server:
  workers: 8              # Set to CPU cores
  max_connections: 10000  # Adjust based on RAM
  keep_alive: 60         # Connection keep-alive timeout
```

#### 2. Cache Optimization
```yaml
caching:
  enabled: true
  max_size: "1GB"        # Adjust based on available RAM
  ttl: 300              # Cache TTL in seconds
```

### Monitoring Performance

```bash
# Real-time metrics
curl http://localhost:9090/metrics | grep proxy_

# Load testing

## Option 1: Python Load Tester (Recommended)
# Install dependencies
pip install -r requirements.txt

# Basic load test
python tests/load_test.py --url http://localhost:8080

# High concurrency test  
python tests/load_test.py --url http://localhost:8080 --concurrency 100 --duration 60

# Custom configuration
python tests/load_test.py --url http://localhost:8080 --concurrency 50 --duration 30

## Option 2: WRK Load Tester (Alternative)
# Install wrk
sudo apt-get install wrk

# Basic load test
wrk -t12 -c400 -d30s http://localhost:8080/

# Advanced load test with Lua script
wrk -t12 -c400 -d30s -s tests/load_test.lua http://localhost:8080/
```

## 📞 Support

### Getting Help

- **Documentation**: Check this SETUP.md and README.md
- **Issues**: [GitHub Issues](https://github.com/deepskilling/waf-reverse-proxy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/deepskilling/waf-reverse-proxy/discussions)

### Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**© 2025 Deepskilling. All rights reserved.**

*Built with ❤️ using Rust for enterprise-grade web application security and performance.*
