# WAF + Reverse Proxy Python Wrapper

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Deepskilling](https://img.shields.io/badge/powered%20by-deepskilling-blue)

A comprehensive Python wrapper for the **WAF + Reverse Proxy** by **Deepskilling**, providing easy integration, management, and monitoring capabilities for the high-performance Rust-based security solution.

## 🚀 Features

### 🐍 **Python Integration**
- **Admin API Client**: Full-featured client for the WAF admin API
- **Configuration Management**: YAML configuration parsing, validation, and management
- **Process Management**: Start, stop, restart, and monitor the Rust binary
- **Health Monitoring**: Comprehensive health checks and status monitoring
- **Async Support**: Both synchronous and asynchronous API clients

### 🛠️ **Management Tools**
- **CLI Interface**: Command-line tool for all operations
- **Real-time Monitoring**: Process monitoring with resource tracking
- **Log Management**: Capture and display service logs
- **Configuration Validation**: Validate configurations before deployment
- **Backup & Restore**: Configuration backup and restore functionality

### 📊 **Monitoring & Analytics**
- **Health Checks**: Multi-layer health monitoring (ports, endpoints, SSL, resources)
- **Statistics**: Real-time WAF, proxy, cache, and SSL statistics  
- **Metrics Integration**: Prometheus metrics support
- **Alerting**: Built-in alerting for service issues

## 📦 Installation

### From Source
```bash
# Clone the repository
git clone https://github.com/deepskilling/waf-reverse-proxy.git
cd waf-reverse-proxy/python_wrapper

# Install the package
pip install .

# Or install in development mode
pip install -e .
```

### With Extra Dependencies
```bash
# Install with CLI enhancements
pip install .[cli]

# Install with monitoring features
pip install .[monitoring]

# Install with all optional features
pip install .[all]
```

### Requirements
- **Python 3.8+**
- **WAF + Reverse Proxy binary** (Rust application)
- **Dependencies**: See `requirements.txt`

## 🏃‍♂️ Quick Start

### 1. **Command Line Interface**

The Python wrapper provides a comprehensive CLI for managing the WAF service:

```bash
# Start the service
waf-proxy start --config config/config.yaml --auto-restart

# Check service status
waf-proxy status --process

# Monitor health
waf-proxy health --full --watch 5

# View statistics
waf-proxy stats waf
waf-proxy stats proxy

# Manage configurations
waf-proxy config validate
waf-proxy config backup
waf-proxy config show --section ssl

# Manage WAF rules
waf-proxy rules list
waf-proxy ip block 192.168.1.100 --reason "Suspicious activity"

# Cache management
waf-proxy cache stats
waf-proxy cache clear --pattern "/api/*"

# View logs
waf-proxy logs --lines 100 --follow
```

### 2. **Python API Usage**

#### **Basic Client Usage**
```python
from waf_proxy import WafProxyClient

# Initialize client
client = WafProxyClient(
    base_url="http://localhost:8081",
    username="admin",
    password="password"
)

# Get service health
try:
    health = client.get_health()
    print(f"Service status: {health.status}")
    
    # Get WAF statistics
    waf_stats = client.get_waf_stats()
    print(f"Blocked requests: {waf_stats.blocked_requests}")
    
    # Block an IP address
    result = client.block_ip("192.168.1.100", reason="Malicious activity")
    print("IP blocked successfully")
    
except WafProxyError as e:
    print(f"API error: {e}")
```

#### **Process Management**
```python
from waf_proxy import ProcessManager

# Initialize process manager
manager = ProcessManager(
    binary_path="./target/release/waf-reverse-proxy",
    config_path="config/config.yaml"
)

# Start the service
try:
    success = manager.start(
        validate_config=True,
        auto_restart=True
    )
    
    if success:
        print(f"Service started with PID: {manager.get_pid()}")
        
        # Get process status
        status = manager.get_status()
        print(f"CPU: {status.get('cpu_percent', 0):.1f}%")
        print(f"Memory: {status.get('memory_mb', 0):.1f} MB")
        
except ProcessError as e:
    print(f"Failed to start service: {e}")

# Context manager usage
with ProcessManager() as pm:
    pm.start()
    # Service will be automatically stopped when exiting
```

#### **Configuration Management**
```python
from waf_proxy import ConfigManager

# Initialize config manager
config_mgr = ConfigManager("config/config.yaml")

# Load and validate configuration
try:
    config = config_mgr.load_config(validate=True)
    print("Configuration is valid")
    
    # Enable SSL with auto-provisioning
    config_mgr.enable_ssl(
        domains=["example.com", "www.example.com"],
        auto_provision=True,
        email="admin@example.com"
    )
    
    # Add a new upstream
    config_mgr.add_upstream("api-backend", {
        "servers": [
            {"url": "http://api1.local:8080", "weight": 100},
            {"url": "http://api2.local:8080", "weight": 100}
        ],
        "load_balancer": "round_robin",
        "health_check": {
            "enabled": True,
            "interval": "10s",
            "path": "/health"
        }
    })
    
    # Create backup before changes
    backup_path = config_mgr.create_backup("before_update")
    print(f"Backup created: {backup_path}")
    
except ConfigurationError as e:
    print(f"Configuration error: {e}")
```

#### **Health Monitoring**
```python
from waf_proxy import HealthMonitor

# Initialize health monitor
monitor = HealthMonitor(
    service_url="http://localhost:8080",
    admin_url="http://localhost:8081"
)

# Perform health checks
health = monitor.check_all(include_optional=True)

print(f"Overall status: {health.overall_status.value}")
print(f"Uptime: {health.uptime:.1f} seconds")

# Check individual components
for check in health.checks:
    status_icon = "✅" if check.status.value == "healthy" else "❌"
    print(f"{status_icon} {check.name}: {check.message}")

# Get uptime statistics
uptime_24h = monitor.get_uptime_percentage(24)
print(f"24-hour uptime: {uptime_24h:.2f}%")

# Generate comprehensive report
report = monitor.generate_health_report(include_history=True)
print(f"Health report: {report}")
```

#### **Async Usage**
```python
import asyncio
from waf_proxy import AsyncWafProxyClient

async def main():
    async with AsyncWafProxyClient(base_url="http://localhost:8081") as client:
        # Get health status
        health = await client.get_health()
        print(f"Service status: {health.status}")
        
        # Get WAF statistics
        stats = await client.get_waf_stats()
        print(f"Total requests: {stats.total_requests}")

# Run async code
asyncio.run(main())
```

### 3. **Integration Examples**

#### **Django Integration**
```python
# settings.py
from waf_proxy import WafProxyClient

# Initialize WAF client
WAF_CLIENT = WafProxyClient(
    base_url="http://localhost:8081",
    api_token="your-jwt-token"
)

# middleware.py
from django.http import HttpResponseForbidden

class WafMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Check if IP is blocked
        client_ip = self.get_client_ip(request)
        blocked_ips = WAF_CLIENT.get_blocked_ips()
        
        if client_ip in blocked_ips:
            return HttpResponseForbidden("Access denied")
        
        return self.get_response(request)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')
```

#### **Flask Integration**
```python
from flask import Flask, request, abort
from waf_proxy import WafProxyClient

app = Flask(__name__)
waf_client = WafProxyClient(base_url="http://localhost:8081")

@app.before_request
def check_waf_status():
    """Check WAF status before each request"""
    try:
        health = waf_client.get_health()
        if health.status != 'healthy':
            app.logger.warning(f"WAF status: {health.status}")
    except Exception as e:
        app.logger.error(f"WAF health check failed: {e}")

@app.route('/admin/waf/stats')
def waf_stats():
    """Get WAF statistics endpoint"""
    try:
        stats = waf_client.get_waf_stats()
        return {
            'total_requests': stats.total_requests,
            'blocked_requests': stats.blocked_requests,
            'blocked_percentage': (stats.blocked_requests / stats.total_requests * 100) if stats.total_requests > 0 else 0
        }
    except Exception as e:
        return {'error': str(e)}, 500
```

#### **FastAPI Integration**
```python
from fastapi import FastAPI, HTTPException, BackgroundTasks
from waf_proxy import WafProxyClient, ProcessManager
import asyncio

app = FastAPI(title="WAF Management API")

# Initialize managers
waf_client = WafProxyClient(base_url="http://localhost:8081")
process_manager = ProcessManager()

@app.on_event("startup")
async def startup_event():
    """Start WAF service if not running"""
    if not process_manager.is_running():
        success = process_manager.start(auto_restart=True)
        if not success:
            raise RuntimeError("Failed to start WAF service")

@app.get("/waf/health")
async def get_waf_health():
    """Get WAF health status"""
    try:
        health = waf_client.get_health()
        return {
            "status": health.status,
            "uptime": health.uptime,
            "components": health.components
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/waf/rules")
async def add_waf_rule(rule: dict):
    """Add WAF rule"""
    try:
        result = waf_client.add_waf_rule(rule)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/waf/ip/{ip}/block")
async def block_ip(ip: str, reason: str = "Blocked via API"):
    """Block IP address"""
    try:
        result = waf_client.block_ip(ip, reason=reason)
        return {"message": f"IP {ip} blocked successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
```

## 🔧 Configuration

### **Environment Variables**
```bash
# WAF service configuration
export WAF_CONFIG_PATH="config/config.yaml"
export WAF_BINARY_PATH="./target/release/waf-reverse-proxy"
export WAF_ADMIN_URL="http://localhost:8081"
export WAF_SERVICE_URL="http://localhost:8080"

# Authentication
export WAF_ADMIN_USERNAME="admin"
export WAF_ADMIN_PASSWORD="secure_password"
export WAF_JWT_TOKEN="your-jwt-token"

# Monitoring
export WAF_HEALTH_CHECK_INTERVAL="30"
export WAF_METRICS_ENABLED="true"
```

### **Configuration File Example**
```python
# waf_config.py
from waf_proxy import ConfigManager

# Create configuration manager
config_mgr = ConfigManager()

# Generate sample configuration
sample_config = config_mgr.generate_sample_config()

# Customize for your environment
sample_config['server']['host'] = '0.0.0.0'
sample_config['server']['port'] = 8080

# Enable SSL with Let's Encrypt
sample_config['ssl'].update({
    'enabled': True,
    'auto_provision': True,
    'domains': ['yourdomain.com', 'www.yourdomain.com'],
    'acme_email': 'admin@yourdomain.com'
})

# Configure WAF protection
sample_config['waf'].update({
    'enabled': True,
    'mode': 'block',
    'rate_limiting': {
        'global': {'requests_per_second': 1000, 'burst': 2000},
        'per_ip': {'requests_per_minute': 5000, 'burst': 1000}
    }
})

# Save configuration
config_mgr.save_config(sample_config)
```

## 📚 API Reference

### **WafProxyClient**
Main client for interacting with the WAF admin API.

**Methods:**
- `get_health()` - Get service health status
- `get_waf_stats()` - Get WAF statistics
- `get_proxy_stats()` - Get proxy statistics
- `get_waf_rules()` - List WAF rules
- `add_waf_rule(rule)` - Add new WAF rule
- `block_ip(ip, reason)` - Block IP address
- `unblock_ip(ip)` - Unblock IP address
- `get_upstreams()` - Get upstream servers
- `clear_cache(pattern)` - Clear cache entries
- `get_ssl_stats()` - Get SSL certificate status

### **ProcessManager**
Manages the WAF service process lifecycle.

**Methods:**
- `start(validate_config, auto_restart)` - Start service
- `stop(timeout, force)` - Stop service
- `restart()` - Restart service
- `is_running()` - Check if running
- `get_status()` - Get process status
- `get_logs(lines)` - Get recent logs
- `send_signal(signal)` - Send signal to process

### **ConfigManager**
Configuration file management and validation.

**Methods:**
- `load_config(validate)` - Load configuration
- `save_config(config, backup)` - Save configuration
- `validate_config(config)` - Validate configuration
- `create_backup(suffix)` - Create backup
- `restore_backup(path)` - Restore from backup
- `enable_ssl(domains, auto_provision)` - Enable SSL
- `add_upstream(name, config)` - Add upstream server

### **HealthMonitor**
Comprehensive health monitoring and checks.

**Methods:**
- `check_all(include_optional)` - Perform all health checks
- `check_service_port()` - Check service port accessibility
- `check_admin_health()` - Check admin API health
- `check_ssl_status()` - Check SSL certificate status
- `get_uptime_percentage(hours)` - Calculate uptime percentage
- `generate_health_report()` - Generate comprehensive report

## 🧪 Testing

### **Running Tests**
```bash
# Install development dependencies
pip install -e .[dev]

# Run tests
pytest tests/

# Run with coverage
pytest --cov=waf_proxy tests/

# Run specific test file
pytest tests/test_client.py -v

# Run async tests
pytest tests/test_async_client.py -v
```

### **Example Tests**
```python
# tests/test_integration.py
import pytest
from waf_proxy import WafProxyClient, ProcessManager, ConfigManager

@pytest.fixture
def waf_client():
    return WafProxyClient(base_url="http://localhost:8081")

@pytest.fixture  
def process_manager():
    return ProcessManager(binary_path="./mock/waf-binary")

def test_client_health_check(waf_client):
    """Test WAF client health check"""
    health = waf_client.get_health()
    assert health.status in ['healthy', 'degraded', 'unhealthy']

def test_process_lifecycle(process_manager):
    """Test process start/stop lifecycle"""
    # Start process
    success = process_manager.start()
    assert success
    assert process_manager.is_running()
    
    # Get status
    status = process_manager.get_status()
    assert status['running'] is True
    assert status['pid'] is not None
    
    # Stop process
    success = process_manager.stop()
    assert success
    assert not process_manager.is_running()

@pytest.mark.asyncio
async def test_async_client():
    """Test async client functionality"""
    from waf_proxy import AsyncWafProxyClient
    
    async with AsyncWafProxyClient() as client:
        health = await client.get_health()
        assert health.status is not None
```

## 📖 Documentation

### **CLI Documentation**
```bash
# Get help for main command
waf-proxy --help

# Get help for specific subcommand
waf-proxy start --help
waf-proxy config --help
waf-proxy health --help

# List all available commands
waf-proxy --help | grep -A 20 "Available commands"
```

### **API Documentation**
Generate API documentation:
```bash
# Install documentation tools
pip install sphinx sphinx-autodoc-typehints

# Generate docs
cd docs/
make html

# View documentation
open _build/html/index.html
```

## 🚨 Troubleshooting

### **Common Issues**

**1. Service Won't Start**
```bash
# Check configuration
waf-proxy config validate

# Check binary permissions
chmod +x ./target/release/waf-reverse-proxy

# Check logs
waf-proxy logs --lines 50
```

**2. API Connection Issues**
```bash
# Check if admin API is accessible
curl http://localhost:8081/api/v1/health

# Check service status
waf-proxy status --process

# Verify configuration
waf-proxy config show --section admin
```

**3. SSL Certificate Issues**
```bash
# Check SSL status
waf-proxy stats ssl

# Validate SSL configuration
waf-proxy config show --section ssl

# Check certificate files
ls -la /path/to/certificates/
```

**4. High Resource Usage**
```bash
# Monitor resource usage
waf-proxy status --process

# Check health status
waf-proxy health --full

# View detailed statistics
waf-proxy stats proxy
waf-proxy stats waf
```

### **Debug Mode**
```bash
# Enable verbose logging
waf-proxy --verbose start

# Enable debug logging in Python
export PYTHONPATH=.
export LOG_LEVEL=DEBUG
python -m waf_proxy.cli start --verbose
```

## 🤝 Contributing

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes** and add tests
4. **Run tests**: `pytest tests/`
5. **Commit changes**: `git commit -m 'Add amazing feature'`
6. **Push to branch**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**

### **Development Setup**
```bash
# Clone repository
git clone https://github.com/deepskilling/waf-reverse-proxy.git
cd waf-reverse-proxy/python_wrapper

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .[dev,all]

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run tests
pytest tests/ --cov=waf_proxy
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Deepskilling** - For the amazing WAF + Reverse Proxy implementation
- **Rust Community** - For the powerful and secure foundation
- **Python Community** - For the excellent ecosystem and tools

---

<div align="center">
<p><strong>WAF + Reverse Proxy Python Wrapper</strong></p>
<p>Built with ❤️ by <strong>Deepskilling</strong></p>
<p><a href="https://deepskilling.com">https://deepskilling.com</a></p>
</div>
