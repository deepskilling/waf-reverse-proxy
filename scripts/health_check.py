#!/usr/bin/env python3
"""
WAF + Reverse Proxy - Health Check Script
=========================================

This script performs comprehensive health checks on the WAF + Reverse Proxy system,
including service status, configuration validation, performance metrics, and security checks.

Usage:
    python health_check.py [options]
    
Options:
    --service       Check service status and connectivity
    --config        Validate configuration files
    --performance   Check performance metrics
    --security      Run security health checks
    --endpoints     Test all endpoints
    --full          Run comprehensive health check
    --json          Output results in JSON format
    --quiet         Suppress detailed output
    
Requirements:
    - Python 3.6+
    - requests library (pip install requests)
"""

import os
import sys
import json
import yaml
import time
import argparse
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("❌ Required 'requests' library not found. Install with: pip install requests")
    sys.exit(1)

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class HealthChecker:
    """Comprehensive health checking for WAF + Reverse Proxy"""
    
    def __init__(self, quiet=False, json_output=False):
        self.project_root = Path(__file__).parent.parent
        self.config_file = self.project_root / "config" / "config.yaml"
        self.quiet = quiet
        self.json_output = json_output
        self.results = {}
        
        # Default endpoints
        self.endpoints = {
            "proxy": "http://localhost:8080",
            "admin": "http://localhost:8081",
            "metrics": "http://localhost:9090"
        }
        
        # Setup HTTP session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
    def log(self, message, level="info"):
        """Log message with appropriate color coding"""
        if self.json_output or self.quiet:
            return
            
        color = {
            "info": Colors.OKCYAN,
            "success": Colors.OKGREEN,
            "warning": Colors.WARNING,
            "error": Colors.FAIL,
            "header": Colors.HEADER + Colors.BOLD
        }.get(level, Colors.ENDC)
        
        print(f"{color}{message}{Colors.ENDC}")
        
    def print_header(self):
        """Print welcome header"""
        if not self.json_output:
            self.log("🏥 WAF + Reverse Proxy - Health Check", "header")
            self.log("=" * 42, "header")
            
    def load_config(self):
        """Load and validate configuration file"""
        try:
            if not self.config_file.exists():
                return None, "Configuration file not found"
                
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
                
            # Update endpoints from config
            if 'server' in config:
                host = config['server'].get('host', 'localhost')
                port = config['server'].get('port', 8080)
                if host == '0.0.0.0':
                    host = 'localhost'
                self.endpoints['proxy'] = f"http://{host}:{port}"
                
            if 'admin' in config:
                port = config['admin'].get('port', 8081)
                self.endpoints['admin'] = f"http://localhost:{port}"
                
            if 'metrics' in config:
                port = config['metrics'].get('port', 9090)
                self.endpoints['metrics'] = f"http://localhost:{port}"
                
            return config, None
        except Exception as e:
            return None, str(e)
            
    def check_service_status(self):
        """Check if services are running"""
        self.log("\n🔍 Checking service status...", "info")
        
        service_results = {}
        
        # Check main proxy service
        try:
            response = self.session.get(f"{self.endpoints['proxy']}/health", timeout=5)
            if response.status_code == 200:
                self.log("✅ Main proxy service: Running", "success")
                service_results['proxy'] = {"status": "running", "response_time": response.elapsed.total_seconds()}
            else:
                self.log(f"⚠️  Main proxy service: HTTP {response.status_code}", "warning")
                service_results['proxy'] = {"status": f"http_{response.status_code}", "response_time": response.elapsed.total_seconds()}
        except requests.exceptions.RequestException as e:
            self.log(f"❌ Main proxy service: Not accessible ({str(e)[:50]})", "error")
            service_results['proxy'] = {"status": "not_accessible", "error": str(e)}
            
        # Check admin API
        try:
            response = self.session.get(f"{self.endpoints['admin']}/api/health", timeout=5)
            if response.status_code == 200:
                self.log("✅ Admin API service: Running", "success")
                service_results['admin'] = {"status": "running", "response_time": response.elapsed.total_seconds()}
            else:
                self.log(f"⚠️  Admin API service: HTTP {response.status_code}", "warning")
                service_results['admin'] = {"status": f"http_{response.status_code}", "response_time": response.elapsed.total_seconds()}
        except requests.exceptions.RequestException as e:
            self.log(f"❌ Admin API service: Not accessible ({str(e)[:50]})", "error")
            service_results['admin'] = {"status": "not_accessible", "error": str(e)}
            
        # Check metrics endpoint
        try:
            response = self.session.get(f"{self.endpoints['metrics']}/metrics", timeout=5)
            if response.status_code == 200:
                self.log("✅ Metrics service: Running", "success")
                service_results['metrics'] = {"status": "running", "response_time": response.elapsed.total_seconds()}
            else:
                self.log(f"⚠️  Metrics service: HTTP {response.status_code}", "warning")
                service_results['metrics'] = {"status": f"http_{response.status_code}", "response_time": response.elapsed.total_seconds()}
        except requests.exceptions.RequestException as e:
            self.log(f"❌ Metrics service: Not accessible ({str(e)[:50]})", "error")
            service_results['metrics'] = {"status": "not_accessible", "error": str(e)}
            
        self.results['services'] = service_results
        return service_results
        
    def validate_configuration(self):
        """Validate configuration file"""
        self.log("\n📋 Validating configuration...", "info")
        
        config, error = self.load_config()
        if error:
            self.log(f"❌ Configuration error: {error}", "error")
            self.results['configuration'] = {"valid": False, "error": error}
            return False
            
        validation_results = {"valid": True, "warnings": [], "errors": []}
        
        # Check required sections
        required_sections = ['server', 'waf', 'proxy', 'logging', 'metrics']
        for section in required_sections:
            if section not in config:
                validation_results["errors"].append(f"Missing required section: {section}")
                validation_results["valid"] = False
                
        # Validate server configuration
        server = config.get('server', {})
        if not isinstance(server.get('port'), int) or not (1 <= server.get('port') <= 65535):
            validation_results["errors"].append("Invalid server port")
            validation_results["valid"] = False
            
        # Validate upstream servers
        upstreams = config.get('proxy', {}).get('upstreams', {})
        if not upstreams:
            validation_results["warnings"].append("No upstream servers configured")
        else:
            for name, upstream in upstreams.items():
                if not upstream.get('servers'):
                    validation_results["errors"].append(f"Upstream '{name}' has no servers")
                    validation_results["valid"] = False
                    
        # Check WAF configuration
        waf_config = config.get('waf', {})
        if waf_config.get('enabled') and not waf_config.get('owasp_protection'):
            validation_results["warnings"].append("WAF enabled but no OWASP protection configured")
            
        if validation_results["valid"]:
            self.log("✅ Configuration validation passed", "success")
            if validation_results["warnings"]:
                for warning in validation_results["warnings"]:
                    self.log(f"⚠️  {warning}", "warning")
        else:
            self.log("❌ Configuration validation failed", "error")
            for error in validation_results["errors"]:
                self.log(f"   • {error}", "error")
                
        self.results['configuration'] = validation_results
        return validation_results["valid"]
        
    def check_performance_metrics(self):
        """Check performance and collect metrics"""
        self.log("\n⚡ Checking performance metrics...", "info")
        
        performance_results = {}
        
        # Test response times
        endpoints_to_test = [
            ("/health", "Health endpoint"),
            ("/", "Root endpoint"),
        ]
        
        response_times = []
        for endpoint, description in endpoints_to_test:
            try:
                start_time = time.time()
                response = self.session.get(f"{self.endpoints['proxy']}{endpoint}", timeout=10)
                response_time = (time.time() - start_time) * 1000  # Convert to ms
                response_times.append(response_time)
                
                if response_time < 100:
                    self.log(f"✅ {description}: {response_time:.1f}ms (excellent)", "success")
                elif response_time < 500:
                    self.log(f"✅ {description}: {response_time:.1f}ms (good)", "success")
                else:
                    self.log(f"⚠️  {description}: {response_time:.1f}ms (slow)", "warning")
                    
            except requests.exceptions.RequestException as e:
                self.log(f"❌ {description}: Failed ({str(e)[:30]})", "error")
                
        # Calculate average response time
        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            performance_results['average_response_time_ms'] = avg_response_time
            performance_results['response_times'] = response_times
            
        # Check memory usage (if available)
        try:
            import psutil
            process_found = False
            for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent']):
                if 'waf-reverse-proxy' in proc.info['name']:
                    memory_mb = proc.info['memory_info'].rss / 1024 / 1024
                    cpu_percent = proc.info['cpu_percent']
                    performance_results['memory_usage_mb'] = memory_mb
                    performance_results['cpu_usage_percent'] = cpu_percent
                    self.log(f"📊 Memory usage: {memory_mb:.1f} MB", "info")
                    self.log(f"📊 CPU usage: {cpu_percent:.1f}%", "info")
                    process_found = True
                    break
                    
            if not process_found:
                self.log("⚠️  Process not found for resource monitoring", "warning")
                
        except ImportError:
            self.log("ℹ️  psutil not available for resource monitoring", "info")
            
        self.results['performance'] = performance_results
        return performance_results
        
    def run_security_checks(self):
        """Run security-focused health checks"""
        self.log("\n🛡️  Running security checks...", "info")
        
        security_results = {"checks": []}
        
        # Test WAF blocking
        waf_tests = [
            ("/?id=1' OR '1'='1", "SQL Injection test"),
            ("/?q=<script>alert(1)</script>", "XSS test"),
            ("/admin", "Admin path access test"),
            ("/../../../etc/passwd", "Path traversal test"),
        ]
        
        for test_path, test_name in waf_tests:
            try:
                response = self.session.get(f"{self.endpoints['proxy']}{test_path}", timeout=5)
                if response.status_code == 403 or response.status_code == 406:
                    self.log(f"✅ {test_name}: Blocked (HTTP {response.status_code})", "success")
                    security_results["checks"].append({
                        "test": test_name,
                        "status": "blocked",
                        "http_code": response.status_code
                    })
                elif response.status_code == 200:
                    self.log(f"⚠️  {test_name}: Not blocked", "warning")
                    security_results["checks"].append({
                        "test": test_name,
                        "status": "allowed",
                        "http_code": response.status_code
                    })
                else:
                    self.log(f"ℹ️  {test_name}: HTTP {response.status_code}", "info")
                    security_results["checks"].append({
                        "test": test_name,
                        "status": f"http_{response.status_code}",
                        "http_code": response.status_code
                    })
            except requests.exceptions.RequestException as e:
                self.log(f"❌ {test_name}: Test failed ({str(e)[:30]})", "error")
                security_results["checks"].append({
                    "test": test_name,
                    "status": "failed",
                    "error": str(e)
                })
                
        # Check security headers
        try:
            response = self.session.get(self.endpoints['proxy'], timeout=5)
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': None,  # Only for HTTPS
            }
            
            headers_results = {}
            for header, expected in security_headers.items():
                if header in response.headers:
                    headers_results[header] = response.headers[header]
                    if expected and response.headers[header] == expected:
                        self.log(f"✅ Security header {header}: Present", "success")
                    else:
                        self.log(f"ℹ️  Security header {header}: {response.headers[header]}", "info")
                else:
                    headers_results[header] = None
                    self.log(f"⚠️  Security header {header}: Missing", "warning")
                    
            security_results["security_headers"] = headers_results
            
        except requests.exceptions.RequestException as e:
            self.log(f"❌ Security headers check failed: {e}", "error")
            
        self.results['security'] = security_results
        return security_results
        
    def test_all_endpoints(self):
        """Test all available endpoints"""
        self.log("\n🌐 Testing all endpoints...", "info")
        
        endpoints_results = {}
        
        # Main proxy endpoints
        proxy_endpoints = [
            ("/", "Root"),
            ("/health", "Health check"),
            ("/favicon.ico", "Favicon"),
        ]
        
        for endpoint, name in proxy_endpoints:
            try:
                response = self.session.get(f"{self.endpoints['proxy']}{endpoint}", timeout=5)
                status = "ok" if 200 <= response.status_code < 400 else "error"
                endpoints_results[f"proxy_{endpoint}"] = {
                    "status": status,
                    "http_code": response.status_code,
                    "response_time": response.elapsed.total_seconds()
                }
                
                status_color = "success" if status == "ok" else "warning"
                self.log(f"✅ Proxy {name}: HTTP {response.status_code}", status_color)
                
            except requests.exceptions.RequestException as e:
                endpoints_results[f"proxy_{endpoint}"] = {
                    "status": "failed",
                    "error": str(e)
                }
                self.log(f"❌ Proxy {name}: Failed", "error")
                
        # Admin API endpoints
        admin_endpoints = [
            ("/api/health", "Health"),
            ("/api/status", "Status"),
            ("/api/metrics", "Metrics summary"),
        ]
        
        for endpoint, name in admin_endpoints:
            try:
                response = self.session.get(f"{self.endpoints['admin']}{endpoint}", timeout=5)
                status = "ok" if 200 <= response.status_code < 400 else "error"
                endpoints_results[f"admin_{endpoint}"] = {
                    "status": status,
                    "http_code": response.status_code,
                    "response_time": response.elapsed.total_seconds()
                }
                
                status_color = "success" if status == "ok" else "warning"
                self.log(f"✅ Admin {name}: HTTP {response.status_code}", status_color)
                
            except requests.exceptions.RequestException as e:
                endpoints_results[f"admin_{endpoint}"] = {
                    "status": "failed",
                    "error": str(e)
                }
                self.log(f"❌ Admin {name}: Failed", "error")
                
        self.results['endpoints'] = endpoints_results
        return endpoints_results
        
    def generate_health_report(self):
        """Generate comprehensive health report"""
        timestamp = datetime.now().isoformat()
        
        # Calculate overall health score
        total_checks = 0
        passed_checks = 0
        
        # Service checks
        for service, result in self.results.get('services', {}).items():
            total_checks += 1
            if result.get('status') == 'running':
                passed_checks += 1
                
        # Configuration check
        total_checks += 1
        if self.results.get('configuration', {}).get('valid'):
            passed_checks += 1
            
        # Security checks
        for check in self.results.get('security', {}).get('checks', []):
            total_checks += 1
            if check.get('status') in ['blocked', 'allowed']:
                passed_checks += 1
                
        health_score = (passed_checks / total_checks * 100) if total_checks > 0 else 0
        
        overall_status = "healthy" if health_score >= 80 else "degraded" if health_score >= 60 else "unhealthy"
        
        report = {
            "timestamp": timestamp,
            "overall_status": overall_status,
            "health_score": round(health_score, 1),
            "summary": {
                "total_checks": total_checks,
                "passed_checks": passed_checks,
                "failed_checks": total_checks - passed_checks
            },
            "details": self.results
        }
        
        return report
        
    def run_health_check(self, checks=None):
        """Run health check with specified checks"""
        if checks is None:
            checks = ['service', 'config', 'performance', 'security', 'endpoints']
            
        self.print_header()
        
        if 'service' in checks:
            self.check_service_status()
            
        if 'config' in checks:
            self.validate_configuration()
            
        if 'performance' in checks:
            self.check_performance_metrics()
            
        if 'security' in checks:
            self.run_security_checks()
            
        if 'endpoints' in checks:
            self.test_all_endpoints()
            
        # Generate and output report
        report = self.generate_health_report()
        
        if self.json_output:
            print(json.dumps(report, indent=2))
        else:
            self.log(f"\n📊 Health Check Summary", "header")
            self.log(f"Overall Status: {report['overall_status'].upper()}", 
                    "success" if report['overall_status'] == 'healthy' else 'warning')
            self.log(f"Health Score: {report['health_score']}/100", "info")
            self.log(f"Checks: {report['summary']['passed_checks']}/{report['summary']['total_checks']} passed", "info")
            
            if report['overall_status'] != 'healthy':
                self.log("\n⚠️  Issues detected. Review the detailed output above.", "warning")
            else:
                self.log("\n✅ All systems operational!", "success")
                
        return report

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="WAF + Reverse Proxy Health Check")
    parser.add_argument("--service", action="store_true", help="Check service status")
    parser.add_argument("--config", action="store_true", help="Validate configuration")
    parser.add_argument("--performance", action="store_true", help="Check performance metrics")
    parser.add_argument("--security", action="store_true", help="Run security checks")
    parser.add_argument("--endpoints", action="store_true", help="Test all endpoints")
    parser.add_argument("--full", action="store_true", help="Run all checks")
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--quiet", action="store_true", help="Suppress detailed output")
    
    args = parser.parse_args()
    
    # Determine which checks to run
    checks = []
    if args.service:
        checks.append('service')
    if args.config:
        checks.append('config')
    if args.performance:
        checks.append('performance')
    if args.security:
        checks.append('security')
    if args.endpoints:
        checks.append('endpoints')
    if args.full or not checks:
        checks = ['service', 'config', 'performance', 'security', 'endpoints']
        
    # Run health check
    checker = HealthChecker(quiet=args.quiet, json_output=args.json)
    report = checker.run_health_check(checks)
    
    # Exit with appropriate code
    exit_code = 0 if report['overall_status'] == 'healthy' else 1
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
