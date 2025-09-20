#!/usr/bin/env python3
"""
WAF + Reverse Proxy - Deployment Setup Script
=============================================

This script helps set up the deployment environment for the WAF + Reverse Proxy,
including Docker, configuration validation, and monitoring stack.

Usage:
    python setup_deployment.py [options]
    
Options:
    --docker        Set up Docker deployment
    --kubernetes    Generate Kubernetes manifests
    --monitor       Set up monitoring stack (Prometheus/Grafana)
    --ssl           Generate SSL certificates for testing
    --validate      Validate configuration files
    --all           Run all setup tasks
    
Requirements:
    - Python 3.6+
    - Docker (for Docker deployment)
    - kubectl (for Kubernetes deployment)
"""

import os
import sys
import json
import yaml
import argparse
import subprocess
import shutil
from pathlib import Path
from datetime import datetime, timedelta

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

class DeploymentSetup:
    """Handles deployment setup tasks"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent
        self.config_file = self.project_root / "config" / "config.yaml"
        
    def print_header(self):
        """Print welcome header"""
        print(f"{Colors.HEADER}{Colors.BOLD}")
        print("🐳 WAF + Reverse Proxy - Deployment Setup")
        print("=" * 45)
        print(f"{Colors.ENDC}")
        
    def check_docker(self):
        """Check if Docker is installed and running"""
        print(f"{Colors.OKCYAN}🐳 Checking Docker...{Colors.ENDC}")
        
        if not shutil.which("docker"):
            print(f"{Colors.FAIL}❌ Docker is not installed{Colors.ENDC}")
            print("   Install from: https://docker.com/get-started")
            return False
            
        try:
            result = subprocess.run(["docker", "info"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                print(f"{Colors.FAIL}❌ Docker daemon is not running{Colors.ENDC}")
                return False
        except subprocess.TimeoutExpired:
            print(f"{Colors.FAIL}❌ Docker daemon is not responding{Colors.ENDC}")
            return False
            
        print(f"{Colors.OKGREEN}✅ Docker is ready{Colors.ENDC}")
        return True
        
    def check_docker_compose(self):
        """Check Docker Compose availability"""
        # Check for docker-compose command
        if shutil.which("docker-compose"):
            return True
            
        # Check for docker compose plugin
        try:
            result = subprocess.run(["docker", "compose", "version"], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False
            
    def setup_docker_deployment(self):
        """Set up Docker deployment environment"""
        print(f"\n{Colors.OKCYAN}🐳 Setting up Docker deployment...{Colors.ENDC}")
        
        if not self.check_docker():
            return False
            
        if not self.check_docker_compose():
            print(f"{Colors.FAIL}❌ Docker Compose is not available{Colors.ENDC}")
            print("   Install docker-compose or use Docker Desktop")
            return False
            
        # Create necessary directories
        dirs_to_create = ["logs", "ssl", "data", "prometheus", "grafana"]
        for dir_name in dirs_to_create:
            dir_path = self.project_root / dir_name
            dir_path.mkdir(exist_ok=True)
            print(f"📁 Created directory: {dir_name}/")
            
        # Create demo content for nginx backend
        demo_dir = self.project_root / "demo-content"
        demo_dir.mkdir(exist_ok=True)
        
        demo_html = demo_dir / "index.html"
        demo_html.write_text("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Protected Backend</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .status { color: #4CAF50; font-weight: bold; }
        .header { color: #2196F3; border-bottom: 2px solid #2196F3; padding-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="header">🛡️ WAF Protected Backend Service</h1>
        <p class="status">✅ Backend service is running and protected by WAF</p>
        <p>This is a demo backend service running behind the WAF + Reverse Proxy.</p>
        
        <h2>🔍 Test Endpoints:</h2>
        <ul>
            <li><strong>/health</strong> - Health check endpoint</li>
            <li><strong>/api/data</strong> - Sample API endpoint</li>
            <li><strong>/admin</strong> - Protected admin area (should be blocked)</li>
            <li><strong>/static/</strong> - Static content (cached)</li>
        </ul>
        
        <h2>📊 Monitoring:</h2>
        <ul>
            <li><a href="http://localhost:3000">Grafana Dashboard</a></li>
            <li><a href="http://localhost:9090">Prometheus Metrics</a></li>
            <li><a href="http://localhost:8081/api/status">Admin API</a></li>
        </ul>
        
        <p><em>Request processed at: <span id="timestamp"></span></em></p>
        <script>
            document.getElementById('timestamp').textContent = new Date().toISOString();
        </script>
    </div>
</body>
</html>""")
        
        # Create health endpoint
        health_html = demo_dir / "health.html"
        health_html.write_text('{"status": "healthy", "service": "demo-backend", "timestamp": "' + 
                              datetime.now().isoformat() + '"}')
        
        print(f"{Colors.OKGREEN}✅ Docker deployment environment ready{Colors.ENDC}")
        print("\nTo start the stack:")
        print("   docker-compose up -d")
        return True
        
    def generate_kubernetes_manifests(self):
        """Generate Kubernetes deployment manifests"""
        print(f"\n{Colors.OKCYAN}☸️  Generating Kubernetes manifests...{Colors.ENDC}")
        
        k8s_dir = self.project_root / "k8s"
        k8s_dir.mkdir(exist_ok=True)
        
        # Deployment manifest
        deployment_yaml = k8s_dir / "deployment.yaml"
        deployment_yaml.write_text("""apiVersion: apps/v1
kind: Deployment
metadata:
  name: waf-reverse-proxy
  labels:
    app: waf-reverse-proxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: waf-reverse-proxy
  template:
    metadata:
      labels:
        app: waf-reverse-proxy
    spec:
      containers:
      - name: waf-reverse-proxy
        image: waf-reverse-proxy:latest
        ports:
        - containerPort: 8080
          name: proxy
        - containerPort: 8081
          name: admin
        - containerPort: 9090
          name: metrics
        env:
        - name: RUST_LOG
          value: "info"
        - name: CONFIG_PATH
          value: "/app/config/config.yaml"
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        - name: logs
          mountPath: /app/logs
        resources:
          limits:
            cpu: "1000m"
            memory: "512Mi"
          requests:
            cpu: "100m"
            memory: "128Mi"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: config
        configMap:
          name: waf-config
      - name: logs
        emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: waf-reverse-proxy-service
  labels:
    app: waf-reverse-proxy
spec:
  selector:
    app: waf-reverse-proxy
  ports:
  - name: proxy
    port: 80
    targetPort: 8080
  - name: admin
    port: 8081
    targetPort: 8081
  - name: metrics
    port: 9090
    targetPort: 9090
  type: LoadBalancer
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: waf-config
data:
  config.yaml: |
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
            - url: "http://backend-service:80"
              weight: 1
          load_balancer: "round_robin"
          health_check:
            enabled: true
            path: "/health"
            interval: 30s
            timeout: 5s
    
    logging:
      level: "info"
      format: "json"
      
    metrics:
      enabled: true
      port: 9090
      path: "/metrics"
""")
        
        # HPA manifest
        hpa_yaml = k8s_dir / "hpa.yaml"
        hpa_yaml.write_text("""apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: waf-reverse-proxy-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: waf-reverse-proxy
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
""")
        
        # Service Monitor for Prometheus
        servicemonitor_yaml = k8s_dir / "servicemonitor.yaml"
        servicemonitor_yaml.write_text("""apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: waf-reverse-proxy-metrics
  labels:
    app: waf-reverse-proxy
spec:
  selector:
    matchLabels:
      app: waf-reverse-proxy
  endpoints:
  - port: metrics
    path: /metrics
    interval: 30s
    scrapeTimeout: 10s
""")
        
        print(f"📄 Generated: {deployment_yaml}")
        print(f"📄 Generated: {hpa_yaml}")
        print(f"📄 Generated: {servicemonitor_yaml}")
        print(f"{Colors.OKGREEN}✅ Kubernetes manifests generated in k8s/ directory{Colors.ENDC}")
        
        print("\nTo deploy to Kubernetes:")
        print("   kubectl apply -f k8s/")
        return True
        
    def setup_monitoring_stack(self):
        """Set up Prometheus and Grafana monitoring"""
        print(f"\n{Colors.OKCYAN}📊 Setting up monitoring stack...{Colors.ENDC}")
        
        # Create Grafana provisioning directories
        grafana_dir = self.project_root / "grafana"
        (grafana_dir / "provisioning" / "datasources").mkdir(parents=True, exist_ok=True)
        (grafana_dir / "provisioning" / "dashboards").mkdir(parents=True, exist_ok=True)
        
        # Grafana datasource configuration
        datasource_yaml = grafana_dir / "provisioning" / "datasources" / "prometheus.yaml"
        datasource_yaml.write_text("""apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: true
""")
        
        # Grafana dashboard configuration
        dashboard_yaml = grafana_dir / "provisioning" / "dashboards" / "waf-dashboard.yaml"
        dashboard_yaml.write_text("""apiVersion: 1

providers:
  - name: 'WAF Dashboards'
    orgId: 1
    folder: 'WAF + Reverse Proxy'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
""")
        
        # Create sample Grafana dashboard
        dashboard_json = grafana_dir / "provisioning" / "dashboards" / "waf-metrics.json"
        dashboard = {
            "dashboard": {
                "id": None,
                "title": "WAF + Reverse Proxy Metrics",
                "tags": ["waf", "proxy", "security"],
                "timezone": "browser",
                "panels": [
                    {
                        "id": 1,
                        "title": "Request Rate",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(waf_requests_total[5m])",
                                "legendFormat": "{{action}} - {{type}}"
                            }
                        ],
                        "gridPos": {"h": 9, "w": 12, "x": 0, "y": 0}
                    },
                    {
                        "id": 2,
                        "title": "WAF Blocks",
                        "type": "graph",
                        "targets": [
                            {
                                "expr": "rate(waf_requests_blocked[5m])",
                                "legendFormat": "{{type}}"
                            }
                        ],
                        "gridPos": {"h": 9, "w": 12, "x": 12, "y": 0}
                    }
                ],
                "time": {"from": "now-1h", "to": "now"},
                "refresh": "10s"
            }
        }
        
        with open(dashboard_json, 'w') as f:
            json.dump(dashboard, f, indent=2)
            
        print(f"📊 Created Grafana configuration")
        print(f"{Colors.OKGREEN}✅ Monitoring stack configuration ready{Colors.ENDC}")
        return True
        
    def generate_ssl_certificates(self):
        """Generate self-signed SSL certificates for testing"""
        print(f"\n{Colors.OKCYAN}🔒 Generating SSL certificates...{Colors.ENDC}")
        
        ssl_dir = self.project_root / "ssl"
        ssl_dir.mkdir(exist_ok=True)
        
        # Check if openssl is available
        if not shutil.which("openssl"):
            print(f"{Colors.WARNING}⚠️  OpenSSL not found, skipping certificate generation{Colors.ENDC}")
            return False
            
        cert_file = ssl_dir / "server.crt"
        key_file = ssl_dir / "server.key"
        
        if cert_file.exists() and key_file.exists():
            print(f"{Colors.OKGREEN}✅ SSL certificates already exist{Colors.ENDC}")
            return True
            
        # Generate private key
        subprocess.run([
            "openssl", "genpkey", "-algorithm", "RSA",
            "-out", str(key_file), "-pkcs8", "-aes256"
        ], input="test123\ntest123\n", text=True, capture_output=True)
        
        # Generate certificate
        subprocess.run([
            "openssl", "req", "-new", "-x509", "-key", str(key_file),
            "-out", str(cert_file), "-days", "365",
            "-subj", "/C=US/ST=Test/L=Test/O=WAF-Test/CN=localhost"
        ], input="test123\n", text=True, capture_output=True)
        
        print(f"🔐 Generated: {key_file}")
        print(f"🔐 Generated: {cert_file}")
        print(f"{Colors.OKGREEN}✅ SSL certificates generated (password: test123){Colors.ENDC}")
        return True
        
    def validate_configuration(self):
        """Validate configuration files"""
        print(f"\n{Colors.OKCYAN}✅ Validating configuration...{Colors.ENDC}")
        
        if not self.config_file.exists():
            print(f"{Colors.FAIL}❌ Configuration file not found: {self.config_file}{Colors.ENDC}")
            return False
            
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f)
                
            # Basic validation
            required_sections = ['server', 'waf', 'proxy', 'logging', 'metrics']
            for section in required_sections:
                if section not in config:
                    print(f"{Colors.FAIL}❌ Missing required section: {section}{Colors.ENDC}")
                    return False
                    
            # Validate server config
            server = config.get('server', {})
            if not isinstance(server.get('port'), int):
                print(f"{Colors.FAIL}❌ Invalid server port configuration{Colors.ENDC}")
                return False
                
            # Validate upstream configs
            upstreams = config.get('proxy', {}).get('upstreams', {})
            if not upstreams:
                print(f"{Colors.WARNING}⚠️  No upstream servers configured{Colors.ENDC}")
                
            for name, upstream in upstreams.items():
                if not upstream.get('servers'):
                    print(f"{Colors.FAIL}❌ Upstream '{name}' has no servers{Colors.ENDC}")
                    return False
                    
            print(f"{Colors.OKGREEN}✅ Configuration validation passed{Colors.ENDC}")
            return True
            
        except yaml.YAMLError as e:
            print(f"{Colors.FAIL}❌ YAML parsing error: {e}{Colors.ENDC}")
            return False
        except Exception as e:
            print(f"{Colors.FAIL}❌ Configuration validation error: {e}{Colors.ENDC}")
            return False
            
    def print_deployment_info(self):
        """Print deployment information and next steps"""
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}🎉 Deployment setup complete!{Colors.ENDC}")
        
        print(f"\n{Colors.HEADER}🐳 Docker Deployment:{Colors.ENDC}")
        print("   docker-compose up -d              # Start all services")
        print("   docker-compose down               # Stop all services")
        print("   docker-compose logs -f waf-proxy  # View logs")
        
        print(f"\n{Colors.HEADER}☸️  Kubernetes Deployment:{Colors.ENDC}")
        print("   kubectl apply -f k8s/             # Deploy to cluster")
        print("   kubectl get pods                  # Check pod status")
        print("   kubectl logs -l app=waf-reverse-proxy  # View logs")
        
        print(f"\n{Colors.HEADER}📊 Access Points:{Colors.ENDC}")
        print("   • Main Proxy: http://localhost:8080")
        print("   • Admin API: http://localhost:8081/api")
        print("   • Metrics: http://localhost:9090/metrics")
        print("   • Grafana: http://localhost:3000 (admin/admin123)")
        print("   • Prometheus: http://localhost:9091")
        
        print(f"\n{Colors.HEADER}🧪 Testing:{Colors.ENDC}")
        print("   curl http://localhost:8080/health")
        print("   curl http://localhost:8081/api/status")
        print("   curl http://localhost:8080/admin   # Should be blocked")
        
def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="WAF + Reverse Proxy Deployment Setup")
    parser.add_argument("--docker", action="store_true", help="Set up Docker deployment")
    parser.add_argument("--kubernetes", action="store_true", help="Generate Kubernetes manifests")
    parser.add_argument("--monitor", action="store_true", help="Set up monitoring stack")
    parser.add_argument("--ssl", action="store_true", help="Generate SSL certificates")
    parser.add_argument("--validate", action="store_true", help="Validate configuration")
    parser.add_argument("--all", action="store_true", help="Run all setup tasks")
    
    args = parser.parse_args()
    
    if not any([args.docker, args.kubernetes, args.monitor, args.ssl, args.validate, args.all]):
        parser.print_help()
        return
        
    setup = DeploymentSetup()
    setup.print_header()
    
    success = True
    
    if args.all or args.validate:
        success &= setup.validate_configuration()
        
    if args.all or args.docker:
        success &= setup.setup_docker_deployment()
        
    if args.all or args.kubernetes:
        success &= setup.generate_kubernetes_manifests()
        
    if args.all or args.monitor:
        success &= setup.setup_monitoring_stack()
        
    if args.all or args.ssl:
        setup.generate_ssl_certificates()  # Optional, don't fail on this
        
    if success:
        setup.print_deployment_info()
    else:
        print(f"\n{Colors.FAIL}❌ Some setup tasks failed{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
