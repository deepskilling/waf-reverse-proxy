"""
PyWAF Metrics Collection

Prometheus-compatible metrics collection for monitoring WAF and proxy performance.
"""

import asyncio
import time
import psutil
from typing import Dict, List, Optional, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field

from prometheus_client import (
    Counter as PrometheusCounter, 
    Histogram, 
    Gauge, 
    CollectorRegistry,
    generate_latest,
    CONTENT_TYPE_LATEST
)

from ..core.config import Config


@dataclass
class MetricData:
    """Individual metric data point"""
    name: str
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class MetricsCollector:
    """Main metrics collection system"""
    
    def __init__(self, config: Config):
        self.config = config
        self.registry = CollectorRegistry()
        
        # Initialize metrics
        self._init_prometheus_metrics()
        
        # Custom metrics storage
        self.custom_metrics = {}
        self.metric_history = defaultdict(list)
        
        # Statistics
        self.start_time = time.time()
        self.request_stats = {
            "total_requests": 0,
            "total_responses": 0,
            "total_errors": 0,
            "methods": Counter(),
            "status_codes": Counter(),
            "response_times": [],
        }
        
        # System metrics
        self.process = psutil.Process()
    
    def _init_prometheus_metrics(self):
        """Initialize Prometheus metrics"""
        
        # Request metrics
        self.http_requests_total = PrometheusCounter(
            'pywaf_http_requests_total',
            'Total HTTP requests',
            ['method', 'status', 'endpoint'],
            registry=self.registry
        )
        
        self.http_request_duration_seconds = Histogram(
            'pywaf_http_request_duration_seconds',
            'HTTP request duration in seconds',
            ['method', 'endpoint'],
            registry=self.registry
        )
        
        # WAF metrics
        self.waf_requests_total = PrometheusCounter(
            'pywaf_waf_requests_total',
            'Total requests processed by WAF',
            ['action', 'rule'],
            registry=self.registry
        )
        
        self.waf_blocks_total = PrometheusCounter(
            'pywaf_waf_blocks_total',
            'Total requests blocked by WAF',
            ['rule', 'client_ip'],
            registry=self.registry
        )
        
        # Rate limiting metrics
        self.rate_limit_hits_total = PrometheusCounter(
            'pywaf_rate_limit_hits_total',
            'Total rate limit hits',
            ['limit_type', 'client_ip'],
            registry=self.registry
        )
        
        # SSL metrics
        self.ssl_certificates_total = Gauge(
            'pywaf_ssl_certificates_total',
            'Total SSL certificates',
            registry=self.registry
        )
        
        self.ssl_certificates_expiring = Gauge(
            'pywaf_ssl_certificates_expiring',
            'SSL certificates expiring within 30 days',
            registry=self.registry
        )
        
        # Proxy metrics
        self.proxy_upstream_requests_total = PrometheusCounter(
            'pywaf_proxy_upstream_requests_total',
            'Total upstream requests',
            ['upstream', 'server', 'status'],
            registry=self.registry
        )
        
        self.proxy_upstream_response_time_seconds = Histogram(
            'pywaf_proxy_upstream_response_time_seconds',
            'Upstream response time in seconds',
            ['upstream', 'server'],
            registry=self.registry
        )
        
        # Cache metrics
        self.cache_requests_total = PrometheusCounter(
            'pywaf_cache_requests_total',
            'Total cache requests',
            ['result'],  # hit, miss
            registry=self.registry
        )
        
        self.cache_size_bytes = Gauge(
            'pywaf_cache_size_bytes',
            'Cache size in bytes',
            registry=self.registry
        )
        
        # System metrics
        self.system_cpu_usage = Gauge(
            'pywaf_system_cpu_usage_percent',
            'CPU usage percentage',
            registry=self.registry
        )
        
        self.system_memory_usage = Gauge(
            'pywaf_system_memory_usage_bytes',
            'Memory usage in bytes',
            registry=self.registry
        )
        
        self.system_connections_active = Gauge(
            'pywaf_system_connections_active',
            'Active network connections',
            registry=self.registry
        )
    
    async def initialize(self):
        """Initialize metrics collector"""
        # Start system metrics collection
        import asyncio
        asyncio.create_task(self._collect_system_metrics())
    
    async def _collect_system_metrics(self):
        """Collect system metrics periodically"""
        while True:
            try:
                # CPU usage
                cpu_percent = self.process.cpu_percent()
                self.system_cpu_usage.set(cpu_percent)
                
                # Memory usage
                memory_info = self.process.memory_info()
                self.system_memory_usage.set(memory_info.rss)
                
                # Network connections
                connections = len(self.process.connections())
                self.system_connections_active.set(connections)
                
                await asyncio.sleep(10)  # Collect every 10 seconds
                
            except Exception as e:
                print(f"Error collecting system metrics: {e}")
                await asyncio.sleep(10)
    
    async def record_request(self, method: str, path: str, status_code: int, response_time: float):
        """Record HTTP request metrics"""
        # Update counters
        self.request_stats["total_requests"] += 1
        self.request_stats["methods"][method] += 1
        self.request_stats["status_codes"][status_code] += 1
        self.request_stats["response_times"].append(response_time)
        
        # Limit response times history
        if len(self.request_stats["response_times"]) > 1000:
            self.request_stats["response_times"] = self.request_stats["response_times"][-1000:]
        
        # Update Prometheus metrics
        endpoint = self._normalize_endpoint(path)
        status = str(status_code)
        
        self.http_requests_total.labels(method=method, status=status, endpoint=endpoint).inc()
        self.http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(response_time)
    
    def _normalize_endpoint(self, path: str) -> str:
        """Normalize endpoint path for metrics"""
        # Remove query parameters
        path = path.split('?')[0]
        
        # Normalize common patterns
        import re
        
        # Replace UUIDs
        path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{uuid}', path, flags=re.IGNORECASE)
        
        # Replace numeric IDs
        path = re.sub(r'/\d+', '/{id}', path)
        
        return path
    
    async def record_waf_event(self, action: str, rule: Optional[str] = None, client_ip: Optional[str] = None):
        """Record WAF event metrics"""
        rule = rule or "unknown"
        self.waf_requests_total.labels(action=action, rule=rule).inc()
        
        if action == "block" and client_ip:
            self.waf_blocks_total.labels(rule=rule, client_ip=client_ip).inc()
    
    async def record_rate_limit_event(self, limit_type: str, client_ip: str):
        """Record rate limiting event"""
        self.rate_limit_hits_total.labels(limit_type=limit_type, client_ip=client_ip).inc()
    
    async def record_ssl_metrics(self, total_certs: int, expiring_certs: int):
        """Record SSL certificate metrics"""
        self.ssl_certificates_total.set(total_certs)
        self.ssl_certificates_expiring.set(expiring_certs)
    
    async def record_upstream_request(self, upstream: str, server: str, status: str, response_time: float):
        """Record upstream request metrics"""
        self.proxy_upstream_requests_total.labels(upstream=upstream, server=server, status=status).inc()
        self.proxy_upstream_response_time_seconds.labels(upstream=upstream, server=server).observe(response_time)
    
    async def record_cache_event(self, result: str, size_bytes: int = 0):
        """Record cache event metrics"""
        self.cache_requests_total.labels(result=result).inc()
        if size_bytes > 0:
            self.cache_size_bytes.set(size_bytes)
    
    def add_custom_metric(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Add custom metric"""
        metric = MetricData(
            name=name,
            value=value,
            labels=labels or {},
            timestamp=time.time()
        )
        
        if name not in self.custom_metrics:
            self.custom_metrics[name] = []
        
        self.custom_metrics[name].append(metric)
        
        # Keep only recent metrics (last 1000)
        if len(self.custom_metrics[name]) > 1000:
            self.custom_metrics[name] = self.custom_metrics[name][-1000:]
    
    async def generate_metrics(self) -> str:
        """Generate Prometheus metrics output"""
        return generate_latest(self.registry).decode('utf-8')
    
    def get_content_type(self) -> str:
        """Get metrics content type"""
        return CONTENT_TYPE_LATEST
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detailed statistics"""
        current_time = time.time()
        uptime = current_time - self.start_time
        
        # Calculate average response time
        avg_response_time = 0.0
        if self.request_stats["response_times"]:
            avg_response_time = sum(self.request_stats["response_times"]) / len(self.request_stats["response_times"])
        
        # Calculate request rate (requests per second)
        request_rate = self.request_stats["total_requests"] / uptime if uptime > 0 else 0
        
        # Get system info
        try:
            system_info = {
                "cpu_percent": self.process.cpu_percent(),
                "memory_info": self.process.memory_info()._asdict(),
                "connections": len(self.process.connections()),
                "threads": self.process.num_threads(),
                "fd_count": self.process.num_fds() if hasattr(self.process, 'num_fds') else None,
            }
        except Exception:
            system_info = {}
        
        return {
            "uptime_seconds": uptime,
            "requests": {
                "total": self.request_stats["total_requests"],
                "rate_per_second": round(request_rate, 2),
                "average_response_time_ms": round(avg_response_time * 1000, 2),
                "methods": dict(self.request_stats["methods"]),
                "status_codes": dict(self.request_stats["status_codes"]),
            },
            "system": system_info,
            "custom_metrics": {
                name: len(metrics) for name, metrics in self.custom_metrics.items()
            },
            "prometheus_metrics": {
                "families": len(list(self.registry.collect())),
                "samples": sum(len(list(family.samples)) for family in self.registry.collect()),
            }
        }
    
    def get_health_metrics(self) -> Dict[str, Any]:
        """Get metrics for health checking"""
        current_time = time.time()
        uptime = current_time - self.start_time
        
        # Calculate error rate
        total_requests = self.request_stats["total_requests"]
        error_requests = sum(
            count for status, count in self.request_stats["status_codes"].items()
            if int(status) >= 500
        )
        error_rate = (error_requests / total_requests * 100) if total_requests > 0 else 0
        
        # Calculate recent response time (last 100 requests)
        recent_response_times = self.request_stats["response_times"][-100:]
        avg_recent_response_time = (
            sum(recent_response_times) / len(recent_response_times)
            if recent_response_times else 0
        )
        
        # System health indicators
        try:
            cpu_percent = self.process.cpu_percent()
            memory_info = self.process.memory_info()
            memory_percent = (memory_info.rss / (1024 * 1024 * 1024))  # GB
        except Exception:
            cpu_percent = 0
            memory_percent = 0
        
        return {
            "uptime": uptime,
            "error_rate_percent": round(error_rate, 2),
            "avg_response_time_ms": round(avg_recent_response_time * 1000, 2),
            "cpu_percent": round(cpu_percent, 2),
            "memory_gb": round(memory_percent, 2),
            "total_requests": total_requests,
            "recent_requests": len(recent_response_times)
        }
    
    async def cleanup(self):
        """Cleanup metrics collector"""
        # Clear metrics
        self.custom_metrics.clear()
        self.metric_history.clear()
        self.request_stats = {
            "total_requests": 0,
            "total_responses": 0,
            "total_errors": 0,
            "methods": Counter(),
            "status_codes": Counter(),
            "response_times": [],
        }
