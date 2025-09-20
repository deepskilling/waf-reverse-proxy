"""
Health Monitor for WAF + Reverse Proxy

Provides comprehensive health checking and monitoring capabilities
for the WAF and Reverse Proxy service.
"""

import asyncio
import time
import socket
import ssl
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from urllib.parse import urlparse

import requests
import aiohttp


class HealthStatus(Enum):
    """Health status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"  
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a health check"""
    name: str
    status: HealthStatus
    response_time: float
    message: str
    timestamp: datetime
    details: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        result['status'] = self.status.value
        result['timestamp'] = self.timestamp.isoformat()
        return result


@dataclass
class ServiceHealth:
    """Overall service health summary"""
    overall_status: HealthStatus
    checks: List[HealthCheckResult]
    uptime: float
    last_updated: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'overall_status': self.overall_status.value,
            'checks': [check.to_dict() for check in self.checks],
            'uptime': self.uptime,
            'last_updated': self.last_updated.isoformat()
        }


class HealthMonitor:
    """
    Comprehensive health monitor for WAF + Reverse Proxy
    
    Performs various health checks including:
    - Service endpoint availability
    - Admin API health
    - Proxy functionality
    - SSL certificate status
    - Resource utilization
    - Database connectivity
    """
    
    def __init__(
        self,
        service_url: str = "http://localhost:8080",
        admin_url: str = "http://localhost:8081",
        timeout: int = 30,
        ssl_verify: bool = True
    ):
        """
        Initialize health monitor
        
        Args:
            service_url: Main service URL
            admin_url: Admin API URL
            timeout: Request timeout in seconds
            ssl_verify: Whether to verify SSL certificates
        """
        self.service_url = service_url.rstrip('/')
        self.admin_url = admin_url.rstrip('/')
        self.timeout = timeout
        self.ssl_verify = ssl_verify
        
        # Parse URLs
        self.service_parsed = urlparse(self.service_url)
        self.admin_parsed = urlparse(self.admin_url)
        
        # Health check results history
        self.results_history: List[ServiceHealth] = []
        self.max_history = 100
        
        # Start time for uptime calculation
        self.start_time = datetime.now()
    
    def check_all(self, include_optional: bool = True) -> ServiceHealth:
        """
        Perform all health checks
        
        Args:
            include_optional: Whether to include optional checks
            
        Returns:
            Overall service health status
        """
        checks = []
        
        # Core checks
        checks.append(self.check_service_port())
        checks.append(self.check_admin_port())
        checks.append(self.check_admin_health())
        checks.append(self.check_proxy_functionality())
        
        if include_optional:
            checks.append(self.check_ssl_status())
            checks.append(self.check_metrics_endpoint())
            checks.append(self.check_resource_usage())
        
        # Determine overall status
        overall_status = self._calculate_overall_status(checks)
        
        # Create service health summary
        uptime = (datetime.now() - self.start_time).total_seconds()
        
        service_health = ServiceHealth(
            overall_status=overall_status,
            checks=checks,
            uptime=uptime,
            last_updated=datetime.now()
        )
        
        # Store in history
        self.results_history.append(service_health)
        if len(self.results_history) > self.max_history:
            self.results_history = self.results_history[-self.max_history:]
        
        return service_health
    
    def check_service_port(self) -> HealthCheckResult:
        """Check if main service port is accessible"""
        start_time = time.time()
        
        try:
            host = self.service_parsed.hostname or 'localhost'
            port = self.service_parsed.port or (443 if self.service_parsed.scheme == 'https' else 80)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            response_time = time.time() - start_time
            
            if result == 0:
                return HealthCheckResult(
                    name="service_port",
                    status=HealthStatus.HEALTHY,
                    response_time=response_time,
                    message=f"Service port {port} is accessible",
                    timestamp=datetime.now(),
                    details={'host': host, 'port': port}
                )
            else:
                return HealthCheckResult(
                    name="service_port",
                    status=HealthStatus.UNHEALTHY,
                    response_time=response_time,
                    message=f"Cannot connect to service port {port}",
                    timestamp=datetime.now(),
                    details={'host': host, 'port': port, 'error_code': result}
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="service_port",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message=f"Service port check failed: {str(e)}",
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    def check_admin_port(self) -> HealthCheckResult:
        """Check if admin API port is accessible"""
        start_time = time.time()
        
        try:
            host = self.admin_parsed.hostname or 'localhost'
            port = self.admin_parsed.port or (443 if self.admin_parsed.scheme == 'https' else 80)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            response_time = time.time() - start_time
            
            if result == 0:
                return HealthCheckResult(
                    name="admin_port",
                    status=HealthStatus.HEALTHY,
                    response_time=response_time,
                    message=f"Admin port {port} is accessible",
                    timestamp=datetime.now(),
                    details={'host': host, 'port': port}
                )
            else:
                return HealthCheckResult(
                    name="admin_port",
                    status=HealthStatus.UNHEALTHY,
                    response_time=response_time,
                    message=f"Cannot connect to admin port {port}",
                    timestamp=datetime.now(),
                    details={'host': host, 'port': port, 'error_code': result}
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="admin_port",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message=f"Admin port check failed: {str(e)}",
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    def check_admin_health(self) -> HealthCheckResult:
        """Check admin API health endpoint"""
        start_time = time.time()
        
        try:
            response = requests.get(
                f"{self.admin_url}/api/v1/health",
                timeout=self.timeout,
                verify=self.ssl_verify
            )
            
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()
                status = data.get('status', 'unknown')
                
                if status == 'healthy':
                    health_status = HealthStatus.HEALTHY
                elif status == 'degraded':
                    health_status = HealthStatus.DEGRADED
                else:
                    health_status = HealthStatus.UNHEALTHY
                
                return HealthCheckResult(
                    name="admin_health",
                    status=health_status,
                    response_time=response_time,
                    message=f"Admin API reports status: {status}",
                    timestamp=datetime.now(),
                    details=data
                )
            else:
                return HealthCheckResult(
                    name="admin_health",
                    status=HealthStatus.UNHEALTHY,
                    response_time=response_time,
                    message=f"Admin health endpoint returned HTTP {response.status_code}",
                    timestamp=datetime.now(),
                    details={'status_code': response.status_code}
                )
                
        except requests.exceptions.Timeout:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="admin_health",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message="Admin health check timed out",
                timestamp=datetime.now(),
                details={'timeout': self.timeout}
            )
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="admin_health",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message=f"Admin health check failed: {str(e)}",
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    def check_proxy_functionality(self) -> HealthCheckResult:
        """Check if proxy is forwarding requests properly"""
        start_time = time.time()
        
        try:
            # Try to make a request through the proxy
            response = requests.get(
                f"{self.service_url}/health",  # Health endpoint on main service
                timeout=self.timeout,
                verify=self.ssl_verify,
                headers={'User-Agent': 'WAF-Health-Check/1.0'}
            )
            
            response_time = time.time() - start_time
            
            if response.status_code in [200, 404]:  # 404 is OK if no health endpoint
                return HealthCheckResult(
                    name="proxy_functionality",
                    status=HealthStatus.HEALTHY,
                    response_time=response_time,
                    message="Proxy is forwarding requests",
                    timestamp=datetime.now(),
                    details={
                        'status_code': response.status_code,
                        'headers': dict(response.headers)
                    }
                )
            else:
                return HealthCheckResult(
                    name="proxy_functionality",
                    status=HealthStatus.DEGRADED,
                    response_time=response_time,
                    message=f"Proxy returned unexpected status: {response.status_code}",
                    timestamp=datetime.now(),
                    details={'status_code': response.status_code}
                )
                
        except requests.exceptions.Timeout:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="proxy_functionality",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message="Proxy functionality check timed out",
                timestamp=datetime.now(),
                details={'timeout': self.timeout}
            )
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="proxy_functionality",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message=f"Proxy functionality check failed: {str(e)}",
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    def check_ssl_status(self) -> HealthCheckResult:
        """Check SSL certificate status"""
        start_time = time.time()
        
        try:
            if self.service_parsed.scheme != 'https':
                return HealthCheckResult(
                    name="ssl_status",
                    status=HealthStatus.HEALTHY,
                    response_time=0.0,
                    message="SSL not configured (HTTP service)",
                    timestamp=datetime.now(),
                    details={'ssl_enabled': False}
                )
            
            host = self.service_parsed.hostname or 'localhost'
            port = self.service_parsed.port or 443
            
            # Get SSL certificate info
            context = ssl.create_default_context()
            if not self.ssl_verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            
            response_time = time.time() - start_time
            
            if cert:
                # Check certificate expiration
                not_after = cert.get('notAfter')
                if not_after:
                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (expiry - datetime.now()).days
                    
                    if days_until_expiry > 30:
                        status = HealthStatus.HEALTHY
                        message = f"SSL certificate valid for {days_until_expiry} more days"
                    elif days_until_expiry > 7:
                        status = HealthStatus.DEGRADED
                        message = f"SSL certificate expires in {days_until_expiry} days"
                    else:
                        status = HealthStatus.UNHEALTHY
                        message = f"SSL certificate expires in {days_until_expiry} days"
                    
                    return HealthCheckResult(
                        name="ssl_status",
                        status=status,
                        response_time=response_time,
                        message=message,
                        timestamp=datetime.now(),
                        details={
                            'certificate': cert,
                            'expires': not_after,
                            'days_until_expiry': days_until_expiry
                        }
                    )
            
            return HealthCheckResult(
                name="ssl_status",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message="Could not retrieve SSL certificate information",
                timestamp=datetime.now(),
                details={}
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="ssl_status",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message=f"SSL status check failed: {str(e)}",
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    def check_metrics_endpoint(self) -> HealthCheckResult:
        """Check Prometheus metrics endpoint"""
        start_time = time.time()
        
        try:
            response = requests.get(
                f"{self.admin_url}/metrics",
                timeout=self.timeout,
                verify=self.ssl_verify
            )
            
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                metrics_text = response.text
                # Basic validation that it looks like Prometheus metrics
                if '# HELP' in metrics_text or '# TYPE' in metrics_text:
                    return HealthCheckResult(
                        name="metrics_endpoint",
                        status=HealthStatus.HEALTHY,
                        response_time=response_time,
                        message="Metrics endpoint is responding with valid data",
                        timestamp=datetime.now(),
                        details={
                            'metrics_size': len(metrics_text),
                            'line_count': len(metrics_text.splitlines())
                        }
                    )
                else:
                    return HealthCheckResult(
                        name="metrics_endpoint",
                        status=HealthStatus.DEGRADED,
                        response_time=response_time,
                        message="Metrics endpoint responding but content may be invalid",
                        timestamp=datetime.now(),
                        details={'content_size': len(metrics_text)}
                    )
            else:
                return HealthCheckResult(
                    name="metrics_endpoint",
                    status=HealthStatus.UNHEALTHY,
                    response_time=response_time,
                    message=f"Metrics endpoint returned HTTP {response.status_code}",
                    timestamp=datetime.now(),
                    details={'status_code': response.status_code}
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="metrics_endpoint",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message=f"Metrics endpoint check failed: {str(e)}",
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    def check_resource_usage(self) -> HealthCheckResult:
        """Check system resource usage"""
        start_time = time.time()
        
        try:
            # Get stats from admin API if available
            response = requests.get(
                f"{self.admin_url}/api/v1/stats",
                timeout=self.timeout,
                verify=self.ssl_verify
            )
            
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                stats = response.json()
                
                # Analyze resource usage
                status = HealthStatus.HEALTHY
                issues = []
                
                # Check memory usage
                memory_mb = stats.get('memory_mb', 0)
                if memory_mb > 1024:  # > 1GB
                    status = HealthStatus.DEGRADED
                    issues.append(f"High memory usage: {memory_mb:.1f}MB")
                
                # Check CPU usage
                cpu_percent = stats.get('cpu_percent', 0)
                if cpu_percent > 80:
                    status = HealthStatus.DEGRADED
                    issues.append(f"High CPU usage: {cpu_percent:.1f}%")
                
                message = "Resource usage is normal"
                if issues:
                    message = "; ".join(issues)
                
                return HealthCheckResult(
                    name="resource_usage",
                    status=status,
                    response_time=response_time,
                    message=message,
                    timestamp=datetime.now(),
                    details=stats
                )
            else:
                return HealthCheckResult(
                    name="resource_usage",
                    status=HealthStatus.UNKNOWN,
                    response_time=response_time,
                    message="Could not retrieve resource usage stats",
                    timestamp=datetime.now(),
                    details={'status_code': response.status_code}
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="resource_usage",
                status=HealthStatus.UNKNOWN,
                response_time=response_time,
                message=f"Resource usage check failed: {str(e)}",
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    def _calculate_overall_status(self, checks: List[HealthCheckResult]) -> HealthStatus:
        """Calculate overall status from individual checks"""
        if not checks:
            return HealthStatus.UNKNOWN
        
        statuses = [check.status for check in checks]
        
        # If any check is unhealthy, overall is unhealthy
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        
        # If any check is degraded, overall is degraded
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        
        # If all checks are healthy, overall is healthy
        if all(status == HealthStatus.HEALTHY for status in statuses):
            return HealthStatus.HEALTHY
        
        # Otherwise, unknown
        return HealthStatus.UNKNOWN
    
    def get_health_history(self, minutes: int = 60) -> List[ServiceHealth]:
        """
        Get health check history
        
        Args:
            minutes: Number of minutes of history to return
            
        Returns:
            List of health check results
        """
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return [
            health for health in self.results_history
            if health.last_updated >= cutoff
        ]
    
    def get_uptime_percentage(self, hours: int = 24) -> float:
        """
        Calculate uptime percentage over specified period
        
        Args:
            hours: Number of hours to calculate over
            
        Returns:
            Uptime percentage (0.0 to 100.0)
        """
        cutoff = datetime.now() - timedelta(hours=hours)
        recent_results = [
            health for health in self.results_history
            if health.last_updated >= cutoff
        ]
        
        if not recent_results:
            return 100.0  # Assume healthy if no data
        
        healthy_count = sum(
            1 for health in recent_results
            if health.overall_status == HealthStatus.HEALTHY
        )
        
        return (healthy_count / len(recent_results)) * 100.0
    
    def generate_health_report(self, include_history: bool = False) -> Dict[str, Any]:
        """
        Generate comprehensive health report
        
        Args:
            include_history: Whether to include historical data
            
        Returns:
            Health report dictionary
        """
        current_health = self.check_all()
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'current_status': current_health.to_dict(),
            'uptime_24h': self.get_uptime_percentage(24),
            'uptime_7d': self.get_uptime_percentage(24 * 7),
            'service_info': {
                'service_url': self.service_url,
                'admin_url': self.admin_url,
                'monitor_uptime': current_health.uptime
            }
        }
        
        if include_history:
            report['history'] = {
                'last_hour': [h.to_dict() for h in self.get_health_history(60)],
                'last_24h': [h.to_dict() for h in self.get_health_history(24 * 60)]
            }
        
        return report


# Async version for integration with async applications
class AsyncHealthMonitor:
    """Async version of HealthMonitor"""
    
    def __init__(self, **kwargs):
        self.service_url = kwargs.get('service_url', 'http://localhost:8080').rstrip('/')
        self.admin_url = kwargs.get('admin_url', 'http://localhost:8081').rstrip('/')
        self.timeout = kwargs.get('timeout', 30)
        self.ssl_verify = kwargs.get('ssl_verify', True)
        
        self.service_parsed = urlparse(self.service_url)
        self.admin_parsed = urlparse(self.admin_url)
        self.start_time = datetime.now()
    
    async def check_all(self, include_optional: bool = True) -> ServiceHealth:
        """Perform all health checks asynchronously"""
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Run checks concurrently
            tasks = [
                self._check_admin_health_async(session),
                self._check_proxy_functionality_async(session),
                self._check_metrics_endpoint_async(session)
            ]
            
            checks = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Filter out exceptions and convert to results
            valid_checks = []
            for check in checks:
                if isinstance(check, HealthCheckResult):
                    valid_checks.append(check)
                elif isinstance(check, Exception):
                    # Create error result
                    valid_checks.append(HealthCheckResult(
                        name="async_check_error",
                        status=HealthStatus.UNHEALTHY,
                        response_time=0.0,
                        message=f"Async check failed: {str(check)}",
                        timestamp=datetime.now(),
                        details={'error': str(check)}
                    ))
            
            overall_status = self._calculate_overall_status(valid_checks)
            uptime = (datetime.now() - self.start_time).total_seconds()
            
            return ServiceHealth(
                overall_status=overall_status,
                checks=valid_checks,
                uptime=uptime,
                last_updated=datetime.now()
            )
    
    async def _check_admin_health_async(self, session: aiohttp.ClientSession) -> HealthCheckResult:
        """Async admin health check"""
        start_time = time.time()
        
        try:
            async with session.get(f"{self.admin_url}/api/v1/health") as response:
                response_time = time.time() - start_time
                
                if response.status == 200:
                    data = await response.json()
                    status = data.get('status', 'unknown')
                    
                    if status == 'healthy':
                        health_status = HealthStatus.HEALTHY
                    elif status == 'degraded':
                        health_status = HealthStatus.DEGRADED
                    else:
                        health_status = HealthStatus.UNHEALTHY
                    
                    return HealthCheckResult(
                        name="admin_health_async",
                        status=health_status,
                        response_time=response_time,
                        message=f"Admin API reports status: {status}",
                        timestamp=datetime.now(),
                        details=data
                    )
                else:
                    return HealthCheckResult(
                        name="admin_health_async",
                        status=HealthStatus.UNHEALTHY,
                        response_time=response_time,
                        message=f"Admin health endpoint returned HTTP {response.status}",
                        timestamp=datetime.now(),
                        details={'status_code': response.status}
                    )
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="admin_health_async",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message=f"Admin health check failed: {str(e)}",
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    async def _check_proxy_functionality_async(self, session: aiohttp.ClientSession) -> HealthCheckResult:
        """Async proxy functionality check"""
        start_time = time.time()
        
        try:
            async with session.get(
                f"{self.service_url}/health",
                headers={'User-Agent': 'WAF-Health-Check-Async/1.0'}
            ) as response:
                response_time = time.time() - start_time
                
                if response.status in [200, 404]:
                    return HealthCheckResult(
                        name="proxy_functionality_async",
                        status=HealthStatus.HEALTHY,
                        response_time=response_time,
                        message="Proxy is forwarding requests",
                        timestamp=datetime.now(),
                        details={'status_code': response.status}
                    )
                else:
                    return HealthCheckResult(
                        name="proxy_functionality_async",
                        status=HealthStatus.DEGRADED,
                        response_time=response_time,
                        message=f"Proxy returned unexpected status: {response.status}",
                        timestamp=datetime.now(),
                        details={'status_code': response.status}
                    )
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="proxy_functionality_async",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message=f"Proxy functionality check failed: {str(e)}",
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    async def _check_metrics_endpoint_async(self, session: aiohttp.ClientSession) -> HealthCheckResult:
        """Async metrics endpoint check"""
        start_time = time.time()
        
        try:
            async with session.get(f"{self.admin_url}/metrics") as response:
                response_time = time.time() - start_time
                
                if response.status == 200:
                    metrics_text = await response.text()
                    
                    if '# HELP' in metrics_text or '# TYPE' in metrics_text:
                        return HealthCheckResult(
                            name="metrics_endpoint_async",
                            status=HealthStatus.HEALTHY,
                            response_time=response_time,
                            message="Metrics endpoint is responding with valid data",
                            timestamp=datetime.now(),
                            details={
                                'metrics_size': len(metrics_text),
                                'line_count': len(metrics_text.splitlines())
                            }
                        )
                    else:
                        return HealthCheckResult(
                            name="metrics_endpoint_async",
                            status=HealthStatus.DEGRADED,
                            response_time=response_time,
                            message="Metrics endpoint responding but content may be invalid",
                            timestamp=datetime.now(),
                            details={'content_size': len(metrics_text)}
                        )
                else:
                    return HealthCheckResult(
                        name="metrics_endpoint_async",
                        status=HealthStatus.UNHEALTHY,
                        response_time=response_time,
                        message=f"Metrics endpoint returned HTTP {response.status}",
                        timestamp=datetime.now(),
                        details={'status_code': response.status}
                    )
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckResult(
                name="metrics_endpoint_async",
                status=HealthStatus.UNHEALTHY,
                response_time=response_time,
                message=f"Metrics endpoint check failed: {str(e)}",
                timestamp=datetime.now(),
                details={'error': str(e)}
            )
    
    def _calculate_overall_status(self, checks: List[HealthCheckResult]) -> HealthStatus:
        """Calculate overall status from individual checks"""
        if not checks:
            return HealthStatus.UNKNOWN
        
        statuses = [check.status for check in checks]
        
        if HealthStatus.UNHEALTHY in statuses:
            return HealthStatus.UNHEALTHY
        
        if HealthStatus.DEGRADED in statuses:
            return HealthStatus.DEGRADED
        
        if all(status == HealthStatus.HEALTHY for status in statuses):
            return HealthStatus.HEALTHY
        
        return HealthStatus.UNKNOWN
