"""
PyWAF Health Checking System

Comprehensive health checking for all system components.
"""

import asyncio
import time
import json
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

import httpx
import redis.asyncio as redis

from ..core.config import Config
from ..core.exceptions import HealthCheckError


class HealthStatus(str, Enum):
    """Health status values"""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Individual health check result"""
    name: str
    status: HealthStatus
    message: str = ""
    duration_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "duration_ms": round(self.duration_ms, 2),
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }


@dataclass
class OverallHealth:
    """Overall system health status"""
    status: HealthStatus
    message: str
    timestamp: float
    uptime: float
    checks: List[HealthCheckResult]
    summary: Dict[str, int]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "status": self.status.value,
            "message": self.message,
            "timestamp": self.timestamp,
            "uptime": round(self.uptime, 2),
            "summary": self.summary,
            "checks": [check.to_dict() for check in self.checks]
        }


class HealthChecker:
    """Main health checking system"""
    
    def __init__(self, config: Config):
        self.config = config
        self.start_time = time.time()
        
        # Health check functions
        self.health_checks: Dict[str, Callable] = {}
        
        # Health check history
        self.check_history: Dict[str, List[HealthCheckResult]] = {}
        self.max_history_size = 100
        
        # Register built-in health checks
        self._register_builtin_checks()
    
    def _register_builtin_checks(self):
        """Register built-in health checks"""
        self.health_checks["system"] = self._check_system_health
        self.health_checks["database"] = self._check_database_health
        self.health_checks["redis"] = self._check_redis_health
        self.health_checks["ssl"] = self._check_ssl_health
        self.health_checks["upstreams"] = self._check_upstream_health
        self.health_checks["disk_space"] = self._check_disk_space
        self.health_checks["memory"] = self._check_memory_usage
    
    def register_health_check(self, name: str, check_func: Callable):
        """Register custom health check"""
        self.health_checks[name] = check_func
    
    def unregister_health_check(self, name: str):
        """Unregister health check"""
        self.health_checks.pop(name, None)
        self.check_history.pop(name, None)
    
    async def run_health_check(self, name: str) -> HealthCheckResult:
        """Run individual health check"""
        if name not in self.health_checks:
            return HealthCheckResult(
                name=name,
                status=HealthStatus.UNKNOWN,
                message=f"Health check '{name}' not found"
            )
        
        start_time = time.time()
        
        try:
            check_func = self.health_checks[name]
            result = await check_func()
            
            duration = (time.time() - start_time) * 1000  # Convert to ms
            result.duration_ms = duration
            result.timestamp = time.time()
            
            # Store in history
            self._store_check_result(result)
            
            return result
            
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            
            result = HealthCheckResult(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                duration_ms=duration
            )
            
            self._store_check_result(result)
            return result
    
    def _store_check_result(self, result: HealthCheckResult):
        """Store health check result in history"""
        if result.name not in self.check_history:
            self.check_history[result.name] = []
        
        self.check_history[result.name].append(result)
        
        # Limit history size
        if len(self.check_history[result.name]) > self.max_history_size:
            self.check_history[result.name] = self.check_history[result.name][-self.max_history_size:]
    
    async def check_all_health(self) -> OverallHealth:
        """Run all health checks and determine overall health"""
        results = []
        
        # Run all registered health checks
        for name in self.health_checks:
            result = await self.run_health_check(name)
            results.append(result)
        
        # Determine overall status
        overall_status = self._determine_overall_status(results)
        
        # Create summary
        summary = {
            "healthy": sum(1 for r in results if r.status == HealthStatus.HEALTHY),
            "unhealthy": sum(1 for r in results if r.status == HealthStatus.UNHEALTHY),
            "degraded": sum(1 for r in results if r.status == HealthStatus.DEGRADED),
            "unknown": sum(1 for r in results if r.status == HealthStatus.UNKNOWN),
            "total": len(results)
        }
        
        # Create overall health message
        if overall_status == HealthStatus.HEALTHY:
            message = "All systems operational"
        elif overall_status == HealthStatus.DEGRADED:
            message = f"{summary['degraded']} systems degraded, {summary['unhealthy']} systems unhealthy"
        elif overall_status == HealthStatus.UNHEALTHY:
            unhealthy_checks = [r.name for r in results if r.status == HealthStatus.UNHEALTHY]
            message = f"System unhealthy. Failed checks: {', '.join(unhealthy_checks)}"
        else:
            message = "System status unknown"
        
        return OverallHealth(
            status=overall_status,
            message=message,
            timestamp=time.time(),
            uptime=time.time() - self.start_time,
            checks=results,
            summary=summary
        )
    
    def _determine_overall_status(self, results: List[HealthCheckResult]) -> HealthStatus:
        """Determine overall health status from individual results"""
        if not results:
            return HealthStatus.UNKNOWN
        
        # Count statuses
        statuses = [r.status for r in results]
        
        unhealthy_count = statuses.count(HealthStatus.UNHEALTHY)
        degraded_count = statuses.count(HealthStatus.DEGRADED)
        healthy_count = statuses.count(HealthStatus.HEALTHY)
        
        # Determine overall status based on business logic
        if unhealthy_count > 0:
            # Any unhealthy check makes the whole system unhealthy
            return HealthStatus.UNHEALTHY
        elif degraded_count > 0:
            # Any degraded check makes the system degraded
            return HealthStatus.DEGRADED
        elif healthy_count == len(results):
            # All checks healthy
            return HealthStatus.HEALTHY
        else:
            # Mixed or unknown statuses
            return HealthStatus.UNKNOWN
    
    async def check_overall_health(self) -> Dict[str, Any]:
        """Get overall health status (simplified for endpoints)"""
        overall_health = await self.check_all_health()
        return overall_health.to_dict()
    
    # Built-in health checks
    
    async def _check_system_health(self) -> HealthCheckResult:
        """Check system resource health"""
        try:
            import psutil
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Disk usage
            disk = psutil.disk_usage('/')
            
            # Determine status based on usage thresholds
            issues = []
            status = HealthStatus.HEALTHY
            
            if cpu_percent > 90:
                issues.append(f"High CPU usage: {cpu_percent}%")
                status = HealthStatus.UNHEALTHY
            elif cpu_percent > 80:
                issues.append(f"Elevated CPU usage: {cpu_percent}%")
                status = HealthStatus.DEGRADED
            
            if memory.percent > 95:
                issues.append(f"Critical memory usage: {memory.percent}%")
                status = HealthStatus.UNHEALTHY
            elif memory.percent > 85:
                issues.append(f"High memory usage: {memory.percent}%")
                status = HealthStatus.DEGRADED
            
            if disk.percent > 95:
                issues.append(f"Critical disk usage: {disk.percent}%")
                status = HealthStatus.UNHEALTHY
            elif disk.percent > 85:
                issues.append(f"High disk usage: {disk.percent}%")
                status = HealthStatus.DEGRADED
            
            message = "; ".join(issues) if issues else "System resources normal"
            
            return HealthCheckResult(
                name="system",
                status=status,
                message=message,
                metadata={
                    "cpu_percent": round(cpu_percent, 2),
                    "memory_percent": round(memory.percent, 2),
                    "disk_percent": round(disk.percent, 2),
                    "load_avg": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="system",
                status=HealthStatus.UNKNOWN,
                message=f"Cannot check system health: {str(e)}"
            )
    
    async def _check_database_health(self) -> HealthCheckResult:
        """Check database connection health"""
        try:
            # For this example, we'll assume SQLite
            # In production, you'd check your actual database
            import sqlite3
            import tempfile
            
            # Test database connection
            with tempfile.NamedTemporaryFile(suffix='.db') as tmp:
                conn = sqlite3.connect(tmp.name)
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
                conn.close()
                
                if result and result[0] == 1:
                    return HealthCheckResult(
                        name="database",
                        status=HealthStatus.HEALTHY,
                        message="Database connection OK"
                    )
                else:
                    return HealthCheckResult(
                        name="database",
                        status=HealthStatus.UNHEALTHY,
                        message="Database query failed"
                    )
        
        except Exception as e:
            return HealthCheckResult(
                name="database",
                status=HealthStatus.UNHEALTHY,
                message=f"Database connection failed: {str(e)}"
            )
    
    async def _check_redis_health(self) -> HealthCheckResult:
        """Check Redis connection health"""
        try:
            if not hasattr(self.config.proxy.cache, 'redis_url') or not self.config.proxy.cache.redis_url:
                return HealthCheckResult(
                    name="redis",
                    status=HealthStatus.HEALTHY,
                    message="Redis not configured (optional)"
                )
            
            redis_client = redis.from_url(self.config.proxy.cache.redis_url)
            
            # Test connection
            await redis_client.ping()
            
            # Get info
            info = await redis_client.info()
            
            await redis_client.close()
            
            return HealthCheckResult(
                name="redis",
                status=HealthStatus.HEALTHY,
                message="Redis connection OK",
                metadata={
                    "connected_clients": info.get("connected_clients", 0),
                    "used_memory": info.get("used_memory", 0),
                    "uptime_in_seconds": info.get("uptime_in_seconds", 0)
                }
            )
        
        except Exception as e:
            return HealthCheckResult(
                name="redis",
                status=HealthStatus.UNHEALTHY,
                message=f"Redis connection failed: {str(e)}"
            )
    
    async def _check_ssl_health(self) -> HealthCheckResult:
        """Check SSL certificate health"""
        try:
            if not self.config.ssl.enabled:
                return HealthCheckResult(
                    name="ssl",
                    status=HealthStatus.HEALTHY,
                    message="SSL not enabled"
                )
            
            # This would check actual SSL manager status in production
            # For now, simulate the check
            issues = []
            status = HealthStatus.HEALTHY
            
            # Check if SSL is properly configured
            if self.config.ssl.auto_provision:
                if not self.config.ssl.domains:
                    issues.append("No domains configured for auto-provisioning")
                    status = HealthStatus.DEGRADED
                
                if not self.config.ssl.acme_email:
                    issues.append("No ACME email configured")
                    status = HealthStatus.DEGRADED
            else:
                if not self.config.ssl.cert_file or not self.config.ssl.key_file:
                    issues.append("SSL certificate or key file not configured")
                    status = HealthStatus.UNHEALTHY
            
            message = "; ".join(issues) if issues else "SSL configuration OK"
            
            return HealthCheckResult(
                name="ssl",
                status=status,
                message=message,
                metadata={
                    "enabled": self.config.ssl.enabled,
                    "auto_provision": self.config.ssl.auto_provision,
                    "domains": len(self.config.ssl.domains)
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="ssl",
                status=HealthStatus.UNKNOWN,
                message=f"Cannot check SSL health: {str(e)}"
            )
    
    async def _check_upstream_health(self) -> HealthCheckResult:
        """Check upstream server health"""
        try:
            if not self.config.proxy.upstreams:
                return HealthCheckResult(
                    name="upstreams",
                    status=HealthStatus.DEGRADED,
                    message="No upstream servers configured"
                )
            
            total_servers = 0
            healthy_servers = 0
            unhealthy_servers = 0
            
            async with httpx.AsyncClient(timeout=5.0) as client:
                for upstream in self.config.proxy.upstreams:
                    for server in upstream.servers:
                        total_servers += 1
                        
                        try:
                            # Try to connect to upstream server
                            health_url = f"{server.url}/health"
                            response = await client.get(health_url)
                            
                            if response.status_code in [200, 204]:
                                healthy_servers += 1
                            else:
                                unhealthy_servers += 1
                        
                        except Exception:
                            unhealthy_servers += 1
            
            # Determine status
            if healthy_servers == 0:
                status = HealthStatus.UNHEALTHY
                message = f"All {total_servers} upstream servers are unhealthy"
            elif unhealthy_servers > 0:
                status = HealthStatus.DEGRADED
                message = f"{unhealthy_servers} of {total_servers} upstream servers are unhealthy"
            else:
                status = HealthStatus.HEALTHY
                message = f"All {total_servers} upstream servers are healthy"
            
            return HealthCheckResult(
                name="upstreams",
                status=status,
                message=message,
                metadata={
                    "total_servers": total_servers,
                    "healthy_servers": healthy_servers,
                    "unhealthy_servers": unhealthy_servers
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="upstreams",
                status=HealthStatus.UNKNOWN,
                message=f"Cannot check upstream health: {str(e)}"
            )
    
    async def _check_disk_space(self) -> HealthCheckResult:
        """Check disk space health"""
        try:
            import psutil
            
            disk = psutil.disk_usage('/')
            
            if disk.percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Critical disk space: {disk.percent}% used"
            elif disk.percent > 85:
                status = HealthStatus.DEGRADED
                message = f"Low disk space: {disk.percent}% used"
            else:
                status = HealthStatus.HEALTHY
                message = f"Disk space OK: {disk.percent}% used"
            
            return HealthCheckResult(
                name="disk_space",
                status=status,
                message=message,
                metadata={
                    "percent_used": round(disk.percent, 2),
                    "free_gb": round(disk.free / (1024**3), 2),
                    "total_gb": round(disk.total / (1024**3), 2)
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="disk_space",
                status=HealthStatus.UNKNOWN,
                message=f"Cannot check disk space: {str(e)}"
            )
    
    async def _check_memory_usage(self) -> HealthCheckResult:
        """Check memory usage health"""
        try:
            import psutil
            
            memory = psutil.virtual_memory()
            
            if memory.percent > 95:
                status = HealthStatus.UNHEALTHY
                message = f"Critical memory usage: {memory.percent}%"
            elif memory.percent > 85:
                status = HealthStatus.DEGRADED
                message = f"High memory usage: {memory.percent}%"
            else:
                status = HealthStatus.HEALTHY
                message = f"Memory usage OK: {memory.percent}%"
            
            return HealthCheckResult(
                name="memory",
                status=status,
                message=message,
                metadata={
                    "percent_used": round(memory.percent, 2),
                    "available_gb": round(memory.available / (1024**3), 2),
                    "total_gb": round(memory.total / (1024**3), 2)
                }
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="memory",
                status=HealthStatus.UNKNOWN,
                message=f"Cannot check memory usage: {str(e)}"
            )
    
    def get_check_history(self, check_name: str) -> List[Dict[str, Any]]:
        """Get history for specific health check"""
        if check_name not in self.check_history:
            return []
        
        return [result.to_dict() for result in self.check_history[check_name]]
    
    def get_all_check_history(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get history for all health checks"""
        return {
            name: [result.to_dict() for result in results]
            for name, results in self.check_history.items()
        }
    
    def clear_history(self, check_name: Optional[str] = None):
        """Clear health check history"""
        if check_name:
            self.check_history.pop(check_name, None)
        else:
            self.check_history.clear()
