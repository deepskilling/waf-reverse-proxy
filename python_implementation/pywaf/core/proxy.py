"""
PyWAF Reverse Proxy Implementation

High-performance reverse proxy with load balancing, health checks,
caching, and advanced routing capabilities.
"""

import asyncio
import time
import hashlib
import json
import random
from typing import Dict, List, Optional, Any, Tuple, AsyncGenerator
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlparse

import httpx
import redis.asyncio as redis
from fastapi import Request, Response
from fastapi.responses import StreamingResponse

from .config import Config, LoadBalancerAlgorithm
from .exceptions import UpstreamError, UpstreamTimeoutError, CacheError


class UpstreamStatus(str, Enum):
    """Upstream server status"""
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class UpstreamServer:
    """Upstream server representation"""
    name: str
    url: str
    weight: int = 100
    backup: bool = False
    
    # Health status
    status: UpstreamStatus = UpstreamStatus.UNKNOWN
    consecutive_failures: int = 0
    last_failure_time: Optional[datetime] = None
    response_time: float = 0.0
    
    # Statistics
    requests_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    
    def is_available(self) -> bool:
        """Check if server is available for requests"""
        return self.status == UpstreamStatus.HEALTHY and not self.backup
    
    def record_success(self, response_time: float):
        """Record successful request"""
        self.requests_count += 1
        self.success_count += 1
        self.consecutive_failures = 0
        self.response_time = response_time
        self.status = UpstreamStatus.HEALTHY
    
    def record_failure(self):
        """Record failed request"""
        self.requests_count += 1
        self.failure_count += 1
        self.consecutive_failures += 1
        self.last_failure_time = datetime.now()


@dataclass
class Route:
    """Route configuration"""
    path_pattern: str
    upstream_name: str
    host_pattern: Optional[str] = None
    methods: List[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"])
    strip_path: bool = False
    add_headers: Dict[str, str] = field(default_factory=dict)
    remove_headers: List[str] = field(default_factory=list)
    
    def matches(self, method: str, path: str, host: Optional[str] = None) -> bool:
        """Check if route matches request"""
        # Check method
        if method.upper() not in [m.upper() for m in self.methods]:
            return False
        
        # Check path pattern
        import re
        if not re.match(self.path_pattern, path):
            return False
        
        # Check host pattern if specified
        if self.host_pattern and host:
            if not re.match(self.host_pattern, host):
                return False
        
        return True


class LoadBalancer:
    """Load balancing algorithms implementation"""
    
    def __init__(self, algorithm: LoadBalancerAlgorithm):
        self.algorithm = algorithm
        self.current_index = 0
    
    def select_server(self, servers: List[UpstreamServer], client_ip: Optional[str] = None) -> Optional[UpstreamServer]:
        """Select upstream server based on algorithm"""
        available_servers = [s for s in servers if s.is_available()]
        if not available_servers:
            return None
        
        if self.algorithm == LoadBalancerAlgorithm.ROUND_ROBIN:
            return self._round_robin(available_servers)
        elif self.algorithm == LoadBalancerAlgorithm.LEAST_CONNECTIONS:
            return self._least_connections(available_servers)
        elif self.algorithm == LoadBalancerAlgorithm.IP_HASH:
            return self._ip_hash(available_servers, client_ip)
        elif self.algorithm == LoadBalancerAlgorithm.WEIGHTED:
            return self._weighted_random(available_servers)
        elif self.algorithm == LoadBalancerAlgorithm.RANDOM:
            return self._random(available_servers)
        else:
            return self._round_robin(available_servers)
    
    def _round_robin(self, servers: List[UpstreamServer]) -> UpstreamServer:
        """Round-robin load balancing"""
        server = servers[self.current_index % len(servers)]
        self.current_index += 1
        return server
    
    def _least_connections(self, servers: List[UpstreamServer]) -> UpstreamServer:
        """Least connections load balancing"""
        # For this implementation, we'll use request count as a proxy for connections
        return min(servers, key=lambda s: s.requests_count - s.success_count - s.failure_count)
    
    def _ip_hash(self, servers: List[UpstreamServer], client_ip: Optional[str]) -> UpstreamServer:
        """IP hash load balancing"""
        if not client_ip:
            return self._round_robin(servers)
        
        hash_value = int(hashlib.md5(client_ip.encode()).hexdigest(), 16)
        index = hash_value % len(servers)
        return servers[index]
    
    def _weighted_random(self, servers: List[UpstreamServer]) -> UpstreamServer:
        """Weighted random load balancing"""
        weights = [s.weight for s in servers]
        total_weight = sum(weights)
        
        if total_weight == 0:
            return random.choice(servers)
        
        r = random.randint(1, total_weight)
        current_weight = 0
        
        for i, weight in enumerate(weights):
            current_weight += weight
            if r <= current_weight:
                return servers[i]
        
        return servers[-1]  # Fallback
    
    def _random(self, servers: List[UpstreamServer]) -> UpstreamServer:
        """Random load balancing"""
        return random.choice(servers)


class HealthChecker:
    """Health checker for upstream servers"""
    
    def __init__(self, config):
        self.config = config
        self.http_client = httpx.AsyncClient(timeout=30.0)
        self._health_check_tasks = {}
    
    async def start_health_checks(self, upstreams: Dict[str, List[UpstreamServer]]):
        """Start health check tasks for all upstreams"""
        for upstream_name, servers in upstreams.items():
            for server in servers:
                task = asyncio.create_task(self._health_check_loop(server))
                self._health_check_tasks[f"{upstream_name}:{server.name}"] = task
    
    async def stop_health_checks(self):
        """Stop all health check tasks"""
        for task in self._health_check_tasks.values():
            task.cancel()
        
        await asyncio.gather(*self._health_check_tasks.values(), return_exceptions=True)
        self._health_check_tasks.clear()
        await self.http_client.aclose()
    
    async def _health_check_loop(self, server: UpstreamServer):
        """Health check loop for a single server"""
        while True:
            try:
                await asyncio.sleep(30)  # Default health check interval
                await self._check_server_health(server)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Health check error for {server.name}: {e}")
    
    async def _check_server_health(self, server: UpstreamServer):
        """Perform health check on a single server"""
        health_url = urljoin(server.url, "/health")
        
        try:
            start_time = time.time()
            response = await self.http_client.get(health_url, timeout=5.0)
            response_time = time.time() - start_time
            
            if response.status_code in [200, 204]:
                server.record_success(response_time)
                if server.consecutive_failures >= 3:  # Was unhealthy, now healthy
                    print(f"Server {server.name} is now healthy")
            else:
                server.record_failure()
                server.status = UpstreamStatus.UNHEALTHY
                
        except Exception:
            server.record_failure()
            server.status = UpstreamStatus.UNHEALTHY
            
            if server.consecutive_failures >= 3:
                print(f"Server {server.name} marked as unhealthy")


class Cache:
    """Response caching implementation"""
    
    def __init__(self, config, redis_client: Optional[redis.Redis] = None):
        self.config = config
        self.redis_client = redis_client
        self.memory_cache = {}  # Simple in-memory cache
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "evictions": 0
        }
    
    def _generate_cache_key(self, method: str, url: str, headers: Dict[str, str]) -> str:
        """Generate cache key for request"""
        # Include method, URL, and vary headers
        key_parts = [method, url]
        
        # Add vary headers if any are specified for this URL
        vary_headers = self._get_vary_headers(url)
        for header in vary_headers:
            if header.lower() in headers:
                key_parts.append(f"{header}:{headers[header.lower()]}")
        
        key_string = "|".join(key_parts)
        return f"pywaf:cache:{hashlib.sha256(key_string.encode()).hexdigest()[:16]}"
    
    def _get_vary_headers(self, url: str) -> List[str]:
        """Get vary headers for URL based on cache rules"""
        # Check cache rules for matching patterns
        for rule in self.config.proxy.cache.rules:
            import re
            if re.match(rule.pattern, url):
                return rule.vary_headers
        
        return ["accept-encoding"]  # Default vary headers
    
    def _get_ttl(self, url: str, status_code: int) -> int:
        """Get TTL for URL based on cache rules"""
        # Check cache rules for matching patterns
        for rule in self.config.proxy.cache.rules:
            import re
            if re.match(rule.pattern, url):
                if status_code in rule.status_codes:
                    return rule.ttl
        
        return self.config.proxy.cache.default_ttl
    
    def _is_cacheable(self, method: str, status_code: int, url: str) -> bool:
        """Check if response is cacheable"""
        if not self.config.proxy.cache.enabled:
            return False
        
        # Check method
        if method.upper() not in ["GET", "HEAD"]:
            return False
        
        # Check status code
        if status_code not in [200, 301, 302, 404]:
            return False
        
        # Check cache rules
        for rule in self.config.proxy.cache.rules:
            import re
            if re.match(rule.pattern, url):
                return method.upper() in [m.upper() for m in rule.methods] and status_code in rule.status_codes
        
        # Default: cache GET/HEAD 200 responses
        return method.upper() in ["GET", "HEAD"] and status_code == 200
    
    async def get(self, method: str, url: str, headers: Dict[str, str]) -> Optional[Tuple[int, Dict[str, str], bytes]]:
        """Get cached response"""
        if not self.config.proxy.cache.enabled:
            return None
        
        cache_key = self._generate_cache_key(method, url, headers)
        
        try:
            # Try Redis first if available
            if self.redis_client:
                cached_data = await self.redis_client.get(cache_key)
                if cached_data:
                    self.cache_stats["hits"] += 1
                    cache_entry = json.loads(cached_data)
                    return (
                        cache_entry["status_code"],
                        cache_entry["headers"],
                        cache_entry["body"].encode("utf-8")
                    )
            
            # Try memory cache
            if cache_key in self.memory_cache:
                cache_entry = self.memory_cache[cache_key]
                if cache_entry["expires"] > time.time():
                    self.cache_stats["hits"] += 1
                    return (
                        cache_entry["status_code"],
                        cache_entry["headers"],
                        cache_entry["body"]
                    )
                else:
                    # Expired entry
                    del self.memory_cache[cache_key]
                    self.cache_stats["evictions"] += 1
            
            self.cache_stats["misses"] += 1
            return None
            
        except Exception as e:
            print(f"Cache get error: {e}")
            self.cache_stats["misses"] += 1
            return None
    
    async def set(self, method: str, url: str, headers: Dict[str, str], 
                  status_code: int, response_headers: Dict[str, str], body: bytes):
        """Cache response"""
        if not self._is_cacheable(method, status_code, url):
            return
        
        cache_key = self._generate_cache_key(method, url, headers)
        ttl = self._get_ttl(url, status_code)
        
        if ttl <= 0:
            return
        
        try:
            cache_entry = {
                "status_code": status_code,
                "headers": response_headers,
                "body": body.decode("utf-8", errors="ignore"),
                "cached_at": time.time(),
                "expires": time.time() + ttl
            }
            
            # Try Redis first if available
            if self.redis_client:
                await self.redis_client.setex(
                    cache_key, 
                    ttl, 
                    json.dumps(cache_entry, default=str)
                )
            else:
                # Use memory cache with size limit
                if len(self.memory_cache) >= self.config.proxy.cache.max_entries:
                    # Simple LRU eviction - remove oldest entry
                    oldest_key = min(self.memory_cache.keys(), 
                                   key=lambda k: self.memory_cache[k]["cached_at"])
                    del self.memory_cache[oldest_key]
                    self.cache_stats["evictions"] += 1
                
                self.memory_cache[cache_key] = cache_entry
            
            self.cache_stats["sets"] += 1
            
        except Exception as e:
            print(f"Cache set error: {e}")
    
    async def clear(self, pattern: Optional[str] = None):
        """Clear cache entries"""
        if pattern:
            # Clear matching entries
            if self.redis_client:
                keys = await self.redis_client.keys(f"pywaf:cache:*{pattern}*")
                if keys:
                    await self.redis_client.delete(*keys)
            
            # Clear from memory cache
            keys_to_remove = []
            for key in self.memory_cache:
                if pattern in key:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.memory_cache[key]
        else:
            # Clear all
            if self.redis_client:
                keys = await self.redis_client.keys("pywaf:cache:*")
                if keys:
                    await self.redis_client.delete(*keys)
            
            self.memory_cache.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
        hit_rate = (self.cache_stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            **self.cache_stats,
            "hit_rate": round(hit_rate, 2),
            "memory_entries": len(self.memory_cache),
            "memory_size_bytes": sum(len(str(entry)) for entry in self.memory_cache.values())
        }


class ReverseProxy:
    """Main reverse proxy implementation"""
    
    def __init__(self, config: Config):
        self.config = config
        self.upstreams = {}  # upstream_name -> List[UpstreamServer]
        self.routes = []
        self.load_balancers = {}  # upstream_name -> LoadBalancer
        
        # Initialize components
        self.health_checker = HealthChecker(config)
        
        # Initialize cache
        redis_client = None
        if config.proxy.cache.backend in ["redis", "hybrid"] and config.proxy.cache.redis_url:
            try:
                redis_client = redis.from_url(config.proxy.cache.redis_url)
            except Exception as e:
                print(f"Failed to connect to Redis: {e}")
        
        self.cache = Cache(config, redis_client)
        
        # HTTP client for upstream requests
        self.http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=5.0,
                read=30.0,
                write=30.0,
                pool=None
            ),
            limits=httpx.Limits(
                max_keepalive_connections=100,
                max_connections=200
            )
        )
        
        # Statistics - initialize before loading configuration
        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "upstream_errors": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "average_response_time": 0.0,
            "upstreams": {}
        }
        
        # Load configuration
        self._load_upstreams()
        self._load_routes()
    
    def _load_upstreams(self):
        """Load upstream configurations"""
        for upstream_config in self.config.proxy.upstreams:
            servers = []
            
            for server_config in upstream_config.servers:
                server = UpstreamServer(
                    name=f"{upstream_config.name}:{server_config.url}",
                    url=server_config.url,
                    weight=server_config.weight,
                    backup=server_config.backup
                )
                servers.append(server)
            
            self.upstreams[upstream_config.name] = servers
            self.load_balancers[upstream_config.name] = LoadBalancer(upstream_config.algorithm)
            self.stats["upstreams"][upstream_config.name] = {
                "total_requests": 0,
                "successful_requests": 0,
                "failed_requests": 0,
                "healthy_servers": 0,
                "total_servers": len(servers)
            }
    
    def _load_routes(self):
        """Load route configurations"""
        for route_config in self.config.proxy.routes:
            route = Route(
                path_pattern=route_config.path,
                upstream_name=route_config.upstream,
                host_pattern=getattr(route_config, 'host', None),
                methods=route_config.methods,
                strip_path=route_config.strip_path,
                add_headers=route_config.add_headers,
                remove_headers=route_config.remove_headers
            )
            self.routes.append(route)
    
    async def start(self):
        """Start the reverse proxy"""
        await self.health_checker.start_health_checks(self.upstreams)
        print("Reverse proxy started")
    
    async def stop(self):
        """Stop the reverse proxy"""
        await self.health_checker.stop_health_checks()
        await self.http_client.aclose()
        print("Reverse proxy stopped")
    
    def _find_route(self, method: str, path: str, host: Optional[str] = None) -> Optional[Route]:
        """Find matching route for request"""
        for route in self.routes:
            if route.matches(method, path, host):
                return route
        return None
    
    def _select_upstream_server(self, upstream_name: str, client_ip: Optional[str]) -> Optional[UpstreamServer]:
        """Select upstream server for request"""
        if upstream_name not in self.upstreams:
            return None
        
        servers = self.upstreams[upstream_name]
        load_balancer = self.load_balancers[upstream_name]
        
        return load_balancer.select_server(servers, client_ip)
    
    def _build_upstream_url(self, route: Route, server: UpstreamServer, original_path: str) -> str:
        """Build upstream URL"""
        if route.strip_path:
            # Remove the matched path prefix
            import re
            stripped_path = re.sub(f"^{route.path_pattern}", "", original_path)
            path = stripped_path if stripped_path else "/"
        else:
            path = original_path
        
        return urljoin(server.url, path)
    
    def _prepare_upstream_headers(self, route: Route, original_headers: Dict[str, str], 
                                client_ip: str, original_host: str) -> Dict[str, str]:
        """Prepare headers for upstream request"""
        headers = original_headers.copy()
        
        # Remove headers specified in route
        for header in route.remove_headers:
            headers.pop(header.lower(), None)
        
        # Add headers specified in route
        headers.update(route.add_headers)
        
        # Add proxy headers
        headers["x-forwarded-for"] = client_ip
        headers["x-forwarded-host"] = original_host
        headers["x-forwarded-proto"] = "https" if self.config.ssl.enabled else "http"
        headers["x-real-ip"] = client_ip
        
        return headers
    
    async def handle_request(self, request: Request) -> Response:
        """Handle incoming request"""
        self.stats["total_requests"] += 1
        start_time = time.time()
        
        try:
            # Get request details
            method = request.method
            path = str(request.url.path)
            query = str(request.url.query) if request.url.query else ""
            host = request.headers.get("host", "")
            client_ip = request.client.host if request.client else "unknown"
            
            full_url = f"{path}?{query}" if query else path
            
            # Check cache first
            cached_response = await self.cache.get(method, full_url, dict(request.headers))
            if cached_response:
                status_code, headers, body = cached_response
                self.stats["cache_hits"] += 1
                self.cache.cache_stats["hits"] += 1
                
                return Response(
                    content=body,
                    status_code=status_code,
                    headers=headers
                )
            
            self.cache.cache_stats["misses"] += 1
            
            # Find route
            route = self._find_route(method, path, host)
            if not route:
                # Use default upstream if configured
                if self.config.proxy.default_upstream:
                    upstream_name = self.config.proxy.default_upstream
                else:
                    return Response(
                        content=json.dumps({"error": "No route found"}),
                        status_code=404,
                        media_type="application/json"
                    )
            else:
                upstream_name = route.upstream_name
            
            # Select upstream server
            server = self._select_upstream_server(upstream_name, client_ip)
            if not server:
                self.stats["failed_requests"] += 1
                self.stats["upstream_errors"] += 1
                
                raise UpstreamError(
                    f"No healthy upstream servers available for {upstream_name}",
                    upstream_name=upstream_name
                )
            
            # Build upstream URL
            if route:
                upstream_url = self._build_upstream_url(route, server, path)
            else:
                upstream_url = urljoin(server.url, path)
            
            if query:
                upstream_url += f"?{query}"
            
            # Prepare headers
            if route:
                upstream_headers = self._prepare_upstream_headers(route, dict(request.headers), client_ip, host)
            else:
                upstream_headers = dict(request.headers)
                upstream_headers["x-forwarded-for"] = client_ip
                upstream_headers["x-real-ip"] = client_ip
            
            # Get request body if present
            body = None
            if method.upper() in ["POST", "PUT", "PATCH"]:
                body = await request.body()
            
            # Make upstream request
            try:
                upstream_start = time.time()
                
                upstream_response = await self.http_client.request(
                    method=method,
                    url=upstream_url,
                    headers=upstream_headers,
                    content=body,
                    timeout=30.0
                )
                
                upstream_time = time.time() - upstream_start
                server.record_success(upstream_time)
                
                # Update statistics
                self.stats["successful_requests"] += 1
                self.stats["upstreams"][upstream_name]["successful_requests"] += 1
                self.stats["upstreams"][upstream_name]["total_requests"] += 1
                
                # Prepare response
                response_headers = dict(upstream_response.headers)
                response_body = upstream_response.content
                status_code = upstream_response.status_code
                
                # Cache response if cacheable
                await self.cache.set(
                    method, full_url, dict(request.headers),
                    status_code, response_headers, response_body
                )
                
                # Update average response time
                total_time = time.time() - start_time
                self.stats["average_response_time"] = (
                    (self.stats["average_response_time"] * (self.stats["total_requests"] - 1) + total_time)
                    / self.stats["total_requests"]
                )
                
                return Response(
                    content=response_body,
                    status_code=status_code,
                    headers=response_headers
                )
                
            except httpx.TimeoutException:
                server.record_failure()
                self.stats["failed_requests"] += 1
                self.stats["upstream_errors"] += 1
                self.stats["upstreams"][upstream_name]["failed_requests"] += 1
                self.stats["upstreams"][upstream_name]["total_requests"] += 1
                
                raise UpstreamTimeoutError(
                    f"Upstream server timeout: {server.url}",
                    upstream_name=upstream_name,
                    upstream_url=server.url,
                    timeout_duration=30.0
                )
            
            except httpx.RequestError as e:
                server.record_failure()
                self.stats["failed_requests"] += 1
                self.stats["upstream_errors"] += 1
                self.stats["upstreams"][upstream_name]["failed_requests"] += 1
                self.stats["upstreams"][upstream_name]["total_requests"] += 1
                
                raise UpstreamError(
                    f"Upstream request failed: {str(e)}",
                    upstream_name=upstream_name,
                    upstream_url=server.url,
                    cause=e
                )
        
        except (UpstreamError, UpstreamTimeoutError):
            # Re-raise upstream errors
            raise
        except Exception as e:
            self.stats["failed_requests"] += 1
            
            # Return generic error
            return Response(
                content=json.dumps({
                    "error": "Internal proxy error",
                    "message": str(e)
                }),
                status_code=500,
                media_type="application/json"
            )
    
    async def handle_streaming_request(self, request: Request) -> StreamingResponse:
        """Handle streaming request (for large uploads/downloads)"""
        # Implementation for streaming requests
        # This would be used for file uploads, websockets, etc.
        pass
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get proxy statistics"""
        # Update upstream health statistics
        for upstream_name, servers in self.upstreams.items():
            healthy_servers = sum(1 for s in servers if s.is_available())
            self.stats["upstreams"][upstream_name]["healthy_servers"] = healthy_servers
        
        # Add cache statistics
        cache_stats = self.cache.get_stats()
        self.stats["cache_hits"] = cache_stats["hits"]
        self.stats["cache_misses"] = cache_stats["misses"]
        
        return self.stats.copy()
    
    def get_upstream_status(self) -> Dict[str, Any]:
        """Get detailed upstream status"""
        status = {}
        
        for upstream_name, servers in self.upstreams.items():
            server_status = []
            for server in servers:
                server_status.append({
                    "name": server.name,
                    "url": server.url,
                    "status": server.status.value,
                    "weight": server.weight,
                    "backup": server.backup,
                    "consecutive_failures": server.consecutive_failures,
                    "last_failure_time": server.last_failure_time.isoformat() if server.last_failure_time else None,
                    "response_time": server.response_time,
                    "requests_count": server.requests_count,
                    "success_count": server.success_count,
                    "failure_count": server.failure_count,
                    "success_rate": (server.success_count / server.requests_count * 100) if server.requests_count > 0 else 0
                })
            
            status[upstream_name] = {
                "algorithm": self.load_balancers[upstream_name].algorithm.value,
                "servers": server_status,
                "healthy_servers": sum(1 for s in servers if s.is_available()),
                "total_servers": len(servers)
            }
        
        return status
