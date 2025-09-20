"""
WAF Proxy Admin API Client

Provides a Python client for interacting with the WAF + Reverse Proxy admin API.
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime, timedelta

import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class WafStats:
    """WAF statistics data structure"""
    total_requests: int
    blocked_requests: int
    allowed_requests: int
    rate_limited: int
    geo_blocked: int
    bot_blocked: int
    owasp_blocked: int
    custom_rule_blocked: int


@dataclass
class ProxyStats:
    """Proxy statistics data structure"""
    total_requests: int
    successful_requests: int
    failed_requests: int
    avg_response_time: float
    cache_hits: int
    cache_misses: int
    upstream_errors: int


@dataclass
class HealthStatus:
    """Health status data structure"""
    status: str
    uptime: float
    version: str
    last_check: datetime
    components: Dict[str, Dict[str, Any]]


class WafProxyError(Exception):
    """Custom exception for WAF Proxy API errors"""
    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[Dict] = None):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class WafProxyClient:
    """
    Python client for WAF + Reverse Proxy admin API
    
    Provides both synchronous and asynchronous methods for interacting
    with the WAF and Reverse Proxy admin endpoints.
    """
    
    def __init__(
        self,
        base_url: str = "http://localhost:8081",
        username: Optional[str] = None,
        password: Optional[str] = None,
        api_token: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        verify_ssl: bool = True
    ):
        """
        Initialize the WAF Proxy client
        
        Args:
            base_url: Base URL of the admin API
            username: Username for basic auth
            password: Password for basic auth
            api_token: JWT token for authentication
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.api_token = api_token
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set authentication
        if api_token:
            self.session.headers.update({'Authorization': f'Bearer {api_token}'})
        elif username and password:
            self.session.auth = (username, password)
    
    def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict:
        """Make HTTP request to the API"""
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            response.raise_for_status()
            
            if response.content:
                return response.json()
            return {}
            
        except requests.exceptions.RequestException as e:
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_data = e.response.json()
                    raise WafProxyError(
                        message=error_data.get('error', {}).get('message', str(e)),
                        status_code=e.response.status_code,
                        details=error_data
                    )
                except ValueError:
                    pass
            raise WafProxyError(f"Request failed: {str(e)}")
    
    # Authentication Methods
    def login(self, username: str, password: str) -> Dict:
        """Login and get JWT token"""
        response = self._make_request(
            'POST', 
            '/api/v1/auth/login',
            data={'username': username, 'password': password}
        )
        
        if 'token' in response:
            self.api_token = response['token']
            self.session.headers.update({'Authorization': f'Bearer {self.api_token}'})
        
        return response
    
    def logout(self) -> Dict:
        """Logout and invalidate token"""
        response = self._make_request('POST', '/api/v1/auth/logout')
        self.api_token = None
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']
        return response
    
    # Health and Status Methods
    def get_health(self) -> HealthStatus:
        """Get overall health status"""
        response = self._make_request('GET', '/api/v1/health')
        return HealthStatus(
            status=response.get('status', 'unknown'),
            uptime=response.get('uptime', 0),
            version=response.get('version', ''),
            last_check=datetime.now(),
            components=response.get('components', {})
        )
    
    def get_status(self) -> Dict:
        """Get detailed system status"""
        return self._make_request('GET', '/api/v1/status')
    
    # Statistics Methods
    def get_waf_stats(self) -> WafStats:
        """Get WAF statistics"""
        response = self._make_request('GET', '/api/v1/stats/waf')
        return WafStats(
            total_requests=response.get('total_requests', 0),
            blocked_requests=response.get('blocked_requests', 0),
            allowed_requests=response.get('allowed_requests', 0),
            rate_limited=response.get('rate_limited', 0),
            geo_blocked=response.get('geo_blocked', 0),
            bot_blocked=response.get('bot_blocked', 0),
            owasp_blocked=response.get('owasp_blocked', 0),
            custom_rule_blocked=response.get('custom_rule_blocked', 0)
        )
    
    def get_proxy_stats(self) -> ProxyStats:
        """Get proxy statistics"""
        response = self._make_request('GET', '/api/v1/stats/proxy')
        return ProxyStats(
            total_requests=response.get('total_requests', 0),
            successful_requests=response.get('successful_requests', 0),
            failed_requests=response.get('failed_requests', 0),
            avg_response_time=response.get('avg_response_time', 0.0),
            cache_hits=response.get('cache_hits', 0),
            cache_misses=response.get('cache_misses', 0),
            upstream_errors=response.get('upstream_errors', 0)
        )
    
    def get_metrics(self) -> Dict:
        """Get Prometheus metrics"""
        return self._make_request('GET', '/metrics')
    
    # Configuration Methods
    def get_config(self) -> Dict:
        """Get current configuration"""
        return self._make_request('GET', '/api/v1/config')
    
    def update_config(self, config: Dict) -> Dict:
        """Update configuration"""
        return self._make_request('PUT', '/api/v1/config', data=config)
    
    def reload_config(self) -> Dict:
        """Reload configuration from file"""
        return self._make_request('POST', '/api/v1/config/reload')
    
    # WAF Rule Management
    def get_waf_rules(self) -> List[Dict]:
        """Get all WAF rules"""
        response = self._make_request('GET', '/api/v1/waf/rules')
        return response.get('rules', [])
    
    def add_waf_rule(self, rule: Dict) -> Dict:
        """Add new WAF rule"""
        return self._make_request('POST', '/api/v1/waf/rules', data=rule)
    
    def update_waf_rule(self, rule_id: str, rule: Dict) -> Dict:
        """Update existing WAF rule"""
        return self._make_request('PUT', f'/api/v1/waf/rules/{rule_id}', data=rule)
    
    def delete_waf_rule(self, rule_id: str) -> Dict:
        """Delete WAF rule"""
        return self._make_request('DELETE', f'/api/v1/waf/rules/{rule_id}')
    
    # IP Management
    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs"""
        response = self._make_request('GET', '/api/v1/waf/blocked-ips')
        return response.get('ips', [])
    
    def block_ip(self, ip: str, reason: str = "", duration: Optional[int] = None) -> Dict:
        """Block an IP address"""
        data = {'ip': ip, 'reason': reason}
        if duration:
            data['duration'] = duration
        return self._make_request('POST', '/api/v1/waf/block-ip', data=data)
    
    def unblock_ip(self, ip: str) -> Dict:
        """Unblock an IP address"""
        return self._make_request('POST', '/api/v1/waf/unblock-ip', data={'ip': ip})
    
    # Upstream Management
    def get_upstreams(self) -> List[Dict]:
        """Get upstream server status"""
        response = self._make_request('GET', '/api/v1/proxy/upstreams')
        return response.get('upstreams', [])
    
    def add_upstream(self, upstream: Dict) -> Dict:
        """Add new upstream server"""
        return self._make_request('POST', '/api/v1/proxy/upstreams', data=upstream)
    
    def update_upstream(self, upstream_id: str, upstream: Dict) -> Dict:
        """Update upstream server"""
        return self._make_request('PUT', f'/api/v1/proxy/upstreams/{upstream_id}', data=upstream)
    
    def remove_upstream(self, upstream_id: str) -> Dict:
        """Remove upstream server"""
        return self._make_request('DELETE', f'/api/v1/proxy/upstreams/{upstream_id}')
    
    # Cache Management  
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        return self._make_request('GET', '/api/v1/cache/stats')
    
    def clear_cache(self, pattern: Optional[str] = None) -> Dict:
        """Clear cache entries"""
        data = {}
        if pattern:
            data['pattern'] = pattern
        return self._make_request('POST', '/api/v1/cache/clear', data=data)
    
    def warm_cache(self, urls: List[str]) -> Dict:
        """Warm cache with specific URLs"""
        return self._make_request('POST', '/api/v1/cache/warm', data={'urls': urls})
    
    # SSL Certificate Management
    def get_ssl_certificates(self) -> List[Dict]:
        """Get SSL certificate information"""
        response = self._make_request('GET', '/api/v1/ssl/certificates')
        return response.get('certificates', [])
    
    def renew_certificate(self, domain: str) -> Dict:
        """Request certificate renewal for domain"""
        return self._make_request('POST', '/api/v1/ssl/renew', data={'domain': domain})
    
    def get_ssl_stats(self) -> Dict:
        """Get SSL/TLS statistics"""
        return self._make_request('GET', '/api/v1/ssl/stats')
    
    # Security Events
    def get_security_events(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Get recent security events"""
        params = {'limit': limit, 'offset': offset}
        response = self._make_request('GET', '/api/v1/security/events', params=params)
        return response.get('events', [])
    
    def get_attack_summary(self, time_range: str = '24h') -> Dict:
        """Get attack summary for time range"""
        params = {'time_range': time_range}
        return self._make_request('GET', '/api/v1/security/attacks', params=params)
    
    # System Control
    def shutdown(self, graceful: bool = True) -> Dict:
        """Shutdown the WAF proxy"""
        data = {'graceful': graceful}
        return self._make_request('POST', '/api/v1/system/shutdown', data=data)
    
    def restart(self) -> Dict:
        """Restart the WAF proxy"""
        return self._make_request('POST', '/api/v1/system/restart')
    
    # Monitoring and Alerting
    def get_alerts(self) -> List[Dict]:
        """Get active alerts"""
        response = self._make_request('GET', '/api/v1/alerts')
        return response.get('alerts', [])
    
    def acknowledge_alert(self, alert_id: str) -> Dict:
        """Acknowledge an alert"""
        return self._make_request('POST', f'/api/v1/alerts/{alert_id}/acknowledge')
    
    # Context manager support
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()


class AsyncWafProxyClient:
    """
    Async version of the WAF Proxy client for use with asyncio
    """
    
    def __init__(self, **kwargs):
        self.base_url = kwargs.get('base_url', 'http://localhost:8081').rstrip('/')
        self.username = kwargs.get('username')
        self.password = kwargs.get('password')
        self.api_token = kwargs.get('api_token')
        self.timeout = kwargs.get('timeout', 30)
        self.verify_ssl = kwargs.get('verify_ssl', True)
        
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
        )
        
        if self.api_token:
            self.session.headers.update({'Authorization': f'Bearer {self.api_token}'})
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def _make_request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict] = None,
        params: Optional[Dict] = None
    ) -> Dict:
        """Make async HTTP request to the API"""
        if not self.session:
            raise WafProxyError("Session not initialized. Use async context manager.")
        
        url = f"{self.base_url}{endpoint}"
        
        try:
            kwargs = {
                'url': url,
                'params': params,
            }
            
            if data:
                kwargs['json'] = data
            
            if self.username and self.password and not self.api_token:
                kwargs['auth'] = aiohttp.BasicAuth(self.username, self.password)
            
            async with self.session.request(method, **kwargs) as response:
                response.raise_for_status()
                
                if response.content_length and response.content_length > 0:
                    return await response.json()
                return {}
                
        except aiohttp.ClientError as e:
            raise WafProxyError(f"Async request failed: {str(e)}")
    
    async def get_health(self) -> HealthStatus:
        """Get overall health status (async)"""
        response = await self._make_request('GET', '/api/v1/health')
        return HealthStatus(
            status=response.get('status', 'unknown'),
            uptime=response.get('uptime', 0),
            version=response.get('version', ''),
            last_check=datetime.now(),
            components=response.get('components', {})
        )
    
    async def get_waf_stats(self) -> WafStats:
        """Get WAF statistics (async)"""
        response = await self._make_request('GET', '/api/v1/stats/waf')
        return WafStats(
            total_requests=response.get('total_requests', 0),
            blocked_requests=response.get('blocked_requests', 0),
            allowed_requests=response.get('allowed_requests', 0),
            rate_limited=response.get('rate_limited', 0),
            geo_blocked=response.get('geo_blocked', 0),
            bot_blocked=response.get('bot_blocked', 0),
            owasp_blocked=response.get('owasp_blocked', 0),
            custom_rule_blocked=response.get('custom_rule_blocked', 0)
        )
    
    # Add other async methods as needed...
