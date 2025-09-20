"""
PyWAF Engine - Web Application Firewall Implementation

Main WAF engine that coordinates all security protection mechanisms including
OWASP Top 10 protection, bot detection, rate limiting, geo-blocking, and custom rules.
"""

import re
import json
import time
import asyncio
import ipaddress
from typing import Dict, List, Optional, Any, Tuple, Pattern
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

import geoip2.database
import geoip2.errors
from fastapi import Request
from limits import RateLimitItem, parse
from limits.storage import RedisStorage, MemoryStorage
from limits.strategies import MovingWindowRateLimiter

from .config import Config, WAFMode
from .exceptions import (
    SecurityError, RateLimitError, IPBlockedError, 
    GeoBlockedError, BotDetectedError, PyWAFError
)


class WAFAction(str, Enum):
    """WAF actions"""
    ALLOW = "allow"
    BLOCK = "block"
    MONITOR = "monitor"
    LOG = "log"
    CHALLENGE = "challenge"


class ThreatLevel(str, Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium" 
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class WAFResult:
    """Result of WAF inspection"""
    action: WAFAction
    threat_level: ThreatLevel
    rule_name: Optional[str] = None
    confidence: float = 0.0
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def should_block(self) -> bool:
        """Check if request should be blocked"""
        return self.action in [WAFAction.BLOCK, WAFAction.CHALLENGE]


@dataclass
class RequestContext:
    """Request context for WAF analysis"""
    client_ip: str
    user_agent: str
    method: str
    path: str
    query_string: str
    headers: Dict[str, str]
    body: Optional[bytes] = None
    content_type: Optional[str] = None
    country_code: Optional[str] = None
    
    @classmethod
    def from_request(cls, request: Request) -> "RequestContext":
        """Create context from FastAPI request"""
        # Get real client IP (considering proxies)
        client_ip = cls._get_real_ip(request)
        
        return cls(
            client_ip=client_ip,
            user_agent=request.headers.get("user-agent", ""),
            method=request.method,
            path=str(request.url.path),
            query_string=str(request.url.query) if request.url.query else "",
            headers=dict(request.headers),
            content_type=request.headers.get("content-type"),
        )
    
    @staticmethod
    def _get_real_ip(request: Request) -> str:
        """Extract real client IP considering proxies"""
        # Check various headers for real IP
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
        
        forwarded = request.headers.get("forwarded")
        if forwarded:
            # Parse Forwarded header (RFC 7239)
            for part in forwarded.split(","):
                if "for=" in part:
                    ip = part.split("for=")[1].split(";")[0].strip('"')
                    return ip
        
        # Fallback to direct connection
        return request.client.host if request.client else "unknown"


class OwaspProtector:
    """OWASP Top 10 protection implementation"""
    
    def __init__(self, config):
        self.config = config
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for attack detection"""
        
        # SQL Injection patterns
        self.sql_patterns = [
            re.compile(r"(\'|\")[\s]*(\bor\b|\band\b)[\s]*(\\'|\")[\s]*=[\s]*(\\'|\")", re.IGNORECASE),
            re.compile(r"\bunion\b[\s]+\bselect\b", re.IGNORECASE),
            re.compile(r"\bselect\b[\s]+.*\bfrom\b", re.IGNORECASE),
            re.compile(r"\binsert\b[\s]+\binto\b", re.IGNORECASE),
            re.compile(r"\bdelete\b[\s]+\bfrom\b", re.IGNORECASE),
            re.compile(r"\bdrop\b[\s]+\btable\b", re.IGNORECASE),
            re.compile(r"\bexec\b[\s]*\(", re.IGNORECASE),
            re.compile(r"benchmark\s*\(", re.IGNORECASE),
            re.compile(r"sleep\s*\(", re.IGNORECASE),
            re.compile(r"waitfor\s+delay", re.IGNORECASE),
            re.compile(r"0x[0-9a-f]+", re.IGNORECASE),
            re.compile(r"(\'|\")[^\'\"]*\1[\s]*;", re.IGNORECASE),
        ]
        
        # XSS patterns
        self.xss_patterns = [
            re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
            re.compile(r"<script[^>]*>", re.IGNORECASE),
            re.compile(r"</script>", re.IGNORECASE),
            re.compile(r"javascript:", re.IGNORECASE),
            re.compile(r"vbscript:", re.IGNORECASE),
            re.compile(r"on\w+\s*=", re.IGNORECASE),
            re.compile(r"<iframe[^>]*>", re.IGNORECASE),
            re.compile(r"<object[^>]*>", re.IGNORECASE),
            re.compile(r"<embed[^>]*>", re.IGNORECASE),
            re.compile(r"<applet[^>]*>", re.IGNORECASE),
            re.compile(r"eval\s*\(", re.IGNORECASE),
            re.compile(r"expression\s*\(", re.IGNORECASE),
            re.compile(r"document\.cookie", re.IGNORECASE),
            re.compile(r"document\.location", re.IGNORECASE),
        ]
        
        # RCE patterns
        self.rce_patterns = [
            re.compile(r"(\||&|;|\$\(|\`)\s*(cat|ls|id|whoami|ps|uname|pwd)", re.IGNORECASE),
            re.compile(r"system\s*\(", re.IGNORECASE),
            re.compile(r"exec\s*\(", re.IGNORECASE),
            re.compile(r"shell_exec\s*\(", re.IGNORECASE),
            re.compile(r"passthru\s*\(", re.IGNORECASE),
            re.compile(r"proc_open\s*\(", re.IGNORECASE),
            re.compile(r"Runtime\.getRuntime\(\)\.exec", re.IGNORECASE),
            re.compile(r"subprocess\.(run|call|check_output)", re.IGNORECASE),
            re.compile(r"os\.system\s*\(", re.IGNORECASE),
            re.compile(r"child_process\.(exec|spawn)", re.IGNORECASE),
        ]
        
        # Path traversal patterns  
        self.path_traversal_patterns = [
            re.compile(r"\.\./", re.IGNORECASE),
            re.compile(r"\.\.\\", re.IGNORECASE),
            re.compile(r"%2e%2e%2f", re.IGNORECASE),
            re.compile(r"%2e%2e%5c", re.IGNORECASE),
            re.compile(r"(%252e){2}(%252f|%255c)", re.IGNORECASE),
            re.compile(r"/etc/passwd", re.IGNORECASE),
            re.compile(r"/windows/win\.ini", re.IGNORECASE),
            re.compile(r"/proc/self/environ", re.IGNORECASE),
        ]
    
    def check_sql_injection(self, context: RequestContext) -> Optional[WAFResult]:
        """Check for SQL injection attempts"""
        if not self.config.waf.owasp_protection.sql_injection:
            return None
        
        confidence = 0.0
        matched_patterns = []
        
        # Check URL, query string, and body
        check_strings = [context.path, context.query_string]
        if context.body:
            try:
                check_strings.append(context.body.decode('utf-8', errors='ignore'))
            except:
                pass
        
        for text in check_strings:
            for pattern in self.sql_patterns:
                if pattern.search(text):
                    confidence += 0.3
                    matched_patterns.append(pattern.pattern)
        
        # Check headers
        for header_value in context.headers.values():
            for pattern in self.sql_patterns:
                if pattern.search(header_value):
                    confidence += 0.2
                    matched_patterns.append(f"header:{pattern.pattern}")
        
        if confidence >= self.config.waf.owasp_protection.sql_injection_threshold:
            return WAFResult(
                action=WAFAction.BLOCK,
                threat_level=ThreatLevel.HIGH,
                rule_name="sql_injection",
                confidence=min(confidence, 1.0),
                message="SQL injection attempt detected",
                metadata={
                    "attack_type": "sql_injection",
                    "matched_patterns": matched_patterns[:5],  # Limit output
                    "client_ip": context.client_ip
                }
            )
        
        return None
    
    def check_xss(self, context: RequestContext) -> Optional[WAFResult]:
        """Check for XSS attempts"""
        if not self.config.waf.owasp_protection.xss_protection:
            return None
        
        confidence = 0.0
        matched_patterns = []
        
        # Check URL, query string, and body
        check_strings = [context.path, context.query_string]
        if context.body:
            try:
                check_strings.append(context.body.decode('utf-8', errors='ignore'))
            except:
                pass
        
        for text in check_strings:
            for pattern in self.xss_patterns:
                if pattern.search(text):
                    confidence += 0.3
                    matched_patterns.append(pattern.pattern)
        
        # Check headers (especially user-agent, referer)
        for header_name, header_value in context.headers.items():
            if header_name.lower() in ['user-agent', 'referer', 'origin']:
                for pattern in self.xss_patterns:
                    if pattern.search(header_value):
                        confidence += 0.4
                        matched_patterns.append(f"{header_name}:{pattern.pattern}")
        
        if confidence >= self.config.waf.owasp_protection.xss_threshold:
            return WAFResult(
                action=WAFAction.BLOCK,
                threat_level=ThreatLevel.HIGH,
                rule_name="xss_protection",
                confidence=min(confidence, 1.0),
                message="Cross-site scripting (XSS) attempt detected",
                metadata={
                    "attack_type": "xss",
                    "matched_patterns": matched_patterns[:5],
                    "client_ip": context.client_ip
                }
            )
        
        return None
    
    def check_rce(self, context: RequestContext) -> Optional[WAFResult]:
        """Check for Remote Code Execution attempts"""
        if not self.config.waf.owasp_protection.rce_protection:
            return None
        
        confidence = 0.0
        matched_patterns = []
        
        # Check URL, query string, and body
        check_strings = [context.path, context.query_string]
        if context.body:
            try:
                check_strings.append(context.body.decode('utf-8', errors='ignore'))
            except:
                pass
        
        for text in check_strings:
            for pattern in self.rce_patterns:
                if pattern.search(text):
                    confidence += 0.4
                    matched_patterns.append(pattern.pattern)
        
        if confidence >= self.config.waf.owasp_protection.rce_threshold:
            return WAFResult(
                action=WAFAction.BLOCK,
                threat_level=ThreatLevel.CRITICAL,
                rule_name="rce_protection",
                confidence=min(confidence, 1.0),
                message="Remote code execution attempt detected",
                metadata={
                    "attack_type": "rce",
                    "matched_patterns": matched_patterns[:5],
                    "client_ip": context.client_ip
                }
            )
        
        return None
    
    def check_path_traversal(self, context: RequestContext) -> Optional[WAFResult]:
        """Check for path traversal attempts"""
        if not self.config.waf.owasp_protection.path_traversal:
            return None
        
        confidence = 0.0
        matched_patterns = []
        
        # Check path and query string
        check_strings = [context.path, context.query_string]
        
        for text in check_strings:
            for pattern in self.path_traversal_patterns:
                if pattern.search(text):
                    confidence += 0.5
                    matched_patterns.append(pattern.pattern)
        
        if confidence >= self.config.waf.owasp_protection.path_traversal_threshold:
            return WAFResult(
                action=WAFAction.BLOCK,
                threat_level=ThreatLevel.HIGH,
                rule_name="path_traversal",
                confidence=min(confidence, 1.0),
                message="Path traversal attempt detected",
                metadata={
                    "attack_type": "path_traversal",
                    "matched_patterns": matched_patterns[:5],
                    "client_ip": context.client_ip
                }
            )
        
        return None
    
    def check_csrf(self, context: RequestContext) -> Optional[WAFResult]:
        """Check for CSRF attacks"""
        if not self.config.waf.owasp_protection.csrf_protection:
            return None
        
        # Only check state-changing methods
        if context.method.upper() not in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return None
        
        confidence = 0.0
        issues = []
        
        # Check for CSRF token
        csrf_token = None
        
        # Check headers
        csrf_headers = ['x-csrf-token', 'x-xsrf-token', 'csrf-token']
        for header in csrf_headers:
            if header in context.headers:
                csrf_token = context.headers[header]
                break
        
        # Check for referer header
        referer = context.headers.get('referer', '')
        origin = context.headers.get('origin', '')
        
        if not csrf_token:
            confidence += 0.3
            issues.append("missing_csrf_token")
        
        if not referer and not origin:
            confidence += 0.4
            issues.append("missing_referer_origin")
        
        # Check content type for forms
        content_type = context.content_type or ""
        if "application/x-www-form-urlencoded" in content_type and not csrf_token:
            confidence += 0.3
            issues.append("form_without_csrf")
        
        if confidence >= self.config.waf.owasp_protection.csrf_threshold:
            return WAFResult(
                action=WAFAction.BLOCK,
                threat_level=ThreatLevel.MEDIUM,
                rule_name="csrf_protection",
                confidence=min(confidence, 1.0),
                message="Potential CSRF attack detected",
                metadata={
                    "attack_type": "csrf",
                    "issues": issues,
                    "client_ip": context.client_ip
                }
            )
        
        return None


class RateLimiter:
    """Advanced rate limiting implementation"""
    
    def __init__(self, config, redis_url: Optional[str] = None):
        self.config = config
        
        # Initialize storage backend
        if redis_url:
            self.storage = RedisStorage(redis_url)
        else:
            self.storage = MemoryStorage()
        
        self.limiter = MovingWindowRateLimiter(self.storage)
        
        # Compile rate limits
        self.global_limits = self._compile_rate_limits(config.waf.rate_limiting.global_limit)
        self.per_ip_limits = self._compile_rate_limits(config.waf.rate_limiting.per_ip)
        self.per_endpoint_limits = self._compile_rate_limits(config.waf.rate_limiting.per_endpoint)
    
    def _compile_rate_limits(self, rate_config) -> List[RateLimitItem]:
        """Compile rate limit configuration to limits"""
        if not rate_config:
            return []
        
        limits = []
        
        if rate_config.requests_per_second:
            limits.append(parse(f"{rate_config.requests_per_second}/second"))
        
        if rate_config.requests_per_minute:
            limits.append(parse(f"{rate_config.requests_per_minute}/minute"))
        
        if rate_config.requests_per_hour:
            limits.append(parse(f"{rate_config.requests_per_hour}/hour"))
        
        return limits
    
    def check_global_limit(self) -> bool:
        """Check global rate limit"""
        if not self.global_limits:
            return True
        
        for limit in self.global_limits:
            if not self.limiter.hit(limit, "global"):
                return False
        
        return True
    
    def check_ip_limit(self, client_ip: str) -> bool:
        """Check per-IP rate limit"""
        if not self.per_ip_limits:
            return True
        
        for limit in self.per_ip_limits:
            if not self.limiter.hit(limit, f"ip:{client_ip}"):
                return False
        
        return True
    
    def check_endpoint_limit(self, endpoint: str) -> bool:
        """Check per-endpoint rate limit"""
        if not self.per_endpoint_limits:
            return True
        
        for limit in self.per_endpoint_limits:
            if not self.limiter.hit(limit, f"endpoint:{endpoint}"):
                return False
        
        return True
    
    def get_retry_after(self, client_ip: str) -> Optional[int]:
        """Get retry-after time for rate limited IP"""
        if not self.per_ip_limits:
            return None
        
        # Get the limit with the longest window
        max_window = 0
        for limit in self.per_ip_limits:
            window = limit.per
            if window > max_window:
                max_window = window
        
        return max_window


class BotDetector:
    """Bot detection and protection"""
    
    def __init__(self, config):
        self.config = config
        self._compile_bot_patterns()
        
        # Behavioral tracking
        self.request_patterns = {}  # IP -> request patterns
        self.suspicious_ips = set()
        self.known_bots = set()
    
    def _compile_bot_patterns(self):
        """Compile bot detection patterns"""
        
        # Known bot user agents
        self.bot_patterns = [
            re.compile(r"bot|crawler|spider|scraper", re.IGNORECASE),
            re.compile(r"googlebot|bingbot|yahoobot", re.IGNORECASE),
            re.compile(r"curl|wget|python|java|perl|php", re.IGNORECASE),
            re.compile(r"scanner|probe|test|monitor", re.IGNORECASE),
            re.compile(r"automated|headless", re.IGNORECASE),
        ]
        
        # Suspicious patterns
        self.suspicious_patterns = [
            re.compile(r"^$"),  # Empty user agent
            re.compile(r"^Mozilla/4\.0$"),  # Minimal user agent
            re.compile(r"libwww|mechanize|scrapy", re.IGNORECASE),
        ]
    
    def analyze_user_agent(self, user_agent: str) -> Tuple[float, str]:
        """Analyze user agent for bot indicators"""
        if not user_agent:
            return 0.8, "empty_user_agent"
        
        # Check against known bot patterns
        for pattern in self.bot_patterns:
            if pattern.search(user_agent):
                return 0.9, "known_bot_pattern"
        
        # Check against suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern.search(user_agent):
                return 0.7, "suspicious_pattern"
        
        # Check for very short user agents
        if len(user_agent) < 10:
            return 0.6, "short_user_agent"
        
        # Check for missing common browser indicators
        if not any(browser in user_agent.lower() for browser in ['chrome', 'firefox', 'safari', 'edge']):
            return 0.4, "non_browser_agent"
        
        return 0.0, "normal_user_agent"
    
    def analyze_behavior(self, context: RequestContext) -> float:
        """Analyze request behavior patterns"""
        client_ip = context.client_ip
        current_time = time.time()
        
        # Initialize or update request patterns
        if client_ip not in self.request_patterns:
            self.request_patterns[client_ip] = {
                'requests': [],
                'paths': set(),
                'user_agents': set(),
                'first_seen': current_time
            }
        
        patterns = self.request_patterns[client_ip]
        
        # Add current request
        patterns['requests'].append(current_time)
        patterns['paths'].add(context.path)
        patterns['user_agents'].add(context.user_agent)
        
        # Keep only recent requests (last hour)
        patterns['requests'] = [t for t in patterns['requests'] if current_time - t < 3600]
        
        # Calculate suspicion score
        suspicion = 0.0
        
        # High request rate
        recent_requests = [t for t in patterns['requests'] if current_time - t < 300]  # 5 minutes
        if len(recent_requests) > 100:
            suspicion += 0.3
        elif len(recent_requests) > 50:
            suspicion += 0.2
        
        # Too many different paths
        if len(patterns['paths']) > 100:
            suspicion += 0.2
        
        # Multiple user agents from same IP
        if len(patterns['user_agents']) > 5:
            suspicion += 0.3
        
        # Very regular request intervals (bot-like behavior)
        if len(patterns['requests']) > 10:
            intervals = []
            for i in range(1, min(len(patterns['requests']), 20)):
                intervals.append(patterns['requests'][i] - patterns['requests'][i-1])
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                
                # Low variance indicates regular intervals (bot behavior)
                if variance < 1.0 and avg_interval < 10:
                    suspicion += 0.2
        
        return min(suspicion, 1.0)
    
    def check_bot(self, context: RequestContext) -> Optional[WAFResult]:
        """Check if request is from a bot"""
        if not self.config.waf.bot_protection.enabled:
            return None
        
        total_confidence = 0.0
        detection_reasons = []
        
        # User agent analysis
        if self.config.waf.bot_protection.user_agent_analysis:
            ua_confidence, ua_reason = self.analyze_user_agent(context.user_agent)
            total_confidence += ua_confidence * 0.6
            if ua_confidence > 0.5:
                detection_reasons.append(ua_reason)
        
        # Behavioral analysis
        if self.config.waf.bot_protection.behavioral_analysis:
            behavior_confidence = self.analyze_behavior(context)
            total_confidence += behavior_confidence * 0.4
            if behavior_confidence > 0.5:
                detection_reasons.append("suspicious_behavior")
        
        # Check against known bot list
        if context.client_ip in self.known_bots:
            total_confidence = max(total_confidence, 0.9)
            detection_reasons.append("known_bot_ip")
        
        # Determine action based on confidence and configuration
        if total_confidence >= self.config.waf.bot_protection.bot_threshold:
            if self.config.waf.bot_protection.block_known_bots:
                action = WAFAction.BLOCK
            else:
                action = WAFAction.MONITOR
        elif total_confidence >= self.config.waf.bot_protection.suspicious_threshold:
            if self.config.waf.bot_protection.challenge_suspicious:
                action = WAFAction.CHALLENGE
            else:
                action = WAFAction.MONITOR
        else:
            return None
        
        # Add to suspicious IPs if needed
        if total_confidence > 0.6:
            self.suspicious_ips.add(context.client_ip)
        
        return WAFResult(
            action=action,
            threat_level=ThreatLevel.MEDIUM if action == WAFAction.CHALLENGE else ThreatLevel.HIGH,
            rule_name="bot_detection",
            confidence=total_confidence,
            message=f"Bot/automated request detected: {', '.join(detection_reasons)}",
            metadata={
                "detection_reasons": detection_reasons,
                "user_agent": context.user_agent,
                "client_ip": context.client_ip,
                "confidence": total_confidence
            }
        )


class GeoBlocker:
    """Geographic blocking implementation"""
    
    def __init__(self, config):
        self.config = config
        self.geoip_reader = None
        
        if config.waf.geo_blocking.enabled:
            self._load_geoip_database()
    
    def _load_geoip_database(self):
        """Load GeoIP database"""
        try:
            db_path = self.config.waf.geo_blocking.geoip_database
            self.geoip_reader = geoip2.database.Reader(db_path)
        except Exception as e:
            print(f"Warning: Could not load GeoIP database: {e}")
            self.geoip_reader = None
    
    def get_country_code(self, client_ip: str) -> Optional[str]:
        """Get country code for IP address"""
        if not self.geoip_reader:
            return None
        
        try:
            response = self.geoip_reader.country(client_ip)
            return response.country.iso_code
        except (geoip2.errors.AddressNotFoundError, Exception):
            return None
    
    def check_geo_blocking(self, context: RequestContext) -> Optional[WAFResult]:
        """Check geographic blocking rules"""
        if not self.config.waf.geo_blocking.enabled:
            return None
        
        country_code = self.get_country_code(context.client_ip)
        if not country_code:
            # Unknown location - allow by default but log
            return None
        
        # Update context
        context.country_code = country_code
        
        blocked_countries = self.config.waf.geo_blocking.blocked_countries
        allowed_countries = self.config.waf.geo_blocking.allowed_countries
        
        # Check blocked countries
        if blocked_countries and country_code in blocked_countries:
            return WAFResult(
                action=WAFAction.BLOCK,
                threat_level=ThreatLevel.MEDIUM,
                rule_name="geo_blocking",
                confidence=1.0,
                message=f"Request blocked from country: {country_code}",
                metadata={
                    "country_code": country_code,
                    "client_ip": context.client_ip,
                    "block_type": "country_blocked"
                }
            )
        
        # Check allowed countries (if specified, only these are allowed)
        if allowed_countries and country_code not in allowed_countries:
            return WAFResult(
                action=WAFAction.BLOCK,
                threat_level=ThreatLevel.MEDIUM,
                rule_name="geo_blocking",
                confidence=1.0,
                message=f"Request from non-allowed country: {country_code}",
                metadata={
                    "country_code": country_code,
                    "client_ip": context.client_ip,
                    "block_type": "country_not_allowed"
                }
            )
        
        return None


class IPBlocklist:
    """IP address blocking management"""
    
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_subnets = []
        self.temporary_blocks = {}  # IP -> expiry time
    
    def is_blocked(self, client_ip: str) -> Tuple[bool, Optional[str]]:
        """Check if IP is blocked"""
        # Check permanent blocks
        if client_ip in self.blocked_ips:
            return True, "permanently_blocked"
        
        # Check subnet blocks
        try:
            ip_addr = ipaddress.ip_address(client_ip)
            for subnet in self.blocked_subnets:
                if ip_addr in subnet:
                    return True, "subnet_blocked"
        except ValueError:
            pass
        
        # Check temporary blocks
        if client_ip in self.temporary_blocks:
            if time.time() < self.temporary_blocks[client_ip]:
                return True, "temporarily_blocked"
            else:
                # Expired temporary block
                del self.temporary_blocks[client_ip]
        
        return False, None
    
    def block_ip(self, client_ip: str, duration: Optional[int] = None, reason: str = ""):
        """Block an IP address"""
        if duration:
            # Temporary block
            self.temporary_blocks[client_ip] = time.time() + duration
        else:
            # Permanent block
            self.blocked_ips.add(client_ip)
    
    def unblock_ip(self, client_ip: str):
        """Unblock an IP address"""
        self.blocked_ips.discard(client_ip)
        self.temporary_blocks.pop(client_ip, None)
    
    def block_subnet(self, subnet_str: str):
        """Block a subnet"""
        try:
            subnet = ipaddress.ip_network(subnet_str)
            self.blocked_subnets.append(subnet)
        except ValueError as e:
            raise ValueError(f"Invalid subnet: {subnet_str}: {e}")


class WAFEngine:
    """Main WAF engine that coordinates all protection mechanisms"""
    
    def __init__(self, config: Config, redis_url: Optional[str] = None):
        self.config = config
        
        # Initialize protection modules
        self.owasp_protector = OwaspProtector(config)
        self.rate_limiter = RateLimiter(config, redis_url)
        self.bot_detector = BotDetector(config)
        self.geo_blocker = GeoBlocker(config)
        self.ip_blocklist = IPBlocklist()
        
        # Statistics
        self.stats = {
            "requests_processed": 0,
            "requests_blocked": 0,
            "sql_injection_blocked": 0,
            "xss_blocked": 0,
            "rce_blocked": 0,
            "rate_limited": 0,
            "bots_blocked": 0,
            "geo_blocked": 0,
            "ip_blocked": 0,
        }
    
    async def inspect_request(self, context: RequestContext) -> WAFResult:
        """Main request inspection method"""
        self.stats["requests_processed"] += 1
        
        if not self.config.waf.enabled:
            return WAFResult(
                action=WAFAction.ALLOW,
                threat_level=ThreatLevel.LOW,
                message="WAF disabled"
            )
        
        # 1. Check IP blocklist first (fastest check)
        is_blocked, block_reason = self.ip_blocklist.is_blocked(context.client_ip)
        if is_blocked:
            self.stats["ip_blocked"] += 1
            self.stats["requests_blocked"] += 1
            return WAFResult(
                action=WAFAction.BLOCK,
                threat_level=ThreatLevel.HIGH,
                rule_name="ip_blocklist",
                confidence=1.0,
                message=f"IP address blocked: {block_reason}",
                metadata={
                    "client_ip": context.client_ip,
                    "block_reason": block_reason
                }
            )
        
        # 2. Rate limiting checks
        if not self.rate_limiter.check_global_limit():
            self.stats["rate_limited"] += 1
            self.stats["requests_blocked"] += 1
            raise RateLimitError(
                "Global rate limit exceeded",
                limit_type="global",
                client_ip=context.client_ip
            )
        
        if not self.rate_limiter.check_ip_limit(context.client_ip):
            self.stats["rate_limited"] += 1
            self.stats["requests_blocked"] += 1
            retry_after = self.rate_limiter.get_retry_after(context.client_ip)
            raise RateLimitError(
                "Per-IP rate limit exceeded",
                limit_type="per_ip",
                client_ip=context.client_ip,
                retry_after=retry_after
            )
        
        endpoint = f"{context.method}:{context.path}"
        if not self.rate_limiter.check_endpoint_limit(endpoint):
            self.stats["rate_limited"] += 1
            self.stats["requests_blocked"] += 1
            raise RateLimitError(
                "Per-endpoint rate limit exceeded",
                limit_type="per_endpoint",
                client_ip=context.client_ip
            )
        
        # 3. Geographic blocking
        geo_result = self.geo_blocker.check_geo_blocking(context)
        if geo_result and geo_result.should_block():
            self.stats["geo_blocked"] += 1
            self.stats["requests_blocked"] += 1
            return geo_result
        
        # 4. Bot detection
        bot_result = self.bot_detector.check_bot(context)
        if bot_result and bot_result.should_block():
            self.stats["bots_blocked"] += 1
            self.stats["requests_blocked"] += 1
            return bot_result
        
        # 5. OWASP Top 10 protections
        
        # SQL Injection
        sql_result = self.owasp_protector.check_sql_injection(context)
        if sql_result and sql_result.should_block():
            self.stats["sql_injection_blocked"] += 1
            self.stats["requests_blocked"] += 1
            return sql_result
        
        # XSS
        xss_result = self.owasp_protector.check_xss(context)
        if xss_result and xss_result.should_block():
            self.stats["xss_blocked"] += 1
            self.stats["requests_blocked"] += 1
            return xss_result
        
        # RCE
        rce_result = self.owasp_protector.check_rce(context)
        if rce_result and rce_result.should_block():
            self.stats["rce_blocked"] += 1
            self.stats["requests_blocked"] += 1
            return rce_result
        
        # Path Traversal
        path_result = self.owasp_protector.check_path_traversal(context)
        if path_result and path_result.should_block():
            self.stats["requests_blocked"] += 1
            return path_result
        
        # CSRF
        csrf_result = self.owasp_protector.check_csrf(context)
        if csrf_result and csrf_result.should_block():
            self.stats["requests_blocked"] += 1
            return csrf_result
        
        # If we get here, request is allowed
        return WAFResult(
            action=WAFAction.ALLOW,
            threat_level=ThreatLevel.LOW,
            message="Request allowed"
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get WAF statistics"""
        return self.stats.copy()
    
    def block_ip(self, client_ip: str, duration: Optional[int] = None, reason: str = ""):
        """Block an IP address"""
        self.ip_blocklist.block_ip(client_ip, duration, reason)
    
    def unblock_ip(self, client_ip: str):
        """Unblock an IP address"""
        self.ip_blocklist.unblock_ip(client_ip)
    
    def get_blocked_ips(self) -> List[str]:
        """Get list of blocked IPs"""
        return list(self.ip_blocklist.blocked_ips)
