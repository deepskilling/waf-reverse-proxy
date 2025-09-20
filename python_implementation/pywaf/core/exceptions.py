"""
PyWAF Exception Classes

Centralized exception handling for the PyWAF system.
"""

from typing import Any, Dict, Optional
from enum import Enum


class ErrorCode(str, Enum):
    """Standard error codes for PyWAF"""
    # Configuration errors
    CONFIG_INVALID = "CONFIG_INVALID"
    CONFIG_MISSING = "CONFIG_MISSING"
    CONFIG_VALIDATION_FAILED = "CONFIG_VALIDATION_FAILED"
    
    # Security errors  
    WAF_BLOCKED = "WAF_BLOCKED"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    IP_BLOCKED = "IP_BLOCKED"
    GEO_BLOCKED = "GEO_BLOCKED"
    BOT_DETECTED = "BOT_DETECTED"
    
    # Authentication/Authorization
    AUTH_FAILED = "AUTH_FAILED"
    AUTH_TOKEN_INVALID = "AUTH_TOKEN_INVALID"
    AUTH_PERMISSION_DENIED = "AUTH_PERMISSION_DENIED"
    
    # Proxy errors
    UPSTREAM_ERROR = "UPSTREAM_ERROR"
    UPSTREAM_TIMEOUT = "UPSTREAM_TIMEOUT"
    UPSTREAM_UNAVAILABLE = "UPSTREAM_UNAVAILABLE"
    LOAD_BALANCER_ERROR = "LOAD_BALANCER_ERROR"
    
    # SSL/TLS errors
    SSL_ERROR = "SSL_ERROR"
    CERTIFICATE_ERROR = "CERTIFICATE_ERROR"
    CERTIFICATE_EXPIRED = "CERTIFICATE_EXPIRED"
    ACME_ERROR = "ACME_ERROR"
    
    # Cache errors
    CACHE_ERROR = "CACHE_ERROR"
    CACHE_TIMEOUT = "CACHE_TIMEOUT"
    
    # Health check errors
    HEALTH_CHECK_FAILED = "HEALTH_CHECK_FAILED"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    
    # General errors
    INTERNAL_ERROR = "INTERNAL_ERROR"
    TIMEOUT = "TIMEOUT"
    NETWORK_ERROR = "NETWORK_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"


class PyWAFError(Exception):
    """Base exception class for all PyWAF errors"""
    
    def __init__(
        self,
        message: str,
        error_code: Optional[ErrorCode] = None,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or ErrorCode.INTERNAL_ERROR
        self.status_code = status_code
        self.details = details or {}
        self.cause = cause
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON serialization"""
        return {
            "error": {
                "code": self.error_code.value,
                "message": self.message,
                "status_code": self.status_code,
                "details": self.details
            }
        }
    
    def __str__(self) -> str:
        return f"{self.error_code.value}: {self.message}"


class ConfigurationError(PyWAFError):
    """Configuration-related errors"""
    
    def __init__(
        self,
        message: str,
        config_section: Optional[str] = None,
        validation_errors: Optional[list] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if config_section:
            details['config_section'] = config_section
        if validation_errors:
            details['validation_errors'] = validation_errors
        
        super().__init__(
            message=message,
            error_code=ErrorCode.CONFIG_INVALID,
            status_code=400,
            details=details,
            **kwargs
        )


class SecurityError(PyWAFError):
    """Security-related errors (WAF blocks, rate limits, etc.)"""
    
    def __init__(
        self,
        message: str,
        rule_name: Optional[str] = None,
        client_ip: Optional[str] = None,
        confidence: Optional[float] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if rule_name:
            details['rule_name'] = rule_name
        if client_ip:
            details['client_ip'] = client_ip
        if confidence is not None:
            details['confidence'] = confidence
        
        super().__init__(
            message=message,
            error_code=ErrorCode.WAF_BLOCKED,
            status_code=403,
            details=details,
            **kwargs
        )


class RateLimitError(SecurityError):
    """Rate limiting errors"""
    
    def __init__(
        self,
        message: str,
        limit_type: str = "unknown",
        retry_after: Optional[int] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            'limit_type': limit_type,
            'retry_after': retry_after
        })
        
        super().__init__(
            message=message,
            error_code=ErrorCode.RATE_LIMIT_EXCEEDED,
            status_code=429,
            details=details,
            **kwargs
        )


class IPBlockedError(SecurityError):
    """IP address blocked error"""
    
    def __init__(
        self,
        message: str,
        client_ip: str,
        block_reason: Optional[str] = None,
        block_duration: Optional[int] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            'client_ip': client_ip,
            'block_reason': block_reason,
            'block_duration': block_duration
        })
        
        super().__init__(
            message=message,
            error_code=ErrorCode.IP_BLOCKED,
            status_code=403,
            details=details,
            **kwargs
        )


class GeoBlockedError(SecurityError):
    """Geographic blocking error"""
    
    def __init__(
        self,
        message: str,
        client_ip: str,
        country_code: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            'client_ip': client_ip,
            'country_code': country_code
        })
        
        super().__init__(
            message=message,
            error_code=ErrorCode.GEO_BLOCKED,
            status_code=403,
            details=details,
            **kwargs
        )


class BotDetectedError(SecurityError):
    """Bot detection error"""
    
    def __init__(
        self,
        message: str,
        client_ip: str,
        user_agent: Optional[str] = None,
        bot_type: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            'client_ip': client_ip,
            'user_agent': user_agent,
            'bot_type': bot_type
        })
        
        super().__init__(
            message=message,
            error_code=ErrorCode.BOT_DETECTED,
            status_code=403,
            details=details,
            **kwargs
        )


class AuthenticationError(PyWAFError):
    """Authentication-related errors"""
    
    def __init__(
        self,
        message: str = "Authentication failed",
        **kwargs
    ):
        super().__init__(
            message=message,
            error_code=ErrorCode.AUTH_FAILED,
            status_code=401,
            **kwargs
        )


class AuthorizationError(PyWAFError):
    """Authorization-related errors"""
    
    def __init__(
        self,
        message: str = "Permission denied",
        required_permission: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if required_permission:
            details['required_permission'] = required_permission
        
        super().__init__(
            message=message,
            error_code=ErrorCode.AUTH_PERMISSION_DENIED,
            status_code=403,
            details=details,
            **kwargs
        )


class UpstreamError(PyWAFError):
    """Upstream server errors"""
    
    def __init__(
        self,
        message: str,
        upstream_name: Optional[str] = None,
        upstream_url: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if upstream_name:
            details['upstream_name'] = upstream_name
        if upstream_url:
            details['upstream_url'] = upstream_url
        
        super().__init__(
            message=message,
            error_code=ErrorCode.UPSTREAM_ERROR,
            status_code=502,
            details=details,
            **kwargs
        )


class UpstreamTimeoutError(UpstreamError):
    """Upstream timeout errors"""
    
    def __init__(
        self,
        message: str = "Upstream server timeout",
        timeout_duration: Optional[float] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if timeout_duration:
            details['timeout_duration'] = timeout_duration
        
        super().__init__(
            message=message,
            error_code=ErrorCode.UPSTREAM_TIMEOUT,
            status_code=504,
            details=details,
            **kwargs
        )


class SSLError(PyWAFError):
    """SSL/TLS related errors"""
    
    def __init__(
        self,
        message: str,
        domain: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if domain:
            details['domain'] = domain
        
        super().__init__(
            message=message,
            error_code=ErrorCode.SSL_ERROR,
            status_code=500,
            details=details,
            **kwargs
        )


class CertificateError(SSLError):
    """SSL certificate errors"""
    
    def __init__(
        self,
        message: str,
        domain: str,
        certificate_info: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            'domain': domain,
            'certificate_info': certificate_info
        })
        
        super().__init__(
            message=message,
            error_code=ErrorCode.CERTIFICATE_ERROR,
            status_code=500,
            details=details,
            **kwargs
        )


class CacheError(PyWAFError):
    """Cache-related errors"""
    
    def __init__(
        self,
        message: str,
        cache_key: Optional[str] = None,
        cache_backend: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if cache_key:
            details['cache_key'] = cache_key
        if cache_backend:
            details['cache_backend'] = cache_backend
        
        super().__init__(
            message=message,
            error_code=ErrorCode.CACHE_ERROR,
            status_code=500,
            details=details,
            **kwargs
        )


class HealthCheckError(PyWAFError):
    """Health check related errors"""
    
    def __init__(
        self,
        message: str,
        check_name: Optional[str] = None,
        service_name: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if check_name:
            details['check_name'] = check_name
        if service_name:
            details['service_name'] = service_name
        
        super().__init__(
            message=message,
            error_code=ErrorCode.HEALTH_CHECK_FAILED,
            status_code=503,
            details=details,
            **kwargs
        )


class ValidationError(PyWAFError):
    """Data validation errors"""
    
    def __init__(
        self,
        message: str,
        field_name: Optional[str] = None,
        field_value: Optional[Any] = None,
        validation_rules: Optional[list] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        if field_name:
            details['field_name'] = field_name
        if field_value is not None:
            details['field_value'] = str(field_value)
        if validation_rules:
            details['validation_rules'] = validation_rules
        
        super().__init__(
            message=message,
            error_code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
            details=details,
            **kwargs
        )
