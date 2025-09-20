"""
PyWAF - Complete Python implementation of WAF + Reverse Proxy by Deepskilling

A high-performance, enterprise-grade Web Application Firewall (WAF) and 
Reverse Proxy implementation in Python, providing comprehensive security,
load balancing, and SSL/TLS management capabilities.
"""

__version__ = "1.0.0"
__author__ = "Deepskilling"
__email__ = "support@deepskilling.com"
__license__ = "MIT"

from .core.waf import WAFEngine
from .core.proxy import ReverseProxy
from .core.ssl import SSLManager
from .core.config import Config
from .core.exceptions import PyWAFError, ConfigurationError, SecurityError
from .admin.api import create_admin_router
from .monitoring.metrics import MetricsCollector
from .monitoring.health import HealthChecker

__all__ = [
    "__version__",
    "__author__", 
    "__email__",
    "__license__",
    "WAFEngine",
    "ReverseProxy", 
    "SSLManager",
    "Config",
    "PyWAFError",
    "ConfigurationError", 
    "SecurityError",
    "create_admin_router",
    "MetricsCollector",
    "HealthChecker",
]
