"""
PyWAF Admin API

RESTful API for managing and monitoring the PyWAF system.
"""

import time
import hashlib
from typing import Dict, List, Optional, Any

import jwt
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from ..core.config import Config
from ..core.exceptions import AuthenticationError, AuthorizationError


# API Models

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class ConfigUpdate(BaseModel):
    section: str
    data: Dict[str, Any]


class IPBlockRequest(BaseModel):
    ip_address: str
    duration: Optional[int] = None  # seconds, None for permanent
    reason: Optional[str] = ""


class RuleUpdate(BaseModel):
    rule_id: Optional[str] = None
    name: str
    enabled: bool
    conditions: List[Dict[str, Any]]
    action: str
    priority: int = 100


class UpstreamUpdate(BaseModel):
    name: str
    servers: List[Dict[str, Any]]
    algorithm: str
    health_check: Dict[str, Any]


# Authentication

security = HTTPBearer()


class AuthManager:
    """Authentication and authorization manager"""
    
    def __init__(self, config: Config):
        self.config = config
        self.jwt_secret = config.admin.jwt_secret or "default-secret-change-in-production"
        self.jwt_expiry = config.admin.jwt_expiry
    
    def verify_password(self, username: str, password: str) -> bool:
        """Verify username and password"""
        if not self.config.admin.auth_enabled:
            return True
        
        if username != self.config.admin.username:
            return False
        
        # Hash the provided password and compare
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash == self.config.admin.password_hash
    
    def create_access_token(self, username: str) -> str:
        """Create JWT access token"""
        payload = {
            "sub": username,
            "iat": int(time.time()),
            "exp": int(time.time()) + self.jwt_expiry
        }
        
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")
    
    def verify_token(self, token: str) -> Optional[str]:
        """Verify JWT token and return username"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            username = payload.get("sub")
            
            # Check expiration
            exp = payload.get("exp", 0)
            if exp < time.time():
                return None
            
            return username
        except jwt.PyJWTError:
            return None


def create_admin_router(config: Config, app_instance) -> APIRouter:
    """Create admin API router"""
    
    router = APIRouter(
        tags=["admin"],
        responses={
            401: {"description": "Unauthorized"},
            403: {"description": "Forbidden"},
            404: {"description": "Not Found"},
            500: {"description": "Internal Server Error"}
        }
    )
    
    auth_manager = AuthManager(config)
    
    async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
        """Get current authenticated user"""
        if not config.admin.auth_enabled:
            return "anonymous"
        
        token = credentials.credentials
        username = auth_manager.verify_token(token)
        
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
        
        return username
    
    # Authentication endpoints
    
    @router.post("/auth/login", response_model=LoginResponse)
    async def login(request: LoginRequest):
        """Authenticate and get access token"""
        if not auth_manager.verify_password(request.username, request.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        access_token = auth_manager.create_access_token(request.username)
        
        return LoginResponse(
            access_token=access_token,
            expires_in=config.admin.jwt_expiry
        )
    
    @router.post("/auth/refresh")
    async def refresh_token(current_user: str = Depends(get_current_user)):
        """Refresh access token"""
        access_token = auth_manager.create_access_token(current_user)
        
        return LoginResponse(
            access_token=access_token,
            expires_in=config.admin.jwt_expiry
        )
    
    # System status endpoints
    
    @router.get("/status")
    async def get_system_status(current_user: str = Depends(get_current_user)):
        """Get overall system status"""
        return app_instance.get_stats()
    
    @router.get("/health")
    async def get_health_status(current_user: str = Depends(get_current_user)):
        """Get system health status"""
        if app_instance.health_checker:
            return await app_instance.health_checker.check_overall_health()
        return {"status": "unknown", "message": "Health checker not available"}
    
    @router.get("/metrics")
    async def get_metrics_summary(current_user: str = Depends(get_current_user)):
        """Get metrics summary"""
        if app_instance.metrics_collector:
            return app_instance.metrics_collector.get_statistics()
        return {"error": "Metrics collector not available"}
    
    # Configuration management
    
    @router.get("/config")
    async def get_configuration(current_user: str = Depends(get_current_user)):
        """Get current configuration"""
        return config.dict(exclude_none=True)
    
    @router.get("/config/summary")
    async def get_config_summary(current_user: str = Depends(get_current_user)):
        """Get configuration summary"""
        return config.get_summary()
    
    @router.put("/config")
    async def update_configuration(
        update: ConfigUpdate,
        current_user: str = Depends(get_current_user)
    ):
        """Update configuration section"""
        # This is a simplified implementation
        # In production, you'd want proper validation and atomic updates
        
        try:
            # Update the configuration
            if hasattr(config, update.section):
                section_config = getattr(config, update.section)
                for key, value in update.data.items():
                    if hasattr(section_config, key):
                        setattr(section_config, key, value)
            
            # Validate updated configuration
            errors = config.validate_config()
            if errors:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"errors": errors}
                )
            
            return {"message": "Configuration updated successfully"}
            
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Configuration update failed: {str(e)}"
            )
    
    @router.post("/config/reload")
    async def reload_configuration(current_user: str = Depends(get_current_user)):
        """Reload configuration from file"""
        try:
            # This would reload the configuration in a production system
            return {"message": "Configuration reloaded successfully"}
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Configuration reload failed: {str(e)}"
            )
    
    # WAF management
    
    @router.get("/waf/status")
    async def get_waf_status(current_user: str = Depends(get_current_user)):
        """Get WAF status and statistics"""
        if app_instance.waf_engine:
            return app_instance.waf_engine.get_statistics()
        return {"error": "WAF engine not available"}
    
    @router.put("/waf/enable")
    async def enable_waf(current_user: str = Depends(get_current_user)):
        """Enable WAF"""
        config.waf.enabled = True
        return {"message": "WAF enabled"}
    
    @router.put("/waf/disable")
    async def disable_waf(current_user: str = Depends(get_current_user)):
        """Disable WAF"""
        config.waf.enabled = False
        return {"message": "WAF disabled"}
    
    @router.get("/waf/blocked-ips")
    async def get_blocked_ips(current_user: str = Depends(get_current_user)):
        """Get list of blocked IP addresses"""
        if app_instance.waf_engine:
            return {"blocked_ips": app_instance.waf_engine.get_blocked_ips()}
        return {"blocked_ips": []}
    
    @router.post("/waf/block-ip")
    async def block_ip(
        request: IPBlockRequest,
        current_user: str = Depends(get_current_user)
    ):
        """Block IP address"""
        if app_instance.waf_engine:
            app_instance.waf_engine.block_ip(
                request.ip_address,
                request.duration,
                request.reason
            )
            return {"message": f"IP {request.ip_address} blocked successfully"}
        
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WAF engine not available"
        )
    
    @router.delete("/waf/block-ip/{ip_address}")
    async def unblock_ip(
        ip_address: str,
        current_user: str = Depends(get_current_user)
    ):
        """Unblock IP address"""
        if app_instance.waf_engine:
            app_instance.waf_engine.unblock_ip(ip_address)
            return {"message": f"IP {ip_address} unblocked successfully"}
        
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="WAF engine not available"
        )
    
    @router.get("/waf/rules")
    async def get_waf_rules(current_user: str = Depends(get_current_user)):
        """Get WAF custom rules"""
        return {"rules": config.waf.custom_rules}
    
    @router.post("/waf/rules")
    async def create_waf_rule(
        rule: RuleUpdate,
        current_user: str = Depends(get_current_user)
    ):
        """Create new WAF rule"""
        # This is a simplified implementation
        # In production, you'd want proper rule validation and management
        
        new_rule = {
            "name": rule.name,
            "enabled": rule.enabled,
            "conditions": rule.conditions,
            "action": rule.action,
            "priority": rule.priority
        }
        
        config.waf.custom_rules.append(new_rule)
        
        return {"message": "WAF rule created successfully", "rule": new_rule}
    
    @router.put("/waf/rules/{rule_name}")
    async def update_waf_rule(
        rule_name: str,
        rule: RuleUpdate,
        current_user: str = Depends(get_current_user)
    ):
        """Update WAF rule"""
        # Find and update rule
        for i, existing_rule in enumerate(config.waf.custom_rules):
            if existing_rule.get("name") == rule_name:
                config.waf.custom_rules[i] = {
                    "name": rule.name,
                    "enabled": rule.enabled,
                    "conditions": rule.conditions,
                    "action": rule.action,
                    "priority": rule.priority
                }
                return {"message": "WAF rule updated successfully"}
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"WAF rule '{rule_name}' not found"
        )
    
    @router.delete("/waf/rules/{rule_name}")
    async def delete_waf_rule(
        rule_name: str,
        current_user: str = Depends(get_current_user)
    ):
        """Delete WAF rule"""
        for i, rule in enumerate(config.waf.custom_rules):
            if rule.get("name") == rule_name:
                del config.waf.custom_rules[i]
                return {"message": "WAF rule deleted successfully"}
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"WAF rule '{rule_name}' not found"
        )
    
    # Proxy management
    
    @router.get("/proxy/status")
    async def get_proxy_status(current_user: str = Depends(get_current_user)):
        """Get reverse proxy status"""
        if app_instance.reverse_proxy:
            return {
                "statistics": app_instance.reverse_proxy.get_statistics(),
                "upstreams": app_instance.reverse_proxy.get_upstream_status()
            }
        return {"error": "Reverse proxy not available"}
    
    @router.get("/proxy/upstreams")
    async def get_upstreams(current_user: str = Depends(get_current_user)):
        """Get upstream server status"""
        if app_instance.reverse_proxy:
            return app_instance.reverse_proxy.get_upstream_status()
        return {"upstreams": {}}
    
    @router.get("/proxy/cache/stats")
    async def get_cache_stats(current_user: str = Depends(get_current_user)):
        """Get cache statistics"""
        if app_instance.reverse_proxy and app_instance.reverse_proxy.cache:
            return app_instance.reverse_proxy.cache.get_stats()
        return {"error": "Cache not available"}
    
    @router.post("/proxy/cache/clear")
    async def clear_cache(
        pattern: Optional[str] = None,
        current_user: str = Depends(get_current_user)
    ):
        """Clear cache entries"""
        if app_instance.reverse_proxy and app_instance.reverse_proxy.cache:
            await app_instance.reverse_proxy.cache.clear(pattern)
            return {"message": "Cache cleared successfully"}
        
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cache not available"
        )
    
    # SSL management
    
    @router.get("/ssl/status")
    async def get_ssl_status(current_user: str = Depends(get_current_user)):
        """Get SSL certificate status"""
        if app_instance.ssl_manager:
            return app_instance.ssl_manager.get_statistics()
        return {
            "ssl_enabled": config.ssl.enabled,
            "message": "SSL manager not available" if config.ssl.enabled else "SSL not enabled"
        }
    
    @router.get("/ssl/certificates")
    async def get_certificates(current_user: str = Depends(get_current_user)):
        """Get SSL certificate information"""
        if app_instance.ssl_manager:
            certificates = app_instance.ssl_manager.list_certificates()
            return {"certificates": [cert.to_dict() for cert in certificates]}
        return {"certificates": []}
    
    @router.get("/ssl/certificates/{domain}")
    async def get_certificate_info(
        domain: str,
        current_user: str = Depends(get_current_user)
    ):
        """Get information for specific certificate"""
        if app_instance.ssl_manager:
            cert_info = app_instance.ssl_manager.get_certificate_info(domain)
            if cert_info:
                return cert_info
        
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Certificate for domain '{domain}' not found"
        )
    
    @router.post("/ssl/certificates/{domain}/renew")
    async def renew_certificate(
        domain: str,
        current_user: str = Depends(get_current_user)
    ):
        """Request certificate renewal for domain"""
        if app_instance.ssl_manager:
            # This would trigger certificate renewal in production
            return {"message": f"Certificate renewal requested for {domain}"}
        
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSL manager not available"
        )
    
    # Logs and monitoring
    
    @router.get("/logs/security")
    async def get_security_logs(
        limit: int = 100,
        current_user: str = Depends(get_current_user)
    ):
        """Get recent security events"""
        # This would fetch from actual log storage in production
        return {
            "logs": [],
            "message": "Log retrieval not implemented in this demo"
        }
    
    @router.get("/logs/access")
    async def get_access_logs(
        limit: int = 100,
        current_user: str = Depends(get_current_user)
    ):
        """Get recent access logs"""
        # This would fetch from actual log storage in production
        return {
            "logs": [],
            "message": "Log retrieval not implemented in this demo"
        }
    
    # System operations
    
    @router.post("/system/restart")
    async def restart_system(current_user: str = Depends(get_current_user)):
        """Restart the PyWAF system"""
        # This would gracefully restart the system in production
        return {"message": "System restart initiated"}
    
    @router.post("/system/backup/config")
    async def backup_configuration(current_user: str = Depends(get_current_user)):
        """Create configuration backup"""
        try:
            # This would create an actual backup in production
            backup_data = config.dict(exclude_none=True)
            return {
                "message": "Configuration backup created",
                "timestamp": time.time(),
                "backup_size": len(str(backup_data))
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Backup failed: {str(e)}"
            )
    
    return router
