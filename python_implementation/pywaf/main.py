"""
PyWAF Main Application

Main FastAPI application that integrates WAF, reverse proxy, and SSL management.
"""

import asyncio
import time
import uvicorn
from contextlib import asynccontextmanager
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
import structlog

from .core.config import Config
from .core.waf import WAFEngine, RequestContext, WAFAction
from .core.proxy import ReverseProxy
from .core.ssl import SSLManager
from .core.exceptions import (
    PyWAFError, SecurityError, RateLimitError, IPBlockedError,
    GeoBlockedError, BotDetectedError, UpstreamError
)
from .admin.api import create_admin_router
from .monitoring.metrics import MetricsCollector
from .monitoring.health import HealthChecker


# Configure structured logging
logger = structlog.get_logger()


class PyWAFApp:
    """Main PyWAF application class"""
    
    def __init__(self, config: Config):
        self.config = config
        
        # Core components
        self.waf_engine: Optional[WAFEngine] = None
        self.reverse_proxy: Optional[ReverseProxy] = None
        self.ssl_manager: Optional[SSLManager] = None
        self.metrics_collector: Optional[MetricsCollector] = None
        self.health_checker: Optional[HealthChecker] = None
        
        # FastAPI app
        self.app = self._create_app()
    
    def _create_app(self) -> FastAPI:
        """Create FastAPI application"""
        
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            """Application lifespan manager"""
            # Startup
            await self.startup()
            yield
            # Shutdown
            await self.shutdown()
        
        app = FastAPI(
            title="PyWAF - Web Application Firewall & Reverse Proxy",
            description="High-performance WAF and reverse proxy implementation in Python by Deepskilling",
            version="1.0.0",
            lifespan=lifespan,
            docs_url="/docs" if self.config.debug else None,
            redoc_url="/redoc" if self.config.debug else None
        )
        
        # Add middleware
        self._setup_middleware(app)
        
        # Add routes
        self._setup_routes(app)
        
        # Add exception handlers
        self._setup_exception_handlers(app)
        
        return app
    
    def _setup_middleware(self, app: FastAPI):
        """Setup middleware"""
        
        # CORS middleware
        if self.config.admin.cors_enabled:
            app.add_middleware(
                CORSMiddleware,
                allow_origins=self.config.admin.cors_origins or ["*"],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        
        # Trusted host middleware for security
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=["*"]  # Configure based on your needs
        )
        
        # WAF middleware (custom)
        app.middleware("http")(self._waf_middleware)
    
    def _setup_routes(self, app: FastAPI):
        """Setup application routes"""
        
        # Health check endpoint
        @app.get("/health")
        async def health_check():
            if self.health_checker:
                status = await self.health_checker.check_overall_health()
                return {"status": status["status"], "timestamp": status["timestamp"]}
            return {"status": "ok", "timestamp": time.time()}
        
        # Metrics endpoint
        @app.get("/metrics")
        async def metrics():
            if self.metrics_collector:
                return Response(
                    content=await self.metrics_collector.generate_metrics(),
                    media_type="text/plain"
                )
            return Response("# No metrics available\n", media_type="text/plain")
        
        # Admin API routes
        if self.config.admin.enabled:
            admin_router = create_admin_router(self.config, self)
            app.include_router(admin_router, prefix="/admin/api/v1")
        
        # Catch-all route for proxy
        @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
        async def proxy_handler(request: Request, path: str):
            if self.reverse_proxy:
                return await self.reverse_proxy.handle_request(request)
            else:
                raise HTTPException(status_code=503, detail="Proxy not available")
    
    def _setup_exception_handlers(self, app: FastAPI):
        """Setup exception handlers"""
        
        @app.exception_handler(SecurityError)
        async def security_error_handler(request: Request, exc: SecurityError):
            await self._log_security_event(request, exc)
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.to_dict()
            )
        
        @app.exception_handler(RateLimitError)
        async def rate_limit_error_handler(request: Request, exc: RateLimitError):
            await self._log_security_event(request, exc)
            
            headers = {}
            if hasattr(exc, 'retry_after') and exc.retry_after:
                headers["Retry-After"] = str(exc.retry_after)
            
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.to_dict(),
                headers=headers
            )
        
        @app.exception_handler(IPBlockedError)
        async def ip_blocked_handler(request: Request, exc: IPBlockedError):
            await self._log_security_event(request, exc)
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.to_dict()
            )
        
        @app.exception_handler(GeoBlockedError)
        async def geo_blocked_handler(request: Request, exc: GeoBlockedError):
            await self._log_security_event(request, exc)
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.to_dict()
            )
        
        @app.exception_handler(BotDetectedError)
        async def bot_detected_handler(request: Request, exc: BotDetectedError):
            await self._log_security_event(request, exc)
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.to_dict()
            )
        
        @app.exception_handler(UpstreamError)
        async def upstream_error_handler(request: Request, exc: UpstreamError):
            logger.error("Upstream error", error=str(exc), details=exc.details)
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.to_dict()
            )
        
        @app.exception_handler(PyWAFError)
        async def pywaf_error_handler(request: Request, exc: PyWAFError):
            logger.error("PyWAF error", error=str(exc), details=exc.details)
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.to_dict()
            )
    
    async def _waf_middleware(self, request: Request, call_next):
        """WAF middleware for request inspection"""
        start_time = time.time()
        
        try:
            # Skip WAF for health and metrics endpoints
            if request.url.path in ["/health", "/metrics"] or request.url.path.startswith("/admin/"):
                response = await call_next(request)
                return response
            
            # WAF inspection
            if self.waf_engine and self.config.waf.enabled:
                # Create request context
                context = RequestContext.from_request(request)
                
                # Read body if present (for POST/PUT requests)
                if request.method in ["POST", "PUT", "PATCH"]:
                    body = await request.body()
                    context.body = body
                    # Recreate request with body for downstream processing
                    # Note: This is a simplified approach; in production, you'd want to handle this more efficiently
                
                # Inspect request
                waf_result = await self.waf_engine.inspect_request(context)
                
                # Log WAF result
                await self._log_waf_result(request, waf_result)
                
                # Handle WAF result based on mode and action
                if waf_result.should_block():
                    if self.config.waf.mode.value == "block":
                        # Block the request
                        if waf_result.rule_name == "rate_limiter":
                            raise RateLimitError(
                                waf_result.message,
                                client_ip=context.client_ip
                            )
                        elif waf_result.rule_name == "ip_blocklist":
                            raise IPBlockedError(
                                waf_result.message,
                                client_ip=context.client_ip
                            )
                        elif waf_result.rule_name == "geo_blocking":
                            raise GeoBlockedError(
                                waf_result.message,
                                client_ip=context.client_ip,
                                country_code=context.country_code
                            )
                        elif waf_result.rule_name == "bot_detection":
                            raise BotDetectedError(
                                waf_result.message,
                                client_ip=context.client_ip,
                                user_agent=context.user_agent
                            )
                        else:
                            raise SecurityError(
                                waf_result.message,
                                rule_name=waf_result.rule_name,
                                client_ip=context.client_ip,
                                confidence=waf_result.confidence
                            )
                    elif self.config.waf.mode.value == "monitor":
                        # Monitor mode - log but allow
                        logger.warning(
                            "WAF would block request in block mode",
                            rule=waf_result.rule_name,
                            message=waf_result.message,
                            client_ip=context.client_ip,
                            confidence=waf_result.confidence
                        )
            
            # Continue with request processing
            response = await call_next(request)
            
            # Record metrics
            if self.metrics_collector:
                processing_time = time.time() - start_time
                await self.metrics_collector.record_request(
                    method=request.method,
                    path=request.url.path,
                    status_code=response.status_code,
                    response_time=processing_time
                )
            
            return response
            
        except (SecurityError, RateLimitError, IPBlockedError, GeoBlockedError, BotDetectedError):
            # Security exceptions are handled by exception handlers
            raise
        except Exception as e:
            # Log unexpected errors
            logger.error("Unexpected error in WAF middleware", error=str(e))
            # Continue processing - don't let WAF errors break the proxy
            response = await call_next(request)
            return response
    
    async def _log_waf_result(self, request: Request, waf_result):
        """Log WAF inspection result"""
        client_ip = request.client.host if request.client else "unknown"
        
        if waf_result.action in [WAFAction.BLOCK, WAFAction.CHALLENGE]:
            logger.warning(
                "WAF blocked request",
                action=waf_result.action.value,
                rule=waf_result.rule_name,
                message=waf_result.message,
                client_ip=client_ip,
                method=request.method,
                path=str(request.url.path),
                user_agent=request.headers.get("user-agent", ""),
                confidence=waf_result.confidence,
                metadata=waf_result.metadata
            )
        elif waf_result.action == WAFAction.MONITOR:
            logger.info(
                "WAF monitored request",
                rule=waf_result.rule_name,
                message=waf_result.message,
                client_ip=client_ip,
                confidence=waf_result.confidence
            )
    
    async def _log_security_event(self, request: Request, exc: PyWAFError):
        """Log security events"""
        client_ip = request.client.host if request.client else "unknown"
        
        logger.warning(
            "Security event",
            event_type=exc.error_code.value,
            message=exc.message,
            client_ip=client_ip,
            method=request.method,
            path=str(request.url.path),
            user_agent=request.headers.get("user-agent", ""),
            details=exc.details
        )
    
    async def startup(self):
        """Application startup"""
        logger.info("Starting PyWAF application")
        
        try:
            # Initialize metrics collector
            self.metrics_collector = MetricsCollector(self.config)
            await self.metrics_collector.initialize()
            
            # Initialize health checker
            self.health_checker = HealthChecker(self.config)
            
            # Initialize SSL manager
            if self.config.ssl.enabled:
                self.ssl_manager = SSLManager(self.config)
                await self.ssl_manager.initialize()
            
            # Initialize WAF engine
            if self.config.waf.enabled:
                redis_url = None
                if hasattr(self.config.proxy.cache, 'redis_url'):
                    redis_url = self.config.proxy.cache.redis_url
                
                self.waf_engine = WAFEngine(self.config, redis_url)
                logger.info("WAF engine initialized")
            
            # Initialize reverse proxy
            self.reverse_proxy = ReverseProxy(self.config)
            await self.reverse_proxy.start()
            logger.info("Reverse proxy initialized")
            
            logger.info("PyWAF application started successfully")
            
        except Exception as e:
            logger.error("Failed to start PyWAF application", error=str(e))
            raise
    
    async def shutdown(self):
        """Application shutdown"""
        logger.info("Shutting down PyWAF application")
        
        try:
            # Cleanup components
            if self.reverse_proxy:
                await self.reverse_proxy.stop()
            
            if self.ssl_manager:
                await self.ssl_manager.cleanup()
            
            if self.metrics_collector:
                await self.metrics_collector.cleanup()
            
            logger.info("PyWAF application shutdown complete")
            
        except Exception as e:
            logger.error("Error during shutdown", error=str(e))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get application statistics"""
        stats = {}
        
        if self.waf_engine:
            stats["waf"] = self.waf_engine.get_statistics()
        
        if self.reverse_proxy:
            stats["proxy"] = self.reverse_proxy.get_statistics()
            stats["upstreams"] = self.reverse_proxy.get_upstream_status()
        
        if self.ssl_manager:
            stats["ssl"] = self.ssl_manager.get_statistics()
        
        if self.metrics_collector:
            stats["metrics"] = self.metrics_collector.get_statistics()
        
        return stats


def create_app(config_file: str = "config/config.yaml") -> FastAPI:
    """Create PyWAF application"""
    # Load configuration
    config = Config.load_from_file(config_file)
    
    # Validate configuration
    errors = config.validate_config()
    if errors:
        logger.error("Configuration validation failed", errors=errors)
        raise RuntimeError(f"Configuration validation failed: {errors}")
    
    # Create application
    app_instance = PyWAFApp(config)
    return app_instance.app


def run_server(
    config_file: str = "config/config.yaml",
    host: Optional[str] = None,
    port: Optional[int] = None,
    workers: Optional[int] = None,
    ssl_keyfile: Optional[str] = None,
    ssl_certfile: Optional[str] = None
):
    """Run the PyWAF server"""
    
    # Load configuration
    config = Config.load_from_file(config_file)
    
    # Override with parameters if provided
    if host:
        config.server.host = host
    if port:
        config.server.port = port
    if workers:
        config.server.workers = workers
    
    # SSL configuration
    ssl_config = {}
    if config.ssl.enabled:
        if ssl_certfile and ssl_keyfile:
            ssl_config["ssl_certfile"] = ssl_certfile
            ssl_config["ssl_keyfile"] = ssl_keyfile
        elif config.ssl.cert_file and config.ssl.key_file:
            ssl_config["ssl_certfile"] = config.ssl.cert_file
            ssl_config["ssl_keyfile"] = config.ssl.key_file
    
    # Create application
    app = create_app(config_file)
    
    # Run server
    logger.info(
        "Starting PyWAF server",
        host=config.server.host,
        port=config.server.port,
        workers=config.server.workers,
        ssl_enabled=config.ssl.enabled
    )
    
    uvicorn.run(
        app,
        host=config.server.host,
        port=config.server.port,
        workers=config.server.workers if not config.debug else 1,
        access_log=True,
        log_level="info" if not config.debug else "debug",
        **ssl_config
    )


if __name__ == "__main__":
    import sys
    
    config_file = sys.argv[1] if len(sys.argv) > 1 else "config/config.yaml"
    run_server(config_file)
