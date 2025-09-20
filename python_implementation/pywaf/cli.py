"""
PyWAF Command Line Interface

Comprehensive CLI for managing and monitoring PyWAF.
"""

import sys
import json
import asyncio
import time
from pathlib import Path
from typing import Optional

import typer
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.json import JSON
from rich import print as rprint

from .core.config import Config
from .main import PyWAFApp, create_app

# Initialize CLI app
app = typer.Typer(
    name="pywaf",
    help="PyWAF - Web Application Firewall & Reverse Proxy by Deepskilling",
    add_completion=False
)

console = Console()


# Configuration management commands
config_app = typer.Typer(name="config", help="Configuration management")
app.add_typer(config_app)

@config_app.command("validate")
def validate_config(
    config_file: str = typer.Option("config/config.yaml", "--config", "-c", help="Configuration file path")
):
    """Validate configuration file"""
    try:
        config = Config.load_from_file(config_file)
        errors = config.validate_config()
        
        if errors:
            console.print(f"❌ Configuration validation failed:", style="red")
            for error in errors:
                console.print(f"  • {error}", style="red")
            raise typer.Exit(1)
        else:
            console.print("✅ Configuration is valid", style="green")
    except Exception as e:
        console.print(f"❌ Failed to load configuration: {e}", style="red")
        raise typer.Exit(1)


@config_app.command("show")
def show_config(
    config_file: str = typer.Option("config/config.yaml", "--config", "-c", help="Configuration file path"),
    section: Optional[str] = typer.Option(None, "--section", "-s", help="Show specific section"),
    format: str = typer.Option("yaml", "--format", "-f", help="Output format (yaml, json)")
):
    """Show configuration"""
    try:
        config = Config.load_from_file(config_file)
        
        if section:
            if hasattr(config, section):
                data = getattr(config, section).dict()
            else:
                console.print(f"❌ Section '{section}' not found", style="red")
                raise typer.Exit(1)
        else:
            data = config.dict(exclude_none=True)
        
        if format == "json":
            console.print(JSON.from_data(data))
        else:
            import yaml
            yaml_output = yaml.dump(data, default_flow_style=False, indent=2)
            console.print(yaml_output)
            
    except Exception as e:
        console.print(f"❌ Failed to show configuration: {e}", style="red")
        raise typer.Exit(1)


@config_app.command("summary")
def config_summary(
    config_file: str = typer.Option("config/config.yaml", "--config", "-c", help="Configuration file path")
):
    """Show configuration summary"""
    try:
        config = Config.load_from_file(config_file)
        summary = config.get_summary()
        
        console.print(Panel.fit("📋 Configuration Summary", style="blue"))
        
        # Environment info
        console.print(f"Environment: {summary['environment']}")
        console.print(f"Debug Mode: {summary['debug']}")
        
        # Server info
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Component", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Details")
        
        # Server
        table.add_row(
            "Server",
            "🟢" if summary['server']['host'] else "🔴",
            f"{summary['server']['host']}:{summary['server']['port']} ({summary['server']['workers']} workers)"
        )
        
        # SSL
        ssl_status = "🟢" if summary['ssl']['enabled'] else "⚪"
        ssl_details = f"Auto-provision: {summary['ssl']['auto_provision']}, Domains: {summary['ssl']['domains']}"
        table.add_row("SSL/TLS", ssl_status, ssl_details)
        
        # WAF
        waf_status = "🟢" if summary['waf']['enabled'] else "🔴"
        waf_details = f"Mode: {summary['waf']['mode']}, OWASP: {summary['waf']['owasp_protection']}, Bot: {summary['waf']['bot_protection']}"
        table.add_row("WAF", waf_status, waf_details)
        
        # Proxy
        proxy_status = "🟢" if summary['proxy']['upstreams'] > 0 else "🔴"
        proxy_details = f"Upstreams: {summary['proxy']['upstreams']}, Routes: {summary['proxy']['routes']}, Cache: {summary['proxy']['cache_enabled']}"
        table.add_row("Proxy", proxy_status, proxy_details)
        
        # Admin
        admin_status = "🟢" if summary['admin']['enabled'] else "⚪"
        admin_details = f"Port: {summary['admin']['port']}, Auth: {summary['admin']['auth_enabled']}"
        table.add_row("Admin API", admin_status, admin_details)
        
        # Metrics
        metrics_status = "🟢" if summary['metrics']['enabled'] else "⚪"
        metrics_details = f"Port: {summary['metrics']['port']}"
        table.add_row("Metrics", metrics_status, metrics_details)
        
        console.print(table)
        
    except Exception as e:
        console.print(f"❌ Failed to show configuration summary: {e}", style="red")
        raise typer.Exit(1)


# Server management commands
server_app = typer.Typer(name="server", help="Server management")
app.add_typer(server_app)

@server_app.command("start")
def start_server(
    config_file: str = typer.Option("config/config.yaml", "--config", "-c", help="Configuration file path"),
    host: Optional[str] = typer.Option(None, "--host", "-h", help="Server host"),
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Server port"),
    workers: Optional[int] = typer.Option(None, "--workers", "-w", help="Number of workers"),
    ssl_cert: Optional[str] = typer.Option(None, "--ssl-cert", help="SSL certificate file"),
    ssl_key: Optional[str] = typer.Option(None, "--ssl-key", help="SSL private key file"),
    daemon: bool = typer.Option(False, "--daemon", "-d", help="Run in daemon mode")
):
    """Start PyWAF server"""
    from .main import run_server
    
    console.print("🚀 Starting PyWAF server...", style="blue")
    
    try:
        run_server(
            config_file=config_file,
            host=host,
            port=port,
            workers=workers,
            ssl_certfile=ssl_cert,
            ssl_keyfile=ssl_key
        )
    except KeyboardInterrupt:
        console.print("\n🛑 Server stopped by user", style="yellow")
    except Exception as e:
        console.print(f"❌ Server failed to start: {e}", style="red")
        raise typer.Exit(1)


@server_app.command("check")
def check_server(
    config_file: str = typer.Option("config/config.yaml", "--config", "-c", help="Configuration file path")
):
    """Check server configuration and dependencies"""
    console.print("🔍 Checking server configuration...", style="blue")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Validating configuration...", total=None)
        
        try:
            # Load and validate config
            config = Config.load_from_file(config_file)
            errors = config.validate_config()
            
            if errors:
                progress.stop()
                console.print("❌ Configuration validation failed:", style="red")
                for error in errors:
                    console.print(f"  • {error}", style="red")
                raise typer.Exit(1)
            
            progress.update(task, description="Checking dependencies...")
            
            # Check Python dependencies
            import pkg_resources
            requirements = [
                "fastapi", "uvicorn", "httpx", "redis", "cryptography",
                "prometheus-client", "pydantic", "pyyaml"
            ]
            
            missing_deps = []
            for req in requirements:
                try:
                    pkg_resources.get_distribution(req)
                except pkg_resources.DistributionNotFound:
                    missing_deps.append(req)
            
            progress.update(task, description="Checking ports...")
            
            # Check port availability
            import socket
            ports_to_check = [config.server.port]
            if config.ssl.enabled:
                ports_to_check.append(config.ssl.port)
            if config.admin.enabled:
                ports_to_check.append(config.admin.port)
            if config.metrics.enabled:
                ports_to_check.append(config.metrics.port)
            
            unavailable_ports = []
            for port in ports_to_check:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    result = s.connect_ex((config.server.host, port))
                    if result == 0:  # Port is in use
                        unavailable_ports.append(port)
            
            progress.stop()
            
            # Show results
            if missing_deps or unavailable_ports:
                console.print("⚠️  Issues found:", style="yellow")
                
                if missing_deps:
                    console.print(f"Missing dependencies: {', '.join(missing_deps)}", style="yellow")
                
                if unavailable_ports:
                    console.print(f"Ports in use: {', '.join(map(str, unavailable_ports))}", style="yellow")
            else:
                console.print("✅ Server configuration check passed", style="green")
                
        except Exception as e:
            progress.stop()
            console.print(f"❌ Configuration check failed: {e}", style="red")
            raise typer.Exit(1)


# WAF management commands
waf_app = typer.Typer(name="waf", help="WAF management")
app.add_typer(waf_app)

@waf_app.command("status")
def waf_status(
    admin_url: str = typer.Option("http://localhost:8081", "--admin-url", help="Admin API URL"),
    token: Optional[str] = typer.Option(None, "--token", help="Authentication token")
):
    """Get WAF status"""
    asyncio.run(_waf_status_async(admin_url, token))


async def _waf_status_async(admin_url: str, token: Optional[str]):
    """Async implementation of WAF status"""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{admin_url}/admin/api/v1/waf/status", headers=headers)
            response.raise_for_status()
            
            data = response.json()
            
            console.print(Panel.fit("🛡️  WAF Status", style="blue"))
            
            table = Table(show_header=True, header_style="bold blue")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", justify="right")
            
            table.add_row("Total Requests", str(data.get("requests_processed", 0)))
            table.add_row("Blocked Requests", str(data.get("requests_blocked", 0)))
            table.add_row("SQL Injection Blocks", str(data.get("sql_injection_blocked", 0)))
            table.add_row("XSS Blocks", str(data.get("xss_blocked", 0)))
            table.add_row("Rate Limited", str(data.get("rate_limited", 0)))
            table.add_row("Bots Blocked", str(data.get("bots_blocked", 0)))
            table.add_row("Geo Blocked", str(data.get("geo_blocked", 0)))
            
            console.print(table)
            
    except httpx.HTTPStatusError as e:
        console.print(f"❌ API request failed: {e.response.status_code}", style="red")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Failed to get WAF status: {e}", style="red")
        raise typer.Exit(1)


@waf_app.command("block-ip")
def block_ip(
    ip_address: str,
    admin_url: str = typer.Option("http://localhost:8081", "--admin-url", help="Admin API URL"),
    token: Optional[str] = typer.Option(None, "--token", help="Authentication token"),
    duration: Optional[int] = typer.Option(None, "--duration", help="Block duration in seconds"),
    reason: Optional[str] = typer.Option("", "--reason", help="Block reason")
):
    """Block IP address"""
    asyncio.run(_block_ip_async(admin_url, token, ip_address, duration, reason))


async def _block_ip_async(admin_url: str, token: Optional[str], ip_address: str, duration: Optional[int], reason: str):
    """Async implementation of IP blocking"""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    data = {
        "ip_address": ip_address,
        "duration": duration,
        "reason": reason
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{admin_url}/admin/api/v1/waf/block-ip",
                headers=headers,
                json=data
            )
            response.raise_for_status()
            
            console.print(f"✅ IP {ip_address} blocked successfully", style="green")
            
    except httpx.HTTPStatusError as e:
        console.print(f"❌ API request failed: {e.response.status_code}", style="red")
        if e.response.status_code == 401:
            console.print("Authentication required. Use --token option.", style="yellow")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Failed to block IP: {e}", style="red")
        raise typer.Exit(1)


# Proxy management commands
proxy_app = typer.Typer(name="proxy", help="Proxy management")
app.add_typer(proxy_app)

@proxy_app.command("status")
def proxy_status(
    admin_url: str = typer.Option("http://localhost:8081", "--admin-url", help="Admin API URL"),
    token: Optional[str] = typer.Option(None, "--token", help="Authentication token")
):
    """Get proxy status"""
    asyncio.run(_proxy_status_async(admin_url, token))


async def _proxy_status_async(admin_url: str, token: Optional[str]):
    """Async implementation of proxy status"""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{admin_url}/admin/api/v1/proxy/status", headers=headers)
            response.raise_for_status()
            
            data = response.json()
            
            console.print(Panel.fit("🔄 Proxy Status", style="blue"))
            
            # Statistics
            stats = data.get("statistics", {})
            table = Table(show_header=True, header_style="bold blue")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", justify="right")
            
            table.add_row("Total Requests", str(stats.get("total_requests", 0)))
            table.add_row("Successful Requests", str(stats.get("successful_requests", 0)))
            table.add_row("Failed Requests", str(stats.get("failed_requests", 0)))
            table.add_row("Cache Hits", str(stats.get("cache_hits", 0)))
            table.add_row("Cache Misses", str(stats.get("cache_misses", 0)))
            table.add_row("Avg Response Time", f"{stats.get('average_response_time', 0):.2f}s")
            
            console.print(table)
            
            # Upstreams
            upstreams = data.get("upstreams", {})
            if upstreams:
                console.print("\n🎯 Upstream Status:", style="bold")
                
                upstream_table = Table(show_header=True, header_style="bold green")
                upstream_table.add_column("Upstream", style="cyan")
                upstream_table.add_column("Healthy/Total", justify="center")
                upstream_table.add_column("Algorithm")
                
                for name, info in upstreams.items():
                    status_color = "green" if info.get("healthy_servers", 0) > 0 else "red"
                    healthy_total = f"[{status_color}]{info.get('healthy_servers', 0)}/{info.get('total_servers', 0)}[/{status_color}]"
                    upstream_table.add_row(
                        name,
                        healthy_total,
                        info.get("algorithm", "unknown")
                    )
                
                console.print(upstream_table)
            
    except httpx.HTTPStatusError as e:
        console.print(f"❌ API request failed: {e.response.status_code}", style="red")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Failed to get proxy status: {e}", style="red")
        raise typer.Exit(1)


# SSL management commands
ssl_app = typer.Typer(name="ssl", help="SSL certificate management")
app.add_typer(ssl_app)

@ssl_app.command("status")
def ssl_status(
    admin_url: str = typer.Option("http://localhost:8081", "--admin-url", help="Admin API URL"),
    token: Optional[str] = typer.Option(None, "--token", help="Authentication token")
):
    """Get SSL certificate status"""
    asyncio.run(_ssl_status_async(admin_url, token))


async def _ssl_status_async(admin_url: str, token: Optional[str]):
    """Async implementation of SSL status"""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{admin_url}/admin/api/v1/ssl/status", headers=headers)
            response.raise_for_status()
            
            data = response.json()
            
            console.print(Panel.fit("🔒 SSL Status", style="blue"))
            
            if not data.get("ssl_enabled", False):
                console.print("SSL is not enabled", style="yellow")
                return
            
            table = Table(show_header=True, header_style="bold blue")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", justify="right")
            
            table.add_row("SSL Enabled", "✅" if data.get("ssl_enabled") else "❌")
            table.add_row("Auto Provision", "✅" if data.get("auto_provision") else "❌")
            table.add_row("Total Certificates", str(data.get("total_certificates", 0)))
            table.add_row("Valid Certificates", str(data.get("valid_certificates", 0)))
            table.add_row("Expiring Certificates", str(data.get("expiring_certificates", 0)))
            table.add_row("Expired Certificates", str(data.get("expired_certificates", 0)))
            
            console.print(table)
            
            # Certificate details
            if data.get("certificate_details"):
                console.print("\n📜 Certificate Details:", style="bold")
                
                cert_table = Table(show_header=True, header_style="bold green")
                cert_table.add_column("Domain", style="cyan")
                cert_table.add_column("Status", justify="center")
                cert_table.add_column("Expires", justify="center")
                cert_table.add_column("Days Left", justify="right")
                
                for cert in data["certificate_details"]:
                    status = cert.get("status", "unknown")
                    status_emoji = {
                        "valid": "✅",
                        "expiring_soon": "⚠️",
                        "expired": "❌"
                    }.get(status, "❓")
                    
                    cert_table.add_row(
                        cert.get("domain", "unknown"),
                        status_emoji,
                        cert.get("expires_at", "unknown")[:10] if cert.get("expires_at") else "unknown",
                        str(cert.get("days_until_expiry", 0))
                    )
                
                console.print(cert_table)
            
    except httpx.HTTPStatusError as e:
        console.print(f"❌ API request failed: {e.response.status_code}", style="red")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Failed to get SSL status: {e}", style="red")
        raise typer.Exit(1)


# System monitoring commands
monitor_app = typer.Typer(name="monitor", help="System monitoring")
app.add_typer(monitor_app)

@monitor_app.command("health")
def health_check(
    admin_url: str = typer.Option("http://localhost:8081", "--admin-url", help="Admin API URL"),
    token: Optional[str] = typer.Option(None, "--token", help="Authentication token")
):
    """Get system health status"""
    asyncio.run(_health_check_async(admin_url, token))


async def _health_check_async(admin_url: str, token: Optional[str]):
    """Async implementation of health check"""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{admin_url}/admin/api/v1/health", headers=headers)
            response.raise_for_status()
            
            data = response.json()
            
            status = data.get("status", "unknown")
            status_emoji = {
                "healthy": "✅",
                "degraded": "⚠️",
                "unhealthy": "❌",
                "unknown": "❓"
            }.get(status, "❓")
            
            console.print(Panel.fit(f"{status_emoji} System Health: {status.upper()}", style="blue"))
            
            # Summary
            summary = data.get("summary", {})
            console.print(f"Uptime: {data.get('uptime', 0):.2f}s")
            console.print(f"Health Checks: {summary.get('healthy', 0)}✅ {summary.get('degraded', 0)}⚠️ {summary.get('unhealthy', 0)}❌")
            
            # Individual checks
            checks = data.get("checks", [])
            if checks:
                console.print("\n🔍 Health Check Details:", style="bold")
                
                check_table = Table(show_header=True, header_style="bold blue")
                check_table.add_column("Check", style="cyan")
                check_table.add_column("Status", justify="center")
                check_table.add_column("Message")
                check_table.add_column("Duration", justify="right")
                
                for check in checks:
                    check_status = check.get("status", "unknown")
                    check_emoji = {
                        "healthy": "✅",
                        "degraded": "⚠️",
                        "unhealthy": "❌",
                        "unknown": "❓"
                    }.get(check_status, "❓")
                    
                    check_table.add_row(
                        check.get("name", "unknown"),
                        check_emoji,
                        check.get("message", ""),
                        f"{check.get('duration_ms', 0):.1f}ms"
                    )
                
                console.print(check_table)
            
    except httpx.HTTPStatusError as e:
        console.print(f"❌ API request failed: {e.response.status_code}", style="red")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Failed to get health status: {e}", style="red")
        raise typer.Exit(1)


# Authentication helper
@app.command("login")
def login(
    admin_url: str = typer.Option("http://localhost:8081", "--admin-url", help="Admin API URL"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Username"),
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password"),
    save_token: bool = typer.Option(True, "--save", help="Save token to file")
):
    """Login and get authentication token"""
    asyncio.run(_login_async(admin_url, username, password, save_token))


async def _login_async(admin_url: str, username: Optional[str], password: Optional[str], save_token: bool):
    """Async implementation of login"""
    if not username:
        username = typer.prompt("Username")
    
    if not password:
        password = typer.prompt("Password", hide_input=True)
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{admin_url}/admin/api/v1/auth/login",
                json={"username": username, "password": password}
            )
            response.raise_for_status()
            
            data = response.json()
            token = data.get("access_token")
            expires_in = data.get("expires_in", 3600)
            
            console.print("✅ Login successful", style="green")
            console.print(f"Token expires in: {expires_in}s")
            
            if save_token:
                token_file = Path.home() / ".pywaf_token"
                token_file.write_text(token)
                console.print(f"Token saved to: {token_file}")
            else:
                console.print(f"Token: {token}")
            
    except httpx.HTTPStatusError as e:
        console.print(f"❌ Login failed: {e.response.status_code}", style="red")
        if e.response.status_code == 401:
            console.print("Invalid username or password", style="red")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"❌ Login failed: {e}", style="red")
        raise typer.Exit(1)


@app.command()
def hash_password(
    password: Optional[str] = typer.Option(None, "--password", "-p", help="Password to hash")
):
    """Generate bcrypt hash for a password"""
    if not password:
        password = typer.prompt("Password", hide_input=True)
        confirm = typer.prompt("Confirm password", hide_input=True)
        if password != confirm:
            console.print("❌ Passwords do not match", style="red")
            raise typer.Exit(1)
    
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    password_hash = pwd_context.hash(password)
    
    console.print("✅ Password hash generated:", style="green")
    console.print(f"Hash: {password_hash}")
    console.print("\nUse this hash in your configuration file:")
    console.print(f"admin:\n  password_hash: \"{password_hash}\"", style="blue")


# Main CLI entry point
def main():
    """Main CLI entry point"""
    app()


if __name__ == "__main__":
    main()
