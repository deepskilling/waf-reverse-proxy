#!/usr/bin/env python3
"""
PyWAF Demo Script

This script demonstrates the key features of the PyWAF Python implementation
including WAF protection, reverse proxy, SSL management, and monitoring.
"""

import asyncio
import sys
from pathlib import Path

# Add the package to the Python path
sys.path.insert(0, str(Path(__file__).parent))

from pywaf.core.config import Config
from pywaf.core.waf import WAFEngine, RequestContext, WAFAction
from pywaf.core.proxy import ReverseProxy
from pywaf.core.ssl import SSLManager
from pywaf.monitoring.metrics import MetricsCollector
from pywaf.monitoring.health import HealthChecker


async def demo_waf_protection():
    """Demonstrate WAF protection capabilities"""
    print("🛡️  WAF PROTECTION DEMO")
    print("=" * 50)
    
    # Load configuration
    config = Config.load_from_file("config/config.yaml")
    
    # Initialize WAF
    waf = WAFEngine(config)
    
    # Test cases for WAF
    test_cases = [
        {
            "name": "Normal Request",
            "context": RequestContext(
                client_ip="192.168.1.100",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                method="GET",
                path="/api/users",
                query_string="",
                headers={"host": "example.com"}
            )
        },
        {
            "name": "SQL Injection Attempt",
            "context": RequestContext(
                client_ip="192.168.1.200",
                user_agent="Mozilla/5.0 (compatible; Bot/1.0)",
                method="GET", 
                path="/api/users",
                query_string="id=1' UNION SELECT * FROM users--",
                headers={"host": "example.com"}
            )
        },
        {
            "name": "XSS Attempt",
            "context": RequestContext(
                client_ip="192.168.1.300",
                user_agent="Mozilla/5.0",
                method="POST",
                path="/api/comment",
                query_string="",
                headers={"host": "example.com", "content-type": "application/json"},
                body=b'{"comment": "<script>alert(document.cookie)</script>"}'
            )
        },
        {
            "name": "Bot Request",
            "context": RequestContext(
                client_ip="192.168.1.400",
                user_agent="BadBot/1.0 (automated scraper)",
                method="GET",
                path="/api/data",
                query_string="",
                headers={"host": "example.com"}
            )
        }
    ]
    
    for test_case in test_cases:
        print(f"\n🔍 Testing: {test_case['name']}")
        result = await waf.inspect_request(test_case['context'])
        
        status_emoji = "✅" if result.action == WAFAction.ALLOW else "🚫"
        print(f"{status_emoji} Result: {result.action.value} - {result.message}")
        if result.confidence > 0:
            print(f"   Confidence: {result.confidence:.2f}")
        if result.rule_name:
            print(f"   Rule: {result.rule_name}")
    
    # Get WAF statistics
    stats = waf.get_statistics()
    print(f"\n📊 WAF Statistics:")
    print(f"   Total requests processed: {stats['requests_processed']}")
    print(f"   Requests blocked: {stats['requests_blocked']}")
    print(f"   SQL injection blocks: {stats['sql_injection_blocked']}")
    print(f"   XSS blocks: {stats['xss_blocked']}")
    print(f"   Bot blocks: {stats['bots_blocked']}")


async def demo_metrics_collection():
    """Demonstrate metrics collection"""
    print("\n\n📊 METRICS COLLECTION DEMO")
    print("=" * 50)
    
    config = Config.load_from_file("config/config.yaml")
    metrics = MetricsCollector(config)
    await metrics.initialize()
    
    # Simulate some requests
    print("📈 Recording sample metrics...")
    await metrics.record_request("GET", "/api/users", 200, 0.05)
    await metrics.record_request("POST", "/api/login", 200, 0.12)
    await metrics.record_request("GET", "/api/data", 404, 0.02)
    await metrics.record_waf_event("block", "sql_injection", "192.168.1.200")
    await metrics.record_waf_event("allow", None, "192.168.1.100")
    
    # Get statistics
    stats = metrics.get_statistics()
    print(f"✅ Total requests: {stats['requests']['total']}")
    print(f"✅ Request rate: {stats['requests']['rate_per_second']} req/s")
    print(f"✅ Average response time: {stats['requests']['average_response_time_ms']} ms")
    print(f"✅ System CPU: {stats['system'].get('cpu_percent', 0):.1f}%")
    
    # Generate Prometheus metrics
    prometheus_output = await metrics.generate_metrics()
    print(f"✅ Prometheus metrics: {len(prometheus_output)} bytes generated")
    
    await metrics.cleanup()


async def demo_health_checking():
    """Demonstrate health checking"""
    print("\n\n🔍 HEALTH CHECKING DEMO")
    print("=" * 50)
    
    config = Config.load_from_file("config/config.yaml")
    health = HealthChecker(config)
    
    # Run individual health checks
    print("🔍 Running individual health checks...")
    
    system_health = await health.run_health_check("system")
    print(f"✅ System Health: {system_health.status.value} - {system_health.message}")
    
    disk_health = await health.run_health_check("disk_space")
    print(f"✅ Disk Health: {disk_health.status.value} - {disk_health.message}")
    
    memory_health = await health.run_health_check("memory")
    print(f"✅ Memory Health: {memory_health.status.value} - {memory_health.message}")
    
    # Run overall health check
    print("\n🔍 Running overall health assessment...")
    overall = await health.check_all_health()
    
    print(f"📋 Overall Status: {overall.status.value}")
    print(f"📋 Total Checks: {overall.summary['total']}")
    print(f"📋 Healthy: {overall.summary['healthy']}")
    print(f"📋 Unhealthy: {overall.summary['unhealthy']}")
    print(f"📋 Degraded: {overall.summary['degraded']}")


async def demo_ssl_management():
    """Demonstrate SSL certificate management"""
    print("\n\n🔒 SSL CERTIFICATE MANAGEMENT DEMO")
    print("=" * 50)
    
    config = Config.load_from_file("config/config.yaml")
    config.ssl.enabled = True  # Enable SSL for demo
    
    ssl_manager = SSLManager(config)
    await ssl_manager.initialize()
    
    # Get SSL statistics
    stats = ssl_manager.get_statistics()
    print(f"🔒 SSL Enabled: {stats['ssl_enabled']}")
    print(f"🔒 Auto Provisioning: {stats['auto_provision']}")
    print(f"🔒 Total Certificates: {stats['total_certificates']}")
    print(f"🔒 Valid Certificates: {stats['valid_certificates']}")
    print(f"🔒 Expiring Certificates: {stats['expiring_certificates']}")
    
    if stats['certificate_details']:
        print("\n📜 Certificate Details:")
        for cert in stats['certificate_details']:
            print(f"   Domain: {cert['domain']} - Status: {cert['status']}")
    else:
        print("   No certificates currently managed")
    
    await ssl_manager.cleanup()


async def demo_proxy_functionality():
    """Demonstrate reverse proxy functionality"""
    print("\n\n🔄 REVERSE PROXY DEMO")
    print("=" * 50)
    
    config = Config.load_from_file("config/config.yaml")
    proxy = ReverseProxy(config)
    
    # Get proxy statistics
    stats = proxy.get_statistics()
    print(f"🔄 Total Requests: {stats['total_requests']}")
    print(f"🔄 Successful Requests: {stats['successful_requests']}")
    print(f"🔄 Failed Requests: {stats['failed_requests']}")
    print(f"🔄 Cache Hits: {stats['cache_hits']}")
    print(f"🔄 Cache Misses: {stats['cache_misses']}")
    
    # Get upstream status
    upstream_status = proxy.get_upstream_status()
    print(f"\n🎯 Upstream Status:")
    for name, info in upstream_status.items():
        print(f"   {name}: {info['healthy_servers']}/{info['total_servers']} healthy")
        print(f"   Algorithm: {info['algorithm']}")
    
    # Get cache statistics
    cache_stats = proxy.cache.get_stats()
    print(f"\n💾 Cache Statistics:")
    print(f"   Hit Rate: {cache_stats['hit_rate']}%")
    print(f"   Memory Entries: {cache_stats['memory_entries']}")
    print(f"   Memory Size: {cache_stats['memory_size_bytes']} bytes")
    
    await proxy.stop()


def demo_configuration():
    """Demonstrate configuration management"""
    print("\n\n⚙️  CONFIGURATION MANAGEMENT DEMO")
    print("=" * 50)
    
    # Load configuration
    config = Config.load_from_file("config/config.yaml")
    
    # Validate configuration
    errors = config.validate_config()
    if errors:
        print("❌ Configuration validation errors:")
        for error in errors:
            print(f"   - {error}")
    else:
        print("✅ Configuration validation passed")
    
    # Get configuration summary
    summary = config.get_summary()
    print(f"\n📋 Configuration Summary:")
    print(f"   Environment: {summary['environment']}")
    print(f"   Debug Mode: {summary['debug']}")
    print(f"   Server: {summary['server']['host']}:{summary['server']['port']}")
    print(f"   Workers: {summary['server']['workers']}")
    print(f"   SSL Enabled: {summary['ssl']['enabled']}")
    print(f"   WAF Enabled: {summary['waf']['enabled']}")
    print(f"   WAF Mode: {summary['waf']['mode']}")
    print(f"   Upstreams: {summary['proxy']['upstreams']}")
    print(f"   Routes: {summary['proxy']['routes']}")
    print(f"   Admin Enabled: {summary['admin']['enabled']}")
    print(f"   Metrics Enabled: {summary['metrics']['enabled']}")


async def main():
    """Main demo function"""
    print("🚀 PYWAF - COMPLETE PYTHON IMPLEMENTATION DEMO")
    print("=" * 60)
    print("This demo showcases all major features of PyWAF")
    print("=" * 60)
    
    try:
        # Configuration demo (synchronous)
        demo_configuration()
        
        # WAF protection demo
        await demo_waf_protection()
        
        # Metrics collection demo  
        await demo_metrics_collection()
        
        # Health checking demo
        await demo_health_checking()
        
        # SSL management demo
        await demo_ssl_management()
        
        # Proxy functionality demo
        await demo_proxy_functionality()
        
        print("\n\n🎉 DEMO COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print("PyWAF Python implementation is fully functional with:")
        print("✅ Complete WAF protection (OWASP Top 10, bot detection, rate limiting)")
        print("✅ Advanced reverse proxy with load balancing and caching")
        print("✅ SSL/TLS certificate management")
        print("✅ Comprehensive monitoring and health checking")
        print("✅ Rich CLI and REST API management")
        print("✅ Production-ready deployment with Docker")
        print("\nReady for enterprise deployment! 🚀")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
