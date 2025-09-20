#!/usr/bin/env python3
"""
WAF + Reverse Proxy Load Test Script - Python Version
=====================================================

A comprehensive load testing tool for the WAF + Reverse Proxy by Deepskilling.
Supports concurrent requests, various attack scenarios, and detailed reporting.

Usage:
    python load_test.py --url http://localhost:8080 --threads 12 --connections 400 --duration 30
    
Features:
    - Multi-threaded concurrent requests
    - WAF attack scenario simulation (SQL injection, XSS)
    - Bot detection testing with various user agents
    - Detailed statistics and latency reporting
    - Customizable test scenarios and parameters
"""

import asyncio
import aiohttp
import argparse
import json
import random
import time
import statistics
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple
import sys
import signal

class LoadTestStats:
    """Statistics collector for load test results"""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        self.response_times = []
        self.status_codes = Counter()
        self.error_types = Counter()
        self.bytes_received = 0
        self.waf_blocks = 0
        self.server_errors = 0
        
    def add_response(self, response_time: float, status_code: int, 
                    content_length: int = 0, error_type: str = None):
        """Add a response to statistics"""
        self.total_requests += 1
        self.response_times.append(response_time)
        self.status_codes[status_code] += 1
        self.bytes_received += content_length
        
        if 200 <= status_code < 300:
            self.successful_requests += 1
        elif 400 <= status_code < 500:
            self.failed_requests += 1
            if status_code in [403, 429]:  # Common WAF/rate limit status codes
                self.waf_blocks += 1
        elif 500 <= status_code < 600:
            self.failed_requests += 1
            self.server_errors += 1
        
        if error_type:
            self.error_types[error_type] += 1
    
    def get_percentile(self, percentile: float) -> float:
        """Calculate response time percentile"""
        if not self.response_times:
            return 0.0
        return statistics.quantiles(sorted(self.response_times), n=100)[int(percentile) - 1]
    
    def get_summary(self) -> Dict:
        """Get comprehensive test summary"""
        duration = (self.end_time - self.start_time).total_seconds() if self.end_time else 0
        
        return {
            'duration': duration,
            'total_requests': self.total_requests,
            'successful_requests': self.successful_requests,
            'failed_requests': self.failed_requests,
            'requests_per_second': self.total_requests / duration if duration > 0 else 0,
            'bytes_received': self.bytes_received,
            'waf_blocks': self.waf_blocks,
            'server_errors': self.server_errors,
            'avg_response_time': statistics.mean(self.response_times) if self.response_times else 0,
            'min_response_time': min(self.response_times) if self.response_times else 0,
            'max_response_time': max(self.response_times) if self.response_times else 0,
            'p50_response_time': self.get_percentile(50) if self.response_times else 0,
            'p90_response_time': self.get_percentile(90) if self.response_times else 0,
            'p99_response_time': self.get_percentile(99) if self.response_times else 0,
            'status_codes': dict(self.status_codes),
            'error_types': dict(self.error_types)
        }

class WAFLoadTester:
    """Main load tester class"""
    
    # Test endpoints
    PATHS = [
        "/",
        "/api/health",
        "/api/status", 
        "/test",
        "/static/index.html",
        "/api/users",
        "/dashboard",
        "/admin"
    ]
    
    # HTTP methods to test
    METHODS = ["GET", "POST", "PUT", "DELETE"]
    
    # User agents for bot detection testing
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "curl/7.68.0",
        "python-requests/2.31.0",
        "Wget/1.20.3",
        "HTTPie/3.2.0",
        "PostmanRuntime/7.32.0",
        # Suspicious bot patterns (should be blocked)
        "BadBot/1.0",
        "Scrapy/2.5.0",
        "python-crawler/1.0"
    ]
    
    # Attack payloads for WAF testing
    SQL_INJECTION_PAYLOADS = [
        "1' OR '1'='1",
        "' UNION SELECT * FROM users--",
        "'; DROP TABLE users;--",
        "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM users GROUP BY x)a)",
        "admin'/*"
    ]
    
    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "'+alert('xss')+'",
        "<svg onload=alert('xss')>"
    ]
    
    RCE_PAYLOADS = [
        "; cat /etc/passwd",
        "| whoami",
        "&& ls -la",
        "`id`",
        "$(cat /etc/hosts)"
    ]
    
    def __init__(self, base_url: str, concurrency: int = 10, duration: int = 30):
        self.base_url = base_url.rstrip('/')
        self.concurrency = concurrency
        self.duration = duration
        self.stats = LoadTestStats()
        self.request_counter = 0
        self.running = True
        
    async def make_request(self, session: aiohttp.ClientSession) -> None:
        """Make a single HTTP request"""
        self.request_counter += 1
        
        # Select random components
        path = random.choice(self.PATHS)
        method = random.choice(self.METHODS)
        user_agent = random.choice(self.USER_AGENTS)
        
        # Add attack payloads occasionally to test WAF
        if self.request_counter % 10 == 0:
            # SQL Injection test
            payload = random.choice(self.SQL_INJECTION_PAYLOADS)
            path += f"?id={payload}"
        elif self.request_counter % 15 == 0:
            # XSS test
            payload = random.choice(self.XSS_PAYLOADS)
            path += f"?search={payload}"
        elif self.request_counter % 20 == 0:
            # RCE test  
            payload = random.choice(self.RCE_PAYLOADS)
            path += f"?cmd={payload}"
        elif self.request_counter % 25 == 0:
            # Path traversal test
            path += "/../../../etc/passwd"
        elif self.request_counter % 30 == 0:
            # Large payload test (potential DoS)
            path += "?data=" + "A" * 10000
        
        # Build headers
        headers = {
            'User-Agent': user_agent,
            'Accept': 'application/json, text/html, */*',
            'Connection': 'keep-alive',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        
        # Add body for POST/PUT requests
        data = None
        if method in ['POST', 'PUT']:
            headers['Content-Type'] = 'application/json'
            data = json.dumps({
                'test': 'data',
                'counter': self.request_counter,
                'timestamp': datetime.now().isoformat(),
                'user_id': random.randint(1, 1000)
            })
        
        # Add some random headers occasionally
        if self.request_counter % 7 == 0:
            headers['X-Forwarded-For'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        
        if self.request_counter % 11 == 0:
            headers['X-Real-IP'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        
        url = f"{self.base_url}{path}"
        start_time = time.time()
        
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with session.request(
                method=method,
                url=url, 
                headers=headers,
                data=data,
                timeout=timeout,
                allow_redirects=False
            ) as response:
                content = await response.read()
                response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
                
                self.stats.add_response(
                    response_time=response_time,
                    status_code=response.status,
                    content_length=len(content)
                )
                
        except asyncio.TimeoutError:
            response_time = (time.time() - start_time) * 1000
            self.stats.add_response(
                response_time=response_time,
                status_code=408,  # Request Timeout
                error_type="timeout"
            )
        except aiohttp.ClientError as e:
            response_time = (time.time() - start_time) * 1000
            self.stats.add_response(
                response_time=response_time,
                status_code=0,  # Connection error
                error_type=type(e).__name__
            )
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            self.stats.add_response(
                response_time=response_time,
                status_code=0,
                error_type=type(e).__name__
            )
    
    async def worker(self, session: aiohttp.ClientSession) -> None:
        """Worker coroutine for making requests"""
        while self.running:
            await self.make_request(session)
            # Small delay to prevent overwhelming
            await asyncio.sleep(0.001)
    
    async def run_test(self) -> None:
        """Run the load test"""
        print(f"🚀 Starting WAF + Reverse Proxy Load Test - Deepskilling")
        print(f"📊 Target: {self.base_url}")
        print(f"⚡ Concurrency: {self.concurrency}")
        print(f"⏱️  Duration: {self.duration} seconds")
        print(f"🛡️  WAF Attack Scenarios: Enabled")
        print("-" * 60)
        
        self.stats.start_time = datetime.now()
        
        # Configure aiohttp session
        connector = aiohttp.TCPConnector(
            limit=self.concurrency * 2,
            limit_per_host=self.concurrency * 2,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )
        
        timeout = aiohttp.ClientTimeout(total=30)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={'User-Agent': 'WAF-LoadTester/1.0 (Deepskilling)'}
        ) as session:
            
            # Start worker tasks
            tasks = [
                asyncio.create_task(self.worker(session)) 
                for _ in range(self.concurrency)
            ]
            
            # Run for specified duration
            await asyncio.sleep(self.duration)
            
            # Stop workers
            self.running = False
            
            # Cancel remaining tasks
            for task in tasks:
                task.cancel()
            
            # Wait for tasks to complete
            await asyncio.gather(*tasks, return_exceptions=True)
        
        self.stats.end_time = datetime.now()
    
    def print_results(self) -> None:
        """Print detailed test results"""
        summary = self.stats.get_summary()
        
        print("\n" + "=" * 80)
        print("🎯 LOAD TEST RESULTS - WAF + Reverse Proxy by Deepskilling")
        print("=" * 80)
        
        # Basic statistics
        print(f"⏱️  Duration: {summary['duration']:.2f} seconds")
        print(f"📊 Total Requests: {summary['total_requests']:,}")
        print(f"✅ Successful: {summary['successful_requests']:,} ({summary['successful_requests']/summary['total_requests']*100:.1f}%)")
        print(f"❌ Failed: {summary['failed_requests']:,} ({summary['failed_requests']/summary['total_requests']*100:.1f}%)")
        print(f"🔥 Requests/sec: {summary['requests_per_second']:.2f}")
        print(f"📈 Throughput: {summary['bytes_received']/1024/1024:.2f} MB")
        
        print(f"\n🛡️  WAF PROTECTION ANALYSIS:")
        print(f"🚫 WAF Blocks: {summary['waf_blocks']:,}")
        print(f"💥 Server Errors: {summary['server_errors']:,}")
        print(f"🔒 Block Rate: {summary['waf_blocks']/summary['total_requests']*100:.2f}%")
        
        print(f"\n⚡ RESPONSE TIME ANALYSIS:")
        print(f"📊 Average: {summary['avg_response_time']:.2f} ms")
        print(f"⚡ Minimum: {summary['min_response_time']:.2f} ms")
        print(f"🐌 Maximum: {summary['max_response_time']:.2f} ms")
        print(f"📈 50th percentile: {summary['p50_response_time']:.2f} ms")
        print(f"📈 90th percentile: {summary['p90_response_time']:.2f} ms") 
        print(f"📈 99th percentile: {summary['p99_response_time']:.2f} ms")
        
        print(f"\n📋 STATUS CODE DISTRIBUTION:")
        for status_code, count in sorted(summary['status_codes'].items()):
            percentage = count / summary['total_requests'] * 100
            status_desc = self.get_status_description(status_code)
            print(f"   {status_code} ({status_desc}): {count:,} ({percentage:.1f}%)")
        
        if summary['error_types']:
            print(f"\n❌ ERROR TYPES:")
            for error_type, count in summary['error_types'].items():
                percentage = count / summary['total_requests'] * 100
                print(f"   {error_type}: {count:,} ({percentage:.1f}%)")
        
        # WAF Effectiveness Analysis
        attack_requests = summary['total_requests'] // 10 + summary['total_requests'] // 15 + summary['total_requests'] // 20
        if attack_requests > 0:
            print(f"\n🛡️  WAF EFFECTIVENESS:")
            print(f"🎯 Attack Requests: ~{attack_requests}")
            print(f"🚫 Blocked Attacks: {summary['waf_blocks']}")
            print(f"📊 Block Effectiveness: {summary['waf_blocks']/attack_requests*100:.1f}%")
        
        print("\n" + "=" * 80)
        print("✅ Load test completed successfully!")
        print("📊 WAF + Reverse Proxy performance analyzed by Deepskilling")
        print("=" * 80)
    
    @staticmethod
    def get_status_description(status_code: int) -> str:
        """Get human-readable status code description"""
        status_map = {
            200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
            301: "Moved Permanently", 302: "Found", 304: "Not Modified",
            400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 
            404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
            429: "Too Many Requests", 500: "Internal Server Error",
            502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
            0: "Connection Error"
        }
        return status_map.get(status_code, "Unknown")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n🛑 Test interrupted by user")
    sys.exit(0)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="WAF + Reverse Proxy Load Tester by Deepskilling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Basic load test
    python load_test.py --url http://localhost:8080
    
    # High concurrency test
    python load_test.py --url http://localhost:8080 --concurrency 100 --duration 60
    
    # Test specific scenarios
    python load_test.py --url http://localhost:8080 --concurrency 50 --duration 30
        """
    )
    
    parser.add_argument(
        '--url', '-u',
        default='http://localhost:8080',
        help='Target URL (default: http://localhost:8080)'
    )
    
    parser.add_argument(
        '--concurrency', '-c',
        type=int,
        default=10,
        help='Number of concurrent connections (default: 10)'
    )
    
    parser.add_argument(
        '--duration', '-d',
        type=int, 
        default=30,
        help='Test duration in seconds (default: 30)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='WAF Load Tester 1.0.0 by Deepskilling'
    )
    
    args = parser.parse_args()
    
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Validate arguments
    if args.concurrency < 1:
        print("❌ Error: Concurrency must be at least 1")
        sys.exit(1)
    
    if args.duration < 1:
        print("❌ Error: Duration must be at least 1 second")
        sys.exit(1)
    
    # Create and run load tester
    tester = WAFLoadTester(
        base_url=args.url,
        concurrency=args.concurrency,
        duration=args.duration
    )
    
    try:
        # Run the async test
        asyncio.run(tester.run_test())
        
        # Print results
        tester.print_results()
        
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
