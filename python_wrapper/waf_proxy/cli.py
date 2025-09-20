"""
Command Line Interface for WAF + Reverse Proxy Python Wrapper

Provides a comprehensive CLI for managing, monitoring, and interacting
with the WAF and Reverse Proxy service.
"""

import os
import sys
import json
import time
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from .client import WafProxyClient, WafProxyError
from .config import ConfigManager, ConfigurationError
from .process import ProcessManager, ProcessError
from .health import HealthMonitor, HealthStatus


class Colors:
    """Terminal color codes"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


class CLI:
    """
    Command Line Interface for WAF + Reverse Proxy
    
    Provides commands for:
    - Service management (start, stop, restart, status)
    - Configuration management
    - Health monitoring
    - Statistics and metrics
    - Admin operations
    """
    
    def __init__(self):
        self.config_manager = None
        self.process_manager = None
        self.client = None
        self.health_monitor = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('waf-proxy-cli')
    
    def print_colored(self, message: str, color: str = Colors.ENDC):
        """Print colored message"""
        print(f"{color}{message}{Colors.ENDC}")
    
    def print_success(self, message: str):
        """Print success message"""
        self.print_colored(f"✅ {message}", Colors.OKGREEN)
    
    def print_error(self, message: str):
        """Print error message"""
        self.print_colored(f"❌ {message}", Colors.FAIL)
    
    def print_warning(self, message: str):
        """Print warning message"""
        self.print_colored(f"⚠️  {message}", Colors.WARNING)
    
    def print_info(self, message: str):
        """Print info message"""
        self.print_colored(f"ℹ️  {message}", Colors.OKBLUE)
    
    def create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description='WAF + Reverse Proxy Management Tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  waf-proxy start --config config/config.yaml
  waf-proxy status --json
  waf-proxy health --full
  waf-proxy config validate
  waf-proxy stats waf
  waf-proxy logs --lines 100
            """
        )
        
        # Global options
        parser.add_argument('--config', '-c', 
                          default='config/config.yaml',
                          help='Configuration file path')
        parser.add_argument('--binary', '-b',
                          default='./target/release/waf-reverse-proxy',
                          help='WAF proxy binary path')
        parser.add_argument('--json', action='store_true',
                          help='Output in JSON format')
        parser.add_argument('--verbose', '-v', action='store_true',
                          help='Verbose output')
        parser.add_argument('--admin-url',
                          default='http://localhost:8081',
                          help='Admin API URL')
        parser.add_argument('--service-url',
                          default='http://localhost:8080',
                          help='Service URL')
        
        # Subcommands
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Service management commands
        self._add_service_commands(subparsers)
        
        # Configuration commands
        self._add_config_commands(subparsers)
        
        # Health and monitoring commands
        self._add_health_commands(subparsers)
        
        # Statistics commands
        self._add_stats_commands(subparsers)
        
        # Admin commands
        self._add_admin_commands(subparsers)
        
        return parser
    
    def _add_service_commands(self, subparsers):
        """Add service management commands"""
        # Start command
        start_parser = subparsers.add_parser('start', help='Start WAF proxy service')
        start_parser.add_argument('--validate', action='store_true',
                                help='Validate configuration before starting')
        start_parser.add_argument('--auto-restart', action='store_true',
                                help='Enable auto-restart on failure')
        start_parser.add_argument('--daemon', action='store_true',
                                help='Run as daemon process')
        
        # Stop command
        stop_parser = subparsers.add_parser('stop', help='Stop WAF proxy service')
        stop_parser.add_argument('--force', action='store_true',
                               help='Force kill if graceful shutdown fails')
        stop_parser.add_argument('--timeout', type=int, default=30,
                               help='Shutdown timeout in seconds')
        
        # Restart command
        restart_parser = subparsers.add_parser('restart', help='Restart WAF proxy service')
        restart_parser.add_argument('--validate', action='store_true',
                                  help='Validate configuration before restart')
        
        # Status command
        status_parser = subparsers.add_parser('status', help='Show service status')
        status_parser.add_argument('--process', action='store_true',
                                 help='Show detailed process information')
        
        # Logs command
        logs_parser = subparsers.add_parser('logs', help='Show service logs')
        logs_parser.add_argument('--lines', '-n', type=int, default=50,
                               help='Number of lines to show')
        logs_parser.add_argument('--follow', '-f', action='store_true',
                               help='Follow log output')
    
    def _add_config_commands(self, subparsers):
        """Add configuration commands"""
        config_parser = subparsers.add_parser('config', help='Configuration management')
        config_subparsers = config_parser.add_subparsers(dest='config_action')
        
        # Validate config
        config_subparsers.add_parser('validate', help='Validate configuration')
        
        # Show config
        show_parser = config_subparsers.add_parser('show', help='Show current configuration')
        show_parser.add_argument('--section', help='Show specific section only')
        
        # Edit config
        config_subparsers.add_parser('edit', help='Edit configuration file')
        
        # Backup config
        backup_parser = config_subparsers.add_parser('backup', help='Create configuration backup')
        backup_parser.add_argument('--suffix', help='Backup filename suffix')
        
        # Restore config
        restore_parser = config_subparsers.add_parser('restore', help='Restore from backup')
        restore_parser.add_argument('backup_file', help='Backup file to restore')
        
        # List backups
        config_subparsers.add_parser('backups', help='List available backups')
        
        # Generate sample config
        sample_parser = config_subparsers.add_parser('sample', help='Generate sample configuration')
        sample_parser.add_argument('--output', '-o', help='Output file path')
    
    def _add_health_commands(self, subparsers):
        """Add health monitoring commands"""
        health_parser = subparsers.add_parser('health', help='Health monitoring')
        health_parser.add_argument('--full', action='store_true',
                                 help='Include all optional health checks')
        health_parser.add_argument('--history', type=int, default=0,
                                 help='Include history (minutes)')
        health_parser.add_argument('--watch', '-w', type=int,
                                 help='Watch mode (refresh interval in seconds)')
    
    def _add_stats_commands(self, subparsers):
        """Add statistics commands"""
        stats_parser = subparsers.add_parser('stats', help='Show statistics')
        stats_subparsers = stats_parser.add_subparsers(dest='stats_type')
        
        stats_subparsers.add_parser('waf', help='WAF statistics')
        stats_subparsers.add_parser('proxy', help='Proxy statistics')
        stats_subparsers.add_parser('ssl', help='SSL certificate statistics')
        stats_subparsers.add_parser('cache', help='Cache statistics')
        stats_subparsers.add_parser('upstreams', help='Upstream server statistics')
        
        # Metrics command
        metrics_parser = subparsers.add_parser('metrics', help='Show Prometheus metrics')
        metrics_parser.add_argument('--filter', help='Filter metrics by name pattern')
    
    def _add_admin_commands(self, subparsers):
        """Add admin commands"""
        # WAF rules management
        rules_parser = subparsers.add_parser('rules', help='Manage WAF rules')
        rules_subparsers = rules_parser.add_subparsers(dest='rules_action')
        
        rules_subparsers.add_parser('list', help='List WAF rules')
        
        add_rule_parser = rules_subparsers.add_parser('add', help='Add WAF rule')
        add_rule_parser.add_argument('--file', help='Rule definition file (JSON/YAML)')
        add_rule_parser.add_argument('--name', required=True, help='Rule name')
        add_rule_parser.add_argument('--action', required=True, 
                                   choices=['allow', 'block', 'monitor', 'log'],
                                   help='Rule action')
        
        delete_rule_parser = rules_subparsers.add_parser('delete', help='Delete WAF rule')
        delete_rule_parser.add_argument('rule_id', help='Rule ID to delete')
        
        # IP management
        ip_parser = subparsers.add_parser('ip', help='IP address management')
        ip_subparsers = ip_parser.add_subparsers(dest='ip_action')
        
        ip_subparsers.add_parser('blocked', help='List blocked IPs')
        
        block_ip_parser = ip_subparsers.add_parser('block', help='Block IP address')
        block_ip_parser.add_argument('ip', help='IP address to block')
        block_ip_parser.add_argument('--reason', help='Reason for blocking')
        block_ip_parser.add_argument('--duration', type=int, help='Block duration in seconds')
        
        unblock_ip_parser = ip_subparsers.add_parser('unblock', help='Unblock IP address')
        unblock_ip_parser.add_argument('ip', help='IP address to unblock')
        
        # Cache management
        cache_parser = subparsers.add_parser('cache', help='Cache management')
        cache_subparsers = cache_parser.add_subparsers(dest='cache_action')
        
        cache_subparsers.add_parser('stats', help='Cache statistics')
        
        clear_cache_parser = cache_subparsers.add_parser('clear', help='Clear cache')
        clear_cache_parser.add_argument('--pattern', help='Clear entries matching pattern')
        
        warm_cache_parser = cache_subparsers.add_parser('warm', help='Warm cache')
        warm_cache_parser.add_argument('urls', nargs='+', help='URLs to warm')
    
    def run(self, args: Optional[List[str]] = None):
        """Run CLI with given arguments"""
        parser = self.create_parser()
        parsed_args = parser.parse_args(args)
        
        # Setup verbose logging
        if parsed_args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Initialize managers
        try:
            self._initialize_managers(parsed_args)
        except Exception as e:
            self.print_error(f"Initialization failed: {e}")
            return 1
        
        # Execute command
        try:
            return self._execute_command(parsed_args)
        except KeyboardInterrupt:
            self.print_info("Operation cancelled by user")
            return 130
        except Exception as e:
            if parsed_args.verbose:
                import traceback
                traceback.print_exc()
            self.print_error(f"Command failed: {e}")
            return 1
    
    def _initialize_managers(self, args):
        """Initialize manager instances"""
        self.config_manager = ConfigManager(args.config)
        self.process_manager = ProcessManager(
            binary_path=args.binary,
            config_path=args.config,
            logger=self.logger
        )
        self.client = WafProxyClient(base_url=args.admin_url)
        self.health_monitor = HealthMonitor(
            service_url=args.service_url,
            admin_url=args.admin_url
        )
    
    def _execute_command(self, args) -> int:
        """Execute the specified command"""
        if args.command == 'start':
            return self._cmd_start(args)
        elif args.command == 'stop':
            return self._cmd_stop(args)
        elif args.command == 'restart':
            return self._cmd_restart(args)
        elif args.command == 'status':
            return self._cmd_status(args)
        elif args.command == 'logs':
            return self._cmd_logs(args)
        elif args.command == 'config':
            return self._cmd_config(args)
        elif args.command == 'health':
            return self._cmd_health(args)
        elif args.command == 'stats':
            return self._cmd_stats(args)
        elif args.command == 'metrics':
            return self._cmd_metrics(args)
        elif args.command == 'rules':
            return self._cmd_rules(args)
        elif args.command == 'ip':
            return self._cmd_ip(args)
        elif args.command == 'cache':
            return self._cmd_cache(args)
        else:
            self.print_error("No command specified. Use --help for available commands.")
            return 1
    
    def _cmd_start(self, args) -> int:
        """Start service command"""
        try:
            if self.process_manager.is_running():
                self.print_warning("Service is already running")
                return 0
            
            self.print_info("Starting WAF + Reverse Proxy service...")
            
            success = self.process_manager.start(
                validate_config=args.validate,
                auto_restart=args.auto_restart
            )
            
            if success:
                self.print_success(f"Service started successfully (PID: {self.process_manager.get_pid()})")
                
                # Wait a moment and check health
                time.sleep(2)
                try:
                    health = self.health_monitor.check_all(include_optional=False)
                    if health.overall_status == HealthStatus.HEALTHY:
                        self.print_success("Service is healthy and ready")
                    else:
                        self.print_warning("Service started but health check indicates issues")
                except Exception:
                    self.print_warning("Service started but health check failed")
                
                return 0
            else:
                self.print_error("Failed to start service")
                return 1
                
        except ProcessError as e:
            self.print_error(f"Start failed: {e}")
            return 1
    
    def _cmd_stop(self, args) -> int:
        """Stop service command"""
        try:
            if not self.process_manager.is_running():
                self.print_warning("Service is not running")
                return 0
            
            self.print_info("Stopping WAF + Reverse Proxy service...")
            
            success = self.process_manager.stop(
                timeout=args.timeout,
                force=args.force
            )
            
            if success:
                self.print_success("Service stopped successfully")
                return 0
            else:
                self.print_error("Failed to stop service")
                return 1
                
        except ProcessError as e:
            self.print_error(f"Stop failed: {e}")
            return 1
    
    def _cmd_restart(self, args) -> int:
        """Restart service command"""
        try:
            self.print_info("Restarting WAF + Reverse Proxy service...")
            
            success = self.process_manager.restart(
                validate_config=args.validate
            )
            
            if success:
                self.print_success(f"Service restarted successfully (PID: {self.process_manager.get_pid()})")
                return 0
            else:
                self.print_error("Failed to restart service")
                return 1
                
        except ProcessError as e:
            self.print_error(f"Restart failed: {e}")
            return 1
    
    def _cmd_status(self, args) -> int:
        """Show status command"""
        try:
            status = self.process_manager.get_status()
            
            if args.json:
                print(json.dumps(status, indent=2, default=str))
                return 0
            
            # Pretty print status
            self.print_colored("📊 WAF + Reverse Proxy Status", Colors.BOLD)
            print()
            
            if status['running']:
                self.print_success(f"Service is running (PID: {status['pid']})")
                if status.get('uptime'):
                    uptime_str = self._format_uptime(status['uptime'])
                    self.print_info(f"Uptime: {uptime_str}")
                
                if args.process and 'cpu_percent' in status:
                    print()
                    self.print_colored("Process Information:", Colors.HEADER)
                    print(f"  CPU Usage: {status.get('cpu_percent', 0):.1f}%")
                    print(f"  Memory: {status.get('memory_mb', 0):.1f} MB")
                    print(f"  Threads: {status.get('threads', 0)}")
                    print(f"  Open Files: {status.get('open_files', 0)}")
                    print(f"  Connections: {status.get('connections', 0)}")
            else:
                self.print_error("Service is not running")
                if status.get('restart_count', 0) > 0:
                    self.print_info(f"Restart count: {status['restart_count']}")
            
            return 0
            
        except Exception as e:
            self.print_error(f"Status check failed: {e}")
            return 1
    
    def _cmd_logs(self, args) -> int:
        """Show logs command"""
        try:
            logs = self.process_manager.get_logs(args.lines)
            
            if not logs:
                self.print_info("No logs available")
                return 0
            
            if args.follow:
                # TODO: Implement follow mode
                self.print_warning("Follow mode not yet implemented")
            
            for log_line in logs:
                print(log_line)
            
            return 0
            
        except Exception as e:
            self.print_error(f"Failed to get logs: {e}")
            return 1
    
    def _cmd_config(self, args) -> int:
        """Configuration management commands"""
        try:
            if args.config_action == 'validate':
                config = self.config_manager.load_config(validate=True)
                self.print_success("Configuration is valid")
                if args.json:
                    print(json.dumps(config, indent=2, default=str))
                return 0
                
            elif args.config_action == 'show':
                config = self.config_manager.get_current_config()
                
                if args.section and args.section in config:
                    config = {args.section: config[args.section]}
                
                if args.json:
                    print(json.dumps(config, indent=2, default=str))
                else:
                    import yaml
                    print(yaml.dump(config, default_flow_style=False, indent=2))
                return 0
                
            elif args.config_action == 'backup':
                backup_path = self.config_manager.create_backup(args.suffix)
                self.print_success(f"Configuration backed up to: {backup_path}")
                return 0
                
            elif args.config_action == 'restore':
                self.config_manager.restore_backup(args.backup_file)
                self.print_success(f"Configuration restored from: {args.backup_file}")
                return 0
                
            elif args.config_action == 'backups':
                backups = self.config_manager.list_backups()
                
                if args.json:
                    print(json.dumps(backups, indent=2, default=str))
                else:
                    self.print_colored("Available Configuration Backups:", Colors.HEADER)
                    for backup in backups:
                        print(f"  {backup['filename']} - {backup['created']} ({backup['size']} bytes)")
                return 0
                
            elif args.config_action == 'sample':
                sample_config = self.config_manager.generate_sample_config()
                
                if args.output:
                    import yaml
                    with open(args.output, 'w') as f:
                        yaml.dump(sample_config, f, default_flow_style=False, indent=2)
                    self.print_success(f"Sample configuration written to: {args.output}")
                else:
                    import yaml
                    print(yaml.dump(sample_config, default_flow_style=False, indent=2))
                return 0
            
        except (ConfigurationError, Exception) as e:
            self.print_error(f"Configuration command failed: {e}")
            return 1
    
    def _cmd_health(self, args) -> int:
        """Health monitoring command"""
        try:
            if args.watch:
                # Watch mode
                import signal
                def signal_handler(signum, frame):
                    sys.exit(0)
                signal.signal(signal.SIGINT, signal_handler)
                
                while True:
                    os.system('clear' if os.name == 'posix' else 'cls')
                    self._show_health_status(args)
                    time.sleep(args.watch)
            else:
                return self._show_health_status(args)
                
        except Exception as e:
            self.print_error(f"Health check failed: {e}")
            return 1
    
    def _show_health_status(self, args) -> int:
        """Show health status"""
        health = self.health_monitor.check_all(include_optional=args.full)
        
        if args.json:
            result = health.to_dict()
            if args.history > 0:
                history = self.health_monitor.get_health_history(args.history)
                result['history'] = [h.to_dict() for h in history]
            print(json.dumps(result, indent=2))
            return 0
        
        # Pretty print health status
        self.print_colored("🏥 Health Status", Colors.BOLD)
        print()
        
        # Overall status
        status_color = Colors.OKGREEN if health.overall_status == HealthStatus.HEALTHY else Colors.FAIL
        self.print_colored(f"Overall Status: {health.overall_status.value.upper()}", status_color)
        print(f"Last Updated: {health.last_updated}")
        print(f"Uptime: {self._format_uptime(health.uptime)}")
        print()
        
        # Individual checks
        self.print_colored("Individual Checks:", Colors.HEADER)
        for check in health.checks:
            status_icon = "✅" if check.status == HealthStatus.HEALTHY else "❌" if check.status == HealthStatus.UNHEALTHY else "⚠️"
            print(f"  {status_icon} {check.name}: {check.message} ({check.response_time:.3f}s)")
        
        # Uptime percentage
        uptime_24h = self.health_monitor.get_uptime_percentage(24)
        uptime_7d = self.health_monitor.get_uptime_percentage(24 * 7)
        print()
        self.print_colored("Uptime Statistics:", Colors.HEADER)
        print(f"  Last 24 hours: {uptime_24h:.2f}%")
        print(f"  Last 7 days: {uptime_7d:.2f}%")
        
        return 0 if health.overall_status == HealthStatus.HEALTHY else 1
    
    def _cmd_stats(self, args) -> int:
        """Statistics command"""
        try:
            if args.stats_type == 'waf':
                stats = self.client.get_waf_stats()
                if args.json:
                    print(json.dumps(stats.__dict__, indent=2))
                else:
                    self._print_waf_stats(stats)
                    
            elif args.stats_type == 'proxy':
                stats = self.client.get_proxy_stats()
                if args.json:
                    print(json.dumps(stats.__dict__, indent=2))
                else:
                    self._print_proxy_stats(stats)
                    
            elif args.stats_type == 'ssl':
                stats = self.client.get_ssl_stats()
                if args.json:
                    print(json.dumps(stats, indent=2))
                else:
                    self._print_ssl_stats(stats)
                    
            else:
                self.print_error("Invalid stats type")
                return 1
            
            return 0
            
        except WafProxyError as e:
            self.print_error(f"Statistics request failed: {e}")
            return 1
    
    def _cmd_metrics(self, args) -> int:
        """Metrics command"""
        try:
            metrics = self.client.get_metrics()
            
            if args.filter:
                # Filter metrics by pattern
                filtered_lines = []
                for line in metrics.split('\n'):
                    if args.filter.lower() in line.lower():
                        filtered_lines.append(line)
                print('\n'.join(filtered_lines))
            else:
                print(metrics)
            
            return 0
            
        except WafProxyError as e:
            self.print_error(f"Metrics request failed: {e}")
            return 1
    
    def _cmd_rules(self, args) -> int:
        """WAF rules management"""
        try:
            if args.rules_action == 'list':
                rules = self.client.get_waf_rules()
                
                if args.json:
                    print(json.dumps(rules, indent=2))
                else:
                    self.print_colored("WAF Rules:", Colors.HEADER)
                    for rule in rules:
                        print(f"  {rule.get('id', 'N/A')}: {rule.get('name', 'N/A')} ({rule.get('action', 'N/A')})")
                
            return 0
            
        except WafProxyError as e:
            self.print_error(f"Rules command failed: {e}")
            return 1
    
    def _cmd_ip(self, args) -> int:
        """IP management commands"""
        try:
            if args.ip_action == 'blocked':
                ips = self.client.get_blocked_ips()
                
                if args.json:
                    print(json.dumps(ips, indent=2))
                else:
                    self.print_colored("Blocked IPs:", Colors.HEADER)
                    for ip in ips:
                        print(f"  {ip}")
                        
            elif args.ip_action == 'block':
                result = self.client.block_ip(
                    args.ip, 
                    reason=args.reason or "Blocked via CLI",
                    duration=args.duration
                )
                self.print_success(f"IP {args.ip} blocked successfully")
                
            elif args.ip_action == 'unblock':
                result = self.client.unblock_ip(args.ip)
                self.print_success(f"IP {args.ip} unblocked successfully")
            
            return 0
            
        except WafProxyError as e:
            self.print_error(f"IP management command failed: {e}")
            return 1
    
    def _cmd_cache(self, args) -> int:
        """Cache management commands"""
        try:
            if args.cache_action == 'stats':
                stats = self.client.get_cache_stats()
                
                if args.json:
                    print(json.dumps(stats, indent=2))
                else:
                    self._print_cache_stats(stats)
                    
            elif args.cache_action == 'clear':
                result = self.client.clear_cache(pattern=args.pattern)
                self.print_success("Cache cleared successfully")
                
            elif args.cache_action == 'warm':
                result = self.client.warm_cache(args.urls)
                self.print_success(f"Cache warmed for {len(args.urls)} URLs")
            
            return 0
            
        except WafProxyError as e:
            self.print_error(f"Cache command failed: {e}")
            return 1
    
    def _format_uptime(self, seconds: float) -> str:
        """Format uptime in human readable format"""
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        seconds = int(seconds % 60)
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if seconds > 0 or not parts:
            parts.append(f"{seconds}s")
            
        return " ".join(parts)
    
    def _print_waf_stats(self, stats):
        """Print WAF statistics in formatted way"""
        self.print_colored("🛡️  WAF Statistics", Colors.BOLD)
        print(f"  Total Requests: {stats.total_requests:,}")
        print(f"  Blocked Requests: {stats.blocked_requests:,}")
        print(f"  Allowed Requests: {stats.allowed_requests:,}")
        print(f"  Rate Limited: {stats.rate_limited:,}")
        print(f"  Geo Blocked: {stats.geo_blocked:,}")
        print(f"  Bot Blocked: {stats.bot_blocked:,}")
        print(f"  OWASP Blocked: {stats.owasp_blocked:,}")
        print(f"  Custom Rule Blocked: {stats.custom_rule_blocked:,}")
    
    def _print_proxy_stats(self, stats):
        """Print proxy statistics in formatted way"""
        self.print_colored("🔄 Proxy Statistics", Colors.BOLD)
        print(f"  Total Requests: {stats.total_requests:,}")
        print(f"  Successful Requests: {stats.successful_requests:,}")
        print(f"  Failed Requests: {stats.failed_requests:,}")
        print(f"  Average Response Time: {stats.avg_response_time:.3f}s")
        print(f"  Cache Hits: {stats.cache_hits:,}")
        print(f"  Cache Misses: {stats.cache_misses:,}")
        print(f"  Upstream Errors: {stats.upstream_errors:,}")
    
    def _print_ssl_stats(self, stats):
        """Print SSL statistics in formatted way"""
        self.print_colored("🔐 SSL Statistics", Colors.BOLD)
        for key, value in stats.items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
    
    def _print_cache_stats(self, stats):
        """Print cache statistics in formatted way"""
        self.print_colored("💾 Cache Statistics", Colors.BOLD)
        for key, value in stats.items():
            if isinstance(value, (int, float)):
                print(f"  {key.replace('_', ' ').title()}: {value:,}")
            else:
                print(f"  {key.replace('_', ' ').title()}: {value}")


def main():
    """Main entry point for CLI"""
    cli = CLI()
    sys.exit(cli.run())


if __name__ == '__main__':
    main()
