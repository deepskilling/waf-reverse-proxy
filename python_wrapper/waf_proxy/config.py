"""
Configuration Manager for WAF + Reverse Proxy

Provides utilities for managing YAML configuration files, validation,
and runtime configuration updates.
"""

import os
import yaml
import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import ipaddress
import re


@dataclass
class ServerConfig:
    """Server configuration"""
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4
    max_connections: int = 1000


@dataclass
class SslConfig:
    """SSL/TLS configuration"""
    enabled: bool = False
    https_port: int = 8443
    cert_path: Optional[str] = None
    key_path: Optional[str] = None
    protocols: List[str] = None
    ciphers: List[str] = None
    auto_provision: bool = False
    acme_directory_url: str = "https://acme-v02.api.letsencrypt.org/directory"
    acme_email: str = "admin@example.com"
    storage_path: Optional[str] = "./certs"
    renewal_check_interval: str = "1h"
    domains: List[str] = None
    
    def __post_init__(self):
        if self.protocols is None:
            self.protocols = ["TLS1.2", "TLS1.3"]
        if self.ciphers is None:
            self.ciphers = ["TLS13_AES_256_GCM_SHA384", "TLS13_AES_128_GCM_SHA256"]
        if self.domains is None:
            self.domains = []


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    requests_per_second: Optional[int] = None
    requests_per_minute: Optional[int] = None
    burst: int = 100
    cleanup_interval: str = "5m"


@dataclass
class WafConfig:
    """WAF configuration"""
    enabled: bool = True
    mode: str = "block"  # block, monitor, log
    rate_limiting: Dict[str, RateLimitConfig] = None
    owasp_protection: Dict[str, Any] = None
    bot_protection: Dict[str, Any] = None
    geo_blocking: Dict[str, Any] = None
    custom_rules: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.rate_limiting is None:
            self.rate_limiting = {
                "global": {"requests_per_second": 100, "burst": 200},
                "per_ip": {"requests_per_minute": 1000, "burst": 500},
                "per_endpoint": {"requests_per_second": 10, "burst": 20}
            }
        if self.custom_rules is None:
            self.custom_rules = []


@dataclass
class ProxyConfig:
    """Proxy configuration"""
    upstreams: Dict[str, Dict[str, Any]] = None
    routes: List[Dict[str, Any]] = None
    caching: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.upstreams is None:
            self.upstreams = {}
        if self.routes is None:
            self.routes = []
        if self.caching is None:
            self.caching = {"enabled": True, "default_ttl": "300s", "max_size": "1GB"}


class ConfigurationError(Exception):
    """Configuration-related errors"""
    pass


class ConfigValidator:
    """Configuration validator"""
    
    @staticmethod
    def validate_server_config(config: Dict[str, Any]) -> List[str]:
        """Validate server configuration"""
        errors = []
        
        if 'port' in config:
            port = config['port']
            if not isinstance(port, int) or port < 1 or port > 65535:
                errors.append("Server port must be between 1 and 65535")
        
        if 'workers' in config:
            workers = config['workers']
            if not isinstance(workers, int) or workers < 1:
                errors.append("Worker count must be a positive integer")
        
        if 'max_connections' in config:
            max_conn = config['max_connections']
            if not isinstance(max_conn, int) or max_conn < 1:
                errors.append("Max connections must be a positive integer")
        
        return errors
    
    @staticmethod
    def validate_ssl_config(config: Dict[str, Any]) -> List[str]:
        """Validate SSL configuration"""
        errors = []
        
        if not config.get('enabled', False):
            return errors  # Skip validation if SSL is disabled
        
        if not config.get('auto_provision', False):
            # Manual certificate mode
            if not config.get('cert_path'):
                errors.append("SSL cert_path is required when auto_provision is disabled")
            if not config.get('key_path'):
                errors.append("SSL key_path is required when auto_provision is disabled")
        else:
            # Auto-provision mode
            if not config.get('acme_email'):
                errors.append("ACME email is required for auto-provisioning")
            
            email = config.get('acme_email', '')
            if email and not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
                errors.append("Invalid ACME email format")
            
            domains = config.get('domains', [])
            if not domains:
                errors.append("At least one domain is required for auto-provisioning")
        
        return errors
    
    @staticmethod
    def validate_waf_rules(rules: List[Dict[str, Any]]) -> List[str]:
        """Validate WAF custom rules"""
        errors = []
        
        for i, rule in enumerate(rules):
            if 'name' not in rule:
                errors.append(f"Rule {i}: 'name' is required")
            
            if 'action' not in rule:
                errors.append(f"Rule {i}: 'action' is required")
            elif rule['action'] not in ['allow', 'block', 'monitor', 'log']:
                errors.append(f"Rule {i}: invalid action '{rule['action']}'")
            
            if 'conditions' not in rule or not rule['conditions']:
                errors.append(f"Rule {i}: at least one condition is required")
        
        return errors
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address or CIDR"""
        try:
            ipaddress.ip_network(ip, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_upstreams(upstreams: Dict[str, Any]) -> List[str]:
        """Validate upstream configurations"""
        errors = []
        
        for name, upstream in upstreams.items():
            if 'servers' not in upstream:
                errors.append(f"Upstream '{name}': servers list is required")
                continue
            
            servers = upstream.get('servers', [])
            if not servers:
                errors.append(f"Upstream '{name}': at least one server is required")
            
            for j, server in enumerate(servers):
                if 'url' not in server:
                    errors.append(f"Upstream '{name}' server {j}: URL is required")
        
        return errors


class ConfigManager:
    """
    Configuration manager for WAF + Reverse Proxy
    
    Handles loading, validation, updating, and saving configuration files.
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize configuration manager
        
        Args:
            config_path: Path to the main configuration file
        """
        self.config_path = Path(config_path)
        self.config_dir = self.config_path.parent
        self.backup_dir = self.config_dir / "backups"
        self.validator = ConfigValidator()
        self._config: Optional[Dict[str, Any]] = None
        
        # Ensure directories exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def load_config(self, validate: bool = True) -> Dict[str, Any]:
        """
        Load configuration from file
        
        Args:
            validate: Whether to validate the configuration
            
        Returns:
            Loaded configuration dictionary
            
        Raises:
            ConfigurationError: If config file is invalid or doesn't exist
        """
        if not self.config_path.exists():
            raise ConfigurationError(f"Configuration file not found: {self.config_path}")
        
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            if config is None:
                raise ConfigurationError("Configuration file is empty")
            
            if validate:
                errors = self.validate_config(config)
                if errors:
                    raise ConfigurationError(f"Configuration validation failed:\n" + "\n".join(errors))
            
            self._config = config
            return config
            
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Failed to parse YAML configuration: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {e}")
    
    def validate_config(self, config: Dict[str, Any]) -> List[str]:
        """
        Validate configuration
        
        Args:
            config: Configuration dictionary to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Validate server config
        if 'server' in config:
            errors.extend(self.validator.validate_server_config(config['server']))
        
        # Validate SSL config
        if 'ssl' in config:
            errors.extend(self.validator.validate_ssl_config(config['ssl']))
        
        # Validate WAF rules
        if 'waf' in config and 'custom_rules' in config['waf']:
            errors.extend(self.validator.validate_waf_rules(config['waf']['custom_rules']))
        
        # Validate upstreams
        if 'proxy' in config and 'upstreams' in config['proxy']:
            errors.extend(self.validator.validate_upstreams(config['proxy']['upstreams']))
        
        return errors
    
    def save_config(self, config: Optional[Dict[str, Any]] = None, backup: bool = True) -> bool:
        """
        Save configuration to file
        
        Args:
            config: Configuration to save (uses current if None)
            backup: Whether to create a backup first
            
        Returns:
            True if saved successfully
            
        Raises:
            ConfigurationError: If save fails
        """
        if config is None:
            if self._config is None:
                raise ConfigurationError("No configuration to save")
            config = self._config
        
        # Validate before saving
        errors = self.validate_config(config)
        if errors:
            raise ConfigurationError(f"Cannot save invalid configuration:\n" + "\n".join(errors))
        
        # Create backup if requested
        if backup and self.config_path.exists():
            self.create_backup()
        
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            
            self._config = config
            return True
            
        except Exception as e:
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def create_backup(self, suffix: Optional[str] = None) -> Path:
        """
        Create a backup of the current configuration
        
        Args:
            suffix: Optional suffix for backup filename
            
        Returns:
            Path to the backup file
        """
        if not self.config_path.exists():
            raise ConfigurationError("No configuration file to backup")
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if suffix:
            backup_name = f"config_{timestamp}_{suffix}.yaml"
        else:
            backup_name = f"config_{timestamp}.yaml"
        
        backup_path = self.backup_dir / backup_name
        shutil.copy2(self.config_path, backup_path)
        
        return backup_path
    
    def restore_backup(self, backup_path: Union[str, Path]) -> bool:
        """
        Restore configuration from backup
        
        Args:
            backup_path: Path to backup file
            
        Returns:
            True if restored successfully
        """
        backup_path = Path(backup_path)
        if not backup_path.exists():
            raise ConfigurationError(f"Backup file not found: {backup_path}")
        
        # Create current backup before restore
        self.create_backup("before_restore")
        
        try:
            shutil.copy2(backup_path, self.config_path)
            # Reload the restored configuration
            self.load_config(validate=True)
            return True
        except Exception as e:
            raise ConfigurationError(f"Failed to restore backup: {e}")
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """
        List all configuration backups
        
        Returns:
            List of backup information
        """
        backups = []
        for backup_file in sorted(self.backup_dir.glob("config_*.yaml")):
            stat = backup_file.stat()
            backups.append({
                'filename': backup_file.name,
                'path': str(backup_file),
                'created': datetime.fromtimestamp(stat.st_ctime),
                'size': stat.st_size
            })
        
        return backups
    
    def update_waf_rules(self, rules: List[Dict[str, Any]]) -> bool:
        """
        Update WAF custom rules
        
        Args:
            rules: List of WAF rule dictionaries
            
        Returns:
            True if updated successfully
        """
        if self._config is None:
            self.load_config()
        
        # Validate rules
        errors = self.validator.validate_waf_rules(rules)
        if errors:
            raise ConfigurationError(f"Invalid WAF rules:\n" + "\n".join(errors))
        
        # Update configuration
        if 'waf' not in self._config:
            self._config['waf'] = {}
        
        self._config['waf']['custom_rules'] = rules
        return self.save_config()
    
    def add_upstream(self, name: str, upstream_config: Dict[str, Any]) -> bool:
        """
        Add new upstream configuration
        
        Args:
            name: Upstream name
            upstream_config: Upstream configuration
            
        Returns:
            True if added successfully
        """
        if self._config is None:
            self.load_config()
        
        # Validate upstream
        errors = self.validator.validate_upstreams({name: upstream_config})
        if errors:
            raise ConfigurationError(f"Invalid upstream configuration:\n" + "\n".join(errors))
        
        # Update configuration
        if 'proxy' not in self._config:
            self._config['proxy'] = {}
        if 'upstreams' not in self._config['proxy']:
            self._config['proxy']['upstreams'] = {}
        
        self._config['proxy']['upstreams'][name] = upstream_config
        return self.save_config()
    
    def remove_upstream(self, name: str) -> bool:
        """
        Remove upstream configuration
        
        Args:
            name: Upstream name to remove
            
        Returns:
            True if removed successfully
        """
        if self._config is None:
            self.load_config()
        
        if ('proxy' in self._config and 
            'upstreams' in self._config['proxy'] and 
            name in self._config['proxy']['upstreams']):
            
            del self._config['proxy']['upstreams'][name]
            return self.save_config()
        
        return False
    
    def enable_ssl(self, domains: List[str], auto_provision: bool = True, 
                   email: str = "admin@example.com") -> bool:
        """
        Enable SSL with automatic certificate provisioning
        
        Args:
            domains: List of domains for SSL certificates
            auto_provision: Whether to use auto-provisioning
            email: Email for Let's Encrypt account
            
        Returns:
            True if enabled successfully
        """
        if self._config is None:
            self.load_config()
        
        if 'ssl' not in self._config:
            self._config['ssl'] = {}
        
        ssl_config = self._config['ssl']
        ssl_config.update({
            'enabled': True,
            'auto_provision': auto_provision,
            'domains': domains,
            'acme_email': email
        })
        
        return self.save_config()
    
    def get_current_config(self) -> Dict[str, Any]:
        """Get current loaded configuration"""
        if self._config is None:
            self.load_config()
        return self._config.copy()
    
    def to_structured_config(self) -> Dict[str, Any]:
        """
        Convert configuration to structured dataclass objects
        
        Returns:
            Configuration with structured objects
        """
        if self._config is None:
            self.load_config()
        
        config = self._config.copy()
        
        # Convert to structured objects
        if 'server' in config:
            config['server'] = ServerConfig(**config['server'])
        
        if 'ssl' in config:
            config['ssl'] = SslConfig(**config['ssl'])
        
        if 'waf' in config:
            config['waf'] = WafConfig(**config['waf'])
        
        if 'proxy' in config:
            config['proxy'] = ProxyConfig(**config['proxy'])
        
        return config
    
    def generate_sample_config(self) -> Dict[str, Any]:
        """
        Generate a sample configuration with sensible defaults
        
        Returns:
            Sample configuration dictionary
        """
        sample_config = {
            'server': asdict(ServerConfig()),
            'ssl': asdict(SslConfig()),
            'waf': {
                'enabled': True,
                'mode': 'block',
                'rate_limiting': {
                    'global': {'requests_per_second': 100, 'burst': 200},
                    'per_ip': {'requests_per_minute': 1000, 'burst': 500},
                    'per_endpoint': {'requests_per_second': 10, 'burst': 20}
                },
                'owasp_protection': {
                    'sql_injection': {'enabled': True, 'confidence_threshold': 0.8},
                    'xss_protection': {'enabled': True, 'confidence_threshold': 0.8},
                    'csrf_protection': {'enabled': True, 'confidence_threshold': 0.8},
                    'rce_protection': {'enabled': True, 'confidence_threshold': 0.9},
                    'path_traversal': {'enabled': True, 'confidence_threshold': 0.9}
                },
                'bot_protection': {
                    'enabled': True,
                    'challenge_suspicious': True,
                    'block_known_bots': True
                },
                'geo_blocking': {
                    'enabled': False,
                    'blocked_countries': ['KP', 'IR'],
                    'allowed_countries': ['US', 'CA']
                },
                'custom_rules': []
            },
            'proxy': asdict(ProxyConfig()),
            'logging': {
                'level': 'info',
                'format': 'json',
                'output': 'stdout'
            },
            'metrics': {
                'enabled': True,
                'port': 9090,
                'path': '/metrics'
            },
            'admin': {
                'enabled': True,
                'port': 8081,
                'auth': {
                    'enabled': True,
                    'username': 'admin'
                }
            }
        }
        
        return sample_config
