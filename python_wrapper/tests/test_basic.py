"""
Basic tests for WAF + Reverse Proxy Python Wrapper
"""

import pytest
import json
from unittest.mock import Mock, patch
from datetime import datetime

from waf_proxy import (
    WafProxyClient, ConfigManager, ProcessManager, HealthMonitor,
    WafProxyError, ConfigurationError, ProcessError
)
from waf_proxy.health import HealthStatus, HealthCheckResult


class TestWafProxyClient:
    """Test WAF Proxy client functionality"""
    
    def setup_method(self):
        """Setup test client"""
        self.client = WafProxyClient(base_url="http://localhost:8081")
    
    def test_client_initialization(self):
        """Test client initialization"""
        assert self.client.base_url == "http://localhost:8081"
        assert self.client.timeout == 30
        
    def test_client_with_auth(self):
        """Test client with authentication"""
        client = WafProxyClient(
            base_url="http://localhost:8081",
            username="admin",
            password="password"
        )
        assert client.username == "admin"
        assert client.password == "password"
        
    def test_client_with_token(self):
        """Test client with JWT token"""
        client = WafProxyClient(
            base_url="http://localhost:8081",
            api_token="jwt-token-123"
        )
        assert client.api_token == "jwt-token-123"
        assert 'Authorization' in client.session.headers
        assert client.session.headers['Authorization'] == 'Bearer jwt-token-123'
    
    @patch('requests.Session.request')
    def test_get_health_success(self, mock_request):
        """Test successful health check"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'status': 'healthy',
            'uptime': 3600,
            'version': '1.0.0',
            'components': {}
        }
        mock_request.return_value = mock_response
        
        health = self.client.get_health()
        
        assert health.status == 'healthy'
        assert health.uptime == 3600
        assert health.version == '1.0.0'
    
    @patch('requests.Session.request')
    def test_get_health_error(self, mock_request):
        """Test health check error"""
        mock_request.side_effect = Exception("Connection failed")
        
        with pytest.raises(WafProxyError):
            self.client.get_health()
    
    @patch('requests.Session.request')
    def test_get_waf_stats(self, mock_request):
        """Test getting WAF statistics"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'total_requests': 1000,
            'blocked_requests': 50,
            'allowed_requests': 950,
            'rate_limited': 10,
            'geo_blocked': 15,
            'bot_blocked': 20,
            'owasp_blocked': 5,
            'custom_rule_blocked': 0
        }
        mock_request.return_value = mock_response
        
        stats = self.client.get_waf_stats()
        
        assert stats.total_requests == 1000
        assert stats.blocked_requests == 50
        assert stats.allowed_requests == 950
        assert stats.rate_limited == 10
    
    @patch('requests.Session.request')
    def test_block_ip(self, mock_request):
        """Test blocking IP address"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True}
        mock_request.return_value = mock_response
        
        result = self.client.block_ip("192.168.1.100", "Test block")
        
        assert result['success'] is True
        mock_request.assert_called_once()


class TestConfigManager:
    """Test configuration management"""
    
    def setup_method(self):
        """Setup test config manager"""
        self.config_manager = ConfigManager("test_config.yaml")
    
    def test_config_manager_initialization(self):
        """Test config manager initialization"""
        assert self.config_manager.config_path.name == "test_config.yaml"
        assert self.config_manager.config_dir == self.config_manager.config_path.parent
    
    def test_generate_sample_config(self):
        """Test sample configuration generation"""
        sample_config = self.config_manager.generate_sample_config()
        
        assert 'server' in sample_config
        assert 'ssl' in sample_config
        assert 'waf' in sample_config
        assert 'proxy' in sample_config
        assert 'logging' in sample_config
        assert 'metrics' in sample_config
        assert 'admin' in sample_config
        
        # Check server config structure
        server_config = sample_config['server']
        assert 'host' in server_config
        assert 'port' in server_config
        assert 'workers' in server_config
        assert 'max_connections' in server_config
    
    def test_validate_server_config(self):
        """Test server configuration validation"""
        # Valid config
        valid_config = {'port': 8080, 'workers': 4, 'max_connections': 1000}
        errors = self.config_manager.validator.validate_server_config(valid_config)
        assert len(errors) == 0
        
        # Invalid port
        invalid_config = {'port': 99999, 'workers': 4}
        errors = self.config_manager.validator.validate_server_config(invalid_config)
        assert len(errors) > 0
        assert any('port' in error.lower() for error in errors)
        
        # Invalid workers
        invalid_config = {'port': 8080, 'workers': 0}
        errors = self.config_manager.validator.validate_server_config(invalid_config)
        assert len(errors) > 0
        assert any('worker' in error.lower() for error in errors)
    
    def test_validate_ssl_config(self):
        """Test SSL configuration validation"""
        # SSL disabled - should pass
        disabled_ssl = {'enabled': False}
        errors = self.config_manager.validator.validate_ssl_config(disabled_ssl)
        assert len(errors) == 0
        
        # SSL enabled without auto-provision - should require cert paths
        manual_ssl = {'enabled': True, 'auto_provision': False}
        errors = self.config_manager.validator.validate_ssl_config(manual_ssl)
        assert len(errors) > 0
        assert any('cert_path' in error for error in errors)
        
        # SSL enabled with auto-provision - should require email and domains
        auto_ssl = {'enabled': True, 'auto_provision': True}
        errors = self.config_manager.validator.validate_ssl_config(auto_ssl)
        assert len(errors) > 0
        assert any('email' in error for error in errors)
    
    def test_validate_waf_rules(self):
        """Test WAF rules validation"""
        # Valid rule
        valid_rules = [
            {
                'name': 'test_rule',
                'action': 'block',
                'conditions': [
                    {'type': 'ip_in_blacklist', 'value': ['192.168.1.1']}
                ]
            }
        ]
        errors = self.config_manager.validator.validate_waf_rules(valid_rules)
        assert len(errors) == 0
        
        # Invalid rule - missing name
        invalid_rules = [
            {
                'action': 'block',
                'conditions': []
            }
        ]
        errors = self.config_manager.validator.validate_waf_rules(invalid_rules)
        assert len(errors) > 0
        assert any('name' in error for error in errors)


class TestProcessManager:
    """Test process management"""
    
    def setup_method(self):
        """Setup test process manager"""
        self.process_manager = ProcessManager(
            binary_path="/bin/sleep",  # Use sleep as mock binary
            config_path="test_config.yaml"
        )
    
    def test_process_manager_initialization(self):
        """Test process manager initialization"""
        assert str(self.process_manager.binary_path) == "/bin/sleep"
        assert str(self.process_manager.config_path) == "test_config.yaml"
        assert self.process_manager.process is None
        assert not self.process_manager.is_running()
    
    def test_get_status_not_running(self):
        """Test status when not running"""
        status = self.process_manager.get_status()
        
        assert status['running'] is False
        assert status['pid'] is None
        assert status['uptime'] is None
        assert status['restart_count'] == 0
    
    @patch('subprocess.Popen')
    def test_start_process_mock(self, mock_popen):
        """Test starting process (mocked)"""
        mock_process = Mock()
        mock_process.pid = 12345
        mock_process.poll.return_value = None  # Process is running
        mock_popen.return_value = mock_process
        
        # Mock psutil.Process
        with patch('psutil.Process') as mock_psutil:
            mock_psutil_instance = Mock()
            mock_psutil.return_value = mock_psutil_instance
            
            success = self.process_manager.start(validate_config=False)
            
            assert success is True
            assert self.process_manager.process == mock_process
            assert self.process_manager.is_running() is True


class TestHealthMonitor:
    """Test health monitoring"""
    
    def setup_method(self):
        """Setup test health monitor"""
        self.health_monitor = HealthMonitor(
            service_url="http://localhost:8080",
            admin_url="http://localhost:8081"
        )
    
    def test_health_monitor_initialization(self):
        """Test health monitor initialization"""
        assert self.health_monitor.service_url == "http://localhost:8080"
        assert self.health_monitor.admin_url == "http://localhost:8081"
        assert self.health_monitor.timeout == 30
        assert self.health_monitor.ssl_verify is True
    
    def test_calculate_overall_status(self):
        """Test overall status calculation"""
        # All healthy
        healthy_checks = [
            HealthCheckResult(
                name="test1", status=HealthStatus.HEALTHY, response_time=0.1,
                message="OK", timestamp=datetime.now(), details={}
            ),
            HealthCheckResult(
                name="test2", status=HealthStatus.HEALTHY, response_time=0.1,
                message="OK", timestamp=datetime.now(), details={}
            )
        ]
        status = self.health_monitor._calculate_overall_status(healthy_checks)
        assert status == HealthStatus.HEALTHY
        
        # One degraded
        mixed_checks = [
            HealthCheckResult(
                name="test1", status=HealthStatus.HEALTHY, response_time=0.1,
                message="OK", timestamp=datetime.now(), details={}
            ),
            HealthCheckResult(
                name="test2", status=HealthStatus.DEGRADED, response_time=0.5,
                message="Slow", timestamp=datetime.now(), details={}
            )
        ]
        status = self.health_monitor._calculate_overall_status(mixed_checks)
        assert status == HealthStatus.DEGRADED
        
        # One unhealthy
        unhealthy_checks = [
            HealthCheckResult(
                name="test1", status=HealthStatus.HEALTHY, response_time=0.1,
                message="OK", timestamp=datetime.now(), details={}
            ),
            HealthCheckResult(
                name="test2", status=HealthStatus.UNHEALTHY, response_time=10.0,
                message="Failed", timestamp=datetime.now(), details={}
            )
        ]
        status = self.health_monitor._calculate_overall_status(unhealthy_checks)
        assert status == HealthStatus.UNHEALTHY
    
    def test_check_service_port_failure(self):
        """Test service port check failure"""
        # This will fail since nothing is running on port 8080
        result = self.health_monitor.check_service_port()
        
        assert result.name == "service_port"
        assert result.status == HealthStatus.UNHEALTHY
        assert "cannot connect" in result.message.lower() or "connection refused" in result.message.lower()
    
    def test_uptime_percentage_no_data(self):
        """Test uptime percentage with no data"""
        percentage = self.health_monitor.get_uptime_percentage(24)
        assert percentage == 100.0  # Should assume healthy if no data


class TestErrorHandling:
    """Test error handling"""
    
    def test_waf_proxy_error(self):
        """Test WafProxyError"""
        error = WafProxyError("Test error", status_code=500, details={"key": "value"})
        
        assert str(error) == "Test error"
        assert error.status_code == 500
        assert error.details == {"key": "value"}
    
    def test_configuration_error(self):
        """Test ConfigurationError"""
        error = ConfigurationError("Config invalid")
        
        assert str(error) == "Config invalid"
        assert isinstance(error, Exception)
    
    def test_process_error(self):
        """Test ProcessError"""
        error = ProcessError("Process failed")
        
        assert str(error) == "Process failed"
        assert isinstance(error, Exception)


class TestDataStructures:
    """Test data structures and models"""
    
    def test_health_check_result_to_dict(self):
        """Test HealthCheckResult to_dict method"""
        result = HealthCheckResult(
            name="test_check",
            status=HealthStatus.HEALTHY,
            response_time=0.123,
            message="All good",
            timestamp=datetime(2024, 1, 15, 10, 30, 0),
            details={"key": "value"}
        )
        
        result_dict = result.to_dict()
        
        assert result_dict['name'] == "test_check"
        assert result_dict['status'] == "healthy"
        assert result_dict['response_time'] == 0.123
        assert result_dict['message'] == "All good"
        assert result_dict['timestamp'] == "2024-01-15T10:30:00"
        assert result_dict['details'] == {"key": "value"}


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])
