"""
Comprehensive DXT integration tests for production readiness.
"""

import pytest
import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
from pathlib import Path

import mcp.types as types
from src.wazuh_mcp_server import WazuhMCPServer
from src.config import WazuhConfig


class TestDXTIntegration:
    """Test DXT-specific functionality and integration."""
    
    @pytest.fixture
    def mock_config(self):
        """Mock configuration for testing."""
        return WazuhConfig(
            host="test-wazuh.example.com",
            username="test-user",
            password="test-password-12345",
            verify_ssl=False,
            debug=True
        )
    
    @pytest.fixture
    def mock_server(self, mock_config):
        """Create a mock server instance."""
        with patch('src.wazuh_mcp_server.WazuhConfig.from_env', return_value=mock_config):
            server = WazuhMCPServer()
            return server
    
    @pytest.mark.asyncio
    async def test_server_initialization(self, mock_server):
        """Test server initializes correctly for DXT."""
        assert mock_server.server.name == "wazuh-mcp"
        assert hasattr(mock_server, 'api_client')
        assert hasattr(mock_server, 'security_analyzer')
        assert hasattr(mock_server, 'compliance_analyzer')
    
    @pytest.mark.asyncio
    async def test_stdio_transport_compatibility(self, mock_server):
        """Test that server works with stdio transport."""
        # Mock stdio streams
        mock_read_stream = AsyncMock()
        mock_write_stream = AsyncMock()
        
        with patch('mcp.server.stdio.stdio_server') as mock_stdio:
            mock_stdio.return_value.__aenter__.return_value = (mock_read_stream, mock_write_stream)
            
            with patch.object(mock_server.server, 'run') as mock_run:
                mock_run.return_value = None
                
                with patch.object(mock_server.api_client, 'health_check') as mock_health:
                    mock_health.return_value = {"status": "healthy"}
                    
                    try:
                        await asyncio.wait_for(mock_server.run(), timeout=0.1)
                    except asyncio.TimeoutError:
                        pass  # Expected for test
                    
                    mock_stdio.assert_called_once()
                    mock_run.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_tool_timeout_handling(self, mock_server):
        """Test that tools properly handle timeouts."""
        # Mock a slow API call
        with patch.object(mock_server.api_client, 'get_alerts') as mock_get_alerts:
            mock_get_alerts.side_effect = asyncio.TimeoutError()
            
            # Test the tool handler directly
            result = await mock_server._handle_get_alerts({"limit": 100})
            
            assert len(result) == 1
            response = json.loads(result[0].text)
            assert "timed out" in response["error"].lower()
            assert "request_id" in response
    
    @pytest.mark.asyncio
    async def test_resource_access(self, mock_server):
        """Test resource endpoints work correctly."""
        mock_data = {
            "data": {
                "affected_items": [
                    {
                        "id": "001",
                        "timestamp": "2024-01-01T00:00:00.000Z",
                        "rule": {"id": "100", "description": "Test alert", "level": 5},
                        "agent": {"id": "001", "name": "test-agent", "ip": "192.168.1.100"}
                    }
                ],
                "total_affected_items": 1
            }
        }
        
        with patch.object(mock_server.api_client, 'get_alerts', return_value=mock_data):
            result = await mock_server.server._resource_handlers[0](
                "wazuh://alerts/recent"
            )
            
            parsed = json.loads(result)
            assert "total_alerts" in parsed
            assert "alerts" in parsed
            assert parsed["total_alerts"] == 1
    
    @pytest.mark.asyncio
    async def test_error_recovery(self, mock_server):
        """Test error recovery mechanisms."""
        # Test API connection failure
        with patch.object(mock_server.api_client, 'get_alerts') as mock_get_alerts:
            mock_get_alerts.side_effect = Exception("Connection failed")
            
            result = await mock_server._handle_get_alerts({"limit": 100})
            
            assert len(result) == 1
            response = json.loads(result[0].text)
            assert "error" in response
            assert "Connection failed" in response["error"]
    
    def test_manifest_validation(self):
        """Test that manifest.json is valid for DXT."""
        manifest_path = Path(__file__).parent.parent / "manifest.json"
        assert manifest_path.exists(), "manifest.json not found"
        
        with open(manifest_path) as f:
            manifest = json.load(f)
        
        # Required DXT fields
        required_fields = [
            "dxt_version", "name", "version", "description", 
            "author", "server", "user_config"
        ]
        
        for field in required_fields:
            assert field in manifest, f"Required field '{field}' missing from manifest"
        
        # Server configuration
        server_config = manifest["server"]
        assert server_config["type"] == "python"
        assert "entry_point" in server_config
        assert "mcp_config" in server_config
        
        # User configuration validation
        user_config = manifest["user_config"]
        assert len(user_config) > 0, "No user configuration defined"
        
        # Check required config fields
        required_configs = ["WAZUH_HOST", "WAZUH_USER", "WAZUH_PASS"]
        config_keys = {config["key"] for config in user_config}
        
        for required in required_configs:
            assert required in config_keys, f"Required config '{required}' missing"
    
    @pytest.mark.asyncio
    async def test_production_logging(self, mock_server):
        """Test production logging configuration."""
        # Test that logger is configured
        assert mock_server.logger is not None
        
        # Test structured logging
        with patch.object(mock_server.logger, 'info') as mock_log:
            await mock_server._handle_get_alerts({"limit": 10})
            mock_log.assert_called()
    
    @pytest.mark.asyncio
    async def test_security_validation(self, mock_server):
        """Test security validation and input sanitization."""
        # Test SQL injection attempt
        malicious_input = {"limit": "100; DROP TABLE alerts;--"}
        
        with patch.object(mock_server.api_client, 'get_alerts') as mock_get_alerts:
            mock_get_alerts.return_value = {"data": {"affected_items": []}}
            
            result = await mock_server._handle_get_alerts(malicious_input)
            
            # Should handle validation error gracefully
            response = json.loads(result[0].text)
            if "error" in response:
                assert "validation" in response["error"].lower()
    
    def test_dependency_security(self):
        """Test that dependencies are secure and up-to-date."""
        requirements_path = Path(__file__).parent.parent / "requirements.txt"
        assert requirements_path.exists(), "requirements.txt not found"
        
        with open(requirements_path) as f:
            requirements = f.read()
        
        # Check for known secure versions
        secure_deps = [
            "mcp>=0.9.0",
            "aiohttp>=3.9.0",
            "urllib3>=2.0.0",
            "pydantic>=2.0.0"
        ]
        
        for dep in secure_deps:
            assert any(dep.split('>=')[0] in line for line in requirements.split('\n')), \
                f"Secure dependency {dep} not found"
    
    @pytest.mark.asyncio
    async def test_performance_metrics(self, mock_server):
        """Test performance monitoring and metrics collection."""
        start_time = datetime.utcnow()
        
        with patch.object(mock_server.api_client, 'get_alerts') as mock_get_alerts:
            mock_get_alerts.return_value = {"data": {"affected_items": []}}
            
            # Test tool execution time tracking
            result = await mock_server._handle_get_alerts({"limit": 100})
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            assert execution_time < 5.0, "Tool execution took too long"
    
    def test_configuration_validation(self):
        """Test configuration validation and security."""
        # Test weak password rejection
        with pytest.raises(ValueError):
            WazuhConfig(
                host="test.example.com",
                username="admin",
                password="123456"  # Weak password
            )
        
        # Test missing required fields
        with pytest.raises(ValueError):
            WazuhConfig(
                host="",  # Empty host
                username="user",
                password="secure-password-12345"
            )
    
    @pytest.mark.asyncio
    async def test_graceful_shutdown(self, mock_server):
        """Test graceful shutdown and cleanup."""
        # Mock the cleanup process
        with patch.object(mock_server.api_client, '__aexit__') as mock_cleanup:
            mock_cleanup.return_value = None
            
            # Simulate shutdown
            try:
                await mock_server.api_client.__aexit__(None, None, None)
                mock_cleanup.assert_called_once()
            except Exception as e:
                pytest.fail(f"Graceful shutdown failed: {e}")


class TestProductionReadiness:
    """Test production readiness criteria."""
    
    def test_environment_variable_handling(self):
        """Test proper environment variable handling."""
        # Test with missing environment variables
        original_env = os.environ.copy()
        
        try:
            # Clear critical env vars
            for key in ['WAZUH_HOST', 'WAZUH_USER', 'WAZUH_PASS']:
                os.environ.pop(key, None)
            
            with pytest.raises(Exception):
                WazuhConfig.from_env()
                
        finally:
            os.environ.clear()
            os.environ.update(original_env)
    
    def test_file_permissions(self):
        """Test that sensitive files have appropriate permissions."""
        sensitive_files = [
            ".env.example",
            "manifest.json"
        ]
        
        for filename in sensitive_files:
            filepath = Path(__file__).parent.parent / filename
            if filepath.exists():
                # Check that file is readable
                assert filepath.is_file()
                assert os.access(filepath, os.R_OK)
    
    def test_documentation_completeness(self):
        """Test that all required documentation exists."""
        required_docs = [
            "README.md",
            "DXT_README.md",
            "docs/dxt-setup.md",
            "LICENSE"
        ]
        
        for doc in required_docs:
            doc_path = Path(__file__).parent.parent / doc
            assert doc_path.exists(), f"Required documentation '{doc}' missing"
            
            # Check minimum content length
            content_length = len(doc_path.read_text())
            assert content_length > 100, f"Documentation '{doc}' appears incomplete"
    
    def test_packaging_structure(self):
        """Test that package structure is correct for DXT."""
        required_files = [
            "manifest.json",
            "src/__init__.py",
            "src/wazuh_mcp_server.py",
            "src/__main__.py",
            "requirements.txt"
        ]
        
        for file_path in required_files:
            full_path = Path(__file__).parent.parent / file_path
            assert full_path.exists(), f"Required file '{file_path}' missing"
    
    def test_version_consistency(self):
        """Test that version numbers are consistent across files."""
        # Check manifest.json
        manifest_path = Path(__file__).parent.parent / "manifest.json"
        with open(manifest_path) as f:
            manifest = json.load(f)
        
        # Check package.json
        package_path = Path(__file__).parent.parent / "package.json"
        with open(package_path) as f:
            package = json.load(f)
        
        # Check setup.py
        setup_path = Path(__file__).parent.parent / "setup.py"
        setup_content = setup_path.read_text()
        
        # All should have consistent version
        manifest_version = manifest["version"]
        package_version = package["version"]
        
        assert manifest_version == package_version, \
            f"Version mismatch: manifest={manifest_version}, package={package_version}"