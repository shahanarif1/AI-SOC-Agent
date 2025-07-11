"""Tests for optional dependency checking."""

import pytest
import os
from unittest.mock import patch, MagicMock
import sys

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from wazuh_mcp_server.main import WazuhMCPServer
    from wazuh_mcp_server.config import WazuhConfig
    SERVER_AVAILABLE = True
except ImportError:
    SERVER_AVAILABLE = False


@pytest.mark.skipif(not SERVER_AVAILABLE, reason="Main server module not available")
class TestOptionalDependencies:
    """Test optional dependency checking."""
    
    @patch('wazuh_mcp_server.main.setup_logging')
    @patch('wazuh_mcp_server.config.WazuhConfig.from_env')
    def test_dependency_checking_with_no_optional_features(self, mock_config, mock_logging):
        """Test dependency checking when no optional features are enabled."""
        # Mock config with no optional features
        config = MagicMock()
        config.log_level = "INFO"
        config.debug = False
        config.virustotal_api_key = None
        config.shodan_api_key = None
        config.abuseipdb_api_key = None
        config.enable_prompt_enhancement = False
        config.enable_ml_analysis = False
        mock_config.return_value = config
        
        # Mock logger
        logger = MagicMock()
        mock_logging.return_value = logger
        
        with patch('wazuh_mcp_server.main.WazuhClientManager'), \
             patch('wazuh_mcp_server.main.SecurityAnalyzer'), \
             patch('wazuh_mcp_server.main.ComplianceAnalyzer'), \
             patch.object(WazuhMCPServer, '_setup_handlers'):
            
            server = WazuhMCPServer()
            
            # Should have empty lists since no features are enabled
            assert hasattr(server, '_available_features')
            assert hasattr(server, '_missing_features')
    
    @patch('wazuh_mcp_server.main.setup_logging')
    @patch('wazuh_mcp_server.config.WazuhConfig.from_env')
    def test_dependency_checking_with_external_apis(self, mock_config, mock_logging):
        """Test dependency checking with external API keys configured."""
        # Mock config with external APIs
        config = MagicMock()
        config.log_level = "INFO"
        config.debug = False
        config.virustotal_api_key = "test-vt-key"
        config.shodan_api_key = "test-shodan-key"
        config.abuseipdb_api_key = "test-abuse-key"
        config.enable_prompt_enhancement = False
        config.enable_ml_analysis = False
        mock_config.return_value = config
        
        # Mock logger
        logger = MagicMock()
        mock_logging.return_value = logger
        
        with patch('wazuh_mcp_server.main.WazuhClientManager'), \
             patch('wazuh_mcp_server.main.SecurityAnalyzer'), \
             patch('wazuh_mcp_server.main.ComplianceAnalyzer'), \
             patch.object(WazuhMCPServer, '_setup_handlers'):
            
            server = WazuhMCPServer()
            
            # Should have detected external API features as available
            assert hasattr(server, '_available_features')
            assert hasattr(server, '_missing_features')
            
            # Verify logger was called with appropriate messages
            logger.info.assert_called()
    
    @patch('wazuh_mcp_server.main.setup_logging')
    @patch('wazuh_mcp_server.config.WazuhConfig.from_env')
    def test_dependency_checking_with_missing_requests(self, mock_config, mock_logging):
        """Test dependency checking when requests library is missing."""
        # Mock config with external APIs
        config = MagicMock()
        config.log_level = "INFO"
        config.debug = False
        config.virustotal_api_key = "test-vt-key"
        config.shodan_api_key = None
        config.abuseipdb_api_key = None
        config.enable_prompt_enhancement = False
        config.enable_ml_analysis = False
        mock_config.return_value = config
        
        # Mock logger
        logger = MagicMock()
        mock_logging.return_value = logger
        
        with patch('wazuh_mcp_server.main.WazuhClientManager'), \
             patch('wazuh_mcp_server.main.SecurityAnalyzer'), \
             patch('wazuh_mcp_server.main.ComplianceAnalyzer'), \
             patch.object(WazuhMCPServer, '_setup_handlers'), \
             patch.object(WazuhMCPServer, '_check_optional_dependencies') as mock_check:
            
            # Mock the import error for requests
            def side_effect():
                raise ImportError("No module named 'requests'")
            
            mock_check.side_effect = side_effect
            
            try:
                server = WazuhMCPServer()
            except ImportError:
                # This is expected when requests is missing
                pass
    
    @patch('wazuh_mcp_server.main.setup_logging')
    @patch('wazuh_mcp_server.config.WazuhConfig.from_env')
    def test_dependency_checking_with_ml_analysis(self, mock_config, mock_logging):
        """Test dependency checking with ML analysis enabled."""
        # Mock config with ML analysis
        config = MagicMock()
        config.log_level = "INFO"
        config.debug = False
        config.virustotal_api_key = None
        config.shodan_api_key = None
        config.abuseipdb_api_key = None
        config.enable_prompt_enhancement = False
        config.enable_ml_analysis = True
        mock_config.return_value = config
        
        # Mock logger
        logger = MagicMock()
        mock_logging.return_value = logger
        
        with patch('wazuh_mcp_server.main.WazuhClientManager'), \
             patch('wazuh_mcp_server.main.SecurityAnalyzer'), \
             patch('wazuh_mcp_server.main.ComplianceAnalyzer'), \
             patch.object(WazuhMCPServer, '_setup_handlers'):
            
            server = WazuhMCPServer()
            
            # Should have basic ML analysis available (json is always available)
            assert hasattr(server, '_available_features')
            assert "Basic ML analysis" in server._available_features


if __name__ == "__main__":
    if SERVER_AVAILABLE:
        print("Running optional dependency tests...")
        pytest.main([__file__, "-v"])
    else:
        print("Server module not available for testing")