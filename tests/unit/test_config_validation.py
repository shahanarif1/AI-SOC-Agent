"""Tests for configuration validation improvements."""

import pytest
import os
from unittest.mock import patch, MagicMock

# Add src to path for testing
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from wazuh_mcp_server.config import WazuhConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False


@pytest.mark.skipif(not CONFIG_AVAILABLE, reason="Config module not available")
class TestConfigValidation:
    """Test configuration validation for feature flags and memory management."""
    
    def test_feature_flag_validation_boolean_true(self):
        """Test feature flag validation with boolean True."""
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'ENABLE_PROMPT_ENHANCEMENT': 'true'
        }):
            config = WazuhConfig.from_env()
            assert config.enable_prompt_enhancement is True
    
    def test_feature_flag_validation_boolean_false(self):
        """Test feature flag validation with boolean False."""
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'ENABLE_PROMPT_ENHANCEMENT': 'false'
        }):
            config = WazuhConfig.from_env()
            assert config.enable_prompt_enhancement is False
    
    def test_feature_flag_validation_yes_no(self):
        """Test feature flag validation with yes/no values."""
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'ENABLE_CONTEXT_AGGREGATION': 'yes',
            'ENABLE_ADAPTIVE_RESPONSES': 'no'
        }):
            config = WazuhConfig.from_env()
            assert config.enable_context_aggregation is True
            assert config.enable_adaptive_responses is False
    
    def test_feature_flag_validation_numeric(self):
        """Test feature flag validation with numeric values."""
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'ENABLE_REALTIME_UPDATES': '1',
            'ENABLE_EXTERNAL_INTEL': '0'
        }):
            config = WazuhConfig.from_env()
            assert config.enable_realtime_updates is True
            assert config.enable_external_intel is False
    
    def test_feature_flag_validation_on_off(self):
        """Test feature flag validation with on/off values."""
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'ENABLE_ML_ANALYSIS': 'on',
            'ENABLE_COMPLIANCE_CHECKING': 'off'
        }):
            config = WazuhConfig.from_env()
            assert config.enable_ml_analysis is True
            assert config.enable_compliance_checking is False
    
    def test_feature_flag_validation_enabled_disabled(self):
        """Test feature flag validation with enabled/disabled values."""
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'ENABLE_EXPERIMENTAL': 'enabled'
        }):
            config = WazuhConfig.from_env()
            assert config.enable_experimental is True
        
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'ENABLE_EXPERIMENTAL': 'disabled'
        }):
            config = WazuhConfig.from_env()
            assert config.enable_experimental is False
    
    def test_feature_flag_validation_invalid_value_defaults_false(self):
        """Test that invalid feature flag values default to False with warning."""
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'ENABLE_PROMPT_ENHANCEMENT': 'invalid-value'
        }):
            with patch('wazuh_mcp_server.config.logging.warning') as mock_warning:
                config = WazuhConfig.from_env()
                assert config.enable_prompt_enhancement is False
                mock_warning.assert_called()
    
    def test_memory_management_defaults(self):
        """Test memory management configuration defaults."""
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123'
        }):
            config = WazuhConfig.from_env()
            assert config.max_cache_memory_mb == 500
            assert config.max_context_count == 100
            assert config.cache_cleanup_aggressive is False
            assert config.memory_check_interval == 300
    
    def test_memory_management_custom_values(self):
        """Test memory management configuration with custom values."""
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'MAX_CACHE_MEMORY_MB': '1000',
            'MAX_CONTEXT_COUNT': '200',
            'CACHE_CLEANUP_AGGRESSIVE': 'true',
            'MEMORY_CHECK_INTERVAL': '600'
        }):
            config = WazuhConfig.from_env()
            assert config.max_cache_memory_mb == 1000
            assert config.max_context_count == 200
            assert config.cache_cleanup_aggressive is True
            assert config.memory_check_interval == 600
    
    def test_memory_management_bounds(self):
        """Test memory management configuration bounds validation."""
        # Test lower bounds
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'MAX_CACHE_MEMORY_MB': '25',  # Below minimum
            'MAX_CONTEXT_COUNT': '5'      # Below minimum
        }):
            with pytest.raises(ValueError):
                WazuhConfig.from_env()
        
        # Test upper bounds
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'MAX_CACHE_MEMORY_MB': '5000',  # Above maximum
            'MAX_CONTEXT_COUNT': '2000'     # Above maximum
        }):
            with pytest.raises(ValueError):
                WazuhConfig.from_env()
    
    def test_case_insensitive_feature_flags(self):
        """Test that feature flags are case insensitive."""
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'ENABLE_PROMPT_ENHANCEMENT': 'TRUE',
            'ENABLE_CONTEXT_AGGREGATION': 'Yes',
            'ENABLE_ADAPTIVE_RESPONSES': 'ON',
            'ENABLE_REALTIME_UPDATES': 'Enabled'
        }):
            config = WazuhConfig.from_env()
            assert config.enable_prompt_enhancement is True
            assert config.enable_context_aggregation is True
            assert config.enable_adaptive_responses is True
            assert config.enable_realtime_updates is True
    
    def test_whitespace_handling(self):
        """Test that feature flags handle whitespace correctly."""
        with patch.dict(os.environ, {
            'WAZUH_HOST': 'test-server.com',
            'WAZUH_USER': 'test-user',
            'WAZUH_PASS': 'test-password-123',
            'ENABLE_PROMPT_ENHANCEMENT': '  true  ',
            'ENABLE_CONTEXT_AGGREGATION': '\tyes\t',
            'ENABLE_ADAPTIVE_RESPONSES': ' 1 '
        }):
            config = WazuhConfig.from_env()
            assert config.enable_prompt_enhancement is True
            assert config.enable_context_aggregation is True
            assert config.enable_adaptive_responses is True


if __name__ == "__main__":
    if CONFIG_AVAILABLE:
        print("Running configuration validation tests...")
        pytest.main([__file__, "-v"])
    else:
        print("Configuration module not available for testing")