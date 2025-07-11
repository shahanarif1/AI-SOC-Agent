"""Tests for standardized error handling."""

import pytest
import asyncio
import os
import sys
from unittest.mock import patch, MagicMock

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from wazuh_mcp_server.utils.error_standardization import (
        standardized_error_handler, safe_execute, safe_execute_async,
        StandardErrorResponse, ErrorAggregator, ErrorHandlingStrategy,
        validate_and_handle_error
    )
    ERROR_STANDARDIZATION_AVAILABLE = True
except ImportError:
    ERROR_STANDARDIZATION_AVAILABLE = False


@pytest.mark.skipif(not ERROR_STANDARDIZATION_AVAILABLE, reason="Error standardization module not available")
class TestErrorStandardization:
    """Test standardized error handling functionality."""
    
    def test_standard_error_response_creation(self):
        """Test StandardErrorResponse creation and formatting."""
        error = ValueError("Test error message")
        context = {"operation": "test_operation", "data": "test_data"}
        
        response = StandardErrorResponse(error, context)
        
        # Test dictionary format
        error_dict = response.to_dict()
        assert error_dict["success"] is False
        assert error_dict["error"]["type"] == "ValueError"
        assert error_dict["error"]["message"] == "Test error message"
        assert error_dict["error"]["context"] == context
        assert "timestamp" in error_dict["error"]
        
        # Test string format
        error_str = response.to_string()
        assert "Error: Test error message" in error_str
        assert "Context:" in error_str
    
    def test_safe_execute_success(self):
        """Test safe_execute with successful operation."""
        def successful_operation():
            return "success result"
        
        result = safe_execute(successful_operation, default_value="default")
        assert result == "success result"
    
    def test_safe_execute_failure(self):
        """Test safe_execute with failing operation."""
        def failing_operation():
            raise ValueError("Operation failed")
        
        result = safe_execute(
            failing_operation, 
            default_value="default_value",
            log_errors=False  # Disable logging for test
        )
        assert result == "default_value"
    
    @pytest.mark.asyncio
    async def test_safe_execute_async_success(self):
        """Test safe_execute_async with successful operation."""
        async def successful_async_operation():
            return "async success result"
        
        result = await safe_execute_async(successful_async_operation, default_value="default")
        assert result == "async success result"
    
    @pytest.mark.asyncio
    async def test_safe_execute_async_failure(self):
        """Test safe_execute_async with failing operation."""
        async def failing_async_operation():
            raise ValueError("Async operation failed")
        
        result = await safe_execute_async(
            failing_async_operation,
            default_value="async_default_value",
            log_errors=False  # Disable logging for test
        )
        assert result == "async_default_value"
    
    def test_validate_and_handle_error_success(self):
        """Test validate_and_handle_error with valid condition."""
        # Should not raise any exception
        validate_and_handle_error(True, ValueError, "Should not fail")
    
    def test_validate_and_handle_error_failure(self):
        """Test validate_and_handle_error with invalid condition."""
        with pytest.raises(ValueError, match="Validation failed"):
            validate_and_handle_error(False, ValueError, "Validation failed")
    
    def test_error_aggregator_basic_functionality(self):
        """Test ErrorAggregator basic functionality."""
        aggregator = ErrorAggregator()
        
        # Initially no errors
        assert not aggregator.has_errors()
        assert aggregator.get_summary()["error_count"] == 0
        
        # Add some errors
        error1 = ValueError("First error")
        error2 = TypeError("Second error")
        error3 = ValueError("Third error")
        
        aggregator.add_error(error1, {"context": "first"})
        aggregator.add_error(error2, {"context": "second"})
        aggregator.add_error(error3, {"context": "third"})
        
        # Check aggregator state
        assert aggregator.has_errors()
        summary = aggregator.get_summary()
        assert summary["error_count"] == 3
        assert summary["error_types"]["ValueError"] == 2
        assert summary["error_types"]["TypeError"] == 1
        assert len(summary["errors"]) == 3
    
    def test_error_aggregator_raise_if_errors(self):
        """Test ErrorAggregator raise_if_errors functionality."""
        aggregator = ErrorAggregator()
        
        # Should not raise when no errors
        aggregator.raise_if_errors()  # Should pass
        
        # Add an error
        aggregator.add_error(ValueError("Test error"))
        
        # Should raise when errors exist
        with pytest.raises(Exception, match="Multiple errors occurred"):
            aggregator.raise_if_errors()
    
    def test_standardized_error_handler_decorator_sync(self):
        """Test standardized_error_handler decorator with sync function."""
        
        @standardized_error_handler(
            strategy=ErrorHandlingStrategy.UTILITY_OPERATION,
            context={"test": "sync_function"}
        )
        def test_function(should_fail=False):
            if should_fail:
                raise ValueError("Test error")
            return "success"
        
        # Test successful execution
        result = test_function(should_fail=False)
        assert result == "success"
        
        # Test error handling (should return None due to UTILITY_OPERATION strategy)
        result = test_function(should_fail=True)
        assert result is None
    
    def test_standardized_error_handler_decorator_with_reraise(self):
        """Test standardized_error_handler decorator with reraise strategy."""
        
        @standardized_error_handler(
            strategy=ErrorHandlingStrategy.VALIDATION_OPERATION,
            context={"test": "validation_function"}
        )
        def validation_function():
            raise ValueError("Validation error")
        
        # Should reraise the exception
        with pytest.raises(ValueError, match="Validation error"):
            validation_function()
    
    @pytest.mark.asyncio
    async def test_standardized_error_handler_decorator_async(self):
        """Test standardized_error_handler decorator with async function."""
        
        @standardized_error_handler(
            strategy=ErrorHandlingStrategy.OPTIONAL_FEATURE,
            context={"test": "async_function"}
        )
        async def async_test_function(should_fail=False):
            if should_fail:
                raise ValueError("Async test error")
            return "async success"
        
        # Test successful execution
        result = await async_test_function(should_fail=False)
        assert result == "async success"
        
        # Test error handling (should return None due to OPTIONAL_FEATURE strategy)
        result = await async_test_function(should_fail=True)
        assert result is None
    
    def test_error_handling_strategies(self):
        """Test different error handling strategies have correct configurations."""
        
        # API operation strategy should reraise and use production handler
        api_strategy = ErrorHandlingStrategy.API_OPERATION
        assert api_strategy["reraise"] is True
        assert api_strategy["use_production_handler"] is True
        
        # Optional feature strategy should not reraise and return None
        optional_strategy = ErrorHandlingStrategy.OPTIONAL_FEATURE
        assert optional_strategy["reraise"] is False
        assert optional_strategy["return_none_on_error"] is True
        
        # Config operation strategy should include traceback
        config_strategy = ErrorHandlingStrategy.CONFIG_OPERATION
        assert config_strategy["include_traceback"] is True
        assert config_strategy["reraise"] is True


if __name__ == "__main__":
    if ERROR_STANDARDIZATION_AVAILABLE:
        print("Running error standardization tests...")
        pytest.main([__file__, "-v"])
    else:
        print("Error standardization module not available for testing")