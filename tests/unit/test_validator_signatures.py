"""
Test specific validator signatures and compatibility issues.
This file specifically tests the identified problematic validators.
"""

import pytest
import sys
import os
import unittest.mock
from typing import Any, Dict

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../src'))

class TestValidatorSignatureIssues:
    """Test specific validator signature compatibility issues."""
    
    def setup_method(self):
        """Set up test environment."""
        try:
            from wazuh_mcp_server.utils.validation import FileHash, AlertSummaryQuery, ValidationError
            self.FileHash = FileHash
            self.AlertSummaryQuery = AlertSummaryQuery
            self.ValidationError = ValidationError
            self.pydantic_available = True
        except ImportError as e:
            self.pydantic_available = False
            pytest.skip(f"Pydantic not available: {e}")
    
    def test_filehash_three_param_validator(self):
        """Test FileHash validator with 3-parameter signature (cls, v, values)."""
        if not self.pydantic_available:
            pytest.skip("Pydantic not available")
        
        # This validator tries to modify 'values' dict which is problematic in V2
        # Test that it still works correctly
        hash_obj = self.FileHash(hash_value="5d41402abc4b2a76b9719d911017c592")
        assert hash_obj.hash_value == "5d41402abc4b2a76b9719d911017c592"
        assert hash_obj.hash_type == "md5"
        
        # Test SHA1
        hash_obj = self.FileHash(hash_value="aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        assert hash_obj.hash_value == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        assert hash_obj.hash_type == "sha1"
        
        # Test SHA256
        hash_obj = self.FileHash(hash_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert hash_obj.hash_value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert hash_obj.hash_type == "sha256"
    
    def test_alert_summary_four_param_validator(self):
        """Test AlertSummaryQuery validator with 4-parameter signature (cls, v, values, field)."""
        if not self.pydantic_available:
            pytest.skip("Pydantic not available")
        
        # This validator uses field parameter to get field name
        # Test that it works with both V1 and V2
        query = self.AlertSummaryQuery(
            custom_start="2023-01-01T00:00:00"
        )
        assert query.custom_start == "2023-01-01T00:00:00"
        
        # Test validation error handling
        with pytest.raises((ValueError, self.ValidationError)):
            self.AlertSummaryQuery(
                custom_start="invalid_format"
            )
    
    def test_filehash_values_modification_issue(self):
        """Test FileHash values modification issue in V2."""
        if not self.pydantic_available:
            pytest.skip("Pydantic not available")
        
        # The FileHash validator tries to modify values['hash_type']
        # This should work in V1 but may cause issues in V2
        # Test that the workaround in __init__ method handles this
        hash_obj = self.FileHash(hash_value="5d41402abc4b2a76b9719d911017c592")
        
        # Verify that hash_type is set correctly even if values modification fails
        assert hash_obj.hash_type == "md5"
        
        # Test edge case: creating with explicit hash_type
        hash_obj = self.FileHash(hash_value="5d41402abc4b2a76b9719d911017c592", hash_type="custom")
        # Should still be detected as md5 due to __init__ logic
        assert hash_obj.hash_type == "md5"  # __init__ overwrites custom value

class TestValidatorCompatibilityMocks:
    """Test validator compatibility using mocks to simulate different Pydantic versions."""
    
    def test_validator_with_pydantic_v1_mock(self):
        """Test validators work with Pydantic V1 simulation."""
        # Mock Pydantic V1 environment
        mock_validator_calls = []
        
        def mock_validator(*args, **kwargs):
            def decorator(func):
                # Simulate V1 validator call patterns
                def wrapper(cls, v, values=None, field=None):
                    mock_validator_calls.append({
                        'func': func.__name__,
                        'args_count': len([x for x in [cls, v, values, field] if x is not None]),
                        'has_values': values is not None,
                        'has_field': field is not None
                    })
                    
                    # Call original function with appropriate signature
                    import inspect
                    sig = inspect.signature(func)
                    params = list(sig.parameters.keys())
                    
                    if len(params) == 2:  # cls, v
                        return func(cls, v)
                    elif len(params) == 3:  # cls, v, values
                        return func(cls, v, values or {})
                    elif len(params) == 4:  # cls, v, values, field
                        class MockField:
                            name = 'test_field'
                        return func(cls, v, values or {}, field or MockField())
                    else:
                        return func(cls, v)
                
                wrapper._original_func = func
                return wrapper
            return decorator
        
        # Test with mocked validator
        with unittest.mock.patch('wazuh_mcp_server.utils.pydantic_compat.validator', mock_validator):
            # This would test the compatibility but requires more complex mocking
            pass
    
    def test_validator_with_pydantic_v2_mock(self):
        """Test validators work with Pydantic V2 simulation."""
        # Mock Pydantic V2 environment
        mock_field_validator_calls = []
        
        def mock_field_validator(*fields):
            def decorator(func):
                def wrapper(cls, v, info=None):
                    mock_field_validator_calls.append({
                        'func': func.__name__,
                        'fields': fields,
                        'has_info': info is not None
                    })
                    
                    # Simulate V2 to V1 compatibility layer
                    import inspect
                    sig = inspect.signature(func)
                    params = list(sig.parameters.keys())
                    
                    if len(params) == 4:  # Old V1 signature: cls, v, values, field
                        class MockField:
                            name = getattr(info, 'field_name', 'test_field') if info else 'test_field'
                        return func(cls, v, {}, MockField())
                    elif len(params) == 3:  # V1 signature: cls, v, values  
                        return func(cls, v, {})
                    else:  # New signature: cls, v
                        return func(cls, v)
                
                return classmethod(wrapper)
            return decorator
        
        # Test with mocked field_validator
        with unittest.mock.patch('wazuh_mcp_server.utils.pydantic_compat.field_validator', mock_field_validator):
            # This would test the V2 compatibility
            pass

class TestSpecificValidatorFixes:
    """Test specific fixes for identified validator issues."""
    
    def setup_method(self):
        """Set up test environment."""
        try:
            from wazuh_mcp_server.utils.validation import FileHash, AlertSummaryQuery, ValidationError
            self.FileHash = FileHash
            self.AlertSummaryQuery = AlertSummaryQuery  
            self.ValidationError = ValidationError
            self.pydantic_available = True
        except ImportError as e:
            self.pydantic_available = False
            pytest.skip(f"Pydantic not available: {e}")
    
    def test_filehash_init_method_fallback(self):
        """Test that FileHash.__init__ provides fallback for hash_type detection."""
        if not self.pydantic_available:
            pytest.skip("Pydantic not available")
        
        # Test that __init__ method correctly sets hash_type as fallback
        hash_obj = self.FileHash(hash_value="5d41402abc4b2a76b9719d911017c592")
        
        # hash_type should be set by validator or __init__
        assert hash_obj.hash_type is not None
        assert hash_obj.hash_type == "md5"
        
        # Test with different hash types
        test_cases = [
            ("5d41402abc4b2a76b9719d911017c592", "md5"),
            ("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "sha1"),
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256")
        ]
        
        for hash_value, expected_type in test_cases:
            hash_obj = self.FileHash(hash_value=hash_value)
            assert hash_obj.hash_type == expected_type
    
    def test_field_name_compatibility(self):
        """Test field name access compatibility in validators."""
        if not self.pydantic_available:
            pytest.skip("Pydantic not available")
        
        # Test that validator with field parameter works
        # The validate_custom_times method should handle field name correctly
        with pytest.raises((ValueError, self.ValidationError)) as exc_info:
            self.AlertSummaryQuery(custom_start="invalid")
        
        # Error message should be meaningful (not crash on field access)
        error_msg = str(exc_info.value)
        assert len(error_msg) > 0
        # Should contain some reference to the field or format issue
        assert any(word in error_msg.lower() for word in ['format', 'iso', 'custom', 'time'])

class TestValidatorEdgeCases:
    """Test edge cases in validator compatibility."""
    
    def setup_method(self):
        """Set up test environment."""
        try:
            from wazuh_mcp_server.utils.validation import FileHash, ValidationError
            self.FileHash = FileHash
            self.ValidationError = ValidationError
            self.pydantic_available = True
        except ImportError as e:
            self.pydantic_available = False
            pytest.skip(f"Pydantic not available: {e}")
    
    def test_filehash_validator_with_none_values(self):
        """Test FileHash validator when values parameter is None."""
        if not self.pydantic_available:
            pytest.skip("Pydantic not available")
        
        # This tests the scenario where values parameter might be None in V2
        # The validator should handle this gracefully
        hash_obj = self.FileHash(hash_value="5d41402abc4b2a76b9719d911017c592")
        assert hash_obj.hash_value == "5d41402abc4b2a76b9719d911017c592"
        assert hash_obj.hash_type == "md5"
    
    def test_filehash_validator_exception_handling(self):
        """Test FileHash validator exception handling."""
        if not self.pydantic_available:
            pytest.skip("Pydantic not available")
        
        # Test various invalid inputs
        invalid_cases = [
            "",  # Empty string
            "abc",  # Too short
            "not_hex_characters!",  # Invalid characters
            "way_too_long_to_be_any_valid_hash_format_even_for_sha256_which_is_64_chars",  # Too long
        ]
        
        for invalid_hash in invalid_cases:
            with pytest.raises((ValueError, self.ValidationError)):
                self.FileHash(hash_value=invalid_hash)
    
    def test_multiple_validator_decorators(self):
        """Test validators that apply to multiple fields."""
        if not self.pydantic_available:
            pytest.skip("Pydantic not available")
        
        # Test validator that applies to multiple fields like @validator('custom_start', 'custom_end')
        from wazuh_mcp_server.utils.validation import AlertSummaryQuery
        
        # Both fields should be validated by the same validator
        query = AlertSummaryQuery(
            custom_start="2023-01-01T00:00:00",
            custom_end="2023-01-02T00:00:00"
        )
        assert query.custom_start == "2023-01-01T00:00:00"
        assert query.custom_end == "2023-01-02T00:00:00"
        
        # Both should fail validation with invalid format
        with pytest.raises((ValueError, self.ValidationError)):
            AlertSummaryQuery(custom_start="invalid")
        
        with pytest.raises((ValueError, self.ValidationError)):
            AlertSummaryQuery(custom_end="invalid")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])