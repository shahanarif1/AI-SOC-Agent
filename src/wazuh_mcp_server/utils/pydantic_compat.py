"""
Comprehensive Pydantic V1/V2 compatibility layer.
Specifically designed for cross-platform compatibility while maintaining functionality.
"""

import sys
import warnings
import logging
from typing import Any, Callable, Dict, Optional, Type, Union

# Platform detection for compatibility
def detect_platform() -> dict:
    """Detect current platform and Pydantic version."""
    import platform
    import os
    
    system = platform.system().lower()
    
    # Detect if we're on Fedora
    is_fedora = False
    if system == 'linux':
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                is_fedora = 'fedora' in content or 'red hat' in content
        except (FileNotFoundError, PermissionError):
            # Fallback check for Fedora-specific paths
            is_fedora = any([
                os.path.exists('/etc/fedora-release'),
                os.path.exists('/etc/redhat-release'),
                'fedora' in platform.platform().lower()
            ])
    
    # Check Pydantic version
    pydantic_version = None
    pydantic_v2 = False
    try:
        import pydantic
        pydantic_version = getattr(pydantic, '__version__', getattr(pydantic, 'VERSION', 'unknown'))
        pydantic_v2 = pydantic_version.startswith('2')
    except ImportError:
        pass
    
    return {
        'system': system,
        'is_fedora': is_fedora,
        'is_macos': system == 'darwin',
        'is_ubuntu': 'ubuntu' in platform.platform().lower(),
        'pydantic_version': pydantic_version,
        'pydantic_v2': pydantic_v2,
        'platform_string': platform.platform()
    }

# Global platform info
PLATFORM_INFO = detect_platform()

def log_platform_info():
    """Log platform detection results for debugging."""
    logging.info(f"Platform detected: {PLATFORM_INFO}")
    if PLATFORM_INFO['is_fedora'] and PLATFORM_INFO['pydantic_v2']:
        logging.warning("Fedora with Pydantic V2 detected - using compatibility mode")

# Log platform info for debugging
log_platform_info()

try:
    import pydantic
    pydantic_available = True
    
    # Check version and create compatibility layer
    if hasattr(pydantic, '__version__'):
        version = pydantic.__version__
    elif hasattr(pydantic, 'VERSION'):
        version = pydantic.VERSION
    else:
        version = "unknown"
    
    PYDANTIC_V2 = version.startswith('2')
    
    if PYDANTIC_V2:
        # Pydantic V2 - Create V1 compatibility
        from pydantic import BaseModel as V2BaseModel, Field
        try:
            from pydantic import field_validator, ValidationInfo
        except ImportError:
            # Fallback for older V2 versions
            from pydantic import validator as field_validator
            ValidationInfo = None
        
        # V1-compatible validator decorator for V2
        def validator(
            field_name: str,
            *fields: str,
            pre: bool = False,
            each_item: bool = False,
            always: bool = False,
            check_fields: bool = True
        ):
            """V1-compatible validator decorator that works with V2."""
            def decorator(func: Callable) -> Callable:
                if ValidationInfo is not None:
                    # Full V2 with ValidationInfo
                    @field_validator(field_name, *fields)
                    @classmethod
                    def wrapper(cls, v: Any, info: ValidationInfo) -> Any:
                        # For V1 compatibility, we need to handle the old signature
                        # that expected (cls, v, values, field)
                        import inspect
                        sig = inspect.signature(func)
                        params = list(sig.parameters.keys())
                        
                        if len(params) == 4:  # Old V1 signature: cls, v, values, field
                            # Create a mock field object for compatibility
                            class MockField:
                                def __init__(self, name):
                                    self.name = name
                            
                            mock_field = MockField(info.field_name)
                            return func(cls, v, {}, mock_field)
                        else:  # New signature: cls, v
                            return func(cls, v)
                else:
                    # Older V2 or fallback
                    @field_validator(field_name, *fields)
                    @classmethod  
                    def wrapper(cls, v: Any) -> Any:
                        return func(cls, v)
                
                return wrapper
            return decorator
        
        # V1-compatible BaseModel with V2 config compatibility
        class BaseModel(V2BaseModel):
            """V1-compatible BaseModel for V2."""
            
            # V2 configuration compatibility
            model_config = {
                'str_strip_whitespace': True,
                'validate_assignment': True,
                'extra': 'forbid'
            }
            
        # Fedora-specific warning
        if PLATFORM_INFO['is_fedora']:
            warnings.warn(
                "Fedora with Pydantic V2 detected. Using compatibility mode. "
                "For better performance, consider using Pydantic V1: "
                "pip install 'pydantic>=1.10.0,<2.0.0'",
                UserWarning
            )
    
    else:
        # Pydantic V1 - Use directly  
        from pydantic import BaseModel, Field, validator
        ValidationInfo = None
        
        # Log success for non-Fedora systems
        if not PLATFORM_INFO['is_fedora']:
            logging.info(f"Pydantic V1 detected on {PLATFORM_INFO['system']} - using native mode")

except ImportError as e:
    # Pydantic not available
    pydantic_available = False
    PYDANTIC_V2 = False
    
    # Create minimal fallback classes
    class BaseModel:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)
    
    def Field(*args, **kwargs):
        return None
        
    def validator(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    
    ValidationInfo = None
    
    # Error message with platform-specific guidance
    error_msg = f"Pydantic is required but not installed on {PLATFORM_INFO['system']}"
    if PLATFORM_INFO['is_fedora']:
        error_msg += "\nFor Fedora, install with: sudo dnf install python3-pydantic or pip install pydantic"
    elif PLATFORM_INFO['is_ubuntu']:
        error_msg += "\nFor Ubuntu, install with: sudo apt install python3-pydantic or pip install pydantic"
    elif PLATFORM_INFO['is_macos']:
        error_msg += "\nFor macOS, install with: pip install pydantic"
    else:
        error_msg += "\nInstall with: pip install pydantic"
    
    raise ImportError(error_msg) from None

# Export unified interface
__all__ = [
    'BaseModel',
    'Field',
    'validator', 
    'ValidationInfo',
    'PYDANTIC_V2',
    'pydantic_available'
]