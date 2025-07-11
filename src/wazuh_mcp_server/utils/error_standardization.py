"""Standardized error handling patterns for consistent behavior across the codebase."""

import functools
import traceback
from typing import Any, Callable, Dict, List, Optional, Type, Union
from datetime import datetime
import logging

try:
    from .logging import get_logger
    from .exceptions import WazuhMCPError, APIError, ValidationError, ConfigurationError
    from .production_error_handler import production_error_handler
except ImportError:
    # Fallback for test environments
    def get_logger(name):
        return logging.getLogger(name)
    
    class WazuhMCPError(Exception): pass
    class APIError(WazuhMCPError): pass
    class ValidationError(WazuhMCPError): pass
    class ConfigurationError(WazuhMCPError): pass
    
    production_error_handler = None


class StandardErrorResponse:
    """Standardized error response format."""
    
    def __init__(self, error: Exception, context: Optional[Dict[str, Any]] = None):
        self.error = error
        self.context = context or {}
        self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format for JSON responses."""
        return {
            "error": {
                "type": type(self.error).__name__,
                "message": str(self.error),
                "timestamp": self.timestamp.isoformat(),
                "context": self.context
            },
            "success": False
        }
    
    def to_string(self) -> str:
        """Convert to string format for text responses."""
        context_str = f" (Context: {self.context})" if self.context else ""
        return f"Error: {str(self.error)}{context_str}"


class ErrorHandlingStrategy:
    """Define different error handling strategies."""
    
    # Strategy for API operations
    API_OPERATION = {
        "log_level": logging.ERROR,
        "include_traceback": False,
        "reraise": True,
        "return_none_on_error": False,
        "use_production_handler": True
    }
    
    # Strategy for configuration operations
    CONFIG_OPERATION = {
        "log_level": logging.CRITICAL,
        "include_traceback": True,
        "reraise": True,
        "return_none_on_error": False,
        "use_production_handler": False
    }
    
    # Strategy for optional feature operations
    OPTIONAL_FEATURE = {
        "log_level": logging.WARNING,
        "include_traceback": False,
        "reraise": False,
        "return_none_on_error": True,
        "use_production_handler": False
    }
    
    # Strategy for validation operations
    VALIDATION_OPERATION = {
        "log_level": logging.ERROR,
        "include_traceback": False,
        "reraise": True,
        "return_none_on_error": False,
        "use_production_handler": False
    }
    
    # Strategy for utility operations
    UTILITY_OPERATION = {
        "log_level": logging.WARNING,
        "include_traceback": False,
        "reraise": False,
        "return_none_on_error": True,
        "use_production_handler": False
    }


def standardized_error_handler(
    strategy: Dict[str, Any] = ErrorHandlingStrategy.API_OPERATION,
    context: Optional[Dict[str, Any]] = None,
    logger_name: Optional[str] = None
):
    """Decorator for standardized error handling.
    
    Args:
        strategy: Error handling strategy configuration
        context: Additional context to include in error logs
        logger_name: Custom logger name (defaults to module name)
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Get logger
            nonlocal logger_name
            if logger_name is None:
                logger_name = func.__module__
            logger = get_logger(logger_name)
            
            # Build context
            error_context = {
                "function": func.__name__,
                "module": func.__module__,
                **(context or {})
            }
            
            try:
                return func(*args, **kwargs)
                
            except Exception as e:
                # Create standardized error response
                error_response = StandardErrorResponse(e, error_context)
                
                # Log the error according to strategy
                log_message = f"Error in {func.__name__}: {str(e)}"
                log_extra = {"details": error_context}
                
                if strategy.get("include_traceback", False):
                    log_extra["traceback"] = traceback.format_exc()
                
                logger.log(strategy.get("log_level", logging.ERROR), log_message, extra=log_extra)
                
                # Handle based on strategy
                if strategy.get("reraise", True):
                    # Reraise the original exception
                    raise
                elif strategy.get("return_none_on_error", False):
                    return None
                else:
                    # Return standardized error response
                    return error_response
        
        # Async version
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            # Get logger
            nonlocal logger_name
            if logger_name is None:
                logger_name = func.__module__
            logger = get_logger(logger_name)
            
            # Build context
            error_context = {
                "function": func.__name__,
                "module": func.__module__,
                "is_async": True,
                **(context or {})
            }
            
            try:
                return await func(*args, **kwargs)
                
            except Exception as e:
                # Create standardized error response
                error_response = StandardErrorResponse(e, error_context)
                
                # Log the error according to strategy
                log_message = f"Error in async {func.__name__}: {str(e)}"
                log_extra = {"details": error_context}
                
                if strategy.get("include_traceback", False):
                    log_extra["traceback"] = traceback.format_exc()
                
                logger.log(strategy.get("log_level", logging.ERROR), log_message, extra=log_extra)
                
                # Use production error handler if configured
                if strategy.get("use_production_handler", False) and production_error_handler:
                    # Re-execute with production error handler
                    return await production_error_handler.execute_with_retry(
                        func, func.__name__, "api", "unknown", *args, **kwargs
                    )
                
                # Handle based on strategy
                if strategy.get("reraise", True):
                    # Reraise the original exception
                    raise
                elif strategy.get("return_none_on_error", False):
                    return None
                else:
                    # Return standardized error response
                    return error_response
        
        # Return appropriate wrapper based on whether function is async
        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper
    
    return decorator


def safe_execute(
    operation: Callable,
    default_value: Any = None,
    error_context: Optional[Dict[str, Any]] = None,
    log_errors: bool = True,
    logger_name: Optional[str] = None
) -> Any:
    """Safely execute an operation with standardized error handling.
    
    Args:
        operation: Function to execute
        default_value: Value to return on error
        error_context: Additional context for error logging
        log_errors: Whether to log errors
        logger_name: Custom logger name
    
    Returns:
        Operation result or default_value on error
    """
    try:
        return operation()
    except Exception as e:
        if log_errors:
            logger = get_logger(logger_name or __name__)
            logger.warning(f"Safe execution failed: {str(e)}", extra={
                "details": {
                    "operation": operation.__name__ if hasattr(operation, '__name__') else str(operation),
                    "error_type": type(e).__name__,
                    **(error_context or {})
                }
            })
        return default_value


async def safe_execute_async(
    operation: Callable,
    default_value: Any = None,
    error_context: Optional[Dict[str, Any]] = None,
    log_errors: bool = True,
    logger_name: Optional[str] = None
) -> Any:
    """Safely execute an async operation with standardized error handling.
    
    Args:
        operation: Async function to execute
        default_value: Value to return on error
        error_context: Additional context for error logging
        log_errors: Whether to log errors
        logger_name: Custom logger name
    
    Returns:
        Operation result or default_value on error
    """
    try:
        return await operation()
    except Exception as e:
        if log_errors:
            logger = get_logger(logger_name or __name__)
            logger.warning(f"Safe async execution failed: {str(e)}", extra={
                "details": {
                    "operation": operation.__name__ if hasattr(operation, '__name__') else str(operation),
                    "error_type": type(e).__name__,
                    "is_async": True,
                    **(error_context or {})
                }
            })
        return default_value


def validate_and_handle_error(
    condition: bool,
    error_type: Type[Exception] = ValidationError,
    error_message: str = "Validation failed",
    context: Optional[Dict[str, Any]] = None
):
    """Validate a condition and raise standardized error if false.
    
    Args:
        condition: Condition to validate
        error_type: Exception type to raise
        error_message: Error message
        context: Additional context
    
    Raises:
        error_type: If condition is False
    """
    if not condition:
        if context:
            error_message += f" (Context: {context})"
        raise error_type(error_message)


class ErrorAggregator:
    """Aggregate multiple errors for batch operations."""
    
    def __init__(self):
        self.errors: List[Dict[str, Any]] = []
    
    def add_error(self, error: Exception, context: Optional[Dict[str, Any]] = None):
        """Add an error to the aggregator."""
        self.errors.append({
            "error_type": type(error).__name__,
            "error_message": str(error),
            "context": context or {},
            "timestamp": datetime.utcnow().isoformat()
        })
    
    def has_errors(self) -> bool:
        """Check if any errors have been recorded."""
        return len(self.errors) > 0
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all errors."""
        if not self.errors:
            return {"error_count": 0, "errors": []}
        
        error_types = {}
        for error in self.errors:
            error_type = error["error_type"]
            error_types[error_type] = error_types.get(error_type, 0) + 1
        
        return {
            "error_count": len(self.errors),
            "error_types": error_types,
            "errors": self.errors
        }
    
    def raise_if_errors(self, aggregate_message: str = "Multiple errors occurred"):
        """Raise an exception if any errors have been recorded."""
        if self.errors:
            summary = self.get_summary()
            raise WazuhMCPError(f"{aggregate_message}: {summary}")


# Convenience decorators for common patterns
api_error_handler = functools.partial(
    standardized_error_handler, 
    strategy=ErrorHandlingStrategy.API_OPERATION
)

config_error_handler = functools.partial(
    standardized_error_handler, 
    strategy=ErrorHandlingStrategy.CONFIG_OPERATION
)

optional_feature_handler = functools.partial(
    standardized_error_handler, 
    strategy=ErrorHandlingStrategy.OPTIONAL_FEATURE
)

validation_error_handler = functools.partial(
    standardized_error_handler, 
    strategy=ErrorHandlingStrategy.VALIDATION_OPERATION
)

utility_error_handler = functools.partial(
    standardized_error_handler, 
    strategy=ErrorHandlingStrategy.UTILITY_OPERATION
)