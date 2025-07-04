"""
Wazuh MCP Server utilities.

This module provides common utilities used throughout the application:
- Logging utilities
- Error handling and recovery
- Validation and sanitization
- Rate limiting
- SSL configuration
"""

# Core imports that don't require external dependencies
from .logging import get_logger, setup_logging
from .exceptions import (
    WazuhMCPError,
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
    APIError,
    RateLimitError,
    ValidationError,
    ConfigurationError,
    handle_api_error,
    handle_connection_error,
)

# Optional imports with graceful fallback for modules requiring external dependencies
try:
    from .validation import (
        validate_alert_query, 
        validate_agent_query, 
        validate_threat_analysis,
        validate_ip_address,
        validate_file_hash,
        sanitize_string
    )
except ImportError:
    # Provide minimal implementations
    def validate_alert_query(query):
        return query if isinstance(query, dict) else {}
    def validate_agent_query(query):
        return query if isinstance(query, dict) else {}
    def validate_threat_analysis(data):
        return data if isinstance(data, dict) else {}
    def validate_ip_address(ip):
        return str(ip) if ip else ""
    def validate_file_hash(hash_val):
        return str(hash_val) if hash_val else ""
    def sanitize_string(text, max_len=100):
        return str(text)[:max_len] if text else ""

try:
    from .rate_limiter import global_rate_limiter, RateLimitConfig
except ImportError:
    # Minimal rate limiter implementation
    class RateLimitConfig:
        def __init__(self, **kwargs):
            pass
    class _MinimalRateLimiter:
        def enforce_rate_limit(self, key):
            pass
        def configure_endpoint(self, name, config):
            pass
    global_rate_limiter = _MinimalRateLimiter()

try:
    from .logging import LogContext
except ImportError:
    class LogContext:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

__all__ = [
    "get_logger",
    "setup_logging",
    "LogContext",
    "WazuhMCPError",
    "AuthenticationError",
    "AuthorizationError", 
    "ConnectionError",
    "APIError",
    "RateLimitError",
    "ValidationError",
    "ConfigurationError",
    "handle_api_error",
    "handle_connection_error",
    "validate_alert_query",
    "validate_agent_query",
    "validate_threat_analysis",
    "validate_ip_address",
    "validate_file_hash",
    "sanitize_string",
    "global_rate_limiter",
    "RateLimitConfig",
]