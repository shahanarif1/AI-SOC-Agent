"""Utility modules for Wazuh MCP Server."""

from .validation import (
    ValidationError,
    AlertQuery,
    AgentQuery,
    ThreatAnalysisQuery,
    IPAddress,
    FileHash,
    validate_alert_query,
    validate_agent_query,
    validate_threat_analysis,
    validate_ip_address,
    validate_file_hash,
    sanitize_string,
    validate_json_payload
)

from .exceptions import (
    WazuhMCPError,
    ConfigurationError,
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
    APIError,
    RateLimitError,
    ExternalAPIError,
    DataProcessingError,
    SecurityError,
    handle_api_error,
    handle_connection_error
)

from .logging import (
    setup_logging,
    get_logger,
    LogContext,
    log_performance,
    sanitize_log_data
)

from .rate_limiter import (
    RateLimitConfig,
    TokenBucket,
    SlidingWindowRateLimiter,
    AdaptiveRateLimiter,
    GlobalRateLimiter,
    global_rate_limiter,
    rate_limit
)

__all__ = [
    # Validation
    "ValidationError", "AlertQuery", "AgentQuery", "ThreatAnalysisQuery", 
    "IPAddress", "FileHash", "validate_alert_query", "validate_agent_query",
    "validate_threat_analysis", "validate_ip_address", "validate_file_hash",
    "sanitize_string", "validate_json_payload",
    
    # Exceptions
    "WazuhMCPError", "ConfigurationError", "AuthenticationError", 
    "AuthorizationError", "ConnectionError", "APIError", "RateLimitError",
    "ExternalAPIError", "DataProcessingError", "SecurityError",
    "handle_api_error", "handle_connection_error",
    
    # Logging
    "setup_logging", "get_logger", "LogContext", "log_performance", 
    "sanitize_log_data",
    
    # Rate limiting
    "RateLimitConfig", "TokenBucket", "SlidingWindowRateLimiter",
    "AdaptiveRateLimiter", "GlobalRateLimiter", "global_rate_limiter",
    "rate_limit"
]