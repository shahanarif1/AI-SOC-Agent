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

# Additional validation functions needed by main.py (fallback implementations)
def validate_alert_summary_query(query):
    """Fallback validation for alert summary queries."""
    return query if isinstance(query, dict) else {}

def validate_vulnerability_summary_query(query):
    """Fallback validation for vulnerability summary queries."""
    return query if isinstance(query, dict) else {}

def validate_critical_vulnerabilities_query(query):
    """Fallback validation for critical vulnerabilities queries."""
    return query if isinstance(query, dict) else {}

def validate_running_agents_query(query):
    """Fallback validation for running agents queries."""
    return query if isinstance(query, dict) else {}

def validate_rules_summary_query(query):
    """Fallback validation for rules summary queries."""
    return query if isinstance(query, dict) else {}

def validate_weekly_stats_query(query):
    """Fallback validation for weekly stats queries."""
    return query if isinstance(query, dict) else {}

def validate_remoted_stats_query(query):
    """Fallback validation for remoted stats queries."""
    return query if isinstance(query, dict) else {}

def validate_log_collector_stats_query(query):
    """Fallback validation for log collector stats queries."""
    return query if isinstance(query, dict) else {}

def validate_cluster_health_query(query):
    """Fallback validation for cluster health queries."""
    return query if isinstance(query, dict) else {}

def validate_manager_error_logs_query(query):
    """Fallback validation for manager error logs queries."""
    return query if isinstance(query, dict) else {}

def validate_agent_processes_query(query):
    """Fallback validation for agent processes queries."""
    return query if isinstance(query, dict) else {}

def validate_agent_ports_query(query):
    """Fallback validation for agent ports queries."""
    return query if isinstance(query, dict) else {}

def validate_time_range(time_range):
    """Fallback validation for time range values."""
    if isinstance(time_range, int) and time_range > 0:
        return time_range
    return 3600  # Default to 1 hour

def validate_agent_id(agent_id):
    """Fallback validation for agent ID."""
    return str(agent_id) if agent_id else None

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
    "validate_alert_summary_query",
    "validate_vulnerability_summary_query",
    "validate_critical_vulnerabilities_query",
    "validate_running_agents_query",
    "validate_rules_summary_query",
    "validate_weekly_stats_query",
    "validate_remoted_stats_query",
    "validate_log_collector_stats_query",
    "validate_cluster_health_query",
    "validate_manager_error_logs_query",
    "validate_agent_processes_query",
    "validate_agent_ports_query",
    "validate_time_range",
    "validate_agent_id",
    "global_rate_limiter",
    "RateLimitConfig",
]