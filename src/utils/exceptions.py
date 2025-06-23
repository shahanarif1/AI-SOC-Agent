"""Custom exceptions for better error handling and debugging."""

import logging
from typing import Optional, Dict, Any


class WazuhMCPError(Exception):
    """Base exception for all Wazuh MCP Server errors."""
    
    def __init__(self, message: str, error_code: Optional[str] = None, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        
        # Log the error for debugging
        logging.error(f"{self.error_code}: {message}", extra={"details": self.details})


class ConfigurationError(WazuhMCPError):
    """Raised when configuration is invalid or missing."""
    pass


class AuthenticationError(WazuhMCPError):
    """Raised when Wazuh API authentication fails."""
    pass


class AuthorizationError(WazuhMCPError):
    """Raised when user doesn't have required permissions."""
    pass


class ConnectionError(WazuhMCPError):
    """Raised when connection to Wazuh API fails."""
    pass


class APIError(WazuhMCPError):
    """Raised when Wazuh API returns an error response."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, response_data: Optional[Dict[str, Any]] = None):
        super().__init__(message, details={"status_code": status_code, "response": response_data})
        self.status_code = status_code
        self.response_data = response_data


class ValidationError(WazuhMCPError):
    """Raised when input validation fails."""
    pass


class RateLimitError(WazuhMCPError):
    """Raised when rate limits are exceeded."""
    
    def __init__(self, message: str, retry_after: Optional[int] = None):
        super().__init__(message, details={"retry_after": retry_after})
        self.retry_after = retry_after


class ExternalAPIError(WazuhMCPError):
    """Raised when external API calls fail."""
    
    def __init__(self, message: str, service: str, status_code: Optional[int] = None):
        super().__init__(message, details={"service": service, "status_code": status_code})
        self.service = service
        self.status_code = status_code


class DataProcessingError(WazuhMCPError):
    """Raised when data processing or analysis fails."""
    pass


class SecurityError(WazuhMCPError):
    """Raised when security violations are detected."""
    pass


def handle_api_error(response_status: int, response_data: Optional[Dict[str, Any]] = None) -> None:
    """Handle API response errors and raise appropriate exceptions."""
    error_message = "Unknown API error"
    
    if response_data:
        error_message = response_data.get("message", str(response_data))
    
    if response_status == 400:
        raise ValidationError(f"Bad request: {error_message}")
    elif response_status == 401:
        raise AuthenticationError(f"Authentication failed: {error_message}")
    elif response_status == 403:
        raise AuthorizationError(f"Access denied: {error_message}")
    elif response_status == 404:
        raise APIError(f"Resource not found: {error_message}", status_code=response_status)
    elif response_status == 429:
        retry_after = None
        if response_data:
            retry_after = response_data.get("retry_after")
        raise RateLimitError(f"Rate limit exceeded: {error_message}", retry_after=retry_after)
    elif response_status >= 500:
        raise APIError(f"Server error: {error_message}", status_code=response_status, response_data=response_data)
    else:
        raise APIError(f"API error: {error_message}", status_code=response_status, response_data=response_data)


def handle_connection_error(error: Exception, url: str) -> None:
    """Handle connection errors with context."""
    if "timeout" in str(error).lower():
        raise ConnectionError(f"Connection timeout to {url}: {str(error)}")
    elif "refused" in str(error).lower():
        raise ConnectionError(f"Connection refused to {url}: {str(error)}")
    elif "ssl" in str(error).lower():
        raise ConnectionError(f"SSL error connecting to {url}: {str(error)}")
    else:
        raise ConnectionError(f"Connection failed to {url}: {str(error)}")