"""Production-grade error handling for Wazuh API operations."""

import asyncio
import time
from typing import Dict, Any, Optional, List, Callable, Union
from dataclasses import dataclass
from enum import Enum
import aiohttp
from datetime import datetime, timedelta

try:
    from .logging import get_logger
    from .exceptions import (
        WazuhMCPError, APIError, ConnectionError, AuthenticationError,
        AuthorizationError, RateLimitError
    )
except ImportError:
    # Fallback for test environments
    import logging
    def get_logger(name):
        return logging.getLogger(name)
    
    class WazuhMCPError(Exception): pass
    class APIError(WazuhMCPError): pass
    class ConnectionError(WazuhMCPError): pass
    class AuthenticationError(WazuhMCPError): pass
    class AuthorizationError(WazuhMCPError): pass
    class RateLimitError(WazuhMCPError): pass

logger = get_logger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, rejecting requests  
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class ErrorContext:
    """Context information for error handling."""
    operation: str
    api_type: str  # "server" or "indexer"
    endpoint: str
    attempt: int
    max_attempts: int
    timestamp: datetime
    error_details: Dict[str, Any]


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5
    recovery_timeout: int = 60  # seconds
    test_request_timeout: int = 10  # seconds
    success_threshold: int = 2  # consecutive successes to close


class CircuitBreaker:
    """Circuit breaker for API calls."""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.success_count = 0
        
    def can_execute(self) -> bool:
        """Check if circuit breaker allows execution."""
        if self.state == CircuitBreakerState.CLOSED:
            return True
        elif self.state == CircuitBreakerState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitBreakerState.HALF_OPEN
                self.success_count = 0
                return True
            return False
        else:  # HALF_OPEN
            return True
    
    def record_success(self):
        """Record successful execution."""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
        elif self.state == CircuitBreakerState.CLOSED:
            self.failure_count = 0
    
    def record_failure(self):
        """Record failed execution."""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()
        
        if self.state == CircuitBreakerState.CLOSED:
            if self.failure_count >= self.config.failure_threshold:
                self.state = CircuitBreakerState.OPEN
        elif self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.OPEN
            self.success_count = 0
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if not self.last_failure_time:
            return True
        
        time_since_failure = (datetime.utcnow() - self.last_failure_time).total_seconds()
        return time_since_failure >= self.config.recovery_timeout


class ProductionErrorHandler:
    """Production-grade error handler with retry logic and circuit breaker."""
    
    # Retry configurations for different error types
    RETRY_CONFIGS = {
        # Connection errors - aggressive retry
        "connection": {
            "max_attempts": 5,
            "base_delay": 1.0,
            "max_delay": 30.0,
            "exponential_base": 2.0,
            "jitter": True
        },
        # Rate limiting - backoff retry
        "rate_limit": {
            "max_attempts": 10,
            "base_delay": 5.0,
            "max_delay": 300.0,
            "exponential_base": 2.0,
            "jitter": True
        },
        # Authentication errors - limited retry
        "auth": {
            "max_attempts": 3,
            "base_delay": 2.0,
            "max_delay": 10.0,
            "exponential_base": 1.5,
            "jitter": False
        },
        # Server errors - moderate retry
        "server": {
            "max_attempts": 4,
            "base_delay": 2.0,
            "max_delay": 60.0,
            "exponential_base": 2.0,
            "jitter": True
        },
        # Client errors - minimal retry
        "client": {
            "max_attempts": 2,
            "base_delay": 1.0,
            "max_delay": 5.0,
            "exponential_base": 1.0,
            "jitter": False
        }
    }
    
    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.error_counts: Dict[str, int] = {}
        self.last_errors: Dict[str, datetime] = {}
    
    def get_circuit_breaker(self, api_type: str) -> CircuitBreaker:
        """Get or create circuit breaker for API type."""
        if api_type not in self.circuit_breakers:
            config = CircuitBreakerConfig()
            self.circuit_breakers[api_type] = CircuitBreaker(config)
        return self.circuit_breakers[api_type]
    
    async def execute_with_retry(
        self,
        operation: Callable,
        operation_name: str,
        api_type: str,
        endpoint: str,
        *args,
        **kwargs
    ) -> Any:
        """Execute operation with retry logic and circuit breaker."""
        
        circuit_breaker = self.get_circuit_breaker(api_type)
        
        # Check circuit breaker
        if not circuit_breaker.can_execute():
            raise APIError(f"Circuit breaker open for {api_type} API")
        
        last_exception = None
        
        for attempt in range(1, 6):  # Max 5 attempts
            try:
                error_context = ErrorContext(
                    operation=operation_name,
                    api_type=api_type,
                    endpoint=endpoint,
                    attempt=attempt,
                    max_attempts=5,
                    timestamp=datetime.utcnow(),
                    error_details={}
                )
                
                logger.debug(f"Executing {operation_name} attempt {attempt}", extra={
                    "details": {
                        "api_type": api_type,
                        "endpoint": endpoint,
                        "attempt": attempt
                    }
                })
                
                result = await operation(*args, **kwargs)
                
                # Record success
                circuit_breaker.record_success()
                self._record_success(api_type, operation_name)
                
                if attempt > 1:
                    logger.info(f"Operation {operation_name} succeeded after {attempt} attempts")
                
                return result
                
            except Exception as e:
                last_exception = e
                error_context.error_details = self._extract_error_details(e)
                
                # Classify error and determine retry strategy
                error_type = self._classify_error(e)
                retry_config = self.RETRY_CONFIGS.get(error_type, self.RETRY_CONFIGS["client"])
                
                # Record failure
                circuit_breaker.record_failure()
                self._record_failure(api_type, operation_name, e)
                
                # Check if we should retry
                if attempt >= retry_config["max_attempts"]:
                    logger.error(f"Operation {operation_name} failed after {attempt} attempts", extra={
                        "details": error_context.__dict__
                    })
                    break
                
                # Calculate delay
                delay = self._calculate_delay(attempt, retry_config)
                
                logger.warning(f"Operation {operation_name} failed (attempt {attempt}), retrying in {delay}s", extra={
                    "details": {
                        "error": str(e),
                        "error_type": error_type,
                        "retry_delay": delay,
                        "api_type": api_type
                    }
                })
                
                await asyncio.sleep(delay)
        
        # All retries exhausted
        raise last_exception
    
    def _classify_error(self, error: Exception) -> str:
        """Classify error type for retry strategy."""
        if isinstance(error, aiohttp.ClientConnectorError):
            return "connection"
        elif isinstance(error, aiohttp.ClientTimeout):
            return "connection"
        elif isinstance(error, RateLimitError):
            return "rate_limit"
        elif isinstance(error, AuthenticationError):
            return "auth"
        elif isinstance(error, AuthorizationError):
            return "auth"
        elif isinstance(error, APIError):
            # Check HTTP status codes
            error_str = str(error).lower()
            if "500" in error_str or "502" in error_str or "503" in error_str or "504" in error_str:
                return "server"
            elif "401" in error_str or "403" in error_str:
                return "auth"
            elif "429" in error_str:
                return "rate_limit"
            else:
                return "client"
        else:
            return "server"
    
    def _calculate_delay(self, attempt: int, config: Dict[str, Any]) -> float:
        """Calculate retry delay with exponential backoff and jitter."""
        base_delay = config["base_delay"]
        max_delay = config["max_delay"]
        exponential_base = config["exponential_base"]
        jitter = config["jitter"]
        
        # Exponential backoff
        delay = base_delay * (exponential_base ** (attempt - 1))
        delay = min(delay, max_delay)
        
        # Add jitter if enabled
        if jitter:
            import random
            jitter_amount = delay * 0.1  # 10% jitter
            delay += random.uniform(-jitter_amount, jitter_amount)
        
        return max(0, delay)
    
    def _extract_error_details(self, error: Exception) -> Dict[str, Any]:
        """Extract detailed error information."""
        details = {
            "error_type": type(error).__name__,
            "error_message": str(error),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if isinstance(error, aiohttp.ClientError):
            details["aiohttp_error"] = True
            if hasattr(error, 'status'):
                details["http_status"] = error.status
            if hasattr(error, 'headers'):
                details["response_headers"] = dict(error.headers) if error.headers else {}
        
        if isinstance(error, APIError):
            details["api_error"] = True
            # Extract additional API error details if available
        
        return details
    
    def _record_success(self, api_type: str, operation: str):
        """Record successful operation."""
        key = f"{api_type}_{operation}"
        # Reset error count on success
        if key in self.error_counts:
            del self.error_counts[key]
    
    def _record_failure(self, api_type: str, operation: str, error: Exception):
        """Record failed operation."""
        key = f"{api_type}_{operation}"
        self.error_counts[key] = self.error_counts.get(key, 0) + 1
        self.last_errors[key] = datetime.utcnow()
        
        # Log error metrics
        logger.error(f"API operation failed: {api_type}.{operation}", extra={
            "details": {
                "api_type": api_type,
                "operation": operation,
                "error": str(error),
                "error_count": self.error_counts[key],
                "error_type": type(error).__name__
            }
        })
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics for monitoring."""
        return {
            "circuit_breakers": {
                api_type: {
                    "state": breaker.state.value,
                    "failure_count": breaker.failure_count,
                    "last_failure": breaker.last_failure_time.isoformat() if breaker.last_failure_time else None
                }
                for api_type, breaker in self.circuit_breakers.items()
            },
            "error_counts": dict(self.error_counts),
            "last_errors": {
                key: timestamp.isoformat() 
                for key, timestamp in self.last_errors.items()
            }
        }
    
    def reset_circuit_breaker(self, api_type: str):
        """Manually reset circuit breaker (for operational use)."""
        if api_type in self.circuit_breakers:
            breaker = self.circuit_breakers[api_type]
            breaker.state = CircuitBreakerState.CLOSED
            breaker.failure_count = 0
            breaker.success_count = 0
            logger.info(f"Circuit breaker reset for {api_type} API")
    
    def is_healthy(self, api_type: str) -> bool:
        """Check if API type is healthy."""
        if api_type not in self.circuit_breakers:
            return True
        
        breaker = self.circuit_breakers[api_type]
        return breaker.state == CircuitBreakerState.CLOSED


# Global instance
production_error_handler = ProductionErrorHandler()