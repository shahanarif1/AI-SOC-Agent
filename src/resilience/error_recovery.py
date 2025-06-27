"""
Production-grade error recovery and resilience mechanisms for DXT extension.
"""

import asyncio
import time
import random
import logging
from typing import Any, Callable, Dict, List, Optional, Type, Union
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
import json
from datetime import datetime, timedelta


class ErrorSeverity(Enum):
    """Error severity levels for recovery strategies."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecoveryStrategy(Enum):
    """Available recovery strategies."""
    RETRY = "retry"
    FALLBACK = "fallback"
    CIRCUIT_BREAKER = "circuit_breaker"
    CACHE = "cache"
    GRACEFUL_DEGRADATION = "graceful_degradation"


@dataclass
class ErrorContext:
    """Context information for error recovery."""
    error_type: Type[Exception]
    error_message: str
    timestamp: datetime
    severity: ErrorSeverity
    attempt_count: int = 0
    recoverable: bool = True
    context_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_factor: float = 2.0
    jitter: bool = True
    retryable_exceptions: List[Type[Exception]] = field(default_factory=list)


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker pattern."""
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    expected_exception: Type[Exception] = Exception


class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Blocking requests
    HALF_OPEN = "half_open"  # Testing recovery


class CircuitBreaker:
    """Implementation of circuit breaker pattern for resilience."""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.logger = logging.getLogger(__name__)
    
    def can_execute(self) -> bool:
        """Check if execution is allowed based on circuit breaker state."""
        if self.state == CircuitBreakerState.CLOSED:
            return True
        elif self.state == CircuitBreakerState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitBreakerState.HALF_OPEN
                return True
            return False
        elif self.state == CircuitBreakerState.HALF_OPEN:
            return True
        
        return False
    
    def record_success(self):
        """Record successful execution."""
        self.failure_count = 0
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.CLOSED
            self.logger.info("Circuit breaker reset to CLOSED state")
    
    def record_failure(self, exception: Exception):
        """Record failed execution."""
        if isinstance(exception, self.config.expected_exception):
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.config.failure_threshold:
                self.state = CircuitBreakerState.OPEN
                self.logger.warning(
                    f"Circuit breaker opened after {self.failure_count} failures"
                )
    
    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self.last_failure_time is None:
            return True
        
        return (time.time() - self.last_failure_time) >= self.config.recovery_timeout


class ErrorRecoveryManager:
    """Comprehensive error recovery and resilience manager."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.error_counts: Dict[str, int] = {}
        self.fallback_cache: Dict[str, Any] = {}
        self.recovery_strategies: Dict[Type[Exception], RecoveryStrategy] = {}
        
        # Default recovery strategies
        self._setup_default_strategies()
    
    def _setup_default_strategies(self):
        """Setup default recovery strategies for common exceptions."""
        self.recovery_strategies.update({
            ConnectionError: RecoveryStrategy.RETRY,
            TimeoutError: RecoveryStrategy.RETRY,
            asyncio.TimeoutError: RecoveryStrategy.RETRY,
            ValueError: RecoveryStrategy.FALLBACK,
            KeyError: RecoveryStrategy.FALLBACK,
            FileNotFoundError: RecoveryStrategy.GRACEFUL_DEGRADATION,
        })
    
    def register_circuit_breaker(self, name: str, config: CircuitBreakerConfig):
        """Register a circuit breaker for a specific operation."""
        self.circuit_breakers[name] = CircuitBreaker(config)
    
    def add_recovery_strategy(self, exception_type: Type[Exception], strategy: RecoveryStrategy):
        """Add custom recovery strategy for exception type."""
        self.recovery_strategies[exception_type] = strategy
    
    async def execute_with_recovery(
        self,
        operation: Callable,
        operation_name: str,
        retry_config: Optional[RetryConfig] = None,
        fallback_func: Optional[Callable] = None,
        cache_key: Optional[str] = None,
        **kwargs
    ) -> Any:
        """Execute operation with comprehensive error recovery."""
        
        retry_config = retry_config or RetryConfig()
        attempt = 0
        last_exception = None
        
        # Check circuit breaker
        if operation_name in self.circuit_breakers:
            circuit_breaker = self.circuit_breakers[operation_name]
            if not circuit_breaker.can_execute():
                self.logger.warning(f"Circuit breaker open for {operation_name}, using fallback")
                return await self._execute_fallback(fallback_func, cache_key, operation_name)
        
        while attempt < retry_config.max_attempts:
            try:
                # Execute the operation
                if asyncio.iscoroutinefunction(operation):
                    result = await operation(**kwargs)
                else:
                    result = operation(**kwargs)
                
                # Record success
                if operation_name in self.circuit_breakers:
                    self.circuit_breakers[operation_name].record_success()
                
                # Cache successful result
                if cache_key:
                    self.fallback_cache[cache_key] = {
                        'data': result,
                        'timestamp': datetime.utcnow(),
                        'operation': operation_name
                    }
                
                return result
                
            except Exception as e:
                attempt += 1
                last_exception = e
                
                # Record failure
                if operation_name in self.circuit_breakers:
                    self.circuit_breakers[operation_name].record_failure(e)
                
                # Determine recovery strategy
                error_context = ErrorContext(
                    error_type=type(e),
                    error_message=str(e),
                    timestamp=datetime.utcnow(),
                    severity=self._assess_error_severity(e),
                    attempt_count=attempt
                )
                
                strategy = self._get_recovery_strategy(e)
                
                self.logger.warning(
                    f"Operation {operation_name} failed (attempt {attempt}/{retry_config.max_attempts}): {e}"
                )
                
                # Handle based on strategy
                if strategy == RecoveryStrategy.RETRY and attempt < retry_config.max_attempts:
                    if self._should_retry(e, retry_config):
                        delay = self._calculate_retry_delay(attempt, retry_config)
                        self.logger.info(f"Retrying {operation_name} in {delay:.2f}s")
                        await asyncio.sleep(delay)
                        continue
                
                elif strategy == RecoveryStrategy.FALLBACK:
                    return await self._execute_fallback(fallback_func, cache_key, operation_name)
                
                elif strategy == RecoveryStrategy.GRACEFUL_DEGRADATION:
                    return await self._graceful_degradation(operation_name, error_context)
                
                # If we reach here, all retries exhausted or non-retryable error
                break
        
        # All recovery attempts failed
        self.logger.error(
            f"All recovery attempts failed for {operation_name}: {last_exception}"
        )
        
        # Try final fallback
        fallback_result = await self._execute_fallback(fallback_func, cache_key, operation_name)
        if fallback_result is not None:
            return fallback_result
        
        # Re-raise the last exception if no fallback available
        raise last_exception
    
    def _get_recovery_strategy(self, exception: Exception) -> RecoveryStrategy:
        """Determine recovery strategy for exception."""
        exception_type = type(exception)
        
        # Check exact type match first
        if exception_type in self.recovery_strategies:
            return self.recovery_strategies[exception_type]
        
        # Check parent types
        for exc_type, strategy in self.recovery_strategies.items():
            if isinstance(exception, exc_type):
                return strategy
        
        # Default strategy
        return RecoveryStrategy.RETRY
    
    def _assess_error_severity(self, exception: Exception) -> ErrorSeverity:
        """Assess error severity for recovery decisions."""
        if isinstance(exception, (SystemExit, KeyboardInterrupt)):
            return ErrorSeverity.CRITICAL
        elif isinstance(exception, (MemoryError, OSError)):
            return ErrorSeverity.HIGH
        elif isinstance(exception, (ConnectionError, TimeoutError)):
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def _should_retry(self, exception: Exception, config: RetryConfig) -> bool:
        """Determine if exception should trigger retry."""
        if not config.retryable_exceptions:
            # Default retryable exceptions
            retryable_types = (
                ConnectionError, TimeoutError, asyncio.TimeoutError,
                OSError  # Network-related OS errors
            )
            return isinstance(exception, retryable_types)
        
        return any(isinstance(exception, exc_type) for exc_type in config.retryable_exceptions)
    
    def _calculate_retry_delay(self, attempt: int, config: RetryConfig) -> float:
        """Calculate delay for retry with exponential backoff and jitter."""
        delay = config.base_delay * (config.exponential_factor ** (attempt - 1))
        delay = min(delay, config.max_delay)
        
        if config.jitter:
            # Add jitter to prevent thundering herd
            jitter_factor = random.uniform(0.5, 1.5)
            delay *= jitter_factor
        
        return delay
    
    async def _execute_fallback(
        self,
        fallback_func: Optional[Callable],
        cache_key: Optional[str],
        operation_name: str
    ) -> Any:
        """Execute fallback strategy."""
        
        # Try custom fallback function first
        if fallback_func:
            try:
                if asyncio.iscoroutinefunction(fallback_func):
                    return await fallback_func()
                else:
                    return fallback_func()
            except Exception as e:
                self.logger.error(f"Fallback function failed for {operation_name}: {e}")
        
        # Try cached data
        if cache_key and cache_key in self.fallback_cache:
            cached_data = self.fallback_cache[cache_key]
            cache_age = datetime.utcnow() - cached_data['timestamp']
            
            # Use cached data if it's less than 1 hour old
            if cache_age < timedelta(hours=1):
                self.logger.info(f"Using cached data for {operation_name} (age: {cache_age})")
                return cached_data['data']
        
        # Return None if no fallback available
        return None
    
    async def _graceful_degradation(
        self,
        operation_name: str,
        error_context: ErrorContext
    ) -> Dict[str, Any]:
        """Implement graceful degradation strategy."""
        
        degraded_response = {
            "status": "degraded",
            "message": f"Service {operation_name} temporarily unavailable",
            "error": {
                "type": error_context.error_type.__name__,
                "severity": error_context.severity.value,
                "timestamp": error_context.timestamp.isoformat()
            },
            "fallback_data": None
        }
        
        # Try to provide some basic functionality
        if "alerts" in operation_name.lower():
            degraded_response["fallback_data"] = {
                "alerts": [],
                "total_alerts": 0,
                "message": "Alert data temporarily unavailable"
            }
        elif "agents" in operation_name.lower():
            degraded_response["fallback_data"] = {
                "agents": [],
                "total_agents": 0,
                "message": "Agent data temporarily unavailable"
            }
        
        self.logger.info(f"Graceful degradation activated for {operation_name}")
        return degraded_response
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics for monitoring."""
        stats = {
            "circuit_breakers": {},
            "error_counts": dict(self.error_counts),
            "cache_size": len(self.fallback_cache),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        for name, breaker in self.circuit_breakers.items():
            stats["circuit_breakers"][name] = {
                "state": breaker.state.value,
                "failure_count": breaker.failure_count,
                "last_failure": breaker.last_failure_time
            }
        
        return stats
    
    def clear_cache(self, max_age_hours: float = 24):
        """Clear old cached data."""
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        
        keys_to_remove = [
            key for key, data in self.fallback_cache.items()
            if data['timestamp'] < cutoff_time
        ]
        
        for key in keys_to_remove:
            del self.fallback_cache[key]
        
        if keys_to_remove:
            self.logger.info(f"Cleared {len(keys_to_remove)} expired cache entries")


# Global error recovery manager
error_recovery_manager = ErrorRecoveryManager()


def resilient_operation(
    operation_name: str,
    retry_config: Optional[RetryConfig] = None,
    fallback_func: Optional[Callable] = None,
    cache_key: Optional[str] = None
):
    """Decorator for adding resilience to operations."""
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await error_recovery_manager.execute_with_recovery(
                operation=func,
                operation_name=operation_name,
                retry_config=retry_config,
                fallback_func=fallback_func,
                cache_key=cache_key,
                *args,
                **kwargs
            )
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(
                error_recovery_manager.execute_with_recovery(
                    operation=func,
                    operation_name=operation_name,
                    retry_config=retry_config,
                    fallback_func=fallback_func,
                    cache_key=cache_key,
                    *args,
                    **kwargs
                )
            )
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def setup_circuit_breakers():
    """Setup circuit breakers for critical operations."""
    
    # Wazuh API operations
    wazuh_config = CircuitBreakerConfig(
        failure_threshold=3,
        recovery_timeout=30.0,
        expected_exception=ConnectionError
    )
    error_recovery_manager.register_circuit_breaker("wazuh_api", wazuh_config)
    
    # Database operations
    db_config = CircuitBreakerConfig(
        failure_threshold=5,
        recovery_timeout=60.0,
        expected_exception=Exception
    )
    error_recovery_manager.register_circuit_breaker("database", db_config)
    
    # External threat intelligence APIs
    threat_intel_config = CircuitBreakerConfig(
        failure_threshold=2,
        recovery_timeout=120.0,
        expected_exception=(ConnectionError, TimeoutError)
    )
    error_recovery_manager.register_circuit_breaker("threat_intel", threat_intel_config)


def create_fallback_response(operation_type: str, error_message: str) -> Dict[str, Any]:
    """Create standardized fallback response."""
    return {
        "status": "error",
        "error": {
            "message": error_message,
            "operation": operation_type,
            "timestamp": datetime.utcnow().isoformat(),
            "fallback": True
        },
        "data": None
    }