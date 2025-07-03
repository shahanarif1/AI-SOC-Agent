#!/usr/bin/env python3
"""
Production-grade error recovery and resilience system for Wazuh MCP Server.
Provides intelligent error handling, automatic recovery, and degraded service modes.
"""

import asyncio
import logging
import time
import random
from enum import Enum
from typing import Dict, Any, Optional, Callable, List, Union
from dataclasses import dataclass, field
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels for recovery strategies."""
    LOW = "low"          # Temporary issues, fast recovery
    MEDIUM = "medium"    # Service degradation, measured recovery  
    HIGH = "high"        # Service failure, aggressive recovery
    CRITICAL = "critical" # System failure, emergency recovery


class RecoveryStrategy(Enum):
    """Recovery strategy types."""
    RETRY = "retry"                    # Simple retry with backoff
    CIRCUIT_BREAKER = "circuit_breaker"  # Circuit breaker pattern
    FALLBACK = "fallback"              # Use alternative service
    DEGRADE = "degrade"                # Reduced functionality mode
    EMERGENCY = "emergency"            # Emergency protocols


@dataclass
class ErrorPattern:
    """Definition of an error pattern and its recovery strategy."""
    error_types: List[type]
    keywords: List[str] = field(default_factory=list)
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    strategy: RecoveryStrategy = RecoveryStrategy.RETRY
    max_retries: int = 3
    backoff_factor: float = 2.0
    max_backoff: float = 60.0
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: float = 300.0


class ErrorRecoveryManager:
    """Production-grade error recovery and resilience manager."""
    
    def __init__(self):
        self.logger = logger
        self.error_counts: Dict[str, int] = {}
        self.circuit_breakers: Dict[str, Dict[str, Any]] = {}
        self.last_errors: Dict[str, float] = {}
        self.recovery_stats: Dict[str, Dict[str, Any]] = {}
        
        # Default error patterns
        self.error_patterns = self._create_default_patterns()
        
        # Fallback services registry
        self.fallback_services: Dict[str, Callable] = {}
        
        # Emergency mode flag
        self.emergency_mode = False
    
    def _create_default_patterns(self) -> List[ErrorPattern]:
        """Create default error patterns for common issues."""
        return [
            # Network connectivity issues
            ErrorPattern(
                error_types=[ConnectionError, TimeoutError],
                keywords=["connection", "timeout", "network"],
                severity=ErrorSeverity.MEDIUM,
                strategy=RecoveryStrategy.RETRY,
                max_retries=5,
                backoff_factor=1.5
            ),
            
            # Authentication/Authorization issues
            ErrorPattern(
                error_types=[PermissionError],
                keywords=["authentication", "authorization", "401", "403", "forbidden"],
                severity=ErrorSeverity.HIGH,
                strategy=RecoveryStrategy.FALLBACK,
                max_retries=2
            ),
            
            # SSL/TLS issues
            ErrorPattern(
                error_types=[Exception],  # Catch-all for SSL errors
                keywords=["ssl", "tls", "certificate", "handshake"],
                severity=ErrorSeverity.HIGH,
                strategy=RecoveryStrategy.DEGRADE,
                max_retries=3
            ),
            
            # API parsing issues (like the match_all query problem)
            ErrorPattern(
                error_types=[ValueError, TypeError],
                keywords=["parsing_exception", "malformed", "invalid", "json"],
                severity=ErrorSeverity.MEDIUM,
                strategy=RecoveryStrategy.FALLBACK,
                max_retries=2
            ),
            
            # Rate limiting
            ErrorPattern(
                error_types=[Exception],
                keywords=["rate", "limit", "429", "too many requests"],
                severity=ErrorSeverity.LOW,
                strategy=RecoveryStrategy.RETRY,
                max_retries=10,
                backoff_factor=3.0
            ),
            
            # Service unavailable
            ErrorPattern(
                error_types=[Exception],
                keywords=["503", "service unavailable", "maintenance"],
                severity=ErrorSeverity.HIGH,
                strategy=RecoveryStrategy.CIRCUIT_BREAKER,
                circuit_breaker_threshold=3,
                circuit_breaker_timeout=600.0
            ),
            
            # Critical system errors
            ErrorPattern(
                error_types=[MemoryError, OSError],
                keywords=["memory", "disk", "system"],
                severity=ErrorSeverity.CRITICAL,
                strategy=RecoveryStrategy.EMERGENCY,
                max_retries=1
            )
        ]
    
    def classify_error(self, error: Exception, context: str = "") -> ErrorPattern:
        """
        Classify an error and determine appropriate recovery strategy.
        
        Args:
            error: The exception that occurred
            context: Additional context about the operation
            
        Returns:
            Matching error pattern with recovery strategy
        """
        error_str = str(error).lower()
        error_type = type(error)
        
        # Find matching pattern
        for pattern in self.error_patterns:
            # Check error type match
            if any(issubclass(error_type, pattern_type) for pattern_type in pattern.error_types):
                return pattern
            
            # Check keyword match
            if any(keyword in error_str or keyword in context.lower() 
                   for keyword in pattern.keywords):
                return pattern
        
        # Default pattern for unclassified errors
        return ErrorPattern(
            error_types=[Exception],
            severity=ErrorSeverity.MEDIUM,
            strategy=RecoveryStrategy.RETRY,
            max_retries=3
        )
    
    async def handle_error(
        self, 
        error: Exception, 
        operation: str,
        retry_func: Optional[Callable] = None,
        fallback_func: Optional[Callable] = None,
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """
        Handle an error using appropriate recovery strategy.
        
        Args:
            error: The exception that occurred
            operation: Name of the operation that failed
            retry_func: Function to retry the operation
            fallback_func: Fallback function if primary fails
            context: Additional context for recovery decisions
            
        Returns:
            Recovery result with success status and data
        """
        if context is None:
            context = {}
        
        # Classify the error
        pattern = self.classify_error(error, str(context))
        
        # Update error statistics
        self._update_error_stats(operation, error, pattern)
        
        # Log the error with classification
        self.logger.error(f"Error in {operation}: {error}", extra={
            "details": {
                "error_type": type(error).__name__,
                "severity": pattern.severity.value,
                "strategy": pattern.strategy.value,
                "context": context
            }
        })
        
        # Execute recovery strategy
        if pattern.strategy == RecoveryStrategy.RETRY:
            return await self._execute_retry_strategy(
                error, operation, retry_func, pattern, context
            )
        elif pattern.strategy == RecoveryStrategy.CIRCUIT_BREAKER:
            return await self._execute_circuit_breaker_strategy(
                error, operation, retry_func, pattern, context
            )
        elif pattern.strategy == RecoveryStrategy.FALLBACK:
            return await self._execute_fallback_strategy(
                error, operation, fallback_func, pattern, context
            )
        elif pattern.strategy == RecoveryStrategy.DEGRADE:
            return await self._execute_degraded_strategy(
                error, operation, pattern, context
            )
        elif pattern.strategy == RecoveryStrategy.EMERGENCY:
            return await self._execute_emergency_strategy(
                error, operation, pattern, context
            )
        else:
            # Unknown strategy, default to simple retry
            return await self._execute_retry_strategy(
                error, operation, retry_func, pattern, context
            )
    
    async def _execute_retry_strategy(
        self, 
        error: Exception, 
        operation: str, 
        retry_func: Optional[Callable],
        pattern: ErrorPattern,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute retry strategy with exponential backoff."""
        if not retry_func:
            return {"success": False, "error": "No retry function provided"}
        
        retry_count = self.error_counts.get(operation, 0)
        
        if retry_count >= pattern.max_retries:
            self.logger.error(f"Max retries exceeded for {operation}")
            return {
                "success": False, 
                "error": f"Max retries ({pattern.max_retries}) exceeded",
                "original_error": str(error)
            }
        
        # Calculate backoff delay
        delay = min(
            pattern.backoff_factor ** retry_count + random.uniform(0, 1),
            pattern.max_backoff
        )
        
        self.logger.warning(f"Retrying {operation} in {delay:.2f}s (attempt {retry_count + 1})")
        await asyncio.sleep(delay)
        
        try:
            result = await retry_func() if asyncio.iscoroutinefunction(retry_func) else retry_func()
            
            # Reset error count on success
            self.error_counts[operation] = 0
            self.logger.info(f"Retry successful for {operation}")
            
            return {"success": True, "data": result, "retries": retry_count + 1}
            
        except Exception as retry_error:
            self.error_counts[operation] = retry_count + 1
            return await self.handle_error(retry_error, operation, retry_func, None, context)
    
    async def _execute_circuit_breaker_strategy(
        self, 
        error: Exception, 
        operation: str, 
        retry_func: Optional[Callable],
        pattern: ErrorPattern,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute circuit breaker strategy."""
        breaker_key = f"{operation}_circuit"
        
        # Initialize circuit breaker if not exists
        if breaker_key not in self.circuit_breakers:
            self.circuit_breakers[breaker_key] = {
                "state": "closed",  # closed, open, half_open
                "failure_count": 0,
                "last_failure": 0,
                "success_count": 0
            }
        
        breaker = self.circuit_breakers[breaker_key]
        current_time = time.time()
        
        # Check circuit breaker state
        if breaker["state"] == "open":
            # Check if timeout period has passed
            if current_time - breaker["last_failure"] > pattern.circuit_breaker_timeout:
                breaker["state"] = "half_open"
                self.logger.info(f"Circuit breaker for {operation} entering half-open state")
            else:
                self.logger.warning(f"Circuit breaker for {operation} is open")
                return {
                    "success": False, 
                    "error": "Circuit breaker is open",
                    "retry_after": pattern.circuit_breaker_timeout - (current_time - breaker["last_failure"])
                }
        
        # Try operation
        if retry_func and breaker["state"] in ["closed", "half_open"]:
            try:
                result = await retry_func() if asyncio.iscoroutinefunction(retry_func) else retry_func()
                
                # Success - reset circuit breaker
                breaker["failure_count"] = 0
                breaker["success_count"] += 1
                breaker["state"] = "closed"
                
                self.logger.info(f"Circuit breaker for {operation} reset to closed state")
                return {"success": True, "data": result}
                
            except Exception as retry_error:
                breaker["failure_count"] += 1
                breaker["last_failure"] = current_time
                
                # Check if should open circuit
                if breaker["failure_count"] >= pattern.circuit_breaker_threshold:
                    breaker["state"] = "open"
                    self.logger.error(f"Circuit breaker for {operation} opened due to {breaker['failure_count']} failures")
                
                return await self.handle_error(retry_error, operation, None, None, context)
        
        return {
            "success": False, 
            "error": "Circuit breaker strategy failed",
            "original_error": str(error)
        }
    
    async def _execute_fallback_strategy(
        self, 
        error: Exception, 
        operation: str, 
        fallback_func: Optional[Callable],
        pattern: ErrorPattern,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute fallback strategy."""
        if not fallback_func and operation not in self.fallback_services:
            self.logger.error(f"No fallback available for {operation}")
            return {
                "success": False, 
                "error": "No fallback service available",
                "original_error": str(error)
            }
        
        # Use provided fallback or registered fallback service
        fallback = fallback_func or self.fallback_services.get(operation)
        
        try:
            self.logger.info(f"Executing fallback for {operation}")
            result = await fallback(**context) if asyncio.iscoroutinefunction(fallback) else fallback(**context)
            
            return {
                "success": True, 
                "data": result, 
                "fallback": True,
                "original_error": str(error)
            }
            
        except Exception as fallback_error:
            self.logger.error(f"Fallback failed for {operation}: {fallback_error}")
            return {
                "success": False, 
                "error": "Fallback service failed",
                "original_error": str(error),
                "fallback_error": str(fallback_error)
            }
    
    async def _execute_degraded_strategy(
        self, 
        error: Exception, 
        operation: str, 
        pattern: ErrorPattern,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute degraded service strategy."""
        self.logger.warning(f"Entering degraded mode for {operation}")
        
        # Return minimal/cached data or reduced functionality
        degraded_data = {
            "status": "degraded",
            "message": "Service operating in degraded mode due to errors",
            "original_error": str(error),
            "reduced_functionality": True
        }
        
        # Add any cached or minimal data if available
        if "cached_data" in context:
            degraded_data["data"] = context["cached_data"]
        
        return {
            "success": True,
            "data": degraded_data,
            "degraded": True
        }
    
    async def _execute_emergency_strategy(
        self, 
        error: Exception, 
        operation: str, 
        pattern: ErrorPattern,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute emergency recovery strategy."""
        self.logger.critical(f"EMERGENCY: Critical error in {operation}")
        self.emergency_mode = True
        
        # Log emergency details
        self.logger.critical(f"Emergency mode activated due to: {error}", extra={
            "details": {
                "operation": operation,
                "error_type": type(error).__name__,
                "context": context,
                "timestamp": time.time()
            }
        })
        
        return {
            "success": False,
            "error": "System in emergency mode",
            "emergency": True,
            "original_error": str(error)
        }
    
    def _update_error_stats(self, operation: str, error: Exception, pattern: ErrorPattern):
        """Update error statistics for monitoring."""
        current_time = time.time()
        
        if operation not in self.recovery_stats:
            self.recovery_stats[operation] = {
                "total_errors": 0,
                "error_types": {},
                "last_error": None,
                "recovery_attempts": 0,
                "successful_recoveries": 0
            }
        
        stats = self.recovery_stats[operation]
        stats["total_errors"] += 1
        stats["last_error"] = current_time
        
        error_type = type(error).__name__
        stats["error_types"][error_type] = stats["error_types"].get(error_type, 0) + 1
    
    def register_fallback_service(self, operation: str, fallback_func: Callable):
        """Register a fallback service for an operation."""
        self.fallback_services[operation] = fallback_func
        self.logger.info(f"Registered fallback service for {operation}")
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get comprehensive error and recovery statistics."""
        return {
            "error_counts": self.error_counts.copy(),
            "circuit_breakers": self.circuit_breakers.copy(),
            "recovery_stats": self.recovery_stats.copy(),
            "emergency_mode": self.emergency_mode,
            "registered_fallbacks": list(self.fallback_services.keys())
        }
    
    def reset_error_counts(self, operation: Optional[str] = None):
        """Reset error counts for an operation or all operations."""
        if operation:
            self.error_counts[operation] = 0
            self.logger.info(f"Reset error count for {operation}")
        else:
            self.error_counts.clear()
            self.circuit_breakers.clear()
            self.emergency_mode = False
            self.logger.info("Reset all error counts and circuit breakers")
    
    @asynccontextmanager
    async def managed_operation(
        self, 
        operation: str,
        retry_func: Optional[Callable] = None,
        fallback_func: Optional[Callable] = None,
        context: Dict[str, Any] = None
    ):
        """
        Context manager for automatic error recovery.
        
        Usage:
            async with error_manager.managed_operation("get_alerts") as manager:
                result = await some_operation()
                manager.set_result(result)
        """
        if context is None:
            context = {}
        
        class OperationManager:
            def __init__(self, recovery_manager, op_name):
                self.recovery_manager = recovery_manager
                self.operation = op_name
                self.result = None
                self.error = None
            
            def set_result(self, result):
                self.result = result
            
            def set_error(self, error):
                self.error = error
        
        manager = OperationManager(self, operation)
        
        try:
            yield manager
            
            # If error was set but not handled, handle it now
            if manager.error and manager.result is None:
                recovery_result = await self.handle_error(
                    manager.error, operation, retry_func, fallback_func, context
                )
                manager.result = recovery_result
                
        except Exception as e:
            recovery_result = await self.handle_error(
                e, operation, retry_func, fallback_func, context
            )
            manager.result = recovery_result


# Global error recovery manager instance
error_recovery_manager = ErrorRecoveryManager()


# Convenience functions
async def handle_error_with_recovery(
    error: Exception,
    operation: str,
    retry_func: Optional[Callable] = None,
    fallback_func: Optional[Callable] = None,
    context: Dict[str, Any] = None
) -> Dict[str, Any]:
    """Handle an error with automatic recovery."""
    return await error_recovery_manager.handle_error(
        error, operation, retry_func, fallback_func, context
    )


def register_fallback(operation: str, fallback_func: Callable):
    """Register a fallback service."""
    error_recovery_manager.register_fallback_service(operation, fallback_func)


if __name__ == "__main__":
    # Test the error recovery system
    async def test_recovery():
        print("🔧 Testing error recovery system...")
        
        # Test retry strategy
        async def failing_operation():
            raise ConnectionError("Connection failed")
        
        async def retry_operation():
            print("Retrying operation...")
            return {"status": "success"}
        
        result = await error_recovery_manager.handle_error(
            ConnectionError("Test error"),
            "test_operation",
            retry_func=retry_operation
        )
        
        print(f"Recovery result: {result}")
        
        # Get statistics
        stats = error_recovery_manager.get_error_statistics()
        print(f"Error statistics: {stats}")
    
    asyncio.run(test_recovery())