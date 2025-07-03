#!/usr/bin/env python3
"""
Production-grade health checks and self-diagnostics for MCP server.
"""

import asyncio
import time
import psutil
import json
import logging
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import subprocess
import sys
from pathlib import Path

from .config import WazuhConfig
from .monitoring.performance_monitor import performance_monitor
from .resilience.error_recovery import error_recovery_manager


class HealthStatus(Enum):
    """Health check status levels."""
    HEALTHY = "healthy"
    WARNING = "warning" 
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a health check."""
    name: str
    status: HealthStatus
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    duration_ms: float = 0.0
    recommendations: List[str] = field(default_factory=list)


class HealthChecker:
    """Comprehensive health checking and diagnostics system."""
    
    def __init__(self, config: WazuhConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.health_checks: Dict[str, Callable] = {}
        self.last_results: Dict[str, HealthCheckResult] = {}
        
        # Register default health checks
        self._register_default_checks()
    
    def _register_default_checks(self):
        """Register default health checks."""
        self.health_checks.update({
            'system_resources': self._check_system_resources,
            'python_environment': self._check_python_environment,
            'dependencies': self._check_dependencies,
            'wazuh_connectivity': self._check_wazuh_connectivity,
            'configuration': self._check_configuration,
            'performance': self._check_performance,
            'error_rates': self._check_error_rates,
            'disk_space': self._check_disk_space,
            'memory_usage': self._check_memory_usage,
            'network_connectivity': self._check_network_connectivity
        })
    
    def register_health_check(self, name: str, check_function: Callable):
        """Register a custom health check."""
        self.health_checks[name] = check_function
    
    async def run_all_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all registered health checks."""
        results = {}
        
        for name, check_func in self.health_checks.items():
            try:
                start_time = time.time()
                
                if asyncio.iscoroutinefunction(check_func):
                    result = await check_func()
                else:
                    result = check_func()
                
                duration_ms = (time.time() - start_time) * 1000
                result.duration_ms = duration_ms
                
                results[name] = result
                self.last_results[name] = result
                
                self.logger.info(f"Health check '{name}' completed: {result.status.value}")
                
            except Exception as e:
                error_result = HealthCheckResult(
                    name=name,
                    status=HealthStatus.CRITICAL,
                    message=f"Health check failed: {str(e)}",
                    details={'error': str(e), 'error_type': type(e).__name__}
                )
                results[name] = error_result
                self.last_results[name] = error_result
                
                self.logger.error(f"Health check '{name}' failed: {e}")
        
        return results
    
    def _check_system_resources(self) -> HealthCheckResult:
        """Check system resource utilization."""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            details = {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_available_gb': memory.available / (1024**3),
                'disk_percent': disk.percent,
                'disk_free_gb': disk.free / (1024**3)
            }
            
            # Determine status based on thresholds
            status = HealthStatus.HEALTHY
            recommendations = []
            
            if cpu_percent > 90:
                status = HealthStatus.CRITICAL
                recommendations.append("CPU usage is critically high")
            elif cpu_percent > 80:
                status = HealthStatus.WARNING
                recommendations.append("CPU usage is high")
            
            if memory.percent > 95:
                status = HealthStatus.CRITICAL
                recommendations.append("Memory usage is critically high")
            elif memory.percent > 85:
                status = HealthStatus.WARNING
                recommendations.append("Memory usage is high")
            
            message = f"CPU: {cpu_percent:.1f}%, Memory: {memory.percent:.1f}%, Disk: {disk.percent:.1f}%"
            
            return HealthCheckResult(
                name="system_resources",
                status=status,
                message=message,
                details=details,
                recommendations=recommendations
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="system_resources",
                status=HealthStatus.CRITICAL,
                message=f"Failed to check system resources: {str(e)}"
            )
    
    def _check_python_environment(self) -> HealthCheckResult:
        """Check Python environment and version."""
        try:
            python_version = sys.version_info
            
            details = {
                'python_version': f"{python_version.major}.{python_version.minor}.{python_version.micro}",
                'executable': sys.executable,
                'platform': sys.platform,
                'prefix': sys.prefix
            }
            
            # Check minimum Python version
            if python_version < (3, 8):
                return HealthCheckResult(
                    name="python_environment",
                    status=HealthStatus.CRITICAL,
                    message=f"Python version {details['python_version']} is below minimum requirement (3.8)",
                    details=details,
                    recommendations=["Upgrade to Python 3.8 or later"]
                )
            
            return HealthCheckResult(
                name="python_environment",
                status=HealthStatus.HEALTHY,
                message=f"Python {details['python_version']} environment is healthy",
                details=details
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="python_environment",
                status=HealthStatus.CRITICAL,
                message=f"Failed to check Python environment: {str(e)}"
            )
    
    def _check_dependencies(self) -> HealthCheckResult:
        """Check that all required dependencies are available."""
        try:
            required_modules = [
                'mcp', 'aiohttp', 'urllib3', 'pydantic', 
                'python_dateutil', 'dotenv', 'psutil'
            ]
            
            missing_modules = []
            installed_versions = {}
            
            for module in required_modules:
                try:
                    if module == 'python_dateutil':
                        import dateutil
                        installed_versions[module] = getattr(dateutil, '__version__', 'unknown')
                    elif module == 'dotenv':
                        import dotenv
                        installed_versions[module] = getattr(dotenv, '__version__', 'unknown')
                    else:
                        imported = __import__(module)
                        installed_versions[module] = getattr(imported, '__version__', 'unknown')
                except ImportError:
                    missing_modules.append(module)
            
            details = {
                'installed_versions': installed_versions,
                'missing_modules': missing_modules
            }
            
            if missing_modules:
                return HealthCheckResult(
                    name="dependencies",
                    status=HealthStatus.CRITICAL,
                    message=f"Missing required modules: {', '.join(missing_modules)}",
                    details=details,
                    recommendations=[f"Install missing modules: pip install {' '.join(missing_modules)}"]
                )
            
            return HealthCheckResult(
                name="dependencies",
                status=HealthStatus.HEALTHY,
                message="All required dependencies are available",
                details=details
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="dependencies",
                status=HealthStatus.CRITICAL,
                message=f"Failed to check dependencies: {str(e)}"
            )
    
    async def _check_wazuh_connectivity(self) -> HealthCheckResult:
        """Check connectivity to Wazuh server."""
        try:
            from .api.wazuh_client_manager import WazuhClientManager
            
            async with WazuhClientManager(self.config) as client:
                start_time = time.time()
                health_data = await client.health_check()
                response_time = (time.time() - start_time) * 1000
                
                details = {
                    'server_url': self.config.base_url,
                    'response_time_ms': response_time,
                    'health_data': health_data
                }
                
                if health_data.get('status') == 'healthy':
                    status = HealthStatus.HEALTHY
                    message = f"Wazuh connectivity healthy (response: {response_time:.1f}ms)"
                else:
                    status = HealthStatus.WARNING
                    message = f"Wazuh server responded but status unclear"
                
                return HealthCheckResult(
                    name="wazuh_connectivity",
                    status=status,
                    message=message,
                    details=details
                )
                
        except Exception as e:
            return HealthCheckResult(
                name="wazuh_connectivity",
                status=HealthStatus.CRITICAL,
                message=f"Cannot connect to Wazuh server: {str(e)}",
                details={'error': str(e)},
                recommendations=[
                    "Check network connectivity",
                    "Verify Wazuh server is running",
                    "Check credentials and permissions"
                ]
            )
    
    def _check_configuration(self) -> HealthCheckResult:
        """Check configuration validity."""
        try:
            details = {
                'host': self.config.host,
                'port': self.config.port,
                'api_version': self.config.api_version,
                'verify_ssl': self.config.verify_ssl,
                'log_level': self.config.log_level
            }
            
            recommendations = []
            status = HealthStatus.HEALTHY
            
            # Check for insecure configurations
            if not self.config.verify_ssl:
                status = HealthStatus.WARNING
                recommendations.append("SSL verification is disabled - consider enabling for security")
            
            if self.config.debug:
                recommendations.append("Debug mode is enabled - disable in production")
            
            return HealthCheckResult(
                name="configuration",
                status=status,
                message="Configuration is valid",
                details=details,
                recommendations=recommendations
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="configuration",
                status=HealthStatus.CRITICAL,
                message=f"Configuration validation failed: {str(e)}"
            )
    
    def _check_performance(self) -> HealthCheckResult:
        """Check performance metrics."""
        try:
            perf_summary = performance_monitor.get_performance_summary()
            
            details = {
                'active_metrics': len(perf_summary.get('application_metrics', {})),
                'timer_stats': len(perf_summary.get('timer_stats', {})),
                'alerts_count': len(perf_summary.get('alerts', []))
            }
            
            # Check for performance alerts
            alerts = perf_summary.get('alerts', [])
            status = HealthStatus.HEALTHY
            recommendations = []
            
            if alerts:
                critical_alerts = [a for a in alerts if a.get('severity') == 'critical']
                if critical_alerts:
                    status = HealthStatus.CRITICAL
                    recommendations.append("Critical performance issues detected")
                else:
                    status = HealthStatus.WARNING
                    recommendations.append("Performance warnings detected")
            
            message = f"Performance monitoring active with {details['active_metrics']} metrics"
            
            return HealthCheckResult(
                name="performance",
                status=status,
                message=message,
                details=details,
                recommendations=recommendations
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="performance",
                status=HealthStatus.WARNING,
                message=f"Performance check failed: {str(e)}"
            )
    
    def _check_error_rates(self) -> HealthCheckResult:
        """Check error rates and recovery status."""
        try:
            error_stats = error_recovery_manager.get_error_statistics()
            
            # Check circuit breaker status
            status = HealthStatus.HEALTHY
            recommendations = []
            
            circuit_breakers = error_stats.get('circuit_breakers', {})
            for name, breaker_info in circuit_breakers.items():
                if breaker_info['state'] == 'open':
                    status = HealthStatus.CRITICAL
                    recommendations.append(f"Circuit breaker '{name}' is open")
                elif breaker_info['state'] == 'half_open':
                    status = HealthStatus.WARNING
                    recommendations.append(f"Circuit breaker '{name}' is testing recovery")
            
            message = f"Error recovery system operational with {len(circuit_breakers)} circuit breakers"
            
            return HealthCheckResult(
                name="error_rates",
                status=status,
                message=message,
                details=error_stats,
                recommendations=recommendations
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="error_rates",
                status=HealthStatus.WARNING,
                message=f"Error rate check failed: {str(e)}"
            )
    
    def _check_disk_space(self) -> HealthCheckResult:
        """Check available disk space."""
        try:
            disk_usage = psutil.disk_usage('/')
            
            details = {
                'total_gb': disk_usage.total / (1024**3),
                'used_gb': disk_usage.used / (1024**3),
                'free_gb': disk_usage.free / (1024**3),
                'percent_used': (disk_usage.used / disk_usage.total) * 100
            }
            
            percent_used = details['percent_used']
            
            if percent_used > 95:
                status = HealthStatus.CRITICAL
                recommendations = ["Disk space is critically low - immediate action required"]
            elif percent_used > 90:
                status = HealthStatus.WARNING
                recommendations = ["Disk space is running low - consider cleanup"]
            else:
                status = HealthStatus.HEALTHY
                recommendations = []
            
            message = f"Disk usage: {percent_used:.1f}% ({details['free_gb']:.1f}GB free)"
            
            return HealthCheckResult(
                name="disk_space",
                status=status,
                message=message,
                details=details,
                recommendations=recommendations
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="disk_space",
                status=HealthStatus.CRITICAL,
                message=f"Failed to check disk space: {str(e)}"
            )
    
    def _check_memory_usage(self) -> HealthCheckResult:
        """Check memory usage patterns."""
        try:
            memory = psutil.virtual_memory()
            process = psutil.Process()
            process_memory = process.memory_info()
            
            details = {
                'system_memory_percent': memory.percent,
                'system_available_gb': memory.available / (1024**3),
                'process_memory_mb': process_memory.rss / (1024**2),
                'process_virtual_mb': process_memory.vms / (1024**2)
            }
            
            status = HealthStatus.HEALTHY
            recommendations = []
            
            # Check system memory
            if memory.percent > 95:
                status = HealthStatus.CRITICAL
                recommendations.append("System memory critically low")
            elif memory.percent > 85:
                status = HealthStatus.WARNING
                recommendations.append("System memory usage high")
            
            message = f"Memory: {memory.percent:.1f}% system, {details['process_memory_mb']:.1f}MB process"
            
            return HealthCheckResult(
                name="memory_usage",
                status=status,
                message=message,
                details=details,
                recommendations=recommendations
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="memory_usage",
                status=HealthStatus.CRITICAL,
                message=f"Failed to check memory usage: {str(e)}"
            )
    
    async def _check_network_connectivity(self) -> HealthCheckResult:
        """Check network connectivity to external services."""
        try:
            import aiohttp
            
            test_urls = [
                ('dns', 'https://1.1.1.1'),
                ('google', 'https://www.google.com')
            ]
            
            results = {}
            overall_status = HealthStatus.HEALTHY
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                for name, url in test_urls:
                    try:
                        start_time = time.time()
                        async with session.get(url) as response:
                            response_time = (time.time() - start_time) * 1000
                            results[name] = {
                                'status': 'ok' if response.status < 400 else 'error',
                                'status_code': response.status,
                                'response_time_ms': response_time
                            }
                    except Exception as e:
                        results[name] = {
                            'status': 'error',
                            'error': str(e)
                        }
                        overall_status = HealthStatus.WARNING
            
            message = f"Network connectivity: {len([r for r in results.values() if r['status'] == 'ok'])}/{len(test_urls)} tests passed"
            
            return HealthCheckResult(
                name="network_connectivity",
                status=overall_status,
                message=message,
                details=results
            )
            
        except Exception as e:
            return HealthCheckResult(
                name="network_connectivity",
                status=HealthStatus.CRITICAL,
                message=f"Failed to check network connectivity: {str(e)}"
            )
    
    def get_overall_health(self) -> Dict[str, Any]:
        """Get overall system health summary."""
        if not self.last_results:
            return {
                'status': HealthStatus.UNKNOWN.value,
                'message': 'No health checks have been run',
                'timestamp': datetime.utcnow().isoformat()
            }
        
        # Determine overall status
        statuses = [result.status for result in self.last_results.values()]
        
        if HealthStatus.CRITICAL in statuses:
            overall_status = HealthStatus.CRITICAL
        elif HealthStatus.WARNING in statuses:
            overall_status = HealthStatus.WARNING
        else:
            overall_status = HealthStatus.HEALTHY
        
        # Count status types
        status_counts = {
            'healthy': sum(1 for s in statuses if s == HealthStatus.HEALTHY),
            'warning': sum(1 for s in statuses if s == HealthStatus.WARNING),
            'critical': sum(1 for s in statuses if s == HealthStatus.CRITICAL),
            'unknown': sum(1 for s in statuses if s == HealthStatus.UNKNOWN)
        }
        
        return {
            'status': overall_status.value,
            'message': f"Overall system health: {overall_status.value}",
            'check_counts': status_counts,
            'total_checks': len(self.last_results),
            'timestamp': datetime.utcnow().isoformat()
        }


# Global health checker (will be initialized when config is available)
health_checker: Optional[HealthChecker] = None


def initialize_health_checker(config: WazuhConfig) -> HealthChecker:
    """Initialize global health checker with configuration."""
    global health_checker
    health_checker = HealthChecker(config)
    return health_checker


async def run_health_checks() -> Dict[str, Any]:
    """Run all health checks and return results."""
    if health_checker is None:
        raise RuntimeError("Health checker not initialized")
    
    results = await health_checker.run_all_checks()
    return {
        'individual_results': results,
        'overall_health': health_checker.get_overall_health()
    }


# Legacy compatibility function
async def health_check():
    """Legacy health check function for backward compatibility."""
    try:
        from .config import WazuhConfig
        from .api.wazuh_client_manager import WazuhClientManager
        
        # Test configuration loading
        config = WazuhConfig.from_env()
        
        # Test API client creation and health
        async with WazuhClientManager(config) as client:
            health_data = await client.health_check()
            
            if health_data.get("status") == "healthy":
                print("Health check passed")
                return 0
            else:
                print(f"Health check failed: {health_data}")
                return 1
                
    except Exception as e:
        print(f"Health check error: {str(e)}")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(health_check())
    sys.exit(exit_code)