"""
Production-grade performance monitoring and optimization for DXT extension.
"""

import time
import psutil
import asyncio
import threading
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics
import logging
import json
from enum import Enum


class MetricType(Enum):
    """Types of performance metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class PerformanceMetric:
    """Performance metric data structure."""
    name: str
    value: float
    metric_type: MetricType
    timestamp: datetime = field(default_factory=datetime.utcnow)
    tags: Dict[str, str] = field(default_factory=dict)
    unit: str = "count"


@dataclass
class SystemMetrics:
    """System resource metrics."""
    cpu_percent: float
    memory_percent: float
    memory_available: int
    disk_usage_percent: float
    network_io: Dict[str, int]
    process_count: int
    load_average: Optional[List[float]] = None


class PerformanceMonitor:
    """Production-grade performance monitoring system."""
    
    def __init__(self, max_history: int = 1000):
        self.logger = logging.getLogger(__name__)
        self.max_history = max_history
        
        # Metric storage
        self.metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_history))
        self.timers: Dict[str, List[float]] = defaultdict(list)
        
        # System monitoring
        self.system_metrics_history: deque = deque(maxlen=max_history)
        self.monitoring_enabled = True
        self.monitoring_interval = 30  # seconds
        
        # Performance thresholds
        self.thresholds = {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'disk_usage_percent': 90.0,
            'response_time_ms': 5000.0,
            'error_rate_percent': 5.0
        }
        
        # Alert callbacks
        self.alert_callbacks: List[Callable] = []
        
        # Start background monitoring
        self._start_monitoring()
    
    def record_metric(self, name: str, value: float, metric_type: MetricType = MetricType.GAUGE, 
                     tags: Optional[Dict[str, str]] = None, unit: str = "count"):
        """Record a performance metric."""
        metric = PerformanceMetric(
            name=name,
            value=value,
            metric_type=metric_type,
            tags=tags or {},
            unit=unit
        )
        
        self.metrics[name].append(metric)
        
        # Check thresholds
        self._check_threshold(name, value)
    
    def start_timer(self, name: str) -> 'TimerContext':
        """Start a performance timer."""
        return TimerContext(self, name)
    
    def record_timer(self, name: str, duration_ms: float, tags: Optional[Dict[str, str]] = None):
        """Record timer duration."""
        self.timers[name].append(duration_ms)
        if len(self.timers[name]) > self.max_history:
            self.timers[name] = self.timers[name][-self.max_history:]
        
        self.record_metric(
            f"{name}_duration",
            duration_ms,
            MetricType.TIMER,
            tags,
            "milliseconds"
        )
        
        # Check response time threshold
        self._check_threshold(f"{name}_duration", duration_ms)
    
    def increment_counter(self, name: str, value: float = 1.0, tags: Optional[Dict[str, str]] = None):
        """Increment a counter metric."""
        self.record_metric(name, value, MetricType.COUNTER, tags)
    
    def set_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None, unit: str = "count"):
        """Set a gauge metric."""
        self.record_metric(name, value, MetricType.GAUGE, tags, unit)
    
    def get_metric_stats(self, name: str, time_window: Optional[timedelta] = None) -> Dict[str, Any]:
        """Get statistical summary of a metric."""
        if name not in self.metrics:
            return {}
        
        metrics = list(self.metrics[name])
        
        if time_window:
            cutoff_time = datetime.utcnow() - time_window
            metrics = [m for m in metrics if m.timestamp >= cutoff_time]
        
        if not metrics:
            return {}
        
        values = [m.value for m in metrics]
        
        return {
            'count': len(values),
            'min': min(values),
            'max': max(values),
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'std_dev': statistics.stdev(values) if len(values) > 1 else 0,
            'latest': values[-1] if values else None,
            'time_window': str(time_window) if time_window else 'all_time'
        }
    
    def get_timer_stats(self, name: str) -> Dict[str, Any]:
        """Get timer statistics."""
        if name not in self.timers or not self.timers[name]:
            return {}
        
        durations = self.timers[name]
        
        return {
            'count': len(durations),
            'min_ms': min(durations),
            'max_ms': max(durations),
            'mean_ms': statistics.mean(durations),
            'median_ms': statistics.median(durations),
            'p95_ms': self._percentile(durations, 95),
            'p99_ms': self._percentile(durations, 99),
            'std_dev_ms': statistics.stdev(durations) if len(durations) > 1 else 0
        }
    
    def collect_system_metrics(self) -> SystemMetrics:
        """Collect current system metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Disk usage (root partition)
            disk = psutil.disk_usage('/')
            
            # Network I/O
            network = psutil.net_io_counters()
            network_io = {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            }
            
            # Process count
            process_count = len(psutil.pids())
            
            # Load average (Unix-like systems)
            load_avg = None
            try:
                load_avg = list(psutil.getloadavg())
            except AttributeError:
                # Windows doesn't have load average
                pass
            
            metrics = SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_available=memory.available,
                disk_usage_percent=disk.percent,
                network_io=network_io,
                process_count=process_count,
                load_average=load_avg
            )
            
            self.system_metrics_history.append(metrics)
            
            # Record as individual metrics
            self.set_gauge('system_cpu_percent', cpu_percent, unit='percent')
            self.set_gauge('system_memory_percent', memory.percent, unit='percent')
            self.set_gauge('system_disk_percent', disk.percent, unit='percent')
            self.set_gauge('system_memory_available', memory.available, unit='bytes')
            self.set_gauge('system_process_count', process_count)
            
            if load_avg:
                self.set_gauge('system_load_1m', load_avg[0])
                self.set_gauge('system_load_5m', load_avg[1])
                self.set_gauge('system_load_15m', load_avg[2])
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
            return SystemMetrics(0, 0, 0, 0, {}, 0)
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        summary = {
            'timestamp': datetime.utcnow().isoformat(),
            'monitoring_enabled': self.monitoring_enabled,
            'system_metrics': {},
            'application_metrics': {},
            'timer_stats': {},
            'alerts': []
        }
        
        # Latest system metrics
        if self.system_metrics_history:
            latest_system = self.system_metrics_history[-1]
            summary['system_metrics'] = {
                'cpu_percent': latest_system.cpu_percent,
                'memory_percent': latest_system.memory_percent,
                'memory_available_mb': latest_system.memory_available // (1024 * 1024),
                'disk_usage_percent': latest_system.disk_usage_percent,
                'process_count': latest_system.process_count,
                'load_average': latest_system.load_average
            }
        
        # Application metrics summary
        key_metrics = [
            'api_requests_total', 'api_errors_total', 'api_response_time',
            'wazuh_api_calls', 'wazuh_api_errors', 'mcp_tool_calls'
        ]
        
        for metric_name in key_metrics:
            stats = self.get_metric_stats(metric_name, timedelta(hours=1))
            if stats:
                summary['application_metrics'][metric_name] = stats
        
        # Timer statistics
        for timer_name in self.timers.keys():
            stats = self.get_timer_stats(timer_name)
            if stats:
                summary['timer_stats'][timer_name] = stats
        
        # Check for active alerts
        summary['alerts'] = self._get_active_alerts()
        
        return summary
    
    def add_alert_callback(self, callback: Callable[[str, str, float], None]):
        """Add callback for performance alerts."""
        self.alert_callbacks.append(callback)
    
    def _check_threshold(self, metric_name: str, value: float):
        """Check if metric exceeds threshold and trigger alerts."""
        threshold_key = metric_name.replace('_duration', '_ms')
        
        if threshold_key in self.thresholds:
            threshold = self.thresholds[threshold_key]
            
            if value > threshold:
                alert_message = f"Metric '{metric_name}' ({value}) exceeded threshold ({threshold})"
                self.logger.warning(alert_message)
                
                # Trigger alert callbacks
                for callback in self.alert_callbacks:
                    try:
                        callback(metric_name, alert_message, value)
                    except Exception as e:
                        self.logger.error(f"Error in alert callback: {e}")
    
    def _get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get list of active performance alerts."""
        alerts = []
        current_time = datetime.utcnow()
        
        # Check recent metrics against thresholds
        for metric_name, threshold in self.thresholds.items():
            recent_metrics = [
                m for m in self.metrics.get(metric_name, [])
                if (current_time - m.timestamp).total_seconds() < 300  # Last 5 minutes
            ]
            
            if recent_metrics:
                latest_value = recent_metrics[-1].value
                if latest_value > threshold:
                    alerts.append({
                        'metric': metric_name,
                        'value': latest_value,
                        'threshold': threshold,
                        'timestamp': recent_metrics[-1].timestamp.isoformat(),
                        'severity': 'warning' if latest_value < threshold * 1.2 else 'critical'
                    })
        
        return alerts
    
    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile value."""
        if not data:
            return 0.0
        
        sorted_data = sorted(data)
        index = (percentile / 100.0) * (len(sorted_data) - 1)
        
        if index.is_integer():
            return sorted_data[int(index)]
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return lower + (upper - lower) * (index - int(index))
    
    def _start_monitoring(self):
        """Start background system monitoring."""
        def monitor_loop():
            while self.monitoring_enabled:
                try:
                    self.collect_system_metrics()
                    time.sleep(self.monitoring_interval)
                except Exception as e:
                    self.logger.error(f"Error in monitoring loop: {e}")
                    time.sleep(self.monitoring_interval)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        self.monitoring_enabled = False
    
    def export_metrics(self, format_type: str = 'json') -> str:
        """Export metrics in specified format."""
        if format_type == 'json':
            return json.dumps(self.get_performance_summary(), indent=2)
        elif format_type == 'prometheus':
            return self._export_prometheus_format()
        else:
            raise ValueError(f"Unsupported export format: {format_type}")
    
    def _export_prometheus_format(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        
        for metric_name, metric_deque in self.metrics.items():
            if not metric_deque:
                continue
            
            latest_metric = metric_deque[-1]
            
            # Convert metric name to Prometheus format
            prom_name = metric_name.replace('-', '_').lower()
            
            # Add help and type
            lines.append(f"# HELP {prom_name} {latest_metric.metric_type.value}")
            lines.append(f"# TYPE {prom_name} {latest_metric.metric_type.value}")
            
            # Add metric value with tags
            tags_str = ""
            if latest_metric.tags:
                tag_pairs = [f'{k}="{v}"' for k, v in latest_metric.tags.items()]
                tags_str = "{" + ",".join(tag_pairs) + "}"
            
            lines.append(f"{prom_name}{tags_str} {latest_metric.value}")
        
        return "\n".join(lines)


class TimerContext:
    """Context manager for timing operations."""
    
    def __init__(self, monitor: PerformanceMonitor, name: str, tags: Optional[Dict[str, str]] = None):
        self.monitor = monitor
        self.name = name
        self.tags = tags or {}
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            duration_ms = (time.time() - self.start_time) * 1000
            self.monitor.record_timer(self.name, duration_ms, self.tags)


# Global performance monitor instance
performance_monitor = PerformanceMonitor()


def monitor_performance(operation_name: str, tags: Optional[Dict[str, str]] = None):
    """Decorator for monitoring function performance."""
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            with performance_monitor.start_timer(operation_name, tags):
                try:
                    result = await func(*args, **kwargs)
                    performance_monitor.increment_counter(f"{operation_name}_success", tags=tags)
                    return result
                except Exception as e:
                    performance_monitor.increment_counter(f"{operation_name}_error", tags=tags)
                    raise
        
        def sync_wrapper(*args, **kwargs):
            with performance_monitor.start_timer(operation_name, tags):
                try:
                    result = func(*args, **kwargs)
                    performance_monitor.increment_counter(f"{operation_name}_success", tags=tags)
                    return result
                except Exception as e:
                    performance_monitor.increment_counter(f"{operation_name}_error", tags=tags)
                    raise
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator