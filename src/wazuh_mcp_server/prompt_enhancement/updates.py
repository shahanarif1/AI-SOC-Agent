"""
Real-Time Context Updates

Provides real-time context updates during ongoing incidents with intelligent
change detection and prioritized monitoring.
"""

import asyncio
from typing import Dict, Any, Optional, Set, Callable, List, Tuple
from datetime import datetime, timedelta
import logging
import json
import hashlib
from dataclasses import dataclass, asdict


@dataclass
class ContextSnapshot:
    """Snapshot of context data for change detection."""
    timestamp: str
    context_id: str
    context_type: str
    data: Dict[str, Any]
    checksum: str
    
    @classmethod
    def create(cls, context_id: str, context_type: str, data: Dict[str, Any]) -> 'ContextSnapshot':
        """Create a new context snapshot."""
        timestamp = datetime.utcnow().isoformat()
        data_str = json.dumps(data, sort_keys=True)
        checksum = hashlib.md5(data_str.encode()).hexdigest()
        
        return cls(
            timestamp=timestamp,
            context_id=context_id,
            context_type=context_type,
            data=data,
            checksum=checksum
        )


@dataclass 
class ChangeEvent:
    """Represents a detected change in context."""
    change_type: str  # new_alert, status_change, escalation, resolution, data_update
    source: str       # alerts, agent_health, vulnerabilities, etc.
    severity: str     # critical, high, medium, low
    description: str
    old_value: Any
    new_value: Any
    timestamp: str
    metadata: Dict[str, Any]


class ChangeDetector:
    """Detect significant changes in security posture and context."""
    
    def __init__(self):
        """Initialize the change detector."""
        self.logger = logging.getLogger(__name__)
        
        # Define change detection thresholds
        self.alert_thresholds = {
            'new_critical_alerts': 1,    # Any new critical alert is significant
            'new_high_alerts': 3,        # 3+ new high severity alerts
            'alert_rate_increase': 50,   # 50% increase in alert rate
            'new_rule_triggered': True   # Any new rule type
        }
        
        self.health_thresholds = {
            'health_score_drop': 20,     # 20 point drop in health score
            'connection_status_change': True,  # Any connection status change
            'version_mismatch': True     # New version inconsistencies
        }
        
        self.vulnerability_thresholds = {
            'new_critical_vulns': 1,     # Any new critical vulnerability
            'new_exploitable': 1,        # Any new exploitable vulnerability
            'cvss_increase': 2.0         # CVSS score increase by 2.0+
        }
    
    def detect_changes(self, old_context: Dict[str, Any], 
                      new_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detect changes between old and new context.
        
        Args:
            old_context: Previous context state
            new_context: Current context state
            
        Returns:
            Dictionary of detected changes with prioritized events
        """
        timestamp = datetime.utcnow().isoformat()
        
        if not old_context or not new_context:
            return {
                'changes': [], 
                'summary': 'No context data available for comparison',
                'total_changes': 0,
                'critical_changes': 0,
                'high_changes': 0,
                'detection_timestamp': timestamp
            }
        
        changes = []
        
        # Detect changes in each data source
        changes.extend(self._detect_alert_changes(old_context, new_context, timestamp))
        changes.extend(self._detect_health_changes(old_context, new_context, timestamp))
        changes.extend(self._detect_vulnerability_changes(old_context, new_context, timestamp))
        changes.extend(self._detect_process_changes(old_context, new_context, timestamp))
        changes.extend(self._detect_port_changes(old_context, new_context, timestamp))
        
        # Prioritize changes by severity
        changes.sort(key=lambda x: self._get_change_priority(x), reverse=True)
        
        # Generate summary
        summary = self._generate_change_summary(changes)
        
        return {
            'changes': [asdict(change) for change in changes],
            'summary': summary,
            'total_changes': len(changes),
            'critical_changes': len([c for c in changes if c.severity == 'critical']),
            'high_changes': len([c for c in changes if c.severity == 'high']),
            'detection_timestamp': timestamp
        }
    
    def _detect_alert_changes(self, old_context: Dict[str, Any], 
                             new_context: Dict[str, Any], timestamp: str) -> List[ChangeEvent]:
        """Detect changes in alert data."""
        changes = []
        
        # Safely extract alert data with error handling
        try:
            old_alerts = old_context.get('alerts', {})
            if not isinstance(old_alerts, dict):
                old_alerts = {}
            else:
                old_alerts = old_alerts.get('data', {})
                
            new_alerts = new_context.get('alerts', {})
            if not isinstance(new_alerts, dict):
                new_alerts = {}
            else:
                new_alerts = new_alerts.get('data', {})
        except (AttributeError, TypeError):
            return changes
        
        if not old_alerts or not new_alerts:
            return changes
        
        # Check for new critical/high alerts
        old_critical = old_alerts.get('critical_count', 0)
        new_critical = new_alerts.get('critical_count', 0)
        old_high = old_alerts.get('high_severity_count', 0)
        new_high = new_alerts.get('high_severity_count', 0)
        
        if new_critical > old_critical:
            changes.append(ChangeEvent(
                change_type='new_alert',
                source='alerts',
                severity='critical',
                description=f'New critical alerts detected: +{new_critical - old_critical}',
                old_value=old_critical,
                new_value=new_critical,
                timestamp=timestamp,
                metadata={'alert_type': 'critical', 'increase': new_critical - old_critical}
            ))
        
        if new_high > old_high and (new_high - old_high) >= self.alert_thresholds['new_high_alerts']:
            changes.append(ChangeEvent(
                change_type='new_alert',
                source='alerts',
                severity='high',
                description=f'Significant increase in high-severity alerts: +{new_high - old_high}',
                old_value=old_high,
                new_value=new_high,
                timestamp=timestamp,
                metadata={'alert_type': 'high', 'increase': new_high - old_high}
            ))
        
        # Check for alert trend changes
        old_trend = old_alerts.get('alert_trend', 'stable')
        new_trend = new_alerts.get('alert_trend', 'stable')
        
        if old_trend != new_trend and new_trend in ['increasing', 'spiking']:
            severity = 'high' if new_trend == 'spiking' else 'medium'
            changes.append(ChangeEvent(
                change_type='escalation',
                source='alerts',
                severity=severity,
                description=f'Alert trend changed from {old_trend} to {new_trend}',
                old_value=old_trend,
                new_value=new_trend,
                timestamp=timestamp,
                metadata={'trend_change': True}
            ))
        
        # Check for new rule types
        old_rules = set(rule.get('id', '') for rule in old_alerts.get('top_rules', []))
        new_rules = set(rule.get('id', '') for rule in new_alerts.get('top_rules', []))
        
        new_rule_ids = new_rules - old_rules
        if new_rule_ids:
            changes.append(ChangeEvent(
                change_type='new_alert',
                source='alerts',
                severity='medium',
                description=f'New alert rules triggered: {", ".join(new_rule_ids)}',
                old_value=list(old_rules),
                new_value=list(new_rules),
                timestamp=timestamp,
                metadata={'new_rules': list(new_rule_ids)}
            ))
        
        return changes
    
    def _detect_health_changes(self, old_context: Dict[str, Any], 
                              new_context: Dict[str, Any], timestamp: str) -> List[ChangeEvent]:
        """Detect changes in agent health data."""
        changes = []
        
        # Safely extract health data with error handling
        try:
            old_health = old_context.get('agent_health', {})
            if not isinstance(old_health, dict):
                old_health = {}
            else:
                old_health = old_health.get('data', {})
                
            new_health = new_context.get('agent_health', {})
            if not isinstance(new_health, dict):
                new_health = {}
            else:
                new_health = new_health.get('data', {})
        except (AttributeError, TypeError):
            return changes
        
        if not old_health or not new_health:
            return changes
        
        # Check for health score drops
        old_score = old_health.get('health_score', 100)
        new_score = new_health.get('health_score', 100)
        
        if old_score - new_score >= self.health_thresholds['health_score_drop']:
            changes.append(ChangeEvent(
                change_type='status_change',
                source='agent_health',
                severity='high' if old_score - new_score >= 30 else 'medium',
                description=f'Agent health score dropped significantly: {old_score} → {new_score}',
                old_value=old_score,
                new_value=new_score,
                timestamp=timestamp,
                metadata={'score_drop': old_score - new_score}
            ))
        
        # Check for connection quality changes
        old_connection = old_health.get('connection_quality', 'unknown')
        new_connection = new_health.get('connection_quality', 'unknown')
        
        if old_connection != new_connection:
            severity = self._assess_connection_change_severity(old_connection, new_connection)
            changes.append(ChangeEvent(
                change_type='status_change',
                source='agent_health',
                severity=severity,
                description=f'Agent connection quality changed: {old_connection} → {new_connection}',
                old_value=old_connection,
                new_value=new_connection,
                timestamp=timestamp,
                metadata={'connection_change': True}
            ))
        
        return changes
    
    def _detect_vulnerability_changes(self, old_context: Dict[str, Any], 
                                     new_context: Dict[str, Any], timestamp: str) -> List[ChangeEvent]:
        """Detect changes in vulnerability data."""
        changes = []
        
        # Safely extract vulnerability data with error handling
        try:
            old_vulns = old_context.get('vulnerabilities', {})
            if not isinstance(old_vulns, dict):
                old_vulns = {}
            else:
                old_vulns = old_vulns.get('data', {})
                
            new_vulns = new_context.get('vulnerabilities', {})
            if not isinstance(new_vulns, dict):
                new_vulns = {}
            else:
                new_vulns = new_vulns.get('data', {})
        except (AttributeError, TypeError):
            return changes
        
        if not old_vulns or not new_vulns:
            return changes
        
        # Check for new critical vulnerabilities
        old_critical = old_vulns.get('critical_count', 0)
        new_critical = new_vulns.get('critical_count', 0)
        
        if new_critical > old_critical:
            changes.append(ChangeEvent(
                change_type='new_vulnerability',
                source='vulnerabilities',
                severity='critical',
                description=f'New critical vulnerabilities detected: +{new_critical - old_critical}',
                old_value=old_critical,
                new_value=new_critical,
                timestamp=timestamp,
                metadata={'vuln_type': 'critical', 'increase': new_critical - old_critical}
            ))
        
        # Check for new exploitable vulnerabilities
        old_exploitable = old_vulns.get('exploitable_count', 0)
        new_exploitable = new_vulns.get('exploitable_count', 0)
        
        if new_exploitable > old_exploitable:
            changes.append(ChangeEvent(
                change_type='escalation',
                source='vulnerabilities',
                severity='high',
                description=f'New exploitable vulnerabilities found: +{new_exploitable - old_exploitable}',
                old_value=old_exploitable,
                new_value=new_exploitable,
                timestamp=timestamp,
                metadata={'exploitable_increase': new_exploitable - old_exploitable}
            ))
        
        return changes
    
    def _detect_process_changes(self, old_context: Dict[str, Any], 
                               new_context: Dict[str, Any], timestamp: str) -> List[ChangeEvent]:
        """Detect changes in process data."""
        changes = []
        
        # Safely extract process data with error handling
        try:
            old_processes = old_context.get('processes', {})
            if not isinstance(old_processes, dict):
                old_processes = {}
            else:
                old_processes = old_processes.get('data', {})
                
            new_processes = new_context.get('processes', {})
            if not isinstance(new_processes, dict):
                new_processes = {}
            else:
                new_processes = new_processes.get('data', {})
        except (AttributeError, TypeError):
            return changes
        
        if not old_processes or not new_processes:
            return changes
        
        # Check for new suspicious processes
        old_suspicious = old_processes.get('suspicious_count', 0)
        new_suspicious = new_processes.get('suspicious_count', 0)
        
        if new_suspicious > old_suspicious:
            changes.append(ChangeEvent(
                change_type='new_threat',
                source='processes',
                severity='high',
                description=f'New suspicious processes detected: +{new_suspicious - old_suspicious}',
                old_value=old_suspicious,
                new_value=new_suspicious,
                timestamp=timestamp,
                metadata={'process_threat_increase': new_suspicious - old_suspicious}
            ))
        
        return changes
    
    def _detect_port_changes(self, old_context: Dict[str, Any], 
                            new_context: Dict[str, Any], timestamp: str) -> List[ChangeEvent]:
        """Detect changes in port/network data."""
        changes = []
        
        # Safely extract port data with error handling
        try:
            old_ports = old_context.get('ports', {})
            if not isinstance(old_ports, dict):
                old_ports = {}
            else:
                old_ports = old_ports.get('data', {})
                
            new_ports = new_context.get('ports', {})
            if not isinstance(new_ports, dict):
                new_ports = {}
            else:
                new_ports = new_ports.get('data', {})
        except (AttributeError, TypeError):
            return changes
        
        if not old_ports or not new_ports:
            return changes
        
        # Check for network exposure changes
        old_exposure = old_ports.get('network_exposure', 'none')
        new_exposure = new_ports.get('network_exposure', 'none')
        
        if old_exposure != new_exposure:
            severity = self._assess_exposure_change_severity(old_exposure, new_exposure)
            changes.append(ChangeEvent(
                change_type='status_change',
                source='ports',
                severity=severity,
                description=f'Network exposure level changed: {old_exposure} → {new_exposure}',
                old_value=old_exposure,
                new_value=new_exposure,
                timestamp=timestamp,
                metadata={'exposure_change': True}
            ))
        
        return changes
    
    def _assess_connection_change_severity(self, old_connection: str, new_connection: str) -> str:
        """Assess severity of connection quality changes."""
        quality_levels = {'excellent': 4, 'good': 3, 'fair': 2, 'poor': 1, 'unknown': 0}
        
        old_level = quality_levels.get(old_connection, 0)
        new_level = quality_levels.get(new_connection, 0)
        
        if new_level < old_level:
            if new_level <= 1:  # poor or unknown
                return 'high'
            elif new_level == 2:  # fair
                return 'medium'
        
        return 'low'
    
    def _assess_exposure_change_severity(self, old_exposure: str, new_exposure: str) -> str:
        """Assess severity of network exposure changes."""
        exposure_levels = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        
        old_level = exposure_levels.get(old_exposure, 0)
        new_level = exposure_levels.get(new_exposure, 0)
        
        if new_level > old_level:
            if new_level >= 3:  # high or critical
                return 'critical'
            elif new_level == 2:  # medium
                return 'high'
            else:
                return 'medium'
        
        return 'low'
    
    def _get_change_priority(self, change: ChangeEvent) -> int:
        """Get numerical priority for sorting changes."""
        severity_scores = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        type_multipliers = {
            'new_alert': 1.2,
            'escalation': 1.1,
            'new_vulnerability': 1.3,
            'new_threat': 1.2,
            'status_change': 1.0,
            'data_update': 0.8
        }
        
        base_score = severity_scores.get(change.severity, 1)
        type_multiplier = type_multipliers.get(change.change_type, 1.0)
        
        return int(base_score * type_multiplier * 10)  # Scale for integer sorting
    
    def _generate_change_summary(self, changes: List[ChangeEvent]) -> str:
        """Generate a human-readable summary of changes."""
        if not changes:
            return "No significant changes detected"
        
        critical_count = len([c for c in changes if c.severity == 'critical'])
        high_count = len([c for c in changes if c.severity == 'high'])
        
        if critical_count > 0:
            return f"CRITICAL: {critical_count} critical changes detected, {high_count} high-priority changes"
        elif high_count > 0:
            return f"HIGH PRIORITY: {high_count} high-priority changes detected"
        else:
            return f"MODERATE: {len(changes)} changes detected, monitoring recommended"


class RealTimeContextUpdater:
    """Manage real-time context updates during incidents."""
    
    def __init__(self, server_instance=None):
        """Initialize the real-time context updater."""
        self.logger = logging.getLogger(__name__)
        self.server = server_instance
        self.change_detector = ChangeDetector()
        
        # Active monitoring contexts
        self.active_contexts: Dict[str, Dict[str, Any]] = {}
        self.context_snapshots: Dict[str, ContextSnapshot] = {}
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}
        
        # Update intervals based on priority
        self.update_intervals = {
            'critical': 30,    # seconds
            'high': 60,
            'medium': 300,     # 5 minutes
            'low': 900,        # 15 minutes
            'background': 1800 # 30 minutes
        }
        
        # Subscriber management
        self.subscribers: Dict[str, Set[Callable]] = {}
        self.global_subscribers: Set[Callable] = set()
        
        # Statistics
        self.stats = {
            'total_updates': 0,
            'change_events': 0,
            'active_monitors': 0,
            'last_update': None
        }
    
    async def start_monitoring(self, context_id: str, context_type: str, 
                              priority: str = 'medium', initial_context: Optional[Dict[str, Any]] = None) -> None:
        """
        Start monitoring a context for real-time updates.
        
        Args:
            context_id: Unique identifier for the context
            context_type: Type of context (incident, hunting, etc.)
            priority: Update priority level
            initial_context: Initial context data for baseline
        """
        if context_id in self.active_contexts:
            self.logger.warning(f"Context {context_id} is already being monitored")
            return
        
        self.logger.info(f"Starting real-time monitoring for context {context_id} (type: {context_type}, priority: {priority})")
        
        # Initialize context tracking
        self.active_contexts[context_id] = {
            'context_type': context_type,
            'priority': priority,
            'started_at': datetime.utcnow().isoformat(),
            'last_update': datetime.utcnow().isoformat(),
            'update_count': 0,
            'change_count': 0,
            'status': 'active'
        }
        
        # Create initial snapshot if context provided
        if initial_context:
            snapshot = ContextSnapshot.create(context_id, context_type, initial_context)
            self.context_snapshots[context_id] = snapshot
            self.logger.debug(f"Created initial snapshot for {context_id}: {snapshot.checksum}")
        
        # Initialize subscriber list
        if context_id not in self.subscribers:
            self.subscribers[context_id] = set()
        
        # Start monitoring task
        interval = self.update_intervals.get(priority, 300)
        task = asyncio.create_task(self._monitor_context(context_id, interval))
        self.monitoring_tasks[context_id] = task
        
        # Update statistics
        self.stats['active_monitors'] = len(self.active_contexts)
        
        self.logger.info(f"Real-time monitoring started for {context_id} with {interval}s intervals")
    
    async def stop_monitoring(self, context_id: str) -> None:
        """
        Stop monitoring a context.
        
        Args:
            context_id: Context identifier to stop monitoring
        """
        if context_id not in self.active_contexts:
            self.logger.warning(f"Context {context_id} is not being monitored")
            return
        
        self.logger.info(f"Stopping real-time monitoring for context {context_id}")
        
        # Cancel monitoring task
        if context_id in self.monitoring_tasks:
            task = self.monitoring_tasks[context_id]
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            del self.monitoring_tasks[context_id]
        
        # Update context status
        if context_id in self.active_contexts:
            self.active_contexts[context_id]['status'] = 'stopped'
            self.active_contexts[context_id]['stopped_at'] = datetime.utcnow().isoformat()
        
        # Clean up resources
        self.active_contexts.pop(context_id, None)
        self.context_snapshots.pop(context_id, None)
        self.subscribers.pop(context_id, None)
        
        # Update statistics
        self.stats['active_monitors'] = len(self.active_contexts)
        
        self.logger.info(f"Real-time monitoring stopped for {context_id}")
    
    async def update_context(self, context_id: str, new_context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Update context and detect changes.
        
        Args:
            context_id: Context identifier
            new_context: New context data
            
        Returns:
            Change detection result or None if no monitoring
        """
        if context_id not in self.active_contexts:
            self.logger.debug(f"Context {context_id} is not being monitored, skipping update")
            return None
        
        # Get previous snapshot
        old_snapshot = self.context_snapshots.get(context_id)
        
        # Create new snapshot
        context_info = self.active_contexts[context_id]
        new_snapshot = ContextSnapshot.create(context_id, context_info['context_type'], new_context)
        
        # Check if context actually changed
        if old_snapshot and old_snapshot.checksum == new_snapshot.checksum:
            self.logger.debug(f"No changes detected in context {context_id}")
            return None
        
        # Detect changes
        changes = None
        if old_snapshot:
            changes = self.change_detector.detect_changes(old_snapshot.data, new_context)
            
            if changes and changes.get('total_changes', 0) > 0:
                self.logger.info(f"Detected {changes['total_changes']} changes in context {context_id}: {changes['summary']}")
                
                # Update statistics
                self.stats['change_events'] += changes['total_changes']
                context_info['change_count'] += changes['total_changes']
                
                # Notify subscribers
                await self._notify_subscribers(context_id, changes, new_context)
            else:
                self.logger.debug(f"No significant changes detected in context {context_id}")
        
        # Update snapshot and statistics
        self.context_snapshots[context_id] = new_snapshot
        context_info['last_update'] = datetime.utcnow().isoformat()
        context_info['update_count'] += 1
        self.stats['total_updates'] += 1
        self.stats['last_update'] = datetime.utcnow().isoformat()
        
        return changes
    
    def subscribe_to_updates(self, context_id: str, callback: Callable) -> None:
        """
        Subscribe to updates for a specific context.
        
        Args:
            context_id: Context identifier
            callback: Function to call when updates occur
        """
        if context_id not in self.subscribers:
            self.subscribers[context_id] = set()
        
        self.subscribers[context_id].add(callback)
        self.logger.debug(f"Added subscriber for context {context_id}")
    
    def unsubscribe_from_updates(self, context_id: str, callback: Callable) -> None:
        """
        Unsubscribe from updates for a specific context.
        
        Args:
            context_id: Context identifier
            callback: Function to remove from subscribers
        """
        if context_id in self.subscribers:
            self.subscribers[context_id].discard(callback)
            self.logger.debug(f"Removed subscriber for context {context_id}")
    
    def subscribe_to_all_updates(self, callback: Callable) -> None:
        """
        Subscribe to updates for all contexts.
        
        Args:
            callback: Function to call when any context updates occur
        """
        self.global_subscribers.add(callback)
        self.logger.debug("Added global subscriber")
    
    def unsubscribe_from_all_updates(self, callback: Callable) -> None:
        """
        Unsubscribe from all context updates.
        
        Args:
            callback: Function to remove from global subscribers
        """
        self.global_subscribers.discard(callback)
        self.logger.debug("Removed global subscriber")
    
    async def get_context_status(self, context_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status information for a monitored context.
        
        Args:
            context_id: Context identifier
            
        Returns:
            Status information or None if not monitored
        """
        if context_id not in self.active_contexts:
            return None
        
        context_info = self.active_contexts[context_id].copy()
        
        # Add snapshot information
        if context_id in self.context_snapshots:
            snapshot = self.context_snapshots[context_id]
            context_info['last_snapshot'] = {
                'timestamp': snapshot.timestamp,
                'checksum': snapshot.checksum
            }
        
        # Add subscriber count
        context_info['subscriber_count'] = len(self.subscribers.get(context_id, set()))
        
        return context_info
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """
        Get overall monitoring statistics.
        
        Returns:
            Dictionary of monitoring statistics
        """
        return {
            **self.stats,
            'active_contexts': list(self.active_contexts.keys()),
            'total_subscribers': sum(len(subs) for subs in self.subscribers.values()) + len(self.global_subscribers),
            'monitoring_intervals': self.update_intervals
        }
    
    async def _monitor_context(self, context_id: str, interval: int) -> None:
        """
        Background task to monitor a context.
        
        Args:
            context_id: Context identifier
            interval: Update interval in seconds
        """
        self.logger.debug(f"Started background monitoring for {context_id} with {interval}s interval")
        
        try:
            while context_id in self.active_contexts:
                await asyncio.sleep(interval)
                
                if context_id not in self.active_contexts:
                    break
                
                # Gather fresh context if server is available
                if self.server and hasattr(self.server, 'context_aggregator'):
                    try:
                        context_info = self.active_contexts[context_id]
                        context_type = context_info['context_type']
                        
                        # Create a mock request for background monitoring
                        from .context_aggregator import ContextRequest
                        request = ContextRequest(
                            prompt=f"Background monitoring for {context_type}",
                            tool_name="monitoring",
                            arguments={"context_id": context_id}
                        )
                        
                        # Gather fresh context
                        fresh_context = await self.server.context_aggregator._gather_context(request)
                        
                        if fresh_context:
                            await self.update_context(context_id, fresh_context)
                        
                    except Exception as e:
                        self.logger.debug(f"Background context gathering failed for {context_id}: {str(e)}")
                
        except asyncio.CancelledError:
            self.logger.debug(f"Background monitoring cancelled for {context_id}")
            raise
        except Exception as e:
            self.logger.error(f"Background monitoring error for {context_id}: {str(e)}")
    
    async def _notify_subscribers(self, context_id: str, changes: Dict[str, Any], new_context: Dict[str, Any]) -> None:
        """
        Notify subscribers of context changes.
        
        Args:
            context_id: Context identifier
            changes: Detected changes
            new_context: Updated context data
        """
        notification = {
            'context_id': context_id,
            'changes': changes,
            'context': new_context,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Notify context-specific subscribers
        context_subscribers = self.subscribers.get(context_id, set())
        for callback in context_subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(notification)
                else:
                    callback(notification)
            except Exception as e:
                self.logger.error(f"Subscriber callback error for {context_id}: {str(e)}")
        
        # Notify global subscribers
        for callback in self.global_subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(notification)
                else:
                    callback(notification)
            except Exception as e:
                self.logger.error(f"Global subscriber callback error: {str(e)}")
    
    async def cleanup(self) -> None:
        """Clean up all monitoring resources."""
        self.logger.info("Cleaning up real-time context updater")
        
        # Stop all monitoring
        context_ids = list(self.active_contexts.keys())
        for context_id in context_ids:
            await self.stop_monitoring(context_id)
        
        # Clear all subscribers
        self.subscribers.clear()
        self.global_subscribers.clear()
        
        self.logger.info("Real-time context updater cleanup completed")