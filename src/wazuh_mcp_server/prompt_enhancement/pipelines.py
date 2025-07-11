"""
Context Pipelines

Specialized pipelines for gathering context based on different analysis types:
- Incident Investigation
- Threat Hunting
- Compliance Assessment
- Forensic Analysis
"""

import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import logging

from .cache import AsyncContextCache, CacheKeyBuilder


class ContextPipeline(ABC):
    """Base class for context gathering pipelines."""
    
    def __init__(self, server_instance, cache: AsyncContextCache):
        """
        Initialize the pipeline.
        
        Args:
            server_instance: Reference to the main WazuhMCPServer instance
            cache: Async context cache instance
        """
        self.server = server_instance
        self.cache = cache
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.timeout = 5.0
    
    @abstractmethod
    async def gather_context(self, request, confidence_score: float) -> Optional[Dict[str, Any]]:
        """
        Gather context for the given request.
        
        Args:
            request: ContextRequest object
            confidence_score: Confidence that this pipeline is relevant (0.0-1.0)
            
        Returns:
            Context dictionary or None if no context could be gathered
        """
        pass
    
    async def _safe_api_call(self, api_func, *args, **kwargs):
        """Safely call an API function with error handling."""
        try:
            result = await api_func(*args, **kwargs)
            return result
        except Exception as e:
            self.logger.debug(f"API call failed: {str(e)}")
            return None
    
    def _extract_time_range(self, arguments: Dict[str, Any]) -> str:
        """Extract time range from arguments with sensible default."""
        return arguments.get('time_range', '24h')
    
    def _extract_agent_id(self, arguments: Dict[str, Any]) -> Optional[str]:
        """Extract agent ID from arguments."""
        return arguments.get('agent_id')


class IncidentPipeline(ContextPipeline):
    """Pipeline for incident investigation context."""
    
    async def gather_context(self, request, confidence_score: float) -> Optional[Dict[str, Any]]:
        """Gather incident-related context."""
        context = {
            'type': 'incident',
            'confidence': confidence_score,
            'gathered_at': datetime.utcnow().isoformat()
        }
        
        try:
            # Determine scope based on available information
            agent_id = self._extract_agent_id(request.arguments)
            time_range = self._extract_time_range(request.arguments)
            
            # Gather context in parallel
            tasks = []
            
            # Always gather recent alerts
            tasks.append(self._gather_recent_alerts(time_range, agent_id))
            
            # If we have an agent ID, gather agent-specific context
            if agent_id:
                tasks.append(self._gather_agent_health(agent_id))
                tasks.append(self._gather_agent_vulnerabilities(agent_id))
                tasks.append(self._gather_agent_processes(agent_id))
                tasks.append(self._gather_agent_ports(agent_id))
            
            # Execute all context gathering tasks
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            context_data = {}
            result_keys = ['alerts', 'agent_health', 'vulnerabilities', 'processes', 'ports']
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    self.logger.debug(f"Context gathering failed for {result_keys[i] if i < len(result_keys) else 'unknown'}: {str(result)}")
                    continue
                
                if result:
                    key = result_keys[i] if i < len(result_keys) else f'data_{i}'
                    context_data[key] = result
            
            if context_data:
                context['data'] = context_data
                context['completeness'] = len(context_data) / 5.0  # 5 possible data sources
                return context
            
            return None
            
        except Exception as e:
            self.logger.error(f"Incident context gathering failed: {str(e)}")
            return None
    
    async def _gather_recent_alerts(self, time_range: str, agent_id: Optional[str] = None):
        """Gather recent alerts."""
        cache_key = CacheKeyBuilder.alerts_key(agent_id, time_range)
        
        # Check cache first
        cached_result = await self.cache.get('alerts', cache_key)
        if cached_result:
            return cached_result
        
        # Fetch from API
        try:
            # Use the actual API client with proper parameters
            data = await self._safe_api_call(
                self.server.api_client.get_alerts,
                limit=100,
                time_range=time_range,
                agent_id=agent_id
            )
            
            if data:
                alerts = data.get("data", {}).get("affected_items", [])
                if alerts:
                    # Analyze alerts for context
                    severity_dist = self._analyze_alert_severity(alerts)
                    high_severity_alerts = [a for a in alerts if a.get('rule', {}).get('level', 0) >= 7]
                    
                    result = {
                        'total_count': len(alerts),
                        'high_severity_count': len(high_severity_alerts),
                        'recent_alerts': alerts[:5],  # Top 5 most recent
                        'high_severity_alerts': high_severity_alerts[:3],  # Top 3 high severity
                        'severity_distribution': severity_dist,
                        'alert_trend': self._calculate_alert_trend(alerts),
                        'top_rules': self._get_top_triggered_rules(alerts)
                    }
                    
                    # Cache the result
                    await self.cache.set('alerts', cache_key, result, ttl=300)
                    return result
                else:
                    # Return empty result structure
                    result = {
                        'total_count': 0,
                        'high_severity_count': 0,
                        'recent_alerts': [],
                        'high_severity_alerts': [],
                        'severity_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
                        'alert_trend': 'stable',
                        'top_rules': []
                    }
                    await self.cache.set('alerts', cache_key, result, ttl=60)
                    return result
                    
        except Exception as e:
            self.logger.debug(f"Failed to gather alerts: {str(e)}")
        
        return None
    
    async def _gather_agent_health(self, agent_id: str):
        """Gather agent health information."""
        cache_key = CacheKeyBuilder.agent_health_key(agent_id)
        
        # Check cache first
        cached_result = await self.cache.get('agent_health', cache_key)
        if cached_result:
            return cached_result
        
        # Fetch from API
        try:
            # Get agent basic info
            agent_data = await self._safe_api_call(
                self.server.api_client.get_agents,
                agent_id=agent_id
            )
            
            # Get agent statistics if available
            stats_data = await self._safe_api_call(
                self.server.api_client.get_agent_stats,
                agent_id
            )
            
            if agent_data:
                agents = agent_data.get("data", {}).get("affected_items", [])
                if agents:
                    agent = agents[0]
                    
                    # Calculate health score and status
                    health_score = self._calculate_agent_health_score(agent, stats_data)
                    
                    result = {
                        'agent_id': agent_id,
                        'status': agent.get('status'),
                        'last_keep_alive': agent.get('last_keep_alive'),
                        'os': agent.get('os', {}),
                        'version': agent.get('version'),
                        'node_name': agent.get('node_name'),
                        'ip': agent.get('ip'),
                        'health_score': health_score,
                        'health_status': self._get_health_status(health_score),
                        'connection_quality': self._assess_connection_quality(agent),
                        'version_status': self._assess_version_status(agent.get('version')),
                        'statistics': self._extract_agent_statistics(stats_data) if stats_data else None
                    }
                    
                    # Cache the result
                    await self.cache.set('agent_health', cache_key, result, ttl=60)
                    return result
                    
        except Exception as e:
            self.logger.debug(f"Failed to gather agent health: {str(e)}")
        
        return None
    
    async def _gather_agent_vulnerabilities(self, agent_id: str):
        """Gather agent vulnerabilities."""
        cache_key = CacheKeyBuilder.vulnerabilities_key(agent_id)
        
        # Check cache first
        cached_result = await self.cache.get('vulnerabilities', cache_key)
        if cached_result:
            return cached_result
        
        # Fetch from API
        try:
            # Use the actual vulnerability API method
            data = await self._safe_api_call(
                self.server.api_client.get_agent_vulnerabilities,
                agent_id
            )
            
            if data:
                vulns = data.get("data", {}).get("affected_items", [])
                if vulns:
                    # Analyze vulnerabilities by severity
                    critical_vulns = [v for v in vulns if v.get('severity') == 'Critical']
                    high_vulns = [v for v in vulns if v.get('severity') == 'High']
                    medium_vulns = [v for v in vulns if v.get('severity') == 'Medium']
                    low_vulns = [v for v in vulns if v.get('severity') == 'Low']
                    
                    # Identify exploitable vulnerabilities
                    exploitable_vulns = [v for v in vulns if self._is_exploitable_vulnerability(v)]
                    
                    result = {
                        'total_count': len(vulns),
                        'severity_breakdown': {
                            'critical': len(critical_vulns),
                            'high': len(high_vulns),
                            'medium': len(medium_vulns),
                            'low': len(low_vulns)
                        },
                        'exploitable_count': len(exploitable_vulns),
                        'top_critical': critical_vulns[:3],  # Top 3 critical
                        'top_exploitable': exploitable_vulns[:3],  # Top 3 exploitable
                        'packages_affected': self._get_vulnerable_packages(vulns),
                        'cvss_distribution': self._analyze_cvss_scores(vulns),
                        'remediation_priority': self._calculate_remediation_priority(vulns)
                    }
                    
                    # Cache the result (longer TTL as vulnerabilities change less frequently)
                    await self.cache.set('vulnerabilities', cache_key, result, ttl=1800)
                    return result
                else:
                    # Return empty structure
                    result = {
                        'total_count': 0,
                        'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                        'exploitable_count': 0,
                        'top_critical': [],
                        'top_exploitable': [],
                        'packages_affected': [],
                        'cvss_distribution': {},
                        'remediation_priority': []
                    }
                    await self.cache.set('vulnerabilities', cache_key, result, ttl=300)
                    return result
                    
        except Exception as e:
            self.logger.debug(f"Failed to gather vulnerabilities: {str(e)}")
        
        return None
    
    async def _gather_agent_processes(self, agent_id: str):
        """Gather agent processes."""
        cache_key = CacheKeyBuilder.processes_key(agent_id)
        
        # Check cache first
        cached_result = await self.cache.get('processes', cache_key)
        if cached_result:
            return cached_result
        
        # Fetch from API
        try:
            data = await self._safe_api_call(
                self.server.api_client.get_agent_processes,
                agent_id
            )
            
            if data:
                processes = data.get("data", {}).get("affected_items", [])
                if processes:
                    # Analyze processes for security context
                    high_cpu_processes = [p for p in processes if float(p.get('cpu', 0)) > 50]
                    high_memory_processes = [p for p in processes if float(p.get('rss', 0)) > 100000]  # >100MB
                    suspicious_processes = self._identify_suspicious_processes(processes)
                    system_processes = self._identify_system_processes(processes)
                    
                    result = {
                        'total_count': len(processes),
                        'running_count': len([p for p in processes if p.get('state') == 'R']),
                        'high_cpu_count': len(high_cpu_processes),
                        'high_memory_count': len(high_memory_processes),
                        'suspicious_count': len(suspicious_processes),
                        'top_cpu_processes': sorted(high_cpu_processes, key=lambda x: float(x.get('cpu', 0)), reverse=True)[:3],
                        'top_memory_processes': sorted(high_memory_processes, key=lambda x: float(x.get('rss', 0)), reverse=True)[:3],
                        'suspicious_processes': suspicious_processes[:5],
                        'system_process_health': self._assess_system_process_health(system_processes),
                        'process_anomalies': self._detect_process_anomalies(processes)
                    }
                    
                    # Cache the result (shorter TTL as processes change frequently)
                    await self.cache.set('processes', cache_key, result, ttl=120)
                    return result
                else:
                    # Return empty structure
                    result = {
                        'total_count': 0,
                        'running_count': 0,
                        'high_cpu_count': 0,
                        'high_memory_count': 0,
                        'suspicious_count': 0,
                        'top_cpu_processes': [],
                        'top_memory_processes': [],
                        'suspicious_processes': [],
                        'system_process_health': 'unknown',
                        'process_anomalies': []
                    }
                    await self.cache.set('processes', cache_key, result, ttl=60)
                    return result
                    
        except Exception as e:
            self.logger.debug(f"Failed to gather processes: {str(e)}")
        
        return None
    
    async def _gather_agent_ports(self, agent_id: str):
        """Gather agent network ports."""
        cache_key = CacheKeyBuilder.ports_key(agent_id)
        
        # Check cache first
        cached_result = await self.cache.get('ports', cache_key)
        if cached_result:
            return cached_result
        
        # Fetch from API
        try:
            data = await self._safe_api_call(
                self.server.api_client.get_agent_ports,
                agent_id
            )
            
            if data:
                ports = data.get("data", {}).get("affected_items", [])
                if ports:
                    # Analyze ports for security context
                    open_ports = [p for p in ports if p.get('state') == 'open']
                    listening_ports = [p for p in ports if p.get('state') == 'listening']
                    suspicious_ports = self._identify_suspicious_ports(ports)
                    critical_service_ports = self._identify_critical_service_ports(ports)
                    
                    result = {
                        'total_count': len(ports),
                        'open_count': len(open_ports),
                        'listening_count': len(listening_ports),
                        'suspicious_count': len(suspicious_ports),
                        'critical_services_count': len(critical_service_ports),
                        'protocol_distribution': self._analyze_port_protocols(ports),
                        'suspicious_ports': suspicious_ports[:5],
                        'critical_service_ports': critical_service_ports[:5],
                        'network_exposure': self._assess_network_exposure(ports),
                        'port_anomalies': self._detect_port_anomalies(ports)
                    }
                    
                    # Cache the result
                    await self.cache.set('ports', cache_key, result, ttl=300)
                    return result
                else:
                    # Return empty structure
                    result = {
                        'total_count': 0,
                        'open_count': 0,
                        'listening_count': 0,
                        'suspicious_count': 0,
                        'critical_services_count': 0,
                        'protocol_distribution': {'tcp': 0, 'udp': 0},
                        'suspicious_ports': [],
                        'critical_service_ports': [],
                        'network_exposure': 'low',
                        'port_anomalies': []
                    }
                    await self.cache.set('ports', cache_key, result, ttl=120)
                    return result
                    
        except Exception as e:
            self.logger.debug(f"Failed to gather ports: {str(e)}")
        
        return None
    
    def _analyze_alert_severity(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze alert severity distribution."""
        severity_count = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for alert in alerts:
            level = alert.get('rule', {}).get('level', 0)
            if level >= 12:
                severity_count['critical'] += 1
            elif level >= 7:
                severity_count['high'] += 1
            elif level >= 4:
                severity_count['medium'] += 1
            else:
                severity_count['low'] += 1
        
        return severity_count
    
    def _identify_suspicious_processes(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potentially suspicious processes."""
        suspicious = []
        suspicious_names = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
        
        for process in processes:
            name = process.get('name', '').lower()
            if any(sus_name in name for sus_name in suspicious_names):
                suspicious.append(process)
        
        return suspicious[:5]  # Limit results
    
    def _identify_suspicious_ports(self, ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify potentially suspicious ports."""
        suspicious = []
        suspicious_port_numbers = {4444, 8080, 8888, 9999, 31337, 12345}
        
        for port in ports:
            port_num = port.get('local_port')
            if port_num in suspicious_port_numbers:
                suspicious.append(port)
        
        return suspicious
    
    # New helper methods for enhanced incident pipeline
    
    def _calculate_alert_trend(self, alerts: List[Dict[str, Any]]) -> str:
        """Calculate alert trend based on timestamps."""
        if not alerts or len(alerts) < 2:
            return 'stable'
        
        # Simple trend analysis based on alert frequency
        try:
            recent_count = len([a for a in alerts[:len(alerts)//2]])
            older_count = len([a for a in alerts[len(alerts)//2:]])
            
            if recent_count > older_count * 1.5:
                return 'increasing'
            elif recent_count < older_count * 0.5:
                return 'decreasing'
            else:
                return 'stable'
        except:
            return 'stable'
    
    def _get_top_triggered_rules(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Get most frequently triggered rules."""
        rule_counts = {}
        
        for alert in alerts:
            rule_id = alert.get('rule', {}).get('id')
            rule_description = alert.get('rule', {}).get('description', 'Unknown')
            
            if rule_id:
                if rule_id not in rule_counts:
                    rule_counts[rule_id] = {
                        'id': rule_id,
                        'description': rule_description,
                        'count': 0
                    }
                rule_counts[rule_id]['count'] += 1
        
        # Return top 5 rules by count
        return sorted(rule_counts.values(), key=lambda x: x['count'], reverse=True)[:5]
    
    def _calculate_agent_health_score(self, agent: Dict[str, Any], stats_data: Optional[Dict[str, Any]]) -> int:
        """Calculate agent health score (0-100)."""
        score = 100
        
        # Deduct points based on status
        status = agent.get('status', '').lower()
        if status == 'disconnected':
            score -= 50
        elif status == 'never_connected':
            score -= 80
        elif status != 'active':
            score -= 30
        
        # Check last keep alive
        try:
            from datetime import datetime, timedelta
            last_keepalive = agent.get('last_keep_alive')
            if last_keepalive:
                # Parse keepalive timestamp and check if it's recent
                # This is a simplified check
                if 'T' in last_keepalive:
                    score += 10  # Recent keepalive
        except:
            pass
        
        # Factor in stats if available
        if stats_data:
            stats = stats_data.get('data', {})
            if isinstance(stats, dict):
                # Check for high resource usage
                cpu_usage = stats.get('cpu_usage', 0)
                if cpu_usage > 80:
                    score -= 20
                elif cpu_usage > 60:
                    score -= 10
        
        return max(0, min(100, score))
    
    def _get_health_status(self, health_score: int) -> str:
        """Convert health score to status."""
        if health_score >= 90:
            return 'excellent'
        elif health_score >= 70:
            return 'good'
        elif health_score >= 50:
            return 'fair'
        elif health_score >= 30:
            return 'poor'
        else:
            return 'critical'
    
    def _assess_connection_quality(self, agent: Dict[str, Any]) -> str:
        """Assess agent connection quality."""
        status = agent.get('status', '').lower()
        if status == 'active':
            return 'good'
        elif status == 'disconnected':
            return 'poor'
        else:
            return 'unknown'
    
    def _assess_version_status(self, version: Optional[str]) -> str:
        """Assess agent version status."""
        if not version:
            return 'unknown'
        
        # Simple version assessment
        if version.startswith('4.8'):
            return 'current'
        elif version.startswith('4.7'):
            return 'outdated'
        elif version.startswith('4.6'):
            return 'deprecated'
        else:
            return 'very_old'
    
    def _extract_agent_statistics(self, stats_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract useful statistics from agent stats."""
        if not stats_data:
            return {}
        
        stats = stats_data.get('data', {})
        if not isinstance(stats, dict):
            return {}
        
        return {
            'events_received': stats.get('events_received', 0),
            'events_sent': stats.get('events_sent', 0),
            'cpu_usage': stats.get('cpu_usage', 0),
            'memory_usage': stats.get('memory_usage', 0),
            'uptime': stats.get('uptime', 'unknown')
        }
    
    def _is_exploitable_vulnerability(self, vuln: Dict[str, Any]) -> bool:
        """Check if vulnerability is exploitable."""
        # Look for exploit availability indicators
        cve = vuln.get('cve', '')
        severity = vuln.get('severity', '').lower()
        
        # High/Critical vulnerabilities with CVE are more likely exploitable
        if severity in ['critical', 'high'] and cve:
            return True
        
        # Check for specific exploit indicators
        description = vuln.get('description', '').lower()
        exploit_keywords = ['exploit', 'remote code execution', 'buffer overflow', 'injection']
        
        return any(keyword in description for keyword in exploit_keywords)
    
    def _get_vulnerable_packages(self, vulns: List[Dict[str, Any]]) -> List[str]:
        """Get list of vulnerable packages."""
        packages = set()
        
        for vuln in vulns:
            package = vuln.get('package', {})
            if isinstance(package, dict):
                name = package.get('name')
                if name:
                    packages.add(name)
        
        return list(packages)[:10]  # Limit to 10 packages
    
    def _analyze_cvss_scores(self, vulns: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze CVSS score distribution."""
        distribution = {'0-3': 0, '4-6': 0, '7-8': 0, '9-10': 0}
        
        for vuln in vulns:
            cvss = vuln.get('cvss', {})
            score = 0
            
            if isinstance(cvss, dict):
                score = cvss.get('cvss3', {}).get('base_score', 0)
            elif isinstance(cvss, (int, float)):
                score = cvss
            
            if score <= 3:
                distribution['0-3'] += 1
            elif score <= 6:
                distribution['4-6'] += 1
            elif score <= 8:
                distribution['7-8'] += 1
            else:
                distribution['9-10'] += 1
        
        return distribution
    
    def _calculate_remediation_priority(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Calculate remediation priority for vulnerabilities."""
        priorities = []
        
        for vuln in vulns:
            severity = vuln.get('severity', '').lower()
            exploitable = self._is_exploitable_vulnerability(vuln)
            
            priority_score = 0
            if severity == 'critical':
                priority_score += 100
            elif severity == 'high':
                priority_score += 75
            elif severity == 'medium':
                priority_score += 50
            else:
                priority_score += 25
            
            if exploitable:
                priority_score += 50
            
            priorities.append({
                'cve': vuln.get('cve', 'N/A'),
                'package': vuln.get('package', {}).get('name', 'Unknown'),
                'priority_score': priority_score,
                'priority_level': 'critical' if priority_score >= 120 else 'high' if priority_score >= 80 else 'medium'
            })
        
        return sorted(priorities, key=lambda x: x['priority_score'], reverse=True)[:5]
    
    def _identify_system_processes(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify system processes."""
        system_process_names = ['systemd', 'kernel', 'init', 'kthreadd', 'ksoftirqd', 'sshd', 'nginx', 'apache2']
        
        system_processes = []
        for process in processes:
            name = process.get('name', '').lower()
            if any(sys_name in name for sys_name in system_process_names):
                system_processes.append(process)
        
        return system_processes
    
    def _assess_system_process_health(self, system_processes: List[Dict[str, Any]]) -> str:
        """Assess system process health."""
        if not system_processes:
            return 'unknown'
        
        critical_processes = ['systemd', 'init', 'sshd']
        found_critical = any(
            any(crit in proc.get('name', '').lower() for crit in critical_processes)
            for proc in system_processes
        )
        
        return 'healthy' if found_critical else 'concerning'
    
    def _detect_process_anomalies(self, processes: List[Dict[str, Any]]) -> List[str]:
        """Detect process anomalies."""
        anomalies = []
        
        # Check for processes with unusual characteristics
        for process in processes:
            cpu = float(process.get('cpu', 0))
            memory = float(process.get('rss', 0))
            name = process.get('name', '')
            
            if cpu > 95:
                anomalies.append(f"Process {name} using {cpu}% CPU")
            
            if memory > 1000000:  # >1GB
                anomalies.append(f"Process {name} using excessive memory")
            
            # Check for suspicious process names
            if any(char in name for char in ['$', '@', '#']) or len(name) == 1:
                anomalies.append(f"Process with suspicious name: {name}")
        
        return anomalies[:5]  # Limit to 5 anomalies
    
    def _identify_critical_service_ports(self, ports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify critical service ports."""
        critical_ports = {22: 'SSH', 443: 'HTTPS', 80: 'HTTP', 3389: 'RDP', 25: 'SMTP', 53: 'DNS'}
        
        critical_service_ports = []
        for port in ports:
            port_num = port.get('local_port')
            if port_num in critical_ports:
                port_info = port.copy()
                port_info['service_name'] = critical_ports[port_num]
                critical_service_ports.append(port_info)
        
        return critical_service_ports
    
    def _analyze_port_protocols(self, ports: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze port protocol distribution."""
        distribution = {'tcp': 0, 'udp': 0, 'other': 0}
        
        for port in ports:
            protocol = port.get('protocol', '').lower()
            if protocol in distribution:
                distribution[protocol] += 1
            else:
                distribution['other'] += 1
        
        return distribution
    
    def _assess_network_exposure(self, ports: List[Dict[str, Any]]) -> str:
        """Assess network exposure level."""
        open_count = len([p for p in ports if p.get('state') == 'open'])
        
        if open_count == 0:
            return 'none'
        elif open_count <= 5:
            return 'low'
        elif open_count <= 15:
            return 'medium'
        else:
            return 'high'
    
    def _detect_port_anomalies(self, ports: List[Dict[str, Any]]) -> List[str]:
        """Detect port anomalies."""
        anomalies = []
        
        suspicious_port_numbers = {4444, 8080, 8888, 9999, 31337, 12345, 6667}
        
        for port in ports:
            port_num = port.get('local_port')
            if port_num in suspicious_port_numbers:
                anomalies.append(f"Suspicious port {port_num} is open")
            
            # Check for high port numbers (potential backdoors)
            if port_num and port_num > 50000:
                anomalies.append(f"High port number {port_num} detected")
        
        return anomalies[:5]  # Limit to 5 anomalies


class ThreatHuntingPipeline(ContextPipeline):
    """Pipeline for threat hunting context."""
    
    async def gather_context(self, request, confidence_score: float) -> Optional[Dict[str, Any]]:
        """Gather threat hunting context."""
        context = {
            'type': 'threat_hunting',
            'confidence': confidence_score,
            'gathered_at': datetime.utcnow().isoformat()
        }
        
        try:
            # Extract hunting parameters
            agent_id = self._extract_agent_id(request.arguments)
            time_range = self._extract_time_range(request.arguments)
            
            # Gather hunting-specific context
            tasks = [
                self._gather_ioc_matches(time_range, agent_id),
                self._gather_anomalous_behavior(time_range, agent_id),
                self._gather_network_anomalies(agent_id)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            context_data = {}
            result_keys = ['ioc_matches', 'anomalous_behavior', 'network_anomalies']
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    continue
                if result:
                    context_data[result_keys[i]] = result
            
            if context_data:
                context['data'] = context_data
                context['completeness'] = len(context_data) / 3.0
                return context
            
            return None
            
        except Exception as e:
            self.logger.error(f"Threat hunting context gathering failed: {str(e)}")
            return None
    
    async def _gather_ioc_matches(self, time_range: str, agent_id: Optional[str] = None):
        """Gather IOC matches."""
        # Placeholder - would integrate with threat intelligence
        return {
            'total_matches': 0,
            'recent_matches': [],
            'match_types': {'ip': 0, 'domain': 0, 'hash': 0}
        }
    
    async def _gather_anomalous_behavior(self, time_range: str, agent_id: Optional[str] = None):
        """Gather anomalous behavior indicators."""
        # Placeholder - would analyze patterns
        return {
            'behavioral_anomalies': [],
            'statistical_outliers': [],
            'temporal_anomalies': []
        }
    
    async def _gather_network_anomalies(self, agent_id: Optional[str] = None):
        """Gather network anomalies."""
        # Placeholder - would analyze network patterns
        return {
            'unusual_connections': [],
            'port_scanning': [],
            'data_exfiltration_indicators': []
        }


class CompliancePipeline(ContextPipeline):
    """Pipeline for compliance assessment context."""
    
    async def gather_context(self, request, confidence_score: float) -> Optional[Dict[str, Any]]:
        """Gather compliance-related context."""
        context = {
            'type': 'compliance',
            'confidence': confidence_score,
            'gathered_at': datetime.utcnow().isoformat()
        }
        
        try:
            agent_id = self._extract_agent_id(request.arguments)
            
            # Gather compliance context
            tasks = [
                self._gather_policy_violations(agent_id),
                self._gather_configuration_status(agent_id),
                self._gather_audit_events(agent_id)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            context_data = {}
            result_keys = ['policy_violations', 'configuration_status', 'audit_events']
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    continue
                if result:
                    context_data[result_keys[i]] = result
            
            if context_data:
                context['data'] = context_data
                context['completeness'] = len(context_data) / 3.0
                return context
            
            return None
            
        except Exception as e:
            self.logger.error(f"Compliance context gathering failed: {str(e)}")
            return None
    
    async def _gather_policy_violations(self, agent_id: Optional[str] = None):
        """Gather policy violations."""
        # Placeholder - would check compliance rules
        return {
            'total_violations': 0,
            'critical_violations': [],
            'violation_categories': {}
        }
    
    async def _gather_configuration_status(self, agent_id: Optional[str] = None):
        """Gather configuration compliance status."""
        # Placeholder - would check configuration standards
        return {
            'compliance_score': 85,
            'failed_checks': [],
            'recommendations': []
        }
    
    async def _gather_audit_events(self, agent_id: Optional[str] = None):
        """Gather audit events."""
        # Placeholder - would gather audit logs
        return {
            'recent_events': [],
            'failed_logins': 0,
            'privilege_escalations': 0
        }


class ForensicPipeline(ContextPipeline):
    """Pipeline for forensic analysis context."""
    
    async def gather_context(self, request, confidence_score: float) -> Optional[Dict[str, Any]]:
        """Gather forensic analysis context."""
        context = {
            'type': 'forensic',
            'confidence': confidence_score,
            'gathered_at': datetime.utcnow().isoformat()
        }
        
        try:
            agent_id = self._extract_agent_id(request.arguments)
            time_range = self._extract_time_range(request.arguments)
            
            # Gather forensic context
            tasks = [
                self._gather_timeline_events(time_range, agent_id),
                self._gather_evidence_artifacts(agent_id),
                self._gather_correlation_data(time_range, agent_id)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            context_data = {}
            result_keys = ['timeline', 'artifacts', 'correlations']
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    continue
                if result:
                    context_data[result_keys[i]] = result
            
            if context_data:
                context['data'] = context_data
                context['completeness'] = len(context_data) / 3.0
                return context
            
            return None
            
        except Exception as e:
            self.logger.error(f"Forensic context gathering failed: {str(e)}")
            return None
    
    async def _gather_timeline_events(self, time_range: str, agent_id: Optional[str] = None):
        """Gather timeline events for reconstruction."""
        # Placeholder - would build forensic timeline
        return {
            'events': [],
            'event_types': {},
            'temporal_patterns': []
        }
    
    async def _gather_evidence_artifacts(self, agent_id: Optional[str] = None):
        """Gather digital evidence artifacts."""
        # Placeholder - would collect artifacts
        return {
            'file_artifacts': [],
            'registry_artifacts': [],
            'network_artifacts': []
        }
    
    async def _gather_correlation_data(self, time_range: str, agent_id: Optional[str] = None):
        """Gather data for event correlation."""
        # Placeholder - would perform correlation analysis
        return {
            'correlated_events': [],
            'relationship_graph': {},
            'causal_chains': []
        }