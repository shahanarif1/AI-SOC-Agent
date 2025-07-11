"""
Context Aggregation System

Automatically gathers comprehensive context for each prompt to provide
enhanced, intelligent responses without requiring explicit tool calls.
"""

import asyncio
import re
from typing import Dict, Any, Optional, List, Set, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import logging

from .cache import ContextCache, AsyncContextCache, CacheKeyBuilder
from .pipelines import ContextPipeline


@dataclass
class ContextRequest:
    """Represents a context gathering request."""
    prompt: str
    tool_name: str
    arguments: Dict[str, Any]
    priority: str = "medium"  # low, medium, high, critical
    timeout: float = 5.0


@dataclass
class ContextResult:
    """Represents the result of context gathering."""
    context_type: str
    data: Dict[str, Any]
    confidence: float  # 0.0 to 1.0
    completeness: float  # 0.0 to 1.0
    gathered_at: datetime
    sources: List[str]
    processing_time: float


class PromptPatternMatcher:
    """Analyzes prompts to determine context requirements."""
    
    def __init__(self):
        """Initialize pattern matchers."""
        self.patterns = {
            'incident': [
                r'(?i)\b(incident|attack|breach|compromise|intrusion)\b',
                r'(?i)\b(investigate|investigation|forensic|what happened)\b',
                r'(?i)\b(suspicious|malicious|threat|IOC)\b',
                r'(?i)\b(timeline|sequence|chain of events)\b'
            ],
            'hunting': [
                r'(?i)\b(hunt|hunting|search for|look for)\b',
                r'(?i)\b(IOC|indicator|suspicious activity)\b',
                r'(?i)\b(lateral movement|persistence|privilege escalation)\b',
                r'(?i)\b(anomaly|unusual|abnormal|outlier)\b'
            ],
            'compliance': [
                r'(?i)\b(compliance|audit|policy|regulation)\b',
                r'(?i)\b(PCI|HIPAA|SOX|GDPR|CIS)\b',
                r'(?i)\b(configuration|hardening|baseline)\b',
                r'(?i)\b(violation|non-compliant|failed check)\b'
            ],
            'forensic': [
                r'(?i)\b(forensic|evidence|artifact|trace)\b',
                r'(?i)\b(log analysis|timeline|reconstruction)\b',
                r'(?i)\b(root cause|attribution|analysis)\b',
                r'(?i)\b(correlation|relationship|connection)\b'
            ],
            'monitoring': [
                r'(?i)\b(monitor|monitoring|status|health)\b',
                r'(?i)\b(dashboard|overview|summary)\b',
                r'(?i)\b(performance|metrics|statistics)\b',
                r'(?i)\b(trend|pattern|baseline)\b'
            ]
        }
        
        self.entity_patterns = {
            'agent_id': r'\b([0-9a-fA-F]{3,8})\b',
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'hash': r'\b[a-fA-F0-9]{32,64}\b',
            'domain': r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            'process_name': r'\b\w+\.exe\b|\b\w+\.bin\b|\b\w+\.sh\b',
            'port': r'\bport\s+(\d+)\b|\b:(\d+)\b'
        }
    
    def analyze_prompt(self, prompt: str, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze prompt to determine context requirements.
        
        Returns:
            Dictionary with detected patterns, entities, and confidence scores
        """
        analysis = {
            'context_types': {},
            'entities': {},
            'priority': 'medium',
            'confidence': 0.0
        }
        
        # Detect context types
        for context_type, patterns in self.patterns.items():
            score = 0.0
            matches = []
            
            for pattern in patterns:
                found = re.findall(pattern, prompt)
                if found:
                    score += 1.0 / len(patterns)
                    matches.extend(found)
            
            if score > 0:
                analysis['context_types'][context_type] = {
                    'score': score,
                    'matches': matches
                }
        
        # Extract entities
        for entity_type, pattern in self.entity_patterns.items():
            matches = re.findall(pattern, prompt)
            if matches:
                analysis['entities'][entity_type] = matches
        
        # Add entities from tool arguments
        if 'agent_id' in arguments:
            analysis['entities']['agent_id'] = [arguments['agent_id']]
        
        # Determine priority based on keywords
        priority_keywords = {
            'critical': ['critical', 'urgent', 'emergency', 'breach', 'compromise'],
            'high': ['important', 'security', 'incident', 'attack', 'malicious'],
            'medium': ['investigate', 'check', 'review', 'analyze'],
            'low': ['status', 'summary', 'overview', 'general']
        }
        
        for priority, keywords in priority_keywords.items():
            for keyword in keywords:
                if re.search(rf'\b{keyword}\b', prompt, re.IGNORECASE):
                    analysis['priority'] = priority
                    break
            if analysis['priority'] != 'medium':
                break
        
        # Calculate overall confidence
        if analysis['context_types']:
            max_score = max(ctx['score'] for ctx in analysis['context_types'].values())
            analysis['confidence'] = min(max_score, 1.0)
        
        return analysis


class PromptContextAggregator:
    """Main context aggregation system."""
    
    def __init__(self, server_instance):
        """
        Initialize the context aggregator.
        
        Args:
            server_instance: Reference to the main WazuhMCPServer instance
        """
        self.server = server_instance
        self.logger = logging.getLogger(__name__)
        
        # Initialize cache
        cache_ttl = getattr(self.server.config, 'context_cache_ttl', 300)
        max_size = getattr(self.server.config, 'max_context_size', 1000)
        self.cache = AsyncContextCache(ContextCache(max_size=max_size, default_ttl=cache_ttl))
        
        # Initialize pattern matcher
        self.pattern_matcher = PromptPatternMatcher()
        
        # Initialize pipelines (will be set up in separate method)
        self.pipelines: Dict[str, ContextPipeline] = {}
        
        # Initialize adaptive components (Phase 5.2)
        try:
            from .adapters import DataAvailabilityDetector, AdaptiveResponseFormatter, ResponseQualityIndicator
            self.data_detector = DataAvailabilityDetector()
            self.response_formatter = AdaptiveResponseFormatter()
            self.quality_indicator = ResponseQualityIndicator()
            self.logger.info("Adaptive response components initialized")
        except ImportError as e:
            self.logger.warning(f"Adaptive components not available: {str(e)}")
            self.data_detector = None
            self.response_formatter = None
            self.quality_indicator = None
        
        # Initialize real-time updater (Phase 5.3)
        self.realtime_updater = None
        if getattr(self.server.config, 'enable_realtime_updates', False):
            try:
                from .updates import RealTimeContextUpdater
                self.realtime_updater = RealTimeContextUpdater(server_instance)
                self.logger.info("Real-time context updater initialized")
            except ImportError as e:
                self.logger.warning(f"Real-time updates not available: {str(e)}")
        
        # Feature flags
        self._enabled = getattr(self.server.config, 'enable_context_aggregation', False)
        self._adaptive_enabled = getattr(self.server.config, 'enable_adaptive_responses', False)
        self._realtime_enabled = getattr(self.server.config, 'enable_realtime_updates', False)
        
        # Performance settings
        self.timeout = getattr(self.server.config, 'enhancement_timeout', 5.0)
        self.max_concurrent_requests = 5
        
        # Statistics
        self.stats = {
            'requests_processed': 0,
            'cache_hits': 0,
            'pipeline_invocations': 0,
            'errors': 0,
            'average_processing_time': 0.0,
            'realtime_monitors': 0,
            'change_events': 0
        }
    
    def setup_pipelines(self):
        """Set up context pipelines - called after server initialization."""
        try:
            from .pipelines import (
                IncidentPipeline, ThreatHuntingPipeline, 
                CompliancePipeline, ForensicPipeline
            )
            
            self.pipelines = {
                'incident': IncidentPipeline(self.server, self.cache),
                'hunting': ThreatHuntingPipeline(self.server, self.cache),
                'compliance': CompliancePipeline(self.server, self.cache),
                'forensic': ForensicPipeline(self.server, self.cache)
            }
            
            self.logger.info("Context aggregation pipelines initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize context pipelines: {str(e)}")
            # Graceful degradation - system still works without pipelines
            self.pipelines = {}
    
    async def enhance_response(self, tool_name: str, arguments: Dict[str, Any], 
                             original_response: Any, prompt: str = "") -> Any:
        """
        Enhance a tool response with additional context, adaptive formatting, and real-time monitoring.
        
        Args:
            tool_name: Name of the tool being executed
            arguments: Tool arguments
            original_response: Original tool response
            prompt: User prompt (if available)
            
        Returns:
            Enhanced response or original response if enhancement fails
        """
        # Safety check - if prompt enhancement is disabled, return original
        if not getattr(self.server.config, 'enable_prompt_enhancement', False):
            return original_response
        
        if not getattr(self.server.config, 'enable_context_aggregation', False):
            return original_response
        
        start_time = datetime.utcnow()
        
        try:
            # Create context request
            context_request = ContextRequest(
                prompt=prompt,
                tool_name=tool_name,
                arguments=arguments,
                timeout=self.timeout
            )
            
            # Gather context
            context = await self._gather_context(context_request)
            
            # Enhance response if context was gathered
            if context:
                enhanced_response = await self._enhance_with_context(
                    original_response, context, prompt
                )
                
                # Start real-time monitoring for incident-related requests (Phase 5.3)
                await self._maybe_start_realtime_monitoring(context_request, context)
                
                # Add processing metadata
                processing_time = (datetime.utcnow() - start_time).total_seconds()
                self._update_stats(processing_time, True)
                
                return enhanced_response
            
            return original_response
            
        except asyncio.TimeoutError:
            self.logger.warning(f"Context aggregation timeout for {tool_name}")
            self._update_stats(self.timeout, False)
            return original_response
            
        except Exception as e:
            self.logger.error(f"Context aggregation error for {tool_name}: {str(e)}")
            self._update_stats(0, False)
            return original_response
    
    async def _gather_context(self, request: ContextRequest) -> Optional[Dict[str, Any]]:
        """Gather context based on the request."""
        try:
            # Analyze the prompt to determine context requirements
            analysis = self.pattern_matcher.analyze_prompt(
                request.prompt, request.tool_name, request.arguments
            )
            
            if not analysis['context_types']:
                return None
            
            # Gather context from relevant pipelines
            context_tasks = []
            for context_type, type_info in analysis['context_types'].items():
                if context_type in self.pipelines:
                    pipeline = self.pipelines[context_type]
                    task = asyncio.create_task(
                        pipeline.gather_context(request, type_info['score'])
                    )
                    context_tasks.append((context_type, task))
            
            if not context_tasks:
                return None
            
            # Wait for context gathering with timeout
            context_results = {}
            async with asyncio.timeout(request.timeout):
                for context_type, task in context_tasks:
                    try:
                        result = await task
                        if result:
                            context_results[context_type] = result
                    except Exception as e:
                        self.logger.debug(f"Pipeline {context_type} failed: {str(e)}")
            
            return context_results if context_results else None
            
        except asyncio.TimeoutError:
            self.logger.warning("Context gathering timeout")
            return None
        except Exception as e:
            self.logger.error(f"Context gathering error: {str(e)}")
            return None
    
    async def _enhance_with_context(self, original_response: Any, 
                                   context: Dict[str, Any], prompt: str = "") -> Any:
        """Enhance response with gathered context and adaptive formatting."""
        try:
            # If response is a list of TextContent, enhance the first one
            if isinstance(original_response, list) and len(original_response) > 0:
                import json
                from mcp import types
                
                # Parse the original response
                original_text = original_response[0].text
                try:
                    original_data = json.loads(original_text)
                except json.JSONDecodeError:
                    # If not JSON, return original
                    return original_response
                
                # Apply adaptive formatting if enabled (Phase 5.2)
                enhanced_data = original_data.copy()
                
                if self._adaptive_enabled and self.data_detector and self.response_formatter:
                    # Assess data quality
                    quality_assessment = self.data_detector.assess_data_quality(context)
                    
                    # Apply adaptive formatting
                    enhanced_data = self.response_formatter.format_response(enhanced_data, quality_assessment)
                    
                    # Add quality indicators if quality indicator is available
                    if self.quality_indicator:
                        quality_indicators = self.quality_indicator.generate_indicators(enhanced_data, context)
                        enhanced_data['_quality_metrics'] = quality_indicators
                
                # Add context to the response
                enhanced_data['_context'] = context
                enhanced_data['_enhancement_metadata'] = {
                    'enhanced': True,
                    'context_types': list(context.keys()),
                    'enhancement_timestamp': datetime.utcnow().isoformat(),
                    'adaptive_formatting': self._adaptive_enabled and self.response_formatter is not None,
                    'realtime_monitoring': self._realtime_enabled and self.realtime_updater is not None
                }
                
                # Return enhanced response
                return [types.TextContent(
                    type="text",
                    text=json.dumps(enhanced_data, indent=2, default=str)
                )]
            
            return original_response
            
        except Exception as e:
            self.logger.error(f"Response enhancement error: {str(e)}")
            return original_response
    
    def _update_stats(self, processing_time: float, success: bool):
        """Update performance statistics."""
        self.stats['requests_processed'] += 1
        
        if success:
            # Update average processing time
            current_avg = self.stats['average_processing_time']
            count = self.stats['requests_processed']
            self.stats['average_processing_time'] = (
                (current_avg * (count - 1) + processing_time) / count
            )
        else:
            self.stats['errors'] += 1
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get aggregator statistics."""
        cache_stats = await self.cache.get_stats()
        
        return {
            'aggregator_stats': self.stats.copy(),
            'cache_stats': cache_stats,
            'pipelines_available': list(self.pipelines.keys()),
            'enabled': getattr(self.server.config, 'enable_context_aggregation', False)
        }
    
    async def invalidate_cache(self, namespace: Optional[str] = None):
        """Invalidate cached context data."""
        if namespace:
            await self.cache.invalidate(namespace)
        else:
            self.cache.cache.clear()
    
    def is_enabled(self) -> bool:
        """Check if context aggregation is enabled."""
        return (getattr(self.server.config, 'enable_prompt_enhancement', False) and
                getattr(self.server.config, 'enable_context_aggregation', False))
    
    async def _maybe_start_realtime_monitoring(self, request: ContextRequest, context: Dict[str, Any]) -> None:
        """Start real-time monitoring if conditions are met (Phase 5.3)."""
        if not self._realtime_enabled or not self.realtime_updater:
            return
        
        try:
            # Analyze prompt to determine if real-time monitoring is needed
            analysis = self.pattern_matcher.analyze_prompt(
                request.prompt, request.tool_name, request.arguments
            )
            
            # Start monitoring for incident and hunting contexts
            monitoring_contexts = ['incident', 'hunting', 'forensic']
            should_monitor = any(ctx in analysis['context_types'] for ctx in monitoring_contexts)
            
            if should_monitor:
                # Determine priority from analysis
                priority = analysis.get('priority', 'medium')
                
                # Generate unique context ID
                import hashlib
                context_id = hashlib.md5(
                    f"{request.tool_name}_{request.arguments.get('agent_id', 'system')}_{datetime.utcnow().isoformat()}"
                    .encode()
                ).hexdigest()[:12]
                
                # Start monitoring
                context_type = next((ctx for ctx in monitoring_contexts if ctx in analysis['context_types']), 'incident')
                await self.realtime_updater.start_monitoring(
                    context_id=context_id,
                    context_type=context_type,
                    priority=priority,
                    initial_context=context
                )
                
                # Update statistics
                self.stats['realtime_monitors'] += 1
                
                self.logger.info(f"Started real-time monitoring for {context_type} context: {context_id}")
        
        except Exception as e:
            self.logger.error(f"Failed to start real-time monitoring: {str(e)}")
    
    async def get_realtime_stats(self) -> Dict[str, Any]:
        """Get real-time monitoring statistics."""
        if not self.realtime_updater:
            return {'realtime_monitoring': 'disabled'}
        
        return {
            'realtime_monitoring': 'enabled',
            'monitoring_stats': self.realtime_updater.get_monitoring_stats(),
            'active_contexts': len(self.realtime_updater.active_contexts)
        }
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        if self.realtime_updater:
            await self.realtime_updater.cleanup()
        
        # Clear cache
        self.cache.cache.clear()
        
        self.logger.info("Context aggregator cleanup completed")