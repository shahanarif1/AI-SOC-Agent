"""
Prompt Enhancement System (Phase 5)

This module provides intelligent context aggregation, adaptive response formatting,
and real-time updates to enhance the quality and comprehensiveness of MCP responses.

All enhancements are optional and disabled by default to maintain backward compatibility.
"""

from .context_aggregator import PromptContextAggregator
from .cache import ContextCache
from .pipelines import (
    IncidentPipeline,
    ThreatHuntingPipeline, 
    CompliancePipeline,
    ForensicPipeline
)
from .adapters import AdaptiveResponseFormatter, DataAvailabilityDetector
from .updates import RealTimeContextUpdater

__all__ = [
    'PromptContextAggregator',
    'ContextCache',
    'IncidentPipeline',
    'ThreatHuntingPipeline',
    'CompliancePipeline', 
    'ForensicPipeline',
    'AdaptiveResponseFormatter',
    'DataAvailabilityDetector',
    'RealTimeContextUpdater'
]