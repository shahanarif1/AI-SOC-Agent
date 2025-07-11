"""
Test Phase 5.2: Dynamic Prompt Adaptation
Tests for adaptive response formatting and data quality assessment.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, AsyncMock

# Add src to path for testing
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from wazuh_mcp_server.prompt_enhancement.adapters import (
        DataAvailabilityDetector,
        AdaptiveResponseFormatter, 
        ResponseQualityIndicator
    )
    ADAPTERS_AVAILABLE = True
except ImportError:
    ADAPTERS_AVAILABLE = False


@pytest.fixture
def sample_context():
    """Create sample context data for testing."""
    return {
        'alerts': {
            'data': [
                {'id': '1', 'level': 10, 'description': 'Critical alert'},
                {'id': '2', 'level': 8, 'description': 'High alert'}
            ],
            'total': 2,
            'confidence': 0.9,
            'completeness': 0.8
        },
        'agent_health': {
            'data': {
                'total_agents': 5,
                'active_agents': 4,
                'inactive_agents': 1
            },
            'confidence': 0.85,
            'completeness': 0.75
        },
        'vulnerabilities': {
            'data': {
                'critical': 2,
                'high': 5,
                'medium': 10
            },
            'confidence': 0.8,
            'completeness': 0.7
        }
    }


@pytest.fixture
def sample_response():
    """Create sample response data for testing."""
    return {
        'alerts': [
            {'id': '1', 'level': 10, 'description': 'Critical alert'},
            {'id': '2', 'level': 8, 'description': 'High alert'}
        ],
        'summary': {
            'total_alerts': 2,
            'critical_count': 1,
            'high_count': 1
        }
    }


@pytest.mark.skipif(not ADAPTERS_AVAILABLE, reason="Phase 5.2 adapters not available")
class TestDataAvailabilityDetector:
    """Test data availability detection and quality assessment."""
    
    def test_detector_initialization(self):
        """Test detector initialization."""
        detector = DataAvailabilityDetector()
        
        assert detector.source_weights is not None
        assert 'alerts' in detector.source_weights
        assert 'agent_health' in detector.source_weights
        assert detector.quality_thresholds is not None
    
    def test_assess_data_quality_high_quality(self, sample_context):
        """Test quality assessment for high-quality data."""
        detector = DataAvailabilityDetector()
        
        # Enhance context to ensure high quality
        enhanced_context = sample_context.copy()
        enhanced_context['processes'] = {
            'data': {'count': 50, 'suspicious': 2},
            'confidence': 0.9,
            'completeness': 0.85
        }
        enhanced_context['ports'] = {
            'data': {'open_ports': 15, 'suspicious': 1},
            'confidence': 0.88,
            'completeness': 0.82
        }
        
        assessment = detector.assess_data_quality(enhanced_context)
        
        assert 'completeness' in assessment
        assert 'confidence' in assessment
        assert 'source_coverage' in assessment
        assert assessment['completeness'] >= 0.80  # Should be high quality
        assert assessment['confidence'] > 0
    
    def test_assess_data_quality_partial(self, sample_context):
        """Test quality assessment for partial data."""
        detector = DataAvailabilityDetector()
        
        # Use only some sources for partial quality
        partial_context = {
            'alerts': sample_context['alerts'],
            'agent_health': sample_context['agent_health']
        }
        
        assessment = detector.assess_data_quality(partial_context)
        
        assert 'completeness' in assessment
        assert assessment['completeness'] >= 0.50  # Should be partial quality
        assert assessment['completeness'] < 0.80
    
    def test_assess_data_quality_minimal(self):
        """Test quality assessment for minimal data."""
        detector = DataAvailabilityDetector()
        
        minimal_context = {
            'alerts': {
                'data': [{'id': '1', 'level': 5}],
                'confidence': 0.6,
                'completeness': 0.4
            }
        }
        
        assessment = detector.assess_data_quality(minimal_context)
        
        assert 'completeness' in assessment
        assert assessment['completeness'] < 0.60  # Should be minimal quality
    
    def test_assess_empty_context(self):
        """Test quality assessment for empty context."""
        detector = DataAvailabilityDetector()
        
        assessment = detector.assess_data_quality({})
        
        assert assessment['completeness'] == 0.0
        assert assessment['confidence'] == 0.0
        assert assessment['source_coverage'] == 0.0


@pytest.mark.skipif(not ADAPTERS_AVAILABLE, reason="Phase 5.2 adapters not available")
class TestAdaptiveResponseFormatter:
    """Test adaptive response formatting based on data quality."""
    
    def test_formatter_initialization(self):
        """Test formatter initialization."""
        formatter = AdaptiveResponseFormatter()
        
        assert formatter.quality_thresholds is not None
        assert len(formatter.quality_thresholds) == 3  # high, partial, minimal
    
    def test_format_response_high_quality(self, sample_response):
        """Test response formatting for high-quality data."""
        formatter = AdaptiveResponseFormatter()
        
        quality_assessment = {
            'completeness': 0.85,
            'confidence': 0.9,
            'source_coverage': 0.8,
            'quality_level': 'high'
        }
        
        formatted = formatter.format_response(sample_response, quality_assessment)
        
        # High quality should include detailed formatting
        assert '_formatting_level' in formatted
        assert formatted['_formatting_level'] == 'comprehensive'
        assert '_data_quality' in formatted
    
    def test_format_response_partial_quality(self, sample_response):
        """Test response formatting for partial-quality data."""
        formatter = AdaptiveResponseFormatter()
        
        quality_assessment = {
            'completeness': 0.65,
            'confidence': 0.7,
            'source_coverage': 0.6,
            'quality_level': 'partial'
        }
        
        formatted = formatter.format_response(sample_response, quality_assessment)
        
        # Partial quality should include gap identification
        assert '_formatting_level' in formatted
        assert formatted['_formatting_level'] == 'partial_with_gaps'
        assert '_identified_gaps' in formatted
    
    def test_format_response_minimal_quality(self, sample_response):
        """Test response formatting for minimal-quality data."""
        formatter = AdaptiveResponseFormatter()
        
        quality_assessment = {
            'completeness': 0.35,
            'confidence': 0.4,
            'source_coverage': 0.3,
            'quality_level': 'minimal'
        }
        
        formatted = formatter.format_response(sample_response, quality_assessment)
        
        # Minimal quality should include guidance
        assert '_formatting_level' in formatted
        assert formatted['_formatting_level'] == 'minimal_with_guidance'
        assert '_improvement_suggestions' in formatted
    
    def test_identify_data_gaps(self):
        """Test data gap identification."""
        formatter = AdaptiveResponseFormatter()
        
        partial_context = {
            'alerts': {'completeness': 0.8},
            'agent_health': {'completeness': 0.6}
            # Missing vulnerabilities, processes, ports
        }
        
        gaps = formatter._identify_data_gaps(partial_context)
        
        assert 'missing_sources' in gaps
        assert 'vulnerabilities' in gaps['missing_sources']
        assert 'processes' in gaps['missing_sources']
        assert 'ports' in gaps['missing_sources']
    
    def test_generate_improvement_suggestions(self):
        """Test improvement suggestion generation."""
        formatter = AdaptiveResponseFormatter()
        
        minimal_context = {
            'alerts': {'completeness': 0.3, 'confidence': 0.4}
        }
        
        suggestions = formatter._generate_improvement_suggestions(minimal_context)
        
        assert isinstance(suggestions, list)
        assert len(suggestions) > 0
        assert any('agent' in suggestion.lower() for suggestion in suggestions)


@pytest.mark.skipif(not ADAPTERS_AVAILABLE, reason="Phase 5.2 adapters not available")
class TestResponseQualityIndicator:
    """Test response quality indicator generation."""
    
    def test_indicator_initialization(self):
        """Test indicator initialization."""
        indicator = ResponseQualityIndicator()
        assert indicator is not None
    
    def test_generate_indicators_high_quality(self, sample_response, sample_context):
        """Test indicator generation for high-quality responses."""
        indicator = ResponseQualityIndicator()
        
        indicators = indicator.generate_indicators(sample_response, sample_context)
        
        assert 'data_completeness' in indicators
        assert 'confidence_score' in indicators
        assert 'enhancement_level' in indicators
        assert 'reliability_score' in indicators
        
        # Should be high quality based on sample data
        assert indicators['data_completeness'] > 0.7
        assert indicators['confidence_score'] > 0.7
    
    def test_generate_indicators_with_metadata(self, sample_response, sample_context):
        """Test indicator generation includes metadata."""
        indicator = ResponseQualityIndicator()
        
        indicators = indicator.generate_indicators(sample_response, sample_context)
        
        assert 'sources_available' in indicators
        assert 'timestamp' in indicators
        assert isinstance(indicators['sources_available'], list)
        assert len(indicators['sources_available']) > 0


@pytest.mark.skipif(not ADAPTERS_AVAILABLE, reason="Phase 5.2 adapters not available")
class TestAdaptiveFormattingIntegration:
    """Test integrated adaptive formatting workflow."""
    
    def test_full_adaptive_workflow(self, sample_context, sample_response):
        """Test complete adaptive formatting workflow."""
        detector = DataAvailabilityDetector()
        formatter = AdaptiveResponseFormatter()
        indicator = ResponseQualityIndicator()
        
        # Step 1: Assess data quality
        quality_assessment = detector.assess_data_quality(sample_context)
        
        # Step 2: Format response adaptively
        formatted_response = formatter.format_response(sample_response, quality_assessment)
        
        # Step 3: Generate quality indicators
        quality_indicators = indicator.generate_indicators(formatted_response, sample_context)
        
        # Verify workflow results
        assert '_formatting_level' in formatted_response
        assert '_data_quality' in formatted_response
        assert 'data_completeness' in quality_indicators
        assert 'enhancement_level' in quality_indicators
    
    def test_workflow_with_empty_context(self, sample_response):
        """Test workflow handles empty context gracefully."""
        detector = DataAvailabilityDetector()
        formatter = AdaptiveResponseFormatter()
        indicator = ResponseQualityIndicator()
        
        empty_context = {}
        
        # Should not raise exceptions
        quality_assessment = detector.assess_data_quality(empty_context)
        formatted_response = formatter.format_response(sample_response, quality_assessment)
        quality_indicators = indicator.generate_indicators(formatted_response, empty_context)
        
        # Should indicate minimal quality
        assert quality_assessment['completeness'] == 0.0
        assert formatted_response['_formatting_level'] == 'minimal_with_guidance'
        assert quality_indicators['data_completeness'] == 0.0


if __name__ == "__main__":
    if ADAPTERS_AVAILABLE:
        print("Running Phase 5.2 adapter tests...")
        pytest.main([__file__, "-v"])
    else:
        print("Phase 5.2 adapters not available for testing")