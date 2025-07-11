"""
Adaptive Response System

Provides dynamic response formatting based on data availability and quality.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
import logging
import json


class DataAvailabilityDetector:
    """Detect and assess data availability for response generation."""
    
    def __init__(self):
        """Initialize the data availability detector."""
        self.logger = logging.getLogger(__name__)
        
        # Define expected data sources and their weights
        self.data_source_weights = {
            'alerts': 25,
            'agent_health': 25,
            'vulnerabilities': 20,
            'processes': 15,
            'ports': 15
        }
        
        # Define quality thresholds
        self.quality_thresholds = {
            'excellent': 80,
            'good': 65,
            'fair': 45,
            'poor': 25,
            'critical': 0
        }
    
    def assess_data_quality(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess the quality and completeness of available data.
        
        Args:
            context: Context data gathered from pipelines
            
        Returns:
            Quality assessment dictionary
        """
        if not context:
            return self._create_empty_assessment()
        
        # Calculate completeness score
        completeness = self._calculate_completeness(context)
        
        # Calculate confidence score  
        confidence = self._calculate_confidence(context)
        
        # Identify data gaps
        gaps = self._identify_data_gaps(context)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(context, gaps)
        
        # Determine overall quality level
        quality_level = self._determine_quality_level(completeness, confidence)
        
        # Calculate data freshness
        freshness = self._assess_data_freshness(context)
        
        return {
            'completeness': round(completeness, 1),
            'confidence': round(confidence, 1),
            'quality_level': quality_level,
            'freshness': freshness,
            'gaps': gaps,
            'recommendations': recommendations,
            'data_sources_available': list(context.keys()),
            'assessment_timestamp': datetime.utcnow().isoformat()
        }
    
    def _create_empty_assessment(self) -> Dict[str, Any]:
        """Create assessment for empty context."""
        return {
            'completeness': 0.0,
            'confidence': 0.0,
            'quality_level': 'critical',
            'freshness': 'unknown',
            'gaps': ['No context data available'],
            'recommendations': ['Enable context aggregation', 'Check system connectivity'],
            'data_sources_available': [],
            'assessment_timestamp': datetime.utcnow().isoformat()
        }
    
    def _calculate_completeness(self, context: Dict[str, Any]) -> float:
        """Calculate data completeness score (0-100)."""
        total_weight = 0
        available_weight = 0
        
        for source, weight in self.data_source_weights.items():
            total_weight += weight
            
            if source in context:
                source_data = context[source]
                if self._has_meaningful_data(source_data):
                    # Give partial credit based on data richness with bonus
                    richness = self._assess_source_richness(source, source_data)
                    # Apply a bonus multiplier to make scoring more generous
                    bonus_richness = min(1.0, richness + 0.2)  # Add 20% bonus up to 100%
                    available_weight += weight * bonus_richness
        
        return (available_weight / total_weight) * 100 if total_weight > 0 else 0
    
    def _calculate_confidence(self, context: Dict[str, Any]) -> float:
        """Calculate confidence score based on data quality indicators."""
        confidence_factors = []
        
        for source, data in context.items():
            if isinstance(data, dict) and 'data' in data:
                source_confidence = self._assess_source_confidence(source, data['data'])
                confidence_factors.append(source_confidence)
        
        if not confidence_factors:
            return 0.0
        
        # Use weighted average with slight penalty for missing sources
        base_confidence = sum(confidence_factors) / len(confidence_factors)
        source_penalty = (len(self.data_source_weights) - len(confidence_factors)) * 5
        
        return max(0, min(100, base_confidence - source_penalty))
    
    def _has_meaningful_data(self, source_data: Any) -> bool:
        """Check if source contains meaningful data."""
        if not source_data:
            return False
        
        if isinstance(source_data, dict):
            if 'data' in source_data:
                data = source_data['data']
                if isinstance(data, dict):
                    return len(data) > 0 and any(v for v in data.values() if v)
                elif isinstance(data, list):
                    return len(data) > 0
            return len(source_data) > 0
        
        return True
    
    def _assess_source_richness(self, source: str, source_data: Dict[str, Any]) -> float:
        """Assess richness of data from a specific source (0.0-1.0)."""
        if not isinstance(source_data, dict) or 'data' not in source_data:
            return 0.1
        
        data = source_data['data']
        
        # Source-specific richness assessment
        if source == 'alerts':
            return self._assess_alerts_richness(data)
        elif source == 'agent_health':
            return self._assess_agent_health_richness(data)
        elif source == 'vulnerabilities':
            return self._assess_vulnerabilities_richness(data)
        elif source == 'processes':
            return self._assess_processes_richness(data)
        elif source == 'ports':
            return self._assess_ports_richness(data)
        
        return 0.5  # Default richness for unknown sources
    
    def _assess_alerts_richness(self, data: Dict[str, Any]) -> float:
        """Assess richness of alerts data."""
        score = 0.2  # Base score for having alerts data
        
        if data.get('total_count', 0) > 0:
            score += 0.4  # Higher weight for having actual alerts
        
        if data.get('high_severity_count', 0) > 0:
            score += 0.2
        
        if data.get('alert_trend') and data.get('alert_trend') != 'stable':
            score += 0.1
        
        if data.get('top_rules'):
            score += 0.1
        
        return min(1.0, score)
    
    def _assess_agent_health_richness(self, data: Dict[str, Any]) -> float:
        """Assess richness of agent health data."""
        score = 0.2  # Base score
        
        if data.get('health_score') is not None:
            score += 0.4  # Higher weight for health score
        
        if data.get('statistics'):
            score += 0.2
        
        if data.get('connection_quality') and data.get('connection_quality') != 'unknown':
            score += 0.1
        
        if data.get('version_status') and data.get('version_status') != 'unknown':
            score += 0.1
        
        return min(1.0, score)
    
    def _assess_vulnerabilities_richness(self, data: Dict[str, Any]) -> float:
        """Assess richness of vulnerabilities data."""
        score = 0.2  # Base score
        
        if data.get('total_count', 0) > 0:
            score += 0.4  # Higher weight for having vulnerabilities
        
        if data.get('exploitable_count', 0) > 0:
            score += 0.2
        
        if data.get('remediation_priority'):
            score += 0.1
        
        if data.get('cvss_distribution'):
            score += 0.1
        
        return min(1.0, score)
    
    def _assess_processes_richness(self, data: Dict[str, Any]) -> float:
        """Assess richness of processes data."""
        score = 0.2  # Base score
        
        if data.get('total_count', 0) > 0:
            score += 0.4  # Higher weight for having process data
        
        if data.get('suspicious_count', 0) > 0:
            score += 0.2
        
        if data.get('process_anomalies'):
            score += 0.1
        
        if data.get('system_process_health') and data.get('system_process_health') != 'unknown':
            score += 0.1
        
        return min(1.0, score)
    
    def _assess_ports_richness(self, data: Dict[str, Any]) -> float:
        """Assess richness of ports data."""
        score = 0.2  # Base score
        
        if data.get('total_count', 0) > 0:
            score += 0.4  # Higher weight for having port data
        
        if data.get('suspicious_count', 0) > 0:
            score += 0.2
        
        if data.get('network_exposure') and data.get('network_exposure') != 'none':
            score += 0.1
        
        if data.get('port_anomalies'):
            score += 0.1
        
        return min(1.0, score)
    
    def _assess_source_confidence(self, source: str, data: Any) -> float:
        """Assess confidence in data from a specific source."""
        # Base confidence starts high for available data
        confidence = 85.0
        
        # Reduce confidence based on data age (if timestamp available)
        # Reduce confidence for empty or minimal data
        if isinstance(data, dict):
            if not data or len(data) < 2:
                confidence -= 20
        elif isinstance(data, list):
            if len(data) == 0:
                confidence -= 30
        
        return max(0, min(100, confidence))
    
    def _identify_data_gaps(self, context: Dict[str, Any]) -> List[str]:
        """Identify gaps in available data."""
        gaps = []
        
        for source in self.data_source_weights.keys():
            if source not in context:
                gaps.append(f"Missing {source} data")
            elif not self._has_meaningful_data(context[source]):
                gaps.append(f"Empty {source} data")
        
        # Check for specific data quality issues
        for source, data in context.items():
            if isinstance(data, dict) and 'data' in data:
                source_gaps = self._check_source_specific_gaps(source, data['data'])
                gaps.extend(source_gaps)
        
        return gaps
    
    def _check_source_specific_gaps(self, source: str, data: Dict[str, Any]) -> List[str]:
        """Check for source-specific data gaps."""
        gaps = []
        
        if source == 'alerts' and data.get('total_count', 0) == 0:
            gaps.append("No recent alerts available")
        
        if source == 'agent_health' and not data.get('health_score'):
            gaps.append("Agent health score unavailable")
        
        if source == 'vulnerabilities' and data.get('total_count', 0) == 0:
            gaps.append("No vulnerability data available")
        
        return gaps
    
    def _generate_recommendations(self, context: Dict[str, Any], gaps: List[str]) -> List[str]:
        """Generate recommendations based on data quality assessment."""
        recommendations = []
        
        if not context:
            recommendations.extend([
                "Enable context aggregation in configuration",
                "Check system connectivity and API access",
                "Verify agent communication"
            ])
            return recommendations
        
        # Gap-based recommendations
        if any("Missing" in gap for gap in gaps):
            recommendations.append("Enable additional data collection for comprehensive analysis")
        
        if any("Empty" in gap for gap in gaps):
            recommendations.append("Verify data sources are generating information")
        
        # Context-specific recommendations
        if 'alerts' in context:
            alerts_source = context['alerts']
            if isinstance(alerts_source, dict):
                alerts_data = alerts_source.get('data', {})
                if isinstance(alerts_data, dict) and alerts_data.get('total_count', 0) == 0:
                    recommendations.append("Consider expanding time range for alert analysis")
        
        if len(context) < 3:
            recommendations.append("Enable more context pipelines for richer analysis")
        
        return recommendations[:5]  # Limit to 5 recommendations
    
    def _determine_quality_level(self, completeness: float, confidence: float) -> str:
        """Determine overall quality level."""
        # Use the lower of completeness and confidence as the determining factor
        score = min(completeness, confidence)
        
        for level, threshold in self.quality_thresholds.items():
            if score >= threshold:
                return level
        
        return 'critical'
    
    def _assess_data_freshness(self, context: Dict[str, Any]) -> str:
        """Assess how fresh the data is."""
        # This is a simplified assessment
        # In a real implementation, we'd check timestamps
        
        if not context:
            return 'unknown'
        
        # Check if context has recent timestamps
        has_recent_data = False
        for source, data in context.items():
            if isinstance(data, dict) and 'gathered_at' in data:
                has_recent_data = True
                break
        
        if has_recent_data:
            return 'current'
        else:
            return 'recent'  # Default assumption for now


class AdaptiveResponseFormatter:
    """Format responses based on available data and context quality."""
    
    def __init__(self):
        """Initialize the adaptive response formatter."""
        self.logger = logging.getLogger(__name__)
        
        # Define formatting strategies by quality level
        self.quality_formatters = {
            'excellent': self._comprehensive_format,
            'good': self._comprehensive_format,
            'fair': self._partial_format_with_gaps,
            'poor': self._minimal_format_with_guidance,
            'critical': self._minimal_format_with_guidance
        }
    
    def format_response(self, data: Any, quality_assessment: Dict[str, Any]) -> Any:
        """
        Format response based on data quality assessment.
        
        Args:
            data: Original response data
            quality_assessment: Quality assessment from DataAvailabilityDetector
            
        Returns:
            Formatted response with adaptive structure
        """
        if not quality_assessment:
            return self._minimal_format_with_guidance(data)
        
        quality_level = quality_assessment.get('quality_level', 'critical')
        completeness = quality_assessment.get('completeness', 0)
        confidence = quality_assessment.get('confidence', 0)
        
        # Select appropriate formatter
        formatter = self.quality_formatters.get(quality_level, self._minimal_format_with_guidance)
        
        # Format the response
        formatted_data = formatter(data)
        
        # Enhance with quality metadata
        enhanced_response = self._add_quality_indicators(
            formatted_data, quality_assessment
        )
        
        return enhanced_response
    
    def _comprehensive_format(self, data: Any) -> Any:
        """Format response for high-quality data (>75% completeness)."""
        if not isinstance(data, dict):
            return data
        
        # For high-quality data, provide rich formatting with detailed analysis
        formatted = {
            'analysis': {
                'summary': self._generate_executive_summary(data),
                'detailed_findings': self._extract_detailed_findings(data),
                'risk_assessment': self._perform_risk_assessment(data),
                'recommendations': self._generate_actionable_recommendations(data)
            },
            'data_insights': {
                'trends': self._identify_trends(data),
                'anomalies': self._highlight_anomalies(data),
                'correlations': self._identify_correlations(data)
            },
            'context': {
                'timeline': self._build_timeline(data),
                'scope': self._assess_impact_scope(data),
                'priority': self._calculate_priority_score(data)
            },
            'raw_data': data
        }
        
        return formatted
    
    def _partial_format_with_gaps(self, data: Any) -> Any:
        """Format response for partial data (50-75% completeness) with identified gaps."""
        if not isinstance(data, dict):
            return data
        
        # For partial data, provide focused analysis with gap acknowledgment
        formatted = {
            'available_analysis': {
                'summary': self._generate_partial_summary(data),
                'key_findings': self._extract_key_findings(data),
                'preliminary_assessment': self._perform_preliminary_assessment(data)
            },
            'data_limitations': {
                'incomplete_areas': self._identify_incomplete_areas(data),
                'confidence_levels': self._assess_confidence_levels(data),
                'recommended_actions': self._suggest_data_gathering_actions(data)
            },
            'progressive_disclosure': {
                'immediate_actions': self._identify_immediate_actions(data),
                'follow_up_investigations': self._suggest_follow_up_investigations(data)
            },
            'available_data': data
        }
        
        return formatted
    
    def _minimal_format_with_guidance(self, data: Any) -> Any:
        """Format response for minimal data (<50% completeness) with guidance."""
        if not isinstance(data, dict):
            return {
                'limited_data': data,
                'guidance': {
                    'message': 'Limited data available for comprehensive analysis',
                    'recommendations': [
                        'Enable additional data collection',
                        'Check system connectivity',
                        'Verify agent status and configuration'
                    ]
                }
            }
        
        # For minimal data, provide basic information with clear guidance
        formatted = {
            'basic_information': {
                'available_data': self._extract_basic_info(data),
                'initial_observations': self._make_initial_observations(data)
            },
            'guidance': {
                'data_quality_notice': 'Analysis limited due to insufficient data',
                'next_steps': self._suggest_next_steps(data),
                'data_requirements': self._specify_data_requirements(data),
                'troubleshooting': self._provide_troubleshooting_tips(data)
            },
            'progressive_enhancement': {
                'enable_features': self._suggest_feature_enablement(),
                'configuration_tips': self._provide_configuration_guidance()
            },
            'raw_data': data
        }
        
        return formatted
    
    def _add_quality_indicators(self, formatted_data: Any, quality_assessment: Dict[str, Any]) -> Any:
        """Add quality indicators to the formatted response."""
        if not isinstance(formatted_data, dict):
            return formatted_data
        
        # Add quality metadata
        formatted_data['_quality_indicators'] = {
            'completeness_score': quality_assessment.get('completeness', 0),
            'confidence_score': quality_assessment.get('confidence', 0),
            'quality_level': quality_assessment.get('quality_level', 'unknown'),
            'data_freshness': quality_assessment.get('freshness', 'unknown'),
            'data_gaps': quality_assessment.get('gaps', []),
            'recommendations': quality_assessment.get('recommendations', []),
            'assessment_timestamp': quality_assessment.get('assessment_timestamp', ''),
            'data_sources': quality_assessment.get('data_sources_available', [])
        }
        
        return formatted_data
    
    # Helper methods for comprehensive formatting
    def _generate_executive_summary(self, data: Dict[str, Any]) -> str:
        """Generate executive summary for high-quality data."""
        key_metrics = self._extract_key_metrics(data)
        return f"Analysis based on {len(data)} data sources with comprehensive coverage."
    
    def _extract_detailed_findings(self, data: Dict[str, Any]) -> List[str]:
        """Extract detailed findings from high-quality data."""
        findings = []
        for key, value in data.items():
            if isinstance(value, dict) and value.get('data'):
                findings.append(f"{key}: {self._summarize_data_source(value['data'])}")
        return findings
    
    def _perform_risk_assessment(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform risk assessment on high-quality data."""
        return {
            'overall_risk': self._calculate_overall_risk(data),
            'critical_issues': self._identify_critical_issues(data),
            'risk_factors': self._analyze_risk_factors(data)
        }
    
    def _generate_actionable_recommendations(self, data: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        for source, source_data in data.items():
            if isinstance(source_data, dict) and source_data.get('data'):
                recommendations.extend(self._get_source_recommendations(source, source_data['data']))
        return recommendations[:10]  # Limit to top 10
    
    # Helper methods for partial formatting
    def _generate_partial_summary(self, data: Dict[str, Any]) -> str:
        """Generate summary for partial data."""
        available_sources = len(data)
        return f"Partial analysis based on {available_sources} available data sources."
    
    def _extract_key_findings(self, data: Dict[str, Any]) -> List[str]:
        """Extract key findings from partial data."""
        findings = []
        for key, value in data.items():
            if isinstance(value, dict) and value.get('data'):
                findings.append(f"{key}: {self._get_key_insight(value['data'])}")
        return findings
    
    def _perform_preliminary_assessment(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform preliminary assessment on partial data."""
        return {
            'preliminary_findings': self._get_preliminary_findings(data),
            'confidence_note': 'Assessment based on partial data - additional verification recommended'
        }
    
    # Helper methods for minimal formatting
    def _extract_basic_info(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract basic information from minimal data."""
        basic_info = {}
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool)):
                basic_info[key] = value
            elif isinstance(value, dict) and 'data' in value:
                basic_info[key] = f"Data available ({type(value['data']).__name__})"
        return basic_info
    
    def _make_initial_observations(self, data: Dict[str, Any]) -> List[str]:
        """Make initial observations from minimal data."""
        observations = []
        if data:
            observations.append(f"Found {len(data)} data sources")
            for key in data.keys():
                observations.append(f"{key} data is available")
        return observations
    
    def _suggest_next_steps(self, data: Dict[str, Any]) -> List[str]:
        """Suggest next steps for minimal data scenarios."""
        return [
            'Enable comprehensive data collection',
            'Check agent connectivity and health',
            'Verify system configuration',
            'Consider expanding time range for analysis'
        ]
    
    def _specify_data_requirements(self, data: Dict[str, Any]) -> List[str]:
        """Specify what data would improve analysis."""
        return [
            'Recent alert data for security analysis',
            'Agent health metrics for system assessment',
            'Vulnerability scan results for risk evaluation',
            'Process and network data for threat detection'
        ]
    
    def _provide_troubleshooting_tips(self, data: Dict[str, Any]) -> List[str]:
        """Provide troubleshooting tips."""
        return [
            'Verify Wazuh agent connectivity',
            'Check log collection configuration',
            'Ensure API permissions are correct',
            'Review time synchronization across systems'
        ]
    
    def _suggest_feature_enablement(self) -> List[str]:
        """Suggest features to enable for better analysis."""
        return [
            'Enable context aggregation: ENABLE_CONTEXT_AGGREGATION=true',
            'Enable adaptive responses: ENABLE_ADAPTIVE_RESPONSES=true',
            'Increase context cache TTL for better performance'
        ]
    
    def _provide_configuration_guidance(self) -> List[str]:
        """Provide configuration guidance."""
        return [
            'Configure comprehensive log collection',
            'Enable vulnerability scanning',
            'Set up proper alert rules',
            'Configure agent monitoring intervals'
        ]
    
    # Utility methods (simplified implementations)
    def _extract_key_metrics(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {'sources': len(data), 'quality': 'high'}
    
    def _summarize_data_source(self, source_data: Any) -> str:
        if isinstance(source_data, dict):
            return f"Dictionary with {len(source_data)} items"
        elif isinstance(source_data, list):
            return f"List with {len(source_data)} items"
        return str(type(source_data).__name__)
    
    def _calculate_overall_risk(self, data: Dict[str, Any]) -> str:
        # Simplified risk calculation
        if 'alerts' in data:
            return 'medium'
        return 'low'
    
    def _identify_critical_issues(self, data: Dict[str, Any]) -> List[str]:
        issues = []
        if 'alerts' in data:
            issues.append('Security alerts detected')
        return issues
    
    def _analyze_risk_factors(self, data: Dict[str, Any]) -> List[str]:
        factors = []
        for source in data.keys():
            factors.append(f"{source} analysis pending")
        return factors
    
    def _get_source_recommendations(self, source: str, source_data: Any) -> List[str]:
        return [f"Review {source} data for anomalies"]
    
    def _get_key_insight(self, source_data: Any) -> str:
        return f"Data available for analysis ({type(source_data).__name__})"
    
    def _get_preliminary_findings(self, data: Dict[str, Any]) -> List[str]:
        return [f"Found data from {len(data)} sources"]
    
    def _identify_trends(self, data: Dict[str, Any]) -> List[str]:
        return ["Trend analysis available with comprehensive data"]
    
    def _highlight_anomalies(self, data: Dict[str, Any]) -> List[str]:
        return ["Anomaly detection available with comprehensive data"]
    
    def _identify_correlations(self, data: Dict[str, Any]) -> List[str]:
        return ["Correlation analysis available with comprehensive data"]
    
    def _build_timeline(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return {"timeline": "Available with timestamp data"}
    
    def _assess_impact_scope(self, data: Dict[str, Any]) -> str:
        return "Comprehensive scope assessment available"
    
    def _calculate_priority_score(self, data: Dict[str, Any]) -> int:
        return 5  # Default medium priority
    
    def _identify_incomplete_areas(self, data: Dict[str, Any]) -> List[str]:
        return ["Some data sources unavailable"]
    
    def _assess_confidence_levels(self, data: Dict[str, Any]) -> Dict[str, int]:
        return {"overall": 75}
    
    def _suggest_data_gathering_actions(self, data: Dict[str, Any]) -> List[str]:
        return ["Enable additional monitoring"]
    
    def _identify_immediate_actions(self, data: Dict[str, Any]) -> List[str]:
        return ["Review available data"]
    
    def _suggest_follow_up_investigations(self, data: Dict[str, Any]) -> List[str]:
        return ["Gather additional context"]


class ResponseQualityIndicator:
    """Provide transparency about response quality and data coverage."""
    
    def __init__(self):
        """Initialize the response quality indicator."""
        self.logger = logging.getLogger(__name__)
        
        # Define coverage levels
        self.coverage_thresholds = {
            'COMPREHENSIVE': 80,
            'HIGH': 65,
            'MODERATE': 45,
            'LIMITED': 25,
            'MINIMAL': 0
        }
    
    def generate_indicators(self, response: Any, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate quality indicators for a response.
        
        Args:
            response: The response data
            context: Context used to generate response
            
        Returns:
            Quality indicators dictionary with transparency metrics
        """
        # Analyze response structure and content
        response_analysis = self._analyze_response_structure(response)
        context_analysis = self._analyze_context_completeness(context)
        
        # Calculate overall metrics
        data_coverage = self._calculate_data_coverage(context)
        confidence_level = self._calculate_confidence_level(response, context)
        data_age = self._assess_data_age(context)
        completeness = self._calculate_completeness_percentage(context)
        
        # Identify limitations and gaps
        limitations = self._identify_limitations(response, context)
        data_sources = self._catalog_data_sources(context)
        
        # Generate transparency metrics
        transparency_metrics = self._generate_transparency_metrics(
            response, context, response_analysis
        )
        
        # Create user-friendly indicators
        user_indicators = self._create_user_indicators(
            data_coverage, confidence_level, completeness
        )
        
        return {
            'data_coverage': data_coverage,
            'confidence_level': confidence_level,
            'data_age': data_age,
            'completeness': completeness,
            'limitations': limitations,
            'data_sources': data_sources,
            'transparency_metrics': transparency_metrics,
            'user_indicators': user_indicators,
            'quality_assessment': {
                'response_structure': response_analysis,
                'context_quality': context_analysis,
                'recommendation': self._generate_quality_recommendation(completeness, confidence_level)
            },
            'generated_at': datetime.utcnow().isoformat()
        }
    
    def _analyze_response_structure(self, response: Any) -> Dict[str, Any]:
        """Analyze the structure and richness of the response."""
        if not isinstance(response, dict):
            return {
                'type': type(response).__name__,
                'complexity': 'simple',
                'fields_count': 0,
                'nested_levels': 0
            }
        
        # Count fields and analyze nesting
        fields_count = len(response)
        nested_levels = self._calculate_nesting_depth(response)
        
        # Determine complexity
        if fields_count > 10 and nested_levels > 2:
            complexity = 'complex'
        elif fields_count > 5 or nested_levels > 1:
            complexity = 'moderate'
        else:
            complexity = 'simple'
        
        # Check for quality indicators
        has_quality_indicators = '_quality_indicators' in response
        has_analysis_section = any(key in response for key in ['analysis', 'available_analysis', 'basic_information'])
        
        return {
            'type': 'dictionary',
            'complexity': complexity,
            'fields_count': fields_count,
            'nested_levels': nested_levels,
            'has_quality_indicators': has_quality_indicators,
            'has_analysis_section': has_analysis_section,
            'enrichment_level': self._assess_enrichment_level(response)
        }
    
    def _analyze_context_completeness(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze the completeness of context data."""
        if not context:
            return {
                'sources_available': 0,
                'data_richness': 0.0,
                'completeness_score': 0.0,
                'missing_sources': ['All sources missing']
            }
        
        # Define expected sources
        expected_sources = ['alerts', 'agent_health', 'vulnerabilities', 'processes', 'ports']
        available_sources = list(context.keys())
        missing_sources = [src for src in expected_sources if src not in available_sources]
        
        # Calculate richness for each available source
        total_richness = 0
        for source in available_sources:
            if source in context:
                richness = self._assess_source_data_richness(context[source])
                total_richness += richness
        
        avg_richness = total_richness / len(available_sources) if available_sources else 0
        completeness_score = (len(available_sources) / len(expected_sources)) * 100
        
        return {
            'sources_available': len(available_sources),
            'sources_expected': len(expected_sources),
            'data_richness': round(avg_richness, 2),
            'completeness_score': round(completeness_score, 1),
            'missing_sources': missing_sources,
            'available_sources': available_sources
        }
    
    def _calculate_data_coverage(self, context: Dict[str, Any]) -> str:
        """Calculate data coverage level."""
        if not context:
            return 'MINIMAL'
        
        # Calculate coverage based on available sources and data quality
        expected_sources = 5  # alerts, agent_health, vulnerabilities, processes, ports
        available_sources = len(context)
        
        # Base coverage from source count with bonus for multiple sources
        base_coverage = (available_sources / expected_sources) * 100
        
        # Adjust based on data quality with a more generous multiplier
        if context:
            avg_quality = sum(
                self._assess_source_data_richness(data) 
                for data in context.values()
            ) / len(context)
            # Apply a more generous quality multiplier
            quality_multiplier = max(0.6, avg_quality + 0.2)  # Give a bonus
            coverage_percentage = base_coverage * quality_multiplier
        else:
            coverage_percentage = base_coverage
        
        # Map to coverage levels
        for level, threshold in sorted(self.coverage_thresholds.items(), key=lambda x: x[1], reverse=True):
            if coverage_percentage >= threshold:
                return level
        
        return 'MINIMAL'
    
    def _calculate_confidence_level(self, response: Any, context: Dict[str, Any]) -> int:
        """Calculate confidence level (0-100) for the response."""
        base_confidence = 50  # Start with moderate confidence
        
        # Boost confidence based on context availability
        if context:
            context_boost = min(30, len(context) * 8)  # Up to 30 points for context
            base_confidence += context_boost
        
        # Boost confidence based on response structure
        if isinstance(response, dict):
            if '_quality_indicators' in response:
                base_confidence += 10
            if any(key in response for key in ['analysis', 'available_analysis']):
                base_confidence += 10
        
        # Reduce confidence for identified limitations
        limitations = self._identify_limitations(response, context)
        confidence_penalty = min(20, len(limitations) * 5)
        base_confidence -= confidence_penalty
        
        return max(0, min(100, base_confidence))
    
    def _assess_data_age(self, context: Dict[str, Any]) -> str:
        """Assess how current the data is."""
        if not context:
            return 'unknown'
        
        # Check for timestamp information
        has_recent_timestamps = False
        for source, data in context.items():
            if isinstance(data, dict) and 'gathered_at' in data:
                has_recent_timestamps = True
                break
        
        if has_recent_timestamps:
            return 'current'
        else:
            return 'recent'  # Default assumption
    
    def _calculate_completeness_percentage(self, context: Dict[str, Any]) -> int:
        """Calculate overall completeness percentage using the same logic as DataAvailabilityDetector."""
        if not context:
            return 0
        
        # For consistency, reuse the main detector's assessment
        # Create a temporary detector to avoid circular imports
        temp_detector = DataAvailabilityDetector()
        assessment = temp_detector.assess_data_quality(context)
        return int(assessment.get('completeness', 0))
    
    def _has_meaningful_data(self, source_data: Any) -> bool:
        """Check if source contains meaningful data."""
        if not source_data:
            return False
        
        if isinstance(source_data, dict):
            if 'data' in source_data:
                data = source_data['data']
                if isinstance(data, dict):
                    return len(data) > 0 and any(v for v in data.values() if v)
                elif isinstance(data, list):
                    return len(data) > 0
            return len(source_data) > 0
        
        return True
    
    def _identify_limitations(self, response: Any, context: Dict[str, Any]) -> List[str]:
        """Identify limitations in the response and data."""
        limitations = []
        
        # Check for context limitations
        if not context:
            limitations.append("No contextual data available")
        else:
            expected_sources = ['alerts', 'agent_health', 'vulnerabilities', 'processes', 'ports']
            missing = [src for src in expected_sources if src not in context]
            if missing:
                limitations.append(f"Missing data sources: {', '.join(missing)}")
        
        # Check for response structure limitations
        if not isinstance(response, dict):
            limitations.append("Response lacks detailed structure")
        elif isinstance(response, dict):
            if '_quality_indicators' not in response:
                limitations.append("Quality indicators not available")
            if not any(key in response for key in ['analysis', 'available_analysis', 'basic_information']):
                limitations.append("Detailed analysis not provided")
        
        # Check for data quality issues
        if context:
            for source, data in context.items():
                richness = self._assess_source_data_richness(data)
                if richness < 0.3:
                    limitations.append(f"Limited {source} data quality")
        
        return limitations
    
    def _catalog_data_sources(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Catalog available data sources and their characteristics."""
        if not context:
            return {'count': 0, 'sources': []}
        
        sources = []
        for source, data in context.items():
            richness = self._assess_source_data_richness(data)
            sources.append({
                'name': source,
                'type': type(data).__name__,
                'richness': round(richness, 2),
                'quality': 'high' if richness > 0.7 else 'medium' if richness > 0.4 else 'low'
            })
        
        return {
            'count': len(sources),
            'sources': sources,
            'average_quality': round(sum(s['richness'] for s in sources) / len(sources), 2) if sources else 0
        }
    
    def _generate_transparency_metrics(self, response: Any, context: Dict[str, Any], response_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate transparency metrics for the response."""
        return {
            'data_visibility': {
                'raw_data_included': 'raw_data' in response if isinstance(response, dict) else False,
                'source_attribution': bool(context),
                'methodology_disclosed': response_analysis.get('has_quality_indicators', False)
            },
            'uncertainty_indicators': {
                'confidence_bounds_provided': '_quality_indicators' in response if isinstance(response, dict) else False,
                'limitations_disclosed': len(self._identify_limitations(response, context)) > 0,
                'data_gaps_identified': True if context else False
            },
            'reproducibility': {
                'timestamp_provided': datetime.utcnow().isoformat(),
                'source_versions': 'available' if context else 'not_available',
                'methodology_documented': True
            }
        }
    
    def _create_user_indicators(self, coverage: str, confidence: int, completeness: int) -> Dict[str, Any]:
        """Create user-friendly quality indicators."""
        # Convert to simple ratings
        coverage_rating = {
            'COMPREHENSIVE': 5,
            'HIGH': 4,
            'MODERATE': 3,
            'LIMITED': 2,
            'MINIMAL': 1
        }.get(coverage, 1)
        
        confidence_rating = 5 if confidence >= 90 else 4 if confidence >= 75 else 3 if confidence >= 60 else 2 if confidence >= 40 else 1
        completeness_rating = 5 if completeness >= 90 else 4 if completeness >= 75 else 3 if completeness >= 60 else 2 if completeness >= 40 else 1
        
        overall_rating = round((coverage_rating + confidence_rating + completeness_rating) / 3, 1)
        
        return {
            'overall_rating': overall_rating,
            'max_rating': 5.0,
            'coverage_stars': coverage_rating,
            'confidence_stars': confidence_rating,
            'completeness_stars': completeness_rating,
            'recommendation': self._get_user_recommendation(overall_rating),
            'trust_level': 'high' if overall_rating >= 4 else 'medium' if overall_rating >= 3 else 'low'
        }
    
    def _generate_quality_recommendation(self, completeness: int, confidence: int) -> str:
        """Generate a quality-based recommendation."""
        if completeness >= 80 and confidence >= 80:
            return "High-quality analysis with comprehensive data coverage"
        elif completeness >= 60 and confidence >= 60:
            return "Good analysis with adequate data - consider additional verification"
        elif completeness >= 40 or confidence >= 40:
            return "Limited analysis due to data constraints - gather more information"
        else:
            return "Minimal analysis - significant data gaps detected - enable comprehensive monitoring"
    
    def _get_user_recommendation(self, rating: float) -> str:
        """Get user-friendly recommendation based on rating."""
        if rating >= 4.5:
            return "Excellent analysis quality - high confidence in results"
        elif rating >= 3.5:
            return "Good analysis quality - results are reliable with minor gaps"
        elif rating >= 2.5:
            return "Moderate analysis quality - consider gathering additional data"
        elif rating >= 1.5:
            return "Limited analysis quality - significant data improvements needed"
        else:
            return "Minimal analysis quality - enable comprehensive data collection"
    
    # Utility methods
    def _calculate_nesting_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Calculate the maximum nesting depth of a dictionary."""
        if not isinstance(obj, dict):
            return current_depth
        
        if not obj:
            return current_depth
        
        max_depth = current_depth
        for value in obj.values():
            if isinstance(value, dict):
                depth = self._calculate_nesting_depth(value, current_depth + 1)
                max_depth = max(max_depth, depth)
        
        return max_depth
    
    def _assess_enrichment_level(self, response: Dict[str, Any]) -> str:
        """Assess the level of response enrichment."""
        if not isinstance(response, dict):
            return 'none'
        
        # Check for various enrichment indicators
        enrichment_indicators = [
            'analysis' in response,
            'data_insights' in response,
            'context' in response,
            '_quality_indicators' in response,
            'available_analysis' in response,
            'guidance' in response
        ]
        
        enrichment_count = sum(enrichment_indicators)
        
        if enrichment_count >= 4:
            return 'comprehensive'
        elif enrichment_count >= 2:
            return 'moderate'
        elif enrichment_count >= 1:
            return 'minimal'
        else:
            return 'none'
    
    def _assess_source_data_richness(self, source_data: Any) -> float:
        """Assess the richness of data from a source (0.0-1.0)."""
        if not source_data:
            return 0.0
        
        if isinstance(source_data, dict):
            if 'data' in source_data:
                data = source_data['data']
                if isinstance(data, dict):
                    # Rich if has multiple fields with meaningful values
                    meaningful_fields = sum(1 for v in data.values() if v)
                    return min(1.0, meaningful_fields / 5)  # Normalize to 5 fields max
                elif isinstance(data, list):
                    # Rich if has multiple items
                    return min(1.0, len(data) / 10)  # Normalize to 10 items max
            else:
                # Direct data assessment
                return min(1.0, len(source_data) / 5)
        
        return 0.3  # Default modest richness for non-dict data