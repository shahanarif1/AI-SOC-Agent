# Phase 5: Prompt Enhancement System - Detailed Implementation Plan

## Executive Summary

Phase 5 introduces an intelligent prompt enhancement system that will automatically gather comprehensive context, adapt responses based on available data, and provide real-time updates during incidents. This system will transform the Wazuh MCP Server from a reactive tool-based system to a proactive, context-aware security intelligence platform.

## Critical Requirements

### Non-Negotiable Constraints
1. **ZERO Breaking Changes**: All existing functionality must remain intact
2. **Backward Compatibility**: All current tools must work exactly as before
3. **Opt-in Enhancement**: New features should be optional with sensible defaults
4. **Performance**: No degradation of existing response times
5. **Stability**: No impact on current error handling or reliability

## Phase 5 Overview

### Goals
- **Automatic Context Gathering**: 80% reduction in manual tool calls
- **Intelligent Response Adaptation**: Dynamic formatting based on data availability
- **Real-time Updates**: Live tracking during ongoing incidents
- **Quality Improvement**: 4-9x improvement in response comprehensiveness

### Components
1. **Task 5.1**: Context Aggregation System
2. **Task 5.2**: Dynamic Prompt Adaptation
3. **Task 5.3**: Real-Time Context Updates

---

## Task 5.1: Context Aggregation System

### Objective
Automatically gather comprehensive context for each prompt without requiring explicit tool calls.

### Technical Design

#### 1. PromptContextAggregator Class
```python
class PromptContextAggregator:
    """Intelligent context aggregation for enhanced prompt responses."""
    
    def __init__(self, server_instance):
        self.server = server_instance
        self.cache = ContextCache(ttl=300)  # 5-minute cache
        self.pipelines = {
            'incident': IncidentPipeline(),
            'hunting': ThreatHuntingPipeline(),
            'compliance': CompliancePipeline(),
            'forensic': ForensicPipeline()
        }
```

#### 2. Context Detection System
- **Pattern Recognition**: Analyze prompt to determine context type
- **Keyword Mapping**: Map keywords to relevant tool combinations
- **Intent Classification**: Determine user intent (investigate, monitor, audit, etc.)

#### 3. Pipeline Architecture

##### Incident Investigation Pipeline
When detecting incident-related prompts:
1. Automatically gather:
   - Recent alerts (last 24h)
   - Agent health status
   - Related vulnerabilities
   - Network connections
   - Running processes
2. Correlate data across sources
3. Build comprehensive incident context

##### Threat Hunting Pipeline
When detecting hunting-related prompts:
1. Automatically gather:
   - IOC matches
   - Suspicious processes
   - Network anomalies
   - File integrity changes
   - User behavior analytics
2. Cross-reference with threat intelligence
3. Generate hunting hypotheses

##### Compliance Pipeline
When detecting compliance-related prompts:
1. Automatically gather:
   - Compliance check results
   - Configuration assessments
   - Policy violations
   - Audit trails
2. Map to frameworks (PCI-DSS, HIPAA, etc.)
3. Generate compliance posture

##### Forensic Pipeline
When detecting forensic-related prompts:
1. Automatically gather:
   - Log timeline reconstruction
   - Event correlation
   - Evidence chains
   - System artifacts
2. Build forensic timeline
3. Identify evidence gaps

#### 4. Implementation Strategy

##### A. Base Infrastructure (No Breaking Changes)
```python
# Add to WazuhMCPServer class
def __init__(self):
    # ... existing initialization ...
    # Add new optional component
    self.context_aggregator = None
    if self.config.enable_prompt_enhancement:  # New config option, default False
        self.context_aggregator = PromptContextAggregator(self)
```

##### B. Hook Integration (Non-Invasive)
```python
async def _handle_tool_execution(self, name: str, arguments: dict):
    # Existing tool execution logic remains unchanged
    result = await existing_handler(name, arguments)
    
    # New enhancement layer (only if enabled)
    if self.context_aggregator:
        enhanced_result = await self.context_aggregator.enhance_response(
            name, arguments, result
        )
        return enhanced_result
    
    return result  # Original behavior preserved
```

##### C. Caching System
- **Purpose**: Prevent redundant API calls
- **Strategy**: LRU cache with TTL
- **Key Design**: Cache invalidation on write operations
- **Implementation**: Decorator-based, transparent to existing code

### Benefits
- No changes to existing tool interfaces
- Completely optional enhancement
- Graceful degradation if disabled
- Progressive enhancement pattern

---

## Task 5.2: Dynamic Prompt Adaptation

### Objective
Adjust prompt responses based on available data and context quality.

### Technical Design

#### 1. Data Availability Detector
```python
class DataAvailabilityDetector:
    """Detect what data is available for response generation."""
    
    def assess_data_quality(self, context):
        return {
            'completeness': 0-100,
            'confidence': 0-100,
            'gaps': ['list of missing data'],
            'recommendations': ['suggested actions']
        }
```

#### 2. Response Formatter
```python
class AdaptiveResponseFormatter:
    """Format responses based on available data."""
    
    def format_response(self, data, quality_assessment):
        if quality_assessment['completeness'] > 80:
            return self._comprehensive_format(data)
        elif quality_assessment['completeness'] > 50:
            return self._partial_format_with_gaps(data)
        else:
            return self._minimal_format_with_guidance(data)
```

#### 3. Progressive Disclosure System
- **Level 1**: Executive summary
- **Level 2**: Key findings and metrics
- **Level 3**: Detailed analysis
- **Level 4**: Raw data and evidence

#### 4. Quality Indicators
```python
class ResponseQualityIndicator:
    """Provide transparency about response quality."""
    
    def generate_indicators(self, response):
        return {
            'data_coverage': 'HIGH|MEDIUM|LOW',
            'confidence_level': 0-100,
            'data_age': 'current|recent|stale',
            'completeness': 0-100,
            'limitations': ['list of limitations']
        }
```

### Implementation Approach

#### Non-Breaking Integration
1. **Wrapper Pattern**: Wrap existing responses without modifying them
2. **Metadata Addition**: Add quality indicators as optional metadata
3. **Format Preservation**: Keep original response structure intact
4. **Enhancement Flags**: Use feature flags for new formatting options

#### Example Enhancement
```python
# Original response
{
    "alerts": [...],
    "total": 50
}

# Enhanced response (only when enabled)
{
    "alerts": [...],
    "total": 50,
    "_quality_metadata": {
        "coverage": "HIGH",
        "confidence": 95,
        "gaps": [],
        "enhanced": true
    },
    "_context": {
        "related_vulnerabilities": [...],
        "affected_agents": [...],
        "correlation_insights": [...]
    }
}
```

---

## Task 5.3: Real-Time Context Updates

### Objective
Keep analysis current during ongoing incidents with live updates.

### Technical Design

#### 1. Update System Architecture
```python
class RealTimeContextUpdater:
    """Manage real-time context updates during incidents."""
    
    def __init__(self):
        self.active_contexts = {}
        self.update_intervals = {
            'critical': 30,    # seconds
            'high': 60,
            'medium': 300,
            'low': 900
        }
```

#### 2. Change Detection
```python
class ChangeDetector:
    """Detect significant changes in security posture."""
    
    def detect_changes(self, old_context, new_context):
        return {
            'new_alerts': [...],
            'status_changes': [...],
            'escalations': [...],
            'resolutions': [...]
        }
```

#### 3. Incremental Updates
- **Delta Calculation**: Only send changes, not full dataset
- **Priority-based Updates**: Critical changes immediate, others batched
- **Subscription Model**: Tools can subscribe to specific update types

#### 4. Implementation Strategy

##### WebSocket Integration (Optional)
```python
# Only activated if real-time mode is enabled
if self.config.enable_realtime_updates:
    self.websocket_handler = WebSocketHandler()
    self.context_updater = RealTimeContextUpdater()
```

##### Polling Fallback
```python
# For compatibility, provide polling-based updates
class PollingUpdater:
    async def check_updates(self, context_id):
        # Non-breaking polling mechanism
        # Returns empty if no updates
        return await self.get_changes_since_last_check(context_id)
```

---

## Implementation Phases

### Phase 5.1.1: Foundation (Week 1)
1. Create base classes without integration
2. Implement caching system
3. Build pattern recognition engine
4. Create unit tests

### Phase 5.1.2: Pipeline Development (Week 1-2)
1. Implement incident pipeline
2. Implement hunting pipeline
3. Implement compliance pipeline
4. Implement forensic pipeline

### Phase 5.2.1: Response Enhancement (Week 2)
1. Build data availability detector
2. Create adaptive formatter
3. Implement quality indicators
4. Add progressive disclosure

### Phase 5.3.1: Real-Time System (Week 3)
1. Create update detection system
2. Implement incremental updates
3. Build subscription mechanism
4. Add notification system

### Integration Phase (Week 3-4)
1. Integrate with existing handlers
2. Add configuration options
3. Implement feature flags
4. Comprehensive testing

---

## Risk Mitigation

### 1. Breaking Changes Prevention
- **Strategy**: All enhancements behind feature flags
- **Default**: System works exactly as before when flags are off
- **Testing**: Dual-mode testing (enhanced on/off)
- **Rollback**: Simple flag toggle to disable

### 2. Performance Protection
- **Caching**: Aggressive caching to prevent API overload
- **Lazy Loading**: Only gather context when needed
- **Timeouts**: Strict timeouts on enhancement operations
- **Circuit Breakers**: Disable enhancement on repeated failures

### 3. Stability Assurance
- **Isolation**: Enhancement errors don't affect core functionality
- **Logging**: Detailed logging for troubleshooting
- **Monitoring**: Performance metrics for enhancement overhead
- **Graceful Degradation**: Fall back to basic mode on issues

---

## Configuration Design

### New Configuration Options
```python
# config.py additions
class WazuhConfig:
    # ... existing config ...
    
    # Prompt Enhancement Settings (all default to False/conservative values)
    enable_prompt_enhancement: bool = Field(default=False)
    enable_context_aggregation: bool = Field(default=False)
    enable_adaptive_responses: bool = Field(default=False)
    enable_realtime_updates: bool = Field(default=False)
    
    context_cache_ttl: int = Field(default=300)  # 5 minutes
    max_context_size: int = Field(default=1000)  # Maximum items per context
    enhancement_timeout: float = Field(default=5.0)  # Maximum enhancement time
```

---

## Testing Strategy

### 1. Unit Tests
- Test each component in isolation
- Verify no impact when disabled
- Test cache behavior
- Test timeout handling

### 2. Integration Tests
- Test with enhancement on/off
- Verify backward compatibility
- Test performance impact
- Test error scenarios

### 3. Load Tests
- Measure overhead of enhancement
- Test cache effectiveness
- Verify scaling behavior
- Test circuit breaker triggers

### 4. Regression Tests
- Run all existing tests with enhancement off
- Verify identical behavior
- Run with enhancement on
- Verify only additive changes

---

## Success Metrics

### Quantitative Metrics
1. **Context Coverage**: 85-95% automated context gathering
2. **Response Time**: <10% overhead when enabled
3. **Cache Hit Rate**: >70% for common queries
4. **Error Rate**: <1% enhancement failures

### Qualitative Metrics
1. **User Satisfaction**: Reduced follow-up questions
2. **Completeness**: More comprehensive initial responses
3. **Accuracy**: Better correlation and insights
4. **Usability**: Intuitive quality indicators

---

## Rollout Plan

### Stage 1: Alpha (Internal Testing)
- Deploy with all flags off
- Enable for specific test accounts
- Monitor performance and stability
- Gather feedback

### Stage 2: Beta (Limited Release)
- Enable context aggregation only
- Monitor API usage patterns
- Tune cache parameters
- Address issues

### Stage 3: GA (General Availability)
- Enable all features with opt-in
- Provide migration guide
- Monitor adoption
- Iterate based on feedback

---

## Conclusion

This implementation plan ensures that Phase 5 enhances the Wazuh MCP Server's capabilities dramatically while maintaining 100% backward compatibility. The opt-in nature, careful isolation, and comprehensive testing strategy guarantee that existing functionality remains untouched while providing powerful new capabilities for those who choose to enable them.

The modular design allows for incremental rollout and easy rollback if issues arise. By following this plan, we can achieve the goal of 4-9x improvement in response quality without any risk to current operations.