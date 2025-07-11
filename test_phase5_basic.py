#!/usr/bin/env python3
"""
Basic test to verify Phase 5 module structure is correct.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_import_structure():
    """Test that all Phase 5 modules can be imported."""
    print("Testing Phase 5 import structure...")
    
    try:
        # Test basic imports
        from wazuh_mcp_server.prompt_enhancement import PromptContextAggregator
        from wazuh_mcp_server.prompt_enhancement.cache import ContextCache, AsyncContextCache
        from wazuh_mcp_server.prompt_enhancement.context_aggregator import PromptPatternMatcher
        from wazuh_mcp_server.prompt_enhancement.pipelines import ContextPipeline, IncidentPipeline
        from wazuh_mcp_server.prompt_enhancement.adapters import DataAvailabilityDetector
        from wazuh_mcp_server.prompt_enhancement.updates import RealTimeContextUpdater
        
        print("✓ All Phase 5 modules imported successfully")
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {str(e)}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {str(e)}")
        return False


def test_cache_functionality():
    """Test that the cache system works correctly."""
    print("Testing cache functionality...")
    
    try:
        from wazuh_mcp_server.prompt_enhancement.cache import ContextCache, CacheKeyBuilder
        
        # Create cache instance
        cache = ContextCache(max_size=10, default_ttl=60)
        
        # Test basic operations
        key_data = CacheKeyBuilder.alerts_key(agent_id="001", time_range="24h")
        test_value = {"test": "data"}
        
        # Set and get
        cache.set("test_namespace", key_data, test_value)
        retrieved = cache.get("test_namespace", key_data)
        
        assert retrieved == test_value
        
        # Test stats
        stats = cache.get_stats()
        assert stats['cache_size'] == 1
        assert stats['hits'] == 1
        
        print("✓ Cache functionality works correctly")
        return True
        
    except Exception as e:
        print(f"✗ Cache test failed: {str(e)}")
        return False


def test_pattern_matcher():
    """Test that the pattern matcher works correctly."""
    print("Testing pattern matcher...")
    
    try:
        from wazuh_mcp_server.prompt_enhancement.context_aggregator import PromptPatternMatcher
        
        matcher = PromptPatternMatcher()
        
        # Test incident detection
        analysis = matcher.analyze_prompt(
            "investigate suspicious activity on agent 001",
            "get_alerts",
            {"agent_id": "001"}
        )
        
        assert 'incident' in analysis['context_types']
        assert analysis['entities']['agent_id'] == ['001']
        assert analysis['confidence'] > 0
        
        print("✓ Pattern matcher works correctly")
        return True
        
    except Exception as e:
        print(f"✗ Pattern matcher test failed: {str(e)}")
        return False


def test_pipeline_structure():
    """Test that pipelines are structured correctly."""
    print("Testing pipeline structure...")
    
    try:
        from wazuh_mcp_server.prompt_enhancement.pipelines import (
            IncidentPipeline, ThreatHuntingPipeline, 
            CompliancePipeline, ForensicPipeline
        )
        from wazuh_mcp_server.prompt_enhancement.cache import AsyncContextCache, ContextCache
        
        # Create mock cache
        cache = AsyncContextCache(ContextCache())
        
        # Create pipeline instances (these should not fail)
        incident_pipeline = IncidentPipeline(None, cache)
        hunting_pipeline = ThreatHuntingPipeline(None, cache)
        compliance_pipeline = CompliancePipeline(None, cache)
        forensic_pipeline = ForensicPipeline(None, cache)
        
        # Check they have required methods
        assert hasattr(incident_pipeline, 'gather_context')
        assert hasattr(hunting_pipeline, 'gather_context')
        assert hasattr(compliance_pipeline, 'gather_context')
        assert hasattr(forensic_pipeline, 'gather_context')
        
        print("✓ Pipeline structure is correct")
        return True
        
    except Exception as e:
        print(f"✗ Pipeline structure test failed: {str(e)}")
        return False


def main():
    """Run all basic tests."""
    print("Phase 5 Basic Test Suite")
    print("=" * 30)
    
    tests = [
        test_import_structure,
        test_cache_functionality,
        test_pattern_matcher,
        test_pipeline_structure
    ]
    
    passed = 0
    total = len(tests)
    
    for test_func in tests:
        if test_func():
            passed += 1
        print()
    
    print(f"Test Results: {passed}/{total} tests passed")
    print()
    
    if passed == total:
        print("✓ All basic tests passed! Phase 5.1 foundation is working correctly.")
        print("✓ The prompt enhancement system is ready for integration.")
        return True
    else:
        print("✗ Some tests failed. Please check the implementation.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)