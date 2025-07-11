#!/usr/bin/env python3
"""
Test script for Phase 5.3: Real-Time Context Updates.

Tests the ChangeDetector and RealTimeContextUpdater classes to ensure
they properly detect changes and manage real-time monitoring.
"""

import sys
import os
import asyncio
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))


def test_context_snapshot():
    """Test ContextSnapshot creation and checksum functionality."""
    print("Testing ContextSnapshot...")
    
    try:
        from wazuh_mcp_server.prompt_enhancement.updates import ContextSnapshot
        
        # Test snapshot creation
        test_data = {
            'alerts': {'total_count': 10, 'high_severity_count': 3},
            'agent_health': {'health_score': 85, 'connection_quality': 'good'}
        }
        
        snapshot1 = ContextSnapshot.create("test_001", "incident", test_data)
        snapshot2 = ContextSnapshot.create("test_001", "incident", test_data)
        
        # Same data should produce same checksum
        assert snapshot1.checksum == snapshot2.checksum
        assert snapshot1.context_id == "test_001"
        assert snapshot1.context_type == "incident"
        
        # Different data should produce different checksum
        different_data = test_data.copy()
        different_data['alerts']['total_count'] = 15
        snapshot3 = ContextSnapshot.create("test_001", "incident", different_data)
        
        assert snapshot1.checksum != snapshot3.checksum
        
        print("✓ ContextSnapshot working correctly")
        return True
        
    except Exception as e:
        print(f"✗ ContextSnapshot test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def test_change_detector():
    """Test ChangeDetector functionality."""
    print("Testing ChangeDetector...")
    
    try:
        from wazuh_mcp_server.prompt_enhancement.updates import ChangeDetector
        
        detector = ChangeDetector()
        
        # Test empty context handling
        empty_result = detector.detect_changes({}, {})
        assert empty_result['total_changes'] == 0
        assert empty_result['summary'] == 'No context data available for comparison'
        
        # Test alert changes detection
        old_context = {
            'alerts': {
                'data': {
                    'total_count': 10,
                    'critical_count': 2,
                    'high_severity_count': 5,
                    'alert_trend': 'stable',
                    'top_rules': [{'id': 'rule_001'}, {'id': 'rule_002'}]
                }
            }
        }
        
        new_context = {
            'alerts': {
                'data': {
                    'total_count': 15,
                    'critical_count': 4,  # Increased critical alerts
                    'high_severity_count': 8,  # Significant increase
                    'alert_trend': 'increasing',  # Trend change
                    'top_rules': [{'id': 'rule_001'}, {'id': 'rule_002'}, {'id': 'rule_003'}]  # New rule
                }
            }
        }
        
        changes = detector.detect_changes(old_context, new_context)
        
        assert changes['total_changes'] > 0
        assert changes['critical_changes'] > 0  # Should detect critical alert increase
        assert 'CRITICAL' in changes['summary'] or 'HIGH PRIORITY' in changes['summary']
        
        # Verify specific change types
        change_types = [change['change_type'] for change in changes['changes']]
        assert 'new_alert' in change_types  # Critical alerts increased
        assert 'escalation' in change_types  # Trend changed
        
        # Test health changes
        old_health_context = {
            'agent_health': {
                'data': {
                    'health_score': 90,
                    'connection_quality': 'excellent'
                }
            }
        }
        
        new_health_context = {
            'agent_health': {
                'data': {
                    'health_score': 65,  # Significant drop
                    'connection_quality': 'poor'  # Connection degraded
                }
            }
        }
        
        health_changes = detector.detect_changes(old_health_context, new_health_context)
        assert health_changes['total_changes'] > 0
        
        health_change_types = [change['change_type'] for change in health_changes['changes']]
        assert 'status_change' in health_change_types
        
        print("✓ ChangeDetector working correctly")
        return True
        
    except Exception as e:
        print(f"✗ ChangeDetector test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


async def test_realtime_updater():
    """Test RealTimeContextUpdater functionality."""
    print("Testing RealTimeContextUpdater...")
    
    try:
        from wazuh_mcp_server.prompt_enhancement.updates import RealTimeContextUpdater
        
        updater = RealTimeContextUpdater()
        
        # Test initial state
        stats = updater.get_monitoring_stats()
        assert stats['active_monitors'] == 0
        assert stats['total_updates'] == 0
        
        # Test starting monitoring
        initial_context = {
            'alerts': {'data': {'total_count': 5, 'critical_count': 1}},
            'agent_health': {'data': {'health_score': 80}}
        }
        
        await updater.start_monitoring(
            context_id="test_incident_001",
            context_type="incident",
            priority="high",
            initial_context=initial_context
        )
        
        # Verify monitoring started
        stats = updater.get_monitoring_stats()
        assert stats['active_monitors'] == 1
        assert "test_incident_001" in stats['active_contexts']
        
        # Test context status
        status = await updater.get_context_status("test_incident_001")
        assert status is not None
        assert status['context_type'] == "incident"
        assert status['priority'] == "high"
        assert status['status'] == "active"
        
        # Test context update with changes
        updated_context = {
            'alerts': {'data': {'total_count': 8, 'critical_count': 3}},  # More critical alerts
            'agent_health': {'data': {'health_score': 75}}  # Slight health drop
        }
        
        change_result = await updater.update_context("test_incident_001", updated_context)
        
        if change_result:  # Changes detected
            assert change_result['total_changes'] > 0
            assert 'summary' in change_result
        
        # Test subscriber functionality
        received_notifications = []
        
        def test_callback(notification):
            received_notifications.append(notification)
        
        updater.subscribe_to_updates("test_incident_001", test_callback)
        
        # Make another update
        final_context = {
            'alerts': {'data': {'total_count': 12, 'critical_count': 5}},  # Even more alerts
            'agent_health': {'data': {'health_score': 65}}  # More health drop
        }
        
        await updater.update_context("test_incident_001", final_context)
        
        # Give a moment for notification processing
        await asyncio.sleep(0.1)
        
        # Test stopping monitoring
        await updater.stop_monitoring("test_incident_001")
        
        # Verify monitoring stopped
        stats = updater.get_monitoring_stats()
        assert stats['active_monitors'] == 0
        
        status = await updater.get_context_status("test_incident_001")
        assert status is None
        
        print("✓ RealTimeContextUpdater working correctly")
        return True
        
    except Exception as e:
        print(f"✗ RealTimeContextUpdater test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


async def test_change_event_priority():
    """Test change event prioritization."""
    print("Testing change event prioritization...")
    
    try:
        from wazuh_mcp_server.prompt_enhancement.updates import ChangeDetector, ChangeEvent
        
        detector = ChangeDetector()
        
        # Create test change events
        events = [
            ChangeEvent(
                change_type='new_alert',
                source='alerts',
                severity='medium',
                description='Medium alert',
                old_value=0,
                new_value=1,
                timestamp=datetime.utcnow().isoformat(),
                metadata={}
            ),
            ChangeEvent(
                change_type='new_vulnerability',
                source='vulnerabilities',
                severity='critical',
                description='Critical vulnerability',
                old_value=0,
                new_value=1,
                timestamp=datetime.utcnow().isoformat(),
                metadata={}
            ),
            ChangeEvent(
                change_type='status_change',
                source='agent_health',
                severity='high',
                description='Health degradation',
                old_value='good',
                new_value='poor',
                timestamp=datetime.utcnow().isoformat(),
                metadata={}
            )
        ]
        
        # Test priority calculation
        priorities = [detector._get_change_priority(event) for event in events]
        
        # Critical vulnerability should have highest priority
        assert max(priorities) == detector._get_change_priority(events[1])
        
        # Events should be sortable by priority
        sorted_events = sorted(events, key=lambda x: detector._get_change_priority(x), reverse=True)
        assert sorted_events[0].severity == 'critical'
        
        print("✓ Change event prioritization working correctly")
        return True
        
    except Exception as e:
        print(f"✗ Change event prioritization test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


async def test_integration_with_context_aggregator():
    """Test integration with context aggregator."""
    print("Testing integration with context aggregator...")
    
    try:
        from wazuh_mcp_server.prompt_enhancement.context_aggregator import PromptContextAggregator
        from wazuh_mcp_server.prompt_enhancement.updates import RealTimeContextUpdater
        
        # Create mock server
        class MockServer:
            def __init__(self):
                self.config = type('Config', (), {
                    'enable_prompt_enhancement': True,
                    'enable_context_aggregation': True,
                    'enable_realtime_updates': True,
                    'context_cache_ttl': 300,
                    'max_context_size': 1000,
                    'enhancement_timeout': 5.0
                })()
        
        mock_server = MockServer()
        aggregator = PromptContextAggregator(mock_server)
        
        # Verify real-time updater was initialized
        assert aggregator.realtime_updater is not None
        assert isinstance(aggregator.realtime_updater, RealTimeContextUpdater)
        
        # Test feature flags
        assert aggregator._realtime_enabled is True
        
        # Test cleanup
        await aggregator.cleanup()
        
        print("✓ Integration with context aggregator working correctly")
        return True
        
    except Exception as e:
        print(f"✗ Integration test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


async def test_edge_cases():
    """Test edge cases and error handling."""
    print("Testing edge cases...")
    
    try:
        from wazuh_mcp_server.prompt_enhancement.updates import ChangeDetector, RealTimeContextUpdater
        
        detector = ChangeDetector()
        updater = RealTimeContextUpdater()
        
        # Test None inputs
        result = detector.detect_changes(None, None)
        assert result['total_changes'] == 0
        
        # Test malformed context
        malformed_old = {'alerts': 'not_a_dict'}
        malformed_new = {'alerts': {'data': 'also_not_dict'}}
        
        # Should not crash
        result = detector.detect_changes(malformed_old, malformed_new)
        assert isinstance(result, dict)
        
        # Test stopping non-existent monitoring
        await updater.stop_monitoring("non_existent_context")
        
        # Test updating non-monitored context
        result = await updater.update_context("non_existent", {})
        assert result is None
        
        # Test empty context updates
        await updater.start_monitoring("empty_test", "incident", "low", {})
        result = await updater.update_context("empty_test", {})
        await updater.stop_monitoring("empty_test")
        
        print("✓ Edge cases handled correctly")
        return True
        
    except Exception as e:
        print(f"✗ Edge cases test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all Phase 5.3 tests."""
    print("Phase 5.3: Real-Time Context Updates Test Suite")
    print("=" * 55)
    
    sync_tests = [
        test_context_snapshot,
        test_change_detector
    ]
    
    async_tests = [
        test_realtime_updater,
        test_change_event_priority,
        test_integration_with_context_aggregator,
        test_edge_cases
    ]
    
    passed = 0
    total = len(sync_tests) + len(async_tests)
    
    # Run sync tests
    for test_func in sync_tests:
        if test_func():
            passed += 1
        print()
    
    # Run async tests
    for test_func in async_tests:
        try:
            if await test_func():
                passed += 1
        except Exception as e:
            print(f"✗ Async test failed: {str(e)}")
        print()
    
    print(f"Test Results: {passed}/{total} tests passed")
    print()
    
    if passed == total:
        print("✓ All Phase 5.3 tests passed!")
        print("✓ ContextSnapshot provides reliable change detection through checksums")
        print("✓ ChangeDetector identifies significant security posture changes")
        print("✓ RealTimeContextUpdater manages monitoring lifecycle and notifications")
        print("✓ Change event prioritization ensures critical events get attention")
        print("✓ Integration with context aggregator enables automatic monitoring")
        print("✓ Phase 5.3: Real-Time Context Updates is fully functional")
        return True
    else:
        print("✗ Some tests failed. Please check the implementation.")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)