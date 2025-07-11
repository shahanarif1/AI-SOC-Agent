"""Tests for the get_wazuh_alert_summary tool."""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from wazuh_mcp_server.main import WazuhMCPServer
from wazuh_mcp_server.utils.validation import validate_alert_summary_query, ValidationError


@pytest.fixture
def mock_alerts_data():
    """Mock alert data for testing."""
    base_time = datetime.utcnow()
    
    return [
        {
            "id": "alert_001",
            "timestamp": (base_time - timedelta(hours=1)).isoformat() + "Z",
            "rule": {
                "id": 5501,
                "description": "Login session opened",
                "level": 3,
                "groups": ["authentication", "pci_dss"]
            },
            "agent": {
                "id": "001",
                "name": "web-server-01"
            },
            "data": {
                "srcip": "192.168.1.100"
            }
        },
        {
            "id": "alert_002", 
            "timestamp": (base_time - timedelta(hours=2)).isoformat() + "Z",
            "rule": {
                "id": 5503,
                "description": "User login failed",
                "level": 7,
                "groups": ["authentication", "authentication_failed"]
            },
            "agent": {
                "id": "002",
                "name": "db-server-01"
            },
            "data": {
                "srcip": "10.0.0.50"
            }
        },
        {
            "id": "alert_003",
            "timestamp": (base_time - timedelta(hours=3)).isoformat() + "Z",
            "rule": {
                "id": 31166,
                "description": "High number of login failures",
                "level": 12,
                "groups": ["authentication", "authentication_failures"]
            },
            "agent": {
                "id": "001",
                "name": "web-server-01"
            },
            "data": {
                "srcip": "192.168.1.100"
            }
        },
        {
            "id": "alert_004",
            "timestamp": (base_time - timedelta(hours=4)).isoformat() + "Z",
            "rule": {
                "id": 40101,
                "description": "Critical vulnerability detected",
                "level": 15,
                "groups": ["vulnerability", "high_priority"]
            },
            "agent": {
                "id": "003", 
                "name": "critical-server-01"
            },
            "data": {
                "srcip": "172.16.0.10"
            }
        }
    ]


class TestAlertSummaryValidation:
    """Test validation of alert summary query parameters."""
    
    def test_valid_basic_query(self):
        """Test validation with basic valid parameters."""
        params = {"time_range": "24h", "group_by": "severity"}
        result = validate_alert_summary_query(params)
        
        assert result.time_range == "24h"
        assert result.group_by == "severity"
        assert result.include_stats is True
        assert result.max_alerts == 1000
    
    def test_valid_custom_time_range(self):
        """Test validation with custom time range."""
        params = {
            "time_range": "custom",
            "custom_start": "2024-01-01T00:00:00",
            "custom_end": "2024-01-02T00:00:00",
            "group_by": "agent"
        }
        result = validate_alert_summary_query(params)
        
        assert result.time_range == "custom"
        assert result.custom_start == "2024-01-01T00:00:00"
        assert result.custom_end == "2024-01-02T00:00:00"
    
    def test_invalid_time_range(self):
        """Test validation with invalid time range."""
        params = {"time_range": "invalid"}
        
        with pytest.raises(ValidationError):
            validate_alert_summary_query(params)
    
    def test_invalid_severity_filter(self):
        """Test validation with invalid severity."""
        params = {
            "time_range": "24h",
            "severity_filter": ["invalid_severity"]
        }
        
        with pytest.raises(ValidationError):
            validate_alert_summary_query(params)
    
    def test_invalid_group_by(self):
        """Test validation with invalid group_by field."""
        params = {
            "time_range": "24h",
            "group_by": "invalid_field"
        }
        
        with pytest.raises(ValidationError):
            validate_alert_summary_query(params)
    
    def test_custom_time_missing_start(self):
        """Test validation when custom time is missing start."""
        params = {
            "time_range": "custom",
            "custom_end": "2024-01-02T00:00:00"
        }
        
        with pytest.raises(ValidationError):
            validate_alert_summary_query(params)
    
    def test_max_alerts_boundary(self):
        """Test max_alerts boundary validation."""
        # Test minimum
        params = {"time_range": "24h", "max_alerts": 100}
        result = validate_alert_summary_query(params)
        assert result.max_alerts == 100
        
        # Test maximum
        params = {"time_range": "24h", "max_alerts": 10000}
        result = validate_alert_summary_query(params)
        assert result.max_alerts == 10000
        
        # Test below minimum
        params = {"time_range": "24h", "max_alerts": 50}
        with pytest.raises(ValidationError):
            validate_alert_summary_query(params)


@pytest.mark.asyncio
class TestAlertSummaryTool:
    """Test the alert summary tool functionality."""
    
    @pytest.fixture
    async def wazuh_server(self):
        """Create a mock Wazuh MCP server."""
        with patch('wazuh_mcp_server.main.WazuhConfig') as mock_config:
            mock_config.from_env.return_value = MagicMock()
            mock_config.from_env.return_value.log_level = "INFO"
            mock_config.from_env.return_value.debug = False
            mock_config.from_env.return_value.request_timeout_seconds = 30
            
            server = WazuhMCPServer()
            server.api_client = AsyncMock()
            return server
    
    async def test_basic_alert_summary(self, wazuh_server, mock_alerts_data):
        """Test basic alert summary functionality."""
        # Mock API response
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_data}
        }
        
        arguments = {"time_range": "24h", "group_by": "severity"}
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Check basic structure
        assert "query_parameters" in response_data
        assert "summary" in response_data
        assert "grouped_analysis" in response_data
        assert "statistical_analysis" in response_data
        assert "trend_analysis" in response_data
        assert "key_insights" in response_data
        
        # Check summary data
        assert response_data["summary"]["total_alerts"] == 4
        assert response_data["grouped_analysis"]["grouping_field"] == "severity"
    
    async def test_severity_grouping(self, wazuh_server, mock_alerts_data):
        """Test grouping by severity."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_data}
        }
        
        arguments = {"time_range": "24h", "group_by": "severity"}
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        response_data = json.loads(result[0].text)
        groups = response_data["grouped_analysis"]["groups"]
        
        # Should have different severity levels
        severity_levels = list(groups.keys())
        assert "critical" in severity_levels
        assert "medium" in severity_levels
        assert "low" in severity_levels
        
        # Check critical alert count
        assert groups["critical"]["count"] == 1
        assert groups["medium"]["count"] == 1
        assert groups["low"]["count"] == 2
    
    async def test_agent_grouping(self, wazuh_server, mock_alerts_data):
        """Test grouping by agent."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_data}
        }
        
        arguments = {"time_range": "24h", "group_by": "agent"}
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        response_data = json.loads(result[0].text)
        groups = response_data["grouped_analysis"]["groups"]
        
        # Should have different agents
        agent_names = list(groups.keys())
        assert any("web-server-01" in name for name in agent_names)
        assert any("db-server-01" in name for name in agent_names)
        assert any("critical-server-01" in name for name in agent_names)
    
    async def test_severity_filtering(self, wazuh_server, mock_alerts_data):
        """Test filtering by severity."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_data}
        }
        
        arguments = {
            "time_range": "24h",
            "severity_filter": ["critical", "high"],
            "group_by": "severity"
        }
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should only have critical and high severity alerts
        # Based on our mock data: 1 critical (level 15), 1 high (level 12)
        assert response_data["summary"]["total_alerts"] == 2
    
    async def test_statistical_analysis(self, wazuh_server, mock_alerts_data):
        """Test statistical analysis features."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_data}
        }
        
        arguments = {"time_range": "24h", "include_stats": True}
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        response_data = json.loads(result[0].text)
        stats = response_data["statistical_analysis"]
        
        assert "alert_levels" in stats
        assert "temporal_analysis" in stats
        
        # Check alert level statistics
        level_stats = stats["alert_levels"]
        assert "mean" in level_stats
        assert "median" in level_stats
        assert "std_dev" in level_stats
        assert "distribution" in level_stats
    
    async def test_trend_analysis(self, wazuh_server, mock_alerts_data):
        """Test trend analysis features."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_data}
        }
        
        arguments = {"time_range": "24h", "include_trends": True}
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        response_data = json.loads(result[0].text)
        trends = response_data["trend_analysis"]
        
        assert "severity_trends" in trends
        assert "agent_patterns" in trends
        assert "rule_patterns" in trends
        assert "temporal_patterns" in trends
    
    async def test_empty_alert_response(self, wazuh_server):
        """Test handling of empty alert response."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"time_range": "24h"}
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        response_data = json.loads(result[0].text)
        assert response_data["summary"]["total_alerts"] == 0
        assert "No alerts found" in response_data["summary"]["message"]
    
    async def test_pagination_handling(self, wazuh_server):
        """Test pagination with large datasets."""
        # Create mock data for multiple batches
        large_dataset = []
        for i in range(2500):  # More than default batch size
            large_dataset.append({
                "id": f"alert_{i:04d}",
                "timestamp": (datetime.utcnow() - timedelta(hours=i % 24)).isoformat() + "Z",
                "rule": {
                    "id": 5501 + (i % 10),
                    "description": f"Test rule {i % 10}",
                    "level": 3 + (i % 10),
                    "groups": ["test"]
                },
                "agent": {
                    "id": f"{i % 10:03d}",
                    "name": f"test-agent-{i % 10:02d}"
                },
                "data": {"srcip": f"192.168.1.{i % 254 + 1}"}
            })
        
        # Mock multiple API calls for pagination
        def mock_get_alerts(limit, offset=0, **kwargs):
            start_idx = offset
            end_idx = min(offset + limit, len(large_dataset))
            return {
                "data": {"affected_items": large_dataset[start_idx:end_idx]}
            }
        
        wazuh_server.api_client.get_alerts.side_effect = mock_get_alerts
        
        arguments = {"time_range": "24h", "max_alerts": 2000}
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        response_data = json.loads(result[0].text)
        assert response_data["summary"]["total_alerts"] == 2000
        
        # Verify API was called multiple times for pagination
        assert wazuh_server.api_client.get_alerts.call_count >= 2
    
    async def test_custom_time_range(self, wazuh_server, mock_alerts_data):
        """Test custom time range functionality."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_data}
        }
        
        arguments = {
            "time_range": "custom",
            "custom_start": "2024-01-01T00:00:00",
            "custom_end": "2024-01-02T00:00:00"
        }
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        response_data = json.loads(result[0].text)
        query_params = response_data["query_parameters"]
        
        assert query_params["time_range"] == "custom"
        assert "2024-01-01T00:00:00" in query_params["period"]
        assert "2024-01-02T00:00:00" in query_params["period"]
    
    async def test_error_handling(self, wazuh_server):
        """Test error handling in alert summary."""
        # Mock API error
        wazuh_server.api_client.get_alerts.side_effect = Exception("API Error")
        
        arguments = {"time_range": "24h"}
        
        with pytest.raises(Exception):
            await wazuh_server._handle_get_wazuh_alert_summary(arguments)
    
    async def test_memory_efficiency_indicator(self, wazuh_server, mock_alerts_data):
        """Test memory efficiency indicator."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_data}
        }
        
        arguments = {"time_range": "24h"}
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        response_data = json.loads(result[0].text)
        metadata = response_data["analysis_metadata"]
        
        assert "memory_efficient" in metadata
        assert metadata["memory_efficient"] is True  # Small dataset
        assert "processing_time_seconds" in metadata
        assert "alerts_per_second" in metadata


class TestAlertSummaryHelperMethods:
    """Test helper methods used in alert summary."""
    
    @pytest.fixture
    def wazuh_server(self):
        """Create a minimal server instance for testing helper methods."""
        with patch('wazuh_mcp_server.main.WazuhConfig') as mock_config:
            mock_config.from_env.return_value = MagicMock()
            mock_config.from_env.return_value.log_level = "INFO"
            mock_config.from_env.return_value.debug = False
            
            server = WazuhMCPServer()
            return server
    
    def test_map_level_to_severity(self, wazuh_server):
        """Test alert level to severity mapping."""
        assert wazuh_server._map_level_to_severity(1) == "low"
        assert wazuh_server._map_level_to_severity(6) == "low"
        assert wazuh_server._map_level_to_severity(7) == "medium"
        assert wazuh_server._map_level_to_severity(9) == "medium"
        assert wazuh_server._map_level_to_severity(10) == "high"
        assert wazuh_server._map_level_to_severity(12) == "high"
        assert wazuh_server._map_level_to_severity(13) == "critical"
        assert wazuh_server._map_level_to_severity(15) == "critical"
    
    def test_calculate_time_range_standard(self, wazuh_server):
        """Test time range calculation for standard ranges."""
        from wazuh_mcp_server.utils.validation import AlertSummaryQuery
        
        query = AlertSummaryQuery(time_range="24h")
        result = wazuh_server._calculate_time_range(query)
        
        assert "start_time" in result
        assert "end_time" in result
        assert "duration_seconds" in result
        assert "duration_hours" in result
        
        # Should be approximately 24 hours
        assert abs(result["duration_hours"] - 24) < 0.1
    
    def test_calculate_time_range_custom(self, wazuh_server):
        """Test time range calculation for custom ranges."""
        from wazuh_mcp_server.utils.validation import AlertSummaryQuery
        
        query = AlertSummaryQuery(
            time_range="custom",
            custom_start="2024-01-01T00:00:00",
            custom_end="2024-01-02T12:00:00"
        )
        result = wazuh_server._calculate_time_range(query)
        
        # Should be exactly 36 hours
        assert result["duration_hours"] == 36.0
    
    def test_filter_alerts_by_severity(self, wazuh_server, mock_alerts_data):
        """Test alert filtering by severity."""
        from wazuh_mcp_server.utils.validation import AlertSummaryQuery
        
        query = AlertSummaryQuery(
            time_range="24h",
            severity_filter=["critical"]
        )
        time_params = {"start_time": datetime.utcnow() - timedelta(days=1),
                      "end_time": datetime.utcnow()}
        
        filtered = wazuh_server._filter_alerts(mock_alerts_data, query, time_params)
        
        # Should only have critical alerts (level >= 13)
        assert len(filtered) == 1
        assert filtered[0]["rule"]["level"] == 15
    
    def test_filter_alerts_by_agent(self, wazuh_server, mock_alerts_data):
        """Test alert filtering by agent."""
        from wazuh_mcp_server.utils.validation import AlertSummaryQuery
        
        query = AlertSummaryQuery(
            time_range="24h",
            agent_filter=["web-server-01"]
        )
        time_params = {"start_time": datetime.utcnow() - timedelta(days=1),
                      "end_time": datetime.utcnow()}
        
        filtered = wazuh_server._filter_alerts(mock_alerts_data, query, time_params)
        
        # Should only have alerts from web-server-01
        assert len(filtered) == 2
        for alert in filtered:
            assert alert["agent"]["name"] == "web-server-01"


@pytest.mark.asyncio
class TestAlertSummaryEdgeCases:
    """Test edge cases and error conditions."""
    
    @pytest.fixture
    async def wazuh_server(self):
        """Create a mock server for edge case testing."""
        with patch('wazuh_mcp_server.main.WazuhConfig') as mock_config:
            mock_config.from_env.return_value = MagicMock()
            mock_config.from_env.return_value.log_level = "INFO"
            mock_config.from_env.return_value.debug = False
            mock_config.from_env.return_value.request_timeout_seconds = 30
            
            server = WazuhMCPServer()
            server.api_client = AsyncMock()
            return server
    
    async def test_malformed_alert_data(self, wazuh_server):
        """Test handling of malformed alert data."""
        # Mock response with malformed data
        malformed_alerts = [
            {"id": "alert_001"},  # Missing required fields
            {"invalid": "structure"},  # Completely wrong structure
            {
                "id": "alert_002",
                "timestamp": "invalid_timestamp",
                "rule": {"level": "not_a_number"}
            }
        ]
        
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": malformed_alerts}
        }
        
        arguments = {"time_range": "24h"}
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        # Should not crash and should handle gracefully
        response_data = json.loads(result[0].text)
        assert "summary" in response_data
        assert response_data["summary"]["total_alerts"] >= 0
    
    async def test_api_timeout_partial_results(self, wazuh_server):
        """Test handling of API timeouts with partial results."""
        # First call succeeds, second call fails
        def mock_api_calls(limit, offset=0, **kwargs):
            if offset == 0:
                return {"data": {"affected_items": [{"id": "alert_001", "rule": {"level": 5}}]}}
            else:
                raise Exception("Timeout")
        
        wazuh_server.api_client.get_alerts.side_effect = mock_api_calls
        
        arguments = {"time_range": "24h", "max_alerts": 2000}
        
        # Should not raise exception, should return partial results
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        response_data = json.loads(result[0].text)
        
        assert response_data["summary"]["total_alerts"] == 1
    
    async def test_zero_duration_time_range(self, wazuh_server):
        """Test handling of zero or very small time ranges."""
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {
            "time_range": "custom",
            "custom_start": "2024-01-01T12:00:00",
            "custom_end": "2024-01-01T12:00:00"  # Same time
        }
        
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        response_data = json.loads(result[0].text)
        
        # Should handle gracefully
        assert response_data["query_parameters"]["duration_hours"] == 0.0
    
    async def test_very_large_dataset_memory_management(self, wazuh_server):
        """Test memory management with very large datasets."""
        # Mock response that returns max alerts
        large_dataset = [
            {
                "id": f"alert_{i:06d}",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "rule": {"id": i, "level": 5, "description": f"Rule {i}"},
                "agent": {"id": f"{i % 100:03d}", "name": f"agent-{i % 100}"}
            }
            for i in range(1000)  # Create 1000 alerts per batch
        ]
        
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": large_dataset}
        }
        
        arguments = {"time_range": "24h", "max_alerts": 10000}
        result = await wazuh_server._handle_get_wazuh_alert_summary(arguments)
        
        response_data = json.loads(result[0].text)
        metadata = response_data["analysis_metadata"]
        
        # Should indicate non-memory-efficient processing
        assert "memory_efficient" in metadata
        # Large dataset should be processed but marked as non-memory-efficient
        assert response_data["summary"]["total_alerts"] > 0