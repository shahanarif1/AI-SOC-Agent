"""Tests for statistics tools."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta

from wazuh_mcp_server.tools.statistics import StatisticsTools


class TestStatisticsTools:
    """Test cases for StatisticsTools class."""
    
    @pytest.fixture
    def mock_server(self):
        """Create a mock server instance."""
        server = Mock()
        server.api_client = AsyncMock()
        server.logger = Mock()
        server.config = Mock()
        return server
    
    @pytest.fixture
    def statistics_tools(self, mock_server):
        """Create StatisticsTools instance with mock server."""
        return StatisticsTools(mock_server)
    
    def test_tool_definitions(self, statistics_tools):
        """Test that tool definitions are properly created."""
        tools = statistics_tools.tool_definitions
        
        assert len(tools) == 4
        tool_names = [tool.name for tool in tools]
        assert "get_wazuh_alert_summary" in tool_names
        assert "get_wazuh_weekly_stats" in tool_names
        assert "get_wazuh_remoted_stats" in tool_names
        assert "get_wazuh_log_collector_stats" in tool_names
    
    def test_handler_mapping(self, statistics_tools):
        """Test that handler mapping is correct."""
        mapping = statistics_tools.get_handler_mapping()
        
        assert "get_wazuh_alert_summary" in mapping
        assert "get_wazuh_weekly_stats" in mapping
        assert "get_wazuh_remoted_stats" in mapping
        assert "get_wazuh_log_collector_stats" in mapping
        
        # Check all handlers are callable
        for handler in mapping.values():
            assert callable(handler)
    
    @pytest.mark.asyncio
    async def test_handle_alert_summary_advanced(self, statistics_tools, mock_server):
        """Test advanced alert summary handler."""
        # Mock API response
        mock_server.api_client.get_alerts.return_value = {
            "data": {
                "affected_items": [
                    {
                        "rule": {"id": "5501", "level": 7},
                        "agent": {"id": "001"},
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": {"srcip": "192.168.1.1", "srcuser": "admin"}
                    },
                    {
                        "rule": {"id": "5502", "level": 10},
                        "agent": {"id": "002"},
                        "timestamp": (datetime.utcnow() - timedelta(minutes=30)).isoformat(),
                        "data": {"srcip": "192.168.1.2", "process": "sshd"}
                    }
                ]
            }
        }
        
        # Call handler
        result = await statistics_tools.handle_alert_summary_advanced({
            "time_range": 3600,
            "include_anomalies": True,
            "include_predictions": False
        })
        
        # Verify result structure
        assert result["status"] == "success"
        assert "data" in result
        data = result["data"]
        
        assert "overview" in data
        assert data["overview"]["total_alerts"] == 2
        
        assert "statistics" in data
        assert "patterns" in data
        assert "top_indicators" in data
        assert "anomalies" in data
        
        # Verify API was called correctly
        mock_server.api_client.get_alerts.assert_called_once_with(
            limit=10000,
            time_range=3600
        )
    
    @pytest.mark.asyncio
    async def test_handle_weekly_stats(self, statistics_tools, mock_server):
        """Test weekly statistics handler."""
        # Mock API response
        mock_server.api_client.get_manager_stats.return_value = {
            "data": {
                "total_alerts": 1500,
                "daily_average": 214,
                "peak_day": "Monday",
                "total_events": 50000,
                "eps": 0.58,
                "avg_processing_time": 0.025,
                "peak_memory": 512
            }
        }
        
        # Call handler
        result = await statistics_tools.handle_weekly_stats({
            "weeks": 1,
            "compare_previous": False
        })
        
        # Verify result structure
        assert result["status"] == "success"
        assert "data" in result
        data = result["data"]
        
        assert "period" in data
        assert data["period"]["weeks"] == 1
        
        assert "alerts" in data
        assert "events" in data
        assert "performance" in data
        assert "anomalies" in data
        
        # Should not have comparison without compare_previous
        assert "comparison" not in data
    
    @pytest.mark.asyncio
    async def test_handle_weekly_stats_with_comparison(self, statistics_tools, mock_server):
        """Test weekly statistics with period comparison."""
        # Mock API responses for current and previous periods
        mock_server.api_client.get_manager_stats.side_effect = [
            {"data": {"total_alerts": 1500}},  # Current period
            {"data": {"total_alerts": 1200}}   # Previous period
        ]
        
        # Call handler
        result = await statistics_tools.handle_weekly_stats({
            "weeks": 1,
            "compare_previous": True
        })
        
        # Verify comparison was performed
        assert result["status"] == "success"
        data = result["data"]
        assert "comparison" in data
        assert data["comparison"]["alert_change_percent"] == 25.0
        assert data["comparison"]["trend"] == "increasing"
        
        # Verify two API calls were made
        assert mock_server.api_client.get_manager_stats.call_count == 2
    
    @pytest.mark.asyncio
    async def test_handle_remoted_stats(self, statistics_tools, mock_server):
        """Test remote daemon statistics handler."""
        # Mock API response
        mock_server.api_client.get_remoted_stats.return_value = {
            "data": {
                "uptime": 86400,
                "last_restart": "2024-01-14T00:00:00Z",
                "active_connections": 50,
                "total_connections": 1000,
                "failed_connections": 10,
                "messages_received": 50000,
                "messages_sent": 48000,
                "mps": 1.2,
                "queue_size": 100,
                "queue_usage": 25,
                "cpu_usage": 15.5,
                "memory_usage": 256,
                "bandwidth": 10.5
            }
        }
        
        # Call handler
        result = await statistics_tools.handle_remoted_stats({
            "include_performance": True
        })
        
        # Verify result structure
        assert result["status"] == "success"
        data = result["data"]
        
        assert "daemon_status" in data
        assert "connection_stats" in data
        assert "message_stats" in data
        assert "queue_stats" in data
        assert "performance" in data
        assert "health_assessment" in data
        
        # Check health assessment
        health = data["health_assessment"]
        assert health["status"] == "healthy"
        assert health["score"] == 100
    
    @pytest.mark.asyncio
    async def test_handle_log_collector_stats(self, statistics_tools, mock_server):
        """Test log collector statistics handler."""
        # Mock API response
        mock_server.api_client.get_manager_stats.return_value = {
            "data": {
                "files_monitored": 25,
                "bytes_read": 1073741824,  # 1GB
                "lines_processed": 1000000,
                "coverage": 85,
                "monitored_paths": ["/var/log/syslog", "/var/log/auth.log"],
                "missing_paths": [],
                "read_rate": 5.5,
                "processing_delay": 50,
                "files": [
                    {
                        "path": "/var/log/syslog",
                        "size": 104857600,  # 100MB
                        "lines_read": 500000,
                        "last_read": "2024-01-14T10:00:00Z"
                    }
                ]
            }
        }
        
        # Call handler without agent_id (global stats)
        result = await statistics_tools.handle_log_collector_stats({
            "include_file_analysis": True
        })
        
        # Verify result structure
        assert result["status"] == "success"
        data = result["data"]
        
        assert "overview" in data
        assert data["overview"]["total_files_monitored"] == 25
        
        assert "coverage" in data
        assert "performance" in data
        assert "file_analysis" in data
        assert "recommendations" in data
        
        # Should have no recommendations for good coverage
        assert len(data["recommendations"]) == 0
    
    @pytest.mark.asyncio
    async def test_handle_log_collector_stats_with_agent(self, statistics_tools, mock_server):
        """Test log collector statistics for specific agent."""
        # Mock API response
        mock_server.api_client.get_agent_stats.return_value = {
            "data": {
                "files_monitored": 10,
                "bytes_read": 536870912,  # 512MB
                "lines_processed": 500000
            }
        }
        
        # Call handler with agent_id
        result = await statistics_tools.handle_log_collector_stats({
            "agent_id": "001",
            "include_file_analysis": False
        })
        
        # Verify result
        assert result["status"] == "success"
        assert result["metadata"]["agent_id"] == "001"
        
        # Should not have file analysis
        assert "file_analysis" not in result["data"]
        
        # Verify correct API call
        mock_server.api_client.get_agent_stats.assert_called_once_with(
            agent_id="001",
            component="logcollector"
        )
    
    def test_detect_anomalies(self, statistics_tools):
        """Test anomaly detection in alerts."""
        # Create test data with spike
        alerts = []
        base_time = datetime.utcnow()
        
        # Normal hours (10 alerts each)
        for hour in range(20):
            for i in range(10):
                alerts.append({
                    "timestamp": (base_time - timedelta(hours=hour)).isoformat() + "Z"
                })
        
        # Spike hour (50 alerts)
        spike_time = base_time - timedelta(hours=5)
        for i in range(50):
            alerts.append({
                "timestamp": spike_time.isoformat() + "Z"
            })
        
        # Detect anomalies
        anomalies = statistics_tools._detect_anomalies(alerts)
        
        # Should detect the spike
        assert len(anomalies) > 0
        assert any(a["type"] == "alert_spike" for a in anomalies)
    
    def test_calculate_alert_statistics(self, statistics_tools):
        """Test alert statistics calculation."""
        alerts = [
            {
                "rule": {"id": "5501", "level": 7},
                "agent": {"id": "001"},
                "timestamp": datetime.utcnow().isoformat() + "Z"
            },
            {
                "rule": {"id": "5502", "level": 10},
                "agent": {"id": "001"},
                "timestamp": (datetime.utcnow() - timedelta(hours=1)).isoformat() + "Z"
            },
            {
                "rule": {"id": "5501", "level": 7},
                "agent": {"id": "002"},
                "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat() + "Z"
            }
        ]
        
        stats = statistics_tools._calculate_alert_statistics(alerts)
        
        assert "time_statistics" in stats
        assert stats["time_statistics"]["alert_rate_per_hour"] > 0
        
        assert "level_distribution" in stats
        assert stats["level_distribution"][7] == 2
        assert stats["level_distribution"][10] == 1
        
        assert stats["unique_rules"] == 2
        assert stats["unique_agents"] == 2
    
    def test_assess_remoted_health(self, statistics_tools):
        """Test remote daemon health assessment."""
        # Healthy stats
        healthy_stats = {
            "connection_stats": {
                "failed_connections": 5,
                "total_connections": 1000
            },
            "queue_stats": {
                "queue_usage_percent": 50
            }
        }
        
        health = statistics_tools._assess_remoted_health(healthy_stats)
        assert health["status"] == "healthy"
        assert health["score"] == 100
        assert len(health["issues"]) == 0
        
        # Degraded stats
        degraded_stats = {
            "connection_stats": {
                "failed_connections": 150,
                "total_connections": 1000
            },
            "queue_stats": {
                "queue_usage_percent": 85
            }
        }
        
        health = statistics_tools._assess_remoted_health(degraded_stats)
        assert health["status"] == "degraded"
        assert health["score"] < 100
        assert len(health["issues"]) > 0
    
    @pytest.mark.asyncio
    async def test_error_handling(self, statistics_tools, mock_server):
        """Test error handling in handlers."""
        # Make API call fail
        mock_server.api_client.get_alerts.side_effect = Exception("API Error")
        
        # Call handler
        result = await statistics_tools.handle_alert_summary_advanced({})
        
        # Should return error response
        assert result["status"] == "error"
        assert "error" in result
        assert result["error"]["type"] == "Exception"
        assert "API Error" in result["error"]["message"]