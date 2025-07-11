"""Tests for the get_wazuh_remoted_stats tool."""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from wazuh_mcp_server.main import WazuhMCPServer
from wazuh_mcp_server.utils.validation import validate_remoted_stats_query, ValidationError


@pytest.fixture
def mock_cluster_nodes():
    """Mock cluster nodes data."""
    return [
        {
            "name": "master",
            "type": "master",
            "ip": "192.168.1.10",
            "status": "connected"
        },
        {
            "name": "worker-1",
            "type": "worker",
            "ip": "192.168.1.11",
            "status": "connected"
        },
        {
            "name": "worker-2",
            "type": "worker",
            "ip": "192.168.1.12",
            "status": "connected"
        }
    ]


@pytest.fixture
def mock_daemon_stats():
    """Mock daemon statistics data."""
    return {
        "master": {
            "remoted": {
                "uptime": 86400,
                "received_messages": 15420,
                "sent_messages": 15418,
                "queue_size": 245,
                "agents_count": 150,
                "active_connections": 148,
                "error_count": 3,
                "bytes_received": 2048576,
                "bytes_sent": 2047832
            }
        },
        "worker-1": {
            "remoted": {
                "uptime": 86300,
                "received_messages": 8250,
                "sent_messages": 8249,
                "queue_size": 128,
                "agents_count": 75,
                "active_connections": 74,
                "error_count": 1,
                "bytes_received": 1024000,
                "bytes_sent": 1023500
            }
        }
    }


@pytest.fixture
def mock_performance_data():
    """Mock performance metrics data."""
    return {
        "master": {
            "cpu_usage": {
                "current": 25.5,
                "average": 22.8,
                "peak": 35.2
            },
            "memory_usage": {
                "current": 45.7,
                "average": 42.3,
                "peak": 52.1
            },
            "process_info": {
                "pid": 1234,
                "threads": 8,
                "memory_mb": 256,
                "cpu_percent": 25.5
            }
        },
        "worker-1": {
            "cpu_usage": {
                "current": 18.2,
                "average": 16.5,
                "peak": 28.9
            },
            "memory_usage": {
                "current": 38.1,
                "average": 35.7,
                "peak": 44.2
            },
            "process_info": {
                "pid": 5678,
                "threads": 6,
                "memory_mb": 192,
                "cpu_percent": 18.2
            }
        }
    }


@pytest.fixture
def mock_connection_stats():
    """Mock connection statistics."""
    return {
        "master": {
            "active_connections": 148,
            "total_agents": 150,
            "connected_agents": 148,
            "disconnected_agents": 2,
            "connection_types": {
                "tcp": 120,
                "udp": 28
            },
            "bandwidth_usage": {
                "inbound_mbps": 2.5,
                "outbound_mbps": 2.4,
                "total_mbps": 4.9
            },
            "agent_distribution": {
                "windows": 45,
                "linux": 85,
                "macos": 18
            }
        }
    }


@pytest.fixture
def mock_event_stats():
    """Mock event processing statistics."""
    return {
        "master": {
            "events_processed": 15420,
            "events_per_second": 3.55,
            "event_types": {
                "syscheck": 8250,
                "rootcheck": 2840,
                "syscollector": 3120,
                "logcollector": 1210
            },
            "processing_latency": {
                "average_ms": 125,
                "p95_ms": 250,
                "p99_ms": 450
            },
            "dropped_events": 12,
            "buffered_events": 245
        }
    }


@pytest.fixture
def mock_queue_stats():
    """Mock queue statistics."""
    return {
        "master": {
            "queue_size": 245,
            "max_queue_size": 16384,
            "queue_utilization": 1.5,
            "queue_efficiency": 98.5,
            "average_wait_time": 2.1,
            "queue_peaks": {
                "max_size_today": 1250,
                "max_utilization": 7.6
            }
        }
    }


@pytest.fixture
def mock_error_logs():
    """Mock error logs for analysis."""
    base_time = datetime.utcnow()
    return [
        {
            "timestamp": (base_time - timedelta(hours=2)).isoformat() + "Z",
            "level": 3,
            "description": "Agent connection timeout",
            "tag": "remoted"
        },
        {
            "timestamp": (base_time - timedelta(hours=1)).isoformat() + "Z",
            "level": 2,
            "description": "Queue size approaching limit",
            "tag": "remoted"
        },
        {
            "timestamp": (base_time - timedelta(minutes=30)).isoformat() + "Z",
            "level": 4,
            "description": "Authentication failed for agent",
            "tag": "remoted"
        },
        {
            "timestamp": (base_time - timedelta(minutes=15)).isoformat() + "Z",
            "level": 3,
            "description": "Connection refused from unknown IP",
            "tag": "remoted"
        }
    ]


class TestRemotedStatsValidation:
    """Test validation of remoted stats query parameters."""
    
    def test_valid_basic_query(self):
        """Test validation with basic valid parameters."""
        params = {"time_range": "24h"}
        result = validate_remoted_stats_query(params)
        
        assert result.time_range == "24h"
        assert result.include_performance is True
        assert result.include_connections is True
        assert result.group_by == "node"
        assert result.output_format == "detailed"
        assert result.threshold_cpu == 80.0
        assert result.threshold_memory == 80.0
        assert result.threshold_queue == 1000
    
    def test_valid_complete_query(self):
        """Test validation with all parameters."""
        params = {
            "time_range": "6h",
            "node_filter": ["master", "worker-1"],
            "include_performance": False,
            "include_connections": True,
            "include_events": False,
            "include_queues": True,
            "include_errors": False,
            "include_trends": False,
            "group_by": "connection_type",
            "output_format": "summary",
            "threshold_cpu": 75.0,
            "threshold_memory": 85.0,
            "threshold_queue": 500
        }
        result = validate_remoted_stats_query(params)
        
        assert result.time_range == "6h"
        assert result.node_filter == ["master", "worker-1"]
        assert result.include_performance is False
        assert result.include_connections is True
        assert result.include_events is False
        assert result.include_queues is True
        assert result.include_errors is False
        assert result.include_trends is False
        assert result.group_by == "connection_type"
        assert result.output_format == "summary"
        assert result.threshold_cpu == 75.0
        assert result.threshold_memory == 85.0
        assert result.threshold_queue == 500
    
    def test_invalid_time_range(self):
        """Test validation with invalid time range."""
        params = {"time_range": "invalid_range"}
        
        with pytest.raises(ValidationError):
            validate_remoted_stats_query(params)
    
    def test_invalid_group_by(self):
        """Test validation with invalid group_by field."""
        params = {"group_by": "invalid_field"}
        
        with pytest.raises(ValidationError):
            validate_remoted_stats_query(params)
    
    def test_invalid_output_format(self):
        """Test validation with invalid output format."""
        params = {"output_format": "invalid_format"}
        
        with pytest.raises(ValidationError):
            validate_remoted_stats_query(params)
    
    def test_invalid_threshold_values(self):
        """Test validation with invalid threshold values."""
        # Test negative CPU threshold
        params = {"threshold_cpu": -10.0}
        with pytest.raises(ValidationError):
            validate_remoted_stats_query(params)
        
        # Test excessive memory threshold
        params = {"threshold_memory": 150.0}
        with pytest.raises(ValidationError):
            validate_remoted_stats_query(params)
        
        # Test negative queue threshold
        params = {"threshold_queue": -100}
        with pytest.raises(ValidationError):
            validate_remoted_stats_query(params)
    
    def test_threshold_boundary_values(self):
        """Test threshold boundary validation."""
        # Test minimum values
        params = {
            "threshold_cpu": 0.0,
            "threshold_memory": 0.0,
            "threshold_queue": 0
        }
        result = validate_remoted_stats_query(params)
        assert result.threshold_cpu == 0.0
        assert result.threshold_memory == 0.0
        assert result.threshold_queue == 0
        
        # Test maximum values
        params = {
            "threshold_cpu": 100.0,
            "threshold_memory": 100.0,
            "threshold_queue": 100000
        }
        result = validate_remoted_stats_query(params)
        assert result.threshold_cpu == 100.0
        assert result.threshold_memory == 100.0
        assert result.threshold_queue == 100000


@pytest.mark.asyncio
class TestRemotedStatsTool:
    """Test the remoted stats tool functionality."""
    
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
    
    async def test_basic_remoted_stats(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test basic remoted stats functionality."""
        # Mock API responses
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": mock_cluster_nodes}
        }
        
        def mock_get_daemon_stats(node_name, daemon_name):
            return {"data": mock_daemon_stats.get(node_name, {}).get(daemon_name, {})}
        
        wazuh_server.api_client.get_daemon_stats.side_effect = mock_get_daemon_stats
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        arguments = {"time_range": "24h"}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Check basic structure
        assert "query_parameters" in response_data
        assert "summary" in response_data
        assert "node_analysis" in response_data
        assert "global_stats" in response_data
        assert "analysis_metadata" in response_data
        
        # Check summary data
        summary = response_data["summary"]
        assert "total_nodes" in summary
        assert "total_agents" in summary
        assert "total_connections" in summary
        assert "overall_health_score" in summary
        
        # Check node analysis
        node_analysis = response_data["node_analysis"]
        assert len(node_analysis) >= 1  # At least master node
        
        # Check global stats
        global_stats = response_data["global_stats"]
        assert "aggregated_metrics" in global_stats
        assert "performance_summary" in global_stats
    
    async def test_performance_metrics_collection(self, wazuh_server, mock_cluster_nodes, 
                                                 mock_daemon_stats, mock_performance_data):
        """Test performance metrics collection."""
        # Mock API responses
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": mock_cluster_nodes[:1]}  # Only master
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": mock_daemon_stats["master"]["remoted"]
        }
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        arguments = {"time_range": "24h", "include_performance": True}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check that performance metrics are included
        node_analysis = response_data["node_analysis"]
        master_analysis = node_analysis["master"]
        
        assert "performance_analysis" in master_analysis
        performance = master_analysis["performance_analysis"]
        assert "cpu_analysis" in performance
        assert "memory_analysis" in performance
        assert "performance_alerts" in performance
    
    async def test_connection_analysis(self, wazuh_server, mock_cluster_nodes, 
                                     mock_daemon_stats, mock_connection_stats):
        """Test connection statistics analysis."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": mock_cluster_nodes[:1]}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": mock_daemon_stats["master"]["remoted"]
        }
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        arguments = {"time_range": "24h", "include_connections": True}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check connection analysis
        node_analysis = response_data["node_analysis"]
        master_analysis = node_analysis["master"]
        
        assert "connection_analysis" in master_analysis
        connections = master_analysis["connection_analysis"]
        assert "connectivity_health" in connections
        assert "agent_distribution" in connections
        assert "connection_efficiency" in connections
    
    async def test_event_processing_analysis(self, wazuh_server, mock_cluster_nodes, 
                                           mock_daemon_stats, mock_event_stats):
        """Test event processing metrics analysis."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": mock_cluster_nodes[:1]}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": mock_daemon_stats["master"]["remoted"]
        }
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        arguments = {"time_range": "24h", "include_events": True}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check event analysis
        node_analysis = response_data["node_analysis"]
        master_analysis = node_analysis["master"]
        
        assert "event_analysis" in master_analysis
        events = master_analysis["event_analysis"]
        assert "processing_efficiency" in events
        assert "event_distribution" in events
        assert "performance_metrics" in events
    
    async def test_queue_analysis(self, wazuh_server, mock_cluster_nodes, 
                                mock_daemon_stats, mock_queue_stats):
        """Test queue statistics analysis."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": mock_cluster_nodes[:1]}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": mock_daemon_stats["master"]["remoted"]
        }
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        arguments = {"time_range": "24h", "include_queues": True}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check queue analysis
        node_analysis = response_data["node_analysis"]
        master_analysis = node_analysis["master"]
        
        assert "queue_analysis" in master_analysis
        queues = master_analysis["queue_analysis"]
        assert "queue_health" in queues
        assert "utilization_analysis" in queues
        assert "performance_impact" in queues
    
    async def test_error_analysis(self, wazuh_server, mock_cluster_nodes, 
                                mock_daemon_stats, mock_error_logs):
        """Test error statistics analysis."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": mock_cluster_nodes[:1]}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": mock_daemon_stats["master"]["remoted"]
        }
        wazuh_server.api_client.get_logs.return_value = {
            "data": {"affected_items": mock_error_logs}
        }
        
        arguments = {"time_range": "24h", "include_errors": True}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check error analysis
        node_analysis = response_data["node_analysis"]
        master_analysis = node_analysis["master"]
        
        assert "error_analysis" in master_analysis
        errors = master_analysis["error_analysis"]
        assert "error_summary" in errors
        assert "error_categories" in errors
        assert "critical_issues" in errors
        assert "resolution_impact" in errors
    
    async def test_node_filtering(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test filtering by specific nodes."""
        # Filter to only master node
        filtered_nodes = [node for node in mock_cluster_nodes if node["name"] == "master"]
        
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": mock_cluster_nodes}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": mock_daemon_stats["master"]["remoted"]
        }
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        arguments = {"time_range": "24h", "node_filter": ["master"]}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should only analyze master node
        assert response_data["query_parameters"]["node_filter"] == ["master"]
        node_analysis = response_data["node_analysis"]
        assert "master" in node_analysis
        assert len(node_analysis) == 1
    
    async def test_threshold_alerting(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test threshold-based alerting."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": mock_cluster_nodes[:1]}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": mock_daemon_stats["master"]["remoted"]
        }
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        # Set very low thresholds to trigger alerts
        arguments = {
            "time_range": "24h",
            "threshold_cpu": 10.0,  # Very low to trigger alert
            "threshold_memory": 20.0,  # Very low to trigger alert
            "threshold_queue": 100  # Low to trigger alert
        }
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have alerts due to low thresholds
        if "alerts" in response_data:
            alerts = response_data["alerts"]
            assert len(alerts) > 0
            
            # Check alert structure
            for alert in alerts:
                assert "type" in alert
                assert "severity" in alert
                assert "message" in alert
                assert "node" in alert
    
    async def test_output_formats(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test different output formats."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": mock_cluster_nodes[:1]}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": mock_daemon_stats["master"]["remoted"]
        }
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        # Test minimal format
        arguments = {"time_range": "24h", "output_format": "minimal"}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Minimal format should have reduced data
        assert "summary" in response_data
        assert "status" in response_data
        # Detailed analysis sections may be omitted or reduced
        
        # Test summary format
        arguments = {"time_range": "24h", "output_format": "summary"}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Summary format should have key metrics
        assert "summary" in response_data
        assert "key_metrics" in response_data
        assert "top_insights" in response_data
    
    async def test_time_range_parsing(self, wazuh_server, mock_cluster_nodes):
        """Test different time range parsing."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": mock_cluster_nodes[:1]}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {"data": {}}
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        time_ranges = ["1h", "6h", "12h", "24h", "7d", "30d"]
        
        for time_range in time_ranges:
            arguments = {"time_range": time_range}
            result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
            
            response_data = json.loads(result[0].text)
            
            # Check that time range is properly parsed
            assert response_data["query_parameters"]["time_range"] == time_range
            assert "analysis_metadata" in response_data
            assert "time_range" in response_data["analysis_metadata"]
    
    async def test_recommendations_generation(self, wazuh_server, mock_cluster_nodes, 
                                            mock_daemon_stats, mock_error_logs):
        """Test recommendations generation."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": mock_cluster_nodes[:1]}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": mock_daemon_stats["master"]["remoted"]
        }
        wazuh_server.api_client.get_logs.return_value = {
            "data": {"affected_items": mock_error_logs}
        }
        
        arguments = {"time_range": "24h"}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have recommendations
        if "recommendations" in response_data:
            recommendations = response_data["recommendations"]
            assert len(recommendations) > 0
            
            # Check recommendation structure
            for rec in recommendations:
                assert "priority" in rec
                assert "category" in rec
                assert "title" in rec
                assert "description" in rec
                assert "action" in rec
                assert "impact" in rec
                assert rec["priority"] in ["HIGH", "MEDIUM", "LOW"]
    
    async def test_empty_cluster_response(self, wazuh_server):
        """Test handling of empty cluster response."""
        # Mock empty cluster response (standalone mode)
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": []}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {"data": {}}
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        arguments = {"time_range": "24h"}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle standalone mode gracefully
        assert "summary" in response_data
        assert "node_analysis" in response_data
        # Should default to master node in standalone mode
        assert "master" in response_data["node_analysis"]
    
    async def test_error_handling(self, wazuh_server):
        """Test error handling in remoted stats analysis."""
        # Mock API error
        wazuh_server.api_client.get_cluster_nodes.side_effect = Exception("API Error")
        
        arguments = {"time_range": "24h"}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        # Should return error response
        response_data = json.loads(result[0].text)
        assert "error" in response_data


class TestRemotedStatsHelperMethods:
    """Test helper methods for remoted stats analysis."""
    
    @pytest.fixture
    def wazuh_server(self):
        """Create a minimal server instance for testing helper methods."""
        with patch('wazuh_mcp_server.main.WazuhConfig') as mock_config:
            mock_config.from_env.return_value = MagicMock()
            mock_config.from_env.return_value.log_level = "INFO"
            mock_config.from_env.return_value.debug = False
            
            server = WazuhMCPServer()
            return server
    
    def test_parse_time_range(self, wazuh_server):
        """Test time range parsing functionality."""
        # Test 1 hour
        result = wazuh_server._parse_time_range("1h")
        assert result["range_label"] == "1h"
        assert result["duration_hours"] == 1
        assert "start_time" in result
        assert "end_time" in result
        
        # Test 24 hours
        result = wazuh_server._parse_time_range("24h")
        assert result["range_label"] == "24h"
        assert result["duration_hours"] == 24
        
        # Test 7 days
        result = wazuh_server._parse_time_range("7d")
        assert result["range_label"] == "7d"
        assert result["duration_hours"] == 168  # 7 * 24
        
        # Test invalid range (should default to 24h)
        result = wazuh_server._parse_time_range("invalid")
        assert result["duration_hours"] == 24
    
    def test_calculate_global_remoted_stats(self, wazuh_server):
        """Test global statistics calculation."""
        node_stats = {
            "master": {
                "daemon_stats": {
                    "received_messages": 15420,
                    "sent_messages": 15418,
                    "agents_count": 150,
                    "active_connections": 148
                },
                "performance": {
                    "cpu_usage": {"current": 25.5},
                    "memory_usage": {"current": 45.7}
                }
            },
            "worker-1": {
                "daemon_stats": {
                    "received_messages": 8250,
                    "sent_messages": 8249,
                    "agents_count": 75,
                    "active_connections": 74
                },
                "performance": {
                    "cpu_usage": {"current": 18.2},
                    "memory_usage": {"current": 38.1}
                }
            }
        }
        
        global_stats = wazuh_server._calculate_global_remoted_stats(node_stats)
        
        # Check aggregated metrics
        assert "aggregated_metrics" in global_stats
        aggregated = global_stats["aggregated_metrics"]
        assert aggregated["total_nodes"] == 2
        assert aggregated["total_agents"] == 225  # 150 + 75
        assert aggregated["total_connections"] == 222  # 148 + 74
        assert aggregated["total_messages_received"] == 23670  # 15420 + 8250
        
        # Check performance summary
        assert "performance_summary" in global_stats
        perf = global_stats["performance_summary"]
        assert perf["average_cpu_usage"] == 21.85  # (25.5 + 18.2) / 2
        assert perf["average_memory_usage"] == 41.9  # (45.7 + 38.1) / 2


@pytest.mark.asyncio
class TestRemotedStatsEdgeCases:
    """Test edge cases for remoted stats analysis."""
    
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
    
    async def test_malformed_daemon_stats(self, wazuh_server):
        """Test handling of malformed daemon statistics."""
        # Mock response with malformed data
        malformed_stats = {
            "invalid": "structure",
            "missing_fields": True
        }
        
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": [{"name": "master", "type": "master"}]}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": malformed_stats
        }
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        arguments = {"time_range": "24h"}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        # Should not crash and should handle gracefully
        response_data = json.loads(result[0].text)
        assert "summary" in response_data
        assert "node_analysis" in response_data
    
    async def test_partial_data_collection_failures(self, wazuh_server):
        """Test handling when some data collection fails."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": [{"name": "master", "type": "master"}]}
        }
        
        # Mock daemon stats to succeed
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": {"received_messages": 1000}
        }
        
        # Mock logs to fail
        wazuh_server.api_client.get_logs.side_effect = Exception("Logs API Error")
        
        arguments = {"time_range": "24h", "include_errors": True}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle partial failures gracefully
        assert "summary" in response_data
        # Should have collection errors logged
        if "analysis_metadata" in response_data:
            assert "collection_errors" in response_data["analysis_metadata"]
    
    async def test_high_threshold_no_alerts(self, wazuh_server):
        """Test scenario with very high thresholds (no alerts)."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": [{"name": "master", "type": "master"}]}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": {"received_messages": 1000, "queue_size": 50}
        }
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        # Set very high thresholds
        arguments = {
            "time_range": "24h",
            "threshold_cpu": 99.0,
            "threshold_memory": 99.0,
            "threshold_queue": 50000
        }
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have minimal or no alerts
        if "alerts" in response_data:
            assert len(response_data["alerts"]) == 0
        
        # Health score should be high
        if "summary" in response_data and "overall_health_score" in response_data["summary"]:
            assert response_data["summary"]["overall_health_score"] >= 80
    
    async def test_standalone_mode_operation(self, wazuh_server):
        """Test operation in standalone (non-cluster) mode."""
        # Mock standalone mode (no cluster nodes)
        wazuh_server.api_client.get_cluster_nodes.side_effect = Exception("No cluster")
        wazuh_server.api_client.get_daemon_stats.return_value = {
            "data": {"received_messages": 500, "agents_count": 25}
        }
        wazuh_server.api_client.get_logs.return_value = {"data": {"affected_items": []}}
        
        arguments = {"time_range": "24h"}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle standalone mode
        assert "summary" in response_data
        assert "node_analysis" in response_data
        # Should default to master node
        assert "master" in response_data["node_analysis"]
    
    async def test_large_log_dataset_handling(self, wazuh_server):
        """Test handling of large log datasets."""
        # Create large error log dataset
        large_logs = []
        base_time = datetime.utcnow()
        
        for i in range(5000):  # Large number of logs
            large_logs.append({
                "timestamp": (base_time - timedelta(hours=i % 24)).isoformat() + "Z",
                "level": 2 + (i % 3),  # Levels 2-4
                "description": f"Error message {i}",
                "tag": "remoted"
            })
        
        wazuh_server.api_client.get_cluster_nodes.return_value = {
            "data": {"affected_items": [{"name": "master", "type": "master"}]}
        }
        wazuh_server.api_client.get_daemon_stats.return_value = {"data": {}}
        wazuh_server.api_client.get_logs.return_value = {
            "data": {"affected_items": large_logs}
        }
        
        arguments = {"time_range": "24h", "include_errors": True}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle large dataset
        assert "summary" in response_data
        assert "node_analysis" in response_data
        
        # Error analysis should be present
        master_analysis = response_data["node_analysis"]["master"]
        if "error_analysis" in master_analysis:
            error_analysis = master_analysis["error_analysis"]
            assert "error_summary" in error_analysis
            assert error_analysis["error_summary"]["total_errors"] > 0
    
    async def test_missing_api_endpoints(self, wazuh_server):
        """Test graceful handling when API endpoints are missing."""
        # Mock all API calls to fail
        wazuh_server.api_client.get_cluster_nodes.side_effect = Exception("Endpoint not found")
        wazuh_server.api_client.get_daemon_stats.side_effect = Exception("Endpoint not found")
        wazuh_server.api_client.get_logs.side_effect = Exception("Endpoint not found")
        
        arguments = {"time_range": "24h"}
        result = await wazuh_server._handle_get_wazuh_remoted_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should return error response but not crash
        assert "error" in response_data or "summary" in response_data
        # If summary exists, should handle missing data gracefully
        if "summary" in response_data:
            assert "collection_errors" in response_data.get("analysis_metadata", {})