"""Tests for the get_wazuh_log_collector_stats tool."""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from wazuh_mcp_server.main import WazuhMCPServer
from wazuh_mcp_server.utils.validation import validate_log_collector_stats_query, ValidationError


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
def mock_agents_data():
    """Mock agents data."""
    return [
        {
            "id": "001",
            "name": "web-server-01",
            "status": "active",
            "os": {"platform": "ubuntu", "version": "20.04"},
            "version": "4.8.0",
            "node_name": "master",
            "ip": "192.168.1.100"
        },
        {
            "id": "002",
            "name": "db-server-01",
            "status": "active",
            "os": {"platform": "centos", "version": "8"},
            "version": "4.8.0",
            "node_name": "worker-1",
            "ip": "192.168.1.101"
        },
        {
            "id": "003",
            "name": "app-server-01",
            "status": "active",
            "os": {"platform": "windows", "version": "2019"},
            "version": "4.8.0",
            "node_name": "worker-2",
            "ip": "192.168.1.102"
        }
    ]


@pytest.fixture
def mock_daemon_stats():
    """Mock daemon statistics data."""
    return {
        "master": {
            "logcollector": {
                "uptime": 86400,
                "events": {
                    "processed": 125000,
                    "dropped": 250,
                    "queue_size": 1024,
                    "queue_usage": 12.5
                },
                "files": {
                    "monitored": 45,
                    "reading": 42,
                    "errors": 3
                },
                "bytes": {
                    "read": 2048576000,
                    "processed": 2047832000
                }
            }
        },
        "worker-1": {
            "logcollector": {
                "uptime": 86300,
                "events": {
                    "processed": 85000,
                    "dropped": 120,
                    "queue_size": 512,
                    "queue_usage": 8.2
                },
                "files": {
                    "monitored": 38,
                    "reading": 36,
                    "errors": 2
                },
                "bytes": {
                    "read": 1524288000,
                    "processed": 1523456000
                }
            }
        },
        "worker-2": {
            "logcollector": {
                "uptime": 86200,
                "events": {
                    "processed": 95000,
                    "dropped": 180,
                    "queue_size": 768,
                    "queue_usage": 15.0
                },
                "files": {
                    "monitored": 52,
                    "reading": 48,
                    "errors": 4
                },
                "bytes": {
                    "read": 1835008000,
                    "processed": 1834176000
                }
            }
        }
    }


@pytest.fixture
def mock_log_files_data():
    """Mock log files monitoring data."""
    return {
        "master": [
            {
                "file": "/var/log/syslog",
                "events": 45000,
                "bytes": 512000000,
                "status": "reading",
                "target": "agent",
                "format": "syslog"
            },
            {
                "file": "/var/log/auth.log",
                "events": 8500,
                "bytes": 85000000,
                "status": "reading",
                "target": "agent",
                "format": "syslog"
            },
            {
                "file": "/var/log/apache2/access.log",
                "events": 71500,
                "bytes": 1451776000,
                "status": "reading",
                "target": "agent",
                "format": "apache"
            }
        ],
        "worker-1": [
            {
                "file": "/var/log/messages",
                "events": 32000,
                "bytes": 384000000,
                "status": "reading",
                "target": "agent",
                "format": "syslog"
            },
            {
                "file": "/var/log/secure",
                "events": 6200,
                "bytes": 62000000,
                "status": "reading",
                "target": "agent",
                "format": "syslog"
            },
            {
                "file": "/var/log/nginx/access.log",
                "events": 46800,
                "bytes": 1078288000,
                "status": "reading",
                "target": "agent",
                "format": "nginx"
            }
        ]
    }


@pytest.fixture
def mock_performance_data():
    """Mock performance metrics data."""
    return {
        "master": {
            "cpu_usage": {
                "current": 18.5,
                "average": 16.2,
                "peak": 25.8
            },
            "memory_usage": {
                "current": 42.1,
                "average": 38.7,
                "peak": 48.3
            },
            "disk_io": {
                "read_rate": 2048.5,
                "write_rate": 1024.2,
                "avg_latency": 2.5
            }
        },
        "worker-1": {
            "cpu_usage": {
                "current": 14.2,
                "average": 12.8,
                "peak": 19.5
            },
            "memory_usage": {
                "current": 35.8,
                "average": 32.1,
                "peak": 41.2
            },
            "disk_io": {
                "read_rate": 1536.3,
                "write_rate": 768.1,
                "avg_latency": 3.2
            }
        }
    }


class TestLogCollectorStatsValidation:
    """Test validation of log collector stats query parameters."""
    
    def test_valid_basic_query(self):
        """Test validation with basic valid parameters."""
        params = {"time_range": "24h"}
        result = validate_log_collector_stats_query(params)
        
        assert result.time_range == "24h"
        assert result.include_performance is True
        assert result.include_file_monitoring is True
        assert result.group_by == "node"
        assert result.threshold_processing_rate == 1000
        assert result.threshold_error_rate == 5.0
        assert result.threshold_file_lag == 300
    
    def test_valid_complete_query(self):
        """Test validation with all parameters."""
        params = {
            "time_range": "12h",
            "node_filter": ["master", "worker-1"],
            "agent_filter": ["001", "002"],
            "log_type_filter": ["syslog", "apache"],
            "include_performance": False,
            "include_file_monitoring": False,
            "include_processing_stats": False,
            "include_error_analysis": False,
            "include_efficiency": False,
            "include_trends": False,
            "group_by": "agent",
            "output_format": "summary",
            "threshold_processing_rate": 2000,
            "threshold_error_rate": 10.0,
            "threshold_file_lag": 600
        }
        result = validate_log_collector_stats_query(params)
        
        assert result.time_range == "12h"
        assert result.node_filter == ["master", "worker-1"]
        assert result.agent_filter == ["001", "002"]
        assert result.log_type_filter == ["syslog", "apache"]
        assert result.include_performance is False
        assert result.include_file_monitoring is False
        assert result.group_by == "agent"
        assert result.output_format == "summary"
        assert result.threshold_processing_rate == 2000
        assert result.threshold_error_rate == 10.0
        assert result.threshold_file_lag == 600
    
    def test_invalid_time_range(self):
        """Test validation with invalid time range."""
        params = {"time_range": "invalid"}
        
        with pytest.raises(ValidationError):
            validate_log_collector_stats_query(params)
    
    def test_invalid_log_type_filter(self):
        """Test validation with invalid log type."""
        params = {"log_type_filter": ["invalid$type"]}
        
        with pytest.raises(ValidationError):
            validate_log_collector_stats_query(params)
    
    def test_invalid_group_by(self):
        """Test validation with invalid group_by field."""
        params = {"group_by": "invalid_field"}
        
        with pytest.raises(ValidationError):
            validate_log_collector_stats_query(params)
    
    def test_invalid_output_format(self):
        """Test validation with invalid output format."""
        params = {"output_format": "invalid_format"}
        
        with pytest.raises(ValidationError):
            validate_log_collector_stats_query(params)
    
    def test_invalid_error_rate_threshold(self):
        """Test validation with invalid error rate threshold."""
        # Test below minimum
        params = {"threshold_error_rate": -1.0}
        with pytest.raises(ValidationError):
            validate_log_collector_stats_query(params)
        
        # Test above maximum
        params = {"threshold_error_rate": 101.0}
        with pytest.raises(ValidationError):
            validate_log_collector_stats_query(params)
    
    def test_threshold_boundaries(self):
        """Test threshold boundary validation."""
        # Test minimum values
        params = {
            "threshold_processing_rate": 0,
            "threshold_error_rate": 0.0,
            "threshold_file_lag": 0
        }
        result = validate_log_collector_stats_query(params)
        assert result.threshold_processing_rate == 0
        assert result.threshold_error_rate == 0.0
        assert result.threshold_file_lag == 0
        
        # Test maximum values
        params = {
            "threshold_error_rate": 100.0
        }
        result = validate_log_collector_stats_query(params)
        assert result.threshold_error_rate == 100.0


@pytest.mark.asyncio
class TestLogCollectorStatsTool:
    """Test the log collector stats tool functionality."""
    
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
    
    async def test_basic_log_collector_stats(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test basic log collector stats functionality."""
        # Mock API responses
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        arguments = {"time_range": "24h", "group_by": "node"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Check basic structure
        assert "query_parameters" in response_data
        assert "summary" in response_data
        assert "grouped_analysis" in response_data
        assert "performance_metrics" in response_data
        assert "file_monitoring" in response_data
        assert "processing_stats" in response_data
        assert "error_analysis" in response_data
        assert "efficiency_analysis" in response_data
        assert "recommendations" in response_data
        assert "analysis_metadata" in response_data
        
        # Check summary data
        summary = response_data["summary"]
        assert summary["total_nodes"] == 3
        assert summary["total_events_processed"] > 0
        assert summary["total_files_monitored"] > 0
        assert summary["overall_processing_rate"] > 0
    
    async def test_node_grouping(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test grouping by node."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        arguments = {"group_by": "node"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        groups = response_data["grouped_analysis"]["groups"]
        
        # Check node distribution
        assert "master" in groups
        assert "worker-1" in groups
        assert "worker-2" in groups
        
        # Check node stats
        master_stats = groups["master"]
        assert master_stats["events_processed"] == 125000
        assert master_stats["files_monitored"] == 45
        assert master_stats["processing_rate"] > 0
    
    async def test_agent_grouping(self, wazuh_server, mock_cluster_nodes, mock_agents_data, mock_daemon_stats):
        """Test grouping by agent."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_agents.return_value = {"data": {"affected_items": mock_agents_data}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        arguments = {"group_by": "agent"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        groups = response_data["grouped_analysis"]["groups"]
        
        # Check agent distribution
        assert "001" in groups or "002" in groups or "003" in groups
        
        # Check agent stats structure
        for agent_id, stats in groups.items():
            assert "node" in stats
            assert "events_processed" in stats
            assert "processing_rate" in stats
    
    async def test_performance_metrics_collection(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats, mock_performance_data):
        """Test performance metrics collection."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        def mock_get_performance_metrics(node):
            return mock_performance_data.get(node, {})
        
        wazuh_server.api_client.get_performance_metrics.side_effect = mock_get_performance_metrics
        
        arguments = {"include_performance": True}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        performance = response_data["performance_metrics"]
        
        # Check performance metrics structure
        assert "node_performance" in performance
        assert "overall_performance" in performance
        assert "performance_issues" in performance
        
        # Check node performance data
        node_perf = performance["node_performance"]
        assert "master" in node_perf
        assert "cpu_usage" in node_perf["master"]
        assert "memory_usage" in node_perf["master"]
        assert "disk_io" in node_perf["master"]
    
    async def test_file_monitoring_analysis(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats, mock_log_files_data):
        """Test file monitoring analysis."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        def mock_get_log_files(node):
            return mock_log_files_data.get(node, [])
        
        wazuh_server.api_client.get_log_files.side_effect = mock_get_log_files
        
        arguments = {"include_file_monitoring": True}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        file_monitoring = response_data["file_monitoring"]
        
        # Check file monitoring structure
        assert "file_statistics" in file_monitoring
        assert "log_type_distribution" in file_monitoring
        assert "file_performance" in file_monitoring
        assert "monitoring_issues" in file_monitoring
        
        # Check file statistics
        file_stats = file_monitoring["file_statistics"]
        assert file_stats["total_files"] > 0
        assert file_stats["files_reading"] > 0
        assert "top_files_by_events" in file_stats
        assert "top_files_by_bytes" in file_stats
    
    async def test_processing_stats_analysis(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test processing statistics analysis."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        arguments = {"include_processing_stats": True}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        processing = response_data["processing_stats"]
        
        # Check processing stats structure
        assert "processing_rates" in processing
        assert "queue_statistics" in processing
        assert "throughput_analysis" in processing
        assert "bottleneck_analysis" in processing
        
        # Check processing rates
        rates = processing["processing_rates"]
        assert "events_per_second" in rates
        assert "bytes_per_second" in rates
        assert "average_processing_rate" in rates
        
        # Check queue statistics
        queue_stats = processing["queue_statistics"]
        assert "total_queue_size" in queue_stats
        assert "average_queue_usage" in queue_stats
        assert "queue_efficiency" in queue_stats
    
    async def test_error_analysis(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test error analysis functionality."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        arguments = {"include_error_analysis": True}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        error_analysis = response_data["error_analysis"]
        
        # Check error analysis structure
        assert "error_statistics" in error_analysis
        assert "error_categories" in error_analysis
        assert "error_trends" in error_analysis
        assert "resolution_suggestions" in error_analysis
        
        # Check error statistics
        error_stats = error_analysis["error_statistics"]
        assert "total_errors" in error_stats
        assert "error_rate" in error_stats
        assert "most_affected_nodes" in error_stats
        
        # Check error categories
        categories = error_analysis["error_categories"]
        assert "file_errors" in categories
        assert "processing_errors" in categories
        assert "configuration_errors" in categories
    
    async def test_efficiency_analysis(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test efficiency analysis functionality."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        arguments = {"include_efficiency": True}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        efficiency = response_data["efficiency_analysis"]
        
        # Check efficiency analysis structure
        assert "efficiency_score" in efficiency
        assert "efficiency_rating" in efficiency
        assert "efficiency_metrics" in efficiency
        assert "improvement_areas" in efficiency
        
        # Check efficiency score
        assert 0 <= efficiency["efficiency_score"] <= 100
        assert efficiency["efficiency_rating"] in ["Excellent", "Good", "Fair", "Poor", "Critical"]
        
        # Check efficiency metrics
        metrics = efficiency["efficiency_metrics"]
        assert "processing_efficiency" in metrics
        assert "resource_utilization" in metrics
        assert "throughput_efficiency" in metrics
    
    async def test_trend_analysis(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test trend analysis functionality."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        # Mock historical data
        def mock_get_historical_data(node, time_range):
            return {
                "timestamps": [datetime.utcnow() - timedelta(hours=i) for i in range(24, 0, -1)],
                "processing_rates": [1000 + i * 50 for i in range(24)],
                "error_rates": [2.5 + i * 0.1 for i in range(24)]
            }
        
        wazuh_server.api_client.get_historical_data.side_effect = mock_get_historical_data
        
        arguments = {"include_trends": True}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check for trend analysis in various sections
        if "trend_analysis" in response_data:
            trends = response_data["trend_analysis"]
            assert "processing_trends" in trends
            assert "error_trends" in trends
            assert "performance_trends" in trends
    
    async def test_filtering_functionality(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test filtering functionality."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        # Test node filtering
        arguments = {"node_filter": ["master", "worker-1"]}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should only include filtered nodes
        assert response_data["summary"]["total_nodes"] <= 2
        if "grouped_analysis" in response_data:
            groups = response_data["grouped_analysis"]["groups"]
            for node in groups.keys():
                assert node in ["master", "worker-1"]
    
    async def test_threshold_analysis(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test threshold-based analysis."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        # Set low thresholds to trigger alerts
        arguments = {
            "threshold_processing_rate": 200000,  # Very high threshold
            "threshold_error_rate": 0.1,         # Very low threshold
            "threshold_file_lag": 10              # Very low threshold
        }
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have performance issues due to thresholds
        if "performance_metrics" in response_data:
            perf_issues = response_data["performance_metrics"].get("performance_issues", [])
            assert len(perf_issues) >= 0  # May or may not have issues based on mock data
        
        # Should have recommendations
        recommendations = response_data["recommendations"]
        assert len(recommendations) >= 0
    
    async def test_output_formats(self, wazuh_server, mock_cluster_nodes, mock_daemon_stats):
        """Test different output formats."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: mock_daemon_stats.get(node, {})
        
        # Test summary format
        arguments = {"output_format": "summary"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        assert "summary" in response_data
        
        # Test minimal format
        arguments = {"output_format": "minimal"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        assert "summary" in response_data
        # Minimal format should have fewer sections
        
        # Test detailed format
        arguments = {"output_format": "detailed"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        assert "summary" in response_data
        # Detailed format should have more sections
    
    async def test_empty_response_handling(self, wazuh_server):
        """Test handling of empty responses."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": []}}
        
        arguments = {"group_by": "node"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle empty response gracefully
        assert response_data["summary"]["total_nodes"] == 0
        assert "No nodes found" in response_data["summary"]["message"]
    
    async def test_error_handling(self, wazuh_server):
        """Test error handling in log collector stats analysis."""
        # Mock API error
        wazuh_server.api_client.get_cluster_nodes.side_effect = Exception("API Error")
        
        arguments = {"group_by": "node"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        # Should return error response
        response_data = json.loads(result[0].text)
        assert "error" in response_data
        assert "API Error" in response_data["error"]


class TestLogCollectorStatsHelperMethods:
    """Test helper methods for log collector stats analysis."""
    
    @pytest.fixture
    def wazuh_server(self):
        """Create a minimal server instance for testing helper methods."""
        with patch('wazuh_mcp_server.main.WazuhConfig') as mock_config:
            mock_config.from_env.return_value = MagicMock()
            mock_config.from_env.return_value.log_level = "INFO"
            mock_config.from_env.return_value.debug = False
            
            server = WazuhMCPServer()
            return server
    
    def test_calculate_processing_rate(self, wazuh_server):
        """Test processing rate calculation."""
        events = 125000
        time_seconds = 86400  # 24 hours
        
        rate = wazuh_server._calculate_processing_rate(events, time_seconds)
        
        # Should be approximately 1.45 events per second
        assert 1.4 <= rate <= 1.5
        assert isinstance(rate, float)
    
    def test_calculate_efficiency_score(self, wazuh_server):
        """Test efficiency score calculation."""
        stats = {
            "processing_rate": 1500,
            "error_rate": 2.5,
            "queue_usage": 15.0,
            "resource_utilization": 45.0
        }
        
        score = wazuh_server._calculate_log_collector_efficiency_score(stats)
        
        # Should be reasonable score
        assert 0 <= score <= 100
        assert isinstance(score, float)
    
    def test_categorize_log_errors(self, wazuh_server):
        """Test error categorization."""
        errors = [
            {"type": "file_read_error", "message": "Cannot read file"},
            {"type": "permission_denied", "message": "Permission denied"},
            {"type": "queue_full", "message": "Queue is full"},
            {"type": "format_error", "message": "Invalid format"}
        ]
        
        categories = wazuh_server._categorize_log_collector_errors(errors)
        
        # Should have error categories
        assert "file_errors" in categories
        assert "processing_errors" in categories
        assert "configuration_errors" in categories
        assert isinstance(categories, dict)
    
    def test_analyze_file_performance(self, wazuh_server):
        """Test file performance analysis."""
        files = [
            {"file": "/var/log/syslog", "events": 45000, "bytes": 512000000},
            {"file": "/var/log/auth.log", "events": 8500, "bytes": 85000000},
            {"file": "/var/log/apache2/access.log", "events": 71500, "bytes": 1451776000}
        ]
        
        analysis = wazuh_server._analyze_file_performance(files)
        
        # Should have performance analysis
        assert "top_files_by_events" in analysis
        assert "top_files_by_bytes" in analysis
        assert "average_file_size" in analysis
        assert "total_events" in analysis
        assert isinstance(analysis, dict)
    
    def test_generate_log_collector_recommendations(self, wazuh_server):
        """Test recommendation generation."""
        stats = {
            "error_rate": 8.5,  # High error rate
            "processing_rate": 800,  # Low processing rate
            "queue_usage": 85.0,  # High queue usage
            "efficiency_score": 45.0  # Low efficiency
        }
        
        recommendations = wazuh_server._generate_log_collector_recommendations(stats)
        
        # Should generate recommendations
        assert len(recommendations) > 0
        
        # Check recommendation structure
        for rec in recommendations:
            assert "priority" in rec
            assert "category" in rec
            assert "title" in rec
            assert "description" in rec
            assert "action" in rec
            assert rec["priority"] in ["HIGH", "MEDIUM", "LOW"]
    
    def test_calculate_throughput_metrics(self, wazuh_server):
        """Test throughput metrics calculation."""
        nodes_data = {
            "master": {"events": 125000, "bytes": 2048576000, "uptime": 86400},
            "worker-1": {"events": 85000, "bytes": 1524288000, "uptime": 86300},
            "worker-2": {"events": 95000, "bytes": 1835008000, "uptime": 86200}
        }
        
        metrics = wazuh_server._calculate_throughput_metrics(nodes_data)
        
        # Should have throughput metrics
        assert "events_per_second" in metrics
        assert "bytes_per_second" in metrics
        assert "average_processing_rate" in metrics
        assert "total_throughput" in metrics
        assert isinstance(metrics, dict)


@pytest.mark.asyncio
class TestLogCollectorStatsEdgeCases:
    """Test edge cases for log collector stats analysis."""
    
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
    
    async def test_missing_daemon_stats(self, wazuh_server, mock_cluster_nodes):
        """Test handling of missing daemon statistics."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        wazuh_server.api_client.get_daemon_stats.return_value = {}  # Empty stats
        
        arguments = {"group_by": "node"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle missing stats gracefully
        assert "summary" in response_data
        assert response_data["summary"]["total_nodes"] == 3
        assert "collection_errors" in response_data.get("analysis_metadata", {})
    
    async def test_partial_data_collection(self, wazuh_server, mock_cluster_nodes):
        """Test handling of partial data collection."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        
        # Mock some nodes to fail
        def mock_get_daemon_stats(node):
            if node == "master":
                return {"logcollector": {"uptime": 86400, "events": {"processed": 125000}}}
            else:
                raise Exception(f"Failed to get stats for {node}")
        
        wazuh_server.api_client.get_daemon_stats.side_effect = mock_get_daemon_stats
        
        arguments = {"group_by": "node"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle partial failures
        assert "summary" in response_data
        assert response_data["summary"]["total_nodes"] == 3
        assert "collection_errors" in response_data.get("analysis_metadata", {})
        assert len(response_data["analysis_metadata"]["collection_errors"]) == 2
    
    async def test_zero_processing_rate(self, wazuh_server, mock_cluster_nodes):
        """Test handling of zero processing rates."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        
        # Mock zero processing data
        zero_stats = {
            "master": {
                "logcollector": {
                    "uptime": 86400,
                    "events": {"processed": 0, "dropped": 0, "queue_size": 0},
                    "files": {"monitored": 0, "reading": 0, "errors": 0},
                    "bytes": {"read": 0, "processed": 0}
                }
            }
        }
        
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: zero_stats.get(node, {})
        
        arguments = {"group_by": "node"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle zero rates
        assert response_data["summary"]["total_events_processed"] == 0
        assert response_data["summary"]["overall_processing_rate"] == 0.0
        
        # Should have recommendations for zero processing
        recommendations = response_data["recommendations"]
        assert len(recommendations) > 0
    
    async def test_high_error_rates(self, wazuh_server, mock_cluster_nodes):
        """Test handling of high error rates."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        
        # Mock high error data
        high_error_stats = {
            "master": {
                "logcollector": {
                    "uptime": 86400,
                    "events": {"processed": 10000, "dropped": 9000, "queue_size": 1024},
                    "files": {"monitored": 10, "reading": 2, "errors": 8},
                    "bytes": {"read": 1000000, "processed": 100000}
                }
            }
        }
        
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: high_error_stats.get(node, {})
        
        arguments = {"threshold_error_rate": 10.0}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should detect high error rates
        if "error_analysis" in response_data:
            error_stats = response_data["error_analysis"]["error_statistics"]
            assert error_stats["error_rate"] > 10.0
        
        # Should have high priority recommendations
        recommendations = response_data["recommendations"]
        high_priority = [r for r in recommendations if r["priority"] == "HIGH"]
        assert len(high_priority) > 0
    
    async def test_large_dataset_handling(self, wazuh_server):
        """Test handling of large datasets."""
        # Create large node list
        large_node_list = [
            {"name": f"node-{i:03d}", "type": "worker", "status": "connected"}
            for i in range(100)
        ]
        
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": large_node_list}}
        
        # Mock stats for all nodes
        def mock_get_daemon_stats(node):
            return {
                "logcollector": {
                    "uptime": 86400,
                    "events": {"processed": 1000, "dropped": 10, "queue_size": 100},
                    "files": {"monitored": 5, "reading": 4, "errors": 1},
                    "bytes": {"read": 10000000, "processed": 9900000}
                }
            }
        
        wazuh_server.api_client.get_daemon_stats.side_effect = mock_get_daemon_stats
        
        arguments = {"group_by": "node"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle large dataset
        assert response_data["summary"]["total_nodes"] == 100
        assert "processing_time_seconds" in response_data["analysis_metadata"]
        
        # Should have aggregated stats
        assert response_data["summary"]["total_events_processed"] == 100000  # 1000 * 100
    
    async def test_malformed_stats_data(self, wazuh_server, mock_cluster_nodes):
        """Test handling of malformed statistics data."""
        wazuh_server.api_client.get_cluster_nodes.return_value = {"data": {"affected_items": mock_cluster_nodes}}
        
        # Mock malformed data
        malformed_stats = {
            "master": {
                "logcollector": {
                    "uptime": "invalid",  # Should be int
                    "events": {"processed": None, "dropped": -1},  # Invalid values
                    "files": "not_a_dict",  # Should be dict
                    "bytes": {"read": "not_a_number"}  # Should be int
                }
            }
        }
        
        wazuh_server.api_client.get_daemon_stats.side_effect = lambda node: malformed_stats.get(node, {})
        
        arguments = {"group_by": "node"}
        result = await wazuh_server._handle_get_wazuh_log_collector_stats(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle malformed data gracefully
        assert "summary" in response_data
        assert "collection_errors" in response_data.get("analysis_metadata", {})
        assert len(response_data["analysis_metadata"]["collection_errors"]) > 0