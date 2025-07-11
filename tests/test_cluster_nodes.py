"""Tests for the get_wazuh_cluster_nodes tool."""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from wazuh_mcp_server.main import WazuhMCPServer
from wazuh_mcp_server.utils.validation import validate_cluster_nodes_query, ValidationError


@pytest.fixture
def mock_cluster_nodes_data():
    """Mock cluster nodes data for testing."""
    base_time = datetime.utcnow()
    
    return [
        {
            "name": "master-node",
            "type": "master",
            "status": "active",
            "ip": "192.168.1.100",
            "version": "4.8.0",
            "last_keep_alive": (base_time - timedelta(minutes=1)).isoformat() + "Z",
            "uptime": "7 days, 2:30:45",
            "cluster_version": "4.8.0"
        },
        {
            "name": "worker-node-01",
            "type": "worker",
            "status": "active",
            "ip": "192.168.1.101",
            "version": "4.8.0",
            "last_keep_alive": (base_time - timedelta(minutes=2)).isoformat() + "Z",
            "uptime": "6 days, 10:15:20",
            "cluster_version": "4.8.0"
        },
        {
            "name": "worker-node-02",
            "type": "worker",
            "status": "disconnected",
            "ip": "192.168.1.102",
            "version": "4.8.0",
            "last_keep_alive": (base_time - timedelta(hours=2)).isoformat() + "Z",
            "uptime": "0 days, 0:00:00",
            "cluster_version": "4.8.0"
        }
    ]


@pytest.fixture
def mock_node_performance_data():
    """Mock node performance data for testing."""
    return {
        "master-node": {
            "cpu_usage": 45.2,
            "memory_usage": 67.8,
            "disk_usage": 34.5,
            "load_average": [1.2, 1.1, 1.0],
            "uptime": "7 days, 2:30:45",
            "process_count": 245,
            "network_stats": {
                "bytes_sent": 1024000,
                "bytes_received": 2048000
            }
        },
        "worker-node-01": {
            "cpu_usage": 78.5,
            "memory_usage": 89.2,
            "disk_usage": 56.7,
            "load_average": [2.8, 2.5, 2.3],
            "uptime": "6 days, 10:15:20",
            "process_count": 189,
            "network_stats": {
                "bytes_sent": 512000,
                "bytes_received": 1024000
            }
        }
    }


@pytest.fixture
def mock_node_sync_data():
    """Mock node synchronization data for testing."""
    return {
        "master-node": {
            "sync_status": "synchronized",
            "last_sync": datetime.utcnow().isoformat() + "Z",
            "sync_lag_seconds": 5,
            "files_to_sync": 0,
            "integrity_check": "passed",
            "sync_errors": []
        },
        "worker-node-01": {
            "sync_status": "synchronizing",
            "last_sync": (datetime.utcnow() - timedelta(minutes=2)).isoformat() + "Z",
            "sync_lag_seconds": 45,
            "files_to_sync": 23,
            "integrity_check": "in_progress",
            "sync_errors": []
        }
    }


@pytest.fixture
def mock_agent_distribution_data():
    """Mock agent distribution data for testing."""
    return {
        "master-node": {
            "total_agents": 0,
            "active_agents": 0,
            "disconnected_agents": 0,
            "agent_types": {},
            "agent_versions": {},
            "load_distribution": "balanced"
        },
        "worker-node-01": {
            "total_agents": 150,
            "active_agents": 142,
            "disconnected_agents": 8,
            "agent_types": {
                "windows": 85,
                "linux": 65
            },
            "agent_versions": {
                "4.8.0": 120,
                "4.7.5": 30
            },
            "load_distribution": "high"
        }
    }


class TestClusterNodesValidation:
    """Test cluster nodes query validation."""

    def test_valid_cluster_nodes_query(self):
        """Test validation of valid cluster nodes query."""
        query_params = {
            "node_type": ["master", "worker"],
            "status_filter": ["active"],
            "include_performance": True,
            "include_sync_status": True,
            "performance_threshold_cpu": 85.0,
            "performance_threshold_memory": 90.0,
            "sync_lag_threshold": 60,
            "output_format": "detailed"
        }
        
        validated = validate_cluster_nodes_query(query_params)
        assert validated.node_type == ["master", "worker"]
        assert validated.status_filter == ["active"]
        assert validated.include_performance is True
        assert validated.performance_threshold_cpu == 85.0

    def test_invalid_node_type(self):
        """Test validation with invalid node type."""
        query_params = {
            "node_type": ["invalid_type"]
        }
        
        with pytest.raises(ValidationError):
            validate_cluster_nodes_query(query_params)

    def test_invalid_status_filter(self):
        """Test validation with invalid status filter."""
        query_params = {
            "status_filter": ["invalid_status"]
        }
        
        with pytest.raises(ValidationError):
            validate_cluster_nodes_query(query_params)

    def test_invalid_node_name(self):
        """Test validation with invalid node name."""
        query_params = {
            "node_name": "invalid@name!"
        }
        
        with pytest.raises(ValidationError):
            validate_cluster_nodes_query(query_params)

    def test_invalid_threshold_values(self):
        """Test validation with invalid threshold values."""
        query_params = {
            "performance_threshold_cpu": 150.0  # > 100
        }
        
        with pytest.raises(ValidationError):
            validate_cluster_nodes_query(query_params)

    def test_invalid_output_format(self):
        """Test validation with invalid output format."""
        query_params = {
            "output_format": "invalid_format"
        }
        
        with pytest.raises(ValidationError):
            validate_cluster_nodes_query(query_params)

    def test_default_values(self):
        """Test validation with default values."""
        query_params = {}
        
        validated = validate_cluster_nodes_query(query_params)
        assert validated.node_type == ["all"]
        assert validated.status_filter == ["all"]
        assert validated.include_performance is True
        assert validated.include_sync_status is True
        assert validated.performance_threshold_cpu == 80.0
        assert validated.performance_threshold_memory == 85.0
        assert validated.sync_lag_threshold == 30


class TestClusterNodesHandler:
    """Test cluster nodes handler functionality."""

    @pytest.fixture
    def server(self):
        """Create server instance for testing."""
        server = WazuhMCPServer()
        server.logger = MagicMock()
        return server

    @pytest.mark.asyncio
    async def test_handle_cluster_nodes_success(self, server, mock_cluster_nodes_data, 
                                               mock_node_performance_data, mock_node_sync_data,
                                               mock_agent_distribution_data):
        """Test successful cluster nodes handling."""
        # Mock API client
        server.api_client = AsyncMock()
        server.api_client.get_cluster_nodes.return_value = {"data": mock_cluster_nodes_data}
        
        # Mock individual data collection methods
        server._collect_node_performance_data = AsyncMock()
        server._collect_node_performance_data.side_effect = lambda node_name: mock_node_performance_data.get(node_name, {})
        
        server._collect_node_sync_status = AsyncMock()
        server._collect_node_sync_status.side_effect = lambda node_name: mock_node_sync_data.get(node_name, {})
        
        server._collect_node_agent_distribution = AsyncMock()
        server._collect_node_agent_distribution.side_effect = lambda node_name: mock_agent_distribution_data.get(node_name, {})
        
        server._collect_node_load_metrics = AsyncMock()
        server._collect_node_load_metrics.return_value = {
            "current_load": 50,
            "max_capacity": 100,
            "utilization_percent": 50.0,
            "queue_size": 25,
            "processed_events": 10000,
            "failed_events": 5,
            "average_processing_time": 0.05
        }
        
        server._collect_node_configuration = AsyncMock()
        server._collect_node_configuration.return_value = {
            "cluster_config": {"node_type": "worker"},
            "logging_config": {"level": "info"},
            "auth_config": {"method": "password"},
            "api_config": {"port": 55000},
            "resource_limits": {"max_memory": "8GB"}
        }

        # Test the handler
        arguments = {
            "node_type": ["all"],
            "status_filter": ["active"],
            "include_performance": True,
            "include_sync_status": True,
            "include_load_metrics": True,
            "include_agent_distribution": True,
            "include_configuration": False,
            "output_format": "detailed"
        }
        
        result = await server._handle_get_wazuh_cluster_nodes(arguments)
        
        # Verify result structure
        assert len(result) == 1
        assert result[0].type == "text"
        
        # Parse the JSON response
        response_data = json.loads(result[0].text)
        
        # Verify response structure
        assert "summary" in response_data
        assert "node_analysis" in response_data
        assert "performance_insights" in response_data
        assert "sync_analysis" in response_data
        assert "load_analysis" in response_data
        assert "agent_distribution_analysis" in response_data
        assert "recommendations" in response_data
        assert "alerts" in response_data
        assert "quality_indicators" in response_data
        
        # Verify summary data
        summary = response_data["summary"]
        assert summary["total_nodes"] == 2  # Only active nodes should be counted with status filter
        assert "master" in summary["node_types"]
        assert "worker" in summary["node_types"]
        assert "active" in summary["status_distribution"]

    @pytest.mark.asyncio
    async def test_handle_cluster_nodes_with_filters(self, server, mock_cluster_nodes_data):
        """Test cluster nodes handling with filters."""
        # Mock API client
        server.api_client = AsyncMock()
        server.api_client.get_cluster_nodes.return_value = {"data": mock_cluster_nodes_data}
        
        # Mock individual data collection methods
        server._collect_node_performance_data = AsyncMock()
        server._collect_node_performance_data.return_value = {"cpu_usage": 50.0, "memory_usage": 60.0}
        
        server._collect_node_sync_status = AsyncMock()
        server._collect_node_sync_status.return_value = {"sync_status": "synchronized", "sync_lag_seconds": 10}
        
        server._collect_node_load_metrics = AsyncMock()
        server._collect_node_load_metrics.return_value = {"utilization_percent": 45.0}
        
        server._collect_node_agent_distribution = AsyncMock()
        server._collect_node_agent_distribution.return_value = {"total_agents": 100}

        # Test with master node filter
        arguments = {
            "node_type": ["master"],
            "status_filter": ["active"],
            "include_performance": True,
            "output_format": "summary"
        }
        
        result = await server._handle_get_wazuh_cluster_nodes(arguments)
        
        # Verify result
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Should only have master node data
        summary = response_data["summary"]
        assert summary["total_nodes"] == 1
        assert summary["node_types"]["master"] == 1

    @pytest.mark.asyncio
    async def test_handle_cluster_nodes_with_node_name_filter(self, server, mock_cluster_nodes_data):
        """Test cluster nodes handling with specific node name filter."""
        # Mock API client
        server.api_client = AsyncMock()
        server.api_client.get_cluster_nodes.return_value = {"data": mock_cluster_nodes_data}
        
        # Mock individual data collection methods
        server._collect_node_performance_data = AsyncMock()
        server._collect_node_performance_data.return_value = {"cpu_usage": 50.0, "memory_usage": 60.0}

        # Test with specific node name
        arguments = {
            "node_name": "master-node",
            "include_performance": True,
            "output_format": "detailed"
        }
        
        result = await server._handle_get_wazuh_cluster_nodes(arguments)
        
        # Verify result
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Should only have the specific node
        summary = response_data["summary"]
        assert summary["total_nodes"] == 1

    @pytest.mark.asyncio
    async def test_handle_cluster_nodes_performance_alerts(self, server, mock_cluster_nodes_data):
        """Test cluster nodes handling with performance alerts."""
        # Mock API client
        server.api_client = AsyncMock()
        server.api_client.get_cluster_nodes.return_value = {"data": mock_cluster_nodes_data}
        
        # Mock high performance metrics to trigger alerts
        server._collect_node_performance_data = AsyncMock()
        server._collect_node_performance_data.return_value = {
            "cpu_usage": 95.0,  # High CPU
            "memory_usage": 98.0  # High memory
        }

        # Test with low thresholds to trigger alerts
        arguments = {
            "include_performance": True,
            "performance_threshold_cpu": 80.0,
            "performance_threshold_memory": 85.0,
            "output_format": "detailed"
        }
        
        result = await server._handle_get_wazuh_cluster_nodes(arguments)
        
        # Verify result contains alerts
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Should have performance alerts
        assert "alerts" in response_data
        alerts = response_data["alerts"]
        
        # Should have CPU and memory alerts for the nodes
        cpu_alerts = [alert for alert in alerts if alert["type"] == "high_cpu"]
        memory_alerts = [alert for alert in alerts if alert["type"] == "high_memory"]
        
        assert len(cpu_alerts) > 0
        assert len(memory_alerts) > 0

    @pytest.mark.asyncio
    async def test_handle_cluster_nodes_sync_alerts(self, server, mock_cluster_nodes_data):
        """Test cluster nodes handling with sync alerts."""
        # Mock API client
        server.api_client = AsyncMock()
        server.api_client.get_cluster_nodes.return_value = {"data": mock_cluster_nodes_data}
        
        # Mock high sync lag to trigger alerts
        server._collect_node_sync_status = AsyncMock()
        server._collect_node_sync_status.return_value = {
            "sync_status": "synchronizing",
            "sync_lag_seconds": 120,  # High lag
            "files_to_sync": 500  # Many files
        }

        # Test with low sync threshold
        arguments = {
            "include_sync_status": True,
            "sync_lag_threshold": 30,
            "output_format": "detailed"
        }
        
        result = await server._handle_get_wazuh_cluster_nodes(arguments)
        
        # Verify result contains sync analysis
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Should have sync analysis
        assert "sync_analysis" in response_data
        sync_analysis = response_data["sync_analysis"]
        
        # Should detect sync issues
        assert "sync_alerts" in sync_analysis
        assert len(sync_analysis["sync_alerts"]) > 0

    @pytest.mark.asyncio
    async def test_handle_cluster_nodes_error_handling(self, server):
        """Test cluster nodes error handling."""
        # Mock API client to raise an exception
        server.api_client = AsyncMock()
        server.api_client.get_cluster_nodes.side_effect = Exception("API Error")
        
        server._format_error_response = MagicMock()
        server._format_error_response.return_value = "Error: API Error"

        arguments = {
            "output_format": "detailed"
        }
        
        result = await server._handle_get_wazuh_cluster_nodes(arguments)
        
        # Verify error handling
        assert len(result) == 1
        assert result[0].type == "text"
        assert "Error: API Error" in result[0].text

    @pytest.mark.asyncio
    async def test_handle_cluster_nodes_minimal_output(self, server, mock_cluster_nodes_data):
        """Test cluster nodes handling with minimal output."""
        # Mock API client
        server.api_client = AsyncMock()
        server.api_client.get_cluster_nodes.return_value = {"data": mock_cluster_nodes_data}

        arguments = {
            "include_performance": False,
            "include_sync_status": False,
            "include_load_metrics": False,
            "include_agent_distribution": False,
            "include_configuration": False,
            "output_format": "minimal"
        }
        
        result = await server._handle_get_wazuh_cluster_nodes(arguments)
        
        # Verify result
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Should have minimal data
        assert "summary" in response_data
        assert "node_analysis" in response_data
        
        # Performance insights should be empty or not present
        assert response_data.get("performance_insights", {}) == {}


class TestClusterNodesAnalysis:
    """Test cluster nodes analysis functions."""

    @pytest.fixture
    def server(self):
        """Create server instance for testing."""
        server = WazuhMCPServer()
        server.logger = MagicMock()
        return server

    def test_filter_cluster_nodes(self, server, mock_cluster_nodes_data):
        """Test node filtering functionality."""
        # Create mock query
        from wazuh_mcp_server.utils.validation import ClusterNodesQuery
        
        # Test filter by type
        query = ClusterNodesQuery(node_type=["master"])
        filtered = server._filter_cluster_nodes(mock_cluster_nodes_data, query)
        assert len(filtered) == 1
        assert filtered[0]["type"] == "master"
        
        # Test filter by status
        query = ClusterNodesQuery(status_filter=["active"])
        filtered = server._filter_cluster_nodes(mock_cluster_nodes_data, query)
        assert len(filtered) == 2  # Two active nodes
        assert all(node["status"] == "active" for node in filtered)
        
        # Test filter by node name
        query = ClusterNodesQuery(node_name="master-node")
        filtered = server._filter_cluster_nodes(mock_cluster_nodes_data, query)
        assert len(filtered) == 1
        assert filtered[0]["name"] == "master-node"

    def test_calculate_performance_score(self, server):
        """Test performance score calculation."""
        # Test good performance
        metrics = {"cpu_usage": 30.0, "memory_usage": 40.0}
        score = server._calculate_performance_score(metrics)
        assert score > 70  # Should be high score
        
        # Test poor performance
        metrics = {"cpu_usage": 90.0, "memory_usage": 95.0}
        score = server._calculate_performance_score(metrics)
        assert score < 30  # Should be low score

    def test_determine_performance_status(self, server):
        """Test performance status determination."""
        from wazuh_mcp_server.utils.validation import ClusterNodesQuery
        
        query = ClusterNodesQuery(
            performance_threshold_cpu=80.0,
            performance_threshold_memory=85.0
        )
        
        # Test good performance
        status = server._determine_performance_status(50.0, 60.0, query)
        assert status == "good"
        
        # Test moderate performance
        status = server._determine_performance_status(75.0, 80.0, query)
        assert status == "moderate"
        
        # Test concerning performance
        status = server._determine_performance_status(85.0, 90.0, query)
        assert status == "concerning"


if __name__ == "__main__":
    pytest.main([__file__])