"""Tests for the get_wazuh_running_agents tool."""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from wazuh_mcp_server.main import WazuhMCPServer
from wazuh_mcp_server.utils.validation import validate_running_agents_query, ValidationError


@pytest.fixture
def mock_agents_data():
    """Mock agent data for testing."""
    base_time = datetime.utcnow()
    
    return [
        {
            "id": "001",
            "name": "web-server-01",
            "status": "active",
            "last_keep_alive": (base_time - timedelta(minutes=2)).isoformat() + "Z",
            "os": {
                "platform": "ubuntu",
                "version": "20.04"
            },
            "version": "4.8.0",
            "group": ["web", "production"],
            "node_name": "master",
            "ip": "192.168.1.10",
            "register_ip": "192.168.1.10"
        },
        {
            "id": "002",
            "name": "db-server-01",
            "status": "active",
            "last_keep_alive": (base_time - timedelta(minutes=10)).isoformat() + "Z",
            "os": {
                "platform": "centos",
                "version": "8"
            },
            "version": "4.8.0",
            "group": ["database", "production"],
            "node_name": "master",
            "ip": "192.168.1.20",
            "register_ip": "192.168.1.20"
        },
        {
            "id": "003",
            "name": "win-server-01",
            "status": "disconnected",
            "last_keep_alive": (base_time - timedelta(hours=2)).isoformat() + "Z",
            "os": {
                "platform": "windows",
                "version": "2019"
            },
            "version": "4.7.5",
            "group": ["windows", "production"],
            "node_name": "worker-1",
            "ip": "192.168.1.30",
            "register_ip": "192.168.1.30"
        },
        {
            "id": "004",
            "name": "test-server-01",
            "status": "active",
            "last_keep_alive": (base_time - timedelta(minutes=1)).isoformat() + "Z",
            "os": {
                "platform": "ubuntu",
                "version": "22.04"
            },
            "version": "4.8.1",
            "group": ["test"],
            "node_name": "master",
            "ip": "192.168.1.40",
            "register_ip": "192.168.1.40"
        },
        {
            "id": "005",
            "name": "dev-server-01",
            "status": "never_connected",
            "os": {
                "platform": "debian",
                "version": "11"
            },
            "version": "4.8.0",
            "group": ["development"],
            "node_name": "worker-2",
            "ip": "192.168.1.50",
            "register_ip": "192.168.1.50"
        }
    ]


@pytest.fixture
def mock_agent_stats():
    """Mock agent stats data."""
    return {
        "001": {
            "data": {
                "cpu_usage": 15.2,
                "memory_usage": 45.8,
                "disk_usage": 67.3,
                "events_received": 1250,
                "events_sent": 1248
            }
        },
        "002": {
            "data": {
                "cpu_usage": 8.1,
                "memory_usage": 52.3,
                "disk_usage": 78.9,
                "events_received": 890,
                "events_sent": 888
            }
        }
    }


class TestRunningAgentsValidation:
    """Test validation of running agents query parameters."""
    
    def test_valid_basic_query(self):
        """Test validation with basic valid parameters."""
        params = {"group_by": "status"}
        result = validate_running_agents_query(params)
        
        assert result.group_by == "status"
        assert result.inactive_threshold == 300
        assert result.include_disconnected is False
        assert result.max_agents == 1000
    
    def test_valid_complete_query(self):
        """Test validation with all parameters."""
        params = {
            "status_filter": ["active", "disconnected"],
            "os_filter": ["ubuntu", "centos"],
            "version_filter": "4.8.0",
            "group_filter": ["production", "web"],
            "inactive_threshold": 600,
            "include_disconnected": True,
            "include_health_metrics": False,
            "include_last_activity": False,
            "group_by": "os",
            "max_agents": 500
        }
        result = validate_running_agents_query(params)
        
        assert result.status_filter == ["active", "disconnected"]
        assert result.os_filter == ["ubuntu", "centos"]
        assert result.version_filter == "4.8.0"
        assert result.group_filter == ["production", "web"]
        assert result.inactive_threshold == 600
        assert result.include_disconnected is True
        assert result.group_by == "os"
        assert result.max_agents == 500
    
    def test_invalid_status_filter(self):
        """Test validation with invalid status."""
        params = {"status_filter": ["invalid_status"]}
        
        with pytest.raises(ValidationError):
            validate_running_agents_query(params)
    
    def test_invalid_group_by(self):
        """Test validation with invalid group_by field."""
        params = {"group_by": "invalid_field"}
        
        with pytest.raises(ValidationError):
            validate_running_agents_query(params)
    
    def test_invalid_inactive_threshold(self):
        """Test validation with invalid inactive threshold."""
        # Test below minimum
        params = {"inactive_threshold": 30}
        with pytest.raises(ValidationError):
            validate_running_agents_query(params)
        
        # Test above maximum
        params = {"inactive_threshold": 4000}
        with pytest.raises(ValidationError):
            validate_running_agents_query(params)
    
    def test_max_agents_boundary(self):
        """Test max_agents boundary validation."""
        # Test minimum
        params = {"max_agents": 1}
        result = validate_running_agents_query(params)
        assert result.max_agents == 1
        
        # Test maximum
        params = {"max_agents": 5000}
        result = validate_running_agents_query(params)
        assert result.max_agents == 5000
        
        # Test over maximum
        params = {"max_agents": 6000}
        with pytest.raises(ValidationError):
            validate_running_agents_query(params)


@pytest.mark.asyncio
class TestRunningAgentsTool:
    """Test the running agents tool functionality."""
    
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
    
    async def test_basic_running_agents(self, wazuh_server, mock_agents_data):
        """Test basic running agents functionality."""
        # Mock API response
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_data}
        }
        
        arguments = {"group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Check basic structure
        assert "query_parameters" in response_data
        assert "summary" in response_data
        assert "grouped_analysis" in response_data
        assert "infrastructure_health" in response_data
        assert "agent_details" in response_data
        assert "recommendations" in response_data
        assert "analysis_metadata" in response_data
        
        # Check summary data
        assert response_data["summary"]["total_agents"] == 5
        assert response_data["summary"]["active_agents"] == 3
        assert response_data["summary"]["disconnected_agents"] == 1
        assert response_data["summary"]["never_connected_agents"] == 1
        
        # Check grouped analysis
        assert response_data["grouped_analysis"]["grouping_field"] == "status"
        groups = response_data["grouped_analysis"]["groups"]
        assert "active" in groups
        assert "disconnected" in groups
        assert "never_connected" in groups
    
    async def test_status_grouping(self, wazuh_server, mock_agents_data):
        """Test grouping by status."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_data}
        }
        
        arguments = {"group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        groups = response_data["grouped_analysis"]["groups"]
        
        # Check status distribution
        assert groups["active"]["count"] == 3
        assert groups["disconnected"]["count"] == 1
        assert groups["never_connected"]["count"] == 1
        
        # Check percentages
        assert groups["active"]["percentage"] == 60.0
        assert groups["disconnected"]["percentage"] == 20.0
        assert groups["never_connected"]["percentage"] == 20.0
    
    async def test_os_grouping(self, wazuh_server, mock_agents_data):
        """Test grouping by operating system."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_data}
        }
        
        arguments = {"group_by": "os"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        groups = response_data["grouped_analysis"]["groups"]
        
        # Check OS distribution
        assert "ubuntu" in groups
        assert "centos" in groups
        assert "windows" in groups
        assert "debian" in groups
        
        assert groups["ubuntu"]["count"] == 2  # web-server-01, test-server-01
        assert groups["centos"]["count"] == 1  # db-server-01
        assert groups["windows"]["count"] == 1  # win-server-01
        assert groups["debian"]["count"] == 1  # dev-server-01
    
    async def test_version_grouping(self, wazuh_server, mock_agents_data):
        """Test grouping by agent version."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_data}
        }
        
        arguments = {"group_by": "version"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        groups = response_data["grouped_analysis"]["groups"]
        
        # Check version distribution
        assert "4.8.0" in groups
        assert "4.7.5" in groups
        assert "4.8.1" in groups
        
        assert groups["4.8.0"]["count"] == 3  # web, db, dev servers
        assert groups["4.7.5"]["count"] == 1  # win server
        assert groups["4.8.1"]["count"] == 1  # test server
    
    async def test_status_filtering(self, wazuh_server, mock_agents_data):
        """Test filtering by agent status."""
        # Filter only active agents
        active_agents = [agent for agent in mock_agents_data if agent["status"] == "active"]
        
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": active_agents}
        }
        
        arguments = {"status_filter": ["active"], "group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should only have active agents
        assert response_data["summary"]["total_agents"] == 3
        assert response_data["summary"]["active_agents"] == 3
        assert response_data["summary"]["disconnected_agents"] == 0
    
    async def test_os_filtering(self, wazuh_server, mock_agents_data):
        """Test filtering by operating system."""
        # Filter only Ubuntu agents
        ubuntu_agents = [agent for agent in mock_agents_data 
                        if agent["os"]["platform"] == "ubuntu"]
        
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": ubuntu_agents}
        }
        
        arguments = {"os_filter": ["ubuntu"], "group_by": "os"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should only have Ubuntu agents
        assert response_data["summary"]["total_agents"] == 2
        groups = response_data["grouped_analysis"]["groups"]
        assert "ubuntu" in groups
        assert groups["ubuntu"]["count"] == 2
    
    async def test_inactive_threshold_analysis(self, wazuh_server, mock_agents_data):
        """Test inactive threshold analysis."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_data}
        }
        
        # Set a very low threshold (120 seconds) to make some agents inactive
        arguments = {"inactive_threshold": 120, "group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        
        # db-server-01 should be considered inactive (last seen 10 minutes ago)
        assert response_data["summary"]["inactive_agents"] > 0
        assert response_data["summary"]["health_issues_count"] > 0
        
        # Check health issues
        health_issues = response_data["infrastructure_health"]["health_issues"]
        assert len(health_issues) > 0
        assert any(issue["issue"] == "inactive" for issue in health_issues)
    
    async def test_health_metrics_collection(self, wazuh_server, mock_agents_data, mock_agent_stats):
        """Test health metrics collection."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_data}
        }
        
        def mock_get_agent_stats(agent_id):
            return mock_agent_stats.get(agent_id, {"data": {}})
        
        wazuh_server.api_client.get_agent_stats.side_effect = mock_get_agent_stats
        
        arguments = {"include_health_metrics": True, "group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have health metrics
        assert "health_metrics" in response_data
        health_metrics = response_data["health_metrics"]
        assert "agent_stats" in health_metrics
        assert len(health_metrics["agent_stats"]) > 0
        
        # Check that stats were collected
        for stat in health_metrics["agent_stats"]:
            assert "agent_id" in stat
            assert "stats" in stat
    
    async def test_activity_analysis(self, wazuh_server, mock_agents_data):
        """Test activity analysis functionality."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_data}
        }
        
        arguments = {"include_last_activity": True, "group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have activity analysis
        assert "activity_analysis" in response_data
        activity = response_data["activity_analysis"]
        assert "last_seen_analysis" in activity
        assert "activity_patterns" in activity
        
        # Check last seen analysis buckets
        last_seen = activity["last_seen_analysis"]
        assert "last_5_minutes" in last_seen
        assert "last_15_minutes" in last_seen
        assert "last_hour" in last_seen
        assert "last_day" in last_seen
        assert "older" in last_seen
        
        # Should have some agents in recent buckets
        assert last_seen["last_5_minutes"] > 0 or last_seen["last_15_minutes"] > 0
    
    async def test_infrastructure_health_scoring(self, wazuh_server, mock_agents_data):
        """Test infrastructure health scoring."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_data}
        }
        
        arguments = {"group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        health = response_data["infrastructure_health"]
        
        # Check health score structure
        assert "overall_health_score" in health
        assert "health_rating" in health
        assert "active_percentage" in health
        assert "coverage_analysis" in health
        
        # Health score should be reasonable
        assert 0 <= health["overall_health_score"] <= 100
        assert health["health_rating"] in ["Excellent", "Good", "Fair", "Poor", "Critical"]
        
        # Coverage analysis should show diversity
        coverage = health["coverage_analysis"]
        assert coverage["operating_systems"] >= 3  # ubuntu, centos, windows, debian
        assert coverage["agent_versions"] >= 2     # Multiple versions in test data
    
    async def test_recommendations_generation(self, wazuh_server, mock_agents_data):
        """Test recommendations generation."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_data}
        }
        
        arguments = {"group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        recommendations = response_data["recommendations"]
        
        # Should have recommendations due to disconnected agents
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
        
        # Should have connectivity recommendation due to disconnected agent
        connectivity_recs = [r for r in recommendations if r["category"] == "connectivity"]
        assert len(connectivity_recs) > 0
    
    async def test_empty_agent_response(self, wazuh_server):
        """Test handling of empty agent response."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle empty response gracefully
        assert response_data["summary"]["total_agents"] == 0
        assert "No agents found" in response_data["summary"]["message"]
        assert response_data["analysis_metadata"]["total_agents_analyzed"] == 0
    
    async def test_agent_details_structure(self, wazuh_server, mock_agents_data):
        """Test agent details structure."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_data}
        }
        
        arguments = {"group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        agent_details = response_data["agent_details"]
        
        # Should have agent details
        assert len(agent_details) > 0
        
        # Check agent detail structure
        for agent in agent_details:
            assert "id" in agent
            assert "name" in agent
            assert "status" in agent
            assert "os" in agent
            assert "version" in agent
            assert "group" in agent
            assert "node" in agent
            assert "ip" in agent
    
    async def test_error_handling(self, wazuh_server):
        """Test error handling in running agents analysis."""
        # Mock API error
        wazuh_server.api_client.get_agents.side_effect = Exception("API Error")
        
        arguments = {"group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        # Should return error response
        response_data = json.loads(result[0].text)
        assert "error" in response_data
        assert "API Error" in response_data["error"]


class TestRunningAgentsHelperMethods:
    """Test helper methods for running agents analysis."""
    
    @pytest.fixture
    def wazuh_server(self):
        """Create a minimal server instance for testing helper methods."""
        with patch('wazuh_mcp_server.main.WazuhConfig') as mock_config:
            mock_config.from_env.return_value = MagicMock()
            mock_config.from_env.return_value.log_level = "INFO"
            mock_config.from_env.return_value.debug = False
            
            server = WazuhMCPServer()
            return server
    
    def test_calculate_infrastructure_health_score(self, wazuh_server):
        """Test infrastructure health score calculation."""
        agents = [{"id": f"{i:03d}", "version": "4.8.0"} for i in range(10)]
        active_agents = agents[:8]  # 80% active
        health_issues = [{"issue": "test"}] * 2  # 2 issues
        
        score = wazuh_server._calculate_infrastructure_health_score(agents, active_agents, health_issues)
        
        # Should be around 80% - 4% (2 issues * 2) = 76%
        assert 70 <= score <= 80
        assert isinstance(score, float)
    
    def test_get_health_rating(self, wazuh_server):
        """Test health rating classification."""
        assert wazuh_server._get_health_rating(95) == "Excellent"
        assert wazuh_server._get_health_rating(85) == "Good"
        assert wazuh_server._get_health_rating(65) == "Fair"
        assert wazuh_server._get_health_rating(45) == "Poor"
        assert wazuh_server._get_health_rating(25) == "Critical"
    
    def test_analyze_agent_activity(self, wazuh_server, mock_agents_data):
        """Test agent activity analysis."""
        activity = wazuh_server._analyze_agent_activity(mock_agents_data, 300)
        
        assert "last_seen_analysis" in activity
        assert "activity_patterns" in activity
        
        # Check buckets structure
        buckets = activity["last_seen_analysis"]
        assert all(bucket in buckets for bucket in [
            "last_5_minutes", "last_15_minutes", "last_hour", "last_day", "older"
        ])
        
        # Should have some recent activity
        recent_activity = buckets["last_5_minutes"] + buckets["last_15_minutes"]
        assert recent_activity > 0
    
    def test_generate_infrastructure_recommendations(self, wazuh_server):
        """Test recommendation generation logic."""
        # Mock summary with issues
        summary = {
            "disconnected_agents": 2,
            "inactive_agents": 3
        }
        
        # Mock health with low score
        health = {
            "overall_health_score": 65,
            "coverage_analysis": {
                "agent_versions": 5
            }
        }
        
        issues = [{"issue": "test"}] * 2
        
        recommendations = wazuh_server._generate_infrastructure_recommendations(summary, health, issues)
        
        # Should generate multiple recommendations
        assert len(recommendations) > 0
        
        # Check for expected recommendation categories
        categories = [rec["category"] for rec in recommendations]
        assert "connectivity" in categories  # For disconnected agents
        assert "health" in categories        # For low health score
        assert "monitoring" in categories    # For inactive agents
        
        # Check priority levels
        priorities = [rec["priority"] for rec in recommendations]
        assert all(priority in ["HIGH", "MEDIUM", "LOW"] for priority in priorities)


@pytest.mark.asyncio
class TestRunningAgentsEdgeCases:
    """Test edge cases for running agents analysis."""
    
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
    
    async def test_malformed_agent_data(self, wazuh_server):
        """Test handling of malformed agent data."""
        # Mock response with malformed data
        malformed_agents = [
            {"id": "001"},  # Missing required fields
            {"invalid": "structure"},  # Completely wrong structure
            {
                "id": "002",
                "name": "test-agent",
                "status": "active",
                "last_keep_alive": "invalid_timestamp"
            }
        ]
        
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": malformed_agents}
        }
        
        arguments = {"group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        # Should not crash and should handle gracefully
        response_data = json.loads(result[0].text)
        assert "summary" in response_data
        assert response_data["summary"]["total_agents"] >= 0
    
    async def test_health_metrics_collection_errors(self, wazuh_server, mock_agents_data):
        """Test handling of health metrics collection errors."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_data[:2]}  # Limit for testing
        }
        
        # Mock stats collection to always fail
        wazuh_server.api_client.get_agent_stats.side_effect = Exception("Stats API Error")
        
        arguments = {"include_health_metrics": True, "group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle errors gracefully
        assert "health_metrics" in response_data
        health_metrics = response_data["health_metrics"]
        assert "collection_errors" in health_metrics
        assert len(health_metrics["collection_errors"]) > 0
    
    async def test_large_agent_dataset(self, wazuh_server):
        """Test handling of large agent datasets."""
        # Create large dataset
        large_agent_list = []
        for i in range(1000):
            large_agent_list.append({
                "id": f"{i:03d}",
                "name": f"agent-{i:03d}",
                "status": "active" if i % 4 != 0 else "disconnected",
                "os": {"platform": "ubuntu", "version": "20.04"},
                "version": "4.8.0",
                "group": ["production"],
                "node_name": "master",
                "last_keep_alive": datetime.utcnow().isoformat() + "Z"
            })
        
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": large_agent_list}
        }
        
        arguments = {"group_by": "status", "max_agents": 1000}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle large dataset successfully
        assert response_data["summary"]["total_agents"] == 1000
        assert "analysis_metadata" in response_data
        assert "processing_time_seconds" in response_data["analysis_metadata"]
        
        # Agent details should be limited for performance
        assert len(response_data["agent_details"]) <= 50
    
    async def test_missing_last_keep_alive(self, wazuh_server):
        """Test handling agents without last_keep_alive data."""
        agents_without_keepalive = [
            {
                "id": "001",
                "name": "agent-001",
                "status": "active",
                "os": {"platform": "ubuntu", "version": "20.04"},
                "version": "4.8.0"
                # Missing last_keep_alive
            },
            {
                "id": "002",
                "name": "agent-002",
                "status": "active",
                "last_keep_alive": None,  # Explicit None
                "os": {"platform": "centos", "version": "8"},
                "version": "4.8.0"
            }
        ]
        
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": agents_without_keepalive}
        }
        
        arguments = {"include_last_activity": True, "group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle missing keepalive gracefully
        assert response_data["summary"]["total_agents"] == 2
        assert response_data["summary"]["truly_active_agents"] == 2  # Should assume active
        
        # Activity analysis should not crash
        if "activity_analysis" in response_data:
            assert "last_seen_analysis" in response_data["activity_analysis"]
    
    async def test_all_agents_disconnected(self, wazuh_server):
        """Test scenario where all agents are disconnected."""
        disconnected_agents = [
            {
                "id": f"{i:03d}",
                "name": f"agent-{i:03d}",
                "status": "disconnected",
                "os": {"platform": "ubuntu", "version": "20.04"},
                "version": "4.8.0"
            }
            for i in range(5)
        ]
        
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": disconnected_agents}
        }
        
        arguments = {"include_disconnected": True, "group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_running_agents(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle all disconnected scenario
        assert response_data["summary"]["total_agents"] == 5
        assert response_data["summary"]["active_agents"] == 0
        assert response_data["summary"]["disconnected_agents"] == 5
        
        # Health score should be very low
        assert response_data["infrastructure_health"]["overall_health_score"] < 50
        assert response_data["infrastructure_health"]["health_rating"] in ["Poor", "Critical"]
        
        # Should have high priority recommendations
        recommendations = response_data["recommendations"]
        high_priority_recs = [r for r in recommendations if r["priority"] == "HIGH"]
        assert len(high_priority_recs) > 0