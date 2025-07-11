"""Tests for the get_wazuh_rules_summary tool."""

import pytest
import json
from unittest.mock import AsyncMock, MagicMock, patch

from wazuh_mcp_server.main import WazuhMCPServer
from wazuh_mcp_server.utils.validation import validate_rules_summary_query, ValidationError


@pytest.fixture
def mock_rules_data():
    """Mock rules data for testing."""
    return [
        {
            "id": 1001,
            "description": "Successful SSH login",
            "level": 3,
            "groups": ["authentication", "ssh"],
            "filename": "0025-sshd_rules.xml",
            "status": "enabled"
        },
        {
            "id": 1002,
            "description": "Failed SSH login attempt",
            "level": 5,
            "groups": ["authentication", "ssh", "authentication_failed"],
            "filename": "0025-sshd_rules.xml",
            "status": "enabled"
        },
        {
            "id": 5001,
            "description": "Multiple failed login attempts",
            "level": 10,
            "groups": ["authentication", "authentication_failures"],
            "filename": "0025-sshd_rules.xml",
            "status": "enabled"
        },
        {
            "id": 31100,
            "description": "Web attack detected",
            "level": 12,
            "groups": ["web", "attack", "ids"],
            "filename": "0280-web_rules.xml",
            "status": "enabled"
        },
        {
            "id": 40101,
            "description": "Critical vulnerability found",
            "level": 15,
            "groups": ["vulnerability", "high_priority"],
            "filename": "0330-vulnerability_rules.xml",
            "status": "enabled"
        },
        {
            "id": 50001,
            "description": "Custom organizational rule",
            "level": 8,
            "groups": ["custom", "organization"],
            "filename": "local_rules.xml",
            "status": "enabled"
        },
        {
            "id": 60001,
            "description": "Disabled test rule",
            "level": 6,
            "groups": ["test"],
            "filename": "test_rules.xml",
            "status": "disabled"
        },
        {
            "id": 2001,
            "description": "Firewall block",
            "level": 4,
            "groups": ["firewall", "blocked"],
            "filename": "0020-firewall_rules.xml",
            "status": "enabled"
        },
        {
            "id": 7001,
            "description": "Malware detection",
            "level": 12,
            "groups": ["malware", "attack"],
            "filename": "0350-malware_rules.xml",
            "status": "enabled"
        },
        {
            "id": 8001,
            "description": "File integrity monitoring",
            "level": 7,
            "groups": ["syscheck", "file_monitoring"],
            "filename": "0100-syscheck_rules.xml",
            "status": "enabled"
        }
    ]


@pytest.fixture
def mock_alerts_data():
    """Mock alerts data for usage statistics."""
    return [
        {"rule": {"id": 1001}, "timestamp": "2024-01-01T10:00:00Z"},
        {"rule": {"id": 1001}, "timestamp": "2024-01-01T10:05:00Z"},
        {"rule": {"id": 1002}, "timestamp": "2024-01-01T10:10:00Z"},
        {"rule": {"id": 5001}, "timestamp": "2024-01-01T10:15:00Z"},
        {"rule": {"id": 31100}, "timestamp": "2024-01-01T10:20:00Z"},
        {"rule": {"id": 31100}, "timestamp": "2024-01-01T10:25:00Z"},
        {"rule": {"id": 31100}, "timestamp": "2024-01-01T10:30:00Z"},
        {"rule": {"id": 2001}, "timestamp": "2024-01-01T10:35:00Z"},
        {"rule": {"id": 7001}, "timestamp": "2024-01-01T10:40:00Z"},
        {"rule": {"id": 8001}, "timestamp": "2024-01-01T10:45:00Z"}
    ]


class TestRulesSummaryValidation:
    """Test validation of rules summary query parameters."""
    
    def test_valid_basic_query(self):
        """Test validation with basic valid parameters."""
        params = {"group_by": "level"}
        result = validate_rules_summary_query(params)
        
        assert result.group_by == "level"
        assert result.status_filter == "enabled"
        assert result.include_usage_stats is True
        assert result.max_rules == 1000
    
    def test_valid_complete_query(self):
        """Test validation with all parameters."""
        params = {
            "rule_level_filter": [10, 12, 15],
            "rule_group_filter": ["authentication", "attack"],
            "rule_id_filter": [1001, 5001],
            "category_filter": ["authentication", "web"],
            "status_filter": "all",
            "include_disabled": True,
            "include_usage_stats": False,
            "include_coverage_analysis": False,
            "group_by": "group",
            "sort_by": "frequency",
            "max_rules": 500
        }
        result = validate_rules_summary_query(params)
        
        assert result.rule_level_filter == [10, 12, 15]
        assert result.rule_group_filter == ["authentication", "attack"]
        assert result.rule_id_filter == [1001, 5001]
        assert result.category_filter == ["authentication", "web"]
        assert result.status_filter == "all"
        assert result.include_disabled is True
        assert result.group_by == "group"
        assert result.sort_by == "frequency"
        assert result.max_rules == 500
    
    def test_invalid_rule_level(self):
        """Test validation with invalid rule level."""
        params = {"rule_level_filter": [20]}  # Over maximum of 16
        
        with pytest.raises(ValidationError):
            validate_rules_summary_query(params)
    
    def test_invalid_status_filter(self):
        """Test validation with invalid status filter."""
        params = {"status_filter": "invalid_status"}
        
        with pytest.raises(ValidationError):
            validate_rules_summary_query(params)
    
    def test_invalid_group_by(self):
        """Test validation with invalid group_by field."""
        params = {"group_by": "invalid_field"}
        
        with pytest.raises(ValidationError):
            validate_rules_summary_query(params)
    
    def test_invalid_sort_by(self):
        """Test validation with invalid sort_by field."""
        params = {"sort_by": "invalid_field"}
        
        with pytest.raises(ValidationError):
            validate_rules_summary_query(params)
    
    def test_max_rules_boundary(self):
        """Test max_rules boundary validation."""
        # Test minimum
        params = {"max_rules": 10}
        result = validate_rules_summary_query(params)
        assert result.max_rules == 10
        
        # Test maximum
        params = {"max_rules": 10000}
        result = validate_rules_summary_query(params)
        assert result.max_rules == 10000
        
        # Test below minimum
        params = {"max_rules": 5}
        with pytest.raises(ValidationError):
            validate_rules_summary_query(params)


@pytest.mark.asyncio
class TestRulesSummaryTool:
    """Test the rules summary tool functionality."""
    
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
    
    async def test_basic_rules_summary(self, wazuh_server, mock_rules_data):
        """Test basic rules summary functionality."""
        # Mock API responses
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": mock_rules_data}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"group_by": "level"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Check basic structure
        assert "query_parameters" in response_data
        assert "summary" in response_data
        assert "grouped_analysis" in response_data
        assert "coverage_analysis" in response_data
        assert "usage_analysis" in response_data
        assert "rule_details" in response_data
        assert "recommendations" in response_data
        assert "analysis_metadata" in response_data
        
        # Check summary data
        assert response_data["summary"]["total_rules"] == 10
        assert response_data["summary"]["enabled_rules"] == 9
        assert response_data["summary"]["disabled_rules"] == 1
        assert response_data["summary"]["high_priority_rules"] == 4  # Level >= 10
        assert response_data["summary"]["custom_rules"] == 2  # local_rules.xml, test_rules.xml
        
        # Check grouped analysis
        assert response_data["grouped_analysis"]["grouping_field"] == "level"
        groups = response_data["grouped_analysis"]["groups"]
        assert "level_3" in groups
        assert "level_15" in groups
    
    async def test_level_grouping(self, wazuh_server, mock_rules_data):
        """Test grouping by rule level."""
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": mock_rules_data}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"group_by": "level"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        groups = response_data["grouped_analysis"]["groups"]
        
        # Check level distribution
        assert "level_3" in groups
        assert "level_15" in groups
        assert groups["level_15"]["count"] == 1
        assert groups["level_15"]["severity"] == "critical"
        assert groups["level_3"]["severity"] == "low"
    
    async def test_group_grouping(self, wazuh_server, mock_rules_data):
        """Test grouping by rule groups."""
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": mock_rules_data}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"group_by": "group"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        groups = response_data["grouped_analysis"]["groups"]
        
        # Check group distribution
        assert "authentication" in groups
        assert "attack" in groups
        assert "web" in groups
        assert groups["authentication"]["count"] == 3  # Rules with authentication group
    
    async def test_file_grouping(self, wazuh_server, mock_rules_data):
        """Test grouping by filename."""
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": mock_rules_data}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"group_by": "file"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        groups = response_data["grouped_analysis"]["groups"]
        
        # Check file distribution
        assert "0025-sshd_rules.xml" in groups
        assert "local_rules.xml" in groups
        assert groups["0025-sshd_rules.xml"]["count"] == 3  # SSH rules
        assert groups["local_rules.xml"]["is_custom"] is True
    
    async def test_status_filtering(self, wazuh_server, mock_rules_data):
        """Test filtering by rule status."""
        # Filter only enabled rules
        enabled_rules = [rule for rule in mock_rules_data if rule["status"] == "enabled"]
        
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": enabled_rules}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"status_filter": "enabled", "group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should only have enabled rules
        assert response_data["summary"]["total_rules"] == 9
        assert response_data["summary"]["enabled_rules"] == 9
        assert response_data["summary"]["disabled_rules"] == 0
    
    async def test_level_filtering(self, wazuh_server, mock_rules_data):
        """Test filtering by rule levels."""
        # Filter high level rules (>= 10)
        high_level_rules = [rule for rule in mock_rules_data if rule["level"] >= 10]
        
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": high_level_rules}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"rule_level_filter": [10, 12, 15], "group_by": "level"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should only have high level rules
        assert response_data["summary"]["total_rules"] == 4
        assert response_data["summary"]["high_priority_rules"] == 4
        
        # All rules should be level >= 10
        for rule in response_data["rule_details"]:
            assert rule["level"] >= 10
    
    async def test_usage_statistics(self, wazuh_server, mock_rules_data, mock_alerts_data):
        """Test usage statistics functionality."""
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": mock_rules_data}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_data}
        }
        
        arguments = {"include_usage_stats": True, "group_by": "level"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have usage analysis
        assert "usage_analysis" in response_data
        usage = response_data["usage_analysis"]
        assert "efficiency_metrics" in usage
        assert "activity_distribution" in usage
        assert "trending_rules" in usage
        
        # Check efficiency metrics
        efficiency = usage["efficiency_metrics"]
        assert "utilization_rate" in efficiency
        assert "active_rules" in efficiency
        assert "silent_rules" in efficiency
        
        # Rule 31100 should be most active (3 hits in mock data)
        trending = usage["trending_rules"]
        if trending:
            assert trending[0]["rule_id"] == 31100
            assert trending[0]["frequency"] == 3
    
    async def test_coverage_analysis(self, wazuh_server, mock_rules_data):
        """Test security coverage analysis."""
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": mock_rules_data}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"include_coverage_analysis": True, "group_by": "level"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have coverage analysis
        assert "coverage_analysis" in response_data
        coverage = response_data["coverage_analysis"]
        assert "category_coverage" in coverage
        assert "coverage_gaps" in coverage
        assert "strength_areas" in coverage
        
        # Check category coverage
        categories = coverage["category_coverage"]
        assert "authentication" in categories
        assert "web" in categories
        assert "malware" in categories
        
        # Authentication should have good coverage (3 rules)
        auth_coverage = categories["authentication"]
        assert auth_coverage["rule_count"] >= 3
        assert auth_coverage["status"] in ["excellent", "good", "adequate"]
    
    async def test_sort_by_frequency(self, wazuh_server, mock_rules_data, mock_alerts_data):
        """Test sorting rules by frequency."""
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": mock_rules_data}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": mock_alerts_data}
        }
        
        arguments = {"sort_by": "frequency", "include_usage_stats": True}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        rule_details = response_data["rule_details"]
        
        # Rules should be sorted by frequency (highest first)
        frequencies = [rule["frequency"] for rule in rule_details]
        assert frequencies == sorted(frequencies, reverse=True)
        
        # Rule 31100 should be first (highest frequency)
        if rule_details:
            assert rule_details[0]["id"] == 31100
    
    async def test_recommendations_generation(self, wazuh_server, mock_rules_data):
        """Test recommendations generation."""
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": mock_rules_data}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"include_coverage_analysis": True}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        recommendations = response_data["recommendations"]
        
        # Should have recommendations
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
        
        # Should have disabled rules recommendation
        disabled_recs = [r for r in recommendations if "disabled" in r["description"].lower()]
        assert len(disabled_recs) > 0
    
    async def test_empty_rules_response(self, wazuh_server):
        """Test handling of empty rules response."""
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"group_by": "level"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle empty response gracefully
        assert response_data["summary"]["total_rules"] == 0
        assert "No rules found" in response_data["summary"]["message"]
        assert response_data["analysis_metadata"]["total_rules_analyzed"] == 0
    
    async def test_error_handling(self, wazuh_server):
        """Test error handling in rules summary analysis."""
        # Mock API error
        wazuh_server.api_client.get_rules.side_effect = Exception("API Error")
        
        arguments = {"group_by": "level"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        # Should return error response
        response_data = json.loads(result[0].text)
        assert "error" in response_data
        assert "API Error" in response_data["error"]


class TestRulesSummaryHelperMethods:
    """Test helper methods for rules summary analysis."""
    
    @pytest.fixture
    def wazuh_server(self):
        """Create a minimal server instance for testing helper methods."""
        with patch('wazuh_mcp_server.main.WazuhConfig') as mock_config:
            mock_config.from_env.return_value = MagicMock()
            mock_config.from_env.return_value.log_level = "INFO"
            mock_config.from_env.return_value.debug = False
            
            server = WazuhMCPServer()
            return server
    
    def test_calculate_rules_coverage_score(self, wazuh_server, mock_rules_data):
        """Test rules coverage score calculation."""
        group_counts = {
            "authentication": 3,
            "web": 1,
            "attack": 2,
            "malware": 1,
            "vulnerability": 1,
            "firewall": 1,
            "syscheck": 1
        }
        
        score = wazuh_server._calculate_rules_coverage_score(mock_rules_data, group_counts)
        
        # Should be a reasonable score
        assert 0 <= score <= 100
        assert isinstance(score, float)
        
        # Should be > 0 since we have rules covering essential categories
        assert score > 0
    
    def test_get_level_severity(self, wazuh_server):
        """Test level to severity mapping."""
        assert wazuh_server._get_level_severity(15) == "critical"
        assert wazuh_server._get_level_severity(12) == "critical"
        assert wazuh_server._get_level_severity(10) == "high"
        assert wazuh_server._get_level_severity(8) == "high"
        assert wazuh_server._get_level_severity(5) == "medium"
        assert wazuh_server._get_level_severity(4) == "medium"
        assert wazuh_server._get_level_severity(3) == "low"
        assert wazuh_server._get_level_severity(1) == "low"
    
    def test_analyze_security_coverage(self, wazuh_server, mock_rules_data):
        """Test security coverage analysis."""
        group_counts = {
            "authentication": 3,
            "web": 1,
            "attack": 2,
            "malware": 1,
            "firewall": 1
        }
        
        coverage = wazuh_server._analyze_security_coverage(mock_rules_data, group_counts)
        
        assert "category_coverage" in coverage
        assert "coverage_gaps" in coverage
        assert "strength_areas" in coverage
        
        # Check category coverage structure
        categories = coverage["category_coverage"]
        assert "authentication" in categories
        assert "web" in categories
        
        # Authentication should have good coverage
        auth_coverage = categories["authentication"]
        assert auth_coverage["rule_count"] == 3
        assert auth_coverage["coverage_score"] >= 50  # Should be adequate or better
    
    def test_sort_rules(self, wazuh_server, mock_rules_data):
        """Test rule sorting functionality."""
        frequencies = {
            1001: {"frequency": 5},
            1002: {"frequency": 3},
            5001: {"frequency": 10},
            31100: {"frequency": 15}
        }
        
        # Test sort by level
        sorted_by_level = wazuh_server._sort_rules(mock_rules_data, "level", {})
        assert sorted_by_level[0]["level"] >= sorted_by_level[-1]["level"]
        
        # Test sort by frequency
        sorted_by_freq = wazuh_server._sort_rules(mock_rules_data, "frequency", frequencies)
        freq_values = [frequencies.get(rule["id"], {}).get("frequency", 0) for rule in sorted_by_freq]
        assert freq_values == sorted(freq_values, reverse=True)
        
        # Test sort by ID
        sorted_by_id = wazuh_server._sort_rules(mock_rules_data, "id", {})
        ids = [rule["id"] for rule in sorted_by_id]
        assert ids == sorted(ids)
    
    def test_generate_rules_recommendations(self, wazuh_server):
        """Test recommendation generation logic."""
        # Mock summary with issues
        summary = {
            "disabled_rules": 5,
            "custom_rules": 0
        }
        
        # Mock coverage with gaps
        coverage = {
            "coverage_gaps": [
                {
                    "category": "ids",
                    "current_rules": 2,
                    "recommended_rules": 10,
                    "priority": "high"
                }
            ]
        }
        
        # Mock usage stats with many silent rules
        usage_stats = {
            "rule_frequencies": {str(i): {"frequency": 0} for i in range(100)},
            "silent_rules": [{"rule_id": i} for i in range(60)]  # 60% silent
        }
        
        recommendations = wazuh_server._generate_rules_recommendations(summary, coverage, usage_stats)
        
        # Should generate multiple recommendations
        assert len(recommendations) > 0
        
        # Check for expected recommendation categories
        categories = [rec["category"] for rec in recommendations]
        assert "coverage" in categories     # For IDS gap
        assert "optimization" in categories # For disabled rules
        assert "customization" in categories # For no custom rules
        assert "efficiency" in categories   # For silent rules
        
        # Check priority levels
        priorities = [rec["priority"] for rec in recommendations]
        assert all(priority in ["HIGH", "MEDIUM", "LOW"] for priority in priorities)


@pytest.mark.asyncio
class TestRulesSummaryEdgeCases:
    """Test edge cases for rules summary analysis."""
    
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
    
    async def test_malformed_rules_data(self, wazuh_server):
        """Test handling of malformed rules data."""
        # Mock response with malformed data
        malformed_rules = [
            {"id": 1001},  # Missing required fields
            {"invalid": "structure"},  # Completely wrong structure
            {
                "id": 1002,
                "description": "Valid rule",
                "level": "not_a_number",  # Invalid level
                "groups": "not_a_list"    # Invalid groups
            }
        ]
        
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": malformed_rules}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"group_by": "level"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        # Should not crash and should handle gracefully
        response_data = json.loads(result[0].text)
        assert "summary" in response_data
        assert response_data["summary"]["total_rules"] >= 0
    
    async def test_usage_stats_collection_errors(self, wazuh_server, mock_rules_data):
        """Test handling of usage statistics collection errors."""
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": mock_rules_data}
        }
        
        # Mock alerts API to always fail
        wazuh_server.api_client.get_alerts.side_effect = Exception("Alerts API Error")
        
        arguments = {"include_usage_stats": True, "group_by": "level"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle errors gracefully
        assert "usage_analysis" in response_data
        # Usage analysis might be empty or have error indicators
        assert isinstance(response_data["usage_analysis"], dict)
    
    async def test_large_rules_dataset(self, wazuh_server):
        """Test handling of large rules datasets."""
        # Create large dataset
        large_rules_list = []
        for i in range(2000):
            large_rules_list.append({
                "id": i + 1000,
                "description": f"Rule {i}",
                "level": (i % 16),  # Levels 0-15
                "groups": [f"group_{i % 10}"],
                "filename": f"rules_{i % 20}.xml",
                "status": "enabled" if i % 10 != 0 else "disabled"
            })
        
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": large_rules_list}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"group_by": "level", "max_rules": 2000}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle large dataset successfully
        assert response_data["summary"]["total_rules"] == 2000
        assert "analysis_metadata" in response_data
        assert "processing_time_seconds" in response_data["analysis_metadata"]
        
        # Rule details should be limited for performance
        assert len(response_data["rule_details"]) <= 50
    
    async def test_all_rules_disabled(self, wazuh_server):
        """Test scenario where all rules are disabled."""
        disabled_rules = [
            {
                "id": i + 1000,
                "description": f"Disabled rule {i}",
                "level": 5,
                "groups": ["test"],
                "filename": "disabled_rules.xml",
                "status": "disabled"
            }
            for i in range(10)
        ]
        
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": disabled_rules}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"include_disabled": True, "group_by": "status"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle all disabled scenario
        assert response_data["summary"]["total_rules"] == 10
        assert response_data["summary"]["enabled_rules"] == 0
        assert response_data["summary"]["disabled_rules"] == 10
        
        # Coverage score should be very low
        assert response_data["summary"]["coverage_score"] < 50
        
        # Should have high priority recommendations
        recommendations = response_data["recommendations"]
        high_priority_recs = [r for r in recommendations if r["priority"] == "HIGH"]
        assert len(high_priority_recs) > 0
    
    async def test_no_usage_data_available(self, wazuh_server, mock_rules_data):
        """Test when no alert data is available for usage statistics."""
        wazuh_server.api_client.get_rules.return_value = {
            "data": {"affected_items": mock_rules_data}
        }
        wazuh_server.api_client.get_alerts.return_value = {
            "data": {"affected_items": []}  # No alerts
        }
        
        arguments = {"include_usage_stats": True, "sort_by": "frequency"}
        result = await wazuh_server._handle_get_wazuh_rules_summary(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should handle no usage data gracefully
        assert "usage_analysis" in response_data
        usage = response_data["usage_analysis"]
        
        # All rules should have zero frequency
        if "efficiency_metrics" in usage:
            assert usage["efficiency_metrics"]["active_rules"] == 0
            assert usage["efficiency_metrics"]["utilization_rate"] == 0.0
        
        # Rules should still be sorted (by ID as fallback)
        rule_details = response_data["rule_details"]
        assert len(rule_details) > 0