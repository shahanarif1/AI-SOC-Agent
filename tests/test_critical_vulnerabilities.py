"""Tests for the get_wazuh_critical_vulnerabilities tool."""

import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from wazuh_mcp_server.main import WazuhMCPServer
from wazuh_mcp_server.utils.validation import validate_critical_vulnerabilities_query, ValidationError


@pytest.fixture
def mock_agents_critical():
    """Mock agent data for critical vulnerability testing."""
    return [
        {
            "id": "001",
            "name": "payment-server-01",
            "status": "active", 
            "ip": "192.168.1.10",
            "os": {"platform": "ubuntu", "version": "20.04"},
            "labels": {"role": "payment", "environment": "production"}
        },
        {
            "id": "002",
            "name": "web-server-01",
            "status": "active",
            "ip": "192.168.1.20",
            "os": {"platform": "centos", "version": "8"},
            "labels": {"role": "web", "environment": "production"}
        },
        {
            "id": "003",
            "name": "database-server-01",
            "status": "active",
            "ip": "192.168.1.30",
            "os": {"platform": "ubuntu", "version": "22.04"},
            "labels": {"role": "database", "environment": "production"}
        }
    ]


@pytest.fixture
def mock_critical_vulnerabilities():
    """Mock critical vulnerability data."""
    base_time = datetime.utcnow()
    
    return {
        "agent_001": [
            {
                "cve": "CVE-2024-0001",
                "name": "openssl",
                "version": "1.1.1",
                "cvss3_score": 9.8,
                "severity": "critical",
                "exploit_available": True,
                "metasploit_module": True,
                "published_date": (base_time - timedelta(days=5)).isoformat() + "Z",
                "fixed_version": "1.1.1n",
                "solution": "Update openssl to version 1.1.1n or later"
            },
            {
                "cve": "CVE-2024-0002",
                "name": "payment-api",
                "version": "2.5.0",
                "cvss3_score": 9.1,
                "severity": "critical",
                "exploit_available": False,
                "published_date": (base_time - timedelta(days=60)).isoformat() + "Z",
                "patch_available": True
            }
        ],
        "agent_002": [
            {
                "cve": "CVE-2024-0003",
                "name": "apache2",
                "version": "2.4.41",
                "cvss3_score": 9.4,
                "severity": "critical",
                "exploit_available": True,
                "exploit_code_maturity": "functional",
                "published_date": (base_time - timedelta(days=10)).isoformat() + "Z",
                "references": ["https://www.exploit-db.com/exploits/50001"]
            }
        ],
        "agent_003": [
            {
                "cve": "CVE-2024-0004",
                "name": "mysql",
                "version": "8.0.25",
                "cvss3_score": 8.8,
                "severity": "high",
                "exploit_available": False,
                "published_date": (base_time - timedelta(days=90)).isoformat() + "Z"
            }
        ]
    }


@pytest.fixture
def mock_context_data():
    """Mock context data for vulnerability analysis."""
    return {
        "001": {
            "open_ports": [
                {"local": {"port": 443}, "process": "payment-api"},
                {"local": {"port": 8443}, "process": "payment-api-admin"}
            ],
            "running_processes": [
                {"name": "payment-api", "pid": 1234},
                {"name": "openssl", "pid": 5678}
            ]
        },
        "002": {
            "open_ports": [
                {"local": {"port": 80}, "process": "apache2"},
                {"local": {"port": 443}, "process": "apache2"}
            ],
            "running_processes": [
                {"name": "apache2", "pid": 2345}
            ]
        },
        "003": {
            "open_ports": [
                {"local": {"port": 3306}, "process": "mysqld"},
                {"local": {"port": 33060}, "process": "mysqld"}
            ],
            "running_processes": [
                {"name": "mysqld", "pid": 3456}
            ]
        }
    }


class TestCriticalVulnerabilitiesValidation:
    """Test validation of critical vulnerabilities query parameters."""
    
    def test_valid_basic_query(self):
        """Test validation with basic valid parameters."""
        params = {"min_cvss": 9.0}
        result = validate_critical_vulnerabilities_query(params)
        
        assert result.min_cvss == 9.0
        assert result.exploit_required is True
        assert result.include_context is True
        assert result.max_results == 100
    
    def test_valid_complete_query(self):
        """Test validation with all parameters."""
        params = {
            "min_cvss": 8.5,
            "exploit_required": False,
            "internet_exposed": True,
            "patch_available": True,
            "age_days": 30,
            "affected_services": ["web", "database"],
            "include_context": False,
            "max_results": 50
        }
        result = validate_critical_vulnerabilities_query(params)
        
        assert result.min_cvss == 8.5
        assert result.exploit_required is False
        assert result.internet_exposed is True
        assert result.age_days == 30
        assert result.affected_services == ["web", "database"]
    
    def test_invalid_cvss_score(self):
        """Test validation with invalid CVSS score."""
        params = {"min_cvss": 11.0}
        
        with pytest.raises(ValidationError):
            validate_critical_vulnerabilities_query(params)
    
    def test_max_results_boundary(self):
        """Test max_results boundary validation."""
        # Test minimum
        params = {"max_results": 1}
        result = validate_critical_vulnerabilities_query(params)
        assert result.max_results == 1
        
        # Test maximum
        params = {"max_results": 500}
        result = validate_critical_vulnerabilities_query(params)
        assert result.max_results == 500
        
        # Test over maximum
        params = {"max_results": 501}
        with pytest.raises(ValidationError):
            validate_critical_vulnerabilities_query(params)


@pytest.mark.asyncio
class TestCriticalVulnerabilitiesTool:
    """Test the critical vulnerabilities tool functionality."""
    
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
    
    async def test_basic_critical_vulnerabilities(self, wazuh_server, mock_agents_critical, mock_critical_vulnerabilities):
        """Test basic critical vulnerabilities functionality."""
        # Mock API responses
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_critical}
        }
        
        def mock_get_vulnerabilities(agent_id):
            return {
                "data": {"affected_items": mock_critical_vulnerabilities.get(f"agent_{agent_id}", [])}
            }
        
        wazuh_server.api_client.get_agent_vulnerabilities.side_effect = mock_get_vulnerabilities
        
        arguments = {"min_cvss": 9.0}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        assert len(result) == 1
        response_data = json.loads(result[0].text)
        
        # Check structure
        assert "query_parameters" in response_data
        assert "summary" in response_data
        assert "severity_breakdown" in response_data
        assert "top_risks" in response_data
        assert "attack_surface" in response_data
        assert "immediate_actions" in response_data
        assert "critical_vulnerabilities" in response_data
        assert "risk_metrics" in response_data
        
        # Check summary
        assert response_data["summary"]["total_critical_vulnerabilities"] == 3  # CVE-0001, 0002, 0003 with CVSS >= 9.0
        assert response_data["summary"]["exploitable_vulnerabilities"] == 2  # CVE-0001, 0003
    
    async def test_exploit_required_filter(self, wazuh_server, mock_agents_critical, mock_critical_vulnerabilities):
        """Test filtering by exploit requirement."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_critical}
        }
        
        def mock_get_vulnerabilities(agent_id):
            return {
                "data": {"affected_items": mock_critical_vulnerabilities.get(f"agent_{agent_id}", [])}
            }
        
        wazuh_server.api_client.get_agent_vulnerabilities.side_effect = mock_get_vulnerabilities
        
        arguments = {"min_cvss": 9.0, "exploit_required": True}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should only include vulnerabilities with exploits (CVE-0001, 0003)
        assert response_data["summary"]["total_critical_vulnerabilities"] == 2
        assert all(
            vuln["risk_factors"]["exploitable"] 
            for vuln in response_data["critical_vulnerabilities"]
        )
    
    async def test_internet_exposure_detection(self, wazuh_server, mock_agents_critical, 
                                             mock_critical_vulnerabilities, mock_context_data):
        """Test internet exposure detection."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_critical}
        }
        
        def mock_get_vulnerabilities(agent_id):
            return {
                "data": {"affected_items": mock_critical_vulnerabilities.get(f"agent_{agent_id}", [])}
            }
        
        def mock_get_ports(agent_id):
            return {
                "data": {"affected_items": mock_context_data.get(agent_id, {}).get("open_ports", [])}
            }
        
        def mock_get_processes(agent_id):
            return {
                "data": {"affected_items": mock_context_data.get(agent_id, {}).get("running_processes", [])}
            }
        
        wazuh_server.api_client.get_agent_vulnerabilities.side_effect = mock_get_vulnerabilities
        wazuh_server.api_client.get_agent_ports.side_effect = mock_get_ports
        wazuh_server.api_client.get_agent_processes.side_effect = mock_get_processes
        
        arguments = {"min_cvss": 9.0, "internet_exposed": True, "include_context": True}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check that internet exposure was detected
        assert response_data["summary"]["internet_exposed_vulnerabilities"] > 0
        
        # Apache vulnerability should be marked as exposed (ports 80, 443)
        apache_vuln = next(
            (v for v in response_data["critical_vulnerabilities"] if "apache" in v["package"]), 
            None
        )
        if apache_vuln:
            assert apache_vuln["risk_factors"]["internet_exposed"] is True
    
    async def test_patch_available_filter(self, wazuh_server, mock_agents_critical, mock_critical_vulnerabilities):
        """Test filtering by patch availability."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_critical}
        }
        
        def mock_get_vulnerabilities(agent_id):
            return {
                "data": {"affected_items": mock_critical_vulnerabilities.get(f"agent_{agent_id}", [])}
            }
        
        wazuh_server.api_client.get_agent_vulnerabilities.side_effect = mock_get_vulnerabilities
        
        arguments = {"min_cvss": 9.0, "patch_available": True}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should only include vulnerabilities with patches (CVE-0001 has fixed_version, CVE-0002 has patch_available)
        assert all(
            vuln["risk_factors"]["patch_available"] 
            for vuln in response_data["critical_vulnerabilities"]
        )
    
    async def test_age_filter(self, wazuh_server, mock_agents_critical, mock_critical_vulnerabilities):
        """Test filtering by vulnerability age."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_critical}
        }
        
        def mock_get_vulnerabilities(agent_id):
            return {
                "data": {"affected_items": mock_critical_vulnerabilities.get(f"agent_{agent_id}", [])}
            }
        
        wazuh_server.api_client.get_agent_vulnerabilities.side_effect = mock_get_vulnerabilities
        
        arguments = {"min_cvss": 9.0, "age_days": 30}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should only include recent vulnerabilities (CVE-0001: 5 days, CVE-0003: 10 days)
        for vuln in response_data["critical_vulnerabilities"]:
            assert vuln["risk_factors"]["age_days"] <= 30
    
    async def test_affected_services_filter(self, wazuh_server, mock_agents_critical, mock_critical_vulnerabilities):
        """Test filtering by affected services."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_critical}
        }
        
        def mock_get_vulnerabilities(agent_id):
            return {
                "data": {"affected_items": mock_critical_vulnerabilities.get(f"agent_{agent_id}", [])}
            }
        
        wazuh_server.api_client.get_agent_vulnerabilities.side_effect = mock_get_vulnerabilities
        
        arguments = {
            "min_cvss": 8.0,
            "affected_services": ["payment", "database"],
            "exploit_required": False
        }
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should prioritize payment and database services
        # Should include payment-api (CVE-0002) and mysql (CVE-0004)
        packages = [v["package"] for v in response_data["critical_vulnerabilities"]]
        assert any("payment" in pkg for pkg in packages)
        assert any("mysql" in pkg for pkg in packages)
    
    async def test_risk_scoring(self, wazuh_server, mock_agents_critical, mock_critical_vulnerabilities):
        """Test risk scoring calculation."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_critical[:1]}  # Just payment server
        }
        
        def mock_get_vulnerabilities(agent_id):
            return {
                "data": {"affected_items": mock_critical_vulnerabilities.get(f"agent_{agent_id}", [])}
            }
        
        wazuh_server.api_client.get_agent_vulnerabilities.side_effect = mock_get_vulnerabilities
        
        arguments = {"min_cvss": 9.0}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Check risk scores are calculated and reasonable
        for vuln in response_data["critical_vulnerabilities"]:
            risk_score = vuln["risk_score"]
            cvss_score = vuln["cvss_score"]
            
            # Risk score should be >= CVSS score (due to multipliers)
            assert risk_score >= cvss_score
            
            # If exploitable, risk score should be higher
            if vuln["risk_factors"]["exploitable"]:
                assert risk_score > cvss_score
    
    async def test_immediate_actions_generation(self, wazuh_server, mock_agents_critical, 
                                              mock_critical_vulnerabilities, mock_context_data):
        """Test immediate action generation."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_critical}
        }
        
        def mock_get_vulnerabilities(agent_id):
            return {
                "data": {"affected_items": mock_critical_vulnerabilities.get(f"agent_{agent_id}", [])}
            }
        
        def mock_get_ports(agent_id):
            return {
                "data": {"affected_items": mock_context_data.get(agent_id, {}).get("open_ports", [])}
            }
        
        wazuh_server.api_client.get_agent_vulnerabilities.side_effect = mock_get_vulnerabilities
        wazuh_server.api_client.get_agent_ports.side_effect = mock_get_ports
        wazuh_server.api_client.get_agent_processes.return_value = {"data": {"affected_items": []}}
        
        arguments = {"min_cvss": 8.0, "internet_exposed": True, "include_context": True}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have immediate actions
        assert len(response_data["immediate_actions"]) > 0
        
        # Check for critical priority actions
        critical_actions = [a for a in response_data["immediate_actions"] if a["priority"] == "CRITICAL"]
        assert len(critical_actions) > 0
    
    async def test_attack_surface_analysis(self, wazuh_server, mock_agents_critical, mock_critical_vulnerabilities):
        """Test attack surface analysis."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_critical}
        }
        
        def mock_get_vulnerabilities(agent_id):
            return {
                "data": {"affected_items": mock_critical_vulnerabilities.get(f"agent_{agent_id}", [])}
            }
        
        wazuh_server.api_client.get_agent_vulnerabilities.side_effect = mock_get_vulnerabilities
        
        arguments = {"min_cvss": 8.0}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        attack_surface = response_data["attack_surface"]
        
        # Check attack surface analysis
        assert "exposed_services" in attack_surface
        assert "affected_agents" in attack_surface
        assert "risk_summary" in attack_surface
        
        # Should have affected agents
        assert attack_surface["risk_summary"]["agents_at_risk"] > 0
    
    async def test_empty_result_handling(self, wazuh_server, mock_agents_critical):
        """Test handling when no critical vulnerabilities found."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_critical}
        }
        
        wazuh_server.api_client.get_agent_vulnerabilities.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"min_cvss": 9.0}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        
        assert response_data["summary"]["total_critical_vulnerabilities"] == 0
        assert "No critical vulnerabilities found" in response_data["summary"]["message"]
    
    async def test_error_handling_partial_results(self, wazuh_server, mock_agents_critical):
        """Test handling partial failures gracefully."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": mock_agents_critical}
        }
        
        def mock_vulnerabilities_with_error(agent_id):
            if agent_id == "001":
                raise Exception("API Error")
            return {"data": {"affected_items": []}}
        
        wazuh_server.api_client.get_agent_vulnerabilities.side_effect = mock_vulnerabilities_with_error
        
        arguments = {"min_cvss": 9.0}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should have processing errors
        assert "processing_errors" in response_data
        assert len(response_data["processing_errors"]) > 0


class TestCriticalVulnerabilitiesHelperMethods:
    """Test helper methods for critical vulnerabilities."""
    
    @pytest.fixture
    def wazuh_server(self):
        """Create a minimal server instance for testing helper methods."""
        with patch('wazuh_mcp_server.main.WazuhConfig') as mock_config:
            mock_config.from_env.return_value = MagicMock()
            mock_config.from_env.return_value.log_level = "INFO"
            mock_config.from_env.return_value.debug = False
            
            server = WazuhMCPServer()
            return server
    
    def test_has_available_patch(self, wazuh_server):
        """Test patch availability detection."""
        # Test explicit patch available
        vuln1 = {"patch_available": True}
        assert wazuh_server._has_available_patch(vuln1) is True
        
        # Test fixed version
        vuln2 = {"fixed_version": "2.0.1"}
        assert wazuh_server._has_available_patch(vuln2) is True
        
        # Test solution field
        vuln3 = {"solution": "Update to latest version"}
        assert wazuh_server._has_available_patch(vuln3) is True
        
        # Test remediation with patch keyword
        vuln4 = {"remediation": "Apply the security patch"}
        assert wazuh_server._has_available_patch(vuln4) is True
        
        # Test no patch indicators
        vuln5 = {"cve": "CVE-2024-0001"}
        assert wazuh_server._has_available_patch(vuln5) is False
    
    def test_calculate_vulnerability_age(self, wazuh_server):
        """Test vulnerability age calculation."""
        current_date = datetime.utcnow()
        
        # Test recent vulnerability
        recent_vuln = {
            "published_date": (current_date - timedelta(days=5)).isoformat() + "Z"
        }
        age = wazuh_server._calculate_vulnerability_age(recent_vuln, current_date)
        assert age == 5
        
        # Test old vulnerability
        old_vuln = {
            "published_date": (current_date - timedelta(days=90)).isoformat() + "Z"
        }
        age = wazuh_server._calculate_vulnerability_age(old_vuln, current_date)
        assert age == 90
        
        # Test no date available
        no_date_vuln = {"cve": "CVE-2024-0001"}
        age = wazuh_server._calculate_vulnerability_age(no_date_vuln, current_date)
        assert age == 9999  # Default for unknown age
    
    def test_is_service_related(self, wazuh_server):
        """Test service-port relationship detection."""
        # Test Apache on port 80
        assert wazuh_server._is_service_related("apache2", 80) is True
        assert wazuh_server._is_service_related("apache-httpd", 443) is True
        
        # Test MySQL on port 3306
        assert wazuh_server._is_service_related("mysql-server", 3306) is True
        
        # Test unrelated service-port
        assert wazuh_server._is_service_related("apache2", 3306) is False
        assert wazuh_server._is_service_related("mysql", 80) is False
    
    def test_calculate_vulnerability_risk_score(self, wazuh_server):
        """Test risk score calculation with multipliers."""
        # Base vulnerability
        base_vuln = {"cvss3_score": 9.0}
        base_score = wazuh_server._calculate_vulnerability_risk_score(base_vuln)
        assert base_score == 9.0
        
        # Vulnerability with exploit
        exploit_vuln = {"cvss3_score": 9.0, "exploit_available": True}
        exploit_score = wazuh_server._calculate_vulnerability_risk_score(exploit_vuln)
        assert exploit_score > base_score  # Should be multiplied by 1.5
        
        # Internet exposed vulnerability
        exposed_vuln = {
            "cvss3_score": 9.0,
            "exploit_available": True,
            "internet_exposed": True
        }
        exposed_score = wazuh_server._calculate_vulnerability_risk_score(exposed_vuln)
        assert exposed_score > exploit_score  # Should be multiplied by 2.0
        
        # Recent vulnerability
        recent_vuln = {
            "cvss3_score": 9.0,
            "published_date": (datetime.utcnow() - timedelta(days=5)).isoformat() + "Z"
        }
        recent_score = wazuh_server._calculate_vulnerability_risk_score(recent_vuln)
        assert recent_score > base_score  # Should be multiplied by 1.3
        
        # Critical service vulnerability
        critical_vuln = {
            "cvss3_score": 9.0,
            "name": "payment-processor"
        }
        critical_score = wazuh_server._calculate_vulnerability_risk_score(critical_vuln)
        assert critical_score > base_score  # Should be multiplied by 1.4


@pytest.mark.asyncio
class TestCriticalVulnerabilitiesEdgeCases:
    """Test edge cases for critical vulnerabilities."""
    
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
    
    async def test_malformed_vulnerability_data(self, wazuh_server):
        """Test handling of malformed vulnerability data."""
        agents = [{"id": "001", "name": "test-agent", "status": "active"}]
        
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": agents}
        }
        
        # Malformed vulnerability data
        malformed_vulns = [
            {"cve": "CVE-2024-001"},  # Missing CVSS score
            {"cvss3_score": "not_a_number"},  # Invalid CVSS
            {}  # Empty vulnerability
        ]
        
        wazuh_server.api_client.get_agent_vulnerabilities.return_value = {
            "data": {"affected_items": malformed_vulns}
        }
        
        arguments = {"min_cvss": 9.0}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        # Should not crash
        response_data = json.loads(result[0].text)
        assert "summary" in response_data
    
    async def test_no_agents_scenario(self, wazuh_server):
        """Test handling when no agents are available."""
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": []}
        }
        
        arguments = {"min_cvss": 9.0}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        assert response_data["summary"]["agents_analyzed"] == 0
        assert response_data["summary"]["total_critical_vulnerabilities"] == 0
    
    async def test_context_fetch_failures(self, wazuh_server):
        """Test handling when context fetching fails."""
        agents = [{"id": "001", "name": "test-agent", "status": "active"}]
        vulns = [{"cve": "CVE-2024-001", "cvss3_score": 9.5, "name": "apache2"}]
        
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": agents}
        }
        
        wazuh_server.api_client.get_agent_vulnerabilities.return_value = {
            "data": {"affected_items": vulns}
        }
        
        # Context fetching fails
        wazuh_server.api_client.get_agent_ports.side_effect = Exception("Port fetch failed")
        wazuh_server.api_client.get_agent_processes.side_effect = Exception("Process fetch failed")
        
        arguments = {"min_cvss": 9.0, "include_context": True}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        # Should still return results without context
        response_data = json.loads(result[0].text)
        assert response_data["summary"]["total_critical_vulnerabilities"] == 1
    
    async def test_large_result_truncation(self, wazuh_server):
        """Test handling of large result sets."""
        agents = [{"id": "001", "name": "test-agent", "status": "active"}]
        
        # Create 200 vulnerabilities
        many_vulns = []
        for i in range(200):
            many_vulns.append({
                "cve": f"CVE-2024-{i:04d}",
                "name": f"package-{i}",
                "cvss3_score": 9.0 + (i % 10) / 10,
                "exploit_available": i % 2 == 0
            })
        
        wazuh_server.api_client.get_agents.return_value = {
            "data": {"affected_items": agents}
        }
        
        wazuh_server.api_client.get_agent_vulnerabilities.return_value = {
            "data": {"affected_items": many_vulns}
        }
        
        arguments = {"min_cvss": 9.0, "max_results": 50}
        result = await wazuh_server._handle_get_wazuh_critical_vulnerabilities(arguments)
        
        response_data = json.loads(result[0].text)
        
        # Should limit results
        assert len(response_data["critical_vulnerabilities"]) <= 50
        
        # Should be sorted by risk score (highest first)
        risk_scores = [v["risk_score"] for v in response_data["critical_vulnerabilities"]]
        assert risk_scores == sorted(risk_scores, reverse=True)