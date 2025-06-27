"""
Mock data fixtures for comprehensive testing.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any
import json


class MockWazuhData:
    """Mock Wazuh API responses for testing."""
    
    @staticmethod
    def get_mock_alerts(count: int = 10) -> Dict[str, Any]:
        """Generate mock alert data."""
        alerts = []
        base_time = datetime.utcnow()
        
        for i in range(count):
            alert = {
                "id": f"alert_{i:03d}",
                "timestamp": (base_time - timedelta(minutes=i)).isoformat() + "Z",
                "rule": {
                    "id": f"rule_{i % 5}",
                    "description": f"Mock security rule {i % 5}",
                    "level": (i % 15) + 1,
                    "groups": ["test", "security", "mock"]
                },
                "agent": {
                    "id": f"agent_{i % 3:03d}",
                    "name": f"test-agent-{i % 3}",
                    "ip": f"192.168.1.{100 + (i % 3)}"
                },
                "location": f"/var/log/test{i % 3}.log",
                "full_log": f"Mock log entry {i} for testing purposes",
                "decoder": {
                    "name": "test-decoder"
                }
            }
            alerts.append(alert)
        
        return {
            "error": 0,
            "data": {
                "affected_items": alerts,
                "total_affected_items": count,
                "failed_items": []
            }
        }
    
    @staticmethod
    def get_mock_agents(count: int = 5) -> Dict[str, Any]:
        """Generate mock agent data."""
        agents = []
        statuses = ["active", "active", "active", "disconnected", "never_connected"]
        
        for i in range(count):
            agent = {
                "id": f"agent_{i:03d}",
                "name": f"test-agent-{i}",
                "ip": f"192.168.1.{100 + i}",
                "status": statuses[i % len(statuses)],
                "os": {
                    "platform": "linux" if i % 2 == 0 else "windows",
                    "version": "Ubuntu 20.04" if i % 2 == 0 else "Windows 10",
                    "arch": "x86_64"
                },
                "version": "Wazuh v4.8.0",
                "manager": "test-manager",
                "lastKeepAlive": datetime.utcnow().isoformat() + "Z",
                "registerIP": f"192.168.1.{100 + i}",
                "configSum": f"ab12cd34ef56{i}",
                "mergedSum": f"12ab34cd56ef{i}"
            }
            agents.append(agent)
        
        return {
            "error": 0,
            "data": {
                "affected_items": agents,
                "total_affected_items": count,
                "failed_items": []
            }
        }
    
    @staticmethod
    def get_mock_vulnerabilities(agent_id: str, count: int = 3) -> Dict[str, Any]:
        """Generate mock vulnerability data for an agent."""
        vulnerabilities = []
        severities = ["critical", "high", "medium", "low"]
        
        for i in range(count):
            vuln = {
                "cve": f"CVE-2024-{1000 + i}",
                "title": f"Mock vulnerability {i} for testing",
                "severity": severities[i % len(severities)],
                "published": (datetime.utcnow() - timedelta(days=i * 10)).isoformat() + "Z",
                "updated": (datetime.utcnow() - timedelta(days=i * 5)).isoformat() + "Z",
                "reference": f"https://nvd.nist.gov/vuln/detail/CVE-2024-{1000 + i}",
                "rationale": f"Mock rationale for vulnerability {i}",
                "condition": f"Package version condition {i}",
                "external_references": [
                    f"https://example.com/vuln-{i}",
                    f"https://security.example.com/advisory-{i}"
                ]
            }
            vulnerabilities.append(vuln)
        
        return {
            "error": 0,
            "data": {
                "affected_items": vulnerabilities,
                "total_affected_items": count,
                "failed_items": []
            }
        }
    
    @staticmethod
    def get_mock_health_check() -> Dict[str, Any]:
        """Generate mock health check response."""
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "api_version": "v4.8.0",
            "cluster_status": "enabled",
            "last_keep_alive": datetime.utcnow().isoformat() + "Z"
        }
    
    @staticmethod
    def get_mock_system_info() -> Dict[str, Any]:
        """Generate mock system information."""
        return {
            "error": 0,
            "data": {
                "affected_items": [{
                    "version": "v4.8.0",
                    "api_version": "v4.8.0",
                    "hostname": "test-wazuh-manager",
                    "cluster": {
                        "enabled": True,
                        "running": True,
                        "name": "test-cluster"
                    },
                    "compilation_date": "2024-01-01T00:00:00Z",
                    "node_name": "master-node",
                    "type": "master"
                }]
            }
        }
    
    @staticmethod
    def get_mock_error_response(error_code: int = 1000, message: str = "Mock error") -> Dict[str, Any]:
        """Generate mock error response."""
        return {
            "error": error_code,
            "message": message,
            "data": {
                "affected_items": [],
                "total_affected_items": 0,
                "failed_items": []
            }
        }


class MockThreatIntelData:
    """Mock threat intelligence data for testing."""
    
    @staticmethod
    def get_mock_virustotal_response(hash_value: str) -> Dict[str, Any]:
        """Generate mock VirusTotal response."""
        return {
            "data": {
                "id": hash_value,
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 45,
                        "malicious": 15,
                        "suspicious": 2,
                        "undetected": 12,
                        "timeout": 0
                    },
                    "last_analysis_results": {
                        "Avira": {
                            "category": "malicious",
                            "engine_name": "Avira",
                            "result": "Malware.Generic"
                        },
                        "ClamAV": {
                            "category": "harmless",
                            "engine_name": "ClamAV",
                            "result": None
                        }
                    },
                    "reputation": -50,
                    "total_votes": {
                        "harmless": 10,
                        "malicious": 25
                    }
                }
            }
        }
    
    @staticmethod
    def get_mock_abuseipdb_response(ip_address: str) -> Dict[str, Any]:
        """Generate mock AbuseIPDB response."""
        return {
            "data": {
                "ipAddress": ip_address,
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidencePercentage": 75,
                "countryCode": "US",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Example ISP",
                "domain": "example.com",
                "totalReports": 50,
                "numDistinctUsers": 25,
                "lastReportedAt": datetime.utcnow().isoformat() + "Z"
            }
        }
    
    @staticmethod
    def get_mock_shodan_response(ip_address: str) -> Dict[str, Any]:
        """Generate mock Shodan response."""
        return {
            "ip_str": ip_address,
            "org": "Example Organization",
            "data": [
                {
                    "port": 80,
                    "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
                    "transport": "tcp",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                },
                {
                    "port": 443,
                    "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
                    "transport": "tcp",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            ],
            "ports": [80, 443],
            "vulns": ["CVE-2024-1000", "CVE-2024-1001"],
            "country_name": "United States",
            "city": "New York",
            "latitude": 40.7128,
            "longitude": -74.0060
        }


class MockComplianceData:
    """Mock compliance assessment data."""
    
    @staticmethod
    def get_mock_pci_requirements() -> List[Dict[str, Any]]:
        """Generate mock PCI DSS requirements."""
        return [
            {
                "id": "1.1",
                "title": "Install and maintain a firewall configuration",
                "description": "Network firewalls are devices that control computer-to-computer traffic.",
                "status": "compliant",
                "evidence": ["Firewall rules configured", "Regular rule reviews"],
                "score": 100
            },
            {
                "id": "2.1",
                "title": "Always change vendor-supplied defaults",
                "description": "Malicious individuals often use vendor default passwords.",
                "status": "partial",
                "evidence": ["Some default passwords changed"],
                "gaps": ["Default SNMP community strings detected"],
                "score": 75
            },
            {
                "id": "6.1",
                "title": "Establish a process to identify security vulnerabilities",
                "description": "Unscrupulous individuals use security vulnerabilities to gain privileged access.",
                "status": "non_compliant",
                "evidence": [],
                "gaps": ["No vulnerability scanning process", "No patch management"],
                "score": 0
            }
        ]
    
    @staticmethod
    def get_mock_hipaa_requirements() -> List[Dict[str, Any]]:
        """Generate mock HIPAA requirements."""
        return [
            {
                "id": "164.308(a)(1)",
                "title": "Conduct an accurate and thorough assessment",
                "description": "Assigned security responsibility (Required)",
                "status": "compliant",
                "evidence": ["Security officer assigned", "Documented policies"],
                "score": 100
            },
            {
                "id": "164.312(a)(1)",
                "title": "Access control",
                "description": "Unique user identification (Required)",
                "status": "partial",
                "evidence": ["User accounts configured"],
                "gaps": ["No automatic logoff implemented"],
                "score": 80
            }
        ]


def load_mock_data_file(filename: str) -> Dict[str, Any]:
    """Load mock data from JSON file."""
    import os
    
    mock_data_dir = os.path.dirname(__file__)
    file_path = os.path.join(mock_data_dir, f"{filename}.json")
    
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return json.load(f)
    else:
        # Return empty mock data if file doesn't exist
        return {"error": 0, "data": {"affected_items": [], "total_affected_items": 0}}


# Pre-generate some commonly used mock data
MOCK_ALERTS_SAMPLE = MockWazuhData.get_mock_alerts(20)
MOCK_AGENTS_SAMPLE = MockWazuhData.get_mock_agents(10)
MOCK_VULNERABILITIES_SAMPLE = MockWazuhData.get_mock_vulnerabilities("001", 5)
MOCK_HEALTH_CHECK = MockWazuhData.get_mock_health_check()