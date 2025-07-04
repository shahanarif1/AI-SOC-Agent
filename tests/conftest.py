"""Pytest configuration and fixtures."""

import pytest
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from wazuh_mcp_server.config import WazuhConfig


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield tmp_dir


@pytest.fixture
def mock_config():
    """Create a mock WazuhConfig for testing."""
    return WazuhConfig(
        host="test.example.com",
        port=55000,
        username="testuser",
        password="testpassword123",
        verify_ssl=False,
        api_version="v4",
        max_alerts_per_query=1000,
        max_agents_per_scan=10,
        debug=True,
        log_level="DEBUG"
    )


@pytest.fixture
def sample_alerts():
    """Sample alert data for testing."""
    return [
        {
            "id": "1",
            "timestamp": (datetime.utcnow() - timedelta(minutes=5)).isoformat() + "Z",
            "rule": {
                "id": "5710",
                "level": 10,
                "description": "Multiple authentication failures",
                "groups": ["authentication_failed", "pci_dss_8.2.3"]
            },
            "agent": {
                "id": "001",
                "name": "web-server-01",
                "ip": "192.168.1.10"
            },
            "location": "/var/log/auth.log"
        },
        {
            "id": "2",
            "timestamp": (datetime.utcnow() - timedelta(minutes=3)).isoformat() + "Z",
            "rule": {
                "id": "5712",
                "level": 12,
                "description": "Possible attack detected",
                "groups": ["attack", "intrusion_attempt"]
            },
            "agent": {
                "id": "002",
                "name": "web-server-02",
                "ip": "192.168.1.11"
            },
            "location": "/var/log/apache2/access.log"
        }
    ]


@pytest.fixture
def sample_agents():
    """Sample agent data for testing."""
    return [
        {
            "id": "001",
            "name": "web-server-01",
            "ip": "192.168.1.10",
            "status": "active",
            "os": {"platform": "linux"},
            "version": "4.3.0",
            "lastKeepAlive": "2023-12-01T10:00:00Z"
        },
        {
            "id": "002",
            "name": "web-server-02",
            "ip": "192.168.1.11",
            "status": "disconnected",
            "os": {"platform": "linux"},
            "version": "4.2.0",
            "lastKeepAlive": "2023-12-01T09:30:00Z"
        },
        {
            "id": "003",
            "name": "db-server-01",
            "ip": "192.168.1.20",
            "status": "active",
            "os": {"platform": "windows"},
            "version": "4.3.0",
            "lastKeepAlive": "2023-12-01T10:01:00Z"
        }
    ]


@pytest.fixture
def sample_vulnerabilities():
    """Sample vulnerability data for testing."""
    return [
        {
            "agent_id": "001",
            "severity": "critical",
            "title": "Remote Code Execution Vulnerability",
            "cve": "CVE-2023-1234",
            "description": "Critical RCE vulnerability in web server"
        },
        {
            "agent_id": "002",
            "severity": "high",
            "title": "SQL Injection Vulnerability",
            "cve": "CVE-2023-5678",
            "description": "SQL injection in database interface"
        },
        {
            "agent_id": "003",
            "severity": "medium",
            "title": "Cross-Site Scripting",
            "cve": "CVE-2023-9012",
            "description": "XSS vulnerability in web application"
        }
    ]


@pytest.fixture
def mock_wazuh_api_response():
    """Mock Wazuh API response structure."""
    def _create_response(data, total_items=None):
        if total_items is None:
            total_items = len(data) if isinstance(data, list) else 1
        
        return {
            "data": {
                "affected_items": data,
                "total_affected_items": total_items,
                "total_failed_items": 0,
                "failed_items": []
            },
            "message": "Success",
            "error": 0
        }
    
    return _create_response


@pytest.fixture
def mock_aiohttp_session():
    """Mock aiohttp session for testing."""
    session = AsyncMock()
    
    # Mock successful authentication response
    auth_response = AsyncMock()
    auth_response.status = 200
    auth_response.json.return_value = {
        "data": {
            "token": "mock_jwt_token"
        }
    }
    
    # Mock API responses
    api_response = AsyncMock()
    api_response.status = 200
    api_response.json.return_value = {
        "data": {
            "affected_items": [],
            "total_affected_items": 0
        }
    }
    
    session.get.return_value.__aenter__.return_value = auth_response
    session.request.return_value.__aenter__.return_value = api_response
    
    return session


@pytest.fixture
def mock_env_vars():
    """Mock environment variables for testing."""
    env_vars = {
        "WAZUH_HOST": "test.example.com",
        "WAZUH_PORT": "55000",
        "WAZUH_USER": "testuser",
        "WAZUH_PASS": "testpassword123",
        "VERIFY_SSL": "false",
        "DEBUG": "true",
        "LOG_LEVEL": "DEBUG"
    }
    
    with patch.dict(os.environ, env_vars, clear=False):
        yield env_vars


@pytest.fixture
def mock_datetime():
    """Mock datetime for consistent testing."""
    fixed_datetime = datetime(2023, 12, 1, 10, 0, 0)
    
    with patch('wazuh_mcp_server.analyzers.security_analyzer.datetime') as mock_dt:
        mock_dt.utcnow.return_value = fixed_datetime
        mock_dt.fromisoformat = datetime.fromisoformat
        mock_dt.return_value = fixed_datetime
        yield mock_dt


@pytest.fixture(autouse=True)
def reset_global_state():
    """Reset global state between tests."""
    # Reset any global state here if needed
    yield
    # Cleanup after test