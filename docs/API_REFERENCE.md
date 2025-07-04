# API Reference - Wazuh MCP Server

## Overview

The Wazuh MCP Server provides both **Model Context Protocol (MCP) tools** for AI assistants and **HTTP/WebSocket APIs** for custom integrations. This reference covers all available endpoints, tools, and integration methods.

## Table of Contents

1. [MCP Tools](#mcp-tools)
2. [HTTP API](#http-api)
3. [WebSocket API](#websocket-api)
4. [Authentication](#authentication)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)
7. [Data Models](#data-models)

---

## MCP Tools

These tools are available when using the server with Claude Desktop or other MCP-compatible clients.

### Security Analysis Tools

#### `get_alerts`
Retrieve security alerts from Wazuh with comprehensive filtering options.

**Arguments:**
- `limit` (int, optional): Maximum number of alerts to return (default: 50, max: 1000)
- `level` (string, optional): Alert level filter ("low", "medium", "high", "critical")
- `rule_id` (string, optional): Specific rule ID to filter by
- `agent_id` (string, optional): Specific agent ID to filter by
- `time_range` (string, optional): Time range ("1h", "24h", "7d", "30d")
- `search` (string, optional): Search term for alert content

**Example:**
```json
{
  "limit": 100,
  "level": "high",
  "time_range": "24h",
  "search": "malware"
}
```

#### `analyze_threats`
Perform advanced threat analysis with intelligence correlation.

**Arguments:**
- `time_range` (string, optional): Analysis time window (default: "24h")
- `include_mitre` (bool, optional): Include MITRE ATT&CK mapping (default: true)
- `threat_intel` (bool, optional): Include threat intelligence lookups (default: true)
- `severity_threshold` (string, optional): Minimum severity level (default: "medium")

#### `security_overview`
Generate comprehensive security dashboard with key metrics.

**Arguments:**
- `time_range` (string, optional): Overview time window (default: "24h")
- `include_trends` (bool, optional): Include trend analysis (default: true)
- `detailed_breakdown` (bool, optional): Include detailed breakdowns (default: false)

### Agent Management Tools

#### `get_agents`
Retrieve information about Wazuh agents.

**Arguments:**
- `status` (string, optional): Filter by agent status ("active", "disconnected", "never_connected")
- `os_type` (string, optional): Filter by OS type ("windows", "linux", "macos")
- `agent_id` (string, optional): Specific agent ID
- `limit` (int, optional): Maximum number of agents to return (default: 50)

#### `get_agent_processes`
List running processes on a specific agent.

**Arguments:**
- `agent_id` (string, required): Target agent ID
- `limit` (int, optional): Maximum number of processes (default: 100)
- `sort_by` (string, optional): Sort field ("pid", "name", "cpu", "memory")

#### `get_agent_ports`
Show open network ports on a specific agent.

**Arguments:**
- `agent_id` (string, required): Target agent ID
- `protocol` (string, optional): Protocol filter ("tcp", "udp")
- `state` (string, optional): Port state filter ("listening", "established")

### Vulnerability Management Tools

#### `get_vulnerabilities`
Retrieve vulnerability information from Wazuh.

**Arguments:**
- `severity` (string, optional): Severity filter ("low", "medium", "high", "critical")
- `agent_id` (string, optional): Specific agent ID
- `package_name` (string, optional): Specific package name
- `limit` (int, optional): Maximum number of vulnerabilities (default: 50)

### Search and Investigation Tools

#### `search_wazuh_logs`
Search through Wazuh log data with advanced filtering.

**Arguments:**
- `query` (string, required): Search query
- `time_range` (string, optional): Time range for search (default: "24h")
- `log_type` (string, optional): Log type filter ("alerts", "events", "archives")
- `limit` (int, optional): Maximum number of results (default: 100)

#### `get_cluster_health`
Check Wazuh cluster health and status.

**Arguments:**
- `include_nodes` (bool, optional): Include individual node status (default: true)
- `include_stats` (bool, optional): Include cluster statistics (default: true)

### Compliance Tools

#### `compliance_check`
Perform compliance assessment against various frameworks.

**Arguments:**
- `framework` (string, optional): Compliance framework ("pci_dss", "gdpr", "hipaa", "nist")
- `agent_id` (string, optional): Specific agent ID
- `detailed` (bool, optional): Include detailed findings (default: false)

---

## HTTP API

Base URL: `https://your-domain.com/api/v1`

### Authentication Endpoints

#### `POST /auth/login`
Obtain JWT token for API access.

**Request Body:**
```json
{
  "api_key": "your-api-key"
}
```

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1Q...",
  "expires_in": 86400,
  "user_info": {
    "username": "user",
    "role": "admin"
  }
}
```

#### `POST /auth/refresh`
Refresh JWT token.

**Headers:**
- `Authorization: Bearer <token>`

**Response:**
```json
{
  "token": "eyJ0eXAiOiJKV1Q...",
  "expires_in": 86400
}
```

### Tool Execution Endpoints

#### `GET /tools`
List available MCP tools.

**Headers:**
- `Authorization: Bearer <token>` or `Authorization: ApiKey <api-key>`

**Response:**
```json
{
  "tools": [
    {
      "name": "get_alerts",
      "description": "Retrieve security alerts",
      "arguments": {
        "limit": {"type": "integer", "optional": true},
        "level": {"type": "string", "optional": true}
      }
    }
  ]
}
```

#### `POST /tools/{tool_name}/call`
Execute a specific MCP tool.

**Headers:**
- `Authorization: Bearer <token>` or `Authorization: ApiKey <api-key>`
- `Content-Type: application/json`

**Request Body:**
```json
{
  "arguments": {
    "limit": 10,
    "level": "high"
  }
}
```

**Response:**
```json
{
  "result": {
    "alerts": [...],
    "total_count": 42,
    "execution_time": "1.23s"
  },
  "metadata": {
    "tool_name": "get_alerts",
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

### Resource Endpoints

#### `GET /resources`
List available MCP resources.

**Headers:**
- `Authorization: Bearer <token>` or `Authorization: ApiKey <api-key>`

#### `GET /resources/{resource_uri}`
Get specific resource content.

**Headers:**
- `Authorization: Bearer <token>` or `Authorization: ApiKey <api-key>`

### Health and Status Endpoints

#### `GET /health`
Health check endpoint (no authentication required).

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "wazuh_connection": "connected",
  "uptime": "72h15m"
}
```

#### `GET /metrics`
Prometheus metrics endpoint.

**Headers:**
- `Authorization: Bearer <token>` (admin role required)

### Admin Endpoints

#### `GET /admin/stats`
Server statistics and metrics.

**Headers:**
- `Authorization: Bearer <token>` (admin role required)

**Response:**
```json
{
  "requests_total": 1234,
  "active_connections": 5,
  "avg_response_time": "0.45s",
  "error_rate": "0.1%",
  "memory_usage": "256MB"
}
```

---

## WebSocket API

WebSocket URL: `wss://your-domain.com/ws`

### Connection

Connect to WebSocket with authentication:

```javascript
const ws = new WebSocket('wss://your-domain.com/ws');

// Send authentication after connection
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'auth',
    token: 'your-jwt-token'
  }));
};
```

### Message Format

All WebSocket messages use JSON format:

```json
{
  "id": "unique-request-id",
  "type": "request",
  "command": "call_tool",
  "data": {
    "tool_name": "get_alerts",
    "arguments": {"limit": 10}
  }
}
```

### Commands

#### `ping`
Test connection and measure latency.

**Request:**
```json
{
  "id": "req-001",
  "type": "request",
  "command": "ping"
}
```

**Response:**
```json
{
  "id": "req-001",
  "type": "response",
  "command": "ping",
  "data": {
    "pong": true,
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

#### `list_tools`
Get available tools.

**Request:**
```json
{
  "id": "req-002",
  "type": "request",
  "command": "list_tools"
}
```

#### `call_tool`
Execute a tool.

**Request:**
```json
{
  "id": "req-003",
  "type": "request",
  "command": "call_tool",
  "data": {
    "tool_name": "get_alerts",
    "arguments": {"limit": 5}
  }
}
```

#### `subscribe`
Subscribe to real-time updates.

**Request:**
```json
{
  "id": "req-004",
  "type": "request",
  "command": "subscribe",
  "data": {
    "subscription": "alerts",
    "filters": {"level": "high"}
  }
}
```

**Update Notification:**
```json
{
  "type": "notification",
  "subscription": "alerts",
  "data": {
    "new_alerts": [...],
    "timestamp": "2024-01-15T10:30:00Z"
  }
}
```

---

## Authentication

### API Key Authentication

Send API key in Authorization header:

```bash
curl -H "Authorization: ApiKey your-api-key" \
     https://your-domain.com/api/v1/tools
```

### JWT Token Authentication

1. **Get Token:**
```bash
curl -X POST https://your-domain.com/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"api_key": "your-api-key"}'
```

2. **Use Token:**
```bash
curl -H "Authorization: Bearer eyJ0eXAiOiJKV1Q..." \
     https://your-domain.com/api/v1/tools
```

### Role-Based Access Control

- **user**: Basic access to security tools
- **admin**: Full access including metrics and admin endpoints

---

## Error Handling

### HTTP Status Codes

- `200 OK`: Success
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Missing or invalid authentication
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

### Error Response Format

```json
{
  "error": {
    "code": "INVALID_PARAMETERS",
    "message": "The 'limit' parameter must be between 1 and 1000",
    "details": {
      "parameter": "limit",
      "received": 2000,
      "max_allowed": 1000
    }
  },
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Common Error Codes

- `AUTHENTICATION_FAILED`: Invalid credentials
- `INVALID_PARAMETERS`: Bad request parameters
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `WAZUH_CONNECTION_ERROR`: Can't connect to Wazuh
- `TOOL_EXECUTION_ERROR`: Tool execution failed
- `PERMISSION_DENIED`: Insufficient permissions

---

## Rate Limiting

### Limits

- **Default**: 100 requests per minute per API key
- **Admin**: 500 requests per minute per API key
- **WebSocket**: 50 messages per minute per connection

### Headers

Rate limit information is returned in response headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1642248600
```

### Exceeding Limits

When rate limit is exceeded, you'll receive:

```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Try again in 60 seconds.",
    "retry_after": 60
  }
}
```

---

## Data Models

### Alert Object

```json
{
  "id": "alert-123",
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "high",
  "rule_id": "100001",
  "description": "Malware detected",
  "agent": {
    "id": "001",
    "name": "web-server-01",
    "ip": "192.168.1.10"
  },
  "location": "/var/log/auth.log",
  "full_log": "Jan 15 10:30:00 malware.exe detected",
  "mitre": {
    "tactic": "Initial Access",
    "technique": "T1566"
  }
}
```

### Agent Object

```json
{
  "id": "001",
  "name": "web-server-01",
  "ip": "192.168.1.10",
  "status": "active",
  "os": {
    "platform": "ubuntu",
    "version": "20.04",
    "architecture": "x86_64"
  },
  "version": "4.5.0",
  "last_keepalive": "2024-01-15T10:30:00Z",
  "group": ["web-servers", "production"]
}
```

### Vulnerability Object

```json
{
  "cve": "CVE-2024-1234",
  "severity": "high",
  "score": 8.5,
  "package": "openssl",
  "version": "1.1.1f",
  "fixed_version": "1.1.1g",
  "description": "Buffer overflow in OpenSSL",
  "agent_id": "001",
  "detection_time": "2024-01-15T10:30:00Z"
}
```

---

## Integration Examples

### Python Integration

```python
import requests
import json

class WazuhMCPClient:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key
        self.token = None
        self.authenticate()
    
    def authenticate(self):
        response = requests.post(
            f"{self.base_url}/auth/login",
            json={"api_key": self.api_key}
        )
        self.token = response.json()["token"]
    
    def get_alerts(self, **kwargs):
        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.post(
            f"{self.base_url}/tools/get_alerts/call",
            headers=headers,
            json={"arguments": kwargs}
        )
        return response.json()

# Usage
client = WazuhMCPClient("https://wazuh-mcp.company.com/api/v1", "your-api-key")
alerts = client.get_alerts(limit=10, level="high")
```

### JavaScript Integration

```javascript
class WazuhMCPClient {
    constructor(baseUrl, apiKey) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.token = null;
    }
    
    async authenticate() {
        const response = await fetch(`${this.baseUrl}/auth/login`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({api_key: this.apiKey})
        });
        const data = await response.json();
        this.token = data.token;
    }
    
    async getAlerts(options = {}) {
        const response = await fetch(`${this.baseUrl}/tools/get_alerts/call`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${this.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({arguments: options})
        });
        return response.json();
    }
}

// Usage
const client = new WazuhMCPClient('https://wazuh-mcp.company.com/api/v1', 'your-api-key');
await client.authenticate();
const alerts = await client.getAlerts({limit: 10, level: 'high'});
```

---

## Best Practices

1. **Authentication**: Always use HTTPS and rotate API keys regularly
2. **Rate Limiting**: Implement client-side rate limiting to avoid 429 errors
3. **Error Handling**: Always handle errors gracefully with retry logic
4. **Pagination**: Use limit parameters for large datasets
5. **Filtering**: Apply filters to reduce unnecessary data transfer
6. **WebSocket**: Use WebSocket for real-time updates, HTTP for one-time queries
7. **Security**: Never log or expose API keys or JWT tokens
8. **Monitoring**: Monitor API usage and performance metrics

---

## Support

For API support and questions:

- **Documentation**: [GitHub Repository](https://github.com/gensecaihq/Wazuh-MCP-Server)
- **Issues**: Report bugs and feature requests via GitHub Issues
- **Community**: Join discussions in GitHub Discussions

---

**API Version:** 1.0.0  
**Last Updated:** January 2024  
**Compatible with:** Wazuh 4.5.0+, MCP Protocol 1.0