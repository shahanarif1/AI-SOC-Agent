# IP/Port-Based Deployment Guide - Wazuh MCP Server

## Overview

This guide provides instructions for deploying the Wazuh MCP Server using IP addresses and ports instead of fully qualified domain names (FQDNs). This deployment mode is ideal for:

- **Private Networks**: Internal corporate networks and LANs
- **Development Environments**: Local testing and development setups  
- **Isolated Environments**: Air-gapped or restricted network environments
- **IP-Only Infrastructure**: Systems without DNS or domain management
- **Cloud Private Networks**: VPC/VNet deployments with private IP ranges

## 🎯 Deployment Options

### Option 1: Direct IP/Port Access (Recommended)
Services run on specific ports and are accessed directly via IP:port combinations.

**Advantages:**
- No SSL configuration required
- Works in any network environment
- Simple firewall rules
- No DNS dependencies

**Use Cases:**
- Private LANs (192.168.x.x)
- Corporate networks (10.x.x.x)
- Cloud private subnets
- Development environments

### Option 2: IP-Based Proxy (Optional)
Uses Traefik proxy for HTTP routing while still using IP addresses.

**Advantages:**
- Centralized access through single port
- Load balancing capabilities
- Request routing and middleware

**Use Cases:**
- Multiple service instances
- Load balancing requirements
- Centralized logging/monitoring

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose installed
- Network connectivity to Wazuh server
- Open ports for services (default: 8000, 8001)

### 1. Clone and Setup

```bash
# Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Copy IP-based configuration template
cp .env.local-ip.example .env.local-ip
```

### 2. Configure Environment

Edit `.env.local-ip` with your settings:

```env
# Wazuh Server (use IP address)
WAZUH_HOST=192.168.1.100
WAZUH_PORT=55000
WAZUH_USER=your-username
WAZUH_PASS=your-password
VERIFY_SSL=false

# Security Configuration
JWT_SECRET=your-generated-secret-key
API_KEYS=admin-key:admin:admin,user-key:user:user

# Service Ports
HTTP_PORT=8000
WS_PORT=8001
```

### 3. Generate Security Keys

```bash
# Generate JWT secret
openssl rand -base64 64

# Generate API keys
openssl rand -hex 32
```

### 4. Deploy Services

```bash
# Make deployment script executable
chmod +x deploy-local-ip.sh

# Deploy with core services only
./deploy-local-ip.sh deploy

# Or deploy with monitoring and storage
COMPOSE_PROFILES=storage,monitoring ./deploy-local-ip.sh deploy
```

### 5. Verify Deployment

```bash
# Check service health
curl http://localhost:8000/health

# List available tools
curl http://localhost:8000/tools

# Get JWT token
curl -X POST http://localhost:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"api_key": "your-api-key"}'
```

## 🔧 Configuration Reference

### Network Configuration

#### Service Ports
```env
# Core Services
HTTP_PORT=8000          # HTTP API port
WS_PORT=8001           # WebSocket API port

# Optional Services  
REDIS_PORT=6379        # Redis cache
PROMETHEUS_PORT=9090   # Metrics collection
GRAFANA_PORT=3000      # Monitoring dashboard

# Proxy (if enabled)
TRAEFIK_HTTP_PORT=80   # HTTP proxy
TRAEFIK_DASHBOARD_PORT=8080  # Traefik dashboard
```

#### Network Subnet
```env
# Docker network configuration
NETWORK_SUBNET=172.20.0.0/24
```

### Wazuh Server Configuration

#### IP-Based Setup
```env
# Use IP addresses instead of hostnames
WAZUH_HOST=192.168.1.100
WAZUH_INDEXER_HOST=192.168.1.101

# Disable SSL verification for private networks
VERIFY_SSL=false
WAZUH_INDEXER_VERIFY_SSL=false
```

#### Mixed Environment
```env
# Mix of IP and hostname (if some systems have DNS)
WAZUH_HOST=wazuh-manager.local
WAZUH_INDEXER_HOST=192.168.1.101
```

### Service Profiles

Control which services are deployed using profiles:

```env
# Core services only (HTTP, WebSocket)
COMPOSE_PROFILES=

# With storage (Redis)
COMPOSE_PROFILES=storage

# With monitoring (Prometheus, Grafana)
COMPOSE_PROFILES=monitoring

# Full deployment
COMPOSE_PROFILES=storage,monitoring

# With proxy
COMPOSE_PROFILES=proxy,storage,monitoring
```

## 🌐 Access Methods

### Direct IP Access

#### Local Access
```bash
# HTTP API
curl http://localhost:8000/health

# WebSocket (using wscat)
wscat -c ws://localhost:8001
```

#### LAN Access
```bash
# Replace with your server's IP
SERVER_IP=192.168.1.50

# HTTP API
curl http://$SERVER_IP:8000/health

# WebSocket
wscat -c ws://$SERVER_IP:8001
```

### Proxy Access (Optional)

When using the proxy profile:

```bash
# All services through proxy
curl http://192.168.1.50/api/health
curl http://192.168.1.50/ws/
```

## 🔐 Security Considerations

### Firewall Configuration

#### Basic Setup
```bash
# Allow MCP server ports
sudo ufw allow 8000/tcp  # HTTP API
sudo ufw allow 8001/tcp  # WebSocket API

# Optional services
sudo ufw allow 3000/tcp  # Grafana
sudo ufw allow 9090/tcp  # Prometheus
```

#### Restricted Access
```bash
# Allow only from specific network
sudo ufw allow from 192.168.1.0/24 to any port 8000
sudo ufw allow from 192.168.1.0/24 to any port 8001
```

#### Corporate Network
```bash
# Allow from corporate network range
sudo ufw allow from 10.0.0.0/8 to any port 8000
sudo ufw allow from 10.0.0.0/8 to any port 8001
```

### Authentication

#### API Key Authentication
```bash
# Use API key directly
curl -H "Authorization: ApiKey your-api-key" \
     http://192.168.1.50:8000/tools
```

#### JWT Token Authentication
```bash
# Get token
TOKEN=$(curl -s -X POST http://192.168.1.50:8000/auth/login \
             -H "Content-Type: application/json" \
             -d '{"api_key": "your-api-key"}' | \
        jq -r '.token')

# Use token
curl -H "Authorization: Bearer $TOKEN" \
     http://192.168.1.50:8000/tools
```

### SSL/TLS in Private Networks

#### Option 1: No SSL (Recommended for Private Networks)
```env
VERIFY_SSL=false
TRAEFIK_ENTRYPOINT=web
TLS_RESOLVER=none
```

#### Option 2: Self-Signed Certificates
```bash
# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout server.key -out server.crt \
    -subj "/CN=192.168.1.50"

# Use with custom SSL configuration
```

## 🔧 Management Commands

### Deployment Management
```bash
# Deploy services
./deploy-local-ip.sh deploy

# Stop services
./deploy-local-ip.sh stop

# Restart services
./deploy-local-ip.sh restart

# View status
./deploy-local-ip.sh status

# View logs
./deploy-local-ip.sh logs

# Validate configuration
./deploy-local-ip.sh config
```

### Docker Compose Commands
```bash
# Direct Docker Compose usage
docker-compose -f docker-compose.local-ip.yml \
               --env-file .env.local-ip \
               --profile storage,monitoring \
               up -d

# Scale HTTP service
docker-compose -f docker-compose.local-ip.yml \
               scale wazuh-mcp-http=3
```

## 📊 Monitoring and Logging

### Grafana Dashboard (Optional)

Access Grafana at `http://192.168.1.50:3000`:
- Username: `admin`
- Password: Set via `GRAFANA_PASSWORD` in `.env.local-ip`

### Prometheus Metrics (Optional)

Access Prometheus at `http://192.168.1.50:9090`:
- View metrics and targets
- Query MCP server performance data

### Log Access
```bash
# View all logs
./deploy-local-ip.sh logs

# View specific service logs
./deploy-local-ip.sh logs wazuh-mcp-http
./deploy-local-ip.sh logs wazuh-mcp-ws

# Follow logs in real-time
docker-compose -f docker-compose.local-ip.yml logs -f
```

## 🧪 Testing and Validation

### Health Checks
```bash
# Test core services
curl http://192.168.1.50:8000/health
echo "test" | nc 192.168.1.50 8001

# Test authentication
curl -X POST http://192.168.1.50:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"api_key": "your-api-key"}'

# Test tool execution
curl -X POST http://192.168.1.50:8000/tools/get_alerts/call \
     -H "Authorization: ApiKey your-api-key" \
     -H "Content-Type: application/json" \
     -d '{"arguments": {"limit": 5}}'
```

### Network Connectivity
```bash
# Test from different machines on network
ping 192.168.1.50
telnet 192.168.1.50 8000
telnet 192.168.1.50 8001
```

## 🌍 Integration Examples

### Python Client (IP-based)
```python
import requests

class WazuhMCPClient:
    def __init__(self, server_ip, http_port=8000, api_key=None):
        self.base_url = f"http://{server_ip}:{http_port}"
        self.api_key = api_key
        self.token = None
        
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
client = WazuhMCPClient("192.168.1.50", api_key="your-api-key")
client.authenticate()
alerts = client.get_alerts(limit=10)
```

### JavaScript Client (IP-based)
```javascript
class WazuhMCPClient {
    constructor(serverIP, httpPort = 8000, apiKey) {
        this.baseUrl = `http://${serverIP}:${httpPort}`;
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
const client = new WazuhMCPClient('192.168.1.50', 8000, 'your-api-key');
await client.authenticate();
const alerts = await client.getAlerts({limit: 10});
```

### WebSocket Client (IP-based)
```python
import websocket
import json

def on_message(ws, message):
    print(f"Received: {message}")

def on_open(ws):
    # Send authentication
    auth_msg = {
        "type": "auth",
        "token": "your-jwt-token"
    }
    ws.send(json.dumps(auth_msg))
    
    # Request alerts
    request_msg = {
        "id": "req-001",
        "type": "request", 
        "command": "call_tool",
        "data": {
            "tool_name": "get_alerts",
            "arguments": {"limit": 5}
        }
    }
    ws.send(json.dumps(request_msg))

# Connect to WebSocket
ws = websocket.WebSocketApp(
    "ws://192.168.1.50:8001",
    on_open=on_open,
    on_message=on_message
)
ws.run_forever()
```

## 🔄 Migration and Scaling

### Migrating from FQDN to IP
```bash
# 1. Stop existing FQDN deployment
./deploy.sh stop

# 2. Export data (if needed)
docker-compose -f docker-compose.yml exec redis redis-cli --rdb /backup/dump.rdb

# 3. Deploy IP-based version
./deploy-local-ip.sh deploy

# 4. Import data (if needed)
docker-compose -f docker-compose.local-ip.yml exec redis redis-cli --rdb /backup/dump.rdb
```

### Horizontal Scaling
```bash
# Scale HTTP service for load balancing
docker-compose -f docker-compose.local-ip.yml \
               --profile proxy \
               scale wazuh-mcp-http=3

# Verify scaling
docker-compose -f docker-compose.local-ip.yml ps
```

## 📝 Troubleshooting

### Common Issues

#### Port Conflicts
```bash
# Check if ports are in use
netstat -tlnp | grep :8000
lsof -i :8000

# Change ports in .env.local-ip
HTTP_PORT=8080
WS_PORT=8081
```

#### Network Connectivity
```bash
# Test basic connectivity
ping 192.168.1.50
telnet 192.168.1.50 8000

# Check firewall rules
sudo ufw status
iptables -L
```

#### Service Health
```bash
# Check container status
docker-compose -f docker-compose.local-ip.yml ps

# View container logs
docker-compose -f docker-compose.local-ip.yml logs wazuh-mcp-http

# Check resource usage
docker stats
```

#### Authentication Issues
```bash
# Verify API keys
grep API_KEYS .env.local-ip

# Test authentication endpoint
curl -v -X POST http://192.168.1.50:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"api_key": "your-api-key"}'
```

### Performance Optimization

#### For High Load
```env
# Increase connection limits
MAX_CONNECTIONS=20
POOL_SIZE=10

# Adjust timeouts
REQUEST_TIMEOUT_SECONDS=60

# Enable caching
CACHE_TTL_SECONDS=600
```

#### For Low Resources
```env
# Reduce resource usage
MAX_CONNECTIONS=5
POOL_SIZE=2

# Disable optional services
COMPOSE_PROFILES=
```

## 📚 Additional Resources

- [Configuration Reference](CONFIGURATION_REFERENCE.md) - Complete configuration options
- [API Reference](API_REFERENCE.md) - API documentation and examples
- [Operations Manual](OPERATIONS_MANUAL.md) - Production operations guide
- [Troubleshooting Guide](LOCAL_SETUP.md#troubleshooting) - Common issues and solutions

---

**IP/Port Deployment Version:** 1.0.0  
**Last Updated:** January 2024  
**Compatible with:** Docker 20.10+, Docker Compose v2