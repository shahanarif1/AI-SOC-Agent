# Production Deployment Guide - Wazuh MCP Server

This comprehensive guide covers deploying the Wazuh MCP Server for production use with enterprise-grade security, monitoring, and scalability. Perfect for teams and organizations requiring shared access from multiple AI clients.

## 🌐 Architecture Overview

The remote setup provides:
- **HTTP API** - RESTful endpoints for integration
- **WebSocket API** - Real-time bidirectional communication  
- **Authentication** - JWT tokens and API key security
- **Rate Limiting** - Protection against abuse
- **SSL Termination** - HTTPS/WSS with Let's Encrypt
- **Monitoring** - Prometheus + Grafana dashboards
- **Load Balancing** - Traefik reverse proxy

## Prerequisites

### Infrastructure Requirements

- **Docker**: Version 20.10+ with Docker Compose v2
- **Server**: Linux server with minimum 2GB RAM, 1 CPU core, 10GB storage
- **Network**: Public IP address with ports 80/443 accessible (FQDN mode) OR any IP address with custom ports (IP mode)
- **Domain**: Registered domain name pointing to your server (FQDN mode only)
- **DNS**: Ability to configure DNS A records (FQDN mode only)

> **Note**: For private networks, internal LANs, or environments without domain names, see the [IP/Port Deployment Guide](IP_PORT_DEPLOYMENT.md).

### Wazuh Environment

- **Wazuh Server**: Version 4.5.0 or higher
- **API Access**: Valid Wazuh API credentials with appropriate permissions
- **Network**: Connectivity from deployment server to Wazuh API
- **SSL**: Production-grade SSL certificates (Let's Encrypt supported)

### Security Considerations

- **Firewall**: Properly configured firewall rules
- **SSH Access**: Secure SSH key-based authentication
- **Monitoring**: Log aggregation and monitoring infrastructure
- **Backup**: Regular backup procedures for data persistence

## 🚀 Quick Deployment

### 1. Prepare Environment

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Copy environment template
cp .env.remote.example .env.remote

# Edit configuration
nano .env.remote
```

### 2. Configure Environment

**Minimum required settings in `.env.remote`:**

```env
# Wazuh Configuration
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-wazuh-username
WAZUH_PASS=your-wazuh-password

# Domain Configuration  
DOMAIN=your-domain.com
ACME_EMAIL=admin@your-domain.com

# Security
JWT_SECRET=your-jwt-secret-key
API_KEYS=key1:user1:user,admin-key:admin:admin
```

### 3. Deploy Services

```bash
# Make deployment script executable
chmod +x deploy-remote.sh

# Deploy all services
./deploy-remote.sh deploy
```

## 🔧 Configuration Options

### Environment Variables

**Wazuh Server:**
```env
WAZUH_HOST=wazuh-manager.company.com
WAZUH_PORT=55000
WAZUH_USER=api-user
WAZUH_PASS=secure-password
VERIFY_SSL=false
```

**Wazuh Indexer (4.8.0+):**
```env
WAZUH_INDEXER_HOST=wazuh-indexer.company.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=indexer-password
```

**Security:**
```env
# JWT Configuration
JWT_SECRET=your-very-secure-secret-key
JWT_EXPIRY_HOURS=24
ENABLE_AUTH=true

# API Keys (format: key:username:role)
API_KEYS=prod-key:production:admin,dev-key:developer:user

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# CORS
CORS_ORIGINS=https://your-app.com,https://dashboard.company.com
```

**SSL & Domains:**
```env
DOMAIN=mcp.company.com
ACME_EMAIL=admin@company.com
```

**Monitoring:**
```env
REDIS_PASSWORD=secure-redis-password
GRAFANA_PASSWORD=secure-grafana-password
```

## 🔐 Authentication

### API Key Authentication

1. **Generate API Keys** in `.env.remote`:
   ```env
   API_KEYS=mykey123:john:user,adminkey456:admin:admin
   ```

2. **Use API Key directly**:
   ```bash
   curl -H "Authorization: ApiKey mykey123" \
        http://your-domain.com:8000/tools
   ```

### JWT Token Authentication

1. **Get JWT Token**:
   ```bash
   curl -X POST http://your-domain.com:8000/auth/login \
        -H "Content-Type: application/json" \
        -d '{"api_key": "mykey123"}'
   ```

2. **Use JWT Token**:
   ```bash
   curl -H "Authorization: Bearer eyJ0eXAiOiJKV1Q..." \
        http://your-domain.com:8000/tools
   ```

## 🌐 API Endpoints

### HTTP API (Port 8000)

**Public Endpoints:**
- `GET /health` - Health check
- `POST /auth/login` - Get JWT token

**Protected Endpoints (require authentication):**
- `GET /tools` - List available tools
- `POST /tools/{tool_name}/call` - Execute a tool
- `GET /resources` - List available resources
- `GET /resources/{uri}` - Get a resource

**Admin Endpoints:**
- `GET /admin/metrics` - Server metrics (admin role required)

### WebSocket API (Port 8001)

**Commands:**
```json
{"command": "ping"}
{"command": "list_tools"}
{"command": "call_tool", "tool_name": "get_alerts", "arguments": {"limit": 10}}
{"command": "subscribe", "subscription": "alerts"}
```

## 📊 Monitoring

### Service URLs

After deployment with domain `mcp.company.com`:

- **HTTP API**: `https://mcp-http.mcp.company.com`
- **WebSocket**: `wss://mcp-ws.mcp.company.com`
- **Traefik Dashboard**: `https://traefik.mcp.company.com`
- **Grafana**: `https://grafana.mcp.company.com`
- **Prometheus**: `https://prometheus.mcp.company.com`

### Health Checks

```bash
# Check HTTP service
curl https://mcp-http.mcp.company.com/health

# Check all services status
./deploy-remote.sh status
```

## 🐳 Docker Management

### Service Commands

```bash
# View logs
./deploy-remote.sh logs

# Stop services
./deploy-remote.sh stop

# Restart services  
./deploy-remote.sh restart

# Check status
./deploy-remote.sh status
```

### Manual Docker Commands

```bash
# View all services
docker-compose -f docker-compose.remote.yml ps

# View logs for specific service
docker-compose -f docker-compose.remote.yml logs -f wazuh-mcp-http

# Scale HTTP service
docker-compose -f docker-compose.remote.yml up -d --scale wazuh-mcp-http=3

# Update services
docker-compose -f docker-compose.remote.yml pull
docker-compose -f docker-compose.remote.yml up -d
```

## 🔒 Security Best Practices

### 1. Use Strong Authentication

```env
# Generate secure secrets
JWT_SECRET=$(openssl rand -base64 32)
API_KEYS=prod_$(openssl rand -hex 16):production:admin
```

### 2. Network Security

```bash
# Use firewall to restrict access
ufw allow 80/tcp
ufw allow 443/tcp
ufw deny 8000/tcp  # Block direct access to API
ufw deny 8001/tcp  # Block direct access to WebSocket
```

### 3. SSL Configuration

```env
# Always use HTTPS in production
DOMAIN=your-secure-domain.com
ACME_EMAIL=security@company.com
```

### 4. Rate Limiting

```env
# Adjust based on your needs
RATE_LIMIT_REQUESTS=50
RATE_LIMIT_WINDOW=60
```

## 🌍 Client Integration Examples

### Python Client

```python
import requests
import websocket
import json

# HTTP API
def get_wazuh_alerts():
    # Get token
    auth_response = requests.post(
        "https://mcp-http.company.com/auth/login",
        json={"api_key": "your-api-key"}
    )
    token = auth_response.json()["token"]
    
    # Call tool
    response = requests.post(
        "https://mcp-http.company.com/tools/get_alerts/call",
        headers={"Authorization": f"Bearer {token}"},
        json={"arguments": {"limit": 10}}
    )
    return response.json()

# WebSocket API
def websocket_client():
    ws = websocket.WebSocket()
    ws.connect("wss://mcp-ws.company.com")
    
    # Send command
    ws.send(json.dumps({
        "command": "call_tool",
        "tool_name": "get_alerts",
        "arguments": {"limit": 5}
    }))
    
    # Receive response
    response = json.loads(ws.recv())
    ws.close()
    return response
```

### JavaScript/Node.js Client

```javascript
// HTTP API
async function getAlerts() {
    // Get token
    const authResponse = await fetch('https://mcp-http.company.com/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({api_key: 'your-api-key'})
    });
    const {token} = await authResponse.json();
    
    // Call tool
    const response = await fetch('https://mcp-http.company.com/tools/get_alerts/call', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({arguments: {limit: 10}})
    });
    return response.json();
}

// WebSocket API
function websocketClient() {
    const ws = new WebSocket('wss://mcp-ws.company.com');
    
    ws.onopen = () => {
        ws.send(JSON.stringify({
            command: 'call_tool',
            tool_name: 'get_alerts',
            arguments: {limit: 5}
        }));
    };
    
    ws.onmessage = (event) => {
        const response = JSON.parse(event.data);
        console.log(response);
    };
}
```

## 🔧 Troubleshooting

### Common Issues

1. **SSL Certificate Issues**
   ```bash
   # Check certificate status
   docker-compose -f docker-compose.remote.yml logs traefik
   
   # Verify domain DNS
   nslookup mcp-http.your-domain.com
   ```

2. **Authentication Failures**
   ```bash
   # Check API keys configuration
   grep API_KEYS .env.remote
   
   # Test authentication
   curl -X POST http://localhost:8000/auth/login \
        -d '{"api_key": "your-key"}'
   ```

3. **Service Health Issues**
   ```bash
   # Check service status
   ./deploy-remote.sh status
   
   # View detailed logs
   ./deploy-remote.sh logs wazuh-mcp-http
   ```

### Debug Mode

Enable debug logging:

```env
LOG_LEVEL=DEBUG
DEBUG=true
```

## 📈 Scaling

### Horizontal Scaling

```yaml
# In docker-compose.remote.yml
wazuh-mcp-http:
  # ... existing config
  deploy:
    replicas: 3
```

### Load Balancing

Traefik automatically load balances between multiple instances.

### Resource Limits

```yaml
wazuh-mcp-http:
  # ... existing config
  deploy:
    resources:
      limits:
        memory: 1G
        cpus: '0.5'
```

## 🔄 Updates

```bash
# Pull latest changes
git pull origin main

# Rebuild and redeploy
./deploy-remote.sh deploy

# Zero-downtime update (if using multiple replicas)
docker-compose -f docker-compose.remote.yml up -d --no-deps wazuh-mcp-http
```