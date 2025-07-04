# Wazuh MCP Server

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)
[![Wazuh 4.5.0+](https://img.shields.io/badge/Wazuh-4.5.0+-blue.svg)](https://wazuh.com/)
[![Production Ready](https://img.shields.io/badge/Status-Production%20Ready-success.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server)

**Enterprise-grade Model Context Protocol server for Wazuh security platform integration**

*Production-ready • Secure by default • Cross-platform compatible*

[Quick Start](#quick-start) •
[Documentation](#documentation) •
[Security](#security) •
[Support](#support)

</div>

---

## Overview

The **Wazuh MCP Server** is a production-grade Model Context Protocol (MCP) server that bridges Wazuh SIEM platforms with AI assistants like Claude Desktop. It enables security teams to leverage natural language interfaces for threat detection, incident response, and security operations while maintaining enterprise-grade security and compliance standards.

### What Problems Does It Solve?

- **Complex Security Data Access**: Transform complex Wazuh API calls into simple natural language queries
- **Time-Consuming Analysis**: Accelerate threat hunting and incident response with AI-powered insights
- **Team Collaboration**: Enable multiple team members to access Wazuh data through AI assistants
- **Operational Efficiency**: Reduce manual security operations tasks through intelligent automation

### Who Is This For?

- **Security Operations Centers (SOCs)** requiring efficient threat analysis
- **Security Analysts** seeking AI-enhanced threat hunting capabilities
- **DevSecOps Teams** integrating security into CI/CD pipelines
- **Enterprise Organizations** needing secure, scalable security data access

## Key Features

- **Dual Deployment Modes**: Local integration for individual users and remote deployment for teams
- **Production-Ready Architecture**: Enterprise-grade error recovery, monitoring, and security
- **Security-First Design**: JWT authentication, rate limiting, and comprehensive SSL/TLS handling
- **Cross-Platform Support**: Native support for Windows, macOS, and Linux environments
- **Comprehensive Monitoring**: Built-in health checks, metrics collection, and alerting
- **Intelligent Error Recovery**: Automatic failover and self-healing capabilities
- **Multi-Client Support**: Single server instance supports multiple concurrent AI clients

## Deployment Options

### Local Deployment

For individual users requiring direct integration with Claude Desktop or other MCP-compatible clients.

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["/path/to/wazuh_mcp_server.py", "--stdio"],
      "env": {
        "WAZUH_HOST": "your-wazuh-server.com",
        "WAZUH_USER": "your-username",
        "WAZUH_PASS": "your-password"
      }
    }
  }
}
```

### Production Deployment

For teams and organizations requiring shared access with enterprise security and monitoring.

```bash
# Deploy production stack
./deploy.sh deploy

# Access via HTTPS API
curl -H "Authorization: Bearer TOKEN" \
     https://your-domain.com/api/health

# WebSocket connection
wss://your-domain.com/ws
```

## Quick Start

Choose your deployment option based on your needs:

- **🖥️ Local Setup**: Perfect for individual security analysts using Claude Desktop
- **🌐 Production Setup**: Ideal for teams and organizations requiring shared access

### Prerequisites

**All Deployments:**
- Python 3.9 or higher
- Access to a Wazuh server (4.5.0+)
- Git for installation

**Production Deployments:**
- Docker and Docker Compose
- Domain name (for SSL certificates)
- 2GB+ RAM, 1+ CPU cores

### Local Setup (Claude Desktop Integration)

Perfect for individual users who want AI-powered Wazuh analysis directly in Claude Desktop.

#### Step 1: Install the Server

**Windows (PowerShell):**
```powershell
# Clone and install
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
python setup.py

# Configure your Wazuh connection
notepad .env
```

**macOS/Linux:**
```bash
# Clone and install
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
python setup.py

# Configure your Wazuh connection
nano .env  # or vim .env
```

#### Step 2: Configure Environment

Edit your `.env` file with your Wazuh server details:
```bash
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-username
WAZUH_PASS=your-secure-password
VERIFY_SSL=true
```

#### Step 3: Test Connection

```bash
# Test server connection
python -m wazuh_mcp_server.scripts.test_connection

# Test MCP server
python wazuh_mcp_server.py --stdio
```

#### Step 4: Configure Claude Desktop

Add the MCP server to your Claude Desktop configuration:

**Configuration File Locations:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

**Configuration:**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["/full/path/to/wazuh_mcp_server.py", "--stdio"],
      "env": {
        "WAZUH_HOST": "your-wazuh-server.com",
        "WAZUH_USER": "your-username",
        "WAZUH_PASS": "your-password"
      }
    }
  }
}
```

**Important Notes:**
- Use the full absolute path to `wazuh_mcp_server.py`
- Replace placeholder values with your actual Wazuh credentials
- Restart Claude Desktop after configuration changes

#### Step 5: Start Using

After restarting Claude Desktop, you can ask questions like:
- "Show me the latest security alerts from Wazuh"
- "What are the top threat sources today?"
- "Check the compliance status for PCI DSS"
- "Analyze recent authentication failures"

### Option 2: Production Setup (Teams & Remote Access)

#### 🖥️ Windows
```powershell
# PowerShell
.\deploy.ps1 deploy

# Command Prompt  
deploy.bat deploy
```

#### 🍎 macOS / 🐧 Linux
```bash
# 1. Prepare environment
cp .env.production.example .env.production
# Edit .env.production with your configuration

# 2. Deploy
./deploy.sh deploy

# 3. Access
# HTTP: https://mcp-http.your-domain.com
# WebSocket: wss://mcp-ws.your-domain.com
```

## 🖥️ Local Setup (Claude Desktop)

### Prerequisites

- Python 3.9+
- Claude Desktop
- Access to Wazuh server

### Installation

```bash
# Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Configure environment
cp .env.example .env
nano .env  # Add your Wazuh credentials
```

### Claude Desktop Configuration

**Configuration file location:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\\Claude\\claude_desktop_config.json`

**Add this configuration:**

```json
{
  "mcpServers": {
    "wazuh-security": {
      "command": "python",
      "args": [
        "/absolute/path/to/Wazuh-MCP-Server/wazuh_mcp_server.py",
        "--stdio"
      ],
      "env": {
        "WAZUH_HOST": "your-wazuh-server.com",
        "WAZUH_PORT": "55000",
        "WAZUH_USER": "your-username",
        "WAZUH_PASS": "your-password",
        "VERIFY_SSL": "true",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Alternative (if installed globally):**

```json
{
  "mcpServers": {
    "wazuh-security": {
      "command": "wazuh-mcp-server",
      "args": ["--stdio"],
      "env": {
        "WAZUH_HOST": "your-wazuh-server.com",
        "WAZUH_USER": "your-username",
        "WAZUH_PASS": "your-password"
      }
    }
  }
}
```

### Testing Local Setup

```bash
# Test connection
python -m wazuh_mcp_server.scripts.test_connection

# Test Claude Desktop integration
# Restart Claude Desktop and ask:
# "Show me the latest security alerts from Wazuh"
```

## 🌐 Production Setup (Teams & Multi-Client)

### Prerequisites

- Docker and Docker Compose
- Domain name (for SSL)
- 2GB+ RAM, 1+ CPU cores

### Quick Deployment

```bash
# 1. Prepare configuration
cp .env.production.example .env.production

# 2. Configure minimum required settings
cat >> .env.production << EOF
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-wazuh-username
WAZUH_PASS=your-wazuh-password
DOMAIN=your-domain.com
ACME_EMAIL=admin@your-domain.com
JWT_SECRET=$(openssl rand -base64 32)
API_KEYS=admin-key:admin:admin,user-key:user:user
EOF

# 3. Deploy all services
chmod +x deploy.sh
./deploy.sh deploy
```

### Remote Architecture

The remote deployment includes:

- **HTTP API Server** (Port 8000) - RESTful endpoints
- **WebSocket Server** (Port 8001) - Real-time communication
- **Traefik Proxy** - SSL termination and load balancing
- **Redis** - Session management and caching
- **Prometheus** - Metrics collection
- **Grafana** - Monitoring dashboards

### Service URLs

After deployment:

- **HTTP API**: `https://mcp-http.your-domain.com`
- **WebSocket**: `wss://mcp-ws.your-domain.com`
- **Grafana**: `https://grafana.your-domain.com`
- **Traefik Dashboard**: `https://traefik.your-domain.com`

### Authentication

**Get JWT Token:**
```bash
curl -X POST https://mcp-http.your-domain.com/auth/login \
     -H "Content-Type: application/json" \
     -d '{"api_key": "your-api-key"}'
```

**Use Token:**
```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     https://mcp-http.your-domain.com/tools
```

## 🛠️ Available Tools

Both local and remote deployments provide these AI tools:

### Core Security Tools
- **get_alerts** - Retrieve security alerts with advanced filtering
- **get_agents** - Get Wazuh agent status and information
- **analyze_threats** - AI-powered threat analysis and risk assessment
- **get_vulnerabilities** - Vulnerability data for agents
- **security_overview** - Comprehensive security dashboard

### Advanced Analysis Tools
- **get_agent_processes** - List running processes on agents
- **get_agent_ports** - Show open network ports
- **search_wazuh_logs** - Search and analyze log data
- **get_cluster_health** - Cluster status and health metrics

### Compliance and Reporting
- **compliance_check** - Framework compliance analysis
- **generate_report** - Custom security reports
- **threat_intelligence** - External threat intelligence integration

## 🔧 Configuration Options

### Environment Variables

**Core Wazuh Settings:**
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
USE_INDEXER_FOR_ALERTS=true
USE_INDEXER_FOR_VULNERABILITIES=true
```

**External Integrations:**
```env
VIRUSTOTAL_API_KEY=your-virustotal-key
SHODAN_API_KEY=your-shodan-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

**Security (Remote Mode):**
```env
ENABLE_AUTH=true
JWT_SECRET=your-secret-key
API_KEYS=key1:user1:admin,key2:user2:user
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
```

## 📊 Usage Examples

### Claude Desktop (Local Mode)

Ask Claude Desktop:
- "Show me the latest critical security alerts"
- "What agents are currently offline?"
- "Analyze the threat landscape for the last 24 hours" 
- "What vulnerabilities need immediate attention?"
- "Generate a security compliance report"

### HTTP API (Remote Mode)

```bash
# Get security alerts
curl -H "Authorization: Bearer TOKEN" \
     -X POST https://mcp.company.com/tools/get_alerts/call \
     -d '{"arguments": {"limit": 10, "level": 10}}'

# Analyze threats
curl -H "Authorization: Bearer TOKEN" \
     -X POST https://mcp.company.com/tools/analyze_threats/call \
     -d '{"arguments": {"analysis_type": "comprehensive"}}'
```

### WebSocket API (Remote Mode)

```javascript
const ws = new WebSocket('wss://mcp.company.com');
ws.send(JSON.stringify({
  command: 'call_tool',
  tool_name: 'get_alerts',
  arguments: {limit: 5}
}));
```

## 🔍 Monitoring and Observability

### Health Checks

```bash
# Local mode
python wazuh_mcp_server.py --stdio
# Check stderr for health status

# Remote mode
curl https://mcp.company.com/health
./deploy.sh status
```

### Logs

```bash
# Local mode
# Logs output to stderr when running

# Production mode
./deploy.sh logs
docker-compose logs -f wazuh-mcp-http
```

### Metrics

Remote mode includes comprehensive metrics via Prometheus and Grafana:
- Request rates and response times
- Error rates and types
- Wazuh API performance
- Authentication metrics
- Resource utilization

## 🔒 Security Features

### Local Mode Security
- Secure credential management via environment variables
- SSL/TLS support with certificate validation
- Input validation and sanitization

### Remote Mode Security
- JWT-based authentication with configurable expiry
- API key authentication for initial access
- Rate limiting per client IP
- CORS protection with configurable origins
- HTTPS/WSS with Let's Encrypt certificates
- Network isolation via Docker networks

## 📚 Documentation

- **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)** - Choose the right deployment option
- **[Local Setup Guide](docs/LOCAL_SETUP.md)** - Detailed Claude Desktop integration
- **[Production Setup Guide](docs/REMOTE_SETUP.md)** - Team and remote deployment
- **[API Reference](docs/API_REFERENCE.md)** - Complete API documentation
- **[Configuration Guide](docs/CONFIGURATION.md)** - All configuration options
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions

## 🚀 Production Deployment

### Scaling

```bash
# Scale HTTP API instances
docker-compose up -d --scale wazuh-mcp-http=3

# Scale WebSocket instances  
docker-compose up -d --scale wazuh-mcp-ws=2
```

### High Availability

- Load balancing via Traefik
- Health checks and automatic recovery
- Redis for session persistence
- SSL termination and renewal

### Security Hardening

```bash
# Generate secure secrets
JWT_SECRET=$(openssl rand -base64 32)
API_KEYS=prod_$(openssl rand -hex 16):production:admin

# Configure firewall
ufw allow 80/tcp
ufw allow 443/tcp
ufw deny 8000/tcp  # Block direct API access
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Install in development mode
pip install -e .

# Run tests
pytest tests/

# Run linting
ruff check src/
black src/
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

### Security Features

- **Authentication**: JWT tokens and API key authentication
- **Transport Security**: HTTPS/WSS with automatic SSL certificate management
- **Rate Limiting**: Configurable request throttling and abuse prevention
- **Input Validation**: Comprehensive input sanitization and validation
- **Secure Configuration**: Secure defaults with explicit security warnings

### Security Best Practices

1. **Use Strong Authentication**:
   ```bash
   # Generate secure JWT secret
   JWT_SECRET=$(openssl rand -base64 64)
   
   # Generate secure API keys
   API_KEYS=$(openssl rand -base64 32):admin:admin
   ```

2. **Enable SSL Verification**:
   ```bash
   VERIFY_SSL=true
   WAZUH_INDEXER_VERIFY_SSL=true
   ```

3. **Secure Network Configuration**:
   ```bash
   # Bind to specific interfaces only
   BIND_ADDRESS=127.0.0.1
   
   # Use non-default ports if needed
   HTTP_PORT=8000
   ```

4. **Regular Updates**:
   ```bash
   # Check for security updates
   git pull origin main
   pip install --upgrade -r requirements.txt
   ```

### Reporting Security Issues

For security vulnerabilities, please email: security@wazuh-mcp-server.org

Do not report security issues in public GitHub issues.

## Support

- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)
- **Documentation**: [docs/](docs/)

## Acknowledgments

- **Wazuh Team** - For the excellent SIEM platform
- **Anthropic** - For Claude and the Model Context Protocol
- **Open Source Community** - For the foundational tools and libraries

---

<div align="center">

**Enterprise-grade security integration for the AI era**

[Report Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues) • [Request Features](https://github.com/gensecaihq/Wazuh-MCP-Server/issues) • [Contribute](CONTRIBUTING.md)

</div>