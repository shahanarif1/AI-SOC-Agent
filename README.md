# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Wazuh Compatible](https://img.shields.io/badge/Wazuh-4.8%2B-orange.svg)](https://wazuh.com/)
[![Current Release](https://img.shields.io/badge/Release-v2.0.0-green.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server/releases)

A **local Model Context Protocol (MCP) server** that connects Wazuh SIEM with Claude Desktop for AI-powered security operations using **stdio transport**.

## What it does

- **🔍 Security Monitoring**: Query Wazuh alerts, agents, and vulnerabilities through Claude
- **🧠 AI Analysis**: Get AI-powered security insights, threat analysis, and compliance reports
- **💬 Natural Language**: Ask questions like "Show me critical alerts from the last hour" or "Analyze this security incident"
- **📱 Local Integration**: Direct stdio connection with Claude Desktop - no network setup required

<img width="797" height="568" alt="claude0mcp-wazuh" src="https://github.com/user-attachments/assets/458d3c94-e1f9-4143-a1a4-85cb629287d4" />

---

## 🏷️ Version Information

### **✅ v1.0.1 - Most Stable Release** (Recommended for Production)
- **Status**: ✅ **MOST STABLE** - [GitHub Release](https://github.com/gensecaihq/Wazuh-MCP-Server/releases/tag/v1.0.1)
- **Architecture**: **Local MCP Server** with **stdio transport**
- **Features**: 11 core security tools covering essential operations
- **Best For**: **Production environments** requiring maximum stability and reliability
- **Download**: Go to [Releases](https://github.com/gensecaihq/Wazuh-MCP-Server/releases) and download v1.0.1
- **Documentation**: [v1.0.1 README](https://github.com/gensecaihq/Wazuh-MCP-Server/blob/v1.0.1/README.md)

### **🚀 Main Branch - Advanced Tools** (This Branch)
- **Status**: 🧪 **ADVANCED TESTING** - For users who want to try advanced tools
- **Architecture**: **Local MCP Server** with **stdio transport**
- **Features**: 26 security tools with enhanced capabilities (109% more than v1.0.1)
- **Best For**: **Power users** who want to test advanced features and tools
- **Stability**: More features but potentially less stable than v1.0.1
- **Installation**: Available on this branch for testing

### **🔬 v3-check Branch - Future WIP** (For Brave Early Adopters)
- **Status**: 🔬 **WORK IN PROGRESS** - For users who dare to try future features
- **Architecture**: **Remote MCP Server** with **HTTP/SSE transport**
- **Deployment**: Docker containerization with complete orchestration
- **Transport**: HTTP/HTTPS + Server-Sent Events (SSE)
- **Features**: All main branch features + OAuth2, monitoring, high availability
- **Best For**: **Early adopters** who want to test cutting-edge remote MCP capabilities
- **Preview**: Available on [v3-check branch](https://github.com/gensecaihq/Wazuh-MCP-Server/tree/v3-check)

> **💡 Recommendation Guide**:
> - **Production Use**: Use **v1.0.1 release** for maximum stability
> - **Advanced Tools**: Use **main branch** if you want more security tools and features
> - **Future Features**: Use **v3-check branch** if you dare to try remote MCP server capabilities

---

## 🚀 Quick Start

> **Choose Your Version First**: See [Version Information](#️-version-information) above to choose between v1.0.1 (most stable), main branch (advanced tools), or v3-check (future WIP).

### 📋 Installation Options

#### ✅ **Option 1: v1.0.1 - Most Stable** (Recommended for Production)
```bash
# Download from GitHub Releases
# Go to: https://github.com/gensecaihq/Wazuh-MCP-Server/releases/tag/v1.0.1
# Download and extract the source code

# OR clone the specific tag
git clone -b v1.0.1 https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
python3 install.py  # Note: v1.0.1 uses root-level install.py
```

#### 🧪 **Option 2: Main Branch - Advanced Tools** (This Branch)
```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Ensure you're on the main branch
git checkout main

# Install dependencies  
python3 scripts/install.py  # Note: main branch uses scripts/install.py
```

#### 🔬 **Option 3: v3-check Branch - Future WIP** (For Brave Users)
```bash
# Clone and switch to v3-check
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
git checkout v3-check

# Docker deployment (no Python setup needed)
cp .env.example .env
# Edit .env with your Wazuh details
docker compose up -d
```

### 2. Configuration

**First, create a dedicated API user in Wazuh Dashboard:**

1. Login to Wazuh Dashboard (https://your-wazuh-server:443)
2. Go to **Security** → **Internal users**
3. Create user with `wazuh` backend role
4. Use these credentials (not your dashboard login)

**Then configure your environment:**

```bash
# Copy and edit configuration
cp .env.example .env
# Edit .env with your Wazuh details
```

**Example .env configuration:**
```env
# Required Wazuh Configuration
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-api-username
WAZUH_PASS=your-api-password
WAZUH_PORT=55000

# Security (recommended for production)
VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=true

# Optional Performance Settings
MAX_ALERTS_PER_QUERY=1000
CACHE_TTL_SECONDS=300
LOG_LEVEL=INFO
```

### 3. Claude Desktop Integration

**Add to Claude Desktop configuration:**

1. Open Claude Desktop → **Settings** → **Developer**
2. Click **Edit Config** to create/open `claude_desktop_config.json`
3. Add the server configuration:

**macOS/Linux (Recommended - uses wrapper script):**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/full/path/to/Wazuh-MCP-Server/scripts/mcp_wrapper.sh",
      "args": ["--stdio"]
    }
  }
}
```

**Windows:**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["/full/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"],
      "env": {}
    }
  }
}
```

4. **Replace** `/full/path/to/Wazuh-MCP-Server` with your actual installation path
5. **Restart Claude Desktop**

### 4. Test Your Setup

```bash
# Validate configuration
python scripts/validate_setup.py

# Test Wazuh connectivity
curl -u username:password https://your-wazuh:55000/
```

**In Claude Desktop, try asking:**
- "Show me recent security alerts"
- "What's the status of my Wazuh agents?"
- "Analyze security threats in the last 24 hours"

---

## 🎯 Features by Version

### 🛡️ Security Tools by Version
- **v1.0.1 (Stable)**: 11 core security tools
- **Main Branch (Advanced)**: 26 security tools (109% more than v1.0.1)
- **v3-check (WIP)**: All main branch tools + remote capabilities

### 🧪 Main Branch Features (26 Total Tools)
- **get_alerts**: Retrieve and filter Wazuh alerts with advanced filtering
- **analyze_threats**: AI-powered threat analysis and recommendations
- **check_agent_health**: Comprehensive agent status monitoring
- **compliance_check**: Multi-framework compliance assessments (PCI DSS, GDPR, HIPAA, NIST, ISO27001)
- **risk_assessment**: Comprehensive security risk analysis
- **vulnerability_prioritization**: Risk-based vulnerability management
- **security_summary**: Executive security dashboard
- **incident_analysis**: Structured security incident investigation
- **threat_hunting**: Proactive threat detection strategies
- **forensic_analysis**: Digital forensics investigation tools
- **And 16 more specialized security tools...**

### 🧠 AI-Powered Prompts
- **Security Incident Analysis**: Structured incident investigation workflows
- **Threat Hunting Queries**: Proactive threat detection strategies
- **Compliance Assessment**: Framework-specific compliance analysis
- **Executive Reporting**: High-level security summaries
- **Technical Deep Dives**: Detailed security analysis

### 🔄 Real-time Capabilities
- **Live Alert Monitoring**: Immediate alerts for high-severity events
- **Agent Status Updates**: Real-time agent health monitoring
- **Progress Tracking**: Live progress for long-running operations
- **Continuous Monitoring**: Background security monitoring

---

## 🛠️ Development & Testing

### Local Development
```bash
# Setup development environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements.txt

# Run tests
pytest tests/

# Start development server
python3 -m wazuh_mcp_server.main --stdio
```

### Validation Tools
```bash
# Test your Wazuh connection
python scripts/test_connection.py

# Validate your configuration
python scripts/validate_setup.py

# Check dependency compatibility
python scripts/check_compatibility.py
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Authentication Problems
**Problem**: "Invalid credentials" despite correct dashboard login

**Solution**: Wazuh Dashboard and API use different authentication
- Create dedicated API user in Wazuh Dashboard
- Use API credentials (not dashboard credentials) in `.env`
- Ensure user has proper backend roles assigned

#### 2. Claude Desktop Connection Issues
**Problem**: Server not appearing in Claude Desktop

**Solutions**:
- Ensure configuration file path is absolute and correct
- Restart Claude Desktop after adding server
- Check Claude Desktop logs for specific errors
- Verify config file location:
  - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
  - **Linux**: `~/.config/Claude/claude_desktop_config.json`
  - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

#### 3. SSL Certificate Issues
**For production with proper SSL:**
```env
VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=true
```

**For development/testing only:**
```env
VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true
```

#### 4. Platform-Specific Issues

**macOS/Linux**: Use the wrapper script for better environment handling
```bash
chmod +x scripts/mcp_wrapper.sh
```

**Windows**: Ensure Python is in PATH and use full paths in configuration

### Getting Help
- Check [Troubleshooting Documentation](docs/troubleshooting/)
- Review [Setup Guide](docs/user-guides/claude-desktop-setup.md)
- Report issues on [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)

---

## 📊 Version Comparison

| Feature | v1.0.1 (Stable) | Main Branch (Advanced) | v3-check (WIP) |
|---------|------------------|-------------------------|-----------------|
| **Status** | ✅ Most Stable | 🧪 Advanced Testing | 🔬 Work in Progress |
| **Tools** | 11 core tools | 26 tools (109% more) | 26 tools + remote |
| **Transport** | stdio (local) | stdio (local) | HTTP/HTTPS + SSE (remote) |
| **Deployment** | Python install | Python install | Docker containers |
| **Setup** | `install.py` | `scripts/install.py` | `docker compose up` |
| **Dependencies** | Host Python | Host Python | All containerized |
| **Authentication** | Basic | Basic | OAuth2 + JWT |
| **Monitoring** | Basic logging | Basic logging | Prometheus + Grafana |
| **Best For** | Production use | Power users | Early adopters |
| **Stability** | Highest | Medium | Experimental |

---

## 📚 Documentation

### User Guides
- **[Claude Desktop Setup Guide](docs/user-guides/claude-desktop-setup.md)** - Complete installation and configuration
- **[Configuration Guide](docs/configuration/README.md)** - Environment and performance tuning
- **[Troubleshooting Guide](docs/troubleshooting/README.md)** - Platform-specific solutions

### Technical Documentation
- **[API Reference](docs/api/README.md)** - Complete tool and function reference
- **[Development Guide](docs/development/README.md)** - Contributing and extending
- **[Examples](examples/)** - Configuration examples and usage patterns

### Version Information
- **[Version Comparison](docs/ARCHITECTURE_COMPARISON.md)** - Detailed v2 vs v3 comparison
- **[Migration Planning](docs/MIGRATION_GUIDE.md)** - Future v3 upgrade path
- **[v3 Preview](https://github.com/gensecaihq/Wazuh-MCP-Server/tree/v3-check)** - Explore upcoming features

---

## 🤝 Support & Community

- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)
- **Documentation**: [Complete docs](docs/)
- **Security**: [Security Policy](SECURITY.md)

### Special Thanks
**[@marcolinux46](https://github.com/marcolinux46)** - Extensive testing, feedback, and edge-case reporting

---

## 📊 Project Status

- **Stable Release**: v1.0.1 (Most Stable - Recommended for Production)
- **Advanced Branch**: main (Advanced Tools - For Power Users)
- **Future Branch**: v3-check (Work in Progress - For Early Adopters)
- **Maintenance**: Active development and support
- **Compatibility**: Python 3.9+ | Wazuh 4.8+ | Claude Desktop
- **Platforms**: Windows, macOS, Linux
- **License**: MIT License

## 🎯 Which Version Should You Choose?

### ✅ **Choose v1.0.1 if you want:**
✅ **Maximum Stability**: Thoroughly tested and stable  
✅ **Production Ready**: Proven in production environments  
✅ **11 Core Tools**: Essential security monitoring capabilities  
✅ **Rock Solid**: No experimental features, just reliable functionality  

### 🧪 **Choose Main Branch if you want:**
🧪 **Advanced Tools**: 26 security tools (109% more than v1.0.1)  
🧪 **Latest Features**: Enhanced AI analysis and advanced capabilities  
🧪 **Power User Features**: More sophisticated security operations  
🧪 **Testing Environment**: Willing to help test advanced features  

### 🔬 **Choose v3-check if you dare:**
🔬 **Cutting Edge**: Remote MCP server with HTTP/SSE transport  
🔬 **Docker Native**: Complete containerization with monitoring  
🔬 **OAuth2 Security**: Enterprise-grade authentication  
🔬 **Early Adopter**: Want to test future capabilities  

**Production Recommendation**: Use **v1.0.1** for production, **main branch** for advanced testing, **v3-check** for future exploration.