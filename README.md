# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Wazuh Compatible](https://img.shields.io/badge/Wazuh-4.8%2B-orange.svg)](https://wazuh.com/)

A Model Context Protocol (MCP) server that connects Wazuh SIEM with Claude Desktop for AI-powered security operations.

## What it does

- **Security Monitoring**: Query Wazuh alerts, agents, and vulnerabilities through Claude
- **AI Analysis**: Get AI-powered security insights, threat analysis, and compliance reports
- **Natural Language**: Ask questions like "Show me critical alerts from the last hour" or "Analyze this security incident"

<img width="797" height="568" alt="claude0mcp-wazuh" src="https://github.com/user-attachments/assets/458d3c94-e1f9-4143-a1a4-85cb629287d4" />

## ✨ What's Coming in v2.0.0 (Future Release)

🎯 **Enhanced Capabilities**: 23 powerful tools (109% increase from v1.0.1)  
🧠 **Phase 5 Prompt Enhancement System**: Advanced context aggregation and adaptive responses  
🔧 **Production-Ready**: Robust error handling, memory management, and cross-platform support  
🏗️ **Modular Architecture**: Clean, maintainable codebase with standardized patterns  
🚀 **Migration Support**: Seamless upgrade from v1.0.1 with automated migration tools  

## 🏷️ Version Information

### **Current Main Branch: v2.0.0-dev** (This Branch)
- **Status**: 🚧 **Active Development** - Main branch with latest features under development
- **Tools**: 23 powerful security tools with advanced capabilities  
- **Best For**: Developers and early adopters who want to test upcoming features
- **Stability**: Under active development - use for testing purposes only

### **Stable Release: v1.0.1** 
- **Status**: ✅ **Production Stable** - [GitHub Release](https://github.com/gensecaihq/Wazuh-MCP-Server/releases/tag/v1.0.1)
- **Tools**: 11 core security tools covering essential operations
- **Best For**: Production environments requiring maximum stability
- **Download**: Go to [Releases](https://github.com/gensecaihq/Wazuh-MCP-Server/releases) and download v1.0.1
- **Documentation**: [v1.0.1 README](https://github.com/gensecaihq/Wazuh-MCP-Server/blob/v1.0.1/README.md)

> **💡 Recommendation**: Use **v1.0.1 release** for all production systems. The **main branch (v2.0.0-dev)** is for testing and development only - it will be released after thorough testing and validation.

<h2>🙏 Special Thanks</h2>
<p>Big shout-out to <strong><a href="https://github.com/marcolinux46">@marcolinux46</a></strong> for tireless testing, detailed feedback, and reporting edge-case Wazuh issues round the clock.</p>

## Quick Setup

> **Choose Your Version First**: See [Version Information](#️-version-information) above to choose between v1.0.1(production stable)
### 1. Install


**For v1.0.1 (Production Stable):**
1. Go to [Releases](https://github.com/gensecaihq/Wazuh-MCP-Server/releases)
2. Download v1.0.1 source code (zip/tar.gz)
3. Extract and install:
```bash
cd Wazuh-MCP-Server-1.0.1
python3 install.py
```

**Alternative - Clone v1.0.1 tag:**
```bash
git clone -b v1.0.1 https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
python3 install.py
```

> **📁 Note**: v1.0.1 uses `install.py` in the root directory, while main branch (v2.0.0-dev) uses `scripts/install.py` due to improved organization.  
> **⚠️ Important**: Main branch is under active development. Use v1.0.1 release for production systems.

### 2. Configure

**Important**: Create a dedicated API user in Wazuh Dashboard first:

1. Login to Wazuh Dashboard (https://your-wazuh-server:443)
2. Go to ** Server Management ** **Security** → **Users**
3. Click **Create user**
4. Username: `wazuh-mcp-api` (or your preferred name)
5. Password: Generate a strong password
6. Backend roles: `Select Appropriate one`

Then edit `.env` with your Wazuh details:

```env
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=wazuh-mcp-api
WAZUH_PASS=your-api-password
```

### 3. Add to Claude Desktop

First, create the configuration file in Claude Desktop:

1. Open Claude Desktop
2. Go to **Settings** → **Developer**
3. Click **Edit Config** to create/open `claude_desktop_config.json`

The configuration file location:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

Add the appropriate configuration for your platform:

### macOS/Linux Configuration

**Recommended**: Use the wrapper script for better environment handling and compatibility.

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

### Windows Configuration

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

**Using Virtual Environment** (recommended for Windows):
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "C:/full/path/to/Wazuh-MCP-Server/venv/Scripts/python.exe",
      "args": ["C:/full/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"]
    }
  }
}
```

Replace `/full/path/to/Wazuh-MCP-Server` with your actual installation path.

**Note**: The configuration file is not created automatically. You must use Claude Desktop's Developer settings to create it.

For detailed setup instructions, see [Claude Desktop Setup Guide](docs/user-guides/claude-desktop-setup.md).

**Note**: Unix systems (macOS/Linux) use the wrapper script for optimal compatibility, while Windows uses direct Python execution.

### 4. Test

Restart Claude Desktop and try asking:
- "Show me recent security alerts"
- "What's the status of my Wazuh agents?"
- "Analyze security threats in the last 24 hours"

## Configuration Options

Key environment variables in `.env`:

```env
# Required
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-username
WAZUH_PASS=your-password

# Optional
WAZUH_PORT=55000
WAZUH_INDEXER_HOST=your-indexer.com
WAZUH_INDEXER_PORT=9200
VERIFY_SSL=true
DEBUG=false
```

## Features

### Security Tools
- **get_alerts**: Retrieve and filter Wazuh alerts
- **analyze_threats**: AI-powered threat analysis
- **check_agent_health**: Monitor agent status
- **compliance_check**: Compliance assessments (PCI DSS, GDPR, HIPAA, etc.)
- **risk_assessment**: Comprehensive security risk analysis
- **vulnerability_prioritization**: Risk-based vulnerability management

### AI Prompts
- **Security Incident Analysis**: Structured incident investigation
- **Threat Hunting**: Proactive threat detection strategies
- **Compliance Assessment**: Framework-specific compliance analysis
- **Forensic Analysis**: Digital forensics investigation
- **Security Reporting**: Executive and technical security reports

### Real-time Features
- **Critical Alert Notifications**: Immediate alerts for high-severity events
- **Progress Tracking**: Real-time progress for long-running operations
- **Agent Status Updates**: Live agent health monitoring

## Troubleshooting

### Connection Issues
```bash
# Test your setup
python scripts/validate_setup.py

# Check Wazuh connectivity
curl -u username:password https://your-wazuh:55000/
```

### Authentication Issues

**Problem**: "Invalid credentials" error despite correct dashboard login

**Solution**: Wazuh Dashboard and API use separate authentication systems.

1. **Create API User**:
   - Login to Wazuh Dashboard
   - Go to **Security** → **Internal users**
   - Create a new user with `wazuh` backend role
   - Use these credentials in your `.env` file

2. **Test API Authentication**:
   ```bash
   curl -k -X POST "https://your-wazuh:55000/security/user/authenticate" \
     -H "Content-Type: application/json" \
     -d '{"username":"your-api-user","password":"your-api-password"}'
   ```

3. **Common Issues**:
   - Dashboard credentials ≠ API credentials
   - Default admin account may be disabled for API
   - User must have proper backend roles assigned

### Claude Desktop Issues
- Ensure the path in claude_desktop_config.json is absolute and correct
- The config file must be created through Claude Desktop Settings → Developer → Edit Config
- Restart Claude Desktop after adding the server
- Check Claude Desktop logs for errors
- Verify the config file location:
  - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
  - Linux: `~/.config/Claude/claude_desktop_config.json`
  - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

### macOS/Linux Issues

**Problem**: "Read-only file system" errors or environment issues

**Solution**: Use the wrapper script instead of direct Python execution:

1. **Ensure wrapper script is executable**:
   ```bash
   chmod +x /path/to/Wazuh-MCP-Server/scripts/mcp_wrapper.sh
   ```

2. **Test the wrapper**:
   ```bash
   ./scripts/mcp_wrapper.sh --stdio
   ```

3. **Use wrapper in Claude Desktop config**:
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

**Why this is recommended**: The wrapper script handles environment setup, working directories, and temporary file creation across Unix-like systems (macOS/Linux). See [Unix Troubleshooting Guide](docs/troubleshooting/unix-troubleshooting.md) for detailed information.

### SSL Issues

**For production: Only If you have a proper SSL installed** (recommended):
```env
# Use proper SSL verification with self-signed certificate support
VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=true
```

**For development only**:
```env
# Disable SSL verification completely (not recommended for production)
VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true
```

> **Security Note**: `VERIFY_SSL=true` with `WAZUH_ALLOW_SELF_SIGNED=true` provides the best balance of security and compatibility.

## Platform-Specific Requirements

### All Platforms
- Python 3.9+
- Wazuh Manager 4.8+
- Claude Desktop
- Network access to Wazuh API (port 55000)
- Dedicated Wazuh API user (not dashboard credentials)

### macOS/Linux
- Bash shell (for wrapper script)
- Write permissions for temporary directories
- Standard development tools (gcc, make) for some dependencies
- Execute permissions for wrapper script (`chmod +x scripts/mcp_wrapper.sh`)

### Windows
- Windows Terminal or PowerShell (recommended)
- Visual Studio Build Tools (for some dependencies)
- Python properly installed and in PATH

## Documentation

### 📚 User Guides
- [Claude Desktop Setup Guide](docs/user-guides/claude-desktop-setup.md) - Complete setup instructions
- [Unix Troubleshooting Guide](docs/troubleshooting/unix-troubleshooting.md) - macOS/Linux troubleshooting  
- [Windows Troubleshooting Guide](docs/troubleshooting/windows-troubleshooting.md) - Windows-specific issues

### 🔧 Technical Documentation
- [Production Readiness Audit](docs/technical/PRODUCTION_READINESS_AUDIT.md) - Development readiness assessment
- [Comprehensive Audit Report](docs/technical/COMPREHENSIVE_AUDIT_REPORT.md) - Complete implementation overview
- [Phase 5 Enhancement System](docs/technical/PHASE_5_PROMPT_ENHANCEMENT_DETAILED_PLAN.md) - Advanced features
- [Wrapper Script Documentation](docs/technical/WRAPPER_SCRIPT_DOCUMENTATION.md) - Technical details

### 💻 Development
- [Contributing Guidelines](docs/development/CONTRIBUTING.md) - How to contribute
- [Configuration Examples](examples/configuration_examples/) - Environment configurations
- [Usage Examples](examples/basic_usage.py) - Code examples and queries

### 🚀 Release Information
- [Migration Guide](docs/MIGRATION_GUIDE.md) - Future upgrade path from v1.0.1 to v2.0.0 (when released)
- [What's Coming](docs/releases/UPCOMING.md) - Planned v2.0.0 features and enhancements

## Support

- [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- [Documentation](docs/)

## License

MIT License - see [LICENSE](LICENSE) file.
