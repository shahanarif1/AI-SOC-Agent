# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Wazuh Compatible](https://img.shields.io/badge/Wazuh-4.8%2B-orange.svg)](https://wazuh.com/)

A Model Context Protocol (MCP) server that connects Wazuh SIEM with Claude Desktop for AI-powered security operations.

## What it does

- **Security Monitoring**: Query Wazuh alerts, agents, and vulnerabilities through Claude
- **AI Analysis**: Get AI-powered security insights, threat analysis, and compliance reports
- **Natural Language**: Ask questions like "Show me critical alerts from the last hour" or "Analyze this security incident"

## Quick Setup

### 1. Install

```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
python3 install.py
```

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
      "command": "/full/path/to/Wazuh-MCP-Server/mcp_wrapper.sh",
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

For detailed setup instructions, see [Claude Desktop Setup Guide](docs/claude-desktop-setup.md).

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
python validate_setup.py

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
   chmod +x /path/to/Wazuh-MCP-Server/mcp_wrapper.sh
   ```

2. **Test the wrapper**:
   ```bash
   ./mcp_wrapper.sh --stdio
   ```

3. **Use wrapper in Claude Desktop config**:
   ```json
   {
     "mcpServers": {
       "wazuh": {
         "command": "/full/path/to/Wazuh-MCP-Server/mcp_wrapper.sh",
         "args": ["--stdio"]
       }
     }
   }
   ```

**Why this is recommended**: The wrapper script handles environment setup, working directories, and temporary file creation across Unix-like systems (macOS/Linux). See [Unix Troubleshooting Guide](docs/unix-troubleshooting.md) for detailed information.

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
- Execute permissions for wrapper script (`chmod +x mcp_wrapper.sh`)

### Windows
- Windows Terminal or PowerShell (recommended)
- Visual Studio Build Tools (for some dependencies)
- Python properly installed and in PATH

## Documentation

- [Claude Desktop Setup Guide](docs/claude-desktop-setup.md) - Complete setup instructions
- [Unix Troubleshooting Guide](docs/unix-troubleshooting.md) - macOS/Linux troubleshooting  
- [Windows Troubleshooting Guide](docs/windows-troubleshooting.md) - Windows-specific issues
- [Wrapper Script Documentation](WRAPPER_SCRIPT_DOCUMENTATION.md) - Technical details

## Support

- [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- [Documentation](docs/)

## License

MIT License - see [LICENSE](LICENSE) file.