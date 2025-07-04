# Local Setup Guide - Wazuh MCP Server

This comprehensive guide walks you through setting up the Wazuh MCP Server for local use with Claude Desktop and other MCP-compatible AI assistants.

## Prerequisites

### System Requirements

- **Python**: 3.9 or higher with pip
- **Operating System**: Windows 10+, macOS 10.15+, or Linux (Ubuntu 20.04+)
- **Memory**: 512MB+ available RAM
- **Network**: Internet access for package installation

### Wazuh Infrastructure

- **Wazuh Server**: Version 4.5.0 or higher
- **Network Access**: Connectivity to Wazuh API (default port 55000)
- **Credentials**: Valid Wazuh API user account
- **SSL**: Valid SSL certificate (recommended) or self-signed (development only)

### AI Assistant

- **Claude Desktop**: Latest version
- **Alternative MCP Clients**: Any MCP-compatible AI assistant

## 🚀 Quick Start

### 1. Install the Package

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Install dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

### 2. Configure Environment

Create a `.env` file in the project root:

```bash
# Copy the example file
cp .env.example .env

# Edit with your Wazuh configuration
nano .env
```

Minimum required configuration:
```env
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=your-username
WAZUH_PASS=your-password
VERIFY_SSL=false
```

### 3. Test the Connection

```bash
# Test the connection to your Wazuh server
python wazuh_mcp_server.py --stdio
```

## 🖥️ Claude Desktop Integration

### Configuration

Add the following to your Claude Desktop configuration file:

**Location of config file:**
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

**Configuration:**
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
        "VERIFY_SSL": "false",
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Alternative: Using Installed Package

If you installed the package system-wide:

```json
{
  "mcpServers": {
    "wazuh-security": {
      "command": "wazuh-mcp-server",
      "args": ["--stdio"],
      "env": {
        "WAZUH_HOST": "your-wazuh-server.com",
        "WAZUH_PORT": "55000",
        "WAZUH_USER": "your-username",
        "WAZUH_PASS": "your-password",
        "VERIFY_SSL": "false"
      }
    }
  }
}
```

## 🔧 Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `WAZUH_HOST` | Wazuh server hostname/IP | `wazuh.company.com` |
| `WAZUH_USER` | Wazuh API username | `wazuh-user` |
| `WAZUH_PASS` | Wazuh API password | `secure-password` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_PORT` | `55000` | Wazuh API port |
| `VERIFY_SSL` | `false` | Enable SSL verification |
| `LOG_LEVEL` | `INFO` | Logging level |
| `DEBUG` | `false` | Enable debug mode |

### Wazuh Indexer (4.8.0+)

For Wazuh 4.8.0+ with Indexer:

```env
WAZUH_INDEXER_HOST=your-indexer.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=indexer-password
USE_INDEXER_FOR_ALERTS=true
USE_INDEXER_FOR_VULNERABILITIES=true
```

### External Integrations

```env
# Optional threat intelligence APIs
VIRUSTOTAL_API_KEY=your-vt-key
SHODAN_API_KEY=your-shodan-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
```

## 🧪 Testing

### Manual Testing

```bash
# Test stdio mode (for Claude Desktop)
python wazuh_mcp_server.py --stdio

# The server will show initialization logs in stderr
# and wait for MCP protocol messages on stdin
```

### Connection Test Script

```bash
# Use the built-in test script
python -m wazuh_mcp_server.scripts.test_connection

# Or use the standalone script
python src/wazuh_mcp_server/scripts/test_connection.py
```

## 🔍 Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure package is installed
   pip install -e .
   
   # Check Python path
   python -c "import wazuh_mcp_server; print('OK')"
   ```

2. **Wazuh Connection Failed**
   ```bash
   # Test manually
   curl -k -u username:password https://wazuh-host:55000/
   
   # Check firewall/network
   telnet wazuh-host 55000
   ```

3. **SSL Issues**
   ```env
   # Disable SSL verification (development only)
   VERIFY_SSL=false
   
   # Or provide custom CA bundle
   CA_BUNDLE_PATH=/path/to/ca-bundle.pem
   ```

4. **Claude Desktop Not Finding Server**
   - Use absolute paths in configuration
   - Check that Python is in PATH
   - Verify environment variables are set
   - Check Claude Desktop logs

### Debug Mode

Enable detailed logging:

```json
{
  "mcpServers": {
    "wazuh-security": {
      "command": "python",
      "args": ["/path/to/wazuh_mcp_server.py", "--stdio"],
      "env": {
        "DEBUG": "true",
        "LOG_LEVEL": "DEBUG",
        // ... other config
      }
    }
  }
}
```

## 🎯 Available Tools

Once configured, Claude Desktop will have access to these tools:

- **get_alerts** - Retrieve security alerts with filtering
- **get_agents** - Get Wazuh agent information
- **analyze_threats** - Perform threat analysis
- **get_vulnerabilities** - Get vulnerability data
- **security_overview** - Comprehensive security dashboard
- **get_agent_processes** - List agent processes
- **get_agent_ports** - Show open ports
- **search_wazuh_logs** - Search log data
- **get_cluster_health** - Cluster status information

## 📝 Usage Examples

Ask Claude Desktop:

- "Show me the latest security alerts from Wazuh"
- "What agents are currently offline?"
- "Analyze the threat landscape for the last hour"
- "Show me all critical vulnerabilities"
- "What processes are running on agent 001?"

## 🔄 Updates

To update the MCP server:

```bash
# Pull latest changes
git pull origin main

# Reinstall package
pip install -e .

# Restart Claude Desktop to reload the MCP server
```