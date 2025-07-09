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

Edit `.env` with your Wazuh details:

```env
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-username
WAZUH_PASS=your-password
```

### 3. Add to Claude Desktop

Add this to your Claude Desktop settings (`~/.config/Claude/settings.json`):

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["/full/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py"],
      "env": {}
    }
  }
}
```

Replace `/full/path/to/Wazuh-MCP-Server` with your actual installation path.

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

### Claude Desktop Issues
- Ensure the path in settings.json is absolute and correct
- Restart Claude Desktop after adding the server
- Check Claude Desktop logs for errors

### SSL Issues
```env
# For development with self-signed certificates
VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true
```

## Requirements

- Python 3.9+
- Wazuh Manager 4.8+
- Claude Desktop
- Network access to Wazuh API (port 55000)

## Support

- [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- [Documentation](docs/)

## License

MIT License - see [LICENSE](LICENSE) file.