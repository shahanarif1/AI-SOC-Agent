# Local Setup Guide - Wazuh MCP Server

This guide provides step-by-step instructions for setting up the Wazuh MCP Server locally with Claude Desktop.

## Prerequisites

### System Requirements
- **Python**: 3.9 or higher with pip
- **Operating System**: Windows 10+, macOS 10.15+, or Linux (Ubuntu 20.04+)
- **Memory**: Minimum 2GB RAM available
- **Network**: Access to your Wazuh deployment

### Wazuh Requirements
- **Wazuh Manager**: Version 4.8+ with API enabled
- **Wazuh Indexer**: OpenSearch/Elasticsearch for advanced features
- **API Credentials**: Valid username and password for Wazuh API
- **Network Access**: HTTPS connectivity to Wazuh services

## Installation Steps

### 1. Clone the Repository
```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
```

### 2. Run Setup Script
The setup script will create a virtual environment and install all dependencies:

```bash
python3 install.py
```

This will:
- Check Python version compatibility
- Create a virtual environment (`venv/`)
- Install all required dependencies
- Create configuration files
- Set up logging directories

### 3. Configure Environment
Edit the `.env` file with your Wazuh deployment details:

```bash
# Edit with your preferred editor
nano .env
# or
code .env
```

Required configuration:
```env
# Wazuh Manager
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=your-username
WAZUH_PASS=your-password

# Wazuh Indexer
WAZUH_INDEXER_HOST=your-indexer-host.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=your-indexer-username
WAZUH_INDEXER_PASS=your-indexer-password

# Security (adjust for your environment)
VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true
```

### 4. Test Connection
Verify your Wazuh connection:

```bash
source venv/bin/activate
python src/wazuh_mcp_server/main.py --stdio
```

You should see initialization logs without authentication errors.

## Claude Desktop Integration

### 1. Locate Claude Desktop Configuration
Find your Claude Desktop settings file:

- **macOS**: `~/Library/Application Support/Claude/settings.json`
- **Windows**: `%APPDATA%\Claude\settings.json`
- **Linux**: `~/.config/Claude/settings.json`

### 2. Add MCP Server Configuration
Add the Wazuh MCP server to your settings:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["/absolute/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Important**: Use the absolute path to your installation directory.

### 3. Restart Claude Desktop
Close and restart Claude Desktop to load the new MCP server.

## Verification and Testing

### 1. Check Claude Desktop Connection
In Claude Desktop, you should see the Wazuh MCP server listed in available tools or you can ask Claude:

"What security tools do you have access to?"

### 2. Test Basic Functionality
Try these example queries in Claude Desktop:

- "Show me the status of my Wazuh agents"
- "What security alerts do I have today?"
- "Generate a compliance report for PCI DSS"

### 3. Monitor Logs
Check the application logs for any issues:

```bash
tail -f logs/wazuh-mcp.log
```

## Troubleshooting

### Connection Issues
1. **Authentication Failures**:
   - Verify username/password in `.env`
   - Check if user has API permissions in Wazuh
   - Ensure API is enabled on Wazuh Manager

2. **SSL Certificate Issues**:
   - Set `VERIFY_SSL=false` for self-signed certificates
   - Set `WAZUH_ALLOW_SELF_SIGNED=true`
   - For production, use proper CA certificates

3. **Network Connectivity**:
   - Verify firewall settings
   - Test manual connection: `curl -k https://your-wazuh-host:55000`
   - Check DNS resolution

### Claude Desktop Issues
1. **MCP Server Not Loading**:
   - Check settings.json syntax
   - Verify absolute path to main.py
   - Restart Claude Desktop
   - Check Claude Desktop logs

2. **Permission Errors**:
   - Ensure virtual environment is activated
   - Check file permissions on `.env` (should be 600)
   - Verify Python executable path

### Performance Issues
1. **Slow Response Times**:
   - Increase timeouts in `.env`:
     ```env
     WAZUH_REQUEST_TIMEOUT=60
     WAZUH_SSL_TIMEOUT=30
     ```
   - Check network latency to Wazuh server

2. **Memory Usage**:
   - Monitor with: `ps aux | grep python`
   - Reduce concurrent connections:
     ```env
     WAZUH_MAX_CONNECTIONS=5
     ```

## Advanced Configuration

### SSL/TLS Security
For production environments:

```env
VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=false
WAZUH_CA_BUNDLE_PATH=/path/to/ca-bundle.pem
```

### Custom Logging
Adjust logging levels:

```env
LOG_LEVEL=DEBUG  # For troubleshooting
LOG_LEVEL=INFO   # For normal operation
LOG_LEVEL=ERROR  # For minimal logging
```

### Performance Tuning
Optimize for your environment:

```env
WAZUH_MAX_CONNECTIONS=10
WAZUH_REQUEST_TIMEOUT=30
WAZUH_RATE_LIMIT=10
```

## Security Best Practices

1. **Credential Management**:
   - Use dedicated service accounts
   - Rotate credentials regularly
   - Set minimal required permissions

2. **File Permissions**:
   ```bash
   chmod 600 .env
   chmod 755 logs/
   ```

3. **Network Security**:
   - Use VPN for remote connections
   - Enable firewall rules
   - Monitor access logs

## Support

If you encounter issues:

1. Check the [troubleshooting section](#troubleshooting)
2. Review logs in `logs/` directory
3. Search [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
4. Create a new issue with:
   - Operating system and Python version
   - Wazuh version and deployment type
   - Error messages and logs
   - Steps to reproduce

## Next Steps

Once successfully set up:

- Explore available security operations in Claude Desktop
- Review [API Reference](API_REFERENCE.md) for advanced usage
- Configure compliance frameworks in [Configuration Reference](CONFIGURATION_REFERENCE.md)
- Set up monitoring and alerting workflows