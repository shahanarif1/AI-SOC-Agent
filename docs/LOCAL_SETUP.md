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

## Post-Installation Configuration

### 3. Configure Wazuh Connection

#### 3.1 Edit Configuration File
```bash
# Edit with your preferred editor
nano .env
# or
code .env
```

#### 3.2 Update Required Fields
Replace placeholder values with your actual Wazuh deployment details:

```env
# =============================================================================
# WAZUH MANAGER CONFIGURATION (REQUIRED)
# =============================================================================
WAZUH_HOST=192.168.1.100           # Your Wazuh server IP or hostname
WAZUH_PORT=55000                   # Default Wazuh API port
WAZUH_USER=api_user                # Valid Wazuh API username
WAZUH_PASS=secure_password123      # Valid Wazuh API password

# =============================================================================
# WAZUH INDEXER CONFIGURATION (OPTIONAL - for advanced features)
# =============================================================================
WAZUH_INDEXER_HOST=192.168.1.100   # Your Indexer IP (usually same as Manager)
WAZUH_INDEXER_PORT=9200            # Default OpenSearch/Elasticsearch port
WAZUH_INDEXER_USER=admin           # Indexer username
WAZUH_INDEXER_PASS=indexer_pass    # Indexer password

# =============================================================================
# SECURITY SETTINGS
# =============================================================================
VERIFY_SSL=false                   # Set to true if you have valid SSL certificates
WAZUH_ALLOW_SELF_SIGNED=true       # Allow self-signed certificates
WAZUH_API_VERSION=v4              # Wazuh API version

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================
LOG_LEVEL=INFO                     # DEBUG, INFO, WARNING, ERROR
```

#### 3.3 Security Considerations
- **Production environments**: Set `VERIFY_SSL=true` if you have valid SSL certificates
- **Self-signed certificates**: Keep `VERIFY_SSL=false` and `WAZUH_ALLOW_SELF_SIGNED=true`
- **Credentials security**: Ensure `.env` file has 600 permissions (read/write for owner only)

### 4. Test and Validate Connection

#### 4.1 Activate Virtual Environment
```bash
source venv/bin/activate
```

#### 4.2 Test Basic Connection
```bash
python src/wazuh_mcp_server/main.py --stdio
```
You should see initialization logs without authentication errors.

#### 4.3 Run Connection Validator
```bash
python src/wazuh_mcp_server/scripts/connection_validator.py
```
This will test both Manager and Indexer connections and provide recommendations.

#### 4.4 Comprehensive Setup Validation
```bash
python validate_setup.py
```
This validates the entire installation and configuration.

## Claude Desktop Integration

### 5. Configure Claude Desktop

#### 5.1 Locate Claude Desktop Configuration File
Find your Claude Desktop settings file based on your operating system:

- **Linux**: `~/.config/Claude/settings.json`
- **macOS**: `~/Library/Application Support/Claude/settings.json`
- **Windows**: `%APPDATA%\Claude\settings.json`

#### 5.2 Get Your Project Path
First, get the absolute path to your project:
```bash
pwd
# Copy this path - you'll need it for the configuration
```

#### 5.3 Add MCP Server Configuration
Edit the Claude Desktop settings file and add the Wazuh MCP server:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["/full/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Critical**: Replace `/full/path/to/Wazuh-MCP-Server` with your actual project directory path from step 5.2.

#### 5.4 Restart Claude Desktop
1. Close Claude Desktop completely
2. Restart the Claude Desktop application
3. Wait for the application to fully load

### 6. Test Integration

#### 6.1 Verify MCP Server Connection
Open Claude Desktop and look for:
- No error messages about MCP server connection
- The Wazuh tools should be available to Claude

#### 6.2 Test Basic Functionality
Try these example queries in Claude Desktop:

**Security Monitoring:**
- "Show me the latest security alerts from Wazuh"
- "What agents are currently active?"
- "Check for any high-severity events in the last 24 hours"

**Agent Management:**
- "List all Wazuh agents and their status"
- "Show me agents that are disconnected"
- "Get agent configuration for agent ID 001"

**Security Analysis:**
- "Analyze recent failed login attempts"
- "Look for any suspicious network activity"
- "Generate a security summary for today"

#### 6.3 Monitor Logs
Keep an eye on the logs for any issues:
```bash
tail -f logs/wazuh-mcp.log
```
## Verification and Final Testing

### 7. Comprehensive Verification

#### 7.1 Run Full Validation
```bash
python validate_setup.py
```
This should show all checks passing:
- ✅ System Information
- ✅ Virtual Environment  
- ✅ Dependencies
- ✅ Package Installation
- ✅ Configuration
- ✅ Logs Directory
- ✅ Connection Test

#### 7.2 Test Claude Desktop Integration
In Claude Desktop, verify the integration by asking:
- "What security tools do you have access to?"
- "Can you connect to my Wazuh server?"

#### 7.3 Test Core Functionality
Try these example queries in Claude Desktop:

**Basic Queries:**
- "Show me the status of my Wazuh agents"
- "What security alerts do I have from the last hour?"
- "List all active agents and their operating systems"

**Advanced Queries:**
- "Analyze failed authentication attempts from the last 24 hours"
- "Generate a compliance report for PCI DSS requirements"
- "Show me any agents that haven't checked in recently"

#### 7.4 Monitor System Health
Keep logs open to monitor for any issues:
```bash
# In one terminal, monitor MCP server logs
tail -f logs/wazuh-mcp.log

# In another terminal, check for any errors
tail -f logs/errors.log
```

## Troubleshooting Common Issues

### 🔧 Connection Problems

#### Authentication Failures (HTTP 401)
**Symptoms:** Connection validator shows "Authentication failed: HTTP 401"

**Solutions:**
1. Verify Wazuh credentials in `.env`:
   ```bash
   # Check your .env file
   grep -E "WAZUH_(USER|PASS)" .env
   ```
2. Test credentials directly on Wazuh server:
   ```bash
   curl -k -u "username:password" https://your-wazuh-server:55000/
   ```
3. Ensure the user has API access permissions in Wazuh

#### SSL Certificate Issues
**Symptoms:** "SSL certificate verification failed"

**Solutions:**
1. For self-signed certificates, ensure in `.env`:
   ```env
   VERIFY_SSL=false
   WAZUH_ALLOW_SELF_SIGNED=true
   ```
2. For production with valid certificates:
   ```env
   VERIFY_SSL=true
   WAZUH_ALLOW_SELF_SIGNED=false
   ```

#### Network Connectivity Issues
**Symptoms:** "Connection timed out" or "Host unreachable"

**Solutions:**
1. Test basic connectivity:
   ```bash
   ping your-wazuh-server
   telnet your-wazuh-server 55000
   ```
2. Check firewall rules on both client and server
3. Verify Wazuh API is enabled and running

### 🔧 Claude Desktop Integration Issues

#### MCP Server Not Loading
**Symptoms:** Claude doesn't recognize Wazuh tools

**Solutions:**
1. Check Claude Desktop settings path is correct
2. Verify JSON syntax in settings.json:
   ```bash
   python -m json.tool ~/.config/Claude/settings.json
   ```
3. Ensure absolute path is used in configuration
4. Restart Claude Desktop completely

#### Python Path Issues
**Symptoms:** "Python command not found" in Claude Desktop

**Solutions:**
1. Use full Python path in settings.json:
   ```json
   "command": "/usr/bin/python3"
   ```
2. Or use the virtual environment Python:
   ```json
   "command": "/full/path/to/project/venv/bin/python"
   ```

### 🔧 Performance Issues

#### Slow Response Times
**Solutions:**
1. Check network latency to Wazuh server
2. Reduce query result limits in requests
3. Monitor system resources (CPU, memory)

#### High Memory Usage
**Solutions:**
1. Adjust log levels to reduce verbosity:
   ```env
   LOG_LEVEL=WARNING
   ```
2. Monitor and rotate log files regularly

### 🔧 Advanced Troubleshooting

#### Debug Mode
Enable debug logging for detailed troubleshooting:
```env
LOG_LEVEL=DEBUG
```

#### Manual Testing
Test MCP server directly:
```bash
# Activate virtual environment
source venv/bin/activate

# Run server in debug mode
python src/wazuh_mcp_server/main.py --stdio --debug
```

#### Check Dependencies
Verify all required packages are installed:
```bash
venv/bin/pip list | grep -E "(mcp|aiohttp|pydantic|python-dotenv)"
```

### 📞 Getting Help

If issues persist:

1. **Check Documentation:**
   - `docs/API_REFERENCE.md` - Available tools and methods
   - `docs/CONFIGURATION_REFERENCE.md` - Configuration options

2. **Run Diagnostics:**
   ```bash
   python validate_setup.py > diagnostic_report.txt
   ```

3. **Collect Logs:**
   ```bash
   tar -czf wazuh-mcp-logs.tar.gz logs/
   ```

4. **GitHub Issues:**
   - Create an issue at: https://github.com/gensecaihq/Wazuh-MCP-Server/issues
   - Include diagnostic report and logs
   - Describe your environment and steps taken

## 🎉 Success Indicators

Your setup is successful when:
- ✅ `validate_setup.py` shows all checks passing
- ✅ Connection validator shows successful authentication
- ✅ Claude Desktop recognizes Wazuh tools
- ✅ You can query security alerts and agent status
- ✅ Logs show no authentication or connection errors

**Congratulations!** You now have a fully functional Wazuh MCP Server integrated with Claude Desktop for natural language security operations.
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