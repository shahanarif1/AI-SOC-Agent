# Unix Systems Troubleshooting (macOS/Linux)

## Overview

This guide covers troubleshooting for Unix-like systems (macOS and Linux) using the wrapper script approach. Both platforms share similar setup and common issues.

## Common Issues and Solutions

### Wrapper Script Issues

#### Permission Denied

**Error**: `Permission denied` when running wrapper script

**Solution**:
```bash
chmod +x mcp_wrapper.sh
```

#### Script Not Found

**Error**: `./mcp_wrapper.sh: No such file or directory`

**Solution**: Verify you're in the correct directory and the script exists:
```bash
ls -la mcp_wrapper.sh
cd /path/to/Wazuh-MCP-Server
chmod +x mcp_wrapper.sh
```

### Environment Issues

#### Python Not Found

**Error**: `python3: command not found` in wrapper script

**Solution**:

**macOS**:
```bash
# Install via Homebrew
brew install python3

# Or install from python.org
# Download and install Python 3.9+ from https://python.org
```

**Linux**:
```bash
# Ubuntu/Debian
sudo apt install python3

# CentOS/RHEL
sudo yum install python3

# Fedora
sudo dnf install python3

# Arch Linux
sudo pacman -S python
```

#### Virtual Environment Issues

**Error**: Virtual environment not found or not activated

**Solution**: The wrapper script handles virtual environment activation automatically. If issues persist:

1. **Verify virtual environment exists**:
   ```bash
   ls -la venv/bin/python
   ```

2. **Recreate virtual environment**:
   ```bash
   rm -rf venv
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

### File System Issues

#### Read-Only File System (macOS)

**Error**: `[Errno 30] Read-only file system: 'logs'`

**Cause**: Claude Desktop on macOS runs MCP servers from read-only locations.

**Solution**: The wrapper script automatically creates temporary directories. Ensure you're using the wrapper script in Claude Desktop configuration.

#### Log Directory Issues

**Error**: Cannot create or write to log files

**Solution**: The wrapper script creates temporary log directories automatically:

1. **Check temporary directory creation**:
   ```bash
   # The wrapper creates: /tmp/wazuh-mcp-XXXXXX/logs/
   ls -la /tmp/wazuh-mcp-*/logs/
   ```

2. **Manual cleanup if needed**:
   ```bash
   rm -rf /tmp/wazuh-mcp-*
   ```

### Configuration Issues

#### Environment Variables Not Loading

**Error**: Configuration not found or environment variables missing

**Solution**: The wrapper script automatically loads `.env` file. Ensure:

1. **`.env` file exists**:
   ```bash
   ls -la .env
   # If missing, copy from example:
   cp .env.example .env
   ```

2. **Proper .env format**:
   ```env
   WAZUH_HOST=your-wazuh-server
   WAZUH_USER=wazuh-mcp-api
   WAZUH_PASS=your-password
   ```

3. **No quotes around values** (unless spaces are present)

#### Working Directory Issues

**Error**: Cannot find source files or modules

**Solution**: The wrapper script automatically sets the correct working directory:

1. **Verify installation path**:
   ```bash
   cd /path/to/Wazuh-MCP-Server
   ls -la src/wazuh_mcp_server/main.py
   ```

2. **Check wrapper script paths**:
   ```bash
   head -20 mcp_wrapper.sh
   ```

### Python Path Issues

#### Module Import Errors

**Error**: `ModuleNotFoundError` for wazuh_mcp_server modules

**Solution**: The wrapper script sets `PYTHONPATH` automatically. If issues persist:

1. **Test Python path manually**:
   ```bash
   export PYTHONPATH="$PWD/src:$PYTHONPATH"
   python3 -c "import wazuh_mcp_server; print('OK')"
   ```

2. **Verify src directory structure**:
   ```bash
   ls -la src/wazuh_mcp_server/
   ```

### Claude Desktop Issues

#### Server Not Appearing

**Error**: Wazuh server not showing in Claude Desktop

**Solution**:

1. **Verify configuration file location**:
   
   **macOS**:
   ```bash
   ls -la ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```
   
   **Linux**:
   ```bash
   ls -la ~/.config/Claude/claude_desktop_config.json
   ```

2. **Check JSON syntax**:
   ```bash
   python3 -m json.tool ~/.config/Claude/claude_desktop_config.json  # Linux
   python3 -m json.tool ~/Library/Application\ Support/Claude/claude_desktop_config.json  # macOS
   ```

3. **Correct configuration format**:
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

4. **Restart Claude Desktop** after configuration changes

### SSL Certificate Issues

#### SSL Verification Failed

**Error**: SSL certificate verification failed

**Solution**: Update `.env` file:

```env
# For self-signed certificates (recommended)
VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=true

# For development only (not recommended for production)
VERIFY_SSL=false
```

### Network Issues

#### Connection Timeout

**Error**: Connection timeout or network unreachable

**Solution**:

1. **Test network connectivity**:
   ```bash
   # Test basic connectivity
   ping your-wazuh-server
   
   # Test port connectivity
   nc -zv your-wazuh-server 55000
   ```

2. **Check firewall settings**:
   
   **macOS**:
   ```bash
   # Check firewall status
   sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
   ```
   
   **Linux**:
   ```bash
   # Check firewall status
   sudo ufw status
   
   # Allow outbound connections if needed
   sudo ufw allow out 55000/tcp
   sudo ufw allow out 9200/tcp
   sudo ufw allow out 443/tcp
   ```

## Testing and Validation

### Complete Test Procedure

1. **Test wrapper script**:
   ```bash
   ./mcp_wrapper.sh --stdio
   ```

2. **Test MCP communication**:
   ```bash
   echo '{"jsonrpc": "2.0", "method": "initialize", "id": 1}' | ./mcp_wrapper.sh --stdio
   ```

3. **Test Wazuh authentication**:
   ```bash
   curl -k -X POST "https://your-wazuh:55000/security/user/authenticate" \
     -H "Content-Type: application/json" \
     -d '{"username":"your-api-user","password":"your-api-password"}'
   ```

4. **Run validation script**:
   ```bash
   python3 validate_setup.py
   ```

5. **Test from Claude Desktop**:
   - Restart Claude Desktop
   - Try: "Show me recent Wazuh alerts"

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
# Enable debug in wrapper script
export DEBUG=1
./mcp_wrapper.sh --stdio
```

Or add to `.env` file:
```env
DEBUG=true
LOG_LEVEL=DEBUG
```

## Platform-Specific Notes

### macOS Specific

- **Homebrew**: Recommended for installing Python and dependencies
- **Xcode Command Line Tools**: Required for compilation
  ```bash
  xcode-select --install
  ```
- **SIP (System Integrity Protection)**: May affect some operations

### Linux Specific

- **Package Managers**: Use system package manager for dependencies
- **Development Tools**: Install build-essential or equivalent
- **SELinux/AppArmor**: May require configuration for some operations

## Performance Tips

### Resource Usage

1. **Monitor wrapper script resource usage**:
   ```bash
   top -p $(pgrep -f mcp_wrapper.sh)
   ```

2. **Optimize environment variables**:
   ```env
   MAX_CONNECTIONS=10
   POOL_SIZE=5
   REQUEST_TIMEOUT_SECONDS=30
   ```

### Log Management

1. **Log rotation** (handled automatically by wrapper):
   ```bash
   # Check temporary log directories
   ls -la /tmp/wazuh-mcp-*/logs/
   ```

2. **Clean old temporary directories**:
   ```bash
   find /tmp -name "wazuh-mcp-*" -type d -mtime +7 -exec rm -rf {} \;
   ```

## Getting Help

### Information to Collect

When reporting issues, include:

1. **System information**:
   ```bash
   uname -a
   python3 --version
   ls -la mcp_wrapper.sh
   ```

2. **Configuration**:
   ```bash
   # Sanitize sensitive information before sharing
   grep -v "PASS\|TOKEN\|KEY" .env
   ```

3. **Error logs**:
   ```bash
   # Check temporary logs
   cat /tmp/wazuh-mcp-*/logs/wazuh-mcp.log
   ```

4. **Test results**:
   ```bash
   ./mcp_wrapper.sh --stdio 2>&1 | head -20
   ```

### Support Resources

1. **GitHub Issues**: Report bugs and feature requests
2. **Documentation**: Check README.md and other docs
3. **Community**: Join discussions and share solutions

## Summary

The wrapper script approach provides a unified solution for both macOS and Linux systems, handling environment setup, directory management, and process lifecycle automatically. Most issues can be resolved by ensuring proper permissions, verifying paths, and using the wrapper script correctly in Claude Desktop configuration.