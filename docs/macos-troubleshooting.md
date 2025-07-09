# macOS Troubleshooting

## Common Issues and Solutions

### Read-Only File System Errors

**Error**: `[Errno 30] Read-only file system: 'logs'`

**Cause**: Claude Desktop on macOS runs MCP servers from read-only locations, preventing log file creation.

**Solution**: Use the wrapper script instead of direct Python execution.

1. **Ensure wrapper script exists and is executable**:
   ```bash
   chmod +x /path/to/Wazuh-MCP-Server/mcp_wrapper.sh
   ```

2. **Test the wrapper script**:
   ```bash
   ./mcp_wrapper.sh --stdio
   ```
   You should see server initialization without read-only errors.

3. **Update Claude Desktop configuration**:
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

### Wrapper Script Issues

**Error**: `Permission denied` when running wrapper script

**Solution**:
```bash
chmod +x mcp_wrapper.sh
```

**Error**: `python3: command not found` in wrapper script

**Solution**: Install Python 3 or update the wrapper script to use correct Python path:
```bash
# Check Python location
which python3

# Update wrapper script if needed
# Edit mcp_wrapper.sh and change python3 to full path
```

### Environment Variable Issues

**Error**: Environment variables not loading properly

**Solution**: The wrapper script handles .env loading automatically. Ensure:

1. **`.env` file exists**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. **Proper .env format**:
   ```env
   WAZUH_HOST=your-wazuh-server
   WAZUH_USER=wazuh-mcp-api
   WAZUH_PASS=your-password
   ```

3. **No quotes around values** unless necessary

### Working Directory Issues

**Error**: Cannot find source files or modules

**Solution**: The wrapper script automatically sets the correct working directory. If issues persist:

1. **Verify installation path**:
   ```bash
   cd /path/to/Wazuh-MCP-Server
   ls -la src/wazuh_mcp_server/main.py
   ```

2. **Check wrapper script configuration**:
   ```bash
   # View wrapper script paths
   head -20 mcp_wrapper.sh
   ```

### Virtual Environment Issues

**Error**: Virtual environment not activated properly

**Solution**: The wrapper script handles virtual environment activation automatically:

1. **Verify virtual environment exists**:
   ```bash
   ls -la venv/bin/python
   ```

2. **Recreate virtual environment if needed**:
   ```bash
   rm -rf venv
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

### Python Path Issues

**Error**: `ModuleNotFoundError` for wazuh_mcp_server modules

**Solution**: The wrapper script sets `PYTHONPATH` automatically. If issues persist:

1. **Check Python path in wrapper**:
   ```bash
   grep PYTHONPATH mcp_wrapper.sh
   ```

2. **Manual Python path test**:
   ```bash
   export PYTHONPATH="$PWD/src:$PYTHONPATH"
   python3 -c "import wazuh_mcp_server; print('OK')"
   ```

### Temporary Directory Issues

**Error**: Cannot create temporary directories

**Solution**: The wrapper script creates temporary directories in `/tmp`. If issues occur:

1. **Check `/tmp` permissions**:
   ```bash
   ls -ld /tmp
   # Should show: drwxrwxrwt
   ```

2. **Manual cleanup**:
   ```bash
   # Clean up old temporary directories
   rm -rf /tmp/wazuh-mcp-*
   ```

### Claude Desktop Configuration Issues

**Error**: Server not appearing in Claude Desktop

**Solution**: 

1. **Verify configuration file location**:
   ```bash
   ls -la ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

2. **Check JSON syntax**:
   ```bash
   python3 -m json.tool ~/Library/Application\ Support/Claude/claude_desktop_config.json
   ```

3. **Correct configuration format**:
   ```json
   {
     "mcpServers": {
       "wazuh": {
         "command": "/Users/yourusername/path/to/Wazuh-MCP-Server/mcp_wrapper.sh",
         "args": ["--stdio"]
       }
     }
   }
   ```

4. **Restart Claude Desktop** after configuration changes

### SSL Certificate Issues

**Error**: SSL certificate verification failed

**Solution**: Update `.env` file:

```env
# For self-signed certificates
VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=true

# For development only (not recommended for production)
VERIFY_SSL=false
```

### Testing the Setup

**Complete test procedure**:

1. **Test wrapper script**:
   ```bash
   ./mcp_wrapper.sh --stdio
   ```

2. **Test MCP communication**:
   ```bash
   echo '{"jsonrpc": "2.0", "method": "initialize", "id": 1}' | ./mcp_wrapper.sh --stdio
   ```

3. **Test from Claude Desktop**:
   - Restart Claude Desktop
   - Try: "Show me recent Wazuh alerts"

### Getting Help

1. **Check wrapper script logs**:
   ```bash
   # Enable debug mode in wrapper script
   export DEBUG=1
   ./mcp_wrapper.sh --stdio
   ```

2. **Check temporary log files**:
   ```bash
   ls -la /tmp/wazuh-mcp-*/logs/
   ```

3. **Run validation**:
   ```bash
   python3 validate_setup.py
   ```

4. **Create GitHub issue** with:
   - macOS version
   - Python version
   - Error messages
   - Wrapper script output