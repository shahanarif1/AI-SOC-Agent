# Windows Troubleshooting

## Installation Issues

### Python Not Found
```batch
# Install Python from python.org or Microsoft Store
# During installation, check "Add Python to PATH"

# Or install via winget
winget install Python.Python.3.11
```

### Character Encoding Errors
```batch
# Use Windows Terminal (recommended)
# Or set console to UTF-8
chcp 65001
```

### Permission Errors
```batch
# Run PowerShell as Administrator
# Or disable Windows Defender Real-time protection temporarily
```

### Virtual Environment Issues
```batch
# If venv creation fails
python -m pip install --upgrade pip
python -m pip install virtualenv
python -m virtualenv venv
```

### SSL Certificate Errors
```env
# Add to .env file
VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true
```

### Network/Firewall Issues
```batch
# Allow Python through Windows Firewall
# Check corporate proxy settings
# Test connectivity: telnet your-wazuh-server 55000
```

## Claude Desktop Setup

### Configuration File Location
```
%APPDATA%\Claude\claude_desktop_config.json
```

### Creating the Configuration
1. Open Claude Desktop
2. Go to **Settings** → **Developer**
3. Click **Edit Config** to create/open the configuration file
4. Add your MCP server configuration

### Common Issues
- The config file is NOT created automatically - use Claude Desktop's Developer settings
- Use forward slashes `/` or double backslashes `\\` in paths
- Ensure Python is in PATH
- Restart Claude Desktop after changes
- Example path format: `C:/Users/YourName/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py`

## Getting Help

1. Run diagnostics: `python validate_setup.py`
2. Check logs in the installation directory
3. Create GitHub issue with error details