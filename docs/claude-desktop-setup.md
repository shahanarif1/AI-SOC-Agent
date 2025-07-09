# Claude Desktop Setup Guide

This guide explains how to configure the Wazuh MCP Server with Claude Desktop.

## Overview

The Wazuh MCP Server uses the Model Context Protocol (MCP) to integrate with Claude Desktop, allowing you to interact with your Wazuh security infrastructure using natural language.

## Configuration File Location

Claude Desktop stores its MCP server configuration in a specific location based on your operating system:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

> **Important**: This configuration file is NOT created automatically. You must create it through Claude Desktop's interface.

## Setup Steps

### 1. Create Wazuh API User

**Important**: Before configuring Claude Desktop, create a dedicated API user in Wazuh:

1. Login to your Wazuh Dashboard (https://your-wazuh-server:443)
2. Navigate to **Security** → **Internal users**
3. Click **Create internal user**
4. Fill in the details:
   - Username: `wazuh-mcp-api` (or your preferred name)
   - Password: Generate a strong password
   - Backend roles: `wazuh`
5. Save the user

> **Why this is needed**: Wazuh Dashboard and API use separate authentication systems. Your dashboard login credentials won't work for API access.

### 2. Create the Configuration File

1. Open Claude Desktop
2. Navigate to **Settings** → **Developer**
3. Click **Edit Config**
   - This will create the `claude_desktop_config.json` file if it doesn't exist
   - It will also open the file in your default text editor

### 3. Add Platform-Specific Configuration

#### macOS Configuration

**Important**: macOS requires the wrapper script due to Claude Desktop's read-only filesystem restrictions.

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/Wazuh-MCP-Server/mcp_wrapper.sh",
      "args": ["--stdio"],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**macOS Example:**
```json
"command": "/Users/username/Documents/Wazuh-MCP-Server/mcp_wrapper.sh"
```

#### Linux/Windows Configuration

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Linux Example:**
```json
"args": ["/home/username/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"]
```

### 4. Update the Path

Replace `/path/to/Wazuh-MCP-Server` with your actual installation path:

**Windows Example:**
```json
"args": ["C:/Users/username/Documents/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"]
```

> **Note**: On Windows, use forward slashes `/` or double backslashes `\\` in paths.

### 5. Using Virtual Environment (Recommended for Linux/Windows)

**macOS**: The wrapper script automatically handles virtual environment activation.

**Linux:**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/Wazuh-MCP-Server/venv/bin/python",
      "args": ["/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

**Windows:**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "C:/path/to/Wazuh-MCP-Server/venv/Scripts/python.exe",
      "args": ["C:/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### 6. Save and Restart

1. Save the configuration file
2. **Restart Claude Desktop** (required for changes to take effect)
3. The Wazuh server should now appear in Claude's MCP servers

## Verifying the Setup

After restarting Claude Desktop:

1. In a new conversation, try asking:
   - "Show me recent Wazuh alerts"
   - "What's the status of my Wazuh agents?"
   - "List critical vulnerabilities"

2. Check for the Wazuh server in Claude's interface:
   - Look for MCP server indicators in the UI
   - The server name "wazuh" should be visible when active

## Troubleshooting

### Server Not Appearing

1. **Check the configuration file path**:
   - Ensure you're editing the correct file
   - The file must be named exactly `claude_desktop_config.json`

2. **Verify JSON syntax**:
   - Ensure proper JSON formatting (use a JSON validator)
   - Check for missing commas or brackets

3. **Confirm paths are absolute**:
   - Use full paths, not relative paths
   - Verify the paths exist and are accessible

### Connection Errors

1. **Test the server manually**:
   ```bash
   python /path/to/src/wazuh_mcp_server/main.py --stdio
   ```
   Type: `{"jsonrpc": "2.0", "method": "initialize", "id": 1}`
   
   You should see a response if the server is working.

2. **Check Python environment**:
   - Ensure all dependencies are installed
   - Run `python validate_setup.py` in the project directory

3. **Review logs**:
   - Check Claude Desktop logs for error messages
   - Look for Wazuh MCP Server logs in the `logs/` directory

### Authentication Issues

**Problem**: "Invalid credentials" or "Authentication failed" errors

**Solution**: This usually means you need to create a proper API user:

1. **Create API User** (if not done already):
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
   - Default admin account may be disabled for API access
   - User must have proper backend roles assigned
   - Check that `WAZUH_USER` and `WAZUH_PASS` in `.env` match your API user

### Environment Variables

If your Wazuh configuration uses environment variables, you can add them to the MCP server configuration:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["/path/to/src/wazuh_mcp_server/main.py", "--stdio"],
      "env": {
        "LOG_LEVEL": "INFO",
        "WAZUH_HOST": "your-wazuh-server.com",
        "WAZUH_USER": "wazuh-mcp-api",
        "WAZUH_PASS": "your-api-password"
      }
    }
  }
}
```

> **Security Note**: Adding credentials directly to the config file is less secure than using a `.env` file. Use this method only for testing or in secure environments.

## Advanced Configuration

### Multiple Wazuh Instances

You can configure multiple Wazuh servers:

```json
{
  "mcpServers": {
    "wazuh-prod": {
      "command": "python",
      "args": ["/path/to/src/wazuh_mcp_server/main.py", "--stdio"],
      "env": {
        "WAZUH_HOST": "prod.wazuh.com"
      }
    },
    "wazuh-dev": {
      "command": "python",
      "args": ["/path/to/src/wazuh_mcp_server/main.py", "--stdio"],
      "env": {
        "WAZUH_HOST": "dev.wazuh.com"
      }
    }
  }
}
```

### Debug Mode

Enable debug logging for troubleshooting:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["/path/to/src/wazuh_mcp_server/main.py", "--stdio"],
      "env": {
        "LOG_LEVEL": "DEBUG",
        "DEBUG": "true"
      }
    }
  }
}
```

## Getting Help

- **Documentation**: Check the main [README.md](../README.md)
- **Issues**: Report problems on [GitHub](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **MCP Documentation**: Learn more about MCP at [modelcontextprotocol.io](https://modelcontextprotocol.io)