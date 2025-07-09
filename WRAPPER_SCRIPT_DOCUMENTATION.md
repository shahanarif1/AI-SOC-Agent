# Wazuh MCP Server Wrapper Script Documentation

## Overview

The `mcp_wrapper.sh` script is a comprehensive solution to run the Wazuh MCP Server from Claude Desktop on Unix-like systems (macOS and Linux), addressing read-only file system issues and environment configuration problems.

## Scope and Purpose

### Problems Solved

1. **Read-only file system error**: Creates a temporary writable directory for logs (especially important on macOS)
2. **Working directory issues**: Ensures the server runs from the correct project directory
3. **Environment variable loading**: Properly loads .env configuration across Unix systems
4. **Process management**: Handles signals and cleanup properly
5. **Python environment**: Uses the correct virtual environment
6. **Cross-platform compatibility**: Works seamlessly on both macOS and Linux

### Functionality

The wrapper script provides:
- Environment validation and setup
- Temporary directory management
- Signal handling for graceful shutdown
- Python environment configuration
- MCP protocol compatibility
- Error handling and logging

## Implementation Details

### 1. Environment Validation

```bash
validate_environment() {
    # Checks for:
    # - Virtual environment existence
    # - Main script presence
    # - .env file availability (with warning if missing)
}
```

### 2. Environment Variable Loading

The script loads variables from `.env` file with:
- Comment and empty line handling
- Quote removal
- Whitespace trimming
- Proper export to environment

### 3. Temporary Directory Management

```bash
setup_temp_directory() {
    # Creates: /tmp/wazuh-mcp-XXXXXX/logs/
    # Sets: WAZUH_LOG_DIR and LOG_DIR environment variables
}
```

### 4. Python Environment Configuration

Sets critical Python variables:
- `PYTHONUNBUFFERED=1` - Prevents output buffering (critical for MCP)
- `PYTHONDONTWRITEBYTECODE=1` - Prevents .pyc file creation
- `PYTHONPATH` - Includes project source directory

### 5. Signal Handling

Properly handles:
- `SIGTERM` - Graceful shutdown request
- `SIGINT` - Interrupt signal (Ctrl+C)
- `SIGHUP` - Hang up signal

### 6. Cleanup Management

Automatic cleanup of:
- Temporary directories
- Log files
- Process resources

## Usage

### For Claude Desktop

Update your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/Users/alokemajumder/Documents/GitHub/Wazuh-MCP-Server/mcp_wrapper.sh",
      "args": ["--stdio"]
    }
  }
}
```

### For Testing

```bash
# Test the wrapper
./test_wrapper.sh

# Manual test
./mcp_wrapper.sh --stdio
```

### For Development

```bash
# Run with debug output
./mcp_wrapper.sh --debug

# Test environment only
./mcp_wrapper.sh --test-env
```

## Features

### Robust Error Handling

- Validates all prerequisites before starting
- Provides clear error messages
- Exits with proper codes for automation

### Environment Flexibility

- Works with or without .env file
- Provides sensible defaults
- Handles missing configuration gracefully

### Process Management

- Uses `exec` to replace wrapper process with Python
- Ensures signals reach the actual server process
- Proper cleanup on all exit scenarios

### MCP Protocol Compatibility

- Maintains stdio passthrough
- Disables output buffering
- Sets appropriate environment flags

## Technical Details

### Directory Structure

```
/Users/alokemajumder/Documents/GitHub/Wazuh-MCP-Server/
├── mcp_wrapper.sh          # Main wrapper script
├── test_wrapper.sh         # Test script
├── venv/                   # Python virtual environment
├── src/                    # Source code
├── .env                    # Environment configuration
└── logs/                   # Original logs directory (may be read-only)
```

### Temporary Directory Structure

```
/tmp/wazuh-mcp-XXXXXX/
└── logs/                   # Writable logs directory
```

### Environment Variables Set

The wrapper sets these environment variables:

```bash
PYTHONUNBUFFERED=1
PYTHONDONTWRITEBYTECODE=1
PYTHONPATH="$PROJECT_ROOT/src:$PYTHONPATH"
MCP_MODE=1
WAZUH_RUNNING_IN_CLAUDE=1
WAZUH_LOG_DIR="$TEMP_DIR/logs"
LOG_DIR="$TEMP_DIR/logs"
```

Plus all variables from `.env` file.

## Security Considerations

### File Permissions

- Script requires execute permissions (`chmod +x`)
- Temporary directories use secure creation (`mktemp -d`)
- Environment file should have restricted permissions (600)

### Process Security

- Uses `set -euo pipefail` for strict error handling
- Validates all inputs before execution
- Proper signal handling prevents orphaned processes

### Data Security

- Temporary directories are cleaned on exit
- No sensitive data is logged to stdout
- Environment variables are properly scoped

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   chmod +x mcp_wrapper.sh
   ```

2. **Virtual Environment Not Found**
   ```bash
   python3 -m venv venv
   venv/bin/pip install -r requirements.txt
   ```

3. **Script Not Working**
   ```bash
   ./test_wrapper.sh
   ```

### Debug Mode

For debugging, you can modify the script to add debug output:

```bash
# Add this after the main() function call
set -x  # Enable debug mode
```

### Log Analysis

When issues occur, check:
1. Claude Desktop logs (in the logs directory)
2. System console for any wrapper script errors
3. Temporary directory contents (if any)

## Maintenance

### Updates Required

The wrapper should be updated if:
- Project structure changes
- Python environment requirements change
- New environment variables are needed
- MCP protocol requirements change

### Monitoring

Monitor the wrapper by:
- Checking Claude Desktop connection status
- Verifying log creation in temporary directories
- Testing with `test_wrapper.sh` periodically

## Compatibility

### Supported Platforms

**macOS:**
- macOS 10.15+
- macOS 11.0+
- macOS 12.0+
- macOS 13.0+
- macOS 14.0+

**Linux:**
- Ubuntu 20.04+
- Debian 11+
- CentOS 8+
- Fedora 34+
- Arch Linux
- Other modern Linux distributions

### Claude Desktop Versions

Compatible with:
- Claude Desktop 0.10.x
- Claude Desktop 0.11.x

### Python Versions

Requires:
- Python 3.9+
- Virtual environment with required packages

## Performance

### Resource Usage

- Minimal memory overhead
- No permanent disk usage (temporary only)
- Fast startup time (<1 second)

### Optimization

The wrapper is optimized for:
- Fast startup
- Low resource usage
- Reliable cleanup
- Minimal dependencies

## Conclusion

The wrapper script provides a robust, production-ready solution for running the Wazuh MCP Server from Claude Desktop on Unix-like systems (macOS and Linux), handling all environment issues without requiring modifications to the existing codebase. This unified approach ensures consistent behavior across different Unix platforms while maintaining compatibility with Claude Desktop's requirements.