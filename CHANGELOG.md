# Changelog

## v1.0.0 - Unix Systems Consolidation

### Major Changes

#### Platform Consolidation
- **Unified Unix Support**: macOS and Linux now both use the wrapper script approach
- **Simplified Setup**: Single configuration method for Unix-like systems
- **Windows Distinction**: Windows continues to use direct Python execution

#### Documentation Restructuring
- **Consolidated Troubleshooting**: Merged macOS and Linux troubleshooting into unified Unix guide
- **Updated Setup Instructions**: Clear platform-specific configuration examples
- **Enhanced README**: Streamlined setup process with platform-specific sections

#### Security Improvements
- **Credential Security**: Removed exposed production credentials from repository
- **Enhanced .gitignore**: Comprehensive exclusion of sensitive files
- **SSL Configuration**: Clear guidance on production vs development settings

#### API Authentication
- **Dedicated API Users**: Clear instructions for creating Wazuh API users
- **Separation of Concerns**: Distinct Dashboard vs API authentication explained
- **Enhanced Troubleshooting**: Comprehensive authentication troubleshooting guide

### Files Added
- `docs/unix-troubleshooting.md` - Comprehensive Unix systems troubleshooting
- `CHANGELOG.md` - This changelog file

### Files Modified
- `README.md` - Updated with consolidated platform approach
- `WRAPPER_SCRIPT_DOCUMENTATION.md` - Updated to reflect Unix support
- `docs/claude-desktop-setup.md` - Platform-specific configuration examples
- `docs/windows-troubleshooting.md` - Enhanced Windows-specific guidance
- `.env` - Sanitized credentials (placeholder values)

### Files Removed
- `docs/macos-troubleshooting.md` - Merged into unix-troubleshooting.md
- `docs/linux-setup.md` - Merged into main documentation
- `logs/*.log` - Removed log files from repository

### Configuration Changes

#### Unix Systems (macOS/Linux)
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/Wazuh-MCP-Server/mcp_wrapper.sh",
      "args": ["--stdio"]
    }
  }
}
```

#### Windows
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "C:/path/to/Wazuh-MCP-Server/venv/Scripts/python.exe",
      "args": ["C:/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"]
    }
  }
}
```

### Benefits
- **Simplified Setup**: Users no longer need to distinguish between macOS and Linux
- **Better Error Handling**: Unified troubleshooting approach
- **Enhanced Security**: Proper credential management and SSL configuration
- **Improved Documentation**: Clear, comprehensive guides for all platforms
- **Production Ready**: Cleaned repository ready for deployment

### Migration Guide

#### For Existing macOS Users
- No changes needed - existing configuration continues to work
- Refer to `docs/unix-troubleshooting.md` for any issues

#### For Existing Linux Users
- Update Claude Desktop configuration to use wrapper script
- Change from direct Python execution to wrapper script approach
- Refer to updated documentation for configuration examples

#### For New Users
- Follow platform-specific setup instructions in README.md
- Use appropriate configuration for your operating system
- Refer to platform-specific troubleshooting guides

### Technical Improvements
- **Cross-Platform Compatibility**: Wrapper script tested on both macOS and Linux
- **Environment Handling**: Improved .env file loading and validation
- **Process Management**: Enhanced signal handling and cleanup
- **Logging**: Better log management with temporary directory creation
- **Error Recovery**: Comprehensive error handling and recovery mechanisms

### Future Considerations
- Monitor wrapper script performance across different Linux distributions
- Consider adding automated testing for all supported platforms
- Evaluate potential for Windows wrapper script if needed
- Plan for additional platform support based on user feedback