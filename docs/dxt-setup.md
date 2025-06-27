# 🛡️ Wazuh MCP Server - Desktop Extension (DXT) Setup Guide

## Overview

This guide covers how to install and configure the Wazuh MCP Server as a Desktop Extension (DXT) for Claude Desktop.

## Prerequisites

- **Claude Desktop**: Version 0.3.0 or later
- **Python**: Version 3.8 or later
- **Wazuh Deployment**: Version 4.x with API access
- **Operating System**: Windows, macOS, or Linux

## Installation

### Method 1: Using DXT Package Manager (Recommended)

1. **Download the Extension**:
   ```bash
   # Clone the repository
   git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
   cd Wazuh-MCP-Server
   
   # Package as DXT (if you have dxt CLI tools)
   dxt pack .
   ```

2. **Install in Claude Desktop**:
   - Open Claude Desktop
   - Navigate to Extensions → Install Extension
   - Select the generated `.dxt` file

### Method 2: Manual Installation

1. **Create Extension Archive**:
   ```bash
   # Ensure all dependencies are bundled
   pip install -r requirements.txt --target ./lib
   
   # Create zip archive with all files
   zip -r wazuh-mcp-server.dxt \
     manifest.json \
     src/ \
     lib/ \
     requirements.txt \
     README.md \
     LICENSE
   ```

2. **Install in Claude Desktop**:
   - Import the `.dxt` file through Claude Desktop's extension manager

## Configuration

### Required Configuration

The extension requires the following configuration parameters:

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `WAZUH_HOST` | Wazuh server hostname/IP | ✅ | - |
| `WAZUH_USER` | Wazuh API username | ✅ | - |
| `WAZUH_PASS` | Wazuh API password | ✅ | - |
| `WAZUH_PORT` | Wazuh API port | ❌ | 55000 |
| `VERIFY_SSL` | Enable SSL verification | ❌ | true |

### Optional Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `WAZUH_INDEXER_HOST` | Wazuh Indexer hostname (4.8+) | - |
| `WAZUH_INDEXER_PORT` | Wazuh Indexer port | 9200 |
| `WAZUH_INDEXER_USER` | Wazuh Indexer username | - |
| `WAZUH_INDEXER_PASS` | Wazuh Indexer password | - |
| `LOG_LEVEL` | Logging verbosity | INFO |

### Configuration in Claude Desktop

1. **Open Extension Settings**:
   - Navigate to Extensions → Wazuh MCP Server → Settings

2. **Configure Connection**:
   ```
   Wazuh Server Host: your-wazuh.example.com
   Wazuh Username: your-api-user
   Wazuh Password: your-secure-password
   Verify SSL Certificate: ✓ (recommended)
   ```

3. **Advanced Settings** (Optional):
   ```
   Wazuh Indexer Host: your-indexer.example.com
   Wazuh Indexer Username: indexer-user
   Wazuh Indexer Password: indexer-password
   Logging Level: INFO
   ```

## Features Available

### 🛠️ Tools

- **get_alerts**: Retrieve security alerts with filtering
- **analyze_threats**: AI-powered threat analysis
- **check_agent_health**: Monitor agent status
- **compliance_check**: Framework compliance assessment
- **check_ioc**: Indicator of compromise verification
- **risk_assessment**: Comprehensive security risk scoring

### 📊 Resources

- **Recent Alerts**: Live security alert feed
- **Agent Status**: Real-time agent health dashboard
- **Critical Vulnerabilities**: High-priority vulnerability tracker
- **Compliance Status**: Compliance posture monitoring
- **Active Threats**: Current threat campaign detection
- **System Health**: Overall system metrics

## Usage Examples

Once configured, you can interact with your Wazuh deployment through natural language:

### Security Monitoring
```
"Are we under attack right now?"
"Show me all high-severity alerts from the last 2 hours"
"Which agents are offline or unhealthy?"
```

### Threat Analysis
```
"Analyze recent threats and provide risk assessment"
"Look for signs of lateral movement in our network"
"Check if IP 192.168.1.100 is malicious"
```

### Compliance Reporting
```
"Generate a PCI DSS compliance report"
"Show me HIPAA compliance gaps"
"What's our current security posture score?"
```

## Troubleshooting

### Common Issues

1. **Connection Failed**:
   - Verify Wazuh server is accessible
   - Check firewall rules for API port (55000)
   - Validate credentials and permissions

2. **SSL Certificate Errors**:
   - Set `VERIFY_SSL` to `false` for testing
   - Install proper SSL certificates in production

3. **Performance Issues**:
   - Adjust `LOG_LEVEL` to `WARNING` or `ERROR`
   - Reduce query limits in complex operations
   - Check network latency to Wazuh server

4. **Permission Errors**:
   - Ensure API user has sufficient Wazuh permissions
   - Check agent access policies
   - Verify indexer authentication (Wazuh 4.8+)

### Debug Mode

Enable debug logging by setting:
```
LOG_LEVEL: DEBUG
```

This provides detailed operation logs for troubleshooting.

### Health Check

The extension performs automatic health checks:
- Wazuh API connectivity
- Agent communication status
- Performance metrics monitoring

## Security Considerations

### Best Practices

1. **Credentials**:
   - Use strong, unique passwords
   - Enable SSL certificate verification
   - Regularly rotate API credentials

2. **Network Security**:
   - Restrict API access to specific IPs
   - Use VPN for remote connections
   - Monitor API access logs

3. **Permissions**:
   - Follow principle of least privilege
   - Create dedicated API users
   - Regularly audit user permissions

### Data Privacy

- All communication uses HTTPS encryption
- No sensitive data is cached locally
- Audit logs are maintained for compliance

## Support

### Getting Help

- **Documentation**: [Installation Guide](installation.md) | [Usage Guide](usage.md)
- **Issues**: Report bugs at [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Discussions**: Join community at [GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)

### Version Compatibility

| Claude Desktop | Extension | Wazuh | Python |
|----------------|-----------|-------|--------|
| 0.3.0+ | 2.0.0+ | 4.x | 3.8+ |
| 0.4.0+ | 2.1.0+ | 4.8+ | 3.9+ |

---

**Built with ❤️ for the security community**

*Transform your security operations with AI-powered analysis and natural language interaction.*