# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Wazuh Compatible](https://img.shields.io/badge/Wazuh-4.8%2B-orange.svg)](https://wazuh.com/)

A production-grade Model Context Protocol (MCP) server that integrates Wazuh SIEM with Claude Desktop, enabling natural language security operations and analysis.

## 🌟 Features

### 🛡️ **Comprehensive Security Integration**
- **Real-time Security Monitoring**: Direct access to Wazuh alerts and events
- **Agent Management**: Monitor and manage Wazuh agents across your infrastructure
- **Vulnerability Analysis**: Comprehensive vulnerability scanning and reporting
- **Compliance Reporting**: PCI DSS, GDPR, HIPAA, and custom compliance frameworks
- **Rule & Decoder Management**: Create and modify Wazuh rules and decoders

### 🔍 **Advanced Analytics**
- **Threat Intelligence**: AI-powered security analysis and correlation
- **Incident Response**: Automated incident detection and response workflows
- **Risk Assessment**: Comprehensive security posture analysis
- **Forensic Analysis**: Deep dive into security events and attack patterns

### 🏗️ **Enterprise-Grade Architecture**
- **Production Ready**: Robust error handling and retry mechanisms
- **Secure by Default**: HTTPS-only connections with SSL/TLS validation
- **High Performance**: Async I/O and connection pooling
- **Comprehensive Logging**: Structured logging with security event tracking

## 🚀 Quick Start

### Prerequisites
- Python 3.9 or higher
- Wazuh Server 4.8+ with API access
- Wazuh Indexer (OpenSearch) for advanced features
- Claude Desktop application

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
   cd Wazuh-MCP-Server
   ```

2. **Run the installation script**
   ```bash
   python3 install.py
   ```

3. **Configure Wazuh connection**
   ```bash
   # Edit .env file with your Wazuh details
   nano .env
   ```

4. **Test the connection**
   ```bash
   source venv/bin/activate
   python src/wazuh_mcp_server/main.py --stdio
   ```

### Configuration

Edit the `.env` file with your Wazuh deployment details:

```env
# Wazuh Manager Configuration
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=your-username
WAZUH_PASS=your-password

# Wazuh Indexer Configuration
WAZUH_INDEXER_HOST=your-indexer-host.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=your-indexer-username
WAZUH_INDEXER_PASS=your-indexer-password

# Security Settings
VERIFY_SSL=false                    # Set to true for production
WAZUH_ALLOW_SELF_SIGNED=true        # Set to false for production
```

### Claude Desktop Integration

Add the following to your Claude Desktop `settings.json`:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"]
    }
  }
}
```

## 📋 Supported Operations

### 🔍 **Security Monitoring**
- Real-time alert monitoring
- Security event analysis
- Threat detection and correlation
- Attack pattern identification

### 👥 **Agent Management**
- Agent status monitoring
- Agent configuration management
- Group management
- Performance metrics

### 🛠️ **Rule & Configuration Management**
- Custom rule creation and modification
- Decoder management
- Configuration templates
- Rule testing and validation

### 📊 **Compliance & Reporting**
- PCI DSS compliance reports
- GDPR compliance monitoring
- HIPAA compliance tracking
- Custom compliance frameworks
- Executive dashboards

### 🔎 **Vulnerability Management**
- Vulnerability scanning results
- Risk prioritization
- Patch management tracking
- Remediation workflows

## 🏗️ Project Structure

```
Wazuh-MCP-Server/
├── src/wazuh_mcp_server/          # Main application code
│   ├── api/                       # Wazuh API clients
│   ├── analyzers/                 # Security and compliance analyzers
│   ├── scripts/                   # Utility scripts
│   ├── utils/                     # Helper utilities
│   ├── config.py                  # Configuration management
│   └── main.py                    # Main server entry point
├── tests/                         # Test suite
├── docs/                          # Documentation
├── .env                          # Environment configuration
├── requirements.txt              # Python dependencies
├── install.py                   # Installation script
├── validate_setup.py            # Setup validation tool
└── pyproject.toml               # Python package configuration
```

## 🔧 Advanced Configuration

### SSL/TLS Security
For production deployments, enable SSL verification:
```env
VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=false
```

### Custom CA Certificates
```env
WAZUH_CA_BUNDLE_PATH=/path/to/ca-bundle.pem
WAZUH_CLIENT_CERT_PATH=/path/to/client.crt
WAZUH_CLIENT_KEY_PATH=/path/to/client.key
```

### Performance Tuning
```env
WAZUH_MAX_CONNECTIONS=20
WAZUH_REQUEST_TIMEOUT=30
WAZUH_RATE_LIMIT=10
LOG_LEVEL=INFO
```

## 🧪 Testing

Run the test suite:
```bash
source venv/bin/activate
python -m pytest tests/ -v
```

Test connection to your Wazuh server:
```bash
python src/wazuh_mcp_server/scripts/test_connection.py
```

## 📚 Documentation

- [API Reference](docs/API_REFERENCE.md) - Complete API documentation
- [Configuration Reference](docs/CONFIGURATION_REFERENCE.md) - Detailed configuration options
- [Local Setup Guide](docs/LOCAL_SETUP.md) - Step-by-step setup instructions

## 🛡️ Security Considerations

### Production Deployment
- Use dedicated service accounts with minimal required permissions
- Enable SSL/TLS verification (`VERIFY_SSL=true`)
- Use proper CA-signed certificates in production
- Regularly rotate API credentials
- Monitor access logs and security events
- Set appropriate file permissions (600) on `.env` file

### Network Security
- Ensure Wazuh API endpoints are properly secured
- Use firewalls to restrict access to Wazuh services
- Consider VPN or private network connections
- Enable audit logging on Wazuh servers

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)
- **Documentation**: [Project Documentation](docs/)

## 🔄 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.

---

**Made with ❤️ for the security community**

Transform your Wazuh SIEM into an AI-powered security operations center with natural language queries and advanced analytics through Claude Desktop.