# 🛡️ Wazuh MCP Server - Production-Grade AI Security Operations

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)
[![Wazuh 4.8.0+](https://img.shields.io/badge/Wazuh-4.8.0+-blue.svg)](https://wazuh.com/)
[![Production Ready](https://img.shields.io/badge/Status-Production%20Ready-success.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server)
[![Claude Desktop](https://img.shields.io/badge/Claude-Desktop-purple.svg)](https://claude.ai/)

**Transform your security operations with AI-powered threat detection, automated incident response, and natural language security analysis.**

*Production-grade reliability • Enterprise security • Intelligent error recovery*

[Quick Start](#-quick-start) •
[Features](#-key-features) •
[Production Setup](#-production-deployment) •
[Contributing](#-contributing)

</div>

---

## 🎯 What is Wazuh MCP Server?

Wazuh MCP Server is a **production-grade** integration that bridges traditional SIEM operations with conversational AI, enabling security teams to interact with their Wazuh infrastructure using natural language through Claude Desktop. Built with enterprise reliability in mind, it features intelligent error recovery, robust SSL handling, and comprehensive production monitoring.

### 🚀 Why Choose This Solution?

- **⚡ Production-Ready**: Built with enterprise-grade error recovery and monitoring
- **🛡️ Security-First**: Comprehensive SSL/TLS handling and secure defaults
- **🧠 AI-Enhanced**: Leverage Claude's reasoning for advanced threat analysis
- **🔄 Self-Healing**: Intelligent error recovery with circuit breakers and fallbacks
- **📊 Real-time Intelligence**: Instant insights from multiple data sources
- **🎯 Zero-Config**: Works out-of-the-box with any certificate setup

## 🌟 Key Features

### 🔧 Production-Grade Engineering

- **🔄 Intelligent Error Recovery**: Automatic retry, circuit breaker, and fallback mechanisms
- **🛡️ Enterprise SSL Handling**: Auto-detection and configuration for any certificate type
- **📊 Comprehensive Monitoring**: Built-in performance metrics and health checks
- **🌐 Cross-Platform**: Robust import resolution for Windows, Linux, and macOS
- **⚡ High Performance**: Async operations with connection pooling and rate limiting

### 🔍 Advanced Security Analytics

- **Multi-dimensional Risk Scoring**: Combines alert patterns, vulnerabilities, and threat intelligence
- **ML-based Anomaly Detection**: Statistical analysis with configurable sensitivity
- **MITRE ATT&CK Mapping**: Automatic TTP identification and kill chain analysis
- **Threat Correlation Engine**: Cross-references with external threat intelligence

### 🤖 Natural Language Security Operations

Ask Claude questions like:
- *"Are we under attack right now?"*
- *"Show me all privilege escalation attempts in the last 48 hours"*
- *"Which systems have critical vulnerabilities being actively exploited?"*
- *"Generate an executive security report"*

### 📋 Compliance Automation

- **Multi-Framework Support**: PCI DSS, HIPAA, GDPR, NIST, ISO 27001
- **Automated Gap Analysis**: Identifies missing controls and generates remediation plans
- **Continuous Monitoring**: Real-time compliance scoring with trend analysis
- **Audit-Ready Reports**: Generate compliance evidence with natural language commands

## 🚀 Quick Start

### ⚡ Production Installation (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env with your Wazuh credentials

# 4. Test connection (with automatic error recovery)
python scripts/test_connection.py

# 5. Start the server
python src/wazuh_mcp_server.py --stdio
```

### 🐳 Docker Deployment

```bash
# Quick deployment with docker-compose
docker-compose up -d
```

### 🔧 Claude Desktop Configuration

Add to your Claude Desktop config (`~/Library/Application\ Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "wazuh-security": {
      "command": "python",
      "args": ["path/to/Wazuh-MCP-Server/src/wazuh_mcp_server.py", "--stdio"],
      "env": {
        "WAZUH_HOST": "your-wazuh-server",
        "WAZUH_PORT": "55000",
        "WAZUH_USER": "your-username",
        "WAZUH_PASS": "your-password",
        "VERIFY_SSL": "false"
      }
    }
  }
}
```

## 🏢 Production Deployment

### 🔒 Security Configuration

The server includes enterprise-grade security features:

```python
# Automatic SSL configuration
SSL_VERIFY = "true"           # Enable for production certificates
SSL_CA_BUNDLE = "/path/to/ca"   # Custom CA bundle
SSL_CERT_PATH = "/path/to/cert" # Client certificate
SSL_KEY_PATH = "/path/to/key"   # Client key
```

### 📊 Monitoring & Health Checks

Built-in production monitoring:

- **Health Endpoints**: Real-time system health monitoring
- **Performance Metrics**: Request latency, error rates, connection stats
- **Error Recovery Stats**: Circuit breaker status, retry attempts, fallback usage
- **SSL Status**: Certificate validation and auto-detection results

### 🔄 Error Recovery Features

- **Intelligent Retry**: Exponential backoff with jitter for transient failures
- **Circuit Breaker**: Prevents cascade failures during service outages
- **Fallback Services**: Graceful degradation when primary services fail
- **Emergency Mode**: Critical error handling for system stability

## 📊 Available Tools & Resources

### 🛠️ Core Security Tools

| Tool | Description | Production Features |
|------|-------------|-------------------|
| `get_alerts` | Retrieve and analyze security alerts | Auto-retry, rate limiting |
| `analyze_threats` | Advanced threat analysis with ML | Circuit breaker protection |
| `risk_assessment` | Comprehensive security risk scoring | Fallback data sources |
| `check_agent_health` | Agent monitoring and diagnostics | Health aggregation |
| `compliance_check` | Framework compliance validation | Evidence collection |
| `check_ioc` | IOC reputation and threat intel | Multi-source validation |

### 📚 Real-time Resources

- `wazuh://alerts/recent` - Live security alert feed with auto-refresh
- `wazuh://agents/status` - Agent health dashboard with metrics
- `wazuh://vulnerabilities/critical` - Critical vulnerability tracker
- `wazuh://compliance/status` - Compliance posture monitoring
- `wazuh://threats/active` - Active threat campaign tracking
- `wazuh://system/health` - System health and performance metrics

## 🔧 Configuration

### Environment Variables

```bash
# Wazuh Server Configuration
WAZUH_HOST=your-wazuh-server.domain.com
WAZUH_PORT=55000
WAZUH_USER=api-user
WAZUH_PASS=secure-password

# Wazuh Indexer (4.8+)
WAZUH_INDEXER_HOST=your-indexer.domain.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=indexer-user
WAZUH_INDEXER_PASS=indexer-password

# SSL/TLS Configuration
VERIFY_SSL=true
SSL_CA_BUNDLE=/path/to/ca-bundle.pem
SSL_CERT_PATH=/path/to/client.crt
SSL_KEY_PATH=/path/to/client.key

# Performance Tuning
MAX_CONNECTIONS=50
POOL_SIZE=10
REQUEST_TIMEOUT=30
MAX_ALERTS_PER_QUERY=1000

# Logging & Monitoring
LOG_LEVEL=INFO
ENABLE_PERFORMANCE_LOGS=true
ENABLE_ERROR_RECOVERY_STATS=true
```

## 🛠️ Development & Testing

### Development Setup

```bash
# Create development environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install with dev dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Check code quality
python -m flake8 src/
```

### Testing Error Recovery

```bash
# Test connection with error recovery
python scripts/test_connection.py

# Check SSL configuration
python -c "from src.utils.ssl_config import SSLConfigurationManager; print('SSL OK')"

# Test import resolution
python -c "from src.utils.import_resolver import setup_imports; print('Imports OK')"
```

## 💡 Usage Examples

### Security Operations

```python
# Natural language security queries
"Show me all failed login attempts in the last hour"
"Are there any signs of ransomware activity?"
"Check if our web servers are under attack"
"Generate a security incident timeline for the last 24 hours"
```

### Compliance & Reporting

```python
# Compliance assessments
"Run a PCI DSS compliance check and show gaps"
"Generate an executive security report"
"Check our NIST framework compliance score"
"Show evidence for SOC 2 audit requirements"
```

### Threat Intelligence

```python
# IOC analysis and threat hunting
"Check if IP 192.168.1.100 is malicious"
"Hunt for indicators of lateral movement"
"Analyze this file hash: d41d8cd98f00b204e9800998ecf8427e"
"Show active threat campaigns targeting our industry"
```

## 🚨 Troubleshooting

### Common Issues

**Import Errors:**
```bash
# The server includes automatic import resolution
# If issues persist, run:
python -c "from src.utils.import_resolver import setup_imports; setup_imports(verify=True)"
```

**SSL/Certificate Issues:**
```bash
# Test SSL configuration
python -c "
from src.utils.ssl_config import SSLConfigurationManager
manager = SSLConfigurationManager()
print(manager.auto_detect_ssl_issues('your-host', 55000))
"
```

**Connection Problems:**
```bash
# The server includes intelligent error recovery
# Check logs for recovery attempts and fallback usage
tail -f logs/wazuh_mcp_server.log
```

## 🏗️ Architecture

### Core Components

- **Error Recovery Engine**: Intelligent failure handling with multiple recovery strategies
- **SSL Configuration Manager**: Production-grade certificate and TLS handling
- **Import Resolver**: Cross-platform import path resolution
- **API Client Manager**: High-performance async clients with connection pooling
- **Security Analyzer**: Advanced threat detection and risk assessment
- **Compliance Engine**: Multi-framework compliance checking

### Production Features

- **Circuit Breaker Pattern**: Prevents cascade failures
- **Exponential Backoff**: Smart retry mechanisms with jitter
- **Health Monitoring**: Comprehensive system health checks
- **Performance Metrics**: Real-time operational statistics
- **Graceful Degradation**: Fallback services for high availability

## 📈 Monitoring & Observability

The server provides comprehensive monitoring capabilities:

```python
# Health check endpoint
GET /health
{
  "status": "healthy",
  "components": {
    "wazuh_server": "healthy",
    "wazuh_indexer": "healthy",
    "error_recovery": "active"
  },
  "metrics": {
    "total_requests": 1542,
    "error_rate": 0.02,
    "avg_response_time": 145.3
  }
}

# Error recovery statistics
GET /stats/recovery
{
  "circuit_breakers": {
    "wazuh_server_get": "closed",
    "wazuh_indexer_search": "closed"
  },
  "fallback_usage": {
    "get_alerts": 3,
    "health_check": 1
  }
}
```

## 🤝 Contributing

We welcome contributions from the security community! The codebase is designed for easy extension and modification.

### 🎯 How You Can Help

- **🔍 Security Researchers**: Contribute new threat detection algorithms
- **💻 Developers**: Add integrations, improve performance, enhance reliability
- **🛡️ SOC Analysts**: Share real-world use cases and workflows
- **📚 Technical Writers**: Improve documentation and tutorials

### 🚀 Getting Started

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes with tests
4. Ensure all tests pass (`python -m pytest`)
5. Commit your changes (`git commit -m 'Add AmazingFeature'`)
6. Push to the branch (`git push origin feature/AmazingFeature`)
7. Open a Pull Request

### 🛠️ Development Guidelines

- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation for API changes
- Use type hints for better code clarity
- Include error handling and logging

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

### Special Thanks

**[@marcolinux46](https://github.com/marcolinux46)** for outstanding contributions including thorough testing, detailed log sharing, research, and real-time feedback that enabled rapid identification and resolution of critical production issues.

**Security Community** for continuous feedback and real-world testing that drives our production-grade improvements.

---

<div align="center">

**Built with ❤️ for Production Security Operations**

*"Making enterprise security as natural as having a conversation"*

[![GitHub stars](https://img.shields.io/github/stars/gensecaihq/Wazuh-MCP-Server?style=social)](https://github.com/gensecaihq/Wazuh-MCP-Server/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/gensecaihq/Wazuh-MCP-Server?style=social)](https://github.com/gensecaihq/Wazuh-MCP-Server/network/members)

</div>