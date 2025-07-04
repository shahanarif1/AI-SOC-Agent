# Configuration Reference - Wazuh MCP Server

## Overview

This document provides comprehensive configuration options for the Wazuh MCP Server, including environment variables, configuration files, and advanced settings for both local and production deployments.

## Table of Contents

1. [Environment Variables](#environment-variables)
2. [Configuration Files](#configuration-files)
3. [Security Configuration](#security-configuration)
4. [Performance Tuning](#performance-tuning)
5. [Logging Configuration](#logging-configuration)
6. [Integration Settings](#integration-settings)
7. [Platform-Specific Settings](#platform-specific-settings)

---

## Environment Variables

### Core Wazuh Settings

#### `WAZUH_HOST` (Required)
**Description:** Hostname or IP address of the Wazuh server  
**Default:** None  
**Example:** `wazuh.company.com`, `192.168.1.100`

#### `WAZUH_PORT`
**Description:** Port number for Wazuh API  
**Default:** `55000`  
**Example:** `55000`, `8080`

#### `WAZUH_USER` (Required)
**Description:** Username for Wazuh API authentication  
**Default:** None  
**Example:** `wazuh-api-user`

#### `WAZUH_PASS` (Required)
**Description:** Password for Wazuh API authentication  
**Default:** None  
**Example:** `secure-password-123`

#### `WAZUH_PROTOCOL`
**Description:** Protocol for Wazuh API communication  
**Default:** `https`  
**Options:** `http`, `https`

#### `VERIFY_SSL`
**Description:** Enable SSL certificate verification  
**Default:** `true`  
**Options:** `true`, `false`  
**Note:** Set to `false` only for development with self-signed certificates

#### `CA_BUNDLE_PATH`
**Description:** Path to custom CA bundle for SSL verification  
**Default:** None  
**Example:** `/path/to/ca-bundle.pem`

### Wazuh Indexer Settings (4.8.0+)

#### `WAZUH_INDEXER_HOST`
**Description:** Hostname or IP of Wazuh Indexer  
**Default:** None  
**Example:** `wazuh-indexer.company.com`

#### `WAZUH_INDEXER_PORT`
**Description:** Port for Wazuh Indexer  
**Default:** `9200`  
**Example:** `9200`, `9443`

#### `WAZUH_INDEXER_USER`
**Description:** Username for Wazuh Indexer  
**Default:** `admin`  
**Example:** `indexer-user`

#### `WAZUH_INDEXER_PASS`
**Description:** Password for Wazuh Indexer  
**Default:** None  
**Example:** `indexer-password`

#### `USE_INDEXER_FOR_ALERTS`
**Description:** Use Indexer for alert queries  
**Default:** `false`  
**Options:** `true`, `false`

#### `USE_INDEXER_FOR_VULNERABILITIES`
**Description:** Use Indexer for vulnerability queries  
**Default:** `false`  
**Options:** `true`, `false`

### Authentication & Security

#### `JWT_SECRET`
**Description:** Secret key for JWT token generation  
**Default:** Auto-generated secure random string  
**Example:** `your-very-secure-jwt-secret-key`  
**Note:** Must be at least 32 characters for production

#### `JWT_EXPIRY_HOURS`
**Description:** JWT token expiration time in hours  
**Default:** `24`  
**Example:** `24`, `168` (1 week)

#### `API_KEYS`
**Description:** Comma-separated list of API keys with roles  
**Format:** `key1:username1:role1,key2:username2:role2`  
**Default:** None  
**Example:** `prod-key:admin:admin,dev-key:developer:user`

#### `ENABLE_AUTH`
**Description:** Enable authentication for HTTP/WebSocket APIs  
**Default:** `true`  
**Options:** `true`, `false`

#### `CORS_ORIGINS`
**Description:** Comma-separated list of allowed CORS origins  
**Default:** `*`  
**Example:** `https://app.company.com,https://dashboard.company.com`

### Rate Limiting

#### `RATE_LIMIT_ENABLED`
**Description:** Enable rate limiting  
**Default:** `true`  
**Options:** `true`, `false`

#### `RATE_LIMIT_REQUESTS`
**Description:** Maximum requests per time window  
**Default:** `100`  
**Example:** `50`, `200`

#### `RATE_LIMIT_WINDOW`
**Description:** Time window in seconds  
**Default:** `60`  
**Example:** `60`, `300`

#### `RATE_LIMIT_ADMIN_REQUESTS`
**Description:** Rate limit for admin users  
**Default:** `500`  
**Example:** `500`, `1000`

### Logging Configuration

#### `LOG_LEVEL`
**Description:** Logging level  
**Default:** `INFO`  
**Options:** `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`

#### `LOG_FORMAT`
**Description:** Log format style  
**Default:** `detailed`  
**Options:** `simple`, `detailed`, `json`

#### `LOG_FILE`
**Description:** Path to log file  
**Default:** Platform-specific (see platform settings)  
**Example:** `/var/log/wazuh-mcp/server.log`

#### `LOG_ROTATION`
**Description:** Enable log rotation  
**Default:** `true`  
**Options:** `true`, `false`

#### `LOG_MAX_SIZE`
**Description:** Maximum log file size in MB  
**Default:** `10`  
**Example:** `10`, `50`

#### `LOG_BACKUP_COUNT`
**Description:** Number of backup log files to keep  
**Default:** `5`  
**Example:** `5`, `10`

### Performance Settings

#### `MAX_CONCURRENT_REQUESTS`
**Description:** Maximum concurrent requests  
**Default:** `50`  
**Example:** `50`, `100`

#### `REQUEST_TIMEOUT`
**Description:** Request timeout in seconds  
**Default:** `30`  
**Example:** `30`, `60`

#### `CACHE_ENABLED`
**Description:** Enable response caching  
**Default:** `true`  
**Options:** `true`, `false`

#### `CACHE_TTL`
**Description:** Cache time-to-live in seconds  
**Default:** `300`  
**Example:** `300`, `600`

#### `WORKER_THREADS`
**Description:** Number of worker threads  
**Default:** `4`  
**Example:** `4`, `8`

### Production Deployment

#### `DOMAIN`
**Description:** Domain name for SSL certificates  
**Default:** None  
**Example:** `mcp.company.com`

#### `ACME_EMAIL`
**Description:** Email for Let's Encrypt certificates  
**Default:** None  
**Example:** `admin@company.com`

#### `REDIS_HOST`
**Description:** Redis host for session storage  
**Default:** `redis`  
**Example:** `redis.company.com`

#### `REDIS_PORT`
**Description:** Redis port  
**Default:** `6379`  
**Example:** `6379`

#### `REDIS_PASSWORD`
**Description:** Redis password  
**Default:** None  
**Example:** `secure-redis-password`

#### `GRAFANA_PASSWORD`
**Description:** Grafana admin password  
**Default:** `admin`  
**Example:** `secure-grafana-password`

### External Integrations

#### `VIRUSTOTAL_API_KEY`
**Description:** VirusTotal API key for threat intelligence  
**Default:** None  
**Example:** `your-virustotal-api-key`

#### `SHODAN_API_KEY`
**Description:** Shodan API key for IP intelligence  
**Default:** None  
**Example:** `your-shodan-api-key`

#### `ABUSEIPDB_API_KEY`
**Description:** AbuseIPDB API key for IP reputation  
**Default:** None  
**Example:** `your-abuseipdb-api-key`

#### `CORTEX_API_URL`
**Description:** Cortex analyzer API URL  
**Default:** None  
**Example:** `https://cortex.company.com/api`

#### `CORTEX_API_KEY`
**Description:** Cortex API key  
**Default:** None  
**Example:** `your-cortex-api-key`

---

## Configuration Files

### `.env` File Structure

```env
# Core Wazuh Configuration
WAZUH_HOST=wazuh.company.com
WAZUH_PORT=55000
WAZUH_USER=api-user
WAZUH_PASS=secure-password
VERIFY_SSL=true

# Wazuh Indexer (4.8.0+)
WAZUH_INDEXER_HOST=wazuh-indexer.company.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=indexer-password
USE_INDEXER_FOR_ALERTS=true

# Security
JWT_SECRET=your-very-secure-jwt-secret-key
API_KEYS=prod-key:admin:admin,dev-key:developer:user
ENABLE_AUTH=true

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=detailed

# Performance
MAX_CONCURRENT_REQUESTS=50
REQUEST_TIMEOUT=30
CACHE_ENABLED=true
CACHE_TTL=300

# External Integrations
VIRUSTOTAL_API_KEY=your-vt-key
SHODAN_API_KEY=your-shodan-key
```

### JSON Configuration (Advanced)

Create `config.json` in the project root for advanced configuration:

```json
{
  "wazuh": {
    "host": "wazuh.company.com",
    "port": 55000,
    "user": "api-user",
    "password": "secure-password",
    "protocol": "https",
    "verify_ssl": true,
    "timeout": 30
  },
  "indexer": {
    "host": "wazuh-indexer.company.com",
    "port": 9200,
    "user": "admin",
    "password": "indexer-password",
    "use_for_alerts": true,
    "use_for_vulnerabilities": true
  },
  "security": {
    "jwt_secret": "your-jwt-secret",
    "jwt_expiry_hours": 24,
    "api_keys": {
      "prod-key": {"username": "admin", "role": "admin"},
      "dev-key": {"username": "developer", "role": "user"}
    },
    "cors_origins": ["https://app.company.com"]
  },
  "rate_limiting": {
    "enabled": true,
    "requests": 100,
    "window": 60,
    "admin_requests": 500
  },
  "logging": {
    "level": "INFO",
    "format": "detailed",
    "file": "/var/log/wazuh-mcp/server.log",
    "rotation": true,
    "max_size": 10,
    "backup_count": 5
  },
  "performance": {
    "max_concurrent_requests": 50,
    "request_timeout": 30,
    "cache_enabled": true,
    "cache_ttl": 300,
    "worker_threads": 4
  },
  "integrations": {
    "virustotal": {
      "api_key": "your-vt-key",
      "enabled": true
    },
    "shodan": {
      "api_key": "your-shodan-key",
      "enabled": true
    },
    "cortex": {
      "url": "https://cortex.company.com/api",
      "api_key": "your-cortex-key",
      "enabled": false
    }
  }
}
```

---

## Security Configuration

### SSL/TLS Settings

#### Development (Self-Signed Certificates)
```env
VERIFY_SSL=false
WAZUH_PROTOCOL=https
```

#### Production (Valid Certificates)
```env
VERIFY_SSL=true
CA_BUNDLE_PATH=/path/to/ca-bundle.pem
WAZUH_PROTOCOL=https
```

#### Custom CA Bundle
```env
VERIFY_SSL=true
CA_BUNDLE_PATH=/etc/ssl/certs/company-ca-bundle.pem
```

### Authentication Best Practices

#### Strong JWT Secret Generation
```bash
# Generate secure JWT secret
openssl rand -base64 32
```

#### API Key Generation
```bash
# Generate secure API keys
openssl rand -hex 32
```

#### Role-Based Access Control
```env
# Format: key:username:role
API_KEYS=admin_$(openssl rand -hex 16):admin:admin,user_$(openssl rand -hex 16):user:user
```

### Network Security

#### CORS Configuration
```env
# Specific origins (recommended)
CORS_ORIGINS=https://app.company.com,https://dashboard.company.com

# Development only
CORS_ORIGINS=*
```

#### Rate Limiting by Role
```env
# Admin users get higher limits
RATE_LIMIT_ADMIN_REQUESTS=500
RATE_LIMIT_REQUESTS=100
```

---

## Performance Tuning

### Memory Optimization

#### Low Memory Environment
```env
MAX_CONCURRENT_REQUESTS=25
WORKER_THREADS=2
CACHE_ENABLED=false
```

#### High Memory Environment
```env
MAX_CONCURRENT_REQUESTS=100
WORKER_THREADS=8
CACHE_ENABLED=true
CACHE_TTL=600
```

### Network Optimization

#### High Latency Network
```env
REQUEST_TIMEOUT=60
WAZUH_TIMEOUT=45
```

#### Low Latency Network
```env
REQUEST_TIMEOUT=15
WAZUH_TIMEOUT=10
```

### Caching Strategy

#### Aggressive Caching
```env
CACHE_ENABLED=true
CACHE_TTL=600
CACHE_SIZE=100
```

#### Conservative Caching
```env
CACHE_ENABLED=true
CACHE_TTL=60
CACHE_SIZE=50
```

---

## Logging Configuration

### Log Levels

#### Production
```env
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE=/var/log/wazuh-mcp/server.log
```

#### Development
```env
LOG_LEVEL=DEBUG
LOG_FORMAT=detailed
LOG_FILE=./logs/debug.log
```

#### Troubleshooting
```env
LOG_LEVEL=DEBUG
LOG_FORMAT=detailed
DEBUG=true
```

### Log Rotation

#### Daily Rotation
```env
LOG_ROTATION=true
LOG_MAX_SIZE=50
LOG_BACKUP_COUNT=30
```

#### Weekly Rotation
```env
LOG_ROTATION=true
LOG_MAX_SIZE=100
LOG_BACKUP_COUNT=4
```

---

## Integration Settings

### Threat Intelligence

#### VirusTotal Configuration
```env
VIRUSTOTAL_API_KEY=your-api-key
VIRUSTOTAL_ENABLED=true
VIRUSTOTAL_RATE_LIMIT=4
```

#### Shodan Configuration
```env
SHODAN_API_KEY=your-api-key
SHODAN_ENABLED=true
SHODAN_TIMEOUT=30
```

### External Analysis

#### Cortex Integration
```env
CORTEX_API_URL=https://cortex.company.com/api
CORTEX_API_KEY=your-api-key
CORTEX_ENABLED=true
CORTEX_TIMEOUT=300
```

---

## Platform-Specific Settings

### Windows

#### Default Paths
```env
LOG_FILE=%APPDATA%\WazuhMCP\logs\server.log
CONFIG_DIR=%APPDATA%\WazuhMCP\config
```

#### Service Installation
```env
SERVICE_NAME=WazuhMCPServer
SERVICE_DISPLAY_NAME=Wazuh MCP Server
SERVICE_DESCRIPTION=Wazuh MCP Server for AI Integration
```

### macOS

#### Default Paths
```env
LOG_FILE=~/Library/Logs/WazuhMCP/server.log
CONFIG_DIR=~/Library/Application Support/WazuhMCP
```

#### LaunchAgent Configuration
```env
LAUNCH_AGENT_ENABLED=true
LAUNCH_AGENT_INTERVAL=30
```

### Linux

#### Default Paths
```env
LOG_FILE=/var/log/wazuh-mcp/server.log
CONFIG_DIR=/etc/wazuh-mcp
```

#### Systemd Service
```env
SYSTEMD_ENABLED=true
SYSTEMD_USER=wazuh-mcp
SYSTEMD_GROUP=wazuh-mcp
```

---

## Configuration Validation

### Validation Commands

#### Check Configuration
```bash
# Validate configuration
python -m wazuh_mcp_server --validate-config

# Test Wazuh connection
python -m wazuh_mcp_server --test-connection

# Check all integrations
python -m wazuh_mcp_server --test-integrations
```

#### Configuration Diagnostics
```bash
# Full diagnostic report
python -m wazuh_mcp_server --diagnostics

# Export configuration (sanitized)
python -m wazuh_mcp_server --export-config
```

### Common Configuration Issues

#### SSL Certificate Issues
```bash
# Test SSL connection
curl -I https://wazuh.company.com:55000/

# Check certificate details
openssl s_client -connect wazuh.company.com:55000 -showcerts
```

#### Authentication Problems
```bash
# Test API credentials
curl -u username:password https://wazuh.company.com:55000/

# Verify JWT secret
python -c "import secrets; print(f'Strong secret: {len(secrets.token_hex(32)) >= 32}')"
```

---

## Environment Templates

### `.env.local` (Local Development)
```env
# Wazuh Configuration
WAZUH_HOST=localhost
WAZUH_PORT=55000
WAZUH_USER=wazuh
WAZUH_PASS=wazuh
VERIFY_SSL=false

# Logging
LOG_LEVEL=DEBUG
LOG_FORMAT=detailed

# Performance
MAX_CONCURRENT_REQUESTS=10
CACHE_ENABLED=false
```

### `.env.production` (Production)
```env
# Wazuh Configuration
WAZUH_HOST=wazuh-prod.company.com
WAZUH_PORT=55000
WAZUH_USER=mcp-api-user
WAZUH_PASS=your-secure-password
VERIFY_SSL=true

# Security
JWT_SECRET=your-very-secure-jwt-secret-key
API_KEYS=prod_key:admin:admin
ENABLE_AUTH=true

# Domain
DOMAIN=mcp.company.com
ACME_EMAIL=admin@company.com

# Performance
MAX_CONCURRENT_REQUESTS=100
CACHE_ENABLED=true
CACHE_TTL=300

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE=/var/log/wazuh-mcp/server.log
```

### `.env.testing` (Testing/Staging)
```env
# Wazuh Configuration
WAZUH_HOST=wazuh-test.company.com
WAZUH_PORT=55000
WAZUH_USER=test-user
WAZUH_PASS=test-password
VERIFY_SSL=true

# Security
JWT_SECRET=test-jwt-secret
API_KEYS=test_key:tester:user
ENABLE_AUTH=true

# Performance
MAX_CONCURRENT_REQUESTS=25
CACHE_ENABLED=true
CACHE_TTL=60

# Logging
LOG_LEVEL=DEBUG
LOG_FORMAT=detailed
```

---

## Best Practices

1. **Security**: Always use strong, unique passwords and API keys
2. **SSL**: Enable SSL verification in production environments
3. **Logging**: Use appropriate log levels for different environments
4. **Performance**: Tune settings based on your infrastructure capacity
5. **Monitoring**: Enable comprehensive logging and monitoring
6. **Backup**: Backup configuration files regularly
7. **Validation**: Validate configuration before deployment
8. **Documentation**: Document custom configuration changes

---

**Configuration Version:** 1.0.0  
**Last Updated:** January 2024  
**Compatible with:** Wazuh 4.5.0+, Python 3.9+