# Wazuh 4.8.0 Migration Guide

## Overview

Wazuh 4.8.0 introduced significant API changes that affect how alerts and vulnerabilities are accessed. This guide helps you migrate your Wazuh MCP Server to be compatible with Wazuh 4.8.0 and later versions.

## Key Changes in Wazuh 4.8.0

### Removed Endpoints
- ❌ `GET /alerts` - Moved to Indexer API
- ❌ `GET /vulnerability/{agent_id}` - Moved to Indexer API
- ❌ `PUT /vulnerability` - Removed completely
- ❌ `GET /vulnerability/{agent_id}/last_scan` - Removed completely
- ❌ `GET /vulnerability/{agent_id}/summary/{field}` - Removed completely

### New Data Sources
- ✅ **Alerts**: Now accessed via Wazuh Indexer API using `wazuh-alerts*` index pattern
- ✅ **Vulnerabilities**: Now accessed via Wazuh Indexer API using `wazuh-states-vulnerabilities*` index pattern

## Migration Steps

### 1. Update Your Environment Configuration

#### For Wazuh 4.8.0+ Deployments

Add the following variables to your `.env` file:

```bash
# Wazuh Indexer API Configuration (Required for 4.8.0+)
WAZUH_INDEXER_HOST=your-wazuh-host    # Usually same as WAZUH_HOST
WAZUH_INDEXER_PORT=9200               # Default Indexer port
WAZUH_INDEXER_USER=admin              # Usually same as dashboard login
WAZUH_INDEXER_PASS=your-password      # Usually same as dashboard password
WAZUH_INDEXER_VERIFY_SSL=false        # Set to true in production

# API Behavior Configuration
USE_INDEXER_FOR_ALERTS=true           # Use Indexer for alerts
USE_INDEXER_FOR_VULNERABILITIES=true  # Use Indexer for vulnerabilities
WAZUH_VERSION=4.8.0                   # Optional: Set your version explicitly
```

#### For Mixed Environments (Supporting Both 4.7.x and 4.8.0+)

The MCP server automatically detects the Wazuh version and uses the appropriate API. You can configure both:

```bash
# Server API (Always required)
WAZUH_HOST=your-wazuh-host
WAZUH_PORT=55000
WAZUH_USER=admin
WAZUH_PASS=your-password

# Indexer API (For 4.8.0+ compatibility)
WAZUH_INDEXER_HOST=your-wazuh-host
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your-indexer-password

# Let the system auto-detect and use appropriate APIs
USE_INDEXER_FOR_ALERTS=true
USE_INDEXER_FOR_VULNERABILITIES=true
```

### 2. Test Your Configuration

#### Check Environment Variables
```bash
python scripts/check_env.py
```

#### Test Connections
```bash
python scripts/test_connection.py
```

Expected output for Wazuh 4.8.0+:
```
✓ Detected Wazuh version: v4.8.0
✓ Server API health: healthy
✓ Indexer API health: green
✓ Found 10 agents
✓ Found 150 alerts
  ℹ Using Indexer API for alerts
```

### 3. Update Your Applications

If you're using the MCP server programmatically, the API remains the same. The underlying implementation automatically routes requests to the appropriate API based on:

1. **Detected Wazuh version**
2. **Configuration flags**
3. **API availability**

#### No Code Changes Required

The following methods continue to work unchanged:
- `get_alerts()` - Automatically uses Server API (4.7.x) or Indexer API (4.8.0+)
- `get_agent_vulnerabilities()` - Automatically uses appropriate API
- All other functionality remains the same

## Troubleshooting

### Common Issues

#### 1. "404 Not Found" for Alerts
**Problem**: Using Wazuh 4.8.0+ but alerts endpoint returns 404.

**Solution**: 
- Configure Indexer API credentials in `.env`
- Set `USE_INDEXER_FOR_ALERTS=true`
- Restart the MCP server

#### 2. Authentication Failed for Indexer
**Problem**: Can't authenticate with Wazuh Indexer.

**Solution**:
- Use the same credentials as your Wazuh Dashboard login
- Verify the Indexer is accessible on port 9200
- Check SSL settings (`WAZUH_INDEXER_VERIFY_SSL`)

#### 3. Mixed Version Environment
**Problem**: Some deployments use 4.7.x, others use 4.8.0+.

**Solution**:
- Configure both Server and Indexer APIs
- Enable auto-detection: don't set `WAZUH_VERSION` explicitly
- The system will automatically choose the right API

### Version Detection Debug

To see which APIs are being used:

```bash
# Enable debug logging
DEBUG=true python scripts/test_connection.py
```

Look for log messages like:
- `"Using Indexer API for alerts"`
- `"Using Server API for alerts"`
- `"Detected Wazuh version: v4.8.0"`

## Backward Compatibility

### Wazuh 4.7.x and Earlier
- ✅ Fully supported
- ✅ Uses Server API for all operations
- ✅ No configuration changes required

### Wazuh 4.8.0 and Later
- ✅ Fully supported with proper configuration
- ✅ Automatically uses Indexer API for alerts/vulnerabilities
- ✅ Falls back to Server API if Indexer is unavailable

## Configuration Reference

### Complete .env Example for Wazuh 4.8.0+

```bash
# Server API (Required)
WAZUH_HOST=192.168.1.100
WAZUH_PORT=55000
WAZUH_USER=wazuh-mcp
WAZUH_PASS=strong-password-123
VERIFY_SSL=true
WAZUH_API_VERSION=v4

# Indexer API (Required for 4.8.0+)
WAZUH_INDEXER_HOST=192.168.1.100
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=SecretPassword
WAZUH_INDEXER_VERIFY_SSL=true

# Behavior Configuration
WAZUH_VERSION=4.8.0
USE_INDEXER_FOR_ALERTS=true
USE_INDEXER_FOR_VULNERABILITIES=true

# Performance Tuning
MAX_ALERTS_PER_QUERY=500
REQUEST_TIMEOUT_SECONDS=60
MAX_CONNECTIONS=20

# Logging
LOG_LEVEL=INFO
DEBUG=false
```

## Getting Help

If you encounter issues during migration:

1. **Check the logs**: Enable `DEBUG=true` in your `.env` file
2. **Verify connectivity**: Run `python scripts/test_connection.py`
3. **Check configuration**: Run `python scripts/check_env.py`
4. **Review Wazuh version**: Ensure you know which version you're running
5. **Test APIs separately**: Test Server API and Indexer API independently

## Migration Checklist

- [ ] Updated `.env` file with Indexer API configuration
- [ ] Tested connection with `test_connection.py`
- [ ] Verified environment variables with `check_env.py`
- [ ] Confirmed alerts are working
- [ ] Confirmed vulnerability queries are working
- [ ] Updated any custom scripts or integrations
- [ ] Documented the new configuration for your team
- [ ] Tested in staging environment before production deployment

---

**Note**: This migration maintains full backward compatibility. Existing Wazuh 4.7.x deployments continue to work without any changes, while new 4.8.0+ deployments automatically benefit from the improved Indexer API integration.