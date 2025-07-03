# SSL/TLS Troubleshooting Guide - Wazuh MCP Server

## Overview
This guide addresses SSL/TLS connectivity issues that can prevent the Wazuh MCP Server from connecting to Wazuh services.

## Quick SSL Diagnostics

### 🔍 Run SSL Check Script
```bash
# Test all SSL connectivity and configuration
python scripts/check_ssl.py

# Alternative execution methods
python -m scripts.check_ssl
python scripts/run.py ssl-check  # If using launcher
```

### 🩺 Manual SSL Tests
```bash
# Test connectivity to Wazuh Server
openssl s_client -connect your-wazuh-server:55000

# Test connectivity to Wazuh Indexer
openssl s_client -connect your-wazuh-indexer:9200

# Check certificate details
echo | openssl s_client -servername your-wazuh-server -connect your-wazuh-server:55000 2>/dev/null | openssl x509 -text
```

## Common SSL Issues & Solutions

### Issue 1: Certificate Verification Failed

**Symptoms:**
```
SSL: CERTIFICATE_VERIFY_FAILED
SSL verification failed for Indexer API
```

**Solutions:**

#### Option A: Use Custom CA Bundle
```bash
# Download your organization's CA certificate
curl -o wazuh-ca.crt https://your-ca-server/ca.crt

# Configure in .env
WAZUH_CA_BUNDLE_PATH=/path/to/wazuh-ca.crt
WAZUH_INDEXER_CA_BUNDLE_PATH=/path/to/wazuh-ca.crt
```

#### Option B: Temporarily Disable SSL (Development Only)
```bash
# In .env file
VERIFY_SSL=false
WAZUH_INDEXER_VERIFY_SSL=false
```

#### Option C: Allow Self-Signed Certificates (Development Only)
```bash
# In .env file
WAZUH_ALLOW_SELF_SIGNED=true
WAZUH_INDEXER_ALLOW_SELF_SIGNED=true
```

### Issue 2: Python SSL Environment Issues

**Symptoms:**
```
pip SSL errors
requests.exceptions.SSLError
urllib3.exceptions.SSLError
```

**Solutions:**

#### Update Certificate Bundle
```bash
# Update certifi package
pip install --upgrade certifi

# Force certificate bundle update
python -c "import certifi; print(certifi.where())"
pip install --upgrade --force-reinstall certifi
```

#### Set Certificate Environment Variables
```bash
# Linux/macOS
export SSL_CERT_FILE=$(python -c "import certifi; print(certifi.where())")
export REQUESTS_CA_BUNDLE=$(python -c "import certifi; print(certifi.where())")

# Windows PowerShell
$env:SSL_CERT_FILE = python -c "import certifi; print(certifi.where())"
$env:REQUESTS_CA_BUNDLE = python -c "import certifi; print(certifi.where())"
```

#### Corporate Proxy/Firewall
```bash
# In .env file
HTTP_PROXY=http://proxy.company.com:8080
HTTPS_PROXY=http://proxy.company.com:8080
NO_PROXY=localhost,127.0.0.1,your-wazuh-server

# Skip SSL verification for pip (temporary)
pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org package-name
```

### Issue 3: Self-Signed Certificates

**Symptoms:**
```
SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed certificate
```

**Solutions:**

#### Development Environment (Quick Fix)
```bash
# In .env file
WAZUH_ALLOW_SELF_SIGNED=true
WAZUH_INDEXER_ALLOW_SIGNED=true
```

#### Production Environment (Proper Fix)
```bash
# 1. Add self-signed certificate to CA bundle
cat your-self-signed-cert.crt >> /path/to/ca-bundle.pem

# 2. Or create custom CA bundle
python -c "
from src.utils.ssl_helper import create_custom_ca_bundle
create_custom_ca_bundle(['/path/to/your-cert.crt'])
"

# 3. Configure custom bundle
WAZUH_CA_BUNDLE_PATH=/path/to/custom_ca_bundle.pem
```

### Issue 4: Client Certificate Authentication

**Configuration:**
```bash
# Generate client certificate (if needed)
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -out client.crt

# Configure in .env
WAZUH_CLIENT_CERT_PATH=/path/to/client.crt
WAZUH_CLIENT_KEY_PATH=/path/to/client.key
WAZUH_INDEXER_CLIENT_CERT_PATH=/path/to/indexer-client.crt
WAZUH_INDEXER_CLIENT_KEY_PATH=/path/to/indexer-client.key
```

## Platform-Specific Issues

### Windows

**Certificate Store Issues:**
```powershell
# Update Windows certificate store
certlm.msc  # Manual certificate management

# Or use PowerShell
Import-Certificate -FilePath "C:\path\to\cert.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

**Python Installation Issues:**
```powershell
# Reinstall Python with SSL support
# Download from python.org (includes SSL libraries)

# Or update certificates
pip install --upgrade certifi requests urllib3
```

### Linux

**System Certificate Issues:**
```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install ca-certificates
sudo update-ca-certificates

# CentOS/RHEL/Fedora
sudo yum update ca-certificates
# or
sudo dnf update ca-certificates

# Add custom certificate
sudo cp your-cert.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

### macOS

**Keychain Issues:**
```bash
# Add certificate to system keychain
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain your-cert.crt

# Or user keychain
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain your-cert.crt

# Update certificates
brew install ca-certificates
```

## Environment Variables Reference

### Basic SSL Configuration
```bash
# Enable/disable SSL verification
VERIFY_SSL=true
WAZUH_INDEXER_VERIFY_SSL=true

# SSL timeout
WAZUH_SSL_TIMEOUT=30
```

### Advanced SSL Configuration
```bash
# Custom CA bundles
WAZUH_CA_BUNDLE_PATH=/path/to/ca-bundle.pem
WAZUH_INDEXER_CA_BUNDLE_PATH=/path/to/indexer-ca-bundle.pem

# Client certificates
WAZUH_CLIENT_CERT_PATH=/path/to/client.crt
WAZUH_CLIENT_KEY_PATH=/path/to/client.key
WAZUH_INDEXER_CLIENT_CERT_PATH=/path/to/indexer-client.crt
WAZUH_INDEXER_CLIENT_KEY_PATH=/path/to/indexer-client.key

# Self-signed certificates (development only)
WAZUH_ALLOW_SELF_SIGNED=false
WAZUH_INDEXER_ALLOW_SELF_SIGNED=false
```

### System Environment Variables
```bash
# Python certificate bundle
SSL_CERT_FILE=/path/to/ca-bundle.pem
REQUESTS_CA_BUNDLE=/path/to/ca-bundle.pem

# Proxy configuration
HTTP_PROXY=http://proxy.company.com:8080
HTTPS_PROXY=http://proxy.company.com:8080
NO_PROXY=localhost,127.0.0.1
```

## Testing SSL Configuration

### Test Suite
```bash
# Run comprehensive SSL tests
make test-ssl              # If using Makefile
python scripts/check_ssl.py  # Direct execution

# Test connection after changes
python scripts/run.py test
wazuh-mcp-test            # If installed
```

### Manual Verification
```bash
# Test Python SSL
python -c "
import ssl
import socket
context = ssl.create_default_context()
with socket.create_connection(('your-wazuh-server', 55000)) as sock:
    with context.wrap_socket(sock, server_hostname='your-wazuh-server') as ssock:
        print('SSL connection successful')
        print('Certificate:', ssock.getpeercert()['subject'])
"
```

## Production Recommendations

### Security Best Practices
1. **Always enable SSL verification in production**
2. **Use proper CA-signed certificates**
3. **Rotate certificates regularly**
4. **Monitor certificate expiration**
5. **Use client certificates for additional security**

### Certificate Management
```bash
# Monitor certificate expiration
python -c "
from src.utils.ssl_helper import check_ssl_connectivity
result = check_ssl_connectivity('your-wazuh-server', 55000)
cert = result['certificate_info']
print(f'Certificate expires: {cert[\"not_after\"]}')
print(f'Is expired: {cert[\"is_expired\"]}')
"

# Automated certificate renewal (example)
# Add to cron job or monitoring system
0 0 * * * /path/to/check-cert-expiry.sh
```

### Troubleshooting Checklist

- [ ] Verify network connectivity (ping, telnet)
- [ ] Check firewall rules (ports 55000, 9200)
- [ ] Validate certificate chain
- [ ] Test with openssl s_client
- [ ] Check Python SSL environment
- [ ] Verify CA bundle integrity
- [ ] Test with SSL verification disabled (temporarily)
- [ ] Check proxy/corporate firewall settings
- [ ] Validate certificate dates (not expired)
- [ ] Test client certificate authentication (if used)

## Getting Help

### Log Analysis
```bash
# Enable debug logging
DEBUG=true
LOG_LEVEL=DEBUG

# Check logs for SSL errors
grep -i ssl /path/to/logs
grep -i certificate /path/to/logs
```

### Support Resources
- [Wazuh SSL Documentation](https://documentation.wazuh.com/current/user-manual/certificates.html)
- [Python SSL Documentation](https://docs.python.org/3/library/ssl.html)
- [OpenSSL Documentation](https://www.openssl.org/docs/)

### Common Error Messages
| Error Message | Likely Cause | Solution |
|---------------|--------------|----------|
| `CERTIFICATE_VERIFY_FAILED` | Invalid certificate chain | Add CA certificate to bundle |
| `certificate verify failed: self signed certificate` | Self-signed certificate | Allow self-signed or add to CA bundle |
| `SSL: WRONG_VERSION_NUMBER` | Non-SSL connection to SSL port | Check port configuration |
| `Connection refused` | Service not running or firewall | Check service status and firewall |
| `certificate verify failed: certificate has expired` | Expired certificate | Renew certificate |
| `hostname doesn't match` | Certificate hostname mismatch | Use correct hostname or disable hostname check |

This guide covers the most common SSL/TLS issues. For complex scenarios, consider consulting your network security team or Wazuh support.