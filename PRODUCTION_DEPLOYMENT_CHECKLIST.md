# Production Deployment Checklist: Wazuh 4.8.0+ MCP Server

## Pre-Deployment Requirements

### 🔍 **Environment Verification**
- [ ] **Wazuh Version Confirmed**: Verify exact Wazuh version running in production
  - [ ] `curl -k -u admin:password https://wazuh-server:55000/` 
  - [ ] Version is 4.8.0 or later for full Indexer API support
- [ ] **Network Connectivity**: All required ports accessible
  - [ ] Wazuh Server API: `https://wazuh-host:55000` 
  - [ ] Wazuh Indexer API: `https://wazuh-host:9200`
  - [ ] No firewall blocking between MCP server and Wazuh components

### 🔐 **Security Configuration**
- [ ] **SSL/TLS Configuration**: Production-grade SSL setup
  - [ ] `VERIFY_SSL=true` for both Server and Indexer APIs
  - [ ] Valid SSL certificates installed on Wazuh components
  - [ ] Certificate validation working: `openssl s_client -connect wazuh-host:9200`
- [ ] **Authentication**: Dedicated service accounts configured
  - [ ] Separate API user created (not default admin account)
  - [ ] Strong passwords meeting security policy
  - [ ] Minimum required permissions granted
  - [ ] Indexer credentials configured and tested

### 📋 **Configuration Validation**
- [ ] **Environment Variables**: All required settings configured
  ```bash
  python scripts/check_env.py
  ```
  - [ ] All required variables present and valid
  - [ ] No default/weak passwords in use
  - [ ] SSL settings appropriate for environment
- [ ] **Configuration Testing**: End-to-end connectivity verified
  ```bash
  python scripts/test_connection.py
  ```
  - [ ] Server API connectivity confirmed
  - [ ] Indexer API connectivity confirmed  
  - [ ] Version detection working
  - [ ] Sample alert/vulnerability queries successful

## Deployment Steps

### 🚀 **Application Deployment**
- [ ] **Dependencies**: All required packages installed
  ```bash
  pip install -r requirements.txt
  ```
  - [ ] Python 3.8+ confirmed
  - [ ] All dependencies compatible
  - [ ] No security vulnerabilities in dependencies
- [ ] **File Permissions**: Secure file system permissions
  - [ ] `.env` file permissions: `chmod 600 .env`
  - [ ] Application files owned by service account
  - [ ] Logs directory writable: `/var/log/wazuh-mcp/`

### 🔧 **Runtime Configuration**
- [ ] **Process Management**: Production process supervision
  - [ ] Systemd service file configured
  - [ ] Auto-restart on failure enabled
  - [ ] Resource limits configured (memory, CPU)
  - [ ] Process monitoring configured
- [ ] **Logging Configuration**: Production logging setup
  - [ ] Log level set appropriately (`INFO` or `WARNING`)
  - [ ] Log rotation configured
  - [ ] Structured logging enabled
  - [ ] Log aggregation configured (if applicable)

## Production Validation

### 🧪 **Functional Testing**
- [ ] **API Compatibility**: All endpoints working correctly
  - [ ] Alerts query via appropriate API (Server vs Indexer)
  - [ ] Vulnerabilities query via appropriate API 
  - [ ] Agent status retrieval working
  - [ ] Version detection automatic routing confirmed
- [ ] **Error Handling**: Resilience testing completed
  - [ ] Network interruption recovery tested
  - [ ] Authentication failure handling verified
  - [ ] Circuit breaker functionality tested
  - [ ] Fallback mechanisms working

### 📊 **Performance Validation**
- [ ] **Response Times**: Acceptable performance confirmed
  - [ ] Alert queries < 5 seconds for typical volumes
  - [ ] Health checks < 2 seconds response time
  - [ ] No memory leaks detected in extended testing
- [ ] **Scalability**: Load testing completed
  - [ ] Concurrent request handling verified
  - [ ] Rate limiting working properly
  - [ ] Connection pooling optimized

### 🔍 **Monitoring Setup**
- [ ] **Health Monitoring**: Comprehensive health checks active
  ```bash
  curl http://localhost:8000/health
  ```
  - [ ] Both Server and Indexer API health monitored
  - [ ] Circuit breaker status visible
  - [ ] Error rates tracked
- [ ] **Alerting**: Production alerting configured
  - [ ] High error rate alerts
  - [ ] API unavailability alerts  
  - [ ] Performance degradation alerts
  - [ ] SSL certificate expiration alerts

## Post-Deployment Verification

### ✅ **Production Smoke Tests**
- [ ] **Basic Functionality**: Core features working
  - [ ] MCP server starts successfully
  - [ ] Claude integration working
  - [ ] Alert queries returning expected results
  - [ ] Agent status queries functional
- [ ] **API Routing**: Correct API selection confirmed
  - [ ] Wazuh 4.8+ using Indexer API for alerts/vulnerabilities
  - [ ] Wazuh 4.7.x using Server API (if mixed environment)
  - [ ] Fallback logic working when one API unavailable

### 🔒 **Security Verification**
- [ ] **Access Controls**: Proper security boundaries
  - [ ] No sensitive data in logs
  - [ ] Environment variables not exposed
  - [ ] Network access restricted to required ports
  - [ ] Service running with minimal privileges
- [ ] **Audit Trail**: Security logging active
  - [ ] Authentication events logged
  - [ ] API access logged with proper details
  - [ ] Error events tracked for security analysis

## Operational Readiness

### 📖 **Documentation**
- [ ] **Runbook**: Operations documentation complete
  - [ ] Service restart procedures
  - [ ] Troubleshooting guides
  - [ ] Emergency contacts and escalation paths
  - [ ] Configuration change procedures
- [ ] **Monitoring Playbook**: Alert response procedures
  - [ ] Alert investigation steps
  - [ ] Performance issue diagnosis
  - [ ] API failure troubleshooting

### 🚨 **Incident Response**
- [ ] **Backup Plan**: Rollback strategy prepared
  - [ ] Previous version deployment package ready
  - [ ] Configuration backups available
  - [ ] Rollback procedure tested
- [ ] **Support**: Team readiness confirmed
  - [ ] On-call engineer familiar with deployment
  - [ ] Access to logs and monitoring dashboards
  - [ ] Communication channels established

## Performance Benchmarks

### 📈 **Expected Performance Baselines**
- [ ] **Response Times** (95th percentile):
  - [ ] Alert queries: < 3 seconds
  - [ ] Vulnerability queries: < 5 seconds  
  - [ ] Health checks: < 1 second
  - [ ] Agent status: < 2 seconds
- [ ] **Throughput**:
  - [ ] Concurrent requests: 50+ per minute
  - [ ] Error rate: < 1% under normal load
  - [ ] Availability: > 99.9% uptime target

### 🛠 **Optimization Checkpoints**
- [ ] **Resource Usage**:
  - [ ] Memory usage stable (< 512MB typical)
  - [ ] CPU usage reasonable (< 50% average)
  - [ ] Connection pool efficiency validated
- [ ] **Network Optimization**:
  - [ ] Keep-alive connections enabled
  - [ ] Request compression configured
  - [ ] Timeout values optimized

## Security Hardening

### 🔐 **Production Security Standards**
- [ ] **Network Security**:
  - [ ] TLS 1.2+ enforced for all connections
  - [ ] Certificate validation strict
  - [ ] No deprecated ciphers allowed
- [ ] **Application Security**:
  - [ ] Input validation active on all parameters
  - [ ] SQL injection protections (if applicable)
  - [ ] Rate limiting preventing abuse
  - [ ] Session management secure

### 🛡 **Compliance Requirements**
- [ ] **Data Protection**:
  - [ ] Sensitive data handling procedures
  - [ ] Data retention policies implemented
  - [ ] Access logging for audit requirements
- [ ] **Standards Compliance**:
  - [ ] Industry-specific requirements met
  - [ ] Security framework alignment confirmed
  - [ ] Penetration testing completed (if required)

---

## Deployment Sign-off

### ✍️ **Required Approvals**
- [ ] **Technical Lead**: Code review and architecture approval
- [ ] **Security Team**: Security assessment completed
- [ ] **Operations Team**: Deployment procedure approved
- [ ] **Product Owner**: Feature acceptance confirmed

### 📅 **Deployment Schedule**
- [ ] **Maintenance Window**: Deployment time scheduled
- [ ] **Rollback Time**: Rollback window defined
- [ ] **Stakeholder Communication**: Notifications sent
- [ ] **Go-Live Authorization**: Final approval obtained

### 📊 **Success Criteria**
- [ ] All checklist items completed
- [ ] Smoke tests passing
- [ ] Performance baselines met
- [ ] No critical issues identified
- [ ] Monitoring and alerting active

---

**Deployment Date**: ___________  
**Deployed By**: ___________  
**Approved By**: ___________  
**Production URL**: ___________  

## Emergency Contacts

- **Primary Engineer**: ___________
- **Backup Engineer**: ___________  
- **Operations Team**: ___________
- **Security Team**: ___________

---

*This checklist ensures production-grade deployment of Wazuh MCP Server with Wazuh 4.8.0+ compatibility and operational excellence.*