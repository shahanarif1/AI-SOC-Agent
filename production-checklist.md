# Wazuh MCP Server - Production Deployment Checklist

## 🔧 Pre-Deployment Configuration

### ✅ Environment Configuration
- [ ] Copy `.env.example` to `.env`
- [ ] Replace all placeholder values in `.env` with production values:
  - [ ] `WAZUH_HOST` - Production Wazuh server IP/hostname
  - [ ] `WAZUH_USER` - Production API username (not admin)
  - [ ] `WAZUH_PASS` - Strong, unique password
  - [ ] `WAZUH_INDEXER_HOST` - Production Indexer IP/hostname
  - [ ] `WAZUH_INDEXER_USER` - Indexer username
  - [ ] `WAZUH_INDEXER_PASS` - Indexer password
- [ ] Set secure file permissions: `chmod 600 .env`
- [ ] Verify `DEBUG=false` in production
- [ ] Set appropriate `LOG_LEVEL` (INFO or WARNING)

### ✅ Security Configuration
- [ ] Enable SSL verification: `VERIFY_SSL=true` (if you have valid certificates)
- [ ] Configure custom CA bundle if using internal certificates
- [ ] Review and set `WAZUH_ALLOW_SELF_SIGNED=false` if possible
- [ ] Change default ports if required by security policy
- [ ] Configure rate limiting: `RATE_LIMIT_PER_MINUTE=60`
- [ ] Set up API key rotation schedule

### ✅ Performance Configuration
- [ ] Tune `MAX_ALERTS_PER_QUERY` based on system capacity
- [ ] Set `MAX_AGENTS_PER_SCAN` based on network capacity
- [ ] Configure `CACHE_TTL_SECONDS` for optimal performance
- [ ] Adjust `REQUEST_TIMEOUT_SECONDS` for network conditions
- [ ] Set `MAX_CONNECTIONS` and `POOL_SIZE` appropriately

## 🖥️ System Requirements

### ✅ Hardware Requirements
- [ ] Minimum 2GB RAM (4GB+ recommended)
- [ ] Minimum 2 CPU cores (4+ recommended)
- [ ] Minimum 10GB free disk space
- [ ] Network connectivity to Wazuh servers (ports 55000, 9200)

### ✅ Software Requirements
- [ ] Python 3.8+ installed
- [ ] Virtual environment created and activated
- [ ] All dependencies installed: `pip install -r requirements-prod.txt`
- [ ] System monitoring tools available (htop, iostat)

## 🔒 Security Hardening

### ✅ System Security
- [ ] Run as non-root user (create dedicated service user)
- [ ] Configure firewall rules (allow only necessary ports)
- [ ] Set up fail2ban or similar intrusion prevention
- [ ] Enable system audit logging
- [ ] Configure log rotation and retention

### ✅ Application Security
- [ ] Remove or secure development endpoints
- [ ] Implement request rate limiting
- [ ] Set up security headers
- [ ] Configure CORS appropriately
- [ ] Enable audit logging: `AUDIT_LOG_ENABLED=true`
- [ ] Set up security monitoring alerts

### ✅ Network Security
- [ ] Use TLS 1.2+ for all connections
- [ ] Validate SSL certificates in production
- [ ] Configure network segmentation
- [ ] Set up VPN access if required
- [ ] Monitor network traffic for anomalies

## 📊 Monitoring and Logging

### ✅ Application Monitoring
- [ ] Configure structured logging: `LOG_FORMAT=json`
- [ ] Set up log aggregation (ELK, Splunk, etc.)
- [ ] Enable Prometheus metrics: `ENABLE_PROMETHEUS_METRICS=true`
- [ ] Configure health check endpoints
- [ ] Set up application performance monitoring (APM)

### ✅ System Monitoring
- [ ] Monitor CPU, memory, and disk usage
- [ ] Set up alerts for resource thresholds
- [ ] Monitor network connectivity to Wazuh servers
- [ ] Track application response times
- [ ] Monitor error rates and patterns

### ✅ Security Monitoring
- [ ] Monitor authentication failures
- [ ] Track API usage patterns
- [ ] Set up alerts for suspicious activity
- [ ] Monitor SSL certificate expiration
- [ ] Log all configuration changes

## 🚀 Deployment Process

### ✅ Pre-Deployment Testing
- [ ] Run validation script: `python validate_setup.py`
- [ ] Verify all checks pass (score >= 95%)
- [ ] Test connectivity to all Wazuh services
- [ ] Perform load testing
- [ ] Validate configuration with staging environment

### ✅ Deployment Steps
- [ ] Create backup of previous version
- [ ] Deploy code to production server
- [ ] Install/update dependencies
- [ ] Copy production configuration files
- [ ] Run database migrations (if applicable)
- [ ] Start services using process manager (systemd, supervisor)
- [ ] Verify deployment health

### ✅ Post-Deployment Verification
- [ ] Verify all services are running
- [ ] Test critical functionality
- [ ] Check log files for errors
- [ ] Verify monitoring is active
- [ ] Test failover procedures
- [ ] Update documentation

## 🔄 Operational Procedures

### ✅ Backup and Recovery
- [ ] Implement automated backups
- [ ] Test backup restoration procedures
- [ ] Document recovery processes
- [ ] Set up off-site backup storage
- [ ] Define Recovery Time Objective (RTO)
- [ ] Define Recovery Point Objective (RPO)

### ✅ Maintenance Procedures
- [ ] Schedule regular security updates
- [ ] Plan for certificate renewals
- [ ] Implement API key rotation
- [ ] Regular configuration reviews
- [ ] Performance optimization reviews
- [ ] Disaster recovery testing

### ✅ Incident Response
- [ ] Define incident response procedures
- [ ] Set up alerting and escalation
- [ ] Create runbooks for common issues
- [ ] Implement emergency shutdown procedures
- [ ] Document rollback procedures
- [ ] Set up communication channels

## 📋 Compliance and Governance

### ✅ Documentation
- [ ] Update deployment documentation
- [ ] Document configuration changes
- [ ] Maintain security procedures
- [ ] Update emergency contacts
- [ ] Review and update policies

### ✅ Compliance Requirements
- [ ] Data retention policies implemented
- [ ] Privacy controls in place (GDPR, CCPA)
- [ ] Audit trail maintained
- [ ] Security assessments completed
- [ ] Regulatory requirements met

## 🎯 Performance Optimization

### ✅ Application Performance
- [ ] Enable connection pooling
- [ ] Implement caching strategies
- [ ] Optimize database queries
- [ ] Use async processing where possible
- [ ] Monitor and optimize memory usage

### ✅ Infrastructure Performance
- [ ] Configure load balancing (if multiple instances)
- [ ] Optimize network settings
- [ ] Use SSD storage for logs and cache
- [ ] Configure appropriate swap settings
- [ ] Optimize container resources (if using containers)

## ✅ Final Production Readiness

### ✅ Go-Live Checklist
- [ ] All checklist items completed
- [ ] Validation score >= 95%
- [ ] Stakeholder approval obtained
- [ ] Support team trained
- [ ] Monitoring dashboard configured
- [ ] Emergency procedures tested
- [ ] Communication plan activated

### ✅ Post-Go-Live
- [ ] Monitor for 24-48 hours continuously
- [ ] Verify all alerts are working
- [ ] Check performance metrics
- [ ] Validate security controls
- [ ] Review logs for issues
- [ ] Update status page/documentation

---

## 🚨 Emergency Contacts

- **Technical Lead**: [Name] - [Email] - [Phone]
- **Security Team**: [Email] - [Phone]
- **Infrastructure Team**: [Email] - [Phone]
- **On-Call Engineer**: [Phone]

## 📞 Support Escalation

1. **Level 1**: Application issues, configuration problems
2. **Level 2**: Infrastructure issues, performance problems
3. **Level 3**: Security incidents, critical system failures

---

*Last Updated: Generated by validate_setup.py*
*Review Date: [Insert quarterly review date]*