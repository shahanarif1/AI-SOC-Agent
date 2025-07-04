# Disaster Recovery Plan - Wazuh MCP Server

## Overview

This document provides comprehensive disaster recovery procedures for the Wazuh MCP Server production deployment. It ensures business continuity with minimal downtime during system failures, data corruption, security incidents, or infrastructure outages.

### Document Scope

This plan covers:
- **Service Interruptions**: Container failures, application crashes
- **Data Loss**: Database corruption, volume failures
- **Infrastructure Failures**: Server hardware, network, storage issues
- **Security Incidents**: Breach response, data integrity issues
- **Human Error**: Configuration mistakes, accidental deletions

### Roles and Responsibilities

- **Operations Team**: Execute recovery procedures, monitor systems
- **Security Team**: Assess security implications, validate data integrity
- **Management**: Business continuity decisions, external communications
- **DevOps Team**: Infrastructure recovery, performance optimization

## Recovery Objectives

- **Recovery Time Objective (RTO)**: 15 minutes
- **Recovery Point Objective (RPO)**: 1 hour
- **Maximum Tolerable Downtime**: 1 hour

## Backup Strategy

### Automated Backups

Daily automated backups are performed using the included backup scripts:

```bash
# Automated daily backup (add to crontab)
0 2 * * * /path/to/Wazuh-MCP-Server/scripts/backup.sh
```

### Backup Components

1. **Configuration Files**
   - Environment files (`.env.production`, `.env`)
   - Docker Compose configuration
   - SSL certificates (Let's Encrypt, custom)
   - Monitoring configuration

2. **Persistent Data**
   - Prometheus metrics data
   - Grafana dashboards and settings
   - Redis session data
   - Application logs

3. **System State**
   - Docker container configurations
   - Volume mappings
   - Network configurations

### Backup Retention

- **Daily backups**: Retained for 30 days
- **Weekly backups**: Retained for 12 weeks
- **Monthly backups**: Retained for 12 months

## Disaster Scenarios & Recovery Procedures

### Scenario 1: Service Failure (containers crash)

**Symptoms**: Services not responding, containers exited

**Recovery Steps**:
```bash
# 1. Check service status
docker-compose ps

# 2. Restart failed services
docker-compose restart

# 3. If restart fails, recreate services
docker-compose down
docker-compose up -d

# 4. Verify recovery
curl -k https://localhost/health
```

**Expected Recovery Time**: 2-5 minutes

### Scenario 2: Configuration Corruption

**Symptoms**: Services fail to start due to invalid configuration

**Recovery Steps**:
```bash
# 1. Stop services
docker-compose down

# 2. Restore configuration from latest backup
./scripts/restore.sh <backup-name> --config-only

# 3. Start services
docker-compose up -d

# 4. Verify services are healthy
./scripts/health-check.sh
```

**Expected Recovery Time**: 5-10 minutes

### Scenario 3: Data Volume Corruption

**Symptoms**: Monitoring dashboards lost, metrics missing

**Recovery Steps**:
```bash
# 1. Stop services to prevent further corruption
docker-compose down

# 2. Restore data volumes from backup
./scripts/restore.sh <backup-name> --data-only

# 3. Start services
docker-compose up -d

# 4. Verify data integrity
# Check Grafana dashboards, Prometheus metrics
```

**Expected Recovery Time**: 10-15 minutes

### Scenario 4: Complete System Failure

**Symptoms**: Server hardware failure, OS corruption, complete data loss

**Recovery Steps**:
```bash
# On new/restored system:

# 1. Install prerequisites
# - Docker and Docker Compose
# - Git

# 2. Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# 3. Copy backup files to new system
scp -r backup-server:/backups/* ./backups/

# 4. Full restore from latest backup
./scripts/restore.sh <latest-backup-name>

# 5. Verify complete system recovery
./scripts/health-check.sh
```

**Expected Recovery Time**: 30-60 minutes

### Scenario 5: Network/DNS Issues

**Symptoms**: SSL certificate errors, external connectivity issues

**Recovery Steps**:
```bash
# 1. Check DNS resolution
nslookup your-domain.com

# 2. Check SSL certificate status
openssl x509 -in letsencrypt/live/your-domain.com/cert.pem -text -noout

# 3. Renew SSL certificates if needed
docker-compose exec traefik traefik-cert-renew

# 4. Update DNS records if IP changed
# (Manual process depends on DNS provider)

# 5. Restart services to pick up changes
docker-compose restart
```

**Expected Recovery Time**: 15-30 minutes

## Recovery Validation

After any recovery procedure, perform the following validation:

### 1. Service Health Check
```bash
# Check all services are running
docker-compose ps

# Verify HTTP endpoints
curl -k https://localhost/health
curl -k https://localhost/metrics

# Check WebSocket connectivity
wscat -c wss://localhost/ws
```

### 2. Data Integrity Check
```bash
# Verify Prometheus is collecting metrics
curl -k https://localhost/prometheus/api/v1/query?query=up

# Check Grafana dashboards load
curl -k https://localhost/grafana/api/health

# Verify MCP server functionality
python test-mcp-connection.py
```

### 3. Security Validation
```bash
# Verify SSL certificates are valid
openssl s_client -connect localhost:443 -servername your-domain.com

# Check authentication is working
curl -k -H "Authorization: Bearer <token>" https://localhost/api/health
```

## Backup Verification

Regular backup verification ensures recovery capability:

### Daily Verification
```bash
# Automated verification (add to crontab)
0 3 * * * /path/to/Wazuh-MCP-Server/scripts/backup.sh verify <latest-backup>
```

### Monthly Full Recovery Test
1. Set up isolated test environment
2. Perform complete recovery from backup
3. Validate all functionality
4. Document any issues or improvements

## Emergency Contacts

### Internal Team
- **Primary Contact**: Operations Team (ops@company.com)
- **Secondary Contact**: DevOps Lead (devops-lead@company.com)
- **Escalation**: CTO (cto@company.com)

### External Vendors
- **Cloud Provider**: [Provider Support]
- **DNS Provider**: [DNS Support]
- **Monitoring Service**: [Monitoring Support]

## Recovery Documentation

### Recovery Log Template
```
Date/Time: _______________
Incident: ________________
Symptoms: ________________
Actions Taken:
1. _____________________
2. _____________________
3. _____________________

Recovery Time: ___________
Root Cause: _____________
Preventive Actions: _____
```

### Post-Incident Review
After any disaster recovery:
1. Document the incident and response
2. Review response time vs objectives
3. Identify process improvements
4. Update documentation and procedures
5. Conduct team debrief

## Monitoring & Alerting

### Critical Alerts
- Service unavailability > 2 minutes
- Backup failure
- SSL certificate expiration < 7 days
- High error rates > 5%

### Alert Channels
- **Immediate**: PagerDuty, SMS
- **Non-Critical**: Email, Slack
- **Status Page**: Public status updates

## Business Continuity

### Temporary Measures
During extended outages:
1. Activate status page with updates
2. Implement manual processes if needed
3. Communicate with stakeholders
4. Document business impact

### Vendor Alternatives
- **Backup Storage**: Multiple cloud providers
- **DNS Services**: Primary and secondary providers
- **Monitoring**: Backup monitoring solution

## Compliance & Audit

### Documentation Requirements
- Backup logs and verification reports
- Recovery test results
- Incident reports and post-mortems
- RTO/RPO compliance reports

### Audit Trail
- All recovery actions are logged
- Access to backup systems is audited
- Configuration changes are tracked
- Regular compliance reviews

## Testing Schedule

### Monthly Tests
- Configuration-only restore
- Individual service recovery
- Backup integrity verification

### Quarterly Tests
- Full disaster recovery simulation
- Cross-regional failover test
- Team response drill

### Annual Tests
- Complete infrastructure rebuild
- Business continuity simulation
- Third-party audit of procedures

---

## Quick Reference

### Emergency Numbers
- **Operations Hotline**: +1-XXX-XXX-XXXX
- **DevOps On-Call**: +1-XXX-XXX-XXXX

### Key Commands
```bash
# Emergency stop
docker-compose down

# Quick restart
docker-compose restart

# Full backup
./scripts/backup.sh

# Full restore
./scripts/restore.sh <backup-name>

# Health check
curl -k https://localhost/health
```

### Backup Locations
- **Primary**: `/opt/wazuh-mcp/backups`
- **Remote**: `s3://company-backups/wazuh-mcp/`
- **Offsite**: `backup-server:/backups/wazuh-mcp/`