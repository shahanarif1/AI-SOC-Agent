# Operations Manual - Wazuh MCP Server

## Overview

This manual provides comprehensive operational procedures for maintaining, monitoring, and troubleshooting the Wazuh MCP Server in production environments.

## Table of Contents

1. [Daily Operations](#daily-operations)
2. [Weekly Maintenance](#weekly-maintenance)
3. [Monthly Tasks](#monthly-tasks)
4. [Monitoring and Alerting](#monitoring-and-alerting)
5. [Troubleshooting](#troubleshooting)
6. [Performance Optimization](#performance-optimization)
7. [Security Operations](#security-operations)
8. [Emergency Procedures](#emergency-procedures)

---

## Daily Operations

### Morning Health Check (5 minutes)

```bash
# Run comprehensive health check
./scripts/health-check.sh

# Check service status
docker-compose ps

# Review overnight logs
docker-compose logs --since 24h | grep -E "(ERROR|WARN|CRITICAL)"

# Verify Wazuh connectivity
python -m wazuh_mcp_server.scripts.test_connection
```

### Key Metrics to Monitor

| Metric | Healthy Range | Action Required |
|--------|---------------|-----------------|
| CPU Usage | < 70% | Investigate if > 80% |
| Memory Usage | < 80% | Scale if > 85% |
| Disk Usage | < 80% | Cleanup if > 85% |
| Response Time | < 2 seconds | Optimize if > 5 seconds |
| Error Rate | < 1% | Investigate if > 5% |

### Daily Tasks Checklist

- [ ] **Service Health**: All containers running and healthy
- [ ] **Security Alerts**: Review any security notifications
- [ ] **Performance**: Check response times and resource usage
- [ ] **Backups**: Verify previous day's backup completed
- [ ] **SSL Certificates**: Check expiration status (>30 days remaining)
- [ ] **Log Review**: Scan for errors, warnings, or unusual patterns

---

## Weekly Maintenance

### Security Review (15 minutes)

```bash
# Update security patches
sudo apt update && sudo apt upgrade -y

# Scan for vulnerabilities
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  clair-scanner:latest --ip localhost wazuh-mcp-server

# Review access logs
tail -n 1000 logs/access.log | grep -E "(40[1-5]|50[0-9])"

# Check for unauthorized access attempts
grep "authentication failed" logs/security.log
```

### Performance Review

```bash
# Analyze response times
./scripts/performance-report.sh

# Check resource utilization trends
docker stats --no-stream

# Review slow queries and operations
grep "slow" logs/application.log
```

### Weekly Tasks Checklist

- [ ] **Security Updates**: Apply OS and container updates
- [ ] **Log Rotation**: Verify log rotation is working
- [ ] **Performance Analysis**: Review weekly performance trends
- [ ] **Backup Verification**: Test restore from recent backup
- [ ] **Configuration Review**: Check for any unauthorized changes
- [ ] **Dependency Updates**: Review and apply library updates

---

## Monthly Tasks

### Comprehensive System Review

```bash
# Full system audit
./scripts/security-audit.sh

# Performance baseline update
./scripts/performance-baseline.sh

# Disaster recovery test
./scripts/dr-test.sh --dry-run
```

### Capacity Planning

```bash
# Generate capacity report
./scripts/capacity-report.sh

# Review growth trends
./scripts/growth-analysis.sh

# Update scaling thresholds
./scripts/update-scaling.sh
```

### Monthly Tasks Checklist

- [ ] **Security Audit**: Comprehensive security assessment
- [ ] **Disaster Recovery Test**: Full DR procedure test
- [ ] **Capacity Planning**: Review and update capacity plans
- [ ] **Documentation Update**: Update operational procedures
- [ ] **Training Review**: Update team training materials
- [ ] **Vendor Review**: Assess third-party dependencies

---

## Monitoring and Alerting

### Critical Alerts (Immediate Response)

| Alert | Description | Response |
|-------|-------------|----------|
| Service Down | MCP server not responding | Execute [emergency restart](#emergency-restart) |
| High Error Rate | > 5% error rate for 5 minutes | Check logs, escalate if needed |
| SSL Expiry | Certificate expires < 7 days | Renew certificate immediately |
| Security Breach | Unauthorized access detected | Execute [security incident response](#security-incident-response) |

### Warning Alerts (1-hour Response)

| Alert | Description | Response |
|-------|-------------|----------|
| High CPU | > 80% for 15 minutes | Investigate and scale if needed |
| High Memory | > 85% for 10 minutes | Check for memory leaks |
| Slow Response | > 5 seconds average | Performance optimization |
| Backup Failure | Daily backup failed | Investigate and retry |

### Monitoring Dashboard URLs

- **Grafana**: `https://your-domain.com/grafana`
- **Prometheus**: `https://your-domain.com/prometheus`
- **Health Status**: `https://your-domain.com/health`

---

## Troubleshooting

### Common Issues and Solutions

#### Issue: Service Won't Start

**Symptoms**: Containers fail to start, health checks fail

**Diagnosis**:
```bash
# Check container logs
docker-compose logs

# Verify configuration
docker-compose config

# Check disk space
df -h

# Check memory usage
free -m
```

**Solutions**:
1. **Configuration Error**: Fix configuration and restart
2. **Resource Exhaustion**: Free up resources or scale
3. **Dependency Issue**: Check Wazuh server connectivity

#### Issue: High Memory Usage

**Symptoms**: Memory usage > 85%, potential OOM kills

**Diagnosis**:
```bash
# Check container memory usage
docker stats

# Analyze memory allocation
docker exec container_name ps aux --sort=-%mem

# Check for memory leaks
./scripts/memory-analysis.sh
```

**Solutions**:
1. **Memory Leak**: Restart affected containers
2. **High Load**: Scale horizontally
3. **Configuration**: Adjust memory limits

#### Issue: SSL Certificate Problems

**Symptoms**: HTTPS errors, certificate warnings

**Diagnosis**:
```bash
# Check certificate validity
openssl x509 -in cert.pem -text -noout

# Test SSL connection
openssl s_client -connect domain.com:443

# Check Let's Encrypt status
docker-compose logs traefik
```

**Solutions**:
1. **Expired Certificate**: Renew with Let's Encrypt
2. **Wrong Certificate**: Update certificate files
3. **DNS Issues**: Verify DNS configuration

#### Issue: Wazuh Connectivity Problems

**Symptoms**: API timeouts, authentication failures

**Diagnosis**:
```bash
# Test network connectivity
curl -k https://wazuh-server:55000

# Check credentials
python -m wazuh_mcp_server.scripts.test_connection

# Review Wazuh logs
tail -f /var/log/wazuh/api.log
```

**Solutions**:
1. **Network Issue**: Check firewall, VPN, routing
2. **Authentication**: Verify credentials, permissions
3. **SSL Issue**: Check certificate configuration

---

## Performance Optimization

### Response Time Optimization

```bash
# Identify slow endpoints
grep "response_time" logs/access.log | sort -nrk5 | head -20

# Optimize database queries
./scripts/query-optimization.sh

# Review caching effectiveness
./scripts/cache-analysis.sh
```

### Resource Optimization

```bash
# Optimize Docker images
docker system prune -f

# Adjust container resources
./scripts/resource-tuning.sh

# Review scaling parameters
./scripts/scaling-review.sh
```

### Performance Tuning Checklist

- [ ] **Response Times**: < 2 seconds for 95% of requests
- [ ] **Throughput**: Handle expected concurrent users
- [ ] **Resource Usage**: Optimal CPU/memory allocation
- [ ] **Caching**: Effective caching strategy implemented
- [ ] **Database**: Optimized queries and indexes

---

## Security Operations

### Daily Security Tasks

```bash
# Review security logs
tail -n 500 logs/security.log | grep -E "(failed|breach|attack)"

# Check for suspicious IPs
./scripts/ip-analysis.sh

# Verify SSL/TLS configuration
./scripts/ssl-check.sh
```

### Security Incident Response

#### Phase 1: Detection and Analysis (0-15 minutes)

1. **Identify the Incident**
   ```bash
   # Check security logs
   grep -E "(failed_login|attack|breach)" logs/security.log
   
   # Review monitoring alerts
   ./scripts/security-status.sh
   ```

2. **Assess Impact**
   ```bash
   # Check affected systems
   ./scripts/impact-analysis.sh
   
   # Identify compromised data
   ./scripts/data-integrity-check.sh
   ```

#### Phase 2: Containment (15-30 minutes)

1. **Isolate Affected Systems**
   ```bash
   # Block malicious IPs
   ./scripts/block-ip.sh <malicious-ip>
   
   # Isolate compromised containers
   docker-compose stop <compromised-service>
   ```

2. **Preserve Evidence**
   ```bash
   # Create forensic backup
   ./scripts/forensic-backup.sh
   
   # Capture system state
   ./scripts/capture-state.sh
   ```

#### Phase 3: Recovery (30-60 minutes)

1. **Restore from Clean Backup**
   ```bash
   # Restore from known good state
   ./scripts/restore.sh <clean-backup-name>
   
   # Verify system integrity
   ./scripts/integrity-check.sh
   ```

2. **Update Security Measures**
   ```bash
   # Update security rules
   ./scripts/update-security-rules.sh
   
   # Refresh credentials
   ./scripts/rotate-credentials.sh
   ```

---

## Emergency Procedures

### Emergency Restart

```bash
# Graceful restart
docker-compose restart

# Force restart if needed
docker-compose down && docker-compose up -d

# Verify health after restart
./scripts/health-check.sh
```

### Emergency Shutdown

```bash
# Graceful shutdown
docker-compose down

# Force shutdown if needed
docker-compose kill

# Preserve data
./scripts/emergency-backup.sh
```

### Emergency Contacts

| Role | Contact | Phone | Email |
|------|---------|-------|-------|
| Operations Lead | John Doe | +1-555-0101 | ops-lead@company.com |
| Security Lead | Jane Smith | +1-555-0102 | security-lead@company.com |
| DevOps Engineer | Bob Johnson | +1-555-0103 | devops@company.com |
| Management | Alice Wilson | +1-555-0104 | management@company.com |

### Escalation Matrix

| Severity | Initial Response | Escalation Time | Escalation Contact |
|----------|------------------|-----------------|-------------------|
| Critical | Operations Team | 15 minutes | Security Lead |
| High | Operations Team | 1 hour | DevOps Engineer |
| Medium | Operations Team | 4 hours | Operations Lead |
| Low | Operations Team | Next business day | Team Lead |

---

## Documentation Updates

### When to Update This Manual

- After any operational incident
- When procedures change
- After system upgrades
- Quarterly review cycle

### Update Process

1. **Identify Changes**: Document what procedures changed
2. **Test Updates**: Verify new procedures work
3. **Review**: Have team review changes
4. **Approve**: Get management approval
5. **Distribute**: Update team training materials

### Version Control

- **Current Version**: 1.1.0
- **Last Updated**: [Current Date]
- **Next Review**: [3 months from last update]
- **Approved By**: Operations Manager

---

## Appendix

### Useful Commands Reference

```bash
# Service management
docker-compose ps                    # Check service status
docker-compose logs -f <service>     # Follow service logs
docker-compose restart <service>     # Restart specific service

# System monitoring
docker stats                         # Container resource usage
df -h                               # Disk usage
free -m                             # Memory usage
top                                 # Process monitoring

# Network troubleshooting
netstat -tlnp                       # Check listening ports
curl -I https://domain.com          # Test HTTP connectivity
dig domain.com                      # DNS lookup

# Security operations
./scripts/security-scan.sh          # Run security scan
./scripts/audit-logs.sh             # Audit access logs
./scripts/cert-check.sh             # Check SSL certificates
```

### Log File Locations

| Service | Log Location | Rotation |
|---------|-------------|----------|
| MCP Server | `/var/log/wazuh-mcp/app.log` | Daily |
| Access Logs | `/var/log/wazuh-mcp/access.log` | Daily |
| Security Logs | `/var/log/wazuh-mcp/security.log` | Daily |
| Error Logs | `/var/log/wazuh-mcp/error.log` | Daily |
| Docker Logs | `docker-compose logs` | Container restart |

### Performance Baselines

| Metric | Baseline | Good | Needs Attention |
|--------|----------|------|-----------------|
| Response Time | < 1s | < 2s | > 5s |
| CPU Usage | < 50% | < 70% | > 80% |
| Memory Usage | < 60% | < 80% | > 85% |
| Disk I/O | < 50% | < 70% | > 80% |
| Network Usage | < 100Mbps | < 500Mbps | > 1Gbps |