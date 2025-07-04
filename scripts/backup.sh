#!/bin/bash
# Wazuh MCP Server - Production Backup Script
# Backs up configuration, data, and persistent volumes

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="wazuh-mcp-backup-${TIMESTAMP}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# Create backup directory
mkdir -p "${BACKUP_DIR}"

echo "=========================================="
echo "  Wazuh MCP Server - Backup Script"
echo "=========================================="
echo "Backup started at: $(date)"
echo "Backup directory: ${BACKUP_DIR}"
echo "Backup name: ${BACKUP_NAME}"
echo ""

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        log "ERROR: Docker is not running or not accessible"
        exit 1
    fi
}

# Function to backup configuration files
backup_config() {
    log "Backing up configuration files..."
    
    local config_backup="${BACKUP_DIR}/${BACKUP_NAME}-config.tar.gz"
    
    # Files to backup
    local files_to_backup=""
    
    # Environment files
    [ -f ".env.production" ] && files_to_backup="$files_to_backup .env.production"
    [ -f ".env" ] && files_to_backup="$files_to_backup .env"
    [ -f "docker-compose.yml" ] && files_to_backup="$files_to_backup docker-compose.yml"
    
    # SSL certificates (if using Let's Encrypt)
    [ -d "letsencrypt" ] && files_to_backup="$files_to_backup letsencrypt/"
    
    # Custom certificates
    [ -d "certs" ] && files_to_backup="$files_to_backup certs/"
    
    # Monitoring configuration
    [ -d "monitoring" ] && files_to_backup="$files_to_backup monitoring/"
    
    if [ -n "$files_to_backup" ]; then
        tar -czf "$config_backup" $files_to_backup 2>/dev/null || {
            log "WARNING: Some configuration files could not be backed up"
        }
        log "Configuration backup created: $config_backup"
    else
        log "WARNING: No configuration files found to backup"
    fi
}

# Function to backup Docker volumes
backup_volumes() {
    log "Backing up Docker volumes..."
    
    # Check if containers are running
    local running_containers=$(docker-compose ps -q 2>/dev/null || echo "")
    
    if [ -z "$running_containers" ]; then
        log "No running containers found, skipping volume backup"
        return 0
    fi
    
    # Backup Prometheus data
    if docker volume ls | grep -q prometheus-data; then
        log "Backing up Prometheus data..."
        docker run --rm \
            -v prometheus-data:/data:ro \
            -v "${PWD}/${BACKUP_DIR}:/backup" \
            busybox:latest \
            tar -czf "/backup/${BACKUP_NAME}-prometheus.tar.gz" -C /data . \
            2>/dev/null || log "WARNING: Prometheus backup failed"
    fi
    
    # Backup Grafana data
    if docker volume ls | grep -q grafana-data; then
        log "Backing up Grafana data..."
        docker run --rm \
            -v grafana-data:/data:ro \
            -v "${PWD}/${BACKUP_DIR}:/backup" \
            busybox:latest \
            tar -czf "/backup/${BACKUP_NAME}-grafana.tar.gz" -C /data . \
            2>/dev/null || log "WARNING: Grafana backup failed"
    fi
    
    # Backup Redis data (if exists)
    if docker volume ls | grep -q redis-data; then
        log "Backing up Redis data..."
        docker run --rm \
            -v redis-data:/data:ro \
            -v "${PWD}/${BACKUP_DIR}:/backup" \
            busybox:latest \
            tar -czf "/backup/${BACKUP_NAME}-redis.tar.gz" -C /data . \
            2>/dev/null || log "WARNING: Redis backup failed"
    fi
}

# Function to backup application logs
backup_logs() {
    log "Backing up application logs..."
    
    local logs_backup="${BACKUP_DIR}/${BACKUP_NAME}-logs.tar.gz"
    local logs_found=0
    
    # Local logs directory
    if [ -d "logs" ]; then
        tar -czf "$logs_backup" logs/ 2>/dev/null && logs_found=1
        log "Local logs backed up: $logs_backup"
    fi
    
    # Docker container logs
    local log_dir="${BACKUP_DIR}/${BACKUP_NAME}-container-logs"
    mkdir -p "$log_dir"
    
    for container in $(docker-compose ps -q 2>/dev/null || echo ""); do
        if [ -n "$container" ]; then
            local container_name=$(docker inspect --format='{{.Name}}' "$container" | sed 's/^.//')
            docker logs "$container" > "$log_dir/${container_name}.log" 2>&1 || true
            logs_found=1
        fi
    done
    
    if [ $logs_found -eq 1 ]; then
        tar -czf "${logs_backup%.tar.gz}-containers.tar.gz" -C "$log_dir" . 2>/dev/null || true
        rm -rf "$log_dir"
        log "Container logs backed up"
    else
        log "No logs found to backup"
    fi
}

# Function to create backup manifest
create_manifest() {
    log "Creating backup manifest..."
    
    local manifest="${BACKUP_DIR}/${BACKUP_NAME}-manifest.txt"
    
    cat > "$manifest" << EOF
Wazuh MCP Server Backup Manifest
================================
Backup Date: $(date)
Backup Name: ${BACKUP_NAME}
Backup Directory: ${BACKUP_DIR}

System Information:
- Hostname: $(hostname)
- Docker Version: $(docker --version 2>/dev/null || echo "Not available")
- Docker Compose Version: $(docker-compose --version 2>/dev/null || echo "Not available")

Backup Contents:
EOF
    
    # List backup files
    find "${BACKUP_DIR}" -name "${BACKUP_NAME}*" -type f | while read -r file; do
        local size=$(du -h "$file" | cut -f1)
        echo "- $(basename "$file") (${size})" >> "$manifest"
    done
    
    log "Backup manifest created: $manifest"
}

# Function to cleanup old backups
cleanup_old_backups() {
    log "Cleaning up backups older than ${RETENTION_DAYS} days..."
    
    find "${BACKUP_DIR}" -name "wazuh-mcp-backup-*" -type f -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true
    
    local remaining=$(find "${BACKUP_DIR}" -name "wazuh-mcp-backup-*" -type f | wc -l)
    log "Cleanup complete. ${remaining} backup files remaining."
}

# Function to verify backup integrity
verify_backup() {
    log "Verifying backup integrity..."
    
    local error_count=0
    
    for backup_file in "${BACKUP_DIR}/${BACKUP_NAME}"*.tar.gz; do
        if [ -f "$backup_file" ]; then
            if tar -tzf "$backup_file" >/dev/null 2>&1; then
                log "✓ $(basename "$backup_file") - integrity verified"
            else
                log "✗ $(basename "$backup_file") - INTEGRITY CHECK FAILED"
                error_count=$((error_count + 1))
            fi
        fi
    done
    
    if [ $error_count -eq 0 ]; then
        log "All backup files passed integrity verification"
    else
        log "WARNING: ${error_count} backup files failed integrity verification"
        return 1
    fi
}

# Main backup function
main() {
    # Check prerequisites
    check_docker
    
    # Perform backup steps
    backup_config
    backup_volumes
    backup_logs
    create_manifest
    verify_backup
    cleanup_old_backups
    
    # Summary
    echo ""
    echo "=========================================="
    echo "  Backup Complete"
    echo "=========================================="
    log "Backup completed successfully"
    log "Backup location: ${BACKUP_DIR}/${BACKUP_NAME}*"
    
    # Show backup size
    local total_size=$(du -sh "${BACKUP_DIR}" | cut -f1)
    log "Total backup directory size: ${total_size}"
    
    echo ""
    echo "To restore from this backup:"
    echo "  ./scripts/restore.sh ${BACKUP_NAME}"
    echo ""
}

# Handle command line arguments
case "${1:-backup}" in
    "backup")
        main
        ;;
    "cleanup")
        log "Performing cleanup only..."
        cleanup_old_backups
        ;;
    "verify")
        if [ -z "${2:-}" ]; then
            log "ERROR: Backup name required for verification"
            echo "Usage: $0 verify <backup-name>"
            exit 1
        fi
        BACKUP_NAME="$2"
        verify_backup
        ;;
    "help"|"-h"|"--help")
        echo "Wazuh MCP Server Backup Script"
        echo ""
        echo "Usage: $0 [command] [options]"
        echo ""
        echo "Commands:"
        echo "  backup    Create a full backup (default)"
        echo "  cleanup   Remove old backups only"
        echo "  verify    Verify backup integrity"
        echo "  help      Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  BACKUP_DIR              Backup directory (default: ./backups)"
        echo "  BACKUP_RETENTION_DAYS   Days to keep backups (default: 30)"
        echo ""
        ;;
    *)
        log "ERROR: Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac