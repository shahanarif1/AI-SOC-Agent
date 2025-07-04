#!/bin/bash
# Wazuh MCP Server - Production Restore Script
# Restores configuration, data, and persistent volumes from backup

set -euo pipefail

# Configuration
BACKUP_DIR="${BACKUP_DIR:-./backups}"
RESTORE_DIR="${RESTORE_DIR:-./restore-temp}"

echo "=========================================="
echo "  Wazuh MCP Server - Restore Script"
echo "=========================================="

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

# Function to show usage
show_usage() {
    echo "Usage: $0 <backup-name> [options]"
    echo ""
    echo "Arguments:"
    echo "  backup-name     Name of backup to restore (without timestamp suffix)"
    echo "                  Example: wazuh-mcp-backup-20240101_120000"
    echo ""
    echo "Options:"
    echo "  --config-only   Restore configuration files only"
    echo "  --data-only     Restore data volumes only"
    echo "  --dry-run       Show what would be restored without making changes"
    echo "  --force         Skip confirmation prompts"
    echo ""
    echo "Examples:"
    echo "  $0 wazuh-mcp-backup-20240101_120000"
    echo "  $0 wazuh-mcp-backup-20240101_120000 --config-only"
    echo "  $0 wazuh-mcp-backup-20240101_120000 --dry-run"
    echo ""
}

# Function to list available backups
list_backups() {
    log "Available backups:"
    find "${BACKUP_DIR}" -name "*-manifest.txt" -type f | while read -r manifest; do
        local backup_name=$(basename "$manifest" "-manifest.txt")
        local backup_date=$(grep "Backup Date:" "$manifest" 2>/dev/null | cut -d: -f2- | xargs || echo "Unknown")
        echo "  - $backup_name ($backup_date)"
    done
}

# Function to validate backup exists
validate_backup() {
    local backup_name="$1"
    
    log "Validating backup: $backup_name"
    
    # Check if manifest exists
    local manifest="${BACKUP_DIR}/${backup_name}-manifest.txt"
    if [ ! -f "$manifest" ]; then
        log "ERROR: Backup manifest not found: $manifest"
        echo ""
        list_backups
        exit 1
    fi
    
    # Check backup files exist
    local missing_files=0
    for backup_type in config prometheus grafana redis logs; do
        local backup_file="${BACKUP_DIR}/${backup_name}-${backup_type}.tar.gz"
        if [ ! -f "$backup_file" ]; then
            log "WARNING: Backup file not found: $(basename "$backup_file")"
            missing_files=$((missing_files + 1))
        fi
    done
    
    if [ $missing_files -gt 0 ]; then
        log "WARNING: Some backup files are missing, restore may be incomplete"
    fi
    
    log "Backup validation complete"
}

# Function to stop services
stop_services() {
    log "Stopping Docker services..."
    
    if docker-compose ps -q >/dev/null 2>&1; then
        docker-compose down || {
            log "WARNING: Failed to stop some services cleanly"
        }
    else
        log "No running services found"
    fi
}

# Function to restore configuration
restore_config() {
    local backup_name="$1"
    local config_backup="${BACKUP_DIR}/${backup_name}-config.tar.gz"
    
    if [ ! -f "$config_backup" ]; then
        log "No configuration backup found, skipping..."
        return 0
    fi
    
    log "Restoring configuration from: $(basename "$config_backup")"
    
    # Create backup of current config
    if [ -f ".env.production" ] || [ -f ".env" ] || [ -d "letsencrypt" ]; then
        local current_backup="config-backup-$(date +%Y%m%d_%H%M%S).tar.gz"
        log "Backing up current configuration to: $current_backup"
        tar -czf "$current_backup" .env* letsencrypt/ certs/ monitoring/ 2>/dev/null || true
    fi
    
    # Restore configuration
    tar -xzf "$config_backup" 2>/dev/null || {
        log "ERROR: Failed to extract configuration backup"
        return 1
    }
    
    log "Configuration restored successfully"
}

# Function to restore Docker volumes
restore_volumes() {
    local backup_name="$1"
    
    log "Restoring Docker volumes..."
    
    # Restore Prometheus data
    local prometheus_backup="${BACKUP_DIR}/${backup_name}-prometheus.tar.gz"
    if [ -f "$prometheus_backup" ]; then
        log "Restoring Prometheus data..."
        
        # Create volume if it doesn't exist
        docker volume create prometheus-data >/dev/null 2>&1 || true
        
        docker run --rm \
            -v prometheus-data:/data \
            -v "${PWD}/${BACKUP_DIR}:/backup:ro" \
            busybox:latest \
            sh -c "cd /data && tar -xzf /backup/$(basename "$prometheus_backup")" \
            2>/dev/null || log "WARNING: Prometheus restore failed"
    fi
    
    # Restore Grafana data
    local grafana_backup="${BACKUP_DIR}/${backup_name}-grafana.tar.gz"
    if [ -f "$grafana_backup" ]; then
        log "Restoring Grafana data..."
        
        # Create volume if it doesn't exist
        docker volume create grafana-data >/dev/null 2>&1 || true
        
        docker run --rm \
            -v grafana-data:/data \
            -v "${PWD}/${BACKUP_DIR}:/backup:ro" \
            busybox:latest \
            sh -c "cd /data && tar -xzf /backup/$(basename "$grafana_backup")" \
            2>/dev/null || log "WARNING: Grafana restore failed"
    fi
    
    # Restore Redis data
    local redis_backup="${BACKUP_DIR}/${backup_name}-redis.tar.gz"
    if [ -f "$redis_backup" ]; then
        log "Restoring Redis data..."
        
        # Create volume if it doesn't exist
        docker volume create redis-data >/dev/null 2>&1 || true
        
        docker run --rm \
            -v redis-data:/data \
            -v "${PWD}/${BACKUP_DIR}:/backup:ro" \
            busybox:latest \
            sh -c "cd /data && tar -xzf /backup/$(basename "$redis_backup")" \
            2>/dev/null || log "WARNING: Redis restore failed"
    fi
    
    log "Volume restoration complete"
}

# Function to restore logs
restore_logs() {
    local backup_name="$1"
    local logs_backup="${BACKUP_DIR}/${backup_name}-logs.tar.gz"
    
    if [ ! -f "$logs_backup" ]; then
        log "No logs backup found, skipping..."
        return 0
    fi
    
    log "Restoring logs from: $(basename "$logs_backup")"
    
    # Create logs directory if it doesn't exist
    mkdir -p logs/
    
    # Extract logs
    tar -xzf "$logs_backup" 2>/dev/null || {
        log "WARNING: Failed to extract logs backup"
        return 1
    }
    
    log "Logs restored successfully"
}

# Function to start services
start_services() {
    log "Starting Docker services..."
    
    if [ -f "docker-compose.yml" ]; then
        docker-compose up -d || {
            log "ERROR: Failed to start services"
            return 1
        }
        
        # Wait for services to be ready
        sleep 10
        
        # Check service status
        log "Checking service status..."
        docker-compose ps
        
    else
        log "WARNING: docker-compose.yml not found, services not started"
    fi
}

# Function to verify restoration
verify_restore() {
    log "Verifying restoration..."
    
    local errors=0
    
    # Check if configuration files exist
    if [ ! -f ".env.production" ] && [ ! -f ".env" ]; then
        log "WARNING: No environment configuration found"
        errors=$((errors + 1))
    fi
    
    # Check Docker volumes
    for volume in prometheus-data grafana-data; do
        if docker volume ls | grep -q "$volume"; then
            log "✓ Volume $volume exists"
        else
            log "✗ Volume $volume missing"
            errors=$((errors + 1))
        fi
    done
    
    # Check running services
    local running_services=$(docker-compose ps -q 2>/dev/null | wc -l)
    log "Services running: $running_services"
    
    if [ $errors -eq 0 ]; then
        log "Restoration verification successful"
        return 0
    else
        log "Restoration verification completed with $errors warnings"
        return 1
    fi
}

# Main restore function
main() {
    local backup_name="$1"
    local config_only=false
    local data_only=false
    local dry_run=false
    local force=false
    
    # Parse options
    shift
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config-only)
                config_only=true
                shift
                ;;
            --data-only)
                data_only=true
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            --force)
                force=true
                shift
                ;;
            *)
                log "ERROR: Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Validate backup
    validate_backup "$backup_name"
    
    # Show restore plan
    echo ""
    echo "Restore Plan:"
    echo "============="
    echo "Backup: $backup_name"
    echo "Config restore: $([ "$data_only" = true ] && echo "No" || echo "Yes")"
    echo "Data restore: $([ "$config_only" = true ] && echo "No" || echo "Yes")"
    echo "Dry run: $([ "$dry_run" = true ] && echo "Yes" || echo "No")"
    echo ""
    
    if [ "$dry_run" = true ]; then
        log "Dry run complete - no changes made"
        return 0
    fi
    
    # Confirmation
    if [ "$force" != true ]; then
        echo "WARNING: This will overwrite current configuration and data!"
        read -p "Continue with restore? (yes/no): " -r
        if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
            log "Restore cancelled by user"
            exit 0
        fi
    fi
    
    # Check prerequisites
    check_docker
    
    # Perform restore
    log "Starting restore process..."
    
    # Stop services first
    stop_services
    
    # Restore components
    if [ "$data_only" != true ]; then
        restore_config "$backup_name"
    fi
    
    if [ "$config_only" != true ]; then
        restore_volumes "$backup_name"
        restore_logs "$backup_name"
    fi
    
    # Start services
    start_services
    
    # Verify restoration
    verify_restore
    
    echo ""
    echo "=========================================="
    echo "  Restore Complete"
    echo "=========================================="
    log "Restore completed successfully"
    log "Restored from backup: $backup_name"
    echo ""
    echo "Next steps:"
    echo "1. Verify all services are running: docker-compose ps"
    echo "2. Check service health: curl -k https://localhost/health"
    echo "3. Review logs: docker-compose logs"
    echo ""
}

# Handle command line arguments
if [ $# -eq 0 ]; then
    log "ERROR: Backup name required"
    echo ""
    show_usage
    echo ""
    list_backups
    exit 1
fi

case "${1:-}" in
    "help"|"-h"|"--help")
        show_usage
        ;;
    "list")
        list_backups
        ;;
    *)
        main "$@"
        ;;
esac