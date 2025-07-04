#!/bin/bash
# Wazuh MCP Server - Health Check Script
# Validates all components are working properly

set -euo pipefail

# Configuration
TIMEOUT=10
VERBOSE=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to log with colors
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Docker services
check_docker_services() {
    log_info "Checking Docker services..."
    
    local failed_services=0
    
    if ! command_exists docker; then
        log_error "Docker not found"
        return 1
    fi
    
    if ! command_exists docker-compose; then
        log_error "Docker Compose not found"
        return 1
    fi
    
    # Check if docker-compose.yml exists
    if [ ! -f "docker-compose.yml" ]; then
        log_error "docker-compose.yml not found"
        return 1
    fi
    
    # Get service status
    local services=$(docker-compose ps --services 2>/dev/null || echo "")
    if [ -z "$services" ]; then
        log_warn "No services defined or docker-compose not available"
        return 1
    fi
    
    echo "Service Status:"
    for service in $services; do
        local status=$(docker-compose ps -q "$service" 2>/dev/null || echo "")
        if [ -n "$status" ]; then
            local health=$(docker inspect --format='{{.State.Health.Status}}' "$status" 2>/dev/null || echo "unknown")
            local state=$(docker inspect --format='{{.State.Status}}' "$status" 2>/dev/null || echo "unknown")
            
            if [ "$state" = "running" ]; then
                if [ "$health" = "healthy" ] || [ "$health" = "unknown" ]; then
                    echo "  ✓ $service: running ($health)"
                else
                    echo "  ✗ $service: running but unhealthy ($health)"
                    failed_services=$((failed_services + 1))
                fi
            else
                echo "  ✗ $service: $state"
                failed_services=$((failed_services + 1))
            fi
        else
            echo "  ✗ $service: not found"
            failed_services=$((failed_services + 1))
        fi
    done
    
    if [ $failed_services -eq 0 ]; then
        log_info "All Docker services are healthy"
        return 0
    else
        log_error "$failed_services service(s) are unhealthy"
        return 1
    fi
}

# Function to check HTTP endpoints
check_http_endpoints() {
    log_info "Checking HTTP endpoints..."
    
    local failed_endpoints=0
    
    # Health endpoint
    if curl -k -s --max-time $TIMEOUT https://localhost/health >/dev/null 2>&1; then
        echo "  ✓ Health endpoint: accessible"
    else
        echo "  ✗ Health endpoint: failed"
        failed_endpoints=$((failed_endpoints + 1))
    fi
    
    # Metrics endpoint
    if curl -k -s --max-time $TIMEOUT https://localhost/metrics >/dev/null 2>&1; then
        echo "  ✓ Metrics endpoint: accessible"
    else
        echo "  ✗ Metrics endpoint: failed"
        failed_endpoints=$((failed_endpoints + 1))
    fi
    
    # Grafana
    if curl -k -s --max-time $TIMEOUT https://localhost/grafana/api/health >/dev/null 2>&1; then
        echo "  ✓ Grafana: accessible"
    else
        echo "  ✗ Grafana: failed"
        failed_endpoints=$((failed_endpoints + 1))
    fi
    
    # Prometheus
    if curl -k -s --max-time $TIMEOUT https://localhost/prometheus/-/healthy >/dev/null 2>&1; then
        echo "  ✓ Prometheus: accessible"
    else
        echo "  ✗ Prometheus: failed"
        failed_endpoints=$((failed_endpoints + 1))
    fi
    
    if [ $failed_endpoints -eq 0 ]; then
        log_info "All HTTP endpoints are accessible"
        return 0
    else
        log_error "$failed_endpoints endpoint(s) are inaccessible"
        return 1
    fi
}

# Function to check SSL certificates
check_ssl_certificates() {
    log_info "Checking SSL certificates..."
    
    local cert_issues=0
    
    # Check main certificate
    if openssl s_client -connect localhost:443 -servername localhost -verify_return_error >/dev/null 2>&1; then
        echo "  ✓ SSL certificate: valid"
        
        # Check expiration
        local expiry=$(echo | openssl s_client -connect localhost:443 -servername localhost 2>/dev/null | openssl x509 -noout -dates 2>/dev/null | grep notAfter | cut -d= -f2 || echo "")
        if [ -n "$expiry" ]; then
            local expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || echo "0")
            local now_epoch=$(date +%s)
            local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
            
            if [ $days_left -gt 30 ]; then
                echo "  ✓ SSL certificate expires in $days_left days"
            elif [ $days_left -gt 7 ]; then
                echo "  ⚠ SSL certificate expires in $days_left days (renewal recommended)"
                log_warn "SSL certificate expires soon"
            else
                echo "  ✗ SSL certificate expires in $days_left days (urgent renewal needed)"
                cert_issues=$((cert_issues + 1))
            fi
        fi
    else
        echo "  ✗ SSL certificate: invalid or inaccessible"
        cert_issues=$((cert_issues + 1))
    fi
    
    if [ $cert_issues -eq 0 ]; then
        log_info "SSL certificates are valid"
        return 0
    else
        log_error "SSL certificate issues detected"
        return 1
    fi
}

# Function to check Docker volumes
check_docker_volumes() {
    log_info "Checking Docker volumes..."
    
    local volume_issues=0
    
    # Expected volumes
    local expected_volumes="prometheus-data grafana-data"
    
    for volume in $expected_volumes; do
        if docker volume ls | grep -q "$volume"; then
            echo "  ✓ Volume $volume: exists"
        else
            echo "  ✗ Volume $volume: missing"
            volume_issues=$((volume_issues + 1))
        fi
    done
    
    if [ $volume_issues -eq 0 ]; then
        log_info "All required volumes exist"
        return 0
    else
        log_error "$volume_issues volume(s) are missing"
        return 1
    fi
}

# Function to check configuration
check_configuration() {
    log_info "Checking configuration..."
    
    local config_issues=0
    
    # Check environment files
    if [ -f ".env.production" ] || [ -f ".env" ]; then
        echo "  ✓ Environment configuration: found"
    else
        echo "  ✗ Environment configuration: missing"
        config_issues=$((config_issues + 1))
    fi
    
    # Check Docker Compose file
    if [ -f "docker-compose.yml" ]; then
        echo "  ✓ Docker Compose configuration: found"
        
        # Validate Docker Compose syntax
        if docker-compose config >/dev/null 2>&1; then
            echo "  ✓ Docker Compose syntax: valid"
        else
            echo "  ✗ Docker Compose syntax: invalid"
            config_issues=$((config_issues + 1))
        fi
    else
        echo "  ✗ Docker Compose configuration: missing"
        config_issues=$((config_issues + 1))
    fi
    
    if [ $config_issues -eq 0 ]; then
        log_info "Configuration is valid"
        return 0
    else
        log_error "Configuration issues detected"
        return 1
    fi
}

# Function to check network connectivity
check_network() {
    log_info "Checking network connectivity..."
    
    local network_issues=0
    
    # Check if ports are listening
    local ports="80 443"
    for port in $ports; do
        if netstat -tln 2>/dev/null | grep -q ":$port " || ss -tln 2>/dev/null | grep -q ":$port "; then
            echo "  ✓ Port $port: listening"
        else
            echo "  ✗ Port $port: not listening"
            network_issues=$((network_issues + 1))
        fi
    done
    
    if [ $network_issues -eq 0 ]; then
        log_info "Network connectivity is good"
        return 0
    else
        log_error "Network connectivity issues detected"
        return 1
    fi
}

# Function to run comprehensive health check
run_health_check() {
    echo "========================================"
    echo "  Wazuh MCP Server - Health Check"
    echo "========================================"
    echo "Started at: $(date)"
    echo ""
    
    local total_checks=0
    local failed_checks=0
    
    # Run all checks
    local checks=(
        "check_configuration"
        "check_docker_services" 
        "check_docker_volumes"
        "check_network"
        "check_http_endpoints"
        "check_ssl_certificates"
    )
    
    for check in "${checks[@]}"; do
        total_checks=$((total_checks + 1))
        echo ""
        if ! $check; then
            failed_checks=$((failed_checks + 1))
        fi
    done
    
    # Summary
    echo ""
    echo "========================================"
    echo "  Health Check Summary"
    echo "========================================"
    echo "Total checks: $total_checks"
    echo "Failed checks: $failed_checks"
    echo "Success rate: $(( (total_checks - failed_checks) * 100 / total_checks ))%"
    echo ""
    
    if [ $failed_checks -eq 0 ]; then
        log_info "All health checks passed ✓"
        echo "System is healthy and ready for production use."
        return 0
    else
        log_error "$failed_checks health check(s) failed ✗"
        echo "System requires attention before production use."
        return 1
    fi
}

# Function to show usage
show_usage() {
    echo "Wazuh MCP Server Health Check Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --verbose, -v    Show detailed output"
    echo "  --timeout <sec>  Set timeout for checks (default: 10)"
    echo "  --help, -h       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                    # Run all health checks"
    echo "  $0 --verbose          # Run with detailed output"
    echo "  $0 --timeout 30       # Use 30 second timeout"
    echo ""
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
if ! command_exists curl; then
    log_error "curl is required but not installed"
    exit 1
fi

if ! command_exists openssl; then
    log_error "openssl is required but not installed"  
    exit 1
fi

# Run health check
run_health_check