#!/bin/bash
# Wazuh MCP Server - Local IP/Port Deployment Script
# This script deploys the MCP server for private networks and IP-based access

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENV_FILE=".env.local-ip"
COMPOSE_FILE="docker-compose.local-ip.yml"
SERVICE_NAME="wazuh-mcp-server-local"

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Setup environment
setup_environment() {
    log_info "Setting up environment..."
    
    if [ ! -f "$ENV_FILE" ]; then
        if [ -f ".env.local-ip.example" ]; then
            log_warning "Environment file not found. Creating from example..."
            cp .env.local-ip.example "$ENV_FILE"
            log_warning "Please edit $ENV_FILE with your configuration before proceeding"
            log_warning "At minimum, set: WAZUH_HOST, WAZUH_USER, WAZUH_PASS"
            log_warning "Generate JWT secret with: openssl rand -base64 64"
            log_warning "Generate API keys with: openssl rand -hex 32"
            exit 1
        else
            log_error "No environment file found. Please create $ENV_FILE"
            exit 1
        fi
    fi
    
    # Source environment file
    export $(grep -v '^#' "$ENV_FILE" | xargs)
    
    # Create required directories
    mkdir -p logs data monitoring/grafana/provisioning
    
    # Validate required configuration
    if [ -z "$WAZUH_HOST" ] || [ -z "$WAZUH_USER" ] || [ -z "$WAZUH_PASS" ]; then
        log_error "Missing required Wazuh configuration. Please set WAZUH_HOST, WAZUH_USER, and WAZUH_PASS"
        exit 1
    fi
    
    if [ "$JWT_SECRET" = "REPLACE_WITH_GENERATED_SECRET" ]; then
        log_error "Please generate a secure JWT secret and update JWT_SECRET in $ENV_FILE"
        log_info "Generate with: openssl rand -base64 64"
        exit 1
    fi
    
    log_success "Environment setup complete"
}

# Generate default Prometheus config if not exists
create_prometheus_config() {
    local prometheus_config="monitoring/prometheus.yml"
    
    if [ ! -f "$prometheus_config" ]; then
        log_info "Creating default Prometheus configuration..."
        mkdir -p monitoring
        cat > "$prometheus_config" <<EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'wazuh-mcp-http'
    static_configs:
      - targets: ['wazuh-mcp-http:8000']
    scrape_interval: 30s
    metrics_path: '/metrics'
    
  - job_name: 'wazuh-mcp-ws'
    static_configs:
      - targets: ['wazuh-mcp-ws:8001']
    scrape_interval: 30s
    metrics_path: '/metrics'
    
  - job_name: 'redis'
    static_configs:
      - targets: ['redis:6379']
    scrape_interval: 30s
EOF
        log_success "Prometheus configuration created"
    fi
}

# Build and deploy
deploy() {
    log_info "Building and deploying Wazuh MCP Server (IP/Port mode)..."
    
    # Build the image
    log_info "Building Docker image..."
    docker build -t wazuh-mcp-server:local-ip .
    
    # Create Prometheus config
    create_prometheus_config
    
    # Deploy with Docker Compose
    log_info "Starting services with Docker Compose..."
    
    # Determine profiles to use
    local profiles=""
    if [ -n "$COMPOSE_PROFILES" ]; then
        profiles="--profile $(echo $COMPOSE_PROFILES | tr ',' ' --profile ')"
    fi
    
    if command -v docker-compose &> /dev/null; then
        docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" $profiles up -d
    else
        docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" $profiles up -d
    fi
    
    log_success "Deployment complete!"
}

# Check service health
check_health() {
    log_info "Checking service health..."
    
    # Wait for services to start
    sleep 10
    
    local http_port=${HTTP_PORT:-8000}
    local ws_port=${WS_PORT:-8001}
    
    # Check HTTP service
    if curl -f "http://localhost:$http_port/health" > /dev/null 2>&1; then
        log_success "HTTP transport is healthy (port $http_port)"
    else
        log_warning "HTTP transport health check failed (port $http_port)"
    fi
    
    # Check WebSocket service (basic connection test)
    if timeout 5 bash -c "echo > /dev/tcp/localhost/$ws_port" 2>/dev/null; then
        log_success "WebSocket transport is accessible (port $ws_port)"
    else
        log_warning "WebSocket transport connection failed (port $ws_port)"
    fi
    
    # Check Redis if enabled
    if [[ "$COMPOSE_PROFILES" == *"storage"* ]]; then
        local redis_port=${REDIS_PORT:-6379}
        if timeout 5 bash -c "echo > /dev/tcp/localhost/$redis_port" 2>/dev/null; then
            log_success "Redis is accessible (port $redis_port)"
        else
            log_warning "Redis connection failed (port $redis_port)"
        fi
    fi
    
    # Check Grafana if enabled
    if [[ "$COMPOSE_PROFILES" == *"monitoring"* ]]; then
        local grafana_port=${GRAFANA_PORT:-3000}
        if timeout 5 bash -c "echo > /dev/tcp/localhost/$grafana_port" 2>/dev/null; then
            log_success "Grafana is accessible (port $grafana_port)"
        else
            log_warning "Grafana connection failed (port $grafana_port)"
        fi
    fi
}

# Show deployment info
show_info() {
    log_info "Deployment Information:"
    echo ""
    echo "🌐 Service URLs (IP-based):"
    
    local server_ip=${SERVER_IP:-$(hostname -I | awk '{print $1}')}
    local http_port=${HTTP_PORT:-8000}
    local ws_port=${WS_PORT:-8001}
    local traefik_port=${TRAEFIK_HTTP_PORT:-80}
    local traefik_dashboard_port=${TRAEFIK_DASHBOARD_PORT:-8080}
    local grafana_port=${GRAFANA_PORT:-3000}
    local prometheus_port=${PROMETHEUS_PORT:-9090}
    
    echo "   HTTP API:       http://localhost:$http_port"
    echo "   HTTP API (LAN): http://$server_ip:$http_port"
    echo "   WebSocket:      ws://localhost:$ws_port"
    echo "   WebSocket (LAN): ws://$server_ip:$ws_port"
    
    if [[ "$COMPOSE_PROFILES" == *"proxy"* ]]; then
        echo "   Traefik Proxy:  http://localhost:$traefik_port"
        echo "   Traefik Proxy (LAN): http://$server_ip:$traefik_port"
        echo "   Traefik Dashboard: http://localhost:$traefik_dashboard_port"
    fi
    
    if [[ "$COMPOSE_PROFILES" == *"monitoring"* ]]; then
        echo "   Grafana:        http://localhost:$grafana_port"
        echo "   Grafana (LAN):  http://$server_ip:$grafana_port"
        echo "   Prometheus:     http://localhost:$prometheus_port"
        echo "   Prometheus (LAN): http://$server_ip:$prometheus_port"
    fi
    
    echo ""
    echo "📋 Management Commands:"
    echo "   View logs:    docker-compose -f $COMPOSE_FILE logs -f"
    echo "   Stop:         docker-compose -f $COMPOSE_FILE down"
    echo "   Restart:      docker-compose -f $COMPOSE_FILE restart"
    echo "   Status:       docker-compose -f $COMPOSE_FILE ps"
    echo ""
    echo "🔑 Authentication:"
    if [ "$ENABLE_AUTH" = "true" ]; then
        echo "   Authentication: ENABLED"
        echo "   Get JWT token: curl -X POST http://localhost:$http_port/auth/login -H 'Content-Type: application/json' -d '{\"api_key\":\"your-api-key\"}'"
        echo "   Use API key:   curl -H 'Authorization: ApiKey your-api-key' http://localhost:$http_port/tools"
    else
        echo "   Authentication: DISABLED (development mode)"
    fi
    echo ""
    echo "📖 Usage Examples:"
    echo "   Health check: curl http://localhost:$http_port/health"
    echo "   List tools:   curl http://localhost:$http_port/tools"
    echo "   Get alerts:   curl -X POST http://localhost:$http_port/tools/get_alerts/call -H 'Content-Type: application/json' -d '{\"arguments\":{\"limit\":10}}'"
    echo ""
    echo "🔧 Configuration:"
    echo "   Config file:  $ENV_FILE"
    echo "   Wazuh host:   $WAZUH_HOST:${WAZUH_PORT:-55000}"
    echo "   Profiles:     ${COMPOSE_PROFILES:-none (core services only)}"
}

# Main script
main() {
    echo "🚀 Wazuh MCP Server - Local IP/Port Deployment"
    echo "=============================================="
    echo ""
    
    check_prerequisites
    setup_environment
    deploy
    check_health
    show_info
    
    log_success "Wazuh MCP Server is now running in IP/port mode!"
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "stop")
        log_info "Stopping Wazuh MCP Server..."
        if command -v docker-compose &> /dev/null; then
            docker-compose -f "$COMPOSE_FILE" down
        else
            docker compose -f "$COMPOSE_FILE" down
        fi
        log_success "Services stopped"
        ;;
    "logs")
        if command -v docker-compose &> /dev/null; then
            docker-compose -f "$COMPOSE_FILE" logs -f "${2:-wazuh-mcp-http}"
        else
            docker compose -f "$COMPOSE_FILE" logs -f "${2:-wazuh-mcp-http}"
        fi
        ;;
    "restart")
        log_info "Restarting Wazuh MCP Server..."
        if command -v docker-compose &> /dev/null; then
            docker-compose -f "$COMPOSE_FILE" restart
        else
            docker compose -f "$COMPOSE_FILE" restart
        fi
        log_success "Services restarted"
        ;;
    "status")
        if command -v docker-compose &> /dev/null; then
            docker-compose -f "$COMPOSE_FILE" ps
        else
            docker compose -f "$COMPOSE_FILE" ps
        fi
        ;;
    "config")
        log_info "Validating configuration..."
        if command -v docker-compose &> /dev/null; then
            docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" config
        else
            docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" config
        fi
        ;;
    *)
        echo "Usage: $0 {deploy|stop|logs|restart|status|config}"
        echo ""
        echo "Commands:"
        echo "  deploy   - Deploy the IP/port-based MCP server (default)"
        echo "  stop     - Stop all services"
        echo "  logs     - View service logs"
        echo "  restart  - Restart all services"
        echo "  status   - Show service status"
        echo "  config   - Validate configuration"
        exit 1
        ;;
esac