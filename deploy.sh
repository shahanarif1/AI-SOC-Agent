#!/bin/bash
# Wazuh MCP Server - Production Deployment Script
# This script deploys the MCP server with Docker Compose for remote/team access

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
ENV_FILE=".env.production"
COMPOSE_FILE="docker-compose.yml"
SERVICE_NAME="wazuh-mcp-server"

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
        if [ -f ".env.production.example" ]; then
            log_warning "Environment file not found. Creating from example..."
            cp .env.production.example "$ENV_FILE"
            log_warning "Please edit $ENV_FILE with your configuration before proceeding"
            log_warning "At minimum, set: WAZUH_HOST, WAZUH_USER, WAZUH_PASS"
            exit 1
        else
            log_error "No environment file found. Please create $ENV_FILE"
            exit 1
        fi
    fi
    
    # Source environment file
    export $(grep -v '^#' "$ENV_FILE" | xargs)
    
    # Create required directories
    mkdir -p logs data letsencrypt monitoring/grafana/provisioning
    
    log_success "Environment setup complete"
}

# Build and deploy
deploy() {
    log_info "Building and deploying Wazuh MCP Server..."
    
    # Build the image
    log_info "Building Docker image..."
    docker build -f Dockerfile.remote -t wazuh-mcp-server:latest .
    
    # Deploy with Docker Compose
    log_info "Starting services with Docker Compose..."
    
    if command -v docker-compose &> /dev/null; then
        docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d
    else
        docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d
    fi
    
    log_success "Deployment complete!"
}

# Check service health
check_health() {
    log_info "Checking service health..."
    
    # Wait for services to start
    sleep 10
    
    # Check HTTP service
    if curl -f http://localhost:8000/health > /dev/null 2>&1; then
        log_success "HTTP transport is healthy"
    else
        log_warning "HTTP transport health check failed"
    fi
    
    # Check WebSocket service (basic connection test)
    if timeout 5 bash -c 'echo > /dev/tcp/localhost/8001' 2>/dev/null; then
        log_success "WebSocket transport is accessible"
    else
        log_warning "WebSocket transport connection failed"
    fi
}

# Show deployment info
show_info() {
    log_info "Deployment Information:"
    echo ""
    echo "🌐 Service URLs:"
    
    if [ -n "$DOMAIN" ]; then
        echo "   HTTP API:     https://mcp-http.$DOMAIN"
        echo "   WebSocket:    wss://mcp-ws.$DOMAIN"
        echo "   Traefik:      https://traefik.$DOMAIN"
        echo "   Grafana:      https://grafana.$DOMAIN"
        echo "   Prometheus:   https://prometheus.$DOMAIN"
    else
        echo "   HTTP API:     http://localhost:8000"
        echo "   WebSocket:    ws://localhost:8001"
        echo "   Traefik:      http://localhost:8080"
        echo "   Grafana:      http://localhost:3000"
        echo "   Prometheus:   http://localhost:9090"
    fi
    
    echo ""
    echo "📋 Management Commands:"
    echo "   View logs:    docker-compose -f $COMPOSE_FILE logs -f"
    echo "   Stop:         docker-compose -f $COMPOSE_FILE down"
    echo "   Restart:      docker-compose -f $COMPOSE_FILE restart"
    echo "   Update:       ./deploy-remote.sh"
    echo ""
    echo "🔑 Authentication:"
    echo "   Default auth is disabled for testing"
    echo "   To enable: Set ENABLE_AUTH=true in $ENV_FILE"
    echo "   API Keys:  Set API_KEYS=key1:user1:role1 in $ENV_FILE"
    echo ""
    echo "📖 Usage Examples:"
    echo "   Health check: curl http://localhost:8000/health"
    echo "   List tools:   curl http://localhost:8000/tools"
    echo "   Get token:    curl -X POST http://localhost:8000/auth/login -d '{\"api_key\":\"your-key\"}'"
}

# Main script
main() {
    echo "🚀 Wazuh MCP Server - Remote Deployment"
    echo "======================================"
    echo ""
    
    check_prerequisites
    setup_environment
    deploy
    check_health
    show_info
    
    log_success "Wazuh MCP Server is now running in remote mode!"
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
    *)
        echo "Usage: $0 {deploy|stop|logs|restart|status}"
        echo ""
        echo "Commands:"
        echo "  deploy   - Deploy the remote MCP server (default)"
        echo "  stop     - Stop all services"
        echo "  logs     - View service logs"
        echo "  restart  - Restart all services"
        echo "  status   - Show service status"
        exit 1
        ;;
esac