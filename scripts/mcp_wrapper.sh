#!/bin/bash
#
# Wazuh MCP Server Wrapper Script
# This script handles environment setup and working directory issues
# when running the MCP server from Claude Desktop
#

# Enable strict error handling
set -euo pipefail

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_PYTHON="$PROJECT_ROOT/venv/bin/python3"
MAIN_SCRIPT="$PROJECT_ROOT/src/wazuh_mcp_server/main.py"
ENV_FILE="$PROJECT_ROOT/.env"
TEMP_DIR=""

# Color codes for output (when not in MCP mode)
if [ -t 2 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
else
    RED=''
    GREEN=''
    YELLOW=''
    NC=''
fi

# Error handler
error_exit() {
    echo -e "${RED}Error: $1${NC}" >&2
    cleanup
    exit 1
}

# Cleanup function
cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || true
    fi
}

# Signal handler for graceful shutdown
handle_signal() {
    cleanup
    exit 0
}

# Register signal handlers
trap handle_signal SIGTERM SIGINT SIGHUP

# Validate environment
validate_environment() {
    # Check if virtual environment exists
    if [ ! -f "$VENV_PYTHON" ]; then
        error_exit "Virtual environment not found. Please run: python3 -m venv venv"
    fi
    
    # Check if main script exists
    if [ ! -f "$MAIN_SCRIPT" ]; then
        error_exit "Main script not found at: $MAIN_SCRIPT"
    fi
    
    # Check if .env file exists
    if [ ! -f "$ENV_FILE" ]; then
        echo -e "${YELLOW}Warning: .env file not found. Using defaults.${NC}" >&2
    fi
}

# Load environment variables from .env file
load_env_file() {
    if [ -f "$ENV_FILE" ]; then
        # Export variables from .env file, handling comments and empty lines
        while IFS='=' read -r key value; do
            # Skip comments and empty lines
            if [[ ! "$key" =~ ^[[:space:]]*# ]] && [[ -n "$key" ]]; then
                # Remove leading/trailing whitespace
                key=$(echo "$key" | xargs)
                value=$(echo "$value" | xargs)
                # Remove quotes if present
                value="${value%\"}"
                value="${value#\"}"
                value="${value%\'}"
                value="${value#\'}"
                # Export the variable
                export "$key=$value"
            fi
        done < "$ENV_FILE"
    fi
}

# Create temporary directory for logs
setup_temp_directory() {
    # Create a temporary directory for logs
    TEMP_DIR=$(mktemp -d -t wazuh-mcp-XXXXXX)
    
    # Create logs subdirectory
    mkdir -p "$TEMP_DIR/logs"
    
    # Set it as the logs directory
    export WAZUH_LOG_DIR="$TEMP_DIR/logs"
    export LOG_DIR="$TEMP_DIR/logs"
}

# Main execution
main() {
    # Validate environment first
    validate_environment
    
    # Change to project directory
    cd "$PROJECT_ROOT" || error_exit "Failed to change to project directory"
    
    # Load environment variables from .env
    load_env_file
    
    # Create temporary directory for logs
    setup_temp_directory
    
    # Set Python environment variables
    export PYTHONUNBUFFERED=1
    export PYTHONDONTWRITEBYTECODE=1
    export PYTHONPATH="$PROJECT_ROOT/src:${PYTHONPATH:-}"
    
    # Set MCP-specific environment variables
    export MCP_MODE=1
    export WAZUH_RUNNING_IN_CLAUDE=1
    
    # Override log directory to use temp directory
    export WAZUH_DISABLE_FILE_LOGGING=${WAZUH_DISABLE_FILE_LOGGING:-false}
    
    # If .env wasn't loaded, set some defaults to prevent errors
    if [ -z "${WAZUH_HOST:-}" ]; then
        export WAZUH_HOST="localhost"
        export WAZUH_USER="admin"
        export WAZUH_PASS="admin"
    fi
    
    # Debug output (only if not in stdio mode)
    if [ "${1:-}" != "--stdio" ]; then
        echo -e "${GREEN}Wazuh MCP Server Wrapper${NC}" >&2
        echo "Working directory: $PWD" >&2
        echo "Python: $VENV_PYTHON" >&2
        echo "Temp logs: $TEMP_DIR/logs" >&2
        echo "Starting server..." >&2
    fi
    
    # Execute the Python script with all arguments
    # Use exec to replace this process, ensuring signals are properly forwarded
    exec "$VENV_PYTHON" -u "$MAIN_SCRIPT" "$@"
}

# Run main function with all arguments
main "$@"

# Cleanup on normal exit (should not reach here due to exec)
cleanup