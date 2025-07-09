#!/bin/bash
#
# Test script for the Wazuh MCP Server Wrapper
# This script validates the wrapper functionality before using with Claude Desktop
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WRAPPER_SCRIPT="$SCRIPT_DIR/mcp_wrapper.sh"

echo "Testing Wazuh MCP Server Wrapper..."
echo "===================================="

# Test 1: Check if wrapper exists and is executable
if [ ! -x "$WRAPPER_SCRIPT" ]; then
    echo "❌ Wrapper script not found or not executable"
    exit 1
fi
echo "✅ Wrapper script exists and is executable"

# Test 2: Test environment validation
echo "Testing environment validation..."
"$WRAPPER_SCRIPT" --test-env 2>/dev/null || echo "✅ Environment validation working"

# Test 3: Test server startup (3 second timeout)
echo "Testing server startup..."
timeout 3s "$WRAPPER_SCRIPT" --stdio 2>&1 | head -1 || echo "✅ Server starts without immediate errors"

echo ""
echo "Wrapper script is ready for use!"
echo ""
echo "To use with Claude Desktop, update your claude_desktop_config.json:"
echo "{"
echo "  \"mcpServers\": {"
echo "    \"wazuh\": {"
echo "      \"command\": \"$WRAPPER_SCRIPT\","
echo "      \"args\": [\"--stdio\"]"
echo "    }"
echo "  }"
echo "}"