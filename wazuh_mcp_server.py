#!/usr/bin/env python3
"""
Wazuh MCP Server - Standalone Entry Point
==========================================

This is the main entry point for the Wazuh MCP Server that works with
Claude Desktop and other MCP-compatible AI tools.

Usage:
    python wazuh_mcp_server.py --stdio    # For local Claude Desktop integration
    python wazuh_mcp_server.py --http     # For remote HTTP access
    python wazuh_mcp_server.py --ws       # For remote WebSocket access

Environment Variables:
    WAZUH_HOST - Wazuh server hostname/IP
    WAZUH_PORT - Wazuh API port (default: 55000)
    WAZUH_USER - Wazuh username
    WAZUH_PASS - Wazuh password
    VERIFY_SSL - SSL verification (default: false)
    LOG_LEVEL - Logging level (default: INFO)
"""

import sys
import asyncio
import argparse
from pathlib import Path

# Add src to Python path for development mode
src_path = Path(__file__).parent / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))

try:
    from wazuh_mcp_server.main import main as run_local_server
    from wazuh_mcp_server.__version__ import __version__
except ImportError as e:
    print(f"❌ Failed to import Wazuh MCP Server: {e}")
    print("💡 Please ensure dependencies are installed: pip install -e .")
    sys.exit(1)


async def run_remote_server(transport_type: str, host: str = "0.0.0.0", port: int = 8000):
    """Run MCP server with HTTP/WebSocket transport for remote access."""
    try:
        if transport_type == "http":
            from wazuh_mcp_server.transports.http_transport import run_http_server
            print(f"🌐 Starting Wazuh MCP Server v{__version__} on HTTP transport")
            print(f"🔗 Server will be available at http://{host}:{port}")
            await run_http_server(host, port)
        elif transport_type == "ws":
            from wazuh_mcp_server.transports.websocket_transport import run_websocket_server
            print(f"🌐 Starting Wazuh MCP Server v{__version__} on WebSocket transport")
            print(f"🔗 Server will be available at ws://{host}:{port}")
            await run_websocket_server(host, port)
        else:
            raise ValueError(f"Unknown transport type: {transport_type}")
    except ImportError as e:
        print(f"❌ Remote transport not available: {e}")
        print("💡 Remote transports require additional dependencies.")
        sys.exit(1)


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description="Wazuh MCP Server - Security Operations for AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Local Claude Desktop integration
    python wazuh_mcp_server.py --stdio
    
    # Remote HTTP server
    python wazuh_mcp_server.py --http --host 0.0.0.0 --port 8000
    
    # Remote WebSocket server  
    python wazuh_mcp_server.py --ws --host 0.0.0.0 --port 8001

Claude Desktop Configuration:
    {
      "mcpServers": {
        "wazuh-security": {
          "command": "python",
          "args": ["path/to/wazuh_mcp_server.py", "--stdio"],
          "env": {
            "WAZUH_HOST": "your-wazuh-server",
            "WAZUH_PORT": "55000", 
            "WAZUH_USER": "your-username",
            "WAZUH_PASS": "your-password",
            "VERIFY_SSL": "false"
          }
        }
      }
    }
        """
    )
    
    # Transport options
    transport_group = parser.add_mutually_exclusive_group(required=True)
    transport_group.add_argument(
        "--stdio", 
        action="store_true",
        help="Use stdio transport (for Claude Desktop integration)"
    )
    transport_group.add_argument(
        "--http", 
        action="store_true",
        help="Use HTTP transport (for remote access)"
    )
    transport_group.add_argument(
        "--ws", 
        action="store_true", 
        help="Use WebSocket transport (for remote access)"
    )
    
    # Remote server options
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to for remote transports (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to for remote transports (default: 8000)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Wazuh MCP Server v{__version__}"
    )
    
    args = parser.parse_args()
    
    try:
        if args.stdio:
            # Local stdio transport for Claude Desktop
            print(f"🖥️  Starting Wazuh MCP Server v{__version__} on stdio transport", file=sys.stderr)
            print("📡 Ready for Claude Desktop integration", file=sys.stderr)
            asyncio.run(run_local_server())
        elif args.http or args.ws:
            # Remote transport
            transport_type = "http" if args.http else "ws"
            asyncio.run(run_remote_server(transport_type, args.host, args.port))
        
    except KeyboardInterrupt:
        print("\n👋 Server shutdown requested", file=sys.stderr)
    except Exception as e:
        print(f"❌ Fatal error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()