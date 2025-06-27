#!/usr/bin/env python3
"""
Entry point for running Wazuh MCP Server as a module.
This allows the server to be run with: python -m src.wazuh_mcp_server
"""

import sys
import asyncio
from .wazuh_mcp_server import main

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server shutdown requested", file=sys.stderr)
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {str(e)}", file=sys.stderr)
        sys.exit(1)