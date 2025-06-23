#!/usr/bin/env python3
"""Health check script for Docker container."""

import sys
import asyncio
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

async def health_check():
    """Perform basic health check."""
    try:
        from config import WazuhConfig
        from api.wazuh_client import WazuhAPIClient
        
        # Test configuration loading
        config = WazuhConfig.from_env()
        
        # Test API client creation and health
        async with WazuhAPIClient(config) as client:
            health_data = await client.health_check()
            
            if health_data.get("status") == "healthy":
                print("Health check passed")
                return 0
            else:
                print(f"Health check failed: {health_data}")
                return 1
                
    except Exception as e:
        print(f"Health check error: {str(e)}")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(health_check())
    sys.exit(exit_code)