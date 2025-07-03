#!/usr/bin/env python3
import asyncio
import sys
from pathlib import Path
from dotenv import load_dotenv

# Find .env file - works on both Windows and Linux
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
env_file = project_root / '.env'

# Load environment variables from .env file if it exists
if env_file.exists():
    load_dotenv(dotenv_path=env_file)
    print(f"Loaded .env file from: {env_file}")
else:
    # Try loading from current working directory as fallback
    load_dotenv()
    print("Warning: No .env file found at project root, trying current directory")

# Setup import path and error handling
src_path = str(project_root / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Setup enhanced error handling for imports
try:
    from utils.import_helper import setup_import_error_handler
    setup_import_error_handler()
except ImportError:
    # Fallback if import_helper is not available
    pass

from config import WazuhConfig
from api.wazuh_client_manager import WazuhClientManager


async def test_connection():
    config = WazuhConfig.from_env()
    
    print(f"Testing connection to Wazuh Server API: {config.base_url}")
    if config.indexer_host:
        print(f"Testing connection to Wazuh Indexer API: https://{config.indexer_host}:{config.indexer_port}")
    
    try:
        async with WazuhClientManager(config) as client:
            # Detect version
            version = await client.detect_wazuh_version()
            if version:
                print(f"✓ Detected Wazuh version: {version}")
            else:
                print("⚠ Could not detect Wazuh version")
            
            # Test health check
            health = await client.health_check()
            print(f"✓ Server API health: {health['server_api']['status']}")
            
            if health.get('indexer_api'):
                print(f"✓ Indexer API health: {health['indexer_api']['status']}")
            elif config.indexer_host:
                print("⚠ Indexer API configured but not accessible")
            
            # Test basic functionality
            agents = await client.get_agents()
            agent_count = agents.get("data", {}).get("total_affected_items", 0)
            print(f"✓ Found {agent_count} agents")
            
            # Test alerts (will use appropriate API)
            try:
                alerts = await client.get_alerts(limit=5)
                alert_count = alerts.get("data", {}).get("total_affected_items", 0)
                print(f"✓ Found {alert_count} alerts")
                
                if health.get('using_indexer_for_alerts'):
                    print("  ℹ Using Indexer API for alerts")
                else:
                    print("  ℹ Using Server API for alerts")
                    
            except Exception as e:
                print(f"⚠ Alert query failed: {str(e)}")
            
            print(f"\n🎉 Connection test successful!")
            print(f"📊 Configuration summary:")
            print(f"   • Wazuh version: {version or 'Unknown'}")
            print(f"   • Server API: {config.host}:{config.port}")
            print(f"   • Indexer API: {config.indexer_host}:{config.indexer_port}" if config.indexer_host else "   • Indexer API: Not configured")
            print(f"   • Using Indexer for alerts: {health.get('using_indexer_for_alerts', False)}")
            
    except Exception as e:
        print(f"✗ Connection test failed: {str(e)}")
        print(f"\n💡 Troubleshooting tips:")
        print(f"   • Check your .env file configuration")
        print(f"   • Verify Wazuh server is running and accessible")
        print(f"   • Run: python scripts/check_env.py")
        sys.exit(1)


def main():
    """Main entry point for console script."""
    asyncio.run(test_connection())


if __name__ == "__main__":
    main()
