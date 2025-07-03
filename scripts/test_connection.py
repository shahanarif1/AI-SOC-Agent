#!/usr/bin/env python3
"""
Production-grade Wazuh MCP Server connection test script.
Handles cross-platform execution and robust import path resolution.
"""

import asyncio
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Setup import paths first
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
src_path = str(project_root / "src")

if src_path not in sys.path:
    sys.path.insert(0, src_path)
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# Import the resolver and setup imports
try:
    from utils.import_resolver import setup_imports, safe_import
    resolver = setup_imports(verify=True)
    print("✅ Import paths configured successfully")
except ImportError as e:
    print(f"❌ Failed to setup imports: {e}")
    print(f"Trying basic import setup...")
    # Fallback to basic setup

# Load environment
env_file = project_root / '.env'
if env_file.exists():
    load_dotenv(dotenv_path=env_file)
    print(f"Loaded .env file from: {env_file}")
else:
    load_dotenv()
    print("Warning: No .env file found at project root, trying current directory")

# Import required modules with error handling
try:
    from config import WazuhConfig
    from api.wazuh_client_manager import WazuhClientManager
    print("✅ All modules imported successfully")
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("\n🔍 Debugging Information:")
    print(f"  Python path: {sys.path}")
    print(f"  Project root: {project_root}")
    print(f"  Src directory exists: {(project_root / 'src').exists()}")
    print(f"  Config file exists: {(project_root / 'src' / 'config.py').exists()}")
    print(f"  Working directory: {os.getcwd()}")
    
    # Try to provide helpful suggestions
    print("\n💡 Suggestions:")
    print("  1. Run from project root: cd /path/to/wazuh-mcp-server")
    print("  2. Install package: pip install -e .")
    print("  3. Use module execution: python -m scripts.test_connection")
    raise


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
