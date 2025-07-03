#!/usr/bin/env python3
"""
Smart SSL setup script for Wazuh MCP Server.
Automatically detects certificate types and configures optimal SSL settings.
"""

import asyncio
import sys
from pathlib import Path
from dotenv import load_dotenv

# Setup import path and error handling
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
src_path = str(project_root / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Load environment
env_file = project_root / '.env'
if env_file.exists():
    load_dotenv(dotenv_path=env_file)

try:
    from config import WazuhConfig
    from utils.ssl_helper import (
        get_recommended_ssl_settings, test_ssl_with_fallback,
        create_user_friendly_ssl_config
    )
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("💡 Try: pip install -e .")
    sys.exit(1)


def print_banner():
    """Print setup banner."""
    print("🔒 Wazuh MCP Server - Smart SSL Setup")
    print("=" * 50)
    print("🚀 This tool will automatically configure SSL for maximum compatibility")
    print("✅ Works with: Self-signed, Internal CA, Commercial, and Development certificates")
    print()


def update_env_file(recommendations: dict):
    """Update .env file with recommended SSL settings."""
    env_file = project_root / '.env'
    
    if not env_file.exists():
        # Create .env from .env.example
        example_file = project_root / '.env.example'
        if example_file.exists():
            with open(example_file, 'r') as f:
                content = f.read()
            with open(env_file, 'w') as f:
                f.write(content)
            print(f"✅ Created .env file from .env.example")
        else:
            print("❌ No .env.example file found")
            return False
    
    # Read current .env content
    with open(env_file, 'r') as f:
        lines = f.readlines()
    
    # Update SSL settings
    env_vars = recommendations.get('environment_variables', {})
    updated_lines = []
    
    for line in lines:
        line_updated = False
        for var, value in env_vars.items():
            if line.startswith(f'{var}=') or line.startswith(f'#{var}='):
                updated_lines.append(f'{var}={value}\n')
                line_updated = True
                break
        
        if not line_updated:
            updated_lines.append(line)
    
    # Write updated content
    with open(env_file, 'w') as f:
        f.writelines(updated_lines)
    
    print(f"✅ Updated .env file with recommended SSL settings")
    return True


async def main():
    """Main SSL setup function."""
    print_banner()
    
    try:
        # Try to load configuration
        config = WazuhConfig.from_env()
        
        print("🔍 Analyzing your Wazuh SSL configuration...")
        print(f"   Wazuh Server: {config.host}:{config.port}")
        
        # Test Wazuh Server SSL
        print("\n📊 Testing Wazuh Server SSL...")
        server_recommendations = get_recommended_ssl_settings(config.host, config.port)
        
        print(f"   Result: {server_recommendations['reasoning']}")
        print(f"   Success Probability: {server_recommendations['success_probability']}")
        
        # Test Wazuh Indexer SSL if configured
        indexer_recommendations = None
        if config.indexer_host:
            print(f"\n📊 Testing Wazuh Indexer SSL...")
            print(f"   Wazuh Indexer: {config.indexer_host}:{config.indexer_port}")
            
            indexer_recommendations = get_recommended_ssl_settings(
                config.indexer_host, config.indexer_port
            )
            print(f"   Result: {indexer_recommendations['reasoning']}")
            print(f"   Success Probability: {indexer_recommendations['success_probability']}")
        
        # Combine recommendations
        print("\n🎯 Recommended Configuration:")
        print("=" * 40)
        
        final_recommendations = {
            'environment_variables': server_recommendations['environment_variables'].copy()
        }
        
        # Add indexer-specific settings
        if indexer_recommendations:
            indexer_vars = {
                'WAZUH_INDEXER_VERIFY_SSL': 'true' if indexer_recommendations['verify_ssl'] else 'false',
                'WAZUH_INDEXER_ALLOW_SELF_SIGNED': 'true' if indexer_recommendations['allow_self_signed'] else 'false'
            }
            final_recommendations['environment_variables'].update(indexer_vars)
        
        # Display recommendations
        for var, value in final_recommendations['environment_variables'].items():
            print(f"   {var}={value}")
        
        # Ask user if they want to apply changes
        print(f"\n💡 These settings will provide maximum compatibility with your certificate setup.")
        
        apply_changes = input("\n❓ Apply these settings to your .env file? (y/N): ").strip().lower()
        
        if apply_changes in ['y', 'yes']:
            if update_env_file(final_recommendations):
                print("\n🎉 SSL configuration completed successfully!")
                print("✅ Your Wazuh MCP Server is now configured for optimal SSL compatibility")
                print("\n🚀 Next steps:")
                print("   1. Test connection: python scripts/run.py test")
                print("   2. Start server: python scripts/run.py server")
                print("   3. Or use: wazuh-mcp-test && wazuh-mcp-server")
            else:
                print("\n❌ Failed to update .env file")
                return 1
        else:
            print("\n📝 Manual configuration:")
            print("   Add these settings to your .env file:")
            for var, value in final_recommendations['environment_variables'].items():
                print(f"   {var}={value}")
        
        print(f"\n📖 For troubleshooting, see: SSL_TROUBLESHOOTING_GUIDE.md")
        return 0
        
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        print("\n💡 Fallback configuration for maximum compatibility:")
        print("   Add these to your .env file:")
        print("   VERIFY_SSL=false")
        print("   WAZUH_ALLOW_SELF_SIGNED=true")
        print("   WAZUH_INDEXER_VERIFY_SSL=false")
        print("   WAZUH_INDEXER_ALLOW_SELF_SIGNED=true")
        print("\n📖 This configuration works with ANY certificate type")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))