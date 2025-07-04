#!/usr/bin/env python3
"""
Complete installation and verification script for Wazuh MCP Server.
Handles dependency installation and verification in one step.
"""

import sys
import subprocess
import os
from pathlib import Path


def run_command(cmd: str, description: str) -> bool:
    """Run a command and return success status."""
    print(f"📋 {description}...")
    try:
        result = subprocess.run(
            cmd.split(), 
            capture_output=True, 
            text=True, 
            check=True
        )
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"Error: {e.stderr}")
        return False


def install_dependencies() -> bool:
    """Install all required dependencies."""
    project_root = Path(__file__).parent.parent
    requirements_file = project_root / "requirements.txt"
    
    if not requirements_file.exists():
        print(f"❌ Requirements file not found: {requirements_file}")
        return False
    
    print("📦 Installing dependencies...")
    
    # Upgrade pip first
    if not run_command("python -m pip install --upgrade pip", "Upgrading pip"):
        return False
    
    # Install requirements
    if not run_command(f"pip install -r {requirements_file}", "Installing requirements"):
        return False
    
    # Install in development mode
    if not run_command("pip install -e .", "Installing package in development mode"):
        return False
    
    return True


def verify_installation() -> bool:
    """Verify the installation is working."""
    print("\n🔍 Verifying installation...")
    
    # Run dependency verification script
    verify_script = Path(__file__).parent / "verify_dependencies.py"
    
    try:
        result = subprocess.run([sys.executable, str(verify_script)], check=True)
        return True
    except subprocess.CalledProcessError:
        print("❌ Installation verification failed")
        return False


def test_basic_functionality() -> bool:
    """Test basic import functionality."""
    print("\n🧪 Testing basic functionality...")
    
    test_code = '''
import sys
from pathlib import Path

# Add src to path
src_path = str(Path(__file__).parent.parent / "src")
sys.path.insert(0, src_path)

try:
    # Test critical imports
    from config import WazuhConfig
    from utils.error_recovery import error_recovery_manager
    from utils.ssl_config import SSLConfigurationManager
    from api import WazuhClientManager, WazuhIndexerClient
    
    print("✅ All critical imports successful")
    
    # Test basic configuration
    config = WazuhConfig(
        host="test.example.com",
        username="test",
        password="test"
    )
    print("✅ Configuration creation successful")
    
    # Test error recovery manager
    stats = error_recovery_manager.get_error_statistics()
    print("✅ Error recovery system functional")
    
    print("🎉 Basic functionality test passed!")
    
except Exception as e:
    print(f"❌ Basic functionality test failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
'''
    
    try:
        result = subprocess.run(
            [sys.executable, "-c", test_code],
            cwd=Path(__file__).parent.parent,
            capture_output=True,
            text=True,
            check=True
        )
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print("❌ Basic functionality test failed:")
        print(e.stdout)
        print(e.stderr)
        return False


def main():
    """Main installation and verification process."""
    print("🚀 Wazuh MCP Server Installation & Verification")
    print("=" * 55)
    
    # Change to project directory
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    print(f"📁 Working directory: {project_root}")
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Installation failed")
        return 1
    
    # Verify installation
    if not verify_installation():
        print("\n❌ Verification failed")
        return 1
    
    # Test basic functionality
    if not test_basic_functionality():
        print("\n❌ Functionality test failed")
        return 1
    
    # Success!
    print("\n" + "=" * 55)
    print("🎉 Installation and verification completed successfully!")
    print("")
    print("🚀 Next steps:")
    print("1. Copy .env.example to .env and configure your Wazuh credentials")
    print("2. Run: python scripts/test_connection.py")
    print("3. Start the server: python src/wazuh_mcp_server.py --stdio")
    print("")
    print("📚 For more information, see README.md")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())