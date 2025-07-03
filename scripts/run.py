#!/usr/bin/env python3
"""
Cross-platform script launcher for Wazuh MCP Server.
Handles proper Python module execution context on Windows, Linux, and macOS.
"""

import sys
import os
import subprocess
import argparse
from pathlib import Path


def get_project_root():
    """Get project root directory (works on Windows/Linux/Mac)."""
    return Path(__file__).resolve().parent.parent


def ensure_python_path():
    """Ensure proper Python path for imports."""
    project_root = get_project_root()
    src_path = str(project_root / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)


def run_with_module_context(module_name, cwd=None):
    """Run Python module with proper execution context."""
    if cwd is None:
        cwd = get_project_root()
    
    cmd = [sys.executable, "-m", module_name]
    try:
        result = subprocess.run(cmd, cwd=cwd, check=True)
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"Error running {module_name}: {e}")
        return e.returncode
    except FileNotFoundError:
        print(f"Python executable not found: {sys.executable}")
        return 1


def run_test_connection():
    """Run connection test with proper context."""
    print("🔍 Running Wazuh MCP connection test...")
    return run_with_module_context("scripts.test_connection")


def run_server():
    """Run MCP server with proper context."""
    print("🚀 Starting Wazuh MCP server...")
    return run_with_module_context("src.wazuh_mcp_server")


def run_env_check():
    """Run environment check."""
    print("🔧 Checking environment configuration...")
    return run_with_module_context("scripts.check_env")


def run_ssl_setup():
    """Run smart SSL setup."""
    print("🔒 Running smart SSL setup...")
    return run_with_module_context("scripts.setup_ssl")


def run_ssl_check():
    """Run SSL connectivity check."""
    print("🔍 Checking SSL connectivity...")
    return run_with_module_context("scripts.check_ssl")


def install_package():
    """Install package in development mode."""
    print("📦 Installing Wazuh MCP Server in development mode...")
    project_root = get_project_root()
    cmd = [sys.executable, "-m", "pip", "install", "-e", "."]
    try:
        result = subprocess.run(cmd, cwd=project_root, check=True)
        print("✅ Installation completed successfully!")
        print("🎉 You can now use:")
        print("   • wazuh-mcp-server    (to start server)")
        print("   • wazuh-mcp-test      (to test connection)")
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"❌ Installation failed: {e}")
        return e.returncode


def main():
    """Main entry point with command-line argument parsing."""
    parser = argparse.ArgumentParser(
        description="Cross-platform launcher for Wazuh MCP Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/run.py test           # Test connection
  python scripts/run.py server         # Start server
  python scripts/run.py install        # Install package
  python scripts/run.py env-check      # Check environment
  python scripts/run.py ssl-setup      # Smart SSL configuration
  python scripts/run.py ssl-check      # Check SSL connectivity
        """
    )
    
    parser.add_argument(
        "command",
        choices=["test", "server", "install", "env-check", "ssl-setup", "ssl-check"],
        help="Command to execute"
    )
    
    args = parser.parse_args()
    
    # Ensure we're in the right environment
    project_root = get_project_root()
    if not (project_root / "src").exists():
        print("❌ Error: Could not find src/ directory.")
        print(f"   Current project root: {project_root}")
        print("   Please run this script from the Wazuh MCP Server project directory.")
        return 1
    
    # Execute the requested command
    if args.command == "test":
        return run_test_connection()
    elif args.command == "server":
        return run_server()
    elif args.command == "install":
        return install_package()
    elif args.command == "env-check":
        return run_env_check()
    elif args.command == "ssl-setup":
        return run_ssl_setup()
    elif args.command == "ssl-check":
        return run_ssl_check()
    else:
        print(f"Unknown command: {args.command}")
        return 1


if __name__ == "__main__":
    sys.exit(main())