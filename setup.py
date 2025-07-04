#!/usr/bin/env python3
"""Cross-platform setup script for Wazuh MCP Server local mode.

This script handles the initial setup and configuration for local development
across Windows, macOS, and Linux platforms.
"""

import os
import sys
import platform
import subprocess
from pathlib import Path
import shutil


def print_header():
    """Print setup header."""
    print("=" * 50)
    print("   Wazuh MCP Server - Local Setup")
    print("=" * 50)
    print()


def print_info(message):
    """Print info message."""
    print(f"[INFO] {message}")


def print_success(message):
    """Print success message."""
    print(f"[SUCCESS] {message}")


def print_error(message):
    """Print error message."""
    print(f"[ERROR] {message}")


def print_warning(message):
    """Print warning message."""
    print(f"[WARNING] {message}")


def check_python_version():
    """Check if Python version is compatible."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print_error(f"Python 3.9+ required, found {version.major}.{version.minor}")
        print_info("Please upgrade Python and try again")
        return False
    
    print_success(f"Python {version.major}.{version.minor}.{version.micro} - Compatible")
    return True


def check_pip():
    """Check if pip is available."""
    try:
        import pip
        print_success("pip is available")
        return True
    except ImportError:
        print_error("pip is not installed")
        print_info("Please install pip and try again")
        return False


def install_package():
    """Install the package in development mode."""
    print_info("Installing Wazuh MCP Server in development mode...")
    
    try:
        # Install in editable mode
        cmd = [sys.executable, "-m", "pip", "install", "-e", "."]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print_success("Package installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install package: {e}")
        print_error(f"Output: {e.stdout}")
        print_error(f"Error: {e.stderr}")
        return False


def install_dev_dependencies():
    """Install development dependencies."""
    print_info("Installing development dependencies...")
    
    dev_requirements = Path("requirements-dev.txt")
    if not dev_requirements.exists():
        print_warning("requirements-dev.txt not found, skipping dev dependencies")
        return True
    
    try:
        cmd = [sys.executable, "-m", "pip", "install", "-r", str(dev_requirements)]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print_success("Development dependencies installed")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install dev dependencies: {e}")
        return False


def setup_environment_file():
    """Setup environment configuration file."""
    print_info("Setting up environment configuration...")
    
    env_example = Path(".env.example")
    env_file = Path(".env")
    
    if not env_example.exists():
        print_error(".env.example file not found")
        return False
    
    if env_file.exists():
        print_warning(".env file already exists")
        response = input("Overwrite existing .env file? (y/N): ").strip().lower()
        if response not in ('y', 'yes'):
            print_info("Keeping existing .env file")
            return True
    
    try:
        shutil.copy2(env_example, env_file)
        print_success("Environment file created from .env.example")
        print_info("Please edit .env file with your Wazuh server configuration")
        return True
    except Exception as e:
        print_error(f"Failed to create .env file: {e}")
        return False


def create_directories():
    """Create necessary directories."""
    print_info("Creating application directories...")
    
    # Import platform utilities to get proper directories
    try:
        sys.path.insert(0, str(Path("src")))
        from wazuh_mcp_server.utils.platform_utils import (
            get_config_dir, get_data_dir, get_log_dir, get_cache_dir,
            ensure_directory_exists
        )
        
        directories = [
            get_config_dir(),
            get_data_dir(), 
            get_log_dir(),
            get_cache_dir()
        ]
        
        for directory in directories:
            if ensure_directory_exists(directory):
                print_success(f"Created directory: {directory}")
            else:
                print_warning(f"Could not create directory: {directory}")
                
        return True
    except ImportError as e:
        print_warning(f"Could not import platform utilities: {e}")
        print_info("Directories will be created on first run")
        return True


def test_installation():
    """Test if the installation works."""
    print_info("Testing installation...")
    
    try:
        # Test import
        sys.path.insert(0, str(Path("src")))
        from wazuh_mcp_server.main import main
        print_success("Package import successful")
        
        # Test entry point
        cmd = [sys.executable, "-c", "from wazuh_mcp_server.main import main; print('Entry point OK')"]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print_success("Entry point test successful")
        
        return True
    except (ImportError, subprocess.CalledProcessError) as e:
        print_error(f"Installation test failed: {e}")
        return False


def show_usage_instructions():
    """Show usage instructions after successful setup."""
    system = platform.system()
    
    print()
    print("=" * 50)
    print("   Setup Complete!")
    print("=" * 50)
    print()
    print("Next steps:")
    print()
    print("1. Edit .env file with your Wazuh server details:")
    print("   - WAZUH_HOST=your-wazuh-server.com")
    print("   - WAZUH_USER=your-username")
    print("   - WAZUH_PASS=your-password")
    print()
    print("2. Test the connection:")
    print("   python wazuh_mcp_server.py --stdio")
    print()
    print("3. Configure Claude Desktop (add to settings.json):")
    print('   "mcpServers": {')
    print('     "wazuh": {')
    print('       "command": "python"',)
    print(f'       "args": ["{Path.cwd() / "wazuh_mcp_server.py"}", "--stdio"]')
    print('     }')
    print('   }')
    print()
    
    if system == "Windows":
        print("Windows-specific notes:")
        print("- Use PowerShell or Command Prompt")
        print("- Ensure Python is in your PATH")
        print("- Consider using virtual environments")
    elif system == "Darwin":
        print("macOS-specific notes:")
        print("- Configuration will be stored in ~/Library/Application Support/WazuhMCP")
        print("- Logs will be stored in ~/Library/Logs/WazuhMCP")
    else:
        print("Linux-specific notes:")
        print("- Configuration will be stored in ~/.config/wazuh-mcp")
        print("- Logs may be stored in /var/log/wazuh-mcp (if writable) or ~/.local/share/wazuh-mcp/logs")
    
    print()
    print("For production deployment with Docker:")
    if system == "Windows":
        print("   .\\deploy.ps1 deploy    # PowerShell")
        print("   deploy.bat deploy      # Command Prompt") 
    else:
        print("   ./deploy.sh deploy")
    print()


def main():
    """Main setup function."""
    print_header()
    
    print_info(f"Detected platform: {platform.system()} {platform.release()}")
    print_info(f"Python version: {platform.python_version()}")
    print()
    
    # Check prerequisites
    if not check_python_version():
        return 1
    
    if not check_pip():
        return 1
    
    # Setup steps
    steps = [
        ("Installing package", install_package),
        ("Installing dev dependencies", install_dev_dependencies), 
        ("Setting up environment", setup_environment_file),
        ("Creating directories", create_directories),
        ("Testing installation", test_installation)
    ]
    
    for step_name, step_func in steps:
        print_info(f"Step: {step_name}")
        if not step_func():
            print_error(f"Setup failed at step: {step_name}")
            return 1
        print()
    
    show_usage_instructions()
    return 0


if __name__ == "__main__":
    sys.exit(main())