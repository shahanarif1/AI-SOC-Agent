#!/usr/bin/env python3
"""Comprehensive validation script for Wazuh MCP Server setup.

This script validates the entire installation and provides detailed
diagnostics for troubleshooting.
"""

import sys
import platform
import subprocess
from pathlib import Path


def print_header():
    """Print validation header."""
    print("=" * 70)
    print("   WAZUH MCP SERVER - SETUP VALIDATION")
    print("=" * 70)
    print()


def print_section(title: str):
    """Print section header."""
    print(f"\n🔍 {title}")
    print("-" * (len(title) + 3))


def print_check(name: str, status: bool, details: str = ""):
    """Print check result."""
    icon = "✅" if status else "❌"
    print(f"{icon} {name}")
    if details:
        print(f"   {details}")


def check_system_info():
    """Check system information."""
    print_section("SYSTEM INFORMATION")
    
    system_info = {
        'OS': platform.system(),
        'Version': platform.release(),
        'Architecture': platform.machine(),
        'Python': platform.python_version(),
        'Platform': platform.platform()
    }
    
    for key, value in system_info.items():
        print(f"📋 {key}: {value}")
    
    return True


def check_virtual_environment():
    """Check virtual environment status."""
    print_section("VIRTUAL ENVIRONMENT")
    
    venv_path = Path("venv")
    venv_exists = venv_path.exists()
    print_check("Virtual environment exists", venv_exists)
    
    if not venv_exists:
        return False
    
    # Check if we can use the virtual environment
    if platform.system() == "Windows":
        python_exe = venv_path / "Scripts" / "python.exe"
        pip_exe = venv_path / "Scripts" / "pip.exe"
    else:
        python_exe = venv_path / "bin" / "python"
        pip_exe = venv_path / "bin" / "pip"
    
    python_works = python_exe.exists()
    pip_works = pip_exe.exists()
    
    print_check("Python executable", python_works, str(python_exe))
    print_check("Pip executable", pip_works, str(pip_exe))
    
    if python_works:
        try:
            result = subprocess.run([str(python_exe), "--version"], 
                                  capture_output=True, text=True)
            print_check("Python version check", result.returncode == 0, 
                       result.stdout.strip() if result.returncode == 0 else result.stderr)
        except Exception as e:
            print_check("Python version check", False, str(e))
    
    return python_works and pip_works


def check_dependencies():
    """Check if required dependencies are installed."""
    print_section("DEPENDENCIES")
    
    # Get python executable
    if platform.system() == "Windows":
        python_exe = Path("venv") / "Scripts" / "python.exe"
    else:
        python_exe = Path("venv") / "bin" / "python"
    
    if not python_exe.exists():
        print_check("Dependencies check", False, "Virtual environment not found")
        return False
    
    # Check key dependencies
    dependencies = [
        "mcp", "aiohttp", "pydantic", "python-dotenv", 
        "websockets", "urllib3", "certifi"
    ]
    
    all_installed = True
    for dep in dependencies:
        try:
            result = subprocess.run([str(python_exe), "-c", f"import {dep}; print('OK')"],
                                  capture_output=True, text=True)
            success = result.returncode == 0
            print_check(f"Package: {dep}", success)
            if not success:
                all_installed = False
        except Exception as e:
            print_check(f"Package: {dep}", False, str(e))
            all_installed = False
    
    return all_installed


def check_package_installation():
    """Check if the Wazuh MCP Server package is installed."""
    print_section("PACKAGE INSTALLATION")
    
    # Get python executable
    if platform.system() == "Windows":
        python_exe = Path("venv") / "Scripts" / "python.exe"
    else:
        python_exe = Path("venv") / "bin" / "python"
    
    if not python_exe.exists():
        print_check("Package installation", False, "Virtual environment not found")
        return False
    
    # Test imports
    test_imports = [
        ("Main module", "wazuh_mcp_server.main", "WazuhMCPServer"),
        ("Configuration", "wazuh_mcp_server.config", "WazuhConfig"),
        ("API client", "wazuh_mcp_server.api.wazuh_client", "WazuhAPIClient"),
        ("Analyzers", "wazuh_mcp_server.analyzers.security_analyzer", "SecurityAnalyzer"),
        ("Utilities", "wazuh_mcp_server.utils.logging", "get_logger"),
    ]
    
    all_imported = True
    for name, module, class_name in test_imports:
        try:
            result = subprocess.run([
                str(python_exe), "-c", 
                f"from {module} import {class_name}; print('{class_name} imported successfully')"
            ], capture_output=True, text=True)
            success = result.returncode == 0
            print_check(name, success, result.stdout.strip() if success else result.stderr.strip())
            if not success:
                all_imported = False
        except Exception as e:
            print_check(name, False, str(e))
            all_imported = False
    
    return all_imported


def check_configuration():
    """Check configuration files."""
    print_section("CONFIGURATION")
    
    # Check .env file
    env_file = Path(".env")
    env_exists = env_file.exists()
    print_check(".env file exists", env_exists)
    
    if not env_exists:
        return False
    
    # Check .env permissions (Unix-like systems)
    if platform.system() != "Windows":
        stat_info = env_file.stat()
        permissions = oct(stat_info.st_mode)[-3:]
        secure_perms = permissions == "600"
        print_check(".env file permissions", secure_perms, f"Permissions: {permissions} (should be 600)")
    
    # Parse .env file
    config = {}
    try:
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
    except Exception as e:
        print_check("Parse .env file", False, str(e))
        return False
    
    # Check required configuration
    required_vars = ['WAZUH_HOST', 'WAZUH_USER', 'WAZUH_PASS']
    config_complete = True
    
    for var in required_vars:
        if var in config and config[var] and not config[var].startswith('your-'):
            print_check(f"Config: {var}", True, "Configured")
        else:
            print_check(f"Config: {var}", False, "Not configured or using placeholder")
            config_complete = False
    
    return config_complete


def check_logs_directory():
    """Check logs directory."""
    print_section("LOGGING")
    
    logs_dir = Path("logs")
    logs_exists = logs_dir.exists()
    print_check("Logs directory", logs_exists)
    
    if logs_exists:
        # Check if writable
        try:
            test_file = logs_dir / "test_write.tmp"
            test_file.write_text("test")
            test_file.unlink()
            print_check("Logs directory writable", True)
        except Exception as e:
            print_check("Logs directory writable", False, str(e))
            return False
    
    return logs_exists


def test_connection():
    """Test connection to Wazuh server if configured."""
    print_section("CONNECTION TEST")
    
    # Get python executable
    if platform.system() == "Windows":
        python_exe = Path("venv") / "Scripts" / "python.exe"
    else:
        python_exe = Path("venv") / "bin" / "python"
    
    if not python_exe.exists():
        print_check("Connection test", False, "Virtual environment not found")
        return False
    
    # Run connection validator
    validator_script = Path("src") / "wazuh_mcp_server" / "scripts" / "connection_validator.py"
    if not validator_script.exists():
        print_check("Connection validator", False, "Validator script not found")
        return False
    
    try:
        print("Running connection validation...")
        result = subprocess.run([str(python_exe), str(validator_script)],
                              capture_output=True, text=True, timeout=30)
        
        success = result.returncode == 0
        print_check("Connection test", success)
        
        # Print validator output
        if result.stdout:
            print("Connection test output:")
            for line in result.stdout.split('\n')[-10:]:  # Show last 10 lines
                if line.strip():
                    print(f"   {line}")
        
        return success
        
    except subprocess.TimeoutExpired:
        print_check("Connection test", False, "Test timed out")
        return False
    except Exception as e:
        print_check("Connection test", False, str(e))
        return False


def main():
    """Main validation function."""
    print_header()
    
    all_checks = [
        ("System Information", check_system_info),
        ("Virtual Environment", check_virtual_environment),
        ("Dependencies", check_dependencies),
        ("Package Installation", check_package_installation),
        ("Configuration", check_configuration),
        ("Logs Directory", check_logs_directory),
        ("Connection Test", test_connection),
    ]
    
    results = {}
    for name, check_func in all_checks:
        try:
            results[name] = check_func()
        except Exception as e:
            print(f"❌ Error in {name}: {e}")
            results[name] = False
    
    # Print summary
    print_section("VALIDATION SUMMARY")
    
    passed = sum(results.values())
    total = len(results)
    
    for name, result in results.items():
        icon = "✅" if result else "❌"
        print(f"{icon} {name}")
    
    print(f"\n📊 Overall Status: {passed}/{total} checks passed")
    
    if passed == total:
        print("\n🎉 All validation checks passed! Setup is complete and ready for use.")
        print("\nNext steps:")
        print("1. Update .env with your actual Wazuh credentials if not done")
        print("2. Add MCP server to Claude Desktop configuration")
        print("3. Test with Claude Desktop")
        return 0
    else:
        print(f"\n⚠️  {total - passed} validation checks failed. Please review the issues above.")
        print("\nCommon solutions:")
        print("1. Re-run setup.py to fix dependency issues")
        print("2. Check .env file configuration")
        print("3. Verify network connectivity to Wazuh server")
        return 1


if __name__ == "__main__":
    sys.exit(main())