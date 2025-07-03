"""
Import helper utilities for production-grade import error handling.
Provides clear error messages and resolution guidance.
"""

import sys
import traceback
from pathlib import Path
from typing import Optional


def setup_import_error_handler():
    """Setup custom import error handler with helpful messages."""
    
    def custom_excepthook(exc_type, exc_value, exc_traceback):
        """Custom exception handler for import errors."""
        
        if exc_type == ImportError:
            error_msg = str(exc_value)
            
            if "attempted relative import beyond top-level package" in error_msg:
                print("\n🚨 IMPORT ERROR DETECTED 🚨")
                print("=" * 70)
                print("Issue: Relative import failed due to incorrect execution context")
                print("\nSOLUTION OPTIONS:")
                print("1. Install and use console scripts (RECOMMENDED):")
                print("   pip install -e .")
                print("   wazuh-mcp-server")
                print("   wazuh-mcp-test")
                print("\n2. Use module execution:")
                print("   python -m src.wazuh_mcp_server")
                print("   python -m scripts.test_connection")
                print("\n3. Use the launcher script:")
                print("   python scripts/run.py server")
                print("   python scripts/run.py test")
                print("=" * 70)
                print()
            
            elif "No module named" in error_msg:
                module_name = error_msg.split("'")[1] if "'" in error_msg else "unknown"
                print(f"\n🚨 MISSING MODULE: {module_name} 🚨")
                print("=" * 70)
                print("Issue: Required Python package not installed")
                print("\nSOLUTION:")
                print("1. Install requirements:")
                print("   pip install -r requirements.txt")
                print("\n2. For development:")
                print("   pip install -r requirements-dev.txt")
                print("\n3. Or install the package:")
                print("   pip install -e .")
                print("=" * 70)
                print()
        
        elif exc_type == ModuleNotFoundError:
            print(f"\n🚨 MODULE NOT FOUND: {exc_value} 🚨")
            print("=" * 70)
            print("Possible causes:")
            print("• Missing dependency (run: pip install -r requirements.txt)")
            print("• Incorrect Python environment")
            print("• Missing package installation (run: pip install -e .)")
            print("=" * 70)
            print()
        
        # Call default handler for full traceback
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
    
    sys.excepthook = custom_excepthook


def validate_environment() -> bool:
    """Validate the Python environment and installation."""
    issues = []
    
    # Check if we're in a virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✅ Virtual environment detected")
    else:
        issues.append("Not running in a virtual environment")
    
    # Check for required directories
    project_root = Path(__file__).parent.parent.parent
    required_dirs = ["src", "scripts", "tests"]
    
    for dir_name in required_dirs:
        if (project_root / dir_name).exists():
            print(f"✅ {dir_name}/ directory found")
        else:
            issues.append(f"Missing {dir_name}/ directory")
    
    # Check for key files
    key_files = ["setup.py", "requirements.txt", "src/wazuh_mcp_server.py"]
    
    for file_name in key_files:
        if (project_root / file_name).exists():
            print(f"✅ {file_name} found")
        else:
            issues.append(f"Missing {file_name}")
    
    if issues:
        print("\n⚠️  ENVIRONMENT ISSUES DETECTED:")
        for issue in issues:
            print(f"   • {issue}")
        return False
    
    print("\n✅ Environment validation passed!")
    return True


def check_dependencies() -> bool:
    """Check if all required dependencies are installed."""
    required_packages = [
        "mcp",
        "aiohttp", 
        "urllib3",
        "python_dateutil",
        "python_dotenv",
        "pydantic"
    ]
    
    missing = []
    
    for package in required_packages:
        try:
            __import__(package.replace("-", "_"))
            print(f"✅ {package}")
        except ImportError:
            missing.append(package)
            print(f"❌ {package}")
    
    if missing:
        print(f"\n⚠️  MISSING DEPENDENCIES:")
        for package in missing:
            print(f"   • {package}")
        print("\nTo fix: pip install -r requirements.txt")
        return False
    
    print("\n✅ All dependencies installed!")
    return True


def get_python_info():
    """Get Python environment information for debugging."""
    print("🐍 PYTHON ENVIRONMENT INFO:")
    print(f"   Python version: {sys.version}")
    print(f"   Python executable: {sys.executable}")
    print(f"   Platform: {sys.platform}")
    print(f"   Python path: {sys.path[:3]}...") # Show first 3 entries
    
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print(f"   Virtual environment: {sys.prefix}")
    else:
        print("   Virtual environment: Not detected")


def safe_import_with_guidance(module_name: str, package: Optional[str] = None):
    """Safely import a module with helpful error guidance."""
    try:
        if package:
            return __import__(module_name, fromlist=[package])
        else:
            return __import__(module_name)
    except ImportError as e:
        print(f"\n❌ Failed to import {module_name}")
        print(f"Error: {e}")
        
        if "relative import" in str(e):
            print("\n💡 Try running with proper module context:")
            print("   python -m src.wazuh_mcp_server")
            print("   python -m scripts.test_connection")
        else:
            print("\n💡 Try installing dependencies:")
            print("   pip install -r requirements.txt")
            print("   pip install -e .")
        
        raise