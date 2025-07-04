#!/usr/bin/env python3
"""
Dependency verification script for Wazuh MCP Server.
Checks that all required dependencies are available and working.
"""

import sys
import importlib
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional


def check_python_version() -> bool:
    """Check if Python version meets requirements."""
    required_version = (3, 8)
    current_version = sys.version_info[:2]
    
    print(f"🐍 Python version: {sys.version}")
    if current_version >= required_version:
        print(f"✅ Python {current_version} >= {required_version}")
        return True
    else:
        print(f"❌ Python {current_version} < {required_version}")
        return False


def get_requirements() -> List[str]:
    """Read requirements from requirements.txt."""
    req_file = Path(__file__).parent.parent / "requirements.txt"
    
    if not req_file.exists():
        print(f"❌ Requirements file not found: {req_file}")
        return []
    
    requirements = []
    with open(req_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                # Extract package name (before version specifier)
                package = line.split('>=')[0].split('==')[0].split('<')[0]
                requirements.append(package)
    
    return requirements


def check_package_import(package: str) -> Tuple[bool, Optional[str]]:
    """Check if a package can be imported."""
    try:
        # Handle special cases
        import_name = package
        if package == 'python-dotenv':
            import_name = 'dotenv'
        elif package == 'python-dateutil':
            import_name = 'dateutil'
        
        module = importlib.import_module(import_name)
        version = getattr(module, '__version__', 'unknown')
        return True, version
    except ImportError as e:
        return False, str(e)


def check_critical_imports() -> bool:
    """Check critical application imports."""
    critical_imports = [
        'src.config',
        'src.utils.error_recovery', 
        'src.utils.ssl_config',
        'src.utils.import_resolver',
        'src.api.wazuh_client_manager',
        'src.api.wazuh_indexer_client'
    ]
    
    print("\n🔍 Checking critical application imports...")
    
    # Add src to path
    src_path = str(Path(__file__).parent.parent / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    
    all_good = True
    for module_name in critical_imports:
        try:
            importlib.import_module(module_name)
            print(f"✅ {module_name}")
        except ImportError as e:
            print(f"❌ {module_name}: {e}")
            all_good = False
    
    return all_good


def verify_setup_py_consistency() -> bool:
    """Check if setup.py dependencies match requirements.txt."""
    setup_file = Path(__file__).parent.parent / "setup.py"
    
    if not setup_file.exists():
        print("⚠️ setup.py not found")
        return False
    
    print("\n📋 Checking setup.py consistency...")
    
    # Read requirements.txt
    requirements = set(get_requirements())
    
    # Read setup.py (simplified - look for install_requires)
    with open(setup_file, 'r') as f:
        content = f.read()
    
    # Extract packages from setup.py (basic parsing)
    setup_packages = set()
    in_install_requires = False
    for line in content.split('\n'):
        line = line.strip()
        if 'install_requires=' in line:
            in_install_requires = True
        elif in_install_requires:
            if line == '],':
                break
            if '"' in line:
                package = line.split('"')[1].split('>=')[0].split('==')[0]
                setup_packages.add(package)
    
    # Compare
    missing_in_setup = requirements - setup_packages
    extra_in_setup = setup_packages - requirements
    
    if missing_in_setup:
        print(f"❌ Missing in setup.py: {missing_in_setup}")
        return False
    
    if extra_in_setup:
        print(f"⚠️ Extra in setup.py: {extra_in_setup}")
    
    print("✅ setup.py and requirements.txt are consistent")
    return True


def main():
    """Main verification function."""
    print("🔍 Wazuh MCP Server Dependency Verification")
    print("=" * 50)
    
    all_checks_passed = True
    
    # Check Python version
    if not check_python_version():
        all_checks_passed = False
    
    # Check requirements
    print(f"\n📦 Checking package dependencies...")
    requirements = get_requirements()
    
    if not requirements:
        print("❌ No requirements found")
        all_checks_passed = False
    else:
        print(f"Found {len(requirements)} required packages")
        
        for package in requirements:
            success, info = check_package_import(package)
            if success:
                print(f"✅ {package} (v{info})")
            else:
                print(f"❌ {package}: {info}")
                all_checks_passed = False
    
    # Check critical imports
    if not check_critical_imports():
        all_checks_passed = False
    
    # Check setup.py consistency
    if not verify_setup_py_consistency():
        all_checks_passed = False
    
    # Summary
    print("\n" + "=" * 50)
    if all_checks_passed:
        print("🎉 All dependency checks passed!")
        print("✅ Your environment is ready for Wazuh MCP Server")
        return 0
    else:
        print("❌ Some dependency checks failed")
        print("💡 Run: pip install -r requirements.txt")
        return 1


if __name__ == "__main__":
    sys.exit(main())