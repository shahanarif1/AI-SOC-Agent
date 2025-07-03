#!/usr/bin/env python3
"""
Production-grade import resolver for Wazuh MCP Server.
Handles cross-platform import path resolution and module loading.
"""

import os
import sys
import importlib.util
from pathlib import Path
from typing import Optional, List


class ImportResolver:
    """Production-grade import path resolver for cross-platform compatibility."""
    
    def __init__(self):
        self.project_root = self._find_project_root()
        self.src_path = self.project_root / "src"
        self._setup_paths()
    
    def _find_project_root(self) -> Path:
        """Find the project root directory by looking for key files."""
        current = Path(__file__).resolve()
        
        # Look for project markers (setup.py, requirements.txt, etc.)
        markers = ['setup.py', 'requirements.txt', 'manifest.json', '.git']
        
        for parent in [current] + list(current.parents):
            if any((parent / marker).exists() for marker in markers):
                return parent
        
        # Fallback: assume we're in src/utils and go up two levels
        return current.parent.parent.parent
    
    def _setup_paths(self):
        """Setup Python import paths."""
        paths_to_add = [
            str(self.src_path),
            str(self.project_root),
        ]
        
        for path in paths_to_add:
            if path not in sys.path:
                sys.path.insert(0, path)
    
    def verify_imports(self) -> bool:
        """Verify that critical modules can be imported."""
        critical_modules = [
            'config',
            'api.wazuh_client_manager',
            'utils.logging',
            'analyzers',
        ]
        
        for module_name in critical_modules:
            try:
                spec = importlib.util.find_spec(module_name)
                if spec is None:
                    print(f"❌ Cannot find module: {module_name}")
                    return False
                else:
                    print(f"✅ Module found: {module_name}")
            except Exception as e:
                print(f"❌ Error checking module {module_name}: {e}")
                return False
        
        return True
    
    def get_debug_info(self) -> dict:
        """Get debug information about import paths and environment."""
        return {
            "project_root": str(self.project_root),
            "src_path": str(self.src_path),
            "python_path": sys.path,
            "working_directory": os.getcwd(),
            "src_exists": self.src_path.exists(),
            "config_exists": (self.src_path / "config.py").exists(),
            "python_version": sys.version,
        }


def setup_imports(verify: bool = False) -> ImportResolver:
    """
    Setup import paths for Wazuh MCP Server.
    
    Args:
        verify: Whether to verify that critical modules can be imported
        
    Returns:
        ImportResolver instance
        
    Raises:
        ImportError: If verification fails and verify=True
    """
    resolver = ImportResolver()
    
    if verify:
        if not resolver.verify_imports():
            debug_info = resolver.get_debug_info()
            print("❌ Import verification failed!")
            print("Debug information:")
            for key, value in debug_info.items():
                print(f"  {key}: {value}")
            raise ImportError("Critical modules cannot be imported")
    
    return resolver


def safe_import(module_name: str, package: Optional[str] = None):
    """
    Safely import a module with enhanced error reporting.
    
    Args:
        module_name: Name of the module to import
        package: Package name for relative imports
        
    Returns:
        Imported module
        
    Raises:
        ImportError: With enhanced error information
    """
    try:
        if package:
            return importlib.import_module(module_name, package)
        else:
            return importlib.import_module(module_name)
    except ImportError as e:
        resolver = ImportResolver()
        debug_info = resolver.get_debug_info()
        
        error_msg = f"""
Failed to import module: {module_name}
Original error: {e}

Debug Information:
- Project root: {debug_info['project_root']}
- Source path: {debug_info['src_path']}
- Source exists: {debug_info['src_exists']}
- Config exists: {debug_info['config_exists']}
- Working directory: {debug_info['working_directory']}
- Python version: {debug_info['python_version']}

Python path:
{chr(10).join(f"  {p}" for p in debug_info['python_path'])}

Suggestions:
1. Ensure you're running from the project root directory
2. Check that the src/ directory exists
3. Verify all required dependencies are installed
4. Try running: python -m src.wazuh_mcp_server instead of python src/wazuh_mcp_server.py
"""
        raise ImportError(error_msg) from e


if __name__ == "__main__":
    # Test the import resolver
    print("🔍 Testing Wazuh MCP Server import resolver...")
    
    try:
        resolver = setup_imports(verify=True)
        print("✅ All imports verified successfully!")
        
        debug_info = resolver.get_debug_info()
        print("\n📊 Environment Information:")
        for key, value in debug_info.items():
            print(f"  {key}: {value}")
            
    except Exception as e:
        print(f"❌ Import test failed: {e}")
        sys.exit(1)