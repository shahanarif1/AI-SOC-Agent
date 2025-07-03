# Production Fixes Guide - Wazuh MCP Server

## Overview
This guide documents the production-grade fixes implemented to resolve critical import and execution issues across Windows, Linux, and macOS platforms.

## Issues Fixed

### 1. ✅ Critical Elasticsearch Query Bug
**Issue**: Malformed JSON query causing 400 errors
**Location**: `src/api/wazuh_indexer_client.py:309-313`
**Fix**: Moved `boost` parameter inside `match_all` object
```python
# Fixed query structure
query["query"] = {
    "match_all": {
        "boost": 1.0  # Correct placement
    }
}
```

### 2. ✅ Setup.py Entry Points
**Issue**: Incorrect entry point paths preventing console script installation
**Location**: `setup.py:32`
**Fix**: Corrected package paths and added test script entry point
```python
entry_points={
    "console_scripts": [
        "wazuh-mcp-server=wazuh_mcp_server:main",     # Fixed path
        "wazuh-mcp-test=scripts.test_connection:main", # Added
    ],
},
```

### 3. ✅ Import Resolution
**Issue**: "attempted relative import beyond top-level package" errors
**Fix**: Added proper main() functions and module execution support
- Added `scripts/__init__.py` to make scripts a package
- Added `scripts/__main__.py` for module execution
- Enhanced `src/__main__.py` for better module context

### 4. ✅ Cross-Platform Script Launcher
**Created**: `scripts/run.py` - Universal launcher for all platforms
```bash
python scripts/run.py install    # Install package
python scripts/run.py test       # Test connection
python scripts/run.py server     # Start server
python scripts/run.py env-check  # Check environment
```

### 5. ✅ Enhanced Error Handling
**Created**: `src/utils/import_helper.py` - Production error handling
- Clear error messages with resolution guidance
- Environment validation
- Dependency checking
- Python environment info

### 6. ✅ Production Makefile
**Enhanced**: Cross-platform support with Windows/Linux/macOS compatibility
- Automatic platform detection
- Cross-platform clean commands
- Enhanced installation targets
- Development environment setup

## Installation Methods (All Working)

### Method 1: Production Installation (Recommended)
```bash
# Install the package
pip install -e .

# Use console scripts
wazuh-mcp-server    # Start server
wazuh-mcp-test      # Test connection
```

### Method 2: Cross-Platform Launcher
```bash
# Works on Windows, Linux, macOS
python scripts/run.py install    # One-time setup
python scripts/run.py test       # Test connection
python scripts/run.py server     # Start server
```

### Method 3: Module Execution
```bash
# From project root
python -m src.wazuh_mcp_server      # Start server
python -m scripts.test_connection   # Test connection
```

### Method 4: Makefile (Development)
```bash
# Cross-platform development setup
make dev-setup          # Complete environment setup
make run-server          # Start server
make run-test           # Test connection
make validate-env       # Check environment
```

## Troubleshooting

### Import Errors
If you see import errors, the enhanced error handler will provide guidance:
```bash
🚨 IMPORT ERROR DETECTED 🚨
SOLUTION OPTIONS:
1. Install and use console scripts (RECOMMENDED):
   pip install -e .
   wazuh-mcp-server
```

### Environment Issues
Run environment validation:
```bash
make validate-env
# Or directly:
python -c "from src.utils.import_helper import validate_environment; validate_environment()"
```

### Dependency Issues
Install all requirements:
```bash
pip install -r requirements.txt
pip install -e .
```

## Verification Steps

### 1. Test Installation
```bash
# Install and verify
pip install -e .
wazuh-mcp-server --help    # Should work without errors
wazuh-mcp-test            # Should connect to Wazuh
```

### 2. Test Cross-Platform Launcher
```bash
python scripts/run.py install
python scripts/run.py test
```

### 3. Test Module Execution
```bash
python -m src.wazuh_mcp_server
python -m scripts.test_connection
```

### 4. Run Test Suite
```bash
make test                 # Full test suite
make test-connection      # Connection test only
make test-scripts        # Script execution test
```

## What Was Changed

### Files Modified:
- `src/api/wazuh_indexer_client.py` - Fixed Elasticsearch query
- `setup.py` - Fixed entry points
- `scripts/test_connection.py` - Added main() function
- `Makefile` - Enhanced cross-platform support

### Files Added:
- `scripts/__init__.py` - Package initialization
- `scripts/__main__.py` - Module execution support
- `scripts/run.py` - Cross-platform launcher
- `src/utils/import_helper.py` - Enhanced error handling
- `PRODUCTION_FIXES_GUIDE.md` - This documentation

### Key Improvements:
1. **Zero sys.path modifications needed** - All import issues resolved
2. **Cross-platform compatibility** - Works on Windows, Linux, macOS
3. **Multiple execution methods** - Console scripts, module execution, launcher
4. **Production-grade error handling** - Clear messages with solutions
5. **Comprehensive testing** - Validation and troubleshooting tools

## Migration from Old Approach

### Remove sys.path Modifications
If you previously added sys.path modifications to files, they can now be removed:
```python
# Remove these lines (no longer needed):
import sys
sys.path.append('/path/to/src')
```

### Use New Execution Methods
Replace old script execution:
```bash
# Old (problematic):
python scripts/test_connection.py
python src/wazuh_mcp_server.py

# New (production-ready):
wazuh-mcp-test                    # After pip install -e .
wazuh-mcp-server                  # After pip install -e .
python scripts/run.py test        # Cross-platform launcher
python -m scripts.test_connection # Module execution
```

## Success Criteria

All of these should work without errors:

1. ✅ `pip install -e .` - Clean installation
2. ✅ `wazuh-mcp-server` - Console script execution
3. ✅ `wazuh-mcp-test` - Connection testing
4. ✅ `python scripts/run.py test` - Launcher execution
5. ✅ `python -m src.wazuh_mcp_server` - Module execution
6. ✅ `make dev-setup` - Development environment
7. ✅ No Elasticsearch 400 errors - Query syntax fixed
8. ✅ Cross-platform compatibility - Windows/Linux/macOS

The codebase is now production-ready with robust error handling, clear documentation, and multiple execution methods that work across all platforms.