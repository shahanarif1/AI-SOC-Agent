# Root Cause Analysis (RCA) Scripts for Import Issues

## Overview

These RCA scripts are designed to diagnose and resolve the specific Python import error affecting some Linux and Windows machines:

```
ImportError: attempted relative import beyond top-level package
```

## The Problem

**Error Location**: `src/api/wazuh_client.py:11`  
**Failing Import**: `from ..config import WazuhConfig`  
**Root Cause**: Package not properly installed with `pip install -e .`

This error occurs when:
1. The script is run directly without proper package installation
2. Python's module resolution cannot find the relative imports
3. The `src` directory structure requires proper package installation for relative imports to work

## Affected Systems

- **Linux**: Various distributions (Ubuntu, RHEL, CentOS, etc.)
- **Windows**: Windows 10/11 with Python 3.9+
- **Common Factor**: Scripts run from wrong directory or package not installed

## Quick Fix (If You Don't Want to Run RCA)

```bash
# Navigate to project root
cd /path/to/Wazuh-MCP-Server

# Install package in editable mode
pip install -e .

# Now run the test
python -m scripts.test_connection
```

## RCA Scripts

### Linux: `rca-linux.sh`

**Comprehensive diagnostic script for Linux systems**

```bash
# Make executable and run
chmod +x rca-linux.sh
./rca-linux.sh
```

**What it does:**
- Analyzes system information and Python environment
- Checks project structure and package installation status
- Tests various import scenarios
- Generates detailed report with suggested fixes
- Creates auto-fix script
- Tests the actual fix

**Output:**
- `rca_output_linux_TIMESTAMP/` directory containing:
  - `rca_report.txt` - Complete analysis report
  - `rca_errors.txt` - Error log
  - `quick_fix.sh` - Automated fix script
  - `pip_install_output.txt` - Installation log

### Windows Batch: `rca-windows.bat`

**Diagnostic script for Windows Command Prompt**

```cmd
rca-windows.bat
```

**Features:**
- Windows-specific environment analysis
- Registry and PATH checking
- Multiple Python installation detection
- Automated fix generation

### Windows PowerShell: `rca-windows.ps1`

**Advanced diagnostic script for PowerShell**

```powershell
# Set execution policy if needed
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# Run the script
.\rca-windows.ps1
```

**Enhanced Features:**
- Object-oriented output
- JSON-formatted reports
- Advanced Windows environment analysis
- PowerShell-based automated fixes

## What the RCA Scripts Analyze

### 1. System Information
- Operating system and version
- Python installation details
- User environment and permissions
- Current working directory

### 2. Python Environment
- Python version and location
- Multiple Python installations
- pip installation and version
- sys.path analysis
- Virtual environment detection

### 3. Project Structure
- Project root detection
- Source directory structure
- Scripts directory analysis
- Installation file presence (setup.py, pyproject.toml)

### 4. Package Installation Status
- Installed packages analysis
- Editable installation detection
- Dependency checking
- Requirements file analysis

### 5. Import Testing
- Basic import tests
- Relative import diagnosis
- Module resolution testing
- Specific failing import recreation

### 6. Environment Variables
- PATH analysis
- PYTHONPATH checking
- Virtual environment variables
- Platform-specific variables

### 7. Permissions and Access
- File and directory permissions
- User access rights
- Security context analysis

## Common Issues Detected

### 1. Package Not Installed
**Symptom**: `ImportError: attempted relative import beyond top-level package`  
**Cause**: Package not installed with `pip install -e .`  
**Fix**: Run `pip install -e .` from project root

### 2. Wrong Working Directory
**Symptom**: Module not found errors  
**Cause**: Running scripts from wrong directory  
**Fix**: Always run from project root

### 3. Python Path Issues
**Symptom**: Import errors despite correct installation  
**Cause**: PYTHONPATH not set correctly  
**Fix**: Use module execution: `python -m scripts.test_connection`

### 4. Multiple Python Installations
**Symptom**: Package installed but not found  
**Cause**: Using different Python executable  
**Fix**: Use consistent Python/pip commands

### 5. Virtual Environment Issues
**Symptom**: Permission errors or conflicting packages  
**Cause**: Not using virtual environment or wrong environment  
**Fix**: Create and activate virtual environment

### 6. Permission Problems
**Symptom**: Installation failures  
**Cause**: Insufficient permissions  
**Fix**: Use virtual environment or user installation

## Understanding the Output

### Linux Output Structure
```
rca_output_linux_TIMESTAMP/
├── rca_report.txt          # Main analysis report
├── rca_errors.txt          # Error messages and warnings  
├── quick_fix.sh            # Automated fix script
├── pip_install_output.txt  # Package installation log
└── ...                     # Additional diagnostic files
```

### Windows Output Structure
```
rca_output_windows_TIMESTAMP/
├── rca_report.txt          # Main analysis report
├── system_info.txt         # System information
├── python_info.json        # Python environment details
├── quick_fix.bat/.ps1      # Automated fix scripts
└── ...                     # Additional diagnostic files
```

## Interpreting Results

### ✅ Success Indicators
- `✓ Successfully imported config`
- `✓ Successfully imported WazuhClientManager`
- `Package installation successful`
- `Import successful after package installation`

### ❌ Problem Indicators
- `✗ Failed to import config: attempted relative import beyond top-level package`
- `✗ Failed to import WazuhClientManager`
- `Package installation failed`
- `wazuh-mcp-server package not found in pip list`

### ⚠️ Warning Indicators
- `No virtual environment detected`
- `Multiple Python installations found`
- `No editable wazuh installations found`

## Automated Fixes

Each RCA script generates automated fix scripts:

### Linux: `quick_fix.sh`
```bash
cd rca_output_linux_*/
chmod +x quick_fix.sh
./quick_fix.sh
```

### Windows: `quick_fix.bat` or `quick_fix.ps1`
```cmd
cd rca_output_windows_*
quick_fix.bat
```

```powershell
cd rca_output_windows_*
.\quick_fix.ps1
```

## Manual Troubleshooting Steps

If automated fixes don't work:

### Step 1: Verify Project Structure
```bash
# Should see these files in project root:
ls -la
# Look for: setup.py, pyproject.toml, src/, scripts/
```

### Step 2: Check Python Installation
```bash
# Verify Python version
python --version
python3 --version

# Check pip
pip --version
pip3 --version
```

### Step 3: Install Package Correctly
```bash
# Navigate to project root (where setup.py or pyproject.toml exists)
cd /path/to/Wazuh-MCP-Server

# Install in editable mode
pip install -e .

# Verify installation
pip list | grep wazuh
```

### Step 4: Use Correct Import Method
```bash
# From project root, use module execution
python -m scripts.test_connection

# NOT: python scripts/test_connection.py
```

### Step 5: Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate (Linux/macOS)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

# Install package
pip install -e .

# Test
python -m scripts.test_connection
```

## Platform-Specific Notes

### Linux-Specific
- Check for conflicting system Python packages
- Verify user permissions for pip installation
- Consider using `python3` instead of `python`
- Check for SELinux or AppArmor restrictions

### Windows-Specific
- Multiple Python installations common (Microsoft Store, python.org, Anaconda)
- Use Python Launcher (`py`) for version management
- Check PATH order for Python executables
- Consider Windows-specific permission issues

## Prevention

To prevent this issue in the future:

1. **Always use virtual environments**
2. **Install packages in editable mode during development**
3. **Run scripts using module execution** (`python -m`)
4. **Document the correct setup procedure**
5. **Use consistent Python/pip commands**

## Support

If RCA scripts don't resolve the issue:

1. **Review the complete RCA report**
2. **Check Python and pip versions compatibility**
3. **Verify Wazuh server connectivity separately**
4. **Consider reinstalling Python in a clean environment**
5. **Open an issue with RCA output attached**

---

**RCA Scripts Version**: 1.0.0  
**Last Updated**: January 2024  
**Compatible with**: Python 3.9+, Windows 10+, Linux (Ubuntu 20.04+)