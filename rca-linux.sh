#!/bin/bash
# Root Cause Analysis Script for Wazuh MCP Server Import Issues - Linux
# This script gathers diagnostic information and creates a findings report

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW} $1${NC}"
    echo -e "${YELLOW}========================================${NC}"
}

# Create output directory with timestamp
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="rca_findings_linux_${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"

log_info "Starting Root Cause Analysis for Wazuh MCP Server Import Issues"
log_info "Output directory: $OUTPUT_DIR"

# Start building the findings report
REPORT_FILE="$OUTPUT_DIR/RCA_FINDINGS_REPORT.txt"

# Create report header
cat > "$REPORT_FILE" << EOF
================================================================================
                   ROOT CAUSE ANALYSIS FINDINGS REPORT
                        Wazuh MCP Server Import Issues
================================================================================

Analysis Date: $(date)
System: Linux
Report Version: 1.0

ISSUE SUMMARY:
-------------
Error: ImportError: attempted relative import beyond top-level package
File: src/api/wazuh_client.py, line 11
Failing Import: from ..config import WazuhConfig

================================================================================

EOF

log_section "SYSTEM INFORMATION"

# System information
log_info "Gathering system information..."
{
    echo "1. SYSTEM INFORMATION"
    echo "===================="
    echo "Hostname: $(hostname)"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"')"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "User: $(whoami)"
    echo "Home Directory: $HOME"
    echo "Current Directory: $(pwd)"
    echo "Script Run Location: $0"
    echo ""
} >> "$REPORT_FILE"

log_section "PYTHON ENVIRONMENT"

# Python version and location
log_info "Checking Python installation..."
{
    echo "2. PYTHON ENVIRONMENT"
    echo "===================="
    echo ""
    echo "2.1 Python Installations Found:"
    echo "-------------------------------"
} >> "$REPORT_FILE"

# Check all Python versions
for py_cmd in python python3 python3.9 python3.10 python3.11 python3.12 python3.13; do
    if command -v $py_cmd &> /dev/null; then
        {
            echo "  $py_cmd:"
            echo "    Version: $($py_cmd --version 2>&1)"
            echo "    Location: $(which $py_cmd)"
            echo "    Real Path: $(readlink -f $(which $py_cmd) 2>/dev/null || echo 'N/A')"
        } >> "$REPORT_FILE"
    fi
done

# Python sys.path analysis
{
    echo ""
    echo "2.2 Python Module Search Path (sys.path):"
    echo "-----------------------------------------"
    python3 -c "
import sys
for i, path in enumerate(sys.path):
    print(f'  [{i}] {path}')
" 2>&1 || echo "  ERROR: Could not retrieve Python sys.path"
    echo ""
} >> "$REPORT_FILE"

# Pip information
{
    echo "2.3 Package Manager (pip) Information:"
    echo "-------------------------------------"
    echo "  pip3 version: $(pip3 --version 2>&1 || echo 'pip3 not found')"
    echo "  pip3 location: $(which pip3 2>&1 || echo 'pip3 not found')"
    echo ""
} >> "$REPORT_FILE"

log_section "PROJECT STRUCTURE ANALYSIS"

# Find project root
log_info "Analyzing project structure..."
PROJECT_ROOT=""
CURRENT_DIR=$(pwd)

# Check multiple levels for project root
if [ -f "pyproject.toml" ] || [ -f "setup.py" ]; then
    PROJECT_ROOT=$(pwd)
elif [ -f "../pyproject.toml" ] || [ -f "../setup.py" ]; then
    PROJECT_ROOT=$(cd .. && pwd)
elif [ -f "../../pyproject.toml" ] || [ -f "../../setup.py" ]; then
    PROJECT_ROOT=$(cd ../.. && pwd)
fi

{
    echo "3. PROJECT STRUCTURE ANALYSIS"
    echo "============================="
    echo ""
    echo "3.1 Project Root Detection:"
    echo "---------------------------"
    echo "  Current Directory: $CURRENT_DIR"
    echo "  Detected Project Root: ${PROJECT_ROOT:-NOT FOUND}"
    echo ""
    
    echo "3.2 Directory Structure:"
    echo "------------------------"
} >> "$REPORT_FILE"

if [ -n "$PROJECT_ROOT" ]; then
    cd "$PROJECT_ROOT"
    {
        echo "  Project Root Contents:"
        ls -la | sed 's/^/    /'
        echo ""
        
        echo "  Key Files Present:"
        for file in setup.py pyproject.toml requirements.txt README.md .env .env.example; do
            if [ -f "$file" ]; then
                echo "    ✓ $file ($(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null || echo 'size unknown') bytes)"
            else
                echo "    ✗ $file (NOT FOUND)"
            fi
        done
        echo ""
        
        echo "  Source Directory Analysis:"
        if [ -d "src" ]; then
            echo "    src/ directory EXISTS"
            echo "    Python files in src/:"
            find src -name "*.py" -type f | head -20 | sed 's/^/      /'
            echo "    Total Python files: $(find src -name "*.py" -type f | wc -l)"
        else
            echo "    src/ directory NOT FOUND"
        fi
        echo ""
        
        echo "  Scripts Directory Analysis:"
        if [ -d "scripts" ]; then
            echo "    scripts/ directory EXISTS"
            echo "    Contents:"
            ls -la scripts/ | sed 's/^/      /'
        else
            echo "    scripts/ directory NOT FOUND"
        fi
    } >> "$REPORT_FILE"
else
    echo "  ERROR: Could not locate project root directory" >> "$REPORT_FILE"
fi

log_section "PACKAGE INSTALLATION STATUS"

log_info "Checking package installation status..."
{
    echo ""
    echo "4. PACKAGE INSTALLATION STATUS"
    echo "=============================="
    echo ""
    echo "4.1 Installed Packages (wazuh-related):"
    echo "---------------------------------------"
    pip3 list 2>&1 | grep -i wazuh | sed 's/^/  /' || echo "  No wazuh-related packages found"
    echo ""
    
    echo "4.2 Editable Installations:"
    echo "---------------------------"
    pip3 list --editable 2>&1 | grep -i wazuh | sed 's/^/  /' || echo "  No editable wazuh installations found"
    echo ""
    
    echo "4.3 Package Installation Method:"
    echo "--------------------------------"
    if pip3 show wazuh-mcp-server &>/dev/null; then
        echo "  Package 'wazuh-mcp-server' is installed"
        pip3 show wazuh-mcp-server | grep -E "Name:|Version:|Location:|Requires:" | sed 's/^/  /'
    else
        echo "  Package 'wazuh-mcp-server' is NOT installed via pip"
    fi
    echo ""
} >> "$REPORT_FILE"

log_section "IMPORT ERROR ANALYSIS"

log_info "Analyzing import error conditions..."
{
    echo "5. IMPORT ERROR ANALYSIS"
    echo "========================"
    echo ""
    echo "5.1 Error Context:"
    echo "------------------"
    echo "  Error Type: ImportError"
    echo "  Error Message: attempted relative import beyond top-level package"
    echo "  Source File: src/api/wazuh_client.py"
    echo "  Line Number: 11"
    echo "  Import Statement: from ..config import WazuhConfig"
    echo ""
    
    echo "5.2 Import Path Analysis:"
    echo "-------------------------"
} >> "$REPORT_FILE"

if [ -n "$PROJECT_ROOT" ]; then
    cd "$PROJECT_ROOT"
    
    # Test various import scenarios
    {
        echo "  Test 1 - Direct module import (without package installation):"
        python3 -c "
import sys
print(f'    Working directory: {sys.argv[1]}')
sys.path.insert(0, sys.argv[1] + '/src')
try:
    import config
    print('    Result: SUCCESS - config module can be imported')
except Exception as e:
    print(f'    Result: FAILED - {type(e).__name__}: {e}')
" "$PROJECT_ROOT" 2>&1
        echo ""
        
        echo "  Test 2 - Package import (wazuh_mcp_server):"
        python3 -c "
try:
    import wazuh_mcp_server
    print('    Result: SUCCESS - wazuh_mcp_server package can be imported')
    print(f'    Package location: {wazuh_mcp_server.__file__ if hasattr(wazuh_mcp_server, \"__file__\") else \"Unknown\"}')
except Exception as e:
    print(f'    Result: FAILED - {type(e).__name__}: {e}')
" 2>&1
        echo ""
        
        echo "  Test 3 - Problematic import (api.wazuh_client_manager):"
        python3 -c "
import sys
sys.path.insert(0, '$PROJECT_ROOT/src')
try:
    from api.wazuh_client_manager import WazuhClientManager
    print('    Result: SUCCESS - WazuhClientManager can be imported')
except Exception as e:
    print(f'    Result: FAILED - {type(e).__name__}: {e}')
" 2>&1
        echo ""
        
        echo "  Test 4 - Relative import context:"
        python3 -c "
import sys
sys.path.insert(0, '$PROJECT_ROOT/src')
try:
    import api.wazuh_client
    print('    Result: PARTIAL - api.wazuh_client module found')
    print('    Note: This will fail on relative imports within the module')
except Exception as e:
    print(f'    Result: FAILED - {type(e).__name__}: {e}')
" 2>&1
        echo ""
    } >> "$REPORT_FILE"
fi

log_section "ENVIRONMENT VARIABLES"

log_info "Checking environment variables..."
{
    echo "6. ENVIRONMENT VARIABLES"
    echo "========================"
    echo ""
    echo "6.1 Python-related Variables:"
    echo "-----------------------------"
    echo "  PYTHONPATH: ${PYTHONPATH:-NOT SET}"
    echo "  PYTHONHOME: ${PYTHONHOME:-NOT SET}"
    echo "  VIRTUAL_ENV: ${VIRTUAL_ENV:-NOT SET}"
    echo "  CONDA_DEFAULT_ENV: ${CONDA_DEFAULT_ENV:-NOT SET}"
    echo ""
    
    echo "6.2 System Variables:"
    echo "--------------------"
    echo "  PATH entries containing 'python':"
    echo "$PATH" | tr ':' '\n' | grep -i python | sed 's/^/    /' || echo "    None found"
    echo ""
    echo "  Shell: $SHELL"
    echo "  Terminal: $TERM"
    echo ""
} >> "$REPORT_FILE"

log_section "DEPENDENCY ANALYSIS"

log_info "Analyzing dependencies..."
{
    echo "7. DEPENDENCY ANALYSIS"
    echo "======================"
    echo ""
    echo "7.1 Required Package Check:"
    echo "---------------------------"
    
    REQUIRED_PACKAGES="mcp fastapi websockets uvicorn pydantic requests urllib3 python-dotenv"
    for package in $REQUIRED_PACKAGES; do
        if python3 -c "import $package" 2>/dev/null; then
            version=$(python3 -c "import $package; print(getattr($package, '__version__', 'installed'))" 2>/dev/null || echo "version unknown")
            echo "  ✓ $package: $version"
        else
            echo "  ✗ $package: NOT INSTALLED"
        fi
    done
    echo ""
    
    echo "7.2 Total Installed Packages:"
    echo "-----------------------------"
    echo "  Total packages: $(pip3 list 2>/dev/null | wc -l || echo 'Unable to count')"
    echo ""
} >> "$REPORT_FILE"

log_section "PERMISSION AND ACCESS ANALYSIS"

log_info "Checking permissions..."
{
    echo "8. PERMISSION AND ACCESS ANALYSIS"
    echo "================================="
    echo ""
    
    if [ -n "$PROJECT_ROOT" ]; then
        cd "$PROJECT_ROOT"
        echo "8.1 Directory Permissions:"
        echo "--------------------------"
        echo "  Project root:"
        ls -ld . | sed 's/^/    /'
        
        if [ -d "src" ]; then
            echo "  src directory:"
            ls -ld src | sed 's/^/    /'
        fi
        
        if [ -d "scripts" ]; then
            echo "  scripts directory:"
            ls -ld scripts | sed 's/^/    /'
        fi
        echo ""
        
        echo "8.2 File Ownership:"
        echo "-------------------"
        echo "  Current user: $(whoami)"
        echo "  User groups: $(groups)"
        echo ""
    fi
} >> "$REPORT_FILE"

log_section "DIAGNOSTIC SUMMARY"

log_info "Creating diagnostic summary..."
{
    echo "9. DIAGNOSTIC SUMMARY"
    echo "===================="
    echo ""
    echo "9.1 Key Findings:"
    echo "-----------------"
    
    # Check if package is installed
    if pip3 show wazuh-mcp-server &>/dev/null; then
        echo "  • Package Installation: FOUND (wazuh-mcp-server installed)"
    else
        echo "  • Package Installation: NOT FOUND (wazuh-mcp-server not installed)"
    fi
    
    # Check if running from correct location
    if [ -n "$PROJECT_ROOT" ]; then
        echo "  • Project Root: FOUND at $PROJECT_ROOT"
    else
        echo "  • Project Root: NOT FOUND (unable to locate setup.py or pyproject.toml)"
    fi
    
    # Check Python version
    PYTHON_VERSION=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    echo "  • Python Version: $PYTHON_VERSION"
    
    # Check virtual environment
    if [ -n "$VIRTUAL_ENV" ]; then
        echo "  • Virtual Environment: ACTIVE ($VIRTUAL_ENV)"
    else
        echo "  • Virtual Environment: NOT ACTIVE"
    fi
    
    echo ""
    echo "9.2 Probable Root Causes:"
    echo "-------------------------"
    echo "  1. Package not installed in editable mode (pip install -e .)"
    echo "  2. Script executed from incorrect directory"
    echo "  3. Python path not properly configured"
    echo "  4. Missing or incorrect package structure"
    echo ""
    
    echo "9.3 Additional Observations:"
    echo "----------------------------"
    
    # Check for common issues
    if [ ! -d "$PROJECT_ROOT/src" ]; then
        echo "  • WARNING: src/ directory not found in project root"
    fi
    
    if [ ! -f "$PROJECT_ROOT/setup.py" ] && [ ! -f "$PROJECT_ROOT/pyproject.toml" ]; then
        echo "  • WARNING: No setup.py or pyproject.toml found"
    fi
    
    if [ -z "$PYTHONPATH" ]; then
        echo "  • INFO: PYTHONPATH environment variable not set"
    fi
    
    echo ""
} >> "$REPORT_FILE"

# Add footer to report
{
    echo "================================================================================"
    echo "END OF REPORT"
    echo "Generated on: $(date)"
    echo "Report location: $REPORT_FILE"
    echo "================================================================================"
} >> "$REPORT_FILE"

# Create additional diagnostic files
log_info "Collecting additional diagnostic data..."

# Save pip list output
pip3 list > "$OUTPUT_DIR/pip_list.txt" 2>&1

# Save pip freeze output
pip3 freeze > "$OUTPUT_DIR/pip_freeze.txt" 2>&1

# Save directory tree (if tree command available)
if command -v tree &> /dev/null && [ -n "$PROJECT_ROOT" ]; then
    cd "$PROJECT_ROOT"
    tree -I '__pycache__|*.pyc|.git' -L 3 > "$OUTPUT_DIR/directory_tree.txt" 2>&1
fi

# Save environment variables
env | sort > "$OUTPUT_DIR/environment_variables.txt"

log_section "ANALYSIS COMPLETE"

log_success "Root Cause Analysis completed!"
echo ""
echo "📁 Report generated: $REPORT_FILE"
echo "📁 Additional files saved in: $OUTPUT_DIR/"
echo ""
echo "Files created:"
echo "  - RCA_FINDINGS_REPORT.txt (main report)"
echo "  - pip_list.txt (installed packages)"
echo "  - pip_freeze.txt (package versions)"
echo "  - environment_variables.txt (all env vars)"
if [ -f "$OUTPUT_DIR/directory_tree.txt" ]; then
    echo "  - directory_tree.txt (project structure)"
fi
echo ""
echo "Please review the findings report for detailed analysis of the import issue."