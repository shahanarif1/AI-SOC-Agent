# Root Cause Analysis Script for Wazuh MCP Server Import Issues - Windows PowerShell
# This script gathers diagnostic information and creates a findings report

# Set execution policy for this session
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# Colors for output
function Write-Info($message) { Write-Host "[INFO] $message" -ForegroundColor Blue }
function Write-Success($message) { Write-Host "[SUCCESS] $message" -ForegroundColor Green }
function Write-Warning($message) { Write-Host "[WARNING] $message" -ForegroundColor Yellow }
function Write-Error($message) { Write-Host "[ERROR] $message" -ForegroundColor Red }
function Write-Section($message) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host " $message" -ForegroundColor Yellow  
    Write-Host "========================================" -ForegroundColor Yellow
}

# Create output directory with timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "rca_findings_windows_ps_$timestamp"
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

Write-Info "Starting Root Cause Analysis for Wazuh MCP Server Import Issues"
Write-Info "Output directory: $outputDir"

# Start building the findings report
$reportFile = "$outputDir\RCA_FINDINGS_REPORT.txt"

# Create report header
@"
================================================================================
                   ROOT CAUSE ANALYSIS FINDINGS REPORT
                        Wazuh MCP Server Import Issues
================================================================================

Analysis Date: $(Get-Date)
System: Windows (PowerShell)
Report Version: 1.0

ISSUE SUMMARY:
-------------
Error: ImportError: attempted relative import beyond top-level package
File: src\api\wazuh_client.py, line 11
Failing Import: from ..config import WazuhConfig

================================================================================

"@ | Out-File -FilePath $reportFile -Encoding UTF8

Write-Section "SYSTEM INFORMATION"

Write-Info "Gathering system information..."

# System information
$systemInfo = @"
1. SYSTEM INFORMATION
====================
Computer Name: $env:COMPUTERNAME
User: $env:USERNAME
User Domain: $env:USERDOMAIN
User Profile: $env:USERPROFILE
OS Version: $((Get-WmiObject -Class Win32_OperatingSystem).Caption)
OS Architecture: $((Get-WmiObject -Class Win32_OperatingSystem).OSArchitecture)
OS Build: $((Get-WmiObject -Class Win32_OperatingSystem).BuildNumber)
PowerShell Version: $($PSVersionTable.PSVersion.ToString())
PowerShell Edition: $($PSVersionTable.PSEdition)
.NET Version: $([System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription)
Current Directory: $(Get-Location)
Script Location: $PSCommandPath
System Uptime: $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)

"@
$systemInfo | Out-File -FilePath $reportFile -Encoding UTF8 -Append

Write-Section "PYTHON ENVIRONMENT"

Write-Info "Checking Python installation..."

# Python environment
$pythonInfo = @"
2. PYTHON ENVIRONMENT
====================

2.1 Python Installations Found:
-------------------------------
"@
$pythonInfo | Out-File -FilePath $reportFile -Encoding UTF8 -Append

# Check various Python commands
$pythonCommands = @('python', 'python3', 'py')
foreach ($cmd in $pythonCommands) {
    try {
        $location = (Get-Command $cmd -ErrorAction SilentlyContinue).Source
        if ($location) {
            $version = & $cmd --version 2>&1
            $realPath = (Get-Item $location).Target
            @"
  $cmd:
    Version: $version
    Location: $location
    Real Path: $realPath

"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        }
        else {
            "  $cmd: NOT FOUND`n" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        }
    }
    catch {
        "  $cmd: NOT FOUND`n" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
}

# Python sys.path analysis
Write-Info "Python sys.path analysis..."
@"
2.2 Python Module Search Path (sys.path):
-----------------------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

try {
    $syspath = python -c "import sys; import json; print(json.dumps(sys.path))" 2>&1 | ConvertFrom-Json
    for ($i = 0; $i -lt $syspath.Length; $i++) {
        "  [$i] $($syspath[$i])" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
}
catch {
    "  ERROR: Could not retrieve Python sys.path" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}
"`n" | Out-File -FilePath $reportFile -Encoding UTF8 -Append

# Pip information
@"
2.3 Package Manager (pip) Information:
-------------------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

$pipCommands = @('pip', 'pip3')
foreach ($cmd in $pipCommands) {
    try {
        $location = (Get-Command $cmd -ErrorAction SilentlyContinue).Source
        if ($location) {
            $version = & $cmd --version 2>&1
            @"
  $cmd version: $version
  $cmd location: $location
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        }
        else {
            "  $cmd: NOT FOUND" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        }
    }
    catch {
        "  $cmd: NOT FOUND" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
}
"`n" | Out-File -FilePath $reportFile -Encoding UTF8 -Append

Write-Section "PROJECT STRUCTURE ANALYSIS"

Write-Info "Analyzing project structure..."

# Find project root
$projectRoot = $null
$currentDir = Get-Location

# Check current directory and parent directories for project files
$checkDirs = @($currentDir, (Split-Path $currentDir -Parent), (Split-Path (Split-Path $currentDir -Parent) -Parent))

foreach ($dir in $checkDirs) {
    if ((Test-Path "$dir\pyproject.toml") -or (Test-Path "$dir\setup.py")) {
        $projectRoot = $dir
        break
    }
}

@"
3. PROJECT STRUCTURE ANALYSIS
=============================

3.1 Project Root Detection:
---------------------------
  Current Directory: $currentDir
  Detected Project Root: $(if ($projectRoot) { $projectRoot } else { "NOT FOUND" })

3.2 Directory Structure:
------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

if ($projectRoot) {
    Push-Location $projectRoot
    
    "  Project Root Contents:" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    Get-ChildItem | Select-Object Name, Mode, Length, LastWriteTime | Format-Table | Out-String | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    
    "`n  Key Files Present:" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    $keyFiles = @("setup.py", "pyproject.toml", "requirements.txt", "README.md", ".env", ".env.example")
    foreach ($file in $keyFiles) {
        if (Test-Path $file) {
            $fileInfo = Get-Item $file
            "    ✓ $file ($($fileInfo.Length) bytes)" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        }
        else {
            "    ✗ $file (NOT FOUND)" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        }
    }
    
    "`n  Source Directory Analysis:" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    if (Test-Path "src") {
        "    src\ directory EXISTS" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        $pyFiles = Get-ChildItem -Path "src" -Recurse -Filter "*.py"
        "    Python files in src: $($pyFiles.Count)" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        "    Sample files:" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        $pyFiles | Select-Object -First 10 | ForEach-Object { "      $($_.FullName.Replace($projectRoot, '.'))" } | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
    else {
        "    src\ directory NOT FOUND" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
    
    "`n  Scripts Directory Analysis:" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    if (Test-Path "scripts") {
        "    scripts\ directory EXISTS" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        "    Contents:" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        Get-ChildItem -Path "scripts" | Select-Object Name, Length, LastWriteTime | Format-Table | Out-String | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
    else {
        "    scripts\ directory NOT FOUND" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
    
    Pop-Location
}
else {
    "  ERROR: Could not locate project root directory" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}
"`n" | Out-File -FilePath $reportFile -Encoding UTF8 -Append

Write-Section "PACKAGE INSTALLATION STATUS"

Write-Info "Checking package installation status..."

@"
4. PACKAGE INSTALLATION STATUS
==============================

4.1 Installed Packages (wazuh-related):
---------------------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

try {
    $pipList = pip list 2>&1
    $wazuhPackages = $pipList | Select-String -Pattern "wazuh" -CaseSensitive:$false
    if ($wazuhPackages) {
        $wazuhPackages | ForEach-Object { "  $_" } | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
    else {
        "  No wazuh-related packages found" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
}
catch {
    "  ERROR: Could not retrieve pip list" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}

@"

4.2 Editable Installations:
---------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

try {
    $editableList = pip list --editable 2>&1
    $editableWazuh = $editableList | Select-String -Pattern "wazuh" -CaseSensitive:$false
    if ($editableWazuh) {
        $editableWazuh | ForEach-Object { "  $_" } | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
    else {
        "  No editable wazuh installations found" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
}
catch {
    "  ERROR: Could not retrieve editable installations" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}

@"

4.3 Package Installation Method:
--------------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

try {
    $packageInfo = pip show wazuh-mcp-server 2>&1
    if ($LASTEXITCODE -eq 0) {
        "  Package 'wazuh-mcp-server' is installed" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        $packageInfo | Select-String -Pattern "Name:|Version:|Location:|Requires:" | ForEach-Object { "  $_" } | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
    else {
        "  Package 'wazuh-mcp-server' is NOT installed via pip" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
}
catch {
    "  ERROR: Could not check package status" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}
"`n" | Out-File -FilePath $reportFile -Encoding UTF8 -Append

Write-Section "IMPORT ERROR ANALYSIS"

Write-Info "Analyzing import error conditions..."

@"
5. IMPORT ERROR ANALYSIS
========================

5.1 Error Context:
------------------
  Error Type: ImportError
  Error Message: attempted relative import beyond top-level package
  Source File: src\api\wazuh_client.py
  Line Number: 11
  Import Statement: from ..config import WazuhConfig

5.2 Import Path Analysis:
-------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

if ($projectRoot) {
    Push-Location $projectRoot
    
    # Test 1: Direct module import
    "  Test 1 - Direct module import (without package installation):" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    $test1Result = python -c @"
import sys
import os
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))
try:
    import config
    print('    Result: SUCCESS - config module can be imported')
except Exception as e:
    print(f'    Result: FAILED - {type(e).__name__}: {e}')
"@ 2>&1
    $test1Result | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    
    # Test 2: Package import
    "`n  Test 2 - Package import (wazuh_mcp_server):" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    $test2Result = python -c @"
try:
    import wazuh_mcp_server
    print('    Result: SUCCESS - wazuh_mcp_server package can be imported')
    print(f'    Package location: {wazuh_mcp_server.__file__ if hasattr(wazuh_mcp_server, "__file__") else "Unknown"}')
except Exception as e:
    print(f'    Result: FAILED - {type(e).__name__}: {e}')
"@ 2>&1
    $test2Result | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    
    # Test 3: Problematic import
    "`n  Test 3 - Problematic import (api.wazuh_client_manager):" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    $test3Result = python -c @"
import sys
import os
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))
try:
    from api.wazuh_client_manager import WazuhClientManager
    print('    Result: SUCCESS - WazuhClientManager can be imported')
except Exception as e:
    print(f'    Result: FAILED - {type(e).__name__}: {e}')
"@ 2>&1
    $test3Result | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    
    # Test 4: Relative import context
    "`n  Test 4 - Relative import context:" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    $test4Result = python -c @"
import sys
import os
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))
try:
    import api.wazuh_client
    print('    Result: PARTIAL - api.wazuh_client module found')
    print('    Note: This will fail on relative imports within the module')
except Exception as e:
    print(f'    Result: FAILED - {type(e).__name__}: {e}')
"@ 2>&1
    $test4Result | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    
    Pop-Location
}
"`n" | Out-File -FilePath $reportFile -Encoding UTF8 -Append

Write-Section "ENVIRONMENT VARIABLES"

Write-Info "Checking environment variables..."

@"
6. ENVIRONMENT VARIABLES
========================

6.1 Python-related Variables:
-----------------------------
  PYTHONPATH: $(if ($env:PYTHONPATH) { $env:PYTHONPATH } else { "NOT SET" })
  PYTHONHOME: $(if ($env:PYTHONHOME) { $env:PYTHONHOME } else { "NOT SET" })
  VIRTUAL_ENV: $(if ($env:VIRTUAL_ENV) { $env:VIRTUAL_ENV } else { "NOT SET" })
  CONDA_DEFAULT_ENV: $(if ($env:CONDA_DEFAULT_ENV) { $env:CONDA_DEFAULT_ENV } else { "NOT SET" })

6.2 System Variables:
--------------------
  PATH entries containing 'python':
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

$pathEntries = $env:PATH -split ';'
$pythonPaths = $pathEntries | Where-Object { $_ -match 'python' }
if ($pythonPaths) {
    $pythonPaths | ForEach-Object { "    $_" } | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}
else {
    "    None found" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}

@"

  ComSpec: $env:ComSpec
  PROCESSOR_ARCHITECTURE: $env:PROCESSOR_ARCHITECTURE
  NUMBER_OF_PROCESSORS: $env:NUMBER_OF_PROCESSORS

"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

Write-Section "DEPENDENCY ANALYSIS"

Write-Info "Analyzing dependencies..."

@"
7. DEPENDENCY ANALYSIS
======================

7.1 Required Package Check:
---------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

$requiredPackages = @("mcp", "fastapi", "websockets", "uvicorn", "pydantic", "requests", "urllib3", "python-dotenv")
foreach ($package in $requiredPackages) {
    try {
        $result = python -c "import $package; print(f'  ✓ $package`: {getattr($package, `'__version__`', `'installed`')}')" 2>&1
        if ($result -match "✓") {
            $result | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        }
        else {
            "  ✗ $package`: NOT INSTALLED" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
        }
    }
    catch {
        "  ✗ $package`: NOT INSTALLED" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
}

@"

7.2 Total Installed Packages:
-----------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

try {
    $totalPackages = (pip list 2>&1 | Measure-Object -Line).Lines
    "  Total packages: $totalPackages" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}
catch {
    "  Total packages: Unable to count" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}
"`n" | Out-File -FilePath $reportFile -Encoding UTF8 -Append

Write-Section "PERMISSION AND ACCESS ANALYSIS"

Write-Info "Checking permissions..."

@"
8. PERMISSION AND ACCESS ANALYSIS
=================================

8.1 User Information:
--------------------
  Current user: $env:USERNAME
  User domain: $env:USERDOMAIN
  User profile: $env:USERPROFILE
  User groups: $((whoami /groups | Select-String -Pattern "^\s+\S+" | ForEach-Object { $_.ToString().Trim() }) -join ", ")

8.2 Administrative Privileges:
-----------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
"  Running with Administrator privileges: $(if ($isAdmin) { 'YES' } else { 'NO' })" | Out-File -FilePath $reportFile -Encoding UTF8 -Append

if ($projectRoot) {
    @"

8.3 Directory Permissions:
-------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    
    $acl = Get-Acl $projectRoot
    "  Project root owner: $($acl.Owner)" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    "  Access rules count: $($acl.Access.Count)" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}
"`n" | Out-File -FilePath $reportFile -Encoding UTF8 -Append

Write-Section "DIAGNOSTIC SUMMARY"

Write-Info "Creating diagnostic summary..."

@"
9. DIAGNOSTIC SUMMARY
====================

9.1 Key Findings:
-----------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

# Check if package is installed
$packageInstalled = $false
try {
    pip show wazuh-mcp-server 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $packageInstalled = $true
        "  • Package Installation: FOUND (wazuh-mcp-server installed)" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
}
catch {}
if (-not $packageInstalled) {
    "  • Package Installation: NOT FOUND (wazuh-mcp-server not installed)" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}

# Check project root
if ($projectRoot) {
    "  • Project Root: FOUND at $projectRoot" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}
else {
    "  • Project Root: NOT FOUND (unable to locate setup.py or pyproject.toml)" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}

# Python version
try {
    $pythonVersion = python --version 2>&1
    "  • Python Version: $pythonVersion" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}
catch {
    "  • Python Version: Unable to determine" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}

# Virtual environment
if ($env:VIRTUAL_ENV) {
    "  • Virtual Environment: ACTIVE ($env:VIRTUAL_ENV)" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}
else {
    "  • Virtual Environment: NOT ACTIVE" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}

@"

9.2 Probable Root Causes:
-------------------------
  1. Package not installed in editable mode (pip install -e .)
  2. Script executed from incorrect directory
  3. Python path not properly configured
  4. Missing or incorrect package structure

9.3 Additional Observations:
----------------------------
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

# Additional checks
if ($projectRoot) {
    if (-not (Test-Path "$projectRoot\src")) {
        "  • WARNING: src\ directory not found in project root" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
    if (-not (Test-Path "$projectRoot\setup.py") -and -not (Test-Path "$projectRoot\pyproject.toml")) {
        "  • WARNING: No setup.py or pyproject.toml found" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
    }
}

if (-not $env:PYTHONPATH) {
    "  • INFO: PYTHONPATH environment variable not set" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}

# Check for multiple Python installations
$pythonInstalls = Get-Command python* -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source | Get-Unique
if ($pythonInstalls.Count -gt 1) {
    "  • INFO: Multiple Python installations detected ($($pythonInstalls.Count) found)" | Out-File -FilePath $reportFile -Encoding UTF8 -Append
}

@"

================================================================================
END OF REPORT
Generated on: $(Get-Date)
Report location: $reportFile
================================================================================
"@ | Out-File -FilePath $reportFile -Encoding UTF8 -Append

# Create additional diagnostic files
Write-Info "Collecting additional diagnostic data..."

# Save pip list output
pip list 2>&1 | Out-File "$outputDir\pip_list.txt"

# Save pip freeze output
pip freeze 2>&1 | Out-File "$outputDir\pip_freeze.txt"

# Save environment variables
Get-ChildItem env: | Format-Table Name, Value -AutoSize | Out-String | Out-File "$outputDir\environment_variables.txt"

# Save Python locations
Get-Command python* -ErrorAction SilentlyContinue | Select-Object Name, Source, Version | Format-Table -AutoSize | Out-String | Out-File "$outputDir\python_locations.txt"

# Save directory tree (if project root found)
if ($projectRoot -and (Get-Command tree -ErrorAction SilentlyContinue)) {
    Push-Location $projectRoot
    tree /F /A | Select-Object -First 100 | Out-File "$outputDir\directory_tree.txt"
    Pop-Location
}

# Save detailed system information
Get-WmiObject -Class Win32_OperatingSystem | Select-Object * | Format-List | Out-String | Out-File "$outputDir\system_details.txt"

Write-Section "ANALYSIS COMPLETE"

Write-Success "Root Cause Analysis completed!"
Write-Host ""
Write-Host "📁 Report generated: $reportFile" -ForegroundColor Cyan
Write-Host "📁 Additional files saved in: $outputDir\" -ForegroundColor Cyan
Write-Host ""
Write-Host "Files created:" -ForegroundColor Yellow
Write-Host "  - RCA_FINDINGS_REPORT.txt (main report)"
Write-Host "  - pip_list.txt (installed packages)"
Write-Host "  - pip_freeze.txt (package versions)"
Write-Host "  - environment_variables.txt (all env vars)"
Write-Host "  - python_locations.txt (Python installations)"
Write-Host "  - system_details.txt (detailed system info)"
if (Test-Path "$outputDir\directory_tree.txt") {
    Write-Host "  - directory_tree.txt (project structure)"
}
Write-Host ""
Write-Host "Please review the findings report for detailed analysis of the import issue." -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")