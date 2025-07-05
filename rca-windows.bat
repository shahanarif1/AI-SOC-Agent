@echo off
REM Root Cause Analysis Script for Wazuh MCP Server Import Issues - Windows
REM This script gathers diagnostic information and creates a findings report

setlocal enabledelayedexpansion

echo ========================================
echo  Wazuh MCP Server RCA - Windows
echo ========================================
echo.

REM Create output directory with timestamp
for /f "tokens=2 delims==" %%I in ('wmic OS Get localdatetime /value') do set datetime=%%I
set timestamp=%datetime:~0,8%_%datetime:~8,6%
set OUTPUT_DIR=rca_findings_windows_%timestamp%
mkdir "%OUTPUT_DIR%" 2>nul

echo [INFO] Starting Root Cause Analysis for Wazuh MCP Server Import Issues
echo [INFO] Output directory: %OUTPUT_DIR%
echo.

REM Start building the findings report
set REPORT_FILE=%OUTPUT_DIR%\RCA_FINDINGS_REPORT.txt

REM Create report header
(
echo ================================================================================
echo                    ROOT CAUSE ANALYSIS FINDINGS REPORT
echo                         Wazuh MCP Server Import Issues
echo ================================================================================
echo.
echo Analysis Date: %DATE% %TIME%
echo System: Windows
echo Report Version: 1.0
echo.
echo ISSUE SUMMARY:
echo -------------
echo Error: ImportError: attempted relative import beyond top-level package
echo File: src\api\wazuh_client.py, line 11
echo Failing Import: from ..config import WazuhConfig
echo.
echo ================================================================================
echo.
) > "%REPORT_FILE%"

echo ======================================== 
echo  SYSTEM INFORMATION
echo ========================================

echo [INFO] Gathering system information...
(
echo 1. SYSTEM INFORMATION
echo ====================
echo Computer Name: %COMPUTERNAME%
echo User: %USERNAME%
echo User Profile: %USERPROFILE%
echo OS Version:
) >> "%REPORT_FILE%"
ver >> "%REPORT_FILE%"
(
echo Architecture: %PROCESSOR_ARCHITECTURE%
echo Number of Processors: %NUMBER_OF_PROCESSORS%
echo Current Directory: %CD%
echo Script Run Location: %0
echo.
) >> "%REPORT_FILE%"

echo ======================================== 
echo  PYTHON ENVIRONMENT
echo ========================================

echo [INFO] Checking Python installation...
(
echo 2. PYTHON ENVIRONMENT
echo ====================
echo.
echo 2.1 Python Installations Found:
echo -------------------------------
) >> "%REPORT_FILE%"

REM Check various Python commands
for %%P in (python python3 py) do (
    echo Checking %%P... >> "%REPORT_FILE%"
    where %%P 2>nul
    if !errorlevel! equ 0 (
        echo   %%P: >> "%REPORT_FILE%"
        %%P --version 2>&1 >> "%REPORT_FILE%"
        echo   Location: >> "%REPORT_FILE%"
        where %%P >> "%REPORT_FILE%"
    ) else (
        echo   %%P: NOT FOUND >> "%REPORT_FILE%"
    )
    echo. >> "%REPORT_FILE%"
)

echo [INFO] Checking pip installation...
(
echo 2.2 Package Manager ^(pip^) Information:
echo --------------------------------------
) >> "%REPORT_FILE%"

for %%P in (pip pip3) do (
    where %%P 2>nul
    if !errorlevel! equ 0 (
        echo   %%P version: >> "%REPORT_FILE%"
        %%P --version >> "%REPORT_FILE%"
        echo   %%P location: >> "%REPORT_FILE%"
        where %%P >> "%REPORT_FILE%"
    ) else (
        echo   %%P: NOT FOUND >> "%REPORT_FILE%"
    )
    echo. >> "%REPORT_FILE%"
)

echo [INFO] Python sys.path analysis...
(
echo 2.3 Python Module Search Path ^(sys.path^):
echo -----------------------------------------
) >> "%REPORT_FILE%"
python -c "import sys; print('\n'.join([f'  [{i}] {path}' for i, path in enumerate(sys.path)]))" 2>>"%REPORT_FILE%" || echo   ERROR: Could not retrieve Python sys.path >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

echo ======================================== 
echo  PROJECT STRUCTURE ANALYSIS
echo ========================================

echo [INFO] Analyzing project structure...
(
echo 3. PROJECT STRUCTURE ANALYSIS
echo =============================
echo.
echo 3.1 Project Root Detection:
echo ---------------------------
echo   Current Directory: %CD%
) >> "%REPORT_FILE%"

REM Find project root
set PROJECT_ROOT=
if exist "pyproject.toml" set PROJECT_ROOT=%CD%
if exist "setup.py" set PROJECT_ROOT=%CD%
if exist "..\pyproject.toml" set PROJECT_ROOT=%CD%\..
if exist "..\setup.py" set PROJECT_ROOT=%CD%\..
if exist "..\..\pyproject.toml" set PROJECT_ROOT=%CD%\..\..
if exist "..\..\setup.py" set PROJECT_ROOT=%CD%\..\..

if defined PROJECT_ROOT (
    echo   Detected Project Root: %PROJECT_ROOT% >> "%REPORT_FILE%"
) else (
    echo   Detected Project Root: NOT FOUND >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

(
echo 3.2 Directory Structure:
echo ------------------------
) >> "%REPORT_FILE%"

if defined PROJECT_ROOT (
    pushd "%PROJECT_ROOT%"
    echo   Project Root Contents: >> "%REPORT_FILE%"
    dir /b >> "%REPORT_FILE%"
    echo. >> "%REPORT_FILE%"
    
    echo   Key Files Present: >> "%REPORT_FILE%"
    for %%F in (setup.py pyproject.toml requirements.txt README.md .env .env.example) do (
        if exist "%%F" (
            for %%A in ("%%F") do echo     √ %%F ^(%%~zA bytes^) >> "%REPORT_FILE%"
        ) else (
            echo     × %%F ^(NOT FOUND^) >> "%REPORT_FILE%"
        )
    )
    echo. >> "%REPORT_FILE%"
    
    echo   Source Directory Analysis: >> "%REPORT_FILE%"
    if exist "src" (
        echo     src\ directory EXISTS >> "%REPORT_FILE%"
        echo     Python files in src: >> "%REPORT_FILE%"
        dir /s /b src\*.py 2>nul | find /c ".py" > temp_count.txt
        set /p PYCOUNT=<temp_count.txt
        echo     Total Python files: !PYCOUNT! >> "%REPORT_FILE%"
        del temp_count.txt
    ) else (
        echo     src\ directory NOT FOUND >> "%REPORT_FILE%"
    )
    echo. >> "%REPORT_FILE%"
    
    echo   Scripts Directory Analysis: >> "%REPORT_FILE%"
    if exist "scripts" (
        echo     scripts\ directory EXISTS >> "%REPORT_FILE%"
        echo     Contents: >> "%REPORT_FILE%"
        dir scripts >> "%REPORT_FILE%"
    ) else (
        echo     scripts\ directory NOT FOUND >> "%REPORT_FILE%"
    )
    popd
) else (
    echo   ERROR: Could not locate project root directory >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

echo ======================================== 
echo  PACKAGE INSTALLATION STATUS
echo ========================================

echo [INFO] Checking package installation status...
(
echo 4. PACKAGE INSTALLATION STATUS
echo ==============================
echo.
echo 4.1 Installed Packages ^(wazuh-related^):
echo ---------------------------------------
) >> "%REPORT_FILE%"

pip list 2>nul | findstr /i wazuh >> "%REPORT_FILE%" || echo   No wazuh-related packages found >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

(
echo 4.2 Editable Installations:
echo ---------------------------
) >> "%REPORT_FILE%"
pip list --editable 2>nul | findstr /i wazuh >> "%REPORT_FILE%" || echo   No editable wazuh installations found >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

(
echo 4.3 Package Installation Method:
echo --------------------------------
) >> "%REPORT_FILE%"
pip show wazuh-mcp-server 2>nul | findstr /i "Name: Version: Location: Requires:" >> "%REPORT_FILE%" || echo   Package 'wazuh-mcp-server' is NOT installed via pip >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

echo ======================================== 
echo  IMPORT ERROR ANALYSIS
echo ========================================

echo [INFO] Analyzing import error conditions...
(
echo 5. IMPORT ERROR ANALYSIS
echo ========================
echo.
echo 5.1 Error Context:
echo ------------------
echo   Error Type: ImportError
echo   Error Message: attempted relative import beyond top-level package
echo   Source File: src\api\wazuh_client.py
echo   Line Number: 11
echo   Import Statement: from ..config import WazuhConfig
echo.
echo 5.2 Import Path Analysis:
echo -------------------------
) >> "%REPORT_FILE%"

if defined PROJECT_ROOT (
    pushd "%PROJECT_ROOT%"
    
    echo   Test 1 - Direct module import ^(without package installation^): >> "%REPORT_FILE%"
    python -c "import sys; import os; sys.path.insert(0, os.path.join(os.getcwd(), 'src')); exec('try:\n    import config\n    print(\"    Result: SUCCESS - config module can be imported\")\nexcept Exception as e:\n    print(f\"    Result: FAILED - {type(e).__name__}: {e}\")')" 2>&1 >> "%REPORT_FILE%"
    echo. >> "%REPORT_FILE%"
    
    echo   Test 2 - Package import ^(wazuh_mcp_server^): >> "%REPORT_FILE%"
    python -c "exec('try:\n    import wazuh_mcp_server\n    print(\"    Result: SUCCESS - wazuh_mcp_server package can be imported\")\nexcept Exception as e:\n    print(f\"    Result: FAILED - {type(e).__name__}: {e}\")')" 2>&1 >> "%REPORT_FILE%"
    echo. >> "%REPORT_FILE%"
    
    echo   Test 3 - Problematic import ^(api.wazuh_client_manager^): >> "%REPORT_FILE%"
    python -c "import sys; import os; sys.path.insert(0, os.path.join(os.getcwd(), 'src')); exec('try:\n    from api.wazuh_client_manager import WazuhClientManager\n    print(\"    Result: SUCCESS - WazuhClientManager can be imported\")\nexcept Exception as e:\n    print(f\"    Result: FAILED - {type(e).__name__}: {e}\")')" 2>&1 >> "%REPORT_FILE%"
    echo. >> "%REPORT_FILE%"
    
    popd
)

echo ======================================== 
echo  ENVIRONMENT VARIABLES
echo ========================================

echo [INFO] Checking environment variables...
(
echo 6. ENVIRONMENT VARIABLES
echo ========================
echo.
echo 6.1 Python-related Variables:
echo -----------------------------
echo   PYTHONPATH: %PYTHONPATH%
echo   PYTHONHOME: %PYTHONHOME%
echo   VIRTUAL_ENV: %VIRTUAL_ENV%
echo   CONDA_DEFAULT_ENV: %CONDA_DEFAULT_ENV%
echo.
echo 6.2 System Variables:
echo --------------------
echo   PATH entries containing 'python':
) >> "%REPORT_FILE%"

echo %PATH% | findstr /i python >> "%REPORT_FILE%" || echo     None found >> "%REPORT_FILE%"
(
echo.
echo   ComSpec: %ComSpec%
echo   PROCESSOR_ARCHITECTURE: %PROCESSOR_ARCHITECTURE%
echo.
) >> "%REPORT_FILE%"

echo ======================================== 
echo  DEPENDENCY ANALYSIS
echo ========================================

echo [INFO] Analyzing dependencies...
(
echo 7. DEPENDENCY ANALYSIS
echo ======================
echo.
echo 7.1 Required Package Check:
echo ---------------------------
) >> "%REPORT_FILE%"

for %%P in (mcp fastapi websockets uvicorn pydantic requests urllib3 python-dotenv) do (
    python -c "import %%P; print('  √ %%P: installed')" 2>nul >> "%REPORT_FILE%" || echo   × %%P: NOT INSTALLED >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

(
echo 7.2 Total Installed Packages:
echo -----------------------------
) >> "%REPORT_FILE%"
pip list 2>nul | find /c /v "" > temp_count.txt
set /p PKGCOUNT=<temp_count.txt
echo   Total packages: %PKGCOUNT% >> "%REPORT_FILE%"
del temp_count.txt
echo. >> "%REPORT_FILE%"

echo ======================================== 
echo  PERMISSION AND ACCESS ANALYSIS
echo ========================================

echo [INFO] Checking permissions...
(
echo 8. PERMISSION AND ACCESS ANALYSIS
echo =================================
echo.
echo 8.1 User Information:
echo --------------------
echo   Current user: %USERNAME%
echo   User domain: %USERDOMAIN%
echo   User profile: %USERPROFILE%
echo.
echo 8.2 Administrative Privileges:
echo -----------------------------
) >> "%REPORT_FILE%"

net session >nul 2>&1
if %errorlevel% == 0 (
    echo   Running with Administrator privileges: YES >> "%REPORT_FILE%"
) else (
    echo   Running with Administrator privileges: NO >> "%REPORT_FILE%"
)
echo. >> "%REPORT_FILE%"

echo ======================================== 
echo  DIAGNOSTIC SUMMARY
echo ========================================

echo [INFO] Creating diagnostic summary...
(
echo 9. DIAGNOSTIC SUMMARY
echo ====================
echo.
echo 9.1 Key Findings:
echo -----------------
) >> "%REPORT_FILE%"

REM Check if package is installed
pip show wazuh-mcp-server >nul 2>&1
if %errorlevel% == 0 (
    echo   • Package Installation: FOUND ^(wazuh-mcp-server installed^) >> "%REPORT_FILE%"
) else (
    echo   • Package Installation: NOT FOUND ^(wazuh-mcp-server not installed^) >> "%REPORT_FILE%"
)

REM Check if running from correct location
if defined PROJECT_ROOT (
    echo   • Project Root: FOUND at %PROJECT_ROOT% >> "%REPORT_FILE%"
) else (
    echo   • Project Root: NOT FOUND ^(unable to locate setup.py or pyproject.toml^) >> "%REPORT_FILE%"
)

REM Check Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo   • Python Version: %PYTHON_VERSION% >> "%REPORT_FILE%"

REM Check virtual environment
if defined VIRTUAL_ENV (
    echo   • Virtual Environment: ACTIVE ^(%VIRTUAL_ENV%^) >> "%REPORT_FILE%"
) else (
    echo   • Virtual Environment: NOT ACTIVE >> "%REPORT_FILE%"
)

(
echo.
echo 9.2 Probable Root Causes:
echo -------------------------
echo   1. Package not installed in editable mode ^(pip install -e .^)
echo   2. Script executed from incorrect directory
echo   3. Python path not properly configured
echo   4. Missing or incorrect package structure
echo.
echo 9.3 Additional Observations:
echo ----------------------------
) >> "%REPORT_FILE%"

if defined PROJECT_ROOT (
    pushd "%PROJECT_ROOT%"
    if not exist "src" echo   • WARNING: src\ directory not found in project root >> "%REPORT_FILE%"
    if not exist "setup.py" if not exist "pyproject.toml" echo   • WARNING: No setup.py or pyproject.toml found >> "%REPORT_FILE%"
    popd
)

if not defined PYTHONPATH echo   • INFO: PYTHONPATH environment variable not set >> "%REPORT_FILE%"
echo. >> "%REPORT_FILE%"

REM Add footer to report
(
echo ================================================================================
echo END OF REPORT
echo Generated on: %DATE% %TIME%
echo Report location: %REPORT_FILE%
echo ================================================================================
) >> "%REPORT_FILE%"

REM Create additional diagnostic files
echo [INFO] Collecting additional diagnostic data...

REM Save pip list output
pip list > "%OUTPUT_DIR%\pip_list.txt" 2>&1

REM Save pip freeze output
pip freeze > "%OUTPUT_DIR%\pip_freeze.txt" 2>&1

REM Save environment variables
set > "%OUTPUT_DIR%\environment_variables.txt"

REM Save Python installation details
where python > "%OUTPUT_DIR%\python_locations.txt" 2>&1
where pip >> "%OUTPUT_DIR%\python_locations.txt" 2>&1

echo.
echo ========================================
echo  ANALYSIS COMPLETE
echo ========================================
echo.
echo [SUCCESS] Root Cause Analysis completed!
echo.
echo Report generated: %REPORT_FILE%
echo Additional files saved in: %OUTPUT_DIR%\
echo.
echo Files created:
echo   - RCA_FINDINGS_REPORT.txt (main report)
echo   - pip_list.txt (installed packages)
echo   - pip_freeze.txt (package versions)
echo   - environment_variables.txt (all env vars)
echo   - python_locations.txt (Python paths)
echo.
echo Please review the findings report for detailed analysis of the import issue.
echo.
pause