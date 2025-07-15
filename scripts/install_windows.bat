@echo off
REM =============================================================================
REM Windows Installation Script for Wazuh MCP Server
REM =============================================================================

setlocal enabledelayedexpansion

echo.
echo ======================================================================
echo    WAZUH MCP SERVER - WINDOWS SETUP
echo    Secure Integration for Claude Desktop ^& Wazuh SIEM
echo ======================================================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.9+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

REM Get Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [INFO] Python %PYTHON_VERSION% detected

REM Check Python version (basic check for 3.x)
echo %PYTHON_VERSION% | findstr /r "^3\.[9-9]" >nul
if %errorlevel% neq 0 (
    echo %PYTHON_VERSION% | findstr /r "^3\.1[0-9]" >nul
    if !errorlevel! neq 0 (
        echo [ERROR] Python 3.9+ required, found %PYTHON_VERSION%
        pause
        exit /b 1
    )
)

echo [INFO] Python version compatible

REM Check if git is available (optional but recommended)
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Git not found - some features may be limited
    echo Install Git from https://git-scm.com/download/win
) else (
    echo [INFO] Git available
)

REM Create virtual environment
echo.
echo [INFO] Creating virtual environment...
if exist venv (
    echo [INFO] Virtual environment already exists
) else (
    python -m venv venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [SUCCESS] Virtual environment created
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat
if %errorlevel% neq 0 (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b 1
)

REM Upgrade pip
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip setuptools wheel
if %errorlevel% neq 0 (
    echo [WARNING] Pip upgrade failed, continuing with existing version
)

REM Install dependencies
echo [INFO] Installing dependencies...
if exist requirements.txt (
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to install dependencies
        pause
        exit /b 1
    )
    echo [SUCCESS] Dependencies installed
) else (
    echo [ERROR] requirements.txt not found
    pause
    exit /b 1
)

REM Install the package
echo [INFO] Installing Wazuh MCP Server...
pip install -e .
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install Wazuh MCP Server
    pause
    exit /b 1
)
echo [SUCCESS] Wazuh MCP Server installed

REM Setup configuration
echo [INFO] Setting up configuration...
if not exist .env (
    if exist .env.example (
        copy .env.example .env
        echo [SUCCESS] Created .env from .env.example
    ) else (
        echo # Wazuh MCP Server Configuration > .env
        echo WAZUH_HOST=your-wazuh-server.com >> .env
        echo WAZUH_PORT=55000 >> .env
        echo WAZUH_USER=your-username >> .env
        echo WAZUH_PASS=your-password >> .env
        echo VERIFY_SSL=false >> .env
        echo LOG_LEVEL=INFO >> .env
        echo [SUCCESS] Created default .env file
    )
) else (
    echo [INFO] .env file already exists
)

REM Create logs directory
if not exist logs (
    mkdir logs
    echo [SUCCESS] Created logs directory
)

REM Test installation
echo [INFO] Testing installation...
python -c "import wazuh_mcp_server; print('[SUCCESS] Import test passed')"
if %errorlevel% neq 0 (
    echo [ERROR] Installation test failed
    pause
    exit /b 1
)

REM Show completion message
echo.
echo ======================================================================
echo    SETUP COMPLETE - WINDOWS CONFIGURATION
echo ======================================================================
echo.
echo [NEXT STEPS]
echo.
echo 1. Configure Wazuh Connection:
echo    - Edit .env file with your Wazuh server details
echo    - Required: WAZUH_HOST, WAZUH_USER, WAZUH_PASS
echo.
echo 2. Test Connection:
echo    - Open Command Prompt in this directory
echo    - Run: venv\Scripts\activate
echo    - Run: python -m wazuh_mcp_server --stdio
echo.
echo 3. Claude Desktop Integration:
echo    - Open Claude Desktop
echo    - Go to Settings → Developer → Edit Config
echo    - Add the configuration shown in the documentation
echo.
echo 4. Claude Desktop Config Location:
echo    %%APPDATA%%\Claude\claude_desktop_config.json
echo.
echo [CAPABILITIES ENABLED]
echo • Real-time security monitoring and alerting
echo • AI-powered threat analysis and correlation
echo • Comprehensive vulnerability management
echo • Compliance reporting (PCI DSS, GDPR, HIPAA)
echo • Agent management and configuration
echo.
echo [SUPPORT]
echo • Documentation: .\docs\
echo • Logs: .\logs\
echo • Issues: https://github.com/gensecaihq/Wazuh-MCP-Server/issues
echo.
echo ======================================================================
echo.
pause