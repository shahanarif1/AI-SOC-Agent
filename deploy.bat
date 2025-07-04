@echo off
REM Windows Batch Deployment Script for Wazuh MCP Server
REM Production deployment using Docker Compose

echo.
echo ========================================
echo   Wazuh MCP Server - Windows Deployment
echo ========================================
echo.

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed or not in PATH
    echo Please install Docker Desktop for Windows first
    echo Download from: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Check if Docker Compose is installed
docker-compose --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose is not installed
    echo Please install Docker Compose or use Docker Desktop
    pause
    exit /b 1
)

REM Check if Docker daemon is running
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker daemon is not running
    echo Please start Docker Desktop and try again
    pause
    exit /b 1
)

if "%1"=="deploy" goto deploy
if "%1"=="stop" goto stop
if "%1"=="restart" goto restart
if "%1"=="logs" goto logs
if "%1"=="status" goto status
if "%1"=="clean" goto clean

:help
echo Usage: deploy.bat [command]
echo.
echo Commands:
echo   deploy    - Deploy the production stack
echo   stop      - Stop all services
echo   restart   - Restart all services
echo   logs      - Show service logs
echo   status    - Show service status
echo   clean     - Remove all containers and volumes
echo   help      - Show this help message
echo.
goto end

:deploy
echo [INFO] Deploying Wazuh MCP Server production stack...
echo [INFO] Creating required directories...
if not exist "monitoring\prometheus\data" mkdir monitoring\prometheus\data
if not exist "monitoring\grafana\data" mkdir monitoring\grafana\data
if not exist "logs" mkdir logs

echo [INFO] Setting up environment configuration...
if not exist ".env.production" (
    echo [WARNING] .env.production not found, copying from example...
    copy .env.production.example .env.production
    echo [INFO] Please edit .env.production with your settings before running again
    pause
    goto end
)

echo [INFO] Starting services with Docker Compose...
docker-compose --env-file .env.production up -d

if errorlevel 0 (
    echo.
    echo [SUCCESS] Deployment completed successfully!
    echo.
    echo Services:
    echo   - Wazuh MCP HTTP API: https://localhost/api
    echo   - Wazuh MCP WebSocket: wss://localhost/ws  
    echo   - Grafana Dashboard: https://localhost/grafana
    echo   - Prometheus Metrics: https://localhost/prometheus
    echo.
    echo Use 'deploy.bat logs' to view service logs
    echo Use 'deploy.bat status' to check service status
) else (
    echo [ERROR] Deployment failed!
    echo Check the logs above for details
)
goto end

:stop
echo [INFO] Stopping all services...
docker-compose down
echo [INFO] Services stopped
goto end

:restart
echo [INFO] Restarting all services...
docker-compose restart
echo [INFO] Services restarted
goto end

:logs
if "%2"=="" (
    docker-compose logs -f
) else (
    docker-compose logs -f %2
)
goto end

:status
echo [INFO] Service Status:
docker-compose ps
echo.
echo [INFO] Container Health:
docker-compose exec wazuh-mcp-http python -c "import requests; print('HTTP OK' if requests.get('http://localhost:8000/health').status_code == 200 else 'HTTP FAILED')" 2>nul
goto end

:clean
echo [WARNING] This will remove all containers, volumes, and data!
set /p confirm="Are you sure? (y/N): "
if /i "%confirm%"=="y" (
    echo [INFO] Removing all containers and volumes...
    docker-compose down -v --remove-orphans
    docker system prune -f
    echo [INFO] Cleanup completed
) else (
    echo [INFO] Cleanup cancelled
)
goto end

:end
echo.
pause