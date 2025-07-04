# PowerShell Deployment Script for Wazuh MCP Server
# Production deployment using Docker Compose

param(
    [Parameter(Position=0)]
    [ValidateSet("deploy", "stop", "restart", "logs", "status", "clean", "help")]
    [string]$Command = "help",
    
    [Parameter(Position=1)]
    [string]$Service = ""
)

# Colors for output
$ErrorColor = "Red"
$SuccessColor = "Green"
$InfoColor = "Cyan"
$WarningColor = "Yellow"

function Write-Header {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor $InfoColor
    Write-Host "   Wazuh MCP Server - PowerShell Deployment" -ForegroundColor $InfoColor
    Write-Host "========================================" -ForegroundColor $InfoColor
    Write-Host ""
}

function Test-DockerInstallation {
    Write-Host "[INFO] Checking Docker installation..." -ForegroundColor $InfoColor
    
    try {
        $dockerVersion = docker --version 2>$null
        if (-not $dockerVersion) {
            throw "Docker not found"
        }
        Write-Host "[OK] Docker found: $dockerVersion" -ForegroundColor $SuccessColor
    }
    catch {
        Write-Host "[ERROR] Docker is not installed or not in PATH" -ForegroundColor $ErrorColor
        Write-Host "Please install Docker Desktop for Windows first" -ForegroundColor $ErrorColor
        Write-Host "Download from: https://www.docker.com/products/docker-desktop" -ForegroundColor $InfoColor
        exit 1
    }
    
    try {
        $composeVersion = docker-compose --version 2>$null
        if (-not $composeVersion) {
            throw "Docker Compose not found"
        }
        Write-Host "[OK] Docker Compose found: $composeVersion" -ForegroundColor $SuccessColor
    }
    catch {
        Write-Host "[ERROR] Docker Compose is not installed" -ForegroundColor $ErrorColor
        Write-Host "Please install Docker Compose or use Docker Desktop" -ForegroundColor $ErrorColor
        exit 1
    }
    
    try {
        $dockerInfo = docker info 2>$null
        if (-not $dockerInfo) {
            throw "Docker daemon not running"
        }
        Write-Host "[OK] Docker daemon is running" -ForegroundColor $SuccessColor
    }
    catch {
        Write-Host "[ERROR] Docker daemon is not running" -ForegroundColor $ErrorColor
        Write-Host "Please start Docker Desktop and try again" -ForegroundColor $ErrorColor
        exit 1
    }
}

function Deploy-Services {
    Write-Host "[INFO] Deploying Wazuh MCP Server production stack..." -ForegroundColor $InfoColor
    
    # Create required directories
    Write-Host "[INFO] Creating required directories..." -ForegroundColor $InfoColor
    $directories = @(
        "monitoring\prometheus\data",
        "monitoring\grafana\data", 
        "logs"
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "[CREATED] $dir" -ForegroundColor $SuccessColor
        }
    }
    
    # Check environment configuration
    Write-Host "[INFO] Setting up environment configuration..." -ForegroundColor $InfoColor
    if (-not (Test-Path ".env.production")) {
        Write-Host "[WARNING] .env.production not found, copying from example..." -ForegroundColor $WarningColor
        Copy-Item ".env.production.example" ".env.production"
        Write-Host "[INFO] Please edit .env.production with your settings before running again" -ForegroundColor $InfoColor
        Read-Host "Press Enter to continue"
        return
    }
    
    # Deploy with Docker Compose
    Write-Host "[INFO] Starting services with Docker Compose..." -ForegroundColor $InfoColor
    try {
        $result = docker-compose --env-file .env.production up -d
        if ($LASTEXITCODE -eq 0) {
            Write-Host ""
            Write-Host "[SUCCESS] Deployment completed successfully!" -ForegroundColor $SuccessColor
            Write-Host ""
            Write-Host "Services:" -ForegroundColor $InfoColor
            Write-Host "  - Wazuh MCP HTTP API: https://localhost/api" -ForegroundColor $InfoColor
            Write-Host "  - Wazuh MCP WebSocket: wss://localhost/ws" -ForegroundColor $InfoColor
            Write-Host "  - Grafana Dashboard: https://localhost/grafana" -ForegroundColor $InfoColor
            Write-Host "  - Prometheus Metrics: https://localhost/prometheus" -ForegroundColor $InfoColor
            Write-Host ""
            Write-Host "Use './deploy.ps1 logs' to view service logs" -ForegroundColor $InfoColor
            Write-Host "Use './deploy.ps1 status' to check service status" -ForegroundColor $InfoColor
        } else {
            throw "Docker Compose failed"
        }
    }
    catch {
        Write-Host "[ERROR] Deployment failed!" -ForegroundColor $ErrorColor
        Write-Host "Check the logs above for details" -ForegroundColor $ErrorColor
    }
}

function Stop-Services {
    Write-Host "[INFO] Stopping all services..." -ForegroundColor $InfoColor
    docker-compose down
    Write-Host "[INFO] Services stopped" -ForegroundColor $SuccessColor
}

function Restart-Services {
    Write-Host "[INFO] Restarting all services..." -ForegroundColor $InfoColor
    docker-compose restart
    Write-Host "[INFO] Services restarted" -ForegroundColor $SuccessColor
}

function Show-Logs {
    if ($Service -eq "") {
        docker-compose logs -f
    } else {
        docker-compose logs -f $Service
    }
}

function Show-Status {
    Write-Host "[INFO] Service Status:" -ForegroundColor $InfoColor
    docker-compose ps
    Write-Host ""
    Write-Host "[INFO] Container Health:" -ForegroundColor $InfoColor
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 5 -UseBasicParsing
        if ($response.StatusCode -eq 200) {
            Write-Host "HTTP API: OK" -ForegroundColor $SuccessColor
        } else {
            Write-Host "HTTP API: FAILED" -ForegroundColor $ErrorColor
        }
    }
    catch {
        Write-Host "HTTP API: UNREACHABLE" -ForegroundColor $WarningColor
    }
}

function Clean-Services {
    Write-Host "[WARNING] This will remove all containers, volumes, and data!" -ForegroundColor $WarningColor
    $confirm = Read-Host "Are you sure? (y/N)"
    if ($confirm -eq "y" -or $confirm -eq "Y") {
        Write-Host "[INFO] Removing all containers and volumes..." -ForegroundColor $InfoColor
        docker-compose down -v --remove-orphans
        docker system prune -f
        Write-Host "[INFO] Cleanup completed" -ForegroundColor $SuccessColor
    } else {
        Write-Host "[INFO] Cleanup cancelled" -ForegroundColor $InfoColor
    }
}

function Show-Help {
    Write-Host "Usage: .\deploy.ps1 [command] [service]" -ForegroundColor $InfoColor
    Write-Host ""
    Write-Host "Commands:" -ForegroundColor $InfoColor
    Write-Host "  deploy    - Deploy the production stack" -ForegroundColor $InfoColor
    Write-Host "  stop      - Stop all services" -ForegroundColor $InfoColor
    Write-Host "  restart   - Restart all services" -ForegroundColor $InfoColor
    Write-Host "  logs      - Show service logs (optionally specify service name)" -ForegroundColor $InfoColor
    Write-Host "  status    - Show service status" -ForegroundColor $InfoColor
    Write-Host "  clean     - Remove all containers and volumes" -ForegroundColor $InfoColor
    Write-Host "  help      - Show this help message" -ForegroundColor $InfoColor
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor $InfoColor
    Write-Host "  .\deploy.ps1 deploy" -ForegroundColor $InfoColor
    Write-Host "  .\deploy.ps1 logs wazuh-mcp-http" -ForegroundColor $InfoColor
    Write-Host "  .\deploy.ps1 status" -ForegroundColor $InfoColor
}

# Main execution
Write-Header

switch ($Command) {
    "deploy" {
        Test-DockerInstallation
        Deploy-Services
    }
    "stop" {
        Test-DockerInstallation
        Stop-Services
    }
    "restart" {
        Test-DockerInstallation
        Restart-Services
    }
    "logs" {
        Test-DockerInstallation
        Show-Logs
    }
    "status" {
        Test-DockerInstallation
        Show-Status
    }
    "clean" {
        Test-DockerInstallation
        Clean-Services
    }
    "help" {
        Show-Help
    }
    default {
        Show-Help
    }
}

Write-Host ""