# Cross-Platform Deployment Guide

This guide provides detailed instructions for setting up and running the Wazuh MCP Server across different operating systems.

## 🎯 Overview

The Wazuh MCP Server is designed to work seamlessly across all major operating systems:

- **🖥️ Windows** (10, 11, Server 2019+)
- **🍎 macOS** (10.15+, Intel and Apple Silicon)
- **🐧 Linux** (Ubuntu 20.04+, RHEL 8+, Debian 11+, CentOS 8+)

Both local and production deployment modes are fully supported on all platforms.

## 🛠️ Prerequisites by Platform

### Windows

#### Required Software
- **Python 3.9+** - [Download from python.org](https://www.python.org/downloads/windows/)
- **Git** - [Download Git for Windows](https://git-scm.com/download/win)
- **Docker Desktop** (production mode) - [Download](https://www.docker.com/products/docker-desktop)

#### PowerShell vs Command Prompt
- **PowerShell** (recommended): Better Unicode support, modern features
- **Command Prompt**: Basic functionality, legacy compatibility

#### Windows-Specific Notes
- Use PowerShell ISE or Windows Terminal for best experience
- Ensure Python is added to PATH during installation
- Consider using Windows Subsystem for Linux (WSL2) for Unix-like experience

### macOS

#### Required Software
- **Python 3.9+** - Use Homebrew: `brew install python3`
- **Git** - Pre-installed or via Xcode Command Line Tools
- **Docker Desktop** (production mode) - [Download](https://www.docker.com/products/docker-desktop)

#### Installation via Homebrew
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python and Git
brew install python3 git

# Install Docker (optional for production mode)
brew install --cask docker
```

#### macOS-Specific Notes
- Configuration stored in `~/Library/Application Support/WazuhMCP`
- Logs stored in `~/Library/Logs/WazuhMCP`
- May require granting Terminal permissions for file access

### Linux

#### Ubuntu/Debian
```bash
# Update package list
sudo apt update

# Install Python 3.9+ and Git
sudo apt install python3 python3-pip git

# Install Docker (production mode)
sudo apt install docker.io docker-compose
sudo usermod -aG docker $USER
```

#### RHEL/CentOS/Fedora
```bash
# Install Python 3.9+ and Git
sudo dnf install python3 python3-pip git

# Install Docker (production mode)
sudo dnf install docker docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

#### Linux-Specific Notes
- Configuration stored in `~/.config/wazuh-mcp`
- Logs stored in `/var/log/wazuh-mcp` (if writable) or `~/.local/share/wazuh-mcp/logs`
- May require sudo permissions for system-wide log directories

## 🚀 Platform-Specific Setup

### Windows Setup

#### Option 1: PowerShell (Recommended)
```powershell
# Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Run setup script
python setup.py

# Configure environment
notepad .env  # Edit with your settings

# Test installation
python wazuh_mcp_server.py --stdio
```

#### Option 2: Command Prompt
```cmd
# Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Run setup script
python setup.py

# Configure environment
notepad .env

# Test installation
python wazuh_mcp_server.py --stdio
```

#### Production Deployment (Windows)
```powershell
# PowerShell deployment
.\deploy.ps1 deploy

# Command Prompt deployment  
deploy.bat deploy

# Check status
.\deploy.ps1 status
```

### macOS Setup

```bash
# Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Run setup script
python3 setup.py

# Configure environment
nano .env  # or vim .env

# Test installation
python3 wazuh_mcp_server.py --stdio
```

#### Production Deployment (macOS)
```bash
# Deploy production stack
./deploy.sh deploy

# Check status
./deploy.sh status

# View logs
./deploy.sh logs
```

### Linux Setup

```bash
# Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Run setup script
python3 setup.py

# Configure environment
nano .env

# Test installation
python3 wazuh_mcp_server.py --stdio
```

#### Production Deployment (Linux)
```bash
# Deploy production stack
./deploy.sh deploy

# Check status
./deploy.sh status

# View logs
./deploy.sh logs
```

## 🔧 Configuration Differences

### File Paths

#### Windows
- **Config**: `%APPDATA%\WazuhMCP\`
- **Data**: `%LOCALAPPDATA%\WazuhMCP\`
- **Logs**: `%LOCALAPPDATA%\WazuhMCP\logs\`
- **Cache**: `%LOCALAPPDATA%\WazuhMCP\cache\`

#### macOS
- **Config**: `~/Library/Application Support/WazuhMCP/`
- **Data**: `~/Library/Application Support/WazuhMCP/`
- **Logs**: `~/Library/Logs/WazuhMCP/`
- **Cache**: `~/Library/Caches/WazuhMCP/`

#### Linux
- **Config**: `~/.config/wazuh-mcp/`
- **Data**: `~/.local/share/wazuh-mcp/`
- **Logs**: `/var/log/wazuh-mcp/` or `~/.local/share/wazuh-mcp/logs/`
- **Cache**: `~/.cache/wazuh-mcp/`

### Environment Variables

All platforms support the same environment variables, but Windows has additional case-insensitive fallbacks:

```bash
# Standard (all platforms)
WAZUH_HOST=your-server.com
WAZUH_USER=username
WAZUH_PASS=password

# Windows also supports (case-insensitive)
wazuh_host=your-server.com
WAZUH_HOST=your-server.com
```

## 🖥️ Claude Desktop Integration

### Windows Configuration

Add to Claude Desktop settings (`%APPDATA%\Claude\settings.json`):

```json
{
  "mcpServers": {
    "wazuh-security": {
      "command": "python",
      "args": ["C:\\path\\to\\Wazuh-MCP-Server\\wazuh_mcp_server.py", "--stdio"],
      "env": {
        "WAZUH_HOST": "your-wazuh-server.com",
        "WAZUH_USER": "your-username", 
        "WAZUH_PASS": "your-password"
      }
    }
  }
}
```

### macOS Configuration

Add to Claude Desktop settings (`~/Library/Application Support/Claude/settings.json`):

```json
{
  "mcpServers": {
    "wazuh-security": {
      "command": "python3",
      "args": ["/path/to/Wazuh-MCP-Server/wazuh_mcp_server.py", "--stdio"],
      "env": {
        "WAZUH_HOST": "your-wazuh-server.com",
        "WAZUH_USER": "your-username",
        "WAZUH_PASS": "your-password"
      }
    }
  }
}
```

### Linux Configuration

Add to Claude Desktop settings (`~/.config/Claude/settings.json`):

```json
{
  "mcpServers": {
    "wazuh-security": {
      "command": "python3",
      "args": ["/path/to/Wazuh-MCP-Server/wazuh_mcp_server.py", "--stdio"],
      "env": {
        "WAZUH_HOST": "your-wazuh-server.com",
        "WAZUH_USER": "your-username",
        "WAZUH_PASS": "your-password"
      }
    }
  }
}
```

## 🐛 Platform-Specific Troubleshooting

### Windows Issues

#### Python Not Found
```powershell
# Check Python installation
python --version

# Add Python to PATH
$env:PATH += ";C:\Python39;C:\Python39\Scripts"

# Or reinstall Python with "Add to PATH" checked
```

#### Permission Errors
```powershell
# Run PowerShell as Administrator
Start-Process powershell -Verb runAs

# Or use user directory installation
pip install --user -e .
```

#### SSL Certificate Issues
```powershell
# Update certificates
pip install --upgrade certifi

# Set environment variable
$env:SSL_CERT_FILE = "$(python -m certifi)"
```

### macOS Issues

#### Command Line Tools Missing
```bash
# Install Xcode Command Line Tools
xcode-select --install
```

#### Permission Denied
```bash
# Fix directory permissions
sudo chown -R $(whoami) /usr/local/lib/python3.9/site-packages

# Or use --user flag
pip3 install --user -e .
```

#### SSL Verification
```bash
# Update certificates on macOS
/Applications/Python\ 3.9/Install\ Certificates.command
```

### Linux Issues

#### Python Version Too Old
```bash
# Ubuntu: Install Python 3.9+
sudo apt install python3.9 python3.9-pip python3.9-venv

# CentOS/RHEL: Enable EPEL repository
sudo dnf install epel-release
sudo dnf install python39 python39-pip
```

#### Docker Permission Denied
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Restart session or run:
newgrp docker
```

#### Port Conflicts
```bash
# Check port usage
sudo netstat -tulpn | grep :8000

# Change ports in docker-compose.yml if needed
```

## 🔒 Security Considerations

### Windows Security

- **Windows Defender**: May flag Python scripts - add exclusions if needed
- **Firewall**: Ensure Python is allowed through Windows Firewall
- **UAC**: Some operations may require administrator privileges

### macOS Security

- **Gatekeeper**: May require approving unsigned binaries
- **SIP**: System Integrity Protection may prevent certain operations
- **Keychain**: Consider storing credentials in Keychain

### Linux Security

- **SELinux**: May need policy adjustments on RHEL/CentOS
- **UFW/iptables**: Configure firewall rules for production mode
- **AppArmor**: Ubuntu's AppArmor may restrict file access

## 📊 Performance Optimization

### Windows
```powershell
# Use Python optimizations
$env:PYTHONOPTIMIZE = "1"

# Increase process priority
Get-Process python | ForEach-Object { $_.PriorityClass = "High" }
```

### macOS
```bash
# Use faster JSON parser
export PYTHONPATH="/opt/homebrew/lib/python3.9/site-packages:$PYTHONPATH"

# Optimize for Apple Silicon
export ARCHFLAGS="-arch arm64"
```

### Linux
```bash
# Use performance governor
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Increase file descriptor limits
ulimit -n 65536
```

## 🧪 Testing Cross-Platform

### Automated Testing
```bash
# Run platform-specific tests
python -m pytest tests/ -v --platform-specific

# Test environment detection
python -c "from src.wazuh_mcp_server.utils.platform_utils import get_platform_info; print(get_platform_info())"
```

### Manual Verification
1. **Configuration Loading**: Verify .env file is found in correct location
2. **Directory Creation**: Check platform-appropriate directories are created
3. **Log Files**: Ensure logs are written to correct platform location
4. **Network Connectivity**: Test Wazuh API connections
5. **SSL/TLS**: Verify certificate handling works

## 🎯 Best Practices

### All Platforms
- Use virtual environments to isolate dependencies
- Keep Python and dependencies updated
- Configure logging appropriately for each platform
- Use platform-specific configuration directories
- Handle file paths using `pathlib` instead of string concatenation

### Development
- Test on multiple platforms before releasing
- Use CI/CD with Windows, macOS, and Linux runners
- Document platform-specific requirements clearly
- Provide platform-specific setup scripts