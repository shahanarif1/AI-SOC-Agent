# Windows Setup Guide for Wazuh MCP Server

## 🖥️ Windows-Specific Installation & Troubleshooting

### ⚡ Quick Windows Installation

1. **Download and run the Windows installer:**
   ```cmd
   install-windows.bat
   ```

2. **If you encounter encoding errors, run the fix script:**
   ```cmd
   python fix-windows-encoding.py
   ```

3. **Validate the installation:**
   ```cmd
   python validate_setup.py
   ```

---

## 🔧 Common Windows Issues & Solutions

### ❌ Issue: 'charmap' codec can't decode byte 0x8f

**Symptoms:**
- Error when parsing .env file
- UnicodeDecodeError during validation
- Characters appearing as question marks or boxes

**Solutions:**

#### Option 1: Automatic Fix (Recommended)
```cmd
python fix-windows-encoding.py
```

#### Option 2: Manual Fix
1. Open `.env` file in **Notepad++** or **VS Code**
2. Go to **Encoding** → **Convert to UTF-8** (without BOM)
3. Save the file
4. Re-run validation

#### Option 3: Console Encoding
```cmd
# Set console to UTF-8
chcp 65001

# Then run your commands
python validate_setup.py
```

### ❌ Issue: Unicode characters not displaying (□ symbols)

**Symptoms:**
- Emojis and Unicode symbols show as boxes
- Connection validator shows garbled output

**Solutions:**

#### Option 1: Use Windows Terminal (Recommended)
1. Install **Windows Terminal** from Microsoft Store
2. Run commands in Windows Terminal instead of Command Prompt

#### Option 2: Update Console Font
1. Right-click Command Prompt title bar
2. Select **Properties** → **Font**
3. Choose **Consolas** or **Cascadia Code**

#### Option 3: Fallback Mode
The scripts automatically detect if Unicode is supported and fall back to ASCII characters:
- ✅ becomes `[PASS]`
- ❌ becomes `[FAIL]`
- ⚠️ becomes `[WARN]`

### ❌ Issue: PowerShell Execution Policy

**Symptoms:**
- Cannot run `.ps1` scripts
- "Execution policy" errors

**Solution:**
```powershell
# Temporarily allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or use Command Prompt instead
cmd
install-windows.bat
```

### ❌ Issue: Python not found

**Symptoms:**
- `'python' is not recognized as an internal or external command`

**Solutions:**

1. **Install Python from python.org:**
   - Download Python 3.8+ from https://python.org
   - ✅ **Check "Add Python to PATH"** during installation

2. **Alternative: Microsoft Store Python:**
   ```cmd
   # Search for Python in Microsoft Store
   ms-windows-store://pdp/?productid=9pjpw5ldxlz5
   ```

3. **Verify installation:**
   ```cmd
   python --version
   pip --version
   ```

### ❌ Issue: Virtual Environment Creation Failed

**Symptoms:**
- `Failed to create virtual environment`
- Permission denied errors

**Solutions:**

1. **Run as Administrator:**
   - Right-click Command Prompt
   - Select "Run as administrator"

2. **Check antivirus/security software:**
   - Temporarily disable real-time protection
   - Add project folder to exclusions

3. **Use alternative venv location:**
   ```cmd
   python -m venv C:\temp\wazuh-venv
   C:\temp\wazuh-venv\Scripts\activate
   ```

### ❌ Issue: SSL/Certificate Errors

**Symptoms:**
- SSL verification failed
- Certificate errors in connection test

**Solutions:**

1. **Corporate Networks:**
   ```cmd
   # Set pip to use corporate certificates
   pip config set global.trusted-host pypi.org
   pip config set global.trusted-host pypi.python.org
   pip config set global.trusted-host files.pythonhosted.org
   ```

2. **Update certificates:**
   ```cmd
   pip install --upgrade certifi
   ```

3. **Configure .env for self-signed certificates:**
   ```
   VERIFY_SSL=false
   WAZUH_ALLOW_SELF_SIGNED=true
   ```

---

## 🚀 Windows Performance Optimization

### Memory and CPU Settings
```
# .env optimizations for Windows
MAX_CONNECTIONS=5
POOL_SIZE=3
REQUEST_TIMEOUT_SECONDS=60
CACHE_TTL_SECONDS=600
```

### Windows Defender Exclusions
Add these folders to Windows Defender exclusions for better performance:
- Project directory: `C:\path\to\Wazuh-MCP-Server`
- Virtual environment: `C:\path\to\Wazuh-MCP-Server\venv`
- Python installation: `C:\Users\{username}\AppData\Local\Programs\Python`

---

## 🛠️ Advanced Windows Configuration

### 1. Windows Terminal Configuration
Create a profile for the MCP server:

**settings.json** addition:
```json
{
  "name": "Wazuh MCP Server",
  "commandline": "cmd.exe /k \"cd /d C:\\path\\to\\Wazuh-MCP-Server && venv\\Scripts\\activate\"",
  "startingDirectory": "C:\\path\\to\\Wazuh-MCP-Server",
  "icon": "🛡️"
}
```

### 2. Batch Scripts for Common Tasks

**validate.bat:**
```batch
@echo off
cd /d "%~dp0"
call venv\Scripts\activate
python validate_setup.py
pause
```

**test-connection.bat:**
```batch
@echo off
cd /d "%~dp0"
call venv\Scripts\activate
python src\wazuh_mcp_server\scripts\test_connection.py
pause
```

### 3. Task Scheduler Setup
To run validation automatically:

1. Open **Task Scheduler**
2. Create **Basic Task**
3. Set trigger (e.g., daily)
4. Action: **Start a program**
5. Program: `C:\path\to\Wazuh-MCP-Server\validate.bat`

---

## 🔍 Windows-Specific Debugging

### Enable Detailed Logging
```cmd
set DEBUG=true
set LOG_LEVEL=DEBUG
python validate_setup.py
```

### Check System Information
```cmd
# System info
systeminfo | findstr /C:"OS Name" /C:"OS Version" /C:"System Type"

# Python info
python -c "import sys, platform; print(f'Python: {sys.version}'); print(f'Platform: {platform.platform()}')"

# Network connectivity
ping your-wazuh-server-ip
telnet your-wazuh-server-ip 55000
```

### Collect Debug Information
```cmd
# Create debug report
python -c "
import sys, platform, os
print('=== SYSTEM INFO ===')
print(f'OS: {platform.system()} {platform.release()}')
print(f'Python: {sys.version}')
print(f'Encoding: {sys.stdout.encoding}')
print(f'Locale: {os.environ.get('LANG', 'Not set')}')
print('=== ENVIRONMENT ===')
for k, v in os.environ.items():
    if 'WAZUH' in k:
        print(f'{k}={v}')
" > debug-info.txt
```

---

## 📞 Windows Support Resources

### Microsoft Documentation
- [Windows Terminal](https://docs.microsoft.com/en-us/windows/terminal/)
- [Python on Windows](https://docs.python.org/3/using/windows.html)
- [PowerShell Execution Policies](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)

### Common Windows Tools
- **Windows Terminal**: Modern terminal with Unicode support
- **VS Code**: Text editor with excellent UTF-8 support
- **Notepad++**: Advanced text editor with encoding options
- **Process Monitor**: Debug file/registry access issues

### Emergency Recovery
If installation becomes corrupted:

1. **Clean reinstall:**
   ```cmd
   rmdir /s /q venv
   del .env
   copy .env.example .env
   install-windows.bat
   ```

2. **Reset PATH if needed:**
   - Windows Key + R → `sysdm.cpl`
   - Advanced → Environment Variables
   - Edit PATH to include Python installation

---

## ✅ Windows Validation Checklist

- [ ] Python 3.8+ installed with PATH configured
- [ ] Virtual environment created successfully  
- [ ] All dependencies installed without errors
- [ ] .env file in UTF-8 encoding (no BOM)
- [ ] Console supports UTF-8 output
- [ ] Network connectivity to Wazuh servers
- [ ] Windows Defender exclusions configured
- [ ] validate_setup.py runs without encoding errors
- [ ] Connection test succeeds

---

*For additional Windows support, please create an issue with your debug-info.txt output.*