#!/usr/bin/env python3
"""
Check if environment variables are properly loaded from .env file.
Works on both Windows and Linux.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Colors for terminal output (works on Windows 10+ and Linux/Mac)
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def check_env_loading():
    """Check if .env file is loaded and variables are accessible."""
    
    print(f"{BLUE}=== Wazuh MCP Environment Check ==={RESET}\n")
    
    # Find .env file
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    env_file = project_root / '.env'
    
    print(f"Script location: {script_dir}")
    print(f"Project root: {project_root}")
    print(f"Looking for .env at: {env_file}")
    
    # Check if .env exists
    if env_file.exists():
        print(f"{GREEN}✓ .env file found{RESET}")
        load_dotenv(dotenv_path=env_file)
    else:
        print(f"{RED}✗ .env file not found{RESET}")
        print(f"{YELLOW}  Create it by copying .env.example:{RESET}")
        if sys.platform.startswith('win'):
            print(f"  copy .env.example .env")
        else:
            print(f"  cp .env.example .env")
        return False
    
    print(f"\n{BLUE}--- Required Environment Variables ---{RESET}")
    
    # Check required variables
    required_vars = {
        'WAZUH_HOST': 'Wazuh server hostname or IP',
        'WAZUH_USER': 'Wazuh Server API username',
        'WAZUH_PASS': 'Wazuh Server API password',
        'WAZUH_PORT': 'Wazuh Server API port (default: 55000)'
    }
    
    all_present = True
    for var, description in required_vars.items():
        value = os.getenv(var)
        if value:
            # Mask sensitive values
            if 'PASS' in var or 'KEY' in var:
                display_value = value[:3] + '*' * (len(value) - 3) if len(value) > 3 else '***'
            else:
                display_value = value
            print(f"{GREEN}✓{RESET} {var}: {display_value} ({description})")
        else:
            print(f"{RED}✗{RESET} {var}: NOT SET ({description})")
            all_present = False
    
    # Check Wazuh 4.8.0+ Indexer variables
    print(f"\n{BLUE}--- Wazuh 4.8.0+ Indexer API Variables ---{RESET}")
    
    indexer_vars = {
        'WAZUH_INDEXER_HOST': 'Wazuh Indexer hostname (fallback: WAZUH_HOST)',
        'WAZUH_INDEXER_PORT': 'Wazuh Indexer port (default: 9200)',
        'WAZUH_INDEXER_USER': 'Wazuh Indexer username (fallback: WAZUH_USER)',
        'WAZUH_INDEXER_PASS': 'Wazuh Indexer password (fallback: WAZUH_PASS)',
        'USE_INDEXER_FOR_ALERTS': 'Use Indexer for alerts (default: true)',
        'USE_INDEXER_FOR_VULNERABILITIES': 'Use Indexer for vulnerabilities (default: true)'
    }
    
    for var, description in indexer_vars.items():
        value = os.getenv(var)
        if value:
            # Mask sensitive values
            if 'PASS' in var or 'KEY' in var:
                display_value = value[:3] + '*' * (len(value) - 3) if len(value) > 3 else '***'
            else:
                display_value = value
            print(f"{GREEN}✓{RESET} {var}: {display_value} ({description})")
        else:
            print(f"{YELLOW}-{RESET} {var}: not set ({description})")
    
    # Check optional variables
    print(f"\n{BLUE}--- Optional Environment Variables ---{RESET}")
    
    optional_vars = {
        'VERIFY_SSL': 'SSL verification (default: true)',
        'WAZUH_VERSION': 'Wazuh version (auto-detected if not set)',
        'VIRUSTOTAL_API_KEY': 'VirusTotal API key',
        'SHODAN_API_KEY': 'Shodan API key',
        'ABUSEIPDB_API_KEY': 'AbuseIPDB API key',
        'DEBUG': 'Debug mode (default: false)',
        'LOG_LEVEL': 'Logging level (default: INFO)'
    }
    
    for var, description in optional_vars.items():
        value = os.getenv(var)
        if value:
            # Mask API keys
            if 'KEY' in var and len(value) > 6:
                display_value = value[:3] + '...' + value[-3:]
            else:
                display_value = value
            print(f"{GREEN}✓{RESET} {var}: {display_value} ({description})")
        else:
            print(f"{YELLOW}-{RESET} {var}: not set ({description})")
    
    # Summary
    print(f"\n{BLUE}--- Summary ---{RESET}")
    if all_present:
        print(f"{GREEN}✓ All required environment variables are set!{RESET}")
        print(f"\nYou can now run:")
        print(f"  python scripts/test_connection.py")
        return True
    else:
        print(f"{RED}✗ Some required environment variables are missing!{RESET}")
        print(f"\nPlease edit your .env file and set the missing variables.")
        return False

if __name__ == "__main__":
    success = check_env_loading()
    sys.exit(0 if success else 1)