#!/usr/bin/env python3
"""
Entry point for running scripts as a module.
This allows scripts to be run with: python -m scripts.test_connection
"""

import sys
import asyncio
from pathlib import Path

# Ensure proper path resolution for module execution
if __package__ is None:
    # Add src directory to path when run as script
    project_root = Path(__file__).parent.parent
    src_dir = project_root / "src"
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))

def main():
    """Entry point for scripts module."""
    if len(sys.argv) < 2:
        print("Usage: python -m scripts <script_name>")
        print("Available scripts:")
        print("  • test_connection  - Test Wazuh server connection")
        print("  • check_env       - Check environment configuration")
        sys.exit(1)
    
    script_name = sys.argv[1]
    # Remove script name from args so target script gets clean args
    sys.argv = [sys.argv[0]] + sys.argv[2:]
    
    if script_name == "test_connection":
        from .test_connection import main as test_main
        test_main()
    elif script_name == "check_env":
        from .check_env import main as check_main
        check_main()
    else:
        print(f"Unknown script: {script_name}")
        sys.exit(1)

if __name__ == "__main__":
    main()