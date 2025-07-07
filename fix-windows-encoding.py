#!/usr/bin/env python3
"""
Windows Encoding Fix Script for Wazuh MCP Server
================================================

This script fixes common Windows encoding issues by:
1. Converting .env file to UTF-8 encoding
2. Removing BOM (Byte Order Mark) if present
3. Fixing line endings
4. Validating character encoding
"""

import sys
import os
import codecs
from pathlib import Path
import chardet

def detect_file_encoding(file_path):
    """Detect the encoding of a file."""
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
            result = chardet.detect(raw_data)
            return result['encoding'], result['confidence']
    except Exception as e:
        print(f"Error detecting encoding: {e}")
        return None, 0

def has_bom(file_path):
    """Check if file has BOM (Byte Order Mark)."""
    try:
        with open(file_path, 'rb') as f:
            bom = f.read(3)
            return bom == codecs.BOM_UTF8
    except Exception:
        return False

def fix_env_file_encoding(env_file_path):
    """Fix .env file encoding issues."""
    if not env_file_path.exists():
        print(f"❌ .env file not found: {env_file_path}")
        return False
    
    print(f"🔍 Analyzing {env_file_path}...")
    
    # Detect current encoding
    encoding, confidence = detect_file_encoding(env_file_path)
    print(f"📋 Current encoding: {encoding} (confidence: {confidence:.2%})")
    
    # Check for BOM
    has_bom_marker = has_bom(env_file_path)
    if has_bom_marker:
        print("⚠️  File has BOM (Byte Order Mark)")
    
    # Create backup
    backup_path = env_file_path.with_suffix('.env.backup')
    try:
        import shutil
        shutil.copy2(env_file_path, backup_path)
        print(f"💾 Created backup: {backup_path}")
    except Exception as e:
        print(f"⚠️  Could not create backup: {e}")
    
    # Read file content with detected encoding
    try:
        # Try different encodings in order of preference
        encodings_to_try = [
            encoding if encoding else 'utf-8',
            'utf-8-sig',  # UTF-8 with BOM
            'cp1252',     # Windows-1252
            'latin1',     # ISO-8859-1
            'ascii'
        ]
        
        content = None
        used_encoding = None
        
        for enc in encodings_to_try:
            if enc is None:
                continue
            try:
                with open(env_file_path, 'r', encoding=enc) as f:
                    content = f.read()
                    used_encoding = enc
                    print(f"✅ Successfully read file with {enc} encoding")
                    break
            except UnicodeDecodeError:
                print(f"❌ Failed to read with {enc} encoding")
                continue
        
        if content is None:
            print("❌ Could not read file with any encoding")
            return False
        
        # Normalize line endings to LF
        content = content.replace('\r\n', '\n').replace('\r', '\n')
        
        # Write file as UTF-8 without BOM
        with open(env_file_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(content)
        
        print("✅ File converted to UTF-8 encoding")
        print("✅ Line endings normalized")
        if has_bom_marker:
            print("✅ BOM removed")
        
        return True
        
    except Exception as e:
        print(f"❌ Error processing file: {e}")
        return False

def validate_env_file(env_file_path):
    """Validate that .env file can be properly parsed."""
    try:
        with open(env_file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        issues = []
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if line and not line.startswith('#'):
                if '=' not in line:
                    issues.append(f"Line {line_num}: Missing '=' separator")
                else:
                    # Check for problematic characters
                    try:
                        line.encode('ascii')
                    except UnicodeEncodeError as e:
                        # This is actually OK for UTF-8, but flag for awareness
                        pass
        
        if issues:
            print("⚠️  Validation issues found:")
            for issue in issues:
                print(f"   {issue}")
        else:
            print("✅ .env file validation passed")
        
        return len(issues) == 0
        
    except Exception as e:
        print(f"❌ Validation error: {e}")
        return False

def fix_console_encoding():
    """Set up console for better Unicode support on Windows."""
    if sys.platform == 'win32':
        try:
            # Set console code page to UTF-8
            os.system('chcp 65001 >nul')
            print("✅ Console encoding set to UTF-8")
        except Exception as e:
            print(f"⚠️  Could not set console encoding: {e}")

def main():
    """Main function."""
    print("=" * 60)
    print("   WAZUH MCP SERVER - WINDOWS ENCODING FIX")
    print("=" * 60)
    print()
    
    # Fix console encoding
    fix_console_encoding()
    
    # Find .env file
    env_files = [
        Path('.env'),
        Path('src/.env'),
        Path('../.env')
    ]
    
    env_file = None
    for ef in env_files:
        if ef.exists():
            env_file = ef
            break
    
    if not env_file:
        print("❌ No .env file found in current directory or common locations")
        print("💡 Available .env.example files:")
        for example_file in Path('.').glob('**/.env.example'):
            print(f"   {example_file}")
        return 1
    
    print(f"📂 Found .env file: {env_file}")
    
    # Fix encoding
    if fix_env_file_encoding(env_file):
        print()
        print("🔍 Validating fixed file...")
        validate_env_file(env_file)
        print()
        print("✅ Encoding fix completed successfully!")
        print()
        print("Next steps:")
        print("1. Verify your .env configuration")
        print("2. Run: python validate_setup.py")
        print("3. Test connection: python src\\wazuh_mcp_server\\scripts\\test_connection.py")
        return 0
    else:
        print()
        print("❌ Encoding fix failed")
        print("💡 Manual steps:")
        print("1. Open .env file in a text editor")
        print("2. Save as UTF-8 encoding (without BOM)")
        print("3. Ensure line endings are LF or CRLF")
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        input("\nPress Enter to continue...")
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to continue...")
        sys.exit(1)