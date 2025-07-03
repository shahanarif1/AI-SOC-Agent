#!/usr/bin/env python3
"""
SSL/TLS validation and troubleshooting script for Wazuh MCP Server.
Diagnoses SSL connectivity issues and provides resolution guidance.
"""

import asyncio
import sys
from pathlib import Path
from dotenv import load_dotenv

# Setup import path and error handling
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent
src_path = str(project_root / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

# Load environment
env_file = project_root / '.env'
if env_file.exists():
    load_dotenv(dotenv_path=env_file)
    print(f"Loaded .env file from: {env_file}")

try:
    from config import WazuhConfig
    from utils.ssl_helper import (
        check_ssl_connectivity, validate_ca_bundle, 
        diagnose_ssl_issues, fix_pip_ssl_issues
    )
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("💡 Try: pip install -e .")
    sys.exit(1)


def print_separator(title: str):
    """Print a formatted section separator."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def print_ssl_connectivity_results(results: dict):
    """Print SSL connectivity test results."""
    host = results["host"]
    port = results["port"]
    
    if results["connected"]:
        print(f"✅ Network connectivity to {host}:{port}")
    else:
        print(f"❌ Cannot connect to {host}:{port}")
        for error in results["errors"]:
            print(f"   Error: {error}")
        return
    
    if results["ssl_available"]:
        print(f"✅ SSL/TLS available on {host}:{port}")
        
        cert_info = results["certificate_info"]
        if cert_info:
            print(f"📋 Certificate Information:")
            subject = cert_info.get("subject", {})
            issuer = cert_info.get("issuer", {})
            
            print(f"   Subject: {subject.get('commonName', 'N/A')}")
            print(f"   Issuer: {issuer.get('commonName', 'N/A')}")
            print(f"   Valid From: {cert_info.get('not_before', 'N/A')}")
            print(f"   Valid Until: {cert_info.get('not_after', 'N/A')}")
            
            if cert_info.get("is_expired"):
                print("   ⚠️  Certificate is EXPIRED")
            else:
                print("   ✅ Certificate is valid")
    else:
        print(f"❌ SSL/TLS not available on {host}:{port}")
        for error in results["errors"]:
            print(f"   Error: {error}")


def print_ca_bundle_results(results: dict):
    """Print CA bundle validation results."""
    if results["ca_bundle_exists"]:
        print(f"✅ CA bundle found: {results['ca_bundle_path']}")
    else:
        print(f"❌ CA bundle not found: {results['ca_bundle_path']}")
    
    if results["ca_bundle_readable"]:
        print(f"✅ CA bundle is readable")
        print(f"📊 Contains {results['certificates_count']} certificates")
    else:
        print(f"❌ CA bundle is not readable")
    
    print(f"🐍 Python SSL: {results['python_ssl_version']}")
    
    if results["errors"]:
        print("❌ CA Bundle Issues:")
        for error in results["errors"]:
            print(f"   {error}")


def print_diagnosis_results(diagnosis: dict):
    """Print comprehensive diagnosis results."""
    severity = diagnosis["severity"]
    
    if severity == "info":
        print("✅ No SSL issues detected")
    elif severity == "warning":
        print("⚠️  SSL warnings detected")
    elif severity == "error":
        print("❌ SSL errors detected")
    
    if diagnosis["recommendations"]:
        print("\n💡 Recommendations:")
        for i, rec in enumerate(diagnosis["recommendations"], 1):
            print(f"   {i}. {rec}")


async def test_wazuh_ssl():
    """Test SSL connectivity to Wazuh services."""
    try:
        config = WazuhConfig.from_env()
        
        print_separator("Testing Wazuh Server SSL")
        server_results = check_ssl_connectivity(config.host, config.port)
        print_ssl_connectivity_results(server_results)
        
        if config.indexer_host:
            print_separator("Testing Wazuh Indexer SSL")
            indexer_results = check_ssl_connectivity(config.indexer_host, config.indexer_port)
            print_ssl_connectivity_results(indexer_results)
        else:
            print_separator("Wazuh Indexer")
            print("ℹ️  Indexer not configured")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False


def test_ca_bundle():
    """Test CA bundle validity."""
    print_separator("CA Bundle Validation")
    
    results = validate_ca_bundle()
    print_ca_bundle_results(results)
    
    return len(results["errors"]) == 0


def run_ssl_diagnosis():
    """Run comprehensive SSL diagnosis."""
    try:
        config = WazuhConfig.from_env()
        
        print_separator("SSL Diagnosis")
        
        # Diagnose Wazuh Server
        print("🔍 Diagnosing Wazuh Server SSL...")
        server_diagnosis = diagnose_ssl_issues(config.host, config.port)
        print_diagnosis_results(server_diagnosis)
        
        # Diagnose Wazuh Indexer
        if config.indexer_host:
            print("\n🔍 Diagnosing Wazuh Indexer SSL...")
            indexer_diagnosis = diagnose_ssl_issues(config.indexer_host, config.indexer_port)
            print_diagnosis_results(indexer_diagnosis)
        
        return True
        
    except Exception as e:
        print(f"❌ Diagnosis failed: {e}")
        return False


def fix_ssl_issues():
    """Attempt to fix common SSL issues."""
    print_separator("SSL Issue Fixes")
    
    print("🔧 Attempting to fix SSL issues...")
    
    fixes = fix_pip_ssl_issues()
    
    if fixes:
        print("✅ Fixes applied:")
        for fix in fixes:
            print(f"   • {fix}")
    else:
        print("ℹ️  No automatic fixes available")
    
    print("\n💡 Manual fixes you can try:")
    print("   1. Update certificates: pip install --upgrade certifi")
    print("   2. Set environment variables:")
    print("      export REQUESTS_CA_BUNDLE=/path/to/ca-bundle.crt")
    print("      export SSL_CERT_FILE=/path/to/ca-bundle.crt")
    print("   3. For self-signed certificates, set:")
    print("      WAZUH_ALLOW_SELF_SIGNED=true")
    print("      WAZUH_INDEXER_ALLOW_SELF_SIGNED=true")


def main():
    """Main SSL validation and troubleshooting function."""
    print("🔒 Wazuh MCP Server - SSL Validation & Troubleshooting")
    print("=" * 60)
    
    # Test CA bundle
    ca_bundle_ok = test_ca_bundle()
    
    # Test Wazuh SSL connectivity
    wazuh_ssl_ok = asyncio.run(test_wazuh_ssl())
    
    # Run comprehensive diagnosis
    diagnosis_ok = run_ssl_diagnosis()
    
    # Attempt fixes if issues detected
    if not (ca_bundle_ok and wazuh_ssl_ok and diagnosis_ok):
        fix_ssl_issues()
    
    print_separator("Summary")
    
    if ca_bundle_ok and wazuh_ssl_ok:
        print("✅ SSL configuration is working correctly!")
        print("🎉 You should be able to connect to Wazuh services.")
    else:
        print("❌ SSL issues detected. Review the recommendations above.")
        print("📖 See PRODUCTION_FIXES_GUIDE.md for detailed troubleshooting.")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())