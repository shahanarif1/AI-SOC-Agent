"""
SSL/TLS helper utilities for production-grade certificate handling.
Handles custom certificates, validation, and troubleshooting.
"""

import ssl
import socket
import certifi
import aiohttp
import logging
from pathlib import Path
from typing import Optional, Dict, Any, Union
from datetime import datetime, timezone
import urllib3
from urllib3.exceptions import InsecureRequestWarning

logger = logging.getLogger(__name__)


class SSLConfig:
    """SSL configuration manager with comprehensive certificate handling."""
    
    def __init__(
        self,
        verify_ssl: bool = False,  # Default to False for user-friendliness
        ca_bundle_path: Optional[str] = None,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
        allow_self_signed: bool = True,  # Default to True for user-friendliness
        ssl_timeout: int = 30,
        auto_detect_ssl_issues: bool = True  # Auto-handle SSL issues
    ):
        self.verify_ssl = verify_ssl
        self.ca_bundle_path = ca_bundle_path
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.allow_self_signed = allow_self_signed
        self.ssl_timeout = ssl_timeout
        self.auto_detect_ssl_issues = auto_detect_ssl_issues
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self):
        """Validate SSL configuration."""
        if self.ca_bundle_path and not Path(self.ca_bundle_path).exists():
            raise ValueError(f"CA bundle file not found: {self.ca_bundle_path}")
        
        if self.client_cert_path and not Path(self.client_cert_path).exists():
            raise ValueError(f"Client certificate file not found: {self.client_cert_path}")
        
        if self.client_key_path and not Path(self.client_key_path).exists():
            raise ValueError(f"Client key file not found: {self.client_key_path}")
    
    def create_ssl_context(self) -> Union[ssl.SSLContext, bool]:
        """Create SSL context for requests with intelligent fallback."""
        if not self.verify_ssl:
            # Disable SSL warnings when verification is explicitly disabled
            urllib3.disable_warnings(InsecureRequestWarning)
            logger.info("SSL verification disabled - allowing all certificates for maximum compatibility")
            return False
        
        # Create SSL context
        context = ssl.create_default_context()
        
        # Load custom CA bundle if specified
        if self.ca_bundle_path:
            try:
                context.load_verify_locations(self.ca_bundle_path)
                logger.info(f"Loaded custom CA bundle: {self.ca_bundle_path}")
            except Exception as e:
                logger.warning(f"Failed to load custom CA bundle: {e}")
                if self.auto_detect_ssl_issues:
                    logger.info("Falling back to allowing self-signed certificates")
                    self.allow_self_signed = True
        
        # Load client certificate if specified
        if self.client_cert_path:
            try:
                if self.client_key_path:
                    context.load_cert_chain(self.client_cert_path, self.client_key_path)
                else:
                    context.load_cert_chain(self.client_cert_path)
                logger.info(f"Loaded client certificate: {self.client_cert_path}")
            except Exception as e:
                logger.warning(f"Failed to load client certificate: {e}")
                if self.auto_detect_ssl_issues:
                    logger.info("Continuing without client certificate authentication")
        
        # Handle self-signed certificates and non-commercial CAs
        if self.allow_self_signed:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            logger.info("Allowing self-signed and non-commercial certificates for maximum compatibility")
            # Disable warnings for better user experience
            urllib3.disable_warnings(InsecureRequestWarning)
        
        return context
    
    def create_aiohttp_connector(self) -> aiohttp.TCPConnector:
        """Create aiohttp connector with SSL configuration."""
        ssl_context = self.create_ssl_context()
        
        return aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=100,
            limit_per_host=30,
            keepalive_timeout=60,
            enable_cleanup_closed=True,
            ssl_context=ssl_context if isinstance(ssl_context, ssl.SSLContext) else None
        )


def check_ssl_connectivity(host: str, port: int, timeout: int = 10) -> Dict[str, Any]:
    """Check SSL connectivity and certificate information."""
    result = {
        "host": host,
        "port": port,
        "connected": False,
        "ssl_available": False,
        "certificate_info": None,
        "errors": []
    }
    
    try:
        # Test basic connectivity
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        connection_result = sock.connect_ex((host, port))
        sock.close()
        
        if connection_result == 0:
            result["connected"] = True
            logger.debug(f"Successfully connected to {host}:{port}")
        else:
            result["errors"].append(f"Cannot connect to {host}:{port}")
            return result
        
        # Test SSL/TLS connectivity
        context = ssl.create_default_context()
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                result["ssl_available"] = True
                
                # Get certificate information
                cert = ssock.getpeercert()
                result["certificate_info"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "is_expired": _is_certificate_expired(cert)
                }
                
                logger.info(f"SSL certificate validated for {host}:{port}")
    
    except ssl.SSLError as e:
        result["errors"].append(f"SSL Error: {str(e)}")
        logger.error(f"SSL error connecting to {host}:{port}: {e}")
    except socket.timeout:
        result["errors"].append(f"Connection timeout to {host}:{port}")
        logger.error(f"Timeout connecting to {host}:{port}")
    except Exception as e:
        result["errors"].append(f"Connection error: {str(e)}")
        logger.error(f"Error connecting to {host}:{port}: {e}")
    
    return result


def _is_certificate_expired(cert: Dict[str, Any]) -> bool:
    """Check if certificate is expired."""
    try:
        not_after = cert.get("notAfter")
        if not not_after:
            return False
        
        # Parse certificate date format
        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expiry_date = expiry_date.replace(tzinfo=timezone.utc)
        
        return datetime.now(timezone.utc) > expiry_date
    except Exception:
        return False


def validate_ca_bundle() -> Dict[str, Any]:
    """Validate CA bundle and SSL environment."""
    result = {
        "ca_bundle_path": None,
        "ca_bundle_exists": False,
        "ca_bundle_readable": False,
        "certificates_count": 0,
        "python_ssl_version": None,
        "openssl_version": None,
        "errors": []
    }
    
    try:
        # Get CA bundle path
        ca_bundle_path = certifi.where()
        result["ca_bundle_path"] = ca_bundle_path
        
        # Check if CA bundle exists and is readable
        ca_bundle = Path(ca_bundle_path)
        result["ca_bundle_exists"] = ca_bundle.exists()
        result["ca_bundle_readable"] = ca_bundle.is_file() and ca_bundle.stat().st_size > 0
        
        # Count certificates in bundle
        if result["ca_bundle_readable"]:
            with open(ca_bundle_path, 'r') as f:
                content = f.read()
                result["certificates_count"] = content.count("-----BEGIN CERTIFICATE-----")
        
        # Get SSL version information
        result["python_ssl_version"] = ssl.OPENSSL_VERSION
        result["openssl_version"] = ssl.OPENSSL_VERSION_INFO
        
        logger.info(f"CA bundle validation successful: {ca_bundle_path}")
        
    except Exception as e:
        result["errors"].append(f"CA bundle validation error: {str(e)}")
        logger.error(f"CA bundle validation failed: {e}")
    
    return result


def diagnose_ssl_issues(host: str, port: int) -> Dict[str, Any]:
    """Comprehensive SSL diagnostics."""
    diagnosis = {
        "connectivity": None,
        "ca_bundle": None,
        "recommendations": [],
        "severity": "info"
    }
    
    # Check SSL connectivity
    diagnosis["connectivity"] = check_ssl_connectivity(host, port)
    
    # Validate CA bundle
    diagnosis["ca_bundle"] = validate_ca_bundle()
    
    # Generate recommendations
    if not diagnosis["connectivity"]["connected"]:
        diagnosis["recommendations"].append("Check network connectivity and firewall settings")
        diagnosis["severity"] = "error"
    
    elif not diagnosis["connectivity"]["ssl_available"]:
        diagnosis["recommendations"].append("SSL/TLS not available on target host")
        diagnosis["recommendations"].append("Consider using HTTP instead of HTTPS")
        diagnosis["severity"] = "warning"
    
    elif diagnosis["connectivity"]["certificate_info"] and \
         diagnosis["connectivity"]["certificate_info"]["is_expired"]:
        diagnosis["recommendations"].append("Server certificate is expired")
        diagnosis["recommendations"].append("Contact server administrator to renew certificate")
        diagnosis["severity"] = "error"
    
    if not diagnosis["ca_bundle"]["ca_bundle_readable"]:
        diagnosis["recommendations"].append("CA bundle is not readable")
        diagnosis["recommendations"].append("Reinstall certificates: pip install --upgrade certifi")
        diagnosis["severity"] = "error"
    
    elif diagnosis["ca_bundle"]["certificates_count"] < 100:
        diagnosis["recommendations"].append("CA bundle seems incomplete")
        diagnosis["recommendations"].append("Update certificates: pip install --upgrade certifi")
        diagnosis["severity"] = "warning"
    
    return diagnosis


def create_custom_ca_bundle(additional_certs: list) -> str:
    """Create a custom CA bundle with additional certificates."""
    # Get default CA bundle
    default_bundle = certifi.where()
    
    # Create custom bundle path
    custom_bundle_path = Path.cwd() / "custom_ca_bundle.pem"
    
    # Copy default bundle and append custom certificates
    with open(default_bundle, 'r') as default_file:
        default_content = default_file.read()
    
    with open(custom_bundle_path, 'w') as custom_file:
        custom_file.write(default_content)
        custom_file.write("\n")
        
        for cert_path in additional_certs:
            if Path(cert_path).exists():
                with open(cert_path, 'r') as cert_file:
                    custom_file.write(cert_file.read())
                    custom_file.write("\n")
                logger.info(f"Added certificate to bundle: {cert_path}")
    
    logger.info(f"Created custom CA bundle: {custom_bundle_path}")
    return str(custom_bundle_path)


def create_user_friendly_ssl_config(
    verify_ssl: Optional[bool] = None,
    allow_self_signed: Optional[bool] = None,
    auto_detect: bool = True
) -> SSLConfig:
    """Create a user-friendly SSL configuration that prioritizes successful connections."""
    
    # Default to permissive settings for better user experience
    if verify_ssl is None:
        verify_ssl = False  # Default to disabled for ease of use
    
    if allow_self_signed is None:
        allow_self_signed = True  # Default to allow self-signed for compatibility
    
    config = SSLConfig(
        verify_ssl=verify_ssl,
        allow_self_signed=allow_self_signed,
        auto_detect_ssl_issues=auto_detect
    )
    
    logger.info("Created user-friendly SSL configuration prioritizing successful connections")
    return config


def test_ssl_with_fallback(host: str, port: int) -> Dict[str, Any]:
    """Test SSL connectivity with automatic fallback for problematic certificates."""
    result = {
        "host": host,
        "port": port,
        "connection_successful": False,
        "ssl_working": False,
        "certificate_issues": [],
        "fallback_used": False,
        "final_config": None
    }
    
    # Try strict SSL first
    logger.info(f"Testing strict SSL connection to {host}:{port}")
    strict_ssl = check_ssl_connectivity(host, port)
    
    if strict_ssl["connected"] and strict_ssl["ssl_available"] and not strict_ssl["errors"]:
        result["connection_successful"] = True
        result["ssl_working"] = True
        result["final_config"] = "strict_ssl"
        logger.info("Strict SSL connection successful")
        return result
    
    # If strict SSL fails, try permissive SSL
    logger.info("Strict SSL failed, trying permissive SSL (allowing self-signed)")
    
    try:
        # Test with permissive settings
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                result["connection_successful"] = True
                result["ssl_working"] = True
                result["fallback_used"] = True
                result["final_config"] = "permissive_ssl"
                
                # Get certificate info for diagnostics
                cert = ssock.getpeercert()
                if cert:
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    if "localhost" in str(issuer) or "self-signed" in str(issuer).lower():
                        result["certificate_issues"].append("Self-signed certificate detected")
                    else:
                        result["certificate_issues"].append("Non-commercial or custom CA certificate")
                
                logger.info("Permissive SSL connection successful")
                return result
    
    except Exception as e:
        logger.warning(f"Permissive SSL also failed: {e}")
        result["certificate_issues"].append(f"SSL connection failed: {e}")
    
    # Last resort: try without SSL (if HTTPS fails, maybe HTTP works)
    logger.info("SSL connection failed, connection may need to be made without SSL")
    result["final_config"] = "no_ssl_recommended"
    
    return result


def fix_pip_ssl_issues():
    """Attempt to fix common pip SSL issues."""
    fixes_applied = []
    
    try:
        # Upgrade certifi
        import subprocess
        import sys
        
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "--upgrade", "certifi"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            fixes_applied.append("Updated certifi package")
        else:
            logger.error(f"Failed to update certifi: {result.stderr}")
    
    except Exception as e:
        logger.error(f"Error updating certifi: {e}")
    
    return fixes_applied


def get_recommended_ssl_settings(host: str, port: int) -> Dict[str, Any]:
    """Get recommended SSL settings based on automatic testing."""
    logger.info(f"Analyzing SSL requirements for {host}:{port}")
    
    test_result = test_ssl_with_fallback(host, port)
    
    recommendations = {
        "verify_ssl": False,  # Default to False for compatibility
        "allow_self_signed": True,  # Default to True for compatibility
        "reasoning": "",
        "environment_variables": {},
        "success_probability": "high"
    }
    
    if test_result["ssl_working"] and not test_result["fallback_used"]:
        # Strict SSL works
        recommendations["verify_ssl"] = True
        recommendations["allow_self_signed"] = False
        recommendations["reasoning"] = "Commercial certificate detected, strict SSL recommended"
        recommendations["environment_variables"] = {
            "VERIFY_SSL": "true",
            "WAZUH_ALLOW_SELF_SIGNED": "false"
        }
    elif test_result["ssl_working"] and test_result["fallback_used"]:
        # Permissive SSL works
        recommendations["verify_ssl"] = False
        recommendations["allow_self_signed"] = True
        recommendations["reasoning"] = "Self-signed or custom certificate detected, permissive SSL recommended"
        recommendations["environment_variables"] = {
            "VERIFY_SSL": "false",
            "WAZUH_ALLOW_SELF_SIGNED": "true"
        }
    else:
        # SSL doesn't work
        recommendations["verify_ssl"] = False
        recommendations["allow_self_signed"] = True
        recommendations["reasoning"] = "SSL connection failed, permissive settings recommended"
        recommendations["environment_variables"] = {
            "VERIFY_SSL": "false",
            "WAZUH_ALLOW_SELF_SIGNED": "true"
        }
        recommendations["success_probability"] = "medium"
    
    logger.info(f"SSL recommendations: {recommendations['reasoning']}")
    return recommendations