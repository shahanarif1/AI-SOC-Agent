#!/usr/bin/env python3
"""
Production-grade SSL configuration and certificate handling for Wazuh MCP Server.
Provides secure defaults while supporting various deployment scenarios.
"""

import os
import ssl
import warnings
import urllib3
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SSLConfig:
    """SSL configuration settings for production deployment."""
    verify_ssl: bool = True
    ca_bundle_path: Optional[str] = None
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    allow_self_signed: bool = False
    ssl_timeout: int = 30
    auto_detect_issues: bool = True
    min_tls_version: str = "TLSv1.2"


class SSLConfigurationManager:
    """Production-grade SSL configuration manager."""
    
    def __init__(self):
        self.logger = logger
        self._ssl_warnings_disabled = False
    
    def create_ssl_context(self, config: SSLConfig) -> Optional[ssl.SSLContext]:
        """
        Create SSL context with security-first configuration.
        
        Args:
            config: SSL configuration settings
            
        Returns:
            Configured SSL context or None for unverified connections
        """
        if not config.verify_ssl:
            self._handle_unverified_ssl(config)
            return None
        
        # Create secure SSL context
        context = ssl.create_default_context()
        
        # Set minimum TLS version
        if config.min_tls_version == "TLSv1.3":
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        elif config.min_tls_version == "TLSv1.2":
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            self.logger.warning(f"Unsupported TLS version: {config.min_tls_version}, using TLSv1.2")
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Configure custom CA bundle
        if config.ca_bundle_path:
            if Path(config.ca_bundle_path).exists():
                context.load_verify_locations(config.ca_bundle_path)
                self.logger.info(f"Loaded custom CA bundle: {config.ca_bundle_path}")
            else:
                self.logger.error(f"CA bundle not found: {config.ca_bundle_path}")
                raise FileNotFoundError(f"CA bundle not found: {config.ca_bundle_path}")
        
        # Configure client certificates
        if config.client_cert_path and config.client_key_path:
            if Path(config.client_cert_path).exists() and Path(config.client_key_path).exists():
                context.load_cert_chain(config.client_cert_path, config.client_key_path)
                self.logger.info("Client certificate authentication configured")
            else:
                self.logger.error("Client certificate or key file not found")
                raise FileNotFoundError("Client certificate or key file not found")
        
        # Handle self-signed certificates
        if config.allow_self_signed:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.logger.warning("Self-signed certificates allowed - not recommended for production")
        
        return context
    
    def _handle_unverified_ssl(self, config: SSLConfig):
        """Handle unverified SSL connections with appropriate warnings."""
        if not self._ssl_warnings_disabled:
            # Show warning but don't disable globally
            self.logger.warning(
                "SSL verification disabled - not recommended for production. "
                "Consider using proper certificates or configuring ca_bundle_path."
            )
            
            # Only disable urllib3 warnings for this specific case
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self._ssl_warnings_disabled = True
    
    def get_aiohttp_connector_args(self, config: SSLConfig) -> Dict[str, Any]:
        """
        Get aiohttp connector arguments for SSL configuration.
        
        Args:
            config: SSL configuration settings
            
        Returns:
            Dictionary of connector arguments
        """
        connector_args = {}
        
        if config.verify_ssl:
            ssl_context = self.create_ssl_context(config)
            if ssl_context:
                connector_args["ssl_context"] = ssl_context
        else:
            connector_args["ssl"] = False
        
        return connector_args
    
    def validate_ssl_config(self, config: SSLConfig) -> bool:
        """
        Validate SSL configuration for security best practices.
        
        Args:
            config: SSL configuration to validate
            
        Returns:
            True if configuration is valid and secure
        """
        issues = []
        
        # Check for insecure configurations
        if not config.verify_ssl:
            issues.append("SSL verification is disabled")
        
        if config.allow_self_signed:
            issues.append("Self-signed certificates are allowed")
        
        if config.min_tls_version not in ["TLSv1.2", "TLSv1.3"]:
            issues.append(f"Insecure TLS version: {config.min_tls_version}")
        
        # Check file paths
        if config.ca_bundle_path and not Path(config.ca_bundle_path).exists():
            issues.append(f"CA bundle file not found: {config.ca_bundle_path}")
        
        if config.client_cert_path and not Path(config.client_cert_path).exists():
            issues.append(f"Client certificate file not found: {config.client_cert_path}")
        
        if config.client_key_path and not Path(config.client_key_path).exists():
            issues.append(f"Client key file not found: {config.client_key_path}")
        
        # Log issues
        if issues:
            self.logger.warning("SSL configuration issues found:")
            for issue in issues:
                self.logger.warning(f"  - {issue}")
            return False
        
        self.logger.info("SSL configuration validated successfully")
        return True
    
    def auto_detect_ssl_issues(self, host: str, port: int) -> Dict[str, Any]:
        """
        Auto-detect SSL configuration issues for a given host.
        
        Args:
            host: Target hostname
            port: Target port
            
        Returns:
            Dictionary with detection results and recommendations
        """
        import socket
        import ssl
        
        results = {
            "host": host,
            "port": port,
            "ssl_available": False,
            "certificate_valid": False,
            "self_signed": False,
            "tls_versions": [],
            "recommendations": []
        }
        
        try:
            # Test SSL connection
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    results["ssl_available"] = True
                    results["certificate_valid"] = True
                    
                    # Get certificate info
                    cert = ssock.getpeercert()
                    if cert:
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        subject = dict(x[0] for x in cert.get('subject', []))
                        
                        # Check for self-signed
                        if issuer == subject:
                            results["self_signed"] = True
                            results["recommendations"].append(
                                "Certificate appears to be self-signed. Consider using a proper CA."
                            )
        
        except ssl.SSLError as e:
            results["ssl_available"] = True
            results["certificate_valid"] = False
            self.logger.warning(f"SSL error connecting to {host}:{port}: {e}")
            
            if "CERTIFICATE_VERIFY_FAILED" in str(e):
                results["recommendations"].append(
                    "Certificate verification failed. Check if using self-signed certificates."
                )
            
        except Exception as e:
            self.logger.error(f"Failed to connect to {host}:{port}: {e}")
            results["recommendations"].append(
                "Connection failed. Check if SSL/TLS is enabled on the target."
            )
        
        return results
    
    @classmethod
    def from_environment(cls, prefix: str = "") -> SSLConfig:
        """
        Create SSL configuration from environment variables.
        
        Args:
            prefix: Environment variable prefix (e.g., "WAZUH_")
            
        Returns:
            SSL configuration object
        """
        return SSLConfig(
            verify_ssl=os.getenv(f"{prefix}VERIFY_SSL", "true").lower() == "true",
            ca_bundle_path=os.getenv(f"{prefix}CA_BUNDLE_PATH"),
            client_cert_path=os.getenv(f"{prefix}CLIENT_CERT_PATH"),
            client_key_path=os.getenv(f"{prefix}CLIENT_KEY_PATH"),
            allow_self_signed=os.getenv(f"{prefix}ALLOW_SELF_SIGNED", "false").lower() == "true",
            ssl_timeout=int(os.getenv(f"{prefix}SSL_TIMEOUT", "30")),
            auto_detect_issues=os.getenv(f"{prefix}AUTO_DETECT_SSL_ISSUES", "true").lower() == "true",
            min_tls_version=os.getenv(f"{prefix}MIN_TLS_VERSION", "TLSv1.2")
        )


# Global SSL manager instance
ssl_manager = SSLConfigurationManager()


def get_ssl_config(prefix: str = "") -> SSLConfig:
    """Get SSL configuration from environment variables."""
    return SSLConfigurationManager.from_environment(prefix)


def create_secure_ssl_context(config: SSLConfig) -> Optional[ssl.SSLContext]:
    """Create a secure SSL context."""
    return ssl_manager.create_ssl_context(config)


def validate_ssl_setup(config: SSLConfig) -> bool:
    """Validate SSL configuration."""
    return ssl_manager.validate_ssl_config(config)


# SSL configuration testing and validation module
# For testing, run: python -m wazuh_mcp_server.utils.ssl_config