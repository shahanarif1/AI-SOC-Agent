"""Configuration management with validation and security best practices."""

import os
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from pydantic import BaseModel, validator, Field


class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceFramework(Enum):
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST = "nist"
    ISO27001 = "iso27001"


class ThreatCategory(Enum):
    MALWARE = "malware"
    INTRUSION = "intrusion"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    AUTHENTICATION = "authentication"
    DOS = "denial_of_service"
    DATA_LEAK = "data_leak"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing required values."""
    pass


class WazuhConfig(BaseModel):
    """Validated Wazuh configuration with security best practices."""
    
    # Required Wazuh settings - no defaults for security
    host: str = Field(..., description="Wazuh server hostname or IP address")
    port: int = Field(default=55000, ge=1, le=65535, description="Wazuh API port")
    username: str = Field(..., min_length=1, description="Wazuh API username")
    password: str = Field(..., min_length=1, description="Wazuh API password")
    verify_ssl: bool = Field(default=True, description="Enable SSL certificate verification")
    api_version: str = Field(default="v4", description="Wazuh API version")
    
    # Optional external API keys
    virustotal_api_key: Optional[str] = Field(default=None, description="VirusTotal API key")
    shodan_api_key: Optional[str] = Field(default=None, description="Shodan API key")
    abuseipdb_api_key: Optional[str] = Field(default=None, description="AbuseIPDB API key")
    
    # Performance settings
    max_alerts_per_query: int = Field(default=1000, ge=1, le=10000)
    max_agents_per_scan: int = Field(default=10, ge=1, le=100)
    cache_ttl_seconds: int = Field(default=300, ge=0)
    request_timeout_seconds: int = Field(default=30, ge=1, le=300)
    max_connections: int = Field(default=10, ge=1, le=100)
    pool_size: int = Field(default=5, ge=1, le=50)
    
    # Feature flags
    enable_external_intel: bool = Field(default=True)
    enable_ml_analysis: bool = Field(default=True)
    enable_compliance_checking: bool = Field(default=True)
    enable_experimental: bool = Field(default=False)
    
    # Logging configuration
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    
    class Config:
        """Pydantic configuration."""
        env_prefix = ""
        case_sensitive = False
    
    @validator('host')
    def validate_host(cls, v):
        """Validate host is not empty and not default insecure values."""
        if not v or v.strip() == "":
            raise ValueError("WAZUH_HOST must be provided")
        return v.strip()
    
    @validator('username')
    def validate_username(cls, v):
        """Validate username is provided."""
        if not v or v.strip() == "":
            raise ValueError("WAZUH_USER must be provided")
        if v.strip().lower() in ["admin", "wazuh", "user", "test"]:
            logging.warning("Using default username '%s' is not recommended for production", v)
        return v.strip()
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password meets minimum security requirements."""
        if not v or v.strip() == "":
            raise ValueError("WAZUH_PASS must be provided")
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if v.lower() in ["admin", "password", "123456", "wazuh"]:
            raise ValueError("Password is too weak. Use a strong, unique password.")
        return v
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level is valid."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"LOG_LEVEL must be one of {valid_levels}")
        return v.upper()
    
    @property
    def base_url(self) -> str:
        """Get the base URL for Wazuh API."""
        return f"https://{self.host}:{self.port}"
    
    @classmethod
    def from_env(cls) -> 'WazuhConfig':
        """Create configuration from environment variables."""
        try:
            return cls(
                host=os.getenv("WAZUH_HOST"),
                port=int(os.getenv("WAZUH_PORT", "55000")),
                username=os.getenv("WAZUH_USER"),
                password=os.getenv("WAZUH_PASS"),
                verify_ssl=os.getenv("VERIFY_SSL", "true").lower() == "true",
                api_version=os.getenv("WAZUH_API_VERSION", "v4"),
                virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
                shodan_api_key=os.getenv("SHODAN_API_KEY"),
                abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
                max_alerts_per_query=int(os.getenv("MAX_ALERTS_PER_QUERY", "1000")),
                max_agents_per_scan=int(os.getenv("MAX_AGENTS_PER_SCAN", "10")),
                cache_ttl_seconds=int(os.getenv("CACHE_TTL_SECONDS", "300")),
                request_timeout_seconds=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30")),
                max_connections=int(os.getenv("MAX_CONNECTIONS", "10")),
                pool_size=int(os.getenv("POOL_SIZE", "5")),
                enable_external_intel=os.getenv("ENABLE_EXTERNAL_INTEL", "true").lower() == "true",
                enable_ml_analysis=os.getenv("ENABLE_ML_ANALYSIS", "true").lower() == "true",
                enable_compliance_checking=os.getenv("ENABLE_COMPLIANCE_CHECKING", "true").lower() == "true",
                enable_experimental=os.getenv("ENABLE_EXPERIMENTAL", "false").lower() == "true",
                debug=os.getenv("DEBUG", "false").lower() == "true",
                log_level=os.getenv("LOG_LEVEL", "INFO"),
            )
        except Exception as e:
            raise ConfigurationError(f"Configuration validation failed: {str(e)}") from e
