"""
Production-grade security manager for DXT extension.
"""

import re
import hashlib
import hmac
import secrets
import time
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass
from enum import Enum
import logging
from ipaddress import ip_address, AddressValueError
from urllib.parse import urlparse
import json

from ..utils.exceptions import SecurityError, ValidationError


class SecurityLevel(Enum):
    """Security levels for different operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityContext:
    """Security context for operations."""
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    client_ip: Optional[str] = None
    timestamp: float = None
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()


class SecurityManager:
    """Production-grade security manager with comprehensive protection."""
    
    def __init__(self, secret_key: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.secret_key = secret_key or secrets.token_hex(32)
        self.failed_attempts = {}  # Rate limiting tracking
        self.blocked_ips = set()   # IP blocking
        
        # Security patterns
        self.sql_injection_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)",
            r"(;|\|\||&&)",
            r"(\/\*|\*\/|--|\#)",
            r"(\bOR\b.*=.*\bOR\b)",
            r"(\bAND\b.*=.*\bAND\b)"
        ]
        
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>"
        ]
        
        self.command_injection_patterns = [
            r"[;&|`$(){}[\]\\]",
            r"(rm|del|format|fdisk)",
            r"(wget|curl|nc|netcat)",
            r"(&&|\|\|)",
            r"(\$\(|\`)"
        ]
    
    def validate_input(self, data: Any, context: SecurityContext) -> Any:
        """Comprehensive input validation and sanitization."""
        if data is None:
            return data
        
        if isinstance(data, str):
            return self._validate_string_input(data, context)
        elif isinstance(data, dict):
            return self._validate_dict_input(data, context)
        elif isinstance(data, list):
            return self._validate_list_input(data, context)
        elif isinstance(data, (int, float, bool)):
            return self._validate_primitive_input(data, context)
        else:
            raise ValidationError(f"Unsupported data type: {type(data)}")
    
    def _validate_string_input(self, text: str, context: SecurityContext) -> str:
        """Validate and sanitize string input."""
        if not isinstance(text, str):
            raise ValidationError("Expected string input")
        
        # Length validation
        if len(text) > 10000:  # 10KB limit
            raise ValidationError("Input too long")
        
        # Security pattern detection
        if context.security_level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
            self._detect_security_threats(text)
        
        # Basic sanitization
        sanitized = self._sanitize_string(text)
        
        return sanitized
    
    def _validate_dict_input(self, data: Dict[str, Any], context: SecurityContext) -> Dict[str, Any]:
        """Validate dictionary input recursively."""
        if len(data) > 100:  # Limit dict size
            raise ValidationError("Dictionary too large")
        
        validated = {}
        for key, value in data.items():
            # Validate key
            if not isinstance(key, str):
                raise ValidationError("Dictionary keys must be strings")
            
            if len(key) > 100:
                raise ValidationError("Dictionary key too long")
            
            validated_key = self._validate_string_input(key, context)
            validated_value = self.validate_input(value, context)
            validated[validated_key] = validated_value
        
        return validated
    
    def _validate_list_input(self, data: List[Any], context: SecurityContext) -> List[Any]:
        """Validate list input recursively."""
        if len(data) > 1000:  # Limit list size
            raise ValidationError("List too large")
        
        return [self.validate_input(item, context) for item in data]
    
    def _validate_primitive_input(self, data: Union[int, float, bool], context: SecurityContext) -> Union[int, float, bool]:
        """Validate primitive data types."""
        if isinstance(data, (int, float)):
            # Check for reasonable numeric limits
            if isinstance(data, int) and abs(data) > 2**53:
                raise ValidationError("Integer too large")
            if isinstance(data, float) and abs(data) > 1e100:
                raise ValidationError("Float too large")
        
        return data
    
    def _detect_security_threats(self, text: str) -> None:
        """Detect common security threats in text input."""
        text_lower = text.lower()
        
        # SQL Injection detection
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                self.logger.warning(f"SQL injection attempt detected: {pattern}")
                raise SecurityError("Potential SQL injection detected")
        
        # XSS detection
        for pattern in self.xss_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                self.logger.warning(f"XSS attempt detected: {pattern}")
                raise SecurityError("Potential XSS attack detected")
        
        # Command injection detection
        for pattern in self.command_injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                self.logger.warning(f"Command injection attempt detected: {pattern}")
                raise SecurityError("Potential command injection detected")
    
    def _sanitize_string(self, text: str) -> str:
        """Basic string sanitization."""
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        # Remove control characters except common ones
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\t\n\r')
        
        return text
    
    def validate_ip_address(self, ip_str: str) -> str:
        """Validate and normalize IP address."""
        try:
            ip_obj = ip_address(ip_str.strip())
            
            # Check for private/reserved addresses if needed
            if ip_obj.is_private:
                self.logger.info(f"Private IP address: {ip_str}")
            
            if ip_obj.is_loopback:
                self.logger.info(f"Loopback IP address: {ip_str}")
            
            return str(ip_obj)
        except AddressValueError as e:
            raise ValidationError(f"Invalid IP address: {str(e)}")
    
    def validate_url(self, url: str) -> str:
        """Validate and sanitize URL."""
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                raise ValidationError("Only HTTP and HTTPS URLs are allowed")
            
            # Check for suspicious patterns
            if any(char in url for char in ['<', '>', '"', "'"]):
                raise ValidationError("URL contains suspicious characters")
            
            return url
        except Exception as e:
            raise ValidationError(f"Invalid URL: {str(e)}")
    
    def validate_wazuh_query_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Wazuh API query parameters."""
        validated = {}
        
        # Allowed parameters with validation rules
        allowed_params = {
            'limit': {'type': int, 'min': 1, 'max': 10000},
            'offset': {'type': int, 'min': 0, 'max': 1000000},
            'sort': {'type': str, 'max_length': 100},
            'search': {'type': str, 'max_length': 1000},
            'select': {'type': str, 'max_length': 500},
            'q': {'type': str, 'max_length': 2000},
            'level': {'type': int, 'min': 0, 'max': 16},
            'agent_id': {'type': str, 'max_length': 20},
            'status': {'type': str, 'allowed': ['active', 'pending', 'never_connected', 'disconnected']},
            'time_range': {'type': int, 'min': 60, 'max': 86400}  # 1 minute to 24 hours
        }
        
        for key, value in params.items():
            if key not in allowed_params:
                self.logger.warning(f"Unknown parameter ignored: {key}")
                continue
            
            rules = allowed_params[key]
            
            # Type validation
            if not isinstance(value, rules['type']):
                try:
                    value = rules['type'](value)
                except (ValueError, TypeError):
                    raise ValidationError(f"Parameter '{key}' must be of type {rules['type'].__name__}")
            
            # Range validation for integers
            if rules['type'] == int:
                if 'min' in rules and value < rules['min']:
                    raise ValidationError(f"Parameter '{key}' must be >= {rules['min']}")
                if 'max' in rules and value > rules['max']:
                    raise ValidationError(f"Parameter '{key}' must be <= {rules['max']}")
            
            # Length validation for strings
            if rules['type'] == str:
                if 'max_length' in rules and len(value) > rules['max_length']:
                    raise ValidationError(f"Parameter '{key}' too long (max {rules['max_length']})")
                if 'allowed' in rules and value not in rules['allowed']:
                    raise ValidationError(f"Parameter '{key}' must be one of: {rules['allowed']}")
            
            validated[key] = value
        
        return validated
    
    def rate_limit_check(self, identifier: str, max_requests: int = 100, window_seconds: int = 3600) -> bool:
        """Check rate limits for an identifier (IP, user, etc.)."""
        current_time = time.time()
        window_start = current_time - window_seconds
        
        # Clean old entries
        if identifier in self.failed_attempts:
            self.failed_attempts[identifier] = [
                timestamp for timestamp in self.failed_attempts[identifier]
                if timestamp > window_start
            ]
        else:
            self.failed_attempts[identifier] = []
        
        # Check current rate
        if len(self.failed_attempts[identifier]) >= max_requests:
            self.logger.warning(f"Rate limit exceeded for {identifier}")
            return False
        
        # Record this request
        self.failed_attempts[identifier].append(current_time)
        return True
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure token."""
        return secrets.token_hex(length)
    
    def hash_sensitive_data(self, data: str, salt: Optional[str] = None) -> str:
        """Hash sensitive data with salt."""
        if salt is None:
            salt = secrets.token_hex(16)
        
        return hashlib.pbkdf2_hmac('sha256', data.encode(), salt.encode(), 100000).hex()
    
    def verify_integrity(self, data: str, signature: str) -> bool:
        """Verify data integrity using HMAC."""
        try:
            expected_signature = hmac.new(
                self.secret_key.encode(),
                data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(signature, expected_signature)
        except Exception:
            return False
    
    def sanitize_log_data(self, data: Any) -> str:
        """Sanitize data for safe logging."""
        if isinstance(data, dict):
            # Remove sensitive keys
            sensitive_keys = ['password', 'token', 'key', 'secret', 'credential']
            sanitized = {
                k: '[REDACTED]' if any(sens in k.lower() for sens in sensitive_keys) else v
                for k, v in data.items()
            }
            return json.dumps(sanitized, default=str)
        
        # For strings, mask potential sensitive patterns
        if isinstance(data, str):
            # Mask potential passwords, tokens, etc.
            patterns = [
                (r'(password|pwd|pass)\s*[:=]\s*\S+', r'\1=[REDACTED]'),
                (r'(token|key|secret)\s*[:=]\s*\S+', r'\1=[REDACTED]'),
                (r'([A-Za-z0-9+/]{20,}={0,2})', '[BASE64_REDACTED]'),  # Base64 tokens
                (r'([0-9a-fA-F]{32,})', '[HEX_REDACTED]')  # Hex tokens
            ]
            
            for pattern, replacement in patterns:
                data = re.sub(pattern, replacement, data, flags=re.IGNORECASE)
        
        return str(data)
    
    def audit_log(self, action: str, context: SecurityContext, result: str = "success", details: Optional[Dict] = None):
        """Create security audit log entry."""
        audit_entry = {
            "timestamp": time.time(),
            "action": action,
            "result": result,
            "user_id": context.user_id,
            "session_id": context.session_id,
            "client_ip": context.client_ip,
            "security_level": context.security_level.value,
            "details": self.sanitize_log_data(details) if details else None
        }
        
        self.logger.info(f"AUDIT: {json.dumps(audit_entry)}")


# Global security manager instance
security_manager = SecurityManager()


# Decorator for securing functions
def secure_operation(security_level: SecurityLevel = SecurityLevel.MEDIUM):
    """Decorator to add security validation to functions."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Create security context
            context = SecurityContext(security_level=security_level)
            
            # Validate all arguments
            try:
                validated_args = [security_manager.validate_input(arg, context) for arg in args]
                validated_kwargs = {
                    k: security_manager.validate_input(v, context)
                    for k, v in kwargs.items()
                }
                
                # Audit the operation
                security_manager.audit_log(func.__name__, context, "attempt")
                
                # Execute function
                result = func(*validated_args, **validated_kwargs)
                
                # Audit success
                security_manager.audit_log(func.__name__, context, "success")
                
                return result
                
            except (ValidationError, SecurityError) as e:
                security_manager.audit_log(func.__name__, context, "security_error", {"error": str(e)})
                raise
            except Exception as e:
                security_manager.audit_log(func.__name__, context, "error", {"error": str(e)})
                raise
        
        return wrapper
    return decorator