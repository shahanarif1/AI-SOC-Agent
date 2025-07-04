"""
Authentication and authorization for remote MCP server access.
"""

import os
import jwt
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from functools import wraps
from aiohttp import web

from wazuh_mcp_server.utils import get_logger

logger = get_logger(__name__)


class SecurityManager:
    """Manages authentication and authorization for remote access."""
    
    def __init__(self):
        # Require JWT secret to be explicitly set for security
        self.jwt_secret = os.getenv('JWT_SECRET')
        if not self.jwt_secret:
            self.jwt_secret = self._generate_secure_secret()
            logger.warning("JWT_SECRET not set - generated secure random secret for this session")
            logger.warning("For production, set JWT_SECRET environment variable with: openssl rand -base64 64")
        elif self.jwt_secret == 'wazuh-mcp-default-secret':
            raise ValueError("Default JWT secret detected! Set JWT_SECRET environment variable with a secure random value")
        
        self.jwt_expiry_hours = int(os.getenv('JWT_EXPIRY_HOURS', '24'))
        self.enable_auth = os.getenv('ENABLE_AUTH', 'true').lower() == 'true'
        
        # Simple API key authentication as fallback
        self.api_keys = self._load_api_keys()
        
        logger.info(f"Security manager initialized (auth_enabled: {self.enable_auth})")
    
    def _generate_secure_secret(self) -> str:
        """Generate a cryptographically secure JWT secret."""
        import secrets
        import base64
        
        # Generate 64 bytes of secure random data and encode as base64
        secure_bytes = secrets.token_bytes(64)
        secure_secret = base64.b64encode(secure_bytes).decode('utf-8')
        
        logger.info("Generated secure JWT secret using cryptographically secure random generator")
        return secure_secret
    
    def _load_api_keys(self) -> Dict[str, Dict[str, Any]]:
        """Load API keys from environment or config."""
        api_keys = {}
        
        # Load from environment variables
        api_key_env = os.getenv('API_KEYS', '')
        if api_key_env:
            # Format: "key1:user1:role1,key2:user2:role2"
            for key_config in api_key_env.split(','):
                if ':' in key_config:
                    parts = key_config.split(':')
                    if len(parts) >= 2:
                        key = parts[0].strip()
                        user = parts[1].strip()
                        role = parts[2].strip() if len(parts) > 2 else 'user'
                        api_keys[key] = {'user': user, 'role': role}
        
        # Add admin key if specified (no insecure defaults)
        admin_key = os.getenv('ADMIN_API_KEY')
        if admin_key and admin_key != 'wazuh-mcp-admin-key':
            api_keys[admin_key] = {'user': 'admin', 'role': 'admin'}
        elif admin_key == 'wazuh-mcp-admin-key':
            logger.warning("Default admin API key detected - ignoring for security. Set ADMIN_API_KEY to a secure value.")
        
        return api_keys
    
    def generate_token(self, user: str, role: str = 'user') -> str:
        """Generate JWT token for user."""
        payload = {
            'user': user,
            'role': role,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=self.jwt_expiry_hours)
        }
        
        token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
        logger.info(f"Generated token for user: {user}")
        return token
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token and return payload."""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    def verify_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Verify API key and return user info."""
        if api_key in self.api_keys:
            user_info = self.api_keys[api_key].copy()
            logger.info(f"Valid API key for user: {user_info['user']}")
            return user_info
        return None
    
    def authenticate_request(self, request) -> Optional[Dict[str, Any]]:
        """Authenticate incoming request."""
        if not self.enable_auth:
            return {'user': 'anonymous', 'role': 'admin'}  # No auth required
        
        # Check Authorization header
        auth_header = request.headers.get('Authorization', '')
        
        # JWT Bearer token
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
            payload = self.verify_token(token)
            if payload:
                return payload
        
        # API Key
        elif auth_header.startswith('ApiKey '):
            api_key = auth_header[7:]
            user_info = self.verify_api_key(api_key)
            if user_info:
                return user_info
        
        # Query parameter authentication removed for security
        # API keys in URLs can be exposed in logs, browser history, and referrer headers
        # Use Authorization header: "Authorization: ApiKey your-api-key"
        
        return None
    
    def require_auth(self, required_role: str = 'user'):
        """Decorator to require authentication for endpoints."""
        def decorator(func):
            @wraps(func)
            async def wrapper(request, *args, **kwargs):
                if not self.enable_auth:
                    # Add mock user info when auth is disabled
                    request.user = {'user': 'anonymous', 'role': 'admin'}
                    return await func(request, *args, **kwargs)
                
                user_info = self.authenticate_request(request)
                if not user_info:
                    return web.json_response(
                        {'error': 'Authentication required'}, 
                        status=401,
                        headers={'WWW-Authenticate': 'Bearer'}
                    )
                
                # Check role if required
                user_role = user_info.get('role', 'user')
                if required_role == 'admin' and user_role != 'admin':
                    return web.json_response(
                        {'error': 'Admin access required'}, 
                        status=403
                    )
                
                # Add user info to request
                request.user = user_info
                return await func(request, *args, **kwargs)
            
            return wrapper
        return decorator


class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self):
        self.requests = {}
        self.max_requests = int(os.getenv('RATE_LIMIT_REQUESTS', '100'))
        self.window_seconds = int(os.getenv('RATE_LIMIT_WINDOW', '60'))
        self.cleanup_interval = 300  # 5 minutes
        self.last_cleanup = time.time()
    
    def _cleanup_old_entries(self):
        """Remove old entries from memory."""
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            cutoff = current_time - self.window_seconds
            keys_to_remove = []
            
            for client_ip, timestamps in self.requests.items():
                # Filter out old timestamps
                recent_timestamps = [ts for ts in timestamps if ts > cutoff]
                if recent_timestamps:
                    self.requests[client_ip] = recent_timestamps
                else:
                    keys_to_remove.append(client_ip)
            
            # Remove empty entries
            for key in keys_to_remove:
                del self.requests[key]
            
            self.last_cleanup = current_time
    
    def is_allowed(self, client_ip: str) -> bool:
        """Check if request is allowed based on rate limits."""
        current_time = time.time()
        self._cleanup_old_entries()
        
        # Get recent requests for this client
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        
        recent_requests = self.requests[client_ip]
        
        # Filter requests within the time window
        window_start = current_time - self.window_seconds
        recent_requests = [ts for ts in recent_requests if ts > window_start]
        
        # Check if under the limit
        if len(recent_requests) < self.max_requests:
            recent_requests.append(current_time)
            self.requests[client_ip] = recent_requests
            return True
        
        return False
    
    def get_reset_time(self, client_ip: str) -> int:
        """Get when the rate limit resets for this client."""
        if client_ip not in self.requests or not self.requests[client_ip]:
            return int(time.time())
        
        oldest_request = min(self.requests[client_ip])
        return int(oldest_request + self.window_seconds)


# Global instances
security_manager = SecurityManager()
rate_limiter = RateLimiter()


def require_auth(required_role: str = 'user'):
    """Convenience function for authentication decorator."""
    return security_manager.require_auth(required_role)


async def rate_limit_middleware(request, handler):
    """Rate limiting middleware."""
    client_ip = request.remote
    
    if not rate_limiter.is_allowed(client_ip):
        reset_time = rate_limiter.get_reset_time(client_ip)
        return web.json_response(
            {'error': 'Rate limit exceeded', 'reset_time': reset_time},
            status=429,
            headers={
                'X-RateLimit-Limit': str(rate_limiter.max_requests),
                'X-RateLimit-Remaining': '0',
                'X-RateLimit-Reset': str(reset_time)
            }
        )
    
    return await handler(request)