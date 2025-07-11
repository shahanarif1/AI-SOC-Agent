"""
Context Cache System

Provides intelligent caching for context data to prevent redundant API calls
and improve response times for the prompt enhancement system.
"""

import time
import hashlib
import json
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import OrderedDict
import asyncio
from threading import RLock


class ContextCache:
    """Thread-safe LRU cache with TTL for context data."""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        """
        Initialize the context cache.
        
        Args:
            max_size: Maximum number of items to cache
            default_ttl: Default time-to-live in seconds
        """
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, Tuple[Any, float, int]] = OrderedDict()
        self._lock = RLock()
        self._stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expirations': 0
        }
    
    def _generate_cache_key(self, namespace: str, key_data: Dict[str, Any]) -> str:
        """Generate a cache key from namespace and key data."""
        # Sort keys to ensure consistent hashing
        sorted_data = json.dumps(key_data, sort_keys=True, separators=(',', ':'))
        hash_input = f"{namespace}:{sorted_data}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def _is_expired(self, stored_time: float, ttl: int) -> bool:
        """Check if a cache entry has expired."""
        return time.time() - stored_time > ttl
    
    def _evict_expired(self):
        """Remove expired entries from cache."""
        current_time = time.time()
        expired_keys = []
        
        for key, (value, stored_time, ttl) in self._cache.items():
            if current_time - stored_time > ttl:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._cache[key]
            self._stats['expirations'] += 1
    
    def _evict_lru(self):
        """Evict least recently used items if cache is full."""
        while len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)  # Remove oldest item
            self._stats['evictions'] += 1
    
    def get(self, namespace: str, key_data: Dict[str, Any]) -> Optional[Any]:
        """
        Get value from cache.
        
        Args:
            namespace: Cache namespace (e.g., 'alerts', 'agents')
            key_data: Dictionary containing key parameters
            
        Returns:
            Cached value if found and not expired, None otherwise
        """
        with self._lock:
            cache_key = self._generate_cache_key(namespace, key_data)
            
            if cache_key not in self._cache:
                self._stats['misses'] += 1
                return None
            
            value, stored_time, ttl = self._cache[cache_key]
            
            # Check if expired
            if self._is_expired(stored_time, ttl):
                del self._cache[cache_key]
                self._stats['expirations'] += 1
                self._stats['misses'] += 1
                return None
            
            # Move to end (most recently used)
            self._cache.move_to_end(cache_key)
            self._stats['hits'] += 1
            return value
    
    def set(self, namespace: str, key_data: Dict[str, Any], value: Any, 
            ttl: Optional[int] = None) -> None:
        """
        Set value in cache.
        
        Args:
            namespace: Cache namespace
            key_data: Dictionary containing key parameters
            value: Value to cache
            ttl: Time-to-live in seconds (uses default if None)
        """
        with self._lock:
            cache_key = self._generate_cache_key(namespace, key_data)
            cache_ttl = ttl if ttl is not None else self.default_ttl
            
            # Clean up expired entries
            self._evict_expired()
            
            # Evict LRU if necessary
            self._evict_lru()
            
            # Store the value
            self._cache[cache_key] = (value, time.time(), cache_ttl)
    
    def invalidate(self, namespace: str, key_data: Optional[Dict[str, Any]] = None) -> int:
        """
        Invalidate cache entries.
        
        Args:
            namespace: Cache namespace to invalidate
            key_data: Specific key data to invalidate (all namespace if None)
            
        Returns:
            Number of entries invalidated
        """
        with self._lock:
            if key_data is not None:
                # Invalidate specific key
                cache_key = self._generate_cache_key(namespace, key_data)
                if cache_key in self._cache:
                    del self._cache[cache_key]
                    return 1
                return 0
            else:
                # Invalidate all keys in namespace
                keys_to_remove = []
                for key in self._cache.keys():
                    # Check if key belongs to namespace
                    if key.startswith(namespace):
                        keys_to_remove.append(key)
                
                for key in keys_to_remove:
                    del self._cache[key]
                
                return len(keys_to_remove)
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._cache.clear()
            self._stats = {
                'hits': 0,
                'misses': 0,
                'evictions': 0,
                'expirations': 0
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_requests = self._stats['hits'] + self._stats['misses']
            hit_rate = self._stats['hits'] / total_requests if total_requests > 0 else 0
            
            return {
                **self._stats.copy(),
                'hit_rate': hit_rate,
                'cache_size': len(self._cache),
                'max_size': self.max_size
            }
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get detailed cache information."""
        with self._lock:
            current_time = time.time()
            entries_by_namespace = {}
            expired_count = 0
            
            for key, (value, stored_time, ttl) in self._cache.items():
                namespace = key.split(':')[0] if ':' in key else 'unknown'
                if namespace not in entries_by_namespace:
                    entries_by_namespace[namespace] = 0
                entries_by_namespace[namespace] += 1
                
                if self._is_expired(stored_time, ttl):
                    expired_count += 1
            
            return {
                'total_entries': len(self._cache),
                'expired_entries': expired_count,
                'entries_by_namespace': entries_by_namespace,
                'stats': self.get_stats()
            }


class AsyncContextCache:
    """Async wrapper for ContextCache with batch operations."""
    
    def __init__(self, cache: ContextCache):
        """Initialize with a ContextCache instance."""
        self.cache = cache
        self._lock = asyncio.Lock()
    
    async def get(self, namespace: str, key_data: Dict[str, Any]) -> Optional[Any]:
        """Async get operation."""
        async with self._lock:
            return self.cache.get(namespace, key_data)
    
    async def set(self, namespace: str, key_data: Dict[str, Any], value: Any,
                  ttl: Optional[int] = None) -> None:
        """Async set operation."""
        async with self._lock:
            self.cache.set(namespace, key_data, value, ttl)
    
    async def get_many(self, requests: list[Tuple[str, Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Get multiple values from cache.
        
        Args:
            requests: List of (namespace, key_data) tuples
            
        Returns:
            Dictionary mapping request index to cached value (None if not found)
        """
        async with self._lock:
            results = {}
            for i, (namespace, key_data) in enumerate(requests):
                results[i] = self.cache.get(namespace, key_data)
            return results
    
    async def set_many(self, items: list[Tuple[str, Dict[str, Any], Any, Optional[int]]]) -> None:
        """
        Set multiple values in cache.
        
        Args:
            items: List of (namespace, key_data, value, ttl) tuples
        """
        async with self._lock:
            for namespace, key_data, value, ttl in items:
                self.cache.set(namespace, key_data, value, ttl)
    
    async def invalidate(self, namespace: str, key_data: Optional[Dict[str, Any]] = None) -> int:
        """Async invalidate operation."""
        async with self._lock:
            return self.cache.invalidate(namespace, key_data)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics asynchronously."""
        async with self._lock:
            return self.cache.get_stats()


# Cache key builders for common operations
class CacheKeyBuilder:
    """Helper class to build standardized cache keys."""
    
    @staticmethod
    def alerts_key(agent_id: Optional[str] = None, time_range: str = "24h", 
                   level: Optional[int] = None) -> Dict[str, Any]:
        """Build cache key for alerts."""
        return {
            'agent_id': agent_id,
            'time_range': time_range,
            'level': level
        }
    
    @staticmethod
    def agent_health_key(agent_id: str) -> Dict[str, Any]:
        """Build cache key for agent health."""
        return {'agent_id': agent_id}
    
    @staticmethod
    def vulnerabilities_key(agent_id: Optional[str] = None, 
                           severity: Optional[str] = None) -> Dict[str, Any]:
        """Build cache key for vulnerabilities."""
        return {
            'agent_id': agent_id,
            'severity': severity
        }
    
    @staticmethod
    def processes_key(agent_id: str, include_children: bool = True) -> Dict[str, Any]:
        """Build cache key for processes."""
        return {
            'agent_id': agent_id,
            'include_children': include_children
        }
    
    @staticmethod
    def ports_key(agent_id: str, state: list[str] = None, 
                  protocol: list[str] = None) -> Dict[str, Any]:
        """Build cache key for ports."""
        return {
            'agent_id': agent_id,
            'state': sorted(state) if state else None,
            'protocol': sorted(protocol) if protocol else None
        }