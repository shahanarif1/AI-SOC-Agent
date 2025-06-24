"""Production-grade Wazuh Indexer API client for querying alerts and vulnerabilities."""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from urllib.parse import urljoin
import aiohttp
import json

from ..config import WazuhConfig
from ..utils.exceptions import (
    AuthenticationError, AuthorizationError, ConnectionError,
    APIError, RateLimitError, handle_api_error, handle_connection_error
)
from ..utils.logging import get_logger, log_performance, LogContext
from ..utils.rate_limiter import global_rate_limiter, RateLimitConfig
from ..utils.validation import validate_alert_query, sanitize_string
from ..utils.production_error_handler import production_error_handler
from .wazuh_field_mappings import WazuhFieldMapper, WazuhVersion

logger = get_logger(__name__)


class WazuhIndexerClient:
    """Production-grade client for Wazuh Indexer (OpenSearch/Elasticsearch) API."""
    
    def __init__(self, config: WazuhConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Use indexer settings if available, otherwise fallback to server settings
        self.host = getattr(config, 'indexer_host', config.host)
        self.port = getattr(config, 'indexer_port', 9200)
        self.username = getattr(config, 'indexer_username', config.username)
        self.password = getattr(config, 'indexer_password', config.password)
        self.verify_ssl = getattr(config, 'indexer_verify_ssl', config.verify_ssl)
        
        self.base_url = f"https://{self.host}:{self.port}"
        
        # Initialize field mapper for schema compatibility
        wazuh_version = getattr(config, 'wazuh_version', None)
        if wazuh_version and wazuh_version.startswith('4.8'):
            self.field_mapper = WazuhFieldMapper(WazuhVersion.V4_8_X)
        elif wazuh_version and wazuh_version.startswith('4.9'):
            self.field_mapper = WazuhFieldMapper(WazuhVersion.V4_9_X)
        else:
            self.field_mapper = WazuhFieldMapper(WazuhVersion.V4_8_X)  # Default to 4.8.x
        
        # Configure rate limiting for indexer
        global_rate_limiter.configure_endpoint(
            "wazuh_indexer", 
            RateLimitConfig(max_requests=200, time_window=60)  # 200 requests per minute
        )
        
        # Performance and health metrics
        self.request_count = 0
        self.error_count = 0
        self.last_successful_request = None
        self.connection_pool_stats = {}
        
        # SSL/TLS configuration validation
        self._validate_ssl_config()
        
        logger.info(f"Initialized production Wazuh Indexer client for {self.host}:{self.port}", extra={
            "details": {
                "verify_ssl": self.verify_ssl,
                "field_mapper_version": self.field_mapper.version.value,
                "base_url": self.base_url
            }
        })
    
    def _validate_ssl_config(self):
        """Validate SSL/TLS configuration for production."""
        if not self.verify_ssl:
            logger.warning("SSL verification disabled for Indexer API - not recommended for production", extra={
                "details": {
                    "host": self.host,
                    "port": self.port,
                    "security_risk": "high"
                }
            })
        
        # Check for localhost/internal networks with SSL disabled
        if not self.verify_ssl and not (
            self.host in ['localhost', '127.0.0.1'] or 
            self.host.startswith('192.168.') or
            self.host.startswith('10.') or
            self.host.startswith('172.')
        ):
            logger.error("SSL verification disabled for external host - critical security risk", extra={
                "details": {
                    "host": self.host,
                    "recommendation": "Enable SSL verification for external hosts"
                }
            })
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self._create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with proper cleanup."""
        if self.session:
            await self.session.close()
            logger.debug("Wazuh Indexer client session closed")
    
    async def _create_session(self):
        """Create aiohttp session with proper configuration."""
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout_seconds)
        connector = aiohttp.TCPConnector(
            ssl=self.verify_ssl,
            limit=self.config.max_connections,
            limit_per_host=self.config.pool_size,
            keepalive_timeout=60,
            enable_cleanup_closed=True
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "WazuhMCP/2.1.0"},
            auth=aiohttp.BasicAuth(self.username, self.password)
        )
        
        logger.debug("Created Wazuh Indexer session with optimized settings")
    
    async def _request(
        self, 
        method: str, 
        endpoint: str, 
        data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make authenticated request to Wazuh Indexer with production error handling."""
        
        async def _make_request() -> Dict[str, Any]:
            # Rate limit requests
            await global_rate_limiter.enforce_rate_limit("wazuh_indexer")
            
            url = urljoin(self.base_url, endpoint)
            request_id = f"indexer_req_{int(time.time() * 1000)}"
            
            with LogContext(request_id):
                logger.debug(f"Making {method} request to {endpoint}", extra={
                    "details": {"endpoint": endpoint, "has_data": data is not None}
                })
                
                kwargs = {
                    "headers": {
                        "Content-Type": "application/json",
                        "User-Agent": "WazuhMCP-Indexer/2.1.0"
                    }
                }
                if data:
                    kwargs["json"] = data
                
                start_time = time.time()
                
                async with self.session.request(method, url, **kwargs) as response:
                    self.request_count += 1
                    response_time = time.time() - start_time
                    
                    # Log performance metrics
                    logger.debug(f"Indexer request completed", extra={
                        "details": {
                            "status": response.status,
                            "response_time_ms": round(response_time * 1000, 2),
                            "endpoint": endpoint
                        }
                    })
                    
                    if response.status not in [200, 201]:
                        response_data = None
                        try:
                            response_data = await response.json()
                        except:
                            # Try to get text response for better error details
                            try:
                                response_text = await response.text()
                                response_data = {"error": response_text}
                            except:
                                response_data = {"error": f"HTTP {response.status}"}
                        
                        # Enhanced error logging for production
                        logger.error(f"Indexer API error: {response.status}", extra={
                            "details": {
                                "status": response.status,
                                "endpoint": endpoint,
                                "response_data": response_data,
                                "headers": dict(response.headers)
                            }
                        })
                        
                        handle_api_error(response.status, response_data)
                    
                    result = await response.json()
                    self.last_successful_request = datetime.utcnow()
                    
                    # Validate response structure
                    self._validate_response_structure(result, endpoint)
                    
                    return result
        
        # Use production error handler with retry logic
        return await production_error_handler.execute_with_retry(
            _make_request,
            f"indexer_{method.lower()}",
            "indexer",
            endpoint
        )
    
    def _validate_response_structure(self, response: Dict[str, Any], endpoint: str):
        """Validate Indexer API response structure for production compatibility."""
        if "_search" in endpoint:
            # Validate search response structure
            if "hits" not in response:
                logger.warning(f"Unexpected search response structure: missing 'hits'", extra={
                    "details": {
                        "endpoint": endpoint,
                        "response_keys": list(response.keys())
                    }
                })
            elif "total" not in response.get("hits", {}):
                logger.warning(f"Search response missing total count", extra={
                    "details": {"endpoint": endpoint}
                })
        elif "_cluster/health" in endpoint:
            # Validate cluster health response
            expected_fields = ["status", "cluster_name", "number_of_nodes"]
            missing_fields = [field for field in expected_fields if field not in response]
            if missing_fields:
                logger.warning(f"Cluster health response missing fields: {missing_fields}", extra={
                    "details": {"endpoint": endpoint}
                })
    
    @log_performance
    async def search_alerts(
        self, 
        limit: int = 100, 
        offset: int = 0,
        level: Optional[int] = None, 
        sort: str = "-timestamp",
        time_range: Optional[int] = None,
        agent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Search alerts in Wazuh Indexer with production-grade field mapping."""
        
        # Use field mapper for proper index pattern
        index_pattern = self.field_mapper.get_index_pattern("alerts")
        
        # Map sort field using field mapper
        mapped_sort_field = self.field_mapper.get_sort_field(sort)
        sort_field, sort_order = (mapped_sort_field[1:], "desc") if mapped_sort_field.startswith("-") else (mapped_sort_field, "asc")
        
        # Build production-grade Elasticsearch query
        query = {
            "size": min(limit, self.config.max_alerts_per_query),
            "from": offset,
            "sort": [
                {
                    sort_field: {
                        "order": sort_order,
                        "unmapped_type": "date" if "timestamp" in sort_field else "keyword"
                    }
                }
            ],
            "query": {
                "bool": {
                    "must": [],
                    "filter": []
                }
            },
            "_source": {
                "excludes": ["full_log"]  # Exclude large fields for performance
            }
        }
        
        # Add filters using field mapper
        if level is not None:
            rule_level_field = self.field_mapper.map_server_to_indexer_field("rule.level", "alert")
            query["query"]["bool"]["filter"].append({
                "term": {rule_level_field: level}
            })
        
        if time_range:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(seconds=time_range)
            timestamp_field = self.field_mapper.map_server_to_indexer_field("timestamp", "alert")
            query["query"]["bool"]["filter"].append({
                "range": {
                    timestamp_field: {
                        "gte": start_time.isoformat() + "Z",
                        "lte": end_time.isoformat() + "Z",
                        "format": "strict_date_optional_time"
                    }
                }
            })
        
        if agent_id:
            clean_agent_id = sanitize_string(agent_id, 20)
            agent_id_field = self.field_mapper.map_server_to_indexer_field("agent.id", "alert")
            query["query"]["bool"]["filter"].append({
                "term": {f"{agent_id_field}.keyword": clean_agent_id}  # Use keyword field for exact match
            })
        
        # If no filters, use match_all with basic performance optimization
        if not query["query"]["bool"]["must"] and not query["query"]["bool"]["filter"]:
            query["query"] = {
                "match_all": {},
                "boost": 1.0
            }
        
        # Add aggregations for monitoring and debugging
        query["aggs"] = {
            "rule_levels": {
                "terms": {
                    "field": "rule.level",
                    "size": 10
                }
            },
            "top_agents": {
                "terms": {
                    "field": "agent.name.keyword",
                    "size": 5
                }
            }
        }
        
        logger.info(f"Searching alerts in Indexer", extra={
            "details": {
                "index_pattern": index_pattern,
                "limit": limit,
                "level": level, 
                "agent_id": agent_id,
                "sort_field": sort_field,
                "query_size": len(str(query))
            }
        })
        
        result = await self._request("POST", f"/{index_pattern}/_search", data=query)
        
        # Validate result before transformation
        issues = self._validate_alert_response(result)
        if issues:
            logger.warning(f"Alert response validation issues: {issues}")
        
        # Transform to match Server API format
        return self._transform_alerts_response(result)
    
    def _validate_alert_response(self, response: Dict[str, Any]) -> List[str]:
        """Validate alert search response using field mapper."""
        return self.field_mapper.validate_field_compatibility(
            response.get("hits", {}).get("hits", [{}])[0].get("_source", {}),
            "alert"
        )
    
    @log_performance
    async def search_vulnerabilities(
        self, 
        agent_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Search vulnerabilities in Wazuh Indexer."""
        
        query = {
            "size": min(limit, 1000),
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ],
            "query": {
                "bool": {
                    "must": []
                }
            }
        }
        
        # Add filters
        if agent_id:
            clean_agent_id = sanitize_string(agent_id, 20)
            query["query"]["bool"]["must"].append({
                "term": {"agent.id": clean_agent_id}
            })
        
        if cve_id:
            clean_cve_id = sanitize_string(cve_id, 50)
            query["query"]["bool"]["must"].append({
                "term": {"vulnerability.id": clean_cve_id}
            })
        
        # If no filters, match all
        if not query["query"]["bool"]["must"]:
            query["query"] = {"match_all": {}}
        
        logger.info(f"Searching vulnerabilities in Indexer", extra={
            "details": {"agent_id": agent_id, "cve_id": cve_id, "limit": limit}
        })
        
        result = await self._request("POST", "/wazuh-states-vulnerabilities*/_search", data=query)
        
        # Transform to match Server API format
        return self._transform_vulnerabilities_response(result)
    
    def _transform_alerts_response(self, indexer_response: Dict[str, Any]) -> Dict[str, Any]:
        """Transform Indexer response to match Server API format."""
        hits = indexer_response.get("hits", {})
        total = hits.get("total", {})
        
        # Handle different total formats
        total_count = total.get("value", 0) if isinstance(total, dict) else total
        
        alerts = []
        for hit in hits.get("hits", []):
            source = hit.get("_source", {})
            alerts.append(source)
        
        return {
            "data": {
                "affected_items": alerts,
                "total_affected_items": total_count,
                "total_failed_items": 0,
                "failed_items": []
            },
            "message": "Alerts retrieved successfully from Indexer",
            "error": 0
        }
    
    def _transform_vulnerabilities_response(self, indexer_response: Dict[str, Any]) -> Dict[str, Any]:
        """Transform vulnerabilities response to match Server API format."""
        hits = indexer_response.get("hits", {})
        total = hits.get("total", {})
        
        # Handle different total formats
        total_count = total.get("value", 0) if isinstance(total, dict) else total
        
        vulnerabilities = []
        for hit in hits.get("hits", []):
            source = hit.get("_source", {})
            vulnerabilities.append(source)
        
        return {
            "data": {
                "affected_items": vulnerabilities,
                "total_affected_items": total_count,
                "total_failed_items": 0,
                "failed_items": []
            },
            "message": "Vulnerabilities retrieved successfully from Indexer",
            "error": 0
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of Wazuh Indexer."""
        try:
            result = await self._request("GET", "/_cluster/health")
            
            health_data = {
                "status": "healthy" if result.get("status") in ["green", "yellow"] else "unhealthy",
                "cluster_name": result.get("cluster_name", "unknown"),
                "cluster_status": result.get("status", "unknown"),
                "number_of_nodes": result.get("number_of_nodes", 0),
                "client_stats": {
                    "total_requests": self.request_count,
                    "error_count": self.error_count,
                    "error_rate_percentage": round((self.error_count / max(self.request_count, 1)) * 100, 2)
                },
                "last_check": datetime.utcnow().isoformat()
            }
            
            logger.info("Indexer health check passed", extra={"details": health_data})
            return health_data
            
        except Exception as e:
            health_data = {
                "status": "unhealthy",
                "error": str(e),
                "client_stats": {
                    "total_requests": self.request_count,
                    "error_count": self.error_count
                },
                "last_check": datetime.utcnow().isoformat()
            }
            
            logger.error("Indexer health check failed", extra={"details": health_data})
            return health_data
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get client performance metrics."""
        return {
            "total_requests": self.request_count,
            "error_count": self.error_count,
            "error_rate": (self.error_count / max(self.request_count, 1)) * 100,
            "base_url": self.base_url
        }