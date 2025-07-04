"""
HTTP transport for Wazuh MCP Server - Remote access via HTTP API.
"""

import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from aiohttp import web, ClientSession
from aiohttp.web import middleware
import aiohttp_cors

from wazuh_mcp_server.main import WazuhMCPServer
from wazuh_mcp_server.utils import get_logger
from wazuh_mcp_server.__version__ import __version__
from wazuh_mcp_server.security.auth import require_auth, rate_limit_middleware, security_manager

logger = get_logger(__name__)


class HTTPTransport:
    """HTTP transport for MCP server with REST API endpoints."""
    
    def __init__(self):
        self.mcp_server = None
        self.app = web.Application(middlewares=[
            rate_limit_middleware,
            self.error_middleware, 
            self.cors_middleware
        ])
        self.setup_routes()
        
    @middleware
    async def error_middleware(self, request, handler):
        """Global error handling middleware."""
        try:
            return await handler(request)
        except web.HTTPException:
            raise
        except Exception as e:
            logger.error(f"Unhandled error in HTTP transport: {e}")
            return web.json_response(
                {"error": "Internal server error", "details": str(e)},
                status=500
            )
    
    @middleware 
    async def cors_middleware(self, request, handler):
        """CORS middleware for cross-origin requests."""
        # Add CORS headers
        response = await handler(request)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response
        
    def setup_routes(self):
        """Setup HTTP routes for MCP operations."""
        # Public endpoints
        self.app.router.add_get('/', self.health_check)
        self.app.router.add_get('/health', self.health_check)
        self.app.router.add_post('/auth/login', self.login)
        self.app.router.add_options('/{path:.*}', self.handle_options)
        
        # Protected endpoints
        self.app.router.add_get('/tools', require_auth('user')(self.list_tools))
        self.app.router.add_post('/tools/{tool_name}/call', require_auth('user')(self.call_tool))
        self.app.router.add_get('/resources', require_auth('user')(self.list_resources))
        self.app.router.add_get('/resources/{uri}', require_auth('user')(self.get_resource))
        
        # Admin endpoints
        self.app.router.add_get('/admin/metrics', require_auth('admin')(self.get_metrics))
        
    async def handle_options(self, request):
        """Handle CORS preflight requests."""
        return web.Response(
            headers={
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization'
            }
        )
        
    async def health_check(self, request):
        """Health check endpoint."""
        try:
            if self.mcp_server:
                health_data = await self.mcp_server.api_client.health_check()
                return web.json_response({
                    "status": "healthy",
                    "version": __version__,
                    "timestamp": datetime.utcnow().isoformat(),
                    "wazuh_status": health_data
                })
            else:
                return web.json_response({
                    "status": "initializing",
                    "version": __version__,
                    "timestamp": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return web.json_response({
                "status": "unhealthy", 
                "error": str(e),
                "version": __version__,
                "timestamp": datetime.utcnow().isoformat()
            }, status=503)
    
    async def list_tools(self, request):
        """List available MCP tools."""
        try:
            if not self.mcp_server:
                return web.json_response({"error": "MCP server not initialized"}, status=503)
            
            # Get tools from the MCP server
            tools = [
                {
                    "name": "get_alerts",
                    "description": "Get security alerts from Wazuh with filtering options",
                    "parameters": {
                        "limit": {"type": "number", "description": "Maximum number of alerts to return"},
                        "level": {"type": "number", "description": "Alert severity level filter"},
                        "time_range": {"type": "number", "description": "Time range in seconds"}
                    }
                },
                {
                    "name": "get_agents", 
                    "description": "Get information about Wazuh agents",
                    "parameters": {
                        "status": {"type": "string", "description": "Agent status filter"},
                        "limit": {"type": "number", "description": "Maximum number of agents to return"}
                    }
                },
                {
                    "name": "analyze_threats",
                    "description": "Perform threat analysis on security data", 
                    "parameters": {
                        "analysis_type": {"type": "string", "description": "Type of analysis to perform"}
                    }
                },
                {
                    "name": "get_vulnerabilities",
                    "description": "Get vulnerability information for agents",
                    "parameters": {
                        "agent_id": {"type": "string", "description": "Agent ID to get vulnerabilities for"}
                    }
                },
                {
                    "name": "security_overview",
                    "description": "Get comprehensive security overview",
                    "parameters": {}
                }
            ]
            
            return web.json_response({"tools": tools})
            
        except Exception as e:
            logger.error(f"Failed to list tools: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def call_tool(self, request):
        """Call an MCP tool with parameters."""
        try:
            if not self.mcp_server:
                return web.json_response({"error": "MCP server not initialized"}, status=503)
                
            tool_name = request.match_info['tool_name']
            
            # Parse request body
            try:
                data = await request.json()
                arguments = data.get('arguments', {})
            except Exception:
                arguments = {}
            
            logger.info(f"Calling tool: {tool_name} with arguments: {arguments}")
            
            # Map HTTP tool calls to MCP server methods
            tool_handlers = {
                'get_alerts': self.mcp_server._handle_get_alerts,
                'get_agents': self.mcp_server._handle_get_agents,
                'analyze_threats': self.mcp_server._handle_analyze_threats,
                'get_vulnerabilities': self.mcp_server._handle_get_vulnerabilities,
                'security_overview': self.mcp_server._handle_security_overview,
                'get_agent_processes': self.mcp_server._handle_get_agent_processes,
                'get_agent_ports': self.mcp_server._handle_get_agent_ports,
                'get_wazuh_stats': self.mcp_server._handle_get_wazuh_stats,
                'search_wazuh_logs': self.mcp_server._handle_search_wazuh_logs,
                'get_cluster_health': self.mcp_server._handle_get_cluster_health
            }
            
            if tool_name not in tool_handlers:
                return web.json_response({
                    "error": f"Unknown tool: {tool_name}",
                    "available_tools": list(tool_handlers.keys())
                }, status=404)
            
            # Call the tool handler
            result = await tool_handlers[tool_name](arguments)
            
            # Extract text content from MCP result
            if isinstance(result, list) and len(result) > 0:
                content = result[0]
                if hasattr(content, 'text'):
                    response_data = {"result": content.text}
                else:
                    response_data = {"result": str(content)}
            else:
                response_data = {"result": str(result)}
            
            return web.json_response(response_data)
            
        except Exception as e:
            logger.error(f"Tool call failed: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def list_resources(self, request):
        """List available MCP resources."""
        try:
            resources = [
                {
                    "uri": "wazuh://alerts/recent",
                    "name": "Recent Security Alerts",
                    "description": "Latest security alerts from Wazuh",
                    "mimeType": "application/json"
                },
                {
                    "uri": "wazuh://agents/status", 
                    "name": "Agent Status Overview",
                    "description": "Current status of all Wazuh agents",
                    "mimeType": "application/json"
                },
                {
                    "uri": "wazuh://security/overview",
                    "name": "Security Overview",
                    "description": "Comprehensive security status overview", 
                    "mimeType": "application/json"
                }
            ]
            
            return web.json_response({"resources": resources})
            
        except Exception as e:
            logger.error(f"Failed to list resources: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def get_resource(self, request):
        """Get a specific MCP resource."""
        try:
            if not self.mcp_server:
                return web.json_response({"error": "MCP server not initialized"}, status=503)
                
            uri = request.match_info['uri']
            
            # Handle different resource types
            if uri == "alerts/recent":
                result = await self.mcp_server._handle_get_alerts({"limit": 50})
            elif uri == "agents/status":
                result = await self.mcp_server._handle_get_agents({})
            elif uri == "security/overview":
                result = await self.mcp_server._handle_security_overview({})
            else:
                return web.json_response({"error": f"Unknown resource: {uri}"}, status=404)
            
            # Extract content
            if isinstance(result, list) and len(result) > 0:
                content = result[0]
                if hasattr(content, 'text'):
                    response_data = {"content": content.text, "mimeType": "application/json"}
                else:
                    response_data = {"content": str(content), "mimeType": "text/plain"}
            else:
                response_data = {"content": str(result), "mimeType": "text/plain"}
            
            return web.json_response(response_data)
            
        except Exception as e:
            logger.error(f"Resource access failed: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def login(self, request):
        """Handle login requests for JWT token generation."""
        try:
            data = await request.json()
            api_key = data.get('api_key', '')
            
            if not api_key:
                return web.json_response({"error": "API key required"}, status=400)
            
            user_info = security_manager.verify_api_key(api_key)
            if not user_info:
                return web.json_response({"error": "Invalid API key"}, status=401)
            
            # Generate JWT token
            token = security_manager.generate_token(user_info['user'], user_info['role'])
            
            return web.json_response({
                "token": token,
                "user": user_info['user'],
                "role": user_info['role'],
                "expires_in": security_manager.jwt_expiry_hours * 3600
            })
            
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return web.json_response({"error": "Login failed"}, status=500)
    
    async def get_metrics(self, request):
        """Get server metrics (admin only)."""
        try:
            if not self.mcp_server:
                return web.json_response({"error": "MCP server not initialized"}, status=503)
            
            # Get metrics from MCP server
            metrics = self.mcp_server.api_client.get_metrics()
            
            # Add transport-specific metrics
            metrics.update({
                "transport": "http",
                "timestamp": datetime.utcnow().isoformat(),
                "user": getattr(request, 'user', {}).get('user', 'unknown')
            })
            
            return web.json_response({"metrics": metrics})
            
        except Exception as e:
            logger.error(f"Failed to get metrics: {e}")
            return web.json_response({"error": str(e)}, status=500)
    
    async def start_server(self, host: str = "0.0.0.0", port: int = 8000):
        """Start the HTTP server."""
        try:
            # Initialize MCP server
            self.mcp_server = WazuhMCPServer()
            await self.mcp_server.api_client.__aenter__()
            
            logger.info(f"Starting HTTP transport on {host}:{port}")
            
            # Start HTTP server
            runner = web.AppRunner(self.app)
            await runner.setup()
            site = web.TCPSite(runner, host, port)
            await site.start()
            
            logger.info(f"HTTP transport ready at http://{host}:{port}")
            logger.info("Available endpoints:")
            logger.info("  GET  /health - Health check")
            logger.info("  POST /auth/login - Get JWT token")
            logger.info("  GET  /tools - List available tools (auth required)")
            logger.info("  POST /tools/{tool_name}/call - Call a tool (auth required)")
            logger.info("  GET  /resources - List available resources (auth required)")
            logger.info("  GET  /resources/{uri} - Get a resource (auth required)")
            logger.info("  GET  /admin/metrics - Get server metrics (admin required)")
            
            # Keep server running
            while True:
                await asyncio.sleep(3600)  # Sleep for 1 hour
                
        except Exception as e:
            logger.error(f"HTTP server startup failed: {e}")
            raise
        finally:
            if self.mcp_server:
                await self.mcp_server.api_client.__aexit__(None, None, None)


async def run_http_server(host: str = "0.0.0.0", port: int = 8000):
    """Run the HTTP transport server."""
    transport = HTTPTransport()
    await transport.start_server(host, port)