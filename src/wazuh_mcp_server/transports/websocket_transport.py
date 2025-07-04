"""
WebSocket transport for Wazuh MCP Server - Real-time remote access.
"""

import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, Set
import websockets
from websockets.server import serve
from websockets.exceptions import ConnectionClosed

from wazuh_mcp_server.main import WazuhMCPServer
from wazuh_mcp_server.utils import get_logger
from wazuh_mcp_server.__version__ import __version__

logger = get_logger(__name__)


class WebSocketTransport:
    """WebSocket transport for MCP server with real-time communication."""
    
    def __init__(self):
        self.mcp_server = None
        self.connected_clients: Set[websockets.WebSocketServerProtocol] = set()
        self.client_subscriptions: Dict[websockets.WebSocketServerProtocol, Set[str]] = {}
        
    async def initialize(self):
        """Initialize the MCP server."""
        if not self.mcp_server:
            self.mcp_server = WazuhMCPServer()
            await self.mcp_server.api_client.__aenter__()
            logger.info("MCP server initialized for WebSocket transport")
    
    async def handle_client(self, websocket, path):
        """Handle a new WebSocket client connection."""
        client_id = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        logger.info(f"New WebSocket client connected: {client_id}")
        
        self.connected_clients.add(websocket)
        self.client_subscriptions[websocket] = set()
        
        try:
            # Send welcome message
            await self.send_message(websocket, {
                "type": "welcome",
                "server_version": __version__,
                "timestamp": datetime.utcnow().isoformat(),
                "available_commands": [
                    "ping", "list_tools", "call_tool", "list_resources", 
                    "get_resource", "subscribe", "unsubscribe"
                ]
            })
            
            # Handle messages
            async for message in websocket:
                try:
                    data = json.loads(message)
                    await self.handle_message(websocket, data)
                except json.JSONDecodeError:
                    await self.send_error(websocket, "Invalid JSON message")
                except Exception as e:
                    logger.error(f"Error handling message from {client_id}: {e}")
                    await self.send_error(websocket, f"Error processing message: {str(e)}")
                    
        except ConnectionClosed:
            logger.info(f"WebSocket client disconnected: {client_id}")
        except Exception as e:
            logger.error(f"WebSocket error for client {client_id}: {e}")
        finally:
            # Cleanup
            self.connected_clients.discard(websocket)
            self.client_subscriptions.pop(websocket, None)
    
    async def handle_message(self, websocket, data: Dict[str, Any]):
        """Handle incoming WebSocket message."""
        command = data.get("command")
        request_id = data.get("id", "unknown")
        
        logger.debug(f"Handling command: {command} (id: {request_id})")
        
        try:
            if command == "ping":
                await self.send_response(websocket, request_id, {"pong": True})
            
            elif command == "list_tools":
                tools = await self.get_available_tools()
                await self.send_response(websocket, request_id, {"tools": tools})
            
            elif command == "call_tool":
                tool_name = data.get("tool_name")
                arguments = data.get("arguments", {})
                result = await self.call_tool(tool_name, arguments)
                await self.send_response(websocket, request_id, {"result": result})
            
            elif command == "list_resources":
                resources = await self.get_available_resources()
                await self.send_response(websocket, request_id, {"resources": resources})
            
            elif command == "get_resource":
                uri = data.get("uri")
                resource = await self.get_resource(uri)
                await self.send_response(websocket, request_id, {"resource": resource})
            
            elif command == "subscribe":
                subscription = data.get("subscription")
                await self.handle_subscription(websocket, subscription, True)
                await self.send_response(websocket, request_id, {"subscribed": True})
            
            elif command == "unsubscribe":
                subscription = data.get("subscription")
                await self.handle_subscription(websocket, subscription, False)
                await self.send_response(websocket, request_id, {"unsubscribed": True})
            
            else:
                await self.send_error(websocket, f"Unknown command: {command}", request_id)
                
        except Exception as e:
            logger.error(f"Error executing command {command}: {e}")
            await self.send_error(websocket, str(e), request_id)
    
    async def send_message(self, websocket, data: Dict[str, Any]):
        """Send a message to a WebSocket client."""
        try:
            message = json.dumps(data)
            await websocket.send(message)
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
    
    async def send_response(self, websocket, request_id: str, data: Dict[str, Any]):
        """Send a response to a specific request."""
        response = {
            "type": "response",
            "id": request_id,
            "timestamp": datetime.utcnow().isoformat(),
            **data
        }
        await self.send_message(websocket, response)
    
    async def send_error(self, websocket, error: str, request_id: str = None):
        """Send an error message."""
        response = {
            "type": "error",
            "error": error,
            "timestamp": datetime.utcnow().isoformat()
        }
        if request_id:
            response["id"] = request_id
        await self.send_message(websocket, response)
    
    async def broadcast(self, data: Dict[str, Any], subscription_filter: str = None):
        """Broadcast a message to all connected clients or filtered by subscription."""
        if not self.connected_clients:
            return
        
        message = {
            "type": "broadcast",
            "timestamp": datetime.utcnow().isoformat(),
            **data
        }
        
        disconnected = set()
        for websocket in self.connected_clients:
            try:
                # Check subscription filter
                if subscription_filter:
                    subscriptions = self.client_subscriptions.get(websocket, set())
                    if subscription_filter not in subscriptions:
                        continue
                
                await self.send_message(websocket, message)
            except ConnectionClosed:
                disconnected.add(websocket)
            except Exception as e:
                logger.error(f"Failed to broadcast to client: {e}")
                disconnected.add(websocket)
        
        # Clean up disconnected clients
        for websocket in disconnected:
            self.connected_clients.discard(websocket)
            self.client_subscriptions.pop(websocket, None)
    
    async def handle_subscription(self, websocket, subscription: str, subscribe: bool):
        """Handle client subscription management."""
        subscriptions = self.client_subscriptions.get(websocket, set())
        
        if subscribe:
            subscriptions.add(subscription)
            logger.info(f"Client subscribed to: {subscription}")
        else:
            subscriptions.discard(subscription)
            logger.info(f"Client unsubscribed from: {subscription}")
        
        self.client_subscriptions[websocket] = subscriptions
    
    async def get_available_tools(self):
        """Get list of available MCP tools."""
        return [
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
    
    async def get_available_resources(self):
        """Get list of available MCP resources."""
        return [
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
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]):
        """Call an MCP tool."""
        if not self.mcp_server:
            raise Exception("MCP server not initialized")
        
        # Map tool calls to MCP server methods
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
            raise Exception(f"Unknown tool: {tool_name}")
        
        result = await tool_handlers[tool_name](arguments)
        
        # Extract content from MCP result
        if isinstance(result, list) and len(result) > 0:
            content = result[0]
            if hasattr(content, 'text'):
                return content.text
            else:
                return str(content)
        else:
            return str(result)
    
    async def get_resource(self, uri: str):
        """Get an MCP resource."""
        if not self.mcp_server:
            raise Exception("MCP server not initialized")
        
        # Remove wazuh:// prefix if present
        if uri.startswith("wazuh://"):
            uri = uri[8:]
        
        # Handle different resource types
        if uri == "alerts/recent":
            result = await self.mcp_server._handle_get_alerts({"limit": 50})
        elif uri == "agents/status":
            result = await self.mcp_server._handle_get_agents({})
        elif uri == "security/overview":
            result = await self.mcp_server._handle_security_overview({})
        else:
            raise Exception(f"Unknown resource: {uri}")
        
        # Extract content
        if isinstance(result, list) and len(result) > 0:
            content = result[0]
            if hasattr(content, 'text'):
                return {"content": content.text, "mimeType": "application/json"}
            else:
                return {"content": str(content), "mimeType": "text/plain"}
        else:
            return {"content": str(result), "mimeType": "text/plain"}
    
    async def start_notification_loop(self):
        """Start background task for periodic notifications."""
        while True:
            try:
                # Send periodic updates to subscribed clients
                if self.connected_clients and self.mcp_server:
                    # Get recent alerts for subscribers
                    recent_alerts = await self.mcp_server._handle_get_alerts({"limit": 5})
                    if recent_alerts:
                        await self.broadcast({
                            "event": "alerts_update",
                            "data": "New security alerts available"
                        }, "alerts")
                
                await asyncio.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Error in notification loop: {e}")
                await asyncio.sleep(60)
    
    async def start_server(self, host: str = "0.0.0.0", port: int = 8001):
        """Start the WebSocket server."""
        try:
            await self.initialize()
            
            logger.info(f"Starting WebSocket transport on {host}:{port}")
            
            # Start notification loop
            notification_task = asyncio.create_task(self.start_notification_loop())
            
            # Start WebSocket server
            server = await serve(self.handle_client, host, port)
            
            logger.info(f"WebSocket transport ready at ws://{host}:{port}")
            logger.info("WebSocket Commands:")
            logger.info("  ping - Health check")
            logger.info("  list_tools - Get available tools")
            logger.info("  call_tool - Execute a tool")
            logger.info("  list_resources - Get available resources")
            logger.info("  get_resource - Get a resource")
            logger.info("  subscribe/unsubscribe - Manage notifications")
            
            # Keep server running
            await server.wait_closed()
            
        except Exception as e:
            logger.error(f"WebSocket server startup failed: {e}")
            raise
        finally:
            if self.mcp_server:
                await self.mcp_server.api_client.__aexit__(None, None, None)


async def run_websocket_server(host: str = "0.0.0.0", port: int = 8001):
    """Run the WebSocket transport server."""
    transport = WebSocketTransport()
    await transport.start_server(host, port)