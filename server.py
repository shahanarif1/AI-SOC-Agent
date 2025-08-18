import asyncio
import sys
import json
from typing import Optional
from contextlib import AsyncExitStack
from dotenv import load_dotenv

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from langchain_core.messages import HumanMessage, ToolMessage
from langchain_ollama import ChatOllama

load_dotenv()

# --- Fix booleans from string JSON ---
def fix_booleans(obj):
    if isinstance(obj, dict):
        return {k: fix_booleans(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [fix_booleans(v) for v in obj]
    elif isinstance(obj, str):
        lowered = obj.lower()
        if lowered == 'true':
            return True
        elif lowered == 'false':
            return False
    return obj

# Monkey-patch builtins (safety net)
import builtins
builtins.false = False
builtins.true = True

class MCPClient:
    def __init__(self):
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.deepseek = ChatOllama(
            model="deepseek-r1:1.5b",
            temperature=0.6,
            streaming=False
        )

    async def connect_to_server(self, server_script_path: str):
        is_python = server_script_path.endswith('.py')
        is_js = server_script_path.endswith('.js')
        if not (is_python or is_js):
            raise ValueError("Server script must be a .py or .js file")

        command = "python" if is_python else "node"
        server_params = StdioServerParameters(
            command=command,
            args=[server_script_path],
            env=None
        )

        stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
        self.stdio, self.write = stdio_transport
        self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))

        print("Connecting to MCP server...")
        await self.session.initialize()

        response = await self.session.list_resources()
        print(f"Available resources: {[r.uri for r in response.resources]}")
        print("Connected to server with resources:", [r.name for r in response.resources])

    async def process_query(self, query: str) -> str:
        messages = [HumanMessage(content=query)]

        print("Fetching and converting MCP resources to tools...")
        # self.session.list_resources()
        response = await self.session.list_resources()
        returned_data = await self.session.read_resource(response.resources[1].uri)
        print(f"Returned data: {returned_data.contents}")
           
        response = await self.session.read_resource(response.resources[1].uri)
        if response:
            content = response.contents
            print(f"Returned content is : {content[0]}")
            data = content[0]
         
            print("Reinvoking DeepSeek with resource results...")
            response = self.deepseek.invoke(
                input=messages,
                config={"tools": data, "streaming": False}
            )

        return "\n".join(final_text)

    async def chat_loop(self):
        print("Type your query (Ctrl+C to exit):")
        try:
            while True:
                query = input("> ")
                result = await self.process_query(query)
                print(result)
        except (KeyboardInterrupt, EOFError):
            print("\nExiting chat.")

    async def cleanup(self):
        await self.exit_stack.aclose()

async def main():
    if len(sys.argv) < 2:
        print("Usage: python server.py <path_to_mcp_server_script>")
        sys.exit(1)

    client = MCPClient()
    try:
        await client.connect_to_server(sys.argv[1])
        await client.chat_loop()
    finally:
        await client.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
