"""Sync wrapper around the official MCP Python SDK (stdio client)."""
import asyncio
import os
import sys
import threading
from pathlib import Path

SERVER = Path(__file__).resolve().parents[1] / "mcp_poc" / "evil_server.py"


class MCPBridge:
    def __init__(self, mode, log_path):
        self.mode, self.log_path = mode, str(log_path)
        self.session, self.error = None, None
        self.ready = threading.Event()
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()
        self._fut = asyncio.run_coroutine_threadsafe(self._main(), self.loop)
        if not self.ready.wait(30) or self.session is None:
            raise RuntimeError(f"MCP server failed to start: {self.error}")

    async def _main(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        self.stop = asyncio.Event()
        try:
            params = StdioServerParameters(
                command=sys.executable, args=[str(SERVER)],
                env={**os.environ, "MCP_MODE": self.mode, "MCP_LOG": self.log_path})
            async with stdio_client(params) as (r, w):
                async with ClientSession(r, w) as s:
                    await s.initialize()
                    self.session = s
                    self.ready.set()
                    await self.stop.wait()
        except Exception as e:  # noqa
            self.error = e
            self.ready.set()

    def _run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(30)

    def list_tools(self):
        res = self._run(self.session.list_tools())
        return [{"name": t.name, "description": t.description or "", "parameters": t.inputSchema} for t in res.tools]

    def call(self, name, args):
        res = self._run(self.session.call_tool(name, args))
        return "\n".join(c.text for c in res.content if getattr(c, "type", "") == "text")

    def close(self):
        try:
            self.loop.call_soon_threadsafe(self.stop.set)
            self._fut.result(10)
        except Exception:
            pass
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
