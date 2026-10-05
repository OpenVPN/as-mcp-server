"""A rate limit on tool calls, so an agent stuck in a loop cannot flood Access Server.

The MCP specification requires servers to rate limit tool invocations. Only tool
calls count: initialize and tools/list are never refused, so a client can always
connect and read the tool list. (FastMCP 4.0.3 answers an MCP ping with "Method not
found", limit or not.) A refused call is a tool error the agent can
read and act on.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from typing import Any

from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware

TOOL_CALL_BURST = 30
TOOL_CALLS_PER_MINUTE = 30

MSG_RATE_LIMITED = (
    "This call was not run: as-mcp-server allows {per_minute} tool calls per minute "
    "(up to {burst} in a row) to protect Access Server, and that limit is reached. "
    "Wait {wait} before the next call, and fetch more per call where a tool allows "
    "it (a larger page_size, several usernames or ruleset_ids at once). If you are "
    "repeating the same call, stop and tell the user what you have so far."
)


class ToolCallLimit(Middleware):
    """Token bucket: `burst` calls at once, then `per_minute` calls per minute."""

    def __init__(
        self,
        burst: int = TOOL_CALL_BURST,
        per_minute: int = TOOL_CALLS_PER_MINUTE,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.burst = burst
        self.per_minute = per_minute
        self._per_second = per_minute / 60
        self._clock = clock
        self._tokens = float(burst)
        self._updated = clock()

    async def on_call_tool(self, context: Any, call_next: Any) -> Any:
        now = self._clock()
        self._tokens = min(
            float(self.burst), self._tokens + (now - self._updated) * self._per_second
        )
        self._updated = now
        if self._tokens < 1:
            seconds = math.ceil((1 - self._tokens) / self._per_second)
            wait = "1 second" if seconds == 1 else f"{seconds} seconds"
            raise ToolError(
                MSG_RATE_LIMITED.format(
                    per_minute=self.per_minute, burst=self.burst, wait=wait
                )
            )
        self._tokens -= 1
        return await call_next(context)
