"""Write-mode tool that restarts Access Server: `warm_restart`.

Decided on 2026-11-18: no write tool restarts the server by itself. The
administrator asks for the restart and approves it, also in automatic approval
mode. Measured on 3.1.0 and 3.2.4: `POST /server/restart?restartMode=warm` answers
200 `{}`, makes a group created since the last restart accept its members, and
answers 400 when the firewall configuration has errors. A connected client can be
told to reconnect by a warm restart.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError

from as_mcp_server.client import AccessServerClient
from as_mcp_server.preview import PreviewItem
from as_mcp_server.texts import MSG_RESTART_NEEDS_PROMPT, NOTE_RESTARTED
from as_mcp_server.writes import (
    DESTRUCTIVE,
    RESULT_HELP,
    Own,
    Partial,
    Plan,
    WriteDeps,
    run_write,
)

TOOLS = ("warm_restart",)
TARGET = "Access Server"
RESTART = "/server/restart?restartMode=warm"
RESTART_TIMEOUT = 120.0
# How long to wait for /server/status to show the new restart time.
SETTLE_POLLS = 10
POLL_SECONDS = 1.0


async def _last_restarted(client: AccessServerClient) -> Any:
    status = await client.get("/server/status")
    if not isinstance(status, dict) or "last_restarted" not in status:
        raise ToolError("Access Server did not return the time of its last restart.")
    return status["last_restarted"]


async def _client_count(client: AccessServerClient) -> int:
    status = await client.get("/vpn/status")
    clients = status.get("vpn_clients") if isinstance(status, dict) else None
    if not isinstance(clients, list):
        raise ToolError("Access Server returned no list of VPN sessions.")
    return len(clients)


@dataclass
class _WarmRestart:
    tool: str = "warm_restart"
    action: str = "Warm restart"
    note: str = NOTE_RESTARTED
    needs_output_dir: bool = False
    always_ask: bool = True
    msg_no_elicitation: str = MSG_RESTART_NEEDS_PROMPT
    _clients: int = 0
    _before: Any = None

    def key(self, item: str) -> str:
        return item

    def target(self, item: str) -> str:
        return item

    async def read(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        # The number of clients is shown, not compared: it changes by itself.
        self._clients = await _client_count(client)
        return {"last_restarted": await _last_restarted(client)}

    def plan(self, item: str, before: dict[str, Any], own: Own) -> Plan:
        self._before = before["last_restarted"]
        return Plan(
            PreviewItem(
                item,
                {"last restart": (self._before, "now")},
                (
                    f"{self._clients} connected VPN client(s) can be disconnected "
                    "and have to reconnect",
                    "groups created since the last restart start to work",
                ),
            )
        )

    async def apply(
        self, client: AccessServerClient, item: str, before: dict[str, Any]
    ) -> dict[str, Any]:
        await client.post(RESTART, timeout=RESTART_TIMEOUT)
        return {"clients_connected_before": self._clients}

    async def verify(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        for attempt in range(SETTLE_POLLS):
            if attempt:
                await asyncio.sleep(POLL_SECONDS)
            try:
                now = await _last_restarted(client)
            except ToolError:
                continue
            if now != self._before:
                return {"last_restarted": now}
        raise Partial(
            ["restart requested"],
            "Access Server accepted the restart but does not show a new restart "
            "time; check get_server_status before asking again",
        )


def register_restart_tools(mcp: FastMCP, deps: WriteDeps) -> None:
    @mcp.tool(
        name="warm_restart",
        description=(
            "Warm restart of Access Server, so that changes that wait for a "
            "restart take effect: a group created since the last restart starts "
            "to accept the VPN connections of its members, and a user moved to "
            "another group gets everything from that group. Call it only when "
            "the user asks for a restart, or agrees after a tool said one is "
            "needed; never decide it yourself and never call it after every "
            "change. The administrator is always asked for approval, also in "
            "automatic approval mode; an app that cannot show the approval "
            "prompt cannot restart. Connected VPN clients can be disconnected "
            "and have to reconnect; the approval question says how many are "
            "connected. No parameters." + RESULT_HELP
        ),
        annotations=DESTRUCTIVE,
        tags={"write"},
    )
    async def warm_restart(ctx: Context) -> Any:
        return await run_write(ctx, deps, _WarmRestart(), [TARGET], {})
