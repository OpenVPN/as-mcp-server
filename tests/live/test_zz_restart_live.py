"""warm_restart against both real servers. The file name keeps it last: a warm
restart can make connected clients reconnect, and the stand needs about 75 seconds
before VPN clients behave as before."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError

from as_mcp_server.server import build
from as_mcp_server.settings import Settings
from as_mcp_server.texts import MSG_CANCELLED, MSG_RESTART_NEEDS_PROMPT, NOTE_RESTARTED
from tests.conftest import call_tool


async def last_restarted(mcp) -> str:
    return (await call_tool(mcp, "get_server_status"))["last_restarted"]


async def test_a_warm_restart_asks_in_automatic_mode_and_moves_the_restart_time(
    stand: tuple[str, Settings], tmp_path: Path
) -> None:
    _, settings = stand
    mcp = build(settings.model_copy(update={"write_tools": True, "approval": "auto"}))
    before = await last_restarted(mcp)

    with pytest.raises(ToolError) as error:
        await call_tool(mcp, "warm_restart", answer="none")
    assert str(error.value) == MSG_RESTART_NEEDS_PROMPT
    with pytest.raises(ToolError) as error:
        await call_tool(mcp, "warm_restart", answer="decline")
    assert str(error.value) == MSG_CANCELLED
    assert await last_restarted(mcp) == before

    seen: list[str] = []
    result = await call_tool(mcp, "warm_restart", seen=seen)
    assert seen[0].splitlines()[1] == "Action: Warm restart (1 item): Access Server"
    assert f"    last restart: {before} -> now" in seen[0].splitlines()
    (item,) = result["items"]
    assert item["outcome"] == "done", item
    assert item["before"] == {"last_restarted": before}
    assert item["after"]["last_restarted"] != before
    assert result["notes"] == [NOTE_RESTARTED] and result["approval"] == "prompt"
    assert await last_restarted(mcp) == item["after"]["last_restarted"]
