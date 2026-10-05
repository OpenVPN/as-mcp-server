"""The tool-call rate limit: a token bucket, measured with a fake clock."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from as_mcp_server.limits import TOOL_CALL_BURST, TOOL_CALLS_PER_MINUTE, ToolCallLimit
from as_mcp_server.server import build
from as_mcp_server.settings import Settings
from tests.conftest import LOGIN, Router, load_fixture

SERVER_INFO = ("GET", "/api/server/info")


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def limited_server(tmp_path: Path, burst: int, per_minute: int):
    clock = FakeClock()
    router = Router(
        {LOGIN: load_fixture("login_ok"), SERVER_INFO: load_fixture("server_info")}
    )
    settings = Settings(
        url="https://as.example:943",
        user="openvpn",
        password="limit-test-password",
        config_dir=tmp_path,
    )
    limit = ToolCallLimit(burst=burst, per_minute=per_minute, clock=clock)
    mcp = build(settings, transport=router.transport(), limit=limit)
    return mcp, router, clock


def info_requests(router: Router) -> int:
    return sum(r.url.path == SERVER_INFO[1] for r in router.requests)


async def test_calls_past_the_burst_are_refused_without_reaching_access_server(
    tmp_path: Path,
) -> None:
    mcp, router, _clock = limited_server(tmp_path, burst=3, per_minute=30)
    async with Client(mcp) as client:
        for _ in range(3):
            await client.call_tool("get_server_info", {})
        with pytest.raises(ToolError) as refused:
            await client.call_tool("get_server_info", {})
    assert info_requests(router) == 3
    text = str(refused.value)
    assert text.startswith("This call was not run")
    assert "30 tool calls per minute (up to 3 in a row)" in text
    assert "Wait 2 seconds" in text and "page_size" in text
    assert "stop and tell the user" in text


async def test_the_bucket_refills_at_the_per_minute_rate(tmp_path: Path) -> None:
    mcp, router, clock = limited_server(tmp_path, burst=1, per_minute=30)
    async with Client(mcp) as client:
        await client.call_tool("get_server_info", {})
        clock.now += 1.5
        with pytest.raises(ToolError, match="Wait 1 second before"):
            await client.call_tool("get_server_info", {})
        clock.now += 0.5
        await client.call_tool("get_server_info", {})
    assert info_requests(router) == 2


async def test_the_wait_it_names_is_enough(tmp_path: Path) -> None:
    mcp, _router, clock = limited_server(tmp_path, burst=1, per_minute=6)
    async with Client(mcp) as client:
        await client.call_tool("get_server_info", {})
        clock.now += 3
        with pytest.raises(ToolError, match="Wait 7 seconds"):
            await client.call_tool("get_server_info", {})
        clock.now += 7
        await client.call_tool("get_server_info", {})


async def test_idle_time_saves_up_no_more_than_the_burst(tmp_path: Path) -> None:
    mcp, _router, clock = limited_server(tmp_path, burst=2, per_minute=30)
    clock.now += 3600
    async with Client(mcp) as client:
        for _ in range(2):
            await client.call_tool("get_server_info", {})
        with pytest.raises(ToolError):
            await client.call_tool("get_server_info", {})


async def test_listing_tools_is_never_refused(tmp_path: Path) -> None:
    mcp, _router, _clock = limited_server(tmp_path, burst=1, per_minute=30)
    async with Client(mcp) as client:
        await client.call_tool("get_server_info", {})
        for _ in range(5):
            assert await client.list_tools()
        with pytest.raises(ToolError):
            await client.call_tool("connection_info", {})


def test_the_server_is_built_with_the_default_limit(tmp_path: Path) -> None:
    mcp = build(Settings(url="https://as.example:943", config_dir=tmp_path))
    limits = [m for m in mcp.middleware if isinstance(m, ToolCallLimit)]
    assert [(m.burst, m.per_minute) for m in limits] == [
        (TOOL_CALL_BURST, TOOL_CALLS_PER_MINUTE)
    ]
    assert (TOOL_CALL_BURST, TOOL_CALLS_PER_MINUTE) == (30, 30)
