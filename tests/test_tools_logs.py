"""get_log_reports turns typed parameters into the log/reports filter grammar.

The grammar was measured on real servers.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from tests.conftest import body_of, load_fixture
from tests.test_server import server_for

pytestmark = pytest.mark.usefixtures("clean_env")
LOGS = ("POST", "/api/log/reports")


async def call_logs(tmp_path: Path, arguments: dict, fixture: str = "log_reports"):
    mcp, router = server_for(tmp_path, {LOGS: load_fixture(fixture)})
    async with Client(mcp) as client:
        result = (
            await client.call_tool("get_log_reports", arguments)
        ).structured_content
    return result, body_of(router.sent(*LOGS)[0])


async def test_defaults_are_the_latest_50_records_newest_first(tmp_path: Path) -> None:
    result, sent = await call_logs(tmp_path, {})
    assert sent == {
        "page_size": 50,
        "offset": 0,
        "order_by": "timestamp",
        "sort_by": "desc",
    }
    _status, body = load_fixture("log_reports")
    assert result == body  # passthrough: 5 records requested out of the server's 88
    assert len(result["records"]) == 5 and result["total"] == 88


async def test_every_filter_maps_to_the_documented_and_measured_grammar(
    tmp_path: Path,
) -> None:
    _, sent = await call_logs(
        tmp_path,
        {
            "page_size": 10,
            "offset": 20,
            "username": "ali",
            "since": "24h",
            "until": "1m",
            "errors_only": True,
            "active_only": True,
            "search": "vpn",
            "order_by": "username",
            "sort": "asc",
        },
    )
    assert sent == {
        "page_size": 10,
        "offset": 20,
        "order_by": "username",
        "sort_by": "asc",
        "filters": {
            "username": {"operation": "substring", "value": "ali"},
            "timestamp": {"start_relative": "24h", "end_relative": "1m"},
            "error": {"operation": "not_equal", "value": ""},
            "active": {"value": True},
            "anywhere": {
                "value": "vpn",
                "fields": [
                    "username",
                    "node",
                    "service",
                    "error",
                    "platform",
                    "version",
                    "gui_version",
                ],
            },
        },
    }


async def test_only_since_produces_an_open_ended_window(tmp_path: Path) -> None:
    _, sent = await call_logs(tmp_path, {"since": "7d"}, "log_reports_filter_time")
    assert sent["filters"] == {"timestamp": {"start_relative": "7d"}}


async def test_the_servers_validation_error_for_a_bad_duration_reaches_the_agent(
    tmp_path: Path,
) -> None:
    bad = (
        400,
        {
            "reason": "Request failed",
            "detail": {
                "filters.timestamp": (
                    "Value error, value must match pattern: digits followed by a "
                    "letter [smhdwMy], such as 2d"
                )
            },
        },
    )
    mcp, _ = server_for(tmp_path, {LOGS: bad})
    async with Client(mcp) as client:
        with pytest.raises(
            ToolError,
            match=r"filters\.timestamp: Value error, value must match pattern",
        ):
            await client.call_tool("get_log_reports", {"since": "1 hour"})


@pytest.mark.parametrize(
    "arguments", [{"page_size": 0}, {"page_size": 1001}, {"offset": -1}]
)
async def test_out_of_range_paging_is_refused_without_a_request(
    tmp_path: Path, arguments: dict
) -> None:
    mcp, router = server_for(tmp_path, {})
    async with Client(mcp) as client:
        with pytest.raises(ToolError):
            await client.call_tool("get_log_reports", arguments)
    assert router.sent(*LOGS) == []
