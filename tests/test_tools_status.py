"""Status tools hit one endpoint each and pass the server's JSON through unchanged."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import Client

from as_mcp_server.client import redact
from tests.conftest import body_of, load_fixture
from tests.test_server import server_for

pytestmark = pytest.mark.usefixtures("clean_env")


@pytest.mark.parametrize(
    ("tool", "method", "path", "fixture"),
    [
        ("get_server_status", "GET", "/api/server/status", "server_status"),
        ("get_server_info", "GET", "/api/server/info", "server_info"),
        ("get_active_vpn_connections", "GET", "/api/vpn/status", "vpn_status"),
        ("get_license_info", "GET", "/api/license/info", "license_info_subscription"),
    ],
)
async def test_parameterless_tools_return_the_endpoint_body(
    tmp_path: Path, tool: str, method: str, path: str, fixture: str
) -> None:
    status, body = load_fixture(fixture)
    mcp, router = server_for(tmp_path, {(method, path): (status, body)})
    async with Client(mcp) as client:
        result = (await client.call_tool(tool, {})).structured_content
    assert result == redact(body)
    request = router.sent(method, path)[-1]
    assert request.headers["X-OpenVPN-As-AuthToken"] == "SESS_TOKEN_test"


async def test_license_info_is_passed_through_for_unlicensed_servers_too(
    tmp_path: Path,
) -> None:
    status, body = load_fixture("license_info_unlicensed")
    mcp, _ = server_for(tmp_path, {("GET", "/api/license/info"): (status, body)})
    async with Client(mcp) as client:
        result = (await client.call_tool("get_license_info", {})).structured_content
    assert result == {"licensing_type": "unlicensed", "current_cc": 0, "max_cc": 2}


async def test_status_overview_sends_an_empty_names_list_by_default(
    tmp_path: Path,
) -> None:
    status, body = load_fixture("status_overview")
    mcp, router = server_for(
        tmp_path, {("POST", "/api/helper/status-overview"): (status, body)}
    )
    async with Client(mcp) as client:
        result = (await client.call_tool("get_status_overview", {})).structured_content
    assert result == body
    assert body_of(router.sent("POST", "/api/helper/status-overview")[0]) == {
        "names": []
    }


async def test_status_overview_forwards_requested_configuration_keys(
    tmp_path: Path,
) -> None:
    status, body = load_fixture("status_overview_with_names")
    mcp, router = server_for(
        tmp_path, {("POST", "/api/helper/status-overview"): (status, body)}
    )
    async with Client(mcp) as client:
        result = (
            await client.call_tool(
                "get_status_overview",
                {"config_names": ["host.name", "vpn.server.daemon.enable"]},
            )
        ).structured_content
    assert result["configuration_items"]["total"] == 2
    assert body_of(router.sent("POST", "/api/helper/status-overview")[0]) == {
        "names": ["host.name", "vpn.server.daemon.enable"]
    }


async def test_only_status_overview_takes_a_parameter_and_it_is_optional(
    tmp_path: Path,
) -> None:
    mcp, _ = server_for(tmp_path, {})
    async with Client(mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    for name in (
        "get_server_status",
        "get_server_info",
        "get_active_vpn_connections",
        "get_license_info",
    ):
        assert tools[name].input_schema.get("properties", {}) == {}, name
    assert set(tools["get_status_overview"].input_schema["properties"]) == {
        "config_names"
    }
    assert "required" not in tools["get_status_overview"].input_schema
