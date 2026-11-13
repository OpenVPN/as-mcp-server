"""The tools released in 0.1.0 are a contract: name, description, schema, annotations.

`fixtures/contract_0_1_0.json` is the tool list of tag v0.1.0, dumped the same way as
here. A later release may add tools; it may not change these.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastmcp import Client, FastMCP

from as_mcp_server.server import build
from as_mcp_server.settings import Settings
from tests.conftest import FIXTURES

pytestmark = pytest.mark.usefixtures("clean_env")

ADDED_READ_TOOLS = ["list_access_lists", "list_connection_profiles"]


def settings(**overrides: Any) -> Settings:
    values = {"url": "https://as.example:943", "user": "u", "password": "p"}
    return Settings(**{**values, **overrides})


async def dump(mcp: FastMCP) -> list[dict[str, Any]]:
    async with Client(mcp) as client:
        tools = await client.list_tools()
    return sorted(
        (
            {
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_schema,
                "annotations": tool.annotations.model_dump(
                    by_alias=True, exclude_none=True
                )
                if tool.annotations
                else None,
            }
            for tool in tools
        ),
        key=lambda tool: tool["name"],
    )


def released() -> list[dict[str, Any]]:
    text = (FIXTURES / "contract_0_1_0.json").read_text(encoding="utf-8")
    return json.loads(text)


def test_the_frozen_contract_holds_the_thirteen_tools_of_0_1_0() -> None:
    assert len(released()) == 13


async def test_read_mode_is_the_0_1_0_tools_unchanged_plus_two_read_tools() -> None:
    tools = await dump(build(settings()))
    old = released()
    names = {tool["name"] for tool in old}
    assert [tool for tool in tools if tool["name"] in names] == old
    assert sorted(tool["name"] for tool in tools) == sorted(
        [tool["name"] for tool in old] + ADDED_READ_TOOLS
    )


async def test_the_two_added_tools_are_read_only() -> None:
    tools = {tool["name"]: tool for tool in await dump(build(settings()))}
    for name in ADDED_READ_TOOLS:
        assert tools[name]["annotations"] == {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        }, name
