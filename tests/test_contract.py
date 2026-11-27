"""The tools released in 0.1.0 are a contract: name, description, schema, annotations.

`fixtures/contract_0_1_0.json` is the tool list of tag v0.1.0, dumped the same way as
here. A later release may add tools; it may not change these.

`fixtures/contract_0_2_0_write.json` holds the thirteen write tools of 0.2.0 (commit
f150c90, dumped with `dump` below). 0.3.0 changes only update_user (a new parameter)
and update_group (deny=true now points to block_group), and adds eight write tools.
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
CHANGED_WRITE_TOOLS = {"update_user": ["remove_from_group"], "update_group": []}
ADDED_WRITE_TOOLS = [
    "assign_access_ruleset",
    "block_group",
    "delete_access_rulesets",
    "modify_access_list",
    "modify_access_rules",
    "reset_user_mfa",
    "reset_user_password",
    "save_access_ruleset",
]


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


def released_writes() -> list[dict[str, Any]]:
    text = (FIXTURES / "contract_0_2_0_write.json").read_text(encoding="utf-8")
    return json.loads(text)


def without_descriptions(schema: Any) -> Any:
    if isinstance(schema, dict):
        return {
            key: without_descriptions(value)
            for key, value in schema.items()
            if key != "description"
        }
    if isinstance(schema, list):
        return [without_descriptions(value) for value in schema]
    return schema


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


async def test_write_mode_keeps_the_fifteen_read_mode_tools_unchanged() -> None:
    read_mode = await dump(build(settings()))
    write_mode = await dump(build(settings(write_tools=True)))
    names = {tool["name"] for tool in read_mode}
    assert [tool for tool in write_mode if tool["name"] in names] == read_mode
    assert [
        tool for tool in write_mode if tool["name"] in {t["name"] for t in released()}
    ] == released()


async def test_no_write_tool_is_registered_unless_the_switch_is_on() -> None:
    for tool in await dump(build(settings())):
        assert tool["annotations"]["readOnlyHint"] is True or tool["name"] == "login"


def test_the_frozen_write_contract_holds_the_thirteen_write_tools_of_0_2_0() -> None:
    assert len(released_writes()) == 13


async def test_the_write_tools_of_0_2_0_change_only_where_0_3_0_says() -> None:
    tools = {
        tool["name"]: tool for tool in await dump(build(settings(write_tools=True)))
    }
    for old in released_writes():
        now = tools[old["name"]]
        if old["name"] not in CHANGED_WRITE_TOOLS:
            assert now == old, old["name"]
            continue
        # The descriptions may change; every parameter of 0.2.0 keeps its type.
        assert now["annotations"] == old["annotations"], old["name"]
        before = old["inputSchema"]["properties"]
        after = now["inputSchema"]["properties"]
        for param, schema in before.items():
            assert without_descriptions(after[param]) == without_descriptions(schema), (
                old["name"],
                param,
            )
        added = sorted(set(after) - set(before))
        assert added == CHANGED_WRITE_TOOLS[old["name"]], old["name"]
        assert now["inputSchema"].get("required") == old["inputSchema"].get("required")


async def test_0_3_0_adds_exactly_eight_write_tools() -> None:
    read_mode = {tool["name"] for tool in await dump(build(settings()))}
    write_mode = {
        tool["name"] for tool in await dump(build(settings(write_tools=True)))
    }
    old = {tool["name"] for tool in released_writes()}
    assert sorted(write_mode - read_mode - old) == ADDED_WRITE_TOOLS
    assert len(write_mode - read_mode) == 21
