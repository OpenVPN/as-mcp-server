"""Every tool parameter tells the agent its format and meaning in the schema itself."""

from __future__ import annotations

import json

import pytest
from fastmcp import Client

from as_mcp_server.server import build
from as_mcp_server.settings import Settings

pytestmark = pytest.mark.usefixtures("clean_env")

EXPECTED_HINTS = {
    ("get_log_reports", "since"): ["24h", "start_relative"],
    ("get_log_reports", "until"): ["end_relative"],
    ("get_log_reports", "errors_only"): ["error"],
    ("get_log_reports", "active_only"): ["still active"],
    ("get_log_reports", "search"): ["anywhere"],
    ("list_users", "usernames"): ["absent"],
    ("list_users", "group"): ["Exact group name"],
    ("list_groups", "include_members"): ["member_count"],
    ("list_groups", "group_names"): ["absent"],
    ("list_access_rulesets", "owner"): ["__DEFAULT__"],
    ("list_access_rules", "ruleset_ids"): ["list_access_rulesets"],
    ("get_status_overview", "config_names"): ["host.name", "derived_from"],
    ("login", "totp_code"): ["6-digit", "30 seconds"],
}


async def schemas() -> dict[str, dict]:
    mcp = build(Settings(url="https://as.example:943", user="u", password="p"))
    async with Client(mcp) as client:
        return {tool.name: tool.input_schema for tool in await client.list_tools()}


async def test_every_parameter_of_every_tool_has_a_description() -> None:
    missing = [
        f"{name}.{param}"
        for name, schema in (await schemas()).items()
        for param, prop in schema.get("properties", {}).items()
        if not prop.get("description", "").strip()
    ]
    assert missing == []


async def test_descriptions_carry_the_facts_an_agent_needs() -> None:
    all_schemas = await schemas()
    for (tool, param), hints in EXPECTED_HINTS.items():
        description = all_schemas[tool]["properties"][param].get("description", "")
        for hint in hints:
            assert hint in description, (tool, param, hint, description)


async def test_bounds_and_enums_survive_the_annotations() -> None:
    all_schemas = await schemas()
    logs = all_schemas["get_log_reports"]["properties"]
    assert logs["page_size"]["minimum"] == 1 and logs["page_size"]["maximum"] == 1000
    assert logs["offset"]["minimum"] == 0
    assert logs["sort"]["enum"] == ["asc", "desc"]
    assert "timestamp" in json.dumps(logs["order_by"])
    rule_type = all_schemas["list_access_rules"]["properties"]["rule_type"]
    assert "domain_routing" in json.dumps(rule_type)
    assert all_schemas["list_access_rules"]["required"] == ["ruleset_ids"]
