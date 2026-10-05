"""Rulesets name what is assigned to whom.

Rules carry the destinations and actions.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from tests.conftest import body_of, load_fixture
from tests.test_server import server_for

pytestmark = pytest.mark.usefixtures("clean_env")
RULESETS = ("POST", "/api/access/rulesets/list")
RULES = ("POST", "/api/access/rules/list")


async def test_rulesets_without_owner_asks_for_everything(tmp_path: Path) -> None:
    mcp, router = server_for(tmp_path, {RULESETS: load_fixture("access_rulesets_all")})
    async with Client(mcp) as client:
        result = (await client.call_tool("list_access_rulesets", {})).structured_content
    assert body_of(router.sent(*RULESETS)[0]) == {}
    assert result["rulesets"][0] == {
        "owner": "staff",
        "owner_type": "group",
        "id": 1,
        "name": "Staff web",
        "position": 100,
        "comment": "dev-stand fixture",
    }


async def test_rulesets_owner_and_name_filter_are_forwarded(tmp_path: Path) -> None:
    mcp, router = server_for(
        tmp_path, {RULESETS: load_fixture("access_rulesets_staff")}
    )
    async with Client(mcp) as client:
        await client.call_tool(
            "list_access_rulesets", {"owner": "staff", "name_contains": "web"}
        )
        await client.call_tool("list_access_rulesets", {"owner": "__DEFAULT__"})
    first, second = (body_of(r) for r in router.sent(*RULESETS))
    assert first == {
        "owner": "staff",
        "filters": {"name": {"operation": "substring", "value": "web"}},
    }
    assert second == {"owner": "__DEFAULT__"}


async def test_the_documented_DEFAULT_owner_error_reaches_the_agent(
    tmp_path: Path,
) -> None:
    mcp, _ = server_for(tmp_path, {RULESETS: load_fixture("error_bad_owner_400")})
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="Non-existent ruleset owner: DEFAULT"):
            await client.call_tool("list_access_rulesets", {"owner": "DEFAULT"})


async def test_rules_require_ids_and_forward_filters(tmp_path: Path) -> None:
    mcp, router = server_for(
        tmp_path,
        {
            RULES: [
                load_fixture("access_rules"),
                load_fixture("access_rules_filter_type"),
            ]
        },
    )
    async with Client(mcp) as client:
        rules = (
            await client.call_tool("list_access_rules", {"ruleset_ids": [1]})
        ).structured_content
        filtered = (
            await client.call_tool(
                "list_access_rules",
                {
                    "ruleset_ids": [1, 2],
                    "rule_type": "domain_routing",
                    "match_data_contains": "intranet",
                },
            )
        ).structured_content
    first, second = (body_of(r) for r in router.sent(*RULES))
    assert first == {"ruleset_ids": [1]}
    assert second == {
        "ruleset_ids": [1, 2],
        "filters": {
            "type": {"operation": "equal", "value": "domain_routing"},
            "match_data": {"operation": "substring", "value": "intranet"},
        },
    }
    assert [r["match_data"] for r in rules["rules"]] == [
        "intranet.example.com",
        "blocked.example.com",
    ]
    assert rules["rules"][1]["action"] == "deny"
    assert filtered["rules"][0]["match_data"] == "intranet.example.com"


async def test_an_empty_id_list_is_refused_locally(tmp_path: Path) -> None:
    mcp, router = server_for(tmp_path, {})
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="ruleset_ids must contain at least one id"):
            await client.call_tool("list_access_rules", {"ruleset_ids": []})
    assert router.sent(*RULES) == []


async def test_an_unknown_ruleset_id_is_the_servers_400_text(tmp_path: Path) -> None:
    mcp, _ = server_for(tmp_path, {RULES: load_fixture("error_bad_ruleset_400")})
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="Non-existent ruleset: 999999"):
            await client.call_tool("list_access_rules", {"ruleset_ids": [999999]})
