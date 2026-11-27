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
    ("list_connection_profiles", "username"): ["Exact", "equal"],
    ("list_connection_profiles", "autologin_only"): ["without a password"],
    ("list_access_lists", "usernames"): ["absent"],
    ("list_access_lists", "group_names"): ["absent"],
    ("create_connection_profile", "usernames"): ["case-sensitive", "not a group"],
    ("create_connection_profile", "profile_type"): ["without a password"],
    ("create_connection_profile", "comment"): ["200"],
    ("create_profile_download_link", "lifetime_seconds"): ["86400", "604800"],
    ("create_profile_download_link", "usages"): ["at most 5"],
    ("delete_connection_profiles", "serials"): ["string", "not a", "100"],
    ("delete_connection_profiles", "username"): ["case-sensitive", "every profile"],
    ("block_user", "usernames"): ["case-sensitive", "not a group"],
    ("disconnect_vpn_sessions", "usernames"): ["case-sensitive", "every running"],
    ("disconnect_vpn_sessions", "sessions"): ["daemon_id", "client_id"],
    ("disconnect_vpn_sessions", "reason"): ["log", "does not see"],
    ("create_user", "users"): ["up to 100"],
    ("update_user", "usernames"): ["case-sensitive", "not a group"],
    ("update_user", "deny"): ["block_user", "false unblocks"],
    ("update_user", "group"): ["existing group", "restart"],
    ("update_user", "admin"): ["automatic approval mode"],
    ("update_user", "totp"): ["Switching it off", "automatic approval mode"],
    ("update_user", "reroute_gw"): ["vpn.client.routing.reroute_gw", "dns_only"],
    ("update_user", "reset_to_inherited"): ["group", "server", "preview"],
    ("delete_user", "usernames"): ["case-sensitive", "not a group"],
    ("create_group", "name"): ["128", "existing user or group"],
    ("create_group", "deny"): ["every member"],
    ("update_group", "name"): ["case-sensitive", "not a user"],
    ("update_group", "deny"): ["block_group"],
    ("update_user", "remove_from_group"): ["server values", "not with group"],
    ("block_group", "names"): ["case-sensitive"],
    ("reset_user_password", "usernames"): ["case-sensitive", "local"],
    ("reset_user_mfa", "usernames"): ["case-sensitive"],
    ("delete_group", "name"): ["case-sensitive"],
}


async def schemas() -> dict[str, dict]:
    """Every tool of write mode, which holds the read-mode tools too."""
    mcp = build(
        Settings(url="https://as.example:943", user="u", password="p", write_tools=True)
    )
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


async def test_the_profile_write_tools_state_their_bounds_in_the_schema() -> None:
    all_schemas = await schemas()
    create = all_schemas["create_connection_profile"]
    assert create["required"] == ["usernames"]
    assert create["properties"]["profile_type"]["enum"] == ["userlogin", "autologin"]
    assert "200" in json.dumps(create["properties"]["comment"])
    link = all_schemas["create_profile_download_link"]["properties"]
    assert link["lifetime_seconds"]["minimum"] == 60
    assert link["lifetime_seconds"]["default"] == 86400
    assert link["usages"]["minimum"] == 1 and link["usages"]["default"] == 1
    delete = all_schemas["delete_connection_profiles"]
    assert "required" not in delete or delete["required"] == []
    assert set(delete["properties"]) == {"serials", "username"}
    for schema in all_schemas.values():
        assert "ctx" not in schema.get("properties", {})


async def test_the_download_link_tool_names_the_access_server_term() -> None:
    mcp = build(
        Settings(url="https://as.example:943", user="u", password="p", write_tools=True)
    )
    async with Client(mcp) as client:
        listed = await client.list_tools()
    tools = {tool.name: tool.description or "" for tool in listed}
    link = tools["create_profile_download_link"]
    assert "called Token URL in Access Server" in link
