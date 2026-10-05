"""Users, groups and the default user.

totp_secret never leaves the server unredacted.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import Client

from as_mcp_server.client import REDACTED
from tests.conftest import body_of, load_fixture
from tests.test_server import server_for

pytestmark = pytest.mark.usefixtures("clean_env")
USERS = ("POST", "/api/users/list")
GROUPS = ("POST", "/api/groups/list")
DEFAULT_USER = ("GET", "/api/users/defaultuser")


async def test_list_users_defaults_and_redaction_of_totp_secret(tmp_path: Path) -> None:
    status, body = load_fixture("users_list")
    mcp, router = server_for(tmp_path, {USERS: (status, body)})
    async with Client(mcp) as client:
        result = (await client.call_tool("list_users", {})).structured_content
    assert body_of(router.sent(*USERS)[0]) == {
        "page_size": 50,
        "offset": 0,
        "order_by": "name",
        "sort_by": "asc",
    }
    assert result["total"] == 3
    names = {profile["name"] for profile in result["profiles"]}
    assert names == {"openvpn", "mfa-admin", "alice"}
    mfa_admin = next(p for p in result["profiles"] if p["name"] == "mfa-admin")
    assert mfa_admin["totp_secret"] == REDACTED
    assert "JBSWY3DPEHPK3PXP" not in repr(result)
    assert mfa_admin["admin"]["value"] is True  # non-secret fields untouched


async def test_list_users_filters_map_to_the_api_grammar(tmp_path: Path) -> None:
    mcp, router = server_for(tmp_path, {USERS: load_fixture("users_list_filter_name")})
    async with Client(mcp) as client:
        await client.call_tool(
            "list_users",
            {
                "page_size": 5,
                "offset": 10,
                "name_contains": "ali",
                "group": "staff",
                "admins_only": True,
                "autologin_only": True,
                "usernames": ["alice", "nobody"],
                "order_by": "mfa_status",
                "sort": "desc",
            },
        )
    assert body_of(router.sent(*USERS)[0]) == {
        "page_size": 5,
        "offset": 10,
        "order_by": "mfa_status",
        "sort_by": "desc",
        "filters": {
            "name": {"operation": "substring", "value": "ali"},
            "group": {"operation": "equal", "value": "staff"},
            "admin": {"value": True},
            "autologin": {"value": True},
        },
        "users": ["alice", "nobody"],
    }


async def test_list_groups_counts_members_by_default_and_enumerates_on_request(
    tmp_path: Path,
) -> None:
    mcp, router = server_for(
        tmp_path,
        {GROUPS: [load_fixture("groups_list"), load_fixture("groups_list_members")]},
    )
    async with Client(mcp) as client:
        counted = (await client.call_tool("list_groups", {})).structured_content
        listed = (
            await client.call_tool(
                "list_groups",
                {
                    "include_members": True,
                    "name_contains": "sta",
                    "group_names": ["staff"],
                    "order_by": "member_count",
                    "sort": "desc",
                },
            )
        ).structured_content
    first, second = (body_of(r) for r in router.sent(*GROUPS))
    assert first == {
        "page_size": 50,
        "offset": 0,
        "order_by": "name",
        "sort_by": "asc",
        "enumerate_members": False,
    }
    assert second == {
        "page_size": 50,
        "offset": 0,
        "order_by": "member_count",
        "sort_by": "desc",
        "enumerate_members": True,
        "filters": {"name": {"operation": "substring", "value": "sta"}},
        "groups": ["staff"],
    }
    assert counted["profiles"][0]["member_count"] == 2
    assert listed["profiles"][0]["members"] == ["mfa-admin", "alice"]


async def test_get_default_user_returns_the_default_profile(tmp_path: Path) -> None:
    status, body = load_fixture("default_user")
    mcp, router = server_for(tmp_path, {DEFAULT_USER: (status, body)})
    async with Client(mcp) as client:
        result = (await client.call_tool("get_default_user", {})).structured_content
    assert result == body
    assert result["name"] == "__DEFAULT__"
    assert len(router.sent(*DEFAULT_USER)) == 1
