"""Connection profiles and access lists can be read; a profile's content never is."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastmcp import Client

from as_mcp_server.texts import NOTE_GLOBAL_IP
from tests.conftest import body_of, load_fixture
from tests.test_server import server_for

pytestmark = pytest.mark.usefixtures("clean_env")
PROFILES = ("POST", "/api/profiles/list")
ACCESS = ("POST", "/api/userprop/access/list")


@pytest.mark.parametrize("fixture", ["profiles_list", "profiles_list_3_1_0"])
async def test_profiles_are_listed_by_serial_with_their_owner_and_type(
    tmp_path: Path, fixture: str
) -> None:
    mcp, router = server_for(tmp_path, {PROFILES: load_fixture(fixture)})
    async with Client(mcp) as client:
        result = (
            await client.call_tool("list_connection_profiles", {})
        ).structured_content
    assert body_of(router.sent(*PROFILES)[0]) == {
        "page_size": 50,
        "offset": 0,
        "order_by": "serial",
        "sort_by": "asc",
    }
    assert result["total"] == 2
    owners = {p["username"]: p["profile_type"] for p in result["profiles"]}
    assert owners == {"alice": "userlogin", "qa vpn test user": "autologin"}


async def test_profile_filters_go_nested_under_filters(tmp_path: Path) -> None:
    """A top-level `username` is refused by the server with 400."""
    mcp, router = server_for(tmp_path, {PROFILES: load_fixture("profiles_list")})
    async with Client(mcp) as client:
        await client.call_tool(
            "list_connection_profiles",
            {
                "username": "alice",
                "autologin_only": True,
                "page_size": 10,
                "offset": 20,
                "sort": "desc",
            },
        )
    assert body_of(router.sent(*PROFILES)[0]) == {
        "page_size": 10,
        "offset": 20,
        "order_by": "serial",
        "sort_by": "desc",
        "filters": {
            "username": {"operation": "equal", "value": "alice"},
            "autologin": {"value": True},
        },
    }


async def test_a_serial_above_2_to_the_53_comes_back_as_a_string_of_digits(
    tmp_path: Path,
) -> None:
    """JavaScript clients lose precision on such integers, whichever way the server
    sends them."""
    body = {
        "total": 2,
        "profiles": [
            {"serial": 1810972200425098125, "username": "alice"},
            {"serial": "2877949965557316950", "username": "bob"},
        ],
    }
    mcp, _ = server_for(tmp_path, {PROFILES: (200, body)})
    async with Client(mcp) as client:
        result = (
            await client.call_tool("list_connection_profiles", {})
        ).structured_content
    assert [p["serial"] for p in result["profiles"]] == [
        "1810972200425098125",
        "2877949965557316950",
    ]


def strings(value: object) -> list[str]:
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return [value] if isinstance(value, str) else []


@pytest.mark.parametrize("fixture", ["profiles_list", "profiles_list_3_1_0"])
async def test_no_profile_content_or_key_is_in_the_listing(
    tmp_path: Path, fixture: str
) -> None:
    mcp, _ = server_for(tmp_path, {PROFILES: load_fixture(fixture)})
    async with Client(mcp) as client:
        result = (
            await client.call_tool("list_connection_profiles", {})
        ).structured_content
    assert not [s for s in strings(result) if s.startswith("-----BEGIN")]
    assert "PRIVATE KEY" not in json.dumps(result)


@pytest.mark.parametrize("fixture", ["access_lists", "access_lists_3_1_0"])
async def test_access_lists_of_everyone_are_listed_with_the_note(
    tmp_path: Path, fixture: str
) -> None:
    mcp, router = server_for(tmp_path, {ACCESS: load_fixture(fixture)})
    async with Client(mcp) as client:
        result = (await client.call_tool("list_access_lists", {})).structured_content
    assert body_of(router.sent(*ACCESS)[0]) == {}
    assert result["note"] == NOTE_GLOBAL_IP
    by_owner = {e.get("username") or e["groupname"]: e for e in result["profiles"]}
    assert by_owner["staff"]["access_route"]["subnet"]["netip"] == "10.20.0.0"
    assert by_owner["alice"]["access_route"]["type"] == "nat"


@pytest.mark.parametrize(
    ("arguments", "body"),
    [
        (
            {"usernames": ["alice"]},
            {"users": ["alice"], "filters": {"object_type": "user"}},
        ),
        (
            {"group_names": ["staff"]},
            {"groups": ["staff"], "filters": {"object_type": "group"}},
        ),
        (
            {"usernames": ["alice"], "group_names": ["staff"]},
            {"users": ["alice"], "groups": ["staff"]},
        ),
        ({"usernames": [], "group_names": []}, {}),
    ],
)
async def test_naming_only_users_does_not_bring_every_group_along(
    tmp_path: Path, arguments: dict, body: dict
) -> None:
    """Measured on 3.1.0 and 3.2.4: `users` narrows only the user entries and every
    group entry still comes back, and the other way round; `object_type` drops the
    side that was not asked for."""
    mcp, router = server_for(tmp_path, {ACCESS: load_fixture("access_lists")})
    async with Client(mcp) as client:
        await client.call_tool("list_access_lists", arguments)
    assert body_of(router.sent(*ACCESS)[0]) == body


async def test_the_global_rules_note_is_also_on_an_empty_result(
    tmp_path: Path,
) -> None:
    mcp, _ = server_for(tmp_path, {ACCESS: (200, {"profiles": []})})
    async with Client(mcp) as client:
        result = (
            await client.call_tool("list_access_lists", {"usernames": ["nobody"]})
        ).structured_content
    assert result == {"profiles": [], "note": NOTE_GLOBAL_IP}
