"""Connection profiles and access lists can be read; a profile's content never is."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from as_mcp_server.texts import NOTE_ACCESS_LISTS, NOTE_GLOBAL_IP
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
    assert result["total"] == 7
    owners = {p["username"]: p["profile_type"] for p in result["profiles"]}
    assert owners == {
        "alice": "userlogin",
        "bob": "userlogin",
        "жанна": "userlogin",
        "qa vpn test user": "autologin",
    }
    serials = [p["serial"] for p in result["profiles"]]
    assert all(isinstance(serial, str) and serial.isdigit() for serial in serials)
    assert [int(serial) for serial in serials] == sorted(map(int, serials))


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
    assert result["note"] == NOTE_ACCESS_LISTS
    owners = [e.get("username") or e["groupname"] for e in result["profiles"]]
    assert sorted(owners) == sorted(
        ["alice"] * 3 + ["bob"] * 2 + ["жанна", "contractors", "staff"]
    )


@pytest.mark.parametrize("fixture", ["access_lists", "access_lists_3_1_0"])
async def test_every_shape_of_access_entry_reaches_the_agent_unchanged(
    tmp_path: Path, fixture: str
) -> None:
    """Ports, a port range, an ICMP type, a deny entry, the user, group and
    all_vpn_clients classes, access_from: the stand holds one of each."""
    _, captured = load_fixture(fixture)
    mcp, _ = server_for(tmp_path, {ACCESS: load_fixture(fixture)})
    async with Client(mcp) as client:
        result = (await client.call_tool("list_access_lists", {})).structured_content
    assert result["profiles"] == captured["profiles"]
    routes = [e["access_route"] for e in result["profiles"]]
    assert {r["type"] for r in routes} == {
        "route",
        "nat",
        "user",
        "group",
        "all_vpn_clients",
    }
    assert [r["subnet"]["netip"] for r in routes if r["accept"] is False] == [
        "10.40.0.99"
    ]
    services = next(
        r["subnet"]["service"] for r in routes if r.get("subnet", {}).get("service")
    )
    assert services == [
        {"protocol": "tcp", "start_port": 443},
        {"protocol": "udp", "start_port": 2000, "end_port": 2999},
        {"protocol": "icmp", "type": "icmp-echo-request"},
    ]
    assert {e["type"] for e in result["profiles"]} == {
        "access_to_ipv4",
        "access_from_ipv4",
    }


def test_the_note_names_both_things_the_list_cannot_show() -> None:
    assert NOTE_ACCESS_LISTS == (
        "Global IP/subnet rules are not visible through the API; check the Admin UI. "
        "IPv6 access lists are not returned by the API."
    )
    assert NOTE_ACCESS_LISTS.startswith(NOTE_GLOBAL_IP)


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


async def test_the_note_is_also_on_an_empty_result(
    tmp_path: Path,
) -> None:
    mcp, _ = server_for(tmp_path, {ACCESS: (200, {"profiles": []})})
    async with Client(mcp) as client:
        result = (
            await client.call_tool("list_access_lists", {"usernames": ["nobody"]})
        ).structured_content
    assert result == {"profiles": [], "note": NOTE_ACCESS_LISTS}


async def test_a_non_latin_username_is_sent_as_it_is(tmp_path: Path) -> None:
    mcp, router = server_for(
        tmp_path,
        {PROFILES: load_fixture("profiles_list"), ACCESS: load_fixture("access_lists")},
    )
    async with Client(mcp) as client:
        await client.call_tool("list_connection_profiles", {"username": "жанна"})
        await client.call_tool("list_access_lists", {"usernames": ["жанна"]})
    assert body_of(router.sent(*PROFILES)[0])["filters"] == {
        "username": {"operation": "equal", "value": "жанна"}
    }
    assert body_of(router.sent(*ACCESS)[0])["users"] == ["жанна"]


async def test_an_empty_username_means_no_filter(tmp_path: Path) -> None:
    mcp, router = server_for(tmp_path, {PROFILES: load_fixture("profiles_list")})
    async with Client(mcp) as client:
        await client.call_tool("list_connection_profiles", {"username": ""})
    assert "filters" not in body_of(router.sent(*PROFILES)[0])


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("list_connection_profiles", {"page_size": 0}),
        ("list_connection_profiles", {"page_size": 1001}),
        ("list_connection_profiles", {"offset": -1}),
        ("list_connection_profiles", {"sort": "up"}),
        ("list_connection_profiles", {"autologin_only": "maybe"}),
        ("list_access_lists", {"usernames": "alice"}),
        ("list_access_lists", {"group_names": "staff"}),
    ],
)
async def test_a_malformed_argument_is_refused_before_any_request(
    tmp_path: Path, tool: str, arguments: dict
) -> None:
    mcp, router = server_for(
        tmp_path,
        {PROFILES: load_fixture("profiles_list"), ACCESS: load_fixture("access_lists")},
    )
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="validation error"):
            await client.call_tool(tool, arguments)
    assert router.sent(*PROFILES) == [] and router.sent(*ACCESS) == []


@pytest.mark.parametrize(
    ("tool", "endpoint"),
    [("list_connection_profiles", PROFILES), ("list_access_lists", ACCESS)],
)
async def test_a_403_from_the_endpoint_is_explained_not_passed_as_data(
    tmp_path: Path, tool: str, endpoint: tuple[str, str]
) -> None:
    mcp, _ = server_for(tmp_path, {endpoint: load_fixture("error_forbidden_403")})
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="403"):
            await client.call_tool(tool, {})
