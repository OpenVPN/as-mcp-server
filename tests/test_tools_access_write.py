"""modify_access_list against an Access Server kept in memory. The server removes
every copy of each item of items_remove first, then appends items_append (measured
on 3.1.0 and 3.2.4)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp.exceptions import ToolError

from as_mcp_server import approval
from as_mcp_server.server import build
from as_mcp_server.settings import Settings
from as_mcp_server.texts import (
    AUTO_ACCESS,
    MSG_AUTO_LIMIT,
    MSG_CONFLICT_ENTRY,
    MSG_NO_ACCESS_CHANGE,
    MSG_NOT_WRITABLE,
    NOTE_ACCESS_LIST_RESTART,
    WARN_HIDDEN,
)
from as_mcp_server.tools_access_write import MSG_NO_DEFAULT_VIA
from as_mcp_server.versions import untested_refusal
from tests.conftest import LOGIN, Router, body_of, call_tool
from tests.conftest import load_fixture as fixture
from tests.test_effective import own as own_value
from tests.test_effective import record
from tests.test_writes import users_route

pytestmark = pytest.mark.usefixtures("clean_env")

SERVER_INFO = ("GET", "/api/server/info")
USERS = ("POST", "/api/users/list")
GROUPS = ("POST", "/api/groups/list")
LIST = ("POST", "/api/userprop/access/list")
SET = ("POST", "/api/userprop/access/set")
OVERVIEW = ("POST", "/api/helper/status-overview")


@pytest.fixture(autouse=True)
def no_pending_prompts():
    approval._issued.clear()
    yield
    approval._issued.clear()


def route(network: str, *, accept: bool = True, via: str = "route", **more) -> dict:
    address, prefix = network.split("/")
    return {
        "type": via,
        "accept": accept,
        "subnet": {
            "ipv6": False,
            "netip": address,
            "prefix_length": int(prefix),
            "service": more.get("service", []),
        },
    }


def item(owner: str, access_route: dict, kind: str = "username") -> dict:
    return {kind: owner, "access_route": access_route, "type": "access_to_ipv4"}


class FakeServer:
    def __init__(
        self,
        tmp_path: Path,
        *,
        mode: str = "prompt",
        version: str | None = None,
        private_access: str = "nat",
        lists: list[dict] | None = None,
    ) -> None:
        self.tmp_path = tmp_path
        self.users = [record("openvpn", admin=own_value(True)), record("alice")]
        self.groups = [record("staff")]
        self.lists = list(lists if lists is not None else [])
        self.private_access = private_access
        self.reorder = False  # store items_append backwards, like a broken server
        status, info = fixture("server_info")
        if version is not None:
            info = {**info, "version": version}
        self.router = Router(
            {
                LOGIN: fixture("login_ok"),
                SERVER_INFO: (status, info),
                USERS: lambda request: users_route(self.users)(request),
                GROUPS: lambda request: users_route(self.groups)(request),
                LIST: self._list,
                SET: self._set,
                OVERVIEW: self._overview,
            }
        )
        settings = Settings(
            url="https://as.example:943",
            user="openvpn",
            password="write-test-password",
            config_dir=tmp_path,
            write_tools=True,
            approval=mode,  # type: ignore[arg-type]
        )
        self.mcp = build(settings, transport=self.router.transport())

    def _list(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        names = set(body.get("users", [])) | set(body.get("groups", []))
        found = [
            entry
            for entry in self.lists
            if not names or (entry.get("username") or entry.get("groupname")) in names
        ]
        return httpx.Response(200, json={"profiles": found})

    def _set(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        gone = body.get("items_remove", [])
        self.lists = [entry for entry in self.lists if entry not in gone]
        appended = body.get("items_append", [])
        self.lists += list(reversed(appended)) if self.reorder else appended
        return httpx.Response(200, json=None)

    def _overview(self, request: httpx.Request) -> httpx.Response:
        names = json.loads(request.content)["names"]
        items = [
            {"name": name, "value": self.private_access, "default_value": "no"}
            for name in names
        ]
        return httpx.Response(
            200, json={"configuration_items": {"total": len(items), "items": items}}
        )

    async def call(self, args: dict[str, Any], **options: Any) -> Any:
        return await call_tool(self.mcp, "modify_access_list", args, **options)

    def sent(self, route_key: tuple[str, str]) -> list[Any]:
        return [body_of(request) for request in self.router.sent(*route_key)]

    def audit(self) -> list[dict[str, Any]]:
        path = self.tmp_path / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text("utf-8").splitlines()]


WIDE = item("alice", route("10.0.0.0/24"))
DENY_HOST = {"subnet": "10.0.0.5", "allow": False, "via": "route"}


async def test_a_deny_under_a_wider_allow_is_written_in_front_in_one_request(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path, lists=[WIDE])
    result = await server.call({"owner": "alice", "add": [DENY_HOST]})
    deny = item("alice", route("10.0.0.5/32", accept=False))
    assert server.sent(SET) == [{"items_remove": [WIDE], "items_append": [deny, WIDE]}]
    assert server.lists == [deny, WIDE]
    (row,) = result["items"]
    assert row["outcome"] == "done"
    assert row["before"]["access_list"] == ["allow 10.0.0.0/24 (route)"]
    assert row["after"]["access_list"] == [
        "deny 10.0.0.5/32 (route)",
        "allow 10.0.0.0/24 (route)",
    ]


async def test_the_preview_shows_the_list_after_the_change_in_order(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path, lists=[WIDE])
    seen: list[str] = []
    await server.call({"owner": "alice", "add": [DENY_HOST]}, seen=seen)
    (text,) = seen
    assert "Action: Change access list (1 item): alice" in text
    assert (
        "also: adds deny 10.0.0.5/32 (route) in front of allow 10.0.0.0/24 (route)"
        in text
    )
    assert (
        "    order after the change:\n"
        "      1. deny 10.0.0.5/32 (route)\n"
        "      2. allow 10.0.0.0/24 (route)"
    ) in text
    assert "takes effect only after a warm restart" in text.splitlines()[2]


async def test_the_result_says_a_warm_restart_is_needed(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, lists=[WIDE])
    result = await server.call({"owner": "alice", "add": [DENY_HOST]})
    assert NOTE_ACCESS_LIST_RESTART in result["notes"]


async def test_automatic_mode_refuses_every_access_list_change(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, mode="auto", lists=[WIDE])
    with pytest.raises(ToolError) as refused:
        await server.call({"owner": "alice", "add": [DENY_HOST]})
    assert str(refused.value) == MSG_AUTO_LIMIT.format(reason=AUTO_ACCESS)
    assert server.sent(SET) == []
    assert [line["outcome"] for line in server.audit()] == ["refused_auto_limit"]


async def test_an_untested_minor_is_refused(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, version="3.3.0", lists=[WIDE])
    with pytest.raises(ToolError) as refused:
        await server.call({"owner": "alice", "add": [DENY_HOST]})
    assert str(refused.value) == untested_refusal("3.3.0")
    assert server.sent(LIST) == [] and server.sent(SET) == []


async def test_default_is_refused_as_owner(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError, match="__DEFAULT__"):
        await server.call({"owner": "__DEFAULT__", "add": [DENY_HOST]})
    assert server.sent(SET) == []


async def test_an_unknown_owner_is_refused_before_any_write(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError, match="There is no user or group named nobody"):
        await server.call({"owner": "nobody", "add": [DENY_HOST]})
    assert server.sent(SET) == []
    assert [line["outcome"] for line in server.audit()] == ["failed"]


async def test_a_group_owner_uses_the_groups_filter(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    await server.call(
        {"owner": "staff", "add": [{"subnet": "10.20.0.0/24", "allow": True}]}
    )
    assert server.sent(LIST)[0] == {
        "groups": ["staff"],
        "filters": {"object_type": "group"},
    }
    assert server.lists == [
        item("staff", route("10.20.0.0/24", via="nat"), kind="groupname")
    ]


async def test_a_different_order_read_back_is_a_partial_result(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, lists=[WIDE])
    server.reorder = True
    result = await server.call({"owner": "alice", "add": [DENY_HOST]})
    (row,) = result["items"]
    assert row["outcome"] == "partial"
    assert "another order" in row["detail"]


async def test_nothing_to_change_is_refused(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, lists=[WIDE])
    with pytest.raises(ToolError) as refused:
        await server.call({"owner": "alice"})
    assert str(refused.value) == MSG_NO_ACCESS_CHANGE
    assert server.sent(SET) == []


@pytest.mark.parametrize(
    "service",
    [
        {"protocol": "icmp"},
        {"protocol": "tcp"},
        {"protocol": "udp", "port": 53, "icmp_type": "icmp-any"},
        {"protocol": "tcp", "port": 2000, "end_port": 1000},
        {"protocol": "icmp", "icmp_type": "icmp-pong"},
    ],
)
async def test_a_service_that_does_not_fit_its_protocol_is_refused_before_any_request(
    tmp_path: Path, service: dict
) -> None:
    server = FakeServer(tmp_path, lists=[WIDE])
    entry = {**DENY_HOST, "services": [service]}
    with pytest.raises(ToolError):
        await server.call({"owner": "alice", "add": [entry]})
    assert server.sent(LIST) == [] and server.sent(SET) == []


@pytest.mark.parametrize("subnet", ["10.0.0.5/24", "10.0.0.0/33", "fd00::/64", "x"])
async def test_a_subnet_that_is_not_an_ipv4_network_is_refused(
    tmp_path: Path, subnet: str
) -> None:
    server = FakeServer(tmp_path, lists=[WIDE])
    with pytest.raises(ToolError):
        await server.call({"owner": "alice", "add": [{**DENY_HOST, "subnet": subnet}]})
    assert server.sent(SET) == []


async def test_services_are_written_in_the_shape_the_server_returns(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    services = [
        {"protocol": "tcp", "port": 443},
        {"protocol": "udp", "port": 2000, "end_port": 2999},
        {"protocol": "icmp", "icmp_type": "icmp-echo-request"},
    ]
    await server.call(
        {
            "owner": "alice",
            "add": [{**DENY_HOST, "subnet": "10.40.0.0/24", "services": services}],
        }
    )
    _, captured = fixture("access_lists")
    alice_web = captured["profiles"][1]["access_route"]["subnet"]["service"]
    (written,) = server.lists
    assert written["access_route"]["subnet"]["service"] == alice_web


async def test_without_via_the_server_setting_is_used(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, private_access="route")
    await server.call(
        {"owner": "alice", "add": [{"subnet": "10.9.0.0/16", "allow": True}]}
    )
    assert server.lists == [item("alice", route("10.9.0.0/16"))]
    asked = server.sent(OVERVIEW)
    assert asked and all(
        body == {"names": ["vpn.server.routing.private_access"]} for body in asked
    )


async def test_without_via_and_without_a_server_default_the_call_is_refused(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path, private_access="no")
    with pytest.raises(ToolError) as refused:
        await server.call(
            {"owner": "alice", "add": [{"subnet": "10.9.0.0/16", "allow": True}]}
        )
    assert str(refused.value) == MSG_NO_DEFAULT_VIA.format(value="no")
    assert server.sent(SET) == []


async def test_an_entry_is_replaced_by_its_opposite_in_one_call(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, lists=[WIDE])
    wide = {"subnet": "10.0.0.0/24", "allow": True, "via": "route"}
    await server.call(
        {"owner": "alice", "remove": [wide], "add": [{**wide, "allow": False}]}
    )
    deny = item("alice", route("10.0.0.0/24", accept=False))
    assert server.sent(SET) == [{"items_remove": [WIDE], "items_append": [deny]}]


async def test_the_opposite_action_without_removing_is_refused_before_the_question(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path, lists=[WIDE])
    seen: list[str] = []
    with pytest.raises(ToolError) as refused:
        await server.call(
            {
                "owner": "alice",
                "add": [{"subnet": "10.0.0.0/24", "allow": False, "via": "nat"}],
            },
            seen=seen,
        )
    assert str(refused.value) == MSG_CONFLICT_ENTRY.format(
        owner="alice", entry="allow 10.0.0.0/24 (route)"
    )
    assert seen == [] and server.sent(SET) == []


async def test_an_entry_of_class_all_that_would_be_rewritten_is_refused(
    tmp_path: Path,
) -> None:
    everything = item("alice", {"type": "all", "accept": True})
    server = FakeServer(tmp_path, lists=[WIDE, everything])
    with pytest.raises(ToolError) as refused:
        await server.call({"owner": "alice", "add": [DENY_HOST]})
    assert str(refused.value) == MSG_NOT_WRITABLE.format(
        owner="alice", entry="allow all"
    )
    assert server.sent(SET) == []


async def test_an_entry_of_class_all_in_front_of_the_change_stays(
    tmp_path: Path,
) -> None:
    everything = item("alice", {"type": "all", "accept": True})
    server = FakeServer(tmp_path, lists=[everything, WIDE])
    await server.call({"owner": "alice", "add": [DENY_HOST]})
    deny = item("alice", route("10.0.0.5/32", accept=False))
    assert server.lists == [everything, deny, WIDE]


async def test_an_entry_that_has_no_effect_is_warned_in_preview_and_result(
    tmp_path: Path,
) -> None:
    hidden = item("alice", route("10.0.0.5/32", accept=False))
    server = FakeServer(tmp_path, lists=[WIDE, hidden])
    seen: list[str] = []
    result = await server.call(
        {"owner": "alice", "add": [{"subnet": "10.9.0.0/16", "allow": True}]}, seen=seen
    )
    warning = WARN_HIDDEN.format(
        entry="deny 10.0.0.5/32 (route)", earlier="allow 10.0.0.0/24 (route)"
    )
    assert warning in seen[0]
    assert result["items"][0]["warnings"] == [warning]
