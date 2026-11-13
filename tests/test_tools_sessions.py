"""block_user and disconnect_vpn_sessions against an Access Server kept in memory,
including its habit of listing a session for a few seconds after it ended."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError

from as_mcp_server import approval, tools_sessions
from as_mcp_server.guards import Effect
from as_mcp_server.server import build
from as_mcp_server.settings import Settings
from as_mcp_server.texts import (
    CLIENT_REASON,
    DEFAULT_REASON,
    MSG_CANCELLED,
    MSG_CHANGED,
    MSG_LOCKOUT,
    MSG_NOT_DISCONNECTED,
)
from as_mcp_server.tools_sessions import (
    MSG_STILL_CONNECTED,
    NOTE_DOWNLOAD_LINK,
    Session,
    disconnect,
    not_disconnected,
    sessions_of,
)
from as_mcp_server.writes import NOTE_LIVE
from tests.conftest import LOGIN, MODES, Router, body_of, call_tool
from tests.conftest import load_fixture as fixture
from tests.test_effective import own as own_value
from tests.test_effective import record, state
from tests.test_writes import users_route

pytestmark = pytest.mark.usefixtures("clean_env")

SERVER_INFO = ("GET", "/api/server/info")
USERS = ("POST", "/api/users/list")
GROUPS = ("POST", "/api/groups/list")
STATUS = ("GET", "/api/vpn/status")
SET = ("POST", "/api/userprop/set")
DISCONNECT = ("POST", "/api/vpn/client/disconnect")
MISSING = {"reason": "Some of the clients are missing"}


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch: pytest.MonkeyPatch):
    approval._issued.clear()
    monkeypatch.setattr(tools_sessions, "POLL_SECONDS", 0)
    monkeypatch.setattr(tools_sessions, "SETTLE_POLLS", 4)
    yield
    approval._issued.clear()


def session(username: str, daemon: str = "openvpn_1", client_id: int = 0) -> dict:
    return {
        "daemon_id": daemon,
        "client_id": client_id,
        "username": username,
        "common_name": f"{username}_AUTOLOGIN",
        "connected_since": f"2026-11-14T10:00:0{client_id}Z",
        "bytes_received": 4001,
        "bytes_sent": 3077,
        "real_address": "172.21.0.5:38402",
    }


def short(username: str, daemon: str = "openvpn_1", client_id: int = 0) -> dict:
    return {"daemon_id": daemon, "client_id": client_id, "username": username}


class FakeServer:
    """Users with a deny flag and VPN sessions. A disconnected session stays in the
    status for `lag` more reads, and a disconnect for a listed-but-gone session
    answers 404, as measured on the real servers."""

    def __init__(self, tmp_path: Path, *, mode: str = "prompt", user: str = "openvpn"):
        self.tmp_path = tmp_path
        self.users = [
            record("openvpn", admin=own_value(True)),
            record("alice"),
            record("bob"),
            record("Bob"),
            record("carol", deny=own_value(True)),
        ]
        self.groups = [record("staff")]
        self.sessions = [
            session("alice", "openvpn_1", 0),
            session("alice", "openvpn_2", 1),
            session("bob", "openvpn_1", 2),
            session("openvpn", "openvpn_3", 0),
        ]
        self.lag = 0
        self.ending: list[tuple[dict, int]] = []  # (session, status reads left)
        self.deaf: set[str] = set()  # usernames whose sessions ignore a disconnect
        self.events: list[str] = []
        self.router = Router(
            {
                LOGIN: fixture("login_ok"),
                SERVER_INFO: fixture("server_info"),
                USERS: lambda request: users_route(self.users)(request),
                GROUPS: lambda request: users_route(self.groups)(request),
                STATUS: self._status,
                SET: self._set,
                DISCONNECT: self._disconnect,
            }
        )
        settings = Settings(
            url="https://as.example:943",
            user=user,
            password="write-test-password",
            config_dir=tmp_path,
            write_tools=True,
            approval=mode,  # type: ignore[arg-type]
        )
        self.settings = settings
        self.mcp = build(settings, transport=self.router.transport())

    def _status(self, request: httpx.Request) -> httpx.Response:
        listed = [*self.sessions, *(s for s, _ in self.ending)]
        self.ending = [(s, left - 1) for s, left in self.ending if left > 1]
        return httpx.Response(200, json={"vpn_clients": listed, "vpn_daemons": {}})

    def _set(self, request: httpx.Request) -> httpx.Response:
        for change in json.loads(request.content):
            self.events.append(f"deny {change['name']}")
            for index, user in enumerate(self.users):
                if user["name"] == change["name"]:
                    self.users[index] = {**user, "deny": own_value(change["deny"])}
        return httpx.Response(200, json=None)

    def _disconnect(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        users = body.get("users", [])
        clients = [(c["daemon_id"], c["client_id"]) for c in body.get("clients", [])]
        self.events.append(f"disconnect {users or clients}")
        hit = [
            s
            for s in self.sessions
            if s["username"] in users or (s["daemon_id"], s["client_id"]) in clients
        ]
        if not hit:
            return httpx.Response(404, json=MISSING)
        for found in hit:
            if found["username"] in self.deaf:
                continue
            self.sessions.remove(found)
            if self.lag:
                self.ending.append((found, self.lag))
        return httpx.Response(200, json=None)

    def end(self, username: str) -> None:
        """The user's client goes away by itself; the status still lists it."""
        gone = [s for s in self.sessions if s["username"] == username]
        self.sessions = [s for s in self.sessions if s["username"] != username]
        self.ending += [(s, max(self.lag, 1)) for s in gone]

    async def call(self, tool: str, args: dict[str, Any], **options: Any) -> Any:
        return await call_tool(self.mcp, tool, args, **options)

    def sent(self, route: tuple[str, str]) -> list[Any]:
        return [body_of(request) for request in self.router.sent(*route)]

    def audit(self) -> list[dict[str, Any]]:
        path = self.tmp_path / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text("utf-8").splitlines()]

    def denied(self, name: str) -> bool:
        return next(u for u in self.users if u["name"] == name)["deny"]["value"]

    def connected(self, name: str) -> int:
        return len([s for s in self.sessions if s["username"] == name])


async def approve_after(server: FakeServer, change: Any, tool: str, args: dict) -> Any:
    async def handler(message, response_type, params, context):
        change()
        fields = params.requested_schema.get("properties", {})
        return ElicitResult(action="accept", content=dict.fromkeys(fields, True))

    async with Client(server.mcp, mode="legacy", elicitation_handler=handler) as client:
        return (await client.call_tool(tool, args)).structured_content


# --- block_user -------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_block_sets_deny_before_it_disconnects(tmp_path: Path, mode: str) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "block_user", {"usernames": ["alice"]}, mode=mode, seen=seen
    )
    assert server.events == ["deny alice", "disconnect ['alice']"]
    assert server.sent(SET) == [[{"name": "alice", "deny": True}]]
    (item,) = result["items"]
    assert item["outcome"] == "done" and item["disconnected"] == 2
    assert item["before"]["deny"] is False and item["after"]["deny"] is True
    assert item["before"]["sessions"] == [
        short("alice", "openvpn_1", 0),
        short("alice", "openvpn_2", 1),
    ]
    assert item["after"]["sessions"] == []
    assert server.denied("alice") and server.connected("alice") == 0
    assert server.connected("bob") == 1 and not server.denied("bob")
    assert result["notes"] == [NOTE_LIVE]
    assert seen[0] == (
        "Server: https://as.example:943\n"
        "Action: Block user (1 item)\n"
        "\n"
        "- alice\n"
        "    deny: false -> true\n"
        "    also: disconnects 2 active session(s)\n"
        f"    also: {NOTE_DOWNLOAD_LINK}"
    )
    (line,) = server.audit()
    assert line["tool"] == "block_user" and line["outcome"] == "applied"


@pytest.mark.parametrize("name", ["openvpn", "OpenVPN", "OPENVPN"])
@pytest.mark.parametrize("mode", ["prompt", "auto"])
async def test_blocking_the_own_account_is_refused_before_any_request(
    tmp_path: Path, name: str, mode: str
) -> None:
    server = FakeServer(tmp_path, mode=mode)
    server.users.append(record("OpenVPN"))
    server.users.append(record("OPENVPN"))
    with pytest.raises(ToolError) as refused:
        await server.call("block_user", {"usernames": ["alice", name]})
    assert str(refused.value) == MSG_LOCKOUT.format(name="openvpn")
    assert server.sent(SET) == [] and server.sent(DISCONNECT) == []
    assert not server.denied("alice")
    assert [line["outcome"] for line in server.audit()] == ["refused_lockout"] * 2


async def test_the_own_account_is_the_one_signed_in_not_the_name_openvpn(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path, user="alice")
    server.users[1] = record("alice", admin=own_value(True))
    with pytest.raises(ToolError, match="lock as-mcp-server out"):
        await server.call("block_user", {"usernames": ["alice"]})
    result = await server.call("block_user", {"usernames": ["openvpn"]})
    assert result["items"][0]["outcome"] == "done" and server.denied("openvpn")


async def test_block_in_auto_mode_needs_no_prompt(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, mode="auto")
    result = await server.call("block_user", {"usernames": ["bob"]}, answer="none")
    assert result["approval"] == "auto" and result["items"][0]["outcome"] == "done"
    assert server.denied("bob") and server.connected("bob") == 0
    assert not server.denied("Bob")


async def test_block_without_sessions_skips_the_disconnect(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call("block_user", {"usernames": ["Bob"]}, seen=seen)
    assert server.sent(DISCONNECT) == []
    (item,) = result["items"]
    assert item["outcome"] == "done" and item["disconnected"] == 0
    assert "also: disconnects 0 active session(s)" in seen[0]
    assert server.denied("Bob") and not server.denied("bob")
    assert server.connected("bob") == 1  # bob is another user


async def test_a_session_that_survives_the_block_is_reported(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    server.deaf = {"alice"}
    result = await server.call("block_user", {"usernames": ["alice", "bob"]})
    first, second = result["items"]
    assert first["outcome"] == "partial"
    assert first["detail"] == f"{MSG_STILL_CONNECTED} (done: deny set)"
    assert server.denied("alice")
    assert second["outcome"] == "not attempted" and not server.denied("bob")
    assert [line["outcome"] for line in server.audit()] == ["partial"]


async def test_a_session_that_stays_listed_for_a_moment_is_waited_for(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.lag = 3
    result = await server.call("block_user", {"usernames": ["alice"]})
    assert result["items"][0]["outcome"] == "done"
    server.sessions.append(session("bob", "openvpn_4", 5))
    server.lag = 9  # longer than the tool waits
    result = await server.call("block_user", {"usernames": ["bob"]})
    assert result["items"][0]["outcome"] == "partial"


async def test_a_session_that_ended_just_before_the_block_does_not_fail_it(
    tmp_path: Path,
) -> None:
    """The status still lists it, the disconnect answers 404, then it is gone."""
    server = FakeServer(tmp_path)
    server.lag = 4  # listed for the three reads before the disconnect, and one after
    server.end("bob")
    result = await server.call("block_user", {"usernames": ["bob"]})
    (item,) = result["items"]
    assert item["outcome"] == "done" and server.denied("bob")
    assert len(server.sent(DISCONNECT)) == 1


async def test_a_disconnect_that_fails_after_deny_is_partial_and_says_what_to_call(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.router.routes[DISCONNECT] = [(500, {"reason": "daemon is busy"})]
    result = await server.call("block_user", {"usernames": ["alice"]})
    (item,) = result["items"]
    assert item["outcome"] == "partial" and server.denied("alice")
    assert "daemon is busy" in item["detail"]
    assert (
        "Call disconnect_vpn_sessions for this user. (done: deny set)"
        in (item["detail"])
    )


async def test_the_block_preview_and_result_mention_the_download_link(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call("block_user", {"usernames": ["alice"]}, seen=seen)
    assert NOTE_DOWNLOAD_LINK in seen[0]
    assert result["items"][0]["download_links"] == NOTE_DOWNLOAD_LINK
    assert "still returns a profile" in NOTE_DOWNLOAD_LINK


async def test_block_user_has_no_disconnect_parameter(tmp_path: Path) -> None:
    async with Client(FakeServer(tmp_path).mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    assert set(tools["block_user"].input_schema["properties"]) == {"usernames"}
    assert tools["block_user"].annotations.destructive_hint is True
    assert tools["disconnect_vpn_sessions"].annotations.destructive_hint is True
    assert "update_user" in tools["block_user"].description
    for name in tools_sessions.TOOLS:
        assert tools[name].annotations.read_only_hint is False
        assert tools[name].annotations.idempotent_hint is False
        assert tools[name].meta["fastmcp"]["tags"] == ["write"]
    read_only = build(Settings(url="https://as.example:943", user="u", password="p"))
    async with Client(read_only) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert not names & set(tools_sessions.TOOLS)


@pytest.mark.parametrize("name", ["staff", "nobody", "ALICE", "__DEFAULT__"])
async def test_a_group_name_is_refused_as_a_block_target(
    tmp_path: Path, name: str
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError):
        await server.call("block_user", {"usernames": ["alice", name]})
    assert server.sent(SET) == [] and not server.denied("alice")


async def test_a_user_who_is_already_blocked_is_blocked_again_without_harm(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call("block_user", {"usernames": ["carol"]}, seen=seen)
    assert "deny: true -> true" in seen[0]
    assert result["items"][0]["outcome"] == "done"


async def test_a_declined_block_changes_nothing(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as refused:
        await server.call("block_user", {"usernames": ["alice"]}, answer="no")
    assert str(refused.value) == MSG_CANCELLED
    assert server.events == [] and not server.denied("alice")


async def test_a_session_that_appears_during_the_prompt_refuses_the_block(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as refused:
        await approve_after(
            server,
            lambda: server.sessions.append(session("Bob", "openvpn_9", 9)),
            "block_user",
            {"usernames": ["Bob"]},
        )
    assert str(refused.value) == MSG_CHANGED and server.events == []


async def test_a_user_who_is_not_shown_as_blocked_afterwards_is_partial(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.router.routes[SET] = [(200, None)]  # accepted, not stored
    result = await server.call("block_user", {"usernames": ["Bob"]})
    (item,) = result["items"]
    assert item["outcome"] == "partial"
    assert item["detail"] == (
        "Access Server does not show the user as blocked (done: written)"
    )


# --- disconnect_vpn_sessions ------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_three_users_send_three_disconnect_requests_with_one_target_each(
    tmp_path: Path, mode: str
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "disconnect_vpn_sessions",
        {"usernames": ["alice", "bob", "openvpn"]},
        mode=mode,
        seen=seen,
    )
    assert [body["users"] for body in server.sent(DISCONNECT)] == [
        ["alice"],
        ["bob"],
        ["openvpn"],  # the own account may be disconnected
    ]
    assert [item["outcome"] for item in result["items"]] == ["done"] * 3
    assert [item["disconnected"] for item in result["items"]] == [2, 1, 1]
    assert server.sessions == [] and server.sent(SET) == []
    assert len(seen) == 1
    assert seen[0].startswith(
        "Server: https://as.example:943\n"
        "Action: Disconnect VPN sessions (3 items)\n"
        "\n"
        "- alice\n"
        "    active sessions: 2 -> 0\n"
        "    also: disconnect openvpn_1/0 (alice)\n"
        "    also: disconnect openvpn_2/1 (alice)\n"
        f'    also: reason in the server log: "{DEFAULT_REASON}"\n'
        "- bob\n"
    )
    assert result["items"][0]["after"] == {"sessions": []}


async def test_the_text_shown_to_the_vpn_user_is_fixed(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    await server.call(
        "disconnect_vpn_sessions", {"usernames": ["bob"], "reason": "laptop lost"}
    )
    assert server.sent(DISCONNECT) == [
        {"reason": "laptop lost", "client_reason": CLIENT_REASON, "users": ["bob"]}
    ]
    assert CLIENT_REASON == "Disconnected by your administrator."
    async with Client(server.mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    assert set(tools["disconnect_vpn_sessions"].input_schema["properties"]) == {
        "usernames",
        "sessions",
        "reason",
    }


async def test_disconnect_never_sends_ignore_missing_user(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    await server.call("disconnect_vpn_sessions", {"usernames": ["bob"]})
    await server.call("block_user", {"usernames": ["alice"]})
    for request in server.router.requests:
        assert b"ignore_missing" not in request.content


@pytest.mark.parametrize(
    "reason",
    ["line one\nline two", "tab\there", "", "   ", "x" * 201, chr(0x2028), chr(0x202E)],
)
async def test_a_reason_with_a_newline_is_rejected(tmp_path: Path, reason: str) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError):
        await server.call(
            "disconnect_vpn_sessions", {"usernames": ["bob"], "reason": reason}
        )
    assert server.router.requests == []


@pytest.mark.parametrize(
    "args",
    [
        {},
        {
            "usernames": ["bob"],
            "sessions": [{"daemon_id": "openvpn_1", "client_id": 2}],
        },
        {"usernames": []},
        {"sessions": []},
    ],
)
async def test_usernames_and_sessions_together_or_neither_are_refused(
    tmp_path: Path, args: dict[str, Any]
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as refused:
        await server.call("disconnect_vpn_sessions", args)
    assert str(refused.value) == "Give exactly one of usernames or sessions."
    assert server.router.requests == []


async def test_one_session_of_a_user_is_disconnected_and_the_other_stays(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "disconnect_vpn_sessions",
        {"sessions": [{"daemon_id": "openvpn_2", "client_id": 1}]},
        seen=seen,
    )
    assert server.sent(DISCONNECT) == [
        {
            "reason": DEFAULT_REASON,
            "client_reason": CLIENT_REASON,
            "clients": [{"daemon_id": "openvpn_2", "client_id": 1}],
        }
    ]
    (item,) = result["items"]
    assert item["target"] == "session openvpn_2/1" and item["outcome"] == "done"
    assert item["before"] == {"sessions": [short("alice", "openvpn_2", 1)]}
    assert "- session openvpn_2/1\n    active sessions: 1 -> 0\n" in seen[0]
    assert "also: disconnect openvpn_2/1 (alice)" in seen[0]
    assert server.connected("alice") == 1


@pytest.mark.parametrize(
    "bad",
    [
        {"daemon_id": "openvpn_1"},
        {"daemon_id": "openvpn_1", "client_id": -1},
        {"daemon_id": "open vpn", "client_id": 0},
        {"daemon_id": "openvpn_1", "client_id": 0, "username": "alice"},
        {"daemon_id": "", "client_id": 0},
    ],
)
async def test_a_malformed_session_is_refused_before_any_request(
    tmp_path: Path, bad: dict[str, Any]
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError):
        await server.call("disconnect_vpn_sessions", {"sessions": [bad]})
    assert server.router.requests == []


async def test_a_user_without_a_session_or_a_session_that_is_gone_refuses_the_call(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as refused:
        await server.call("disconnect_vpn_sessions", {"usernames": ["bob", "Bob"]})
    assert "is in the list twice" in str(refused.value)
    with pytest.raises(ToolError) as refused:
        await server.call("disconnect_vpn_sessions", {"usernames": ["bob", "carol"]})
    assert str(refused.value) == (
        "carol has no active VPN session on this Access Server (names are "
        "case-sensitive)."
    )
    with pytest.raises(ToolError) as refused:
        await server.call(
            "disconnect_vpn_sessions",
            {"sessions": [{"daemon_id": "openvpn_7", "client_id": 3}]},
        )
    assert str(refused.value).startswith(
        "There is no VPN session openvpn_7/3 on this Access Server"
    )
    assert server.sent(DISCONNECT) == [] and server.connected("bob") == 1


async def test_sessions_of_a_user_whose_record_is_gone_can_be_disconnected(
    tmp_path: Path,
) -> None:
    """Measured: a session survives the deletion of its user."""
    server = FakeServer(tmp_path)
    server.sessions.append(session("deleted-user", "openvpn_5", 0))
    result = await server.call(
        "disconnect_vpn_sessions", {"usernames": ["deleted-user"]}
    )
    assert result["items"][0]["outcome"] == "done"


async def test_a_session_that_ended_before_the_disconnect_counts_as_done(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.lag = 2
    server.end("bob")  # still listed, already gone
    result = await server.call("disconnect_vpn_sessions", {"usernames": ["bob"]})
    (item,) = result["items"]
    assert item["outcome"] == "done" and len(server.sent(DISCONNECT)) == 1


async def test_after_a_404_a_target_that_is_still_connected_is_failed(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.router.routes[DISCONNECT] = [(404, MISSING)]
    result = await server.call(
        "disconnect_vpn_sessions", {"usernames": ["bob", "alice"]}
    )
    first, second = result["items"]
    assert first["outcome"] == "failed"
    assert first["detail"] == (
        "Access Server did not find the session to disconnect (404), but still "
        "lists it as connected."
    )
    assert second["outcome"] == "not attempted"
    assert len(server.sent(DISCONNECT)) == 1  # not repeated


async def test_a_session_that_stays_listed_after_the_disconnect_is_partial(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.deaf = {"bob"}
    result = await server.call("disconnect_vpn_sessions", {"usernames": ["bob"]})
    (item,) = result["items"]
    assert item["outcome"] == "partial"
    assert item["detail"] == "Access Server still lists the session (done: written)"


async def test_a_client_that_reconnects_at_once_is_not_a_failed_disconnect(
    tmp_path: Path,
) -> None:
    """disconnect does not block: the client may be back before the check."""
    server = FakeServer(tmp_path)
    original = server._disconnect

    def disconnect_then_reconnect(request: httpx.Request) -> httpx.Response:
        answer = original(request)
        again = session("bob", "openvpn_1", 2)
        server.sessions.append({**again, "connected_since": "2026-11-14T11:11:11Z"})
        return answer

    server.router.routes[DISCONNECT] = [disconnect_then_reconnect]
    result = await server.call("disconnect_vpn_sessions", {"usernames": ["bob"]})
    assert result["items"][0]["outcome"] == "done"


async def test_a_session_that_ends_during_the_prompt_refuses_the_disconnect(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as refused:
        await approve_after(
            server,
            lambda: server.sessions.pop(0),
            "disconnect_vpn_sessions",
            {"usernames": ["alice"]},
        )
    assert str(refused.value) == MSG_CHANGED and server.sent(DISCONNECT) == []


async def test_byte_counters_of_a_session_are_not_a_change(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)

    def traffic() -> None:
        server.sessions[2]["bytes_sent"] += 5000

    result = await approve_after(
        server, traffic, "disconnect_vpn_sessions", {"usernames": ["bob"]}
    )
    assert result["items"][0]["outcome"] == "done"


async def test_more_than_100_sessions_are_refused(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    many = [{"daemon_id": "openvpn_1", "client_id": n} for n in range(101)]
    with pytest.raises(ToolError, match="the limit is 100"):
        await server.call("disconnect_vpn_sessions", {"sessions": many})
    assert server.sent(DISCONNECT) == []


# --- helpers for the user and group tools -----------------------------------------


async def test_sessions_of_matches_the_exact_name_and_drops_the_counters(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.sessions.append(session("Bob", "openvpn_0", 7))
    from as_mcp_server.client import ClientHolder

    client = ClientHolder(server.settings, transport=server.router.transport()).get()
    assert await sessions_of(client, ["bob", "Bob", "nobody"]) == [
        short("Bob", "openvpn_0", 7),
        short("bob", "openvpn_1", 2),
    ]
    assert await sessions_of(client, ["BOB"]) == []
    with pytest.raises(ValueError, match="exactly one"):
        await disconnect(client)
    with pytest.raises(ValueError, match="exactly one"):
        await disconnect(
            client, user="bob", session=Session(daemon_id="openvpn_1", client_id=2)
        )


def test_not_disconnected_names_only_newly_blocked_users_with_a_session() -> None:
    def effect(name: str, before: bool, after: bool) -> Effect:
        return Effect("user", name, state(deny=before), state(deny=after))

    effects = [
        effect("alice", False, True),
        effect("bob", False, True),  # no session
        effect("carol", True, True),  # was blocked already
        effect("dave", False, False),
        Effect("group", "staff", state(deny=False), state(deny=True)),
    ]
    sessions = [short("alice"), short("carol"), short("dave"), short("staff")]
    assert not_disconnected(effects, sessions) == (
        MSG_NOT_DISCONNECTED.format(name="alice"),
    )
    assert not_disconnected(effects, []) == ()
