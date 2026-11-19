"""Write tools against both real servers. Every test works on a throwaway user and
leaves the stand as it found it."""

from __future__ import annotations

import asyncio
import contextlib
import json
import shutil
import stat
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError
from mcp.server import request_state
from mcp.shared.exceptions import MCPError

from as_mcp_server.server import build
from as_mcp_server.settings import Settings
from as_mcp_server.texts import (
    MSG_AUTO_LIMIT,
    MSG_CANCELLED,
    MSG_LATE_ANSWER,
    MSG_LOCKOUT,
    MSG_NO_ELICITATION,
)
from tests.conftest import call_tool, elicitation_handler
from tests.live.vpn_clients import VpnClient, for_the_stand, require_client_image
from tests.test_approval import YES

SCRATCH = "live-write-user"


def sacli(stand: str, *args: str) -> None:
    subprocess.run(
        ["docker", "exec", stand, "sacli", *args],
        check=True,
        text=True,
        capture_output=True,
    )


class Live:
    def __init__(self, name: str, settings: Settings, tmp_path: Path) -> None:
        self.name = name
        self.tmp_path = tmp_path
        self.out = tmp_path / "out"
        self.settings = settings.model_copy(
            update={"write_tools": True, "output_dir": self.out}
        )
        self.mcp = build(self.settings)
        self.auto = build(self.settings.model_copy(update={"approval": "auto"}))

    async def call(self, tool: str, args: dict | None = None, **options):
        return await call_tool(self.mcp, tool, args, **options)

    async def profiles(self, username: str | None = None) -> list[dict]:
        args = {"page_size": 1000}
        if username is not None:
            args["username"] = username
        return (await self.call("list_connection_profiles", args))["profiles"]

    def audit(self) -> list[dict]:
        text = (self.tmp_path / "audit.jsonl").read_text("utf-8")
        return [json.loads(line) for line in text.splitlines()]


@pytest.fixture
async def live(stand, tmp_path: Path):
    """A user nobody else uses, with the autologin right; gone afterwards, together
    with every profile issued to it."""
    if shutil.which("docker") is None:
        pytest.skip("docker is needed to create the throwaway user")
    name, settings = stand
    server = Live(name, settings, tmp_path)
    before = len(await server.profiles())
    sacli(
        name,
        "--user",
        SCRATCH,
        "--key",
        "type",
        "--value",
        "user_connect",
        "UserPropPut",
    )
    sacli(
        name,
        "--user",
        SCRATCH,
        "--key",
        "prop_autologin",
        "--value",
        "true",
        "UserPropPut",
    )
    try:
        yield server
    finally:
        if await server.profiles(SCRATCH):
            await call_tool(
                server.auto, "delete_connection_profiles", {"username": SCRATCH}
            )
        sacli(name, "--user", SCRATCH, "UserPropDelAll")
        assert len(await server.profiles()) == before


async def test_a_profile_is_created_saved_listed_and_deleted_by_serial(live) -> None:
    seen: list[str] = []
    result = await live.call(
        "create_connection_profile",
        {"usernames": [SCRATCH], "comment": "live test", "tls_crypt_v2": True},
        seen=seen,
    )
    (item,) = result["items"]
    assert item["outcome"] == "done" and result["approval"] == "prompt"
    assert "connection profiles: 0 -> 1" in seen[0]
    path = Path(item["path"])
    text = path.read_text("utf-8")
    assert "<key>" in text and "PRIVATE KEY" in text and "<tls-crypt-v2>" in text
    assert f"Certificate serial: {item['serial']}" in text
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(live.out.stat().st_mode) == 0o700
    assert "PRIVATE KEY" not in json.dumps(result)
    assert "PRIVATE KEY" not in (live.tmp_path / "audit.jsonl").read_text("utf-8")
    (listed,) = await live.profiles(SCRATCH)
    assert listed["serial"] == item["serial"] and listed["comment"] == "live test"
    assert listed["profile_type"] == "userlogin" and listed["tls_crypt_v2"] is True

    seen.clear()
    deleted = await live.call(
        "delete_connection_profiles", {"serials": [item["serial"]]}, seen=seen
    )
    assert deleted["items"][0]["outcome"] == "done"
    assert deleted["items"][0]["deleted"] == [item["serial"]]
    assert (
        f'delete {item["serial"]} ({SCRATCH}, userlogin, comment "live test")'
        in (seen[0])
    )
    assert await live.profiles(SCRATCH) == []
    assert [line["outcome"] for line in live.audit()] == ["applied", "applied"]


async def test_every_profile_of_a_user_is_deleted_by_username(live) -> None:
    for _ in range(2):
        await live.call("create_connection_profile", {"usernames": [SCRATCH]})
    serials = sorted(p["serial"] for p in await live.profiles(SCRATCH))
    assert len(serials) == 2
    result = await live.call("delete_connection_profiles", {"username": SCRATCH})
    (item,) = result["items"]
    assert item["outcome"] == "done" and sorted(item["deleted"]) == serials
    assert await live.profiles(SCRATCH) == []
    with pytest.raises(ToolError, match="There are no connection profiles of user"):
        await live.call("delete_connection_profiles", {"username": SCRATCH})


async def test_an_autologin_profile_needs_a_person_and_the_users_right(live) -> None:
    args = {"usernames": [SCRATCH], "profile_type": "autologin"}
    with pytest.raises(ToolError) as refused:
        await call_tool(live.auto, "create_connection_profile", args)
    assert str(refused.value) == MSG_AUTO_LIMIT.format(
        reason=f"an autologin connection profile would be created for user {SCRATCH}"
    )
    assert await live.profiles(SCRATCH) == []
    result = await live.call("create_connection_profile", args)
    (item,) = result["items"]
    assert item["outcome"] == "done"
    (listed,) = await live.profiles(SCRATCH)
    assert listed["profile_type"] == "autologin"
    assert "auth-user-pass" not in Path(item["path"]).read_text("utf-8")
    # alice has no autologin right on the stand.
    with pytest.raises(ToolError, match="autologin is off for user alice"):
        await live.call(
            "create_connection_profile",
            {"usernames": ["alice"], "profile_type": "autologin"},
        )


@pytest.mark.parametrize("name", ["staff", "no-such-user", "ALICE", "__DEFAULT__"])
@pytest.mark.parametrize(
    "tool", ["create_connection_profile", "create_profile_download_link"]
)
async def test_nothing_is_issued_to_a_group_or_to_a_name_that_is_not_a_user(
    live, tool: str, name: str
) -> None:
    """The server itself would issue it (measured), so the tool must not ask."""
    with pytest.raises(ToolError):
        await call_tool(live.auto, tool, {"usernames": [SCRATCH, name]})
    assert await live.profiles(SCRATCH) == [] and await live.profiles(name) == []
    assert not live.out.exists() or not list(live.out.iterdir())


async def test_a_download_link_is_saved_with_its_expiry_and_never_returned(
    live,
) -> None:
    result = await live.call(
        "create_profile_download_link",
        {"usernames": [SCRATCH], "lifetime_seconds": 60, "usages": 2},
    )
    (item,) = result["items"]
    assert item["outcome"] == "done" and item["usages"] == 2
    lines = Path(item["path"]).read_text("utf-8").splitlines()
    assert lines[0].startswith("openvpn://import-profile/https://")
    assert lines[1] == f"valid until {item['valid_until']}, 2 use(s)"
    assert "://" not in json.dumps(result)
    assert "import-profile" not in (live.tmp_path / "audit.jsonl").read_text("utf-8")
    assert await live.profiles(SCRATCH) == []  # a link alone creates no profile
    with pytest.raises(
        ToolError, match=r"at most 604800 seconds \(168 hours\) and 5 uses"
    ):
        await live.call(
            "create_profile_download_link",
            {"usernames": [SCRATCH], "lifetime_seconds": 604801},
        )
    auto = await call_tool(
        live.auto, "create_profile_download_link", {"usernames": [SCRATCH]}
    )
    assert auto["approval"] == "auto" and auto["items"][0]["outcome"] == "done"
    with pytest.raises(ToolError, match="Refused in automatic approval mode"):
        await call_tool(
            live.auto,
            "create_profile_download_link",
            {"usernames": [SCRATCH], "profile_type": "autologin"},
        )


@pytest.mark.parametrize(
    ("answer", "message"), [("decline", MSG_CANCELLED), ("none", MSG_NO_ELICITATION)]
)
@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_without_a_yes_nothing_is_created_or_deleted(
    live, mode: str, answer: str, message: str
) -> None:
    with pytest.raises(ToolError) as refused:
        await live.call(
            "create_connection_profile",
            {"usernames": [SCRATCH]},
            mode=mode,
            answer=answer,
        )
    assert str(refused.value) == message
    assert await live.profiles(SCRATCH) == []
    with pytest.raises(ToolError) as refused:
        await live.call(
            "delete_connection_profiles",
            {"username": "bob"},
            mode=mode,
            answer=answer,
        )
    assert str(refused.value) == message
    assert len(await live.profiles("bob")) == 4


async def test_profiles_for_several_users_in_one_approved_call(live) -> None:
    """жанна has a non-ASCII name; her file must be written and found again."""
    seen: list[str] = []
    result = await live.call(
        "create_connection_profile",
        {"usernames": [SCRATCH, "жанна"], "comment": "batch"},
        mode="2026-07-28",
        seen=seen,
    )
    assert len(seen) == 1 and "(2 items)" in seen[0]
    first, second = result["items"]
    assert [first["outcome"], second["outcome"]] == ["done", "done"]
    assert "жанна" in Path(second["path"]).name and Path(second["path"]).exists()
    try:
        assert len(await live.profiles("жанна")) == 2
    finally:
        await live.call("delete_connection_profiles", {"serials": [second["serial"]]})
    assert len(await live.profiles("жанна")) == 1
    assert len({line["batch_id"] for line in live.audit()[:2]}) == 1


async def test_a_serial_that_is_not_on_the_server_refuses_the_whole_delete(
    live,
) -> None:
    await live.call("create_connection_profile", {"usernames": [SCRATCH]})
    (listed,) = await live.profiles(SCRATCH)
    with pytest.raises(ToolError, match="no connection profile with serial 123456789"):
        await live.call(
            "delete_connection_profiles", {"serials": [listed["serial"], "123456789"]}
        )
    assert len(await live.profiles(SCRATCH)) == 1


async def test_a_profile_that_cannot_be_saved_is_reported_with_its_serial(
    live,
) -> None:
    """The folder turns read-only while the administrator reads the prompt."""

    async def handler(message, response_type, params, context):
        live.out.chmod(0o500)
        fields = params.requested_schema.get("properties", {})
        return ElicitResult(action="accept", content=dict.fromkeys(fields, True))

    async def create(mode: str):
        live.out.mkdir(exist_ok=True)
        try:
            async with Client(
                live.mcp, mode=mode, elicitation_handler=handler
            ) as client:
                return (
                    await client.call_tool(
                        "create_connection_profile", {"usernames": [SCRATCH]}
                    )
                ).structured_content
        finally:
            live.out.chmod(0o700)

    # Since 2026-07-28 the call runs again after the answer, so the folder is
    # checked once more and nothing is created.
    with pytest.raises(ToolError, match="Cannot write to the output folder"):
        await create("2026-07-28")
    assert await live.profiles(SCRATCH) == []

    result = await create("legacy")
    (item,) = result["items"]
    (listed,) = await live.profiles(SCRATCH)
    assert item["outcome"] == "partial" and item["serial"] == listed["serial"]
    assert "could not be saved" in item["detail"]
    assert "delete it with delete_connection_profiles" in item["detail"]
    assert "path" not in item and not list(live.out.iterdir())
    assert live.audit()[-1]["outcome"] == "partial"
    await live.call("delete_connection_profiles", {"serials": [item["serial"]]})
    assert await live.profiles(SCRATCH) == []


async def test_a_download_link_really_hands_out_a_profile_once_per_use(live) -> None:
    """What the tool promises about a link: it works, each use issues one profile,
    and it stops after the last use."""
    result = await live.call(
        "create_profile_download_link", {"usernames": [SCRATCH], "usages": 2}
    )
    link = Path(result["items"][0]["path"]).read_text("utf-8").splitlines()[0]
    path = "/rest/" + link.rsplit("/rest/", 1)[1]
    statuses = []
    async with httpx.AsyncClient(verify=False, base_url=live.settings.url) as http:
        for _ in range(3):
            answer = await http.get(path)
            statuses.append((answer.status_code, "<key>" in answer.text))
    assert statuses[:2] == [(200, True), (200, True)]
    assert statuses[2][1] is False
    assert len(await live.profiles(SCRATCH)) == 2


# --- sessions: real VPN clients ---------------------------------------------------


class Connected:
    """The throwaway user with a profile made by the tool, and clients using it."""

    def __init__(self, live: Live, profile: Path) -> None:
        self.live = live
        self.profile = profile
        self.clients: list[VpnClient] = []

    async def sessions(self) -> list[dict]:
        status = await self.live.call("get_active_vpn_connections")
        return [s for s in status["vpn_clients"] if s["username"] == SCRATCH]

    async def connect(self, expected: int = 1) -> VpnClient:
        """Start one more client and wait until the server lists `expected`
        sessions."""
        name = f"live-vpn-{self.live.name}-{len(self.clients)}"
        client = VpnClient(name, self.profile).start()
        self.clients.append(client)
        assert client.wait_connected(), client.log()[-600:]
        for _ in range(40):
            if len(await self.sessions()) >= expected:
                return client
            await asyncio.sleep(0.5)
        raise AssertionError("the session never appeared in /vpn/status")

    async def stop(self) -> None:
        """Stop the clients and leave no session behind: the stand allows two."""
        for client in self.clients:
            client.stop()
        for attempt in range(40):
            if not await self.sessions():
                return
            if attempt == 20:  # a session the server did not notice ending
                with contextlib.suppress(ToolError):
                    await call_tool(
                        self.live.auto,
                        "disconnect_vpn_sessions",
                        {"usernames": [SCRATCH]},
                    )
            await asyncio.sleep(0.5)


@pytest.fixture
async def connected(live):
    require_client_image()
    made = await live.call(
        "create_connection_profile",
        {"usernames": [SCRATCH], "profile_type": "autologin"},
    )
    profile = for_the_stand(Path(made["items"][0]["path"]), live.name, live.tmp_path)
    user = Connected(live, profile)
    try:
        yield user
    finally:
        # The live fixture deletes the user; a block set by a test goes with it.
        await user.stop()


async def test_block_user_blocks_and_disconnects_a_connected_user(connected) -> None:
    live = connected.live
    client = await connected.connect()
    link = await live.call("create_profile_download_link", {"usernames": [SCRATCH]})
    seen: list[str] = []
    result = await live.call("block_user", {"usernames": [SCRATCH]}, seen=seen)
    (item,) = result["items"]
    assert item["outcome"] == "done" and item["disconnected"] == 1
    assert item["before"]["deny"] is False and item["after"]["deny"] is True
    assert "disconnects 1 active session(s)" in seen[0]
    assert client.wait_exited(), client.log()[-600:]
    assert await connected.sessions() == []
    (user,) = (await live.call("list_users", {"usernames": [SCRATCH]}))["profiles"]
    assert user["deny"]["value"] is True

    again = VpnClient(f"{client.name}-again", connected.profile).start()
    connected.clients.append(again)
    assert again.wait_exited(30)
    assert again.refused("DENY")

    # What the tool says about download links, checked on the real server.
    url = Path(link["items"][0]["path"]).read_text("utf-8").splitlines()[0]
    path = "/rest/" + url.rsplit("/rest/", 1)[1]
    async with httpx.AsyncClient(verify=False, base_url=live.settings.url) as http:
        answer = await http.get(path)
    assert answer.status_code == 200 and "<key>" in answer.text


async def test_disconnect_by_username_ends_every_session_and_does_not_block(
    connected,
) -> None:
    live = connected.live
    first = await connected.connect(1)
    second = await connected.connect(2)
    seen: list[str] = []
    result = await live.call(
        "disconnect_vpn_sessions",
        {"usernames": [SCRATCH], "reason": "live test"},
        mode="2026-07-28",
        seen=seen,
    )
    (item,) = result["items"]
    assert item["outcome"] == "done" and item["disconnected"] == 2
    assert "active sessions: 2 -> 0" in seen[0]
    assert first.wait_exited() and second.wait_exited()
    assert await connected.sessions() == []
    (user,) = (await live.call("list_users", {"usernames": [SCRATCH]}))["profiles"]
    assert user["deny"]["value"] is False
    back = await connected.connect(1)  # not blocked: the same profile connects again
    assert back.running()
    with pytest.raises(ToolError, match="has no active VPN session"):
        await live.call("disconnect_vpn_sessions", {"usernames": [SCRATCH, "alice"]})
    assert back.running() and len(await connected.sessions()) == 1


async def test_disconnect_by_session_ends_one_of_two_sessions(connected) -> None:
    live = connected.live
    await connected.connect(1)
    await connected.connect(2)
    one, other = sorted(
        await connected.sessions(), key=lambda s: (s["daemon_id"], s["client_id"])
    )
    target = {"daemon_id": one["daemon_id"], "client_id": one["client_id"]}
    result = await call_tool(
        live.auto, "disconnect_vpn_sessions", {"sessions": [target]}
    )
    (item,) = result["items"]
    assert item["outcome"] == "done" and result["approval"] == "auto"
    assert item["target"] == f"session {one['daemon_id']}/{one['client_id']}"
    left = await connected.sessions()
    assert [(s["daemon_id"], s["client_id"]) for s in left] == [
        (other["daemon_id"], other["client_id"])
    ]
    assert sorted(client.running() for client in connected.clients) == [False, True]
    # The same session again: it is gone now.
    with pytest.raises(ToolError, match="There is no VPN session"):
        await call_tool(live.auto, "disconnect_vpn_sessions", {"sessions": [target]})


async def test_a_declined_block_leaves_the_user_connected(connected) -> None:
    live = connected.live
    client = await connected.connect()
    for tool in ("block_user", "disconnect_vpn_sessions"):
        with pytest.raises(ToolError) as refused:
            await live.call(tool, {"usernames": [SCRATCH]}, answer="decline")
        assert str(refused.value) == MSG_CANCELLED
    assert client.running() and len(await connected.sessions()) == 1
    (user,) = (await live.call("list_users", {"usernames": [SCRATCH]}))["profiles"]
    assert user["deny"]["value"] is False


async def test_block_user_without_a_session_and_its_refusals(live) -> None:
    result = await live.call("block_user", {"usernames": [SCRATCH]})
    (item,) = result["items"]
    assert item["outcome"] == "done" and item["disconnected"] == 0
    (user,) = (await live.call("list_users", {"usernames": [SCRATCH]}))["profiles"]
    assert user["deny"]["value"] is True

    own = live.settings.user
    for mcp in (live.mcp, live.auto):
        with pytest.raises(ToolError) as refused:
            await call_tool(mcp, "block_user", {"usernames": ["alice", own]})
        assert str(refused.value) == MSG_LOCKOUT.format(name=own)
    for name in ("staff", "no-such-user", "__DEFAULT__"):
        with pytest.raises(ToolError):
            await call_tool(live.auto, "block_user", {"usernames": ["alice", name]})
    users = (await live.call("list_users", {"usernames": ["alice", own]}))["profiles"]
    assert [user["deny"]["value"] for user in users] == [False, False]


async def test_the_support_report_is_saved_whole_and_stays_out_of_the_result(
    stand, tmp_path: Path
) -> None:
    name, settings = stand
    server = Live(name, settings, tmp_path)
    result = await server.call("create_support_report", {}, answer="none")
    assert set(result) == {"path", "size_bytes", "reminder"}
    path = Path(result["path"])
    assert path.parent == server.out and path.name.endswith(
        "-support-report-access-server.txt"
    )
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert result["size_bytes"] == path.stat().st_size > 10_000
    text = path.read_text("utf-8")
    lines = text.strip().splitlines()
    assert "Support summary" in lines[0] and "End Support summary" in lines[-1]
    # Access Server masks its own secrets; the stand has a RADIUS secret set.
    secrets = [
        line for line in lines if line.startswith("auth.radius.0.server.0.secret")
    ]
    assert secrets and all(line.endswith(": [redacted]") for line in secrets)
    assert "PRIVATE KEY-----" not in text
    assert not (tmp_path / "audit.jsonl").exists()


async def test_an_approval_answered_after_ten_minutes_changes_nothing(
    live, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = {"usernames": [SCRATCH]}
    handler = elicitation_handler("accept")
    options = {"mode": "2026-07-28", "elicitation_handler": handler}
    async with Client(live.mcp, **options) as client:
        asked = await client.session.call_tool(
            "block_user", arguments, allow_input_required=True
        )
        later = time.time() + 601
        monkeypatch.setattr(request_state, "time", SimpleNamespace(time=lambda: later))
        with pytest.raises(MCPError) as refused:
            await client.session.call_tool(
                "block_user",
                arguments,
                input_responses=YES,
                request_state=asked.request_state,
                allow_input_required=True,
            )
        monkeypatch.undo()
    assert refused.value.error.message == MSG_LATE_ANSWER.format(tool="block_user")
    line = live.audit()[-1]
    assert line["tool"] == "block_user" and line["outcome"] == "refused_no_approval"
    assert SCRATCH in line["target"] and line["server_url"] == live.settings.url
    (user,) = (await live.call("list_users", {"usernames": [SCRATCH]}))["profiles"]
    assert user["deny"]["value"] is False
