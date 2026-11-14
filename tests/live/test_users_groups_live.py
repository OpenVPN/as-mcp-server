"""User and group tools against both real servers. Every test works on throwaway
names and leaves the stand as it found it."""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError

from as_mcp_server.texts import MSG_AUTO_LIMIT, MSG_LOCKOUT, MSG_NOT_DISCONNECTED
from as_mcp_server.tools_users import NOTE_NEW_GROUP
from tests.conftest import call_tool
from tests.live.test_writes_live import Live
from tests.live.vpn_clients import VpnClient, for_the_stand, require_client_image

SERVER_VALUES = {
    "deny": False,
    "deny_web": False,
    "admin": False,
    "autologin": False,
    "auth_method": "local",
    "totp": False,
    "allow_password_change": True,
    "allow_generate_profiles": True,
    "reroute_gw": True,
}


class Scratch:
    """Throwaway names of one test, and the broom that removes them."""

    def __init__(self, live: Live) -> None:
        self.live = live
        tag = os.urandom(3).hex()
        self.user = f"mcp-live-{tag}"
        self.other = f"mcp-live-{tag}-b"
        self.group = f"mcp-live-g-{tag}"
        self.clients: list[VpnClient] = []

    async def call(self, tool: str, args: dict | None = None, **options):
        return await self.live.call(tool, args, **options)

    async def auto(self, tool: str, args: dict | None = None):
        return await call_tool(self.live.auto, tool, args, answer="none")

    async def user_record(self, name: str) -> dict | None:
        found = (await self.call("list_users", {"usernames": [name]}))["profiles"]
        return next((user for user in found if user["name"] == name), None)

    async def group_record(self, name: str) -> dict | None:
        found = await self.call(
            "list_groups", {"group_names": [name], "include_members": True}
        )
        return next((g for g in found["profiles"] if g["name"] == name), None)

    async def sessions(self, name: str) -> list[dict]:
        status = await self.call("get_active_vpn_connections")
        return [s for s in status["vpn_clients"] if s["username"] == name]

    async def connect(self, name: str, profile: Path, auth: Path | None = None):
        client = VpnClient(
            f"live-ug-{self.live.name}-{len(self.clients)}", profile, auth
        )
        self.clients.append(client.start())
        assert client.wait_connected(), client.log()[-600:]
        for _ in range(40):
            if await self.sessions(name):
                return client
            await asyncio.sleep(0.5)
        raise AssertionError("the session never appeared in /vpn/status")

    async def autologin_profile(self, name: str) -> Path:
        made = await self.call(
            "create_connection_profile",
            {"usernames": [name], "profile_type": "autologin"},
        )
        path = Path(made["items"][0]["path"])
        return for_the_stand(path, self.live.name, self.live.tmp_path)

    async def sweep(self) -> None:
        for client in self.clients:
            client.stop()
        for name in (self.user, self.other):
            for _ in range(30):
                if not await self.sessions(name):
                    break
                with contextlib.suppress(ToolError):
                    await self.auto("disconnect_vpn_sessions", {"usernames": [name]})
                await asyncio.sleep(0.5)
            if await self.live.profiles(name):
                await self.auto("delete_connection_profiles", {"username": name})
        for name in (self.user, self.other, self.group):
            # No check: a name the test already removed is the normal case.
            subprocess.run(
                [
                    "docker",
                    "exec",
                    self.live.name,
                    "sacli",
                    "--user",
                    name,
                    "UserPropDelAll",
                ],
                capture_output=True,
            )


@pytest.fixture
async def scratch(stand, tmp_path: Path):
    if shutil.which("docker") is None:
        pytest.skip("docker is needed to clean up after the test")
    name, settings = stand
    live = Live(name, settings, tmp_path)
    users = len((await live.call("list_users", {"page_size": 1000}))["profiles"])
    groups = len((await live.call("list_groups", {}))["profiles"])
    profiles = len(await live.profiles())
    made = Scratch(live)
    try:
        yield made
    finally:
        await made.sweep()
        after = await live.call("list_users", {"page_size": 1000})
        assert len(after["profiles"]) == users
        assert len((await live.call("list_groups", {}))["profiles"]) == groups
        assert len(await live.profiles()) == profiles


def values(record: dict) -> dict:
    return {name: record[name]["value"] for name in SERVER_VALUES}


async def test_a_user_lives_from_create_to_delete_in_automatic_mode(scratch) -> None:
    name = scratch.user
    created = await scratch.auto(
        "create_user", {"users": [{"username": name, "generate_password": True}]}
    )
    (item,) = created["items"]
    assert item["outcome"] == "done" and created["approval"] == "auto"
    assert item["before"] == {"exists": False}
    assert item["after"] == {
        **SERVER_VALUES,
        "group": None,
        "own": [],
        "password_defined": True,
    }
    path = Path(item["path"])
    password = path.read_text("utf-8").strip()
    assert len(password) >= 20 and password not in str(created)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

    moved = await scratch.auto("update_user", {"usernames": [name], "group": "staff"})
    assert moved["items"][0]["after"]["group"] == "staff"
    assert (await scratch.user_record(name))["group"] == "staff"

    await scratch.auto("create_connection_profile", {"usernames": [name]})
    await scratch.auto("create_profile_download_link", {"usernames": [name]})
    assert len(await scratch.live.profiles(name)) == 1

    blocked = await scratch.auto("block_user", {"usernames": [name]})
    assert blocked["items"][0]["after"]["deny"] is True
    unblocked = await scratch.auto("update_user", {"usernames": [name], "deny": False})
    assert unblocked["items"][0]["after"]["deny"] is False

    deleted = await scratch.auto("delete_user", {"usernames": [name]})
    (item,) = deleted["items"]
    assert item["outcome"] == "done" and item["deleted_profiles"] == 1
    assert item["after"] == {"exists": False, "profiles": [], "sessions": []}
    assert await scratch.user_record(name) is None
    assert await scratch.live.profiles(name) == []

    lines = scratch.live.audit()
    assert [line["tool"] for line in lines] == [
        "create_user",
        "update_user",
        "create_connection_profile",
        "create_profile_download_link",
        "block_user",
        "update_user",
        "delete_user",
    ]
    assert {line["outcome"] for line in lines} == {"applied"}
    assert password not in (scratch.live.tmp_path / "audit.jsonl").read_text("utf-8")


@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_every_field_of_a_user_is_set_read_back_and_reset(scratch, mode) -> None:
    name = scratch.user
    await scratch.call("create_user", {"users": [{"username": name}]}, mode=mode)
    changes = {
        "deny_web": True,
        "admin": True,
        "autologin": True,
        "auth_method": "pam",
        "totp": True,
        "allow_password_change": False,
        "allow_generate_profiles": False,
        "reroute_gw": "dns_only",
    }
    seen: list[str] = []
    result = await scratch.call(
        "update_user", {"usernames": [name], **changes}, mode=mode, seen=seen
    )
    (item,) = result["items"]
    assert item["outcome"] == "done", item
    assert {k: item["after"][k] for k in changes} == changes
    assert sorted(item["after"]["own"]) == sorted(changes)
    assert "    reroute_gw: true -> dns_only" in seen[0]
    assert values(await scratch.user_record(name)) == {**SERVER_VALUES, **changes}

    seen.clear()
    result = await scratch.call(
        "update_user",
        {"usernames": [name], "reset_to_inherited": list(changes)},
        mode=mode,
        seen=seen,
    )
    (item,) = result["items"]
    assert item["outcome"] == "done", item
    # What the preview promised is what the server shows afterwards.
    assert "totp: true -> inherited (server-wide value: False)" in seen[0]
    assert "reroute_gw: dns_only -> inherited (server-wide value: True)" in seen[0]
    assert "auth_method: pam -> inherited (server-wide value: local)" in seen[0]
    assert item["after"]["own"] == []
    assert values(await scratch.user_record(name)) == SERVER_VALUES


async def test_a_user_is_created_with_group_block_and_method(scratch) -> None:
    result = await scratch.call(
        "create_user",
        {
            "users": [
                {"username": scratch.user, "group": "staff", "deny": True},
                {"username": scratch.other, "auth_method": "radius"},
            ]
        },
    )
    first, second = result["items"]
    assert first["outcome"] == second["outcome"] == "done"
    assert first["after"]["group"] == "staff" and first["after"]["deny"] is True
    assert first["after"]["own"] == ["deny"]
    assert second["after"]["auth_method"] == "radius"
    assert second["after"]["password_defined"] is False
    assert len({line["batch_id"] for line in scratch.live.audit()}) == 1


async def test_what_the_server_would_accept_and_the_tools_refuse(scratch) -> None:
    name = scratch.user
    refused = [
        ("create_user", {"users": [{"username": name, "group": "no-such-group"}]}),
        ("create_user", {"users": [{"username": name, "group": "alice"}]}),
        ("create_user", {"users": [{"username": "alice"}]}),
        ("create_user", {"users": [{"username": "staff"}]}),
        ("create_group", {"name": "alice"}),
        ("create_group", {"name": "staff"}),
        ("delete_user", {"usernames": ["staff"]}),
        ("delete_group", {"name": "alice"}),
        ("update_user", {"usernames": ["alice"], "group": "no-such-group"}),
        ("update_user", {"usernames": ["no-such-user"], "totp": True}),
        ("update_group", {"name": "no-such-group", "totp": True}),
    ]
    for tool, args in refused:
        with pytest.raises(ToolError):
            await scratch.call(tool, args)
    with pytest.raises(ToolError, match="would use pam"):
        await scratch.call(
            "create_user",
            {
                "users": [
                    {"username": name, "auth_method": "pam", "generate_password": True}
                ]
            },
        )
    assert await scratch.user_record(name) is None
    assert await scratch.user_record("no-such-user") is None
    assert {line["outcome"] for line in scratch.live.audit()} == {"failed"}


async def test_the_own_account_and_automatic_mode_are_guarded_on_a_real_server(
    scratch,
) -> None:
    own = scratch.live.settings.user
    for tool, args in (
        ("delete_user", {"usernames": [own]}),
        ("update_user", {"usernames": [own], "admin": False}),
        ("update_user", {"usernames": [own], "reset_to_inherited": ["admin"]}),
        ("update_user", {"usernames": [own], "group": "staff"}),
        ("update_user", {"usernames": [own], "deny_web": True}),
    ):
        with pytest.raises(ToolError) as error:
            await scratch.call(tool, args)
        assert str(error.value) == MSG_LOCKOUT.format(name=own)
    for tool, args, reason in (
        (
            "create_user",
            {"users": [{"username": scratch.user, "admin": True}]},
            f"user {scratch.user} would become an administrator",
        ),
        (
            "update_user",
            {"usernames": ["alice"], "autologin": True},
            "autologin would be switched on for user alice",
        ),
        (
            "create_group",
            {"name": scratch.group, "admin": True},
            f"group {scratch.group} would become an administrator",
        ),
    ):
        with pytest.raises(ToolError) as error:
            await scratch.auto(tool, args)
        assert str(error.value) == MSG_AUTO_LIMIT.format(reason=reason)
    assert await scratch.user_record(scratch.user) is None
    assert await scratch.group_record(scratch.group) is None


@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_a_group_lives_from_create_to_delete(scratch, mode) -> None:
    group, name = scratch.group, scratch.user
    seen: list[str] = []
    created = await scratch.call(
        "create_group",
        {"name": group, "totp": True, "allow_generate_profiles": False},
        mode=mode,
        seen=seen,
    )
    (item,) = created["items"]
    assert item["outcome"] == "done", item
    assert item["after"]["own"] == ["totp", "allow_generate_profiles"]
    assert created["notes"] == [NOTE_NEW_GROUP]
    assert "until Access Server is restarted" in seen[0]

    await scratch.call("create_user", {"users": [{"username": name, "group": group}]})
    member = await scratch.user_record(name)
    assert member["totp"]["value"] is True
    assert member["totp"]["inherited_source_type"] == "group"

    seen.clear()
    updated = await scratch.call(
        "update_group",
        {"name": group, "reroute_gw": "disable", "reset_to_inherited": ["totp"]},
        mode=mode,
        seen=seen,
    )
    (item,) = updated["items"]
    assert item["outcome"] == "done", item
    assert "totp: true -> inherited (server-wide value: False)" in seen[0]
    assert item["after"]["totp"] is False and item["after"]["reroute_gw"] == "disable"
    member = await scratch.user_record(name)
    assert member["totp"]["value"] is False
    assert member["reroute_gw"]["value"] == "disable"

    seen.clear()
    deleted = await scratch.call("delete_group", {"name": group}, mode=mode, seen=seen)
    (item,) = deleted["items"]
    assert item["outcome"] == "done", item
    assert item["members_without_group"] == [name]
    assert f"members that lose this group: {name}" in seen[0]
    assert await scratch.group_record(group) is None
    member = await scratch.user_record(name)
    assert "group" not in member and values(member) == SERVER_VALUES


# --- real VPN clients -------------------------------------------------------------


async def test_a_generated_password_signs_in_and_a_deleted_user_is_disconnected(
    scratch,
) -> None:
    require_client_image()
    name, live = scratch.user, scratch.live
    created = await scratch.call(
        "create_user", {"users": [{"username": name, "generate_password": True}]}
    )
    password_file = Path(created["items"][0]["path"])
    made = await scratch.call("create_connection_profile", {"usernames": [name]})
    profile = for_the_stand(Path(made["items"][0]["path"]), live.name, live.tmp_path)
    auth = live.tmp_path / "auth.txt"
    auth.write_text(f"{name}\n{password_file.read_text('utf-8')}", "utf-8")
    auth.chmod(0o600)
    client = await scratch.connect(name, profile, auth)

    seen: list[str] = []
    result = await scratch.call("delete_user", {"usernames": [name]}, seen=seen)
    (item,) = result["items"]
    assert item["outcome"] == "done", item
    assert item["deleted_profiles"] == 1 and item["disconnected"] == 1
    assert "disconnects 1 active session(s)" in seen[0]
    assert client.wait_exited(), client.log()[-600:]
    assert await scratch.sessions(name) == []
    assert await scratch.user_record(name) is None

    again = VpnClient(f"{client.name}-again", profile, auth).start()
    scratch.clients.append(again)
    assert again.wait_exited(30) and "AUTH_FAILED" in again.log()


async def test_a_block_through_a_group_names_the_connected_user_and_leaves_the_session(
    scratch,
) -> None:
    require_client_image()
    name, group = scratch.user, scratch.group
    await scratch.call("create_user", {"users": [{"username": name}]})
    await scratch.call("update_user", {"usernames": [name], "autologin": True})
    client = await scratch.connect(name, await scratch.autologin_profile(name))
    await scratch.call("create_group", {"name": group})
    await scratch.call("update_user", {"usernames": [name], "group": group})
    line = MSG_NOT_DISCONNECTED.format(name=name)

    seen: list[str] = []
    result = await scratch.call(
        "update_group", {"name": group, "deny": True}, seen=seen
    )
    (item,) = result["items"]
    assert item["outcome"] == "done" and item["warnings"] == [line]
    assert f"also: {line}" in seen[0]
    await asyncio.sleep(8)
    assert client.running() and len(await scratch.sessions(name)) == 1  # measured

    # The same through a move: out of the group, then back into the blocked group.
    await scratch.call("update_group", {"name": group, "deny": False})
    await scratch.call("update_group", {"name": group, "deny": True})
    record = await scratch.user_record(name)
    assert record["deny"]["value"] is True
    seen.clear()
    result = await scratch.call(
        "update_user", {"usernames": [name], "reset_to_inherited": ["autologin"]}
    )
    assert "warnings" not in result["items"][0]  # already blocked: nothing new

    gone = await scratch.call("disconnect_vpn_sessions", {"usernames": [name]})
    assert gone["items"][0]["disconnected"] == 1 and client.wait_exited()


async def test_a_member_of_a_new_group_cannot_connect_until_a_restart(scratch) -> None:
    """A canary for the note of create_group: when a newer Access Server lets the
    member in, this test fails and the note can go."""
    require_client_image()
    name, group = scratch.user, scratch.group
    await scratch.call("create_user", {"users": [{"username": name}]})
    await scratch.call("update_user", {"usernames": [name], "autologin": True})
    profile = await scratch.autologin_profile(name)
    first = await scratch.connect(name, profile)  # without a group it connects
    first.stop()
    for _ in range(40):
        if not await scratch.sessions(name):
            break
        await asyncio.sleep(0.5)
    await scratch.call("create_group", {"name": group})
    await scratch.call("update_user", {"usernames": [name], "group": group})
    refused = VpnClient(f"{first.name}-in-group", profile).start()
    scratch.clients.append(refused)
    assert refused.wait_exited(30), "a member of a new group connected"
    assert "AUTH_FAILED" in refused.log()
