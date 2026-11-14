"""Users and groups: create, update, delete, against an Access Server kept in
memory that inherits values the way the real one does."""

from __future__ import annotations

import json
import logging
import stat
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from as_mcp_server import approval, tools_sessions, tools_users
from as_mcp_server.outputs import DELIVERY_REMINDER
from as_mcp_server.server import build
from as_mcp_server.settings import Settings
from as_mcp_server.texts import (
    MSG_AUTO_LIMIT,
    MSG_CANCELLED,
    MSG_CHANGED,
    MSG_LOCKOUT,
    MSG_NOT_DISCONNECTED,
    MSG_USE_BLOCK,
)
from as_mcp_server.tools_sessions import MSG_STILL_CONNECTED
from as_mcp_server.tools_users import (
    FIELDS,
    MSG_NOTHING_TO_CHANGE,
    NOTE_NEW_GROUP,
    generate_password,
    userprop_body,
)
from as_mcp_server.writes import NOTE_LIVE, NOTE_USERPROP_CACHE
from tests.conftest import LOGIN, MODES, Router, call_tool
from tests.conftest import load_fixture as fixture
from tests.test_tools_sessions import approve_after

pytestmark = pytest.mark.usefixtures("clean_env")

SERVER = {
    "deny": (False, "implicit_default"),
    "deny_web": (False, "implicit_default"),
    "admin": (False, "implicit_default"),
    "autologin": (False, "implicit_default"),
    "auth_method": ("local", "configuration"),
    "totp": (False, "configuration"),
    "allow_password_change": (True, "configuration"),
    "allow_generate_profiles": (True, "default"),
    "reroute_gw": (True, "configuration"),
}
P = "/api"
USERS = ("POST", f"{P}/users/list")
CREATE = ("POST", f"{P}/users/create")
PASSWORD = ("POST", f"{P}/auth/password/change")
SET = ("POST", f"{P}/userprop/set")
DELETE = ("POST", f"{P}/users/delete")
PROFILES_DELETE = ("POST", f"{P}/profiles/delete-user")
DISCONNECT = ("POST", f"{P}/vpn/client/disconnect")
GROUP_CREATE = ("POST", f"{P}/groups/create")
GROUP_DELETE = ("POST", f"{P}/groups/delete")
WRITES = (
    CREATE,
    PASSWORD,
    SET,
    DELETE,
    PROFILES_DELETE,
    DISCONNECT,
    GROUP_CREATE,
    GROUP_DELETE,
)


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch: pytest.MonkeyPatch):
    approval._issued.clear()
    monkeypatch.setattr(tools_sessions, "POLL_SECONDS", 0)
    monkeypatch.setattr(tools_sessions, "SETTLE_POLLS", 3)
    yield
    approval._issued.clear()


def captured(name: str) -> httpx.Response:
    """A real answer of Access Server 3.2.4, from tests/fixtures."""
    status, body = fixture(name)
    if body is None:
        return httpx.Response(status)
    return httpx.Response(status, json=body)


class FakeServer:
    """Users and groups with own values; every other value is inherited from the
    group, then from the server, and reported with its source like the real API."""

    def __init__(self, tmp_path: Path, *, mode: str = "prompt", user: str = "openvpn"):
        self.tmp_path = tmp_path
        self.users: dict[str, dict[str, Any]] = {
            "openvpn": {"own": {"admin": True}, "group": None},
            "alice": {"own": {}, "group": "staff"},
            "bob": {"own": {"deny": False}, "group": None},
            "carol": {"own": {"totp": True, "admin": True}, "group": None},
        }
        self.groups: dict[str, dict[str, Any]] = {
            "staff": {"own": {"totp": False, "allow_password_change": False}},
            "admins": {"own": {"admin": True}},
            "blocked": {"own": {"deny": True}},
            "mfa": {"own": {"totp": True}},
        }
        self.server = dict(SERVER)
        self.passwords: dict[str, str] = {}
        self.profiles: dict[str, list[str]] = {"alice": ["11", "12"]}
        self.sessions: list[dict[str, Any]] = []
        self.deaf: set[str] = set()
        self.fail: dict[tuple[str, str], Any] = {}
        self.events: list[str] = []
        self.router = Router(
            {
                LOGIN: fixture("login_ok"),
                ("GET", f"{P}/server/info"): fixture("server_info"),
                USERS: self._users_list,
                ("POST", f"{P}/groups/list"): self._groups_list,
                CREATE: self._guarded(self._create),
                PASSWORD: self._guarded(self._password),
                SET: self._guarded(self._set),
                DELETE: self._guarded(self._delete),
                ("POST", f"{P}/profiles/list"): self._profiles_list,
                PROFILES_DELETE: self._guarded(self._profiles_delete),
                ("GET", f"{P}/vpn/status"): self._status,
                DISCONNECT: self._guarded(self._disconnect),
                GROUP_CREATE: self._guarded(self._group_create),
                GROUP_DELETE: self._guarded(self._group_delete),
            }
        )
        self.settings = Settings(
            url="https://as.example:943",
            user=user,
            password="write-test-password",
            config_dir=tmp_path,
            write_tools=True,
            approval=mode,  # type: ignore[arg-type]
        )
        self.mcp = build(self.settings, transport=self.router.transport())

    # --- records as the API reports them ---

    def _prop(self, own: dict, group: str | None, name: str) -> dict[str, Any]:
        if name in own:
            return {"value": own[name], "inherited": False}
        holder = self.groups.get(group) if group else None
        if holder is not None and name in holder["own"]:
            return {
                "value": holder["own"][name],
                "inherited": True,
                "inherited_source_type": "group",
                "inherited_source_name": group,
            }
        if name not in self.server:
            return {"inherited": True}
        value, source = self.server[name]
        return {"value": value, "inherited": True, "inherited_source_type": source}

    def user(self, name: str) -> dict[str, Any]:
        entry = self.users[name]
        record: dict[str, Any] = {
            field: self._prop(entry["own"], entry["group"], field) for field in FIELDS
        }
        record["name"] = name
        record["password_defined"] = name in self.passwords
        if entry["group"] is not None:
            record["group"] = entry["group"]
        return record

    def group(self, name: str, members: bool = False) -> dict[str, Any]:
        record: dict[str, Any] = {
            field: self._prop(self.groups[name]["own"], None, field) for field in FIELDS
        }
        record["name"] = name
        names = [n for n, entry in self.users.items() if entry["group"] == name]
        record["member_count"] = len(names)
        if members:
            record["members"] = names
        return record

    def value(self, name: str, field: str) -> Any:
        record = self.user(name) if name in self.users else self.group(name)
        return record[field]["value"]

    # --- routes ---

    def _guarded(self, handler: Any) -> Any:
        def route(request: httpx.Request) -> httpx.Response:
            key = (request.method, request.url.path)
            planned = self.fail.get(key)
            if isinstance(planned, list):
                planned = planned.pop(0) if planned else None
            if isinstance(planned, Exception):
                raise planned
            if planned is not None:
                return planned
            return handler(json.loads(request.content))

        return route

    def _page(self, body: dict, records: list[dict]) -> httpx.Response:
        offset, size = body.get("offset", 0), body.get("page_size", 100)
        page = records[offset : offset + size]
        return httpx.Response(200, json={"total": len(records), "profiles": page})

    def _users_list(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        names = list(self.users)
        if "users" in body:
            names = [name for name in names if name in body["users"]]
        group = body.get("filters", {}).get("group", {}).get("value")
        if group is not None:
            names = [name for name in names if self.users[name]["group"] == group]
        return self._page(body, [self.user(name) for name in names])

    def _groups_list(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        names = list(self.groups)
        if "groups" in body:
            names = [name for name in names if name in body["groups"]]
        members = body.get("enumerate_members", False)
        return self._page(body, [self.group(name, members) for name in names])

    def _create(self, body: dict) -> httpx.Response:
        name = body["name"]
        self.events.append(f"create {name}")
        if name in self.users or name in self.groups:
            return captured("error_user_exists_400")
        own = {k: v for k, v in body.items() if k not in ("name", "group")}
        self.users[name] = {"own": own, "group": body.get("group")}
        return captured("users_create_201")

    def _password(self, body: dict) -> httpx.Response:
        name = body["username"]
        self.events.append(f"password {name}")
        if self.user(name)["auth_method"]["value"] != "local":
            return captured("error_password_not_local_403")
        if not any(character in "-_" for character in body["new_password"]):
            return captured("error_password_policy_403")
        self.passwords[name] = body["new_password"]
        return captured("password_change_ok")

    def _set(self, body: list[dict]) -> httpx.Response:
        for change in body:
            name = change["name"]
            self.events.append(f"set {name}")
            entry = self.users.get(name) or self.groups.get(name)
            if entry is None:
                return captured("error_userprop_missing_user_400")
            for key, value in change.items():
                if key == "name":
                    continue
                if key == "group":
                    entry["group"] = value
                elif value is None:
                    entry["own"].pop(key, None)
                else:
                    entry["own"][key] = value
        return httpx.Response(200, json=None)

    def _delete(self, body: dict) -> httpx.Response:
        (name,) = body["users"]
        self.events.append(f"delete {name}")
        if name not in self.users:
            return captured("error_users_delete_404")
        del self.users[name]
        return captured("users_delete_204")

    def _profiles_list(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        wanted = body.get("filters", {}).get("username", {}).get("value")
        found = [
            {"serial": serial, "username": name, "profile_type": "userlogin"}
            for name, serials in self.profiles.items()
            for serial in serials
            if wanted is None or name == wanted
        ]
        return self._page(body, found)

    def _profiles_delete(self, body: dict) -> httpx.Response:
        (name,) = body["users"]
        self.events.append(f"profiles {name}")
        if not self.profiles.pop(name, None):
            return httpx.Response(404, json={"reason": "not found"})
        return httpx.Response(200, json={"message": "The user profiles were deleted"})

    def _status(self, request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"vpn_clients": self.sessions, "vpn_daemons": {}}
        )

    def _disconnect(self, body: dict) -> httpx.Response:
        (name,) = body["users"]
        self.events.append(f"disconnect {name}")
        if not any(s["username"] == name for s in self.sessions):
            return httpx.Response(
                404, json={"reason": "Some of the clients are missing"}
            )
        if name not in self.deaf:
            self.sessions = [s for s in self.sessions if s["username"] != name]
        return httpx.Response(200, json=None)

    def _group_create(self, body: dict) -> httpx.Response:
        name = body["name"]
        self.events.append(f"group {name}")
        if name in self.users or name in self.groups:
            return captured("error_group_exists_400")
        self.groups[name] = {"own": {k: v for k, v in body.items() if k != "name"}}
        return captured("groups_create_201")

    def _group_delete(self, body: dict) -> httpx.Response:
        (name,) = body["groups"]
        self.events.append(f"group-delete {name}")
        if name not in self.groups:
            return httpx.Response(404, json={"reason": "not found"})
        del self.groups[name]
        for entry in self.users.values():
            if entry["group"] == name:
                entry["group"] = None
        return captured("groups_delete_204")

    # --- helpers for tests ---

    def connect(self, name: str, client_id: int = 0) -> None:
        self.sessions.append(
            {
                "daemon_id": "openvpn_1",
                "client_id": client_id,
                "username": name,
                "connected_since": f"2026-11-14T10:00:0{client_id}Z",
            }
        )

    async def call(self, tool: str, args: dict[str, Any], **options: Any) -> Any:
        return await call_tool(self.mcp, tool, args, **options)

    def sent(self, route: tuple[str, str]) -> list[Any]:
        return [json.loads(r.content) for r in self.router.sent(*route)]

    def written(self) -> list[tuple[str, str]]:
        """Every request that changes the server, in order."""
        return [
            (r.method, r.url.path)
            for r in self.router.requests
            if (r.method, r.url.path) in WRITES
        ]

    def audit(self) -> list[dict[str, Any]]:
        path = self.tmp_path / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text("utf-8").splitlines()]

    def files(self) -> list[Path]:
        folder = self.tmp_path / "output"
        return sorted(folder.iterdir()) if folder.is_dir() else []


def only(result: dict[str, Any]) -> dict[str, Any]:
    (item,) = result["items"]
    return item


async def schema(tool: str) -> dict[str, Any]:
    mcp = build(
        Settings(url="https://as.example:943", user="u", password="p", write_tools=True)
    )
    async with Client(mcp) as client:
        tools = {t.name: t.input_schema for t in await client.list_tools()}
    return tools[tool]


# --- pure helpers -----------------------------------------------------------------


def test_the_userprop_body_sets_changes_and_nulls_resets() -> None:
    assert userprop_body("alice", {"deny_web": True}, ["totp"]) == [
        {"name": "alice", "deny_web": True, "totp": None}
    ]


def test_a_generated_password_always_has_what_access_server_asks_for() -> None:
    seen = {generate_password() for _ in range(300)}
    assert len(seen) == 300
    for password in seen:
        assert len(password) >= 20
        assert any(c.isdigit() for c in password)
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c in "-_" for c in password)
        assert password.isascii() and password.isprintable() and " " not in password


def test_a_token_without_a_symbol_is_thrown_away(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tokens = iter(
        ["abcdefghijklmnopqrstuvwxyzABCD12", "abcdefghijklmnop-rstuvwxyzABCD12"]
    )
    monkeypatch.setattr(
        tools_users.stdlib_secrets, "token_urlsafe", lambda size: next(tokens)
    )
    assert generate_password() == "abcdefghijklmnop-rstuvwxyzABCD12"


# --- create_user ------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_a_generated_password_goes_to_a_file_and_never_to_the_model(
    tmp_path: Path, mode: str, caplog: pytest.LogCaptureFixture
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    with caplog.at_level(logging.DEBUG):
        result = await server.call(
            "create_user",
            {"users": [{"username": "dave", "generate_password": True}]},
            mode=mode,
            seen=seen,
        )
    (sent,) = server.sent(PASSWORD)
    password = sent["new_password"]
    assert sent == {"username": "dave", "new_password": password}
    assert len(password) >= 20
    item = only(result)
    assert item["outcome"] == "done" and item["reminder"] == DELIVERY_REMINDER
    path = Path(item["path"])
    assert path.read_text("utf-8") == password + "\n"
    assert path.parent == tmp_path / "output" and "-password-dave" in path.name
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert item["after"]["password_defined"] is True
    audit = (tmp_path / "audit.jsonl").read_text("utf-8")
    for place in (json.dumps(result), "\n".join(seen), audit, caplog.text):
        assert password not in place
    assert "a generated password is saved to a file" in seen[0]
    assert server.events == ["create dave", "password dave"]
    assert result["notes"] == [NOTE_LIVE]


async def test_the_tool_schema_has_no_password_parameter() -> None:
    for tool in tools_users.TOOLS:
        text = json.dumps(await schema(tool))
        assert '"password"' not in text and "new_password" not in text, tool
    item = (await schema("create_user"))["properties"]["users"]["items"]["properties"]
    assert set(item) == {
        "username",
        "group",
        "admin",
        "auth_method",
        "deny",
        "generate_password",
    }


async def test_a_new_user_item_is_named_by_username(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    await server.call("create_user", {"users": [{"username": "dave"}]})
    assert server.sent(CREATE) == [{"name": "dave"}]
    with pytest.raises(ToolError):
        await server.call("create_user", {"users": [{"name": "erin"}]})
    assert "erin" not in server.users


async def test_a_user_is_created_with_what_was_asked_and_nothing_else(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "create_user",
        {
            "users": [
                {"username": "dave", "group": "staff", "auth_method": "pam"},
                {"username": "erin", "deny": True},
            ]
        },
        seen=seen,
    )
    assert server.sent(CREATE) == [
        {"name": "dave", "group": "staff", "auth_method": "pam"},
        {"name": "erin", "deny": True},
    ]
    assert server.sent(PASSWORD) == []
    dave, erin = result["items"]
    assert dave["before"] == {
        "exists": False,
        "group_state": {
            **{name: value for name, (value, _) in SERVER.items()},
            "allow_password_change": False,
        },
    }
    assert dave["after"]["group"] == "staff" and dave["after"]["auth_method"] == "pam"
    assert dave["after"]["own"] == ["auth_method"]
    assert dave["after"]["allow_password_change"] is False  # from the group
    assert erin["after"]["deny"] is True and erin["after"]["password_defined"] is False
    text = seen[0]
    assert "Action: Create user (2 items)" in text
    assert "    group: (not set) -> staff" in text
    assert "    auth_method: (not set) -> pam" in text
    assert "    also: the user is created blocked" in text
    assert text.count("also: no password is set") == 2
    assert [line["outcome"] for line in server.audit()] == ["applied", "applied"]
    assert len({line["batch_id"] for line in server.audit()}) == 1


@pytest.mark.parametrize(
    ("item", "message"),
    [
        ({"username": "alice"}, "alice is the name of an existing user"),
        ({"username": "staff"}, "staff is the name of an existing group"),
        ({"username": "__DEFAULT__"}, "__DEFAULT__ is the server's default record"),
        ({"username": " dave"}, "starts or ends with a space"),
        ({"username": "da\nve"}, "line break, a double space or an invisible"),
        ({"username": "da" + chr(0x202E) + "ve"}, "invisible character"),
        ({"username": "dave", "group": "nobody"}, "There is no group named nobody"),
        ({"username": "dave", "group": "bob"}, "bob is a user, not a group"),
    ],
)
async def test_a_bad_new_user_refuses_the_whole_call(
    tmp_path: Path, item: dict, message: str
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError, match=message):
        await server.call("create_user", {"users": [{"username": "fine"}, item]})
    assert server.written() == [] and "fine" not in server.users
    assert [line["outcome"] for line in server.audit()] == ["failed", "failed"]


@pytest.mark.parametrize("name", ["", "x" * 129])
async def test_the_length_of_a_new_name_is_checked_by_the_schema(
    tmp_path: Path, name: str
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError):
        await server.call("create_user", {"users": [{"username": name}]})
    assert server.written() == []


async def test_a_name_that_differs_only_in_case_is_created_with_a_warning(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "create_user", {"users": [{"username": "Alice"}]}, seen=seen
    )
    assert only(result)["outcome"] == "done" and "Alice" in server.users
    assert "a user named alice exists already" in seen[0]


async def test_creating_an_admin_is_refused_in_auto_mode(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, mode="auto")
    with pytest.raises(ToolError) as error:
        await server.call(
            "create_user", {"users": [{"username": "dave", "admin": True}]}
        )
    assert str(error.value) == MSG_AUTO_LIMIT.format(
        reason="user dave would become an administrator"
    )
    assert server.written() == []
    assert server.audit()[0]["outcome"] == "refused_auto_limit"


async def test_creating_a_user_in_an_admin_group_is_refused_in_auto_mode(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path, mode="auto")
    with pytest.raises(ToolError, match="user dave would become an administrator"):
        await server.call(
            "create_user", {"users": [{"username": "dave", "group": "admins"}]}
        )
    assert server.written() == []
    # A person approving may do it, and the preview says what the group gives.
    prompt = FakeServer(tmp_path / "prompt")
    seen: list[str] = []
    await prompt.call(
        "create_user", {"users": [{"username": "dave", "group": "admins"}]}, seen=seen
    )
    assert "    admin: (not set) -> true" in seen[0]
    assert prompt.sent(CREATE) == [{"name": "dave", "group": "admins"}]


async def test_a_plain_user_is_created_in_auto_mode(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, mode="auto")
    result = await server.call(
        "create_user",
        {"users": [{"username": "dave", "group": "staff", "generate_password": True}]},
        answer="none",
    )
    assert only(result)["outcome"] == "done" and result["approval"] == "auto"
    assert "dave" in server.passwords


async def test_a_password_is_refused_for_a_user_that_would_not_sign_in_locally(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.groups["staff"]["own"]["auth_method"] = "ldap"
    for item in (
        {"username": "dave", "auth_method": "radius", "generate_password": True},
        {"username": "dave", "group": "staff", "generate_password": True},
    ):
        with pytest.raises(ToolError, match=r"would use (radius|ldap)"):
            await server.call("create_user", {"users": [item]})
    assert server.written() == [] and server.files() == []


async def test_a_failed_password_change_removes_the_file_and_reports_partial(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.fail[PASSWORD] = httpx.Response(403, json={"reason": "policy says no"})
    result = await server.call(
        "create_user",
        {
            "users": [
                {"username": "dave", "generate_password": True},
                {"username": "erin"},
            ]
        },
    )
    dave, erin = result["items"]
    assert dave["outcome"] == "partial"
    assert (
        "password was not set" in dave["detail"] and "policy says no" in dave["detail"]
    )
    assert dave["detail"].endswith("(done: user created)")
    assert "path" not in dave and server.files() == []
    assert dave["after"]["password_defined"] is False
    assert erin["outcome"] == "not attempted" and "erin" not in server.users
    assert [line["outcome"] for line in server.audit()] == ["partial"]


async def test_a_password_change_that_times_out_keeps_the_file_and_is_partial(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.fail[PASSWORD] = httpx.ReadTimeout("slow")
    result = await server.call(
        "create_user", {"users": [{"username": "dave", "generate_password": True}]}
    )
    item = only(result)
    assert item["outcome"] == "partial"
    assert "the password in the file may or may not be set" in item["detail"]
    (path,) = server.files()
    assert item["path"] == str(path) and item["reminder"] == DELIVERY_REMINDER
    assert len(server.sent(PASSWORD)) == 1  # never repeated


async def test_a_password_file_that_cannot_be_written_sets_no_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer(tmp_path)

    def refuse(*args: Any, **kwargs: Any) -> Path:
        raise tools_users.OutputError("Cannot write to the output folder: disk full.")

    monkeypatch.setattr(tools_users, "write_secret_file", refuse)
    result = await server.call(
        "create_user", {"users": [{"username": "dave", "generate_password": True}]}
    )
    item = only(result)
    assert item["outcome"] == "partial" and "no password was set" in item["detail"]
    assert server.sent(PASSWORD) == [] and "dave" in server.users


async def test_the_output_folder_is_probed_only_when_a_password_is_generated(
    tmp_path: Path,
) -> None:
    (tmp_path / "output").write_text("a file where the folder should be")
    server = FakeServer(tmp_path)
    result = await server.call("create_user", {"users": [{"username": "dave"}]})
    assert only(result)["outcome"] == "done"
    with pytest.raises(ToolError, match="Cannot write to the output folder"):
        await server.call(
            "create_user", {"users": [{"username": "erin", "generate_password": True}]}
        )
    assert "erin" not in server.users


async def test_a_declined_create_writes_nothing(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await server.call(
            "create_user",
            {"users": [{"username": "dave", "generate_password": True}]},
            answer="decline",
        )
    assert str(error.value) == MSG_CANCELLED
    assert server.written() == [] and server.files() == []


async def test_a_user_created_by_someone_else_during_the_prompt_is_not_overwritten(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)

    def taken() -> None:
        server.users["dave"] = {"own": {}, "group": None}

    result = await approve_after(
        server, taken, "create_user", {"users": [{"username": "dave"}]}
    )
    item = only(result)
    assert item["outcome"] == "failed"
    assert "dave is the name of an existing user" in item["detail"]
    assert server.sent(CREATE) == []


# --- update_user ------------------------------------------------------------------


async def test_null_and_omitted_fields_are_not_sent(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "update_user", {"usernames": ["alice"], "deny_web": True}, seen=seen
    )
    assert server.sent(SET) == [[{"name": "alice", "deny_web": True}]]
    item = only(result)
    assert item["outcome"] == "done"
    assert item["before"]["deny_web"] is False and item["after"]["deny_web"] is True
    assert item["after"]["own"] == ["deny_web"]
    assert "    deny_web: false -> true" in seen[0]
    assert "totp" not in seen[0] and "group:" not in seen[0]
    assert result["notes"] == [NOTE_USERPROP_CACHE]
    await server.call(
        "update_user",
        {"usernames": ["alice"], "deny_web": None, "totp": True, "group": None},
    )
    assert server.sent(SET)[1] == [{"name": "alice", "totp": True}]


async def test_update_user_refuses_deny_true_and_points_to_block_user(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await server.call("update_user", {"usernames": ["alice"], "deny": True})
    assert str(error.value) == MSG_USE_BLOCK
    assert server.router.sent(*SET) == [] and server.router.sent(*USERS) == []
    server.users["alice"]["own"]["deny"] = True
    result = await server.call("update_user", {"usernames": ["alice"], "deny": False})
    assert server.sent(SET) == [[{"name": "alice", "deny": False}]]
    assert only(result)["after"]["deny"] is False


async def test_a_call_that_changes_nothing_is_refused(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    for args in (
        {"usernames": ["alice"]},
        {"usernames": ["alice"], "reset_to_inherited": []},
    ):
        with pytest.raises(ToolError) as error:
            await server.call("update_user", args)
        assert str(error.value) == MSG_NOTHING_TO_CHANGE
    with pytest.raises(ToolError) as error:
        await server.call("update_group", {"name": "staff"})
    assert str(error.value) == MSG_NOTHING_TO_CHANGE
    assert server.router.sent(*USERS) == []


async def test_a_field_both_set_and_reset_is_refused(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError, match="totp is both set and reset"):
        await server.call(
            "update_user",
            {"usernames": ["alice"], "totp": True, "reset_to_inherited": ["totp"]},
        )
    with pytest.raises(ToolError, match="admin is both set and reset"):
        await server.call(
            "update_group",
            {"name": "staff", "admin": False, "reset_to_inherited": ["admin"]},
        )
    assert server.written() == []


async def test_reset_to_inherited_sends_null_and_previews_the_inherited_value(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.users["alice"]["own"]["totp"] = True
    seen: list[str] = []
    result = await server.call(
        "update_user",
        {"usernames": ["alice"], "reset_to_inherited": ["totp", "totp"]},
        seen=seen,
    )
    assert server.sent(SET) == [[{"name": "alice", "totp": None}]]
    assert "    totp: true -> inherited (staff value: false)" in seen[0]
    item = only(result)
    assert item["before"]["own"] == ["totp"] and item["after"]["own"] == []
    assert item["after"]["totp"] is False


async def test_a_reset_of_allow_password_change_previews_the_group_value(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.users["alice"]["own"]["allow_password_change"] = True
    server.users["bob"]["own"]["allow_password_change"] = False
    seen: list[str] = []
    await server.call(
        "update_user",
        {
            "usernames": ["alice", "bob"],
            "reset_to_inherited": ["allow_password_change"],
        },
        seen=seen,
    )
    text = seen[0]
    assert "allow_password_change: true -> inherited (staff value: false)" in text
    assert "allow_password_change: false -> inherited (server-wide value: true)" in text
    assert server.value("alice", "allow_password_change") is False
    assert server.value("bob", "allow_password_change") is True


async def test_a_reset_with_an_unknown_server_wide_value_is_previewed_as_unknown(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    # Every record sets the field itself, so nobody shows what the server would give.
    for entry in (*server.users.values(), *server.groups.values()):
        entry["own"]["allow_generate_profiles"] = False
    seen: list[str] = []
    result = await server.call(
        "update_user",
        {"usernames": ["bob"], "reset_to_inherited": ["allow_generate_profiles"]},
        seen=seen,
    )
    assert (
        "allow_generate_profiles: false -> inherited (server-wide value unknown)"
        in seen[0]
    )
    assert only(result)["outcome"] == "done"
    assert server.value("bob", "allow_generate_profiles") is True


async def test_reroute_gw_takes_the_three_words_and_no_boolean(tmp_path: Path) -> None:
    for tool in ("update_user", "create_group", "update_group"):
        prop = (await schema(tool))["properties"]["reroute_gw"]
        assert json.dumps(prop).count('"disable", "dns_only", "global"') == 1, tool
    server = FakeServer(tmp_path)
    for bad in (True, "full"):
        with pytest.raises(ToolError):
            await server.call(
                "update_user", {"usernames": ["alice"], "reroute_gw": bad}
            )
    assert server.written() == []


async def test_the_reroute_gw_description_says_global_follows_the_server_setting() -> (
    None
):
    for tool in ("update_user", "create_group", "update_group"):
        description = (await schema(tool))["properties"]["reroute_gw"]["description"]
        assert "vpn.client.routing.reroute_gw" in description, tool
        assert "not the same as" in description, tool


async def test_an_inherited_reroute_gw_of_true_set_to_global_is_not_a_verify_mismatch(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "update_user", {"usernames": ["bob"], "reroute_gw": "global"}, seen=seen
    )
    item = only(result)
    assert item["outcome"] == "done" and item["detail"] is None
    assert (
        item["before"]["reroute_gw"] is True and item["after"]["reroute_gw"] == "global"
    )
    assert "    reroute_gw: true -> global" in seen[0]
    seen.clear()
    await server.call(
        "update_user",
        {"usernames": ["bob"], "reset_to_inherited": ["reroute_gw"]},
        seen=seen,
    )
    assert "reroute_gw: global -> inherited (server-wide value: true)" in seen[0]
    assert server.value("bob", "reroute_gw") is True


async def test_group_cannot_be_reset_and_script_fields_are_not_parameters() -> None:
    for tool in ("update_user", "update_group"):
        properties = (await schema(tool))["properties"]
        reset = json.dumps(properties["reset_to_inherited"])
        assert '"group"' not in reset and '"reroute_gw"' in reset
        for name in properties:
            assert not name.startswith("cli_script") and name not in (
                "cc_commands",
                "totp_secret",
                "password",
                "bypass_subnets",
                "password_strength",
            )
    assert "group" not in (await schema("update_group"))["properties"]
    assert "group" not in (await schema("create_group"))["properties"]


async def test_a_move_to_another_group_shows_everything_that_changes(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "update_user", {"usernames": ["alice"], "group": "mfa"}, seen=seen
    )
    assert server.sent(SET) == [[{"name": "alice", "group": "mfa"}]]
    text = seen[0]
    assert "    group: staff -> mfa" in text
    assert "    totp: false -> true" in text
    assert "    allow_password_change: false -> true" in text
    assert "deny:" not in text
    item = only(result)
    assert item["after"]["group"] == "mfa" and item["after"]["totp"] is True
    assert "warnings" not in item


@pytest.mark.parametrize(
    ("group", "message"),
    [
        ("nobody", "There is no group named nobody"),
        ("bob", "bob is a user, not a group"),
        ("__DEFAULT__", "__DEFAULT__ is the server's default record"),
    ],
)
async def test_a_move_into_something_that_is_not_a_group_is_refused(
    tmp_path: Path, group: str, message: str
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError, match=message):
        await server.call("update_user", {"usernames": ["alice"], "group": group})
    assert server.written() == []


async def test_a_move_into_a_deny_group_names_the_connected_user_as_not_disconnected(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.connect("alice")
    seen: list[str] = []
    result = await server.call(
        "update_user", {"usernames": ["alice", "carol"], "group": "blocked"}, seen=seen
    )
    line = MSG_NOT_DISCONNECTED.format(name="alice")
    assert f"    also: {line}" in seen[0]
    assert "    deny: false -> true" in seen[0]
    alice, carol = result["items"]
    assert alice["outcome"] == "done" and alice["warnings"] == [line]
    assert alice["before"]["sessions"] == [
        {"daemon_id": "openvpn_1", "client_id": 0, "username": "alice"}
    ]
    assert "warnings" not in carol  # blocked too, but has no session
    assert MSG_NOT_DISCONNECTED.format(name="carol") not in seen[0]
    assert server.sent(DISCONNECT) == []  # update_user never disconnects
    # bob sets deny=false himself, so the group's block does not reach him
    server.connect("bob", 1)
    seen.clear()
    result = await server.call(
        "update_user", {"usernames": ["bob"], "group": "blocked"}, seen=seen
    )
    assert "also:" not in seen[0] and "warnings" not in only(result)


async def test_resetting_deny_to_an_inherited_true_names_the_connected_user(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.users["bob"]["group"] = "blocked"
    server.connect("bob")
    seen: list[str] = []
    result = await server.call(
        "update_user", {"usernames": ["bob"], "reset_to_inherited": ["deny"]}, seen=seen
    )
    line = MSG_NOT_DISCONNECTED.format(name="bob")
    assert "deny: false -> inherited (blocked value: true)" in seen[0]
    assert f"also: {line}" in seen[0]
    assert only(result)["warnings"] == [line]
    assert server.value("bob", "deny") is True


async def test_a_session_that_begins_during_the_prompt_is_a_changed_state(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await approve_after(
            server,
            lambda: server.connect("alice"),
            "update_user",
            {"usernames": ["alice"], "group": "blocked"},
        )
    assert str(error.value) == MSG_CHANGED and server.sent(SET) == []


async def test_a_group_that_changes_during_the_prompt_is_a_changed_state(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)

    def block_the_group() -> None:
        server.groups["mfa"]["own"]["deny"] = True

    with pytest.raises(ToolError) as error:
        await approve_after(
            server,
            block_the_group,
            "update_user",
            {"usernames": ["alice"], "group": "mfa"},
        )
    assert str(error.value) == MSG_CHANGED and server.sent(SET) == []


async def test_resetting_mfa_to_an_off_group_value_is_refused_in_auto_mode(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path, mode="auto")
    server.users["alice"]["own"]["totp"] = True
    with pytest.raises(ToolError, match="MFA would be switched off for user alice"):
        await server.call(
            "update_user", {"usernames": ["alice"], "reset_to_inherited": ["totp"]}
        )
    server.users["dave"] = {"own": {}, "group": "mfa"}
    with pytest.raises(ToolError, match="MFA would be switched off for user dave"):
        await server.call("update_user", {"usernames": ["dave"], "group": "staff"})
    # carol sets totp herself, so the move does not touch it
    assert (
        only(
            await server.call("update_user", {"usernames": ["carol"], "group": "staff"})
        )["outcome"]
        == "done"
    )
    assert server.sent(SET) == [[{"name": "carol", "group": "staff"}]]


@pytest.mark.parametrize(
    ("args", "reason"),
    [
        ({"admin": True}, "user alice would become an administrator"),
        ({"group": "admins"}, "user alice would become an administrator"),
        ({"autologin": True}, "autologin would be switched on for user alice"),
        (
            {"auth_method": "pam"},
            "the authentication method of user alice would change",
        ),
    ],
)
async def test_what_auto_mode_never_does_to_a_user(
    tmp_path: Path, args: dict, reason: str
) -> None:
    server = FakeServer(tmp_path, mode="auto")
    with pytest.raises(ToolError) as error:
        await server.call("update_user", {"usernames": ["alice", "bob"], **args})
    assert str(error.value) == MSG_AUTO_LIMIT.format(reason=reason)
    assert server.written() == []
    assert {line["outcome"] for line in server.audit()} == {"refused_auto_limit"}


async def test_auto_mode_makes_a_harmless_change_without_asking(tmp_path: Path) -> None:
    server = FakeServer(tmp_path, mode="auto")
    result = await server.call(
        "update_user",
        {"usernames": ["alice"], "totp": True, "allow_generate_profiles": False},
        answer="none",
    )
    assert only(result)["outcome"] == "done"
    assert server.sent(SET) == [
        [{"name": "alice", "totp": True, "allow_generate_profiles": False}]
    ]


async def test_moving_the_own_account_to_another_group_is_refused(
    tmp_path: Path,
) -> None:
    for mode in ("prompt", "auto"):
        server = FakeServer(tmp_path / mode, mode=mode)
        with pytest.raises(ToolError) as error:
            await server.call(
                "update_user", {"usernames": ["openvpn"], "group": "staff"}
            )
        assert str(error.value) == MSG_LOCKOUT.format(name="openvpn")
        assert server.written() == []
        assert server.audit()[0]["outcome"] == "refused_lockout"


async def test_removing_admin_from_the_own_account_is_refused_also_through_reset(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    for args in (
        {"admin": False},
        {"reset_to_inherited": ["admin"]},
        {"deny_web": True},
        {"auth_method": "ldap"},
        {"usernames": ["alice", "OpenVPN"], "admin": False},
    ):
        with pytest.raises(ToolError) as error:
            await server.call("update_user", {"usernames": ["openvpn"], **args})
        assert str(error.value) in (
            MSG_LOCKOUT.format(name="openvpn"),
            "There is no user named OpenVPN on this Access Server (names are "
            "case-sensitive).",
        )
    assert server.written() == []
    # A change that keeps the account working is made.
    result = await server.call("update_user", {"usernames": ["openvpn"], "totp": True})
    assert only(result)["outcome"] == "done"


async def test_a_group_name_as_a_user_target_is_refused(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    for tool, args in (
        ("delete_user", {"usernames": ["staff"]}),
        ("update_user", {"usernames": ["staff"], "totp": True}),
    ):
        with pytest.raises(ToolError) as error:
            await server.call(tool, args)
        assert str(error.value) == "staff is a group, not a user."
    assert server.written() == [] and "staff" in server.groups


async def test_the_default_record_is_refused_as_a_target(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    for tool, args in (
        ("delete_user", {"usernames": ["__DEFAULT__"]}),
        ("update_user", {"usernames": ["__DEFAULT__"], "totp": True}),
        ("update_group", {"name": "__DEFAULT__", "totp": True}),
        ("delete_group", {"name": "__DEFAULT__"}),
        ("create_group", {"name": "__DEFAULT__"}),
    ):
        with pytest.raises(
            ToolError, match="__DEFAULT__ is the server's default record"
        ):
            await server.call(tool, args)
    assert server.written() == []


async def test_a_user_in_a_group_that_does_not_exist_can_still_be_changed(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.users["bob"]["group"] = "ghost-group"
    server.users["bob"]["own"]["totp"] = True
    seen: list[str] = []
    result = await server.call(
        "update_user", {"usernames": ["bob"], "reset_to_inherited": ["totp"]}, seen=seen
    )
    item = only(result)
    assert item["outcome"] == "done" and item["after"]["group"] == "ghost-group"
    assert "totp: true -> inherited (server-wide value: false)" in seen[0]
    assert "group_state" not in item["before"]


async def test_a_write_the_server_does_not_keep_is_partial(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    server.fail[SET] = httpx.Response(200, json=None)  # answers yes, stores nothing
    result = await server.call("update_user", {"usernames": ["alice"], "totp": True})
    item = only(result)
    assert item["outcome"] == "partial"
    assert "Access Server does not show totp as written" in item["detail"]


async def test_one_change_for_twenty_users_is_one_approval_and_twenty_audit_lines(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    names = [f"user{number:02d}" for number in range(20)]
    for name in names:
        server.users[name] = {"own": {}, "group": None}
    seen: list[str] = []
    result = await server.call(
        "update_user", {"usernames": names, "allow_generate_profiles": False}, seen=seen
    )
    assert len(seen) == 1 and "Action: Update user (20 items)" in seen[0]
    assert [item["outcome"] for item in result["items"]] == ["done"] * 20
    lines = server.audit()
    assert [line["target"] for line in lines] == names
    assert {line["outcome"] for line in lines} == {"applied"}
    assert len({line["batch_id"] for line in lines}) == 1 and lines[0]["batch_id"]
    assert len(server.sent(SET)) == 20  # one request per user, in order


# --- delete_user ------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_delete_removes_profiles_then_the_user_then_disconnects(
    tmp_path: Path, mode: str
) -> None:
    server = FakeServer(tmp_path)
    server.connect("alice")
    seen: list[str] = []
    result = await server.call(
        "delete_user", {"usernames": ["alice"]}, mode=mode, seen=seen
    )
    assert server.events == ["profiles alice", "delete alice", "disconnect alice"]
    assert server.sent(PROFILES_DELETE) == [{"users": ["alice"]}]
    assert server.sent(DELETE) == [{"users": ["alice"]}]
    text = seen[0]
    assert "Action: Delete user (1 item)" in text
    assert "    user: exists -> deleted" in text
    assert "    also: deletes 2 connection profile(s)" in text
    assert "    also: disconnects 1 active session(s)" in text
    assert "    also: cannot be undone" in text
    item = only(result)
    assert item["outcome"] == "done"
    assert item["deleted_profiles"] == 2 and item["disconnected"] == 1
    assert item["before"]["profiles"] == ["11", "12"]
    assert item["after"] == {"exists": False, "profiles": [], "sessions": []}
    assert "alice" not in server.users and server.sessions == []
    assert result["notes"] == [NOTE_LIVE]


async def test_a_user_without_profiles_is_deleted_without_the_profile_request(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    result = await server.call("delete_user", {"usernames": ["bob"]})
    assert server.events == ["delete bob"]
    item = only(result)
    assert item["outcome"] == "done"
    assert item["deleted_profiles"] == 0 and item["disconnected"] == 0


async def test_a_delete_that_stops_after_the_profiles_is_partial(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.fail[DELETE] = httpx.Response(500, json={"reason": "database is busy"})
    result = await server.call("delete_user", {"usernames": ["alice", "bob"]})
    alice, bob = result["items"]
    assert alice["outcome"] == "partial"
    assert alice["detail"].endswith("(done: connection profiles deleted)")
    assert alice["after"]["profiles"] == [] and "alice" in server.users
    assert bob["outcome"] == "not attempted" and "bob" in server.users


async def test_a_delete_whose_first_request_fails_is_failed_not_partial(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.fail[DELETE] = httpx.Response(500, json={"reason": "database is busy"})
    result = await server.call("delete_user", {"usernames": ["bob"]})
    assert only(result)["outcome"] == "failed" and "bob" in server.users


async def test_a_session_that_survives_the_delete_is_reported(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    server.connect("bob")
    server.deaf.add("bob")
    result = await server.call("delete_user", {"usernames": ["bob"]})
    item = only(result)
    assert item["outcome"] == "partial" and "bob" not in server.users
    assert MSG_STILL_CONNECTED in item["detail"]
    assert "user deleted" in item["detail"]


async def test_a_failed_disconnect_after_the_delete_names_the_tool_to_call(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.connect("bob")
    server.fail[DISCONNECT] = httpx.Response(500, json={"reason": "busy"})
    result = await server.call("delete_user", {"usernames": ["bob"]})
    item = only(result)
    assert item["outcome"] == "partial"
    assert "Call disconnect_vpn_sessions for this user." in item["detail"]
    assert item["detail"].endswith("(done: user deleted)")


async def test_the_own_account_cannot_be_deleted(tmp_path: Path) -> None:
    for mode in ("prompt", "auto"):
        server = FakeServer(tmp_path / mode, mode=mode)
        with pytest.raises(ToolError) as error:
            await server.call("delete_user", {"usernames": ["bob", "openvpn"]})
        assert str(error.value) == MSG_LOCKOUT.format(name="openvpn")
        assert server.written() == []


async def test_a_delete_is_allowed_in_auto_mode_and_declined_deletes_nothing(
    tmp_path: Path,
) -> None:
    auto = FakeServer(tmp_path / "auto", mode="auto")
    result = await auto.call("delete_user", {"usernames": ["carol"]}, answer="none")
    assert only(result)["outcome"] == "done" and "carol" not in auto.users
    prompt = FakeServer(tmp_path / "prompt")
    with pytest.raises(ToolError) as error:
        await prompt.call("delete_user", {"usernames": ["alice"]}, answer="no")
    assert str(error.value) == MSG_CANCELLED
    assert prompt.written() == [] and prompt.profiles == {"alice": ["11", "12"]}


async def test_a_profile_issued_during_the_prompt_stops_the_delete(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as error:
        await approve_after(
            server,
            lambda: server.profiles["alice"].append("13"),
            "delete_user",
            {"usernames": ["alice"]},
        )
    assert str(error.value) == MSG_CHANGED and "alice" in server.users


async def test_a_missing_user_refuses_the_whole_delete(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError, match="There is no user named Alice"):
        await server.call("delete_user", {"usernames": ["bob", "Alice"]})
    assert server.written() == []


# --- groups -----------------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_a_group_is_created_with_the_given_fields_and_a_restart_warning(
    tmp_path: Path, mode: str
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "create_group",
        {"name": "ops", "totp": True, "reroute_gw": "dns_only", "deny": None},
        mode=mode,
        seen=seen,
    )
    assert server.sent(GROUP_CREATE) == [
        {"name": "ops", "totp": True, "reroute_gw": "dns_only"}
    ]
    text = seen[0]
    assert "Action: Create group (1 item)" in text
    assert "    totp: (not set) -> true" in text
    assert "    reroute_gw: (not set) -> dns_only" in text
    assert "cannot connect to the VPN until Access Server is restarted" in text
    item = only(result)
    assert item["outcome"] == "done" and item["before"] == {"exists": False}
    assert item["after"]["totp"] is True and item["after"]["own"] == [
        "totp",
        "reroute_gw",
    ]
    assert result["notes"] == [NOTE_NEW_GROUP]
    assert "restarted" in NOTE_NEW_GROUP


async def test_an_empty_group_is_created_and_says_everything_is_inherited(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    await server.call("create_group", {"name": "ops"}, seen=seen)
    assert server.sent(GROUP_CREATE) == [{"name": "ops"}]
    assert "also: every value is inherited from the server" in seen[0]


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("staff", "staff is the name of an existing group"),
        ("alice", "alice is the name of an existing user"),
        ("ops ", "starts or ends with a space"),
    ],
)
async def test_a_group_name_that_is_taken_or_bad_is_refused(
    tmp_path: Path, name: str, message: str
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError, match=message):
        await server.call("create_group", {"name": name})
    assert server.written() == []


@pytest.mark.parametrize(
    ("tool", "args", "reason"),
    [
        (
            "create_group",
            {"name": "ops", "admin": True},
            "would become an administrator",
        ),
        (
            "create_group",
            {"name": "ops", "autologin": True},
            "autologin would be switched",
        ),
        (
            "update_group",
            {"name": "staff", "admin": True},
            "would become an administrator",
        ),
        ("update_group", {"name": "mfa", "totp": False}, "MFA would be switched off"),
        (
            "update_group",
            {"name": "mfa", "reset_to_inherited": ["totp"]},
            "MFA would be switched off",
        ),
        (
            "update_group",
            {"name": "staff", "auth_method": "saml"},
            "authentication method",
        ),
    ],
)
async def test_what_auto_mode_never_does_to_a_group(
    tmp_path: Path, tool: str, args: dict, reason: str
) -> None:
    server = FakeServer(tmp_path, mode="auto")
    with pytest.raises(ToolError, match=reason):
        await server.call(tool, args)
    assert server.written() == []
    # The same change goes through when a person approves it.
    prompt = FakeServer(tmp_path / "prompt")
    assert only(await prompt.call(tool, args))["outcome"] == "done"


async def test_a_group_change_reaches_the_group_and_is_previewed(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "update_group",
        {
            "name": "staff",
            "totp": True,
            "reset_to_inherited": ["allow_password_change"],
        },
        seen=seen,
    )
    assert server.sent(SET) == [
        [{"name": "staff", "totp": True, "allow_password_change": None}]
    ]
    text = seen[0]
    assert "Action: Update group (1 item)" in text
    assert "    totp: false -> true" in text
    assert "allow_password_change: false -> inherited (server-wide value: true)" in text
    assert "also: applies to every member that does not set the value itself" in text
    item = only(result)
    assert item["outcome"] == "done" and item["after"]["own"] == ["totp"]
    assert server.value("alice", "totp") is True  # the member follows
    assert result["notes"] == [NOTE_USERPROP_CACHE]


async def test_blocking_the_own_group_is_refused_when_the_own_account_inherits_it(
    tmp_path: Path,
) -> None:
    for mode in ("prompt", "auto"):
        server = FakeServer(tmp_path / mode, mode=mode)
        server.users["openvpn"]["group"] = "staff"
        for args in ({"deny": True}, {"deny_web": True}, {"admin": False}):
            before = len(server.audit())
            if args == {"admin": False}:
                # The own account sets admin itself: the group value does not reach it.
                result = await server.call("update_group", {"name": "staff", **args})
                assert only(result)["outcome"] == "done"
                continue
            with pytest.raises(ToolError) as error:
                await server.call("update_group", {"name": "staff", **args})
            assert str(error.value) == MSG_LOCKOUT.format(name="openvpn")
            assert server.audit()[before]["outcome"] == "refused_lockout"
        assert server.sent(SET) == [[{"name": "staff", "admin": False}]]


async def test_blocking_the_own_group_is_allowed_when_the_own_account_sets_deny_itself(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.users["openvpn"] = {
        "own": {"admin": True, "deny": False, "deny_web": False},
        "group": "staff",
    }
    result = await server.call("update_group", {"name": "staff", "deny": True})
    assert only(result)["outcome"] == "done"
    assert server.value("openvpn", "deny") is False
    assert server.value("alice", "deny") is True


async def test_a_group_block_names_only_connected_members_that_inherit_it(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.users["bob"]["group"] = "staff"  # sets deny=false himself
    server.users["dave"] = {"own": {}, "group": "staff"}  # inherits, not connected
    server.connect("alice")
    server.connect("bob", 1)
    server.connect("carol", 2)  # not a member
    seen: list[str] = []
    result = await server.call(
        "update_group", {"name": "staff", "deny": True}, seen=seen
    )
    line = MSG_NOT_DISCONNECTED.format(name="alice")
    assert f"    also: {line}" in seen[0]
    for other in ("bob", "carol", "dave"):
        assert MSG_NOT_DISCONNECTED.format(name=other) not in seen[0]
    item = only(result)
    assert item["outcome"] == "done" and item["warnings"] == [line]
    assert item["before"]["member_sessions"] == [
        {"daemon_id": "openvpn_1", "client_id": 0, "username": "alice"},
        {"daemon_id": "openvpn_1", "client_id": 1, "username": "bob"},
    ]
    assert server.sent(DISCONNECT) == []
    assert len(server.sessions) == 3


async def test_a_group_change_that_cannot_block_reads_no_sessions(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    result = await server.call("update_group", {"name": "staff", "deny": False})
    assert "member_sessions" not in only(result)["before"]
    assert server.router.sent("GET", f"{P}/vpn/status") == []


async def test_a_reset_of_a_group_block_to_a_blocking_server_value_names_the_members(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.groups["staff"]["own"]["deny"] = False
    server.server["deny"] = (True, "configuration")
    server.users["openvpn"]["own"]["deny"] = False
    server.connect("alice")
    seen: list[str] = []
    result = await server.call(
        "update_group", {"name": "staff", "reset_to_inherited": ["deny"]}, seen=seen
    )
    assert "deny: false -> inherited (server-wide value: true)" in seen[0]
    assert only(result)["warnings"] == [MSG_NOT_DISCONNECTED.format(name="alice")]


async def test_a_user_name_as_a_group_target_is_refused(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    for tool, args in (
        ("update_group", {"name": "alice", "totp": True}),
        ("delete_group", {"name": "alice"}),
    ):
        with pytest.raises(ToolError) as error:
            await server.call(tool, args)
        assert str(error.value) == "alice is a user, not a group."
    with pytest.raises(ToolError, match="There is no group named Staff"):
        await server.call("delete_group", {"name": "Staff"})
    assert server.written() == [] and "alice" in server.users


@pytest.mark.parametrize("mode", MODES)
async def test_a_group_delete_lists_the_members_that_lose_it(
    tmp_path: Path, mode: str
) -> None:
    server = FakeServer(tmp_path)
    server.users["bob"]["group"] = "staff"
    seen: list[str] = []
    result = await server.call("delete_group", {"name": "staff"}, mode=mode, seen=seen)
    text = seen[0]
    assert "Action: Delete group (1 item)" in text
    assert "    group: exists -> deleted" in text
    assert "    also: members that lose this group: alice, bob" in text
    assert "keep their running VPN sessions" in text
    assert "    also: the group's access list is deleted" in text
    assert "    also: cannot be undone" in text
    assert server.sent(GROUP_DELETE) == [{"groups": ["staff"]}]
    item = only(result)
    assert item["outcome"] == "done" and item["after"] == {"exists": False}
    assert item["before"]["members"] == ["alice", "bob"]
    assert item["members_without_group"] == ["alice", "bob"]
    assert server.users["alice"]["group"] is None and "staff" not in server.groups
    assert result["notes"] == [NOTE_LIVE]


async def test_a_long_member_list_is_cut_in_the_preview(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    for number in range(25):
        server.users[f"m{number:02d}"] = {"own": {}, "group": "mfa"}
    server.users["evil\nname"] = {"own": {}, "group": "mfa"}
    seen: list[str] = []
    result = await server.call("delete_group", {"name": "mfa"}, seen=seen)
    wanted = "members that lose this group"
    (line,) = [text for text in seen[0].splitlines() if wanted in text]
    assert line.endswith("m18 and 6 more")
    assert "evil name, m00, m01" in line
    assert len(only(result)["members_without_group"]) == 26


async def test_long_member_names_never_push_the_count_out_of_the_preview(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    for number in range(12):
        server.users[f"{number:02d}-" + "n" * 90] = {"own": {}, "group": "mfa"}
    seen: list[str] = []
    await server.call("delete_group", {"name": "mfa"}, seen=seen)
    wanted = "members that lose this group"
    (line,) = [text for text in seen[0].splitlines() if wanted in text]
    assert line.endswith(" and 9 more") and len(line) < 300
    assert line.count("nnnn" + chr(0x2026)) == 3  # each name cut to 60 characters


async def test_a_group_without_members_says_so(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    await server.call("delete_group", {"name": "admins"}, seen=seen)
    assert "also: the group has no members" in seen[0]


async def test_the_own_group_cannot_be_deleted(tmp_path: Path) -> None:
    for mode in ("prompt", "auto"):
        server = FakeServer(tmp_path / mode, mode=mode)
        server.users["openvpn"]["group"] = "staff"
        with pytest.raises(ToolError) as error:
            await server.call("delete_group", {"name": "staff"})
        assert str(error.value) == MSG_LOCKOUT.format(name="openvpn")
        assert server.written() == [] and "staff" in server.groups


async def test_a_group_delete_is_allowed_in_auto_mode_also_with_mfa_members(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path, mode="auto")
    server.users["alice"]["group"] = "mfa"
    result = await server.call("delete_group", {"name": "mfa"}, answer="none")
    assert only(result)["outcome"] == "done" and "mfa" not in server.groups


async def test_a_member_that_joins_during_the_prompt_stops_the_group_delete(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)

    def join() -> None:
        server.users["bob"]["group"] = "staff"

    with pytest.raises(ToolError) as error:
        await approve_after(server, join, "delete_group", {"name": "staff"})
    assert str(error.value) == MSG_CHANGED and "staff" in server.groups


async def test_the_user_and_group_tools_exist_only_in_write_mode(
    tmp_path: Path,
) -> None:
    async with Client(FakeServer(tmp_path).mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    destructive = {"delete_user", "delete_group"}
    for name in tools_users.TOOLS:
        annotations = tools[name].annotations
        assert annotations.read_only_hint is False, name
        assert annotations.idempotent_hint is False, name
        assert annotations.destructive_hint is (name in destructive), name
        assert tools[name].meta["fastmcp"]["tags"] == ["write"]
    assert "restarted" in tools["create_group"].description
    read_only = build(Settings(url="https://as.example:943", user="u", password="p"))
    async with Client(read_only) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert not names & set(tools_users.TOOLS)
