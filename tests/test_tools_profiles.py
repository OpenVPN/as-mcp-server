"""Connection profiles and download links: the secret goes to a file, never to the
agent, and nothing is created or deleted without the administrator's yes."""

from __future__ import annotations

import json
import logging
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.elicitation import ElicitResult
from fastmcp.exceptions import ToolError

from as_mcp_server import approval, outputs, tools_profiles
from as_mcp_server.outputs import DELIVERY_REMINDER
from as_mcp_server.preview import clean
from as_mcp_server.server import build
from as_mcp_server.settings import Settings
from as_mcp_server.texts import MSG_AUTO_LIMIT, MSG_CANCELLED, MSG_CHANGED
from as_mcp_server.writes import NOTE_LIVE
from tests.conftest import FIXTURES, LOGIN, MODES, Router, body_of, call_tool
from tests.conftest import load_fixture as fixture
from tests.test_effective import own as own_value
from tests.test_effective import record
from tests.test_writes import users_route

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file modes do not exist on Windows"
)

pytestmark = pytest.mark.usefixtures("clean_env")

SERVER_INFO = ("GET", "/api/server/info")
USERS = ("POST", "/api/users/list")
GROUPS = ("POST", "/api/groups/list")
LIST = ("POST", "/api/profiles/list")
CREATE = ("POST", "/api/profiles/create")
TOKEN_URL = ("POST", "/api/token-url")
DELETE = ("POST", "/api/profiles/delete")
DELETE_USER = ("POST", "/api/profiles/delete-user")
PROFILE_BODY = (FIXTURES / "profile_create_201.txt").read_text(encoding="utf-8")
LINK = fixture("token_url_ok")[1]
NOW = datetime(2026, 11, 13, 12, 0, 0, tzinfo=UTC)
FIRST_NEW_SERIAL = 9000000000000000001
SECRETS = ("PRIVATE KEY", "TESTKEY", "TESTSTATICKEY", "TESTLINKTOKEN", "import-profile")


@pytest.fixture(autouse=True)
def fixed_state(monkeypatch: pytest.MonkeyPatch):
    approval._issued.clear()
    monkeypatch.setattr(tools_profiles, "_now", lambda: NOW)
    yield
    approval._issued.clear()


def profile(serial: str, username: str, kind: str = "userlogin", comment: str = ""):
    return {
        "serial": serial,
        "username": username,
        "profile_type": kind,
        "common_name": username,
        "comment": comment,
        "tls_crypt_v2": False,
        "last_used": None,
    }


class FakeServer:
    """An Access Server that keeps users and profiles in memory."""

    def __init__(self, tmp_path: Path, *, mode: str = "prompt", **settings: Any):
        self.tmp_path = tmp_path
        self.users = [
            record("openvpn", admin=own_value(True)),
            record("alice", autologin=own_value(True)),
            record("bob"),
            record("Bob"),
            record("жанна"),
        ]
        self.groups = [record("staff")]
        self.profiles = [
            profile("1810972200425098125", "alice", comment="laptop"),
            profile("20", "bob"),
            profile("21", "bob", comment="phone"),
            profile("30", "ghost", "autologin"),
        ]
        self.delete_statuses: dict[str, int] = {}
        self.keep_on_delete_user = False
        self.router = Router(
            {
                LOGIN: fixture("login_ok"),
                SERVER_INFO: fixture("server_info"),
                USERS: lambda request: users_route(self.users)(request),
                GROUPS: lambda request: users_route(self.groups)(request),
                LIST: self._list,
                CREATE: self._create,
                TOKEN_URL: (200, LINK),
                DELETE: self._delete,
                DELETE_USER: self._delete_user,
            }
        )
        self.out = tmp_path / "out"
        values = {
            "url": "https://as.example:943",
            "user": "openvpn",
            "password": "write-test-password",
            "config_dir": tmp_path,
            "output_dir": self.out,
            "write_tools": True,
            "approval": mode,
        }
        values.update(settings)
        self.mcp = build(Settings(**values), transport=self.router.transport())

    def _list(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        wanted = body.get("filters", {}).get("username", {}).get("value")
        found = [p for p in self.profiles if wanted in (None, p["username"])]
        found.sort(key=lambda p: int(p["serial"]))
        page = found[body["offset"] : body["offset"] + body["page_size"]]
        return httpx.Response(200, json={"total": len(found), "profiles": page})

    def _create(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        serial = str(FIRST_NEW_SERIAL + len(self.profiles))
        self.profiles.append(
            profile(
                serial,
                body["username"],
                body["profile_type"],
                body.get("comment", ""),
            )
        )
        return httpx.Response(
            201,
            text=PROFILE_BODY.replace("1810972200425098125", serial),
            headers={"content-type": "application/x-openvpn-profile"},
        )

    def _delete(self, request: httpx.Request) -> httpx.Response:
        serials = json.loads(request.content)
        response = {s: self.delete_statuses.get(s, 204) for s in serials}
        gone = {s for s, code in response.items() if code == 204}
        self.profiles = [p for p in self.profiles if p["serial"] not in gone]
        return httpx.Response(200, json={"response": response, "message": "done"})

    def _delete_user(self, request: httpx.Request) -> httpx.Response:
        users = json.loads(request.content)["users"]
        if not self.keep_on_delete_user:
            self.profiles = [p for p in self.profiles if p["username"] not in users]
        return httpx.Response(200, json={"message": "The user profiles were deleted"})

    async def call(self, tool: str, args: dict[str, Any], **options: Any) -> Any:
        return await call_tool(self.mcp, tool, args, **options)

    def sent(self, route: tuple[str, str]) -> list[Any]:
        return [body_of(request) for request in self.router.sent(*route)]

    def audit(self) -> list[dict[str, Any]]:
        path = self.tmp_path / "audit.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text("utf-8").splitlines()]

    def audit_text(self) -> str:
        path = self.tmp_path / "audit.jsonl"
        return path.read_text("utf-8") if path.exists() else ""

    def serials_of(self, username: str) -> list[str]:
        return [p["serial"] for p in self.profiles if p["username"] == username]


async def approve_after(server: FakeServer, change: Any, tool: str, args: dict) -> Any:
    """The admin says yes, but `change` happened while the prompt was open."""

    async def handler(message, response_type, params, context):
        change()
        fields = params.requested_schema.get("properties", {})
        return ElicitResult(action="accept", content=dict.fromkeys(fields, True))

    async with Client(server.mcp, mode="legacy", elicitation_handler=handler) as client:
        return (await client.call_tool(tool, args)).structured_content


def assert_no_secret(*texts: str) -> None:
    for text in texts:
        for secret in SECRETS:
            assert secret not in text


# --- create_connection_profile ----------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_a_created_profile_goes_to_a_file_and_never_into_the_result(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, mode: str
) -> None:
    caplog.set_level(logging.DEBUG)
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "create_connection_profile", {"usernames": ["alice"]}, mode=mode, seen=seen
    )
    (item,) = result["items"]
    new_serial = server.serials_of("alice")[-1]
    assert item["outcome"] == "done" and item["serial"] == new_serial
    assert item["reminder"] == DELIVERY_REMINDER
    assert item["before"] == {"profiles": ["1810972200425098125"]}
    assert item["after"] == {"profiles": sorted(["1810972200425098125", new_serial])}
    path = Path(item["path"])
    assert path.parent == server.out and path.suffix == ".ovpn"
    assert "profile-alice" in path.name
    assert path.read_text("utf-8") == PROFILE_BODY.replace(
        "1810972200425098125", new_serial
    )
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert result["notes"] == [NOTE_LIVE]
    assert_no_secret(
        json.dumps(result), "\n".join(seen), server.audit_text(), caplog.text
    )
    assert seen[0] == (
        "Server: https://as.example:943\n"
        "Action: Create a userlogin connection profile (1 item): alice\n"
        f"Total: {clean('the profile file is saved in ' + str(server.out), 100)}\n"
        "\n"
        "- alice\n"
        "    connection profiles: 1 -> 2\n"
        f"    also: the profile file is saved in {server.out}"
    )
    (line,) = server.audit()
    assert line["tool"] == "create_connection_profile"
    assert line["outcome"] == "applied" and line["target"] == "alice"


async def test_the_profile_request_never_carries_ignore_missing_user(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    await server.call("create_connection_profile", {"usernames": ["alice"]})
    assert server.sent(CREATE) == [{"username": "alice", "profile_type": "userlogin"}]
    await server.call(
        "create_connection_profile",
        {"usernames": ["bob"], "tls_crypt_v2": False, "comment": "new phone"},
    )
    assert server.sent(CREATE)[1] == {
        "username": "bob",
        "profile_type": "userlogin",
        "tls_crypt_v2": False,
        "comment": "new phone",
    }


@pytest.mark.parametrize("name", ["ghost", "staff", "ALICE", "__DEFAULT__", ""])
async def test_a_profile_for_a_group_name_or_a_missing_user_is_refused_before_create(
    tmp_path: Path, name: str
) -> None:
    """Measured on 3.1.0 and 3.2.4: the server itself would create it."""
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError):
        await server.call("create_connection_profile", {"usernames": ["alice", name]})
    assert server.sent(CREATE) == []
    assert [line["outcome"] for line in server.audit()] == ["failed", "failed"]


async def test_an_autologin_profile_is_refused_in_auto_mode_and_allowed_with_a_prompt(
    tmp_path: Path,
) -> None:
    args = {"usernames": ["alice"], "profile_type": "autologin"}
    auto = FakeServer(tmp_path / "auto", mode="auto")
    with pytest.raises(ToolError) as refused:
        await auto.call("create_connection_profile", args)
    assert str(refused.value) == MSG_AUTO_LIMIT.format(
        reason="an autologin connection profile would be created for user alice"
    )
    assert auto.sent(CREATE) == []
    assert [line["outcome"] for line in auto.audit()] == ["refused_auto_limit"]

    prompt = FakeServer(tmp_path / "prompt")
    seen: list[str] = []
    result = await prompt.call("create_connection_profile", args, seen=seen)
    assert result["items"][0]["outcome"] == "done"
    assert prompt.sent(CREATE) == [{"username": "alice", "profile_type": "autologin"}]
    assert "Action: Create an autologin connection profile" in seen[0]
    assert "connects without a password" in seen[0]


async def test_an_autologin_profile_is_refused_in_auto_mode_also_for_a_user_with_autologin_on(  # noqa: E501
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path, mode="auto")
    assert server.users[1]["autologin"]["value"] is True  # alice
    with pytest.raises(ToolError, match="Refused in automatic approval mode"):
        await server.call(
            "create_connection_profile",
            {"usernames": ["alice"], "profile_type": "autologin"},
        )
    assert server.sent(CREATE) == []
    await server.call("create_connection_profile", {"usernames": ["alice"]})
    assert len(server.sent(CREATE)) == 1  # a userlogin profile is fine in auto


@pytest.mark.parametrize(
    "tool", ["create_connection_profile", "create_profile_download_link"]
)
async def test_autologin_for_a_user_without_the_autologin_right_is_refused_before_the_request(  # noqa: E501
    tmp_path: Path, tool: str
) -> None:
    """Measured: the server answers 400 "No permission to generate profile"."""
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as refused:
        await server.call(tool, {"usernames": ["bob"], "profile_type": "autologin"})
    assert str(refused.value) == (
        "Refused: autologin is off for user bob, and Access Server gives no "
        "autologin profile to such a user. Nothing was changed."
    )
    assert server.sent(CREATE) == [] and server.sent(TOKEN_URL) == []


async def test_a_change_of_the_autologin_right_after_the_preview_refuses_the_write(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)

    def switch_off() -> None:
        server.users[1] = record("alice", autologin=own_value(False))

    with pytest.raises(ToolError) as refused:
        await approve_after(
            server,
            switch_off,
            "create_connection_profile",
            {"usernames": ["alice"], "profile_type": "autologin"},
        )
    assert str(refused.value) == MSG_CHANGED
    assert server.sent(CREATE) == []


async def test_a_profile_that_cannot_be_saved_is_reported_as_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer(tmp_path)

    def full_disk(*args: Any, **kwargs: Any) -> Path:
        raise outputs.OutputError("Cannot write to the output folder: disk full.")

    monkeypatch.setattr(tools_profiles, "write_secret_file", full_disk)
    result = await server.call(
        "create_connection_profile", {"usernames": ["alice", "bob"]}
    )
    first, second = result["items"]
    new_serial = server.serials_of("alice")[-1]
    assert first["outcome"] == "partial" and first["serial"] == new_serial
    assert "path" not in first
    assert first["detail"] == (
        "could not be saved: Cannot write to the output folder: disk full.; delete "
        "it with delete_connection_profiles (done: created on the server)"
    )
    assert first["after"] == {"profiles": sorted(["1810972200425098125", new_serial])}
    assert second["outcome"] == "not attempted" and len(server.sent(CREATE)) == 1
    assert [line["outcome"] for line in server.audit()] == ["partial"]
    assert_no_secret(json.dumps(result), server.audit_text())


@posix_only
async def test_a_read_only_folder_is_noticed_before_anything_is_created(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.out.mkdir()
    server.out.chmod(0o500)
    try:
        with pytest.raises(ToolError, match="Cannot write to the output folder"):
            await server.call("create_connection_profile", {"usernames": ["alice"]})
    finally:
        server.out.chmod(0o700)
    assert server.sent(CREATE) == []


@posix_only
async def test_no_link_is_created_when_it_could_not_be_saved(tmp_path: Path) -> None:
    """A link cannot be revoked, so the folder is tried before the server is asked."""
    server = FakeServer(tmp_path)
    server.out.mkdir()
    server.out.chmod(0o500)
    try:
        with pytest.raises(ToolError, match="Cannot write to the output folder"):
            await server.call("create_profile_download_link", {"usernames": ["alice"]})
    finally:
        server.out.chmod(0o700)
    assert server.sent(TOKEN_URL) == []


async def test_one_user_in_two_letter_cases_is_a_duplicate(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    for tool in ("create_connection_profile", "create_profile_download_link"):
        with pytest.raises(ToolError, match="is in the list twice"):
            await server.call(tool, {"usernames": ["alice", "ALICE"]})
    assert server.sent(CREATE) == [] and server.sent(TOKEN_URL) == []


async def test_profiles_for_three_users_need_one_approval(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "create_connection_profile",
        {"usernames": ["alice", "bob", "жанна"], "comment": "rollout"},
        seen=seen,
    )
    assert len(seen) == 1 and "(3 items)" in seen[0]
    assert 'comment "rollout"' in seen[0]
    assert [item["outcome"] for item in result["items"]] == ["done"] * 3
    paths = [Path(item["path"]) for item in result["items"]]
    assert len(set(paths)) == 3 and all(path.exists() for path in paths)
    assert "жанна" in paths[2].name
    lines = server.audit()
    assert len({line["batch_id"] for line in lines}) == 1 and lines[0]["batch_id"]


async def test_users_that_differ_only_in_letter_case_are_one_duplicate(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError, match="is in the list twice"):
        await server.call("create_connection_profile", {"usernames": ["bob", "Bob"]})
    assert server.sent(CREATE) == []


@pytest.mark.parametrize(
    "comment",
    ["line one\nremote evil.example 1194", "tab\there", "x" * 201, chr(0x202E)],
)
async def test_a_comment_with_line_breaks_or_over_200_characters_is_refused(
    tmp_path: Path, comment: str
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError):
        await server.call(
            "create_connection_profile", {"usernames": ["alice"], "comment": comment}
        )
    assert server.router.requests == []


async def test_a_declined_profile_is_not_created(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as refused:
        await server.call(
            "create_connection_profile", {"usernames": ["alice"]}, answer="decline"
        )
    assert str(refused.value) == MSG_CANCELLED
    assert server.sent(CREATE) == [] and not list(server.out.glob("*.ovpn"))


async def test_a_profile_someone_else_created_meanwhile_is_not_mistaken_for_the_new_one(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    original = server._create

    def create_two(request: httpx.Request) -> httpx.Response:
        server.profiles.append(profile("5", "alice", comment="from the Admin UI"))
        return original(request)

    server.router.routes[CREATE] = [create_two]
    result = await server.call("create_connection_profile", {"usernames": ["alice"]})
    (item,) = result["items"]
    assert item["outcome"] == "done"
    assert item["serial"] == str(FIRST_NEW_SERIAL + 5)  # the one named in the file


# --- create_profile_download_link -------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_a_download_link_goes_to_a_file_with_its_expiry(
    tmp_path: Path, mode: str
) -> None:
    server = FakeServer(tmp_path)
    result = await server.call(
        "create_profile_download_link",
        {"usernames": ["alice"], "lifetime_seconds": 3600, "usages": 2},
        mode=mode,
    )
    (item,) = result["items"]
    assert item["outcome"] == "done"
    assert item["valid_until"] == "2026-11-13T13:00:00+00:00" and item["usages"] == 2
    assert item["reminder"] == DELIVERY_REMINDER
    assert item["after"] == {"valid_until": "2026-11-13T13:00:00+00:00", "usages": 2}
    path = Path(item["path"])
    assert path.suffix == ".txt" and "download-link-alice" in path.name
    assert path.read_text("utf-8") == (
        f"{LINK}\nvalid until 2026-11-13T13:00:00+00:00, 2 use(s)\n"
    )
    if sys.platform != "win32":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "https://" not in json.dumps(result) and "://" not in json.dumps(result)
    assert server.sent(TOKEN_URL) == [
        {
            "lifetime": 3600,
            "usages": 2,
            "profile_type": "userlogin",
            "username": "alice",
        }
    ]


async def test_the_link_appears_in_no_result_preview_audit_line_or_log(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "create_profile_download_link", {"usernames": ["alice", "bob"]}, seen=seen
    )
    assert [item["outcome"] for item in result["items"]] == ["done", "done"]
    assert_no_secret(
        json.dumps(result), "\n".join(seen), server.audit_text(), caplog.text
    )
    revoked = (
        "cannot be revoked, valid until about 2026-11-14T12:00:00+00:00, 1 use(s); "
        "blocking the user later does not stop the link; profiles already "
        "downloaded through it can be deleted"
    )
    assert seen[0] == (
        "Server: https://as.example:943\n"
        "Action: Create a userlogin profile download link (2 items): alice, bob\n"
        f"Total: {clean(revoked, 100)}, "
        f"{clean('the link is saved to a file in ' + str(server.out), 100)}\n"
        "\n"
        "- alice\n"
        "    download link: (not set) -> valid until about 2026-11-14T12:00:00+00:00, "
        "1 use(s)\n"
        "    also: cannot be revoked, valid until about 2026-11-14T12:00:00+00:00, 1 "
        "use(s); blocking the user later does not stop the link; profiles already "
        "downloaded through it can be deleted\n"
        f"    also: the link is saved to a file in {server.out}\n"
        "- bob\n"
        "    download link: (not set) -> valid until about 2026-11-14T12:00:00+00:00, "
        "1 use(s)\n"
        "    also: cannot be revoked, valid until about 2026-11-14T12:00:00+00:00, 1 "
        "use(s); blocking the user later does not stop the link; profiles already "
        "downloaded through it can be deleted\n"
        f"    also: the link is saved to a file in {server.out}"
    )


async def test_the_lifetime_is_always_sent_explicitly(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    await server.call("create_profile_download_link", {"usernames": ["alice"]})
    assert server.sent(TOKEN_URL) == [
        {
            "lifetime": 86400,
            "usages": 1,
            "profile_type": "userlogin",
            "username": "alice",
        }
    ]


@pytest.mark.parametrize("name", ["staff", "ghost", "__DEFAULT__"])
async def test_a_link_for_a_group_name_or_a_missing_user_is_refused_before_any_request_to_token_url(  # noqa: E501
    tmp_path: Path, name: str
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError):
        await server.call(
            "create_profile_download_link", {"usernames": ["alice", name]}
        )
    assert server.sent(TOKEN_URL) == []


@pytest.mark.parametrize(
    ("kind", "lifetime", "usages", "hours"),
    [
        ("userlogin", 604801, 1, 168),
        ("userlogin", 3600, 6, 168),
        ("autologin", 86401, 1, 24),
        ("autologin", 60, 6, 24),
    ],
)
async def test_a_link_above_the_hard_limit_is_refused(
    tmp_path: Path, kind: str, lifetime: int, usages: int, hours: int
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as refused:
        await server.call(
            "create_profile_download_link",
            {
                "usernames": ["alice"],
                "profile_type": kind,
                "lifetime_seconds": lifetime,
                "usages": usages,
            },
        )
    article = "an" if kind == "autologin" else "a"
    assert str(refused.value) == (
        f"Refused: {article} {kind} link may be valid for at most {hours * 3600} "
        f"seconds ({hours} hours) and 5 uses; this call asked for {lifetime} "
        f"seconds and {usages} use(s). Nothing was created."
    )
    assert server.sent(TOKEN_URL) == []


@pytest.mark.parametrize(
    ("kind", "lifetime", "usages"),
    [("userlogin", 604800, 5), ("autologin", 86400, 5), ("userlogin", 60, 1)],
)
async def test_a_link_at_the_hard_limit_is_created(
    tmp_path: Path, kind: str, lifetime: int, usages: int
) -> None:
    server = FakeServer(tmp_path)
    result = await server.call(
        "create_profile_download_link",
        {
            "usernames": ["alice"],
            "profile_type": kind,
            "lifetime_seconds": lifetime,
            "usages": usages,
        },
    )
    assert result["items"][0]["outcome"] == "done"


@pytest.mark.parametrize(("lifetime", "usages"), [(59, 1), (3600, 0), (-1, 1)])
async def test_a_lifetime_under_a_minute_or_zero_uses_is_refused(
    tmp_path: Path, lifetime: int, usages: int
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError):
        await server.call(
            "create_profile_download_link",
            {"usernames": ["alice"], "lifetime_seconds": lifetime, "usages": usages},
        )
    assert server.router.requests == []


async def test_an_autologin_link_is_refused_in_auto_mode_and_allowed_with_a_prompt(
    tmp_path: Path,
) -> None:
    args = {"usernames": ["alice"], "profile_type": "autologin"}
    auto = FakeServer(tmp_path / "auto", mode="auto")
    with pytest.raises(ToolError) as refused:
        await auto.call("create_profile_download_link", args)
    assert str(refused.value) == MSG_AUTO_LIMIT.format(
        reason="an autologin download link would be created for user alice"
    )
    assert auto.sent(TOKEN_URL) == []
    prompt = FakeServer(tmp_path / "prompt")
    result = await prompt.call("create_profile_download_link", args)
    assert result["items"][0]["outcome"] == "done"


async def test_a_link_that_cannot_be_saved_says_it_cannot_be_revoked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = FakeServer(tmp_path)

    def full_disk(*args: Any, **kwargs: Any) -> Path:
        raise outputs.OutputError("Cannot write to the output folder: disk full.")

    monkeypatch.setattr(tools_profiles, "write_secret_file", full_disk)
    result = await server.call("create_profile_download_link", {"usernames": ["alice"]})
    (item,) = result["items"]
    assert item["outcome"] == "partial" and "path" not in item
    assert item["detail"] == (
        "the link exists, cannot be revoked and expires at "
        "2026-11-14T12:00:00+00:00; it could not be saved: Cannot write to the "
        "output folder: disk full. (done: created on the server)"
    )
    assert_no_secret(json.dumps(result), server.audit_text())


async def test_an_answer_that_is_not_a_link_is_reported_and_not_saved(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.router.routes[TOKEN_URL] = [(200, {"unexpected": "TESTLINKTOKEN"})]
    result = await server.call("create_profile_download_link", {"usernames": ["alice"]})
    (item,) = result["items"]
    assert item["outcome"] == "partial"
    assert "answered without a link" in item["detail"]
    assert_no_secret(json.dumps(result), server.audit_text())
    assert not list(server.out.glob("*.txt"))


# --- delete_connection_profiles ---------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
async def test_profiles_are_deleted_by_serial_after_the_admin_saw_whose_they_are(
    tmp_path: Path, mode: str
) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "delete_connection_profiles",
        {"serials": ["21", "1810972200425098125"]},
        mode=mode,
        seen=seen,
    )
    assert seen[0] == (
        "Server: https://as.example:943\n"
        "Action: Delete connection profiles (1 item): 2 connection profiles\n"
        'Total: delete 21 (bob, userlogin, comment "phone"), '
        'delete 1810972200425098125 (alice, userlogin, comment "laptop")\n'
        "\n"
        "- 2 connection profiles\n"
        '    also: delete 21 (bob, userlogin, comment "phone")\n'
        '    also: delete 1810972200425098125 (alice, userlogin, comment "laptop")'
    )
    (item,) = result["items"]
    assert item["outcome"] == "done"
    assert item["deleted"] == ["21", "1810972200425098125"]
    assert item["after"] == {"profiles": []}
    assert [p["serial"] for p in item["before"]["profiles"]] == [
        "21",
        "1810972200425098125",
    ]
    assert server.sent(DELETE) == [["21", "1810972200425098125"]]
    assert server.sent(DELETE_USER) == []
    assert server.serials_of("bob") == ["20"] and server.serials_of("alice") == []


async def test_deleting_a_users_profiles_never_sends_a_filter(tmp_path: Path) -> None:
    server = FakeServer(tmp_path)
    seen: list[str] = []
    result = await server.call(
        "delete_connection_profiles", {"username": "bob"}, seen=seen
    )
    assert server.sent(DELETE_USER) == [{"users": ["bob"]}]
    assert server.sent(DELETE) == []
    (item,) = result["items"]
    assert item["target"] == "bob" and item["deleted"] == ["20", "21"]
    assert item["after"] == {"profiles": []}
    assert "- bob\n    connection profiles: 2 -> 0\n" in seen[0]
    assert "also: delete 20 (bob, userlogin)" in seen[0]
    assert server.serials_of("alice") == ["1810972200425098125"]


async def test_profiles_left_behind_by_a_deleted_user_can_be_deleted_by_username(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    result = await server.call("delete_connection_profiles", {"username": "ghost"})
    assert result["items"][0]["deleted"] == ["30"]


async def test_a_user_without_profiles_is_refused_before_the_delete_request(
    tmp_path: Path,
) -> None:
    """Measured: /profiles/delete-user answers 404 for a user without profiles."""
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as refused:
        await server.call("delete_connection_profiles", {"username": "жанна"})
    assert str(refused.value) == (
        "There are no connection profiles of user жанна on this Access Server "
        "(names are case-sensitive)."
    )
    assert server.sent(DELETE_USER) == []


@pytest.mark.parametrize(
    "args",
    [{}, {"serials": ["20"], "username": "bob"}, {"serials": []}, {"username": ""}],
)
async def test_serials_and_username_together_or_neither_are_refused_before_any_request(
    tmp_path: Path, args: dict[str, Any]
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as refused:
        await server.call("delete_connection_profiles", args)
    assert str(refused.value) == "Give exactly one of serials or username."
    assert server.router.requests == []


@pytest.mark.parametrize("serial", ["12a", "-1", 123, "", " 20", "٢٠", "2.0"])
async def test_a_serial_that_is_not_all_digits_is_refused(
    tmp_path: Path, serial: Any
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError):
        await server.call("delete_connection_profiles", {"serials": ["20", serial]})
    assert server.router.requests == []


async def test_a_repeated_serial_and_more_than_100_serials_are_refused(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError, match="20 is in the list twice"):
        await server.call("delete_connection_profiles", {"serials": ["20", "20"]})
    with pytest.raises(ToolError, match=r"101 serials in one call; the limit is 100"):
        await server.call(
            "delete_connection_profiles", {"serials": [str(n) for n in range(101)]}
        )
    assert server.router.requests == []


async def test_a_serial_that_does_not_exist_refuses_the_whole_call(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    with pytest.raises(ToolError) as refused:
        await server.call("delete_connection_profiles", {"serials": ["20", "999"]})
    assert str(refused.value) == (
        "There is no connection profile with serial 999 on this Access Server."
    )
    assert server.sent(DELETE) == []


async def test_a_serial_the_server_did_not_delete_makes_the_item_partial(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.delete_statuses = {"21": 404}
    result = await server.call("delete_connection_profiles", {"serials": ["20", "21"]})
    (item,) = result["items"]
    assert item["outcome"] == "partial" and item["deleted"] == ["20"]
    assert item["detail"] == (
        "Access Server did not delete 21 (status 404) (done: deleted 20)"
    )
    assert [p["serial"] for p in item["after"]["profiles"]] == ["21"]
    assert [line["outcome"] for line in server.audit()] == ["partial"]


async def test_profiles_still_listed_after_the_delete_make_the_item_partial(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)
    server.keep_on_delete_user = True
    result = await server.call("delete_connection_profiles", {"username": "bob"})
    (item,) = result["items"]
    assert item["outcome"] == "partial"
    assert item["detail"] == ("Access Server still lists 20, 21 (done: written)")


async def test_a_profile_created_after_the_preview_refuses_the_delete(
    tmp_path: Path,
) -> None:
    server = FakeServer(tmp_path)

    def issue_one_more() -> None:
        server.profiles.append(profile("22", "bob", comment="issued meanwhile"))

    with pytest.raises(ToolError) as refused:
        await approve_after(
            server, issue_one_more, "delete_connection_profiles", {"username": "bob"}
        )
    assert str(refused.value) == MSG_CHANGED
    assert server.sent(DELETE_USER) == [] and len(server.serials_of("bob")) == 3


async def test_the_profile_list_is_read_page_by_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tools_profiles, "PAGE_SIZE", 2)
    server = FakeServer(tmp_path)
    server.profiles += [profile(str(n), "bob") for n in range(40, 45)]
    result = await server.call("delete_connection_profiles", {"username": "bob"})
    assert result["items"][0]["deleted"] == ["20", "21", "40", "41", "42", "43", "44"]


# --- registration -----------------------------------------------------------------


async def test_the_three_tools_exist_only_in_write_mode_with_the_right_annotations(
    tmp_path: Path,
) -> None:
    async with Client(FakeServer(tmp_path).mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    destructive = {name: tools[name].annotations.destructive_hint for name in tools}
    assert {name: destructive[name] for name in tools_profiles.TOOLS} == {
        "create_connection_profile": False,
        "create_profile_download_link": False,
        "delete_connection_profiles": True,
    }
    for name in tools_profiles.TOOLS:
        annotations = tools[name].annotations
        assert annotations.read_only_hint is False, name
        assert annotations.idempotent_hint is False, name
        assert annotations.open_world_hint is True, name
        assert tools[name].meta["fastmcp"]["tags"] == ["write"], name
    read_only = build(
        Settings(url="https://as.example:943", user="u", password="p"),
    )
    async with Client(read_only) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert not names & set(tools_profiles.TOOLS)
