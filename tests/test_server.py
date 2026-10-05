"""The server lists its tools with honest annotations.

connection_info explains any problem instead of failing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError

from as_mcp_server import __version__
from as_mcp_server.config import INSECURE_WARNING
from as_mcp_server.server import INSTRUCTIONS, build
from as_mcp_server.settings import Settings
from tests.conftest import LOGIN, MFAAUTH, Router, body_of, load_fixture

pytestmark = pytest.mark.usefixtures("clean_env")

SERVER_INFO = ("GET", "/api/server/info")
PASSWORD = "server-test-password"
EXPECTED_TOOLS = {
    "connection_info",
    "login",
    "get_status_overview",
    "get_server_status",
    "get_server_info",
    "get_active_vpn_connections",
    "get_license_info",
    "get_log_reports",
    "list_users",
    "list_groups",
    "get_default_user",
    "list_access_rulesets",
    "list_access_rules",
}
assert len(EXPECTED_TOOLS) == 13


def server_for(tmp_path: Path, routes: dict, **settings) -> tuple[FastMCP, Router]:
    router = Router(
        {
            LOGIN: load_fixture("login_ok"),
            SERVER_INFO: load_fixture("server_info"),
            **routes,
        }
    )
    defaults = {
        "url": "https://as.example:943",
        "user": "openvpn",
        "password": PASSWORD,
        "config_dir": tmp_path,
    }
    defaults.update(settings)
    return build(Settings(**defaults), transport=router.transport()), router


async def test_the_server_lists_exactly_the_thirteen_tools(tmp_path: Path) -> None:
    mcp, _ = server_for(tmp_path, {})
    async with Client(mcp) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert names == EXPECTED_TOOLS


async def test_read_tools_are_annotated_read_only_and_login_is_not(
    tmp_path: Path,
) -> None:
    mcp, _ = server_for(tmp_path, {})
    async with Client(mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    for name, tool in tools.items():
        annotations = tool.annotations
        assert annotations is not None, name
        if name == "login":
            assert annotations.read_only_hint is False
            assert annotations.destructive_hint is False
        else:
            assert annotations.read_only_hint is True, name
            assert annotations.destructive_hint is False, name
            assert annotations.idempotent_hint is True, name
        assert annotations.open_world_hint is True, name
        assert tool.description, name


async def test_every_tool_carries_its_group_tag(tmp_path: Path) -> None:
    mcp, _ = server_for(tmp_path, {})
    async with Client(mcp) as client:
        tools = await client.list_tools()
    groups = {"connection_info": "diagnostics", "login": "auth"}
    for tool in tools:
        tags = set(tool.meta["fastmcp"]["tags"])
        assert tags == {groups.get(tool.name, "read")}, tool.name


async def test_server_identity_carries_package_version_and_instructions(
    tmp_path: Path,
) -> None:
    mcp, _ = server_for(tmp_path, {})
    async with Client(mcp, mode="legacy") as client:
        result = client.initialize_result
        assert result is not None
        assert result.server_info.name == "as-mcp-server"
        assert result.server_info.version == __version__
        assert result.instructions == INSTRUCTIONS
    assert "connection_info" in INSTRUCTIONS and "login" in INSTRUCTIONS
    assert "__DEFAULT__" in INSTRUCTIONS


@pytest.mark.usefixtures("no_keyring")
async def test_connection_info_explains_a_missing_configuration_instead_of_failing(
    tmp_path: Path,
) -> None:
    mcp = build(Settings(config_dir=tmp_path))
    async with Client(mcp) as client:
        result = (await client.call_tool("connection_info", {})).structured_content
    assert result["url"] is None and result["username"] is None
    assert result["server"] is None
    assert result["session"] == {
        "authenticated": False,
        "expires_after": None,
        "renewable_until": None,
        "keep_alive": False,
        "challenge": None,
    }
    assert "not configured" in result["error"]
    assert "uvx as-mcp-server setup" in result["error"]
    assert result["config"]["keyring_backend"].startswith("unavailable")
    assert result["mcp_version"] == __version__


async def test_connection_info_reports_server_session_sources_and_tls(
    tmp_path: Path,
) -> None:
    mcp, router = server_for(tmp_path, {})
    async with Client(mcp) as client:
        result = (await client.call_tool("connection_info", {})).structured_content
    assert result["url"] == "https://as.example:943" and result["username"] == "openvpn"
    assert result["server"]["version"] == "3.2.2"
    assert result["session"]["authenticated"] is True
    assert result["session"]["expires_after"] == "2026-09-09T20:58:48.000000Z"
    assert result["config"]["url_source"] == "env"
    assert result["config"]["password_source"] == "env"
    assert result["config"]["profile"] == "default"
    assert result["tls"] == {
        "verify": True,
        "ca_cert": None,
        "insecure": False,
        "warning": None,
    }
    assert result["server_warning"] is None and result["error"] is None
    assert [(r.method, r.url.path) for r in router.requests] == [LOGIN, SERVER_INFO]
    assert PASSWORD not in repr(result) and "SESS_TOKEN_test" not in repr(result)


async def test_connection_info_is_loud_about_insecure_tls_and_old_servers(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    status, info = load_fixture("server_info")
    with caplog.at_level("WARNING"):
        mcp, _ = server_for(
            tmp_path,
            {SERVER_INFO: (status, {**info, "version": "3.0.2"})},
            insecure=True,
        )
    assert INSECURE_WARNING in caplog.text
    async with Client(mcp) as client:
        result = (await client.call_tool("connection_info", {})).structured_content
    assert result["tls"]["insecure"] is True
    assert result["tls"]["warning"] == INSECURE_WARNING
    assert "3.0.2" in result["server_warning"] and "3.1" in result["server_warning"]


async def test_connection_info_reports_an_mfa_challenge_as_error_text(
    tmp_path: Path,
) -> None:
    mcp, _ = server_for(
        tmp_path, {LOGIN: load_fixture("login_mfa_required_401")}, user="mfa-admin"
    )
    async with Client(mcp) as client:
        result = (await client.call_tool("connection_info", {})).structured_content
    assert result["server"] is None
    assert "one-time MFA code" in result["error"]
    assert result["session"]["authenticated"] is False


async def test_login_answers_the_challenge_and_later_calls_reuse_the_token(
    tmp_path: Path,
) -> None:
    mcp, router = server_for(
        tmp_path,
        {
            LOGIN: load_fixture("login_mfa_required_401"),
            MFAAUTH: load_fixture("mfaauth_ok"),
        },
        user="mfa-admin",
    )
    async with Client(mcp) as client:
        login = (
            await client.call_tool("login", {"totp_code": "123456"})
        ).structured_content
        assert login["mfa_used"] is True and login["authenticated_user"] == "mfa-admin"
        info = (await client.call_tool("connection_info", {})).structured_content
    assert info["server"]["version"] == "3.2.2" and info["error"] is None
    assert len(router.sent("POST", "/api/auth/login/mfaauth")) == 1


async def test_an_empty_code_is_refused_before_any_request(tmp_path: Path) -> None:
    mcp, router = server_for(tmp_path, {})
    async with Client(mcp) as client:
        with pytest.raises(ToolError, match="is empty"):
            await client.call_tool("login", {"totp_code": "   "})
    assert router.requests == []


@pytest.mark.parametrize("code", ["abc", "12345", "1234567", "12a456", "12-34-56"])
async def test_a_malformed_code_is_refused_without_a_request(
    tmp_path: Path, code: str
) -> None:
    """The authenticator prompt is pending, so the six-digit rule is known."""
    mcp, router = server_for(
        tmp_path, {LOGIN: load_fixture("login_mfa_required_401")}, user="mfa-admin"
    )
    async with Client(mcp) as client:
        info = (await client.call_tool("connection_info", {})).structured_content
        assert info["session"]["challenge"] == "Enter Authenticator Code"
        with pytest.raises(ToolError, match="must be the current 6-digit code"):
            await client.call_tool("login", {"totp_code": code})
    assert len(router.sent(*LOGIN)) == 1
    assert router.sent("POST", "/api/auth/login/mfaauth") == []


async def test_spaces_inside_the_code_are_removed_before_it_is_sent(
    tmp_path: Path,
) -> None:
    mcp, router = server_for(
        tmp_path,
        {
            LOGIN: load_fixture("login_mfa_required_401"),
            MFAAUTH: load_fixture("mfaauth_ok"),
        },
        user="mfa-admin",
    )
    async with Client(mcp) as client:
        await client.call_tool("login", {"totp_code": " 123 456 "})
    sent = body_of(router.sent("POST", "/api/auth/login/mfaauth")[0])
    assert sent["response"] == "123456"


async def test_the_agent_is_told_that_lockout_state_cannot_be_read(
    tmp_path: Path,
) -> None:
    mcp, _ = server_for(tmp_path, {})
    async with Client(mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    for phrase in ("locked out", "get_log_reports", "cannot be confirmed"):
        assert phrase in INSTRUCTIONS, phrase
    lockout = next(line for line in INSTRUCTIONS.splitlines() if "locked out" in line)
    assert lockout.startswith("When asked whether user X is locked out, call")
    assert "list_users(usernames=[X]) right away, without asking" in INSTRUCTIONS
    assert "count only records whose username is exactly X" in INSTRUCTIONS
    users = tools["list_users"].description or ""
    assert "permanent settings" in users and "locked out" in users
    logs = tools["get_log_reports"].description or ""
    assert "LOCKOUT" in logs and "still active" in logs


async def test_a_saml_bound_account_is_refused_without_asking_for_a_code(
    tmp_path: Path,
) -> None:
    mcp, router = server_for(
        tmp_path, {LOGIN: load_fixture("login_saml_required_401")}, user="samluser"
    )
    async with Client(mcp) as client:
        info = (await client.call_tool("connection_info", {})).structured_content
        assert "SAML" in info["error"]
        assert "do not ask the user for a code" in info["error"]
        assert info["session"]["authenticated"] is False
        with pytest.raises(ToolError, match="SAML"):
            await client.call_tool("login", {"totp_code": "123456"})
    assert router.sent("POST", "/api/auth/login/mfaauth") == []


async def test_a_radius_prompt_reaches_the_agent_and_is_answered(
    tmp_path: Path,
) -> None:
    mcp, router = server_for(
        tmp_path,
        {
            LOGIN: load_fixture("login_challenge_radius_401"),
            MFAAUTH: load_fixture("mfaauth_radius_ok"),
        },
        user="radius-admin",
    )
    async with Client(mcp) as client:
        info = (await client.call_tool("connection_info", {})).structured_content
        assert 'asks: "Enter your PIN"' in info["error"]
        assert info["session"]["challenge"] == "Enter your PIN"
        login = (
            await client.call_tool("login", {"totp_code": "4321"})
        ).structured_content
        assert login["mfa_used"] is True
        info = (await client.call_tool("connection_info", {})).structured_content
    assert info["error"] is None and info["session"]["challenge"] is None
    assert len(router.sent(*LOGIN)) == 1


@pytest.mark.parametrize(
    "phrase",
    [
        "requires SAML sign-in, stop",
        "no code will help",
        "show the user the server's prompt",
        "word for word",
        "never ask for the password",
    ],
)
def test_instructions_tell_the_agent_how_to_handle_sign_in_steps(phrase: str) -> None:
    assert phrase in INSTRUCTIONS


def test_instructions_send_every_how_to_to_the_3x_docs_not_to_remembered_steps() -> (
    None
):
    """Agents gave Access Server 2.x menus and sacli commands for a 3.2.2 server, also
    when they offered a password reset nobody asked for."""
    rule = INSTRUCTIONS.splitlines()[1:7]
    assert rule[0].startswith("This server cannot change anything")
    for phrase in ("sacli", "file paths", "asks how", "offer a change", "2.x"):
        assert phrase in " ".join(rule), phrase
    assert "https://openvpn.net/as-docs/v3/" in INSTRUCTIONS


async def test_an_unexpected_exception_does_not_reach_the_agent_verbatim(
    tmp_path: Path,
) -> None:
    """mask_error_details: only ToolError texts, which are written for the agent,
    are shown; anything else could quote internal state."""

    def crash(request):
        raise RuntimeError("internal state LEAK-internal")

    mcp, _ = server_for(tmp_path, {("POST", "/api/users/list"): crash})
    async with Client(mcp) as client:
        with pytest.raises(ToolError) as exc_info:
            await client.call_tool("list_users", {})
    assert "LEAK-internal" not in str(exc_info.value)


async def test_the_login_tool_states_the_renewal_limit_as_a_default(
    tmp_path: Path,
) -> None:
    mcp, _ = server_for(tmp_path, {})
    async with Client(mcp) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
    description = tools["login"].description or ""
    assert "renewal limit (4 hours by default)" in description
    assert "Never pass a password" in description
