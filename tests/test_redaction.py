"""Nothing secret reaches the model: tool responses, error texts and logs.

Anything a tool returns goes to the agent's model provider (SECURITY.md).
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from as_mcp_server.client import (
    REDACTED,
    SECRET_KEYS,
    AccessServerClient,
    MfaRequiredError,
    is_secret_config_name,
    redact,
)
from tests.conftest import (
    LOGIN,
    MFAAUTH,
    RENEW,
    Router,
    load_fixture,
    make_config,
)
from tests.test_server import EXPECTED_TOOLS, server_for

PLANTED = {
    "password": "LEAK-password",
    "subkey": "LEAK-subkey",
    "records": [
        {
            "name": "alice",
            "totp_secret": "LEAK-totp",
            "session": {"auth_token": "LEAK-token", "mfa_secret": "LEAK-mfa"},
        }
    ],
    "items": [{"name": "auth.ldap.0.bind_pw", "value": "LEAK-bind-pw"}],
}

SECURITY_MD = Path(__file__).resolve().parents[1] / "SECURITY.md"
DOCUMENTED_SECRET_KEYS = {
    "totp_secret",
    "mfa_secret",
    "pvt_google_auth_secret",
    "password",
    "auth_token",
    "subkey",
    "challenge_context",
}

# (tool, arguments, endpoint the tool reads)
DATA_TOOLS = [
    ("connection_info", {}, ("GET", "/api/server/info")),
    ("get_status_overview", {}, ("POST", "/api/helper/status-overview")),
    ("get_server_status", {}, ("GET", "/api/server/status")),
    ("get_server_info", {}, ("GET", "/api/server/info")),
    ("get_active_vpn_connections", {}, ("GET", "/api/vpn/status")),
    ("get_license_info", {}, ("GET", "/api/license/info")),
    ("get_log_reports", {}, ("POST", "/api/log/reports")),
    ("list_users", {}, ("POST", "/api/users/list")),
    ("list_groups", {}, ("POST", "/api/groups/list")),
    ("get_default_user", {}, ("GET", "/api/users/defaultuser")),
    ("list_access_rulesets", {}, ("POST", "/api/access/rulesets/list")),
    ("list_access_rules", {"ruleset_ids": [1]}, ("POST", "/api/access/rules/list")),
]


def test_every_tool_that_returns_server_data_is_in_the_redaction_test() -> None:
    """A new tool fails here until it is added to DATA_TOOLS."""
    assert {tool for tool, _, _ in DATA_TOOLS} == EXPECTED_TOOLS - {"login"}


@pytest.mark.parametrize(
    ("tool", "arguments", "endpoint"), DATA_TOOLS, ids=[t for t, _, _ in DATA_TOOLS]
)
async def test_every_tool_redacts_secrets_planted_in_the_response(
    tmp_path: Path, tool: str, arguments: dict, endpoint: tuple[str, str]
) -> None:
    mcp, _ = server_for(tmp_path, {endpoint: (200, PLANTED)})
    async with Client(mcp) as client:
        result = (await client.call_tool(tool, arguments)).structured_content
    assert "LEAK" not in repr(result)
    assert "alice" in repr(result)  # the rest of the body is still there


def test_the_secret_keys_are_exactly_the_documented_ones() -> None:
    """Dropping a key from the code, or from SECURITY.md, must fail a test."""
    assert SECRET_KEYS == DOCUMENTED_SECRET_KEYS
    security_md = SECURITY_MD.read_text(encoding="utf-8")
    assert [key for key in SECRET_KEYS if f"`{key}`" not in security_md] == []


def test_redact_replaces_secret_keys_at_any_depth_and_keeps_the_rest() -> None:
    _status, body = load_fixture("users_list")
    redacted = redact(body)
    secrets_seen = [
        p["totp_secret"] for p in redacted["profiles"] if "totp_secret" in p
    ]
    assert secrets_seen and all(value == REDACTED for value in secrets_seen)
    assert [p["name"] for p in redacted["profiles"]] == [
        p["name"] for p in body["profiles"]
    ]
    assert redact(
        {"a": [{"mfa_secret": "x", "auth_token": "y", "password": "z", "ok": 1}]}
    ) == {
        "a": [
            {
                "mfa_secret": REDACTED,
                "auth_token": REDACTED,
                "password": REDACTED,
                "ok": 1,
            }
        ]
    }
    assert redact({"subkey": "ASUW-key", "name": "Subscription 1"}) == {
        "subkey": REDACTED,
        "name": "Subscription 1",
    }
    assert redact("plain") == "plain" and redact(None) is None


def test_redact_masks_configuration_values_whose_key_looks_secret() -> None:
    items = [
        {"name": "auth.ldap.0.bind_pw", "value": "BIND_PW_test", "default_value": ""},
        {
            "name": "cs.priv_key",
            "value": "PRIVKEY_test",
            "default_value": "DEFAULT_test",
        },
        {
            "name": "vpn.server.routing.private_access",
            "value": "nat",
            "default_value": "nat",
        },
        {"name": "host.name", "value": "vpn.example.com", "default_value": ""},
        {
            "name": "subscription.saved_state",
            "value": "STATE_test",
            "default_value": "",
        },
        {
            "name": "auth.radius.0.server.0.secret",
            "value": None,
            "redacted_value": "[password]",
        },
    ]
    result = {item["name"]: item for item in redact({"items": items})["items"]}
    assert result["auth.ldap.0.bind_pw"]["value"] == REDACTED
    assert result["cs.priv_key"]["value"] == REDACTED
    assert result["cs.priv_key"]["default_value"] == REDACTED
    assert result["subscription.saved_state"]["value"] == REDACTED
    assert result["vpn.server.routing.private_access"]["value"] == "nat"
    assert result["host.name"]["value"] == "vpn.example.com"
    assert result["auth.ldap.0.bind_pw"]["default_value"] == ""
    assert result["auth.radius.0.server.0.secret"] == {
        "name": "auth.radius.0.server.0.secret",
        "value": None,
        "redacted_value": "[password]",
    }


def test_secret_config_names_are_recognised_despite_numeric_suffixes() -> None:
    """`*_key` and `*.key` are end-anchored; suffixes move the end."""
    assert is_secret_config_name("acme.eab_hmac_key.2.9.0")
    assert is_secret_config_name("acme.internal.private_key.2.9.0")
    assert is_secret_config_name("cs.priv_key")
    assert is_secret_config_name("something.key.1")
    assert is_secret_config_name("AUTH.LDAP.0.BIND_PW")
    assert not is_secret_config_name("vpn.server.routing.private_network.0")
    assert not is_secret_config_name("vpn.daemon.0.listen.port")
    assert not is_secret_config_name("host.name")
    assert not is_secret_config_name("acme.eab_kid.2.9.0")


def test_version_suffixed_secret_values_are_masked() -> None:
    _, body = load_fixture("status_overview_versioned_secret")
    items = {i["name"]: i for i in redact(body)["configuration_items"]["items"]}
    assert items["acme.eab_hmac_key.2.9.0"]["value"] == REDACTED
    assert items["acme.eab_hmac_key.2.9.0"]["default_value"] is None
    assert items["auth.ldap.0.bind_pw"]["value"] == ""
    assert "EAB_HMAC_test" not in repr(items)


def test_a_server_side_redaction_marker_masks_the_value_regardless_of_the_name() -> (
    None
):
    """Safety net: today the server sends value=null with the marker (measured);
    if a build ever sends both, the marker alone must be enough."""
    item = {
        "name": "acme.something.harmless_name",
        "value": "PRIVATE_test",
        "default_value": "DEFAULT_test",
        "redacted_value": "[secp384r1]",
    }
    result = redact({"items": [item]})["items"][0]
    assert result["value"] == REDACTED
    assert result["default_value"] == REDACTED
    assert result["redacted_value"] == "[secp384r1]"
    plain = redact({"items": [{**item, "redacted_value": None}]})["items"][0]
    assert plain["value"] == "PRIVATE_test"


@pytest.mark.parametrize(
    "name",
    [
        "auth.radius.0.server.0.secret",
        "admin_ui.password",
        "auth.pam.0.passwd",
        "auth.ldap.0.bind_pw",
        "api.token",
        "cs.priv_key",
        "cs.ca.key",
        "subscription.bundle",
        "subscription.saved_state",
    ],
)
def test_every_secret_pattern_masks_a_matching_name(name: str) -> None:
    item = {"name": name, "value": "LEAK-value", "default_value": "LEAK-default"}
    result = redact({"items": [item]})["items"][0]
    assert result["value"] == REDACTED and result["default_value"] == REDACTED


async def test_debug_logs_of_a_whole_sign_in_carry_no_secret(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Challenge, a wrong answer, the right one and a renewal, logged at DEBUG."""
    challenge = load_fixture("login_challenge_radius_401")
    router = Router(
        {
            LOGIN: challenge,
            MFAAUTH: [
                load_fixture("mfaauth_radius_bad_answer"),
                load_fixture("mfaauth_radius_ok"),
            ],
            RENEW: load_fixture("token_renew_ok"),
            ("GET", "/api/server/info"): [
                load_fixture("error_invalid_token_401"),
                load_fixture("server_info"),
            ],
        }
    )
    client = AccessServerClient(
        make_config(username="radius-admin", password="LEAK-password"),
        transport=router.transport(),
        keep_alive=False,
    )
    errors: list[str] = []
    with caplog.at_level(logging.DEBUG):
        with pytest.raises(MfaRequiredError) as quoted:  # prompt shown, nothing sent
            await client.login("LEAK-wrong")
        errors.append(str(quoted.value))
        with pytest.raises(ToolError) as rejected:  # wrong PIN sent and refused
            await client.login("LEAK-wrong")
        errors.append(str(rejected.value))
        with pytest.raises(MfaRequiredError) as quoted_again:  # new challenge
            await client.login("LEAK-right")
        errors.append(str(quoted_again.value))
        await client.login("LEAK-right")
        await client.get("/server/info")  # 401, then the token is renewed
    await client.aclose()
    assert "POST /auth/login/mfaauth -> 200" in caplog.text
    for secret in ("LEAK", "SESS_TOKEN_test", challenge[1]["challenge_context"]):
        assert secret not in caplog.text, secret
        assert all(secret not in text for text in errors), secret
