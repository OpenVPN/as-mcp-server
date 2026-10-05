"""Every HTTP and transport failure becomes a ToolError the agent can act on."""

from __future__ import annotations

import httpx
import pytest
from fastmcp.exceptions import ToolError

from as_mcp_server.client import AccessServerClient
from tests.conftest import LOGIN, MFAAUTH, Router, load_fixture, make_config

USERS = ("POST", "/api/users/list")


def client_with(routes: dict) -> tuple[AccessServerClient, Router]:
    router = Router({LOGIN: load_fixture("login_ok"), **routes})
    return AccessServerClient(make_config(), transport=router.transport()), router


async def test_a_400_quotes_reason_and_every_detail_field() -> None:
    client, _ = client_with(
        {
            USERS: (
                400,
                {
                    "reason": "Request failed",
                    "detail": {
                        "page_size": "Input should be greater than 0",
                        "order_by": "Input should be 'admin', 'name'",
                    },
                },
            )
        }
    )
    with pytest.raises(ToolError) as exc_info:
        await client.post("/users/list", {"page_size": 0})
    message = str(exc_info.value)
    assert message.startswith(
        "Access Server rejected POST /users/list (400): Request failed; "
    )
    assert "page_size: Input should be greater than 0" in message
    assert "order_by: Input should be 'admin', 'name'" in message


async def test_a_400_without_detail_has_no_trailing_separator() -> None:
    client, _ = client_with(
        {("POST", "/api/access/rules/list"): load_fixture("error_bad_ruleset_400")}
    )
    with pytest.raises(ToolError) as exc_info:
        await client.post("/access/rules/list", {"ruleset_ids": [999999]})
    assert str(exc_info.value) == (
        "Access Server rejected POST /access/rules/list (400): "
        "Non-existent ruleset: 999999"
    )


async def test_a_403_on_a_call_asks_for_admin_privileges() -> None:
    client, _ = client_with(
        {("GET", "/api/server/status"): load_fixture("error_forbidden_403")}
    )
    with pytest.raises(
        ToolError,
        match=(
            r"denied GET /server/status "
            r"\(403: Insufficient privileges to use this API\)"
        ),
    ):
        await client.get("/server/status")


async def test_a_404_explains_the_minimum_version() -> None:
    client, _ = client_with({})
    with pytest.raises(
        ToolError,
        match=(
            r"POST /access/policysets/list is not available "
            r"on this Access Server \(404\)"
        ),
    ) as exc_info:
        await client.post("/access/policysets/list", {})
    assert "Access Server 3.1 or newer" in str(exc_info.value)


async def test_a_5xx_is_reported_with_status_and_reason() -> None:
    client, _ = client_with({USERS: (500, {"detail": "Internal server error"})})
    with pytest.raises(
        ToolError,
        match=r"failed to handle POST /users/list \(500\): Internal server error",
    ):
        await client.post("/users/list")


async def test_a_non_json_success_body_is_an_error() -> None:
    client, _ = client_with(
        {USERS: lambda request: httpx.Response(200, text="<html>login</html>")}
    )
    with pytest.raises(ToolError, match="non-JSON response to POST /users/list"):
        await client.post("/users/list")


async def test_an_empty_2xx_body_is_none() -> None:
    client, _ = client_with({USERS: (200, None)})
    assert await client.post("/users/list") is None


async def test_a_connection_failure_names_the_url_and_port_943() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("All connection attempts failed", request=request)

    client = AccessServerClient(make_config(), transport=httpx.MockTransport(refuse))
    with pytest.raises(
        ToolError, match=r"Could not connect to https://as\.example:943"
    ) as exc_info:
        await client.get("/server/info")
    assert "943" in str(exc_info.value)


async def test_a_certificate_failure_points_at_ca_cert_and_insecure() -> None:
    def tls(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "self-signed certificate",
            request=request,
        )

    client = AccessServerClient(make_config(), transport=httpx.MockTransport(tls))
    with pytest.raises(
        ToolError, match="TLS certificate verification failed"
    ) as exc_info:
        await client.get("/server/info")
    assert "OPENVPN_AS_CA_CERT" in str(exc_info.value)
    assert "OPENVPN_AS_INSECURE=true" in str(exc_info.value)


async def test_a_timeout_names_the_budget_and_the_call() -> None:
    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    client = AccessServerClient(
        make_config(timeout=7), transport=httpx.MockTransport(slow)
    )
    with pytest.raises(
        ToolError, match=r"did not answer within 7s \(POST /auth/login/userpassword\)"
    ):
        await client.get("/server/info")


async def test_an_unexpected_status_quotes_the_body_text() -> None:
    client, _ = client_with(
        {USERS: lambda request: httpx.Response(418, text="I'm a teapot")}
    )
    with pytest.raises(
        ToolError, match=r"Unexpected response 418 for POST /users/list: I'm a teapot"
    ):
        await client.post("/users/list")


async def test_any_other_transport_error_names_the_call() -> None:
    def drop(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError("peer closed connection", request=request)

    client = AccessServerClient(make_config(), transport=httpx.MockTransport(drop))
    with pytest.raises(
        ToolError,
        match=r"HTTP error talking to Access Server \(POST /auth/login/userpassword\)",
    ):
        await client.get("/server/info")


async def test_a_login_200_without_a_token_says_so_and_names_the_fields() -> None:
    client, _ = client_with({LOGIN: (200, {"user_properties": {}, "status": "ok"})})
    with pytest.raises(ToolError) as exc_info:
        await client.get("/server/info")
    message = str(exc_info.value)
    assert "POST /auth/login/userpassword) with 200 but sent no auth_token" in message
    assert "do not ask the user for them again" in message
    assert "fields: status, user_properties." in message
    assert "non-JSON" not in message
    assert client.session_state()["authenticated"] is False


async def test_an_mfaauth_200_without_a_token_names_the_mfaauth_call() -> None:
    client, _ = client_with(
        {LOGIN: load_fixture("login_mfa_required_401"), MFAAUTH: (200, {})}
    )
    with pytest.raises(ToolError) as exc_info:
        await client.login("123456")
    message = str(exc_info.value)
    assert "POST /auth/login/mfaauth) with 200 but sent no auth_token" in message
    assert "fields: none." in message


async def test_a_login_200_that_is_not_json_is_reported_as_non_json() -> None:
    client, _ = client_with(
        {LOGIN: lambda request: httpx.Response(200, text="<html>portal</html>")}
    )
    with pytest.raises(
        ToolError,
        match=r"non-JSON response to POST /auth/login/userpassword \(200\)",
    ):
        await client.get("/server/info")


@pytest.mark.parametrize(
    "verify", [True, False, "/etc/ssl/private-ca.pem"], ids=["on", "off", "ca"]
)
async def test_the_tls_setting_reaches_the_http_client(
    monkeypatch: pytest.MonkeyPatch, verify
) -> None:
    """ResolvedConfig.verify is tested in test_config; this proves httpx gets it."""
    seen: list = []
    real_client = httpx.AsyncClient

    def recording_client(**kwargs):
        seen.append(kwargs["verify"])
        return real_client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", recording_client)
    router = Router({LOGIN: load_fixture("login_ok"), USERS: (200, {"total": 0})})
    client = AccessServerClient(
        make_config(verify=verify), transport=router.transport()
    )
    await client.post("/users/list")
    assert seen == [verify]


async def test_a_secret_inside_a_400_detail_is_redacted() -> None:
    client, _ = client_with(
        {USERS: (400, {"reason": "Request failed", "detail": {"password": "LEAK-pw"}})}
    )
    with pytest.raises(ToolError) as exc_info:
        await client.post("/users/list")
    assert "LEAK-pw" not in str(exc_info.value)
    assert "password: <redacted>" in str(exc_info.value)
