"""Login, MFA challenge/response, token renewal and the single retry.

As measured on real servers.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

import httpx
import pytest
from fastmcp.exceptions import ToolError

from as_mcp_server.client import (
    AccessServerClient,
    MfaEnrollmentRequiredError,
    MfaRequiredError,
    is_totp_prompt,
    next_renewal_delay,
)
from tests.conftest import (
    LOGIN,
    MFAAUTH,
    RENEW,
    Router,
    body_of,
    load_fixture,
    make_config,
)

SERVER_INFO = ("GET", "/api/server/info")
INVALID_TOKEN = load_fixture("error_invalid_token_401")


def renewed(token: str) -> tuple[int, dict]:
    status, body = load_fixture("token_renew_ok")
    return status, {**body, "auth_token": token}


def logged_in(token: str) -> tuple[int, dict]:
    status, body = load_fixture("login_ok")
    return status, {**body, "auth_token": token}


async def test_first_call_logs_in_with_request_admin_and_sends_the_token_header() -> (
    None
):
    router = Router(
        {LOGIN: load_fixture("login_ok"), SERVER_INFO: load_fixture("server_info")}
    )
    client = AccessServerClient(make_config(), transport=router.transport())
    result = await client.get("/server/info")
    assert result["version"] == "3.2.2"
    login, call = router.requests
    assert body_of(login) == {
        "request_admin": True,
        "username": "openvpn",
        "password": "correct-horse",
    }
    assert "X-OpenVPN-As-AuthToken" not in login.headers
    assert call.headers["X-OpenVPN-As-AuthToken"] == "SESS_TOKEN_test"
    assert call.headers["Accept"] == "application/json"
    assert call.headers["User-Agent"].startswith("as-mcp-server/")
    assert str(call.url) == "https://as.example:943/api/server/info"
    assert client.session_state() == {
        "authenticated": True,
        "expires_after": "2026-09-09T20:58:48.000000Z",
        "renewable_until": "2026-09-10T00:48:48.000000Z",
        "keep_alive": False,
        "challenge": None,
    }


async def test_a_401_is_renewed_and_the_call_is_retried_once_with_the_new_token() -> (
    None
):
    router = Router(
        {
            LOGIN: load_fixture("login_ok"),
            SERVER_INFO: [INVALID_TOKEN, load_fixture("server_info")],
            RENEW: renewed("SESS_TOKEN_renewed"),
        }
    )
    client = AccessServerClient(make_config(), transport=router.transport())
    assert (await client.get("/server/info"))["version"] == "3.2.2"
    methods = [(r.method, r.url.path) for r in router.requests]
    assert methods == [LOGIN, SERVER_INFO, RENEW, SERVER_INFO]
    assert router.requests[2].headers["X-OpenVPN-As-AuthToken"] == "SESS_TOKEN_test"
    assert router.requests[3].headers["X-OpenVPN-As-AuthToken"] == "SESS_TOKEN_renewed"


async def test_when_renewal_fails_the_client_logs_in_again_before_retrying() -> None:
    router = Router(
        {
            LOGIN: [logged_in("SESS_TOKEN_first"), logged_in("SESS_TOKEN_second")],
            SERVER_INFO: [INVALID_TOKEN, load_fixture("server_info")],
            RENEW: INVALID_TOKEN,
        }
    )
    client = AccessServerClient(make_config(), transport=router.transport())
    await client.get("/server/info")
    methods = [(r.method, r.url.path) for r in router.requests]
    assert methods == [LOGIN, SERVER_INFO, RENEW, LOGIN, SERVER_INFO]
    assert router.requests[-1].headers["X-OpenVPN-As-AuthToken"] == "SESS_TOKEN_second"


async def test_a_second_401_is_not_retried_again() -> None:
    router = Router(
        {
            LOGIN: load_fixture("login_ok"),
            SERVER_INFO: INVALID_TOKEN,
            RENEW: renewed("x"),
        }
    )
    client = AccessServerClient(make_config(), transport=router.transport())
    with pytest.raises(ToolError, match="rejected the auth token twice"):
        await client.get("/server/info")
    assert len(router.sent("GET", "/api/server/info")) == 2


async def test_an_mfa_challenge_asks_for_a_code_not_the_password() -> None:
    router = Router({LOGIN: load_fixture("login_mfa_required_401")})
    client = AccessServerClient(
        make_config(username="mfa-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError) as exc_info:
        await client.get("/server/info")
    message = str(exc_info.value)
    assert 'one-time MFA code for user "mfa-admin"' in message
    assert 'call the "login" tool' in message
    assert "Do not ask for the password" in message
    context = load_fixture("login_mfa_required_401")[1]["challenge_context"]
    assert context not in message
    assert client.session_state()["authenticated"] is False


async def test_login_with_a_code_answers_the_challenge_through_mfaauth() -> None:
    router = Router(
        {
            LOGIN: load_fixture("login_mfa_required_401"),
            MFAAUTH: load_fixture("mfaauth_ok"),
            SERVER_INFO: load_fixture("server_info"),
        }
    )
    client = AccessServerClient(
        make_config(username="mfa-admin"), transport=router.transport()
    )
    result = await client.login(" 123456 ")
    assert result == {
        "authenticated_user": "mfa-admin",
        "user_type": "admin",
        "expires_after": "2026-09-09T21:06:31.000000Z",
        "renewable_until": "2026-09-10T00:56:31.000000Z",
        "mfa_used": True,
    }
    assert body_of(router.sent("POST", "/api/auth/login/mfaauth")[0]) == {
        "request_admin": True,
        "username": "mfa-admin",
        "response": "123456",
        "challenge_context": "XEpeZ96sXP/JCrdOb/l0uVV6788W7Tmd",
    }
    await client.get("/server/info")
    assert router.requests[-1].headers["X-OpenVPN-As-AuthToken"] == "SESS_TOKEN_test"


async def test_login_without_mfa_reports_mfa_used_false() -> None:
    router = Router({LOGIN: load_fixture("login_ok")})
    client = AccessServerClient(make_config(), transport=router.transport())
    result = await client.login("000000")
    assert result["mfa_used"] is False
    assert result["authenticated_user"] == "openvpn"
    assert len(router.requests) == 1


async def test_a_rejected_code_explains_30_seconds_single_use_and_lockout() -> None:
    router = Router(
        {
            LOGIN: load_fixture("login_mfa_required_401"),
            MFAAUTH: load_fixture("mfaauth_bad_code"),
        }
    )
    client = AccessServerClient(
        make_config(username="mfa-admin"), transport=router.transport()
    )
    with pytest.raises(ToolError, match="rejected the MFA code") as exc_info:
        await client.login("000000")
    message = str(exc_info.value)
    assert (
        "30 seconds" in message and "used once" in message and "5 failures" in message
    )
    assert "000000" not in message
    assert "refuses even a correct code the same way" in message
    assert "LOCKOUT record instead of retrying" in message


async def test_mfa_enrollment_required_points_at_the_web_interface() -> None:
    router = Router(
        {
            LOGIN: (
                409,
                {
                    "auth_token": "SESS_TOKEN_test",
                    "user_properties": {"requires_mfa_enrollment": True},
                },
            )
        }
    )
    client = AccessServerClient(
        make_config(username="mfa-admin"), transport=router.transport()
    )
    with pytest.raises(MfaEnrollmentRequiredError, match="complete MFA enrollment"):
        await client.get("/server/info")


async def test_bad_credentials_and_non_admin_share_the_same_actionable_message() -> (
    None
):
    router = Router({LOGIN: load_fixture("login_bad_password_403")})
    client = AccessServerClient(make_config(), transport=router.transport())
    with pytest.raises(
        ToolError,
        match="Either the password is wrong or the user is not an administrator",
    ):
        await client.get("/server/info")


async def test_a_lockout_says_wait_and_do_not_loop() -> None:
    router = Router({LOGIN: load_fixture("login_lockout_403")})
    client = AccessServerClient(make_config(), transport=router.transport())
    with pytest.raises(ToolError, match="temporarily locked out") as exc_info:
        await client.get("/server/info")
    assert "do not retry in a loop" in str(exc_info.value)


async def test_a_lockout_during_mfaauth_is_reported_as_a_lockout() -> None:
    router = Router(
        {
            LOGIN: load_fixture("login_mfa_required_401"),
            MFAAUTH: load_fixture("login_lockout_403"),
        }
    )
    client = AccessServerClient(
        make_config(username="mfa-admin"), transport=router.transport()
    )
    with pytest.raises(ToolError, match="temporarily locked out"):
        await client.login("123456")


async def test_a_200_for_a_non_admin_user_is_refused() -> None:
    status, body = load_fixture("login_ok")
    body = {**body, "user_properties": {**body["user_properties"], "user_type": "user"}}
    router = Router({LOGIN: (status, body)})
    client = AccessServerClient(
        make_config(username="alice"), transport=router.transport()
    )
    with pytest.raises(ToolError, match="is not an administrator"):
        await client.get("/server/info")
    assert client.session_state()["authenticated"] is False


async def test_concurrent_first_calls_log_in_exactly_once() -> None:
    async def login_after_a_pause(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0)  # let the other calls start while this one waits
        status, body = load_fixture("login_ok")
        return httpx.Response(status, json=body)

    router = Router(
        {LOGIN: login_after_a_pause, SERVER_INFO: load_fixture("server_info")}
    )
    client = AccessServerClient(make_config(), transport=router.transport())
    await asyncio.gather(*(client.get("/server/info") for _ in range(5)))
    assert len(router.sent("POST", "/api/auth/login/userpassword")) == 1
    assert len(router.sent("GET", "/api/server/info")) == 5


async def test_aclose_is_safe_before_and_after_use() -> None:
    router = Router(
        {LOGIN: load_fixture("login_ok"), SERVER_INFO: load_fixture("server_info")}
    )
    client = AccessServerClient(make_config(), transport=router.transport())
    await client.aclose()
    assert (await client.get("/server/info"))["version"] == "3.2.2"
    await client.aclose()
    assert client.session_state()["keep_alive"] is False


LOGIN_EXPIRES = "2026-09-09T20:58:48.000000Z"  # login_ok / token_renew_ok fixtures


def epoch(timestamp: str) -> float:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()


class FakeTime:
    """Deterministic clock: sleeping advances time; the third sleep parks forever."""

    def __init__(self, now: float) -> None:
        self.now = now
        self.sleeps: list[float] = []
        self.parked = asyncio.Event()

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        if len(self.sleeps) > 2:
            self.parked.set()
            await asyncio.sleep(3600)
        self.now += seconds
        await asyncio.sleep(0)


async def until(predicate) -> None:
    for _ in range(200):
        if predicate():
            return
        await asyncio.sleep(0)
    raise AssertionError("condition not reached")


def test_next_renewal_delay_is_half_the_remaining_lifetime_within_bounds() -> None:
    assert next_renewal_delay(600) == 300
    assert next_renewal_delay(60) == 30
    assert next_renewal_delay(3600) == 300
    assert next_renewal_delay(4) == 5
    assert next_renewal_delay(0) == 5
    assert next_renewal_delay(-30) == 5
    assert next_renewal_delay(None) == 240


async def test_the_token_is_renewed_in_the_background_before_it_expires() -> None:
    fake = FakeTime(epoch(LOGIN_EXPIRES) - 600)
    router = Router(
        {
            LOGIN: logged_in("T0"),
            RENEW: [renewed("T1"), renewed("T2")],
            SERVER_INFO: (200, {"version": "3.2.2"}),
        }
    )
    client = AccessServerClient(
        make_config(),
        transport=router.transport(),
        clock=fake.clock,
        sleep=fake.sleep,
    )
    await client.get("/server/info")
    assert client.session_state()["keep_alive"] is True
    await asyncio.wait_for(fake.parked.wait(), timeout=5)
    assert fake.sleeps[:2] == [300.0, 150.0]
    assert [r.headers["X-OpenVPN-As-AuthToken"] for r in router.sent(*RENEW)] == [
        "T0",
        "T1",
    ]
    await client.get("/server/info")
    assert router.sent(*SERVER_INFO)[-1].headers["X-OpenVPN-As-AuthToken"] == "T2"
    await client.aclose()
    assert client.session_state()["keep_alive"] is False


async def test_a_call_renews_a_token_that_is_about_to_expire_first() -> None:
    fake = FakeTime(epoch(LOGIN_EXPIRES) - 600)
    router = Router(
        {
            LOGIN: logged_in("T0"),
            RENEW: renewed("T1"),
            SERVER_INFO: (200, {"version": "3.2.2"}),
        }
    )
    client = AccessServerClient(
        make_config(),
        transport=router.transport(),
        clock=fake.clock,
        sleep=fake.sleep,
        keep_alive=False,
    )
    await client.get("/server/info")
    fake.now = epoch(LOGIN_EXPIRES) - 30
    await client.get("/server/info")
    assert [(r.method, r.url.path) for r in router.requests] == [
        LOGIN,
        SERVER_INFO,
        RENEW,
        SERVER_INFO,
    ]
    assert router.sent(*SERVER_INFO)[-1].headers["X-OpenVPN-As-AuthToken"] == "T1"
    assert client.session_state()["keep_alive"] is False


async def test_a_refused_background_renewal_forgets_the_token() -> None:
    fake = FakeTime(epoch(LOGIN_EXPIRES) - 600)
    router = Router(
        {
            LOGIN: [logged_in("T0"), logged_in("T3")],
            RENEW: INVALID_TOKEN,
            SERVER_INFO: (200, {"version": "3.2.2"}),
        }
    )
    client = AccessServerClient(
        make_config(),
        transport=router.transport(),
        clock=fake.clock,
        sleep=fake.sleep,
    )
    await client.get("/server/info")
    await until(lambda: client.session_state()["authenticated"] is False)
    assert client.session_state()["keep_alive"] is False
    await client.get("/server/info")
    assert len(router.sent(*LOGIN)) == 2
    assert router.sent(*SERVER_INFO)[-1].headers["X-OpenVPN-As-AuthToken"] == "T3"


async def test_a_401_without_challenge_context_is_not_treated_as_mfa() -> None:
    """A SAML-bound account is refused, not challenged."""
    router = Router({LOGIN: load_fixture("login_saml_required_401")})
    client = AccessServerClient(
        make_config(username="samluser"), transport=router.transport()
    )
    with pytest.raises(ToolError) as exc_info:
        await client.get("/server/info")
    assert not isinstance(exc_info.value, MfaRequiredError)
    message = str(exc_info.value)
    assert 'user "samluser"' in message
    assert "requires web based SAML authentication" in message
    assert "does not support" in message
    assert "do not ask the user for a code" in message
    assert "auth_method in list_users" in message
    assert "Please sign in via SAML). The account signs in" in message
    assert router.sent("POST", "/api/auth/login/mfaauth") == []
    assert client.session_state()["authenticated"] is False


async def test_a_401_with_neither_challenge_nor_saml_reason_is_reported_as_is() -> None:
    router = Router({LOGIN: (401, {"reason": "Something unexpected"})})
    client = AccessServerClient(make_config(), transport=router.transport())
    with pytest.raises(ToolError) as exc_info:
        await client.get("/server/info")
    assert not isinstance(exc_info.value, MfaRequiredError)
    message = str(exc_info.value)
    assert "without an MFA challenge (Something unexpected)" in message
    assert "do not ask the user for one" in message
    assert router.sent("POST", "/api/auth/login/mfaauth") == []


async def test_a_challenge_nested_under_mfachallenge_is_accepted_too() -> None:
    """The API document nests the fields; real servers send them top-level."""
    wrapped = {
        "MFAChallenge": {
            "echo": True,
            "challenge": "Enter Authenticator Code",
            "challenge_context": "WRAPPED/ctx",
        }
    }
    router = Router({LOGIN: (401, wrapped), MFAAUTH: load_fixture("mfaauth_ok")})
    client = AccessServerClient(
        make_config(username="mfa-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError):
        await client.get("/server/info")
    result = await client.login("123456")
    assert result["mfa_used"] is True
    sent = body_of(router.sent("POST", "/api/auth/login/mfaauth")[0])
    assert sent["challenge_context"] == "WRAPPED/ctx"


@pytest.mark.parametrize(
    "expires_after",
    [
        "2026-09-09T20:58:48.000000Z",
        "2026-09-09T22:58:48+02:00",
        "Tue Sep 09 2026 20:58:48 GMT+0000 (UTC)",
        "Tue Sep 09 2026 22:58:48 GMT+0200 (CEST)",
        "Tue Sep 09 2026 15:58:48 GMT-0500 (CDT)",
    ],
)
async def test_every_expiry_format_gives_the_same_ten_minutes(expires_after) -> None:
    """ISO is what 3.1 and 3.2 send; the other form is the API document's."""
    fake = FakeTime(epoch(LOGIN_EXPIRES) - 600)
    status, body = load_fixture("login_ok")
    router = Router({LOGIN: (status, {**body, "expires_after": expires_after})})
    client = AccessServerClient(
        make_config(), transport=router.transport(), clock=fake.clock, keep_alive=False
    )
    await client.login("000000")
    assert client.seconds_left() == 600


@pytest.mark.parametrize(
    "expires_after",
    [
        "soon",
        None,
        1757451528,
        "Tue Foo 09 2026 20:58:48 GMT+0000 (UTC)",
        "Wed Sep 31 2026 20:58:48 GMT+0000 (UTC)",
    ],
)
async def test_an_expiry_that_cannot_be_read_leaves_the_lifetime_unknown(
    expires_after,
) -> None:
    status, body = load_fixture("login_ok")
    router = Router({LOGIN: (status, {**body, "expires_after": expires_after})})
    client = AccessServerClient(
        make_config(), transport=router.transport(), keep_alive=False
    )
    await client.login("000000")
    assert client.seconds_left() is None
    assert client.session_state()["authenticated"] is True


async def test_an_unreadable_expiry_still_renews_in_the_background(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """First renewal after the fallback delay; the renewed token's readable expiry
    then puts the loop back on half the remaining lifetime."""
    fake = FakeTime(epoch(LOGIN_EXPIRES) - 600)
    status, body = load_fixture("login_ok")
    router = Router(
        {
            LOGIN: (status, {**body, "expires_after": "soon"}),
            RENEW: [renewed("T1"), renewed("T2")],
            SERVER_INFO: (200, {"version": "3.2.2"}),
        }
    )
    client = AccessServerClient(
        make_config(),
        transport=router.transport(),
        clock=fake.clock,
        sleep=fake.sleep,
    )
    with caplog.at_level(logging.WARNING, logger="as_mcp_server.client"):
        await client.get("/server/info")
    assert client.seconds_left() is None
    assert client.session_state()["keep_alive"] is True
    assert "token expiry that could not be read ('soon')" in caplog.text
    assert "renewed every 240 s" in caplog.text
    await asyncio.wait_for(fake.parked.wait(), timeout=5)
    assert fake.sleeps[:2] == [240.0, 180.0]
    assert len(router.sent(*RENEW)) == 2
    await client.aclose()


RADIUS_CHALLENGE = load_fixture("login_challenge_radius_401")


async def test_a_radius_prompt_is_quoted_and_answered_with_one_password_login() -> None:
    """The server's own prompt reaches the agent; the pending challenge is
    answered directly, so a push-based back end is not triggered twice."""
    router = Router(
        {
            LOGIN: RADIUS_CHALLENGE,
            MFAAUTH: load_fixture("mfaauth_radius_ok"),
            SERVER_INFO: load_fixture("server_info"),
        }
    )
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError) as exc_info:
        await client.get("/server/info")
    message = str(exc_info.value)
    assert 'sign in user "radius-admin" and asks: "Enter your PIN"' in message
    assert "word for word" in message and "Do not ask for the password" in message
    assert "authenticator" not in message.lower()
    assert client.session_state()["challenge"] == "Enter your PIN"
    result = await client.login("4321")
    assert result["mfa_used"] is True and result["user_type"] == "admin"
    assert len(router.sent(*LOGIN)) == 1
    sent = body_of(router.sent(*MFAAUTH)[0])
    assert sent["response"] == "4321"
    assert sent["challenge_context"] == RADIUS_CHALLENGE[1]["challenge_context"]
    assert client.session_state()["challenge"] is None
    await client.get("/server/info")
    assert len(router.sent(*LOGIN)) == 1


async def test_a_wrong_radius_answer_is_reported_with_the_prompt() -> None:
    router = Router(
        {LOGIN: RADIUS_CHALLENGE, MFAAUTH: load_fixture("mfaauth_radius_bad_answer")}
    )
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError):
        await client.get("/server/info")
    with pytest.raises(ToolError) as exc_info:
        await client.login("0000")
    message = str(exc_info.value)
    assert 'rejected the answer of user "radius-admin" to "Enter your PIN"' in message
    assert "(403: Login failed)" in message and 'call "login" with it' in message
    assert "30 seconds" not in message
    assert "0000" not in message and "correct-horse" not in message
    assert "refuses even a correct answer the same way" in message
    assert client.session_state()["challenge"] is None
    with pytest.raises(MfaRequiredError, match='asks: "Enter your PIN"'):
        await client.login("1111")
    assert len(router.sent(*LOGIN)) == 2 and len(router.sent(*MFAAUTH)) == 1
    with pytest.raises(ToolError, match="rejected the answer"):
        await client.login("1111")
    assert len(router.sent(*LOGIN)) == 2 and len(router.sent(*MFAAUTH)) == 2


async def test_a_non_totp_answer_is_sent_as_typed_after_trimming() -> None:
    router = Router(
        {LOGIN: RADIUS_CHALLENGE, MFAAUTH: load_fixture("mfaauth_radius_ok")}
    )
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError):
        await client.get("/server/info")
    await client.login("  my secret answer 42 ")
    assert body_of(router.sent(*MFAAUTH)[0])["response"] == "my secret answer 42"


@pytest.mark.parametrize(
    ("echo", "sensitive"), [(False, True), (True, False), ("absent", False)]
)
async def test_only_echo_false_marks_the_answer_as_sensitive(echo, sensitive) -> None:
    status, body = RADIUS_CHALLENGE
    body = {k: v for k, v in body.items() if k != "echo"}
    if echo != "absent":
        body["echo"] = echo
    router = Router({LOGIN: (status, body)})
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError) as exc_info:
        await client.get("/server/info")
    assert ("do not repeat it back" in str(exc_info.value)) is sensitive


async def test_a_malformed_totp_code_keeps_the_pending_challenge() -> None:
    router = Router(
        {
            LOGIN: load_fixture("login_mfa_required_401"),
            MFAAUTH: load_fixture("mfaauth_ok"),
        }
    )
    client = AccessServerClient(
        make_config(username="mfa-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError):
        await client.get("/server/info")
    with pytest.raises(ToolError, match="6-digit"):
        await client.login("12345")
    assert router.sent(*MFAAUTH) == []
    assert client.session_state()["challenge"] == "Enter Authenticator Code"
    await client.login("123456")
    assert len(router.sent(*LOGIN)) == 1 and len(router.sent(*MFAAUTH)) == 1


async def test_a_code_given_first_still_answers_a_fresh_challenge() -> None:
    """No pending challenge (for example after a restart): one password login is
    made to obtain the prompt, then the answer is checked against it."""
    router = Router(
        {
            LOGIN: load_fixture("login_mfa_required_401"),
            MFAAUTH: load_fixture("mfaauth_ok"),
        }
    )
    client = AccessServerClient(
        make_config(username="mfa-admin"), transport=router.transport()
    )
    with pytest.raises(ToolError, match="6-digit"):
        await client.login("abc")
    assert len(router.sent(*LOGIN)) == 1 and router.sent(*MFAAUTH) == []
    assert client.session_state()["challenge"] == "Enter Authenticator Code"
    await client.login("123456")
    assert len(router.sent(*LOGIN)) == 1 and len(router.sent(*MFAAUTH)) == 1


async def test_a_stale_challenge_is_not_answered_but_requested_again() -> None:
    """Access Server refused a 180 s old context (2026-09-22) and would then read
    the answer as a password; the client asks for a fresh challenge instead."""
    fake = FakeTime(epoch(LOGIN_EXPIRES) - 600)
    router = Router(
        {
            LOGIN: [
                RADIUS_CHALLENGE,
                (401, {**RADIUS_CHALLENGE[1], "challenge_context": "NEW/ctx"}),
            ],
            MFAAUTH: load_fixture("mfaauth_radius_ok"),
        }
    )
    client = AccessServerClient(
        make_config(username="radius-admin"),
        transport=router.transport(),
        clock=fake.clock,
        sleep=fake.sleep,
    )
    with pytest.raises(MfaRequiredError):
        await client.get("/server/info")
    fake.now += 91
    with pytest.raises(MfaRequiredError, match='asks: "Enter your PIN"'):
        await client.login("4321")
    assert len(router.sent(*LOGIN)) == 2 and router.sent(*MFAAUTH) == []
    await client.login("4321")
    assert body_of(router.sent(*MFAAUTH)[0])["challenge_context"] == "NEW/ctx"
    await client.aclose()


def test_totp_prompts_are_recognised_in_both_documented_spellings() -> None:
    assert is_totp_prompt("Enter Authenticator Code")
    assert is_totp_prompt("  enter   authenticator code ")
    assert is_totp_prompt("Enter your TOTP code")
    assert not is_totp_prompt("Enter your PIN")
    assert not is_totp_prompt("Enter the code we just texted you")
    assert not is_totp_prompt("Enter the 8-digit code from your TOTP hardware token")
    assert not is_totp_prompt("Duo: type your authenticator code or 1 for push")


async def test_an_answer_never_shown_a_non_totp_prompt_is_not_sent_blindly() -> None:
    """login() first, RADIUS back end: the prompt must reach the agent before any
    answer is sent, otherwise a dynamic prompt (SMS code, next token) gets a stale
    answer and a counted failure."""
    router = Router(
        {LOGIN: RADIUS_CHALLENGE, MFAAUTH: load_fixture("mfaauth_radius_ok")}
    )
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError, match='asks: "Enter your PIN"'):
        await client.login("4321")
    assert router.sent(*MFAAUTH) == []
    await client.login("4321")
    assert len(router.sent(*LOGIN)) == 1 and len(router.sent(*MFAAUTH)) == 1


async def test_a_changed_question_on_retry_is_quoted_instead_of_answered() -> None:
    status, body = RADIUS_CHALLENGE
    sms = (
        status,
        {
            **body,
            "challenge": "Enter the code we texted you",
            "challenge_context": "SMS/ctx",
        },
    )
    router = Router(
        {
            LOGIN: [RADIUS_CHALLENGE, sms],
            MFAAUTH: [
                load_fixture("mfaauth_radius_bad_answer"),
                load_fixture("mfaauth_radius_ok"),
            ],
        }
    )
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError):
        await client.get("/server/info")
    with pytest.raises(ToolError, match="rejected the answer"):
        await client.login("4321")
    with pytest.raises(MfaRequiredError, match='asks: "Enter the code we texted you"'):
        await client.login("4321")
    assert len(router.sent(*MFAAUTH)) == 1
    assert client.session_state()["challenge"] == "Enter the code we texted you"
    await client.login("777888")
    assert body_of(router.sent(*MFAAUTH)[1]) == {
        "request_admin": True,
        "username": "radius-admin",
        "response": "777888",
        "challenge_context": "SMS/ctx",
    }


async def test_a_second_round_from_mfaauth_is_quoted_and_the_context_stays_secret() -> (
    None
):
    second = (
        401,
        {
            "echo": False,
            "challenge": "Enter new PIN",
            "challenge_context": "CTX2/secret",
        },
    )
    router = Router(
        {
            LOGIN: RADIUS_CHALLENGE,
            MFAAUTH: [second, load_fixture("mfaauth_radius_ok")],
        }
    )
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError):
        await client.get("/server/info")
    with pytest.raises(MfaRequiredError) as exc_info:
        await client.login("4321")
    message = str(exc_info.value)
    assert 'asks: "Enter new PIN"' in message and "do not repeat it back" in message
    assert "CTX2" not in message
    await client.login("9999")
    assert body_of(router.sent(*MFAAUTH)[1])["challenge_context"] == "CTX2/secret"
    assert client.session_state()["authenticated"] is True


async def test_an_unexpected_login_body_is_redacted_in_the_error_text() -> None:
    odd = (401, {"echo": True, "challenge": "x", "challenge_context": ""})
    router = Router({LOGIN: RADIUS_CHALLENGE, MFAAUTH: odd})
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError):
        await client.get("/server/info")
    with pytest.raises(ToolError, match="Unexpected response") as exc_info:
        await client.login("4321")
    assert '"challenge_context":"<redacted>"' in str(exc_info.value)


async def test_a_challenge_without_prompt_text_is_not_treated_as_totp() -> None:
    status, body = RADIUS_CHALLENGE
    bare = (status, {"challenge_context": body["challenge_context"]})
    router = Router({LOGIN: bare, MFAAUTH: load_fixture("mfaauth_radius_ok")})
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError, match="sent no prompt text") as exc_info:
        await client.get("/server/info")
    assert "Authenticator" not in str(exc_info.value)
    assert body["challenge_context"] not in str(exc_info.value)
    assert client.session_state()["challenge"] == ""
    await client.login("my-pin")
    assert body_of(router.sent(*MFAAUTH)[0])["response"] == "my-pin"


async def test_a_failed_password_login_drops_the_pending_challenge() -> None:
    fake = FakeTime(epoch(LOGIN_EXPIRES) - 600)
    router = Router(
        {LOGIN: [RADIUS_CHALLENGE, load_fixture("login_radius_bad_password_403")]}
    )
    client = AccessServerClient(
        make_config(username="radius-admin"),
        transport=router.transport(),
        clock=fake.clock,
    )
    with pytest.raises(MfaRequiredError):
        await client.get("/server/info")
    fake.now += 91  # too old to answer, so the next call logs in with the password
    with pytest.raises(ToolError, match=r"\(403: Wrong password\)"):
        await client.get("/server/info")
    assert client.session_state()["challenge"] is None


async def test_a_failed_mfaauth_request_consumes_the_pending_challenge() -> None:
    router = Router(
        {
            LOGIN: [RADIUS_CHALLENGE, RADIUS_CHALLENGE],
            MFAAUTH: [(500, {"reason": "boom"}), load_fixture("mfaauth_radius_ok")],
        }
    )
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError):
        await client.get("/server/info")
    with pytest.raises(ToolError, match="Unexpected response"):
        await client.login("4321")
    assert client.session_state()["challenge"] is None
    with pytest.raises(MfaRequiredError, match='asks: "Enter your PIN"'):
        await client.login("4321")
    await client.login("4321")
    assert len(router.sent(*LOGIN)) == 2 and len(router.sent(*MFAAUTH)) == 2


async def test_concurrent_first_calls_provoke_one_challenge_only() -> None:
    async def challenge_after_a_pause(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0)  # let the other calls start while this one waits
        return httpx.Response(RADIUS_CHALLENGE[0], json=RADIUS_CHALLENGE[1])

    router = Router({LOGIN: challenge_after_a_pause})
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    results = await asyncio.gather(
        client.get("/server/info"),
        client.get("/server/info"),
        client.get("/server/info"),
        return_exceptions=True,
    )
    assert all(isinstance(r, MfaRequiredError) for r in results)
    assert len(router.sent(*LOGIN)) == 1


async def test_a_stale_token_does_not_provoke_a_new_challenge_while_one_is_fresh() -> (
    None
):
    """The token is rejected, the new login is challenged; the next call quotes the
    pending challenge instead of logging in again."""
    router = Router(
        {
            LOGIN: [logged_in("T0"), RADIUS_CHALLENGE],
            RENEW: INVALID_TOKEN,
            SERVER_INFO: [INVALID_TOKEN, INVALID_TOKEN],
        }
    )
    client = AccessServerClient(
        make_config(username="radius-admin"),
        transport=router.transport(),
        keep_alive=False,
    )
    with pytest.raises(MfaRequiredError):
        await client.get("/server/info")
    assert len(router.sent(*LOGIN)) == 2
    with pytest.raises(MfaRequiredError, match='asks: "Enter your PIN"'):
        await client.get("/server/info")
    assert len(router.sent(*LOGIN)) == 2


async def test_a_prompt_that_merely_mentions_totp_is_quoted_and_sent_as_typed() -> None:
    status, body = RADIUS_CHALLENGE
    hardware = (
        status,
        {**body, "challenge": "Enter the 8-digit code from your TOTP hardware token"},
    )
    router = Router({LOGIN: hardware, MFAAUTH: load_fixture("mfaauth_radius_ok")})
    client = AccessServerClient(
        make_config(username="radius-admin"), transport=router.transport()
    )
    with pytest.raises(MfaRequiredError, match="8-digit code from your TOTP"):
        await client.get("/server/info")
    await client.login("12345678")
    assert body_of(router.sent(*MFAAUTH)[0])["response"] == "12345678"


async def test_calls_rejected_together_share_one_new_challenge() -> None:
    """Two calls hold the same token when the server rejects it: the first one logs in
    again and is challenged, the second one quotes that challenge instead of
    triggering a second push on the back end."""

    async def rejected_after_a_pause(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0)  # both calls are in flight before either is refused
        return httpx.Response(INVALID_TOKEN[0], json=INVALID_TOKEN[1])

    router = Router(
        {
            LOGIN: [logged_in("T0"), RADIUS_CHALLENGE],
            RENEW: INVALID_TOKEN,
            SERVER_INFO: [load_fixture("server_info"), rejected_after_a_pause],
        }
    )
    client = AccessServerClient(
        make_config(username="radius-admin"),
        transport=router.transport(),
        keep_alive=False,
    )
    await client.get("/server/info")
    results = await asyncio.gather(
        client.get("/server/info"), client.get("/server/info"), return_exceptions=True
    )
    assert all(isinstance(r, MfaRequiredError) for r in results)
    assert all('asks: "Enter your PIN"' in str(r) for r in results)
    assert len(router.sent(*LOGIN)) == 2
