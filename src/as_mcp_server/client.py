"""The Access Server Web API v0.2 client: one HTTP session, login/MFA/renew, errors.

Facts this module is built on (measured 2026-09-09 on AS 3.1.0 and 3.2.2):
tokens expire after 10 minutes and renew for 4 hours by default
(`expires_after` arrives as ISO 8601, although the API document describes a
JavaScript-style date, so both are parsed);
an MFA challenge is a 401 whose body carries `challenge_context` (at the top level as
measured, or nested under `MFAChallenge` as documented), while a 401 without it is a
refusal (a SAML-bound account, measured 2026-09-21) and never a challenge; passing
`totp` in the first login call crashes the server (500), so the challenge/response
endpoint is used; `users/list` returns `totp_secret` in clear text, hence `redact()`.
Every failure is raised as a ToolError whose text tells the agent what happened and what
to do next.
"""

from __future__ import annotations

import asyncio
import contextlib
import fnmatch
import json
import logging
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from fastmcp.exceptions import ToolError

from as_mcp_server import __version__
from as_mcp_server.config import DEFAULT_PROFILE, ResolvedConfig, resolve
from as_mcp_server.settings import Settings
from as_mcp_server.untrusted import clean_server_text

log = logging.getLogger(__name__)

SECRET_KEYS = frozenset(
    {
        "totp_secret",
        "mfa_secret",
        "challenge_context",
        "pvt_google_auth_secret",
        "password",
        "auth_token",
        "subkey",
    }
)
REDACTED = "<redacted>"
CONFIG_SECRET_NAMES = frozenset({"subscription.bundle", "subscription.saved_state"})
CONFIG_SECRET_PATTERNS = (
    "*secret*",
    "*password*",
    "*passwd*",
    "*bind_pw*",
    "*token*",
    "*_key",
    "*.key",
)

RENEW_BEFORE_SECONDS = 60.0
KEEP_ALIVE_MIN_DELAY = 5.0
KEEP_ALIVE_MAX_DELAY = 300.0
KEEP_ALIVE_FALLBACK_DELAY = 240.0
CHALLENGE_REUSE_SECONDS = 90.0

TOTP_PROMPT = "Enter Authenticator Code"

MSG_MFA_REQUIRED = (
    'Access Server requires a one-time MFA code for user "{user}". Ask the user for '
    'the current 6-digit code from their authenticator app, then call the "login" '
    "tool with it. Do not ask for the password."
)
MSG_MFA_REJECTED = (
    'Access Server rejected the MFA code for user "{user}" (403: {reason}). Codes '
    "are valid for 30 seconds and each code can be used once; ask the user for the "
    'next code and call "login" again. After 5 failures the account is locked for '
    "15 minutes, and Access Server then refuses even a correct code the same way: "
    "if a correct code is refused, stop and check get_log_reports(username=..., "
    "errors_only=true) for a LOCKOUT record instead of retrying."
)
MSG_CHALLENGE_REQUIRED = (
    'Access Server needs a second step to sign in user "{user}" and asks: "{prompt}". '
    "Show this question to the user word for word, ask for their answer and call the "
    '"login" tool with it (the totp_code argument carries the answer). Do not ask for '
    "the password.{echo_note}"
)
MSG_ANSWER_HIDDEN = (
    " The server marks the answer as sensitive: do not repeat it back to the user."
)
MSG_CHALLENGE_NO_PROMPT = (
    'Access Server needs a second step to sign in user "{user}" but sent no prompt '
    "text. Ask the user for the second factor their account uses (an authenticator "
    'code, a PIN or a passcode) and call the "login" tool with it (the totp_code '
    "argument carries the answer). Do not ask for the password."
)
MSG_CHALLENGE_REJECTED = (
    'Access Server rejected the answer of user "{user}" to "{prompt}" (403: {reason}). '
    'Ask the user for the answer again and call "login" with it; if the server then '
    "asks a different question, it is quoted again. Repeated failures lock the "
    "account (Access Server default: 5 failures, 15 minutes), and Access Server then "
    "refuses even a correct answer the same way: if a correct answer is refused, stop "
    "and check get_log_reports(username=..., errors_only=true) for a LOCKOUT record "
    "instead of retrying."
)
MSG_BAD_TOTP = (
    "The answer (totp_code) must be the current 6-digit code from the authenticator "
    "app (digits only; spaces are ignored). The code was not sent to the server, so "
    "this did not count as a failed login attempt."
)
MSG_EMPTY_ANSWER = "The answer (totp_code) is empty; nothing was sent to the server."
MSG_SAML_REQUIRED = (
    'Access Server refused the password login for user "{user}" (401: {reason}). '
    "The account signs in through the browser-based SAML flow, which as-mcp-server "
    "does not support: it only does username/password plus an optional TOTP code. "
    "This is not an MFA challenge, so do not ask the user for a code; no code can "
    "succeed. Use an administrator whose authentication method is not SAML: Access "
    "Server sets the method per user (auth_method in list_users, user_auth_type in "
    'sacli; the built-in "openvpn" administrator uses local), then re-run '
    '"uvx as-mcp-server setup".'
)
MSG_EXPIRY_UNREADABLE = (
    "Access Server sent a token expiry that could not be read (%r); the token is "
    "renewed every %.0f s instead of just before it expires."
)
MSG_LOGIN_NO_CHALLENGE = (
    'Access Server answered the password login for user "{user}" with 401 but '
    "without an MFA challenge ({reason}). This is not a request for a TOTP code, so "
    "do not ask the user for one; report the server's reason as it is."
)
MSG_MFA_ENROLLMENT = (
    'User "{user}" must complete MFA enrollment before the API can be used: sign in '
    "to the Access Server web interface once, scan the QR code, then retry."
)
MSG_LOCKOUT = (
    'Access Server has temporarily locked out user "{user}" after repeated '
    "authentication failures (default: 5 failures, 15 minutes). Wait and retry later; "
    "do not retry in a loop."
)
MSG_BAD_CREDENTIALS = (
    'Access Server rejected the login for user "{user}" at {url} (403: {reason}). '
    "Either the password is wrong or the user is not an administrator (admin "
    'privileges are required). Re-run "uvx as-mcp-server setup" with an admin account.'
)
MSG_NOT_ADMIN = (
    'User "{user}" authenticated but is not an administrator '
    "(user_type={user_type!r}); Access Server admin privileges are required."
)
MSG_LOGIN_UNEXPECTED = (
    "Unexpected response from Access Server during login ({status}): {reason}"
)
MSG_TOKEN_TWICE = (
    "Access Server rejected the auth token twice in a row (401 {reason}). Call "
    "connection_info and, if the account uses MFA, login."
)
MSG_FORBIDDEN = (
    "Access Server denied {method} {path} (403: {reason}). The configured user must "
    "have admin privileges."
)
MSG_NOT_FOUND = (
    "{method} {path} is not available on this Access Server (404). It requires Web API "
    "v0.2, i.e. Access Server 3.1 or newer; call get_server_info to see the version."
)
MSG_BAD_REQUEST = "Access Server rejected {method} {path} (400): {reason}{detail}"
MSG_SERVER_ERROR = "Access Server failed to handle {method} {path} ({status}): {reason}"
MSG_UNEXPECTED = "Unexpected response {status} for {method} {path}: {reason}"
MSG_NON_JSON = (
    "Access Server returned a non-JSON response to {method} {path} ({status})."
)
MSG_LOGIN_NO_TOKEN = (
    'Access Server answered the login of user "{user}" (POST {path}) with {status} '
    "but sent no auth_token, so no session was created. The password and the code "
    "were not refused: do not ask the user for them again. This Access Server "
    "answers in a form as-mcp-server does not know; report it with the server "
    "version. The response carried these fields: {fields}."
)
MSG_CONNECT = (
    "Could not connect to {url}: {exc}. Check the URL, that the Access Server web port "
    "(943 by default) is reachable from this machine, and any VPN or firewall in "
    "between."
)
MSG_TLS = (
    "TLS certificate verification failed for {url}. If the Access Server uses a "
    "private CA set OPENVPN_AS_CA_CERT=/path/to/ca.pem; for a self-signed test server "
    "you may set OPENVPN_AS_INSECURE=true (unsafe)."
)
MSG_TIMEOUT = (
    "Access Server did not answer within {timeout:g}s ({method} {path}). Raise "
    "OPENVPN_AS_TIMEOUT if the server is slow."
)
MSG_HTTP = "HTTP error talking to Access Server ({method} {path}): {exc}"


class MfaRequiredError(ToolError):
    """The server asked a second sign-in question (authenticator code, PIN, ...).

    The agent must show the prompt, ask the user for the answer and call `login`.
    """


class MfaEnrollmentRequiredError(ToolError):
    """The account has MFA enabled but never enrolled.

    Only the web interface can finish enrollment.
    """


def redact(value: Any) -> Any:
    """Replace the value of every known secret key, at any depth, with REDACTED.

    A configuration item (a dict with `name` and `value`) gets its `value` and
    `default_value` masked when its key name matches CONFIG_SECRET_NAMES or
    CONFIG_SECRET_PATTERNS, or when the server itself marks it with a
    `redacted_value`; the server hides some of these itself, this covers the rest
    (measured: `auth.ldap.0.bind_pw` and `subscription.bundle` come back in clear
    text).
    """
    if isinstance(value, dict):
        result = {
            k: (REDACTED if k in SECRET_KEYS else redact(v)) for k, v in value.items()
        }
        name = value.get("name")
        if "value" in value and (
            (isinstance(name, str) and is_secret_config_name(name))
            or _server_redacted(value.get("redacted_value"))
        ):
            for field in ("value", "default_value"):
                if result.get(field) not in (None, ""):
                    result[field] = REDACTED
        return result
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


_NUMERIC_SUFFIX = re.compile(r"(\.\d+)+$")


def is_secret_config_name(name: str) -> bool:
    """True when the key name looks like a secret.

    Trailing numeric components are ignored before matching: Access Server appends
    release versions to some keys (`acme.eab_hmac_key.2.9.0`) and indexes
    to others (`private_network.0`), and both would otherwise defeat the
    end-anchored patterns `*_key` and `*.key`.
    """
    lowered = name.lower()
    stem = _NUMERIC_SUFFIX.sub("", lowered)
    return any(
        candidate in CONFIG_SECRET_NAMES
        or any(fnmatch.fnmatchcase(candidate, p) for p in CONFIG_SECRET_PATTERNS)
        for candidate in (lowered, stem)
    )


def _server_redacted(marker: Any) -> bool:
    return isinstance(marker, str) and marker != ""


def next_renewal_delay(seconds_left: float | None) -> float:
    """Seconds to wait before the next background renewal.

    Half the remaining lifetime, so a clock a few minutes off still renews in time;
    bounded so the loop neither spins nor sleeps past a 10-minute token.
    """
    if seconds_left is None:
        return KEEP_ALIVE_FALLBACK_DELAY
    return min(max(seconds_left / 2, KEEP_ALIVE_MIN_DELAY), KEEP_ALIVE_MAX_DELAY)


_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}  # fmt: skip
_JS_DATE = re.compile(
    r"^[A-Za-z]{3} (?P<mon>[A-Za-z]{3}) (?P<day>\d{1,2}) (?P<year>\d{4}) "
    r"(?P<h>\d{1,2}):(?P<m>\d{1,2}):(?P<s>\d{1,2}) "
    r"GMT(?P<sign>[+-])(?P<oh>\d{2})(?P<om>\d{2})"
)


def _parse_timestamp(value: Any) -> float | None:
    """Epoch seconds from the server's timestamp, or None when it is not understood.

    Access Server 3.1 and 3.2 send ISO 8601 (`2026-09-09T20:58:48.000000Z`); the API
    document describes `Tue Sep 09 2026 20:58:48 GMT+0000 (UTC)`. Both are accepted,
    the second one without relying on the process locale.
    """
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        pass
    match = _JS_DATE.match(value.strip())
    if match is None or match["mon"].title() not in _MONTHS:
        return None
    try:
        naive = datetime(
            int(match["year"]),
            _MONTHS[match["mon"].title()],
            int(match["day"]),
            int(match["h"]),
            int(match["m"]),
            int(match["s"]),
            tzinfo=UTC,
        )
    except ValueError:
        return None
    offset = (int(match["oh"]) * 60 + int(match["om"])) * 60
    if match["sign"] == "-":
        offset = -offset
    return naive.timestamp() - offset


def _challenge_context(body: Any) -> str | None:
    """Challenge context: top-level (measured) or under MFAChallenge (documented)."""
    if not isinstance(body, dict):
        return None
    context = body.get("challenge_context")
    if context is None and isinstance(body.get("MFAChallenge"), dict):
        context = body["MFAChallenge"].get("challenge_context")
    if isinstance(context, str) and context:
        return context
    return None


def _challenge_field(body: Any, key: str) -> Any:
    if not isinstance(body, dict):
        return None
    value = body.get(key)
    if value is None and isinstance(body.get("MFAChallenge"), dict):
        value = body["MFAChallenge"].get(key)
    return value


TOTP_PROMPTS = frozenset({TOTP_PROMPT.lower(), "enter your totp code"})


def is_totp_prompt(prompt: str) -> bool:
    """True only for Access Server's own authenticator prompt, as a whole.

    3.1 and 3.2 send exactly "Enter Authenticator Code"; the API document's example
    is "Enter your TOTP code". A back-end prompt that merely mentions a token or
    an authenticator is quoted verbatim and answered as typed.
    """
    return " ".join(prompt.lower().split()) in TOTP_PROMPTS


@dataclass(frozen=True)
class PendingChallenge:
    """A challenge the server issued and nobody answered yet.

    `prompt` is the server's text (the RADIUS Reply-Message for a RADIUS back end),
    None when the server sent none; `echo` false means the server wants the answer
    treated like a password. A stale context is not answered: the server would take
    the answer for a password.
    """

    context: str
    prompt: str | None
    echo: bool
    issued_at: float

    @classmethod
    def from_body(cls, body: Any, context: str, now: float) -> PendingChallenge:
        prompt = _challenge_field(body, "challenge")
        echo = _challenge_field(body, "echo")
        return cls(
            context=context,
            prompt=prompt.strip()
            if isinstance(prompt, str) and prompt.strip()
            else None,
            echo=echo is not False,
            issued_at=now,
        )

    @property
    def totp(self) -> bool:
        return self.prompt is not None and is_totp_prompt(self.prompt)

    def fresh(self, now: float) -> bool:
        """Measured on 3.1.0 and 3.2.2: a context is accepted 120 s after it was
        issued and refused at 180 s (2026-09-22); 90 s leaves a margin."""
        return now - self.issued_at < CHALLENGE_REUSE_SECONDS


class AccessServerClient:
    """One authenticated session with one Access Server; safe for concurrent calls.

    While a token is valid a background task renews it before it expires
    (`keep_alive`), so an MFA account is asked for a code once per 4-hour window
    instead of after every 10 idle minutes. `clock` and `sleep` exist for tests.
    """

    def __init__(
        self,
        config: ResolvedConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        keep_alive: bool = True,
    ) -> None:
        self._config = config
        self._transport = transport
        self._clock = clock
        self._sleep = sleep
        self._keep_alive = keep_alive
        self._http: httpx.AsyncClient | None = None
        self._lock = asyncio.Lock()
        self._token: str | None = None
        self._expires_after: str | None = None
        self._renewable_until: str | None = None
        self._expires_at: float | None = None
        self._keep_alive_task: asyncio.Task[None] | None = None
        self._challenge: PendingChallenge | None = None

    @property
    def config(self) -> ResolvedConfig:
        return self._config

    @property
    def challenge(self) -> PendingChallenge | None:
        """The challenge waiting for an answer, if any.

        Callers show `prompt` and honour `echo`; `context` must never be printed
        or serialised.
        """
        return self._challenge

    def session_state(self) -> dict[str, Any]:
        return {
            "authenticated": self._token is not None,
            "expires_after": self._expires_after,
            "renewable_until": self._renewable_until,
            "keep_alive": self._keep_alive_running(),
            "challenge": (self._challenge.prompt or "") if self._challenge else None,
        }

    def seconds_left(self) -> float | None:
        """Seconds until `expires_after` by the local clock; None when unknown."""
        if self._expires_at is None:
            return None
        return self._expires_at - self._clock()

    async def aclose(self) -> None:
        await self._cancel_keep_alive()
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def get(self, path: str) -> Any:
        return await self._request("GET", path, None)

    async def post(self, path: str, body: dict[str, Any] | None = None) -> Any:
        return await self._request("POST", path, {} if body is None else body)

    async def login(self, totp_code: str | None = None) -> dict[str, Any]:
        """Authenticate now.

        With an answer, answer the pending challenge (or the one a fresh password
        login issues) through /auth/login/mfaauth.
        """
        async with self._lock:
            answer = totp_code.strip() if totp_code is not None else None
            if answer == "":
                raise ToolError(MSG_EMPTY_ANSWER)
            return await self._login(answer)

    # -- internals --

    async def _request(
        self, method: str, path: str, body: dict[str, Any] | None
    ) -> Any:
        await self._ensure_token()
        await self._renew_if_about_to_expire()
        response = await self._send(method, path, body, token=self._token)
        if response.status_code == 401:
            await self._reauthenticate()
            response = await self._send(method, path, body, token=self._token)
        return self._decode(method, path, response)

    async def _ensure_token(self) -> None:
        if self._token is None:
            async with self._lock:
                if self._token is None:
                    pending = self._challenge
                    if pending is not None and pending.fresh(self._clock()):
                        raise MfaRequiredError(self._challenge_message(pending))
                    await self._login(None)

    async def _reauthenticate(self) -> None:
        async with self._lock:
            if self._token is not None and await self._try_renew():
                return
            self._forget_token()
            pending = self._challenge
            if pending is not None and pending.fresh(self._clock()):
                raise MfaRequiredError(self._challenge_message(pending))
            await self._login(None)

    async def _renew_if_about_to_expire(self) -> None:
        left = self.seconds_left()
        if self._token is None or left is None or not 0 < left < RENEW_BEFORE_SECONDS:
            return
        async with self._lock:
            if self._token is not None:
                await self._try_renew()

    async def _try_renew(self) -> bool:
        """Renew the current token; True on success. A 401 forgets the token (F4)."""
        response = await self._send(
            "POST", "/auth/token/renew", None, token=self._token
        )
        data = _json_or_none(response)
        if (
            response.status_code == 200
            and isinstance(data, dict)
            and "auth_token" in data
        ):
            self._store_token(data)
            return True
        if response.status_code == 401:
            self._forget_token()
        return False

    def _forget_token(self) -> None:
        self._token = None
        self._expires_at = None

    def _keep_alive_running(self) -> bool:
        task = self._keep_alive_task
        return task is not None and not task.done()

    def _schedule_keep_alive(self) -> None:
        left = self.seconds_left()
        if not self._keep_alive or self._keep_alive_running():
            return
        if left is not None and left <= 0:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._keep_alive_task = loop.create_task(self._keep_alive_loop())

    async def _keep_alive_loop(self) -> None:
        while True:
            await self._sleep(next_renewal_delay(self.seconds_left()))
            async with self._lock:
                if self._token is None:
                    return
                try:
                    renewed = await self._try_renew()
                except ToolError as exc:
                    log.debug("background token renewal skipped: %s", exc)
                    return
            if not renewed:
                return

    async def _cancel_keep_alive(self) -> None:
        task, self._keep_alive_task = self._keep_alive_task, None
        if task is None or task.done():
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _login(self, answer: str | None) -> dict[str, Any]:
        cfg = self._config
        pending = self._challenge
        challenge: PendingChallenge | None = None
        if answer is not None and pending is not None and pending.fresh(self._clock()):
            challenge = pending
        mfa_used = False
        if challenge is None:
            # A password login supersedes whatever challenge was pending.
            self._challenge = None
            response = await self._send(
                "POST",
                "/auth/login/userpassword",
                {
                    "request_admin": True,
                    "username": cfg.username,
                    "password": cfg.password,
                },
                token=None,
            )
            if response.status_code == 401:
                body = _json_or_none(response)
                context = _challenge_context(body)
                if context is None:
                    reason = _reason(body, response.text) or "empty body"
                    if "saml" in reason.lower():
                        raise ToolError(
                            MSG_SAML_REQUIRED.format(
                                user=cfg.username, reason=reason.rstrip(".")
                            )
                        )
                    raise ToolError(
                        MSG_LOGIN_NO_CHALLENGE.format(user=cfg.username, reason=reason)
                    )
                challenge = PendingChallenge.from_body(body, context, self._clock())
                self._challenge = challenge
                if answer is None or not challenge.totp:
                    # Only an authenticator code may answer a challenge the agent has
                    # not seen: it is time-based, not tied to one challenge. Any other
                    # question (PIN, SMS code, next token) is quoted first, even when
                    # its text repeats, because the expected answer may have changed.
                    raise MfaRequiredError(self._challenge_message(challenge))
        if challenge is not None and answer is not None:
            payload = self._check_answer(challenge, answer)
            # Consumed from here on, even if the request fails half-way.
            self._challenge = None
            response = await self._send(
                "POST",
                "/auth/login/mfaauth",
                {
                    "request_admin": True,
                    "username": cfg.username,
                    "response": payload,
                    "challenge_context": challenge.context,
                },
                token=None,
            )
            mfa_used = True
            if response.status_code == 401:
                body = _json_or_none(response)
                context = _challenge_context(body)
                if context is not None:
                    # Another round of the same conversation (multi-step back ends).
                    challenge = PendingChallenge.from_body(body, context, self._clock())
                    self._challenge = challenge
                    raise MfaRequiredError(self._challenge_message(challenge))
            if response.status_code == 403:
                reason = _reason(_json_or_none(response), response.text)
                if reason.startswith("LOCKOUT"):
                    raise ToolError(MSG_LOCKOUT.format(user=cfg.username))
                raise ToolError(self._rejected_message(challenge, reason))
        if response.status_code == 409:
            raise MfaEnrollmentRequiredError(
                MSG_MFA_ENROLLMENT.format(user=cfg.username)
            )
        if response.status_code == 403:
            reason = _reason(_json_or_none(response), response.text)
            if reason.startswith("LOCKOUT"):
                raise ToolError(MSG_LOCKOUT.format(user=cfg.username))
            raise ToolError(
                MSG_BAD_CREDENTIALS.format(
                    user=cfg.username, url=cfg.url, reason=reason
                )
            )
        if response.status_code != 200:
            raise ToolError(
                MSG_LOGIN_UNEXPECTED.format(
                    status=response.status_code,
                    reason=_reason(_json_or_none(response), response.text),
                )
            )
        data = _json_or_none(response)
        path = "/auth/login/mfaauth" if mfa_used else "/auth/login/userpassword"
        if not isinstance(data, dict):
            raise ToolError(
                MSG_NON_JSON.format(
                    method="POST", path=path, status=response.status_code
                )
            )
        if "auth_token" not in data:
            raise ToolError(
                MSG_LOGIN_NO_TOKEN.format(
                    user=cfg.username,
                    path=path,
                    status=response.status_code,
                    fields=", ".join(sorted(map(str, data))[:20]) or "none",
                )
            )
        user_type = (data.get("user_properties") or {}).get("user_type")
        if user_type != "admin":
            raise ToolError(
                MSG_NOT_ADMIN.format(user=cfg.username, user_type=user_type)
            )
        self._store_token(data)
        return {
            "authenticated_user": cfg.username,
            "user_type": user_type,
            "expires_after": self._expires_after,
            "renewable_until": self._renewable_until,
            "mfa_used": mfa_used,
        }

    def _challenge_message(self, challenge: PendingChallenge) -> str:
        user = self._config.username
        if challenge.prompt is None:
            return MSG_CHALLENGE_NO_PROMPT.format(user=user)
        if challenge.totp:
            return MSG_MFA_REQUIRED.format(user=user)
        return MSG_CHALLENGE_REQUIRED.format(
            user=user,
            prompt=challenge.prompt,
            echo_note="" if challenge.echo else MSG_ANSWER_HIDDEN,
        )

    def _rejected_message(self, challenge: PendingChallenge, reason: str) -> str:
        user = self._config.username
        if challenge.totp:
            return MSG_MFA_REJECTED.format(user=user, reason=reason)
        return MSG_CHALLENGE_REJECTED.format(
            user=user, prompt=challenge.prompt or "the server's prompt", reason=reason
        )

    @staticmethod
    def _check_answer(challenge: PendingChallenge, answer: str) -> str:
        """The value to send, or a ToolError before anything reaches the server."""
        if not challenge.totp:
            return answer.strip()
        code = re.sub(r"\s+", "", answer)
        if not re.fullmatch(r"\d{6}", code):
            raise ToolError(MSG_BAD_TOTP)
        return code

    def _store_token(self, data: dict[str, Any]) -> None:
        self._challenge = None
        self._token = str(data["auth_token"])
        self._expires_after = data.get("expires_after")
        self._renewable_until = data.get("renewable_until")
        self._expires_at = _parse_timestamp(self._expires_after)
        if self._expires_at is None:
            log.warning(
                MSG_EXPIRY_UNREADABLE, self._expires_after, KEEP_ALIVE_FALLBACK_DELAY
            )
        self._schedule_keep_alive()

    def _http_client(self) -> httpx.AsyncClient:
        if self._http is None:
            cfg = self._config
            self._http = httpx.AsyncClient(
                base_url=f"{cfg.url}/api",
                verify=cfg.verify,
                timeout=httpx.Timeout(cfg.timeout, connect=min(10.0, cfg.timeout)),
                headers={
                    "Accept": "application/json",
                    "User-Agent": f"as-mcp-server/{__version__}",
                },
                transport=self._transport,
            )
        return self._http

    async def _send(
        self, method: str, path: str, body: dict[str, Any] | None, *, token: str | None
    ) -> httpx.Response:
        headers = {"X-OpenVPN-As-AuthToken": token} if token else {}
        started = time.monotonic()
        try:
            response = await self._http_client().request(
                method, path, json=body, headers=headers
            )
        except httpx.ConnectError as exc:
            if _is_tls_failure(exc):
                raise ToolError(MSG_TLS.format(url=self._config.url)) from exc
            raise ToolError(MSG_CONNECT.format(url=self._config.url, exc=exc)) from exc
        except httpx.TimeoutException as exc:
            raise ToolError(
                MSG_TIMEOUT.format(
                    timeout=self._config.timeout, method=method, path=path
                )
            ) from exc
        except httpx.HTTPError as exc:
            raise ToolError(MSG_HTTP.format(method=method, path=path, exc=exc)) from exc
        log.debug(
            "%s %s -> %s in %.0f ms",
            method,
            path,
            response.status_code,
            (time.monotonic() - started) * 1000,
        )
        return response

    def _decode(self, method: str, path: str, response: httpx.Response) -> Any:
        status = response.status_code
        if 200 <= status < 300:
            if not response.content:
                return None
            data = _json_or_none(response)
            if data is None:
                raise ToolError(
                    MSG_NON_JSON.format(method=method, path=path, status=status)
                )
            return data
        body = _json_or_none(response)
        reason = _reason(body, response.text)
        if status == 401:
            raise ToolError(MSG_TOKEN_TWICE.format(reason=reason))
        if status == 403:
            raise ToolError(
                MSG_FORBIDDEN.format(method=method, path=path, reason=reason)
            )
        if status == 404:
            raise ToolError(MSG_NOT_FOUND.format(method=method, path=path))
        if status == 400:
            raise ToolError(
                MSG_BAD_REQUEST.format(
                    method=method, path=path, reason=reason, detail=_detail(body)
                )
            )
        if status >= 500:
            raise ToolError(
                MSG_SERVER_ERROR.format(
                    method=method, path=path, status=status, reason=reason
                )
            )
        raise ToolError(
            MSG_UNEXPECTED.format(
                status=status, method=method, path=path, reason=reason
            )
        )


class ClientHolder:
    """Creates the AccessServerClient on first use.

    A misconfigured server therefore still starts and lists its tools.
    """

    def __init__(
        self,
        settings: Settings,
        profile: str = DEFAULT_PROFILE,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.profile = profile
        self._transport = transport
        self._client: AccessServerClient | None = None

    @property
    def created(self) -> bool:
        return self._client is not None

    def get(self) -> AccessServerClient:
        if self._client is None:
            config = resolve(
                self.settings, self.profile
            )  # raises ConfigError (a ToolError)
            self._client = AccessServerClient(config, transport=self._transport)
        return self._client


def _json_or_none(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def _reason(body: Any, fallback: str = "") -> str:
    if isinstance(body, dict):
        for key in ("reason", "detail", "message"):
            value = body.get(key)
            if isinstance(value, str) and value:
                return clean_server_text(value)
        return json.dumps(redact(body), separators=(",", ":"))[:200]
    return clean_server_text((fallback or "").strip()[:200])


def _detail(body: Any) -> str:
    if isinstance(body, dict) and isinstance(body.get("detail"), dict):
        detail = redact(body["detail"])
        return "; " + "; ".join(f"{k}: {v}" for k, v in detail.items())
    return ""


def _is_tls_failure(exc: httpx.ConnectError) -> bool:
    text = str(exc)
    return "CERTIFICATE_VERIFY_FAILED" in text or "SSL" in text or "TLS" in text
