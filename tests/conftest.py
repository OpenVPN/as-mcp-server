"""Shared fixtures: clean env, in-memory keyrings, canned Access Server replies."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Literal

import httpx
import keyring
import keyring.backend
import keyring.backends.fail
import keyring.errors
import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.elicitation import ElicitResult

from as_mcp_server.config import ResolvedConfig

FIXTURES = Path(__file__).parent / "fixtures"
LOGIN = ("POST", "/api/auth/login/userpassword")
MFAAUTH = ("POST", "/api/auth/login/mfaauth")
RENEW = ("POST", "/api/auth/token/renew")


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop every OPENVPN_AS_* variable so a developer's shell cannot decide a test."""
    for name in list(os.environ):
        if name.startswith("OPENVPN_AS_"):
            monkeypatch.delenv(name, raising=False)


class MemoryKeyring(keyring.backend.KeyringBackend):
    """A real KeyringBackend that keeps secrets in a dict.

    Priority 10 makes it 'recommended'.
    """

    priority = 10  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self.store: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.store.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.store[(service, username)] = password

    def delete_password(self, service: str, username: str) -> None:
        if (service, username) not in self.store:
            raise keyring.errors.PasswordDeleteError("no such password")
        del self.store[(service, username)]


@pytest.fixture
def memory_keyring():
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous)


@pytest.fixture
def no_keyring():
    previous = keyring.get_keyring()
    keyring.set_keyring(keyring.backends.fail.Keyring())
    yield
    keyring.set_keyring(previous)


def load_fixture(name: str) -> tuple[int, Any]:
    """(status, body) of a captured response from tests/fixtures/<name>.json."""
    data = json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))
    return data["status"], data["body"]


class Router:
    """MockTransport handler: routes (METHOD, path) to canned responses.

    A value is `(status, body)`, a list of them (consumed in order, the last one
    repeats), or a callable taking the request. Unrouted paths answer 404 like a real
    Access Server. Every request is recorded in `.requests` so tests can assert
    headers and bodies.
    """

    def __init__(self, routes: dict[tuple[str, str], Any]) -> None:
        self.routes = {
            key: (list(value) if isinstance(value, list) else [value])
            for key, value in routes.items()
        }
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        queue = self.routes.get((request.method, request.url.path))
        if not queue:
            return httpx.Response(404, json={"detail": "Not Found"})
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if callable(item):
            return item(request)
        status, body = item
        if body is None:
            return httpx.Response(status)
        return httpx.Response(status, json=body)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self)

    def sent(self, method: str, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and r.url.path == path]


def make_config(**overrides: Any) -> ResolvedConfig:
    values: dict[str, Any] = {
        "url": "https://as.example:943",
        "username": "openvpn",
        "password": "correct-horse",
        "verify": True,
        "insecure": False,
        "timeout": 30.0,
        "url_source": "env",
        "username_source": "env",
        "password_source": "env",
    }
    values.update(overrides)
    return ResolvedConfig(**values)


def body_of(request: httpx.Request) -> Any:
    return json.loads(request.content) if request.content else None


Answer = Literal["accept", "no", "decline", "cancel", "none"]
MODES = ("legacy", "2026-07-28")


def elicitation_handler(answer: Answer, seen: list[str] | None = None):
    """A client-side approval prompt that always gives `answer`.

    "accept" ticks every yes/no box of the form, "no" submits it unticked; "decline"
    and "cancel" are the two ways to refuse. The prompt texts go to `seen`.
    """

    async def handler(message, response_type, params, context):
        if seen is not None:
            seen.append(message)
        if answer in ("decline", "cancel"):
            return ElicitResult(action=answer)
        fields = params.requested_schema.get("properties", {})
        return ElicitResult(
            action="accept", content=dict.fromkeys(fields, answer == "accept")
        )

    return handler


async def call_tool(
    mcp: FastMCP,
    name: str,
    args: dict[str, Any] | None = None,
    *,
    mode: str = "legacy",
    answer: Answer = "accept",
    seen: list[str] | None = None,
) -> Any:
    """Call a tool through the in-process FastMCP Client and return its structured
    result. `mode` is "legacy" or "2026-07-28"; `answer` "none" builds the Client
    without an elicitation handler, which is an app that cannot show a prompt."""
    options: dict[str, Any] = {"mode": mode}
    if answer != "none":
        options["elicitation_handler"] = elicitation_handler(answer, seen)
    async with Client(mcp, **options) as client:
        return (await client.call_tool(name, args or {})).structured_content
