"""Token lifetime against a real Access Server, not a mocked one.

`test_client_auth.py` already proves the client's state machine with canned responses.
These tests prove the real server's contract. Measured 2026-09-12 on 3.1.0 and 3.2.2:
`/auth/token/renew` accepts a still-valid token (new `expires_after`, same
`renewable_until`) and refuses an expired one, so the client renews in the
background before the 10-minute lifetime ends and an MFA account is asked for a code
once per 4-hour window, not after every idle 10 minutes.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from as_mcp_server.client import AccessServerClient, ClientHolder
from tests.live.conftest import (
    LOCAL,
    read_env_file,
    settings_for,
    totp,
    wait_for_fresh_totp_window,
)


def _count_logins(client) -> list[str | None]:
    """Record every password login the client performs (the `totp_code` argument)."""
    calls: list[str | None] = []
    original = client._login

    async def recording(totp_code):
        calls.append(totp_code)
        return await original(totp_code)

    client._login = recording
    return calls


async def _mfa_client(name: str, tmp_path: Path) -> tuple[AccessServerClient, str]:
    mfa = read_env_file(LOCAL / "mfa-admin.env")
    secret = mfa[
        "MFA_ADMIN_TOTP_SECRET" if name == "as-3-2-2" else "MFA_ADMIN_TOTP_SECRET_3_1_0"
    ]
    settings = settings_for(
        f"{name}.env", tmp_path, user="mfa-admin", password=mfa["OPENVPN_AS_PASSWORD"]
    )
    return ClientHolder(settings).get(), secret


async def test_an_invalid_token_makes_the_client_log_in_again_for_real(stand) -> None:
    _, settings = stand
    client = ClientHolder(settings).get()
    await client.get("/server/info")
    first_token = client._token
    logins = _count_logins(client)

    client._token = "not-a-real-token"

    info = await client.get("/server/info")
    assert info["version"]
    assert client.session_state()["authenticated"] is True
    assert client._token != first_token
    assert logins == [None]  # renew with a bogus token fails, so one fresh login
    await client.aclose()


async def test_a_real_login_starts_the_background_renewal(stand) -> None:
    _, settings = stand
    client = ClientHolder(settings).get()
    await client.get("/server/info")
    state = client.session_state()
    assert state["keep_alive"] is True
    left = client.seconds_left()
    assert left is not None and 0 < left <= 10 * 60
    await client.aclose()
    assert client.session_state()["keep_alive"] is False


@pytest.mark.slow
async def test_an_mfa_session_survives_the_token_lifetime_without_a_new_code(
    stand, tmp_path: Path
) -> None:
    """Needs OPENVPN_AS_LIVE_SLOW=1; waits past the real 10-minute token lifetime."""
    name, _ = stand
    client, secret = await _mfa_client(name, tmp_path)
    wait_for_fresh_totp_window()
    first = await client.login(totp(secret))
    assert first["mfa_used"] is True
    first_token = client._token
    logins = _count_logins(client)

    await asyncio.sleep(11 * 60)  # expires_after = login + 10 min (design F3)

    info = await client.get("/server/info")
    assert info["version"]
    state = client.session_state()
    assert state["authenticated"] is True and state["keep_alive"] is True
    assert client._token != first_token  # renewed in the background at least once
    assert state["expires_after"] > first["expires_after"]
    assert logins == []  # no password login, so no second TOTP code was needed
    await client.aclose()
