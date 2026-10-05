"""Live tests: real Access Servers from dev/compose.yaml.

Skipped unless OPENVPN_AS_LIVE=1.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from pathlib import Path

import pytest

from as_mcp_server.settings import Settings

ROOT = Path(__file__).resolve().parents[2]
LOCAL = ROOT / "dev" / ".local"
STANDS = ["as-3-2-2", "as-3-1-0"]


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    live = os.environ.get("OPENVPN_AS_LIVE") == "1"
    slow = os.environ.get("OPENVPN_AS_LIVE_SLOW") == "1"
    skip_live = pytest.mark.skip(
        reason="live tests need OPENVPN_AS_LIVE=1 and the dev stand (make live)"
    )
    skip_slow = pytest.mark.skip(
        reason="needs OPENVPN_AS_LIVE_SLOW=1; waits ~11 minutes for a real token expiry"
    )
    for item in items:
        if "tests/live" not in str(item.fspath).replace("\\", "/"):
            continue
        if not live:
            item.add_marker(skip_live)
        elif "slow" in item.keywords and not slow:
            item.add_marker(skip_slow)


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def totp(secret: str, at: float | None = None) -> str:
    """RFC 6238, SHA-1, 30 s, 6 digits - what Access Server uses."""
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    counter = int((at if at is not None else time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 15
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)


def wait_for_fresh_totp_window() -> None:
    """A code may be used once; wait for a window nobody has used yet."""
    time.sleep(30 - (time.time() % 30) + 1)


def settings_for(env_file: str, tmp_path: Path, **overrides) -> Settings:
    values = read_env_file(LOCAL / env_file)
    return Settings(
        url=values["OPENVPN_AS_URL"],
        user=overrides.pop("user", values["OPENVPN_AS_USER"]),
        password=overrides.pop("password", values["OPENVPN_AS_PASSWORD"]),
        insecure=True,
        config_dir=tmp_path,
        **overrides,
    )


@pytest.fixture(params=STANDS, ids=STANDS)
def stand(request: pytest.FixtureRequest, tmp_path: Path) -> tuple[str, Settings]:
    return request.param, settings_for(f"{request.param}.env", tmp_path)
