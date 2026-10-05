"""Environment configuration: the OPENVPN_AS_* variables and nothing else.

Resolving against the profiles file and the OS keyring happens in config.py; this
module only reads the environment, so tests can build a Settings with explicit values
and no side effects. No `.env` file is read on purpose: an MCP server spawned by an
agent has an arbitrary working directory, and a stray `.env` there must not decide
which Access Server we talk to.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]


def default_config_dir() -> Path:
    """`~/.config/as-mcp-server` on every operating system (documented as such)."""
    return Path.home() / ".config" / "as-mcp-server"


class Settings(BaseSettings):
    """Settings prefixed with `OPENVPN_AS_`, e.g. `OPENVPN_AS_URL=https://vpn.example.com:943`."""

    model_config = SettingsConfigDict(env_prefix="OPENVPN_AS_", extra="ignore")

    url: str | None = None
    user: str | None = None
    password: SecretStr | None = None
    ca_cert: Path | None = None
    insecure: bool = False
    timeout: float = Field(default=30.0, gt=0)
    log_level: LogLevel = "WARNING"
    config_dir: Path = Field(default_factory=default_config_dir)
