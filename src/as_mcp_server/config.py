"""Turn Settings + profiles.toml + the OS keyring into one ResolvedConfig.

Resolution order per field: environment variable, else the stored profile,
else the keyring (password only). It runs lazily, at the first tool call, so a
misconfigured server still starts and can explain itself through `connection_info`.
ConfigError is a ToolError so the text reaches the agent verbatim; every message says
how to fix the problem.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from fastmcp.exceptions import ToolError

from as_mcp_server import profiles, secrets
from as_mcp_server.settings import Settings

DEFAULT_PROFILE = "default"
SETUP_HINT = (
    'Run "uvx as-mcp-server setup" once, or set OPENVPN_AS_URL, OPENVPN_AS_USER and '
    "OPENVPN_AS_PASSWORD in the MCP server's environment."
)
INSECURE_WARNING = (
    "TLS certificate verification is DISABLED (OPENVPN_AS_INSECURE=true); traffic "
    "to the Access Server can be intercepted."
)

Source = Literal["env", "profile"]
PasswordSource = Literal["env", "keyring"]


class ConfigError(ToolError):
    """Configuration is missing or invalid; the message says how to fix it."""


@dataclass(frozen=True)
class ResolvedConfig:
    url: str
    username: str
    password: str
    verify: bool | str
    insecure: bool
    timeout: float
    url_source: Source
    username_source: Source
    password_source: PasswordSource


def normalize_url(raw: str) -> str:
    """`https://host[:port]` without a trailing slash or `/api`.

    Anything else is an error.
    """
    value = raw.strip().rstrip("/")
    if value.endswith("/api"):
        value = value[: -len("/api")]
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.netloc:
        raise ConfigError(
            f"OPENVPN_AS_URL must start with https:// (got {raw!r}); Access Server "
            "serves its Web API over TLS only, for example https://vpn.example.com:943."
        )
    return value


def resolve(settings: Settings, profile: str = DEFAULT_PROFILE) -> ResolvedConfig:
    stored = _stored_profile(settings, profile)
    url = settings.url or (stored.url if stored else None)
    username = settings.user or (stored.username if stored else None)
    if not url or not username:
        raise ConfigError(f"Access Server is not configured. {SETUP_HINT}")
    if settings.password is not None:
        password = settings.password.get_secret_value()
        password_source: PasswordSource = "env"
    else:
        password = _keyring_password(profile)
        password_source = "keyring"
    return ResolvedConfig(
        url=normalize_url(url),
        username=username,
        password=password,
        verify=_verify_setting(settings),
        insecure=settings.insecure,
        timeout=settings.timeout,
        url_source="env" if settings.url else "profile",
        username_source="env" if settings.user else "profile",
        password_source=password_source,
    )


def describe(settings: Settings, profile: str = DEFAULT_PROFILE) -> dict[str, Any]:
    """Non-secret view of the configuration for connection_info and `check`.

    Never raises.
    """
    profile_error: str | None = None
    try:
        stored = _stored_profile(settings, profile)
    except ConfigError as exc:
        stored, profile_error = None, str(exc)
    usable, backend = secrets.keyring_status()
    if settings.password is not None:
        password_source: str | None = "env"
    else:
        password_source = "keyring" if usable else None
    return {
        "url": settings.url or (stored.url if stored else None),
        "username": settings.user or (stored.username if stored else None),
        "profile": profile,
        "config_dir": str(settings.config_dir),
        "url_source": "env" if settings.url else ("profile" if stored else None),
        "username_source": "env" if settings.user else ("profile" if stored else None),
        "password_source": password_source,
        "keyring_backend": backend if usable else f"unavailable: {backend}",
        "profile_error": profile_error,
        "tls": {
            "verify": not settings.insecure,
            "ca_cert": str(settings.ca_cert) if settings.ca_cert else None,
            "insecure": settings.insecure,
            "warning": INSECURE_WARNING if settings.insecure else None,
        },
    }


def _stored_profile(settings: Settings, profile: str) -> profiles.Profile | None:
    try:
        return profiles.read_profiles(settings.config_dir).get(profile)
    except profiles.ProfilesError as exc:
        raise ConfigError(str(exc)) from exc


def _keyring_password(profile: str) -> str:
    try:
        password = secrets.get_password(profile)
    except secrets.SecretStoreError as exc:
        raise ConfigError(
            f'No password is available for profile "{profile}": {exc}. Either run '
            '"uvx as-mcp-server setup" on a machine with an OS keyring, or set '
            "OPENVPN_AS_PASSWORD in the MCP server's environment."
        ) from exc
    if password is None:
        raise ConfigError(
            f'No password is stored for profile "{profile}" in the OS keyring. '
            'Run "uvx as-mcp-server setup" or set OPENVPN_AS_PASSWORD.'
        )
    return password


def _verify_setting(settings: Settings) -> bool | str:
    if settings.insecure:
        return False
    if settings.ca_cert is not None:
        if not settings.ca_cert.is_file():
            raise ConfigError(
                f"OPENVPN_AS_CA_CERT points to {settings.ca_cert}, "
                "which does not exist."
            )
        return str(settings.ca_cert)
    return True
