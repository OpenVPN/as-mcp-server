"""Command line: run the stdio server (default), `setup`, `check`, `--version`.

`setup` is the only place a password is typed. It verifies the credentials with a
real login before storing anything, prompts for an MFA code only when the server asks
for one, then writes URL + username to profiles.toml and the password to the OS
keyring. `check` is the troubleshooting command for people; agents use the
connection_info tool instead.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import logging
import sys
from collections.abc import Sequence
from typing import Any

from fastmcp.exceptions import ToolError
from pydantic import SecretStr

from as_mcp_server import __version__, profiles, secrets
from as_mcp_server.client import AccessServerClient, MfaRequiredError
from as_mcp_server.config import (
    DEFAULT_PROFILE,
    ConfigError,
    ResolvedConfig,
    describe,
    resolve,
)
from as_mcp_server.server import build
from as_mcp_server.settings import Settings
from as_mcp_server.tools import MINIMUM_VERSION, below_minimum_version

AGENT_CONFIG_SNIPPET = """\
Register the server with your agent (no secret is stored in its configuration):

  Claude Code:  claude mcp add openvpn-as -- uvx as-mcp-server
  Codex CLI:    codex mcp add openvpn-as -- uvx as-mcp-server
  Gemini CLI:   gemini mcp add -s user openvpn-as uvx as-mcp-server
  OpenCode:     opencode mcp add openvpn-as -- uvx as-mcp-server

The command is "uvx" with the argument "as-mcp-server". Configuration file formats for
VS Code, Cursor, Claude Desktop and the others:
https://github.com/OpenVPN/as-mcp-server#agent-setup
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="as-mcp-server",
        description=(
            "Local MCP server for OpenVPN Access Server (read-only). "
            "Without a subcommand it serves MCP over stdio, which is what agents "
            "launch."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    commands = parser.add_subparsers(dest="command")
    setup = commands.add_parser(
        "setup", help="store the Access Server URL, admin user and password (one-time)"
    )
    setup.add_argument(
        "--url", help="Access Server URL, e.g. https://vpn.example.com:943"
    )
    setup.add_argument("--username", help="admin username")
    setup.add_argument(
        "--clear",
        action="store_true",
        help="remove the stored profile and keyring entry",
    )
    commands.add_parser(
        "check", help="verify the configuration: log in and print the server version"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    settings = Settings()
    logging.basicConfig(
        level=settings.log_level,
        stream=sys.stderr,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        if args.command == "setup":
            return _setup(args, settings)
        if args.command == "check":
            return _check(settings)
        return _serve(settings)
    except KeyboardInterrupt:
        return 130
    except (ToolError, profiles.ProfilesError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _serve(settings: Settings) -> int:
    build(settings).run(show_banner=False)
    return 0


def _setup(args: argparse.Namespace, settings: Settings) -> int:
    if args.clear:
        return _clear(settings)
    existing = profiles.read_profiles(settings.config_dir).get(DEFAULT_PROFILE)
    url = args.url or _prompt("Access Server URL", existing.url if existing else None)
    username = args.username or _prompt(
        "Admin username", existing.username if existing else None
    )
    if settings.password is not None:
        password = settings.password.get_secret_value()
    else:
        password = getpass.getpass("Password (input hidden): ")
    if not password:
        raise ConfigError("A password is required.")
    config = resolve(
        settings.model_copy(
            update={"url": url, "user": username, "password": SecretStr(password)}
        )
    )
    info = asyncio.run(_verify(config))
    print(
        f"Connected to Access Server {info.get('version', '?')} at {config.url} "
        f"as {config.username}."
    )
    path = profiles.write_profile(
        settings.config_dir,
        DEFAULT_PROFILE,
        profiles.Profile(config.url, config.username),
    )
    try:
        secrets.set_password(DEFAULT_PROFILE, password)
    except secrets.SecretStoreError as exc:
        print(
            f"Saved URL and username to {path}, but the password could NOT be "
            f"stored in the OS keyring: {exc}.\nSet OPENVPN_AS_PASSWORD in your MCP "
            "client configuration instead.",
            file=sys.stderr,
        )
        return 1
    print(
        f"Saved URL and username to {path}; password stored in the OS keyring "
        f"(service '{secrets.SERVICE_NAME}')."
    )
    print(AGENT_CONFIG_SNIPPET)
    return 0


def _clear(settings: Settings) -> int:
    removed_profile = profiles.delete_profile(settings.config_dir, DEFAULT_PROFILE)
    try:
        removed_secret = secrets.delete_password(DEFAULT_PROFILE)
    except secrets.SecretStoreError as exc:
        print(f"Could not reach the OS keyring: {exc}", file=sys.stderr)
        removed_secret = False
    profile_state = "yes" if removed_profile else "nothing stored"
    secret_state = "yes" if removed_secret else "nothing stored"
    print(
        f"Profile '{DEFAULT_PROFILE}' removed: {profile_state}; "
        f"keyring entry removed: {secret_state}."
    )
    return 0


def _check(settings: Settings) -> int:
    config = resolve(settings)
    info = asyncio.run(_verify(config))
    if config.insecure:
        tls = "DISABLED (OPENVPN_AS_INSECURE=true)"
    elif isinstance(config.verify, str):
        tls = f"verified against CA {config.verify}"
    else:
        tls = "verified"
    version = str(info.get("version", "?"))
    print(f"URL:      {config.url} (from {config.url_source})")
    print(
        f"User:     {config.username} (from {config.username_source}); "
        f"password from {config.password_source}"
    )
    print(f"TLS:      {tls}")
    print(
        f"Server:   Access Server {version} ({info.get('build', '?')}) on "
        f"{info.get('os_distribution', '?')}"
    )
    print(f"Keyring:  {describe(settings)['keyring_backend']}")
    if below_minimum_version(version):
        print(
            f"WARNING: Access Server {version} is below the supported minimum "
            f"{MINIMUM_VERSION[0]}.{MINIMUM_VERSION[1]}; Web API v0.2 endpoints "
            "may be missing."
        )
    return 0


async def _verify(config: ResolvedConfig) -> dict[str, Any]:
    """Log in (asking for an MFA code if challenged) and read /server/info."""
    client = _new_client(config)
    try:
        try:
            await client.login()
        except MfaRequiredError:
            pending = client.challenge
            if pending is None or pending.totp:
                label, ask = "MFA code from your authenticator app", input
            elif pending.prompt is None:
                label, ask = "Second factor", getpass.getpass
            else:
                label = " ".join(pending.prompt.split()).rstrip(":")
                ask = input if pending.echo else getpass.getpass
            await client.login(ask(f"{label}: ").strip())
        info = await client.get("/server/info")
        return info if isinstance(info, dict) else {}
    finally:
        await client.aclose()


def _new_client(config: ResolvedConfig) -> AccessServerClient:
    """Indirection so tests can hand the CLI an httpx transport."""
    return AccessServerClient(config)


def _prompt(label: str, default: str | None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip() or (default or "")
    if not value:
        raise ConfigError(f"{label} is required.")
    return value
