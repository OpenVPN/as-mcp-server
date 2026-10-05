"""Env vars win per field, then profiles.toml and the keyring.

Every gap has an actionable error.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from as_mcp_server import secrets
from as_mcp_server.config import (
    DEFAULT_PROFILE,
    INSECURE_WARNING,
    ConfigError,
    describe,
    normalize_url,
    resolve,
)
from as_mcp_server.profiles import Profile, write_profile
from as_mcp_server.settings import Settings

pytestmark = pytest.mark.usefixtures("clean_env")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://vpn.example.com:943", "https://vpn.example.com:943"),
        ("https://vpn.example.com:943/", "https://vpn.example.com:943"),
        ("https://vpn.example.com:943/api", "https://vpn.example.com:943"),
        ("https://vpn.example.com:943/api/", "https://vpn.example.com:943"),
        ("  https://vpn.example.com  ", "https://vpn.example.com"),
    ],
)
def test_urls_are_normalised_to_scheme_host_port(raw: str, expected: str) -> None:
    assert normalize_url(raw) == expected


@pytest.mark.parametrize(
    "raw", ["http://vpn.example.com:943", "vpn.example.com", "", "https://"]
)
def test_non_https_urls_are_configuration_errors(raw: str) -> None:
    with pytest.raises(ConfigError, match="must start with https://"):
        normalize_url(raw)


def test_env_vars_alone_are_enough_and_win_over_the_profile(
    tmp_path: Path, memory_keyring
) -> None:
    write_profile(tmp_path, "default", Profile("https://file.example:943", "file-user"))
    memory_keyring.store[(secrets.SERVICE_NAME, "default")] = "file-pw"
    settings = Settings(
        url="https://env.example:943/",
        user="env-user",
        password="env-pw",
        config_dir=tmp_path,
    )
    config = resolve(settings)
    assert (config.url, config.username, config.password) == (
        "https://env.example:943",
        "env-user",
        "env-pw",
    )
    assert (config.url_source, config.username_source, config.password_source) == (
        "env",
        "env",
        "env",
    )
    assert config.verify is True and config.insecure is False and config.timeout == 30.0


def test_profile_and_keyring_fill_what_the_environment_leaves_empty(
    tmp_path: Path, memory_keyring
) -> None:
    write_profile(tmp_path, "default", Profile("https://file.example:943", "file-user"))
    memory_keyring.store[(secrets.SERVICE_NAME, "default")] = "file-pw"
    config = resolve(Settings(config_dir=tmp_path))
    assert (config.url, config.username, config.password) == (
        "https://file.example:943",
        "file-user",
        "file-pw",
    )
    assert (config.url_source, config.username_source, config.password_source) == (
        "profile",
        "profile",
        "keyring",
    )


def test_missing_url_or_user_says_how_to_configure(
    tmp_path: Path, memory_keyring
) -> None:
    with pytest.raises(ConfigError, match='Run "uvx as-mcp-server setup"'):
        resolve(Settings(config_dir=tmp_path))
    with pytest.raises(ConfigError, match="not configured"):
        resolve(Settings(url="https://x.example", config_dir=tmp_path))


def test_missing_password_with_a_working_keyring_names_the_profile(
    tmp_path: Path, memory_keyring
) -> None:
    with pytest.raises(
        ConfigError, match='No password is stored for profile "default"'
    ):
        resolve(Settings(url="https://x.example", user="u", config_dir=tmp_path))


@pytest.mark.usefixtures("no_keyring")
def test_missing_password_without_a_keyring_points_at_the_env_var(
    tmp_path: Path,
) -> None:
    with pytest.raises(ConfigError, match="OPENVPN_AS_PASSWORD") as exc_info:
        resolve(Settings(url="https://x.example", user="u", config_dir=tmp_path))
    assert "no OS keyring backend" in str(exc_info.value)


def test_insecure_disables_verification_and_ca_cert_is_passed_as_a_path(
    tmp_path: Path,
) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    base = {
        "url": "https://x.example",
        "user": "u",
        "password": "p",
        "config_dir": tmp_path,
    }
    assert resolve(Settings(**base, ca_cert=ca)).verify == str(ca)
    assert resolve(Settings(**base, insecure=True)).verify is False
    assert resolve(Settings(**base, insecure=True, ca_cert=ca)).verify is False


def test_a_missing_ca_file_is_reported(tmp_path: Path) -> None:
    settings = Settings(
        url="https://x.example",
        user="u",
        password="p",
        ca_cert=tmp_path / "missing.pem",
        config_dir=tmp_path,
    )
    with pytest.raises(ConfigError, match="does not exist"):
        resolve(settings)


def test_a_broken_profiles_file_is_a_configuration_error(
    tmp_path: Path, memory_keyring
) -> None:
    (tmp_path / "profiles.toml").write_text("[default\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=r"profiles\.toml"):
        resolve(Settings(config_dir=tmp_path))


def test_describe_never_raises_and_never_reveals_the_password(
    tmp_path: Path, memory_keyring
) -> None:
    write_profile(tmp_path, "default", Profile("https://file.example:943", "file-user"))
    memory_keyring.store[(secrets.SERVICE_NAME, "default")] = "file-pw"
    info = describe(Settings(config_dir=tmp_path, insecure=True))
    assert info["url"] == "https://file.example:943"
    assert info["username"] == "file-user"
    assert info["profile"] == DEFAULT_PROFILE
    assert info["config_dir"] == str(tmp_path)
    assert info["url_source"] == "profile"
    assert info["password_source"] == "keyring"
    assert info["keyring_backend"].endswith("MemoryKeyring")
    assert info["profile_error"] is None
    assert info["tls"] == {
        "verify": False,
        "ca_cert": None,
        "insecure": True,
        "warning": INSECURE_WARNING,
    }
    assert "file-pw" not in repr(info)


@pytest.mark.usefixtures("no_keyring")
def test_describe_reports_an_unusable_keyring_and_a_broken_profiles_file(
    tmp_path: Path,
) -> None:
    (tmp_path / "profiles.toml").write_text("[default\n", encoding="utf-8")
    info = describe(Settings(config_dir=tmp_path))
    assert info["url"] is None
    assert info["password_source"] is None
    assert info["keyring_backend"].startswith("unavailable:")
    assert "profiles.toml" in info["profile_error"]
