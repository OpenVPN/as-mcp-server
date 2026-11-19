"""Settings read only OPENVPN_AS_* variables and default to safe values."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from as_mcp_server.settings import Settings, default_config_dir


@pytest.mark.usefixtures("clean_env")
def test_defaults_are_verify_tls_warning_log_level_and_30s_timeout() -> None:
    settings = Settings()
    assert settings.url is None
    assert settings.user is None
    assert settings.password is None
    assert settings.ca_cert is None
    assert settings.insecure is False
    assert settings.timeout == 30.0
    assert settings.log_level == "WARNING"
    assert settings.config_dir == default_config_dir()
    assert default_config_dir() == Path.home() / ".config" / "as-mcp-server"


@pytest.mark.usefixtures("clean_env")
def test_every_variable_is_read_with_the_openvpn_as_prefix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("OPENVPN_AS_URL", "https://vpn.example.com:943")
    monkeypatch.setenv("OPENVPN_AS_USER", "mcp-admin")
    monkeypatch.setenv("OPENVPN_AS_PASSWORD", "s3cret")
    monkeypatch.setenv("OPENVPN_AS_CA_CERT", str(tmp_path / "ca.pem"))
    monkeypatch.setenv("OPENVPN_AS_INSECURE", "true")
    monkeypatch.setenv("OPENVPN_AS_TIMEOUT", "5.5")
    monkeypatch.setenv("OPENVPN_AS_LOG_LEVEL", "DEBUG")
    monkeypatch.setenv("OPENVPN_AS_CONFIG_DIR", str(tmp_path))
    settings = Settings()
    assert settings.url == "https://vpn.example.com:943"
    assert settings.user == "mcp-admin"
    assert isinstance(settings.password, SecretStr)
    assert settings.password.get_secret_value() == "s3cret"
    assert settings.ca_cert == tmp_path / "ca.pem"
    assert settings.insecure is True
    assert settings.timeout == 5.5
    assert settings.log_level == "DEBUG"
    assert settings.config_dir == tmp_path


@pytest.mark.usefixtures("clean_env")
def test_the_password_never_appears_in_repr() -> None:
    settings = Settings(password="s3cret")
    assert "s3cret" not in repr(settings)
    assert "s3cret" not in str(settings)


@pytest.mark.usefixtures("clean_env")
def test_a_non_numeric_timeout_and_a_zero_timeout_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENVPN_AS_TIMEOUT", "soon")
    with pytest.raises(ValidationError):
        Settings()
    monkeypatch.setenv("OPENVPN_AS_TIMEOUT", "0")
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.usefixtures("clean_env")
def test_unknown_openvpn_as_variables_are_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "OPENVPN_AS_TOOLS", "list_users"
    )  # reserved, not implemented yet
    assert Settings().url is None


@pytest.mark.usefixtures("clean_env")
def test_write_mode_is_off_and_approval_is_prompt_by_default() -> None:
    settings = Settings()
    assert settings.write_tools is False
    assert settings.approval == "prompt"
    assert settings.output_dir is None
    assert settings.resolved_output_dir() == settings.config_dir / "output"


@pytest.mark.usefixtures("clean_env")
def test_the_write_mode_variables_are_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("OPENVPN_AS_WRITE_TOOLS", "true")
    monkeypatch.setenv("OPENVPN_AS_APPROVAL", "auto")
    monkeypatch.setenv("OPENVPN_AS_OUTPUT_DIR", str(tmp_path / "out"))
    settings = Settings()
    assert settings.write_tools is True
    assert settings.approval == "auto"
    assert settings.resolved_output_dir() == tmp_path / "out"


@pytest.mark.usefixtures("clean_env")
def test_an_unknown_approval_mode_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENVPN_AS_APPROVAL", "yes")
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.usefixtures("clean_env")
def test_a_tilde_in_a_path_is_the_home_folder(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A JSON client config has no shell to expand it."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("OPENVPN_AS_OUTPUT_DIR", "~/qa-out")
    monkeypatch.setenv("OPENVPN_AS_CONFIG_DIR", "~/cfg")
    monkeypatch.setenv("OPENVPN_AS_CA_CERT", "~/ca.pem")
    settings = Settings()
    assert settings.resolved_output_dir() == tmp_path / "qa-out"
    assert settings.config_dir == tmp_path / "cfg"
    assert settings.ca_cert == tmp_path / "ca.pem"


@pytest.mark.usefixtures("clean_env")
def test_a_relative_output_folder_is_returned_as_a_full_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("OPENVPN_AS_OUTPUT_DIR", "out")
    resolved = Settings().resolved_output_dir()
    assert resolved.is_absolute() and resolved == Path.cwd() / "out"
