"""The keyring wrapper stores one secret per profile and explains every failure."""

from __future__ import annotations

import keyring.errors
import pytest

from as_mcp_server import secrets


def test_set_get_delete_round_trip(memory_keyring) -> None:
    assert secrets.get_password("default") is None
    secrets.set_password("default", "s3cret")
    assert memory_keyring.store == {(secrets.SERVICE_NAME, "default"): "s3cret"}
    assert secrets.get_password("default") == "s3cret"
    assert secrets.delete_password("default") is True
    assert secrets.delete_password("default") is False
    assert secrets.get_password("default") is None


def test_the_service_name_is_the_public_contract() -> None:
    assert secrets.SERVICE_NAME == "as-mcp-server"


def test_status_reports_a_usable_backend_by_class_path(memory_keyring) -> None:
    usable, description = secrets.keyring_status()
    assert usable is True
    assert description.endswith("MemoryKeyring")


@pytest.mark.usefixtures("no_keyring")
def test_status_reports_the_fail_backend_as_unusable() -> None:
    usable, description = secrets.keyring_status()
    assert usable is False
    assert "no usable OS keyring backend" in description
    assert "fail.Keyring" in description


@pytest.mark.usefixtures("no_keyring")
def test_every_operation_becomes_a_secret_store_error_without_a_backend() -> None:
    with pytest.raises(secrets.SecretStoreError, match="no OS keyring backend"):
        secrets.get_password("default")
    with pytest.raises(secrets.SecretStoreError, match="no OS keyring backend"):
        secrets.set_password("default", "x")
    with pytest.raises(secrets.SecretStoreError, match="no OS keyring backend"):
        secrets.delete_password("default")


@pytest.mark.parametrize(
    ("error", "explanation"),
    [
        (keyring.errors.KeyringLocked("denied"), "locked or access was denied"),
        (keyring.errors.InitError("dbus gone"), "the OS keyring failed: dbus gone"),
    ],
)
def test_a_keyring_that_refuses_access_is_explained(
    memory_keyring, monkeypatch: pytest.MonkeyPatch, error, explanation: str
) -> None:
    """macOS asks again after a uvx upgrade; a refusal is not 'nothing stored'."""

    def refuse(service: str, username: str) -> None:
        raise error

    monkeypatch.setattr(memory_keyring, "get_password", refuse)
    with pytest.raises(secrets.SecretStoreError, match=explanation):
        secrets.get_password("default")
