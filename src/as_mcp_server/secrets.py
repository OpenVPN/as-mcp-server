"""OS keyring access for the one secret this server stores: the Access Server password.

Every keyring failure becomes a SecretStoreError whose text says what to do instead
(the OPENVPN_AS_PASSWORD fallback), so callers never need to know keyring's exception
hierarchy. The item is stored under service "as-mcp-server" with the profile name as
the account, so a future multi-instance release adds profiles without touching this
module.
"""

from __future__ import annotations

import keyring
import keyring.core
from keyring import errors as keyring_errors

SERVICE_NAME = "as-mcp-server"


class SecretStoreError(Exception):
    """The OS keyring is unavailable, locked, or refused the operation."""


def keyring_status() -> tuple[bool, str]:
    """(usable, description) without raising.

    keyring falls back to its own `fail`/`null` backends (priority < 1) when no real
    store is available - the headless-Linux-without-Secret-Service case - and
    `recommended()` is False for exactly those.
    """
    try:
        backend = keyring.get_keyring()
    except Exception as exc:  # keyring may raise anything while probing
        return False, f"keyring initialisation failed: {exc}"
    name = f"{type(backend).__module__}.{type(backend).__qualname__}"
    if not keyring.core.recommended(backend):
        return False, f"no usable OS keyring backend (active backend: {name})"
    return True, name


def get_password(profile: str) -> str | None:
    """The stored password, or None when nothing is stored for this profile."""
    try:
        return keyring.get_password(SERVICE_NAME, profile)
    except keyring_errors.KeyringError as exc:
        raise SecretStoreError(_describe(exc)) from exc


def set_password(profile: str, password: str) -> None:
    try:
        keyring.set_password(SERVICE_NAME, profile, password)
    except keyring_errors.KeyringError as exc:
        raise SecretStoreError(_describe(exc)) from exc


def delete_password(profile: str) -> bool:
    """Remove the stored password; False when nothing was stored."""
    try:
        keyring.delete_password(SERVICE_NAME, profile)
    except keyring_errors.PasswordDeleteError:
        return False
    except keyring_errors.KeyringError as exc:
        raise SecretStoreError(_describe(exc)) from exc
    return True


def _describe(exc: keyring_errors.KeyringError) -> str:
    if isinstance(exc, keyring_errors.NoKeyringError):
        return f"no OS keyring backend is available ({exc})"
    if isinstance(exc, keyring_errors.KeyringLocked):
        return f"the OS keyring is locked or access was denied ({exc})"
    return f"the OS keyring failed: {exc}"
