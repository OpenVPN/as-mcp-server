"""Secret files of write mode: profiles, download links, passwords, support reports.

A secret never goes into a tool result. It is written to a file only its owner can
read, in a folder the administrator chose, and the tool returns the path.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Literal

from fastmcp.exceptions import ToolError

Kind = Literal[
    "profile-userlocked",
    "profile-autologin",
    "download-link-userlocked",
    "download-link-autologin",
    "password",
    "support-report",
]
DELIVERY_REMINDER = "Delete the file once it has been delivered."
MAX_NAME = 64
MAX_NAME_BYTES = 160
# How many files with the same time, kind and name are told apart by a number.
MAX_SAME_NAME = 1000
_NO_FOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)


class OutputError(ToolError):
    """The output folder or a file in it cannot be written."""


def _error(directory: Path, reason: str) -> OutputError:
    return OutputError(
        f"Cannot write to the output folder {directory}: {reason}. Set "
        "OPENVPN_AS_OUTPUT_DIR to a folder this user can write to."
    )


def _ensure_directory(directory: Path) -> None:
    """Create the folder private to the user; a folder that exists is left as it is."""
    try:
        if directory.is_dir():
            return
        if directory.exists():
            raise _error(directory, "it is not a directory")
        directory.mkdir(parents=True)
        directory.chmod(0o700)
    except OSError as exc:
        raise _error(directory, exc.strerror or str(exc)) from exc


def _create(path: Path) -> int:
    """A new file nobody else can read. Never an existing file, never through a link."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NO_FOLLOW | _BINARY
    return os.open(path, flags, 0o600)


def probe_output_dir(directory: Path) -> None:
    """Fail now, before a secret exists on the server, when it could not be saved."""
    _ensure_directory(directory)
    probe = directory / f".as-mcp-server-probe-{os.getpid()}-{os.urandom(4).hex()}"
    try:
        os.close(_create(probe))
        probe.unlink()
    except OSError as exc:
        raise _error(directory, exc.strerror or str(exc)) from exc


def safe_component(name: str) -> str:
    """`name` as one path component: letters, digits, `.`, `_` and `-` only."""
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
    cleaned = cleaned.lstrip(".")[:MAX_NAME]
    # A file name is limited in bytes (255 on most file systems), not in characters.
    while len(cleaned.encode("utf-8")) > MAX_NAME_BYTES:
        cleaned = cleaned[:-1]
    return cleaned or "unnamed"


def write_secret_file(
    directory: Path,
    kind: Kind,
    name: str,
    ext: str,
    data: str,
    now: datetime | None = None,
) -> Path:
    """Write `data` to `<YYYYmmdd-HHMMSS>-<kind>-<name>.<ext>` and return the path.

    A name that is taken gets `-2`, `-3`, ... before the extension, so two files of
    one second, or two usernames that differ only in letter case, never overwrite
    each other.
    """
    if not (ext.isascii() and ext.isalnum()):
        raise ValueError(f"file extension must be plain letters and digits: {ext!r}")
    _ensure_directory(directory)
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    stem = f"{stamp}-{kind}-{safe_component(name)}"
    for number in range(1, MAX_SAME_NAME + 1):
        suffix = "" if number == 1 else f"-{number}"
        path = directory / f"{stem}{suffix}.{ext}"
        try:
            descriptor = _create(path)
        except FileExistsError:
            continue
        except OSError as exc:
            if path.is_symlink():  # O_NOFOLLOW on a planted link
                continue
            raise _error(directory, exc.strerror or str(exc)) from exc
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data.encode("utf-8"))
        except OSError as exc:
            path.unlink(missing_ok=True)
            raise _error(directory, exc.strerror or str(exc)) from exc
        return path
    raise _error(directory, f"{MAX_SAME_NAME} files named {stem} already exist")
