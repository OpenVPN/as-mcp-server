"""The audit log of write mode: one JSON line per write attempt, never a secret.

The file is `audit.jsonl` in the configuration directory, readable by its owner only.
It records what was asked, by which account, on which server and how it ended, also
when nothing was changed.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from fastmcp.exceptions import ToolError

from as_mcp_server.client import redact

Outcome = Literal[
    "applied",
    "partial",
    "cancelled",
    "refused_changed",
    "refused_no_approval",
    "refused_lockout",
    "refused_auto_limit",
    "failed",
    "unknown_after_timeout",
]
FILE_NAME = "audit.jsonl"
# json.dumps leaves these in a string as they are, and tools that split a file into
# lines break on them.
_LINE_BREAKS = {chr(code): f"\\u{code:04x}" for code in (0x85, 0x2028, 0x2029)}


class AuditError(ToolError):
    """The audit log cannot be written."""


def _now() -> datetime:
    return datetime.now(UTC)


class AuditLog:
    # ponytail: no rotation. The file only grows; one line is a few hundred bytes.
    def __init__(self, config_dir: Path, clock: Callable[[], datetime] = _now) -> None:
        self.path = Path(config_dir) / FILE_NAME
        self._clock = clock

    def probe(self) -> None:
        """Fail now, before anything is changed, when a line could not be written."""
        os.close(self._open())

    def append(
        self,
        *,
        tool: str,
        target: str,
        outcome: Outcome,
        approval: str,
        server_url: str,
        server_version: str,
        version_tested: bool,
        admin_user: str,
        before: Any,
        after: Any,
        batch_id: str | None = None,
        error: str | None = None,
    ) -> str:
        """Write one line and return its change_id."""
        change_id = str(uuid.uuid4())
        record = {
            "ts": self._clock().astimezone(UTC).isoformat(),
            "change_id": change_id,
            "batch_id": batch_id,
            "tool": tool,
            "target": target,
            "outcome": outcome,
            "approval": approval,
            "server_url": server_url,
            "server_version": server_version,
            "version_tested": version_tested,
            "admin_user": admin_user,
            "before": redact(before),
            "after": redact(after),
            "error": error,
        }
        line = json.dumps(record, ensure_ascii=False, default=str)
        for character, escaped in _LINE_BREAKS.items():
            line = line.replace(character, escaped)
        descriptor = self._open()
        try:
            os.write(descriptor, f"{line}\n".encode())
        except OSError as exc:
            raise self._error(exc) from exc
        finally:
            os.close(descriptor)
        return change_id

    def _open(self) -> int:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            return os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        except OSError as exc:
            raise self._error(exc) from exc

    def _error(self, exc: OSError) -> AuditError:
        return AuditError(
            f"Cannot write the audit log {self.path}: {exc.strerror or exc}. "
            "as-mcp-server makes no change it cannot record; make the file writable "
            "for this user or set OPENVPN_AS_CONFIG_DIR."
        )
