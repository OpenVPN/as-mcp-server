"""Every write attempt leaves one line in audit.jsonl, and no secret does."""

from __future__ import annotations

import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from as_mcp_server import audit
from as_mcp_server.audit import AuditError, AuditLog

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file modes do not exist on Windows"
)


def entry(**overrides: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "tool": "block_user",
        "target": "alice",
        "outcome": "applied",
        "approval": "prompt",
        "server_url": "https://as.example:943",
        "server_version": "3.2.4",
        "version_tested": True,
        "admin_user": "openvpn",
        "before": {"deny": False},
        "after": {"deny": True},
    }
    return {**values, **overrides}


def lines(config_dir: Path) -> list[dict[str, Any]]:
    text = (config_dir / "audit.jsonl").read_text(encoding="utf-8")
    assert text.endswith("\n")
    return [json.loads(line) for line in text.splitlines()]


def test_two_changes_are_two_json_lines_with_their_own_change_id(
    tmp_path: Path,
) -> None:
    log = AuditLog(tmp_path)
    first = log.append(**entry())
    second = log.append(**entry(target="bob"))
    written = lines(tmp_path)
    assert [line["change_id"] for line in written] == [first, second]
    assert first != second and len(first) == 36
    assert [line["target"] for line in written] == ["alice", "bob"]


def test_a_line_carries_who_what_where_when_and_the_outcome(tmp_path: Path) -> None:
    at = datetime(2026, 11, 13, 21, 30, 5, tzinfo=timezone(timedelta(hours=2)))
    log = AuditLog(tmp_path, clock=lambda: at)
    change_id = log.append(
        **entry(outcome="failed", batch_id="b-1", error="Access Server said no")
    )
    assert lines(tmp_path) == [
        {
            "ts": "2026-11-13T19:30:05+00:00",
            "change_id": change_id,
            "batch_id": "b-1",
            "tool": "block_user",
            "target": "alice",
            "outcome": "failed",
            "approval": "prompt",
            "server_url": "https://as.example:943",
            "server_version": "3.2.4",
            "version_tested": True,
            "admin_user": "openvpn",
            "before": {"deny": False},
            "after": {"deny": True},
            "error": "Access Server said no",
        }
    ]


def test_the_default_clock_writes_the_current_time_in_utc(tmp_path: Path) -> None:
    before = datetime.now(UTC)
    AuditLog(tmp_path).append(**entry())
    written = datetime.fromisoformat(lines(tmp_path)[0]["ts"])
    assert written.utcoffset() == timedelta(0)
    assert before - timedelta(seconds=1) <= written <= datetime.now(UTC)


def test_secrets_in_before_and_after_are_written_redacted(tmp_path: Path) -> None:
    AuditLog(tmp_path).append(
        **entry(
            before={"password": "LEAK-old", "name": "alice"},
            after={
                "name": "alice",
                "nested": [{"totp_secret": "LEAK-totp", "auth_token": "LEAK-token"}],
            },
        )
    )
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "LEAK" not in text
    line = lines(tmp_path)[0]
    assert line["before"] == {"password": "<redacted>", "name": "alice"}
    assert line["after"]["nested"] == [
        {"totp_secret": "<redacted>", "auth_token": "<redacted>"}
    ]


def test_a_value_with_line_breaks_or_other_alphabets_stays_one_line(
    tmp_path: Path,
) -> None:
    log = AuditLog(tmp_path)
    log.append(**entry(target="жанна", error="first\nsecond\r\nthird\u2028fourth"))
    log.append(**entry())
    raw = (tmp_path / "audit.jsonl").read_bytes()
    assert raw.count(b"\n") == 2
    assert "жанна".encode() in raw
    first = lines(tmp_path)[0]
    assert first["target"] == "жанна"
    assert first["error"] == "first\nsecond\r\nthird\u2028fourth"


def test_a_value_json_cannot_hold_is_written_as_text_not_dropped(
    tmp_path: Path,
) -> None:
    AuditLog(tmp_path).append(
        **entry(
            before={"path": Path("/tmp/x"), "when": datetime(2026, 1, 2, tzinfo=UTC)}
        )
    )
    before = lines(tmp_path)[0]["before"]
    assert before == {
        "path": str(Path("/tmp/x")),
        "when": "2026-01-02 00:00:00+00:00",
    }


@posix_only
def test_the_file_is_private_to_the_user(tmp_path: Path) -> None:
    AuditLog(tmp_path).append(**entry())
    assert stat.S_IMODE((tmp_path / "audit.jsonl").stat().st_mode) == 0o600


def test_a_missing_config_directory_is_created(tmp_path: Path) -> None:
    config_dir = tmp_path / "not" / "there"
    AuditLog(config_dir).append(**entry())
    assert len(lines(config_dir)) == 1


def test_lines_of_an_earlier_run_are_kept(tmp_path: Path) -> None:
    AuditLog(tmp_path).append(**entry(target="first"))
    AuditLog(tmp_path).append(**entry(target="second"))
    assert [line["target"] for line in lines(tmp_path)] == ["first", "second"]


def test_probe_passes_and_writes_nothing_when_the_log_can_be_written(
    tmp_path: Path,
) -> None:
    log = AuditLog(tmp_path / "new")
    log.probe()
    assert (tmp_path / "new" / "audit.jsonl").read_text(encoding="utf-8") == ""
    log.append(**entry())
    log.probe()
    assert len(lines(tmp_path / "new")) == 1


@posix_only
@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file modes"
)
def test_a_log_that_cannot_be_written_is_an_error_naming_the_file(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o500)
    try:
        log = AuditLog(tmp_path)
        with pytest.raises(AuditError, match=r"audit\.jsonl") as probe:
            log.probe()
        assert str(tmp_path) in str(probe.value)
        with pytest.raises(AuditError, match=r"audit\.jsonl"):
            log.append(**entry())
    finally:
        tmp_path.chmod(0o700)


def test_a_directory_in_place_of_the_file_is_an_error_not_a_crash(
    tmp_path: Path,
) -> None:
    (tmp_path / "audit.jsonl").mkdir()
    with pytest.raises(AuditError, match=r"audit\.jsonl"):
        AuditLog(tmp_path).append(**entry())


def test_the_module_says_that_the_log_is_not_rotated() -> None:
    source = Path(audit.__file__).read_text(encoding="utf-8")
    assert "# ponytail: no rotation" in source
