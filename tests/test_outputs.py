"""Secrets go to private local files, never over a file that is already there."""

from __future__ import annotations

import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path

import pytest
from fastmcp.exceptions import ToolError

from as_mcp_server.outputs import (
    DELIVERY_REMINDER,
    OutputError,
    probe_output_dir,
    write_secret_file,
)

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX file modes do not exist on Windows"
)
not_root = pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file modes"
)
NOW = datetime(2026, 11, 13, 21, 30, 5)


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_the_file_name_is_time_kind_name_and_extension(tmp_path: Path) -> None:
    path = write_secret_file(tmp_path / "out", "profile", "alice", "ovpn", "BODY")
    assert path.parent == tmp_path / "out"
    assert re.fullmatch(r"\d{8}-\d{6}-profile-alice\.ovpn", path.name)
    fixed = write_secret_file(tmp_path, "password", "alice", "txt", "x", now=NOW)
    assert fixed.name == "20261113-213005-password-alice.txt"


def test_the_content_is_written_exactly_also_line_endings(tmp_path: Path) -> None:
    body = "client\nremote as.example 1194\r\n<key>\n密钥\n</key>\n"
    path = write_secret_file(tmp_path, "profile", "alice", "ovpn", body, now=NOW)
    assert path.read_bytes() == body.encode("utf-8")


@posix_only
def test_file_and_new_directory_are_private_to_the_user(tmp_path: Path) -> None:
    directory = tmp_path / "deep" / "out"
    path = write_secret_file(directory, "profile", "alice", "ovpn", "BODY", now=NOW)
    assert mode(path) == 0o600
    assert mode(directory) == 0o700


@posix_only
def test_the_mode_does_not_depend_on_the_umask(tmp_path: Path) -> None:
    previous = os.umask(0)
    try:
        directory = tmp_path / "out"
        path = write_secret_file(directory, "profile", "a", "ovpn", "BODY", now=NOW)
    finally:
        os.umask(previous)
    assert mode(path) == 0o600 and mode(directory) == 0o700


@posix_only
def test_a_directory_the_admin_already_has_keeps_its_mode(tmp_path: Path) -> None:
    """OPENVPN_AS_OUTPUT_DIR may be a folder with other things in it."""
    tmp_path.chmod(0o755)
    path = write_secret_file(tmp_path, "profile", "alice", "ovpn", "BODY", now=NOW)
    assert mode(tmp_path) == 0o755 and mode(path) == 0o600


def test_a_second_file_in_the_same_second_gets_its_own_name(tmp_path: Path) -> None:
    first = write_secret_file(tmp_path, "profile", "alice", "ovpn", "FIRST", now=NOW)
    second = write_secret_file(tmp_path, "profile", "alice", "ovpn", "SECOND", now=NOW)
    third = write_secret_file(tmp_path, "profile", "alice", "ovpn", "THIRD", now=NOW)
    assert first.name == "20261113-213005-profile-alice.ovpn"
    assert second.name == "20261113-213005-profile-alice-2.ovpn"
    assert third.name == "20261113-213005-profile-alice-3.ovpn"
    assert [p.read_text() for p in (first, second, third)] == [
        "FIRST",
        "SECOND",
        "THIRD",
    ]


def test_names_that_differ_only_in_letter_case_do_not_overwrite_each_other(
    tmp_path: Path,
) -> None:
    """Access Server usernames are case-sensitive; macOS and Windows file names are
    not."""
    lower = write_secret_file(tmp_path, "password", "alice", "txt", "lower", now=NOW)
    upper = write_secret_file(tmp_path, "password", "Alice", "txt", "upper", now=NOW)
    assert lower != upper
    assert lower.read_text() == "lower" and upper.read_text() == "upper"


def test_an_existing_file_is_never_overwritten(tmp_path: Path) -> None:
    taken = tmp_path / "20261113-213005-profile-alice.ovpn"
    taken.write_text("the admin's own file")
    path = write_secret_file(tmp_path, "profile", "alice", "ovpn", "NEW", now=NOW)
    assert path != taken and taken.read_text() == "the admin's own file"


@posix_only
def test_a_link_planted_under_the_file_name_is_not_followed(tmp_path: Path) -> None:
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    (tmp_path / "20261113-213005-profile-alice.ovpn").symlink_to(victim)
    path = write_secret_file(tmp_path, "profile", "alice", "ovpn", "SECRET", now=NOW)
    assert victim.read_text() == "untouched"
    assert not path.is_symlink() and path.read_text() == "SECRET"


@pytest.mark.parametrize(
    ("name", "component"),
    [
        ("../../etc/x", "_.._etc_x"),
        ("a/b", "a_b"),
        ("a\\b", "a_b"),
        ("a\x00b", "a_b"),
        ("a\nb\tc", "a_b_c"),
        ("qa vpn test user", "qa_vpn_test_user"),
        ("...hidden", "hidden"),
        ("..", "unnamed"),
        ("", "unnamed"),
        ("   ", "___"),
        ("жанна", "жанна"),
        ("user@example.com", "user_example.com"),
        ("C:\\Windows\\x", "C__Windows_x"),
        ("a" * 200, "a" * 64),
    ],
)
def test_any_name_becomes_one_safe_path_component(
    tmp_path: Path, name: str, component: str
) -> None:
    path = write_secret_file(tmp_path, "profile", name, "ovpn", "BODY", now=NOW)
    assert path.name == f"20261113-213005-profile-{component}.ovpn"
    assert path.parent == tmp_path
    assert [p.name for p in tmp_path.iterdir()] == [path.name]


def test_two_names_that_clean_to_the_same_text_get_two_files(tmp_path: Path) -> None:
    one = write_secret_file(tmp_path, "profile", "a/b", "ovpn", "ONE", now=NOW)
    two = write_secret_file(tmp_path, "profile", "a_b", "ovpn", "TWO", now=NOW)
    assert one != two and one.read_text() == "ONE" and two.read_text() == "TWO"


@pytest.mark.parametrize("ext", ["../x", "o/vpn", "", "tar.gz", "a b"])
def test_an_extension_that_is_not_plain_letters_is_a_programming_error(
    tmp_path: Path, ext: str
) -> None:
    with pytest.raises(ValueError, match="extension"):
        write_secret_file(tmp_path, "profile", "alice", ext, "BODY", now=NOW)
    assert list(tmp_path.iterdir()) == []


def test_probe_creates_the_directory_and_leaves_it_empty(tmp_path: Path) -> None:
    directory = tmp_path / "a" / "b"
    probe_output_dir(directory)
    assert directory.is_dir() and list(directory.iterdir()) == []
    probe_output_dir(directory)  # and again on an existing one
    assert list(directory.iterdir()) == []


@posix_only
@not_root
def test_probe_on_a_read_only_directory_names_the_directory(tmp_path: Path) -> None:
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(OutputError) as refused:
            probe_output_dir(tmp_path)
    finally:
        tmp_path.chmod(0o700)
    assert str(tmp_path) in str(refused.value)
    assert "OPENVPN_AS_OUTPUT_DIR" in str(refused.value)


@posix_only
@not_root
def test_probe_names_the_directory_it_could_not_create(tmp_path: Path) -> None:
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(OutputError) as refused:
            probe_output_dir(tmp_path / "new")
    finally:
        tmp_path.chmod(0o700)
    assert str(tmp_path / "new") in str(refused.value)


def test_a_file_in_place_of_the_directory_is_an_error_not_a_crash(
    tmp_path: Path,
) -> None:
    blocker = tmp_path / "output"
    blocker.write_text("I am a file")
    with pytest.raises(OutputError, match="not a directory"):
        probe_output_dir(blocker)
    with pytest.raises(OutputError):
        write_secret_file(blocker, "profile", "alice", "ovpn", "BODY", now=NOW)
    assert blocker.read_text() == "I am a file"


@posix_only
@not_root
def test_a_write_that_fails_says_where_and_never_shows_the_secret(
    tmp_path: Path,
) -> None:
    tmp_path.chmod(0o500)
    try:
        with pytest.raises(OutputError) as refused:
            write_secret_file(
                tmp_path, "password", "alice", "txt", "LEAK-secret", now=NOW
            )
    finally:
        tmp_path.chmod(0o700)
    assert str(tmp_path) in str(refused.value)
    assert "LEAK-secret" not in str(refused.value)


def test_an_output_error_reaches_the_agent_as_a_tool_error() -> None:
    assert issubclass(OutputError, ToolError)


def test_the_reminder_text_is_fixed() -> None:
    assert DELIVERY_REMINDER == "Delete the file once it has been delivered."
