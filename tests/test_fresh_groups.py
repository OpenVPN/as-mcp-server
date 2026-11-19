from __future__ import annotations

import json
import sys
from pathlib import Path

from as_mcp_server.fresh_groups import FILE_NAME, FreshGroups

URL = "https://as.example:943"
T1, T2 = "2026-09-09T20:47:29.403414Z", "2026-09-10T08:00:00.000000Z"


def test_a_created_group_is_fresh_until_the_server_shows_another_restart(
    tmp_path: Path,
) -> None:
    groups = FreshGroups(tmp_path)
    assert not groups.has(URL, T1, "sales")
    groups.add(URL, T1, "Sales")
    assert groups.has(URL, T1, "sales") and groups.has(URL, T1, "SALES")
    assert not groups.has(URL, T2, "sales")
    assert not groups.has("https://other.example", T1, "sales")
    assert not groups.has(URL, T1, "support")


def test_the_list_is_still_there_in_the_next_session(tmp_path: Path) -> None:
    FreshGroups(tmp_path).add(URL, T1, "sales")
    assert FreshGroups(tmp_path).has(URL, T1, "sales")
    if sys.platform != "win32":
        assert (tmp_path / FILE_NAME).stat().st_mode & 0o777 == 0o600


def test_a_group_created_after_a_restart_drops_the_names_from_before_it(
    tmp_path: Path,
) -> None:
    groups = FreshGroups(tmp_path)
    groups.add(URL, T1, "old")
    groups.add(URL, T2, "new")
    assert groups.has(URL, T2, "new")
    assert not groups.has(URL, T2, "old") and not groups.has(URL, T1, "old")
    stored = json.loads((tmp_path / FILE_NAME).read_text())
    assert stored["servers"][URL] == {"restarted": T2, "groups": ["new"]}


def test_a_deleted_group_is_no_longer_fresh(tmp_path: Path) -> None:
    groups = FreshGroups(tmp_path)
    groups.add(URL, T1, "sales")
    groups.add(URL, T1, "support")
    groups.remove(URL, "SALES")
    groups.remove(URL, "never-there")
    assert not groups.has(URL, T1, "sales") and groups.has(URL, T1, "support")
    groups.remove(URL, "support")
    assert json.loads((tmp_path / FILE_NAME).read_text())["servers"] == {}


def test_two_servers_do_not_share_a_list(tmp_path: Path) -> None:
    groups = FreshGroups(tmp_path)
    groups.add(URL, T1, "sales")
    groups.add("https://other.example", T2, "sales")
    assert groups.has(URL, T1, "sales")
    assert groups.has("https://other.example", T2, "sales")


def test_a_broken_or_unwritable_file_is_an_empty_list_not_an_error(
    tmp_path: Path,
) -> None:
    (tmp_path / FILE_NAME).write_text("{ not json")
    groups = FreshGroups(tmp_path)
    assert not groups.has(URL, T1, "sales")
    groups.add(URL, T1, "sales")
    assert groups.has(URL, T1, "sales")
    (tmp_path / FILE_NAME).write_text('{"servers": {"x": {"groups": 5}, "y": []}}')
    assert not groups.has("x", T1, "sales")
    blocked = FreshGroups(tmp_path / FILE_NAME / "below-a-file")
    blocked.add(URL, T1, "sales")
    assert not blocked.has(URL, T1, "sales")
