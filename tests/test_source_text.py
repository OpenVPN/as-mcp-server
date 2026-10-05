"""Invisible characters in the sources hide what the code does (Trojan Source)."""

from __future__ import annotations

import subprocess
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HIDDEN = ("Cf", "Co", "Cn")
BLANK = "\u00a0\u3164"


def tracked_text_files() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True
    )
    if listed.returncode != 0:
        pytest.skip("not a git checkout")
    names = listed.stdout.splitlines()
    files = []
    for name in names:
        path = ROOT / name
        try:
            path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        files.append(path)
    return files


def test_no_tracked_file_contains_raw_invisible_or_bidi_characters() -> None:
    """Tests that need such characters write them as escapes, e.g. \\u202e."""
    found = []
    for path in tracked_text_files():
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, 1):
            found += [
                f"{path.relative_to(ROOT)}:{number} U+{ord(ch):04X}"
                for ch in line
                if unicodedata.category(ch) in HIDDEN or ch in BLANK
            ]
    assert found == []
