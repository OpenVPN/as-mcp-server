"""dev/pin_release.py pins the release build to uv.lock; these pin how."""

from __future__ import annotations

import importlib.util
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[1] / "dev" / "pin_release.py"
_SPEC = importlib.util.spec_from_file_location("pin_release", _PATH)
pin_release = importlib.util.module_from_spec(_SPEC)
sys.modules["pin_release"] = pin_release
_SPEC.loader.exec_module(pin_release)

PYPROJECT = """\
[project]
name = "demo"
dependencies = [
    "fastmcp>=4.0.3,<5",
    "keyring>=25.6,<26",
]

[dependency-groups]
dev = [
    "pytest>=8.4",
]
"""

LOCKED = [
    "fastmcp==4.0.3",
    "keyring==25.7.0",
    "pywin32==312 ; sys_platform == 'win32'",
]


def test_only_the_dependencies_block_changes_and_it_becomes_the_locked_set() -> None:
    pinned = pin_release.pin(PYPROJECT, LOCKED)
    assert tomllib.loads(pinned)["project"]["dependencies"] == LOCKED
    assert pinned.startswith(PYPROJECT.split("dependencies = [\n")[0])
    assert pinned.endswith(PYPROJECT.split("\n]\n", 1)[1])


def test_a_direct_dependency_without_a_locked_version_stops_the_build() -> None:
    with pytest.raises(SystemExit, match="no pinned version for keyring"):
        pin_release.pin(PYPROJECT, ["fastmcp==4.0.3"])


def test_a_pyproject_without_exactly_one_dependencies_block_stops_the_build() -> None:
    with pytest.raises(SystemExit, match="found 0"):
        pin_release.pin("[project]\nname = 'demo'\n", LOCKED)


def wheel(tmp_path: Path, requires: list[str]) -> Path:
    path = tmp_path / "demo-0.1.0-py3-none-any.whl"
    metadata = "Metadata-Version: 2.4\nName: demo\n" + "".join(
        f"Requires-Dist: {r}\n" for r in requires
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("demo-0.1.0.dist-info/METADATA", metadata)
    return path


def test_a_wheel_with_the_locked_pins_passes_whatever_the_spelling(tmp_path) -> None:
    built = wheel(
        tmp_path,
        ["FastMCP==4.0.3", "keyring==25.7.0", 'pywin32==312; sys_platform == "win32"'],
    )
    assert pin_release.verify(built, LOCKED) == []


def test_a_wheel_with_ranges_or_a_lost_marker_fails(tmp_path) -> None:
    built = wheel(tmp_path, ["fastmcp>=4.0.3,<5", "keyring==25.7.0", "pywin32==312"])
    assert pin_release.verify(built, LOCKED) == [
        "missing: fastmcp==4.0.3",
        "missing: pywin32==312 ; sys_platform == 'win32'",
        "unexpected: fastmcp>=4.0.3,<5",
        "unexpected: pywin32==312",
    ]


def test_the_real_lock_pins_every_direct_dependency_of_the_project() -> None:
    root = _PATH.parents[1]
    requirements = pin_release.locked_requirements(root)
    pinned = pin_release.pin((root / "pyproject.toml").read_text(), requirements)
    assert all("==" in r for r in tomllib.loads(pinned)["project"]["dependencies"])
