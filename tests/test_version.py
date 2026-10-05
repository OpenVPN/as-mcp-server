"""The installed distribution reports its own version, and the CLI prints it."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from as_mcp_server import __version__
from as_mcp_server.cli import main

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"
PROJECT_VERSION = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"][
    "version"
]


def test_the_package_version_is_the_pyproject_version() -> None:
    assert __version__ == PROJECT_VERSION


def test_dash_dash_version_prints_name_and_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"as-mcp-server {PROJECT_VERSION}"
