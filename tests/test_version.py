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


ROOT = PYPROJECT.parent
ALLOWED_MINORS = (12, 13, 14)


def _windows_wheel_for(wheels: list[str], minor: int) -> bool:
    for wheel in wheels:
        if "win_amd64" not in wheel:
            continue
        python, abi = wheel.split("-")[-3:-1]
        if python.startswith("py3") and abi == "none":
            return True
        if abi == "abi3" and int(python.removeprefix("cp3")) <= minor:
            return True
        if python == abi == f"cp3{minor}":
            return True
    return False


def test_python_3_15_is_refused_until_every_binary_dependency_builds_on_windows() -> (
    None
):
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    assert project["requires-python"] == ">=3.12,<3.15"
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    for package in lock["package"]:
        wheels = [w["url"].rsplit("/", 1)[-1] for w in package.get("wheels", [])]
        if not wheels or any(w.endswith("-none-any.whl") for w in wheels):
            continue  # pure Python, or a pure fallback
        for minor in ALLOWED_MINORS:
            assert _windows_wheel_for(wheels, minor), (package["name"], minor)


def test_the_readme_still_names_python_3_13_in_every_command() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "uvx --python 3.13 as-mcp-server setup" in readme
    assert "--python 3.15" not in readme
