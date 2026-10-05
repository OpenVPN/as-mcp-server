"""Pin the release build to the runtime dependency versions in uv.lock.

Usage: uv run --frozen python dev/pin_release.py
       uv run --frozen python dev/pin_release.py --verify dist/<wheel>.whl

pyproject.toml keeps version ranges for development. The release workflow runs this
script right before `uv build`, so the published package requires exactly the versions
the tests ran against: [project].dependencies is replaced in place by the runtime set
`uv export` prints from uv.lock, platform markers included. With --verify it checks that
a built wheel requires exactly that set and exits 1 otherwise.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
_DEPENDENCIES = re.compile(r"^dependencies = \[\n(.*?)^\]\n", re.MULTILINE | re.DOTALL)
_NAME = re.compile(r"[A-Za-z0-9._-]+")


def locked_requirements(root: Path = ROOT) -> list[str]:
    """Every runtime package in uv.lock as `name==version[ ; marker]`."""
    out = subprocess.run(
        [
            "uv",
            "export",
            "--frozen",
            "--no-dev",
            "--no-hashes",
            "--no-emit-project",
            "--no-header",
            "--no-annotate",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [line.strip() for line in out.splitlines() if line.strip()]


def name_of(requirement: str) -> str:
    return re.sub(r"[-_.]+", "-", _NAME.match(requirement.strip()).group()).lower()


def normalize(requirement: str) -> str:
    """One spelling: canonical name, no spaces in the version, single-quoted marker."""
    spec, _, marker = requirement.partition(";")
    spec = spec.strip()
    text = name_of(spec) + spec[_NAME.match(spec).end() :].replace(" ", "")
    marker = " ".join(marker.replace('"', "'").split())
    return f"{text} ; {marker}" if marker else text


def pin(pyproject: str, requirements: list[str]) -> str:
    """pyproject.toml text with [project].dependencies replaced by `requirements`."""
    blocks = _DEPENDENCIES.findall(pyproject)
    if len(blocks) != 1:
        raise SystemExit(f"expected one 'dependencies = [' block, found {len(blocks)}")
    direct = {name_of(line.strip().strip('",')) for line in blocks[0].splitlines()}
    missing = sorted(direct - {name_of(r) for r in requirements})
    if missing:
        raise SystemExit(f"uv.lock has no pinned version for {', '.join(missing)}")
    lines = "".join(f'    "{r}",\n' for r in requirements)
    return _DEPENDENCIES.sub(lambda _: f"dependencies = [\n{lines}]\n", pyproject)


def wheel_requirements(wheel: Path) -> list[str]:
    with zipfile.ZipFile(wheel) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".dist-info/METADATA"))
        metadata = archive.read(name).decode("utf-8")
    return [
        line.removeprefix("Requires-Dist:").strip()
        for line in metadata.splitlines()
        if line.startswith("Requires-Dist:")
    ]


def verify(wheel: Path, requirements: list[str]) -> list[str]:
    """Differences between the wheel's requirements and the locked set."""
    got = {normalize(r) for r in wheel_requirements(wheel)}
    want = {normalize(r) for r in requirements}
    return [f"missing: {r}" for r in sorted(want - got)] + [
        f"unexpected: {r}" for r in sorted(got - want)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--verify", type=Path, metavar="WHEEL")
    args = parser.parse_args()
    requirements = locked_requirements()
    if args.verify:
        problems = verify(args.verify, requirements)
        for problem in problems:
            print(problem)
        print(f"{args.verify.name}: {len(requirements)} pins, {len(problems)} problems")
        return 1 if problems else 0
    PYPROJECT.write_text(pin(PYPROJECT.read_text(), requirements))
    print(f"pinned {len(requirements)} runtime dependencies in {PYPROJECT.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
