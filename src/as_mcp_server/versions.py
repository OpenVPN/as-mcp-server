"""Which Access Server versions this release reads from and writes to.

The tested list holds minor versions. An untested newer minor may be written to
with a warning; below the minimum, or a version that cannot be read, is refused.
"""

from __future__ import annotations

from typing import Literal

from as_mcp_server import __version__
from as_mcp_server.texts import MSG_UNTESTED

MINIMUM_VERSION = (3, 1)
TESTED_MINORS = frozenset({(3, 1), (3, 2)})

VersionStatus = Literal["tested", "untested", "unsupported"]


def parse_minor(version: str) -> tuple[int, int] | None:
    """`(major, minor)` of a version string, or None when it cannot be read."""
    parts = version.split(".")
    if len(parts) < 2:
        return None
    try:
        return int(parts[0]), int(parts[1])
    except ValueError:
        return None


def version_status(version: str) -> VersionStatus:
    minor = parse_minor(version)
    if minor is None or minor < MINIMUM_VERSION:
        return "unsupported"
    return "tested" if minor in TESTED_MINORS else "untested"


def below_minimum_version(version: str) -> bool:
    minor = parse_minor(version)
    return minor is None or minor < MINIMUM_VERSION


def untested_warning(version: str) -> str:
    server = parse_minor(version)
    mcp = parse_minor(__version__)
    return MSG_UNTESTED.format(
        server=f"{server[0]}.{server[1]}" if server else version,
        mcp=f"{mcp[0]}.{mcp[1]}" if mcp else __version__,
    )
