"""The text an administrator approves before a change is written.

Every name and value in it came from the server or from the agent, so each one goes
through `clean()`: one value is one piece of one line, whatever it contains.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from as_mcp_server.effective import UNKNOWN

CUT = "…"
UNKNOWN_TEXT = "inherited (server-wide value unknown)"
# Line and paragraph separators, and the C1 "next line": line breaks to a terminal.
_BREAKS = {"Zl", "Zp"}
# Control, format (bidi overrides, zero-width), surrogate and private-use characters.
_DROPPED = {"Cc", "Cf", "Cs", "Co", "Cn"}


def clean(text: Any, limit: int = 120) -> str:
    """`text` as part of one line: no line breaks, no control or invisible
    characters, single spaces, at most `limit` characters (a cut ends with `…`)."""
    kept: list[str] = []
    for character in str(text):
        category = unicodedata.category(character)
        if character in "\t\n\r\x0b\x0c\x85" or category in _BREAKS:
            kept.append(" ")
        elif category not in _DROPPED:
            kept.append(" " if category == "Zs" else character)
    cleaned = " ".join("".join(kept).split())
    if len(cleaned) > limit:
        return cleaned[: limit - len(CUT)] + CUT
    return cleaned


@dataclass(frozen=True)
class PreviewItem:
    """One target of the change. `changes` maps a field to (before, after); secrets
    never go in here."""

    target: str
    changes: dict[str, tuple[Any, Any]]
    side_effects: tuple[str, ...] = ()


def render(
    server_url: str,
    action: str,
    items: Sequence[PreviewItem],
    warnings: Sequence[str] = (),
) -> str:
    """The approval text: the server, the action, one block per item, the warnings."""
    if not items:
        raise ValueError("a preview has no items")
    count = "1 item" if len(items) == 1 else f"{len(items)} items"
    lines = [f"Server: {clean(server_url)}", f"Action: {clean(action)} ({count})", ""]
    for item in items:
        lines.append(f"- {_named(item.target)}")
        for field, (before, after) in item.changes.items():
            lines.append(f"    {clean(field)}: {_shown(before)} -> {_shown(after)}")
        lines.extend(f"    also: {clean(effect, 300)}" for effect in item.side_effects)
    if warnings:
        lines.append("")
        lines.extend(f"Warning: {clean(warning, 300)}" for warning in warnings)
    return "\n".join(lines)


def _named(text: Any) -> str:
    return clean(text) or '""'


def _shown(value: Any) -> str:
    if value is UNKNOWN:
        return UNKNOWN_TEXT
    if value is None:
        return "(not set)"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple, set, frozenset)):
        return ", ".join(_named(item) for item in value) or "(none)"
    return _named(value)
