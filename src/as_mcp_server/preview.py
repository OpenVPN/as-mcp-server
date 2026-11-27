"""The text an administrator approves before a change is written.

Every name and value in it came from the server or from the agent, so each one goes
through `clean()`: one value is one piece of one line, whatever it contains.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from as_mcp_server.effective import UNKNOWN
from as_mcp_server.untrusted import _is_blank

CUT = "…"
UNKNOWN_TEXT = "inherited (server-wide value unknown)"
# Line and paragraph separators, and the C1 "next line": line breaks to a terminal.
_BREAKS = {"Zl", "Zp"}
# Control, format (bidi overrides, zero-width), surrogate and private-use characters.
_DROPPED = {"Cc", "Cf", "Cs", "Co", "Cn"}
_BRAILLE_BLANK = chr(0x2800)
NAME_LIMIT = 300
HIDDEN = " (the real name holds characters that are not shown here)"
# Some apps show only the first three lines of the approval text.
HEAD_NAMES = 3
HEAD_NAME_LIMIT = 60
HEAD_PART_LIMIT = 100
# How much of a change the third line names before it only counts the rest.
HEAD_CHANGES = 3
HEAD_FIELDS = 4
_COUNTED = re.compile(r"(?:(\w+) )?(\d+) (\D+)")


def clean(text: Any, limit: int = 120) -> str:
    """`text` as part of one line: no line breaks, no control or invisible
    characters, single spaces, at most `limit` characters (a cut ends with `…`)."""
    kept: list[str] = []
    for character in str(text):
        category = unicodedata.category(character)
        if character in "\t\n\r\x0b\x0c\x85" or category in _BREAKS:
            kept.append(" ")
        elif _is_blank(character) or character == _BRAILLE_BLANK:
            # Letters and marks that render as nothing: a run of them would push
            # the rest of a name to where a field of the preview is expected.
            kept.append(" ")
        elif category not in _DROPPED:
            kept.append(" " if category == "Zs" else character)
    cleaned = " ".join("".join(kept).split())
    if len(cleaned) > limit:
        return cleaned[: limit - len(CUT)] + CUT
    return cleaned


def shown_name(text: Any) -> str:
    """A target as one piece of a line, and a plain statement when that is not the
    name itself: two names that differ only in invisible characters, or after the
    cut, must not look like one name to the person who approves or reads the log."""
    raw = str(text)
    cleaned = clean(raw, NAME_LIMIT)
    if not cleaned:
        return '""'
    return cleaned if cleaned == raw else cleaned + HIDDEN


@dataclass(frozen=True)
class PreviewItem:
    """One target of the change. `changes` maps a field to (before, after); secrets
    never go in here."""

    target: str
    changes: dict[str, tuple[Any, Any]]
    side_effects: tuple[str, ...] = ()
    # A list whose order matters, shown in full after the change and left out of
    # the totals. None shows nothing; an empty tuple shows "(empty)".
    order_after: tuple[str, ...] | None = None
    # What the administrator must not miss. With several items these lines come
    # right under the action line; with one item they are side effects.
    warnings: tuple[str, ...] = ()


def render(
    server_url: str,
    action: str,
    items: Sequence[PreviewItem],
    warnings: Sequence[str] = (),
    *,
    head_changes: str | None = None,
) -> str:
    """The approval text. The first three lines carry the most: the server, the
    action with the count and the first targets, the totals. Then one block per
    item and the warnings.

    `head_changes` is for an action that is nothing but its changes (an update):
    the plural of what is changed ("users"). The third line then starts with the
    changes, which would otherwise be below the lines some apps show."""
    if not items:
        raise ValueError("a preview has no items")
    count = "1 item" if len(items) == 1 else f"{len(items)} items"
    names = [_head_name(item.target) for item in items[:HEAD_NAMES]]
    more = len(items) - len(names)
    targets = ", ".join(names) + (f" and {more} more" if more else "")
    lines = [
        f"Server: {clean(server_url)}",
        f"Action: {clean(action)} ({count}): {targets}",
    ]
    several = len(items) > 1
    if several:
        # A long list is read from the top: what needs attention comes first.
        flagged = [item for item in items if item.warnings]
        if flagged:
            lines.append(f"{len(flagged)} of {len(items)} items need attention")
        lines.extend(f"Warning: {clean(warning, 300)}" for warning in warnings)
        lines.extend(
            f"Warning: {_head_name(item.target)}: {clean(warning, 300)}"
            for item in flagged
            for warning in item.warnings
        )
    changed = _head_changes(items, head_changes) if head_changes else []
    total = _total(items, len(warnings), changed)
    if total:
        lines.append(f"Total: {total}")
    lines.append("")
    for item in items:
        lines.append(f"- {shown_name(item.target)}")
        for field, (before, after) in item.changes.items():
            lines.append(f"    {clean(field)}: {_shown(before)} -> {_shown(after)}")
        effects = item.side_effects if several else (*item.side_effects, *item.warnings)
        lines.extend(f"    also: {clean(effect, 300)}" for effect in effects)
        if item.order_after is not None:
            lines.append(
                "    order after the change:" + ("" if item.order_after else " (empty)")
            )
            lines.extend(
                f"      {number}. {clean(entry, 300)}"
                for number, entry in enumerate(item.order_after, 1)
            )
    if warnings and not several:
        lines.append("")
        lines.extend(f"Warning: {clean(warning, 300)}" for warning in warnings)
    return "\n".join(lines)


def _head_name(target: Any) -> str:
    return clean(target, HEAD_NAME_LIMIT) or '""'


def _head_changes(items: Sequence[PreviewItem], noun: str) -> list[str]:
    """The changes for the third line. One item: its first changes as
    `field before -> after`. Several items: the fields and how many items."""
    if len(items) == 1:
        changes = list(items[0].changes.items())
        parts = [
            clean(f"{field} {_shown(before)} -> {_shown(after)}", HEAD_PART_LIMIT)
            for field, (before, after) in changes[:HEAD_CHANGES]
        ]
        if len(changes) > HEAD_CHANGES:
            parts.append(f"and {len(changes) - HEAD_CHANGES} more changes")
        return parts
    fields = list(dict.fromkeys(field for item in items for field in item.changes))
    if not fields:
        return []
    named = ", ".join(clean(field, 30) for field in fields[:HEAD_FIELDS])
    if len(fields) > HEAD_FIELDS:
        named += f" and {len(fields) - HEAD_FIELDS} more"
    return [clean(f"changes {named} for {len(items)} {noun}", HEAD_PART_LIMIT + 60)]


def _total(
    items: Sequence[PreviewItem], warnings: int, leading: Sequence[str] = ()
) -> str:
    """One line for all items: counted side effects ("deletes 2 connection
    profile(s)") are added up, a side effect every item has is said once."""
    sums: dict[tuple[str, str], int] = {}
    shared: dict[str, int] = {}
    order: list[tuple[str, str] | str] = []
    for item in items:
        # One item: its warnings are side effects; several: they head the text.
        effects = (
            item.side_effects if len(items) > 1 else item.side_effects + item.warnings
        )
        for effect in dict.fromkeys(effects):
            counted = _COUNTED.fullmatch(effect)
            key: tuple[str, str] | str = effect
            if counted:
                key = (counted[1] or "", counted[3])
                sums[key] = sums.get(key, 0) + int(counted[2])
            else:
                shared[effect] = shared.get(effect, 0) + 1
            if key not in order:
                order.append(key)
    parts: list[str] = list(leading)
    for key in order:
        if isinstance(key, str):
            if shared[key] == len(items):
                parts.append(clean(key, HEAD_PART_LIMIT))
        elif sums[key]:
            verb, noun = key
            noun = noun.replace("(s)", "" if sums[key] == 1 else "s")
            parts.append(clean(f"{verb} {sums[key]} {noun}", HEAD_PART_LIMIT))
    if warnings:
        parts.append("1 warning" if warnings == 1 else f"{warnings} warnings")
    return ", ".join(part for part in parts if part)


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
