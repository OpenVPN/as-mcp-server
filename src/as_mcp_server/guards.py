"""Refusals decided before any write. No I/O here.

`lockout_reason` protects the account as-mcp-server itself signs in with, in every
approval mode. `auto_limit_reason` lists what is never done without a person
approving it. Both judge the state after the change (see effective.py), so a
reset, a group move and a group-level change are covered like a direct one.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal


@dataclass(frozen=True)
class Effect:
    """One user or group before and after a write.

    `before` None means created, `after` None means deleted; both are snapshots.
    """

    kind: Literal["user", "group"]
    name: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None


def lockout_reason(
    own_name: str, own_group: str | None, effects: Sequence[Effect]
) -> str | None:
    """Why the write would lock as-mcp-server out of its own account, or None."""
    for effect in effects:
        if effect.kind == "group":
            if (
                own_group is not None
                and effect.after is None
                and _same(effect.name, own_group)
            ):
                return "the group of the own account would be deleted"
            continue
        if not _same(effect.name, own_name):
            continue
        before, after = effect.before, effect.after
        if after is None:
            return "the own account would be deleted"
        if after["deny"]:
            return "the own account would be blocked"
        if after["deny_web"]:
            return "the own account would lose web and API access"
        if not after["admin"]:
            return "the own account would lose its administrator right"
        if before is not None and after["auth_method"] != before["auth_method"]:
            return "the authentication method of the own account would change"
        if before is not None and after["group"] != before["group"]:
            return "the own account would move to another group"
    return None


def auto_limit_reason(effects: Sequence[Effect]) -> str | None:
    """Why the write needs a person's approval, or None. Deletes pass."""
    for effect in effects:
        before, after = effect.before, effect.after
        if after is None:
            continue
        who = f"{effect.kind} {effect.name}"
        if after["admin"] and not (before and before["admin"]):
            return f"{who} would become an administrator"
        if before and before["totp"] and not after["totp"]:
            return f"MFA would be switched off for {who}"
        if before and after["auth_method"] != before["auth_method"]:
            return f"the authentication method of {who} would change"
        if after["autologin"] and not (before and before["autologin"]):
            return f"autologin would be switched on for {who}"
    return None


def _same(left: str, right: str) -> bool:
    return left.casefold() == right.casefold()
