"""Refusals decided before any write. No I/O here.

`lockout_reason` protects the account as-mcp-server itself signs in with, in every
approval mode. `auto_limit_reason` lists what is never done without a person
approving it. Both judge the state after the change (see effective.py), so a
reset, a group move and a group-level change are covered like a direct one. A value
that is `UNKNOWN` after the change is refused for the own account and in automatic
mode; for another user with a person approving, the write goes ahead.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal

from as_mcp_server.effective import GUARDED, UNKNOWN

# What the own account needs to keep signing in to the API.
OWN_SIGN_IN = ("deny", "deny_web", "admin", "auth_method")


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
        for field in OWN_SIGN_IN:
            if after[field] is UNKNOWN:
                return f"the {field} of the own account after this change is not known"
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
        for field in GUARDED:
            if after[field] is UNKNOWN:
                return f"the {field} of {who} after this change is not known"
        if after["admin"] and not (before and before["admin"]):
            return f"{who} would become an administrator"
        if before and before["totp"] and not after["totp"]:
            return f"MFA would be switched off for {who}"
        if before and after["auth_method"] != before["auth_method"]:
            return f"the authentication method of {who} would change"
        if after["autologin"] and not (before and before["autologin"]):
            return f"autologin would be switched on for {who}"
    return None


def newly_denied(effects: Sequence[Effect]) -> list[str]:
    """Users who are blocked after the write and were not before, in the given order.

    They may keep a running VPN session: a change of `deny` that is not made by
    block_user does not disconnect anyone. An `UNKNOWN` deny counts, because it may
    be a block. Created and deleted users have no session to keep.
    """
    return [
        effect.name
        for effect in effects
        if effect.kind == "user"
        and effect.before is not None
        and effect.after is not None
        and effect.before["deny"] is False
        and (effect.after["deny"] is UNKNOWN or effect.after["deny"] is True)
    ]


def _same(left: str, right: str) -> bool:
    return left.casefold() == right.casefold()
