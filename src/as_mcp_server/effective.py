"""What a user or group record will be after a change, computed before the write.

No I/O here. Records are the Access Server's own: every property is
`{"value", "inherited", "inherited_source_type"}` and `value` is already the
effective one; a user's `group` is a plain string or absent.

Measured 2026-11-12 on 3.1.0 and 3.2.3: a value inherited from a group has source
type `group`; `configuration`, `default` and `implicit_default` are server-wide.
`/users/defaultuser` does not report the configuration: with `auth.module.type=pam`
every inheriting record says `pam` and the default record still says `local`. The
server-wide value is therefore read off records that inherit it (`server_wide`).
When none does, or when they disagree, the value after a reset is `UNKNOWN`: the
write may still go ahead where the design allows it, and the guards decide where it
may not.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

GUARDED = ("deny", "deny_web", "admin", "auth_method", "totp", "autologin")
INHERITABLE = (
    "deny",
    "deny_web",
    "admin",
    "autologin",
    "auth_method",
    "totp",
    "allow_password_change",
    "allow_generate_profiles",
    "reroute_gw",
)
SERVER_WIDE_SOURCES = frozenset({"configuration", "default", "implicit_default"})
DEFAULT_RECORD = "__DEFAULT__"


class CannotCompute(Exception):
    """The read itself is broken: a record without a guarded field, or a user in a
    group whose state was not given."""


class _Unknown:
    """The value of a field that will be inherited from a server-wide setting nobody
    could read. Equal to nothing, and asking it for a truth value is an error, so no
    check can pass or fail on it by accident."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "unknown"

    def __bool__(self) -> bool:
        raise TypeError("an unknown value has no truth; test `is UNKNOWN` first")

    def __copy__(self) -> _Unknown:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> _Unknown:
        return self


UNKNOWN: Final = _Unknown()


def snapshot(
    record: Mapping[str, Any], *, fields: Sequence[str] = GUARDED
) -> dict[str, Any]:
    """`{field: effective value}` for `fields`, plus `group` (None without one)."""
    result = {field: _prop(record, field)["value"] for field in fields}
    result["group"] = _group_of(record)
    return result


def server_wide(
    records: Iterable[Mapping[str, Any]],
    *,
    fields: Sequence[str] = GUARDED,
    complete: bool = True,
) -> dict[str, Any]:
    """The values of `fields` a record with no own value and no group inherits.

    A field is present only when some record inherits it from the server and all
    records that do agree. `complete=False` says that not every record was read:
    then nothing is known.
    """
    if not complete:
        return {}
    base: dict[str, Any] = {}
    disputed: set[str] = set()
    for record in records:
        if record.get("name") == DEFAULT_RECORD:
            continue
        for field in fields:
            prop = record.get(field)
            if field in disputed or not _from_server(prop):
                continue
            value = prop["value"]
            if field not in base:
                base[field] = value
            elif type(base[field]) is not type(value) or base[field] != value:
                del base[field]
                disputed.add(field)
    return base


def user_after(
    user: Mapping[str, Any] | None,
    changes: Mapping[str, Any],
    reset: Sequence[str],
    group: Mapping[str, Any] | None,
    base: Mapping[str, Any],
    *,
    fields: Sequence[str] = GUARDED,
) -> dict[str, Any]:
    """The snapshot of a user after `changes` and `reset`; `user` None is a new user.

    `group` is the state (a snapshot or `group_after`) of the group the user is in
    after the change; `base` is `server_wide(...)`. A change set to None is no change.
    A field that would come from `base` and is not there is `UNKNOWN`.
    """
    group_name = changes.get("group") or (_group_of(user) if user else None)
    if group_name is not None and group is None:
        raise CannotCompute(f"the state of group {group_name!r} is not known")
    result = _after(user, changes, reset, group if group_name else None, base, fields)
    result["group"] = group_name
    return result


def group_after(
    group: Mapping[str, Any] | None,
    changes: Mapping[str, Any],
    reset: Sequence[str],
    base: Mapping[str, Any],
    *,
    fields: Sequence[str] = GUARDED,
) -> dict[str, Any]:
    """The snapshot of a group after `changes` and `reset`; None is a new group."""
    result = _after(group, changes, reset, None, base, fields)
    result["group"] = None
    return result


def _after(
    record: Mapping[str, Any] | None,
    changes: Mapping[str, Any],
    reset: Sequence[str],
    group: Mapping[str, Any] | None,
    base: Mapping[str, Any],
    fields: Sequence[str] = GUARDED,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in fields:
        if changes.get(field) is not None:
            result[field] = changes[field]
            continue
        prop = _prop(record, field) if record is not None else None
        if prop is not None and prop.get("inherited") is False and field not in reset:
            result[field] = prop["value"]
        elif group is not None:
            if field not in group:
                raise CannotCompute(f"the group state has no {field}")
            result[field] = group[field]
        elif _from_server(prop):
            result[field] = prop["value"]
        else:
            result[field] = base.get(field, UNKNOWN)
    return result


def _prop(record: Mapping[str, Any], field: str) -> Mapping[str, Any]:
    prop = record.get(field)
    if not isinstance(prop, Mapping) or "value" not in prop:
        raise CannotCompute(f"the record has no readable {field}")
    return prop


def _from_server(prop: Any) -> bool:
    return (
        isinstance(prop, Mapping)
        and "value" in prop
        and prop.get("inherited") is True
        and prop.get("inherited_source_type") in SERVER_WIDE_SOURCES
    )


def _group_of(record: Mapping[str, Any]) -> str | None:
    group = record.get("group")
    return group if isinstance(group, str) and group else None
