"""Write tools for users and groups: create, update, delete.

Measured on 3.1.0 and 3.2.4 before this was written:

- Access Server stores any text as a user's group, also the name of a group that
  does not exist, so every tool here checks the group first.
- Users and groups share one namespace: a name can be one or the other.
- `/auth/password/change` creates a user record for a name that has none, and sets
  a password only for a user whose authentication method is `local`. The password
  must hold a digit, an upper-case letter and a symbol.
- Deleting a user, deleting a group, blocking a group and moving a user into a
  blocked group all leave a running VPN session connected.
- A group that did not exist when Access Server last started refuses the VPN
  connections of its members until the next restart.
"""

from __future__ import annotations

import contextlib
import secrets as stdlib_secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal, get_args

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field

from as_mcp_server.client import (
    AccessServerClient,
    NotFoundError,
    RequestTimeoutError,
)
from as_mcp_server.effective import (
    DEFAULT_RECORD,
    INHERITABLE,
    UNKNOWN,
    CannotCompute,
    group_after,
    snapshot,
    user_after,
)
from as_mcp_server.guards import Effect, auto_limit_reason
from as_mcp_server.outputs import DELIVERY_REMINDER, OutputError, write_secret_file
from as_mcp_server.preview import PreviewItem, clean
from as_mcp_server.texts import (
    MSG_USE_BLOCK,
    NOTE_GROUP_RESTART,
    WARN_GROUP_RESTART,
)
from as_mcp_server.tools_profiles import serials_of
from as_mcp_server.tools_sessions import (
    MSG_STILL_CONNECTED,
    disconnect,
    not_disconnected,
    sessions_of,
    still_connected,
)
from as_mcp_server.writes import (
    DESTRUCTIVE,
    MAX_ITEMS,
    NOTE_LIVE,
    NOTE_USERPROP_CACHE,
    PAGE_SIZE,
    RESULT_HELP,
    SECRET_FILE_HELP,
    WRITE,
    Own,
    Partial,
    Plan,
    WriteDeps,
    find_record,
    kind_of,
    read_group,
    read_user,
    run_write,
)

AuthMethod = Literal["local", "pam", "radius", "ldap", "saml"]
RerouteGw = Literal["disable", "dns_only", "global"]
UpdatableField = Literal[
    "deny",
    "deny_web",
    "admin",
    "autologin",
    "auth_method",
    "totp",
    "allow_password_change",
    "allow_generate_profiles",
    "reroute_gw",
]
FIELDS = INHERITABLE
assert get_args(UpdatableField) == FIELDS
TOOLS = (
    "create_user",
    "update_user",
    "delete_user",
    "create_group",
    "update_group",
    "delete_group",
)
MAX_NAME = 128
MAX_MEMBERS_SHOWN = 20
# A side effect line of the preview is cut at 300 characters.
MAX_MEMBERS_TEXT = 220
NOTE_NEW_GROUP = (
    "The group is saved. Access Server refuses the VPN connections of its members "
    "until the server is restarted. Ask the administrator whether to restart now "
    "with warm_restart, and do not move users into the group before that."
)
MSG_NOTHING_TO_CHANGE = (
    "Refused: nothing to change. Give at least one field, a group, or "
    "reset_to_inherited."
)
MSG_PASSWORD_NEEDS_LOCAL = (
    "Refused: a password can be set only for a user with the local authentication "
    "method, and {name} would use {method}. Nothing was changed."
)


class NewUser(BaseModel):
    """One user to create."""

    model_config = ConfigDict(extra="forbid")

    username: Annotated[
        str,
        Field(
            description=(
                "Name of the new user, 1 to 128 characters, case-sensitive. It "
                "must not be the name of an existing user or group."
            ),
            min_length=1,
            max_length=MAX_NAME,
        ),
    ]
    group: Annotated[
        str | None,
        Field(
            description=(
                "Exact name of an existing group to put the user in. Omit for no "
                "group. A group created since the last Access Server restart "
                "refuses the VPN connections of its members."
            )
        ),
    ] = None
    admin: Annotated[
        bool,
        Field(
            description=(
                "true makes the user an administrator; refused in automatic "
                "approval mode. false (default) sets nothing: the value of the "
                "group or the server applies."
            )
        ),
    ] = False
    auth_method: Annotated[
        AuthMethod | None,
        Field(
            description=(
                "How the user signs in: local, pam, radius, ldap or saml. Omit to "
                "inherit the method of the group or the server."
            )
        ),
    ] = None
    deny: Annotated[
        bool,
        Field(
            description=(
                "true creates the user blocked (no VPN, no web sign-in). false "
                "(default) sets nothing."
            )
        ),
    ] = False
    generate_password: Annotated[
        bool,
        Field(
            description=(
                "true sets a random local password and saves it to a file in the "
                "output folder; the result has the path, never the password. Only "
                "for a user whose authentication method is local. false "
                "(default): the user has no password yet."
            )
        ),
    ] = False


def userprop_body(
    name: str, changes: Mapping[str, Any], reset: Sequence[str]
) -> list[dict[str, Any]]:
    """The body of `/userprop/set` for one record: a null resets a field."""
    return [{"name": name, **changes, **dict.fromkeys(reset)}]


def generate_password() -> str:
    """A random password Access Server accepts: it asks for a digit, an upper-case
    letter and a symbol (measured), which a random token alone often lacks."""
    while True:
        password = stdlib_secrets.token_urlsafe(24)
        if (
            any(character.isdigit() for character in password)
            and any(character.isupper() for character in password)
            and any(character.islower() for character in password)
            and any(character in "-_" for character in password)
        ):
            return password


def _check_new_name(name: str, kind: str) -> None:
    if name == DEFAULT_RECORD:
        raise ToolError(
            f"Refused: {DEFAULT_RECORD} is the server's default record, not a {kind}; "
            "as-mcp-server does not change it."
        )
    if not 1 <= len(name) <= MAX_NAME:
        raise ToolError(f"Refused: a {kind} name has 1 to {MAX_NAME} characters.")
    if clean(name, MAX_NAME + 1) != name or not name.isprintable():
        raise ToolError(
            f"Refused: the {kind} name {clean(name) or '(empty)'} starts or ends "
            "with a space, or holds a line break, a double space or an invisible "
            "character."
        )


async def _refuse_taken(client: AccessServerClient, name: str, kind: str) -> None:
    taken = await kind_of(client, name)
    if taken is not None:
        raise ToolError(
            f"Refused: {clean(name)} is the name of an existing {taken}; a new "
            f"{kind} needs a name of its own. Nothing was changed."
        )


def _state(record: Mapping[str, Any]) -> dict[str, Any]:
    """The nine values as the server reports them, the group, and `own`: the fields
    the record sets itself (every other value is inherited)."""
    try:
        state = snapshot(record, fields=FIELDS)
    except CannotCompute as exc:
        raise ToolError(
            f"Access Server returned a record that cannot be read: {exc}."
        ) from exc
    state["own"] = [f for f in FIELDS if record[f].get("inherited") is False]
    return state


def _values(state: Mapping[str, Any]) -> dict[str, Any]:
    return {name: state[name] for name in FIELDS}


def _guarded(state: Mapping[str, Any]) -> dict[str, Any]:
    return {name: state[name] for name in (*FIELDS, "group")}


def _word(value: Any) -> str:
    """A value as the rest of the preview writes it: true and false, not Python's."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return clean(value)


def _differs(before: Any, after: Any) -> bool:
    return after is UNKNOWN or type(before) is not type(after) or before != after


def _preview_changes(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    changes: Mapping[str, Any],
    reset: Sequence[str],
    source: str,
) -> dict[str, tuple[Any, Any]]:
    """`field: before -> after` for everything the change touches or moves."""
    shown: dict[str, tuple[Any, Any]] = {}
    if before.get("group") != after.get("group"):
        shown["group"] = (before.get("group"), after.get("group"))
    for name in FIELDS:
        value = after[name]
        if name in reset:
            inherited = (
                value
                if value is UNKNOWN
                else f"inherited ({clean(source)} value: {_word(value)})"
            )
            shown[name] = (before[name], inherited)
        elif name in changes or _differs(before[name], value):
            shown[name] = (before[name], value)
    return shown


def _check_written(
    record: Mapping[str, Any],
    changes: Mapping[str, Any],
    reset: Sequence[str],
    done: list[str],
) -> None:
    """Compare only what was written: an inherited `reroute_gw` reads as true or
    false and a set one as the word, so the two forms are never compared."""
    for name, value in changes.items():
        if name == "group":
            if record.get("group") != value:
                raise Partial(done, "Access Server does not show the group as written")
            continue
        prop = record.get(name)
        prop = prop if isinstance(prop, Mapping) else {}
        if prop.get("inherited") is not False or prop.get("value") != value:
            raise Partial(done, f"Access Server does not show {name} as written")
    for name in reset:
        prop = record.get(name)
        if isinstance(prop, Mapping) and prop.get("inherited") is False:
            raise Partial(done, f"Access Server still shows an own value of {name}")


async def _warnings_now(
    client: AccessServerClient,
    effects: Sequence[Effect],
    names: Sequence[str],
    previewed: tuple[str, ...],
) -> tuple[str, ...]:
    """Who is blocked by the change that was just written and still connected.

    Read after the write, so a session that began during the approval is named
    too. Sessions come and go by themselves, which is why they are not part of the
    state the approval is bound to. When they cannot be read now, the lines of the
    preview stand."""
    try:
        sessions = await sessions_of(client, names)
    except ToolError:
        return previewed
    return not_disconnected(effects, sessions)


def _some_names(names: Sequence[str]) -> str:
    """The first names, as many as fit one preview line, then "and <n> more"."""
    listed: list[str] = []
    for name in names[:MAX_MEMBERS_SHOWN]:
        text = clean(name, 60)
        if listed and len(", ".join([*listed, text])) > MAX_MEMBERS_TEXT:
            break
        listed.append(text)
    rest = len(names) - len(listed)
    return ", ".join(listed) + (f" and {rest} more" if rest else "")


async def _members(client: AccessServerClient, group: str) -> list[dict[str, Any]]:
    """The user records of every member of `group` (exact name)."""
    found: list[dict[str, Any]] = []
    while True:
        page = await client.post(
            "/users/list",
            {
                "page_size": PAGE_SIZE,
                "offset": len(found),
                "filters": {"group": {"operation": "equal", "value": group}},
            },
        )
        profiles = page.get("profiles") if isinstance(page, dict) else None
        if not isinstance(profiles, list):
            raise ToolError("Access Server returned no list of users.")
        found.extend(profiles)
        total = page.get("total")
        if not profiles or not isinstance(total, int) or len(found) >= total:
            break
    return [
        record
        for record in found
        if isinstance(record, dict) and record.get("group") == group
    ]


# --- users ------------------------------------------------------------------------


@dataclass
class _CreateUser:
    directory: Path
    needs_output_dir: bool = False
    tool: str = "create_user"
    action: str = "Create user"
    note: str = NOTE_LIVE
    _created: set[str] = field(default_factory=set)
    _files: dict[str, Path] = field(default_factory=dict)

    def key(self, item: NewUser) -> str:
        return item.username.casefold()

    def target(self, item: NewUser) -> str:
        return item.username

    def _fields(self, item: NewUser) -> dict[str, Any]:
        """Only what was asked for: a false `admin` or `deny` is not written, so
        the value of the group or the server keeps applying."""
        fields: dict[str, Any] = {}
        if item.group is not None:
            fields["group"] = item.group
        if item.admin:
            fields["admin"] = True
        if item.auth_method is not None:
            fields["auth_method"] = item.auth_method
        if item.deny:
            fields["deny"] = True
        return fields

    async def read(self, client: AccessServerClient, item: NewUser) -> dict[str, Any]:
        name = item.username
        if name in self._created:
            return await self._user_state(client, name)
        _check_new_name(name, "user")
        await _refuse_taken(client, name, "user")
        before: dict[str, Any] = {"exists": False}
        if item.group is not None:
            group = await read_group(client, item.group)
            before["group_state"] = _values(_state(group))
        return before

    async def _user_state(self, client: AccessServerClient, name: str) -> dict:
        user = await read_user(client, name)
        return {**_state(user), "password_defined": user.get("password_defined")}

    def plan(self, item: NewUser, before: dict[str, Any], own: Own) -> Plan:
        name = item.username
        fields = self._fields(item)
        after = user_after(
            None, fields, [], before.get("group_state"), own.base, fields=FIELDS
        )
        method = after["auth_method"]
        if item.generate_password and method is not UNKNOWN and method != "local":
            raise ToolError(
                MSG_PASSWORD_NEEDS_LOCAL.format(name=clean(name), method=clean(method))
            )
        changes: dict[str, tuple[Any, Any]] = {}
        if item.group is not None:
            changes["group"] = (None, item.group)
        for shown in ("admin", "deny", "deny_web", "auth_method", "totp", "autologin"):
            changes[shown] = (None, after[shown])
        effects: list[str] = []
        if item.group is not None:
            effects.append(WARN_GROUP_RESTART)
        if item.deny:
            effects.append("the user is created blocked")
        if item.generate_password:
            effects.append(
                f"a generated password is saved to a file in {self.directory}"
            )
        else:
            effects.append("no password is set")
        twin = own.users.get(name.casefold())
        if twin is not None:
            effects.append(
                f"a user named {twin['name']} exists already; the two names differ "
                "only in letter case"
            )
        return Plan(
            PreviewItem(name, changes, tuple(effects)),
            (Effect("user", name, None, _guarded(after)),),
        )

    async def apply(
        self, client: AccessServerClient, item: NewUser, before: dict[str, Any]
    ) -> dict[str, Any]:
        name = item.username
        await client.post("/users/create", {"name": name, **self._fields(item)})
        self._created.add(name)
        if not item.generate_password:
            return {}
        done = ["user created"]
        password = generate_password()
        try:
            # The file first: a password nobody can read back must not be set.
            path = write_secret_file(
                self.directory, "password", name, "txt", password + "\n"
            )
        except OutputError as exc:
            raise Partial(done, f"no password was set: {exc}") from exc
        known = {"path": str(path), "reminder": DELIVERY_REMINDER}
        self._files[name] = path
        try:
            await client.post(
                "/auth/password/change", {"username": name, "new_password": password}
            )
        except RequestTimeoutError as exc:
            raise Partial(
                done,
                "the password change timed out; the password in the file may or "
                "may not be set",
                known,
            ) from exc
        except ToolError as exc:
            path.unlink(missing_ok=True)
            raise Partial(done, f"password was not set: {exc}") from exc
        return known

    async def verify(self, client: AccessServerClient, item: NewUser) -> dict[str, Any]:
        name = item.username
        user = await read_user(client, name)
        done = ["user created"]
        _check_written(user, self._fields(item), (), done)
        if item.generate_password and user.get("password_defined") is not True:
            # A file with a password that does not work must not be handed out.
            saved = self._files.pop(name, None)
            if saved is not None:
                saved.unlink(missing_ok=True)
            raise Partial(
                done,
                "the password was not set (Access Server shows no password for "
                "the user) and the password file was removed",
                {"path": None, "reminder": None},
            )
        return {**_state(user), "password_defined": user.get("password_defined")}


@dataclass
class _UpdateUser:
    changes: dict[str, Any]
    group: str | None = None
    reset: tuple[str, ...] = ()
    tool: str = "update_user"
    action: str = "Update user"
    note: str = NOTE_USERPROP_CACHE
    needs_output_dir: bool = False
    # Per user: the server's record, and the record of the group it will be in.
    _users: dict[str, dict[str, Any]] = field(default_factory=dict)
    _groups: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    _sessions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    _effects: dict[str, Effect] = field(default_factory=dict)
    _warnings: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.group is not None:
            self.note = f"{NOTE_USERPROP_CACHE} {NOTE_GROUP_RESTART}"

    def key(self, item: str) -> str:
        return item.casefold()

    def target(self, item: str) -> str:
        return item

    def _written(self) -> dict[str, Any]:
        moved = {"group": self.group} if self.group is not None else {}
        return {**self.changes, **moved}

    async def read(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        user = await read_user(client, item)
        before = _state(user)
        current = before["group"]
        if self.group is not None:
            group = await read_group(client, self.group)
        elif current is not None:
            # A group name without a group record gives the user nothing (measured:
            # the server stores any text as the group).
            group = await find_record(client, current, "group")
        else:
            group = None
        self._users[item], self._groups[item] = user, group
        if group is not None:
            before["group_state"] = _values(_state(group))
        if self.group is not None or "deny" in self.reset:
            # The change can block the user without disconnecting anyone.
            self._sessions[item] = await sessions_of(client, [item])
        return before

    def _after(self, item: str, base: Mapping[str, Any]) -> dict[str, Any]:
        user, group = self._users[item], self._groups[item]
        if group is None and user.get("group"):
            loose = {k: v for k, v in user.items() if k != "group"}
            after = user_after(
                loose, self.changes, self.reset, None, base, fields=FIELDS
            )
            after["group"] = user["group"]
            return after
        state = _values(_state(group)) if group is not None else None
        return user_after(user, self._written(), self.reset, state, base, fields=FIELDS)

    def plan(self, item: str, before: dict[str, Any], own: Own) -> Plan:
        after = self._after(item, own.base)
        in_group = after["group"] if self._groups[item] is not None else None
        changes = _preview_changes(
            before, after, self.changes, self.reset, in_group or "server-wide"
        )
        effect = Effect("user", item, _guarded(before), _guarded(after))
        warnings = not_disconnected((effect,), self._sessions.get(item, ()))
        self._effects[item], self._warnings[item] = effect, warnings
        return Plan(PreviewItem(item, changes, self._shown(warnings)), (effect,))

    def _shown(self, warnings: tuple[str, ...]) -> tuple[str, ...]:
        return warnings if self.group is None else (WARN_GROUP_RESTART, *warnings)

    async def apply(
        self, client: AccessServerClient, item: str, before: dict[str, Any]
    ) -> dict[str, Any]:
        await client.post(
            "/userprop/set", userprop_body(item, self._written(), self.reset)
        )
        warnings = self._warnings.get(item, ())
        if item in self._sessions and item in self._effects:
            warnings = await _warnings_now(
                client, (self._effects[item],), [item], warnings
            )
        warnings = self._shown(warnings)
        return {"warnings": list(warnings)} if warnings else {}

    async def verify(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        user = await read_user(client, item)
        _check_written(user, self._written(), self.reset, ["written"])
        return _state(user)


@dataclass
class _DeleteUser:
    tool: str = "delete_user"
    action: str = "Delete user"
    note: str = NOTE_LIVE
    needs_output_dir: bool = False
    _done: dict[str, list[str]] = field(default_factory=dict)

    def key(self, item: str) -> str:
        return item.casefold()

    def target(self, item: str) -> str:
        return item

    async def read(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        user = await read_user(client, item)
        return {
            **_state(user),
            "profiles": await serials_of(client, item),
            "sessions": await sessions_of(client, [item]),
        }

    def plan(self, item: str, before: dict[str, Any], own: Own) -> Plan:
        profiles, sessions = len(before["profiles"]), len(before["sessions"])
        return Plan(
            PreviewItem(
                item,
                {"user": ("exists", "deleted")},
                (
                    f"deletes {profiles} connection profile(s)",
                    f"disconnects {sessions} active session(s)",
                    "cannot be undone",
                ),
            ),
            (Effect("user", item, _guarded(before), None),),
        )

    async def apply(
        self, client: AccessServerClient, item: str, before: dict[str, Any]
    ) -> dict[str, Any]:
        done = self._done.setdefault(item, [])
        try:
            if before["profiles"]:
                # Never the `filter` field: it deletes by substring. Measured: 404
                # when the user has no profiles (left).
                with contextlib.suppress(NotFoundError):
                    await client.post("/profiles/delete-user", {"users": [item]})
                done.append("connection profiles deleted")
            await client.post("/users/delete", {"users": [item]})
            done.append("user deleted")
            # Measured: the session of a deleted user stays connected.
            sessions = await sessions_of(client, [item])
            if sessions:
                await disconnect(client, user=item)
        except ToolError as exc:
            if not done:
                raise
            if "user deleted" in done:
                hint = " Call disconnect_vpn_sessions for this user."
            elif isinstance(exc, RequestTimeoutError):
                # Nobody saw the answer: the user may be gone and still connected.
                hint = (
                    " It is not known whether the user was deleted; the request "
                    "was not repeated. Check with list_users, and if the user is "
                    "gone call disconnect_vpn_sessions for this user."
                )
            else:
                hint = ""
            raise Partial(done, f"{exc}{hint}") from exc
        return {
            "deleted_profiles": len(before["profiles"]),
            "disconnected": len(sessions),
        }

    async def verify(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        done = self._done.get(item, [])
        if await find_record(client, item, "user") is not None:
            raise Partial(done, "Access Server still lists the user")
        if await serials_of(client, item):
            raise Partial(
                done,
                "Access Server still lists connection profiles of the user; call "
                "delete_connection_profiles",
            )
        if await still_connected(client, user=item):
            raise Partial(done, MSG_STILL_CONNECTED)
        return {"exists": False, "profiles": [], "sessions": []}


# --- groups -----------------------------------------------------------------------


@dataclass
class _CreateGroup:
    fields: dict[str, Any]
    tool: str = "create_group"
    action: str = "Create group"
    note: str = NOTE_NEW_GROUP
    needs_output_dir: bool = False
    _created: bool = False

    def key(self, item: str) -> str:
        return item.casefold()

    def target(self, item: str) -> str:
        return item

    async def read(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        if self._created:
            return _state(await read_group(client, item))
        _check_new_name(item, "group")
        await _refuse_taken(client, item, "group")
        waiting = await _members(client, item)
        if waiting:
            # Access Server keeps any text as a user's group, so users can point at
            # a group that is not there; creating it would change them at once.
            names = _some_names(sorted(str(user["name"]) for user in waiting))
            raise ToolError(
                f"Refused: {len(waiting)} user(s) already have {clean(item)} as "
                f"their group although no such group exists ({names}); creating "
                "it would change these users at once. Nothing was changed."
            )
        return {"exists": False}

    def plan(self, item: str, before: dict[str, Any], own: Own) -> Plan:
        after = group_after(None, self.fields, [], own.base, fields=FIELDS)
        changes = {name: (None, value) for name, value in self.fields.items()}
        effects = [
            "members of a new group cannot connect to the VPN until Access Server "
            "is restarted"
        ]
        if not changes:
            effects.append("every value is inherited from the server")
        twin = own.groups.get(item.casefold())
        if twin is not None:
            effects.append(
                f"a group named {twin['name']} exists already; the two names "
                "differ only in letter case"
            )
        return Plan(
            PreviewItem(item, changes, tuple(effects)),
            (Effect("group", item, None, _guarded(after)),),
        )

    async def apply(
        self, client: AccessServerClient, item: str, before: dict[str, Any]
    ) -> dict[str, Any]:
        await client.post("/groups/create", {"name": item, **self.fields})
        self._created = True
        return {}

    async def verify(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        group = await read_group(client, item)
        _check_written(group, self.fields, (), ["group created"])
        return _state(group)


@dataclass
class _UpdateGroup:
    changes: dict[str, Any]
    reset: tuple[str, ...] = ()
    tool: str = "update_group"
    action: str = "Update group"
    note: str = NOTE_USERPROP_CACHE
    needs_output_dir: bool = False
    _group: dict[str, Any] | None = None
    _members: list[dict[str, Any]] = field(default_factory=list)
    _sessions: list[dict[str, Any]] = field(default_factory=list)
    _member_effects: list[Effect] = field(default_factory=list)
    _warnings: tuple[str, ...] = ()

    def key(self, item: str) -> str:
        return item.casefold()

    def target(self, item: str) -> str:
        return item

    def _may_block(self) -> bool:
        return self.changes.get("deny") is True or "deny" in self.reset

    async def read(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        group = await read_group(client, item)
        self._group = group
        before = _state(group)
        if self._may_block():
            # Members that inherit the block keep their running sessions.
            self._members = await _members(client, item)
            names = [str(member["name"]) for member in self._members]
            self._sessions = await sessions_of(client, names)
        return before

    def plan(self, item: str, before: dict[str, Any], own: Own) -> Plan:
        assert self._group is not None
        after = group_after(
            self._group, self.changes, self.reset, own.base, fields=FIELDS
        )
        changes = _preview_changes(
            before, after, self.changes, self.reset, "server-wide"
        )
        effects = [Effect("group", item, _guarded(before), _guarded(after))]
        if own.group is not None and own.group.casefold() == item.casefold():
            # The own account follows its group wherever it sets no value itself.
            effects.append(self._member_effect(own.user, after, own.base))
        members = [
            self._member_effect(member, after, own.base) for member in self._members
        ]
        self._member_effects = members
        self._warnings = not_disconnected(members, self._sessions)
        count = self._group.get("member_count")
        reach = (
            f"the group has {count} member(s); the change applies to each one "
            "that does not set the value itself"
            if isinstance(count, int)
            else "applies to every member that does not set the value itself"
        )
        return Plan(
            PreviewItem(item, changes, (reach, *self._warnings)), tuple(effects)
        )

    def _member_effect(
        self, member: Mapping[str, Any], group: Mapping[str, Any], base: Mapping
    ) -> Effect:
        before = _guarded(_state(member))
        after = user_after(member, {}, [], _values(group), base, fields=FIELDS)
        return Effect("user", str(member["name"]), before, _guarded(after))

    async def apply(
        self, client: AccessServerClient, item: str, before: dict[str, Any]
    ) -> dict[str, Any]:
        await client.post(
            "/userprop/set", userprop_body(item, self.changes, self.reset)
        )
        warnings = self._warnings
        if self._may_block():
            names = [effect.name for effect in self._member_effects]
            warnings = await _warnings_now(
                client, self._member_effects, names, warnings
            )
        return {"warnings": list(warnings)} if warnings else {}

    async def verify(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        group = await read_group(client, item)
        _check_written(group, self.changes, self.reset, ["written"])
        return _state(group)


@dataclass
class _DeleteGroup:
    tool: str = "delete_group"
    action: str = "Delete group"
    note: str = NOTE_LIVE
    needs_output_dir: bool = False
    _records: list[dict[str, Any]] = field(default_factory=list)

    def key(self, item: str) -> str:
        return item.casefold()

    def target(self, item: str) -> str:
        return item

    async def read(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        group = await read_group(client, item, members=True)
        members = group.get("members")
        names = sorted(str(m) for m in members) if isinstance(members, list) else []
        self._records = await _members(client, item) if names else []
        return {**_state(group), "members": names}

    def _auto_reason(self, item: str, own: Own) -> str | None:
        """What a member loses with the group that is never taken without a person."""
        effects = []
        for member in self._records:
            alone = user_after(
                {**member, "group": None}, {}, [], None, own.base, fields=FIELDS
            )
            effects.append(
                Effect(
                    "user",
                    str(member["name"]),
                    _guarded(_state(member)),
                    _guarded(alone),
                )
            )
        reason = auto_limit_reason(effects)
        if reason is None:
            reason = next(
                (
                    f"user {effect.name} would no longer be blocked"
                    for effect in effects
                    if effect.before["deny"] is True and effect.after["deny"] is False
                ),
                None,
            )
        return None if reason is None else f"{reason} when group {item} is deleted"

    def plan(self, item: str, before: dict[str, Any], own: Own) -> Plan:
        members = before["members"]
        if members:
            shown = _some_names(members)
            lost = (
                f"members that lose this group: {shown}",
                "members stay as users, lose every value they inherited from the "
                "group, and keep their running VPN sessions",
            )
        else:
            lost = ("the group has no members",)
        return Plan(
            PreviewItem(
                item,
                {"group": ("exists", "deleted")},
                (*lost, "the group's access list is deleted", "cannot be undone"),
            ),
            (Effect("group", item, _guarded(before), None),),
            self._auto_reason(item, own),
        )

    async def apply(
        self, client: AccessServerClient, item: str, before: dict[str, Any]
    ) -> dict[str, Any]:
        await client.post("/groups/delete", {"groups": [item]})
        return {"members_without_group": before["members"]}

    async def verify(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        if await find_record(client, item, "group") is not None:
            raise Partial(["written"], "Access Server still lists the group")
        return {"exists": False}


# --- parameters -------------------------------------------------------------------

_REFUSED_AUTO = "refused in automatic approval mode"
Admin = Annotated[
    bool | None,
    Field(
        description=(
            "true gives administrator rights (Admin UI and API); switching it on "
            f"is {_REFUSED_AUTO}. Omit to write nothing for this field."
        )
    ),
]
DenyWeb = Annotated[
    bool | None,
    Field(
        description=(
            "true denies sign-in to the web interface and the API; the VPN is not "
            "affected. Omit to write nothing for this field."
        )
    ),
]
Autologin = Annotated[
    bool | None,
    Field(
        description=(
            "true allows autologin connection profiles, which connect without a "
            f"password; switching it on is {_REFUSED_AUTO}. Omit to leave it as "
            "it is."
        )
    ),
]
AuthMethodParam = Annotated[
    AuthMethod | None,
    Field(
        description=(
            "How to sign in: local, pam, radius, ldap or saml. A change is "
            f"{_REFUSED_AUTO}. Omit to write nothing for this field."
        )
    ),
]
Totp = Annotated[
    bool | None,
    Field(
        description=(
            "true requires TOTP multi-factor authentication. Switching it off is "
            f"{_REFUSED_AUTO}. Omit to write nothing for this field."
        )
    ),
]
AllowPasswordChange = Annotated[
    bool | None,
    Field(
        description=(
            "true lets the user change their own local password. Omit to leave it "
            "as it is."
        )
    ),
]
AllowGenerateProfiles = Annotated[
    bool | None,
    Field(
        description=(
            "true lets the user create their own connection profiles. Omit to "
            "leave it as it is."
        )
    ),
]
RerouteGwParam = Annotated[
    RerouteGw | None,
    Field(
        description=(
            "Which client traffic goes through the VPN gateway. disable: none of "
            "the internet traffic; dns_only: only DNS; global: follow the server "
            "setting vpn.client.routing.reroute_gw, which is not the same as "
            '"full tunnel". When read, an inherited value shows as true or false '
            "and a set one as the word. Omit to write nothing for this field."
        )
    ),
]
Reset = Annotated[
    list[UpdatableField] | None,
    Field(
        description=(
            "Fields to remove from the record, so the value of the group (for a "
            "user) or of the server applies again. The preview shows the value "
            "that will apply. A field cannot be set and reset in one call."
        )
    ),
]
GroupName = Annotated[
    str,
    Field(
        description=("Exact, case-sensitive name of an existing group (not a user)."),
        min_length=1,
        max_length=MAX_NAME,
    ),
]


def _changes(reset: Sequence[str] | None, **values: Any) -> tuple[dict, tuple]:
    """The fields that were given and the fields to reset; refuses a call that
    names none, or one field as both."""
    changes = {name: value for name, value in values.items() if value is not None}
    cleared = tuple(dict.fromkeys(reset or ()))
    both = [name for name in cleared if name in changes]
    if both:
        raise ToolError(f"Refused: {both[0]} is both set and reset.")
    return changes, cleared


def register_user_tools(mcp: FastMCP, deps: WriteDeps) -> None:
    def output_dir() -> Path:
        return deps.holder.settings.resolved_output_dir()

    @mcp.tool(
        name="create_user",
        description=(
            "Create users on Access Server. Each item names the user and may set a "
            "group, administrator rights, an authentication method, a block, and "
            "generate_password. A generated password is saved to a file in the "
            "output folder and never returned; there is no way to pass a password "
            "to this tool. Without generate_password the user has no password. "
            "A name that is already a user or a group refuses the whole call. "
            "Creating an administrator is refused in automatic approval mode. "
            "Each item of 'items': outcome, the state after, and path and "
            "reminder when a password was generated. To give the user a "
            "connection profile, call create_connection_profile afterwards. An "
            "existing user cannot get a new password through this server: never "
            "delete and create a user again to change a password; say that it is "
            "not supported." + SECRET_FILE_HELP + RESULT_HELP
        ),
        annotations=WRITE,
        tags={"write"},
    )
    async def create_user(
        ctx: Context,
        users: Annotated[
            list[NewUser],
            Field(description=f"The users to create, up to {MAX_ITEMS}, each once."),
        ],
    ) -> Any:
        op = _CreateUser(
            directory=output_dir(),
            needs_output_dir=any(user.generate_password for user in users),
        )
        args = {"users": [user.model_dump() for user in users]}
        return await run_write(ctx, deps, op, users, args)

    @mcp.tool(
        name="update_user",
        description=(
            "Change settings of existing users: the same change for every listed "
            "user. Only the fields you give are written; an omitted field stays as "
            "it is. group moves the users into another group; reset_to_inherited "
            "removes a user's own value so the group or server value applies. To "
            "block a user call block_user (deny=true is refused here); "
            "deny=false unblocks. A move into a blocked group, or a reset of "
            "deny, can block a user without disconnecting them: the preview and "
            "'warnings' in the result name such users. The account this server "
            "signs in with cannot be locked out. Granting administrator rights, "
            "switching MFA off, changing the authentication method and switching "
            "autologin on are refused in automatic approval mode. A false writes "
            "the user's own false, which then overrides the group and the server; "
            "to make a user follow the group or the server again use "
            "reset_to_inherited. A call with deny=true is not run at all: call "
            "block_user, then update_user for the other fields. This tool cannot "
            "set a password, reset MFA enrollment, clear a failed-login lockout "
            "(deny is not the lockout) or take a user out of every group; say so "
            "instead of trying another tool." + RESULT_HELP
        ),
        annotations=WRITE,
        tags={"write"},
    )
    async def update_user(
        ctx: Context,
        usernames: Annotated[
            list[str],
            Field(
                description=(
                    "Exact, case-sensitive usernames, up to 100, each once. Every "
                    "name must be an existing user (not a group); one bad name "
                    "refuses the whole call before anything is changed."
                )
            ),
        ],
        deny: Annotated[
            bool | None,
            Field(
                description=(
                    "false unblocks the user. true is refused: use block_user, "
                    "which also disconnects. Omit to write nothing for this field."
                )
            ),
        ] = None,
        deny_web: DenyWeb = None,
        admin: Admin = None,
        autologin: Autologin = None,
        auth_method: AuthMethodParam = None,
        group: Annotated[
            str | None,
            Field(
                description=(
                    "Exact name of an existing group to move the users into. Omit "
                    "to leave the group as it is; this tool cannot take a user "
                    "out of every group. A group created since the last Access "
                    "Server restart refuses the VPN connections of its members."
                ),
                min_length=1,
                max_length=MAX_NAME,
            ),
        ] = None,
        totp: Totp = None,
        allow_password_change: AllowPasswordChange = None,
        allow_generate_profiles: AllowGenerateProfiles = None,
        reroute_gw: RerouteGwParam = None,
        reset_to_inherited: Reset = None,
    ) -> Any:
        if deny is True:
            raise ToolError(MSG_USE_BLOCK)
        changes, reset = _changes(
            reset_to_inherited,
            deny=deny,
            deny_web=deny_web,
            admin=admin,
            autologin=autologin,
            auth_method=auth_method,
            totp=totp,
            allow_password_change=allow_password_change,
            allow_generate_profiles=allow_generate_profiles,
            reroute_gw=reroute_gw,
        )
        if not changes and not reset and group is None:
            raise ToolError(MSG_NOTHING_TO_CHANGE)
        args = {
            "usernames": usernames,
            **changes,
            "group": group,
            "reset_to_inherited": list(reset),
        }
        op = _UpdateUser(changes=changes, group=group, reset=reset)
        return await run_write(ctx, deps, op, usernames, args)

    @mcp.tool(
        name="delete_user",
        description=(
            "Delete users for good: each user's connection profiles, the user "
            "record, and then the user's running VPN sessions, which Access "
            "Server would otherwise leave connected. Cannot be undone. The "
            "account this server signs in with cannot be deleted. To keep a user "
            "but stop their access, call block_user instead. Each item of "
            "'items': outcome, deleted_profiles and disconnected (numbers)."
            + RESULT_HELP
        ),
        annotations=DESTRUCTIVE,
        tags={"write"},
    )
    async def delete_user(
        ctx: Context,
        usernames: Annotated[
            list[str],
            Field(
                description=(
                    "Exact, case-sensitive usernames to delete, up to 100, each "
                    "once. Every name must be an existing user (not a group); one "
                    "bad name refuses the whole call before anyone is deleted."
                )
            ),
        ],
    ) -> Any:
        return await run_write(
            ctx, deps, _DeleteUser(), usernames, {"usernames": usernames}
        )

    @mcp.tool(
        name="create_group",
        description=(
            "Create a group. Only the fields you give are set on it; every other "
            "value is inherited from the server. Members inherit each value they "
            "do not set themselves. Important: Access Server refuses the VPN "
            "connections of the members of a new group until the server is "
            "restarted, so tell the user and offer warm_restart before moving "
            "anyone into the group. A name that is already a user "
            "or a group is refused. A group with administrator rights or "
            "autologin is refused in automatic approval mode." + RESULT_HELP
        ),
        annotations=WRITE,
        tags={"write"},
    )
    async def create_group(
        ctx: Context,
        name: Annotated[
            str,
            Field(
                description=(
                    "Name of the new group, 1 to 128 characters, case-sensitive. "
                    "It must not be the name of an existing user or group."
                ),
                min_length=1,
                max_length=MAX_NAME,
            ),
        ],
        admin: Admin = None,
        auth_method: AuthMethodParam = None,
        deny: Annotated[
            bool | None,
            Field(
                description=(
                    "true blocks every member that does not set deny itself. "
                    "Omit to inherit the server value."
                )
            ),
        ] = None,
        deny_web: DenyWeb = None,
        autologin: Autologin = None,
        totp: Totp = None,
        allow_password_change: AllowPasswordChange = None,
        allow_generate_profiles: AllowGenerateProfiles = None,
        reroute_gw: RerouteGwParam = None,
    ) -> Any:
        fields, _ = _changes(
            None,
            deny=deny,
            deny_web=deny_web,
            admin=admin,
            autologin=autologin,
            auth_method=auth_method,
            totp=totp,
            allow_password_change=allow_password_change,
            allow_generate_profiles=allow_generate_profiles,
            reroute_gw=reroute_gw,
        )
        op = _CreateGroup(fields=fields)
        return await run_write(ctx, deps, op, [name], {"name": name, **fields})

    @mcp.tool(
        name="update_group",
        description=(
            "Change settings of one group. Only the fields you give are written. "
            "The change reaches every member that does not set the value itself. "
            "deny=true blocks such members but does not disconnect their running "
            "VPN sessions: the preview and 'warnings' in the result name the "
            "connected ones; call disconnect_vpn_sessions for them. "
            "reset_to_inherited removes the group's own value so the server "
            "value applies. A change that would lock out the account this server "
            "signs in with is refused. Granting administrator rights, switching "
            "MFA off, changing the authentication method and switching autologin "
            "on are refused in automatic approval mode. A false writes the "
            "group's own false; to make the group follow the server again use "
            "reset_to_inherited." + RESULT_HELP
        ),
        annotations=WRITE,
        tags={"write"},
    )
    async def update_group(
        ctx: Context,
        name: GroupName,
        admin: Admin = None,
        auth_method: AuthMethodParam = None,
        deny: Annotated[
            bool | None,
            Field(
                description=(
                    "true blocks every member that does not set deny itself; "
                    "their running sessions stay connected. false unblocks. Omit "
                    "to leave it as it is."
                )
            ),
        ] = None,
        deny_web: DenyWeb = None,
        autologin: Autologin = None,
        totp: Totp = None,
        allow_password_change: AllowPasswordChange = None,
        allow_generate_profiles: AllowGenerateProfiles = None,
        reroute_gw: RerouteGwParam = None,
        reset_to_inherited: Reset = None,
    ) -> Any:
        changes, reset = _changes(
            reset_to_inherited,
            deny=deny,
            deny_web=deny_web,
            admin=admin,
            autologin=autologin,
            auth_method=auth_method,
            totp=totp,
            allow_password_change=allow_password_change,
            allow_generate_profiles=allow_generate_profiles,
            reroute_gw=reroute_gw,
        )
        if not changes and not reset:
            raise ToolError(MSG_NOTHING_TO_CHANGE)
        args = {"name": name, **changes, "reset_to_inherited": list(reset)}
        op = _UpdateGroup(changes=changes, reset=reset)
        return await run_write(ctx, deps, op, [name], args)

    @mcp.tool(
        name="delete_group",
        description=(
            "Delete one group for good. Its members stay as users and lose their "
            "group value and everything they inherited from the group (also a "
            "block or MFA set on the group); their running VPN sessions stay "
            "connected. The group's access list is deleted. Cannot be undone. "
            "The group of the account this server signs in with cannot be "
            "deleted. In automatic approval mode the delete is refused when a "
            "member would lose MFA, a block or its authentication method with "
            "the group. The result lists members_without_group." + RESULT_HELP
        ),
        annotations=DESTRUCTIVE,
        tags={"write"},
    )
    async def delete_group(ctx: Context, name: GroupName) -> Any:
        return await run_write(ctx, deps, _DeleteGroup(), [name], {"name": name})
