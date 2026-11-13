"""Write tools for connection profiles and their download links.

A profile holds a private key and a link hands one out, so neither ever goes into a
tool result: both are saved to a file and the tool returns its path.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from as_mcp_server.client import AccessServerClient, NotFoundError
from as_mcp_server.outputs import (
    DELIVERY_REMINDER,
    OutputError,
    write_secret_file,
)
from as_mcp_server.preview import PreviewItem, clean
from as_mcp_server.texts import MSG_ONE_TARGET
from as_mcp_server.writes import (
    DESTRUCTIVE,
    MAX_ITEMS,
    NOTE_LIVE,
    WRITE,
    Own,
    Partial,
    Plan,
    WriteDeps,
    read_user,
    run_write,
)

ProfileType = Literal["userlogin", "autologin"]
# Per profile type: the most uses and the longest lifetime (seconds) of a link.
LINK_LIMITS = {"userlogin": (5, 604800), "autologin": (5, 86400)}
PAGE_SIZE = 500
MAX_COMMENT = 200
TOOLS = (
    "create_connection_profile",
    "create_profile_download_link",
    "delete_connection_profiles",
)
_SERIAL = re.compile(r"[0-9]+", re.ASCII)
_SERIAL_IN_FILE = re.compile(r"^#\s*Certificate serial: ([0-9]+)", re.M | re.ASCII)

Usernames = Annotated[
    list[str],
    Field(
        description=(
            "Exact, case-sensitive usernames, up to 100, each once. Every name must "
            "be an existing user (not a group); one bad name refuses the whole call "
            "before anything is created."
        )
    ),
]
ProfileTypeParam = Annotated[
    ProfileType,
    Field(
        description=(
            "userlogin (default): the user types their password when connecting. "
            "autologin: connects without a password; needs autologin enabled for "
            "the user and is refused in automatic approval mode."
        )
    ),
]


def _now() -> datetime:
    return datetime.now(UTC)


def _article(profile_type: str) -> str:
    return "an" if profile_type == "autologin" else "a"


def _by_number(serial: str) -> tuple[int, str]:
    return len(serial), serial


async def _profiles(
    client: AccessServerClient, username: str | None = None
) -> list[dict[str, Any]]:
    """Every profile on the server, or every profile of one user (exact name)."""
    found: list[dict[str, Any]] = []
    while True:
        body: dict[str, Any] = {
            "page_size": PAGE_SIZE,
            "offset": len(found),
            "order_by": "serial",
            "sort_by": "asc",
        }
        if username is not None:
            body["filters"] = {"username": {"operation": "equal", "value": username}}
        page = await client.post("/profiles/list", body)
        profiles = page.get("profiles") if isinstance(page, dict) else None
        if not isinstance(profiles, list):
            raise ToolError("Access Server returned no list of connection profiles.")
        found.extend(profiles)
        total = page.get("total")
        if not profiles or not isinstance(total, int) or len(found) >= total:
            break
    return [
        {**profile, "serial": str(profile["serial"])}
        for profile in found
        if isinstance(profile, dict)
        and profile.get("serial") is not None
        and (username is None or profile.get("username") == username)
    ]


async def _serials(client: AccessServerClient, username: str) -> list[str]:
    serials = [profile["serial"] for profile in await _profiles(client, username)]
    return sorted(serials, key=_by_number)


def _autologin_allowed(user: dict[str, Any]) -> Any:
    prop = user.get("autologin")
    return prop.get("value") if isinstance(prop, dict) else None


def _refuse_without_autologin(name: str, before: dict[str, Any]) -> None:
    """Measured on 3.1.0 and 3.2.4: the server answers 400 "No permission to
    generate profile"; say why instead."""
    if before.get("autologin") is not True:
        raise ToolError(
            f"Refused: autologin is off for user {clean(name)}, and Access Server "
            "gives no autologin profile to such a user. Nothing was changed."
        )


@dataclass
class _UserOp:
    """What the two create tools share: one item is one username."""

    profile_type: ProfileType
    directory: Path
    note: str = NOTE_LIVE
    needs_output_dir: bool = True

    def key(self, item: str) -> str:
        return item.casefold()

    def target(self, item: str) -> str:
        return item

    async def _user_state(self, client: AccessServerClient, name: str) -> dict:
        """Refuses a name that is not a user: the server itself would not (measured:
        /profiles/create and /token-url accept a group name)."""
        user = await read_user(client, name)
        if self.profile_type == "autologin":
            return {"autologin": _autologin_allowed(user)}
        return {}


@dataclass
class _CreateProfile(_UserOp):
    tls_crypt_v2: bool | None = None
    comment: str | None = None
    tool: str = "create_connection_profile"
    _created: dict[str, str] = field(default_factory=dict)

    @property
    def action(self) -> str:
        kind = self.profile_type
        return f"Create {_article(kind)} {kind} connection profile"

    async def read(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        state = await self._user_state(client, item)
        return {"profiles": await _serials(client, item), **state}

    def plan(self, item: str, before: dict[str, Any], own: Own) -> Plan:
        effects: list[str] = []
        reason = None
        if self.profile_type == "autologin":
            _refuse_without_autologin(item, before)
            effects.append("an autologin profile connects without a password")
            reason = f"an autologin connection profile would be created for user {item}"
        if self.tls_crypt_v2 is not None:
            effects.append(f"TLS-Crypt v2: {'on' if self.tls_crypt_v2 else 'off'}")
        if self.comment is not None:
            effects.append(f'comment "{self.comment}"')
        effects.append(f"the profile file is saved in {self.directory}")
        count = len(before["profiles"])
        return Plan(
            PreviewItem(
                item, {"connection profiles": (count, count + 1)}, tuple(effects)
            ),
            auto_reason=reason,
        )

    async def apply(
        self, client: AccessServerClient, item: str, before: dict[str, Any]
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"username": item, "profile_type": self.profile_type}
        if self.tls_crypt_v2 is not None:
            body["tls_crypt_v2"] = self.tls_crypt_v2
        if self.comment is not None:
            body["comment"] = self.comment
        text = await client.post_text("/profiles/create", body)
        done = ["created on the server"]
        serial = await self._new_serial(client, item, before["profiles"], text)
        known = {"serial": serial} if serial else {}
        if serial:
            self._created[item] = serial
        if not text.strip():
            raise Partial(
                done,
                "Access Server answered without the profile; delete it with "
                "delete_connection_profiles",
                known,
            )
        try:
            path = write_secret_file(self.directory, "profile", item, "ovpn", text)
        except OutputError as exc:
            raise Partial(
                done,
                f"could not be saved: {exc}; delete it with delete_connection_profiles",
                known,
            ) from exc
        result = {"path": str(path), **known, "reminder": DELIVERY_REMINDER}
        if not serial:
            raise Partial(
                [*done, "saved to the file"],
                "the new profile could not be told apart in the profile list, so "
                "its serial is not known",
                result,
            )
        return result

    async def _new_serial(
        self, client: AccessServerClient, name: str, before: list[str], text: str
    ) -> str | None:
        try:
            new = set(await _serials(client, name)) - set(before)
        except ToolError:
            return None
        named = _SERIAL_IN_FILE.search(text)
        if named and named.group(1) in new:
            return named.group(1)
        return next(iter(new)) if len(new) == 1 else None

    async def verify(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        serials = await _serials(client, item)
        created = self._created.get(item)
        if created is not None and created not in serials:
            raise Partial(
                ["written"], f"Access Server does not list the new profile {created}"
            )
        return {"profiles": serials}


@dataclass
class _CreateLink(_UserOp):
    lifetime: int = 86400
    usages: int = 1
    tool: str = "create_profile_download_link"
    _made: dict[str, dict[str, Any]] = field(default_factory=dict)

    @property
    def action(self) -> str:
        kind = self.profile_type
        return f"Create {_article(kind)} {kind} profile download link"

    def _valid_until(self) -> str:
        expiry = _now().replace(microsecond=0) + timedelta(seconds=self.lifetime)
        return expiry.isoformat()

    async def read(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        return {"user": item, **await self._user_state(client, item)}

    def plan(self, item: str, before: dict[str, Any], own: Own) -> Plan:
        kind = self.profile_type
        max_usages, max_lifetime = LINK_LIMITS[kind]
        if self.lifetime > max_lifetime or self.usages > max_usages:
            raise ToolError(
                f"Refused: {_article(kind)} {kind} link may be valid for at most "
                f"{max_lifetime // 3600} hours and {max_usages} uses."
            )
        terms = f"valid until {self._valid_until()}, {self.usages} use(s)"
        effects = [
            f"cannot be revoked, {terms}; blocking the user later does not stop "
            "the link; profiles already downloaded through it can be deleted"
        ]
        reason = None
        if kind == "autologin":
            _refuse_without_autologin(item, before)
            effects.append("the downloaded profile connects without a password")
            reason = f"an autologin download link would be created for user {item}"
        effects.append(f"the link is saved to a file in {self.directory}")
        return Plan(
            PreviewItem(item, {"download link": (None, terms)}, tuple(effects)),
            auto_reason=reason,
        )

    async def apply(
        self, client: AccessServerClient, item: str, before: dict[str, Any]
    ) -> dict[str, Any]:
        valid_until = self._valid_until()
        uri = await client.post(
            "/token-url",
            {
                "lifetime": self.lifetime,
                "usages": self.usages,
                "profile_type": self.profile_type,
                "username": item,
            },
        )
        terms = {"valid_until": valid_until, "usages": self.usages}
        if not isinstance(uri, str) or not uri.strip():
            raise Partial(
                [],
                "Access Server answered without a link; if one was created it "
                f"cannot be revoked and expires at {valid_until}",
            )
        self._made[item] = terms
        content = f"{uri}\nvalid until {valid_until}, {self.usages} use(s)\n"
        try:
            path = write_secret_file(
                self.directory, "download-link", item, "txt", content
            )
        except OutputError as exc:
            raise Partial(
                ["created on the server"],
                "the link exists, cannot be revoked and expires at "
                f"{valid_until}; it could not be saved: {exc}",
            ) from exc
        return {"path": str(path), **terms, "reminder": DELIVERY_REMINDER}

    async def verify(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        # A link cannot be read back from the server; this is what was asked for.
        return dict(self._made.get(item, {}))


@dataclass(frozen=True)
class _Target:
    """What one delete call removes: every profile of a user, or the listed ones."""

    username: str | None = None
    serials: tuple[str, ...] = ()


def _described(profile: dict[str, Any]) -> dict[str, Any]:
    """The fields of a profile that do not change by themselves."""
    return {
        "serial": profile["serial"],
        "username": profile.get("username"),
        "profile_type": profile.get("profile_type"),
        "comment": profile.get("comment") or "",
    }


@dataclass
class _DeleteProfiles:
    tool: str = "delete_connection_profiles"
    action: str = "Delete connection profiles"
    note: str = NOTE_LIVE
    needs_output_dir: bool = False
    # Set when the delete was sent: from then on a profile that is gone is expected.
    _sent: list[str] | None = None

    def key(self, item: _Target) -> str:
        if item.username is not None:
            return f"user:{item.username.casefold()}"
        return "serials"

    def target(self, item: _Target) -> str:
        if item.username is not None:
            return item.username
        if len(item.serials) == 1:
            return f"connection profile {item.serials[0]}"
        return f"{len(item.serials)} connection profiles"

    async def read(self, client: AccessServerClient, item: _Target) -> dict[str, Any]:
        if self._sent is not None:
            return {"profiles": await self._still_listed(client, item)}
        if item.username is not None:
            found = await _profiles(client, item.username)
            if not found:
                raise ToolError(
                    "There are no connection profiles of user "
                    f"{clean(item.username)} on this Access Server (names are "
                    "case-sensitive)."
                )
            found.sort(key=lambda profile: _by_number(profile["serial"]))
        else:
            by_serial = {p["serial"]: p for p in await _profiles(client)}
            missing = [s for s in item.serials if s not in by_serial]
            if missing:
                raise ToolError(
                    f"There is no connection profile with serial {missing[0]} on "
                    "this Access Server."
                )
            found = [by_serial[serial] for serial in item.serials]
        return {"profiles": [_described(profile) for profile in found]}

    def plan(self, item: _Target, before: dict[str, Any], own: Own) -> Plan:
        effects = []
        for profile in before["profiles"]:
            about = f"{profile['username']}, {profile['profile_type']}"
            if profile["comment"]:
                about += f', comment "{profile["comment"]}"'
            effects.append(f"delete {profile['serial']} ({about})")
        changes: dict[str, tuple[Any, Any]] = {}
        if item.username is not None:
            changes["connection profiles"] = (len(before["profiles"]), 0)
        return Plan(PreviewItem(self.target(item), changes, tuple(effects)))

    async def apply(
        self, client: AccessServerClient, item: _Target, before: dict[str, Any]
    ) -> dict[str, Any]:
        serials = [profile["serial"] for profile in before["profiles"]]
        self._sent = serials
        if item.username is not None:
            # Never the `filter` field: it deletes by substring.
            try:
                await client.post("/profiles/delete-user", {"users": [item.username]})
            except NotFoundError as exc:
                # Measured: 404 when the user has no profiles (left).
                raise ToolError(
                    "Access Server found no connection profiles of user "
                    f"{clean(item.username)} to delete (404)."
                ) from exc
            return {"deleted": serials}
        answer = await client.post("/profiles/delete", serials)
        statuses = answer.get("response") if isinstance(answer, dict) else None
        statuses = statuses if isinstance(statuses, dict) else {}
        deleted = [serial for serial in serials if statuses.get(serial) == 204]
        kept = [serial for serial in serials if serial not in deleted]
        if kept:
            listed = ", ".join(
                f"{serial} (status {clean(statuses.get(serial, 'missing'), 20)})"
                for serial in kept
            )
            raise Partial(
                [f"deleted {', '.join(deleted)}"] if deleted else [],
                f"Access Server did not delete {listed}",
                {"deleted": deleted},
            )
        return {"deleted": deleted}

    async def _still_listed(
        self, client: AccessServerClient, item: _Target
    ) -> list[dict[str, Any]]:
        sent = set(self._sent or ())
        return [
            _described(profile)
            for profile in await _profiles(client, item.username)
            if profile["serial"] in sent
        ]

    async def verify(self, client: AccessServerClient, item: _Target) -> dict[str, Any]:
        left = await self._still_listed(client, item)
        if left:
            serials = ", ".join(profile["serial"] for profile in left)
            raise Partial(["written"], f"Access Server still lists {serials}")
        return {"profiles": []}


def _check_comment(comment: str | None) -> None:
    if comment is None:
        return
    if len(comment) > MAX_COMMENT or not comment.isprintable():
        raise ToolError(
            f"Refused: a comment is at most {MAX_COMMENT} printable characters on "
            "one line."
        )


def _delete_target(serials: list[str] | None, username: str | None) -> _Target:
    if bool(serials) == bool(username):
        raise ToolError(MSG_ONE_TARGET.format(a="serials", b="username"))
    if username:
        return _Target(username=username)
    assert serials is not None
    if len(serials) > MAX_ITEMS:
        raise ToolError(
            f"Refused: {len(serials)} serials in one call; the limit is "
            f"{MAX_ITEMS}. Nothing was changed."
        )
    seen: set[str] = set()
    for serial in serials:
        if not isinstance(serial, str) or not _SERIAL.fullmatch(serial):
            raise ToolError(
                f"Refused: {clean(serial, 40) or '(empty)'} is not a profile "
                "serial. A serial is a string of digits; copy it exactly from "
                "list_connection_profiles."
            )
        if serial in seen:
            raise ToolError(
                f"Refused: {serial} is in the list twice. Nothing was changed."
            )
        seen.add(serial)
    return _Target(serials=tuple(serials))


def register_profile_tools(mcp: FastMCP, deps: WriteDeps) -> None:
    def output_dir() -> Path:
        return deps.holder.settings.resolved_output_dir()

    @mcp.tool(
        name="create_connection_profile",
        description=(
            "Create a new connection profile (an .ovpn file: a client certificate "
            "with its private key) for each listed user. The file is saved on the "
            "administrator's computer and only its path is returned; the content "
            "of a profile is never returned. Profiles the user already has stay "
            "valid. The administrator approves the whole list once. Each item of "
            "'items': outcome, path, serial (a string of digits) and a reminder to "
            "delete the file after delivery. To let a user fetch the profile "
            "themselves, use create_profile_download_link instead."
        ),
        annotations=WRITE,
        tags={"write"},
    )
    async def create_connection_profile(
        ctx: Context,
        usernames: Usernames,
        profile_type: ProfileTypeParam = "userlogin",
        tls_crypt_v2: Annotated[
            bool | None,
            Field(
                description=(
                    "true: a profile for clients that support TLS-Crypt v2; false: "
                    "the older TLS-Crypt. Omit to let Access Server decide."
                )
            ),
        ] = None,
        comment: Annotated[
            str | None,
            Field(
                description=(
                    "A note stored with every created profile and shown by "
                    "list_connection_profiles, e.g. the device it is for. One "
                    "line, at most 200 characters."
                ),
                max_length=MAX_COMMENT,
            ),
        ] = None,
    ) -> Any:
        _check_comment(comment)
        op = _CreateProfile(
            profile_type=profile_type,
            directory=output_dir(),
            tls_crypt_v2=tls_crypt_v2,
            comment=comment,
        )
        args = {
            "usernames": usernames,
            "profile_type": profile_type,
            "tls_crypt_v2": tls_crypt_v2,
            "comment": comment,
        }
        return await run_write(ctx, deps, op, usernames, args)

    @mcp.tool(
        name="create_profile_download_link",
        description=(
            "Create a link through which a user downloads a new connection profile "
            "into their OpenVPN client, one link for each listed user. The link is "
            "saved to a file on the administrator's computer and only the path is "
            "returned; the link itself is never returned. A link cannot be revoked "
            "or listed afterwards: it works until it expires or its uses run out, "
            "also when the user is blocked later. Limits: userlogin at most 168 "
            "hours and 5 uses, autologin at most 24 hours and 5 uses. Each item of "
            "'items': outcome, path, valid_until (UTC), usages and a reminder to "
            "delete the file after delivery."
        ),
        annotations=WRITE,
        tags={"write"},
    )
    async def create_profile_download_link(
        ctx: Context,
        usernames: Usernames,
        profile_type: ProfileTypeParam = "userlogin",
        lifetime_seconds: Annotated[
            int,
            Field(
                description=(
                    "How long the link works, in seconds, from 60. Default 86400 "
                    "(24 hours). At most 604800 (7 days) for userlogin and 86400 "
                    "for autologin."
                ),
                ge=60,
            ),
        ] = 86400,
        usages: Annotated[
            int,
            Field(
                description=(
                    "How many times the link can be used; each use creates one "
                    "profile. Default 1, at most 5."
                ),
                ge=1,
            ),
        ] = 1,
    ) -> Any:
        op = _CreateLink(
            profile_type=profile_type,
            directory=output_dir(),
            lifetime=lifetime_seconds,
            usages=usages,
        )
        args = {
            "usernames": usernames,
            "profile_type": profile_type,
            "lifetime_seconds": lifetime_seconds,
            "usages": usages,
        }
        return await run_write(ctx, deps, op, usernames, args)

    @mcp.tool(
        name="delete_connection_profiles",
        description=(
            "Delete connection profiles for good: the listed serials, or every "
            "profile of one user. Give exactly one of serials or username. A "
            "deleted profile can no longer be used to connect and cannot be "
            "restored; the user needs a new one. A session that is already "
            "connected with a deleted profile stays connected until it ends or is "
            "disconnected with disconnect_vpn_sessions. The administrator sees the "
            "owner, "
            "type and comment of every profile before approving. Find serials "
            "with list_connection_profiles. The item of 'items' has outcome and "
            "'deleted', the serials that were deleted."
        ),
        annotations=DESTRUCTIVE,
        tags={"write"},
    )
    async def delete_connection_profiles(
        ctx: Context,
        serials: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Serials of the profiles to delete, up to 100, each a string "
                    "of digits copied exactly from list_connection_profiles (not a "
                    "number: serials are larger than a number can hold). Omit when "
                    "username is given."
                )
            ),
        ] = None,
        username: Annotated[
            str | None,
            Field(
                description=(
                    "Exact, case-sensitive username: deletes every profile issued "
                    "to this name, also when the user itself no longer exists. "
                    "Omit when serials is given."
                )
            ),
        ] = None,
    ) -> Any:
        target = _delete_target(serials, username)
        args = {"serials": serials, "username": username}
        return await run_write(ctx, deps, _DeleteProfiles(), [target], args)
