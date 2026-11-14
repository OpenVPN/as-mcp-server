"""Write-mode tools for VPN sessions and support: block a user, disconnect
sessions, save a support report.

Measured with real VPN clients on 3.1.0 and 3.2.4: setting `deny` does not end a
running session, so `block_user` disconnects it itself. `/vpn/status` keeps a
session listed for about five seconds after it ended, and a disconnect sent in that
time answers 404, so "is it gone" is always asked with a short wait.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Annotated, Any

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, ConfigDict, Field

from as_mcp_server.client import AccessServerClient, NotFoundError
from as_mcp_server.effective import snapshot
from as_mcp_server.guards import Effect, newly_denied
from as_mcp_server.outputs import DELIVERY_REMINDER, probe_output_dir, write_secret_file
from as_mcp_server.preview import PreviewItem, clean
from as_mcp_server.texts import (
    CLIENT_REASON,
    DEFAULT_REASON,
    MSG_NOT_DISCONNECTED,
    MSG_ONE_TARGET,
)
from as_mcp_server.tools import READ
from as_mcp_server.writes import (
    DESTRUCTIVE,
    MAX_ITEMS,
    NOTE_LIVE,
    RESULT_HELP,
    Own,
    Partial,
    Plan,
    WriteDeps,
    read_user,
    run_write,
)

TOOLS = ("block_user", "disconnect_vpn_sessions", "create_support_report")
# Access Server runs diagnostic programs to build the report.
REPORT_TIMEOUT = 300.0
# How long to wait for an ended session to leave /vpn/status: SETTLE_POLLS reads,
# POLL_SECONDS apart. The server needed 5 to 6 seconds on both tested versions.
SETTLE_POLLS = 15
POLL_SECONDS = 1.0
MAX_REASON = 200
NOTE_DOWNLOAD_LINK = (
    "An unused download link of this user still returns a profile, but the user "
    "cannot connect while blocked."
)
MSG_STILL_CONNECTED = "a session is still connected; call disconnect_vpn_sessions"
MSG_EMPTY_REPORT = "Access Server returned an empty support report. No file was saved."


class Session(BaseModel):
    """One VPN session, as get_active_vpn_connections lists it."""

    model_config = ConfigDict(extra="forbid")

    daemon_id: Annotated[
        str,
        Field(
            description=(
                "daemon_id of the session, copied from get_active_vpn_connections, "
                "e.g. openvpn_3."
            ),
            pattern=r"^[A-Za-z0-9_.-]{1,64}$",
        ),
    ]
    client_id: Annotated[
        int,
        Field(
            description=(
                "client_id of the session inside that daemon, copied from "
                "get_active_vpn_connections."
            ),
            ge=0,
        ),
    ]


def _reduced(session: dict[str, Any]) -> dict[str, Any]:
    return {
        "daemon_id": session.get("daemon_id"),
        "client_id": session.get("client_id"),
        "username": session.get("username"),
    }


def _order(session: dict[str, Any]) -> tuple[str, int, str]:
    client_id = session.get("client_id")
    return (
        str(session.get("daemon_id")),
        client_id if isinstance(client_id, int) else -1,
        str(session.get("username")),
    )


async def _connected(client: AccessServerClient) -> list[dict[str, Any]]:
    """Every session `/vpn/status` lists, with all its fields."""
    status = await client.get("/vpn/status")
    clients = status.get("vpn_clients") if isinstance(status, dict) else None
    if not isinstance(clients, list):
        raise ToolError("Access Server returned no list of VPN sessions.")
    return [session for session in clients if isinstance(session, dict)]


async def sessions_of(
    client: AccessServerClient, usernames: Sequence[str]
) -> list[dict[str, Any]]:
    """The sessions of these users as `{daemon_id, client_id, username}`, sorted.

    The name must match exactly: a VPN login in another letter case is refused by
    the server (measured), and `Bob` and `bob` are two users.
    """
    wanted = set(usernames)
    found = [s for s in await _connected(client) if s.get("username") in wanted]
    return sorted((_reduced(session) for session in found), key=_order)


def _same(session: dict[str, Any], target: Session) -> bool:
    return (
        session.get("daemon_id") == target.daemon_id
        and session.get("client_id") == target.client_id
    )


async def _listed(
    client: AccessServerClient, user: str | None, session: Session | None
) -> list[dict[str, Any]]:
    if user is not None:
        return await sessions_of(client, [user])
    assert session is not None
    return [_reduced(s) for s in await _connected(client) if _same(s, session)]


async def still_connected(
    client: AccessServerClient,
    *,
    user: str | None = None,
    session: Session | None = None,
    started: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """The sessions of the target that are left after waiting for the status to
    settle. With `started` (the `connected_since` values seen before), a session
    that began later is somebody reconnecting, not a session that survived."""
    left: list[dict[str, Any]] = []
    for attempt in range(SETTLE_POLLS):
        if attempt:
            await asyncio.sleep(POLL_SECONDS)
        if user is not None and started is not None:
            left = [
                _reduced(s)
                for s in await _connected(client)
                if s.get("username") == user and s.get("connected_since") in started
            ]
        else:
            left = await _listed(client, user, session)
        if not left:
            break
    return left


async def disconnect(
    client: AccessServerClient,
    *,
    user: str | None = None,
    session: Session | None = None,
    reason: str = DEFAULT_REASON,
) -> None:
    """Disconnect every session of one user, or one session. Exactly one target.

    A 404 means "some of the clients are missing": the session may have ended a
    moment ago. Look again; nothing left is success, something left is an error.
    """
    if (user is None) == (session is None):
        raise ValueError("disconnect takes exactly one of user or session")
    body: dict[str, Any] = {"reason": reason, "client_reason": CLIENT_REASON}
    if user is not None:
        body["users"] = [user]
    else:
        assert session is not None
        body["clients"] = [
            {"daemon_id": session.daemon_id, "client_id": session.client_id}
        ]
    started = None
    if user is not None:
        # A client that reconnects while we wait is not the session that was asked
        # for: remember which ones were.
        started = [
            str(s.get("connected_since"))
            for s in await _connected(client)
            if s.get("username") == user
        ]
    try:
        await client.post("/vpn/client/disconnect", body)
    except NotFoundError as exc:
        if await still_connected(client, user=user, session=session, started=started):
            raise ToolError(
                "Access Server did not find the session to disconnect (404), but "
                "still lists it as connected."
            ) from exc


def not_disconnected(
    effects: Sequence[Effect], sessions: Sequence[dict[str, Any]]
) -> tuple[str, ...]:
    """One line per user who becomes blocked by a change that is not block_user and
    has a running session."""
    connected = {session.get("username") for session in sessions}
    return tuple(
        MSG_NOT_DISCONNECTED.format(name=name)
        for name in newly_denied(effects)
        if name in connected
    )


@dataclass
class _BlockUser:
    tool: str = "block_user"
    action: str = "Block user"
    note: str = NOTE_LIVE
    needs_output_dir: bool = False

    def key(self, item: str) -> str:
        return item.casefold()

    def target(self, item: str) -> str:
        return item

    async def read(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        user = await read_user(client, item)
        return {**snapshot(user), "sessions": await sessions_of(client, [item])}

    def plan(self, item: str, before: dict[str, Any], own: Own) -> Plan:
        state = {k: v for k, v in before.items() if k != "sessions"}
        count = len(before["sessions"])
        return Plan(
            PreviewItem(
                item,
                {"deny": (before["deny"], True)},
                (f"disconnects {count} active session(s)", NOTE_DOWNLOAD_LINK),
            ),
            (Effect("user", item, state, {**state, "deny": True}),),
        )

    async def apply(
        self, client: AccessServerClient, item: str, before: dict[str, Any]
    ) -> dict[str, Any]:
        # deny first: a client that is disconnected before it is blocked reconnects.
        await client.post("/userprop/set", [{"name": item, "deny": True}])
        try:
            sessions = await sessions_of(client, [item])
            if sessions:
                await disconnect(client, user=item)
        except ToolError as exc:
            raise Partial(
                ["deny set"], f"{exc} Call disconnect_vpn_sessions for this user."
            ) from exc
        return {"disconnected": len(sessions), "download_links": NOTE_DOWNLOAD_LINK}

    async def verify(self, client: AccessServerClient, item: str) -> dict[str, Any]:
        state = snapshot(await read_user(client, item))
        if state["deny"] is not True:
            raise Partial(
                ["written"], "Access Server does not show the user as blocked"
            )
        if await still_connected(client, user=item):
            raise Partial(["deny set"], MSG_STILL_CONNECTED)
        return {**state, "sessions": []}


@dataclass(frozen=True)
class _Target:
    """One item of a disconnect call: every session of a user, or one session."""

    user: str | None = None
    session: Session | None = None


@dataclass
class _Disconnect:
    reason: str = DEFAULT_REASON
    tool: str = "disconnect_vpn_sessions"
    action: str = "Disconnect VPN sessions"
    note: str = NOTE_LIVE
    needs_output_dir: bool = False
    # Per item: when the sessions that are being disconnected began.
    _started: dict[str, list[str]] = field(default_factory=dict)

    def key(self, item: _Target) -> str:
        if item.user is not None:
            return f"user:{item.user.casefold()}"
        assert item.session is not None
        return f"session:{item.session.daemon_id}:{item.session.client_id}"

    def target(self, item: _Target) -> str:
        if item.user is not None:
            return item.user
        assert item.session is not None
        return f"session {item.session.daemon_id}/{item.session.client_id}"

    async def read(self, client: AccessServerClient, item: _Target) -> dict[str, Any]:
        if self.key(item) in self._started:
            # The disconnect was sent: a session that is gone is what was asked for.
            return {"sessions": await _listed(client, item.user, item.session)}
        sessions = await _listed(client, item.user, item.session)
        if not sessions and item.user is not None:
            raise ToolError(
                f"{clean(item.user)} has no active VPN session on this Access "
                "Server (names are case-sensitive). Nothing was disconnected; call "
                "again without this name."
            )
        if not sessions:
            raise ToolError(
                f"There is no VPN {self.target(item)} on this Access Server; it "
                "may have ended. Call get_active_vpn_connections for the current "
                "list."
            )
        return {"sessions": sessions}

    def plan(self, item: _Target, before: dict[str, Any], own: Own) -> Plan:
        sessions = before["sessions"]
        effects = tuple(
            f"disconnect {s['daemon_id']}/{s['client_id']} ({s['username']})"
            for s in sessions
        )
        return Plan(
            PreviewItem(
                self.target(item),
                {"active sessions": (len(sessions), 0)},
                (*effects, f'reason in the server log: "{self.reason}"'),
            )
        )

    async def apply(
        self, client: AccessServerClient, item: _Target, before: dict[str, Any]
    ) -> dict[str, Any]:
        if item.user is not None:
            self._started[self.key(item)] = [
                str(s.get("connected_since"))
                for s in await _connected(client)
                if s.get("username") == item.user
            ]
        else:
            self._started[self.key(item)] = []
        await disconnect(
            client, user=item.user, session=item.session, reason=self.reason
        )
        return {"disconnected": len(before["sessions"])}

    async def verify(self, client: AccessServerClient, item: _Target) -> dict[str, Any]:
        started = self._started.get(self.key(item)) if item.user is not None else None
        left = await still_connected(
            client, user=item.user, session=item.session, started=started
        )
        if left:
            raise Partial(["written"], "Access Server still lists the session")
        return {"sessions": []}


def _check_reason(reason: str) -> None:
    if not reason.strip() or len(reason) > MAX_REASON or not reason.isprintable():
        raise ToolError(
            f"Refused: the reason is 1 to {MAX_REASON} printable characters on one "
            "line."
        )


def _targets(
    usernames: list[str] | None, sessions: list[Session] | None
) -> list[_Target]:
    if bool(usernames) == bool(sessions):
        raise ToolError(MSG_ONE_TARGET.format(a="usernames", b="sessions"))
    if usernames:
        return [_Target(user=name) for name in usernames]
    assert sessions is not None
    return [_Target(session=session) for session in sessions]


def register_session_tools(mcp: FastMCP, deps: WriteDeps) -> None:
    @mcp.tool(
        name="block_user",
        description=(
            "Block users from the VPN and the web interface: sets deny for each "
            "listed user and disconnects the user's running VPN sessions. New "
            "connections are refused at once; a running session is not ended by "
            "deny alone, so this tool disconnects it and checks that none is "
            "left. The user, the user's profiles and settings stay as they are. "
            "To unblock, call update_user with deny=false. The account this "
            "server signs in with cannot be blocked. Each item of 'items': "
            "outcome, disconnected (number of sessions) and a note on download "
            "links." + RESULT_HELP
        ),
        annotations=DESTRUCTIVE,
        tags={"write"},
    )
    async def block_user(
        ctx: Context,
        usernames: Annotated[
            list[str],
            Field(
                description=(
                    "Exact, case-sensitive usernames to block, up to "
                    f"{MAX_ITEMS}, each once. Every name must be an existing user "
                    "(not a group); one bad name refuses the whole call before "
                    "anyone is blocked."
                )
            ),
        ],
    ) -> Any:
        return await run_write(
            ctx, deps, _BlockUser(), usernames, {"usernames": usernames}
        )

    @mcp.tool(
        name="disconnect_vpn_sessions",
        description=(
            "Disconnect running VPN sessions: every session of the listed users, "
            "or the listed sessions. Give exactly one of usernames or sessions. "
            "The user is not blocked and can connect again right away; to keep a "
            "user out, use block_user instead. The VPN client is shown the fixed "
            'text "Disconnected by your administrator." Find sessions with '
            "get_active_vpn_connections. Each item of 'items': outcome and "
            "disconnected (number of sessions)." + RESULT_HELP
        ),
        annotations=DESTRUCTIVE,
        tags={"write"},
    )
    async def disconnect_vpn_sessions(
        ctx: Context,
        usernames: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Exact, case-sensitive usernames, up to 100: every running "
                    "session of each is disconnected. A name without a running "
                    "session refuses the whole call. A session whose username "
                    "get_active_vpn_connections shows as withheld cannot be named "
                    "here: pass it in sessions. Omit when sessions is given."
                )
            ),
        ] = None,
        sessions: Annotated[
            list[Session] | None,
            Field(
                description=(
                    "Single sessions to disconnect, up to 100, each as daemon_id "
                    "and client_id from get_active_vpn_connections. Use it to "
                    "end one of several sessions of a user. Omit when usernames "
                    "is given."
                )
            ),
        ] = None,
        reason: Annotated[
            str,
            Field(
                description=(
                    "Why, for the Access Server log; the VPN user does not see "
                    'it. One line, 1 to 200 characters. Default: "Disconnected '
                    'through as-mcp-server".'
                ),
                min_length=1,
                max_length=MAX_REASON,
                pattern=r"^[^\x00-\x1f\x7f]*$",
            ),
        ] = DEFAULT_REASON,
    ) -> Any:
        _check_reason(reason)
        targets = _targets(usernames, sessions)
        args = {
            "usernames": usernames,
            "sessions": [s.model_dump() for s in sessions] if sessions else None,
            "reason": reason,
        }
        return await run_write(ctx, deps, _Disconnect(reason=reason), targets, args)

    @mcp.tool(
        name="create_support_report",
        description=(
            "Save the Access Server support report to a local file, for OpenVPN "
            "support or for your own troubleshooting. The report is plain text: "
            "version and platform, service status, configuration keys, license "
            "usage, cluster state, network interfaces, routes and firewall rules. "
            "Access Server replaces passwords and keys with [redacted], but the "
            "report still holds sensitive settings, so its text is not returned: "
            "the result has only path, size_bytes and a reminder. Do not read the "
            "file back into the conversation unless the user asks for it. Nothing "
            "on the server is changed and no approval is asked. The server runs "
            "diagnostic programs to build it, so allow up to 5 minutes; do not "
            "call it in a loop."
        ),
        annotations=READ,
        tags={"write"},
    )
    async def create_support_report() -> dict[str, Any]:
        directory = deps.holder.settings.resolved_output_dir()
        probe_output_dir(directory)
        text = await deps.holder.get().get_text(
            "/support/report", timeout=REPORT_TIMEOUT
        )
        if not text.strip():
            raise ToolError(MSG_EMPTY_REPORT)
        path = write_secret_file(
            directory, "support-report", "access-server", "txt", text
        )
        return {
            "path": str(path),
            "size_bytes": path.stat().st_size,
            "reminder": DELIVERY_REMINDER,
        }
