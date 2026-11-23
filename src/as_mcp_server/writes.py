"""The one way a change reaches Access Server.

Every write tool hands `run_write` a small `WriteOp`: how to read one item, plan
it, apply it and read it back. `run_write` does the rest in a fixed order:
validate the list, check the server version, read every item, run the guards, show
the change and ask, read again, write item by item, read back, and record each
attempt in the audit log. A tool cannot skip a step because it does not own one.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

import mcp_types
from fastmcp import Context
from fastmcp.exceptions import ToolError
from fastmcp.server.middleware import Middleware
from mcp.shared.exceptions import MCPError
from mcp.types import ToolAnnotations

from as_mcp_server.approval import Decision, ask, binding, canonical
from as_mcp_server.audit import AuditError, AuditLog, Outcome
from as_mcp_server.client import (
    AccessServerClient,
    ClientHolder,
    RequestTimeoutError,
    redact,
)
from as_mcp_server.effective import (
    DEFAULT_RECORD,
    INHERITABLE,
    CannotCompute,
    server_wide,
)
from as_mcp_server.fresh_groups import FreshGroups
from as_mcp_server.guards import (
    Effect,
    auto_limit_reason,
    lockout_reason,
    own_mfa_reason,
)
from as_mcp_server.outputs import probe_output_dir
from as_mcp_server.preview import PreviewItem, clean, render, shown_name
from as_mcp_server.settings import Approval
from as_mcp_server.texts import (
    MSG_AUTO_LIMIT,
    MSG_CANCELLED,
    MSG_CHANGED,
    MSG_LATE_ANSWER,
    MSG_LOCKOUT,
    MSG_NO_ELICITATION,
    WARN_OWN_MFA,
)
from as_mcp_server.versions import untested_warning, version_status

log = logging.getLogger(__name__)

MAX_ITEMS = 100
PAGE_SIZE = 500
WRITE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True
)
DESTRUCTIVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True
)
NOTE_LIVE = "The change is live."
NOTE_USERPROP_CACHE = (
    "The change is live (may take up to the user-property cache timeout)."
)
MSG_OLD_SERVER = (
    "Refused: writes need Access Server 3.1 or newer; this server reports {version}."
)
# Appended to the description of every tool that goes through run_write.
RESULT_HELP = (
    " Result: 'items', one per target, each with 'outcome': done, partial, failed, "
    "refused_changed, unknown_after_timeout or not attempted. The list stops at the "
    "first item that is not done. Tell the user how many items were done, read "
    "'detail' for what is left to do, never repeat an item that is done, partial or "
    "unknown_after_timeout, and relay 'notes'."
)
# Appended to the description of every tool that saves a secret to a file.
SECRET_FILE_HELP = (
    " Do not open, copy, send or delete the saved file yourself: give the user its "
    "path and the reminder."
)
MSG_EARLIER_ITEMS_WRITTEN = (
    "The items before this one in the list were already written: repeat the call "
    "only for this item and the ones marked not attempted."
)
MSG_INTERRUPTED = (
    "The tool call was interrupted while this change was being written; whether it "
    "was applied is not known. The write was not repeated; read the current state "
    "before doing anything else."
)
MSG_NO_OWN_RECORD = (
    "Refused: the state of the signed-in account ({name}) cannot be read, so "
    "as-mcp-server cannot tell whether a change would lock it out. Nothing was "
    "changed."
)


@dataclass(frozen=True)
class Own:
    """The account as-mcp-server is signed in with, and everything a guard needs."""

    name: str
    user: dict[str, Any]
    group: str | None
    users: dict[str, dict[str, Any]]
    groups: dict[str, dict[str, Any]]
    base: dict[str, Any]


@dataclass
class WriteDeps:
    holder: ClientHolder
    audit: AuditLog
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    fresh: FreshGroups = field(init=False)

    def __post_init__(self) -> None:
        self.fresh = FreshGroups(self.audit.path.parent)

    async def own(self) -> Own:
        """Read every user and group once. `/users/defaultuser` is never read."""
        client = self.holder.get()
        users, users_complete = await _all_pages(client, "/users/list", {})
        groups, groups_complete = await _all_pages(
            client, "/groups/list", {"enumerate_members": False}
        )
        name = client.config.username
        by_name = {record["name"].casefold(): record for record in users}
        # The exact spelling first: `openvpn` and `OpenVPN` can be two users.
        record = next(
            (user for user in users if user["name"] == name),
            by_name.get(name.casefold()),
        )
        if record is None:
            raise ToolError(MSG_NO_OWN_RECORD.format(name=clean(name)))
        group = record.get("group")
        return Own(
            name=record["name"],
            user=record,
            group=group if isinstance(group, str) and group else None,
            users=by_name,
            groups={record["name"].casefold(): record for record in groups},
            base=server_wide(
                [*users, *groups],
                fields=INHERITABLE,
                complete=users_complete and groups_complete,
            ),
        )


async def _all_pages(
    client: AccessServerClient, path: str, extra: dict[str, Any]
) -> tuple[list[dict[str, Any]], bool]:
    """Every record of a list endpoint, and whether all of them could be read.

    The first page must answer. A later page that fails leaves the list incomplete
    instead of failing the write: the guards then treat inherited values as unknown.
    """
    records: list[dict[str, Any]] = []
    while True:
        body = {"page_size": PAGE_SIZE, "offset": len(records), **extra}
        try:
            page = await client.post(path, body)
        except ToolError:
            if not records:
                raise
            return records, False
        profiles = page.get("profiles") if isinstance(page, dict) else None
        if not isinstance(profiles, list):
            raise ToolError(f"Access Server returned no list of records for {path}.")
        records.extend(p for p in profiles if isinstance(p, dict) and "name" in p)
        total = page.get("total")
        if not profiles or not isinstance(total, int) or len(records) >= total:
            return records, True


@dataclass(frozen=True)
class Plan:
    """What one item will do: the lines shown to the administrator, the records it
    changes, and a reason when it is never done without a person approving."""

    preview: PreviewItem
    effects: tuple[Effect, ...] = ()
    auto_reason: str | None = None
    # A whole refusal for automatic mode, when "repeat it with a prompt" is the
    # wrong advice.
    auto_message: str | None = None


class Partial(Exception):
    """A multi-step item stopped midway, or the server does not show what was
    written. `result` carries what the administrator still needs (a serial, a
    path)."""

    def __init__(
        self,
        steps_done: list[str],
        error: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(error)
        self.steps_done = list(steps_done)
        self.error = error
        self.result = dict(result or {})


class WriteOp[Item](Protocol):
    tool: str
    action: str
    note: str
    needs_output_dir: bool

    # Optional: `always_ask = True` asks for approval in automatic mode too, and
    # `msg_no_elicitation` replaces the answer for an app that cannot ask.

    def key(self, item: Item) -> str:
        """Casefolded identity of the item: for duplicates."""
        ...

    def target(self, item: Item) -> str:
        """The item's name as the administrator wrote it: for results and audit."""
        ...

    async def read(self, client: AccessServerClient, item: Item) -> dict[str, Any]:
        """The state before, stable fields only (no counters, no timestamps).
        Raises ToolError when the target is missing or of the wrong kind."""
        ...

    def plan(self, item: Item, before: dict[str, Any], own: Own) -> Plan: ...

    async def apply(
        self, client: AccessServerClient, item: Item, before: dict[str, Any]
    ) -> dict[str, Any]:
        """Write the item; return extra result fields. May raise Partial."""
        ...

    async def verify(self, client: AccessServerClient, item: Item) -> dict[str, Any]:
        """The state after; raises Partial(["written"], ...) when it does not show
        what was written."""
        ...


async def last_restarted(client: AccessServerClient) -> Any:
    status = await client.get("/server/status")
    if not isinstance(status, dict) or "last_restarted" not in status:
        raise ToolError("Access Server did not return the time of its last restart.")
    return status["last_restarted"]


async def read_user(client: AccessServerClient, name: str) -> dict[str, Any]:
    """The record of user `name`, exact spelling. ToolError when there is none."""
    return await _read_record(client, name, "user")


async def read_group(
    client: AccessServerClient, name: str, *, members: bool = False
) -> dict[str, Any]:
    """The record of group `name`, exact spelling. ToolError when there is none."""
    return await _read_record(client, name, "group", members=members)


async def find_record(
    client: AccessServerClient, name: str, kind: str, *, members: bool = False
) -> dict[str, Any] | None:
    """The record of the user or group (`kind`) called exactly `name`, or None."""
    return await _lookup(client, name, kind, members=members)


async def kind_of(client: AccessServerClient, name: str) -> str | None:
    """ "user" or "group" when a record with exactly this name exists, else None.
    Access Server keeps both kinds in one namespace (measured)."""
    for kind in ("user", "group"):
        if await _lookup(client, name, kind) is not None:
            return kind
    return None


_ENDPOINTS = {
    "user": ("/users/list", "users"),
    "group": ("/groups/list", "groups"),
}


async def _read_record(
    client: AccessServerClient, name: str, kind: str, *, members: bool = False
) -> dict[str, Any]:
    shown = clean(name) or '""'
    if name == DEFAULT_RECORD:
        raise ToolError(
            f"Refused: {DEFAULT_RECORD} is the server's default record, not a {kind}; "
            "as-mcp-server does not change it."
        )
    found = await _lookup(client, name, kind, members=members)
    if found is not None:
        return found
    other = "group" if kind == "user" else "user"
    if await _lookup(client, name, other) is not None:
        raise ToolError(f"{shown} is a {other}, not a {kind}.")
    raise ToolError(
        f"There is no {kind} named {shown} on this Access Server (names are "
        "case-sensitive)."
    )


async def _lookup(
    client: AccessServerClient, name: str, kind: str, *, members: bool = False
) -> dict[str, Any] | None:
    path, key = _ENDPOINTS[kind]
    body: dict[str, Any] = {"page_size": 10, "offset": 0, key: [name]}
    if kind == "group":
        body["enumerate_members"] = members
    page = await client.post(path, body)
    profiles = page.get("profiles") if isinstance(page, dict) else None
    for record in profiles if isinstance(profiles, list) else []:
        if isinstance(record, dict) and record.get("name") == name:
            return record
    return None


@dataclass
class _Row:
    """One item on its way through the flow."""

    target: str
    before: dict[str, Any] | None = None
    plan: Plan | None = None
    outcome: str = "not attempted"
    after: Any = None
    detail: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Run:
    """What every audit line of one call has in common."""

    deps: WriteDeps
    tool: str
    approval: str
    server_url: str
    admin_user: str
    server_version: str = ""
    version_tested: bool = True
    batch_id: str | None = None
    problems: list[str] = field(default_factory=list)

    def audit(
        self,
        row: _Row,
        outcome: Outcome,
        *,
        after: Any = None,
        error: str | None = None,
    ) -> None:
        try:
            self.deps.audit.append(
                tool=self.tool,
                target=row.target,
                outcome=outcome,
                approval=self.approval,
                server_url=self.server_url,
                server_version=self.server_version,
                version_tested=self.version_tested,
                admin_user=self.admin_user,
                before=row.before,
                after=row.after if after is None else after,
                batch_id=self.batch_id,
                error=error if error is not None else row.detail,
            )
        except AuditError as exc:
            # The outcome of the write itself must still reach the administrator.
            log.error("%s", exc)
            if str(exc) not in self.problems:
                self.problems.append(str(exc))

    def refuse(
        self,
        rows: Sequence[_Row],
        outcome: Outcome,
        message: str,
        *,
        error: str | None = None,
        predicted: bool = False,
    ) -> ToolError:
        """Audit every item with `outcome` and return the error to raise."""
        for row in rows:
            after = _predicted(row) if predicted else None
            self.audit(row, outcome, after=after, error=error or message)
        return ToolError(message)


class LateAnswer(Middleware):
    """An approval answer the framework turned down before any tool ran.

    The framework keeps a question open for 10 minutes and answers anything later,
    or anything it did not issue, with one fixed protocol error. This puts the
    attempt into the audit log and says in plain words what happened.
    """

    def __init__(self, deps: WriteDeps) -> None:
        self.deps = deps

    async def on_message(self, context: Any, call_next: Any) -> Any:
        try:
            return await call_next(context)
        except MCPError as exc:
            data = exc.error.data
            if not (
                context.method == "tools/call"
                and isinstance(data, dict)
                and data.get("reason") == "invalid_request_state"
            ):
                raise
            params = context.message if isinstance(context.message, dict) else {}
            tool = clean(str(params.get("name", "")))
            message = MSG_LATE_ANSWER.format(tool=tool)
            self._audit(tool, params.get("arguments"), message)
            raise MCPError(code=exc.error.code, message=message, data=data) from exc

    def _audit(self, tool: str, arguments: Any, message: str) -> None:
        try:
            config = self.deps.holder.get().config
            self.deps.audit.append(
                tool=tool,
                target=canonical(arguments or {}),
                outcome="refused_no_approval",
                approval="prompt",
                server_url=config.url,
                server_version="",
                version_tested=True,
                admin_user=config.username,
                before=None,
                after=None,
                error=message,
            )
        except ToolError as exc:
            log.warning("%s", exc)


def _predicted(row: _Row) -> Any:
    if row.plan is None:
        return None
    return [
        {"kind": effect.kind, "name": effect.name, "after": effect.after}
        for effect in row.plan.effects
    ]


async def run_write[Item](
    ctx: Context,
    deps: WriteDeps,
    op: WriteOp[Item],
    items: Sequence[Item],
    args: Any,
) -> dict[str, Any] | mcp_types.InputRequiredResult:
    """Run one write tool call. See the module docstring for the order of steps."""
    settings = deps.holder.settings
    client = deps.holder.get()
    mode: Approval = "prompt" if getattr(op, "always_ask", False) else settings.approval
    run = _Run(
        deps=deps,
        tool=op.tool,
        approval=mode,
        server_url=client.config.url,
        admin_user=client.config.username,
    )

    # 1. The list itself.
    if not items:
        raise ToolError("Refused: the list is empty; give at least one item.")
    if len(items) > MAX_ITEMS:
        raise run.refuse(
            [_Row(f"{len(items)} items")],
            "failed",
            f"Refused: {len(items)} items in one call; the limit is {MAX_ITEMS}. "
            "Nothing was changed.",
        )
    rows = [_Row(shown_name(op.target(item))) for item in items]
    if len(rows) > 1:
        run.batch_id = uuid.uuid4().hex
    seen: dict[str, str] = {}
    for item, row in zip(items, rows, strict=True):
        key = op.key(item)
        if key in seen:
            raise run.refuse(
                rows,
                "failed",
                f"Refused: {row.target} is in the list twice (as {seen[key]} and "
                f"{row.target}; names are compared without letter case). Nothing "
                "was changed.",
            )
        seen[key] = row.target

    try:
        # 2. The server version. 3. Places a result must be written to.
        deps.audit.probe()
        info = await client.get("/server/info")
        version = str(info.get("version", "")) if isinstance(info, dict) else ""
        run.server_version = version
        status = version_status(version)
        run.version_tested = status == "tested"
        if status == "unsupported":
            raise ToolError(MSG_OLD_SERVER.format(version=clean(version) or "none"))
        warnings = [untested_warning(version)] if status == "untested" else []
        if op.needs_output_dir:
            probe_output_dir(settings.resolved_output_dir())

        # 4. Read and plan every item before anything is written.
        own = await deps.own()
        for item, row in zip(items, rows, strict=True):
            try:
                row.before = await op.read(client, item)
                row.plan = op.plan(item, row.before, own)
            except CannotCompute as exc:
                raise ToolError(
                    f"Refused: the result of this change for {row.target} cannot "
                    f"be computed ({exc}). Nothing was changed."
                ) from exc
    except ToolError as exc:
        raise run.refuse(rows, "failed", str(exc)) from exc
    plans = [row.plan for row in rows if row.plan is not None]

    # 5. Guards over everything the call would do.
    effects = [effect for plan in plans for effect in plan.effects]
    reason = lockout_reason(own.name, own.group, effects)
    if reason is not None:
        raise run.refuse(
            rows,
            "refused_lockout",
            MSG_LOCKOUT.format(name=clean(own.name)),
            error=reason,
            predicted=True,
        )
    own_mfa = own_mfa_reason(own.name, effects)
    if mode == "auto":
        reason = (
            next((plan.auto_reason for plan in plans if plan.auto_reason), None)
            or auto_limit_reason(effects)
            or own_mfa
        )
        if reason is not None:
            raise run.refuse(
                rows,
                "refused_auto_limit",
                MSG_AUTO_LIMIT.format(reason=clean(reason, 300)),
                error=reason,
                predicted=True,
            )
        message = next((p.auto_message for p in plans if p.auto_message), None)
        if message is not None:
            raise run.refuse(rows, "refused_auto_limit", message, predicted=True)

    if own_mfa is not None:
        warnings.append(WARN_OWN_MFA.format(name=clean(own.name)))

    # 6. Show the change and ask.
    text = render(
        client.config.url,
        op.action,
        [p.preview for p in plans],
        warnings,
        head_changes=getattr(op, "head_changes", None),
    )
    befores = [row.before for row in rows]
    decision = await ask(ctx, mode, text, binding(op.tool, args, befores))
    if isinstance(decision, mcp_types.InputRequiredResult):
        return decision
    if decision is Decision.CANCELLED:
        raise run.refuse(rows, "cancelled", MSG_CANCELLED)
    if decision is Decision.NO_ELICITATION:
        message = getattr(op, "msg_no_elicitation", MSG_NO_ELICITATION)
        raise run.refuse(rows, "refused_no_approval", message)
    if decision is Decision.STALE:
        raise run.refuse(rows, "refused_changed", MSG_CHANGED)

    # 7. Write, one item at a time, nobody else writing in between.
    try:
        async with deps.lock:
            for index, (item, row) in enumerate(zip(items, rows, strict=True)):
                try:
                    current = await op.read(client, item)
                except (ToolError, CannotCompute) as exc:
                    # The target is gone or unreadable since the preview: say what
                    # the server says now, which tells more than "changed".
                    row.outcome, row.detail = "failed", str(exc)
                    break
                if canonical(current) != canonical(row.before):
                    if index == 0:
                        raise run.refuse(rows, "refused_changed", MSG_CHANGED)
                    row.outcome = "refused_changed"
                    row.detail = f"{MSG_CHANGED} {MSG_EARLIER_ITEMS_WRITTEN}"
                    break
                if not await _write_one(client, op, item, row):
                    break
    finally:
        # 8. One audit line per item that was attempted, whatever happened above.
        for row in rows:
            if row.outcome != "not attempted":
                audited = "applied" if row.outcome == "done" else row.outcome
                run.audit(row, audited)  # type: ignore[arg-type]

    changed = any(row.outcome in ("done", "partial") for row in rows)
    notes = [*([op.note] if changed else []), *warnings, *run.problems]
    return {
        "tool": op.tool,
        "approval": mode,
        "batch_id": run.batch_id,
        "items": [
            {
                "target": row.target,
                "outcome": row.outcome,
                "before": redact(row.before),
                "after": redact(row.after),
                "detail": row.detail,
                **row.extra,
            }
            for row in rows
        ],
        "notes": notes,
    }


async def _write_one[Item](
    client: AccessServerClient, op: WriteOp[Item], item: Item, row: _Row
) -> bool:
    """Apply and verify one item. False stops the list.

    Whatever ends this function, the row has an outcome by then: the audit line of
    a change that may have reached the server must not depend on how the call ended
    (a cancelled tool call raises `CancelledError`, which is not an `Exception`).
    """
    try:
        return await _apply_and_verify(client, op, item, row)
    except BaseException:
        if row.outcome == "not attempted":
            row.outcome, row.detail = "unknown_after_timeout", MSG_INTERRUPTED
        raise


async def _apply_and_verify[Item](
    client: AccessServerClient, op: WriteOp[Item], item: Item, row: _Row
) -> bool:
    try:
        row.extra = dict(await op.apply(client, item, row.before or {}))
    except Partial as exc:
        _partial(row, exc)
        row.after = await _state_or_none(op.read(client, item))
        return False
    except RequestTimeoutError as exc:
        row.outcome = "unknown_after_timeout"
        row.detail = (
            f"{exc} The write was not repeated; 'after' is the state read "
            "afterwards, when it could be read."
        )
        await _state_after_timeout(client, op, item, row)
        return False
    except ToolError as exc:
        row.outcome, row.detail = "failed", str(exc)
        return False
    except Exception as exc:
        log.exception("unexpected error while writing %s", row.target)
        row.outcome = "failed"
        row.detail = f"Unexpected error ({type(exc).__name__}); see the server log."
        return False
    try:
        row.after = await op.verify(client, item)
    except Partial as exc:
        _partial(row, exc)
        return False
    except ToolError as exc:
        row.outcome = "partial"
        row.detail = (
            f"Written, but the state afterwards could not be read: {exc} "
            "(done: written)"
        )
        return False
    except Exception as exc:
        log.exception("unexpected error after writing %s", row.target)
        row.outcome = "partial"
        row.detail = (
            "Written, but the state afterwards could not be read: unexpected error "
            f"({type(exc).__name__}); see the server log. (done: written)"
        )
        return False
    row.outcome = "done"
    return True


async def _state_after_timeout[Item](
    client: AccessServerClient, op: WriteOp[Item], item: Item, row: _Row
) -> None:
    """After a write nobody saw answered: the state now, and what `verify` misses.

    When the server did apply the write, `verify` may find a later step undone (a
    blocked user still connected, a new user without the password); that must
    reach the administrator, not be dropped with the failed read."""
    try:
        row.after = await op.verify(client, item)
    except Partial as exc:
        row.detail = f"{row.detail} Read afterwards: {exc.error}."
        row.extra = {**row.extra, **exc.result}
        row.after = await _state_or_none(op.read(client, item))
    except (ToolError, CannotCompute):
        row.after = None
    except Exception:
        log.exception("unexpected error while reading %s after a timeout", row.target)
        row.after = None


def _partial(row: _Row, exc: Partial) -> None:
    row.outcome = "partial"
    done = ", ".join(exc.steps_done) or "nothing"
    row.detail = f"{exc.error} (done: {done})"
    row.extra = {**row.extra, **exc.result}


async def _state_or_none(reading: Any) -> Any:
    try:
        return await reading
    except (ToolError, Partial, CannotCompute):
        return None
